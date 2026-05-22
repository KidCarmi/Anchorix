//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/audit"
	"github.com/kidcarmi/anchorix/backend/internal/clock"
	"github.com/kidcarmi/anchorix/backend/internal/identity"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// failingAuditRecorder wraps a real audit recorder but returns
// a forced error on Record for the specified action. Used by
// the rollback test to prove that an audit-write failure
// inside Service.WithTx callback rolls the entire transaction
// back at the postgres layer — including the state-change
// repo writes that ran before the audit call. Distinct from
// the in-memory fake used in the service unit tests, which
// can't prove the actual postgres rollback path.
type failingAuditRecorder struct {
	delegate audit.Recorder
	failOn   string // action name; "" means never fail
}

func (f *failingAuditRecorder) Record(ctx context.Context, e audit.Event) error {
	if e.Action == f.failOn {
		return errors.New("forced audit failure for rollback test")
	}
	return f.delegate.Record(ctx, e)
}

func (f *failingAuditRecorder) List(ctx context.Context, q audit.ListQuery) ([]audit.Event, error) {
	return f.delegate.List(ctx, q)
}

// TestIdentityAuditRollback verifies the binding atomicity
// claim from CLAUDE.md §9: when a state-changing identity
// service call's audit row fails to write, the prior state-
// change repo call in the same transaction MUST be rolled back.
//
// The service unit tests (internal/identity/service_test.go)
// exercise the error path with a fake Transactor that does NOT
// implement real rollback semantics — they confirm the
// service returns ErrInternalAudit but cannot confirm the
// row didn't make it into postgres. This test stands the
// service up against a real postgres pool with a real
// postgres.DB.WithTx transactor and asserts the row is
// genuinely absent after audit failure.
//
// Why split per-method: the audit action name fed to
// failingAuditRecorder.failOn is method-specific. We exercise
// CreateTag, AssignTag, and DisableTag — three different code
// paths (insert, insert-with-target-lookup, update-with-preflight)
// — to confirm the rollback holds across all three shapes.
func TestIdentityAuditRollback(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	realAudit := postgres.NewAuditRecorder(db, clock.System{})
	identityRepo := postgres.NewIdentityRepository(db)
	targetResolver := postgres.NewIdentityTargetResolver(db)

	// Helper: builds an identity.Service that fails its audit
	// recorder on the specified action.
	newSvc := func(failOn string) *identity.Service {
		t.Helper()
		failing := &failingAuditRecorder{delegate: realAudit, failOn: failOn}
		svc, err := identity.NewService(
			identityRepo, db, failing, targetResolver, clock.System{},
		)
		if err != nil {
			t.Fatalf("identity.NewService: %v", err)
		}
		return svc
	}

	t.Run("CreateTag rolls back on audit failure", func(t *testing.T) {
		freshDatabase(t, db)
		svc := newSvc("tag.created")

		_, err := svc.CreateTag(ctx, identity.CreateTagInput{
			OrganizationID: "anchorix",
			Key:            "rollback-test",
			Value:          "x",
			ActorUserID:    "operator-1",
		})
		if !errors.Is(err, identity.ErrInternalAudit) {
			t.Fatalf("CreateTag err = %v; want ErrInternalAudit", err)
		}

		// No tag row should exist. This is the binding claim:
		// audit-in-transaction means the insert was rolled
		// back at the postgres layer.
		count := countRows(t, db, ctx,
			`SELECT COUNT(*) FROM tags WHERE organization_id = $1 AND key = $2 AND value = $3`,
			"anchorix", "rollback-test", "x")
		if count != 0 {
			t.Fatalf("tag row leaked despite audit failure: count=%d", count)
		}
		// And no audit row for the failed action.
		auditCount := countRows(t, db, ctx,
			`SELECT COUNT(*) FROM audit_events WHERE action = 'tag.created'`)
		if auditCount != 0 {
			t.Fatalf("audit row for tag.created written despite forced failure: count=%d", auditCount)
		}
	})

	t.Run("AssignTag rolls back on audit failure", func(t *testing.T) {
		freshDatabase(t, db)
		// Seed a tag + a cert (target). The seed must succeed
		// — only the AssignTag audit is failed.
		seedSvc := newSvc("")
		tag, err := seedSvc.CreateTag(ctx, identity.CreateTagInput{
			OrganizationID: "anchorix", Key: "a", Value: "b", ActorUserID: "op",
		})
		if err != nil {
			t.Fatalf("seed CreateTag: %v", err)
		}
		seedCertificate(t, db, ctx, "cert-rb-1")

		// Now flip the audit to fail on the assignment.
		svc := newSvc("tag.assignment_created")
		_, err = svc.AssignTag(ctx, identity.AssignTagInput{
			OrganizationID: "anchorix",
			TagID:          tag.ID,
			TargetType:     identity.TagTargetCertificate,
			TargetID:       "cert-rb-1",
			ActorUserID:    "op",
		})
		if !errors.Is(err, identity.ErrInternalAudit) {
			t.Fatalf("AssignTag err = %v; want ErrInternalAudit", err)
		}

		// No assignment row should exist.
		count := countRows(t, db, ctx,
			`SELECT COUNT(*) FROM tag_assignments WHERE tag_id = $1`, tag.ID)
		if count != 0 {
			t.Fatalf("tag_assignments row leaked: count=%d", count)
		}
		// The earlier successful seed audit (tag.created) is
		// still present; we only failed tag.assignment_created.
		auditCount := countRows(t, db, ctx,
			`SELECT COUNT(*) FROM audit_events WHERE action = 'tag.assignment_created'`)
		if auditCount != 0 {
			t.Fatalf("assignment audit leaked: count=%d", auditCount)
		}
	})

	t.Run("DisableTag rolls back on audit failure", func(t *testing.T) {
		freshDatabase(t, db)
		seedSvc := newSvc("")
		tag, err := seedSvc.CreateTag(ctx, identity.CreateTagInput{
			OrganizationID: "anchorix", Key: "d", Value: "i", ActorUserID: "op",
		})
		if err != nil {
			t.Fatalf("seed CreateTag: %v", err)
		}

		svc := newSvc("tag.disabled")
		err = svc.DisableTag(ctx, identity.DisableTagInput{
			OrganizationID: "anchorix", TagID: tag.ID,
			Reason: "rotate", ActorUserID: "op",
		})
		if !errors.Is(err, identity.ErrInternalAudit) {
			t.Fatalf("DisableTag err = %v; want ErrInternalAudit", err)
		}

		// The tag must NOT be disabled: disabled_at must
		// still be NULL because the UPDATE was rolled back.
		// disabled_at NULL is the active state; the
		// post-failure row must look exactly like it did
		// before the call.
		var disabled *time.Time
		if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx,
				`SELECT disabled_at FROM tags WHERE id = $1`, tag.ID,
			).Scan(&disabled)
		}); err != nil {
			t.Fatalf("query tag: %v", err)
		}
		if disabled != nil {
			t.Fatalf("DisableTag rolled forward: disabled_at = %v; want NULL", disabled)
		}
	})

	t.Run("CreateServiceGroup rolls back on audit failure", func(t *testing.T) {
		freshDatabase(t, db)
		svc := newSvc("service_group.created")
		_, err := svc.CreateServiceGroup(ctx, identity.CreateServiceGroupInput{
			OrganizationID: "anchorix", Slug: "sg-rb",
			DisplayName: "RB", ActorUserID: "op",
		})
		if !errors.Is(err, identity.ErrInternalAudit) {
			t.Fatalf("CreateServiceGroup err = %v; want ErrInternalAudit", err)
		}
		count := countRows(t, db, ctx,
			`SELECT COUNT(*) FROM service_groups WHERE slug = 'sg-rb'`)
		if count != 0 {
			t.Fatalf("service_group row leaked: count=%d", count)
		}
	})

	t.Run("DisableServiceGroup rolls back on audit failure", func(t *testing.T) {
		// Disable path is structurally different from the
		// INSERT paths above: it threads a children
		// preflight + an UPDATE under WithTx. A regression
		// that moves the audit Record() outside the
		// preflight tx would let the disable land even when
		// the audit row fails.
		freshDatabase(t, db)
		seedSvc := newSvc("")
		group, err := seedSvc.CreateServiceGroup(ctx, identity.CreateServiceGroupInput{
			OrganizationID: "anchorix", Slug: "sg-rb-disable",
			DisplayName: "RB Disable", ActorUserID: "op",
		})
		if err != nil {
			t.Fatalf("seed CreateServiceGroup: %v", err)
		}
		disableSvc := newSvc("service_group.disabled")
		err = disableSvc.DisableServiceGroup(ctx, identity.DisableServiceGroupInput{
			OrganizationID: "anchorix", GroupID: group.ID,
			Reason: "rb", ActorUserID: "op",
		})
		if !errors.Is(err, identity.ErrInternalAudit) {
			t.Fatalf("DisableServiceGroup err = %v; want ErrInternalAudit", err)
		}
		var disabledAt *time.Time
		if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx,
				`SELECT disabled_at FROM service_groups WHERE id = $1`, group.ID,
			).Scan(&disabledAt)
		}); err != nil {
			t.Fatalf("query service_group: %v", err)
		}
		if disabledAt != nil {
			t.Fatalf("service_group.disabled_at populated despite audit failure")
		}
	})

	t.Run("AddAgentToGroup rolls back on audit failure", func(t *testing.T) {
		freshDatabase(t, db)
		// Seed an agent + an agent group via direct repo
		// access so the seed audit doesn't fail. The
		// agent must be a real row for the resolver's
		// AgentExists check to pass.
		if err := execRawSQL(ctx, db, rawStmt{
			`INSERT INTO agents (id, organization_id, hostname, status, public_key_fingerprint)
			 VALUES ('agent-rb-1', 'anchorix', 'host', 'active', 'fp-rb-1')`, nil,
		}); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		seedSvc := newSvc("")
		group, err := seedSvc.CreateAgentGroup(ctx, identity.CreateAgentGroupInput{
			OrganizationID: "anchorix", Slug: "ag-rb",
			DisplayName: "RB", ActorUserID: "op",
		})
		if err != nil {
			t.Fatalf("seed CreateAgentGroup: %v", err)
		}
		svc := newSvc("agent_group.membership_created")
		err = svc.AddAgentToGroup(ctx, identity.AddAgentToGroupInput{
			OrganizationID: "anchorix",
			AgentID:        "agent-rb-1",
			GroupID:        group.ID,
			ActorUserID:    "op",
		})
		if !errors.Is(err, identity.ErrInternalAudit) {
			t.Fatalf("AddAgentToGroup err = %v; want ErrInternalAudit", err)
		}
		count := countRows(t, db, ctx,
			`SELECT COUNT(*) FROM agent_group_memberships WHERE agent_id = $1 AND agent_group_id = $2`,
			"agent-rb-1", group.ID)
		if count != 0 {
			t.Fatalf("agent_group_memberships row leaked: count=%d", count)
		}
	})
}

// countRows is a narrow scalar-count helper for the rollback
// assertions. Uses WithTxRaw to issue a single SELECT COUNT(*)
// outside the service's transactional scope so the read sees
// the post-commit / post-rollback view.
func countRows(t *testing.T, db *postgres.DB, ctx context.Context, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, q, args...).Scan(&n)
	}); err != nil {
		t.Fatalf("countRows %q: %v", q, err)
	}
	return n
}
