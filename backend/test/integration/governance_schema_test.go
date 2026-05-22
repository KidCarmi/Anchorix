//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// TestGovernanceMigrationApplies verifies the H-026A1
// migrations (0009/0010/0011) leave every new table in place and
// register the expected schema_migrations versions. Mirrors the
// MigrateUp-idempotency test pattern for the rest of the schema.
func TestGovernanceMigrationApplies(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	expected := []string{
		"tags",
		"tag_assignments",
		"services",
		"service_groups",
		"service_group_memberships",
		"agent_groups",
		"agent_group_memberships",
		"ownership_rules",
		"certificate_ownership_overrides",
		"ownership_match_explanations",
		"certificate_ownership",
		"policy_definitions",
		"policy_assignments",
		"policy_waivers",
		"governance_recompute_runs",
	}

	for _, tbl := range expected {
		var exists bool
		if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
			row := tx.QueryRow(ctx,
				`SELECT EXISTS (
					SELECT 1 FROM pg_catalog.pg_tables
					 WHERE schemaname = 'public' AND tablename = $1
				 )`, tbl)
			return row.Scan(&exists)
		}); err != nil {
			t.Fatalf("check table %s: %v", tbl, err)
		}
		if !exists {
			t.Fatalf("table %s missing after migration", tbl)
		}
	}

	for _, want := range []int{9, 10, 11} {
		var present bool
		if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
			row := tx.QueryRow(ctx,
				`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, want)
			return row.Scan(&present)
		}); err != nil {
			t.Fatalf("check migration version %d: %v", want, err)
		}
		if !present {
			t.Fatalf("schema_migrations missing version %d", want)
		}
	}
}

// TestGovernanceCheckConstraintsRejectInvalidEnums pins every
// new text-enum CHECK constraint introduced in H-026A1. A
// regression that loosens any of them lets a buggy insert
// silently widen the engine-facing vocabulary.
func TestGovernanceCheckConstraintsRejectInvalidEnums(t *testing.T) {
	db := testDB(t)

	cases := []struct {
		name string
		// setup SQL is run first; it must succeed. (Run inside
		// the same tx that runs the invalid statement so the
		// rollback on failure cleans both up.)
		setup []rawStmt
		// invalid SQL must fail with a CHECK violation.
		invalid rawStmt
		// fragment we expect in the pg error so an unrelated
		// failure is caught.
		wantErrContains string
	}{
		{
			name: "tag_assignments.target_type rejects unknown enum",
			setup: []rawStmt{
				{`INSERT INTO tags (id, organization_id, key, value)
				   VALUES ($1, 'anchorix', 'env', 'prod')`, []any{"tag-bad-1"}},
			},
			invalid: rawStmt{
				`INSERT INTO tag_assignments (
					id, organization_id, tag_id, target_type, target_id, assigned_by
				 ) VALUES (
					'ta-bad-1', 'anchorix', 'tag-bad-1', 'bogus_kind', 'whatever', 'system'
				 )`, nil,
			},
			wantErrContains: "target_type",
		},
		{
			name: "ownership_rules.precedence_tier rejects unknown enum",
			setup: []rawStmt{
				{`INSERT INTO services (id, organization_id, slug, display_name)
				   VALUES ($1, 'anchorix', $1, 'svc')`, []any{"svc-bad-1"}},
			},
			invalid: rawStmt{
				`INSERT INTO ownership_rules (
					id, organization_id, name, service_id,
					precedence_tier, priority, match_kind, match_value, created_by
				 ) VALUES (
					'rule-bad-1', 'anchorix', 'bad-tier-1', 'svc-bad-1',
					'bogus_tier', 100, 'san_glob', '*.example.com', 'tester'
				 )`, nil,
			},
			wantErrContains: "precedence_tier",
		},
		{
			name: "ownership_rules.match_kind rejects unknown enum",
			setup: []rawStmt{
				{`INSERT INTO services (id, organization_id, slug, display_name)
				   VALUES ($1, 'anchorix', $1, 'svc')`, []any{"svc-bad-2"}},
			},
			invalid: rawStmt{
				`INSERT INTO ownership_rules (
					id, organization_id, name, service_id,
					precedence_tier, priority, match_kind, match_value, created_by
				 ) VALUES (
					'rule-bad-2', 'anchorix', 'bad-kind-1', 'svc-bad-2',
					'san_pattern', 100, 'bogus_kind', '*.example.com', 'tester'
				 )`, nil,
			},
			wantErrContains: "match_kind",
		},
		{
			name: "policy_assignments.scope_kind rejects unknown enum",
			setup: []rawStmt{
				{`INSERT INTO policy_definitions (
					id, organization_id, slug, display_name, rules, created_by
				 ) VALUES (
					$1, 'anchorix', $1, 'p', '[]'::jsonb, 'tester'
				 )`, []any{"pol-bad-1"}},
			},
			invalid: rawStmt{
				`INSERT INTO policy_assignments (
					id, organization_id, policy_definition_id,
					scope_kind, scope_id, assigned_by
				 ) VALUES (
					'pa-bad-1', 'anchorix', 'pol-bad-1', 'bogus', 'anchorix', 'tester'
				 )`, nil,
			},
			wantErrContains: "scope_kind",
		},
		{
			name: "policy_waivers.scope_kind rejects unknown enum",
			setup: []rawStmt{
				{`INSERT INTO policy_definitions (
					id, organization_id, slug, display_name, rules, created_by
				 ) VALUES (
					$1, 'anchorix', $1, 'p', '[]'::jsonb, 'tester'
				 )`, []any{"pol-bad-2"}},
			},
			invalid: rawStmt{
				`INSERT INTO policy_waivers (
					id, organization_id, policy_definition_id, policy_rule_local_id,
					scope_kind, scope_id, reason,
					granted_by, expires_at
				 ) VALUES (
					'pw-bad-1', 'anchorix', 'pol-bad-2', 'r1',
					'bogus', 'anchorix', 'because',
					'tester', now() + interval '1 day'
				 )`, nil,
			},
			wantErrContains: "scope_kind",
		},
		{
			name: "governance_recompute_runs.kind rejects unknown enum",
			invalid: rawStmt{
				`INSERT INTO governance_recompute_runs (
					id, organization_id, kind, started_at, actor, actor_kind, engine_version
				 ) VALUES (
					'rr-bad-1', 'anchorix', 'bogus', now(), 'system', 'system', 1
				 )`, nil,
			},
			wantErrContains: "kind",
		},
		{
			name: "governance_recompute_runs.actor_kind rejects unknown enum",
			invalid: rawStmt{
				`INSERT INTO governance_recompute_runs (
					id, organization_id, kind, started_at, actor, actor_kind, engine_version
				 ) VALUES (
					'rr-bad-2', 'anchorix', 'ownership', now(), 'system', 'bogus', 1
				 )`, nil,
			},
			wantErrContains: "actor_kind",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			freshDatabase(t, db)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			for _, s := range tc.setup {
				if err := execRawSQL(ctx, db, s); err != nil {
					t.Fatalf("setup: %v", err)
				}
			}
			err := execRawSQL(ctx, db, tc.invalid)
			if err == nil {
				t.Fatalf("invalid insert succeeded; want CHECK violation")
			}
			if !strings.Contains(err.Error(), tc.wantErrContains) {
				t.Fatalf("error %q does not mention %q", err, tc.wantErrContains)
			}
		})
	}
}

// TestPolicyWaiverExpiresAfterGrantedCheck pins the
// `policy_waivers_expires_after_granted` CHECK constraint —
// past-or-equal expiries are refused at the DB level even if a
// service-layer bypass is attempted.
func TestPolicyWaiverExpiresAfterGrantedCheck(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := execRawSQL(ctx, db, rawStmt{
		`INSERT INTO policy_definitions (id, organization_id, slug, display_name, rules, created_by)
		 VALUES ('pol-ttl-1', 'anchorix', 'pol-ttl-1', 'p', '[]'::jsonb, 'tester')`,
		nil,
	}); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	// granted_at and expires_at are the same instant — CHECK
	// is strictly greater, so this MUST fail.
	err := execRawSQL(ctx, db, rawStmt{
		`INSERT INTO policy_waivers (
			id, organization_id, policy_definition_id, policy_rule_local_id,
			scope_kind, scope_id, reason,
			granted_by, granted_at, expires_at
		 ) VALUES (
			'pw-ttl-1', 'anchorix', 'pol-ttl-1', 'r1',
			'service', 'svc-x', 'tester',
			'tester', now(), now()
		 )`,
		nil,
	})
	if err == nil {
		t.Fatalf("expires_at == granted_at insert succeeded; CHECK should reject")
	}
	if !strings.Contains(err.Error(), "policy_waivers_expires_after_granted") {
		t.Fatalf("error %q does not mention expires_after_granted CHECK", err)
	}

	// granted_at in the future of expires_at — also rejected.
	err = execRawSQL(ctx, db, rawStmt{
		`INSERT INTO policy_waivers (
			id, organization_id, policy_definition_id, policy_rule_local_id,
			scope_kind, scope_id, reason,
			granted_by, granted_at, expires_at
		 ) VALUES (
			'pw-ttl-2', 'anchorix', 'pol-ttl-1', 'r1',
			'service', 'svc-x', 'tester',
			'tester', now(), now() - interval '1 day'
		 )`,
		nil,
	})
	if err == nil {
		t.Fatalf("expires_at < granted_at insert succeeded; CHECK should reject")
	}

	// Valid future expiry — must succeed.
	if err := execRawSQL(ctx, db, rawStmt{
		`INSERT INTO policy_waivers (
			id, organization_id, policy_definition_id, policy_rule_local_id,
			scope_kind, scope_id, reason,
			granted_by, granted_at, expires_at
		 ) VALUES (
			'pw-ttl-3', 'anchorix', 'pol-ttl-1', 'r1',
			'service', 'svc-x', 'tester',
			'tester', now(), now() + interval '30 days'
		 )`,
		nil,
	}); err != nil {
		t.Fatalf("valid waiver rejected: %v", err)
	}
}

// TestPartialUniqueIndexes pins the three partial unique
// indexes introduced in H-026A1: only one ACTIVE row per scope
// is allowed, but historical cleared rows do not block new
// inserts.
func TestPartialUniqueIndexes(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	seedCertificate(t, db, ctx, "cert-piu-1")
	seedService(t, db, ctx, "svc-piu-1")

	// ----- certificate_ownership_overrides_active_idx -----
	insertOverride := func(id string) error {
		return execRawSQL(ctx, db, rawStmt{
			`INSERT INTO certificate_ownership_overrides (
				id, organization_id, certificate_id, service_id,
				reason, set_by
			 ) VALUES ($1, 'anchorix', 'cert-piu-1', 'svc-piu-1', 'because', 'tester')`,
			[]any{id},
		})
	}
	if err := insertOverride("ovr-1"); err != nil {
		t.Fatalf("first active override insert: %v", err)
	}
	if err := insertOverride("ovr-2"); err == nil {
		t.Fatalf("second active override insert succeeded; partial unique index should reject")
	}

	if err := execRawSQL(ctx, db, rawStmt{
		`UPDATE certificate_ownership_overrides
		    SET cleared_at = now(), cleared_by = 'tester', cleared_reason = 'rotated'
		  WHERE id = 'ovr-1'`,
		nil,
	}); err != nil {
		t.Fatalf("clear first override: %v", err)
	}
	if err := insertOverride("ovr-2"); err != nil {
		t.Fatalf("override insert after clear: %v", err)
	}

	// ----- policy_assignments_active_idx -----
	seedPolicyDefinition(t, db, ctx, "pol-piu-1", "pol-piu-1", 1)
	insertAssignment := func(id string) error {
		return execRawSQL(ctx, db, rawStmt{
			`INSERT INTO policy_assignments (
				id, organization_id, policy_definition_id,
				scope_kind, scope_id, assigned_by
			 ) VALUES ($1, 'anchorix', 'pol-piu-1', 'service', 'svc-piu-1', 'tester')`,
			[]any{id},
		})
	}
	if err := insertAssignment("pa-1"); err != nil {
		t.Fatalf("first active assignment insert: %v", err)
	}
	if err := insertAssignment("pa-2"); err == nil {
		t.Fatalf("second active assignment insert succeeded; partial unique index should reject")
	}
	if err := execRawSQL(ctx, db, rawStmt{
		`UPDATE policy_assignments
		    SET cleared_at = now(), cleared_by = 'tester'
		  WHERE id = 'pa-1'`,
		nil,
	}); err != nil {
		t.Fatalf("clear first assignment: %v", err)
	}
	if err := insertAssignment("pa-2"); err != nil {
		t.Fatalf("assignment insert after clear: %v", err)
	}

	// ----- policy_waivers_active_idx -----
	insertWaiver := func(id string) error {
		return execRawSQL(ctx, db, rawStmt{
			`INSERT INTO policy_waivers (
				id, organization_id, policy_definition_id, policy_rule_local_id,
				scope_kind, scope_id, reason,
				granted_by, expires_at
			 ) VALUES (
				$1, 'anchorix', 'pol-piu-1', 'r1',
				'service', 'svc-piu-1', 'because',
				'tester', now() + interval '30 days'
			 )`,
			[]any{id},
		})
	}
	if err := insertWaiver("pw-1"); err != nil {
		t.Fatalf("first active waiver insert: %v", err)
	}
	if err := insertWaiver("pw-2"); err == nil {
		t.Fatalf("second active waiver insert succeeded; partial unique index should reject")
	}
	if err := execRawSQL(ctx, db, rawStmt{
		`UPDATE policy_waivers
		    SET cleared_at = now(), cleared_by = 'tester'
		  WHERE id = 'pw-1'`,
		nil,
	}); err != nil {
		t.Fatalf("clear first waiver: %v", err)
	}
	if err := insertWaiver("pw-2"); err != nil {
		t.Fatalf("waiver insert after clear: %v", err)
	}
}

// TestCompositeFKCrossOrgRejection pins the H-009 cross-org
// safety: every composite FK refuses a row whose organization
// id disagrees with the parent row's organization id. We pick
// one representative FK per new table family — adding a second
// organization is the minimum required to exercise the
// constraint.
func TestCompositeFKCrossOrgRejection(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := execRawSQL(ctx, db, rawStmt{
		`INSERT INTO organizations (id, name) VALUES ('other', 'Other')`, nil,
	}); err != nil {
		t.Fatalf("seed other org: %v", err)
	}

	// Tag in 'anchorix', tag_assignment claiming 'other' — must
	// fail (composite FK on (org, tag_id)).
	if err := execRawSQL(ctx, db, rawStmt{
		`INSERT INTO tags (id, organization_id, key, value)
		 VALUES ('tag-x', 'anchorix', 'env', 'prod')`, nil,
	}); err != nil {
		t.Fatalf("seed tag: %v", err)
	}
	err := execRawSQL(ctx, db, rawStmt{
		`INSERT INTO tag_assignments (
			id, organization_id, tag_id, target_type, target_id, assigned_by
		 ) VALUES (
			'ta-x', 'other', 'tag-x', 'service', 'whatever', 'tester'
		 )`, nil,
	})
	if err == nil {
		t.Fatalf("cross-org tag_assignments insert succeeded")
	}

	if err := execRawSQL(ctx, db, rawStmt{
		`INSERT INTO services (id, organization_id, slug, display_name)
		 VALUES ('svc-x', 'anchorix', 'svc-x', 'X')`, nil,
	}); err != nil {
		t.Fatalf("seed service: %v", err)
	}
	err = execRawSQL(ctx, db, rawStmt{
		`INSERT INTO ownership_rules (
			id, organization_id, name, service_id,
			precedence_tier, priority, match_kind, match_value, created_by
		 ) VALUES (
			'rule-x', 'other', 'r', 'svc-x',
			'fallback', 1000, 'fallback', '', 'tester'
		 )`, nil,
	})
	if err == nil {
		t.Fatalf("cross-org ownership_rule insert succeeded")
	}

	// service_groups self-FK: child claiming 'other' parent in
	// 'anchorix' must fail.
	if err := execRawSQL(ctx, db, rawStmt{
		`INSERT INTO service_groups (id, organization_id, slug, display_name)
		 VALUES ('sg-anc', 'anchorix', 'anc', 'Anc')`, nil,
	}); err != nil {
		t.Fatalf("seed parent group: %v", err)
	}
	err = execRawSQL(ctx, db, rawStmt{
		`INSERT INTO service_groups (id, organization_id, slug, display_name, parent_id)
		 VALUES ('sg-bad', 'other', 'bad', 'B', 'sg-anc')`, nil,
	})
	if err == nil {
		t.Fatalf("cross-org service_group parent_id insert succeeded")
	}
}

// TestServiceGroupParentFK pins the self-FK on service_groups:
// a row's parent_id MUST resolve to an existing service_group
// row in the same organization, with ON DELETE RESTRICT
// preventing accidental dangling references.
func TestServiceGroupParentFK(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := execRawSQL(ctx, db, rawStmt{
		`INSERT INTO service_groups (id, organization_id, slug, display_name, parent_id)
		 VALUES ('sg-orphan', 'anchorix', 'orphan', 'Orphan', 'sg-missing')`, nil,
	})
	if err == nil {
		t.Fatalf("orphan parent insert succeeded; FK should reject")
	}

	if err := execRawSQL(ctx, db, rawStmt{
		`INSERT INTO service_groups (id, organization_id, slug, display_name)
		 VALUES ('sg-root', 'anchorix', 'root', 'Root')`, nil,
	}); err != nil {
		t.Fatalf("root insert: %v", err)
	}
	if err := execRawSQL(ctx, db, rawStmt{
		`INSERT INTO service_groups (id, organization_id, slug, display_name, parent_id)
		 VALUES ('sg-child', 'anchorix', 'child', 'Child', 'sg-root')`, nil,
	}); err != nil {
		t.Fatalf("child insert: %v", err)
	}

	err = execRawSQL(ctx, db, rawStmt{
		`DELETE FROM service_groups WHERE id = 'sg-root'`, nil,
	})
	if err == nil {
		t.Fatalf("delete of referenced parent succeeded; RESTRICT should reject")
	}
}

// ----- raw SQL helpers (file-local) -----

// rawStmt is a parameterized SQL statement for the
// schema-correctness tests that need to assert DB-level
// behaviors (CHECK constraints, partial indexes, FKs) outside
// the repository layer.
type rawStmt struct {
	sql  string
	args []any
}

func execRawSQL(ctx context.Context, db *postgres.DB, s rawStmt) error {
	return db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, s.sql, s.args...)
		return err
	})
}

func seedCertificate(t *testing.T, db *postgres.DB, ctx context.Context, id string) {
	t.Helper()
	const q = `
		INSERT INTO certificates (
			id, organization_id, fingerprint_sha256, subject, issuer,
			serial_number_hex, signature_algorithm, public_key_algorithm,
			public_key_bits, not_before, not_after, pem
		) VALUES (
			$1, 'anchorix', $1, 'CN=test', 'CN=test-ca',
			'01', 'SHA256-RSA', 'RSA',
			2048, now() - interval '30 days', now() + interval '365 days',
			'-----BEGIN CERTIFICATE-----' || E'\n' || 'MIIBxxx' || E'\n' || '-----END CERTIFICATE-----'
		)`
	if err := execRawSQL(ctx, db, rawStmt{q, []any{id}}); err != nil {
		t.Fatalf("seed certificate %s: %v", id, err)
	}
}

func seedService(t *testing.T, db *postgres.DB, ctx context.Context, id string) {
	t.Helper()
	const q = `
		INSERT INTO services (id, organization_id, slug, display_name)
		 VALUES ($1, 'anchorix', $1, 'svc')`
	if err := execRawSQL(ctx, db, rawStmt{q, []any{id}}); err != nil {
		t.Fatalf("seed service %s: %v", id, err)
	}
}

func seedPolicyDefinition(t *testing.T, db *postgres.DB, ctx context.Context, id, slug string, version int) {
	t.Helper()
	const q = `
		INSERT INTO policy_definitions (
			id, organization_id, slug, display_name, rules, version, created_by
		) VALUES ($1, 'anchorix', $2, 'pol', '[]'::jsonb, $3, 'tester')`
	if err := execRawSQL(ctx, db, rawStmt{q, []any{id, slug, version}}); err != nil {
		t.Fatalf("seed policy definition %s: %v", id, err)
	}
}
