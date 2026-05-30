//go:build integration

package integration

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/clock"
	"github.com/kidcarmi/anchorix/backend/internal/governance"
	"github.com/kidcarmi/anchorix/backend/internal/governance/ownership"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// --- instrumented repo wrapper ----------------------------------------

// countingOwnershipRepo wraps the real OwnershipRepository and records
// every GetCertificateOwnershipByCertificateIDs call's batch contents.
// Used to assert the streaming bound (batch size <= signal pageSize)
// and the no-orphan-queried property.
type countingOwnershipRepo struct {
	governance.OwnershipRepository
	mu         sync.Mutex
	lookupArgs [][]string // copies of certIDs from each call
}

func (r *countingOwnershipRepo) GetCertificateOwnershipByCertificateIDs(ctx context.Context, organizationID string, certIDs []string) (map[string]governance.CertificateOwnership, error) {
	r.mu.Lock()
	captured := append([]string(nil), certIDs...)
	r.lookupArgs = append(r.lookupArgs, captured)
	r.mu.Unlock()
	return r.OwnershipRepository.GetCertificateOwnershipByCertificateIDs(ctx, organizationID, certIDs)
}

func (r *countingOwnershipRepo) Snapshot() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]string, len(r.lookupArgs))
	for i, args := range r.lookupArgs {
		out[i] = append([]string(nil), args...)
	}
	return out
}

func newOwnershipServiceWithCountingRepo(t *testing.T, db *postgres.DB) (*ownership.Service, *countingOwnershipRepo) {
	t.Helper()
	counter := &countingOwnershipRepo{OwnershipRepository: postgres.NewOwnershipRepository(db)}
	repo := &governance.Repo{
		Ownership:     counter,
		Policy:        postgres.NewPolicyRepository(db),
		RecomputeRuns: postgres.NewGovernanceRecomputeRunsRepository(db),
	}
	svc, err := ownership.NewService(repo, db, postgres.NewAuditRecorder(db, clock.System{}),
		clock.System{}, postgres.NewOwnershipRuleTargetResolver(db), ownership.ServiceConfig{})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, counter
}

// --- streaming bound ---------------------------------------------------

// TestRecomputeLookupBatchSizeBoundedByPageSize proves the
// prior-ownership lookup is called once per signal page with a batch
// strictly ≤ the signal pageSize. Streaming property: never the
// fleet in one batch; never an unbounded read.
func TestRecomputeLookupBatchSizeBoundedByPageSize(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedService(t, db, ctx, "svc-bound")
	seedOwnershipRule(t, db, ctx, "rule-bound", "svc-bound",
		governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.bound.x", 100)
	const fleet = 10
	for i := 1; i <= fleet; i++ {
		id := fmt.Sprintf("cert-bound-%02d", i)
		seedCertMeta(t, db, ctx, "anchorix", id, "CN=x", "CN=ca", []string{"h" + fmt.Sprint(i) + ".bound.x"})
	}

	const pageSize = 3
	svc, counter := newOwnershipServiceWithCountingRepo(t, db)
	svc.SetPageSizeForTest(pageSize)

	if _, err := svc.Recompute(ctx, "anchorix", "op"); err != nil {
		t.Fatalf("recompute: %v", err)
	}
	args := counter.Snapshot()
	// fleet=10, pageSize=3 → pages: 3+3+3+1 = 4 lookups.
	if len(args) != 4 {
		t.Fatalf("lookup calls = %d; want 4 (ceil(10/3))", len(args))
	}
	totalCerts := 0
	for i, batch := range args {
		if len(batch) > pageSize {
			t.Fatalf("call %d batch size = %d; want <= %d (pageSize)", i, len(batch), pageSize)
		}
		totalCerts += len(batch)
	}
	if totalCerts != fleet {
		t.Fatalf("total cert ids across batches = %d; want %d (each cert visited exactly once)", totalCerts, fleet)
	}
}

// TestRecomputeNoFleetWideLookupInOneBatch is an explicit single-page
// boundedness check independent of page-count arithmetic: with a
// large pageSize and a tiny fleet, the lookup is called once and the
// batch size equals the fleet — never larger. This rules out a
// regression that might lazily concatenate batches across pages.
func TestRecomputeNoFleetWideLookupInOneBatch(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedService(t, db, ctx, "svc-onepage")
	seedOwnershipRule(t, db, ctx, "rule-onepage", "svc-onepage",
		governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.onepage.x", 100)
	for i := 1; i <= 3; i++ {
		seedCertMeta(t, db, ctx, "anchorix", fmt.Sprintf("cert-onepage-%d", i), "CN=x", "CN=ca", []string{fmt.Sprintf("h%d.onepage.x", i)})
	}

	svc, counter := newOwnershipServiceWithCountingRepo(t, db)
	svc.SetPageSizeForTest(500) // production default

	if _, err := svc.Recompute(ctx, "anchorix", "op"); err != nil {
		t.Fatalf("recompute: %v", err)
	}
	args := counter.Snapshot()
	if len(args) != 1 {
		t.Fatalf("lookup calls = %d; want exactly 1 for a fleet smaller than pageSize", len(args))
	}
	if len(args[0]) != 3 {
		t.Fatalf("single-page batch size = %d; want 3 (= fleet)", len(args[0]))
	}
}

// --- collation hazard --------------------------------------------------

// TestRecomputeWithCaseSensitiveCollationHazardIDs proves the
// recompute classifies cert IDs whose Go byte order and PostgreSQL
// en_US.UTF-8 collation order DIVERGE.
//
// Cert IDs use mixed case + hyphens — the classic shape where glibc
// en_US.UTF-8 sorts case-insensitively (`Aa Bb Aa` interleaved) but
// Go byte order sorts uppercase strictly before lowercase
// (`A B a b`). The pre-refactor merge — which Go-side compared
// `ownCur.CertificateID < sig.CertificateID` while SQL ORDER BY ran
// under the DB collation — could mis-pair signals with prior
// ownership for this fixture. The post-refactor set-lookup keys on
// `cert_id` opaque-string equality with NO Go-side ordering, so it
// must classify every cert correctly regardless of byte/collation
// divergence.
func TestRecomputeWithCaseSensitiveCollationHazardIDs(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedService(t, db, ctx, "svc-haz")
	seedOwnershipRule(t, db, ctx, "rule-haz", "svc-haz",
		governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.haz.x", 100)

	// IDs intentionally chosen so byte order and en_US.UTF-8 differ:
	// byte order: Cert-A-1 < Cert-A-2 < Cert-B-1 < Cert-B-2 < cert-A-1 < cert-A-2 < cert-B-1 < cert-B-2
	// en_US:     Cert-A-1 < cert-A-1 < Cert-A-2 < cert-A-2 < Cert-B-1 < cert-B-1 < Cert-B-2 < cert-B-2 (case-insensitive, interleaved)
	certIDs := []string{
		"Cert-A-1", "cert-A-2",
		"Cert-B-1", "cert-B-2",
		"Cert-A-2", "cert-A-1",
	}
	for _, id := range certIDs {
		seedCertMeta(t, db, ctx, "anchorix", id, "CN="+id, "CN=ca", []string{"h." + id + ".haz.x"})
	}

	svc := ownershipService(t, db, 0)
	svc.SetPageSizeForTest(2) // force multi-page walks

	// Pass 1: every cert becomes owned by svc-haz.
	res1, err := svc.Recompute(ctx, "anchorix", "op")
	if err != nil {
		t.Fatalf("pass1: %v", err)
	}
	if res1.EvaluatedCertificates != len(certIDs) || res1.BecameOwned != len(certIDs) {
		t.Fatalf("pass1 res = %+v; want evaluated=becameOwned=%d", res1, len(certIDs))
	}

	// Pass 2: prior exists for every cert; the post-refactor set
	// lookup must find each one regardless of byte/collation divergence.
	// Any miss would surface as a flip (prior was overridden→matched,
	// now becomes matched fresh) or a wrong unchanged count.
	res2, err := svc.Recompute(ctx, "anchorix", "op")
	if err != nil {
		t.Fatalf("pass2: %v", err)
	}
	if res2.UnchangedCertificates != len(certIDs) || res2.ChangedCertificates != 0 {
		t.Fatalf("pass2 res = %+v; want unchanged=%d changed=0 (every prior must be found)", res2, len(certIDs))
	}
	for _, id := range certIDs {
		dec, svcID := certOwnershipDecision(t, db, ctx, "anchorix", id)
		if dec != governance.DecisionMatched {
			t.Fatalf("%s decision = %s; want matched", id, dec)
		}
		if svcID != "svc-haz" {
			t.Fatalf("%s service_id = %q; want svc-haz", id, svcID)
		}
	}
}

// --- orphan ownership row is not queried -------------------------------

// TestRecomputeOrphanOwnershipNotQueriedUnderNewMechanism is a
// behavior pin of the H-030 design's structural property: under the
// new set-lookup mechanism, orphan prior-ownership rows (whose cert
// has been deleted) are NEVER queried. The counting wrapper records
// every batch of cert IDs passed to GetCertificateOwnershipByCertificateIDs;
// the orphan id must not appear in any batch.
//
// Mechanism: the same FK-bypass orphan-injection technique as
// TestOwnershipMergeSkipLoopHandlesOrphanOwnershipRows (existing).
// What's new is the assertion: not "the recompute does not flip a
// live decision because of the orphan" (the existing test pins
// that), but "the recompute does not ASK about the orphan at all".
// That makes the structural property machine-verifiable.
func TestRecomputeOrphanOwnershipNotQueriedUnderNewMechanism(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedService(t, db, ctx, "svc-orph")
	seedOwnershipRule(t, db, ctx, "rule-orph", "svc-orph",
		governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.orph.x", 100)
	for i := 1; i <= 3; i++ {
		seedCertMeta(t, db, ctx, "anchorix", fmt.Sprintf("cert-orph-h-%d", i), "CN=x", "CN=ca",
			[]string{fmt.Sprintf("h%d.orph.x", i)})
	}
	// Pass 1 with the real repo: classify all three.
	svc := ownershipService(t, db, 0)
	if _, err := svc.Recompute(ctx, "anchorix", "op"); err != nil {
		t.Fatalf("pass1: %v", err)
	}
	// Bypass FK cascade so DELETE cert leaves the ownership row as
	// orphan. SET LOCAL session_replication_role='replica' is tx-scoped.
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SET LOCAL session_replication_role = 'replica'"); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`DELETE FROM certificates WHERE organization_id='anchorix' AND id = 'cert-orph-h-2'`)
		return err
	}); err != nil {
		t.Fatalf("orphan delete: %v", err)
	}

	// Pass 2 with the counting wrapper: assert the orphan id
	// (cert-orph-h-2) is NEVER passed to the lookup.
	countingSvc, counter := newOwnershipServiceWithCountingRepo(t, db)
	countingSvc.SetPageSizeForTest(2)
	if _, err := countingSvc.Recompute(ctx, "anchorix", "op"); err != nil {
		t.Fatalf("pass2: %v", err)
	}
	for callIdx, batch := range counter.Snapshot() {
		for _, id := range batch {
			if id == "cert-orph-h-2" {
				t.Fatalf("call %d batch contained orphan cert id %q — H-030 contract violated; the orphan must never be queried under the new set-lookup mechanism", callIdx, id)
			}
		}
	}
}

// --- first-run semantic for one cert ----------------------------------

// TestRecomputeAbsentPriorTreatedAsFirstRunForThatCert proves a
// single cert with no prior ownership row is classified fresh and
// the recompute correctly emits a becameOwned for it — while certs
// with prior ownership rows are unchanged. This pins the "absent
// from prior map → fresh classification" branch of streamAndDecide.
func TestRecomputeAbsentPriorTreatedAsFirstRunForThatCert(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedService(t, db, ctx, "svc-fr")
	seedOwnershipRule(t, db, ctx, "rule-fr", "svc-fr",
		governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.fr.x", 100)
	for i := 1; i <= 3; i++ {
		seedCertMeta(t, db, ctx, "anchorix", fmt.Sprintf("cert-fr-%d", i), "CN=x", "CN=ca",
			[]string{fmt.Sprintf("h%d.fr.x", i)})
	}
	svc := ownershipService(t, db, 0)
	svc.SetPageSizeForTest(2)
	if _, err := svc.Recompute(ctx, "anchorix", "op"); err != nil {
		t.Fatalf("pass1: %v", err)
	}
	// Add a fourth cert AFTER the first recompute; only this cert has
	// no prior ownership row.
	seedCertMeta(t, db, ctx, "anchorix", "cert-fr-new", "CN=x", "CN=ca", []string{"hnew.fr.x"})

	res, err := svc.Recompute(ctx, "anchorix", "op")
	if err != nil {
		t.Fatalf("pass2: %v", err)
	}
	if res.EvaluatedCertificates != 4 {
		t.Fatalf("evaluated = %d; want 4", res.EvaluatedCertificates)
	}
	if res.BecameOwned != 1 {
		t.Fatalf("becameOwned = %d; want 1 (only cert-fr-new is new)", res.BecameOwned)
	}
	if res.UnchangedCertificates != 3 {
		t.Fatalf("unchanged = %d; want 3 (the three priors)", res.UnchangedCertificates)
	}
	// cert-fr-new is owned by svc-fr after the recompute.
	dec, svcID := certOwnershipDecision(t, db, ctx, "anchorix", "cert-fr-new")
	if dec != governance.DecisionMatched || svcID != "svc-fr" {
		t.Fatalf("cert-fr-new ownership = %s/%s; want matched/svc-fr", dec, svcID)
	}
}
