//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/governance"
)

// TestRecomputeCollationIndependenceWithUUIDStyleIDs proves the H-030
// refactor's central property end-to-end: the recompute produces
// correct decisions for cert ids whose Go byte-order and PostgreSQL
// en_US.UTF-8 collation order would diverge.
//
// The fixture uses UUIDv7-style ids (`8-4-4-4-12` hyphenated, mixed
// digit / lowercase letters), interleaved with the same-prefix ids
// the existing recompute test uses. Under the previous two-stream
// merge, these ids' Go byte order disagreed with glibc en_US.UTF-8
// collation order (glibc ignores hyphens for most positions, so the
// hyphen / digit boundary triggers a different sort). After the
// refactor, no Go-side cert_id comparison remains — the prior
// ownership lookup is keyed on `= ANY($2::text[])` and the result is
// a map. The fixture would have hit the merge-misalignment hazard
// pre-refactor; post-refactor it must produce the correct decision
// for every cert.
func TestRecomputeCollationIndependenceWithUUIDStyleIDs(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedService(t, db, ctx, "svc-col")
	// A SAN-pattern rule the fixture certs all match so every cert
	// has a determinate owner.
	seedOwnershipRule(t, db, ctx, "rule-col", "svc-col",
		governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.col.x", 100)

	// UUIDv7-style cert ids deliberately ordered so byte order vs
	// glibc collation order can diverge. We don't have to be exhaustive
	// about which collation diverges where — the point is that the
	// refactor does NOT depend on byte/collation agreement, so any of
	// these ids work even if they would have been a hazard before.
	certIDs := []string{
		"018f3a-2b-4c-7d-cert-aa", // hyphen-heavy lowercase
		"018F3A-2B-4C-7D-CERT-BB", // mixed case
		"018f3a-2b-4c-7d-cert-cc",
		"018F3A-2B-4C-7D-CERT-DD",
		"cert-vanilla-01", // plain ascii control
	}
	for _, id := range certIDs {
		seedCertMeta(t, db, ctx, "anchorix", id, "CN="+id, "CN=ca", []string{"h." + id + ".col.x"})
	}

	svc := ownershipService(t, db, 0)
	svc.SetPageSizeForTest(2) // force the inner loop to do multiple lookups

	// Pass 1: every cert classifies as owned by svc-col.
	res1, err := svc.Recompute(ctx, "anchorix", "op")
	if err != nil {
		t.Fatalf("pass1: %v", err)
	}
	if res1.EvaluatedCertificates != len(certIDs) {
		t.Fatalf("pass1 evaluated = %d; want %d (each cert visited exactly once)", res1.EvaluatedCertificates, len(certIDs))
	}
	if res1.BecameOwned != len(certIDs) {
		t.Fatalf("pass1 becameOwned = %d; want %d", res1.BecameOwned, len(certIDs))
	}
	if !res1.FirstRun {
		t.Fatal("pass1 firstRun = false; want true on a clean fixture")
	}

	// Pass 2: prior ownership exists for every cert; nothing changes.
	// This is the canonical post-refactor success criterion — the
	// per-page set lookup must find each cert's prior row regardless
	// of byte/collation order.
	res2, err := svc.Recompute(ctx, "anchorix", "op")
	if err != nil {
		t.Fatalf("pass2: %v", err)
	}
	if res2.EvaluatedCertificates != len(certIDs) {
		t.Fatalf("pass2 evaluated = %d; want %d", res2.EvaluatedCertificates, len(certIDs))
	}
	if res2.UnchangedCertificates != len(certIDs) {
		t.Fatalf("pass2 unchanged = %d; want %d (prior ownership lookup must match every cert)", res2.UnchangedCertificates, len(certIDs))
	}
	if res2.ChangedCertificates != 0 {
		t.Fatalf("pass2 changed = %d; want 0", res2.ChangedCertificates)
	}
	if res2.FirstRun {
		t.Fatal("pass2 firstRun = true; want false (prior ownership exists)")
	}

	// Every cert's owner is svc-col.
	for _, id := range certIDs {
		dec, svcID := certOwnershipDecision(t, db, ctx, "anchorix", id)
		if dec != governance.DecisionMatched {
			t.Fatalf("%s decision = %s; want matched", id, dec)
		}
		if svcID != "svc-col" {
			t.Fatalf("%s service_id = %q; want svc-col", id, svcID)
		}
	}
}

// TestRecomputeDeterministicAcrossRepeatedRuns proves repeated
// recomputes over a stable input produce stable outputs — the
// per-page set-lookup approach is deterministic.
func TestRecomputeDeterministicAcrossRepeatedRuns(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	seedService(t, db, ctx, "svc-det")
	seedOwnershipRule(t, db, ctx, "rule-det", "svc-det",
		governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.det.x", 100)
	const fleet = 10
	for i := 0; i < fleet; i++ {
		id := "cert-det-" + string(rune('a'+i))
		seedCertMeta(t, db, ctx, "anchorix", id, "CN="+id, "CN=ca", []string{"h." + id + ".det.x"})
	}

	svc := ownershipService(t, db, 0)
	svc.SetPageSizeForTest(3) // multi-page walks

	// Run 1 + Run 2 + Run 3 all over the same stable input. We compare
	// via persisted state, not the per-run summary struct.
	for i := 0; i < 3; i++ {
		if _, err := svc.Recompute(ctx, "anchorix", "op"); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}

	// Persistent state determinism: every cert is owned by svc-det,
	// every cert has exactly one ownership row and one current
	// explanation. (Multiple explanations may exist if a decision
	// flipped, which it didn't — so explanation count == ownership
	// count.)
	if got := scalarInt(t, db, ctx, `SELECT count(*) FROM certificate_ownership WHERE organization_id='anchorix'`); got != fleet {
		t.Fatalf("ownership rows = %d; want %d after stable repeated runs", got, fleet)
	}
	if got := scalarInt(t, db, ctx, `SELECT count(*) FROM certificate_ownership WHERE organization_id='anchorix' AND service_id='svc-det'`); got != fleet {
		t.Fatalf("owned-by-svc-det rows = %d; want %d", got, fleet)
	}
	// On stable inputs, only the FIRST run writes explanations; runs
	// 2 and 3 are no-ops on the explanation table. So the explanation
	// row count equals the fleet size.
	if got := scalarInt(t, db, ctx, `SELECT count(*) FROM ownership_match_explanations WHERE organization_id='anchorix'`); got != fleet {
		t.Fatalf("explanation rows = %d; want %d (stable input: no flips, no extra explanations)", got, fleet)
	}
}
