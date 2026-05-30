//go:build integration

package integration

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/governance"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// --- helpers -----------------------------------------------------------

// seedExpiringOverride seeds a cert + an active override with the
// supplied expires_at, in the given org. expiresAt = nil seeds an
// override without an expiry (the "no expiry → excluded" case).
func seedExpiringOverride(t *testing.T, db *postgres.DB, ctx context.Context, org, overrideID, certID, serviceID string, expiresAt *time.Time) {
	t.Helper()
	repo := postgres.NewOwnershipRepository(db)
	if err := repo.CreateOwnershipOverride(ctx, &governance.CertificateOwnershipOverride{
		ID:             overrideID,
		OrganizationID: org,
		CertificateID:  certID,
		ServiceID:      serviceID,
		Reason:         "pin",
		SetBy:          "tester",
		SetAt:          time.Now().UTC().Add(-2 * time.Hour),
		ExpiresAt:      expiresAt,
	}); err != nil {
		t.Fatalf("create override %s in %s: %v", overrideID, org, err)
	}
}

// pastTime is a convenience helper for "expires_at strictly before now".
func pastTime(now time.Time, deltaHours int) *time.Time {
	t := now.Add(-time.Duration(deltaHours) * time.Hour)
	return &t
}

// futureTime is a convenience helper for "expires_at strictly after now".
func futureTime(now time.Time, deltaHours int) *time.Time {
	t := now.Add(time.Duration(deltaHours) * time.Hour)
	return &t
}

// --- filter semantics --------------------------------------------------

// TestListExpiringOverridesPagedReturnsOnlyExpiredActive proves the
// page's filter: only active (cleared_at IS NULL) overrides whose
// expires_at is non-NULL and <= now are returned. Future expiry,
// no-expiry, and cleared overrides are all excluded.
func TestListExpiringOverridesPagedReturnsOnlyExpiredActive(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	now := time.Now().UTC()

	seedService(t, db, ctx, "svc-exp")
	for _, c := range []string{"cert-a", "cert-b", "cert-c", "cert-d"} {
		seedCertificate(t, db, ctx, c)
	}
	seedExpiringOverride(t, db, ctx, "anchorix", "exp-past", "cert-a", "svc-exp", pastTime(now, 1))     // expired + active → in
	seedExpiringOverride(t, db, ctx, "anchorix", "exp-future", "cert-b", "svc-exp", futureTime(now, 1)) // future → out
	seedExpiringOverride(t, db, ctx, "anchorix", "exp-none", "cert-c", "svc-exp", nil)                  // no expiry → out
	seedExpiringOverride(t, db, ctx, "anchorix", "exp-cleared", "cert-d", "svc-exp", pastTime(now, 1))  // expired but cleared → out
	repo := postgres.NewOwnershipRepository(db)
	if err := repo.ClearOwnershipOverride(ctx, "anchorix", "exp-cleared", "tester", "done", now); err != nil {
		t.Fatalf("clear: %v", err)
	}

	got, err := repo.ListExpiringOverridesPaged(ctx, "anchorix", now, "", 100)
	if err != nil {
		t.Fatalf("ListExpiringOverridesPaged: %v", err)
	}
	if len(got) != 1 || got[0].ID != "exp-past" {
		t.Fatalf("got = %+v; want only exp-past", got)
	}
}

// TestListExpiringOverridesPagedCutoffBoundary proves the cutoff uses
// inclusive <=: a row whose expires_at is exactly now is selected.
// The check is done at the SQL primitive level by reading back a
// seeded expires_at and passing it as the `now` cutoff, so wall-clock
// drift between seed and query cannot affect the comparison.
func TestListExpiringOverridesPagedCutoffBoundary(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedService(t, db, ctx, "svc-exp")
	seedCertificate(t, db, ctx, "cert-eq")
	expiry := time.Now().UTC().Add(-time.Hour)
	seedExpiringOverride(t, db, ctx, "anchorix", "exp-eq", "cert-eq", "svc-exp", &expiry)

	// Read the stored expires_at back so the cutoff matches it exactly.
	var stored time.Time
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT expires_at FROM certificate_ownership_overrides WHERE id='exp-eq'`).Scan(&stored)
	}); err != nil {
		t.Fatalf("read expires_at: %v", err)
	}

	repo := postgres.NewOwnershipRepository(db)
	// cutoff == stored expires_at → row IS selected (inclusive <=).
	got, err := repo.ListExpiringOverridesPaged(ctx, "anchorix", stored, "", 100)
	if err != nil {
		t.Fatalf("at-cutoff: %v", err)
	}
	if len(got) != 1 || got[0].ID != "exp-eq" {
		t.Fatalf("at-cutoff got = %+v; want exp-eq (inclusive <= boundary)", got)
	}

	// cutoff < stored by 1ns → row is NOT selected.
	got2, err := repo.ListExpiringOverridesPaged(ctx, "anchorix", stored.Add(-time.Nanosecond), "", 100)
	if err != nil {
		t.Fatalf("before-cutoff: %v", err)
	}
	if len(got2) != 0 {
		t.Fatalf("before-cutoff got = %+v; want empty (row strictly after cutoff is kept)", got2)
	}
}

// --- cross-org isolation ----------------------------------------------

// TestListExpiringOverridesPagedCrossOrgIsolation proves the page reads
// only the requested org's rows even when an identical fixture exists
// in another org.
func TestListExpiringOverridesPagedCrossOrgIsolation(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	now := time.Now().UTC()

	seedOrganization(t, db, "other-org", "Other Org")
	seedService(t, db, ctx, "svc-exp")
	// Seed an other-org service + 2 other-org certs directly: the
	// helpers hardcode organization_id='anchorix', and adding org-aware
	// helpers is out of scope for PR-1 (used in one cross-org test).
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO services (id, organization_id, slug, display_name) VALUES ('svc-exp-other','other-org','svc-exp-other','Svc Other')`,
		); err != nil {
			return err
		}
		for _, c := range []string{"cert-o1", "cert-o2"} {
			if _, err := tx.Exec(ctx, `
				INSERT INTO certificates (
					id, organization_id, fingerprint_sha256, subject, issuer,
					serial_number_hex, signature_algorithm, public_key_algorithm,
					public_key_bits, not_before, not_after, pem
				) VALUES ($1, 'other-org', $1, 'CN=test', 'CN=test-ca',
					'01', 'SHA256-RSA', 'RSA',
					2048, now() - interval '30 days', now() + interval '365 days',
					'-----BEGIN CERTIFICATE-----' || E'\n' || 'MIIBxxx' || E'\n' || '-----END CERTIFICATE-----'
				)`, c); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed other-org rows: %v", err)
	}

	// anchorix: one expired override; other-org: two expired overrides.
	seedCertificate(t, db, ctx, "cert-a1")
	seedExpiringOverride(t, db, ctx, "anchorix", "exp-a1", "cert-a1", "svc-exp", pastTime(now, 1))
	seedExpiringOverride(t, db, ctx, "other-org", "exp-o1", "cert-o1", "svc-exp-other", pastTime(now, 1))
	seedExpiringOverride(t, db, ctx, "other-org", "exp-o2", "cert-o2", "svc-exp-other", pastTime(now, 1))

	repo := postgres.NewOwnershipRepository(db)
	gotA, err := repo.ListExpiringOverridesPaged(ctx, "anchorix", now, "", 100)
	if err != nil {
		t.Fatalf("anchorix: %v", err)
	}
	if len(gotA) != 1 || gotA[0].ID != "exp-a1" {
		t.Fatalf("anchorix got = %+v; want [exp-a1]", gotA)
	}
	gotB, err := repo.ListExpiringOverridesPaged(ctx, "other-org", now, "", 100)
	if err != nil {
		t.Fatalf("other-org: %v", err)
	}
	if len(gotB) != 2 || gotB[0].OrganizationID != "other-org" || gotB[1].OrganizationID != "other-org" {
		t.Fatalf("other-org got = %+v; want 2 rows in other-org", gotB)
	}
}

// --- cursor pagination -------------------------------------------------

// TestListExpiringOverridesPagedCursorWalk proves the walk completes
// deterministically: each cert is visited exactly once, cursor advances
// strictly, the final page has fewer rows than the page size.
func TestListExpiringOverridesPagedCursorWalk(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	now := time.Now().UTC()

	seedService(t, db, ctx, "svc-exp")
	const fleet = 7
	for i := 1; i <= fleet; i++ {
		certID := fmt.Sprintf("cert-%02d", i)
		seedCertificate(t, db, ctx, certID)
		seedExpiringOverride(t, db, ctx, "anchorix", fmt.Sprintf("ovr-%02d", i), certID, "svc-exp", pastTime(now, 1))
	}

	repo := postgres.NewOwnershipRepository(db)
	cursor := ""
	const pageSize = 3
	var seen []string
	for pages := 0; pages < 10; pages++ {
		got, err := repo.ListExpiringOverridesPaged(ctx, "anchorix", now, cursor, pageSize)
		if err != nil {
			t.Fatalf("page (cursor=%q): %v", cursor, err)
		}
		if len(got) == 0 {
			break
		}
		for _, ovr := range got {
			if ovr.CertificateID <= cursor {
				t.Fatalf("cursor did not advance: cursor=%q got cert=%q", cursor, ovr.CertificateID)
			}
			seen = append(seen, ovr.CertificateID)
		}
		cursor = got[len(got)-1].CertificateID
		if len(got) < pageSize {
			break
		}
	}
	if len(seen) != fleet {
		t.Fatalf("seen %d certs; want %d (each exactly once)", len(seen), fleet)
	}
	for i := 1; i <= fleet; i++ {
		want := fmt.Sprintf("cert-%02d", i)
		if seen[i-1] != want {
			t.Fatalf("seen[%d] = %q; want %q (deterministic order)", i-1, seen[i-1], want)
		}
	}
}

// TestListExpiringOverridesPagedCursorExclusive proves cursor semantics
// are strictly exclusive: passing a cert id as the cursor never returns
// that id again.
func TestListExpiringOverridesPagedCursorExclusive(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	now := time.Now().UTC()

	seedService(t, db, ctx, "svc-exp")
	for _, c := range []string{"cert-a", "cert-b", "cert-c"} {
		seedCertificate(t, db, ctx, c)
	}
	seedExpiringOverride(t, db, ctx, "anchorix", "ovr-a", "cert-a", "svc-exp", pastTime(now, 1))
	seedExpiringOverride(t, db, ctx, "anchorix", "ovr-b", "cert-b", "svc-exp", pastTime(now, 1))
	seedExpiringOverride(t, db, ctx, "anchorix", "ovr-c", "cert-c", "svc-exp", pastTime(now, 1))

	repo := postgres.NewOwnershipRepository(db)
	got, err := repo.ListExpiringOverridesPaged(ctx, "anchorix", now, "cert-a", 100)
	if err != nil {
		t.Fatalf("ListExpiringOverridesPaged: %v", err)
	}
	for _, ovr := range got {
		if ovr.CertificateID == "cert-a" {
			t.Fatalf("cursor=cert-a returned cert-a (cursor must be exclusive): %+v", got)
		}
	}
	if len(got) != 2 || got[0].CertificateID != "cert-b" || got[1].CertificateID != "cert-c" {
		t.Fatalf("got = %+v; want [cert-b, cert-c]", got)
	}
}

// --- page size bounds --------------------------------------------------

// TestListExpiringOverridesPagedSizeZeroUsesDefault proves pageSize <= 0
// falls back to DefaultExpiringOverridesPageSize rather than returning
// zero rows. With a small fleet < default, the whole fleet is returned.
func TestListExpiringOverridesPagedSizeZeroUsesDefault(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	now := time.Now().UTC()

	seedService(t, db, ctx, "svc-exp")
	const fleet = 5
	for i := 0; i < fleet; i++ {
		certID := fmt.Sprintf("cert-%02d", i)
		seedCertificate(t, db, ctx, certID)
		seedExpiringOverride(t, db, ctx, "anchorix", fmt.Sprintf("ovr-%02d", i), certID, "svc-exp", pastTime(now, 1))
	}

	repo := postgres.NewOwnershipRepository(db)
	got, err := repo.ListExpiringOverridesPaged(ctx, "anchorix", now, "", 0)
	if err != nil {
		t.Fatalf("pageSize=0: %v", err)
	}
	if len(got) != fleet {
		t.Fatalf("pageSize=0 got %d rows; want %d (default >= fleet)", len(got), fleet)
	}
	got2, err := repo.ListExpiringOverridesPaged(ctx, "anchorix", now, "", -5)
	if err != nil {
		t.Fatalf("pageSize=-5: %v", err)
	}
	if len(got2) != fleet {
		t.Fatalf("pageSize=-5 got %d rows; want %d (default >= fleet)", len(got2), fleet)
	}
}

// TestListExpiringOverridesPagedSizeAboveMaxIsClamped proves pageSize >
// MaxExpiringOverridesPageSize is clamped down. We seed Max+10 expired
// overrides and request a huge pageSize; at most Max rows come back.
func TestListExpiringOverridesPagedSizeAboveMaxIsClamped(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	now := time.Now().UTC()

	seedService(t, db, ctx, "svc-exp")
	const overMax = postgres.MaxExpiringOverridesPageSize + 10
	for i := 0; i < overMax; i++ {
		certID := fmt.Sprintf("cert-%04d", i)
		seedCertificate(t, db, ctx, certID)
		seedExpiringOverride(t, db, ctx, "anchorix", fmt.Sprintf("ovr-%04d", i), certID, "svc-exp", pastTime(now, 1))
	}

	repo := postgres.NewOwnershipRepository(db)
	got, err := repo.ListExpiringOverridesPaged(ctx, "anchorix", now, "", 100_000)
	if err != nil {
		t.Fatalf("oversize pageSize: %v", err)
	}
	if len(got) > postgres.MaxExpiringOverridesPageSize {
		t.Fatalf("got %d rows; want <= %d (clamped)", len(got), postgres.MaxExpiringOverridesPageSize)
	}
	if len(got) != postgres.MaxExpiringOverridesPageSize {
		t.Fatalf("got %d rows; want exactly %d (clamp to max with fleet > max)", len(got), postgres.MaxExpiringOverridesPageSize)
	}
}

// --- empty inputs ------------------------------------------------------

// TestListExpiringOverridesPagedEmptyOrgReturnsNothing proves an org
// with no overrides yields an empty page, not an error.
func TestListExpiringOverridesPagedEmptyOrgReturnsNothing(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	repo := postgres.NewOwnershipRepository(db)
	got, err := repo.ListExpiringOverridesPaged(ctx, "anchorix", time.Now().UTC(), "", 100)
	if err != nil {
		t.Fatalf("empty org: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("empty org got %d rows; want 0", len(got))
	}
}

// --- EXPLAIN -----------------------------------------------------------

// TestListExpiringOverridesPagedExplainBounded pins the query plan as
// bounded by a Limit and not fleet-aggregating, aligned with the
// project's H-027 EXPLAIN convention. (Seq Scan vs Index is left to
// the planner — on tiny test tables a filtered Seq Scan under the
// Limit is expected and harmless.)
func TestListExpiringOverridesPagedExplainBounded(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	now := time.Now().UTC()

	seedService(t, db, ctx, "svc-exp")
	for i := 0; i < 20; i++ {
		certID := fmt.Sprintf("cert-%02d", i)
		seedCertificate(t, db, ctx, certID)
		seedExpiringOverride(t, db, ctx, "anchorix", fmt.Sprintf("ovr-%02d", i), certID, "svc-exp", pastTime(now, 1))
	}
	plan := explainPlan(t, db, ctx, postgres.ListExpiringOverridesPagedQuery, "anchorix", now, "", 5)
	if !strings.Contains(plan, "Limit") {
		t.Fatalf("plan must be bounded (Limit), got:\n%s", plan)
	}
	if strings.Contains(plan, "Group Key") {
		t.Fatalf("plan must not fleet-aggregate (Group Key), got:\n%s", plan)
	}
}
