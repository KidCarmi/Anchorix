//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/clock"
	"github.com/kidcarmi/anchorix/backend/internal/findings"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// --- wire DTOs (mirror the handler response shapes) ----------------

type recomputeResponseDTO struct {
	Status                string `json:"status"`
	EvaluatedCertificates int    `json:"evaluated_certificates"`
	Opened                int    `json:"opened"`
	Updated               int    `json:"updated"`
	Resolved              int    `json:"resolved"`
	Unchanged             int    `json:"unchanged"`
	RuleCount             int    `json:"rule_count"`
}

type findingRowDTO struct {
	ID                string          `json:"id"`
	RuleID            string          `json:"rule_id"`
	RuleVersion       int             `json:"rule_version"`
	Title             string          `json:"title"`
	Severity          string          `json:"severity"`
	Status            string          `json:"status"`
	CertificateID     string          `json:"certificate_id"`
	FingerprintSHA256 string          `json:"fingerprint_sha256,omitempty"`
	Subject           string          `json:"subject,omitempty"`
	Evidence          json.RawMessage `json:"evidence"`
	FirstSeenAt       string          `json:"first_seen_at"`
	LastSeenAt        string          `json:"last_seen_at"`
	ResolvedAt        *string         `json:"resolved_at"`
	UpdatedAt         string          `json:"updated_at"`
	// H-023 override metadata.
	StatusReason      string  `json:"status_reason"`
	StatusActor       string  `json:"status_actor"`
	StatusChangedAt   *string `json:"status_changed_at"`
	SuppressExpiresAt *string `json:"suppress_expires_at"`
}

type findingsListDTO struct {
	Items      []findingRowDTO `json:"items"`
	NextCursor *string         `json:"next_cursor"`
}

// --- request helpers ------------------------------------------------

func recompute(t *testing.T, srv string, client *http.Client) recomputeResponseDTO {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv+"/api/v1/findings/recompute", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("recompute: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("recompute status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	var out recomputeResponseDTO
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode recompute: %v; body=%s", err, body)
	}
	return out
}

func findingsList(t *testing.T, srv string, client *http.Client, query string) findingsListDTO {
	t.Helper()
	url := srv + "/api/v1/findings"
	if query != "" {
		url += "?" + query
	}
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	var out findingsListDTO
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode list: %v; body=%s", err, body)
	}
	return out
}

// --- fixtures: seed certs directly via SQL so each test can target
//     specific rule properties without round-tripping through the
//     agent ingestion endpoint. ------------------------------------

type certFixture struct {
	ID                 string
	Subject            string
	Issuer             string
	SignatureAlgorithm string
	PublicKeyAlgorithm string
	PublicKeyBits      int
	NotBefore          time.Time
	NotAfter           time.Time
	IsSelfSigned       bool
	IsCA               bool
}

func defaultCertFixture(id, subject string) certFixture {
	now := time.Now().UTC()
	return certFixture{
		ID:                 id,
		Subject:            "CN=" + subject,
		Issuer:             "CN=Internal Issuing CA",
		SignatureAlgorithm: "SHA256-RSA",
		PublicKeyAlgorithm: "RSA",
		PublicKeyBits:      2048,
		NotBefore:          now.Add(-30 * 24 * time.Hour),
		NotAfter:           now.Add(180 * 24 * time.Hour),
		IsSelfSigned:       false,
		IsCA:               false,
	}
}

// seedCert inserts a certificate row in 'anchorix' org with the
// supplied fixture. Fingerprint is derived from the id so each
// fixture has a unique fingerprint without the caller having to
// invent one.
func seedCert(t *testing.T, db *postgres.DB, f certFixture) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fp := "fp-" + f.ID
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO certificates
				(id, organization_id, fingerprint_sha256, subject, issuer,
				 serial_number_hex, signature_algorithm, public_key_algorithm,
				 public_key_bits, not_before, not_after,
				 sans, key_usages, ext_key_usages,
				 is_self_signed, is_ca, pem, first_seen_at, last_seen_at)
			 VALUES ($1, 'anchorix', $2, $3, $4,
				 $5, $6, $7,
				 $8, $9, $10,
				 '[]'::jsonb, '[]'::jsonb, '[]'::jsonb,
				 $11, $12, '-----BEGIN CERTIFICATE-----\nseed\n-----END CERTIFICATE-----\n',
				 $13, $13)`,
			f.ID, fp, f.Subject, f.Issuer,
			"01", f.SignatureAlgorithm, f.PublicKeyAlgorithm,
			f.PublicKeyBits, f.NotBefore, f.NotAfter,
			f.IsSelfSigned, f.IsCA,
			time.Now().UTC(),
		)
		return err
	}); err != nil {
		t.Fatalf("seed cert %s: %v", f.ID, err)
	}
}

// --- recompute happy path ------------------------------------------

// TestFindingsRecomputeOpensFindings seeds one cert that fires
// exactly one rule (weak_rsa_key) and verifies the recompute
// counts + the resulting open finding row.
func TestFindingsRecomputeOpensFindings(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	weak := defaultCertFixture("weak-rsa-cert", "weak.example")
	weak.PublicKeyBits = 1024 // triggers weak_rsa_key
	seedCert(t, db, weak)

	out := recompute(t, srv.URL, adminClient)
	if out.EvaluatedCertificates != 1 {
		t.Errorf("evaluated_certificates = %d, want 1", out.EvaluatedCertificates)
	}
	if out.Opened != 1 {
		t.Errorf("opened = %d, want 1", out.Opened)
	}
	if out.Updated != 0 || out.Resolved != 0 || out.Unchanged != 0 {
		t.Errorf("unexpected counters: updated=%d resolved=%d unchanged=%d",
			out.Updated, out.Resolved, out.Unchanged)
	}

	list := findingsList(t, srv.URL, adminClient, "")
	if len(list.Items) != 1 {
		t.Fatalf("findings list items = %d, want 1", len(list.Items))
	}
	got := list.Items[0]
	if got.RuleID != "weak_rsa_key" {
		t.Errorf("rule_id = %q, want weak_rsa_key", got.RuleID)
	}
	if got.Status != "open" {
		t.Errorf("status = %q, want open", got.Status)
	}
	if got.Severity != "high" {
		t.Errorf("severity = %q, want high", got.Severity)
	}
	if got.ResolvedAt != nil {
		t.Errorf("resolved_at = %v, want nil", *got.ResolvedAt)
	}
}

// TestFindingsRecomputeIsIdempotent runs recompute twice with no
// underlying changes. The first run opens findings; the second
// run UPDATEs the same rows (last_seen_at bumped) without
// opening or resolving anything.
func TestFindingsRecomputeIsIdempotent(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	weak := defaultCertFixture("idempotent-cert", "idempotent.example")
	weak.PublicKeyBits = 1024
	seedCert(t, db, weak)

	first := recompute(t, srv.URL, adminClient)
	if first.Opened != 1 || first.Updated != 0 {
		t.Fatalf("first run: opened=%d updated=%d (want 1, 0)", first.Opened, first.Updated)
	}

	second := recompute(t, srv.URL, adminClient)
	if second.Opened != 0 {
		t.Errorf("second run opened = %d, want 0 (idempotent)", second.Opened)
	}
	if second.Updated != 1 {
		t.Errorf("second run updated = %d, want 1", second.Updated)
	}
	if second.Resolved != 0 {
		t.Errorf("second run resolved = %d, want 0", second.Resolved)
	}
}

// TestFindingsRecomputeResolvesWhenCertNoLongerMatches: open a
// finding via recompute, then mutate the cert so the rule no
// longer matches; the next recompute resolves the finding.
func TestFindingsRecomputeResolvesWhenCertNoLongerMatches(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	cert := defaultCertFixture("transient-cert", "transient.example")
	cert.PublicKeyBits = 1024 // weak
	seedCert(t, db, cert)

	first := recompute(t, srv.URL, adminClient)
	if first.Opened != 1 {
		t.Fatalf("first run opened = %d, want 1", first.Opened)
	}

	// Operator-style remediation surrogate: bump the cert to
	// 2048 bits. v0.1 has no public mutation API; we go around
	// it via SQL exactly because no API path exists.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE certificates SET public_key_bits = 2048 WHERE id = $1`, cert.ID)
		return err
	}); err != nil {
		t.Fatalf("bump key bits: %v", err)
	}

	second := recompute(t, srv.URL, adminClient)
	if second.Resolved != 1 {
		t.Errorf("second run resolved = %d, want 1", second.Resolved)
	}
	if second.Opened != 0 {
		t.Errorf("second run opened = %d, want 0", second.Opened)
	}

	// Default list filter is status=open → empty.
	listOpen := findingsList(t, srv.URL, adminClient, "")
	if len(listOpen.Items) != 0 {
		t.Errorf("default open list items = %d, want 0", len(listOpen.Items))
	}

	// status=resolved → contains the now-resolved finding.
	listResolved := findingsList(t, srv.URL, adminClient, "status=resolved")
	if len(listResolved.Items) != 1 {
		t.Fatalf("resolved list items = %d, want 1", len(listResolved.Items))
	}
	if listResolved.Items[0].ResolvedAt == nil {
		t.Errorf("resolved_at = nil on resolved finding")
	}

	// Third run is unchanged: the resolved finding still doesn't
	// match → counter goes to "unchanged".
	third := recompute(t, srv.URL, adminClient)
	if third.Resolved != 0 {
		t.Errorf("third run resolved = %d, want 0", third.Resolved)
	}
	if third.Unchanged != 1 {
		t.Errorf("third run unchanged = %d, want 1", third.Unchanged)
	}
}

// TestFindingsRecomputeReopenPreservesFirstSeenAt: open, resolve,
// then mutate the cert back so the rule matches again. The
// finding reopens with first_seen_at preserved at the ORIGINAL
// detection time, not the reopen time.
func TestFindingsRecomputeReopenPreservesFirstSeenAt(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	cert := defaultCertFixture("reopen-cert", "reopen.example")
	cert.PublicKeyBits = 1024
	seedCert(t, db, cert)

	recompute(t, srv.URL, adminClient)
	listAfterOpen := findingsList(t, srv.URL, adminClient, "")
	if len(listAfterOpen.Items) != 1 {
		t.Fatalf("after first open: items = %d, want 1", len(listAfterOpen.Items))
	}
	originalFirstSeen := listAfterOpen.Items[0].FirstSeenAt

	// Resolve.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE certificates SET public_key_bits = 2048 WHERE id = $1`, cert.ID)
		return err
	}); err != nil {
		t.Fatalf("strengthen: %v", err)
	}
	recompute(t, srv.URL, adminClient)

	// Re-weaken so the rule matches again.
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE certificates SET public_key_bits = 1024 WHERE id = $1`, cert.ID)
		return err
	}); err != nil {
		t.Fatalf("re-weaken: %v", err)
	}
	out := recompute(t, srv.URL, adminClient)
	if out.Opened != 1 {
		t.Errorf("reopen opened = %d, want 1", out.Opened)
	}

	listAfterReopen := findingsList(t, srv.URL, adminClient, "")
	if len(listAfterReopen.Items) != 1 {
		t.Fatalf("after reopen: items = %d, want 1", len(listAfterReopen.Items))
	}
	if listAfterReopen.Items[0].FirstSeenAt != originalFirstSeen {
		t.Errorf("first_seen_at = %q (reopen), want %q (original)",
			listAfterReopen.Items[0].FirstSeenAt, originalFirstSeen)
	}
}

// TestFindingsRecomputeNoDuplicateOpenFindings: two recomputes
// against the same data produce exactly one finding row per
// (cert, rule) — pinned via raw COUNT on the findings table.
func TestFindingsRecomputeNoDuplicateOpenFindings(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	cert := defaultCertFixture("dup-check-cert", "dup.example")
	cert.PublicKeyBits = 1024
	seedCert(t, db, cert)

	recompute(t, srv.URL, adminClient)
	recompute(t, srv.URL, adminClient)
	recompute(t, srv.URL, adminClient)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var count int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT COUNT(*) FROM findings WHERE organization_id = 'anchorix'`,
		).Scan(&count)
	}); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("findings rows = %d, want 1 (three recomputes must not duplicate)", count)
	}
}

// TestFindingsRecomputeMultipleRulesPerCert: a single cert that
// triggers multiple rules produces one finding per rule.
func TestFindingsRecomputeMultipleRulesPerCert(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	// Weak RSA + SHA1 sig + self-signed leaf = three rule hits.
	cert := defaultCertFixture("triple-cert", "triple.example")
	cert.PublicKeyBits = 1024
	cert.SignatureAlgorithm = "SHA1-RSA"
	cert.IsSelfSigned = true
	cert.IsCA = false
	seedCert(t, db, cert)

	out := recompute(t, srv.URL, adminClient)
	if out.Opened != 3 {
		t.Errorf("opened = %d, want 3 (weak_rsa_key + weak_signature_algorithm + self_signed_leaf)", out.Opened)
	}

	// Filter by rule_id to confirm each rule fired.
	for _, rule := range []string{"weak_rsa_key", "weak_signature_algorithm", "self_signed_leaf"} {
		list := findingsList(t, srv.URL, adminClient, "rule_id="+rule)
		if len(list.Items) != 1 {
			t.Errorf("rule_id=%s: items = %d, want 1", rule, len(list.Items))
		}
	}
}

// --- audit policy --------------------------------------------------

// TestFindingsRecomputeWritesOneAuditRow: each Recompute writes
// exactly one `findings.recomputed` audit row.
func TestFindingsRecomputeWritesOneAuditRow(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	seedCert(t, db, defaultCertFixture("audit-check-cert", "audit-check.example"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	auditCountBefore := countAudit(t, ctx, db, "findings.recomputed")

	recompute(t, srv.URL, adminClient)
	auditCountAfter := countAudit(t, ctx, db, "findings.recomputed")
	if auditCountAfter-auditCountBefore != 1 {
		t.Errorf("findings.recomputed audit rows = %d (delta), want 1",
			auditCountAfter-auditCountBefore)
	}

	// A second recompute writes one more row.
	recompute(t, srv.URL, adminClient)
	auditCountAfter2 := countAudit(t, ctx, db, "findings.recomputed")
	if auditCountAfter2-auditCountAfter != 1 {
		t.Errorf("second recompute audit delta = %d, want 1",
			auditCountAfter2-auditCountAfter)
	}
}

// TestFindingsReadEndpointsEmitNoAuditRows: GET /findings and
// GET /findings/{id} are read-only — no audit_events row should
// land for them. Mirrors the H-020 read-policy test.
func TestFindingsReadEndpointsEmitNoAuditRows(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	cert := defaultCertFixture("read-audit-cert", "read-audit.example")
	cert.PublicKeyBits = 1024
	seedCert(t, db, cert)
	recompute(t, srv.URL, adminClient)

	// List once to get the finding id.
	list := findingsList(t, srv.URL, adminClient, "")
	if len(list.Items) != 1 {
		t.Fatalf("seed list items = %d, want 1", len(list.Items))
	}
	findingID := list.Items[0].ID

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	before := totalAudit(t, ctx, db)

	// Two list calls (with and without filters) + one GET.
	findingsList(t, srv.URL, adminClient, "")
	findingsList(t, srv.URL, adminClient, "status=open&severity=high")
	getFindingRaw(t, srv.URL, adminClient, findingID, http.StatusOK)

	after := totalAudit(t, ctx, db)
	if after != before {
		t.Errorf("audit_events grew from %d to %d on read-only finding endpoints", before, after)
	}
}

func countAudit(t *testing.T, ctx context.Context, db *postgres.DB, action string) int {
	t.Helper()
	var n int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT COUNT(*) FROM audit_events WHERE action = $1`, action,
		).Scan(&n)
	}); err != nil {
		t.Fatalf("count audit %s: %v", action, err)
	}
	return n
}

func totalAudit(t *testing.T, ctx context.Context, db *postgres.DB) int {
	t.Helper()
	var n int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COUNT(*) FROM audit_events`).Scan(&n)
	}); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	return n
}

// TestFindingsRecomputeAuditFailureRollsBack: a stronger guarantee
// than count-checking. Cannot be exercised through the public
// API (the audit recorder doesn't have a failure-injection
// path); the audit-failure path is covered by the service unit
// tests in service_test.go via a fake recorder. This integration
// test instead pins the OBSERVABLE property: with audit working
// normally, every recompute produces both finding state changes
// AND its audit row (i.e., they ride together).
func TestFindingsRecomputeAuditAccompaniesStateChange(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	seedCert(t, db, mustWeakCertFixture("audit-pair"))
	recompute(t, srv.URL, adminClient)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var hasFinding bool
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM findings WHERE organization_id = 'anchorix')`,
		).Scan(&hasFinding)
	}); err != nil {
		t.Fatalf("check findings: %v", err)
	}
	if !hasFinding {
		t.Fatal("expected a finding to exist after recompute")
	}
	if countAudit(t, ctx, db, "findings.recomputed") == 0 {
		t.Error("findings state changed but no audit row was written")
	}
}

// TestFindingsRecomputeAuditCarriesRealActorID pins the Codex
// P2 fix on PR #30: the findings.recomputed audit row's
// `actor` column MUST carry the authenticated operator's user
// id, NOT the previous generic "operator" placeholder. Without
// the real actor, post-hoc filtering by user is broken and
// incident investigation can't point at who triggered a
// recompute.
func TestFindingsRecomputeAuditCarriesRealActorID(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	seedCert(t, db, mustWeakCertFixture("actor-attribution"))
	recompute(t, srv.URL, adminClient)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Find the seeded admin's user id directly from the users
	// table — signInAdmin doesn't surface it to the test, and
	// the audit row should match.
	var adminUserID string
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id FROM users WHERE email = $1`, testEmail,
		).Scan(&adminUserID)
	}); err != nil {
		t.Fatalf("lookup admin id: %v", err)
	}

	// Latest findings.recomputed audit row for the org.
	var actor, actorType string
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT actor, actor_type
			   FROM audit_events
			  WHERE action = 'findings.recomputed'
			    AND organization_id = 'anchorix'
			  ORDER BY occurred_at DESC
			  LIMIT 1`,
		).Scan(&actor, &actorType)
	}); err != nil {
		t.Fatalf("lookup audit row: %v", err)
	}

	if actor == "operator" {
		t.Fatal("audit actor = 'operator' (generic placeholder); want real user id")
	}
	if actor != adminUserID {
		t.Errorf("audit actor = %q, want admin user id %q", actor, adminUserID)
	}
	if actorType != "user" {
		t.Errorf("audit actor_type = %q, want user", actorType)
	}
}

// TestFindingsListResponseIncludesCertContext pins the second
// Codex P2 fix on PR #30: the GET /findings response shape
// promises `fingerprint_sha256` and `subject`. The handler must
// populate both via the repository's JOIN to `certificates` —
// not leave them empty.
func TestFindingsListResponseIncludesCertContext(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	// Cert with a recognizable subject so the assertion is
	// strict, not just "non-empty".
	cert := defaultCertFixture("cert-context-target", "context-target.example")
	cert.PublicKeyBits = 1024 // fires weak_rsa_key
	seedCert(t, db, cert)
	recompute(t, srv.URL, adminClient)

	// List path.
	list := findingsList(t, srv.URL, adminClient, "")
	if len(list.Items) != 1 {
		t.Fatalf("list items = %d, want 1", len(list.Items))
	}
	got := list.Items[0]
	if got.Subject != "CN=context-target.example" {
		t.Errorf("list[0].subject = %q, want CN=context-target.example", got.Subject)
	}
	if got.FingerprintSHA256 != "fp-cert-context-target" {
		t.Errorf("list[0].fingerprint_sha256 = %q, want fp-cert-context-target", got.FingerprintSHA256)
	}

	// Detail path.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/findings/"+got.ID, nil)
	resp, err := adminClient.Do(req)
	if err != nil {
		t.Fatalf("detail GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("detail status = %d, want 200", resp.StatusCode)
	}
	var detail findingRowDTO
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	if detail.Subject != "CN=context-target.example" {
		t.Errorf("detail.subject = %q, want CN=context-target.example", detail.Subject)
	}
	if detail.FingerprintSHA256 != "fp-cert-context-target" {
		t.Errorf("detail.fingerprint_sha256 = %q, want fp-cert-context-target", detail.FingerprintSHA256)
	}
}

// TestFindingsListResponseAlwaysHasCertContextFields catches
// `omitempty`-style regressions: the cert-context fields must
// be PRESENT in the JSON object even when (hypothetically)
// empty. A future change that adds `omitempty` would drop the
// keys from the JSON, breaking the documented contract; this
// raw-JSON probe fails on that regression.
func TestFindingsListResponseAlwaysHasCertContextFields(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	cert := defaultCertFixture("schema-shape-cert", "schema-shape.example")
	cert.PublicKeyBits = 1024
	seedCert(t, db, cert)
	recompute(t, srv.URL, adminClient)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/findings", nil)
	resp, err := adminClient.Do(req)
	if err != nil {
		t.Fatalf("list GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	for _, key := range []string{`"fingerprint_sha256"`, `"subject"`} {
		if !strings.Contains(string(body), key) {
			t.Errorf("list payload missing field %s; body=%s", key, body)
		}
	}
}

func mustWeakCertFixture(id string) certFixture {
	f := defaultCertFixture(id, id+".example")
	f.PublicKeyBits = 1024
	return f
}

// --- cross-org / auth ---------------------------------------------

func TestFindingsRecomputeRequiresSession(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, _ := testServer(t, db)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/findings/recompute", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("anon: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anon status = %d, want 401", resp.StatusCode)
	}
}

func TestFindingsEndpointsRejectAgentBearer(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	bearerOnly := &http.Client{Timeout: 5 * time.Second}
	for _, target := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/findings/recompute"},
		{http.MethodGet, "/api/v1/findings"},
		{http.MethodGet, "/api/v1/findings/anything"},
	} {
		req, _ := http.NewRequest(target.method, srv.URL+target.path, nil)
		req.Header.Set("Authorization", "Bearer "+credential)
		resp, err := bearerOnly.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", target.method, target.path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s status = %d, want 401", target.method, target.path, resp.StatusCode)
		}
	}
}

func TestFindingsListIsOrgScoped(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	seedCert(t, db, mustWeakCertFixture("home-org-finding"))

	// Seed a foreign org + cert + finding directly via SQL. The
	// home-org admin's GET /findings must NOT surface this row.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO organizations (id, name) VALUES ('other-org', 'Other Org')`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO certificates
				(id, organization_id, fingerprint_sha256, subject, issuer,
				 serial_number_hex, signature_algorithm, public_key_algorithm,
				 public_key_bits, not_before, not_after,
				 sans, key_usages, ext_key_usages,
				 is_self_signed, is_ca, pem, first_seen_at, last_seen_at)
			 VALUES ('foreign-cert', 'other-org', 'foreign-fp', 'CN=foreign', 'CN=foreign-ca',
				 '01', 'SHA256-RSA', 'RSA',
				 1024, now() - interval '1 day', now() + interval '90 days',
				 '[]'::jsonb, '[]'::jsonb, '[]'::jsonb,
				 false, false, 'foreign-pem', now(), now())`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO findings (
				id, organization_id, certificate_id, rule_id, rule_version,
				severity, status, title, evidence,
				opened_at, last_seen_at, resolved_at, updated_at
			) VALUES (
				'foreign-finding', 'other-org', 'foreign-cert', 'weak_rsa_key', 1,
				'high', 'open', 'Foreign finding', '{}'::jsonb,
				now(), now(), NULL, now()
			)`)
		return err
	}); err != nil {
		t.Fatalf("seed foreign: %v", err)
	}

	recompute(t, srv.URL, adminClient)

	list := findingsList(t, srv.URL, adminClient, "status=all")
	for _, item := range list.Items {
		if item.ID == "foreign-finding" {
			t.Errorf("foreign finding leaked into home org's list")
		}
		if item.CertificateID == "foreign-cert" {
			t.Errorf("foreign certificate_id leaked: %+v", item)
		}
	}
}

func TestFindingsGetCrossOrgReturns404(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	// Seed a foreign org with a finding directly via SQL.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO organizations (id, name) VALUES ('other-org', 'Other Org')`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO certificates
				(id, organization_id, fingerprint_sha256, subject, issuer,
				 serial_number_hex, signature_algorithm, public_key_algorithm,
				 public_key_bits, not_before, not_after,
				 sans, key_usages, ext_key_usages,
				 is_self_signed, is_ca, pem, first_seen_at, last_seen_at)
			 VALUES ('foreign-cert-2', 'other-org', 'fp2', 'CN=foreign', 'CN=ca',
				 '01', 'SHA256-RSA', 'RSA', 2048,
				 now() - interval '1 day', now() + interval '90 days',
				 '[]'::jsonb, '[]'::jsonb, '[]'::jsonb,
				 false, false, 'pem', now(), now())`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO findings (
				id, organization_id, certificate_id, rule_id, rule_version,
				severity, status, title, evidence,
				opened_at, last_seen_at, resolved_at, updated_at
			) VALUES (
				'foreign-finding-id', 'other-org', 'foreign-cert-2', 'weak_rsa_key', 1,
				'high', 'open', 'Foreign', '{}'::jsonb,
				now(), now(), NULL, now()
			)`)
		return err
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	getFindingRaw(t, srv.URL, adminClient, "foreign-finding-id", http.StatusNotFound)
}

func TestFindingsGetUnknownReturns404(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	getFindingRaw(t, srv.URL, adminClient, "no-such-finding", http.StatusNotFound)
}

func getFindingRaw(t *testing.T, srv string, client *http.Client, id string, wantStatus int) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, srv+"/api/v1/findings/"+id, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("get finding: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("get finding %s: status = %d, want %d; body=%s",
			id, resp.StatusCode, wantStatus, b)
	}
}

// --- filters --------------------------------------------------------

func TestFindingsListFilterBySeverity(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	// Cert that fires only the long-lived rule (severity:low).
	longLived := defaultCertFixture("longlived-cert", "longlived.example")
	now := time.Now().UTC()
	longLived.NotBefore = now.Add(-30 * 24 * time.Hour)
	longLived.NotAfter = now.Add(500 * 24 * time.Hour) // 530 days total
	seedCert(t, db, longLived)

	// Cert that fires weak_rsa_key (severity:high).
	weak := defaultCertFixture("weak-cert", "weak.example")
	weak.PublicKeyBits = 1024
	seedCert(t, db, weak)

	recompute(t, srv.URL, adminClient)

	high := findingsList(t, srv.URL, adminClient, "severity=high")
	for _, f := range high.Items {
		if f.Severity != "high" {
			t.Errorf("severity filter leaked %s row", f.Severity)
		}
	}
	if len(high.Items) == 0 {
		t.Error("severity=high returned 0 rows; expected weak_rsa_key finding")
	}

	low := findingsList(t, srv.URL, adminClient, "severity=low")
	for _, f := range low.Items {
		if f.Severity != "low" {
			t.Errorf("severity filter leaked %s row", f.Severity)
		}
	}
}

func TestFindingsListFilterByRuleID(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	expired := defaultCertFixture("expired-cert", "expired.example")
	expired.NotBefore = time.Now().UTC().Add(-365 * 24 * time.Hour)
	expired.NotAfter = time.Now().UTC().Add(-1 * time.Hour)
	seedCert(t, db, expired)

	weak := defaultCertFixture("weak-rule-cert", "weak-rule.example")
	weak.PublicKeyBits = 1024
	seedCert(t, db, weak)

	recompute(t, srv.URL, adminClient)

	expiredList := findingsList(t, srv.URL, adminClient, "rule_id=certificate_expired")
	if len(expiredList.Items) != 1 {
		t.Errorf("rule_id=certificate_expired items = %d, want 1", len(expiredList.Items))
	}
	for _, f := range expiredList.Items {
		if f.RuleID != "certificate_expired" {
			t.Errorf("rule_id filter leaked %s row", f.RuleID)
		}
	}
}

func TestFindingsListFilterByCertificateID(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	for i := 0; i < 3; i++ {
		f := defaultCertFixture(fmt.Sprintf("multi-cert-%d", i), fmt.Sprintf("multi-%d.example", i))
		f.PublicKeyBits = 1024
		seedCert(t, db, f)
	}
	recompute(t, srv.URL, adminClient)

	list := findingsList(t, srv.URL, adminClient, "certificate_id=multi-cert-1")
	if len(list.Items) != 1 {
		t.Errorf("certificate_id filter items = %d, want 1", len(list.Items))
	}
	for _, f := range list.Items {
		if f.CertificateID != "multi-cert-1" {
			t.Errorf("certificate_id filter leaked %s row", f.CertificateID)
		}
	}
}

func TestFindingsListInvalidStatusReturns400(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/findings?status=nonsense", nil)
	resp, err := adminClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestFindingsListLimitOutOfBounds(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	for _, q := range []string{"limit=0", "limit=-1", "limit=201", "limit=junk"} {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/findings?"+q, nil)
		resp, err := adminClient.Do(req)
		if err != nil {
			t.Fatalf("get %s: %v", q, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s status = %d, want 400", q, resp.StatusCode)
		}
	}
}

// --- pagination -----------------------------------------------------

func TestFindingsListPagination(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	const n = 5
	for i := 0; i < n; i++ {
		f := defaultCertFixture(fmt.Sprintf("paginate-%d", i), fmt.Sprintf("paginate-%d.example", i))
		f.PublicKeyBits = 1024
		seedCert(t, db, f)
	}
	recompute(t, srv.URL, adminClient)

	first := findingsList(t, srv.URL, adminClient, "limit=2")
	if len(first.Items) != 2 {
		t.Fatalf("first page items = %d, want 2", len(first.Items))
	}
	if first.NextCursor == nil {
		t.Fatal("first next_cursor = nil; want non-nil")
	}

	second := findingsList(t, srv.URL, adminClient, "limit=2&cursor="+*first.NextCursor)
	if len(second.Items) != 2 {
		t.Fatalf("second page items = %d, want 2", len(second.Items))
	}
	// No id appears in both pages.
	seen := map[string]bool{}
	for _, it := range first.Items {
		seen[it.ID] = true
	}
	for _, it := range second.Items {
		if seen[it.ID] {
			t.Errorf("id %s appears on both pages", it.ID)
		}
	}

	third := findingsList(t, srv.URL, adminClient, "limit=2&cursor="+*second.NextCursor)
	if len(third.Items) != 1 {
		t.Fatalf("third page items = %d, want 1", len(third.Items))
	}
	if third.NextCursor != nil {
		t.Errorf("third next_cursor = %v, want nil", *third.NextCursor)
	}
}

func TestFindingsListMalformedCursorReturns400(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/findings?cursor=not-base64", nil)
	resp, err := adminClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// --- evidence shape -------------------------------------------------

// TestFindingsEvidenceContainsRuleSpecificFields proves the
// rule-specific evidence payload reaches the API caller verbatim.
func TestFindingsEvidenceContainsRuleSpecificFields(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	weak := defaultCertFixture("evidence-cert", "evidence.example")
	weak.PublicKeyBits = 1024
	seedCert(t, db, weak)
	recompute(t, srv.URL, adminClient)

	list := findingsList(t, srv.URL, adminClient, "rule_id=weak_rsa_key")
	if len(list.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(list.Items))
	}
	var ev struct {
		PublicKeyAlgorithm string `json:"public_key_algorithm"`
		PublicKeyBits      int    `json:"public_key_bits"`
		ThresholdBits      int    `json:"threshold_bits"`
	}
	if err := json.Unmarshal(list.Items[0].Evidence, &ev); err != nil {
		t.Fatalf("decode evidence: %v", err)
	}
	if ev.PublicKeyBits != 1024 {
		t.Errorf("evidence.public_key_bits = %d, want 1024", ev.PublicKeyBits)
	}
	if ev.ThresholdBits != 2048 {
		t.Errorf("evidence.threshold_bits = %d, want 2048", ev.ThresholdBits)
	}
	if !strings.EqualFold(ev.PublicKeyAlgorithm, "RSA") {
		t.Errorf("evidence.public_key_algorithm = %q, want RSA-like", ev.PublicKeyAlgorithm)
	}
}

// --- concurrency --------------------------------------------------

// TestFindingsRecomputeConcurrentSafety pins the per-organization
// advisory lock added in response to the Codex P2 review on PR #30.
// Two simultaneous POST /findings/recompute calls for the same org
// MUST both return 200 — the lock serializes them so the second
// caller sees the first caller's INSERTs and counts them as
// `updated` rather than `opened` (instead of racing against the
// UNIQUE (organization_id, certificate_id, rule_id) constraint
// and surfacing as 500).
//
// Property checks on every iteration:
//
//   - Both HTTP responses are 200 OK.
//   - Total findings rows for the org = expected_rule_match_count
//     (no duplicates). Without the lock the second INSERT would
//     unique-violate; with the lock it correctly UPDATEs the
//     first caller's row.
//
// Iterates to make the test a reliable regression detector. The
// race without the lock manifests probabilistically (Postgres
// transactions interleave depending on scheduling); a single
// iteration would false-pass too often.
func TestFindingsRecomputeConcurrentSafety(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	// Three certs that each trigger one rule → 3 findings on
	// the first recompute. The number is small so each
	// iteration completes quickly; the variety reduces the
	// odds that a race manifests as identical-looking races
	// every time.
	for i, fixture := range []certFixture{
		mustWeakCertFixture("concurrency-weak-rsa"),
		func() certFixture {
			f := defaultCertFixture("concurrency-expired", "expired-conc.example")
			f.NotBefore = time.Now().UTC().Add(-365 * 24 * time.Hour)
			f.NotAfter = time.Now().UTC().Add(-1 * time.Hour)
			return f
		}(),
		func() certFixture {
			f := defaultCertFixture("concurrency-sha1", "sha1-conc.example")
			f.SignatureAlgorithm = "SHA1-RSA"
			return f
		}(),
	} {
		_ = i
		seedCert(t, db, fixture)
	}

	const concurrencyIterations = 5
	for iter := 0; iter < concurrencyIterations; iter++ {
		var wg sync.WaitGroup
		var aOK, bOK int32
		wg.Add(2)
		go func() {
			defer wg.Done()
			if recomputeTolerant(srv.URL, adminClient) {
				atomic.AddInt32(&aOK, 1)
			}
		}()
		go func() {
			defer wg.Done()
			if recomputeTolerant(srv.URL, adminClient) {
				atomic.AddInt32(&bOK, 1)
			}
		}()
		wg.Wait()

		if aOK == 0 || bOK == 0 {
			t.Fatalf("iteration %d: concurrent recomputes failed (a=%d, b=%d) — advisory lock broken",
				iter, aOK, bOK)
		}

		// Post-condition: exactly 3 findings exist for the org
		// (one per cert × matching rule). A duplicate INSERT
		// race would have either failed (counts already
		// asserted above) or, in a hypothetical broken state,
		// produced extra rows.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		var count int
		err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx,
				`SELECT COUNT(*) FROM findings WHERE organization_id = 'anchorix'`,
			).Scan(&count)
		})
		cancel()
		if err != nil {
			t.Fatalf("iteration %d: count: %v", iter, err)
		}
		if count != 3 {
			t.Fatalf("iteration %d: findings count = %d, want 3 (duplicate INSERT race?)", iter, count)
		}
	}
}

// recomputeTolerant performs a POST /findings/recompute that
// returns success/failure as a boolean rather than failing the
// test directly. Use from goroutines where t.Fatal would be
// unsafe.
func recomputeTolerant(srv string, client *http.Client) bool {
	req, _ := http.NewRequest(http.MethodPost, srv+"/api/v1/findings/recompute", nil)
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// --- H-022 scheduled-recompute audit envelope ---------------------

// TestFindingsRecomputeScheduledWritesSchedulerActor pins the
// H-022 contract that scheduled recomputes write an audit row
// with actor="scheduler" and actor_type="system". Operators
// filtering audit_events.actor = 'scheduler' can then see every
// background recompute without inspecting metadata.
//
// The test invokes Service.RecomputeScheduled directly (bypassing
// the HTTP layer) — there is no HTTP endpoint for the scheduler
// path, and the scheduler's own loop is tested via unit tests
// with fakes. This integration test exists to verify the
// audit-row column values produced against real Postgres.
func TestFindingsRecomputeScheduledWritesSchedulerActor(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	_ = signInAdmin(t, urlSrv{url: srv.URL}, svc)

	// Seed a cert that triggers the weak_rsa_key rule.
	seedCert(t, db, mustWeakCertFixture("scheduled-actor"))

	// Build a findings service that mirrors the testServer's
	// wiring and call RecomputeScheduled directly.
	findingsRepo := postgres.NewFindingsRepository(db)
	certRepo := postgres.NewCertificateInventoryRepository(db)
	auditRecorder := postgres.NewAuditRecorder(db, clock.System{})
	findingsSvc, err := findings.NewService(
		findingsRepo, certRepo, db, auditRecorder, clock.System{}, findings.DefaultRules(),
	)
	if err != nil {
		t.Fatalf("findings.NewService: %v", err)
	}
	if _, err := findingsSvc.RecomputeScheduled(context.Background(), "anchorix"); err != nil {
		t.Fatalf("RecomputeScheduled: %v", err)
	}

	// Verify the most recent findings.recomputed audit row has
	// actor="scheduler" and actor_type="system".
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var actor, actorType string
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT actor, actor_type
			   FROM audit_events
			  WHERE action = 'findings.recomputed'
			    AND organization_id = 'anchorix'
			  ORDER BY occurred_at DESC
			  LIMIT 1`,
		).Scan(&actor, &actorType)
	}); err != nil {
		t.Fatalf("read audit row: %v", err)
	}
	if actor != findings.SchedulerActorID {
		t.Errorf("audit actor = %q, want %q", actor, findings.SchedulerActorID)
	}
	if actorType != "system" {
		t.Errorf("audit actor_type = %q, want system", actorType)
	}
}

// TestFindingsListOrganizationIDsReturnsSeededOrg pins the
// minimal contract OrganizationsRepository.ListOrganizationIDs
// must satisfy: it returns the home org (and any seeded
// foreign orgs) in deterministic id-ascending order. The
// scheduler iterates this slice on every tick.
func TestFindingsListOrganizationIDsReturnsSeededOrg(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)

	// Seed a second org so we can prove ordering.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO organizations (id, name) VALUES ('zzz-other-org', 'Other Org')`)
		return err
	}); err != nil {
		t.Fatalf("seed second org: %v", err)
	}

	repo := postgres.NewOrganizationsRepository(db)
	ids, err := repo.ListOrganizationIDs(ctx)
	if err != nil {
		t.Fatalf("ListOrganizationIDs: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("ids = %v, want 2", ids)
	}
	// Order: anchorix < zzz-other-org lexicographically.
	if ids[0] != "anchorix" || ids[1] != "zzz-other-org" {
		t.Errorf("ids = %v, want [anchorix, zzz-other-org]", ids)
	}
}

// TestFindingsRecomputeScheduledSerializesWithManual pins the
// H-022 promise that a scheduled recompute and a concurrent
// manual recompute serialize at the per-org advisory lock
// barrier — neither path returns 500 from the
// UNIQUE (organization_id, certificate_id, rule_id) race.
//
// Two goroutines: one calls Service.RecomputeScheduled
// directly, one calls Service.Recompute via the same code
// path. Both must return without error and the org's findings
// row count stays at exactly 1 (no duplicates).
func TestFindingsRecomputeScheduledSerializesWithManual(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	_ = signInAdmin(t, urlSrv{url: srv.URL}, svc)

	seedCert(t, db, mustWeakCertFixture("scheduler-vs-manual"))

	findingsRepo := postgres.NewFindingsRepository(db)
	certRepo := postgres.NewCertificateInventoryRepository(db)
	auditRecorder := postgres.NewAuditRecorder(db, clock.System{})
	findingsSvc, err := findings.NewService(
		findingsRepo, certRepo, db, auditRecorder, clock.System{}, findings.DefaultRules(),
	)
	if err != nil {
		t.Fatalf("findings.NewService: %v", err)
	}

	const iterations = 5
	for iter := 0; iter < iterations; iter++ {
		var wg sync.WaitGroup
		var manualOK, scheduledOK int32
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, err := findingsSvc.Recompute(context.Background(), findings.RecomputeInput{
				OrganizationID: "anchorix",
				ActorUserID:    "test-manual-user",
			}); err == nil {
				atomic.AddInt32(&manualOK, 1)
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := findingsSvc.RecomputeScheduled(context.Background(), "anchorix"); err == nil {
				atomic.AddInt32(&scheduledOK, 1)
			}
		}()
		wg.Wait()

		if manualOK == 0 || scheduledOK == 0 {
			t.Fatalf("iteration %d: concurrent recomputes failed (manual=%d, scheduled=%d)",
				iter, manualOK, scheduledOK)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		var count int
		err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx,
				`SELECT COUNT(*) FROM findings WHERE organization_id = 'anchorix'`,
			).Scan(&count)
		})
		cancel()
		if err != nil {
			t.Fatalf("iteration %d: count: %v", iter, err)
		}
		if count != 1 {
			t.Fatalf("iteration %d: findings count = %d, want 1 (duplicate INSERT race?)", iter, count)
		}
	}
}

// --- H-023 acknowledge / suppress workflow -------------------------

// seedFindingForOverride seeds a weak-RSA cert + runs an initial
// recompute so an open finding exists for the org. Returns the
// finding id so override tests can hit it directly.
func seedFindingForOverride(t *testing.T, db *postgres.DB, srv string, adminClient *http.Client, certID string) string {
	t.Helper()
	cert := defaultCertFixture(certID, certID+".example")
	cert.PublicKeyBits = 1024 // weak_rsa_key
	seedCert(t, db, cert)
	recompute(t, srv, adminClient)

	list := findingsList(t, srv, adminClient, "rule_id=weak_rsa_key&certificate_id="+certID)
	if len(list.Items) != 1 {
		t.Fatalf("seed list items = %d, want 1", len(list.Items))
	}
	return list.Items[0].ID
}

// postJSON is a small helper for POST /findings/{id}/{action}.
func postJSON(t *testing.T, client *http.Client, url, body string, wantStatus int) []byte {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		t.Fatalf("POST %s: status = %d, want %d; body=%s",
			url, resp.StatusCode, wantStatus, respBody)
	}
	return respBody
}

// TestFindingsAcknowledgeHappyPath: operator acknowledges an
// open finding; response includes override metadata; the
// finding row in the DB has status=acknowledged + reason + actor.
func TestFindingsAcknowledgeHappyPath(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	findingID := seedFindingForOverride(t, db, srv.URL, adminClient, "ack-happy")

	body := postJSON(t, adminClient,
		srv.URL+"/api/v1/findings/"+findingID+"/acknowledge",
		`{"reason":"ticket CSCM-001, blocked on vendor"}`, http.StatusOK)

	var got findingRowDTO
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v; body=%s", err, body)
	}
	if got.Status != "acknowledged" {
		t.Errorf("status = %q, want acknowledged", got.Status)
	}
	if got.StatusReason != "ticket CSCM-001, blocked on vendor" {
		t.Errorf("status_reason = %q", got.StatusReason)
	}
	if got.StatusActor == "" {
		t.Errorf("status_actor empty; want admin user id")
	}
	if got.StatusChangedAt == nil {
		t.Errorf("status_changed_at = nil")
	}
}

// TestFindingsSuppressHappyPath: operator suppresses a finding
// with a future expiry; response carries suppress_expires_at.
func TestFindingsSuppressHappyPath(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	findingID := seedFindingForOverride(t, db, srv.URL, adminClient, "supp-happy")

	expiresAt := time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339)
	body := postJSON(t, adminClient,
		srv.URL+"/api/v1/findings/"+findingID+"/suppress",
		`{"reason":"known false positive","expires_at":"`+expiresAt+`"}`,
		http.StatusOK)

	var got findingRowDTO
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v; body=%s", err, body)
	}
	if got.Status != "suppressed" {
		t.Errorf("status = %q, want suppressed", got.Status)
	}
	if got.SuppressExpiresAt == nil {
		t.Errorf("suppress_expires_at = nil")
	}
}

// TestFindingsOverride_EmptyReason400: both endpoints reject
// empty reason as 400 bad_request.
func TestFindingsOverride_EmptyReason400(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	findingID := seedFindingForOverride(t, db, srv.URL, adminClient, "empty-reason")

	for _, ep := range []string{"acknowledge", "suppress"} {
		body := postJSON(t, adminClient,
			srv.URL+"/api/v1/findings/"+findingID+"/"+ep,
			`{"reason":"   "}`, http.StatusBadRequest)
		if !strings.Contains(string(body), "bad_request") {
			t.Errorf("%s: missing bad_request code; body=%s", ep, body)
		}
	}
}

// TestFindingsSuppress_PastExpiry400: suppress with expires_at
// in the past returns 400.
func TestFindingsSuppress_PastExpiry400(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	findingID := seedFindingForOverride(t, db, srv.URL, adminClient, "past-expiry")

	past := time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)
	body := postJSON(t, adminClient,
		srv.URL+"/api/v1/findings/"+findingID+"/suppress",
		`{"reason":"ok","expires_at":"`+past+`"}`,
		http.StatusBadRequest)
	if !strings.Contains(string(body), "bad_request") {
		t.Errorf("missing bad_request code; body=%s", body)
	}
}

// TestFindingsOverride_CrossOrg404: a foreign-org finding's id
// passed to the home org's POST returns 404.
func TestFindingsOverride_CrossOrg404(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	// Seed a foreign org + cert + finding directly via SQL —
	// no public path produces a cross-org finding.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO organizations (id, name) VALUES ('other-org', 'Other Org')`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO certificates
				(id, organization_id, fingerprint_sha256, subject, issuer,
				 serial_number_hex, signature_algorithm, public_key_algorithm,
				 public_key_bits, not_before, not_after,
				 sans, key_usages, ext_key_usages,
				 is_self_signed, is_ca, pem, first_seen_at, last_seen_at)
			 VALUES ('foreign-cert-h023', 'other-org', 'fp', 'CN=foreign', 'CN=ca',
				 '01', 'SHA256-RSA', 'RSA', 1024,
				 now()-interval '1 day', now()+interval '90 days',
				 '[]'::jsonb, '[]'::jsonb, '[]'::jsonb,
				 false, false, 'pem', now(), now())`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO findings (
				id, organization_id, certificate_id, rule_id, rule_version,
				severity, status, title, evidence,
				opened_at, last_seen_at, resolved_at, updated_at
			) VALUES (
				'foreign-finding-h023', 'other-org', 'foreign-cert-h023', 'weak_rsa_key', 1,
				'high', 'open', 'foreign', '{}'::jsonb,
				now(), now(), NULL, now()
			)`)
		return err
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	for _, ep := range []string{"acknowledge", "suppress"} {
		postJSON(t, adminClient,
			srv.URL+"/api/v1/findings/foreign-finding-h023/"+ep,
			`{"reason":"x"}`, http.StatusNotFound)
	}
}

// TestFindingsOverride_AgentBearerRejected: agent bearer
// credentials must not work against operator-only override
// endpoints.
func TestFindingsOverride_AgentBearerRejected(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	bearerOnly := &http.Client{Timeout: 5 * time.Second}
	for _, ep := range []string{"acknowledge", "suppress"} {
		req, _ := http.NewRequest(http.MethodPost,
			srv.URL+"/api/v1/findings/anything/"+ep,
			strings.NewReader(`{"reason":"x"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+credential)
		resp, err := bearerOnly.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", ep, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s status = %d, want 401", ep, resp.StatusCode)
		}
	}
}

// TestFindingsOverride_AuditRowsWritten: an acknowledge + a
// suppress each produce one audit row with the correct action,
// severity:"security", and actor matching the operator's user
// id.
func TestFindingsOverride_AuditRowsWritten(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	findingID := seedFindingForOverride(t, db, srv.URL, adminClient, "audit-check")

	postJSON(t, adminClient,
		srv.URL+"/api/v1/findings/"+findingID+"/acknowledge",
		`{"reason":"ack reason"}`, http.StatusOK)

	expiresAt := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	postJSON(t, adminClient,
		srv.URL+"/api/v1/findings/"+findingID+"/suppress",
		`{"reason":"suppress reason","expires_at":"`+expiresAt+`"}`, http.StatusOK)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Look up admin id from the users table.
	var adminUserID string
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id FROM users WHERE email = $1`, testEmail).Scan(&adminUserID)
	}); err != nil {
		t.Fatalf("lookup admin: %v", err)
	}

	for _, action := range []string{"finding.acknowledged", "finding.suppressed"} {
		var actor, actorType string
		var metadata []byte
		if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx,
				`SELECT actor, actor_type, metadata
				   FROM audit_events
				  WHERE action = $1
				    AND organization_id = 'anchorix'
				  ORDER BY occurred_at DESC
				  LIMIT 1`, action,
			).Scan(&actor, &actorType, &metadata)
		}); err != nil {
			t.Fatalf("%s lookup: %v", action, err)
		}
		if actor != adminUserID {
			t.Errorf("%s actor = %q, want admin user id %q", action, actor, adminUserID)
		}
		if actorType != "user" {
			t.Errorf("%s actor_type = %q, want user", action, actorType)
		}
		// Parse the JSONB column instead of substring-matching:
		// PostgreSQL's canonical JSONB text form may reorder
		// keys and tweak spacing, so a `"severity":"security"`
		// substring search would be fragile across PG versions.
		var meta map[string]any
		if err := json.Unmarshal(metadata, &meta); err != nil {
			t.Fatalf("%s metadata unmarshal: %v; raw=%s", action, err, metadata)
		}
		if got := meta["severity"]; got != "security" {
			t.Errorf("%s metadata.severity = %v, want security; raw=%s", action, got, metadata)
		}
	}
}

// TestFindingsGet_ShowsOverrideMetadata: after acknowledge,
// GET /findings/{id} returns the override fields.
func TestFindingsGet_ShowsOverrideMetadata(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	findingID := seedFindingForOverride(t, db, srv.URL, adminClient, "get-shows")

	postJSON(t, adminClient,
		srv.URL+"/api/v1/findings/"+findingID+"/acknowledge",
		`{"reason":"context"}`, http.StatusOK)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/findings/"+findingID, nil)
	resp, err := adminClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	var got findingRowDTO
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v; body=%s", err, body)
	}
	if got.StatusReason != "context" {
		t.Errorf("GET status_reason = %q", got.StatusReason)
	}
	if got.StatusActor == "" {
		t.Errorf("GET status_actor empty")
	}
}

// TestFindingsList_StatusFilters: status=acknowledged and
// status=suppressed filters surface only the matching rows.
func TestFindingsList_StatusFilters(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	ackID := seedFindingForOverride(t, db, srv.URL, adminClient, "list-ack")
	supID := seedFindingForOverride(t, db, srv.URL, adminClient, "list-supp")

	postJSON(t, adminClient,
		srv.URL+"/api/v1/findings/"+ackID+"/acknowledge",
		`{"reason":"r"}`, http.StatusOK)
	expiresAt := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	postJSON(t, adminClient,
		srv.URL+"/api/v1/findings/"+supID+"/suppress",
		`{"reason":"r","expires_at":"`+expiresAt+`"}`, http.StatusOK)

	ackList := findingsList(t, srv.URL, adminClient, "status=acknowledged")
	if len(ackList.Items) != 1 || ackList.Items[0].ID != ackID {
		t.Errorf("acknowledged filter = %+v, want only %s", ackList.Items, ackID)
	}

	supList := findingsList(t, srv.URL, adminClient, "status=suppressed")
	if len(supList.Items) != 1 || supList.Items[0].ID != supID {
		t.Errorf("suppressed filter = %+v, want only %s", supList.Items, supID)
	}
}

// TestFindingsRecompute_AcknowledgedStaysAcknowledged:
// end-to-end check via the HTTP path that an acknowledged
// finding's status survives a recompute when the rule still
// matches.
func TestFindingsRecompute_AcknowledgedStaysAcknowledged(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	findingID := seedFindingForOverride(t, db, srv.URL, adminClient, "ack-survives")

	postJSON(t, adminClient,
		srv.URL+"/api/v1/findings/"+findingID+"/acknowledge",
		`{"reason":"r"}`, http.StatusOK)

	recompute(t, srv.URL, adminClient)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/findings/"+findingID, nil)
	resp, _ := adminClient.Do(req)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var got findingRowDTO
	json.Unmarshal(body, &got)
	if got.Status != "acknowledged" {
		t.Errorf("status = %q, want acknowledged after recompute", got.Status)
	}
	if got.StatusReason != "r" {
		t.Errorf("status_reason = %q, want preserved", got.StatusReason)
	}
}

// TestFindingsRecompute_ExpiredSuppressionReopens:
// end-to-end check that a suppressed finding past its expiry
// reopens to `open` on the next recompute.
//
// Timing constants are deliberately conservative for slow CI:
// the wire-format RFC3339Nano preserves sub-second precision
// (RFC3339 alone would truncate, leaving a residual margin
// smaller than HTTP roundtrip latency); the future-offset is
// 3 seconds so a slow handler can't time-travel past the
// suppress validator's "strictly in the future" check; the
// sleep is 4 seconds so the recompute's clock is always past
// the expiry by at least 1 second.
func TestFindingsRecompute_ExpiredSuppressionReopens(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	findingID := seedFindingForOverride(t, db, srv.URL, adminClient, "supp-reopens")

	expiresAt := time.Now().UTC().Add(3 * time.Second).Format(time.RFC3339Nano)
	postJSON(t, adminClient,
		srv.URL+"/api/v1/findings/"+findingID+"/suppress",
		`{"reason":"brief","expires_at":"`+expiresAt+`"}`, http.StatusOK)

	time.Sleep(4 * time.Second)
	recompute(t, srv.URL, adminClient)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/findings/"+findingID, nil)
	resp, _ := adminClient.Do(req)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var got findingRowDTO
	json.Unmarshal(body, &got)
	if got.Status != "open" {
		t.Errorf("status = %q, want open after expired suppression", got.Status)
	}
	if got.SuppressExpiresAt != nil {
		t.Errorf("suppress_expires_at = %v, want nil after reopen", *got.SuppressExpiresAt)
	}
}
