//go:build integration

package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// --- shared DTOs (mirror the wire shapes the handlers emit) --------

type certListItemDTO struct {
	ID                     string  `json:"id"`
	FingerprintSHA256      string  `json:"fingerprint_sha256"`
	Subject                string  `json:"subject"`
	Issuer                 string  `json:"issuer"`
	SerialNumberHex        string  `json:"serial_number_hex"`
	SignatureAlgorithm     string  `json:"signature_algorithm"`
	PublicKeyAlgorithm     string  `json:"public_key_algorithm"`
	PublicKeyBits          int     `json:"public_key_bits"`
	NotBefore              string  `json:"not_before"`
	NotAfter               string  `json:"not_after"`
	IsSelfSigned           bool    `json:"is_self_signed"`
	IsCA                   bool    `json:"is_ca"`
	FirstSeenAt            string  `json:"first_seen_at"`
	LastSeenAt             string  `json:"last_seen_at"`
	ObservationCount       int     `json:"observation_count"`
	ActiveObservationCount int     `json:"active_observation_count"`
	PEM                    *string `json:"pem,omitempty"`
}

type certListDTO struct {
	Items      []certListItemDTO `json:"items"`
	NextCursor *string           `json:"next_cursor"`
}

type certDetailDTO struct {
	ID                     string   `json:"id"`
	FingerprintSHA256      string   `json:"fingerprint_sha256"`
	Subject                string   `json:"subject"`
	Issuer                 string   `json:"issuer"`
	PublicKeyBits          int      `json:"public_key_bits"`
	NotBefore              string   `json:"not_before"`
	NotAfter               string   `json:"not_after"`
	SANs                   []string `json:"sans"`
	KeyUsages              []string `json:"key_usages"`
	ExtKeyUsages           []string `json:"ext_key_usages"`
	IsCA                   bool     `json:"is_ca"`
	PEM                    string   `json:"pem"`
	ObservationCount       int      `json:"observation_count"`
	ActiveObservationCount int      `json:"active_observation_count"`
}

type observationListItemDTO struct {
	ID            string  `json:"id"`
	AgentID       string  `json:"agent_id"`
	Hostname      string  `json:"hostname"`
	StoreLocation string  `json:"store_location"`
	FriendlyName  string  `json:"friendly_name"`
	FirstSeenAt   string  `json:"first_seen_at"`
	LastSeenAt    string  `json:"last_seen_at"`
	RemovedAt     *string `json:"removed_at"`
	Status        string  `json:"status"`
}

type observationListDTO struct {
	Items      []observationListItemDTO `json:"items"`
	NextCursor *string                  `json:"next_cursor"`
}

// --- request helpers ------------------------------------------------

func operatorGetJSON(t *testing.T, srv string, client *http.Client, path string, wantStatus int, target any) []byte {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, srv+path, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		t.Fatalf("GET %s: status = %d, want %d; body=%s", path, resp.StatusCode, wantStatus, body)
	}
	if target != nil && wantStatus == http.StatusOK {
		if err := json.Unmarshal(body, target); err != nil {
			t.Fatalf("decode %s: %v; body=%s", path, err, body)
		}
	}
	return body
}

// submitOneCert is a small convenience over submitCertBatch for tests
// that just want a single cert ingested by a given agent into a
// declared store. Returns the response counters for assertions.
func submitOneCert(t *testing.T, srv, credential, pem, storeLocation, friendlyName string) ingestResponseDTO {
	t.Helper()
	return submitCertBatch(t, srv, credential, ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{storeLocation},
		Certificates: []ingestCertDTO{
			{StoreLocation: storeLocation, CertificatePEM: pem, FriendlyName: friendlyName},
		},
	}, http.StatusOK)
}

// --- happy-path list -----------------------------------------------

func TestOperatorListCertificatesHappyPath(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	// Two certs must be submitted in the SAME batch — the H-015
	// ingestion contract is set-reconciliation per declared
	// store_coverage, so a second batch covering the same store
	// without the first cert would mark the first cert's
	// observation as removed. Multi-cert single batch is the
	// only way two certs coexist as active observations in one
	// store under the contract this PR consumes.
	a := generatedCert(t, "alpha.example")
	b := generatedCert(t, "beta.example")
	submitCertBatch(t, srv.URL, credential, ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, CertificatePEM: a, FriendlyName: "alpha-friendly"},
			{StoreLocation: `LocalMachine\My`, CertificatePEM: b, FriendlyName: "beta-friendly"},
		},
	}, http.StatusOK)

	var out certListDTO
	operatorGetJSON(t, srv.URL, adminClient, "/api/v1/certificates", http.StatusOK, &out)
	if len(out.Items) != 2 {
		t.Fatalf("items = %d, want 2", len(out.Items))
	}
	if out.NextCursor != nil {
		t.Errorf("next_cursor = %v, want nil", *out.NextCursor)
	}
	// Assert set membership rather than position. The wire
	// `collected_at` is RFC3339 second-precision (the agent test
	// helper formats it that way), so two submits within the same
	// second produce identical `last_seen_at` and the id-ASC
	// tiebreaker takes over — that ordering is implementation-
	// derived and not part of the operator contract worth pinning
	// in this test. Ordering correctness is exercised by the
	// pagination test, which seeds 5 certs and walks the cursor.
	subjects := map[string]bool{}
	for _, item := range out.Items {
		subjects[item.Subject] = true
		if item.ObservationCount != 1 {
			t.Errorf("%s observation_count = %d, want 1", item.Subject, item.ObservationCount)
		}
		if item.ActiveObservationCount != 1 {
			t.Errorf("%s active_observation_count = %d, want 1", item.Subject, item.ActiveObservationCount)
		}
	}
	if !subjects["CN=alpha.example"] || !subjects["CN=beta.example"] {
		t.Errorf("subjects = %v, want both CN=alpha.example and CN=beta.example", subjects)
	}
}

// TestOperatorListCertificatesDoesNotIncludePEM proves the list
// payload omits the PEM. A raw-JSON contains-check catches an
// accidental server-side reintroduction of the field.
func TestOperatorListCertificatesDoesNotIncludePEM(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	pemA := generatedCert(t, "pem-leak-check.example")
	submitOneCert(t, srv.URL, credential, pemA, `LocalMachine\My`, "")

	body := operatorGetJSON(t, srv.URL, adminClient, "/api/v1/certificates", http.StatusOK, nil)
	if strings.Contains(string(body), "-----BEGIN CERTIFICATE-----") {
		t.Errorf("list payload contains PEM bytes; body=%s", body)
	}
	if strings.Contains(string(body), `"pem"`) {
		t.Errorf("list payload exposes pem field; body=%s", body)
	}
}

// --- detail endpoint -----------------------------------------------

func TestOperatorGetCertificateIncludesPEM(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	pemA := generatedCert(t, "detail.example")
	submitOneCert(t, srv.URL, credential, pemA, `LocalMachine\My`, "")

	// Find the cert id from the list response.
	var list certListDTO
	operatorGetJSON(t, srv.URL, adminClient, "/api/v1/certificates", http.StatusOK, &list)
	if len(list.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(list.Items))
	}
	certID := list.Items[0].ID

	var detail certDetailDTO
	operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/certificates/"+certID, http.StatusOK, &detail)

	if detail.PEM == "" {
		t.Errorf("detail.pem is empty")
	}
	if !strings.Contains(detail.PEM, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("detail.pem missing BEGIN marker: %q", detail.PEM)
	}
	if detail.Subject != "CN=detail.example" {
		t.Errorf("detail.subject = %q, want CN=detail.example", detail.Subject)
	}
	// The generated cert includes one DNS SAN (subject CN) and one
	// ExtKeyUsage=ServerAuth.
	if len(detail.SANs) == 0 {
		t.Errorf("detail.sans = %v, want at least one SAN", detail.SANs)
	}
	if detail.ObservationCount != 1 || detail.ActiveObservationCount != 1 {
		t.Errorf("counts = (%d,%d), want (1,1)",
			detail.ObservationCount, detail.ActiveObservationCount)
	}
}

func TestOperatorGetCertificateNotFound(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	body := operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/certificates/unknown-id", http.StatusNotFound, nil)
	if !strings.Contains(string(body), "not_found") {
		t.Errorf("body missing not_found code: %s", body)
	}
}

// --- cross-org 404 --------------------------------------------------

// TestOperatorGetCertificateCrossOrgReturns404 hardens the
// org-scoping promise: an admin in org A reading a cert that
// exists only in org B must get 404 — not 200, not 403.
func TestOperatorGetCertificateCrossOrgReturns404(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const foreignCertID = "foreign-cert-id-h020"
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO organizations (id, name) VALUES ('other-org', 'Other Org')`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO certificates
				(id, organization_id, fingerprint_sha256, subject, issuer,
				 serial_number_hex, signature_algorithm, public_key_algorithm,
				 public_key_bits, not_before, not_after,
				 sans, key_usages, ext_key_usages,
				 is_self_signed, is_ca, pem, first_seen_at, last_seen_at)
			 VALUES ($1, 'other-org', 'foreign-fp', 'CN=foreign-cert', 'CN=foreign-ca',
				 'deadbeef', 'sha256-rsa', 'RSA',
				 2048, '2025-01-01', '2027-01-01',
				 '[]', '[]', '[]',
				 false, false, 'foreign-pem', now(), now())`,
			foreignCertID)
		return err
	}); err != nil {
		t.Fatalf("seed foreign cert: %v", err)
	}

	body := operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/certificates/"+foreignCertID, http.StatusNotFound, nil)
	if strings.Contains(string(body), "foreign-cert") || strings.Contains(string(body), "foreign-pem") {
		t.Errorf("response leaks foreign cert content: %s", body)
	}
}

// --- auth: unauthenticated + agent-bearer rejection ----------------

func TestOperatorListCertificatesRequiresSession(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, _ := testServer(t, db)

	for _, path := range []string{
		"/api/v1/certificates",
		"/api/v1/certificates/anything",
		"/api/v1/certificates/anything/observations",
		"/api/v1/agents/anything/certificates",
	} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("anon GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s anon status = %d, want 401", path, resp.StatusCode)
		}
	}
}

func TestOperatorListCertificatesAgentBearerRejected(t *testing.T) {
	// Agent bearer credentials are NOT honored on operator routes.
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	bearerOnly := &http.Client{Timeout: 5 * time.Second}
	for _, path := range []string{
		"/api/v1/certificates",
		"/api/v1/certificates/anything",
		"/api/v1/certificates/anything/observations",
		"/api/v1/agents/anything/certificates",
	} {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+credential)
		resp, err := bearerOnly.Do(req)
		if err != nil {
			t.Fatalf("bearer GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s agent-bearer status = %d, want 401", path, resp.StatusCode)
		}
	}
}

// --- observations endpoint -----------------------------------------

func TestOperatorListCertificateObservations(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	_, credential := enrolledAgent(t, srv.URL, adminClient)

	pem := generatedCert(t, "obs.example")
	submitOneCert(t, srv.URL, credential, pem, `LocalMachine\My`, "obs-friendly")

	// Look up cert id via list.
	var list certListDTO
	operatorGetJSON(t, srv.URL, adminClient, "/api/v1/certificates", http.StatusOK, &list)
	if len(list.Items) != 1 {
		t.Fatalf("certs = %d, want 1", len(list.Items))
	}
	certID := list.Items[0].ID

	var obs observationListDTO
	operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/certificates/"+certID+"/observations", http.StatusOK, &obs)
	if len(obs.Items) != 1 {
		t.Fatalf("observations = %d, want 1", len(obs.Items))
	}
	item := obs.Items[0]
	if item.AgentID == "" {
		t.Errorf("agent_id missing")
	}
	if item.StoreLocation != `LocalMachine\My` {
		t.Errorf("store_location = %q, want LocalMachine\\My", item.StoreLocation)
	}
	if item.FriendlyName != "obs-friendly" {
		t.Errorf("friendly_name = %q, want obs-friendly", item.FriendlyName)
	}
	if item.Status != "active" {
		t.Errorf("status = %q, want active", item.Status)
	}
	if item.RemovedAt != nil {
		t.Errorf("removed_at = %v, want nil", *item.RemovedAt)
	}
}

// TestOperatorObservationsCurrentOnlyDefault asserts the default
// (current_only absent) hides observations that have been marked
// removed by set reconciliation. current_only=false includes them.
func TestOperatorObservationsCurrentOnlyDefault(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	originalPEM := generatedCert(t, "removed-obs.example")
	replacementPEM := generatedCert(t, "replacement-obs.example")
	// First batch: original cert present in My.
	submitOneCert(t, srv.URL, credential, originalPEM, `LocalMachine\My`, "")
	// Second batch: a DIFFERENT cert covers the same store. Set
	// reconciliation marks the original cert's observation as
	// removed because it is absent from this batch's
	// certificates[] in the declared coverage. The H-015 handler
	// rejects empty `certificates` arrays as bad_request, so the
	// only way to drive an observation to removed via the public
	// API is to submit a replacement batch.
	submitCertBatch(t, srv.URL, credential, ingestRequestDTO{
		CollectedAt:   time.Now().UTC().Add(1 * time.Second).Format(time.RFC3339),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, CertificatePEM: replacementPEM},
		},
	}, http.StatusOK)

	// Find the ORIGINAL cert's id (the one now in the removed
	// state). `q=removed-obs` matches the original's subject
	// uniquely. current_only=false so the removed-only cert
	// still surfaces.
	var list certListDTO
	operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/certificates?current_only=false&q=removed-obs", http.StatusOK, &list)
	if len(list.Items) != 1 {
		t.Fatalf("certs by q=removed-obs = %d, want 1", len(list.Items))
	}
	certID := list.Items[0].ID

	// Default (no param) excludes the removed observation.
	var def observationListDTO
	operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/certificates/"+certID+"/observations", http.StatusOK, &def)
	if len(def.Items) != 0 {
		t.Errorf("default current_only items = %d, want 0", len(def.Items))
	}

	// Explicit current_only=false includes it.
	var withRemoved observationListDTO
	operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/certificates/"+certID+"/observations?current_only=false",
		http.StatusOK, &withRemoved)
	if len(withRemoved.Items) != 1 {
		t.Fatalf("current_only=false items = %d, want 1", len(withRemoved.Items))
	}
	if withRemoved.Items[0].Status != "removed" {
		t.Errorf("status = %q, want removed", withRemoved.Items[0].Status)
	}
	if withRemoved.Items[0].RemovedAt == nil {
		t.Errorf("removed_at = nil; want non-nil")
	}
}

// --- /agents/{id}/certificates -------------------------------------

func TestOperatorAgentCertificatesHappyPath(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	agentA, credA := enrolledAgent(t, srv.URL, adminClient)
	agentB, credB := enrolledAgent(t, srv.URL, adminClient)

	pemA := generatedCert(t, "for-agent-a.example")
	pemB := generatedCert(t, "for-agent-b.example")
	submitOneCert(t, srv.URL, credA, pemA, `LocalMachine\My`, "")
	submitOneCert(t, srv.URL, credB, pemB, `LocalMachine\My`, "")

	var aList certListDTO
	operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/agents/"+agentA+"/certificates", http.StatusOK, &aList)
	if len(aList.Items) != 1 {
		t.Fatalf("agent A list = %d, want 1", len(aList.Items))
	}
	if aList.Items[0].Subject != "CN=for-agent-a.example" {
		t.Errorf("agent A subject = %q; expected for-agent-a", aList.Items[0].Subject)
	}

	var bList certListDTO
	operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/agents/"+agentB+"/certificates", http.StatusOK, &bList)
	if len(bList.Items) != 1 {
		t.Fatalf("agent B list = %d, want 1", len(bList.Items))
	}
	if bList.Items[0].Subject != "CN=for-agent-b.example" {
		t.Errorf("agent B subject = %q; expected for-agent-b", bList.Items[0].Subject)
	}
}

func TestOperatorAgentCertificatesUnknownAgent404(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	body := operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/agents/unknown-agent/certificates", http.StatusNotFound, nil)
	if !strings.Contains(string(body), "not_found") {
		t.Errorf("body missing not_found: %s", body)
	}
}

// TestOperatorAgentCertificatesCrossOrgReturns404 hardens the
// org-scoping promise on the per-agent certificate list.
func TestOperatorAgentCertificatesCrossOrgReturns404(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const foreignAgentID = "foreign-agent-h020"
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO organizations (id, name) VALUES ('other-org', 'Other Org')`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO agents (id, organization_id, hostname, version, status, enrolled_at, last_seen_at)
			 VALUES ($1, 'other-org', 'foreign-host', '', 'active', now(), now())`,
			foreignAgentID)
		return err
	}); err != nil {
		t.Fatalf("seed foreign agent: %v", err)
	}

	body := operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/agents/"+foreignAgentID+"/certificates", http.StatusNotFound, nil)
	if strings.Contains(string(body), foreignAgentID) {
		t.Errorf("body leaks foreign agent id: %s", body)
	}
}

// TestOperatorListCertificatesOrgScoping seeds certs in two orgs;
// the admin in 'anchorix' must NOT see the foreign-org cert
// regardless of how recent it is.
func TestOperatorListCertificatesOrgScoping(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	homePEM := generatedCert(t, "home-cert.example")
	submitOneCert(t, srv.URL, credential, homePEM, `LocalMachine\My`, "")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO organizations (id, name) VALUES ('other-org', 'Other Org')`); err != nil {
			return err
		}
		// Foreign cert with a FUTURE last_seen_at — proves that a
		// missing org filter would have surfaced this row at the
		// top of the list.
		_, err := tx.Exec(ctx,
			`INSERT INTO certificates
				(id, organization_id, fingerprint_sha256, subject, issuer,
				 serial_number_hex, signature_algorithm, public_key_algorithm,
				 public_key_bits, not_before, not_after,
				 sans, key_usages, ext_key_usages,
				 is_self_signed, is_ca, pem, first_seen_at, last_seen_at)
			 VALUES ('foreign-cert-list', 'other-org', 'foreign-fp-list',
				 'CN=foreign-leak', 'CN=foreign-ca',
				 'beef', 'sha256-rsa', 'RSA',
				 2048, '2025-01-01', '2099-01-01',
				 '[]', '[]', '[]',
				 false, false, 'foreign-pem',
				 '2099-01-01T00:00:00Z', '2099-01-01T00:00:00Z')`)
		return err
	}); err != nil {
		t.Fatalf("seed foreign org/cert: %v", err)
	}

	var list certListDTO
	body := operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/certificates?current_only=false", http.StatusOK, &list)
	if len(list.Items) != 1 {
		t.Fatalf("home org certs = %d, want 1 (foreign leaked?); body=%s", len(list.Items), body)
	}
	if list.Items[0].Subject == "CN=foreign-leak" {
		t.Errorf("foreign cert leaked into list: %s", body)
	}
}

// --- filters --------------------------------------------------------

func TestOperatorListCertificatesQFilter(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	// Single batch — see TestOperatorListCertificatesHappyPath
	// for the set-reconciliation rationale.
	submitCertBatch(t, srv.URL, credential, ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, CertificatePEM: generatedCert(t, "match-needle.example")},
			{StoreLocation: `LocalMachine\My`, CertificatePEM: generatedCert(t, "no-relation.example")},
		},
	}, http.StatusOK)

	var list certListDTO
	operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/certificates?q=needle", http.StatusOK, &list)
	if len(list.Items) != 1 {
		t.Fatalf("q=needle items = %d, want 1", len(list.Items))
	}
	if list.Items[0].Subject != "CN=match-needle.example" {
		t.Errorf("q=needle subject = %q", list.Items[0].Subject)
	}

	// Also confirm fingerprint substring works — take the prefix
	// of the seeded cert's fingerprint and request just that.
	prefix := list.Items[0].FingerprintSHA256[:16]
	var byFP certListDTO
	operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/certificates?q="+prefix, http.StatusOK, &byFP)
	if len(byFP.Items) != 1 {
		t.Errorf("q=fingerprint-prefix items = %d, want 1", len(byFP.Items))
	}
}

func TestOperatorListCertificatesExpiringBeforeFilter(t *testing.T) {
	// Two certs are seeded by the agent (both ~365 days from now).
	// We additionally seed a soon-expiring cert via raw SQL so we
	// can craft a value the agent-generated certs would not match.
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)
	submitOneCert(t, srv.URL, credential, generatedCert(t, "later.example"), `LocalMachine\My`, "")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Seed a cert in the SAME org with not_after = 7 days from now.
	soon := time.Now().UTC().Add(7 * 24 * time.Hour)
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO certificates
				(id, organization_id, fingerprint_sha256, subject, issuer,
				 serial_number_hex, signature_algorithm, public_key_algorithm,
				 public_key_bits, not_before, not_after,
				 sans, key_usages, ext_key_usages,
				 is_self_signed, is_ca, pem, first_seen_at, last_seen_at)
			 VALUES ('soon-cert', 'anchorix', 'soon-fp',
				 'CN=expiring-soon', 'CN=ca',
				 'aa', 'sha256-rsa', 'RSA',
				 2048, now() - interval '1 hour', $1,
				 '[]', '[]', '[]',
				 false, false, '-----BEGIN CERTIFICATE-----\nseed\n-----END CERTIFICATE-----\n',
				 now(), now())`,
			soon)
		return err
	}); err != nil {
		t.Fatalf("seed soon cert: %v", err)
	}

	// expiring_before = 30 days from now: matches only the soon cert.
	threshold := time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339)
	var list certListDTO
	operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/certificates?expiring_before="+threshold+"&current_only=false",
		http.StatusOK, &list)
	if len(list.Items) != 1 {
		t.Fatalf("expiring_before items = %d, want 1", len(list.Items))
	}
	if list.Items[0].Subject != "CN=expiring-soon" {
		t.Errorf("subject = %q, want CN=expiring-soon", list.Items[0].Subject)
	}
}

func TestOperatorListCertificatesIsCAFilter(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)
	submitOneCert(t, srv.URL, credential, generatedCert(t, "leaf.example"), `LocalMachine\My`, "")

	// Seed a CA row directly. The agent-generated cert is a leaf
	// (is_ca = false) so this fixture is the only is_ca=true row.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO certificates
				(id, organization_id, fingerprint_sha256, subject, issuer,
				 serial_number_hex, signature_algorithm, public_key_algorithm,
				 public_key_bits, not_before, not_after,
				 sans, key_usages, ext_key_usages,
				 is_self_signed, is_ca, pem, first_seen_at, last_seen_at)
			 VALUES ('ca-cert', 'anchorix', 'ca-fp',
				 'CN=is-ca-true', 'CN=is-ca-true',
				 'cc', 'sha256-rsa', 'RSA',
				 4096, now() - interval '1 hour', now() + interval '365 days',
				 '[]', '[]', '[]',
				 true, true, '-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n',
				 now(), now())`)
		return err
	}); err != nil {
		t.Fatalf("seed ca cert: %v", err)
	}

	var caOnly certListDTO
	operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/certificates?is_ca=true&current_only=false", http.StatusOK, &caOnly)
	if len(caOnly.Items) != 1 {
		t.Fatalf("is_ca=true items = %d, want 1", len(caOnly.Items))
	}
	if !caOnly.Items[0].IsCA {
		t.Errorf("is_ca = false; want true")
	}

	var nonCA certListDTO
	operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/certificates?is_ca=false&current_only=false", http.StatusOK, &nonCA)
	if len(nonCA.Items) != 1 {
		t.Fatalf("is_ca=false items = %d, want 1", len(nonCA.Items))
	}
	if nonCA.Items[0].IsCA {
		t.Errorf("is_ca = true; want false")
	}
}

func TestOperatorListCertificatesAgentIDFilter(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	agentA, credA := enrolledAgent(t, srv.URL, adminClient)
	_, credB := enrolledAgent(t, srv.URL, adminClient)

	submitOneCert(t, srv.URL, credA, generatedCert(t, "by-a.example"), `LocalMachine\My`, "")
	submitOneCert(t, srv.URL, credB, generatedCert(t, "by-b.example"), `LocalMachine\My`, "")

	var list certListDTO
	operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/certificates?agent_id="+agentA, http.StatusOK, &list)
	if len(list.Items) != 1 {
		t.Fatalf("agent_id filter items = %d, want 1", len(list.Items))
	}
	if list.Items[0].Subject != "CN=by-a.example" {
		t.Errorf("filter returned wrong row: %q", list.Items[0].Subject)
	}
}

// TestOperatorListCertificatesCurrentOnlyHidesRemoved asserts the
// default (current_only absent) hides certs whose only observations
// have removed_at; current_only=false surfaces them.
func TestOperatorListCertificatesCurrentOnlyHidesRemoved(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	// Two certs: original gets reconciled away by a replacement
	// batch (the H-015 handler rejects empty `certificates`
	// arrays, so a replacement cert is the only way to push the
	// original's observation to removed_at via the public API).
	originalPEM := generatedCert(t, "to-be-removed.example")
	replacementPEM := generatedCert(t, "still-active.example")
	submitOneCert(t, srv.URL, credential, originalPEM, `LocalMachine\My`, "")
	submitCertBatch(t, srv.URL, credential, ingestRequestDTO{
		CollectedAt:   time.Now().UTC().Add(1 * time.Second).Format(time.RFC3339),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, CertificatePEM: replacementPEM},
		},
	}, http.StatusOK)

	// Default current_only=true: the ORIGINAL cert is hidden (no
	// active observations). The replacement cert is active, so it
	// shows up. We filter by the original's subject to scope the
	// assertion to "the cert we drove to removed is hidden".
	var defOriginal certListDTO
	operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/certificates?q=to-be-removed", http.StatusOK, &defOriginal)
	if len(defOriginal.Items) != 0 {
		t.Errorf("default current_only with q=to-be-removed items = %d, want 0", len(defOriginal.Items))
	}

	// Explicit current_only=false with the same subject scope:
	// the original surfaces with active_observation_count = 0.
	var withRemoved certListDTO
	operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/certificates?current_only=false&q=to-be-removed", http.StatusOK, &withRemoved)
	if len(withRemoved.Items) != 1 {
		t.Fatalf("current_only=false with q=to-be-removed items = %d, want 1", len(withRemoved.Items))
	}
	if withRemoved.Items[0].ActiveObservationCount != 0 {
		t.Errorf("active_observation_count = %d, want 0",
			withRemoved.Items[0].ActiveObservationCount)
	}
	if withRemoved.Items[0].ObservationCount != 1 {
		t.Errorf("observation_count = %d, want 1",
			withRemoved.Items[0].ObservationCount)
	}
}

// --- pagination -----------------------------------------------------

func TestOperatorListCertificatesPaginationLimitAndCursor(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	// All 5 certs in a single batch — sequential batches with
	// the same store_coverage would reconcile earlier certs away.
	// They share a last_seen_at by design here; the id-ASC
	// tiebreaker keeps cursor pagination deterministic and the
	// test only asserts page sizes + no-shared-ids, not which
	// specific cert lands on which page.
	const n = 5
	certs := make([]ingestCertDTO, 0, n)
	for i := 0; i < n; i++ {
		certs = append(certs, ingestCertDTO{
			StoreLocation:  `LocalMachine\My`,
			CertificatePEM: generatedCert(t, "page-"+strconv.Itoa(i)+".example"),
		})
	}
	submitCertBatch(t, srv.URL, credential, ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates:  certs,
	}, http.StatusOK)

	var first certListDTO
	operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/certificates?limit=2", http.StatusOK, &first)
	if len(first.Items) != 2 {
		t.Fatalf("first page items = %d, want 2", len(first.Items))
	}
	if first.NextCursor == nil {
		t.Fatal("next_cursor = nil; want non-nil")
	}

	var second certListDTO
	operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/certificates?limit=2&cursor="+*first.NextCursor,
		http.StatusOK, &second)
	if len(second.Items) != 2 {
		t.Fatalf("second page items = %d, want 2", len(second.Items))
	}
	// No id appears in both pages.
	pageIDs := map[string]bool{}
	for _, it := range first.Items {
		pageIDs[it.ID] = true
	}
	for _, it := range second.Items {
		if pageIDs[it.ID] {
			t.Errorf("id %s appears on both pages", it.ID)
		}
	}

	var third certListDTO
	operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/certificates?limit=2&cursor="+*second.NextCursor,
		http.StatusOK, &third)
	if len(third.Items) != 1 {
		t.Fatalf("third page items = %d, want 1", len(third.Items))
	}
	if third.NextCursor != nil {
		t.Errorf("third next_cursor = %v, want nil", *third.NextCursor)
	}
}

func TestOperatorListCertificatesLimitOutOfBounds(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	for _, q := range []string{
		"limit=0", // explicit zero is a caller-input bug, not "use default"
		"limit=-1",
		"limit=201", // above MaxListLimit
		"limit=notanumber",
		"cursor=not-base64",
		"is_ca=maybe",
		"current_only=maybe",
		"expiring_before=not-rfc3339",
	} {
		path := "/api/v1/certificates?" + q
		body := operatorGetJSON(t, srv.URL, adminClient, path, http.StatusBadRequest, nil)
		if !strings.Contains(string(body), "bad_request") {
			t.Errorf("%s: expected bad_request; body=%s", path, body)
		}
	}
}

// --- audit policy ---------------------------------------------------

// TestOperatorReadsEmitNoAuditRows hammers each read endpoint once
// and asserts that no audit_events row appeared. Reads are
// stateless; CLAUDE.md §9 reserves audit for state changes.
func TestOperatorReadsEmitNoAuditRows(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	agentID, credential := enrolledAgent(t, srv.URL, adminClient)
	submitOneCert(t, srv.URL, credential,
		generatedCert(t, "audit-check.example"),
		`LocalMachine\My`, "")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Baseline audit count BEFORE the reads.
	var before int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COUNT(*) FROM audit_events`).Scan(&before)
	}); err != nil {
		t.Fatalf("baseline count: %v", err)
	}

	var list certListDTO
	operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/certificates", http.StatusOK, &list)
	if len(list.Items) != 1 {
		t.Fatalf("seeded cert missing from list: %d items", len(list.Items))
	}
	certID := list.Items[0].ID
	operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/certificates/"+certID, http.StatusOK, nil)
	operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/certificates/"+certID+"/observations", http.StatusOK, nil)
	operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/agents/"+agentID+"/certificates", http.StatusOK, nil)

	var after int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COUNT(*) FROM audit_events`).Scan(&after)
	}); err != nil {
		t.Fatalf("after count: %v", err)
	}
	if after != before {
		t.Errorf("audit_events grew from %d to %d on read-only operator endpoints", before, after)
	}
}

// --- post-merge hardening pass (H-020 review) ----------------------
//
// The four tests below pin properties that an adversarial review
// surfaced as silent-correctness / silent-leak risks. Each fails
// loudly if a future change regresses the documented behavior.

// TestOperatorListCertificatesQFilterEscapesUnderscore proves the
// `q` filter treats SQL LIKE metacharacters as LITERAL bytes, not
// as wildcards. Without escaping, `?q=foo_bar` would match both
// `foo_bar.example` (intended) and `fooXbar.example` (unintended —
// `_` is the LIKE single-char wildcard). The fix escapes `_`, `%`,
// and `\` and adds `ESCAPE '\'` to each ILIKE clause.
func TestOperatorListCertificatesQFilterEscapesUnderscore(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	submitCertBatch(t, srv.URL, credential, ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates: []ingestCertDTO{
			// Intentional underscore in the subject.
			{StoreLocation: `LocalMachine\My`, CertificatePEM: generatedCert(t, "foo_bar.example")},
			// Same length, no underscore — would falsely match
			// `foo_bar` under unescaped LIKE.
			{StoreLocation: `LocalMachine\My`, CertificatePEM: generatedCert(t, "fooXbar.example")},
		},
	}, http.StatusOK)

	var list certListDTO
	operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/certificates?q=foo_bar", http.StatusOK, &list)
	if len(list.Items) != 1 {
		subjects := make([]string, 0, len(list.Items))
		for _, it := range list.Items {
			subjects = append(subjects, it.Subject)
		}
		t.Fatalf("q=foo_bar items = %d, want 1 (got %v); `_` must be literal, not LIKE wildcard",
			len(list.Items), subjects)
	}
	if list.Items[0].Subject != "CN=foo_bar.example" {
		t.Errorf("matched subject = %q, want CN=foo_bar.example", list.Items[0].Subject)
	}
}

// TestOperatorListCertificatesQFilterEscapesPercent proves the
// same property for the `%` LIKE wildcard. The fixture is chosen
// so the test exercises the buggy behavior, not just the fixed
// one: `amazon.example` contains `a` followed (eventually) by `z`,
// so under unescaped LIKE the wrapped pattern `%a%z%` matches it
// — and the test would fail. With the fix, the wrapped pattern
// is `%a\%z%` ESCAPE '\', which requires the literal byte
// sequence `a%z` that the subject does not contain. The unrelated
// `xyz.example` row is along for the ride as a negative-space
// check that the query is not silently broken in some other way.
func TestOperatorListCertificatesQFilterEscapesPercent(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	submitCertBatch(t, srv.URL, credential, ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates: []ingestCertDTO{
			// `amazon.example` is the trap: under unescaped LIKE
			// the pattern `%a%z%` matches it (a, then anything,
			// then z appears inside `amazon`); under the fix, the
			// literal byte sequence `a%z` is required and is
			// absent, so this cert MUST NOT appear in results.
			{StoreLocation: `LocalMachine\My`, CertificatePEM: generatedCert(t, "amazon.example")},
			// Unrelated row that does not match either form.
			{StoreLocation: `LocalMachine\My`, CertificatePEM: generatedCert(t, "xyz.example")},
		},
	}, http.StatusOK)

	// `?q=a%25z` is `?q=a%z` after URL-decoding. With `%` escaped
	// at the SQL layer, this is a literal-byte search and matches
	// nothing. Without the escape, the same query would match
	// `amazon.example` (a wildcard z somewhere later) — that is
	// the regression this test is here to catch.
	var list certListDTO
	operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/certificates?q=a%25z", http.StatusOK, &list)
	if len(list.Items) != 0 {
		subjects := make([]string, 0, len(list.Items))
		for _, it := range list.Items {
			subjects = append(subjects, it.Subject)
		}
		t.Errorf("q=a%%z items = %d, want 0 (got %v); `%%` must be literal, not LIKE wildcard",
			len(list.Items), subjects)
	}
}

// TestOperatorListCertificatesAgentIDFilterCrossOrgReturnsEmpty
// hardens the org-scoping promise on the agent_id filter. A
// foreign agent's id passed as `?agent_id=...` on /certificates
// (as opposed to the path-bound /agents/{id}/certificates which
// 404s on cross-org) returns 200 with an empty items list — the
// foreign agent has no observations IN THE HOME ORG by
// construction of the composite FK
// `(observations.organization_id, agent_id) REFERENCES
// agents(organization_id, id)`.
func TestOperatorListCertificatesAgentIDFilterCrossOrgReturnsEmpty(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	// Seed a real cert in the home org so the list isn't empty
	// for unrelated reasons.
	submitOneCert(t, srv.URL, credential,
		generatedCert(t, "home-cert.example"),
		`LocalMachine\My`, "")

	// Seed a foreign agent in a different org. There is no path
	// in the product that produces a cert observation for this
	// agent in the home org — the composite FK prevents it.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	const foreignAgentID = "foreign-agent-h020-hardening"
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO organizations (id, name) VALUES ('other-org', 'Other Org')`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO agents (id, organization_id, hostname, version, status, enrolled_at, last_seen_at)
			 VALUES ($1, 'other-org', 'foreign-host', '', 'active', now(), now())`,
			foreignAgentID)
		return err
	}); err != nil {
		t.Fatalf("seed foreign agent: %v", err)
	}

	// Filter the home org's list by the foreign agent id. The
	// expected response is 200 OK with an empty items array — the
	// agent_id filter is a content filter, not an identity check,
	// so it MUST not 404 here even though the agent does not
	// exist in the caller's org.
	var list certListDTO
	operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/certificates?agent_id="+foreignAgentID, http.StatusOK, &list)
	if len(list.Items) != 0 {
		t.Errorf("foreign agent_id filter items = %d, want 0; got %+v", len(list.Items), list.Items)
	}
}

// TestOperatorListCertificatesCursorIsNotIdentity proves that an
// opaque cursor is a comparison anchor, not an authentication
// token. A cursor whose embedded id is a real cert in a DIFFERENT
// org (or no real cert at all) must still produce a valid
// home-org response — it cannot leak data from another org and it
// cannot crash. This is the negative-space test for "cursor is
// just an ordering offset".
func TestOperatorListCertificatesCursorIsNotIdentity(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	// Two home-org certs so the list is non-trivial.
	submitCertBatch(t, srv.URL, credential, ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, CertificatePEM: generatedCert(t, "home-a.example")},
			{StoreLocation: `LocalMachine\My`, CertificatePEM: generatedCert(t, "home-b.example")},
		},
	}, http.StatusOK)

	// Craft a cursor anchored to a far-future timestamp + a
	// fabricated id. The decoder sees this as valid (RFC3339 ok,
	// non-empty fields). The repository uses it as a comparison
	// anchor: with future timestamp, the WHERE clause matches
	// everything in the home org. Result: 200 OK, items present,
	// no leak.
	farFuture := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	rawCursor := farFuture + "|fabricated-cross-org-id-bytes"
	cursor := base64.RawURLEncoding.EncodeToString([]byte(rawCursor))

	var list certListDTO
	operatorGetJSON(t, srv.URL, adminClient,
		"/api/v1/certificates?cursor="+cursor+"&current_only=false", http.StatusOK, &list)
	// The home org has 2 certs; both should be returned because
	// every home cert has a last_seen_at strictly less than the
	// year-2099 anchor.
	if len(list.Items) != 2 {
		t.Errorf("fabricated cursor items = %d, want 2 (both home-org certs)", len(list.Items))
	}
	for _, it := range list.Items {
		if !strings.HasPrefix(it.Subject, "CN=home-") {
			t.Errorf("foreign-looking subject in list: %q", it.Subject)
		}
	}
}
