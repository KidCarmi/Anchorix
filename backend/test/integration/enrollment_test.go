//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/auth"
)

const operatorEmail = "operator@example.com"

// signInAdmin creates an operator-admin and logs them in via the
// real HTTP flow. Returns an HTTP client whose cookie jar carries
// the session cookie, plus the user struct so tests can assert on
// org id.
func signInAdmin(t *testing.T, srv stringer, svc *auth.Service) *http.Client {
	t.Helper()
	user := seedAdmin(t, svc)
	_ = user
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	body := strings.NewReader(`{"email":"` + testEmail + `","password":"` + testPassword + `"}`)
	req, _ := http.NewRequest(http.MethodPost, srv.URL()+"/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, want 200", resp.StatusCode)
	}
	return client
}

// stringer is a tiny interface so the helper accepts both the real
// httptest.Server (.URL is a string field) and any future wrapper.
type stringer interface{ URL() string }

// urlSrv adapts an *httptest.Server to the stringer interface above.
type urlSrv struct{ url string }

func (u urlSrv) URL() string { return u.url }

// createPackageBody is the JSON shape the handler expects.
type createPackageBody struct {
	Name             string   `json:"name"`
	Description      string   `json:"description,omitempty"`
	PackageType      string   `json:"package_type"`
	AgentVersion     string   `json:"agent_version,omitempty"`
	TTLSeconds       int      `json:"ttl_seconds"`
	MaxUses          int      `json:"max_uses"`
	DefaultGroupName string   `json:"default_group_name,omitempty"`
	DefaultLabels    []string `json:"default_labels,omitempty"`
}

type createPackageResp struct {
	ID              string   `json:"id"`
	OrganizationID  string   `json:"organization_id"`
	Name            string   `json:"name"`
	PackageType     string   `json:"package_type"`
	MaxUses         int      `json:"max_uses"`
	UsesCount       int      `json:"uses_count"`
	BootstrapSecret string   `json:"bootstrap_secret"`
	DefaultLabels   []string `json:"default_labels"`
	BootstrapMeta   struct {
		PackageID string `json:"package_id"`
		MaxUses   int    `json:"max_uses"`
	} `json:"bootstrap_metadata"`
}

func decodeJSON(t *testing.T, body io.ReadCloser, out any) {
	t.Helper()
	defer body.Close()
	if err := json.NewDecoder(body).Decode(out); err != nil {
		t.Fatalf("decode: %v", err)
	}
}

// adminCreatePackage walks through the operator flow: login as
// admin, POST /deployment-packages with the given body, return the
// parsed response.
func adminCreatePackage(t *testing.T, srv string, client *http.Client, in createPackageBody) createPackageResp {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, srv+"/api/v1/deployment-packages", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("create deployment package: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("create package status = %d; body=%s", resp.StatusCode, b)
	}
	var out createPackageResp
	decodeJSON(t, resp.Body, &out)
	return out
}

func enrollAgent(srv string, payload map[string]any) (*http.Response, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, srv+"/api/v1/agents/enroll", bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return (&http.Client{Timeout: 5 * time.Second}).Do(req)
}

func TestDeploymentPackageCreateHappyPath(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	client := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	pkg := adminCreatePackage(t, srv.URL, client, createPackageBody{
		Name:             "Baseline Windows 0.1.0",
		PackageType:      "baseline",
		AgentVersion:     "0.1.0",
		TTLSeconds:       3600,
		MaxUses:          500,
		DefaultGroupName: "Default",
		DefaultLabels:    []string{"baseline", "win"},
	})
	if pkg.BootstrapSecret == "" {
		t.Fatal("BootstrapSecret missing from response")
	}
	if pkg.BootstrapMeta.PackageID != pkg.ID {
		t.Errorf("bootstrap_metadata.package_id = %q, want %q", pkg.BootstrapMeta.PackageID, pkg.ID)
	}
	if pkg.BootstrapMeta.MaxUses != 500 {
		t.Errorf("bootstrap_metadata.max_uses = %d, want 500", pkg.BootstrapMeta.MaxUses)
	}
	// The DB stores only the hash. Verify there is no row whose
	// bootstrap_secret_hash column equals the plaintext bytes.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var hashPlaintextMatches int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT COUNT(*) FROM deployment_packages WHERE bootstrap_secret_hash = $1`,
			[]byte(pkg.BootstrapSecret),
		).Scan(&hashPlaintextMatches)
	}); err != nil {
		t.Fatalf("count plaintext rows: %v", err)
	}
	if hashPlaintextMatches != 0 {
		t.Errorf("plaintext bootstrap secret found in DB; %d match", hashPlaintextMatches)
	}
}

func TestDeploymentPackageCreateRequiresAdmin(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	// Seed the admin so the org row gets ensured. We do NOT log in
	// as admin here — the rest of the test exercises anonymous and
	// operator-role 403.
	_ = seedAdmin(t, svc)

	// Anonymous: 401.
	body := `{"name":"x","package_type":"baseline","ttl_seconds":3600,"max_uses":1}`
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/deployment-packages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("anon: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous status = %d, want 401", resp.StatusCode)
	}

	// Non-admin operator: 403. Create one directly via the auth
	// service so we can authenticate as a non-admin.
	if _, err := svc.CreateUser(context.Background(), "anchorix", operatorEmail, "Op", testPassword, auth.RoleOperator); err != nil {
		t.Fatalf("create operator: %v", err)
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	loginBody := strings.NewReader(`{"email":"` + operatorEmail + `","password":"` + testPassword + `"}`)
	loginReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/auth/login", loginBody)
	loginReq.Header.Set("Content-Type", "application/json")
	loginResp, err := client.Do(loginReq)
	if err != nil {
		t.Fatalf("operator login: %v", err)
	}
	loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("operator login status = %d, want 200", loginResp.StatusCode)
	}

	req2, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/deployment-packages", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("operator create: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("operator status = %d, want 403", resp2.StatusCode)
	}
}

func TestDeploymentPackageCreateRejectsInvalidInput(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	client := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	body := `{"name":"","package_type":"unknown","ttl_seconds":0,"max_uses":0}`
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/deployment-packages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestEnrollAgentHappyPath(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	client := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	pkg := adminCreatePackage(t, srv.URL, client, createPackageBody{
		Name:             "SCCM rollout - Finance",
		PackageType:      "bulk_sccm",
		AgentVersion:     "0.1.0",
		TTLSeconds:       3600,
		MaxUses:          50,
		DefaultGroupName: "Finance",
		DefaultLabels:    []string{"sccm", "finance"},
	})

	resp, err := enrollAgent(srv.URL, map[string]any{
		"bootstrap_secret": pkg.BootstrapSecret,
		"hostname":         "fin-laptop-01",
		"agent_version":    "0.1.0",
		"install_id":       "install-fin-01",
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("enroll status = %d; body=%s", resp.StatusCode, b)
	}
	var enrolled struct {
		AgentID         string `json:"agent_id"`
		OrganizationID  string `json:"organization_id"`
		Status          string `json:"status"`
		AgentCredential string `json:"agent_credential"`
	}
	decodeJSON(t, resp.Body, &enrolled)
	if enrolled.AgentID == "" {
		t.Fatal("agent_id missing")
	}
	if enrolled.AgentCredential == "" {
		t.Fatal("agent_credential missing")
	}
	if enrolled.Status != "active" {
		t.Errorf("status = %q, want active", enrolled.Status)
	}

	// GET /agents must return the freshly enrolled row with the
	// package's group/labels.
	listReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/agents", nil)
	listResp, err := client.Do(listReq)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d, want 200", listResp.StatusCode)
	}
	var listed struct {
		Items []struct {
			ID                  string   `json:"id"`
			Hostname            string   `json:"hostname"`
			Status              string   `json:"status"`
			DeploymentPackageID string   `json:"deployment_package_id"`
			GroupName           string   `json:"group_name"`
			Labels              []string `json:"labels"`
		} `json:"items"`
	}
	decodeJSON(t, listResp.Body, &listed)
	if len(listed.Items) != 1 {
		t.Fatalf("agents list count = %d, want 1", len(listed.Items))
	}
	got := listed.Items[0]
	if got.ID != enrolled.AgentID {
		t.Errorf("listed id = %q, want %q", got.ID, enrolled.AgentID)
	}
	if got.Hostname != "fin-laptop-01" {
		t.Errorf("listed hostname = %q", got.Hostname)
	}
	if got.DeploymentPackageID != pkg.ID {
		t.Errorf("deployment_package_id = %q, want %q", got.DeploymentPackageID, pkg.ID)
	}
	if got.GroupName != "Finance" {
		t.Errorf("group_name = %q, want Finance", got.GroupName)
	}
	if len(got.Labels) != 2 || got.Labels[0] != "sccm" || got.Labels[1] != "finance" {
		t.Errorf("labels = %v", got.Labels)
	}

	// uses_count should have been incremented to 1.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var uses int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT uses_count FROM deployment_packages WHERE id = $1`, pkg.ID).Scan(&uses)
	}); err != nil {
		t.Fatalf("uses_count read: %v", err)
	}
	if uses != 1 {
		t.Errorf("uses_count = %d, want 1", uses)
	}
}

func TestEnrollAgentRejectsBadSecret(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, _ := testServer(t, db)

	resp, err := enrollAgent(srv.URL, map[string]any{
		"bootstrap_secret": "not-a-real-secret",
		"hostname":         "ws-001",
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestEnrollAgentRejectsRevokedPackage(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	client := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	pkg := adminCreatePackage(t, srv.URL, client, createPackageBody{
		Name:        "VIP",
		PackageType: "vip",
		TTLSeconds:  3600,
		MaxUses:     10,
	})

	// Revoke the package via direct SQL — the revoke API is not part
	// of this PR.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE deployment_packages SET revoked_at = now() WHERE id = $1`, pkg.ID)
		return err
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	resp, err := enrollAgent(srv.URL, map[string]any{
		"bootstrap_secret": pkg.BootstrapSecret,
		"hostname":         "ws-001",
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestEnrollAgentRejectsExpiredPackage(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	client := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	pkg := adminCreatePackage(t, srv.URL, client, createPackageBody{
		Name:        "Lab",
		PackageType: "lab",
		TTLSeconds:  3600,
		MaxUses:     10,
	})

	// Force the package into the past.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE deployment_packages SET expires_at = now() - interval '1 hour' WHERE id = $1`, pkg.ID)
		return err
	}); err != nil {
		t.Fatalf("expire: %v", err)
	}

	resp, err := enrollAgent(srv.URL, map[string]any{
		"bootstrap_secret": pkg.BootstrapSecret,
		"hostname":         "ws-001",
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestEnrollAgentRejectsExhaustedPackage(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	client := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	pkg := adminCreatePackage(t, srv.URL, client, createPackageBody{
		Name:        "Tiny",
		PackageType: "lab",
		TTLSeconds:  3600,
		MaxUses:     1,
	})

	// First enrollment succeeds.
	resp1, err := enrollAgent(srv.URL, map[string]any{
		"bootstrap_secret": pkg.BootstrapSecret,
		"hostname":         "ws-001",
		"install_id":       "i1",
	})
	if err != nil {
		t.Fatalf("enroll #1: %v", err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusCreated {
		t.Fatalf("enroll #1 status = %d, want 201", resp1.StatusCode)
	}

	// Second enrollment exhausts the package — rejected.
	resp2, err := enrollAgent(srv.URL, map[string]any{
		"bootstrap_secret": pkg.BootstrapSecret,
		"hostname":         "ws-002",
		"install_id":       "i2",
	})
	if err != nil {
		t.Fatalf("enroll #2: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("enroll #2 status = %d, want 401", resp2.StatusCode)
	}
}

func TestEnrollAgentMaxUsesAtomicUnderConcurrency(t *testing.T) {
	// CLAUDE.md §18 + AGENT_ENROLLMENT.md atomicity invariant: even
	// when many devices race through the enrollment endpoint, the
	// number of agents created cannot exceed max_uses. The
	// conditional UPDATE inside IncrementUses() is the choke point;
	// this test fires N concurrent enrollments at a package with
	// max_uses=K and asserts exactly K succeed.
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	client := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	const concurrentEnrollments = 20
	const maxUses = 7
	pkg := adminCreatePackage(t, srv.URL, client, createPackageBody{
		Name:        "Concurrency",
		PackageType: "bulk_sccm",
		TTLSeconds:  3600,
		MaxUses:     maxUses,
	})

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		success int
		reject  int
	)
	for i := 0; i < concurrentEnrollments; i++ {
		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()
			resp, err := enrollAgent(srv.URL, map[string]any{
				"bootstrap_secret": pkg.BootstrapSecret,
				"hostname":         "ws-concurrent",
				"install_id":       "concurrent-install-" + itoa(i),
			})
			if err != nil {
				return
			}
			defer resp.Body.Close()
			mu.Lock()
			defer mu.Unlock()
			switch resp.StatusCode {
			case http.StatusCreated:
				success++
			case http.StatusUnauthorized:
				reject++
			}
		}()
	}
	wg.Wait()

	if success != maxUses {
		t.Errorf("successful enrollments = %d, want %d", success, maxUses)
	}
	if success+reject < concurrentEnrollments {
		t.Errorf("accounted enrollments = %d (success=%d reject=%d); want %d", success+reject, success, reject, concurrentEnrollments)
	}
	// uses_count in the DB should equal max_uses.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var uses int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT uses_count FROM deployment_packages WHERE id = $1`, pkg.ID).Scan(&uses)
	}); err != nil {
		t.Fatalf("uses_count read: %v", err)
	}
	if uses != maxUses {
		t.Errorf("uses_count = %d, want %d", uses, maxUses)
	}
}

func TestEnrollAgentDuplicateInstallIDRejected(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	client := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	pkg := adminCreatePackage(t, srv.URL, client, createPackageBody{
		Name:        "Dup",
		PackageType: "baseline",
		TTLSeconds:  3600,
		MaxUses:     10,
	})

	// First enrollment with install_id succeeds.
	resp1, err := enrollAgent(srv.URL, map[string]any{
		"bootstrap_secret": pkg.BootstrapSecret,
		"hostname":         "ws-a",
		"install_id":       "shared-install-id",
	})
	if err != nil {
		t.Fatalf("enroll #1: %v", err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusCreated {
		t.Fatalf("enroll #1 status = %d", resp1.StatusCode)
	}

	// Second enrollment with the same install_id must be rejected.
	resp2, err := enrollAgent(srv.URL, map[string]any{
		"bootstrap_secret": pkg.BootstrapSecret,
		"hostname":         "ws-b",
		"install_id":       "shared-install-id",
	})
	if err != nil {
		t.Fatalf("enroll #2: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("enroll #2 status = %d, want 401", resp2.StatusCode)
	}
}

func TestEnrollAgentLeavesNoSecretInLogs_ViaAuditMetadataSpotCheck(t *testing.T) {
	// Belt and braces: enroll, then scan every audit_events row's
	// metadata for the plaintext bootstrap secret and the plaintext
	// agent credential. Neither must appear. (The H-001
	// redaction_test.go covers the broader log surface.)
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	client := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	pkg := adminCreatePackage(t, srv.URL, client, createPackageBody{
		Name:        "Audit-check",
		PackageType: "baseline",
		TTLSeconds:  3600,
		MaxUses:     10,
	})

	resp, err := enrollAgent(srv.URL, map[string]any{
		"bootstrap_secret": pkg.BootstrapSecret,
		"hostname":         "audit-host",
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	defer resp.Body.Close()
	var enrolled struct {
		AgentCredential string `json:"agent_credential"`
	}
	decodeJSON(t, resp.Body, &enrolled)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var allMeta []byte
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT metadata FROM audit_events`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m []byte
			if err := rows.Scan(&m); err != nil {
				return err
			}
			allMeta = append(allMeta, m...)
		}
		return rows.Err()
	}); err != nil {
		t.Fatalf("read audit metadata: %v", err)
	}
	combined := string(allMeta)
	if strings.Contains(combined, pkg.BootstrapSecret) {
		t.Error("audit metadata leaked the bootstrap secret")
	}
	if strings.Contains(combined, enrolled.AgentCredential) {
		t.Error("audit metadata leaked the agent credential")
	}
}

// itoa is a tiny local helper used by the concurrency test so each
// goroutine submits a distinct install_id without depending on
// strconv. Keeping it local avoids reaching outside the file for a
// one-liner.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// --- POST /deployment-packages/{id}/revoke (H-005) -----------------

// revokedResponseDTO mirrors the handler's success body. Kept local
// to this test file so the test does not depend on internal handler
// types (CLAUDE.md §8.6 — integration tests treat the HTTP boundary
// as opaque).
type revokedResponseDTO struct {
	ID              string `json:"id"`
	OrganizationID  string `json:"organization_id"`
	Name            string `json:"name"`
	PackageType     string `json:"package_type"`
	RevokedAt       string `json:"revoked_at"`
	RevokedByUserID string `json:"revoked_by_user_id"`
	RevokedReason   string `json:"revoked_reason,omitempty"`
	AlreadyRevoked  bool   `json:"already_revoked"`
	BootstrapSecret string `json:"bootstrap_secret"` // MUST stay empty
}

// adminRevokePackage posts a revoke for the given package id and
// returns the parsed response. The status code is asserted equal
// to wantStatus; tests pass http.StatusOK for the happy path or
// http.StatusForbidden / http.StatusUnauthorized / http.StatusNotFound
// for negative cases.
func adminRevokePackage(t *testing.T, srv string, client *http.Client, pkgID, reason string, wantStatus int) revokedResponseDTO {
	t.Helper()
	bodyBytes, _ := json.Marshal(map[string]string{"reason": reason})
	req, _ := http.NewRequest(http.MethodPost, srv+"/api/v1/deployment-packages/"+pkgID+"/revoke", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("revoke status = %d, want %d; body=%s", resp.StatusCode, wantStatus, b)
	}
	if wantStatus != http.StatusOK {
		return revokedResponseDTO{}
	}
	var out revokedResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode revoke: %v", err)
	}
	return out
}

func TestDeploymentPackageRevokeHappyPath(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	client := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	pkg := adminCreatePackage(t, srv.URL, client, createPackageBody{
		Name:         "Baseline-revoke",
		PackageType:  "baseline",
		TTLSeconds:   3600,
		MaxUses:      10,
		AgentVersion: "0.1.0",
	})

	got := adminRevokePackage(t, srv.URL, client, pkg.ID, "version superseded", http.StatusOK)
	if got.RevokedAt == "" {
		t.Error("revoked_at missing from response")
	}
	if got.RevokedReason != "version superseded" {
		t.Errorf("revoked_reason = %q, want 'version superseded'", got.RevokedReason)
	}
	if got.AlreadyRevoked {
		t.Error("already_revoked = true on first revoke")
	}
	// Critical: the revoke response must NOT echo a bootstrap secret.
	if got.BootstrapSecret != "" {
		t.Errorf("bootstrap_secret leaked into revoke response: %q", got.BootstrapSecret)
	}

	// Subsequent enrollment through the revoked package must fail.
	enrollResp, err := enrollAgent(srv.URL, map[string]any{
		"bootstrap_secret": pkg.BootstrapSecret,
		"hostname":         "post-revoke",
	})
	if err != nil {
		t.Fatalf("enroll post-revoke: %v", err)
	}
	enrollResp.Body.Close()
	if enrollResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("enroll-after-revoke status = %d, want 401", enrollResp.StatusCode)
	}

	// Audit row: deployment_package.revoked must exist;
	// agent.enrollment_rejected with reason package_revoked must exist.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var (
		sawRevoke         bool
		sawRevokeRejected bool
	)
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT action, metadata::text FROM audit_events WHERE target_id = $1`, pkg.ID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var action, meta string
			if err := rows.Scan(&action, &meta); err != nil {
				return err
			}
			switch action {
			case "deployment_package.revoked":
				sawRevoke = true
				if strings.Contains(meta, pkg.BootstrapSecret) {
					t.Errorf("audit metadata leaked bootstrap secret")
				}
			case "agent.enrollment_rejected":
				// PostgreSQL renders jsonb::text with a single space
				// after each colon and comma, so an exact
				// `"reason":"package_revoked"` substring search would
				// miss the stored form `"reason": "package_revoked"`.
				// The bare `package_revoked` substring is unique
				// enough — no other audit reason contains it.
				if strings.Contains(meta, "package_revoked") {
					sawRevokeRejected = true
				}
			}
		}
		return rows.Err()
	}); err != nil {
		t.Fatalf("audit read: %v", err)
	}
	if !sawRevoke {
		t.Error("missing deployment_package.revoked audit row")
	}
	if !sawRevokeRejected {
		t.Error("missing agent.enrollment_rejected (reason=package_revoked) audit row")
	}
}

func TestDeploymentPackageRevokeRequiresAdmin(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	// Seed an admin so the org row + a real package exist, but do
	// NOT log in as admin for the anonymous + operator-role tests
	// below.
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	pkg := adminCreatePackage(t, srv.URL, adminClient, createPackageBody{
		Name: "RBAC", PackageType: "baseline", TTLSeconds: 3600, MaxUses: 5,
	})

	// Anonymous → 401.
	anonReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/deployment-packages/"+pkg.ID+"/revoke", strings.NewReader(`{}`))
	anonReq.Header.Set("Content-Type", "application/json")
	anonResp, err := http.DefaultClient.Do(anonReq)
	if err != nil {
		t.Fatalf("anon: %v", err)
	}
	anonResp.Body.Close()
	if anonResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anon status = %d, want 401", anonResp.StatusCode)
	}

	// Operator role → 403.
	if _, err := svc.CreateUser(context.Background(), "anchorix", operatorEmail, "Op", testPassword, auth.RoleOperator); err != nil {
		t.Fatalf("create operator: %v", err)
	}
	jar, _ := cookiejar.New(nil)
	opClient := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	loginBody := strings.NewReader(`{"email":"` + operatorEmail + `","password":"` + testPassword + `"}`)
	loginReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/auth/login", loginBody)
	loginReq.Header.Set("Content-Type", "application/json")
	loginResp, err := opClient.Do(loginReq)
	if err != nil {
		t.Fatalf("operator login: %v", err)
	}
	loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("operator login status = %d, want 200", loginResp.StatusCode)
	}
	opReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/deployment-packages/"+pkg.ID+"/revoke", strings.NewReader(`{}`))
	opReq.Header.Set("Content-Type", "application/json")
	opResp, err := opClient.Do(opReq)
	if err != nil {
		t.Fatalf("operator revoke: %v", err)
	}
	opResp.Body.Close()
	if opResp.StatusCode != http.StatusForbidden {
		t.Errorf("operator status = %d, want 403", opResp.StatusCode)
	}
}

func TestDeploymentPackageRevokeNotFound(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	client := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	adminRevokePackage(t, srv.URL, client, "no-such-id", "", http.StatusNotFound)
}

func TestDeploymentPackageRevokeIdempotent(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	client := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	pkg := adminCreatePackage(t, srv.URL, client, createPackageBody{
		Name: "Idem", PackageType: "baseline", TTLSeconds: 3600, MaxUses: 5,
	})

	first := adminRevokePackage(t, srv.URL, client, pkg.ID, "first", http.StatusOK)
	if first.AlreadyRevoked {
		t.Error("first revoke reported already_revoked=true")
	}

	second := adminRevokePackage(t, srv.URL, client, pkg.ID, "second", http.StatusOK)
	if !second.AlreadyRevoked {
		t.Error("second revoke did NOT report already_revoked=true")
	}
	// The response reflects the original revoker's reason — re-revoke
	// must NOT overwrite the existing revoke metadata.
	if second.RevokedReason != "first" {
		t.Errorf("revoked_reason after re-revoke = %q, want 'first' (preserved)", second.RevokedReason)
	}

	// Audit table must contain exactly ONE deployment_package.revoked
	// row for this package — the idempotent second call writes none.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var revokeAuditCount int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT COUNT(*) FROM audit_events WHERE action = 'deployment_package.revoked' AND target_id = $1`,
			pkg.ID,
		).Scan(&revokeAuditCount)
	}); err != nil {
		t.Fatalf("audit count: %v", err)
	}
	if revokeAuditCount != 1 {
		t.Errorf("deployment_package.revoked audit count = %d, want 1 (idempotent)", revokeAuditCount)
	}
}

// --- GET /agent/me (H-007) -----------------------------------------

// agentMeDTO mirrors the handler's success body. Kept local to
// this test file so the test does not depend on internal handler
// types (CLAUDE.md §8.6 — integration tests treat the HTTP
// boundary as opaque).
type agentMeDTO struct {
	AgentID             string   `json:"agent_id"`
	OrganizationID      string   `json:"organization_id"`
	Status              string   `json:"status"`
	DeploymentPackageID string   `json:"deployment_package_id"`
	AgentVersion        string   `json:"agent_version"`
	GroupName           string   `json:"group_name"`
	Labels              []string `json:"labels"`
}

// enrolledAgent walks through the full create-package + enroll
// flow and returns the resulting agent id + plaintext credential
// for use by /agent/me tests.
func enrolledAgent(t *testing.T, srv string, adminClient *http.Client) (agentID, credential string) {
	t.Helper()
	pkg := adminCreatePackage(t, srv, adminClient, createPackageBody{
		Name:             "auth-test",
		PackageType:      "baseline",
		AgentVersion:     "0.1.0",
		TTLSeconds:       3600,
		MaxUses:          5,
		DefaultGroupName: "Default",
		DefaultLabels:    []string{"baseline"},
	})
	resp, err := enrollAgent(srv, map[string]any{
		"bootstrap_secret": pkg.BootstrapSecret,
		"hostname":         "auth-host",
		"agent_version":    "0.1.0",
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("enroll status = %d; body=%s", resp.StatusCode, b)
	}
	var enrolled struct {
		AgentID         string `json:"agent_id"`
		AgentCredential string `json:"agent_credential"`
	}
	decodeJSON(t, resp.Body, &enrolled)
	if enrolled.AgentCredential == "" {
		t.Fatal("enroll returned empty credential")
	}
	return enrolled.AgentID, enrolled.AgentCredential
}

func TestAgentMeHappyPath(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	agentID, credential := enrolledAgent(t, srv.URL, adminClient)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/agent/me", nil)
	req.Header.Set("Authorization", "Bearer "+credential)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("/agent/me: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("/agent/me status = %d; body=%s", resp.StatusCode, b)
	}
	var got agentMeDTO
	decodeJSON(t, resp.Body, &got)
	if got.AgentID != agentID {
		t.Errorf("agent_id = %q, want %q", got.AgentID, agentID)
	}
	if got.Status != "active" {
		t.Errorf("status = %q, want active", got.Status)
	}
	if got.GroupName != "Default" {
		t.Errorf("group_name = %q, want Default", got.GroupName)
	}
	// Response MUST NOT echo the credential or any hash. The raw
	// JSON body is reread from a fresh request below to assert
	// absence-of-substrings.
}

func TestAgentMeRejectsMissingHeader(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, _ := testServer(t, db)

	resp, err := http.Get(srv.URL + "/api/v1/agent/me")
	if err != nil {
		t.Fatalf("/agent/me: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}

	// Codex P2 fix: even missing/malformed headers must land in
	// the security audit feed so probing patterns are visible.
	// The middleware now passes HeaderRejection=header_missing
	// through to AuthenticateAgent for exactly this purpose.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var count int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT COUNT(*) FROM audit_events
			  WHERE action = 'agent.authentication_failed'
			    AND metadata::text LIKE '%header_missing%'`,
		).Scan(&count)
	}); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("audit rows with reason=header_missing = %d, want 1", count)
	}
}

func TestAgentMeRejectsMalformedHeader(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, _ := testServer(t, db)

	cases := []string{
		"",                   // missing
		"not-bearer-scheme",  // wrong scheme
		"Bearer",             // bearer but no token
		"Bearer ",            // bearer with empty token
		"Basic dXNlcjpwYXNz", // wrong scheme entirely
	}
	for _, header := range cases {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/agent/me", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("header %q: %v", header, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("header %q: status = %d, want 401", header, resp.StatusCode)
		}
	}
}

func TestAgentMeRejectsUnknownCredential(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, _ := testServer(t, db)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/agent/me", nil)
	req.Header.Set("Authorization", "Bearer this-credential-was-never-issued")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("/agent/me: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAgentMeRejectsDisabledAgent(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	// Flip agent status to disabled via direct SQL (the agent-
	// revoke API is not part of this PR).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE agents SET status = 'disabled' WHERE credential_hash IS NOT NULL`)
		return err
	}); err != nil {
		t.Fatalf("disable agent: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/agent/me", nil)
	req.Header.Set("Authorization", "Bearer "+credential)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("/agent/me: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAgentMeOperatorCookieIsRejected(t *testing.T) {
	// An authenticated operator cookie MUST NOT grant access to
	// /agent/me — the agent and operator identity axes are kept
	// strictly separate (CLAUDE.md §8.6).
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/agent/me", nil)
	resp, err := adminClient.Do(req)
	if err != nil {
		t.Fatalf("/agent/me: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("admin cookie reached /agent/me; status = %d, want 401", resp.StatusCode)
	}
}

func TestAuthMeAgentBearerIsRejected(t *testing.T) {
	// Symmetric: an agent bearer MUST NOT authenticate to the
	// operator /auth/me endpoint. /auth/me requires a session
	// cookie.
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+credential)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("/auth/me: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("agent bearer reached /auth/me; status = %d, want 401", resp.StatusCode)
	}
}

func TestAgentMeResponseDoesNotEchoCredential(t *testing.T) {
	// Belt-and-braces: read the raw response body and assert that
	// the plaintext credential string does not appear anywhere in
	// it. The handler uses a typed struct that excludes the
	// credential field, but a regression that inlined a debug
	// dump would be caught here.
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/agent/me", nil)
	req.Header.Set("Authorization", "Bearer "+credential)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("/agent/me: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), credential) {
		t.Error("/agent/me response echoed the plaintext credential")
	}
}

// --- POST /agent/heartbeat (PR-017) -----------------------------------

type heartbeatRespDTO struct {
	Status               string `json:"status"`
	ServerTime           string `json:"server_time"`
	NextHeartbeatSeconds int    `json:"next_heartbeat_seconds"`
}

// agentHeartbeat performs an authenticated heartbeat request and
// returns the parsed response. Status code is asserted equal to
// wantStatus.
func agentHeartbeat(t *testing.T, srv, credential string, body any, wantStatus int) heartbeatRespDTO {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
	}
	req, _ := http.NewRequest(http.MethodPost, srv+"/api/v1/agent/heartbeat", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("heartbeat status = %d, want %d; body=%s", resp.StatusCode, wantStatus, b)
	}
	if wantStatus != http.StatusOK {
		return heartbeatRespDTO{}
	}
	var out heartbeatRespDTO
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode heartbeat: %v", err)
	}
	return out
}

func TestAgentHeartbeatUpdatesLastSeenAt(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	agentID, credential := enrolledAgent(t, srv.URL, adminClient)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var before, after time.Time
	readLastSeen := func() time.Time {
		var ts time.Time
		if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT last_seen_at FROM agents WHERE id = $1`, agentID).Scan(&ts)
		}); err != nil {
			t.Fatalf("read last_seen_at: %v", err)
		}
		return ts
	}
	before = readLastSeen()

	resp := agentHeartbeat(t, srv.URL, credential, map[string]string{
		"agent_version": "0.1.1",
		"hostname":      "renamed",
	}, http.StatusOK)
	if resp.Status != "ok" {
		t.Errorf("status = %q, want ok", resp.Status)
	}
	if resp.NextHeartbeatSeconds <= 0 {
		t.Errorf("next_heartbeat_seconds = %d, want > 0", resp.NextHeartbeatSeconds)
	}
	if resp.ServerTime == "" {
		t.Error("server_time missing")
	}

	after = readLastSeen()
	if !after.After(before) {
		t.Errorf("last_seen_at = %v; want strictly after %v", after, before)
	}

	// agent_version and hostname columns must have been refreshed
	// from the request body.
	var version, hostname string
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT version, hostname FROM agents WHERE id = $1`, agentID).
			Scan(&version, &hostname)
	}); err != nil {
		t.Fatalf("read drift columns: %v", err)
	}
	if version != "0.1.1" {
		t.Errorf("version = %q, want 0.1.1", version)
	}
	if hostname != "renamed" {
		t.Errorf("hostname = %q, want renamed", hostname)
	}

	// Audit policy: heartbeats are operational telemetry, not an
	// audit stream. No new audit row should land for this heartbeat
	// beyond what enrollment already wrote.
	var heartbeatAudits int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT COUNT(*) FROM audit_events
			  WHERE target_id = $1
			    AND action LIKE 'agent.heartbeat%'`,
			agentID,
		).Scan(&heartbeatAudits)
	}); err != nil {
		t.Fatalf("audit count: %v", err)
	}
	if heartbeatAudits != 0 {
		t.Errorf("heartbeat audit count = %d, want 0 (operational telemetry, not audit)", heartbeatAudits)
	}

	// And exactly one agent row exists — heartbeat MUST NOT create
	// a duplicate.
	var rowCount int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COUNT(*) FROM agents`).Scan(&rowCount)
	}); err != nil {
		t.Fatalf("agents count: %v", err)
	}
	if rowCount != 1 {
		t.Errorf("agents row count = %d, want 1 (heartbeat must not create rows)", rowCount)
	}
}

func TestAgentHeartbeatRejectsUnauthenticated(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, _ := testServer(t, db)

	// Anonymous — no Authorization header.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/agent/heartbeat", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("anon: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anon status = %d, want 401", resp.StatusCode)
	}
}

func TestAgentHeartbeatRejectsOperatorCookie(t *testing.T) {
	// Operator session cookies must not authenticate /agent/*.
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/agent/heartbeat", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := adminClient.Do(req)
	if err != nil {
		t.Fatalf("operator: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("operator cookie reached heartbeat; status = %d, want 401", resp.StatusCode)
	}
}

func TestAgentHeartbeatRejectsDisabledAgent(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	// Flip status to disabled via direct SQL (agent-revoke API is
	// not part of this PR).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE agents SET status = 'disabled' WHERE credential_hash IS NOT NULL`)
		return err
	}); err != nil {
		t.Fatalf("disable agent: %v", err)
	}

	// Disabled agent → middleware short-circuits before the
	// heartbeat handler runs.
	agentHeartbeat(t, srv.URL, credential, map[string]string{}, http.StatusUnauthorized)
}

func TestAgentHeartbeatPreservesValuesOnEmptyBody(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	agentID, credential := enrolledAgent(t, srv.URL, adminClient)

	// Seed known starting values via one heartbeat carrying both.
	agentHeartbeat(t, srv.URL, credential, map[string]string{
		"agent_version": "0.1.0",
		"hostname":      "ws-original",
	}, http.StatusOK)

	// Empty body — both fields preserved.
	agentHeartbeat(t, srv.URL, credential, map[string]string{}, http.StatusOK)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var version, hostname string
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT version, hostname FROM agents WHERE id = $1`, agentID).
			Scan(&version, &hostname)
	}); err != nil {
		t.Fatalf("read drift: %v", err)
	}
	if version != "0.1.0" {
		t.Errorf("version = %q after empty heartbeat; want preserved 0.1.0", version)
	}
	if hostname != "ws-original" {
		t.Errorf("hostname = %q after empty heartbeat; want preserved ws-original", hostname)
	}
}
