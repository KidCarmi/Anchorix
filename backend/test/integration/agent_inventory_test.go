//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// inventoryReqDTO is the JSON body the agent submits to
// POST /api/v1/agent/inventory. Mirrors handlers.agentInventoryRequest;
// duplicated here so the test does not depend on internal types.
type inventoryReqDTO struct {
	Hostname     string     `json:"hostname"`
	OSName       string     `json:"os_name"`
	OSVersion    string     `json:"os_version"`
	AgentVersion string     `json:"agent_version"`
	MachineArch  string     `json:"machine_arch"`
	LocalIPs     []string   `json:"local_ips,omitempty"`
	InstalledAt  *time.Time `json:"installed_at,omitempty"`
}

type inventoryRespDTO struct {
	Status     string `json:"status"`
	ReceivedAt string `json:"received_at"`
}

type operatorInventoryRespDTO struct {
	AgentID        string     `json:"agent_id"`
	OrganizationID string     `json:"organization_id"`
	Hostname       string     `json:"hostname"`
	OSName         string     `json:"os_name"`
	OSVersion      string     `json:"os_version"`
	AgentVersion   string     `json:"agent_version"`
	MachineArch    string     `json:"machine_arch"`
	LocalIPs       []string   `json:"local_ips"`
	InstalledAt    *time.Time `json:"installed_at"`
	ReceivedAt     string     `json:"received_at"`
	UpdatedAt      string     `json:"updated_at"`
}

// submitInventoryRaw POSTs the supplied raw body bytes (so tests can
// exercise malformed JSON, trailing garbage, etc.). Status code is
// asserted equal to wantStatus.
func submitInventoryRaw(t *testing.T, srv, credential string, body []byte, wantStatus int) inventoryRespDTO {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv+"/api/v1/agent/inventory", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("inventory status = %d, want %d; body=%s", resp.StatusCode, wantStatus, b)
	}
	if wantStatus != http.StatusOK {
		return inventoryRespDTO{}
	}
	var out inventoryRespDTO
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	return out
}

// submitInventory marshals the body and delegates to submitInventoryRaw.
func submitInventory(t *testing.T, srv, credential string, body inventoryReqDTO, wantStatus int) inventoryRespDTO {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return submitInventoryRaw(t, srv, credential, raw, wantStatus)
}

func TestAgentInventorySubmitHappyPath(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	agentID, credential := enrolledAgent(t, srv.URL, adminClient)

	installed := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	resp := submitInventory(t, srv.URL, credential, inventoryReqDTO{
		Hostname:     "ws-001.corp.example",
		OSName:       "Windows 11",
		OSVersion:    "10.0.22631",
		AgentVersion: "0.1.0",
		MachineArch:  "amd64",
		LocalIPs:     []string{"10.0.0.5", "fe80::1%eth0"},
		InstalledAt:  &installed,
	}, http.StatusOK)
	if resp.Status != "ok" {
		t.Errorf("status = %q, want ok", resp.Status)
	}
	if resp.ReceivedAt == "" {
		t.Error("received_at missing")
	}

	// Row exists; agent_id and organization_id match the
	// authenticated principal, NOT anything from the body (there
	// were no such fields in the body — the snapshot identity axis
	// is the credential).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var (
		rowOrg, rowAgent, hostname, osName, agentVersion string
		localIPsRaw                                      []byte
		rowCount                                         int
	)
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM agent_inventory_snapshots`).Scan(&rowCount); err != nil {
			return err
		}
		return tx.QueryRow(ctx,
			`SELECT organization_id, agent_id, hostname, os_name, agent_version, local_ips
			   FROM agent_inventory_snapshots WHERE agent_id = $1`, agentID,
		).Scan(&rowOrg, &rowAgent, &hostname, &osName, &agentVersion, &localIPsRaw)
	}); err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	if rowCount != 1 {
		t.Errorf("row count = %d, want 1", rowCount)
	}
	if rowOrg != "anchorix" {
		t.Errorf("org = %q, want anchorix (from auth context)", rowOrg)
	}
	if rowAgent != agentID {
		t.Errorf("agent_id = %q, want %q (from auth context)", rowAgent, agentID)
	}
	if hostname != "ws-001.corp.example" {
		t.Errorf("hostname = %q", hostname)
	}
	if osName != "Windows 11" {
		t.Errorf("os_name = %q", osName)
	}
	if agentVersion != "0.1.0" {
		t.Errorf("agent_version = %q", agentVersion)
	}
	var localIPs []string
	if err := json.Unmarshal(localIPsRaw, &localIPs); err != nil {
		t.Fatalf("unmarshal local_ips: %v", err)
	}
	if len(localIPs) != 2 {
		t.Errorf("local_ips len = %d, want 2", len(localIPs))
	}
}

func TestAgentInventorySecondSubmitReplacesSnapshot(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	agentID, credential := enrolledAgent(t, srv.URL, adminClient)

	submitInventory(t, srv.URL, credential, inventoryReqDTO{
		Hostname:     "first",
		AgentVersion: "0.1.0",
		MachineArch:  "amd64",
	}, http.StatusOK)
	submitInventory(t, srv.URL, credential, inventoryReqDTO{
		Hostname:     "second",
		AgentVersion: "0.1.1",
		MachineArch:  "amd64",
		LocalIPs:     []string{"10.0.0.6"},
	}, http.StatusOK)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var (
		rowCount               int
		hostname, agentVersion string
		localIPsRaw            []byte
	)
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx,
			`SELECT COUNT(*) FROM agent_inventory_snapshots WHERE agent_id = $1`, agentID,
		).Scan(&rowCount); err != nil {
			return err
		}
		return tx.QueryRow(ctx,
			`SELECT hostname, agent_version, local_ips FROM agent_inventory_snapshots WHERE agent_id = $1`, agentID,
		).Scan(&hostname, &agentVersion, &localIPsRaw)
	}); err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	if rowCount != 1 {
		t.Errorf("row count = %d, want 1 (UPSERT must not create duplicate)", rowCount)
	}
	if hostname != "second" {
		t.Errorf("hostname = %q, want second (latest)", hostname)
	}
	if agentVersion != "0.1.1" {
		t.Errorf("agent_version = %q, want 0.1.1 (latest)", agentVersion)
	}
	var localIPs []string
	if err := json.Unmarshal(localIPsRaw, &localIPs); err != nil {
		t.Fatalf("unmarshal local_ips: %v", err)
	}
	if len(localIPs) != 1 || localIPs[0] != "10.0.0.6" {
		t.Errorf("local_ips = %#v, want [10.0.0.6] (latest)", localIPs)
	}
}

func TestAgentInventoryEmptyLocalIPs(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	// LocalIPs omitted entirely.
	submitInventory(t, srv.URL, credential, inventoryReqDTO{
		Hostname:    "no-ips",
		MachineArch: "amd64",
	}, http.StatusOK)

	// Explicit empty list.
	submitInventory(t, srv.URL, credential, inventoryReqDTO{
		Hostname:    "no-ips",
		MachineArch: "amd64",
		LocalIPs:    []string{},
	}, http.StatusOK)
}

func TestAgentInventoryRejectsMalformedJSON(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	// Garbage payload — not valid JSON.
	submitInventoryRaw(t, srv.URL, credential, []byte(`{"hostname": "no-close"`), http.StatusBadRequest)
}

func TestAgentInventoryRejectsTrailingJSON(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	// Valid first object followed by a second object — must be
	// rejected by the documented two-Decode-must-EOF idiom.
	submitInventoryRaw(t, srv.URL, credential,
		[]byte(`{"hostname":"first"}{"hostname":"second"}`),
		http.StatusBadRequest)

	// Valid object followed by non-JSON garbage — same envelope.
	submitInventoryRaw(t, srv.URL, credential,
		[]byte(`{"hostname":"first"} not-json`),
		http.StatusBadRequest)
}

func TestAgentInventoryRejectsOversizeField(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	submitInventory(t, srv.URL, credential, inventoryReqDTO{
		// 256 bytes — one over MaxHostnameLength.
		Hostname: strings.Repeat("h", 256),
	}, http.StatusBadRequest)
}

func TestAgentInventoryRejectsTooManyLocalIPs(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	// 33 entries — one over MaxLocalIPs.
	ips := make([]string, 33)
	for i := range ips {
		ips[i] = "10.0.0.1"
	}
	submitInventory(t, srv.URL, credential, inventoryReqDTO{
		Hostname: "host",
		LocalIPs: ips,
	}, http.StatusBadRequest)
}

func TestAgentInventoryRejectsOperatorCookie(t *testing.T) {
	// Operator session cookies must not authenticate /agent/*.
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/agent/inventory",
		strings.NewReader(`{"hostname":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := adminClient.Do(req)
	if err != nil {
		t.Fatalf("operator: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("operator cookie reached inventory; status = %d, want 401", resp.StatusCode)
	}
}

func TestAgentInventoryRejectsUnauthenticated(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, _ := testServer(t, db)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/agent/inventory",
		strings.NewReader(`{}`))
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

func TestAgentInventoryEmitsNoAuditRow(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	agentID, credential := enrolledAgent(t, srv.URL, adminClient)

	submitInventory(t, srv.URL, credential, inventoryReqDTO{
		Hostname: "audit-test",
	}, http.StatusOK)

	// Audit policy: inventory snapshots are operational state sync,
	// not an audit event stream. No new audit row should land for
	// the submit beyond what enrollment already wrote (auth failures
	// are still audited by the agent-auth middleware, but this is a
	// successful auth, so the only audit-side traffic that could
	// possibly appear would be wrong).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var inventoryAudits int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT COUNT(*) FROM audit_events
			  WHERE action LIKE 'agent.inventory%'
			     OR (target_id = $1 AND action LIKE 'agent.snapshot%')`,
			agentID,
		).Scan(&inventoryAudits)
	}); err != nil {
		t.Fatalf("audit count: %v", err)
	}
	if inventoryAudits != 0 {
		t.Errorf("inventory audit count = %d, want 0 (operational telemetry, not audit)", inventoryAudits)
	}
}

func TestAgentInventoryIdentityFromAuthContextNotBody(t *testing.T) {
	// Body-supplied agent_id/organization_id MUST be ignored — the
	// only authoritative identity is the bearer credential. We
	// submit a body with "extra" fields the handler does not even
	// know about; they must be dropped at decode time and the
	// snapshot must still be written for the authenticated agent.
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	agentID, credential := enrolledAgent(t, srv.URL, adminClient)

	// agent_id and organization_id are NOT part of the contract;
	// supplying them does nothing. The handler reads identity only
	// from AgentFromContext.
	rawBody := []byte(`{"hostname":"identity-test","agent_id":"forged-agent","organization_id":"other-org"}`)
	submitInventoryRaw(t, srv.URL, credential, rawBody, http.StatusOK)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var rowOrg, rowAgent string
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT organization_id, agent_id FROM agent_inventory_snapshots
			  WHERE hostname = 'identity-test'`,
		).Scan(&rowOrg, &rowAgent)
	}); err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	if rowOrg != "anchorix" {
		t.Errorf("organization_id = %q, want anchorix (from auth, ignore body)", rowOrg)
	}
	if rowAgent != agentID {
		t.Errorf("agent_id = %q, want %q (from auth, ignore body)", rowAgent, agentID)
	}

	// No row was created for "other-org" / "forged-agent".
	var stranger int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT COUNT(*) FROM agent_inventory_snapshots
			  WHERE organization_id = 'other-org' OR agent_id = 'forged-agent'`,
		).Scan(&stranger)
	}); err != nil {
		t.Fatalf("stranger count: %v", err)
	}
	if stranger != 0 {
		t.Errorf("stranger rows = %d, want 0", stranger)
	}
}

func TestOperatorGetAgentInventory(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	agentID, credential := enrolledAgent(t, srv.URL, adminClient)

	submitInventory(t, srv.URL, credential, inventoryReqDTO{
		Hostname:     "operator-read",
		OSName:       "Windows Server 2022",
		AgentVersion: "0.1.0",
		MachineArch:  "amd64",
		LocalIPs:     []string{"10.0.0.7"},
	}, http.StatusOK)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/agents/"+agentID+"/inventory", nil)
	resp, err := adminClient.Do(req)
	if err != nil {
		t.Fatalf("operator GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("operator GET status = %d; body=%s", resp.StatusCode, b)
	}
	var got operatorInventoryRespDTO
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.AgentID != agentID {
		t.Errorf("agent_id = %q, want %q", got.AgentID, agentID)
	}
	if got.Hostname != "operator-read" {
		t.Errorf("hostname = %q", got.Hostname)
	}
	if got.OSName != "Windows Server 2022" {
		t.Errorf("os_name = %q", got.OSName)
	}
	if len(got.LocalIPs) != 1 || got.LocalIPs[0] != "10.0.0.7" {
		t.Errorf("local_ips = %#v", got.LocalIPs)
	}
}

func TestOperatorGetAgentInventoryNotFound(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	// Agent with no submitted snapshot — must surface 404.
	agentID, _ := enrolledAgent(t, srv.URL, adminClient)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/agents/"+agentID+"/inventory", nil)
	resp, err := adminClient.Do(req)
	if err != nil {
		t.Fatalf("operator GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing snapshot status = %d, want 404", resp.StatusCode)
	}

	// Unknown agent id — same envelope (cross-org indistinguishable
	// from truly-missing).
	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/api/v1/agents/does-not-exist/inventory", nil)
	resp, err = adminClient.Do(req)
	if err != nil {
		t.Fatalf("operator GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown agent status = %d, want 404", resp.StatusCode)
	}
}

// TestAgentInventoryCompositeFKEnforcesOrgMatch defends the
// denormalized organization_id column on agent_inventory_snapshots.
// The application path never produces a mismatched (org, agent)
// pair (the service derives both from AgentFromContext), but a
// future buggy repository or a direct SQL path could. Migration
// 0004's composite FK
//
//	(organization_id, agent_id) -> agents(organization_id, id)
//
// must reject any insert whose organization_id disagrees with the
// agent row's own org with a 23503 foreign_key_violation. This
// test attempts that insert via raw SQL and asserts the constraint
// fires.
func TestAgentInventoryCompositeFKEnforcesOrgMatch(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	agentID, _ := enrolledAgent(t, srv.URL, adminClient)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Stand up a second org so the (organization_id) -> organizations
	// FK is satisfied — the mismatch we want to test is between the
	// snapshot's organization_id and the AGENT's organization_id,
	// not between the snapshot and an unknown org.
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO organizations (id, name) VALUES ('other-org', 'Other Org')`)
		return err
	}); err != nil {
		t.Fatalf("seed other-org: %v", err)
	}

	// Mismatched insert: organization_id = 'other-org', agent_id =
	// <agent enrolled in 'anchorix'>. The composite FK on
	// agents(organization_id, id) must reject this.
	err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO agent_inventory_snapshots
				(organization_id, agent_id, hostname, received_at, updated_at)
			 VALUES ('other-org', $1, 'cross-org-attempt', now(), now())`,
			agentID)
		return err
	})
	if err == nil {
		t.Fatal("composite FK did not reject mismatched (org, agent); want 23503 foreign_key_violation")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("err type = %T (%v); want *pgconn.PgError", err, err)
	}
	if pgErr.Code != "23503" {
		t.Errorf("SQLSTATE = %q, want 23503 (foreign_key_violation)", pgErr.Code)
	}

	// No row was created.
	var count int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT COUNT(*) FROM agent_inventory_snapshots WHERE agent_id = $1`,
			agentID,
		).Scan(&count)
	}); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if count != 0 {
		t.Errorf("row count = %d, want 0 (FK should have blocked the insert)", count)
	}
}

func TestOperatorGetAgentInventoryRequiresSession(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, _ := testServer(t, db)

	resp, err := http.Get(srv.URL + "/api/v1/agents/whatever/inventory")
	if err != nil {
		t.Fatalf("anon: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anon status = %d, want 401", resp.StatusCode)
	}
}
