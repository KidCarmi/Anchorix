//go:build integration

package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/governance"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// --- helpers --------------------------------------------------------

type stringerURL struct{ s string }

func (u stringerURL) URL() string { return u.s }

func ownershipServer(t *testing.T, db *postgres.DB) (string, *http.Client) {
	t.Helper()
	srv, svc := testServerWithOptions(t, db, testServerOpts{
		IdentityEnabled:  true,
		OwnershipEnabled: true,
	})
	client := signInAdmin(t, stringerURL{srv.URL}, svc)
	return srv.URL, client
}

type ownershipRowDTO struct {
	CertificateID   string  `json:"certificate_id"`
	Decision        string  `json:"decision"`
	ServiceID       *string `json:"service_id"`
	WinningRuleID   *string `json:"winning_rule_id"`
	Confidence      string  `json:"confidence"`
	ExplanationID   string  `json:"explanation_id"`
	FirstAssignedAt string  `json:"first_assigned_at"`
	LastEvaluatedAt string  `json:"last_evaluated_at"`
	LastChangedAt   string  `json:"last_changed_at"`
}

type ownershipListDTO struct {
	Items      []ownershipRowDTO `json:"items"`
	NextCursor *string           `json:"next_cursor"`
}

type recomputeTriggerDTO struct {
	RunID                 string `json:"run_id"`
	FirstRun              bool   `json:"first_run"`
	EvaluatedCertificates int    `json:"evaluated_certificates"`
	ChangedCertificates   int    `json:"changed_certificates"`
	UnchangedCertificates int    `json:"unchanged_certificates"`
	BecameOwned           int    `json:"became_owned"`
	CreatedUnownedRows    int    `json:"created_unowned_rows"`
	EngineVersion         int    `json:"engine_version"`
	DurationMs            int64  `json:"duration_ms"`
}

func httpGetStatus(t *testing.T, client *http.Client, url string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func httpGetJSON(t *testing.T, client *http.Client, url string, dst any) {
	t.Helper()
	status, body := httpGetStatus(t, client, url)
	if status != http.StatusOK {
		t.Fatalf("GET %s: status=%d body=%s", url, status, body)
	}
	if err := json.Unmarshal(body, dst); err != nil {
		t.Fatalf("decode %s: %v; body=%s", url, err, body)
	}
}

func httpPostJSON(t *testing.T, client *http.Client, url string, dst any) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if dst != nil && resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(body, dst); err != nil {
			t.Fatalf("decode %s: %v; body=%s", url, err, body)
		}
	}
	return resp.StatusCode, body
}

// --- tests ----------------------------------------------------------

func TestOwnershipRecomputeHappyPath(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)

	// Seed three certs with no rules → first-run, all unowned.
	for _, id := range []string{"cert-h-1", "cert-h-2", "cert-h-3"} {
		seedCertMeta(t, db, ctx, "anchorix", id, "CN="+id, "CN=ca", nil)
	}

	var out recomputeTriggerDTO
	status, body := httpPostJSON(t, client, srvURL+"/api/v1/ownership/recompute", &out)
	if status != http.StatusOK {
		t.Fatalf("recompute status=%d body=%s", status, body)
	}
	if !out.FirstRun || out.EvaluatedCertificates != 3 || out.CreatedUnownedRows != 3 {
		t.Fatalf("recompute body=%+v; want firstRun=true, evaluated=3, createdUnowned=3", out)
	}
	if out.DurationMs <= 0 {
		t.Fatalf("duration_ms = %d; want > 0", out.DurationMs)
	}
	if out.RunID == "" {
		t.Fatalf("run_id missing")
	}

	// Second run: not first run.
	var out2 recomputeTriggerDTO
	httpPostJSON(t, client, srvURL+"/api/v1/ownership/recompute", &out2)
	if out2.FirstRun || out2.UnchangedCertificates != 3 {
		t.Fatalf("second run body=%+v; want firstRun=false, unchanged=3", out2)
	}
}

func TestOwnershipRecomputeNoWaitConflict(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)
	seedCertMeta(t, db, ctx, "anchorix", "cert-nw-1", "CN=x", "CN=ca", nil)

	// Hold the per-org advisory lock from a background goroutine via
	// the xact-scope helper; release on signal. While held, a nowait
	// recompute POST must surface as 409 ownership_recompute_in_progress.
	released := make(chan struct{})
	acquired := make(chan struct{})
	go func() {
		_ = db.WithTxLockedOwnership(ctx, "anchorix", func(context.Context) error {
			close(acquired)
			<-released
			return nil
		})
	}()
	<-acquired

	req, _ := http.NewRequest(http.MethodPost, srvURL+"/api/v1/ownership/recompute?nowait=true", nil)
	resp, err := client.Do(req)
	if err != nil {
		close(released)
		t.Fatalf("nowait POST: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		close(released)
		t.Fatalf("nowait status=%d body=%s; want 409", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "ownership_recompute_in_progress") {
		close(released)
		t.Fatalf("nowait body missing error code: %s", body)
	}
	close(released)
}

func TestOwnershipRecomputeBlockingSerializesContention(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)
	for i := 0; i < 5; i++ {
		seedCertMeta(t, db, ctx, "anchorix", "cert-cont-"+string(rune('a'+i)), "CN=x", "CN=ca", nil)
	}

	// Two concurrent (blocking) POSTs — both must succeed without
	// duplicate-key errors. The advisory lock serializes them.
	var wg sync.WaitGroup
	results := make([]int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodPost, srvURL+"/api/v1/ownership/recompute", nil)
			resp, err := client.Do(req)
			if err != nil {
				results[idx] = -1
				return
			}
			resp.Body.Close()
			results[idx] = resp.StatusCode
		}(i)
	}
	wg.Wait()
	for i, code := range results {
		if code != http.StatusOK {
			t.Fatalf("concurrent POST %d status=%d; want 200 (lock should serialize)", i, code)
		}
	}
}

func TestOwnershipUnownedListPagination(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		seedCertMeta(t, db, ctx, "anchorix", "cert-pg-"+n, "CN=x", "CN=ca", nil)
	}
	httpPostJSON(t, client, srvURL+"/api/v1/ownership/recompute", &recomputeTriggerDTO{})

	// First page: limit=2.
	var page1 ownershipListDTO
	httpGetJSON(t, client, srvURL+"/api/v1/ownership/unowned?limit=2", &page1)
	if len(page1.Items) != 2 {
		t.Fatalf("page1 items = %d; want 2", len(page1.Items))
	}
	if page1.NextCursor == nil {
		t.Fatalf("page1 next_cursor is nil; want a cursor")
	}
	// Cursor is base64 — decode and verify it's the second cert id.
	got, _ := base64.RawURLEncoding.DecodeString(*page1.NextCursor)
	if string(got) != page1.Items[1].CertificateID {
		t.Fatalf("cursor=%q want %q", got, page1.Items[1].CertificateID)
	}

	// Second page: continue with cursor.
	var page2 ownershipListDTO
	httpGetJSON(t, client, srvURL+"/api/v1/ownership/unowned?limit=2&cursor="+*page1.NextCursor, &page2)
	if len(page2.Items) != 2 {
		t.Fatalf("page2 items = %d; want 2", len(page2.Items))
	}
	// Final page should have the 5th cert and no next_cursor.
	var page3 ownershipListDTO
	httpGetJSON(t, client, srvURL+"/api/v1/ownership/unowned?limit=2&cursor="+*page2.NextCursor, &page3)
	if len(page3.Items) != 1 || page3.NextCursor != nil {
		t.Fatalf("page3 items=%d next=%v; want 1 item and no cursor", len(page3.Items), page3.NextCursor)
	}
}

func TestOwnershipUnownedEmptyAndLimitValidation(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srvURL, client := ownershipServer(t, db)

	var empty ownershipListDTO
	httpGetJSON(t, client, srvURL+"/api/v1/ownership/unowned", &empty)
	if len(empty.Items) != 0 || empty.NextCursor != nil {
		t.Fatalf("empty list = %+v; want []", empty)
	}
	// limit=0 → 400.
	if status, _ := httpGetStatus(t, client, srvURL+"/api/v1/ownership/unowned?limit=0"); status != http.StatusBadRequest {
		t.Fatalf("limit=0 status=%d; want 400", status)
	}
	// limit over cap → 400.
	if status, _ := httpGetStatus(t, client, srvURL+"/api/v1/ownership/unowned?limit=500"); status != http.StatusBadRequest {
		t.Fatalf("limit=500 status=%d; want 400", status)
	}
	// Invalid cursor → 400.
	if status, _ := httpGetStatus(t, client, srvURL+"/api/v1/ownership/unowned?cursor=!!not-base64!!"); status != http.StatusBadRequest {
		t.Fatalf("bad cursor status=%d; want 400", status)
	}
}

func TestOwnershipAmbiguousList(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)
	seedService(t, db, ctx, "svc-amb")
	seedCertMeta(t, db, ctx, "anchorix", "cert-amb-1", "CN=x", "CN=ca", []string{"a.example"})
	// Two equal-priority same-created_at rules → ambiguous.
	repo := postgres.NewOwnershipRepository(db)
	now := time.Now().UTC()
	for _, id := range []string{"rule-amb-b", "rule-amb-a"} {
		if err := repo.CreateOwnershipRule(ctx, &governance.OwnershipRule{
			ID: id, OrganizationID: "anchorix", Name: id, ServiceID: "svc-amb",
			PrecedenceTier: governance.PrecedenceSANPattern, Priority: 100,
			MatchKind: governance.MatchSANGlob, MatchValue: "*.example",
			Enabled: true, CreatedAt: now, UpdatedAt: now, CreatedBy: "tester",
		}); err != nil {
			t.Fatalf("seed rule: %v", err)
		}
	}
	httpPostJSON(t, client, srvURL+"/api/v1/ownership/recompute", &recomputeTriggerDTO{})

	var out ownershipListDTO
	httpGetJSON(t, client, srvURL+"/api/v1/ownership/ambiguous", &out)
	if len(out.Items) != 1 || out.Items[0].Decision != "ambiguous" {
		t.Fatalf("ambiguous list = %+v; want one ambiguous row", out)
	}
}

func TestOwnershipStaleWithOlderThan(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srv, svc := testServerWithOptions(t, db, testServerOpts{
		IdentityEnabled:     true,
		OwnershipEnabled:    true,
		OwnershipStaleAfter: time.Hour,
	})
	client := signInAdmin(t, stringerURL{srv.URL}, svc)
	seedCertMeta(t, db, ctx, "anchorix", "cert-st-1", "CN=x", "CN=ca", nil)
	httpPostJSON(t, client, srv.URL+"/api/v1/ownership/recompute", &recomputeTriggerDTO{})

	// Default threshold (1h) → fresh row, not stale.
	var fresh ownershipListDTO
	httpGetJSON(t, client, srv.URL+"/api/v1/ownership/stale", &fresh)
	if len(fresh.Items) != 0 {
		t.Fatalf("fresh stale list = %d items; want 0", len(fresh.Items))
	}
	// older_than=0s should be rejected.
	if status, _ := httpGetStatus(t, client, srv.URL+"/api/v1/ownership/stale?older_than=0s"); status != http.StatusBadRequest {
		t.Fatalf("older_than=0s status=%d; want 400", status)
	}
	// older_than=-1ns (negative) → row qualifies as stale.
	var negStale ownershipListDTO
	httpGetJSON(t, client, srv.URL+"/api/v1/ownership/stale?older_than=1ns", &negStale)
	// With 1ns threshold, any row evaluated more than 1ns ago is stale.
	if len(negStale.Items) != 1 {
		t.Fatalf("stale with 1ns threshold = %d; want 1", len(negStale.Items))
	}
}

func TestCertificateOwnershipDetailAndExplanation(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)
	seedCertMeta(t, db, ctx, "anchorix", "cert-det-1", "CN=x", "CN=ca", nil)
	httpPostJSON(t, client, srvURL+"/api/v1/ownership/recompute", &recomputeTriggerDTO{})

	var detail struct {
		Ownership *ownershipRowDTO `json:"ownership"`
	}
	httpGetJSON(t, client, srvURL+"/api/v1/certificates/cert-det-1/ownership", &detail)
	if detail.Ownership == nil || detail.Ownership.Decision != "unowned" {
		t.Fatalf("ownership detail = %+v; want unowned", detail.Ownership)
	}

	// Explanation: current only.
	var exp struct {
		Current *struct {
			ID string `json:"id"`
		} `json:"current"`
		History []struct{} `json:"history"`
	}
	httpGetJSON(t, client, srvURL+"/api/v1/certificates/cert-det-1/ownership/explanation", &exp)
	if exp.Current == nil {
		t.Fatalf("explanation current missing")
	}
	if len(exp.History) != 0 {
		t.Fatalf("explanation history without include_history = %d; want 0", len(exp.History))
	}

	// Explanation with include_history.
	var expHist struct {
		Current any `json:"current"`
		History []struct {
			ID string `json:"id"`
		} `json:"history"`
	}
	httpGetJSON(t, client, srvURL+"/api/v1/certificates/cert-det-1/ownership/explanation?include_history=true&limit=10", &expHist)
	// Only one explanation (single recompute) → history is empty.
	if len(expHist.History) != 0 {
		t.Fatalf("history = %d; want 0 (only one recompute pass)", len(expHist.History))
	}

	// Cross-org id → 404.
	if status, _ := httpGetStatus(t, client, srvURL+"/api/v1/certificates/cert-foreign/ownership"); status != http.StatusNotFound {
		t.Fatalf("foreign cert status=%d; want 404", status)
	}
	if status, _ := httpGetStatus(t, client, srvURL+"/api/v1/certificates/cert-foreign/ownership/explanation"); status != http.StatusNotFound {
		t.Fatalf("foreign cert explanation status=%d; want 404", status)
	}
}

func TestCertificateOwnershipOverrideRead(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)
	seedService(t, db, ctx, "svc-ovr-h")
	seedCertMeta(t, db, ctx, "anchorix", "cert-ovr-h", "CN=x", "CN=ca", nil)

	// No override yet.
	var noOv struct {
		Active any `json:"active"`
	}
	httpGetJSON(t, client, srvURL+"/api/v1/certificates/cert-ovr-h/ownership/override", &noOv)
	if noOv.Active != nil {
		t.Fatalf("active = %v; want null", noOv.Active)
	}

	// Seed an override directly via repo (B3A is read-only).
	repo := postgres.NewOwnershipRepository(db)
	if err := repo.CreateOwnershipOverride(ctx, &governance.CertificateOwnershipOverride{
		ID: "ovr-h-1", OrganizationID: "anchorix", CertificateID: "cert-ovr-h",
		ServiceID: "svc-ovr-h", Reason: "pin", SetBy: "op", SetAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed override: %v", err)
	}
	var hasOv struct {
		Active struct {
			ID        string `json:"id"`
			ServiceID string `json:"service_id"`
		} `json:"active"`
	}
	httpGetJSON(t, client, srvURL+"/api/v1/certificates/cert-ovr-h/ownership/override", &hasOv)
	if hasOv.Active.ID != "ovr-h-1" || hasOv.Active.ServiceID != "svc-ovr-h" {
		t.Fatalf("active override = %+v; want ovr-h-1/svc-ovr-h", hasOv.Active)
	}
}

func TestOwnershipRulesListAndGet(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)
	seedService(t, db, ctx, "svc-rule")
	seedOwnershipRule(t, db, ctx, "rule-a", "svc-rule", governance.PrecedenceFallback, governance.MatchFallback, "", 1)
	seedOwnershipRule(t, db, ctx, "rule-b", "svc-rule", governance.PrecedenceSANPattern, governance.MatchSANGlob, "*.x", 100)

	var list struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	httpGetJSON(t, client, srvURL+"/api/v1/ownership-rules", &list)
	if len(list.Items) != 2 {
		t.Fatalf("rule list = %d; want 2", len(list.Items))
	}

	// Single-rule get.
	var one struct {
		ID        string `json:"id"`
		ServiceID string `json:"service_id"`
		MatchKind string `json:"match_kind"`
	}
	httpGetJSON(t, client, srvURL+"/api/v1/ownership-rules/rule-a", &one)
	if one.ID != "rule-a" || one.MatchKind != "fallback" {
		t.Fatalf("rule detail = %+v", one)
	}

	// Cross-org id → 404.
	if status, _ := httpGetStatus(t, client, srvURL+"/api/v1/ownership-rules/rule-foreign"); status != http.StatusNotFound {
		t.Fatalf("foreign rule status=%d; want 404", status)
	}
}

func TestGovernanceRecomputeRunsList(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)
	seedCertMeta(t, db, ctx, "anchorix", "cert-rr-1", "CN=x", "CN=ca", nil)
	httpPostJSON(t, client, srvURL+"/api/v1/ownership/recompute", &recomputeTriggerDTO{})
	httpPostJSON(t, client, srvURL+"/api/v1/ownership/recompute", &recomputeTriggerDTO{})

	var runs struct {
		Items []struct {
			Kind           string `json:"kind"`
			EvaluatedCount int    `json:"evaluated_count"`
		} `json:"items"`
	}
	httpGetJSON(t, client, srvURL+"/api/v1/governance/recompute-runs?kind=ownership", &runs)
	if len(runs.Items) != 2 {
		t.Fatalf("runs = %d; want 2", len(runs.Items))
	}
	for _, r := range runs.Items {
		if r.Kind != "ownership" {
			t.Fatalf("run kind = %s; want ownership", r.Kind)
		}
	}
	// Invalid kind → 400.
	if status, _ := httpGetStatus(t, client, srvURL+"/api/v1/governance/recompute-runs?kind=bogus"); status != http.StatusBadRequest {
		t.Fatalf("bad kind status=%d; want 400", status)
	}
}

func TestOwnershipRoutesAuthRequired(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, _ := testServerWithOptions(t, db, testServerOpts{
		IdentityEnabled: true, OwnershipEnabled: true,
	})
	client := &http.Client{Timeout: 5 * time.Second}
	// Anonymous: every route → 401.
	for _, path := range []string{
		"/api/v1/ownership/unowned",
		"/api/v1/ownership/ambiguous",
		"/api/v1/ownership/stale",
		"/api/v1/certificates/any/ownership",
		"/api/v1/certificates/any/ownership/explanation",
		"/api/v1/certificates/any/ownership/override",
		"/api/v1/ownership-rules",
		"/api/v1/ownership-rules/any",
		"/api/v1/governance/recompute-runs",
	} {
		if status, _ := httpGetStatus(t, client, srv.URL+path); status != http.StatusUnauthorized {
			t.Fatalf("anonymous GET %s status=%d; want 401", path, status)
		}
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/ownership/recompute", nil)
	resp, _ := client.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous POST recompute status=%d; want 401", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestOwnershipRoutesAbsentWhenGovernanceDisabled(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	// OwnershipEnabled=false → no ownership routes registered.
	srv, svc := testServerWithOptions(t, db, testServerOpts{
		IdentityEnabled: true, OwnershipEnabled: false,
	})
	client := signInAdmin(t, stringerURL{srv.URL}, svc)
	// Authenticated, but the routes are not in the mux → 404.
	for _, path := range []string{
		"/api/v1/ownership/unowned",
		"/api/v1/ownership-rules",
		"/api/v1/governance/recompute-runs",
	} {
		if status, _ := httpGetStatus(t, client, srv.URL+path); status != http.StatusNotFound {
			t.Fatalf("gate-off GET %s status=%d; want 404", path, status)
		}
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/ownership/recompute", nil)
	resp, _ := client.Do(req)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("gate-off POST recompute status=%d; want 404", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestOwnershipCertificateCrossOrgIsolation(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	seedOrganization(t, db, "other", "Other")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvURL, client := ownershipServer(t, db)
	// Seed a cert in the FOREIGN org with derived ownership.
	seedCertMeta(t, db, ctx, "other", "cert-foreign-1", "CN=x", "CN=ca", nil)
	// Seed ownership directly in 'other' so it has a row.
	repo := postgres.NewOwnershipRepository(db)
	now := time.Now().UTC()
	exp := &governance.OwnershipMatchExplanation{
		ID: "exp-foreign", OrganizationID: "other", CertificateID: "cert-foreign-1",
		DecidedAt: now, DecidedDecision: governance.DecisionUnowned,
		LosingRules: json.RawMessage(`[]`), SignalsSeen: json.RawMessage(`{}`), EngineVersion: 1,
	}
	if err := repo.CreateOwnershipExplanation(ctx, exp); err != nil {
		t.Fatalf("seed foreign exp: %v", err)
	}
	if err := repo.UpsertCertificateOwnership(ctx, &governance.CertificateOwnership{
		OrganizationID: "other", CertificateID: "cert-foreign-1",
		Decision: governance.DecisionUnowned, ExplanationID: exp.ID, Confidence: governance.ConfidenceLow,
		FirstAssignedAt: now, LastEvaluatedAt: now, LastChangedAt: now,
	}); err != nil {
		t.Fatalf("seed foreign ownership: %v", err)
	}

	// Anchorix session must NOT see the other-org cert.
	if status, _ := httpGetStatus(t, client, srvURL+"/api/v1/certificates/cert-foreign-1/ownership"); status != http.StatusNotFound {
		t.Fatalf("cross-org cert ownership status=%d; want 404", status)
	}
}
