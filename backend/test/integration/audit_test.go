//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/audit"
	"github.com/kidcarmi/anchorix/backend/internal/clock"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// TestAuditEventsRecordedOnAuthFlow exercises the audit promise from
// CLAUDE.md §9: every state-changing operation produces an audit_events
// row, and the X-Request-Id header propagates to the row.
func TestAuditEventsRecordedOnAuthFlow(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)

	_ = seedAdmin(t, svc) // emits auth.admin_created

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}

	// login_succeeded (with a request id we can grep for).
	loginBody := strings.NewReader(`{"email":"` + testEmail + `","password":"` + testPassword + `"}`)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/auth/login", loginBody)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-login-1")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()

	// login_failed
	failBody := strings.NewReader(`{"email":"` + testEmail + `","password":"wrong"}`)
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/api/v1/auth/login", failBody)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("login (fail): %v", err)
	}
	resp.Body.Close()

	// logout
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/api/v1/auth/logout", nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	resp.Body.Close()

	recorder := postgres.NewAuditRecorder(db, clock.System{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	events, err := recorder.List(ctx, audit.ListQuery{OrganizationID: "anchorix"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := map[string]bool{
		"auth.admin_created":   false,
		"auth.login_succeeded": false,
		"auth.login_failed":    false,
		"auth.logout":          false,
	}
	loginRequestID := ""
	for _, e := range events {
		if _, ok := want[e.Action]; ok {
			want[e.Action] = true
		}
		if e.Action == "auth.login_succeeded" {
			loginRequestID = e.RequestID
		}
	}
	for action, seen := range want {
		if !seen {
			t.Errorf("missing audit event %q", action)
		}
	}
	if loginRequestID != "req-login-1" {
		t.Errorf("login_succeeded request_id = %q; want req-login-1 (propagation from header)", loginRequestID)
	}

	// Spot-check the login_failed metadata carries the security tag —
	// no plaintext password, no full token.
	for _, e := range events {
		if e.Action != "auth.login_failed" {
			continue
		}
		var meta map[string]any
		if err := json.Unmarshal(e.Metadata, &meta); err != nil {
			t.Fatalf("login_failed metadata invalid JSON: %v", err)
		}
		if meta["severity"] != "security" {
			t.Errorf("login_failed metadata severity = %v; want security", meta["severity"])
		}
		if strings.Contains(string(e.Metadata), testPassword) {
			t.Error("login_failed metadata contains plaintext password")
		}
	}
}

// TestAuditEventsAreAppendOnly asserts the DB-level immutability
// invariant from CLAUDE.md §9 / §16: UPDATE and DELETE on audit_events
// are rejected by trigger.
func TestAuditEventsAreAppendOnly(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	_, svc := testServer(t, db)

	// Produce one event we can target.
	_ = seedAdmin(t, svc)

	recorder := postgres.NewAuditRecorder(db, clock.System{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	events, err := recorder.List(ctx, audit.ListQuery{OrganizationID: "anchorix"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected at least one audit event from seedAdmin")
	}
	id := events[0].ID

	if err := tryStatement(db, `UPDATE audit_events SET actor='hax' WHERE id=$1`, id); err == nil {
		t.Fatal("UPDATE on audit_events succeeded; want failure")
	}
	if err := tryStatement(db, `DELETE FROM audit_events WHERE id=$1`, id); err == nil {
		t.Fatal("DELETE on audit_events succeeded; want failure")
	}
}

// tryStatement runs the SQL in a transaction and returns the error
// from the Exec. The transaction is rolled back regardless so test
// state stays clean.
func tryStatement(db *postgres.DB, sql string, args ...any) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var execErr error
	// WithTxRaw exposes pgx.Tx because this test exercises raw SQL
	// (UPDATE/DELETE on audit_events) to confirm the production
	// trigger rejects them. Domain code MUST NOT use WithTxRaw.
	_ = db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		_, execErr = tx.Exec(ctx, sql, args...)
		// Always return a sentinel error so WithTxRaw rolls back;
		// the real error we care about is execErr, captured above.
		return errors.New("rollback")
	})
	return execErr
}
