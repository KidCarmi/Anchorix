//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/agentinventory"
	"github.com/kidcarmi/anchorix/backend/internal/auth"
	"github.com/kidcarmi/anchorix/backend/internal/clock"
	"github.com/kidcarmi/anchorix/backend/internal/enrollment"
	"github.com/kidcarmi/anchorix/backend/internal/findings"
	"github.com/kidcarmi/anchorix/backend/internal/httpapi"
	"github.com/kidcarmi/anchorix/backend/internal/inventory"
	"github.com/kidcarmi/anchorix/backend/internal/logger"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// safeBuffer is a bytes.Buffer wrapped in a mutex so concurrent writes
// from slog handlers (which the standard library documents as safe for
// concurrent use) cannot tear the captured output mid-line. Tests must
// read via String() only after the flow under test has finished.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestNoPlaintextSecretsInLogs runs the real auth flow (login → /me →
// logout) through the real HTTP server, with the real auth.Service and
// real PostgreSQL repositories, and captures every log line the real
// logger emits. It then asserts that none of the sensitive values
// involved in the flow appear anywhere in the captured stream.
//
// The redaction allow-list is owned by internal/logger and exercised by
// its unit tests. This integration test is the belt-and-braces guard
// that prevents a regression — a new handler, middleware, panic stack,
// or audit-metadata path adding a secret to a structured log field —
// from shipping unnoticed (CLAUDE.md §6.9, §9).
//
// The test deliberately:
//
//   - sets log level to debug so the broadest set of log lines flows
//     through, mirroring what a verbose production deployment would
//     emit;
//   - attaches a sentinel Bearer token on every request so any future
//     middleware that logs the Authorization header trips the assertion;
//   - reads the bcrypt password hash from the DB before the flow so it
//     can assert the exact hash bytes are absent, not just the bcrypt
//     prefix heuristic;
//   - does not redefine, sanitize, or filter the captured output before
//     asserting — the captured stream IS the assertion target.
func TestNoPlaintextSecretsInLogs(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)

	cfg := testConfig(t)
	// Crank verbosity all the way up. The whole point of this sweep
	// is to make sure a noisy production logger still doesn't leak.
	var captured safeBuffer
	log := logger.NewWithWriter("debug", cfg.Env, &captured)

	usersRepo := postgres.NewAuthRepository(db)
	sessionsRepo := postgres.NewSessionsRepository(db)
	auditRecorder := postgres.NewAuditRecorder(db, clock.System{})

	passwd, err := auth.NewPasswordPolicy(cfg.BcryptCost)
	if err != nil {
		t.Fatalf("password policy: %v", err)
	}
	sessPol, err := auth.NewSessionPolicy(cfg.SessionIdleLifetime, cfg.SessionAbsoluteLifetime)
	if err != nil {
		t.Fatalf("session policy: %v", err)
	}
	signer, err := auth.NewSignedCookie(cfg.SessionKey)
	if err != nil {
		t.Fatalf("signed cookie: %v", err)
	}
	svc, err := auth.NewService(usersRepo, sessionsRepo, auditRecorder, db, passwd, sessPol, clock.System{})
	if err != nil {
		t.Fatalf("auth.NewService: %v", err)
	}

	// EnrollmentService + AgentInventoryService are required by
	// httpapi.NewServer's Dependencies (PR-013 / PR-018). The
	// redaction sweep does not exercise those routes directly, but
	// the server constructor validates every dep at construction
	// time — wire real services so the gate passes.
	deploymentPkgRepo := postgres.NewDeploymentPackageRepository(db)
	agentsRepo := postgres.NewAgentRepository(db)
	enrollSvc, err := enrollment.NewService(
		deploymentPkgRepo, agentsRepo, auditRecorder, db, clock.System{}, rand.Reader,
	)
	if err != nil {
		t.Fatalf("enrollment.NewService: %v", err)
	}

	inventoryRepo := postgres.NewAgentInventorySnapshotRepository(db)
	inventorySvc, err := agentinventory.NewService(inventoryRepo, clock.System{})
	if err != nil {
		t.Fatalf("agentinventory.NewService: %v", err)
	}

	certRepo := postgres.NewCertificateInventoryRepository(db)
	certSvc, err := inventory.NewService(certRepo, db, auditRecorder, clock.System{})
	if err != nil {
		t.Fatalf("inventory.NewService: %v", err)
	}

	findingsRepo := postgres.NewFindingsRepository(db)
	findingsSvc, err := findings.NewService(
		findingsRepo, certRepo, db, auditRecorder, clock.System{}, findings.DefaultRules(),
	)
	if err != nil {
		t.Fatalf("findings.NewService: %v", err)
	}

	apiServer, err := httpapi.NewServer(cfg, log, httpapi.Dependencies{
		AuthService:           svc,
		CookieSigner:          signer,
		EnrollmentService:     enrollSvc,
		AgentInventoryService: inventorySvc,
		InventoryService:      certSvc,
		FindingsService:       findingsSvc,
	})
	if err != nil {
		t.Fatalf("httpapi.NewServer: %v", err)
	}
	apiServer.Readiness().Register("postgres", db.Ping)

	httpSrv := httptest.NewServer(apiServer.Handler())
	t.Cleanup(httpSrv.Close)

	_ = seedAdmin(t, svc)

	// Read the stored bcrypt hash so we can assert the exact bytes
	// never reach the log stream — covering the case where a future
	// debug log of a User struct accidentally serializes its hash.
	storedHash := lookupPasswordHash(t, db, testEmail)

	jar, _ := cookiejar.New(nil)
	httpClient := &http.Client{Jar: jar, Timeout: 5 * time.Second}

	const bearerSentinel = "sentinel-bearer-must-not-leak-into-logs"

	// 1. Login. The Authorization header is set on every request so
	//    any middleware that ever logs request headers will trip the
	//    bearer-sentinel assertion below.
	loginBody := strings.NewReader(`{"email":"` + testEmail + `","password":"` + testPassword + `"}`)
	loginReq, _ := http.NewRequest(http.MethodPost, httpSrv.URL+"/api/v1/auth/login", loginBody)
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.Header.Set("Authorization", "Bearer "+bearerSentinel)
	loginResp, err := httpClient.Do(loginReq)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d; want 200", loginResp.StatusCode)
	}

	cookieValue, rawSessionID := extractSessionCookie(t, jar, httpSrv.URL, cfg.SessionCookieName)

	// 2. GET /me.
	meReq, _ := http.NewRequest(http.MethodGet, httpSrv.URL+"/api/v1/auth/me", nil)
	meReq.Header.Set("Authorization", "Bearer "+bearerSentinel)
	meResp, err := httpClient.Do(meReq)
	if err != nil {
		t.Fatalf("/me: %v", err)
	}
	meResp.Body.Close()
	if meResp.StatusCode != http.StatusOK {
		t.Fatalf("/me status = %d; want 200", meResp.StatusCode)
	}

	// 3. Logout.
	logoutReq, _ := http.NewRequest(http.MethodPost, httpSrv.URL+"/api/v1/auth/logout", nil)
	logoutReq.Header.Set("Authorization", "Bearer "+bearerSentinel)
	logoutResp, err := httpClient.Do(logoutReq)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	logoutResp.Body.Close()
	if logoutResp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout status = %d; want 204", logoutResp.StatusCode)
	}

	logs := captured.String()
	if logs == "" {
		// A vacuously passing test would be worse than a missing one.
		// loggingMiddleware emits one info line per request, so an
		// empty buffer means the logger wiring is wrong.
		t.Fatal("captured log buffer is empty — logger wiring is incorrect; assertions would pass vacuously")
	}
	t.Logf("captured %d bytes of log output across login → /me → logout", len(logs))

	// sessionKeyMaterial is the raw test session key string. testConfig
	// constructs it as 32 repeated 'k' bytes — a value distinctive
	// enough that a grep for it across the log buffer is meaningful.
	sessionKeyMaterial := string(cfg.SessionKey)

	forbidden := []struct {
		name, value string
	}{
		{"plaintext password", testPassword},
		{"signed session cookie value (full)", cookieValue},
		{"raw session id (pre-MAC half of cookie)", rawSessionID},
		{"test session key material (32 'k's)", sessionKeyMaterial},
		{"bcrypt hash bytes from DB", storedHash},
		{"bcrypt cost prefix $2a$", "$2a$"},
		{"bcrypt cost prefix $2b$", "$2b$"},
		{"bcrypt cost prefix $2y$", "$2y$"},
		{"Bearer token sentinel", bearerSentinel},
	}

	for _, f := range forbidden {
		if f.value == "" {
			continue
		}
		if strings.Contains(logs, f.value) {
			t.Errorf("captured logs contain forbidden value (%s).\n"+
				"This means a log line emitted during the auth flow leaked a secret.\n"+
				"Captured log tail (last 80 lines):\n%s",
				f.name, tailLines(logs, 80))
		}
	}
}

func lookupPasswordHash(t *testing.T, db *postgres.DB, email string) string {
	t.Helper()
	// Scan into []byte because password_hash is BYTEA in 0001_init.sql
	// and the auth repository scans it the same way. Bcrypt hashes are
	// pure ASCII, so the []byte → string conversion is lossless.
	var hash []byte
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT password_hash FROM users WHERE email = $1`, email).Scan(&hash)
	}); err != nil {
		t.Fatalf("lookup password hash: %v", err)
	}
	if len(hash) == 0 {
		t.Fatal("lookupPasswordHash: empty hash; seedAdmin did not insert a row")
	}
	return string(hash)
}

// extractSessionCookie returns the full cookie value and the raw
// session-id portion (everything before the final '.' of the signed
// cookie). Both are asserted absent from the log stream so a regression
// that prints either piece is caught.
func extractSessionCookie(t *testing.T, jar http.CookieJar, base, name string) (full, rawID string) {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse base URL: %v", err)
	}
	for _, c := range jar.Cookies(u) {
		if c.Name == name {
			full = c.Value
			if dot := strings.LastIndex(full, "."); dot > 0 {
				rawID = full[:dot]
			}
			return full, rawID
		}
	}
	t.Fatalf("session cookie %q not set after login", name)
	return "", ""
}

// tailLines returns the last n newline-separated lines of s, or s
// itself if it has fewer than n lines. Used only to keep failure
// messages readable; not part of any production code path.
func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) <= n {
		return s
	}
	return strings.Join(lines[len(lines)-n:], "\n")
}
