//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// --- helpers: deterministic-enough self-signed cert factory ---------

// generatedCert returns a self-signed cert in PEM form. Each call
// uses a fresh key so the fingerprint is unique across tests but
// stable within a test (caller uses the returned pemBytes for both
// the upload and any later assertions).
func generatedCert(t *testing.T, subject string) string {
	t.Helper()
	key, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, _ := cryptorand.Int(cryptorand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: subject},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{subject},
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// generatedEcdsaCert is the ECDSA variant — used to verify the
// parser handles non-RSA keys cleanly.
func generatedEcdsaCert(t *testing.T, subject string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	serial, _ := cryptorand.Int(cryptorand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: subject},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{subject},
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create ecdsa cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// --- helpers: wire DTO mirrors -------------------------------------

type ingestRequestDTO struct {
	CollectedAt   string          `json:"collected_at"`
	StoreCoverage []string        `json:"store_coverage"`
	Certificates  []ingestCertDTO `json:"certificates"`
}

type ingestCertDTO struct {
	StoreLocation  string `json:"store_location"`
	FriendlyName   string `json:"friendly_name,omitempty"`
	CertificatePEM string `json:"certificate_pem"`
}

type ingestResponseDTO struct {
	Status           string `json:"status"`
	ReceivedAt       string `json:"received_at"`
	Accepted         int    `json:"accepted"`
	ReconciledAbsent int    `json:"reconciled_absent"`
}

// submitCertBatch performs an authenticated POST /agent/certificates
// with the supplied body. Asserts wantStatus and returns the
// parsed response (or zero value on non-200).
func submitCertBatch(t *testing.T, srv, credential string, body ingestRequestDTO, wantStatus int) ingestResponseDTO {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return submitCertBatchRaw(t, srv, credential, raw, wantStatus)
}

func submitCertBatchRaw(t *testing.T, srv, credential string, raw []byte, wantStatus int) ingestResponseDTO {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv+"/api/v1/agent/certificates", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d; body=%s", resp.StatusCode, wantStatus, b)
	}
	if wantStatus != http.StatusOK {
		return ingestResponseDTO{}
	}
	var out ingestResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

// --- happy path ---------------------------------------------------

func TestAgentCertificatesHappyPath(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	agentID, credential := enrolledAgent(t, srv.URL, adminClient)

	cert1 := generatedCert(t, "leaf-1.example")
	cert2 := generatedEcdsaCert(t, "leaf-2.example")

	resp := submitCertBatch(t, srv.URL, credential, ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`, `LocalMachine\WebHosting`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, FriendlyName: "Leaf 1", CertificatePEM: cert1},
			{StoreLocation: `LocalMachine\WebHosting`, CertificatePEM: cert2},
		},
	}, http.StatusOK)

	if resp.Status != "ok" {
		t.Errorf("status = %q, want ok", resp.Status)
	}
	if resp.Accepted != 2 {
		t.Errorf("accepted = %d, want 2", resp.Accepted)
	}
	if resp.ReconciledAbsent != 0 {
		t.Errorf("reconciled_absent = %d, want 0 (first batch)", resp.ReconciledAbsent)
	}

	// Verify DB shape.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var (
		certRows, obsRows int
	)
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM certificates`).Scan(&certRows); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT COUNT(*) FROM certificate_observations WHERE agent_id = $1`, agentID).Scan(&obsRows)
	}); err != nil {
		t.Fatalf("read: %v", err)
	}
	if certRows != 2 {
		t.Errorf("cert rows = %d, want 2", certRows)
	}
	if obsRows != 2 {
		t.Errorf("observation rows = %d, want 2", obsRows)
	}
}

// --- multi-store reconciliation ------------------------------------

func TestAgentCertificatesMultiStoreReconciliation(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	agentID, credential := enrolledAgent(t, srv.URL, adminClient)

	a := generatedCert(t, "cert-a.example")
	b := generatedCert(t, "cert-b.example")

	// Batch 1: certA in My, certB in WebHosting.
	submitCertBatch(t, srv.URL, credential, ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`, `LocalMachine\WebHosting`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, CertificatePEM: a},
			{StoreLocation: `LocalMachine\WebHosting`, CertificatePEM: b},
		},
	}, http.StatusOK)

	// Batch 2: only certA in My; coverage = [My]. WebHosting NOT
	// in coverage → certB observation stays active.
	resp2 := submitCertBatch(t, srv.URL, credential, ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, CertificatePEM: a},
		},
	}, http.StatusOK)
	if resp2.Accepted != 1 {
		t.Errorf("batch 2 accepted = %d, want 1", resp2.Accepted)
	}
	if resp2.ReconciledAbsent != 0 {
		t.Errorf("batch 2 reconciled_absent = %d, want 0 (no certs in My disappeared)", resp2.ReconciledAbsent)
	}

	// Confirm: 2 observations active (certA in My, certB in
	// WebHosting); certB untouched because WebHosting not in coverage.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var activeMy, activeWeb int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx,
			`SELECT COUNT(*) FROM certificate_observations WHERE agent_id = $1 AND store_location = $2 AND removed_at IS NULL`,
			agentID, `LocalMachine\My`).Scan(&activeMy); err != nil {
			return err
		}
		return tx.QueryRow(ctx,
			`SELECT COUNT(*) FROM certificate_observations WHERE agent_id = $1 AND store_location = $2 AND removed_at IS NULL`,
			agentID, `LocalMachine\WebHosting`).Scan(&activeWeb)
	}); err != nil {
		t.Fatalf("read: %v", err)
	}
	if activeMy != 1 || activeWeb != 1 {
		t.Errorf("active counts: My=%d, WebHosting=%d; want 1, 1", activeMy, activeWeb)
	}

	// Batch 3: empty My (only certB in WebHosting now, but coverage = [My]).
	// certA must be marked removed.
	resp3 := submitCertBatch(t, srv.URL, credential, ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates:  []ingestCertDTO{}, // empty batch in this store.
	}, http.StatusBadRequest)
	_ = resp3 // certificates must be non-empty per handler shape check; this rejects
	// before reaching the reconciliation primitive.

	// Re-do batch 3 the right way: include a different cert in My
	// (so the request passes shape validation but reconciliation
	// still marks certA absent).
	c := generatedCert(t, "cert-c.example")
	resp4 := submitCertBatch(t, srv.URL, credential, ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, CertificatePEM: c},
		},
	}, http.StatusOK)
	if resp4.Accepted != 1 {
		t.Errorf("batch 4 accepted = %d, want 1", resp4.Accepted)
	}
	if resp4.ReconciledAbsent != 1 {
		t.Errorf("batch 4 reconciled_absent = %d, want 1 (certA marked removed)", resp4.ReconciledAbsent)
	}
}

// --- reappearance clears removed_at --------------------------------

func TestAgentCertificatesReappearClearsRemovedAt(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	a := generatedCert(t, "cert-a.example")
	other := generatedCert(t, "cert-other.example")

	submitCertBatch(t, srv.URL, credential, ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, CertificatePEM: a},
		},
	}, http.StatusOK)

	// Batch without certA → it gets removed_at.
	resp2 := submitCertBatch(t, srv.URL, credential, ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, CertificatePEM: other},
		},
	}, http.StatusOK)
	if resp2.ReconciledAbsent != 1 {
		t.Errorf("expected 1 reconciled_absent, got %d", resp2.ReconciledAbsent)
	}

	// certA reappears.
	resp3 := submitCertBatch(t, srv.URL, credential, ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, CertificatePEM: a},
			{StoreLocation: `LocalMachine\My`, CertificatePEM: other},
		},
	}, http.StatusOK)
	if resp3.Accepted != 2 {
		t.Errorf("batch 3 accepted = %d, want 2", resp3.Accepted)
	}
}

// --- concurrent batches: advisory lock serializes ------------------

func TestAgentCertificatesConcurrentBatchSafety(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	agentID, credential := enrolledAgent(t, srv.URL, adminClient)

	// Two batches submitted concurrently for the SAME agent. Each
	// reports a distinct cert with the same store_coverage =
	// [LocalMachine\My]. The advisory lock MUST serialize them.
	//
	// A correct serial execution produces ONE of TWO equivalent
	// outcomes (order-dependent, but otherwise identical):
	//
	//   A-then-B:
	//     1. A inserts certA, upserts observation (active).
	//     2. A reconciles store=My, observed=[certA]: no other
	//        observations → no-op.
	//     3. B inserts certB, upserts observation (active).
	//     4. B reconciles store=My, observed=[certB]: sees certA
	//        not in observed → marks certA removed_at = B.collected_at.
	//     Final: certB active, certA removed.
	//
	//   B-then-A: symmetric → certA active, certB removed.
	//
	// Either way the post-condition is identical:
	//
	//   - Total observations: exactly 2 (no rows lost).
	//   - Active observations: exactly 1 (the second batch's cert).
	//   - Removed observations: exactly 1 with removed_at set
	//     (the first batch's cert).
	//
	// A BROKEN interleaving (no advisory lock) can produce:
	//
	//   - 0 active observations (both certs reconciled out by each
	//     other's MarkMissing) — the original H-017 race.
	//   - 2 active observations (neither reconciliation saw the
	//     other's row) — possible if the upserts interleaved
	//     between each transaction's reconcile step.
	//
	// We iterate the concurrent race (each iteration on a fresh
	// agent, so the per-agent advisory lock starts each round at
	// the clean state) to make the test a reliable regression
	// detector. Without the lock the race manifests roughly 30%
	// per attempt under our local test conditions; iterating
	// 10× drops the false-pass probability to ~3% per CI run
	// while running in well under 10 seconds. With the lock,
	// every iteration must pass deterministically.
	const concurrencyIterations = 10
	for iter := 0; iter < concurrencyIterations; iter++ {
		// Fresh agent per iteration so each starts from empty
		// observations and the per-agent advisory lock applies
		// to its own clean state.
		iterAgentID, iterCred := enrolledAgent(t, srv.URL, adminClient)
		certA := generatedCert(t, fmt.Sprintf("concurrent-a-%d", iter))
		certB := generatedCert(t, fmt.Sprintf("concurrent-b-%d", iter))

		var wg sync.WaitGroup
		var aOK, bOK int32
		wg.Add(2)
		go func() {
			defer wg.Done()
			raw, _ := json.Marshal(ingestRequestDTO{
				CollectedAt:   nowRFC3339(),
				StoreCoverage: []string{`LocalMachine\My`},
				Certificates: []ingestCertDTO{
					{StoreLocation: `LocalMachine\My`, CertificatePEM: certA},
				},
			})
			req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/agent/certificates", bytes.NewReader(raw))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+iterCred)
			resp, _ := http.DefaultClient.Do(req)
			if resp != nil && resp.StatusCode == http.StatusOK {
				atomic.AddInt32(&aOK, 1)
			}
			if resp != nil {
				resp.Body.Close()
			}
		}()
		go func() {
			defer wg.Done()
			raw, _ := json.Marshal(ingestRequestDTO{
				CollectedAt:   nowRFC3339(),
				StoreCoverage: []string{`LocalMachine\My`},
				Certificates: []ingestCertDTO{
					{StoreLocation: `LocalMachine\My`, CertificatePEM: certB},
				},
			})
			req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/agent/certificates", bytes.NewReader(raw))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+iterCred)
			resp, _ := http.DefaultClient.Do(req)
			if resp != nil && resp.StatusCode == http.StatusOK {
				atomic.AddInt32(&bOK, 1)
			}
			if resp != nil {
				resp.Body.Close()
			}
		}()
		wg.Wait()

		if aOK == 0 || bOK == 0 {
			t.Fatalf("iter %d: both batches should succeed; aOK=%d bOK=%d", iter, aOK, bOK)
		}

		// Strict serial-equivalence assertions: count totals,
		// count active vs removed, and verify the row identities
		// map cleanly to one of the two valid serial outcomes.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		var totalRows, activeCount, removedCount int
		if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
			if err := tx.QueryRow(ctx,
				`SELECT COUNT(*) FROM certificate_observations
				  WHERE agent_id = $1 AND store_location = $2`,
				iterAgentID, `LocalMachine\My`).Scan(&totalRows); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx,
				`SELECT COUNT(*) FROM certificate_observations
				  WHERE agent_id = $1 AND store_location = $2 AND removed_at IS NULL`,
				iterAgentID, `LocalMachine\My`).Scan(&activeCount); err != nil {
				return err
			}
			return tx.QueryRow(ctx,
				`SELECT COUNT(*) FROM certificate_observations
				  WHERE agent_id = $1 AND store_location = $2 AND removed_at IS NOT NULL`,
				iterAgentID, `LocalMachine\My`).Scan(&removedCount)
		}); err != nil {
			cancel()
			t.Fatalf("iter %d: read: %v", iter, err)
		}
		if totalRows != 2 {
			cancel()
			t.Fatalf("iter %d: total observation rows = %d, want 2 (one per cert; serial execution preserves both rows)", iter, totalRows)
		}
		if activeCount != 1 {
			cancel()
			t.Fatalf("iter %d: active observation count = %d, want exactly 1 (serial execution leaves the SECOND batch's cert active; %d active observations proves a corrupted interleaving)", iter, activeCount, activeCount)
		}
		if removedCount != 1 {
			cancel()
			t.Fatalf("iter %d: removed observation count = %d, want exactly 1 (serial execution marks the FIRST batch's cert as removed; %d removed proves both batches reconciled each other out)", iter, removedCount, removedCount)
		}

		// The active observation must be exactly one of certA or
		// certB (by fingerprint). Map the canonical PEMs through
		// the same SHA-256(cert.Raw) the server uses so the test
		// does not need access to the server's internal
		// fingerprint logic.
		certAFP := fingerprintOf(t, certA)
		certBFP := fingerprintOf(t, certB)
		var activeFP, removedFP string
		if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
			if err := tx.QueryRow(ctx,
				`SELECT c.fingerprint_sha256
				   FROM certificate_observations o
				   JOIN certificates c ON c.id = o.certificate_id
				  WHERE o.agent_id = $1 AND o.store_location = $2 AND o.removed_at IS NULL`,
				iterAgentID, `LocalMachine\My`).Scan(&activeFP); err != nil {
				return err
			}
			return tx.QueryRow(ctx,
				`SELECT c.fingerprint_sha256
				   FROM certificate_observations o
				   JOIN certificates c ON c.id = o.certificate_id
				  WHERE o.agent_id = $1 AND o.store_location = $2 AND o.removed_at IS NOT NULL`,
				iterAgentID, `LocalMachine\My`).Scan(&removedFP)
		}); err != nil {
			cancel()
			t.Fatalf("iter %d: read fingerprints: %v", iter, err)
		}
		cancel()

		// One serial outcome: certA active + certB removed.
		// The other:        certB active + certA removed.
		// Anything else (e.g., same cert appearing twice) is a corruption.
		validAthenB := activeFP == certBFP && removedFP == certAFP
		validBthenA := activeFP == certAFP && removedFP == certBFP
		if !(validAthenB || validBthenA) {
			t.Fatalf("iter %d: post-state inconsistent with any valid serial execution:\n"+
				"  activeFP   = %s\n  removedFP  = %s\n  certA FP   = %s\n  certB FP   = %s",
				iter, activeFP, removedFP, certAFP, certBFP)
		}
	}

	// Static analysis: assertion that the unused-when-loop-fires
	// `agentID` and `credential` from the test setup remain
	// reachable (the test scaffolding allocates them up front).
	_ = agentID
	_ = credential
}

// fingerprintOf re-derives the SHA-256(cert.Raw) fingerprint the
// server uses, for tests that need to assert on the canonical
// stored fingerprint without depending on the internal package.
func fingerprintOf(t *testing.T, certPEM string) string {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatalf("fingerprintOf: pem.Decode returned nil")
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("fingerprintOf: parse: %v", err)
	}
	sum := sha256.Sum256(parsed.Raw)
	return hex.EncodeToString(sum[:])
}

// --- private key rejection -----------------------------------------

func TestAgentCertificatesRejectsPrivateKey(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	agentID, credential := enrolledAgent(t, srv.URL, adminClient)

	good := generatedCert(t, "good-cert.example")
	// One PEM contains a private-key marker — the entire batch
	// must be rejected with 400 private_key_rejected.
	badPEM := "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n"

	raw, _ := json.Marshal(ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, CertificatePEM: good},
			{StoreLocation: `LocalMachine\My`, CertificatePEM: badPEM},
		},
	})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/agent/certificates", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+credential)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 400; body=%s", resp.StatusCode, body)
	}
	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode envelope: %v; body=%s", err, body)
	}
	if envelope.Error.Code != "private_key_rejected" {
		t.Errorf("error code = %q, want private_key_rejected; body=%s", envelope.Error.Code, body)
	}

	// Nothing should have been written to the certificates or
	// observations tables.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var certRows, obsRows int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM certificates`).Scan(&certRows); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT COUNT(*) FROM certificate_observations`).Scan(&obsRows)
	}); err != nil {
		t.Fatalf("count: %v", err)
	}
	if certRows != 0 || obsRows != 0 {
		t.Errorf("whole-batch reject leaked data: certRows=%d obsRows=%d, want 0/0", certRows, obsRows)
	}

	// An audit_events row MUST have been written.
	var auditCount int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT COUNT(*) FROM audit_events
			  WHERE action = 'agent.certificate_batch_rejected'
			    AND target_id = $1
			    AND metadata::text LIKE '%private_key_material%'`,
			agentID).Scan(&auditCount)
	}); err != nil {
		t.Fatalf("audit count: %v", err)
	}
	if auditCount != 1 {
		t.Errorf("audit rows = %d, want 1 (security audit for private-key reject)", auditCount)
	}
}

// --- invalid PEM ---------------------------------------------------

func TestAgentCertificatesRejectsUnparseablePEM(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	good := generatedCert(t, "good-1.example")
	// "Looks like" a certificate but the bytes are garbage.
	bad := "-----BEGIN CERTIFICATE-----\nbm90LWEtcmVhbC1jZXJ0aWZpY2F0ZQ==\n-----END CERTIFICATE-----\n"

	raw, _ := json.Marshal(ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, CertificatePEM: good},
			{StoreLocation: `LocalMachine\My`, CertificatePEM: bad},
		},
	})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/agent/certificates", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+credential)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 400; body=%s", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "certificate_unparseable") {
		t.Errorf("envelope did not contain certificate_unparseable; body=%s", body)
	}
}

// --- PEM input-contract strictness ---------------------------------
//
// The parser is the trust boundary between the agent's local PEM
// serializer (any whitespace habit, any number of blocks) and the
// control plane's canonical PEM column. The four tests below pin
// the post-PR-026 hardening contract: exactly one CERTIFICATE block
// per entry, surrounded only by whitespace. Each test exercises a
// distinct adversarial / malformed path the parser silently accepted
// before the hardening pass.

// TestAgentCertificatesRejectsMultiCertChain asserts that a single
// certificates[] entry containing leaf+intermediate concatenated PEM
// is rejected, not silently truncated to the first block. Agents
// that legitimately want to report multiple certs must put each in
// its own array entry — the per-entry parser refuses to guess which
// cert to keep.
func TestAgentCertificatesRejectsMultiCertChain(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	leaf := generatedCert(t, "leaf.example")
	intermediate := generatedCert(t, "intermediate.example")
	chain := leaf + intermediate

	raw, _ := json.Marshal(ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, CertificatePEM: chain},
		},
	})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/agent/certificates", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+credential)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 400; body=%s", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "certificate_unparseable") {
		t.Errorf("envelope did not contain certificate_unparseable; body=%s", body)
	}

	// And critically: NO cert row was stored. A silent truncation
	// bug would have inserted exactly the leaf — the assertion below
	// makes regressions visible.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var certRows int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COUNT(*) FROM certificates`).Scan(&certRows)
	}); err != nil {
		t.Fatalf("count: %v", err)
	}
	if certRows != 0 {
		t.Errorf("certificates rows = %d, want 0 (chain entry must be wholly rejected, not partially stored)", certRows)
	}
}

// TestAgentCertificatesRejectsNonCertificatePEM asserts the parser
// refuses a PEM block whose type is anything other than CERTIFICATE
// (CSR, PUBLIC KEY, etc.). Before the hardening pass, the parser
// looped past non-CERTIFICATE blocks silently — a CSR followed by a
// real cert would have been accepted with the CSR thrown away.
func TestAgentCertificatesRejectsNonCertificatePEM(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	// A syntactically valid CERTIFICATE REQUEST PEM. The base64
	// payload is just placeholder bytes — pem.Decode only looks at
	// the markers, and the parser must reject on the block type
	// before x509 parsing runs.
	csr := "-----BEGIN CERTIFICATE REQUEST-----\nbm90LWEtcmVhbC1jc3I=\n-----END CERTIFICATE REQUEST-----\n"

	raw, _ := json.Marshal(ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, CertificatePEM: csr},
		},
	})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/agent/certificates", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+credential)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 400; body=%s", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "certificate_unparseable") {
		t.Errorf("envelope did not contain certificate_unparseable; body=%s", body)
	}
}

// TestAgentCertificatesRejectsTrailingGarbageAfterPEM asserts that
// non-whitespace bytes after the END CERTIFICATE line cause the
// whole entry to be rejected. encoding/pem.Decode returns the
// trailing remainder in `rest`; the previous parser ignored it,
// allowing an attacker (or a buggy serializer) to attach arbitrary
// content the control plane never saw.
func TestAgentCertificatesRejectsTrailingGarbageAfterPEM(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	good := generatedCert(t, "good-trailing.example")
	// Append non-whitespace garbage AFTER the END CERTIFICATE line.
	// Deliberately not a private-key marker (that would be caught by
	// the upstream containsPrivateKeyMarker scan, not by the parser),
	// and not a second CERTIFICATE block (that's the chain test). A
	// plain text suffix is the minimum case we care about.
	withGarbage := good + "trailing-non-whitespace-content\n"

	raw, _ := json.Marshal(ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, CertificatePEM: withGarbage},
		},
	})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/agent/certificates", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+credential)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 400; body=%s", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "certificate_unparseable") {
		t.Errorf("envelope did not contain certificate_unparseable; body=%s", body)
	}
}

// TestAgentCertificatesRejectsLeadingGarbageBeforePEM asserts that
// non-whitespace bytes BEFORE the BEGIN CERTIFICATE line cause the
// entry to be rejected. encoding/pem.Decode silently skips any
// preamble before the first PEM marker; that's by design in the
// stdlib but wrong for an ingestion endpoint where the wire shape
// is supposed to be exactly one cert per entry.
func TestAgentCertificatesRejectsLeadingGarbageBeforePEM(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	good := generatedCert(t, "good-leading.example")
	// Prepend non-whitespace garbage BEFORE the BEGIN CERTIFICATE
	// line. Leading whitespace (\n, spaces, tabs, CRLF) is and
	// remains TOLERATED — TestAgentCertificatesNormalizationConsistency
	// pins that case.
	withGarbage := "leading-non-whitespace-content\n" + good

	raw, _ := json.Marshal(ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, CertificatePEM: withGarbage},
		},
	})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/agent/certificates", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+credential)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 400; body=%s", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "certificate_unparseable") {
		t.Errorf("envelope did not contain certificate_unparseable; body=%s", body)
	}
}

// --- malformed JSON / trailing garbage -----------------------------

func TestAgentCertificatesRejectsMalformedJSON(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	submitCertBatchRaw(t, srv.URL, credential, []byte(`{"collected_at":`), http.StatusBadRequest)
}

func TestAgentCertificatesRejectsTrailingJSON(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	good := generatedCert(t, "trailing-test.example")
	raw1, _ := json.Marshal(ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, CertificatePEM: good},
		},
	})
	// Append a second JSON object — second-Decode-must-EOF guard fires.
	combined := append(append([]byte{}, raw1...), []byte(`{"extra":1}`)...)
	submitCertBatchRaw(t, srv.URL, credential, combined, http.StatusBadRequest)

	// Trailing garbage.
	garbageAppended := append(append([]byte{}, raw1...), []byte(`xyzabc`)...)
	submitCertBatchRaw(t, srv.URL, credential, garbageAppended, http.StatusBadRequest)
}

// --- empty store_coverage rejection --------------------------------

func TestAgentCertificatesRejectsEmptyStoreCoverage(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	good := generatedCert(t, "no-cov.example")
	submitCertBatch(t, srv.URL, credential, ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, CertificatePEM: good},
		},
	}, http.StatusBadRequest)
}

func TestAgentCertificatesRejectsStoreNotInCoverage(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	good := generatedCert(t, "wrong-store.example")
	submitCertBatch(t, srv.URL, credential, ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\WebHosting`, CertificatePEM: good},
		},
	}, http.StatusBadRequest)
}

func TestAgentCertificatesRejectsDuplicateStoreCoverageEntries(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	good := generatedCert(t, "dup-cov.example")
	submitCertBatch(t, srv.URL, credential, ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`, `LocalMachine\My`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, CertificatePEM: good},
		},
	}, http.StatusBadRequest)
}

// --- duplicate fingerprint/store inside batch ----------------------

func TestAgentCertificatesRejectsDuplicateFingerprintStorePair(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	c := generatedCert(t, "dup-fp-store.example")
	submitCertBatch(t, srv.URL, credential, ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, CertificatePEM: c},
			{StoreLocation: `LocalMachine\My`, CertificatePEM: c}, // exact duplicate
		},
	}, http.StatusBadRequest)
}

// --- cross-store: same cert in multiple stores allowed -------------

func TestAgentCertificatesSameCertMultipleStoresAllowed(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	c := generatedCert(t, "cross-store.example")
	resp := submitCertBatch(t, srv.URL, credential, ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`, `LocalMachine\WebHosting`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, CertificatePEM: c},
			{StoreLocation: `LocalMachine\WebHosting`, CertificatePEM: c},
		},
	}, http.StatusOK)
	if resp.Accepted != 2 {
		t.Errorf("accepted = %d, want 2 (same cert, two stores)", resp.Accepted)
	}

	// Exactly ONE cert row, TWO observation rows.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var certRows, obsRows int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM certificates`).Scan(&certRows); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT COUNT(*) FROM certificate_observations`).Scan(&obsRows)
	}); err != nil {
		t.Fatalf("count: %v", err)
	}
	if certRows != 1 {
		t.Errorf("cert rows = %d, want 1 (dedup)", certRows)
	}
	if obsRows != 2 {
		t.Errorf("observation rows = %d, want 2", obsRows)
	}
}

// --- PEM normalization consistency ---------------------------------

func TestAgentCertificatesNormalizationConsistency(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	canonical := generatedCert(t, "norm-test.example")
	// Mangle the formatting in the ways a Windows agent's serializer
	// realistically might: CRLF line endings instead of LF, plus a
	// couple of leading/trailing blank lines. pem.Decode requires
	// `-----BEGIN ` to appear at start-of-input or immediately after
	// a `\n` — so we deliberately do NOT add leading whitespace on
	// the BEGIN line itself (that's a separate, real bug we're not
	// claiming to handle).
	mangled := "\n\n" + strings.ReplaceAll(canonical, "\n", "\r\n") + "\n\n"

	submitCertBatch(t, srv.URL, credential, ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, CertificatePEM: canonical},
		},
	}, http.StatusOK)

	// Different agent (or different host's formatting) submits the
	// SAME cert with different whitespace. Must dedup to ONE cert
	// row, not two — the server normalizes before fingerprinting.
	_, secondCredential := enrolledAgent(t, srv.URL, adminClient)
	submitCertBatch(t, srv.URL, secondCredential, ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, CertificatePEM: mangled},
		},
	}, http.StatusOK)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var certRows int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COUNT(*) FROM certificates`).Scan(&certRows)
	}); err != nil {
		t.Fatalf("count: %v", err)
	}
	if certRows != 1 {
		t.Errorf("cert rows = %d, want 1 (normalized PEM should dedup)", certRows)
	}
}

// --- oversized PEM / oversized payload -----------------------------

func TestAgentCertificatesRejectsOversizedPEM(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	// 33 KiB cert PEM exceeds MaxCertPEMBytes (32 KiB).
	huge := "-----BEGIN CERTIFICATE-----\n" + strings.Repeat("A", 33*1024) + "\n-----END CERTIFICATE-----\n"
	submitCertBatch(t, srv.URL, credential, ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, CertificatePEM: huge},
		},
	}, http.StatusBadRequest)
}

func TestAgentCertificatesRejectsTooManyCerts(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	// MaxCertsPerBatch + 1 entries — synthesize a small fake PEM
	// per entry. They won't parse if we reach the parser, but the
	// handler rejects on count BEFORE the service runs.
	const N = 5001
	certs := make([]ingestCertDTO, 0, N)
	stub := "-----BEGIN CERTIFICATE-----\nMIIBIjA=\n-----END CERTIFICATE-----\n"
	for i := 0; i < N; i++ {
		certs = append(certs, ingestCertDTO{
			StoreLocation:  `LocalMachine\My`,
			CertificatePEM: stub,
		})
	}
	submitCertBatch(t, srv.URL, credential, ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates:  certs,
	}, http.StatusBadRequest)
}

// --- out-of-order arrival uses storage primitives -------------------

func TestAgentCertificatesOutOfOrderRespectsStorageGuards(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	agentID, credential := enrolledAgent(t, srv.URL, adminClient)

	c := generatedCert(t, "out-of-order.example")

	tNew := time.Now().UTC()
	tOld := tNew.Add(-1 * time.Hour)

	// Newer batch first.
	submitCertBatch(t, srv.URL, credential, ingestRequestDTO{
		CollectedAt:   tNew.Format(time.RFC3339),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, CertificatePEM: c},
		},
	}, http.StatusOK)

	// Older batch second. With H-018 storage semantics:
	// first_seen_at retreats to tOld; last_seen_at stays at tNew.
	submitCertBatch(t, srv.URL, credential, ingestRequestDTO{
		CollectedAt:   tOld.Format(time.RFC3339),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, CertificatePEM: c},
		},
	}, http.StatusOK)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var firstSeen, lastSeen time.Time
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT first_seen_at, last_seen_at FROM certificate_observations WHERE agent_id = $1`,
			agentID).Scan(&firstSeen, &lastSeen)
	}); err != nil {
		t.Fatalf("read: %v", err)
	}
	// Within 1 second (RFC3339 precision).
	if firstSeen.After(tOld.Add(1 * time.Second)) {
		t.Errorf("first_seen_at = %v; want around tOld %v (LEAST wins)", firstSeen, tOld)
	}
	if lastSeen.Before(tNew.Add(-1 * time.Second)) {
		t.Errorf("last_seen_at = %v; want around tNew %v (GREATEST wins)", lastSeen, tNew)
	}
}

// --- clock-skew rejection ------------------------------------------

func TestAgentCertificatesRejectsFutureCollectedAt(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	c := generatedCert(t, "future.example")
	// More than 24h in the future.
	future := time.Now().UTC().Add(48 * time.Hour).Format(time.RFC3339)
	submitCertBatch(t, srv.URL, credential, ingestRequestDTO{
		CollectedAt:   future,
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, CertificatePEM: c},
		},
	}, http.StatusBadRequest)
}

// TestAgentCertificatesRejectsMissingCollectedAt (Blocker 1 / Codex
// P1 regression). An omitted collected_at deserializes to Go's
// zero time (year 0001). Without the IsZero check in
// inventory.Service.Submit, the batch would persist 0001-01-01
// into first_seen_at/last_seen_at and corrupt reconciliation
// comparisons against future rows. Service rejects with
// ErrInvalidBatch; handler maps to 400 bad_request; nothing is
// written to certificates or certificate_observations.
func TestAgentCertificatesRejectsMissingCollectedAt(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	_, credential := enrolledAgent(t, srv.URL, adminClient)

	c := generatedCert(t, "missing-collected-at.example")
	// Hand-crafted body that intentionally omits collected_at.
	// (json.Marshal of our DTO with an empty CollectedAt string
	// would serialize as "" which is also invalid, but the bug
	// the user flagged is the wire-omitted case — confirm both.)
	rawOmitted := []byte(`{
		"store_coverage": ["LocalMachine\\My"],
		"certificates": [
			{"store_location": "LocalMachine\\My", "certificate_pem": ` + jsonString(c) + `}
		]
	}`)
	submitCertBatchRaw(t, srv.URL, credential, rawOmitted, http.StatusBadRequest)

	// Also confirm explicit null is rejected.
	rawNull := []byte(`{
		"collected_at": null,
		"store_coverage": ["LocalMachine\\My"],
		"certificates": [
			{"store_location": "LocalMachine\\My", "certificate_pem": ` + jsonString(c) + `}
		]
	}`)
	submitCertBatchRaw(t, srv.URL, credential, rawNull, http.StatusBadRequest)

	// Nothing should have been written on the rejection path.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var certRows, obsRows int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM certificates`).Scan(&certRows); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT COUNT(*) FROM certificate_observations`).Scan(&obsRows)
	}); err != nil {
		t.Fatalf("count: %v", err)
	}
	if certRows != 0 || obsRows != 0 {
		t.Errorf("missing-collected_at reject leaked data: certRows=%d obsRows=%d, want 0/0", certRows, obsRows)
	}
}

// jsonString returns the JSON-escaped string form of s, suitable
// for inlining into a hand-crafted JSON literal. We use it only
// in the missing-collected_at test where we deliberately bypass
// json.Marshal of our wire DTO (which would always emit a
// collected_at key, even if zero-valued).
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// --- auth: operator cookie + anonymous + bearer rejection ----------

func TestAgentCertificatesRejectsOperatorCookie(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)

	c := generatedCert(t, "operator-cookie.example")
	raw, _ := json.Marshal(ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, CertificatePEM: c},
		},
	})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/agent/certificates", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := adminClient.Do(req)
	if err != nil {
		t.Fatalf("operator submit: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("operator cookie admitted; status = %d, want 401", resp.StatusCode)
	}
}

func TestAgentCertificatesRejectsAnonymous(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, _ := testServer(t, db)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/agent/certificates", strings.NewReader(`{}`))
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

// --- successful batch does NOT write audit ------------------------

func TestAgentCertificatesSuccessNoAuditRow(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	srv, svc := testServer(t, db)
	adminClient := signInAdmin(t, urlSrv{url: srv.URL}, svc)
	agentID, credential := enrolledAgent(t, srv.URL, adminClient)

	c := generatedCert(t, "no-audit.example")
	submitCertBatch(t, srv.URL, credential, ingestRequestDTO{
		CollectedAt:   nowRFC3339(),
		StoreCoverage: []string{`LocalMachine\My`},
		Certificates: []ingestCertDTO{
			{StoreLocation: `LocalMachine\My`, CertificatePEM: c},
		},
	}, http.StatusOK)

	// Per CERTIFICATE_INVENTORY.md §6 — no per-batch audit row on
	// success.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var n int
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT COUNT(*) FROM audit_events
			  WHERE action LIKE 'agent.certificate%' AND target_id = $1`,
			agentID).Scan(&n)
	}); err != nil {
		t.Fatalf("audit count: %v", err)
	}
	if n != 0 {
		t.Errorf("audit rows = %d, want 0 (successful ingestion is operational telemetry)", n)
	}
}

// --- diagnostic: build-time check that our wire IDs match server ---

func TestAgentCertificatesEnforcesBearerOnly(t *testing.T) {
	// Bearer credential is checked by RequireAuthenticatedAgent
	// middleware (covered by H-007 tests). This belt-and-braces
	// test confirms the bearer prefix is required — a missing /
	// malformed Authorization header surfaces as 401.
	db := testDB(t)
	freshDatabase(t, db)
	srv, _ := testServer(t, db)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/agent/certificates",
		strings.NewReader(`{}`))
	req.Header.Set("Authorization", "NotBearer something")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("malformed auth: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

// --- silence the unused-import warning when this file's helpers
// shrink in the future. Keeps fmt importable for ad-hoc debugging.
var _ = fmt.Sprintf
