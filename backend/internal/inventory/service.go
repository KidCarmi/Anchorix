package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/audit"
	"github.com/kidcarmi/anchorix/backend/internal/clock"
)

// Service is the certificate-inventory domain entrypoint. The HTTP
// handler depends on this struct, never on the Repository /
// Transactor types directly (CLAUDE.md §8.6, §8.8). Service owns:
//
//   - private-key detection (whole-batch reject; CERTIFICATE_INVENTORY.md §7),
//   - server-side X.509 parsing + canonical fingerprint computation,
//   - the set-reconciliation orchestration (upsert each cert +
//     observation, then MarkMissingObservationsRemoved for the
//     declared store_coverage),
//   - the H-017 advisory-lock-per-agent transactional boundary so
//     concurrent batches for the same agent serialize,
//   - audit recording on rejection paths (no audit on success —
//     CERTIFICATE_INVENTORY.md §6 cardinality argument).
type Service struct {
	repo  Repository
	tx    Transactor
	audit audit.Recorder
	clock clock.Clock
}

// NewService wires the service. Constructor-based DI per CLAUDE.md
// §8.8. Returns an error if any dependency is missing — never
// panics (CLAUDE.md §18: no panic-driven business flow).
func NewService(repo Repository, tx Transactor, auditRec audit.Recorder, clk clock.Clock) (*Service, error) {
	switch {
	case repo == nil:
		return nil, errors.New("inventory.NewService: repository required")
	case tx == nil:
		return nil, errors.New("inventory.NewService: transactor required")
	case auditRec == nil:
		return nil, errors.New("inventory.NewService: audit recorder required")
	case clk == nil:
		return nil, errors.New("inventory.NewService: clock required")
	}
	return &Service{
		repo:  repo,
		tx:    tx,
		audit: auditRec,
		clock: clk,
	}, nil
}

// maxClockSkew is the upper bound on how far in the future the
// agent's collected_at may be relative to the server clock. Matches
// CERTIFICATE_INVENTORY.md §4's documented "Future > now + 24h is
// rejected" contract. v0.1 does not gate on past collected_at —
// out-of-order arrival is handled by the storage layer's LEAST /
// GREATEST timestamps (H-018 fix).
const maxClockSkew = 24 * time.Hour

// Submit validates and ingests a certificate batch from one agent.
// The HTTP handler MUST populate in.OrganizationID and in.AgentID
// from AgentFromContext (NEVER from the request body) — Submit
// surfaces an ErrInvalidBatch if either is empty, but the API
// boundary is the trust boundary.
//
// Validation order is deliberate:
//
//  1. Shape validation (org / agent ids, store_coverage non-empty,
//     no duplicate stores in coverage, clock skew). Fail fast — no
//     audit row, no PEM parsing.
//  2. Per-cert private-key marker scan, BEFORE any PEM parse. Any
//     hit rejects the ENTIRE batch with an audited
//     agent.certificate_batch_rejected event (severity:"security").
//  3. Per-cert store_location must be in store_coverage. Fail fast
//     — no audit row (it's a caller misconfiguration, not a
//     security signal).
//  4. Per-cert PEM parse + canonical fingerprint computation. ANY
//     parse failure rejects the entire batch with an audited
//     agent.certificate_batch_invalid event.
//  5. Per-cert duplicate (fingerprint, store_location) detection
//     across the batch. Whole-batch reject; no audit.
//  6. Transactional ingestion with advisory lock (H-017):
//     UpsertCertificate × N + UpsertObservation × N +
//     MarkMissingObservationsRemoved.
//
// On success, the IngestionOutput counters mirror what the wire
// response echoes back to the agent (CERTIFICATE_INVENTORY.md §4).
func (s *Service) Submit(ctx context.Context, in IngestionInput) (*IngestionOutput, error) {
	// (1) shape validation.
	if strings.TrimSpace(in.OrganizationID) == "" {
		return nil, fmt.Errorf("%w: organization id required", ErrInvalidBatch)
	}
	if strings.TrimSpace(in.AgentID) == "" {
		return nil, fmt.Errorf("%w: agent id required", ErrInvalidBatch)
	}
	if len(in.StoreCoverage) == 0 {
		return nil, fmt.Errorf("%w: store_coverage must be non-empty", ErrInvalidBatch)
	}
	coverage := make(map[string]struct{}, len(in.StoreCoverage))
	for _, store := range in.StoreCoverage {
		if _, dup := coverage[store]; dup {
			return nil, fmt.Errorf("%w: duplicate store_coverage entry %q", ErrInvalidBatch, store)
		}
		coverage[store] = struct{}{}
	}
	if in.CollectedAt.After(s.clock.Now().Add(maxClockSkew)) {
		return nil, fmt.Errorf("%w: collected_at more than 24h in the future", ErrInvalidBatch)
	}

	// (2) private-key marker scan, BEFORE any parse. Whole-batch
	// reject + security audit.
	for _, c := range in.Certificates {
		if containsPrivateKeyMarker(c.CertificatePEM) {
			if err := s.recordBatchRejection(ctx, in, "private_key_material"); err != nil {
				return nil, err
			}
			return nil, ErrPrivateKeyMaterial
		}
	}

	// (3) every cert's store_location must be declared in
	// store_coverage. Fail closed without auditing — this is a
	// caller wiring bug, not a security signal.
	for _, c := range in.Certificates {
		if _, ok := coverage[c.StoreLocation]; !ok {
			return nil, fmt.Errorf("%w: store_location %q not in store_coverage",
				ErrInvalidBatch, c.StoreLocation)
		}
	}

	// (4) parse + canonical fingerprint per cert. (5) duplicate
	// (fingerprint, store_location) detection across the batch.
	parsed := make([]ingestionRecord, 0, len(in.Certificates))
	seen := make(map[string]struct{}, len(in.Certificates))
	for _, c := range in.Certificates {
		cert, err := parseAndCanonicalize(c.CertificatePEM)
		if err != nil {
			if auditErr := s.recordBatchInvalid(ctx, in, "certificate_unparseable"); auditErr != nil {
				return nil, auditErr
			}
			return nil, ErrInvalidCertificate
		}
		key := cert.FingerprintSHA256 + "|" + c.StoreLocation
		if _, dup := seen[key]; dup {
			return nil, fmt.Errorf("%w: duplicate (fingerprint, store_location) in batch", ErrInvalidBatch)
		}
		seen[key] = struct{}{}
		parsed = append(parsed, ingestionRecord{
			cert:          cert,
			storeLocation: c.StoreLocation,
			friendlyName:  c.FriendlyName,
		})
	}

	// (6) transactional ingestion with advisory lock per agent.
	out := &IngestionOutput{}
	if err := s.tx.WithTxLockedAgent(ctx, in.AgentID, func(ctx context.Context) error {
		observedCertIDs := make([]string, 0, len(parsed))
		for _, p := range parsed {
			cert := certificateForIngestion(in.OrganizationID, p.cert)
			stored, err := s.repo.UpsertCertificate(ctx, cert, in.CollectedAt)
			if err != nil {
				return fmt.Errorf("inventory: upsert certificate: %w", err)
			}
			obs := &CertificateObservation{
				OrganizationID: in.OrganizationID,
				CertificateID:  stored.ID,
				AgentID:        in.AgentID,
				StoreLocation:  p.storeLocation,
				FriendlyName:   p.friendlyName,
			}
			if err := s.repo.UpsertObservation(ctx, obs, in.CollectedAt); err != nil {
				return fmt.Errorf("inventory: upsert observation: %w", err)
			}
			observedCertIDs = append(observedCertIDs, stored.ID)
			out.Accepted++
		}
		n, err := s.repo.MarkMissingObservationsRemoved(ctx,
			in.OrganizationID, in.AgentID, in.StoreCoverage,
			observedCertIDs, in.CollectedAt)
		if err != nil {
			return fmt.Errorf("inventory: reconcile: %w", err)
		}
		out.ReconciledAbsent = n
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// ingestionRecord is the parsed+canonicalized form of one batch
// entry, ready for the transactional ingestion loop. Held local
// to Submit to keep the parse output threaded with its
// (storeLocation, friendlyName) wire metadata.
type ingestionRecord struct {
	cert          *parsedCertificate
	storeLocation string
	friendlyName  string
}

// certificateForIngestion translates the parsed X.509 view into the
// domain Certificate shape the repository UpsertCertificate
// expects. The ID is left empty so UpsertCertificate mints one (or
// reuses the existing row's id on conflict).
func certificateForIngestion(orgID string, p *parsedCertificate) *Certificate {
	return &Certificate{
		OrganizationID:    orgID,
		FingerprintSHA256: p.FingerprintSHA256,
		Subject:           p.Subject,
		Issuer:            p.Issuer,
		SerialNumberHex:   p.SerialNumberHex,
		SignatureAlg:      p.SignatureAlg,
		PublicKeyAlg:      p.PublicKeyAlg,
		PublicKeyBits:     p.PublicKeyBits,
		NotBefore:         p.NotBefore,
		NotAfter:          p.NotAfter,
		SANs:              p.SANs,
		KeyUsages:         p.KeyUsages,
		ExtKeyUsages:      p.ExtKeyUsages,
		IsSelfSigned:      p.IsSelfSigned,
		IsCA:              p.IsCA,
		PEM:               p.CanonicalPEM,
	}
}

// recordBatchRejection writes the audit row for a private-key
// rejection. Per CERTIFICATE_INVENTORY.md §6:
//
//   - severity: "security" so downstream alerting can filter,
//   - metadata carries reason + agent_id + batch_size; NEVER cert
//     content, NEVER private-key marker text.
//
// Audit failure is propagated as ErrInternalAudit (HTTP 500). The
// audit row IS the only visible trail for this rejection signal;
// silently dropping it would violate CLAUDE.md §9 (audits are not
// optional on security-significant flows).
func (s *Service) recordBatchRejection(ctx context.Context, in IngestionInput, reason string) error {
	md, _ := json.Marshal(map[string]any{
		"reason":     reason,
		"severity":   "security",
		"agent_id":   in.AgentID,
		"batch_size": len(in.Certificates),
	})
	if err := s.audit.Record(ctx, audit.Event{
		OrganizationID: in.OrganizationID,
		Actor:          in.AgentID,
		ActorType:      "agent",
		Action:         "agent.certificate_batch_rejected",
		TargetType:     "agent",
		TargetID:       in.AgentID,
		Metadata:       md,
	}); err != nil {
		return fmt.Errorf("%w: %v", ErrInternalAudit, err)
	}
	return nil
}

// recordBatchInvalid writes the audit row for a non-security
// validation failure that's still operator-interesting (e.g., the
// agent submitted a PEM that doesn't parse as X.509). Best-effort
// in spirit, but treated the same as recordBatchRejection for
// consistency — both surface audit failures as 500.
func (s *Service) recordBatchInvalid(ctx context.Context, in IngestionInput, reason string) error {
	md, _ := json.Marshal(map[string]any{
		"reason":     reason,
		"agent_id":   in.AgentID,
		"batch_size": len(in.Certificates),
	})
	if err := s.audit.Record(ctx, audit.Event{
		OrganizationID: in.OrganizationID,
		Actor:          in.AgentID,
		ActorType:      "agent",
		Action:         "agent.certificate_batch_invalid",
		TargetType:     "agent",
		TargetID:       in.AgentID,
		Metadata:       md,
	}); err != nil {
		return fmt.Errorf("%w: %v", ErrInternalAudit, err)
	}
	return nil
}
