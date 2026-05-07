package inventory

import (
	"context"
	"errors"
	"strings"

	"github.com/kidcarmi/anchorix/backend/internal/clock"
)

// ErrPrivateKeyMaterial is returned when an ingest payload appears to carry
// private key material. Per CLAUDE.md §6.2 this MUST be a hard rejection.
var ErrPrivateKeyMaterial = errors.New("private key material is not accepted")

// Service is the inventory domain entrypoint. Handlers depend on this
// struct, not on the storage implementation.
type Service struct {
	repo  Repository
	clock clock.Clock
}

// NewService wires the inventory service. Callers own the repository and
// clock lifetimes.
func NewService(repo Repository, c clock.Clock) *Service {
	return &Service{repo: repo, clock: c}
}

// Ingest processes a batch of certificate observations from a single agent.
// It performs the private-key-material safety check, then delegates upserts
// and observations to the repository. Risk evaluation runs as a follow-up
// step in internal/risks (wired in Phase 4).
func (s *Service) Ingest(ctx context.Context, p IngestPayload) error {
	if err := rejectPrivateKeyMaterial(p); err != nil {
		return err
	}
	// Real ingestion logic (parse PEM, normalize, upsert, observe) lands in
	// Phase 3. The skeleton stays explicit about the intended shape.
	_ = ctx
	return errors.New("inventory ingestion not yet implemented (Phase 3)")
}

// rejectPrivateKeyMaterial scans the payload for any field name that hints
// at private key material. We err on the side of rejection.
func rejectPrivateKeyMaterial(p IngestPayload) error {
	for _, c := range p.Certificates {
		if looksLikePrivateKey(c.CertificatePEM) {
			return ErrPrivateKeyMaterial
		}
	}
	return nil
}

func looksLikePrivateKey(pem string) bool {
	upper := strings.ToUpper(pem)
	switch {
	case strings.Contains(upper, "BEGIN PRIVATE KEY"),
		strings.Contains(upper, "BEGIN RSA PRIVATE KEY"),
		strings.Contains(upper, "BEGIN EC PRIVATE KEY"),
		strings.Contains(upper, "BEGIN DSA PRIVATE KEY"),
		strings.Contains(upper, "BEGIN ENCRYPTED PRIVATE KEY"):
		return true
	}
	return false
}
