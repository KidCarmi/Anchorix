package inventory

import (
	"context"
	"errors"
	"strings"

	"github.com/kidcarmi/anchorix/backend/internal/clock"
)

// ErrPrivateKeyMaterial is returned when an inventory batch appears to carry
// private key material. Per CLAUDE.md §6.2 this MUST be a hard rejection.
var ErrPrivateKeyMaterial = errors.New("private key material is not accepted")

// Ingestor accepts inventory batches from agents and persists them via the
// repository. It owns the no-private-key safety check and is the only path
// through which agent-reported certificates enter the system.
//
// Ingestor is intentionally narrow: ingestion is its single responsibility.
// New domain capabilities (search, classification, lifecycle actions) belong
// in their own types, not on this struct.
type Ingestor struct {
	repo  Repository
	clock clock.Clock
}

// NewIngestor wires the ingestion pipeline. Callers own the repository and
// clock lifetimes.
func NewIngestor(repo Repository, c clock.Clock) *Ingestor {
	return &Ingestor{repo: repo, clock: c}
}

// Ingest processes a batch of certificate observations from a single agent.
// It performs the private-key-material safety check, then delegates upserts
// and observations to the repository. Risk evaluation runs as a follow-up
// step in internal/risks (wired in Phase 4).
func (i *Ingestor) Ingest(ctx context.Context, batch InventoryBatch) error {
	if err := rejectPrivateKeyMaterial(batch); err != nil {
		return err
	}
	// Real ingestion logic (parse PEM, normalize, upsert, observe) lands in
	// Phase 3. The skeleton stays explicit about the intended shape.
	_ = ctx
	return errors.New("inventory ingestion not yet implemented (Phase 3)")
}

// rejectPrivateKeyMaterial scans the batch for any field that hints at
// private key material. We err on the side of rejection.
func rejectPrivateKeyMaterial(batch InventoryBatch) error {
	for _, cert := range batch.Certificates {
		if looksLikePrivateKey(cert.CertificatePEM) {
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
