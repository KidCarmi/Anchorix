package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kidcarmi/anchorix/backend/internal/audit"
	"github.com/kidcarmi/anchorix/backend/internal/clock"
	"github.com/kidcarmi/anchorix/backend/internal/ids"
)

// AuditRecorder writes audit_events rows. Append-only at the
// database level — UPDATE/DELETE on the table are rejected by
// trigger (CLAUDE.md §9, §16).
type AuditRecorder struct {
	pool  *pgxpool.Pool
	clock clock.Clock
}

// NewAuditRecorder wires the recorder.
func NewAuditRecorder(db *DB, c clock.Clock) *AuditRecorder {
	return &AuditRecorder{pool: db.querier(), clock: c}
}

// Record inserts a new audit row. Fills in ID and OccurredAt if the
// caller left them zero, so callers only need to set the semantic
// fields (actor, action, target). CLAUDE.md §9: every state-changing
// operation calls this exactly once on success.
func (r *AuditRecorder) Record(ctx context.Context, e audit.Event) error {
	if e.ID == "" {
		e.ID = ids.New()
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = r.clock.Now()
	}
	if e.OrganizationID == "" {
		return fmt.Errorf("audit: organization_id required")
	}
	if e.Actor == "" || e.ActorType == "" {
		return fmt.Errorf("audit: actor and actor_type required")
	}
	if e.Action == "" || e.TargetType == "" || e.TargetID == "" {
		return fmt.Errorf("audit: action/target_type/target_id required")
	}
	metadata := []byte("{}")
	if len(e.Metadata) > 0 {
		if !json.Valid(e.Metadata) {
			return fmt.Errorf("audit: metadata is not valid JSON")
		}
		metadata = e.Metadata
	}
	const q = `
		INSERT INTO audit_events
		  (id, organization_id, occurred_at, actor, actor_type,
		   action, target_type, target_id, request_id, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb)`
	_, err := r.pool.Exec(ctx, q,
		e.ID, e.OrganizationID, e.OccurredAt, e.Actor, e.ActorType,
		e.Action, e.TargetType, e.TargetID, nullIfEmpty(e.RequestID), metadata,
	)
	if err != nil {
		return fmt.Errorf("postgres: insert audit_event: %w", err)
	}
	return nil
}

// List returns audit events matching the query, newest-first.
func (r *AuditRecorder) List(ctx context.Context, q audit.ListQuery) ([]audit.Event, error) {
	limit := q.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	const sql = `
		SELECT id, organization_id, occurred_at, actor, actor_type,
		       action, target_type, target_id, request_id, metadata
		  FROM audit_events
		 WHERE ($1::text IS NULL OR organization_id = $1)
		   AND ($2::text IS NULL OR actor = $2)
		   AND ($3::text IS NULL OR action = $3)
		   AND ($4::text IS NULL OR target_type = $4)
		   AND ($5::text IS NULL OR target_id = $5)
		 ORDER BY occurred_at DESC
		 LIMIT $6`
	rows, err := r.pool.Query(ctx, sql,
		nullIfEmpty(q.OrganizationID), nullIfEmpty(q.Actor),
		nullIfEmpty(q.Action), nullIfEmpty(q.TargetType),
		nullIfEmpty(q.TargetID), limit,
	)
	if err != nil {
		return nil, fmt.Errorf("postgres: list audit_events: %w", err)
	}
	defer rows.Close()
	out := make([]audit.Event, 0, limit)
	for rows.Next() {
		var (
			e         audit.Event
			requestID *string
			metadata  []byte
			occurred  time.Time
		)
		if err := rows.Scan(
			&e.ID, &e.OrganizationID, &occurred, &e.Actor, &e.ActorType,
			&e.Action, &e.TargetType, &e.TargetID, &requestID, &metadata,
		); err != nil {
			return nil, fmt.Errorf("postgres: scan audit_event: %w", err)
		}
		e.OccurredAt = occurred
		if requestID != nil {
			e.RequestID = *requestID
		}
		e.Metadata = metadata
		out = append(out, e)
	}
	return out, rows.Err()
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
