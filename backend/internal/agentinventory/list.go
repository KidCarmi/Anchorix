package agentinventory

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Defaults and bounds for ListSummaries pagination. The values come
// from H-010: 50 is a reasonable default page size for the operator
// list UI, and 200 caps the SQL response so a malicious or buggy
// caller cannot ask for the entire fleet in one round trip. Both
// bounds are enforced strictly (oversize / non-positive limits are
// rejected with ErrInvalidListInput, NOT silently clamped) so the
// caller always sees the same row count it requested.
const (
	DefaultListLimit = 50
	MaxListLimit     = 200
)

// ErrInvalidListInput is returned by Service.ListSummaries when the
// caller-supplied query is invalid (missing organization id, limit
// out of bounds, malformed cursor). The HTTP layer maps this to
// 400 bad_request.
var ErrInvalidListInput = errors.New("agentinventory: invalid list input")

// ListSummariesInput is the operator's filter for an inventory list
// call. The OrganizationID always comes from the authenticated
// operator session — never from query params. Limit / Cursor are
// the standard cursor-pagination knobs.
//
// Limit == 0 is treated as "use DefaultListLimit". A negative limit
// or a limit above MaxListLimit returns ErrInvalidListInput.
type ListSummariesInput struct {
	OrganizationID string
	Limit          int
	Cursor         string
}

// Summary is the slim row returned by ListSummaries. It is
// deliberately narrower than Snapshot — LocalIPs is reported as a
// count only and certain fields are omitted entirely so the
// payload stays small at fleet scale. Operators wanting the full
// snapshot still use GET /agents/{id}/inventory.
type Summary struct {
	AgentID       string
	Hostname      string
	OSName        string
	OSVersion     string
	AgentVersion  string
	MachineArch   string
	LocalIPsCount int
	InstalledAt   *time.Time
	ReceivedAt    time.Time
	UpdatedAt     time.Time
}

// ListSummariesOutput is what Service.ListSummaries returns. Items
// is the page; NextCursor is the opaque token to feed back as the
// `cursor` query parameter to fetch the next page, or empty if no
// further rows exist.
type ListSummariesOutput struct {
	Items      []Summary
	NextCursor string
}

// SummaryRepositoryQuery is the storage-layer translation of a
// validated ListSummariesInput. CursorReceivedAt is the zero value
// when no cursor was supplied (the SQL treats that as "no
// after-bound"). Limit is the application-level page size; the
// repository internally asks for Limit+1 rows so the service can
// detect a next page without an extra COUNT.
type SummaryRepositoryQuery struct {
	OrganizationID   string
	Limit            int
	CursorReceivedAt time.Time
	CursorAgentID    string
}

// ListSummaries returns one page of inventory summaries for the
// organization, ordered by received_at DESC then agent_id ASC so
// recent snapshots surface first and the (received_at, agent_id)
// tuple is a stable cursor.
//
// Org scoping: the caller (the HTTP handler) MUST set
// OrganizationID from the authenticated operator session. The
// service additionally rejects an empty org id for defense in depth
// — the repository's SQL already filters on organization_id, so a
// missing value would return zero rows, but rejecting up front
// surfaces the misuse loudly instead of silently.
//
// Cursor: opaque, base64-url-encoded "RFC3339Nano|agent_id". The
// service decodes and validates here; the storage layer takes the
// already-parsed (time, id) pair. Malformed cursors return
// ErrInvalidListInput (HTTP 400).
//
// Pagination strategy: the repository fetches Limit+1 rows. If
// Limit+1 rows come back, the (Limit+1)th row is the cursor for the
// next page and is dropped from the returned Items. If <= Limit
// rows come back, NextCursor is empty (this is the last page).
func (s *Service) ListSummaries(ctx context.Context, in ListSummariesInput) (*ListSummariesOutput, error) {
	q, err := in.toRepositoryQuery()
	if err != nil {
		return nil, err
	}
	rows, err := s.repo.ListSummaries(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("agentinventory: list summaries: %w", err)
	}
	limit := q.Limit - 1 // toRepositoryQuery added the +1 sentinel
	out := &ListSummariesOutput{Items: rows}
	if len(rows) > limit {
		// Truncate the +1 sentinel and emit its (received_at, agent_id)
		// as the opaque cursor for the next page.
		last := rows[limit-1]
		out.Items = rows[:limit]
		out.NextCursor = encodeListCursor(last.ReceivedAt, last.AgentID)
	}
	return out, nil
}

// toRepositoryQuery validates ListSummariesInput, applies defaults,
// decodes the cursor, and adds the +1 row sentinel that the
// pagination strategy depends on. Returned errors are wrapped with
// ErrInvalidListInput so the HTTP layer can `errors.Is` for the
// 400 mapping.
func (in ListSummariesInput) toRepositoryQuery() (SummaryRepositoryQuery, error) {
	if strings.TrimSpace(in.OrganizationID) == "" {
		return SummaryRepositoryQuery{}, fmt.Errorf("%w: organization id required", ErrInvalidListInput)
	}
	limit := in.Limit
	if limit == 0 {
		limit = DefaultListLimit
	}
	if limit < 0 {
		return SummaryRepositoryQuery{}, fmt.Errorf("%w: limit must be positive", ErrInvalidListInput)
	}
	if limit > MaxListLimit {
		return SummaryRepositoryQuery{}, fmt.Errorf("%w: limit exceeds %d", ErrInvalidListInput, MaxListLimit)
	}
	cursorAt, cursorAgent, err := decodeListCursor(in.Cursor)
	if err != nil {
		return SummaryRepositoryQuery{}, err
	}
	return SummaryRepositoryQuery{
		OrganizationID:   strings.TrimSpace(in.OrganizationID),
		Limit:            limit + 1, // +1 sentinel for next-page detection
		CursorReceivedAt: cursorAt,
		CursorAgentID:    cursorAgent,
	}, nil
}

// listCursorSeparator is the single byte we use between the
// timestamp and the agent id inside the opaque cursor payload. The
// timestamp's RFC3339Nano format never contains '|', and agent ids
// are hex strings (see internal/ids), so '|' is collision-safe.
const listCursorSeparator = "|"

// encodeListCursor packs (receivedAt, agentID) into the opaque
// cursor string handed back as next_cursor. RFC3339Nano keeps
// nanosecond precision so two snapshots written in the same UTC
// nanosecond still produce distinct cursors when their agent ids
// differ — which they always do, since agent_id is unique.
func encodeListCursor(receivedAt time.Time, agentID string) string {
	raw := receivedAt.UTC().Format(time.RFC3339Nano) + listCursorSeparator + agentID
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// decodeListCursor reverses encodeListCursor. An empty input is
// valid and means "first page"; the returned zero time signals the
// storage layer to omit the after-bound from its WHERE clause.
// Malformed input (bad base64, missing separator, unparseable
// timestamp, empty agent id) maps to ErrInvalidListInput.
func decodeListCursor(raw string) (time.Time, string, error) {
	if raw == "" {
		return time.Time{}, "", nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("%w: malformed cursor", ErrInvalidListInput)
	}
	parts := strings.SplitN(string(decoded), listCursorSeparator, 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return time.Time{}, "", fmt.Errorf("%w: malformed cursor", ErrInvalidListInput)
	}
	at, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, "", fmt.Errorf("%w: malformed cursor", ErrInvalidListInput)
	}
	return at, parts[1], nil
}
