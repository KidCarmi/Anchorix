package inventory

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Defaults / bounds for cursor-paginated operator read endpoints
// (H-020). The values match the H-010 agent-inventory list endpoint
// so the operator UI sees a single consistent paging model across
// `/agent-inventory`, `/certificates`, `/certificates/{id}/observations`,
// and `/agents/{id}/certificates`.
const (
	DefaultListLimit = 50
	MaxListLimit     = 200
)

// ErrInvalidListInput is returned by the list service methods when
// the caller-supplied query is structurally invalid (missing
// organization id, limit out of bounds, malformed cursor, malformed
// filter value). The HTTP layer maps this to 400 bad_request.
var ErrInvalidListInput = errors.New("inventory: invalid list input")

// CertificateSummary is the slim row returned by ListCertificates
// and ListAgentCertificates. Deliberately narrower than Certificate:
// the PEM, SANs, and key-usage arrays are excluded so the list
// payload stays small at fleet scale. Operators wanting the full
// detail use GET /certificates/{id}.
//
// observation_count includes both active and removed observations;
// active_observation_count counts only rows where removed_at IS NULL.
// Both are scoped to the same organization as the certificate (the
// composite FKs in migration 0005 enforce this at the DB level).
type CertificateSummary struct {
	ID                     string
	FingerprintSHA256      string
	Subject                string
	Issuer                 string
	SerialNumberHex        string
	SignatureAlg           string
	PublicKeyAlg           string
	PublicKeyBits          int
	NotBefore              time.Time
	NotAfter               time.Time
	IsSelfSigned           bool
	IsCA                   bool
	FirstSeenAt            time.Time
	LastSeenAt             time.Time
	ObservationCount       int
	ActiveObservationCount int
}

// CertificateDetail is what GetCertificateDetail returns: the full
// Certificate plus the same two observation counts as the list
// row. Kept as a separate struct so the detail endpoint can include
// the bulky fields the list intentionally excludes.
type CertificateDetail struct {
	Certificate            Certificate
	ObservationCount       int
	ActiveObservationCount int
}

// ListCertificatesInput is the operator filter for the
// `/certificates` list endpoint. The OrganizationID always comes
// from the authenticated operator session — never from a query
// param. The HTTP handler is responsible for that binding.
//
// CurrentOnly defaults to true at the HTTP boundary (the handler
// parses an omitted query string as "true"); the service trusts
// what it is handed and does not impose its own default.
type ListCertificatesInput struct {
	OrganizationID string
	Search         string
	ExpiringBefore *time.Time
	IsCA           *bool
	AgentID        string
	CurrentOnly    bool
	Limit          int
	Cursor         string
}

// CertificateListQuery is the storage-layer translation of a
// validated ListCertificatesInput. CursorLastSeenAt is the zero
// value when no cursor was supplied (the SQL treats that as "no
// after-bound"). Limit is the application-level page size; the
// repository internally asks for Limit+1 rows so the service can
// detect a next page without an extra COUNT.
type CertificateListQuery struct {
	OrganizationID   string
	Search           string
	ExpiringBefore   *time.Time
	IsCA             *bool
	AgentID          string
	CurrentOnly      bool
	Limit            int
	CursorLastSeenAt time.Time
	CursorID         string
}

// ListCertificatesOutput is what Service.ListCertificates returns.
// Items is the page; NextCursor is the opaque token to feed back
// as the `cursor` query parameter for the next page, or empty when
// no further rows exist.
type ListCertificatesOutput struct {
	Items      []CertificateSummary
	NextCursor string
}

// ObservationListItem is one row of the
// `/certificates/{id}/observations` and per-agent observation list
// responses. Status mirrors removed_at: "active" when removed_at
// IS NULL, "removed" otherwise. Hostname is best-effort from the
// agent's most recent inventory snapshot — it stays empty when the
// agent has never submitted one.
type ObservationListItem struct {
	ID            string
	AgentID       string
	Hostname      string
	StoreLocation string
	FriendlyName  string
	FirstSeenAt   time.Time
	LastSeenAt    time.Time
	RemovedAt     *time.Time
	Status        string
}

// ListObservationsInput is the operator filter for the
// `/certificates/{id}/observations` list endpoint.
type ListObservationsInput struct {
	OrganizationID string
	CertificateID  string
	CurrentOnly    bool
	Limit          int
	Cursor         string
}

// ObservationListQuery is the storage-layer translation of a
// validated ListObservationsInput. The three cursor fields together
// uniquely identify the last row of the previous page under the
// documented ordering (last_seen_at DESC, agent_id ASC,
// store_location ASC).
type ObservationListQuery struct {
	OrganizationID      string
	CertificateID       string
	CurrentOnly         bool
	Limit               int
	CursorLastSeenAt    time.Time
	CursorAgentID       string
	CursorStoreLocation string
}

// ListObservationsOutput is what Service.ListCertificateObservations
// returns. Same envelope shape as ListCertificatesOutput.
type ListObservationsOutput struct {
	Items      []ObservationListItem
	NextCursor string
}

// observationStatusActive / observationStatusRemoved are the two
// values the wire `status` field carries. Defining them once keeps
// the HTTP layer and the service in lockstep.
const (
	observationStatusActive  = "active"
	observationStatusRemoved = "removed"
)

// listCursorSeparator is the byte between fields inside the
// opaque cursor payload. RFC3339Nano timestamps never contain '|'
// and agent / certificate ids are hex (see internal/ids), so '|'
// is collision-safe for those positions. Store locations CAN
// contain arbitrary bytes; the decoders use SplitN with the right
// cap so the trailing field absorbs any embedded separators.
const listCursorSeparator = "|"

// encodeCertCursor packs (lastSeenAt, certificateID) into the
// opaque cursor for the certificate list. RFC3339Nano keeps
// nanosecond precision so two certs with the same last_seen_at
// still produce distinct cursors when their ids differ.
func encodeCertCursor(lastSeenAt time.Time, certificateID string) string {
	raw := lastSeenAt.UTC().Format(time.RFC3339Nano) + listCursorSeparator + certificateID
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// decodeCertCursor reverses encodeCertCursor. An empty input is
// valid and means "first page"; the returned zero time signals
// the storage layer to omit the after-bound from its WHERE
// clause. Malformed input maps to ErrInvalidListInput.
func decodeCertCursor(raw string) (time.Time, string, error) {
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

// encodeObsCursor packs (lastSeenAt, agentID, storeLocation) into
// the opaque cursor for the observations list. The 3-field shape
// matches the documented ordering. SplitN with cap=3 in the
// decoder lets storeLocation absorb any embedded '|' bytes.
func encodeObsCursor(lastSeenAt time.Time, agentID, storeLocation string) string {
	raw := lastSeenAt.UTC().Format(time.RFC3339Nano) + listCursorSeparator + agentID + listCursorSeparator + storeLocation
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// decodeObsCursor reverses encodeObsCursor.
func decodeObsCursor(raw string) (time.Time, string, string, error) {
	if raw == "" {
		return time.Time{}, "", "", nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return time.Time{}, "", "", fmt.Errorf("%w: malformed cursor", ErrInvalidListInput)
	}
	parts := strings.SplitN(string(decoded), listCursorSeparator, 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return time.Time{}, "", "", fmt.Errorf("%w: malformed cursor", ErrInvalidListInput)
	}
	at, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, "", "", fmt.Errorf("%w: malformed cursor", ErrInvalidListInput)
	}
	return at, parts[1], parts[2], nil
}

// toRepositoryQuery validates ListCertificatesInput, applies
// defaults, decodes the cursor, and adds the +1 row sentinel that
// the pagination strategy depends on.
func (in ListCertificatesInput) toRepositoryQuery() (CertificateListQuery, error) {
	if strings.TrimSpace(in.OrganizationID) == "" {
		return CertificateListQuery{}, fmt.Errorf("%w: organization id required", ErrInvalidListInput)
	}
	limit, err := normalizeLimit(in.Limit)
	if err != nil {
		return CertificateListQuery{}, err
	}
	cursorAt, cursorID, err := decodeCertCursor(in.Cursor)
	if err != nil {
		return CertificateListQuery{}, err
	}
	return CertificateListQuery{
		OrganizationID:   strings.TrimSpace(in.OrganizationID),
		Search:           strings.TrimSpace(in.Search),
		ExpiringBefore:   in.ExpiringBefore,
		IsCA:             in.IsCA,
		AgentID:          strings.TrimSpace(in.AgentID),
		CurrentOnly:      in.CurrentOnly,
		Limit:            limit + 1, // +1 sentinel for next-page detection
		CursorLastSeenAt: cursorAt,
		CursorID:         cursorID,
	}, nil
}

// toRepositoryQuery validates ListObservationsInput.
func (in ListObservationsInput) toRepositoryQuery() (ObservationListQuery, error) {
	if strings.TrimSpace(in.OrganizationID) == "" {
		return ObservationListQuery{}, fmt.Errorf("%w: organization id required", ErrInvalidListInput)
	}
	if strings.TrimSpace(in.CertificateID) == "" {
		return ObservationListQuery{}, fmt.Errorf("%w: certificate id required", ErrInvalidListInput)
	}
	limit, err := normalizeLimit(in.Limit)
	if err != nil {
		return ObservationListQuery{}, err
	}
	cursorAt, cursorAgent, cursorStore, err := decodeObsCursor(in.Cursor)
	if err != nil {
		return ObservationListQuery{}, err
	}
	return ObservationListQuery{
		OrganizationID:      strings.TrimSpace(in.OrganizationID),
		CertificateID:       strings.TrimSpace(in.CertificateID),
		CurrentOnly:         in.CurrentOnly,
		Limit:               limit + 1,
		CursorLastSeenAt:    cursorAt,
		CursorAgentID:       cursorAgent,
		CursorStoreLocation: cursorStore,
	}, nil
}

// normalizeLimit applies the default-and-bounds policy for `limit`
// query parameters. 0 -> DefaultListLimit; negative -> error;
// > MaxListLimit -> error. The error path is wrapped in
// ErrInvalidListInput so the HTTP layer can map it to 400.
func normalizeLimit(raw int) (int, error) {
	if raw == 0 {
		return DefaultListLimit, nil
	}
	if raw < 0 {
		return 0, fmt.Errorf("%w: limit must be positive", ErrInvalidListInput)
	}
	if raw > MaxListLimit {
		return 0, fmt.Errorf("%w: limit exceeds %d", ErrInvalidListInput, MaxListLimit)
	}
	return raw, nil
}

// ListCertificates returns one page of certificate summaries for
// the organization, ordered by last_seen_at DESC then id ASC. The
// (last_seen_at, id) tuple is the cursor — last_seen_at provides
// recency; id breaks any nanosecond tie.
//
// Org scoping: the caller MUST set OrganizationID from the
// authenticated operator session. The repository's WHERE clause
// filters on the same id, so cross-org rows cannot surface.
//
// Filters (any combination):
//
//   - Search: case-insensitive substring against subject, issuer,
//     fingerprint_sha256, and the JSONB SANs serialization.
//   - ExpiringBefore: returns rows with not_after < value.
//   - IsCA: when non-nil, exact-match filter.
//   - AgentID: returns only certs observed by this agent (via
//     EXISTS subquery on certificate_observations).
//   - CurrentOnly: when true, returns only certs that have at
//     least one observation with removed_at IS NULL (combined
//     with AgentID when both are set).
func (s *Service) ListCertificates(ctx context.Context, in ListCertificatesInput) (*ListCertificatesOutput, error) {
	q, err := in.toRepositoryQuery()
	if err != nil {
		return nil, err
	}
	rows, err := s.repo.ListCertificates(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("inventory: list certificates: %w", err)
	}
	limit := q.Limit - 1 // strip the +1 sentinel
	out := &ListCertificatesOutput{Items: rows}
	if len(rows) > limit {
		last := rows[limit-1]
		out.Items = rows[:limit]
		out.NextCursor = encodeCertCursor(last.LastSeenAt, last.ID)
	}
	return out, nil
}

// GetCertificateDetail returns the full Certificate plus
// observation counts for one (organization_id, certificate_id)
// pair. Returns ErrCertificateNotFound when no row matches; the
// org column is part of the WHERE clause, so a cross-org id maps
// to the same sentinel (CLAUDE.md §6 deterministic auth).
func (s *Service) GetCertificateDetail(ctx context.Context, organizationID, certificateID string) (*CertificateDetail, error) {
	if strings.TrimSpace(organizationID) == "" {
		return nil, fmt.Errorf("%w: organization id required", ErrInvalidListInput)
	}
	if strings.TrimSpace(certificateID) == "" {
		return nil, fmt.Errorf("%w: certificate id required", ErrInvalidListInput)
	}
	cert, err := s.repo.GetCertificate(ctx, organizationID, certificateID)
	if err != nil {
		return nil, err
	}
	total, active, err := s.repo.CountObservations(ctx, organizationID, certificateID)
	if err != nil {
		return nil, fmt.Errorf("inventory: count observations: %w", err)
	}
	return &CertificateDetail{
		Certificate:            *cert,
		ObservationCount:       total,
		ActiveObservationCount: active,
	}, nil
}

// ListCertificateObservations returns one page of observations for
// a certificate, ordered by last_seen_at DESC then agent_id ASC
// then store_location ASC. Cross-org certificate_id maps to
// ErrCertificateNotFound (so the operator endpoint can return 404
// without observation-row enumeration).
func (s *Service) ListCertificateObservations(ctx context.Context, in ListObservationsInput) (*ListObservationsOutput, error) {
	q, err := in.toRepositoryQuery()
	if err != nil {
		return nil, err
	}
	// Verify the certificate exists in this org. Without this
	// check, an operator probing for a cross-org cert id would
	// get 200 with empty items — useful only as a side-channel
	// for enumeration. GetCertificate already binds on
	// (organization_id, id) and returns ErrCertificateNotFound
	// for cross-org / missing.
	if _, err := s.repo.GetCertificate(ctx, q.OrganizationID, q.CertificateID); err != nil {
		return nil, err
	}
	rows, err := s.repo.ListObservationsPage(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("inventory: list observations: %w", err)
	}
	limit := q.Limit - 1
	out := &ListObservationsOutput{Items: rows}
	if len(rows) > limit {
		last := rows[limit-1]
		out.Items = rows[:limit]
		out.NextCursor = encodeObsCursor(last.LastSeenAt, last.AgentID, last.StoreLocation)
	}
	return out, nil
}

// ListAgentCertificates returns one page of certificate summaries
// observed by a specific agent. Cross-org or missing agent id
// maps to ErrAgentNotFound (so the HTTP layer returns 404 without
// enumerating per-agent state).
func (s *Service) ListAgentCertificates(ctx context.Context, in ListCertificatesInput) (*ListCertificatesOutput, error) {
	if strings.TrimSpace(in.AgentID) == "" {
		return nil, fmt.Errorf("%w: agent id required", ErrInvalidListInput)
	}
	q, err := in.toRepositoryQuery()
	if err != nil {
		return nil, err
	}
	exists, err := s.repo.AgentExistsInOrg(ctx, q.OrganizationID, q.AgentID)
	if err != nil {
		return nil, fmt.Errorf("inventory: agent existence check: %w", err)
	}
	if !exists {
		return nil, ErrAgentNotFound
	}
	rows, err := s.repo.ListCertificates(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("inventory: list agent certificates: %w", err)
	}
	limit := q.Limit - 1
	out := &ListCertificatesOutput{Items: rows}
	if len(rows) > limit {
		last := rows[limit-1]
		out.Items = rows[:limit]
		out.NextCursor = encodeCertCursor(last.LastSeenAt, last.ID)
	}
	return out, nil
}
