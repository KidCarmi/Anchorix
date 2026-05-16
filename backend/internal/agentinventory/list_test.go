package agentinventory

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

// seedSummaries inserts n distinct snapshots into the fake repo with
// staggered received_at times so the ListSummaries ordering is
// deterministic and predictable in assertions. The newest row is at
// index 0 of the returned slice (mirrors the DESC sort).
func seedSummaries(t *testing.T, repo *fakeRepo, n int) []Snapshot {
	t.Helper()
	base := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	out := make([]Snapshot, 0, n)
	for i := 0; i < n; i++ {
		// Each later index gets an OLDER received_at so sorting DESC
		// surfaces them in ascending index order — easier to read in
		// assertions like "got[0].AgentID == 'agent-0'".
		s := &Snapshot{
			OrganizationID: testOrg,
			AgentID:        agentIDFor(i),
			Hostname:       "host-" + agentIDFor(i),
			OSName:         "Linux",
			OSVersion:      "6.1",
			AgentVersion:   "0.1.0",
			MachineArch:    "amd64",
			LocalIPs:       []string{"10.0.0.1"},
			ReceivedAt:     base.Add(-time.Duration(i) * time.Minute),
			UpdatedAt:      base.Add(-time.Duration(i) * time.Minute),
		}
		if err := repo.Upsert(context.Background(), s); err != nil {
			t.Fatalf("seed upsert: %v", err)
		}
		out = append(out, *s)
	}
	return out
}

// agentIDFor returns a stable, sortable agent id for index i.
// Padded so string-sort matches numeric-sort across two-digit ranges.
func agentIDFor(i int) string {
	return "agent-" + zeroPad(i, 3)
}

func zeroPad(i, width int) string {
	s := []byte("0000000000")
	n := i
	for k := width - 1; k >= 0; k-- {
		s[k] = byte('0' + n%10)
		n /= 10
	}
	return string(s[:width])
}

func TestListSummariesRejectsMissingOrg(t *testing.T) {
	svc, _, _ := newServiceForTest(t)
	_, err := svc.ListSummaries(context.Background(), ListSummariesInput{})
	if !errors.Is(err, ErrInvalidListInput) {
		t.Errorf("err = %v, want ErrInvalidListInput", err)
	}
}

func TestListSummariesAppliesDefaultLimit(t *testing.T) {
	svc, repo, _ := newServiceForTest(t)
	seedSummaries(t, repo, DefaultListLimit+5)

	out, err := svc.ListSummaries(context.Background(), ListSummariesInput{
		OrganizationID: testOrg,
	})
	if err != nil {
		t.Fatalf("ListSummaries: %v", err)
	}
	if len(out.Items) != DefaultListLimit {
		t.Errorf("len(items) = %d, want DefaultListLimit=%d", len(out.Items), DefaultListLimit)
	}
	if out.NextCursor == "" {
		t.Error("NextCursor empty, want non-empty (there are more rows)")
	}
}

func TestListSummariesRejectsOversizeLimit(t *testing.T) {
	svc, _, _ := newServiceForTest(t)
	_, err := svc.ListSummaries(context.Background(), ListSummariesInput{
		OrganizationID: testOrg,
		Limit:          MaxListLimit + 1,
	})
	if !errors.Is(err, ErrInvalidListInput) {
		t.Errorf("err = %v, want ErrInvalidListInput", err)
	}
}

func TestListSummariesRejectsNegativeLimit(t *testing.T) {
	svc, _, _ := newServiceForTest(t)
	_, err := svc.ListSummaries(context.Background(), ListSummariesInput{
		OrganizationID: testOrg,
		Limit:          -1,
	})
	if !errors.Is(err, ErrInvalidListInput) {
		t.Errorf("err = %v, want ErrInvalidListInput", err)
	}
}

func TestListSummariesEmptyOrgReturnsEmpty(t *testing.T) {
	svc, _, _ := newServiceForTest(t)
	out, err := svc.ListSummaries(context.Background(), ListSummariesInput{
		OrganizationID: testOrg,
	})
	if err != nil {
		t.Fatalf("ListSummaries: %v", err)
	}
	if len(out.Items) != 0 {
		t.Errorf("len(items) = %d, want 0", len(out.Items))
	}
	if out.NextCursor != "" {
		t.Errorf("NextCursor = %q, want empty", out.NextCursor)
	}
}

func TestListSummariesNextCursorOnLastPageIsEmpty(t *testing.T) {
	svc, repo, _ := newServiceForTest(t)
	seedSummaries(t, repo, 3)

	out, err := svc.ListSummaries(context.Background(), ListSummariesInput{
		OrganizationID: testOrg,
		Limit:          10, // larger than the 3 seeded rows
	})
	if err != nil {
		t.Fatalf("ListSummaries: %v", err)
	}
	if len(out.Items) != 3 {
		t.Errorf("len(items) = %d, want 3", len(out.Items))
	}
	if out.NextCursor != "" {
		t.Errorf("NextCursor = %q, want empty (this IS the last page)", out.NextCursor)
	}
}

func TestListSummariesCursorAdvancesToNextPage(t *testing.T) {
	svc, repo, _ := newServiceForTest(t)
	seeded := seedSummaries(t, repo, 5)
	// Sort the seed by the documented order so we can assert on
	// which rows belong on each page. seedSummaries already creates
	// them in received_at-descending order at index 0..4.
	_ = seeded

	page1, err := svc.ListSummaries(context.Background(), ListSummariesInput{
		OrganizationID: testOrg,
		Limit:          2,
	})
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1.Items) != 2 {
		t.Fatalf("page1 len = %d, want 2", len(page1.Items))
	}
	if page1.Items[0].AgentID != "agent-000" || page1.Items[1].AgentID != "agent-001" {
		t.Errorf("page1 ids = %s, %s; want agent-000, agent-001",
			page1.Items[0].AgentID, page1.Items[1].AgentID)
	}
	if page1.NextCursor == "" {
		t.Fatal("page1 NextCursor empty; want set (more rows remain)")
	}

	page2, err := svc.ListSummaries(context.Background(), ListSummariesInput{
		OrganizationID: testOrg,
		Limit:          2,
		Cursor:         page1.NextCursor,
	})
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2.Items) != 2 {
		t.Fatalf("page2 len = %d, want 2", len(page2.Items))
	}
	if page2.Items[0].AgentID != "agent-002" || page2.Items[1].AgentID != "agent-003" {
		t.Errorf("page2 ids = %s, %s; want agent-002, agent-003",
			page2.Items[0].AgentID, page2.Items[1].AgentID)
	}
	if page2.NextCursor == "" {
		t.Fatal("page2 NextCursor empty; want set (one more row remains)")
	}

	page3, err := svc.ListSummaries(context.Background(), ListSummariesInput{
		OrganizationID: testOrg,
		Limit:          2,
		Cursor:         page2.NextCursor,
	})
	if err != nil {
		t.Fatalf("page3: %v", err)
	}
	if len(page3.Items) != 1 {
		t.Errorf("page3 len = %d, want 1 (final row)", len(page3.Items))
	}
	if page3.NextCursor != "" {
		t.Errorf("page3 NextCursor = %q, want empty (no more rows)", page3.NextCursor)
	}
}

func TestListSummariesRejectsMalformedCursor(t *testing.T) {
	svc, _, _ := newServiceForTest(t)

	cases := []struct {
		name   string
		cursor string
	}{
		{"non-base64", "!!!not-base64!!!"},
		{"base64-no-separator", base64.RawURLEncoding.EncodeToString([]byte("just-one-part"))},
		{"base64-bad-timestamp", base64.RawURLEncoding.EncodeToString([]byte("not-a-timestamp|agent-001"))},
		{"base64-empty-timestamp", base64.RawURLEncoding.EncodeToString([]byte("|agent-001"))},
		{"base64-empty-agent", base64.RawURLEncoding.EncodeToString([]byte("2026-05-14T12:00:00Z|"))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.ListSummaries(context.Background(), ListSummariesInput{
				OrganizationID: testOrg,
				Cursor:         tc.cursor,
			})
			if !errors.Is(err, ErrInvalidListInput) {
				t.Errorf("err = %v, want ErrInvalidListInput", err)
			}
		})
	}
}

func TestListSummariesOmitsCrossOrgRows(t *testing.T) {
	svc, repo, _ := newServiceForTest(t)
	seedSummaries(t, repo, 3) // org = testOrg

	// Seed a snapshot in a DIFFERENT org. It must NOT appear in the
	// list returned for testOrg, regardless of received_at or
	// pagination state. This is defense-in-depth on top of the
	// repository's SQL WHERE clause.
	other := &Snapshot{
		OrganizationID: "other-org",
		AgentID:        "outsider-agent",
		Hostname:       "outsider",
		ReceivedAt:     time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), // newest of all
		UpdatedAt:      time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	if err := repo.Upsert(context.Background(), other); err != nil {
		t.Fatalf("seed other-org: %v", err)
	}

	out, err := svc.ListSummaries(context.Background(), ListSummariesInput{
		OrganizationID: testOrg,
		Limit:          100,
	})
	if err != nil {
		t.Fatalf("ListSummaries: %v", err)
	}
	for _, item := range out.Items {
		if item.AgentID == "outsider-agent" {
			t.Errorf("cross-org row leaked into list: %+v", item)
		}
	}
	if len(out.Items) != 3 {
		t.Errorf("len(items) = %d, want 3 (only same-org rows)", len(out.Items))
	}
}

func TestEncodeDecodeListCursorRoundTrip(t *testing.T) {
	original := time.Date(2026, 5, 14, 12, 34, 56, 123456789, time.UTC)
	cursor := encodeListCursor(original, "agent-042")

	gotTime, gotID, err := decodeListCursor(cursor)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !gotTime.Equal(original) {
		t.Errorf("decoded time = %v, want %v", gotTime, original)
	}
	if gotID != "agent-042" {
		t.Errorf("decoded id = %q, want agent-042", gotID)
	}
	// Encoded cursor must be base64-url safe — no '+', '/', or '='.
	if strings.ContainsAny(cursor, "+/=") {
		t.Errorf("cursor %q contains characters outside RawURL alphabet", cursor)
	}
}

func TestDecodeListCursorEmptyIsFirstPage(t *testing.T) {
	gotTime, gotID, err := decodeListCursor("")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !gotTime.IsZero() {
		t.Errorf("empty cursor decoded time = %v, want zero", gotTime)
	}
	if gotID != "" {
		t.Errorf("empty cursor decoded id = %q, want empty", gotID)
	}
}
