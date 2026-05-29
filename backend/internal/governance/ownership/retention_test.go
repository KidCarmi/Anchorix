package ownership

import (
	"reflect"
	"sort"
	"testing"
	"time"
)

// retentionBase is a fixed reference instant so the age math in these
// tests is deterministic and independent of the wall clock.
var retentionBase = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// rec builds an ExplanationRecord whose decided_at is ageDays before
// retentionBase (so larger ageDays == older).
func rec(id string, ageDays int) ExplanationRecord {
	return ExplanationRecord{
		ID:        id,
		DecidedAt: retentionBase.Add(-time.Duration(ageDays) * 24 * time.Hour),
	}
}

// sortedIDs returns a sorted copy so assertions are order-independent
// where only set membership matters.
func sortedIDs(ids []string) []string {
	out := append([]string(nil), ids...)
	sort.Strings(out)
	return out
}

func TestSelectExplanationsToPruneCurrentAlwaysKept(t *testing.T) {
	// e0 is current AND the oldest — without the current guard it would
	// be the prime prune candidate. It must survive.
	timeline := []ExplanationRecord{
		rec("e3", 1),
		rec("e2", 200),
		rec("e1", 300),
		rec("e0", 400),
	}
	policy := RetentionPolicy{KeepN: 1, MaxAge: 90 * 24 * time.Hour}

	got := SelectExplanationsToPrune(timeline, "e0", policy, retentionBase)
	for _, id := range got {
		if id == "e0" {
			t.Fatalf("current explanation e0 was selected for prune: %v", got)
		}
	}
	// e1 and e2 are beyond latest-1 and older than 90d → pruned; e3 is
	// latest-1 (kept), e0 is current (kept).
	want := []string{"e1", "e2"}
	if !reflect.DeepEqual(sortedIDs(got), want) {
		t.Fatalf("prune set = %v; want %v", sortedIDs(got), want)
	}
}

func TestSelectExplanationsToPruneLatestNAlwaysKept(t *testing.T) {
	// All rows are ancient (well beyond MaxAge), so only the latest-N
	// protection keeps anything.
	timeline := []ExplanationRecord{
		rec("e5", 500),
		rec("e4", 501),
		rec("e3", 502),
		rec("e2", 503),
		rec("e1", 504),
	}
	policy := RetentionPolicy{KeepN: 3, MaxAge: 90 * 24 * time.Hour}

	got := SelectExplanationsToPrune(timeline, "e5", policy, retentionBase)
	// Latest 3 by decided_at DESC are e5,e4,e3 → kept; e2,e1 pruned.
	want := []string{"e1", "e2"}
	if !reflect.DeepEqual(sortedIDs(got), want) {
		t.Fatalf("prune set = %v; want %v", sortedIDs(got), want)
	}
}

func TestSelectExplanationsToPruneNewerThanMaxAgeKeptBeyondN(t *testing.T) {
	// Ten rows, all within the last 9 days; KeepN=2 but MaxAge=90d means
	// the age window protects every row even though 8 are beyond N.
	var timeline []ExplanationRecord
	for i := 0; i < 10; i++ {
		timeline = append(timeline, rec(string(rune('a'+i)), i)) // 0..9 days old
	}
	policy := RetentionPolicy{KeepN: 2, MaxAge: 90 * 24 * time.Hour}

	got := SelectExplanationsToPrune(timeline, "a", policy, retentionBase)
	if len(got) != 0 {
		t.Fatalf("prune set = %v; want empty (all rows newer than MaxAge)", got)
	}
}

func TestSelectExplanationsToPruneOldBeyondNSelected(t *testing.T) {
	timeline := []ExplanationRecord{
		rec("new1", 1),   // latest-N
		rec("new2", 2),   // latest-N
		rec("old1", 100), // beyond N, older than 90d → prune
		rec("old2", 120), // beyond N, older than 90d → prune
	}
	policy := RetentionPolicy{KeepN: 2, MaxAge: 90 * 24 * time.Hour}

	got := SelectExplanationsToPrune(timeline, "new1", policy, retentionBase)
	want := []string{"old1", "old2"}
	if !reflect.DeepEqual(sortedIDs(got), want) {
		t.Fatalf("prune set = %v; want %v", sortedIDs(got), want)
	}
}

func TestSelectExplanationsToPruneEqualDecidedAtIDTiebreaker(t *testing.T) {
	// Four rows share the SAME decided_at. With KeepN=2, the latest-2 by
	// the (decided_at DESC, id ASC) order are the two lexicographically
	// smallest ids; the other two are pruned (and they are old enough).
	same := 200 // 200 days old, beyond MaxAge
	timeline := []ExplanationRecord{
		rec("d", same),
		rec("b", same),
		rec("a", same),
		rec("c", same),
	}
	policy := RetentionPolicy{KeepN: 2, MaxAge: 90 * 24 * time.Hour}

	got := SelectExplanationsToPrune(timeline, "a", policy, retentionBase)
	// id ASC keeps a,b in latest-2; prunes c,d.
	want := []string{"c", "d"}
	if !reflect.DeepEqual(sortedIDs(got), want) {
		t.Fatalf("prune set = %v; want %v (id ASC tiebreaker)", sortedIDs(got), want)
	}

	// Determinism: shuffle the input order, same result.
	shuffled := []ExplanationRecord{rec("c", same), rec("a", same), rec("d", same), rec("b", same)}
	got2 := SelectExplanationsToPrune(shuffled, "a", policy, retentionBase)
	if !reflect.DeepEqual(sortedIDs(got2), want) {
		t.Fatalf("shuffled prune set = %v; want %v (deterministic)", sortedIDs(got2), want)
	}
}

func TestSelectExplanationsToPruneIdempotent(t *testing.T) {
	timeline := []ExplanationRecord{
		rec("new", 1),
		rec("old1", 100),
		rec("old2", 200),
	}
	policy := RetentionPolicy{KeepN: 1, MaxAge: 90 * 24 * time.Hour}

	first := SelectExplanationsToPrune(timeline, "new", policy, retentionBase)
	pruned := map[string]bool{}
	for _, id := range first {
		pruned[id] = true
	}

	// Simulate the prune: remove selected rows, re-run, expect zero.
	var remaining []ExplanationRecord
	for _, r := range timeline {
		if !pruned[r.ID] {
			remaining = append(remaining, r)
		}
	}
	second := SelectExplanationsToPrune(remaining, "new", policy, retentionBase)
	if len(second) != 0 {
		t.Fatalf("second pass selected %v; want empty (idempotent)", second)
	}
}

func TestSelectExplanationsToPruneKeepNOne(t *testing.T) {
	// KeepN=1 keeps only the single newest; everything older (and past
	// MaxAge) is eligible unless it is the current pin.
	timeline := []ExplanationRecord{
		rec("newest", 1),
		rec("mid", 100),
		rec("oldest", 300),
	}
	policy := RetentionPolicy{KeepN: 1, MaxAge: 90 * 24 * time.Hour}

	got := SelectExplanationsToPrune(timeline, "newest", policy, retentionBase)
	want := []string{"mid", "oldest"}
	if !reflect.DeepEqual(sortedIDs(got), want) {
		t.Fatalf("prune set = %v; want %v", sortedIDs(got), want)
	}
}

func TestSelectExplanationsToPruneFailsClosedOnDegeneratePolicy(t *testing.T) {
	timeline := []ExplanationRecord{
		rec("a", 1),
		rec("b", 100),
		rec("c", 200),
	}
	cases := []struct {
		name   string
		policy RetentionPolicy
	}{
		{"keepN zero", RetentionPolicy{KeepN: 0, MaxAge: 90 * 24 * time.Hour}},
		{"keepN negative", RetentionPolicy{KeepN: -5, MaxAge: 90 * 24 * time.Hour}},
		{"maxAge zero", RetentionPolicy{KeepN: 1, MaxAge: 0}},
		{"maxAge negative", RetentionPolicy{KeepN: 1, MaxAge: -time.Hour}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SelectExplanationsToPrune(timeline, "a", tc.policy, retentionBase)
			if got != nil {
				t.Fatalf("degenerate policy %+v selected %v; want nil (fail closed)", tc.policy, got)
			}
		})
	}
}

func TestSelectExplanationsToPruneTimelineWithinKeepN(t *testing.T) {
	// Fewer rows than KeepN → nothing is beyond the latest-N protection.
	timeline := []ExplanationRecord{
		rec("a", 500),
		rec("b", 600),
	}
	policy := RetentionPolicy{KeepN: 10, MaxAge: 90 * 24 * time.Hour}

	got := SelectExplanationsToPrune(timeline, "a", policy, retentionBase)
	if got != nil {
		t.Fatalf("prune set = %v; want nil (timeline within KeepN)", got)
	}
}
