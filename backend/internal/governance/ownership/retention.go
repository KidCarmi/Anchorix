package ownership

import (
	"sort"
	"time"
)

// RetentionPolicy is the validated H-027 explanation-retention policy.
//
// It expresses the hybrid rule from the H-027 design: per certificate,
// keep the latest KeepN explanations OR any explanation newer than
// MaxAge, and prune only the rows that fall outside BOTH protections.
// The certificate's current (FK-pinned) explanation is never prunable.
//
// The policy carries no I/O: it is the parameter object the pure
// selector below consumes. Config (internal/config) validates the
// bounds at startup (KeepN >= 1, MaxAge >= 24h); the selector applies a
// fail-closed guard of its own so a degenerate policy prunes nothing
// rather than over-deleting.
type RetentionPolicy struct {
	// KeepN is the minimum number of most-recent explanations retained
	// per certificate, regardless of age.
	KeepN int
	// MaxAge is the age beyond which an explanation becomes eligible for
	// pruning — but only if it is also beyond KeepN. Measured against the
	// caller-supplied "now".
	MaxAge time.Duration
}

// ExplanationRecord is the minimal projection of an
// ownership_match_explanations row the retention selector needs: the
// row id and when its decision was recorded. The selector takes a
// certificate's timeline as a slice of these plus the id of the
// certificate's current (FK-pinned) explanation, which is supplied
// separately and never pruned.
//
// Deliberately not the full governance.OwnershipMatchExplanation: the
// selection decision depends only on (id, decided_at) and the current
// pin, so a narrow input keeps the logic pure and trivially testable.
type ExplanationRecord struct {
	ID        string
	DecidedAt time.Time
}

// SelectExplanationsToPrune returns the ids of explanations eligible for
// deletion from a SINGLE certificate's timeline under the hybrid policy.
//
// An explanation is pruned only when ALL of the following hold:
//   - it is not the certificate's current (FK-pinned) explanation;
//   - it is beyond the latest KeepN (ordered decided_at DESC, id ASC);
//   - its decided_at is strictly older than now-MaxAge.
//
// Everything else is retained: the current explanation, the latest
// KeepN, and anything newer than MaxAge (even beyond KeepN).
//
// The input need not be pre-sorted — a copy is sorted deterministically
// (decided_at DESC, then id ASC as the stable tiebreaker for equal
// timestamps), matching the B3A explanation-timeline ordering so "the
// latest N this keeps" equals "the first N the timeline read returns".
// Output ids are returned newest-first, so the result is deterministic
// for a fixed (timeline, currentExplanationID, policy, now). Re-running
// over an already-pruned timeline selects nothing (idempotent).
//
// Fail-closed: a degenerate policy (KeepN < 1 or MaxAge <= 0) selects
// nothing rather than risk over-deletion. Config validation makes this
// unreachable in production; it is defensive depth.
func SelectExplanationsToPrune(timeline []ExplanationRecord, currentExplanationID string, policy RetentionPolicy, now time.Time) []string {
	if policy.KeepN < 1 || policy.MaxAge <= 0 {
		return nil
	}
	if len(timeline) <= policy.KeepN {
		// Nothing is beyond the latest-N protection.
		return nil
	}

	ordered := make([]ExplanationRecord, len(timeline))
	copy(ordered, timeline)
	sort.Slice(ordered, func(i, j int) bool {
		if !ordered[i].DecidedAt.Equal(ordered[j].DecidedAt) {
			return ordered[i].DecidedAt.After(ordered[j].DecidedAt)
		}
		return ordered[i].ID < ordered[j].ID
	})

	cutoff := now.Add(-policy.MaxAge)

	var prune []string
	for index, record := range ordered {
		if index < policy.KeepN {
			continue // within latest-N: always kept
		}
		if record.ID == currentExplanationID {
			continue // current explanation: never pruned
		}
		if !record.DecidedAt.Before(cutoff) {
			continue // newer than (or exactly at) MaxAge: kept
		}
		prune = append(prune, record.ID)
	}
	return prune
}
