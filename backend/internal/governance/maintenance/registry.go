package maintenance

import (
	"errors"
	"fmt"
	"sort"
)

// ErrUnknownJob is returned by JobRegistry.Lookup when no registered job
// matches the requested name. Callers fail closed on it: a persisted
// scheduler-state row whose job_name has no registry entry is inert and
// never executed (B4 design §6.4 — orphan job rows).
var ErrUnknownJob = errors.New("maintenance: unknown job")

// JobRegistry is the immutable set of registered jobs, built ONCE at
// composition time and never mutated afterward (CLAUDE.md §8.8 / §19 —
// no runtime registration, no hidden global state). Lookups are the
// only post-construction operation.
type JobRegistry struct {
	jobs map[string]Job
}

// NewJobRegistry builds the registry from the supplied jobs. It rejects:
//   - a nil job,
//   - a job with an empty Name(),
//   - duplicate job names.
//
// Construction is the only place jobs enter the registry; there is no
// Register method, so the set is immutable for the process lifetime.
//
// In B4 PR-2 the composition root passes NO real jobs (the scheduler is
// not wired); tests pass fakes. The real H-029 / H-027 adapters are
// registered in PR-3 / PR-4.
func NewJobRegistry(jobs ...Job) (*JobRegistry, error) {
	m := make(map[string]Job, len(jobs))
	for i, j := range jobs {
		if j == nil {
			return nil, fmt.Errorf("maintenance.NewJobRegistry: job at index %d is nil", i)
		}
		name := j.Name()
		if name == "" {
			return nil, fmt.Errorf("maintenance.NewJobRegistry: job at index %d has empty name", i)
		}
		if _, dup := m[name]; dup {
			return nil, fmt.Errorf("maintenance.NewJobRegistry: duplicate job name %q", name)
		}
		m[name] = j
	}
	return &JobRegistry{jobs: m}, nil
}

// Lookup returns the registered job for name, or ErrUnknownJob. Fail
// closed: an unknown name never resolves to a job, so an orphaned
// scheduler-state row cannot execute arbitrary or stale behavior.
func (r *JobRegistry) Lookup(name string) (Job, error) {
	j, ok := r.jobs[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownJob, name)
	}
	return j, nil
}

// Names returns the registered job names in deterministic (sorted)
// order. Used by the composition root to seed scheduler-state rows and
// by tests; the sort makes the set reproducible (CLAUDE.md §7.6).
func (r *JobRegistry) Names() []string {
	names := make([]string, 0, len(r.jobs))
	for name := range r.jobs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
