package httpapi

import (
	"context"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/httpapi/envelope"
)

// Probe is a readiness check. It MUST be cheap, side-effect free, and
// honor ctx cancellation. A non-nil error means the dependency is not
// ready and the process should be considered unready as a whole.
type Probe func(ctx context.Context) error

// Readiness is a registry of named Probes evaluated by the /readyz handler.
//
// /readyz returns 200 only if every registered probe returns nil within
// the per-probe timeout. With no probes registered the process reports
// ready — that is the expected state at boot before storage is wired in.
// Once Phase 1 lands a DB ping probe, /readyz will fail closed if the DB
// is unreachable.
type Readiness struct {
	mu      sync.RWMutex
	probes  map[string]Probe
	timeout time.Duration
}

// NewReadiness returns an empty registry with a sensible probe timeout.
func NewReadiness() *Readiness {
	return &Readiness{
		probes:  make(map[string]Probe),
		timeout: 2 * time.Second,
	}
}

// Register adds or replaces a probe. Names should be short and stable
// (e.g. "postgres"). Calling Register concurrently with the handler is safe.
func (r *Readiness) Register(name string, p Probe) {
	if name == "" || p == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.probes[name] = p
}

// snapshot returns the registered probes in deterministic order.
func (r *Readiness) snapshot() []probeEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]probeEntry, 0, len(r.probes))
	for name, p := range r.probes {
		out = append(out, probeEntry{name: name, probe: p})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

type probeEntry struct {
	name  string
	probe Probe
}

// handler returns the /readyz HTTP handler.
func (r *Readiness) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		results := make(map[string]string, 4)
		ready := true
		for _, e := range r.snapshot() {
			ctx, cancel := context.WithTimeout(req.Context(), r.timeout)
			err := e.probe(ctx)
			cancel()
			if err != nil {
				ready = false
				results[e.name] = "error: " + err.Error()
				continue
			}
			results[e.name] = "ok"
		}
		status := http.StatusOK
		body := map[string]any{"status": "ready", "checks": results}
		if !ready {
			status = http.StatusServiceUnavailable
			body["status"] = "unready"
		}
		envelope.WriteJSON(w, status, body)
	}
}
