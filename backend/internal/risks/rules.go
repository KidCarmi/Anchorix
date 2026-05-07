package risks

import (
	"context"

	"github.com/kidcarmi/anchorix/backend/internal/inventory"
)

// Rule evaluates a single certificate and returns zero or more findings.
// Rules MUST be pure: deterministic, side-effect free, no IO. The evaluator
// composes them; the rule itself only inspects inputs.
type Rule interface {
	ID() string
	Evaluate(ctx context.Context, c *inventory.Certificate) ([]Finding, error)
}

// Registry is the read-only set of rules the evaluator runs. New rules are
// registered at startup; nothing dynamically loads code at runtime in v0.1.
type Registry struct {
	rules []Rule
}

// NewRegistry returns an empty registry. Rules are added with Register.
func NewRegistry() *Registry { return &Registry{} }

// Register adds a rule. Calling Register after the evaluator is running is
// a programmer error; do all registration during composition root setup.
func (r *Registry) Register(rule Rule) { r.rules = append(r.rules, rule) }

// Rules returns the registered rules in registration order.
func (r *Registry) Rules() []Rule { return r.rules }
