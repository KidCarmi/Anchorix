//go:build perf

package perf

import "github.com/kidcarmi/anchorix/backend/internal/findings"

// defaultRules is a thin re-export of findings.DefaultRules so
// the test bodies above stay readable. Defined as a function
// (not a var) so it does not run at package init — the perf
// tier's process is short-lived and any init-time side effect
// would surface as silent setup cost.
func defaultRules() []findings.Rule {
	return findings.DefaultRules()
}
