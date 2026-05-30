package ownership

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestStreamAndDecideHasNoLegacyMergeShape is a static regression
// guard for the H-030 PR-1 refactor: streamAndDecide's executable
// body must NOT contain the legacy two-stream merge tokens, and it
// MUST contain the new per-page set-lookup tokens. If a future PR
// reintroduces the old merge — even silently — this check fails in
// CI's `go test ./...` phase, long before any integration test could
// catch a cross-language ordering regression on a fixture that
// happened to dodge it.
//
// The check is scoped to streamAndDecide's BODY (between its opening
// `{` and matching closing `}`), not to the file at large — the new
// godoc on streamAndDecide intentionally references the legacy
// `ownCur.CertificateID < sig.CertificateID` shape to explain what
// was replaced and why, and that godoc reference is correct and
// desirable. The body-only scope keeps the assertion focused on
// executable code.
func TestStreamAndDecideHasNoLegacyMergeShape(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed; cannot locate source file")
	}
	sourcePath := filepath.Join(filepath.Dir(thisFile), "recompute.go")
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read %s: %v", sourcePath, err)
	}
	body := extractFunctionBody(t, string(source), "func (s *Service) streamAndDecide(")

	forbidden := []string{
		// Legacy two-stream merge comparator
		"ownCur.CertificateID",
		// Legacy second-stream pager and its generic shape
		"ownPager",
		"pager[governance.CertificateOwnership]",
		// Legacy direct paged-ownership reader (the new B3A read path
		// uses this method, but streamAndDecide must not).
		"ListCertificateOwnershipPaged",
	}
	for _, needle := range forbidden {
		if strings.Contains(body, needle) {
			t.Fatalf("forbidden legacy-merge token %q present in streamAndDecide body; H-030 PR-1 refactor removed the Go-side ordered merge — reintroducing it would silently re-couple correctness to PostgreSQL collation", needle)
		}
	}

	required := []string{
		// The new bounded set-lookup primitive must drive prior-ownership.
		"GetCertificateOwnershipByCertificateIDs",
		// The signal page is the driver of the loop.
		"ListCertificateSignalsPaged",
	}
	for _, needle := range required {
		if !strings.Contains(body, needle) {
			t.Fatalf("required H-030 token %q missing from streamAndDecide body; the post-refactor shape must drive prior-ownership through the bounded set lookup", needle)
		}
	}
}

// extractFunctionBody returns the substring between the opening `{`
// after the given function signature and its matching closing `}`.
// Brace-counting is naive (no string-literal / comment awareness)
// because Go source for streamAndDecide does not contain `{` / `}`
// inside literals; if a future refactor introduces them, this helper
// should be replaced with a `go/parser`-based extractor.
func extractFunctionBody(t *testing.T, src, signature string) string {
	t.Helper()
	start := strings.Index(src, signature)
	if start < 0 {
		t.Fatalf("function signature %q not found", signature)
	}
	openIdx := strings.Index(src[start:], "{")
	if openIdx < 0 {
		t.Fatalf("opening brace not found after %q", signature)
	}
	openIdx += start
	depth := 0
	for i := openIdx; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[openIdx : i+1]
			}
		}
	}
	t.Fatalf("matching close brace not found for %q", signature)
	return ""
}
