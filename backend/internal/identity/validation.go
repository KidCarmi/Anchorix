package identity

import (
	"fmt"
	"strings"
)

// slug validation policy:
//
//   - lowercase ASCII letters [a-z], digits [0-9], and hyphens '-'
//   - length 1..maxSlugLen
//   - MUST start with a letter or digit
//   - MUST NOT end with a hyphen
//   - MUST NOT contain consecutive hyphens
//
// The shape mirrors common naming conventions (DNS labels,
// container image tags) while staying strict enough that the
// engine's tag/service references can be quoted in audit
// metadata without further escaping.
const maxSlugLen = 64

// validateSlug returns ErrInvalidInput (wrapped with field
// context) when s violates the slug policy.
func validateSlug(field, s string) error {
	if s == "" {
		return fmt.Errorf("%w: %s required", ErrInvalidInput, field)
	}
	if len(s) > maxSlugLen {
		return fmt.Errorf("%w: %s must be <= %d bytes", ErrInvalidInput, field, maxSlugLen)
	}
	if !isSlugChar(s[0]) || s[0] == '-' {
		return fmt.Errorf("%w: %s must start with [a-z0-9]", ErrInvalidInput, field)
	}
	if s[len(s)-1] == '-' {
		return fmt.Errorf("%w: %s must not end with '-'", ErrInvalidInput, field)
	}
	prevHyphen := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isSlugChar(c) {
			return fmt.Errorf("%w: %s contains invalid character %q", ErrInvalidInput, field, c)
		}
		if c == '-' {
			if prevHyphen {
				return fmt.Errorf("%w: %s must not contain consecutive '--'", ErrInvalidInput, field)
			}
			prevHyphen = true
		} else {
			prevHyphen = false
		}
	}
	return nil
}

// isSlugChar reports whether c is a valid slug character. The
// policy is intentionally narrower than a permissive [\w-]
// regex — we want the same byte set to round-trip cleanly
// across audit JSON, URL paths, and SQL parameters.
func isSlugChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '-':
		return true
	}
	return false
}

// Length caps for free-form text fields. Lower than
// MaxOverrideReasonLength (1000) — these are operator-facing
// metadata, not policy reasons.
const (
	maxDisplayNameLen = 200
	maxDescriptionLen = 1000
	maxTagKeyLen      = 100
	maxTagValueLen    = 200
	maxOwnerEmailLen  = 320
	maxOwnerTeamLen   = 200
	maxBusinessUnit   = 200
	maxTargetIDLen    = 100
)

// validateNonEmptyBounded validates a required free-form text
// field with a length cap. The trim happens up the call stack;
// this checks the already-trimmed value.
func validateNonEmptyBounded(field, s string, maxLen int) error {
	if strings.TrimSpace(s) == "" {
		return fmt.Errorf("%w: %s required", ErrInvalidInput, field)
	}
	if len(s) > maxLen {
		return fmt.Errorf("%w: %s must be <= %d bytes", ErrInvalidInput, field, maxLen)
	}
	return nil
}

// validateBounded validates an optional free-form text field
// against its length cap. Empty strings are accepted.
func validateBounded(field, s string, maxLen int) error {
	if len(s) > maxLen {
		return fmt.Errorf("%w: %s must be <= %d bytes", ErrInvalidInput, field, maxLen)
	}
	return nil
}

// validateTagKey validates the tag key (a slug-shaped
// identifier — tag keys appear inside ownership-rule
// match_value strings like `tag:env=prod`, so the same byte
// set rules apply).
func validateTagKey(s string) error {
	if s == "" {
		return fmt.Errorf("%w: key required", ErrInvalidInput)
	}
	if len(s) > maxTagKeyLen {
		return fmt.Errorf("%w: key must be <= %d bytes", ErrInvalidInput, maxTagKeyLen)
	}
	// Tag keys reuse the slug character set.
	for i := 0; i < len(s); i++ {
		if !isSlugChar(s[i]) {
			return fmt.Errorf("%w: key contains invalid character %q", ErrInvalidInput, s[i])
		}
	}
	return nil
}

// validateTagValue validates the tag value. Values are more
// permissive than keys — they may be empty (the tag acts as a
// boolean flag), and may contain characters beyond the slug
// alphabet (e.g. `env=prod` style values). We still cap the
// length so audit metadata can quote values without overflow,
// and we reject newlines / control characters so they can't
// poison log lines or audit JSON.
func validateTagValue(s string) error {
	if len(s) > maxTagValueLen {
		return fmt.Errorf("%w: value must be <= %d bytes", ErrInvalidInput, maxTagValueLen)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			return fmt.Errorf("%w: value contains control character", ErrInvalidInput)
		}
	}
	return nil
}

// validateReason validates the operator-supplied disable /
// clear reason string. Required, trimmed, bounded.
const maxReasonLen = 1000

func validateReason(field, s string) error {
	t := strings.TrimSpace(s)
	if t == "" {
		return fmt.Errorf("%w: %s required", ErrInvalidInput, field)
	}
	if len(t) > maxReasonLen {
		return fmt.Errorf("%w: %s must be <= %d bytes", ErrInvalidInput, field, maxReasonLen)
	}
	return nil
}

// validateTargetType verifies the polymorphic target_type
// matches one of the documented enum values. The DB CHECK
// constraint enforces the same set; this is the service-layer
// front door so bad inputs fail with a clear error before any
// query.
func validateTargetType(t TagTargetType) error {
	switch t {
	case TagTargetCertificate, TagTargetAgent, TagTargetService,
		TagTargetServiceGroup, TagTargetAgentGroup:
		return nil
	}
	return fmt.Errorf("%w: unknown target_type %q", ErrInvalidInput, t)
}

// validateTargetID validates the polymorphic target_id string
// (length + non-empty + no control chars).
func validateTargetID(s string) error {
	if s == "" {
		return fmt.Errorf("%w: target_id required", ErrInvalidInput)
	}
	if len(s) > maxTargetIDLen {
		return fmt.Errorf("%w: target_id must be <= %d bytes", ErrInvalidInput, maxTargetIDLen)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			return fmt.Errorf("%w: target_id contains control character", ErrInvalidInput)
		}
	}
	return nil
}
