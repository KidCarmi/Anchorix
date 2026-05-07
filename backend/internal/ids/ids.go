// Package ids generates opaque identifiers for domain entities.
//
// We deliberately keep the format opaque so that we can swap the underlying
// implementation (UUIDv7, ULID, etc.) without rippling changes through the
// rest of the codebase.
package ids

import (
	"crypto/rand"
	"encoding/hex"
)

// New returns a 128-bit random identifier encoded as 32 hex characters.
// In Phase 1 this will be replaced with UUIDv7 for time-ordering, but the
// public API (a stable opaque string) will not change.
func New() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
