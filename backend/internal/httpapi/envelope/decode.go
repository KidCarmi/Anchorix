package envelope

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// MaxJSONBodyBytes is the cap applied to every request body parsed
// through DecodeStrictOptionalJSON. Matches the per-site limit that
// was previously duplicated across handlers
// (heartbeat / inventory / revoke). 64 KiB is comfortably above the
// shapes the documented endpoints accept; oversize bodies surface
// as ErrInvalidJSONBody.
const MaxJSONBodyBytes = 1 << 16

// ErrInvalidJSONBody is returned by DecodeStrictOptionalJSON when
// the request body cannot be parsed as a single complete JSON
// value. Specific causes include:
//
//   - malformed JSON,
//   - trailing JSON or trailing garbage after the first JSON value,
//   - reader-level failure (oversize body via MaxBytesReader, etc.).
//
// The sentinel is intentionally generic. Callers map it to the
// canonical 400 bad_request envelope — handlers MUST NOT echo raw
// parser errors to the wire (CLAUDE.md §6: deterministic behavior /
// no enumeration via error messages).
var ErrInvalidJSONBody = errors.New("envelope: invalid JSON body")

// DecodeStrictOptionalJSON parses an OPTIONAL single JSON object
// from r.Body into dst. It is the canonical body-decoding helper
// for handlers whose request body is either:
//
//   - empty (every field optional; an empty body is a valid request), or
//   - exactly one complete JSON value, with no trailing JSON or garbage.
//
// Behavior contract:
//
//   - Body size is capped at MaxJSONBodyBytes (64 KiB) via
//     http.MaxBytesReader. Exceeding the cap surfaces as
//     ErrInvalidJSONBody.
//   - An empty body (Content-Length: 0, or chunked transfer with no
//     payload) leaves *dst at its zero value and returns nil.
//   - A single valid JSON value populates *dst and returns nil.
//   - Malformed JSON returns ErrInvalidJSONBody.
//   - Trailing JSON or trailing garbage after the first value
//     returns ErrInvalidJSONBody.
//
// The helper does NOT write the response envelope. Callers handle
// ErrInvalidJSONBody by writing the canonical 400 bad_request
// envelope themselves so each handler keeps explicit control over
// its response shape.
//
// Why a second Decode (not dec.More): net/http does not validate
// that the body terminates after the first JSON value. dec.More
// reports remaining elements WITHIN an open array/object, not
// top-level trailing data. The only way to assert "exactly one
// value, then EOF" is to call Decode again and check that it
// returns io.EOF.
//
// The w argument is consumed by http.MaxBytesReader, which uses it
// to signal request-body limits back to net/http; this helper
// itself never writes a response.
func DecodeStrictOptionalJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	return DecodeStrictJSONWithLimit(w, r, dst, MaxJSONBodyBytes)
}

// DecodeStrictJSONWithLimit is the size-configurable variant of
// DecodeStrictOptionalJSON for endpoints whose payload legitimately
// exceeds the default 64 KiB cap — currently only certificate
// ingestion (CERTIFICATE_INVENTORY.md §4 documents up to 4 MiB
// for a batch of hundreds of certs × multi-KiB PEMs).
//
// The single behavior delta is `maxBytes`: callers pass the cap
// their endpoint enforces. Everything else (empty-body OK,
// single-object, second-Decode-must-EOF, ErrInvalidJSONBody on
// failure) is identical to DecodeStrictOptionalJSON.
//
// maxBytes MUST be positive; a zero or negative value is a caller
// bug. Pass via a named constant (e.g.
// inventory.MaxCertificateBatchBodyBytes) rather than a magic
// number at the call site.
func DecodeStrictJSONWithLimit(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBytes))
	if err := dec.Decode(dst); err != nil && !errors.Is(err, io.EOF) {
		return ErrInvalidJSONBody
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalidJSONBody
	}
	return nil
}
