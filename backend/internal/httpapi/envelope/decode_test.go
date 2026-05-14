package envelope

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// decodeWith runs DecodeStrictOptionalJSON against an httptest
// request shaped from body. dst is reset on every call so each
// case's "decoded value" assertion is independent.
func decodeWith(t *testing.T, body string, dst any) error {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body))
	w := httptest.NewRecorder()
	return DecodeStrictOptionalJSON(w, req, dst)
}

type sampleBody struct {
	Name  string   `json:"name"`
	Items []string `json:"items"`
}

func TestDecodeStrictOptionalJSON_EmptyBodyAccepted(t *testing.T) {
	var got sampleBody
	if err := decodeWith(t, "", &got); err != nil {
		t.Fatalf("empty body returned %v; want nil", err)
	}
	if got.Name != "" || got.Items != nil {
		t.Errorf("empty body mutated dst: %#v; want zero value", got)
	}
}

func TestDecodeStrictOptionalJSON_ValidObjectAccepted(t *testing.T) {
	var got sampleBody
	if err := decodeWith(t, `{"name":"alice","items":["a","b"]}`, &got); err != nil {
		t.Fatalf("valid object returned %v; want nil", err)
	}
	if got.Name != "alice" {
		t.Errorf("Name = %q; want alice", got.Name)
	}
	if len(got.Items) != 2 || got.Items[0] != "a" || got.Items[1] != "b" {
		t.Errorf("Items = %#v; want [a b]", got.Items)
	}
}

func TestDecodeStrictOptionalJSON_ValidObjectWithTrailingWhitespaceAccepted(t *testing.T) {
	// json.Decoder treats trailing whitespace as benign; the second
	// Decode call still hits io.EOF.
	var got sampleBody
	if err := decodeWith(t, `{"name":"alice"}`+"\n  \t\r\n", &got); err != nil {
		t.Fatalf("trailing whitespace returned %v; want nil", err)
	}
	if got.Name != "alice" {
		t.Errorf("Name = %q; want alice", got.Name)
	}
}

func TestDecodeStrictOptionalJSON_MalformedJSONRejected(t *testing.T) {
	var got sampleBody
	err := decodeWith(t, `{"name":`, &got)
	if !errors.Is(err, ErrInvalidJSONBody) {
		t.Fatalf("err = %v; want ErrInvalidJSONBody", err)
	}
}

func TestDecodeStrictOptionalJSON_TrailingJSONObjectRejected(t *testing.T) {
	// Two valid objects in sequence: the first Decode succeeds but
	// the second Decode reads the second object instead of EOF.
	var got sampleBody
	err := decodeWith(t, `{"name":"alice"}{"name":"bob"}`, &got)
	if !errors.Is(err, ErrInvalidJSONBody) {
		t.Fatalf("err = %v; want ErrInvalidJSONBody (trailing object)", err)
	}
}

func TestDecodeStrictOptionalJSON_TrailingGarbageRejected(t *testing.T) {
	// Valid object followed by non-JSON garbage. The second Decode
	// returns a syntax error rather than io.EOF.
	var got sampleBody
	err := decodeWith(t, `{"name":"alice"} not-json`, &got)
	if !errors.Is(err, ErrInvalidJSONBody) {
		t.Fatalf("err = %v; want ErrInvalidJSONBody (trailing garbage)", err)
	}
}

func TestDecodeStrictOptionalJSON_OversizedBodyRejected(t *testing.T) {
	// Construct a body strictly larger than MaxJSONBodyBytes. The
	// content is well-formed JSON; the rejection is purely on size.
	big := strings.Repeat("x", MaxJSONBodyBytes+1)
	payload := `{"name":"` + big + `"}`
	if len(payload) <= MaxJSONBodyBytes {
		t.Fatalf("test setup bug: payload len %d not over cap %d",
			len(payload), MaxJSONBodyBytes)
	}
	var got sampleBody
	err := decodeWith(t, payload, &got)
	if !errors.Is(err, ErrInvalidJSONBody) {
		t.Fatalf("err = %v; want ErrInvalidJSONBody (oversize body)", err)
	}
}

func TestDecodeStrictOptionalJSON_BodyAtCapAccepted(t *testing.T) {
	// Defensive: a payload exactly AT the cap (not strictly over it)
	// must still parse. http.MaxBytesReader admits the boundary
	// byte; only strictly-over should fail. This guards against an
	// off-by-one regression in the helper.
	pad := MaxJSONBodyBytes - len(`{"name":""}`)
	if pad < 0 {
		t.Fatalf("test setup: cap %d smaller than envelope overhead", MaxJSONBodyBytes)
	}
	payload := `{"name":"` + strings.Repeat("x", pad) + `"}`
	if len(payload) != MaxJSONBodyBytes {
		t.Fatalf("test setup bug: payload len %d != cap %d", len(payload), MaxJSONBodyBytes)
	}
	var got sampleBody
	if err := decodeWith(t, payload, &got); err != nil {
		t.Errorf("body at cap returned %v; want nil", err)
	}
}
