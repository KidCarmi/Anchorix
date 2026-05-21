package fixtures

import (
	"testing"
)

// TestKeyPoolWeakBitsServedFromEmbeddedKey pins the H-024A
// post-hardening contract: when `keyPool.at` is asked for a
// sub-2048-bit key, the implementation MUST short-circuit to
// `loadFixtureWeakRSAKey` rather than calling
// `rsa.GenerateKey(_, bits)`. Without this guard the
// `weak_rsa_key` fixture bucket would call
// `rsa.GenerateKey(_, 1024)` at runtime, re-introducing the
// CodeQL `go/weak-cryptographic-key` alert this hardening pass
// resolved at the source.
//
// The test asserts the short-circuit via the side effect:
// every weak-bits call returns the SAME cached `*rsa.PrivateKey`
// (because the embedded key is parsed once and shared), whereas
// strong-bits calls return DIFFERENT keys from the pool.
func TestKeyPoolWeakBitsServedFromEmbeddedKey(t *testing.T) {
	pool := newKeyPool()

	// Two weak-bits calls with different `i` indices must
	// return the same key pointer — the embedded key is shared
	// across all weak-bits requests.
	weak0, err := pool.at(1024, 0)
	if err != nil {
		t.Fatalf("pool.at(1024, 0): %v", err)
	}
	weak1, err := pool.at(1024, 999)
	if err != nil {
		t.Fatalf("pool.at(1024, 999): %v", err)
	}
	if weak0 != weak1 {
		t.Errorf("weak-bits calls returned different keys; want shared embedded key")
	}
	if got := weak0.N.BitLen(); got != 1024 {
		t.Errorf("embedded weak key bit length = %d, want 1024", got)
	}

	// Strong-bits calls return distinct keys from the pool
	// (one per pool index). Two different `i` values must
	// produce two different keys; same `i` returns the same.
	strong0a, err := pool.at(2048, 0)
	if err != nil {
		t.Fatalf("pool.at(2048, 0): %v", err)
	}
	strong0b, err := pool.at(2048, 0)
	if err != nil {
		t.Fatalf("pool.at(2048, 0) repeat: %v", err)
	}
	if strong0a != strong0b {
		t.Errorf("same (bits, i) pool slot returned different keys")
	}
	strong1, err := pool.at(2048, 1)
	if err != nil {
		t.Fatalf("pool.at(2048, 1): %v", err)
	}
	if strong0a == strong1 {
		t.Errorf("different pool slots returned the same key — pool is degenerate")
	}
	if got := strong0a.N.BitLen(); got != 2048 {
		t.Errorf("strong key bit length = %d, want 2048", got)
	}
}

// TestLoadFixtureWeakRSAKeyParses checks that the embedded
// PKCS#1 DER const decodes and parses cleanly, isolated from
// the keyPool. If the const ever gets corrupted (truncated,
// re-encoded, hand-edited), this test fails fast with a clear
// "embedded key" message rather than surfacing as a generic
// keyPool error deep inside a perf or stress run.
func TestLoadFixtureWeakRSAKeyParses(t *testing.T) {
	key, err := loadFixtureWeakRSAKey()
	if err != nil {
		t.Fatalf("loadFixtureWeakRSAKey: %v", err)
	}
	if key == nil {
		t.Fatal("loadFixtureWeakRSAKey returned nil key without error")
	}
	if got := key.N.BitLen(); got != 1024 {
		t.Errorf("embedded key bit length = %d, want 1024", got)
	}
	// Second call must return the same pointer — the
	// sync.Once-guarded parse cache is the contract.
	again, err := loadFixtureWeakRSAKey()
	if err != nil {
		t.Fatalf("loadFixtureWeakRSAKey (cached): %v", err)
	}
	if again != key {
		t.Error("loadFixtureWeakRSAKey returned a different pointer on second call; sync.Once cache broken")
	}
}
