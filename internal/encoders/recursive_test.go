package encoders

import (
	"encoding/base64"
	"net/url"
	"reflect"
	"testing"
)

// makeWrapped builds a fixture by encoding innermost with the supplied
// functions in order (outermost first). Using stdlib for the encoding
// avoids hand-rolled base64 strings drifting out of sync with the
// actual encoding algorithm.
func makeWrapped(t *testing.T, innermost string, encoders ...func(string) string) string {
	t.Helper()
	s := innermost
	for i, enc := range encoders {
		next := enc(s)
		if next == s {
			t.Fatalf("makeWrapped: encoder %d was a no-op for %q", i, s)
		}
		s = next
	}
	return s
}

func TestRecursiveDecode_DepthZeroReturnsInputUnchanged(t *testing.T) {
	const input = "aGVsbG8="
	got, chain := RecursiveDecode(input, 0)
	if got != input {
		t.Errorf("RecursiveDecode(_, 0) = %q, want %q (unchanged)", got, input)
	}
	if len(chain) != 0 {
		t.Errorf("RecursiveDecode(_, 0) chain = %v, want empty", chain)
	}
}

func TestRecursiveDecode_SingleBase64Layer(t *testing.T) {
	// "aGVsbG8=" is "hello".
	got, chain := RecursiveDecode("aGVsbG8=", 3)
	const want = "hello"
	if got != want {
		t.Errorf("RecursiveDecode = %q, want %q", got, want)
	}
	wantChain := []string{"base64"}
	if !reflect.DeepEqual(chain, wantChain) {
		t.Errorf("RecursiveDecode chain = %v, want %v", chain, wantChain)
	}
}

func TestRecursiveDecode_DoubleLayerBase64OfURL(t *testing.T) {
	// Build the fixture from stdlib: b64(url("hello world")).
	// makeWrapped applies encoders inner-first, so [urlOf, b64Of] means
	// "URL wraps innermost, then b64 wraps that".
	urlOf := url.PathEscape
	b64Of := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	fixture := makeWrapped(t, "hello world", urlOf, b64Of)

	got, chain := RecursiveDecode(fixture, 3)
	const want = "hello world"
	if got != want {
		t.Errorf("RecursiveDecode(fixture) = %q, want %q", got, want)
	}
	wantChain := []string{"base64", "url"}
	if !reflect.DeepEqual(chain, wantChain) {
		t.Errorf("RecursiveDecode chain = %v, want %v", chain, wantChain)
	}
}

func TestRecursiveDecode_HexOuterBase64Inner(t *testing.T) {
	// b64(hex("hello")).
	hexOf := func(s string) string {
		const hex = "0123456789abcdef"
		out := make([]byte, 0, len(s)*2)
		for i := 0; i < len(s); i++ {
			c := s[i]
			out = append(out, hex[c>>4], hex[c&0xf])
		}
		return string(out)
	}
	b64Of := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	fixture := makeWrapped(t, "hello", hexOf, b64Of)

	got, chain := RecursiveDecode(fixture, 3)
	const want = "hello"
	if got != want {
		t.Errorf("RecursiveDecode(fixture) = %q, want %q", got, want)
	}
	wantChain := []string{"base64", "hex"}
	if !reflect.DeepEqual(chain, wantChain) {
		t.Errorf("RecursiveDecode chain = %v, want %v", chain, wantChain)
	}
}

func TestRecursiveDecode_PlainTextStaysUnrotated(t *testing.T) {
	// ROT13 is intentionally NOT in the L1 registry: it's a cipher, not
	// an encoding wrapper, and applying it to plain English would mangle
	// the input before L2 ever sees it.
	got, chain := RecursiveDecode("hello", 3)
	if got != "hello" {
		t.Errorf("RecursiveDecode(hello) = %q, want unchanged (no ROT13 in L1)", got)
	}
	if len(chain) != 0 {
		t.Errorf("RecursiveDecode(hello) chain = %v, want empty (no ROT13)", chain)
	}
}

func TestRecursiveDecode_Base64NotAppliedWithoutBase64Signals(t *testing.T) {
	// "Mz9i" — all base64-alphabet characters but encodes to "3?b"
	// (M=12, z=51, 9=61, i=34). After base64 fires once, the result
	// is not further decodable.
	got, chain := RecursiveDecode("Mz9i", 3)
	if got == "" {
		t.Fatal("RecursiveDecode(Mz9i) returned empty, want a base64-decoded result")
	}
	wantChain := []string{"base64"}
	if !reflect.DeepEqual(chain, wantChain) {
		t.Errorf("RecursiveDecode(Mz9i) chain = %v, want %v", chain, wantChain)
	}
}

func TestRecursiveDecode_DepthCapStopsAtOneRound(t *testing.T) {
	// 3-deep nested encoding: base64 -> base64 -> base64 ("aGVsbG8=" thrice nested).
	// depth=1 peeks just the outermost layer and stops, leaving a 2-deep
	// residual that the caller can opt to decode deeper if they want.
	got, chain := RecursiveDecode("YUdWc2JHOD0=", 1)
	const want = "aGVsbG8=" // result of decoding ONLY the outer layer
	if got != want {
		t.Errorf("RecursiveDecode(depth=1) = %q, want %q", got, want)
	}
	wantChain := []string{"base64"}
	if !reflect.DeepEqual(chain, wantChain) {
		t.Errorf("RecursiveDecode(depth=1) chain = %v, want %v (must cap at 1)", chain, wantChain)
	}
}

func TestRecursiveDecode_TwoDeepCapFullyDecodesThreeLayer(t *testing.T) {
	// Same 3-deep input, depth=2: two rounds of decoding lands on "hello".
	got, chain := RecursiveDecode("YUdWc2JHOD0=", 2)
	const want = "hello"
	if got != want {
		t.Errorf("RecursiveDecode(depth=2) = %q, want %q", got, want)
	}
	wantChain := []string{"base64", "base64"}
	if !reflect.DeepEqual(chain, wantChain) {
		t.Errorf("RecursiveDecode(depth=2) chain = %v, want %v", chain, wantChain)
	}
}

func TestRecursiveDecode_PlainTextStalls(t *testing.T) {
	got, chain := RecursiveDecode("hello world", 3)
	if got != "hello world" {
		t.Errorf("RecursiveDecode(plain) = %q, want unchanged", got)
	}
	if len(chain) != 0 {
		t.Errorf("RecursiveDecode(plain) chain = %v, want empty", chain)
	}
}

func TestRecursiveDecode_ChainOrderReflectsWrapOrder(t *testing.T) {
	// b64(hex("hello")). Decoding peels the outer wrapper first (b64),
	// then the inner (hex). The chain must record b64 before hex —
	// anything else means we're peeking in the wrong direction.
	// (NOTE: we use "hello" rather than "hi" because hex("hi") = "6869"
	// is exactly 4 chars and happens to be valid base64 input, which
	// would cause base64 to fire twice in a row. hex("hello") = 10 chars,
	// which base64 rejects on length, leaving only hex to fire.)
	hexOf := func(s string) string {
		const hex = "0123456789abcdef"
		out := make([]byte, 0, len(s)*2)
		for i := 0; i < len(s); i++ {
			c := s[i]
			out = append(out, hex[c>>4], hex[c&0xf])
		}
		return string(out)
	}
	b64Of := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	fixture := makeWrapped(t, "hello", hexOf, b64Of)

	got, chain := RecursiveDecode(fixture, 3)
	const want = "hello"
	if got != want {
		t.Errorf("RecursiveDecode(fixture) = %q, want %q", got, want)
	}
	wantChain := []string{"base64", "hex"}
	if !reflect.DeepEqual(chain, wantChain) {
		t.Errorf("RecursiveDecode chain = %v, want %v (outer first)", chain, wantChain)
	}
}
