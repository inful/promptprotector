package encoders

import "testing"

func TestUnicodeEscape_DecodesBackslashU(t *testing.T) {
	// 'e' = U+0065.
	got := UnicodeEscape(`h\u0065llo`)
	const want = "hello"
	if got != want {
		t.Errorf("UnicodeEscape(h\\u0065llo) = %q, want %q", got, want)
	}
}

func TestUnicodeEscape_DecodesBackslashX(t *testing.T) {
	// 'e' = 0x65.
	got := UnicodeEscape(`h\x65llo`)
	const want = "hello"
	if got != want {
		t.Errorf("UnicodeEscape(h\\x65llo) = %q, want %q", got, want)
	}
}

func TestUnicodeEscape_DecodesMixedForms(t *testing.T) {
	// "hello" with each letter in a different escape style, mixed uppercase hex.
	got := UnicodeEscape(`\u0068\x65L\x6c\u006F`)
	const want = "heLlo"
	if got != want {
		t.Errorf("UnicodeEscape(mixed) = %q, want %q", got, want)
	}
}

func TestUnicodeEscape_DecodesAccentedChar(t *testing.T) {
	// 'é' = U+00E9 (encodes to 0xc3 0xa9 in UTF-8).
	got := UnicodeEscape(`h\u00e9llo`)
	const want = "héllo"
	if got != want {
		t.Errorf("UnicodeEscape(h\\u00e9llo) = %q, want %q", got, want)
	}
}

func TestUnicodeEscape_NoEscapesReturnsUnchanged(t *testing.T) {
	got := UnicodeEscape("hello world")
	const want = "hello world"
	if got != want {
		t.Errorf("UnicodeEscape(no-escapes) = %q, want %q", got, want)
	}
}

func TestUnicodeEscape_LeavesLoneBackslashAlone(t *testing.T) {
	// Lone '\n' is not an escape sequence we decode; \u and \x only.
	// 'n' is also hex-invalid as a 4-digit \u payload, so the regex skips it.
	got := UnicodeEscape(`back\slash`)
	const want = `back\slash`
	if got != want {
		t.Errorf("UnicodeEscape(bare-backslashes) = %q, want %q", got, want)
	}
}

func TestUnicodeEscape_LowercaseHexIsAccepted(t *testing.T) {
	got := UnicodeEscape(`\uabcd`)
	const want = "ꯍ" // U+ABCD
	if got != want {
		t.Errorf("UnicodeEscape(\\uabcd) = %q, want %q", got, want)
	}
}
