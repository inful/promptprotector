package encoders

import "testing"

func TestROT13_ShiftsLowercase(t *testing.T) {
	got := ROT13("hello")
	const want = "uryyb"
	if got != want {
		t.Errorf("ROT13(hello) = %q, want %q", got, want)
	}
}

func TestROT13_ShiftsUppercase(t *testing.T) {
	got := ROT13("HELLO")
	const want = "URYYB"
	if got != want {
		t.Errorf("ROT13(HELLO) = %q, want %q", got, want)
	}
}

func TestROT13_PreservesMixedCase(t *testing.T) {
	// ROT13 is case-preserving: 'H' rotates in the uppercase band, 'e' in the lowercase band.
	got := ROT13("Hello")
	const want = "Uryyb"
	if got != want {
		t.Errorf("ROT13(Hello) = %q, want %q", got, want)
	}
}

func TestROT13_PreservesNonLetters(t *testing.T) {
	got := ROT13("h3ll0!@#")
	const want = "u3yy0!@#"
	if got != want {
		t.Errorf("ROT13(h3ll0!@#) = %q, want %q", got, want)
	}
}

func TestROT13_RoundTrip(t *testing.T) {
	// ROT13 is its own inverse (13 = 26-13, so two applications = identity).
	originals := []string{"", "hello", "Hello, World!", "noon", "AbCdEfGhIjK"}
	for _, s := range originals {
		got := ROT13(ROT13(s))
		if got != s {
			t.Errorf("ROT13(ROT13(%q)) = %q, want identity", s, got)
		}
	}
}

func TestROT13_HandlesUnicode(t *testing.T) {
	// Unicode runes pass through unchanged (ROT13 is a Latin-only cipher).
	got := ROT13("héllo")
	const want = "uéyyb"
	if got != want {
		t.Errorf("ROT13(héllo) = %q, want %q", got, want)
	}
}
