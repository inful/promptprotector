package encoders

import (
	"errors"
	"testing"
)

func TestBase64_DecodesKnownAscii(t *testing.T) {
	// "hello" base64-encoded with standard padding.
	got, err := Base64("aGVsbG8=")
	if err != nil {
		t.Fatalf("Base64(unexpected error: %v", err)
	}
	const want = "hello"
	if got != want {
		t.Errorf("Base64(aGVsbG8=) = %q, want %q", got, want)
	}
}

func TestBase64_DecodesUnicode(t *testing.T) {
	// "héllo" — exercises non-ASCII byte order through base64.
	got, err := Base64("aMOpbGxv")
	if err != nil {
		t.Fatalf("Base64(unexpected error: %v", err)
	}
	const want = "héllo"
	if got != want {
		t.Errorf("Base64(aMOpbGxv) = %q, want %q", got, want)
	}
}

func TestBase64_InvalidInputReturnsSentinel(t *testing.T) {
	// '!' and '-' are not in the base64 alphabet; padding is malformed.
	_, err := Base64("not-valid-base64!!!")
	if err == nil {
		t.Fatal("Base64(invalid) returned nil error, want sentinel")
	}
	if !errors.Is(err, ErrInvalidBase64) {
		t.Errorf("Base64(invalid) err = %v, want errors.Is(err, ErrInvalidBase64)", err)
	}
}
