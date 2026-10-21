package encoders

import (
	"errors"
	"testing"
)

func TestURL_DecodesSpaceAsPercent20(t *testing.T) {
	got, err := URL("hello%20world")
	if err != nil {
		t.Fatalf("URL(unexpected error: %v", err)
	}
	const want = "hello world"
	if got != want {
		t.Errorf("URL(hello%%20world) = %q, want %q", got, want)
	}
}

func TestURL_DecodesUnicode(t *testing.T) {
	// "héllo" = 0x68 0xc3 0xa9 0x6c 0x6c 0x6f -> "h%C3%A9llo".
	got, err := URL("h%C3%A9llo")
	if err != nil {
		t.Fatalf("URL(unexpected error: %v", err)
	}
	const want = "héllo"
	if got != want {
		t.Errorf("URL(h%%C3%%A9llo) = %q, want %q", got, want)
	}
}

func TestURL_PreservesPlusSign(t *testing.T) {
	// PathUnescape leaves '+' literal (only QueryUnescape maps '+' to ' ').
	// We use PathUnescape because '+' as space is form-encoded, not raw URL.
	got, err := URL("1+1=2")
	if err != nil {
		t.Fatalf("URL(unexpected error: %v", err)
	}
	const want = "1+1=2"
	if got != want {
		t.Errorf("URL(1+1=2) = %q, want %q", got, want)
	}
}

func TestURL_TruncatedEscapeReturnsSentinel(t *testing.T) {
	_, err := URL("abc%X")
	if !errors.Is(err, ErrInvalidURL) {
		t.Errorf("URL(abc%%X) err = %v, want errors.Is(err, ErrInvalidURL)", err)
	}
}

func TestURL_NonHexEscapeReturnsSentinel(t *testing.T) {
	_, err := URL("abc%ZZ")
	if !errors.Is(err, ErrInvalidURL) {
		t.Errorf("URL(abc%%ZZ) err = %v, want errors.Is(err, ErrInvalidURL)", err)
	}
}
