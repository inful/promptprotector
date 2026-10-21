package encoders

import (
	"errors"
	"testing"
)

func TestHex_DecodesKnownAscii(t *testing.T) {
	// "hello" -> "68656c6c6f" (5 bytes, 10 hex chars, RFC 4648 case-insensitive).
	got, err := Hex("68656c6c6f")
	if err != nil {
		t.Fatalf("Hex(unexpected error: %v", err)
	}
	const want = "hello"
	if got != want {
		t.Errorf("Hex(68656c6c6f) = %q, want %q", got, want)
	}
}

func TestHex_AcceptsUppercaseDigits(t *testing.T) {
	got, err := Hex("68656C6C6F")
	if err != nil {
		t.Fatalf("Hex(unexpected error: %v", err)
	}
	const want = "hello"
	if got != want {
		t.Errorf("Hex(68656C6C6F) = %q, want %q", got, want)
	}
}

func TestHex_DecodesUnicode(t *testing.T) {
	// "héllo" -> 0x68 0xc3 0xa9 0x6c 0x6c 0x6f -> "68c3a96c6c6f".
	got, err := Hex("68c3a96c6c6f")
	if err != nil {
		t.Fatalf("Hex(unexpected error: %v", err)
	}
	const want = "héllo"
	if got != want {
		t.Errorf("Hex(68c3a96c6c6f) = %q, want %q", got, want)
	}
}

func TestHex_OddLengthReturnsSentinel(t *testing.T) {
	_, err := Hex("abc")
	if !errors.Is(err, ErrInvalidHex) {
		t.Errorf("Hex(abc) err = %v, want errors.Is(err, ErrInvalidHex)", err)
	}
}

func TestHex_NonHexCharsReturnsSentinel(t *testing.T) {
	_, err := Hex("zz68656c6c6f")
	if !errors.Is(err, ErrInvalidHex) {
		t.Errorf("Hex(invalid) err = %v, want errors.Is(err, ErrInvalidHex)", err)
	}
}
