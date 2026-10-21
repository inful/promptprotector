package encoders

import (
	"encoding/hex"
	"errors"
)

// ErrInvalidHex is returned by Hex when the input has odd length or contains
// non-hex characters. Callers match with errors.Is.
var ErrInvalidHex = errors.New("encoders: invalid hex input")

// Hex decodes a single hex-encoded string (RFC 4648, base16). Hex digits
// may be upper- or lower-case; length must be even. The "0x" prefix is
// not accepted here — callers strip it before invocation.
func Hex(s string) (string, error) {
	data, err := hex.DecodeString(s)
	if err != nil {
		return "", errors.Join(ErrInvalidHex, err)
	}
	return string(data), nil
}
