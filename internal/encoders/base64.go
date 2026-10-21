package encoders

import (
	"encoding/base64"
	"errors"
)

// ErrInvalidBase64 is returned by Base64 when the input contains characters
// outside the standard base64 alphabet or has malformed padding. Callers
// should match with errors.Is rather than depending on the underlying
// base64.CorruptInputError type.
var ErrInvalidBase64 = errors.New("encoders: invalid base64 input")

// Base64 decodes a single base64-encoded string using the standard alphabet
// with padding. It is one of the L1 single-pass decoders composed by the
// normalize layer (see RecursiveDecode in recursive.go).
func Base64(s string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", errors.Join(ErrInvalidBase64, err)
	}
	return string(data), nil
}
