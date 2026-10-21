package encoders

import (
	"errors"
	"net/url"
)

// ErrInvalidURL is returned by URL when the input contains a malformed
// percent-escape (truncated or non-hex). Callers match with errors.Is.
var ErrInvalidURL = errors.New("encoders: invalid URL escape")

// URL decodes a single percent-encoded string. We use net/url.PathUnescape
// rather than QueryUnescape so '+' is preserved as a literal — '+' becomes
// a space only in form-encoded payloads, and untrusted text is too
// ambiguous to make that decision for the caller.
func URL(s string) (string, error) {
	data, err := url.PathUnescape(s)
	if err != nil {
		return "", errors.Join(ErrInvalidURL, err)
	}
	return data, nil
}
