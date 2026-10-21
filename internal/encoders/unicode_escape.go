package encoders

import (
	"regexp"
	"strconv"
)

// unicodeEscapeRE matches \uXXXX (4 hex digits) or \xXX (2 hex digits).
// Other backslash sequences (e.g. "\n", "\t") are intentionally NOT
// decoded — the L1 layer cares about Unicode code points, not C-style
// escape tables.
var unicodeEscapeRE = regexp.MustCompile(`\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})`)

// UnicodeEscape replaces every \uXXXX and \xXX escape sequence in s with
// the corresponding UTF-8 character. Inputs without any escapes are
// returned unchanged. The function is total on its domain, so it does
// not return an error.
func UnicodeEscape(s string) string {
	return unicodeEscapeRE.ReplaceAllStringFunc(s, func(match string) string {
		// ReplaceAllStringFunc re-runs a FindStringSubmatch on each match;
		// matches are short (always <= 6 chars) so the overhead is trivial.
		sub := unicodeEscapeRE.FindStringSubmatch(match)
		hex := sub[1]
		if hex == "" {
			hex = sub[2]
		}
		n, _ := strconv.ParseUint(hex, 16, 32) // regex constrains digits; ParseUint cannot fail.
		return string(rune(n))
	})
}
