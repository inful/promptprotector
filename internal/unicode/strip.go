package unicode

import "strings"

// Strip returns s with the characters this package detects removed or
// folded: zero-width and bidi-control characters are deleted outright,
// and homoglyphs are replaced by the Latin letter they impersonate.
//
// This exists because detecting an obfuscation character is not the same
// as defeating it. The L2 ruleset matches literal ASCII, so "instructi"
// + U+200B + "ons" trips the zero-width detector and then sails past every
// rule. Handing L2 the stripped form is what closes that gap.
//
// strings.Map allocates nothing and returns s unchanged when no rune
// differs, so the common clean-input case costs one scan and no memory.
func Strip(s string) string {
	return strings.Map(func(r rune) rune {
		if zeroWidthChars[r] || rtlControlChars[r] {
			return -1 // strings.Map drops negative results
		}
		if latin, ok := homoglyphs[r]; ok {
			return latin
		}
		return r
	}, s)
}
