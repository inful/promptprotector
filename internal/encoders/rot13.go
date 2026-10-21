package encoders

// ROT13 applies the ROT13 letter substitution to s. ROT13 is its own
// inverse (shifting by 13 of 26 letters), so applying it twice returns
// the original. Unicode runes outside [A-Za-z] pass through unchanged.
//
// Unlike the Base64/Hex/URL decoders, ROT13 cannot fail: every input is
// a valid ROT13 string of itself. The signature intentionally returns
// only a string so callers don't paper over a never-error channel.
// Recursive-descent callers (see encode.go) treat it specially.
func ROT13(s string) string {
	runes := []rune(s) // explicit rune slice so multi-byte runes are indexed correctly
	for i, r := range runes {
		switch {
		case r >= 'A' && r <= 'Z':
			runes[i] = 'A' + (r-'A'+13)%26
		case r >= 'a' && r <= 'z':
			runes[i] = 'a' + (r-'a'+13)%26
		}
	}
	return string(runes)
}
