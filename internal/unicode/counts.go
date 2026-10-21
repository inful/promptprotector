package unicode

import stdunicode "unicode"

// Counts tallies characters per Unicode category across a single input.
// Only the categories most useful for prompt-injection heuristics are
// tracked; callers wanting exhaustive coverage should use the stdlib
// unicode.Category function directly. Fields are zero-valued when no
// matching runes appear.
//
// Categories:
//   - Cf: Format (zero-width chars, BiDi controls, etc.)
//   - Co: Private Use (often used by attackers as a "Unicode safe haven")
//   - Lm: Modifier Letter (rare in normal text)
//   - Lo: Other Letter (most non-Latin scripts: Cyrillic, Greek, Arabic, ...)
type Counts struct {
	Cf int
	Co int
	Lm int
	Lo int
}

// Count returns the per-category character counts for s.
func Count(s string) Counts {
	var c Counts
	for _, r := range s {
		switch {
		case stdunicode.Is(stdunicode.Cf, r):
			c.Cf++
		case stdunicode.Is(stdunicode.Co, r):
			c.Co++
		case stdunicode.Is(stdunicode.Lm, r):
			c.Lm++
		case stdunicode.Is(stdunicode.Lo, r):
			c.Lo++
		}
	}
	return c
}
