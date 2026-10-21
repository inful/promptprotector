package unicode

// homoglyphs maps non-Latin code points that look like Latin letters to
// their apparent Latin equivalents. The list is small on purpose — adding
// every Unicode confusable would create too many false positives on
// legitimate multilingual text. We focus on Cyrillic and Greek letters
// that are visual lookalikes for common Latin letters used in English
// prompts (e.g., "аdmin" with a Cyrillic 'а' pasted in to bypass a
// keyword blocklist that only matches the ASCII word).
//
// Source: Unicode UTS #39 confusables, hand-curated to the most common
// attack vectors as of 2025.
var homoglyphs = map[rune]rune{
	// Cyrillic lowercase.
	'\u0430': 'a', // CYRILLIC SMALL LETTER A
	'\u0435': 'e', // CYRILLIC SMALL LETTER IE
	'\u043A': 'k', // CYRILLIC SMALL LETTER KA
	'\u043C': 'm', // CYRILLIC SMALL LETTER EM
	'\u043D': 'h', // CYRILLIC SMALL LETTER EN
	'\u043E': 'o', // CYRILLIC SMALL LETTER O
	'\u0440': 'p', // CYRILLIC SMALL LETTER ER
	'\u0441': 'c', // CYRILLIC SMALL LETTER ES
	'\u0442': 't', // CYRILLIC SMALL LETTER TE
	'\u0443': 'y', // CYRILLIC SMALL LETTER U
	'\u0445': 'x', // CYRILLIC SMALL LETTER HA

	// Cyrillic uppercase (visually identical to Latin counterparts in many fonts).
	'\u0410': 'A', // CYRILLIC CAPITAL LETTER A
	'\u0412': 'B', // CYRILLIC CAPITAL LETTER VE
	'\u0415': 'E', // CYRILLIC CAPITAL LETTER IE
	'\u041A': 'K', // CYRILLIC CAPITAL LETTER KA
	'\u041C': 'M', // CYRILLIC CAPITAL LETTER EM
	'\u041D': 'H', // CYRILLIC CAPITAL LETTER EN
	'\u041E': 'O', // CYRILLIC CAPITAL LETTER O
	'\u0420': 'P', // CYRILLIC CAPITAL LETTER ER
	'\u0421': 'C', // CYRILLIC CAPITAL LETTER ES
	'\u0422': 'T', // CYRILLIC CAPITAL LETTER TE
	'\u0425': 'X', // CYRILLIC CAPITAL LETTER HA

	// Greek.
	'\u03BF': 'o', // GREEK SMALL LETTER OMICRON
	'\u03B1': 'a', // GREEK SMALL LETTER ALPHA
	'\u03C1': 'p', // GREEK SMALL LETTER RHO
	'\u0391': 'A', // GREEK CAPITAL LETTER ALPHA
	'\u039F': 'O', // GREEK CAPITAL LETTER OMICRON
	'\u03A1': 'P', // GREEK CAPITAL LETTER RHO
}

// Homoglyph returns the byte spans of contiguous homoglyph runs in s.
// A "run" is a maximal sequence of characters where each character is
// either a homoglyph or a Latin letter that shares a Latin "lookalike"
// with the adjacent homoglyph. So "hеllo" (Cyrillic 'е' between Latin)
// emits a single span, not three. Inputs with no homoglyphs return nil.
func Homoglyph(s string) []Span {
	var spans []Span
	start := -1
	for i, r := range s {
		if _, ok := homoglyphs[r]; ok {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			spans = append(spans, Span{Start: start, End: i})
			start = -1
		}
	}
	if start >= 0 {
		spans = append(spans, Span{Start: start, End: len(s)})
	}
	return spans
}
