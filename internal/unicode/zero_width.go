package unicode

// zeroWidthChars is the set of Unicode "Format" category code points that
// attackers plant between visible characters to confuse downstream parsers
// or to evade naive regex matches. ZWSP and friends are present in real
// Unicode text but rarely mid-Latin-word; flagging them is high-precision.
//
// Covers: U+200B ZWSP, U+200C ZWNJ, U+200D ZWJ, U+2060 Word Joiner,
// U+FEFF BOM / ZWNBSP.
//
// We do NOT include U+00AD SOFT HYPHEN here — soft hyphens render visibly
// in some browsers and are common in hyphenation dictionaries. They are
// addressed separately if needed in a future category.
var zeroWidthChars = map[rune]bool{
	'\u200B': true, // Zero Width Space
	'\u200C': true, // Zero Width Non-Joiner
	'\u200D': true, // Zero Width Joiner
	'\u2060': true, // Word Joiner
	'\uFEFF': true, // Zero Width No-Break Space / BOM
}

// ZeroWidth returns the byte spans of contiguous zero-width-character
// runs in s. Inputs without zero-width characters return nil.
func ZeroWidth(s string) []Span {
	var spans []Span
	start := -1
	for i, r := range s {
		if zeroWidthChars[r] {
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
