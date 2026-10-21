package unicode

// rtlControlChars is the set of bidirectional-formatting code points that
// an attacker can use to reorder displayed text ("BiDi spoofing"). Pure
// ASCII prompts with one of these chars mid-string are suspicious —
// legitimate uses exist (Arabic / Hebrew documents) but in a typical
// LLM-prompt path they usually mean someone is hiding instructions.
//
// Covers: U+202A LRE, U+202B RLE, U+202C PDF, U+202D LRO, U+202E RLO,
// U+2066 LRI, U+2067 RLI, U+2068 FSI, U+2069 PDI.
var rtlControlChars = map[rune]bool{
	'\u202A': true, // Left-to-Right Embedding
	'\u202B': true, // Right-to-Left Embedding
	'\u202C': true, // Pop Directional Formatting
	'\u202D': true, // Left-to-Right Override
	'\u202E': true, // Right-to-Left Override  (most common BiDi-spoof char)
	'\u2066': true, // Left-to-Right Isolate
	'\u2067': true, // Right-to-Left Isolate
	'\u2068': true, // First Strong Isolate
	'\u2069': true, // Pop Directional Isolate
}

// RTL returns the byte spans of contiguous RTL / BiDi control-character
// runs in s. Inputs with no BiDi controls return nil.
func RTL(s string) []Span {
	var spans []Span
	start := -1
	for i, r := range s {
		if rtlControlChars[r] {
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
