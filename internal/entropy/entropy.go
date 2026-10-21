package entropy

import "math"

// Shannon returns the Shannon entropy of s in bits per byte. An empty
// string has entropy 0. The theoretical maximum is 8 bits/byte for a
// string containing all 256 byte values equally.
//
// Entropy is used as a proxy for "does this chunk of text look like
// random bytes rather than natural language or markup?" Encoded
// payloads (base64, hex, gzip-compressed fragments) score high; prose
// scores low (~3.5-4.5 bits/byte for English).
func Shannon(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
