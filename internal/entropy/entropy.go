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
	// Collect the distinct byte values as we count, so the entropy sum
	// walks len(distinct) terms instead of all 256 slots. The sliding
	// window calls this once per byte of input, and a 32-byte window
	// holds at most 32 distinct values — iterating the whole table was
	// about 8 ms of a 49 ms scan at the 32 KiB cap. Both arrays stay on
	// the stack: this is called tens of thousands of times per scan.
	var distinct [256]byte
	nd := 0
	for i := 0; i < len(s); i++ {
		if counts[s[i]] == 0 {
			distinct[nd] = s[i]
			nd++
		}
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, b := range distinct[:nd] {
		p := float64(counts[b]) / n
		h -= p * math.Log2(p)
	}
	return h
}
