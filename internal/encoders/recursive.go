package encoders

import (
	"errors"
	"regexp"
	"sort"
)

// ErrNoMatch is returned by substring decoders that look for an embedded
// encoding rather than decoding the whole input. RecursiveDecode treats
// this the same as any non-nil error.
var ErrNoMatch = errors.New("encoders: no embedded match")

// l1Decoder is one of the single-pass decoders composed by RecursiveDecode.
// fn returns (decoded, nil) on success (decoded may equal input if the
// format trivially applies, e.g., URL("hello")), (input, ErrFoo) when
// the input is not actually that encoding (the loop interprets this as
// "did not apply"), or (transformedInput, nil) when the format applied
// and the result is the transformed form.
type l1Decoder struct {
	name string
	fn   func(string) (string, error)
}

// l1Decoders is the priority order in which RecursiveDecode tries to peel
// layers. Order is roughly outer-encoding-first to inner-encoding-last.
//
// ROT13 is intentionally NOT in this list. It is a cipher, not an
// encoding wrapper, and applying it mangles any text containing letters
// (which is almost all untrusted input). Callers that want to handle
// ROT13'd prompts should ROT13 the input themselves and feed both the
// original and rotated forms to the rest of the pipeline. The standalone
// ROT13 function exists for that purpose.
//
// The base64-substr fallback at the end is what catches encodings buried
// in surrounding text — markdown wrappers, JSON envelopes, the
// promptbuilder datamark form, "see aWdub3Jl...= here" constructions —
// where the whole input is NOT valid base64 but a substring is. Without
// it the L1 layer silently skips every wrapped payload.
var l1Decoders = []l1Decoder{
	{"url", URL},
	{"base64", Base64},
	{"hex", Hex},
	{"unicode-escape", func(s string) (string, error) {
		return UnicodeEscape(s), nil
	}},
	{"base64-substr", decodeBase64Substring},
}

// base64SubstrRe matches a run of base64-alphabet characters long enough
// to plausibly be a base64 payload (>= 32 chars, length-modulo-4 zero or
// one = at the end). It is intentionally permissive: real-world base64
// wraps at 76 chars and may have stray newlines that base64.StdEncoding
// tolerates after a ReplaceAll.
var base64SubstrRe = regexp.MustCompile(`[A-Za-z0-9+/]{32,}={0,2}`)

// decodeBase64Substring is the substring fallback used by RecursiveDecode
// when the whole input is not a single encoding. It finds the longest
// base64-shaped substring, decodes it, and returns the decoded text. If
// no candidate yields text on decode (e.g., random binary noise from
// "aaaaaa…"), it returns ErrNoMatch and the outer loop moves on.
func decodeBase64Substring(s string) (string, error) {
	matches := base64SubstrRe.FindAllString(s, -1)
	if len(matches) == 0 {
		return s, ErrNoMatch
	}
	// Longest first: a longer candidate is more likely to be a real
	// payload (≥ 32 chars is short enough to be one full base64 line of
	// plaintext) and less likely to be a benign phrase that happens
	// to fit the alphabet.
	sort.Slice(matches, func(i, j int) bool { return len(matches[i]) > len(matches[j]) })
	for _, sub := range matches {
		decoded, err := Base64(sub)
		if err != nil {
			continue
		}
		if !isText(decoded) {
			continue
		}
		return decoded, nil
	}
	return s, ErrNoMatch
}

// RecursiveDecode repeatedly applies the L1 single-pass decoders to s
// until none changes the input or maxDepth decoding rounds have run. It
// returns the final decoded string and the ordered list of decoder names
// that fired (e.g., ["base64", "url"] for a base64-wrapped URL-encoded
// payload). The function is total on its domain — errors from a single
// decoder (invalid base64 input) are silently treated as "did not apply"
// and the loop continues.
//
// A decode only counts if it yields TEXT. Base64, hex and percent-encoding
// all round-trip arbitrary bytes, so "the input was valid base64" proves
// nothing: a long run of base64-alphabet characters ("x"*100000, a padded
// identifier, a log blob) decodes to binary noise and was previously
// reported as an obfuscation attack. An attacker wrapping a prompt in
// base64 needs the TEXT to survive, so requiring it costs no recall and
// removes the false positive.
func RecursiveDecode(s string, maxDepth int) (string, []string) {
	var chain []string
	for round := 0; round < maxDepth; round++ {
		prev := s
		for _, d := range l1Decoders {
			out, err := d.fn(s)
			if err != nil || out == s || !isText(out) {
				continue
			}
			chain = append(chain, d.name)
			s = out
			break
		}
		if s == prev {
			break
		}
	}
	return s, chain
}

// textAsciiRatio is the share of runes a decode must have in the ASCII
// range before it counts as text.
//
// A printable-ratio test alone is not enough: "a"*40000 is valid base64
// and decodes to the repeating rune sequence U+0069 U+019A U+0069 U+019A
// — every rune printable — so it still looked like text. Requiring ASCII
// separates real wrapped text from byte soup that happens to land on
// valid UTF-8 code points.
//
// 0.7 is comfortably above uniform-random bytes (~0.375 of the byte
// range is printable ASCII) and comfortably below ordinary text with
// accented characters.
const textASCIIRatio = 0.7

// isText reports whether s looks like human-readable text rather than
// decoded binary. It samples the head and tail only: the decision does
// not need to be exact, and a multi-megabyte decode should not cost a
// full scan.
func isText(s string) bool {
	const sample = 512
	head, tail := s, ""
	if len(s) > 2*sample {
		head, tail = s[:sample], s[len(s)-sample:]
	} else if len(s) > sample {
		head = s[:sample]
	}
	return asciiRatio(head) >= textASCIIRatio && asciiRatio(tail) >= textASCIIRatio
}

// asciiRatio returns the share of runes in s that are printable ASCII or
// common whitespace. Invalid UTF-8 (the signature of decoded binary)
// counts as non-ASCII.
func asciiRatio(s string) float64 {
	if s == "" {
		return 1
	}
	ascii := 0
	total := 0
	for _, r := range s {
		total++
		if r == '\n' || r == '\r' || r == '\t' || (r >= 0x20 && r < 0x7f) {
			ascii++
		}
	}
	return float64(ascii) / float64(total)
}
