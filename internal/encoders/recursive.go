package encoders

import (
	"errors"
	"regexp"
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
// when the whole input is not a single encoding. It iterates over every
// base64-shaped substring in source order and returns the FIRST whose
// decoded form passes the isText gate.
//
// The earlier "longest first" heuristic let a long benign run hide a
// smaller attack run elsewhere in the same input: the decoder picked
// the longest candidate whose decoded form looked like text, even if a
// shorter sibling (later in the input) decoded to a less-benign payload.
// Source order is deterministic but lets an attacker exploit
// "earliest benign run hides the attack" if the attacker can append
// benign padding before the payload. The trade-off is documented and
// mitigated by promptbuilder.Wrap on the input side; it is not a
// detection-side limit callers can solve on their own.
//
// Normalize.go calls ScanAllBase64Payloads separately to surface every
// viable payload as its own finding, so a long benign run no longer
// hides a sibling attack.
func decodeBase64Substring(s string) (string, error) {
	// Built on ScanAllBase64Payloads rather than repeating its regex,
	// decode and isText gate: normalize calls that function on the same
	// string moments later, so a second pass over the same candidates was
	// work done twice on every scan containing base64.
	if payloads := ScanAllBase64Payloads(s, 1); len(payloads) > 0 {
		return payloads[0], nil
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

// ScanAllBase64Payloads scans the ORIGINAL raw input for encoding-shaped
// substrings and returns the decoded payload of each that passes the
// isText gate. Up to limit results are returned.
//
// This is called separately by normalize.go AFTER RecursiveDecode so
// that an input containing multiple encoded substrings yields a
// recursive_decode finding per payload, not just the single one that
// became the canonical decoded form. Without this, a long benign run
// would let the substring decoder pick it and miss a smaller attack run
// later in the same input.
func ScanAllBase64Payloads(s string, limit int) []string {
	if limit <= 0 {
		return nil
	}
	matches := base64SubstrRe.FindAllString(s, -1)
	if len(matches) == 0 {
		return nil
	}
	var out []string
	for _, sub := range matches {
		decoded, ok := textDecode(sub)
		if !ok {
			continue
		}
		out = append(out, decoded)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// textDecode decodes candidate as base64, then as hex, returning the
// first result that looks like text.
//
// The hex fallback exists because the two alphabets overlap: every hex
// digit is a valid base64 character, so base64SubstrRe does find a
// hex-encoded payload buried in prose — but its length is rarely a
// multiple of four, so Base64 rejects it and the payload was skipped
// entirely. Measured: "notes: <hex> end" returned Allow 0.00 with no
// findings, while the same payload hex-encoded as the whole input was
// caught. Adding the fallback costs no false positives on prose carrying
// hex-looking strings (checked against commit SHAs, ETags and tokens).
//
// shortcut: percent-encoded and \u-escaped payloads embedded in
// surrounding text are still missed — neither produces a long run of
// base64-alphabet characters, so they need their own scanner patterns,
// and a %XX run is common in ordinary URLs. They are detected only when
// the whole input is the payload.
func textDecode(candidate string) (string, bool) {
	if decoded, err := Base64(candidate); err == nil && isText(decoded) {
		return decoded, true
	}
	if len(candidate)%2 == 0 && isHexRun(candidate) {
		if decoded, err := Hex(candidate); err == nil && isText(decoded) {
			return decoded, true
		}
	}
	return "", false
}

// isHexRun reports whether every byte is a hex digit.
func isHexRun(s string) bool {
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return len(s) > 0
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
//
// The empty case returns false: a successful decode that produces no
// bytes is not "text" — it is "no payload here". Without this, the
// strip-whitespace behaviour of base64.StdEncoding turns a single
// newline input into a "decoded base64" finding.
func isText(s string) bool {
	if s == "" {
		return false
	}
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
