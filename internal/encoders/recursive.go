package encoders

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
// ROT13 is intentionally NOT in this list. It is a cipher, not a
// encoding wrapper, and applying it mangles any text containing letters
// (which is almost all untrusted input). Callers that want to handle
// ROT13'd prompts should ROT13 the input themselves and feed both the
// original and rotated forms to the rest of the pipeline. The standalone
// ROT13 function exists for that purpose.
var l1Decoders = []l1Decoder{
	{"url", URL},
	{"base64", Base64},
	{"hex", Hex},
	{"unicode-escape", func(s string) (string, error) {
		return UnicodeEscape(s), nil
	}},
}

// RecursiveDecode repeatedly applies the L1 single-pass decoders to s
// until none changes the input or maxDepth decoding rounds have run. It
// returns the final decoded string and the ordered list of decoder names
// that fired (e.g., ["base64", "url"] for a base64-wrapped URL-encoded
// payload). The function is total on its domain — errors from a single
// decoder (invalid base64 input) are silently treated as "did not apply"
// and the loop continues.
func RecursiveDecode(s string, maxDepth int) (string, []string) {
	var chain []string
	for round := 0; round < maxDepth; round++ {
		prev := s
		for _, d := range l1Decoders {
			out, err := d.fn(s)
			if err == nil && out != s {
				chain = append(chain, d.name)
				s = out
				break
			}
		}
		if s == prev {
			break
		}
	}
	return s, chain
}
