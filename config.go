package promptprotector

// config holds the tunable knobs for the detection pipeline. The zero
// value is not usable — start from defaultConfig(). Functional options
// (added in sub-phase 1F) populate a copy of it.
type config struct {
	decodeDepth      int
	entropyWindow    int
	entropyThreshold float64
	maxInputBytes    int
}

func defaultConfig() config {
	return config{
		decodeDepth:   3,
		entropyWindow: 32,
		// 5.0 bits/byte sits above English prose (~4.2) and JSON (~4.0)
		// but below true binary blobs (~6.0). Note that base64 OF
		// ENGLISH only reaches ~4.9, because base64 does not add entropy
		// to its input — so this check catches encrypted/compressed/binary
		// payloads, while base64-of-text is caught by the decoders in
		// RecursiveDecode, not here. Lower this if you accept false
		// positives on dense prose; raise it toward 6.0 if you want
		// binary blobs only.
		entropyThreshold: 5.0,
		maxInputBytes:    32 << 10, // 32 KiB
	}
}

// NormalizeResult is the L1 layer's output. Decoded is empty when nothing
// was decoded; Chain lists the decoders that fired in application order.
type NormalizeResult struct {
	Raw       string
	Decoded   string
	Chain     []string
	Findings  []Finding
	Truncated bool
}

// l1BaseScores are the per-category confidence values for structural
// signals the L1 layer can emit. They are authored constants rather than
// derived from magnitude on purpose: a longer high-entropy run is not
// meaningfully riskier than a short one, and deriving scores from length
// makes the fusion formula unexplainable in a triage session.
//
// Encoding attack scores highest because a successfully decoded payload
// is unambiguous evidence that someone deliberately obfuscated the text.
var l1BaseScores = map[Category]float64{
	CategoryEncodingAttack:      0.35,
	CategoryRTLOverride:         0.30,
	CategoryZeroWidth:           0.25,
	CategoryHomoglyph:           0.30,
	CategoryHighEntropy:         0.20,
	CategoryDelimiterFraming:    0.30,
	CategoryInstructionOverride: 0.40,
}
