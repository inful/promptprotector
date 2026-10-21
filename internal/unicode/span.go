package unicode

// Span is a half-open byte range [Start, End) in the input string where
// an anomaly was detected. End is exclusive so callers can substring with
// s[Start:End] without off-by-one math.
type Span struct {
	Start, End int
}

// Anomaly groups the spans of one detection category within a single input.
// Categories are stable strings — "zero_width", "rtl_override", "homoglyph".
type Anomaly struct {
	Category string
	Spans    []Span
}
