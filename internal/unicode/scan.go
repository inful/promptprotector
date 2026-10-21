package unicode

// Scan runs every anomaly detector over s and returns the union of their
// findings. The result includes ONLY categories that fired — a clean
// scan returns nil (not an empty slice with no entries). The order of
// anomalies is stable (zero_width, rtl_override, homoglyph) regardless
// of which fired first in the input.
func Scan(s string) []Anomaly {
	var out []Anomaly
	if spans := ZeroWidth(s); len(spans) > 0 {
		out = append(out, Anomaly{Category: "zero_width", Spans: spans})
	}
	if spans := RTL(s); len(spans) > 0 {
		out = append(out, Anomaly{Category: "rtl_override", Spans: spans})
	}
	if spans := Homoglyph(s); len(spans) > 0 {
		out = append(out, Anomaly{Category: "homoglyph", Spans: spans})
	}
	return out
}
