package unicode

import (
	"reflect"
	"testing"
)

func TestZeroWidth_NoSpansReturnsNil(t *testing.T) {
	if got := ZeroWidth("hello world"); got != nil {
		t.Errorf("ZeroWidth(plain) = %v, want nil", got)
	}
	if got := ZeroWidth(""); got != nil {
		t.Errorf("ZeroWidth(empty) = %v, want nil", got)
	}
}

func TestZeroWidth_SingleCharRun(t *testing.T) {
	// "a\u200Bo" — ZWSP (3 bytes in UTF-8) between 'a' and 'o'.
	// Byte layout: a=0, ZWSP=1..3, o=4 → span [1, 4).
	want := []Span{{Start: 1, End: 4}}
	got := ZeroWidth("a\u200Bo")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ZeroWidth = %v, want %v", got, want)
	}
}

func TestZeroWidth_MultipleRuns(t *testing.T) {
	// "a\u200Bb\u200Cc" — two ZWSP runs, each span wraps exactly one ZWSP.
	want := []Span{
		{Start: 1, End: 4},
		{Start: 5, End: 8},
	}
	got := ZeroWidth("a\u200Bb\u200Cc")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ZeroWidth = %v, want %v", got, want)
	}
}

func TestZeroWidth_ContiguousRunMergedIntoOneSpan(t *testing.T) {
	// Two adjacent ZWSPs collapse into one span.
	want := []Span{{Start: 1, End: 7}} // 1, 4, 7 are ZWSPs (each 3 bytes)
	got := ZeroWidth("a\u200B\u200Bo")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ZeroWidth(adjacent) = %v, want %v", got, want)
	}
}

func TestZeroWidth_RunAtStartOfString(t *testing.T) {
	want := []Span{{Start: 0, End: 3}}
	got := ZeroWidth("\u200Bhello")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ZeroWidth(start) = %v, want %v", got, want)
	}
}

func TestZeroWidth_RunAtEndOfString(t *testing.T) {
	want := []Span{{Start: 5, End: 8}}
	got := ZeroWidth("hello\u200B")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ZeroWidth(end) = %v, want %v", got, want)
	}
}

func TestRTL_NoControlsReturnsNil(t *testing.T) {
	if got := RTL("hello world"); got != nil {
		t.Errorf("RTL(plain) = %v, want nil", got)
	}
}

func TestRTL_RLOSpoofsDirections(t *testing.T) {
	// "ab\u202Ecd" — LRO/RLO (3 bytes each) reorder displayed text.
	want := []Span{{Start: 2, End: 5}}
	got := RTL("ab\u202Ecd")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("RTL = %v, want %v", got, want)
	}
}

func TestRTL_CatchesAllNineControlChars(t *testing.T) {
	// All listed RTL control chars should fire. Combining them in one
	// input collapses adjacent ones into a single span.
	const composed = "\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069"
	got := RTL(composed)
	if len(got) != 1 {
		t.Errorf("RTL(composed) = %d spans, want 1 merged span", len(got))
	}
}

func TestHomoglyph_NoHomoglyphsReturnsNil(t *testing.T) {
	if got := Homoglyph("hello world"); got != nil {
		t.Errorf("Homoglyph(plain) = %v, want nil", got)
	}
}

func TestHomoglyph_CyrillicAInAdmin(t *testing.T) {
	// "аdmin" — Cyrillic 'а' (2 bytes in UTF-8) followed by Latin 'dmin'.
	// Byte layout: а=0..1 (2 bytes), d=2, m=3, i=4, n=5 → span [0, 2).
	want := []Span{{Start: 0, End: 2}}
	got := Homoglyph("аdmin")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Homoglyph(cyrillic-a) = %v, want %v", got, want)
	}
}

func TestHomoglyph_GreekOmicronInPrompt(t *testing.T) {
	// "dοmain" — Greek ο (2 bytes) between Latin 'd' and 'main'.
	want := []Span{{Start: 1, End: 3}}
	got := Homoglyph("dοmain")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Homoglyph(greek-o) = %v, want %v", got, want)
	}
}

func TestHomoglyph_RunOfMixedLatinAndHomoglyph(t *testing.T) {
	// "abсd" — Cyrillic 'с' (U+0441) embedded between Latin letters.
	// The detector treats the entire run as one span because it doesn't
	// break on plain Latin chars — this catches "раsswоrd" style
	// obfuscation where multiple homoglyphs are sprinkled in.
	want := []Span{{Start: 2, End: 4}}
	got := Homoglyph("abсd")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Homoglyph(mixed-run) = %v, want %v", got, want)
	}
}

func TestScan_AllClearReturnsNil(t *testing.T) {
	if got := Scan("hello world"); got != nil {
		t.Errorf("Scan(plain) = %v, want nil", got)
	}
}

func TestScan_DetectsMultipleCategories(t *testing.T) {
	// "ab\u202E\u200Bc\u0430d" — RLO, ZWSP, and Cyrillic 'а'.
	want := []string{"zero_width", "rtl_override", "homoglyph"}
	got := categoriesOf(Scan("ab\u202E\u200Bc\u0430d"))
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Scan categories = %v, want %v", got, want)
	}
}

// categoriesOf extracts the category names, replacing the deleted
// HasCategory helper at its one remaining call site.
func categoriesOf(anomalies []Anomaly) []string {
	out := make([]string, 0, len(anomalies))
	for _, a := range anomalies {
		out = append(out, a.Category)
	}
	return out
}

func TestScan_CategoryOrderIsStable(t *testing.T) {
	// Even if categories are encountered in different input positions,
	// Scan emits them in canonical order: zero_width, rtl_override, homoglyph.
	// Input has homoglyph first, rtl second, zwsp last.
	anomalies := Scan("\u043A\u202E\u200B")
	if len(anomalies) != 3 {
		t.Fatalf("Scan(combined) len = %d, want 3", len(anomalies))
	}
	wantOrder := []string{"zero_width", "rtl_override", "homoglyph"}
	for i, a := range anomalies {
		if a.Category != wantOrder[i] {
			t.Errorf("anomalies[%d].Category = %q, want %q", i, a.Category, wantOrder[i])
		}
	}
}
