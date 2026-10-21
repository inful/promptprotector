package entropy

import (
	"math"
	"testing"
)

const epsilon = 1e-9 // floating-point tolerance for entropy comparisons

func almostEqual(a, b float64) bool {
	return math.Abs(a-b) < epsilon
}

func TestShannon_EmptyStringReturnsZero(t *testing.T) {
	if got := Shannon(""); got != 0 {
		t.Errorf("Shannon(empty) = %v, want 0", got)
	}
}

func TestShannon_SingleCharReturnsZero(t *testing.T) {
	// One symbol with probability 1 → entropy 0.
	if got := Shannon("aaaa"); !almostEqual(got, 0) {
		t.Errorf("Shannon(aaaa) = %v, want 0", got)
	}
}

func TestShannon_TwoCharFiftyFiftyIsOneBit(t *testing.T) {
	// "ab" or "aabb" — uniform mix of two distinct chars gives 1 bit/byte.
	if got := Shannon("ab"); !almostEqual(got, 1.0) {
		t.Errorf("Shannon(ab) = %v, want 1.0", got)
	}
	if got := Shannon("aabb"); !almostEqual(got, 1.0) {
		t.Errorf("Shannon(aabb) = %v, want 1.0", got)
	}
}

func TestShannon_FourUniformCharsIsTwoBits(t *testing.T) {
	// 4 distinct chars each appearing once → log2(4) = 2 bits/byte.
	if got := Shannon("abcd"); !almostEqual(got, 2.0) {
		t.Errorf("Shannon(abcd) = %v, want 2.0", got)
	}
}

func TestShannon_AllBytesAreFourBits(t *testing.T) {
	// 16 distinct chars each appearing once → log2(16) = 4 bits/byte.
	chars := "0123456789abcdef"
	if got := Shannon(chars); !almostEqual(got, 4.0) {
		t.Errorf("Shannon(16-chars) = %v, want 4.0", got)
	}
}

func TestLongestRun_InputShorterThanWindowReturnsZero(t *testing.T) {
	// Window=32, input of 10 bytes: no qualifying window exists.
	got := LongestHighEntropyRun("shortinput", 32, 1.0)
	if got.Start != 0 || got.End != 0 {
		t.Errorf("LongestHighEntropyRun(short) = %+v, want zero Run", got)
	}
}

func TestLongestRun_EmptyStringReturnsZero(t *testing.T) {
	got := LongestHighEntropyRun("", 32, 1.0)
	if got.Start != 0 || got.End != 0 {
		t.Errorf("LongestHighEntropyRun(empty) = %+v, want zero Run", got)
	}
}

func TestLongestRun_AllHighEntropyReturnsFullSpan(t *testing.T) {
	// 64 uniform-ish bytes — every window will be high entropy.
	// Use the alphabet "0123456789abcdef" cycling, which has 4 bits/byte
	// entropy (well above 3.0 threshold).
	s := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	got := LongestHighEntropyRun(s, 16, 3.0)
	wantEnd := len(s) // covers the whole input via overlapping windows
	if got.Start != 0 || got.End != wantEnd {
		t.Errorf("LongestHighEntropyRun(uniform) = [%d, %d), want [0, %d)", got.Start, got.End, wantEnd)
	}
}

func TestLongestRun_AllSameCharReturnsZero(t *testing.T) {
	// Every window is 0 entropy — never crosses any threshold > 0.
	s := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 32 a's
	got := LongestHighEntropyRun(s, 16, 1.0)
	if got.Start != 0 || got.End != 0 {
		t.Errorf("LongestHighEntropyRun(all-same) = [%d, %d), want [0, 0)", got.Start, got.End)
	}
}

func TestLongestRun_FindsEmbeddedHighEntropyBlock(t *testing.T) {
	// Surround a 32-byte high-entropy block with low-entropy padding.
	// The block cycles 16 distinct chars (4 bits/byte), well above the
	// 3.0 threshold.
	//
	// NOTE: the detected span BLEEDS into the padding by (window-1)
	// bytes on each side. A window straddling the boundary still mixes
	// 12 distinct chars with 4 copies of 'a', which computes to ~3.5
	// bits/byte — above threshold. That is correct behaviour for a
	// sliding-window detector: the boundary region genuinely does look
	// high-entropy. Callers that need a tight span should compute one
	// from the decoded payload instead of relying on this span's edges.
	const window = 16
	low := "aaaa"                               // entropy 0
	block := "0123456789abcdef0123456789abcdef" // 32 chars, entropy 4
	s := low + block + low
	got := LongestHighEntropyRun(s, window, 3.0)

	wantStart := 0
	wantEnd := len(s) // whole input qualifies once bleeding is accounted for
	if got.Start != wantStart || got.End != wantEnd {
		t.Errorf("LongestHighEntropyRun(embedded) = [%d, %d), want [%d, %d) (bleeds into padding)", got.Start, got.End, wantStart, wantEnd)
	}
}

func TestLongestRun_ThresholdZeroAcceptsEverything(t *testing.T) {
	// Threshold 0: any entropy >= 0 (which is all entropy for non-empty
	// strings) qualifies.
	s := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	got := LongestHighEntropyRun(s, 16, 0.0)
	wantEnd := len(s)
	if got.Start != 0 || got.End != wantEnd {
		t.Errorf("LongestHighEntropyRun(threshold=0) = [%d, %d), want [0, %d)", got.Start, got.End, wantEnd)
	}
}

func TestLongestRun_PicksLongestOfMultipleRuns(t *testing.T) {
	// Two high-entropy blocks separated by a low-entropy run; the
	// detector must return the LONGER one. With a 4-byte low-entropy
	// separator and a 16-byte window, the shorter block's span bleeds
	// far enough to reach the longer block's span, so they merge into
	// one continuous qualifying region.
	const window = 16
	low := "aaaa"                              // entropy 0
	short := "0123456789abcdef"                // 16 chars
	long := "0123456789abcdef0123456789abcdef" // 32 chars
	s := low + short + low + long + low
	got := LongestHighEntropyRun(s, window, 3.0)

	wantStart := 0
	wantEnd := len(s)
	if got.Start != wantStart || got.End != wantEnd {
		t.Errorf("LongestHighEntropyRun = [%d, %d), want [%d, %d) (regions merge via boundary bleed)", got.Start, got.End, wantStart, wantEnd)
	}
}

func TestLongestRun_LongBlockPreferredWithWideSeparator(t *testing.T) {
	// Two high-entropy blocks separated by a wide low-entropy region, so
	// their (bled) spans do not overlap. The detector must return the
	// span around the LONGER block.
	//
	// We assert containment rather than exact edges: the bleed boundary
	// depends on window-level entropy arithmetic that is an
	// implementation detail, and pinning it here would make the test
	// brittle. What matters is that the reported span covers the long
	// block and not the short one.
	const window = 16
	low := "aaaaaaaaaaaaaaaa"
	short := "0123456789abcdef"
	long := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	s := low + short + low + long + low

	longStart := 16 + 16 + 16
	longEnd := longStart + len(long)

	got := LongestHighEntropyRun(s, window, 3.0)
	if got.Start > longStart || got.End < longEnd {
		t.Errorf("LongestHighEntropyRun = [%d, %d), want span containing long block [%d, %d)",
			got.Start, got.End, longStart, longEnd)
	}
	if got.Start == 0 {
		t.Errorf("LongestHighEntropyRun.Start = 0, want start inside the long block region (%d+), not the short block at 16", longStart)
	}
}
