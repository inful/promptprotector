package entropy

// Run is a half-open byte span [Start, End) in the scanned input whose
// Shannon entropy meets the caller's threshold across every sliding
// window overlapping that span. Entropy is the maximum window entropy
// observed within the run (not an average), so a caller can see the
// strongest evidence inside the span.
type Run struct {
	Start, End int
	Entropy    float64
}

// LongestHighEntropyRun slides a window of size `window` across s and
// returns the longest contiguous byte span in which every window
// crossing that span has Shannon entropy >= threshold.
//
// Window and threshold are policy knobs, not constants, because the
// right values depend on the application: a minified-JS or config-file
// scanner tolerates a lower threshold than a natural-language chatbot.
//
// A Run of {0, 0, 0} means no qualifying span was found — which is the
// common case for ordinary prose and is NOT an error. Callers should
// treat "no run" as "no encoded-payload signal", not as a failure.
//
// Inputs shorter than `window` yield the zero Run, since no complete
// window can be evaluated.
func LongestHighEntropyRun(s string, window int, threshold float64) Run {
	if window <= 0 || len(s) < window {
		return Run{}
	}

	var best Run
	runStart := -1
	runMaxEntropy := 0.0

	for i := 0; i+window <= len(s); i++ {
		e := Shannon(s[i : i+window])
		if e < threshold {
			if runStart >= 0 {
				// Span closes here.
				if bestLen(runStart, i+window) > bestLen(best.Start, best.End) {
					best = Run{Start: runStart, End: i + window, Entropy: runMaxEntropy}
				}
				runStart = -1
				runMaxEntropy = 0.0
			}
			continue
		}
		if runStart < 0 {
			runStart = i
		}
		if e > runMaxEntropy {
			runMaxEntropy = e
		}
	}

	// Close a run that extends to the end of the input.
	if runStart >= 0 {
		if bestLen(runStart, len(s)) > bestLen(best.Start, best.End) {
			best = Run{Start: runStart, End: len(s), Entropy: runMaxEntropy}
		}
	}

	return best
}

// bestLen returns the byte length of a span, treating the zero Run
// ({0, 0}) as length 0. This keeps the "is the candidate longer?" check
// in LongestHighEntropyRun readable.
func bestLen(start, end int) int {
	if end <= start {
		return 0
	}
	return end - start
}
