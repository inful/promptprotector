package padding

import "strings"

// Kind classifies a padding anomaly.
type Kind string

const (
	// KindRepeatedLine marks a substantive line that recurs many times.
	// Attackers use this to push a target instruction past a context
	// window or to dilute it below salience.
	KindRepeatedLine Kind = "repeated_line"
	// KindFencePadding marks a run of lines containing only separator
	// characters. Legitimate formatting uses a few; dozens is padding.
	KindFencePadding Kind = "fence_padding"
)

// Span is a half-open byte range covering an anomalous region, plus how
// many lines it spans.
type Span struct {
	Kind  Kind
	Start int
	End   int
	Lines int
	// Detail is a short human-readable summary for logs.
	Detail string
}

// Thresholds tunes padding detection. They are exported so an application
// scanning minified or heavily-formatted documents can raise them.
type Thresholds struct {
	// MinRepeats is how many times one line must recur to count.
	MinRepeats int
	// MinFenceLines is how many consecutive separator-only lines count.
	MinFenceLines int
	// MinLineLen ignores near-empty lines, which repeat trivially.
	MinLineLen int
}

// Default returns the standard thresholds.
func Default() Thresholds {
	return Thresholds{MinRepeats: 5, MinFenceLines: 10, MinLineLen: 8}
}

// Detect finds padding and repetition anomalies in s. It returns nil for
// clean input.
//
// A single input can legitimately produce two spans of different kinds —
// twelve identical separator lines are both a fence run and a repeated
// line — so callers should treat the result as a set, not assume one kind.
//
// This deliberately does NOT return a promptprotector.Category: padding is
// an L1 obfuscation mechanism like homoglyphs, and internal packages must
// not import the root package.
func Detect(s string, t Thresholds) []Span {
	if s == "" {
		return nil
	}
	lines := lineSpans(s)
	out := make([]Span, 0, 2)

	out = append(out, repeatedLines(lines, t)...)
	out = append(out, fenceRuns(lines, t)...)
	if len(out) == 0 {
		return nil
	}
	return out
}

// line is one line with its byte bounds and content.
type line struct {
	start, end int // end excludes the newline
	text       string
}

func lineSpans(s string) []line {
	var lines []line
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, line{start: start, end: i, text: s[start:i]})
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, line{start: start, end: len(s), text: s[start:]})
	}
	return lines
}

// repeatedLines finds lines occurring at least MinRepeats times and
// returns one span covering the whole set of occurrences.
func repeatedLines(lines []line, t Thresholds) []Span {
	firstSeen := make(map[string]int) // trimmed content -> first line index
	lastSeen := make(map[string]int)  // trimmed content -> last line index
	counts := make(map[string]int)
	order := make([]string, 0, len(lines))

	for i, ln := range lines {
		key := strings.TrimSpace(ln.text)
		if len(key) < t.MinLineLen {
			continue
		}
		if _, ok := firstSeen[key]; !ok {
			firstSeen[key] = i
			order = append(order, key)
		}
		lastSeen[key] = i
		counts[key]++
	}

	var out []Span
	for _, key := range order {
		n := counts[key]
		if n < t.MinRepeats {
			continue
		}
		startLine := firstSeen[key]
		endLine := lastSeen[key]
		out = append(out, Span{
			Kind:   KindRepeatedLine,
			Start:  lines[startLine].start,
			End:    lines[endLine].end,
			Lines:  endLine - startLine + 1,
			Detail: "line repeated " + itoa(n) + " times",
		})
	}
	return out
}

// fenceRuns finds runs of consecutive lines made only of separator
// characters.
func fenceRuns(lines []line, t Thresholds) []Span {
	var out []Span
	runStart := -1
	runCount := 0

	flush := func(endLine int) {
		if runStart >= 0 && runCount >= t.MinFenceLines {
			out = append(out, Span{
				Kind:   KindFencePadding,
				Start:  lines[runStart].start,
				End:    lines[endLine].end,
				Lines:  runCount,
				Detail: "separator-only run of " + itoa(runCount) + " lines",
			})
		}
		runStart = -1
		runCount = 0
	}

	for i, ln := range lines {
		if isFence(ln.text) {
			if runStart < 0 {
				runStart = i
			}
			runCount++
			continue
		}
		flush(i - 1)
	}
	flush(len(lines) - 1)
	return out
}

// minFenceLen is the minimum trimmed length for a line to count as a
// separator fence. Eight dashes is ordinary inline punctuation; a real
// fence is meaningfully longer.
const minFenceLen = 10

// isFence reports whether a line consists only of separator characters.
// The line must be long enough to be a fence rather than a stray dash.
func isFence(text string) bool {
	trimmed := strings.TrimSpace(text)
	if len(trimmed) < minFenceLen {
		return false
	}
	for i := 0; i < len(trimmed); i++ {
		switch trimmed[i] {
		case '-', '=', '#', '*', '_', '~', '.', '+':
		default:
			return false
		}
	}
	return true
}

// itoa avoids importing strconv for one call site in a hot-ish path.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
