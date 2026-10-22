package promptprotector

import (
	"fmt"
	"strings"
)

// regexScan applies a Ruleset to text and returns one Finding per rule
// that matched. Rules are evaluated against the text as-is: RE2 gives no
// backreferences, so an obfuscation-resistant "clever" pattern is not
// achievable here — most decoding is L1's job, not L2's.
//
// The text passed in is whatever the calling context supplies. Today
// that is the original input (scanForms "raw" form), the canonical
// decoded form (scanForms "decoded" form), or a per-substring decoded
// payload emitted by normalize.go when the input contains multiple
// base64-shaped substrings and the canonical recursion only picks one.
//
// A rule matching multiple times still produces a single Finding (the
// first match position is reported). Triage wants "which rules fired and
// where once", not a per-occurrence flood.
func regexScan(rs Ruleset, text, formLabel string) []Finding {
	if text == "" {
		return nil
	}
	out := make([]Finding, 0, 4)
	for _, r := range rs.Rules {
		if r.re == nil {
			continue
		}
		loc := r.re.FindStringIndex(text)
		if loc == nil {
			continue
		}
		out = append(out, Finding{
			Layer:    layerL2,
			Rule:     r.ID,
			Category: r.Category,
			Score:    r.Weight,
			Span:     &Span{Start: loc[0], End: loc[1]},
			Evidence: formatMatchEvidence(formLabel, r.ID, text[loc[0]:loc[1]]),
		})
	}
	return out
}

// maxEvidenceLen bounds how much matched text we copy into Evidence.
// Evidence is retained in Results for logging, and an attacker can craft
// a pattern that matches megabytes of input.
const maxEvidenceLen = 120

// formatMatchEvidence renders a Finding's Evidence string. The matched
// substring is truncated and control characters are collapsed so a
// terminal or log viewer can't be driven into a broken state by
// attacker-controlled text.
//
// Evidence may contain untrusted content; callers rendering it should
// escape for their output format.
func formatMatchEvidence(formLabel, ruleID, match string) string {
	match = truncateRunes(match, maxEvidenceLen)
	match = strings.Map(sanitizeRune, match)
	match = strings.TrimSpace(match)
	return fmt.Sprintf("%s: %s matched %q", formLabel, ruleID, match)
}

// truncateRunes truncates to at most n runes, appending an ellipsis when
// it cuts. Byte-slicing would split a multi-byte rune and produce
// invalid UTF-8 in Evidence.
func truncateRunes(s string, n int) string {
	count := 0
	for i := range s {
		if count == n {
			return s[:i] + "…"
		}
		count++
	}
	return s
}

// sanitizeRune collapses control characters to spaces so Evidence cannot
// inject newlines, tabs, or ANSI escapes into a log line. Newline and
// carriage return become explicit markers because they are meaningful
// for injection attacks (multi-line rule framing).
func sanitizeRune(r rune) rune {
	switch {
	case r == '\n':
		return '⏎'
	case r == '\r':
		return '␍'
	case r == '\t':
		return '␉'
	case r < 0x20 || r == 0x7f:
		return ' '
	default:
		return r
	}
}
