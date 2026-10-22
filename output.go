package promptprotector

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	canarypkg "github.com/inful/promptprotector/internal/canary"
)

// ---------------------------------------------------------------------------
// Canary tokens
// ---------------------------------------------------------------------------

// canaryPrefixes is the set of recognised canary prefixes. PTP- is the
// native namespace; PPB- is the prefix used by the sibling promptbuilder
// package, and extractCanaries accepts it so a prompt wrapped there is
// still checkable here. Adding a new prefix here is the entire contract
// for adopting a new canary family.
var canaryPrefixes = []string{canarypkg.PrefixPTP, canarypkg.PrefixPPB}

// NewCanary generates a random canary token. Tokens are 16 random bytes
// hex-encoded (32 chars), prefixed with canaryPrefixes[0] (the native
// "PTP-" namespace), which is far beyond guessing range for an attacker
// who cannot observe the system prompt.
func NewCanary() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate canary: %w", err)
	}
	return canaryPrefixes[0] + hex.EncodeToString(buf), nil
}

// InsertCanary returns system with the canary directive appended. The
// resulting prompt does not itself trip the input scanner: the directive
// contains no injection keywords, and the token has no unicode anomalies.
func InsertCanary(system, token string) string {
	return system + "\n\n" + fmt.Sprintf(canarypkg.DirectiveFmt, token)
}

// leakTolerance is the edit distance tolerated when matching a canary.
// Two, not one, because a transposition costs two edits under plain
// Levenshtein and one-character deletions are the failure this check
// exists for. Measured against 45 KB of ordinary prose, tolerance 2
// produced no false match and cost 1.6 ms more than tolerance 1; the
// needle is 36 hex characters, so unrelated text has to be within two
// edits of that specific string to collide.
const leakTolerance = 2

// scanOutputLeak reports whether output leaked any canary embedded in
// system. It returns nil when there is no leak.
//
// Every canary-shaped token in the system is checked — a system that
// plants a global canary alongside a per-session canary must catch a
// leak of either, not just the first. Matches are substring-first with
// a bounded fuzzy fallback that only runs when the exact substring is
// absent and the output is small enough to be worth it.
//
// redact applies WithRedaction's settings: when true, the canary value
// is replaced with "[REDACTED]" in Evidence so an operator who has
// turned secret redaction on for AWS keys does not leak the planted
// canary through this Finding.
func scanOutputLeak(system, output string, redact bool) *Finding {
	if system == "" || output == "" {
		return nil
	}
	for _, canary := range extractCanaries(system) {
		if i := strings.Index(output, canary); i >= 0 {
			return canaryFinding(canaryEvidence(canary, i, redact, false), false)
		}
		if len(output) <= fuzzyMatchCeiling && fuzzyContains(output, canary, leakTolerance) {
			return canaryFinding(canaryEvidence(canary, -1, redact, true), true)
		}
	}
	return nil
}

// canaryEvidence renders the canary's Findings evidence. When redact is
// set, the value is replaced with "[REDACTED]"; otherwise the canary
// string is retained for audit/verification.
func canaryEvidence(canary string, pos int, redact, fuzzy bool) string {
	value := canary
	if redact {
		value = "[REDACTED]"
	}
	if fuzzy {
		return fmt.Sprintf("canary %s appeared within edit distance %d", value, leakTolerance)
	}
	return fmt.Sprintf("canary %s appeared verbatim at byte %d", value, pos)
}

// extractCanaries pulls every canary-shaped token out of a system
// prompt, via internal/canary — which promptbuilder.ExtractCanary uses
// too, so the two cannot drift.
//
// The length floor (minCanaryHexLen) matters: without it any product
// identifier that happens to start with "PTP-" or "PPB-" became a
// canary, so a system prompt documenting a PTP-1234 route code and a
// response echoing that code scored a 0.95 confirmed leak and blocked.
// A real canary is always long.
//
// Accepting both PTP- and PPB- is what makes a system wrapped by the
// sibling promptbuilder package checkable here. Every canary prefix in
// the system prompt is examined — the previous "first wins" behaviour
// silently missed leaks of any non-first canary (e.g. a per-session
// canary inserted alongside a global one).
func extractCanaries(system string) []string {
	return canarypkg.ExtractAll(system, canaryPrefixes...)
}

func canaryFinding(evidence string, fuzzy bool) *Finding {
	rule := "canary_leak"
	if fuzzy {
		rule = "canary_near_miss"
	}
	return &Finding{
		Layer:    layerOutput,
		Rule:     rule,
		Category: CategoryCanaryLeak,
		Score:    l1BaseScores[CategoryCanaryLeak],
		Evidence: evidence,
	}
}

// fuzzyMatchCeiling bounds the input size for fuzzy canary matching.
// Exact matching is a single strings.Index and runs on any input; the
// fuzzy fallback is quadratic per window, and output is typically the
// largest string in the system (a long completion, partly attacker-
// influenced via RAG). Measured on a 'P'-heavy string the fuzzy path
// cost 10ms at 10KB, 74ms at 100KB and 281ms at 400KB. Above the
// ceiling we fall back to exact-only, which still catches the
// security-relevant case: a verbatim leak.
const fuzzyMatchCeiling = 64 << 10

// fuzzyContains reports whether needle appears in haystack within
// maxDist edits. Windows of len(needle)-maxDist .. len(needle)+maxDist
// are compared, so the cost is O(len(haystack) * len(needle) * maxDist).
//
// The window range matters more than it looks. Comparing only fixed-width
// windows of len(needle) catches a substitution but silently misses the
// other two common corruptions: when the model drops a character the
// window absorbs one trailing byte, and the distance comes out as 2
// (one substitution for the dropped character, one for the shift).
func fuzzyContains(haystack, needle string, maxDist int) bool {
	n := len(needle)
	// Two bytes minimum: the prefilter below reads w[1], and a needle
	// shorter than that has nothing meaningful to match.
	if n < 2 || len(haystack) < n-maxDist {
		return false
	}
	lo := max(0, n-maxDist)
	// Prefilter on the first two bytes. One byte is far too weak: the
	// canary starts "PTP-", so a single-byte test fires on any window
	// beginning with 'P' and ran the full distance matrix for each.
	for i := 0; i+n-maxDist <= len(haystack); i++ {
		for size := lo; size <= n+maxDist; size++ {
			if size < 2 || i+size > len(haystack) {
				continue
			}
			w := haystack[i : i+size]
			if w[0] == needle[0] && w[1] == needle[1] && levenshteinWithin(w, needle, maxDist) {
				return true
			}
		}
	}
	return false
}

// levenshteinWithin reports whether a and b are within max edits. It uses
// the two-row formulation to keep memory O(min(len)).
func levenshteinWithin(a, b string, maxDist int) bool {
	ar, br := []rune(a), []rune(b)
	if len(ar) == 0 {
		return len(br) <= maxDist
	}
	prev := make([]int, len(br)+1)
	cur := make([]int, len(br)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ar); i++ {
		cur[0] = i
		rowMin := cur[0]
		for j := 1; j <= len(br); j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			cur[j] = min(cur[j-1]+1, prev[j]+1, prev[j-1]+cost)
			if cur[j] < rowMin {
				rowMin = cur[j]
			}
		}
		if rowMin > maxDist {
			return false
		}
		prev, cur = cur, prev
	}
	return prev[len(br)] <= maxDist
}

// sanitizeRunes collapses control characters in evidence text, matching
// the treatment in regex.go so output findings carry the same guarantees.
func sanitizeRunes(s string) string {
	return strings.Map(sanitizeRune, s)
}

// ---------------------------------------------------------------------------
// Secret detection
// ---------------------------------------------------------------------------

// secretRule pairs a high-precision pattern with its label. Every pattern
// requires a recognisable vendor prefix or structure, so ordinary prose
// and code that merely NAMES a credential never match — see
// TestSecretScan_IgnoresVariableNames.
type secretRule struct {
	id      string
	label   string
	pattern *regexp.Regexp
}

var secretRules = []secretRule{
	{"SEC-AWS-AKID", "aws_access_key_id", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"SEC-GITHUB-TOKEN", "github_token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,255}\b`)},
	{"SEC-SLACK", "slack_token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	{"SEC-GOOGLE", "google_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{"SEC-OPENAI", "openai_api_key", regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b`)},
	{"SEC-STRIPE", "stripe_key", regexp.MustCompile(`\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b`)},
	{"SEC-PEM", "private_key_block", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----`)},
	{"SEC-BEARER", "bearer_token", regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}`)},
	{"SEC-JWT", "jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}`)},
}

// matchFindingsCap bounds how many findings scanSecrets and scanPII
// emit per rule on a single response. A real leak has a handful of
// distinct credentials at most; a dump of identical-looking keys
// (someone copy-pasted a thousand AWS IDs into a single reply) is the
// case the cap protects against — the first N are reported and a
// summary Finding flags the rest. The cap matters because the JSON
// output and any downstream consumer iterating Findings is otherwise
// unbounded on attacker-targeted inputs.
const matchFindingsCap = 32

// scanSecrets returns a Finding for the first matching secret rule, or nil
// when the text looks clean. With redact set, the matched value is
// replaced in Evidence so the finding can be logged safely; without it
// the raw value is retained for audit.
//
// Per rule, at most matchFindingsCap findings are emitted; the rest
// fold into one summary Finding. This guards against dump-style inputs
// (a response pasting a thousand AWS keys) inflating the result slice.
func scanSecrets(text string, redact bool) []*Finding {
	if text == "" {
		return nil
	}
	var findings []*Finding
	for _, r := range secretRules {
		// FindAllIndex so a response leaking two credentials reports
		// both — the previous version returned on the first match and
		// lost the second.
		locs := r.pattern.FindAllStringIndex(text, -1)
		for i, loc := range locs {
			if i == matchFindingsCap {
				findings = append(findings, &Finding{
					Layer:    layerOutput,
					Rule:     r.id,
					Category: CategoryDataExfiltration,
					Score:    0.95,
					Evidence: fmt.Sprintf("possible %s: +%d more matches omitted (flood)",
						r.label, len(locs)-matchFindingsCap),
				})
				break
			}
			findings = append(findings, secretFinding(r, text, loc, redact))
		}
	}
	return findings
}

func secretFinding(r secretRule, text string, loc []int, redact bool) *Finding {
	if redact {
		// Keep surrounding context so a triage reader can see what
		// the secret was attached to, but never the secret itself.
		const ctx = 32
		before := max(0, loc[0]-ctx)
		after := min(len(text), loc[1]+ctx)
		return &Finding{
			Layer:    layerOutput,
			Rule:     r.id,
			Category: CategoryDataExfiltration,
			Score:    0.95,
			// No Span: it would resolve to the very credential this
			// branch exists to keep out of the Result. PII keeps its
			// span because the caller already holds that text and the
			// asymmetry is deliberate (see WithRedaction).
			Evidence: fmt.Sprintf("possible %s: %q [REDACTED:%s] %q",
				r.label, sanitizeRunes(text[before:loc[0]]), r.label,
				sanitizeRunes(text[loc[1]:after])),
		}
	}
	return &Finding{
		Layer:    layerOutput,
		Rule:     r.id,
		Category: CategoryDataExfiltration,
		Score:    0.95,
		Span:     &Span{Start: loc[0], End: loc[1]},
		Evidence: fmt.Sprintf("possible %s: %s", r.label, sanitizeRunes(text[loc[0]:loc[1]])),
	}
}

// ---------------------------------------------------------------------------
// PII detection
// ---------------------------------------------------------------------------

var piiRules = []secretRule{
	{"PII-EMAIL", "email", regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)},
	// Phone numbers require an explicit international prefix or a
	// parenthesised area code. A bare "123-456-7890" is deliberately NOT
	// matched: that shape is far more often an order number, account
	// number, or reference code, and this scanner reads model output,
	// which is exactly where those appear.
	{"PII-INTL-PHONE", "phone", regexp.MustCompile(`\+[1-9]\d{0,2}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{2,4}[\s.-]?\d{2,4}\b`)},
	{"PII-US-PHONE", "phone", regexp.MustCompile(`\(\d{3}\)\s?\d{3}[\s.-]\d{4}\b`)},
}

// piiCardPattern matches a bare 13-19 digit run; the Luhn check in
// scanPII is what makes this safe, since a digit run alone is far too
// common (order IDs, timestamps, version strings).
var piiCardPattern = regexp.MustCompile(`\b\d{13,19}\b`)

// scanPII returns one Finding per PII match, or nil. Email and phone are
// matched structurally; card-like digit runs must additionally pass Luhn,
// which is what keeps order numbers and timestamps out of the results.
//
// Like scanSecrets, every hit is reported — a single response can carry
// an email and a card (or several of each), and a triage operator who
// fixed the email should not be left thinking there was no card. The
// per-rule count is capped at matchFindingsCap (with a summary Finding
// for the rolled-up remainder) to keep Result.Findings bounded on
// dump-style inputs.
func scanPII(text string) []*Finding {
	if text == "" {
		return nil
	}
	var out []*Finding
	for _, r := range piiRules {
		locs := r.pattern.FindAllStringIndex(text, -1)
		for i, loc := range locs {
			if i == matchFindingsCap {
				out = append(out, &Finding{
					Layer:    layerOutput,
					Rule:     r.id,
					Category: CategoryDataExfiltration,
					Score:    0.70,
					Evidence: fmt.Sprintf("possible %s: +%d more matches omitted (flood)",
						r.label, len(locs)-matchFindingsCap),
				})
				break
			}
			out = append(out, &Finding{
				Layer:    layerOutput,
				Rule:     r.id,
				Category: CategoryDataExfiltration,
				Score:    0.70,
				Span:     &Span{Start: loc[0], End: loc[1]},
				Evidence: fmt.Sprintf("possible %s: [REDACTED:%s]", r.label, r.label),
			})
		}
	}
	if locs := piiCardPattern.FindAllStringIndex(text, -1); len(locs) > 0 {
		var kept int
		var dropped int
		for _, loc := range locs {
			if text[loc[0]:loc[1]] == "" || !luhnValid(text[loc[0]:loc[1]]) {
				continue
			}
			if kept >= matchFindingsCap {
				dropped++
				continue
			}
			out = append(out, &Finding{
				Layer:    layerOutput,
				Rule:     "PII-CARD",
				Category: CategoryDataExfiltration,
				Score:    0.85,
				Span:     &Span{Start: loc[0], End: loc[1]},
				Evidence: "possible payment_card_number: [REDACTED:payment_card_number]",
			})
			kept++
		}
		if dropped > 0 {
			out = append(out, &Finding{
				Layer:    layerOutput,
				Rule:     "PII-CARD",
				Category: CategoryDataExfiltration,
				Score:    0.85,
				Evidence: fmt.Sprintf("possible payment_card_number: +%d more matches omitted (flood)", dropped),
			})
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// luhnValid implements the Luhn checksum used by payment card numbers.
func luhnValid(s string) bool {
	sum := 0
	double := false
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
		d := int(s[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}
