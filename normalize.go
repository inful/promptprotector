package promptprotector

import (
	"fmt"
	"strings"

	"github.com/inful/promptprotector/internal/encoders"
	"github.com/inful/promptprotector/internal/entropy"
	"github.com/inful/promptprotector/internal/padding"
	"github.com/inful/promptprotector/internal/unicode"
)

// normalize is the L1 layer. It recursively decodes the input, then scans
// both the raw and the decoded form for unicode anomalies and high-entropy
// runs, emitting a Finding for each distinct signal.
//
// Scanning both forms is deliberate: attackers split payloads precisely to
// defeat single-pass checks, so a homoglyph hidden inside a base64 wrapper
// is only visible after decoding. The cost is one extra regex/entropy pass
// over a short decoded string.
func normalize(raw string, cfg config) NormalizeResult {
	res := NormalizeResult{Raw: raw}

	subject := raw
	if cfg.maxInputBytes > 0 && len(raw) > cfg.maxInputBytes {
		subject = raw[:cfg.maxInputBytes]
		res.Truncated = true
		// Keep Raw in step with what was actually scanned. runPipeline
		// hands this to L2, so leaving the full input here would let the
		// regex layer work past the cap.
		res.Raw = subject
	}

	// L1a: recursive decoding. The chain records each decoder that fired,
	// and the FIRST viable decoded form becomes res.Decoded so L2 regex
	// scans the decoded payload alongside the raw. The substring fallback
	// has a one-shot limitation — it returns the first viable base64 run
	// in source order — so normalize.go also calls ScanAllBase64Payloads
	// on the raw subject and emits a recursive_decode finding per
	// additional payload. Without this, a long benign base64 run would
	// let the substring decoder pick it and miss a smaller attack run
	// later in the same input.
	decoded, chain := encoders.RecursiveDecode(subject, cfg.decodeDepth)
	if len(chain) > 0 && decoded != subject {
		res.Decoded = decoded
		res.Chain = chain
		res.Findings = append(res.Findings, Finding{
			Layer:    layerL1,
			Rule:     "recursive_decode",
			Category: CategoryEncodingAttack,
			Score:    l1BaseScores[CategoryEncodingAttack],
			Evidence: fmt.Sprintf("decoded via %s", strings.Join(chain, " → ")),
		})
	}
	// Surface every viable base64 substring as its own finding AND
	// scan each with L2 rules. Without the L2 scan here, a payload the
	// canonical recursion skipped would only emit "I decoded base64"
	// without revealing whether the payload actually contains an attack.
	// The cap mirrors matchFindingsCap in output.go.
	const additionalCap = 32
	if cfg.decodeDepth > 0 {
		for _, payload := range encoders.ScanAllBase64Payloads(subject, additionalCap) {
			// Skip the payload that already became res.Decoded — its
			// findings have been emitted via scanForms (decoded form).
			if payload == decoded {
				continue
			}
			res.Findings = append(res.Findings, Finding{
				Layer:    layerL1,
				Rule:     "recursive_decode",
				Category: CategoryEncodingAttack,
				Score:    l1BaseScores[CategoryEncodingAttack],
				Evidence: fmt.Sprintf("decoded via base64-substr (additional payload: %q)",
					truncateForEvidence(payload)),
			})
			// L2 regex on the additional decoded payload, so a long benign
			// base64 run cannot hide a sibling attack encoded later in
			// the same input.
			res.Findings = append(res.Findings, regexScan(cfg.rules, payload, "decoded-substr")...)
		}
	}

	// L1b/L1c: scan each distinct form.
	for _, form := range scanForms(subject, res.Decoded) {
		res.Findings = append(res.Findings, unicodeFindings(form.label, form.text)...)
		res.Findings = append(res.Findings, entropyFindings(cfg, form)...)
		res.Findings = append(res.Findings, paddingFindings(cfg, form)...)
	}

	if res.Truncated {
		res.Findings = append(res.Findings, Finding{
			Layer:    layerL1,
			Rule:     "input_truncated",
			Category: CategoryInputTruncated,
			Score:    l1BaseScores[CategoryInputTruncated],
			Evidence: fmt.Sprintf("input exceeded %d bytes; %d byte(s) past the %d-byte prefix were not scanned (canary/secrets/PII in the dropped range went unchecked)",
				cfg.maxInputBytes, len(raw)-cfg.maxInputBytes, cfg.maxInputBytes),
		})
	}

	return res
}

// form is one text variant to scan, tagged so a Finding's Evidence can say
// which variant produced it.
type form struct {
	label string
	text  string
}

// scanForms returns the distinct forms worth scanning: always the raw
// input, plus the decoded form when decoding actually changed something.
// When they are identical we scan once, so a clean input never produces
// duplicate findings.
func scanForms(raw, decoded string) []form {
	forms := []form{{label: "raw", text: raw}}
	if decoded != "" && decoded != raw {
		forms = append(forms, form{label: "decoded", text: decoded})
	}
	return forms
}

// maxSpanFindingsPerCategory bounds the per-(category, form) Finding
// count emitted by unicodeFindings. Without a cap an attacker can flood
// the result with thousands of disjoint zero-width-character spans and
// blow up the size of the Findings slice (and any downstream JSON
// serialization). The cap is high enough to cover any plausible real
// input, and the rolled-up "+N more" Finding preserves the signal.
const maxSpanFindingsPerCategory = 32

// maxAdditionalEvidencePayload bounds the byte count of decoded
// payloads shown in the Evidence string of a recursive_decode finding
// beyond the canonical decoded form. Without a cap, an attacker
// could plant a megabyte-long base64 substring and pull a megabyte
// into the Evidence field that the operator then has to log.
const maxAdditionalEvidencePayload = 64

// truncateForEvidence returns s truncated to maxAdditionalEvidencePayload
// runes, with an ellipsis appended when truncated.
func truncateForEvidence(s string) string {
	const sample = maxAdditionalEvidencePayload
	count := 0
	for i := range s {
		if count == sample {
			return s[:i] + "…"
		}
		count++
	}
	return s
}

// unicodeFindings converts unicode.Anomaly records into Findings, one
// per (category, span) — not one per anomaly — so a triage UI that uses
// Finding.Span for highlighting points at the right region even when an
// input has multiple disjoint homoglyph runs. Per-(category, form) the
// count is capped at maxSpanFindingsPerCategory and the rest fold into
// one summary Finding whose Span is nil and whose Evidence reports the
// real number of omitted spans.
//
// unicode.Scan is called once; the anomalies are grouped by category
// first so the summary can state the true overflow rather than the cap.
func unicodeFindings(label, text string) []Finding {
	type group struct {
		category Category
		detector string
		spans    []unicode.Span
	}
	var groups []group
	index := map[Category]int{}
	for _, anomaly := range unicode.Scan(text) {
		cat, ok := unicodeCategoryFor(anomaly.Category)
		if !ok {
			continue
		}
		i, seen := index[cat]
		if !seen {
			groups = append(groups, group{category: cat, detector: anomaly.Category})
			i = len(groups) - 1
			index[cat] = i
		}
		groups[i].spans = append(groups[i].spans, anomaly.Spans...)
	}

	var out []Finding
	for _, g := range groups {
		for i, sp := range g.spans {
			if i >= maxSpanFindingsPerCategory {
				break
			}
			out = append(out, Finding{
				Layer:    layerL1,
				Rule:     g.detector,
				Category: g.category,
				Score:    l1BaseScores[g.category],
				Span:     &Span{Start: sp.Start, End: sp.End},
				Evidence: fmt.Sprintf("%s: span [%d,%d)", label, sp.Start, sp.End),
			})
		}
		if extra := len(g.spans) - maxSpanFindingsPerCategory; extra > 0 {
			out = append(out, Finding{
				Layer:    layerL1,
				Rule:     g.detector,
				Category: g.category,
				Score:    l1BaseScores[g.category],
				Evidence: fmt.Sprintf("%s: +%d more spans omitted (flood)", label, extra),
			})
		}
	}
	return out
}

// entropyFindings emits a high-entropy finding when the sliding-window
// detector finds a qualifying span.
func entropyFindings(cfg config, f form) []Finding {
	run := entropy.LongestHighEntropyRun(f.text, cfg.entropyWindow, cfg.entropyThreshold)
	if run.End <= run.Start {
		return nil
	}
	return []Finding{{
		Layer:    layerL1,
		Rule:     "high_entropy_run",
		Category: CategoryHighEntropy,
		Score:    l1BaseScores[CategoryHighEntropy],
		Span:     &Span{Start: run.Start, End: run.End},
		Evidence: fmt.Sprintf("%s: %.2f bits/byte over %d bytes", f.label, run.Entropy, run.End-run.Start),
	}}
}

// paddingFindings emits context-padding findings for repeated-line and
// separator-fence anomalies. These were folded in from the planned L3
// structural layer, which was redundant with L1 and L2 except for this
// detector — see the PLAN.md note on the 1E scope reduction.
func paddingFindings(cfg config, f form) []Finding {
	th := padding.Default()
	th.MinRepeats = cfg.paddingMinRepeats
	th.MinFenceLines = cfg.paddingMinFences

	spans := padding.Detect(f.text, th)
	if len(spans) == 0 {
		return nil
	}
	out := make([]Finding, 0, len(spans))
	for _, s := range spans {
		out = append(out, Finding{
			Layer:    layerL1,
			Rule:     string(s.Kind),
			Category: CategoryContextPadding,
			Score:    l1BaseScores[CategoryContextPadding],
			Span:     &Span{Start: s.Start, End: s.End},
			Evidence: fmt.Sprintf("%s: %s over %d lines", f.label, s.Detail, s.Lines),
		})
	}
	return out
}

// unicodeCategoryFor maps an internal unicode detector name to a public
// Category. Unknown names are skipped rather than invented, so adding a
// detector upstream can't silently produce a bogus category.
func unicodeCategoryFor(name string) (Category, bool) {
	switch name {
	case "zero_width":
		return CategoryZeroWidth, true
	case "rtl_override":
		return CategoryRTLOverride, true
	case "homoglyph":
		return CategoryHomoglyph, true
	default:
		return "", false
	}
}
