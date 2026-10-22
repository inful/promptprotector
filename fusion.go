package promptprotector

import (
	"math"
	"time"
)

// runPipeline executes L1 then L2 over an input and fuses the result into
// a Decision. This is the internal engine; the Detector in scan.go is a
// thin wrapper around it.
func runPipeline(input string, cfg config, rs Ruleset) Result {
	start := time.Now()

	// L1: normalization, decoding, structural signals. normalize also
	// runs L2 over any extra base64-substring payloads, so it needs rs.
	norm := normalize(input, cfg, rs)
	findings := norm.Findings

	// L2: authored rules, applied to every distinct form. Scanning the
	// decoded form matters: an attack wrapped in base64 still trips the
	// same rule the clear text would.
	//
	// norm.Raw, not input: normalize truncates to maxInputBytes and
	// stores the capped string there. Using the original input here would
	// let L2 scan the whole thing and report spans past the documented
	// cap, which is the only bound a caller has on this work.
	for _, f := range scanForms(norm.Raw, norm.Decoded) {
		findings = append(findings, regexScan(rs, f.text, f.label)...)
	}

	score, decision := fuse(findings, cfg)

	return Result{
		Decision:      decision,
		Score:         score,
		Findings:      findings,
		LatencyMs:     float64(time.Since(start).Microseconds()) / 1000.0,
		PipelineTrace: traceOf(findings),
	}
}

// fuse collapses per-layer findings into a single score in [0,1] and maps
// that score to a Decision.
//
// The formula has two independent terms:
//
//	maxScore        the strongest single signal. One high-confidence rule
//	                hit (0.95 for a forged chat template) must dominate —
//	                a pile of weak obfuscation signals should not
//	                outvote one certain finding.
//
//	corroboration   a bonus for several DISTINCT categories firing. This
//	                is what separates "one odd character" from "an
//	                obfuscation campaign": an attacker who triggers
//	                instruction_override AND encoding_attack AND
//	                role_hijack is doing something a benign prompt is
//	                not.
//
// Contributions are weighted by layer confidence, because an authored
// rule (L2) is a far stronger signal than a heuristic structural check
// (L1): a rule has been reviewed against a benign corpus, whereas an
// entropy threshold is a guess.
//
// The formula is intentionally simple enough to explain during triage:
//
//	score = clamp(maxScore * 0.7 + corroboration * 0.3, 0, 1)
//
// Note on thresholds: every shipped authored rule has weight >= 0.85,
// which means any single L2 hit saturates maxScore into Block territory.
// The Warn path is reachable only from L1 weak signals on their own or
// from several distinct category firings; add a low-weight rule expecting
// it to trigger Warn and the corroboration term is what carries it there.
func fuse(findings []Finding, cfg config) (float64, Decision) {
	if len(findings) == 0 {
		return 0, Allow
	}

	var maxScore float64
	bestByCat := make(map[Category]float64)
	for _, f := range findings {
		weighted := f.Score * layerConfidence(f.Layer)
		if weighted > maxScore {
			maxScore = weighted
		}
		if prev, ok := bestByCat[f.Category]; !ok || weighted > prev {
			bestByCat[f.Category] = weighted
		}
	}

	// Corroboration sums the best contribution per DISTINCT category, with
	// diminishing returns: the second category is worth 60% of the first,
	// the third 36%, and so on. Without diminishing returns a prompt
	// triggering ten weak signals would saturate the scale.
	var corroboration float64
	weight := 1.0
	for _, v := range sortedValuesDesc(bestByCat) {
		corroboration += v * weight
		weight *= 0.6
	}
	corroboration = math.Min(corroboration, 1.0)

	score := maxScore*cfg.fusionMaxWeight + corroboration*cfg.fusionCorrobWeight
	if score > 1 {
		score = 1
	}

	if cfg.logger != nil {
		cfg.logger.Debug("promptprotector scan",
			"decision", decide(score, cfg),
			"score", score,
			"findings", len(findings),
			"categories", len(bestByCat),
		)
	}

	return score, decide(score, cfg)
}

// layerConfidence scales a finding by how trustworthy its producing layer
// is. Authored, corpus-tested rules outrank heuristic structural checks.
func layerConfidence(layer string) float64 {
	switch layer {
	case layerL2:
		return 1.0
	case layerL1:
		return 0.85
	case layerOutput:
		// An output finding is a CONFIRMED incident, not a probabilistic
		// signal: a canary that appears in the response proves the system
		// prompt leaked, and a prefixed credential is a live key. These
		// are evidence, not risk estimates, so they are not discounted.
		return 1.0
	default:
		return 0.85
	}
}

// decide maps a fused score to a verdict.
func decide(score float64, cfg config) Decision {
	switch {
	case score >= cfg.blockAbove:
		return Block
	case score >= cfg.warnAbove:
		return Warn
	default:
		return Allow
	}
}

// traceOf returns the distinct layer names that produced findings, in the
// order first seen.
func traceOf(findings []Finding) []string {
	var trace []string
	seen := make(map[string]bool, 3)
	for _, f := range findings {
		if !seen[f.Layer] {
			seen[f.Layer] = true
			trace = append(trace, f.Layer)
		}
	}
	return trace
}

// sortedValuesDesc returns a map's values in descending order. Sorting is
// by value rather than by category name so the corroboration bonus is
// deterministic regardless of map iteration order — Go randomises map
// iteration, which would otherwise make fused scores non-reproducible.
func sortedValuesDesc(m map[Category]float64) []float64 {
	values := make([]float64, 0, len(m))
	for _, v := range m {
		values = append(values, v)
	}
	// Insertion sort: the slice is tiny (one entry per distinct category).
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] > values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
	return values
}
