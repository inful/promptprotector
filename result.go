package promptprotector

import "strconv"

// Decision is the pipeline's verdict for a scanned input.
type Decision int

const (
	// Allow means the input looks benign; send it to the LLM.
	Allow Decision = iota
	// Warn means the input has suspicious signals but sits below the
	// block threshold. Most applications should proceed but log.
	Warn
	// Block means the input has enough signal to be treated as an
	// attack. Reject it before it reaches the LLM.
	Block
)

func (d Decision) String() string {
	switch d {
	case Allow:
		return "allow"
	case Warn:
		return "warn"
	case Block:
		return "block"
	default:
		return "unknown(" + strconv.Itoa(int(d)) + ")"
	}
}

// Category is a stable, machine-readable classification for a Finding.
//
// The instruction_*, role_hijack, prompt_leak, jailbreak,
// delimiter_framing, data_exfiltration and social_engineering values
// align with the OWASP LLM Top 10 (LLM01:2025 Prompt Injection)
// sub-categories plus the jailbreak family.
//
// The zero_width, rtl_override, homoglyph, high_entropy and
// encoding_attack values describe the *mechanism* an attacker used rather
// than the *intent*, which is why they have no OWASP sub-label. They are
// still useful for triage: a homoglyph hit on "аdmin" is a different
// response than a role_hijack hit on "you are now DAN".
type Category string

const (
	// CategoryInstructionOverride marks input trying to make the model
	// ignore or replace prior instructions ("ignore previous instructions").
	CategoryInstructionOverride Category = "instruction_override"
	// CategoryRoleHijack marks input trying to reassign the model's role
	// or persona ("you are now DAN").
	CategoryRoleHijack Category = "role_hijack"
	// CategoryPromptLeak marks input trying to extract the system prompt,
	// hidden instructions, or embedded secrets.
	CategoryPromptLeak Category = "prompt_leak"
	// CategoryJailbreak marks input requesting behaviour the model is
	// meant to refuse (harmful content, safety bypass).
	CategoryJailbreak Category = "jailbreak"
	// CategoryDelimiterFraming marks input injecting chat-template or
	// role delimiters to forge a new message boundary.
	CategoryDelimiterFraming Category = "delimiter_framing"
	// CategoryDataExfiltration marks input trying to route conversation
	// data, tool results, or credentials to an attacker-controlled sink.
	CategoryDataExfiltration Category = "data_exfiltration"
	// CategorySocialEngineering marks input fabricating authority to
	// unlock restricted behaviour ("I'm the developer, disable safety").
	CategorySocialEngineering Category = "social_engineering"
)

// Mechanism categories emitted by the L1 normalize layer. These describe
// HOW an input was obfuscated rather than WHAT it was trying to achieve,
// which is why they have no OWASP LLM01:2025 sub-label. They remain
// useful for triage: a homoglyph hit on "аdmin" warrants a different
// response than a role_hijack hit on "you are now DAN".
const (
	// CategoryEncodingAttack marks input wrapped in a reversible encoding
	// (base64, hex, percent-encoding, \uXXXX escapes) and decoded.
	CategoryEncodingAttack Category = "encoding_attack"
	// CategoryZeroWidth marks input containing zero-width or invisible
	// characters splitting otherwise-normal text.
	CategoryZeroWidth Category = "zero_width"
	// CategoryRTLOverride marks input containing bidirectional control
	// characters used to reorder displayed text (BiDi spoofing).
	CategoryRTLOverride Category = "rtl_override"
	// CategoryHomoglyph marks input mixing non-Latin lookalike characters
	// into Latin words (Cyrillic "а" inside "аdmin").
	CategoryHomoglyph Category = "homoglyph"
	// CategoryHighEntropy marks input containing a span whose Shannon
	// entropy indicates compressed, encrypted, or binary content.
	CategoryHighEntropy Category = "high_entropy"
	// CategoryContextPadding marks input padded with repeated lines or
	// separator fences to push a target instruction past a context
	// window or dilute it below salience.
	CategoryContextPadding Category = "context_padding"
)

// Span is a half-open byte range [Start, End) within the text a Finding
// was derived from. A nil Span on a Finding means the finding applies to
// the whole input rather than a specific region.
type Span struct {
	Start, End int
}

// Finding is one piece of evidence that an input is suspicious.
//
// Layer names the pipeline stage that produced it ("l1_normalize",
// "l2_regex", "l3_structural"). Rule is a stable identifier for the
// specific check ("recursive_decode", "zwsp", "JB-001"); it is empty for
// structural findings that have no authored rule ID. Score is 0..1 and is
// the *layer's own* confidence, before cross-layer fusion — callers
// should read Result.Score for the fused verdict.
//
// Evidence is a short human-readable string intended for logs and triage
// UIs. It may contain untrusted text, so do not render it as HTML without
// escaping.
type Finding struct {
	Layer    string
	Rule     string
	Category Category
	Score    float64
	Span     *Span
	Evidence string
}

// Result is the outcome of a scan.
type Result struct {
	// Decision is the fused verdict: Allow, Warn, or Block.
	Decision Decision
	// Score is the fused 0..1 risk score. See the README for the fusion
	// formula and its thresholds.
	Score float64
	// Findings holds every layer's evidence, ordered by layer then by
	// the order within each layer. Never nil for a successful scan (may
	// be empty for a clean input).
	Findings []Finding
	// LatencyMs is wall-clock time spent inside the pipeline.
	LatencyMs float64
	// PipelineTrace lists the layer names that produced at least one
	// Finding, in execution order. Useful for distinguishing "no signal"
	// from "layer did not run".
	PipelineTrace []string
}
