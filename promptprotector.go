// Package promptprotector provides layered detection for prompt-injection
// attempts in Go LLM applications.
//
// # Pipeline
//
// Every input passes through L1 then L2, and the findings are fused into
// a single score mapped to Allow, Warn, or Block:
//
//	L1 normalize   recursive decode (base64/hex/percent/unicode-escape),
//	               zero-width and RTL-override characters, homoglyphs,
//	               Shannon-entropy runs, and context padding. Emits
//	               mechanism categories (encoding_attack, zero_width,
//	               rtl_override, homoglyph, high_entropy,
//	               context_padding).
//	L2 regex       the ruleset — see DefaultRuleset and ParseRuleset —
//	               matched against three forms: the raw input, the
//	               canonical whole-string decoding, and any further
//	               base64-substring payloads found in the raw input.
//	               Emits intent categories (instruction_override,
//	               role_hijack, prompt_leak, delimiter_framing,
//	               data_exfiltration, social_engineering).
//
// ScanOutput adds an output-side check for canary leaks, secrets, and
// PII. See the package-level ScanInput, ScanUntrusted, and ScanOutput.
//
// # Fusion
//
//	score = maxSignal * 0.7 + corroboration * 0.3
//
// maxSignal is the strongest single finding, scaled by layer confidence so
// a pile of weak heuristics cannot outvote one authored rule. corroboration
// sums the best hit per distinct category with diminishing returns, which
// is what separates a single odd character from an obfuscation campaign.
//
// # Scope
//
// This package guards prompt INJECTION, not harmful content. Classifying
// "how do I make a bomb" is content moderation, a different product.
//
// It raises the cost of an attack; it does not prevent one. Every
// published detector is bypassed by adversarial encoding, paraphrase, or
// character injection. Pair it with least-privilege tool scopes,
// role-tagged messaging, output validation, and promptbuilder.Wrap.
package promptprotector
