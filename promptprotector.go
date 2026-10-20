// Package promptprotector provides layered detection for prompt-injection
// attempts in Go LLM applications.
//
// The pipeline runs every input through four deterministic layers and one
// optional escalation tier:
//
//	L1 normalize   recursive decoding (base64/hex/url/rot13/unicode-escape)
//	               and zero-width / RTL / homoglyph cleanup.
//	L2 regex       a YAML-driven ruleset tagged by OWASP LLM01:2025
//	               categories, with per-rule weights and ceilings.
//	L3 structural  entropy, special-token presence, delimiter frames,
//	               unicode-category anomalies.
//	L4 fusion      weighted score + per-category corroboration bonus,
//	               mapped to Allow / Warn / Block thresholds.
//	L6 decide      opt-in escalation via github.com/inful/decide for
//	               ambiguous cases (score in the 0.4-0.7 band).
//
// Phase 0 establishes the module so downstream tooling (lint, formatter,
// importer) has a Go file to analyse. The public API lands in Phase 1.
package promptprotector
