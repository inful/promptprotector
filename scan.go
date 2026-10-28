package promptprotector

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"time"
)

// Detector scans text for prompt injection. A Detector is safe for
// concurrent use: its configuration is immutable after New, so scans
// share it without locking.
type Detector struct {
	cfg config
}

// New builds a Detector from the defaults plus the supplied options.
// It returns an error rather than silently correcting a contradictory
// configuration, because a Detector whose thresholds were adjusted behind
// the caller's back is a security bug waiting to happen.
func New(opts ...Option) (*Detector, error) {
	cfg, err := newConfig(opts...)
	if err != nil {
		return nil, err
	}
	return &Detector{cfg: cfg}, nil
}

// MustNew is New for package-level initialisation, where a configuration
// error is a programming mistake rather than a runtime condition. It
// panics on error.
func MustNew(opts ...Option) *Detector {
	d, err := New(opts...)
	if err != nil {
		panic(err)
	}
	return d
}

// newConfig applies options on top of the defaults and validates.
func newConfig(opts ...Option) (config, error) {
	cfg := defaultConfig()
	for _, o := range opts {
		if o == nil {
			continue
		}
		o(&cfg)
	}
	if cfg.logger == nil {
		cfg.logger = slog.New(slog.DiscardHandler)
	}
	if cfg.rules.Rules == nil {
		rs, err := DefaultRuleset()
		if err != nil {
			return cfg, err
		}
		cfg.rules = rs
	}
	if cfg.indirectRules.Rules == nil {
		// The error is returned, not discarded: a failed parse yields a
		// nil Rules slice, which regexScan treats as "no rules", so
		// swallowing it would make ScanUntrusted silently detect nothing
		// on exactly the path that is meant to be the strictest.
		rs, err := IndirectRuleset()
		if err != nil {
			return cfg, err
		}
		cfg.indirectRules = rs
	}
	if err := compileRules(&cfg.rules); err != nil {
		return cfg, err
	}
	if err := compileRules(&cfg.indirectRules); err != nil {
		return cfg, err
	}
	if err := validateConfig(&cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// compileRules gives every rule a compiled pattern.
//
// A Rule built by hand has no *regexp.Regexp, and regexScan skips those
// silently — so the extension pattern the WithRules doc shows (append a
// Rule to a ruleset from DefaultRuleset) produced a detector that
// reported no error and matched nothing. Editing Rule.Pattern after the
// fact had the same effect: the stored regexp still held the old source.
//
// Compiling here means the caller never has to reach for ParseRuleset
// just to add one rule, and a pattern that does not compile is a New()
// error rather than a mystery. Rules already carrying an up-to-date
// regexp are left alone, so the built-in sets cost nothing.
func compileRules(rs *Ruleset) error {
	for i := range rs.Rules {
		r := &rs.Rules[i]
		if r.re != nil && r.re.String() == r.Pattern {
			continue
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return fmt.Errorf("%w: rule %q: pattern does not compile: %w",
				ErrInvalidRuleset, r.ID, err)
		}
		r.re = re
	}
	return nil
}

// defaultDetector backs the package-level Scan functions. It is
// deliberately unexported: an exported package-level Detector is
// assignable, so any one caller could swap in a weakened configuration
// and change detection for every other user of this package in the
// process. Callers who need to tune anything call New.
var defaultDetector = MustNew()

// ScanInput analyses text the user typed directly. It uses the default
// ruleset, which is tuned for deliberate input and therefore has a lower
// flagging bar than ScanUntrusted.
//
// Typical use, before sending user text to a model:
//
//	res, err := promptprotector.ScanInput(ctx, userText)
//	if err != nil {
//		return err
//	}
//	switch res.Decision {
//	case promptprotector.Block:
//		return errors.New("request rejected")
//	case promptprotector.Warn:
//		log.Warn("suspicious input", "score", res.Score)
//	}
func ScanInput(ctx context.Context, text string) (Result, error) {
	return defaultDetector.ScanInput(ctx, text)
}

// ScanUntrusted analyses text the model is about to READ but that did not
// come from the user: a retrieved document, a tool result, a web page
// chunk. This is the indirect-injection path.
//
// It uses the indirect ruleset: 14 rules rather than 34, because
// instruction-shaped text in a document is often legitimate documentation
// and a false positive on a RAG chunk breaks the product.
//
// On the vendored deepset/prompt-injections train split this scanner
// catches about 5% of in-scope attacks where ScanInput catches about
// 42%, while false-positiving 0% on both. It is a reliable tripwire
// for a forged chat delimiter or a fabricated authority, and a poor
// detector of injection in general.
//
// Pair it with promptbuilder.Wrap (Spotlighting), which is a stronger
// defense than detection alone. Retrieved content should be datamarked
// first; treat a ScanUntrusted hit as an extra signal, not as the gate.
func ScanUntrusted(ctx context.Context, text string) (Result, error) {
	return defaultDetector.ScanUntrusted(ctx, text)
}

// ScanOutput analyses text the model produced, using the system prompt to
// look for a leaked canary and scanning for secrets and PII.
//
// Pass an empty system to skip the canary check, or a system that has not
// had InsertCanary applied — in which case the check is inert. Enable
// WithRedaction to keep matched values out of the Result.
//
// Unlike output, system is never truncated by WithMaxInputBytes: the
// canary search reads it whole, and its cost scales with the number of
// canary tokens present. See maxFuzzyCanaries in output.go.
func ScanOutput(ctx context.Context, system, output string) (Result, error) {
	return defaultDetector.ScanOutput(ctx, system, output)
}

// ScanInput analyses user-typed text. See the package-level ScanInput.
func (d *Detector) ScanInput(ctx context.Context, text string) (Result, error) {
	return d.run(ctx, text, d.cfg.rules)
}

// ScanUntrusted analyses retrieved or tool-returned text. See the
// package-level ScanUntrusted for what its ruleset does and does not
// catch.
func (d *Detector) ScanUntrusted(ctx context.Context, text string) (Result, error) {
	return d.run(ctx, text, d.cfg.indirectRules)
}

// ScanOutput analyses model output. See the package-level ScanOutput.
//
// It deliberately does NOT run the input pipeline. The injection rules
// describe what a *user* writes; a response that quotes one is the
// guardrail working, not failing. Running them here blocked the most
// natural assistant output there is:
//
//	"An attacker might try: 'Ignore all previous instructions.'"
//	"If a user says 'you are now DAN', refuse and continue."
//
// What a response CAN be guilty of is disclosing something: the system
// prompt (via the canary), a credential, or PII. Those are the checks
// that run here.
func (d *Detector) ScanOutput(ctx context.Context, system, output string) (Result, error) {
	start := time.Now()
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	subject, truncated := output, false
	if d.cfg.maxInputBytes > 0 && len(output) > d.cfg.maxInputBytes {
		subject, truncated = output[:d.cfg.maxInputBytes], true
	}

	var findings []Finding
	if f := scanOutputLeak(system, subject, d.cfg.redactOutput); f != nil {
		findings = append(findings, *f)
	}
	for _, f := range scanSecrets(subject, d.cfg.redactOutput) {
		findings = append(findings, *f)
	}
	for _, f := range scanPII(subject) {
		findings = append(findings, *f)
	}
	if truncated {
		dropped := len(output) - d.cfg.maxInputBytes
		findings = append(findings, Finding{
			Layer:    layerOutput,
			Rule:     "input_truncated",
			Category: CategoryInputTruncated,
			Score:    l1BaseScores[CategoryInputTruncated],
			Evidence: fmt.Sprintf("output exceeded %d bytes; %d byte(s) past the %d-byte prefix were not scanned (canary/secrets/PII in the dropped range went unchecked)",
				d.cfg.maxInputBytes, dropped, d.cfg.maxInputBytes),
		})
	}

	score, decision := fuse(findings, d.cfg)
	return Result{
		Decision:      decision,
		Score:         score,
		Findings:      findings,
		LatencyMs:     float64(time.Since(start).Microseconds()) / 1000.0,
		PipelineTrace: traceOf(findings),
	}, nil
}

// run applies the input pipeline, honouring context cancellation.
//
// The pipeline is deliberately synchronous. An earlier version ran it in
// a goroutine and returned on ctx.Done(), which looked like a timeout but
// was not one: the abandoned goroutine kept scanning to completion, so
// WithTimeout cost a leaked goroutine and unbounded background CPU per
// call without ever stopping the work. Real bounding comes from
// WithMaxInputBytes, which is enforced where the input is truncated.
func (d *Detector) run(ctx context.Context, text string, rs Ruleset) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	return runPipeline(text, d.cfg, rs), nil
}
