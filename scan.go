package promptprotector

import (
	"context"
	"fmt"
	"log/slog"
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
		rs, _ := IndirectRuleset()
		cfg.indirectRules = rs
	}
	if err := validateConfig(&cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// Default is a ready-to-use Detector built from the shipped defaults. Use
// New instead when you need to tune anything.
var Default = MustNew()

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
	return Default.ScanInput(ctx, text)
}

// ScanUntrusted analyses text the model is about to READ but that did not
// come from the user: a retrieved document, a tool result, a web page
// chunk. This is the indirect-injection path.
//
// It uses the indirect ruleset, which is stricter than the default,
// because instruction-shaped text in a document is often legitimate
// documentation. Pair it with promptbuilder.Wrap (Spotlighting), which is
// a stronger defense than detection alone.
func ScanUntrusted(ctx context.Context, text string) (Result, error) {
	return Default.ScanUntrusted(ctx, text)
}

// ScanOutput analyses text the model produced, using the system prompt to
// look for a leaked canary and scanning for secrets and PII.
//
// Pass an empty system to skip the canary check, or a system that has not
// had InsertCanary applied — in which case the check is inert. Enable
// WithRedaction to keep matched values out of the Result.
func ScanOutput(ctx context.Context, system, output string) (Result, error) {
	return Default.ScanOutput(ctx, system, output)
}

// ScanInput analyses user-typed text. See the package-level ScanInput.
func (d *Detector) ScanInput(ctx context.Context, text string) (Result, error) {
	return d.run(ctx, text, d.cfg.rules)
}

// ScanUntrusted analyses retrieved or tool-returned text. See the
// package-level ScanUntrusted.
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
	if f := scanOutputLeak(system, subject); f != nil {
		findings = append(findings, *f)
	}
	for _, f := range scanSecrets(subject, d.cfg.redactOutput) {
		findings = append(findings, *f)
	}
	if f := scanPII(subject); f != nil {
		findings = append(findings, *f)
	}
	if truncated {
		findings = append(findings, Finding{
			Layer:    layerOutput,
			Rule:     "input_truncated",
			Category: CategoryInputTruncated,
			Score:    l1BaseScores[CategoryInputTruncated],
			Evidence: fmt.Sprintf("output exceeded %d bytes; scanned the prefix only", d.cfg.maxInputBytes),
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
