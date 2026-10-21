package promptprotector

import (
	"fmt"
	"log/slog"
	"time"
)

// Option customises a Detector. Options are applied to a copy of the
// default configuration, so passing the same option to two Detectors
// cannot make them interfere.
type Option func(*config)

// WithRules replaces the built-in ruleset. Pass the result of
// ParseRuleset on your own ruleset text.
//
// Use this to tune the default ruleset in place:
//
//	base, _ := promptprotector.DefaultRuleset()
//	base.Rules = append(base.Rules, myExtraRule)
//	guard := promptprotector.New(promptprotector.WithRules(base))
func WithRules(rs Ruleset) Option {
	return func(c *config) { c.rules = rs }
}

// WithIndirectRules replaces the ruleset used by ScanUntrusted.
func WithIndirectRules(rs Ruleset) Option {
	return func(c *config) { c.indirectRules = rs }
}

// WithThresholds sets the Warn and Block cut-offs. Both must be in
// [0,1] with warn <= block; an inverted pair is rejected by New.
//
// A stricter pairing suits a regulated domain; a looser one suits a
// developer tool where a false positive costs more than a miss.
func WithThresholds(warnAbove, blockAbove float64) Option {
	return func(c *config) {
		c.warnAbove = warnAbove
		c.blockAbove = blockAbove
	}
}

// WithDecodeDepth caps how many encoding layers L1 will peel. The default
// is 3, which covers the overwhelming majority of real payloads while
// bounding the work an attacker can force. Set 0 to disable decoding.
func WithDecodeDepth(depth int) Option {
	return func(c *config) { c.decodeDepth = depth }
}

// WithEntropyThreshold sets the bits/byte above which a window counts as
// high entropy. Raise it toward 6.0 to detect binary blobs only; lower it
// to catch more base64-of-text at the cost of false positives on dense
// prose. Set to 0 to disable the entropy check.
func WithEntropyThreshold(bits float64) Option {
	return func(c *config) { c.entropyThreshold = bits }
}

// WithMaxInputBytes caps how much input is scanned. Input beyond the cap
// is truncated and the result carries a truncation finding. Set 0 to
// remove the cap.
//
// Cost: the scan is O(cap) across both raw and decoded forms, plus O(n)
// for secret/PII/canary passes. Measured on a 2026-class CPU: 32 KiB
// benign input scans in ~50 ms; with the cap disabled, 2 MiB takes
// ~2.7 s. Anything called in the request path should keep the cap.
func WithMaxInputBytes(n int) Option {
	return func(c *config) { c.maxInputBytes = n }
}

// WithRedaction controls SECRET redaction in output findings. Without
// it, matched credentials are retained in Evidence for audit. PII
// (email, phone, card) is always redacted regardless of this flag — the
// asymmetry is intentional, so the same Evidence field always treats
// personal data safely while the security/audit trade-off stays a
// caller choice for credentials. Only enable redaction when the sink
// is trusted, but assume PII is always safe to log.
func WithRedaction(on bool) Option {
	return func(c *config) { c.redactOutput = on }
}

// WithTimeout is accepted and ignored.
//
// The pipeline is CPU-bound string work with no blocking call, so a
// context cannot interrupt it: an earlier implementation ran the scan in
// a goroutine and returned on ctx.Done(), which leaked the goroutine and
// kept the CPU busy rather than cancelling anything. Bounding a scan is
// WithMaxInputBytes's job.
//
// It remains in the API so existing call sites keep compiling, and so
// this behaviour is documented rather than surprising.
func WithTimeout(time.Duration) Option {
	return func(*config) {}
}

// WithLogger attaches a logger. The detector logs at Debug for the
// decisions it makes and never logs scanned content at any level — input
// is untrusted and must not reach a log sink verbatim.
func WithLogger(l *slog.Logger) Option {
	return func(c *config) { c.logger = l }
}

// ErrInvalidConfig is returned by New for a contradictory configuration.
var ErrInvalidConfig = fmt.Errorf("invalid configuration")

func validateConfig(c *config) error {
	switch {
	case c.warnAbove < 0 || c.warnAbove > 1:
		return fmt.Errorf("%w: warnAbove must be in [0,1], got %v", ErrInvalidConfig, c.warnAbove)
	case c.blockAbove < 0 || c.blockAbove > 1:
		return fmt.Errorf("%w: blockAbove must be in [0,1], got %v", ErrInvalidConfig, c.blockAbove)
	case c.warnAbove > c.blockAbove:
		return fmt.Errorf("%w: warnAbove (%v) must not exceed blockAbove (%v)",
			ErrInvalidConfig, c.warnAbove, c.blockAbove)
	case c.decodeDepth < 0:
		return fmt.Errorf("%w: decodeDepth must be >= 0, got %d", ErrInvalidConfig, c.decodeDepth)
	case c.entropyThreshold < 0:
		return fmt.Errorf("%w: entropyThreshold must be >= 0, got %v", ErrInvalidConfig, c.entropyThreshold)
	}
	return nil
}
