// Package testutil loads the JSONL corpora under testdata/ and turns
// them into the two measurements the release gates are written in
// terms of: detection recall on known injections, and the false-positive
// rate on known-clean text.
//
// The format is deliberately small and stable, so a corpus can be
// vendored as a short sample slice (see testdata/SOURCES.md) and read
// back without a schema dependency. One JSON object per line:
//
//	{"id": "...", "text": "...", "label": 1, ...}
//
// label follows the deepset/prompt-injections convention that the
// corpora are drawn from: 0 is clean, 1 is an injection.
package testutil

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// Sample is one corpus line.
//
// Scope exists because part of every public prompt-injection corpus is
// not prompt injection. deepset/prompt-injections, for example, labels
// persuasion and manipulation tasks ("answer in the style of a colonial
// gentleman: why is Christianity important?") as positives, which this
// library explicitly does not attempt — its README calls content
// moderation and stylisation "a different product". Those samples are
// marked scope="out_of_scope" so recall is computed over what the
// library claims to catch, and the excluded count is reported rather
// than silently dropped.
//
// Expect records the encoding a sample uses ("base64", "hex", ...) and
// defaults to "plain". The encoding gate uses it to assert that a
// decoder fired, not merely that some rule matched the decoded text.
type Sample struct {
	ID     string `json:"id"`
	Text   string `json:"text"`
	Label  int    `json:"label"`
	Source string `json:"source,omitempty"`
	Scope  string `json:"scope,omitempty"`
	Expect string `json:"expect,omitempty"`

	// KnownGap marks a labelled injection the library documents as
	// missed. Such samples are excluded from the recall gate and asserted
	// not to Block instead, so a gap that turns into a false block is
	// still caught, and a gap that gets fixed shows up as a sample the
	// gate silently stopped excluding.
	KnownGap string `json:"known_gap,omitempty"`

	// Rules optionally names the rules that should fire. Empty means
	// "some rule", which is what most samples want: pinning a specific
	// rule ID makes the corpus a test of the ruleset rather than of
	// detection.
	Rules []string `json:"rules,omitempty"`
}

// ScopeOutOfScope marks a labelled injection the library does not attempt.
const ScopeOutOfScope = "out_of_scope"

// LoadCorpus reads a JSONL corpus. It fails the test rather than
// returning an empty slice, because a silently-empty corpus turns every
// recall measurement into 100%.
func LoadCorpus(t testing.TB, path string) []Sample {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open corpus: %v", err)
	}
	defer func() { _ = f.Close() }()

	var out []Sample
	sc := bufio.NewScanner(f)
	// Some injected prompts are long; the default 64 KiB line limit is
	// generous but the scanner is the thing that would truncate them.
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		var s Sample
		if err := json.Unmarshal([]byte(raw), &s); err != nil {
			t.Fatalf("%s:%d: %v", path, line, err)
		}
		if s.Text == "" {
			t.Fatalf("%s:%d: sample %q has empty text", path, line, s.ID)
		}
		if s.Expect == "" {
			s.Expect = "plain"
		}
		out = append(out, s)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	if len(out) == 0 {
		t.Fatalf("%s: corpus is empty; every recall measurement would be a vacuous 100%%", path)
	}
	return out
}

// Report is the result of measuring a corpus.
type Report struct {
	Total    int
	Detected int
	Missed   []Sample // in-scope samples nothing fired on
	Excluded int      // labelled injection but marked out of scope
}

// Rate is the fraction detected, over in-scope samples only.
func (r Report) Rate() float64 {
	if r.Total == 0 {
		return 0
	}
	return float64(r.Detected) / float64(r.Total)
}

// MeasureRecall scores a corpus. A sample counts as detected when the
// decision is above Allow, or — for samples naming specific rules — when
// one of those rules fired.
func MeasureRecall(samples []Sample, verdict func(Sample) (bool, []string)) Report {
	var r Report
	for _, s := range samples {
		if s.Label != 1 {
			continue
		}
		if s.Scope == ScopeOutOfScope {
			r.Excluded++
			continue
		}
		r.Total++
		ok, _ := verdict(s)
		if ok {
			r.Detected++
			continue
		}
		r.Missed = append(r.Missed, s)
	}
	return r
}

// AssertRecall fails the test when recall is below min, listing every
// missed sample. The list is the point: a percentage with no failures
// attached cannot be acted on.
func AssertRecall(t testing.TB, label string, r Report, minRate float64) {
	t.Helper()
	t.Logf("%s: recall %d/%d = %.1f%% (%d out-of-scope excluded)",
		label, r.Detected, r.Total, r.Rate()*100, r.Excluded)
	for _, s := range r.Missed {
		t.Logf("  MISSED %-24s [%s] %.60q", s.ID, s.Expect, s.Text)
	}
	if rate := r.Rate(); rate < minRate {
		t.Errorf("%s: recall %.1f%% is below the %.0f%% gate (%d missed)", label, rate*100, minRate*100, len(r.Missed))
	}
}

// MeasureFalsePositives counts clean samples that were flagged.
func MeasureFalsePositives(samples []Sample, flagged func(Sample) bool) Report {
	var r Report
	for _, s := range samples {
		if s.Label != 0 {
			continue
		}
		r.Total++
		if flagged(s) {
			r.Missed = append(r.Missed, s)
		}
	}
	return r
}

// AssertFalsePositiveRate fails the test when the rate is above max.
func AssertFalsePositiveRate(t testing.TB, label string, r Report, maxRate float64) {
	t.Helper()
	rate := r.Rate()
	if r.Total > 0 {
		t.Logf("%s: %d/%d clean samples flagged = %.1f%%", label, len(r.Missed), r.Total, rate*100)
	}
	for _, s := range r.Missed {
		t.Logf("  FLAGGED %-24s %.60q", s.ID, s.Text)
	}
	if rate > maxRate {
		t.Errorf("%s: false-positive rate %.1f%% is above the %.0f%% gate (%d of %d)",
			label, rate*100, maxRate*100, len(r.Missed), r.Total)
	}
}

// FiredRule returns the rules that fired for a scan, for the corpus'
// optional per-sample expectation.
func FiredRule(fired []string) func(string) bool {
	set := make(map[string]bool, len(fired))
	for _, f := range fired {
		set[f] = true
	}
	return func(rule string) bool { return set[rule] }
}

// Describe renders a sample's metadata for a failure message.
func Describe(s Sample) string {
	return fmt.Sprintf("%s [%s] %s", s.ID, s.Expect, s.Source)
}
