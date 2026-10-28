package promptprotector_test

import (
	"context"
	"testing"

	"github.com/inful/promptprotector"
	"github.com/inful/promptprotector/testutil"
)

// The v0.1 gates from PLAN.md, run against the vendored train split:
//
//	Detection recall: ≥ 90 % on a holdout
//	FP rate:          ≤ 5 % on benign
//
// Neither target is met. Both numbers are asserted against what the
// library actually does today, so a regression fails CI, and the gap to
// the plan's targets is logged on every run rather than discovered once.
//
// The corpus is the full deepset/prompt-injections train split, vendored
// and annotated under testdata/train/. See testdata/SOURCES.md for how
// the annotations were assigned and for the composition breakdown.
//
// Two recall figures are reported, and they answer different questions:
//
//   - Unscoped: over every labelled positive, exactly as the upstream
//     corpus defines them. This is the number a reader gets by pasting a
//     corpus row into the library with no filtering.
//   - Scoped: over the English positives that use a mechanism this
//     library claims to detect (testutil.ScopeEnglishInScope). The
//     upstream corpus mixes in German translations and content requests
//     — persuasion, stylisation, brand persona — that this library does
//     not attempt.
//
// The scoped figure is the one to quote when comparing against another
// detector, because it measures the same population. The unscoped figure
// is the one to quote when describing what a reader of the upstream
// corpus will see.
func TestCorpusGate_Recall(t *testing.T) {
	samples := testutil.LoadCorpus(t, "testdata/train/injections.jsonl")

	d, err := promptprotector.New()
	if err != nil {
		t.Fatal(err)
	}
	hit := func(s testutil.Sample) (bool, []string) {
		res, err := d.ScanInput(context.Background(), s.Text)
		if err != nil {
			t.Fatalf("%s: %v", s.ID, err)
		}
		rules := make([]string, 0, len(res.Findings))
		for _, f := range res.Findings {
			rules = append(rules, f.Rule)
		}
		return res.Decision != promptprotector.Allow, rules
	}

	// Unscoped: every labelled positive, exactly as the upstream corpus
	// defines it. The scope marking is cleared so nothing is excluded.
	all := make([]testutil.Sample, 0, len(samples))
	for _, s := range samples {
		s.Scope = ""
		all = append(all, s)
	}
	unscoped := testutil.MeasureRecall(all, hit)
	t.Logf("UNSCOPED recall: %d/%d = %.1f%%  (PLAN.md target: 90%%)",
		unscoped.Detected, unscoped.Total, unscoped.Rate()*100)

	// Scoped: the English positives whose attack mechanism this library
	// claims to detect.
	scoped := testutil.MeasureRecall(testutil.Filter(samples, testutil.ScopeEnglishInScope), hit)
	t.Logf("SCOPED recall:   %d/%d = %.1f%%  (%d excluded: not English, or out of scope)",
		scoped.Detected, scoped.Total, scoped.Rate()*100, unscoped.Total-scoped.Total)

	// By mechanism, so the shortfall is diagnosable rather than a number.
	byMech := map[string][2]int{}
	for _, s := range testutil.Filter(samples, testutil.ScopeEnglishInScope) {
		ok, _ := hit(s)
		c := byMech[s.Mechanism]
		c[1]++
		if ok {
			c[0]++
		}
		byMech[s.Mechanism] = c
	}
	for m, c := range byMech {
		t.Logf("  %-22s %d/%d", m, c[0], c[1])
	}

	// Assert current behaviour, not the target. Raising these bars is a
	// ruleset change with its own review, not a test edit.
	testutil.AssertRecall(t, "unscoped recall", unscoped, currentUnscopedRecallFloor)
	testutil.AssertRecall(t, "scoped recall", scoped, currentScopedRecallFloor)
}

// Measured against the vendored train split on 2026-10-28. These are
// floors, not goals: they exist so that a change which makes detection
// worse is caught, and are set below the measured values on purpose.
const (
	currentUnscopedRecallFloor = 0.12
	currentScopedRecallFloor   = 0.38
)

func TestCorpusGate_FalsePositiveRate(t *testing.T) {
	samples := testutil.LoadCorpus(t, "testdata/train/clean.jsonl")

	d, err := promptprotector.New()
	if err != nil {
		t.Fatal(err)
	}
	flagged := func(s testutil.Sample) bool {
		res, err := d.ScanInput(context.Background(), s.Text)
		if err != nil {
			t.Fatalf("%s: %v", s.ID, err)
		}
		return res.Decision != promptprotector.Allow
	}

	report := testutil.MeasureFalsePositives(samples, flagged)
	t.Logf("false positives on %d real user prompts (%d of them German): %d flagged = %.1f%%  "+
		"(PLAN.md target: <= 5%%)", report.Total, germanCount(samples), len(report.Missed), report.Rate()*100)

	// This one is comfortably under target and is the strongest number
	// the corpus produces. Assert it as a real gate.
	testutil.AssertFalsePositiveRate(t, "deepset clean", report, 0.05)
}

func germanCount(samples []testutil.Sample) int {
	n := 0
	for _, s := range samples {
		if s.Lang == "de" {
			n++
		}
	}
	return n
}
