package promptprotector_test

import (
	"context"
	"testing"

	"github.com/inful/promptprotector"
	"github.com/inful/promptprotector/testutil"
)

// The v0.1 gates from PLAN.md, run against the vendored dev set:
//
//	Detection recall: ≥ 90 % on a holdout
//	FP rate:          ≤ 5 % on benign
//
// Neither target is met. Both numbers are asserted against what the
// library actually does today, so a regression fails CI, and the gap to
// the plan's targets is logged on every run rather than discovered once.
//
// The unscoped recall is reported first and is the number to quote.
// The scoped figure is larger because it excludes samples whose attack
// mechanism the library does not claim to detect; it is printed for
// diagnosis, not as a headline.
func TestCorpusGate_Recall(t *testing.T) {
	samples := testutil.LoadCorpus(t, "testdata/dev/injections.jsonl")

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
	// defines it.
	all := make([]testutil.Sample, 0, len(samples))
	for _, s := range samples {
		s.Scope = "" // ignore the marking for this measurement
		all = append(all, s)
	}
	unscoped := testutil.MeasureRecall(all, hit)
	t.Logf("UNSCOPED recall: %d/%d = %.1f%%  (PLAN.md target: 90%%)",
		unscoped.Detected, unscoped.Total, unscoped.Rate()*100)

	// Scoped: only the mechanisms the README claims to detect.
	scoped := testutil.MeasureRecall(samples, hit)
	t.Logf("scoped recall:   %d/%d = %.1f%%  (%d excluded as out-of-scope)",
		scoped.Detected, scoped.Total, scoped.Rate()*100, scoped.Excluded)

	// By mechanism, so the shortfall is diagnosable rather than a number.
	byMech := map[string][2]int{}
	for _, s := range samples {
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

// Measured against this dev set on 2026-10-23. These are floors, not
// goals: they exist so that a change which makes detection worse is
// caught, and are set below the measured values on purpose.
const (
	currentUnscopedRecallFloor = 0.04
	currentScopedRecallFloor   = 0.15
)

func TestCorpusGate_FalsePositiveRate(t *testing.T) {
	samples := testutil.LoadCorpus(t, "testdata/dev/clean.jsonl")

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
	t.Logf("false positives on %d real user prompts (14 of them German): %d flagged = %.1f%%  "+
		"(PLAN.md target: <= 5%%)", report.Total, len(report.Missed), report.Rate()*100)

	// This one is comfortably under target and is the strongest number
	// the corpus produces. Assert it as a real gate.
	testutil.AssertFalsePositiveRate(t, "deepset clean", report, 0.05)
}
