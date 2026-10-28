package promptprotector_test

import (
	"context"
	"testing"

	"github.com/inful/promptprotector"
	"github.com/inful/promptprotector/testutil"
)

// The generalisation gate.
//
// deepset/prompt-injections has a `test` split of 116 rows that was
// never vendored until now. It was held out on purpose: the ruleset was
// tuned against the `train` split, and a split you tune against cannot
// measure generalisation.
//
// This file reads that split for the first time. Whatever it reports is
// the number to believe, because nothing in the ruleset was derived from
// it. The rule change that accompanied this commit was derived from the
// TRAIN misses alone — see regression13_test.go — and happens to catch
// two of the rows here.
//
// The result is not flattering: 22.7% scoped against 48.6% on the split
// the ruleset was tuned against. The gap is the finding. It says the
// ruleset matches phrasings it has seen, and that the corpus contains
// attack families the ruleset has never met.
//
// The split is committed under testdata/generalisation/ rather than
// testdata/holdout/ because it is no longer held out: it has now been
// read, scored, and its misses inspected. It is a measurement set from
// here on, and the ruleset must not be tuned against it again.
func TestGeneralisationGate_Recall(t *testing.T) {
	samples := testutil.LoadCorpus(t, "testdata/generalisation/injections.jsonl")

	d, err := promptprotector.New()
	if err != nil {
		t.Fatal(err)
	}
	hit := func(s testutil.Sample) (bool, []string) {
		res, err := d.ScanInput(context.Background(), s.Text)
		if err != nil {
			t.Fatalf("%s: %v", s.ID, err)
		}
		return res.Decision != promptprotector.Allow, nil
	}
	fired := func(s testutil.Sample) bool {
		ok, _ := hit(s)
		return ok
	}

	all := make([]testutil.Sample, 0, len(samples))
	for _, s := range samples {
		s.Scope = ""
		all = append(all, s)
	}
	unscoped := testutil.MeasureRecall(all, hit)
	t.Logf("GENERALISATION unscoped recall: %d/%d = %.1f%%",
		unscoped.Detected, unscoped.Total, unscoped.Rate()*100)

	scoped := testutil.MeasureRecall(testutil.Filter(samples, testutil.ScopeEnglishInScope), hit)
	t.Logf("GENERALISATION scoped recall:   %d/%d = %.1f%%",
		scoped.Detected, scoped.Total, scoped.Rate()*100)

	// The by-mechanism split is where the shortfall is diagnosable.
	byMech := map[string][2]int{}
	for _, s := range testutil.Filter(samples, testutil.ScopeEnglishInScope) {
		ok := fired(s)
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

	// A floor, well below what the ruleset achieves, so that a change
	// which makes generalisation worse fails CI. The point of the floor
	// is to catch a regression, not to pin the number.
	testutil.AssertRecall(t, "generalisation unscoped", unscoped, 0.05)
	testutil.AssertRecall(t, "generalisation scoped", scoped, 0.15)
}

// F1: the generalisation split must not have false positives either. A
// detector that misses most attacks but blocks real prompts is worse
// than one that misses attacks.
func TestGeneralisationGate_FalsePositiveRate(t *testing.T) {
	samples := testutil.LoadCorpus(t, "testdata/generalisation/clean.jsonl")

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
	t.Logf("generalisation false positives on %d clean prompts: %d flagged = %.1f%%",
		report.Total, len(report.Missed), report.Rate()*100)

	testutil.AssertFalsePositiveRate(t, "generalisation clean", report, 0.05)
}
