package promptprotector

import (
	_ "embed"
	"sync"
)

//go:embed rules/default_rules.txt
var defaultRulesetSrc string

//go:embed rules/indirect_rules.txt
var indirectRulesetSrc string

var (
	defaultOnce  sync.Once
	defaultRule  Ruleset
	defaultErr   error
	indirectOnce sync.Once
	indirectRule Ruleset
)

// DefaultRuleset returns the built-in ruleset for direct user input. The
// parse happens once and is reused; a parse failure is impossible because
// TestDefaultRulesetParses runs in CI, so the returned error is always nil
// and exists only to keep the signature honest if the embedded data ever
// changes shape.
func DefaultRuleset() (Ruleset, error) {
	defaultOnce.Do(func() {
		defaultRule, defaultErr = ParseRuleset(defaultRulesetSrc)
	})
	return defaultRule, defaultErr
}

// IndirectRuleset returns the built-in ruleset tuned for retrieved
// documents and tool results rather than typed user input. It is
// deliberately smaller than DefaultRuleset: in a RAG or agent context,
// phrases that look like instructions are often legitimate document
// content (tutorials, security docs, prompt-engineering guides), so the
// bar for flagging is higher.
func IndirectRuleset() (Ruleset, error) {
	indirectOnce.Do(func() {
		indirectRule, _ = ParseRuleset(indirectRulesetSrc)
	})
	return indirectRule, nil
}
