package promptprotector

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Rule is one authored detection pattern.
//
// Rules live in the root package rather than a rules/ subpackage because
// Rule.Category is a Category, which is defined here — a subpackage would
// have to import the root while the root imports it for the embedded
// default ruleset, which is an import cycle. The ruleset FILES still live
// under rules/ (go:embed permits subdirectory paths).
//
// A Rule's compiled pattern (*re) is intentionally shared after a copy:
// RE2 is safe for concurrent reads and rebuilding it on every WithRules
// call would slow scan setups for no benefit. The other fields
// (ID/Category/Weight/Pattern) are value-copied so caller mutations do
// not silently alter a Detector — see cloneRuleset.
type Rule struct {
	// ID is a stable identifier used in Finding.Rule and in triage logs.
	// Never reuse an ID for different logic; deprecate instead.
	ID string
	// Category classifies what the rule detects.
	Category Category
	// Weight is the rule's own confidence in 0..1, before cross-layer
	// fusion. Weights are authored, not derived from match count.
	Weight float64
	// Pattern is the raw Go (RE2) regular expression source.
	Pattern string

	// re is the compiled pattern, populated by ParseRuleset.
	re *regexp.Regexp
}

// cloneRuleset returns a deep copy of rs: a fresh slice whose every
// Rule carries its own ID/Category/Weight/Pattern values. The compiled
// *regexp.Regexp is shared because RE2 is goroutine-safe to share and
// rebuilding it on every Detector construction would slow scan setup.
//
// This closes F2/F3: a caller who mutates a returned Ruleset's Weight
// or ID does not silently change Detectors that already absorbed the
// values.
func cloneRuleset(rs Ruleset) Ruleset {
	// Only a nil slice is collapsed, so WithRules(Ruleset{Rules: []Rule{}})
	// keeps meaning "no rules" — newConfig reads nil as "caller did not
	// supply one". Collapsing empty as well made an empty ruleset silently
	// become the 34-rule default, the opposite of what the caller asked.
	if rs.Rules == nil {
		return Ruleset{}
	}
	out := make([]Rule, len(rs.Rules))
	copy(out, rs.Rules)
	return Ruleset{Rules: out}
}

// Ruleset is an ordered collection of rules. Order is source order and is
// preserved so Finding output is stable and diffable.
type Ruleset struct {
	Rules []Rule
}

// ErrInvalidRuleset is returned by ParseRuleset for any malformed input.
// Use errors.Is to detect it; the wrapped error carries a human-readable
// reason including the offending rule ID where known.
var ErrInvalidRuleset = errors.New("invalid ruleset")

// knownCategories gates the `category:` field so a typo cannot silently
// produce findings in an unexported category.
var knownCategories = map[Category]bool{
	CategoryInstructionOverride: true,
	CategoryRoleHijack:          true,
	CategoryPromptLeak:          true,
	CategoryJailbreak:           true,
	CategoryDelimiterFraming:    true,
	CategoryDataExfiltration:    true,
	CategorySocialEngineering:   true,
}

// ParseRuleset parses the line-oriented ruleset format:
//
//	# Comments run from '#' at the start of a line to end of line.
//	# Blank lines separate rules. Within a rule each line is "key: value"
//	# and only the FIRST colon separates the two, so patterns may contain
//	# colons freely. Required keys: id, category, weight, pattern.
//
// We deliberately do not use YAML: Go's standard library has no YAML
// parser, and the plan calls for a zero-dependency core through Phase 3.
// Writing a YAML subset parser would be more code and more surprising
// than a four-key line format.
//
// Every rule is validated eagerly — unknown keys, unknown categories,
// out-of-range weights, duplicate IDs and patterns that fail to compile
// are all errors. Silently ignoring a misspelled "weigth:" would leave
// the rule at its zero weight and quietly disable it.
func ParseRuleset(src string) (Ruleset, error) {
	// Non-nil from the start: a ruleset file with every rule commented out
	// parses to zero rules, which is what the author asked for, rather
	// than nil, which means "unset" and gets the default back.
	rs := Ruleset{Rules: []Rule{}}
	seen := make(map[string]bool)

	for i, block := range splitBlocks(src) {
		rule, err := parseBlock(block, i+1)
		if err != nil {
			return Ruleset{}, err
		}
		if rule == nil {
			continue
		}
		if seen[rule.ID] {
			return Ruleset{}, fmt.Errorf("%w: duplicate rule id %q (block %d)", ErrInvalidRuleset, rule.ID, i+1)
		}
		seen[rule.ID] = true
		rs.Rules = append(rs.Rules, *rule)
	}
	return rs, nil
}

// splitBlocks splits on blank lines and drops comment-only blocks.
func splitBlocks(src string) []string {
	var blocks []string
	var cur []string
	flush := func() {
		if len(cur) > 0 {
			blocks = append(blocks, strings.Join(cur, "\n"))
			cur = nil
		}
	}
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			flush()
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		cur = append(cur, trimmed)
	}
	flush()
	return blocks
}

// parseBlock parses one rule block. Returns (nil, nil) for an empty block.
func parseBlock(block string, blockNum int) (*Rule, error) {
	rule := &Rule{}
	var haveWeight bool
	seen := map[string]bool{}

	for _, line := range strings.Split(block, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("%w: block %d: line %q has no ':' separator", ErrInvalidRuleset, blockNum, line)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		// Duplicate keys are silently last-wins otherwise — a rule
		// author who wrote 0.2 then 0.9 by accident would get 0.9
		// with no warning, defeating the "fail loudly on typos"
		// contract the rest of this parser enforces.
		if seen[key] {
			return nil, fmt.Errorf("%w: rule %q: duplicate key %q", ErrInvalidRuleset, rule.ID, key)
		}
		seen[key] = true

		switch key {
		case "id":
			rule.ID = value
		case "category":
			rule.Category = Category(value)
			if !knownCategories[rule.Category] {
				return nil, fmt.Errorf("%w: block %d: unknown category %q", ErrInvalidRuleset, blockNum, value)
			}
		case "weight":
			w, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return nil, fmt.Errorf("%w: rule %q: weight %q is not a number", ErrInvalidRuleset, rule.ID, value)
			}
			if w <= 0 || w > 1 {
				return nil, fmt.Errorf("%w: rule %q: weight %v out of range (0,1]", ErrInvalidRuleset, rule.ID, w)
			}
			rule.Weight = w
			haveWeight = true
		case "pattern":
			rule.Pattern = value
		default:
			return nil, fmt.Errorf("%w: block %d: unknown key %q", ErrInvalidRuleset, blockNum, key)
		}
	}

	for name, value := range map[string]string{
		"id": rule.ID, "category": string(rule.Category), "pattern": rule.Pattern,
	} {
		if value == "" {
			return nil, fmt.Errorf("%w: block %d: missing required key %q", ErrInvalidRuleset, blockNum, name)
		}
	}
	if !haveWeight {
		return nil, fmt.Errorf("%w: rule %q: missing required key \"weight\"", ErrInvalidRuleset, rule.ID)
	}

	re, err := regexp.Compile(rule.Pattern)
	if err != nil {
		return nil, fmt.Errorf("%w: rule %q: pattern does not compile: %w", ErrInvalidRuleset, rule.ID, err)
	}
	rule.re = re
	return rule, nil
}
