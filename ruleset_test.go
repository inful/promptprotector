package promptprotector

import (
	"strings"
	"testing"
)

const sampleRuleset = `# A comment line, ignored.

id: PI-001
category: instruction_override
weight: 0.90
pattern: (?i)\bignore\s+previous\b

id: JB-001
category: jailbreak
weight: 0.95
pattern: (?i)\byou are now DAN\b
`

func TestParseRuleset_ReadsAllFields(t *testing.T) {
	rs, err := ParseRuleset(sampleRuleset)
	if err != nil {
		t.Fatalf("ParseRuleset returned error: %v", err)
	}
	if len(rs.Rules) != 2 {
		t.Fatalf("ParseRuleset got %d rules, want 2", len(rs.Rules))
	}

	first := rs.Rules[0]
	if first.ID != "PI-001" {
		t.Errorf("Rules[0].ID = %q, want PI-001", first.ID)
	}
	if first.Category != CategoryInstructionOverride {
		t.Errorf("Rules[0].Category = %q, want %q", first.Category, CategoryInstructionOverride)
	}
	if first.Weight != 0.90 {
		t.Errorf("Rules[0].Weight = %v, want 0.90", first.Weight)
	}
	if !strings.Contains(first.Pattern, `ignore\s+previous`) {
		t.Errorf("Rules[0].Pattern = %q, want it to contain the raw pattern", first.Pattern)
	}
}

func TestParseRuleset_CompilesPatternEagerly(t *testing.T) {
	rs, err := ParseRuleset(sampleRuleset)
	if err != nil {
		t.Fatalf("ParseRuleset returned error: %v", err)
	}
	for _, r := range rs.Rules {
		if r.re == nil {
			t.Errorf("rule %s has nil compiled regexp; ParseRuleset must compile eagerly", r.ID)
		}
	}
}

func TestParseRuleset_RejectsInvalidRegexp(t *testing.T) {
	// "(?i)unclosed" — a group that is never closed.
	src := "id: BAD-1\ncategory: jailbreak\nweight: 0.5\npattern: (?i)(unclosed\n"
	_, err := ParseRuleset(src)
	if err == nil {
		t.Fatal("ParseRuleset(invalid regex) returned nil error, want a compile failure")
	}
	if !strings.Contains(err.Error(), "BAD-1") {
		t.Errorf("error %q should name the offending rule ID", err)
	}
}

func TestParseRuleset_RejectsUnknownCategory(t *testing.T) {
	src := "id: BAD-2\ncategory: not_a_real_category\nweight: 0.5\npattern: hello\n"
	_, err := ParseRuleset(src)
	if err == nil {
		t.Fatal("ParseRuleset(unknown category) returned nil error, want a validation failure")
	}
}

func TestParseRuleset_RejectsOutOfRangeWeight(t *testing.T) {
	src := "id: BAD-3\ncategory: jailbreak\nweight: 1.5\npattern: hello\n"
	if _, err := ParseRuleset(src); err == nil {
		t.Fatal("ParseRuleset(weight=1.5) returned nil error, want a range failure")
	}
}

func TestParseRuleset_RejectsMissingRequiredField(t *testing.T) {
	src := "id: BAD-4\ncategory: jailbreak\npattern: hello\n" // no weight
	_, err := ParseRuleset(src)
	if err == nil {
		t.Fatal("ParseRuleset(missing weight) returned nil error, want a validation failure")
	}
}

func TestParseRuleset_RejectsDuplicateID(t *testing.T) {
	src := "id: DUP\ncategory: jailbreak\nweight: 0.5\npattern: a\n\n" +
		"id: DUP\ncategory: jailbreak\nweight: 0.5\npattern: b\n"
	_, err := ParseRuleset(src)
	if err == nil {
		t.Fatal("ParseRuleset(duplicate id) returned nil error, want a validation failure")
	}
}

func TestParseRuleset_EmptyInputIsValidEmptyRuleset(t *testing.T) {
	rs, err := ParseRuleset("")
	if err != nil {
		t.Fatalf("ParseRuleset(empty) returned error: %v", err)
	}
	if len(rs.Rules) != 0 {
		t.Errorf("ParseRuleset(empty) got %d rules, want 0", len(rs.Rules))
	}
}

func TestParseRuleset_CommentOnlyIsValidEmptyRuleset(t *testing.T) {
	rs, err := ParseRuleset("# nothing here\n\n# really nothing\n")
	if err != nil {
		t.Fatalf("ParseRuleset(comments only) returned error: %v", err)
	}
	if len(rs.Rules) != 0 {
		t.Errorf("ParseRuleset(comments only) got %d rules, want 0", len(rs.Rules))
	}
}

func TestParseRuleset_PatternMayContainColon(t *testing.T) {
	// Only the FIRST colon separates key from value; the rest is verbatim.
	src := "id: C-1\ncategory: jailbreak\nweight: 0.5\npattern: (?i)^note: something\n"
	rs, err := ParseRuleset(src)
	if err != nil {
		t.Fatalf("ParseRuleset returned error: %v", err)
	}
	if rs.Rules[0].Pattern != `(?i)^note: something` {
		t.Errorf("Pattern = %q, want %q", rs.Rules[0].Pattern, `(?i)^note: something`)
	}
}

func TestParseRuleset_UnknownKeyIsAnError(t *testing.T) {
	// Typos in a ruleset should fail loudly rather than be ignored —
	// a silently-dropped "weigth:" would leave a rule at default weight.
	src := "id: T-1\ncategory: jailbreak\nweigth: 0.5\npattern: hello\n"
	if _, err := ParseRuleset(src); err == nil {
		t.Fatal("ParseRuleset(unknown key) returned nil error, want a validation failure")
	}
}

func TestParseRuleset_AllowsHashInsidePattern(t *testing.T) {
	// '#' only starts a comment at the beginning of a line. Patterns
	// legitimately contain it (e.g. an explicit \x23 or a char class).
	src := "id: H-1\ncategory: jailbreak\nweight: 0.5\npattern: (?i)#[a-z]+\n"
	if _, err := ParseRuleset(src); err != nil {
		t.Fatalf("ParseRuleset(hash in pattern) returned error: %v", err)
	}
}

func TestParseRuleset_PreservesSourceOrder(t *testing.T) {
	rs, err := ParseRuleset(sampleRuleset)
	if err != nil {
		t.Fatalf("ParseRuleset returned error: %v", err)
	}
	if rs.Rules[0].ID != "PI-001" || rs.Rules[1].ID != "JB-001" {
		t.Errorf("rule order = [%s %s], want [PI-001 JB-001]", rs.Rules[0].ID, rs.Rules[1].ID)
	}
}
