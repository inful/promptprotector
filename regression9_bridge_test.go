package promptprotector

import (
	"github.com/inful/promptprotector/internal/entropy"
	"github.com/inful/promptprotector/internal/unicode"
	"github.com/inful/promptprotector/promptbuilder"
)

// Bridges to the internal packages for the regression tests, which live
// in the root package where the exported API is.
func homoglyphSpansForTest(s string) []unicode.Span { return unicode.Homoglyph(s) }
func shannonForTest(s string) float64               { return entropy.Shannon(s) }
func extractPPBForTest(s string) string             { return promptbuilder.ExtractCanary(s) }

// extractFirstForTest mirrors what promptbuilder.ExtractCanary does, so
// the two can be compared for agreement.
func extractFirstForTest(system string) string {
	all := extractCanaries(system)
	if len(all) == 0 {
		return ""
	}
	return all[0]
}
