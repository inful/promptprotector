package unicode

import "testing"

func TestCount_EmptyStringReturnsZero(t *testing.T) {
	if got := Count(""); got != (Counts{}) {
		t.Errorf("Count(empty) = %+v, want zero", got)
	}
}

func TestCount_PlainAsciiIsUntrackedCategories(t *testing.T) {
	// ASCII letters are Ll/Lu/Ld/Lm, none of which Count tracks, so the
	// result is all zero. This documents that Count is intentionally
	// narrow — it exists for injection heuristics, not for full text stats.
	if got := Count("hello world 123"); got != (Counts{}) {
		t.Errorf("Count(plain) = %+v, want zero", got)
	}
}

func TestCount_GreekIsLlNotLo(t *testing.T) {
	// Greek lowercase letters like α are category 'Ll' (not 'Lo'). This
	// documents the boundary of Count's tracking: it'll catch Hebrew
	// and Han, but Greek/Cyrillic lowercase fall in 'Ll' which is not
	// tracked here. (Lo is the right call for "non-cased letters in
	// non-Latin scripts" — see Hebrew test below.)
	got := Count("αβγ")
	want := Counts{}
	if got != want {
		t.Errorf("Count(αβγ) = %+v, want %+v", got, want)
	}
}

func TestCount_CyrillicIsLlNotLo(t *testing.T) {
	got := Count("привет") // Russian "hello", all Cyrillic lowercase.
	want := Counts{}
	if got != want {
		t.Errorf("Count(привет) = %+v, want %+v", got, want)
	}
}

func TestCount_HebrewAlephIsLo(t *testing.T) {
	// Hebrew letters are uncased and live in 'Lo'.
	got := Count("אבג") // aleph, bet, gimel
	want := Counts{Lo: 3}
	if got != want {
		t.Errorf("Count(אבג) = %+v, want %+v", got, want)
	}
}

func TestCount_ChineseHanIsLo(t *testing.T) {
	got := Count("中文") // "Chinese language", 2 Han characters
	want := Counts{Lo: 2}
	if got != want {
		t.Errorf("Count(中文) = %+v, want %+v", got, want)
	}
}

func TestCount_ZeroWidthSpaceIsCf(t *testing.T) {
	got := Count("\u200B")
	want := Counts{Cf: 1}
	if got != want {
		t.Errorf("Count(ZWSP) = %+v, want %+v", got, want)
	}
}

func TestCount_RTLOverrideIsCf(t *testing.T) {
	got := Count("\u202E")
	want := Counts{Cf: 1}
	if got != want {
		t.Errorf("Count(RLO) = %+v, want %+v", got, want)
	}
}

func TestCount_PrivateUseAreaIsCo(t *testing.T) {
	// U+E000 is in the BMP Private Use Area.
	got := Count("\uE000")
	want := Counts{Co: 1}
	if got != want {
		t.Errorf("Count(PUA) = %+v, want %+v", got, want)
	}
}

func TestCount_ModifierLetterIsLm(t *testing.T) {
	// U+02B0 MODIFIER LETTER SMALL H — modifier letter category.
	got := Count("\u02B0")
	want := Counts{Lm: 1}
	if got != want {
		t.Errorf("Count(modifier-h) = %+v, want %+v", got, want)
	}
}

func TestCount_MultipleCategoriesComposed(t *testing.T) {
	// Hebrew א (Lo) + ZWSP (Cf) + PUA (Co) + modifier-h (Lm).
	got := Count("א\u200B\uE000\u02B0")
	want := Counts{Cf: 1, Co: 1, Lm: 1, Lo: 1}
	if got != want {
		t.Errorf("Count(composed) = %+v, want %+v", got, want)
	}
}

func TestCount_PlainAsciiAmongUntrackedIsIgnored(t *testing.T) {
	// Greek lowercase 'α' between ASCII letters is 'Ll' (not in Count's
	// tracked set). Only the ZWSP increments Cf.
	got := Count("aαbβc\u200Bd")
	want := Counts{Cf: 1}
	if got != want {
		t.Errorf("Count = %+v, want %+v", got, want)
	}
}
