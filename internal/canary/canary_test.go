package canary

import "testing"

func TestIsHexDigit(t *testing.T) {
	for _, c := range "0123456789abcdefABCDEF" {
		if !IsHexDigit(byte(c)) {
			t.Errorf("IsHexDigit(%q) returned false", c)
		}
	}
	for _, c := range "g-zG-Z!@#$%^&*()_+-={}[]|\\:;\"'<>,.?/`~ \n\t" {
		if IsHexDigit(byte(c)) {
			t.Errorf("IsHexDigit(%q) returned true for non-hex char", c)
		}
	}
}

func TestMinHexLenFloor(t *testing.T) {
	// The floor is what stops "PTP-1234" from being a canary. Same value
	// is used by both packages.
	if MinHexLen < 8 {
		t.Errorf("MinHexLen = %d; below 8 leaves too many short identifiers in scope", MinHexLen)
	}
}

func TestPrefixes(t *testing.T) {
	if PrefixPTP != "PTP-" {
		t.Errorf("PrefixPTP = %q, want PTP-", PrefixPTP)
	}
	if PrefixPPB != "PPB-" {
		t.Errorf("PrefixPPB = %q, want PPB-", PrefixPPB)
	}
}
