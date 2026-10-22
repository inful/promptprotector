package encoders

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestScanAllBase64Payloads_Empty(t *testing.T) {
	for _, s := range []string{"", "short", "no base64 here at all"} {
		if got := ScanAllBase64Payloads(s, 8); got != nil {
			t.Errorf("ScanAllBase64Payloads(%q) = %v, want nil", s, got)
		}
	}
}

func TestScanAllBase64Payloads_SingleAndMultiple(t *testing.T) {
	// base64SubstrRe requires >= 32 alphabet characters, so each payload
	// must be long enough to produce a 32+ char encoding.
	one := base64.StdEncoding.EncodeToString([]byte("first benign configuration payload"))
	two := base64.StdEncoding.EncodeToString([]byte("second configuration payload"))

	got := ScanAllBase64Payloads("prefix "+one+" middle "+two+" suffix", 8)
	if len(got) != 2 {
		t.Fatalf("ScanAllBase64Payloads returned %d payloads, want 2: %v", len(got), got)
	}
	if got[0] != "first benign configuration payload" {
		t.Errorf("payload[0] = %q", got[0])
	}
	if got[1] != "second configuration payload" {
		t.Errorf("payload[1] = %q", got[1])
	}
}

func TestScanAllBase64Payloads_RespectsLimit(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte(
		"configuration payload long enough to exceed the regex floor"))
	in := strings.Repeat(payload+" ", 10)

	got := ScanAllBase64Payloads(in, 3)
	if len(got) != 3 {
		t.Errorf("ScanAllBase64Payloads with limit 3 returned %d, want 3", len(got))
	}
	if ScanAllBase64Payloads(in, 0) != nil {
		t.Error("ScanAllBase64Payloads(limit 0) should be nil")
	}
}

func TestScanAllBase64Payloads_SkipsBinaryNoise(t *testing.T) {
	// "aaaa…" is valid base64 but decodes to byte soup that fails isText.
	noise := strings.Repeat("a", 64)
	if got := ScanAllBase64Payloads(noise, 8); got != nil {
		t.Errorf("binary-noise run produced payloads %v, want nil", got)
	}
}

func TestScanAllBase64Payloads_EmptyDecodeRejected(t *testing.T) {
	// A run of newlines decodes to "" via base64's whitespace handling;
	// isText("") is false so it must not appear as a payload.
	if got := ScanAllBase64Payloads(strings.Repeat("\n", 40), 8); got != nil {
		t.Errorf("whitespace run produced payloads %v, want nil", got)
	}
}
