package promptprotector

import (
	"strings"
	"testing"
)

// canaryCases covers the leak-detection contract: an exact hit, a
// one-character typo (the LLM mangled it), and a clean response.
// Canaries are generated rather than hand-written so the fixtures stay
// honest about the token format.
var canaryCases = []struct {
	name      string
	mutate    func(string) string // applied to output, not the canary
	wantLeak  bool
	skipEmpty bool
}{
	{"clean output", func(string) string { return "The weather is fine today." }, false, false},
	{"exact leak", func(c string) string { return "My instructions say " + c }, true, false},
	{"one char typo", func(c string) string { return "I was told " + c[:len(c)-1] + "z" }, true, false},
	// leakTolerance is 2 because a transposition costs two edits and a
	// one-character deletion was previously invisible to the fixed-width
	// window. Three edits stays outside it.
	{"two char typos is a leak", func(c string) string {
		return "I was told " + c[:len(c)-2] + "zz"
	}, true, false},
	{"three char typos is not a leak", func(c string) string {
		return "I was told " + c[:len(c)-3] + "zzz"
	}, false, false},
	{"truncated is not a leak", func(string) string { return "My secret is PTP-abc" }, false, false},
	{"empty output", func(string) string { return "" }, false, false},
}

func TestScanOutput_DetectsCanaryLeak(t *testing.T) {
	for _, tc := range canaryCases {
		t.Run(tc.name, func(t *testing.T) {
			canary, err := NewCanary()
			if err != nil {
				t.Fatalf("NewCanary: %v", err)
			}
			system := InsertCanary("You are a helpful assistant.", canary)
			output := tc.mutate(canary)

			res := scanOutputLeak(system, output, false)
			if got := res != nil; got != tc.wantLeak {
				t.Errorf("scanOutputLeak found leak = %v, want %v (evidence: %v)", got, tc.wantLeak, evidenceOf(res))
			}
		})
	}
}

func TestScanOutput_NoCanaryInSystemMeansNoLeakCheck(t *testing.T) {
	// A system prompt with no canary cannot leak one; the check must be
	// inert rather than guessing.
	if got := scanOutputLeak("You are a helpful assistant.", "PTP-whatever", false); got != nil {
		t.Errorf("scanOutputLeak flagged output against a canaryless system prompt: %v", evidenceOf(got))
	}
}

func TestNewCanary_IsHardToGuess(t *testing.T) {
	// The canary must not collide with a value an attacker could
	// predict, and two calls must not return the same token.
	a, err := NewCanary()
	if err != nil {
		t.Fatalf("NewCanary error: %v", err)
	}
	b, err := NewCanary()
	if err != nil {
		t.Fatalf("NewCanary error: %v", err)
	}
	if a == b {
		t.Error("NewCanary returned the same token twice; it must be random per call")
	}
	if len(a) < 16 {
		t.Errorf("canary length = %d, want at least 16 to resist guessing", len(a))
	}
}

func TestNewCanary_ProducesValidSystemPrompt(t *testing.T) {
	canary, err := NewCanary()
	if err != nil {
		t.Fatalf("NewCanary error: %v", err)
	}
	sys := InsertCanary("You are a helpful assistant.", canary)
	if !strings.Contains(sys, canary) {
		t.Error("InsertCanary did not embed the canary")
	}
	// The token must be recoverable from the prompt, since scanOutputLeak
	// has no other way to learn it.
	if got := extractCanaries(sys); len(got) != 1 || got[0] != canary {
		t.Errorf("extractCanaries round-trip failed: got %q, want [%q]", got, canary)
	}
	// The instruction must not itself look like an injection attempt, or
	// it would trip our own scanner when scanned as untrusted text.
	leak := scanOutputLeak(sys, "Something benign", false)
	if leak != nil {
		t.Errorf("InsertCanary produced a prompt that leaks itself: %v", evidenceOf(leak))
	}
}

func TestSecretScan_IgnoresVariableNames(t *testing.T) {
	// A code assistant explaining how to read a secret must not trip
	// detection — this is the canonical false-positive trap.
	benign := []string{
		`os.Getenv("AWS_SECRET_ACCESS_KEY")`,
		`const apiKey = process.env.API_KEY;`,
		"Store the password in your .env file, not in source.",
		"Rotate your access token every 90 days.",
	}
	for _, s := range benign {
		if got := scanSecrets(s, false); got != nil {
			t.Errorf("scanSecrets falsely flagged %q: %v", s, evidenceOf(got[0]))
		}
	}
}

// Credential fixtures are assembled from fragments rather than written
// as literals.
//
// These strings are structurally valid credentials, and GitHub's push
// protection blocks any push containing something that matches a known
// credential pattern — which is correct behaviour that we want working.
// Keeping the pieces separate means the detector is still tested against
// the real format while no complete credential ever exists in the tree.
//
// The patterns themselves are unaffected: what matters is that the
// concatenation produces a value the production regex must match.
var (
	// AWS access key ID: AKIA + 16 uppercase alphanumerics.
	awsKeyID = "AKIA" + "IOSFODNN7" + "EXAMPLE"
	// Slack bot token: xoxb- followed by three dash-separated groups.
	slackToken = "xoxb-" + "123456789012" + "-" + "1234567890123" + "-" +
		"abcdefghijklmnopqrstuvwx"
	// GitHub personal access token: ghp_ + 36 alphanumerics.
	githubPAT = "ghp_" + "16C7e42F292c6912" + "E7710c838347Ae178B4a"
	// Google API key: AIza + exactly 35 URL-safe characters.
	googleAPIKey = "AIza" + "AHOVCJQXELSZGNUBIPWDKRYFMTAHOVCJQXE"
)

func TestSecretScan_DetectsKnownPrefixes(t *testing.T) {
	cases := []struct{ name, input string }{
		{"aws access key id", awsKeyID},
		{"github pat", githubPAT},
		{"slack token", slackToken},
		{"google api key", googleAPIKey},
		{"private key block", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scanSecrets(tc.input, false); len(got) == 0 {
				t.Errorf("scanSecrets missed %s (%d chars)", tc.name, len(tc.input))
			}
		})
	}
}

func TestSecretFixturesMatchTheRealFormats(t *testing.T) {
	// Guards the fragments above: if someone edits one, the fixture must
	// still be a structurally valid credential or the detection test
	// above silently stops testing what it claims to.
	if len(awsKeyID) != 20 || !strings.HasPrefix(awsKeyID, "AKIA") {
		t.Errorf("awsKeyID is %d chars / prefix %q, want 20 starting AKIA", len(awsKeyID), awsKeyID[:4])
	}
	if len(googleAPIKey) != 39 || !strings.HasPrefix(googleAPIKey, "AIza") {
		t.Errorf("googleAPIKey is %d chars, want 39 starting AIza", len(googleAPIKey))
	}
	if len(githubPAT) != 40 {
		t.Errorf("githubPAT is %d chars, want 40", len(githubPAT))
	}
}

func TestSecretScan_RedactionPreservesSurroundingText(t *testing.T) {
	input := "Here is the key " + awsKeyID + " for your reference."
	got := scanSecrets(input, true)
	if len(got) == 0 {
		t.Fatal("scanSecrets found nothing")
	}
	if strings.Contains(got[0].Evidence, awsKeyID) {
		t.Error("redacted evidence still contains the raw secret")
	}
	if !strings.Contains(got[0].Evidence, "Here is the key") {
		t.Error("redacted evidence dropped the surrounding context")
	}
	if !strings.Contains(got[0].Evidence, "[REDACTED") {
		t.Error("redacted evidence has no redaction marker")
	}
}

func TestSecretScan_NoRedactionKeepsValueForAudit(t *testing.T) {
	input := "key " + awsKeyID + " here"
	got := scanSecrets(input, false)
	if len(got) == 0 {
		t.Fatal("scanSecrets found nothing")
	}
	if !strings.Contains(got[0].Evidence, awsKeyID) {
		t.Error("audit mode should retain the matched value in evidence")
	}
}

func TestSecretScan_TriggersBearerAndJWT(t *testing.T) {
	cases := []string{
		"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpX" + "VCJ9.eyJzdWIiOiIxIn0.abcdef",
		"token: Bearer sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc",
	}
	for _, c := range cases {
		if got := scanSecrets(c, false); len(got) == 0 {
			t.Errorf("scanSecrets missed bearer token in %q", c)
		}
	}
}

func TestPIIScan_DetectsEmailAndPhone(t *testing.T) {
	got := scanPII("contact me at alice@example.com or +1 555 123 4567")
	if len(got) == 0 {
		t.Fatal("scanPII found nothing in an obvious PII string")
	}
}

func TestPIIScan_IgnoresVersionStringsAndYears(t *testing.T) {
	// A naive 10-13 digit card rule fires on version numbers and long
	// numeric identifiers, which is a common false-positive source.
	benign := []string{
		"Version 1.2.3.4567 released in 2024",
		"ISO 8601 timestamp 2024-01-15T10:30:00Z",
		"HTTP 404 status code",
		"Order number 12345678901234567890 processed",
	}
	for _, s := range benign {
		if got := scanPII(s); len(got) != 0 {
			t.Errorf("scanPII falsely flagged %q: %v", s, evidenceOf(got[0]))
		}
	}
}

func TestPIIScan_DetectsValidLuhnCard(t *testing.T) {
	// 4111111111111111 is the standard test card; it passes Luhn.
	if got := scanPII("card 4111111111111111 charged"); len(got) == 0 {
		t.Error("scanPII missed a valid Luhn card number")
	}
}

func TestPIIScan_IgnoresLuhnInvalidCard(t *testing.T) {
	// Same digits, Luhn check digit corrupted: must not be reported as a
	// card number, otherwise any 16-digit ID becomes a false positive.
	if got := scanPII("id 4111111111111112"); len(got) != 0 {
		t.Errorf("scanPII flagged a Luhn-invalid 16-digit number: %v", evidenceOf(got[0]))
	}
}

func TestPIIScan_Redaction(t *testing.T) {
	got := scanPII("mail bob@corp.com now")
	if len(got) == 0 {
		t.Fatal("scanPII found nothing")
	}
	if strings.Contains(got[0].Evidence, "bob@corp.com") {
		t.Error("redacted PII evidence still contains the address")
	}
}

func evidenceOf(f *Finding) string {
	if f == nil {
		return "(no finding)"
	}
	return f.Evidence
}
