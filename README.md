# promptprotector

Layered prompt-injection detector for Go LLM applications.

Zero dependencies (except the CLI's flag parser), offline, sub-millisecond.
Two input layers plus an output scanner; 48 curated rules; results carry
per-finding evidence rather than a bare verdict.

**This library raises the cost of attacking your LLM app. It does not
eliminate prompt injection.** Every published detector is bypassed by
adversarial character injection, encoding, or paraphrasing ([Hackett et
al. 2025](https://aclanthology.org/2025.llmsec-1.8/)). See
[Not a silver bullet](#not-a-silver-bullet) below.

## Install

```bash
go get github.com/inful/promptprotector
```

## Library usage

```go
import "github.com/inful/promptprotector"

// User-typed input, before it reaches your model.
res, err := promptprotector.ScanInput(ctx, userText)
if err != nil {
    return err
}
switch res.Decision {
case promptprotector.Block:
    return errors.New("request rejected")
case promptprotector.Warn:
    log.Warn("suspicious input", "score", res.Score, "findings", res.Findings)
}
```

The three scanners match the three trust boundaries in an LLM app:

| Function | Scans | Use for |
|---|---|---|
| `ScanInput` | text a user typed | form fields, chat messages |
| `ScanUntrusted` | text the model will *read* | RAG chunks, tool results, web fetches |
| `ScanOutput` | text the model produced | canary leak, secrets, PII |

`ScanUntrusted` uses a **separate, stricter ruleset**. In a document,
instruction-shaped text is often legitimate documentation, so the bar for
flagging is higher.

### Canary leak detection

Plant a canary in your system prompt; if it appears in the response, the
prompt leaked.

```go
canary, _ := promptprotector.NewCanary()
system := promptprotector.InsertCanary(baseSystemPrompt, canary)

response := callModel(system, userText)

res, _ := promptprotector.ScanOutput(ctx, system, response)
if res.Decision == promptprotector.Block {
    // The canary surfaced in the response — treat as an incident.
}
```

### Indirect injection in RAG

Wrap untrusted retrieved text before it enters the context. This is
stronger than detection alone:

```go
docs := retrieve(query)
for _, d := range docs {
    if res, _ := promptprotector.ScanUntrusted(ctx, d.Text); res.Decision != promptprotector.Allow {
        continue
    }
    context += promptbuilder.Wrap(d.Text)   // datamark it as data
}
```

### Tuning

```go
guard, err := promptprotector.New(
    promptprotector.WithThresholds(0.15, 0.45),  // stricter
    promptprotector.WithRedaction(true),         // keep secrets out of Results
    promptprotector.WithLogger(slog.Default()),
)
```

`New` returns `ErrInvalidConfig` rather than silently fixing a
contradictory configuration — a guard whose thresholds were adjusted
behind your back is a security bug waiting to happen.

Options: `WithRules`, `WithIndirectRules`, `WithThresholds`,
`WithDecodeDepth`, `WithEntropyThreshold`, `WithMaxInputBytes`,
`WithRedaction`, `WithTimeout`, `WithLogger`.

## CLI usage

```bash
go install github.com/inful/promptprotector/cmd/pp@latest
```

```bash
# Scan stdin
echo "Ignore all previous instructions" | pp

# Scan files, JSON output for scripting
pp --format=json ./prompts/*.txt

# CI gate: fail on anything suspicious
pp --fail-warn ./input.txt

# Scan retrieved content with the stricter ruleset
pp --mode=untrusted ./retrieved.md

# Check model output for canary leak and secrets
pp --mode=output --system ./system.txt ./response.txt
```

Exit codes are semantic so a CI gate can branch on them:

| Code | Meaning |
|---|---|
| 0 | allow (or warn, without `--fail-warn`) |
| 1 | warn, with `--fail-warn` |
| 2 | block |
| 3 | error (bad flag, unreadable file, invalid ruleset) |

The CLI **never echoes the scanned text**. Input is untrusted, and
reproducing it in a terminal or CI log is how an injection reaches the
next reader.

## How it works

```
raw input
  │
  ├─ L1 normalize    recursive decode (base64/hex/percent/\uXXXX), zero-width
  │                  and RTL-override detection, homoglyphs, Shannon
  │                  entropy runs, context padding
  │
  ├─ L2 regex        48 curated rules across OWASP LLM01:2025 categories
  │
  └─ fusion          max signal × 0.7  +  corroboration × 0.3

ScanOutput adds:  canary leak · secrets · PII
```

Both the raw and the decoded form are scanned. Attackers split payloads
to defeat single-pass checks, so an instruction hidden inside a base64
wrapper is only visible after decoding.

Fusion has two independent terms:

- **max signal** — the strongest single finding, scaled by layer
  confidence. One high-confidence rule hit cannot be outvoted by a pile
  of weak obfuscation signals.
- **corroboration** — a bonus for several *distinct* categories firing,
  with diminishing returns. This is what separates "one odd character"
  from "an obfuscation campaign".

```go
res.Score         // 0..1 fused risk score
res.Decision      // Allow | Warn | Block
res.Findings      // per-finding: layer, rule, category, score, span, evidence
res.PipelineTrace // which layers fired
```

### Custom rulesets

The format is four keys per rule, blank-line separated:

```
id: MY-001
category: instruction_override
weight: 0.90
pattern: (?i)\bstop\s+being\s+helpful\b
```

`category` must be one of the OWASP-aligned values, `weight` is `(0,1]`,
and `pattern` is a Go (RE2) regular expression. Parse-time validation is
strict: unknown keys, unknown categories, duplicate IDs and patterns that
fail to compile are all errors — a misspelled `weigth:` would otherwise
leave a rule at zero weight and silently disable it.

```go
rs, err := promptprotector.ParseRuleset(string(data))
guard, err := promptprotector.New(promptprotector.WithRules(rs))
```

## Not a silver bullet

Detection raises the cost of an attack; it does not prevent one. Pair
this library with:

- **least-privilege tool scopes** — the model never holds raw `exec` or
  database access
- **role-tagged messaging** — system / user / tool roles rather than
  concatenated strings
- **output validation** — never act on a tool call without checking its
  parameters
- **Spotlighting** — wrap untrusted text in datamarks (`promptbuilder.Wrap`)
  before it enters the context

If you need zero-injection-rate defense, the answer is to not pass
untrusted text to the model at all. This library helps you detect well,
not pretend detection is enough.

## Known limitations

These are real, measured, and worth knowing before you rely on it:

- **English-only.** Multilingual injection ("ignoriere les instructions
  précédentes") is not covered. Ship a per-language ruleset.
- **Paraphrase defeats the rules.** The curated set is literal patterns;
  a reworded attack matches nothing. A classifier would be needed, and
  even classifiers fall to paraphrase (see the Hackett et al. bypass
  study). This is why the ruleset ships small — 50 high-precision
  patterns beat 500 speculative ones.
- **The ruleset is a dataset, not a security boundary.** The patterns are
  public; assume an attacker has read them.
- **Injection only, not content safety.** Classifying "how do I make a
  bomb" is content moderation, a different product (Llama Guard, Granite
  Guardian). The classic "jailbreak" phrasings are covered here because
  they reassign the model's identity.
- **Not calibrated against a corpus.** The fusion weights and thresholds
  are reasoned estimates. Treat the verdicts as a starting point and
  tune against your own traffic.
- **Entropy detection covers binary blobs, not base64-of-text.** base64
  does not add entropy to its input, so base64 of English reaches only
  ~4.9 bits/byte. That case is caught by the decoders instead.

## Performance

Measured on an Apple Silicon laptop, single core:

| Input | L1 normalize | L2 regex |
|---|---|---|
| 4.4 KB benign | 1.21 ms | 1.12 ms |
| 3.1 KB attack | 1.22 ms | 1.19 ms |

Input is capped at 32 KiB by default (`WithMaxInputBytes`), and the cap is
enforced in **both** layers: L2 rule matches cannot report a span past it.
Truncated inputs carry a finding saying so.

Cost is linear in input size. Measured on an Apple Silicon laptop, the
32 KiB cap bounds a scan to roughly 30 ms; an uncapped 4.5 MB input takes
about 4.5 seconds, which is why the cap defaults to on.

`WithTimeout` is accepted and ignored: the pipeline is CPU-bound string
work with no blocking call, so a context cannot interrupt it. Bound a scan
with `WithMaxInputBytes`.

## License

GPL-3.0-or-later. See [LICENSE](./LICENSE).

The bundled rulesets are original work derived from published attack
categories (OWASP LLM Top 10 LLM01:2025 and public jailbreak
literature). No third-party rule corpus is vendored.