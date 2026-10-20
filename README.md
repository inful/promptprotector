# promptprotector

Layered prompt-injection detector for Go LLM applications. Direct user input, retrieved/tool
context (indirect injection), and LLM output (canary + secrets/PII) all flow through the same
pipeline: L1 normalize → L2 regex ruleset → L3 structural → L4 score fusion, with an optional
L6 escalation tier via [`decide`](https://github.com/inful/decide) for ambiguous cases.

## NOT a silver bullet

This library raises the cost of attacking your LLM app. It does not eliminate prompt injection.
Every published detector is bypassed by adversarial character injection, encoding, or paraphrasing
([Hackett et al. 2025](https://aclanthology.org/2025.llmsec-1.8/)). Use promptprotector together
with:

- **least-privilege tool scopes** — the model never has raw `exec` or DB access
- **role-tagged messaging** — system / user / tool roles instead of concatenated strings
- **output validation** — never act on a tool/function call without checking parameters
- **Spotlighting** — wrap untrusted retrieved text in datamarks before it enters the context
  (see `promptbuilder.Wrap`)

If you want zero-detection-rate injection defense, the answer is to not pass untrusted text to the
LLM. This library helps you do detection well, not pretend detection is enough.

## License

GPL-3.0-or-later. See [LICENSE](./LICENSE).

## Status

Pre-release. v0.1 is the first shippable release; see [PLAN.md](./PLAN.md) for the phased roadmap.

## Install (library)

```go
import "github.com/inful/promptprotector"
```

Phase 0 ships only the scaffolding; the library lands in v0.1.

## Install (CLI)

```bash
go install github.com/inful/promptprotector/cmd/pprotector@latest
```

Binary name is `pprotector` (avoids `pp`, which is already `/usr/bin/pp` on macOS — the
PostScript pretty-printer — and a homebrew formula).

## More

- [PLAN.md](./PLAN.md) — full architecture, phases, dataset & metrics, risks.
- [docs/DESIGN.md](./docs/DESIGN.md) — research findings that motivate the design.
- [docs/BENCHMARKS.md](./docs/BENCHMARKS.md) — evaluation methodology and datasets.
