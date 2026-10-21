// Command pp scans text for prompt-injection attempts.
//
// pp is a thin shell over the github.com/inful/promptprotector library.
// Everything it does is reachable from Go; the CLI exists for shell
// pipelines, CI gates, and quick triage.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/alecthomas/kong"

	"github.com/inful/promptprotector"
)

// contextBackground exists so scanOne can be exercised without threading a
// context through every call site.
func contextBackground() context.Context { return context.Background() }

// printf writes to w, ignoring the error. Every use is diagnostic output
// on a stream the caller already owns; there is nothing useful to do if
// stderr itself has failed, and letting errcheck force a handler here
// would obscure the exit-code contract that actually matters.
func printf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

// Exit codes are semantic so a CI job can branch on the verdict.
const (
	exitAllow = 0
	exitWarn  = 1
	exitBlock = 2
	exitError = 3
)

// version is overridden at build time via -ldflags.
var version = "dev"

type globals struct {
	// Rules overrides the built-in ruleset with a file in the
	// promptprotector ruleset format.
	Rules string `type:"path" help:"Path to a custom ruleset file. Replaces the built-in rules."`
	// Mode selects which scanner to run.
	Mode string `enum:"input,untrusted,output" default:"input" help:"Scanner to run: input (typed by a user), untrusted (retrieved/tool content), output (model output)."`
	// System is the system prompt, required for --mode output so the
	// canary leak check has something to look for.
	System string `type:"path" help:"Path to the system prompt. Required for --mode output."`
	// Format selects the output rendering.
	Format string `enum:"text,json" default:"text" help:"Output format."`
	// Threshold tuning.
	WarnAbove  float64 `default:"0" help:"Warn at or above this score (0 uses the library default). Must be paired with --block-above."`
	BlockAbove float64 `default:"0" help:"Block at or above this score (0 uses the library default). Must be paired with --warn-above."`
	// Redact keeps matched secrets and PII out of the output.
	Redact bool `help:"Replace matched secrets and PII with [REDACTED:...] markers."`
	// FailWarn makes a Warn verdict a non-zero exit, for CI gates that
	// should treat anything suspicious as a failure.
	FailWarn bool `help:"Exit non-zero on Warn as well as Block."`
}

// cmdScan scans one or more paths, or stdin when none are given.
type cmdScan struct {
	Paths []string `arg:"" optional:"" name:"paths" type:"path" help:"Files to scan. Reads stdin when omitted."`
}

type cmdVersion struct{}

type cli struct {
	globals
	Scan    cmdScan    `cmd:"" default:"withargs" help:"Scan files or stdin for prompt injection."`
	Version cmdVersion `cmd:"" help:"Print the version and exit."`
}

// jsonResult is the machine-readable output shape. It wraps Result so a
// consumer can tell a successful scan with findings from an error.
type jsonResult struct {
	Decision string        `json:"decision"`
	Score    float64       `json:"score"`
	Latency  float64       `json:"latency_ms"`
	Trace    []string      `json:"pipeline_trace,omitempty"`
	Findings []jsonFinding `json:"findings"`
	Error    string        `json:"error,omitempty"`
}

type jsonFinding struct {
	Layer    string  `json:"layer"`
	Rule     string  `json:"rule,omitempty"`
	Category string  `json:"category"`
	Score    float64 `json:"score"`
	Evidence string  `json:"evidence,omitempty"`
	Start    *int    `json:"span_start,omitempty"`
	End      *int    `json:"span_end,omitempty"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run is main's body, parameterised on its IO so tests can drive it
// without touching the process environment.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	var c cli
	parser := kong.Must(&c,
		kong.Name("pp"),
		kong.Description("Scan text for prompt-injection attempts."),
		kong.Exit(func(int) {}),
		kong.Vars{"version": version},
	)
	ctx, err := parser.Parse(args)
	if err != nil {
		printf(stderr, "pp: %v\n", err)
		return exitError
	}

	// Kong reports the selected command including its positional
	// arguments, e.g. "scan <paths>" rather than plain "scan". Dispatch
	// on the command name so a scan with files routes the same way as a
	// scan reading stdin.
	name := ctx.Command()
	if field, _, ok := strings.Cut(name, " "); ok {
		name = field
	}

	switch name {
	case "scan":
		return runScan(c, stdin, stdout, stderr)
	case "version":
		printf(stdout, "pp %s\n", version)
		return exitAllow
	default:
		printf(stderr, "pp: unknown command %q\n", ctx.Command())
		return exitError
	}
}

func runScan(c cli, stdin io.Reader, stdout, stderr io.Writer) int {
	detector, err := buildDetector(c.globals)
	if err != nil {
		printf(stderr, "pp: %v\n", err)
		return exitError
	}

	inputs, err := readInputs(c.Scan.Paths, stdin)
	if err != nil {
		printf(stderr, "pp: %v\n", err)
		return exitError
	}

	var system string
	if c.Mode == "output" {
		system, err = readSystem(c.System)
		if err != nil {
			printf(stderr, "pp: %v\n", err)
			return exitError
		}
	}

	worst := exitAllow
	for _, in := range inputs {
		res, scanErr := scanOne(detector, c.Mode, system, in.text)
		if scanErr != nil {
			printf(stderr, "pp: %v\n", scanErr)
			return exitError
		}
		code := codeFor(res.Decision, c.FailWarn)
		if code > worst {
			worst = code
		}
		if err := render(stdout, c.Format, in.name, res); err != nil {
			printf(stderr, "pp: %v\n", err)
			return exitError
		}
	}
	return worst
}

// input pairs the text to scan with the label used in output.
type input struct {
	name string
	text string
}

// readInputs reads each path, or stdin when no paths are given. "-"
// means stdin, so `pp -` works as an explicit form.
func readInputs(paths []string, stdin io.Reader) ([]input, error) {
	if len(paths) == 0 {
		text, err := io.ReadAll(stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		return []input{{name: "<stdin>", text: string(text)}}, nil
	}

	out := make([]input, 0, len(paths))
	for _, p := range paths {
		if p == "-" {
			text, err := io.ReadAll(stdin)
			if err != nil {
				return nil, fmt.Errorf("read stdin: %w", err)
			}
			out = append(out, input{name: "<stdin>", text: string(text)})
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", p, err)
		}
		out = append(out, input{name: p, text: string(data)})
	}
	return out, nil
}

func readSystem(path string) (string, error) {
	if path == "" {
		// Not an error: ScanOutput treats an empty system as "no canary
		// to check", and secret/PII scanning still works.
		return "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read system prompt %s: %w", path, err)
	}
	return string(data), nil
}

func buildDetector(g globals) (*promptprotector.Detector, error) {
	opts := []promptprotector.Option{
		promptprotector.WithRedaction(g.Redact),
	}
	if g.Rules != "" {
		data, err := os.ReadFile(g.Rules)
		if err != nil {
			return nil, fmt.Errorf("read ruleset %s: %w", g.Rules, err)
		}
		rs, err := promptprotector.ParseRuleset(string(data))
		if err != nil {
			return nil, fmt.Errorf("parse ruleset %s: %w", g.Rules, err)
		}
		if g.Mode == "untrusted" {
			opts = append(opts, promptprotector.WithIndirectRules(rs))
		} else {
			opts = append(opts, promptprotector.WithRules(rs))
		}
	}
	if g.WarnAbove > 0 || g.BlockAbove > 0 {
		// Leaving one unset at 0 would be ambiguous, so only override
		// when the caller supplied both.
		if g.WarnAbove <= 0 || g.BlockAbove <= 0 {
			return nil, errors.New("--warn-above and --block-above must be set together")
		}
		opts = append(opts, promptprotector.WithThresholds(g.WarnAbove, g.BlockAbove))
	}
	return promptprotector.New(opts...)
}

func scanOne(d *promptprotector.Detector, mode, system, text string) (promptprotector.Result, error) {
	ctx := contextBackground()
	switch mode {
	case "input":
		return d.ScanInput(ctx, text)
	case "untrusted":
		return d.ScanUntrusted(ctx, text)
	case "output":
		return d.ScanOutput(ctx, system, text)
	default:
		return promptprotector.Result{}, fmt.Errorf("unknown mode %q", mode)
	}
}

func codeFor(d promptprotector.Decision, failWarn bool) int {
	switch d {
	case promptprotector.Block:
		return exitBlock
	case promptprotector.Warn:
		if failWarn {
			return exitWarn
		}
		return exitAllow
	default:
		return exitAllow
	}
}

func render(w io.Writer, format, name string, res promptprotector.Result) error {
	if format == "json" {
		return renderJSON(w, res)
	}
	return renderText(w, name, res)
}

func renderJSON(w io.Writer, res promptprotector.Result) error {
	out := jsonResult{
		Decision: res.Decision.String(),
		Score:    res.Score,
		Latency:  res.LatencyMs,
		Trace:    res.PipelineTrace,
		Findings: make([]jsonFinding, 0, len(res.Findings)),
	}
	for _, f := range res.Findings {
		jf := jsonFinding{
			Layer:    f.Layer,
			Rule:     f.Rule,
			Category: string(f.Category),
			Score:    f.Score,
			Evidence: f.Evidence,
		}
		if f.Span != nil {
			start, end := f.Span.Start, f.Span.End
			jf.Start, jf.End = &start, &end
		}
		out.Findings = append(out.Findings, jf)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// renderText writes a human-readable summary. It deliberately does NOT
// echo the scanned text: input is untrusted, and echoing it into a
// terminal or a CI log is how injection attacks reach the next reader.
func renderText(w io.Writer, name string, res promptprotector.Result) error {
	var b strings.Builder
	printf(&b, "%s: %s (score %.2f)\n", name, res.Decision, res.Score)
	if len(res.Findings) == 0 {
		b.WriteString("  no findings\n")
	} else {
		printf(&b, "  %d finding(s):\n", len(res.Findings))
		for _, f := range res.Findings {
			line := fmt.Sprintf("  - [%s] %s", f.Layer, f.Category)
			if f.Rule != "" {
				line += " rule=" + f.Rule
			}
			if f.Evidence != "" {
				line += " " + f.Evidence
			}
			b.WriteString(line + "\n")
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// buildCanaryForTest generates a canary with the same shape the CLI's
// tests embed, without importing the library's random source into the
// test's expectations.
func buildCanaryForTest() string {
	c, err := promptprotector.NewCanary()
	if err != nil {
		panic(err)
	}
	return c
}
