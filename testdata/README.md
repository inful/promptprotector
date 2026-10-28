# Test corpora

Every file here is either vendored from a public corpus or generated
locally. `SOURCES.md` records the provenance and licence of each.

## `train/` — the vendored dev set

`train/injections.jsonl` — all 203 positives from deepset/prompt-injections
**train**. `train/clean.jsonl` — all 343 clean train samples, 122 of them
German.

A vendored corpus is a **dev set**: committed, run in `go test`, and
expected to be tuned against. The ruleset *was* tuned against this
split, which is why its recall figure is optimistic.

The whole split is vendored rather than a slice, because a slice cannot
carry a meaningful false-positive figure: at n=50 a ≤5 % gate is 2.5
samples and one re-sample moves the number by two points. At n=343 the
resolution is 0.3 %, and every number the README quotes is something a
reader can reproduce with `go test -v -run TestCorpusGate ./`.

**The holdout was not committed, until it was scored.** deepset's `test`
split used to be fetched at scoring time and never vendored, because a
set you fix rules against stops being held out. It was read for the
first time on 2026-10-28 and is now in `generalisation/`, under a name
that says what it is.
### Schema

| field | meaning |
|---|---|
| `id` | unique within the file |
| `text` | the input handed to `ScanInput` |
| `label` | 1 = injection, 0 = clean (the deepset convention) |
| `mechanism` | attack construction: `instruction_override`, `role_hijack`, `prompt_leak`, `other` |
| `scope` | `out_of_scope` for labelled injections the library does not attempt |
| `lang` | language of the **attack**, which is not always the language of the row |
| `source` | where the sample came from |

`mechanism`, `scope` and `lang` are assigned from the text of the
attack, never from what the detector catches — deciding scope by
detection would make recall 100 % by construction and hide every real
miss. `SOURCES.md` documents the rule and how it was cross-checked.

## `generalisation/` — the split the ruleset was not tuned against

`generalisation/injections.jsonl` — the 60 positives from
deepset/prompt-injections **test**. `generalisation/clean.jsonl` — its 56
clean samples.

This is not called `holdout/` because it is no longer held out. It was
read for the first time on 2026-10-28, scored, and its misses
inspected. It is a **measurement set** from here on: the ruleset must
not be tuned against it, and any future release that changes the
ruleset has to justify the change from the train split alone.

The result is in `SOURCES.md` and is not flattering: 5 of 22 in-scope
attacks, against 36 of 74 on the split the ruleset was tuned against.

Reproduce with `go test -v -run TestGeneralisationGate ./`.

## `encoded/encoded.jsonl`

Generated, not vendored. Every row is a base attack from the regression
suite put through one encoding wrapper, so the corpus can be regenerated
rather than hand-edited. Regenerate with:

```
REGENERATE_ENCODED=1 go test -run TestGenerateEncodedCorpus ./...
```

The generator lives in the commit history rather than in `testdata/`,
because it would otherwise be dead code shipped in the package.

It uses the same schema, plus:

| field | meaning |
|---|---|
| `expect` | encoding used: `plain`, `base64`, `hex`, `url`, `unicode-escape` |
| `known_gap` | set when the library documents this case as missed |

The gate asserts that every sample without `known_gap` is detected **and**
that a `recursive_decode` finding fired — otherwise a rule matching the
decoded text could satisfy the gate while the decoder was broken.

`known_gap` samples are logged, not asserted. Gaps are not uniform:
percent-encoding misses a phrase payload but still surfaces a
`%XX`-escaped delimiter, so those rows straddle `Allow` and `Block`.
Over-blocking is caught by the `train/clean.jsonl` rows instead, which
include an ordinary URL containing a `+`.
