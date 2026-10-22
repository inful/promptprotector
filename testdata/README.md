# Test corpora

Every file here is a small, hand-generated or vendored slice. The full
upstream corpora are **not** committed — see `SOURCES.md`.

## `encoded/encoded.jsonl`

Generated, not vendored. Every row is a base attack from the regression
suite put through one encoding wrapper, so the corpus can be regenerated
rather than hand-edited. Regenerate with:

```
REGENERATE_ENCODED=1 go test -run TestGenerateEncodedCorpus ./...
```

The generator lives in the commit history rather than in `testdata/`,
because it would otherwise be dead code shipped in the package.

Schema, shared by every corpus in this directory:

| field | meaning |
|---|---|
| `id` | unique, `<base-attack>/<wrapper>` |
| `text` | the input handed to `ScanInput` |
| `label` | 1 = injection, 0 = clean (the deepset convention) |
| `expect` | encoding used: `plain`, `base64`, `hex`, `url`, `unicode-escape` |
| `known_gap` | set when the library documents this case as missed |
| `scope` | `out_of_scope` for labelled injections the library does not attempt |
| `source` | where the sample came from |

The gate asserts that every sample without `known_gap` is detected **and**
that a `recursive_decode` finding fired — otherwise a rule matching the
decoded text could satisfy the gate while the decoder was broken.

`known_gap` samples are logged, not asserted. Gaps are not uniform:
percent-encoding misses a phrase payload but still surfaces a
`%XX`-escaped delimiter, so those rows straddle `Allow` and `Block`.
Over-blocking is caught by the `clean/` rows instead, which include an
ordinary URL containing a `+`.

## Vendored corpora

Not yet present. `SOURCES.md` will record, per source: upstream URL,
revision, licence, and the number of samples taken. All three candidate
sources are permissively licensed (Apache-2.0, Apache-2.0, MIT), so
slices may be committed with attribution.

A vendored slice is a **dev set** — committed, run in `go test`, and
expected to be tuned against. The holdout is fetched at CI time and is
never committed, because a set you fix rules against stops being held
out.