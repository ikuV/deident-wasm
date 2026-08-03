# deident

**Privacy transformation engine for structured datasets** — pseudonymization and
risk-assessed anonymization for CSV files, driven by a declarative YAML policy.

```
$ deident anonymize patients.csv --policy patients.yaml --out anon.csv --report report.json
Anonymize complete: 12 row(s) in, 12 row(s) out (dataset 'patients-demo')
  direct identifiers: patient_id (removed), full_name (removed), email (removed)
  quasi-identifiers [age, zip, admission_date]: 5 equivalence class(es), min size 1, 1 unique row(s) (8.3%)
  output: anon.csv
  report: report.json
```

## Two modes, two very different promises

| | `pseudonymize` | `anonymize` |
|---|---|---|
| Reversible? | **Yes** — with the key material | **No** — values are removed or generalized |
| Output is still personal data? | **Yes.** Treat it as such. | Reduced risk, **not** zero risk |
| What happens to direct identifiers | replaced with deterministic tokens | removed (or redacted) |
| What happens to quasi-identifiers | kept unchanged | generalized/suppressed per policy |
| Typical use | joinable test/analytics data, debugging with real structure | sharing data with reduced re-identification risk |

> ⚠️ **No guarantees.** This tool performs *risk-assessed* anonymization: it reduces
> re-identification risk and measures residual risk signals, but it cannot certify
> anonymity — that always depends on external data and context it cannot observe.
> Pseudonymized output remains personal data and is reversible by anyone holding the
> key material, so protect keys separately from outputs.

## Status

MVP. CSV in/out. Two execution engines: `native` (in-process, default) and
`wasm` — each job runs in its own WebAssembly sandbox (Wasmtime + WASI, fresh
store per job, the job directory as the only filesystem capability, no network,
memory/time limits). See [Sandboxed execution](#sandboxed-execution).
JSONL/Parquet support and an encrypted mapping vault are on the roadmap — see
[Roadmap](#roadmap).

## Installation

Requires a Rust toolchain (1.96+).

```bash
git clone <this-repo> && cd deident-wasm

# run tests, then install the `deident` binary onto your PATH
cargo test --workspace
cargo install --path crates/cli

# — or just build and use it from target/release/
cargo build --release
./target/release/deident --help
```

## Quick start

The repo ships a demo dataset and policy:

```bash
# reversible: tokenize direct identifiers, keep everything else
deident pseudonymize examples/data/patients.csv \
  --policy examples/policies/patients.yaml \
  --out pseudo.csv

# irreversible: remove/generalize identifiers, write a risk report
deident anonymize examples/data/patients.csv \
  --policy examples/policies/patients.yaml \
  --out anon.csv \
  --report report.json
```

To run against your own data you need a policy file that lists **every column**
of your CSV — see [Policy reference](#policy-reference).

## CLI reference

```
deident <COMMAND> [OPTIONS]
```

| Command | Description |
|---|---|
| `pseudonymize <INPUT> --policy <FILE> --out <FILE> [--report <FILE>]` | Reversibly tokenize direct identifiers (deterministic per dataset/policy) |
| `anonymize <INPUT> --policy <FILE> --out <FILE> [--report <FILE>]` | Irreversibly remove/generalize identifiers and produce a risk report |
| `chain <MANIFEST> --mode <pseudonymize\|anonymize> [--report <FILE>]` | Run several datasets as one chained export (see [Chained datasets](#chained-datasets)) |
| `help [COMMAND]` | Print help |

Options for `pseudonymize` / `anonymize` (the engine options also apply to `chain`):

| Option | Required | Description |
|---|---|---|
| `<INPUT>` | yes | Input CSV file (first row must be the header) |
| `--policy <FILE>` | yes | Policy YAML describing field classes and strategies |
| `--out <FILE>` | yes | Output CSV file |
| `--report <FILE>` | no | Write the JSON risk report to this path |
| `--engine <ENGINE>` | no | `native` (in-process, default) or `wasm` (per-job sandbox) |
| `--worker <FILE>` | no | Compiled worker module for `--engine wasm` (see discovery order below) |
| `--max-memory-mib <N>` | no | Guest memory limit in MiB (wasm only, default 256) |
| `--timeout-secs <N>` | no | Job wall-clock timeout in seconds (wasm only, default 30) |
| `-h, --help` | | Print help |
| `-v, -V, --version` | | Print version |

Environment:

| Variable | Purpose |
|---|---|
| `DEIDENT_KEY` (or whatever the policy's `key.env` names) | Secret for pseudonymization key derivation |
| `DEIDENT_WORKER_WASM` | Path to the worker module for `--engine wasm` |
| `RUST_LOG` | Log verbosity on stderr, e.g. `RUST_LOG=debug` (default `info`) |

Exit codes: `0` success, non-zero on any failure (bad policy, unreadable input,
unlisted column, missing key, ...). Human summary goes to stdout, logs to stderr.

## Sandboxed execution

`--engine wasm` runs each job inside its own WebAssembly sandbox instead of
in-process. The exact same transformation code runs either way (the core crate
compiles into both), and outputs are byte-identical — the sandbox adds an
isolation layer around the parsing/transformation logic:

- **Fresh instance per job** — a new Wasmtime store and WASI context every
  time; no state survives from one job to the next.
- **One directory, nothing else** — the guest sees a single preopened job
  workspace containing a *copy* of the input; your real filesystem paths never
  reach it. Attempts to read outside (absolute paths, `..` escapes) fail.
- **No network** — the WASI context simply has no socket capability.
- **Minimal environment** — only the one key variable a pseudonymize policy
  names is passed through, and only if set.
- **Resource limits** — guest memory (`--max-memory-mib`) and wall-clock
  timeout (`--timeout-secs`) are enforced per job.

Sandboxing *reduces* the blast radius of malformed inputs and future untrusted
plugins; it is a mitigation, not an absolute security boundary.

Build the worker module once, then use it:

```bash
rustup target add wasm32-wasip1
cargo build -p deident-worker --target wasm32-wasip1 --release

deident anonymize input.csv --policy p.yaml --out out.csv --engine wasm
```

The worker module is found in this order: `--worker <FILE>`, then
`$DEIDENT_WORKER_WASM`, then `deident-worker.wasm` next to the `deident`
binary, then the local cargo build under `target/wasm32-wasip1/`. For
deployment, copy `deident-worker.wasm` next to the installed binary.

## Policy reference

A policy is a YAML file that classifies every column and configures how each mode
treats it. Complete annotated example:

```yaml
version: 1                  # required; only 1 is supported
dataset: patients-demo      # required; scopes key derivation (see Key management)

key:                        # required for pseudonymize, ignored by anonymize
  env: DEIDENT_KEY          # name of the env var holding the secret (preferred)
  inline: "demo-secret"     # fallback secret — demos/tests only, always warned

on_unlisted: error          # what to do with CSV columns not listed below:
                            #   error  – fail the job (default, deny-by-default)
                            #   keep   – pass through unchanged + warning
                            #   remove – drop the column + warning

fields:
  - name: patient_id                # column name, must match the CSV header
    class: direct_identifier        # see field classes below
    pseudonymize:                   # optional, pseudonymize mode only
      prefix: "pid_"                # cosmetic token prefix

  - name: email
    class: direct_identifier        # no config needed: tokenized in pseudonymize
                                    # mode, removed in anonymize mode by default

  - name: age
    class: quasi_identifier
    anonymize:                      # anonymize-mode strategy (see below)
      strategy: bucket
      width: 10

  - name: zip
    class: quasi_identifier
    anonymize:
      strategy: keep_prefix
      chars: 3
      pad: "*"                      # optional, default '*'

  - name: admission_date
    class: quasi_identifier
    anonymize:
      strategy: date_truncate
      granularity: year             # year | year_month

  - name: diagnosis
    class: sensitive

  - name: notes
    class: utility

patterns:                           # content-pattern rules, see below
  - name: iban
    builtin: iban
    fields: [notes]
    action: redact
```

Unknown YAML keys anywhere in the policy are rejected (typos fail fast).

### Field classes

| Class | Meaning | Pseudonymize mode | Anonymize mode |
|---|---|---|---|
| `direct_identifier` | Identifies a person on its own (name, email, ID number) | tokenized | removed (default) or the configured strategy |
| `quasi_identifier` | Identifying in combination (age, zip, dates) | kept unchanged | configured strategy; kept + **warning** if none |
| `sensitive` | Sensitive payload (diagnosis, salary) | kept unchanged | kept, unless a strategy is configured |
| `utility` | Analytic utility only | kept unchanged | kept, unless a strategy is configured |

### Anonymization strategies

Set under a field's `anonymize:` block; applied only in `anonymize` mode.

| `strategy` | Parameters | Example |
|---|---|---|
| `remove` | — | column is dropped entirely |
| `redact` | `replacement` (default `"REDACTED"`) | `Alice` → `REDACTED` |
| `bucket` | `width` (positive integer) | width 10: `34` → `30-39`, `-3` → `-10--1`; floats floored |
| `date_truncate` | `granularity`: `year` \| `year_month` | `2024-03-14` → `2024` or `2024-03`; ISO dates/timestamps only |
| `keep_prefix` | `chars`, `pad` (default `*`) | chars 3: `81549` → `815**` |

Values that don't fit their strategy (e.g. `bucket` on `n/a`, `date_truncate` on
`14.03.2024`) are suppressed to `*` and counted in the report warnings — a single
bad cell never fails the job. Empty cells always pass through empty.

### Pseudonymization options

Set under a field's `pseudonymize:` block; applied only in `pseudonymize` mode and
only to `direct_identifier` fields (which are tokenized with or without this block).

| Key | Description |
|---|---|
| `prefix` | Cosmetic prefix prepended to the token, e.g. `pid_` → `pid_21134bb99aee85cb...` |
| `domain` | Identity domain the token is derived in; defaults to the column name. Give differently named columns in different files (e.g. `patient_id` and `patient_ref`) the same domain so the same value yields the same token — foreign keys survive (see [Chained datasets](#chained-datasets)) |

### Content-pattern rules

Column-level rules can't reach identifiers hiding *inside* values — an IBAN in a
free-text `notes` column, an email in a comment. `patterns:` rules scan cell
content and run in **both modes**, after the column-level transform:

```yaml
patterns:
  - name: iban            # rule name; also the default redaction label
    builtin: iban         # or a custom regex — exactly one of the two:
    # regex: '\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b'
    fields: [notes]       # columns to scan; omit = every column in the output
    action: redact        # detect | redact | token
    # replacement: "[IBAN]"   # redact only; default "[<NAME>]"
    # prefix: "ib_"           # token only
```

| `action` | Effect |
|---|---|
| `detect` | Only count matches for the risk report; values stay in the output (**a warning is recorded**) |
| `redact` | Replace each match with a fixed label (default `[IBAN]`-style) |
| `token` | Replace each match with a deterministic keyed token — same IBAN, same token, so joins/grouping survive. Requires a key source; in anonymize mode the report flags the affected output as pseudonymous (reversible with the key) |

Built-in patterns (`builtin:`): `iban`, `email`, `phone`, `credit_card`. These
are pragmatic heuristics, not validators — expect some false positives/negatives
and switch to a custom `regex` where precision matters. Dropped and tokenized
columns are never scanned (nothing left to find).

## Key management

Pseudonym tokens are 128-bit BLAKE3 keyed hashes. The key is derived from your
secret **and the policy's `dataset` name**, and the hash input includes the column
name. Consequences:

- **Same secret + same policy ⇒ same tokens.** Runs are repeatable, and repeated
  exports of the same dataset stay joinable on their tokens.
- The same value produces **different tokens in different columns and different
  datasets** — tokens can't be used to link across datasets by accident.
- Without the secret, tokens cannot be reversed or recomputed. **Whoever has the
  secret can re-identify.** Store it in a secret manager, never next to the output.

Provide the secret via the environment variable named in `key.env`:

```bash
export DEIDENT_KEY="$(your-secret-manager get deident-prod)"
deident pseudonymize ...
```

`key.inline` embeds the secret in the policy file — useful for demos and tests,
unsafe for production. Every run using it records a warning in the report.

## Chained datasets

Real exports are rarely one file: `patients.csv` plus `visits.csv` that
references it. A chain manifest runs them as one unit so **foreign keys survive
pseudonymization**:

```yaml
# hospital.yaml — paths are resolved relative to this file
version: 1
name: hospital-demo
# Optional overrides forced onto every job policy:
# dataset: hospital-export    # one token scope for all files
# key: { env: DEIDENT_KEY }   # one key source for all files
jobs:
  - name: patients
    input: ../data/patients.csv
    policy: ../policies/patients.yaml
    output: out/patients.csv
    report: out/patients-report.json   # optional per-job report
  - name: visits
    input: ../data/visits.csv
    policy: ../policies/visits.yaml
    output: out/visits.csv
```

```bash
deident chain hospital.yaml --mode pseudonymize --report out/chain-report.json
```

Cross-file linkage needs two things:

1. **Same token scope** — all policies share the same `dataset` (and secret),
   or the manifest forces one via its `dataset:`/`key:` overrides. Diverging
   scopes in pseudonymize mode are flagged as a chain warning, because they
   silently break joins.
2. **Same identity domain** — tokens are namespaced by column name by default,
   so `patient_id` (patients.csv) and `patient_ref` (visits.csv) would *not*
   match. Declare the shared domain on the referencing column:

   ```yaml
   - name: patient_ref
     class: direct_identifier
     pseudonymize:
       prefix: "pid_"
       domain: patient_id    # ← same namespace as patients.csv's patient_id
   ```

Jobs run sequentially and the chain stops at the first failure (remaining jobs
are not run; the combined report says so). Exit code is non-zero unless every
job succeeded. `--engine wasm` gives each job of the chain its own fresh
sandbox. A complete working example ships in
[examples/chains/hospital.yaml](examples/chains/hospital.yaml).

## Risk report

`--report <FILE>` writes a JSON document (also available for `pseudonymize`):

```json
{
  "dataset": "patients-demo",
  "mode": "anonymize",
  "rows_read": 12,
  "rows_written": 12,
  "direct_identifiers": [
    { "field": "patient_id", "action": "removed" },
    { "field": "full_name", "action": "removed" },
    { "field": "email", "action": "removed" }
  ],
  "quasi_identifiers": {
    "fields": ["age", "zip", "admission_date"],
    "equivalence_classes": 5,
    "min_class_size": 1,
    "max_class_size": 5,
    "mean_class_size": 2.4,
    "unique_rows": 1,
    "unique_row_ratio": 0.0833,
    "k_thresholds": [
      { "k": 2, "rows_at_or_above": 11, "ratio": 0.9167 },
      { "k": 5, "rows_at_or_above": 5, "ratio": 0.4167 },
      { "k": 10, "rows_at_or_above": 0, "ratio": 0.0 }
    ]
  },
  "patterns": [
    { "pattern": "iban", "field": "notes", "matches": 1, "action": "redacted" }
  ],
  "warnings": [],
  "limitations": [ "This report supports a risk assessment; it does not certify or guarantee anonymization.", "..." ]
}
```

`patterns` lists content-pattern matches per rule and column with the action
taken (`detected` / `redacted` / `tokenized`). `deident chain --report` writes a
combined chain report instead: chain name, completion flag, chain-level warnings
and each job's outcome with its embedded `RiskReport`.

How to read the `quasi_identifiers` block: rows are grouped by their combination of
(transformed) quasi-identifier values — each distinct combination is an
*equivalence class*. Small classes mean higher re-identification risk:

- `min_class_size` — the k in "k-anonymity style" terms; 1 means at least one row
  is unique on its quasi-identifiers.
- `unique_rows` / `unique_row_ratio` — rows that are one-of-a-kind. These are the
  riskiest rows; consider coarser generalization if this isn't near zero.
- `k_thresholds` — share of rows living in classes of at least size k (2, 5, 10).

`warnings` surfaces anything that needs human attention: inline key usage,
quasi-identifiers without a strategy, suppressed values, unlisted-but-kept columns.
The `limitations` block is embedded in every report by design.

## Security model & non-goals

- Anonymization here is **risk-assessed, never guaranteed**. The report measures
  what it can; residual risk always remains and depends on context.
- Pseudonymized data **remains personal data** under most privacy regimes (e.g.
  GDPR). Reversal requires only the key material — protect it separately.
- Deny-by-default policy handling: unlisted columns and unknown policy keys fail
  the job unless explicitly relaxed.
- With `--engine wasm`, each job runs in a fresh WebAssembly sandbox with a
  preopened job directory as its only filesystem capability, no network, and
  per-job memory/time limits (see [Sandboxed execution](#sandboxed-execution)).
  Sandboxing *reduces* the blast radius of risky parsing logic and future
  untrusted plugins; it is a mitigation, not an absolute boundary, and no
  escape-proof claims are made.
- Non-goals: differential privacy, synthetic data generation, free-text/NLP
  de-identification, and legal certification of any output.

## Project layout

| Crate | Purpose |
|---|---|
| `crates/cli` | `deident` binary — command-line UX |
| `crates/core` | Policy schema, transforms, job engine, risk reports |
| `crates/host` | Execution engines: in-process native and per-job Wasmtime sandbox |
| `crates/worker` | Wasm guest that executes one job inside its sandbox |
| `crates/types` | Shared request/response/report models |

```bash
cargo test --workspace        # unit + integration tests
cargo clippy --workspace --all-targets
```

## Roadmap

- **Sandbox by default** — make `--engine wasm` the default once the worker
  module ships alongside released binaries; tune fuel-based CPU budgets.
- **Encrypted mapping vault** — persist original→token mappings under AEAD for
  authorized reversal workflows.
- **More formats** — JSONL, then Parquet.
- **Format-preserving mocks** — pattern action generating valid-looking fake
  values (e.g. mock IBANs with correct check digits) for test-data use cases.
- **Audit logs** — structured per-job JSONL (job id, policy hash, counts, limits).
- **Policy lints** — warn on risky policies before running.
