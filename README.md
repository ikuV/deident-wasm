# deident

**Privacy transformation engine for structured datasets** — pseudonymization and
risk-assessed anonymization for CSV, JSONL, Parquet and DICOM, driven by a
declarative YAML policy.

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

## What it does

- **Formats** — CSV, JSONL/NDJSON and Parquet, inferred from the file
  extension. Input and output formats are independent, so a job converts while
  it transforms. See [Formats](#formats).
- **Column rules** — classify every column (`direct_identifier`,
  `quasi_identifier`, `sensitive`, `utility`) and pick a strategy: tokenize,
  remove, redact, bucket, truncate dates, keep a prefix. See
  [Policy reference](#policy-reference).
- **Content patterns** — find identifiers *inside* values (an IBAN in a
  free-text note) with **16 built-in detectors** (email, IBAN, card, SSN, phone,
  IP, URL, API key, passport, plate, IFSC, date of birth, plus heuristic name /
  address / organization / medical-term matchers) or your own regex, then detect,
  redact, tokenize or replace them with structurally valid fakes —
  checksum-verified where a checksum exists. See
  [Built-in detectors](#built-in-detectors).
- **Chained datasets** — process several files as one export with shared token
  scoping, so foreign keys still join after pseudonymization. See
  [Chained datasets](#chained-datasets).
- **Sandboxed execution** — each job can run in its own WebAssembly sandbox
  (Wasmtime + WASI): fresh store per job, one preopened directory, no network,
  memory/CPU/time limits. See [Sandboxed execution](#sandboxed-execution).
- **Encrypted mapping vault** — optionally record original→token mappings
  under XChaCha20-Poly1305 for authorized re-identification. See
  [Mapping vault and reversal](#mapping-vault-and-reversal).
- **Risk report** — row counts, per-identifier actions, pattern findings and
  equivalence-class statistics. See [Risk report](#risk-report).
- **DICOM** — metadata de-identification of medical imaging instances, with
  consistent UID remapping across a study. See [DICOM](#dicom).
- **Policy lints** — warn about risky-but-valid policies before a job runs.
  See [Policy lints](#policy-lints).
- **Audit log** — append-only JSONL, metadata only. See
  [Audit log](#audit-log).

Status: MVP, but a complete one — every feature above is implemented and
tested. Streaming for very large datasets, richer vault workflows and more
formats are on the [Roadmap](#roadmap).

## Installation

Requires a Rust toolchain (1.96+).

```bash
git clone <this-repo> && cd deident-wasm

# install the `deident` binary onto your PATH
cargo install --path crates/cli

# to also sandbox jobs, build the guest module (see Sandboxed execution)
rustup target add wasm32-wasip1
cargo build -p deident-worker --target wasm32-wasip1 --release

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
of your dataset — see [Policy reference](#policy-reference). `deident lint` will
tell you if it looks risky.

## CLI reference

```
deident <COMMAND> [OPTIONS]
```

| Command | Description |
|---|---|
| `pseudonymize <INPUT>` | Reversibly tokenize direct identifiers (deterministic per dataset/policy) |
| `anonymize <INPUT>` | Irreversibly remove/generalize identifiers and produce a risk report |
| `chain <MANIFEST> --mode <MODE>` | Run several datasets as one chained export ([Chained datasets](#chained-datasets)) |
| `lint <POLICY>` | Report risky-but-valid policy configurations ([Policy lints](#policy-lints)) |
| `vault export <VAULT> --policy <FILE>` | Decrypt a mapping vault to CSV ([Mapping vault](#mapping-vault-and-reversal)) |
| `reverse <INPUT> --vault <FILE> --policy <FILE> --out <FILE>` | Re-identify tokenized values using a vault |
| `dicom <INPUT> --policy <FILE> --out <PATH>` | De-identify DICOM instance metadata, file or directory ([DICOM](#dicom)) |
| `help [COMMAND]` | Print help |

Options for `pseudonymize` / `anonymize`:

| Option | Required | Description |
|---|---|---|
| `<INPUT>` | yes | Input file; format inferred from the extension (`.csv`, `.jsonl`/`.ndjson`, `.parquet`) |
| `--policy <FILE>` | yes | Policy YAML describing field classes and strategies |
| `--out <FILE>` | yes | Output file; its extension selects the output format |
| `--report <FILE>` | no | Write the JSON risk report here |
| `--vault <FILE>` | no | Write the encrypted mapping vault here (only if the job produces reversible values) |
| `--no-lint` | no | Skip the pre-flight policy lint |
| `--deny-lints` | no | Refuse to run when a warning-level lint fires |

Engine options (also accepted by `chain`):

| Option | Default | Description |
|---|---|---|
| `--engine <ENGINE>` | `auto` | `auto` sandboxes when a worker module is available and falls back in-process with a warning; `wasm` requires the sandbox; `native` runs in-process |
| `--worker <FILE>` | discovery | Compiled worker module (see discovery order below) |
| `--max-memory-mib <N>` | `256` | Guest memory limit in MiB (sandbox only) |
| `--timeout-secs <N>` | `30` | Job wall-clock timeout in seconds (sandbox only) |
| `--fuel <N>` | scaled | Fixed CPU budget in Wasmtime fuel units; the default scales with input size |
| `--no-fuel` | off | Disable fuel metering (the wall-clock timeout still applies) |
| `--audit-log <FILE>` | off | Append one JSONL audit record per job ([Audit log](#audit-log)) |

`lint` also accepts `--mode <MODE>` (restrict to lints relevant for one mode),
`--json`, and `--deny` (exit non-zero on any warning).

Global: `-h, --help`, and `-v` / `-V` / `--version`.

Environment:

| Variable | Purpose |
|---|---|
| `DEIDENT_KEY` (or whatever the policy's `key.env` names) | Secret for key derivation |
| `DEIDENT_WORKER_WASM` | Path to the worker module for sandboxed execution |
| `RUST_LOG` | Log verbosity on stderr, e.g. `RUST_LOG=debug` (default `info`) |

Exit codes: `0` success, non-zero on any failure (bad policy, unreadable input,
unlisted column, missing key, a failed chain job, `--deny-lints` with warnings).
Human summary goes to stdout, logs and lint warnings to stderr.

## Formats

The format of each file is inferred from its extension, independently for input
and output — so a job can convert while it transforms:

| Extension | Format | Notes |
|---|---|---|
| `.csv` | CSV | Header row required |
| `.jsonl`, `.ndjson` | JSON Lines | One **flat** object per line. The first record defines the columns; later records may omit keys (treated as empty) but not add new ones. Nested objects/arrays are rejected rather than silently flattened. Numbers and booleans keep their JSON type when their value is unchanged; generalized values (`"30-39"`) become strings; empty becomes `null` |
| `.parquet`, `.pq` | Apache Parquet | Column types are re-inferred from the transformed values, so untouched numeric columns stay `Int64`/`Float64` while generalized ones become `Utf8`. Not available inside the sandbox (see below) |

```bash
# read Parquet, write JSONL, transforming on the way through
deident anonymize events.parquet --policy p.yaml --out events.jsonl
```

Both Parquet directions hold the table in memory (its footer-based layout makes
true streaming impractical); CSV and JSONL stream row by row.

## Sandboxed execution

`--engine wasm` (and `auto`, the default, when a worker module is available)
runs each job inside its own WebAssembly sandbox instead of in-process. The
exact same transformation code runs either way — the core crate compiles into
both — and outputs are byte-identical, verified by tests. The sandbox adds an
isolation layer around the parsing/transformation logic:

- **Fresh instance per job** — a new Wasmtime store and WASI context every
  time; no state survives from one job to the next.
- **One directory, nothing else** — the guest sees a single preopened job
  workspace containing a *copy* of the input; your real filesystem paths never
  reach it. Attempts to read outside (absolute paths, `..` escapes) fail.
- **No network** — the WASI context simply has no socket capability.
- **Minimal environment** — only the one key variable a pseudonymize policy
  names is passed through, and only if set.
- **Resource limits** — guest memory (`--max-memory-mib`), a wall-clock
  timeout enforced by epoch interruption (`--timeout-secs`), and a CPU budget
  in Wasmtime fuel units. The fuel budget **scales with input size** by
  default (a fixed budget would either starve large jobs or be meaningless for
  small ones); override with `--fuel <N>` or turn it off with `--no-fuel`.

Sandboxing *reduces* the blast radius of malformed inputs and future untrusted
plugins; it is a mitigation, not an absolute security boundary.

**Format caveat:** the sandbox build deliberately excludes Parquet — the arrow
stack inflates the guest module from ~1.9 MB to ~7.4 MB, which Wasmtime then
has to JIT-compile for every job. CSV and JSONL work in the sandbox; Parquet
jobs run in-process (`--engine auto` switches automatically and says so).

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
    action: redact        # detect | redact | token | mock
    # replacement: "[IBAN]"   # redact only; default "[<NAME>]"
    # prefix: "ib_"           # token only
    # mock: iban              # mock only; defaults to the `builtin` shape
```

| `action` | Effect |
|---|---|
| `detect` | Only count matches for the risk report; values stay in the output (**a warning is recorded**) |
| `redact` | Replace each match with a fixed label (default `[IBAN]`-style) |
| `token` | Replace each match with a deterministic keyed token — same IBAN, same token, so joins/grouping survive. Requires a key source |
| `mock` | Replace each match with a deterministic, **structurally valid** fake of the same shape (see below). Requires a key source |

Both `token` and `mock` are **reversible with the key material**: in anonymize
mode the report and the lints flag the affected output as pseudonymous rather
than anonymous.

#### Format-preserving mocks

`action: mock` is for downstream systems that validate their input and would
choke on `[IBAN]` or a hex token. Mocks are derived from the same keyed hash as
tokens, so they are deterministic and stable — the same input always yields the
same mock, and joins on the mocked value keep working.

| Shape | What is preserved | What is generated |
|---|---|---|
| `iban` | Country code and length | Correct mod-97 (ISO 7064) check digits, so validators accept it |
| `credit_card` | Length and separators | Valid Luhn check digit, forced into the `999x` test IIN range so it cannot collide with a real issuer |
| `phone` | Punctuation and digit count | New digits, leading digit kept non-zero |
| `email` | Nothing of the original | A random local part at `example.com` (RFC 2606 documentation domain) |

The shape comes from `builtin:`, or set `mock:` explicitly when mocking a
custom `regex:` rule. A mock is a **pseudonym with a prettier shape**, not
anonymization: it is recorded in the mapping vault exactly like a token, and
anyone with the key can recompute it.

Dropped and tokenized columns are never scanned (nothing left to find).

### Built-in detectors

Sixteen detectors, grouped by **how much a match can be trusted**. That grouping
is the important part: it stops a heuristic guess from being mistaken for a
verified identifier.

| Detector | Example | Class | Verified by |
|---|---|---|---|
| `email` | `user@example.com` | precise | — |
| `iban` | `DE89 3704 0044 0532 0130 00` | precise | mod-97 (ISO 7064) |
| `credit_card` | `4111 1111 1111 1111` | precise | Luhn |
| `ip_address` | `192.168.1.1`, `2001:db8::1` | precise | octet ranges |
| `url` | `https://internal.company.com` | precise | — |
| `api_key` | `AKIA…`, `sk-live_…`, `ghp_…`, `xoxb-…`, `glpat-…` | precise | — |
| `ifsc` | `HDFC0001234 000123456789` | precise | — |
| `phone` | `+1-555-0123`, `+91 98765 43210` | moderate | — |
| `ssn` | `123-45-6789` | moderate | US allocation rules |
| `date_of_birth` | `15/03/1990`, `March 15, 1990` | moderate | — |
| `passport` | `J1234567` | moderate | — |
| `license_plate` | `MH 12 AB 1234` | moderate | — |
| `person_name` | `Dr. Priya Sharma`, `John Smith` | **heuristic** | — |
| `address` | `123 MG Road, Pune 411001` | **heuristic** | — |
| `organization` | `Apollo Hospital`, `HDFC Bank` | **heuristic** | — |
| `medical_term` | `diabetes`, `cardiac arrest` | **heuristic** | — |

- **precise** — distinctive syntax, mostly checksum-verified. Safe to redact
  unattended.
- **moderate** — a recognisable shape that innocent data also has. Expect some
  false positives; read the report.
- **heuristic** — a stand-in for named entity recognition, which this tool does
  **not** have. These are title-based patterns, suffix lists and a small
  gazetteer. They produce false positives *and* miss real entities. They default
  to `detect` in presets, every report says so, and setting one to modify data
  triggers the `heuristic-pattern-modifies-data` lint. Treat them as "show me
  where to look", never as "this text is now clean".

#### Checksum validation

Detectors with a checksum apply it to **every match**, so a loose regex buys
recall without paying for it in false positives — a 13-digit order number matches
the card shape but fails Luhn, so it is not reported as a card.

Rejected matches are **left untouched and counted**, and the report says so:

> `pattern 'credit_card' rejected 1 match(es) that had the right shape but failed
> the Luhn checksum, and left them unchanged. Set validate: none to treat them as
> identifiers anyway (at the cost of false positives)`

That matters for test data: invented card numbers usually fail Luhn, so
`validate: none` is the right choice when you want every card-shaped string
flagged regardless.

#### Presets

Rather than listing sixteen rules, enable a whole class:

```yaml
presets:
  - { preset: precise,   action: redact }   # checksum-verified: act on them
  - { preset: moderate,  action: redact }   # read the report afterwards
  - { preset: heuristic, action: detect }   # report only, for human review
```

`preset: all` covers everything. An explicit `patterns` entry always wins over a
preset of the same detector name, so you can enable a class and still tune one
member of it. A complete example ships in
[examples/policies/detect-all.yaml](examples/policies/detect-all.yaml).

Rules run in sequence over the same value, so two rules using the same detector
would mean the first one's replacement hides the second's matches — the
`duplicate-builtin-detector` lint catches that.

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
unsafe for production. Every run using it records a warning in the report and
triggers the `inline-key` lint.

Key material is **purpose-separated**: the vault encryption key is derived from
the same secret under a different KDF context, so the vault key cannot forge
tokens and the token key cannot decrypt a vault.

## Mapping vault and reversal

Tokens are recomputable from the key alone, so a vault is optional. It exists
for the workflow where an authorized party needs to reverse *specific* values
without holding a re-derivation pipeline — and it is the only way to reverse
mocks and pattern matches conveniently.

```bash
# 1. pseudonymize, recording the mappings
deident pseudonymize patients.csv --policy p.yaml --out pseudo.csv --vault vault.jsonl

# 2. later, with authorization: inspect the mappings
deident vault export vault.jsonl --policy p.yaml --out mappings.csv

# 3. or reverse a whole file in place
deident reverse pseudo.csv --vault vault.jsonl --policy p.yaml --out restored.csv
```

How it is protected:

- Every entry is encrypted with **XChaCha20-Poly1305** under a key derived from
  your secret and the dataset name. The file's header (format, version,
  dataset) stays readable; the mappings do not.
- Nonces are **synthetic** — derived from the key and the plaintext rather than
  randomly. That keeps vault files reproducible and makes appends safe against
  nonce reuse. The trade-off is that identical entries produce identical
  ciphertext, revealing that two lines map the same value; for a deterministic
  mapping table that equality is inherent to the design.
- The AEAD tag is verified on read, so a wrong key or a tampered file **fails
  loudly** instead of decrypting to garbage.

A vault is written only when the job actually produces reversible values
(pseudonymize mode, or `token`/`mock` patterns); otherwise the report says so
and no file is created.

> ⚠️ **A vault is a re-identification table.** It is as sensitive as the
> original data. Store it separately from the output, under stricter access
> control, and treat `vault export` and `reverse` as privileged operations —
> their output contains original personal data again.

## DICOM

Medical imaging instances are not tabular — a DICOM object is a nested,
tag-keyed attribute tree with typed value representations, sequences, a separate
file-meta header and a pixel payload. So DICOM gets its own policy dialect and
its own command, while reusing the same key derivation, tokenization, mocks,
mapping vault and audit log.

```bash
# a single instance
deident dicom study/image-001.dcm --policy dicom.yaml --out deid/image-001.dcm

# or a whole directory tree, recursively, with one shared identity scope
deident dicom study/ --policy dicom.yaml --out deid/ --report deid.json --vault vault.jsonl
```

### Scope — read this first

> ⚠️ **This is not DICOM PS3.15 Annex E conformance.** It implements a *curated
> core* of the Basic Application Level Confidentiality Profile plus structural
> rules, and every report says so. If you need certified conformance you must
> extend the policy's tag list and validate it against your own data.
>
> ⚠️ **Burned-in pixel PHI is detected and flagged, never removed.** Ultrasound
> frames, secondary captures and scanned documents routinely render patient
> details into the image itself. Cleaning that requires OCR and cannot be made
> reliable, so this tool refuses to claim it. Every run prints the caveat and
> reports a `pixel_risk` level with its reasoning.

### How coverage works

Three layers, highest precedence first:

1. **Explicit `tags:` rules** in your policy.
2. **The selected profile** (`basic` — the curated Annex E core).
3. **Structural rules** that catch whole *classes* of attribute rather than
   named instances: every person-name (`PN`) attribute, every identity UID,
   every private attribute (odd group — unknown vendor semantics), and the
   curve/overlay groups.

That third layer is deliberate. Transcribing ~500 Annex E rows from memory would
be error-prone, and a missed row means PHI survives. Rules keyed on VR and tag
structure fail *safe* — they remove what they don't recognise — and the curated
table then handles the well-known core exactly.

### Actions

| Action | Annex E | Effect |
|---|---|---|
| `remove` | `X` | Delete the attribute |
| `empty` | `Z` | Keep the attribute, zero-length |
| `replace` | `D` | Fixed literal (`value:`) |
| `pseudonymize` | `D` | Deterministic keyed pseudonym; `mock: person_name` produces a readable `Family^Given` instead of a hex token |
| `uid` | `U` | New UID, **consistently remapped** — the same original UID becomes the same replacement in every instance of the study |
| `date_shift` | — | Shift by a deterministic per-subject offset, so intervals survive |
| `date_truncate` | — | Truncate to year or year-month (padded to stay a valid `DA`) |
| `clean_text` | `C` | Run the policy's [content-pattern rules](#content-pattern-rules) over the text |
| `keep` | `K` | Leave untouched |

Tags are addressed by standard keyword (`PatientName`) or numerically
(`(0010,0010)`). Replacement UIDs use the `2.25.<decimal>` arc that DICOM PS3.5
reserves for UUID-derived OIDs, so no registered organisational root is needed.

A complete annotated example ships in
[examples/policies/dicom-basic.yaml](examples/policies/dicom-basic.yaml).

### What survives, and why

`PatientSex` and `PatientAge` are **kept** by the basic profile because they are
clinically load-bearing — but they are quasi-identifiers, and the report says so.
Format-identifying UIDs (`SOPClassUID`, `TransferSyntaxUID`) are never remapped;
doing so would make the file unreadable. Pixel data and image geometry pass
through untouched.

UID remapping intentionally **breaks references from outside the processed set**
— a PACS or a report citing the original UIDs will no longer resolve.

### Test data

Public DICOM collections (TCIA, pydicom-data, GDCM) are *already*
de-identified, which makes them unable to demonstrate that a de-identifier
works — there is no PHI left to remove. So the crate generates its own fixtures
with identifiers planted in known attributes, including one nested inside a
sequence and one in a private block:

```bash
cargo run -p deident-dicom --example gen_fixtures -- ./study 3
```

The test suite runs against these and asserts at the **byte level** that no
planted identifier survives anywhere in the output file.

DICOM jobs run in-process: the wasm guest does not carry the DICOM parser (the
same module-size trade-off as Parquet). Since DICOM parsers are historically a
CVE-rich surface, sandboxing this path is on the roadmap.

## Policy lints

A policy can be perfectly valid and still not do what its author intended — a
quasi-identifier with no generalization, a secret pasted into the file,
deny-by-default switched off. `deident lint` reports those:

```bash
deident lint examples/policies/patients.yaml --mode anonymize
deident lint policy.yaml --json          # machine-readable
deident lint policy.yaml --deny          # exit non-zero on any warning
```

Lints also run automatically before every job (warnings to stderr). Use
`--no-lint` to skip them, or `--deny-lints` to refuse to run when a warning
fires — useful in CI.

Two levels: **warning** (likely a privacy problem) and **advice** (legitimate
in many setups). Current rules include: `inline-key`, `missing-key-source`,
`unlisted-columns-kept`, `unlisted-columns-removed`, `qi-without-strategy`,
`direct-identifier-partially-kept`, `ineffective-bucket`,
`free-text-without-patterns`, `no-direct-identifiers`, `no-quasi-identifiers`,
`detect-only-pattern`, `reversible-pattern-in-anonymize`.

Lints are heuristics, not a compliance check — a clean lint run does not mean a
policy is adequate for your data.

## Audit log

`--audit-log <FILE>` appends one JSON object per job:

```json
{"timestamp":"2026-08-04T09:12:33Z","job_id":"…","mode":"anonymize","engine":"wasm",
 "dataset":"patients-demo","policy_hash":"9f2c…","input_path":"in.csv","output_path":"out.csv",
 "status":"succeeded","rows_read":12,"rows_written":12,"warnings":1,"error":null,
 "limits":{"max_memory_bytes":268435456,"timeout_ms":30000,"fuel":2000000000}}
```

It is deliberately **metadata only** — no cell values — so it can be retained
and shipped to a SIEM without inheriting the sensitivity of the data it
describes. `policy_hash` is a BLAKE3 fingerprint of the exact policy text, so
an auditor can prove which policy produced an output without the log carrying
the policy itself (which may hold an inline secret). Records are written for
failed jobs too, and it works identically for native, sandboxed and chained
runs.

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
    vault: out/visits-vault.jsonl      # optional per-job vault
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
- The mapping vault is **re-identification material**, encrypted at rest but as
  sensitive as the source data. `vault export` and `reverse` are privileged
  operations that reproduce personal data.
- `token` and `mock` pattern actions produce **pseudonymous, not anonymous**
  values, even in anonymize mode. Mocks additionally *look* real, which is the
  point and also the hazard — the report and lints call this out.
- The audit log is metadata-only by design; it records what happened, never the
  data it happened to.
- Policy lints are heuristics that catch common mistakes. A clean lint run is
  not a compliance statement.
- Non-goals: differential privacy, synthetic data generation, free-text/NLP
  de-identification, and legal certification of any output.

## Project layout

| Crate | Purpose |
|---|---|
| `crates/cli` | `deident` binary — command-line UX |
| `crates/core` | Policy schema, transforms, job engine, risk reports |
| `crates/host` | Execution engines: in-process native and per-job Wasmtime sandbox |
| `crates/worker` | Wasm guest that executes one job inside its sandbox |
| `crates/dicom` | DICOM policy, profile and de-identification engine |
| `crates/types` | Shared request/response/report models |

```bash
cargo test --workspace        # unit + integration tests (includes the feature matrix)
cargo clippy --workspace --all-targets
cargo test -p deident-cli --test matrix   # just the feature-combination matrix
```

CI (GitHub Actions) — two workflows with no overlapping work:

- `rust.yml` — build, clippy (`-D warnings`) and the test suite on every
  push/PR to main. It skips the feature matrix, which the second workflow
  owns.
- `feature-matrix.yml` — every mode × engine × single/chain combination
  against the sample dataset, triggered by changes under `examples/` or
  `crates/` (plus a manual "Run workflow" button). The matrix test recomputes
  its expectations from the data itself — determinism, native/wasm
  byte-parity, identifier survival, pattern counts, chain linkage — so editing
  the sample dataset automatically re-validates every feature against it.
  The full-feature policy it uses is
  [examples/policies/patients-full.yaml](examples/policies/patients-full.yaml).

Note that CI runs the latest stable Rust, which may lint more strictly than an
older local toolchain; run clippy with `-D warnings` locally to match it.

## Roadmap

Everything on the original roadmap is now implemented. What's next, roughly in
order of value:

- **Act on the security audit** — see [SECURITY_AUDIT.md](SECURITY_AUDIT.md);
  the temp-workspace permissions and fail-closed key resolution come first.
- **Streaming at scale** — Parquet and the equivalence-class statistics hold
  data in memory. Chunked row-group processing and a spill-to-disk class map
  would lift the dataset-size ceiling.
- **Broader DICOM coverage** — extend the tag table toward full Annex E, add the
  profile options (Retain Longitudinal Temporal, Retain Patient Characteristics,
  Retain Safe Private), and sandbox the DICOM parser.
- **Burned-in pixel detection** — OCR-assisted flagging of PHI rendered into
  image pixels. Detection only; cleaning would remain a claim we refuse to make.
- **Ship the worker with releases** — embed or bundle `deident-worker.wasm`
  next to the binary so `auto` always sandboxes instead of falling back.
- **k-anonymity enforcement** — today the report *measures* small equivalence
  classes; a `min_class_size: k` policy option could suppress or coarsen rows
  until the threshold is met, and fail the job if it cannot be.
- **Richer pattern library** — national ID formats, addresses, dates in free
  text, and a `--dry-run` scan mode that reports findings without writing
  output.
- **Vault key rotation and re-tokenization** — re-derive tokens under a new
  secret while preserving joins, using the vault as the bridge.
- **Column-level pattern strategies per class** — e.g. apply a pattern set to
  every `utility` column automatically instead of naming columns.
- **Policy authoring help** — `deident init <input>` to scaffold a policy from
  a dataset's header with class guesses from column names and content sniffing.
- **Differential-privacy noise for aggregates** — out of scope for row-level
  output, but useful if the tool grows a summary-export mode.
