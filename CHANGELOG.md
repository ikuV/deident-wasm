# Changelog

All notable changes to deident. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims at
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) — with the extra
compatibility surfaces described in [Versioning](#versioning) below, which matter
more than the crate version for anyone holding existing outputs.

## [Unreleased]

### Fixed

Two bug-hunting passes over the workspace produced 24 verified findings; these
are the ones fixed so far.

**DICOM multi-valued attributes** — DICOM attributes are frequently multi-valued
(`ID-1\ID-2\ID-3`), and the engine treated the backslash-joined string as one
scalar. Consequences, all now fixed by applying each action **value by value**:

- Values 2..n were destroyed rather than de-identified, and the vault recorded
  the joined string as the "original", so nothing could be reversed per value.
- `date_shift` shifted only the first value and left the rest as **original
  dates**, while the report said the attribute had been shifted.
- The UID cache keyed on the joined string, so one UID received two different
  replacements in different files and a multi-valued reference lost entries.
- Text VRs (`LT`/`ST`/`UT`/`UR`) are exempt, because a backslash there is literal
  content rather than a separator.

**Other correctness fixes**

- Writing the output over the input truncated the source before a byte was read,
  then reported success on the now-empty file — data loss with exit code 0,
  affecting `pseudonymize`, `anonymize`, `chain` and `reverse`. Now refused, with
  canonical-path comparison so `./a.csv` and `a.csv` are recognised as the same
  file. (The sandbox path was unaffected, so native and wasm disagreed.)
- The file-meta group kept the **original** SOP Instance UID unless the action was
  exactly `uid`, reintroducing the identifier the sync exists to remove. It now
  follows whatever the dataset ends up holding, and warns if that is empty.
- `bucket` panicked on `inf`, `NaN`, `1e30` and values near the `i64` bounds (and
  emitted reversed ranges in release builds). Those inputs are what numpy and R
  write for missing floats; they are now suppressed like any other bad value.
- `007` became `7` and `01234` became `1234` in JSONL and Parquet output. Integer
  re-typing now requires an exact text round-trip, as the float path already did.
- A digit string too large for `i64` turned a whole Parquet column into
  `Float64`, rewriting a 20-digit account number as `1e20`.
- `date_truncate` accepted any value starting with four digits, turning `10001`
  into year `1000` with no warning.
- Detector **execution order** was wrong: `phone` consumed SSNs and dates (and
  left fragments behind), and `person_name` claimed organizations and medical
  terms — so reports said "0 SSNs" for files full of them. `ALL` is now ordered
  most-specific-first.
- `::ffff:203.0.113.42` matched only `::ffff:203`, leaving most of the address in
  output the report called redacted.
- `api_key` missed `sk-proj-`, `sk-ant-api03-` and `github_pat_`.
- `email`'s local-part class contained `/ ? # &`, so it ate `//user@host` out of
  URLs and suppressed the `url` detector.
- `address` could never match a German-style address (`Musterstrasse 12`),
  leaving the whole German half of its own vocabulary unreachable.
- Tokenizing rules from `presets` did not count as "produces reversible values",
  so the vault was silently discarded while the report said none was needed; the
  `inline-key` lint was silent for the same reason.
- `free-text-without-patterns` ignored `presets` and so fired on policies that
  did scan the column — a false-positive lint, which teaches people to ignore
  lints.
- DICOM `clean_text` with no `patterns:` was the only silent case, and it is the
  worst one: `profile: basic` marks ~12 free-text attributes for cleaning.
- DICOM `profile: none` silently discarded an explicit `structural:` block, so
  names, private tags and study UIDs survived a policy that asked for exactly
  those protections — and it still warned that values were reversible.
- A DICOM vault was **write-only**: `vault export` parsed only the tabular
  dialect and rejected the policy that produced the vault.
- `chain` ran no policy lints and `--deny-lints` was a hard argument error; it
  also lacked the Parquet native fallback that single jobs have.
- `uids_remapped` counted distinct *tags* rather than distinct UIDs.

### Added

- A deterministic dataset generator
  (`cargo run -p deident-core --example gen_dataset`) producing four
  referentially-consistent tables with an engineered quasi-identifier
  distribution, plus `clinic-messy.csv` containing real-world damage (BOM,
  mixed-case headers, unparsable dates, Luhn-failing card shapes, zero-padded
  identifiers). See the README's *Example datasets*.

## [0.2.0] — 2026-08-04

### Added

- **Sandboxed execution.** Each job can run in its own WebAssembly sandbox
  (Wasmtime + WASI): a fresh store per job, the job directory as the only
  filesystem capability, no network, and per-job memory, wall-clock and
  fuel limits. `--engine auto|wasm|native`; `auto` prefers the sandbox and warns
  when it falls back.
- **Formats.** JSONL/NDJSON and Apache Parquet alongside CSV, inferred from the
  file extension, with input and output independent — so a job converts while it
  transforms.
- **Encrypted mapping vault.** `--vault` records original→token mappings under
  XChaCha20-Poly1305 with synthetic nonces, plus `deident vault export` and
  `deident reverse` for authorized re-identification.
- **Chained datasets.** `deident chain` runs several files as one export with
  shared token scoping, so foreign keys still join after pseudonymization.
  Identity domains (`pseudonymize.domain`) link differently named columns.
- **16 built-in entity detectors**, grouped by how much a match can be trusted:
  email, IBAN, credit card, IP (v4/v6), URL, API key, IFSC (*precise*); phone,
  SSN, date of birth, passport, licence plate (*moderate*); person name,
  address, organization, medical term (*heuristic*). Checksum validation where a
  checksum exists (mod-97, Luhn, SSN allocation rules); rejected matches are left
  intact and reported.
- **Pattern presets** — enable a whole precision class in one line instead of
  listing every rule.
- **Format-preserving mocks** — `action: mock` produces structurally valid fakes:
  IBANs with correct mod-97 digits, cards with a valid Luhn digit in the `999x`
  test range, punctuation-preserving phone numbers, RFC 2606 emails.
- **DICOM de-identification** — `deident dicom` for a file or a directory tree:
  a curated core of PS3.15 Annex E plus structural rules (every person-name VR,
  every identity UID, private tags, curve/overlay groups), consistent UID
  remapping across a study, interval-preserving date shifts, and free-text
  cleaning. Burned-in pixel PHI is **flagged, never removed**.
- **Policy lints** — 15 rules at warning/advice level, `deident lint`, plus
  pre-flight checks with `--no-lint` / `--deny-lints`.
- **Audit log** — `--audit-log` appends one metadata-only JSONL record per job,
  with a BLAKE3 policy fingerprint.
- **Version provenance** — every report and audit record now carries
  `tool_version`, because "no identifiers found" is only meaningful alongside the
  version that looked.

### Fixed

- `deident reverse` silently skipped pattern-derived values embedded in free
  text (an IBAN inside a note was recorded in the vault, exported correctly, and
  then left in place). Reversal now handles `pattern:*` domains by substring,
  longest-token-first.
- **Arbitrary directory deletion** (critical): a chain manifest's `job.name`
  reached a path that is `remove_dir_all`'d, so a manifest containing `../..` in a
  job name could delete an arbitrary directory. Workspace names are now a hash of
  the job id, the parent is asserted before any create/delete, and manifest names
  are validated at load time.
- The IBAN detector missed the canonical space-grouped and lowercase forms, and a
  first fix over-matched into the following words — the checksum then rejected the
  over-match and a **real IBAN went undetected**. Now compact-first alternation.
- The IPv6 detector truncated `2001:db8::1` to `2001:db8::`, leaving a fragment of
  the address in output reported as redacted.
- The `phone` detector matched ISO dates, IBAN digit runs and plain amounts, and
  could mask later, more specific rules.
- The email detector left a fragment behind on non-ASCII local parts
  (`müller@example.de` matched only `ller@example.de`).
- A stale DICOM file-meta group length made readers mis-locate the start of the
  dataset and **silently drop its first attribute** (`SOPClassUID`), rendering the
  instance unusable.
- DICOM padding: `trim()` does not strip the NUL byte DICOM pads odd-length values
  with, so the same UID could remap two different ways depending on its length.
- `clean_text` on a DICOM attribute that matched no pattern passed the free text
  through with no indication; it is now reported.

### Changed

- `JobOutcome::Succeeded` boxes its report (relevant if you deserialize responses
  yourself).
- `BuiltinPattern` moved to `deident_core::detect` and gained twelve variants; it
  is still re-exported from `deident_core::policy`.
- `MockShape::for_builtin` now returns `Option`, since most detectors have no
  meaningful format-preserving equivalent.
- Parquet is excluded from the wasm guest: including it inflated the module from
  ~0.6 MB to ~7.4 MB and dominated JIT time. Parquet jobs run in-process, and
  `--engine auto` routes them there automatically.

### Security

- Three independent audit passes (cryptography, sandbox boundary,
  privacy/leakage) are documented in [SECURITY_AUDIT.md](SECURITY_AUDIT.md) with
  a prioritized fix list. The critical finding is fixed; the high-severity items
  are open and tracked.

## [0.1.0] — 2026-08-03

Initial MVP.

### Added

- Rust workspace with `types`, `core`, `host`, `worker` and `cli` crates.
- YAML policy format classifying fields as `direct_identifier`,
  `quasi_identifier`, `sensitive` or `utility`, with deny-by-default handling of
  unlisted columns.
- Pseudonymization: deterministic BLAKE3 keyed tokenization, stable per
  dataset/policy, with the key sourced from an environment variable.
- Risk-assessed anonymization: `remove`, `redact`, `bucket`, `date_truncate` and
  `keep_prefix` strategies.
- Risk report with row counts, per-identifier actions and equivalence-class
  statistics (class sizes, unique rows, k-thresholds), plus fixed limitations
  language embedded in every report.
- `deident pseudonymize` / `deident anonymize`, sample dataset and policy.

## Versioning

The crate version is not the only compatibility surface that matters. Four move
independently, and the ones below the first are the ones that can invalidate data
you already hold:

| Surface | Where | Breaking means |
|---|---|---|
| Crate version | `Cargo.toml` | Rust API changes |
| Policy schema | `version:` in a policy | An existing policy stops loading |
| Vault format | header `version` field | An existing vault stops decrypting |
| **Token derivation** | not yet versioned | **Every previously issued token changes value** |

That last row is the dangerous one. Tokens are a keyed hash of the domain and the
value, so any change to the hash input — adding a length prefix, changing a
separator, altering the default domain — silently produces different tokens for
the same input. Joins against earlier exports break, and nothing errors.

So: **changing token derivation requires a major version bump and an explicit
migration note here**, even if the Rust API is untouched. The audit's `L4`/`L5`
hardening items (length-prefixing the hash inputs) fall in this category and are
deliberately deferred for that reason.

Reports and audit records carry `tool_version` so an artifact can always be traced
to the build that produced it.
