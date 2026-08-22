# Changelog

All notable changes to deident. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims at
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) — with the extra
compatibility surfaces described in [Versioning](#versioning) below, which matter
more than the crate version for anyone holding existing outputs.

## [Unreleased]

### Added

- **`bic` detector** (ISO 9362 / SWIFT), the eighteenth built-in and the tenth
  validated one. A BIC sits next to an IBAN in every payment export and names
  the account holder's bank, which is one of the strongest linking attributes a
  "pseudonymized" financial dataset can leak; the `iban` detector walked past it.

  Validation is structural, because a BIC carries no check digit: 8 or 11
  characters, a **real ISO 3166-1 country code** in positions 5–6, and the two
  location-code rules from the standard (never `0`/`1` first — reserved to
  distinguish BICs from other code types — and never `O` second, since it is
  indistinguishable from zero in print). The country-code table is what makes
  the detector precise rather than "any eight capitals": `ABCDEFGH` has the
  shape, but `EF` is not a country. `XK` is included even though ISO only
  user-assigns it, because Kosovan banks issue BICs under it.

  Unlike `iban`, the pattern is **uppercase-only**. With no checksum the country
  code is the sole filter, and matching lowercase would put every eight-letter
  word in a free-text note ahead of it; SWIFT specifies uppercase, so the
  recall cost is small and the false-positive saving is not.

  **No `action: mock`**, deliberately. The shape is trivial to imitate, but
  unlike email (`example.com`) or MAC (the locally-administered range), ISO 9362
  reserves no space for codes that cannot exist — so every "fake" BIC risks
  naming a real institution. `redact` and `token` are the honest options.

- **`deident detectors`** — print the built-in detector catalog: name, precision
  class, the validator that runs for it, whether `action: mock` has a
  format-preserving shape for it, and an example match. `--class
  <precise|moderate|heuristic>` narrows the listing, `--json` makes it
  consumable.

  The catalog was documented only in the README, so choosing a `builtin:` value
  meant leaving the terminal, and `mockable` was not written down anywhere at
  all — the difference between a working `action: mock` and a policy that fails
  at run time. The command reads `detect::ALL` directly, so it cannot drift from
  the code the way a table can, and it lists detectors in **execution order**
  (which is load-bearing: an earlier detector consumes text a later one would
  have matched). A test asserts the listing against the catalog rather than
  against a hand-written expectation.

  The heuristic caveat is printed with the listing, not buried in the docs: a
  `person_name` match is a candidate for review, not clean output.

- **`mac_address` detector**, the seventeenth built-in and the ninth validated
  one. Hardware addresses are stable device identifiers — a MAC in a log line or
  a medical-device export follows one machine, and one user, across every other
  pseudonym in the dataset — and until now nothing found them.

  Matches the three written conventions (`00:1A:2B:3C:4D:5E`,
  `00-1a-2b-3c-4d-5e`, Cisco `001a.2b3c.4d5e`), each as its own alternative so a
  mixed-punctuation string matches nothing rather than being reported as an
  address. Validation is structural, since a MAC carries no check digit: twelve
  hex digits, rejecting the all-identical wildcards `00:00:00:00:00:00` and
  `ff:ff:ff:ff:ff:ff` that appear in ARP tables and config templates. An
  unassigned OUI is still accepted — refusing it would be a false negative,
  which is the worse failure.

  It runs **after** `ip_address` in the catalog, and a test enforces the order:
  both read colon-separated hex, and the six-group MAC pattern otherwise claimed
  the first six groups of an eight-group IPv6 address, leaving the last two in
  output the report called redacted.

  `action: mock` is supported. The mock keeps the original's separator style and
  letter case, and always sets the locally-administered bit while clearing the
  multicast bit, so it parses as a unicast address for anything that validates
  its input but can never collide with a real vendor OUI — the same reasoning as
  mocking email into the `example.com` documentation domain.

- **Parallel execution.** Two independent axes, each giving every job its own
  sandbox (fresh `Store`, WASI context and limits); the guest module is compiled
  once and shared, nothing else is.

  - **Several datasets at once** — `deident pseudonymize a.csv b.csv c.jsonl
    --out ./dir`. Results are reported in input order whatever order they finish
    in, and one dataset failing does not stop the others.
  - **One large dataset across N sandboxes** — `--split N`. Output is
    **byte-identical** to an unsplit run, since tokens are a deterministic
    function of the key and the value. On a 200k-row CSV, 8 sandboxes cut wall
    clock roughly 3x.
  - `--jobs N` caps concurrency (default: cores, capped at 8).

  The interesting part is the report merge. Row and pattern counts are additive,
  but the **equivalence-class statistics are not**: a quasi-identifier combination
  appearing once in chunk A and once in chunk B is one class of size two, not two
  classes of size one. Summing them would *overstate* re-identification risk, and
  someone widening their buckets in response would be chasing an artefact of the
  chunking. So they are not merged — after the chunk outputs are concatenated the
  host recomputes them over the whole output through the same code path a
  single-job run uses. A split report says so in a warning, and tests pin its
  `unique_rows`, `equivalence_classes` and `k_thresholds` to the unsplit figures.

  Refused rather than approximated: `--split` with Parquet (columnar, so a byte
  range is not a valid file) and `--split` with `--vault` (each chunk would write
  its own vault with overlapping entries).

- A deterministic dataset generator
  (`cargo run -p deident-core --example gen_dataset`) producing four
  referentially-consistent tables with an engineered quasi-identifier
  distribution, plus `clinic-messy.csv` containing real-world damage (BOM,
  mixed-case headers, unparsable dates, Luhn-failing card shapes, zero-padded
  identifiers). See the README's *Example datasets*.

### Security

Acting on [SECURITY_AUDIT.md](SECURITY_AUDIT.md):

- **H3 — mock collisions no longer corrupt re-identification.** Format-preserving
  mocks have a value space bounded by the shape they imitate: a 9-digit phone
  number allows 10^9 mocks, so by the birthday bound two originals start sharing
  one at ~31,000 distinct values (confirmed by exhaustive search — the two
  colliding values are pinned in `crates/core/tests/mock_collisions.rs`). When
  that happened, `reverse` silently returned whichever mapping won a hash-map
  insert, handing back **the wrong person's data** while reporting success. Now
  the risk report names the pattern and counts collisions at transformation time,
  and `reverse` refuses an ambiguous value — leaving it in place and exiting
  non-zero — instead of guessing.

- **Key resolution is now fail-closed.** A policy declaring both `key.env` and
  `key.inline` used to fall back to the inline value when the variable was unset.
  A forgotten `export` therefore produced output that looked correctly
  pseudonymized but was reversible by anyone holding the policy, and did not join
  with earlier exports. The run now fails; `key.allow_inline_fallback: true` opts
  back in explicitly, and the fallback is then reported identically by both
  engines. **Breaking** for policies that relied on the old behavior.
- **Minimum secret length of 32 bytes**, with a warning for long-but-low-entropy
  passphrases.
- **Reports from a sandboxed job are host-attested.** The host re-derives what it
  owns and verifies what it can cheaply check, rather than trusting figures a
  guest authored — a compromised worker could otherwise report clean counts over
  untransformed data. The new `report_provenance` field states which regime
  produced a report.
- **`policy_hash` no longer commits to an inline secret**: the key block is
  removed before hashing, so the fingerprint still identifies the policy but the
  audit log cannot be used to confirm a guessed secret.
- Per-job sandbox workspaces are created `0700` and staged files `0600`; only the
  one key variable the policy names is passed into the guest; collected artifacts
  are rejected if they are symlinks.
- **The audit log's `error` field is capped** at 300 characters and flattened to
  one line. Failure text is assembled from whatever went wrong, so it could quote
  a policy value or a column name into a long-lived file kept where the data is
  not; the full message still goes to stderr.

### Fixed

- `free-text-without-patterns` was **English-only** while the policies this tool
  ships with are German-facing, so a `Bemerkung` or `Notiz` column full of prose
  passed the lint in silence. The hint list now covers `kommentar`, `notiz`,
  `bemerkung`, `anmerkung` and `beschreibung` alongside `summary`, `details` and
  `subject` (`freitext` already matched via `text`). `body` is deliberately left
  out: as a substring it fires on `antibody_titer`, and a lint with false
  positives is one people learn to ignore.
- The `duplicate-builtin-detector` message reached the terminal with a long run
  of spaces mid-sentence — a missing line continuation in the format string.
- The README's lint list omitted `duplicate-builtin-detector` and
  `heuristic-pattern-modifies-data`, both of which have shipped for a while.

Two bug-hunting passes over the workspace produced 24 verified findings. All of
them are fixed.

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

### Added

- **Five more validated detectors**, taking verification from 3 of 16 to **8 of
  16**. `ip_address` is now parsed with `std::net::IpAddr` (exact, where a regex
  can only approximate — it rejects `1:2:3:4:5:6:7:8:9` and `12:30`);
  `date_of_birth` must be a real calendar date (`31/02/1990` and `29/02/1900` are
  rejected, leap years honoured); `email` is checked against RFC 5321 structure;
  `url` needs a known scheme and plausible host; `phone` must satisfy E.164
  limits. `credit_card` was upgraded from bare Luhn to Luhn **plus** card length
  and issuer prefix, because Luhn alone accepts roughly one in ten arbitrary
  digit strings. Rejection warnings now name the validator that rejected the
  match.

  Validators are conservative by design: they reject only what is definitely not
  the thing, since over-strict validation causes false *negatives*. Ambiguous
  dates are therefore accepted under either DD/MM or MM/DD reading, and
  `date_of_birth` does not check birth-date plausibility. `api_key`, `ifsc`,
  `passport`, `license_plate` and the four heuristics remain unvalidated, which a
  test now pins so the docs cannot over-claim.

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
- **A job that failed partway left its partial output on disk**, where a
  downstream consumer would read it as a complete, transformed dataset. Output and
  vault are now written to a temporary sibling file and moved into place only after
  the job runs to completion; a failure publishes neither.
- **A UTF-8 BOM broke the first column.** Excel and many Windows tools prefix one,
  which made the first header `\u{feff}patient_id` — so a policy field naming that
  column matched nothing. Under the default `on_unlisted: error` the job failed
  confusingly; under `on_unlisted: keep` the identifier was copied through in the
  clear. The BOM is now stripped from CSV headers and from a leading JSONL line.
- **An unmatched policy field is now diagnosed, not just mentioned.** When the only
  difference is case or surrounding whitespace (`patient_id` vs `Patient_ID`) the
  warning names the actual column and states that the rule was *not* applied; when
  the field named a direct identifier, it says the data was copied through
  unchanged.
- Two engines disagreed about the same job: the sandbox host mirrored the
  inline-key fallback warning into every report, including anonymize-only jobs that
  never resolve a key. Both engines now share one `needs_key` predicate rather than
  each deciding for itself.
- A JSONL record declaring an undeclared key put that key verbatim into the error
  message, which travels to logs and audit records. Keys are input-derived, so the
  label is now length-capped with control characters replaced.

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
