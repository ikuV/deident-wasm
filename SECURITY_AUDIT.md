# Security audit — deident

**Date:** 2026-08-04 · **Version audited:** 0.1.0 (commit after Phase 4)
**Scope:** the whole workspace, reviewed in three independent passes —
cryptography/key management, sandbox and host/guest boundary, and privacy/data
leakage. This is an internal engineering audit, not an external assessment or a
compliance certification.

**Threat model.** The primary asset is the re-identification capability: the
root secret, the mapping vault, and any residual identifying signal in
"anonymized" output. Adversaries considered: (a) a recipient of transformed
output, (b) a reader of artifacts the docs describe as safe to share or retain
(risk reports, audit logs, vault files), (c) an unprivileged local user on the
machine running deident, (d) a malicious or malformed *input dataset*. The
sandbox is judged against the project's own stated bar — it reduces blast
radius and makes no escape-proof claim.

---

## Summary of findings

Findings are prefixed by audit pass: **H/M/L** = cryptography, **P** = privacy
and leakage, **S** = sandbox and host boundary.

### Critical

| ID | Finding |
|---|---|
| S1 | A chain manifest's `job.name` flows unsanitized into a filesystem path that is then `remove_dir_all`'d — **arbitrary directory deletion** from a shareable config file |

### High

| ID | Area | Finding |
|---|---|---|
| S3 | Host | Predictable, world-readable `/tmp` workspaces holding a plaintext copy of the input, the vault, and any inline secret *(found independently by all three passes)* |
| S4 | Host | The host accepts the guest's self-attested outcome and risk report verbatim, including the `limitations` text — a hostile guest can forge a clean compliance artifact |
| H1 | Crypto | No entropy floor on the secret and no stretching; tokens are an offline brute-force oracle |
| H2 | Crypto | Inline-key fallback is fail-open: an unset or empty env var silently substitutes the policy-file secret |
| H3 | Crypto | Mocks are not injective; collisions are expected at realistic sizes and `reverse` then restores the wrong record |
| S2 | Host | Guest-planted symlinks turn output collection into host-side arbitrary file read *(requires a hostile guest)* |
| P1 | Privacy | A pattern rule scoped to a non-existent column is a completely silent no-op |
| P2 | Privacy | The IBAN pattern misses the canonical space-grouped format and lowercase |

### Medium

| ID | Area | Finding |
|---|---|---|
| P3 | Privacy | Pattern order dependence: the `phone` builtin swallows IBANs, cards and dates, masking later rules |
| M1 | Crypto | Vault lines are ordered by cleartext and unpadded — leaks the sort order and length of every original value |
| M2 | Audit | `policy_hash` commits to the inline secret, making the "metadata-only" log a key-recovery oracle |
| M3 | Crypto | `reverse` is domain-blind and rewrites every column |
| M4 | Crypto | No whole-file integrity on the vault: truncation, deletion and cross-file splicing are undetected |
| M6 | Crypto | Mock generation can pass the original through while reporting it as "mocked" |
| S5 | Host | A policy can name *any* host environment variable for guest passthrough |
| S6 | Host | No disk, inode or file-descriptor limits; unbounded host-side read of `response.json` |
| S7 | Host | The wall-clock timeout cannot preempt a blocking WASI call (`poll_oneoff`) |
| S8 | Host | Worker-module discovery trusts a CWD-relative path with no integrity check |
| S9 | Host | Chain manifest paths are not confined to the manifest directory |
| P4 | Privacy | Rules that matched nothing leave no trace in the report |
| P5 | Privacy | Builtin false negatives, and partial matches that leave identifying residue |
| P6 | Privacy | An empty-matching custom regex corrupts every scanned cell |
| P7 | Privacy | Nothing reports which columns survived verbatim |
| P8 | Privacy | The reversibility lints are Advice-level, so real runs never print them |
| P9 | Privacy | `free-text-without-patterns` has three bypasses |
| P10 | Privacy | No lint for an ineffective `keep_prefix` on a quasi-identifier |
| P11 | Privacy | `deident chain` skips pre-flight linting entirely |
| P12 | Privacy | The report computes the risk numbers but never warns when they are bad |
| P13 | Privacy | JSONL/Parquet output re-typing silently alters kept values (`007` → `7`) |

### Resolved during this audit

| ID | Finding |
|---|---|
| S1 | Arbitrary directory deletion via chain job names — **fixed**: the workspace directory name is now a BLAKE3 hash of the job id (so no input can introduce a separator or `..`), the parent is asserted to be the jobs root before any create/delete, and manifest/job names are validated against `[A-Za-z0-9._-]{1,64}` at load time. Regression tests in `crates/host/src/wasm.rs` and `crates/host/tests/chain.rs` |
| M5 | `reverse` skipped pattern-derived values embedded in text — **fixed**, with regression tests |

Plus 20 low-severity and informational items detailed in the sections below.

**On the crypto core specifically:** no key- or nonce-reuse break, no
unauthenticated decryption path, and no way to bypass the AEAD. The primitives
and their composition are sound; the high-severity crypto findings are about
key *sourcing* and *lifecycle*, not the construction.

---

## Cryptography and key management

Files: `crates/core/src/key.rs`, `vault.rs`, `mock.rs`, `policy.rs`,
`crates/cli/src/main.rs`, `crates/host/src/audit.rs`.

### H1 (High) — No entropy floor on the secret; tokens are a brute-force oracle

`key.rs` accepts any non-empty string as key material and passes it straight to
`blake3::derive_key`, a single-pass fast KDF. There is no length or entropy
requirement and no password stretching. The `dataset` name is the only salt, and
it is public — it appears in cleartext in the vault header.

Pseudonymized output is *designed to be shared*, and each row pairs a token with
cleartext quasi-identifiers. An attacker takes one token, a small candidate set
of plausible plaintexts (`P001…P999`, a corporate email pattern, a known
individual), and iterates candidate secrets: two BLAKE3 compressions per guess,
so >10⁷ guesses/second/core. Any human-chosen secret falls in minutes. Because
the vault key derives from the same root secret, recovering it collapses the
entire reversibility boundary at once.

The README claims "without the secret, tokens cannot be reversed or
recomputed". That holds only for a high-entropy secret, and nothing enforces it.

**Fix:** require ≥128 bits of real key material (accept only hex/base64 of ≥32
bytes and reject anything else), or route passphrases through Argon2id with the
dataset as salt and document that path explicitly. Add a `weak-secret` lint.
This is the highest-leverage change in the audit — most of the threat model is
downstream of secret entropy.

### H2 (High) — Inline-key fallback is fail-open

When a policy declares both `key.env` and `key.inline`, an **unset or empty**
environment variable silently falls through to the committed inline secret
(`key.rs`, the `_ => {}` arm). The only guardrails are a report warning and a
lint; neither blocks the run.

A renamed variable, a lost `EnvironmentFile`, or an expired CI secret that
resolves to `""` produces a successful job, exit code 0, and output whose tokens
are derivable by anyone with read access to the policy — typically everyone with
git access. Every token also silently changes value, so joins against prior
exports break: the analytics failure is loud, the privacy failure is quiet.

**Fix:** if `key.env` is declared, an unresolvable variable must be a hard
error. Gate the fallback behind an explicit `allow_inline_fallback: true`, or
forbid declaring `env` and `inline` together. Note this changes the shipped
examples' demo UX, which is the point.

### H3 (High) — Mocks are not injective; collisions corrupt reversal

Format-preserving mocks are bounded by the format's digit count, not by the
128-bit hash:

| Shape | Free digits | Space | Expected collisions |
|---|---|---|---|
| phone, 7 digits | 7 | ≈2²³ | ~5.5 at n = 10,000 |
| phone, 11 digits | 11 | ≈2³⁶ | ~5.5 at n = 1,000,000 |
| card, 16 digits | 12 | 10¹² | ~0.5 at n = 1,000,000 |
| email | 10 letters | ≈2⁴⁷ | negligible |
| IBAN (DE, 22) | 18 | 10¹⁸ | negligible |

Mocks are recorded in the vault exactly like tokens, and `reverse` builds a
`HashMap<token, original>` — so a collision means **last write wins, silently**.
A 10k-row export with `action: mock` on 7-digit phone numbers very likely
contains a collision, after which `reverse` writes customer A's real phone
number into customer B's row and reports success. That is worse than failing to
reverse: it is a confident *wrong* re-identification.

The code comment at the reverse map asserts the opposite ("tokens are unique per
value"), which is true for 128-bit tokens and false for mocks.

**Fix:** detect collisions at generation time (the vault writer already holds a
`BTreeMap` — fail or perturb-and-retry when one token maps to a second distinct
original); hard-error on duplicate token keys in `reverse` instead of
overwriting; document that mocks are not a general pseudonym for short formats.

### M1 (Medium) — Vault leaks the sort order and length of every original value

Vault entries are held in a `BTreeMap<(field, original), token>` and written in
`into_iter()` order, so **line order is the lexicographic order of the
cleartext**. XChaCha20-Poly1305 is length-preserving, so each line's length
reveals `len(field) + len(original) + len(token)`.

An attacker holding only the vault — the artifact the docs tell you to store
separately and back up — learns without the key: the number of distinct
mappings, the field grouping boundaries, the **complete lexicographic ordering
of the original values**, and each value's length. That is what
order-preserving encryption leaks, and against an auxiliary population list
(directory, roster, voter roll) sorted-order plus length narrows candidate
assignments sharply, pinning small classes exactly.

**Fix:** two cheap edits. Sort lines by their synthetic nonce instead of by
plaintext (the nonce is already a keyed PRF of the plaintext, so reproducibility
survives and the order leak disappears at zero cost), and pad plaintexts to a
fixed-width bucket before encryption.

### M2 (Medium) — `policy_hash` turns the audit log into a key-recovery oracle

`audit::policy_hash` is an unkeyed BLAKE3 over the *entire* policy text, which
includes `key.inline` when that path is used. The module documents the log as
metadata-only and safe to ship to a SIEM, and says the fingerprint proves which
policy ran "without the log carrying the policy (which may hold an inline
secret)". The hash *is* a commitment to that secret.

An attacker with SIEM read access — a much wider audience than policy-file
access, which is the whole point of exporting logs — plus the policy template
from git only needs to guess the secret and compare 128 bits. The chain path
makes it cleaner still, because the policy is re-serialized canonically by
`serde_yaml`, leaving no whitespace or key ordering to guess. Combined with H1,
this is practical key recovery from a stream documented as safe to export.

**Fix:** redact `key` before fingerprinting (parse, blank the field,
re-serialize canonically, hash that), or use a keyed fingerprint. Update the doc
claim either way.

### M3 (Medium) — `reverse` is domain-blind

The reverse lookup is keyed on the token alone; the recorded domain is
discarded, and the map is applied to every cell of every column. With 128-bit
hex tokens that is harmless. With mocks it is not: a `mock: phone` value
recorded for a free-text column can equal a genuine, never-tokenized phone
number in a kept `contact_phone` column, and `reverse` will overwrite that real
value with an unrelated person's original.

**Fix:** reverse per-domain — key on `(domain, token)` and apply each domain's
map only to the columns it was derived for (the policy supplies this mapping).

### M4 (Medium) — No whole-file integrity on the vault

Each line is individually AEAD-protected, but nothing binds the set of lines
together, and the AAD is identical for every line of every vault of that
dataset. Consequences: deleting or truncating lines is **silent** (`reverse`
reports success while an arbitrary subset was never reversed, with no expected
count to check against); reordering is undetected; and lines from one export can
be spliced into another export of the same dataset, so an attacker with write
access can make `reverse` restore superseded values as current.

Also, `read_vault` derives its AAD from the file's own unauthenticated header
rather than from a caller-supplied expectation.

**Fix:** bind the line index into the AAD and append an authenticated trailer
with the entry count, or encrypt-then-MAC the whole file. Have `read_vault`
take the expected dataset and compare it against the header.

### M5 (Medium) — Pattern values embedded in text were not reversed — **already fixed**

Pattern rules replace *substrings* inside a cell, and the vault records those
mappings, but `reverse` compared whole cells only. An IBAN tokenized inside a
free-text note was recorded, exported correctly, and then silently skipped —
the token stayed in the "restored" output.

Found independently by a manual smoke test during this work and **fixed** in
`crates/cli/src/main.rs`: `pattern:*` domains now reverse by substring,
longest-token-first, and the round trip is byte-exact. Regression tests added in
`crates/cli/tests/cli.rs`.

Still open from this finding: `reverse` reports what it replaced but not what it
*couldn't*. A count of cells containing unresolved token-shaped values would
make a partially-reversed run visible.

### M6 (Medium) — Mock generators can pass the original through unchanged

`credit_card` returns the input verbatim when it has fewer than two digits, and
`phone` substitutes only digit positions while copying every non-digit
character — so a match with no digits emerges unchanged. Both paths then record
`original == token` in the vault, increment the match counter, and the report
says the pattern was `"mocked"`. The operator has written positive evidence that
a value was replaced when it was not.

Reachable via a custom `regex` plus an explicit `mock:` shape — exactly the
combination the docs recommend for tuning. Worst case: `mock: phone` on
`\d{2}-[A-Za-z]+` turns `12-JohnSmith` into `34-JohnSmith`, leaking the name in
full while reporting success.

**Fix:** make the generators fallible. If the shape cannot produce a value that
differs from the original in every sensitive position, fail the job or fall back
to `redact` with a loud warning. A privacy transform must never return its
input.

### Low-severity (crypto)

- **L1 — Default file permissions.** The vault, the pseudonymized output, the
  `reverse` output (raw restored PII) and the `vault export` CSV are all created
  with `File::create` (`0644` after a typical umask); no `set_permissions` call
  exists in the workspace. Additionally, `vault export` writes to stdout when
  `--out` is omitted, and the "re-identification material" warning is printed
  only in the `--out` branch — so the invocation most likely to land in a
  terminal scrollback or CI log gets no warning at all.
- **L2 — `--vault` truncates despite "append-only" docs.** `File::create`
  truncates, so a second run against the same vault path destroys the first.
  Worth noting because the synthetic-nonce design is *justified* by append
  safety — the construction is sound on its own merits, but the stated
  motivation is for a capability the code does not have.
- **L3 — Vault buffers all plaintext in memory** until `finish`, so `--vault`
  fails opaquely at scale (inside the sandbox it trips the memory limit and is
  reported as "timeout, memory limit, or bug"). A mid-job error also leaves a
  0-byte vault, since the header is written in `finish`.
- **L4 — `0x1f` separator is not an injective encoding.** `("a\x1fb", "c")` and
  `("a", "b\x1fc")` hash identically. Not exploitable — the value side is
  attacker-controlled but the domain side is policy-author-controlled — but
  length-prefixing the domain closes the class permanently. Note this **changes
  every derived token**, so it needs a version bump. Field names and domains are
  also unvalidated, and the `pattern:` namespace is not reserved.
- **L5 — Mock material shares the token key** with only string-prefix
  separation, so `token(field="mock", …)` has the same hash input as mock
  material. Contrived to reach, but for a short IBAN the whole mock would be
  derivable from a public token. Same fix as L4, plus a dedicated KDF context.
- **L6 — Vault header is unauthenticated**, and its `cipher`/`kdf` fields are
  written and never read, so a future v2 reader has no trustworthy algorithm
  identifier. Impact today is limited to DoS.
- **L7 — `policy_hash` truncated to 128 bits** (64-bit birthday bound) for what
  is documented as a non-repudiation fingerprint. Keep the full 64 hex chars.
- **L8 — No zeroization** of the secret or derived keys; `zeroize` is not in the
  dependency graph. Secondary — the process holds plaintext PII anyway, and H4
  is a far larger exposure — but cheap to add.

### Verified correct (crypto)

Actively attacked and held:

1. **Key purpose separation is genuine.** `derive_key` is BLAKE3's dedicated KDF
   mode, and the token/vault/nonce contexts diverge early with none a prefix of
   another — no dataset name can make them collide (degenerate cases checked:
   empty dataset, leading `-nonce/`, embedded `/`). Neither key is derivable
   from the other without the root secret.
2. **The synthetic nonce is sound; the catastrophic case cannot occur.** Nonce
   reuse across *different* plaintexts would reuse the ChaCha20 keystream, but
   that needs a 192-bit BLAKE3 collision (~2⁹⁶ work). The subtler cross-AAD case
   is also closed: the vault key is dataset-derived, so same key implies same
   AAD. `key ‖ plaintext` is prefix-MAC, safe for BLAKE3, and the fixed 32-byte
   key makes the concatenation unambiguous. Leakage is exactly plaintext
   equality, length, and count.
3. **128-bit token truncation is sound.** Truncating an XOF is standard; at 10⁹
   distinct values per domain the collision probability is ≈1.5 × 10⁻²¹.
   Per-field and per-dataset separation work as documented.
4. **Wrong key and tampered ciphertext fail closed.** The tag is verified before
   any plaintext is returned; errors name the line without leaking key material;
   `read_vault` aborts on the first bad line rather than returning partial data;
   hex decoding and nonce length are strictly checked, with no panics on
   malformed input.
5. **No secret reaches logs, errors or reports.** Errors name the environment
   *variable*, never its value; the single warning carries no value; the audit
   record has no key field. The only leak is structural, via M2.
6. **Mock checksums are correct.** ISO 7064 mod-97-10 with safe incremental
   reduction (max intermediate 9635, no overflow), and Luhn with the right
   doubling parity for an appended check digit. Both round-trip against real
   reference values.
7. **The email mock discards the original entirely** and emits into RFC 2606
   `example.com` — the one shape with no residual-information concern.

Two documentation corrections worth folding in: the credit-card "999x test
range" comment is mislabeled (MII `9` is *reserved for national assignment*
under ISO/IEC 7812, not a designated test range — the practical claim holds
since no international scheme uses it, but the term is wrong, and for 2–3 digit
inputs the prefix is only `9`/`99`); and the README's framing of what
deterministic vault encryption leaks describes an intra-file case that dedup
makes impossible, while missing the real one — given two vaults for the same
dataset and secret, an attacker with no key can compute their exact
intersection.

---

## Privacy and data leakage

Files: `crates/core/src/engine.rs`, `policy.rs`, `transform.rs`, `report.rs`,
`lint.rs`, `format.rs`, `format_parquet.rs`, `crates/types/src/lib.rs`,
`crates/host/src/audit.rs`.

The headline result: **no dataset values leak into the report, audit log,
tracing output or CLI summary** — that part is genuinely well built and appears
deliberate. The findings are about identifiers *surviving into output* and about
failures that leave no trace.

### P1 (High) — A pattern rule scoped to a non-existent column is a silent no-op

`Patterns::compile` matches `rule.fields` against the actual headers. If nothing
matches, the rule lands in no column's list, never executes, records zero
counts, and therefore produces **no finding, no warning, no lint and no
error**. Policy `fields` absent from the input *are* warned about; the pattern
layer has no equivalent.

A policy scanning `fields: [notes]` against a CSV whose column is `note`,
`Notes`, or was renamed upstream emits IBANs verbatim into "anonymized" output,
and the report is byte-identical to a clean run.

**Fix:** after `Patterns::compile`, warn for every rule whose column set is
empty. Add a lint cross-checking `pattern.fields` against `policy.fields`.

### P2 (High) — The IBAN pattern misses the canonical printed format

`\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b`, verified against the exact pattern:

| Input | Result |
|---|---|
| `DE89370400440532013000` | match |
| `DE89 3704 0044 0532 0130 00` (ISO 13616 print format) | **miss** |
| `de89370400440532013000` | **miss** |

The space-grouped form is the *standard human-readable* IBAN — precisely the
spelling that appears in free-text notes and payment remarks, which is the
rule's stated use case. Combined with P4, the run looks clean.

**Fix:** `(?i)\b[A-Z]{2}[0-9]{2}(?:[ ]?[A-Z0-9]{2,4}){2,8}\b` or similar, with
the token domain computed on the whitespace-stripped match so both spellings map
to one token.

### P3 (Medium-High) — Pattern order dependence: `phone` swallows IBANs, cards and dates

Rules run sequentially, each seeing the previous rule's output. The `phone`
builtin `\+?[0-9][0-9 ()/\-]{6,}[0-9]` matches any run of ≥8
digits/spaces/dashes/parens/slashes — verified to match `2024-03-14` (a date),
an IBAN's digit body, `4111 1111 1111 1111` (a card), `1 234 567` (an amount)
and `90210-1234` (ZIP+4).

Verified on `"IBAN DE89370400440532013000 tel +49 89 5551234"`: with `phone`
first the result is `"IBAN DE[PHONE] tel [PHONE]"` and the `iban` rule then
finds nothing — the IBAN was mangled rather than deliberately handled, and (per
P4) the report shows no trace of the iban rule at all. With `iban` first the
result is correct.

Worse variants: `phone` as `mock` turns an unstrategized date column into a
plausible *different* date with the original recorded in the vault under
`pattern:phone`; a card caught by `phone` is tokenized in the wrong domain.
Mock outputs are also re-matchable — a mock card matches the `phone` builtin, so
a later rule re-replaces an earlier rule's mock.

The project knows about this (the full-feature example policy comments on rule
order) but nothing validates or lints it, and the failure is silent.

**Fix:** tighten the `phone` builtin (require separators or a leading `+`/`0`,
exclude ISO dates); lint when a broad rule precedes a narrower one on
overlapping fields; mark replaced spans as already-handled so later rules cannot
re-replace them.

### P4 (Medium) — Rules that matched nothing leave no trace

Findings and warnings are emitted only when `matches > 0`. So "the rule ran and
the data is clean", "the rule never ran" (P1) and "the regex missed everything"
(P2) are **byte-identical in the report**. For a tool whose report is the
evidence artifact, that is a significant assurance gap.

**Fix:** emit a finding with `matches: 0` per rule, or a per-rule
`columns_scanned` count, so a reader can see the rule executed and where.

### P5 (Medium) — Builtin false negatives, and partial matches that leave residue

Verified misses and partial matches:

- `müller@example.de` matches only `ller@example.de` → redaction yields
  `mü[EMAIL]`, leaving a name fragment. Same for `o'brien@…` → leaves `o'`.
  **Partial matching is worse than a clean miss because it looks handled.**
- `admin@localhost`, `user@[192.168.0.1]` — miss.
- `089.555.1234` (dot-separated) and `+49 89 – 5551234` (en dash) — miss.
- Amex in standard 4-6-5 grouping `3782 822463 10005` — **miss** (the pattern
  hard-codes groups of 4). Conversely a 13-digit order number matches, since
  there is no Luhn filter.

**Fix:** widen the email local-part class, allow `.` as a phone separator, add
Amex/Diners groupings, optionally Luhn-filter card matches, and document the
residue behaviour.

### P6 (Medium) — An empty-matching custom regex corrupts every scanned cell

`validate()` only checks that the regex compiles. `replace_all` with an
empty-matching pattern replaces at every position: verified, `regex: '[0-9]*'`
with `action: redact` turns `abc` into `[R]a[R]b[R]c[R]`. With `action: token`
every position yields a token of the empty string plus a vault entry per
position — the cell becomes unreadable, counts are inflated and the vault fills
with junk. On a large free-text cell this is also memory amplification.

**Fix:** reject any rule whose regex matches the empty string, in
`Policy::validate`.

### P7 (Medium) — Nothing reports which columns survived verbatim

`Sensitive`/`Utility` with no `anonymize` block is kept with **no warning**, and
`RiskReport` has no field enumerating kept-unchanged columns. So
`- {name: email, class: utility}` produces an "anonymize" output containing every
email address, and the report is silent. (`no-direct-identifiers` is Advice and
fires only when *zero* DI fields exist; `free-text-without-patterns` needs a
name hint.) By contrast QI-without-strategy is warned and linted properly.

**Fix:** add `kept_fields` to the report and print it in the CLI summary. Add an
`identifier-name-hint` lint for columns named like identifiers (`email`,
`phone`, `iban`, `ssn`, `dob`, `address`, …) classed `utility`/`sensitive`.

### P8 (Medium) — The reversibility lints are Advice, so real runs never print them

`preflight_lint` filters to `Warning`, and `--deny-lints` counts only warnings.
Both `reversible-pattern-in-anonymize` and `detect-only-pattern` are `Advice`,
so `deident anonymize --deny-lints` runs happily and says nothing about a policy
that inserts reversible tokens into an "anonymized" output. The README's claim
that "the report and the lints flag" this is true only for `deident lint`, not
for the job. The post-hoc report warning does fire — but after the output file
exists.

Worst case: `patterns: [{name: all, regex: '.+', action: token}]` under
`anonymize` is a fully legal policy producing an entirely pseudonymous output
with only an Advice-level pre-flight note.

**Fix:** promote both to `Warning` when the mode is anonymize.

### P9 (Medium) — `free-text-without-patterns` has three bypasses

- "Covered" is satisfied by any rule touching the field, **including a
  `detect`-only rule** — so adding a detect rule silences the lint while leaving
  every identifier in place.
- "Kept" is computed from `field.anonymize` regardless of the linted mode, so a
  `notes` field with `strategy: remove` is treated as removed when linting
  *pseudonymize* — a mode that keeps every non-DI column verbatim.
- The hint list is English-only while the project's examples are German-facing:
  `kommentar`, `bemerkung`, `freitext`, `notiz`, `beschreibung`, `anmerkung`,
  plus `body`, `subject`, `summary`, `details` are all missed.

### P10 (Medium) — No lint for an ineffective `keep_prefix` on a quasi-identifier

`keep_prefix { chars: 5 }` on 5-digit ZIPs returns the value **completely
unchanged**, while the report labels the action `prefix-truncated`. That is
worse than no strategy, because it suppresses the QI-without-strategy warning.

**Fix:** lint large `chars` on a QI, and better, have the engine detect at
runtime that a strategy left ≥X% of values byte-identical and warn.

### P11 (Medium) — `deident chain` skips pre-flight linting entirely

`ChainArgs` has no lint options and `run_chain` never calls `preflight_lint`, so
chained runs — the recommended path for real multi-file exports — never surface
`inline-key`, `qi-without-strategy` or `unlisted-columns-kept`, and
`--deny-lints` is unavailable. The manifest also injects its `key` override
*after* parsing, so a manifest-supplied inline key is never linted.

### P12 (Medium) — The report computes the risk numbers but never warns when they are bad

`min_class_size == 1` or a 90% unique-row ratio produces no warning — only
numbers a reader must interpret. For an anonymize job that is the single most
important residual-risk signal.

**Fix:** warn when `unique_rows > 0` in anonymize mode, and more strongly when
some rows are not even 2-anonymous.

### P13 (Medium) — JSONL and Parquet output re-typing silently alters kept values

Both writers re-infer types from the transformed strings:

- `typed_value("007")` → `7` (a test even asserts this). A ZIP `01067`, a phone
  `0891234`, or any zero-padded reference is **silently mutated** in JSONL.
- `"+4989551234".parse::<i64>()` succeeds in Rust, so a `+49…` phone column is
  inferred as `Int64` in Parquet and the `+` is dropped.
- A 20-digit account number fails `i64`, parses as `f64`, and is written as
  `1.0e20` — the value is destroyed.

Two consequences: a value the policy chose to *keep* is not what lands in the
file; and the equivalence-class statistics are computed on the pre-write
strings, so `01067` and `1067` count as two classes in the report but collapse
to one in the output. **The report can describe a table that differs from the
one shipped.**

**Fix:** require exact text round-trip for integers, as the float path already
does, or make re-typing opt-in.

### Low-severity and informational (privacy)

- **P14 (Low) — The audit log's `error` field can echo policy content.** Records
  are metadata-only for successful jobs, but failures store the raw error
  string, and `serde_yaml` messages quote the offending scalar — e.g. an
  unquoted numeric inline secret appears as `invalid type: integer \`123\``. The
  module doc explicitly promises the log does not carry the policy. `input_path`
  is also stored verbatim and can itself be identifying
  (`/exports/patient-schmidt-2024.csv`).
- **P15 (Low) — The JSONL "unknown key" error echoes a key from the data**,
  which for a value-keyed object puts a record identifier into a string that
  flows into the audit log.
- **P16 (Low) — The native engine leaves a partial output file** at the
  destination on failure (`File::create` truncates before success is known),
  whereas the wasm engine copies only on success. An inconsistency, not a leak;
  write to a sibling temp file and rename.
- **P17 (Low) — Header matching is exact and case-sensitive, and no UTF-8 BOM is
  stripped**, so an Excel-exported `\u{feff}patient_id` or `Email` vs `email`
  makes a policy entry inert. Deny-by-default turns this into a hard failure,
  which is the saving grace.
- **P18 (Informational) — ReDoS verdict.** The `regex` crate has no
  backtracking and guarantees linear time, so catastrophic backtracking is **not
  reachable**, including for user-supplied patterns over untrusted data. What
  that does *not* settle: large bounded repetitions are linear with a huge
  constant and can thrash the lazy-DFA cache (no explicit `size_limit`/
  `dfa_size_limit` is set); `replace_all` allocates unboundedly, compounding P6;
  and these costs are only bounded inside the sandbox. `--engine native` — which
  `auto` silently falls back to, and which **Parquet jobs are forced into** —
  has no memory or CPU bound at all. Worth stating in the README.
- **P19 (Informational) — Suppressed and empty QI values form one large
  equivalence class**, raising `min_class_size` and the k-coverage ratios.
  Defensible (a suppressed cell carries no information) and the suppression
  count is warned, but a reader cannot tell how much of the k≥10 coverage comes
  from suppressed rather than generalized rows. Consider reporting
  `rows_with_suppressed_qi`.

### Verified correct (privacy)

- **No cell values in any report structure.** Every `warnings.push` site
  interpolates only field names, rule names, counts and paths.
  `transform::InvalidValue` is a unit struct, so the failure path *structurally
  cannot* carry the offending value — a nice bit of design.
- **No `CoreError` variant embeds a cell value.** `csv::Error` renders positions
  and field indices only; `serde_json` errors are line/column only. The single
  exception is P15.
- **Tracing output and the CLI summary are value-free.** `vault export` and
  `reverse` are the only value-producing commands, and both print explicit
  re-identification notices.
- **Equivalence-class statistics are computed on the transformed values**, after
  both the column transform and the pattern rules; dropped columns are excluded
  and field order matches the tuple order.
- **The k-anonymity arithmetic is right**: `rows_at_or_above` sums class *sizes*
  (not counts), `unique_rows` equals the rows in size-1 classes, ratios use the
  correct denominator, and the empty cases return `None`. No off-by-one.
- **Anonymize defaults are safe**: direct identifiers default to `Remove`,
  unlisted columns default to `Error`, unknown YAML keys are rejected
  throughout, and there is no column-level strategy that tokenizes a direct
  identifier in anonymize mode.
- **Tokenized and dropped columns are excluded from pattern scanning** —
  correct, and it prevents a rule from re-mangling a token.
- **Empty cells are never tokenized or transformed**, so missing data stays
  missing rather than becoming a token that reveals which rows had a value.
- **Replacement closures do not perform capture-group expansion**, so a
  `replacement` containing `$1` is inserted verbatim — no injection path.
- **Row-length handling is safe** across all three formats.
- **The README's posture matches the code.** The findings above are gaps between
  implementation and the stated posture, not overclaiming in the documentation.

---

## Sandbox and host/guest boundary

Files: `crates/host/src/wasm.rs`, `lib.rs`, `chain.rs`,
`crates/worker/src/main.rs`, `crates/core/src/runner.rs`,
`crates/cli/src/main.rs`.

Findings are split between those exploitable **today** by the untrusted
data/config the tool is designed to consume, and those requiring a
malicious guest module — still in scope, because the boundary exists for
"future untrusted plugins", and because worker discovery (S8) makes a hostile
module realistic.

### S1 (Critical) — Chain job names reach `remove_dir_all` unsanitized

`ChainManifest::from_file` validates only the version and name uniqueness.
`job_id` is built as `format!("{}:{}", manifest.name, job.name)` from arbitrary
YAML strings, and `WasmEngine::run` interpolates it straight into a path:
`jobs_root.join(format!("job-{}", request.job_id))`. That path is then passed to
`create_dir_all`, `fs::copy` — and **`remove_dir_all`**.

```yaml
version: 1
name: export
jobs:
  - name: "../../../../Users/you/Documents"
    input: patients.csv
    policy: p.yaml
    output: out.csv
```

The workspace resolves to `~/Documents`. The host creates it, writes a plaintext
copy of the input dataset and `request.json` into it, and then **recursively
deletes the entire tree**. `remove_dir_all` resolves `..` normally, so std's
symlink-safe implementation does not help — the traversal is in the path itself,
not in its contents.

This needs no malicious guest and no local attacker: only that someone runs a
chain manifest, which is exactly the kind of artifact meant to be shared or
committed. Single jobs are unaffected (they use a UUID).

**Severity note:** the audit pass rated this High; I have raised it to Critical
because it is destructive, silent, and reachable from ordinary untrusted input.

**Fix:** never derive a path component from caller-supplied strings — use a
host-generated identifier — and assert `workspace.parent() == jobs_root` before
any `create_dir_all`/`remove_dir_all`. Validate manifest and job names against
`[A-Za-z0-9._-]{1,64}` as well.

### S2 (High) — Guest symlinks turn output collection into host-side arbitrary read

The workspace is preopened with `DirPerms::all()`/`FilePerms::all()`, which
enables `path_symlink` and `path_unlink_file`. cap-primitives refuses *absolute*
symlink targets but **allows relative targets containing `..`** — its own source
comments acknowledge the "trick a non-WASI program" scenario. cap-std then
refuses to follow them, so the *guest* stays contained; but the host collects
outputs with plain `std::fs::copy`, which **does** follow symlinks.

A hostile guest unlinks `/job/output.csv`, recreates it as a symlink to
`../../../../etc/passwd`, and reports success. The host copies the contents of a
file the guest could not read into the operator's output path — the file they
believe is the anonymized export and may forward onward. Read happens with the
host process's privileges. The same trick works for `report.json` and
`vault.jsonl`, and `staged.is_file()` also follows symlinks (a check-then-use
TOCTOU). Variants: point at a FIFO and the host blocks forever; point at
`/dev/zero` and fill the operator's disk.

**Fix:** collect through a `cap_std::fs::Dir` on the workspace, or at minimum
`symlink_metadata(...)` every artifact and reject anything that is not a regular
file.

### S3 (High) — Predictable, world-readable workspaces holding PII, the vault and the secret

*Found independently by all three audit passes (also reported as crypto H4 and
privacy P3).*

`jobs_root` is the fixed path `std::env::temp_dir().join("deident-jobs")` — on
Linux, inside the shared `/tmp`. `create_dir_all` creates it `0755`; guest files
land `0644`; `request.json` is written with `fs::write` (`0644`) and embeds the
**full `policy_yaml`, including `key.inline`**.

So for the duration of every job, any local user can read a complete plaintext
copy of the input dataset, the transformed output, the risk report, the
encrypted vault, and the inline secret — vault plus key together is full
re-identification. This is the code path whose purpose is to *increase*
isolation. macOS is largely spared because `$TMPDIR` there is a per-user `0700`
directory.

Two aggravations: `deident-jobs` is a fixed name, so an unprivileged user can
pre-create it (or symlink it) and relocate all job data under their control —
which also supplies the S2 primitive without needing a hostile guest. And for
chains the full path is deterministic (S1), so no race is needed at all.

**Fix:** `tempfile::Builder::new().permissions(0o700).tempdir_in(...)` per job
(random name, `O_EXCL`, RAII cleanup); create `jobs_root` `0700` and verify
ownership if it exists; strip `key.inline` from the guest's `request.json` and
pass the secret only via the WASI env, which is already scoped correctly; add a
`--jobs-root` flag so operators can choose a private volume.

### S4 (High) — The host trusts the guest's self-attested report

The host reads `response.json`, deserializes it, and on `Succeeded` copies
artifacts and returns the outcome **unchanged**. It never checks
`rows_read`/`rows_written` against the actual output, never checks that the
output differs from the input, and does not supply the `limitations` text itself
— despite the type documenting it as "fixed limitations language embedded in
every report".

A hostile guest copies the input verbatim to the output and writes a report
claiming `direct_identifiers: [{field: ssn, action: tokenized}]`,
`unique_rows: 0`, generous k-thresholds, `warnings: []`, and an emptied
`limitations` array. The operator sees a clean "Anonymize complete", the audit
log records success with forged counts, and untransformed personal data ships as
anonymized. **This is the highest-consequence failure mode for a privacy tool:
the compliance artifact is guest-attested rather than host-attested.**

**Fix:** treat `response.json` as a claim. Inject `limitations`, mode and
dataset from host-owned constants; recompute `rows_written` (and ideally a hash
of the output) host-side during collection and reject mismatches; bound the
response size before reading; mark report provenance in the audit record.

### Medium (sandbox)

- **S5 — A policy can name any host environment variable.** The variable *name*
  is fully policy-controlled, so `key: { env: AWS_SECRET_ACCESS_KEY }` forwards
  that secret into the guest. The doc claim ("no environment except the single
  key variable a pseudonymize policy names") is literally true but is not an
  allowlist. It also fires for anonymize jobs that need no key. Design note:
  even honestly, the guest receives the **raw secret**, so any future plugin
  gets a full tokenization oracle plus the vault key — the sandbox protects the
  host from the guest, not the key from the guest. **Fix:** require a
  `DEIDENT_*` prefix or an allowlist; resolve host-side and pass under a fixed
  guest-side name; skip passthrough when no key is needed; longer term keep the
  key host-side behind a host-function call.
- **S6 — No disk, inode or descriptor limits.** `StoreLimits` covers only linear
  memory. Nothing bounds bytes written into the preopened workspace, and
  Wasmtime's per-hostcall fuel is reset per call without charging store fuel, so
  `fd_write` loops are nearly free — a guest can fill the host filesystem within
  the 30 s default. The WASI descriptor table is unbounded, so a `path_open`
  loop exhausts `RLIMIT_NOFILE`. And `read_to_string` on `response.json` is
  unbounded, pulling a multi-GB file into host memory outside every configured
  limit.
- **S7 — The timeout cannot preempt a blocking host call.** Epoch interruption
  fires only at wasm instruction boundaries. `poll_oneoff` sleeps for a
  guest-supplied duration on the host thread, so a guest requesting `u64::MAX`
  nanoseconds hangs `Engine::run` effectively forever — `--timeout-secs` is
  bypassed and the workspace (with plaintext PII) is never cleaned up.
  **Fix:** enforce the deadline host-side on a dedicated thread, or use the
  async WASI path with a timeout wrapper.
- **S8 — Worker discovery trusts a CWD-relative path, unverified.** The
  candidate list ends with `target/wasm32-wasip1/{release,debug}/…` relative to
  the *current working directory*, loaded with no hash or signature check. So
  running `deident` inside any repository containing that path executes *that
  repository's* wasm as the "sandboxed" worker — with the dataset staged into
  its preopen and the secret in its environment. Chained with S2 and S4 that is
  a full job compromise delivered by a checked-in binary. **Fix:** drop the
  CWD-relative candidates from release builds, pin an expected BLAKE3 digest
  (the project already has both `blake3` and a policy-hash precedent), and
  record the module digest in the audit log.
- **S9 — Chain manifest paths are not confined.** `Path::join` with an absolute
  operand discards the base entirely, and `..` is never rejected — contradicting
  the documented contract that paths resolve against the manifest's directory.
  `output: ../../../../home/user/.ssh/authorized_keys` writes outside the tree,
  and the parent directory is created for you. Roughly caller-equivalent
  authority for a local CLI, but a real gap once a manifest is shared rather
  than authored locally.
- **S10 — `StoreLimits` leaves table growth unbounded.** `table_elements`
  defaults to unlimited, and table storage lives on the host heap **outside**
  `max_memory_bytes`, so a hostile module can allocate GBs past the advertised
  cap. Add `.table_elements(N)` and `.tables(1)`.

### Low and informational (sandbox)

- **S11 — Collection is non-atomic and ordered.** Output is copied before the
  report; if the report copy fails the job reports `Failed` but the host output
  has already been overwritten, and `fs::copy` can leave a truncated file that a
  downstream chain step may consume as complete. Copy to a temp sibling and
  rename after all artifacts validate.
- **S12 — The epoch deadline truncates instead of rounding up.** Integer
  division plus an unsynchronized ticker means the effective budget is
  `((n−1)·100 ms, n·100 ms]`, so a 150 ms request can be killed after almost no
  time, and `--timeout-secs 0` silently means ~100 ms. The code comment claiming
  timeouts are "rounded up" is wrong. Harmless at the 30 s default.
- **S13 — The epoch ticker thread is leaked per engine.** No shutdown path, no
  `Drop`; the thread holds an `Engine` clone that keeps the compiled module and
  JIT mappings alive for the process lifetime. A service constructing an engine
  per request accumulates a thread and an engine each time. It also wakes 10×/s
  when idle, and after `fork()` the ticker does not exist in the child, so
  **timeouts silently never fire there**. The doc comment claiming one ticker
  serves all instances does not match the code.
- **S14 — `inherit_stderr` is an unfiltered guest channel into host logs.** The
  guest can emit ANSI escapes into an operator's terminal and forge lines that
  mimic host `tracing` records, at unbounded volume. Pipe it into a bounded,
  prefixed, escape-stripped buffer re-emitted through `tracing` instead.
- **S15 — No cleanup on abnormal termination.** Cleanup is a plain statement,
  not a guard, so a panic, `Ctrl-C`, `SIGKILL`, OOM kill or the S7 hang leaves
  the workspace behind with plaintext PII. Nothing ever sweeps stale `job-*`
  directories. RAII (`tempfile::TempDir`) fixes this and S3 together.
- **S16 (Informational) — What the sandbox deliberately does not cover.** Policy
  YAML is parsed **on the host**, up to three times per job, and
  `Policy::validate` compiles guest-supplied regexes in the host process.
  serde_yaml 0.9 has no alias-expansion guard, so an anchor/alias bomb in a
  policy or manifest is a host-side DoS: the sandbox contains *dataset* parsing,
  not *config* parsing. `std::env::temp_dir()` honours `$TMPDIR` unvalidated.
  `Module::from_file` JIT-compiles with no limits, so a compile bomb is possible
  with an untrusted module (S8). And Parquet jobs bypass the sandbox entirely —
  documented, but it means the most complex parser in the tree (arrow/parquet)
  is the one that never runs sandboxed.

### Verified correct (sandbox)

Controls that genuinely hold as claimed:

1. **No network.** The default `SocketAddrCheck` denies everything;
   `inherit_network`/`allow_tcp`/`allow_udp` are never called, and the p1 linker
   exposes no socket-creation call.
2. **No stdio/env/args inheritance beyond intent** — only `inherit_stderr()` and
   three fixed argv values. The single env entry is explicit (S5 is about
   *which* variable, not accidental inheritance).
3. **Single preopen; guest-side traversal genuinely blocked.** cap-std blocks
   `..` and absolute host paths for the guest, `path_link` resolves both ends
   inside the preopen, and the existing tests cover exactly this. The residual
   issue (S2) is host-side symlink following, not a guest escape.
4. **Host paths never reach the guest** — every path is rewritten to `/job/…`
   before `request.json` is serialized.
5. **True per-job freshness** — new `Store`, `WasiCtx` and `ResourceTable` per
   job, with `instances(1)`/`memories(1)`; no cross-job state, including within
   a chain.
6. **Guest identity claims are ignored** — the returned response uses the
   *host's* job id, discarding whatever the guest wrote.
7. **No collection on trap or missing response.** Traps propagate, a missing or
   invalid `response.json` is an error, and collection runs only under
   `Succeeded` — so a fuel/epoch trap mid-write leaves the partial output inside
   the workspace only, and it is deleted. (S11 is a distinct ordering bug.)
8. **Memory and fuel limits are real and observable**, proven by existing tests,
   with `saturating_*` arithmetic and no overflow path. Limit hits surface as
   clean `Failed` outcomes, not panics.
9. **Env-key injection is not possible** — `std::env::var` errors on names
   containing `=` or NUL, so a crafted name cannot smuggle extra entries.
10. **No audit-log line injection** — records are serialized with
    `serde_json::to_vec` before the newline, so guest-controlled strings are
    escaped. (Its *truthfulness* is still limited by S4.)
11. **Cleanup does not follow guest symlinks** — `remove_dir_all` uses the
    `openat`/`unlinkat` implementation. S1 defeats this by manipulating the
    workspace *path*, not its contents.
12. **No `unsafe` anywhere in the workspace**, and job errors are consistently
    folded into `JobOutcome::Failed` rather than panicking.

---

## Recommended order of work

Ranked by (consequence × reachability) ÷ effort. The first three are reachable
from ordinary untrusted input, with no malicious guest and no local attacker.

1. **S1 — arbitrary directory deletion.** Destructive, silent, trivially
   reachable. Fixed immediately (see below).
2. **S3 — temp workspace permissions and predictability.** One `tempfile`
   change plus stripping the inline key from `request.json` closes a leak that
   all three audit passes found independently.
3. **H2 — fail-closed key resolution.** A small change that removes a silent
   production-key downgrade. Note it deliberately breaks the shipped demo UX,
   which is the point.
4. **S4 — host-attested reports.** Inject `limitations` host-side and recompute
   row counts during collection. This is the finding that undermines the
   product's core claim.
5. **P1, P2, P4 — pattern honesty.** Warn on rules that scanned nothing, fix
   the IBAN pattern to match its canonical printed form, and emit zero-match
   findings. Cheap, and directly determines whether identifiers survive.
6. **H1 — entropy floor on the secret.** Most of the threat model is downstream
   of this.
7. **P13 — output re-typing.** A data-integrity bug: values the policy chose to
   keep are silently altered, and the report can describe a different table than
   the one shipped.
8. **H3 + M3 — mock collisions and domain-blind reversal**, then **S2, S5, S8**
   (hostile-guest primitives), **M2** (redact before fingerprinting), **M1**
   (nonce-ordered, padded vault lines), and the remaining Medium items.
9. Low and informational items as convenient. **L4/L5** (length-prefixing hash
   inputs) should ride along with any release that touches `key.rs`, but note
   they **change every derived token** and therefore need a format version bump.

### Cross-cutting observations

- **The privacy-critical invariant holds.** No dataset value reaches a report,
  audit record, log line or CLI summary. That was clearly designed for, and it
  survived three adversarial passes with one trivial exception (P15).
- **The crypto construction is sound; its lifecycle is not.** Every primitive
  choice and composition survived attack. All four high-severity crypto findings
  are about where the secret comes from, how long it lives, and who can read it.
- **The sandbox protects the host from the guest, not the data from the guest.**
  It is honestly documented as a mitigation, and the containment controls hold.
  But the guest is handed the raw secret and a plaintext copy of the dataset, and
  the host trusts its report — so the sandbox does not yet make an untrusted
  plugin *safe*, only *contained*. S4, S5 and S8 are the gap between those two
  words.
- **Silence is the recurring theme.** S1, P1, P4, P7, P12 and M5 are all cases
  where a failure produces output indistinguishable from success. For a tool
  whose report is the evidence artifact, "did nothing, said nothing" is the most
  dangerous failure mode, and it deserves a systematic pass rather than
  case-by-case fixes.

## Methodology and limitations

Three independent read-only passes over the workspace at the commit noted above,
each given a domain, an explicit threat model, and instructions to distinguish
exploitable defects from hardening and to report what it verified as correct.
Findings were cross-checked against the source; the temp-workspace issue was
reported by all three passes independently, which is some evidence the coverage
overlapped usefully rather than leaving gaps.

Not covered: dependency/supply-chain review (no `cargo audit`/`cargo deny` run),
fuzzing of the format parsers, side-channel and timing analysis, review of the
`wasmtime`/`arrow` dependency internals beyond the API surface used here, and any
formal privacy-guarantee analysis. Nothing here constitutes a compliance
assessment.
