# AGENT PLAN — DICOM de-identification

Extends deident from tabular datasets to DICOM instances. Companion to
AGENT_PLAN.md (tabular engine) and SECURITY_AUDIT.md.

## Goal and scope

Implement **metadata (tag-level) de-identification** of DICOM instances,
reusing the existing key/token/mock/vault/audit machinery, with honest
boundaries:

- **In scope:** attribute removal/replacement/zeroing, consistent UID remapping,
  date shifting/truncation, free-text cleaning via the existing pattern rules,
  private-tag handling, recursive descent into sequences, per-instance and
  per-study reports.
- **Detect and flag only:** burned-in pixel PHI. We report the risk signals
  (`BurnedInAnnotation`, high-risk modalities, secondary-capture types) and
  refuse to claim the pixels are clean.
- **Explicitly NOT claimed:** full DICOM PS3.15 Annex E conformance. We
  implement the Basic Profile's well-established core plus *structural* rules,
  and say so. Users extend via policy.

## Why not "just another Format"

The tabular engine is `RowReader`/`RowWriter` over rows of string cells. A DICOM
object is a nested, tag-keyed attribute tree with typed value representations
(VRs), arbitrarily deep `SQ` sequences, a separate file-meta group, and a pixel
payload. It therefore gets its own crate, policy dialect and job kind — not a
`Format` variant.

## Architecture decisions

| Decision | Choice | Rationale |
|---|---|---|
| Placement | New crate `crates/dicom` (`deident-dicom`) | Keeps the dicom-rs stack out of `core`, so the wasm guest and tabular path stay lean (the arrow lesson) |
| Library | `dicom-object` / `dicom-core` / `dicom-dictionary-std` 0.10 | The maintained Rust DICOM stack; in-memory object model with the mutation API we need |
| Tag coverage | Curated Basic-Profile core **+ structural rules** | A half-remembered 500-row table is worse than a small exact table plus rules that catch whole classes (all `PN` VRs, all UID tags, all private tags). Honest and safer |
| Policy | Separate `kind: dicom` YAML dialect, tags by keyword or `(gggg,eeee)` | Tag addressing has nothing in common with column names |
| UID remapping | Deterministic `2.25.<128-bit decimal>` derived from the keyed hash | ISO/IEC 9834-8 / DICOM PS3.5 B.2 permits UUID-derived roots; deterministic ⇒ consistent across a study and reproducible |
| Identity scoping | Reuse `dataset` + token domains | Same UID → same replacement across every file of a study, which is exactly the chain/domain property |
| Dates | Shift by a deterministic per-patient offset, or truncate | Preserves intervals (the clinically useful part) without keeping true dates |
| Reversal | Reuse `EncryptedVault` | UID and identifier mappings recorded exactly like tabular tokens |
| Pixel data | Risk flags only, never modified | Cleaning burned-in text needs OCR and cannot be made reliable |
| Test fixtures | **Synthesized** with known PHI | Public DICOM is already de-identified, so it cannot prove a de-identifier works |

## Deliverables

1. `crates/dicom` — policy, profile, engine, report, UID/date generators.
2. `deident dicom <input> --policy p.yaml --out <output>` — single file or
   directory (recursive), with `--report`, `--vault`, `--audit-log`.
3. Synthetic fixture generator producing PHI-laden instances for tests.
4. Example policy + a generated example instance.
5. Tests: per-action, structural rules, UID consistency across a study,
   sequence recursion, pixel flagging, round-trip readability, CLI e2e.
6. README section + roadmap/plan updates.

## Phases

### Phase D0 — Crate scaffold ✅
- [x] `crates/dicom` with dicom-rs deps, wired into the workspace
- [x] This plan

### Phase D1 — Policy and profile model ✅
- [x] `TagSelector`: keyword (`PatientName`) or explicit `(0010,0010)`
- [x] `TagAction`: `remove | empty | replace | pseudonymize | uid | date_shift |
      date_truncate | clean_text | keep`
- [x] `DicomPolicy`: dataset/key (reused), `profile`, per-tag rules, structural
      toggles, pattern rules for text cleaning
- [x] Built-in `basic` profile: curated Annex E core
- [x] Structural rules: all person-name VRs, all UID tags, private tags,
      curve/overlay groups
- [x] Validation + `deny_unknown_fields`

### Phase D2 — Engine ✅
- [x] Recursive traversal including `SQ` items (PHI hides in nested items)
- [x] Action application, VR-aware
- [x] Deterministic UID generator (valid: ≤64 chars, no leading-zero components)
- [x] Date shift/truncate for `DA`/`DT`/`TM`
- [x] Free-text cleaning through `deident_core` pattern rules
- [x] File-meta consistency (`MediaStorageSOPInstanceUID` follows
      `SOPInstanceUID`)
- [x] Vault recording of every reversible mapping
- [x] Pixel-risk assessment (never modifies pixels)

### Phase D3 — Report ✅
- [x] `DicomReport`: per-tag actions, counts, pixel risk, warnings, fixed
      limitations language
- [x] Study/series/instance UID mapping counts
- [x] Directory mode aggregate report

### Phase D4 — CLI ✅
- [x] `deident dicom` subcommand, file or directory, engine-agnostic (native;
      the dicom stack is not in the wasm guest — documented)
- [x] Report/vault/audit wiring, lint-style pre-flight warnings

### Phase D5 — Fixtures and tests ✅
- [x] `synthetic` module: build instances with known PHI in known tags
- [x] Unit tests per action and per structural rule
- [x] Integration: study-wide UID consistency, sequence recursion, no-PHI-survives
- [x] CLI e2e on a generated study

### Phase D6 — Docs ✅
- [x] README section with the honest scope statement
- [x] Plan/roadmap updates

## Risks and honest limitations

- **Not conformance.** We implement a documented subset. Anyone needing
  certified Annex E conformance must extend the tag table and validate it
  themselves. The report says this in its limitations block.
- **Burned-in PHI is not removed.** Flagged only. This is the single biggest
  residual risk for ultrasound, secondary capture and scanned documents.
- **Private tags** carry unknown vendor semantics; default is removal, which can
  break vendor tooling. `retain_safe_private` is opt-in and explicitly risky.
- **Pixel data passes through untouched**, so file size and transfer syntax are
  preserved but any PHI in the pixels survives.
- **The dicom-rs parser runs in-process**, not in the wasm sandbox — and DICOM
  parsers are historically a CVE-rich surface. Documented; sandboxing the DICOM
  path is future work (the guest would need the dicom stack, repeating the arrow
  bloat trade-off).
- **UID remapping breaks external references** by design; anything outside the
  processed set (a PACS, a report referencing the old UIDs) will not resolve.
