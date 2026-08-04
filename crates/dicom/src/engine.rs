//! The DICOM de-identification engine.
//!
//! Walks an instance's attribute tree — including into sequence items, where PHI
//! routinely hides — and applies the resolved policy to each attribute. Pixel
//! data is never modified; it is only assessed for burned-in-annotation risk.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use dicom_core::header::{HasLength, VR};
use dicom_core::value::{PrimitiveValue, Value};
use dicom_core::{DataElement, Tag};
use dicom_dictionary_std::tags;
use dicom_object::mem::InMemDicomObject;
use dicom_object::DefaultDicomObject;

use deident_core::vault::{MappingEntry, MappingVault, NoopVault};

use crate::error::DicomError;
use crate::policy::{
    DateGranularity, DicomPolicy, MockShapeCfg, ResolvedPolicy, TagAction, is_private,
};
use crate::profile;
use crate::report::{DicomReport, InstanceOutcome, PixelRisk, StudyReport, TagFinding, risk_rank};
use crate::uid;

/// Modalities whose images very often carry burned-in identifiers.
const HIGH_RISK_MODALITIES: &[&str] = &["US", "SC", "OT", "XC", "ES", "GM", "IVUS"];

/// Options for a de-identification run.
#[derive(Debug, Clone, Default)]
pub struct RunOptions {
    /// Path for an encrypted mapping vault recording every reversible mapping.
    pub vault_path: Option<PathBuf>,
}

/// De-identify a single DICOM file.
pub fn deidentify_file(
    input: &Path,
    output: &Path,
    policy: &DicomPolicy,
    options: &RunOptions,
) -> Result<DicomReport, DicomError> {
    let mut vault = open_vault(policy, options)?;
    let mut uid_cache = HashMap::new();
    let report = deidentify_with_cache(input, output, policy, vault.as_mut(), &mut uid_cache)?;
    vault
        .finish()
        .map_err(|e| DicomError::Transform(format!("cannot finalize vault: {e}")))?;
    Ok(report)
}

/// De-identify every DICOM instance under `input` (recursively), writing results
/// into `output` with the same relative layout.
///
/// One shared vault and one shared identity scope, so UID remapping stays
/// consistent across the whole study.
pub fn deidentify_directory(
    input: &Path,
    output: &Path,
    policy: &DicomPolicy,
    options: &RunOptions,
) -> Result<StudyReport, DicomError> {
    let mut vault = open_vault(policy, options)?;
    let mut files = Vec::new();
    collect_files(input, &mut files)?;
    files.sort();

    let mut instances = Vec::new();
    let (mut read, mut written, mut failed, mut skipped) = (0u64, 0u64, 0u64, 0u64);
    let mut uid_cache: HashMap<String, String> = HashMap::new();
    let mut highest_risk = "low".to_string();
    let mut warnings = Vec::new();

    for file in &files {
        let relative = file.strip_prefix(input).unwrap_or(file);
        let destination = output.join(relative);
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)?;
        }
        read += 1;
        match deidentify_with_cache(file, &destination, policy, vault.as_mut(), &mut uid_cache) {
            Ok(report) => {
                if risk_rank(&report.pixel_risk.level) > risk_rank(&highest_risk) {
                    highest_risk = report.pixel_risk.level.clone();
                }
                written += 1;
                instances.push(InstanceOutcome::Succeeded {
                    source: file.display().to_string(),
                    output: destination.display().to_string(),
                    report: Box::new(report),
                });
            }
            Err(DicomError::Read { path, source }) => {
                // Not a DICOM file (or unreadable): skip rather than fail the
                // whole run, so a directory with stray files still works.
                skipped += 1;
                instances.push(InstanceOutcome::Skipped {
                    source: path,
                    reason: format!("not a readable DICOM instance: {source}"),
                });
            }
            Err(err) => {
                failed += 1;
                instances.push(InstanceOutcome::Failed {
                    source: file.display().to_string(),
                    error: err.to_string(),
                });
            }
        }
    }

    vault
        .finish()
        .map_err(|e| DicomError::Transform(format!("cannot finalize vault: {e}")))?;

    if skipped > 0 {
        warnings.push(format!(
            "{skipped} file(s) under the input were not readable DICOM instances and were skipped"
        ));
    }
    if failed > 0 {
        warnings.push(format!("{failed} instance(s) failed to de-identify"));
    }
    if read == 0 {
        warnings.push("no files found under the input path".to_string());
    }

    Ok(StudyReport {
        tool_version: crate::VERSION.to_string(),
        dataset: policy.dataset.clone(),
        root: input.display().to_string(),
        instances_read: read,
        instances_written: written,
        instances_failed: failed,
        non_dicom_skipped: skipped,
        instances,
        distinct_uids_remapped: uid_cache.len() as u64,
        highest_pixel_risk: highest_risk,
        warnings,
        limitations: DicomReport::limitations(),
    })
}

/// Open the mapping vault, if one was requested and the policy can key it.
fn open_vault(
    policy: &DicomPolicy,
    options: &RunOptions,
) -> Result<Box<dyn MappingVault>, DicomError> {
    let Some(path) = &options.vault_path else {
        return Ok(Box::new(NoopVault));
    };
    let secret = resolve_secret(policy)?;
    let vault_key = deident_core::vault::derive_vault_key(&secret, &policy.dataset);
    let file = std::io::BufWriter::new(std::fs::File::create(path)?);
    Ok(Box::new(deident_core::vault::EncryptedVault::new(
        file,
        &vault_key,
        &policy.dataset,
    )))
}

fn resolve_secret(policy: &DicomPolicy) -> Result<Vec<u8>, DicomError> {
    let probe = deident_core::Policy {
        version: 1,
        dataset: policy.dataset.clone(),
        key: policy.key.clone(),
        on_unlisted: Default::default(),
        fields: Vec::new(),
        patterns: Vec::new(),
        presets: Vec::new(),
    };
    let mut warnings = Vec::new();
    deident_core::key::resolve_secret(&probe, &mut warnings)
        .map_err(|e| DicomError::Key(e.to_string()))
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), DicomError> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_files(&path, out)?;
        } else if path.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

/// Per-run mutable state threaded through the traversal.
struct Context<'a> {
    resolved: ResolvedPolicy,
    dataset_key: Option<[u8; 32]>,
    patterns: Vec<(deident_core::policy::PatternRule, regex::Regex)>,
    vault: &'a mut dyn MappingVault,
    /// Findings keyed by tag, accumulating occurrence counts.
    findings: BTreeMap<Tag, TagFinding>,
    /// Original → replacement UID, shared across a run so one UID maps
    /// identically in every instance of a study.
    uid_cache: &'a mut HashMap<String, String>,
    examined: u64,
    modified: u64,
    private_seen: u64,
    max_depth: u32,
    /// Attributes a `clean_text` rule scanned without changing anything, so the
    /// report can say the text passed through rather than staying silent.
    text_unchanged: Vec<String>,
    warnings: Vec<String>,
}

/// De-identify one instance, sharing `uid_cache` so a study's UIDs remap
/// identically across every file (and are counted once for the run).
fn deidentify_with_cache(
    input: &Path,
    output: &Path,
    policy: &DicomPolicy,
    vault: &mut dyn MappingVault,
    uid_cache: &mut HashMap<String, String>,
) -> Result<DicomReport, DicomError> {
    policy.validate()?;
    let mut object = dicom_object::open_file(input).map_err(|source| DicomError::Read {
        path: input.display().to_string(),
        source: Box::new(source),
    })?;

    let resolved = policy.resolve()?;
    let needs_key = policy.tags.iter().any(|r| r.action.needs_key())
        || resolved.explicit_tags().any(|(_, a)| a.needs_key())
        // Only when the structural layer is actually active: consulting it
        // unconditionally made `profile: none` resolve a key and emit a
        // "values are reversible" warning for a run that pseudonymized nothing.
        || (resolved.structural_enabled() && policy.structural.uids)
        || policy.effective_patterns().iter().any(|p| p.action.needs_key());
    let dataset_key = if needs_key {
        let secret = resolve_secret(policy)?;
        Some(deident_core::key::derive_dataset_key(
            &secret,
            &policy.dataset,
        ))
    } else {
        None
    };

    let effective = policy.effective_patterns();
    let mut patterns = Vec::with_capacity(effective.len());
    for rule in &effective {
        let regex = regex::Regex::new(rule.regex_source())
            .map_err(|e| DicomError::Policy(format!("pattern '{}': {e}", rule.name)))?;
        patterns.push((rule.clone(), regex));
    }

    let pixel_risk = assess_pixel_risk(&object);
    let sop_class_uid = string_of(&object, tags::SOP_CLASS_UID);

    let mut ctx = Context {
        resolved,
        dataset_key,
        patterns,
        vault,
        findings: BTreeMap::new(),
        uid_cache,
        examined: 0,
        modified: 0,
        private_seen: 0,
        max_depth: 0,
        text_unchanged: Vec::new(),
        warnings: Vec::new(),
    };

    // Remember the SOP Instance UID so the file-meta group can be kept
    // consistent with the dataset after remapping, and how many UIDs the shared
    // cache already held so this instance's own contribution can be counted.
    let original_sop_instance = string_of(&object, tags::SOP_INSTANCE_UID);
    let uids_before = ctx.uid_cache.len();
    // FileDicomObject derefs to the dataset it wraps.
    process_object(&mut object, &mut ctx, 0)?;

    // The file-meta group duplicates the SOP Instance UID. Leaving it stale
    // produces a file whose header and dataset disagree — and some readers
    // trust the header, which would reintroduce the original identifier.
    //
    // Take the replacement from the UID cache rather than re-reading the
    // dataset: DICOM pads odd-length UI values with NUL on write, so a value
    // read back is not necessarily byte-equal to what we generated.
    // Read the value the dataset actually ends up with, whatever action produced
    // it. Keying this off the UID cache only synced the header for
    // `TagAction::Uid`, so `pseudonymize`, `replace` or `empty` on
    // SOPInstanceUID left the ORIGINAL identifier in the file-meta group — the
    // exact reintroduction this sync exists to prevent.
    let final_sop_instance = string_of(&object, tags::SOP_INSTANCE_UID);
    if let Some(before) = &original_sop_instance
        && final_sop_instance.as_deref() != Some(before.as_str())
    {
        let after = final_sop_instance.clone().unwrap_or_default();
        if after.is_empty() {
            ctx.warnings.push(
                "SOPInstanceUID was emptied or removed; the file-meta group can no longer \
                 identify the instance and some readers will reject the file"
                    .to_string(),
            );
        }
        let meta = object.meta_mut();
        meta.media_storage_sop_instance_uid = after;
        // The replacement UID rarely has the same length as the original, and
        // the meta group carries its own byte length (0002,0000). Leaving that
        // stale writes a file whose header length disagrees with its contents,
        // so a reader starts the dataset at the wrong offset and silently loses
        // its first attribute — SOPClassUID, which makes the instance
        // unusable. Recompute it.
        meta.update_information_group_length();
    }

    if pixel_risk.level != "low" {
        ctx.warnings.push(format!(
            "pixel data risk is '{}': {}. Pixel data was NOT modified — burned-in identifiers, if any, survive",
            pixel_risk.level,
            pixel_risk.reasons.join("; ")
        ));
    }
    if !ctx.text_unchanged.is_empty() {
        let mut fields = ctx.text_unchanged.clone();
        fields.sort();
        fields.dedup();
        ctx.warnings.push(format!(
            "clean_text matched no pattern in {}: the free text is in the output unchanged. \
             Pattern rules only remove what they match — review these fields, or use \
             action: remove if they may contain names",
            fields.join(", ")
        ));
    }
    if ctx.private_seen > 0 && policy.structural.retain_safe_private {
        ctx.warnings.push(format!(
            "{} private attribute(s) were retained because structural.retain_safe_private is set; \
             vendor private blocks are a known PHI hiding place",
            ctx.private_seen
        ));
    }
    if ctx.dataset_key.is_some() {
        ctx.warnings.push(
            "pseudonyms, remapped UIDs and shifted dates are reversible with the key material — \
             protect it separately from this output"
                .to_string(),
        );
    }

    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    object
        .write_to_file(output)
        .map_err(|source| DicomError::Write {
            path: output.display().to_string(),
            source: Box::new(source),
        })?;

    // Distinct UID *values* replaced by this instance, not distinct tags: one
    // sequence can hold four different ReferencedSOPInstanceUIDs, and reporting
    // "1" for it contradicts the field's own documentation.
    let uids_remapped = ctx.uid_cache.len().saturating_sub(uids_before) as u64;
    Ok(DicomReport {
        tool_version: crate::VERSION.to_string(),
        dataset: policy.dataset.clone(),
        source: input.display().to_string(),
        sop_class_uid,
        attributes_examined: ctx.examined,
        attributes_modified: ctx.modified,
        private_attributes: ctx.private_seen,
        max_sequence_depth: ctx.max_depth,
        tags: ctx.findings.into_values().collect(),
        uids_remapped,
        pixel_risk,
        warnings: ctx.warnings,
        limitations: DicomReport::limitations(),
    })
}

/// Apply the policy to every attribute of `object`, recursing into sequences.
fn process_object(
    object: &mut InMemDicomObject,
    ctx: &mut Context,
    depth: u32,
) -> Result<(), DicomError> {
    ctx.max_depth = ctx.max_depth.max(depth);

    // Collect first: the policy may remove attributes, so we cannot hold an
    // iterator over the object while mutating it.
    let tags: Vec<Tag> = object.tags().collect();
    let mut to_remove: Vec<Tag> = Vec::new();
    let mut to_replace: Vec<DataElement<InMemDicomObject>> = Vec::new();

    for tag in tags {
        let Ok(element) = object.element(tag) else {
            continue;
        };
        let vr = element.vr();
        ctx.examined += 1;
        if is_private(tag) {
            ctx.private_seen += 1;
        }

        // Pixel data is never touched.
        if tag == tags::PIXEL_DATA {
            continue;
        }

        // Recurse into sequences before applying an action to the sequence
        // itself, so nested PHI is handled even when the parent is kept.
        if let Value::Sequence(_) = element.value() {
            let action = ctx.resolved.action_for(tag, vr).cloned();
            if matches!(action, Some(TagAction::Remove)) {
                record(ctx, tag, &TagAction::Remove);
                to_remove.push(tag);
                continue;
            }
            let Ok(taken) = object.take_element(tag) else {
                continue;
            };
            let (header, value) = taken.into_parts();
            let rebuilt = match value {
                Value::Sequence(mut sequence) => {
                    for item in sequence.items_mut() {
                        process_object(item, ctx, depth + 1)?;
                    }
                    Value::Sequence(sequence)
                }
                other => other,
            };
            object.put(DataElement::new_with_len(tag, header.vr(), header.len, rebuilt));
            continue;
        }

        let Some(action) = ctx.resolved.action_for(tag, vr).cloned() else {
            continue;
        };
        match apply_action(&action, tag, vr, element.value(), ctx)? {
            Applied::Unchanged => {}
            Applied::Remove => {
                record(ctx, tag, &action);
                to_remove.push(tag);
            }
            Applied::Value(value) => {
                record(ctx, tag, &action);
                to_replace.push(DataElement::new(tag, vr, value));
            }
        }
    }

    for tag in to_remove {
        object.remove_element(tag);
    }
    for element in to_replace {
        object.put(element);
    }
    Ok(())
}

/// Outcome of applying an action to one attribute.
enum Applied {
    Unchanged,
    Remove,
    Value(PrimitiveValue),
}

/// Outcome of applying an action to ONE value of a (possibly multi-valued)
/// attribute.
enum AppliedValue {
    Unchanged,
    /// Drop this value from the attribute.
    Drop,
    Replaced(String),
}

/// VRs whose value multiplicity is always 1 and in which a backslash is literal
/// text rather than a separator (PS3.5 §6.2). Splitting these would corrupt the
/// content.
fn is_single_value_vr(vr: VR) -> bool {
    matches!(vr, VR::LT | VR::ST | VR::UT | VR::UR)
}

/// Apply an action to an attribute, **value by value**.
///
/// DICOM attributes are frequently multi-valued (`ID-1\ID-2\ID-3`). Treating the
/// backslash-joined string as one scalar collapsed the attribute to a single
/// value — so identifiers 2..n were destroyed rather than de-identified, the
/// vault recorded an unreversible joined "original", `date_shift` left every
/// value after the first as an original date, and the UID cache keyed on the
/// joined string gave the same UID two different replacements in different files.
fn apply_action(
    action: &TagAction,
    tag: Tag,
    vr: VR,
    value: &Value<InMemDicomObject>,
    ctx: &mut Context,
) -> Result<Applied, DicomError> {
    let keyword = profile::keyword_of(tag);

    // Actions that replace the whole attribute regardless of its values.
    match action {
        TagAction::Keep => return Ok(Applied::Unchanged),
        TagAction::Remove => {
            ctx.modified += 1;
            return Ok(Applied::Remove);
        }
        TagAction::Empty => {
            return Ok(if value.length() == dicom_core::Length(0) {
                Applied::Unchanged
            } else {
                ctx.modified += 1;
                Applied::Value(PrimitiveValue::Empty)
            });
        }
        TagAction::Replace { value: literal } => {
            ctx.modified += 1;
            return Ok(Applied::Value(PrimitiveValue::Str(literal.clone())));
        }
        _ => {}
    }

    let Some(values) = primitive_values(value, vr) else {
        return Ok(Applied::Unchanged);
    };
    if values.is_empty() || values.iter().all(String::is_empty) {
        return Ok(Applied::Unchanged);
    }

    let mut out: Vec<String> = Vec::with_capacity(values.len());
    let mut changed = false;
    for original in &values {
        if original.is_empty() {
            out.push(String::new());
            continue;
        }
        match apply_to_value(action, &keyword, original, ctx)? {
            AppliedValue::Unchanged => out.push(original.clone()),
            AppliedValue::Drop => changed = true,
            AppliedValue::Replaced(new) => {
                changed |= new != *original;
                out.push(new);
            }
        }
    }

    if !changed {
        return Ok(Applied::Unchanged);
    }
    ctx.modified += 1;
    Ok(match out.len() {
        0 => Applied::Remove,
        1 => Applied::Value(PrimitiveValue::Str(out.remove(0))),
        // Multi-valued attributes must stay multi-valued.
        _ => Applied::Value(PrimitiveValue::Strs(out.into())),
    })
}

/// Apply an action to a single value of an attribute.
fn apply_to_value(
    action: &TagAction,
    keyword: &str,
    original: &str,
    ctx: &mut Context,
) -> Result<AppliedValue, DicomError> {
    Ok(match action {
        // Handled at attribute level.
        TagAction::Keep | TagAction::Remove | TagAction::Empty | TagAction::Replace { .. } => {
            AppliedValue::Unchanged
        }
        TagAction::Pseudonymize {
            prefix,
            domain,
            mock,
        } => {
            let key = ctx.dataset_key.as_ref().expect("key resolved");
            let domain = domain.clone().unwrap_or_else(|| keyword.to_string());
            let replacement = match mock {
                Some(shape) => mock_value(*shape, key, &domain, original),
                None => deident_core::key::token(key, &domain, original, prefix.as_deref()),
            };
            ctx.vault
                .record(MappingEntry {
                    field: format!("dicom:{domain}"),
                    original: original.to_string(),
                    token: replacement.clone(),
                })
                .map_err(|e| DicomError::Transform(e.to_string()))?;
            AppliedValue::Replaced(replacement)
        }
        TagAction::Uid => {
            let key = ctx.dataset_key.as_ref().expect("key resolved");
            // One cache for the whole run, keyed on the INDIVIDUAL UID: the same
            // original must always map to the same replacement, whichever
            // attribute or file it appears in.
            let replacement = match ctx.uid_cache.get(original) {
                Some(existing) => existing.clone(),
                None => {
                    let generated = uid::derive_uid(key, "dicom-uid", original);
                    ctx.uid_cache
                        .insert(original.to_string(), generated.clone());
                    ctx.vault
                        .record(MappingEntry {
                            field: "dicom:uid".to_string(),
                            original: original.to_string(),
                            token: generated.clone(),
                        })
                        .map_err(|e| DicomError::Transform(e.to_string()))?;
                    generated
                }
            };
            AppliedValue::Replaced(replacement)
        }
        TagAction::DateShift { max_days, domain } => {
            let key = ctx.dataset_key.as_ref().expect("key resolved");
            let domain = domain.clone().unwrap_or_else(|| keyword.to_string());
            match shift_date_text(original, key, &domain, *max_days) {
                Some(shifted) => AppliedValue::Replaced(shifted),
                None => {
                    ctx.warnings.push(format!(
                        "{keyword}: a value could not be parsed as a DICOM date and was dropped instead of shifted"
                    ));
                    AppliedValue::Drop
                }
            }
        }
        TagAction::DateTruncate { granularity } => {
            match truncate_date_text(original, *granularity) {
                Some(truncated) => AppliedValue::Replaced(truncated),
                None => AppliedValue::Drop,
            }
        }
        TagAction::CleanText => {
            if ctx.patterns.is_empty() {
                // No rules at all is the WORST case, not a reason to stay quiet:
                // `profile: basic` marks ~12 free-text attributes `clean_text`,
                // so a policy with no `patterns:` ships them all untouched.
                ctx.text_unchanged.push(keyword.to_string());
                return Ok(AppliedValue::Unchanged);
            }
            let cleaned = clean_text(original, ctx, keyword)?;
            if cleaned == original {
                // No pattern matched, so the free text is in the output exactly
                // as it arrived. That is correct for `clean_text` — it only
                // removes what its patterns match — but silence would let a
                // reader assume the field had been sanitized, when a name or
                // identifier the patterns do not cover survives intact.
                ctx.text_unchanged.push(keyword.to_string());
                AppliedValue::Unchanged
            } else {
                AppliedValue::Replaced(cleaned)
            }
        }
    })
}

/// Run the policy's pattern rules over a text value.
fn clean_text(original: &str, ctx: &mut Context, keyword: &str) -> Result<String, DicomError> {
    use deident_core::policy::PatternAction;
    let mut current = original.to_string();
    for (rule, regex) in ctx.patterns.clone() {
        match rule.action {
            PatternAction::Detect => {
                let validator = rule.validator();
                if regex
                    .find_iter(&current)
                    .any(|m| validator.accepts(m.as_str()))
                {
                    ctx.warnings.push(format!(
                        "{keyword}: pattern '{}' matched but action is detect; the value was left in place",
                        rule.name
                    ));
                }
            }
            PatternAction::Redact => {
                let label = rule
                    .replacement
                    .clone()
                    .unwrap_or_else(|| format!("[{}]", rule.name.to_uppercase()));
                let validator = rule.validator();
                current = regex
                    .replace_all(&current, |caps: &regex::Captures| {
                        let matched = caps.get(0).expect("group 0").as_str();
                        // A match that fails its checksum is not an identifier.
                        if validator.accepts(matched) {
                            label.clone()
                        } else {
                            matched.to_string()
                        }
                    })
                    .into_owned();
            }
            PatternAction::Token | PatternAction::Mock => {
                let key = ctx.dataset_key.as_ref().expect("key resolved");
                let domain = format!("pattern:{}", rule.name);
                let mut mappings = Vec::new();
                let validator = rule.validator();
                let replaced = regex.replace_all(&current, |caps: &regex::Captures| {
                    let matched = caps.get(0).expect("group 0").as_str();
                    if !validator.accepts(matched) {
                        return matched.to_string();
                    }
                    let replacement = match (rule.action, rule.mock_shape()) {
                        (PatternAction::Mock, Some(shape)) => {
                            deident_core::mock::generate(shape, key, &domain, matched)
                        }
                        _ => deident_core::key::token(key, &domain, matched, rule.prefix.as_deref()),
                    };
                    mappings.push(MappingEntry {
                        field: format!("dicom:{domain}"),
                        original: matched.to_string(),
                        token: replacement.clone(),
                    });
                    replacement
                });
                if !mappings.is_empty() {
                    current = replaced.into_owned();
                    for entry in mappings {
                        ctx.vault
                            .record(entry)
                            .map_err(|e| DicomError::Transform(e.to_string()))?;
                    }
                }
            }
        }
    }
    Ok(current)
}

/// Generate a shaped mock value for a DICOM attribute.
fn mock_value(shape: MockShapeCfg, key: &[u8; 32], domain: &str, original: &str) -> String {
    match shape {
        // DICOM person names are `Family^Given^Middle^Prefix^Suffix`; emit the
        // two components that matter so viewers render something sensible.
        MockShapeCfg::PersonName => {
            let family = deident_core::key::token(key, &format!("{domain}/family"), original, None);
            let given = deident_core::key::token(key, &format!("{domain}/given"), original, None);
            format!(
                "{}^{}",
                pronounceable(&family, 8),
                pronounceable(&given, 6)
            )
        }
        MockShapeCfg::Email => {
            deident_core::mock::generate(deident_core::mock::MockShape::Email, key, domain, original)
        }
        MockShapeCfg::Phone => {
            deident_core::mock::generate(deident_core::mock::MockShape::Phone, key, domain, original)
        }
    }
}

/// Turn hex into a capitalised alphabetic string, so a mocked person name looks
/// like a name rather than a hash.
fn pronounceable(hex: &str, len: usize) -> String {
    let mut out = String::with_capacity(len);
    for (i, byte) in hex.bytes().take(len).enumerate() {
        let letter = char::from(b'a' + (byte % 26));
        if i == 0 {
            out.extend(letter.to_uppercase());
        } else {
            out.push(letter);
        }
    }
    out
}

/// Shift a DICOM `DA` (`YYYYMMDD`) or `DT` value by a deterministic offset.
///
/// The offset is derived from the key and domain, so every date of one subject
/// moves together and intervals are preserved.
fn shift_date_text(value: &str, key: &[u8; 32], domain: &str, max_days: i64) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.len() < 8 || !trimmed.as_bytes()[..8].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let year: i64 = trimmed[0..4].parse().ok()?;
    let month: i64 = trimmed[4..6].parse().ok()?;
    let day: i64 = trimmed[6..8].parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    let offset = deterministic_offset(key, domain, max_days);
    let shifted = days_to_civil(civil_to_days(year, month, day) + offset);
    let mut out = format!("{:04}{:02}{:02}", shifted.0, shifted.1, shifted.2);
    // Preserve any time component of a DT value unchanged: it carries no date
    // information on its own, and dropping it can break readers.
    if trimmed.len() > 8 {
        out.push_str(&trimmed[8..]);
    }
    Some(out)
}

/// Per-domain offset in `[-max_days, max_days]`.
fn deterministic_offset(key: &[u8; 32], domain: &str, max_days: i64) -> i64 {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(b"dicom-date-offset");
    hasher.update(&[0x1f]);
    hasher.update(domain.as_bytes());
    let digest = hasher.finalize();
    let raw = u64::from_be_bytes(digest.as_bytes()[..8].try_into().expect("8 bytes"));
    let span = max_days.saturating_mul(2).saturating_add(1).max(1);
    (raw % span as u64) as i64 - max_days
}

/// Truncate a DICOM date to year or year-month, padded so it stays a valid `DA`.
fn truncate_date_text(value: &str, granularity: DateGranularity) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.len() < 4 || !trimmed.as_bytes()[..4].iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(match granularity {
        // `YYYY0101` keeps the value a syntactically valid DA, which a bare
        // `YYYY` would not be for every reader.
        DateGranularity::Year => format!("{}0101", &trimmed[0..4]),
        DateGranularity::YearMonth => {
            if trimmed.len() >= 6 && trimmed.as_bytes()[4..6].iter().all(u8::is_ascii_digit) {
                format!("{}01", &trimmed[0..6])
            } else {
                format!("{}0101", &trimmed[0..4])
            }
        }
    })
}

/// Days since the Unix epoch for a civil date (Howard Hinnant's algorithm).
fn civil_to_days(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Inverse of [`civil_to_days`].
fn days_to_civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (if month <= 2 { y + 1 } else { y }, month, day)
}

/// Assess burned-in-annotation risk without inspecting a single pixel.
fn assess_pixel_risk(object: &DefaultDicomObject) -> PixelRisk {
    let has_pixel_data = object.element(tags::PIXEL_DATA).is_ok();
    let burned_in = string_of(object, tags::BURNED_IN_ANNOTATION);
    let modality = string_of(object, tags::MODALITY);
    let mut reasons = Vec::new();

    let level = if !has_pixel_data {
        reasons.push("instance carries no pixel data".to_string());
        "low"
    } else {
        match burned_in.as_deref().map(str::trim) {
            Some("YES") => {
                reasons.push("BurnedInAnnotation is YES".to_string());
                "high"
            }
            Some("NO") => {
                // Trust it only as far as it goes: the attribute is frequently
                // wrong or set by default.
                let risky = modality
                    .as_deref()
                    .is_some_and(|m| HIGH_RISK_MODALITIES.contains(&m.trim()));
                if risky {
                    reasons.push(format!(
                        "BurnedInAnnotation says NO, but modality {} commonly has burned-in text",
                        modality.as_deref().unwrap_or("?")
                    ));
                    "elevated"
                } else {
                    reasons.push("BurnedInAnnotation is NO".to_string());
                    "low"
                }
            }
            _ => {
                reasons.push("BurnedInAnnotation is absent or unrecognised".to_string());
                if modality
                    .as_deref()
                    .is_some_and(|m| HIGH_RISK_MODALITIES.contains(&m.trim()))
                {
                    reasons.push(format!(
                        "modality {} commonly has burned-in text",
                        modality.as_deref().unwrap_or("?")
                    ));
                    "high"
                } else {
                    "unknown"
                }
            }
        }
    };

    PixelRisk {
        has_pixel_data,
        burned_in_annotation: burned_in,
        modality,
        level: level.to_string(),
        reasons,
    }
}

fn record(ctx: &mut Context, tag: Tag, action: &TagAction) {
    let entry = ctx.findings.entry(tag).or_insert_with(|| TagFinding {
        tag: profile::keyword_of(tag),
        numeric: format!("({:04X},{:04X})", tag.group(), tag.element()),
        action: action.action_name().to_string(),
        occurrences: 0,
    });
    entry.occurrences += 1;
}

/// Normalize a DICOM string value.
///
/// DICOM pads odd-length values to an even byte count — UI and most string VRs
/// with a trailing NUL, others with a space — and `to_str` keeps the padding.
/// `str::trim` alone does not remove NUL, so without this the *same* logical UID
/// would hash differently depending on whether its length happened to be odd,
/// silently breaking cross-file remapping consistency between files written by
/// different tools.
fn normalize(raw: &str) -> String {
    raw.trim_matches(|c: char| c.is_whitespace() || c == '\0')
        .to_string()
}

/// Individual values of a primitive attribute, or `None` for non-primitives.
///
/// For text VRs (`LT`/`ST`/`UT`/`UR`) a backslash is literal content rather than
/// a separator, so those are returned as a single value.
fn primitive_values(value: &Value<InMemDicomObject>, vr: VR) -> Option<Vec<String>> {
    let Value::Primitive(primitive) = value else {
        return None;
    };
    if is_single_value_vr(vr) {
        return Some(vec![normalize(&primitive.to_str())]);
    }
    Some(
        primitive
            .to_multi_str()
            .iter()
            .map(|v| normalize(v))
            .collect(),
    )
}

fn string_of(object: &DefaultDicomObject, tag: Tag) -> Option<String> {
    object
        .element(tag)
        .ok()
        .and_then(|e| e.to_str().ok())
        .map(|s| normalize(&s))
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        deident_core::key::derive_dataset_key(b"secret", "study")
    }

    #[test]
    fn date_shift_preserves_intervals_and_validity() {
        let k = key();
        let a = shift_date_text("20240314", &k, "patient", 3650).unwrap();
        let b = shift_date_text("20240414", &k, "patient", 3650).unwrap();
        assert_eq!(a.len(), 8, "must stay a valid DA: {a}");
        assert_ne!(a, "20240314", "must actually shift");
        // 31 days apart before, 31 days after.
        let days = |d: &str| {
            civil_to_days(
                d[0..4].parse().unwrap(),
                d[4..6].parse().unwrap(),
                d[6..8].parse().unwrap(),
            )
        };
        assert_eq!(
            days(&b) - days(&a),
            31,
            "the interval between two dates of one subject must survive"
        );
        // Deterministic.
        assert_eq!(a, shift_date_text("20240314", &k, "patient", 3650).unwrap());
        // A different subject gets a different offset.
        assert_ne!(a, shift_date_text("20240314", &k, "other", 3650).unwrap());
    }

    #[test]
    fn date_shift_keeps_a_time_component() {
        let shifted = shift_date_text("20240314103000.000", &key(), "p", 100).unwrap();
        assert!(shifted.ends_with("103000.000"), "{shifted}");
        assert_eq!(shifted.len(), "20240314103000.000".len());
    }

    #[test]
    fn date_shift_rejects_nonsense() {
        let k = key();
        assert!(shift_date_text("not-a-date", &k, "p", 10).is_none());
        assert!(shift_date_text("2024", &k, "p", 10).is_none());
        assert!(shift_date_text("20241340", &k, "p", 10).is_none(), "month 13");
    }

    #[test]
    fn date_truncation_stays_a_valid_da() {
        assert_eq!(
            truncate_date_text("19850627", DateGranularity::Year).unwrap(),
            "19850101"
        );
        assert_eq!(
            truncate_date_text("19850627", DateGranularity::YearMonth).unwrap(),
            "19850601"
        );
        assert!(truncate_date_text("x", DateGranularity::Year).is_none());
    }

    #[test]
    fn civil_date_conversion_round_trips() {
        for (y, m, d) in [(1970, 1, 1), (2000, 2, 29), (2024, 12, 31), (1900, 3, 1)] {
            let days = civil_to_days(y, m, d);
            assert_eq!(days_to_civil(days), (y, m, d), "{y}-{m}-{d}");
        }
        assert_eq!(civil_to_days(1970, 1, 1), 0, "epoch");
    }

    #[test]
    fn offsets_stay_within_the_configured_bound() {
        let k = key();
        for domain in ["a", "b", "c", "patient-42", "study"] {
            let offset = deterministic_offset(&k, domain, 30);
            assert!((-30..=30).contains(&offset), "{domain}: {offset}");
        }
    }

    #[test]
    fn normalization_strips_dicom_padding() {
        // A NUL-padded odd-length UID and its unpadded form must be identical,
        // or the same UID would remap two different ways.
        assert_eq!(normalize("1.2.840.99\0"), "1.2.840.99");
        assert_eq!(normalize("  Muster^Alice "), "Muster^Alice");
        assert_eq!(normalize("CT\0"), "CT");
        assert_eq!(normalize(""), "");
    }

    #[test]
    fn person_name_mock_looks_like_a_name() {
        let mock = mock_value(MockShapeCfg::PersonName, &key(), "patient", "Muster^Alice");
        let (family, given) = mock.split_once('^').expect("DICOM PN separator");
        assert!(!family.is_empty() && !given.is_empty(), "{mock}");
        assert!(
            family.chars().all(|c| c.is_ascii_alphabetic()),
            "family should be alphabetic: {family}"
        );
        assert!(family.starts_with(|c: char| c.is_ascii_uppercase()), "{family}");
        assert_ne!(mock, "Muster^Alice");
        // Deterministic.
        assert_eq!(
            mock,
            mock_value(MockShapeCfg::PersonName, &key(), "patient", "Muster^Alice")
        );
    }
}
