//! Streaming CSV job engine: plans one action per column from the policy,
//! then transforms row by row while accumulating risk statistics.

use std::collections::HashMap;
use std::io::{Read, Write};

use deident_types::{DirectIdentifierFinding, Mode, PatternFinding, RiskReport};

use crate::error::CoreError;
use crate::format::{self, Format};
use crate::key;
use crate::policy::{AnonymizeCfg, FieldClass, PatternAction, Policy, UnlistedAction};
use crate::report;
use crate::transform;
use crate::vault::{MappingEntry, MappingVault};

/// What the engine does with one input column.
enum ColumnAction {
    Keep,
    Drop,
    /// Deterministic tokenization (pseudonymize mode). `domain` is the
    /// identity namespace the token is derived in (column name unless the
    /// policy overrides it for cross-file linkage).
    Token { prefix: Option<String>, domain: String },
    /// Value-level anonymization strategy.
    Transform(AnonymizeCfg),
}

/// Compiled content-pattern rules plus per-column applicability and counts.
struct Patterns<'p> {
    rules: Vec<(&'p crate::policy::PatternRule, regex::Regex)>,
    /// For each input column: indices into `rules` that scan it.
    per_column: Vec<Vec<usize>>,
    /// Match counts: `counts[rule][column]`.
    counts: Vec<Vec<u64>>,
}

impl<'p> Patterns<'p> {
    /// Compile the policy's rules and work out which columns each scans.
    /// Dropped and tokenized columns are never scanned (nothing left to find).
    fn compile(
        policy: &'p Policy,
        headers: &[String],
        actions: &[ColumnAction],
    ) -> Result<Self, CoreError> {
        let mut rules = Vec::with_capacity(policy.patterns.len());
        for rule in &policy.patterns {
            let regex = regex::Regex::new(rule.regex_source()).map_err(|err| {
                CoreError::Policy(format!("pattern '{}': invalid regex: {err}", rule.name))
            })?;
            rules.push((rule, regex));
        }
        let per_column: Vec<Vec<usize>> = headers
            .iter()
            .enumerate()
            .map(|(col, header)| {
                if !matches!(actions[col], ColumnAction::Keep | ColumnAction::Transform(_)) {
                    return Vec::new();
                }
                rules
                    .iter()
                    .enumerate()
                    .filter(|(_, (rule, _))| {
                        rule.fields
                            .as_ref()
                            .is_none_or(|fields| fields.iter().any(|f| f == header))
                    })
                    .map(|(i, _)| i)
                    .collect()
            })
            .collect();
        let counts = vec![vec![0u64; headers.len()]; rules.len()];
        Ok(Self { rules, per_column, counts })
    }

    /// Whether any rule derives values from the key (token or mock).
    fn needs_key(&self) -> bool {
        self.rules.iter().any(|(rule, _)| rule.action.needs_key())
    }

    /// Run the applicable rules over one (already column-transformed) cell.
    fn apply(
        &mut self,
        col: usize,
        value: String,
        dataset_key: Option<&[u8; 32]>,
        vault: &mut dyn MappingVault,
    ) -> Result<String, CoreError> {
        if value.is_empty() || self.per_column[col].is_empty() {
            return Ok(value);
        }
        let mut current = value;
        for i in self.per_column[col].clone() {
            let (rule, regex) = &self.rules[i];
            match rule.action {
                PatternAction::Detect => {
                    self.counts[i][col] += regex.find_iter(&current).count() as u64;
                }
                PatternAction::Redact => {
                    let label = rule
                        .replacement
                        .clone()
                        .unwrap_or_else(|| format!("[{}]", rule.name.to_uppercase()));
                    let mut matches = 0u64;
                    let replaced = regex.replace_all(&current, |_: &regex::Captures| {
                        matches += 1;
                        label.clone()
                    });
                    if matches > 0 {
                        current = replaced.into_owned();
                        self.counts[i][col] += matches;
                    }
                }
                PatternAction::Token | PatternAction::Mock => {
                    let key = dataset_key.expect("key resolved when keyed patterns exist");
                    let domain = format!("pattern:{}", rule.name);
                    let shape = rule.mock_shape();
                    let mut mappings: Vec<MappingEntry> = Vec::new();
                    let replaced = regex.replace_all(&current, |caps: &regex::Captures| {
                        let matched = caps.get(0).expect("group 0 always exists").as_str();
                        let replacement = match rule.action {
                            PatternAction::Mock => crate::mock::generate(
                                shape.expect("validated: mock rules have a shape"),
                                key,
                                &domain,
                                matched,
                            ),
                            _ => key::token(key, &domain, matched, rule.prefix.as_deref()),
                        };
                        mappings.push(MappingEntry {
                            field: domain.clone(),
                            original: matched.to_string(),
                            token: replacement.clone(),
                        });
                        replacement
                    });
                    if !mappings.is_empty() {
                        current = replaced.into_owned();
                        self.counts[i][col] += mappings.len() as u64;
                        for entry in mappings {
                            vault.record(entry)?;
                        }
                    }
                }
            }
        }
        Ok(current)
    }

    /// Aggregate findings and mode-dependent warnings for the report.
    fn findings(
        &self,
        headers: &[String],
        mode: Mode,
        warnings: &mut Vec<String>,
    ) -> Vec<PatternFinding> {
        let mut findings = Vec::new();
        for (i, (rule, _)) in self.rules.iter().enumerate() {
            let mut rule_total = 0u64;
            for (col, header) in headers.iter().enumerate() {
                let matches = self.counts[i][col];
                if matches > 0 {
                    findings.push(PatternFinding {
                        pattern: rule.name.clone(),
                        field: header.to_string(),
                        matches,
                        action: rule.action.action_name().to_string(),
                    });
                    rule_total += matches;
                }
            }
            if rule_total > 0 {
                match rule.action {
                    PatternAction::Detect => warnings.push(format!(
                        "pattern '{}' matched {rule_total} time(s) (action: detect); matching values remain in the output",
                        rule.name
                    )),
                    PatternAction::Token | PatternAction::Mock if mode == Mode::Anonymize => {
                        warnings.push(format!(
                            "pattern '{}' inserted deterministic {}; treat the affected output as pseudonymous (reversible with the key material)",
                            rule.name,
                            if rule.action == PatternAction::Mock { "mock values" } else { "tokens" }
                        ))
                    }
                    _ => {}
                }
            }
        }
        findings
    }
}

/// Run one CSV job. Convenience wrapper around [`run_job`] for the common
/// CSV-in/CSV-out case.
pub fn run_csv_job<R: Read, W: Write + Send>(
    mode: Mode,
    policy: &Policy,
    input: R,
    output: W,
    vault: &mut dyn MappingVault,
) -> Result<RiskReport, CoreError> {
    run_job(mode, policy, input, output, Format::Csv, Format::Csv, vault)
}

/// Run one job: read `input` in `input_format`, write the transformed table
/// to `output` in `output_format`, and return the risk report. Pseudonym
/// mappings are handed to `vault`.
///
/// Input and output formats are independent, so a job can convert while it
/// transforms.
pub fn run_job<R: Read, W: Write + Send>(
    mode: Mode,
    policy: &Policy,
    input: R,
    output: W,
    input_format: Format,
    output_format: Format,
    vault: &mut dyn MappingVault,
) -> Result<RiskReport, CoreError> {
    policy.validate()?;

    let mut warnings: Vec<String> = Vec::new();
    let mut findings: Vec<DirectIdentifierFinding> = Vec::new();

    let mut reader = format::reader(input_format, input)?;
    let headers = reader.headers()?;

    for field in &policy.fields {
        if !headers.contains(&field.name) {
            warnings.push(format!(
                "policy field '{}' does not exist in the input and was ignored",
                field.name
            ));
        }
    }

    let mut actions: Vec<ColumnAction> = Vec::with_capacity(headers.len());
    for header in headers.iter() {
        actions.push(plan_column(
            mode,
            policy,
            header,
            &mut findings,
            &mut warnings,
        )?);
    }
    let mut patterns = Patterns::compile(policy, &headers, &actions)?;

    // Pseudonymize mode always tokenizes; token-action patterns need the key
    // in either mode.
    let dataset_key = if mode == Mode::Pseudonymize || patterns.needs_key() {
        Some(key::resolve_dataset_key(policy, &mut warnings)?)
    } else {
        None
    };

    // Quasi-identifier columns that survive into the output are grouped
    // (on their transformed values) for the equivalence-class statistics.
    let qi_columns: Vec<usize> = headers
        .iter()
        .enumerate()
        .filter(|(i, h)| {
            !matches!(actions[*i], ColumnAction::Drop)
                && policy
                    .field(h)
                    .is_some_and(|f| f.class == FieldClass::QuasiIdentifier)
        })
        .map(|(i, _)| i)
        .collect();
    let qi_fields: Vec<String> = qi_columns.iter().map(|&i| headers[i].to_string()).collect();

    let mut writer = format::writer(output_format, output)?;
    let out_headers: Vec<String> = headers
        .iter()
        .zip(&actions)
        .filter(|(_, a)| !matches!(a, ColumnAction::Drop))
        .map(|(h, _)| h.clone())
        .collect();
    writer.write_headers(&out_headers)?;

    let mut rows_read = 0u64;
    let mut rows_written = 0u64;
    let mut suppressed_values = 0u64;
    let mut classes: HashMap<Vec<String>, u64> = HashMap::new();

    while let Some(record) = reader.next_row()? {
        rows_read += 1;
        let mut out_row: Vec<String> = Vec::with_capacity(out_headers.len());
        let mut qi_tuple: Vec<String> = Vec::with_capacity(qi_columns.len());

        for (i, cell) in record.iter().enumerate() {
            let Some(action) = actions.get(i) else {
                return Err(CoreError::Policy(format!(
                    "row {rows_read} has more columns than the header"
                )));
            };
            let transformed = match action {
                ColumnAction::Drop => None,
                ColumnAction::Keep => Some(cell.to_string()),
                ColumnAction::Token { prefix, domain } => {
                    if cell.is_empty() {
                        Some(String::new())
                    } else {
                        let token = key::token(
                            dataset_key.as_ref().expect("key resolved in pseudonymize mode"),
                            domain,
                            cell,
                            prefix.as_deref(),
                        );
                        vault.record(MappingEntry {
                            field: domain.clone(),
                            original: cell.to_string(),
                            token: token.clone(),
                        })?;
                        Some(token)
                    }
                }
                ColumnAction::Transform(cfg) => Some(match transform::apply(cfg, cell) {
                    Ok(v) => v,
                    Err(transform::InvalidValue) => {
                        suppressed_values += 1;
                        transform::SUPPRESSED.to_string()
                    }
                }),
            };
            if let Some(value) = transformed {
                let value = patterns.apply(i, value, dataset_key.as_ref(), vault)?;
                if qi_columns.contains(&i) {
                    qi_tuple.push(value.clone());
                }
                out_row.push(value);
            }
        }

        if !qi_columns.is_empty() {
            *classes.entry(qi_tuple).or_insert(0) += 1;
        }
        writer.write_row(&out_row)?;
        rows_written += 1;
    }
    writer.finish()?;

    if suppressed_values > 0 {
        warnings.push(format!(
            "{suppressed_values} value(s) did not match their configured strategy and were suppressed to '{}'",
            transform::SUPPRESSED
        ));
    }

    vault.finish()?;
    let pattern_findings = patterns.findings(&headers, mode, &mut warnings);

    Ok(RiskReport {
        dataset: policy.dataset.clone(),
        mode,
        rows_read,
        rows_written,
        direct_identifiers: findings,
        quasi_identifiers: report::build_quasi_summary(qi_fields, &classes),
        patterns: pattern_findings,
        warnings,
        limitations: report::LIMITATIONS.iter().map(|s| s.to_string()).collect(),
    })
}

/// Decide the action for one column from its policy entry, mode and class.
fn plan_column(
    mode: Mode,
    policy: &Policy,
    header: &str,
    findings: &mut Vec<DirectIdentifierFinding>,
    warnings: &mut Vec<String>,
) -> Result<ColumnAction, CoreError> {
    let Some(field) = policy.field(header) else {
        return match policy.on_unlisted {
            UnlistedAction::Error => Err(CoreError::Policy(format!(
                "column '{header}' is not covered by the policy (on_unlisted: error)"
            ))),
            UnlistedAction::Keep => {
                warnings.push(format!(
                    "column '{header}' is not covered by the policy and was kept unchanged"
                ));
                Ok(ColumnAction::Keep)
            }
            UnlistedAction::Remove => {
                warnings.push(format!(
                    "column '{header}' is not covered by the policy and was removed"
                ));
                Ok(ColumnAction::Drop)
            }
        };
    };

    let action = match mode {
        Mode::Pseudonymize => match field.class {
            FieldClass::DirectIdentifier => {
                findings.push(DirectIdentifierFinding {
                    field: header.to_string(),
                    action: "tokenized".to_string(),
                });
                ColumnAction::Token {
                    prefix: field.pseudonymize.as_ref().and_then(|c| c.prefix.clone()),
                    domain: field
                        .pseudonymize
                        .as_ref()
                        .and_then(|c| c.domain.clone())
                        .unwrap_or_else(|| header.to_string()),
                }
            }
            _ => ColumnAction::Keep,
        },
        Mode::Anonymize => {
            let cfg = field.anonymize.clone();
            match field.class {
                FieldClass::DirectIdentifier => {
                    let cfg = cfg.unwrap_or(AnonymizeCfg::Remove);
                    findings.push(DirectIdentifierFinding {
                        field: header.to_string(),
                        action: cfg.action_name().to_string(),
                    });
                    into_action(cfg)
                }
                FieldClass::QuasiIdentifier => match cfg {
                    Some(cfg) => into_action(cfg),
                    None => {
                        warnings.push(format!(
                            "quasi-identifier '{header}' has no anonymize strategy and was kept unchanged; consider generalization or suppression"
                        ));
                        ColumnAction::Keep
                    }
                },
                FieldClass::Sensitive | FieldClass::Utility => match cfg {
                    Some(cfg) => into_action(cfg),
                    None => ColumnAction::Keep,
                },
            }
        }
    };
    Ok(action)
}

fn into_action(cfg: AnonymizeCfg) -> ColumnAction {
    match cfg {
        AnonymizeCfg::Remove => ColumnAction::Drop,
        other => ColumnAction::Transform(other),
    }
}
