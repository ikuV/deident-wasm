//! Streaming CSV job engine: plans one action per column from the policy,
//! then transforms row by row while accumulating risk statistics.

use std::collections::HashMap;
use std::io::{Read, Write};

use deident_types::{DirectIdentifierFinding, Mode, RiskReport};

use crate::error::CoreError;
use crate::key;
use crate::policy::{AnonymizeCfg, FieldClass, Policy, UnlistedAction};
use crate::report;
use crate::transform;
use crate::vault::{MappingEntry, MappingVault};

/// What the engine does with one input column.
enum ColumnAction {
    Keep,
    Drop,
    /// Deterministic tokenization (pseudonymize mode).
    Token { prefix: Option<String> },
    /// Value-level anonymization strategy.
    Transform(AnonymizeCfg),
}

/// Run one CSV job: read from `input`, write the transformed CSV to `output`,
/// and return the risk report. Pseudonym mappings are handed to `vault`.
pub fn run_csv_job<R: Read, W: Write>(
    mode: Mode,
    policy: &Policy,
    input: R,
    output: W,
    vault: &mut dyn MappingVault,
) -> Result<RiskReport, CoreError> {
    policy.validate()?;

    let mut warnings: Vec<String> = Vec::new();
    let mut findings: Vec<DirectIdentifierFinding> = Vec::new();

    let dataset_key = match mode {
        Mode::Pseudonymize => Some(key::resolve_dataset_key(policy, &mut warnings)?),
        Mode::Anonymize => None,
    };

    let mut reader = csv::Reader::from_reader(input);
    let headers = reader.headers()?.clone();

    for field in &policy.fields {
        if !headers.iter().any(|h| h == field.name) {
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

    let mut writer = csv::Writer::from_writer(output);
    let out_headers: Vec<&str> = headers
        .iter()
        .zip(&actions)
        .filter(|(_, a)| !matches!(a, ColumnAction::Drop))
        .map(|(h, _)| h)
        .collect();
    writer.write_record(&out_headers)?;

    let mut rows_read = 0u64;
    let mut rows_written = 0u64;
    let mut suppressed_values = 0u64;
    let mut classes: HashMap<Vec<String>, u64> = HashMap::new();

    for record in reader.records() {
        let record = record?;
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
                ColumnAction::Token { prefix } => {
                    if cell.is_empty() {
                        Some(String::new())
                    } else {
                        let field = &headers[i];
                        let token = key::token(
                            dataset_key.as_ref().expect("key resolved in pseudonymize mode"),
                            field,
                            cell,
                            prefix.as_deref(),
                        );
                        vault.record(MappingEntry {
                            field: field.to_string(),
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
                if qi_columns.contains(&i) {
                    qi_tuple.push(value.clone());
                }
                out_row.push(value);
            }
        }

        if !qi_columns.is_empty() {
            *classes.entry(qi_tuple).or_insert(0) += 1;
        }
        writer.write_record(&out_row)?;
        rows_written += 1;
    }
    writer.flush()?;

    if suppressed_values > 0 {
        warnings.push(format!(
            "{suppressed_values} value(s) did not match their configured strategy and were suppressed to '{}'",
            transform::SUPPRESSED
        ));
    }

    Ok(RiskReport {
        dataset: policy.dataset.clone(),
        mode,
        rows_read,
        rows_written,
        direct_identifiers: findings,
        quasi_identifiers: report::build_quasi_summary(qi_fields, &classes),
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
