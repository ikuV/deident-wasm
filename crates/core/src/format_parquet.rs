//! Apache Parquet support (crate feature `parquet`).
//!
//! Parquet is columnar and typed while the job engine is row-oriented and
//! string-based, so this module converts at the edges:
//!
//! - **Reading** decodes every column to its display string (nulls become
//!   empty cells), which is what the policy/transform layer expects.
//! - **Writing** buffers the transformed rows, then infers a column type per
//!   column from the values actually written — a column that stayed numeric
//!   is written as `Int64`/`Float64`, a generalized one (`30-39`) as `Utf8`.
//!   Types therefore survive for untouched columns instead of everything
//!   collapsing to strings.
//!
//! Both directions hold the table in memory; Parquet's footer-based layout
//! makes true streaming impractical here. That is fine for the dataset sizes
//! this MVP targets — see the roadmap for chunked row-group processing.

use std::io::{Read, Write};
use std::sync::Arc;

use arrow_array::{ArrayRef, BooleanArray, Float64Array, Int64Array, RecordBatch, StringArray};
use arrow_cast::display::{ArrayFormatter, FormatOptions};
use arrow_schema::{DataType, Field, Schema};
use parquet::arrow::ArrowWriter;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use crate::error::CoreError;
use crate::format::{RowReader, RowWriter};

fn parquet_err(context: &str, err: impl std::fmt::Display) -> CoreError {
    CoreError::Format(format!("{context}: {err}"))
}

/// Reads a Parquet file as rows of display strings.
pub struct ParquetReader {
    headers: Vec<String>,
    rows: std::vec::IntoIter<Vec<String>>,
}

impl ParquetReader {
    pub fn new<R: Read>(mut input: R) -> Result<Self, CoreError> {
        let mut raw = Vec::new();
        input.read_to_end(&mut raw)?;
        let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(raw))
            .map_err(|e| parquet_err("cannot open Parquet input", e))?;
        let schema = builder.schema().clone();
        let headers: Vec<String> = schema.fields().iter().map(|f| f.name().clone()).collect();

        let reader = builder
            .build()
            .map_err(|e| parquet_err("cannot read Parquet input", e))?;
        // Nulls become empty cells, matching CSV's notion of a missing value.
        let options = FormatOptions::default().with_null("");
        let mut rows: Vec<Vec<String>> = Vec::new();
        for batch in reader {
            let batch = batch.map_err(|e| parquet_err("cannot decode Parquet batch", e))?;
            let formatters: Vec<ArrayFormatter> = batch
                .columns()
                .iter()
                .map(|column| ArrayFormatter::try_new(column.as_ref(), &options))
                .collect::<Result<_, _>>()
                .map_err(|e| parquet_err("unsupported Parquet column type", e))?;
            for row in 0..batch.num_rows() {
                rows.push(
                    formatters
                        .iter()
                        .map(|formatter| formatter.value(row).to_string())
                        .collect(),
                );
            }
        }
        Ok(Self {
            headers,
            rows: rows.into_iter(),
        })
    }
}

impl RowReader for ParquetReader {
    fn headers(&mut self) -> Result<Vec<String>, CoreError> {
        Ok(self.headers.clone())
    }

    fn next_row(&mut self) -> Result<Option<Vec<String>>, CoreError> {
        Ok(self.rows.next())
    }
}

/// Buffers rows and writes one Parquet file on [`RowWriter::finish`].
pub struct ParquetWriter<W: Write + Send> {
    output: Option<W>,
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl<W: Write + Send> ParquetWriter<W> {
    pub fn new(output: W) -> Self {
        Self {
            output: Some(output),
            headers: Vec::new(),
            rows: Vec::new(),
        }
    }
}

/// Column type inferred from the values written to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ColumnType {
    Int,
    Float,
    Bool,
    Text,
}

/// Whether a value is a digit string that `i64` cannot represent *exactly*.
///
/// Two cases matter, and both are identifiers rather than quantities:
/// a 20-digit account number (does not fit) and a zero-padded code like `01234`
/// (fits, but loses its padding). Either would otherwise parse as `f64` and turn
/// the whole column into `Float64`, rewriting `99999999999999999999` as `1e20`
/// and its sibling `12` as `12.0`. Binary floating point is the wrong home for an
/// identifier, so these fall back to text.
fn is_inexact_digit_string(value: &str) -> bool {
    let digits = value.strip_prefix('-').unwrap_or(value);
    !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && !value.parse::<i64>().is_ok_and(|n| n.to_string() == value)
}

/// Cell at `index`, or an empty string for short rows.
fn cell_at(row: &[String], index: usize) -> &str {
    row.get(index).map(String::as_str).unwrap_or("")
}

/// Infer a column's type: every non-empty value must agree, otherwise text.
fn infer_column_type<'a>(values: impl Iterator<Item = &'a str>) -> ColumnType {
    let mut candidate: Option<ColumnType> = None;
    for value in values {
        if value.is_empty() {
            continue;
        }
        let this = if value.parse::<i64>().is_ok_and(|n| n.to_string() == value) {
            ColumnType::Int
        } else if value.parse::<f64>().is_ok_and(f64::is_finite)
            && !is_inexact_digit_string(value)
        {
            ColumnType::Float
        } else if value == "true" || value == "false" {
            ColumnType::Bool
        } else {
            ColumnType::Text
        };
        candidate = Some(match (candidate, this) {
            (None, t) => t,
            (Some(a), b) if a == b => a,
            // Ints and floats mix into floats; anything else falls back to text.
            (Some(ColumnType::Int), ColumnType::Float)
            | (Some(ColumnType::Float), ColumnType::Int) => ColumnType::Float,
            _ => ColumnType::Text,
        });
        if candidate == Some(ColumnType::Text) {
            break;
        }
    }
    candidate.unwrap_or(ColumnType::Text)
}

impl<W: Write + Send> RowWriter for ParquetWriter<W> {
    fn write_headers(&mut self, headers: &[String]) -> Result<(), CoreError> {
        self.headers = headers.to_vec();
        Ok(())
    }

    fn write_row(&mut self, row: &[String]) -> Result<(), CoreError> {
        self.rows.push(row.to_vec());
        Ok(())
    }

    fn finish(&mut self) -> Result<(), CoreError> {
        let Some(output) = self.output.take() else {
            return Ok(());
        };
        let column_count = self.headers.len();
        let mut fields = Vec::with_capacity(column_count);
        let mut columns: Vec<ArrayRef> = Vec::with_capacity(column_count);

        for (index, name) in self.headers.iter().enumerate() {
            let column_type = infer_column_type(self.rows.iter().map(|row| cell_at(row, index)));

            let (data_type, array): (DataType, ArrayRef) = match column_type {
                ColumnType::Int => (
                    DataType::Int64,
                    Arc::new(
                        self.rows
                            .iter()
                            .map(|row| cell_at(row, index).parse::<i64>().ok())
                            .collect::<Int64Array>(),
                    ),
                ),
                ColumnType::Float => (
                    DataType::Float64,
                    Arc::new(
                        self.rows
                            .iter()
                            .map(|row| cell_at(row, index).parse::<f64>().ok())
                            .collect::<Float64Array>(),
                    ),
                ),
                ColumnType::Bool => (
                    DataType::Boolean,
                    Arc::new(
                        self.rows
                            .iter()
                            .map(|row| match cell_at(row, index) {
                                "true" => Some(true),
                                "false" => Some(false),
                                _ => None,
                            })
                            .collect::<BooleanArray>(),
                    ),
                ),
                ColumnType::Text => (
                    DataType::Utf8,
                    Arc::new(
                        self.rows
                            .iter()
                            .map(|row| {
                                let value = cell_at(row, index);
                                (!value.is_empty()).then_some(value)
                            })
                            .collect::<StringArray>(),
                    ),
                ),
            };
            fields.push(Field::new(name, data_type, true));
            columns.push(array);
        }

        let schema = Arc::new(Schema::new(fields));
        let mut writer = ArrowWriter::try_new(output, schema.clone(), None)
            .map_err(|e| parquet_err("cannot create Parquet writer", e))?;
        if !self.rows.is_empty() {
            let batch = RecordBatch::try_new(schema, columns)
                .map_err(|e| parquet_err("cannot build Parquet batch", e))?;
            writer
                .write(&batch)
                .map_err(|e| parquet_err("cannot write Parquet batch", e))?;
        }
        writer
            .close()
            .map_err(|e| parquet_err("cannot finalize Parquet output", e))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_preserving_column_types() {
        let headers: Vec<String> = ["id", "age", "cost", "ok", "bucket"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut raw = Vec::new();
        {
            let mut writer = ParquetWriter::new(&mut raw);
            writer.write_headers(&headers).unwrap();
            writer
                .write_row(&[
                    "P1".into(),
                    "34".into(),
                    "220.5".into(),
                    "true".into(),
                    "30-39".into(),
                ])
                .unwrap();
            writer
                .write_row(&["P2".into(), "52".into(), "80".into(), "false".into(), "50-59".into()])
                .unwrap();
            writer.finish().unwrap();
        }
        assert!(!raw.is_empty(), "parquet output must not be empty");

        let mut reader = ParquetReader::new(raw.as_slice()).unwrap();
        assert_eq!(reader.headers().unwrap(), headers);
        assert_eq!(
            reader.next_row().unwrap().unwrap(),
            ["P1", "34", "220.5", "true", "30-39"]
        );
        assert_eq!(
            reader.next_row().unwrap().unwrap(),
            ["P2", "52", "80.0", "false", "50-59"]
        );
        assert!(reader.next_row().unwrap().is_none());
    }

    /// Identifiers must never be routed through binary floating point, and a
    /// zero-padded value must keep its padding.
    #[test]
    fn oversized_and_padded_numbers_stay_text() {
        assert_eq!(
            infer_column_type(["99999999999999999999", "12"].into_iter()),
            ColumnType::Text,
            "a 20-digit account number must not make the column Float64"
        );
        assert_eq!(
            infer_column_type(["01234", "02345"].into_iter()),
            ColumnType::Text,
            "zero-padded values are identifiers, not integers"
        );
        // Genuine numbers are unaffected.
        assert_eq!(infer_column_type(["12", "-3"].into_iter()), ColumnType::Int);
        assert_eq!(infer_column_type(["1.5", "2"].into_iter()), ColumnType::Float);
    }

    #[test]
    fn infers_mixed_and_empty_columns_as_text() {
        assert_eq!(infer_column_type(["1", "2"].into_iter()), ColumnType::Int);
        assert_eq!(infer_column_type(["1", "2.5"].into_iter()), ColumnType::Float);
        assert_eq!(infer_column_type(["1", "x"].into_iter()), ColumnType::Text);
        assert_eq!(infer_column_type([""].into_iter()), ColumnType::Text);
        assert_eq!(infer_column_type(["true", ""].into_iter()), ColumnType::Bool);
    }

    #[test]
    fn nulls_become_empty_cells() {
        let headers = vec!["a".to_string(), "b".to_string()];
        let mut raw = Vec::new();
        {
            let mut writer = ParquetWriter::new(&mut raw);
            writer.write_headers(&headers).unwrap();
            writer.write_row(&["".into(), "x".into()]).unwrap();
            writer.finish().unwrap();
        }
        let mut reader = ParquetReader::new(raw.as_slice()).unwrap();
        assert_eq!(reader.next_row().unwrap().unwrap(), ["", "x"]);
    }
}
