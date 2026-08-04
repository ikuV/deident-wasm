//! Tabular input/output formats.
//!
//! The job engine works on rows of string cells, so every format is reduced
//! to a [`RowReader`]/[`RowWriter`] pair. Adding a format means implementing
//! those two traits — the policy, transform, pattern and report layers never
//! change.
//!
//! Formats are inferred from the file extension, so input and output can
//! differ (`in.csv` → `out.jsonl` converts while it transforms).

use std::io::{BufRead, BufReader, Read, Write};

use crate::error::CoreError;

/// A supported tabular format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// RFC 4180-ish CSV with a header row.
    Csv,
    /// One flat JSON object per line.
    Jsonl,
    #[cfg(feature = "parquet")]
    /// Apache Parquet (native only; see the crate's `parquet` feature).
    Parquet,
}

impl Format {
    /// Infer the format from a path's extension.
    pub fn for_path(path: &str) -> Result<Self, CoreError> {
        let extension = std::path::Path::new(path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        match extension.as_str() {
            "csv" => Ok(Format::Csv),
            "jsonl" | "ndjson" => Ok(Format::Jsonl),
            #[cfg(feature = "parquet")]
            "parquet" | "pq" => Ok(Format::Parquet),
            #[cfg(not(feature = "parquet"))]
            "parquet" | "pq" => Err(CoreError::Format(
                "Parquet support is not compiled into this build (enable the 'parquet' feature; \
                 it is unavailable inside the wasm sandbox)"
                    .into(),
            )),
            "" => Err(CoreError::Format(format!(
                "cannot infer format for '{path}': no file extension (expected .csv, .jsonl)"
            ))),
            other => Err(CoreError::Format(format!(
                "unsupported format '.{other}' for '{path}' (expected .csv, .jsonl)"
            ))),
        }
    }

    /// Short name for messages.
    pub fn name(&self) -> &'static str {
        match self {
            Format::Csv => "csv",
            Format::Jsonl => "jsonl",
            #[cfg(feature = "parquet")]
            Format::Parquet => "parquet",
        }
    }
}

/// Reads a table row by row as string cells.
pub trait RowReader {
    /// Column names, in output order.
    fn headers(&mut self) -> Result<Vec<String>, CoreError>;
    /// Next row, or `None` at end of input.
    fn next_row(&mut self) -> Result<Option<Vec<String>>, CoreError>;
}

/// Writes a table row by row.
pub trait RowWriter {
    fn write_headers(&mut self, headers: &[String]) -> Result<(), CoreError>;
    fn write_row(&mut self, row: &[String]) -> Result<(), CoreError>;
    /// Flush buffered state. Must be called once when the job finishes.
    fn finish(&mut self) -> Result<(), CoreError>;
}

/// Open a reader for `format` over `input`.
pub fn reader<'a, R: Read + 'a>(
    format: Format,
    input: R,
) -> Result<Box<dyn RowReader + 'a>, CoreError> {
    Ok(match format {
        Format::Csv => Box::new(CsvReader::new(input)),
        Format::Jsonl => Box::new(JsonlReader::new(input)?),
        #[cfg(feature = "parquet")]
        Format::Parquet => Box::new(crate::format_parquet::ParquetReader::new(input)?),
    })
}

/// Open a writer for `format` over `output`.
pub fn writer<'a, W: Write + Send + 'a>(
    format: Format,
    output: W,
) -> Result<Box<dyn RowWriter + 'a>, CoreError> {
    Ok(match format {
        Format::Csv => Box::new(CsvWriter::new(output)),
        Format::Jsonl => Box::new(JsonlWriter::new(output)),
        #[cfg(feature = "parquet")]
        Format::Parquet => Box::new(crate::format_parquet::ParquetWriter::new(output)),
    })
}

// --- CSV -----------------------------------------------------------------

struct CsvReader<R: Read> {
    inner: csv::Reader<R>,
}

impl<R: Read> CsvReader<R> {
    fn new(input: R) -> Self {
        Self {
            inner: csv::Reader::from_reader(input),
        }
    }
}

impl<R: Read> RowReader for CsvReader<R> {
    fn headers(&mut self) -> Result<Vec<String>, CoreError> {
        Ok(self.inner.headers()?.iter().map(str::to_string).collect())
    }

    fn next_row(&mut self) -> Result<Option<Vec<String>>, CoreError> {
        match self.inner.records().next() {
            Some(record) => Ok(Some(record?.iter().map(str::to_string).collect())),
            None => Ok(None),
        }
    }
}

struct CsvWriter<W: Write> {
    inner: csv::Writer<W>,
}

impl<W: Write> CsvWriter<W> {
    fn new(output: W) -> Self {
        Self {
            inner: csv::Writer::from_writer(output),
        }
    }
}

impl<W: Write> RowWriter for CsvWriter<W> {
    fn write_headers(&mut self, headers: &[String]) -> Result<(), CoreError> {
        self.inner.write_record(headers)?;
        Ok(())
    }

    fn write_row(&mut self, row: &[String]) -> Result<(), CoreError> {
        self.inner.write_record(row)?;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), CoreError> {
        self.inner.flush()?;
        Ok(())
    }
}

// --- JSONL ---------------------------------------------------------------

/// Scalar JSON type of a column, so untouched values keep their type on write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JsonKind {
    String,
    Number,
    Bool,
    Null,
}

/// One flat JSON object per line. Column order (and the set of columns) comes
/// from the first record; later records may omit keys (treated as empty) but
/// must not introduce new ones.
struct JsonlReader<R: Read> {
    lines: std::io::Lines<BufReader<R>>,
    headers: Vec<String>,
    kinds: Vec<JsonKind>,
    /// First record, consumed before reading further lines.
    pending: Option<Vec<String>>,
    row: u64,
}

impl<R: Read> JsonlReader<R> {
    fn new(input: R) -> Result<Self, CoreError> {
        let mut lines = BufReader::new(input).lines();
        let mut headers = Vec::new();
        let mut kinds = Vec::new();
        let mut pending = None;
        // Skip blank leading lines; the first object defines the schema.
        for line in lines.by_ref() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let object = parse_object(&line, 1)?;
            for (key, value) in &object {
                headers.push(key.clone());
                kinds.push(kind_of(value));
            }
            pending = Some(
                object
                    .into_iter()
                    .map(|(_, value)| scalar_to_string(&value, 1))
                    .collect::<Result<Vec<_>, _>>()?,
            );
            break;
        }
        Ok(Self {
            lines,
            headers,
            kinds,
            pending,
            row: 1,
        })
    }
}

impl<R: Read> RowReader for JsonlReader<R> {
    fn headers(&mut self) -> Result<Vec<String>, CoreError> {
        Ok(self.headers.clone())
    }

    fn next_row(&mut self) -> Result<Option<Vec<String>>, CoreError> {
        if let Some(first) = self.pending.take() {
            return Ok(Some(first));
        }
        for line in self.lines.by_ref() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            self.row += 1;
            let object = parse_object(&line, self.row)?;
            let mut row = vec![String::new(); self.headers.len()];
            for (key, value) in object {
                let Some(index) = self.headers.iter().position(|h| *h == key) else {
                    return Err(CoreError::Format(format!(
                        "JSONL record {} has key '{key}' that the first record did not declare",
                        self.row
                    )));
                };
                row[index] = scalar_to_string(&value, self.row)?;
            }
            return Ok(Some(row));
        }
        Ok(None)
    }
}

fn parse_object(line: &str, row: u64) -> Result<Vec<(String, serde_json::Value)>, CoreError> {
    let value: serde_json::Value = serde_json::from_str(line)
        .map_err(|e| CoreError::Format(format!("JSONL record {row} is not valid JSON: {e}")))?;
    match value {
        serde_json::Value::Object(map) => Ok(map.into_iter().collect()),
        _ => Err(CoreError::Format(format!(
            "JSONL record {row} is not a JSON object"
        ))),
    }
}

fn kind_of(value: &serde_json::Value) -> JsonKind {
    match value {
        serde_json::Value::Number(_) => JsonKind::Number,
        serde_json::Value::Bool(_) => JsonKind::Bool,
        serde_json::Value::Null => JsonKind::Null,
        _ => JsonKind::String,
    }
}

/// Flatten a scalar JSON value to its string form. Nested objects and arrays
/// are rejected: the policy model classifies columns, and a nested value has
/// no single class.
fn scalar_to_string(value: &serde_json::Value, row: u64) -> Result<String, CoreError> {
    match value {
        serde_json::Value::Null => Ok(String::new()),
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        serde_json::Value::Bool(b) => Ok(b.to_string()),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => Err(CoreError::Format(
            format!("JSONL record {row} contains a nested value; only flat objects are supported"),
        )),
    }
}

struct JsonlWriter<W: Write> {
    output: W,
    headers: Vec<String>,
    /// Column types observed on the first written row, used to keep numbers
    /// and booleans typed when their value was not modified.
    kinds: Vec<JsonKind>,
}

impl<W: Write> JsonlWriter<W> {
    fn new(output: W) -> Self {
        Self {
            output,
            headers: Vec::new(),
            kinds: Vec::new(),
        }
    }
}

impl<W: Write> RowWriter for JsonlWriter<W> {
    fn write_headers(&mut self, headers: &[String]) -> Result<(), CoreError> {
        self.headers = headers.to_vec();
        Ok(())
    }

    fn write_row(&mut self, row: &[String]) -> Result<(), CoreError> {
        let mut object = serde_json::Map::with_capacity(row.len());
        for (i, cell) in row.iter().enumerate() {
            let key = self
                .headers
                .get(i)
                .cloned()
                .unwrap_or_else(|| format!("column_{i}"));
            object.insert(key, typed_value(cell, self.kinds.get(i).copied()));
        }
        let mut line = serde_json::to_vec(&object)
            .map_err(|e| CoreError::Format(format!("cannot serialize JSONL record: {e}")))?;
        line.push(b'\n');
        self.output.write_all(&line)?;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), CoreError> {
        self.output.flush()?;
        Ok(())
    }
}

/// Re-type a cell for JSON output: values that still look like numbers or
/// booleans are emitted as such, everything else as a string.
fn typed_value(cell: &str, _hint: Option<JsonKind>) -> serde_json::Value {
    if cell.is_empty() {
        return serde_json::Value::Null;
    }
    if let Ok(number) = cell.parse::<i64>() {
        return serde_json::Value::from(number);
    }
    // Only re-type floats whose text round-trips, so "1.10" stays a string
    // rather than silently becoming 1.1.
    if let Ok(float) = cell.parse::<f64>()
        && float.is_finite()
        && float.to_string() == cell
        && let Some(number) = serde_json::Number::from_f64(float)
    {
        return serde_json::Value::Number(number);
    }
    match cell {
        "true" => serde_json::Value::Bool(true),
        "false" => serde_json::Value::Bool(false),
        other => serde_json::Value::String(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infers_format_from_extension() {
        assert_eq!(Format::for_path("a/b.csv").unwrap(), Format::Csv);
        assert_eq!(Format::for_path("a/b.CSV").unwrap(), Format::Csv);
        assert_eq!(Format::for_path("a/b.jsonl").unwrap(), Format::Jsonl);
        assert_eq!(Format::for_path("a/b.ndjson").unwrap(), Format::Jsonl);
        assert!(Format::for_path("a/b.txt").is_err());
        assert!(Format::for_path("noext").is_err());
    }

    #[test]
    fn jsonl_round_trips_with_types() {
        let input = r#"{"id":"P1","age":34,"ok":true,"note":null}
{"id":"P2","age":52,"ok":false,"note":"hi"}"#;
        let mut reader = JsonlReader::new(input.as_bytes()).unwrap();
        assert_eq!(reader.headers().unwrap(), ["id", "age", "ok", "note"]);
        assert_eq!(
            reader.next_row().unwrap().unwrap(),
            ["P1", "34", "true", ""]
        );
        assert_eq!(
            reader.next_row().unwrap().unwrap(),
            ["P2", "52", "false", "hi"]
        );
        assert!(reader.next_row().unwrap().is_none());

        let mut out = Vec::new();
        {
            let mut writer = JsonlWriter::new(&mut out);
            let headers: Vec<String> = ["id", "age", "ok", "note"].iter().map(|s| s.to_string()).collect();
            writer.write_headers(&headers).unwrap();
            writer
                .write_row(&["P1".into(), "30-39".into(), "true".into(), "".into()])
                .unwrap();
            writer.finish().unwrap();
        }
        let line = String::from_utf8(out).unwrap();
        assert!(line.contains(r#""id":"P1""#), "{line}");
        assert!(line.contains(r#""age":"30-39""#), "generalized values stay strings: {line}");
        assert!(line.contains(r#""ok":true"#), "booleans stay typed: {line}");
        assert!(line.contains(r#""note":null"#), "empty becomes null: {line}");
    }

    #[test]
    fn jsonl_rejects_nested_and_unknown_keys() {
        let nested = r#"{"id":"P1","tags":["a"]}"#;
        assert!(JsonlReader::new(nested.as_bytes()).is_err());

        let extra = "{\"id\":\"P1\"}\n{\"id\":\"P2\",\"surprise\":1}";
        let mut reader = JsonlReader::new(extra.as_bytes()).unwrap();
        reader.next_row().unwrap();
        assert!(reader.next_row().is_err());
    }

    #[test]
    fn numbers_keep_their_text_when_ambiguous() {
        assert_eq!(typed_value("1.10", None), serde_json::Value::String("1.10".into()));
        assert_eq!(typed_value("220.5", None), serde_json::json!(220.5));
        assert_eq!(typed_value("007", None), serde_json::json!(7));
    }
}
