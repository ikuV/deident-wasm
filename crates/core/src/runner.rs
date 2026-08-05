//! File-based job execution shared by the native engine and the wasm worker.

use std::fs::File;
use std::io::{BufReader, BufWriter};

use deident_types::{JobOutcome, JobRequest, JobResponse, Mode, RiskReport};

use crate::engine;
use crate::error::CoreError;
use crate::format::Format;
use crate::key;
use crate::policy::Policy;
use crate::vault::{EncryptedVault, MappingVault, NoopVault, derive_vault_key};

/// Execute a job request against the local filesystem (host paths for the
/// native engine, guest paths inside the preopened dir for the wasm worker).
///
/// Never panics on job errors: failures are folded into the response so the
/// caller can report them uniformly.
pub fn execute(request: &JobRequest) -> JobResponse {
    let outcome = match run(request) {
        Ok(report) => JobOutcome::Succeeded {
            report: Box::new(report),
        },
        Err(err) => JobOutcome::Failed {
            error: err.to_string(),
        },
    };
    JobResponse {
        job_id: request.job_id.clone(),
        outcome,
    }
}

fn run(request: &JobRequest) -> Result<RiskReport, CoreError> {
    let policy = Policy::from_yaml(&request.policy_yaml)?;
    let input_format = Format::for_path(&request.input_path)?;
    let output_format = Format::for_path(&request.output_path)?;
    // Creating the output truncates it, so writing over the input would destroy
    // the source before a byte is read — and the job would then "succeed" on an
    // empty file. Refuse instead, comparing canonical paths so `./a.csv` and
    // `a.csv` are recognised as the same file.
    refuse_in_place(&request.input_path, &request.output_path)?;
    let input = BufReader::new(File::open(&request.input_path).map_err(|e| {
        CoreError::Policy(format!("cannot open input '{}': {e}", request.input_path))
    })?);
    // Staged, not written in place: a job that fails halfway through must not
    // leave a truncated file where a fully transformed dataset is expected. Only
    // a job that ran to completion gets to publish its output.
    let mut staged_output = Staged::create(&request.output_path, &request.job_id, "output")?;
    let output = BufWriter::new(staged_output.take_file()?);

    // A vault only makes sense when the job actually produces reversible
    // values (tokens or mocks); otherwise there is nothing to reverse.
    // Must consider the EXPANDED rule set: a policy whose tokenizing rules come
    // from `presets` still produces reversible values, and deciding otherwise
    // silently discards the vault while the report claims none was needed.
    let produces_tokens = needs_key(&policy, request.mode);
    let mut staged_vault: Option<Staged> = None;
    let report = match (&request.vault_path, produces_tokens) {
        (Some(path), true) => {
            let mut key_warnings = Vec::new();
            let secret = key::resolve_secret(&policy, &mut key_warnings)?;
            let vault_key = derive_vault_key(&secret, &policy.dataset);
            let mut staged = Staged::create(path, &request.job_id, "vault")?;
            let file = BufWriter::new(staged.take_file()?);
            let mut vault = EncryptedVault::new(file, &vault_key, &policy.dataset);
            let mut report = run_job(request, &policy, input, output, input_format, output_format, &mut vault)?;
            // `vault` (and its writer) drop at the end of this arm, flushing
            // before anything is moved into place below.
            staged_vault = Some(staged);
            report.warnings.push(format!(
                "an encrypted mapping vault was written to '{path}'; it is re-identification \
                 material — store and access-control it separately from the output"
            ));
            report
        }
        (Some(path), false) => {
            let mut report = run_job(
                request,
                &policy,
                input,
                output,
                input_format,
                output_format,
                &mut NoopVault,
            )?;
            report.warnings.push(format!(
                "no vault was written to '{path}': this job produces no reversible values"
            ));
            report
        }
        (None, _) => run_job(
            request,
            &policy,
            input,
            output,
            input_format,
            output_format,
            &mut NoopVault,
        )?,
    };

    // Publish. The output goes first: if the rename fails there is no point
    // putting re-identification material on disk for a dataset that never landed.
    staged_output.commit()?;
    if let Some(vault) = staged_vault {
        vault.commit()?;
    }

    if let Some(report_path) = &request.report_path {
        let json = serde_json::to_vec_pretty(&report)
            .map_err(|e| CoreError::Policy(format!("cannot serialize report: {e}")))?;
        std::fs::write(report_path, json)?;
    }
    Ok(report)
}

/// Whether a job with this policy and mode will resolve the secret.
///
/// Pseudonymization always tokenizes; in either mode a pattern rule whose action
/// needs the key does too. The expanded rule set is what counts — rules coming
/// from `presets` tokenize just as much as explicitly listed ones.
///
/// Callers outside the runner need this to stay consistent with it: the sandbox
/// host mirrors key-resolution warnings into the report, and mirroring one for a
/// job that never touched the key makes the two engines disagree about the same
/// dataset.
pub fn needs_key(policy: &Policy, mode: Mode) -> bool {
    mode == Mode::Pseudonymize
        || policy
            .effective_patterns()
            .iter()
            .any(|p| p.action.needs_key())
}

/// A file written to a temporary sibling path and moved into place only once the
/// job has succeeded.
///
/// The temporary name is derived from the job id, so two jobs writing to the same
/// directory never fight over it. If the guard is dropped without
/// [`Staged::commit`] — any `?` on the error path — the partial file is removed.
struct Staged {
    temp: std::path::PathBuf,
    target: std::path::PathBuf,
    file: Option<File>,
    what: &'static str,
    committed: bool,
}

impl Staged {
    fn create(target: &str, job_id: &str, what: &'static str) -> Result<Self, CoreError> {
        let target = std::path::PathBuf::from(target);
        let tag = blake3::hash(job_id.as_bytes()).to_hex();
        let name = target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "deident".to_string());
        let temp = target.with_file_name(format!(".{name}.{}.part", &tag[..8]));
        let file = File::create(&temp).map_err(|e| {
            CoreError::Policy(format!(
                "cannot create {what} '{}' (staged as '{}'): {e}",
                target.display(),
                temp.display()
            ))
        })?;
        Ok(Self {
            temp,
            target,
            file: Some(file),
            what,
            committed: false,
        })
    }

    /// Hand the open handle to the writer. Called exactly once.
    fn take_file(&mut self) -> Result<File, CoreError> {
        self.file
            .take()
            .ok_or_else(|| CoreError::Policy(format!("{} handle already taken", self.what)))
    }

    /// Move the finished file to its real path.
    fn commit(mut self) -> Result<(), CoreError> {
        // Both paths are in the same directory, so this is a rename, not a copy.
        std::fs::rename(&self.temp, &self.target).map_err(|e| {
            CoreError::Policy(format!(
                "cannot move the finished {} into place at '{}': {e}",
                self.what,
                self.target.display()
            ))
        })?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        if !self.committed {
            // Best effort: the job already failed, and a leftover dotfile is a
            // smaller problem than a truncated output that looks complete.
            drop(self.file.take());
            let _ = std::fs::remove_file(&self.temp);
        }
    }
}

/// Reject an output path that resolves to the input file.
///
/// Canonicalizing the input is safe (it exists); the output usually does not, so
/// its parent directory is canonicalized and the file name appended. If either
/// path cannot be resolved the check passes — a genuinely broken path will fail
/// with a clearer error moments later when it is opened.
pub fn refuse_in_place(input: &str, output: &str) -> Result<(), CoreError> {
    let input_path = std::path::Path::new(input);
    let output_path = std::path::Path::new(output);
    let resolved_input = input_path.canonicalize();
    let resolved_output = match (output_path.parent(), output_path.file_name()) {
        (Some(parent), Some(name)) => {
            let parent = if parent.as_os_str().is_empty() {
                std::path::Path::new(".")
            } else {
                parent
            };
            parent.canonicalize().map(|dir| dir.join(name))
        }
        _ => return Ok(()),
    };
    if let (Ok(input), Ok(output)) = (resolved_input, resolved_output)
        && input == output
    {
        return Err(CoreError::Policy(format!(
            "refusing to write the output over the input ('{}'): that would destroy the source \
             data before it is read. Choose a different --out path"
        , input.display())));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_job<R: std::io::Read, W: std::io::Write + Send>(
    request: &JobRequest,
    policy: &Policy,
    input: R,
    output: W,
    input_format: Format,
    output_format: Format,
    vault: &mut dyn MappingVault,
) -> Result<RiskReport, CoreError> {
    engine::run_job(
        request.mode,
        policy,
        input,
        output,
        input_format,
        output_format,
        vault,
    )
}
