use crate::benchmark::artifact_path::{sanitize_component, unique_component};
use crate::benchmark::mcp_session::{CapturedStderr, McpSession};
use crate::benchmark::runner::BenchmarkProfile;
use crate::benchmark::{BenchmarkRepoTarget, BenchmarkScenario};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug)]
pub(super) struct Timed<T> {
    pub duration_ms: f64,
    pub value: T,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct IterationId<'a> {
    pub target: &'a BenchmarkRepoTarget,
    pub scenario: BenchmarkScenario,
    pub case_id: Option<&'a str>,
    pub phase: &'a str,
    pub iteration: usize,
}

pub(super) fn start_initialized_session(
    root: &Path,
    no_line_numbers: bool,
    profile: bool,
) -> Result<McpSession, String> {
    McpSession::start(root, no_line_numbers, profile).and_then(initialize_session)
}

pub(super) fn start_initialized_scan_only_session(
    root: &Path,
    no_line_numbers: bool,
    profile: bool,
) -> Result<McpSession, String> {
    McpSession::start_scan_only(root, no_line_numbers, profile).and_then(initialize_session)
}

fn initialize_session(mut session: McpSession) -> Result<McpSession, String> {
    match session.initialize() {
        Ok(()) => Ok(session),
        Err(error) => {
            let tail = session.shutdown_and_stderr_tail();
            Err(error_with_stderr_tail(error, tail))
        }
    }
}

pub(super) fn run_profiled_iteration<T>(
    session: &mut McpSession,
    profile: Option<&BenchmarkProfile>,
    id: IterationId<'_>,
    operation: impl FnOnce(&mut McpSession) -> Result<T, String>,
) -> (Result<Timed<T>, String>, Option<PathBuf>) {
    let cursor = if profile.is_some() {
        if let Err(error) = session.profile_boundary() {
            return (
                Err(error_with_stderr_tail(error, session.stderr_tail())),
                None,
            );
        }
        Some(session.stderr_cursor())
    } else {
        None
    };

    let start = Instant::now();
    let mut outcome = operation(session).map(|value| Timed {
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
        value,
    });

    if profile.is_some() {
        outcome = preserve_outcome_on_boundary_failure(outcome, session.profile_boundary());
    } else if outcome.is_err() {
        // Flush stderr written before a normal JSON-RPC error response so the
        // diagnostic tail below is complete even outside profile mode.
        let _ = session.profile_boundary();
    }

    let artifact = profile.and_then(|profile| {
        let captured = session.stderr_since(cursor.expect("profile cursor"));
        let timing_outcome = outcome
            .as_ref()
            .map(|observation| observation.duration_ms)
            .map_err(Clone::clone);
        match write_profile_trace(profile, id, &timing_outcome, &captured) {
            Ok(path) => Some(path),
            Err(error) => {
                outcome = Err(error);
                None
            }
        }
    });

    if let Err(error) = outcome {
        outcome = Err(error_with_stderr_tail(error, session.stderr_tail()));
    }
    (outcome, artifact)
}

fn preserve_outcome_on_boundary_failure<T>(
    outcome: Result<T, String>,
    boundary: Result<(), String>,
) -> Result<T, String> {
    match (outcome, boundary) {
        (outcome, Ok(())) => outcome,
        (Ok(_), Err(boundary_error)) => Err(format!(
            "failed to synchronize benchmark profile output: {boundary_error}"
        )),
        (Err(request_error), Err(boundary_error)) => Err(format!(
            "{request_error}\nadditionally failed to synchronize benchmark profile output: {boundary_error}"
        )),
    }
}

fn write_profile_trace(
    profile: &BenchmarkProfile,
    trace: IterationId<'_>,
    outcome: &Result<f64, String>,
    captured: &CapturedStderr,
) -> Result<PathBuf, String> {
    std::fs::create_dir_all(&profile.output_dir).map_err(|error| {
        format!(
            "failed to create benchmark profile dir `{}`: {error}",
            profile.output_dir.display()
        )
    })?;
    let case_component = trace
        .case_id
        .map(|case_id| format!("-{}", unique_component(case_id)))
        .unwrap_or_default();
    let filename = format!(
        "{}-{}{case_component}-{}-{}.log",
        unique_component(&trace.target.name),
        sanitize_component(trace.scenario.label()),
        trace.phase,
        trace.iteration
    );
    let output_path = profile.output_dir.join(&filename);
    let report_path = profile.report_path_prefix.join(&filename);
    let (success, duration_ms, failure) = match outcome {
        Ok(duration_ms) => (true, format!("{duration_ms:.3}"), String::new()),
        Err(error) => (false, String::new(), format!("failure={error}\n")),
    };
    let case_line = trace
        .case_id
        .map(|case_id| format!("case_id={case_id}\n"))
        .unwrap_or_default();
    let contents = format!(
        "repository={}\nscenario={}\n{case_line}phase={}\niteration={}\nsuccess={success}\nduration_ms={duration_ms}\ntruncated={}\n{failure}{}",
        trace.target.name,
        trace.scenario.label(),
        trace.phase,
        trace.iteration,
        captured.truncated,
        captured.text
    );
    std::fs::write(&output_path, contents).map_err(|error| {
        format!(
            "failed to write benchmark profile trace `{}`: {error}",
            output_path.display()
        )
    })?;
    Ok(report_path)
}

pub(super) fn error_with_stderr_tail(error: String, tail: CapturedStderr) -> String {
    if tail.text.trim().is_empty() {
        return error;
    }
    let truncation = if tail.truncated { " (truncated)" } else { "" };
    format!(
        "{error}\nbifrost MCP stderr tail{truncation}:\n{}",
        tail.text
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_failure_preserves_the_primary_request_error() {
        let error = preserve_outcome_on_boundary_failure::<()>(
            Err("MCP child closed early".to_string()),
            Err("stderr boundary unavailable".to_string()),
        )
        .expect_err("combined failure");

        assert!(error.starts_with("MCP child closed early"), "{error}");
        assert!(error.contains("stderr boundary unavailable"), "{error}");
    }
}
