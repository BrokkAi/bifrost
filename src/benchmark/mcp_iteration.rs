use crate::benchmark::artifact_path::{sanitize_component, unique_component};
use crate::benchmark::mcp_session::{CapturedStderr, McpSession};
use crate::benchmark::runner::BenchmarkProfile;
use crate::benchmark::{BenchmarkRepoTarget, BenchmarkScenario, McpTransportPhaseReport};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

const RETAINED_TRANSPORT_TIMING_PREFIX: &str = "retained_transport_timing=";

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
        // The first boundary response is delivered by the same writer as the
        // tool response, proving the tool's writer-delivery scope has closed.
        // A second boundary then seals stderr after that final timing line.
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
    let retained_transport_timings = render_retained_transport_timings(&captured.transport_timings);
    let contents = format!(
        "repository={}\nscenario={}\n{case_line}phase={}\niteration={}\nsuccess={success}\nduration_ms={duration_ms}\ntruncated={}\n{retained_transport_timings}{failure}{}",
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

fn render_retained_transport_timings(lines: &[String]) -> String {
    let mut rendered = String::new();
    for line in lines {
        debug_assert!(!line.contains('\r') && !line.contains('\n'));
        rendered.push_str(RETAINED_TRANSPORT_TIMING_PREFIX);
        rendered.push_str(line);
        rendered.push('\n');
    }
    rendered
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

pub(super) fn transport_phase_report(
    profile: Option<&BenchmarkProfile>,
    artifacts: &[PathBuf],
) -> Result<Vec<McpTransportPhaseReport>, String> {
    let Some(profile) = profile else {
        return Ok(Vec::new());
    };
    let mut measured = artifacts
        .iter()
        .filter(|artifact| {
            artifact
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.contains("-measured-"))
        })
        .peekable();
    if measured.peek().is_none() {
        return Ok(Vec::new());
    }
    let mut timings = BTreeMap::<(String, String), Vec<f64>>::new();
    let mut phases = HashSet::new();
    for artifact in measured {
        let filename = artifact
            .file_name()
            .ok_or_else(|| format!("profile artifact `{}` has no filename", artifact.display()))?;
        let path = profile.output_dir.join(filename);
        let contents = std::fs::read_to_string(&path).map_err(|error| {
            format!(
                "failed to read profile artifact `{}`: {error}",
                path.display()
            )
        })?;
        for (phase, tool, duration_ms) in parse_profile_transport_phase_timings(&contents) {
            phases.insert(phase.clone());
            timings.entry((phase, tool)).or_default().push(duration_ms);
        }
    }
    for required in [
        "queue_wait",
        "execution",
        "response_queue_wait",
        "writer_delivery",
    ] {
        if !phases.contains(required) {
            return Err(format!(
                "profile artifacts omitted required MCP transport phase `{required}`"
            ));
        }
    }
    Ok(timings
        .into_iter()
        .map(|((phase, tool), durations)| {
            McpTransportPhaseReport::from_timings(phase, tool, durations)
        })
        .collect())
}

fn parse_transport_phase_timings(contents: &str) -> Vec<(String, String, f64)> {
    contents
        .lines()
        .filter_map(parse_transport_phase_timing_line)
        .collect()
}

fn parse_profile_transport_phase_timings(contents: &str) -> Vec<(String, String, f64)> {
    let mut retained = contents
        .lines()
        .filter_map(|line| line.strip_prefix(RETAINED_TRANSPORT_TIMING_PREFIX))
        .peekable();
    if retained.peek().is_some() {
        retained
            .filter_map(parse_transport_phase_timing_line)
            .collect()
    } else {
        parse_transport_phase_timings(contents)
    }
}

fn parse_transport_phase_timing_line(line: &str) -> Option<(String, String, f64)> {
    let marker = line.find("mcp_request.")?;
    let timing = &line[marker + "mcp_request.".len()..];
    let phase_end = timing.find('[')?;
    let tool_end = timing[phase_end + 1..].find(']')? + phase_end + 1;
    let phase = &timing[..phase_end];
    if !matches!(
        phase,
        "queue_wait" | "execution" | "response_queue_wait" | "writer_delivery"
    ) {
        return None;
    }
    let duration_start = timing[tool_end + 1..].rfind('(')? + tool_end + 2;
    let duration_end = timing[duration_start..].find(" ms)")? + duration_start;
    let duration_ms = timing[duration_start..duration_end].parse().ok()?;
    Some((
        phase.to_string(),
        timing[phase_end + 1..tool_end].to_string(),
        duration_ms,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_profile(output: &tempfile::TempDir) -> BenchmarkProfile {
        BenchmarkProfile {
            output_dir: output.path().to_path_buf(),
            report_path_prefix: PathBuf::from("profiles"),
        }
    }

    fn write_measured_artifact(profile: &BenchmarkProfile, filename: &str, contents: &str) {
        std::fs::write(profile.output_dir.join(filename), contents).unwrap();
    }

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

    #[test]
    fn issue_1228_transport_phase_parser_separates_queue_and_execution() {
        let timings = parse_transport_phase_timings(
            "[bifrost-timing] DURATION mcp_request.queue_wait[scan_usages_by_location] (1.2 ms)\n\
             [bifrost-timing] END mcp_request.execution[scan_usages_by_location] (3456.7 ms)\n\
             [bifrost-timing] DURATION mcp_request.response_queue_wait[scan_usages_by_location] (0.4 ms)\n\
             [bifrost-timing] END mcp_request.writer_delivery[scan_usages_by_location] (0.2 ms)\n",
        );

        assert_eq!(timings.len(), 4);
        assert_eq!(
            timings[0],
            ("queue_wait".into(), "scan_usages_by_location".into(), 1.2)
        );
        assert_eq!(timings[1].0, "execution");
        assert_eq!(timings[1].2, 3456.7);
    }

    #[test]
    fn issue_1631_retained_timings_replace_truncated_raw_samples() {
        let output = tempfile::tempdir().unwrap();
        let profile = test_profile(&output);
        let filename = "case-measured-1.log";
        let retained = render_retained_transport_timings(&[
            "[bifrost-timing] DURATION mcp_request.queue_wait[search_symbols] (0.2 ms)".to_string(),
            "[bifrost-timing] END mcp_request.execution[search_symbols] (1.0 ms)".to_string(),
            "[bifrost-timing] DURATION mcp_request.response_queue_wait[search_symbols] (0.1 ms)"
                .to_string(),
            "[bifrost-timing] END mcp_request.writer_delivery[search_symbols] (0.1 ms)".to_string(),
        ]);
        write_measured_artifact(
            &profile,
            filename,
            &format!(
                "truncated=true\n{retained}\
                 [bifrost-timing] END mcp_request.execution[search_symbols] (1.0 ms)\n\
                 [bifrost-timing] DURATION mcp_request.response_queue_wait[search_symbols] (0.1 ms)\n\
                 [bifrost-timing] END mcp_request.writer_delivery[search_symbols] (0.1 ms)\n"
            ),
        );

        let phases = transport_phase_report(Some(&profile), &[PathBuf::from(filename)]).unwrap();

        assert_eq!(phases.len(), 4);
        assert!(phases.iter().all(|phase| phase.durations_ms.len() == 1));
    }

    #[test]
    fn issue_1631_warmup_only_profile_has_no_transport_phase_report() {
        let output = tempfile::tempdir().unwrap();
        let profile = test_profile(&output);

        let phases =
            transport_phase_report(Some(&profile), &[PathBuf::from("case-warmup-1.log")]).unwrap();

        assert!(phases.is_empty());
    }

    #[test]
    fn issue_1631_measured_profile_still_requires_all_transport_phases() {
        let output = tempfile::tempdir().unwrap();
        let profile = test_profile(&output);
        let filename = "case-measured-1.log";
        write_measured_artifact(
            &profile,
            filename,
            "[bifrost-timing] END mcp_request.execution[search_symbols] (1.0 ms)\n\
             [bifrost-timing] DURATION mcp_request.response_queue_wait[search_symbols] (0.1 ms)\n\
             [bifrost-timing] END mcp_request.writer_delivery[search_symbols] (0.1 ms)\n",
        );

        let error = transport_phase_report(Some(&profile), &[PathBuf::from(filename)])
            .expect_err("measured profile omitted queue_wait");

        assert_eq!(
            error,
            "profile artifacts omitted required MCP transport phase `queue_wait`"
        );
    }

    #[test]
    fn issue_1631_complete_measured_profile_reports_all_transport_phases() {
        let output = tempfile::tempdir().unwrap();
        let profile = test_profile(&output);
        let filename = "case-measured-1.log";
        write_measured_artifact(
            &profile,
            filename,
            "[bifrost-timing] DURATION mcp_request.queue_wait[search_symbols] (0.2 ms)\n\
             [bifrost-timing] END mcp_request.execution[search_symbols] (1.0 ms)\n\
             [bifrost-timing] DURATION mcp_request.response_queue_wait[search_symbols] (0.1 ms)\n\
             [bifrost-timing] END mcp_request.writer_delivery[search_symbols] (0.1 ms)\n",
        );

        let phases = transport_phase_report(Some(&profile), &[PathBuf::from(filename)]).unwrap();
        let phase_names = phases
            .iter()
            .map(|report| report.phase.as_str())
            .collect::<HashSet<_>>();

        assert_eq!(
            phase_names,
            HashSet::from([
                "queue_wait",
                "execution",
                "response_queue_wait",
                "writer_delivery",
            ])
        );
    }
}
