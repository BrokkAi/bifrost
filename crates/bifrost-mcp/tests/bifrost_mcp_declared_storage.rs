//! Issue #3386: the declared-storage family through MCP `run_policy`.
//!
//! The checked-in Python fixture exercises the whole chain over the wire:
//! the shipped policies activate against the workspace's reviewed
//! endpoint-set documents, the taint policy reports the stored
//! request -> write -> read -> helper -> SQL flow with its bounded
//! cross-file evidence, and the opt-in validation policy diagnoses each
//! missing validator. The fixtures are checked in beside this test rather
//! than shared with the root `tests/fixtures/` tree, which the published
//! projection excludes; the copies are byte-identical to
//! `tests/fixtures/declared-storage/python/`, and
//! `tests/suite_bench_policy/issue_3386_declared_storage.rs` is the canonical
//! acceptance for the same fixture.

// `tests/common/mod.rs` is shared with the other suites and re-exports more
// than this binary uses.
#[allow(unused_imports)]
mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};

use brokk_bifrost_analysis::Language;
use brokk_bifrost_mcp::benchmark_api::{
    BENCHMARK_MCP_REQUEST_BUDGET_SECS, MCP_ANALYZER_REQUEST_BUDGET_SECS_ENV,
};
use common::InlineTestProject;
use serde_json::{Value, json};

const TAINT_POLICY_ID: &str = "bifrost.security.python.stored-request-to-sql";
const VALIDATION_POLICY_ID: &str = "bifrost.security.python.store-requires-validation";
const TAINT_POLICY_PATH: &str = "policies/stored-request-to-sql.rqlp";
const VALIDATION_POLICY_PATH: &str = "policies/store-requires-validation.rqlp";

fn fixture_file(root: &Path, relative: &str) -> String {
    let bytes = std::fs::read(root.join(relative))
        .unwrap_or_else(|error| panic!("read fixture file {relative}: {error}"));
    String::from_utf8(bytes).expect("fixture file is UTF-8")
}

fn mcp_server_binary() -> &'static str {
    option_env!("CARGO_BIN_EXE_bifrost-mcp-test-server")
        .or(option_env!("CARGO_BIN_EXE_bifrost"))
        .expect("Cargo did not provide an MCP server binary")
}

fn spawn_server(root: &Path) -> Child {
    Command::new(mcp_server_binary())
        .env(
            MCP_ANALYZER_REQUEST_BUDGET_SECS_ENV,
            BENCHMARK_MCP_REQUEST_BUDGET_SECS.to_string(),
        )
        .arg("--root")
        .arg(root)
        .arg("--mcp")
        .arg("extended")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the bifrost MCP server")
}

fn write_line(stdin: &mut impl Write, payload: Value) {
    writeln!(stdin, "{payload}").expect("write request");
    stdin.flush().expect("flush request");
}

fn read_line(reader: &mut impl BufRead, stderr: &mut impl Read) -> Value {
    let mut line = String::new();
    let bytes = reader.read_line(&mut line).expect("read response");
    if bytes == 0 {
        let mut buffer = String::new();
        let _ = stderr.read_to_string(&mut buffer);
        panic!("server closed before responding; stderr:\n{buffer}");
    }
    serde_json::from_str(&line).expect("valid JSON response")
}

fn round_trip(
    stdin: &mut impl Write,
    reader: &mut impl BufRead,
    stderr: &mut impl Read,
    payload: Value,
) -> Value {
    write_line(stdin, payload);
    read_line(reader, stderr)
}

fn run_policies_over_mcp(project_root: &Path, policy_paths: &[&str]) -> Value {
    let mut child = spawn_server(project_root);
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stdout);

    let initialize = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "declared-storage-3386", "version": "0.1.0" }
            }
        }),
    );
    assert_eq!(initialize["result"]["protocolVersion"], "2025-11-25");
    write_line(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    );

    let response = round_trip(
        &mut stdin,
        &mut reader,
        &mut stderr,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "run_policy",
                "arguments": {
                    "policy_files": policy_paths,
                    "evaluation_date": "2026-09-16",
                    "fail_on": "never"
                }
            }
        }),
    );
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(response["result"]["isError"], false, "{response}");
    response["result"]["structuredContent"].clone()
}

fn build_project() -> common::BuiltInlineTestProject {
    let fixture_root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/declared-storage-python");
    let mut project = InlineTestProject::with_language(Language::Python);
    for relative in [
        "flask.py",
        "sqlite3.py",
        "jobstore.py",
        "validators.py",
        "nearmiss.py",
        "search_handler.py",
        "search_worker.py",
        "search_queries.py",
        TAINT_POLICY_PATH,
        VALIDATION_POLICY_PATH,
        ".bifrost/endpoint-sets/stores/python-declared-store.rqlp",
        ".bifrost/endpoint-sets/observations/python-declared-store-write.rqlp",
        ".bifrost/endpoint-sets/kills/python-required-validator.rqlp",
    ] {
        let contents = fixture_file(&fixture_root, relative);
        project = project.file(relative, &contents);
    }
    project.build()
}

fn run_object<'a>(report: &'a Value, policy_id: &str) -> &'a Value {
    let runs = report["runs"].as_array().expect("policy runs");
    let matching = runs
        .iter()
        .filter(|run| run["policy_id"] == policy_id)
        .collect::<Vec<_>>();
    assert_eq!(
        matching.len(),
        1,
        "expected exactly one run for {policy_id}: {report}"
    );
    matching[0]
}

#[test]
fn mcp_run_policy_reports_the_stored_flow_and_the_missing_validators() {
    let project = build_project();
    let structured =
        run_policies_over_mcp(project.root(), &[TAINT_POLICY_PATH, VALIDATION_POLICY_PATH]);
    let report = &structured["report"];
    assert_eq!(report["schema_version"], 5, "{report}");

    let taint = run_object(report, TAINT_POLICY_ID);
    assert_eq!(taint["completion"]["type"], "inconclusive", "{taint}");
    let taint_findings = taint["findings"].as_array().expect("taint findings");
    assert_eq!(
        taint_findings.len(),
        5,
        "the five concatenated channels: {taint}"
    );
    let headline = taint_findings
        .iter()
        .find(|finding| {
            finding["related"].as_array().is_some_and(|related| {
                related.iter().any(|location| {
                    location["relationship"] == "source"
                        && location["location"]["path"] == "search_worker.py"
                        && location["location"]["region"]["start_line"] == 8
                })
            })
        })
        .expect("the unvalidated channel's finding");
    let related = headline["related"].as_array().expect("related");
    for (relationship, path, line) in [
        ("source", "search_worker.py", 8),
        ("origin", "search_handler.py", 14),
        ("store_write", "search_handler.py", 15),
    ] {
        assert!(
            related.iter().any(|location| {
                location["relationship"] == relationship
                    && location["location"]["path"] == path
                    && location["location"]["region"]["start_line"] == line
            }),
            "the {relationship} hop must be in the MCP evidence chain: {headline}"
        );
    }

    let validation = run_object(report, VALIDATION_POLICY_ID);
    assert_eq!(validation["completion"]["type"], "complete", "{validation}");
    let validation_findings = validation["findings"]
        .as_array()
        .expect("validation findings");
    let mut puts = validation_findings
        .iter()
        .map(|finding| {
            finding["primary"]["region"]["start_line"]
                .as_u64()
                .expect("line")
        })
        .collect::<Vec<_>>();
    puts.sort_unstable();
    assert_eq!(
        puts,
        vec![15, 32, 37, 47],
        "the four unvalidated channels: {validation}"
    );
}
