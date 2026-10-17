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

use std::path::Path;
use std::process::Child;

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

fn spawn_server(root: &Path) -> Child {
    let request_budget = BENCHMARK_MCP_REQUEST_BUDGET_SECS.to_string();
    common::mcp_server::spawn_mcp_server(
        common::mcp_server::mcp_server_binary(),
        root,
        "extended",
        &[],
        &[(MCP_ANALYZER_REQUEST_BUDGET_SECS_ENV, &request_budget)],
    )
    .expect("spawn the bifrost MCP server")
}

fn run_policies_over_mcp(project_root: &Path, policy_paths: &[&str]) -> Value {
    let mut child = spawn_server(project_root);
    let response = common::mcp_wire::call_mcp_tool(
        &mut child,
        "declared-storage-3386",
        0,
        1,
        "run_policy",
        json!({
            "policy_files": policy_paths,
            "evaluation_date": "2026-09-16",
            "fail_on": "never"
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
    common::policy_report::run_for_policy_id(report, policy_id)
}

#[test]
fn mcp_run_policy_reports_the_stored_flow_and_the_missing_validators() {
    let project = build_project();
    let structured =
        run_policies_over_mcp(project.root(), &[TAINT_POLICY_PATH, VALIDATION_POLICY_PATH]);
    let report = &structured["report"];
    assert_eq!(report["schema_version"], 6, "{report}");

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
