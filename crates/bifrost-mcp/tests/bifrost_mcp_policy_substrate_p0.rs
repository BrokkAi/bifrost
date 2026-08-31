//! The issue-2433 integration checkpoint through MCP `run_policy`.
//!
//! Reference policy B — a forbidden transitive effect — is the one of the two
//! P0 reference policies that needs a semantic model, and MCP is the host that
//! activates a model from its workspace-authoring location
//! (`.bifrost/semantic-models/`, enabled by
//! `BIFROST_WORKSPACE_SEMANTIC_MODELS=on`). Running it here proves the whole
//! chain over the wire: the authored model activates at workspace bind, the
//! relational policy joins the annotation marker against the `procedure_effect`
//! rows the model produces, and `run_policy` returns the same canonical report
//! the CLI renders.
//!
//! The fixtures are checked in beside this test rather than shared with the
//! root `tests/fixtures/` tree, which the published projection excludes; the
//! copies are byte-identical to
//! `tests/fixtures/policy-substrate-p0/`, and
//! `tests/suite_bench_policy/policy_substrate_p0.rs` is the canonical
//! acceptance for the same fixtures.

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

const EFFECT_POLICY: &str =
    include_str!("fixtures/policy-substrate-p0/acme-pure-has-no-network-io.rqlp");
const SEMANTIC_MODEL: &str = include_str!("fixtures/policy-substrate-p0/acme-http-client.json");
const PURE_ANNOTATION: &str = include_str!("fixtures/policy-substrate-p0/Pure.java");
const HTTP_CLIENT: &str = include_str!("fixtures/policy-substrate-p0/AcmeHttpClient.java");
const FINDING_APP: &str = include_str!("fixtures/policy-substrate-p0/FindingApp.java");
const UNRELIABLE_APP: &str = include_str!("fixtures/policy-substrate-p0/UnreliableApp.java");

const POLICY_PATH: &str = "policies/acme-pure-has-no-network-io.rqlp";
const MODEL_PATH: &str = ".bifrost/semantic-models/acme-http-client.json";

fn mcp_server_binary() -> &'static str {
    option_env!("CARGO_BIN_EXE_bifrost-mcp-test-server")
        .or(option_env!("CARGO_BIN_EXE_bifrost"))
        .expect("Cargo did not provide an MCP server binary")
}

fn spawn_server(root: &Path) -> Child {
    Command::new(mcp_server_binary())
        // The workspace-authoring location for semantic models is opt-in.
        .env("BIFROST_WORKSPACE_SEMANTIC_MODELS", "on")
        // A functional wire test must not incidentally assert the cold-start
        // budget: left at the production default a first call made during the
        // workspace build is held to COLD_WORKSPACE_REQUEST_BUDGET (4.5s), and
        // suite saturation then fails a protocol assertion for box load. Two
        // tests prove the cold-start claim deliberately instead, on a reserved
        // machine -- see `apply_test_request_budget` in
        // `crates/bifrost-mcp/tests/bifrost_mcp_server.rs`.
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

/// Run reference policy B over one workspace through MCP `run_policy`.
fn run_policy_over(app: &str) -> Value {
    let project = InlineTestProject::with_language(Language::Java)
        .file("src/com/acme/Pure.java", PURE_ANNOTATION)
        .file("src/com/acme/AcmeHttpClient.java", HTTP_CLIENT)
        .file("src/com/acme/App.java", app)
        .file(MODEL_PATH, SEMANTIC_MODEL)
        .file(POLICY_PATH, EFFECT_POLICY)
        .build();

    let mut child = spawn_server(project.root());
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
                "clientInfo": { "name": "policy-substrate-p0", "version": "0.1.0" }
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
                    "policy_files": [POLICY_PATH],
                    "evaluation_date": "2026-08-20",
                    "fail_on": "warning"
                }
            }
        }),
    );
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(response["result"]["isError"], false, "{response}");
    response["result"]["structuredContent"].clone()
}

/// The violating tree: `run_policy` reports the finding status, exit status 1,
/// and the canonical schema-5 report carrying both marked procedures.
#[test]
fn mcp_run_policy_reports_the_forbidden_transitive_effect() {
    let structured = run_policy_over(FINDING_APP);
    assert_eq!(structured["status"], "finding", "{structured}");
    assert_eq!(structured["exit_status"], 1, "{structured}");

    let report = &structured["report"];
    assert_eq!(report["schema_version"], 5);
    assert_eq!(
        report["evaluation"]["evaluation_date"], "2026-08-20",
        "{report}"
    );
    assert_eq!(
        report["rules"][0]["policy_id"],
        "bifrost.p0.acme-pure-has-no-network-io"
    );
    assert_eq!(
        report["rules"][0]["policy_hash"],
        "998956c26b7123f9f1978261acc6fc40129710ad74bdedc22dd655e30e93e457",
        "the semantic hash the CLI and the library pin must reach MCP unchanged"
    );

    let run = &report["runs"][0];
    assert_eq!(run["completion"]["type"], "complete", "{run}");
    assert_eq!(run["analysis_type"], "assertion");
    let findings = run["findings"].as_array().expect("findings array");
    assert_eq!(
        findings.len(),
        2,
        "the direct and the transitive marked procedures: {run}"
    );
    for finding in findings {
        assert_eq!(
            finding["message"],
            "a procedure annotated @Pure reaches the acme.network_io effect"
        );
        assert_eq!(finding["primary"]["path"], "src/com/acme/App.java");
    }
    assert!(
        run["obligations"]
            .as_array()
            .expect("obligations array")
            .is_empty(),
        "a concluded run has no unmet obligation: {run}"
    );
}

/// The tree with an unresolved callee: `run_policy` abstains rather than
/// returning a clean verdict, and it says which claim it could not make.
#[test]
fn mcp_run_policy_abstains_instead_of_reporting_a_clean_verdict() {
    let structured = run_policy_over(UNRELIABLE_APP);
    assert_eq!(structured["exit_status"], 2, "{structured}");
    assert_ne!(
        structured["status"], "clean",
        "an open effect set is never clean: {structured}"
    );

    let run = &structured["report"]["runs"][0];
    assert_eq!(run["completion"]["type"], "inconclusive", "{run}");
    assert!(
        run["findings"]
            .as_array()
            .expect("findings array")
            .is_empty(),
        "nothing modeled is reached, so there is no positive evidence: {run}"
    );
    let obligations = run["obligations"].as_array().expect("obligations array");
    assert_eq!(obligations.len(), 1, "{run}");
    assert_eq!(
        obligations[0]["kind"],
        "absence_requires_exhaustive_coverage"
    );
    assert_eq!(
        obligations[0]["assertion"],
        "pure-procedure-network-effects"
    );
}
