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

use std::path::Path;
use std::process::Child;

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

fn spawn_server(root: &Path) -> Child {
    // Policy assertions use a generous request budget; production cold-start
    // behavior is covered separately by the reserved budget guards.
    let request_budget = BENCHMARK_MCP_REQUEST_BUDGET_SECS.to_string();
    common::mcp_server::spawn_mcp_server(
        common::mcp_server::mcp_server_binary(),
        root,
        "extended",
        &[],
        &[
            ("BIFROST_WORKSPACE_SEMANTIC_MODELS", "on"),
            (MCP_ANALYZER_REQUEST_BUDGET_SECS_ENV, &request_budget),
        ],
    )
    .expect("spawn the bifrost MCP server")
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
    let response = common::mcp_wire::call_mcp_tool(
        &mut child,
        "policy-substrate-p0",
        0,
        1,
        "run_policy",
        json!({
            "policy_files": [POLICY_PATH],
            "evaluation_date": "2026-08-20",
            "fail_on": "warning"
        }),
    );
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(response["result"]["isError"], false, "{response}");
    response["result"]["structuredContent"].clone()
}

/// The violating tree: `run_policy` reports the finding status, exit status 1,
/// and the canonical schema-5 report carrying both marked procedures.
#[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
#[test]
fn mcp_run_policy_reports_the_forbidden_transitive_effect() {
    let structured = run_policy_over(FINDING_APP);
    assert_eq!(structured["status"], "finding", "{structured}");
    assert_eq!(structured["exit_status"], 1, "{structured}");

    let report = &structured["report"];
    assert_eq!(report["schema_version"], 6);
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

/// The tree with an unresolved callee: the run abstains with an inconclusive
/// completion rather than a complete one, and it says which claim it could not
/// make. The inconclusive verdict is advisory (#8111), so the exit status is 0.
#[test]
fn mcp_run_policy_abstains_with_an_advisory_inconclusive_verdict() {
    let structured = run_policy_over(UNRELIABLE_APP);
    common::policy_report::assert_mcp_policy_abstains(&structured);
    let run = &structured["report"]["runs"][0];
    assert_eq!(
        run["obligations"][0]["assertion"],
        "pure-procedure-network-effects"
    );
}
