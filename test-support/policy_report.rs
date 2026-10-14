use serde_json::Value;
use std::process::Output;

#[allow(dead_code)]
pub fn finding_count_from_single_run(report: &str) -> usize {
    let value: Value = serde_json::from_str(report).expect("canonical policy report JSON");
    let [run] = value["runs"]
        .as_array()
        .expect("canonical policy report runs")
        .as_slice()
    else {
        panic!("expected one policy run in {value}");
    };
    run["findings"]
        .as_array()
        .expect("policy run findings")
        .len()
}

#[allow(dead_code)]
pub fn findings_from_run(run: &Value) -> &[Value] {
    run["findings"].as_array().expect("policy run findings")
}

#[allow(dead_code)]
pub fn findings_from_single_run(report: &Value) -> &[Value] {
    let runs = report["runs"].as_array().expect("policy runs");
    assert_eq!(runs.len(), 1, "expected one policy run: {report}");
    findings_from_run(&runs[0])
}

#[allow(dead_code)]
pub fn parse_json_stdout(output: &Output, failure_context: &str) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{failure_context}: {error}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[allow(dead_code)]
pub fn run_for_policy_id<'a>(report: &'a Value, policy_id: &str) -> &'a Value {
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

#[allow(dead_code)]
pub fn assert_mcp_policy_abstains(structured: &Value) {
    assert_eq!(structured["exit_status"], 2, "{structured}");
    assert_ne!(structured["status"], "clean", "{structured}");
    let run = &structured["report"]["runs"][0];
    assert_eq!(run["completion"]["type"], "inconclusive", "{run}");
    assert!(
        run["findings"]
            .as_array()
            .expect("findings array")
            .is_empty(),
        "an open effect set has no positive finding: {run}"
    );
    let obligations = run["obligations"].as_array().expect("obligations array");
    assert_eq!(obligations.len(), 1, "{run}");
    assert_eq!(
        obligations[0]["kind"],
        "absence_requires_exhaustive_coverage"
    );
}
