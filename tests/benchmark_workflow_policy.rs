use std::fs;
use std::path::PathBuf;

fn checked_in_workflow() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(".github")
        .join("workflows")
        .join("benchmark.yml");
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn step_position(workflow: &str, name: &str) -> usize {
    workflow
        .find(name)
        .unwrap_or_else(|| panic!("workflow is missing step `{name}`"))
}

#[test]
fn benchmark_workflow_enforces_actionable_regressions_by_default() {
    let workflow = checked_in_workflow();

    assert!(workflow.contains("  schedule:\n"));
    assert!(workflow.contains("  workflow_dispatch:\n"));
    assert!(!workflow.contains("  push:\n"));
    assert!(!workflow.contains("  pull_request:\n"));

    let strict_input = workflow
        .split_once("      strict_compare:\n")
        .and_then(|(_, rest)| {
            rest.split_once("\n\npermissions:")
                .map(|(strict_input, _)| strict_input)
        })
        .expect("workflow should define the strict_compare dispatch input");
    assert!(
        strict_input.contains("        default: true\n"),
        "strict_compare must default to enforcement"
    );
    assert!(
        workflow.contains(
            "      BENCHMARK_REPO: ${{ inputs.repo || '' }}\n      BENCHMARK_MAX_FILES: ${{ inputs.max_files || '' }}"
        ),
        "manual string inputs must enter the workflow through environment variables"
    );
    assert!(
        workflow.contains(
            "if [ -n \"$BENCHMARK_REPO\" ]; then\n            args+=(--repo \"$BENCHMARK_REPO\")"
        ),
        "the benchmark repo input must be shell-quoted after environment-variable expansion"
    );
    assert!(
        workflow.contains(
            "if [ -n \"$BENCHMARK_MAX_FILES\" ]; then\n            args+=(--max-files \"$BENCHMARK_MAX_FILES\")"
        ),
        "the max-files input must be shell-quoted after environment-variable expansion"
    );
    assert!(
        workflow.contains(
            "--arg repo_input \"$BENCHMARK_REPO\" \\\n              --arg max_files_input \"$BENCHMARK_MAX_FILES\""
        ),
        "Slack payload creation must consume the safe environment variables"
    );
    assert!(!workflow.contains("args+=(--repo \"${{ inputs.repo }}\")"));
    assert!(!workflow.contains("args+=(--max-files \"${{ inputs.max_files }}\")"));
    assert!(!workflow.contains("--arg repo_input \"${{ inputs.repo || '' }}\""));
    assert!(!workflow.contains("--arg max_files_input \"${{ inputs.max_files || '' }}\""));

    assert!(
        workflow.contains(
            "effective_strict_compare=\"true\"\n          if [ \"${{ github.event_name }}\" = \"workflow_dispatch\" ]; then\n            effective_strict_compare=\"${{ inputs.strict_compare }}\"\n          fi\n          echo \"effective_strict_compare=${effective_strict_compare}\" >> \"$GITHUB_OUTPUT\""
        ),
        "schedule and dispatch policy must produce one effective strictness output"
    );
    assert!(
        workflow.contains(
            "if [ \"${{ steps.paths.outputs.effective_strict_compare }}\" = \"true\" ]; then\n            args+=(--strict)"
        ),
        "compare must use the centralized strictness output"
    );
    assert!(
        workflow.contains("strict_compare=\"${{ steps.paths.outputs.effective_strict_compare }}\""),
        "Slack must report the centralized strictness output"
    );

    let compare = step_position(&workflow, "      - name: Compare against blessed baseline");
    let artifacts = step_position(&workflow, "      - name: Upload benchmark artifacts");
    let summary = step_position(&workflow, "      - name: Publish benchmark summary");
    let slack = step_position(
        &workflow,
        "      - name: Send benchmark data to Slack Workflow",
    );
    let enforcement = step_position(&workflow, "      - name: Enforce benchmark outcome");
    assert!(workflow[compare..artifacts].contains("continue-on-error: true"));
    assert!(compare < artifacts && artifacts < summary && summary < slack && slack < enforcement);
    assert!(
        workflow[enforcement..]
            .contains("if [ \"${{ steps.compare.outcome }}\" = \"failure\" ]; then"),
        "the final gate must enforce a failed strict comparison"
    );
}
