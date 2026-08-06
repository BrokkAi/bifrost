use std::fs;
use std::path::PathBuf;

use brokk_bifrost::policy::{
    HumanRenderColor, HumanRenderDetail, HumanRenderOptions, PolicyEvaluationDate,
    PolicyEvaluationOptions, PolicyRenderError, PolicyRunCompletion, evaluate_policy_files,
    write_policy_human, write_policy_json,
};
use serde_json::{Value, json};

const MATCH_POLICY: &str = r#"(policy
  :schema-version 1
  :id "test.render"
  :name "Render test"
  :message "Avoid target"
  :severity warning
  :analysis
    (analysis
      :type match
      :selector
        (rql :schema-version 1
          (language typescript (function :name "target")))))"#;

fn evaluation_options() -> PolicyEvaluationOptions {
    PolicyEvaluationOptions::new(
        PolicyEvaluationDate::from_ymd(2026, 7, 27).expect("fixed test date"),
    )
}

fn workspace(source: &str, policy_name: &str, policy: &str) -> tempfile::TempDir {
    let workspace = tempfile::tempdir().expect("temporary workspace");
    fs::create_dir_all(workspace.path().join("policies")).expect("policy directory");
    fs::write(workspace.path().join("app.ts"), source).expect("source fixture");
    fs::write(workspace.path().join("policies").join(policy_name), policy).expect("policy fixture");
    workspace
}

fn evaluate(
    workspace: &tempfile::TempDir,
    policy_name: &str,
) -> brokk_bifrost::policy::PolicyBatchOutcome {
    evaluate_policy_files(
        workspace.path(),
        &[PathBuf::from("policies").join(policy_name)],
        &evaluation_options(),
    )
    .expect("coordinated policy evaluation")
}

fn write_suppression(
    workspace: &tempfile::TempDir,
    policy_id: &str,
    policy_hash: &str,
    finding_id: &str,
) {
    let path = workspace.path().join(".bifrost/suppressions.json");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        path,
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "suppressions": [{
                "policy_id": policy_id,
                "finding_id": finding_id,
                "identity_stability": "strong",
                "status": "accepted",
                "reason": "Reviewed compatibility boundary",
                "policy_hash_at_acceptance": policy_hash,
                "accepted_by": "security-review",
                "accepted_at": "2026-07-01",
                "expires_at": "2026-07-27"
            }]
        }))
        .unwrap(),
    )
    .unwrap();
}

#[test]
fn suppressions_hide_only_concise_results_and_keep_verbose_json_audit() {
    let workspace = workspace(
        "export function target() { return 1; }\n",
        "render.rqlp",
        MATCH_POLICY,
    );
    let baseline = evaluate(&workspace, "render.rqlp");
    let rule = &baseline.report().rules()[0];
    let finding = &baseline.report().runs()[0].findings()[0];
    write_suppression(
        &workspace,
        rule.policy_id().as_str(),
        &rule.policy_hash().to_string(),
        &finding.id().to_string(),
    );

    let suppressed = evaluate(&workspace, "render.rqlp");
    let mut concise = Vec::new();
    write_policy_human(
        suppressed.report(),
        &HumanRenderOptions::default(),
        &mut concise,
        usize::MAX,
    )
    .unwrap();
    let concise = String::from_utf8(concise).unwrap();
    assert!(!concise.contains("Avoid target"));
    assert_eq!(
        concise,
        "summary: 0 active findings; 1 suppressed finding; 1 complete policy run; clean\n"
    );

    let mut verbose = Vec::new();
    write_policy_human(
        suppressed.report(),
        &HumanRenderOptions::new(HumanRenderDetail::Verbose, HumanRenderColor::Plain),
        &mut verbose,
        usize::MAX,
    )
    .unwrap();
    let verbose = String::from_utf8(verbose).unwrap();
    assert!(verbose.contains("test.render: Avoid target"));
    assert!(verbose.contains("  suppression: accepted (policy hash matching)\n"));
    assert!(verbose.contains("  suppression reason: Reviewed compatibility boundary\n"));
    assert!(verbose.contains("  accepted: 2026-07-01 by security-review\n"));
    assert!(verbose.contains("  expires: 2026-07-27\n"));
    assert!(!verbose.contains("suppression review:"));

    let mut json_bytes = Vec::new();
    write_policy_json(suppressed.report(), &mut json_bytes, usize::MAX).unwrap();
    let json: Value = serde_json::from_slice(&json_bytes).unwrap();
    assert_eq!(
        json["runs"][0]["findings"][0]["suppression"]["status"],
        "accepted"
    );
    assert_eq!(json["suppressions"][0]["applied"], true);
    assert_eq!(json["suppressions"][0]["result_omitted"], false);

    fs::write(
        workspace.path().join("app.ts"),
        "export function other() { return 1; }\n",
    )
    .unwrap();
    let stale = evaluate(&workspace, "render.rqlp");
    let mut verbose = Vec::new();
    write_policy_human(
        stale.report(),
        &HumanRenderOptions::new(HumanRenderDetail::Verbose, HumanRenderColor::Plain),
        &mut verbose,
        usize::MAX,
    )
    .unwrap();
    let verbose = String::from_utf8(verbose).unwrap();
    assert!(verbose.contains("suppression review: test.render finding "));
    assert!(verbose.contains("disposition: match finding absent; temporal current; policy hash matching; applied no; stale yes; result omitted no"));
    assert!(verbose.ends_with("; 1 stale suppression review; 1 complete policy run; clean\n"));

    fs::write(
        workspace.path().join("app.ts"),
        "export function target() { return 1; }\n",
    )
    .unwrap();
    let expired = evaluate_policy_files(
        workspace.path(),
        &[PathBuf::from("policies/render.rqlp")],
        &PolicyEvaluationOptions::new("2026-07-28".parse().unwrap()),
    )
    .unwrap();
    let mut concise = Vec::new();
    write_policy_human(
        expired.report(),
        &HumanRenderOptions::default(),
        &mut concise,
        usize::MAX,
    )
    .unwrap();
    let concise = String::from_utf8(concise).unwrap();
    assert!(concise.contains("Avoid target"));
    assert!(concise.ends_with(
        "summary: 1 active finding; 0 suppressed findings; 1 expired suppression review; 1 complete policy run\n"
    ));
}

#[test]
fn concise_verbose_and_json_render_the_same_complete_finding_deterministically() {
    let workspace = workspace(
        "export function target() { return 1; }\n",
        "render.rqlp",
        MATCH_POLICY,
    );
    let outcome = evaluate(&workspace, "render.rqlp");
    assert_eq!(outcome.report().runs().len(), 1);
    assert_eq!(outcome.report().runs()[0].findings().len(), 1);
    let finding_id = outcome.report().runs()[0].findings()[0].id().to_string();

    let mut human_first = Vec::new();
    let human_bytes = write_policy_human(
        outcome.report(),
        &HumanRenderOptions::default(),
        &mut human_first,
        usize::MAX,
    )
    .expect("human report");
    let mut human_second = Vec::new();
    write_policy_human(
        outcome.report(),
        &HumanRenderOptions::default(),
        &mut human_second,
        usize::MAX,
    )
    .expect("second human report");
    assert_eq!(human_first, human_second);
    assert_eq!(usize::try_from(human_bytes).unwrap(), human_first.len());
    let human = String::from_utf8(human_first).unwrap();
    assert!(human.starts_with("[warning]  app.ts:1:8\n    Avoid target\n\n"));
    assert!(!human.contains(&finding_id));
    assert!(!human.contains("  evidence:"));
    assert!(!human.contains("policy rule:"));
    assert!(
        human
            .ends_with("summary: 1 active finding; 0 suppressed findings; 1 complete policy run\n")
    );
    assert!(!human.contains('\u{001B}'));

    let verbose_options =
        HumanRenderOptions::new(HumanRenderDetail::Verbose, HumanRenderColor::Plain);
    let mut verbose = Vec::new();
    write_policy_human(outcome.report(), &verbose_options, &mut verbose, usize::MAX)
        .expect("verbose human report");
    let verbose = String::from_utf8(verbose).unwrap();
    assert!(verbose.starts_with("app.ts:1:8: [warning] test.render: Avoid target\n"));
    assert!(verbose.contains(&format!("  finding: {finding_id} (strong)")));
    assert!(verbose.contains("  analysis: match (definite, complete)"));
    assert!(verbose.contains("  evidence: structural_match function\n"));
    assert!(verbose.contains("  match anchor: strong structural_match app.ts\n"));
    assert!(verbose.contains("  match terminal: structural_match function; identity "));
    assert!(verbose.contains("  proof reason: direct_structural_match\n"));
    assert!(verbose.contains("  classification: unclassified\n"));
    assert!(verbose.contains("policy rule: test.render (Render test)\n"));
    assert!(verbose.contains("  policy schema: 1 (explicit)\n"));
    assert!(verbose.contains("  selector schema "));
    assert!(verbose.contains("  endpoint dependencies: none\n"));
    assert!(verbose.contains("  precedence: none\n"));
    assert!(verbose.contains("  message: static - Avoid target\n"));
    assert!(verbose.contains("  severity: fixed warning\n"));
    assert!(!verbose.contains(" detail: {"));
    assert!(verbose.lines().all(|line| line.len() <= 240));
    assert!(
        verbose
            .ends_with("summary: 1 active finding; 0 suppressed findings; 1 complete policy run\n")
    );

    let ansi_options = HumanRenderOptions::new(HumanRenderDetail::Concise, HumanRenderColor::Ansi);
    let mut ansi = Vec::new();
    write_policy_human(outcome.report(), &ansi_options, &mut ansi, usize::MAX)
        .expect("ANSI human report");
    let ansi = String::from_utf8(ansi).unwrap();
    assert!(ansi.starts_with("\u{001B}[33m⚠\u{001B}[0m  app.ts:1:8\n"));

    let mut json_first = Vec::new();
    let json_bytes = write_policy_json(outcome.report(), &mut json_first, usize::MAX)
        .expect("canonical JSON report");
    let mut json_second = Vec::new();
    write_policy_json(outcome.report(), &mut json_second, usize::MAX)
        .expect("second canonical JSON report");
    assert_eq!(json_first, json_second);
    assert_eq!(usize::try_from(json_bytes).unwrap(), json_first.len());
    let json: Value = serde_json::from_slice(&json_first).expect("valid JSON");
    assert_eq!(json["schema_version"], 3);
    assert_eq!(json["rules"][0]["policy_id"], "test.render");
    assert_eq!(json["runs"][0]["findings"][0]["id"], finding_id);
    assert_eq!(
        json["runs"][0]["findings"][0]["evidence"]["evidence"]["terminal"]["type"],
        "structural_match"
    );
    assert_eq!(
        json["runs"][0]["findings"][0]["evidence"]["evidence"]["terminal"]["kind"],
        "function"
    );
    assert_eq!(json["runs"][0]["completion"]["type"], "complete");
}

#[test]
fn typestate_run_renders_findings_and_completion() {
    let fixture_root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/policy-cli/project");
    let outcome = evaluate_policy_files(
        &fixture_root,
        &[PathBuf::from("policies/resource-lifecycle.rqlp")],
        &evaluation_options(),
    )
    .expect("coordinated typestate policy evaluation");
    assert_eq!(outcome.report().runs().len(), 1);
    assert_eq!(outcome.report().runs()[0].findings().len(), 1);
    assert!(matches!(
        outcome.report().runs()[0].completion(),
        PolicyRunCompletion::Inconclusive { .. }
    ));

    let mut rendered = Vec::new();
    write_policy_human(
        outcome.report(),
        &HumanRenderOptions::default(),
        &mut rendered,
        usize::MAX,
    )
    .expect("human report");
    let rendered = String::from_utf8(rendered).unwrap();
    assert_eq!(
        rendered
            .matches("Resource can leave its analysis root without being closed")
            .count(),
        1
    );
    assert!(rendered.contains(
        "summary: 1 active finding; 0 suppressed findings; 1 inconclusive policy run; non-clean"
    ));
}

#[test]
fn human_complete_empty_and_invalid_reports_are_explicitly_clean_and_non_clean() {
    let clean_workspace = workspace(
        "export function other() { return 1; }\n",
        "clean.rqlp",
        MATCH_POLICY,
    );
    let clean = evaluate(&clean_workspace, "clean.rqlp");
    let mut human = Vec::new();
    write_policy_human(
        clean.report(),
        &HumanRenderOptions::default(),
        &mut human,
        usize::MAX,
    )
    .unwrap();
    let human = String::from_utf8(human).unwrap();
    assert!(!human.contains("policy rule: test.render (Render test)\n"));
    assert!(!human.contains(" detail: {"));
    assert!(human.ends_with(
        "summary: 0 active findings; 0 suppressed findings; 1 complete policy run; clean\n"
    ));

    let invalid_workspace = workspace(
        "export function other() { return 1; }\n",
        "invalid.rqlp",
        "(policy :id)",
    );
    let invalid = evaluate(&invalid_workspace, "invalid.rqlp");
    assert!(!invalid.report().diagnostics().is_empty());
    let mut human = Vec::new();
    write_policy_human(
        invalid.report(),
        &HumanRenderOptions::default(),
        &mut human,
        usize::MAX,
    )
    .unwrap();
    let human = String::from_utf8(human).unwrap();
    // `(policy :id)` is valid S-expression syntax but violates the policy
    // schema, so it must remain distinguishable from a source parse failure.
    assert!(human.contains("report diagnostic: [error] policy-validation-failed:"));
    assert!(human.ends_with(
        "summary: 0 active findings; 0 suppressed findings; 0 policy runs; non-clean\n"
    ));
}

#[test]
fn encoded_bounds_apply_after_terminal_and_json_escaping() {
    let unsafe_name = "bad\n\u{001B}\u{007F}\u{0085}\u{202e}\u{2066}.rqlp";
    let workspace = workspace(
        "export function other() { return 1; }\n",
        "safe.rqlp",
        MATCH_POLICY,
    );
    let outcome = evaluate_policy_files(
        workspace.path(),
        &[PathBuf::from("policies").join(unsafe_name)],
        &evaluation_options(),
    )
    .expect("missing unsafe requested path becomes a report diagnostic");

    let mut human = Vec::new();
    let human_size = write_policy_human(
        outcome.report(),
        &HumanRenderOptions::default(),
        &mut human,
        usize::MAX,
    )
    .unwrap();
    let human_text = String::from_utf8(human).unwrap();
    assert!(human_text.contains("invalid-source:sha256:"));
    assert!(!human_text.contains("bad"));
    let human_limit = usize::try_from(human_size).unwrap() - 1;
    let mut bounded_human = Vec::new();
    assert!(matches!(
        write_policy_human(
            outcome.report(),
            &HumanRenderOptions::default(),
            &mut bounded_human,
            human_limit,
        ),
        Err(PolicyRenderError::SerializedReportLimit {
            max_serialized_bytes
        }) if max_serialized_bytes == human_limit
    ));
    assert!(bounded_human.len() <= human_limit);

    let mut json = Vec::new();
    let json_size = write_policy_json(outcome.report(), &mut json, usize::MAX).unwrap();
    let json_text = String::from_utf8(json).unwrap();
    assert!(json_text.contains("invalid-source:sha256:"));
    assert!(!json_text.contains("bad"));
    let json_limit = usize::try_from(json_size).unwrap() - 1;
    let mut bounded_json = Vec::new();
    assert!(matches!(
        write_policy_json(outcome.report(), &mut bounded_json, json_limit),
        Err(PolicyRenderError::SerializedReportLimit {
            max_serialized_bytes
        }) if max_serialized_bytes == json_limit
    ));
    assert!(bounded_json.len() <= json_limit);
}
