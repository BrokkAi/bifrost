use std::fs;
use std::path::PathBuf;

use brokk_bifrost::policy::{
    HumanRenderColor, HumanRenderDetail, HumanRenderOptions, PolicyFailOn, PolicyRenderError,
    evaluate_policy_files, write_policy_human, write_policy_json,
};
use serde_json::Value;

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
        (rql :schema-version 2
          (language typescript (function :name "target")))))"#;

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
        false,
        PolicyFailOn::Never,
    )
    .expect("coordinated policy evaluation")
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
    assert!(human.ends_with("summary: 1 finding; 1 complete policy run\n"));
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
    assert!(verbose.ends_with("summary: 1 finding; 1 complete policy run\n"));

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
    assert_eq!(json["schema_version"], 1);
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
fn unsupported_typestate_run_names_the_policy_and_compilation_capability() {
    let fixture_root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/policy-cli/project");
    let outcome = evaluate_policy_files(
        &fixture_root,
        &[PathBuf::from("policies/resource-lifecycle.rqlp")],
        false,
        PolicyFailOn::Never,
    )
    .expect("coordinated typestate policy evaluation");

    let mut rendered = Vec::new();
    write_policy_human(
        outcome.report(),
        &HumanRenderOptions::default(),
        &mut rendered,
        usize::MAX,
    )
    .expect("human report");
    let rendered = String::from_utf8(rendered).unwrap();
    assert!(rendered.contains(
        "policy bifrost.test.resource-lifecycle (Resource lifecycle): unsupported: typestate policy compilation; non-clean"
    ));
    assert!(!rendered.contains("; clean"));
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
    assert!(human.ends_with("summary: 0 findings; 1 complete policy run; clean\n"));

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
    assert!(human.ends_with("summary: 0 findings; 0 policy runs; non-clean\n"));
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
        false,
        PolicyFailOn::Never,
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
