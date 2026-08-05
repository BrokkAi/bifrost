use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Instant;

use serde_json::Value;

use crate::common::{BuiltInlineTestProject, InlineTestProject};

const APP: &str = include_str!("../fixtures/policy-cli/project/src/app.py");
const RESOURCE_SOURCE: &str = include_str!("../fixtures/policy-cli/project/src/resource.ts");
const CROSS_LANGUAGE_TYPESCRIPT_RESOURCE_SOURCE: &str = r#"interface Resource {}

function openResource(): Resource {
  return {};
}

function closeResource(resource: Resource): void {}

export function leaksResource(): void {
  const resource = openResource();
}
"#;
const JAVA_RESOURCE_SOURCE: &str = r#"class Resource {}

class ResourceLifecycle {
  static Resource openResource() {
    return null;
  }

  static void closeResource(Resource resource) {}

  static void leaksResource() {
    Resource resource = ResourceLifecycle.openResource();
  }
}
"#;
const DYNAMIC: &str = include_str!("../fixtures/policy-cli/project/policies/dynamic-eval.rqlp");
const INFERRED: &str =
    include_str!("../fixtures/policy-cli/project/policies/inferred-dynamic-eval.rqlp");
const NO_EXEC: &str = include_str!("../fixtures/policy-cli/project/policies/no-exec.rqlp");
const RESOURCE: &str =
    include_str!("../fixtures/policy-cli/project/policies/resource-lifecycle.rqlp");
const UNRATED: &str = include_str!("../fixtures/policy-cli/project/policies/unrated-eval.rqlp");
const NOTE: &str = include_str!("../fixtures/policy-cli/project/policies/note-eval.rqlp");
const HTTP_ENDPOINT: &str =
    include_str!("../fixtures/policy-cli/project/policies/endpoints/http-request-parameter.rqlp");
const ACQUIRE_ENDPOINT: &str =
    include_str!("../fixtures/policy-cli/project/policies/endpoints/resource-acquire.rqlp");
const INFERRED_ACQUIRE_ENDPOINT: &str =
    include_str!("../fixtures/policy-cli/overrides/resource-acquire-inferred.rqlp");
const CLOSE_ENDPOINT: &str =
    include_str!("../fixtures/policy-cli/project/policies/endpoints/resource-close.rqlp");
const CROSS_LANGUAGE_ACQUIRE_ENDPOINT: &str = r#"(endpoint
  :schema-version 1
  :id "bifrost.resources.acquire"
  :name "Resource acquisition"
  :display-name "acquired resource"
  :role source
  :categories [resource.lifecycle resource.acquire]
  :selector
    (rql
      :schema-version 2
      (union
        (language typescript (call :callee (name "openResource")))
        (language java (call :callee (name "openResource")))))
  :binding return-value
  :supersedes [])"#;
const CROSS_LANGUAGE_CLOSE_ENDPOINT: &str = r#"(endpoint
  :schema-version 1
  :id "bifrost.resources.close"
  :name "Resource close"
  :display-name "resource close"
  :role sink
  :categories [resource.lifecycle resource.close]
  :selector
    (rql
      :schema-version 2
      (union
        (language typescript (call :callee (name "closeResource")))
        (language java (call :callee (name "closeResource")))))
  :binding (argument :index 0)
  :supersedes [])"#;
const DOMINANT_CLOSE_ENDPOINT: &str = r#"(endpoint
  :schema-version 1
  :id "bifrost.resources.close-dominant"
  :name "Dominant resource close"
  :display-name "dominant resource close"
  :role sink
  :categories [resource.lifecycle resource.close]
  :selector
    (rql
      :schema-version 2
      (language typescript
        (call :callee (name "closeResource"))))
  :binding (argument :index 0)
  :supersedes [bifrost.resources.close])"#;
const DOMINANT_ACQUIRE_ENDPOINT: &str = r#"(endpoint
  :schema-version 1
  :id "bifrost.resources.acquire-dominant"
  :name "Dominant resource acquisition"
  :display-name "dominant acquired resource"
  :role source
  :categories [resource.lifecycle resource.acquire]
  :selector
    (rql
      :schema-version 2
      (language typescript
        (call :callee (name "openResource"))))
  :binding return-value
  :supersedes [bifrost.resources.acquire])"#;
const DOMINANCE_SOURCE: &str = r#"class Resource {}

function openResource(): Resource {
  return new Resource();
}

function closeResource(resource: Resource): void {}

export function closesResource(): void {
  const resource = openResource();
  closeResource(resource);
}
"#;
const EXIT_EVENT_POLICY: &str = r#"(policy
  :schema-version 1
  :id "bifrost.test.resource-exit-event"
  :name "Resource exit event"
  :message "Resource reached the analysis-root exit"
  :severity error
  :analysis
    (analysis
      :type typestate
      :mode may
      :subjects
        (subject-set
          :include-matches [
            (match-directory
              :path "policies/endpoints"
              :scope recursive
              :categories (all [resource.acquire]))]
          :entries [])
      :uncertainty
        (uncertainty
          :escape inconclusive)
      :automaton
        (automaton
          :states [open violated]
          :initial open
          :accepting-states [open]
          :error-states [violated]
          :events [
            (event
              :id finish
              :on (normal-procedure-exit :scope analysis-root)
              :supersedes [])]
          :transitions [
            (transition :from open :on finish :to violated)]
          :terminal-expectations [])))"#;

fn policy_project(extra: &[(&str, String)]) -> BuiltInlineTestProject {
    let mut project = InlineTestProject::new()
        .file("src/app.py", APP)
        .file("src/resource.ts", RESOURCE_SOURCE)
        .file("policies/dynamic-eval.rqlp", DYNAMIC)
        .file("policies/inferred-dynamic-eval.rqlp", INFERRED)
        .file("policies/no-exec.rqlp", NO_EXEC)
        .file("policies/resource-lifecycle.rqlp", RESOURCE)
        .file("policies/unrated-eval.rqlp", UNRATED)
        .file("policies/note-eval.rqlp", NOTE)
        .file(
            "policies/endpoints/http-request-parameter.rqlp",
            HTTP_ENDPOINT,
        )
        .file("policies/endpoints/resource-acquire.rqlp", ACQUIRE_ENDPOINT)
        .file("policies/endpoints/resource-close.rqlp", CLOSE_ENDPOINT);
    for (path, source) in extra {
        project = project.file(*path, source.clone());
    }
    project.build()
}

fn resource_policy_project(path: &str, source: &str) -> BuiltInlineTestProject {
    InlineTestProject::new()
        .file(path, source)
        .file("policies/resource-lifecycle.rqlp", RESOURCE)
        .file(
            "policies/endpoints/resource-acquire.rqlp",
            CROSS_LANGUAGE_ACQUIRE_ENDPOINT,
        )
        .file(
            "policies/endpoints/resource-close.rqlp",
            CROSS_LANGUAGE_CLOSE_ENDPOINT,
        )
        .build()
}

fn repeated_java_resource_policy_project(copy: String) -> BuiltInlineTestProject {
    InlineTestProject::new()
        .file("src/ResourceLifecycle.java", JAVA_RESOURCE_SOURCE)
        .file("policies/resource-lifecycle.rqlp", RESOURCE)
        .file("policies/resource-lifecycle-copy.rqlp", copy)
        .file(
            "policies/endpoints/resource-acquire.rqlp",
            CROSS_LANGUAGE_ACQUIRE_ENDPOINT,
        )
        .file(
            "policies/endpoints/resource-close.rqlp",
            CROSS_LANGUAGE_CLOSE_ENDPOINT,
        )
        .build()
}

fn bifrost(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bifrost"));
    command
        .arg("--root")
        .arg(root)
        .env("BIFROST_PARALLELISM", "1");
    command
}

fn run(root: &Path, args: &[&str]) -> Output {
    bifrost(root)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to run bifrost {args:?}: {error}"))
}

fn assert_status(output: &Output, expected: i32) {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn json_stdout(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid JSON stdout: {error}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
    })
}

fn assert_single_terminal_safe_line(output: &Output) {
    let stderr = String::from_utf8(output.stderr.clone()).expect("UTF-8 stderr");
    assert_eq!(stderr.matches('\n').count(), 1, "{stderr:?}");
    for character in ['\u{001B}', '\u{202E}', '\u{2066}'] {
        assert!(
            !stderr.contains(character),
            "raw {character:?} in {stderr:?}"
        );
    }
    for escaped in ["\\u{A}", "\\u{1B}", "\\u{202E}", "\\u{2066}"] {
        assert!(stderr.contains(escaped), "missing {escaped} in {stderr:?}");
    }
}

#[test]
fn built_in_policy_catalog_lists_without_constructing_a_workspace() {
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--list-policies")
        .output()
        .expect("run policy listing");
    assert_status(&output, 0);
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);
    let manifest = json_stdout(&output);
    assert_eq!(manifest["id"], "bifrost.code-smells");
    assert_eq!(manifest["policies"].as_array().map(Vec::len), Some(12));
    assert_eq!(
        manifest["policies"][0]["id"],
        "bifrost.correctness.dynamic-evaluation"
    );
}

#[test]
fn built_in_and_workspace_policies_run_in_one_batch() {
    let project = policy_project(&[]);
    let output = run(
        project.root(),
        &[
            "--policy-id",
            "bifrost.correctness.dynamic-evaluation",
            "--policy-file",
            "policies/no-exec.rqlp",
            "--evaluation-date",
            "2026-07-28",
            "--fail-on",
            "never",
            "--format",
            "json",
        ],
    );
    assert_status(&output, 0);
    let report = json_stdout(&output);
    let policy_ids = report["runs"]
        .as_array()
        .expect("policy runs")
        .iter()
        .map(|run| run["policy_id"].as_str().expect("policy id"))
        .collect::<Vec<_>>();
    assert_eq!(
        policy_ids,
        vec![
            "bifrost.correctness.dynamic-evaluation",
            "bifrost.security.no-exec"
        ]
    );
}

#[test]
fn built_in_pack_and_category_selectors_run_valid_batches() {
    let project = policy_project(&[]);
    let category = run(
        project.root(),
        &[
            "--policy-category",
            "correctness",
            "--evaluation-date",
            "2026-07-28",
            "--fail-on",
            "never",
            "--format",
            "json",
        ],
    );
    assert_status(&category, 0);
    let category_report = json_stdout(&category);
    let category_ids = category_report["runs"]
        .as_array()
        .expect("category runs")
        .iter()
        .map(|run| run["policy_id"].as_str().expect("category policy id"))
        .collect::<Vec<_>>();
    assert_eq!(
        category_ids,
        vec![
            "bifrost.correctness.dynamic-evaluation",
            "bifrost.correctness.unsafe-deserialization"
        ]
    );

    let pack = run(
        project.root(),
        &[
            "--policy-pack",
            "bifrost.code-smells",
            "--evaluation-date",
            "2026-07-28",
            "--fail-on",
            "never",
            "--format",
            "json",
        ],
    );
    assert_status(&pack, 0);
    let pack_report = json_stdout(&pack);
    let pack_ids = pack_report["runs"]
        .as_array()
        .expect("pack runs")
        .iter()
        .map(|run| run["policy_id"].as_str().expect("pack policy id"))
        .collect::<Vec<_>>();
    assert_eq!(
        pack_ids,
        vec![
            "bifrost.correctness.dynamic-evaluation",
            "bifrost.correctness.unsafe-deserialization",
            "bifrost.performance.database-call-in-loop",
            "bifrost.performance.expensive-operation-in-nested-loop",
            "bifrost.performance.file-read-in-loop",
            "bifrost.performance.network-call-in-loop",
            "bifrost.performance.parsing-in-loop",
            "bifrost.performance.regex-compile-in-loop",
            "bifrost.performance.serialization-in-loop",
            "bifrost.performance.sleep-in-loop",
            "bifrost.performance.sort-in-loop",
            "bifrost.performance.subprocess-in-loop",
        ]
    );
}

#[test]
fn unknown_built_in_selector_is_a_policy_invocation_error() {
    let project = policy_project(&[]);
    let output = run(
        project.root(),
        &["--policy-pack", "bifrost.missing", "--format", "json"],
    );
    assert_status(&output, 2);
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("unknown built-in policy pack `bifrost.missing`")
    );
}

#[test]
fn thresholds_cover_clean_rated_and_unrated_findings() {
    let project = policy_project(&[]);
    let cases: &[(&[&str], i32)] = &[
        (&["--policy-file", "policies/no-exec.rqlp"], 0),
        (
            &[
                "--policy-file",
                "policies/dynamic-eval.rqlp",
                "--fail-on",
                "never",
            ],
            0,
        ),
        (
            &[
                "--policy-file",
                "policies/dynamic-eval.rqlp",
                "--fail-on",
                "warning",
            ],
            1,
        ),
        (
            &[
                "--policy-file",
                "policies/dynamic-eval.rqlp",
                "--fail-on",
                "error",
            ],
            0,
        ),
        (
            &[
                "--policy-file",
                "policies/note-eval.rqlp",
                "--fail-on",
                "note",
            ],
            1,
        ),
        (
            &[
                "--policy-file",
                "policies/note-eval.rqlp",
                "--fail-on",
                "warning",
            ],
            0,
        ),
        (
            &[
                "--policy-file",
                "policies/unrated-eval.rqlp",
                "--fail-on",
                "finding",
            ],
            1,
        ),
        (
            &[
                "--policy-file",
                "policies/unrated-eval.rqlp",
                "--fail-on",
                "note",
            ],
            0,
        ),
    ];
    for (args, expected) in cases {
        let output = run(project.root(), args);
        assert_status(&output, *expected);
    }

    let default = run(
        project.root(),
        &["--policy-file", "policies/dynamic-eval.rqlp"],
    );
    assert_status(&default, 1);
    let stdout = String::from_utf8(default.stdout).expect("UTF-8 human report");
    assert!(!stdout.contains('\u{001B}'));
    assert!(stdout.contains("[warning]  src/app.py:2:12\n"), "{stdout}");
    assert!(
        stdout.contains("    Dynamic evaluation is forbidden\n"),
        "{stdout}"
    );
    assert!(!stdout.contains("  evidence:"), "{stdout}");
    assert!(
        stdout.contains("summary: 1 active finding; 0 suppressed findings; 1 complete policy run")
    );

    let verbose = run(
        project.root(),
        &["--policy-file", "policies/dynamic-eval.rqlp", "--verbose"],
    );
    assert_status(&verbose, 1);
    let verbose = String::from_utf8(verbose.stdout).expect("UTF-8 verbose human report");
    assert!(verbose.contains("src/app.py:2:12: [warning] bifrost.security.dynamic-eval"));
    assert!(verbose.contains("  evidence: structural_match call\n"));

    let colored = run(
        project.root(),
        &[
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--color",
            "always",
        ],
    );
    assert_status(&colored, 1);
    assert!(
        colored
            .stdout
            .windows(5)
            .any(|window| window == b"\x1b[33m")
    );

    let no_color = bifrost(project.root())
        .args([
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--color",
            "auto",
        ])
        .env("NO_COLOR", "1")
        .output()
        .expect("run policy with NO_COLOR");
    assert_status(&no_color, 1);
    assert!(!no_color.stdout.contains(&0x1b));

    let never = run(
        project.root(),
        &[
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--color",
            "never",
        ],
    );
    assert_status(&never, 1);
    assert!(!never.stdout.contains(&0x1b));

    let verbose_colored = run(
        project.root(),
        &[
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--verbose",
            "--color",
            "always",
        ],
    );
    assert_status(&verbose_colored, 1);
    assert!(
        verbose_colored
            .stdout
            .windows(5)
            .any(|window| window == b"\x1b[33m")
    );
}

#[test]
fn policy_suppressions_are_deterministic_auditable_and_threshold_aware_across_formats() {
    let project = policy_project(&[]);
    let baseline = run(
        project.root(),
        &[
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--evaluation-date",
            "2026-07-27",
            "--format",
            "json",
            "--fail-on",
            "warning",
        ],
    );
    assert_status(&baseline, 1);
    let baseline = json_stdout(&baseline);
    let policy_id = baseline["rules"][0]["policy_id"].as_str().unwrap();
    let policy_hash = baseline["rules"][0]["policy_hash"].as_str().unwrap();
    let finding_id = baseline["runs"][0]["findings"][0]["id"].as_str().unwrap();
    let suppression = serde_json::json!({
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
    });
    let default_path = project.root().join(".bifrost/suppressions.json");
    fs::create_dir_all(default_path.parent().unwrap()).unwrap();
    fs::write(
        &default_path,
        serde_json::to_vec_pretty(&suppression).unwrap(),
    )
    .unwrap();
    let custom_path = project.root().join("reviews/accepted.json");
    fs::create_dir_all(custom_path.parent().unwrap()).unwrap();
    fs::write(
        &custom_path,
        serde_json::to_vec_pretty(&suppression).unwrap(),
    )
    .unwrap();

    let concise = run(
        project.root(),
        &[
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--evaluation-date",
            "2026-07-27",
            "--fail-on",
            "warning",
        ],
    );
    assert_status(&concise, 0);
    let concise = String::from_utf8(concise.stdout).unwrap();
    assert!(!concise.contains("Dynamic evaluation is forbidden"));
    assert_eq!(
        concise,
        "summary: 0 active findings; 1 suppressed finding; 1 complete policy run; clean\n"
    );

    let json_args = [
        "--policy-file",
        "policies/dynamic-eval.rqlp",
        "--suppressions-file",
        "reviews/accepted.json",
        "--evaluation-date",
        "2026-07-27",
        "--format",
        "json",
        "--fail-on",
        "warning",
    ];
    let first = run(project.root(), &json_args);
    let second = run(project.root(), &json_args);
    assert_status(&first, 0);
    assert_status(&second, 0);
    assert_eq!(first.stdout, second.stdout);
    let json = json_stdout(&first);
    assert_eq!(json["schema_version"], 3);
    assert_eq!(json["evaluation"]["evaluation_date"], "2026-07-27");
    assert_eq!(
        json["evaluation"]["suppression_path"],
        "reviews/accepted.json"
    );
    assert_eq!(json["runs"][0]["findings"][0]["id"], finding_id);
    assert_eq!(
        json["runs"][0]["findings"][0]["suppression"]["status"],
        "accepted"
    );
    assert_eq!(json["suppressions"][0]["applied"], true);

    let verbose = run(
        project.root(),
        &[
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--evaluation-date",
            "2026-07-27",
            "--verbose",
            "--fail-on",
            "warning",
        ],
    );
    assert_status(&verbose, 0);
    let verbose = String::from_utf8(verbose.stdout).unwrap();
    assert!(verbose.contains("Dynamic evaluation is forbidden"));
    assert!(verbose.contains("  suppression: accepted (policy hash matching)\n"));
    assert!(verbose.contains("  accepted: 2026-07-01 by security-review\n"));

    let sarif = run(
        project.root(),
        &[
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--evaluation-date",
            "2026-07-27",
            "--format",
            "sarif",
            "--fail-on",
            "warning",
        ],
    );
    assert_status(&sarif, 0);
    let sarif = json_stdout(&sarif);
    assert_eq!(
        sarif["runs"][0]["results"][0]["suppressions"][0]["kind"],
        "external"
    );
    assert_eq!(
        sarif["runs"][0]["results"][0]["partialFingerprints"]["bifrostFinding/v1"],
        finding_id
    );

    let expired = run(
        project.root(),
        &[
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--evaluation-date",
            "2026-07-28",
            "--fail-on",
            "warning",
        ],
    );
    assert_status(&expired, 1);
    let expired = String::from_utf8(expired.stdout).unwrap();
    assert!(expired.contains("Dynamic evaluation is forbidden"));
    assert!(expired.contains("1 expired suppression review"));

    fs::write(project.root().join("reviews/invalid.json"), b"not JSON\n").unwrap();
    let invalid = run(
        project.root(),
        &[
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--suppressions-file",
            "reviews/invalid.json",
            "--evaluation-date",
            "2026-07-27",
            "--format",
            "json",
            "--fail-on",
            "warning",
        ],
    );
    assert_status(&invalid, 2);
    let invalid = json_stdout(&invalid);
    assert_eq!(invalid["runs"][0]["findings"].as_array().unwrap().len(), 1);
    assert_eq!(invalid["diagnostics"][0]["code"], "suppression-load-failed");
}

#[test]
fn proven_subset_callers_are_visible_and_reliable_without_claiming_exhaustiveness() {
    let source = r#"class Smells {
    void terminate() { System.exit(1); }
    void directTerminate() { this.terminate(); }
    void secondOrderTerminate() { this.directTerminate(); }
}"#;
    let policy = |id: &str, completeness: &str| {
        format!(
            r#"(policy
  :id "{id}"
  :name "Proven callers"
  :message "Calls System.exit"
  :severity warning
  :analysis (analysis :type match :selector
    (rql (language java
      (callers :depth 2 :proof proven {completeness}
        (enclosing-decl
          (call :receiver (name "System") :callee (name "exit"))))))))"#
        )
    };
    let project = InlineTestProject::new()
        .file("src/Smells.java", source)
        .file(
            "policies/exhaustive.rqlp",
            policy("test.exhaustive-callers", ""),
        )
        .file(
            "policies/proven-subset.rqlp",
            policy("test.proven-subset-callers", ":completeness proven-subset"),
        )
        .build();

    let exhaustive = run(
        project.root(),
        &[
            "--policy-file",
            "policies/exhaustive.rqlp",
            "--format",
            "json",
        ],
    );
    assert_status(&exhaustive, 2);
    let exhaustive = json_stdout(&exhaustive);
    assert_eq!(exhaustive["runs"][0]["completion"]["type"], "inconclusive");

    let subset = run(
        project.root(),
        &[
            "--policy-file",
            "policies/proven-subset.rqlp",
            "--format",
            "json",
        ],
    );
    assert_status(&subset, 1);
    let subset = json_stdout(&subset);
    assert_eq!(subset["runs"][0]["completion"]["type"], "proven_subset");
    assert_eq!(subset["runs"][0]["findings"].as_array().unwrap().len(), 2);
    assert!(
        subset["runs"][0]["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| diagnostic["impact"] == "declared_non_exhaustive")
    );

    let human = run(
        project.root(),
        &["--policy-file", "policies/proven-subset.rqlp"],
    );
    assert_status(&human, 1);
    let human = String::from_utf8(human.stdout).expect("UTF-8 human report");
    assert!(
        human.contains("proven subset (not exhaustive; call_relation_candidates_omitted)"),
        "{human}"
    );
    assert!(human.contains("non-exhaustive"), "{human}");

    let sarif = run(
        project.root(),
        &[
            "--policy-file",
            "policies/proven-subset.rqlp",
            "--format",
            "sarif",
        ],
    );
    assert_status(&sarif, 1);
    let sarif = json_stdout(&sarif);
    assert_eq!(
        sarif["runs"][0]["invocations"][0]["executionSuccessful"],
        true
    );
    assert!(
        sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
            .as_array()
            .unwrap()
            .iter()
            .any(|notification| notification["descriptor"]["id"] == "BIFROST_POLICY_PROVEN_SUBSET"),
        "{sarif:#}"
    );

    let below_threshold = run(
        project.root(),
        &[
            "--policy-file",
            "policies/proven-subset.rqlp",
            "--fail-on",
            "error",
        ],
    );
    assert_status(&below_threshold, 2);
}

#[test]
fn strict_versions_endpoint_roots_and_typestate_execution_have_typed_statuses() {
    let project = policy_project(&[]);

    let inferred = run(
        project.root(),
        &[
            "--policy-file",
            "policies/inferred-dynamic-eval.rqlp",
            "--format",
            "json",
            "--require-explicit-schema-versions",
        ],
    );
    assert_status(&inferred, 2);
    let report = json_stdout(&inferred);
    assert!(report["rules"].as_array().unwrap().is_empty());
    assert!(report["runs"].as_array().unwrap().is_empty());
    let codes = report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|diagnostic| diagnostic["code"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(codes.contains(&"explicit-policy-schema-version-required"));
    assert!(codes.contains(&"explicit-rql-schema-version-required"));

    let accepted_inference = run(
        project.root(),
        &["--policy-file", "policies/inferred-dynamic-eval.rqlp"],
    );
    assert_status(&accepted_inference, 1);
    assert!(
        String::from_utf8_lossy(&accepted_inference.stdout)
            .contains(
                "policy bifrost.security.inferred-dynamic-eval inferred policy schema 1 and RQL schema 13"
            )
    );

    let endpoint = run(
        project.root(),
        &[
            "--policy-file",
            "policies/endpoints/http-request-parameter.rqlp",
        ],
    );
    assert_status(&endpoint, 2);
    assert!(String::from_utf8_lossy(&endpoint.stdout).contains("not-executable-endpoint"));

    let resource = run(
        project.root(),
        &[
            "--policy-file",
            "policies/resource-lifecycle.rqlp",
            "--format",
            "json",
        ],
    );
    assert_status(&resource, 2);
    let report = json_stdout(&resource);
    assert_eq!(report["rules"].as_array().unwrap().len(), 1);
    assert_eq!(report["runs"].as_array().unwrap().len(), 1);
    assert_eq!(
        report["rules"][0]["endpoint_dependencies"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(report["runs"][0]["completion"]["type"], "inconclusive");
    assert_eq!(
        report["runs"][0]["completion"]["reasons"],
        serde_json::json!(["partial_discovery"])
    );
    assert_eq!(report["runs"][0]["findings"].as_array().unwrap().len(), 1);
    for finding in report["runs"][0]["findings"].as_array().unwrap() {
        assert_eq!(finding["analysis_type"], "typestate");
        assert_eq!(finding["identity_stability"], "strong");
        assert!(!finding["related"].as_array().unwrap().is_empty());
        assert!(!finding["witnesses"].as_array().unwrap().is_empty());
    }

    let dependency_project = policy_project(&[(
        "policies/endpoints/resource-acquire.rqlp",
        INFERRED_ACQUIRE_ENDPOINT.to_string(),
    )]);
    let strict_dependency = run(
        dependency_project.root(),
        &[
            "--policy-file",
            "policies/resource-lifecycle.rqlp",
            "--format",
            "json",
            "--require-explicit-schema-versions",
        ],
    );
    assert_status(&strict_dependency, 2);
    let report = json_stdout(&strict_dependency);
    assert!(report["rules"].as_array().unwrap().is_empty());
    assert!(report["runs"].as_array().unwrap().is_empty());
    let dependency_diagnostics = report["diagnostics"].as_array().unwrap();
    assert!(dependency_diagnostics.iter().any(|diagnostic| {
        diagnostic["code"] == "explicit-policy-schema-version-required"
            && diagnostic["source"] == "policies/endpoints/resource-acquire.rqlp"
    }));
    assert!(dependency_diagnostics.iter().any(|diagnostic| {
        diagnostic["code"] == "explicit-rql-schema-version-required"
            && diagnostic["source"] == "policies/endpoints/resource-acquire.rqlp"
    }));
}

#[test]
fn json_sarif_stdout_and_atomic_file_output_are_deterministic() {
    let project = policy_project(&[]);
    let json_args = [
        "--policy-file",
        "policies/dynamic-eval.rqlp",
        "--format",
        "json",
        "--fail-on",
        "never",
    ];
    let first = run(project.root(), &json_args);
    let second = run(project.root(), &json_args);
    assert_status(&first, 0);
    assert_status(&second, 0);
    assert_eq!(first.stdout, second.stdout);
    let report = json_stdout(&first);
    assert_eq!(report["rules"].as_array().unwrap().len(), 1);
    assert_eq!(report["runs"][0]["findings"].as_array().unwrap().len(), 1);
    assert_eq!(report["runs"][0]["completion"]["type"], "complete");

    let sarif = run(
        project.root(),
        &[
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--format",
            "sarif",
            "--fail-on",
            "never",
        ],
    );
    assert_status(&sarif, 0);
    let sarif = json_stdout(&sarif);
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(sarif["runs"][0]["columnKind"], "unicodeCodePoints");
    assert_eq!(
        sarif["runs"][0]["invocations"][0]["executionSuccessful"],
        true
    );
    assert_eq!(
        sarif["runs"][0]["results"][0]["ruleId"],
        "bifrost.security.dynamic-eval"
    );

    let destination = tempfile::tempdir().expect("output directory");
    let output_path = destination.path().join("report.json");
    let written = bifrost(project.root())
        .args(json_args)
        .arg("--output")
        .arg(&output_path)
        .output()
        .expect("write policy JSON");
    assert_status(&written, 0);
    assert!(written.stdout.is_empty());
    assert_eq!(fs::read(&output_path).unwrap(), first.stdout);
}

#[test]
fn policy_id_order_is_stable_and_duplicate_roots_are_all_excluded() {
    let duplicate = DYNAMIC.replace(
        ":name \"No dynamic evaluation\"",
        ":name \"Duplicate dynamic evaluation\"",
    );
    let project = policy_project(&[("policies/duplicate.rqlp", duplicate)]);

    let first = run(
        project.root(),
        &[
            "--policy-file",
            "policies/note-eval.rqlp",
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--format",
            "json",
            "--fail-on",
            "never",
        ],
    );
    let reversed = run(
        project.root(),
        &[
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--policy-file",
            "policies/note-eval.rqlp",
            "--format",
            "json",
            "--fail-on",
            "never",
        ],
    );
    assert_status(&first, 0);
    assert_status(&reversed, 0);
    assert_eq!(first.stdout, reversed.stdout);

    let duplicates = run(
        project.root(),
        &[
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--policy-file",
            "policies/duplicate.rqlp",
            "--format",
            "json",
        ],
    );
    let duplicates_reversed = run(
        project.root(),
        &[
            "--policy-file",
            "policies/duplicate.rqlp",
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--format",
            "json",
        ],
    );
    assert_status(&duplicates, 2);
    assert_status(&duplicates_reversed, 2);
    assert_eq!(duplicates.stdout, duplicates_reversed.stdout);
    let report = json_stdout(&duplicates);
    assert!(report["rules"].as_array().unwrap().is_empty());
    assert!(report["runs"].as_array().unwrap().is_empty());
    assert_eq!(report["diagnostics"].as_array().unwrap().len(), 2);
    let diagnostics = report["diagnostics"].as_array().unwrap();
    let mut sources = Vec::new();
    for diagnostic in diagnostics {
        assert_eq!(diagnostic["code"], "duplicate-policy-id");
        assert_eq!(
            diagnostic["message"],
            "policy ID `bifrost.security.dynamic-eval` has 2 requested definitions across 2 source identities; every definition was excluded"
        );
        sources.push(diagnostic["source"].as_str().unwrap());
        assert_eq!(diagnostic["related"].as_array().unwrap().len(), 1);
    }
    sources.sort_unstable();
    assert_eq!(
        sources,
        ["policies/duplicate.rqlp", "policies/dynamic-eval.rqlp"]
    );
}

#[test]
fn mixed_invalid_and_typestate_batches_retain_valid_findings_with_typed_statuses() {
    let project = policy_project(&[(
        "policies/invalid.rqlp",
        "(policy :id \"broken\"".to_string(),
    )]);
    let destination = tempfile::tempdir().expect("output directory");
    let output_path = destination.path().join("mixed.json");
    let mixed = bifrost(project.root())
        .args([
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--policy-file",
            "policies/invalid.rqlp",
            "--format",
            "json",
            "--output",
        ])
        .arg(&output_path)
        .output()
        .expect("run mixed valid/invalid policy batch");
    assert_status(&mixed, 2);
    assert!(mixed.stdout.is_empty());
    let report: Value = serde_json::from_slice(&fs::read(&output_path).unwrap()).unwrap();
    assert_eq!(report["rules"].as_array().unwrap().len(), 1);
    assert_eq!(report["runs"][0]["findings"].as_array().unwrap().len(), 1);
    assert_eq!(report["diagnostics"].as_array().unwrap().len(), 1);

    let typestate = run(
        project.root(),
        &[
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--policy-file",
            "policies/resource-lifecycle.rqlp",
            "--format",
            "sarif",
        ],
    );
    assert_status(&typestate, 2);
    let sarif = json_stdout(&typestate);
    assert_eq!(sarif["runs"][0]["results"].as_array().unwrap().len(), 2);
    assert_eq!(
        sarif["runs"][0]["invocations"][0]["executionSuccessful"],
        false
    );
    assert!(
        sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
            .as_array()
            .unwrap()
            .iter()
            .any(|notification| {
                notification["descriptor"]["id"] == "BIFROST_POLICY_INCONCLUSIVE"
            })
    );
}

#[test]
fn typestate_finding_identity_locations_and_witnesses_match_human_and_sarif() {
    let project = policy_project(&[]);
    let arguments = [
        "--policy-file",
        "policies/resource-lifecycle.rqlp",
        "--fail-on",
        "never",
    ];
    let json = run(
        project.root(),
        &[&arguments[..], &["--format", "json"]].concat(),
    );
    assert_status(&json, 2);
    let json = json_stdout(&json);
    let findings = json["runs"][0]["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    let finding_ids = findings
        .iter()
        .map(|finding| finding["id"].as_str().unwrap())
        .collect::<Vec<_>>();
    for finding in findings {
        assert!(!finding["related"].as_array().unwrap().is_empty());
        assert!(!finding["witnesses"].as_array().unwrap().is_empty());
        assert_eq!(finding["witnesses_truncated"], false);
    }

    let human = run(project.root(), &[&arguments[..], &["--verbose"]].concat());
    assert_status(&human, 2);
    let human = String::from_utf8(human.stdout).expect("UTF-8 typestate report");
    for finding_id in &finding_ids {
        assert!(
            human.contains(finding_id),
            "missing {finding_id} in:\n{human}"
        );
    }
    assert!(human.contains("  related source: "), "{human}");
    assert!(human.contains("  witness "), "{human}");
    let finding = &findings[0];
    assert!(
        human.contains(finding["policy_id"].as_str().unwrap()),
        "{human}"
    );
    assert!(
        human.contains(&format!(
            "analysis: typestate ({}, {})",
            finding["certainty"]["type"].as_str().unwrap(),
            finding["completeness"]["type"].as_str().unwrap(),
        )),
        "{human}"
    );
    for witness in finding["witnesses"].as_array().unwrap() {
        assert!(human.contains(witness["id"].as_str().unwrap()), "{human}");
        for step in witness["steps"].as_array().unwrap() {
            assert!(human.contains(step["label"].as_str().unwrap()), "{human}");
        }
    }

    let sarif = run(
        project.root(),
        &[&arguments[..], &["--format", "sarif"]].concat(),
    );
    assert_status(&sarif, 2);
    let sarif = json_stdout(&sarif);
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 1);
    let sarif_ids = results
        .iter()
        .map(|result| result["properties"]["bifrost.findingId"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(sarif_ids, finding_ids);
    for (finding, result) in findings.iter().zip(results) {
        assert_eq!(result["ruleId"], finding["policy_id"]);
        assert_eq!(
            result["properties"]["bifrost.certainty"],
            finding["certainty"]
        );
        assert_eq!(
            result["properties"]["bifrost.findingCompleteness"],
            finding["completeness"]
        );
        assert_eq!(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            finding["primary"]["path"]
        );
        assert_eq!(
            result["locations"][0]["physicalLocation"]["region"]["startLine"],
            finding["primary"]["region"]["start_line"]
        );
        assert!(!result["relatedLocations"].as_array().unwrap().is_empty());
        assert!(!result["codeFlows"].as_array().unwrap().is_empty());
        let related = finding["related"].as_array().unwrap();
        let sarif_related = result["relatedLocations"].as_array().unwrap();
        assert_eq!(sarif_related.len(), related.len());
        for (expected, actual) in related.iter().zip(sarif_related) {
            assert_eq!(
                actual["physicalLocation"]["artifactLocation"]["uri"],
                expected["location"]["path"]
            );
            assert_eq!(
                actual["properties"]["bifrost.relationship"],
                expected["relationship"]
            );
        }
        let witnesses = finding["witnesses"].as_array().unwrap();
        let code_flows = result["codeFlows"].as_array().unwrap();
        assert_eq!(code_flows.len(), witnesses.len());
        for (expected, actual) in witnesses.iter().zip(code_flows) {
            assert_eq!(actual["properties"]["bifrost.witnessId"], expected["id"]);
            assert_eq!(
                actual["properties"]["bifrost.truncated"],
                expected["truncated"]
            );
            let actual_steps = actual["threadFlows"][0]["locations"].as_array().unwrap();
            let expected_steps = expected["steps"].as_array().unwrap();
            assert_eq!(actual_steps.len(), expected_steps.len());
            for (expected_step, actual_step) in expected_steps.iter().zip(actual_steps) {
                assert_eq!(
                    actual_step["location"]["message"]["text"],
                    expected_step["label"]
                );
            }
        }
    }
}

#[test]
fn java_and_typescript_resource_rqlp_retain_identity_through_all_renderers() {
    for (language, project) in [
        (
            "typescript",
            resource_policy_project("src/resource.ts", CROSS_LANGUAGE_TYPESCRIPT_RESOURCE_SOURCE),
        ),
        (
            "java",
            resource_policy_project("src/ResourceLifecycle.java", JAVA_RESOURCE_SOURCE),
        ),
    ] {
        let arguments = [
            "--policy-file",
            "policies/resource-lifecycle.rqlp",
            "--fail-on",
            "never",
        ];
        let json = run(
            project.root(),
            &[&arguments[..], &["--format", "json"]].concat(),
        );
        assert_status(&json, 2);
        let json = json_stdout(&json);
        let findings = json["runs"][0]["findings"]
            .as_array()
            .expect("findings array");
        assert_eq!(findings.len(), 1, "{language} report: {json:#}");
        let finding = &findings[0];
        let finding_id = finding["id"].as_str().expect("finding id");
        let policy_id = finding["policy_id"].as_str().expect("policy id");
        assert_eq!(policy_id, "bifrost.test.resource-lifecycle");
        assert!(!finding["witnesses"].as_array().unwrap().is_empty());

        let human = run(project.root(), &[&arguments[..], &["--verbose"]].concat());
        assert_status(&human, 2);
        let human = String::from_utf8(human.stdout).expect("UTF-8 typestate report");
        assert!(human.contains(finding_id), "{human}");
        assert!(human.contains(policy_id), "{human}");

        let sarif = run(
            project.root(),
            &[&arguments[..], &["--format", "sarif"]].concat(),
        );
        assert_status(&sarif, 2);
        let sarif = json_stdout(&sarif);
        let result = &sarif["runs"][0]["results"][0];
        assert_eq!(result["ruleId"], policy_id);
        assert_eq!(result["properties"]["bifrost.findingId"], finding_id);
        assert_eq!(
            result["properties"]["bifrost.certainty"],
            finding["certainty"]
        );
        assert_eq!(
            result["properties"]["bifrost.findingCompleteness"],
            finding["completeness"]
        );
        assert!(!result["codeFlows"].as_array().unwrap().is_empty());
    }
}

#[test]
fn repeated_typestate_policies_share_production_summaries_with_explicit_counters() {
    let copy = RESOURCE
        .replace(
            "bifrost.test.resource-lifecycle",
            "bifrost.test.resource-lifecycle-copy",
        )
        .replace("Resource lifecycle", "Resource lifecycle copy");
    let project = repeated_java_resource_policy_project(copy);
    let output = run(
        project.root(),
        &[
            "--policy-file",
            "policies/resource-lifecycle.rqlp",
            "--policy-file",
            "policies/resource-lifecycle-copy.rqlp",
            "--format",
            "json",
            "--fail-on",
            "never",
        ],
    );
    assert_status(&output, 2);
    let report = json_stdout(&output);
    let runs = report["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 2);
    let metric = |run: &Value, name: &str| {
        run["work"]["metrics"]
            .as_array()
            .unwrap()
            .iter()
            .find(|metric| metric["name"] == name)
            .unwrap_or_else(|| panic!("missing {name} in {}", run["policy_id"]))["value"]
            .as_u64()
            .unwrap()
    };
    let first = runs
        .iter()
        .find(|run| run["policy_id"] == "bifrost.test.resource-lifecycle")
        .unwrap();
    let repeated = runs
        .iter()
        .find(|run| run["policy_id"] == "bifrost.test.resource-lifecycle-copy")
        .unwrap();

    assert!(metric(first, "typestate.summary_misses") > 0);
    assert_eq!(
        metric(first, "typestate.summary_recomputations"),
        metric(first, "typestate.summary_misses")
    );
    // Policy-batch exact results are presentation-neutral and replay their
    // original semantic, solver, and provider-execution charges. The second
    // policy therefore reuses the first result even though policy/finding IDs
    // remain policy-specific.
    assert!(metric(repeated, "typestate.summary_hits") > 0);
    assert_eq!(metric(repeated, "typestate.summary_misses"), 0);
    assert_eq!(metric(repeated, "typestate.summary_recomputations"), 0);
    let first_finding = &first["findings"][0];
    let repeated_finding = &repeated["findings"][0];
    for field in [
        "message",
        "severity",
        "certainty",
        "completeness",
        "primary",
        "related",
        "witnesses_truncated",
    ] {
        assert_eq!(first_finding[field], repeated_finding[field], "{field}");
    }
    let first_witnesses = first_finding["witnesses"].as_array().unwrap();
    let repeated_witnesses = repeated_finding["witnesses"].as_array().unwrap();
    assert_eq!(first_witnesses.len(), repeated_witnesses.len());
    for (first_witness, repeated_witness) in first_witnesses.iter().zip(repeated_witnesses) {
        assert_eq!(first_witness["steps"], repeated_witness["steps"]);
        assert_eq!(first_witness["truncated"], repeated_witness["truncated"]);
    }
    assert_eq!(first["diagnostics"], repeated["diagnostics"]);
    for run in runs {
        assert_eq!(metric(run, "typestate.summary_evictions"), 0);
        let _ = metric(run, "typestate.summary_rejections");
    }
}

#[test]
#[ignore = "emits timing evidence; run explicitly with --ignored --nocapture"]
fn production_summary_repeated_policy_measurement() {
    let copy = RESOURCE
        .replace(
            "bifrost.test.resource-lifecycle",
            "bifrost.test.resource-lifecycle-copy",
        )
        .replace("Resource lifecycle", "Resource lifecycle copy");
    let project = repeated_java_resource_policy_project(copy);
    let started = Instant::now();
    let output = run(
        project.root(),
        &[
            "--policy-file",
            "policies/resource-lifecycle.rqlp",
            "--policy-file",
            "policies/resource-lifecycle-copy.rqlp",
            "--format",
            "json",
            "--fail-on",
            "never",
        ],
    );
    let batch_micros = started.elapsed().as_micros();
    assert_status(&output, 2);
    let report = json_stdout(&output);
    let runs = report["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 2);
    let metric = |run: &Value, name: &str| {
        run["work"]["metrics"]
            .as_array()
            .unwrap()
            .iter()
            .find(|metric| metric["name"] == name)
            .unwrap_or_else(|| panic!("missing {name} in {}", run["policy_id"]))["value"]
            .as_u64()
            .unwrap()
    };
    let measurements = runs
        .iter()
        .map(|run| {
            serde_json::json!({
                "policy_id": run["policy_id"],
                "hits": metric(run, "typestate.summary_hits"),
                "misses": metric(run, "typestate.summary_misses"),
                "rejections": metric(run, "typestate.summary_rejections"),
                "evictions": metric(run, "typestate.summary_evictions"),
                "recomputations": metric(run, "typestate.summary_recomputations"),
                "finding_ids": run["findings"].as_array().unwrap().iter()
                    .map(|finding| finding["id"].clone())
                    .collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    assert!(measurements[1]["hits"].as_u64().unwrap() > 0);
    assert_eq!(measurements[1]["recomputations"], 0);
    println!(
        "BIFROST_PRODUCTION_SUMMARY_POLICY_MEASUREMENT={}",
        serde_json::json!({
            "format": "bifrost_production_summary_policy/v1",
            "fixture": "inline:src/ResourceLifecycle.java",
            "language": "java",
            "repeated_policies": 2,
            "batch_micros": batch_micros,
            "runs": measurements,
        })
    );
}

#[test]
fn typestate_same_site_endpoint_precedence_retains_only_the_dominant_binding() {
    let project = policy_project(&[
        (
            "policies/endpoints/resource-acquire-dominant.rqlp",
            DOMINANT_ACQUIRE_ENDPOINT.to_owned(),
        ),
        (
            "policies/endpoints/resource-close-dominant.rqlp",
            DOMINANT_CLOSE_ENDPOINT.to_owned(),
        ),
        ("src/dominance.ts", DOMINANCE_SOURCE.to_owned()),
    ]);
    let output = run(
        project.root(),
        &[
            "--policy-file",
            "policies/resource-lifecycle.rqlp",
            "--format",
            "json",
            "--fail-on",
            "never",
        ],
    );
    assert_status(&output, 2);
    let report = json_stdout(&output);
    assert_eq!(
        report["rules"][0]["precedence_manifest"]["edges"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );
    let metrics = report["runs"][0]["work"]["metrics"].as_array().unwrap();
    let subjects = metrics
        .iter()
        .find(|metric| metric["name"] == "typestate.subjects")
        .unwrap_or_else(|| panic!("missing typestate subject metric: {report:#}"));
    assert_eq!(subjects["value"], 2);
    let initial_seeds = metrics
        .iter()
        .find(|metric| metric["name"] == "typestate.initial_seeds")
        .expect("typestate initial-seed metric");
    assert_eq!(initial_seeds["value"], 2);
    let event_bindings = metrics
        .iter()
        .find(|metric| metric["name"] == "typestate.event_bindings")
        .expect("typestate event binding metric");
    assert_eq!(event_bindings["value"], 1);
}

#[test]
fn typestate_analysis_root_exit_event_executes_its_transition() {
    let project = policy_project(&[(
        "policies/resource-exit-event.rqlp",
        EXIT_EVENT_POLICY.to_owned(),
    )]);
    let output = run(
        project.root(),
        &[
            "--policy-file",
            "policies/resource-exit-event.rqlp",
            "--format",
            "json",
            "--fail-on",
            "never",
        ],
    );
    assert_status(&output, 2);
    let report = json_stdout(&output);
    assert_eq!(
        report["runs"][0]["findings"]
            .as_array()
            .unwrap_or_else(|| panic!("semantic exit policy report: {report:#}"))
            .len(),
        1,
        "semantic exit policy report: {report:#}"
    );
    let event_bindings = report["runs"][0]["work"]["metrics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|metric| metric["name"] == "typestate.event_bindings")
        .expect("semantic exit event binding metric");
    assert_eq!(event_bindings["value"], 1);
}

#[test]
fn typestate_projection_honors_authored_report_caps_before_authority_validation() {
    let capped = RESOURCE.replace(
        ":severity error",
        ":severity error\n  :report (report\n    :witness (witness :max-steps 1 :max-bytes 256)\n    :witnesses-per-finding 0\n    :origins-per-finding 0)",
    );
    let project = policy_project(&[("policies/resource-capped.rqlp", capped)]);
    let output = run(
        project.root(),
        &[
            "--policy-file",
            "policies/resource-capped.rqlp",
            "--format",
            "json",
            "--fail-on",
            "never",
        ],
    );
    assert_status(&output, 2);
    let report = json_stdout(&output);
    let finding = &report["runs"][0]["findings"][0];
    assert!(finding["witnesses"].as_array().unwrap().is_empty());
    assert_eq!(finding["witnesses_truncated"], true);
    assert!(finding["omitted_witnesses_lower_bound"].as_u64().unwrap() >= 1);
    assert!(finding["related"].as_array().unwrap().is_empty());
    assert_eq!(finding["related_truncated"], true);
    assert!(
        finding["omitted_related_locations_lower_bound"]
            .as_u64()
            .unwrap()
            >= 1
    );
}

#[test]
fn policy_mode_is_exclusive_and_output_failures_use_status_two_without_clobbering() {
    let project = policy_project(&[]);
    let missing = run(
        project.root(),
        &["--policy-file", "policies/missing.rqlp", "--format", "json"],
    );
    assert_status(&missing, 2);
    let missing_report = json_stdout(&missing);
    assert_eq!(
        missing_report["diagnostics"][0]["code"],
        "policy-load-failed"
    );

    let conflict = run(
        project.root(),
        &[
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--sources",
            "src",
        ],
    );
    assert_status(&conflict, 2);
    assert!(conflict.stdout.is_empty());
    assert!(String::from_utf8_lossy(&conflict.stderr).contains("cannot be combined"));

    for arguments in [
        vec!["--format", "xml"],
        vec!["--policy-file"],
        vec!["--policy-file", "policies/dynamic-eval.rqlp", "--unknown"],
        vec!["--unknown", "--policy-file", "policies/dynamic-eval.rqlp"],
        vec![
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--evaluation-date",
            "2026-02-30",
        ],
        vec![
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--suppressions-file",
            "/outside/reviews.json",
        ],
        vec![
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--evaluation-date",
            "2026-07-27",
            "--evaluation-date",
            "2026-07-28",
        ],
        vec![
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--suppressions-file",
            "reviews/one.json",
            "--suppressions-file",
            "reviews/two.json",
        ],
        vec![
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--color",
            "sometimes",
        ],
        vec![
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--format",
            "json",
            "--verbose",
        ],
        vec![
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--format",
            "sarif",
            "--color",
            "never",
        ],
        vec![
            "--args",
            "not-json",
            "--policy-file",
            "policies/dynamic-eval.rqlp",
        ],
    ] {
        let invalid_invocation = run(project.root(), &arguments);
        assert_status(&invalid_invocation, 2);
        assert!(invalid_invocation.stdout.is_empty());
    }

    let legacy_value = run(
        project.root(),
        &["--tool", "--format", "--args", "not-json"],
    );
    assert_status(&legacy_value, 1);
    assert!(String::from_utf8_lossy(&legacy_value.stderr).contains("--args must be valid JSON"));

    let destination = tempfile::tempdir().expect("destination parent");
    let output_path = destination.path().join("report.json");
    fs::write(&output_path, "previous report\n").expect("existing destination");

    let directory_destination = destination.path().join("nonempty-destination");
    fs::create_dir(&directory_destination).expect("nonempty destination directory");
    let sentinel = directory_destination.join("sentinel.txt");
    fs::write(&sentinel, "keep me\n").expect("destination sentinel");
    let directory_failure = bifrost(project.root())
        .args([
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--format",
            "json",
            "--output",
        ])
        .arg(&directory_destination)
        .output()
        .expect("run platform-neutral persist failure");
    assert_status(&directory_failure, 2);
    assert!(directory_failure.stdout.is_empty());
    assert_eq!(fs::read_to_string(&sentinel).unwrap(), "keep me\n");
    assert!(
        String::from_utf8_lossy(&directory_failure.stderr).contains("failed to atomically replace")
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let original = fs::metadata(destination.path()).unwrap().permissions();
        fs::set_permissions(destination.path(), fs::Permissions::from_mode(0o555)).unwrap();
        let failed = bifrost(project.root())
            .args([
                "--policy-file",
                "policies/dynamic-eval.rqlp",
                "--format",
                "json",
                "--output",
            ])
            .arg(&output_path)
            .output()
            .expect("run policy output failure");
        fs::set_permissions(destination.path(), original).unwrap();

        assert_status(&failed, 2);
        assert!(failed.stdout.is_empty());
        assert_eq!(
            fs::read_to_string(&output_path).unwrap(),
            "previous report\n"
        );
        assert!(String::from_utf8_lossy(&failed.stderr).contains("policy report output failed"));
    }
}

#[test]
fn policy_stderr_escapes_control_and_bidirectional_text() {
    let project = policy_project(&[]);
    let unsafe_text = "line\n\u{001B}[31m\u{202E}\u{2066}";

    let invalid_format = run(project.root(), &["--format", unsafe_text]);
    assert_status(&invalid_format, 2);
    assert!(invalid_format.stdout.is_empty());
    assert_single_terminal_safe_line(&invalid_format);

    let unsafe_destination = project.root().join(unsafe_text).join("report.json");
    let failed_output = bifrost(project.root())
        .args(["--policy-file", "policies/dynamic-eval.rqlp", "--output"])
        .arg(unsafe_destination)
        .output()
        .expect("run policy output failure with unsafe path");
    assert_status(&failed_output, 2);
    assert!(failed_output.stdout.is_empty());
    assert_single_terminal_safe_line(&failed_output);
}

#[test]
fn broken_stdout_pipe_is_an_operational_status_two_failure() {
    let project = policy_project(&[]);
    let mut child = bifrost(project.root())
        .args([
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--format",
            "json",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn policy CLI");
    drop(child.stdout.take());
    let output = child.wait_with_output().expect("wait for policy CLI");
    assert_status(&output, 2);
    assert!(String::from_utf8_lossy(&output.stderr).contains("policy report output failed"));
}

#[test]
fn output_path_may_be_outside_the_analyzed_workspace() {
    let project = policy_project(&[]);
    let outside = tempfile::tempdir().expect("outside output root");
    let output_path: PathBuf = outside.path().join("report.txt");
    let output = bifrost(project.root())
        .args(["--policy-file", "policies/dynamic-eval.rqlp", "--output"])
        .arg(&output_path)
        .output()
        .expect("write outside workspace");
    assert_status(&output, 1);
    assert!(output.stdout.is_empty());
    let file_output = fs::read(output_path).unwrap();
    assert!(!file_output.contains(&0x1b));
    assert!(
        String::from_utf8(file_output)
            .unwrap()
            .contains("Dynamic evaluation is forbidden")
    );
}
