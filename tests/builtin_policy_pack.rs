mod common;

use std::collections::BTreeSet;

use brokk_bifrost::AnalyzerConfig;
use brokk_bifrost::policy::{
    BuiltInPolicySelection, CODE_SMELLS_PACK_ID, PolicyEvaluationDate, PolicyEvaluationInput,
    PolicyEvaluationOptions, PolicyRunCompletion, built_in_policy_catalog,
    evaluate_policy_inputs_with_analyzer,
};

use common::InlineTestProject;

const PYTHON_POSITIVES: &str = r#"import json
import pickle
import re
import requests
import subprocess
import time
import yaml

def dynamic(value):
    return eval(value)

def unsafe(value, stream):
    pickle.loads(value)
    pickle.load(stream)
    yaml.load(value)

def local_smells(items, cursor):
    for item in items:
        items.sort()
        re.compile("x")
        open("input.txt")
        json.dumps(item)
        json.loads(item)
        cursor.execute("select 1")
        requests.get("https://example.invalid")
        subprocess.run(["true"])
        time.sleep(1)

def nested_smell(rows):
    for row in rows:
        for item in row:
            open(item)

def direct(value):
    return dynamic(value)

def second_order(value):
    return direct(value)

def outside_bound(value):
    return second_order(value)
"#;

const PYTHON_NEAR_MISSES: &str = r#"import json
import re
import requests
import time
import yaml

def safe(value, items):
    items.sort()
    re.compile("x")
    open("input.txt")
    json.dumps(value)
    json.loads(value)
    requests.get("https://example.invalid")
    time.sleep(1)
    yaml.safe_load(value)
    return evaluate(value)
"#;

const JAVA_POSITIVES: &str = r#"class Smells {
    void localSmells(Iterable<String> items) throws Exception {
        for (String item : items) {
            items.sort(null);
            Pattern.compile("x");
            Files.readString(path);
            mapper.writeValueAsString(item);
            parser.parse(item);
            statement.executeQuery(item);
            client.send(request, handler);
            runtime.exec(item);
            Thread.sleep(1);
        }
    }

    void nestedSmell(Iterable<Iterable<String>> rows) throws Exception {
        for (Iterable<String> row : rows) {
            for (String item : row) {
                Files.readAllBytes(path);
            }
        }
    }
}
"#;

const JAVA_NEAR_MISSES: &str = r#"class Safe {
    void outside(String item) throws Exception {
        items.sort(null);
        Pattern.compile("x");
        Files.readString(path);
        mapper.writeValueAsString(item);
        parser.parse(item);
        statement.executeQuery(item);
        client.send(request, handler);
        runtime.exec(item);
        Thread.sleep(1);
    }
}
"#;

const JAVASCRIPT_POSITIVES: &str = r#"export function dynamicJs(value) {
  return eval(value);
}

export function directJs(value) {
  return dynamicJs(value);
}

export function secondOrderJs(value) {
  return directJs(value);
}

export function outsideBoundJs(value) {
  return secondOrderJs(value);
}

export function localSmells(items) {
  for (const item of items) {
    RegExp("x");
    fs.readFileSync("input.txt");
    JSON.stringify(item);
    JSON.parse(item);
    db.query(item);
    fetch(item);
    child_process.execSync(item);
  }
}

export function nestedSmell(rows) {
  for (const row of rows) {
    for (const item of row) {
      fetch(item);
    }
  }
}
"#;

const JAVASCRIPT_NEAR_MISSES: &str = r#"export function safe(value) {
  RegExp("x");
  fs.readFileSync("input.txt");
  JSON.stringify(value);
  JSON.parse(value);
  db.query(value);
  fetch(value);
  child_process.execSync(value);
  return evaluate(value);
}
"#;

const TYPESCRIPT_POSITIVES: &str = r#"export function dynamicTs(value: string): unknown {
  return eval(value);
}

export function directTs(value: string): unknown {
  return dynamicTs(value);
}

export function secondOrderTs(value: string): unknown {
  return directTs(value);
}

export function outsideBoundTs(value: string): unknown {
  return secondOrderTs(value);
}

export function localSmells(items: string[]): void {
  for (const item of items) {
    items.sort();
    RegExp("x");
    fs.readFileSync("input.txt");
    JSON.stringify(item);
    JSON.parse(item);
    db.query(item);
    fetch(item);
    child_process.execSync(item);
  }
}

export function nestedSmell(rows: string[][]): void {
  for (const row of rows) {
    for (const item of row) {
      JSON.parse(item);
    }
  }
}
"#;

const TYPESCRIPT_NEAR_MISSES: &str = r#"export function safe(value: string, items: string[]): unknown {
  items.sort();
  RegExp("x");
  fs.readFileSync("input.txt");
  JSON.stringify(value);
  JSON.parse(value);
  db.query(value);
  fetch(value);
  child_process.execSync(value);
  return evaluate(value);
}
"#;

fn expected_paths(policy_id: &str) -> BTreeSet<&'static str> {
    let paths: &[&str] = match policy_id {
        "bifrost.correctness.dynamic-evaluation" => &["positive.py", "positive.js", "positive.ts"],
        "bifrost.correctness.unsafe-deserialization" => &["positive.py"],
        "bifrost.performance.sort-in-loop" => &["positive.py", "Positive.java", "positive.ts"],
        "bifrost.performance.regex-compile-in-loop"
        | "bifrost.performance.file-read-in-loop"
        | "bifrost.performance.serialization-in-loop"
        | "bifrost.performance.parsing-in-loop"
        | "bifrost.performance.database-call-in-loop"
        | "bifrost.performance.network-call-in-loop"
        | "bifrost.performance.subprocess-in-loop"
        | "bifrost.performance.expensive-operation-in-nested-loop" => {
            &["positive.py", "Positive.java", "positive.js", "positive.ts"]
        }
        "bifrost.performance.sleep-in-loop" => &["positive.py", "Positive.java"],
        other => panic!("unexpected built-in policy {other}"),
    };
    paths.iter().copied().collect()
}

#[test]
fn code_smell_pack_matches_claimed_languages_and_excludes_outside_loop_near_misses() {
    let project = InlineTestProject::new()
        .file("positive.py", PYTHON_POSITIVES)
        .file("safe.py", PYTHON_NEAR_MISSES)
        .file("Positive.java", JAVA_POSITIVES)
        .file("Safe.java", JAVA_NEAR_MISSES)
        .file("positive.js", JAVASCRIPT_POSITIVES)
        .file("safe.js", JAVASCRIPT_NEAR_MISSES)
        .file("positive.ts", TYPESCRIPT_POSITIVES)
        .file("safe.ts", TYPESCRIPT_NEAR_MISSES)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let selected = built_in_policy_catalog()
        .expect("valid catalog")
        .select(&BuiltInPolicySelection {
            packs: vec![CODE_SMELLS_PACK_ID.to_owned()],
            ..BuiltInPolicySelection::default()
        })
        .expect("select code-smell pack");
    let inputs = selected
        .into_iter()
        .map(|policy| PolicyEvaluationInput::embedded(policy.source_identity(), policy.source()))
        .collect::<Vec<_>>();
    let options = PolicyEvaluationOptions::new(
        PolicyEvaluationDate::from_ymd(2026, 7, 28).expect("fixed evaluation date"),
    );
    let outcome =
        evaluate_policy_inputs_with_analyzer(project.root(), &inputs, &workspace, &options, None)
            .expect("evaluate built-in pack");

    assert!(outcome.report().diagnostics().is_empty());
    assert_eq!(outcome.report().rules().len(), 12);
    assert_eq!(outcome.report().runs().len(), 12);
    for run in outcome.report().runs() {
        assert!(
            matches!(run.completion(), PolicyRunCompletion::Complete),
            "{}: {:?}",
            run.policy_id(),
            run.completion()
        );
        let actual = run
            .findings()
            .iter()
            .map(|finding| finding.primary().path())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            actual,
            expected_paths(run.policy_id().as_str()),
            "{}",
            run.policy_id()
        );
    }
}

#[test]
fn selector_union_is_deduplicated_and_keeps_manifest_order() {
    let catalog = built_in_policy_catalog().expect("valid catalog");
    let selected = catalog
        .select(&BuiltInPolicySelection {
            packs: vec![CODE_SMELLS_PACK_ID.to_owned()],
            categories: vec!["performance".to_owned()],
            policy_ids: vec!["bifrost.correctness.dynamic-evaluation".to_owned()],
        })
        .expect("overlapping selection");
    let selected_ids = selected
        .iter()
        .map(|policy| policy.manifest().id.as_str())
        .collect::<Vec<_>>();
    let manifest_ids = catalog
        .manifest()
        .policies
        .iter()
        .map(|policy| policy.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(selected_ids, manifest_ids);
}
