use std::collections::BTreeMap;

use brokk_bifrost::AnalyzerConfig;
use brokk_bifrost::policy::{
    BuiltInPolicySelection, CODE_SMELLS_PACK_ID, PolicyEvaluationDate, PolicyEvaluationInput,
    PolicyEvaluationOptions, PolicyRunCompletion, built_in_policy_catalog,
    evaluate_policy_inputs_with_analyzer,
};

use crate::common::InlineTestProject;

const PYTHON_POSITIVES: &str = r#"import json
import pickle
import re
import requests
import subprocess
import time

def dynamic(value):
    eval(value)
    exec(value)

def unsafe(value, stream):
    pickle.loads(value)
    pickle.load(stream)

def local_smells(items, cursor):
    for item in items:
        items.sort()
        re.compile("x")
        open("input.txt")
        json.dumps(item)
        json.loads(item)
        cursor.execute("select 1")
        requests.get("https://example.invalid")
        requests.post("https://example.invalid")
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
    yaml.load(value, Loader=yaml.SafeLoader)
    for item in items:
        items.sorted_copy()
        re.search("x", item)
        file_system.open_file(item)
        json.dump(item)
        json.load(item)
        cursor.executemany(item)
        requests.request(item)
        subprocess.check_call([item])
        time.monotonic()
    for row in items:
        for item in row:
            cache.lookup(item)
    while not value:
        time.sleep(1)
    return evaluate(value)
"#;

const PYTHON_DEFERRED_LEXICAL_POSITIVES: &str = r#"import json
import re
import requests
import subprocess
import time

def deferred(items, cursor):
    for item in items:
        def later():
            items.sort()
            re.compile("x")
            open(item)
            json.dumps(item)
            json.loads(item)
            cursor.execute(item)
            requests.get(item)
            subprocess.run([item])
            time.sleep(1)

def nested_deferred(rows):
    for row in rows:
        for item in row:
            def later():
                return open(item)
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
        for (String nested : items) {
            items.sortedCopy();
            Pattern.matches("x", nested);
            Files.exists(path);
            mapper.valueToTree(nested);
            parser.canParse(nested);
            statement.addBatch(nested);
            client.close();
            runtime.availableProcessors();
            Thread.yield();
        }
        while (item.isEmpty()) {
            Thread.sleep(1);
        }
    }
}
"#;

const JAVA_DEFERRED_LEXICAL_POSITIVES: &str = r#"class Deferred {
    void deferred(Iterable<String> items) {
        for (String item : items) {
            class Later {
                void run() throws Exception {
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
        }
    }

    void nestedDeferred(Iterable<Iterable<String>> rows) {
        for (Iterable<String> row : rows) {
            for (String item : row) {
                class Later {
                    void run() throws Exception {
                        Files.readAllBytes(path);
                    }
                }
            }
        }
    }
}
"#;

const JAVASCRIPT_POSITIVES: &str = r#"export function dynamicJs(value) {
  eval(value);
  return (Function(value), value);
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

export function invariantSort(items, groups) {
  for (const group of groups) {
    items.sort();
  }
  return items.length;
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
  for (const item of value) {
    compilePattern(item);
    fs.existsSync(item);
    JSON.isRawJSON(item);
    parseSafely(item);
    db.prepare(item);
    fetchLater(item);
    child_process.spawnSync(item);
  }
  for (const row of value) {
    for (const item of row) {
      cache.lookup(item);
    }
  }
  return evaluate(value);
}
"#;

const JAVASCRIPT_DEFERRED_LEXICAL_POSITIVES: &str = r#"export function deferred(items) {
  for (const item of items) {
    function later() {
      RegExp("x");
      fs.readFileSync(item);
      JSON.stringify(item);
      JSON.parse(item);
      db.query(item);
      fetch(item);
      child_process.execSync(item);
    }
  }
}

export function nestedDeferred(rows) {
  for (const row of rows) {
    for (const item of row) {
      function later() {
        fetch(item);
      }
    }
  }
}
"#;

const TYPESCRIPT_POSITIVES: &str = r#"export function dynamicTs(value: string): unknown {
  eval(value);
  return (Function(value), value);
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
  for (const item of items) {
    items.toSorted();
    compilePattern(item);
    fs.existsSync(item);
    JSON.isRawJSON(item);
    parseSafely(item);
    db.prepare(item);
    fetchLater(item);
    child_process.spawnSync(item);
  }
  for (const row of [items]) {
    for (const item of row) {
      cache.lookup(item);
    }
  }
  return evaluate(value);
}
"#;

const TYPESCRIPT_DEFERRED_LEXICAL_POSITIVES: &str = r#"export function deferred(items: string[]): void {
  for (const item of items) {
    function later(): void {
      items.sort();
      RegExp("x");
      fs.readFileSync(item);
      JSON.stringify(item);
      JSON.parse(item);
      db.query(item);
      fetch(item);
      child_process.execSync(item);
    }
  }
}

export function nestedDeferred(rows: string[][]): void {
  for (const row of rows) {
    for (const item of row) {
      function later(): void {
        JSON.parse(item);
      }
    }
  }
}
"#;

const RUST_POSITIVES: &str = r#"fn local_smells(items: &mut [String]) {
    for item in items.iter() {
        items.sort();
        items.sort_by(|left, right| left.cmp(right));
        items.sort_by_key(|value| value.len());
        items.sort_by_cached_key(|value| value.len());
        items.sort_unstable();
        items.sort_unstable_by(|left, right| left.cmp(right));
        items.sort_unstable_by_key(|value| value.len());
        Regex::new("x");
        fs::read(item);
        std::fs::read_to_string(item);
        serde_json::to_string(item);
        serde_json::to_vec(item);
        bincode::serialize(item);
        serde_json::from_str::<Value>(item);
        serde_json::from_slice::<Value>(item.as_bytes());
        bincode::deserialize::<Value>(item.as_bytes());
        toml::from_str::<Value>(item);
        reqwest::get(item);
        ureq::get(item);
        ureq::post(item);
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn nested_smell(rows: &[Vec<String>]) {
    for row in rows {
        for item in row {
            fs::read(item);
            std::fs::read_to_string(item);
        }
    }
}
"#;

const RUST_NEAR_MISSES: &str = r#"fn outside(items: &mut [String], item: &str) {
    items.sort();
    items.sort_by(|left, right| left.cmp(right));
    items.sort_by_key(|value| value.len());
    items.sort_by_cached_key(|value| value.len());
    items.sort_unstable();
    items.sort_unstable_by(|left, right| left.cmp(right));
    items.sort_unstable_by_key(|value| value.len());
    Regex::new("x");
    fs::read(item);
    std::fs::read_to_string(item);
    serde_json::to_string(item);
    serde_json::to_vec(item);
    bincode::serialize(item);
    serde_json::from_str::<Value>(item);
    serde_json::from_slice::<Value>(item.as_bytes());
    bincode::deserialize::<Value>(item.as_bytes());
    toml::from_str::<Value>(item);
    reqwest::get(item);
    ureq::get(item);
    ureq::post(item);
    std::thread::sleep(Duration::from_millis(1));

    for value in items.iter() {
        items.binary_search(value);
        regex.is_match(value);
        fs::metadata(value);
        serde_json::Value::get(&json, value);
        bincode::serialized_size(value);
        reqwest::Client::new();
        ureq::Agent::new();
        std::thread::yield_now();
    }
    for row in [items] {
        for value in row {
            cache.lookup(value);
        }
    }
    while item.is_empty() {
        std::thread::sleep(Duration::from_millis(1));
    }
}
"#;

const RUST_DEFERRED_LEXICAL_POSITIVES: &str = r#"fn deferred(items: &[String]) {
    for _item in items {
        fn later() {
            let mut values = vec!["b", "a"];
            values.sort_unstable_by_key(|value| value.len());
            Regex::new("x");
            std::fs::read_to_string("input.txt");
            serde_json::to_vec("value");
            toml::from_str::<Value>("key = 'value'");
            ureq::get("https://example.invalid");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

fn nested_deferred(rows: &[Vec<String>]) {
    for row in rows {
        for _item in row {
            fn later() {
                fs::read("input.txt");
            }
        }
    }
}
"#;

const TSX_SORT_POSITIVE: &str = r#"export function SortedRows({ rows }: { rows: string[][] }) {
  for (const row of rows) {
    row.sort();
  }
  return <div>{rows.length}</div>;
}
"#;

const TSX_SORT_NEAR_MISS: &str = r#"export function StableRows({ rows }: { rows: string[][] }) {
  rows.sort();
  for (const row of rows) {
    row.toSorted();
  }
  return <div>{rows.length}</div>;
}
"#;

fn expected_finding_lines(policy_id: &str) -> BTreeMap<&'static str, Vec<u64>> {
    let findings: &[(&str, &[u64])] = match policy_id {
        "bifrost.correctness.dynamic-evaluation" => &[
            ("positive.py", &[9, 10]),
            ("positive.js", &[2, 3]),
            ("positive.ts", &[2, 3]),
        ],
        "bifrost.correctness.unsafe-deserialization" => &[("positive.py", &[13, 14])],
        "bifrost.performance.loop-invariant-sort" => &[
            ("positive.py", &[18]),
            ("deferred.py", &[10]),
            ("Positive.java", &[4]),
            ("Deferred.java", &[6]),
            ("positive.js", &[40]),
            ("positive.ts", &[20]),
            ("deferred.ts", &[4]),
            ("positive.rs", &[3, 4, 5, 6, 7, 8, 9]),
        ],
        "bifrost.performance.regex-compile-in-loop" => &[
            ("positive.py", &[19]),
            ("Positive.java", &[5]),
            ("positive.js", &[20]),
            ("positive.ts", &[21]),
            ("positive.rs", &[10]),
        ],
        "bifrost.performance.file-read-in-loop" => &[
            ("positive.py", &[20, 32]),
            ("Positive.java", &[6, 19]),
            ("positive.js", &[21]),
            ("positive.ts", &[22]),
            ("positive.rs", &[11, 12, 30, 31]),
        ],
        "bifrost.performance.serialization-in-loop" => &[
            ("positive.py", &[21]),
            ("Positive.java", &[7]),
            ("positive.js", &[22]),
            ("positive.ts", &[23]),
            ("positive.rs", &[13, 14, 15]),
        ],
        "bifrost.performance.parsing-in-loop" => &[
            ("positive.py", &[22]),
            ("Positive.java", &[8]),
            ("positive.js", &[23]),
            ("positive.ts", &[24, 34]),
            ("positive.rs", &[16, 17, 18, 19]),
        ],
        "bifrost.performance.database-call-in-loop" => &[
            ("positive.py", &[23]),
            ("Positive.java", &[9]),
            ("positive.js", &[24]),
            ("positive.ts", &[25]),
        ],
        "bifrost.performance.network-call-in-loop" => &[
            ("positive.py", &[24, 25]),
            ("Positive.java", &[10]),
            ("positive.js", &[25, 33]),
            ("positive.ts", &[26]),
            ("positive.rs", &[20, 21, 22]),
        ],
        "bifrost.performance.subprocess-in-loop" => &[
            ("positive.py", &[26]),
            ("Positive.java", &[11]),
            ("positive.js", &[26]),
            ("positive.ts", &[27]),
        ],
        "bifrost.performance.sleep-in-loop" => &[
            ("positive.py", &[27]),
            ("Positive.java", &[12]),
            ("positive.rs", &[23]),
        ],
        "bifrost.performance.expensive-operation-in-nested-loop" => &[
            ("positive.py", &[30]),
            ("deferred.py", &[21]),
            ("Positive.java", &[17]),
            ("Deferred.java", &[21]),
            ("positive.js", &[31]),
            ("deferred.js", &[16]),
            ("positive.ts", &[32]),
            ("deferred.ts", &[17]),
            ("positive.rs", &[28]),
            ("deferred.rs", &[17]),
        ],
        other => panic!("unexpected built-in policy {other}"),
    };
    findings
        .iter()
        .map(|(path, lines)| (*path, lines.to_vec()))
        .collect()
}

#[test]
fn code_smell_pack_matches_every_selector_alternative_and_excludes_near_misses() {
    let project = InlineTestProject::new()
        .file("positive.py", PYTHON_POSITIVES)
        .file("safe.py", PYTHON_NEAR_MISSES)
        .file("deferred.py", PYTHON_DEFERRED_LEXICAL_POSITIVES)
        .file("Positive.java", JAVA_POSITIVES)
        .file("Safe.java", JAVA_NEAR_MISSES)
        .file("Deferred.java", JAVA_DEFERRED_LEXICAL_POSITIVES)
        .file("positive.js", JAVASCRIPT_POSITIVES)
        .file("safe.js", JAVASCRIPT_NEAR_MISSES)
        .file("deferred.js", JAVASCRIPT_DEFERRED_LEXICAL_POSITIVES)
        .file("positive.ts", TYPESCRIPT_POSITIVES)
        .file("safe.ts", TYPESCRIPT_NEAR_MISSES)
        .file("deferred.ts", TYPESCRIPT_DEFERRED_LEXICAL_POSITIVES)
        .file("positive.rs", RUST_POSITIVES)
        .file("safe.rs", RUST_NEAR_MISSES)
        .file("deferred.rs", RUST_DEFERRED_LEXICAL_POSITIVES)
        .file("positive.tsx", TSX_SORT_POSITIVE)
        .file("safe.tsx", TSX_SORT_NEAR_MISS)
        .file("tsx/positive.tsx", TSX_SORT_POSITIVE)
        .file("tsx/safe.tsx", TSX_SORT_NEAR_MISS)
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
        let mut actual = BTreeMap::<_, Vec<_>>::new();
        for finding in run.findings() {
            actual.entry(finding.primary().path()).or_default().push(
                finding
                    .primary()
                    .region()
                    .expect("built-in match finding has a source region")
                    .start_line(),
            );
        }
        for lines in actual.values_mut() {
            lines.sort_unstable();
        }
        assert_eq!(
            actual,
            expected_finding_lines(run.policy_id().as_str()),
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
