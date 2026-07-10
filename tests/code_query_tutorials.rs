mod common;

use brokk_bifrost::analyzer::structural::{CodeQuery, execute};
use brokk_bifrost::{AnalyzerConfig, WorkspaceAnalyzer};
use common::InlineTestProject;
use pretty_assertions::assert_eq;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Debug)]
struct Tutorial {
    fixtures: Vec<Fixture>,
    cases: BTreeMap<String, TutorialCase>,
    verified_on: String,
}

#[derive(Debug)]
struct Fixture {
    path: String,
    source: String,
}

#[derive(Debug, Default)]
struct TutorialCase {
    rql: Option<String>,
    json: Option<String>,
    expected: Option<String>,
}

#[test]
fn executable_tutorial_marker_contract_runs_end_to_end() {
    let markdown = r#"
> Last verified end to end: 2026-07-10 (`query_code` schema version 1).

<!-- code-query-fixture:sample.py -->
```python
def audit(value):
    return value

audit("ok")
```

<!-- code-query-case:audit:rql -->
```lisp
(language python (call :callee (name "audit") :args [(capture "value")]))
```

<!-- code-query-case:audit:json -->
```json
{"languages":["python"],"match":{"kind":"call","callee":{"name":"audit"},"args":[{"capture":"value"}]}}
```

<!-- code-query-case:audit:expected -->
```json
{"matches":[{"path":"sample.py","language":"python","kind":"call","start_line":4,"end_line":4,"text":"audit(\"ok\")","captures":[{"name":"value","text":"\"ok\"","start_line":4}],"enclosing_symbol":"sample"}],"truncated":false}
```
"#;

    verify_tutorial_contents(Path::new("embedded-marker-contract.md"), markdown);
}

#[test]
fn python_tutorial() {
    verify_tutorial("docs/src/content/docs/code-query-tutorials/python.md");
}

#[test]
fn java_tutorial() {
    verify_tutorial("docs/src/content/docs/code-query-tutorials/java.md");
}

#[test]
fn javascript_tutorial() {
    verify_tutorial("docs/src/content/docs/code-query-tutorials/javascript.md");
}

#[test]
fn typescript_tutorial() {
    verify_tutorial("docs/src/content/docs/code-query-tutorials/typescript.md");
}

#[test]
fn go_tutorial() {
    verify_tutorial("docs/src/content/docs/code-query-tutorials/go.md");
}

#[test]
fn cpp_tutorial() {
    verify_tutorial("docs/src/content/docs/code-query-tutorials/cpp.md");
}

#[test]
fn rust_tutorial() {
    verify_tutorial("docs/src/content/docs/code-query-tutorials/rust.md");
}

#[test]
fn php_tutorial() {
    verify_tutorial("docs/src/content/docs/code-query-tutorials/php.md");
}

#[allow(dead_code)]
fn verify_tutorial(relative: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    let markdown = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    verify_tutorial_contents(&path, &markdown);
}

fn verify_tutorial_contents(path: &Path, markdown: &str) {
    let tutorial = parse_tutorial(path, markdown);
    assert_valid_date(path, &tutorial.verified_on);
    assert!(
        !tutorial.fixtures.is_empty(),
        "{} has no fixtures",
        path.display()
    );
    assert!(
        !tutorial.cases.is_empty(),
        "{} has no cases",
        path.display()
    );

    let mut project = InlineTestProject::new();
    for fixture in &tutorial.fixtures {
        project = project.file(&fixture.path, &fixture.source);
    }
    let project = project.build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());

    let mut missing_expectations = Vec::new();
    for (id, case) in &tutorial.cases {
        let rql = required_block(path, id, "rql", &case.rql);
        let json = required_block(path, id, "json", &case.json);
        let expected = required_block(path, id, "expected", &case.expected);

        let rql_query = CodeQuery::from_sexp(rql).unwrap_or_else(|error| {
            panic!(
                "invalid RQL case {id:?} in {}: {error}\n{rql}",
                path.display()
            )
        });
        let json_value: Value = serde_json::from_str(json).unwrap_or_else(|error| {
            panic!(
                "invalid JSON case {id:?} in {}: {error}\n{json}",
                path.display()
            )
        });
        let json_query = CodeQuery::from_json(&json_value).unwrap_or_else(|error| {
            panic!(
                "invalid CodeQuery case {id:?} in {}: {error}\n{json}",
                path.display()
            )
        });
        assert_eq!(
            rql_query.to_canonical_json(),
            json_query.to_canonical_json(),
            "RQL and JSON differ for case {id:?} in {}",
            path.display()
        );

        let rql_result = serde_json::to_value(execute(workspace.analyzer(), &rql_query))
            .expect("serialize RQL result");
        let json_result = serde_json::to_value(execute(workspace.analyzer(), &json_query))
            .expect("serialize JSON result");
        assert_eq!(
            rql_result,
            json_result,
            "RQL and JSON execution differ for case {id:?} in {}",
            path.display()
        );

        let expected_value: Value = serde_json::from_str(expected).unwrap_or_else(|error| {
            panic!(
                "invalid expected JSON for case {id:?} in {}: {error}\n{expected}",
                path.display()
            )
        });
        if expected_value.is_null() {
            eprintln!(
                "generated expectation for {id:?} in {}:\n{}",
                path.display(),
                serde_json::to_string_pretty(&json_result).expect("pretty-print result")
            );
            missing_expectations.push(id.as_str());
            continue;
        }
        assert_eq!(
            json_result,
            expected_value,
            "documented output differs for case {id:?} in {}",
            path.display()
        );
    }
    assert!(
        missing_expectations.is_empty(),
        "{} has generated but undocumented expectations for: {}",
        path.display(),
        missing_expectations.join(", ")
    );
}

fn parse_tutorial(path: &Path, markdown: &str) -> Tutorial {
    let verified_on = markdown
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("> Last verified end to end: ")
                .and_then(|rest| rest.strip_suffix(" (`query_code` schema version 1)."))
        })
        .unwrap_or_else(|| panic!("{} has no last-verified note", path.display()))
        .to_string();

    let lines = markdown.lines().collect::<Vec<_>>();
    let mut fixtures = Vec::new();
    let mut cases: BTreeMap<String, TutorialCase> = BTreeMap::new();
    let mut index = 0;
    while index < lines.len() {
        let marker = lines[index].trim();
        if let Some(fixture_path) = marker
            .strip_prefix("<!-- code-query-fixture:")
            .and_then(|rest| rest.strip_suffix(" -->"))
        {
            let (body, next) = fenced_body(path, &lines, index);
            fixtures.push(Fixture {
                path: fixture_path.to_string(),
                source: body,
            });
            index = next;
            continue;
        }
        if let Some(case_marker) = marker
            .strip_prefix("<!-- code-query-case:")
            .and_then(|rest| rest.strip_suffix(" -->"))
        {
            let (id, format) = case_marker.split_once(':').unwrap_or_else(|| {
                panic!("malformed case marker in {}:{}", path.display(), index + 1)
            });
            let (body, next) = fenced_body(path, &lines, index);
            let case = cases.entry(id.to_string()).or_default();
            let slot = match format {
                "rql" => &mut case.rql,
                "json" => &mut case.json,
                "expected" => &mut case.expected,
                other => panic!(
                    "unknown case format {other:?} in {}:{}",
                    path.display(),
                    index + 1
                ),
            };
            assert!(
                slot.replace(body).is_none(),
                "duplicate {format} block for case {id:?} in {}",
                path.display()
            );
            index = next;
            continue;
        }
        index += 1;
    }

    Tutorial {
        fixtures,
        cases,
        verified_on,
    }
}

fn fenced_body(path: &Path, lines: &[&str], marker_index: usize) -> (String, usize) {
    let fence_index = marker_index + 1;
    let fence = lines
        .get(fence_index)
        .unwrap_or_else(|| panic!("marker at end of {}", path.display()))
        .trim();
    assert!(
        fence.starts_with("```") && fence.len() > 3,
        "marker in {}:{} must be followed by a typed code fence",
        path.display(),
        marker_index + 1
    );
    let mut body = Vec::new();
    let mut index = fence_index + 1;
    while index < lines.len() && lines[index].trim() != "```" {
        body.push(lines[index]);
        index += 1;
    }
    assert!(
        index < lines.len(),
        "unterminated fence in {}:{}",
        path.display(),
        fence_index + 1
    );
    (body.join("\n"), index + 1)
}

fn required_block<'a>(path: &Path, id: &str, format: &str, value: &'a Option<String>) -> &'a str {
    value
        .as_deref()
        .unwrap_or_else(|| panic!("case {id:?} in {} has no {format} block", path.display()))
}

fn assert_valid_date(path: &Path, date: &str) {
    let bytes = date.as_bytes();
    let valid = bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit());
    assert!(
        valid,
        "invalid verification date {date:?} in {}",
        path.display()
    );
}
