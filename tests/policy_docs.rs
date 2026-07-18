mod common;

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use brokk_bifrost::Language;
use brokk_bifrost::policy::{
    PolicyFailOn, PolicySourceIdentity, evaluate_policy_files, parse_rqlp_source,
    validate_rqlp_source,
};
use common::InlineTestProject;
use serde_json::Value;

const POLICY_DOC: &str = "docs/src/content/docs/static-analysis-policies.md";

const REQUIRED_RQLP_FIXTURES: &[&str] = &[
    "tests/fixtures/policies/dynamic-eval.rqlp",
    "tests/fixtures/policies/attacker-controlled-to-sensitive-sinks.rqlp",
    "tests/fixtures/policies/resource-lifecycle.rqlp",
    "tests/fixtures/policies/endpoints/http-request-parameter.rqlp",
];

const REQUIRED_JSON_FRAGMENTS: &[(&str, &str)] = &[
    (
        "tests/fixtures/policies/endpoints/http-request-parameter.normalized.json",
        "/taint",
    ),
    (
        "tests/fixtures/policies/attacker-controlled-to-sensitive-sinks.normalized.json",
        "/analysis/finding_combinations/0",
    ),
    (
        "tests/fixtures/policies/resource-lifecycle.normalized.json",
        "/analysis/automaton/terminal_expectations",
    ),
];

#[derive(Debug)]
struct MarkedExample {
    kind: String,
    target: String,
    body: String,
    marker_line: usize,
}

#[test]
fn marked_rqlp_examples_match_checked_fixtures_and_validate() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let docs = read(root.join(POLICY_DOC));
    let examples = marked_examples(root.join(POLICY_DOC).as_path(), &docs);
    let mut found = HashSet::new();

    for example in examples.iter().filter(|example| example.kind == "rqlp") {
        assert!(
            found.insert(example.target.as_str()),
            "duplicate RQLP docs marker for {}",
            example.target
        );
        let fixture = read(root.join(&example.target));
        assert_eq!(
            example.body.trim_end(),
            fixture.trim_end(),
            "documented RQLP differs from {} at docs marker line {}",
            example.target,
            example.marker_line,
        );
        assert!(
            validate_rqlp_source(&example.body).is_empty(),
            "documented RQLP should validate: {}",
            example.target,
        );
        parse_rqlp_source(
            &example.body,
            PolicySourceIdentity::new(format!("docs:{}", example.target)),
        )
        .unwrap_or_else(|error| {
            panic!(
                "documented RQLP failed to parse at {:?}: {} ({})",
                error.diagnostic.range, error.diagnostic.message, error.diagnostic.code,
            )
        });
    }

    for required in REQUIRED_RQLP_FIXTURES {
        assert!(
            found.contains(required),
            "missing checked RQLP docs marker for {required}"
        );
    }
}

#[test]
fn marked_normalized_fragments_match_checked_golds() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let docs = read(root.join(POLICY_DOC));
    let examples = marked_examples(root.join(POLICY_DOC).as_path(), &docs);
    let mut found = HashSet::new();

    for example in examples.iter().filter(|example| example.kind == "json") {
        let (relative, pointer) = example.target.split_once('#').unwrap_or_else(|| {
            panic!(
                "JSON marker in {}:{} must use fixture.json#/pointer",
                POLICY_DOC, example.marker_line,
            )
        });
        assert!(
            found.insert((relative, pointer)),
            "duplicate JSON docs marker for {relative}#{pointer}"
        );
        let fixture: Value = serde_json::from_str(&read(root.join(relative)))
            .unwrap_or_else(|error| panic!("invalid checked JSON fixture {relative}: {error}"));
        let expected = fixture.pointer(pointer).unwrap_or_else(|| {
            panic!(
                "checked JSON fixture {relative} has no pointer {pointer} (docs line {})",
                example.marker_line,
            )
        });
        let documented: Value = serde_json::from_str(&example.body).unwrap_or_else(|error| {
            panic!(
                "invalid documented JSON in {}:{}: {error}",
                POLICY_DOC, example.marker_line,
            )
        });
        assert_eq!(
            &documented, expected,
            "documented JSON drifted from {relative}#{pointer}"
        );
    }

    for required in REQUIRED_JSON_FRAGMENTS {
        assert!(
            found.contains(required),
            "missing checked JSON docs marker for {}#{}",
            required.0,
            required.1,
        );
    }
}

#[test]
fn documented_match_policy_executes_and_future_analysis_boundary_is_explicit() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let docs = read(root.join(POLICY_DOC));
    let examples = marked_examples(root.join(POLICY_DOC).as_path(), &docs);
    let policy = examples
        .iter()
        .find(|example| {
            example.kind == "rqlp" && example.target == "tests/fixtures/policies/dynamic-eval.rqlp"
        })
        .expect("documented executable match policy");

    let workspace = InlineTestProject::with_language(Language::Python)
        .file(
            "app.py",
            "def run(user_code):\n    return eval(user_code)\n",
        )
        .file("policies/dynamic-eval.rqlp", policy.body.clone())
        .build();

    let outcome = evaluate_policy_files(
        workspace.root(),
        &[PathBuf::from("policies/dynamic-eval.rqlp")],
        false,
        PolicyFailOn::Warning,
    )
    .expect("documented match policy evaluation");
    let report = serde_json::to_value(outcome.report()).expect("canonical policy report");
    assert_eq!(outcome.exit_status(), 1);
    assert_eq!(report["runs"][0]["completion"]["type"], "complete");
    assert_eq!(report["runs"][0]["findings"].as_array().unwrap().len(), 1);
    assert_eq!(
        report["runs"][0]["findings"][0]["policy_id"],
        "bifrost.security.dynamic-eval"
    );

    let unsupported_sentence = "evaluation reports `unsupported` until [#824](https://github.com/BrokkAi/bifrost/issues/824)";
    assert_eq!(
        docs.matches(unsupported_sentence).count(),
        2,
        "taint and typestate rows must both state the #824 execution boundary"
    );
    const REACHABILITY_WARNING: &str = "> **Important:** An RQL selector returns analysis candidates. An endpoint\n\
> selector match is diagnostic-neutral. Neither an endpoint match nor the\n\
> co-presence of a source and sink proves reachability, and neither creates a\n\
> finding by itself.";
    assert!(docs.contains(REACHABILITY_WARNING));
    for required_case in [
        "| Omitted | Native query with no version envelope | Resolve the latest compatible RQL version (currently 2); the version is inferred. |",
        "| Exact pin `N` | Native query with no version envelope | Use exact `N`; the wrapper supplies the explicit pin. |",
        "| Omitted | `(rql :schema-version N QUERY)` | Use exact `N`; the referenced document supplies the explicit pin. |",
        "| Exact pin `N` | `(rql :schema-version N QUERY)` | Use exact `N`; the agreeing referenced-document pin is retained as the resolution origin. |",
    ] {
        assert!(
            docs.contains(required_case),
            "policy docs must retain the rql-file version case: {required_case}"
        );
    }
    let normalized_docs = docs.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(normalized_docs.contains("JSON is not accepted as `.rqlp` source in any role."));
    assert!(normalized_docs.contains(
        "The directory semantic-hash projection contains its selection predicate plus only the selected endpoint identities and their full semantic hashes."
    ));
    assert!(normalized_docs.contains(
        "A policy which uses only `(match-endpoints :ids [...])` likewise needs an embedding to pre-register those endpoint IDs."
    ));
    assert!(normalized_docs.contains(
        "The policy report does not currently record the analyzer version, workspace root/revision, or configured budget maxima;"
    ));
}

fn marked_examples(path: &Path, contents: &str) -> Vec<MarkedExample> {
    let lines = contents.lines().collect::<Vec<_>>();
    let mut examples = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index].trim();
        let Some(marker) = line
            .strip_prefix("<!-- policy-doc-test:")
            .and_then(|value| value.strip_suffix(" -->"))
        else {
            index += 1;
            continue;
        };
        let (kind, target) = marker.split_once(':').unwrap_or_else(|| {
            panic!(
                "malformed policy docs marker in {}:{}",
                path.display(),
                index + 1,
            )
        });
        let expected_fence = match kind {
            "rqlp" => "```lisp",
            "json" => "```json",
            other => panic!(
                "unknown policy docs marker kind {other:?} in {}:{}",
                path.display(),
                index + 1,
            ),
        };
        let fence_index = index + 1;
        assert_eq!(
            lines.get(fence_index).map(|value| value.trim()),
            Some(expected_fence),
            "marker in {}:{} must be immediately followed by {expected_fence}",
            path.display(),
            index + 1,
        );
        index = fence_index + 1;
        let mut body = Vec::new();
        while index < lines.len() && lines[index].trim() != "```" {
            body.push(lines[index]);
            index += 1;
        }
        assert!(
            index < lines.len(),
            "unterminated policy docs example in {}:{}",
            path.display(),
            fence_index + 1,
        );
        examples.push(MarkedExample {
            kind: kind.to_string(),
            target: target.to_string(),
            body: body.join("\n"),
            marker_line: fence_index + 1,
        });
        index += 1;
    }
    examples
}

fn read(path: impl AsRef<Path>) -> String {
    let path = path.as_ref();
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}
