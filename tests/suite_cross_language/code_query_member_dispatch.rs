//! Cross-language conformance for the #1477 member-selection rows.
//!
//! Every fixture pairs a positive with a realistic near miss (same-name wrong
//! owner). The invariants under test are the milestone's acceptance rules:
//! the selection summary is mandatory and agrees with the production trace,
//! `member_targets` equals the projection of selected candidate rows, and
//! `canonical_member_id` distinguishes same-spelling decoys by structured
//! identity rather than rendered names.

use crate::common::InlineTestProject;
use brokk_bifrost::analyzer::structural::{CodeQuery, CodeQueryResult, execute_workspace};
use brokk_bifrost::{AnalyzerConfig, WorkspaceAnalyzer};
use serde_json::{Value, json};

fn run(files: &[(&str, &str)], query: Value) -> CodeQueryResult {
    let mut project = InlineTestProject::new();
    for (path, source) in files {
        project = project.file(*path, *source);
    }
    let project = project.build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&query).expect("query should parse");
    execute_workspace(&workspace, &query)
}

fn serialized(result: &CodeQueryResult) -> Value {
    serde_json::to_value(result).expect("query result should serialize")
}

fn rows(value: &Value) -> &Vec<Value> {
    value["results"].as_array().expect("results array")
}

/// Selection summary, candidates, and `member_targets` agree on a fixture
/// with a same-name wrong-owner decoy: the summary selects, the selected
/// candidate rows carry canonical identity, and `member_targets` returns
/// exactly the selected candidates' declarations.
#[test]
fn typescript_selection_summary_candidates_and_member_targets_agree() {
    let files = [(
        "app.ts",
        r#"class Service { run() {} }
class Decoy { run() {} }
export function caller(service: Service) { service.run(); }
"#,
    )];
    let occurrence_query = |step: Value| {
        json!({
            "where": ["app.ts"],
            "occurrences": { "role": ["member_position"] },
            "steps": [step],
            "result_detail": "full"
        })
    };

    let selection = serialized(&run(
        &files,
        occurrence_query(json!({"op": "member_selection"})),
    ));
    assert_eq!(rows(&selection).len(), 1, "{selection}");
    let summary = &rows(&selection)[0];
    assert_eq!(summary["result_type"], "member_selection", "{selection}");
    assert_eq!(summary["member"], "run", "{selection}");
    assert_eq!(summary["outcome"], "selected", "{selection}");
    let selected_count = summary["selected_count"].as_u64().expect("selected_count");
    assert!(selected_count >= 1, "{selection}");

    let candidates = serialized(&run(
        &files,
        occurrence_query(json!({"op": "candidates_of"})),
    ));
    let selected = rows(&candidates)
        .iter()
        .filter(|row| row["outcome"] == "selected")
        .collect::<Vec<_>>();
    assert_eq!(selected.len() as u64, selected_count, "{candidates}");
    for row in &selected {
        assert!(
            row["canonical_member_id"].as_str().is_some(),
            "a unit-backed selected candidate carries its canonical identity digest: {row}"
        );
        assert_eq!(row["ast_id"], summary["site_ast_id"], "{candidates}");
        assert_eq!(
            row["candidate"]["unit"]["fq_name"], "Service.run",
            "the winner belongs to the receiver's owner, not the decoy: {row}"
        );
    }

    // `member_targets` is the same selection: its declarations equal the
    // selected candidates' declarations, and the decoy never appears.
    let targets = serialized(&run(
        &files,
        occurrence_query(json!({"op": "member_targets"})),
    ));
    let target_fq_names = rows(&targets)
        .iter()
        .flat_map(|row| row["member_targets"].as_array().into_iter().flatten())
        .map(|target| target["fq_name"].as_str().expect("fq_name").to_string())
        .collect::<Vec<_>>();
    let mut selected_fq_names = selected
        .iter()
        .map(|row| {
            row["candidate"]["unit"]["fq_name"]
                .as_str()
                .expect("fq_name")
                .to_string()
        })
        .collect::<Vec<_>>();
    selected_fq_names.sort();
    selected_fq_names.dedup();
    let mut sorted_targets = target_fq_names.clone();
    sorted_targets.sort();
    sorted_targets.dedup();
    assert_eq!(
        sorted_targets, selected_fq_names,
        "member_targets equals the selected-candidate projection: {targets}"
    );
    assert!(
        !target_fq_names.iter().any(|name| name.contains("Decoy")),
        "{targets}"
    );
}

/// Same-spelling members of different owners have distinct canonical
/// identity digests, so a count-distinct winner invariant can never merge a
/// decoy into the winner.
#[test]
fn canonical_member_ids_distinguish_same_spelling_owners() {
    let files = [(
        "app.ts",
        r#"class Service { run() {} }
class Decoy { run() {} }
export function caller(service: Service, decoy: Decoy) {
  service.run();
  decoy.run();
}
"#,
    )];
    let candidates = serialized(&run(
        &files,
        json!({
            "where": ["app.ts"],
            "occurrences": { "role": ["member_position"] },
            "steps": [{"op": "candidates_of"}],
            "result_detail": "full"
        }),
    ));
    let selected_ids = rows(&candidates)
        .iter()
        .filter(|row| row["outcome"] == "selected")
        .filter_map(|row| {
            Some((
                row["candidate"]["unit"]["fq_name"].as_str()?.to_string(),
                row["canonical_member_id"].as_str()?.to_string(),
            ))
        })
        .collect::<Vec<_>>();
    let service = selected_ids
        .iter()
        .find(|(fq_name, _)| fq_name == "Service.run")
        .expect("Service.run selected");
    let decoy = selected_ids
        .iter()
        .find(|(fq_name, _)| fq_name == "Decoy.run")
        .expect("Decoy.run selected");
    assert_ne!(
        service.1, decoy.1,
        "same-spelling members of different owners have distinct canonical identity"
    );
}

/// Every language family emits the mandatory selection summary for a member
/// occurrence with a same-name wrong-owner decoy present, and its stated
/// completeness/coverage pairing is honest. A language whose adapter records
/// no trace must say `untraced`/`unsupported`, never a proven-empty set, and
/// a selecting language must never select the decoy.
#[test]
fn every_language_family_emits_an_honest_mandatory_selection_summary() {
    let fixtures: &[(&str, &str, &str)] = &[
        (
            "typescript",
            "app.ts",
            "class Service { run() {} }\nclass Decoy { run() {} }\nexport function caller(service: Service) { service.run(); }\n",
        ),
        (
            "go",
            "app.go",
            "package main\n\ntype Service struct{}\n\nfunc (s Service) Run() {}\n\ntype Decoy struct{}\n\nfunc (d Decoy) Run() {}\n\nfunc caller(s Service) { s.Run() }\n",
        ),
        (
            "csharp",
            "App.cs",
            "namespace Demo;\npublic class Service { public void Run() {} }\npublic class Decoy { public void Run() {} }\npublic class Caller { public void Call(Service service) { service.Run(); } }\n",
        ),
        (
            "python",
            "app.py",
            "class Service:\n    def run(self):\n        pass\n\nclass Decoy:\n    def run(self):\n        pass\n\ndef caller(service: Service):\n    service.run()\n",
        ),
        (
            "rust",
            "app.rs",
            "struct Service;\nimpl Service { fn run(&self) {} }\nstruct Decoy;\nimpl Decoy { fn run(&self) {} }\nfn caller(service: Service) { service.run(); }\n",
        ),
        (
            "cpp",
            "app.cpp",
            "class Service { public: void run() {} };\nclass Decoy { public: void run() {} };\nvoid caller(Service service) { service.run(); }\n",
        ),
        (
            "php",
            "app.php",
            "<?php\nclass Service { public function run() {} }\nclass Decoy { public function run() {} }\nfunction caller(Service $service) { $service->run(); }\n",
        ),
        (
            "ruby",
            "app.rb",
            "class Service\n  def run\n  end\nend\n\nclass Decoy\n  def run\n  end\nend\n\ndef caller(service)\n  service.run\nend\n",
        ),
    ];
    for (language, path, source) in fixtures {
        let files = [(*path, *source)];
        let selection = serialized(&run(
            &files,
            json!({
                "where": [path],
                "occurrences": { "role": ["member_position"] },
                "steps": [{"op": "member_selection"}],
                "result_detail": "full"
            }),
        ));
        let summaries = rows(&selection);
        if summaries.is_empty() {
            // A language whose structural adapter does not classify
            // member-position occurrences at all has no site to summarize.
            // That gap must be *stated* through an incomplete diagnostic --
            // which is what turns a policy over these rows unreliable --
            // never a silent empty result.
            let role_unsupported = selection["diagnostics"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|diagnostic| {
                    diagnostic["code"] == "occurrence_role_unsupported"
                        && diagnostic["impact"] == "incomplete"
                });
            assert!(
                role_unsupported,
                "{language}: zero summaries require a stated occurrence-role capability gap: {selection}"
            );
            continue;
        }
        for summary in summaries {
            let completeness = summary["trace_completeness"]
                .as_str()
                .unwrap_or_else(|| panic!("{language}: completeness missing: {selection}"));
            match completeness {
                "full" => assert_eq!(summary["coverage"], "exhaustive", "{language}: {selection}"),
                "selection_only" => {
                    assert_eq!(summary["coverage"], "open", "{language}: {selection}")
                }
                "absent" => {
                    assert_eq!(
                        summary["coverage"], "unsupported",
                        "{language}: {selection}"
                    );
                    assert_eq!(summary["outcome"], "untraced", "{language}: {selection}");
                    assert_eq!(summary["selected_count"], 0, "{language}: {selection}");
                }
                other => panic!("{language}: unregistered completeness {other:?}: {selection}"),
            }
            if summary["outcome"] == "selected" {
                let candidates = serialized(&run(
                    &files,
                    json!({
                        "where": [path],
                        "occurrences": { "role": ["member_position"] },
                        "steps": [{"op": "candidates_of"}],
                        "result_detail": "full"
                    }),
                ));
                assert!(
                    rows(&candidates)
                        .iter()
                        .filter(|row| row["outcome"] == "selected"
                            && row["ast_id"] == summary["site_ast_id"])
                        .all(|row| {
                            row["candidate"]["unit"]["fq_name"]
                                .as_str()
                                .is_none_or(|name| !name.contains("Decoy"))
                        }),
                    "{language}: the wrong-owner decoy must never be selected: {candidates}"
                );
            }
        }
    }
}

/// Java: the summary row is mandatory and joins its candidates by AST
/// identity, with an inherited-member fixture and a same-name decoy.
#[test]
fn java_selection_summary_is_mandatory_and_joined_by_ast_identity() {
    let files = [(
        "App.java",
        r#"class Base { void run() {} }
class Service extends Base { }
class Decoy { void run() {} }
class Caller {
    void call(Service service) { service.run(); }
}
"#,
    )];
    let selection = serialized(&run(
        &files,
        json!({
            "where": ["App.java"],
            "occurrences": { "role": ["member_position"] },
            "steps": [{"op": "member_selection"}],
            "result_detail": "full"
        }),
    ));
    assert_eq!(rows(&selection).len(), 1, "{selection}");
    let summary = &rows(&selection)[0];
    assert_eq!(summary["member"], "run", "{selection}");
    // Whatever the Java adapter records (a full trace, a selection-only
    // trace, or none), the summary states it honestly instead of omitting
    // the row.
    let completeness = summary["trace_completeness"]
        .as_str()
        .expect("completeness");
    match completeness {
        "full" => assert_eq!(summary["coverage"], "exhaustive", "{selection}"),
        "selection_only" => assert_eq!(summary["coverage"], "open", "{selection}"),
        "absent" => {
            assert_eq!(summary["coverage"], "unsupported", "{selection}");
            assert_eq!(summary["outcome"], "untraced", "{selection}");
        }
        other => panic!("unregistered trace completeness {other:?}: {selection}"),
    }
    if summary["outcome"] == "selected" {
        let candidates = serialized(&run(
            &files,
            json!({
                "where": ["App.java"],
                "occurrences": { "role": ["member_position"] },
                "steps": [{"op": "candidates_of"}],
                "result_detail": "full"
            }),
        ));
        let selected = rows(&candidates)
            .iter()
            .filter(|row| row["outcome"] == "selected")
            .collect::<Vec<_>>();
        assert_eq!(
            selected.len() as u64,
            summary["selected_count"].as_u64().expect("count"),
            "{candidates}"
        );
        assert!(
            selected
                .iter()
                .all(|row| row["ast_id"] == summary["site_ast_id"]),
            "{candidates}"
        );
        assert!(
            selected
                .iter()
                .all(|row| row["candidate"]["unit"]["fq_name"] != "Decoy.run"),
            "the decoy owner never wins: {candidates}"
        );
    }
}
