use super::*;
use crate::structural::search::units::{
    CodeQueryExecutionScope, execute_code_query_unit, merge_unit_rows, plan_seed_files,
};
use brokk_bifrost_test_macros::hardwon;

#[test]
#[hardwon(
    "#11321: incoming relations and references_of lost pre-charge file and source-byte refusals"
)]
fn budget_telemetry_preserves_legacy_incoming_admission_causes() {
    let seed_source = "export function target() {}\n";
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file("target.js", seed_source)
        .file(
            "a.js",
            "import { target } from './target.js'; export function a() { target(); }\n",
        )
        .file(
            "b.js",
            "import { target } from './target.js'; export function b() { target(); }\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let scope = AnalyzerQueryScope::new(analyzer);
    let target = analyzer
        .get_all_declarations()
        .into_iter()
        .find(|unit| unit.identifier() == "target")
        .unwrap();
    for (files, bytes, file_cut, byte_cut) in [
        (1, usize::MAX, true, false),
        (usize::MAX, 1, false, true),
        (1, 1, true, true),
    ] {
        let query = UsageFinder::new().query_with_source_budget(
            analyzer,
            std::slice::from_ref(&target),
            files,
            16,
            bytes,
        );
        assert_eq!(query.candidate_files_budget_exhausted, file_cut);
        assert_eq!(query.source_byte_refusal.is_some(), byte_cut);
        assert!(query.unavailable_sources.is_empty());
        let reference_query = CodeQuery::from_json(&json!({
            "where": ["target.js"],
            "match": {"kind": "callable", "name": "target"},
            "steps": [{"op": "enclosing_decl"}, {"op": "references_of"}]
        }))
        .unwrap();
        let response = execute_request_with_limits(
            analyzer,
            &reference_query,
            CodeQueryExecutionLimits {
                max_scanned_files: files.saturating_add(1),
                max_scanned_source_bytes: bytes.saturating_add(seed_source.len()),
                ..CodeQueryExecutionLimits::default()
            },
        );
        let result = response.result().unwrap();
        assert!(result.truncated, "{result:?}");
        let roots = result
            .diagnostics
            .iter()
            .flat_map(|diagnostic| &semantic_diagnostic(diagnostic).exhausted_roots)
            // Rendering can hit shared caps too; isolate provider admission.
            .filter(|root| root.stage.as_deref() == Some("reference_scan"))
            .collect::<Vec<_>>();
        assert_eq!(
            roots.iter().any(|root| root.lane == "query/scanned_files"),
            file_cut,
            "{result:?}"
        );
        assert_eq!(
            roots
                .iter()
                .any(|root| root.lane == "query/scanned_source_bytes"),
            byte_cut,
            "{result:?}"
        );
        if byte_cut {
            let root = roots
                .iter()
                .find(|root| root.lane == "query/scanned_source_bytes")
                .unwrap();
            assert_eq!(root.budget.unwrap().consumed, seed_source.len());
            assert_eq!(root.budget.unwrap().limit, seed_source.len() + 1);
            assert_eq!(
                root.charge.unwrap().attempted,
                seed_source.len() + query.source_byte_refusal.unwrap().1
            );
            assert_eq!(root.charge.unwrap().limit, seed_source.len() + 1);
        }
        let result = CallRelationService::incoming_bounded(
            analyzer,
            scope.token(),
            &target,
            CallRelationLimits {
                max_files: files,
                max_source_bytes: bytes,
                max_candidates: 16,
            },
            None,
        );
        if file_cut {
            assert!(
                result
                    .budget_refusals
                    .contains(&CallRelationBudgetRefusal::Files {
                        consumed: files,
                        limit: files
                    }),
                "{result:?}"
            );
        } else {
            assert!(
                !result
                    .budget_refusals
                    .iter()
                    .any(|r| matches!(r, CallRelationBudgetRefusal::Files { .. })),
                "{result:?}"
            );
        }
        if let Some((consumed, attempted, limit)) = query.source_byte_refusal {
            assert!(attempted > limit);
            assert!(
                result
                    .budget_refusals
                    .contains(&CallRelationBudgetRefusal::SourceBytes {
                        consumed,
                        attempted,
                        limit
                    }),
                "{result:?}"
            );
        } else {
            assert!(
                !result
                    .budget_refusals
                    .iter()
                    .any(|r| matches!(r, CallRelationBudgetRefusal::SourceBytes { .. })),
                "{result:?}"
            );
        }
    }
}

#[test]
#[hardwon(
    "#11321: outgoing candidate retention lost its refusal at exactly the allowed work count"
)]
fn budget_telemetry_preserves_legacy_outgoing_candidate_refusal() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "calls.js",
            "function callee() {}\nfunction caller() { callee(); callee(); }\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let scope = AnalyzerQueryScope::new(analyzer);
    let caller = analyzer
        .get_all_declarations()
        .into_iter()
        .find(|unit| unit.short_name() == "caller")
        .expect("fixture caller");
    for limit in [1, 2] {
        let relation = CallRelationService::outgoing_bounded(
            analyzer,
            scope.token(),
            &caller,
            CallRelationLimits {
                max_files: 1,
                max_source_bytes: usize::MAX,
                max_candidates: limit,
            },
            None,
        );
        assert_eq!(relation.work.examined_candidates, limit, "{relation:?}");
        assert_eq!(relation.truncated, limit == 1, "{relation:?}");
        if limit == 1 {
            assert_eq!(
                relation.budget_refusals,
                [CallRelationBudgetRefusal::Candidates {
                    consumed: 1,
                    limit: 1
                }]
            );
            let mut diagnostics = Vec::new();
            push_call_relation_budget_diagnostics(
                &mut diagnostics,
                &CodeQueryExecutionBudget::default(),
                CodeQueryExecutionLimits {
                    max_fact_nodes: limit,
                    ..CodeQueryExecutionLimits::default()
                },
                &CodeQueryExecutionBudget::default(),
                &relation.budget_refusals,
            );
            let roots = &diagnostics[0].exhausted_roots;
            assert_eq!(roots.len(), 1);
            assert_eq!(roots[0].lane, "query/fact_nodes");
            assert_eq!(roots[0].stage.as_deref(), Some("call_relation"));
            assert_eq!(
                roots[0].budget,
                Some(CodeQueryExhaustedBudget {
                    consumed: 1,
                    limit: 1
                })
            );
            assert!(roots[0].charge.is_none());
        } else {
            assert!(relation.budget_refusals.is_empty(), "{relation:?}");
        }
    }
}

#[test]
#[hardwon("#11321: an in-file call byte refusal consumed no work and lost its refused lane")]
fn budget_telemetry_preserves_in_file_source_byte_refusal() {
    let seed_source = "mod caller;\npub fn target() {}\n";
    let caller_source = "pub fn caller() { crate::target(); crate::target(); }\n";
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"byte_refusal\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file("src/lib.rs", seed_source)
        .file("src/caller.rs", caller_source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "where": ["src/lib.rs"],
        "languages": ["rust"],
        "match": {"kind": "callable", "name": "target"},
        "steps": [{"op": "enclosing_decl"}, {"op": "call_sites_to"}]
    }))
    .unwrap();
    let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
    let files = workspace.analyzer().analyzed_files();
    let caller = project.file("src/caller.rs");
    let limit = seed_source.len() + 1;
    let unit = execute_code_query_unit(
        workspace.analyzer(),
        &flow,
        Some(&workspace),
        &query,
        CodeQueryExecutionLimits {
            max_scanned_source_bytes: limit,
            ..CodeQueryExecutionLimits::default()
        },
        None,
        CodeQueryExecutionScope::for_reverse_entered_file(&caller, &files),
    );
    assert!(unit.truncated, "{unit:?}");
    let roots = unit
        .diagnostics
        .iter()
        .flat_map(|diagnostic| &diagnostic.exhausted_roots)
        .collect::<Vec<_>>();
    assert_eq!(roots.len(), 1, "{unit:?}");
    assert_eq!(roots[0].lane, "query/scanned_source_bytes");
    assert_eq!(roots[0].stage.as_deref(), Some("call_relation"));
    let consumed = roots[0].budget.unwrap();
    assert_eq!(consumed.consumed, seed_source.len());
    assert_eq!(
        consumed.consumed,
        usize::try_from(unit.work.scanned_source_bytes).unwrap()
    );
    let charge = roots[0].charge.as_ref().unwrap();
    assert_eq!(consumed.limit, limit);
    assert_eq!(charge.attempted, seed_source.len() + caller_source.len());
    assert_eq!(charge.limit, limit);
}

#[test]
#[hardwon(
    "#11321: later incoming batch targets used the batch start instead of their own allowance"
)]
fn budget_telemetry_offsets_each_in_file_batch_target() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("Cargo.toml", "[package]\nname = \"batch_refusal\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
        .file("src/lib.rs", "mod caller; pub fn a() {} pub fn b() {}\n")
        .file("src/caller.rs", "pub fn caller() { crate::a(); crate::a(); crate::a(); crate::a(); crate::a(); crate::b(); crate::b(); crate::b(); crate::b(); crate::b(); crate::b(); }\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let scope = AnalyzerQueryScope::new(analyzer);
    let mut targets = analyzer
        .get_all_declarations()
        .into_iter()
        .filter(|unit| matches!(unit.short_name(), "a" | "b"))
        .collect::<Vec<_>>();
    targets.sort_by(|left, right| left.short_name().cmp(right.short_name()));
    assert_eq!(targets.len(), 2);
    let caller = project.file("src/caller.rs");
    let answers = CallRelationService::incoming_in_file(
        analyzer,
        scope.token(),
        &caller,
        &targets,
        CallRelationLimits {
            max_candidates: 10,
            max_files: 100,
            max_source_bytes: usize::MAX,
        },
        None,
    )
    .unwrap();
    assert_eq!(answers[0].work.examined_candidates, 5);
    assert_eq!(answers[1].work.examined_candidates, 5);
    assert_eq!(
        answers[1].budget_refusals,
        [CallRelationBudgetRefusal::Candidates {
            consumed: 5,
            limit: 5
        }]
    );

    let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
    let files = analyzer.analyzed_files();
    let mut query_json = json!({ "where": ["src/lib.rs"], "languages": ["rust"],
        "match": {"kind": "callable"}, "steps": [{"op": "enclosing_decl"}] });
    let seed_query = CodeQuery::from_json(&query_json).unwrap();
    let seeds = execute_code_query_unit(
        analyzer,
        &flow,
        Some(&workspace),
        &seed_query,
        CodeQueryExecutionLimits::default(),
        None,
        CodeQueryExecutionScope::for_seed_files(&files, &files),
    );
    assert!(!seeds.truncated, "{seeds:?}");
    query_json["steps"]
        .as_array_mut()
        .unwrap()
        .push(json!({"op": "call_sites_to"}));
    let query = CodeQuery::from_json(&query_json).unwrap();
    let complete = execute_code_query_unit(
        analyzer,
        &flow,
        Some(&workspace),
        &query,
        CodeQueryExecutionLimits::default(),
        None,
        CodeQueryExecutionScope::for_reverse_entered_file(&caller, &files),
    );
    assert!(!complete.truncated, "{complete:?}");
    let attempted = usize::try_from(complete.budgeted_work.admission.call_answers).unwrap();
    // Leave the first target whole and clip sites inside the later target.
    let limit = attempted - targets.len();
    let later_target_sites = complete.rows.len() - answers[0].sites.len();
    // Both target declarations and the first target's sites precede this charge.
    let consumed = attempted - later_target_sites;
    assert!(consumed < limit && limit < attempted);
    let unit = execute_code_query_unit(
        analyzer,
        &flow,
        Some(&workspace),
        &query,
        CodeQueryExecutionLimits {
            max_call_answers: limit,
            ..CodeQueryExecutionLimits::default()
        },
        None,
        CodeQueryExecutionScope::for_reverse_entered_file(&caller, &files),
    );
    assert!(unit.truncated, "{unit:?}");
    let root = unit
        .diagnostics
        .iter()
        .flat_map(|diagnostic| &diagnostic.exhausted_roots)
        .find(|root| root.lane == "query/call_answers")
        .expect("later target call-answer refusal");
    assert_eq!(
        root.budget,
        Some(CodeQueryExhaustedBudget { consumed, limit })
    );
    assert_eq!(
        root.charge,
        Some(CodeQueryExhaustedCharge { attempted, limit })
    );
    assert_eq!(
        unit.budgeted_work.admission.call_answers,
        u64::try_from(limit).unwrap()
    );
    assert_eq!(unit.rows.len(), limit - targets.len());
    assert_eq!(
        unit.work.examined_references,
        complete.work.examined_references
    );
    assert_eq!(
        unit.work.examined_references,
        u64::try_from(complete.rows.len()).unwrap()
    );
    assert_eq!(unit.work.fact_nodes, seeds.work.fact_nodes);
    assert_eq!(
        unit.budgeted_work.admission.fact_nodes,
        seeds.budgeted_work.admission.fact_nodes
    );
}

#[test]
fn structural_units_follow_relative_path_string_order() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("a.py", "def sibling():\n    pass\n")
        .file("a/x.py", "def nested():\n    pass\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({"match": {"kind": "function"}, "limit": 1})).unwrap();
    let files = plan_seed_files(&query.plan, &workspace.analyzer().analyzed_files());
    assert_eq!(files, vec![project.file("a.py"), project.file("a/x.py")]);
}

#[test]
fn bounded_unit_output_survives_a_later_complete_unit() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "a.ts",
            "function first() {}\nfunction second() {}\nfunction third() {}\n",
        )
        .file("b.ts", "function last() {}\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    // Authored output limit: the first file exceeds two, the second fits.
    let query = CodeQuery::from_json(&json!({"match": {"kind": "function"}, "limit": 2})).unwrap();
    let files = plan_seed_files(&query.plan, &workspace.analyzer().analyzed_files());
    let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
    let units: Vec<_> = files
        .iter()
        .map(|file| {
            execute_code_query_unit(
                workspace.analyzer(),
                &flow,
                None,
                &query,
                CodeQueryExecutionLimits::default(),
                None,
                CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(file), &files),
            )
        })
        .collect();
    assert_eq!(units.len(), 2);
    assert!(units[0].truncated, "{units:?}");
    assert!(!units[1].truncated, "{units:?}");
    let merged = merge_unit_rows(&query, units);
    assert!(merged.truncated, "{merged:?}");
    assert!(matches!(
        merged.completion(),
        CodeQueryCompletion::Incomplete { .. }
    ));
}

#[test]
fn rust_reverse_in_file_matches_workspace_call_sites() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"reverse_frontier\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file(
            "src/lib.rs",
            "mod first;\nmod second;\npub fn target(value: i32) -> i32 { value }\n",
        )
        .file(
            "src/first.rs",
            "pub fn first() -> i32 { crate::target(1) }\n",
        )
        .file(
            "src/second.rs",
            "pub fn second() -> i32 { crate::target(2) + crate::target(3) }\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["rust"],
        "match": {"kind": "callable", "name": "target"},
        "steps": [{"op": "enclosing_decl"}, {"op": "call_sites_to"}],
        "limit": 100
    }))
    .unwrap();
    let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
    let files = workspace.analyzer().analyzed_files();
    let run = |scope| {
        execute_code_query_unit(
            workspace.analyzer(),
            &flow,
            Some(&workspace),
            &query,
            CodeQueryExecutionLimits::default(),
            None,
            scope,
        )
    };
    let whole = run(CodeQueryExecutionScope::whole_workspace());
    assert_eq!(whole.completion, CodeQueryCompletion::Complete, "{whole:?}");
    assert_eq!(whole.rows.len(), 3, "{whole:?}");
    let mut local_rows = Vec::new();
    for file in &files {
        let unit = run(CodeQueryExecutionScope::for_reverse_entered_file(
            file, &files,
        ));
        assert_eq!(unit.completion, whole.completion, "{file:?}: {unit:?}");
        local_rows.extend(unit.rows);
    }
    // Compare the rendered row, detailed evidence and stable dedup key.
    let normalize = |rows: Vec<crate::structural::search::units::UnitRow>| {
        let mut rows: Vec<_> = rows
            .into_iter()
            .map(|row| serde_json::to_string(&row).unwrap())
            .collect();
        rows.sort();
        rows
    };
    // A one-file seed restriction keeps its ordinary meaning: the seeds
    // declared in that file, with their call sites anywhere.
    for file in &files {
        let seeded = run(CodeQueryExecutionScope::for_seed_files(
            std::slice::from_ref(file),
            &files,
        ));
        let expected = if file.rel_path() == std::path::Path::new("src/lib.rs") {
            whole.rows.len()
        } else {
            0
        };
        assert_eq!(seeded.rows.len(), expected, "{file:?}: {seeded:?}");
    }
    assert_eq!(normalize(local_rows), normalize(whole.rows));
}

#[test]
fn rust_reverse_in_file_cap_is_reported_per_entered_file() {
    // Three call sites in two files under an output limit of two. The widened
    // run caps inside its one unit. Per entered file no unit reaches the cap,
    // so the units are complete and the merge holds the complete answer; the
    // root limit applied after the merge then caps it. Which rows a capped
    // answer keeps is not a contract; that it is truncated and incomplete is.
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"reverse_frontier\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file(
            "src/lib.rs",
            "mod first;\nmod second;\npub fn target(value: i32) -> i32 { value }\n",
        )
        .file(
            "src/first.rs",
            "pub fn first() -> i32 { crate::target(1) }\n",
        )
        .file(
            "src/second.rs",
            "pub fn second() -> i32 { crate::target(2) + crate::target(3) }\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["rust"],
        "match": {"kind": "callable", "name": "target"},
        "steps": [{"op": "enclosing_decl"}, {"op": "call_sites_to"}],
        "limit": 2
    }))
    .unwrap();
    let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
    let files = workspace.analyzer().analyzed_files();
    let run = |scope| {
        execute_code_query_unit(
            workspace.analyzer(),
            &flow,
            Some(&workspace),
            &query,
            CodeQueryExecutionLimits::default(),
            None,
            scope,
        )
    };
    let whole = run(CodeQueryExecutionScope::whole_workspace());
    let units: Vec<_> = files
        .iter()
        .map(|file| {
            run(CodeQueryExecutionScope::for_reverse_entered_file(
                file, &files,
            ))
        })
        .collect();
    assert!(whole.truncated, "{whole:?}");
    assert!(matches!(
        whole.completion,
        CodeQueryCompletion::Incomplete { .. }
    ));
    let site_ids = |items: Vec<&crate::structural::search::units::UnitRowItem>| {
        let mut ids: Vec<_> = items
            .into_iter()
            .map(|item| serde_json::to_string(item).unwrap())
            .collect();
        ids.sort();
        ids
    };
    for (file, unit) in files.iter().zip(&units) {
        assert!(!unit.truncated, "{file:?}: {unit:?}");
        assert_eq!(unit.completion, CodeQueryCompletion::Complete, "{file:?}");
    }
    let mut merged = merge_unit_rows(&query, units);
    assert_eq!(merged.items.len(), 3, "{merged:?}");
    assert_eq!(merged.completion(), CodeQueryCompletion::Complete);
    merged.apply_result_limit(query.limit);
    assert!(merged.truncated, "{merged:?}");
    assert!(matches!(
        merged.completion(),
        CodeQueryCompletion::Incomplete { .. }
    ));
    assert_eq!(merged.items.len(), whole.rows.len());
    assert_eq!(
        site_ids(merged.items.iter().collect()),
        site_ids(whole.rows.iter().map(|row| &row.item).collect())
    );
}
