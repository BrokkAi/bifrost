use super::*;
use crate::analyzer::structural::EdgeProvenance;
use crate::analyzer::structural::reference_edges::{
    EdgeCompleteness, EdgeDerivationResult, EdgeIncompleteReason, ReferenceEdgeRow,
    inverse_edges_for_declaration,
};
use brokk_bifrost_analysis::native_resolution_test_support::SelectedReferenceInverseIndex;
use serde_json::json;
use std::sync::Arc;

/// Execute the ordinary RQL reducer with native rows, inside the same selected
/// operation that owns their source authority. No incumbent inverse query is
/// used to construct this index.
fn execute_rust_native_edges(
    workspace: &WorkspaceAnalyzer,
    target: &CodeUnit,
    query: &CodeQuery,
    cancellation: &CancellationToken,
    after_staging: impl FnOnce(&CodeQueryResult),
) -> brokk_bifrost_analysis::native_resolution_test_support::RustSelectedReverseOutcome<
    Option<CodeQueryResult>,
> {
    use brokk_bifrost_analysis::native_resolution_test_support::with_rust_selected_reverse_queries;
    let rust = brokk_bifrost_analysis::analyzer::resolve_analyzer::<
        brokk_bifrost_analysis::RustAnalyzer,
    >(workspace.analyzer())
    .expect("Rust fixture analyzer");
    with_rust_selected_reverse_queries(rust, cancellation, |queries| {
        let Some(mut answers) = queries.inverse_for(std::slice::from_ref(target))? else {
            return Ok(None);
        };
        assert_eq!(answers.len(), 1);
        let answer = answers.pop().unwrap();
        let mut rows = answer.edges;
        for row in &mut rows {
            assert_eq!(row.provenance, EdgeProvenance::Inverse);
            row.provenance = EdgeProvenance::Forward;
        }
        let index = SelectedReferenceInverseIndex::from_forward_rows_for_test_support(
            answer.generation,
            vec![target.clone()],
            answer.completeness,
            rows.len(),
            rows,
        );
        let result = super::super::execute_workspace_with_selected_inverse_index_for_test(
            workspace,
            query,
            index,
            &SelectedEdgesOfTelemetry::default(),
        );
        after_staging(&result);
        Ok(Some(result))
    })
}

#[test]
fn native_rust_edges_of_filters_aliases_and_decoys_and_renders_public_rows() {
    use brokk_bifrost_analysis::native_resolution_test_support::RustSelectedReverseOutcome;
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"native_rql\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file(
            "src/lib.rs",
            "pub mod api;\nuse api::target as alias;\npub fn caller() { alias(); alias(); }\n",
        )
        .file("src/api.rs", "pub fn target() {}\npub fn decoy() {}\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    for (name, expected) in [("target", 2), ("decoy", 0)] {
        let target = workspace
            .analyzer()
            .all_declarations()
            .find(|unit| unit.identifier() == name)
            .unwrap();
        let query = CodeQuery::from_json(&json!({
            "languages": ["rust"],
            "match": { "kind": "callable", "name": name },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "edges_of", "proof": "proven", "usage": ["reference"],
                  "surface": "external_usages", "relation": ["external"],
                  "site_class": ["use_site"] }
            ]
        }))
        .unwrap();
        let RustSelectedReverseOutcome::Ready(Some(native)) = execute_rust_native_edges(
            &workspace,
            &target,
            &query,
            &CancellationToken::new(),
            |_| {},
        ) else {
            panic!("closed Rust native query must publish");
        };
        assert_eq!(native.completion(), CodeQueryCompletion::Complete);
        assert_eq!(native.results.len(), expected);
        let incumbent = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            &query,
        );
        assert_eq!(
            serde_json::to_value(native).unwrap(),
            serde_json::to_value(incumbent).unwrap()
        );

        if expected > 0 {
            let cancellation = CancellationToken::new();
            let outcome =
                execute_rust_native_edges(&workspace, &target, &query, &cancellation, |staged| {
                    assert_eq!(staged.results.len(), expected);
                    cancellation.cancel();
                });
            assert!(
                matches!(outcome, RustSelectedReverseOutcome::Cancelled),
                "late cancellation must discard already rendered rows: {outcome:?}"
            );
        }
    }
}

#[test]
fn native_rust_edges_of_does_not_certify_absence_under_open_inventory() {
    use brokk_bifrost_analysis::native_resolution_test_support::RustSelectedReverseOutcome;
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"native_rql_gap\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file(
            "src/lib.rs",
            "pub fn target() {}\ninclude!(\"generated.rs\");\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let target = workspace
        .analyzer()
        .all_declarations()
        .find(|unit| unit.identifier() == "target")
        .unwrap();
    let query = CodeQuery::from_json(&json!({
        "languages": ["rust"], "match": { "kind": "callable", "name": "target" },
        "steps": [{ "op": "enclosing_decl" }, { "op": "edges_of" }]
    }))
    .unwrap();
    let RustSelectedReverseOutcome::Ready(Some(native)) = execute_rust_native_edges(
        &workspace,
        &target,
        &query,
        &CancellationToken::new(),
        |_| {},
    ) else {
        panic!("semantic inventory uncertainty is not an operational failure");
    };
    assert!(native.results.is_empty());
    assert_ne!(native.completion(), CodeQueryCompletion::Complete);
    assert!(
        !native.diagnostics.is_empty(),
        "missing edges must retain their reason"
    );
}

struct SelectedEdgeFixture {
    workspace: WorkspaceAnalyzer,
    _project: inline_project::BuiltInlineTestProject,
}

impl SelectedEdgeFixture {
    fn new() -> Self {
        let project = InlineTestProject::with_language(Language::Java)
            .file(
                "src/Registry.java",
                "package fixture; public class Registry { public void register() {} }\n",
            )
            .file(
                "src/Startup.java",
                "package fixture; public class Startup { void boot(Registry registry) { registry.register(); registry.register(); } }\n",
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        Self {
            workspace,
            _project: project,
        }
    }

    fn register_target(&self) -> CodeUnit {
        self.workspace
            .analyzer()
            .all_declarations()
            .find(|declaration| declaration.fq_name().ends_with("Registry.register"))
            .expect("fixture register declaration")
    }

    fn boot_target(&self) -> CodeUnit {
        self.workspace
            .analyzer()
            .all_declarations()
            .find(|declaration| declaration.fq_name().ends_with("Startup.boot"))
            .expect("fixture boot declaration")
    }

    fn complete_selected_index(&self, target: &CodeUnit) -> SelectedReferenceInverseIndex {
        let (generation, forward_rows) = self.forward_rows(target);
        SelectedReferenceInverseIndex::from_forward_rows_for_test_support(
            generation,
            vec![target.clone()],
            EdgeCompleteness::Complete,
            forward_rows.len(),
            forward_rows,
        )
    }

    fn forward_rows(&self, target: &CodeUnit) -> (u64, Vec<ReferenceEdgeRow>) {
        let legacy = inverse_edges_for_declaration(self.workspace.analyzer(), target, None);
        assert_eq!(legacy.completeness, EdgeCompleteness::Complete);
        let mut forward_rows = legacy.edges;
        for row in &mut forward_rows {
            assert_eq!(row.provenance, EdgeProvenance::Inverse);
            row.provenance = EdgeProvenance::Forward;
        }
        (legacy.generation, forward_rows)
    }
}

#[test]
fn selected_inverse_acquisition_preserves_filter_and_public_rendering() {
    let fixture = SelectedEdgeFixture::new();
    let target = fixture.register_target();
    let query = CodeQuery::from_json(&json!({
        "languages": ["java"],
        "match": { "kind": "callable", "name": "register" },
        "steps": [
            { "op": "enclosing_decl" },
            {
                "op": "edges_of",
                "reference_kinds": ["method_call"],
                "proof": "proven",
                "surface": "external_usages",
                "usage": ["reference"],
                "relation": ["external"],
                "site_class": ["use_site"]
            }
        ]
    }))
    .expect("selected edge query");

    let incumbent = execute_workspace(
        &fixture.workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        &query,
    );
    assert_eq!(incumbent.completion(), CodeQueryCompletion::Complete);
    assert_eq!(incumbent.results.len(), 2);

    let telemetry = SelectedEdgesOfTelemetry::default();
    let selected = super::super::execute_workspace_with_selected_inverse_index_for_test(
        &fixture.workspace,
        &query,
        fixture.complete_selected_index(&target),
        &telemetry,
    );

    assert_eq!(
        serde_json::to_value(&selected).expect("selected result"),
        serde_json::to_value(&incumbent).expect("incumbent result")
    );
    let metrics = telemetry.snapshot();
    assert_eq!(metrics.provider_lookups, 1);
    assert_eq!(metrics.cache_hits, 0);
    assert_eq!(metrics.uncovered_target_lookups, 0);
}

#[test]
fn selected_inverse_cache_reuses_one_exact_target_lookup() {
    let fixture = SelectedEdgeFixture::new();
    let target = fixture.register_target();
    let telemetry = SelectedEdgesOfTelemetry::default();
    let mut cache = EdgeTraversalCache::with_selected_inverse(
        fixture.complete_selected_index(&target),
        telemetry.clone(),
    );

    let first = cache.inverse_for(fixture.workspace.analyzer(), &target, None);
    let second = cache.inverse_for(fixture.workspace.analyzer(), &target, None);

    assert!(Arc::ptr_eq(&first, &second));
    let metrics = telemetry.snapshot();
    assert_eq!(metrics.provider_lookups, 1);
    assert_eq!(metrics.cache_hits, 1);
    assert_eq!(metrics.uncovered_target_lookups, 0);
}

#[test]
fn selected_inverse_canonical_order_preserves_the_limited_rql_prefix() {
    let fixture = SelectedEdgeFixture::new();
    let target = fixture.register_target();
    let (generation, rows) = fixture.forward_rows(&target);
    assert_eq!(rows.len(), 2);
    let mut reversed = rows.clone();
    reversed.reverse();
    let index = |rows: Vec<ReferenceEdgeRow>| {
        SelectedReferenceInverseIndex::from_forward_rows_for_test_support(
            generation,
            vec![target.clone()],
            EdgeCompleteness::Complete,
            rows.len(),
            rows,
        )
    };
    let query = CodeQuery::from_json(&json!({
        "languages": ["java"],
        "match": { "kind": "callable", "name": "register" },
        "steps": [{ "op": "enclosing_decl" }, { "op": "edges_of" }],
        "limit": 1
    }))
    .expect("limited edge query");

    let forward = super::super::execute_workspace_with_selected_inverse_index_for_test(
        &fixture.workspace,
        &query,
        index(rows),
        &SelectedEdgesOfTelemetry::default(),
    );
    let reverse = super::super::execute_workspace_with_selected_inverse_index_for_test(
        &fixture.workspace,
        &query,
        index(reversed),
        &SelectedEdgesOfTelemetry::default(),
    );

    assert_eq!(
        serde_json::to_value(forward).expect("forward prefix"),
        serde_json::to_value(reverse).expect("reverse prefix")
    );
}

#[test]
fn repeated_seed_branches_share_the_one_selected_provider_lookup() {
    let fixture = SelectedEdgeFixture::new();
    let target = fixture.register_target();
    let branch = json!({
        "languages": ["java"],
        "match": { "kind": "callable", "name": "register" }
    });
    let query = CodeQuery::from_json(&json!({
        "union": [branch.clone(), branch],
        "steps": [{ "op": "enclosing_decl" }, { "op": "edges_of" }]
    }))
    .expect("repeated seed union with a shared edge suffix");
    let telemetry = SelectedEdgesOfTelemetry::default();

    let result = super::super::execute_workspace_with_selected_inverse_index_for_test(
        &fixture.workspace,
        &query,
        fixture.complete_selected_index(&target),
        &telemetry,
    );

    assert_eq!(result.completion(), CodeQueryCompletion::Complete);
    let metrics = telemetry.snapshot();
    assert_eq!(metrics.provider_lookups, 1);
}

#[test]
fn selected_index_survives_a_seed_union_before_the_shared_edge_suffix() {
    let fixture = SelectedEdgeFixture::new();
    let target = fixture.register_target();
    let branch = |where_glob: &str| {
        json!({
            "where": [where_glob],
            "languages": ["java"],
            "match": { "kind": "callable", "name": "register" }
        })
    };
    let query = CodeQuery::from_json(&json!({
        "union": [branch("src/Registry.java"), branch("**/Registry.java")],
        "steps": [{ "op": "enclosing_decl" }, { "op": "edges_of" }]
    }))
    .expect("parallel-seed edge query");
    let telemetry = SelectedEdgesOfTelemetry::default();

    let result = super::super::execute_workspace_with_selected_inverse_index_for_test(
        &fixture.workspace,
        &query,
        fixture.complete_selected_index(&target),
        &telemetry,
    );

    assert_eq!(result.completion(), CodeQueryCompletion::Complete);
    assert_eq!(telemetry.snapshot().provider_lookups, 1);
}

#[test]
fn selected_inverse_keeps_edge_target_on_the_ordinary_pipeline() {
    let fixture = SelectedEdgeFixture::new();
    let target = fixture.register_target();
    let query = CodeQuery::from_json(&json!({
        "languages": ["java"],
        "match": { "kind": "callable", "name": "register" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "edges_of", "usage": ["reference"] },
            { "op": "edge_target" }
        ]
    }))
    .expect("edge target query");
    let incumbent = execute_workspace(
        &fixture.workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        &query,
    );

    let selected = super::super::execute_workspace_with_selected_inverse_index_for_test(
        &fixture.workspace,
        &query,
        fixture.complete_selected_index(&target),
        &SelectedEdgesOfTelemetry::default(),
    );

    assert_eq!(
        serde_json::to_value(selected).expect("selected target projection"),
        serde_json::to_value(incumbent).expect("incumbent target projection")
    );
}

#[test]
fn selected_inverse_uncovered_target_never_falls_back_to_legacy_usage() {
    let fixture = SelectedEdgeFixture::new();
    let covered = fixture.register_target();
    let uncovered = fixture.boot_target();
    let telemetry = SelectedEdgesOfTelemetry::default();
    let mut cache = EdgeTraversalCache::with_selected_inverse(
        fixture.complete_selected_index(&covered),
        telemetry.clone(),
    );

    let result = cache.inverse_for(fixture.workspace.analyzer(), &uncovered, None);

    assert!(result.edges.is_empty());
    assert_eq!(
        result.completeness,
        EdgeCompleteness::Incomplete {
            reasons: vec![EdgeIncompleteReason::InverseIndexTargetUncovered]
        }
    );
    let metrics = telemetry.snapshot();
    assert_eq!(metrics.provider_lookups, 1);
    assert_eq!(metrics.cache_hits, 0);
    assert_eq!(metrics.uncovered_target_lookups, 1);

    let mut diagnostics = Vec::new();
    cache.report_inverse_completeness(&uncovered, Language::Java, &result, &mut diagnostics);
    assert_eq!(diagnostics.len(), 1);
    assert!(
        diagnostics[0]
            .message
            .contains("selected Java inverse-index")
    );
    assert!(!diagnostics[0].message.contains("usage listing"));
    assert!(!diagnostics[0].message.contains("structural adapter"));
}

#[test]
fn selected_inverse_covered_empty_status_is_generation_bound_and_honest() {
    let fixture = SelectedEdgeFixture::new();
    let target = fixture.boot_target();
    let generation = fixture.workspace.analyzer().project().analysis_generation();
    let build_index = |completeness| {
        SelectedReferenceInverseIndex::from_forward_rows_for_test_support(
            generation,
            vec![target.clone()],
            completeness,
            0,
            Vec::new(),
        )
    };

    let telemetry = SelectedEdgesOfTelemetry::default();
    let mut complete_cache = EdgeTraversalCache::with_selected_inverse(
        build_index(EdgeCompleteness::Complete),
        telemetry,
    );
    let complete = complete_cache.inverse_for(fixture.workspace.analyzer(), &target, None);
    assert!(complete.edges.is_empty());
    assert_eq!(complete.completeness, EdgeCompleteness::Complete);
    let mut complete_diagnostics = Vec::new();
    complete_cache.report_inverse_completeness(
        &target,
        Language::Java,
        &complete,
        &mut complete_diagnostics,
    );
    assert!(complete_diagnostics.is_empty());

    let mut incomplete_cache = EdgeTraversalCache::with_selected_inverse(
        build_index(EdgeCompleteness::Incomplete {
            reasons: vec![EdgeIncompleteReason::ForwardResolutionIncomplete],
        }),
        SelectedEdgesOfTelemetry::default(),
    );
    let incomplete = incomplete_cache.inverse_for(fixture.workspace.analyzer(), &target, None);
    assert!(incomplete.edges.is_empty());
    assert_eq!(
        incomplete.completeness,
        EdgeCompleteness::Incomplete {
            reasons: vec![EdgeIncompleteReason::InverseIndexResolutionIncomplete]
        }
    );
    let mut incomplete_diagnostics = Vec::new();
    incomplete_cache.report_inverse_completeness(
        &target,
        Language::Java,
        &incomplete,
        &mut incomplete_diagnostics,
    );
    assert_eq!(incomplete_diagnostics.len(), 1);
}

#[test]
fn selected_inverse_diagnostics_separate_global_and_target_local_reasons() {
    let fixture = SelectedEdgeFixture::new();
    let first = fixture.register_target();
    let second = fixture.boot_target();
    let first_name = first.fq_name();
    let second_name = second.fq_name();
    let generation = fixture.workspace.analyzer().project().analysis_generation();
    let selected_index = || {
        SelectedReferenceInverseIndex::from_forward_rows_for_test_support(
            generation,
            vec![first.clone(), second.clone()],
            EdgeCompleteness::Complete,
            0,
            Vec::new(),
        )
    };
    let result = |reason| EdgeDerivationResult {
        edges: Vec::new(),
        completeness: EdgeCompleteness::Incomplete {
            reasons: vec![reason],
        },
        provenance: EdgeProvenance::Inverse,
        generation,
    };

    let mut global_cache = EdgeTraversalCache::with_selected_inverse(
        selected_index(),
        SelectedEdgesOfTelemetry::default(),
    );
    let mut global_diagnostics = Vec::new();
    for target in [&first, &second] {
        global_cache.report_inverse_completeness(
            target,
            Language::Java,
            &result(EdgeIncompleteReason::InverseIndexResolutionIncomplete),
            &mut global_diagnostics,
        );
    }
    assert_eq!(global_diagnostics.len(), 1);
    assert!(global_diagnostics[0].message.contains("generation"));

    let mut local_cache = EdgeTraversalCache::with_selected_inverse(
        selected_index(),
        SelectedEdgesOfTelemetry::default(),
    );
    let mut local_diagnostics = Vec::new();
    local_cache.report_inverse_completeness(
        &first,
        Language::Java,
        &result(EdgeIncompleteReason::InverseIndexAdmissionIncomplete),
        &mut local_diagnostics,
    );
    local_cache.report_inverse_completeness(
        &second,
        Language::Java,
        &EdgeDerivationResult {
            edges: Vec::new(),
            completeness: EdgeCompleteness::Complete,
            provenance: EdgeProvenance::Inverse,
            generation,
        },
        &mut local_diagnostics,
    );
    assert_eq!(local_diagnostics.len(), 1);
    assert!(local_diagnostics[0].message.contains(first_name.as_str()));
    assert!(!local_diagnostics[0].message.contains(second_name.as_str()));

    local_cache.report_inverse_completeness(
        &second,
        Language::Java,
        &result(EdgeIncompleteReason::AxisUnsupported(
            crate::analyzer::structural::EdgeAxis::KindClassification,
        )),
        &mut local_diagnostics,
    );
    assert_eq!(local_diagnostics.len(), 2);
    assert!(local_diagnostics[1].message.contains(second_name.as_str()));
    assert!(!local_diagnostics[1].message.contains("structural adapter"));
}

#[test]
fn selected_inverse_target_local_diagnostics_deduplicate_by_exact_overload() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/Overloads.java",
            "package fixture; class Overloads { void run() {} void run(int value) {} }\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let mut overloads = workspace
        .analyzer()
        .all_declarations()
        .filter(|declaration| declaration.fq_name().ends_with("Overloads.run"))
        .collect::<Vec<_>>();
    overloads.sort_unstable_by(|left, right| left.signature().cmp(&right.signature()));
    let [first, second] = overloads.as_slice() else {
        panic!("the exact-target diagnostic law requires two overloads: {overloads:?}");
    };
    assert_eq!(first.fq_name(), second.fq_name());
    assert_ne!(first.signature(), second.signature());
    assert_ne!(first.declaration_id(), second.declaration_id());

    let generation = workspace.analyzer().project().analysis_generation();
    let index = SelectedReferenceInverseIndex::from_forward_rows_for_test_support(
        generation,
        overloads.clone(),
        EdgeCompleteness::Complete,
        0,
        Vec::new(),
    );
    let mut cache =
        EdgeTraversalCache::with_selected_inverse(index, SelectedEdgesOfTelemetry::default());
    let incomplete = EdgeDerivationResult {
        edges: Vec::new(),
        completeness: EdgeCompleteness::Incomplete {
            reasons: vec![EdgeIncompleteReason::InverseIndexAdmissionIncomplete],
        },
        provenance: EdgeProvenance::Inverse,
        generation,
    };
    let mut diagnostics = Vec::new();
    for overload in [first, second] {
        cache.report_inverse_completeness(overload, Language::Java, &incomplete, &mut diagnostics);
    }
    assert_eq!(diagnostics.len(), 2, "{diagnostics:?}");
    assert!(diagnostics.iter().all(|diagnostic| {
        diagnostic
            .message
            .contains("does not cover every requested reference-edge axis")
    }));

    cache.report_inverse_completeness(first, Language::Java, &incomplete, &mut diagnostics);
    assert_eq!(diagnostics.len(), 2, "{diagnostics:?}");
}

#[test]
fn selected_publication_discards_cancelled_and_stale_prefixes_and_allows_retry() {
    let fixture = SelectedEdgeFixture::new();
    let query = CodeQuery::from_json(&json!({
        "languages": ["java"],
        "match": { "kind": "callable", "name": "register" },
        "steps": [{ "op": "enclosing_decl" }, { "op": "edges_of" }]
    }))
    .expect("publication query");
    let run = || {
        execute_workspace(
            &fixture.workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            &query,
        )
    };
    let generation = fixture.workspace.analyzer().project().analysis_generation();

    let cancelled = CancellationToken::new();
    let completed_prefix = run();
    assert!(!completed_prefix.results.is_empty());
    cancelled.cancel();
    assert!(matches!(
        super::super::selected_edges_of_publication_gate(
            fixture.workspace.analyzer(),
            generation,
            &cancelled,
            completed_prefix,
        ),
        SelectedEdgesOfExecutionOutcome::Cancelled
    ));

    assert!(matches!(
        super::super::selected_edges_of_publication_gate(
            fixture.workspace.analyzer(),
            generation + 1,
            &CancellationToken::new(),
            run(),
        ),
        SelectedEdgesOfExecutionOutcome::Stale
    ));

    let retry = super::super::selected_edges_of_publication_gate(
        fixture.workspace.analyzer(),
        generation,
        &CancellationToken::new(),
        run(),
    );
    let SelectedEdgesOfExecutionOutcome::Executed(retry) = retry else {
        panic!("a fresh same-generation retry must execute");
    };
    assert!(!retry.results.is_empty());
}

#[test]
fn selected_inverse_scope_requires_explicit_java_on_every_seed() {
    let query = |languages: serde_json::Value| {
        CodeQuery::from_json(&json!({
            "languages": languages,
            "match": { "kind": "callable" },
            "steps": [{ "op": "enclosing_decl" }, { "op": "edges_of" }]
        }))
        .expect("scope query")
    };
    assert!(super::super::query_plan_has_explicit_java_only_seeds(
        &query(json!(["java"])).plan
    ));
    assert!(!super::super::query_plan_has_explicit_java_only_seeds(
        &query(json!([])).plan
    ));
    assert!(!super::super::query_plan_has_explicit_java_only_seeds(
        &query(json!(["java", "rust"])).plan
    ));

    let branch = |language: &str| {
        json!({
            "languages": [language],
            "match": { "kind": "callable", "name": "register" }
        })
    };
    let java_union = CodeQuery::from_json(&json!({
        "union": [branch("java"), branch("java")],
        "steps": [{ "op": "enclosing_decl" }, { "op": "edges_of" }]
    }))
    .expect("Java union");
    assert!(super::super::query_plan_has_explicit_java_only_seeds(
        &java_union.plan
    ));
    let mixed_union = CodeQuery::from_json(&json!({
        "union": [branch("java"), branch("rust")],
        "steps": [{ "op": "enclosing_decl" }, { "op": "edges_of" }]
    }))
    .expect("mixed union");
    assert!(!super::super::query_plan_has_explicit_java_only_seeds(
        &mixed_union.plan
    ));

    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert!(matches!(
        super::super::selected_edges_of_entry_gate(&mixed_union, &cancelled),
        Ok(Some(SelectedEdgesOfExecutionOutcome::Cancelled))
    ));
    assert!(
        super::super::selected_edges_of_entry_gate(&mixed_union, &CancellationToken::new())
            .is_err()
    );
}

#[test]
fn selected_inverse_scope_rejects_retryable_branch_local_edges() {
    let branch = json!({
        "languages": ["java"],
        "match": { "kind": "callable", "name": "register" },
        "steps": [{ "op": "enclosing_decl" }, { "op": "edges_of" }]
    });
    let branch_local = CodeQuery::from_json(&json!({
        "union": [branch.clone(), branch]
    }))
    .expect("branch-local edge union");
    assert!(super::super::query_plan_has_retryable_branch_local_edges_of(&branch_local.plan));
    let error =
        super::super::selected_edges_of_entry_gate(&branch_local, &CancellationToken::new())
            .expect_err("branch-local edges must be rejected before selected index construction");
    assert!(
        error.contains("shared edges_of suffix"),
        "unexpected gate error: {error}"
    );

    let shared_suffix = CodeQuery::from_json(&json!({
        "union": [
            {
                "languages": ["java"],
                "match": { "kind": "callable", "name": "register" }
            },
            {
                "languages": ["java"],
                "match": { "kind": "callable", "name": "register" }
            }
        ],
        "steps": [{ "op": "enclosing_decl" }, { "op": "edges_of" }]
    }))
    .expect("shared edge suffix");
    assert!(!super::super::query_plan_has_retryable_branch_local_edges_of(&shared_suffix.plan));
    assert!(matches!(
        super::super::selected_edges_of_entry_gate(&shared_suffix, &CancellationToken::new(),),
        Ok(None)
    ));

    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert!(matches!(
        super::super::selected_edges_of_entry_gate(&branch_local, &cancelled),
        Ok(Some(SelectedEdgesOfExecutionOutcome::Cancelled))
    ));
}

#[test]
fn production_rust_edges_of_preserves_aliases_decoys_and_cache_reuse() {
    const LIBRARY: &str = concat!(
        "pub mod dep;\n",
        "use dep::target as imported_target;\n",
        "pub fn caller() { imported_target(); imported_target(); }\n",
    );
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"rql_shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file("src/lib.rs", LIBRARY)
        .file(
            "src/dep.rs",
            "pub fn target() {}\npub mod nested { pub fn target() {} }\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let target = analyzer
        .all_declarations()
        .find(|declaration| declaration.fq_name().ends_with("dep.target"))
        .expect("fixture target declaration");
    let caller = analyzer
        .all_declarations()
        .find(|declaration| declaration.fq_name().ends_with("caller"))
        .expect("fixture caller declaration");
    let nested_target = analyzer
        .all_declarations()
        .find(|declaration| declaration.fq_name().ends_with("dep.nested.target"))
        .expect("fixture nested decoy declaration");
    let mut cache = EdgeTraversalCache::default();

    let target_edges = cache.inverse_for(analyzer, &target, None);
    assert_eq!(target_edges.completeness, EdgeCompleteness::Complete);
    assert_eq!(
        target_edges
            .edges
            .iter()
            .filter(|row| row.usage_kind == UsageHitKind::Reference)
            .count(),
        2
    );
    // One import edge, not two. The Rust Reference's use declarations bind a
    // new name to the item the path names: in `use dep::target as
    // imported_target;` the path segment `target` names the declaration once,
    // and `imported_target` is the name being bound rather than a second
    // naming of the target. The incumbent counted the alias binder as its own
    // import site, which double-counted one `use` item.
    let imports = target_edges
        .edges
        .iter()
        .filter(|row| row.usage_kind == UsageHitKind::Import)
        .collect::<Vec<_>>();
    assert_eq!(imports.len(), 1, "{imports:?}");
    let import_range = &imports[0].site.range;
    assert_eq!(
        &LIBRARY[import_range.start_byte..import_range.end_byte],
        "target"
    );

    let caller_edges = cache.inverse_for(analyzer, &caller, None);
    assert_eq!(caller_edges.completeness, EdgeCompleteness::Complete);
    assert!(caller_edges.edges.is_empty());
    let nested_target_edges = cache.inverse_for(analyzer, &nested_target, None);
    assert_eq!(nested_target_edges.completeness, EdgeCompleteness::Complete);
    assert!(nested_target_edges.edges.is_empty());
    let repeated = cache.inverse_for(analyzer, &target, None);
    assert!(Arc::ptr_eq(&target_edges, &repeated));
}

#[test]
fn production_rust_edges_of_preserves_glob_import_references() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"rql_glob_shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file(
            "src/lib.rs",
            concat!(
                "pub mod dep;\n",
                "use dep::*;\n",
                "pub fn caller() { target(); target(); }\n",
            ),
        )
        .file("src/dep.rs", "pub fn target() {}\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let target = analyzer
        .all_declarations()
        .find(|declaration| declaration.fq_name().ends_with("dep.target"))
        .expect("fixture target declaration");
    let mut cache = EdgeTraversalCache::default();

    let edges = cache.inverse_for(analyzer, &target, None);
    assert_eq!(edges.completeness, EdgeCompleteness::Complete);
    assert_eq!(
        edges
            .edges
            .iter()
            .filter(|row| row.usage_kind == UsageHitKind::Reference)
            .count(),
        2
    );
    assert_eq!(
        edges
            .edges
            .iter()
            .filter(|row| row.usage_kind == UsageHitKind::Import)
            .count(),
        0
    );
}

/// Row-driven inverse discovery covers module declarations as well as values.
/// Preserve the exact import-token edge instead of the old eager index's
/// target-kind refusal; module coverage must not manufacture empty absence.
#[test]
fn production_rust_edges_of_covers_module_rows_from_reverse_demands() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"rql_uncovered\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file(
            "src/lib.rs",
            concat!(
                "pub mod dep;\n",
                "use dep::target as imported_target;\n",
                "pub fn caller() { imported_target(); }\n",
            ),
        )
        .file("src/dep.rs", "pub fn target() {}\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let module = analyzer
        .all_declarations()
        .find(|declaration| declaration.is_module() && declaration.fq_name().ends_with("dep"))
        .expect("fixture module declaration");
    let target = analyzer
        .all_declarations()
        .find(|declaration| declaration.fq_name().ends_with("dep.target"))
        .expect("fixture target declaration");
    let mut cache = EdgeTraversalCache::default();

    let module_edges = cache.inverse_for(analyzer, &module, None);
    assert_eq!(module_edges.completeness, EdgeCompleteness::Complete);
    assert_eq!(module_edges.edges.len(), 1, "{module_edges:?}");
    let edge = &module_edges.edges[0];
    assert_eq!(edge.target, module);
    assert_eq!(edge.site.file, project.file("src/lib.rs"));
    assert_eq!(
        (edge.site.range.start_byte, edge.site.range.end_byte),
        (17, 20)
    );
    assert_eq!(edge.usage_kind, UsageHitKind::Import);
    assert_eq!(edge.proof, crate::analyzer::usages::UsageProof::Proven);
    assert!(
        module_edges.covers(crate::analyzer::structural::EdgeAxis::InverseProjection),
        "the module import has a covered inverse: {module_edges:?}"
    );

    // A value target through the same import retains its call reference.
    let target_edges = cache.inverse_for(analyzer, &target, None);
    assert_eq!(target_edges.completeness, EdgeCompleteness::Complete);
    assert_eq!(
        target_edges
            .edges
            .iter()
            .filter(|row| row.usage_kind == UsageHitKind::Reference)
            .count(),
        1,
        "{:?}",
        target_edges.edges
    );
}
