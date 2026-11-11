use super::*;

/// Selection applications resolve before the ordinary CallBindings pipeline.
/// Foreign field accesses must never enter that earlier prefetch either.
#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#10759: selection-application discovery resolved foreign procedure calls before filtering ownership"
)]
fn selection_application_prefetch_visits_only_owned_anchors() {
    for (language, path, source) in [
        (
            Language::Scala,
            "Main.scala",
            "object Main { def p1(a: Unknown) = a.first; def p2(b: Unknown) = b.second }",
        ),
        (
            Language::Kotlin,
            "Main.kt",
            "fun p1(a: Unknown) = a.first\nfun p2(b: Unknown) = b.second\n",
        ),
    ] {
        let project = InlineTestProject::with_language(language)
            .file(path, source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let analyzer = workspace.analyzer();
        let file = ProjectFile::new(project.root(), path);
        let facts = analyzer
            .structural_fact_providers()
            .iter()
            .find_map(|provider| provider.structural_facts(&file))
            .expect("structural facts");
        let ranges = facts
            .nodes()
            .iter()
            .filter(|node| node.kind == NormalizedKind::FieldAccess)
            .map(|node| node.range.start_byte..node.range.end_byte)
            .collect::<Vec<_>>();
        assert_eq!(ranges.len(), 2, "{language:?}: two procedure selections");
        for owned_ranges in [vec![], vec![ranges[0].clone()]] {
            let expected = owned_ranges.len();
            let owned = OwnedCallAnchors::new(file.clone(), owned_ranges, ranges.clone());
            let probe = CallBindingCandidateProbe::default();
            let mut bindings = CallBindingCache::default();
            let applications = relations::selection_applications_for_file(
                analyzer,
                &file,
                &facts,
                &mut bindings,
                Some(&owned),
                Some(&probe),
                None,
            );
            assert_eq!(
                probe.count(),
                expected as u64,
                "{language:?}: prefetch inputs"
            );
            assert_eq!(
                applications.len(),
                expected,
                "{language:?}: unresolved own selections remain undecided"
            );
        }
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#10759: compilation-wide target memo hits replayed foreign procedure read sets into owned queries"
)]
fn owned_scope_refuses_file_target_receipts_in_any_builder_order() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "pub fn p1() {} pub fn p2() {}")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let cache =
        crate::analyzer::usages::call_relations::CallTargetOutcomeCache::for_policy_compilation(
            workspace.analyzer(),
        )
        .expect("attested workspace call-target cache");
    let anchors = Arc::new(OwnedCallAnchors::new(
        ProjectFile::new(project.root(), "src/lib.rs"),
        Vec::new(),
        Vec::new(),
    ));
    let ordinary = CodeQueryExecutionScope::whole_workspace()
        .with_optional_shared_call_target_outcomes(Some(&cache));
    assert!(ordinary.shared_call_target_outcomes().is_some());
    let owned_first = CodeQueryExecutionScope::whole_workspace()
        .with_owned_call_anchors(Arc::clone(&anchors))
        .with_optional_shared_call_target_outcomes(Some(&cache));
    let cache_first = ordinary.with_owned_call_anchors(anchors);
    let derived = CodeQueryExecutionScope::whole_workspace()
        .with_shared_call_target_outcomes_from(&cache_first);
    for scope in [owned_first, cache_first, derived] {
        assert!(scope.shared_call_target_outcomes().is_none());
    }
}

fn query_with_fixture_call_ownership(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    query: &CodeQuery,
    owned_call_text: Option<&str>,
    unmapped_call_text: Option<&str>,
) -> CodeQueryResult {
    let files = workspace.analyzer().analyzed_files();
    let scope = CodeQueryExecutionScope::for_seed_files(std::slice::from_ref(file), &files);
    let scope = if let Some(text) = owned_call_text {
        let facts = workspace
            .analyzer()
            .structural_fact_providers()
            .iter()
            .find_map(|provider| provider.structural_facts(file))
            .expect("fixture facts");
        let calls = facts
            .nodes()
            .iter()
            .filter(|node| node.kind == NormalizedKind::Call)
            .map(|node| node.range.start_byte..node.range.end_byte)
            .collect::<Vec<_>>();
        let owned = calls
            .iter()
            .filter(|range| &facts.source()[(*range).clone()] == text)
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(owned.len(), 1, "unique fixture call anchor: {text}");
        let mapped_calls = calls
            .into_iter()
            .filter(|range| {
                unmapped_call_text.is_none_or(|unmapped| &facts.source()[range.clone()] != unmapped)
            })
            .collect();
        scope.with_owned_call_anchors(Arc::new(OwnedCallAnchors::new(
            file.clone(),
            owned,
            mapped_calls,
        )))
    } else {
        scope
    };
    execute_code_query_detailed_eager_index_workspace_in_scope(
        workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        query,
        CodeQueryExecutionLimits::default(),
        None,
        scope,
    )
    .result
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#10759: foreign unresolved sites may stop poisoning owned selection, but owned unresolved sites must remain incomplete"
)]
fn foreign_unresolved_guard_is_an_expected_completion_change() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "fn check(_x: &str) -> bool { true }\npub fn p1() { check(\"good\"); }\npub fn p2(unknown: Unknown) { unknown.check(\"bad\"); }\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let file = ProjectFile::new(project.root(), "src/lib.rs");
    let query = CodeQuery::from_sexp(
        "(language rust (call-bindings (call-shape (call :callee (name \"check\")))))",
    )
    .expect("binding query");
    let legacy = query_with_fixture_call_ownership(&workspace, &file, &query, None, None);
    let known =
        query_with_fixture_call_ownership(&workspace, &file, &query, Some("check(\"good\")"), None);
    let unknown = query_with_fixture_call_ownership(
        &workspace,
        &file,
        &query,
        Some("unknown.check(\"bad\")"),
        None,
    );
    assert_ne!(
        legacy.completion(),
        CodeQueryCompletion::Complete,
        "{legacy:#?}"
    );
    assert_eq!(
        known.completion(),
        CodeQueryCompletion::Complete,
        "{known:#?}"
    );
    assert_ne!(
        unknown.completion(),
        CodeQueryCompletion::Complete,
        "{unknown:#?}"
    );
    assert!(!known.results.is_empty());
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#10759: early ownership pruning must not lose file-level syntax recovery outside the selected procedure"
)]
fn foreign_parse_recovery_stays_incomplete_for_every_owned_visit() {
    let project = InlineTestProject::with_language(Language::Kotlin)
        .file("Main.kt", "class Broken { val x: Int = 1 +\n}\nfun check(x: Int) = true\nfun p1() { check(1) }\nfun p2() { check(2) }\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let file = ProjectFile::new(project.root(), "Main.kt");
    let query =
        CodeQuery::from_sexp("(language kotlin (call-shape (call :callee (name \"check\"))))")
            .expect("call query");
    for owned in [None, Some("check(1)"), Some("check(2)")] {
        let result = query_with_fixture_call_ownership(&workspace, &file, &query, owned, None);
        assert!(
            result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code
                    == CodeQueryDiagnosticCode::RecoveredSyntaxIncomplete),
            "{owned:?}: {result:#?}"
        );
        assert_ne!(result.completion(), CodeQueryCompletion::Complete);
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#10759: an unresolved structural call without a semantic locator was silently dropped from every owned query"
)]
fn unattributed_call_locator_keeps_selection_incomplete() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "fn check(_x: &str) -> bool { true }\npub fn p1() { check(\"good\"); }\npub fn p2(unknown: Unknown) { unknown.check(\"bad\"); }\n").build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let file = ProjectFile::new(project.root(), "src/lib.rs");
    let query = CodeQuery::from_sexp(
        "(language rust (call-bindings (call-shape (call :callee (name \"check\")))))",
    )
    .unwrap();
    let result = query_with_fixture_call_ownership(
        &workspace,
        &file,
        &query,
        Some("check(\"good\")"),
        Some("unknown.check(\"bad\")"),
    );
    assert_ne!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "{result:#?}"
    );
}
