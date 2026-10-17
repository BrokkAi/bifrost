use super::*;

fn python_import_workspace() -> inline_project::BuiltInlineTestProject {
    InlineTestProject::with_language(Language::Python)
        .file(
            "main.py",
            "import helper\nfrom helper import build as make, other\nimport helper\nfrom polluting import *\nfrom safe_export import *\nfrom unreadable_export import *\nimport missing_dependency\nfrom missing_export import *\nimport helper as renamed_helper\nimport other\n\ndef local_imports():\n    import helper\n    from helper import build\n    import other\n\nclass Local:\n    import other\n    from other import value\n",
        )
        .file("helper.py", "import helper\ndef build():\n    return 1\n")
        .file("other.py", "value = 1\n")
        .file("polluting.py", "item = 1\n")
        .file("safe_export.py", "__all__ = [\"item\"]\nitem = 1\n")
        .file("unreadable_export.py", "__all__ = build_exports()\n")
        .build()
}

fn python_import_query() -> CodeQuery {
    CodeQuery::from_json(&json!({
        "languages": ["python"],
        "match": { "kind": "import" },
        "steps": [{ "op": "python_import_site" }],
        "limit": 100,
        "result_detail": "full"
    }))
    .expect("Python import-site query")
}

#[test]
fn python_import_site_relations_preserve_forms_scope_and_incomplete_edges() {
    // Flat module paths avoid making a path-derived package identity claim;
    // package-root identity remains bounded by #3673.
    let project = python_import_workspace();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &python_import_query(),
    );

    let site_at = |path: &str, line: usize| {
        let item = result
            .results
            .iter()
            .find(|item| {
                matches!(
                    &item.value,
                    CodeQueryResultValue::StructuralMatch { value }
                        if value.path == path && value.start_line == line
                )
            })
            .unwrap_or_else(|| panic!("missing import at {path}:{line}: {result:#?}"));
        let CodeQueryResultValue::StructuralMatch { value } = &item.value else {
            unreachable!("query returns structural matches")
        };
        value
            .python_import
            .as_ref()
            .unwrap_or_else(|| panic!("import site was not enriched: {item:#?}"))
    };

    for line in [1, 2, 3] {
        let site = site_at("main.py", line);
        assert!(
            site.mixed_form,
            "same module has both import forms: {site:#?}"
        );
        assert!(site.repeated, "module is imported repeatedly: {site:#?}");
        assert!(site.complete, "flat workspace targets resolve: {site:#?}");
    }
    assert_eq!(site_at("main.py", 1).form, Some("import"));
    assert_eq!(site_at("main.py", 1).module_scope, Some(true));
    let from_site = site_at("main.py", 2);
    assert_eq!(from_site.form, Some("from"));
    assert_eq!(from_site.module.as_deref(), Some("helper"));
    assert_eq!(from_site.sites.len(), 2, "each imported name is retained");
    assert_eq!(from_site.sites[0].name.as_deref(), Some("build"));
    assert_eq!(from_site.sites[0].alias.as_deref(), Some("make"));
    assert_eq!(
        from_site.sites[0]
            .binder_range
            .as_ref()
            .map(|range| (range.start_line, range.start_column)),
        Some((2, 29)),
        "an aliased import binds at the alias token"
    );
    assert_eq!(from_site.sites[1].name.as_deref(), Some("other"));
    assert_eq!(
        from_site.sites[1]
            .binder_range
            .as_ref()
            .map(|range| (range.start_line, range.start_column)),
        Some((2, 35)),
        "an unaliased import binds at the imported name"
    );
    assert_eq!(from_site.aliases, vec!["make".to_string()]);
    let polluting = site_at("main.py", 4);
    assert_eq!(polluting.polluting, Some(true));
    assert_eq!(polluting.export_state, "absent");
    let curated = site_at("main.py", 5);
    assert_eq!(curated.polluting, Some(false));
    assert_eq!(curated.export_state, "listed");
    let unreadable = site_at("main.py", 6);
    assert!(!unreadable.complete);
    assert_eq!(unreadable.polluting, None);
    assert_eq!(unreadable.export_state, "unreadable");

    let unresolved = site_at("main.py", 7);
    assert!(!unresolved.complete);
    assert_eq!(unresolved.target_status, "no_workspace_target");
    assert_eq!(unresolved.own_module, None);
    let unresolved_wildcard = site_at("main.py", 8);
    assert!(!unresolved_wildcard.complete);
    assert_eq!(unresolved_wildcard.export_state, "unresolved");
    assert_eq!(unresolved_wildcard.polluting, None);

    let aliased = site_at("main.py", 9);
    assert_eq!(aliased.alias.as_deref(), Some("renamed_helper"));
    assert!(aliased.sites[0].binder_range.is_some());
    let different_module = site_at("main.py", 10);
    assert_eq!(different_module.module.as_deref(), Some("other"));
    assert!(!different_module.repeated);
    assert!(!different_module.mixed_form);
    let function_local_other = site_at("main.py", 15);
    assert_eq!(function_local_other.module.as_deref(), Some("other"));
    assert!(!function_local_other.repeated);
    assert!(!function_local_other.mixed_form);
    let class_local_other = site_at("main.py", 18);
    assert_eq!(class_local_other.module.as_deref(), Some("other"));
    assert_eq!(class_local_other.module_scope, Some(false));
    assert!(class_local_other.repeated);
    assert!(class_local_other.mixed_form);

    let local_namespace = site_at("main.py", 13);
    let local_from = site_at("main.py", 14);
    assert_eq!(local_namespace.module_scope, Some(false));
    assert_eq!(local_from.module_scope, Some(false));
    assert!(local_namespace.mixed_form);
    assert!(local_from.mixed_form);

    assert_eq!(site_at("helper.py", 1).own_module, Some(true));
}

#[test]
fn python_import_site_filter_selects_only_absent_all_wildcards() {
    let project = python_import_workspace();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["python"],
        "match": { "kind": "import" },
        "steps": [
            { "op": "python_import_site" },
            {
                "op": "filter",
                "where": [{
                    "field": "python_import_polluting",
                    "op": "eq",
                    "value": { "boolean": true }
                }]
            }
        ],
        "result_detail": "full"
    }))
    .expect("typed polluting import query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let locations: Vec<_> = result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::StructuralMatch { value } => {
                Some((value.path.as_str(), value.start_line))
            }
            _ => None,
        })
        .collect();
    assert_eq!(locations, vec![("main.py", 4)]);
}

#[brokk_bifrost_test_macros::hardwon(
    "#4647: repeated imports selected the first occurrence and matched across files"
)]
#[test]
fn python_import_site_duplicate_selects_later_same_binding_imports_within_file() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "main.py",
            "import os\nimport os\nimport os as imported_os\nimport os as imported_os\nimport os as other_os\nimport sys\nimport os.path\nimport os.path\nimport os.path as module_path\nimport os.path as module_path\nimport os.path as other_path\n",
        )
        .file("other.py", "import os\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["python"],
        "match": { "kind": "import" },
        "steps": [
            { "op": "python_import_site" },
            {
                "op": "filter",
                "where": [{
                    "field": "python_import_duplicate",
                    "op": "eq",
                    "value": { "boolean": true }
                }]
            }
        ],
        "limit": 100,
        "result_detail": "full"
    }))
    .expect("typed later-import query");

    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let locations: Vec<_> = result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::StructuralMatch { value } => {
                Some((value.path.as_str(), value.start_line))
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        locations,
        vec![
            ("main.py", 2),
            ("main.py", 4),
            ("main.py", 8),
            ("main.py", 10)
        ]
    );
}

#[brokk_bifrost_test_macros::hardwon(
    "#4647: deprecated fallback imports in builtin ImportError handlers were not excluded"
)]
#[test]
fn python_import_site_identifies_builtin_import_error_handler_context() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "main.py",
            "import md5\ntry:\n    import hashlib\nexcept ImportError:\n    from md5 import md5\ntry:\n    import hashlib\nexcept ValueError:\n    import md5\ntry:\n    import hashlib\nexcept (ValueError, ImportError):\n    import md5\ntry:\n    import hashlib\nexcept ImportError as error:\n    from md5 import md5\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &python_import_query(),
    );
    let imports: Vec<_> = result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::StructuralMatch { value } => value
                .python_import
                .as_ref()
                .map(|site| (value.start_line, site.in_import_error_handler)),
            _ => None,
        })
        .collect();
    assert_eq!(
        imports,
        vec![
            (1, Some(false)),
            (3, Some(false)),
            (5, Some(true)),
            (7, Some(false)),
            (9, Some(false)),
            (11, Some(false)),
            (13, Some(true)),
            (15, Some(false)),
            (17, Some(true)),
        ]
    );

    let handler_query = CodeQuery::from_json(&json!({
        "languages": ["python"],
        "match": { "kind": "import" },
        "steps": [
            { "op": "python_import_site" },
            {
                "op": "filter",
                "where": [{
                    "field": "python_import_in_import_error_handler",
                    "op": "eq",
                    "value": { "boolean": true }
                }]
            }
        ],
        "limit": 100,
        "result_detail": "full"
    }))
    .expect("typed ImportError handler filter");
    let handler_result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &handler_query,
    );
    let handler_lines: Vec<_> = handler_result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::StructuralMatch { value } => Some(value.start_line),
            _ => None,
        })
        .collect();
    assert_eq!(handler_lines, vec![5, 13, 17]);
}

#[test]
fn python_import_site_records_enclosing_main_guard_context() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "main.py",
            "import outside\nif __name__ == \"__main__\":\n    import inside\n    if ready:\n        from nested import value\nif \"__main__\" == __name__:\n    import reversed_guard\nif __name__ != \"__main__\":\n    import other_condition\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &python_import_query(),
    );
    let imports: Vec<_> = result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::StructuralMatch { value } => value
                .python_import
                .as_ref()
                .map(|site| (value.start_line, site.in_main_guard)),
            _ => None,
        })
        .collect();
    assert_eq!(
        imports,
        vec![
            (1, Some(false)),
            (3, Some(true)),
            (5, Some(true)),
            (7, Some(true)),
            (9, Some(false)),
        ]
    );

    let guarded_query = CodeQuery::from_json(&json!({
        "languages": ["python"],
        "match": { "kind": "import" },
        "steps": [
            { "op": "python_import_site" },
            {
                "op": "filter",
                "where": [{
                    "field": "python_import_in_main_guard",
                    "op": "eq",
                    "value": { "boolean": true }
                }]
            }
        ],
        "limit": 100,
        "result_detail": "full"
    }))
    .expect("typed main-guard filter");
    let guarded_result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &guarded_query,
    );
    let guarded_lines: Vec<_> = guarded_result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::StructuralMatch { value } => Some(value.start_line),
            _ => None,
        })
        .collect();
    assert_eq!(guarded_lines, vec![3, 5, 7]);
}

#[test]
fn python_import_cycles_select_only_persisted_cycle_sites_and_keep_absence_incomplete() {
    // Flat module paths avoid treating path-derived package identity as authoritative;
    // package roots remain bounded by #3673.
    let project = InlineTestProject::with_language(Language::Python)
        .file("a.py", "import b\n")
        .file("b.py", "import a\n")
        .file("self_cycle.py", "import self_cycle\n")
        .file("acyclic_a.py", "import acyclic_b\n")
        .file("acyclic_b.py", "value = 1\n")
        .file("package/a.py", "import b\n")
        .file("package/b.py", "import a\n")
        .file("unresolved.py", "import external_dependency\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["python"],
        "match": { "kind": "import" },
        "steps": [{ "op": "python_import_cycles" }],
        "limit": 100,
        "result_detail": "full"
    }))
    .expect("Python import-cycle query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );

    let states = result
        .results
        .iter()
        .map(|item| match &item.value {
            CodeQueryResultValue::StructuralMatch { value } => (
                value.path.as_str(),
                value.start_line,
                value
                    .python_import
                    .as_ref()
                    .and_then(|site| site.cycle_state),
            ),
            other => panic!("Python import-cycle query returns structural matches: {other:?}"),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        states,
        [
            ("a.py", 1, Some("cyclic")),
            ("acyclic_a.py", 1, Some("incomplete")),
            ("b.py", 1, Some("cyclic")),
            ("package/a.py", 1, Some("incomplete")),
            ("package/b.py", 1, Some("incomplete")),
            ("self_cycle.py", 1, Some("cyclic")),
            ("unresolved.py", 1, Some("incomplete")),
        ]
    );
    assert!(result.diagnostics.iter().any(|diagnostic| {
        diagnostic.message.contains("#3673")
            && diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete
    }));
    assert!(matches!(
        result.completion(),
        CodeQueryCompletion::Incomplete { .. }
    ));

    let cyclic_only = CodeQuery::from_json(&json!({
        "languages": ["python"],
        "match": { "kind": "import" },
        "steps": [
            { "op": "python_import_cycles" },
            {
                "op": "filter",
                "where": [{
                    "field": "python_import_cycle_state",
                    "op": "eq",
                    "value": { "enum": "cyclic" }
                }]
            }
        ],
        "limit": 100
    }))
    .expect("typed cycle-state filter");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &cyclic_only,
    );
    let paths = result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::StructuralMatch { value } => Some(value.path.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(paths, ["a.py", "b.py", "self_cycle.py"]);
}

#[test]
fn python_import_cycles_keep_budget_limited_absence_incomplete() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("a.py", "import c\n")
        .file("b.py", "import a\n")
        .file("c.py", "import b\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "where": ["a.py"],
        "languages": ["python"],
        "match": { "kind": "import" },
        "steps": [{ "op": "python_import_cycles" }],
        "limit": 100,
        "result_detail": "full"
    }))
    .expect("Python import-cycle query");
    let warm = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let CodeQueryResultValue::StructuralMatch { value } = &warm.results[0].value else {
        panic!("Python import-cycle query returns a structural match")
    };
    assert_eq!(
        value
            .python_import
            .as_ref()
            .and_then(|site| site.cycle_state),
        Some("cyclic")
    );

    let bounded = execute_workspace_with_limits(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
        CodeQueryExecutionLimits {
            max_scanned_files: 1,
            ..CodeQueryExecutionLimits::default()
        },
    );
    let CodeQueryResultValue::StructuralMatch { value } = &bounded.results[0].value else {
        panic!("Python import-cycle query returns a structural match")
    };
    assert_eq!(
        value
            .python_import
            .as_ref()
            .and_then(|site| site.cycle_state),
        Some("incomplete")
    );
    assert!(bounded.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == CodeQueryDiagnosticCode::ImportGraphBudgetExhausted
            && diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete
    }));
}

#[test]
fn python_unsafe_cyclic_import_proves_order_and_keeps_near_misses_open() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("a.py", "import b\nvalue = b.late\n")
        .file("b.py", "import a\nlate = 1\n")
        .file("safe_a.py", "import safe_b\nvalue = safe_b.ready\n")
        .file("safe_b.py", "ready = 1\nimport safe_a\n")
        .file(
            "deferred_a.py",
            "def load():\n    import deferred_b\n    return deferred_b.late\n",
        )
        .file("deferred_b.py", "import deferred_a\nlate = 1\n")
        .file(
            "deferred_from_a.py",
            "def load():\n    from deferred_from_b import late\n    return late\n",
        )
        .file("deferred_from_b.py", "import deferred_from_a\nlate = 1\n")
        .file("guarded_a.py", "import guarded_b\nvalue = guarded_b.late\n")
        .file("guarded_b.py", "if True:\n    import guarded_a\nlate = 1\n")
        .file("try_a.py", "import try_b\nvalue = try_b.late\n")
        .file(
            "try_b.py",
            "try:\n    import try_a\nexcept ImportError:\n    pass\nlate = 1\n",
        )
        .file("dynamic_a.py", "import dynamic_b\nvalue = dynamic_b.late\n")
        .file(
            "dynamic_b.py",
            "import dynamic_a\ndef __getattr__(name):\n    return 1\nlate = 1\n",
        )
        .file("wild_a.py", "import wild_b\nvalue = wild_b.late\n")
        .file(
            "wild_b.py",
            "import wild_a\nfrom wildcard_source import *\n",
        )
        .file("wildcard_source.py", "late = 1\n")
        .file(
            "external.py",
            "import missing_external\nvalue = missing_external.late\n",
        )
        // Nested path identity stays typed-open under #3673; only flat-module
        // paths support a definite package identity in this query.
        .file(
            "package/identity_a.py",
            "import identity_target\nvalue = identity_target.late\n",
        )
        .file("identity_target.py", "late = 1\n")
        .file("from_a.py", "from from_b import late\n")
        .file("from_b.py", "import from_a\nlate = 1\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let run = |kind: &str| {
        let query = CodeQuery::from_json(&json!({
            "languages": ["python"],
            "match": { "kind": kind },
            "steps": [{ "op": "python_unsafe_cyclic_import" }],
            "limit": 200,
            "result_detail": "full"
        }))
        .expect("unsafe Python import-cycle query");
        execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        )
    };
    let field_result = run("field_access");
    let field_facts = field_result
        .results
        .iter()
        .map(|item| match &item.value {
            CodeQueryResultValue::PythonRuleFact { value } => value.as_ref(),
            other => panic!("unsafe-cycle step returns Python rule facts: {other:?}"),
        })
        .collect::<Vec<_>>();
    for (path, line, outcome) in [
        ("a.py", 2, "issue"),
        ("safe_a.py", 2, "no_issue"),
        ("guarded_a.py", 2, "open"),
        ("try_a.py", 2, "open"),
        ("dynamic_a.py", 2, "open"),
        ("wild_a.py", 2, "open"),
        ("external.py", 2, "open"),
        ("package/identity_a.py", 2, "open"),
    ] {
        assert!(
            field_facts.iter().any(|fact| {
                fact.path == path
                    && fact.range.start_line == line
                    && fact.outcome == outcome
                    && fact.relation == "unsafe_cyclic_import"
            }),
            "missing {path}:{line} => {outcome}: {field_result:#?}"
        );
    }
    assert!(
        field_facts.iter().all(|fact| fact.path != "deferred_a.py"),
        "function-body member uses are deferred near misses: {field_result:#?}"
    );
    assert!(field_facts.iter().any(|fact| {
        fact.path == "guarded_a.py" && fact.completeness == "partial" && fact.proof == "none"
    }));
    assert!(
        field_result
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete })
    );
    assert!(
        field_result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("#3673"))
    );

    let import_result = run("import");
    let import_facts = import_result
        .results
        .iter()
        .map(|item| match &item.value {
            CodeQueryResultValue::PythonRuleFact { value } => value.as_ref(),
            other => panic!("unsafe-cycle step returns Python rule facts: {other:?}"),
        })
        .collect::<Vec<_>>();
    assert!(
        import_facts.iter().any(|fact| {
            fact.path == "from_a.py" && fact.range.start_line == 1 && fact.outcome == "issue"
        }),
        "from-import is an import-time member use: {import_result:#?}"
    );
    assert!(
        import_facts
            .iter()
            .all(|fact| fact.path != "deferred_from_a.py"),
        "function-local from-import uses are deferred: {import_result:#?}"
    );
}
