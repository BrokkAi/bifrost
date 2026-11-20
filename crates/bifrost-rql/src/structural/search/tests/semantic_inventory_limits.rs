//! Public-query contracts for source-bounded procedure inventories.
use super::*;
use brokk_bifrost_test_macros::hardwon;

#[test]
fn call_effects_releases_each_files_semantic_artifact() {
    let source = format!(
        "def sink():\n    pass\ndef run():\n{}",
        "    sink()\n".repeat(20)
    );
    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "match": { "kind": "call", "name": "sink" },
        "steps": [{ "op": "call_shape" }, { "op": "call_effects" }]
    }))
    .expect("call effects query");
    let run = |files: usize| {
        let mut project =
            InlineTestProject::with_language(Language::Python).file("a.py", source.clone());
        if files == 2 {
            project = project.file("b.py", format!("# distinct file\n{source}"));
        }
        let project = project.build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let CodeQueryResponse::Profile(profile) = execute_workspace_request(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        ) else {
            panic!("profile expected")
        };
        assert_eq!(profile.result.results.len(), files * 20);
        assert!(!profile.work.semantic.budget_exhausted);
        profile.work.semantic.resident_retained_bytes_peak
    };
    let one_file_peak = run(1);
    let two_file_peak = run(2);
    assert!(one_file_peak > 0);
    assert!(
        two_file_peak < one_file_peak * 3 / 2,
        "one={one_file_peak}, two={two_file_peak}"
    );
}

#[test]
fn procedure_inventory_reports_source_budget_exhaustion_without_rows() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("main.py", "def run():\n    marker()\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "match": { "kind": "call", "name": "marker" },
        "steps": [{ "op": "procedure_of" }]
    }))
    .expect("procedure query");
    let flow = brokk_bifrost_flow::FlowWorkspaceState::new();
    let CodeQueryResponse::Profile(complete) = execute_workspace_request(&workspace, &flow, &query)
    else {
        panic!("expected profile");
    };
    assert_eq!(complete.result.results.len(), 1, "{complete:#?}");
    let CodeQueryResponse::Profile(limited) = execute_workspace_request_with_limits(
        &workspace,
        &flow,
        &query,
        CodeQueryExecutionLimits {
            semantic: CodeQuerySemanticLimits {
                max_source_bytes: 1,
                ..CodeQuerySemanticLimits::default()
            },
            ..CodeQueryExecutionLimits::default()
        },
    ) else {
        panic!("expected profile");
    };
    assert!(limited.result.results.is_empty(), "{limited:#?}");
    assert!(limited.work.semantic.budget_exhausted, "{limited:#?}");
    assert!(
        limited.result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code() == CodeQueryDiagnosticCode::SemanticBudgetExhausted
                && diagnostic.impact() == CodeQueryDiagnosticImpact::Incomplete
        }),
        "{limited:#?}"
    );
}

#[test]
fn procedure_inventory_reports_partial_provider_budget() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "main.py",
            "def first():\n    pass\ndef second():\n    pass\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "match": { "kind": "function" },
        "steps": [{ "op": "procedure_of" }]
    }))
    .unwrap();
    let complete = execute_workspace_request(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    let CodeQueryResponse::Profile(complete) = complete else {
        panic!("profile expected")
    };
    assert_eq!(complete.result.results.len(), 2, "{complete:#?}");
    assert!(complete.result.diagnostics.is_empty(), "{complete:#?}");
    let response = execute_workspace_request_with_limits(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
        CodeQueryExecutionLimits {
            semantic: CodeQuerySemanticLimits {
                max_rows_per_dimension: 1,
                ..Default::default()
            },
            ..Default::default()
        },
    );
    let CodeQueryResponse::Profile(profile) = response else {
        panic!("profile expected")
    };
    assert!(profile.result.results.is_empty(), "{profile:#?}");
    assert!(
        profile.result.diagnostics.iter().any(|d| d.code()
            == CodeQueryDiagnosticCode::SemanticAnalysisPartial
            && d.impact() == CodeQueryDiagnosticImpact::Incomplete),
        "{profile:#?}"
    );
}

#[test]
fn value_flow_plan_for_another_root_reports_mismatch_without_exhaustion() {
    use crate::analyzer::semantic::{CancellationToken, SemanticBudget, SemanticRequest};
    use crate::structural::ValueFlowPlanRegistration;
    use brokk_bifrost_flow::value_flow::ValueFlowPlan;
    use std::sync::Arc;
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "main.py",
            "def first():\n    pass\ndef second():\n    pass\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let outcome = workspace
        .materialize_program_semantics(
            &project.file("main.py"),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .unwrap();
    let artifact = outcome.available_value().unwrap();
    let root = artifact
        .procedures()
        .iter()
        .find(|procedure| {
            procedure
                .locator()
                .declaration()
                .segments()
                .iter()
                .any(|s| s.name() == Some("first"))
        })
        .map(|procedure| artifact.procedure_handle(procedure.id()).unwrap())
        .unwrap();
    let plan = ValueFlowPlan::try_new(root, vec![], vec![], vec![], vec![]).unwrap();
    let mut registrations = ValueFlowPlanRegistrationSet::default();
    registrations
        .register(
            "test:first".parse().unwrap(),
            ValueFlowPlanRegistration::new(7, Arc::new(plan)),
        )
        .unwrap();
    let query = CodeQuery::from_json(&json!({
        "execution_mode":"profile", "match":{"kind":"function", "name":"second"},
        "steps":[{"op":"procedure_of"},{"op":"value_flow", "plan_ref":"test:first"}]
    }))
    .unwrap();
    let response = execute_workspace_request_with_analysis_registrations(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        7,
        &ProtocolRegistrationSet::default(),
        &registrations,
        &query,
        CodeQueryExecutionLimits::default(),
        None,
    );
    let CodeQueryResponse::Profile(profile) = response else {
        panic!("profile expected")
    };
    assert!(profile.result.results.is_empty(), "{profile:#?}");
    assert!(!profile.work.semantic.budget_exhausted, "{profile:#?}");
    assert!(
        profile
            .result
            .diagnostics
            .iter()
            .any(|d| d.code() == CodeQueryDiagnosticCode::ValueFlowRootMismatch),
        "{profile:#?}"
    );
}

#[test]
fn conditional_absence_merges_dynamic_write_origins_across_roots() {
    for dynamic in [
        "",
        "class Unbounded[A]:\n    def write(self, agent: A, name, value):\n        setattr(agent, name, value)\n    def other(self, agent: A, name, value):\n        setattr(agent, name, value)\n",
    ] {
        for roots in [
            "def first():\n    return read(Empty())\ndef second():\n    return read(Empty())\n",
            "def second():\n    return read(Empty())\ndef first():\n    return read(Empty())\n",
        ] {
            let source = format!(
                "class Empty:\n    pass\ndef read(x):\n    return x.missing\n{roots}{dynamic}"
            );
            let project = InlineTestProject::with_language(Language::Python)
                .file("app.py", source)
                .build();
            let workspace = project.workspace_analyzer(AnalyzerConfig::default());
            let query=CodeQuery::from_json(&json!({"match":{"kind":"function","name":{"regex":"first|second"}},"steps":[{"op":"procedure_of"},{"op":"absent_member","finding_proof":"any"}],"result_detail":"full"})).unwrap();
            let result = execute_workspace(
                &workspace,
                &brokk_bifrost_flow::FlowWorkspaceState::new(),
                &query,
            );
            assert_eq!(result.results.len(), 1, "{result:#?}");
            let item = &result.results[0];
            let CodeQueryResultValue::AbsentMemberFinding { value } = &item.value else {
                panic!("finding expected")
            };
            if dynamic.is_empty() {
                assert_eq!(value.proof, "proven");
                assert!(value.remainders.is_empty());
                assert!(value.condition.is_none());
                assert_eq!(item.provenance.len(), 2);
                continue;
            }
            assert_eq!(value.proof, "conditional");
            assert_eq!(
                value.remainders,
                ["unbounded_dynamic_write:app.py:11:9, app.py:13:9"]
            );
            let condition = value.condition.as_ref().unwrap();
            assert_eq!(condition.matches("app.py:11:9").count(), 1, "{condition}");
            assert_eq!(condition.matches("app.py:13:9").count(), 1, "{condition}");
            assert!(
                condition.contains("app.py:11:9, app.py:13:9"),
                "{condition}"
            );
            assert_eq!(
                item.provenance.len(),
                2,
                "both roots must reach the merged finding: {item:#?}"
            );
        }
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "743f1c727946: a nested function's cleanup made the enclosing procedure's pending-cleanup flow incomplete"
)]
fn nested_cleanup_does_not_make_the_outer_procedure_incomplete() {
    let query = CodeQuery::from_json(&json!({
        "match": {"kind": "function", "name": "run"},
        "steps": [{"op": "procedure_of"}, {"op": "pending_cleanup_flows"}]
    }))
    .unwrap();
    let procedure_query = CodeQuery::from_json(&json!({
        "match": {"kind": "function", "name": "run"},
        "steps": [{"op": "procedure_of"}]
    }))
    .unwrap();
    let execute = |source: &str| {
        let project = InlineTestProject::with_language(Language::Python)
            .file("main.py", source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let flow = brokk_bifrost_flow::FlowWorkspaceState::new();
        let procedures = execute_workspace(&workspace, &flow, &procedure_query);
        assert_eq!(
            procedures.results.len(),
            1,
            "the outer procedure must be selected: {procedures:#?}"
        );
        execute_workspace(&workspace, &flow, &query)
    };
    // An unfinished outer finally has syntax but no published cleanup edge.
    let unpublished = execute("def run():\n    try:\n        return 2\n    finally:\n");
    assert!(unpublished.results.is_empty(), "{unpublished:#?}");
    assert!(
        unpublished.diagnostics.iter().any(|diagnostic| {
            diagnostic.code() == CodeQueryDiagnosticCode::PendingCleanupFlowDerivationIncomplete
                && diagnostic.impact() == CodeQueryDiagnosticImpact::Incomplete
                && diagnostic
                    .message()
                    .contains("cleanup_semantics_unpublished")
        }),
        "the outer procedure's missing cleanup must remain visible: {unpublished:#?}"
    );
    let nested = execute(
        "def run():\n    def nested():\n        try:\n            return 1\n        finally:\n            pass\n    return 2\n",
    );
    assert!(nested.results.is_empty(), "{nested:#?}");
    assert!(
        !nested.diagnostics.iter().any(|diagnostic| {
            diagnostic.code() == CodeQueryDiagnosticCode::PendingCleanupFlowDerivationIncomplete
        }),
        "a lexical child's cleanup does not belong to the outer procedure: {nested:#?}"
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "743f1c727946: a nested function's cleanup made the enclosing procedure's pending-cleanup flow incomplete"
)]
fn local_class_method_cleanup_does_not_make_the_outer_procedure_incomplete() {
    use crate::analyzer::semantic::{CancellationToken, SemanticBudget, SemanticRequest};

    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "main.py",
            concat!(
                "def run():\n",
                "    class Local:\n",
                "        def method(self):\n",
                "            try:\n",
                "                return 1\n",
                "            finally:\n",
                "                pass\n",
                "        class Inner:\n",
                "            def deep(self):\n",
                "                try:\n",
                "                    return 2\n",
                "                finally:\n",
                "                    pass\n",
                "    return 3\n",
            ),
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let mut budget = SemanticBudget::default();
    let cancellation = CancellationToken::default();
    let outcome = workspace
        .materialize_program_semantics(
            &project.file("main.py"),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .unwrap();
    let artifact = outcome.available_value().expect("real Python artifact");
    let procedure_named = |name: &str| {
        artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|s| s.name())
                    == Some(name)
            })
            .expect("fixture procedure must be published")
    };
    let outer = procedure_named("run");
    let children = artifact.lexical_children(outer.id());
    for name in ["method", "deep"] {
        let method = procedure_named(name);
        println!(
            "{name}: id={:?}, lexical_parent={:?}, outer={:?}, outer_children={children:?}",
            method.id(),
            method.lexical_parent(),
            outer.id()
        );
        // Classes add declaration containers, not intermediate procedures.
        assert_eq!(method.lexical_parent(), Some(outer.id()));
        assert!(children.contains(&method.id()), "{name}: {children:?}");
    }
    let procedure_query = CodeQuery::from_json(&json!({
        "match": {"kind": "function", "name": "run"},
        "steps": [{"op": "procedure_of"}]
    }))
    .unwrap();
    let flow = brokk_bifrost_flow::FlowWorkspaceState::new();
    let procedures = execute_workspace(&workspace, &flow, &procedure_query);
    assert_eq!(procedures.results.len(), 1, "{procedures:#?}");
    let query = CodeQuery::from_json(&json!({
        "match": {"kind": "function", "name": "run"},
        "steps": [{"op": "procedure_of"}, {"op": "pending_cleanup_flows"}]
    }))
    .unwrap();
    let result = execute_workspace(&workspace, &flow, &query);
    assert!(result.results.is_empty(), "{result:#?}");
    assert!(
        !result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code() == CodeQueryDiagnosticCode::PendingCleanupFlowDerivationIncomplete
        }),
        "defining a class does not run its methods: {result:#?}"
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "743f1c727946: a nested function's cleanup made the enclosing procedure's pending-cleanup flow incomplete"
)]
fn ruby_nested_cleanup_does_not_make_the_outer_procedure_incomplete() {
    for source in [
        "def run\n  callback = proc do\n    begin\n      1\n    ensure\n      2\n    end\n  end\n  3\nend\n",
        "def run\n  callback = -> { begin; 1; ensure; 2; end }\n  3\nend\n",
    ] {
        let result = ruby_pending_cleanup(source);
        assert!(result.results.is_empty(), "{result:#?}");
        assert!(
            !result.diagnostics.iter().any(
                |d| d.code() == CodeQueryDiagnosticCode::PendingCleanupFlowDerivationIncomplete
            ),
            "{result:#?}"
        );
    }
}

fn ruby_pending_cleanup(source: &str) -> CodeQueryResult {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file("main.rb", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let flow = brokk_bifrost_flow::FlowWorkspaceState::new();
    let procedure_query = CodeQuery::from_json(
        &json!({"match":{"kind":"function","name":"run"},"steps":[{"op":"procedure_of"}]}),
    )
    .unwrap();
    let procedures = execute_workspace(&workspace, &flow, &procedure_query);
    assert_eq!(
        procedures.results.len(),
        1,
        "Ruby outer must be selected: {procedures:#?}"
    );
    let query = CodeQuery::from_json(&json!({"match":{"kind":"function","name":"run"},"steps":[{"op":"procedure_of"},{"op":"pending_cleanup_flows"}]})).unwrap();
    execute_workspace(&workspace, &flow, &query)
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "743f1c727946: Ruby pending-cleanup fallback scanned only the method header and missed the method's own ensure"
)]
fn ruby_unpublished_outer_ensure_remains_incomplete() {
    // Dynamic rescue-class expressions are not lowered, including this ensure.
    let result = ruby_pending_cleanup(
        "def run\n  begin\n    raise\n  rescue (begin; StandardError; ensure; 1; end)\n    2\n  end\nend\n",
    );
    assert!(result.results.is_empty(), "{result:#?}");
    assert!(
        result.diagnostics.iter().any(|d| {
            d.code() == CodeQueryDiagnosticCode::PendingCleanupFlowDerivationIncomplete
                && d.impact() == CodeQueryDiagnosticImpact::Incomplete
                && d.message().contains("cleanup_semantics_unpublished")
        }),
        "the outer method's unpublished ensure must be reported: {result:#?}"
    );
}

#[test]
#[hardwon("#13525: a lost witness deleted a reached endpoint and the query reported Complete")]
fn value_flow_witness_retention_accounts_for_rendered_symbol_and_event_fields() {
    use crate::analyzer::semantic::{
        CancellationToken, EvidenceCompleteness, OracleCallContext, ProofStatus, SemanticBudget,
        SemanticRequest, ValueFlowOracle, ValueFlowRelationKind,
    };
    use crate::structural::ValueFlowPlanRegistration;
    use brokk_bifrost_flow::dataflow::SemanticInputStatus;
    use brokk_bifrost_flow::value_flow::{
        ValueFlowCarrier, ValueFlowEventKey, ValueFlowEventKind, ValueFlowInput,
        ValueFlowObservationPhase, ValueFlowPlan, ValueFlowSinkSpec, ValueFlowSourceSpec,
    };
    use std::sync::Arc;
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "main.py",
            "def run(value):\n    copied = value\n    result = copied\n    return result\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let outcome = workspace
        .materialize_program_semantics(
            &project.file("main.py"),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .unwrap();
    let artifact = outcome.available_value().unwrap();
    let procedure = artifact
        .procedures()
        .iter()
        .find(|p| {
            p.locator()
                .declaration()
                .segments()
                .last()
                .and_then(|s| s.name())
                == Some("run")
        })
        .unwrap();
    let root = artifact.procedure_handle(procedure.id()).unwrap();
    let relations = workspace
        .semantic_oracle_provider()
        .procedure_relations(
            &root,
            &OracleCallContext::empty(),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .unwrap();
    let status = SemanticInputStatus::from_outcome(&relations);
    let snapshot = relations.available_value().unwrap().clone();
    let mut assignments = snapshot
        .relations()
        .iter()
        .filter(|r| r.kind == ValueFlowRelationKind::Assignment)
        .collect::<Vec<_>>();
    assignments.sort_by_key(|r| {
        let semantics = r.point().procedure().semantics();
        let point = semantics.point(r.point().id()).unwrap();
        semantics
            .source_mapping(point.source)
            .unwrap()
            .locator
            .anchor()
            .span()
            .start_byte()
    });
    let relation = assignments.first().expect("source assignment");
    let sink_relation = assignments.last().expect("sink assignment");
    assert_ne!(relation.point(), sink_relation.point());
    let source = ValueFlowSourceSpec::new(
        ValueFlowEventKey::at_point(relation.point(), 0, ValueFlowEventKind::Source).unwrap(),
        relation.point().clone(),
        ValueFlowObservationPhase::BeforeEffects,
        ValueFlowCarrier::from(&relation.source),
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
    );
    let sink = ValueFlowSinkSpec::new(
        ValueFlowEventKey::at_point(sink_relation.point(), 0, ValueFlowEventKind::Sink).unwrap(),
        sink_relation.point().clone(),
        ValueFlowObservationPhase::AfterEffects,
        ValueFlowCarrier::from(&sink_relation.target),
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
    );
    let plan = ValueFlowPlan::try_new(
        root,
        vec![ValueFlowInput::new(snapshot, status)],
        vec![],
        vec![source],
        vec![sink],
    )
    .unwrap();
    let mut registrations = ValueFlowPlanRegistrationSet::default();
    registrations
        .register(
            "test:retention".parse().unwrap(),
            ValueFlowPlanRegistration::new(7, Arc::new(plan)),
        )
        .unwrap();
    let mut query = CodeQuery::from_sexp(
        r#"(witness (value-flow :plan-ref test:retention (procedure-of (function :name "run"))))"#,
    )
    .unwrap();
    query.execution_mode = CodeQueryExecutionMode::Profile;
    query.result_detail = CodeQueryResultDetail::Full;
    let execute = |limits| {
        execute_workspace_request_with_analysis_registrations(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            7,
            &ProtocolRegistrationSet::default(),
            &registrations,
            &query,
            limits,
            None,
        )
    };
    let CodeQueryResponse::Profile(full) = execute(CodeQueryExecutionLimits::default()) else {
        panic!("profile")
    };
    let [item] = full.result.results.as_slice() else {
        panic!("one witness expected: {full:#?}")
    };
    let CodeQueryResultValue::FlowWitness { value: witness } = &item.value else {
        panic!("flow witness expected")
    };
    assert!(!witness.steps.is_empty());
    assert!(
        witness
            .steps
            .iter()
            .all(|s| s.source_symbol.is_some() && s.input.is_some() && s.output.is_some()),
        "{witness:#?}"
    );
    let facts = witness
        .steps
        .iter()
        .flat_map(|s| [&s.input, &s.output])
        .flatten()
        .collect::<Vec<_>>();
    assert!(
        facts
            .iter()
            .any(|f| matches!(f, CodeQueryFlowFactSymbol::Carrier { .. })),
        "{facts:#?}"
    );
    assert!(
        facts
            .iter()
            .any(|f| matches!(f, CodeQueryFlowFactSymbol::Meeting { .. })),
        "{facts:#?}"
    );
    // Temporary fault injection: violate RQL's always-enabled retention invariant.
    super::super::value_flow::DISABLE_WITNESS_RETENTION_13525.set(true);
    let failed = brokk_bifrost_core::panic_report::report_panics("query_code", || {
        execute(CodeQueryExecutionLimits::default())
    });
    super::super::value_flow::DISABLE_WITNESS_RETENTION_13525.set(false);
    let error = failed.expect_err("a missing witness must fail the query visibly");
    let message = error.to_string();
    assert!(
        message.contains("value-flow witness reconstruction invariant failed: RetentionDisabled"),
        "{message}"
    );
    // Every rendered string value needs at least its UTF-8 payload bytes, even
    // before JSON keys, delimiters, numbers, escaping and allocation overhead.
    let rendered = serde_json::to_value(&witness.steps).unwrap();
    let mut pending = vec![&rendered];
    let mut lower_bound = 0;
    while let Some(value) = pending.pop() {
        match value {
            serde_json::Value::String(s) => lower_bound += s.len(),
            serde_json::Value::Array(a) => pending.extend(a),
            serde_json::Value::Object(o) => pending.extend(o.values()),
            _ => {}
        }
    }
    assert!(lower_bound > 0);
    assert!(witness.retained_bytes >= lower_bound, "{witness:#?}");
    assert!(!witness.truncated, "{witness:#?}");
    let mut limits = CodeQueryExecutionLimits::default();
    limits.value_flow.max_witness_bytes = lower_bound - 1;
    let CodeQueryResponse::Profile(limited) = execute(limits) else {
        panic!("profile")
    };
    let [item] = limited.result.results.as_slice() else {
        panic!("bounded witness expected: {limited:#?}")
    };
    let CodeQueryResultValue::FlowWitness { value: bounded } = &item.value else {
        panic!("flow witness expected")
    };
    assert!(bounded.truncated, "{bounded:#?}");
    assert!(bounded.steps.len() < witness.steps.len());
    assert!(bounded.retained_bytes < lower_bound);
    assert!(
        limited
            .result
            .diagnostics
            .iter()
            .any(|d| d.code() == CodeQueryDiagnosticCode::ValueFlowWitnessTruncated),
        "{limited:#?}"
    );
    println!(
        "rendered string lower bound={lower_bound}; full bytes={}; limited bytes={}; steps={} -> {}",
        witness.retained_bytes,
        bounded.retained_bytes,
        witness.steps.len(),
        bounded.steps.len()
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "743f1c727946: a nested function's cleanup made the enclosing procedure's pending-cleanup flow incomplete"
)]
fn ruby_nested_method_cleanup_preserves_the_outer_unpublished_ensure() {
    use crate::analyzer::semantic::{CancellationToken, SemanticBudget, SemanticRequest};

    let nested = "  def inner\n    begin\n      return 1\n    ensure\n      2\n    end\n  end\n";
    let ordinary_tail = "  3\n";
    let unpublished_tail =
        "  begin\n    raise\n  rescue (begin; StandardError; ensure; 1; end)\n    2\n  end\n";
    for tail in [ordinary_tail, unpublished_tail] {
        let source = format!("def run\n{nested}{tail}end\n");
        let project = InlineTestProject::with_language(Language::Ruby)
            .file("main.rb", &source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let mut budget = SemanticBudget::default();
        let cancellation = CancellationToken::default();
        let outcome = workspace
            .materialize_program_semantics(
                &project.file("main.rb"),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .unwrap();
        let artifact = outcome.available_value().expect("real Ruby artifact");
        let procedure_named = |name: &str| {
            artifact
                .procedures()
                .iter()
                .find(|p| {
                    p.locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|s| s.name())
                        == Some(name)
                })
                .expect("fixture method must be published")
        };
        let outer = procedure_named("run");
        let inner = procedure_named("inner");
        let children = artifact.lexical_children(outer.id());
        println!(
            "Ruby inner={:?}, parent={:?}, outer={:?}, outer_children={children:?}",
            inner.id(),
            inner.lexical_parent(),
            outer.id()
        );
        assert_eq!(inner.lexical_parent(), Some(outer.id()));
        assert!(children.contains(&inner.id()), "{children:?}");

        let result = ruby_pending_cleanup(&source);
        assert!(result.results.is_empty(), "{result:#?}");
        let incomplete = result
            .diagnostics
            .iter()
            .filter(|d| d.code() == CodeQueryDiagnosticCode::PendingCleanupFlowDerivationIncomplete)
            .collect::<Vec<_>>();
        if tail == ordinary_tail {
            assert!(
                incomplete.is_empty(),
                "defining inner does not execute its ensure: {result:#?}"
            );
        } else {
            assert!(
                incomplete.iter().any(|d| {
                    d.impact() == CodeQueryDiagnosticImpact::Incomplete
                        && d.message().contains("cleanup_semantics_unpublished")
                }),
                "excluding inner must preserve the outer method's missing cleanup: {result:#?}"
            );
        }
    }
}

fn field_writes_resident_budget_run(files: usize, rows_per_dimension: usize) -> CodeQueryResponse {
    let padded = |value: i32| {
        format!(
            "use crate::Meter;\npub fn bump(m: &mut Meter) {{ m.count = {value}; }}\npub fn pad() -> [i32; 1500] {{ [{}] }}\n",
            "7, ".repeat(1500)
        )
    };
    let mut project = InlineTestProject::with_language(Language::Rust).file(
        "src/lib.rs",
        "pub mod first;\npub mod second;\npub struct Meter { pub count: i32 }\n",
    );
    project = project.file("src/first.rs", padded(10));
    if files == 2 {
        project = project.file("src/second.rs", padded(20));
    }
    let project = project.build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "match": { "kind": "class", "name": "Meter" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "members" },
            { "op": "field_writes_of" }
        ]
    }))
    .expect("field writes query");
    execute_workspace_request_with_limits(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
        CodeQueryExecutionLimits {
            semantic: CodeQuerySemanticLimits {
                max_rows_per_dimension: rows_per_dimension,
                ..Default::default()
            },
            ..Default::default()
        },
    )
}

#[test]
fn field_writes_of_releases_each_files_artifacts() {
    let run = |files: usize| {
        let CodeQueryResponse::Profile(profile) = field_writes_resident_budget_run(
            files,
            CodeQuerySemanticLimits::default().max_rows_per_dimension,
        ) else {
            panic!("profile expected")
        };
        assert_eq!(
            profile.result.results.len(),
            files,
            "{:#?}",
            profile.result.diagnostics
        );
        assert!(
            profile.result.diagnostics.is_empty(),
            "{:#?}",
            profile.result.diagnostics
        );
        profile.work.semantic.resident_retained_bytes_peak
    };
    let one_file_peak = run(1);
    let two_file_peak = run(2);
    assert!(one_file_peak > 0);
    assert!(
        two_file_peak < one_file_peak * 3 / 2,
        "one={one_file_peak}, two={two_file_peak}"
    );
}

#[test]
fn field_writes_of_still_reports_one_file_over_the_resident_budget() {
    let CodeQueryResponse::Profile(profile) = field_writes_resident_budget_run(1, RESIDENT_LIMIT)
    else {
        panic!("profile expected")
    };
    assert!(
        profile
            .result
            .diagnostics
            .iter()
            .any(|d| d.code() == CodeQueryDiagnosticCode::SemanticBudgetExhausted),
        "{profile:#?}"
    );
}

/// Below the semantic rows of one padded file.
const RESIDENT_LIMIT: usize = 6000;

// Run the production executor without rendering/dropping its request ledger,
// so the regression can compare actual resident work with surviving owners.
fn retention_query_state(workspace: &WorkspaceAnalyzer) -> Box<QueryExecutionState<'_>> {
    Box::new(QueryExecutionState {
        sink_demand: None,
        analyzer: workspace.analyzer(),

        workspace: Some(workspace),
        cancellation: None,
        scope: CodeQueryExecutionScope::default(),
        scanned_languages: HashSet::default(),
        step_outputs: Vec::new(),
        candidate_sites: HashSet::default(),
        receiver_budget_override: None,
        budget: CodeQueryExecutionBudget::default(),

        depth_bound_status: None,
        depth_answers: Vec::new(),
        seed_cache: CaptureScopedMemo::default(),

        seed_scan_ledger: SeedScanLedger::default(),
        indexed_declarations: IndexedDeclarations::default(),
        reference_cache: ReferenceTraversalCache::default(),
        occurrence_cache: OccurrenceTraversalCache::default(),
        environment_cache: EnvironmentTraversalCache::default(),
        configuration_cache: ConfigurationFactsTraversalCache::default(),
        materialization_cache: materialization::MaterializationTraversalCache::default(),
        edge_cache: EdgeTraversalCache::default(),
        flow_state_cache: FlowStateTraversalCache::default(),
        control_relation_cache: control_relations::ControlRelationTraversalCache::default(),
        branch_relation_cache: BranchRelationTraversalCache::default(),
        cpp_expression_cache: HashMap::default(),
        cpp_class_fact_cache: HashMap::default(),
        cpp_class_declaration_cache: HashMap::default(),
        rust_marker_impls_cache: rust_marker_impls::RustMarkerImplsCache::default(),
        callable_metrics_cache: HashMap::default(),
        failure_handler_state_cache: FailureHandlerStateCache::default(),
        topology_cache: topology_rows::TopologyTraversalCache::default(),
        rewrite_path_cache: RewritePathTraversalCache::default(),
        path_cache: PathTraversalCache::default(),
        call_cache: CallTraversalCache::default(),
        call_binding_identity_request: call_binding::CallBindingIdentityRequest::None,
        comparison_chain_operators: HashMap::default(),
        receiver_facts: HashMap::default(),
        receiver_service: None,
        semantic: Some(SemanticQueryContext::new(
            workspace,
            None,
            CodeQuerySemanticLimits::default(),
        )),
        pinned_row_artifacts: 0,
        semantic_factory: Box::new(move || {
            Some(SemanticQueryContext::new(
                workspace,
                None,
                CodeQuerySemanticLimits::default(),
            ))
        }),
        call_shape_work: CodeQuerySemanticWork::default(),
        import_graph: None,
        import_graph_content: None,
        direct_import_layer: None,
        direct_import_layer_content: None,
        deferred_derived_builds: HashSet::default(),
        cache_profile: None,
        profile: None,
        retained_value_census: None,
        structural_index_session: QueryStructuralIndexSession::default(),
        access_mode: StructuralAccessMode::ScanOnly,
        access_failure: None,
        parallel_seed_budget: None,
        scheduler_workers: 1,
        reuse: ReuseVerdict::Content,
    })
}

fn run_retention_plan(query: &CodeQuery, state: &mut QueryExecutionState<'_>) -> PlanExecution {
    let plan = select_physical_plan(query, UnionExecutionStrategy::Sequential, 1, 0)
        .expect("retention query plan");
    state.step_outputs = vec![0; plan.node_count()];
    let scope = AnalyzerQueryScope::with_active_semantic_model_snapshot(
        state.analyzer,
        state.analyzer.active_semantic_model_snapshot(),
    );
    let mut diagnostics = Vec::new();
    let result = execute_plan(
        &plan,
        scope.token(),
        plan.root(),
        state,
        CodeQueryExecutionLimits::default(),
        None,
        &mut diagnostics,
        &mut None,
    );
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    assert!(!result.is_truncated());
    assert!(!result.is_cancelled());
    result
}

#[test]
#[hardwon("#13211: relation and guard rows and their traces outlived refunded semantic artifacts")]
fn retained_relation_operands_and_provenance_keep_artifacts_charged() {
    use crate::analyzer::semantic::{
        CancellationToken, SemanticBudget, SemanticRequest, SemanticWork,
    };

    let source = |name: &str| {
        format!(
            "package subject\nfunc {name}(input int) int {{ x := input; if x > 0 {{ x = x + 1 }}; return x }}\n"
        )
    };
    let project = InlineTestProject::with_language(Language::Go)
        .file("first.go", source("first"))
        .file("second.go", source("second"))
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let mut expected = SemanticWork::default();
    for file in ["first.go", "second.go"] {
        let mut budget = SemanticBudget::default();
        let cancellation = CancellationToken::default();
        let materialized = workspace
            .materialize_program_semantics(
                &project.file(file),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("fixture materialization");
        expected = expected.conservative_add(
            materialized
                .available_value()
                .expect("fixture artifact")
                .work(),
        );
    }
    assert!(expected.program_points > 0);
    for family in [
        "state-events-of",
        "flow-relations-of :relation [reaching]",
        "control-relations :relation [control-depends-on]",
        "guards-of",
    ] {
        for wrapped in [false, true] {
            let operand =
                |name: &str| format!("({family} (procedure-of (function :name \"{name}\")))");
            let query = CodeQuery::from_source(&format!(
                "(union {} {})",
                operand("first"),
                operand("second")
            ))
            .expect("relation union query");
            let mut state = retention_query_state(&workspace);
            let mut execution = run_retention_plan(&query, &mut state);
            for file in [project.file("first.go"), project.file("second.go")] {
                assert!(
                    execution
                        .rows
                        .iter()
                        .any(|row| terminal_source_file(&row.value) == Some(&file)),
                    "{family}: both operands must emit rows for {file:?}"
                );
            }
            let semantic = state.semantic.as_ref().unwrap();
            let (resident, bytes) = semantic.resident_for_test();
            // ControlRelationValue holds row metadata and the public row, not a
            // semantic handle, so neither its value nor its trace pins an
            // artifact. The other relation families keep both siblings charged.
            let expected = if family.starts_with("control-relations") {
                SemanticWork::default()
            } else {
                expected
            };
            assert_eq!(
                resident, expected,
                "{family}: both live sibling artifacts stay charged"
            );
            if expected.program_points == 0 {
                assert_eq!(bytes, 0);
            } else {
                assert!(bytes > 0);
            }
            let cumulative = semantic.work();
            assert!(!cumulative.budget_exhausted);

            // Exercise values independently from provenance: an owning trace
            // must not mask a missing outer-value classification.
            for row in &mut execution.rows {
                for trace in &mut row.traces {
                    trace.steps.clear();
                }
                if wrapped {
                    row.value = PipelineValue::CrossDomain(Box::new(
                        cross_domain::CrossDomainValue::CodeWitness(Box::new(
                            PipelineValue::CrossDomain(Box::new(
                                cross_domain::CrossDomainValue::CodeWitness(Box::new(
                                    row.value.clone(),
                                )),
                            )),
                        )),
                    ));
                }
            }
            let sibling = CodeQuery::from_source("(function :name \"first\")").unwrap();
            state.pin_rows_if_retaining(&execution.rows);
            drop(run_retention_plan(&sibling, &mut state));
            assert_eq!(
                state.semantic.as_ref().unwrap().resident_for_test(),
                (resident, bytes),
                "{family}, wrapped={wrapped}: values pin through a handle-free sibling"
            );
            state.set_pinned_row_artifacts(0);

            // FileOf does not accept these row families. Isolate a production
            // trace snapshot as the only remaining semantic owner, with a
            // handle-free File terminal.
            for row in &mut execution.rows {
                let file = terminal_source_file(&row.value)
                    .expect("relation source")
                    .clone();
                let trace_value =
                    pipeline_trace_value(&row.value).expect("production trace snapshot");
                row.traces
                    .first_mut()
                    .expect("emitted row provenance")
                    .steps
                    .push(PipelineTraceStep {
                        op: QueryStep::FileOf,
                        value: trace_value,
                        via: None,
                    });
                row.value = PipelineValue::File(file);
            }
            state.pin_rows_if_retaining(&execution.rows);
            drop(run_retention_plan(&sibling, &mut state));
            assert_eq!(
                state.semantic.as_ref().unwrap().resident_for_test(),
                (resident, bytes),
                "{family}, wrapped={wrapped}: provenance pins through a handle-free sibling"
            );
            drop(execution);
            state.set_pinned_row_artifacts(0);
            state.release_unreferenced_semantic_artifacts();
            let semantic = state.semantic.as_ref().unwrap();
            assert_eq!(semantic.resident_for_test(), (SemanticWork::default(), 0));
            let released = semantic.work();
            assert_eq!(released.cumulative, cumulative.cumulative);
            assert_eq!(
                released.resident_retained_bytes_peak,
                cumulative.resident_retained_bytes_peak
            );
            assert!(!released.budget_exhausted);
        }
    }

    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "pub struct Meter { pub count: i32 }\npub fn bump(m: &mut Meter) -> i32 { m.count = 1; m.count }\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    for op in ["field-writes-of", "field-reads-of"] {
        let query = CodeQuery::from_source(&format!(
            "({op} (members (enclosing-decl (class :name \"Meter\"))))"
        ))
        .expect("field query");
        let mut state = retention_query_state(&workspace);
        let execution = run_retention_plan(&query, &mut state);
        assert!(
            !execution.rows.is_empty(),
            "{op}: field rows must be present"
        );
        assert!(execution.rows.iter().all(|row| matches!(
            row.value,
            PipelineValue::FieldWrite(_) | PipelineValue::FieldRead(_)
        )));
        // Returned field rows, including their production traces, are public
        // snapshots: keeping them must not retain the semantic file window.
        state.pin_rows_if_retaining(&execution.rows);
        state.release_unreferenced_semantic_artifacts();
        let semantic = state.semantic.as_ref().unwrap();
        let (resident, bytes) = semantic.resident_for_test();
        assert_eq!(
            bytes, 0,
            "{op}: no semantic artifact allocation remains charged"
        );
        assert_eq!(resident.source_bytes, 0);
        assert_eq!(resident.procedures, 0);
        assert_eq!(resident.program_points, 0);
        assert!(semantic.can_start_artifact_windows());
        // Derived public field evidence has its own row work; refunding an
        // artifact does not erase that independently charged work.
        assert!(!semantic.work().budget_exhausted);
    }

    let query = CodeQuery::from_source("(procedure-of (function :name \"bump\"))").unwrap();
    let mut state = retention_query_state(&workspace);
    let mut execution = run_retention_plan(&query, &mut state);
    let row = execution.rows.first_mut().expect("procedure reference row");
    let PipelineValue::Semantic(SemanticPipelineValue::ProcedureReference(reference)) = &row.value
    else {
        panic!("procedure inventory emits references")
    };
    let procedure = state
        .semantic
        .as_mut()
        .unwrap()
        .resolve_procedure_reference(reference)
        .expect("exact procedure reference resolves");
    let value = PipelineValue::Semantic(SemanticPipelineValue::Procedure(procedure));
    let snapshot = pipeline_trace_value(&value).expect("production semantic snapshot");
    drop(value);
    assert!(state.semantic.as_ref().unwrap().resident_for_test().1 > 0);
    row.traces
        .first_mut()
        .expect("procedure provenance")
        .steps
        .push(PipelineTraceStep {
            op: QueryStep::FileOf,
            value: snapshot,
            via: None,
        });
    // A cross-domain wrapper around a reference is still handle-free. Its
    // production trace must not turn this into an unconditional pin either.
    row.value = PipelineValue::CrossDomain(Box::new(cross_domain::CrossDomainValue::CodeWitness(
        Box::new(row.value.clone()),
    )));
    let wrapper_snapshot = pipeline_trace_value(&row.value).expect("reference wrapper snapshot");
    row.traces
        .first_mut()
        .unwrap()
        .steps
        .push(PipelineTraceStep {
            op: QueryStep::FileOf,
            value: wrapper_snapshot,
            via: None,
        });
    state.pin_rows_if_retaining(&execution.rows);
    state.release_unreferenced_semantic_artifacts();
    assert_eq!(
        state.semantic.as_ref().unwrap().resident_for_test(),
        (SemanticWork::default(), 0),
        "references, SemanticTraceSnapshot and handle-free cross-domain wrappers release"
    );
}

// Forward real structural facts and all required capabilities. Only the one
// bounded syntax acquisition is replaced, without cancelling the outer query.
struct MacroSyntaxStop<'a> {
    inner: &'a dyn brokk_bifrost_analysis::analyzer::structural::provider::StructuralFactProvider,
    outcome: std::sync::Mutex<
        Option<
            brokk_bifrost_analysis::analyzer::structural::provider::StructuralSyntaxLimitedOutcome,
        >,
    >,
}

impl brokk_bifrost_analysis::analyzer::structural::provider::StructuralFactProvider
    for MacroSyntaxStop<'_>
{
    fn structural_language(&self) -> Language {
        self.inner.structural_language()
    }
    fn structural_files(&self) -> Vec<ProjectFile> {
        self.inner.structural_files()
    }
    fn structural_source(&self, file: &ProjectFile) -> Option<String> {
        self.inner.structural_source(file)
    }
    fn structural_facts(&self, file: &ProjectFile) -> Option<Arc<FileFacts>> {
        self.inner.structural_facts(file)
    }
    fn structural_syntax_limited(
        &self,
        file: &ProjectFile,
        max_source_bytes: usize,
        cancellation: Option<&CancellationToken>,
    ) -> brokk_bifrost_analysis::analyzer::structural::provider::StructuralSyntaxLimitedOutcome
    {
        assert!(cancellation.is_none());
        let facts = self.inner.structural_facts(file).expect("real Rust facts");
        assert_eq!(max_source_bytes, facts.source().len());
        self.outcome
            .lock()
            .unwrap()
            .take()
            .expect("one macro inspection")
    }
    fn structural_extraction_count(&self) -> u64 {
        self.inner.structural_extraction_count()
    }
    fn structural_hydration_count(&self) -> u64 {
        self.inner.structural_hydration_count()
    }
    fn structural_supports_kind(&self, kind: NormalizedKind) -> bool {
        self.inner.structural_supports_kind(kind)
    }
    fn structural_supports_role(&self, role: Role) -> bool {
        self.inner.structural_supports_role(role)
    }
    fn structural_supports_occurrence_role(
        &self,
        role: brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceRole,
    ) -> bool {
        self.inner.structural_supports_occurrence_role(role)
    }
    fn structural_supports_environment_axis(
        &self,
        axis: brokk_bifrost_core::analyzer::structural::resolution::EnvironmentAxis,
    ) -> bool {
        self.inner.structural_supports_environment_axis(axis)
    }
    fn structural_supports_materialization_axis(
        &self,
        axis: brokk_bifrost_core::analyzer::structural::materialization::MaterializationAxis,
    ) -> bool {
        self.inner.structural_supports_materialization_axis(axis)
    }
    fn structural_supports_edge_axis(
        &self,
        axis: brokk_bifrost_core::analyzer::structural::edges::EdgeAxis,
    ) -> bool {
        self.inner.structural_supports_edge_axis(axis)
    }
    fn structural_supports_identity_axis(
        &self,
        axis: brokk_bifrost_core::analyzer::structural::routes::IdentityAxis,
    ) -> bool {
        self.inner.structural_supports_identity_axis(axis)
    }
    fn structural_supports_route_relation(
        &self,
        relation: brokk_bifrost_core::analyzer::structural::routes::RouteHopKind,
    ) -> bool {
        self.inner.structural_supports_route_relation(relation)
    }
}

#[test]
#[hardwon(
    "#13211: macro inspection source failures and stops vanished without field usage candidates"
)]
fn field_macro_syntax_stops_are_reported_without_usages() {
    use brokk_bifrost_analysis::analyzer::structural::provider::StructuralSyntaxLimitedOutcome;
    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "match": { "kind": "class", "name": "Generated" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "members" },
            { "op": "field_writes_of" }
        ]
    }))
    .unwrap();
    // Public controls prove the empty inventory is a real declared field,
    // whose derive requires inspection despite having no source usages.
    for (attribute, expected) in [
        ("", CodeQueryCompletion::Complete),
        (
            "#[derive(Default)]\n",
            CodeQueryCompletion::Incomplete {
                codes: vec![CodeQueryDiagnosticCode::SemanticAnalysisPartial],
            },
        ),
    ] {
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "src/lib.rs",
                format!("{attribute}pub struct Generated {{ pub count: i32 }}\n"),
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let CodeQueryResponse::Profile(profile) = execute_workspace_request(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        ) else {
            panic!("profile expected");
        };
        assert!(profile.result.results.is_empty(), "{profile:#?}");
        assert_eq!(profile.result.completion(), expected, "{profile:#?}");
    }
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            "#[derive(Default)]\npub struct Generated { pub count: i32 }\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let unit = analyzer
        .get_all_declarations()
        .into_iter()
        .find(|unit| unit.identifier() == "count")
        .expect("real field declaration");
    let range = analyzer.ranges_of(&unit)[0];
    let declaration = DeclarationValue::new(unit, range);
    let provider = analyzer
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == Language::Rust)
        .unwrap();
    let knowledge = crate::analyzer::languages::language_knowledge(Language::Rust).unwrap();
    let facts = provider
        .structural_facts(declaration.unit.source())
        .unwrap();
    let matching =
        provider.structural_syntax_limited(declaration.unit.source(), facts.source().len(), None);
    let StructuralSyntaxLimitedOutcome::Available(matching) = matching else {
        panic!("real matching Rust syntax must be available");
    };
    assert_eq!(matching.prepared().source(), facts.source());
    // A second real provider supplies a valid tree for its own source. Returning
    // that outcome beside the first provider's facts models lost source authority
    // without constructing a false tree/source pair or changing a live snapshot.
    let other_project = InlineTestProject::with_language(Language::Rust)
        .file(
            "src/lib.rs",
            "#[derive(Default)]\npub struct Generated { pub count: i64 }\n",
        )
        .build();
    let other_workspace = other_project.workspace_analyzer(AnalyzerConfig::default());
    let other_provider = other_workspace
        .analyzer()
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == Language::Rust)
        .unwrap();
    let other_file = other_project.file("src/lib.rs");
    let other_facts = other_provider.structural_facts(&other_file).unwrap();
    assert_eq!(other_facts.source().len(), facts.source().len());
    let mismatched =
        other_provider.structural_syntax_limited(&other_file, other_facts.source().len(), None);
    let StructuralSyntaxLimitedOutcome::Available(mismatched) = mismatched else {
        panic!("real second Rust syntax must be available");
    };
    assert_ne!(mismatched.prepared().source(), facts.source());
    use brokk_bifrost_core::analyzer::reuse_verdict::{CarriesReuseVerdict, ReuseVerdict};
    let matching_provider = MacroSyntaxStop {
        inner: provider,
        outcome: std::sync::Mutex::new(Some(StructuralSyntaxLimitedOutcome::Available(matching))),
    };
    let mut matching_semantic =
        SemanticQueryContext::new(&workspace, None, CodeQuerySemanticLimits::default());
    field_access::report_field_access_macros_from_provider(
        "field_writes_of",
        analyzer,
        &mut matching_semantic,
        &declaration,
        None,
        knowledge,
        &matching_provider,
    );
    let matching_diagnostics = matching_semantic.take_diagnostics();
    assert!(
        matches!(matching_diagnostics.as_slice(), [diagnostic]
        if diagnostic.code == CodeQueryDiagnosticCode::SemanticAnalysisPartial
            && diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete
            && diagnostic.incompleteness == Incompleteness::Content
            && diagnostic.reuse_verdict() == ReuseVerdict::Content
            && diagnostic.message.contains(&declaration.unit.fq_name())
            && diagnostic.message.contains("derive(Default)")),
        "{matching_diagnostics:#?}"
    );
    let mut observed = Vec::new();
    // Each provider outcome is consumed with the real facts-length bound and
    // an uncancelled request. Collect every case before asserting so failures
    // identify both missing source-authority reasons independently.
    for (label, outcome, code, expected_cause, expected_reuse) in [
        (
            "budget",
            StructuralSyntaxLimitedOutcome::Exceeded {
                minimum_source_bytes: facts.source().len() + 1,
            },
            CodeQueryDiagnosticCode::SemanticBudgetExhausted,
            Incompleteness::Operational(brokk_bifrost_rql::DiagnosticExecutionCause::Budget),
            EXECUTION_DEPENDENT,
        ),
        (
            "cancelled",
            StructuralSyntaxLimitedOutcome::Cancelled,
            CodeQueryDiagnosticCode::Cancelled,
            Incompleteness::Operational(brokk_bifrost_rql::DiagnosticExecutionCause::Cancelled),
            EXECUTION_DEPENDENT,
        ),
        (
            "unavailable",
            StructuralSyntaxLimitedOutcome::Unavailable,
            CodeQueryDiagnosticCode::SemanticAnalysisPartial,
            Incompleteness::Content,
            ReuseVerdict::Content,
        ),
        (
            "source mismatch",
            StructuralSyntaxLimitedOutcome::Available(mismatched),
            CodeQueryDiagnosticCode::SemanticAnalysisPartial,
            Incompleteness::Operational(brokk_bifrost_rql::DiagnosticExecutionCause::Snapshot),
            EXECUTION_DEPENDENT,
        ),
    ] {
        let provider = MacroSyntaxStop {
            inner: provider,
            outcome: std::sync::Mutex::new(Some(outcome)),
        };
        let mut semantic =
            SemanticQueryContext::new(&workspace, None, CodeQuerySemanticLimits::default());
        field_access::report_field_access_macros_from_provider(
            "field_writes_of",
            analyzer,
            &mut semantic,
            &declaration,
            None,
            knowledge,
            &provider,
        );
        assert!(
            provider.outcome.lock().unwrap().is_none(),
            "syntax boundary was not exercised"
        );
        observed.push((
            label,
            code,
            expected_cause,
            expected_reuse,
            semantic.take_diagnostics(),
        ));
    }
    assert!(
        observed
            .iter()
            .all(|(_, code, expected_cause, expected_reuse, diagnostics)| {
                matches!(diagnostics.as_slice(), [diagnostic]
            if diagnostic.code == *code
                && diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete
                && diagnostic.incompleteness == *expected_cause
                && diagnostic.reuse_verdict() == *expected_reuse
                && diagnostic.message.contains("field_writes_of")
                && diagnostic.message.contains(&declaration.unit.fq_name())
                && diagnostic.message.contains(&rel_path_string(declaration.unit.source())))
            }),
        "{observed:#?}"
    );
}
