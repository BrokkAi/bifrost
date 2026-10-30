//! Public-query contracts for source-bounded procedure inventories.
use super::*;

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
            diagnostic.code == CodeQueryDiagnosticCode::SemanticBudgetExhausted
                && diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete
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
        profile.result.diagnostics.iter().any(|d| d.code
            == CodeQueryDiagnosticCode::SemanticAnalysisPartial
            && d.impact == CodeQueryDiagnosticImpact::Incomplete),
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
            .any(|d| d.code == CodeQueryDiagnosticCode::ValueFlowRootMismatch),
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
            diagnostic.code == CodeQueryDiagnosticCode::PendingCleanupFlowDerivationIncomplete
                && diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete
                && diagnostic.message.contains("cleanup_semantics_unpublished")
        }),
        "the outer procedure's missing cleanup must remain visible: {unpublished:#?}"
    );
    let nested = execute(
        "def run():\n    def nested():\n        try:\n            return 1\n        finally:\n            pass\n    return 2\n",
    );
    assert!(nested.results.is_empty(), "{nested:#?}");
    assert!(
        !nested.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::PendingCleanupFlowDerivationIncomplete
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
            diagnostic.code == CodeQueryDiagnosticCode::PendingCleanupFlowDerivationIncomplete
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
            !result
                .diagnostics
                .iter()
                .any(|d| d.code == CodeQueryDiagnosticCode::PendingCleanupFlowDerivationIncomplete),
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
            d.code == CodeQueryDiagnosticCode::PendingCleanupFlowDerivationIncomplete
                && d.impact == CodeQueryDiagnosticImpact::Incomplete
                && d.message.contains("cleanup_semantics_unpublished")
        }),
        "the outer method's unpublished ensure must be reported: {result:#?}"
    );
}

#[test]
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
    let query=CodeQuery::from_json(&json!({"execution_mode":"profile","match":{"kind":"function","name":"run"},
        "steps":[{"op":"procedure_of"},{"op":"value_flow","plan_ref":"test:retention"},{"op":"witness"}],"result_detail":"full"})).unwrap();
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
            .any(|d| d.code == CodeQueryDiagnosticCode::ValueFlowWitnessTruncated),
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
            .filter(|d| d.code == CodeQueryDiagnosticCode::PendingCleanupFlowDerivationIncomplete)
            .collect::<Vec<_>>();
        if tail == ordinary_tail {
            assert!(
                incomplete.is_empty(),
                "defining inner does not execute its ensure: {result:#?}"
            );
        } else {
            assert!(
                incomplete.iter().any(|d| {
                    d.impact == CodeQueryDiagnosticImpact::Incomplete
                        && d.message.contains("cleanup_semantics_unpublished")
                }),
                "excluding inner must preserve the outer method's missing cleanup: {result:#?}"
            );
        }
    }
}
