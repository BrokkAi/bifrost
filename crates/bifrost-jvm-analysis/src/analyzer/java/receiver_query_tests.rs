#[cfg(test)]
mod jvm_extraction_tests {
    use crate::analyzer::java::receiver_query::*;
    use brokk_bifrost_analysis::analyzer::usages::receiver_analysis::ReceiverValue;

    use brokk_bifrost_analysis::analyzer::semantic::AbstractObjectIdentity;

    use std::sync::Arc;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_core::analyzer::model::CodeUnit;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::CompatibilityOutcome;

    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;

    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisOutcome;

    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisWork;

    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverBudgetLimit;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::ReceiverQueryAnalysis;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::ReceiverQueryError;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::ReceiverQueryInput;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::ReceiverQueryOperation;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::ReceiverQueryService;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::ReceiverWorkLedger;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::SemanticReceiverGate;

    use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupOutcome;

    use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupStatus;

    use brokk_bifrost_analysis::analyzer::usages::target_kind::TypeLookupTargetKind;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::test_support::marker_range;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::project_receiver_values;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::test_support::range_at;

    use brokk_bifrost_core::analyzer::usages::reference_site::smallest_named_node_covering;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::analyzer::project::TestProject;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
    use std::path::PathBuf;
    #[test]
    fn java_queries_reuse_prepared_context_and_honor_bounds() {
        let source = r#"
class Service { void run() {} void run(int value) {} }
class Sample {
void caller() {
    Service service = new Service();
    service.run();
}
}
"#;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), PathBuf::from("Sample.java"));
        file.write(source).expect("write source");
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(TestProject::new(root, Language::Java)),
            AnalyzerConfig::default(),
        )
        .expect("ephemeral workspace should build");
        let service = ReceiverQueryService::from_workspace(&workspace);
        let range = marker_range(source, "service.run");

        let first = service
            .analyze(
                ReceiverQueryOperation::MemberTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("first Java receiver query");
        let second = service
            .analyze(
                ReceiverQueryOperation::MemberTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("second Java receiver query");

        assert_eq!(service.prepared_file_count(), 1);
        assert!(first.work.setup_nodes > 0);
        assert_eq!(second.work.setup_nodes, 0);
        for report in [&first, &second] {
            assert!(
                matches!(
                    report.analysis,
                    ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Precise(ref targets))
                        if targets.len() == 1
                ),
                "unexpected Java member-target report: {report:#?}"
            );
        }
        assert_eq!(
            service
                .prepared_java_files
                .borrow()
                .get(&file)
                .expect("prepared Java file")
                .line_starts,
            compute_line_starts(source)
        );

        let warm_scope_budget = ReceiverAnalysisBudget {
            max_scope_nodes: second.work.scope_nodes.saturating_sub(1),
            ..ReceiverAnalysisBudget::default()
        };
        let bounded_warm = service
            .analyze(
                ReceiverQueryOperation::MemberTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                warm_scope_budget,
                None,
            )
            .expect("aggregate-bounded warm Java receiver query");
        assert_eq!(bounded_warm.work.setup_nodes, 0);
        assert!(
            bounded_warm.work.scope_nodes <= warm_scope_budget.max_scope_nodes,
            "warm query must not exceed its aggregate scope ledger"
        );
        assert!(matches!(
            bounded_warm.analysis,
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::ExceededBudget {
                limit: "scope_nodes"
            })
        ));

        let capped = service
            .analyze(
                ReceiverQueryOperation::MemberTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget {
                    max_targets: 1,
                    ..ReceiverAnalysisBudget::default()
                },
                None,
            )
            .expect("candidate-capped Java receiver query");
        assert!(!capped.candidates_truncated);
        assert!(matches!(
            capped.analysis,
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Precise(ref targets))
                if targets.len() == 1
        ));

        let bounded_service = ReceiverQueryService::from_workspace(&workspace);
        let bounded = bounded_service
            .analyze(
                ReceiverQueryOperation::MemberTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget::tiny(),
                None,
            )
            .expect("tiny-budget Java receiver query");
        assert!(matches!(
            bounded.analysis,
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::ExceededBudget {
                limit: "scope_nodes"
            })
        ));
        assert_eq!(bounded.work.setup_nodes, 1);
        assert!(
            bounded
                .work
                .setup_nodes
                .saturating_add(bounded.work.scope_nodes)
                <= ReceiverAnalysisBudget::tiny().max_scope_nodes
        );

        let cancellation = CancellationToken::default();
        cancellation.cancel();
        assert_eq!(
            service.analyze(
                ReceiverQueryOperation::MemberTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget::default(),
                Some(&cancellation),
            ),
            Err(ReceiverQueryError::Cancelled)
        );
    }
    #[test]
    fn java_site_parent_walks_share_scope_budget_and_cancellation() {
        let source = r#"
class Service { void run() {} }
class Sample {
void caller() {
    Service service = new Service();
    service.run();
}
}
"#;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root, PathBuf::from("ParentWalks.java"));
        file.write(source).expect("write source");
        let tree = parse_tree_for_language(&file, Language::Java, source).expect("Java tree");
        let call_range = marker_range(source, "service.run");
        let invocation = smallest_named_node_covering(
            tree.root_node(),
            call_range.start_byte,
            call_range.end_byte,
        )
        .expect("method invocation");
        let receiver = invocation
            .child_by_field_name("object")
            .expect("receiver node");
        let member = invocation.child_by_field_name("name").expect("member node");
        let one_step_budget = ReceiverAnalysisBudget {
            max_scope_nodes: 1,
            ..ReceiverAnalysisBudget::default()
        };

        let mut receiver_ledger = ReceiverWorkLedger::new(one_step_budget);
        let receiver_result = java_receiver_at_site(member, None, &mut receiver_ledger)
            .expect("bounded receiver parent walk");
        assert!(matches!(
            receiver_result,
            CompatibilityOutcome::Complete(Some(node)) if node == receiver
        ));
        assert_eq!(receiver_ledger.work().scope_nodes, 1);

        let mut member_ledger = ReceiverWorkLedger::new(one_step_budget);
        let member_result = java_member_node_at_site(receiver, None, &mut member_ledger)
            .expect("bounded member parent walk");
        assert!(matches!(
            member_result,
            CompatibilityOutcome::Complete(Some(node)) if node == member
        ));
        assert_eq!(member_ledger.work().scope_nodes, 1);

        let mut contextual_ledger = ReceiverWorkLedger::new(one_step_budget);
        let contextual_result = java_contextual_type_node(receiver, None, &mut contextual_ledger)
            .expect("bounded contextual parent walk");
        assert!(matches!(
            contextual_result,
            CompatibilityOutcome::Exceeded(ReceiverBudgetLimit::ScopeNodes)
        ));
        assert_eq!(contextual_ledger.work().scope_nodes, 1);

        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let mut cancelled_ledger = ReceiverWorkLedger::new(ReceiverAnalysisBudget::default());
        assert!(matches!(
            java_receiver_at_site(member, Some(&cancellation), &mut cancelled_ledger),
            Err(ReceiverQueryError::Cancelled)
        ));
        assert_eq!(cancelled_ledger.work(), ReceiverAnalysisWork::default());
    }
    #[test]
    fn java_compatibility_resolution_bounds_deep_hierarchy_and_precancellation() {
        let mut source = String::from("class Root { void target() {} }\n");
        for level in 1..=12 {
            let parent = if level == 1 {
                "Root".to_string()
            } else {
                format!("Level{}", level - 1)
            };
            source.push_str(&format!("class Level{level} extends {parent} {{}}\n"));
        }
        source.push_str(
            "class Sample { void caller() { Level12 value = new Level12(); value.target(); } }\n",
        );

        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), PathBuf::from("DeepHierarchy.java"));
        file.write(&source).expect("write source");
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(TestProject::new(root, Language::Java)),
            AnalyzerConfig::default(),
        )
        .expect("ephemeral workspace should build");
        let service = ReceiverQueryService::from_workspace(&workspace);
        let tree = parse_tree_for_language(&file, Language::Java, &source).expect("Java tree");
        let line_starts = compute_line_starts(&source);
        let resolution_input = JavaReceiverResolutionInput {
            source: &source,
            tree: &tree,
            line_starts: &line_starts,
        };
        let root_node = tree.root_node();
        let range = marker_range(&source, "value.target");
        let invocation =
            smallest_named_node_covering(tree.root_node(), range.start_byte, range.end_byte)
                .expect("method invocation");
        let node = invocation.child_by_field_name("name").expect("method name");
        let no_preprocessing_budget = ReceiverAnalysisBudget {
            max_scope_nodes: 0,
            ..ReceiverAnalysisBudget::default()
        };
        let preprocessing_exceeded = java_definition_at(
            service.analyzer,
            &service.definitions,
            &file,
            resolution_input,
            root_node,
            no_preprocessing_budget,
            None,
        );
        assert!(matches!(
            preprocessing_exceeded,
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                work,
            } if work == ReceiverAnalysisWork::default()
        ));
        let preprocessing_cancellation = CancellationToken::default();
        preprocessing_cancellation.cancel();
        let preprocessing_cancelled = java_definition_at(
            service.analyzer,
            &service.definitions,
            &file,
            resolution_input,
            root_node,
            ReceiverAnalysisBudget::default(),
            Some(&preprocessing_cancellation),
        );
        assert!(matches!(
            preprocessing_cancelled,
            BoundedResolution::Cancelled { work }
                if work == ReceiverAnalysisWork::default()
        ));
        let one_preprocessing_step = java_definition_at(
            service.analyzer,
            &service.definitions,
            &file,
            resolution_input,
            root_node,
            ReceiverAnalysisBudget {
                max_scope_nodes: 1,
                ..ReceiverAnalysisBudget::default()
            },
            None,
        );
        assert!(matches!(
            one_preprocessing_step,
            BoundedResolution::Complete {
                value: DefinitionLookupOutcome {
                    status: DefinitionLookupStatus::InvalidLocation,
                    ..
                },
                work,
            } if work == ReceiverAnalysisWork {
                scope_nodes: 1,
                ..ReceiverAnalysisWork::default()
            }
        ));
        let budget = ReceiverAnalysisBudget {
            max_summary_expansions: 4,
            ..ReceiverAnalysisBudget::default()
        };

        let exceeded = java_definition_at(
            service.analyzer,
            &service.definitions,
            &file,
            resolution_input,
            node,
            budget,
            None,
        );
        assert!(
            matches!(
                &exceeded,
                BoundedResolution::Exceeded {
                    limit: ReceiverBudgetLimit::SummaryExpansions,
                    work,
                } if work.summary_expansions == budget.max_summary_expansions
                    && work.scope_nodes <= budget.max_scope_nodes
            ),
            "deep hierarchy must stop at the shared compatibility budget: {exceeded:#?}"
        );

        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let cancelled = java_definition_at(
            service.analyzer,
            &service.definitions,
            &file,
            resolution_input,
            node,
            ReceiverAnalysisBudget::default(),
            Some(&cancellation),
        );
        assert!(
            matches!(
                &cancelled,
                BoundedResolution::Cancelled { work }
                    if *work == ReceiverAnalysisWork::default()
            ),
            "pre-cancelled resolution must not perform compatibility work: {cancelled:#?}"
        );

        let warm = service
            .analyze(
                ReceiverQueryOperation::MemberTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("warm Java receiver query");
        assert!(matches!(
            warm.analysis,
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Precise(ref targets))
                if targets.len() == 1 && targets[0].fq_name().ends_with("Root.target")
        ));
        let gate = service
            .semantic_receiver_gate(
                &file,
                warm.site.range,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("isolated Java semantic gate");
        assert!(gate.exceeded_limit().is_none());
        let gate_work = gate.work();
        let aggregate_budget = ReceiverAnalysisBudget {
            max_summary_expansions: gate_work.summary_expansions + 4,
            ..ReceiverAnalysisBudget::default()
        };
        let aggregate = service
            .analyze(
                ReceiverQueryOperation::MemberTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                aggregate_budget,
                None,
            )
            .expect("aggregate-bounded Java receiver query");
        assert_eq!(aggregate.work.setup_nodes, 0);
        assert!(aggregate.work.summary_expansions <= aggregate_budget.max_summary_expansions);
        assert!(
            aggregate
                .work
                .setup_nodes
                .saturating_add(aggregate.work.scope_nodes)
                <= aggregate_budget.max_scope_nodes
        );
        assert!(matches!(
            aggregate.analysis,
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::ExceededBudget {
                limit: "summary_expansions"
            })
        ));
    }
    #[test]
    fn java_allocation_projection_stops_at_target_cap_lookahead() {
        let mut source = String::from(
            "class Service { void run() {} }\nclass Sample { void caller(int choice) {\n  Service service;\n",
        );
        for branch in 0..7 {
            if branch == 0 {
                source.push_str(&format!(
                    "  if (choice == {branch}) service = new Service();\n"
                ));
            } else {
                source.push_str(&format!(
                    "  else if (choice == {branch}) service = new Service();\n"
                ));
            }
        }
        source.push_str("  else service = new Service();\n  service.run();\n} }\n");

        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), PathBuf::from("Allocations.java"));
        file.write(&source).expect("write source");
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(TestProject::new(root, Language::Java)),
            AnalyzerConfig::default(),
        )
        .expect("ephemeral workspace should build");
        let service = ReceiverQueryService::from_workspace(&workspace);
        let receiver_start = source.rfind("service.run").expect("receiver call");
        let receiver_range = range_at(&source, "service", receiver_start);
        let gate = service
            .semantic_receiver_gate(
                &file,
                receiver_range,
                ReceiverAnalysisBudget {
                    max_targets: 16,
                    ..ReceiverAnalysisBudget::default()
                },
                None,
            )
            .expect("Java semantic points-to gate");
        let points_to = match gate {
            SemanticReceiverGate::Available { points_to, .. } => points_to,
            _ => panic!("expected Java allocation points-to facts"),
        };

        let total_candidates = points_to.object_candidates().count();
        let mut allocations = Vec::new();
        let mut lookahead_steps = 0usize;
        for candidate in points_to.object_candidates() {
            lookahead_steps += 1;
            if let AbstractObjectIdentity::Allocation(allocation) = candidate.value().identity()
                && !allocations.contains(allocation)
            {
                allocations.push(allocation.clone());
                if allocations.len() == 2 {
                    break;
                }
            }
        }
        assert_eq!(
            allocations.len(),
            2,
            "fixture must expose multiple allocations"
        );
        assert!(
            total_candidates > lookahead_steps,
            "fixture must contain work beyond the max_targets=1 lookahead"
        );

        let service_type = workspace
            .analyzer()
            .definitions("Service")
            .find(CodeUnit::is_class)
            .expect("Service definition");
        let type_outcome = TypeLookupOutcome {
            status: TypeLookupStatus::Resolved,
            reference: None,
            types: vec![TypeLookupType {
                fqn: service_type.fq_name(),
                definitions: vec![service_type],
                semantic_model_id: None,
            }],
            diagnostics: Vec::new(),
            target_kind: TypeLookupTargetKind::ValueExpression,
        };
        let projection_scope = lookahead_steps + 2;
        let mut ledger = ReceiverWorkLedger::new(ReceiverAnalysisBudget {
            max_scope_nodes: projection_scope,
            max_targets: 1,
            ..ReceiverAnalysisBudget::default()
        });
        let projected = project_receiver_values(
            &workspace,
            &points_to,
            &type_outcome,
            &[],
            false,
            None,
            &mut ledger,
        )
        .expect("bounded allocation projection");
        assert!(
            matches!(
                projected,
                CompatibilityOutcome::Complete(ReceiverValueProjection {
                    ref values,
                    truncated: true,
                    ..
                })
                    if matches!(values.as_slice(), [ReceiverValue::AllocationSite { .. }])
            ),
            "projection must return one allocation and report truncation"
        );
        assert_eq!(ledger.work().scope_nodes, projection_scope);

        let cartesian_source = r#"
class Service { void run() {} }
class AlternateService {}
class Sample {
void caller(boolean choice) {
    Service service;
    if (choice) service = new Service();
    else service = new Service();
    service.run();
}
}
"#;
        let cartesian_temp = tempfile::tempdir().expect("cartesian temp dir");
        let cartesian_root = cartesian_temp
            .path()
            .canonicalize()
            .expect("canonical cartesian temp dir");
        let cartesian_file = ProjectFile::new(
            cartesian_root.clone(),
            PathBuf::from("CartesianAllocations.java"),
        );
        cartesian_file
            .write(cartesian_source)
            .expect("write cartesian source");
        let cartesian_workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(TestProject::new(cartesian_root, Language::Java)),
            AnalyzerConfig::default(),
        )
        .expect("ephemeral workspace should build");
        let cartesian_service = ReceiverQueryService::from_workspace(&cartesian_workspace);
        let cartesian_receiver_start = cartesian_source
            .rfind("service.run")
            .expect("cartesian receiver call");
        let cartesian_range = range_at(cartesian_source, "service", cartesian_receiver_start);
        let cartesian_gate = cartesian_service
            .semantic_receiver_gate(
                &cartesian_file,
                cartesian_range,
                ReceiverAnalysisBudget {
                    max_targets: 16,
                    ..ReceiverAnalysisBudget::default()
                },
                None,
            )
            .expect("cartesian Java semantic points-to gate");
        let cartesian_points_to = match cartesian_gate {
            SemanticReceiverGate::Available { points_to, .. } => points_to,
            _ => panic!("expected cartesian Java allocation points-to facts"),
        };
        let cartesian_candidate_steps = cartesian_points_to.object_candidates().count();
        let mut cartesian_allocations = Vec::new();
        for candidate in cartesian_points_to.object_candidates() {
            if let AbstractObjectIdentity::Allocation(allocation) = candidate.value().identity()
                && !cartesian_allocations.contains(allocation)
            {
                cartesian_allocations.push(allocation.clone());
            }
        }
        assert_eq!(
            cartesian_allocations.len(),
            2,
            "fixture must expose exactly two retained allocations"
        );

        let cartesian_analyzer = cartesian_workspace.analyzer();
        let service_type = cartesian_analyzer
            .definitions("Service")
            .find(CodeUnit::is_class)
            .expect("cartesian Service definition");
        let alternate_type = cartesian_analyzer
            .definitions("AlternateService")
            .find(CodeUnit::is_class)
            .expect("AlternateService definition");
        let cartesian_types = TypeLookupOutcome {
            status: TypeLookupStatus::Ambiguous,
            reference: None,
            types: vec![
                TypeLookupType {
                    fqn: service_type.fq_name(),
                    definitions: vec![service_type],
                    semantic_model_id: None,
                },
                TypeLookupType {
                    fqn: alternate_type.fq_name(),
                    definitions: vec![alternate_type],
                    semantic_model_id: None,
                },
            ],
            diagnostics: Vec::new(),
            target_kind: TypeLookupTargetKind::ValueExpression,
        };
        let cartesian_limit = 3;
        let cartesian_scope = cartesian_candidate_steps + 5;
        let mut cartesian_ledger = ReceiverWorkLedger::new(ReceiverAnalysisBudget {
            max_scope_nodes: cartesian_scope,
            max_targets: cartesian_limit,
            ..ReceiverAnalysisBudget::default()
        });
        let cartesian_projection = project_receiver_values(
            &cartesian_workspace,
            &cartesian_points_to,
            &cartesian_types,
            &[],
            false,
            None,
            &mut cartesian_ledger,
        )
        .expect("bounded Cartesian allocation projection");
        assert!(
            matches!(
                cartesian_projection,
                CompatibilityOutcome::Complete(ReceiverValueProjection {
                    ref values,
                    truncated: true,
                    ..
                }) if values.len() == 3
            ),
            "Cartesian projection must stop at the value cap without exhausting the budget"
        );
        assert_eq!(cartesian_ledger.work().scope_nodes, cartesian_scope);
    }
    #[test]
    fn java_current_receiver_keeps_exact_nested_owner_identity() {
        let source = r#"
class Left {
static class Worker {
    void helper() {}
    void caller() { this.helper(); }
}
}
class Right {
static class Worker {
    void helper() {}
    void caller() { this.helper(); }
}
}
"#;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), PathBuf::from("Nested.java"));
        file.write(source).expect("write source");
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(TestProject::new(root, Language::Java)),
            AnalyzerConfig::default(),
        )
        .expect("ephemeral workspace should build");
        let report = ReceiverQueryService::from_workspace(&workspace)
            .analyze(
                ReceiverQueryOperation::ReceiverTargets,
                &file,
                marker_range(source, "this.helper"),
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("nested current-receiver query");

        assert!(
            matches!(
                report.analysis,
                ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Precise(ref values))
                    if matches!(values.as_slice(), [ReceiverValue::CurrentReceiver(owner)]
                        if owner.is_class() && owner.fq_name() == "Left.Worker")
            ),
            "unexpected nested receiver report: {report:#?}"
        );
    }
}
