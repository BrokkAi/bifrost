#[cfg(test)]
mod csharp_extraction_tests {
    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverValue;
    use std::path::PathBuf;

    use std::sync::Arc;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::CompatibilityOutcome;

    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;

    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisOutcome;

    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverBudgetLimit;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::ReceiverMemberTarget;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::ReceiverQueryAnalysis;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::ReceiverQueryError;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::ReceiverQueryInput;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::ReceiverQueryOperation;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::ReceiverQueryService;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::ReceiverSemanticBridge;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::ReceiverWorkLedger;

    use brokk_bifrost_analysis::analyzer::semantic::SemanticOutcome;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::SemanticReceiverGate;

    use brokk_bifrost_analysis::analyzer::semantic::SemanticRequest;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::code_unit_ranges_bounded;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::structural_member_dispatch_supports_precise;

    use brokk_bifrost_analysis::analyzer::structural::FileFacts;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::test_support::last_marker_range;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::test_support::marker_range;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::analyzer::project::TestProject;

    use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
    use brokk_bifrost_csharp_analysis::CSharpAnalyzer;

    fn csharp_structural_facts(
        workspace: &WorkspaceAnalyzer,
        file: &ProjectFile,
    ) -> Arc<FileFacts> {
        workspace
            .analyzer()
            .structural_fact_providers()
            .into_iter()
            .find(|provider| provider.structural_language() == Language::CSharp)
            .and_then(|provider| provider.structural_facts(file))
            .expect("C# structural facts")
    }
    #[test]
    fn csharp_queries_share_cached_setup_exact_resolution_budget_and_cancellation() {
        let source = r#"
namespace Demo;
class Service { public void Run() {} }
class Caller {
void Run() {}
void Call(Service service) {
    service.Run();
    Run();
}
}
"#;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), PathBuf::from("Receiver.cs"));
        file.write(source).expect("write source");
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(TestProject::new(root, Language::CSharp)),
            AnalyzerConfig::default(),
        )
        .expect("ephemeral workspace should build");
        let service = ReceiverQueryService::from_workspace(&workspace);
        let facts = csharp_structural_facts(&workspace, &file);
        let range = marker_range(source, "service.Run");

        let first = service
            .analyze_with_structural_facts(
                ReceiverQueryOperation::MemberTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                &facts,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("first C# receiver query");
        let second = service
            .analyze_with_structural_facts(
                ReceiverQueryOperation::MemberTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                &facts,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("cached C# receiver query");
        for report in [&first, &second] {
            assert!(
                matches!(
                    report.analysis,
                    ReceiverQueryAnalysis::MemberTargets(
                        ReceiverAnalysisOutcome::Precise(ref targets)
                    ) if matches!(targets.as_slice(), [target] if target.fq_name() == "Demo.Service.Run")
                ),
                "{report:#?}"
            );
        }
        assert_eq!(service.prepared_file_count(), 1);
        assert!(first.work.setup_nodes > second.work.setup_nodes);
        assert!(
            second.work.setup_nodes > 0,
            "cached site selection must remain charged"
        );

        let warm_scope = second
            .work
            .setup_nodes
            .saturating_add(second.work.scope_nodes);
        assert!(warm_scope > 0);
        let bounded = service
            .analyze_with_structural_facts(
                ReceiverQueryOperation::MemberTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                &facts,
                ReceiverAnalysisBudget {
                    max_scope_nodes: warm_scope - 1,
                    ..ReceiverAnalysisBudget::default()
                },
                None,
            )
            .expect("bounded cached C# receiver query");
        assert!(matches!(
            bounded.analysis,
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::ExceededBudget {
                limit: "scope_nodes"
            })
        ));
        assert!(
            bounded
                .work
                .setup_nodes
                .saturating_add(bounded.work.scope_nodes)
                < warm_scope
        );

        let cold = ReceiverQueryService::from_workspace(&workspace)
            .analyze_with_structural_facts(
                ReceiverQueryOperation::MemberTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                &facts,
                ReceiverAnalysisBudget::tiny(),
                None,
            )
            .expect("tiny-budget C# receiver query");
        assert!(matches!(
            cold.analysis,
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::ExceededBudget {
                limit: "scope_nodes"
            })
        ));
        assert!(
            cold.work.setup_nodes.saturating_add(cold.work.scope_nodes)
                <= ReceiverAnalysisBudget::tiny().max_scope_nodes
        );

        let cancellation = CancellationToken::default();
        cancellation.cancel();
        assert_eq!(
            service.analyze_with_structural_facts(
                ReceiverQueryOperation::MemberTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                &facts,
                ReceiverAnalysisBudget::default(),
                Some(&cancellation),
            ),
            Err(ReceiverQueryError::Cancelled)
        );
        let mid_cancellation = CancellationToken::cancel_after_checks_for_test(3);
        assert_eq!(
            service.analyze_with_structural_facts(
                ReceiverQueryOperation::MemberTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                &facts,
                ReceiverAnalysisBudget::default(),
                Some(&mid_cancellation),
            ),
            Err(ReceiverQueryError::Cancelled)
        );

        let unsupported = service
            .analyze_with_structural_facts(
                ReceiverQueryOperation::MemberTargets,
                &file,
                last_marker_range(source, "Run()"),
                ReceiverQueryInput::ContainingSite,
                &facts,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("implicit-receiver C# query");
        assert!(matches!(
            unsupported.analysis,
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Unsupported {
                reason: "receiver_site_without_receiver"
            })
        ));
        assert!(
            unsupported.work.setup_nodes > 0,
            "unsupported site selection must report its work"
        );
    }
    #[test]
    fn csharp_nested_member_resolution_fits_the_default_receiver_budget() {
        let source = r#"
namespace Demo;
class Service
{
public Service Next => this;
public void Run() {}
}
class Caller
{
void Call()
{
    var local = new Service();
    local.Next.Run();
}
}
"#;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), PathBuf::from("Receiver.cs"));
        file.write(source).expect("write source");
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(TestProject::new(root, Language::CSharp)),
            AnalyzerConfig::default(),
        )
        .expect("ephemeral workspace should build");
        let service = ReceiverQueryService::from_workspace(&workspace);
        let facts = csharp_structural_facts(&workspace, &file);
        let range = marker_range(source, "local.Next.Run");

        let report = service
            .analyze_with_structural_facts(
                ReceiverQueryOperation::MemberTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                &facts,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("nested C# receiver query");

        assert!(
            matches!(
                report.analysis,
                ReceiverQueryAnalysis::MemberTargets(
                    ReceiverAnalysisOutcome::Ambiguous(ref targets)
                ) if matches!(targets.as_slice(), [target] if target.fq_name() == "Demo.Service.Run")
            ),
            "{report:#?}"
        );
        assert!(
            report.work.summary_expansions
                <= ReceiverAnalysisBudget::default().max_summary_expansions,
            "{report:#?}"
        );
    }
    #[test]
    fn csharp_persisted_metadata_and_ranges_are_bounded_without_file_hydration() {
        let source = r#"
namespace Demo;
sealed class Service {
public void Run() {}
}
"#;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), PathBuf::from("Receiver.cs"));
        file.write(source).expect("write source");
        let project = Arc::new(TestProject::new(root, Language::CSharp));
        {
            let _cold =
                WorkspaceAnalyzer::build_persisted(project.clone(), AnalyzerConfig::default())
                    .expect("cold persisted C# workspace");
        }
        let workspace = WorkspaceAnalyzer::build_persisted(project, AnalyzerConfig::default())
            .expect("warm persisted C# workspace");
        let target = workspace
            .analyzer()
            .get_all_declarations()
            .into_iter()
            .find(|unit| unit.fq_name() == "Demo.Service.Run")
            .expect("persisted service method");
        let csharp = resolve_analyzer::<CSharpAnalyzer>(workspace.analyzer())
            .expect("workspace C# analyzer");
        csharp.reset_full_hydration_count_for_test();

        let one_metadata = csharp.signature_metadata_limited(&target, 1);
        assert_eq!(one_metadata.rows.len(), 1);
        assert_eq!(one_metadata.inspected, 1);
        let complete_metadata = csharp.signature_metadata_limited(&target, 2);
        assert_eq!(complete_metadata.rows.len(), 1);
        assert!(complete_metadata.complete);

        let one_range = csharp.ranges_limited(&target, 1);
        assert_eq!(one_range.rows.len(), 1);
        assert_eq!(one_range.inspected, 1);
        let complete_ranges = csharp.ranges_limited(&target, 2);
        assert_eq!(complete_ranges.rows.len(), 1);
        assert!(complete_ranges.complete);

        let analysis =
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Precise(vec![
                ReceiverMemberTarget::Workspace {
                    receiver: None,
                    member: target.clone(),
                },
            ]));
        let mut dispatch_ledger = ReceiverWorkLedger::new(ReceiverAnalysisBudget::default());
        assert!(matches!(
            structural_member_dispatch_supports_precise(
                workspace.analyzer(),
                Language::CSharp,
                &analysis,
                None,
                &mut dispatch_ledger,
            )
            .expect("bounded dispatch metadata"),
            CompatibilityOutcome::Complete(true)
        ));

        let mut range_ledger = ReceiverWorkLedger::new(ReceiverAnalysisBudget::default());
        assert!(matches!(
            code_unit_ranges_bounded(
                workspace.analyzer(),
                &target,
                None,
                &mut range_ledger,
            )
            .expect("bounded declaration ranges"),
            CompatibilityOutcome::Complete(ranges) if ranges.len() == 1
        ));

        let tiny_budget = ReceiverAnalysisBudget {
            max_scope_nodes: 1,
            ..ReceiverAnalysisBudget::default()
        };
        let mut tiny_dispatch_ledger = ReceiverWorkLedger::new(tiny_budget);
        assert!(matches!(
            structural_member_dispatch_supports_precise(
                workspace.analyzer(),
                Language::CSharp,
                &analysis,
                None,
                &mut tiny_dispatch_ledger,
            )
            .expect("tiny dispatch metadata budget"),
            CompatibilityOutcome::Exceeded(ReceiverBudgetLimit::ScopeNodes)
        ));
        let mut tiny_range_ledger = ReceiverWorkLedger::new(tiny_budget);
        assert!(matches!(
            code_unit_ranges_bounded(workspace.analyzer(), &target, None, &mut tiny_range_ledger,)
                .expect("tiny declaration range budget"),
            CompatibilityOutcome::Exceeded(ReceiverBudgetLimit::ScopeNodes)
        ));
        assert_eq!(
            csharp.full_hydration_count_for_test(),
            0,
            "bounded receiver metadata/range reads must not hydrate persisted FileState"
        );
    }
    #[test]
    fn csharp_requires_per_call_facts_and_rejects_a_mismatched_cached_snapshot() {
        let source = r#"
namespace Demo;
class Service { public void Run() {} }
class Caller {
void Call(Service service) { service.Run(); }
}
"#;
        let unrelated_source = r#"
namespace Other;
class DifferentService { public void Execute() {} }
class DifferentCaller {
void Call(DifferentService service) { service.Execute(); }
}
"#;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), PathBuf::from("Receiver.cs"));
        let unrelated_file = ProjectFile::new(root.clone(), PathBuf::from("Unrelated.cs"));
        file.write(source).expect("write receiver source");
        unrelated_file
            .write(unrelated_source)
            .expect("write unrelated source");
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(TestProject::new(root, Language::CSharp)),
            AnalyzerConfig::default(),
        )
        .expect("ephemeral workspace should build");
        let service = ReceiverQueryService::from_workspace(&workspace);
        let facts = csharp_structural_facts(&workspace, &file);
        let unrelated_facts = csharp_structural_facts(&workspace, &unrelated_file);
        let range = marker_range(source, "service.Run");

        let prepared = service
            .analyze_with_structural_facts(
                ReceiverQueryOperation::MemberTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                &facts,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("prepare exact C# receiver facts");
        assert!(matches!(
            prepared.analysis,
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Precise(_))
        ));

        let missing = service
            .analyze(
                ReceiverQueryOperation::MemberTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("missing-facts C# receiver query");
        assert!(matches!(
            missing.analysis,
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Unsupported {
                reason: "receiver_structural_facts_unavailable"
            })
        ));

        let mismatched = service
            .analyze_with_structural_facts(
                ReceiverQueryOperation::MemberTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                &unrelated_facts,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("mismatched-facts C# receiver query");
        assert!(matches!(
            mismatched.analysis,
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Unsupported {
                reason: "receiver_source_snapshot_mismatch"
            })
        ));

        let prepared_files = service.prepared_structural_files.borrow();
        let cached = prepared_files.get(&file).expect("prepared receiver file");
        assert!(cached.matches(&facts));
        assert!(!cached.matches(&unrelated_facts));
    }
    #[test]
    fn csharp_candidate_cap_cannot_remain_precise() {
        let source = r#"
namespace Demo {
class Service { public void Run() {} }
class Caller {
    void Call(bool flag) {
        var service = new Service();
        if (flag) { service = new Service(); }
        service.Run();
    }
}
}
"#;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), PathBuf::from("Partial.cs"));
        file.write(source).expect("write source");
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(TestProject::new(root, Language::CSharp)),
            AnalyzerConfig::default(),
        )
        .expect("ephemeral workspace should build");
        let facts = csharp_structural_facts(&workspace, &file);
        let report = ReceiverQueryService::from_workspace(&workspace)
            .analyze_with_structural_facts(
                ReceiverQueryOperation::ReceiverTargets,
                &file,
                last_marker_range(source, "service.Run"),
                ReceiverQueryInput::ContainingSite,
                &facts,
                ReceiverAnalysisBudget {
                    max_targets: 1,
                    ..ReceiverAnalysisBudget::default()
                },
                None,
            )
            .expect("candidate-capped C# receiver query");

        assert!(report.candidates_truncated, "{report:#?}");
        assert!(matches!(
            report.analysis,
            ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Ambiguous(ref values))
                if values.len() == 1
        ));
    }
    #[test]
    fn csharp_dynamic_receiver_remains_explicit_after_prior_calls() {
        let source = r#"
namespace Demo;
class Service {
public void Run() {}
public void Touch(Service value) {}
}
class Caller {
void Call(Service service, dynamic opaque) {
    service.Run();
    service.Run();
    service.Run();
    service.Run();
    service.Run();
    service.Run();
    service.Run();
    service.Run();
    opaque.Run();
}
}
"#;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), PathBuf::from("Dynamic.cs"));
        file.write(source).expect("write source");
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(TestProject::new(root, Language::CSharp)),
            AnalyzerConfig::default(),
        )
        .expect("ephemeral workspace should build");
        let receiver_range = last_marker_range(source, "opaque");
        let mut semantic =
            ReceiverSemanticBridge::new(ReceiverAnalysisBudget::default()).expect("bridge");
        let cancellation = CancellationToken::default();
        let semantic_outcome = semantic
            .oracle(&workspace)
            .pointees_at_source(
                &file,
                receiver_range,
                &mut SemanticRequest::new(&mut semantic.budget, &cancellation),
            )
            .expect("dynamic receiver points-to query");
        assert!(
            !matches!(semantic_outcome, SemanticOutcome::ExceededBudget { .. }),
            "default receiver budget must cover a moderate method: {semantic_outcome:#?}"
        );

        let facts = csharp_structural_facts(&workspace, &file);
        let report = ReceiverQueryService::from_workspace(&workspace)
            .analyze_with_structural_facts(
                ReceiverQueryOperation::ReceiverTargets,
                &file,
                last_marker_range(source, "opaque.Run"),
                ReceiverQueryInput::ContainingSite,
                &facts,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("dynamic C# receiver query");
        assert!(
            matches!(
                report.analysis,
                ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Unsupported {
                    reason: "csharp_dynamic_receiver_unsupported"
                })
            ),
            "{report:#?}"
        );
    }
    #[test]
    fn csharp_current_receiver_has_exhaustive_neutral_evidence() {
        let source = r#"
namespace Demo;
class Caller {
void Touch() {}
void Call() { this.Touch(); }
}
"#;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), PathBuf::from("Current.cs"));
        file.write(source).expect("write source");
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(TestProject::new(root, Language::CSharp)),
            AnalyzerConfig::default(),
        )
        .expect("ephemeral workspace should build");
        let service = ReceiverQueryService::from_workspace(&workspace);
        let gate = service
            .semantic_receiver_gate(
                &file,
                last_marker_range(source, "this"),
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("current-receiver semantic gate");
        let SemanticReceiverGate::Available {
            points_to,
            evidence,
            ..
        } = gate
        else {
            panic!("current receiver must have neutral evidence");
        };
        let coverages = points_to
            .observations()
            .iter()
            .map(|observation| observation.objects().coverage())
            .collect::<Vec<_>>();
        assert!(
            evidence.supports_precise(),
            "current receiver evidence must be exhaustive; evidence={evidence:?}, observations={coverages:?}"
        );

        let facts = csharp_structural_facts(&workspace, &file);
        let report = service
            .analyze_with_structural_facts(
                ReceiverQueryOperation::ReceiverTargets,
                &file,
                last_marker_range(source, "this.Touch"),
                ReceiverQueryInput::ContainingSite,
                &facts,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("current receiver query");
        assert!(
            matches!(
                report.analysis,
                ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Precise(ref values))
                    if matches!(values.as_slice(), [ReceiverValue::CurrentReceiver(_)])
            ),
            "{report:#?}"
        );
    }
}
