#[cfg(test)]
mod js_ts_extraction_root {

    use brokk_bifrost_analysis::CodeUnitIndex;
    use std::sync::Arc;

    use brokk_bifrost_analysis::analyzer::semantic::oracle::relation::CandidateCoverage;

    use brokk_bifrost_core::analyzer::model::CodeUnit;

    use brokk_bifrost_core::analyzer::model::Range;

    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;

    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisOutcome;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::ReceiverMemberTarget;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::ReceiverQueryAnalysis;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::ReceiverQueryError;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::ReceiverQueryInput;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::ReceiverQueryOperation;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::ReceiverQueryService;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::ReceiverSemanticBridge;

    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverValue;

    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticProviderError;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::SemanticReceiverEvidence;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::SemanticReceiverGate;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::SemanticReceiverIncompleteness;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::test_support::assert_factory_ranges_limited_and_cancellable;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::test_support::last_marker_range;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::test_support::marker_range;

    use brokk_bifrost_analysis::analyzer::usages::receiver_query::neutral_incomplete;

    use brokk_bifrost_js_ts_analysis::test_typescript_project as test_project;

    use brokk_bifrost_js_ts_analysis::JavascriptAnalyzer;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::analyzer::project::TestProject;

    use brokk_bifrost_js_ts_analysis::TypescriptAnalyzer;

    use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
    use std::path::PathBuf;

    #[test]
    fn incomplete_semantic_evidence_downgrades_values_and_member_targets() {
        let (_temp, _file, analyzer) = test_project("class Service {}\n");
        let service = analyzer
            .definitions("Service")
            .find(CodeUnit::is_class)
            .expect("Service class");
        let mut values = ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Precise(vec![
            ReceiverValue::InstanceType(service.clone()),
        ]));
        let member_target = ReceiverMemberTarget::Workspace {
            receiver: None,
            member: service.clone(),
        };
        let mut members =
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Precise(vec![
                member_target.clone(),
            ]));
        neutral_incomplete(&mut values);
        neutral_incomplete(&mut members);

        assert!(matches!(
            values,
            ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Ambiguous(ref values))
                if values == &[ReceiverValue::InstanceType(service.clone())]
        ));
        assert!(matches!(
            members,
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Ambiguous(ref targets))
                if targets == &[member_target]
        ));
    }
    #[test]
    fn points_to_reports_factory_and_allocation_provenance_with_work() {
        let source = r#"
class Service { run() {} }
function makeService() { return new Service(); }
export function caller() {
  const service = makeService();
  service.run();
}
"#;
        let (_temp, file, analyzer) = test_project(source);

        let report = ReceiverQueryService::new(&analyzer)
            .analyze(
                ReceiverQueryOperation::PointsTo,
                &file,
                last_marker_range(source, "makeService()"),
                ReceiverQueryInput::Expression,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("receiver query");

        assert_eq!(report.operation.as_str(), "points_to");
        assert_eq!(report.site.text, "makeService()");
        assert!(report.work.scope_nodes > 0);
        assert!(!report.candidates_truncated);
        assert!(
            matches!(
                &report.analysis,
                ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Precise(values))
                    if matches!(
                        values.as_slice(),
                        [ReceiverValue::FactoryReturn { factory, value }]
                            if factory.fq_name().ends_with("makeService")
                                && matches!(value.as_ref(), ReceiverValue::AllocationSite { ty, .. } if ty.fq_name().ends_with("Service"))
                    )
            ),
            "unexpected analysis: {:?}",
            report.analysis
        );
    }
    #[test]
    fn workspace_factory_provenance_fits_the_default_aggregate_budget() {
        let source = r#"
class Service {
  run() {}
}

class Other {
  run() {}
}

function makeService() {
  return new Service();
}

function consume(value: Service) {
  value.run();
}

export function caller(flag: boolean) {
  const direct = new Service();
  direct.run();

  const factory = makeService();
  factory.run();

  const ambiguous = flag ? new Service() : new Other();
  ambiguous.run();

  consume(new Service());
}
"#;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), PathBuf::from("app.ts"));
        file.write(source).expect("write source");
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(TestProject::new(root, Language::TypeScript)),
            AnalyzerConfig::default(),
        )
        .expect("ephemeral workspace should build");

        let service = ReceiverQueryService::from_workspace(&workspace);
        let receiver_range = last_marker_range(source, "factory");
        let gate = service
            .semantic_receiver_gate(
                &file,
                receiver_range,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("workspace semantic gate");
        let gate_work = gate.work();
        // `Service` declares no constructor, so the unresolved zero-argument
        // constructor boundary is discharged by its retained allocation and the
        // points-to answer closes exhaustively. The receiver gate must therefore
        // reach the direct precise path rather than the legacy compatibility
        // provider, and must do so inside the unchanged default aggregate budget.
        assert!(
            matches!(
                gate,
                SemanticReceiverGate::Available {
                    evidence: SemanticReceiverEvidence::ExhaustiveComplete,
                    ..
                }
            ),
            "unexpected gate evidence, work: {gate_work:#?}"
        );
        assert!(gate_work.scope_nodes <= ReceiverAnalysisBudget::default().max_scope_nodes);
        assert!(
            gate_work.summary_expansions
                <= ReceiverAnalysisBudget::default().max_summary_expansions
        );
        let report = service
            .analyze(
                ReceiverQueryOperation::PointsTo,
                &file,
                receiver_range,
                ReceiverQueryInput::Expression,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("workspace receiver query");

        assert!(
            matches!(
                &report.analysis,
                ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Precise(values))
                    if matches!(
                        values.as_slice(),
                        [ReceiverValue::FactoryReturn { factory, value }]
                            if factory.fq_name().ends_with("makeService")
                                && matches!(value.as_ref(), ReceiverValue::AllocationSite { ty, .. } if ty.fq_name().ends_with("Service"))
                    )
            ),
            "{report:#?}\nsemantic gate work: {gate_work:#?}"
        );
        assert!(
            report.work.summary_expansions
                <= ReceiverAnalysisBudget::default().max_summary_expansions,
            "{report:#?}"
        );

        let context_disabled = service
            .analyze(
                ReceiverQueryOperation::PointsTo,
                &file,
                receiver_range,
                ReceiverQueryInput::Expression,
                ReceiverAnalysisBudget {
                    context_depth: 0,
                    ..ReceiverAnalysisBudget::default()
                },
                None,
            )
            .expect("context-disabled workspace receiver query");
        assert!(
            matches!(
                &context_disabled.analysis,
                ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Ambiguous(values))
                    if matches!(
                        values.as_slice(),
                        [ReceiverValue::FactoryReturn { factory, value }]
                            if factory.fq_name().ends_with("makeService")
                                && matches!(value.as_ref(), ReceiverValue::AllocationSite { ty, .. } if ty.fq_name().ends_with("Service"))
                    )
            ),
            "{context_disabled:#?}"
        );
    }
    /// A constructor that takes an argument keeps an undischarged call-target
    /// boundary, so the points-to answer stays open while every retained
    /// candidate remains individually proven. The gate must then report
    /// `GlobalCapabilitiesWithProvenCandidates` so the compatibility provider is
    /// still allowed to close the receiver, and it must do so inside the default
    /// aggregate budget.

    #[test]
    fn workspace_factory_provenance_reports_global_capability_openness_with_proven_candidates() {
        let source = r#"
class Service {
  constructor(seed: number) {}
  run() {}
}

function makeService() {
  return new Service(1);
}

export function caller() {
  const factory = makeService();
  factory.run();
}
"#;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), PathBuf::from("app.ts"));
        file.write(source).expect("write source");
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(TestProject::new(root, Language::TypeScript)),
            AnalyzerConfig::default(),
        )
        .expect("ephemeral workspace should build");

        let service = ReceiverQueryService::from_workspace(&workspace);
        let receiver_range = last_marker_range(source, "factory");
        let gate = service
            .semantic_receiver_gate(
                &file,
                receiver_range,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("workspace semantic gate");
        let gate_work = gate.work();
        assert!(
            matches!(
                gate,
                SemanticReceiverGate::Available {
                    evidence: SemanticReceiverEvidence::Incomplete {
                        coverage: CandidateCoverage::Open,
                        unsupported: None,
                        origin:
                            SemanticReceiverIncompleteness::GlobalCapabilitiesWithProvenCandidates,
                    },
                    ..
                }
            ),
            "unexpected gate evidence, work: {gate_work:#?}"
        );
        assert!(gate_work.scope_nodes <= ReceiverAnalysisBudget::default().max_scope_nodes);

        let report = service
            .analyze(
                ReceiverQueryOperation::PointsTo,
                &file,
                receiver_range,
                ReceiverQueryInput::Expression,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("workspace receiver query");
        assert!(
            matches!(
                &report.analysis,
                ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Precise(values))
                    if matches!(
                        values.as_slice(),
                        [ReceiverValue::FactoryReturn { factory, value }]
                            if factory.fq_name().ends_with("makeService")
                                && matches!(value.as_ref(), ReceiverValue::AllocationSite { ty, .. } if ty.fq_name().ends_with("Service"))
                    )
            ),
            "{report:#?}"
        );
    }
    #[test]
    fn member_targets_only_returns_the_receiver_owner_member() {
        let source = r#"
class Service { run() {} }
class Other { run() {} }
export function caller() {
  const service = new Service();
  service.run();
}
"#;
        let (_temp, file, analyzer) = test_project(source);

        let report = ReceiverQueryService::new(&analyzer)
            .analyze(
                ReceiverQueryOperation::MemberTargets,
                &file,
                marker_range(source, "service.run"),
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("member target query");

        assert_eq!(report.site.member_name.as_deref(), Some("run"));
        assert!(matches!(
            report.analysis,
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Precise(ref targets))
                if targets.len() == 1
                    && targets[0].fq_name().contains("Service")
                    && !targets[0].fq_name().contains("Other")
        ));
    }
    #[test]
    fn repeated_queries_reuse_prepared_file_context_and_charge_setup_once() {
        let source = r#"
class Service { run() {} }
export function caller() {
  const first = new Service();
  const second = new Service();
  first.run();
  second.run();
}
"#;
        let (_temp, file, analyzer) = test_project(source);
        let service = ReceiverQueryService::new(&analyzer);

        let first = service
            .analyze(
                ReceiverQueryOperation::PointsTo,
                &file,
                marker_range(source, "first.run"),
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("first receiver query");
        let second = service
            .analyze(
                ReceiverQueryOperation::PointsTo,
                &file,
                marker_range(source, "second.run"),
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("second receiver query");

        assert_eq!(service.prepared_file_count(), 1);
        assert!(first.work.setup_nodes > 0);
        assert_eq!(second.work.setup_nodes, 0);
    }
    #[test]
    fn workspace_semantic_gate_and_compatibility_provider_share_one_budget() {
        let mut source = String::from(
            "class Service { run() {} }\nexport function caller() {\n  const service = new Service();\n",
        );
        for index in 0..32 {
            source.push_str(&format!("  const local{index} = {index};\n"));
        }
        source.push_str("  service.run();\n}\n");

        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), PathBuf::from("app.ts"));
        file.write(&source).expect("write source");
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(TestProject::new(root, Language::TypeScript)),
            AnalyzerConfig::default(),
        )
        .expect("ephemeral workspace should build");
        let range = marker_range(&source, "service.run");
        let workspace_service = ReceiverQueryService::from_workspace(&workspace);
        let warm = workspace_service
            .analyze(
                ReceiverQueryOperation::ReceiverTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("warm workspace receiver query");
        assert!(matches!(
            warm.analysis,
            ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Precise(_))
        ));

        let gate = workspace_service
            .semantic_receiver_gate(
                &file,
                warm.site.range,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("isolated semantic gate");
        assert!(gate.exceeded_limit().is_none());
        let gate_work = gate.work();

        let compatibility_service = ReceiverQueryService::new(workspace.analyzer());
        let _ = compatibility_service
            .analyze(
                ReceiverQueryOperation::ReceiverTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("prepare compatibility receiver query");
        let compatibility = compatibility_service
            .analyze(
                ReceiverQueryOperation::ReceiverTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("measure compatibility receiver query");
        assert_eq!(compatibility.work.setup_nodes, 0);
        assert!(gate_work.scope_nodes > 0 && compatibility.work.scope_nodes > 0);

        let budget = ReceiverAnalysisBudget {
            max_scope_nodes: gate_work
                .scope_nodes
                .max(compatibility.work.scope_nodes)
                .max(ReceiverSemanticBridge::SCOPE_DIMENSIONS),
            max_summary_expansions: gate_work
                .summary_expansions
                .max(compatibility.work.summary_expansions)
                .max(ReceiverSemanticBridge::SUMMARY_DIMENSIONS),
            ..ReceiverAnalysisBudget::default()
        };
        assert!(
            gate_work
                .scope_nodes
                .saturating_add(compatibility.work.scope_nodes)
                > budget.max_scope_nodes,
            "fixture must require more combined work than either phase alone"
        );

        let bounded = workspace_service
            .analyze(
                ReceiverQueryOperation::ReceiverTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                budget,
                None,
            )
            .expect("aggregate-bounded workspace receiver query");
        assert!(
            bounded
                .work
                .setup_nodes
                .saturating_add(bounded.work.scope_nodes)
                <= budget.max_scope_nodes
        );
        assert!(bounded.work.summary_expansions <= budget.max_summary_expansions);
        assert!(matches!(
            bounded.analysis,
            ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::ExceededBudget { .. })
        ));
    }
    #[test]
    fn js_ts_factory_ranges_are_limited_and_cancellable_without_file_hydration() {
        let typescript_temp = tempfile::tempdir().expect("TypeScript temp dir");
        let typescript_root = typescript_temp
            .path()
            .canonicalize()
            .expect("canonical TypeScript temp dir");
        let typescript_file =
            ProjectFile::new(typescript_root.clone(), PathBuf::from("factory.ts"));
        typescript_file
            .write("class Service {}\nfunction makeService() { return new Service(); }\n")
            .expect("write TypeScript source");
        let typescript_project = Arc::new(TestProject::new(typescript_root, Language::TypeScript));
        {
            let _cold = WorkspaceAnalyzer::build_persisted(
                typescript_project.clone(),
                AnalyzerConfig::default(),
            )
            .expect("cold persisted TypeScript workspace");
        }
        let typescript_workspace =
            WorkspaceAnalyzer::build_persisted(typescript_project, AnalyzerConfig::default())
                .expect("warm persisted TypeScript workspace");
        let typescript_factory = typescript_workspace
            .analyzer()
            .get_all_declarations()
            .into_iter()
            .find(|unit| unit.fq_name().ends_with("makeService"))
            .expect("persisted TypeScript factory");
        let typescript = resolve_analyzer::<TypescriptAnalyzer>(typescript_workspace.analyzer())
            .expect("workspace TypeScript analyzer");
        typescript.reset_full_hydration_count_for_test();
        assert_factory_ranges_limited_and_cancellable(
            typescript_workspace.analyzer(),
            &typescript_factory,
        );
        assert_eq!(
            typescript.full_hydration_count_for_test(),
            0,
            "bounded TypeScript factory-range validation must not hydrate persisted FileState"
        );

        let javascript_temp = tempfile::tempdir().expect("JavaScript temp dir");
        let javascript_root = javascript_temp
            .path()
            .canonicalize()
            .expect("canonical JavaScript temp dir");
        let javascript_file =
            ProjectFile::new(javascript_root.clone(), PathBuf::from("factory.js"));
        javascript_file
            .write("class Service {}\nfunction makeService() { return new Service(); }\n")
            .expect("write JavaScript source");
        let javascript_project = Arc::new(TestProject::new(javascript_root, Language::JavaScript));
        {
            let _cold = WorkspaceAnalyzer::build_persisted(
                javascript_project.clone(),
                AnalyzerConfig::default(),
            )
            .expect("cold persisted JavaScript workspace");
        }
        let javascript_workspace =
            WorkspaceAnalyzer::build_persisted(javascript_project, AnalyzerConfig::default())
                .expect("warm persisted JavaScript workspace");
        let javascript_factory = javascript_workspace
            .analyzer()
            .get_all_declarations()
            .into_iter()
            .find(|unit| unit.fq_name().ends_with("makeService"))
            .expect("persisted JavaScript factory");
        let javascript = resolve_analyzer::<JavascriptAnalyzer>(javascript_workspace.analyzer())
            .expect("workspace JavaScript analyzer");
        javascript.inner().reset_full_hydration_count_for_test();
        assert_factory_ranges_limited_and_cancellable(
            javascript_workspace.analyzer(),
            &javascript_factory,
        );
        assert_eq!(
            javascript.inner().full_hydration_count_for_test(),
            0,
            "bounded JavaScript factory-range validation must not hydrate persisted FileState"
        );
    }
    #[test]
    fn unsupported_language_returns_an_explicit_row() {
        let source = "value = object.member\n";
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), PathBuf::from("app.txt"));
        file.write(source).expect("write source");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));

        let report = ReceiverQueryService::new(&analyzer)
            .analyze(
                ReceiverQueryOperation::ReceiverTargets,
                &file,
                marker_range(source, "object.member"),
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("unsupported result");

        assert_eq!(report.site.language, Language::None);
        assert!(matches!(
            report.analysis,
            ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Unsupported {
                reason: "receiver_analysis_language_unsupported"
            })
        ));
    }
    #[test]
    fn semantic_receiver_gate_preserves_provider_identity_failures() {
        let source = "export const value = {};\n";
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(root.clone(), PathBuf::from("app.ts"));
        file.write(source).expect("write source");
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(TestProject::new(root, Language::TypeScript)),
            AnalyzerConfig::default(),
        )
        .expect("ephemeral workspace should build");
        let foreign = tempfile::tempdir().expect("foreign temp dir");
        let foreign_file = ProjectFile::new(
            foreign.path().canonicalize().expect("foreign root"),
            PathBuf::from("app.ts"),
        );

        let result = ReceiverQueryService::from_workspace(&workspace).semantic_receiver_gate(
            &foreign_file,
            Range {
                start_byte: 0,
                end_byte: 1,
                start_line: 0,
                end_line: 0,
            },
            ReceiverAnalysisBudget::default(),
            None,
        );

        assert!(matches!(
            result,
            Err(ReceiverQueryError::SemanticProvider(
                SemanticProviderError::InvalidIdentity(_)
            ))
        ));
    }
}
