use super::*;
use crate::analyzer::CodeUnitIndex;
use crate::analyzer::{
    CSharpAnalyzer, JavaAnalyzer, JavascriptAnalyzer, TestProject, TypescriptAnalyzer,
    resolve_analyzer,
};
use crate::{AnalyzerConfig, WorkspaceAnalyzer};
use std::path::PathBuf;

fn test_project(source: &str) -> (tempfile::TempDir, ProjectFile, TypescriptAnalyzer) {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let file = ProjectFile::new(root.clone(), PathBuf::from("src/app.ts"));
    file.write(source).expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    (temp, file, analyzer)
}

fn marker_range(source: &str, marker: &str) -> Range {
    let start_byte = source.find(marker).expect("marker");
    range_at(source, marker, start_byte)
}

fn last_marker_range(source: &str, marker: &str) -> Range {
    let start_byte = source.rfind(marker).expect("marker");
    range_at(source, marker, start_byte)
}

fn range_at(source: &str, marker: &str, start_byte: usize) -> Range {
    Range {
        start_byte,
        end_byte: start_byte + marker.len(),
        start_line: source[..start_byte]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count(),
        end_line: source[..start_byte + marker.len()]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count(),
    }
}

fn csharp_structural_facts(workspace: &WorkspaceAnalyzer, file: &ProjectFile) -> Arc<FileFacts> {
    workspace
        .analyzer()
        .structural_search_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == Language::CSharp)
        .and_then(|provider| provider.structural_facts(file))
        .expect("C# structural facts")
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
    let workspace = WorkspaceAnalyzer::build(
        Arc::new(TestProject::new(root, Language::TypeScript)),
        AnalyzerConfig::default(),
    );

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
    assert!(matches!(
        gate,
        SemanticReceiverGate::Available {
            evidence: SemanticReceiverEvidence::Incomplete {
                origin: SemanticReceiverIncompleteness::GlobalCapabilitiesWithProvenCandidates,
                ..
            },
            ..
        }
    ));
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
        report.work.summary_expansions <= ReceiverAnalysisBudget::default().max_summary_expansions,
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
    let workspace = WorkspaceAnalyzer::build(
        Arc::new(TestProject::new(root, Language::TypeScript)),
        AnalyzerConfig::default(),
    );
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
    let workspace = WorkspaceAnalyzer::build(
        Arc::new(TestProject::new(root, Language::CSharp)),
        AnalyzerConfig::default(),
    );
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
    let workspace = WorkspaceAnalyzer::build(
        Arc::new(TestProject::new(root, Language::CSharp)),
        AnalyzerConfig::default(),
    );
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
        report.work.summary_expansions <= ReceiverAnalysisBudget::default().max_summary_expansions,
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
        let _cold = WorkspaceAnalyzer::build_persisted(project.clone(), AnalyzerConfig::default())
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
    let csharp =
        resolve_analyzer::<CSharpAnalyzer>(workspace.analyzer()).expect("workspace C# analyzer");
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

    let analysis = ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Precise(vec![
        target.clone(),
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
fn java_factory_ranges_are_limited_and_cancellable_without_file_hydration() {
    let source = r#"
class Service {}
class Sample {
static Service makeService() { return new Service(); }
}
"#;
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let file = ProjectFile::new(root.clone(), PathBuf::from("Sample.java"));
    file.write(source).expect("write source");
    let project = Arc::new(TestProject::new(root, Language::Java));
    {
        let _cold = WorkspaceAnalyzer::build_persisted(project.clone(), AnalyzerConfig::default())
            .expect("cold persisted Java workspace");
    }
    let workspace = WorkspaceAnalyzer::build_persisted(project, AnalyzerConfig::default())
        .expect("warm persisted Java workspace");
    let factory = workspace
        .analyzer()
        .get_all_declarations()
        .into_iter()
        .find(|unit| unit.fq_name().ends_with("Sample.makeService"))
        .expect("persisted Java factory");
    let java =
        resolve_analyzer::<JavaAnalyzer>(workspace.analyzer()).expect("workspace Java analyzer");
    java.inner().reset_full_hydration_count_for_test();

    let tiny_budget = ReceiverAnalysisBudget {
        max_scope_nodes: 1,
        ..ReceiverAnalysisBudget::default()
    };
    let mut tiny_ledger = ReceiverWorkLedger::new(tiny_budget);
    assert!(matches!(
        code_unit_ranges_bounded(workspace.analyzer(), &factory, None, &mut tiny_ledger)
            .expect("tiny Java factory range budget"),
        CompatibilityOutcome::Exceeded(ReceiverBudgetLimit::ScopeNodes)
    ));
    assert_eq!(tiny_ledger.work().scope_nodes, 1);

    let cancellation = CancellationToken::default();
    cancellation.cancel();
    let mut cancelled_ledger = ReceiverWorkLedger::new(ReceiverAnalysisBudget::default());
    assert!(matches!(
        code_unit_ranges_bounded(
            workspace.analyzer(),
            &factory,
            Some(&cancellation),
            &mut cancelled_ledger,
        ),
        Err(ReceiverQueryError::Cancelled)
    ));
    assert_eq!(cancelled_ledger.work(), ReceiverAnalysisWork::default());
    assert_eq!(
        java.inner().full_hydration_count_for_test(),
        0,
        "bounded Java factory-range validation must not hydrate persisted FileState"
    );
}

#[test]
fn js_ts_factory_ranges_are_limited_and_cancellable_without_file_hydration() {
    fn assert_limited_and_cancellable(analyzer: &dyn IAnalyzer, factory: &CodeUnit) {
        let tiny_budget = ReceiverAnalysisBudget {
            max_scope_nodes: 1,
            ..ReceiverAnalysisBudget::default()
        };
        let mut tiny_ledger = ReceiverWorkLedger::new(tiny_budget);
        assert!(matches!(
            code_unit_ranges_bounded(analyzer, factory, None, &mut tiny_ledger)
                .expect("tiny JS/TS factory range budget"),
            CompatibilityOutcome::Exceeded(ReceiverBudgetLimit::ScopeNodes)
        ));
        assert_eq!(tiny_ledger.work().scope_nodes, 1);

        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let mut cancelled_ledger = ReceiverWorkLedger::new(ReceiverAnalysisBudget::default());
        assert!(matches!(
            code_unit_ranges_bounded(
                analyzer,
                factory,
                Some(&cancellation),
                &mut cancelled_ledger,
            ),
            Err(ReceiverQueryError::Cancelled)
        ));
        assert_eq!(cancelled_ledger.work(), ReceiverAnalysisWork::default());
    }

    let typescript_temp = tempfile::tempdir().expect("TypeScript temp dir");
    let typescript_root = typescript_temp
        .path()
        .canonicalize()
        .expect("canonical TypeScript temp dir");
    let typescript_file = ProjectFile::new(typescript_root.clone(), PathBuf::from("factory.ts"));
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
    assert_limited_and_cancellable(typescript_workspace.analyzer(), &typescript_factory);
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
    let javascript_file = ProjectFile::new(javascript_root.clone(), PathBuf::from("factory.js"));
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
    assert_limited_and_cancellable(javascript_workspace.analyzer(), &javascript_factory);
    assert_eq!(
        javascript.inner().full_hydration_count_for_test(),
        0,
        "bounded JavaScript factory-range validation must not hydrate persisted FileState"
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
    let workspace = WorkspaceAnalyzer::build(
        Arc::new(TestProject::new(root, Language::CSharp)),
        AnalyzerConfig::default(),
    );
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
        var service = flag ? new Service() : new Service();
        service.Run();
    }
}
}
"#;
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let file = ProjectFile::new(root.clone(), PathBuf::from("Partial.cs"));
    file.write(source).expect("write source");
    let workspace = WorkspaceAnalyzer::build(
        Arc::new(TestProject::new(root, Language::CSharp)),
        AnalyzerConfig::default(),
    );
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
    let workspace = WorkspaceAnalyzer::build(
        Arc::new(TestProject::new(root, Language::CSharp)),
        AnalyzerConfig::default(),
    );
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
    let workspace = WorkspaceAnalyzer::build(
        Arc::new(TestProject::new(root, Language::CSharp)),
        AnalyzerConfig::default(),
    );
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

#[test]
fn unsupported_language_returns_an_explicit_row() {
    let source = "value = object.member\n";
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let file = ProjectFile::new(root.clone(), PathBuf::from("app.txt"));
    file.write(source).expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));

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
    let workspace = WorkspaceAnalyzer::build(
        Arc::new(TestProject::new(root, Language::Java)),
        AnalyzerConfig::default(),
    );
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
    let invocation =
        smallest_named_node_covering(tree.root_node(), call_range.start_byte, call_range.end_byte)
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
    let workspace = WorkspaceAnalyzer::build(
        Arc::new(TestProject::new(root, Language::Java)),
        AnalyzerConfig::default(),
    );
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
        BoundedJavaResolution::Exceeded {
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
        BoundedJavaResolution::Cancelled { work }
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
        BoundedJavaResolution::Complete {
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
            BoundedJavaResolution::Exceeded {
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
            BoundedJavaResolution::Cancelled { work }
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
    let workspace = WorkspaceAnalyzer::build(
        Arc::new(TestProject::new(root, Language::Java)),
        AnalyzerConfig::default(),
    );
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
    let cartesian_workspace = WorkspaceAnalyzer::build(
        Arc::new(TestProject::new(cartesian_root, Language::Java)),
        AnalyzerConfig::default(),
    );
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
            },
            TypeLookupType {
                fqn: alternate_type.fq_name(),
                definitions: vec![alternate_type],
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
    let workspace = WorkspaceAnalyzer::build(
        Arc::new(TestProject::new(root, Language::Java)),
        AnalyzerConfig::default(),
    );
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

#[test]
fn tiny_budget_and_cancellation_are_deterministic() {
    let source = r#"
class Service { run() {} }
function makeService() { return new Service(); }
export function caller() {
  const service = makeService();
  service.run();
}
"#;
    let (_temp, file, analyzer) = test_project(source);
    let service = ReceiverQueryService::new(&analyzer);
    let range = marker_range(source, "service.run");

    let report = service
        .analyze(
            ReceiverQueryOperation::MemberTargets,
            &file,
            range,
            ReceiverQueryInput::ContainingSite,
            ReceiverAnalysisBudget::tiny(),
            None,
        )
        .expect("tiny-budget result");
    assert!(matches!(
        report.analysis,
        ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::ExceededBudget {
            limit: "scope_nodes"
        })
    ));
    assert_eq!(report.work.setup_nodes, 1);
    assert!(
        report
            .work
            .setup_nodes
            .saturating_add(report.work.scope_nodes)
            <= ReceiverAnalysisBudget::tiny().max_scope_nodes
    );
    assert!(
        report.work.summary_expansions <= ReceiverAnalysisBudget::tiny().max_summary_expansions
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
fn receiver_semantic_bridge_uses_every_receiver_limit() {
    let bridge = ReceiverSemanticBridge::new(ReceiverAnalysisBudget {
        context_depth: 2,
        max_targets: 3,
        max_summary_expansions: 9,
        max_scope_nodes: 17,
    })
    .expect("aggregate semantic budget");
    let semantic = bridge.budget.limits();
    assert_eq!(semantic.procedures, 2);
    assert_eq!(semantic.control_edges, 1);
    assert_eq!(semantic.nested_entries, 5);
    assert_eq!(semantic.call_sites, 4);
    assert_eq!(semantic.memory_locations, 3);
    assert_eq!(semantic.captures, 2);
    assert_eq!(semantic.source_bytes, 17 * 1_024);
    let aggregate_limits = ReceiverSemanticBridge::receiver_work(semantic);
    assert_eq!(aggregate_limits.scope_nodes, 17);
    assert_eq!(aggregate_limits.summary_expansions, 9);

    let oracle = bridge.oracle_limits.values();
    assert_eq!(oracle.dispatch_targets, 3);
    assert_eq!(oracle.objects_per_value, 3);
    assert_eq!(oracle.alias_breadth, 3);
    assert_eq!(oracle.source_observations, 3);
    assert_eq!(oracle.call_context_depth, 2);
    assert_eq!(oracle.summary_depth, 9);
    assert_eq!(oracle.call_binding_entries, 9);

    let zero_context = ReceiverSemanticBridge::new(ReceiverAnalysisBudget {
        context_depth: 0,
        ..ReceiverAnalysisBudget::default()
    })
    .expect("zero-context receiver budget");
    assert_eq!(zero_context.oracle_limits.call_context_depth(), 1);

    assert_eq!(
        ReceiverSemanticBridge::new(ReceiverAnalysisBudget {
            max_scope_nodes: ReceiverSemanticBridge::SCOPE_DIMENSIONS - 1,
            ..ReceiverAnalysisBudget::default()
        })
        .unwrap_err(),
        ReceiverBudgetLimit::ScopeNodes
    );
    assert_eq!(
        ReceiverSemanticBridge::new(ReceiverAnalysisBudget {
            max_summary_expansions: ReceiverSemanticBridge::SUMMARY_DIMENSIONS - 1,
            ..ReceiverAnalysisBudget::default()
        })
        .unwrap_err(),
        ReceiverBudgetLimit::SummaryExpansions
    );
}

#[test]
fn receiver_semantic_bridge_translates_all_row_work_and_limit_kinds() {
    let translated = ReceiverSemanticBridge::receiver_work(SemanticWork {
        source_bytes: usize::MAX,
        procedures: 1,
        blocks: 1,
        program_points: 1,
        values: 1,
        allocations: 1,
        call_sites: 1,
        memory_locations: 1,
        captures: 1,
        source_mappings: 1,
        evidence: 1,
        gaps: 1,
        events: 1,
        control_edges: 1,
        nested_entries: 1,
        owned_text_bytes: usize::MAX,
    });
    assert_eq!(translated.setup_nodes, 0);
    assert_eq!(translated.summary_expansions, 3);
    assert_eq!(translated.scope_nodes, 11);

    let budget = SemanticBudget::uniform(1).unwrap();
    let summary = budget
        .check(SemanticWork {
            call_sites: 2,
            ..SemanticWork::default()
        })
        .unwrap_err();
    assert_eq!(
        ReceiverSemanticBridge::receiver_limit(summary),
        ReceiverBudgetLimit::SummaryExpansions
    );
    let scope = budget
        .check(SemanticWork {
            events: 2,
            ..SemanticWork::default()
        })
        .unwrap_err();
    assert_eq!(
        ReceiverSemanticBridge::receiver_limit(scope),
        ReceiverBudgetLimit::ScopeNodes
    );
    let nested_scope = budget
        .check(SemanticWork {
            nested_entries: 2,
            ..SemanticWork::default()
        })
        .unwrap_err();
    assert_eq!(
        ReceiverSemanticBridge::receiver_limit(nested_scope),
        ReceiverBudgetLimit::ScopeNodes
    );
}

#[test]
fn semantic_receiver_evidence_requires_complete_exhaustive_input_for_precision() {
    let outcomes = [
        SemanticOutcome::Complete {
            value: (),
            work: SemanticWork::default(),
        },
        SemanticOutcome::Ambiguous {
            candidates: (),
            work: SemanticWork::default(),
        },
        SemanticOutcome::Unknown {
            partial: Some(()),
            work: SemanticWork::default(),
        },
        SemanticOutcome::Unsupported {
            capability: crate::analyzer::semantic::SemanticCapability::Values,
            partial: Some(()),
            work: SemanticWork::default(),
        },
        SemanticOutcome::Unproven {
            partial: (),
            work: SemanticWork::default(),
        },
    ];
    let coverages = [
        CandidateCoverage::Exhaustive,
        CandidateCoverage::Open,
        CandidateCoverage::Truncated,
    ];

    for (outcome_index, outcome) in outcomes.iter().enumerate() {
        for coverage in coverages {
            let evidence = SemanticReceiverEvidence::from_outcome(outcome, coverage);
            assert_eq!(
                evidence.supports_precise(),
                outcome_index == 0 && coverage == CandidateCoverage::Exhaustive
            );
            assert_eq!(
                evidence.is_truncated(),
                coverage == CandidateCoverage::Truncated
            );
            assert!(
                !evidence.legacy_provider_can_close(),
                "raw incomplete evidence must not be reclassified as global capability openness"
            );
        }
    }
}

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
    let mut members = ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Precise(vec![
        service.clone(),
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
            if targets == &[service]
    ));
}

#[test]
fn semantic_receiver_gate_preserves_provider_identity_failures() {
    let source = "export const value = {};\n";
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    let file = ProjectFile::new(root.clone(), PathBuf::from("app.ts"));
    file.write(source).expect("write source");
    let workspace = WorkspaceAnalyzer::build(
        Arc::new(TestProject::new(root, Language::TypeScript)),
        AnalyzerConfig::default(),
    );
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
