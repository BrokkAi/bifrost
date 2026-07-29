use std::sync::Arc;

use brokk_bifrost::analyzer::dataflow::{SummaryEffectKey, SummaryPublicationOutcome};
use brokk_bifrost::analyzer::semantic::{
    CancellationToken, ProcedureHandle, ProcedureKind, SemanticBudget, SemanticRequest,
};
use brokk_bifrost::analyzer::typestate::{
    ProductionTypestateSummaryRepository, TypestateSummaryRepositoryRotation,
    project_production_semantic_summaries,
};
use brokk_bifrost::{AnalyzerConfig, Language, WorkspaceAnalyzer};

use crate::common::semantic_graph::SemanticGraph;
use crate::common::{BuiltInlineTestProject, InlineTestProject};

const TYPESCRIPT_SOURCE: &str = r#"
function useResource(resource: object): void {}

function helper(resource: object): void {
  useResource(resource);
}

function lifecycle(resource: object): void {
  helper(resource);
}
"#;

const JAVA_SOURCE: &str = r#"
final class Resource {}

final class LifecycleFixture {
  static void useResource(Resource resource) {}

  static void helper(Resource resource) {
    useResource(resource);
  }

  static void lifecycle(Resource resource) {
    helper(resource);
  }
}
"#;

fn root_named(
    project: &BuiltInlineTestProject,
    workspace: &WorkspaceAnalyzer,
    path: &str,
    name: &str,
) -> ProcedureHandle {
    let graph = SemanticGraph::materialize(project, workspace, path);
    let procedure = graph
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| {
            matches!(
                procedure.kind(),
                ProcedureKind::Function | ProcedureKind::Method
            ) && procedure
                .locator()
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name())
                == Some(name)
        })
        .unwrap_or_else(|| panic!("fixture missing procedure {name}"));
    graph
        .artifact()
        .procedure_handle(procedure.id())
        .expect("fixture procedure has a live handle")
}

fn project_summaries(
    workspace: &WorkspaceAnalyzer,
    root: ProcedureHandle,
) -> brokk_bifrost::analyzer::typestate::ProductionSemanticSummarySet {
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    project_production_semantic_summaries(
        &[root],
        &workspace.icfg_provider(),
        &mut SemanticRequest::new(&mut budget, &cancellation),
    )
    .expect("production semantic summaries")
}

#[test]
fn production_projection_covers_typescript_and_java_call_closures() {
    for (language, path, source) in [
        (Language::TypeScript, "src/main.ts", TYPESCRIPT_SOURCE),
        (Language::Java, "src/LifecycleFixture.java", JAVA_SOURCE),
    ] {
        let project = InlineTestProject::with_language(language)
            .file(path, source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let root = root_named(&project, &workspace, path, "lifecycle");
        let summaries = project_summaries(&workspace, root.clone());

        assert!(summaries.len() >= 2, "{language:?} dependency closure");
        assert!(summaries.summary_for(&root).is_some());
        assert_eq!(
            summaries.protocol_summaries().unwrap().len(),
            summaries.len()
        );
    }
}

#[test]
fn production_projection_retains_unresolved_boundary_completeness_explicitly() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("src/main.ts", TYPESCRIPT_SOURCE)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let root = root_named(&project, &workspace, "src/main.ts", "lifecycle");
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();

    let summaries = project_production_semantic_summaries(
        std::slice::from_ref(&root),
        &workspace.icfg_provider(),
        &mut SemanticRequest::new(&mut budget, &cancellation),
    )
    .unwrap();
    let summary = summaries.summary_for(&root).unwrap();
    let boundary = summary
        .effects()
        .iter()
        .find(|effect| matches!(effect.key(), SummaryEffectKey::UnknownCallBoundary { .. }))
        .expect("unresolved dispatch is an explicit summary effect");
    assert!(!boundary.evidence().is_complete());
    assert!(summary.completeness().is_complete());
}

#[test]
fn generation_rotation_evicts_and_repeated_projection_hits() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("src/main.ts", TYPESCRIPT_SOURCE)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let root = root_named(&project, &workspace, "src/main.ts", "lifecycle");
    let summaries = project_summaries(&workspace, root);
    let repository = Arc::new(ProductionTypestateSummaryRepository::new());

    assert_eq!(
        repository.admit_generation(7),
        TypestateSummaryRepositoryRotation::Initialized
    );
    let lease = repository.lease(7).unwrap();
    repository.record_recomputation();
    assert!(!lease.contains_semantic_set(&summaries).unwrap());
    assert_eq!(
        lease.publish_semantic_set(&summaries).unwrap(),
        SummaryPublicationOutcome::Inserted
    );
    assert!(lease.contains_semantic_set(&summaries).unwrap());
    assert_eq!(
        repository.admit_generation(7),
        TypestateSummaryRepositoryRotation::Current
    );

    let entries = summaries.len();
    assert_eq!(
        repository.admit_generation(8),
        TypestateSummaryRepositoryRotation::Rotated {
            evicted_entries: entries
        }
    );
    let successor_lease = repository.lease(8).unwrap();
    assert!(!successor_lease.contains_semantic_set(&summaries).unwrap());
    assert!(lease.contains_semantic_set(&summaries).is_err());
    assert_eq!(
        repository.admit_generation(7),
        TypestateSummaryRepositoryRotation::Stale {
            current: 8,
            requested: 7,
        }
    );
    assert_eq!(repository.generation(), Some(8));
    assert_eq!(
        repository.counters(),
        brokk_bifrost::analyzer::typestate::ProductionSummaryLifecycleCounters {
            hits: 0,
            misses: 0,
            rejections: 0,
            evictions: entries,
            recomputations: 1,
        }
    );
}

#[test]
fn successor_generation_preserves_in_flight_snapshot_ownership() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("src/main.ts", TYPESCRIPT_SOURCE)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let root = root_named(&project, &workspace, "src/main.ts", "lifecycle");
    let summaries = project_summaries(&workspace, root);
    let current = Arc::new(ProductionTypestateSummaryRepository::new());
    current.admit_generation(7);
    let current_lease = current.lease(7).unwrap();
    current_lease.publish_semantic_set(&summaries).unwrap();

    let successor = Arc::new(current.successor_generation(8));
    let successor_lease = successor.lease(8).unwrap();
    current.record_miss();

    assert_eq!(current.generation(), Some(7));
    assert!(current_lease.contains_semantic_set(&summaries).unwrap());
    assert_eq!(successor.generation(), Some(8));
    assert!(!successor_lease.contains_semantic_set(&summaries).unwrap());
    assert_eq!(successor.counters().evictions, summaries.len());
    assert_eq!(successor.counters().misses, 1);
}

#[test]
fn changed_dependency_changes_the_unchanged_root_summary_key() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/helper.ts",
            "export function helper(resource: object): void { void resource; }",
        )
        .file(
            "src/main.ts",
            "import { helper } from './helper';\nexport function lifecycle(resource: object): void { helper(resource); }",
        )
        .build();
    let workspace_v1 = project.workspace_analyzer(AnalyzerConfig::default());
    let root_v1 = root_named(&project, &workspace_v1, "src/main.ts", "lifecycle");
    let summaries_v1 = project_summaries(&workspace_v1, root_v1.clone());
    let root_summary_v1 = summaries_v1.summary_for(&root_v1).unwrap();

    project
        .file("src/helper.ts")
        .write(
            "export function helper(resource: object): void { const alias = resource; void alias; }",
        )
        .unwrap();
    let workspace_v2 = project.workspace_analyzer(AnalyzerConfig::default());
    let root_v2 = root_named(&project, &workspace_v2, "src/main.ts", "lifecycle");
    let summaries_v2 = project_summaries(&workspace_v2, root_v2.clone());
    let root_summary_v2 = summaries_v2.summary_for(&root_v2).unwrap();

    assert_eq!(
        root_summary_v1.key().identity(),
        root_summary_v2.key().identity(),
        "the unchanged caller keeps its own production identity"
    );
    assert_ne!(
        root_summary_v1.key().dependencies(),
        root_summary_v2.key().dependencies(),
        "the callee revision participates in the caller cache key"
    );
    assert_ne!(root_summary_v1.key(), root_summary_v2.key());
}
