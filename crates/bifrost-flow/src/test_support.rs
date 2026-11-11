use crate::analyzer::Language;
use crate::analyzer::semantic::{
    DeclarationLocator, DeclarationSegment, DeclarationSegmentKind, SemanticBudget,
    SemanticBudgetExceeded, SemanticLanguage, SemanticLocator, SemanticRole, SemanticWork,
    SourceAnchor, SourceSpan, WorkspaceMountId, WorkspaceRelativePath,
};

pub(crate) fn function_locator(
    mount: &str,
    path: &str,
    language: Language,
    role: SemanticRole,
    name: &str,
    span: SourceSpan,
) -> SemanticLocator {
    let anchor = SourceAnchor::new(span, 0);
    SemanticLocator::new(
        WorkspaceMountId::hash_bytes(mount),
        WorkspaceRelativePath::new(path).unwrap(),
        SemanticLanguage::Standard(language),
        DeclarationLocator::new(vec![
            DeclarationSegment::named(DeclarationSegmentKind::Function, name, anchor, 0).unwrap(),
        ])
        .unwrap(),
        role,
        anchor,
    )
}

pub(crate) fn procedure_budget_error(limit: usize, attempted: usize) -> SemanticBudgetExceeded {
    let mut limits = SemanticBudget::default().limits();
    limits.procedures = limit;
    SemanticBudget::new(limits)
        .expect("positive procedure budget")
        .check_admission(SemanticWork {
            procedures: attempted,
            ..SemanticWork::default()
        })
        .expect_err("procedure budget should be exceeded")
}

/// Coverage claims for a synthetic complete summary: protocol admission reads
/// the Protocol dimension, and the legacy completeness still comes from
/// ValueTransfer.
pub(crate) fn complete_summary_coverage() -> Vec<crate::dataflow::SummaryDimensionClaim> {
    use crate::dataflow::{SummaryDimension, SummaryDimensionClaim, SummaryDimensionStatus};
    [SummaryDimension::Protocol, SummaryDimension::ValueTransfer]
        .into_iter()
        .map(|dimension| {
            SummaryDimensionClaim::new(dimension, SummaryDimensionStatus::Complete)
                .expect("complete coverage claim is valid")
        })
        .collect()
}

/// A real, complete leaf summary for cache/read-ledger boundary tests.
pub(crate) fn with_leaf_semantic_summary(
    body: impl FnOnce(&crate::analyzer::WorkspaceAnalyzer, crate::dataflow::SemanticProcedureSummary),
) {
    use crate::analyzer::semantic::{CancellationToken, SemanticBudget, SemanticRequest};
    let project = crate::inline_project::InlineTestProject::with_language(
        crate::analyzer::Language::TypeScript,
    )
    .file("leaf.ts", "export function value() { return 1; }\n")
    .build();
    let workspace = project.workspace_analyzer(crate::analyzer::AnalyzerConfig::default());
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let artifact = workspace
        .materialize_program_semantics(
            &project.file("leaf.ts"),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("fixture materializes")
        .available_value()
        .cloned()
        .expect("fixture artifact");
    let procedure = artifact
        .procedures()
        .iter()
        .find(|p| {
            p.locator()
                .declaration()
                .segments()
                .last()
                .and_then(|s| s.name())
                == Some("value")
        })
        .and_then(|p| artifact.procedure_handle(p.id()))
        .expect("fixture leaf");
    let summaries = crate::typestate::project_production_semantic_summaries(
        &[procedure],
        &workspace.icfg_provider(),
        &mut SemanticRequest::new(&mut budget, &cancellation),
    )
    .expect("leaf projection");
    assert_eq!(summaries.summaries().len(), 1);
    // Protocol repository tests use a synthetic complete artifact. Production
    // projection deliberately refuses this claim without a value projection.
    let projected = &summaries.summaries()[0];
    let semantic = crate::dataflow::SemanticProcedureSummary::try_new_with_coverage(
        projected.key().clone(),
        projected.transfers().to_vec(),
        projected.effects().to_vec(),
        projected.dependencies().to_vec(),
        crate::dataflow::SummaryCompleteness::Complete,
        complete_summary_coverage(),
    )
    .expect("synthetic repository fixture");
    body(&workspace, semantic);
}
