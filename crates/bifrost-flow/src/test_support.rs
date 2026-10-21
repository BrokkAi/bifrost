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
