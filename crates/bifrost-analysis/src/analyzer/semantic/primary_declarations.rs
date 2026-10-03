//! Budgeted handoff from an exact syntax tree to its ordinary primary producer.

use super::{PrimaryDeclarationSemanticsLowerer, SemanticOutcome, SemanticProviderError};
use crate::analyzer::ProjectFile;
use crate::analyzer::semantic::{
    CancellationToken, ProcedureSemanticsParts, SemanticBudget, SemanticWork,
};
use crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree;
use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, walk_tree_preorder};

/// Preflight both the measuring walk and one primary producer visit per parser
/// node. The source snapshot has already passed source-byte admission in the
/// service. Primary construction is synchronous: cancellation is observed
/// before and after it, not falsely advertised as interrupting the producer.
pub(crate) fn lower_with_primary_declarations(
    lowerer: &dyn PrimaryDeclarationSemanticsLowerer,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    budget: &SemanticBudget,
    cancellation: &CancellationToken,
    produce: impl FnOnce() -> ParsedFile,
) -> Result<SemanticOutcome<Vec<ProcedureSemanticsParts>>, SemanticProviderError> {
    assert!(
        budget.used().source_bytes >= prepared.source().len(),
        "primary semantic construction requires source-byte admission"
    );
    let mut primary_work = SemanticWork::default();
    let mut stopped = None;
    walk_tree_preorder(prepared.tree().root_node(), true, |_| {
        if cancellation.is_cancelled() {
            stopped = Some(SemanticOutcome::Cancelled {
                partial: None,
                work: primary_work,
            });
            return WalkControl::Break;
        }
        primary_work.nested_entries = primary_work.nested_entries.saturating_add(2);
        if let Err(exceeded) = budget.check(primary_work) {
            stopped = Some(SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded,
                work: primary_work,
            });
            return WalkControl::Break;
        }
        WalkControl::Continue
    });
    if let Some(stopped) = stopped {
        return Ok(stopped);
    }
    let mut staged = budget.clone();
    staged
        .charge(primary_work)
        .expect("primary traversal was preflighted");
    if cancellation.is_cancelled() {
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work: primary_work,
        });
    }
    let primary = produce();
    assert!(
        primary.source_facts.is_some(),
        "primary declaration input requires canonical source facts"
    );
    if cancellation.is_cancelled() {
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work: primary_work,
        });
    }
    let mut outcome =
        lowerer.lower_with_primary_declarations(file, prepared, &primary, &staged, cancellation)?;
    match &mut outcome {
        SemanticOutcome::Complete { work, .. }
        | SemanticOutcome::Ambiguous { work, .. }
        | SemanticOutcome::Unknown { work, .. }
        | SemanticOutcome::Unsupported { work, .. }
        | SemanticOutcome::Unproven { work, .. }
        | SemanticOutcome::ExceededBudget { work, .. }
        | SemanticOutcome::Cancelled { work, .. } => *work = work.conservative_add(primary_work),
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::tree_sitter_analyzer::{PreparedSourceOrigin, PreparedSyntaxSource};
    use crate::analyzer::{Language, LanguageDialect};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingLowerer(AtomicUsize);

    impl PrimaryDeclarationSemanticsLowerer for CountingLowerer {
        fn lower_with_primary_declarations(
            &self,
            _file: &ProjectFile,
            _prepared: &PreparedSyntaxTree,
            primary: &ParsedFile,
            _budget: &SemanticBudget,
            _cancellation: &CancellationToken,
        ) -> Result<SemanticOutcome<Vec<ProcedureSemanticsParts>>, SemanticProviderError> {
            assert!(primary.source_facts.is_some());
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(SemanticOutcome::Complete {
                value: Vec::new(),
                work: SemanticWork::default(),
            })
        }
    }

    fn prepared() -> (ProjectFile, PreparedSyntaxTree, SemanticBudget) {
        let source = "class C { static int Run() { return 1; } }";
        let file = ProjectFile::new(std::env::temp_dir(), "Primary.cs");
        let tree = brokk_bifrost_csharp::preprocessor::parse_csharp(source).expect("C# tree");
        let prepared = PreparedSyntaxTree::new(
            PreparedSyntaxSource::Exact(Arc::from(source)),
            tree,
            vec![0],
            LanguageDialect::for_path(Language::CSharp, file.rel_path()),
            PreparedSourceOrigin::Disk,
            None,
        );
        let mut budget = SemanticBudget::default();
        budget
            .charge(SemanticWork {
                source_bytes: source.len(),
                ..SemanticWork::default()
            })
            .expect("source admission");
        (file, prepared, budget)
    }

    #[test]
    fn insufficient_primary_budget_never_invokes_the_producer() {
        let (file, prepared, budget) = prepared();
        let mut limits = budget.limits();
        limits.nested_entries = 1;
        let mut budget = SemanticBudget::new(limits).expect("limits");
        budget
            .charge(SemanticWork {
                source_bytes: prepared.source().len(),
                ..SemanticWork::default()
            })
            .unwrap();
        let lowerer = CountingLowerer(AtomicUsize::new(0));
        let result = lower_with_primary_declarations(
            &lowerer,
            &file,
            &prepared,
            &budget,
            &CancellationToken::new(),
            || panic!("producer must not run before admission"),
        )
        .unwrap();
        assert!(matches!(result, SemanticOutcome::ExceededBudget { .. }));
        assert_eq!(lowerer.0.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn cancellation_after_synchronous_primary_construction_prevents_lowering() {
        let (file, prepared, budget) = prepared();
        let cancellation = CancellationToken::new();
        let lowerer = CountingLowerer(AtomicUsize::new(0));
        let result = lower_with_primary_declarations(
            &lowerer,
            &file,
            &prepared,
            &budget,
            &cancellation,
            || {
                let primary = brokk_bifrost_csharp::declarations::parse_csharp_file(
                    &file,
                    prepared.source(),
                    prepared.tree(),
                );
                cancellation.cancel();
                primary
            },
        )
        .unwrap();
        assert!(matches!(result, SemanticOutcome::Cancelled { .. }));
        assert_eq!(lowerer.0.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn exact_primary_projection_is_lowered_and_preflight_work_is_reported() {
        let (file, prepared, budget) = prepared();
        let lowerer = CountingLowerer(AtomicUsize::new(0));
        let result = lower_with_primary_declarations(
            &lowerer,
            &file,
            &prepared,
            &budget,
            &CancellationToken::new(),
            || {
                brokk_bifrost_csharp::declarations::parse_csharp_file(
                    &file,
                    prepared.source(),
                    prepared.tree(),
                )
            },
        )
        .unwrap();
        assert!(matches!(result, SemanticOutcome::Complete { .. }));
        assert!(result.work().nested_entries > 2);
        assert_eq!(lowerer.0.load(Ordering::Relaxed), 1);
    }
}
