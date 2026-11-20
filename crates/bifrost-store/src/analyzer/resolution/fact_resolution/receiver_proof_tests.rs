//! Test-only observation of the normal selected receiver proof session.
//!
//! The decorator changes the selected visitor's returned rows before the
//! shared reader consumes them. It never writes immutable publications or
//! supplies a second ledger or proof algorithm.

use super::super::fact_source::SelectedDeclarationModifier;
use super::*;
use brokk_bifrost_semantic::analyzer::semantic::read_ledger::SelectedReceiverProofQuestion;
use std::sync::{Arc, Mutex};

/// A scoped input decorator shared by actual fill and head verification.
/// Each method changes one selected relation, including an exhausted empty
/// inventory, before the normal proof reader hashes and interprets it.
#[doc(hidden)]
pub trait ReceiverProofTestDecorator: Send + Sync {
    /// Decorate independently supplied source inventory before the normal
    /// session publishes authority. Row evidence is decoded row-only evidence,
    /// never the legacy aggregate. The question is absent for a batch warmup.
    fn inventory_evidence(
        &self,
        _question: Option<&SelectedReceiverProofQuestion>,
        _relation: &'static str,
        _selectors: &[SemanticId],
        _actual_row_evidence: &ResolutionCompletion,
        _inventory: &mut super::super::fact_source::TypedFactInventoryEvidence,
    ) {
    }

    fn frontier_completions(
        &self,
        _question: &SelectedReceiverProofQuestion,
        _rows: &mut Vec<super::super::fact_source::SelectedTypeFrontierCompletion>,
    ) {
    }

    fn proof_attempted(
        &self,
        _source_path: Option<&str>,
        _application: SemanticId,
        _transfer: Option<(SemanticId, SemanticId)>,
    ) {
    }

    fn proof_recordable(&self, _question: &SelectedReceiverProofQuestion) {}

    /// Substitute the selected Base question seen by receipt revalidation.
    /// The input remains a real selected question; the test models a selected
    /// source whose canonical question changed after the original fill.
    fn replay_base_question(
        &self,
        question: &SelectedReceiverProofQuestion,
    ) -> Option<SelectedReceiverProofQuestion> {
        Some(question.clone())
    }

    fn proof_refused(
        &self,
        _source_path: Option<&str>,
        _application: SemanticId,
        _transfer: Option<(SemanticId, SemanticId)>,
        _reason: &'static str,
    ) {
    }

    /// The actual language hook ran, independently of retained provenance or
    /// receipt availability. The source path comes from its selected mount.
    fn conditional_seed_evaluated(
        &self,
        _source_path: &str,
        _read: &super::super::ConditionalTypeSeedRead,
    ) {
    }

    fn conditional_seed_read(
        &self,
        _question: &SelectedReceiverProofQuestion,
        _read: &super::super::ConditionalTypeSeedRead,
    ) {
    }

    fn installed_read(&self, _question: &SelectedReceiverProofQuestion) {}

    fn transfer_proof_read(
        &self,
        _question: &SelectedReceiverProofQuestion,
        _read: &super::receiver_proof::CurrentInstanceTransferObservation,
    ) {
    }

    fn receipt_replayed(&self, _question: &SelectedReceiverProofQuestion) {}

    fn checkpoint_receipt_replayed(&self, _question: &SelectedReceiverProofQuestion) {}

    fn slot_prep_reused(&self, _question: &SelectedReceiverProofQuestion) {}

    fn application_properties(
        &self,
        _question: &SelectedReceiverProofQuestion,
        _rows: &mut Vec<SelectedTypedRow<LoweredDeclarationTypeProperty>>,
    ) {
    }

    fn generic_formals(
        &self,
        _question: &SelectedReceiverProofQuestion,
        _owner: SemanticId,
        _fragment: BindingFragmentId,
        _rows: &mut Vec<SelectedTypedRow<LoweredGenericFormal>>,
    ) {
    }

    fn type_arguments(
        &self,
        _question: &SelectedReceiverProofQuestion,
        _application: SemanticId,
        _fragment: BindingFragmentId,
        _rows: &mut Vec<SelectedTypedRow<LoweredTypeArgument>>,
    ) {
    }

    fn formal_identities(
        &self,
        _question: &SelectedReceiverProofQuestion,
        _rows: &mut Vec<SelectedTypedRow<LoweredDeclarationTypeProperty>>,
    ) {
    }

    fn declaration_modifiers(
        &self,
        _question: &SelectedReceiverProofQuestion,
        _rows: &mut Vec<SelectedTypedRow<SelectedDeclarationModifier>>,
    ) {
    }
}

// Policy workers can run on another thread even with one internal worker.
// The isolated test subprocess installs one immutable decorator for the
// scope, so fill and verifier see precisely the same input transformation.
static DECORATOR: Mutex<Option<Arc<dyn ReceiverProofTestDecorator>>> = Mutex::new(None);

#[doc(hidden)]
pub struct ReceiverProofTestDecoratorGuard {
    _private: (),
}

impl Drop for ReceiverProofTestDecoratorGuard {
    fn drop(&mut self) {
        drop(
            DECORATOR
                .lock()
                .expect("receiver proof decorator poisoned")
                .take(),
        );
    }
}

#[doc(hidden)]
pub fn install_receiver_proof_test_decorator(
    decorator: Arc<dyn ReceiverProofTestDecorator>,
) -> ReceiverProofTestDecoratorGuard {
    let mut active = DECORATOR.lock().expect("receiver proof decorator poisoned");
    assert!(active.is_none(), "receiver proof decorators cannot overlap");
    *active = Some(decorator);
    ReceiverProofTestDecoratorGuard { _private: () }
}

pub(super) fn with_unestablished_base_routes<T>(run: impl FnOnce() -> T) -> T {
    struct UnestablishedBaseRoutes;

    impl ReceiverProofTestDecorator for UnestablishedBaseRoutes {
        fn inventory_evidence(
            &self,
            _question: Option<&SelectedReceiverProofQuestion>,
            relation: &'static str,
            _selectors: &[SemanticId],
            _actual_row_evidence: &ResolutionCompletion,
            inventory: &mut super::super::fact_source::TypedFactInventoryEvidence,
        ) {
            if relation == "routes_for_references" {
                *inventory = super::super::fact_source::TypedFactInventoryEvidence::Unestablished;
            }
        }
    }

    let _guard = install_receiver_proof_test_decorator(Arc::new(UnestablishedBaseRoutes));
    run()
}

pub(super) fn with_missing_base_frontier<T>(run: impl FnOnce() -> T) -> T {
    struct MissingBaseFrontier;

    impl ReceiverProofTestDecorator for MissingBaseFrontier {
        fn frontier_completions(
            &self,
            _question: &SelectedReceiverProofQuestion,
            rows: &mut Vec<super::super::fact_source::SelectedTypeFrontierCompletion>,
        ) {
            rows.clear();
        }
    }

    let _guard = install_receiver_proof_test_decorator(Arc::new(MissingBaseFrontier));
    run()
}

pub(super) fn with_empty_application_properties<T>(run: impl FnOnce() -> T) -> T {
    struct EmptyApplicationProperties;

    impl ReceiverProofTestDecorator for EmptyApplicationProperties {
        fn application_properties(
            &self,
            _question: &SelectedReceiverProofQuestion,
            rows: &mut Vec<SelectedTypedRow<LoweredDeclarationTypeProperty>>,
        ) {
            rows.clear();
        }
    }

    let _guard = install_receiver_proof_test_decorator(Arc::new(EmptyApplicationProperties));
    run()
}

pub(crate) fn with_changed_base_question<T>(
    replacement: SelectedReceiverProofQuestion,
    run: impl FnOnce() -> T,
) -> T {
    struct ChangedBaseQuestion(SelectedReceiverProofQuestion);

    impl ReceiverProofTestDecorator for ChangedBaseQuestion {
        fn replay_base_question(
            &self,
            question: &SelectedReceiverProofQuestion,
        ) -> Option<SelectedReceiverProofQuestion> {
            if matches!(
                question,
                SelectedReceiverProofQuestion::BaseReceiverContext { .. }
            ) {
                Some(self.0.clone())
            } else {
                Some(question.clone())
            }
        }
    }

    let _guard = install_receiver_proof_test_decorator(Arc::new(ChangedBaseQuestion(replacement)));
    run()
}

pub(crate) fn replay_question_for_test(
    question: &SelectedReceiverProofQuestion,
) -> Option<SelectedReceiverProofQuestion> {
    let decorator = active_receiver_proof_test_decorator()?;
    decorator.replay_base_question(question)
}

pub(crate) fn with_receiver_proof_test_decorator(
    apply: impl FnOnce(&dyn ReceiverProofTestDecorator),
) {
    let decorator = active_receiver_proof_test_decorator();
    if let Some(decorator) = decorator {
        apply(decorator.as_ref());
    }
}

fn active_receiver_proof_test_decorator() -> Option<Arc<dyn ReceiverProofTestDecorator>> {
    DECORATOR
        .lock()
        .expect("receiver proof decorator poisoned")
        .clone()
}

/// Assert the worklist's installed subscriptions, using the independently
/// recorded output-to-proof consumption association as the expected set.
/// Merely scanning the installed nodes would miss a dropped dependency.
pub(super) fn observe_installed_receiver_proof_reads(evaluation: &FactEvaluation<'_, '_>) {
    let Some(decorator) = active_receiver_proof_test_decorator() else {
        return;
    };
    for (output, consumed) in &evaluation.session.receiver_proof_consumers {
        if !evaluation.demanded_slots.contains(output) {
            continue;
        }
        for digest in consumed {
            let (question, _) = evaluation
                .session
                .receiver_proof_memos
                .iter()
                .find(|(question, _)| question.canonical_digest().as_bytes() == digest)
                .expect("a consumed selected proof retains its replayable memo");
            let item = TypedWorkItem::Slot(*output);
            let input = TypedInput::QueryNode(QueryNode::SelectedInputQuestion(*digest));
            assert!(
                evaluation
                    .typed_worklist
                    .inputs
                    .get(&item)
                    .is_some_and(|inputs| inputs.contains(&input)),
                "consumed selected proof must be installed on its actual output: {question:?}, {item:?}"
            );
            assert!(
                evaluation
                    .typed_worklist
                    .readers
                    .get(&input)
                    .is_some_and(|readers| readers.contains(&item)),
                "selected proof must wake its actual output: {question:?}, {item:?}"
            );
            decorator.installed_read(question);
        }
    }
}

/// Observe the actual language-hook result, rather than recomputing the
/// language's conditions in the test or mistaking a complete read for Ready.
pub(super) fn observe_conditional_seed_read(
    session: &FactReadSession<'_>,
    slot: SemanticId,
    read: &super::super::ConditionalTypeSeedRead,
) {
    let Some(decorator) = active_receiver_proof_test_decorator() else {
        return;
    };
    for (question, memo) in &session.receiver_proof_memos {
        if memo.query == super::receiver_proof::ReceiverProofQuery::OwnerApplication(slot) {
            decorator.conditional_seed_read(question, read);
        }
    }
}
