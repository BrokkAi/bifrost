//! Native value-type classification lifecycle shared by request-local taint engines.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use crate::taint_policy::TaintPolicyCompileError;
use brokk_bifrost_analysis::analyzer::semantic::{
    BarrierObservation, SemanticExecutionBudget, SemanticLanguage, SemanticRequest,
    ValueTypeBarrierContext, ValueTypeBarrierDecision, ValueTypeBarrierReason, ValueTypePredicate,
    evaluate_value_type_barrier, open_value_type_barrier_context,
};
use brokk_bifrost_analysis::analyzer::{Language, WorkspaceAnalyzer};

#[cfg(any(test, feature = "test-support"))]
thread_local! { static CLASSIFIER_CALLS_FOR_TEST: Cell<u64> = const { Cell::new(0) }; }

/// Count classifier calls within this thread's test request, restoring the
/// enclosing counter even if a test assertion unwinds.
#[cfg(any(test, feature = "test-support"))]
pub fn count_value_type_barrier_calls_for_test<T>(run: impl FnOnce() -> T) -> (T, u64) {
    struct Restore(u64);
    impl Drop for Restore {
        fn drop(&mut self) {
            CLASSIFIER_CALLS_FOR_TEST.set(self.0);
        }
    }
    let restore = Restore(CLASSIFIER_CALLS_FOR_TEST.replace(0));
    let result = run();
    let count = CLASSIFIER_CALLS_FOR_TEST.get();
    drop(restore);
    (result, count)
}

/// Lazy language contexts retain decision and budget-failure memos only for this
/// request. Both lenient and strict refinements borrow the same instance.
pub(crate) struct ValueTypeBarrierService<'a> {
    workspace: &'a WorkspaceAnalyzer,
    execution_budget: SemanticExecutionBudget,
    contexts: RefCell<HashMap<Language, Option<Box<dyn ValueTypeBarrierContext + 'a>>>>,
    checks: Cell<u64>,
}

impl<'a> ValueTypeBarrierService<'a> {
    pub(crate) fn new(
        workspace: &'a WorkspaceAnalyzer,
        execution_budget: SemanticExecutionBudget,
    ) -> Self {
        Self {
            workspace,
            execution_budget,
            contexts: RefCell::new(HashMap::new()),
            checks: Cell::new(0),
        }
    }

    pub(crate) fn checks(&self) -> u64 {
        self.checks.get()
    }

    pub(crate) fn classify(
        &self,
        observation: &BarrierObservation,
        predicate: ValueTypePredicate,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ValueTypeBarrierDecision, TaintPolicyCompileError> {
        self.checks.set(self.checks.get() + 1);
        #[cfg(any(test, feature = "test-support"))]
        CLASSIFIER_CALLS_FOR_TEST.set(CLASSIFIER_CALLS_FOR_TEST.get() + 1);
        let _timing = brokk_bifrost_analysis::profiling::scope("taint.barriers.classify");
        let SemanticLanguage::Standard(language) =
            observation.point().procedure().artifact().key().language()
        else {
            return Ok(ValueTypeBarrierDecision::Undecided(
                ValueTypeBarrierReason::UnsupportedLanguage,
            ));
        };
        let mut contexts = self.contexts.borrow_mut();
        if let std::collections::hash_map::Entry::Vacant(entry) = contexts.entry(language) {
            entry.insert(
                open_value_type_barrier_context(
                    language,
                    self.workspace.analyzer(),
                    request.cancellation,
                )
                .map_err(|error| TaintPolicyCompileError::SemanticProvider(error.to_string()))?,
            );
        }
        let mut staged = request.staged_with_execution_budget(&self.execution_budget);
        if let Some(context) = contexts[&language].as_deref() {
            staged = staged.with_value_type_barrier_context(context);
        }
        evaluate_value_type_barrier(
            language,
            self.workspace.analyzer(),
            observation,
            predicate,
            &mut staged,
        )
        .map_err(|error| {
            let semantics = observation.point().procedure().semantics();
            let value = semantics
                .value(observation.value())
                .expect("a barrier observation names a live value");
            let mapping = semantics
                .source_mapping(value.source)
                .expect("a live value retains its source mapping");
            TaintPolicyCompileError::SemanticProvider(format!(
                "barrier {predicate:?} for value {:?} at {:?} ({:?}, {:?}): {error}",
                observation.value(),
                mapping.locator,
                mapping.kind,
                observation.phase(),
            ))
        })
    }
}
