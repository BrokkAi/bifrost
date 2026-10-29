//! Generation-bound selected inverse handles. Each query owns its candidates
//! and projections; the handle retains only analyzer handles and cancellation.

use super::reference_edges::{
    EdgeDerivationResult, EdgeIncompleteReason, SelectedInverseIndexOutcome,
    SelectedInverseReferenceIndex,
};
use crate::analyzer::{CodeUnit, IAnalyzer};
use brokk_bifrost_core::analyzer::structural::edges::EdgeProvenance;
use brokk_bifrost_core::cancellation::CancellationToken;

#[doc(hidden)]
pub enum SelectedInverseFailure {
    Unavailable(String),
    Stale(String),
    Cancelled,
    StoreError(String),
}

impl From<SelectedInverseFailure> for SelectedInverseIndexOutcome {
    fn from(failure: SelectedInverseFailure) -> Self {
        match failure {
            SelectedInverseFailure::Unavailable(detail) => Self::Unavailable(detail),
            SelectedInverseFailure::Stale(detail) => Self::Stale(detail),
            SelectedInverseFailure::Cancelled => Self::Cancelled,
            SelectedInverseFailure::StoreError(detail) => Self::StoreError(detail),
        }
    }
}

/// Language admission and projection. Admission clones the analyzer only after
/// checking its original selected state; no operation survives admission.
#[doc(hidden)]
pub trait SelectedInverseAdapter: Send + Sync + Sized + 'static {
    fn admit(
        analyzer: &dyn IAnalyzer,
        cancellation: &CancellationToken,
    ) -> Result<(u64, Self), SelectedInverseFailure>;

    fn current_generation(&self) -> u64;

    /// None means the target is uncovered, without a query failure diagnostic.
    fn query(
        &self,
        target: &CodeUnit,
        cancellation: &CancellationToken,
    ) -> Result<Option<EdgeDerivationResult>, SelectedInverseFailure>;
}

#[doc(hidden)]
pub struct LazySelectedInverse<A> {
    generation: u64,
    adapter: A,
    cancellation: CancellationToken,
}

impl<A: SelectedInverseAdapter> LazySelectedInverse<A> {
    pub fn build(
        analyzer: &dyn IAnalyzer,
        cancellation: &CancellationToken,
    ) -> Result<Self, SelectedInverseFailure> {
        let (generation, adapter) = A::admit(analyzer, cancellation)?;
        Ok(Self {
            generation,
            adapter,
            cancellation: cancellation.clone(),
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn adapter(&self) -> &A {
        &self.adapter
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }

    fn incomplete(&self, reason: EdgeIncompleteReason) -> EdgeDerivationResult {
        EdgeDerivationResult::incomplete(vec![reason], EdgeProvenance::Inverse, self.generation)
    }
}

impl<A: SelectedInverseAdapter> SelectedInverseReferenceIndex for LazySelectedInverse<A> {
    fn generation(&self) -> u64 {
        self.generation
    }

    fn inverse_for(&self, target: &CodeUnit) -> EdgeDerivationResult {
        if self.adapter.current_generation() != self.generation {
            return self.incomplete(EdgeIncompleteReason::InverseIndexResolutionIncomplete);
        }
        match self.adapter.query(target, &self.cancellation) {
            Ok(Some(answer)) => answer,
            Ok(None) => self.incomplete(EdgeIncompleteReason::InverseIndexTargetUncovered),
            Err(failure) => {
                let reason = match failure {
                    SelectedInverseFailure::Unavailable(detail) => {
                        EdgeIncompleteReason::SelectedInverseIndexUnavailable {
                            reason_kind: "unavailable".into(),
                            reason: detail,
                        }
                    }
                    SelectedInverseFailure::Stale(detail) => {
                        EdgeIncompleteReason::SelectedInverseIndexUnavailable {
                            reason_kind: "stale".into(),
                            reason: detail,
                        }
                    }
                    SelectedInverseFailure::Cancelled => EdgeIncompleteReason::Cancelled,
                    SelectedInverseFailure::StoreError(detail) => {
                        EdgeIncompleteReason::SelectedInverseIndexUnavailable {
                            reason_kind: "store_error".into(),
                            reason: detail,
                        }
                    }
                };
                self.incomplete(reason)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::reference_edges::EdgeCompleteness;
    use super::*;

    struct Uncovered;
    impl SelectedInverseAdapter for Uncovered {
        fn admit(
            _: &dyn IAnalyzer,
            _: &CancellationToken,
        ) -> Result<(u64, Self), SelectedInverseFailure> {
            Ok((7, Self))
        }
        fn current_generation(&self) -> u64 {
            7
        }
        fn query(
            &self,
            _: &CodeUnit,
            cancellation: &CancellationToken,
        ) -> Result<Option<EdgeDerivationResult>, SelectedInverseFailure> {
            if cancellation.is_cancelled() {
                Err(SelectedInverseFailure::Cancelled)
            } else {
                Ok(None)
            }
        }
    }
    #[test]
    fn uncovered_adapter_target_and_cancelled_request_have_distinct_coverage() {
        let temp = tempfile::tempdir().unwrap();
        let analyzer = super::super::identity_routes::tests::MetadataAnalyzer::new(temp.path());
        let target = CodeUnit::new(
            crate::analyzer::ProjectFile::new(temp.path(), "example.py"),
            crate::analyzer::CodeUnitType::Function,
            "",
            "f",
        );
        let cancellation = CancellationToken::default();
        let Ok(index) = LazySelectedInverse::<Uncovered>::build(&analyzer, &cancellation) else {
            panic!("admitted")
        };
        let answer = index.inverse_for(&target);
        assert!(answer.edges.is_empty());
        assert_eq!(answer.generation, 7);
        assert_eq!(
            answer.completeness,
            EdgeCompleteness::Incomplete {
                reasons: vec![EdgeIncompleteReason::InverseIndexTargetUncovered]
            }
        );
        assert!(!cancellation.is_cancelled());
        cancellation.cancel();
        let answer = index.inverse_for(&target);
        assert!(answer.edges.is_empty());
        assert_eq!(
            answer.completeness,
            EdgeCompleteness::Incomplete {
                reasons: vec![EdgeIncompleteReason::Cancelled]
            }
        );
    }
}
