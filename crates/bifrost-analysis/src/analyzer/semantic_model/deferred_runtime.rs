//! Consumer-local handle tracking for deferred-yield contracts.
//!
//! The caller supplies identities proven in its own executable semantics. The
//! profile's handle type is eligibility evidence, never a concrete handle ID.
//! Construction retains only the source relation; resume exposes projections
//! and leaves zero-yield control flow and member delivery to the caller.

use std::hash::Hash;

use crate::CancellationToken;
use crate::hash::HashMap;

use super::DeferredYieldContract;

/// A validity judgment for this specific resume, supplied by the consumer's
/// lifetime and mutation analysis. It does not close cleanup or dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeferredValidityEvidence {
    Established,
    Unknown,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeferredYieldBoundary {
    Cancelled,
    HandleBudgetExhausted,
    IncompleteContract,
    UnknownHandle,
    AmbiguousHandle,
    DifferentContract,
    Invalidated,
    UnknownValidity,
    UnsupportedValidity,
}

#[derive(Debug)]
enum RetainedHandle<'model, Source> {
    Retained {
        source: Source,
        contract: &'model DeferredYieldContract,
    },
    Ambiguous,
    Invalidated,
}

/// One may-yield event. This carries no concrete count, exhaustion, ordering,
/// or must-yield claim. Each call to resume produces a separate observation.
#[derive(Debug)]
pub struct DeferredYieldObservation<'state, 'model, Source> {
    pub source: &'state Source,
    pub contract: &'model DeferredYieldContract,
}

/// Bounded, analysis-local state. A new instance is required for a new source
/// snapshot or activation. Handle and source identities belong to the caller.
#[derive(Debug)]
pub struct DeferredYieldRuntime<'model, Handle, Source> {
    handles: HashMap<Handle, RetainedHandle<'model, Source>>,
    max_handles: usize,
    exhausted: bool,
}

impl<'model, Handle: Eq + Hash, Source> DeferredYieldRuntime<'model, Handle, Source> {
    pub fn new(max_handles: usize) -> Self {
        Self {
            handles: HashMap::default(),
            max_handles,
            exhausted: false,
        }
    }

    /// Record an exact construction result. Returns no item or transfer.
    /// Reusing an identity for multiple constructions loses singleton proof;
    /// subsequent resumes fail closed rather than selecting the latest source.
    pub fn construct(
        &mut self,
        handle: Handle,
        source: Source,
        contract: &'model DeferredYieldContract,
        cancellation: &CancellationToken,
    ) -> Result<(), DeferredYieldBoundary> {
        if cancellation.is_cancelled() {
            return Err(DeferredYieldBoundary::Cancelled);
        }
        if self.exhausted {
            return Err(DeferredYieldBoundary::HandleBudgetExhausted);
        }
        if let Some(retained) = self.handles.get_mut(&handle) {
            *retained = RetainedHandle::Ambiguous;
            return Err(DeferredYieldBoundary::AmbiguousHandle);
        }
        if !contract.is_complete() {
            return Err(DeferredYieldBoundary::IncompleteContract);
        }
        if self.handles.len() >= self.max_handles {
            self.exhausted = true;
            return Err(DeferredYieldBoundary::HandleBudgetExhausted);
        }
        self.handles
            .insert(handle, RetainedHandle::Retained { source, contract });
        Ok(())
    }

    /// Resume only the exact retained handle and activated linked contract.
    /// The caller must preserve the profile's zero-or-one result branch and
    /// lower every delivered member using its explicit source projection.
    pub fn resume(
        &self,
        handle: &Handle,
        contract: &'model DeferredYieldContract,
        validity: DeferredValidityEvidence,
        cancellation: &CancellationToken,
    ) -> Result<DeferredYieldObservation<'_, 'model, Source>, DeferredYieldBoundary> {
        if cancellation.is_cancelled() {
            return Err(DeferredYieldBoundary::Cancelled);
        }
        if self.exhausted {
            return Err(DeferredYieldBoundary::HandleBudgetExhausted);
        }
        let (source, retained_contract) = match self.handles.get(handle) {
            Some(RetainedHandle::Retained { source, contract }) => (source, *contract),
            Some(RetainedHandle::Ambiguous) => return Err(DeferredYieldBoundary::AmbiguousHandle),
            Some(RetainedHandle::Invalidated) => return Err(DeferredYieldBoundary::Invalidated),
            None => return Err(DeferredYieldBoundary::UnknownHandle),
        };
        // Same display name, payload, or handle type in another activation is
        // not the selected contract. The exact overlay record must be reused.
        if !std::ptr::eq(contract, retained_contract) {
            return Err(DeferredYieldBoundary::DifferentContract);
        }
        match validity {
            DeferredValidityEvidence::Established => {}
            DeferredValidityEvidence::Unknown => {
                return Err(DeferredYieldBoundary::UnknownValidity);
            }
            DeferredValidityEvidence::Unsupported => {
                return Err(DeferredYieldBoundary::UnsupportedValidity);
            }
        }
        Ok(DeferredYieldObservation { source, contract })
    }

    /// The adapter invokes this for a proven invalidation event. Unknown
    /// mutation/lifetime evidence must instead make resume validity unknown.
    pub fn invalidate(&mut self, handle: &Handle) -> Result<(), DeferredYieldBoundary> {
        let retained = self
            .handles
            .get_mut(handle)
            .ok_or(DeferredYieldBoundary::UnknownHandle)?;
        *retained = RetainedHandle::Invalidated;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic_model::{
        Completeness, SemanticModelActivationProvenance, SemanticModelCompleteness,
        SemanticModelMatchedEvidence, SemanticModelOriginKind, SemanticModelProof,
        SemanticModelProvenance,
    };

    fn contract() -> DeferredYieldContract {
        let payload = serde_json::from_str(include_str!(
            "csmi/profiles/deferred-yield-shared-entry.json"
        ))
        .expect("pinned upstream payload");
        DeferredYieldContract {
            factory: "iter".into(),
            resume: "next".into(),
            handle_type: "Iter".into(),
            payload,
            coverage: Some(Completeness::Complete),
            provenance: SemanticModelProvenance {
                active_model_set_hash: "active".into(),
                pack_digest: "digest".into(),
                pack_id: "test.deferred".into(),
                pack_version: "1.0.0".into(),
                producer: "fixture".into(),
                producer_version: "1.0.0".into(),
                record_id: "iter.next.Iter".into(),
                rule_id: None,
                origin: SemanticModelOriginKind::DependencySource,
                activation: SemanticModelActivationProvenance {
                    status: "active".into(),
                    reason: "test".into(),
                    source_kind: "test".into(),
                    source_id: "fixture".into(),
                    matched_evidence: SemanticModelMatchedEvidence {
                        language: "test".into(),
                        ecosystem: "generic".into(),
                        package: None,
                        module: None,
                        toolchain: None,
                        target: None,
                        configuration: None,
                        artifact_sha256: None,
                    },
                },
                proof: SemanticModelProof::PackFact,
                completeness: SemanticModelCompleteness::Complete,
                ambiguous: false,
            },
        }
    }

    #[test]
    fn construction_and_repeated_resume_preserve_source_and_handle_separation() {
        let contract = contract();
        let cancellation = CancellationToken::default();
        let mut runtime = DeferredYieldRuntime::new(2);
        runtime
            .construct(10, "tainted-map", &contract, &cancellation)
            .unwrap();
        runtime
            .construct(20, "clean-map", &contract, &cancellation)
            .unwrap();
        // Construction returns unit: there is no delivered item before this
        // explicit later resume. Every resume retains its source identity.
        for _ in 0..3 {
            assert_eq!(
                *runtime
                    .resume(
                        &10,
                        &contract,
                        DeferredValidityEvidence::Established,
                        &cancellation
                    )
                    .unwrap()
                    .source,
                "tainted-map"
            );
            assert_eq!(
                *runtime
                    .resume(
                        &20,
                        &contract,
                        DeferredValidityEvidence::Established,
                        &cancellation
                    )
                    .unwrap()
                    .source,
                "clean-map"
            );
        }
        assert_eq!(
            runtime
                .resume(
                    &30,
                    &contract,
                    DeferredValidityEvidence::Established,
                    &cancellation
                )
                .unwrap_err(),
            DeferredYieldBoundary::UnknownHandle
        );
    }

    #[test]
    fn resume_declines_unrelated_contract_unknown_validity_and_invalidation() {
        let contract = contract();
        let unrelated = self::contract();
        let cancellation = CancellationToken::default();
        let mut runtime = DeferredYieldRuntime::new(1);
        runtime
            .construct(10, "map", &contract, &cancellation)
            .unwrap();
        assert_eq!(
            runtime
                .resume(
                    &10,
                    &unrelated,
                    DeferredValidityEvidence::Established,
                    &cancellation
                )
                .unwrap_err(),
            DeferredYieldBoundary::DifferentContract
        );
        for (validity, expected) in [
            (
                DeferredValidityEvidence::Unknown,
                DeferredYieldBoundary::UnknownValidity,
            ),
            (
                DeferredValidityEvidence::Unsupported,
                DeferredYieldBoundary::UnsupportedValidity,
            ),
        ] {
            assert_eq!(
                runtime
                    .resume(&10, &contract, validity, &cancellation)
                    .unwrap_err(),
                expected
            );
        }
        runtime.invalidate(&10).unwrap();
        assert_eq!(
            runtime
                .resume(
                    &10,
                    &contract,
                    DeferredValidityEvidence::Established,
                    &cancellation
                )
                .unwrap_err(),
            DeferredYieldBoundary::Invalidated
        );
    }

    #[test]
    fn duplicate_construction_budget_and_cancellation_never_reuse_complete_state() {
        let contract = contract();
        let cancellation = CancellationToken::default();
        let mut runtime = DeferredYieldRuntime::new(2);
        runtime
            .construct(10, "first", &contract, &cancellation)
            .unwrap();
        assert_eq!(
            runtime.construct(10, "second", &contract, &cancellation),
            Err(DeferredYieldBoundary::AmbiguousHandle)
        );
        assert_eq!(
            runtime
                .resume(
                    &10,
                    &contract,
                    DeferredValidityEvidence::Established,
                    &cancellation
                )
                .unwrap_err(),
            DeferredYieldBoundary::AmbiguousHandle
        );
        let mut bounded = DeferredYieldRuntime::new(1);
        bounded
            .construct(10, "first", &contract, &cancellation)
            .unwrap();
        assert_eq!(
            bounded.construct(20, "second", &contract, &cancellation),
            Err(DeferredYieldBoundary::HandleBudgetExhausted)
        );
        assert_eq!(
            bounded
                .resume(
                    &10,
                    &contract,
                    DeferredValidityEvidence::Established,
                    &cancellation
                )
                .unwrap_err(),
            DeferredYieldBoundary::HandleBudgetExhausted
        );
        cancellation.cancel();
        assert_eq!(
            bounded
                .resume(
                    &10,
                    &contract,
                    DeferredValidityEvidence::Established,
                    &cancellation
                )
                .unwrap_err(),
            DeferredYieldBoundary::Cancelled
        );
    }

    #[test]
    fn incomplete_profile_cannot_establish_a_handle() {
        let mut contract = contract();
        contract.coverage = Some(Completeness::Partial);
        let cancellation = CancellationToken::default();
        let mut runtime = DeferredYieldRuntime::new(1);
        assert_eq!(
            runtime.construct(10, "map", &contract, &cancellation),
            Err(DeferredYieldBoundary::IncompleteContract)
        );
        assert_eq!(
            runtime
                .resume(
                    &10,
                    &contract,
                    DeferredValidityEvidence::Established,
                    &cancellation
                )
                .unwrap_err(),
            DeferredYieldBoundary::UnknownHandle
        );
    }
}
