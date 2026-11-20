//! C# structural locator for a `base` receiver. Intent only: the shared
//! evaluator must still consume both receipt-backed source proofs before any
//! request exists (#11894).
use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::resolution::SemanticId;
use brokk_bifrost_analysis::analyzer::resolution::fact_source::{
    DeferredBaseReceiverIntentRead, DeferredBaseReceiverIntentReader,
};
use brokk_bifrost_analysis::analyzer::store::Result;
use brokk_bifrost_core::analyzer::resolution_facts::{
    ResolutionCallableReceiverOrigin, ResolutionSiteKind,
};

/// A candidate is a C# base receiver exactly when its recorded reference site
/// is a member reference whose producer marked the receiver origin `Super`.
/// No source text is consulted.
pub(super) fn intent(
    slot: SemanticId,
    reader: &dyn DeferredBaseReceiverIntentReader,
    cancellation: &CancellationToken,
) -> Result<DeferredBaseReceiverIntentRead> {
    let read = reader.candidates(slot, cancellation)?;
    Ok(read.unique_intent(slot, |candidate| {
        candidate.metadata.is_some_and(|metadata| {
            metadata.site_kind() == ResolutionSiteKind::MemberReference
                && metadata.receiver_origin() == Some(ResolutionCallableReceiverOrigin::Super)
        })
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_analysis::analyzer::resolution::fact_source::{
        DeferredBaseReceiverCandidate, DeferredBaseReceiverCandidatesRead,
        TypedFactInventoryEvidence, TypedFactReadOutcome,
    };
    use brokk_bifrost_analysis::analyzer::resolution::{
        FactReferenceSiteMetadata, ResolutionCompletion,
    };
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;

    struct Fixed(Vec<Option<FactReferenceSiteMetadata>>, SemanticId);
    impl DeferredBaseReceiverIntentReader for Fixed {
        fn candidates(
            &self,
            slot: SemanticId,
            _: &CancellationToken,
        ) -> Result<DeferredBaseReceiverCandidatesRead> {
            Ok(DeferredBaseReceiverCandidatesRead {
                candidates: self
                    .0
                    .iter()
                    .map(|metadata| DeferredBaseReceiverCandidate {
                        receiver_slot: slot,
                        source_reference: self.1,
                        namespace: ResolutionNamespace::Callable,
                        metadata: *metadata,
                    })
                    .collect(),
                outcome: TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
                    .with_inventory_evidence(TypedFactInventoryEvidence::Established(
                        ResolutionCompletion::Complete,
                    )),
            })
        }
    }

    fn site(origin: Option<ResolutionCallableReceiverOrigin>) -> Option<FactReferenceSiteMetadata> {
        Some(FactReferenceSiteMetadata::for_hook_test(
            ResolutionNamespace::Callable,
            ResolutionSiteKind::MemberReference,
            false,
            origin,
        ))
    }

    /// Grammar-boundary pin: only the structural `Super` origin selects base;
    /// `this`, plain qualified receivers and mixed arms never do.
    #[test]
    fn only_the_super_origin_selects_a_base_receiver() {
        let slot = SemanticId::for_test(b"cs-base-slot");
        let reference = SemanticId::for_test(b"cs-base-reference");
        let cancellation = CancellationToken::new();
        let read = |rows: Vec<Option<FactReferenceSiteMetadata>>| {
            intent(slot, &Fixed(rows, reference), &cancellation).unwrap()
        };
        let super_site = site(Some(ResolutionCallableReceiverOrigin::Super));
        assert_eq!(
            read(vec![super_site, super_site]),
            DeferredBaseReceiverIntentRead::Intent {
                receiver_slot: slot,
                source_reference: reference,
            }
        );
        for rejected in [
            site(Some(ResolutionCallableReceiverOrigin::CurrentInstance)),
            site(None),
        ] {
            assert_eq!(
                read(vec![rejected]),
                DeferredBaseReceiverIntentRead::NotProvided
            );
        }
        assert!(matches!(
            read(vec![super_site, site(None)]),
            DeferredBaseReceiverIntentRead::Open { .. }
        ));
        assert!(matches!(
            read(vec![super_site, None]),
            DeferredBaseReceiverIntentRead::Open { .. }
        ));
    }
}
