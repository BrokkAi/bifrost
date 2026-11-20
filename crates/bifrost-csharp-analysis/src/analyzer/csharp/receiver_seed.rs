//! C# current-instance rule over the shared selected application proof.
use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::resolution::{
    ConditionalTypeSeed, ConditionalTypeSeedContext, ConditionalTypeSeedRead, ResolutionCompletion,
    ResolutionSlotValue, ResolutionTypeRef, SemanticId,
};
use brokk_bifrost_analysis::analyzer::store::Result;

pub(super) fn seed(
    slot: SemanticId,
    context: &ConditionalTypeSeedContext<'_>,
    cancellation: &CancellationToken,
) -> Result<ConditionalTypeSeedRead> {
    if cancellation.is_cancelled() {
        return Ok(context.cancelled(slot));
    }
    let proof = context.owner_application(slot, cancellation)?;
    let inputs = proof.observation;
    if inputs.outcome.is_cancelled() {
        let ConditionalTypeSeedRead::Open { completion, .. } = context.cancelled(slot) else {
            unreachable!()
        };
        return Ok(ConditionalTypeSeedRead::Open {
            slot,
            completion: completion.combine(inputs.outcome.evidence()),
        });
    }
    if !inputs.outcome.is_exhausted() {
        let ConditionalTypeSeedRead::Open { completion, .. } = context.open(
            slot,
            "csharp_receiver_source_read_open",
            "The exact source owner application read did not exhaust",
        ) else {
            unreachable!()
        };
        return Ok(ConditionalTypeSeedRead::Open {
            slot,
            completion: completion.combine(inputs.outcome.evidence()),
        });
    }
    if inputs.outcome.evidence() != &ResolutionCompletion::Complete {
        return Ok(ConditionalTypeSeedRead::Open {
            slot,
            completion: inputs.outcome.evidence().clone(),
        });
    }
    if inputs.ambiguous_application {
        return Ok(context.open(
            slot,
            "csharp_receiver_owner_ambiguous",
            "The selected application slot has multiple exact owner properties",
        ));
    }
    if inputs.unsupported_implicit_receiver {
        return Ok(context.open(
            slot,
            "csharp_unsupported_generic_owner",
            "missing enclosing-owner application qualifier / outer-instantiation relation",
        ));
    }
    let Some(application) = inputs.application else {
        // Super/base, static-invalid receivers and unrelated slots have no
        // immediate seed. Their authored gaps remain on the ordinary paths.
        return Ok(ConditionalTypeSeedRead::NotProvided);
    };
    let Some(receipt) = proof.usable_receipt.as_ref() else {
        return Ok(context.open(
            slot,
            "csharp_receiver_source_read_open",
            "The exact source owner application has no usable read receipt",
        ));
    };
    if application.partial != Some(false) {
        return Ok(context.open(
            slot,
            "csharp_receiver_partial_owner",
            "The exact owner is partial or has no complete source modifier evidence",
        ));
    }
    if !application.complete_positions {
        return Ok(context.open(slot, "csharp_receiver_owner_arguments_open", "The exact source owner application has incomplete positional formal or argument evidence"));
    }
    Ok(ready_owner_type_object(slot, application.owner, receipt))
}

fn ready_owner_type_object(
    slot: SemanticId,
    owner: SemanticId,
    _receipt: &brokk_bifrost_analysis::analyzer::resolution::fact_source::UsableReceiverProofReceipt,
) -> ConditionalTypeSeedRead {
    ConditionalTypeSeedRead::Ready(ConditionalTypeSeed {
        slot,
        value: ResolutionSlotValue::type_object(ResolutionTypeRef::new(owner, 0)),
        prerequisites: Vec::new(),
        discharged_gap_reasons: Vec::new(),
    })
}
