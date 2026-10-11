//! Shared JVM call-argument fact publication.

use brokk_bifrost_core::analyzer::resolution_facts::{
    FileResolutionFacts, ResolutionCallArgumentFact, ResolutionNameId, ResolutionSiteId,
    ResolutionTypeSlotId, ResolutionTypeSlotRole, ResolutionTypeTransferFact,
    ResolutionTypeTransferKind, ResolutionTypeTransferValueTransform,
};

/// Publish the call-owned argument state and its expression transfer.
///
/// A language may leave `input` empty when its producer cannot yet represent
/// that argument expression. Java and Kotlin provide every expression slot;
/// Scala supplies one when its grammar hook identifies a selected call result.
pub(crate) fn publish_jvm_call_argument(
    facts: &mut FileResolutionFacts,
    call: ResolutionSiteId,
    list_ordinal: u32,
    ordinal: u32,
    input: Option<ResolutionTypeSlotId>,
    label: Option<ResolutionNameId>,
) -> ResolutionTypeSlotId {
    let value = facts.allocate_type_slot(call, ResolutionTypeSlotRole::Argument);
    if let Some(input) = input {
        facts.type_transfers.push(ResolutionTypeTransferFact::new(
            input,
            value,
            ResolutionTypeTransferKind::Argument,
            0,
            0,
            ResolutionTypeTransferValueTransform::Preserve,
        ));
    }
    facts.call_arguments.push(ResolutionCallArgumentFact {
        call,
        list_ordinal,
        ordinal,
        value,
        label,
    });
    value
}

/// Publish the common transfer from a written JVM declaration type into its
/// runtime value slot.
pub(crate) fn publish_jvm_declared_type_transfer(
    facts: &mut FileResolutionFacts,
    input: ResolutionTypeSlotId,
    output: ResolutionTypeSlotId,
    value_transform: ResolutionTypeTransferValueTransform,
) {
    assert_ne!(input, output);
    facts.type_transfers.push(ResolutionTypeTransferFact::new(
        input,
        output,
        ResolutionTypeTransferKind::DeclaredType,
        0,
        0,
        value_transform,
    ));
}
