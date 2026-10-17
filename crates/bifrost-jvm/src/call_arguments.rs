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

/// Accumulate a JVM bound identity into the common multi-input producer family.
pub(crate) fn publish_jvm_type_union_transfer(
    facts: &mut FileResolutionFacts,
    input: ResolutionTypeSlotId,
    output: ResolutionTypeSlotId,
) {
    assert_ne!(input, output);
    facts.type_transfers.push(ResolutionTypeTransferFact::new(
        input,
        output,
        ResolutionTypeTransferKind::TypeUnion,
        0,
        0,
        ResolutionTypeTransferValueTransform::Preserve,
    ));
}

/// Retain ordered function type identities and their runtime projections.
/// Grammar hooks supply ordered identity slots; shared application consumes
/// the same type-argument rows for Scala FunctionN and Kotlin FunctionN.
pub(crate) fn publish_jvm_function_type_arguments(
    facts: &mut FileResolutionFacts,
    owner: ResolutionTypeSlotId,
    arguments: &[ResolutionTypeSlotId],
) {
    let site = facts.type_slots[owner.index()].site;
    for (ordinal, &input) in arguments.iter().enumerate() {
        // Each position owns an identity frontier and its runtime projection.
        // Keeping that identity separate prevents a declaration initializer
        // from adding values to the intrinsic member's formal/result slots.
        let identity = facts.allocate_type_slot(site, ResolutionTypeSlotRole::TargetTypeIdentity);
        facts.type_transfers.push(ResolutionTypeTransferFact::new(
            input,
            identity,
            ResolutionTypeTransferKind::TypeIdentity,
            0,
            0,
            ResolutionTypeTransferValueTransform::Preserve,
        ));
        let value = facts.allocate_type_slot(site, ResolutionTypeSlotRole::DeclaredValue);
        publish_jvm_declared_type_transfer(
            facts,
            identity,
            value,
            ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
        );
        facts.type_arguments.push(
            brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeArgumentFact {
                application: owner,
                ordinal: u32::try_from(ordinal).expect("function type argument count fits u32"),
                argument: identity,
                indirection_delta: 0,
                reference_indirection_delta: 0,
            },
        );
    }
}
