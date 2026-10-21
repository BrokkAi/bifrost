//! Language-defined JVM parents use ordinary absolute references and hierarchy edges.
use brokk_bifrost_core::analyzer::resolution_facts::*;

/// The producer supplies the synthetic occurrence and language-defined route.
/// The shared publication preserves written parent order after this first edge.
pub(crate) fn publish_implicit_supertype(
    facts: &mut FileResolutionFacts,
    subtype: ResolutionSiteId,
    reference: ResolutionSiteId,
    name: ResolutionNameId,
    prefix: &[ResolutionNameId],
    kind: ResolutionSupertypeKind,
) {
    assert_eq!(
        facts.sites[reference.index()].kind,
        ResolutionSiteKind::SyntheticReference
    );
    facts.identifiers.push(PositionedIdentifierFact {
        site: reference,
        name,
        role: ResolutionIdentifierRole::Reference,
        namespace: ResolutionNamespace::Type,
        qualifier: None,
    });
    facts.reference_owners.push(ResolutionReferenceOwnerFact {
        reference,
        owner: Some(subtype),
    });
    let slot = facts.allocate_type_slot(reference, ResolutionTypeSlotRole::TargetTypeIdentity);
    facts.binding_projections.push(BindingProjectionFact {
        reference,
        output: slot,
        kind: BindingProjectionKind::TargetTypeIdentity,
    });
    facts.root_references.push(ResolutionRootReferenceFact {
        reference,
        root_scope: facts.scopes[0].id,
        anchor: ResolutionRootImportAnchor::Absolute,
        prefix_reference: None,
        owner_continued: false,
    });
    facts
        .root_reference_segments
        .extend(prefix.iter().enumerate().map(|(position, &name)| {
            ResolutionRootReferenceSegmentFact {
                reference,
                position: u32::try_from(position).expect("implicit superclass route fits u32"),
                name,
            }
        }));
    for parent in facts
        .supertypes
        .iter_mut()
        .filter(|parent| parent.subtype == subtype)
    {
        parent.parent_ordinal = parent
            .parent_ordinal
            .checked_add(1)
            .expect("a declaration's parent count fits u32");
    }
    facts.supertypes.push(ResolutionSupertypeFact {
        subtype,
        parent_ordinal: 0,
        supertype_reference: reference,
        supertype_slot: slot,
        kind,
    });
    let route = prefix
        .iter()
        .copied()
        .chain(std::iter::once(name))
        .map(|name| facts.names[name.index()].spelling.as_str());
    if !crate::intrinsics::source_root_hierarchy_is_intrinsic(route) {
        facts.gaps.push(ResolutionGapFact::new(
            reference,
            ResolutionGapKind::UnsupportedHierarchyTraversal,
        ));
    }
}
