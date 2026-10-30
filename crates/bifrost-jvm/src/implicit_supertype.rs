//! Language-defined JVM parents use ordinary absolute references and hierarchy edges.
use brokk_bifrost_core::analyzer::resolution_facts::*;
use brokk_bifrost_core::hash::{HashMap, HashSet};

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

/// A non-nominal alias RHS, such as a function type, can legitimately have no
/// positioned terminal name. Only alias publication may skip such a site.
pub(crate) fn publish_alias_supertype_name(
    facts: &mut FileResolutionFacts,
    site: ResolutionSiteId,
) {
    if facts
        .identifiers
        .iter()
        .any(|identifier| identifier.site == site)
    {
        facts.name_lookups.push(ResolutionNameLookupFact {
            site,
            kind: ResolutionNameLookupKind::SupertypeName,
        });
    }
}

pub(crate) fn publish_written_supertype_names(facts: &mut FileResolutionFacts) {
    // These indexes belong to this file's publication call, never the workspace.
    let mut names_by_site = HashMap::default();
    let mut sites_by_name = HashMap::default();
    for identifier in &facts.identifiers {
        names_by_site.insert(identifier.site, identifier.name);
        sites_by_name
            .entry(identifier.name)
            .or_insert(identifier.site);
    }
    for edge in &facts.supertypes {
        let site = edge.supertype_reference;
        let kind = facts.sites[site.index()].kind;
        if kind == ResolutionSiteKind::SyntheticReference {
            continue;
        }
        assert!(
            names_by_site.contains_key(&site),
            "written supertype site {site:?} of kind {kind:?} must have a positioned identifier"
        );
        facts.name_lookups.push(ResolutionNameLookupFact {
            site,
            kind: ResolutionNameLookupKind::SupertypeName,
        });
    }
    let supertype_names = facts
        .name_lookups
        .iter()
        .filter(|lookup| lookup.kind == ResolutionNameLookupKind::SupertypeName)
        .map(|lookup| names_by_site[&lookup.site])
        .collect::<HashSet<_>>();
    for selector in &facts.import_selectors {
        let (Some(local), Some(source)) = (selector.local_name, selector.source_name) else {
            continue;
        };
        if source == local || !supertype_names.contains(&local) {
            continue;
        }
        let site = if names_by_site.get(&selector.site) == Some(&source) {
            selector.site
        } else {
            // Import selectors currently carry names and a whole-selector site,
            // not a separate source-name site. Keep the name-only candidate key
            // using the indexed positioned identifier when that site is absent.
            *sites_by_name
                .get(&source)
                .expect("a renamed import retains its source identifier")
        };
        facts.name_lookups.push(ResolutionNameLookupFact {
            site,
            kind: ResolutionNameLookupKind::SupertypeName,
        });
    }
}
