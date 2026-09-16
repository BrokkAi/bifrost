//! Language-neutral declaration, relation, and engine-rule rows that do not
//! belong to either the lexical path graph or the typed value-flow graph.

use std::collections::{BTreeMap, BTreeSet};

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::model::CodeUnit;
use brokk_bifrost_core::analyzer::resolution_facts::{
    FileResolutionFacts, PositionedIdentifierFact, ResolutionDeclaredTypeRelationKind,
    ResolutionIdentifierRole, ResolutionMemberAccess, ResolutionMemberKind,
    ResolutionMemberQualifierCompatibility, ResolutionNamespace, ResolutionSiteId,
    ResolutionTypeRelationId,
};
use brokk_bifrost_core::analyzer::structural::resolution::HoistingClass;

use super::fact_lowering::{
    definition_semantic_identity, reference_semantic_identity, scope_head_node_identity,
    type_slot_semantic_identity,
};
use super::local_identity::{ResolutionIdentityCatalogBuilder, ResolutionSemanticIdentity};
use super::model::{BindingNodeId, SemanticId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct LoweredAdditionalDefinitionNamespace {
    pub(crate) definition: SemanticId,
    pub(crate) namespace: ResolutionNamespace,
    pub(crate) hoisting: HoistingClass,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LoweredDefinitionUnitCrosswalk {
    pub(crate) definition: SemanticId,
    pub(crate) unit: CodeUnit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct LoweredDeferredMemberOwner {
    pub(crate) definition: SemanticId,
    pub(crate) owner_frontier: SemanticId,
    pub(crate) kind: ResolutionMemberKind,
    pub(crate) access: ResolutionMemberAccess,
    pub(crate) qualifier_compatibility: ResolutionMemberQualifierCompatibility,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct LoweredDeclaredTypeRelation {
    pub(crate) relation: SemanticId,
    pub(crate) subject_frontier: SemanticId,
    pub(crate) kind: ResolutionDeclaredTypeRelationKind,
    pub(crate) target_reference: Option<SemanticId>,
    pub(crate) target_frontier: Option<SemanticId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct LoweredRelationMember {
    pub(crate) relation: SemanticId,
    pub(crate) position: u32,
    pub(crate) definition: SemanticId,
    pub(crate) kind: ResolutionMemberKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct LoweredDeclaredRootRoute {
    pub(crate) root_scope: BindingNodeId,
    pub(crate) position: u32,
    pub(crate) segment: SemanticId,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LoweredCommonFacts {
    pub(crate) additional_definition_namespaces: Vec<LoweredAdditionalDefinitionNamespace>,
    pub(crate) definition_unit_crosswalks: Vec<LoweredDefinitionUnitCrosswalk>,
    pub(crate) deferred_member_owners: Vec<LoweredDeferredMemberOwner>,
    pub(crate) declared_type_relations: Vec<LoweredDeclaredTypeRelation>,
    pub(crate) relation_members: Vec<LoweredRelationMember>,
    pub(crate) declared_root_routes: Vec<LoweredDeclaredRootRoute>,
}

pub(crate) fn lower_common_resolution_facts(
    identities: &mut ResolutionIdentityCatalogBuilder,
    language: Language,
    facts: &FileResolutionFacts,
) -> LoweredCommonFacts {
    let names = facts
        .names
        .iter()
        .map(|name| (name.id, name.spelling.as_str()))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        names.len(),
        facts.names.len(),
        "resolution names must be unique"
    );
    let identifiers = facts
        .identifiers
        .iter()
        .map(|identifier| (identifier.site, identifier))
        .collect::<BTreeMap<_, _>>();
    let type_slots = facts
        .type_slots
        .iter()
        .map(|slot| slot.id)
        .collect::<BTreeSet<_>>();

    let mut additional_definition_namespaces = facts
        .additional_definition_namespaces
        .iter()
        .map(|fact| {
            assert_ne!(fact.namespace, ResolutionNamespace::TypeOrValue);
            LoweredAdditionalDefinitionNamespace {
                definition: definition_semantic_for_site(
                    &identifiers,
                    identities,
                    fact.declaration,
                ),
                namespace: fact.namespace,
                hoisting: fact.hoisting,
            }
        })
        .collect::<Vec<_>>();
    additional_definition_namespaces.sort_unstable();
    assert!(
        additional_definition_namespaces
            .windows(2)
            .all(|pair| pair[0].definition != pair[1].definition
                || pair[0].namespace != pair[1].namespace)
    );

    let mut definition_unit_crosswalks = facts
        .definition_units
        .iter()
        .map(|fact| LoweredDefinitionUnitCrosswalk {
            definition: definition_semantic_for_site(&identifiers, identities, fact.declaration),
            unit: fact.unit.clone(),
        })
        .collect::<Vec<_>>();
    definition_unit_crosswalks.sort_by_key(|row| row.definition);
    assert!(
        definition_unit_crosswalks
            .windows(2)
            .all(|pair| pair[0].definition != pair[1].definition)
    );
    assert_eq!(
        definition_unit_crosswalks
            .iter()
            .map(|row| &row.unit)
            .collect::<BTreeSet<_>>()
            .len(),
        definition_unit_crosswalks.len(),
        "one parsed unit may map to only one resolution definition"
    );

    let mut deferred_member_owners = facts
        .deferred_member_owners
        .iter()
        .map(|fact| {
            assert!(type_slots.contains(&fact.owner_type));
            LoweredDeferredMemberOwner {
                definition: definition_semantic_for_site(&identifiers, identities, fact.member),
                owner_frontier: identities.semantic(type_slot_semantic_identity(fact.owner_type)),
                kind: fact.kind,
                access: fact.access,
                qualifier_compatibility: fact.qualifier_compatibility,
            }
        })
        .collect::<Vec<_>>();
    deferred_member_owners.sort_unstable();
    assert!(
        deferred_member_owners
            .windows(2)
            .all(|pair| pair[0].definition != pair[1].definition)
    );

    let relation_ids = facts
        .declared_type_relations
        .iter()
        .map(|relation| relation.id)
        .collect::<BTreeSet<_>>();
    assert_eq!(relation_ids.len(), facts.declared_type_relations.len());
    let mut declared_type_relations = facts
        .declared_type_relations
        .iter()
        .map(|fact| {
            assert!(type_slots.contains(&fact.subject));
            let inherent = fact.kind == ResolutionDeclaredTypeRelationKind::InherentImplementation;
            assert_eq!(fact.target_reference.is_none(), inherent);
            assert_eq!(fact.target.is_none(), inherent);
            if let Some(target) = fact.target {
                assert!(type_slots.contains(&target));
            }
            if let Some(reference) = fact.target_reference {
                assert_eq!(
                    identifiers[&reference].role,
                    ResolutionIdentifierRole::Reference
                );
            }
            LoweredDeclaredTypeRelation {
                relation: identities.semantic(type_relation_semantic_identity(fact.id)),
                subject_frontier: identities.semantic(type_slot_semantic_identity(fact.subject)),
                kind: fact.kind,
                target_reference: fact
                    .target_reference
                    .map(|site| identities.semantic(reference_semantic_identity(site))),
                target_frontier: fact
                    .target
                    .map(|slot| identities.semantic(type_slot_semantic_identity(slot))),
            }
        })
        .collect::<Vec<_>>();
    declared_type_relations.sort_unstable();

    let mut relation_members = facts
        .relation_members
        .iter()
        .map(|fact| {
            assert!(relation_ids.contains(&fact.relation));
            LoweredRelationMember {
                relation: identities.semantic(type_relation_semantic_identity(fact.relation)),
                position: fact.ordinal,
                definition: definition_semantic_for_site(&identifiers, identities, fact.member),
                kind: fact.kind,
            }
        })
        .collect::<Vec<_>>();
    relation_members.sort_unstable();
    for members in relation_members.chunk_by(|left, right| left.relation == right.relation) {
        assert!(members.iter().enumerate().all(|(position, member)| {
            usize::try_from(member.position).expect("relation member position must fit usize")
                == position
        }));
    }
    assert_eq!(
        relation_members
            .iter()
            .map(|member| member.definition)
            .collect::<BTreeSet<_>>()
            .len(),
        relation_members.len(),
        "one definition may belong to only one declared type relation"
    );

    let scope_ids = facts
        .scopes
        .iter()
        .map(|scope| scope.id)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        scope_ids.len(),
        facts.scopes.len(),
        "resolution scopes must be unique"
    );
    let package_roots = facts
        .packages
        .iter()
        .map(|package| package.root_scope)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        package_roots.len(),
        facts.packages.len(),
        "one package declaration is allowed per compilation-unit root"
    );
    assert!(
        package_roots.iter().all(|root| scope_ids.contains(root)),
        "every declared package route must name a known root scope"
    );
    assert!(
        facts
            .package_segments
            .iter()
            .all(|segment| package_roots.contains(&segment.root_scope)),
        "every package segment must name a declared package root"
    );
    let mut declared_root_routes = Vec::with_capacity(facts.package_segments.len());
    for &root_scope in &package_roots {
        let mut segments = facts
            .package_segments
            .iter()
            .filter(|segment| segment.root_scope == root_scope)
            .collect::<Vec<_>>();
        segments.sort_unstable_by_key(|segment| segment.ordinal);
        assert!(segments.iter().enumerate().all(|(position, segment)| {
            usize::try_from(segment.ordinal).expect("package segment position must fit usize")
                == position
        }));
        let root_scope = identities.node(scope_head_node_identity(root_scope));
        for segment in segments {
            let spelling = names
                .get(&segment.name)
                .unwrap_or_else(|| panic!("package segment names unknown name {:?}", segment.name));
            declared_root_routes.push(LoweredDeclaredRootRoute {
                root_scope,
                position: segment.ordinal,
                segment: identities.lookup_semantic(language, ResolutionNamespace::Type, spelling),
            });
        }
    }
    declared_root_routes.sort_unstable();
    assert!(
        declared_root_routes
            .windows(2)
            .all(|pair| pair[0] < pair[1]),
        "declared root routes must be unique and canonical"
    );

    LoweredCommonFacts {
        additional_definition_namespaces,
        definition_unit_crosswalks,
        deferred_member_owners,
        declared_type_relations,
        relation_members,
        declared_root_routes,
    }
}

fn type_relation_semantic_identity(
    relation: ResolutionTypeRelationId,
) -> ResolutionSemanticIdentity {
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-type-relation-local:v1");
    hasher.field("relation", &relation.get().to_be_bytes());
    ResolutionSemanticIdentity::fragment_local(hasher.finish())
}

fn definition_semantic_for_site(
    identifiers: &BTreeMap<ResolutionSiteId, &PositionedIdentifierFact>,
    identities: &mut ResolutionIdentityCatalogBuilder,
    site: ResolutionSiteId,
) -> SemanticId {
    let identifier = identifiers
        .get(&site)
        .unwrap_or_else(|| panic!("common resolution row names unknown site {site}"));
    assert_eq!(identifier.role, ResolutionIdentifierRole::Declaration);
    identities.semantic(definition_semantic_identity(site))
}

#[cfg(test)]
mod tests {
    use brokk_bifrost_core::analyzer::ProjectFile;
    use brokk_bifrost_core::analyzer::model::{CodeUnit, CodeUnitType};
    use brokk_bifrost_core::analyzer::resolution_facts::{
        ResolutionAdditionalDefinitionNamespaceFact, ResolutionDeclaredTypeRelationFact,
        ResolutionDeferredMemberOwnerFact, ResolutionDefinitionUnitFact, ResolutionNameFact,
        ResolutionNameId, ResolutionRelationMemberFact, ResolutionTypeSlotFact,
        ResolutionTypeSlotId, ResolutionTypeSlotRole,
    };

    use super::*;
    use crate::analyzer::resolution::BindingFragmentId;

    fn identifier(
        site: u32,
        name: u32,
        role: ResolutionIdentifierRole,
        namespace: ResolutionNamespace,
    ) -> PositionedIdentifierFact {
        PositionedIdentifierFact {
            site: ResolutionSiteId::new(site),
            name: ResolutionNameId::new(name),
            role,
            namespace,
            qualifier: None,
        }
    }

    #[test]
    fn accepted_common_families_lower_to_exact_stable_identities() {
        let unit = CodeUnit::new(
            ProjectFile::new(std::env::temp_dir(), "src/lib.rs"),
            CodeUnitType::Class,
            "crate",
            "Model",
        );
        let facts = FileResolutionFacts {
            names: (0..4)
                .map(|id| ResolutionNameFact {
                    id: ResolutionNameId::new(id),
                    spelling: format!("name{id}"),
                })
                .collect(),
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Type,
                ),
                identifier(
                    1,
                    1,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                ),
                identifier(
                    2,
                    2,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                ),
                identifier(
                    3,
                    3,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                ),
            ],
            additional_definition_namespaces: vec![ResolutionAdditionalDefinitionNamespaceFact {
                declaration: ResolutionSiteId::new(0),
                namespace: ResolutionNamespace::Value,
                hoisting: HoistingClass::ScopeWide,
            }],
            definition_units: vec![ResolutionDefinitionUnitFact {
                declaration: ResolutionSiteId::new(0),
                unit: unit.clone(),
            }],
            type_slots: vec![
                ResolutionTypeSlotFact {
                    id: ResolutionTypeSlotId::new(0),
                    site: ResolutionSiteId::new(0),
                    role: ResolutionTypeSlotRole::TargetTypeIdentity,
                },
                ResolutionTypeSlotFact {
                    id: ResolutionTypeSlotId::new(1),
                    site: ResolutionSiteId::new(3),
                    role: ResolutionTypeSlotRole::TargetTypeIdentity,
                },
            ],
            deferred_member_owners: vec![ResolutionDeferredMemberOwnerFact {
                member: ResolutionSiteId::new(1),
                owner_type: ResolutionTypeSlotId::new(1),
                kind: ResolutionMemberKind::Method,
                access: ResolutionMemberAccess::Instance,
                qualifier_compatibility: ResolutionMemberQualifierCompatibility::RuntimeOnly,
            }],
            declared_type_relations: vec![ResolutionDeclaredTypeRelationFact {
                id: ResolutionTypeRelationId::new(0),
                subject: ResolutionTypeSlotId::new(0),
                kind: ResolutionDeclaredTypeRelationKind::TraitImplementation,
                target_reference: Some(ResolutionSiteId::new(3)),
                target: Some(ResolutionTypeSlotId::new(1)),
            }],
            relation_members: vec![ResolutionRelationMemberFact {
                relation: ResolutionTypeRelationId::new(0),
                ordinal: 0,
                member: ResolutionSiteId::new(2),
                kind: ResolutionMemberKind::AssociatedType,
            }],
            scopes: vec![brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeFact {
                id: brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId::new(0),
                parent: None, owner: None,
                kind: brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeKind::CompilationUnit,
                start_byte: 0, end_byte: 100,
            }],
            packages: vec![brokk_bifrost_core::analyzer::resolution_facts::ResolutionPackageFact {
                root_scope: brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId::new(0),
                declaration: None, placement_gap_site: ResolutionSiteId::new(3),
            }],
            package_segments: vec![brokk_bifrost_core::analyzer::resolution_facts::ResolutionPackageSegmentFact {
                root_scope: brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId::new(0),
                ordinal: 0, name: ResolutionNameId::new(0),
            }],
            ..FileResolutionFacts::default()
        };
        let mut identities =
            ResolutionIdentityCatalogBuilder::new(BindingFragmentId::from_digest([7; 32]));
        let lowered = lower_common_resolution_facts(&mut identities, Language::Rust, &facts);

        assert_eq!(lowered.additional_definition_namespaces.len(), 1);
        assert_eq!(lowered.definition_unit_crosswalks[0].unit, unit);
        assert_eq!(lowered.deferred_member_owners.len(), 1);
        assert_eq!(lowered.declared_type_relations.len(), 1);
        assert_eq!(lowered.relation_members.len(), 1);
        assert_eq!(lowered.declared_root_routes.len(), 1);
        let expected_root = identities.node(scope_head_node_identity(
            brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId::new(0),
        ));
        let expected_segment =
            identities.lookup_semantic(Language::Rust, ResolutionNamespace::Type, "name0");
        assert_eq!(
            lowered.declared_root_routes[0],
            LoweredDeclaredRootRoute {
                root_scope: expected_root,
                position: 0,
                segment: expected_segment,
            }
        );
        assert_eq!(
            lowered.relation_members[0].kind,
            ResolutionMemberKind::AssociatedType
        );
    }
}
