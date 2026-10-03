//! Language-neutral declaration, relation, and engine-rule rows that do not
//! belong to either the lexical path graph or the typed value-flow graph.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::model::CodeUnit;
use brokk_bifrost_core::analyzer::resolution_facts::{
    FileResolutionFacts, PositionedIdentifierFact, ResolutionDeclaredTypeRelationKind,
    ResolutionIdentifierRole, ResolutionImportRouteKind, ResolutionMemberAccess,
    ResolutionMemberKind, ResolutionMemberQualifierCompatibility, ResolutionNameId,
    ResolutionNamespace, ResolutionSiteId, ResolutionTypeRelationId,
};
use brokk_bifrost_core::analyzer::structural::resolution::HoistingClass;

use super::fact_lowering::package::{
    LoweredGoPackageImport, LoweredPackageMember, LoweredPackageReference,
};
use super::fact_lowering::{
    definition_semantic_identity, reference_semantic_identity, root_import_token_identity,
    scope_head_node_identity, type_slot_semantic_identity,
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
pub struct LoweredDeferredMemberOwner {
    pub(crate) definition: SemanticId,
    pub(crate) owner_frontier: SemanticId,
    hierarchy_frontier: Option<SemanticId>,
    pub(crate) lookup: SemanticId,
    pub(crate) kind: ResolutionMemberKind,
    pub(crate) access: ResolutionMemberAccess,
    pub(crate) qualifier_compatibility: ResolutionMemberQualifierCompatibility,
}

pub(crate) fn member_hierarchy_frontiers(
    facts: &FileResolutionFacts,
) -> HashMap<ResolutionSiteId, brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeSlotId>
{
    let relations = facts
        .declared_type_relations
        .iter()
        .map(|relation| (relation.id, relation))
        .collect::<HashMap<_, _>>();
    facts
        .relation_members
        .iter()
        .filter_map(|member| {
            let relation = relations[&member.relation];
            relation.target.map(|target| (member.member, target))
        })
        .collect()
}

pub(crate) const fn member_lookup_namespace(kind: ResolutionMemberKind) -> ResolutionNamespace {
    match kind {
        ResolutionMemberKind::NestedType | ResolutionMemberKind::AssociatedType => {
            ResolutionNamespace::Type
        }
        ResolutionMemberKind::Method => ResolutionNamespace::Callable,
        ResolutionMemberKind::Constructor => ResolutionNamespace::Constructor,
        ResolutionMemberKind::Field => ResolutionNamespace::Value,
    }
}

impl LoweredDeferredMemberOwner {
    pub const fn new(
        definition: SemanticId,
        owner_frontier: SemanticId,
        lookup: SemanticId,
        kind: ResolutionMemberKind,
        access: ResolutionMemberAccess,
        qualifier_compatibility: ResolutionMemberQualifierCompatibility,
    ) -> Self {
        Self {
            definition,
            owner_frontier,
            hierarchy_frontier: None,
            lookup,
            kind,
            access,
            qualifier_compatibility,
        }
    }

    pub const fn hierarchy_frontier(&self) -> Option<SemanticId> {
        self.hierarchy_frontier
    }

    pub const fn with_hierarchy_frontier(mut self, frontier: Option<SemanticId>) -> Self {
        self.hierarchy_frontier = frontier;
        self
    }

    pub const fn definition(&self) -> SemanticId {
        self.definition
    }

    pub const fn owner_frontier(&self) -> SemanticId {
        self.owner_frontier
    }

    pub const fn lookup(&self) -> SemanticId {
        self.lookup
    }

    pub const fn kind(&self) -> ResolutionMemberKind {
        self.kind
    }

    pub const fn access(&self) -> ResolutionMemberAccess {
        self.access
    }

    pub const fn qualifier_compatibility(&self) -> ResolutionMemberQualifierCompatibility {
        self.qualifier_compatibility
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LoweredReferenceLookupIdentity {
    /// The qualified terminal reference that owns the stored root route.
    pub(crate) reference: SemanticId,
    /// The Type lookup identity of the route's first prefix segment.
    pub(crate) lookup: SemanticId,
}

/// One side of an `impl Trait for Type` header, as the path it spells.
///
/// `segments` is the module path written before the head nominal name, in
/// source order and empty for a bare name; `terminal` is that head name. A
/// generic argument list is not part of the head, so `Wrapper<T>` spells
/// `Wrapper`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct LoweredImplHeaderPath {
    pub(crate) segments: Vec<SemanticId>,
    pub(crate) terminal: SemanticId,
}

/// One `impl Trait for Type`, in the shape build-time crate derivation reads.
///
/// The relation fact names type slots and reference sites, not spellings, and
/// the spelling is what a crate derivation has to walk: the subject and the
/// trait may be declared in two other blobs of the same crate, so resolving
/// them is a cross-blob question and its inputs are a persisted row. The
/// spellings come from the producer's own route facts and never from source
/// text: a scoped path publishes its module segments as root-reference
/// segments on its terminal reference, and a bare name publishes none, which
/// is the empty module path the derivation walks from the impl's own module.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct LoweredTraitImplementation {
    pub(crate) relation: SemanticId,
    pub(crate) subject: LoweredImplHeaderPath,
    pub(crate) implemented_trait: LoweredImplHeaderPath,
    /// The subject type reference's source site: the `Foo` of `impl T for Foo`.
    pub(crate) impl_site: u32,
    pub(crate) impl_start_byte: usize,
    pub(crate) impl_end_byte: usize,
}

/// Source-owned provenance for an actual emitted import token. The token may
/// be remounted; its source site, interval and structured route kind may not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct LoweredRootImportProvenance {
    pub(crate) token: SemanticId,
    pub(crate) source_site: ResolutionSiteId,
    pub(crate) start_byte: usize,
    pub(crate) end_byte: usize,
    pub(crate) kind: ResolutionImportRouteKind,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LoweredCommonFacts {
    pub(crate) additional_definition_namespaces: Vec<LoweredAdditionalDefinitionNamespace>,
    pub(crate) definition_unit_crosswalks: Vec<LoweredDefinitionUnitCrosswalk>,
    pub(crate) deferred_member_owners: Vec<LoweredDeferredMemberOwner>,
    pub(crate) declared_type_relations: Vec<LoweredDeclaredTypeRelation>,
    pub(crate) relation_members: Vec<LoweredRelationMember>,
    pub(crate) declared_root_routes: Vec<LoweredDeclaredRootRoute>,
    pub(crate) root_import_provenance: Vec<LoweredRootImportProvenance>,
    pub(crate) package_references: Vec<LoweredPackageReference>,
    pub(crate) package_members: Vec<LoweredPackageMember>,
    pub(crate) go_package_imports: Vec<LoweredGoPackageImport>,
    pub(crate) reference_lookup_identities: Vec<LoweredReferenceLookupIdentity>,
    pub(crate) trait_implementations: Vec<LoweredTraitImplementation>,
}

impl LoweredCommonFacts {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        mut additional_definition_namespaces: Vec<LoweredAdditionalDefinitionNamespace>,
        mut definition_unit_crosswalks: Vec<LoweredDefinitionUnitCrosswalk>,
        mut deferred_member_owners: Vec<LoweredDeferredMemberOwner>,
        mut declared_type_relations: Vec<LoweredDeclaredTypeRelation>,
        mut relation_members: Vec<LoweredRelationMember>,
        mut declared_root_routes: Vec<LoweredDeclaredRootRoute>,
        mut root_import_provenance: Vec<LoweredRootImportProvenance>,
        mut package_references: Vec<LoweredPackageReference>,
        mut package_members: Vec<LoweredPackageMember>,
        mut go_package_imports: Vec<LoweredGoPackageImport>,
        mut reference_lookup_identities: Vec<LoweredReferenceLookupIdentity>,
        mut trait_implementations: Vec<LoweredTraitImplementation>,
    ) -> Self {
        additional_definition_namespaces.sort_unstable();
        assert!(
            additional_definition_namespaces
                .windows(2)
                .all(|pair| pair[0].definition != pair[1].definition
                    || pair[0].namespace != pair[1].namespace)
        );

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

        deferred_member_owners.sort_unstable();
        assert!(
            deferred_member_owners
                .windows(2)
                .all(|pair| pair[0].definition != pair[1].definition)
        );

        declared_type_relations.sort_unstable();
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

        declared_root_routes.sort_unstable();
        assert!(
            declared_root_routes
                .windows(2)
                .all(|pair| pair[0] < pair[1]),
            "declared root routes must be unique and canonical"
        );

        reference_lookup_identities.sort_unstable_by_key(|row| row.reference);
        assert!(
            reference_lookup_identities
                .windows(2)
                .all(|pair| pair[0].reference != pair[1].reference),
            "one root lookup identity per source reference is required"
        );

        trait_implementations.sort_unstable();
        assert!(
            trait_implementations
                .windows(2)
                .all(|pair| pair[0].relation != pair[1].relation),
            "one declared type relation lowers to one trait implementation"
        );

        root_import_provenance.sort_unstable();
        assert!(
            root_import_provenance
                .windows(2)
                .all(|pair| pair[0].token != pair[1].token),
            "one source provenance row per actual import token"
        );
        assert!(
            root_import_provenance
                .iter()
                .all(|row| row.start_byte <= row.end_byte)
        );

        package_references.sort_unstable();
        assert!(
            package_references
                .windows(2)
                .all(|rows| rows[0].token != rows[1].token)
        );
        package_members.sort_unstable();
        assert!(
            package_members
                .windows(2)
                .all(|rows| (rows[0].token, rows[0].definition)
                    != (rows[1].token, rows[1].definition))
        );
        go_package_imports.sort_unstable();
        assert!(
            go_package_imports
                .windows(2)
                .all(|rows| rows[0].definition != rows[1].definition)
        );
        assert!(
            go_package_imports
                .iter()
                .all(|row| row.start_byte <= row.end_byte)
        );
        Self {
            additional_definition_namespaces,
            definition_unit_crosswalks,
            deferred_member_owners,
            declared_type_relations,
            relation_members,
            declared_root_routes,
            root_import_provenance,
            package_references,
            package_members,
            go_package_imports,
            reference_lookup_identities,
            trait_implementations,
        }
    }
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

    let additional_definition_namespaces = facts
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
    let definition_unit_crosswalks = facts
        .definition_units
        .iter()
        .map(|fact| LoweredDefinitionUnitCrosswalk {
            definition: definition_semantic_for_site(&identifiers, identities, fact.declaration),
            unit: fact.unit.clone(),
        })
        .collect::<Vec<_>>();
    let hierarchy_by_member = member_hierarchy_frontiers(facts);
    let deferred_member_owners = facts
        .deferred_member_owners
        .iter()
        .map(|fact| {
            assert!(type_slots.contains(&fact.owner_type));
            LoweredDeferredMemberOwner {
                definition: definition_semantic_for_site(&identifiers, identities, fact.member),
                owner_frontier: identities.semantic(type_slot_semantic_identity(fact.owner_type)),
                hierarchy_frontier: hierarchy_by_member
                    .get(&fact.member)
                    .map(|&slot| identities.semantic(type_slot_semantic_identity(slot))),
                lookup: identities.lookup_semantic(
                    language,
                    member_lookup_namespace(fact.kind),
                    names[&identifiers[&fact.member].name],
                ),
                kind: fact.kind,
                access: fact.access,
                qualifier_compatibility: fact.qualifier_compatibility,
            }
        })
        .collect::<Vec<_>>();
    let relation_ids = facts
        .declared_type_relations
        .iter()
        .map(|relation| relation.id)
        .collect::<BTreeSet<_>>();
    assert_eq!(relation_ids.len(), facts.declared_type_relations.len());
    let declared_type_relations = facts
        .declared_type_relations
        .iter()
        .map(|fact| {
            assert!(type_slots.contains(&fact.subject));
            let inherent = fact.kind == ResolutionDeclaredTypeRelationKind::InherentImplementation;
            assert_eq!(
                fact.target_reference.is_none(),
                inherent || fact.kind == ResolutionDeclaredTypeRelationKind::UnderlyingType,
                "underlying-type relations target a typed slot without a name reference"
            );
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
                    .map(|site| identities.source_reference_semantic(site)),
                target_frontier: fact
                    .target
                    .map(|slot| identities.semantic(type_slot_semantic_identity(slot))),
            }
        })
        .collect::<Vec<_>>();
    let relation_members = facts
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
        let root_scope = identities.source_scope_node(root_scope);
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
    let slot_sites = facts
        .type_slots
        .iter()
        .map(|slot| (slot.id, slot.site))
        .collect::<BTreeMap<_, _>>();
    let site_spans = facts
        .sites
        .iter()
        .map(|site| (site.id, (site.start_byte, site.end_byte)))
        .collect::<BTreeMap<_, _>>();
    let root_reference_prefixes = facts
        .root_references
        .iter()
        .map(|route| (route.reference, route.prefix_reference))
        .collect::<BTreeMap<_, _>>();
    let mut root_reference_spellings =
        BTreeMap::<ResolutionSiteId, BTreeMap<u32, ResolutionNameId>>::new();
    for segment in &facts.root_reference_segments {
        assert!(
            root_reference_spellings
                .entry(segment.reference)
                .or_default()
                .insert(segment.position, segment.name)
                .is_none(),
            "one root reference route holds one segment per position"
        );
    }
    // Only Rust reverse resolution reads these rows (rust_reverse_rows.rs), so
    // other languages publish none. Other languages' root route prefixes also
    // use other namespaces, such as Go's TypeOrValue.
    let mut reference_lookup_identities = Vec::new();
    let rust_root_references = if language == Language::Rust {
        facts.root_references.as_slice()
    } else {
        &[]
    };
    for route in rust_root_references {
        let Some(prefix_reference) = route.prefix_reference else {
            continue;
        };
        let prefix = identifiers
            .get(&prefix_reference)
            .expect("root route prefix has a positioned identifier");
        assert_eq!(
            prefix.namespace,
            ResolutionNamespace::Type,
            "root route prefix lookup uses the Type namespace"
        );
        let prefix_name = names
            .get(&prefix.name)
            .unwrap_or_else(|| panic!("root route prefix names unknown name {:?}", prefix.name));
        assert_eq!(
            root_reference_spellings
                .get(&route.reference)
                .and_then(|segments| segments.get(&0)),
            Some(&prefix.name),
            "root route prefix spelling agrees with its first structured segment"
        );
        reference_lookup_identities.push(LoweredReferenceLookupIdentity {
            reference: identities.source_reference_semantic(route.reference),
            lookup: identities.lookup_semantic(language, prefix.namespace, prefix_name),
        });
    }
    let mut trait_implementations = Vec::new();
    for fact in &facts.declared_type_relations {
        if fact.kind != ResolutionDeclaredTypeRelationKind::TraitImplementation {
            continue;
        }
        let subject_site = slot_sites[&fact.subject];
        let trait_site = fact
            .target_reference
            .expect("a trait implementation retains its trait reference");
        // A subject or trait the producer lowered without a positioned
        // identifier has no nominal path to walk: a generic parameter, a
        // primitive seed or unsupported type syntax. It keeps the gap the
        // producer already published and contributes no row.
        let Some(subject) = spelled_impl_header_path(
            subject_site,
            &identifiers,
            &names,
            &root_reference_prefixes,
            &root_reference_spellings,
            identities,
            language,
        ) else {
            continue;
        };
        let Some(implemented_trait) = spelled_impl_header_path(
            trait_site,
            &identifiers,
            &names,
            &root_reference_prefixes,
            &root_reference_spellings,
            identities,
            language,
        ) else {
            continue;
        };
        let (start_byte, end_byte) = site_spans[&subject_site];
        trait_implementations.push(LoweredTraitImplementation {
            relation: identities.semantic(type_relation_semantic_identity(fact.id)),
            subject,
            implemented_trait,
            impl_site: subject_site.get(),
            impl_start_byte: start_byte,
            impl_end_byte: end_byte,
        });
    }
    let routes_by_site = facts
        .import_routes
        .iter()
        .map(|route| (route.site, route))
        .collect::<HashMap<_, _>>();
    let mut import_tokens = BTreeSet::new();
    let mut root_import_provenance = Vec::new();
    for demand in &facts.root_import_demands {
        let Some(route) = routes_by_site.get(&demand.import_site) else {
            // Languages without structured route facts make no route-kind claim.
            continue;
        };
        if !import_tokens.insert((demand.import_site, demand.namespace)) {
            continue;
        }
        let (start_byte, end_byte) = site_spans[&demand.import_site];
        root_import_provenance.push(LoweredRootImportProvenance {
            token: identities.semantic(root_import_token_identity(
                demand.import_site,
                demand.namespace,
            )),
            source_site: demand.import_site,
            start_byte,
            end_byte,
            kind: route.kind,
        });
    }
    let (package_references, package_members) =
        super::fact_lowering::package::lower_metadata(identities, language, facts);
    let go_package_imports =
        super::fact_lowering::package::lower_import_metadata(identities, language, facts);
    LoweredCommonFacts::new(
        additional_definition_namespaces,
        definition_unit_crosswalks,
        deferred_member_owners,
        declared_type_relations,
        relation_members,
        declared_root_routes,
        root_import_provenance,
        package_references,
        package_members,
        go_package_imports,
        reference_lookup_identities,
        trait_implementations,
    )
}

/// The module path and head nominal name one impl-header reference spells.
///
/// A scoped path's terminal reference carries the module segments written
/// before it. A bare qualified path (`a::b::Foo`) instead anchors on a prefix
/// reference that carries the segments before *it*, so the full path is the
/// prefix chain's segments followed by this reference's own. The producer
/// gives a prefix reference no prefix of its own, so the chain is one deep;
/// the bound below states that rather than trusting it.
fn spelled_impl_header_path(
    reference: ResolutionSiteId,
    identifiers: &BTreeMap<ResolutionSiteId, &PositionedIdentifierFact>,
    names: &BTreeMap<ResolutionNameId, &str>,
    prefixes: &BTreeMap<ResolutionSiteId, Option<ResolutionSiteId>>,
    spellings: &BTreeMap<ResolutionSiteId, BTreeMap<u32, ResolutionNameId>>,
    identities: &mut ResolutionIdentityCatalogBuilder,
    language: Language,
) -> Option<LoweredImplHeaderPath> {
    let identifier = identifiers.get(&reference)?;
    assert_eq!(
        identifier.role,
        ResolutionIdentifierRole::Reference,
        "an impl header names its subject and trait by reference"
    );
    let mut chain = vec![reference];
    let mut current = reference;
    while let Some(prefix) = prefixes.get(&current).copied().flatten() {
        assert!(
            chain.len() < 8,
            "an impl header path anchors on at most one prefix reference: {chain:?}"
        );
        chain.push(prefix);
        current = prefix;
    }
    chain.reverse();
    let mut segments = Vec::new();
    for site in chain {
        for name in spellings.get(&site).into_iter().flat_map(BTreeMap::values) {
            segments.push(identities.lookup_semantic(
                language,
                ResolutionNamespace::Type,
                names[name],
            ));
        }
    }
    Some(LoweredImplHeaderPath {
        segments,
        terminal: identities.lookup_semantic(
            language,
            ResolutionNamespace::Type,
            names[&identifier.name],
        ),
    })
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
    identities.source_definition_semantic(site)
}

#[cfg(test)]
mod tests {
    use brokk_bifrost_core::analyzer::ProjectFile;
    use brokk_bifrost_core::analyzer::model::{CodeUnit, CodeUnitType};
    use brokk_bifrost_core::analyzer::resolution_facts::{
        ResolutionAdditionalDefinitionNamespaceFact, ResolutionDeclaredTypeRelationFact,
        ResolutionDeferredMemberOwnerFact, ResolutionDefinitionUnitFact, ResolutionNameFact,
        ResolutionRelationMemberFact, ResolutionScopeId, ResolutionSiteFact, ResolutionSiteKind,
        ResolutionTypeSlotFact, ResolutionTypeSlotId, ResolutionTypeSlotRole,
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
                // An impl header names its subject by reference, as every
                // producer of a trait implementation does.
                identifier(
                    4,
                    0,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                ),
            ],
            sites: (0..5)
                .map(|id| ResolutionSiteFact {
                    id: ResolutionSiteId::new(id),
                    scope: ResolutionScopeId::new(0),
                    kind: ResolutionSiteKind::TypeReference,
                    start_byte: usize::try_from(id).unwrap(),
                    end_byte: usize::try_from(id).unwrap() + 1,
                })
                .collect(),
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
                    site: ResolutionSiteId::new(4),
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
            ..FileResolutionFacts::default()
        };
        let mut identities = ResolutionIdentityCatalogBuilder::new(
            BindingFragmentId::for_test(b"digest-7"),
            crate::analyzer::resolution::test_shared_names(),
        );
        let lowered = lower_common_resolution_facts(&mut identities, Language::Rust, &facts);

        assert_eq!(lowered.additional_definition_namespaces.len(), 1);
        assert_eq!(lowered.definition_unit_crosswalks[0].unit, unit);
        assert_eq!(lowered.deferred_member_owners.len(), 1);
        assert_eq!(
            lowered.deferred_member_owners[0].lookup,
            identities.lookup_semantic(Language::Rust, ResolutionNamespace::Callable, "name1"),
            "method ownership must use the callable lookup identity, not the declaration site identity"
        );
        assert_eq!(lowered.declared_type_relations.len(), 1);
        assert_eq!(lowered.relation_members.len(), 1);
        assert_eq!(
            lowered.relation_members[0].kind,
            ResolutionMemberKind::AssociatedType
        );
        assert_eq!(lowered.trait_implementations.len(), 1);
        let implementation = &lowered.trait_implementations[0];
        assert_eq!(
            (
                implementation.subject.segments.as_slice(),
                implementation.subject.terminal,
                implementation.implemented_trait.segments.as_slice(),
                implementation.implemented_trait.terminal,
                implementation.impl_site,
            ),
            (
                &[][..],
                identities.lookup_semantic(Language::Rust, ResolutionNamespace::Type, "name0"),
                &[][..],
                identities.lookup_semantic(Language::Rust, ResolutionNamespace::Type, "name3"),
                4,
            ),
            "a header with no module segments spells only its two head names, \
             and its site is the subject reference"
        );
    }
}
