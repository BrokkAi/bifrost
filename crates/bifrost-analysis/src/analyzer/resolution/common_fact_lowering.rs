//! Language-neutral declaration, relation, and engine-rule rows that do not
//! belong to either the lexical path graph or the typed value-flow graph.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::model::CodeUnit;
use brokk_bifrost_core::analyzer::resolution_facts::{
    FileResolutionFacts, PositionedIdentifierFact, ResolutionCallArgumentListFact,
    ResolutionCallableParameterListFact, ResolutionCallableParameterSemanticsFact,
    ResolutionDeclaredTypeRelationKind, ResolutionExtensionReceiverFact, ResolutionIdentifierRole,
    ResolutionImportRouteKind, ResolutionImportSelectorFact, ResolutionInvocationRoleFact,
    ResolutionJvmAliasFact, ResolutionJvmAliasId, ResolutionJvmAliasOwnerSegmentFact,
    ResolutionMemberAccess, ResolutionMemberKind, ResolutionMemberQualifierCompatibility,
    ResolutionNameId, ResolutionNamespace, ResolutionPackageObjectExportFact, ResolutionScopeFact,
    ResolutionScopeId, ResolutionSingletonRelationFact, ResolutionSiteId, ResolutionTypeRelationId,
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

pub(super) fn validate_scope_forest(
    scopes: &crate::hash::HashMap<ResolutionScopeId, ResolutionScopeFact>,
) {
    for scope in scopes.values() {
        if let Some(parent_id) = scope.parent {
            let parent = scopes
                .get(&parent_id)
                .unwrap_or_else(|| panic!("scope {} names unknown parent {parent_id}", scope.id));
            assert!(
                parent.start_byte <= scope.start_byte && scope.end_byte <= parent.end_byte,
                "child scope must be contained by its parent: {scope:?}, {parent:?}"
            );
        }
        let mut cursor = Some(scope.id);
        let mut visited = std::collections::HashSet::new();
        while let Some(id) = cursor {
            assert!(visited.insert(id), "resolution scope parent cycle at {id}");
            cursor = scopes
                .get(&id)
                .unwrap_or_else(|| panic!("unknown resolution scope {id}"))
                .parent;
        }
    }
}

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

/// One package route declared by a source file, keyed by its lexical package
/// scope so nested and braced clauses remain distinct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LoweredPackageRoute {
    pub(crate) root_scope: BindingNodeId,
    pub(crate) declaration: Option<ResolutionSiteId>,
    pub(crate) placement_gap_site: ResolutionSiteId,
    pub(crate) segments: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LoweredReferenceLookupIdentity {
    /// The qualified terminal reference that owns the stored root route.
    pub(crate) reference: SemanticId,
    /// The source reference for the route's first prefix segment.
    pub(crate) prefix_reference: SemanticId,
    /// The Type lookup identity of the route's first prefix segment.
    pub(crate) lookup: SemanticId,
}

/// One name that an unresolved Rust source region may mention. Wildcards are
/// represented by `name == None`; ordinary names retain the namespace chosen
/// by the source resolver.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct LoweredRustReverseGapCandidate {
    pub(crate) site: ResolutionSiteId,
    pub(crate) name: Option<String>,
    pub(crate) namespace: Option<ResolutionNamespace>,
    /// Macro frontiers need input and transcriber names from Rust source facts.
    /// If those facts are unavailable, publication keeps the wildcard.
    pub(crate) macro_frontier: bool,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LoweredJvmAlias {
    pub(crate) alias: ResolutionJvmAliasId,
    pub(crate) declaration: ResolutionSiteId,
    pub(crate) member_name: String,
    pub(crate) kind: brokk_bifrost_core::analyzer::resolution_facts::ResolutionJvmAliasKind,
    pub(crate) is_static: bool,
    pub(crate) parameter_count: u32,
    pub(crate) status: brokk_bifrost_core::analyzer::resolution_facts::ResolutionJvmAliasStatus,
    pub(crate) owner_segments: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LoweredCallArgument {
    pub(crate) call: ResolutionSiteId,
    pub(crate) list_ordinal: u32,
    pub(crate) ordinal: u32,
    pub(crate) value: SemanticId,
    pub(crate) label: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct LoweredCallArgumentList {
    pub(crate) call: ResolutionSiteId,
    pub(crate) list_ordinal: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LoweredNamedArgumentLabel {
    pub(crate) call: ResolutionSiteId,
    pub(crate) reference: ResolutionSiteId,
    pub(crate) label: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct LoweredCallableParameterList {
    pub(crate) callable: ResolutionSiteId,
    pub(crate) list_ordinal: u32,
    pub(crate) contextual: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LoweredCallableParameterSemantics {
    pub(crate) callable: ResolutionSiteId,
    pub(crate) parameter: ResolutionSiteId,
    pub(crate) list_ordinal: u32,
    pub(crate) ordinal: u32,
    pub(crate) label: String,
    pub(crate) has_default: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LoweredExtensionReceiver {
    pub(crate) callable: ResolutionSiteId,
    pub(crate) receiver_type: SemanticId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LoweredImportSelector {
    pub(crate) site: ResolutionSiteId,
    pub(crate) kind: brokk_bifrost_core::analyzer::resolution_facts::ResolutionImportSelectorKind,
    pub(crate) source_name: Option<String>,
    pub(crate) local_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LoweredSingletonRelation {
    pub(crate) declaration: ResolutionSiteId,
    pub(crate) enclosing_type: Option<ResolutionSiteId>,
    pub(crate) kind:
        brokk_bifrost_core::analyzer::resolution_facts::ResolutionSingletonRelationKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LoweredInvocationRole {
    pub(crate) site: ResolutionSiteId,
    pub(crate) role: brokk_bifrost_core::analyzer::resolution_facts::ResolutionInvocationRole,
    pub(crate) receiver: Option<SemanticId>,
    pub(crate) result: Option<SemanticId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LoweredPackageObjectExport {
    pub(crate) package_object: ResolutionSiteId,
    pub(crate) package_scope: BindingNodeId,
    pub(crate) member: ResolutionSiteId,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LoweredSharedLanguageFacts {
    pub(crate) aliases: Vec<LoweredJvmAlias>,
    pub(crate) call_argument_lists: Vec<LoweredCallArgumentList>,
    pub(crate) call_arguments: Vec<LoweredCallArgument>,
    pub(crate) named_argument_labels: Vec<LoweredNamedArgumentLabel>,
    pub(crate) callable_parameter_lists: Vec<LoweredCallableParameterList>,
    pub(crate) callable_parameter_semantics: Vec<LoweredCallableParameterSemantics>,
    pub(crate) extension_receivers: Vec<LoweredExtensionReceiver>,
    pub(crate) import_selectors: Vec<LoweredImportSelector>,
    pub(crate) singleton_relations: Vec<LoweredSingletonRelation>,
    pub(crate) invocation_roles: Vec<LoweredInvocationRole>,
    pub(crate) package_object_exports: Vec<LoweredPackageObjectExport>,
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
    pub(crate) package_routes: Vec<LoweredPackageRoute>,
    pub(crate) go_package_imports: Vec<LoweredGoPackageImport>,
    pub(crate) reference_lookup_identities: Vec<LoweredReferenceLookupIdentity>,
    pub(crate) rust_reverse_gap_candidates: Vec<LoweredRustReverseGapCandidate>,
    pub(crate) trait_implementations: Vec<LoweredTraitImplementation>,
    pub(crate) shared_language: LoweredSharedLanguageFacts,
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
        mut package_routes: Vec<LoweredPackageRoute>,
        mut go_package_imports: Vec<LoweredGoPackageImport>,
        mut reference_lookup_identities: Vec<LoweredReferenceLookupIdentity>,
        mut rust_reverse_gap_candidates: Vec<LoweredRustReverseGapCandidate>,
        mut trait_implementations: Vec<LoweredTraitImplementation>,
        shared_language: LoweredSharedLanguageFacts,
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

        rust_reverse_gap_candidates.sort_unstable();
        rust_reverse_gap_candidates.dedup();

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
        for rows in package_references.windows(2) {
            if rows[0].token == rows[1].token {
                assert_eq!(
                    (
                        rows[0].domain,
                        rows[0].root_scope,
                        rows[0].namespace,
                        rows[0].lookup,
                        rows[0].choice,
                    ),
                    (
                        rows[1].domain,
                        rows[1].root_scope,
                        rows[1].namespace,
                        rows[1].lookup,
                        rows[1].choice,
                    ),
                    "package-reference token must identify one root/namespace/lookup group: {rows:?}"
                );
            }
        }
        let mut package_reference_sites = BTreeSet::new();
        for row in &package_references {
            assert!(
                package_reference_sites.insert((row.reference, row.namespace)),
                "package-reference metadata duplicates one reference namespace: {row:?}"
            );
        }
        package_members.sort_unstable();
        assert!(
            package_members
                .windows(2)
                .all(|rows| (rows[0].token, rows[0].definition)
                    != (rows[1].token, rows[1].definition))
        );
        package_routes.sort_unstable_by_key(|route| route.root_scope);
        assert!(
            package_routes
                .windows(2)
                .all(|pair| pair[0].root_scope != pair[1].root_scope)
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
            package_routes,
            go_package_imports,
            reference_lookup_identities,
            rust_reverse_gap_candidates,
            trait_implementations,
            shared_language,
        }
    }
}

fn lower_shared_language_facts(
    identities: &mut ResolutionIdentityCatalogBuilder,
    facts: &FileResolutionFacts,
    names: &BTreeMap<ResolutionNameId, &str>,
) -> LoweredSharedLanguageFacts {
    let sites = facts
        .sites
        .iter()
        .map(|site| (site.id, site))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        sites.len(),
        facts.sites.len(),
        "resolution sites are unique"
    );
    let declarations = facts
        .identifiers
        .iter()
        .filter(|identifier| identifier.role == ResolutionIdentifierRole::Declaration)
        .map(|identifier| identifier.site)
        .collect::<BTreeSet<_>>();
    let references = facts
        .identifiers
        .iter()
        .filter(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
        .map(|identifier| identifier.site)
        .collect::<BTreeSet<_>>();
    let calls = facts
        .calls
        .iter()
        .map(|call| call.call)
        .collect::<BTreeSet<_>>();
    let call_argument_ordinals = facts
        .call_arguments
        .iter()
        .map(|argument| (argument.call, argument.ordinal))
        .collect::<BTreeSet<_>>();
    assert_eq!(call_argument_ordinals.len(), facts.call_arguments.len());
    let callable_parameters = facts
        .callable_parameters
        .iter()
        .map(|parameter| {
            (
                parameter.callable,
                parameter.parameter,
                parameter.list_ordinal,
                parameter.ordinal,
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(callable_parameters.len(), facts.callable_parameters.len());
    let type_slots = facts
        .type_slots
        .iter()
        .map(|slot| slot.id)
        .collect::<BTreeSet<_>>();
    let import_routes = facts
        .import_routes
        .iter()
        .map(|route| route.site)
        .collect::<BTreeSet<_>>();

    let mut call_argument_lists = BTreeSet::new();
    for list in &facts.call_argument_lists {
        assert!(calls.contains(&list.call));
        assert_eq!(
            sites[&list.call].kind,
            brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind::Call
        );
        assert!(
            call_argument_lists.insert((list.call, list.list_ordinal)),
            "call argument lists are unique"
        );
    }
    let mut call_arguments = facts
        .call_arguments
        .iter()
        .map(|argument| {
            assert!(calls.contains(&argument.call));
            assert!(call_argument_ordinals.contains(&(argument.call, argument.ordinal)));
            assert!(type_slots.contains(&argument.value));
            let key = (argument.call, argument.list_ordinal);
            if !call_argument_lists.contains(&key) {
                assert_eq!(argument.list_ordinal, 0);
                call_argument_lists.insert(key);
            }
            let label = argument.label.map(|name| {
                let spelling = names[&name];
                assert!(!spelling.is_empty(), "named argument labels are nonempty");
                spelling.to_owned()
            });
            LoweredCallArgument {
                call: argument.call,
                list_ordinal: argument.list_ordinal,
                ordinal: argument.ordinal,
                value: identities.semantic(type_slot_semantic_identity(argument.value)),
                label,
            }
        })
        .collect::<Vec<_>>();
    call_arguments.sort_unstable_by_key(|row| (row.call, row.list_ordinal, row.ordinal));
    assert!(call_arguments.windows(2).all(|pair| {
        (pair[0].call, pair[0].list_ordinal, pair[0].ordinal)
            != (pair[1].call, pair[1].list_ordinal, pair[1].ordinal)
    }));
    let mut named_argument_labels = facts
        .named_argument_labels
        .iter()
        .map(|fact| {
            assert!(calls.contains(&fact.call));
            assert_eq!(
                sites[&fact.call].kind,
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind::Call
            );
            assert_eq!(
                sites[&fact.reference].kind,
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind::ValueReference
            );
            let identifier = facts
                .identifiers
                .iter()
                .find(|identifier| identifier.site == fact.reference)
                .expect("named-argument label has a positioned identifier");
            assert_eq!(identifier.role, ResolutionIdentifierRole::Reference);
            assert_eq!(identifier.name, fact.label);
            assert!(
                facts.call_arguments.iter().any(|argument| {
                    argument.call == fact.call && argument.label == Some(fact.label)
                }),
                "positioned named-argument label corresponds to a call argument: {fact:?}"
            );
            let label = names[&fact.label];
            assert!(!label.is_empty(), "named-argument labels are nonempty");
            LoweredNamedArgumentLabel {
                call: fact.call,
                reference: fact.reference,
                label: label.to_owned(),
            }
        })
        .collect::<Vec<_>>();
    named_argument_labels.sort_unstable_by_key(|row| (row.call, row.reference));
    assert!(named_argument_labels.windows(2).all(|pair| {
        (pair[0].call, pair[0].reference) != (pair[1].call, pair[1].reference)
            && pair[0].reference != pair[1].reference
    }));
    let call_argument_lists = call_argument_lists
        .into_iter()
        .map(|(call, list_ordinal)| LoweredCallArgumentList { call, list_ordinal })
        .collect::<Vec<_>>();
    let mut lists_by_call = BTreeMap::<ResolutionSiteId, Vec<u32>>::new();
    for list in &call_argument_lists {
        lists_by_call
            .entry(list.call)
            .or_default()
            .push(list.list_ordinal);
    }
    for (call, ordinals) in lists_by_call {
        assert!(
            ordinals.iter().enumerate().all(|(expected, ordinal)| {
                *ordinal == u32::try_from(expected).expect("call list count fits u32")
            }),
            "call {call} argument-list ordinals are dense from zero"
        );
    }

    let mut callable_parameter_lists = BTreeMap::<(ResolutionSiteId, u32), bool>::new();
    for list in &facts.callable_parameter_lists {
        assert!(declarations.contains(&list.callable));
        let previous =
            callable_parameter_lists.insert((list.callable, list.list_ordinal), list.contextual);
        assert!(previous.is_none(), "callable parameter lists are unique");
    }
    for parameter in &facts.callable_parameters {
        assert!(declarations.contains(&parameter.callable));
        assert!(
            sites.contains_key(&parameter.parameter),
            "callable parameters must name a source site, including unnamed parameters"
        );
        callable_parameter_lists
            .entry((parameter.callable, parameter.list_ordinal))
            .or_insert(false);
    }
    let callable_parameter_lists = callable_parameter_lists
        .into_iter()
        .map(
            |((callable, list_ordinal), contextual)| LoweredCallableParameterList {
                callable,
                list_ordinal,
                contextual,
            },
        )
        .collect::<Vec<_>>();
    let mut lists_by_callable = BTreeMap::<ResolutionSiteId, Vec<u32>>::new();
    for list in &callable_parameter_lists {
        lists_by_callable
            .entry(list.callable)
            .or_default()
            .push(list.list_ordinal);
    }
    for (callable, ordinals) in lists_by_callable {
        assert!(
            ordinals.iter().enumerate().all(|(expected, ordinal)| {
                *ordinal == u32::try_from(expected).expect("parameter list count fits u32")
            }),
            "callable {callable} parameter-list ordinals are dense from zero"
        );
    }

    let mut alias_segments = BTreeMap::<ResolutionJvmAliasId, Vec<(u32, String)>>::new();
    for segment in &facts.jvm_alias_owner_segments {
        let spelling = names[&segment.name];
        assert!(!spelling.is_empty(), "JVM owner segments are nonempty");
        alias_segments
            .entry(segment.alias)
            .or_default()
            .push((segment.ordinal, spelling.to_owned()));
    }
    let mut aliases = facts.jvm_aliases.iter().collect::<Vec<_>>();
    aliases.sort_unstable_by_key(|alias| alias.id);
    let mut lowered_aliases = Vec::with_capacity(aliases.len());
    for (expected, alias) in aliases.into_iter().enumerate() {
        assert_eq!(
            alias.id.index(),
            expected,
            "JVM alias IDs are dense from zero"
        );
        assert!(declarations.contains(&alias.declaration));
        let member_name = names[&alias.member_name];
        assert!(
            !member_name.is_empty(),
            "JVM alias member names are nonempty"
        );
        let mut segments = alias_segments
            .remove(&alias.id)
            .expect("every JVM alias has an owner path");
        segments.sort_unstable_by_key(|(ordinal, _)| *ordinal);
        for (expected, (ordinal, _)) in segments.iter().enumerate() {
            assert_eq!(
                *ordinal,
                u32::try_from(expected).expect("JVM owner path fits its u32 ordinal"),
                "JVM owner path ordinals are dense from zero"
            );
        }
        lowered_aliases.push(LoweredJvmAlias {
            alias: alias.id,
            declaration: alias.declaration,
            member_name: member_name.to_owned(),
            kind: alias.kind,
            is_static: alias.is_static,
            parameter_count: alias.parameter_count,
            status: alias.status,
            owner_segments: segments.into_iter().map(|(_, name)| name).collect(),
        });
    }
    assert!(
        alias_segments.is_empty(),
        "JVM owner paths name known aliases"
    );

    let mut callable_parameter_semantics = facts
        .callable_parameter_semantics
        .iter()
        .map(|semantics: &ResolutionCallableParameterSemanticsFact| {
            assert!(callable_parameters.contains(&(
                semantics.callable,
                semantics.parameter,
                semantics.list_ordinal,
                semantics.ordinal,
            )));
            let spelling = names[&semantics.label];
            assert!(!spelling.is_empty(), "parameter labels are nonempty");
            LoweredCallableParameterSemantics {
                callable: semantics.callable,
                parameter: semantics.parameter,
                list_ordinal: semantics.list_ordinal,
                ordinal: semantics.ordinal,
                label: spelling.to_owned(),
                has_default: semantics.has_default,
            }
        })
        .collect::<Vec<_>>();
    callable_parameter_semantics
        .sort_unstable_by_key(|row| (row.callable, row.list_ordinal, row.ordinal));
    assert!(callable_parameter_semantics.windows(2).all(|pair| {
        (pair[0].callable, pair[0].list_ordinal, pair[0].ordinal)
            != (pair[1].callable, pair[1].list_ordinal, pair[1].ordinal)
    }));

    let mut extension_receivers = facts
        .extension_receivers
        .iter()
        .map(|receiver: &ResolutionExtensionReceiverFact| {
            assert_eq!(
                sites[&receiver.callable].kind,
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind::CallableDeclaration
            );
            assert!(type_slots.contains(&receiver.receiver_type));
            LoweredExtensionReceiver {
                callable: receiver.callable,
                receiver_type: identities.semantic(type_slot_semantic_identity(
                    receiver.receiver_type,
                )),
            }
        })
        .collect::<Vec<_>>();
    extension_receivers.sort_unstable_by_key(|row| row.callable);
    assert!(
        extension_receivers
            .windows(2)
            .all(|pair| pair[0].callable != pair[1].callable)
    );

    let mut import_selectors = facts
        .import_selectors
        .iter()
        .map(|selector: &ResolutionImportSelectorFact| {
            assert_eq!(
                sites[&selector.site].kind,
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind::ImportDeclaration
            );
            assert!(import_routes.contains(&selector.site));
            let source_name = selector.source_name.map(|name| names[&name].to_owned());
            let local_name = selector.local_name.map(|name| names[&name].to_owned());
            match selector.kind {
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionImportSelectorKind::Named => {
                    assert!(source_name.is_some());
                }
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionImportSelectorKind::Star => {
                    assert!(source_name.is_none() && local_name.is_none());
                }
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionImportSelectorKind::ReceiverMember => {
                    assert!(source_name.is_some());
                }
            }
            LoweredImportSelector {
                site: selector.site,
                kind: selector.kind,
                source_name,
                local_name,
            }
        })
        .collect::<Vec<_>>();
    import_selectors.sort_unstable_by_key(|row| row.site);
    assert!(
        import_selectors
            .windows(2)
            .all(|pair| pair[0].site != pair[1].site)
    );

    let mut singleton_relations = facts
        .singleton_relations
        .iter()
        .map(|relation: &ResolutionSingletonRelationFact| {
            assert!(declarations.contains(&relation.declaration));
            if let Some(enclosing_type) = relation.enclosing_type {
                assert!(declarations.contains(&enclosing_type));
                assert_ne!(relation.declaration, enclosing_type);
            }
            LoweredSingletonRelation {
                declaration: relation.declaration,
                enclosing_type: relation.enclosing_type,
                kind: relation.kind,
            }
        })
        .collect::<Vec<_>>();
    singleton_relations.sort_unstable_by_key(|row| row.declaration);
    assert!(
        singleton_relations
            .windows(2)
            .all(|pair| pair[0].declaration != pair[1].declaration)
    );

    let mut invocation_roles = facts
        .invocation_roles
        .iter()
        .map(|fact: &ResolutionInvocationRoleFact| {
            let site = sites[&fact.site];
            match fact.role {
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionInvocationRole::Direct
                | brokk_bifrost_core::analyzer::resolution_facts::ResolutionInvocationRole::Apply => {
                    assert_eq!(
                        site.kind,
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind::Call
                    );
                }
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionInvocationRole::Unapply
                | brokk_bifrost_core::analyzer::resolution_facts::ResolutionInvocationRole::UnapplySeq => {
                    assert!(
                        references.contains(&fact.site),
                        "an extractor role belongs to the pattern's head reference: {fact:?}, {site:?}"
                    );
                }
            }
            let mut slot_semantic = |slot: Option<_>| {
                slot.map(|slot| {
                    assert!(type_slots.contains(&slot));
                    identities.semantic(type_slot_semantic_identity(slot))
                })
            };
            LoweredInvocationRole {
                site: fact.site,
                role: fact.role,
                receiver: slot_semantic(fact.receiver),
                result: slot_semantic(fact.result),
            }
        })
        .collect::<Vec<_>>();
    invocation_roles.sort_unstable_by_key(|row| row.site);
    assert!(
        invocation_roles
            .windows(2)
            .all(|pair| pair[0].site != pair[1].site)
    );

    let package_routes = facts
        .packages
        .iter()
        .map(|route| route.root_scope)
        .collect::<BTreeSet<_>>();
    let package_members = facts
        .package_members
        .iter()
        .map(|member| (member.root_scope, member.declaration))
        .collect::<BTreeSet<_>>();
    let mut package_object_exports = facts
        .package_object_exports
        .iter()
        .map(|export: &ResolutionPackageObjectExportFact| {
            assert!(declarations.contains(&export.package_object));
            assert!(declarations.contains(&export.member));
            assert!(package_routes.contains(&export.package_scope));
            assert!(package_members.contains(&(export.package_scope, export.member)));
            LoweredPackageObjectExport {
                package_object: export.package_object,
                package_scope: identities.source_scope_node(export.package_scope),
                member: export.member,
            }
        })
        .collect::<Vec<_>>();
    package_object_exports.sort_unstable_by_key(|row| (row.package_object, row.member));
    assert!(package_object_exports.windows(2).all(|pair| {
        (pair[0].package_object, pair[0].member) != (pair[1].package_object, pair[1].member)
    }));

    LoweredSharedLanguageFacts {
        aliases: lowered_aliases,
        call_argument_lists,
        call_arguments,
        named_argument_labels,
        callable_parameter_lists,
        callable_parameter_semantics,
        extension_receivers,
        import_selectors,
        singleton_relations,
        invocation_roles,
        package_object_exports,
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
    let sites = facts
        .sites
        .iter()
        .map(|site| (site.id, site))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        sites.len(),
        facts.sites.len(),
        "resolution sites must be unique"
    );
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
    let mut claimed_kotlin_units = BTreeSet::new();
    let definition_unit_crosswalks = facts
        .definition_units
        .iter()
        .filter_map(|fact| {
            // Kotlin overloads its logical constructor CodeUnit with separate
            // primary and secondary source declarations. Keep each declaration
            // identity in the source-declaration bridge; the reverse unit
            // crosswalk remains one-to-one and uses the first source constructor.
            if language == Language::Kotlin && !claimed_kotlin_units.insert(fact.unit.clone()) {
                return None;
            }
            Some(LoweredDefinitionUnitCrosswalk {
                definition: definition_semantic_for_site(
                    &identifiers,
                    identities,
                    fact.declaration,
                ),
                unit: fact.unit.clone(),
            })
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
    let site_ids = facts
        .sites
        .iter()
        .map(|site| site.id)
        .collect::<BTreeSet<_>>();
    let package_roots = facts
        .packages
        .iter()
        .map(|package| package.root_scope)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        package_roots.len(),
        facts.packages.len(),
        "each source package route has a distinct root scope"
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
    let package_facts = facts
        .packages
        .iter()
        .map(|package| (package.root_scope, package))
        .collect::<BTreeMap<_, _>>();
    let mut segments_by_root = BTreeMap::<_, Vec<_>>::new();
    for segment in &facts.package_segments {
        segments_by_root
            .entry(segment.root_scope)
            .or_default()
            .push(segment);
    }
    let mut declared_root_routes = Vec::with_capacity(facts.package_segments.len());
    let mut package_routes = Vec::with_capacity(facts.packages.len());
    for &root_scope in &package_roots {
        let mut segments = segments_by_root.remove(&root_scope).unwrap_or_default();
        segments.sort_unstable_by_key(|segment| segment.ordinal);
        assert!(segments.iter().enumerate().all(|(position, segment)| {
            usize::try_from(segment.ordinal).expect("package segment position must fit usize")
                == position
        }));
        let route_segments = segments
            .iter()
            .map(|segment| {
                (*names.get(&segment.name).unwrap_or_else(|| {
                    panic!("package segment names unknown name {:?}", segment.name)
                }))
                .to_owned()
            })
            .collect::<Vec<_>>();
        let package = package_facts[&root_scope];
        assert!(site_ids.contains(&package.placement_gap_site));
        if let Some(declaration) = package.declaration {
            assert_eq!(
                sites[&declaration].kind,
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind::PackageDeclaration
            );
        }
        assert!(
            package.declaration.is_some() || route_segments.is_empty(),
            "unnamed package routes do not carry path segments"
        );
        package_routes.push(LoweredPackageRoute {
            root_scope: identities.source_scope_node(root_scope),
            declaration: package.declaration,
            placement_gap_site: package.placement_gap_site,
            segments: route_segments,
        });
        let root_node = identities.source_scope_node(root_scope);
        for segment in segments {
            let spelling = names
                .get(&segment.name)
                .unwrap_or_else(|| panic!("package segment names unknown name {:?}", segment.name));
            declared_root_routes.push(LoweredDeclaredRootRoute {
                root_scope: root_node,
                position: segment.ordinal,
                segment: identities.lookup_semantic(language, ResolutionNamespace::Type, spelling),
            });
        }
    }
    assert!(segments_by_root.is_empty());
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
            prefix_reference: identities.source_reference_semantic(prefix_reference),
            lookup: identities.lookup_semantic(language, prefix.namespace, prefix_name),
        });
    }
    let rust_reverse_gap_candidates = if language == Language::Rust {
        let mut gap_sites = BTreeSet::new();
        let mut macro_frontier_sites = BTreeSet::new();
        // Reverse candidate inventory can remain open for a positioned
        // resolution gap even when reference enumeration itself was complete
        // (for example, an unresolved import route). Keep those sites in the
        // name index too; the persisted coverage rows decide whether a given
        // gap affects a whole-answer reverse query.
        for gap in &facts.gaps {
            gap_sites.insert(gap.site);
            if matches!(
                gap.kind,
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::MacroArgument
                    | brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnexpandedItemMacro
                    | brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnexpandedImplMacro
                    | brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::GeneratedItemSurface
            ) {
                macro_frontier_sites.insert(gap.site);
            }
        }
        for gap in &facts.reference_enumeration_gaps {
            gap_sites.insert(gap.site);
            if matches!(
                gap.kind,
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::MacroArgument
                    | brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnexpandedItemMacro
                    | brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnexpandedImplMacro
                    | brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::GeneratedItemSurface
                    // An unsupported binder can be an attribute macro that
                    // replaces its item. Authored identifier spellings cannot
                    // close the names of references hidden by that boundary.
                    | brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnsupportedScopeOrBinder
            ) {
                macro_frontier_sites.insert(gap.site);
            }
        }
        let mut gap_candidates =
            BTreeMap::<ResolutionSiteId, BTreeSet<(String, Option<ResolutionNamespace>)>>::new();
        for gap_site in &gap_sites {
            let gap_span = sites
                .get(gap_site)
                .unwrap_or_else(|| panic!("reverse inventory gap names unknown site {gap_site}"));
            let candidates = gap_candidates.entry(*gap_site).or_default();
            for identifier in facts.identifiers.iter().filter(|identifier| {
                let source = sites.get(&identifier.site).unwrap_or_else(|| {
                    panic!("identifier names unknown site {:?}", identifier.site)
                });
                gap_span.start_byte <= source.start_byte && source.end_byte <= gap_span.end_byte
            }) {
                candidates.insert((
                    names[&identifier.name].to_owned(),
                    Some(identifier.namespace),
                ));
            }
            for route in facts.root_references.iter().filter(|route| {
                let terminal = sites.get(&route.reference).unwrap_or_else(|| {
                    panic!("root route names unknown site {:?}", route.reference)
                });
                let terminal_is_contained = gap_span.start_byte <= terminal.start_byte
                    && terminal.end_byte <= gap_span.end_byte;
                let prefix_is_contained = route.prefix_reference.is_some_and(|prefix| {
                    let prefix = sites.get(&prefix).unwrap_or_else(|| {
                        panic!("root route names unknown prefix site {:?}", prefix)
                    });
                    gap_span.start_byte <= prefix.start_byte && prefix.end_byte <= gap_span.end_byte
                });
                terminal_is_contained || prefix_is_contained
            }) {
                if let Some(prefix) = route.prefix_reference {
                    candidates.insert((
                        names[&identifiers[&prefix].name].to_owned(),
                        Some(ResolutionNamespace::Type),
                    ));
                }
                for segment in facts
                    .root_reference_segments
                    .iter()
                    .filter(|segment| segment.reference == route.reference)
                {
                    candidates.insert((
                        names[&segment.name].to_owned(),
                        Some(ResolutionNamespace::Type),
                    ));
                }
                if let Some(terminal) = identifiers.get(&route.reference) {
                    candidates.insert((names[&terminal.name].to_owned(), Some(terminal.namespace)));
                }
            }
        }
        let mut rust_reverse_gap_candidates = Vec::new();
        for gap_site in gap_sites {
            let macro_frontier = macro_frontier_sites.contains(&gap_site);
            let candidates = gap_candidates.remove(&gap_site).unwrap_or_default();
            if candidates.is_empty() {
                rust_reverse_gap_candidates.push(LoweredRustReverseGapCandidate {
                    site: gap_site,
                    name: None,
                    namespace: None,
                    macro_frontier,
                });
            } else {
                rust_reverse_gap_candidates.extend(candidates.into_iter().map(
                    |(name, namespace)| LoweredRustReverseGapCandidate {
                        site: gap_site,
                        name: Some(name),
                        namespace,
                        macro_frontier,
                    },
                ));
            }
        }
        rust_reverse_gap_candidates
    } else {
        Vec::new()
    };
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
    let shared_language = lower_shared_language_facts(identities, facts, &names);
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
        package_routes,
        go_package_imports,
        reference_lookup_identities,
        rust_reverse_gap_candidates,
        trait_implementations,
        shared_language,
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
    assert_declaration_identifier(identifier);
    identities.source_definition_semantic(site)
}

pub(super) fn assert_declaration_identifier(identifier: &PositionedIdentifierFact) {
    assert_eq!(identifier.role, ResolutionIdentifierRole::Declaration);
}
#[cfg(test)]
mod tests {
    use brokk_bifrost_core::analyzer::ProjectFile;
    use brokk_bifrost_core::analyzer::model::{CodeUnit, CodeUnitType};
    use brokk_bifrost_core::analyzer::resolution_facts::{
        ResolutionAdditionalDefinitionNamespaceFact, ResolutionDeclaredTypeRelationFact,
        ResolutionDeferredMemberOwnerFact, ResolutionDefinitionUnitFact, ResolutionGapFact,
        ResolutionGapKind, ResolutionNameFact, ResolutionReferenceEnumerationGapFact,
        ResolutionRelationMemberFact, ResolutionScopeId, ResolutionSiteFact, ResolutionSiteKind,
        ResolutionTypeSlotFact, ResolutionTypeSlotId, ResolutionTypeSlotRole,
    };

    use super::*;
    use crate::analyzer::resolution::BindingFragmentId;
    use crate::analyzer::resolution::positioned_identifier_for_test as identifier;

    #[test]
    fn scala_extractor_roles_lower_on_the_pattern_head_reference() {
        let source = concat!(
            "package demo\n",
            "object Use {\n",
            "  def f(x: Any): Any = x match {\n",
            "    case Seq(a, b) => a\n",
            "    case New(n) => n\n",
            "    case Seq(rest*) => rest\n",
            "    case _ => 0\n",
            "  }\n",
            "}\n",
        );
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&crate::analyzer::scala::language::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let file = ProjectFile::new(std::env::temp_dir(), "Extractors.scala");
        let parsed = crate::analyzer::scala::declarations::parse_scala_file(&file, source, &tree);
        let facts = &parsed.resolution_facts;
        let mut identities = ResolutionIdentityCatalogBuilder::new(
            BindingFragmentId::for_test(b"scala-extractor-roles"),
            crate::analyzer::resolution::test_shared_names(),
        );
        let lowered = lower_common_resolution_facts(&mut identities, Language::Scala, facts);
        // The row names the head reference, carries the role, and has neither a
        // receiver nor a result slot; it has no argument count.
        let rows = lowered
            .shared_language
            .invocation_roles
            .iter()
            .map(|row| {
                let site = facts.sites[row.site.index()];
                (
                    &source[site.start_byte..site.end_byte],
                    site.kind,
                    row.role,
                    row.receiver.is_some(),
                    row.result.is_some(),
                )
            })
            .collect::<Vec<_>>();
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionInvocationRole::{
            Unapply, UnapplySeq,
        };
        assert_eq!(
            rows,
            [
                (
                    "Seq",
                    ResolutionSiteKind::ValueReference,
                    Unapply,
                    false,
                    false
                ),
                (
                    "New",
                    ResolutionSiteKind::ValueReference,
                    Unapply,
                    false,
                    false
                ),
                (
                    "Seq",
                    ResolutionSiteKind::ValueReference,
                    UnapplySeq,
                    false,
                    false
                ),
            ]
        );
    }

    #[test]
    fn generated_item_surface_gap_is_a_macro_reverse_frontier() {
        let facts = FileResolutionFacts {
            sites: vec![
                ResolutionSiteFact {
                    id: ResolutionSiteId::new(0),
                    scope: ResolutionScopeId::new(0),
                    kind: ResolutionSiteKind::UnsupportedDeclaration,
                    start_byte: 1,
                    end_byte: 10,
                },
                ResolutionSiteFact {
                    id: ResolutionSiteId::new(1),
                    scope: ResolutionScopeId::new(0),
                    kind: ResolutionSiteKind::UnsupportedDeclaration,
                    start_byte: 11,
                    end_byte: 20,
                },
            ],
            gaps: vec![ResolutionGapFact {
                site: ResolutionSiteId::new(0),
                kind: ResolutionGapKind::GeneratedItemSurface,
            }],
            reference_enumeration_gaps: vec![ResolutionReferenceEnumerationGapFact {
                site: ResolutionSiteId::new(1),
                kind: ResolutionGapKind::GeneratedItemSurface,
            }],
            ..FileResolutionFacts::default()
        };
        let mut identities = ResolutionIdentityCatalogBuilder::new(
            BindingFragmentId::for_test(b"generated-item-surface-gap"),
            crate::analyzer::resolution::test_shared_names(),
        );
        let lowered = lower_common_resolution_facts(&mut identities, Language::Rust, &facts);
        assert_eq!(
            lowered
                .rust_reverse_gap_candidates
                .iter()
                .map(|candidate| (
                    candidate.site,
                    candidate.name.as_deref(),
                    candidate.namespace,
                    candidate.macro_frontier
                ))
                .collect::<Vec<_>>(),
            vec![
                (ResolutionSiteId::new(0), None, None, true),
                (ResolutionSiteId::new(1), None, None, true),
            ],
            "generated surfaces from either gap source stay conservative macro frontiers"
        );
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
