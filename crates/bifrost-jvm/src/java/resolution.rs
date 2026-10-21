//! Java lowering for immutable, target-independent resolution facts.
//!
//! This extends the whole-file pass that already records persisted type-name
//! spellings. It consumes the `Tree` built by the adapter and never reparses or
//! scans source text at query time. Cross-file targets are intentionally absent:
//! references project properties of whichever declaration a selected revision
//! later binds.

use crate::constructor_site::ConstructorSite;
use brokk_bifrost_core::analyzer::CodeUnit;
use brokk_bifrost_core::analyzer::model::{DeclarationKind, JavaTypeConstructorShape};
use brokk_bifrost_core::analyzer::resolution_facts::{
    BindingProjectionFact, BindingProjectionKind, DeclarationTypeRole, DeclarationTypeSlotFact,
    FileResolutionFacts, IntrinsicTypeKind, IntrinsicTypeSeedFact, PositionedIdentifierFact,
    ResolutionBinderFact, ResolutionBinderKind, ResolutionCallableParameterFact,
    ResolutionCallableReceiverOrigin, ResolutionCallableReceiverOriginFact,
    ResolutionCallableResultTypeFact, ResolutionCallableResultTypeParameterFact,
    ResolutionCallableSignatureFact, ResolutionConstructionRequirementFact,
    ResolutionConstructionRequirementKind, ResolutionDeclarationVisibilityFact,
    ResolutionDeclaredTypeArgumentFact, ResolutionDeclaredTypeRelationFact,
    ResolutionDeclaredTypeRelationKind, ResolutionDefinitionUnitFact,
    ResolutionEngineRuleEligibilityFact, ResolutionEngineRuleKind, ResolutionGapFact,
    ResolutionGapKind, ResolutionIdentifierRole, ResolutionImportRouteFact,
    ResolutionImportRouteKind, ResolutionImportRouteSegmentFact, ResolutionLocalWriteFact,
    ResolutionMemberAccess, ResolutionMemberKind, ResolutionMemberOwnerFact,
    ResolutionMemberQualifierCompatibility, ResolutionNameId, ResolutionNamespace,
    ResolutionPackageFact, ResolutionPackageMemberFact, ResolutionPackageSegmentFact,
    ResolutionReferenceOwnerFact, ResolutionRootExportFact, ResolutionRootImportAnchor,
    ResolutionRootImportDemandFact, ResolutionRootImportFact, ResolutionRootImportKind,
    ResolutionRootImportKindFact, ResolutionRootImportSegmentFact, ResolutionRootReferenceFact,
    ResolutionRootReferenceSegmentFact, ResolutionRouteGap, ResolutionScopeFact, ResolutionScopeId,
    ResolutionScopeInheritance, ResolutionScopeKind, ResolutionSiteFact, ResolutionSiteId,
    ResolutionSiteKind, ResolutionSupertypeFact, ResolutionSupertypeKind,
    ResolutionTypeComponentFact, ResolutionTypeComponentKind, ResolutionTypeConstructorKind,
    ResolutionTypeRelationId, ResolutionTypeSlotFact, ResolutionTypeSlotId, ResolutionTypeSlotRole,
    ResolutionTypeTransferFact, ResolutionTypeTransferKind, ResolutionTypeTransferValueTransform,
    ResolutionVisibilityEligibilityFact, dense_ordinal,
};
use brokk_bifrost_core::analyzer::source_facts::{
    PrimarySourceFactCollector, SourceDeclarationId, SourceFactRows, SourceOccurrenceId,
};
use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    first_named_child, nearest_ancestor,
};
use brokk_bifrost_core::analyzer::structural::resolution::{DeclaredVisibility, HoistingClass};
use brokk_bifrost_core::analyzer::tree_walk::{
    TreeWalkAction, first_named_child_of_kind, named_children,
};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use tree_sitter::Node;

use super::declarations::{
    JavaCallableShape, JavaDeclarationModifiers, JavaFieldShape, JavaTypeShape, is_declared_name,
    looks_like_pascal_identifier, node_text,
};
use super::graph_support::{
    java_declared_type_parameters, java_method_reference_parts, java_switch_selector_expression,
    java_type_argument_nodes, java_type_parameter_bounds, java_type_parameter_name_node,
};
use super::imports::{JavaImportSyntax, JavaPackageSyntax};
use super::source_types::JavaSourceTypeCollector;
use super::source_types::{is_java_synthetic_class_body, java_named_type_child};
use brokk_bifrost_core::analyzer::java_facts::{
    JavaSourceFacts, JavaSourceTypeId, JavaTypeSyntaxShape,
};

pub(super) struct JavaResolutionExtraction {
    pub facts: FileResolutionFacts,
    pub type_identifiers: HashSet<String>,
    pub source_facts: SourceFactRows,
    pub java_source_facts: JavaSourceFacts,
    pub site_occurrences: Vec<SourceOccurrenceId>,
    pub declaration_sources: Vec<(ResolutionSiteId, SourceDeclarationId)>,
}

pub(super) struct JavaResolutionBuilder<'source> {
    source: &'source str,
    source_collector: PrimarySourceFactCollector<'source>,
    source_types: JavaSourceTypeCollector,
    root_occurrence: SourceOccurrenceId,
    site_occurrences: Vec<SourceOccurrenceId>,
    declaration_sources: Vec<(ResolutionSiteId, SourceDeclarationId)>,
    declaration_sites: HashMap<usize, ResolutionSiteId>,
    facts: FileResolutionFacts,
    type_identifiers: HashSet<String>,
    name_ids: HashMap<String, ResolutionNameId>,
    scope_stack: Vec<ResolutionScopeId>,
    exit_actions: Vec<ExitAction>,
    type_parameter_scopes: HashSet<ResolutionSiteId>,
    suppression_depth: usize,
    type_contexts: Vec<TypeContext>,
    callable_contexts: Vec<CallableContext>,
    lambda_contexts: Vec<LambdaContext>,
    declaration_contexts: Vec<ResolutionSiteId>,
    reference_enclosing_declaration_overrides: Vec<ResolutionSiteId>,
    body_scopes: HashMap<usize, ResolutionScopeId>,
    declaration_type_slots: HashMap<ResolutionSiteId, ResolutionTypeSlotId>,
    type_slots_by_node: HashMap<usize, ResolutionTypeSlotId>,
    expression_slots_by_node: HashMap<usize, ResolutionTypeSlotId>,
    super_receivers: Vec<(ResolutionSiteId, ResolutionTypeSlotId)>,
    anonymous_creation_results: HashMap<usize, ResolutionTypeSlotId>,
    claimed_identifier_nodes: HashSet<usize>,
    gapped_semantic_subtrees: HashSet<usize>,
    next_parameter_ordinal: HashMap<ResolutionSiteId, u32>,
    next_parent_ordinal: HashMap<ResolutionSiteId, u32>,
    local_value_binders_by_scope:
        HashMap<(ResolutionScopeId, ResolutionNameId), Vec<(usize, usize)>>,
    unsupported_implicit_receiver_scopes: HashSet<ResolutionScopeId>,
    unsupported_implicit_receiver_context_depth: usize,
    package_declaration: Option<ResolutionSiteId>,
    package_segment_names: Vec<ResolutionNameId>,
    package_is_invalid: bool,
    pending_type_on_demand_imports: Vec<ResolutionSiteId>,
    pending_static_imports: Vec<(ResolutionSiteId, Option<ResolutionNameId>)>,
    supported_directive_nodes: HashSet<usize>,
    source_declaration_visibilities: HashMap<usize, (SourceDeclarationId, DeclaredVisibility)>,
    source_modifiers: HashMap<usize, JavaDeclarationModifiers>,
    source_type_shapes: HashMap<usize, JavaTypeShape>,
    source_field_shapes: HashMap<usize, JavaFieldShape>,
    source_callable_shapes: HashMap<usize, JavaCallableShape>,
    type_parameter_positions: HashMap<ResolutionSiteId, HashMap<ResolutionNameId, u32>>,
}

#[derive(Debug, Clone, Copy)]
enum ExitAction {
    Scope,
    TypeContext,
    TypeContextWithParameters,
    SyntheticTypeContext,
    CallableContext,
    CallableContextWithParameters,
    LambdaContext,
    Suppression,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompilationUnitDirectivePhase {
    Package,
    Imports,
    Declarations,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TypeFlavor {
    Class,
    Interface,
    Enum,
    Record,
    Annotation,
}

#[derive(Debug, Clone, Copy)]
struct TypeContext {
    declaration: ResolutionSiteId,
    body_scope: Option<ResolutionScopeId>,
    name: Option<ResolutionNameId>,
    flavor: TypeFlavor,
    constructor_shape: Option<JavaTypeConstructorShape>,
    is_java_lang_object: bool,
    has_explicit_superclass: bool,
    has_explicit_superinterface: bool,
}

#[derive(Debug, Clone, Copy)]
struct CallableContext {
    declaration: ResolutionSiteId,
    scope: ResolutionScopeId,
    activation_start: usize,
    activation_end: usize,
    source_node_id: usize,
}

#[derive(Debug, Clone, Copy)]
struct LambdaContext {
    node_id: usize,
    scope: ResolutionScopeId,
    activation_start: usize,
    activation_end: usize,
}

/// A MISSING identifier from recovery is a zero-width token with no spelling.
fn is_spelled_identifier(node: Node<'_>) -> bool {
    node.kind() == "identifier" && !node.is_missing()
}

fn resolution_site(facts: &FileResolutionFacts, id: ResolutionSiteId) -> &ResolutionSiteFact {
    &facts.sites[id.get() as usize]
}

fn insert_source_shape<T>(shapes: &mut HashMap<usize, T>, node: Node<'_>, shape: T, kind: &str) {
    assert!(
        shapes.insert(node.id(), shape).is_none(),
        "one Java native {kind}-shape handoff per declaration node"
    );
}

impl<'source> JavaResolutionBuilder<'source> {
    pub(super) fn new(root: Node<'_>, source: &'source str) -> Self {
        let root_scope = ResolutionScopeId::new(0);
        let mut supported_directive_nodes = HashSet::default();
        let mut directive_phase = CompilationUnitDirectivePhase::Package;
        let mut cursor = root.walk();
        for child in root.children(&mut cursor) {
            if child.is_extra() {
                continue;
            }
            match child.kind() {
                "package_declaration"
                    if directive_phase == CompilationUnitDirectivePhase::Package =>
                {
                    assert!(supported_directive_nodes.insert(child.id()));
                    directive_phase = CompilationUnitDirectivePhase::Imports;
                }
                "import_declaration"
                    if directive_phase != CompilationUnitDirectivePhase::Declarations =>
                {
                    assert!(supported_directive_nodes.insert(child.id()));
                    directive_phase = CompilationUnitDirectivePhase::Imports;
                }
                _ => directive_phase = CompilationUnitDirectivePhase::Declarations,
            }
        }
        let facts = FileResolutionFacts {
            scopes: vec![ResolutionScopeFact {
                id: root_scope,
                parent: None,
                owner: None,
                kind: ResolutionScopeKind::CompilationUnit,
                inheritance: ResolutionScopeInheritance::Lexical,
                start_byte: root.start_byte(),
                end_byte: root.end_byte(),
            }],
            ..FileResolutionFacts::default()
        };
        let mut source_collector = PrimarySourceFactCollector::new(source);
        let root_occurrence = source_collector.intern_node(root);
        Self {
            source,
            source_collector,
            source_types: JavaSourceTypeCollector::default(),
            root_occurrence,
            site_occurrences: Vec::new(),
            declaration_sources: Vec::new(),
            declaration_sites: HashMap::default(),
            facts,
            type_identifiers: HashSet::default(),
            name_ids: HashMap::default(),
            scope_stack: vec![root_scope],
            exit_actions: Vec::new(),
            type_parameter_scopes: HashSet::default(),
            suppression_depth: 0,
            type_contexts: Vec::new(),
            callable_contexts: Vec::new(),
            lambda_contexts: Vec::new(),
            declaration_contexts: Vec::new(),
            reference_enclosing_declaration_overrides: Vec::new(),
            body_scopes: HashMap::default(),
            declaration_type_slots: HashMap::default(),
            type_slots_by_node: HashMap::default(),
            expression_slots_by_node: HashMap::default(),
            super_receivers: Vec::new(),
            anonymous_creation_results: HashMap::default(),
            claimed_identifier_nodes: HashSet::default(),
            gapped_semantic_subtrees: HashSet::default(),
            next_parameter_ordinal: HashMap::default(),
            next_parent_ordinal: HashMap::default(),
            local_value_binders_by_scope: HashMap::default(),
            unsupported_implicit_receiver_scopes: HashSet::default(),
            unsupported_implicit_receiver_context_depth: 0,
            package_declaration: None,
            package_segment_names: Vec::new(),
            package_is_invalid: false,
            pending_type_on_demand_imports: Vec::new(),
            pending_static_imports: Vec::new(),
            supported_directive_nodes,
            source_declaration_visibilities: HashMap::default(),
            source_modifiers: HashMap::default(),
            source_type_shapes: HashMap::default(),
            source_field_shapes: HashMap::default(),
            source_callable_shapes: HashMap::default(),
            type_parameter_positions: HashMap::default(),
        }
    }

    pub(super) fn source_collector_mut(&mut self) -> &mut PrimarySourceFactCollector<'source> {
        &mut self.source_collector
    }

    pub(super) fn record_source_type_parameters(
        &mut self,
        owner_node: Node<'_>,
        owner: SourceDeclarationId,
    ) {
        self.source_types.record_type_parameters(
            owner_node,
            owner,
            self.source,
            &mut self.source_collector,
        );
    }

    pub(super) fn record_source_callable(&mut self, node: Node<'_>, callable: SourceDeclarationId) {
        self.source_types
            .record_callable(node, callable, self.source, &mut self.source_collector);
    }

    pub(super) fn record_source_local_type(
        &mut self,
        declaration_node: Node<'_>,
        declaration: SourceDeclarationId,
    ) {
        self.source_types.record_local_type(
            declaration_node,
            declaration,
            &mut self.source_collector,
        );
    }

    pub(super) fn record_source_declaration_owner(
        &mut self,
        declaration: SourceDeclarationId,
        owner: SourceDeclarationId,
    ) {
        self.source_types
            .record_declaration_owner(declaration, owner);
    }

    /// Generated owners have parser units, but no source declaration authority.
    pub(super) fn record_synthetic_type_unit(&mut self, body: Node<'_>, unit: &CodeUnit) {
        // Native lowering can suppress a recovered subtree while the display
        // projection still retains its synthetic scope.
        let Some(&scope) = self.body_scopes.get(&body.id()) else {
            return;
        };
        let declaration = self
            .scope(scope)
            .owner
            .expect("synthetic type body has an owner");
        assert_eq!(
            self.site(declaration).kind,
            ResolutionSiteKind::TypeDeclaration
        );
        assert_eq!(self.site(declaration).start_byte, body.start_byte());
        assert_eq!(self.site(declaration).end_byte, body.end_byte());
        assert!(unit.is_synthetic());
        self.facts
            .definition_units
            .push(ResolutionDefinitionUnitFact {
                declaration,
                unit: unit.clone(),
            });
    }

    fn capture_source_type(&mut self, node: Node<'_>) -> JavaSourceTypeId {
        self.source_types
            .record_type(node, self.source, &mut self.source_collector)
    }

    pub(super) fn record_type_identifier(&mut self, node: Node<'_>) {
        self.record_persisted_type_identifier(node);
    }

    pub(super) fn set_source_declaration_visibility(
        &mut self,
        node: Node<'_>,
        declaration: SourceDeclarationId,
        visibility: DeclaredVisibility,
    ) {
        assert!(
            self.source_declaration_visibilities
                .insert(node.id(), (declaration, visibility))
                .is_none(),
            "one Java native visibility handoff per source declaration"
        );
    }

    pub(super) fn source_visibility_for(&self, node: Node<'_>) -> DeclaredVisibility {
        self.source_declaration_visibilities
            .get(&node.id())
            .map(|(_, visibility)| *visibility)
            .expect("Java source visibility must precede projection admission")
    }

    pub(super) fn set_source_declaration_modifiers(
        &mut self,
        node: Node<'_>,
        modifiers: JavaDeclarationModifiers,
    ) {
        assert!(
            self.source_modifiers.insert(node.id(), modifiers).is_none(),
            "one Java native modifier handoff per declaration node"
        );
    }

    pub(super) fn finish(mut self) -> JavaResolutionExtraction {
        assert_eq!(
            self.scope_stack.len(),
            1,
            "Java resolution scope traversal did not balance"
        );
        assert!(self.exit_actions.is_empty());
        assert_eq!(self.suppression_depth, 0);
        assert!(self.type_contexts.is_empty());
        assert!(
            self.anonymous_creation_results.is_empty(),
            "anonymous allocation results must have a synthetic body identity"
        );
        assert!(self.callable_contexts.is_empty());
        assert!(self.lambda_contexts.is_empty());
        assert!(self.declaration_contexts.is_empty());
        assert!(self.reference_enclosing_declaration_overrides.is_empty());
        assert_eq!(self.unsupported_implicit_receiver_context_depth, 0);
        // Implicit superclass facts are emitted when the type exits. Delay
        // connecting super receivers until the file walk has published them.
        let superclass_slots = self
            .facts
            .supertypes
            .iter()
            .filter(|parent| {
                matches!(
                    parent.kind,
                    ResolutionSupertypeKind::Superclass
                        | ResolutionSupertypeKind::ImplicitSuperclass
                )
            })
            .map(|parent| {
                (
                    parent.subtype,
                    (parent.supertype_reference, parent.supertype_slot),
                )
            })
            .collect::<HashMap<_, _>>();
        let mut arguments_by_owner = HashMap::<_, Vec<_>>::default();
        for argument in &self.facts.declared_type_arguments {
            arguments_by_owner
                .entry(argument.owner)
                .or_default()
                .push(*argument);
        }
        for (owner, receiver) in std::mem::take(&mut self.super_receivers) {
            if let Some(&(reference, superclass)) = superclass_slots.get(&owner) {
                // The superclass reference selects its nominal identity. Its
                // original slot also carries the enclosing type's hierarchy
                // frontier, which is not uncertainty about this receiver.
                let identity = self.add_slot(
                    self.slot(receiver).site,
                    ResolutionTypeSlotRole::TargetTypeIdentity,
                );
                self.facts
                    .binding_projections
                    .push(BindingProjectionFact::target_type_identity(
                        reference, identity,
                    ));
                self.facts.declared_type_arguments.extend(
                    arguments_by_owner
                        .get(&superclass)
                        .into_iter()
                        .flatten()
                        .map(|argument| ResolutionDeclaredTypeArgumentFact {
                            owner: identity,
                            ..*argument
                        }),
                );
                self.add_transfer_with_transform(
                    identity,
                    receiver,
                    ResolutionTypeTransferKind::Receiver,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                );
            } else {
                self.add_gap(self.slot(receiver).site, ResolutionGapKind::InferredType);
            }
        }
        let root = *self.scope(ResolutionScopeId::new(0));
        assert_eq!(root.kind, ResolutionScopeKind::CompilationUnit);
        let placement = self.add_site_from_occurrence(
            self.root_occurrence,
            ResolutionSiteKind::UnsupportedRoute,
            root.id,
        );
        self.add_gap(placement, ResolutionGapKind::UnsupportedPlacementBoundary);
        // A single-type import owns this compilation unit's simple name even
        // when its selected destination is unavailable. Package peers cannot
        // become fallback targets for that unresolved import. Local/nested
        // declarations still participate through their lexical source paths.
        let explicit_types = self
            .facts
            .import_routes
            .iter()
            .filter(|import| import.kind == ResolutionImportRouteKind::SingleType)
            .filter_map(|import| import.bound_name)
            .collect::<HashSet<_>>();
        if !self.package_is_invalid {
            self.facts.packages.push(ResolutionPackageFact {
                root_scope: root.id,
                declaration: self.package_declaration,
                placement_gap_site: placement,
            });
            self.facts.package_segments.extend(
                self.package_segment_names
                    .iter()
                    .copied()
                    .enumerate()
                    .map(|(ordinal, name)| ResolutionPackageSegmentFact {
                        root_scope: root.id,
                        ordinal: dense_ordinal(ordinal, "package segment"),
                        name,
                    }),
            );
        }
        if !self.package_is_invalid {
            self.facts
                .package_members
                .extend(
                    self.facts
                        .root_exports
                        .iter()
                        .map(|export| ResolutionPackageMemberFact {
                            root_scope: export.root_scope,
                            declaration: export.declaration,
                            namespace: export.namespace,
                        }),
                );
            let package_references = crate::package_lookup::source_owned_package_references(
                &self.facts,
                |identifier, _| identifier.qualifier.is_none(),
                |identifier, _| {
                    (matches!(
                        identifier.namespace,
                        ResolutionNamespace::Type | ResolutionNamespace::TypeOrValue
                    ) && !explicit_types.contains(&identifier.name))
                    .then_some(root.id)
                },
            );
            self.facts.package_references.extend(package_references);
        }
        self.facts.validate_package_relations();
        self.finish_root_import_demands();
        self.validate_directive_facts();
        self.validate_reference_owners();
        self.validate_callable_receivers();
        self.validate_reference_enumeration_gaps();
        assert_eq!(
            self.site_occurrences.len(),
            self.facts.sites.len(),
            "Java native sites must have one canonical source occurrence each"
        );
        let java_source_facts = self.source_types.finish();
        let source_facts = self.source_collector.finish();
        JavaResolutionExtraction {
            facts: self.facts,
            type_identifiers: self.type_identifiers,
            source_facts,
            java_source_facts,
            site_occurrences: self.site_occurrences,
            declaration_sources: self.declaration_sources,
        }
    }

    fn validate_reference_owners(&self) {
        let identifiers = self
            .facts
            .identifiers
            .iter()
            .map(|identifier| (identifier.site, identifier))
            .collect::<HashMap<_, _>>();
        let reference_sites = self
            .facts
            .identifiers
            .iter()
            .filter(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
            .map(|identifier| identifier.site)
            .collect::<HashSet<_>>();
        let mut field_declarations = HashSet::default();
        let mut members = HashSet::default();
        for member in &self.facts.member_owners {
            assert!(
                members.insert(member.member),
                "one Java member-owner row per declaration is required: {member:?}"
            );
            let declaration = identifiers.get(&member.member).unwrap_or_else(|| {
                panic!(
                    "Java member owner names unknown member declaration {}",
                    member.member
                )
            });
            let owner = identifiers.get(&member.owner).unwrap_or_else(|| {
                panic!(
                    "Java member owner names unknown type declaration {}",
                    member.owner
                )
            });
            let (member_kind, member_namespace) = match member.kind {
                ResolutionMemberKind::NestedType => (
                    ResolutionSiteKind::TypeDeclaration,
                    ResolutionNamespace::Type,
                ),
                ResolutionMemberKind::Method => (
                    ResolutionSiteKind::CallableDeclaration,
                    ResolutionNamespace::Callable,
                ),
                ResolutionMemberKind::Constructor => (
                    ResolutionSiteKind::ConstructorDeclaration,
                    ResolutionNamespace::Constructor,
                ),
                ResolutionMemberKind::Field => (
                    ResolutionSiteKind::ValueDeclaration,
                    ResolutionNamespace::Value,
                ),
                ResolutionMemberKind::AssociatedType => {
                    panic!("Java cannot publish an associated-type member: {member:?}")
                }
            };
            assert!(
                declaration.role == ResolutionIdentifierRole::Declaration
                    && self.site(member.member).kind == member_kind
                    && declaration.namespace == member_namespace,
                "Java member-owner member shape is invalid: {member:?}, declaration={declaration:?}"
            );
            assert!(
                owner.role == ResolutionIdentifierRole::Declaration
                    && self.site(member.owner).kind == ResolutionSiteKind::TypeDeclaration
                    && owner.namespace == ResolutionNamespace::Type,
                "Java member-owner type shape is invalid: {member:?}, owner={owner:?}"
            );
            if member.kind == ResolutionMemberKind::Field {
                assert!(field_declarations.insert(member.member));
            }
        }
        let mut owners = HashMap::default();
        for fact in &self.facts.reference_owners {
            let reference = identifiers.get(&fact.reference).unwrap_or_else(|| {
                panic!(
                    "Java reference owner names unknown identifier site {}",
                    fact.reference
                )
            });
            assert_eq!(
                reference.role,
                ResolutionIdentifierRole::Reference,
                "Java reference owner source must be a positioned reference: {fact:?}"
            );
            if let Some(owner) = fact.owner {
                let declaration = identifiers.get(&owner).unwrap_or_else(|| {
                    panic!("Java reference owner names unknown declaration site {owner}")
                });
                assert_eq!(
                    declaration.role,
                    ResolutionIdentifierRole::Declaration,
                    "Java reference owner must be a positioned declaration: {fact:?}"
                );
                let owner_kind = self.site(owner).kind;
                let is_field = owner_kind == ResolutionSiteKind::ValueDeclaration
                    && field_declarations.contains(&owner);
                assert!(
                    matches!(
                        owner_kind,
                        ResolutionSiteKind::TypeDeclaration
                            | ResolutionSiteKind::CallableDeclaration
                            | ResolutionSiteKind::ConstructorDeclaration
                    ) || is_field,
                    "Java reference owner must be an analyzer declaration: {fact:?}"
                );
            }
            assert!(
                owners.insert(fact.reference, fact.owner).is_none(),
                "one Java source owner per positioned reference is required: {fact:?}"
            );
        }
        assert_eq!(
            owners.len(),
            reference_sites.len(),
            "every Java positioned reference must have one source-owner row"
        );
        assert!(
            reference_sites.iter().all(|site| owners.contains_key(site)),
            "every Java positioned reference must have one source-owner row"
        );
        for supertype in &self.facts.supertypes {
            assert_eq!(
                owners.get(&supertype.supertype_reference),
                Some(&Some(supertype.subtype)),
                "a Java supertype occurrence must belong to its subtype declaration"
            );
        }
    }

    fn validate_callable_receivers(&self) {
        let callable_references = self
            .facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == ResolutionNamespace::Callable
            })
            .map(|identifier| (identifier.site, identifier))
            .collect::<HashMap<_, _>>();
        let mut receivers = HashSet::default();
        for fact in &self.facts.callable_receiver_origins {
            let reference = callable_references.get(&fact.reference).unwrap_or_else(|| {
                panic!(
                    "Java callable receiver names unknown callable reference {}",
                    fact.reference
                )
            });
            assert!(
                matches!(
                    self.site(fact.reference).kind,
                    ResolutionSiteKind::CallableReference | ResolutionSiteKind::MemberReference
                ),
                "Java callable receiver must name a terminal callable reference: {fact:?}"
            );
            assert!(
                fact.origin
                    .is_reference_qualification_valid(reference.qualifier.is_none()),
                "Java callable receiver origin must agree with reference qualification: {fact:?}"
            );
            assert!(
                receivers.insert(fact.reference),
                "one Java callable receiver row per positioned reference is required: {fact:?}"
            );
        }
        assert_eq!(
            receivers.len(),
            callable_references.len(),
            "every Java positioned callable reference must have one receiver row"
        );
        assert!(
            callable_references
                .keys()
                .all(|reference| receivers.contains(reference)),
            "every Java positioned callable reference must have one receiver row"
        );
    }

    fn validate_reference_enumeration_gaps(&self) {
        let mut rows = HashSet::default();
        for gap in &self.facts.reference_enumeration_gaps {
            assert!(
                gap.site.index() < self.facts.sites.len(),
                "Java reference-enumeration gap names an unknown site: {gap:?}"
            );
            assert!(
                self.facts
                    .gaps
                    .iter()
                    .any(|point| point.site == gap.site && point.kind == gap.kind),
                "Java reference-enumeration gap must refine an extracted gap: {gap:?}"
            );
            assert!(
                rows.insert(*gap),
                "Java reference-enumeration gaps must be unique: {gap:?}"
            );
        }
    }

    pub(super) fn enter(&mut self, node: Node<'_>) -> TreeWalkAction {
        assert_ne!(
            node.kind(),
            "import_declaration",
            "Java import nodes must enter through enter_import"
        );
        assert_ne!(
            node.kind(),
            "package_declaration",
            "Java package nodes must enter through enter_package"
        );
        if let Some(action) = self.enter_preamble(node) {
            return action;
        }

        self.enter_after_preamble(node)
    }

    pub(super) fn enter_import<'tree>(
        &mut self,
        node: Node<'tree>,
        syntax: &JavaImportSyntax<'tree, 'source>,
    ) -> TreeWalkAction {
        assert_eq!(node.kind(), "import_declaration");
        if let Some(action) = self.enter_preamble(node) {
            return action;
        }
        self.lower_import_declaration(node, syntax)
    }

    pub(super) fn enter_package<'tree>(
        &mut self,
        node: Node<'tree>,
        syntax: &JavaPackageSyntax<'tree, 'source>,
    ) -> TreeWalkAction {
        assert_eq!(node.kind(), "package_declaration");
        assert_eq!(
            syntax.node.id(),
            node.id(),
            "Java package syntax must belong to the entered declaration"
        );
        if let Some(action) = self.enter_preamble(node) {
            return action;
        }
        self.lower_package_declaration(node, syntax)
    }

    fn enter_preamble(&mut self, node: Node<'_>) -> Option<TreeWalkAction> {
        self.record_persisted_type_identifier(node);

        if self.suppression_depth > 0 {
            if node.kind() == "class_body"
                && is_java_synthetic_class_body(node)
                && self.anonymous_creation_results.contains_key(&node.id())
            {
                // An enclosing expression can be suppressed after its
                // dependencies were lowered, for example a cast or a
                // non-local assignment to an anonymous allocation. The
                // allocation result is already published, so its synthetic
                // body still has to supply the identity that result names.
                return Some(self.enter_scope_body(node));
            }
            return Some(TreeWalkAction::Descend);
        }

        if node.is_error() || node.is_missing() {
            return Some(self.suppress_with_gap(
                node,
                ResolutionSiteKind::UnsupportedDeclaration,
                ResolutionGapKind::MalformedSyntax,
            ));
        }

        None
    }

    fn enter_after_preamble(&mut self, node: Node<'_>) -> TreeWalkAction {
        if matches!(node.kind(), "annotation" | "marker_annotation") {
            self.lower_annotation(node);
            return self.suppress_semantics();
        }

        if node.kind() == "method_reference" {
            self.lower_expression(node);
            return self.suppress_semantics();
        }

        if node.kind() == "explicit_constructor_invocation" {
            return self.suppress_with_gap(
                node,
                ResolutionSiteKind::UnsupportedExpression,
                ResolutionGapKind::UnsupportedExpression,
            );
        }

        match node.kind() {
            "lambda_expression" => return self.enter_lambda_expression(node),
            "catch_clause" => return self.enter_catch_clause(node),
            "catch_formal_parameter" => {
                self.lower_catch_formal_parameter(node);
                return TreeWalkAction::Descend;
            }
            _ => {}
        }

        if let Some(parent) = node.parent()
            && parent.kind() == "for_statement"
            && node.kind() != "local_variable_declaration"
            && ["init", "condition", "update"].iter().any(|field| {
                let mut cursor = parent.walk();
                parent
                    .children_by_field_name(field, &mut cursor)
                    .any(|child| child == node)
            })
        {
            self.lower_expression(node);
            return TreeWalkAction::Descend;
        }

        if node.kind() == "module_declaration" {
            return self.lower_module_declaration(node);
        }

        if self.gapped_semantic_subtrees.contains(&node.id()) {
            return self.suppress_semantics();
        }

        if let Some(lambda) = self.lambda_contexts.last().copied()
            && node.kind() != "block"
            && node.parent().is_some_and(|parent| {
                parent.kind() == "lambda_expression"
                    && parent.id() == lambda.node_id
                    && parent.child_by_field_name("body") == Some(node)
            })
        {
            self.lower_expression(node);
            // Expression references are already claimed, but nested type
            // bodies still need their scopes and allocation identities.
            return TreeWalkAction::Descend;
        }

        if node.kind() == "switch_expression" {
            self.lower_switch_selector(node);
        } else if node.kind() == "guard" {
            if let Some(condition) = named_children(node)
                .into_iter()
                .find(|child| !child.is_extra())
            {
                self.lower_expression(condition);
            }
        } else if node.kind() == "switch_label" {
            self.lower_switch_label(node);
        } else if node.kind() == "synchronized_statement"
            && let Some(lock) = first_named_child_of_kind(node, "parenthesized_expression")
        {
            self.lower_expression(lock);
        }

        if node.kind() == "formal_parameters"
            && node.named_child_count() > 0
            && node.parent().is_some_and(|record| {
                record.kind() == "record_declaration"
                    && record.child_by_field_name("parameters") == Some(node)
            })
        {
            // Record components are declarations on the record, not callable
            // parameters. A local record can appear inside a method, so the
            // outer callable context remains on the stack while this exact
            // record parameter list is visited.
            return self.suppress_with_gap(
                node,
                ResolutionSiteKind::UnsupportedDeclaration,
                ResolutionGapKind::UnsupportedScopeOrBinder,
            );
        }

        if let Some(lambda) = self.lambda_context_for_parameter(node) {
            match node.kind() {
                "formal_parameter" => {
                    self.lower_lambda_formal_parameter(node, lambda);
                    return TreeWalkAction::Descend;
                }
                "inferred_parameters" => {
                    for parameter in named_children(node) {
                        self.lower_lambda_inferred_parameter(parameter, lambda);
                    }
                    return TreeWalkAction::Skip;
                }
                "identifier" => {
                    self.lower_lambda_inferred_parameter(node, lambda);
                    return TreeWalkAction::Skip;
                }
                _ => unreachable!("only Java lambda parameter nodes have lambda contexts"),
            }
        }

        if self.is_scope_body(node) {
            return self.enter_scope_body(node);
        }

        match node.kind() {
            "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "annotation_type_declaration" => {
                if let Some(context) = self.lower_type_declaration(node) {
                    self.declaration_contexts.push(context.declaration);
                    self.type_contexts.push(context);
                    self.exit_actions.push(
                        if self.type_parameter_scopes.contains(&context.declaration) {
                            ExitAction::TypeContextWithParameters
                        } else {
                            ExitAction::TypeContext
                        },
                    );
                    return TreeWalkAction::DescendWithExit;
                }
            }
            "method_declaration"
            | "constructor_declaration"
            | "compact_constructor_declaration"
            | "annotation_type_element_declaration" => {
                if let Some(context) = self.lower_callable_declaration(node) {
                    self.declaration_contexts.push(context.declaration);
                    self.callable_contexts.push(context);
                    self.exit_actions.push(
                        if self.type_parameter_scopes.contains(&context.declaration) {
                            ExitAction::CallableContextWithParameters
                        } else {
                            ExitAction::CallableContext
                        },
                    );
                    return TreeWalkAction::DescendWithExit;
                }
            }
            "static_initializer" => self.lower_initializer(node),
            "formal_parameter" => {
                let belongs_to_callable = self.callable_contexts.last().is_some_and(|callable| {
                    self.source_callable_shapes
                        .get(&callable.source_node_id)
                        .and_then(|shape| shape.repeated_for(node.id()))
                        .is_some()
                });
                if belongs_to_callable {
                    self.lower_parameter(node);
                } else {
                    return self.suppress_with_gap(
                        node,
                        ResolutionSiteKind::UnsupportedDeclaration,
                        ResolutionGapKind::UnsupportedScopeOrBinder,
                    );
                }
            }
            "resource" => self.lower_resource(node),
            "record_pattern" => self.lower_record_pattern_type(node),
            "type_pattern" | "record_pattern_component" => self.lower_type_pattern(node),
            "spread_parameter" => {
                return if self.lower_spread_parameter(node) {
                    self.suppress_semantics()
                } else {
                    self.suppress_with_gap(
                        node,
                        ResolutionSiteKind::UnsupportedDeclaration,
                        ResolutionGapKind::UnsupportedScopeOrBinder,
                    )
                };
            }
            "field_declaration" | "constant_declaration" | "local_variable_declaration" => {
                self.lower_variable_declaration(node)
            }
            "enum_constant" => self.lower_enum_constant(node),
            "return_statement" => self.lower_return(node),
            "expression_statement" => {
                if let Some(value) = first_named_child(node) {
                    self.lower_expression(value);
                }
            }
            "superclass" | "super_interfaces" | "extends_interfaces" => {
                self.lower_inheritance_clause(node)
            }
            _ => {}
        }

        if (is_spelled_identifier(node)
            || matches!(node.kind(), "type_identifier" | "this" | "super"))
            && !self.claimed_identifier_nodes.contains(&node.id())
        {
            let site = self.add_site(
                node,
                if node.kind() == "type_identifier" {
                    ResolutionSiteKind::TypeReference
                } else {
                    ResolutionSiteKind::UnsupportedExpression
                },
            );
            let kind = if node.kind() == "type_identifier" {
                ResolutionGapKind::UnsupportedTypeSyntax
            } else {
                ResolutionGapKind::UnsupportedExpression
            };
            self.add_gap(site, kind);
            self.add_reference_enumeration_gap(site, kind);
        }

        TreeWalkAction::Descend
    }

    fn enter_scope_body(&mut self, node: Node<'_>) -> TreeWalkAction {
        if node.kind() == "class_body" && is_java_synthetic_class_body(node) {
            self.enter_synthetic_class_body(node);
        }
        let scope = self
            .body_scopes
            .get(&node.id())
            .copied()
            .unwrap_or_else(|| {
                self.allocate_scope(
                    self.current_scope(),
                    None,
                    ResolutionScopeKind::Block,
                    node.start_byte(),
                    node.end_byte(),
                )
            });
        self.scope_stack.push(scope);
        self.exit_actions.push(ExitAction::Scope);
        if node.kind() == "enhanced_for_statement" {
            self.lower_enhanced_for(node);
        }
        TreeWalkAction::DescendWithExit
    }

    fn enter_lambda_expression(&mut self, node: Node<'_>) -> TreeWalkAction {
        let Some(body) = node.child_by_field_name("body") else {
            return self.suppress_with_gap(
                node,
                ResolutionSiteKind::UnsupportedExpression,
                ResolutionGapKind::MalformedSyntax,
            );
        };
        if !self.expression_slots_by_node.contains_key(&node.id()) {
            self.lower_unsupported_expression_preserving_children(node);
        }
        let callable = self.slot(self.expression_slot(node)).site;
        let scope = self.allocate_scope(
            self.current_scope(),
            Some(callable),
            ResolutionScopeKind::Executable,
            node.start_byte(),
            node.end_byte(),
        );
        let context = LambdaContext {
            node_id: node.id(),
            scope,
            activation_start: body.start_byte(),
            activation_end: body.end_byte(),
        };
        self.scope_stack.push(scope);
        self.lambda_contexts.push(context);
        self.exit_actions.push(ExitAction::LambdaContext);
        TreeWalkAction::DescendWithExit
    }

    fn enter_catch_clause(&mut self, node: Node<'_>) -> TreeWalkAction {
        if node.child_by_field_name("body").is_none() {
            return self.suppress_with_gap(
                node,
                ResolutionSiteKind::UnsupportedDeclaration,
                ResolutionGapKind::MalformedSyntax,
            );
        }
        let scope = self.allocate_scope(
            self.current_scope(),
            None,
            ResolutionScopeKind::Block,
            node.start_byte(),
            node.end_byte(),
        );
        self.scope_stack.push(scope);
        self.exit_actions.push(ExitAction::Scope);
        TreeWalkAction::DescendWithExit
    }

    fn add_declared_head_local(
        &mut self,
        name: Node<'_>,
        activation: std::ops::Range<usize>,
    ) -> ResolutionSiteId {
        let scope = self.current_scope();
        let declaration = self.add_identifier_site(
            name,
            ResolutionSiteKind::ValueDeclaration,
            scope,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
            None,
        );
        self.facts.binders.push(ResolutionBinderFact {
            declaration,
            scope,
            kind: ResolutionBinderKind::Local,
            hoisting: HoistingClass::DeclaredHead,
            activation_start: activation.start,
            activation_end: activation.end,
        });
        self.register_local_value_binder(scope, name, activation.start, activation.end);
        declaration
    }

    fn lower_enhanced_for(&mut self, node: Node<'_>) {
        let (Some(name), Some(type_node), Some(value), Some(body)) = (
            node.child_by_field_name("name"),
            node.child_by_field_name("type"),
            node.child_by_field_name("value"),
            node.child_by_field_name("body"),
        ) else {
            let site = self.add_site(node, ResolutionSiteKind::UnsupportedDeclaration);
            self.add_gap(site, ResolutionGapKind::MalformedSyntax);
            return;
        };
        // The iterable is evaluated outside the loop variable's activation.
        self.lower_expression(value);
        if name.kind() == "underscore_pattern" {
            self.lower_type(type_node);
            return;
        }
        assert!(is_spelled_identifier(name));
        let declaration = self.add_declared_head_local(name, body.start_byte()..body.end_byte());
        let source_declaration = self.record_declaration_source(node, declaration);
        self.source_collector
            .mark_lexical(source_declaration, DeclarationKind::EnhancedForVariable);
        if let Some(dimensions) = node.child_by_field_name("dimensions") {
            self.attach_declaration_gap_type(
                declaration,
                dimensions,
                DeclarationTypeRole::Value,
                ResolutionGapKind::PostfixArrayDimensions,
            );
        } else {
            self.attach_declaration_type(declaration, type_node, DeclarationTypeRole::Value);
        }
        self.attach_implicit_local_initializer(declaration, name);
    }

    fn lower_catch_formal_parameter(&mut self, node: Node<'_>) {
        let Some(clause) = node
            .parent()
            .filter(|parent| parent.kind() == "catch_clause")
        else {
            let site = self.add_site(node, ResolutionSiteKind::UnsupportedDeclaration);
            self.add_gap(site, ResolutionGapKind::MalformedSyntax);
            return;
        };
        let types = named_children(node)
            .into_iter()
            .filter(|child| child.kind() == "catch_type")
            .flat_map(named_children)
            .filter(|child| self.is_type_syntax(child.kind()))
            .collect::<Vec<_>>();
        let Some(name) = node.child_by_field_name("name") else {
            for type_node in types {
                self.lower_type(type_node);
            }
            let site = self.add_site(node, ResolutionSiteKind::UnsupportedDeclaration);
            self.add_gap(site, ResolutionGapKind::MalformedSyntax);
            return;
        };
        if name.kind() != "identifier" {
            for type_node in types {
                self.lower_type(type_node);
            }
            let site = self.add_site(node, ResolutionSiteKind::UnsupportedDeclaration);
            self.add_gap(site, ResolutionGapKind::UnsupportedScopeOrBinder);
            return;
        }

        let body = clause
            .child_by_field_name("body")
            .expect("validated Java catch clause has a body");
        let declaration = self.add_declared_head_local(name, body.start_byte()..body.end_byte());
        let source_declaration = self.record_declaration_source(node, declaration);
        self.source_collector
            .mark_lexical(source_declaration, DeclarationKind::CatchParameter);

        match types.as_slice() {
            [type_node] => {
                if let Some(dimensions) = node.child_by_field_name("dimensions") {
                    self.attach_declaration_gap_type(
                        declaration,
                        dimensions,
                        DeclarationTypeRole::Parameter,
                        ResolutionGapKind::PostfixArrayDimensions,
                    );
                } else {
                    self.attach_declaration_type(
                        declaration,
                        *type_node,
                        DeclarationTypeRole::Parameter,
                    );
                }
            }
            [] => self.add_gap(declaration, ResolutionGapKind::MalformedSyntax),
            _ => {
                for type_node in types.iter().copied() {
                    self.lower_type(type_node);
                }
                self.add_gap(declaration, ResolutionGapKind::UnsupportedTypeSyntax);
            }
        }
        self.attach_implicit_local_initializer(declaration, name);
    }

    fn attach_implicit_local_initializer(&mut self, declaration: ResolutionSiteId, name: Node<'_>) {
        // The written type describes the binding, not the runtime value
        // supplied by iteration, an exception, or a successful pattern match.
        let input = self.add_gap_slot(
            name,
            ResolutionGapKind::InferredType,
            ResolutionTypeSlotRole::ExpressionValue,
        );
        assert_ne!(self.facts.type_slot(input).site, declaration);
        let output = self.add_slot(declaration, ResolutionTypeSlotRole::AssignmentValue);
        self.add_transfer(input, output, ResolutionTypeTransferKind::Assignment);
    }

    fn lambda_context_for_parameter(&self, node: Node<'_>) -> Option<LambdaContext> {
        let lambda = match node.kind() {
            "formal_parameter" => {
                let parameters = node.parent()?;
                let lambda = parameters.parent()?;
                (parameters.kind() == "formal_parameters"
                    && lambda.kind() == "lambda_expression"
                    && lambda.child_by_field_name("parameters") == Some(parameters))
                .then_some(lambda)?
            }
            "inferred_parameters" => {
                let lambda = node.parent()?;
                (lambda.kind() == "lambda_expression"
                    && lambda.child_by_field_name("parameters") == Some(node))
                .then_some(lambda)?
            }
            "identifier" => {
                let lambda = node.parent()?;
                (lambda.kind() == "lambda_expression"
                    && lambda.child_by_field_name("parameters") == Some(node))
                .then_some(lambda)?
            }
            _ => return None,
        };
        self.lambda_contexts
            .last()
            .copied()
            .filter(|context| context.node_id == lambda.id())
    }

    fn lower_lambda_formal_parameter(&mut self, node: Node<'_>, lambda: LambdaContext) {
        let Some(name) = node
            .child_by_field_name("name")
            .filter(|name| name.kind() == "identifier")
        else {
            let site = self.add_site_in_scope(
                node,
                ResolutionSiteKind::UnsupportedDeclaration,
                lambda.scope,
            );
            self.add_gap(site, ResolutionGapKind::UnsupportedScopeOrBinder);
            return;
        };
        let declaration = self.add_identifier_site(
            name,
            ResolutionSiteKind::ValueDeclaration,
            lambda.scope,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
            None,
        );
        let source_declaration = self.record_declaration_source(node, declaration);
        self.source_collector
            .mark_lexical(source_declaration, DeclarationKind::LambdaParameter);
        self.facts.binders.push(ResolutionBinderFact {
            declaration,
            scope: lambda.scope,
            kind: ResolutionBinderKind::Parameter,
            hoisting: HoistingClass::ScopeWide,
            activation_start: lambda.activation_start,
            activation_end: lambda.activation_end,
        });
        self.register_local_value_binder(
            lambda.scope,
            name,
            lambda.activation_start,
            lambda.activation_end,
        );
        let Some(type_node) = node.child_by_field_name("type") else {
            self.add_gap(declaration, ResolutionGapKind::MalformedSyntax);
            return;
        };
        if let Some(dimensions) = node.child_by_field_name("dimensions") {
            self.attach_declaration_gap_type(
                declaration,
                dimensions,
                DeclarationTypeRole::Parameter,
                ResolutionGapKind::PostfixArrayDimensions,
            );
        } else {
            self.attach_declaration_type(declaration, type_node, DeclarationTypeRole::Parameter);
        }
    }

    fn lower_lambda_inferred_parameter(&mut self, name: Node<'_>, lambda: LambdaContext) {
        if name.kind() != "identifier" {
            let site = self.add_site_in_scope(
                name,
                ResolutionSiteKind::UnsupportedDeclaration,
                lambda.scope,
            );
            self.add_gap(site, ResolutionGapKind::UnsupportedScopeOrBinder);
            return;
        }
        let declaration = self.add_identifier_site(
            name,
            ResolutionSiteKind::ValueDeclaration,
            lambda.scope,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
            None,
        );
        let source_declaration =
            self.record_declaration_source_with_name(name, Some(name), declaration);
        self.source_collector
            .mark_lexical(source_declaration, DeclarationKind::LambdaParameter);
        self.facts.binders.push(ResolutionBinderFact {
            declaration,
            scope: lambda.scope,
            kind: ResolutionBinderKind::Parameter,
            hoisting: HoistingClass::ScopeWide,
            activation_start: lambda.activation_start,
            activation_end: lambda.activation_end,
        });
        self.register_local_value_binder(
            lambda.scope,
            name,
            lambda.activation_start,
            lambda.activation_end,
        );
        self.add_gap(declaration, ResolutionGapKind::InferredType);
    }

    fn reject_misplaced_directive(
        &mut self,
        node: Node<'_>,
        kind: ResolutionSiteKind,
    ) -> TreeWalkAction {
        let site = self.add_site(node, kind);
        self.facts.add_route_gap(
            site,
            ResolutionRouteGap::UnknownBinder {
                scope: self.facts.sites[site.index()].scope,
                name: None,
                namespace: None,
                may_publish: false,
            },
        );
        self.add_reference_enumeration_gap_if_omitted(
            node,
            site,
            ResolutionGapKind::UnsupportedRoute,
        );
        if node.has_error() {
            self.add_gap(site, ResolutionGapKind::MalformedSyntax);
            self.add_reference_enumeration_gap_if_omitted(
                node,
                site,
                ResolutionGapKind::MalformedSyntax,
            );
        }
        self.suppress_semantics()
    }

    /// Lower annotation names and their structured element values before the
    /// tree walk suppresses the annotation subtree. Annotation element keys
    /// are labels, not references; only each pair's `value` field participates
    /// in name resolution.
    fn lower_annotation(&mut self, root: Node<'_>) {
        let mut pending = vec![root];
        while let Some(node) = pending.pop() {
            match node.kind() {
                "annotation" | "marker_annotation" => {
                    if let Some(name) = node.child_by_field_name("name") {
                        self.lower_named_type_reference(name);
                    } else {
                        let site = self.add_site(node, ResolutionSiteKind::UnsupportedExpression);
                        self.add_gap(site, ResolutionGapKind::MalformedSyntax);
                        self.add_reference_enumeration_gap_if_omitted(
                            node,
                            site,
                            ResolutionGapKind::MalformedSyntax,
                        );
                    }
                    if let Some(arguments) = node.child_by_field_name("arguments") {
                        pending.push(arguments);
                    }
                    if node.has_error() || node.is_missing() {
                        let site = self.add_site(node, ResolutionSiteKind::UnsupportedExpression);
                        self.add_gap(site, ResolutionGapKind::MalformedSyntax);
                        self.add_reference_enumeration_gap_if_omitted(
                            node,
                            site,
                            ResolutionGapKind::MalformedSyntax,
                        );
                    }
                }
                "annotation_argument_list" | "element_value_array_initializer" => {
                    pending.extend(named_children(node).into_iter().rev());
                }
                "element_value_pair" => {
                    if let Some(value) = node.child_by_field_name("value") {
                        pending.push(value);
                    } else {
                        let site = self.add_site(node, ResolutionSiteKind::UnsupportedExpression);
                        self.add_gap(site, ResolutionGapKind::MalformedSyntax);
                        self.add_reference_enumeration_gap_if_omitted(
                            node,
                            site,
                            ResolutionGapKind::MalformedSyntax,
                        );
                    }
                }
                _ => {
                    self.lower_expression(node);
                }
            }
        }
    }

    fn lower_module_declaration(&mut self, node: Node<'_>) -> TreeWalkAction {
        let Some(body) = node.child_by_field_name("body") else {
            return self.suppress_with_gap(
                node,
                ResolutionSiteKind::UnsupportedDeclaration,
                ResolutionGapKind::MalformedSyntax,
            );
        };
        for annotation in named_children(node)
            .into_iter()
            .filter(|child| matches!(child.kind(), "annotation" | "marker_annotation"))
        {
            self.lower_annotation(annotation);
        }
        // Modules declare no member-resolution binder. Service and provider
        // names are type references; requires/exports/opens name modules or
        // packages and do not participate in member lookup.
        for directive in named_children(body) {
            if directive.has_error() || directive.is_missing() {
                let site = self.add_site(directive, ResolutionSiteKind::UnsupportedDeclaration);
                self.add_gap(site, ResolutionGapKind::MalformedSyntax);
            }
            let type_names = match directive.kind() {
                "uses_module_directive" => directive
                    .child_by_field_name("type")
                    .into_iter()
                    .collect::<Vec<_>>(),
                "provides_module_directive" => {
                    // The grammar fields the service as provided and later
                    // providers as provider, but the first provider is an
                    // unfielded named child. Every direct name is a type.
                    named_children(directive)
                        .into_iter()
                        .filter(|child| matches!(child.kind(), "identifier" | "scoped_identifier"))
                        .collect()
                }
                _ => Vec::new(),
            };
            for type_node in type_names {
                self.lower_named_type_reference(type_node);
            }
        }
        // Keep the existing full-tree legacy type-identifier census, while
        // excluding non-member module/package names from native occurrences.
        self.suppress_semantics()
    }

    // A dotted type name is a `scoped_identifier` in declarations and
    // annotations, but a `field_access` where the grammar admits an
    // expression, such as the receiver of an `Outer.Inner::new` reference.
    fn lower_named_type_reference(&mut self, node: Node<'_>) -> ResolutionTypeSlotId {
        if let Some(slot) = self.type_slots_by_node.get(&node.id()) {
            return *slot;
        }
        if node.has_error() || node.is_missing() {
            return self.lower_gap_type(node, ResolutionGapKind::MalformedSyntax);
        }
        if matches!(node.kind(), "identifier" | "type_identifier") {
            return self.lower_plain_type_reference(node);
        }

        let mut current = node;
        let mut members = Vec::new();
        while let Some((scope_field, name_field)) = match current.kind() {
            "scoped_identifier" => Some(("scope", "name")),
            "field_access" => Some(("object", "field")),
            _ => None,
        } {
            let (Some(scope), Some(name)) = (
                current.child_by_field_name(scope_field),
                current.child_by_field_name(name_field),
            ) else {
                return self.lower_unsupported_type(node);
            };
            members.push((current, name));
            current = scope;
        }
        if members.is_empty() || !matches!(current.kind(), "identifier" | "type_identifier") {
            return self.lower_unsupported_type(node);
        }

        let root_slot = self.lower_plain_type_reference(current);
        let root_reference = self.slot(root_slot).site;
        let mut qualifier = root_slot;
        let mut qualified_sites = Vec::with_capacity(members.len());
        for (qualified, name) in members.iter().rev().copied() {
            let reference = self.add_identifier_site(
                name,
                ResolutionSiteKind::MemberReference,
                self.current_scope(),
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Type,
                Some(qualifier),
            );
            let output = self.add_slot(reference, ResolutionTypeSlotRole::TargetTypeIdentity);
            self.facts.binding_projections.push(BindingProjectionFact {
                reference,
                output,
                kind: BindingProjectionKind::TargetTypeIdentity,
            });
            self.type_slots_by_node.insert(name.id(), output);
            self.type_slots_by_node.insert(qualified.id(), output);
            qualified_sites.push(reference);
            qualifier = output;
        }

        let terminal = self.slot(qualifier).site;
        let mut route_segments = vec![self.intern_name(node_text(current, self.source))];
        route_segments.extend(
            members
                .iter()
                .rev()
                .map(|(_, name)| self.intern_name(node_text(*name, self.source))),
        );
        route_segments
            .pop()
            .expect("qualified type name has a terminal name");
        self.record_rooted_type_route(
            ResolutionRootReferenceFact {
                reference: terminal,
                root_scope: self.facts.scopes[0].id,
                anchor: ResolutionRootImportAnchor::Lexical,
                prefix_reference: Some(root_reference),
                owner_continued: false,
            },
            route_segments,
        );
        self.add_gap(root_reference, ResolutionGapKind::AmbiguousQualifiedType);
        for site in qualified_sites {
            self.add_gap(site, ResolutionGapKind::AmbiguousQualifiedType);
        }
        qualifier
    }

    fn lower_package_declaration<'tree>(
        &mut self,
        node: Node<'tree>,
        syntax: &JavaPackageSyntax<'tree, 'source>,
    ) -> TreeWalkAction {
        let root_scope = ResolutionScopeId::new(0);
        if !self.supported_directive_nodes.contains(&node.id()) {
            return self.reject_misplaced_directive(node, ResolutionSiteKind::PackageDeclaration);
        }
        let declaration =
            self.add_site_in_scope(node, ResolutionSiteKind::PackageDeclaration, root_scope);
        assert!(
            self.package_declaration.is_none(),
            "legal package-prefix phase permits only one declaration"
        );
        self.package_declaration = Some(declaration);

        let mut annotation_has_error = false;
        let mut cursor = node.walk();
        for annotation in node.named_children(&mut cursor).filter(|child| {
            !child.is_extra() && matches!(child.kind(), "annotation" | "marker_annotation")
        }) {
            let annotation_site = self.add_site_in_scope(
                annotation,
                ResolutionSiteKind::UnsupportedDeclaration,
                root_scope,
            );
            let malformed =
                annotation.is_error() || annotation.is_missing() || annotation.has_error();
            let kind = if malformed {
                ResolutionGapKind::MalformedSyntax
            } else {
                ResolutionGapKind::UnsupportedExpression
            };
            self.add_gap(annotation_site, kind);
            self.add_reference_enumeration_gap_if_omitted(annotation, annotation_site, kind);
            annotation_has_error |= malformed;
        }

        let Some(segments) = syntax.segments.as_ref() else {
            self.facts
                .add_route_gap(declaration, ResolutionRouteGap::UnknownPlacement);
            self.add_reference_enumeration_gap_if_omitted(
                node,
                declaration,
                ResolutionGapKind::UnsupportedRoute,
            );
            if node.has_error() && !annotation_has_error {
                self.add_gap(declaration, ResolutionGapKind::MalformedSyntax);
                self.add_reference_enumeration_gap_if_omitted(
                    node,
                    declaration,
                    ResolutionGapKind::MalformedSyntax,
                );
            }
            self.package_is_invalid = true;
            return self.suppress_semantics();
        };
        assert!(
            !segments.is_empty(),
            "package directive collector must return at least one segment"
        );
        self.package_segment_names = segments
            .iter()
            .map(|(_, spelling)| self.intern_name(spelling))
            .collect();
        if node.has_error() && !annotation_has_error {
            self.add_gap(declaration, ResolutionGapKind::MalformedSyntax);
            self.add_reference_enumeration_gap_if_omitted(
                node,
                declaration,
                ResolutionGapKind::MalformedSyntax,
            );
        }
        self.suppress_semantics()
    }

    fn lower_import_declaration<'tree>(
        &mut self,
        node: Node<'tree>,
        syntax: &JavaImportSyntax<'tree, 'source>,
    ) -> TreeWalkAction {
        let root_scope = ResolutionScopeId::new(0);
        if !self.supported_directive_nodes.contains(&node.id()) {
            return self.reject_misplaced_directive(node, ResolutionSiteKind::ImportDeclaration);
        }
        let site = self.add_site_in_scope(node, ResolutionSiteKind::ImportDeclaration, root_scope);
        if node.has_error() {
            self.add_gap(site, ResolutionGapKind::MalformedSyntax);
            self.add_reference_enumeration_gap_if_omitted(
                node,
                site,
                ResolutionGapKind::MalformedSyntax,
            );
        }
        let Some(segments) = syntax.segments.as_ref() else {
            self.facts.add_route_gap(
                site,
                ResolutionRouteGap::UnknownBinder {
                    scope: root_scope,
                    name: None,
                    namespace: (!syntax.is_static).then_some(ResolutionNamespace::Type),
                    may_publish: false,
                },
            );
            self.add_reference_enumeration_gap_if_omitted(
                node,
                site,
                ResolutionGapKind::UnsupportedRoute,
            );
            return self.suppress_semantics();
        };

        let is_static = syntax.is_static;
        let is_on_demand = syntax.is_wildcard;
        let kind = match (is_static, is_on_demand) {
            (false, false) => ResolutionImportRouteKind::SingleType,
            (false, true) => ResolutionImportRouteKind::TypeOnDemand,
            (true, false) => ResolutionImportRouteKind::SingleStatic,
            (true, true) => ResolutionImportRouteKind::StaticOnDemand,
        };
        let names = segments
            .iter()
            .map(|(_, spelling)| self.intern_name(spelling))
            .collect::<Vec<_>>();
        let bound_name = matches!(
            kind,
            ResolutionImportRouteKind::SingleType | ResolutionImportRouteKind::SingleStatic
        )
        .then(|| {
            *names
                .last()
                .expect("single-name import has a terminal name")
        });
        self.facts.import_routes.push(ResolutionImportRouteFact {
            site,
            root_scope,
            kind,
            bound_name,
        });
        self.facts
            .import_route_segments
            .extend(names.iter().copied().enumerate().map(|(ordinal, name)| {
                ResolutionImportRouteSegmentFact {
                    import_site: site,
                    ordinal: dense_ordinal(ordinal, "import route segment"),
                    name,
                }
            }));
        let root_segments = match kind {
            ResolutionImportRouteKind::SingleType | ResolutionImportRouteKind::SingleStatic
                if names.len() > 1 =>
            {
                Some(&names[..names.len() - 1])
            }
            ResolutionImportRouteKind::TypeOnDemand | ResolutionImportRouteKind::StaticOnDemand => {
                Some(names.as_slice())
            }
            ResolutionImportRouteKind::SingleType | ResolutionImportRouteKind::SingleStatic => None,
            ResolutionImportRouteKind::Named | ResolutionImportRouteKind::Star => {
                unreachable!("Java imports use Java-specific route kinds")
            }
        };
        if let Some(segments) = root_segments {
            self.facts.root_imports.push(ResolutionRootImportFact {
                site,
                root_scope,
                anchor: ResolutionRootImportAnchor::Lexical,
                position: None,
            });
            self.facts
                .root_import_kinds
                .push(ResolutionRootImportKindFact {
                    import_site: site,
                    kind: if bound_name.is_some() {
                        ResolutionRootImportKind::Named
                    } else {
                        ResolutionRootImportKind::Glob
                    },
                });
            self.facts
                .root_import_segments
                .extend(
                    segments
                        .iter()
                        .copied()
                        .enumerate()
                        .map(|(position, name)| ResolutionRootImportSegmentFact {
                            import_site: site,
                            position: dense_ordinal(position, "Java root import segment"),
                            name,
                        }),
                );
            match kind {
                ResolutionImportRouteKind::SingleType => {
                    self.facts
                        .root_import_demands
                        .push(ResolutionRootImportDemandFact {
                            import_site: site,
                            namespace: ResolutionNamespace::Type,
                            name: bound_name.expect("single-type import has a terminal name"),
                        });
                }
                ResolutionImportRouteKind::TypeOnDemand => {
                    self.pending_type_on_demand_imports.push(site);
                }
                ResolutionImportRouteKind::SingleStatic
                | ResolutionImportRouteKind::StaticOnDemand => {
                    self.pending_static_imports.push((site, bound_name));
                }
                ResolutionImportRouteKind::Named | ResolutionImportRouteKind::Star => {
                    unreachable!("Java imports use Java-specific route kinds")
                }
            }
        }
        if kind == ResolutionImportRouteKind::SingleType {
            // Import path segments name canonical types independently of lexical names
            // in the importing file. Keep its binder separate from this source
            // reference so usage consumers retain the import edge kind.
            for (position, &(segment, _)) in segments.iter().enumerate() {
                let slot = self.lower_plain_type_reference(segment);
                let reference = self.slot(slot).site;
                self.record_rooted_type_route(
                    ResolutionRootReferenceFact {
                        reference,
                        root_scope,
                        anchor: ResolutionRootImportAnchor::Absolute,
                        prefix_reference: None,
                        owner_continued: false,
                    },
                    names[..position].to_vec(),
                );
            }
        }
        // The source route is exact, but selecting its destination package,
        // owner, and declaration inventory remains operation-local.
        self.facts.add_route_gap(
            site,
            ResolutionRouteGap::UnknownBinder {
                scope: root_scope,
                name: bound_name,
                namespace: matches!(
                    kind,
                    ResolutionImportRouteKind::SingleType | ResolutionImportRouteKind::TypeOnDemand
                )
                .then_some(ResolutionNamespace::Type),
                may_publish: false,
            },
        );
        self.suppress_semantics()
    }

    fn finish_root_import_demands(&mut self) {
        let rooted_references = self
            .facts
            .root_references
            .iter()
            .map(|reference| reference.reference)
            .collect::<HashSet<_>>();
        // Keep on-demand routes even when a single-type import binds the name.
        // Shared ranking selects the single import and retains the defeated
        // wildcard binder as evidence for a complete lookup.
        let mut seen = HashSet::default();
        let demands = self
            .facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == ResolutionNamespace::Type
                    && identifier.qualifier.is_none()
                    && !rooted_references.contains(&identifier.site)
                    && seen.insert(identifier.name)
            })
            .map(|identifier| (identifier.namespace, identifier.name))
            .collect::<Vec<_>>();
        self.facts
            .extend_root_import_demands(&self.pending_type_on_demand_imports, &demands);

        // A static import can expose a nested type, a field, or a method. The
        // source reference supplies the requested namespace; selecting a
        // declaration and proving staticness remain contextual work. An
        // ambiguous expression name keeps both effective alternatives, just
        // as lexical lowering does, rather than guessing from its spelling.
        let mut seen = HashSet::default();
        let mut demands = Vec::new();
        for identifier in &self.facts.identifiers {
            if identifier.role != ResolutionIdentifierRole::Reference
                || rooted_references.contains(&identifier.site)
                || identifier.qualifier.is_some()
            {
                continue;
            }
            let namespaces: &[_] = match identifier.namespace {
                ResolutionNamespace::Type => &[ResolutionNamespace::Type],
                ResolutionNamespace::Value => &[ResolutionNamespace::Value],
                ResolutionNamespace::Callable => &[ResolutionNamespace::Callable],
                ResolutionNamespace::TypeOrValue => {
                    &[ResolutionNamespace::Type, ResolutionNamespace::Value]
                }
                _ => &[],
            };
            for &namespace in namespaces {
                if seen.insert((namespace, identifier.name)) {
                    demands.push((namespace, identifier.name));
                }
            }
        }
        for &(import_site, bound_name) in &self.pending_static_imports {
            for &(namespace, name) in &demands {
                if bound_name.is_none_or(|bound| bound == name) {
                    self.facts
                        .root_import_demands
                        .push(ResolutionRootImportDemandFact {
                            import_site,
                            namespace,
                            name,
                        });
                }
            }
        }
    }

    fn validate_directive_facts(&self) {
        let root_scope = ResolutionScopeId::new(0);
        assert!(
            self.facts.packages.len() <= 1,
            "one package placement per compilation-unit root is required"
        );
        if let Some(package) = self.facts.packages.first() {
            assert_eq!(package.root_scope, root_scope);
            let placement = self.site(package.placement_gap_site);
            assert_eq!(placement.scope, root_scope);
            assert!(self.facts.gaps.contains(&ResolutionGapFact::new(
                package.placement_gap_site,
                ResolutionGapKind::UnsupportedPlacementBoundary
            )));

            match package.declaration {
                Some(declaration) => {
                    let declaration = self.site(declaration);
                    assert_eq!(declaration.scope, root_scope);
                    assert_eq!(declaration.kind, ResolutionSiteKind::PackageDeclaration);
                    assert!(
                        !self.facts.package_segments.is_empty(),
                        "named package must have at least one segment"
                    );
                }
                None => assert!(
                    self.facts.package_segments.is_empty(),
                    "unnamed package cannot have segments"
                ),
            }
            for (ordinal, segment) in self.facts.package_segments.iter().enumerate() {
                assert_eq!(segment.root_scope, root_scope);
                assert_eq!(segment.ordinal, dense_ordinal(ordinal, "package segment"));
                assert!(segment.name.index() < self.facts.names.len());
            }
        } else {
            assert!(
                self.facts.package_segments.is_empty(),
                "package segments require a package placement"
            );
        }

        let mut route_sites = HashSet::default();
        let mut validated_segments = 0usize;
        for route in &self.facts.import_routes {
            assert!(
                route_sites.insert(route.site),
                "one supported route per import site is required"
            );
            assert_eq!(route.root_scope, root_scope);
            let site = self.site(route.site);
            assert_eq!(site.scope, root_scope);
            assert_eq!(site.kind, ResolutionSiteKind::ImportDeclaration);
            assert!(self.facts.gaps.iter().any(
                |gap| gap.site == route.site && gap.kind == ResolutionGapKind::UnsupportedRoute
            ));

            let segments = self
                .facts
                .import_route_segments
                .iter()
                .filter(|segment| segment.import_site == route.site)
                .collect::<Vec<_>>();
            assert!(
                !segments.is_empty(),
                "structured import must include at least one route segment"
            );
            for (ordinal, segment) in segments.iter().enumerate() {
                assert_eq!(
                    segment.ordinal,
                    dense_ordinal(ordinal, "import route segment")
                );
                assert!(segment.name.index() < self.facts.names.len());
            }
            match route.kind {
                ResolutionImportRouteKind::SingleType | ResolutionImportRouteKind::SingleStatic => {
                    assert_eq!(
                        Some(segments.last().expect("route has segments").name),
                        route.bound_name,
                        "single-name import must bind its terminal segment"
                    )
                }
                ResolutionImportRouteKind::TypeOnDemand
                | ResolutionImportRouteKind::StaticOnDemand => assert!(
                    route.bound_name.is_none(),
                    "on-demand import cannot bind one source-owned name"
                ),
                ResolutionImportRouteKind::Named | ResolutionImportRouteKind::Star => {
                    unreachable!("Java imports use Java-specific route kinds")
                }
            }
            validated_segments += segments.len();
        }
        assert_eq!(
            validated_segments,
            self.facts.import_route_segments.len(),
            "import route segments cannot be orphaned"
        );
    }

    pub(super) fn exit_scope(&mut self) {
        match self
            .exit_actions
            .pop()
            .expect("every requested Java tree exit has an action")
        {
            ExitAction::Scope => {
                assert!(self.scope_stack.len() > 1, "cannot exit the root scope");
                self.scope_stack.pop();
                if matches!(
                    self.exit_actions.last(),
                    Some(ExitAction::SyntheticTypeContext)
                ) {
                    self.exit_actions.pop();
                    self.exit_type_context();
                }
            }
            ExitAction::TypeContext => self.exit_type_context(),
            ExitAction::TypeContextWithParameters => {
                self.exit_type_context();
                self.exit_type_parameter_scope();
            }
            ExitAction::SyntheticTypeContext => {
                unreachable!("synthetic type contexts exit with their body scope")
            }
            ExitAction::CallableContext => {
                let context = self
                    .callable_contexts
                    .pop()
                    .expect("callable context exit must balance");
                assert_eq!(
                    self.declaration_contexts.pop(),
                    Some(context.declaration),
                    "callable declaration containment must balance"
                );
            }
            ExitAction::CallableContextWithParameters => {
                let context = self
                    .callable_contexts
                    .pop()
                    .expect("callable context exit must balance");
                assert_eq!(
                    self.declaration_contexts.pop(),
                    Some(context.declaration),
                    "callable declaration containment must balance"
                );
                self.exit_type_parameter_scope();
            }
            ExitAction::LambdaContext => {
                let context = self
                    .lambda_contexts
                    .pop()
                    .expect("lambda context exit must balance");
                assert!(self.scope_stack.len() > 1, "cannot exit the root scope");
                assert_eq!(self.scope_stack.pop(), Some(context.scope));
            }
            ExitAction::Suppression => {
                assert!(self.suppression_depth > 0);
                self.suppression_depth -= 1;
            }
        }
    }

    fn exit_type_context(&mut self) {
        let context = self
            .type_contexts
            .pop()
            .expect("type context exit must balance");
        assert_eq!(
            self.declaration_contexts.pop(),
            Some(context.declaration),
            "type declaration containment must balance"
        );
        let implicit_hierarchy = match context.flavor {
            TypeFlavor::Class => !context.has_explicit_superclass,
            TypeFlavor::Interface => !context.has_explicit_superinterface,
            TypeFlavor::Enum | TypeFlavor::Record | TypeFlavor::Annotation => true,
        };
        if context.flavor == TypeFlavor::Class && !context.has_explicit_superclass {
            if !context.is_java_lang_object {
                self.add_implicit_object_supertype(context.declaration);
            }
        } else if implicit_hierarchy {
            self.add_gap(
                context.declaration,
                ResolutionGapKind::UnsupportedHierarchyTraversal,
            );
        }
    }

    fn exit_type_parameter_scope(&mut self) {
        assert!(self.scope_stack.len() > 1, "cannot exit the root scope");
        self.scope_stack.pop();
    }

    fn current_scope(&self) -> ResolutionScopeId {
        brokk_bifrost_core::analyzer::resolution_facts::current_scope_id(
            &self.scope_stack,
            "root scope is always present",
        )
    }

    fn scope(&self, id: ResolutionScopeId) -> &ResolutionScopeFact {
        self.facts.scope(id)
    }

    fn site(&self, id: ResolutionSiteId) -> &ResolutionSiteFact {
        resolution_site(&self.facts, id)
    }

    fn allocate_scope(
        &mut self,
        parent: ResolutionScopeId,
        owner: Option<ResolutionSiteId>,
        kind: ResolutionScopeKind,
        start_byte: usize,
        end_byte: usize,
    ) -> ResolutionScopeId {
        self.facts
            .allocate_lexical_scope(parent, owner, kind, start_byte, end_byte)
    }

    fn add_site(&mut self, node: Node<'_>, kind: ResolutionSiteKind) -> ResolutionSiteId {
        self.add_site_in_scope(node, kind, self.current_scope())
    }

    fn add_site_in_scope(
        &mut self,
        node: Node<'_>,
        kind: ResolutionSiteKind,
        scope: ResolutionScopeId,
    ) -> ResolutionSiteId {
        let occurrence = self.source_collector.intern_node(node);
        self.add_site_from_occurrence(occurrence, kind, scope)
    }

    fn add_site_from_occurrence(
        &mut self,
        occurrence: SourceOccurrenceId,
        kind: ResolutionSiteKind,
        scope: ResolutionScopeId,
    ) -> ResolutionSiteId {
        let range = self.source_collector.occurrence(occurrence).range;
        let id = self
            .facts
            .add_site(scope, kind, range.start_byte, range.end_byte);
        self.site_occurrences.push(occurrence);
        id
    }

    fn record_declaration_source(
        &mut self,
        node: Node<'_>,
        site: ResolutionSiteId,
    ) -> SourceDeclarationId {
        let name = node.child_by_field_name("name");
        self.record_declaration_source_with_name(node, name, site)
    }

    fn record_declaration_source_with_name(
        &mut self,
        node: Node<'_>,
        name: Option<Node<'_>>,
        site: ResolutionSiteId,
    ) -> SourceDeclarationId {
        let declaration = self.source_collector.declare_node(node, name);
        self.declaration_sources.push((site, declaration));
        assert!(
            self.declaration_sites.insert(node.id(), site).is_none(),
            "one Java declaration node has one native declaration site"
        );
        declaration
    }

    fn intern_name(&mut self, spelling: &str) -> ResolutionNameId {
        self.facts.intern_name(&mut self.name_ids, spelling)
    }

    fn add_identifier_to_site(
        &mut self,
        site: ResolutionSiteId,
        node: Node<'_>,
        role: ResolutionIdentifierRole,
        namespace: ResolutionNamespace,
        qualifier: Option<ResolutionTypeSlotId>,
    ) {
        let name = self.record_identifier_to_site(site, node, role, namespace, qualifier);
        if role == ResolutionIdentifierRole::Reference
            && qualifier.is_none()
            && matches!(
                namespace,
                ResolutionNamespace::TypeOrValue
                    | ResolutionNamespace::Value
                    | ResolutionNamespace::Callable
            )
            && (self.unsupported_implicit_receiver_context_depth > 0
                || self.scope_has_unsupported_implicit_receiver(self.site(site).scope))
            && !self.has_visible_local_value(name, self.site(site).scope, node.start_byte())
        {
            self.add_gap(site, ResolutionGapKind::UnsupportedImplicitReceiver);
        }
    }

    fn add_explicit_this_identifier_to_site(
        &mut self,
        site: ResolutionSiteId,
        node: Node<'_>,
        role: ResolutionIdentifierRole,
        namespace: ResolutionNamespace,
    ) {
        self.record_identifier_to_site(site, node, role, namespace, None);
        if self.unsupported_implicit_receiver_context_depth > 0
            || self.explicit_this_is_in_static_context()
        {
            self.add_gap(site, ResolutionGapKind::UnsupportedExpression);
        }
    }

    fn explicit_this_is_in_static_context(&self) -> bool {
        let Some(type_body_scope) = self
            .type_contexts
            .last()
            .and_then(|context| context.body_scope)
        else {
            return false;
        };
        let mut scope = self.current_scope();
        while scope != type_body_scope {
            if self.unsupported_implicit_receiver_scopes.contains(&scope) {
                return true;
            }
            let Some(parent) = self.scope(scope).parent else {
                return false;
            };
            scope = parent;
        }
        false
    }

    fn record_identifier_to_site(
        &mut self,
        site: ResolutionSiteId,
        node: Node<'_>,
        role: ResolutionIdentifierRole,
        namespace: ResolutionNamespace,
        qualifier: Option<ResolutionTypeSlotId>,
    ) -> ResolutionNameId {
        let spelling = node_text(node, self.source).trim();
        assert!(
            !spelling.is_empty(),
            "identifier token must have a spelling"
        );
        self.claimed_identifier_nodes.insert(node.id());
        let name = self.intern_name(spelling);
        self.facts.identifiers.push(PositionedIdentifierFact {
            site,
            name,
            role,
            namespace,
            qualifier,
        });
        if role == ResolutionIdentifierRole::Reference {
            let owner = self
                .reference_enclosing_declaration_overrides
                .last()
                .copied()
                .or_else(|| self.declaration_contexts.last().copied());
            self.facts
                .reference_owners
                .push(ResolutionReferenceOwnerFact {
                    reference: site,
                    owner,
                });
        }
        name
    }

    fn add_identifier_site(
        &mut self,
        node: Node<'_>,
        kind: ResolutionSiteKind,
        scope: ResolutionScopeId,
        role: ResolutionIdentifierRole,
        namespace: ResolutionNamespace,
        qualifier: Option<ResolutionTypeSlotId>,
    ) -> ResolutionSiteId {
        let site = self.add_site_in_scope(node, kind, scope);
        self.add_identifier_to_site(site, node, role, namespace, qualifier);
        site
    }

    fn add_slot(
        &mut self,
        site: ResolutionSiteId,
        role: ResolutionTypeSlotRole,
    ) -> ResolutionTypeSlotId {
        self.facts.allocate_type_slot(site, role)
    }

    fn add_transfer(
        &mut self,
        input: ResolutionTypeSlotId,
        output: ResolutionTypeSlotId,
        kind: ResolutionTypeTransferKind,
    ) {
        let value_transform = match kind {
            ResolutionTypeTransferKind::DeclaredType | ResolutionTypeTransferKind::Construction => {
                ResolutionTypeTransferValueTransform::ToRuntime { addressable: false }
            }
            ResolutionTypeTransferKind::TypeIdentity
            | ResolutionTypeTransferKind::TypeUnion
            | ResolutionTypeTransferKind::ValueJoin
            | ResolutionTypeTransferKind::Initialization
            | ResolutionTypeTransferKind::Contextual
            | ResolutionTypeTransferKind::ExpressionResult
            | ResolutionTypeTransferKind::Assignment
            | ResolutionTypeTransferKind::Receiver
            | ResolutionTypeTransferKind::Argument
            | ResolutionTypeTransferKind::Return
            | ResolutionTypeTransferKind::ComponentElement
            | ResolutionTypeTransferKind::ComponentKey
            | ResolutionTypeTransferKind::ComponentValue
            | ResolutionTypeTransferKind::ComponentIndex
            | ResolutionTypeTransferKind::ComponentIndexOk
            | ResolutionTypeTransferKind::ComponentCommaOkValue
            | ResolutionTypeTransferKind::ComponentSlice => {
                ResolutionTypeTransferValueTransform::Preserve
            }
            ResolutionTypeTransferKind::NumericPromotion
            | ResolutionTypeTransferKind::StringConcatenation => {
                ResolutionTypeTransferValueTransform::RuntimeOnly
            }
            ResolutionTypeTransferKind::Unwrap => {
                unreachable!("Java has no Option/Result payload layer to unwrap")
            }
            ResolutionTypeTransferKind::UnaryIndirection
            | ResolutionTypeTransferKind::AddressOf => {
                unreachable!("Java has no pointer-type or runtime pointer dereference operator")
            }
            ResolutionTypeTransferKind::TypeAlias => {
                unreachable!("Java has no type alias qualifier transfer")
            }
        };
        self.add_transfer_with_transform(input, output, kind, value_transform);
    }

    fn add_transfer_with_transform(
        &mut self,
        input: ResolutionTypeSlotId,
        output: ResolutionTypeSlotId,
        kind: ResolutionTypeTransferKind,
        value_transform: ResolutionTypeTransferValueTransform,
    ) {
        assert_ne!(input, output);
        self.facts
            .type_transfers
            .push(ResolutionTypeTransferFact::new(
                input,
                output,
                kind,
                0,
                0,
                value_transform,
            ));
    }

    /// Put Java type parameters in a declaration-local lexical scope and
    /// connect each parameter identity to every written upper bound. The
    /// bounds are producer facts; the shared resolver sees ordinary type
    /// identities and union transfers, with no Java-specific lookup rule.
    fn lower_java_type_parameters(&mut self, owner_node: Node<'_>, owner: ResolutionSiteId) {
        let parameters = java_declared_type_parameters(owner_node);
        if parameters.is_empty() {
            return;
        }
        let scope = self.allocate_scope(
            self.current_scope(),
            Some(owner),
            ResolutionScopeKind::Block,
            owner_node.start_byte(),
            owner_node.end_byte(),
        );
        self.scope_stack.push(scope);
        assert!(self.type_parameter_scopes.insert(owner));
        let scope_fact = *self.scope(scope);
        let mut lowered = Vec::with_capacity(parameters.len());
        for (position, parameter) in parameters.into_iter().enumerate() {
            let Some(name_node) = java_type_parameter_name_node(parameter) else {
                continue;
            };
            let declaration = self.add_identifier_site(
                name_node,
                ResolutionSiteKind::TypeDeclaration,
                scope,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Type,
                None,
            );
            self.record_declaration_source(parameter, declaration);
            self.facts.binders.push(ResolutionBinderFact {
                declaration,
                scope,
                kind: ResolutionBinderKind::Type,
                hoisting: HoistingClass::ScopeWide,
                activation_start: scope_fact.start_byte,
                activation_end: scope_fact.end_byte,
            });
            let identity = self.add_slot(declaration, ResolutionTypeSlotRole::TargetTypeIdentity);
            self.facts
                .declaration_type_slots
                .push(DeclarationTypeSlotFact {
                    declaration,
                    slot: identity,
                    role: DeclarationTypeRole::Identity,
                });
            let name = self.intern_name(node_text(name_node, self.source));
            let position = dense_ordinal(position, "Java type parameter");
            let previous = self
                .type_parameter_positions
                .entry(owner)
                .or_default()
                .insert(name, position);
            assert!(previous.is_none(), "Java type-parameter names are unique");
            lowered.push((parameter, declaration, identity));
        }

        for (parameter, declaration, identity) in lowered {
            let bounds = java_type_parameter_bounds(parameter);
            if bounds.is_empty() {
                // JLS 4.4 supplies java.lang.Object here. Until the platform
                // type is selected from the indexed workspace, retain the
                // missing upper-bound surface as an explicit frontier.
                self.add_gap(
                    declaration,
                    ResolutionGapKind::UnsupportedHierarchyTraversal,
                );
                continue;
            }
            for bound in bounds {
                self.reference_enclosing_declaration_overrides
                    .push(declaration);
                let bound_slot = self.lower_type(bound);
                assert_eq!(
                    self.reference_enclosing_declaration_overrides.pop(),
                    Some(declaration),
                    "Java type-bound reference owner must balance"
                );
                let reference = self.slot(bound_slot).site;
                let relation = ResolutionTypeRelationId::try_from_index(
                    self.facts.declared_type_relations.len(),
                )
                .expect("Java type-relation count exceeds u32");
                self.facts
                    .declared_type_relations
                    .push(ResolutionDeclaredTypeRelationFact {
                        id: relation,
                        subject: identity,
                        kind: ResolutionDeclaredTypeRelationKind::TraitBound,
                        target_reference: Some(reference),
                        target: Some(bound_slot),
                    });
                crate::call_arguments::publish_jvm_type_union_transfer(
                    &mut self.facts,
                    bound_slot,
                    identity,
                );
            }
        }
    }

    fn lower_java_callable_result_type_parameter(
        &mut self,
        callable: ResolutionSiteId,
        result_type: Node<'_>,
    ) {
        if result_type.kind() != "type_identifier" {
            return;
        }
        let name = self.intern_name(node_text(result_type, self.source));
        if let Some(&position) = self
            .type_parameter_positions
            .get(&callable)
            .and_then(|positions| positions.get(&name))
        {
            self.facts.callable_result_type_parameters.push(
                ResolutionCallableResultTypeParameterFact {
                    callable,
                    position,
                    indirection_delta: 0,
                    reference_indirection_delta: 0,
                },
            );
            return;
        }
        if let Some(owner) = self.type_contexts.last().map(|context| context.declaration)
            && let Some(&position) = self
                .type_parameter_positions
                .get(&owner)
                .and_then(|positions| positions.get(&name))
        {
            self.facts.callable_result_owner_type_parameters.push(
                ResolutionCallableResultTypeParameterFact {
                    callable,
                    position,
                    indirection_delta: 0,
                    reference_indirection_delta: 0,
                },
            );
        }
    }

    fn lower_type_declaration(&mut self, node: Node<'_>) -> Option<TypeContext> {
        let name = node.child_by_field_name("name")?;
        if !is_spelled_identifier(name) {
            return None;
        }
        let flavor = match node.kind() {
            "class_declaration" => TypeFlavor::Class,
            "interface_declaration" => TypeFlavor::Interface,
            "enum_declaration" => TypeFlavor::Enum,
            "record_declaration" => TypeFlavor::Record,
            "annotation_type_declaration" => TypeFlavor::Annotation,
            _ => unreachable!("caller filters Java type declarations"),
        };
        // Abstract classes have JLS default constructors, but direct `new` is
        // forbidden. Until those two facts have separate rows, an abstract
        // class publishes no default constructor site.
        let modifiers = self.source_modifiers_for(node);
        let enclosing_type = self.type_contexts.last().copied();
        let source_type_shape = self.source_type_shape_for(node);
        let publishes_default_constructor = flavor == TypeFlavor::Class
            && !modifiers.is_abstract
            && matches!(
                source_type_shape.constructor_shape,
                Some(JavaTypeConstructorShape::Default)
            );
        let binding_scope = self.current_scope();
        let is_member_type = self.scope(binding_scope).kind == ResolutionScopeKind::TypeBody;
        let is_local_type = binding_scope != ResolutionScopeId::new(0) && !is_member_type;
        let is_static_nested =
            is_member_type && enclosing_type.is_some_and(|_| source_type_shape.is_static);
        let type_name = self.intern_name(node_text(name, self.source));
        let declaration = self.add_identifier_site(
            name,
            ResolutionSiteKind::TypeDeclaration,
            binding_scope,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
            None,
        );
        let source_declaration = self.record_declaration_source(node, declaration);
        if is_local_type {
            self.record_scoped_visibility(declaration);
        } else {
            self.add_declaration_visibility(declaration, node, source_declaration);
        }
        let scope = *self.scope(binding_scope);
        self.facts.binders.push(ResolutionBinderFact {
            declaration,
            scope: binding_scope,
            kind: ResolutionBinderKind::Type,
            hoisting: if is_local_type {
                HoistingClass::SourceOrder
            } else {
                HoistingClass::ScopeWide
            },
            activation_start: if is_local_type {
                node.start_byte()
            } else {
                scope.start_byte
            },
            activation_end: scope.end_byte,
        });
        if enclosing_type.is_none() && binding_scope == ResolutionScopeId::new(0) {
            self.facts.root_exports.push(ResolutionRootExportFact {
                root_scope: binding_scope,
                declaration,
                namespace: ResolutionNamespace::Type,
            });
        }

        if is_member_type && let Some(owner) = enclosing_type {
            self.facts.member_owners.push(ResolutionMemberOwnerFact {
                member: declaration,
                owner: owner.declaration,
                kind: ResolutionMemberKind::NestedType,
                access: ResolutionMemberAccess::Type,
                // Qualified creation looks up this member through the static
                // type of its enclosing expression, not through a runtime value.
                qualifier_compatibility: ResolutionMemberQualifierCompatibility::TypeOnly,
            });
        }
        if is_member_type && let Some(owner) = enclosing_type {
            let requires_enclosing_instance = flavor == TypeFlavor::Class && !is_static_nested;
            if requires_enclosing_instance {
                self.facts
                    .construction_requirements
                    .push(ResolutionConstructionRequirementFact {
                        constructed_type: declaration,
                        required_owner: owner.declaration,
                        kind: ResolutionConstructionRequirementKind::EnclosingInstance,
                    });
            }
        }

        self.lower_java_type_parameters(node, declaration);

        let body_scope = if let Some(body) = node.child_by_field_name("body") {
            let body_scope = self.allocate_scope(
                self.current_scope(),
                Some(declaration),
                ResolutionScopeKind::TypeBody,
                body.start_byte(),
                body.end_byte(),
            );
            self.body_scopes.insert(body.id(), body_scope);
            if is_static_nested {
                assert!(
                    self.unsupported_implicit_receiver_scopes.insert(body_scope),
                    "one Java type-body scope per type declaration"
                );
            }
            if publishes_default_constructor {
                self.lower_default_constructor(
                    body,
                    declaration,
                    type_name,
                    body_scope,
                    source_declaration,
                );
            }
            Some(body_scope)
        } else {
            None
        };
        Some(TypeContext {
            declaration,
            body_scope,
            name: Some(type_name),
            flavor,
            constructor_shape: source_type_shape.constructor_shape,
            is_java_lang_object: enclosing_type.is_none()
                && binding_scope == ResolutionScopeId::new(0)
                && !self.package_is_invalid
                && node_text(name, self.source) == "Object"
                && self.package_segment_names.len() == 2
                && self.facts.names[self.package_segment_names[0].index()].spelling == "java"
                && self.facts.names[self.package_segment_names[1].index()].spelling == "lang",
            has_explicit_superclass: false,
            has_explicit_superinterface: false,
        })
    }

    fn enter_synthetic_class_body(&mut self, body: Node<'_>) {
        let parent = body
            .parent()
            .expect("synthetic Java class body has a parent");
        assert!(
            matches!(
                parent.kind(),
                "object_creation_expression" | "enum_constant"
            ),
            "only anonymous creation and enum-constant bodies are synthetic classes"
        );
        let enclosing = self.type_contexts.last().copied();
        let declaration = self.add_site(body, ResolutionSiteKind::TypeDeclaration);
        let synthetic_name =
            self.intern_name(&crate::anonymous_type::AnonymousTypeBody::name(body));
        let anonymous = crate::anonymous_type::AnonymousTypeBody {
            site: declaration,
            name: synthetic_name,
        };
        anonymous.declare(&mut self.facts);
        // The semantic site owns members inside the anonymous body, but the
        // synthetic type has no source declaration or source visibility.
        if parent.kind() == "object_creation_expression" {
            let scope = *self.scope(self.current_scope());
            self.facts.binders.push(ResolutionBinderFact {
                declaration,
                scope: scope.id,
                kind: ResolutionBinderKind::Type,
                hoisting: HoistingClass::ScopeWide,
                activation_start: scope.start_byte,
                activation_end: scope.end_byte,
            });
        }
        if let Some(result) = self.anonymous_creation_results.remove(&body.id()) {
            // Source navigation still uses the written supertype. This hidden
            // self-reference supplies the allocation's distinct runtime type.
            let reference = self.add_site(body, ResolutionSiteKind::SyntheticReference);
            self.facts.identifiers.push(PositionedIdentifierFact {
                site: reference,
                name: synthetic_name,
                role: ResolutionIdentifierRole::Reference,
                namespace: ResolutionNamespace::Type,
                qualifier: None,
            });
            self.facts
                .reference_owners
                .push(ResolutionReferenceOwnerFact {
                    reference,
                    owner: Some(declaration),
                });
            let identity = self.add_slot(reference, ResolutionTypeSlotRole::TargetTypeIdentity);
            self.facts
                .binding_projections
                .push(BindingProjectionFact::target_type_identity(
                    reference, identity,
                ));
            self.add_transfer(identity, result, ResolutionTypeTransferKind::Construction);
        }
        self.declaration_contexts.push(declaration);

        let has_explicit_superclass = if parent.kind() == "object_creation_expression" {
            if let Some(type_node) = parent.child_by_field_name("type") {
                self.add_supertype(declaration, type_node, ResolutionSupertypeKind::Superclass);
                true
            } else {
                false
            }
        } else {
            let reference = self.add_site(body, ResolutionSiteKind::TypeReference);
            let name = enclosing
                .and_then(|context| context.name)
                .expect("enum constant bodies are nested under their declaring enum");
            self.facts.identifiers.push(PositionedIdentifierFact {
                site: reference,
                name,
                role: ResolutionIdentifierRole::Reference,
                namespace: ResolutionNamespace::Type,
                qualifier: None,
            });
            self.facts
                .reference_owners
                .push(ResolutionReferenceOwnerFact {
                    reference,
                    owner: Some(declaration),
                });
            let slot = self.add_slot(reference, ResolutionTypeSlotRole::TargetTypeIdentity);
            self.facts.binding_projections.push(BindingProjectionFact {
                reference,
                output: slot,
                kind: BindingProjectionKind::TargetTypeIdentity,
            });
            self.add_supertype_edge(declaration, slot, ResolutionSupertypeKind::Superclass);
            true
        };

        let body_scope = anonymous.open_scope(&mut self.facts);
        assert!(
            self.body_scopes.insert(body.id(), body_scope).is_none(),
            "one type-body scope per synthetic Java class body"
        );
        self.type_contexts.push(TypeContext {
            declaration,
            body_scope: Some(body_scope),
            name: None,
            flavor: TypeFlavor::Class,
            constructor_shape: None,
            is_java_lang_object: false,
            has_explicit_superclass,
            has_explicit_superinterface: false,
        });
        self.exit_actions.push(ExitAction::SyntheticTypeContext);
    }

    fn lower_enum_constant(&mut self, node: Node<'_>) {
        let Some(name) = node.child_by_field_name("name") else {
            return;
        };
        if !is_spelled_identifier(name) {
            return;
        }
        let scope_id = self.current_scope();
        let declaration = self.add_identifier_site(
            name,
            ResolutionSiteKind::ValueDeclaration,
            scope_id,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
            None,
        );
        let source_declaration = self.record_declaration_source(node, declaration);
        self.add_declaration_visibility(declaration, node, source_declaration);
        let scope = *self.scope(scope_id);
        self.facts.binders.push(ResolutionBinderFact {
            declaration,
            scope: scope_id,
            kind: ResolutionBinderKind::Field,
            hoisting: HoistingClass::ScopeWide,
            activation_start: scope.start_byte,
            activation_end: scope.end_byte,
        });
        let owner = self
            .type_contexts
            .last()
            .expect("enum constants are nested under their enum type");
        assert_eq!(owner.flavor, TypeFlavor::Enum);
        self.facts.member_owners.push(ResolutionMemberOwnerFact {
            member: declaration,
            owner: owner.declaration,
            kind: ResolutionMemberKind::Field,
            access: ResolutionMemberAccess::Type,
            qualifier_compatibility: ResolutionMemberQualifierCompatibility::RuntimeOrType,
        });
    }

    fn lower_switch_selector(&mut self, node: Node<'_>) {
        if let Some(selector) = node.child_by_field_name("condition") {
            self.lower_expression(selector);
        }
    }

    fn lower_record_pattern_type(&mut self, pattern: Node<'_>) {
        // This grammar has positional children, not type/name fields:
        // the nominal header precedes record_pattern_body. Nested patterns
        // are visited by the ordinary iterative tree walk.
        let Some(type_node) = named_children(pattern)
            .into_iter()
            .find(|child| !child.is_extra())
        else {
            let site = self.add_site(pattern, ResolutionSiteKind::UnsupportedDeclaration);
            self.add_gap(site, ResolutionGapKind::MalformedSyntax);
            return;
        };
        match type_node.kind() {
            "identifier" => {
                self.lower_named_type_reference(type_node);
            }
            "generic_type" => {
                self.lower_type(type_node);
            }
            _ => {
                let site = self.add_site(pattern, ResolutionSiteKind::UnsupportedDeclaration);
                self.add_gap(site, ResolutionGapKind::MalformedSyntax);
            }
        }
    }

    fn lower_type_pattern(&mut self, pattern: Node<'_>) {
        // type_pattern and record_pattern_component have positional children:
        // type syntax followed by the binding identifier or unnamed pattern.
        let children = named_children(pattern)
            .into_iter()
            .filter(|child| !child.is_extra())
            .collect::<Vec<_>>();
        let Some(type_index) = children
            .iter()
            .position(|child| self.is_type_syntax(child.kind()))
        else {
            let site = self.add_site(pattern, ResolutionSiteKind::UnsupportedDeclaration);
            self.add_gap(site, ResolutionGapKind::UnsupportedScopeOrBinder);
            return;
        };
        let type_node = children[type_index];
        // The pattern's type is a reference independently of its binding
        // variable (JLS 14.30.1). Keep it even when the pattern declares a
        // name, which is the common `case Circle circle` form.
        self.lower_type(type_node);
        let Some(name) = children.get(type_index + 1).copied() else {
            return;
        };
        if name.kind() == "underscore_pattern" {
            return;
        }
        if !is_spelled_identifier(name) {
            let site = self.add_site(pattern, ResolutionSiteKind::UnsupportedDeclaration);
            self.add_gap(site, ResolutionGapKind::UnsupportedScopeOrBinder);
            return;
        }
        let (Some(head), Some(arm)) = (
            nearest_ancestor(pattern, |kind| kind == "pattern"),
            nearest_ancestor(pattern, |kind| {
                matches!(kind, "switch_rule" | "switch_block_statement_group")
            }),
        ) else {
            // instanceof flow scopes do not have a match arm. Preserve the
            // type occurrence and report the unmodeled binder locally.
            let site = self.add_site(pattern, ResolutionSiteKind::UnsupportedDeclaration);
            self.add_gap(site, ResolutionGapKind::UnsupportedScopeOrBinder);
            return;
        };
        let scope_id = self.current_scope();
        let scope = *self.scope(scope_id);
        assert_eq!(scope.start_byte, arm.start_byte());
        assert_eq!(scope.end_byte, arm.end_byte());
        let declaration = self.add_identifier_site(
            name,
            ResolutionSiteKind::ValueDeclaration,
            scope_id,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
            None,
        );
        let source_declaration =
            self.record_declaration_source_with_name(pattern, Some(name), declaration);
        self.source_collector
            .mark_lexical(source_declaration, DeclarationKind::LocalVariable);
        self.facts.binders.push(ResolutionBinderFact {
            declaration,
            scope: scope_id,
            kind: ResolutionBinderKind::Pattern,
            hoisting: HoistingClass::DeclaredHead,
            activation_start: head.end_byte(),
            activation_end: scope.end_byte,
        });
        self.register_local_value_binder(scope_id, name, head.end_byte(), scope.end_byte);
        self.attach_declaration_type(declaration, type_node, DeclarationTypeRole::Value);
        self.attach_implicit_local_initializer(declaration, name);
    }

    fn lower_switch_label(&mut self, label: Node<'_>) {
        let Some(selector) = java_switch_selector_expression(label) else {
            return;
        };
        self.lower_expression(selector);
        let selector_slot = self.expression_slot(selector);
        let constant_variable_selector = self.switch_selector_has_constant_variable_type(selector);
        for expression in named_children(label) {
            if expression.kind() == "pattern" || expression.kind() == "guard" {
                continue;
            }
            if is_spelled_identifier(expression) {
                if constant_variable_selector {
                    self.lower_value_reference_in_namespace(expression, ResolutionNamespace::Value);
                } else {
                    self.lower_qualified_value_reference(expression, selector_slot);
                }
            } else {
                self.lower_expression(expression);
            }
        }
    }

    fn switch_selector_has_constant_variable_type(&self, selector: Node<'_>) -> bool {
        if matches!(selector.kind(), "binary_expression" | "unary_expression") {
            return true;
        }
        if selector.kind() == "cast_expression" {
            return selector
                .child_by_field_name("type")
                .is_some_and(|type_node| {
                    matches!(type_node.kind(), "integral_type" | "floating_point_type")
                });
        }
        let binding = if selector.kind() == "assignment_expression" {
            selector.child_by_field_name("left")
        } else {
            Some(selector)
        };
        let Some(binding) = binding.filter(|node| is_spelled_identifier(*node)) else {
            return false;
        };
        let Some(type_slot) = self.visible_value_type_slot(binding) else {
            return false;
        };
        let Some(source_type_slot) = self
            .facts
            .type_transfers
            .iter()
            .find(|transfer| {
                transfer.output == type_slot
                    && transfer.kind == ResolutionTypeTransferKind::DeclaredType
            })
            .map(|transfer| transfer.input)
        else {
            return false;
        };
        self.facts.intrinsic_type_seeds.iter().any(|seed| {
            seed.output == source_type_slot && seed.kind == IntrinsicTypeKind::Primitive
        })
    }

    fn visible_value_type_slot(&self, reference: Node<'_>) -> Option<ResolutionTypeSlotId> {
        let name = node_text(reference, self.source).trim();
        let name = self.name_ids.get(name).copied()?;
        let mut scope = self.current_scope();
        loop {
            let declaration = self
                .facts
                .identifiers
                .iter()
                .filter(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Declaration
                        && identifier.namespace == ResolutionNamespace::Value
                        && identifier.name == name
                })
                .filter_map(|identifier| {
                    let site = self.site(identifier.site);
                    if site.scope != scope {
                        return None;
                    }
                    let binder = self
                        .facts
                        .binders
                        .iter()
                        .find(|binder| binder.declaration == identifier.site)?;
                    (binder.activation_start <= reference.start_byte()
                        && reference.start_byte() <= binder.activation_end)
                        .then_some((binder.activation_start, identifier.site))
                })
                .max_by_key(|(activation, _)| *activation)
                .map(|(_, declaration)| declaration);
            if let Some(declaration) = declaration {
                return self.declaration_type_slots.get(&declaration).copied();
            }
            let current = self.scope(scope);
            if current.inheritance == ResolutionScopeInheritance::Root {
                return None;
            }
            let parent = current.parent?;
            scope = parent;
        }
    }

    fn lower_qualified_value_reference(&mut self, node: Node<'_>, qualifier: ResolutionTypeSlotId) {
        let reference = self.add_identifier_site(
            node,
            ResolutionSiteKind::MemberReference,
            self.current_scope(),
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Value,
            Some(qualifier),
        );
        let output = self.add_slot(reference, ResolutionTypeSlotRole::ExpressionValue);
        self.facts.binding_projections.push(BindingProjectionFact {
            reference,
            output,
            kind: BindingProjectionKind::TargetDeclaredValueType,
        });
        self.expression_slots_by_node.insert(node.id(), output);
    }

    fn lower_callable_declaration(&mut self, node: Node<'_>) -> Option<CallableContext> {
        let name = node.child_by_field_name("name")?;
        if !is_spelled_identifier(name) || self.current_type_owner().is_none() {
            return None;
        }
        let callable_properties = self.source_callable_shape_for(node).properties();
        let is_constructor = callable_properties.is_constructor;
        let binding_scope = self.current_scope();
        let declaration = self.add_identifier_site(
            name,
            if is_constructor {
                ResolutionSiteKind::ConstructorDeclaration
            } else {
                ResolutionSiteKind::CallableDeclaration
            },
            binding_scope,
            ResolutionIdentifierRole::Declaration,
            if is_constructor {
                ResolutionNamespace::Constructor
            } else {
                ResolutionNamespace::Callable
            },
            None,
        );
        let source_declaration = self.record_declaration_source(node, declaration);
        self.add_declaration_visibility(declaration, node, source_declaration);
        let signature_index = self.facts.callable_signatures.len();
        self.facts
            .callable_signatures
            .push(ResolutionCallableSignatureFact {
                callable: declaration,
                type_parameter_count: dense_ordinal(
                    java_declared_type_parameters(node).len(),
                    "Java callable type parameter",
                ),
                result_types: Vec::new(),
            });
        if node.kind() == "compact_constructor_declaration" {
            // A compact record constructor implicitly has one value parameter
            // per record component. Until those parameters have exact rows,
            // its otherwise empty signature header cannot prove arity.
            self.add_gap(declaration, ResolutionGapKind::UnsupportedCallApplicability);
        }
        if is_constructor {
            let owner = self
                .type_contexts
                .last_mut()
                .expect("constructors are owned by a type context");
            match owner.flavor {
                TypeFlavor::Class => {
                    if let Some(shape) = owner.constructor_shape {
                        assert_eq!(
                            shape,
                            JavaTypeConstructorShape::NoImplicit,
                            "Java constructor admission must agree with the captured type shape"
                        );
                    }
                }
                TypeFlavor::Record | TypeFlavor::Enum => {}
                TypeFlavor::Interface | TypeFlavor::Annotation => {
                    unreachable!("only classes and records declare Java constructors")
                }
            }
        }
        let scope = *self.scope(binding_scope);
        self.facts.binders.push(ResolutionBinderFact {
            declaration,
            scope: binding_scope,
            kind: if is_constructor {
                ResolutionBinderKind::Constructor
            } else {
                ResolutionBinderKind::Callable
            },
            hoisting: HoistingClass::ScopeWide,
            activation_start: scope.start_byte,
            activation_end: scope.end_byte,
        });

        if let Some(owner) = self.current_type_owner() {
            let is_static = callable_properties.is_static;
            self.facts.member_owners.push(ResolutionMemberOwnerFact {
                member: declaration,
                owner,
                kind: if is_constructor {
                    ResolutionMemberKind::Constructor
                } else {
                    ResolutionMemberKind::Method
                },
                access: if is_constructor || is_static {
                    ResolutionMemberAccess::Type
                } else {
                    ResolutionMemberAccess::Instance
                },
                qualifier_compatibility: if is_constructor {
                    ResolutionMemberQualifierCompatibility::TypeOnly
                } else if is_static {
                    ResolutionMemberQualifierCompatibility::RuntimeOrType
                } else {
                    ResolutionMemberQualifierCompatibility::RuntimeOnly
                },
            });
        }

        self.lower_java_type_parameters(node, declaration);

        let body = node.child_by_field_name("body");
        let (body_start, body_end) = body
            .map(|body| (body.start_byte(), body.end_byte()))
            .unwrap_or((node.end_byte(), node.end_byte()));
        let executable_start = node
            .child_by_field_name("parameters")
            .map_or(body_start, |parameters| parameters.start_byte());
        let callable_scope = self.allocate_scope(
            self.current_scope(),
            Some(declaration),
            ResolutionScopeKind::Executable,
            executable_start,
            body_end,
        );
        if !is_constructor && callable_properties.is_static {
            assert!(
                self.unsupported_implicit_receiver_scopes
                    .insert(callable_scope),
                "one Java executable scope per callable declaration"
            );
        }
        if let Some(body) = body {
            self.body_scopes.insert(body.id(), callable_scope);
        }

        if let Some(return_type) = node.child_by_field_name("type") {
            self.reference_enclosing_declaration_overrides
                .push(declaration);
            let value_type =
                self.attach_declaration_type(declaration, return_type, DeclarationTypeRole::Return);
            self.facts.callable_signatures[signature_index]
                .result_types
                .push(ResolutionCallableResultTypeFact {
                    ordinal: 0,
                    value_type,
                });
            self.lower_java_callable_result_type_parameter(declaration, return_type);
            assert_eq!(
                self.reference_enclosing_declaration_overrides.pop(),
                Some(declaration),
                "callable return-type owner override must balance"
            );
        }
        Some(CallableContext {
            declaration,
            scope: callable_scope,
            activation_start: executable_start,
            activation_end: body_end,
            source_node_id: node.id(),
        })
    }

    /// The constructor Java supplies for a class that writes none (JLS 8.8.9):
    /// it takes no arguments and has the class's own access. The class itself
    /// declares it, so its source declaration is the class declaration and a
    /// call that selects it navigates to the class. The class body anchors the
    /// site, since a site must lie within its scope and the body scope does not
    /// reach the class name. The call's result type is the owner.
    fn lower_default_constructor(
        &mut self,
        body: Node<'_>,
        owner: ResolutionSiteId,
        owner_name: ResolutionNameId,
        scope: ResolutionScopeId,
        class_source: SourceDeclarationId,
    ) {
        let site = self.add_site_in_scope(body, ResolutionSiteKind::ConstructorDeclaration, scope);
        self.declaration_sources.push((site, class_source));
        let visibility = self
            .facts
            .declaration_visibilities
            .iter()
            .find(|fact| fact.declaration == owner)
            .expect("a Java class records its visibility before its default constructor")
            .visibility;
        if visibility == DeclaredVisibility::Unknown {
            self.record_scoped_visibility(site);
        } else {
            self.record_declaration_visibility(site, visibility);
        }
        ConstructorSite {
            site,
            owner,
            owner_name,
            scope,
        }
        .publish(&mut self.facts);
        self.facts
            .callable_signatures
            .push(ResolutionCallableSignatureFact {
                callable: site,
                type_parameter_count: 0,
                result_types: Vec::new(),
            });
    }

    fn lower_initializer(&mut self, node: Node<'_>) {
        let site = self.add_site(node, ResolutionSiteKind::Initializer);
        let Some(body) = first_named_child_of_kind(node, "block") else {
            return;
        };
        let scope = self.allocate_scope(
            self.current_scope(),
            Some(site),
            ResolutionScopeKind::Initializer,
            node.start_byte(),
            node.end_byte(),
        );
        if node.kind() == "static_initializer" {
            assert!(
                self.unsupported_implicit_receiver_scopes.insert(scope),
                "one Java initializer scope per initializer declaration"
            );
        }
        self.body_scopes.insert(body.id(), scope);
    }

    fn add_parameter_binder_fact(
        &mut self,
        declaration: ResolutionSiteId,
        scope: ResolutionScopeId,
        activation_start: usize,
        activation_end: usize,
    ) {
        self.facts.binders.push(ResolutionBinderFact {
            declaration,
            scope,
            kind: ResolutionBinderKind::Parameter,
            hoisting: HoistingClass::ScopeWide,
            activation_start,
            activation_end,
        });
    }

    fn next_callable_parameter_ordinal(&mut self, callable: ResolutionSiteId) -> u32 {
        let next = self.next_parameter_ordinal.entry(callable).or_insert(0);
        let ordinal = *next;
        *next += 1;
        ordinal
    }

    fn record_callable_parameter_fact(
        &mut self,
        callable: ResolutionSiteId,
        ordinal: u32,
        parameter: ResolutionSiteId,
        value_type: ResolutionTypeSlotId,
        repeated: bool,
    ) {
        self.facts
            .callable_parameters
            .push(ResolutionCallableParameterFact {
                callable,
                list_ordinal: 0,
                ordinal,
                parameter,
                value_type,
                repeated,
            });
    }

    fn lower_parameter(&mut self, node: Node<'_>) {
        let Some(name) = node.child_by_field_name("name") else {
            return;
        };
        if !is_spelled_identifier(name) {
            return;
        }
        let Some(callable) = self.callable_contexts.last().copied() else {
            return;
        };
        let declaration = self.add_identifier_site(
            name,
            ResolutionSiteKind::ValueDeclaration,
            callable.scope,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
            None,
        );
        let source_declaration = self.record_declaration_source(node, declaration);
        self.source_collector
            .mark_lexical(source_declaration, DeclarationKind::Parameter);
        self.add_parameter_binder_fact(
            declaration,
            callable.scope,
            callable.activation_start,
            callable.activation_end,
        );
        self.register_local_value_binder(
            callable.scope,
            name,
            callable.activation_start,
            callable.activation_end,
        );

        let Some(type_node) = node.child_by_field_name("type") else {
            return;
        };
        let type_node = node.child_by_field_name("dimensions").unwrap_or(type_node);
        let value_type = if type_node.kind() == "dimensions" {
            self.attach_declaration_gap_type(
                declaration,
                type_node,
                DeclarationTypeRole::Parameter,
                ResolutionGapKind::PostfixArrayDimensions,
            )
        } else {
            self.attach_declaration_type(declaration, type_node, DeclarationTypeRole::Parameter)
        };
        let ordinal = self.next_callable_parameter_ordinal(callable.declaration);
        let repeated = self
            .source_callable_shape_for_node(callable.source_node_id)
            .repeated_for(node.id())
            .expect("Java native parameter must have a captured source shape");
        assert!(!repeated, "formal parameters cannot be repeated");
        self.record_callable_parameter_fact(
            callable.declaration,
            ordinal,
            declaration,
            value_type,
            repeated,
        );
    }

    fn lower_spread_parameter(&mut self, node: Node<'_>) -> bool {
        let children = named_children(node);
        let Some(declarator) = children
            .iter()
            .copied()
            .find(|child| child.kind() == "variable_declarator")
        else {
            return false;
        };
        let Some(type_node) = children
            .iter()
            .copied()
            .find(|child| self.is_type_syntax(child.kind()))
        else {
            return false;
        };
        let Some(name) = declarator.child_by_field_name("name") else {
            return false;
        };
        if !is_spelled_identifier(name) {
            return false;
        }
        let Some(callable) = self.callable_contexts.last().copied() else {
            return false;
        };
        let declaration = self.add_identifier_site(
            name,
            ResolutionSiteKind::ValueDeclaration,
            callable.scope,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
            None,
        );
        let source_declaration = self.record_declaration_source(declarator, declaration);
        self.source_collector
            .mark_lexical(source_declaration, DeclarationKind::Parameter);
        self.add_parameter_binder_fact(
            declaration,
            callable.scope,
            callable.activation_start,
            callable.activation_end,
        );
        let value_type = if let Some(dimensions) = declarator.child_by_field_name("dimensions") {
            self.attach_declaration_gap_type(
                declaration,
                dimensions,
                DeclarationTypeRole::Parameter,
                ResolutionGapKind::PostfixArrayDimensions,
            )
        } else {
            self.attach_declaration_type(declaration, type_node, DeclarationTypeRole::Parameter)
        };
        let ordinal = self.next_callable_parameter_ordinal(callable.declaration);
        let repeated = self
            .source_callable_shape_for_node(callable.source_node_id)
            .repeated_for(node.id())
            .expect("Java native spread parameter must have a captured source shape");
        assert!(repeated, "spread parameters must be repeated");
        self.record_callable_parameter_fact(
            callable.declaration,
            ordinal,
            declaration,
            value_type,
            repeated,
        );
        true
    }

    fn lower_resource(&mut self, node: Node<'_>) {
        let Some(name) = node.child_by_field_name("name") else {
            // Java 9 also permits an existing variable or field as a resource.
            if let Some(value) = named_children(node)
                .into_iter()
                .find(|child| matches!(child.kind(), "identifier" | "field_access"))
            {
                self.lower_expression(value);
            } else {
                let site = self.add_site(node, ResolutionSiteKind::UnsupportedDeclaration);
                self.add_gap(site, ResolutionGapKind::MalformedSyntax);
            }
            return;
        };
        let (Some(type_node), Some(value)) = (
            node.child_by_field_name("type"),
            node.child_by_field_name("value"),
        ) else {
            let site = self.add_site(node, ResolutionSiteKind::UnsupportedDeclaration);
            self.add_gap(site, ResolutionGapKind::MalformedSyntax);
            return;
        };
        if name.kind() == "underscore_pattern" {
            self.lower_type(type_node);
            self.lower_expression(value);
            return;
        }
        assert!(is_spelled_identifier(name));
        let statement = node
            .parent()
            .and_then(|resources| resources.parent())
            .expect("a resource belongs to a resource specification and try statement");
        assert_eq!(statement.kind(), "try_with_resources_statement");
        let body = statement
            .child_by_field_name("body")
            .expect("a try-with-resources statement has a body");
        // Earlier resources are visible in later initializers, but not in
        // the catch or finally clauses (JLS 6.3).
        let declaration = self.add_declared_head_local(name, value.end_byte()..body.end_byte());
        let source_declaration = self.record_declaration_source(node, declaration);
        self.source_collector
            .mark_lexical(source_declaration, DeclarationKind::ResourceVariable);
        let source_type = self.capture_source_type(type_node);
        let inferred = node.child_by_field_name("dimensions").is_none()
            && self.source_types.is_inferred_type(source_type);
        let initializer = self.lower_expression(value);
        if inferred {
            self.attach_inferred_local_type(declaration, type_node, initializer);
        } else if let Some(dimensions) = node.child_by_field_name("dimensions") {
            self.attach_declaration_gap_type(
                declaration,
                dimensions,
                DeclarationTypeRole::Value,
                ResolutionGapKind::PostfixArrayDimensions,
            );
        } else {
            self.attach_declaration_type(declaration, type_node, DeclarationTypeRole::Value);
        }
        let observed = self.add_slot(declaration, ResolutionTypeSlotRole::AssignmentValue);
        self.add_transfer(
            initializer,
            observed,
            ResolutionTypeTransferKind::Assignment,
        );
    }

    fn lower_variable_declaration(&mut self, declaration_form: Node<'_>) {
        let is_field = matches!(
            declaration_form.kind(),
            "field_declaration" | "constant_declaration"
        );
        let Some(type_node) = declaration_form.child_by_field_name("type") else {
            return;
        };
        let field_is_static = is_field && self.source_field_shape_for(declaration_form).is_static;
        let scope_id = self.current_scope();
        let scope = *self.scope(scope_id);
        let declaration_children = named_children(declaration_form);
        let single_declarator = declaration_children
            .iter()
            .filter(|child| child.kind() == "variable_declarator")
            .count()
            == 1;
        for node in declaration_children
            .into_iter()
            .filter(|child| child.kind() == "variable_declarator")
        {
            let Some(name) = node.child_by_field_name("name") else {
                continue;
            };
            if !is_spelled_identifier(name) {
                continue;
            }
            let declaration = self.add_identifier_site(
                name,
                ResolutionSiteKind::ValueDeclaration,
                scope_id,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Value,
                None,
            );
            let source_declaration = self.record_declaration_source(node, declaration);
            if is_field {
                self.add_declaration_visibility(declaration, node, source_declaration);
            } else {
                self.source_collector
                    .mark_lexical(source_declaration, DeclarationKind::LocalVariable);
            }
            let activation_start = if is_field {
                scope.start_byte
            } else if let Some(initializer) = node.child_by_field_name("value") {
                initializer.start_byte()
            } else {
                node.end_byte()
            };
            self.facts.binders.push(ResolutionBinderFact {
                declaration,
                scope: scope_id,
                kind: if is_field {
                    ResolutionBinderKind::Field
                } else {
                    ResolutionBinderKind::Local
                },
                hoisting: if is_field {
                    HoistingClass::ScopeWide
                } else {
                    HoistingClass::SourceOrder
                },
                activation_start,
                activation_end: scope.end_byte,
            });
            if !is_field {
                self.register_local_value_binder(scope_id, name, activation_start, scope.end_byte);
            }

            if is_field && let Some(owner) = self.type_contexts.last().copied() {
                self.facts.member_owners.push(ResolutionMemberOwnerFact {
                    member: declaration,
                    owner: owner.declaration,
                    kind: ResolutionMemberKind::Field,
                    access: if field_is_static {
                        ResolutionMemberAccess::Type
                    } else {
                        ResolutionMemberAccess::Instance
                    },
                    qualifier_compatibility: if field_is_static {
                        ResolutionMemberQualifierCompatibility::RuntimeOrType
                    } else {
                        ResolutionMemberQualifierCompatibility::RuntimeOnly
                    },
                });
            }

            let inferred_type = if !is_field
                && single_declarator
                && node.child_by_field_name("dimensions").is_none()
            {
                let source_type = self.capture_source_type(type_node);
                self.source_types.is_inferred_type(source_type)
            } else {
                false
            };
            let inferred_initializer = if inferred_type {
                node.child_by_field_name("value")
                    .map(|value| self.lower_expression(value))
            } else {
                None
            };
            if is_field {
                self.reference_enclosing_declaration_overrides
                    .push(declaration);
            }
            if let Some(initializer) = inferred_initializer {
                self.attach_inferred_local_type(declaration, type_node, initializer);
            } else if let Some(dimensions) = node.child_by_field_name("dimensions") {
                self.attach_declaration_gap_type(
                    declaration,
                    dimensions,
                    DeclarationTypeRole::Value,
                    ResolutionGapKind::PostfixArrayDimensions,
                );
            } else {
                self.attach_declaration_type(declaration, type_node, DeclarationTypeRole::Value);
            }
            if let Some(value) = node.child_by_field_name("value") {
                if field_is_static {
                    self.unsupported_implicit_receiver_context_depth += 1;
                }
                let initializer =
                    inferred_initializer.unwrap_or_else(|| self.lower_expression(value));
                if field_is_static {
                    assert!(self.unsupported_implicit_receiver_context_depth > 0);
                    self.unsupported_implicit_receiver_context_depth -= 1;
                }
                let observed = self.add_slot(declaration, ResolutionTypeSlotRole::AssignmentValue);
                self.add_transfer(
                    initializer,
                    observed,
                    ResolutionTypeTransferKind::Assignment,
                );
            }
            if is_field {
                assert_eq!(
                    self.reference_enclosing_declaration_overrides.pop(),
                    Some(declaration),
                    "field occurrence-owner override must balance"
                );
            }
        }
    }

    fn attach_inferred_local_type(
        &mut self,
        declaration: ResolutionSiteId,
        type_node: Node<'_>,
        initializer: ResolutionTypeSlotId,
    ) {
        // JLS 14.4.1: a local var declaration takes its static type
        // from the initializer's produced value.
        assert_eq!(type_node.kind(), "type_identifier");
        assert!(
            self.claimed_identifier_nodes.insert(type_node.id()),
            "one inferred local declaration claims its var token"
        );
        let value_type = self.add_slot(declaration, ResolutionTypeSlotRole::DeclaredValue);
        self.facts
            .declaration_type_slots
            .push(DeclarationTypeSlotFact {
                declaration,
                slot: value_type,
                role: DeclarationTypeRole::Value,
            });
        self.add_transfer(
            initializer,
            value_type,
            ResolutionTypeTransferKind::Initialization,
        );
        assert!(
            self.declaration_type_slots
                .insert(declaration, value_type)
                .is_none(),
            "one Java declaration has one declared-value slot"
        );
    }

    fn lower_return(&mut self, node: Node<'_>) {
        if let Some(lambda) = self.lambda_contexts.last().copied().filter(|lambda| {
            lambda.activation_start <= node.start_byte() && node.end_byte() <= lambda.activation_end
        }) {
            let lambda_is_nearest_callable = self.callable_contexts.last().is_none_or(|callable| {
                lambda.activation_start >= callable.activation_start
                    && lambda.activation_end <= callable.activation_end
            });
            if lambda_is_nearest_callable {
                if let Some(value) = first_named_child(node) {
                    self.lower_expression(value);
                }
                return;
            }
        }
        let Some(callable) = self.callable_contexts.last().copied() else {
            return;
        };
        if !self
            .declaration_type_slots
            .contains_key(&callable.declaration)
        {
            return;
        }
        let Some(value) = first_named_child(node) else {
            return;
        };
        let input = self.lower_expression(value);
        let observed = self.add_slot(callable.declaration, ResolutionTypeSlotRole::ReturnValue);
        self.add_transfer(input, observed, ResolutionTypeTransferKind::Return);
    }

    fn attach_declaration_type(
        &mut self,
        declaration: ResolutionSiteId,
        type_node: Node<'_>,
        role: DeclarationTypeRole,
    ) -> ResolutionTypeSlotId {
        let input = self.lower_type(type_node);
        self.attach_lowered_declaration_type(declaration, input, type_node, role)
    }

    fn attach_lowered_declaration_type(
        &mut self,
        declaration: ResolutionSiteId,
        input: ResolutionTypeSlotId,
        type_node: Node<'_>,
        role: DeclarationTypeRole,
    ) -> ResolutionTypeSlotId {
        let output = self.add_slot(declaration, ResolutionTypeSlotRole::DeclaredValue);
        self.facts
            .declaration_type_slots
            .push(DeclarationTypeSlotFact {
                declaration,
                slot: output,
                role,
            });
        let value_transform = if type_node.kind() == "void_type" {
            ResolutionTypeTransferValueTransform::ToNoValue
        } else {
            ResolutionTypeTransferValueTransform::ToRuntime { addressable: false }
        };
        crate::call_arguments::publish_jvm_declared_type_transfer(
            &mut self.facts,
            input,
            output,
            value_transform,
        );
        self.declaration_type_slots.insert(declaration, output);
        output
    }

    fn attach_declaration_gap_type(
        &mut self,
        declaration: ResolutionSiteId,
        type_node: Node<'_>,
        role: DeclarationTypeRole,
        gap: ResolutionGapKind,
    ) -> ResolutionTypeSlotId {
        let input = self.lower_gap_type(type_node, gap);
        self.attach_lowered_declaration_type(declaration, input, type_node, role)
    }

    fn lower_inheritance_clause(&mut self, node: Node<'_>) {
        let subtype = self
            .type_contexts
            .last()
            .expect("Java inheritance clauses are nested under a type declaration")
            .declaration;
        if node.kind() == "superclass" {
            if let Some(type_node) = first_named_child(node) {
                self.type_contexts
                    .last_mut()
                    .expect("superclass retains its type context")
                    .has_explicit_superclass = true;
                self.add_supertype(subtype, type_node, ResolutionSupertypeKind::Superclass);
            }
            return;
        }

        let Some(type_list) = first_named_child_of_kind(node, "type_list") else {
            return;
        };
        let type_nodes = named_children(type_list);
        if type_nodes.is_empty() {
            return;
        }
        self.type_contexts
            .last_mut()
            .expect("superinterfaces retain their type context")
            .has_explicit_superinterface = true;
        for type_node in type_nodes {
            self.add_supertype(subtype, type_node, ResolutionSupertypeKind::Interface);
        }
    }

    // The language-defined superclass route is absolute: a source declaration
    // named java or Object cannot shadow it. It has no authored point range.
    fn add_implicit_object_supertype(&mut self, subtype: ResolutionSiteId) {
        let occurrence = self.site_occurrences[subtype.index()];
        let reference = self.add_site_from_occurrence(
            occurrence,
            ResolutionSiteKind::SyntheticReference,
            self.site(subtype).scope,
        );
        let name = self.intern_name("Object");
        let prefix = [self.intern_name("java"), self.intern_name("lang")];
        crate::implicit_supertype::publish_implicit_supertype(
            &mut self.facts,
            subtype,
            reference,
            name,
            &prefix,
            ResolutionSupertypeKind::ImplicitSuperclass,
        );
        let next = self.next_parent_ordinal.entry(subtype).or_default();
        *next = next
            .checked_add(1)
            .expect("a declaration's parent count fits u32");
    }

    fn add_supertype(
        &mut self,
        subtype: ResolutionSiteId,
        type_node: Node<'_>,
        kind: ResolutionSupertypeKind,
    ) {
        let supertype_slot = if type_node.kind() == "generic_type" {
            // Publish the whole generic unsupported frontier first, then use
            // its iteratively discovered base as the hierarchy reference.
            self.lower_type(type_node);
            let Some(base) = self.lower_supertype_base(type_node) else {
                self.add_gap(subtype, ResolutionGapKind::MalformedSyntax);
                return;
            };
            base
        } else {
            self.lower_type(type_node)
        };
        let supertype_reference = self.slot(supertype_slot).site;
        if !matches!(
            self.facts.sites[supertype_reference.index()].kind,
            ResolutionSiteKind::TypeReference | ResolutionSiteKind::MemberReference
        ) {
            // Unsupported syntax has a gap site, not a positioned reference.
            // Retain the subtype's uncertainty without inventing a hierarchy
            // edge whose reference cannot have an owner.
            self.add_gap(subtype, ResolutionGapKind::UnsupportedHierarchyTraversal);
            return;
        }
        // An anonymous creation's type is lowered in its enclosing scope
        // before the synthetic body owner exists. The same written occurrence
        // becomes that body's supertype when the body is entered.
        self.facts
            .reference_owners
            .iter_mut()
            .find(|owner| owner.reference == supertype_reference)
            .expect("a written supertype reference has an owner row")
            .owner = Some(subtype);
        let parent_ordinal = self.take_parent_ordinal(subtype);
        self.facts.supertypes.push(ResolutionSupertypeFact {
            subtype,
            parent_ordinal,
            supertype_reference,
            supertype_slot,
            kind,
        });
        self.add_gap(
            supertype_reference,
            ResolutionGapKind::UnsupportedHierarchyTraversal,
        );
    }

    fn add_supertype_edge(
        &mut self,
        subtype: ResolutionSiteId,
        supertype_slot: ResolutionTypeSlotId,
        kind: ResolutionSupertypeKind,
    ) {
        let supertype_reference = self.slot(supertype_slot).site;
        assert!(matches!(
            self.site(supertype_reference).kind,
            ResolutionSiteKind::TypeReference | ResolutionSiteKind::MemberReference
        ));
        let parent_ordinal = self.take_parent_ordinal(subtype);
        self.facts.supertypes.push(ResolutionSupertypeFact {
            subtype,
            parent_ordinal,
            supertype_reference,
            supertype_slot,
            kind,
        });
        self.add_gap(
            supertype_reference,
            ResolutionGapKind::UnsupportedHierarchyTraversal,
        );
    }

    fn take_parent_ordinal(&mut self, subtype: ResolutionSiteId) -> u32 {
        let next = self.next_parent_ordinal.entry(subtype).or_default();
        let ordinal = *next;
        *next = next
            .checked_add(1)
            .expect("a declaration's parent count fits u32");
        ordinal
    }

    /// The base type still owns the hierarchy reference. Walk nested generic
    /// wrappers iteratively so argument rows retain their owner without
    /// recursive source-tree traversal.
    fn lower_supertype_base(&mut self, node: Node<'_>) -> Option<ResolutionTypeSlotId> {
        let mut current = node;
        loop {
            let source_type = self.capture_source_type(current);
            let shape = self
                .source_types
                .shape(source_type)
                .expect("captured Java source type has a shape");
            if !matches!(shape, JavaTypeSyntaxShape::Generic { .. }) {
                return Some(self.lower_type(current));
            }
            current = named_children(current)
                .into_iter()
                .find(|child| self.is_type_syntax(child.kind()))?;
        }
    }

    /// Iteratively lowers generic, array, and scoped type syntax. The explicit
    /// postorder stack keeps generated or adversarially deep types stack-safe.
    fn lower_type(&mut self, node: Node<'_>) -> ResolutionTypeSlotId {
        if let Some(slot) = self.type_slots_by_node.get(&node.id()) {
            return *slot;
        }
        let mut pending = vec![(node, false)];
        let mut qualified_base_nodes = Vec::new();
        let mut seen_qualified_bases = HashSet::default();
        let mut qualified_member_sites = Vec::new();
        while let Some((current, finishing)) = pending.pop() {
            if self.type_slots_by_node.contains_key(&current.id()) {
                continue;
            }
            // Error recovery can insert a zero-width MISSING token of any type
            // kind, which spells nothing to resolve.
            if current.is_missing() || current.is_error() {
                self.lower_gap_type(current, ResolutionGapKind::MalformedSyntax);
                continue;
            }
            let source_type = self.capture_source_type(current);
            let shape = self
                .source_types
                .shape(source_type)
                .expect("captured Java source type has a shape");
            if finishing {
                match current.kind() {
                    "generic_type" => {
                        let base = current
                            .child_by_field_name("type")
                            .or_else(|| java_named_type_child(current))
                            .expect("Java generic type has a base type");
                        let owner = self.type_slots_by_node[&base.id()];
                        let arguments = java_type_argument_nodes(current);
                        assert!(
                            !arguments.is_empty(),
                            "captured Java generic syntax has at least one type argument"
                        );
                        for (ordinal, argument) in arguments.into_iter().enumerate() {
                            self.facts.declared_type_arguments.push(
                                ResolutionDeclaredTypeArgumentFact {
                                    owner,
                                    ordinal: dense_ordinal(ordinal, "Java type argument"),
                                    argument: self.type_slots_by_node[&argument.id()],
                                },
                            );
                        }
                        self.type_slots_by_node.insert(current.id(), owner);
                    }
                    "scoped_type_identifier" => {
                        let Some((scope, name)) =
                            scoped_type_parts(current).filter(|(_, name)| !name.is_missing())
                        else {
                            let slot = self.lower_unsupported_type(current);
                            self.type_slots_by_node.insert(current.id(), slot);
                            continue;
                        };
                        let qualifier = self.type_slots_by_node[&scope.id()];
                        let reference = self.add_site(name, ResolutionSiteKind::MemberReference);
                        self.add_member_type_reference(reference, current, name, qualifier);
                        qualified_member_sites.push(reference);
                        self.record_qualified_type_root(current, reference);
                    }
                    "array_type" => {
                        let element = current
                            .child_by_field_name("element")
                            .expect("captured Java array has an element type");
                        let element = self.type_slots_by_node[&element.id()];
                        let slot = self.lower_structural_array_type(current, element);
                        self.type_slots_by_node.insert(current.id(), slot);
                    }
                    _ => unreachable!("only structured Java type wrappers finish"),
                }
                continue;
            }
            match (current.kind(), shape) {
                ("generic_type", JavaTypeSyntaxShape::Generic { .. }) => {
                    let Some(base) = current
                        .child_by_field_name("type")
                        .or_else(|| java_named_type_child(current))
                    else {
                        let slot = self.lower_unsupported_type(current);
                        self.type_slots_by_node.insert(current.id(), slot);
                        continue;
                    };
                    let arguments = java_type_argument_nodes(current);
                    if arguments.is_empty() {
                        let slot = self.lower_unsupported_type(current);
                        self.type_slots_by_node.insert(current.id(), slot);
                        continue;
                    }
                    pending.push((current, true));
                    for argument in arguments.into_iter().rev() {
                        pending.push((argument, false));
                    }
                    pending.push((base, false));
                }
                ("scoped_type_identifier", _) => {
                    let Some((scope, _)) = scoped_type_parts(current) else {
                        let slot = self.lower_unsupported_type(current);
                        self.type_slots_by_node.insert(current.id(), slot);
                        continue;
                    };
                    let mut base = current;
                    loop {
                        match base.kind() {
                            "generic_type" => {
                                let Some(inner) = base
                                    .child_by_field_name("type")
                                    .or_else(|| java_named_type_child(base))
                                else {
                                    break;
                                };
                                base = inner;
                            }
                            "scoped_type_identifier" => {
                                let Some((inner, _)) = scoped_type_parts(base) else {
                                    break;
                                };
                                base = inner;
                            }
                            _ => break,
                        }
                    }
                    if seen_qualified_bases.insert(base.id()) {
                        qualified_base_nodes.push(base.id());
                    }
                    pending.push((current, true));
                    pending.push((scope, false));
                }
                ("array_type", _) => {
                    let Some(element) = current.child_by_field_name("element") else {
                        let slot = self.lower_unsupported_type(current);
                        self.type_slots_by_node.insert(current.id(), slot);
                        continue;
                    };
                    pending.push((current, true));
                    pending.push((element, false));
                }
                ("type_identifier" | "identifier", JavaTypeSyntaxShape::Named { .. }) => {
                    self.lower_plain_type_reference(current);
                }
                ("type_identifier", JavaTypeSyntaxShape::Unknown)
                    if self.source_types.is_inferred_type(source_type) =>
                {
                    self.lower_gap_type(current, ResolutionGapKind::InferredType);
                }
                (
                    "integral_type" | "floating_point_type" | "boolean_type" | "void_type",
                    JavaTypeSyntaxShape::NonNominal,
                ) => {
                    self.lower_intrinsic_type(current, IntrinsicTypeKind::Primitive);
                }
                _ => {
                    self.lower_unsupported_type(current);
                }
            }
        }
        for base in qualified_base_nodes {
            let slot = self.type_slots_by_node[&base];
            let site = self.slot(slot).site;
            self.add_gap(site, ResolutionGapKind::AmbiguousQualifiedType);
        }
        for site in qualified_member_sites {
            self.add_gap(site, ResolutionGapKind::AmbiguousQualifiedType);
        }
        self.type_slots_by_node[&node.id()]
    }

    fn lower_structural_array_type(
        &mut self,
        node: Node<'_>,
        element: ResolutionTypeSlotId,
    ) -> ResolutionTypeSlotId {
        let site = self.add_site(node, ResolutionSiteKind::TypeReference);
        let container = self.add_slot(site, ResolutionTypeSlotRole::TargetTypeIdentity);
        let name = self.intern_name("structural-type");
        let source_type = self.capture_source_type(node);
        let JavaTypeSyntaxShape::Array { dimensions, .. } = self
            .source_types
            .shape(source_type)
            .expect("captured Java array type has a shape")
        else {
            panic!("array_type has a structured array type shape")
        };
        assert!(*dimensions > 0, "Java arrays have at least one dimension");
        self.facts.intrinsic_type_seeds.push(IntrinsicTypeSeedFact {
            output: container,
            name,
            kind: IntrinsicTypeKind::Structural,
            indirection: 0,
        });
        let mut containers = vec![container];
        for _ in 1..*dimensions {
            let nested = self.add_slot(site, ResolutionTypeSlotRole::TargetTypeIdentity);
            self.facts.intrinsic_type_seeds.push(IntrinsicTypeSeedFact {
                output: nested,
                name,
                kind: IntrinsicTypeKind::Structural,
                indirection: 0,
            });
            containers.push(nested);
        }
        let mut component = element;
        for container in containers.into_iter().rev() {
            self.facts
                .type_components
                .push(ResolutionTypeComponentFact {
                    container,
                    constructor: ResolutionTypeConstructorKind::Sequence,
                    kind: ResolutionTypeComponentKind::Element,
                    component,
                });
            component = container;
        }
        container
    }

    // Preserve the package interpretation alongside the typed member chain.
    // The selected resolver must evaluate the lexical prefix before admitting
    // a package route: a source type with that name shadows the package.
    fn record_qualified_type_root(&mut self, node: Node<'_>, reference: ResolutionSiteId) {
        let mut current = node;
        let mut segments = Vec::new();
        while current.kind() == "scoped_type_identifier" {
            let Some((scope, name)) = scoped_type_parts(current) else {
                return;
            };
            segments.push(self.intern_name(node_text(name, self.source)));
            current = scope;
        }
        if current.kind() != "type_identifier" {
            return;
        }
        let Some(prefix_slot) = self.type_slots_by_node.get(&current.id()).copied() else {
            return;
        };
        let prefix = self.slot(prefix_slot).site;
        if self.site(prefix).kind != ResolutionSiteKind::TypeReference {
            return;
        }
        segments.push(self.intern_name(node_text(current, self.source)));
        segments.reverse();
        segments.pop().expect("qualified type has a terminal name");
        self.record_rooted_type_route(
            ResolutionRootReferenceFact {
                reference,
                root_scope: self.facts.scopes[0].id,
                anchor: ResolutionRootImportAnchor::Lexical,
                prefix_reference: Some(prefix),
                owner_continued: false,
            },
            segments,
        );
    }

    fn record_rooted_type_route(
        &mut self,
        route: ResolutionRootReferenceFact,
        segments: Vec<ResolutionNameId>,
    ) {
        if route
            .prefix_reference
            .is_some_and(|prefix| self.site(prefix).kind != ResolutionSiteKind::TypeReference)
        {
            return;
        }
        let reference = route.reference;
        self.facts.root_references.push(route);
        self.facts
            .root_reference_segments
            .extend(segments.into_iter().enumerate().map(|(position, name)| {
                ResolutionRootReferenceSegmentFact {
                    reference,
                    position: dense_ordinal(position, "Java type route segment"),
                    name,
                }
            }));
    }

    fn lower_plain_type_reference(&mut self, node: Node<'_>) -> ResolutionTypeSlotId {
        if let Some(slot) = self.type_slots_by_node.get(&node.id()) {
            return *slot;
        }
        let reference = self.add_identifier_site(
            node,
            ResolutionSiteKind::TypeReference,
            self.current_scope(),
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Type,
            None,
        );
        let slot = self.add_slot(reference, ResolutionTypeSlotRole::TargetTypeIdentity);
        self.facts
            .binding_projections
            .push(BindingProjectionFact::target_type_identity(reference, slot));
        self.type_slots_by_node.insert(node.id(), slot);
        slot
    }

    fn lower_intrinsic_type(
        &mut self,
        node: Node<'_>,
        kind: IntrinsicTypeKind,
    ) -> ResolutionTypeSlotId {
        if let Some(slot) = self.type_slots_by_node.get(&node.id()) {
            return *slot;
        }
        // Error recovery can wrap a MISSING keyword in a zero-width intrinsic
        // type node, which spells nothing to seed.
        if node.is_missing() || node.has_error() {
            return self.lower_gap_type(node, ResolutionGapKind::MalformedSyntax);
        }
        let site = self.add_site(node, ResolutionSiteKind::TypeReference);
        let slot = self.add_slot(site, ResolutionTypeSlotRole::TargetTypeIdentity);
        let spelling = node_text(node, self.source).trim();
        let name = self.intern_name(spelling);
        self.facts
            .intrinsic_type_seeds
            .push(IntrinsicTypeSeedFact::direct(slot, name, kind));
        self.type_slots_by_node.insert(node.id(), slot);
        slot
    }

    fn lower_unsupported_type(&mut self, node: Node<'_>) -> ResolutionTypeSlotId {
        self.lower_gap_type(node, ResolutionGapKind::UnsupportedTypeSyntax)
    }

    fn lower_gap_type(&mut self, node: Node<'_>, kind: ResolutionGapKind) -> ResolutionTypeSlotId {
        if let Some(slot) = self.type_slots_by_node.get(&node.id()) {
            return *slot;
        }
        let slot = self.add_gap_slot(node, kind, ResolutionTypeSlotRole::TargetTypeIdentity);
        self.type_slots_by_node.insert(node.id(), slot);
        slot
    }

    fn add_gap_slot(
        &mut self,
        node: Node<'_>,
        kind: ResolutionGapKind,
        role: ResolutionTypeSlotRole,
    ) -> ResolutionTypeSlotId {
        let site = self.add_site(node, ResolutionSiteKind::UnsupportedExpression);
        let slot = self.add_slot(site, role);
        self.add_gap(site, kind);
        self.add_reference_enumeration_gap_if_omitted(node, site, kind);
        self.gapped_semantic_subtrees.insert(node.id());
        slot
    }

    /// Iterative expression postorder. Dependencies are lowered before their
    /// consumer without recursive Rust calls, so a deeply chained selector is
    /// bounded by an explicit heap stack rather than the thread stack.
    fn lower_expression(&mut self, root: Node<'_>) -> ResolutionTypeSlotId {
        if let Some(slot) = self.expression_slots_by_node.get(&root.id()) {
            return *slot;
        }
        let mut stack = vec![(root, false)];
        while let Some((node, finishing)) = stack.pop() {
            if self.expression_slots_by_node.contains_key(&node.id()) {
                continue;
            }
            if finishing {
                self.finish_expression(node);
                continue;
            }
            // Error recovery can insert a zero-width MISSING token of any
            // expression kind, which spells nothing to resolve.
            if node.is_missing() || node.is_error() {
                self.lower_unsupported_expression_as(node, ResolutionGapKind::MalformedSyntax);
                continue;
            }

            match node.kind() {
                "assignment_expression" => {
                    let (Some(left), Some(right)) = (
                        node.child_by_field_name("left"),
                        node.child_by_field_name("right"),
                    ) else {
                        self.lower_unsupported_expression(node);
                        continue;
                    };
                    stack.push((node, true));
                    stack.push((right, false));
                    if is_spelled_identifier(left) {
                        self.lower_value_location_reference(left);
                    } else {
                        stack.push((left, false));
                    }
                }
                "instanceof_expression" => {
                    let Some(left) = node.child_by_field_name("left") else {
                        self.lower_unsupported_expression(node);
                        continue;
                    };
                    if let Some(ty) = node.child_by_field_name("right") {
                        self.lower_type(ty);
                    }
                    stack.push((node, true));
                    stack.push((left, false));
                }
                "binary_expression" => {
                    let (Some(left), Some(right)) = (
                        node.child_by_field_name("left"),
                        node.child_by_field_name("right"),
                    ) else {
                        self.lower_unsupported_expression(node);
                        continue;
                    };
                    stack.push((node, true));
                    stack.push((right, false));
                    stack.push((left, false));
                }
                "ternary_expression" => {
                    let (Some(condition), Some(consequence), Some(alternative)) = (
                        node.child_by_field_name("condition"),
                        node.child_by_field_name("consequence"),
                        node.child_by_field_name("alternative"),
                    ) else {
                        self.lower_unsupported_expression(node);
                        continue;
                    };
                    stack.push((node, true));
                    stack.push((alternative, false));
                    stack.push((consequence, false));
                    stack.push((condition, false));
                }
                "update_expression" => {
                    let Some(operand) = first_named_child(node) else {
                        self.lower_unsupported_expression(node);
                        continue;
                    };
                    stack.push((node, true));
                    if is_spelled_identifier(operand) {
                        self.lower_value_location_reference(operand);
                    } else {
                        stack.push((operand, false));
                    }
                }
                "method_invocation" => {
                    stack.push((node, true));
                    self.push_call_dependencies(node, &mut stack);
                }
                "field_access" => {
                    stack.push((node, true));
                    if let Some(object) = node.child_by_field_name("object") {
                        if object.kind() == "this" {
                            // `this.member` has the current type as its exact
                            // receiver. Member lookup can use the lexical type
                            // scope without inventing a type-name reference.
                            assert!(self.claimed_identifier_nodes.insert(object.id()));
                        } else {
                            stack.push((object, false));
                        }
                    }
                }
                "object_creation_expression" => {
                    stack.push((node, true));
                    self.push_argument_dependencies(node, &mut stack);
                    if let Some(type_node) = node.child_by_field_name("type")
                        && let Some(enclosing) =
                            super::graph_support::java_object_creation_enclosing_expression(
                                node, type_node,
                            )
                    {
                        stack.push((enclosing, false));
                    }
                }
                "switch_expression" => {
                    stack.push((node, true));
                    if let Some(condition) = node.child_by_field_name("condition") {
                        stack.push((condition, false));
                    }
                }
                "parenthesized_expression" => {
                    stack.push((node, true));
                    if let Some(inner) = first_named_child(node) {
                        stack.push((inner, false));
                    }
                }
                "class_literal" => {
                    let Some(type_node) = first_named_child(node) else {
                        self.lower_unsupported_expression_as(
                            node,
                            ResolutionGapKind::MalformedSyntax,
                        );
                        continue;
                    };
                    stack.push((node, true));
                    self.lower_type(type_node);
                }
                "cast_expression" => {
                    let (Some(_type), Some(value)) = (
                        node.child_by_field_name("type"),
                        node.child_by_field_name("value"),
                    ) else {
                        self.lower_unsupported_expression(node);
                        continue;
                    };
                    stack.push((node, true));
                    stack.push((value, false));
                }
                "unary_expression" => {
                    let Some(operator) = node.child_by_field_name("operator") else {
                        self.lower_unsupported_expression(node);
                        continue;
                    };
                    let Some(operand) = node.child_by_field_name("operand") else {
                        self.lower_unsupported_expression(node);
                        continue;
                    };
                    if matches!(node_text(operator, self.source), "+" | "-")
                        && is_java_integer_literal(operand)
                    {
                        stack.push((node, true));
                        stack.push((operand, false));
                    } else {
                        self.lower_unsupported_expression(node);
                    }
                }
                "lambda_expression" => self.lower_unsupported_expression_preserving_children(node),
                "method_reference" => {
                    let Some((receiver, terminal)) = java_method_reference_parts(node) else {
                        self.lower_unsupported_expression_as(
                            node,
                            ResolutionGapKind::MalformedSyntax,
                        );
                        continue;
                    };
                    stack.push((node, true));
                    if self.is_type_syntax(receiver.kind()) {
                        self.lower_type(receiver);
                    } else if terminal.kind() == "new" {
                        // JLS 15.13: a constructor reference names a class or
                        // array type, even where the grammar parsed an expression.
                        self.lower_named_type_reference(receiver);
                    } else if receiver.kind() == "identifier" {
                        self.lower_value_reference_in_namespace(
                            receiver,
                            ResolutionNamespace::TypeOrValue,
                        );
                    } else if receiver.kind() != "this" {
                        stack.push((receiver, false));
                    }
                }
                "identifier"
                | "string_literal"
                | "character_literal"
                | "decimal_integer_literal"
                | "hex_integer_literal"
                | "octal_integer_literal"
                | "binary_integer_literal"
                | "decimal_floating_point_literal"
                | "hex_floating_point_literal"
                | "true"
                | "false"
                | "null_literal" => self.finish_expression(node),
                _ => self.lower_unsupported_expression(node),
            }
        }
        *self
            .expression_slots_by_node
            .get(&root.id())
            .expect("expression postorder always publishes its root slot")
    }

    fn finish_expression(&mut self, node: Node<'_>) {
        if self.expression_slots_by_node.contains_key(&node.id()) {
            return;
        }
        match node.kind() {
            "identifier" => self.lower_value_reference(node),
            "assignment_expression" => self.finish_assignment_expression(node),
            "update_expression" => self.finish_update_expression(node),
            "binary_expression" => self.finish_binary_expression(node),
            "instanceof_expression" => {
                self.lower_literal(node, "boolean", IntrinsicTypeKind::Primitive)
            }
            "ternary_expression" => self.finish_ternary_expression(node),
            "method_invocation" => self.finish_method_invocation(node),
            "method_reference" => self.finish_method_reference(node),
            "field_access" => self.finish_field_access(node),
            "object_creation_expression" => self.finish_object_creation(node),
            "switch_expression" => self.lower_unsupported_expression_preserving_children(node),
            "class_literal" => self.finish_class_literal_expression(node),
            "cast_expression" => self.finish_cast_expression(node),
            "parenthesized_expression" | "unary_expression" => {
                let Some(inner) = first_named_child(node) else {
                    self.lower_unsupported_expression(node);
                    return;
                };
                let slot = *self
                    .expression_slots_by_node
                    .get(&inner.id())
                    .expect("parenthesized expression dependency was lowered");
                self.expression_slots_by_node.insert(node.id(), slot);
            }
            "string_literal" => {
                self.lower_literal(node, "java.lang.String", IntrinsicTypeKind::LanguageBuiltin)
            }
            "character_literal" => self.lower_literal(node, "char", IntrinsicTypeKind::Primitive),
            "decimal_integer_literal"
            | "hex_integer_literal"
            | "octal_integer_literal"
            | "binary_integer_literal" => self.lower_integer_literal(node),
            "decimal_floating_point_literal" | "hex_floating_point_literal" => self
                .lower_unsupported_expression_as(node, ResolutionGapKind::AmbiguousNumericLiteral),
            "true" | "false" => self.lower_literal(node, "boolean", IntrinsicTypeKind::Primitive),
            "null_literal" => self.lower_literal(node, "null", IntrinsicTypeKind::LanguageBuiltin),
            _ => self.lower_unsupported_expression(node),
        }
    }

    fn finish_cast_expression(&mut self, node: Node<'_>) {
        let (Some(type_node), Some(_value)) = (
            node.child_by_field_name("type"),
            node.child_by_field_name("value"),
        ) else {
            self.lower_unsupported_expression(node);
            return;
        };
        let type_slot = self.lower_type(type_node);
        let Some(type_seed) = self
            .facts
            .intrinsic_type_seeds
            .iter()
            .find(|seed| seed.output == type_slot)
            .copied()
            .filter(|seed| seed.kind == IntrinsicTypeKind::Primitive && seed.indirection == 0)
        else {
            self.lower_unsupported_expression(node);
            return;
        };
        let site = self.add_site(node, ResolutionSiteKind::UnaryExpression);
        let output = self.add_slot(site, ResolutionTypeSlotRole::ExpressionValue);
        self.facts.intrinsic_type_seeds.push(IntrinsicTypeSeedFact {
            output,
            ..type_seed
        });
        self.expression_slots_by_node.insert(node.id(), output);
    }

    fn finish_assignment_expression(&mut self, node: Node<'_>) {
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            self.lower_unsupported_expression(node);
            return;
        };
        debug_assert!(self.expression_slots_by_node.contains_key(&right.id()));
        let bare_target = is_spelled_identifier(left);
        if bare_target
            && node
                .child_by_field_name("operator")
                .is_some_and(|operator| operator.kind() == "=")
        {
            let target = self.slot(self.expression_slot(left)).site;
            let value = self.expression_slot(right);
            self.facts
                .local_writes
                .push(ResolutionLocalWriteFact { target, value });
            // Java assignment expressions evaluate to the right-hand value.
            // Reading the old left value here makes chained writes cyclic.
            self.finish_expression_with_value(node, right);
        } else {
            self.lower_unsupported_expression(node);
            if bare_target {
                let target = self.slot(self.expression_slot(left)).site;
                let value = self.expression_slot(node);
                self.facts
                    .local_writes
                    .push(ResolutionLocalWriteFact { target, value });
            }
        }
    }

    fn finish_update_expression(&mut self, node: Node<'_>) {
        let Some(operand) = first_named_child(node) else {
            self.lower_unsupported_expression(node);
            return;
        };
        self.lower_unsupported_expression(node);
        if is_spelled_identifier(operand) {
            let target = self.slot(self.expression_slot(operand)).site;
            let value = self.expression_slot(node);
            self.facts
                .local_writes
                .push(ResolutionLocalWriteFact { target, value });
        }
    }

    fn finish_expression_with_value(&mut self, expression: Node<'_>, value: Node<'_>) {
        self.expression_slots_by_node
            .insert(expression.id(), self.expression_slot(value));
    }

    fn finish_binary_expression(&mut self, node: Node<'_>) {
        let (Some(left), Some(operator), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("operator"),
            node.child_by_field_name("right"),
        ) else {
            self.lower_unsupported_expression(node);
            return;
        };
        debug_assert!(self.expression_slots_by_node.contains_key(&left.id()));
        debug_assert!(self.expression_slots_by_node.contains_key(&right.id()));
        let operator = node_text(operator, self.source);
        if matches!(
            operator,
            "==" | "!=" | "<" | "<=" | ">" | ">=" | "&&" | "||"
        ) {
            self.lower_literal(node, "boolean", IntrinsicTypeKind::Primitive);
            return;
        }
        let (kind, include_right) = match operator {
            "+" => (ResolutionTypeTransferKind::StringConcatenation, true),
            "-" | "*" | "/" | "%" | "&" | "|" | "^" => {
                (ResolutionTypeTransferKind::NumericPromotion, true)
            }
            // JLS 15.19 uses unary promotion of the left operand. The right
            // operand's width never changes the result, so it is not an input.
            "<<" | ">>" | ">>>" => (ResolutionTypeTransferKind::NumericPromotion, false),
            _ => {
                self.lower_unsupported_expression(node);
                return;
            }
        };
        let site = self.add_site(node, ResolutionSiteKind::BinaryExpression);
        let output = self.add_slot(site, ResolutionTypeSlotRole::ExpressionValue);
        let left_slot = self.expression_slot(left);
        self.add_transfer_with_transform(
            left_slot,
            output,
            kind,
            ResolutionTypeTransferValueTransform::RuntimeOnly,
        );
        if include_right {
            let right_slot = self.expression_slot(right);
            // Repeated operands have one transfer identity, which is enough:
            // promotion(T, T) equals promotion(T).
            if right_slot != left_slot {
                self.add_transfer_with_transform(
                    right_slot,
                    output,
                    kind,
                    ResolutionTypeTransferValueTransform::RuntimeOnly,
                );
            }
        }
        self.expression_slots_by_node.insert(node.id(), output);
    }

    fn finish_ternary_expression(&mut self, node: Node<'_>) {
        let (Some(condition), Some(consequence), Some(alternative)) = (
            node.child_by_field_name("condition"),
            node.child_by_field_name("consequence"),
            node.child_by_field_name("alternative"),
        ) else {
            self.lower_unsupported_expression(node);
            return;
        };
        debug_assert!(self.expression_slots_by_node.contains_key(&condition.id()));
        debug_assert!(
            self.expression_slots_by_node
                .contains_key(&consequence.id())
        );
        debug_assert!(
            self.expression_slots_by_node
                .contains_key(&alternative.id())
        );
        let site = self.add_site(node, ResolutionSiteKind::ConditionalExpression);
        let output = self.add_slot(site, ResolutionTypeSlotRole::ExpressionValue);
        let consequence_type = self
            .facts
            .intrinsic_type_seeds
            .iter()
            .find(|seed| seed.output == self.expression_slot(consequence))
            .copied();
        let alternative_type = self
            .facts
            .intrinsic_type_seeds
            .iter()
            .find(|seed| seed.output == self.expression_slot(alternative))
            .copied();
        if let (Some(consequence_type), Some(alternative_type)) =
            (consequence_type, alternative_type)
            && consequence_type.name == alternative_type.name
            && consequence_type.kind == alternative_type.kind
            && consequence_type.indirection == alternative_type.indirection
        {
            self.facts.intrinsic_type_seeds.push(IntrinsicTypeSeedFact {
                output,
                ..consequence_type
            });
        } else {
            // The JLS branch-promotion rules are not represented yet. Preserve
            // the expression and its branches while keeping its type gap open.
            self.add_gap(site, ResolutionGapKind::InferredType);
        }
        self.expression_slots_by_node.insert(node.id(), output);
    }

    fn lower_value_reference(&mut self, node: Node<'_>) {
        let is_member_receiver = node.parent().is_some_and(|parent| {
            matches!(parent.kind(), "field_access" | "method_invocation")
                && parent.child_by_field_name("object") == Some(node)
        });
        self.lower_value_reference_in_namespace(
            node,
            if is_member_receiver {
                ResolutionNamespace::TypeOrValue
            } else {
                ResolutionNamespace::Value
            },
        );
    }

    fn lower_value_location_reference(&mut self, node: Node<'_>) {
        self.lower_value_reference_in_namespace(node, ResolutionNamespace::Value);
    }

    fn lower_value_reference_in_namespace(
        &mut self,
        node: Node<'_>,
        namespace: ResolutionNamespace,
    ) {
        let projection = match namespace {
            ResolutionNamespace::Value => BindingProjectionKind::TargetDeclaredValueType,
            ResolutionNamespace::TypeOrValue => {
                BindingProjectionKind::TargetTypeOrDeclaredValueType
            }
            _ => unreachable!("Java value references use value-capable namespaces"),
        };
        let reference = self.add_identifier_site(
            node,
            ResolutionSiteKind::ValueReference,
            self.current_scope(),
            ResolutionIdentifierRole::Reference,
            namespace,
            None,
        );
        let output = self.add_slot(reference, ResolutionTypeSlotRole::ExpressionValue);
        self.facts.binding_projections.push(BindingProjectionFact {
            reference,
            output,
            kind: projection,
        });
        self.expression_slots_by_node.insert(node.id(), output);
    }

    fn finish_method_reference(&mut self, node: Node<'_>) {
        // Unlike an invocation, a reference has no argument list. In particular,
        // do not select a zero-argument overload when the functional target is unknown.
        let (receiver, terminal) = java_method_reference_parts(node)
            .expect("method-reference dependencies validated the structured segments");
        for arguments in named_children(node)
            .into_iter()
            .filter(|child| child.kind() == "type_arguments")
        {
            for argument in named_children(arguments)
                .into_iter()
                .filter(|argument| !argument.is_extra())
            {
                self.lower_type(argument);
            }
        }
        let constructor = terminal.kind() == "new";
        let qualifier = if receiver.kind() == "this" {
            None
        } else if self.is_type_syntax(receiver.kind()) {
            Some(self.lower_type(receiver))
        } else if constructor {
            Some(self.lower_named_type_reference(receiver))
        } else {
            Some(self.expression_slot(receiver))
        };
        let reference = self.add_site(
            terminal,
            if constructor {
                ResolutionSiteKind::ConstructorReference
            } else {
                ResolutionSiteKind::MemberReference
            },
        );
        let qualifier = qualifier.map(|input| {
            if constructor {
                input
            } else {
                // A type-qualified method reference can bind an instance method:
                // its eventual functional argument supplies the receiver. Java
                // static members also admit runtime qualifiers, so this searches
                // both families without inventing an invocation or its arity.
                let output = self.add_slot(reference, ResolutionTypeSlotRole::Receiver);
                self.add_transfer_with_transform(
                    input,
                    output,
                    ResolutionTypeTransferKind::Receiver,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                );
                output
            }
        });
        self.add_identifier_to_site(
            reference,
            terminal,
            ResolutionIdentifierRole::Reference,
            if constructor {
                ResolutionNamespace::Constructor
            } else {
                ResolutionNamespace::Callable
            },
            qualifier,
        );
        if constructor {
            // Position the reference on `new`, but look up the owner's constructor
            // name, just as an ordinary object creation does.
            if let Some(name) = self
                .type_terminal_name(receiver)
                .or_else(|| (receiver.kind() == "identifier").then_some(receiver))
                .or_else(|| receiver.child_by_field_name("field"))
            {
                let name = self.intern_name(node_text(name, self.source));
                self.facts
                    .identifiers
                    .last_mut()
                    .expect("new constructor reference")
                    .name = name;
            } else {
                self.add_gap(reference, ResolutionGapKind::UnsupportedTypeSyntax);
            }
        } else {
            self.facts
                .callable_receiver_origins
                .push(ResolutionCallableReceiverOriginFact {
                    reference,
                    origin: match receiver.kind() {
                        "this" => ResolutionCallableReceiverOrigin::CurrentInstance,
                        "super" => ResolutionCallableReceiverOrigin::Super,
                        _ => ResolutionCallableReceiverOrigin::ExplicitExpression,
                    },
                });
        }
        let binding = self.add_slot(reference, ResolutionTypeSlotRole::ExpressionValue);
        self.facts.binding_projections.push(BindingProjectionFact {
            reference,
            output: binding,
            kind: BindingProjectionKind::NonInvokingMemberReference,
        });
        // The receiver and callable are navigable independently of the target
        // functional interface, whose value type has not been inferred here.
        let site = self.add_site(node, ResolutionSiteKind::UnsupportedExpression);
        let output = self.add_slot(site, ResolutionTypeSlotRole::ExpressionValue);
        self.add_gap(site, ResolutionGapKind::InferredType);
        self.expression_slots_by_node.insert(node.id(), output);
    }

    fn finish_method_invocation(&mut self, node: Node<'_>) {
        let Some(name) = node.child_by_field_name("name") else {
            self.lower_unsupported_expression(node);
            return;
        };
        if name.is_missing() {
            self.lower_unsupported_expression_as(node, ResolutionGapKind::MalformedSyntax);
            return;
        }
        let call = self.add_site(node, ResolutionSiteKind::Call);
        let object = node.child_by_field_name("object");
        let receiver = object
            .filter(|object| object.kind() != "this")
            .map(|object| {
                let output = self.add_slot(call, ResolutionTypeSlotRole::Receiver);
                if object.kind() == "super" {
                    if let Some(context) = self.type_contexts.last() {
                        self.super_receivers.push((context.declaration, output));
                    } else {
                        self.add_gap(call, ResolutionGapKind::MalformedSyntax);
                    }
                } else {
                    let input = self.expression_slot(object);
                    self.add_transfer(input, output, ResolutionTypeTransferKind::Receiver);
                }
                output
            });
        let callee = self.add_identifier_site(
            name,
            if object.is_some() {
                ResolutionSiteKind::MemberReference
            } else {
                ResolutionSiteKind::CallableReference
            },
            self.current_scope(),
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Callable,
            receiver,
        );
        self.facts
            .callable_receiver_origins
            .push(ResolutionCallableReceiverOriginFact {
                reference: callee,
                origin: super::graph_support::java_callable_receiver_origin(node),
            });
        self.add_gap(callee, ResolutionGapKind::UnsupportedCallApplicability);
        let result = self.add_slot(call, ResolutionTypeSlotRole::CallResult);
        self.facts.binding_projections.push(BindingProjectionFact {
            reference: callee,
            output: result,
            kind: BindingProjectionKind::TargetCallableResultType,
        });
        self.facts.add_single_result_call(
            call,
            callee,
            receiver,
            result,
            explicit_type_argument_count(node),
        );
        self.facts
            .engine_rule_eligibilities
            .push(ResolutionEngineRuleEligibilityFact {
                site: call,
                rule: ResolutionEngineRuleKind::DirectOwnerExactPrimitiveDominance,
            });
        self.attach_call_arguments(node, call);
        self.expression_slots_by_node.insert(node.id(), result);
    }

    fn finish_field_access(&mut self, node: Node<'_>) {
        let Some(field) = node.child_by_field_name("field") else {
            self.lower_unsupported_expression(node);
            return;
        };
        if field.is_missing() {
            self.lower_unsupported_expression_as(node, ResolutionGapKind::MalformedSyntax);
            return;
        }
        let object = node.child_by_field_name("object");
        let explicit_this = object.is_some_and(|object| object.kind() == "this");
        let reference_scope = if explicit_this {
            self.type_contexts
                .last()
                .and_then(|context| context.body_scope)
                .expect("an explicit Java this member access has a current type body")
        } else {
            self.current_scope()
        };
        let reference =
            self.add_site_in_scope(field, ResolutionSiteKind::MemberReference, reference_scope);
        let qualifier = object.and_then(|object| {
            if explicit_this {
                None
            } else {
                let input = self.expression_slot(object);
                let output = self.add_slot(reference, ResolutionTypeSlotRole::Receiver);
                self.add_transfer(input, output, ResolutionTypeTransferKind::Receiver);
                Some(output)
            }
        });
        if explicit_this {
            self.add_explicit_this_identifier_to_site(
                reference,
                field,
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Value,
            );
        } else {
            self.add_identifier_to_site(
                reference,
                field,
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::TypeOrValue,
                qualifier,
            );
        }
        let output = self.add_slot(reference, ResolutionTypeSlotRole::ExpressionValue);
        self.facts.binding_projections.push(BindingProjectionFact {
            reference,
            output,
            kind: if explicit_this {
                BindingProjectionKind::TargetDeclaredValueType
            } else {
                BindingProjectionKind::TargetTypeOrDeclaredValueType
            },
        });
        self.expression_slots_by_node.insert(node.id(), output);
    }

    fn add_member_type_reference(
        &mut self,
        reference: ResolutionSiteId,
        type_node: Node<'_>,
        name: Node<'_>,
        qualifier: ResolutionTypeSlotId,
    ) -> ResolutionTypeSlotId {
        self.add_identifier_to_site(
            reference,
            name,
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Type,
            Some(qualifier),
        );
        let slot = self.add_slot(reference, ResolutionTypeSlotRole::TargetTypeIdentity);
        self.facts
            .binding_projections
            .push(BindingProjectionFact::target_type_identity(reference, slot));
        self.type_slots_by_node.insert(name.id(), slot);
        self.type_slots_by_node.insert(type_node.id(), slot);
        slot
    }

    fn finish_object_creation(&mut self, node: Node<'_>) {
        let anonymous_body = named_children(node)
            .into_iter()
            .find(|child| is_java_synthetic_class_body(*child));
        let Some(type_node) = node.child_by_field_name("type") else {
            self.lower_unsupported_expression(node);
            return;
        };
        let call = self.add_site(node, ResolutionSiteKind::Call);
        let receiver = super::graph_support::java_object_creation_enclosing_expression(
            node, type_node,
        )
        .map(|enclosing| {
            let input = self.expression_slot(enclosing);
            let output = self.add_slot(call, ResolutionTypeSlotRole::Receiver);
            self.add_transfer(input, output, ResolutionTypeTransferKind::Receiver);
            output
        });
        if let Some(receiver) = receiver {
            // JLS 15.9: a qualified creation names a member of the enclosing
            // expression's static type. An unknown receiver must leave this
            // member lookup incomplete; a lexical import cannot supply it.
            let mut member_type = type_node;
            while member_type.kind() == "generic_type" {
                member_type = member_type
                    .child_by_field_name("type")
                    .or_else(|| java_named_type_child(member_type))
                    .expect("Java generic creation type has a base type");
            }
            if let Some(name) = self
                .type_terminal_name(member_type)
                .filter(|name| !name.is_missing())
            {
                let reference = self.add_site(name, ResolutionSiteKind::MemberReference);
                let qualifier = self.add_slot(reference, ResolutionTypeSlotRole::Receiver);
                self.add_transfer_with_transform(
                    receiver,
                    qualifier,
                    ResolutionTypeTransferKind::Receiver,
                    ResolutionTypeTransferValueTransform::StaticTypeObject,
                );
                self.add_member_type_reference(reference, member_type, name, qualifier);
            } else {
                self.lower_unsupported_type(member_type);
            }
        }
        let type_qualified = self.type_terminal_name(type_node).is_some_and(|name| {
            name.parent()
                .is_some_and(|parent| parent.kind() == "scoped_type_identifier")
        });
        let constructed_type = self.lower_type(type_node);
        let Some(name) = self
            .type_terminal_name(type_node)
            .filter(|name| !name.is_missing())
        else {
            let callee = self.add_site(type_node, ResolutionSiteKind::UnsupportedExpression);
            self.add_gap(callee, ResolutionGapKind::UnsupportedTypeSyntax);
            let result = self.add_slot(call, ResolutionTypeSlotRole::CallResult);
            self.facts.add_single_result_call(
                call,
                callee,
                receiver,
                result,
                explicit_type_argument_count(node),
            );
            self.attach_call_arguments(node, call);
            self.expression_slots_by_node.insert(node.id(), result);
            return;
        };
        let callee = self.add_identifier_site(
            name,
            ResolutionSiteKind::ConstructorReference,
            self.current_scope(),
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Constructor,
            Some(constructed_type),
        );
        self.add_gap(callee, ResolutionGapKind::UnsupportedCallApplicability);
        let result = self.add_slot(call, ResolutionTypeSlotRole::CallResult);
        let expression_value = if let Some(body) = anonymous_body {
            assert!(
                self.anonymous_creation_results
                    .insert(body.id(), result)
                    .is_none()
            );
            // The anonymous declaration supplies the actual expression type,
            // including when its written base type is receiver-qualified.
            result
        } else {
            self.facts.binding_projections.push(BindingProjectionFact {
                reference: callee,
                output: result,
                kind: BindingProjectionKind::TargetConstructorOwnerType,
            });
            if receiver.is_some() || type_qualified {
                // Keep the constructor projection: it also anchors callable lookup.
                // The static creation type is independent of constructor selection,
                // so an expression value carries the selected member type even
                // when a constructor argument's type remains unknown.
                let value = self.add_slot(call, ResolutionTypeSlotRole::ExpressionValue);
                self.add_transfer(
                    constructed_type,
                    value,
                    ResolutionTypeTransferKind::Construction,
                );
                value
            } else {
                result
            }
        };
        self.facts.add_single_result_call(
            call,
            callee,
            receiver,
            result,
            explicit_type_argument_count(node),
        );
        self.facts
            .engine_rule_eligibilities
            .push(ResolutionEngineRuleEligibilityFact {
                site: call,
                rule: ResolutionEngineRuleKind::DefaultConstruction,
            });
        self.attach_call_arguments(node, call);
        self.expression_slots_by_node
            .insert(node.id(), expression_value);
    }

    fn finish_class_literal_expression(&mut self, node: Node<'_>) {
        if first_named_child(node).is_none() {
            self.lower_unsupported_expression_as(node, ResolutionGapKind::MalformedSyntax);
            return;
        }
        let site = self.add_site(node, ResolutionSiteKind::UnsupportedExpression);
        let output = self.add_slot(site, ResolutionTypeSlotRole::ExpressionValue);
        // The literal's operand is a resolved type reference above. The
        // runtime Class<?> result type is not modeled by the Java facts yet.
        self.add_gap(site, ResolutionGapKind::InferredType);
        self.expression_slots_by_node.insert(node.id(), output);
    }

    fn type_terminal_name<'tree>(&self, root: Node<'tree>) -> Option<Node<'tree>> {
        let mut current = root;
        loop {
            match current.kind() {
                "type_identifier" => return Some(current),
                "scoped_type_identifier" => {
                    return current
                        .child_by_field_name("name")
                        .or_else(|| named_children(current).into_iter().last());
                }
                "generic_type" => current = first_named_child(current)?,
                _ => return None,
            }
        }
    }

    fn lower_literal(&mut self, node: Node<'_>, spelling: &str, kind: IntrinsicTypeKind) {
        let site = self.add_site(node, ResolutionSiteKind::Literal);
        let output = self.add_slot(site, ResolutionTypeSlotRole::ExpressionValue);
        let name = self.intern_name(spelling);
        self.facts
            .intrinsic_type_seeds
            .push(IntrinsicTypeSeedFact::direct(output, name, kind));
        self.expression_slots_by_node.insert(node.id(), output);
    }

    fn lower_integer_literal(&mut self, node: Node<'_>) {
        let Some(spelling) = java_integer_literal_type(node, self.source) else {
            self.lower_unsupported_expression_as(node, ResolutionGapKind::AmbiguousNumericLiteral);
            return;
        };
        self.lower_literal(node, spelling, IntrinsicTypeKind::Primitive);
    }

    fn lower_unsupported_expression(&mut self, node: Node<'_>) {
        self.lower_unsupported_expression_as(node, ResolutionGapKind::UnsupportedExpression);
    }

    fn lower_unsupported_expression_as(&mut self, node: Node<'_>, kind: ResolutionGapKind) {
        if self.expression_slots_by_node.contains_key(&node.id()) {
            return;
        }
        let output = self.add_gap_slot(node, kind, ResolutionTypeSlotRole::ExpressionValue);
        self.expression_slots_by_node.insert(node.id(), output);
    }

    fn lower_unsupported_expression_preserving_children(&mut self, node: Node<'_>) {
        if self.expression_slots_by_node.contains_key(&node.id()) {
            return;
        }
        let site = self.add_site(node, ResolutionSiteKind::UnsupportedExpression);
        let output = self.add_slot(site, ResolutionTypeSlotRole::ExpressionValue);
        self.add_gap(site, ResolutionGapKind::UnsupportedExpression);
        self.expression_slots_by_node.insert(node.id(), output);
    }

    fn expression_slot(&self, node: Node<'_>) -> ResolutionTypeSlotId {
        *self
            .expression_slots_by_node
            .get(&node.id())
            .expect("expression dependency was lowered before its consumer")
    }

    fn slot(&self, id: ResolutionTypeSlotId) -> &ResolutionTypeSlotFact {
        self.facts.type_slot(id)
    }

    fn push_call_dependencies<'tree>(
        &mut self,
        node: Node<'tree>,
        stack: &mut Vec<(Node<'tree>, bool)>,
    ) {
        self.push_argument_dependencies(node, stack);
        if let Some(object) = node.child_by_field_name("object") {
            if matches!(object.kind(), "this" | "super") {
                // The current instance is represented by the callable
                // receiver origin and lexical type scope. It is not an
                // unsupported expression whose value needs a guessed type.
                assert!(self.claimed_identifier_nodes.insert(object.id()));
            } else {
                stack.push((object, false));
            }
        }
    }

    fn push_argument_dependencies<'tree>(
        &self,
        node: Node<'tree>,
        stack: &mut Vec<(Node<'tree>, bool)>,
    ) {
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        let mut cursor = arguments.walk();
        let values = arguments
            .named_children(&mut cursor)
            .filter(|value| !value.is_extra())
            .collect::<Vec<_>>();
        stack.extend(values.into_iter().rev().map(|value| (value, false)));
    }

    fn attach_call_arguments(&mut self, node: Node<'_>, call: ResolutionSiteId) {
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        let mut cursor = arguments.walk();
        for (ordinal, argument) in arguments
            .named_children(&mut cursor)
            .filter(|argument| !argument.is_extra())
            .enumerate()
        {
            let input = self.expression_slot(argument);
            crate::call_arguments::publish_jvm_call_argument(
                &mut self.facts,
                call,
                0,
                dense_ordinal(ordinal, "call argument"),
                Some(input),
                None,
            );
        }
    }

    fn current_type_owner(&self) -> Option<ResolutionSiteId> {
        (self.scope(self.current_scope()).kind == ResolutionScopeKind::TypeBody)
            .then(|| self.type_contexts.last().map(|context| context.declaration))
            .flatten()
    }

    fn scope_has_unsupported_implicit_receiver(&self, mut scope: ResolutionScopeId) -> bool {
        loop {
            if self.unsupported_implicit_receiver_scopes.contains(&scope) {
                return true;
            }
            let Some(parent) = self.scope(scope).parent else {
                return false;
            };
            scope = parent;
        }
    }

    fn register_local_value_binder(
        &mut self,
        scope: ResolutionScopeId,
        name: Node<'_>,
        activation_start: usize,
        activation_end: usize,
    ) {
        let spelling = node_text(name, self.source).trim();
        let name = self.intern_name(spelling);
        self.local_value_binders_by_scope
            .entry((scope, name))
            .or_default()
            .push((activation_start, activation_end));
    }

    fn has_visible_local_value(
        &self,
        name: ResolutionNameId,
        mut scope: ResolutionScopeId,
        byte: usize,
    ) -> bool {
        loop {
            if self
                .local_value_binders_by_scope
                .get(&(scope, name))
                .is_some_and(|bindings| {
                    bindings
                        .iter()
                        .any(|&(start, end)| start <= byte && byte < end)
                })
            {
                return true;
            }
            let Some(parent) = self.scope(scope).parent else {
                return false;
            };
            scope = parent;
        }
    }

    fn suppress_with_gap(
        &mut self,
        node: Node<'_>,
        site_kind: ResolutionSiteKind,
        gap_kind: ResolutionGapKind,
    ) -> TreeWalkAction {
        let site = self
            .expression_slots_by_node
            .get(&node.id())
            .map(|slot| self.slot(*slot).site)
            .or_else(|| {
                self.type_slots_by_node
                    .get(&node.id())
                    .map(|slot| self.slot(*slot).site)
            })
            .unwrap_or_else(|| self.add_site(node, site_kind));
        self.add_gap(site, gap_kind);
        self.add_reference_enumeration_gap_if_omitted(node, site, gap_kind);
        self.suppress_semantics()
    }

    fn suppress_semantics(&mut self) -> TreeWalkAction {
        self.suppression_depth += 1;
        self.exit_actions.push(ExitAction::Suppression);
        TreeWalkAction::DescendWithExit
    }

    fn add_gap(&mut self, site: ResolutionSiteId, kind: ResolutionGapKind) {
        self.facts.add_gap(site, kind);
    }

    fn add_reference_enumeration_gap_if_omitted(
        &mut self,
        node: Node<'_>,
        site: ResolutionSiteId,
        kind: ResolutionGapKind,
    ) {
        if kind == ResolutionGapKind::MalformedSyntax
            || (kind != ResolutionGapKind::InferredType
                && self.subtree_has_unclaimed_reference_occurrence(node))
        {
            self.add_reference_enumeration_gap(site, kind);
        }
    }

    fn subtree_has_unclaimed_reference_occurrence(&self, root: Node<'_>) -> bool {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if (is_spelled_identifier(node)
                || matches!(node.kind(), "type_identifier" | "this" | "super"))
                && !self.claimed_identifier_nodes.contains(&node.id())
            {
                return true;
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        false
    }

    fn add_reference_enumeration_gap(&mut self, site: ResolutionSiteId, kind: ResolutionGapKind) {
        self.facts.add_reference_enumeration_gap(site, kind);
    }

    fn add_declaration_visibility(
        &mut self,
        declaration: ResolutionSiteId,
        node: Node<'_>,
        source_declaration: SourceDeclarationId,
    ) {
        let (captured_declaration, visibility) = self
            .source_declaration_visibilities
            .get(&node.id())
            .copied()
            .expect("Java native visibility must consume a captured source property");
        assert_eq!(
            captured_declaration, source_declaration,
            "Java native visibility must use the exact source declaration identity"
        );
        self.record_declaration_visibility(declaration, visibility);
    }

    pub(super) fn source_modifiers_for(&self, node: Node<'_>) -> JavaDeclarationModifiers {
        *self
            .source_modifiers
            .get(&node.id())
            .expect("Java native modifier use must follow source capture")
    }

    pub(super) fn set_source_type_shape(&mut self, node: Node<'_>, shape: JavaTypeShape) {
        insert_source_shape(&mut self.source_type_shapes, node, shape, "type");
    }

    pub(super) fn source_type_shape_for(&self, node: Node<'_>) -> JavaTypeShape {
        *self
            .source_type_shapes
            .get(&node.id())
            .expect("Java native type-shape use must follow source capture")
    }

    pub(super) fn set_source_field_shape(&mut self, node: Node<'_>, shape: JavaFieldShape) {
        insert_source_shape(&mut self.source_field_shapes, node, shape, "field");
    }

    pub(super) fn source_field_shape_for(&self, node: Node<'_>) -> JavaFieldShape {
        *self
            .source_field_shapes
            .get(&node.id())
            .expect("Java native field-shape use must follow source capture")
    }

    pub(super) fn set_source_callable_shape(&mut self, node: Node<'_>, shape: JavaCallableShape) {
        insert_source_shape(&mut self.source_callable_shapes, node, shape, "callable");
    }

    pub(super) fn source_callable_shape_for(&self, node: Node<'_>) -> &JavaCallableShape {
        self.source_callable_shape_by_node_id(
            node.id(),
            "Java native callable-shape use must follow source capture",
        )
    }

    fn source_callable_shape_for_node(&self, node_id: usize) -> &JavaCallableShape {
        self.source_callable_shape_by_node_id(
            node_id,
            "Java native parameter use must follow callable source capture",
        )
    }

    fn source_callable_shape_by_node_id(
        &self,
        node_id: usize,
        missing_message: &str,
    ) -> &JavaCallableShape {
        self.source_callable_shapes
            .get(&node_id)
            .unwrap_or_else(|| panic!("{missing_message}"))
    }

    fn record_scoped_visibility(&mut self, declaration: ResolutionSiteId) {
        assert!(matches!(
            self.site(declaration).kind,
            ResolutionSiteKind::TypeDeclaration | ResolutionSiteKind::ConstructorDeclaration
        ));
        assert!(
            self.facts
                .declaration_visibilities
                .iter()
                .all(|fact| fact.declaration != declaration)
        );
        // Local and synthetic types have no Java access modifier. Their
        // lexical or synthetic scope controls reachability; they are never
        // package or member exports. The default constructor of a local class
        // shares that scope.
        self.facts
            .declaration_visibilities
            .push(ResolutionDeclarationVisibilityFact {
                declaration,
                visibility: DeclaredVisibility::Unknown,
            });
        self.facts
            .visibility_eligibilities
            .push(ResolutionVisibilityEligibilityFact { declaration });
    }

    fn record_declaration_visibility(
        &mut self,
        declaration: ResolutionSiteId,
        visibility: DeclaredVisibility,
    ) {
        assert!(matches!(
            self.site(declaration).kind,
            ResolutionSiteKind::TypeDeclaration
                | ResolutionSiteKind::CallableDeclaration
                | ResolutionSiteKind::ConstructorDeclaration
                | ResolutionSiteKind::ValueDeclaration
        ));
        assert!(
            self.facts
                .declaration_visibilities
                .iter()
                .all(|fact| fact.declaration != declaration),
            "one Java declaration visibility fact per supported declaration"
        );
        self.facts
            .declaration_visibilities
            .push(ResolutionDeclarationVisibilityFact {
                declaration,
                visibility,
            });
        self.facts
            .visibility_eligibilities
            .push(ResolutionVisibilityEligibilityFact { declaration });
        if visibility != DeclaredVisibility::Public {
            self.add_gap(declaration, ResolutionGapKind::UnsupportedVisibility);
        }
    }

    fn is_type_syntax(&self, kind: &str) -> bool {
        matches!(
            kind,
            "type_identifier"
                | "scoped_type_identifier"
                | "generic_type"
                | "array_type"
                | "integral_type"
                | "floating_point_type"
                | "boolean_type"
                | "void_type"
        )
    }

    fn is_scope_body(&self, node: Node<'_>) -> bool {
        matches!(
            node.kind(),
            "for_statement"
                | "enhanced_for_statement"
                | "try_with_resources_statement"
                | "class_body"
                | "interface_body"
                | "enum_body"
                | "annotation_type_body"
                | "record_body"
                | "block"
                | "constructor_body"
                | "switch_rule"
                | "switch_block_statement_group"
        )
    }

    fn record_persisted_type_identifier(&mut self, node: Node<'_>) {
        let text = node_text(node, self.source).trim();
        if !text.is_empty()
            && (matches!(node.kind(), "type_identifier" | "scoped_type_identifier")
                || (is_spelled_identifier(node)
                    && looks_like_pascal_identifier(text)
                    && !is_declared_name(node)))
        {
            self.type_identifiers.insert(text.to_string());
        }
    }
}

/// Return the Java primitive type of one tree-sitter integer-literal token.
///
/// The syntax node supplies the radix; the token text supplies only the
/// underscore-separated magnitude and optional `l`/`L` suffix. Decimal and
/// non-decimal literals have different positive ranges in Java because a
/// hexadecimal, octal, or binary literal may spell the two's-complement bit
/// pattern of a negative `int` or `long`. The one-extra-bit decimal magnitudes
/// are accepted only as the direct structured operand of unary minus, as the
/// Java grammar requires.
fn java_integer_literal_type(node: Node<'_>, source: &str) -> Option<&'static str> {
    let token = node_text(node, source);
    let (magnitude, is_long) =
        if let Some(magnitude) = token.strip_suffix('l').or_else(|| token.strip_suffix('L')) {
            (magnitude, true)
        } else {
            (token, false)
        };
    let (digits, radix, is_decimal) = match node.kind() {
        "decimal_integer_literal" => (magnitude, 10, true),
        "hex_integer_literal" => (
            magnitude
                .strip_prefix("0x")
                .or_else(|| magnitude.strip_prefix("0X"))?,
            16,
            false,
        ),
        "octal_integer_literal" => (magnitude.strip_prefix('0')?, 8, false),
        "binary_integer_literal" => (
            magnitude
                .strip_prefix("0b")
                .or_else(|| magnitude.strip_prefix("0B"))?,
            2,
            false,
        ),
        _ => return None,
    };
    let digits = digits.replace('_', "");
    let value = u64::from_str_radix(&digits, radix).ok()?;
    let maximum = match (is_decimal, is_long) {
        (true, false) => i32::MAX as u64,
        (false, false) => u32::MAX as u64,
        (true, true) => i64::MAX as u64,
        (false, true) => u64::MAX,
    };
    let fits = value <= maximum
        || (is_decimal
            && value == maximum + 1
            && java_integer_literal_is_direct_unary_minus_operand(node, source));
    fits.then_some(if is_long { "long" } else { "int" })
}

fn is_java_integer_literal(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "decimal_integer_literal"
            | "hex_integer_literal"
            | "octal_integer_literal"
            | "binary_integer_literal"
    )
}

fn java_integer_literal_is_direct_unary_minus_operand(node: Node<'_>, source: &str) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    parent.kind() == "unary_expression"
        && parent
            .child_by_field_name("operand")
            .is_some_and(|operand| operand.id() == node.id())
        && parent
            .child_by_field_name("operator")
            .is_some_and(|operator| node_text(operator, source) == "-")
}

// The grammar's scoped type has positional nominal children; annotations may
// occur between them and must not become the scope or terminal type name.
fn scoped_type_parts(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    debug_assert_eq!(node.kind(), "scoped_type_identifier");
    let mut cursor = node.walk();
    let mut children = node.named_children(&mut cursor).filter(|child| {
        matches!(
            child.kind(),
            "type_identifier" | "scoped_type_identifier" | "generic_type"
        )
    });
    let scope = children.next()?;
    let name = children.next()?;
    if children.next().is_some() {
        return None;
    }
    Some((scope, name))
}

fn explicit_type_argument_count(node: Node<'_>) -> u32 {
    dense_ordinal(
        brokk_bifrost_core::analyzer::tree_walk::named_child_count_by_field(node, "type_arguments"),
        "Java explicit invocation type argument",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::ProjectFile;
    use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionCallableReceiverOrigin;

    fn parse_file(source: &str) -> ParsedFile {
        let tree = super::super::declarations::parse_tree(source).expect("java tree");
        let root = std::env::current_dir()
            .expect("current directory")
            .join("java-resolution-fixture-root");
        let file = ProjectFile::new(root, "src/Fixture.java");
        super::super::declarations::parse_java_file(&file, source, &tree)
    }

    fn parse_once(source: &str) -> FileResolutionFacts {
        parse_file(source).resolution_facts
    }

    fn parse(source: &str) -> FileResolutionFacts {
        let facts = parse_once(source);
        assert_eq!(facts, parse_once(source), "fact rows must be deterministic");
        facts
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#3739: a recovered MISSING Java operand panicked during resolution instead of remaining a syntax gap"
    )]
    fn recovered_missing_operand_is_a_malformed_syntax_gap() {
        // Recovery inserts a zero-width MISSING identifier as the right
        // operand of `true +` (#3739).
        let facts = parse(
            "class Example { boolean f(boolean c) { if(c) return true +; else return false; } }",
        );
        assert!(
            facts
                .gaps
                .iter()
                .any(|gap| gap.kind == ResolutionGapKind::MalformedSyntax),
            "{:?}",
            facts.gaps
        );
    }

    #[test]
    fn recovered_missing_names_are_malformed_syntax_gaps() {
        // Recovery inserts zero-width MISSING tokens that report the kind they
        // stand in for; a declaration or expression gate that admits one meets
        // the identifier spelling invariant with an empty range (#4290).
        for source in [
            "static DEVICE_ID = \"\";",
            "class A { static DEVICE_ID = \"\"; }",
        ] {
            let facts = parse(source);
            assert!(
                facts
                    .gaps
                    .iter()
                    .any(|gap| gap.kind == ResolutionGapKind::MalformedSyntax),
                "{source:?}: {:?}",
                facts.gaps
            );
        }
        // The sibling declaration and expression gates reject MISSING names
        // the same way; each recovered snippet must surface some gap rather
        // than panic.
        for source in [
            "class {}",
            "class A { void () {} }",
            "class A { void f(int) {} }",
            "class A { void f(int...) {} }",
            "class A { void f() { foo.(); } }",
            "class A { void f() { new (); } }",
            "class A { B. x; }",
            "class A { void f() { ++; } }",
        ] {
            let facts = parse(source);
            assert!(!facts.gaps.is_empty(), "{source:?}");
        }
    }

    #[test]
    fn package_lookup_includes_type_or_value_qualified_receivers() {
        let facts = parse(
            "package use; class Caller { void call() { Peer.call(); } } class Peer { static void call() {} }",
        );
        let receiver = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == ResolutionNamespace::TypeOrValue
                    && name(&facts, identifier.name) == "Peer"
            })
            .expect("qualified Java expression receiver has a type/value reference");
        assert!(
            facts
                .package_references
                .iter()
                .any(|reference| reference.reference == receiver.site)
        );
    }

    #[test]
    fn top_level_anonymous_class_body_needs_no_enclosing_type() {
        // tree-sitter-java admits top-level statements (JEP 463), so an
        // anonymous class body can appear without any declared type (#4364).
        let facts = parse("package p; Runnable r = new Runnable() { public void run() {} };");
        let run = identifier(
            &facts,
            "run",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Callable,
        )
        .site;
        let owner = facts
            .member_owners
            .iter()
            .find(|owner| owner.member == run)
            .expect("run has a member owner");
        let synthetic = site(&facts, owner.owner);
        assert_eq!(synthetic.kind, ResolutionSiteKind::TypeDeclaration);
        let synthetic_identifier = identifier_for_site(&facts, owner.owner);
        assert!(
            name(&facts, synthetic_identifier.name).starts_with("$anon$"),
            "{:?}",
            synthetic_identifier
        );
    }

    #[test]
    fn top_level_main_anonymous_class_body_needs_no_enclosing_type() {
        let facts = parse("void main() { Object x = new X() { }; }");
        assert!(
            facts.identifiers.iter().any(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && identifier.namespace == ResolutionNamespace::Type
                    && name(&facts, identifier.name).starts_with("$anon$")
            }),
            "{:?}",
            facts.identifiers
        );
    }

    #[test]
    fn compact_constructor_in_a_plain_class_agrees_with_the_type_shape() {
        // The grammar admits a compact constructor as a direct child of a
        // plain class body; the captured constructor shape must count it so
        // admission does not contradict it (#4391).
        let facts = parse("class Odd { Odd { } }");
        identifier(
            &facts,
            "Odd",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Constructor,
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "09d3c596ba2e: an unavailable explicit Java type import must own its simple name without erasing lexical bindings"
    )]
    fn explicit_type_import_prevents_package_fallback_without_erasing_lexical_references() {
        let source = "package use; import missing.Target; import other.*; class Use { Target field; Peer peer; class Target {} }";
        let facts = parse(source);
        let target = facts
            .identifiers_named(
                "Target",
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Type,
            )
            .into_iter()
            .find(|identifier| {
                site(&facts, identifier.site).start_byte == source.find("Target field").unwrap()
            })
            .expect("field-type reference");
        assert!(
            facts
                .identifiers_named(
                    "Target",
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                )
                .iter()
                .any(|identifier| site(&facts, identifier.site).start_byte
                    == source.find("Target;").unwrap())
        );
        assert!(
            !facts
                .package_references
                .iter()
                .any(|reference| reference.reference == target.site)
        );
        assert!(facts.package_references.iter().any(|reference| {
            facts.identifiers.iter().any(|identifier| {
                identifier.site == reference.reference && name(&facts, identifier.name) == "Peer"
            })
        }));
        let demand = facts
            .root_import_demands
            .iter()
            .find(|demand| name(&facts, demand.name) == "Target")
            .unwrap();
        assert_eq!(
            facts
                .root_import_demands
                .iter()
                .filter(|candidate| candidate.name == demand.name)
                .count(),
            2
        );
        assert!(
            facts
                .import_routes
                .iter()
                .any(|import| import.site == demand.import_site
                    && import.kind == ResolutionImportRouteKind::SingleType)
        );
        let local = identifier(
            &facts,
            "Target",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        );
        assert!(
            facts
                .binders
                .iter()
                .any(|binder| binder.declaration == local.site)
        );
    }

    fn name(facts: &FileResolutionFacts, id: ResolutionNameId) -> &str {
        facts.name(id)
    }

    fn identifier<'a>(
        facts: &'a FileResolutionFacts,
        spelling: &str,
        role: ResolutionIdentifierRole,
        namespace: ResolutionNamespace,
    ) -> &'a PositionedIdentifierFact {
        let mut matches = facts
            .identifiers_named(spelling, role, namespace)
            .into_iter();
        let result = matches
            .next()
            .unwrap_or_else(|| panic!("missing {role:?} {namespace:?} identifier {spelling:?}"));
        assert!(
            matches.next().is_none(),
            "identifier lookup was not unique for {spelling:?}"
        );
        result
    }

    fn site(facts: &FileResolutionFacts, id: ResolutionSiteId) -> ResolutionSiteFact {
        *resolution_site(facts, id)
    }

    fn slot(facts: &FileResolutionFacts, id: ResolutionTypeSlotId) -> ResolutionTypeSlotFact {
        *facts.type_slot(id)
    }

    fn identifier_for_site(
        facts: &FileResolutionFacts,
        site: ResolutionSiteId,
    ) -> &PositionedIdentifierFact {
        facts
            .identifiers
            .iter()
            .find(|identifier| identifier.site == site)
            .expect("identifier site")
    }

    fn identifier_spellings(facts: &FileResolutionFacts) -> Vec<&str> {
        facts
            .identifiers
            .iter()
            .map(|identifier| name(facts, identifier.name))
            .collect()
    }

    fn declaration_visibilities(
        facts: &FileResolutionFacts,
        spelling: &str,
        kind: ResolutionSiteKind,
    ) -> Vec<DeclaredVisibility> {
        facts
            .declaration_visibilities
            .iter()
            .filter_map(|fact| {
                let identifier = identifier_for_site(facts, fact.declaration);
                (name(facts, identifier.name) == spelling
                    && site(facts, fact.declaration).kind == kind)
                    .then_some(fact.visibility)
            })
            .collect()
    }

    fn visibility_gap_sites(facts: &FileResolutionFacts) -> Vec<ResolutionSiteId> {
        facts
            .gaps
            .iter()
            .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedVisibility)
            .map(|gap| gap.site)
            .collect()
    }

    fn non_visibility_gaps(facts: &FileResolutionFacts) -> Vec<ResolutionGapFact> {
        facts
            .gaps
            .iter()
            .filter(|gap| gap.kind != ResolutionGapKind::UnsupportedVisibility)
            .cloned()
            .collect()
    }

    fn intrinsic_seed_at(
        facts: &FileResolutionFacts,
        start_byte: usize,
    ) -> Option<&IntrinsicTypeSeedFact> {
        facts.intrinsic_type_seeds.iter().find(|seed| {
            let output = slot(facts, seed.output);
            site(facts, output.site).start_byte == start_byte
        })
    }

    fn gap_at(
        facts: &FileResolutionFacts,
        start_byte: usize,
        kind: ResolutionGapKind,
    ) -> Option<&ResolutionGapFact> {
        facts
            .gaps
            .iter()
            .find(|gap| gap.kind == kind && site(facts, gap.site).start_byte == start_byte)
    }

    fn implicit_superclass_reference(
        facts: &FileResolutionFacts,
        owner: ResolutionSiteId,
    ) -> ResolutionSiteId {
        facts
            .supertypes
            .iter()
            .find(|edge| {
                edge.subtype == owner
                    && site(facts, edge.supertype_reference).kind
                        == ResolutionSiteKind::SyntheticReference
            })
            .expect("ordinary class has a synthetic superclass reference")
            .supertype_reference
    }

    #[test]
    fn declaration_visibility_facts_apply_java_defaults_and_exact_local_gaps() {
        let source = r#"
            public class PublicTop {
                public PublicTop() {}
                protected PublicTop(int protectedArgument) {}
                PublicTop(String packageArgument) {}
                private PublicTop(long privateArgument) {}

                public int publicField, publicFieldTwo;
                protected int protectedField;
                int packageField;
                private int privateField;

                public void publicMethod() {}
                protected void protectedMethod() {}
                void packageMethod() {}
                private void privateMethod() {}

                protected class ProtectedNested {}
                class PackageNested {}
                private class PrivateNested {}

                interface ImplicitInterface {
                    int implicitInterfaceField = 1;
                    void implicitInterfaceMethod();
                    private void explicitPrivateInterfaceMethod() {}
                    class InterfaceNested {}
                }

                @interface ImplicitAnnotation {
                    String value();
                    int implicitAnnotationField = 1;
                    class AnnotationNested {}
                }

                void locals(int parameterOnly) { int localOnly = 0; }
                enum E { ENUM_CONSTANT }
            }

            class PackageTop {}
            record PackageRecord(int recordComponentOnly) {
                PackageRecord {}
            }
        "#;
        let facts = parse(source);

        // Thirty-two declarations and the six default constructors of the
        // classes that write none, which take their class's access.
        assert_eq!(facts.declaration_visibilities.len(), 38);
        assert_eq!(facts.visibility_eligibilities.len(), 38);
        assert!(facts.declaration_visibilities.iter().all(|visibility| {
            facts
                .visibility_eligibilities
                .iter()
                .any(|eligibility| eligibility.declaration == visibility.declaration)
        }));
        for (spelling, visibility) in [
            ("PublicTop", DeclaredVisibility::Public),
            ("ProtectedNested", DeclaredVisibility::Protected),
            ("PackageNested", DeclaredVisibility::PackagePrivate),
            ("PrivateNested", DeclaredVisibility::Private),
            ("ImplicitInterface", DeclaredVisibility::PackagePrivate),
            ("InterfaceNested", DeclaredVisibility::Public),
            ("ImplicitAnnotation", DeclaredVisibility::PackagePrivate),
            ("AnnotationNested", DeclaredVisibility::Public),
            ("E", DeclaredVisibility::PackagePrivate),
            ("PackageTop", DeclaredVisibility::PackagePrivate),
            ("PackageRecord", DeclaredVisibility::PackagePrivate),
        ] {
            assert_eq!(
                declaration_visibilities(&facts, spelling, ResolutionSiteKind::TypeDeclaration),
                vec![visibility],
                "effective type visibility for {spelling}"
            );
        }
        assert_eq!(
            declaration_visibilities(
                &facts,
                "PublicTop",
                ResolutionSiteKind::ConstructorDeclaration
            ),
            vec![
                DeclaredVisibility::Public,
                DeclaredVisibility::Protected,
                DeclaredVisibility::PackagePrivate,
                DeclaredVisibility::Private,
            ]
        );
        assert_eq!(
            declaration_visibilities(
                &facts,
                "PackageRecord",
                ResolutionSiteKind::ConstructorDeclaration
            ),
            vec![DeclaredVisibility::PackagePrivate]
        );
        for (spelling, visibility) in [
            ("publicField", DeclaredVisibility::Public),
            ("publicFieldTwo", DeclaredVisibility::Public),
            ("protectedField", DeclaredVisibility::Protected),
            ("packageField", DeclaredVisibility::PackagePrivate),
            ("privateField", DeclaredVisibility::Private),
            ("implicitInterfaceField", DeclaredVisibility::Public),
            ("implicitAnnotationField", DeclaredVisibility::Public),
        ] {
            assert_eq!(
                declaration_visibilities(&facts, spelling, ResolutionSiteKind::ValueDeclaration),
                vec![visibility],
                "effective field visibility for {spelling}"
            );
        }
        for (spelling, visibility) in [
            ("publicMethod", DeclaredVisibility::Public),
            ("protectedMethod", DeclaredVisibility::Protected),
            ("packageMethod", DeclaredVisibility::PackagePrivate),
            ("privateMethod", DeclaredVisibility::Private),
            ("implicitInterfaceMethod", DeclaredVisibility::Public),
            (
                "explicitPrivateInterfaceMethod",
                DeclaredVisibility::Private,
            ),
            ("value", DeclaredVisibility::Public),
            ("locals", DeclaredVisibility::PackagePrivate),
        ] {
            assert_eq!(
                declaration_visibilities(&facts, spelling, ResolutionSiteKind::CallableDeclaration),
                vec![visibility],
                "effective callable visibility for {spelling}"
            );
        }

        let visibility_declarations = facts
            .declaration_visibilities
            .iter()
            .map(|fact| fact.declaration)
            .collect::<Vec<_>>();
        let expected_gaps = facts
            .declaration_visibilities
            .iter()
            .filter(|fact| {
                matches!(
                    fact.visibility,
                    DeclaredVisibility::Protected
                        | DeclaredVisibility::PackagePrivate
                        | DeclaredVisibility::Private
                )
            })
            .map(|fact| fact.declaration)
            .collect::<Vec<_>>();
        let actual_gaps = facts
            .gaps
            .iter()
            .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedVisibility)
            .map(|gap| gap.site)
            .collect::<Vec<_>>();
        assert_eq!(actual_gaps, expected_gaps);
        assert!(
            facts
                .identifiers
                .iter()
                .filter(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Declaration
                        && matches!(
                            name(&facts, identifier.name),
                            "protectedArgument"
                                | "packageArgument"
                                | "privateArgument"
                                | "parameterOnly"
                                | "localOnly"
                        )
                })
                .all(|identifier| !visibility_declarations.contains(&identifier.site))
        );
        assert_eq!(
            declaration_visibilities(
                &facts,
                "ENUM_CONSTANT",
                ResolutionSiteKind::ValueDeclaration
            ),
            vec![DeclaredVisibility::Public]
        );
        assert!(facts.declaration_visibilities.iter().all(|fact| {
            name(&facts, identifier_for_site(&facts, fact.declaration).name)
                != "recordComponentOnly"
        }));
    }

    #[test]
    fn enum_constructors_without_access_modifiers_are_effectively_private() {
        let facts = parse("enum E { A; E() {} private E(int x) {} }");
        let constructor_facts = facts
            .declaration_visibilities
            .iter()
            .filter(|fact| {
                site(&facts, fact.declaration).kind == ResolutionSiteKind::ConstructorDeclaration
                    && name(&facts, identifier_for_site(&facts, fact.declaration).name) == "E"
            })
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(constructor_facts.len(), 2);
        assert!(
            constructor_facts
                .iter()
                .all(|fact| fact.visibility == DeclaredVisibility::Private)
        );

        let constructor_sites = constructor_facts
            .iter()
            .map(|fact| fact.declaration)
            .collect::<Vec<_>>();
        let constructor_visibility_gaps = facts
            .gaps
            .iter()
            .filter(|gap| {
                gap.kind == ResolutionGapKind::UnsupportedVisibility
                    && constructor_sites.contains(&gap.site)
            })
            .map(|gap| gap.site)
            .collect::<Vec<_>>();
        assert_eq!(constructor_visibility_gaps, constructor_sites);
    }

    #[test]
    fn qualified_nested_type_rows_preserve_shape_with_explicit_root_ambiguity() {
        // IntelliJ Community psi/resolve class/ClassExtendsItsInner1.
        let source = "class A extends B.Foo implements B {} interface B { static class Foo {} }";
        let facts = parse(source);

        let a = identifier(
            &facts,
            "A",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        )
        .site;
        let b = identifier(
            &facts,
            "B",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        )
        .site;
        let foo = identifier(
            &facts,
            "Foo",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        )
        .site;

        assert_eq!(facts.scopes.len(), 4);
        assert_eq!(
            facts
                .scopes
                .iter()
                .map(|scope| (scope.kind, scope.parent, scope.owner))
                .collect::<Vec<_>>(),
            vec![
                (ResolutionScopeKind::CompilationUnit, None, None),
                (
                    ResolutionScopeKind::TypeBody,
                    Some(ResolutionScopeId::new(0)),
                    Some(a),
                ),
                (
                    ResolutionScopeKind::TypeBody,
                    Some(ResolutionScopeId::new(0)),
                    Some(b),
                ),
                (
                    ResolutionScopeKind::TypeBody,
                    Some(ResolutionScopeId::new(2)),
                    Some(foo),
                ),
            ]
        );
        assert_eq!(
            facts
                .member_owners
                .iter()
                .filter(|owner| owner.kind == ResolutionMemberKind::NestedType)
                .copied()
                .collect::<Vec<_>>(),
            vec![ResolutionMemberOwnerFact {
                member: foo,
                owner: b,
                kind: ResolutionMemberKind::NestedType,
                access: ResolutionMemberAccess::Type,
                qualifier_compatibility: ResolutionMemberQualifierCompatibility::TypeOnly,
            }]
        );

        let foo_reference = identifier(
            &facts,
            "Foo",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Type,
        );
        let qualifier = foo_reference.qualifier.expect("B qualifier slot");
        let qualifier_site = slot(&facts, qualifier).site;
        assert_eq!(
            name(&facts, identifier_for_site(&facts, qualifier_site).name),
            "B"
        );
        assert!(facts.binding_projections.iter().any(|projection| {
            projection.reference == foo_reference.site
                && projection.kind == BindingProjectionKind::TargetTypeIdentity
        }));
        assert_eq!(facts.supertypes.len(), 3);
        let superclass = facts
            .supertypes
            .iter()
            .find(|row| row.kind == ResolutionSupertypeKind::Superclass)
            .expect("class superclass row");
        assert_eq!(superclass.subtype, a);
        assert_eq!(superclass.supertype_reference, foo_reference.site);
        assert_eq!(
            slot(&facts, superclass.supertype_slot).site,
            foo_reference.site
        );
        let interface = facts
            .supertypes
            .iter()
            .find(|row| row.kind == ResolutionSupertypeKind::Interface)
            .expect("implemented interface row");
        assert_eq!(interface.subtype, a);
        assert_eq!(
            name(
                &facts,
                identifier_for_site(&facts, interface.supertype_reference).name,
            ),
            "B"
        );
        assert_eq!(
            slot(&facts, interface.supertype_slot).site,
            interface.supertype_reference
        );
        assert_eq!(
            non_visibility_gaps(&facts),
            vec![
                ResolutionGapFact::new(qualifier_site, ResolutionGapKind::AmbiguousQualifiedType),
                ResolutionGapFact::new(
                    foo_reference.site,
                    ResolutionGapKind::AmbiguousQualifiedType
                ),
                ResolutionGapFact::new(
                    foo_reference.site,
                    ResolutionGapKind::UnsupportedHierarchyTraversal
                ),
                ResolutionGapFact::new(
                    interface.supertype_reference,
                    ResolutionGapKind::UnsupportedHierarchyTraversal
                ),
                ResolutionGapFact::new(
                    implicit_superclass_reference(&facts, foo),
                    ResolutionGapKind::UnsupportedHierarchyTraversal
                ),
                ResolutionGapFact::new(b, ResolutionGapKind::UnsupportedHierarchyTraversal),
                ResolutionGapFact::new(
                    facts.gaps.last().expect("placement gap").site,
                    ResolutionGapKind::UnsupportedPlacementBoundary
                ),
            ]
        );
        // `A` is package-private, and so is the default constructor it supplies.
        let a_constructor = identifier(
            &facts,
            "A",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Constructor,
        )
        .site;
        assert_eq!(visibility_gap_sites(&facts), vec![a, a_constructor, b]);
    }

    #[test]
    fn local_scope_begins_with_its_own_initializer() {
        let source = "class C { int x; void f() { int x = x; } }";
        let facts = parse(source);
        let rhs = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == ResolutionNamespace::Value
                    && name(&facts, identifier.name) == "x"
            })
            .expect("initializer x reference");
        let local = facts
            .binders
            .iter()
            .find(|binder| {
                binder.kind == ResolutionBinderKind::Local
                    && name(&facts, identifier_for_site(&facts, binder.declaration).name) == "x"
            })
            .expect("local x binder");

        assert_eq!(local.hoisting, HoistingClass::SourceOrder);
        assert_eq!(
            local.activation_start,
            site(&facts, rhs.site).start_byte,
            "JLS 6.3 puts the local in scope throughout its own initializer"
        );
        assert!(local.activation_start > site(&facts, local.declaration).end_byte);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5015: Java reassignment lost RHS values and chained assignments read the stale left value"
    )]
    fn local_writes_use_rhs_values_and_keep_unsupported_mutations_open() {
        let source = "class Box { Box member; void use(Box[] values, int[] items) { \
                      Box first = new Box(); Box second = new Box(); \
                      first = second = new Box(); int count = 0; count += 1; count++; \
                      this.member = second; items[0] = 1; first = values[0]; } }";
        let facts = parse(source);
        let mut writes = facts.local_writes.iter().collect::<Vec<_>>();
        writes.sort_unstable_by_key(|write| site(&facts, write.target).start_byte);
        assert_eq!(writes.len(), 5, "{:?}", facts.local_writes);
        assert_eq!(
            writes[0].value, writes[1].value,
            "both chained writes take the RHS"
        );
        let value_site = site(&facts, facts.type_slot(writes[0].value).site);
        assert_eq!(
            &source[value_site.start_byte..value_site.end_byte],
            "new Box()"
        );
        for write in &writes {
            let target = identifier_for_site(&facts, write.target);
            assert_eq!(target.role, ResolutionIdentifierRole::Reference);
            assert!(target.qualifier.is_none());
            assert!(matches!(
                name(&facts, target.name),
                "first" | "second" | "count"
            ));
        }
        for write in &writes[2..] {
            let value_site = facts.type_slot(write.value).site;
            assert!(
                facts.gaps.iter().any(|gap| gap.site == value_site),
                "{:?}",
                facts.gaps
            );
            assert!(
                !facts
                    .type_transfers
                    .iter()
                    .any(|transfer| transfer.output == write.value)
            );
        }
        for spelling in ["this.member = second", "items[0] = 1"] {
            assert!(
                facts.gaps.iter().any(|gap| {
                    let site = site(&facts, gap.site);
                    gap.kind == ResolutionGapKind::UnsupportedExpression
                        && &source[site.start_byte..site.end_byte] == spelling
                }),
                "{:?}",
                facts.gaps
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5015: implicit local inputs disappeared when later writes supplied known values"
    )]
    fn implicit_local_inputs_are_unknown_without_gapping_declared_types() {
        let facts = parse(
            "class Box { void use(Box[] items, Object selector) { \
             Box pending; Box direct = new Box(); \
             for (Box item : items) { item = new Box(); } \
             try {} catch (RuntimeException caught) { caught = new RuntimeException(); } \
             switch (selector) { case Box matched -> { matched = new Box(); } default -> {} } \
             } }",
        );
        assert_eq!(facts.local_writes.len(), 3);
        for (spelling, role) in [
            ("item", DeclarationTypeRole::Value),
            ("caught", DeclarationTypeRole::Parameter),
            ("matched", DeclarationTypeRole::Value),
        ] {
            let declaration = identifier(
                &facts,
                spelling,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Value,
            )
            .site;
            let declared = facts
                .declaration_type_slots
                .iter()
                .find(|row| row.declaration == declaration && row.role == role)
                .expect("implicit local keeps its static type");
            assert!(facts.type_transfers.iter().any(|row| {
                row.output == declared.slot && row.kind == ResolutionTypeTransferKind::DeclaredType
            }));
            assert!(!facts.gaps.iter().any(|gap| gap.site == declaration));
            let observations = facts
                .type_transfers
                .iter()
                .filter(|row| {
                    row.kind == ResolutionTypeTransferKind::Assignment
                        && facts.type_slot(row.output).site == declaration
                })
                .collect::<Vec<_>>();
            assert_eq!(observations.len(), 1, "{spelling}: {observations:?}");
            assert_eq!(
                facts.type_slot(observations[0].output).role,
                ResolutionTypeSlotRole::AssignmentValue
            );
            let incoming = facts.type_slot(observations[0].input).site;
            assert_ne!(incoming, declaration);
            assert!(facts.gaps.contains(&ResolutionGapFact::new(
                incoming,
                ResolutionGapKind::InferredType
            )));
            assert!(
                !facts
                    .type_transfers
                    .iter()
                    .any(|row| row.output == observations[0].input)
            );
            assert!(
                !facts
                    .reference_enumeration_gaps
                    .iter()
                    .any(|gap| gap.site == incoming)
            );
        }
        for spelling in ["pending", "items", "selector"] {
            let declaration = identifier(
                &facts,
                spelling,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Value,
            )
            .site;
            assert!(!facts.type_slots.iter().any(|slot| {
                slot.site == declaration && slot.role == ResolutionTypeSlotRole::AssignmentValue
            }));
        }
    }

    #[test]
    fn member_qualifier_compatibility_is_producer_owned_java_semantics() {
        let facts = parse(
            "class Members { static int sf; int f; static void sm() {} void m() {} class Inner {} Members() {} }",
        );
        let member = |spelling, namespace| {
            identifier(
                &facts,
                spelling,
                ResolutionIdentifierRole::Declaration,
                namespace,
            )
            .site
        };
        let owner_for = |member| {
            facts
                .member_owners
                .iter()
                .find(|owner| owner.member == member)
                .copied()
                .expect("member owner row")
        };

        for (spelling, namespace) in [
            ("sf", ResolutionNamespace::Value),
            ("sm", ResolutionNamespace::Callable),
        ] {
            let owner = owner_for(member(spelling, namespace));
            assert_eq!(owner.access, ResolutionMemberAccess::Type);
            assert_eq!(
                owner.qualifier_compatibility,
                ResolutionMemberQualifierCompatibility::RuntimeOrType
            );
        }
        for (spelling, namespace) in [
            ("f", ResolutionNamespace::Value),
            ("m", ResolutionNamespace::Callable),
        ] {
            let owner = owner_for(member(spelling, namespace));
            assert_eq!(owner.access, ResolutionMemberAccess::Instance);
            assert_eq!(
                owner.qualifier_compatibility,
                ResolutionMemberQualifierCompatibility::RuntimeOnly
            );
        }
        for (spelling, namespace) in [
            ("Inner", ResolutionNamespace::Type),
            ("Members", ResolutionNamespace::Constructor),
        ] {
            let owner = owner_for(member(spelling, namespace));
            assert_eq!(owner.access, ResolutionMemberAccess::Type);
            assert_eq!(
                owner.qualifier_compatibility,
                ResolutionMemberQualifierCompatibility::TypeOnly
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "0242909d77ed: Java census G09 (2026-10-15): super method calls lacked the enclosing class superclass type"
    )]
    fn super_receiver_uses_the_lexical_superclass_identity() {
        let facts = parse(
            "class Base<T> { void run() {} } class Leaf<T> extends Base<T> { void run() {} void f() { super.run(); } }",
        );
        let origin = facts
            .callable_receiver_origins
            .iter()
            .find(|row| row.origin == ResolutionCallableReceiverOrigin::Super)
            .expect("super call");
        let receiver = facts
            .identifiers
            .iter()
            .find(|row| row.site == origin.reference)
            .expect("callable reference")
            .qualifier
            .expect("super receiver");
        let superclass = facts
            .supertypes
            .iter()
            .find(|row| row.kind == ResolutionSupertypeKind::Superclass)
            .expect("written superclass");
        let identity = facts
            .binding_projections
            .iter()
            .find(|projection| {
                projection.reference == superclass.supertype_reference
                    && projection.output != superclass.supertype_slot
            })
            .expect("super receiver selects the nominal superclass independently of its hierarchy frontier")
            .output;
        let arguments = facts
            .declared_type_arguments
            .iter()
            .filter(|argument| argument.owner == superclass.supertype_slot)
            .collect::<Vec<_>>();
        assert!(!arguments.is_empty(), "generic superclass fixture");
        for argument in arguments {
            assert!(
                facts
                    .declared_type_arguments
                    .contains(&ResolutionDeclaredTypeArgumentFact {
                        owner: identity,
                        ..*argument
                    })
            );
        }
        assert!(
            facts.type_transfers.iter().any(|transfer| {
                transfer.input == identity
                    && transfer.output == receiver
                    && matches!(
                        transfer.value_transform,
                        ResolutionTypeTransferValueTransform::ToRuntime { addressable: false }
                    )
            }),
            "{:?}",
            facts.type_transfers
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "0242909d77ed: Java census G08 (2026-10-15): anonymous creation omitted its constructor and allocation result facts"
    )]
    fn anonymous_creation_keeps_a_constructor_call_and_written_supertype() {
        for source in [
            "interface Task { void run(); } class App { Task value = new Task() { public void run() {} }; }",
            "interface Task { void run(); } interface Factory { Task make(); } class App { Factory value = () -> new Task() { public void run() {} }; }",
        ] {
            let parsed = parse_file(source);
            let facts = &parsed.resolution_facts;
            let creation_start = source.find("new Task").expect("creation");
            let call = facts
                .calls
                .iter()
                .find(|call| facts.sites[call.call.index()].start_byte == creation_start)
                .expect("anonymous constructor call");
            assert_eq!(
                facts.sites[call.callee.index()].kind,
                ResolutionSiteKind::ConstructorReference
            );
            assert!(
                facts.identifiers.iter().any(|row| {
                    row.role == ResolutionIdentifierRole::Reference
                        && row.namespace == ResolutionNamespace::Type
                        && facts.names[row.name.index()].spelling == "Task"
                }),
                "{:?}",
                facts.identifiers
            );
            let allocation_type = facts
                .type_transfers
                .iter()
                .find(|transfer| {
                    transfer.output == call.result
                        && transfer.kind == ResolutionTypeTransferKind::Construction
                })
                .expect("anonymous allocation type")
                .input;
            let identity = facts
                .binding_projections
                .iter()
                .find(|projection| projection.output == allocation_type)
                .expect("synthetic allocation identity projection");
            assert_eq!(
                facts.sites[identity.reference.index()].kind,
                ResolutionSiteKind::SyntheticReference
            );
            let reference = facts
                .identifiers
                .iter()
                .find(|identifier| identifier.site == identity.reference)
                .expect("synthetic self reference");
            assert!(
                facts
                    .identifiers
                    .iter()
                    .any(|identifier| identifier.name == reference.name
                        && identifier.role == ResolutionIdentifierRole::Declaration
                        && facts.sites[identifier.site.index()].kind
                            == ResolutionSiteKind::TypeDeclaration),
                "{:?}",
                facts.identifiers
            );
            let declaration = facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.name == reference.name
                        && identifier.role == ResolutionIdentifierRole::Declaration
                        && facts.sites[identifier.site.index()].kind
                            == ResolutionSiteKind::TypeDeclaration
                })
                .expect("synthetic declaration");
            let unit = facts
                .definition_units
                .iter()
                .find(|unit| unit.declaration == declaration.site)
                .expect("generated allocation identity has its parser-unit projection");
            assert!(unit.unit.is_class() && unit.unit.is_synthetic(), "{unit:?}");
            assert!(
                !facts.gaps.iter().any(|gap| {
                    gap.kind == ResolutionGapKind::UnsupportedExpression
                        && facts.sites[gap.site.index()].start_byte == creation_start
                }),
                "{:?}",
                facts.gaps
            );
        }
    }

    #[test]
    fn callable_receiver_origins_cover_each_terminal_reference_once() {
        let facts = parse(
            r#"
                class Base {
                    void fromSuper() {}
                }
                class Fixture extends Base {
                    static void fromType() {}
                    void bare() {}
                    void fromThis() {}
                    void fromPeer() {}

                    void exercise(Fixture peer) {
                        bare();
                        this.fromThis();
                        super.fromSuper();
                        Fixture.fromType();
                        peer.fromPeer();
                    }
                }
            "#,
        );
        let references = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == ResolutionNamespace::Callable
            })
            .collect::<Vec<_>>();
        assert_eq!(references.len(), 5);
        assert_eq!(facts.callable_receiver_origins.len(), references.len());

        let expected = [
            ("bare", ResolutionCallableReceiverOrigin::Implicit, false),
            (
                "fromThis",
                ResolutionCallableReceiverOrigin::CurrentInstance,
                false,
            ),
            ("fromSuper", ResolutionCallableReceiverOrigin::Super, true),
            (
                "fromType",
                ResolutionCallableReceiverOrigin::ExplicitExpression,
                true,
            ),
            (
                "fromPeer",
                ResolutionCallableReceiverOrigin::ExplicitExpression,
                true,
            ),
        ];
        for (spelling, origin, qualified) in expected {
            let reference = references
                .iter()
                .copied()
                .find(|reference| name(&facts, reference.name) == spelling)
                .unwrap_or_else(|| panic!("missing callable reference {spelling:?}"));
            let receiver_rows = facts
                .callable_receiver_origins
                .iter()
                .filter(|receiver| receiver.reference == reference.site)
                .collect::<Vec<_>>();
            assert_eq!(
                receiver_rows.len(),
                1,
                "each terminal callable reference needs exactly one receiver origin"
            );
            assert_eq!(receiver_rows[0].origin, origin);
            assert_eq!(reference.qualifier.is_some(), qualified);
            assert_eq!(
                site(&facts, reference.site).kind,
                match origin {
                    ResolutionCallableReceiverOrigin::Implicit => {
                        ResolutionSiteKind::CallableReference
                    }
                    ResolutionCallableReceiverOrigin::CurrentInstance
                    | ResolutionCallableReceiverOrigin::Super
                    | ResolutionCallableReceiverOrigin::ExplicitExpression => {
                        ResolutionSiteKind::MemberReference
                    }
                },
                "explicit receiver syntax must retain a member reference site"
            );
        }
    }

    #[test]
    fn generic_callable_and_invocation_arities_are_structured() {
        let source = "class C { <T, U> void f() {} void g() { this.<String, Integer>f(); } }";
        let facts = parse(source);
        let declaration = identifier(
            &facts,
            "f",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Callable,
        )
        .site;
        let reference = identifier(
            &facts,
            "f",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Callable,
        )
        .site;
        assert_eq!(
            facts
                .callable_signatures
                .iter()
                .find(|signature| signature.callable == declaration)
                .expect("generic method signature header")
                .type_parameter_count,
            2
        );
        assert_eq!(
            facts
                .calls
                .iter()
                .find(|call| call.callee == reference)
                .expect("generic method invocation")
                .explicit_type_argument_count,
            2
        );
    }

    #[test]
    fn method_result_type_is_published_for_call_result_projection() {
        let source = "class Token {} class App { Token source() { return null; } void sink(Token value) {} void run() { sink(source()); } }";
        let facts = parse(source);
        let declaration = identifier(
            &facts,
            "source",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Callable,
        )
        .site;
        let signature = facts
            .callable_signatures
            .iter()
            .find(|signature| signature.callable == declaration)
            .expect("source method signature");
        let [result] = signature.result_types.as_slice() else {
            panic!("Java method return type must reach the selected call result: {signature:?}");
        };
        assert_eq!(result.ordinal, 0);
        assert_eq!(
            slot(&facts, result.value_type).role,
            ResolutionTypeSlotRole::DeclaredValue
        );
        assert_eq!(slot(&facts, result.value_type).site, declaration);
    }

    #[test]
    fn chained_call_field_rows_join_only_through_slots() {
        // Externally grounded by IntelliJ's chained_method_return_type and
        // member_through_method_return_type cases: a field lookup consumes the
        // declared result of the immediately preceding call.
        let source = "class B { int field; } class A { B make() { return new B(); } } class Main { int run(A a) { return a.make().field; } }";
        let facts = parse(source);

        let make_reference = identifier(
            &facts,
            "make",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Callable,
        );
        let make_call = facts
            .calls
            .iter()
            .find(|call| call.callee == make_reference.site)
            .expect("make call");
        let field_reference = identifier(
            &facts,
            "field",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::TypeOrValue,
        );
        let field_receiver = field_reference.qualifier.expect("field receiver slot");
        assert!(facts.type_transfers.contains(&ResolutionTypeTransferFact {
            input: make_call.result,
            output: field_receiver,
            kind: ResolutionTypeTransferKind::Receiver,
            indirection_delta: 0,
            reference_indirection_delta: 0,
            value_transform: ResolutionTypeTransferValueTransform::Preserve,
        }));

        let make_receiver = make_reference.qualifier.expect("make receiver slot");
        let a_input = facts
            .type_transfers
            .iter()
            .find(|transfer| transfer.output == make_receiver)
            .expect("a receiver transfer")
            .input;
        assert_eq!(
            name(
                &facts,
                identifier_for_site(&facts, slot(&facts, a_input).site).name,
            ),
            "a"
        );
        let make_declaration = identifier(
            &facts,
            "make",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Callable,
        )
        .site;
        let declared_result = facts
            .declaration_type_slots
            .iter()
            .find(|row| row.declaration == make_declaration)
            .expect("make declared return slot")
            .slot;
        assert_eq!(
            slot(&facts, declared_result).role,
            ResolutionTypeSlotRole::DeclaredValue
        );
        let observed_return = facts
            .type_transfers
            .iter()
            .find(|transfer| {
                transfer.kind == ResolutionTypeTransferKind::Return
                    && slot(&facts, transfer.output).site == make_declaration
            })
            .expect("make observed return");
        assert_eq!(
            slot(&facts, observed_return.output).role,
            ResolutionTypeSlotRole::ReturnValue
        );
        assert_ne!(observed_return.output, declared_result);
        assert!(facts.type_transfers.iter().all(|transfer| {
            transfer.kind != ResolutionTypeTransferKind::Return
                || transfer.output != declared_result
        }));
        // The three ordinary classes each supply a default constructor, which
        // is a declared site now and no longer a marker gap.
        assert!(
            facts
                .gaps
                .iter()
                .all(|gap| gap.kind != ResolutionGapKind::ImplicitConstructor)
        );
        assert_eq!(
            facts
                .identifiers
                .iter()
                .filter(
                    |identifier| identifier.role == ResolutionIdentifierRole::Declaration
                        && identifier.namespace == ResolutionNamespace::Constructor
                )
                .count(),
            3
        );
    }

    #[test]
    fn primitive_cast_expression_has_its_static_type_in_call_argument_facts() {
        let facts = parse(
            "class C { long render(long value) { return value; } long call(int value) { return render((long) value); } }",
        );
        let cast_site = facts
            .sites
            .iter()
            .find(|site| site.kind == ResolutionSiteKind::UnaryExpression)
            .expect("primitive cast expression site");
        let cast_value = facts
            .type_slots
            .iter()
            .find(|slot| {
                slot.site == cast_site.id && slot.role == ResolutionTypeSlotRole::ExpressionValue
            })
            .expect("cast expression value slot");
        let cast_seed = facts
            .intrinsic_type_seeds
            .iter()
            .find(|seed| seed.output == cast_value.id)
            .expect("static primitive type seed for cast result");
        assert_eq!(cast_seed.kind, IntrinsicTypeKind::Primitive);
        assert_eq!(name(&facts, cast_seed.name), "long");
        assert!(!facts.gaps.iter().any(|gap| gap.site == cast_site.id));
        assert!(facts.type_transfers.iter().any(|transfer| {
            transfer.kind == ResolutionTypeTransferKind::Argument && transfer.input == cast_value.id
        }));
    }

    #[test]
    fn static_context_keeps_local_arguments_separate_from_implicit_receiver_gaps() {
        let facts = parse(
            "class C { static void take(long value) {} static void call(int value) { take(value); } }",
        );
        let argument_reference = identifier(
            &facts,
            "value",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Value,
        );
        let callee = identifier(
            &facts,
            "take",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Callable,
        );
        assert!(!facts.gaps.iter().any(|gap| {
            gap.site == argument_reference.site
                && gap.kind == ResolutionGapKind::UnsupportedImplicitReceiver
        }));
        assert!(facts.gaps.iter().any(|gap| {
            gap.site == callee.site && gap.kind == ResolutionGapKind::UnsupportedImplicitReceiver
        }));
        let call = facts
            .calls
            .iter()
            .find(|call| call.callee == callee.site)
            .expect("call uses the unqualified method reference");
        let call_argument = facts
            .call_arguments
            .iter()
            .find(|argument| argument.call == call.call)
            .expect("call has one argument");
        assert_eq!(
            facts
                .gaps
                .iter()
                .filter(|gap| gap.site == callee.site)
                .count(),
            2,
            "the callable site's implicit receiver and applicability remain distinct"
        );
        let local_value = facts
            .binding_projections
            .iter()
            .find(|projection| projection.reference == argument_reference.site)
            .expect("local parameter projection");
        assert!(facts.type_transfers.iter().any(|transfer| {
            transfer.kind == ResolutionTypeTransferKind::Argument
                && transfer.input == local_value.output
                && transfer.output == call_argument.value
        }));
    }

    #[test]
    fn subtype_observations_never_overwrite_declared_base_slots() {
        let source = "class Base {} class Sub extends Base {} class Flow { Base field = new Sub(); Base choose() { return new Sub(); } }";
        let facts = parse(source);
        let field = identifier(
            &facts,
            "field",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
        )
        .site;
        let choose = identifier(
            &facts,
            "choose",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Callable,
        )
        .site;

        for (declaration, observed_role, transfer_kind) in [
            (
                field,
                ResolutionTypeSlotRole::AssignmentValue,
                ResolutionTypeTransferKind::Assignment,
            ),
            (
                choose,
                ResolutionTypeSlotRole::ReturnValue,
                ResolutionTypeTransferKind::Return,
            ),
        ] {
            let declared = facts
                .declaration_type_slots
                .iter()
                .find(|row| row.declaration == declaration)
                .expect("declared Base slot")
                .slot;
            let declared_transfer = facts
                .type_transfers
                .iter()
                .find(|transfer| {
                    transfer.output == declared
                        && transfer.kind == ResolutionTypeTransferKind::DeclaredType
                })
                .expect("Base declared-type transfer");
            assert_eq!(
                declared_transfer.value_transform,
                ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                "Java type syntax becomes a non-addressable runtime declaration value"
            );
            let declared_input = declared_transfer.input;
            assert_eq!(
                name(
                    &facts,
                    identifier_for_site(&facts, slot(&facts, declared_input).site).name,
                ),
                "Base"
            );

            let observation = facts
                .type_transfers
                .iter()
                .find(|transfer| {
                    transfer.kind == transfer_kind
                        && slot(&facts, transfer.output).site == declaration
                })
                .expect("Sub value observation");
            assert_eq!(
                observation.value_transform,
                ResolutionTypeTransferValueTransform::Preserve,
                "observed Java runtime values retain their actual input category"
            );
            assert_eq!(slot(&facts, observation.output).role, observed_role);
            assert_ne!(observation.output, declared);
            let constructor_projection = facts
                .binding_projections
                .iter()
                .find(|projection| {
                    projection.output == observation.input
                        && projection.kind == BindingProjectionKind::TargetConstructorOwnerType
                })
                .expect("observed value comes from constructing Sub");
            let constructor_reference =
                identifier_for_site(&facts, constructor_projection.reference);
            let constructed_type = constructor_reference
                .qualifier
                .expect("Sub constructor type qualifier");
            assert_eq!(
                name(
                    &facts,
                    identifier_for_site(&facts, slot(&facts, constructed_type).site).name,
                ),
                "Sub"
            );
        }
    }

    #[test]
    fn explicit_constructor_binding_is_distinct_from_type_and_method_lookup() {
        let source = "class Outer { static class Product { Product(int value) {} static Product Product() { return new Outer.Product(1); } } }";
        let facts = parse(source);

        let product_type = identifier(
            &facts,
            "Product",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        )
        .site;
        let constructor = identifier(
            &facts,
            "Product",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Constructor,
        )
        .site;
        let same_named_method = identifier(
            &facts,
            "Product",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Callable,
        )
        .site;
        assert_ne!(constructor, product_type);
        assert_ne!(constructor, same_named_method);
        assert_eq!(
            site(&facts, constructor).kind,
            ResolutionSiteKind::ConstructorDeclaration
        );
        assert!(facts.member_owners.contains(&ResolutionMemberOwnerFact {
            member: constructor,
            owner: product_type,
            kind: ResolutionMemberKind::Constructor,
            access: ResolutionMemberAccess::Type,
            qualifier_compatibility: ResolutionMemberQualifierCompatibility::TypeOnly,
        }));

        let constructor_reference = identifier(
            &facts,
            "Product",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Constructor,
        );
        assert_eq!(
            site(&facts, constructor_reference.site).kind,
            ResolutionSiteKind::ConstructorReference
        );
        let owner_slot = constructor_reference
            .qualifier
            .expect("constructed type qualifier");
        let owner_reference = identifier_for_site(&facts, slot(&facts, owner_slot).site);
        assert_eq!(owner_reference.namespace, ResolutionNamespace::Type);
        assert_eq!(name(&facts, owner_reference.name), "Product");
        let outer_slot = owner_reference
            .qualifier
            .expect("qualified construction retains Outer");
        let outer_reference = identifier_for_site(&facts, slot(&facts, outer_slot).site);
        assert_eq!(outer_reference.namespace, ResolutionNamespace::Type);
        assert_eq!(name(&facts, outer_reference.name), "Outer");
        assert_eq!(outer_reference.qualifier, None);
        let call = facts
            .calls
            .iter()
            .find(|call| call.callee == constructor_reference.site)
            .expect("constructor call row");
        assert_eq!(call.receiver, None);
        assert!(facts.binding_projections.contains(&BindingProjectionFact {
            reference: constructor_reference.site,
            output: call.result,
            kind: BindingProjectionKind::TargetConstructorOwnerType,
        }));
        assert!(facts.gaps.iter().all(|gap| {
            gap.site != product_type || gap.kind != ResolutionGapKind::ImplicitConstructor
        }));
    }

    #[test]
    fn qualified_inner_construction_carries_the_enclosing_expression_type_frontier() {
        fn enclosing_type(source_type: &str) -> String {
            let source = format!(
                "class Outer {{ class Inner {{ Inner() {{}} }} }} class Other {{}} class Use {{ Outer.Inner make({source_type} outer) {{ return outer.new Inner(); }} }}"
            );
            let facts = parse(&source);
            let constructor_reference = identifier(
                &facts,
                "Inner",
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Constructor,
            );
            assert_eq!(
                site(&facts, constructor_reference.site).kind,
                ResolutionSiteKind::ConstructorReference
            );
            let call = facts
                .calls
                .iter()
                .find(|call| call.callee == constructor_reference.site)
                .expect("qualified inner construction call");
            let receiver = call.receiver.expect("explicit enclosing instance slot");
            let member_type = constructor_reference
                .qualifier
                .expect("constructed member type slot");
            let member_type_reference = identifier_for_site(&facts, slot(&facts, member_type).site);
            assert_eq!(
                site(&facts, member_type_reference.site).kind,
                ResolutionSiteKind::MemberReference
            );
            assert_eq!(member_type_reference.namespace, ResolutionNamespace::Type);
            let qualifier = member_type_reference
                .qualifier
                .expect("static receiver type qualifier");
            assert_ne!(
                qualifier, receiver,
                "enclosing runtime instance stays separate"
            );
            assert!(facts.type_transfers.iter().any(|transfer| {
                transfer.input == receiver
                    && transfer.output == qualifier
                    && transfer.kind == ResolutionTypeTransferKind::Receiver
                    && transfer.value_transform
                        == ResolutionTypeTransferValueTransform::StaticTypeObject
            }));
            let expression_value = facts
                .type_slots
                .iter()
                .find(|slot| {
                    slot.site == call.call && slot.role == ResolutionTypeSlotRole::ExpressionValue
                })
                .expect("independent static creation value");
            assert!(facts.type_transfers.iter().any(|transfer| {
                transfer.input == member_type
                    && transfer.output == expression_value.id
                    && transfer.kind == ResolutionTypeTransferKind::Construction
            }));
            assert!(facts.binding_projections.contains(&BindingProjectionFact {
                reference: constructor_reference.site,
                output: call.result,
                kind: BindingProjectionKind::TargetConstructorOwnerType,
            }));
            let receiver_input = facts
                .type_transfers
                .iter()
                .find(|transfer| {
                    transfer.output == receiver
                        && transfer.kind == ResolutionTypeTransferKind::Receiver
                })
                .expect("enclosing-instance receiver transfer")
                .input;
            let outer_reference = identifier_for_site(&facts, slot(&facts, receiver_input).site);
            assert_eq!(name(&facts, outer_reference.name), "outer");
            assert_eq!(outer_reference.namespace, ResolutionNamespace::Value);

            let parameter = identifier(
                &facts,
                "outer",
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Value,
            )
            .site;
            let declared_slot = facts
                .declaration_type_slots
                .iter()
                .find(|row| row.declaration == parameter)
                .expect("enclosing parameter declared type")
                .slot;
            let declared_input = facts
                .type_transfers
                .iter()
                .find(|transfer| {
                    transfer.output == declared_slot
                        && transfer.kind == ResolutionTypeTransferKind::DeclaredType
                })
                .expect("enclosing parameter type transfer")
                .input;
            name(
                &facts,
                identifier_for_site(&facts, slot(&facts, declared_input).site).name,
            )
            .to_string()
        }

        assert_eq!(enclosing_type("Outer"), "Outer");
        assert_eq!(enclosing_type("Other"), "Other");
    }

    #[test]
    fn implicit_and_explicit_java_roots_have_distinct_hierarchy_evidence() {
        let facts = parse("class Implicit {} class Explicit extends Object {}");
        let implicit = identifier(
            &facts,
            "Implicit",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        )
        .site;
        let explicit = identifier(
            &facts,
            "Explicit",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        )
        .site;
        assert_eq!(facts.supertypes.len(), 2);
        for subtype in [implicit, explicit] {
            assert!(!facts.gaps.contains(&ResolutionGapFact::new(
                subtype,
                ResolutionGapKind::UnsupportedHierarchyTraversal
            )));
            let edge = facts
                .supertypes
                .iter()
                .find(|edge| edge.subtype == subtype)
                .unwrap();
            assert_eq!(
                edge.kind,
                if subtype == implicit {
                    ResolutionSupertypeKind::ImplicitSuperclass
                } else {
                    ResolutionSupertypeKind::Superclass
                }
            );
            assert_eq!(
                slot(&facts, edge.supertype_slot).site,
                edge.supertype_reference
            );
            assert!(facts.gaps.contains(&ResolutionGapFact::new(
                edge.supertype_reference,
                ResolutionGapKind::UnsupportedHierarchyTraversal
            )));
            let route = facts
                .root_references
                .iter()
                .find(|route| route.reference == edge.supertype_reference);
            if subtype == implicit {
                assert_eq!(
                    facts.sites[edge.supertype_reference.index()].kind,
                    ResolutionSiteKind::SyntheticReference
                );
                let route = route.unwrap();
                assert_eq!(route.anchor, ResolutionRootImportAnchor::Absolute);
                assert_eq!(route.prefix_reference, None);
                let segments = facts
                    .root_reference_segments
                    .iter()
                    .filter(|segment| segment.reference == edge.supertype_reference)
                    .map(|segment| name(&facts, segment.name))
                    .collect::<Vec<_>>();
                assert_eq!(segments, ["java", "lang"]);
                assert!(
                    !facts
                        .package_references
                        .iter()
                        .any(|row| row.reference == edge.supertype_reference)
                );
            } else {
                assert_eq!(
                    facts.sites[edge.supertype_reference.index()].kind,
                    ResolutionSiteKind::TypeReference
                );
                assert!(route.is_none());
            }
        }
    }

    #[test]
    fn only_top_level_java_lang_object_has_no_implicit_superclass() {
        for (source, expected) in [
            ("package java.lang; public class Object {}", 0),
            ("package example; class Object {}", 1),
            ("package java.lang; class Outer { class Object {} }", 2),
            (
                "interface I {} enum E { A } record R() {} @interface A {}",
                0,
            ),
        ] {
            let facts = parse(source);
            assert_eq!(facts.supertypes.len(), expected, "{source}");
        }
    }

    #[test]
    fn unsupported_supertype_does_not_publish_a_non_reference_hierarchy_edge() {
        let facts = parse("class A extends var {}");
        let declaration = identifier(
            &facts,
            "A",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        )
        .site;
        assert!(facts.supertypes.is_empty());
        assert!(facts.gaps.contains(&ResolutionGapFact::new(
            declaration,
            ResolutionGapKind::UnsupportedHierarchyTraversal
        )));
    }

    #[test]
    fn generic_supertype_keeps_base_reference_owner_while_lowering_deep_arguments() {
        let mut source = String::from("class Box<T> {} class Deep extends ");
        for _ in 0..256 {
            source.push_str("Box<");
        }
        source.push_str("String");
        for _ in 0..256 {
            source.push('>');
        }
        source.push_str(" {}");
        let facts = parse(&source);
        let deep = identifier(
            &facts,
            "Deep",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        )
        .site;
        let supertype = facts
            .supertypes
            .iter()
            .find(|fact| fact.subtype == deep)
            .expect("generic superclass must retain one hierarchy row");
        let base = identifier_for_site(&facts, supertype.supertype_reference);
        assert_eq!(name(&facts, base.name), "Box");
        assert_eq!(
            facts
                .reference_owners
                .iter()
                .find(|owner| owner.reference == base.site)
                .expect("generic base reference must have an owner")
                .owner,
            Some(deep)
        );
        assert_eq!(facts.declared_type_arguments.len(), 256);
        assert!(facts.gaps.iter().all(|gap| {
            gap.kind != ResolutionGapKind::UnsupportedTypeSyntax
                || site(&facts, gap.site).kind != ResolutionSiteKind::UnsupportedExpression
        }));
    }

    #[test]
    fn only_directly_instantiable_classes_publish_a_default_constructor_site() {
        let overloaded = parse("record R(int x) { R() { this(0); } }");
        let r = identifier(
            &overloaded,
            "R",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        )
        .site;
        assert!(!overloaded.gaps.contains(&ResolutionGapFact::new(
            r,
            ResolutionGapKind::ImplicitConstructor
        )));

        let compact = parse("record C(int x) { C { } }");
        let c = identifier(
            &compact,
            "C",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        )
        .site;
        assert!(!compact.gaps.contains(&ResolutionGapFact::new(
            c,
            ResolutionGapKind::ImplicitConstructor
        )));
        let compact_constructor = identifier(
            &compact,
            "C",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Constructor,
        )
        .site;
        assert!(compact.gaps.contains(&ResolutionGapFact::new(
            compact_constructor,
            ResolutionGapKind::UnsupportedCallApplicability
        )));
        assert!(
            compact
                .callable_parameters
                .iter()
                .all(|parameter| parameter.callable != compact_constructor),
            "implicit record-component parameters are not fabricated"
        );

        let constructors = |facts: &FileResolutionFacts| {
            facts
                .identifiers
                .iter()
                .filter(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Declaration
                        && identifier.namespace == ResolutionNamespace::Constructor
                })
                .map(|identifier| identifier.site)
                .collect::<Vec<_>>()
        };
        let abstract_class = parse("public abstract class AbstractWorker {}");
        assert!(constructors(&abstract_class).is_empty());

        let written = parse("public class Written { public Written(int x) {} }");
        let written_constructor = identifier(
            &written,
            "Written",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Constructor,
        )
        .site;
        assert_eq!(constructors(&written), vec![written_constructor]);
        assert_eq!(written.callable_signatures.len(), 1);

        // A class that writes no constructor supplies one: no parameters, the
        // class's own access, declared by the class in its body scope.
        let ordinary = parse("public class Worker {}");
        let worker = identifier(
            &ordinary,
            "Worker",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        )
        .site;
        let constructor = identifier(
            &ordinary,
            "Worker",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Constructor,
        )
        .site;
        assert_eq!(constructors(&ordinary), vec![constructor]);
        assert_eq!(
            site(&ordinary, constructor).kind,
            ResolutionSiteKind::ConstructorDeclaration
        );
        let scope = ordinary.scope(site(&ordinary, constructor).scope);
        assert_eq!(scope.kind, ResolutionScopeKind::TypeBody);
        assert_eq!(scope.owner, Some(worker));
        assert!(ordinary.member_owners.contains(&ResolutionMemberOwnerFact {
            member: constructor,
            owner: worker,
            kind: ResolutionMemberKind::Constructor,
            access: ResolutionMemberAccess::Type,
            qualifier_compatibility: ResolutionMemberQualifierCompatibility::TypeOnly,
        }));
        assert!(
            ordinary
                .callable_signatures
                .iter()
                .any(|signature| signature.callable == constructor
                    && signature.type_parameter_count == 0)
        );
        assert!(
            ordinary
                .callable_parameters
                .iter()
                .all(|parameter| parameter.callable != constructor)
        );
        assert!(
            ordinary
                .gaps
                .iter()
                .all(|gap| gap.kind != ResolutionGapKind::ImplicitConstructor)
        );
    }

    #[test]
    fn inheritance_rows_preserve_interface_edges_and_open_member_frontiers() {
        let source = "interface Base {} interface Other {} interface Child extends Base, Other {} class Impl implements Child, Other {}";
        let facts = parse(source);
        let child = identifier(
            &facts,
            "Child",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        )
        .site;
        let base = identifier(
            &facts,
            "Base",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        )
        .site;
        let other = identifier(
            &facts,
            "Other",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        )
        .site;
        let implementation = identifier(
            &facts,
            "Impl",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        )
        .site;

        assert_eq!(facts.supertypes.len(), 5);
        let edge_names = facts
            .supertypes
            .iter()
            .filter(|row| row.kind == ResolutionSupertypeKind::Interface)
            .map(|row| {
                assert_eq!(row.kind, ResolutionSupertypeKind::Interface);
                assert_eq!(
                    slot(&facts, row.supertype_slot).site,
                    row.supertype_reference
                );
                (
                    row.subtype,
                    name(
                        &facts,
                        identifier_for_site(&facts, row.supertype_reference).name,
                    ),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            edge_names,
            vec![
                (child, "Base"),
                (child, "Other"),
                (implementation, "Child"),
                (implementation, "Other"),
            ]
        );
        for row in &facts.supertypes {
            assert!(facts.gaps.contains(&ResolutionGapFact::new(
                row.supertype_reference,
                ResolutionGapKind::UnsupportedHierarchyTraversal
            )));
        }
        assert_eq!(
            facts
                .gaps
                .iter()
                .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedHierarchyTraversal)
                .count(),
            7
        );
        for implicit_root in [base, other] {
            assert!(facts.gaps.contains(&ResolutionGapFact::new(
                implicit_root,
                ResolutionGapKind::UnsupportedHierarchyTraversal
            )));
        }
        assert!(!facts.gaps.contains(&ResolutionGapFact::new(
            child,
            ResolutionGapKind::UnsupportedHierarchyTraversal
        )));
    }

    #[test]
    fn nested_type_lookup_is_type_qualified_but_inner_construction_needs_an_instance() {
        let source = "class Outer { class Inner {} static class StaticNested {} interface NestedInterface {} enum NestedEnum { ONE } record NestedRecord() {} }";
        let facts = parse(source);
        let outer = identifier(
            &facts,
            "Outer",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        )
        .site;
        let inner = identifier(
            &facts,
            "Inner",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        )
        .site;
        let static_nested = identifier(
            &facts,
            "StaticNested",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        )
        .site;
        let nested_interface = identifier(
            &facts,
            "NestedInterface",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        )
        .site;
        let nested_enum = identifier(
            &facts,
            "NestedEnum",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        )
        .site;
        let nested_record = identifier(
            &facts,
            "NestedRecord",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        )
        .site;

        for nested in [
            inner,
            static_nested,
            nested_interface,
            nested_enum,
            nested_record,
        ] {
            assert!(facts.member_owners.contains(&ResolutionMemberOwnerFact {
                member: nested,
                owner: outer,
                kind: ResolutionMemberKind::NestedType,
                access: ResolutionMemberAccess::Type,
                qualifier_compatibility: ResolutionMemberQualifierCompatibility::TypeOnly,
            }));
        }
        assert_eq!(
            facts.construction_requirements,
            vec![ResolutionConstructionRequirementFact {
                constructed_type: inner,
                required_owner: outer,
                kind: ResolutionConstructionRequirementKind::EnclosingInstance,
            }]
        );
        assert!(facts.construction_requirements.iter().all(|requirement| {
            requirement.constructed_type != static_nested
                && requirement.constructed_type != nested_interface
                && requirement.constructed_type != nested_enum
                && requirement.constructed_type != nested_record
        }));
    }

    #[test]
    fn static_wildcard_demands_keep_ambiguous_names_and_distinct_import_sites() {
        let source = r#"
            import static p.Owner.*;
            import static p.Owner.*;
            class Use {
                Nested field;
                int run() { call(); call(); VALUE = 1; return READ + READ; }
            }
        "#;
        let facts = parse(source);
        assert_eq!(facts.root_imports.len(), 2);
        assert_ne!(facts.root_imports[0].site, facts.root_imports[1].site);
        let expected = HashSet::from_iter([
            (ResolutionNamespace::Type, "Nested"),
            (ResolutionNamespace::Callable, "call"),
            (ResolutionNamespace::Value, "VALUE"),
            (ResolutionNamespace::Value, "READ"),
        ]);
        for import in &facts.root_imports {
            let demands = facts
                .root_import_demands
                .iter()
                .filter(|demand| demand.import_site == import.site)
                .map(|demand| (demand.namespace, name(&facts, demand.name)))
                .collect::<Vec<_>>();
            assert_eq!(
                demands.len(),
                expected.len(),
                "duplicate references coalesce"
            );
            assert_eq!(HashSet::from_iter(demands), expected);
            assert_eq!(
                facts
                    .root_import_segments
                    .iter()
                    .filter(|segment| segment.import_site == import.site)
                    .map(|segment| name(&facts, segment.name))
                    .collect::<Vec<_>>(),
                vec!["p", "Owner"]
            );
            assert!(
                facts.gaps.iter().any(|gap| gap.site == import.site
                    && gap.kind == ResolutionGapKind::UnsupportedRoute)
            );
        }
    }

    #[test]
    fn static_import_demands_exclude_qualified_members_and_unobserved_namespaces() {
        let source = r#"
            import static p.Owner.Nested;
            import static p.Owner.VALUE;
            import static p.Owner.call;
            import static p.Owner.Unused;
            class Use {
                Nested make() { return new Nested(); }
                void run(Owner receiver) { receiver.call(); receiver.VALUE = 1; }
                void call() {}
                int VALUE;
                class Unused {}
            }
        "#;
        let facts = parse(source);
        assert_eq!(facts.root_imports.len(), 4);
        assert_eq!(
            facts
                .root_import_demands
                .iter()
                .map(|demand| (demand.namespace, name(&facts, demand.name)))
                .collect::<Vec<_>>(),
            vec![(ResolutionNamespace::Type, "Nested")],
            "construction requests a type, declarations and qualified members do not request imports"
        );
    }

    #[test]
    fn nested_and_late_directives_never_mutate_supported_prefix_rows() {
        let source = "import legal.Target; class A { void f() { import nested.Target; package nested; } } import late.Target; package late;";
        let facts = parse(source);

        assert_eq!(facts.packages.len(), 1);
        assert_eq!(facts.packages[0].declaration, None);
        assert!(facts.package_segments.is_empty());
        assert_eq!(facts.import_routes.len(), 1);
        let route = facts.import_routes[0];
        assert_eq!(
            facts
                .import_route_segments
                .iter()
                .map(|segment| (
                    segment.import_site,
                    segment.ordinal,
                    name(&facts, segment.name)
                ))
                .collect::<Vec<_>>(),
            vec![(route.site, 0, "legal"), (route.site, 1, "Target")]
        );

        let imports = facts
            .sites
            .iter()
            .filter(|site| site.kind == ResolutionSiteKind::ImportDeclaration)
            .collect::<Vec<_>>();
        assert_eq!(imports.len(), 3);
        assert_eq!(
            imports
                .iter()
                .map(|site| &source[site.start_byte..site.end_byte])
                .collect::<Vec<_>>(),
            vec![
                "import legal.Target;",
                "import nested.Target;",
                "import late.Target;"
            ]
        );
        assert_eq!(imports[0].id, route.site);
        assert!(imports[1..].iter().all(|site| {
            facts
                .gaps
                .iter()
                .any(|gap| gap.site == site.id && gap.kind == ResolutionGapKind::UnsupportedRoute)
        }));

        let packages = facts
            .sites
            .iter()
            .filter(|site| site.kind == ResolutionSiteKind::PackageDeclaration)
            .collect::<Vec<_>>();
        assert_eq!(packages.len(), 2);
        assert_eq!(
            packages
                .iter()
                .map(|site| &source[site.start_byte..site.end_byte])
                .collect::<Vec<_>>(),
            vec!["package nested;", "package late;"]
        );
        assert!(packages.iter().all(|site| {
            facts
                .gaps
                .iter()
                .any(|gap| gap.site == site.id && gap.kind == ResolutionGapKind::UnsupportedRoute)
        }));
    }

    #[test]
    fn anonymous_program_semicolons_close_the_directive_prefix() {
        let leading_source = "; package p; class A {}";
        let leading = parse(leading_source);
        assert_eq!(leading.packages.len(), 1);
        assert_eq!(leading.packages[0].declaration, None);
        assert!(leading.package_segments.is_empty());
        let late_package = leading
            .sites
            .iter()
            .find(|site| site.kind == ResolutionSiteKind::PackageDeclaration)
            .expect("late package site");
        assert_eq!(
            &leading_source[late_package.start_byte..late_package.end_byte],
            "package p;"
        );
        assert!(
            leading.gaps.iter().any(|gap| gap.site == late_package.id
                && gap.kind == ResolutionGapKind::UnsupportedRoute)
        );

        let between_source = "package p; ; import q.T; class A {}";
        let between = parse(between_source);
        assert_eq!(between.packages.len(), 1);
        assert!(between.packages[0].declaration.is_some());
        assert_eq!(
            between
                .package_segments
                .iter()
                .map(|segment| (segment.ordinal, name(&between, segment.name)))
                .collect::<Vec<_>>(),
            vec![(0, "p")]
        );
        assert!(between.import_routes.is_empty());
        assert!(between.import_route_segments.is_empty());
        let late_import = between
            .sites
            .iter()
            .find(|site| site.kind == ResolutionSiteKind::ImportDeclaration)
            .expect("late import site");
        assert_eq!(
            &between_source[late_import.start_byte..late_import.end_byte],
            "import q.T;"
        );
        assert!(between.gaps.iter().any(
            |gap| gap.site == late_import.id && gap.kind == ResolutionGapKind::UnsupportedRoute
        ));
    }

    #[test]
    fn malformed_import_does_not_hide_a_structurally_complete_route() {
        let source = "import com.acme.; import Target; class A {}";
        let facts = parse(source);

        assert_eq!(facts.import_routes.len(), 1);
        let route = facts.import_routes[0];
        assert_eq!(
            name(&facts, route.bound_name.expect("single-type bound name")),
            "Target"
        );
        assert_eq!(
            facts
                .import_route_segments
                .iter()
                .map(|segment| (
                    segment.import_site,
                    segment.ordinal,
                    name(&facts, segment.name)
                ))
                .collect::<Vec<_>>(),
            vec![(route.site, 0, "Target")]
        );
        let imports = facts
            .sites
            .iter()
            .filter(|site| site.kind == ResolutionSiteKind::ImportDeclaration)
            .collect::<Vec<_>>();
        assert_eq!(imports.len(), 2);
        assert_eq!(
            &source[imports[0].start_byte..imports[0].end_byte],
            "import com.acme.;"
        );
        assert_ne!(imports[0].id, route.site);
        assert!(facts.gaps.iter().any(
            |gap| gap.site == imports[0].id && gap.kind == ResolutionGapKind::UnsupportedRoute
        ));
        assert_eq!(
            &source[imports[1].start_byte..imports[1].end_byte],
            "import Target;"
        );
        assert_eq!(imports[1].id, route.site);
    }

    #[test]
    fn malformed_and_late_imports_keep_generic_rows_when_native_routes_gap() {
        let source = "class A {} import com.acme.;";
        let parsed = parse_file(source);
        assert_eq!(parsed.imports.len(), 1);
        let import = &parsed.imports[0];
        assert_eq!(import.raw_snippet, "import com.acme.;");
        assert!(import.path.is_none());
        assert!(import.binder_span.is_none());

        let source_facts = parsed
            .source_facts
            .as_ref()
            .expect("coordinated Java producer publishes source facts");
        assert_eq!(source_facts.imports.len(), 1);
        assert_eq!(source_facts.generic_imports.len(), 1);
        assert!(source_facts.imports[0].path.is_none());
        assert!(!source_facts.native_site_occurrences.is_empty());
        assert!(!source_facts.native_declaration_sources.is_empty());
        assert!(!parsed.source_declaration_units.is_empty());
        let import_site = parsed
            .resolution_facts
            .sites
            .iter()
            .find(|site| site.kind == ResolutionSiteKind::ImportDeclaration)
            .expect("late malformed import remains a native site");
        assert!(parsed.resolution_facts.gaps.iter().any(
            |gap| gap.site == import_site.id && gap.kind == ResolutionGapKind::UnsupportedRoute
        ));
    }

    #[test]
    fn malformed_package_does_not_fabricate_a_package_identity() {
        let source = "package broken.; class A {}";
        let facts = parse(source);

        assert!(facts.packages.is_empty());
        assert!(facts.package_segments.is_empty());
        let declarations = facts
            .sites
            .iter()
            .filter(|site| site.kind == ResolutionSiteKind::PackageDeclaration)
            .collect::<Vec<_>>();
        assert_eq!(declarations.len(), 1);
        assert_eq!(
            &source[declarations[0].start_byte..declarations[0].end_byte],
            "package broken.;"
        );
        assert!(
            facts.gaps.iter().any(|gap| gap.site == declarations[0].id
                && gap.kind == ResolutionGapKind::UnsupportedRoute)
        );
        assert_eq!(
            facts
                .gaps
                .iter()
                .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedPlacementBoundary)
                .count(),
            1
        );
    }

    #[test]
    fn varargs_multi_declarators_and_nested_static_types_are_exact() {
        let source = "class C { C(String... values) {} void f(String first, String... rest) { int a, b = a; } interface I {} enum E {} record R() {} @interface N {} }";
        let facts = parse(source);

        let constructor = identifier(
            &facts,
            "C",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Constructor,
        )
        .site;
        let method = identifier(
            &facts,
            "f",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Callable,
        )
        .site;
        assert_eq!(
            site(&facts, constructor).kind,
            ResolutionSiteKind::ConstructorDeclaration
        );
        assert_eq!(
            facts
                .binders
                .iter()
                .find(|binder| binder.declaration == constructor)
                .expect("constructor binder")
                .kind,
            ResolutionBinderKind::Constructor
        );
        assert_eq!(
            facts
                .callable_parameters
                .iter()
                .map(|parameter| parameter.repeated)
                .collect::<Vec<_>>(),
            vec![true, false, true]
        );
        assert_eq!(
            facts
                .callable_parameters
                .iter()
                .map(|parameter| (parameter.ordinal, parameter.repeated))
                .collect::<Vec<_>>(),
            vec![(0, true), (0, false), (1, true)]
        );
        for spelling in ["values", "first", "rest"] {
            let declaration = identifier(
                &facts,
                spelling,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Value,
            )
            .site;
            assert_eq!(
                facts
                    .binders
                    .iter()
                    .find(|binder| binder.declaration == declaration)
                    .expect("parameter binder")
                    .kind,
                ResolutionBinderKind::Parameter
            );
        }

        let a_declaration = identifier(
            &facts,
            "a",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
        )
        .site;
        let b_declaration = identifier(
            &facts,
            "b",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
        )
        .site;
        let a_reference = identifier(
            &facts,
            "a",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Value,
        )
        .site;
        let a_activation = facts
            .binders
            .iter()
            .find(|binder| binder.declaration == a_declaration)
            .expect("a binder")
            .activation_start;
        let b_activation = facts
            .binders
            .iter()
            .find(|binder| binder.declaration == b_declaration)
            .expect("b binder")
            .activation_start;
        assert!(a_activation <= site(&facts, a_reference).start_byte);
        assert_eq!(
            b_activation,
            site(&facts, a_reference).start_byte,
            "the later declarator starts at its own initializer while the earlier local is already active"
        );

        let owner = identifier(
            &facts,
            "C",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        )
        .site;
        for spelling in ["I", "E", "R", "N"] {
            let nested = identifier(
                &facts,
                spelling,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Type,
            )
            .site;
            assert!(facts.member_owners.contains(&ResolutionMemberOwnerFact {
                member: nested,
                owner,
                kind: ResolutionMemberKind::NestedType,
                access: ResolutionMemberAccess::Type,
                qualifier_compatibility: ResolutionMemberQualifierCompatibility::TypeOnly,
            }));
        }
        let nested_type = |spelling| {
            identifier(
                &facts,
                spelling,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Type,
            )
            .site
        };
        let interface = nested_type("I");
        let enumeration = nested_type("E");
        let record = nested_type("R");
        let annotation = nested_type("N");
        assert_eq!(
            non_visibility_gaps(&facts),
            vec![
                ResolutionGapFact::new(interface, ResolutionGapKind::UnsupportedHierarchyTraversal),
                ResolutionGapFact::new(
                    enumeration,
                    ResolutionGapKind::UnsupportedHierarchyTraversal
                ),
                ResolutionGapFact::new(record, ResolutionGapKind::UnsupportedHierarchyTraversal),
                ResolutionGapFact::new(
                    annotation,
                    ResolutionGapKind::UnsupportedHierarchyTraversal
                ),
                ResolutionGapFact::new(
                    implicit_superclass_reference(&facts, owner),
                    ResolutionGapKind::UnsupportedHierarchyTraversal
                ),
                ResolutionGapFact::new(
                    facts.gaps.last().expect("placement gap").site,
                    ResolutionGapKind::UnsupportedPlacementBoundary
                ),
            ]
        );
        assert_eq!(
            visibility_gap_sites(&facts),
            vec![
                owner,
                constructor,
                method,
                interface,
                enumeration,
                record,
                annotation,
            ]
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#2771: record-pattern suppression hid nested component bindings and references"
    )]
    fn record_pattern_grammar_children_bind_only_their_match_arm() {
        use brokk_bifrost_core::analyzer::exception_handling::collect_nodes_by_kind;
        let source = "class A { int f(Object o) { return switch(o) { case Box(int /*binding*/ value, Box(int nested)) when /*guard*/ ok(value) -> value + nested; default -> 0; }; } }";
        let tree = super::super::declarations::parse_tree(source).unwrap();
        assert!(!tree.root_node().has_error());
        let records = collect_nodes_by_kind(tree.root_node(), "record_pattern");
        assert_eq!(records.len(), 2);
        for record in records {
            assert!(record.child_by_field_name("type").is_none());
            assert_eq!(record.named_child(0).unwrap().kind(), "identifier");
            assert_eq!(record.named_child(1).unwrap().kind(), "record_pattern_body");
        }
        let components = collect_nodes_by_kind(tree.root_node(), "record_pattern_component");
        assert_eq!(components.len(), 2);
        for component in components {
            assert!(component.child_by_field_name("name").is_none());
            let children = named_children(component)
                .into_iter()
                .filter(|child| !child.is_extra())
                .collect::<Vec<_>>();
            assert_eq!(children[0].kind(), "integral_type");
            assert_eq!(children[1].kind(), "identifier");
        }
        let head = collect_nodes_by_kind(tree.root_node(), "pattern")[0];
        let arm = nearest_ancestor(head, |kind| kind == "switch_rule").unwrap();
        let facts = parse(source);
        for spelling in ["value", "nested"] {
            let declaration = identifier(
                &facts,
                spelling,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Value,
            )
            .site;
            let binder = facts
                .binders
                .iter()
                .find(|binder| binder.declaration == declaration)
                .unwrap();
            assert_eq!(binder.kind, ResolutionBinderKind::Pattern);
            assert_eq!(binder.activation_start, head.end_byte());
            assert_eq!(binder.activation_end, arm.end_byte());
        }
        let guard_call = identifier(
            &facts,
            "ok",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Callable,
        )
        .site;
        assert!(facts.calls.iter().any(|call| call.callee == guard_call));
        assert!(
            facts
                .gaps
                .iter()
                .all(|gap| gap.kind != ResolutionGapKind::UnsupportedScopeOrBinder),
            "{:?}",
            facts.gaps
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#2771: a for-loop subtree hid every reference and its local binder"
    )]
    fn for_initializer_binder_is_bounded_by_the_loop_scope() {
        let source = "class A { void helper(int x) {} void f() { for (int i = 0; i < 2; i++) helper(i); helper(0); } }";
        let facts = parse(source);
        let declaration = identifier(
            &facts,
            "i",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
        )
        .site;
        let binder = facts
            .binders
            .iter()
            .find(|binder| binder.declaration == declaration)
            .unwrap();
        let scope = facts
            .scopes
            .iter()
            .find(|scope| scope.id == binder.scope)
            .unwrap();
        assert_eq!(
            &source[scope.start_byte..scope.end_byte],
            "for (int i = 0; i < 2; i++) helper(i);"
        );
        assert_eq!(binder.activation_end, scope.end_byte);
        assert_eq!(binder.hoisting, HoistingClass::SourceOrder);
        assert_eq!(
            facts
                .identifiers
                .iter()
                .filter(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Reference
                        && facts.names[identifier.name.index()].spelling == "i"
                })
                .count(),
            3
        );
        assert!(
            facts
                .gaps
                .iter()
                .all(|gap| gap.kind != ResolutionGapKind::UnsupportedScopeOrBinder),
            "{:?}",
            facts.gaps
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#2771: loop and resource suppression hid local bindings and body references"
    )]
    fn unsupported_binders_cannot_leak_affirmative_rows() {
        let source = "class A<T> { enum E { ONE } record R(int component) {} Object f() { try (A resourceValue = open(); var laterResource = resourceValue; resourceValue) { resourceValue.helper(); } catch (Exception caught) { caught.toString(); } for (String item : items) { item.toString(); } class Local {} Object a = () -> { return hidden; }; Object b = new Object() { Object m() { return hidden2; } }; return a; } }";
        let facts = parse(source);
        let spellings = identifier_spellings(&facts);

        let unsupported = "component";
        assert!(
            !spellings.contains(&unsupported),
            "unsupported subtree leaked {unsupported:?}: {spellings:?}"
        );
        for supported in [
            "ONE",
            "Local",
            "m",
            "hidden2",
            "T",
            "caught",
            "hidden",
            "item",
            "items",
            "resourceValue",
            "laterResource",
            "open",
            "helper",
        ] {
            assert!(
                spellings.contains(&supported),
                "supported enum, local or anonymous scope omitted {supported:?}: {spellings:?}"
            );
        }
        for spelling in ["resourceValue", "laterResource"] {
            let resource = identifier(
                &facts,
                spelling,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Value,
            )
            .site;
            let binder = facts
                .binders
                .iter()
                .find(|binder| binder.declaration == resource)
                .unwrap();
            assert_eq!(binder.hoisting, HoistingClass::DeclaredHead);
            assert!(
                source[binder.activation_start..binder.activation_end]
                    .ends_with("{ resourceValue.helper(); }")
            );
            assert!(!source[binder.activation_start..binder.activation_end].contains("catch"));
        }
        let item = identifier(
            &facts,
            "item",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
        )
        .site;
        let item_binder = facts
            .binders
            .iter()
            .find(|binder| binder.declaration == item)
            .unwrap();
        assert_eq!(item_binder.hoisting, HoistingClass::DeclaredHead);
        assert_eq!(
            &source[item_binder.activation_start..item_binder.activation_end],
            "{ item.toString(); }"
        );
        let item_scope = facts.scopes[item_binder.scope.index()];
        assert_eq!(
            &source[item_scope.start_byte..item_scope.end_byte],
            "for (String item : items) { item.toString(); }"
        );
        let caught = identifier(
            &facts,
            "caught",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
        )
        .site;
        let caught_binder = facts
            .binders
            .iter()
            .find(|binder| binder.declaration == caught)
            .expect("catch parameter has a lexical binder");
        assert_eq!(caught_binder.kind, ResolutionBinderKind::Local);
        let lambda_range = source
            .find("() -> { return hidden; }")
            .expect("lambda source range");
        let lambda_site = facts
            .sites
            .iter()
            .find(|site| {
                site.kind == ResolutionSiteKind::UnsupportedExpression
                    && site.start_byte == lambda_range
                    && site.end_byte == lambda_range + "() -> { return hidden; }".len()
            })
            .expect("lambda expression has a value site");
        let lambda_scope = facts
            .scopes
            .iter()
            .find(|scope| {
                scope.owner == Some(lambda_site.id) && scope.kind == ResolutionScopeKind::Executable
            })
            .expect("lambda owns an executable lexical scope");
        let hidden = identifier(
            &facts,
            "hidden",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Value,
        );
        let mut hidden_scope = site(&facts, hidden.site).scope;
        let mut nested_in_lambda = false;
        loop {
            if hidden_scope == lambda_scope.id {
                nested_in_lambda = true;
                break;
            }
            let Some(parent) = facts.scopes[hidden_scope.index()].parent else {
                break;
            };
            hidden_scope = parent;
        }
        assert!(nested_in_lambda, "lambda body reference escaped its scope");
        assert_eq!(
            facts
                .type_transfers
                .iter()
                .filter(|transfer| transfer.kind == ResolutionTypeTransferKind::Return)
                .count(),
            2,
            "the outer and anonymous methods retain their return edges"
        );
        assert_eq!(
            facts
                .gaps
                .iter()
                .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder)
                .count(),
            1,
            "all resolution gaps: {:?}",
            facts.gaps
        );
        assert!(
            facts
                .gaps
                .iter()
                .all(|gap| gap.kind != ResolutionGapKind::ImplicitConstructor),
            "all resolution gaps: {:?}",
            facts.gaps
        );
        assert_eq!(
            facts
                .gaps
                .iter()
                .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedHierarchyTraversal)
                .count(),
            6,
            "all resolution gaps: {:?}",
            facts.gaps
        );
        assert_eq!(
            facts
                .gaps
                .iter()
                .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedVisibility)
                .count(),
            6,
            "all resolution gaps: {:?}",
            facts.gaps
        );
        assert_eq!(
            facts
                .gaps
                .iter()
                .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedPlacementBoundary)
                .count(),
            1
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#2771: modules hid service types and the grammar left the first provider unfielded"
    )]
    fn structured_annotation_references_are_not_enumeration_gaps() {
        let source = "@Marker @Configured(value = \"x\") sealed class A permits Allowed { void f() throws Failure {} }";
        let parsed = parse_file(source);
        for spelling in ["Allowed", "Failure"] {
            assert!(
                parsed.type_identifiers.contains(spelling),
                "legacy type-identifier evidence omitted {spelling:?}: {:?}",
                parsed.type_identifiers
            );
        }

        let facts = parsed.resolution_facts;
        let spellings = identifier_spellings(&facts);
        for spelling in ["A", "f", "Object", "Marker", "Configured"] {
            assert!(
                spellings.contains(&spelling),
                "structured annotation or declaration reference omitted {spelling:?}: {spellings:?}"
            );
        }
        // A `permits` or `throws` clause binds nothing, so it no longer carries
        // a scope-wide unsupported-binder gap; the two names it spells are
        // unmodeled type syntax, each with a gap local to its own reference.
        assert!(
            facts
                .gaps
                .iter()
                .all(|gap| gap.kind != ResolutionGapKind::UnsupportedScopeOrBinder),
            "all resolution gaps: {:?}",
            facts.gaps
        );
        let unmodeled = facts
            .gaps
            .iter()
            .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedTypeSyntax)
            .map(|gap| {
                let site = site(&facts, gap.site);
                assert_eq!(site.kind, ResolutionSiteKind::TypeReference);
                &source[site.start_byte..site.end_byte]
            })
            .collect::<Vec<_>>();
        assert_eq!(unmodeled, ["Allowed", "Failure"]);
        assert_eq!(
            non_visibility_gaps(&facts)
                .iter()
                .map(|gap| gap.kind)
                .collect::<Vec<_>>(),
            vec![
                ResolutionGapKind::UnsupportedTypeSyntax,
                ResolutionGapKind::UnsupportedTypeSyntax,
                ResolutionGapKind::UnsupportedHierarchyTraversal,
                ResolutionGapKind::UnsupportedPlacementBoundary,
            ]
        );
        // The package-private class, its default constructor and `f`.
        assert_eq!(visibility_gap_sites(&facts).len(), 3);
        for spelling in ["Marker", "Configured"] {
            let identifier = facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Reference
                        && identifier.namespace == ResolutionNamespace::Type
                        && name(&facts, identifier.name) == spelling
                })
                .unwrap();
            let reference = site(&facts, identifier.site);
            assert_eq!(&source[reference.start_byte..reference.end_byte], spelling);
            assert!(
                facts.reference_enumeration_gaps.iter().all(|gap| {
                    let omitted = site(&facts, gap.site);
                    omitted.end_byte <= reference.start_byte
                        || reference.end_byte <= omitted.start_byte
                }),
                "structured annotation reference must not retain an omission gap: {:?}",
                facts.reference_enumeration_gaps
            );
        }

        let module = parse_file(
            "module sample.app { requires other.mod; exports sample.pkg to friend.mod; opens sample.internal; uses Service; provides Service with Implementation, other.Implementation; }",
        );
        for spelling in ["Service", "Implementation"] {
            assert!(
                module.type_identifiers.contains(spelling),
                "legacy module type-identifier evidence omitted {spelling:?}: {:?}",
                module.type_identifiers
            );
        }
        assert!(module.resolution_facts.binders.is_empty());
        assert_eq!(
            identifier_spellings(&module.resolution_facts),
            vec![
                "Service",
                "Service",
                "Implementation",
                "other",
                "Implementation"
            ]
        );
        assert!(
            module
                .resolution_facts
                .gaps
                .iter()
                .all(|gap| gap.kind != ResolutionGapKind::UnsupportedScopeOrBinder),
            "{:?}",
            module.resolution_facts.gaps
        );
        assert!(
            module
                .resolution_facts
                .reference_enumeration_gaps
                .is_empty()
        );
        let malformed = parse("module sample.app { uses ; }");
        assert!(
            malformed
                .gaps
                .iter()
                .any(|gap| gap.kind == ResolutionGapKind::MalformedSyntax),
            "{:?}",
            malformed.gaps
        );
        assert!(
            malformed
                .gaps
                .iter()
                .all(|gap| gap.kind != ResolutionGapKind::UnsupportedScopeOrBinder)
        );
    }

    #[test]
    fn omitted_reference_occurrences_own_exact_enumeration_gaps() {
        let source = r#"class A {
    java.util.List<String> values;
    void f() {
        if (probe()) {}
        Runnable task = () -> hidden();
    }
}"#;
        let facts = parse(source);
        let expected = [("probe", ResolutionGapKind::UnsupportedExpression)];

        assert_eq!(facts.reference_enumeration_gaps.len(), expected.len());
        for (snippet, kind) in expected {
            let start = source.find(snippet).expect("enumeration-gap snippet");
            let end = start + snippet.len();
            let gap = facts
                .reference_enumeration_gaps
                .iter()
                .find(|gap| {
                    let site = site(&facts, gap.site);
                    gap.kind == kind && site.start_byte == start && site.end_byte == end
                })
                .unwrap_or_else(|| {
                    panic!(
                        "missing reference-enumeration gap for {snippet:?}: {:?}",
                        facts.reference_enumeration_gaps
                    )
                });
            assert!(
                facts
                    .gaps
                    .iter()
                    .any(|point| point.site == gap.site && point.kind == kind)
            );
        }
        assert!(facts.identifiers.iter().any(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && identifier.namespace == ResolutionNamespace::Callable
                && name(&facts, identifier.name) == "hidden"
        }));
        let [argument] = facts.declared_type_arguments.as_slice() else {
            panic!("List<String> must retain its positional declared type argument");
        };
        let argument_site = site(&facts, facts.type_slots[argument.argument.index()].site);
        assert_eq!(
            &source[argument_site.start_byte..argument_site.end_byte],
            "String"
        );
    }

    #[test]
    fn qualified_annotation_names_and_element_values_keep_structured_sites() {
        let source = r#"package p;
@q.Marker(value = Flags.VALUE, type = String.class)
class A {}
class Flags { static final String VALUE = "x"; }
"#;
        let facts = parse(source);
        let spellings = identifier_spellings(&facts);
        for spelling in ["q", "Marker", "Flags", "VALUE", "String", "A"] {
            assert!(
                spellings.contains(&spelling),
                "annotation name or element value omitted {spelling:?}: {spellings:?}"
            );
        }
        for label in ["value", "type"] {
            assert!(
                !spellings.contains(&label),
                "annotation element label was treated as a reference: {spellings:?}"
            );
        }

        let marker = identifier(
            &facts,
            "Marker",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Type,
        );
        let route = facts
            .root_references
            .iter()
            .find(|route| route.reference == marker.site)
            .expect("qualified annotation retains its package route");
        assert!(route.prefix_reference.is_some());
        assert_eq!(
            facts
                .root_reference_segments
                .iter()
                .filter(|segment| segment.reference == marker.site)
                .map(|segment| name(&facts, segment.name))
                .collect::<Vec<_>>(),
            vec!["q"]
        );

        assert!(
            facts.reference_enumeration_gaps.is_empty(),
            "supported annotation syntax must fully enumerate its references: {:?}",
            facts.reference_enumeration_gaps
        );
    }

    #[test]
    fn structured_and_type_only_gaps_do_not_open_reference_enumeration() {
        let source = r#"package p;
import java.util.List;

class A {
    private java.util.List value;
    int callee(int argument) { return argument; }
    int use() {
        var local = 1.0;
        // Conditional branch promotion remains a structured-only type gap.
        return true ? callee(1) : local;
    }
}"#;
        let facts = parse(source);

        for kind in [
            ResolutionGapKind::UnsupportedRoute,
            ResolutionGapKind::AmbiguousQualifiedType,
            ResolutionGapKind::InferredType,
            ResolutionGapKind::AmbiguousNumericLiteral,
            ResolutionGapKind::UnsupportedVisibility,
            ResolutionGapKind::UnsupportedCallApplicability,
            ResolutionGapKind::UnsupportedPlacementBoundary,
        ] {
            assert!(
                facts.gaps.iter().any(|gap| gap.kind == kind),
                "fixture must exercise the structured-only gap {kind:?}"
            );
        }
        assert!(
            facts.reference_enumeration_gaps.is_empty(),
            "already retained routes, references, and type-only obligations must not contaminate broad enumeration: {:?}",
            facts.reference_enumeration_gaps
        );
    }

    #[test]
    fn keyword_constructor_invocations_are_explicit_gaps() {
        let facts = parse("class A { A() { this(1); } A(int value) { super(); } }");

        assert_eq!(
            facts
                .identifiers
                .iter()
                .filter(
                    |identifier| identifier.role == ResolutionIdentifierRole::Reference
                        && site(&facts, identifier.site).kind
                            != ResolutionSiteKind::SyntheticReference
                )
                .count(),
            0
        );
        let unsupported_invocations = facts
            .gaps
            .iter()
            .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedExpression)
            .collect::<Vec<_>>();
        assert_eq!(unsupported_invocations.len(), 2);
        assert!(unsupported_invocations.iter().all(|gap| {
            site(&facts, gap.site).kind == ResolutionSiteKind::UnsupportedExpression
        }));
        assert_eq!(
            non_visibility_gaps(&facts)
                .iter()
                .map(|gap| gap.kind)
                .collect::<Vec<_>>(),
            vec![
                ResolutionGapKind::UnsupportedExpression,
                ResolutionGapKind::UnsupportedExpression,
                ResolutionGapKind::UnsupportedHierarchyTraversal,
                ResolutionGapKind::UnsupportedPlacementBoundary,
            ]
        );
        assert_eq!(visibility_gap_sites(&facts).len(), 3);
    }

    #[test]
    fn integer_literal_types_follow_java_radix_suffix_and_range_rules() {
        let cases = [
            ("0", "int"),
            ("1", "int"),
            ("2", "int"),
            ("3", "int"),
            ("4", "int"),
            ("+4", "int"),
            ("2_147_483_647", "int"),
            ("0x7fff_ffff", "int"),
            ("0xffff_ffff", "int"),
            ("0377_7777_7777", "int"),
            ("0b1111_1111_1111_1111_1111_1111_1111_1111", "int"),
            ("-2_147_483_648", "int"),
            ("0L", "long"),
            ("7l", "long"),
            ("0x1_0000_0000L", "long"),
            ("9_223_372_036_854_775_807L", "long"),
            ("-9_223_372_036_854_775_808L", "long"),
            ("0xffff_ffff_ffff_ffffL", "long"),
        ];
        let calls = cases
            .iter()
            .map(|(literal, _)| format!("changed({literal});"))
            .collect::<Vec<_>>()
            .join(" ");
        let source =
            format!("class A {{ void changed(long value) {{}} void use() {{ {calls} }} }}");
        let facts = parse(&source);

        assert_eq!(facts.call_arguments.len(), cases.len());
        for (literal, expected_type) in cases {
            let call = format!("changed({literal})");
            let sign_width = if literal.starts_with('+') || literal.starts_with('-') {
                1
            } else {
                0
            };
            let literal_start =
                source.find(&call).expect("literal call") + "changed(".len() + sign_width;
            let seed = intrinsic_seed_at(&facts, literal_start)
                .unwrap_or_else(|| panic!("missing intrinsic seed for {literal}"));
            assert_eq!(seed.kind, IntrinsicTypeKind::Primitive);
            assert_eq!(name(&facts, seed.name), expected_type);
            assert_eq!(
                site(&facts, slot(&facts, seed.output).site).kind,
                ResolutionSiteKind::Literal
            );
            assert!(
                facts.type_transfers.iter().any(|transfer| {
                    transfer.input == seed.output
                        && transfer.kind == ResolutionTypeTransferKind::Argument
                        && facts
                            .call_arguments
                            .iter()
                            .any(|argument| argument.value == transfer.output)
                }),
                "the structured call argument must consume {literal}'s typed literal slot"
            );
            assert!(
                gap_at(
                    &facts,
                    literal_start,
                    ResolutionGapKind::AmbiguousNumericLiteral,
                )
                .is_none()
            );
        }
    }

    #[test]
    fn integer_literal_overflow_and_non_java_octals_remain_incomplete() {
        let literals = [
            "2_147_483_648",
            "+2_147_483_648",
            "0x1_0000_0000",
            "04_000_000_0000",
            "0b1_0000_0000_0000_0000_0000_0000_0000_0000",
            "9_223_372_036_854_775_808L",
            "0x1_0000_0000_0000_0000L",
            // tree-sitter-java accepts this spelling as octal, but Java does
            // not have a `0o`/`0O` radix prefix.
            "0o10",
        ];
        let calls = literals
            .iter()
            .map(|literal| format!("changed({literal});"))
            .collect::<Vec<_>>()
            .join(" ");
        let source =
            format!("class A {{ void changed(long value) {{}} void use() {{ {calls} }} }}");
        let facts = parse(&source);

        for literal in literals {
            let call = format!("changed({literal})");
            let sign_width = if literal.starts_with('+') || literal.starts_with('-') {
                1
            } else {
                0
            };
            let literal_start =
                source.find(&call).expect("literal call") + "changed(".len() + sign_width;
            assert!(
                intrinsic_seed_at(&facts, literal_start).is_none(),
                "invalid Java integer literal {literal} must not mint a type"
            );
            let gap = gap_at(
                &facts,
                literal_start,
                ResolutionGapKind::AmbiguousNumericLiteral,
            )
            .unwrap_or_else(|| panic!("missing numeric-literal gap for {literal}"));
            assert_eq!(
                site(&facts, gap.site).kind,
                ResolutionSiteKind::UnsupportedExpression
            );
        }
    }

    #[test]
    fn generic_bounds_and_declared_arguments_keep_owner_positions() {
        let facts = parse_once(
            "interface FieldElement<T> { T add(T value) { return value; } }\
             class Block<T extends FieldElement<T>> { T step(T value) { return value.add(value); } }",
        );
        let [bound] = facts
            .declared_type_relations
            .iter()
            .filter(|relation| relation.kind == ResolutionDeclaredTypeRelationKind::TraitBound)
            .collect::<Vec<_>>()[..]
        else {
            panic!("the Java type parameter publishes its written upper bound");
        };
        let target = bound.target.expect("a trait bound has a typed target");
        assert_eq!(
            bound.target_reference,
            Some(facts.type_slots[target.index()].site)
        );
        assert!(facts.type_transfers.iter().any(|transfer| {
            transfer.input == target
                && transfer.output == bound.subject
                && transfer.kind == ResolutionTypeTransferKind::TypeUnion
        }));
        let parameter_declaration = facts.type_slots[bound.subject.index()].site;
        assert!(facts.declaration_type_slots.iter().any(|property| {
            property.declaration == parameter_declaration
                && property.slot == bound.subject
                && property.role == DeclarationTypeRole::Identity
        }));
        assert!(
            facts
                .gaps
                .iter()
                .all(|gap| gap.kind != ResolutionGapKind::UnsupportedScopeOrBinder)
        );

        let [argument] = facts.declared_type_arguments.as_slice() else {
            panic!(
                "FieldElement<T> publishes its one positional type argument: {:?}; identifiers={:?}",
                facts.declared_type_arguments, facts.identifiers
            );
        };
        assert_eq!(argument.ordinal, 0);
        assert_eq!(
            facts.type_slots[argument.argument.index()].role,
            ResolutionTypeSlotRole::TargetTypeIdentity
        );
        let add = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && identifier.namespace == ResolutionNamespace::Callable
                    && name(&facts, identifier.name) == "add"
            })
            .expect("FieldElement.add declaration");
        let result_parameter = facts
            .callable_result_owner_type_parameters
            .iter()
            .find(|parameter| parameter.callable == add.site)
            .expect("FieldElement.add returns its owner's type parameter");
        assert_eq!(result_parameter.position, 0);
    }
}
