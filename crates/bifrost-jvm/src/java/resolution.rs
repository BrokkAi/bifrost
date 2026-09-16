//! Java lowering for immutable, target-independent resolution facts.
//!
//! This extends the whole-file pass that already records persisted type-name
//! spellings. It consumes the `Tree` built by the adapter and never reparses or
//! scans source text at query time. Cross-file targets are intentionally absent:
//! references project properties of whichever declaration a selected revision
//! later binds.

mod import_split;
pub use import_split::{
    JavaImportInventory, JavaImportSplitGap, JavaSingleTypeImportProof,
    prove_java_single_type_import,
};

use brokk_bifrost_core::analyzer::java_facts::JavaTypeConstructorShape;
use brokk_bifrost_core::analyzer::resolution_facts::{
    BindingProjectionFact, BindingProjectionKind, DeclarationTypeRole, DeclarationTypeSlotFact,
    FileResolutionFacts, IntrinsicTypeKind, IntrinsicTypeSeedFact, PositionedIdentifierFact,
    ResolutionBinderFact, ResolutionBinderKind, ResolutionCallArgumentFact, ResolutionCallFact,
    ResolutionCallableParameterFact, ResolutionCallableReceiverOrigin,
    ResolutionCallableReceiverOriginFact, ResolutionCallableSignatureFact,
    ResolutionConstructionRequirementFact, ResolutionConstructionRequirementKind,
    ResolutionDeclarationVisibilityFact, ResolutionEngineRuleEligibilityFact,
    ResolutionEngineRuleKind, ResolutionGapFact, ResolutionGapKind, ResolutionIdentifierRole,
    ResolutionImportRouteFact, ResolutionImportRouteKind, ResolutionImportRouteSegmentFact,
    ResolutionMemberAccess, ResolutionMemberKind, ResolutionMemberOwnerFact,
    ResolutionMemberQualifierCompatibility, ResolutionNameFact, ResolutionNameId,
    ResolutionNamespace, ResolutionPackageFact, ResolutionPackageSegmentFact,
    ResolutionReferenceEnumerationGapFact, ResolutionReferenceOwnerFact, ResolutionRootExportFact,
    ResolutionRootImportAnchor, ResolutionRootImportDemandFact, ResolutionRootImportFact,
    ResolutionRootImportSegmentFact, ResolutionScopeFact, ResolutionScopeId, ResolutionScopeKind,
    ResolutionSiteFact, ResolutionSiteId, ResolutionSiteKind, ResolutionSupertypeFact,
    ResolutionSupertypeKind, ResolutionTypeSlotFact, ResolutionTypeSlotId, ResolutionTypeSlotRole,
    ResolutionTypeTransferFact, ResolutionTypeTransferKind, ResolutionTypeTransferValueTransform,
    ResolutionVisibilityEligibilityFact,
};
use brokk_bifrost_core::analyzer::source_facts::{
    PrimarySourceFactCollector, SourceDeclarationId, SourceFactRows, SourceOccurrenceId,
};
use brokk_bifrost_core::analyzer::structural::adapter_helpers::first_named_child;
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
use super::graph_support::java_declared_type_parameters;
use super::imports::{JavaImportSyntax, JavaPackageSyntax};
use super::source_types::JavaSourceTypeCollector;
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
    suppression_depth: usize,
    type_contexts: Vec<TypeContext>,
    callable_contexts: Vec<CallableContext>,
    declaration_contexts: Vec<ResolutionSiteId>,
    reference_enclosing_declaration_overrides: Vec<ResolutionSiteId>,
    body_scopes: HashMap<usize, ResolutionScopeId>,
    declaration_type_slots: HashMap<ResolutionSiteId, ResolutionTypeSlotId>,
    type_slots_by_node: HashMap<usize, ResolutionTypeSlotId>,
    expression_slots_by_node: HashMap<usize, ResolutionTypeSlotId>,
    claimed_identifier_nodes: HashSet<usize>,
    gapped_semantic_subtrees: HashSet<usize>,
    next_parameter_ordinal: HashMap<ResolutionSiteId, u32>,
    unsupported_implicit_receiver_scopes: HashSet<ResolutionScopeId>,
    unsupported_implicit_receiver_context_depth: usize,
    package_declaration: Option<ResolutionSiteId>,
    package_segment_names: Vec<ResolutionNameId>,
    package_is_invalid: bool,
    pending_type_on_demand_imports: Vec<ResolutionSiteId>,
    supported_directive_nodes: HashSet<usize>,
    source_declaration_visibilities: HashMap<usize, (SourceDeclarationId, DeclaredVisibility)>,
    source_modifiers: HashMap<usize, JavaDeclarationModifiers>,
    source_type_shapes: HashMap<usize, JavaTypeShape>,
    source_field_shapes: HashMap<usize, JavaFieldShape>,
    source_callable_shapes: HashMap<usize, JavaCallableShape>,
}

#[derive(Debug, Clone, Copy)]
enum ExitAction {
    Scope,
    TypeContext,
    CallableContext,
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
    flavor: TypeFlavor,
    direct_default_construction_proof_eligible: bool,
    constructor_shape: Option<JavaTypeConstructorShape>,
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
            suppression_depth: 0,
            type_contexts: Vec::new(),
            callable_contexts: Vec::new(),
            declaration_contexts: Vec::new(),
            reference_enclosing_declaration_overrides: Vec::new(),
            body_scopes: HashMap::default(),
            declaration_type_slots: HashMap::default(),
            type_slots_by_node: HashMap::default(),
            expression_slots_by_node: HashMap::default(),
            claimed_identifier_nodes: HashSet::default(),
            gapped_semantic_subtrees: HashSet::default(),
            next_parameter_ordinal: HashMap::default(),
            unsupported_implicit_receiver_scopes: HashSet::default(),
            unsupported_implicit_receiver_context_depth: 0,
            package_declaration: None,
            package_segment_names: Vec::new(),
            package_is_invalid: false,
            pending_type_on_demand_imports: Vec::new(),
            supported_directive_nodes,
            source_declaration_visibilities: HashMap::default(),
            source_modifiers: HashMap::default(),
            source_type_shapes: HashMap::default(),
            source_field_shapes: HashMap::default(),
            source_callable_shapes: HashMap::default(),
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
        assert!(self.callable_contexts.is_empty());
        assert!(self.declaration_contexts.is_empty());
        assert!(self.reference_enclosing_declaration_overrides.is_empty());
        assert_eq!(self.unsupported_implicit_receiver_context_depth, 0);
        let root = *self.scope(ResolutionScopeId::new(0));
        assert_eq!(root.kind, ResolutionScopeKind::CompilationUnit);
        let placement = self.add_site_from_occurrence(
            self.root_occurrence,
            ResolutionSiteKind::UnsupportedRoute,
            root.id,
        );
        self.add_gap(placement, ResolutionGapKind::UnsupportedPlacementBoundary);
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
            assert_eq!(
                reference.qualifier.is_none(),
                fact.origin == ResolutionCallableReceiverOrigin::Implicit,
                "only an implicit Java callable receiver may omit its qualifier slot: {fact:?}"
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
                self.facts.gaps.contains(&ResolutionGapFact {
                    site: gap.site,
                    kind: gap.kind,
                }),
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
        if node.kind() == "method_reference" {
            return self.suppress_with_gap(
                node,
                ResolutionSiteKind::UnsupportedExpression,
                ResolutionGapKind::UnsupportedExpression,
            );
        }

        if node.kind() == "explicit_constructor_invocation" {
            return self.suppress_with_gap(
                node,
                ResolutionSiteKind::UnsupportedExpression,
                ResolutionGapKind::UnsupportedExpression,
            );
        }

        if self.is_unsupported_semantic_subtree(node) {
            return self.suppress_with_gap(
                node,
                ResolutionSiteKind::UnsupportedDeclaration,
                ResolutionGapKind::UnsupportedScopeOrBinder,
            );
        }

        if self.gapped_semantic_subtrees.contains(&node.id()) {
            return self.suppress_semantics();
        }

        if node.kind() == "formal_parameters"
            && node.named_child_count() > 0
            && self.callable_contexts.is_empty()
            && self
                .type_contexts
                .last()
                .is_some_and(|context| context.flavor == TypeFlavor::Record)
        {
            return self.suppress_with_gap(
                node,
                ResolutionSiteKind::UnsupportedDeclaration,
                ResolutionGapKind::UnsupportedScopeOrBinder,
            );
        }

        if self.is_scope_body(node) {
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
            return TreeWalkAction::DescendWithExit;
        }

        match node.kind() {
            "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "annotation_type_declaration" => {
                if !matches!(
                    self.scope(self.current_scope()).kind,
                    ResolutionScopeKind::CompilationUnit | ResolutionScopeKind::TypeBody
                ) {
                    return self.suppress_with_gap(
                        node,
                        ResolutionSiteKind::UnsupportedDeclaration,
                        ResolutionGapKind::UnsupportedScopeOrBinder,
                    );
                }
                if let Some(context) = self.lower_type_declaration(node) {
                    self.declaration_contexts.push(context.declaration);
                    self.type_contexts.push(context);
                    self.exit_actions.push(ExitAction::TypeContext);
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
                    self.exit_actions.push(ExitAction::CallableContext);
                    return TreeWalkAction::DescendWithExit;
                }
            }
            "static_initializer" => self.lower_initializer(node),
            "formal_parameter" => self.lower_parameter(node),
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

        if matches!(
            node.kind(),
            "identifier" | "type_identifier" | "this" | "super"
        ) && !self.claimed_identifier_nodes.contains(&node.id())
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

    fn reject_misplaced_directive(
        &mut self,
        node: Node<'_>,
        kind: ResolutionSiteKind,
    ) -> TreeWalkAction {
        let site = self.add_site(node, kind);
        self.add_gap(site, ResolutionGapKind::UnsupportedRoute);
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
                ResolutionGapKind::UnsupportedScopeOrBinder
            };
            self.add_gap(annotation_site, kind);
            self.add_reference_enumeration_gap_if_omitted(annotation, annotation_site, kind);
            annotation_has_error |= malformed;
        }

        let Some(segments) = syntax.segments.as_ref() else {
            self.add_gap(declaration, ResolutionGapKind::UnsupportedRoute);
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
            self.add_gap(site, ResolutionGapKind::UnsupportedRoute);
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
        match kind {
            ResolutionImportRouteKind::SingleType if names.len() > 1 => {
                self.facts.root_imports.push(ResolutionRootImportFact {
                    site,
                    root_scope,
                    anchor: ResolutionRootImportAnchor::Lexical,
                });
                self.facts.root_import_segments.extend(
                    names[..names.len() - 1]
                        .iter()
                        .copied()
                        .enumerate()
                        .map(|(position, name)| ResolutionRootImportSegmentFact {
                            import_site: site,
                            position: dense_ordinal(position, "Java root import segment"),
                            name,
                        }),
                );
                self.facts
                    .root_import_demands
                    .push(ResolutionRootImportDemandFact {
                        import_site: site,
                        namespace: ResolutionNamespace::Type,
                        name: *names
                            .last()
                            .expect("single-type import has a terminal name"),
                    });
            }
            ResolutionImportRouteKind::TypeOnDemand => {
                self.facts.root_imports.push(ResolutionRootImportFact {
                    site,
                    root_scope,
                    anchor: ResolutionRootImportAnchor::Lexical,
                });
                self.facts
                    .root_import_segments
                    .extend(names.iter().copied().enumerate().map(|(position, name)| {
                        ResolutionRootImportSegmentFact {
                            import_site: site,
                            position: dense_ordinal(position, "Java root import segment"),
                            name,
                        }
                    }));
                self.pending_type_on_demand_imports.push(site);
            }
            ResolutionImportRouteKind::SingleType
            | ResolutionImportRouteKind::SingleStatic
            | ResolutionImportRouteKind::StaticOnDemand => {}
        }
        // The source route is exact, but selecting its destination package,
        // owner, and declaration inventory remains operation-local.
        self.add_gap(site, ResolutionGapKind::UnsupportedRoute);
        self.suppress_semantics()
    }

    fn finish_root_import_demands(&mut self) {
        let explicit_demands = self
            .facts
            .root_import_demands
            .iter()
            .map(|demand| (demand.namespace, demand.name))
            .collect::<HashSet<_>>();
        let mut seen = HashSet::default();
        let demands = self
            .facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == ResolutionNamespace::Type
                    && identifier.qualifier.is_none()
                    && !explicit_demands.contains(&(identifier.namespace, identifier.name))
                    && seen.insert(identifier.name)
            })
            .map(|identifier| identifier.name)
            .collect::<Vec<_>>();
        for import_site in &self.pending_type_on_demand_imports {
            for &name in &demands {
                self.facts
                    .root_import_demands
                    .push(ResolutionRootImportDemandFact {
                        import_site: *import_site,
                        namespace: ResolutionNamespace::Type,
                        name,
                    });
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
            assert!(self.facts.gaps.contains(&ResolutionGapFact {
                site: package.placement_gap_site,
                kind: ResolutionGapKind::UnsupportedPlacementBoundary,
            }));

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
            assert!(self.facts.gaps.contains(&ResolutionGapFact {
                site: route.site,
                kind: ResolutionGapKind::UnsupportedRoute,
            }));

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
            }
            ExitAction::TypeContext => {
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
                if implicit_hierarchy {
                    self.add_gap(
                        context.declaration,
                        ResolutionGapKind::UnsupportedHierarchyTraversal,
                    );
                }
                let implicit_constructor = context.direct_default_construction_proof_eligible;
                if implicit_constructor {
                    self.add_gap(context.declaration, ResolutionGapKind::ImplicitConstructor);
                }
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
            ExitAction::Suppression => {
                assert!(self.suppression_depth > 0);
                self.suppression_depth -= 1;
            }
        }
    }

    fn current_scope(&self) -> ResolutionScopeId {
        *self
            .scope_stack
            .last()
            .expect("root scope is always present")
    }

    fn scope(&self, id: ResolutionScopeId) -> &ResolutionScopeFact {
        &self.facts.scopes[id.get() as usize]
    }

    fn site(&self, id: ResolutionSiteId) -> &ResolutionSiteFact {
        &self.facts.sites[id.get() as usize]
    }

    fn allocate_scope(
        &mut self,
        parent: ResolutionScopeId,
        owner: Option<ResolutionSiteId>,
        kind: ResolutionScopeKind,
        start_byte: usize,
        end_byte: usize,
    ) -> ResolutionScopeId {
        assert!(start_byte <= end_byte);
        let id = ResolutionScopeId::try_from_index(self.facts.scopes.len())
            .expect("resolution scope count exceeds u32");
        self.facts.scopes.push(ResolutionScopeFact {
            id,
            parent: Some(parent),
            owner,
            kind,
            start_byte,
            end_byte,
        });
        id
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
        let id = ResolutionSiteId::try_from_index(self.facts.sites.len())
            .expect("resolution site count exceeds u32");
        self.site_occurrences.push(occurrence);
        self.facts.sites.push(ResolutionSiteFact {
            id,
            scope,
            kind,
            start_byte: range.start_byte,
            end_byte: range.end_byte,
        });
        id
    }

    fn record_declaration_source(
        &mut self,
        node: Node<'_>,
        site: ResolutionSiteId,
    ) -> SourceDeclarationId {
        let occurrence = self.source_collector.intern_node(node);
        let name = node
            .child_by_field_name("name")
            .map(|name| self.source_collector.intern_node(name));
        let declaration = self.source_collector.declare(occurrence, name);
        self.declaration_sources.push((site, declaration));
        assert!(
            self.declaration_sites.insert(node.id(), site).is_none(),
            "one Java declaration node has one native declaration site"
        );
        declaration
    }

    fn intern_name(&mut self, spelling: &str) -> ResolutionNameId {
        if let Some(id) = self.name_ids.get(spelling) {
            return *id;
        }
        let id = ResolutionNameId::try_from_index(self.facts.names.len())
            .expect("resolution name count exceeds u32");
        let owned = spelling.to_string();
        self.name_ids.insert(owned.clone(), id);
        self.facts.names.push(ResolutionNameFact {
            id,
            spelling: owned,
        });
        id
    }

    fn add_identifier_to_site(
        &mut self,
        site: ResolutionSiteId,
        node: Node<'_>,
        role: ResolutionIdentifierRole,
        namespace: ResolutionNamespace,
        qualifier: Option<ResolutionTypeSlotId>,
    ) {
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
        {
            self.add_gap(site, ResolutionGapKind::UnsupportedImplicitReceiver);
        }
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
        let id = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
            .expect("resolution type slot count exceeds u32");
        self.facts
            .type_slots
            .push(ResolutionTypeSlotFact { id, site, role });
        id
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
            ResolutionTypeTransferKind::Assignment
            | ResolutionTypeTransferKind::Receiver
            | ResolutionTypeTransferKind::Argument
            | ResolutionTypeTransferKind::Return => ResolutionTypeTransferValueTransform::Preserve,
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
        self.facts.type_transfers.push(ResolutionTypeTransferFact {
            input,
            output,
            kind,
            indirection_delta: 0,
            value_transform,
        });
    }

    fn lower_type_declaration(&mut self, node: Node<'_>) -> Option<TypeContext> {
        let name = node.child_by_field_name("name")?;
        if name.kind() != "identifier" {
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
        // forbidden. Until those two facts have separate rows, keep this
        // marker conservative for exact direct-construction proof.
        let modifiers = self.source_modifiers_for(node);
        let enclosing_type = self.type_contexts.last().copied();
        let source_type_shape = self.source_type_shape_for(node);
        let direct_default_construction_proof_eligible = flavor == TypeFlavor::Class
            && !modifiers.is_abstract
            && matches!(
                source_type_shape.constructor_shape,
                Some(JavaTypeConstructorShape::Default)
            );
        let is_static_nested = enclosing_type.is_some_and(|_| source_type_shape.is_static);
        let binding_scope = self.current_scope();
        let declaration = self.add_identifier_site(
            name,
            ResolutionSiteKind::TypeDeclaration,
            binding_scope,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
            None,
        );
        let source_declaration = self.record_declaration_source(node, declaration);
        self.add_declaration_visibility(declaration, node, source_declaration);
        let scope = *self.scope(binding_scope);
        self.facts.binders.push(ResolutionBinderFact {
            declaration,
            scope: binding_scope,
            kind: ResolutionBinderKind::Type,
            hoisting: HoistingClass::ScopeWide,
            activation_start: scope.start_byte,
            activation_end: scope.end_byte,
        });
        if enclosing_type.is_none() && binding_scope == ResolutionScopeId::new(0) {
            self.facts.root_exports.push(ResolutionRootExportFact {
                root_scope: binding_scope,
                declaration,
                namespace: ResolutionNamespace::Type,
            });
        }

        if let Some(owner) = enclosing_type {
            self.facts.member_owners.push(ResolutionMemberOwnerFact {
                member: declaration,
                owner: owner.declaration,
                kind: ResolutionMemberKind::NestedType,
                access: ResolutionMemberAccess::Type,
                qualifier_compatibility: ResolutionMemberQualifierCompatibility::TypeOnly,
            });
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

        if let Some(body) = node.child_by_field_name("body") {
            let body_scope = self.allocate_scope(
                binding_scope,
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
        }
        Some(TypeContext {
            declaration,
            flavor,
            direct_default_construction_proof_eligible,
            constructor_shape: source_type_shape.constructor_shape,
            has_explicit_superclass: false,
            has_explicit_superinterface: false,
        })
    }

    fn lower_callable_declaration(&mut self, node: Node<'_>) -> Option<CallableContext> {
        let name = node.child_by_field_name("name")?;
        if name.kind() != "identifier" || self.current_type_owner().is_none() {
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
        self.facts
            .callable_signatures
            .push(ResolutionCallableSignatureFact {
                callable: declaration,
                type_parameter_count: dense_ordinal(
                    java_declared_type_parameters(node).len(),
                    "Java callable type parameter",
                ),
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

        let body = node.child_by_field_name("body");
        let (body_start, body_end) = body
            .map(|body| (body.start_byte(), body.end_byte()))
            .unwrap_or((node.end_byte(), node.end_byte()));
        let executable_start = node
            .child_by_field_name("parameters")
            .map_or(body_start, |parameters| parameters.start_byte());
        let callable_scope = self.allocate_scope(
            binding_scope,
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
            self.attach_declaration_type(declaration, return_type, DeclarationTypeRole::Return);
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

    fn lower_parameter(&mut self, node: Node<'_>) {
        let Some(name) = node.child_by_field_name("name") else {
            return;
        };
        if name.kind() != "identifier" {
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
        self.record_declaration_source(node, declaration);
        self.facts.binders.push(ResolutionBinderFact {
            declaration,
            scope: callable.scope,
            kind: ResolutionBinderKind::Parameter,
            hoisting: HoistingClass::ScopeWide,
            activation_start: callable.activation_start,
            activation_end: callable.activation_end,
        });

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
        let ordinal = {
            let next = self
                .next_parameter_ordinal
                .entry(callable.declaration)
                .or_insert(0);
            let ordinal = *next;
            *next += 1;
            ordinal
        };
        let repeated = self
            .source_callable_shape_for_node(callable.source_node_id)
            .repeated_for(node.id())
            .expect("Java native parameter must have a captured source shape");
        assert!(!repeated, "formal parameters cannot be repeated");
        self.facts
            .callable_parameters
            .push(ResolutionCallableParameterFact {
                callable: callable.declaration,
                ordinal,
                parameter: declaration,
                value_type,
                repeated,
            });
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
        if name.kind() != "identifier" {
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
        self.record_declaration_source(declarator, declaration);
        self.facts.binders.push(ResolutionBinderFact {
            declaration,
            scope: callable.scope,
            kind: ResolutionBinderKind::Parameter,
            hoisting: HoistingClass::ScopeWide,
            activation_start: callable.activation_start,
            activation_end: callable.activation_end,
        });
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
        let ordinal = {
            let next = self
                .next_parameter_ordinal
                .entry(callable.declaration)
                .or_insert(0);
            let ordinal = *next;
            *next += 1;
            ordinal
        };
        let repeated = self
            .source_callable_shape_for_node(callable.source_node_id)
            .repeated_for(node.id())
            .expect("Java native spread parameter must have a captured source shape");
        assert!(repeated, "spread parameters must be repeated");
        self.facts
            .callable_parameters
            .push(ResolutionCallableParameterFact {
                callable: callable.declaration,
                ordinal,
                parameter: declaration,
                value_type,
                repeated,
            });
        true
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
        for node in named_children(declaration_form)
            .into_iter()
            .filter(|child| child.kind() == "variable_declarator")
        {
            let Some(name) = node.child_by_field_name("name") else {
                continue;
            };
            if name.kind() != "identifier" {
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
            }
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
                activation_start: if is_field {
                    scope.start_byte
                } else if let Some(initializer) = node.child_by_field_name("value") {
                    initializer.start_byte()
                } else {
                    node.end_byte()
                },
                activation_end: scope.end_byte,
            });

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

            if is_field {
                self.reference_enclosing_declaration_overrides
                    .push(declaration);
            }
            if let Some(dimensions) = node.child_by_field_name("dimensions") {
                self.attach_declaration_gap_type(
                    declaration,
                    dimensions,
                    DeclarationTypeRole::Value,
                    ResolutionGapKind::PostfixArrayDimensions,
                )
            } else {
                self.attach_declaration_type(declaration, type_node, DeclarationTypeRole::Value)
            };
            if let Some(value) = node.child_by_field_name("value") {
                if field_is_static {
                    self.unsupported_implicit_receiver_context_depth += 1;
                }
                let initializer = self.lower_expression(value);
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

    fn lower_return(&mut self, node: Node<'_>) {
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
        self.add_transfer_with_transform(
            input,
            output,
            ResolutionTypeTransferKind::DeclaredType,
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
        self.add_transfer_with_transform(
            input,
            output,
            ResolutionTypeTransferKind::DeclaredType,
            value_transform,
        );
        self.declaration_type_slots.insert(declaration, output);
        output
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
        self.facts.supertypes.push(ResolutionSupertypeFact {
            subtype,
            supertype_reference,
            supertype_slot,
            kind,
        });
        self.add_gap(
            supertype_reference,
            ResolutionGapKind::UnsupportedHierarchyTraversal,
        );
    }

    /// Generic arguments are not yet a typed relation family, but the base
    /// type still owns the hierarchy reference. Walk through nested generic
    /// wrappers iteratively so the unsupported frontier remains explicit while
    /// the positioned base reference retains its subtype owner.
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

    /// Iteratively lowers wrappers and scoped type paths. The explicit stack
    /// keeps generated or adversarially deep qualified names stack-safe.
    fn lower_type(&mut self, node: Node<'_>) -> ResolutionTypeSlotId {
        if let Some(slot) = self.type_slots_by_node.get(&node.id()) {
            return *slot;
        }

        let mut wrappers = Vec::new();
        let mut current = node;
        let base = loop {
            if let Some(slot) = self.type_slots_by_node.get(&current.id()) {
                break *slot;
            }
            let source_type = self.capture_source_type(current);
            let shape = self
                .source_types
                .shape(source_type)
                .expect("captured Java source type has a shape");
            match (current.kind(), shape) {
                // Type arguments require their own normalized relation. Until
                // that row family exists, preserving only the raw type would
                // falsely certify a complete typed frontier.
                ("generic_type", _) => break self.lower_unsupported_type(current),
                ("scoped_type_identifier", _) => {
                    let Some(scope) = current
                        .child_by_field_name("scope")
                        .or_else(|| first_named_child(current))
                    else {
                        break self.lower_unsupported_type(current);
                    };
                    wrappers.push(current);
                    current = scope;
                }
                ("type_identifier", JavaTypeSyntaxShape::Named { .. }) => {
                    break self.lower_plain_type_reference(current);
                }
                ("type_identifier", JavaTypeSyntaxShape::Unknown)
                    if self.source_types.is_inferred_type(source_type) =>
                {
                    break self.lower_gap_type(current, ResolutionGapKind::InferredType);
                }
                (
                    "integral_type" | "floating_point_type" | "boolean_type" | "void_type",
                    JavaTypeSyntaxShape::NonNominal,
                ) => {
                    break self.lower_intrinsic_type(current, IntrinsicTypeKind::Primitive);
                }
                _ => break self.lower_unsupported_type(current),
            }
        };

        if !wrappers.is_empty() {
            let base_site = self.slot(base).site;
            self.add_gap(base_site, ResolutionGapKind::AmbiguousQualifiedType);
        }
        let mut output = base;
        while let Some(wrapper) = wrappers.pop() {
            output = match wrapper.kind() {
                "scoped_type_identifier" => {
                    let Some(name) = wrapper
                        .child_by_field_name("name")
                        .or_else(|| named_children(wrapper).into_iter().last())
                    else {
                        output = self.lower_unsupported_type(wrapper);
                        continue;
                    };
                    let reference = self.add_identifier_site(
                        name,
                        ResolutionSiteKind::MemberReference,
                        self.current_scope(),
                        ResolutionIdentifierRole::Reference,
                        ResolutionNamespace::Type,
                        Some(output),
                    );
                    let slot = self.add_slot(reference, ResolutionTypeSlotRole::TargetTypeIdentity);
                    self.facts.binding_projections.push(BindingProjectionFact {
                        reference,
                        output: slot,
                        kind: BindingProjectionKind::TargetTypeIdentity,
                    });
                    self.add_gap(reference, ResolutionGapKind::AmbiguousQualifiedType);
                    self.type_slots_by_node.insert(name.id(), slot);
                    slot
                }
                _ => unreachable!("only known wrappers are pushed"),
            };
            self.type_slots_by_node.insert(wrapper.id(), output);
        }
        self.type_slots_by_node.insert(node.id(), output);
        output
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
        self.facts.binding_projections.push(BindingProjectionFact {
            reference,
            output: slot,
            kind: BindingProjectionKind::TargetTypeIdentity,
        });
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
        let site = self.add_site(node, ResolutionSiteKind::TypeReference);
        let slot = self.add_slot(site, ResolutionTypeSlotRole::TargetTypeIdentity);
        let spelling = node_text(node, self.source).trim();
        let name = self.intern_name(spelling);
        self.facts.intrinsic_type_seeds.push(IntrinsicTypeSeedFact {
            output: slot,
            name,
            kind,
            indirection: 0,
        });
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
        let site = self.add_site(node, ResolutionSiteKind::UnsupportedExpression);
        let slot = self.add_slot(site, ResolutionTypeSlotRole::TargetTypeIdentity);
        self.add_gap(site, kind);
        self.add_reference_enumeration_gap_if_omitted(node, site, kind);
        self.gapped_semantic_subtrees.insert(node.id());
        self.type_slots_by_node.insert(node.id(), slot);
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
                    if left.kind() == "identifier" {
                        self.lower_value_location_reference(left);
                    } else {
                        stack.push((left, false));
                    }
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
                "update_expression" => {
                    let Some(operand) = first_named_child(node) else {
                        self.lower_unsupported_expression(node);
                        continue;
                    };
                    stack.push((node, true));
                    if operand.kind() == "identifier" {
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
                        stack.push((object, false));
                    }
                }
                "object_creation_expression" => {
                    if self.has_direct_named_child(node, "class_body") {
                        self.lower_unsupported_expression_as(
                            node,
                            ResolutionGapKind::UnsupportedScopeOrBinder,
                        );
                    } else {
                        stack.push((node, true));
                        self.push_argument_dependencies(node, &mut stack);
                        if let Some(type_node) = node.child_by_field_name("type")
                            && let Some(enclosing) =
                                self.object_creation_enclosing_expression(node, type_node)
                        {
                            stack.push((enclosing, false));
                        }
                    }
                }
                "parenthesized_expression" => {
                    stack.push((node, true));
                    if let Some(inner) = first_named_child(node) {
                        stack.push((inner, false));
                    }
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
                "lambda_expression" => self.lower_unsupported_expression_as(
                    node,
                    ResolutionGapKind::UnsupportedScopeOrBinder,
                ),
                "method_reference" => self.lower_unsupported_expression(node),
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
            "method_invocation" => self.finish_method_invocation(node),
            "field_access" => self.finish_field_access(node),
            "object_creation_expression" => self.finish_object_creation(node),
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

    fn finish_assignment_expression(&mut self, node: Node<'_>) {
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            self.lower_unsupported_expression(node);
            return;
        };
        debug_assert!(self.expression_slots_by_node.contains_key(&right.id()));
        self.expression_slots_by_node
            .insert(node.id(), self.expression_slot(left));
    }

    fn finish_update_expression(&mut self, node: Node<'_>) {
        let Some(operand) = first_named_child(node) else {
            self.lower_unsupported_expression(node);
            return;
        };
        self.expression_slots_by_node
            .insert(node.id(), self.expression_slot(operand));
    }

    fn finish_binary_expression(&mut self, node: Node<'_>) {
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            self.lower_unsupported_expression(node);
            return;
        };
        debug_assert!(self.expression_slots_by_node.contains_key(&left.id()));
        debug_assert!(self.expression_slots_by_node.contains_key(&right.id()));
        let site = self.add_site(node, ResolutionSiteKind::UnsupportedExpression);
        let output = self.add_slot(site, ResolutionTypeSlotRole::ExpressionValue);
        // Java's operator-specific promotion is not represented yet. Retain
        // both structured operands, but do not publish a guessed result type
        // until that source-owned rule family exists.
        self.add_gap(site, ResolutionGapKind::InferredType);
        self.expression_slots_by_node.insert(node.id(), output);
    }

    fn lower_value_reference(&mut self, node: Node<'_>) {
        self.lower_value_reference_in_namespace(node, ResolutionNamespace::TypeOrValue);
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

    fn finish_method_invocation(&mut self, node: Node<'_>) {
        let Some(name) = node.child_by_field_name("name") else {
            self.lower_unsupported_expression(node);
            return;
        };
        let call = self.add_site(node, ResolutionSiteKind::Call);
        let receiver = node.child_by_field_name("object").map(|object| {
            let input = self.expression_slot(object);
            let output = self.add_slot(call, ResolutionTypeSlotRole::Receiver);
            self.add_transfer(input, output, ResolutionTypeTransferKind::Receiver);
            output
        });
        let callee = self.add_identifier_site(
            name,
            if receiver.is_some() {
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
                origin: callable_receiver_origin(node),
            });
        self.add_gap(callee, ResolutionGapKind::UnsupportedCallApplicability);
        let result = self.add_slot(call, ResolutionTypeSlotRole::CallResult);
        self.facts.binding_projections.push(BindingProjectionFact {
            reference: callee,
            output: result,
            kind: BindingProjectionKind::TargetCallableResultType,
        });
        self.facts.calls.push(ResolutionCallFact {
            call,
            callee,
            receiver,
            result,
            explicit_type_argument_count: explicit_type_argument_count(node),
        });
        self.facts
            .engine_rule_eligibilities
            .push(ResolutionEngineRuleEligibilityFact {
                call,
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
        let reference = self.add_site(field, ResolutionSiteKind::MemberReference);
        let qualifier = node.child_by_field_name("object").map(|object| {
            let input = self.expression_slot(object);
            let output = self.add_slot(reference, ResolutionTypeSlotRole::Receiver);
            self.add_transfer(input, output, ResolutionTypeTransferKind::Receiver);
            output
        });
        self.add_identifier_to_site(
            reference,
            field,
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::TypeOrValue,
            qualifier,
        );
        let output = self.add_slot(reference, ResolutionTypeSlotRole::ExpressionValue);
        self.facts.binding_projections.push(BindingProjectionFact {
            reference,
            output,
            kind: BindingProjectionKind::TargetTypeOrDeclaredValueType,
        });
        self.expression_slots_by_node.insert(node.id(), output);
    }

    fn finish_object_creation(&mut self, node: Node<'_>) {
        let Some(type_node) = node.child_by_field_name("type") else {
            self.lower_unsupported_expression(node);
            return;
        };
        let call = self.add_site(node, ResolutionSiteKind::Call);
        let receiver = self
            .object_creation_enclosing_expression(node, type_node)
            .map(|enclosing| {
                let input = self.expression_slot(enclosing);
                let output = self.add_slot(call, ResolutionTypeSlotRole::Receiver);
                self.add_transfer(input, output, ResolutionTypeTransferKind::Receiver);
                output
            });
        let constructed_type = self.lower_type(type_node);
        let Some(name) = self.type_terminal_name(type_node) else {
            let callee = self.add_site(type_node, ResolutionSiteKind::UnsupportedExpression);
            self.add_gap(callee, ResolutionGapKind::UnsupportedTypeSyntax);
            let result = self.add_slot(call, ResolutionTypeSlotRole::CallResult);
            self.facts.calls.push(ResolutionCallFact {
                call,
                callee,
                receiver,
                result,
                explicit_type_argument_count: explicit_type_argument_count(node),
            });
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
        self.facts.binding_projections.push(BindingProjectionFact {
            reference: callee,
            output: result,
            kind: BindingProjectionKind::TargetConstructorOwnerType,
        });
        self.facts.calls.push(ResolutionCallFact {
            call,
            callee,
            receiver,
            result,
            explicit_type_argument_count: explicit_type_argument_count(node),
        });
        self.facts
            .engine_rule_eligibilities
            .push(ResolutionEngineRuleEligibilityFact {
                call,
                rule: ResolutionEngineRuleKind::DefaultConstruction,
            });
        self.attach_call_arguments(node, call);
        self.expression_slots_by_node.insert(node.id(), result);
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

    fn object_creation_enclosing_expression<'tree>(
        &self,
        node: Node<'tree>,
        type_node: Node<'tree>,
    ) -> Option<Node<'tree>> {
        let arguments = node
            .child_by_field_name("arguments")
            .map(|child| child.id());
        let type_arguments = node
            .child_by_field_name("type_arguments")
            .map(|child| child.id());
        let mut candidates = named_children(node).into_iter().filter(|child| {
            child.end_byte() <= type_node.start_byte()
                && Some(child.id()) != arguments
                && Some(child.id()) != type_arguments
                && !matches!(child.kind(), "annotation" | "marker_annotation")
        });
        let enclosing = candidates.next();
        assert!(
            candidates.next().is_none(),
            "Java object creation has at most one leading primary expression"
        );
        enclosing
    }

    fn lower_literal(&mut self, node: Node<'_>, spelling: &str, kind: IntrinsicTypeKind) {
        let site = self.add_site(node, ResolutionSiteKind::Literal);
        let output = self.add_slot(site, ResolutionTypeSlotRole::ExpressionValue);
        let name = self.intern_name(spelling);
        self.facts.intrinsic_type_seeds.push(IntrinsicTypeSeedFact {
            output,
            name,
            kind,
            indirection: 0,
        });
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
        let site = self.add_site(node, ResolutionSiteKind::UnsupportedExpression);
        let output = self.add_slot(site, ResolutionTypeSlotRole::ExpressionValue);
        self.add_gap(site, kind);
        self.add_reference_enumeration_gap_if_omitted(node, site, kind);
        self.gapped_semantic_subtrees.insert(node.id());
        self.expression_slots_by_node.insert(node.id(), output);
    }

    fn expression_slot(&self, node: Node<'_>) -> ResolutionTypeSlotId {
        *self
            .expression_slots_by_node
            .get(&node.id())
            .expect("expression dependency was lowered before its consumer")
    }

    fn slot(&self, id: ResolutionTypeSlotId) -> &ResolutionTypeSlotFact {
        &self.facts.type_slots[id.get() as usize]
    }

    fn push_call_dependencies<'tree>(
        &self,
        node: Node<'tree>,
        stack: &mut Vec<(Node<'tree>, bool)>,
    ) {
        self.push_argument_dependencies(node, stack);
        if let Some(object) = node.child_by_field_name("object") {
            stack.push((object, false));
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
        let values = arguments.named_children(&mut cursor).collect::<Vec<_>>();
        stack.extend(values.into_iter().rev().map(|value| (value, false)));
    }

    fn attach_call_arguments(&mut self, node: Node<'_>, call: ResolutionSiteId) {
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        let mut cursor = arguments.walk();
        for (ordinal, argument) in arguments.named_children(&mut cursor).enumerate() {
            let input = self.expression_slot(argument);
            let value = self.add_slot(call, ResolutionTypeSlotRole::Argument);
            self.add_transfer(input, value, ResolutionTypeTransferKind::Argument);
            self.facts.call_arguments.push(ResolutionCallArgumentFact {
                call,
                ordinal: dense_ordinal(ordinal, "call argument"),
                value,
            });
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
        let gap = ResolutionGapFact { site, kind };
        if !self.facts.gaps.contains(&gap) {
            self.facts.gaps.push(gap);
        }
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
            if matches!(
                node.kind(),
                "identifier" | "type_identifier" | "this" | "super"
            ) && !self.claimed_identifier_nodes.contains(&node.id())
            {
                return true;
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        false
    }

    fn add_reference_enumeration_gap(&mut self, site: ResolutionSiteId, kind: ResolutionGapKind) {
        let gap = ResolutionReferenceEnumerationGapFact { site, kind };
        if !self.facts.reference_enumeration_gaps.contains(&gap) {
            self.facts.reference_enumeration_gaps.push(gap);
        }
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
        assert!(
            self.source_type_shapes.insert(node.id(), shape).is_none(),
            "one Java native type-shape handoff per declaration node"
        );
    }

    pub(super) fn source_type_shape_for(&self, node: Node<'_>) -> JavaTypeShape {
        *self
            .source_type_shapes
            .get(&node.id())
            .expect("Java native type-shape use must follow source capture")
    }

    pub(super) fn set_source_field_shape(&mut self, node: Node<'_>, shape: JavaFieldShape) {
        assert!(
            self.source_field_shapes.insert(node.id(), shape).is_none(),
            "one Java native field-shape handoff per declaration node"
        );
    }

    pub(super) fn source_field_shape_for(&self, node: Node<'_>) -> JavaFieldShape {
        *self
            .source_field_shapes
            .get(&node.id())
            .expect("Java native field-shape use must follow source capture")
    }

    pub(super) fn set_source_callable_shape(&mut self, node: Node<'_>, shape: JavaCallableShape) {
        assert!(
            self.source_callable_shapes
                .insert(node.id(), shape)
                .is_none(),
            "one Java native callable-shape handoff per declaration node"
        );
    }

    pub(super) fn source_callable_shape_for(&self, node: Node<'_>) -> &JavaCallableShape {
        self.source_callable_shapes
            .get(&node.id())
            .expect("Java native callable-shape use must follow source capture")
    }

    fn source_callable_shape_for_node(&self, node_id: usize) -> &JavaCallableShape {
        self.source_callable_shapes
            .get(&node_id)
            .expect("Java native parameter use must follow callable source capture")
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

    fn is_unsupported_semantic_subtree(&self, node: Node<'_>) -> bool {
        matches!(
            node.kind(),
            "annotation"
                | "marker_annotation"
                | "throws"
                | "permits"
                | "module_declaration"
                | "lambda_expression"
                | "catch_clause"
                | "catch_formal_parameter"
                | "resource"
                | "enhanced_for_statement"
                | "for_statement"
                | "type_parameter"
                | "enum_constant"
                | "record_pattern"
                | "type_pattern"
                | "receiver_parameter"
        ) || (node.kind() == "object_creation_expression"
            && self.has_direct_named_child(node, "class_body"))
    }

    fn has_direct_named_child(&self, node: Node<'_>, kind: &str) -> bool {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .any(|child| child.kind() == kind)
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
            "class_body"
                | "interface_body"
                | "enum_body"
                | "annotation_type_body"
                | "record_body"
                | "block"
                | "constructor_body"
        )
    }

    fn record_persisted_type_identifier(&mut self, node: Node<'_>) {
        let text = node_text(node, self.source).trim();
        if !text.is_empty()
            && (matches!(node.kind(), "type_identifier" | "scoped_type_identifier")
                || (node.kind() == "identifier"
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

fn callable_receiver_origin(node: Node<'_>) -> ResolutionCallableReceiverOrigin {
    let Some(object) = node.child_by_field_name("object") else {
        return ResolutionCallableReceiverOrigin::Implicit;
    };
    match object.kind() {
        "this" => ResolutionCallableReceiverOrigin::CurrentInstance,
        "super" => ResolutionCallableReceiverOrigin::Super,
        _ => {
            // The grammar represents `Outer.super.method()` with `Outer` as
            // the object field and a second, direct `super` child. It is still
            // a superclass dispatch rather than an ordinary explicit value.
            let mut cursor = node.walk();
            if node
                .named_children(&mut cursor)
                .any(|child| child.kind() == "super")
            {
                ResolutionCallableReceiverOrigin::Super
            } else {
                ResolutionCallableReceiverOrigin::ExplicitExpression
            }
        }
    }
}

fn dense_ordinal(index: usize, relation: &str) -> u32 {
    u32::try_from(index).unwrap_or_else(|_| panic!("{relation} count exceeds u32"))
}

fn explicit_type_argument_count(node: Node<'_>) -> u32 {
    node.child_by_field_name("type_arguments")
        .map_or(0, |arguments| {
            dense_ordinal(
                named_children(arguments).len(),
                "Java explicit invocation type argument",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::ProjectFile;
    use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
    use tree_sitter::Parser;

    fn parse_file(source: &str) -> ParsedFile {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .expect("java grammar");
        let tree = parser.parse(source, None).expect("java tree");
        let root = std::env::current_dir()
            .expect("current directory")
            .join("java-resolution-fixture-root");
        let file = ProjectFile::new(root, "src/Fixture.java");
        super::super::declarations::parse_java_file(&file, source, &tree)
    }

    fn parse_once(source: &str) -> FileResolutionFacts {
        parse_file(source)
            .native_source
            .expect("Java native packet")
            .into_parts()
            .0
    }

    fn parse(source: &str) -> FileResolutionFacts {
        let facts = parse_once(source);
        assert_eq!(facts, parse_once(source), "fact rows must be deterministic");
        facts
    }

    #[test]
    fn file_has_one_compilation_unit_placement_boundary() {
        let facts = parse("class A {}");
        let placement = facts
            .gaps
            .iter()
            .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedPlacementBoundary)
            .collect::<Vec<_>>();
        assert_eq!(placement.len(), 1);
        let site = site(&facts, placement[0].site);
        assert_eq!(
            facts.scopes[site.scope.index()].kind,
            ResolutionScopeKind::CompilationUnit
        );
        assert_eq!(facts.packages.len(), 1);
        assert_eq!(facts.packages[0].root_scope, site.scope);
        assert_eq!(facts.packages[0].declaration, None);
        assert_eq!(facts.packages[0].placement_gap_site, site.id);
        assert!(facts.package_segments.is_empty());
    }

    fn name(facts: &FileResolutionFacts, id: ResolutionNameId) -> &str {
        &facts.names[id.get() as usize].spelling
    }

    fn identifier<'a>(
        facts: &'a FileResolutionFacts,
        spelling: &str,
        role: ResolutionIdentifierRole,
        namespace: ResolutionNamespace,
    ) -> &'a PositionedIdentifierFact {
        let mut matches = facts.identifiers.iter().filter(|identifier| {
            name(facts, identifier.name) == spelling
                && identifier.role == role
                && identifier.namespace == namespace
        });
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
        facts.sites[id.get() as usize]
    }

    fn slot(facts: &FileResolutionFacts, id: ResolutionTypeSlotId) -> ResolutionTypeSlotFact {
        facts.type_slots[id.get() as usize]
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
            .copied()
            .filter(|gap| gap.kind != ResolutionGapKind::UnsupportedVisibility)
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

    #[test]
    fn reference_owners_separate_declaration_containment_from_lookup_scope() {
        let facts = parse(
            r#"
                class Base {}
                class Child extends Base {
                    Base field;
                    Base method(Base parameter) {
                        return field;
                    }
                }
            "#,
        );
        let owners = facts
            .reference_owners
            .iter()
            .map(|fact| {
                let reference = identifier_for_site(&facts, fact.reference);
                let owner = fact
                    .owner
                    .map(|owner| name(&facts, identifier_for_site(&facts, owner).name));
                (name(&facts, reference.name), owner)
            })
            .collect::<Vec<_>>();
        assert_eq!(owners.len(), 5);
        assert_eq!(
            owners
                .iter()
                .filter(|&&(reference, owner)| reference == "Base" && owner == Some("Child"))
                .count(),
            1,
            "the supertype occurrence belongs to its subtype declaration"
        );
        assert_eq!(
            owners
                .iter()
                .filter(|&&(reference, owner)| reference == "Base" && owner == Some("field"))
                .count(),
            1,
            "the field type occurrence belongs to the analyzer-owned field declaration without changing its lookup scope"
        );
        assert_eq!(
            owners
                .iter()
                .filter(|&&(reference, owner)| reference == "Base" && owner == Some("method"))
                .count(),
            2,
            "return and parameter type references belong to the callable header"
        );
        assert_eq!(
            owners
                .iter()
                .filter(|&&(reference, owner)| reference == "field" && owner == Some("method"))
                .count(),
            1,
            "body references belong to the executable declaration"
        );
        let supertype = facts
            .supertypes
            .iter()
            .find(|supertype| {
                name(
                    &facts,
                    identifier_for_site(&facts, supertype.supertype_reference).name,
                ) == "Base"
            })
            .expect("Child must retain its explicit Base supertype");
        assert_eq!(
            facts
                .reference_owners
                .iter()
                .find(|owner| owner.reference == supertype.supertype_reference)
                .expect("supertype reference must have an explicit source owner")
                .owner,
            Some(supertype.subtype)
        );
    }

    #[test]
    fn field_type_and_initializer_references_belong_to_the_field_declaration() {
        let facts = parse(
            r#"
                class Dependency {
                    static Dependency create() { return null; }
                }
                class Owner {
                    Dependency field = Dependency.create();
                    void method() {
                        Dependency local = Dependency.create();
                    }
                }
            "#,
        );
        let declaration_site = |spelling: &str, kind: ResolutionSiteKind| {
            facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Declaration
                        && name(&facts, identifier.name) == spelling
                        && site(&facts, identifier.site).kind == kind
                })
                .unwrap_or_else(|| panic!("missing {kind:?} declaration {spelling:?}"))
                .site
        };
        let field = declaration_site("field", ResolutionSiteKind::ValueDeclaration);
        let method = declaration_site("method", ResolutionSiteKind::CallableDeclaration);
        assert!(
            facts.member_owners.iter().any(|owner| {
                owner.member == field && owner.kind == ResolutionMemberKind::Field
            })
        );

        let owned_references = |owner| {
            facts
                .reference_owners
                .iter()
                .filter(|reference_owner| reference_owner.owner == Some(owner))
                .map(|reference_owner| {
                    let identifier = identifier_for_site(&facts, reference_owner.reference);
                    (
                        site(&facts, reference_owner.reference).kind,
                        identifier.namespace,
                        name(&facts, identifier.name),
                    )
                })
                .collect::<Vec<_>>()
        };
        let field_references = owned_references(field);
        assert!(
            field_references.iter().any(|&(kind, namespace, spelling)| {
                kind == ResolutionSiteKind::TypeReference
                    && namespace == ResolutionNamespace::Type
                    && spelling == "Dependency"
            }),
            "the declared field type must be field-owned: {field_references:?}"
        );
        assert!(
            field_references.iter().any(|&(kind, namespace, spelling)| {
                kind == ResolutionSiteKind::MemberReference
                    && namespace == ResolutionNamespace::Callable
                    && spelling == "create"
            }),
            "the field initializer call must be field-owned: {field_references:?}"
        );

        let method_references = owned_references(method);
        assert!(
            method_references
                .iter()
                .any(|&(kind, namespace, spelling)| {
                    kind == ResolutionSiteKind::TypeReference
                        && namespace == ResolutionNamespace::Type
                        && spelling == "Dependency"
                }),
            "a local declaration type must remain callable-owned: {method_references:?}"
        );
        assert!(
            method_references
                .iter()
                .any(|&(kind, namespace, spelling)| {
                    kind == ResolutionSiteKind::MemberReference
                        && namespace == ResolutionNamespace::Callable
                        && spelling == "create"
                }),
            "a local initializer call must remain callable-owned: {method_references:?}"
        );
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

        assert_eq!(facts.declaration_visibilities.len(), 31);
        assert_eq!(facts.visibility_eligibilities.len(), 31);
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
            .filter(|fact| fact.visibility != DeclaredVisibility::Public)
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
        for unsupported in ["ENUM_CONSTANT", "recordComponentOnly"] {
            assert!(facts.declaration_visibilities.iter().all(|fact| {
                name(&facts, identifier_for_site(&facts, fact.declaration).name) != unsupported
            }));
        }
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
            facts.member_owners,
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
        assert_eq!(facts.supertypes.len(), 2);
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
                ResolutionGapFact {
                    site: qualifier_site,
                    kind: ResolutionGapKind::AmbiguousQualifiedType,
                },
                ResolutionGapFact {
                    site: foo_reference.site,
                    kind: ResolutionGapKind::AmbiguousQualifiedType,
                },
                ResolutionGapFact {
                    site: foo_reference.site,
                    kind: ResolutionGapKind::UnsupportedHierarchyTraversal,
                },
                ResolutionGapFact {
                    site: interface.supertype_reference,
                    kind: ResolutionGapKind::UnsupportedHierarchyTraversal,
                },
                ResolutionGapFact {
                    site: a,
                    kind: ResolutionGapKind::ImplicitConstructor,
                },
                ResolutionGapFact {
                    site: foo,
                    kind: ResolutionGapKind::UnsupportedHierarchyTraversal,
                },
                ResolutionGapFact {
                    site: foo,
                    kind: ResolutionGapKind::ImplicitConstructor,
                },
                ResolutionGapFact {
                    site: b,
                    kind: ResolutionGapKind::UnsupportedHierarchyTraversal,
                },
                ResolutionGapFact {
                    site: facts.gaps.last().expect("placement gap").site,
                    kind: ResolutionGapKind::UnsupportedPlacementBoundary,
                },
            ]
        );
        assert_eq!(visibility_gap_sites(&facts), vec![a, b]);
    }

    #[test]
    fn typed_local_call_rows_cover_activation_receiver_argument_and_result() {
        // IntelliJ Community psi/resolve method/Simple.
        let source = "class Simple { void method(String s) {} static { Simple a = new Simple(); a.method(\"blah\"); } }";
        let facts = parse(source);

        let method = identifier(
            &facts,
            "method",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Callable,
        )
        .site;
        let parameter = identifier(
            &facts,
            "s",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
        )
        .site;
        let local = identifier(
            &facts,
            "a",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
        )
        .site;
        assert_eq!(
            facts.callable_parameters,
            vec![ResolutionCallableParameterFact {
                callable: method,
                ordinal: 0,
                parameter,
                value_type: facts
                    .declaration_type_slots
                    .iter()
                    .find(|row| row.declaration == parameter)
                    .expect("parameter type")
                    .slot,
                repeated: false,
            }]
        );
        assert_eq!(
            facts
                .callable_signatures
                .iter()
                .find(|signature| signature.callable == method)
                .expect("method signature header")
                .type_parameter_count,
            0
        );
        let local_binder = facts
            .binders
            .iter()
            .find(|binder| binder.declaration == local)
            .expect("local binder");
        assert_eq!(local_binder.kind, ResolutionBinderKind::Local);
        assert_eq!(local_binder.hoisting, HoistingClass::SourceOrder);
        assert!(local_binder.activation_start > site(&facts, local).end_byte);

        let declared_local = facts
            .declaration_type_slots
            .iter()
            .find(|row| row.declaration == local)
            .expect("local declared type")
            .slot;
        assert_eq!(
            slot(&facts, declared_local).role,
            ResolutionTypeSlotRole::DeclaredValue
        );
        let assignment = facts
            .type_transfers
            .iter()
            .find(|transfer| {
                transfer.kind == ResolutionTypeTransferKind::Assignment
                    && slot(&facts, transfer.output).site == local
            })
            .expect("local initializer observation");
        assert_eq!(
            slot(&facts, assignment.output).role,
            ResolutionTypeSlotRole::AssignmentValue
        );
        assert_ne!(assignment.output, declared_local);
        assert!(facts.type_transfers.iter().all(|transfer| {
            transfer.kind != ResolutionTypeTransferKind::Assignment
                || transfer.output != declared_local
        }));

        let constructor_reference = identifier(
            &facts,
            "Simple",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Constructor,
        );
        assert_eq!(
            site(&facts, constructor_reference.site).kind,
            ResolutionSiteKind::ConstructorReference
        );
        let constructed_type = constructor_reference
            .qualifier
            .expect("constructor owner type slot");
        assert_eq!(
            name(
                &facts,
                identifier_for_site(&facts, slot(&facts, constructed_type).site).name,
            ),
            "Simple"
        );
        let constructor_call = facts
            .calls
            .iter()
            .find(|call| call.callee == constructor_reference.site)
            .expect("constructor call");
        assert!(
            facts
                .engine_rule_eligibilities
                .contains(&ResolutionEngineRuleEligibilityFact {
                    call: constructor_call.call,
                    rule: ResolutionEngineRuleKind::DefaultConstruction,
                })
        );
        assert!(facts.binding_projections.contains(&BindingProjectionFact {
            reference: constructor_reference.site,
            output: constructor_call.result,
            kind: BindingProjectionKind::TargetConstructorOwnerType,
        }));
        assert!(facts.type_transfers.iter().all(|transfer| {
            transfer.kind != ResolutionTypeTransferKind::Construction
                || transfer.output != constructor_call.result
        }));

        let method_reference = identifier(
            &facts,
            "method",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Callable,
        );
        let receiver = method_reference.qualifier.expect("typed receiver");
        let receiver_input = facts
            .type_transfers
            .iter()
            .find(|transfer| {
                transfer.output == receiver && transfer.kind == ResolutionTypeTransferKind::Receiver
            })
            .expect("receiver transfer")
            .input;
        assert_eq!(
            name(
                &facts,
                identifier_for_site(&facts, slot(&facts, receiver_input).site).name,
            ),
            "a"
        );

        let call = facts
            .calls
            .iter()
            .find(|call| call.callee == method_reference.site)
            .expect("method call");
        assert_eq!(call.receiver, Some(receiver));
        assert_eq!(call.explicit_type_argument_count, 0);
        assert!(
            facts
                .engine_rule_eligibilities
                .contains(&ResolutionEngineRuleEligibilityFact {
                    call: call.call,
                    rule: ResolutionEngineRuleKind::DirectOwnerExactPrimitiveDominance,
                })
        );
        assert_eq!(facts.call_arguments.len(), 1);
        assert_eq!(facts.call_arguments[0].call, call.call);
        assert!(facts.intrinsic_type_seeds.iter().any(|seed| {
            name(&facts, seed.name) == "java.lang.String"
                && seed.kind == IntrinsicTypeKind::LanguageBuiltin
        }));
        assert!(facts.binding_projections.iter().any(|projection| {
            projection.reference == method_reference.site
                && projection.output == call.result
                && projection.kind == BindingProjectionKind::TargetCallableResultType
        }));
        let simple = identifier(
            &facts,
            "Simple",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        )
        .site;
        assert_eq!(
            non_visibility_gaps(&facts),
            vec![
                ResolutionGapFact {
                    site: constructor_reference.site,
                    kind: ResolutionGapKind::UnsupportedCallApplicability,
                },
                ResolutionGapFact {
                    site: slot(&facts, receiver_input).site,
                    kind: ResolutionGapKind::UnsupportedImplicitReceiver,
                },
                ResolutionGapFact {
                    site: method_reference.site,
                    kind: ResolutionGapKind::UnsupportedCallApplicability,
                },
                ResolutionGapFact {
                    site: simple,
                    kind: ResolutionGapKind::UnsupportedHierarchyTraversal,
                },
                ResolutionGapFact {
                    site: simple,
                    kind: ResolutionGapKind::ImplicitConstructor,
                },
                ResolutionGapFact {
                    site: facts.gaps.last().expect("placement gap").site,
                    kind: ResolutionGapKind::UnsupportedPlacementBoundary,
                },
            ]
        );
        assert_eq!(visibility_gap_sites(&facts), vec![simple, method]);
        assert_eq!(
            site(&facts, simple).kind,
            ResolutionSiteKind::TypeDeclaration
        );
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
                    && identifier.namespace == ResolutionNamespace::TypeOrValue
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
    fn void_declared_return_is_a_complete_no_value_transfer() {
        let source = "abstract class C { abstract void f(); void g() { f(); } }";
        let facts = parse(source);
        let declaration = identifier(
            &facts,
            "f",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Callable,
        )
        .site;
        let declared_slot = facts
            .declaration_type_slots
            .iter()
            .find(|row| row.declaration == declaration && row.role == DeclarationTypeRole::Return)
            .expect("f declared return slot")
            .slot;
        let transfer = facts
            .type_transfers
            .iter()
            .find(|transfer| {
                transfer.output == declared_slot
                    && transfer.kind == ResolutionTypeTransferKind::DeclaredType
            })
            .expect("void declared-type transfer");
        assert_eq!(
            transfer.value_transform,
            ResolutionTypeTransferValueTransform::ToNoValue
        );
        assert_eq!(transfer.indirection_delta, 0);

        let call = identifier(
            &facts,
            "f",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Callable,
        );
        assert!(facts.binding_projections.iter().any(|projection| {
            projection.reference == call.site
                && projection.kind == BindingProjectionKind::TargetCallableResultType
                && slot(&facts, projection.output).role == ResolutionTypeSlotRole::CallResult
        }));
    }

    #[test]
    fn qualified_field_rows_retain_owner_and_receiver_projection() {
        // IntelliJ Community psi/resolve variable/Qualified1, reduced to its
        // exact typed receiver and field access.
        let source = "class Box { int value; int read(Box b) { return b.value; } }";
        let facts = parse(source);

        let box_declaration = identifier(
            &facts,
            "Box",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        )
        .site;
        let field_declaration = identifier(
            &facts,
            "value",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
        )
        .site;
        let read_declaration = identifier(
            &facts,
            "read",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Callable,
        )
        .site;
        assert!(facts.member_owners.contains(&ResolutionMemberOwnerFact {
            member: field_declaration,
            owner: box_declaration,
            kind: ResolutionMemberKind::Field,
            access: ResolutionMemberAccess::Instance,
            qualifier_compatibility: ResolutionMemberQualifierCompatibility::RuntimeOnly,
        }));

        let field_reference = identifier(
            &facts,
            "value",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::TypeOrValue,
        );
        let receiver = field_reference.qualifier.expect("field receiver");
        let receiver_input = facts
            .type_transfers
            .iter()
            .find(|transfer| transfer.output == receiver)
            .expect("receiver transfer")
            .input;
        assert_eq!(
            name(
                &facts,
                identifier_for_site(&facts, slot(&facts, receiver_input).site).name,
            ),
            "b"
        );
        assert!(facts.binding_projections.iter().any(|projection| {
            projection.reference == field_reference.site
                && projection.kind == BindingProjectionKind::TargetTypeOrDeclaredValueType
        }));
        assert_eq!(
            non_visibility_gaps(&facts),
            vec![
                ResolutionGapFact {
                    site: box_declaration,
                    kind: ResolutionGapKind::UnsupportedHierarchyTraversal,
                },
                ResolutionGapFact {
                    site: box_declaration,
                    kind: ResolutionGapKind::ImplicitConstructor,
                },
                ResolutionGapFact {
                    site: facts.gaps.last().expect("placement gap").site,
                    kind: ResolutionGapKind::UnsupportedPlacementBoundary,
                },
            ]
        );
        assert_eq!(
            visibility_gap_sites(&facts),
            vec![box_declaration, field_declaration, read_declaration]
        );
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
                true,
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
                if qualified {
                    ResolutionSiteKind::MemberReference
                } else {
                    ResolutionSiteKind::CallableReference
                },
                "receiver-origin metadata must not change lexical lookup shape"
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
        assert_eq!(
            facts
                .gaps
                .iter()
                .filter(|gap| gap.kind == ResolutionGapKind::ImplicitConstructor)
                .count(),
            3
        );
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
            assert_eq!(outer_reference.namespace, ResolutionNamespace::TypeOrValue);

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
        let object = identifier(
            &facts,
            "Object",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Type,
        );

        assert!(facts.gaps.contains(&ResolutionGapFact {
            site: implicit,
            kind: ResolutionGapKind::UnsupportedHierarchyTraversal,
        }));
        assert!(!facts.gaps.contains(&ResolutionGapFact {
            site: explicit,
            kind: ResolutionGapKind::UnsupportedHierarchyTraversal,
        }));
        assert_eq!(facts.supertypes.len(), 1);
        let explicit_root = facts.supertypes[0];
        assert_eq!(explicit_root.subtype, explicit);
        assert_eq!(explicit_root.supertype_reference, object.site);
        assert_eq!(slot(&facts, explicit_root.supertype_slot).site, object.site);
        assert_eq!(explicit_root.kind, ResolutionSupertypeKind::Superclass);
        assert_eq!(object.qualifier, None);
        assert!(facts.gaps.contains(&ResolutionGapFact {
            site: object.site,
            kind: ResolutionGapKind::UnsupportedHierarchyTraversal,
        }));
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
        assert!(facts.gaps.contains(&ResolutionGapFact {
            site: declaration,
            kind: ResolutionGapKind::UnsupportedHierarchyTraversal,
        }));
    }

    #[test]
    fn generic_supertype_keeps_base_reference_owner_while_gapping_arguments() {
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
        let base = identifier(
            &facts,
            "Box",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Type,
        );
        let supertype = facts
            .supertypes
            .iter()
            .find(|fact| fact.subtype == deep)
            .expect("generic superclass must retain one hierarchy row");
        assert_eq!(supertype.supertype_reference, base.site);
        assert_eq!(
            facts
                .reference_owners
                .iter()
                .find(|owner| owner.reference == base.site)
                .expect("generic base reference must have an owner")
                .owner,
            Some(deep)
        );
        assert!(facts.gaps.iter().any(|gap| {
            gap.kind == ResolutionGapKind::UnsupportedTypeSyntax
                && site(&facts, gap.site).kind == ResolutionSiteKind::UnsupportedExpression
        }));
    }

    #[test]
    fn only_directly_instantiable_classes_publish_default_construction_proof_markers() {
        let overloaded = parse("record R(int x) { R() { this(0); } }");
        let r = identifier(
            &overloaded,
            "R",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        )
        .site;
        assert!(!overloaded.gaps.contains(&ResolutionGapFact {
            site: r,
            kind: ResolutionGapKind::ImplicitConstructor,
        }));

        let compact = parse("record C(int x) { C { } }");
        let c = identifier(
            &compact,
            "C",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        )
        .site;
        assert!(!compact.gaps.contains(&ResolutionGapFact {
            site: c,
            kind: ResolutionGapKind::ImplicitConstructor,
        }));
        let compact_constructor = identifier(
            &compact,
            "C",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Constructor,
        )
        .site;
        assert!(compact.gaps.contains(&ResolutionGapFact {
            site: compact_constructor,
            kind: ResolutionGapKind::UnsupportedCallApplicability,
        }));
        assert!(
            compact
                .callable_parameters
                .iter()
                .all(|parameter| parameter.callable != compact_constructor),
            "implicit record-component parameters are not fabricated"
        );

        let abstract_class = parse("public abstract class AbstractWorker {}");
        let abstract_worker = identifier(
            &abstract_class,
            "AbstractWorker",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        )
        .site;
        assert!(!abstract_class.gaps.contains(&ResolutionGapFact {
            site: abstract_worker,
            kind: ResolutionGapKind::ImplicitConstructor,
        }));

        let ordinary = parse("public class Worker {}");
        let worker = identifier(
            &ordinary,
            "Worker",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        )
        .site;
        assert!(ordinary.gaps.contains(&ResolutionGapFact {
            site: worker,
            kind: ResolutionGapKind::ImplicitConstructor,
        }));
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

        assert_eq!(facts.supertypes.len(), 4);
        let edge_names = facts
            .supertypes
            .iter()
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
            assert!(facts.gaps.contains(&ResolutionGapFact {
                site: row.supertype_reference,
                kind: ResolutionGapKind::UnsupportedHierarchyTraversal,
            }));
        }
        assert_eq!(
            facts
                .gaps
                .iter()
                .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedHierarchyTraversal)
                .count(),
            7
        );
        for implicit_root in [base, other, implementation] {
            assert!(facts.gaps.contains(&ResolutionGapFact {
                site: implicit_root,
                kind: ResolutionGapKind::UnsupportedHierarchyTraversal,
            }));
        }
        assert!(!facts.gaps.contains(&ResolutionGapFact {
            site: child,
            kind: ResolutionGapKind::UnsupportedHierarchyTraversal,
        }));
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
    fn unsupported_expression_is_an_explicit_local_gap() {
        let facts = parse("class A { int f(int a) { return -a; } }");
        let unsupported_expression = facts
            .gaps
            .iter()
            .find(|gap| gap.kind == ResolutionGapKind::UnsupportedExpression)
            .expect("unary expression gap");
        assert_eq!(
            site(&facts, unsupported_expression.site).kind,
            ResolutionSiteKind::UnsupportedExpression
        );
        assert_eq!(
            non_visibility_gaps(&facts)
                .iter()
                .map(|gap| gap.kind)
                .collect::<Vec<_>>(),
            vec![
                ResolutionGapKind::UnsupportedExpression,
                ResolutionGapKind::UnsupportedHierarchyTraversal,
                ResolutionGapKind::ImplicitConstructor,
                ResolutionGapKind::UnsupportedPlacementBoundary,
            ]
        );
        assert_eq!(visibility_gap_sites(&facts).len(), 2);
    }

    #[test]
    fn assignment_update_and_binary_expressions_preserve_structured_children() {
        let source = "class A { int id(int value) { return value; } int assign(int total, int value) { return total += id(value); } int update(int total) { return total++; } int binary(int left, int right) { return id(left) + id(right); } }";
        let facts = parse(source);

        let assignment_text = "total += id(value)";
        let assignment_start = source.find(assignment_text).expect("assignment source");
        let update_text = "total++";
        let update_start = source.find(update_text).expect("update source");
        let binary_text = "id(left) + id(right)";
        let binary_start = source.find(binary_text).expect("binary source");
        let reference_at = |start: usize| {
            facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Reference
                        && site(&facts, identifier.site).start_byte == start
                })
                .expect("positioned value reference")
        };
        let reference_slot = |reference: &PositionedIdentifierFact| {
            facts
                .type_slots
                .iter()
                .find(|slot| {
                    slot.site == reference.site
                        && slot.role == ResolutionTypeSlotRole::ExpressionValue
                })
                .expect("value-reference expression slot")
                .id
        };
        let observed_return_input = |callable: ResolutionSiteId| {
            facts
                .type_transfers
                .iter()
                .find(|transfer| {
                    transfer.kind == ResolutionTypeTransferKind::Return
                        && slot(&facts, transfer.output).site == callable
                })
                .expect("observed return transfer")
                .input
        };

        for (method, start) in [("assign", assignment_start), ("update", update_start)] {
            let reference = reference_at(start);
            assert_eq!(reference.namespace, ResolutionNamespace::Value);
            let output = reference_slot(reference);
            assert!(facts.binding_projections.contains(&BindingProjectionFact {
                reference: reference.site,
                output,
                kind: BindingProjectionKind::TargetDeclaredValueType,
            }));
            let callable = identifier(
                &facts,
                method,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Callable,
            );
            assert_eq!(observed_return_input(callable.site), output);
        }

        let binary_site = facts
            .sites
            .iter()
            .find(|site| {
                site.start_byte == binary_start
                    && site.end_byte == binary_start + binary_text.len()
                    && site.kind == ResolutionSiteKind::UnsupportedExpression
            })
            .expect("binary expression site");
        let binary_output = facts
            .type_slots
            .iter()
            .find(|slot| {
                slot.site == binary_site.id && slot.role == ResolutionTypeSlotRole::ExpressionValue
            })
            .expect("binary result frontier")
            .id;
        assert!(
            facts
                .type_transfers
                .iter()
                .all(|transfer| transfer.output != binary_output),
            "unknown Java operator typing must not publish a guessed result"
        );
        let binary_callable = identifier(
            &facts,
            "binary",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Callable,
        );
        assert_eq!(observed_return_input(binary_callable.site), binary_output);

        let calls_within = |start: usize, end: usize| {
            facts
                .calls
                .iter()
                .filter(|call| {
                    let call_site = site(&facts, call.call);
                    call_site.start_byte >= start && call_site.end_byte <= end
                })
                .count()
        };
        assert_eq!(
            calls_within(assignment_start, assignment_start + assignment_text.len()),
            1
        );
        assert_eq!(
            calls_within(binary_site.start_byte, binary_site.end_byte),
            2
        );
        assert_eq!(
            facts
                .identifiers
                .iter()
                .filter(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Reference
                        && identifier.namespace == ResolutionNamespace::Callable
                        && name(&facts, identifier.name) == "id"
                })
                .count(),
            3,
            "calls nested under assignment and binary expressions stay structured"
        );
        assert_eq!(
            facts
                .gaps
                .iter()
                .filter(|gap| gap.site == binary_site.id)
                .copied()
                .collect::<Vec<_>>(),
            vec![ResolutionGapFact {
                site: binary_site.id,
                kind: ResolutionGapKind::InferredType,
            }]
        );
        assert!(
            facts
                .gaps
                .iter()
                .all(|gap| gap.kind != ResolutionGapKind::UnsupportedExpression)
        );
    }

    #[test]
    fn package_and_import_routes_emit_only_connected_gaps() {
        let source = "package Foo.Bar; import com.acme.Outer.Inner; import static com.acme.Util.call; import com.wild.*; import static com.tools.Util.*; class A {}";
        let facts = parse(source);

        assert_eq!(identifier_spellings(&facts), vec!["A"]);
        assert!(
            facts
                .identifiers
                .iter()
                .all(|identifier| identifier.role == ResolutionIdentifierRole::Declaration)
        );
        assert_eq!(facts.packages.len(), 1);
        let package = facts.packages[0];
        assert_eq!(package.root_scope, ResolutionScopeId::new(0));
        let package_declaration = package.declaration.expect("named package declaration");
        let package_site = site(&facts, package_declaration);
        assert_eq!(package_site.kind, ResolutionSiteKind::PackageDeclaration);
        assert_eq!(
            &source[package_site.start_byte..package_site.end_byte],
            "package Foo.Bar;"
        );
        assert_eq!(
            facts
                .package_segments
                .iter()
                .map(|segment| (segment.ordinal, name(&facts, segment.name)))
                .collect::<Vec<_>>(),
            vec![(0, "Foo"), (1, "Bar")]
        );
        assert!(!facts.gaps.contains(&ResolutionGapFact {
            site: package_declaration,
            kind: ResolutionGapKind::UnsupportedRoute,
        }));

        assert_eq!(facts.import_routes.len(), 4);
        assert!(
            facts
                .import_routes
                .iter()
                .all(|route| route.root_scope == ResolutionScopeId::new(0))
        );
        assert_eq!(
            facts
                .import_routes
                .iter()
                .map(|route| (
                    route.kind,
                    route.bound_name.map(|name_id| name(&facts, name_id)),
                    facts
                        .import_route_segments
                        .iter()
                        .filter(|segment| segment.import_site == route.site)
                        .map(|segment| name(&facts, segment.name))
                        .collect::<Vec<_>>(),
                ))
                .collect::<Vec<_>>(),
            vec![
                (
                    ResolutionImportRouteKind::SingleType,
                    Some("Inner"),
                    vec!["com", "acme", "Outer", "Inner"],
                ),
                (
                    ResolutionImportRouteKind::SingleStatic,
                    Some("call"),
                    vec!["com", "acme", "Util", "call"],
                ),
                (
                    ResolutionImportRouteKind::TypeOnDemand,
                    None,
                    vec!["com", "wild"],
                ),
                (
                    ResolutionImportRouteKind::StaticOnDemand,
                    None,
                    vec!["com", "tools", "Util"],
                ),
            ]
        );
        assert!(facts.import_routes.iter().all(|route| {
            site(&facts, route.site).kind == ResolutionSiteKind::ImportDeclaration
                && facts.gaps.contains(&ResolutionGapFact {
                    site: route.site,
                    kind: ResolutionGapKind::UnsupportedRoute,
                })
        }));
        assert!(
            facts
                .sites
                .iter()
                .filter(|site| site.kind == ResolutionSiteKind::ImportDeclaration)
                .all(|site| facts
                    .import_routes
                    .iter()
                    .any(|route| route.site == site.id))
        );

        assert_eq!(facts.gaps.len(), 8);
        assert!(facts.gaps.iter().take(4).all(|gap| {
            gap.kind == ResolutionGapKind::UnsupportedRoute
                && site(&facts, gap.site).kind == ResolutionSiteKind::ImportDeclaration
        }));
        assert_eq!(facts.gaps[4].kind, ResolutionGapKind::UnsupportedVisibility);
        assert_eq!(
            facts.gaps[5].kind,
            ResolutionGapKind::UnsupportedHierarchyTraversal
        );
        assert_eq!(facts.gaps[6].kind, ResolutionGapKind::ImplicitConstructor);
        assert_eq!(
            facts.gaps[7].kind,
            ResolutionGapKind::UnsupportedPlacementBoundary
        );
    }

    #[test]
    fn package_imports_and_top_level_types_emit_common_root_facts() {
        let source = "package p.q; import x.y.Target; import x.z.*; class Local { Target exact; Wild demanded; } class Second {}";
        let facts = parse(source);
        let root_scope = ResolutionScopeId::new(0);

        assert_eq!(
            facts
                .package_segments
                .iter()
                .map(|segment| (segment.ordinal, name(&facts, segment.name)))
                .collect::<Vec<_>>(),
            vec![(0, "p"), (1, "q")]
        );
        assert_eq!(facts.root_imports.len(), 2);
        let root_route = |site| {
            facts
                .root_import_segments
                .iter()
                .filter(|segment| segment.import_site == site)
                .map(|segment| (segment.position, name(&facts, segment.name)))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            root_route(facts.root_imports[0].site),
            vec![(0, "x"), (1, "y")]
        );
        assert_eq!(
            root_route(facts.root_imports[1].site),
            vec![(0, "x"), (1, "z")]
        );
        assert_eq!(
            facts
                .root_import_demands
                .iter()
                .map(|demand| {
                    (
                        demand.import_site,
                        demand.namespace,
                        name(&facts, demand.name),
                    )
                })
                .collect::<Vec<_>>(),
            vec![
                (
                    facts.root_imports[0].site,
                    ResolutionNamespace::Type,
                    "Target",
                ),
                (
                    facts.root_imports[1].site,
                    ResolutionNamespace::Type,
                    "Wild",
                ),
            ]
        );
        assert_eq!(
            facts
                .root_exports
                .iter()
                .map(|export| {
                    let declaration = facts
                        .identifiers
                        .iter()
                        .find(|identifier| identifier.site == export.declaration)
                        .expect("root export names a positioned declaration");
                    (
                        export.root_scope,
                        export.namespace,
                        name(&facts, declaration.name),
                    )
                })
                .collect::<Vec<_>>(),
            vec![
                (root_scope, ResolutionNamespace::Type, "Local"),
                (root_scope, ResolutionNamespace::Type, "Second"),
            ]
        );
        assert!(
            facts
                .root_imports
                .iter()
                .all(|import| import.root_scope == root_scope)
        );
    }

    #[test]
    fn directive_comments_and_malformed_package_annotation_preserve_exact_paths() {
        let source =
            "@Anno(value=) package p /* package */ . q; import p /* import */ . Target; class A {}";
        let parsed = parse_file(source);
        assert_eq!(
            parsed
                .native_source
                .as_ref()
                .expect("Java native packet")
                .resolution_facts(),
            &parse_once(source),
            "directive facts must remain deterministic"
        );
        assert_eq!(parsed.imports.len(), 1);
        assert_eq!(
            parsed.imports[0]
                .path
                .as_ref()
                .expect("structured import path")
                .segments,
            vec!["p", "Target"]
        );
        let facts = parsed
            .native_source
            .as_ref()
            .expect("Java native packet")
            .resolution_facts();

        assert_eq!(facts.packages.len(), 1);
        let package = facts.packages[0];
        assert_eq!(
            facts
                .package_segments
                .iter()
                .map(|segment| (segment.ordinal, name(facts, segment.name)))
                .collect::<Vec<_>>(),
            vec![(0, "p"), (1, "q")]
        );
        let package_declaration = package.declaration.expect("named package");
        assert!(!facts.gaps.contains(&ResolutionGapFact {
            site: package_declaration,
            kind: ResolutionGapKind::UnsupportedRoute,
        }));

        assert_eq!(facts.import_routes.len(), 1);
        let route = facts.import_routes[0];
        assert_eq!(
            name(facts, route.bound_name.expect("single-type bound name")),
            "Target"
        );
        assert_eq!(
            facts
                .import_route_segments
                .iter()
                .map(|segment| (segment.ordinal, name(facts, segment.name)))
                .collect::<Vec<_>>(),
            vec![(0, "p"), (1, "Target")]
        );

        let annotation = facts
            .sites
            .iter()
            .find(|site| {
                site.kind == ResolutionSiteKind::UnsupportedDeclaration
                    && &source[site.start_byte..site.end_byte] == "@Anno(value=)"
            })
            .expect("package annotation site");
        assert!(facts.gaps.contains(&ResolutionGapFact {
            site: annotation.id,
            kind: ResolutionGapKind::MalformedSyntax,
        }));
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
            facts.gaps.contains(&ResolutionGapFact {
                site: site.id,
                kind: ResolutionGapKind::UnsupportedRoute,
            })
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
            facts.gaps.contains(&ResolutionGapFact {
                site: site.id,
                kind: ResolutionGapKind::UnsupportedRoute,
            })
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
        assert!(leading.gaps.contains(&ResolutionGapFact {
            site: late_package.id,
            kind: ResolutionGapKind::UnsupportedRoute,
        }));

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
        assert!(between.gaps.contains(&ResolutionGapFact {
            site: late_import.id,
            kind: ResolutionGapKind::UnsupportedRoute,
        }));
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
        assert!(facts.gaps.contains(&ResolutionGapFact {
            site: imports[0].id,
            kind: ResolutionGapKind::UnsupportedRoute,
        }));
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
            .native_source
            .as_ref()
            .expect("Java native packet")
            .source_facts();
        assert_eq!(source_facts.imports.len(), 1);
        assert_eq!(source_facts.generic_imports.len(), 1);
        assert!(source_facts.imports[0].path.is_none());
        assert!(!source_facts.native_site_occurrences.is_empty());
        assert!(!source_facts.native_declaration_sources.is_empty());
        assert!(
            !parsed
                .native_source
                .as_ref()
                .expect("Java native packet")
                .source_facts()
                .source_declaration_units
                .is_empty()
        );
        let import_site = parsed
            .native_source
            .as_ref()
            .expect("Java native packet")
            .resolution_facts()
            .sites
            .iter()
            .find(|site| site.kind == ResolutionSiteKind::ImportDeclaration)
            .expect("late malformed import remains a native site");
        assert!(
            parsed
                .native_source
                .as_ref()
                .expect("Java native packet")
                .resolution_facts()
                .gaps
                .contains(&ResolutionGapFact {
                    site: import_site.id,
                    kind: ResolutionGapKind::UnsupportedRoute,
                })
        );
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
        assert!(facts.gaps.contains(&ResolutionGapFact {
            site: declarations[0].id,
            kind: ResolutionGapKind::UnsupportedRoute,
        }));
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
            ResolutionNamespace::TypeOrValue,
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
                ResolutionGapFact {
                    site: interface,
                    kind: ResolutionGapKind::UnsupportedHierarchyTraversal,
                },
                ResolutionGapFact {
                    site: enumeration,
                    kind: ResolutionGapKind::UnsupportedHierarchyTraversal,
                },
                ResolutionGapFact {
                    site: record,
                    kind: ResolutionGapKind::UnsupportedHierarchyTraversal,
                },
                ResolutionGapFact {
                    site: annotation,
                    kind: ResolutionGapKind::UnsupportedHierarchyTraversal,
                },
                ResolutionGapFact {
                    site: owner,
                    kind: ResolutionGapKind::UnsupportedHierarchyTraversal,
                },
                ResolutionGapFact {
                    site: facts.gaps.last().expect("placement gap").site,
                    kind: ResolutionGapKind::UnsupportedPlacementBoundary,
                },
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
    fn unsupported_binders_cannot_leak_affirmative_rows() {
        let source = "class A<T> { enum E { ONE } record R(int component) {} Object f() { try {} catch (Exception caught) { caught.toString(); } for (String item : items) { item.toString(); } class Local {} Object a = () -> { return hidden; }; Object b = new Object() { Object m() { return hidden2; } }; return a; } }";
        let facts = parse(source);
        let spellings = identifier_spellings(&facts);

        for unsupported in [
            "T",
            "ONE",
            "component",
            "caught",
            "item",
            "items",
            "Local",
            "hidden",
            "m",
            "hidden2",
        ] {
            assert!(
                !spellings.contains(&unsupported),
                "unsupported subtree leaked {unsupported:?}: {spellings:?}"
            );
        }
        assert_eq!(
            facts
                .type_transfers
                .iter()
                .filter(|transfer| transfer.kind == ResolutionTypeTransferKind::Return)
                .count(),
            1,
            "only the outer method return may be affirmative"
        );
        assert_eq!(facts.gaps.len(), 17);
        assert_eq!(
            facts
                .gaps
                .iter()
                .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder)
                .count(),
            8
        );
        assert!(
            facts
                .gaps
                .iter()
                .filter(|gap| gap.kind == ResolutionGapKind::ImplicitConstructor)
                .count()
                == 1
        );
        assert_eq!(
            facts
                .gaps
                .iter()
                .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedHierarchyTraversal)
                .count(),
            3
        );
        assert_eq!(
            facts
                .gaps
                .iter()
                .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedVisibility)
                .count(),
            4
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
    fn unsupported_routes_preserve_legacy_names_without_affirmative_resolution_rows() {
        let source = "@Marker @Configured(value = \"x\") sealed class A permits Allowed { void f() throws Failure {} }";
        let parsed = parse_file(source);
        for spelling in ["Allowed", "Failure"] {
            assert!(
                parsed.type_identifiers.contains(spelling),
                "legacy type-identifier evidence omitted {spelling:?}: {:?}",
                parsed.type_identifiers
            );
        }

        let facts = parsed
            .native_source
            .as_ref()
            .expect("Java native packet")
            .resolution_facts();
        assert_eq!(identifier_spellings(facts), vec!["A", "f"]);
        let unsupported = facts
            .gaps
            .iter()
            .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder)
            .collect::<Vec<_>>();
        assert_eq!(unsupported.len(), 4);
        assert!(unsupported.iter().all(|gap| {
            site(facts, gap.site).kind == ResolutionSiteKind::UnsupportedDeclaration
        }));
        assert_eq!(
            non_visibility_gaps(facts)
                .iter()
                .map(|gap| gap.kind)
                .collect::<Vec<_>>(),
            vec![
                ResolutionGapKind::UnsupportedScopeOrBinder,
                ResolutionGapKind::UnsupportedScopeOrBinder,
                ResolutionGapKind::UnsupportedScopeOrBinder,
                ResolutionGapKind::UnsupportedScopeOrBinder,
                ResolutionGapKind::UnsupportedHierarchyTraversal,
                ResolutionGapKind::ImplicitConstructor,
                ResolutionGapKind::UnsupportedPlacementBoundary,
            ]
        );
        assert_eq!(visibility_gap_sites(facts).len(), 2);

        let module =
            parse_file("module sample.app { uses Service; provides Service with Implementation; }");
        for spelling in ["Service", "Implementation"] {
            assert!(
                module.type_identifiers.contains(spelling),
                "legacy module type-identifier evidence omitted {spelling:?}: {:?}",
                module.type_identifiers
            );
        }
        let module_facts = module
            .native_source
            .as_ref()
            .expect("Java module packet")
            .resolution_facts();
        assert!(module_facts.identifiers.is_empty());
        assert_eq!(
            module_facts.gaps,
            vec![
                ResolutionGapFact {
                    site: ResolutionSiteId::new(0),
                    kind: ResolutionGapKind::UnsupportedScopeOrBinder,
                },
                ResolutionGapFact {
                    site: ResolutionSiteId::new(1),
                    kind: ResolutionGapKind::UnsupportedPlacementBoundary,
                },
            ]
        );
        assert_eq!(
            site(module_facts, ResolutionSiteId::new(0)).kind,
            ResolutionSiteKind::UnsupportedDeclaration
        );
    }

    #[test]
    fn unclaimed_semantic_occurrences_become_connected_gaps() {
        let source = "class A { boolean f() { if (probe()) return true; return false; } }";
        let facts = parse(source);

        assert_eq!(identifier_spellings(&facts), vec!["A", "f"]);
        let probe_start = source.find("probe").expect("probe spelling");
        assert!(facts.gaps.iter().any(|gap| {
            let gap_site = site(&facts, gap.site);
            gap.kind == ResolutionGapKind::UnsupportedExpression
                && gap_site.kind == ResolutionSiteKind::UnsupportedExpression
                && gap_site.start_byte == probe_start
                && gap_site.end_byte == probe_start + "probe".len()
        }));
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
        let expected = [
            (
                "java.util.List<String>",
                ResolutionGapKind::UnsupportedTypeSyntax,
            ),
            ("probe", ResolutionGapKind::UnsupportedExpression),
            (
                "() -> hidden()",
                ResolutionGapKind::UnsupportedScopeOrBinder,
            ),
        ];

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
            assert!(facts.gaps.contains(&ResolutionGapFact {
                site: gap.site,
                kind,
            }));
        }
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
        return callee(1) + local;
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
                .filter(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
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
    fn uncertain_type_and_literal_shapes_are_connected_gaps() {
        let facts = parse(
            "class A { java.util.List x; Object y() { var local = 1.0; int values[]; return x; } }",
        );

        assert_eq!(
            non_visibility_gaps(&facts)
                .iter()
                .map(|gap| gap.kind)
                .collect::<Vec<_>>(),
            vec![
                ResolutionGapKind::AmbiguousQualifiedType,
                ResolutionGapKind::AmbiguousQualifiedType,
                ResolutionGapKind::AmbiguousQualifiedType,
                ResolutionGapKind::InferredType,
                ResolutionGapKind::AmbiguousNumericLiteral,
                ResolutionGapKind::PostfixArrayDimensions,
                ResolutionGapKind::UnsupportedHierarchyTraversal,
                ResolutionGapKind::ImplicitConstructor,
                ResolutionGapKind::UnsupportedPlacementBoundary,
            ]
        );
        assert_eq!(visibility_gap_sites(&facts).len(), 3);
        let numeric_site = facts
            .gaps
            .iter()
            .find(|gap| gap.kind == ResolutionGapKind::AmbiguousNumericLiteral)
            .expect("numeric gap")
            .site;
        assert!(
            facts
                .intrinsic_type_seeds
                .iter()
                .all(|seed| { slot(&facts, seed.output).site != numeric_site })
        );
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
    fn unproduced_adapters_have_no_native_source_packet() {
        let parsed = brokk_bifrost_core::analyzer::parsed_file::ParsedFile::new(String::new());
        assert!(parsed.native_source.is_none());
    }

    #[test]
    fn same_pass_preserves_the_type_identifier_superset() {
        let source = "class Outer { Target field; void f() { SamePackageOwner.INSTANCE.use(); } }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .expect("java grammar");
        let tree = parser.parse(source, None).expect("java tree");
        let root = std::env::current_dir()
            .expect("current directory")
            .join("java-resolution-fixture-root");
        let file = ProjectFile::new(root, "src/Outer.java");
        let parsed = super::super::declarations::parse_java_file(&file, source, &tree);
        assert!(parsed.type_identifiers.contains("Target"));
        assert!(parsed.type_identifiers.contains("SamePackageOwner"));
        assert!(!parsed.type_identifiers.contains("Outer"));
        assert!(
            !parsed
                .native_source
                .as_ref()
                .expect("Java native packet")
                .resolution_facts()
                .is_empty()
        );
    }
}
