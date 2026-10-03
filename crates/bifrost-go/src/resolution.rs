//! Go lowering for immutable, target-independent resolution facts.
//!
//! This is deliberately a source-owned second opinion on the common fact
//! schema. It consumes the `Tree` already built by the adapter, uses an
//! iterative walk, and never records a resolved declaration target. Exact Go
//! relations are retained even when a later route is incomplete: pointer
//! depth and variable addressability, struct field ownership, lexical
//! declarations, local type transfer, calls, and return observations.
//!
//! A method declaration is owned through a deferred receiver-type frontier,
//! never a guessed local declaration target. Go method-set applicability still
//! depends on pointer depth and runtime addressability, not only the
//! runtime/type-object category, so method declarations and member routes keep
//! explicit applicability gaps. Likewise, `F(x)` is syntactically a function call,
//! builtin invocation, or type conversion, while the common namespaces have
//! no callable-or-type route. Its call-shape facts remain useful, and selected
//! lexical facts let the engine decide which route applies.

use brokk_bifrost_core::analyzer::go_facts::{
    GoSourceFacts, GoSourceTypeId, GoSourceTypeShape, GoTypeCompoundKind,
};
use brokk_bifrost_core::analyzer::model::DeclarationKind;
use brokk_bifrost_core::analyzer::resolution_facts::{
    BindingProjectionFact, BindingProjectionKind, DeclarationTypeRole, DeclarationTypeSlotFact,
    FileResolutionFacts, IntrinsicTypeKind, IntrinsicTypeSeedFact, PositionedIdentifierFact,
    ResolutionAdditionalDefinitionNamespaceFact, ResolutionBinderFact, ResolutionBinderKind,
    ResolutionCallArgumentFact, ResolutionCallFact, ResolutionCallableParameterFact,
    ResolutionCallableReceiverOrigin, ResolutionCallableReceiverOriginFact,
    ResolutionCallableResultTypeFact, ResolutionCallableSignatureFact,
    ResolutionDeclaredTypeRelationFact, ResolutionDeclaredTypeRelationKind,
    ResolutionDeferredMemberOwnerFact, ResolutionEngineRuleEligibilityFact,
    ResolutionEngineRuleKind, ResolutionGapFact, ResolutionGapKind, ResolutionGoPackageImportFact,
    ResolutionGoPackageImportKind, ResolutionIdentifierRole, ResolutionMemberAccess,
    ResolutionMemberKind, ResolutionMemberOwnerFact, ResolutionMemberQualifierCompatibility,
    ResolutionNameFact, ResolutionNameId, ResolutionNamespace, ResolutionPackageMemberFact,
    ResolutionPackageReferenceFact, ResolutionReferenceEnumerationGapFact,
    ResolutionReferenceOwnerFact, ResolutionRootExportFact, ResolutionRootImportAnchor,
    ResolutionRootImportDemandFact, ResolutionRootImportDemandTarget,
    ResolutionRootImportDemandTargetFact, ResolutionRootImportFact, ResolutionRootImportKind,
    ResolutionRootImportKindFact, ResolutionRootImportSegmentFact, ResolutionRootReferenceFact,
    ResolutionRootReferenceSegmentFact, ResolutionScopeFact, ResolutionScopeId,
    ResolutionScopeInheritance, ResolutionScopeKind, ResolutionSiteFact, ResolutionSiteId,
    ResolutionSiteKind, ResolutionSupertypeFact, ResolutionSupertypeKind,
    ResolutionTypeComponentFact, ResolutionTypeComponentKind, ResolutionTypeConstructorKind,
    ResolutionTypeRelationId, ResolutionTypeSlotFact, ResolutionTypeSlotId, ResolutionTypeSlotRole,
    ResolutionTypeTransferFact, ResolutionTypeTransferKind, ResolutionTypeTransferValueTransform,
};
use brokk_bifrost_core::analyzer::source_facts::{
    PrimarySourceFactCollector, SourceDeclarationId, SourceFactRows, SourceOccurrenceId,
};
use brokk_bifrost_core::analyzer::structural::adapter_helpers::first_named_child;
use brokk_bifrost_core::analyzer::structural::resolution::HoistingClass;
use brokk_bifrost_core::analyzer::tree_walk::TreeWalkAction;
use brokk_bifrost_core::hash::{HashMap, HashSet};
use std::marker::PhantomData;
use tree_sitter::Node;

use crate::declarations::{
    GoImportSpecSyntax, children_by_field, go_embedded_field_name_node, go_identifier_is_exported,
    go_node_text, named_children, sole_spec_declaration_node,
};
use crate::source_properties::{GoSourcePropertyCollector, callable_parameters, result_parameters};

#[cfg(test)]
use crate::declarations::parse_go_import_syntaxes;

#[cfg(test)]
pub(super) fn extract_go_resolution_facts(root: Node<'_>, source: &str) -> FileResolutionFacts {
    let mut builder = GoResolutionBuilder::new(root, source);
    enum Frame<'tree> {
        Enter(Node<'tree>),
        Exit,
    }
    let mut stack = vec![Frame::Enter(root)];
    while let Some(frame) = stack.pop() {
        match frame {
            Frame::Enter(node) => {
                let action = if node.kind() == "import_declaration" {
                    let specs = parse_go_import_syntaxes(node, source);
                    builder.enter_import(node, &specs)
                } else {
                    builder.enter(node)
                };
                match action {
                    TreeWalkAction::Descend => {
                        stack.extend(named_children(node).into_iter().rev().map(Frame::Enter));
                    }
                    TreeWalkAction::DescendWithExit => {
                        stack.push(Frame::Exit);
                        stack.extend(named_children(node).into_iter().rev().map(Frame::Enter));
                    }
                    TreeWalkAction::Skip => {}
                    TreeWalkAction::Stop => break,
                }
            }
            Frame::Exit => builder.exit(),
        }
    }
    builder.finish().facts
}

pub(crate) struct GoResolutionBuilder<'source, 'tree> {
    _tree: PhantomData<Node<'tree>>,
    source: &'source str,
    source_collector: PrimarySourceFactCollector<'source>,
    source_properties: GoSourcePropertyCollector<'source>,
    root_occurrence: SourceOccurrenceId,
    site_occurrences: Vec<SourceOccurrenceId>,
    declaration_sources: Vec<(ResolutionSiteId, SourceDeclarationId)>,
    facts: FileResolutionFacts,
    name_ids: HashMap<String, ResolutionNameId>,
    scope_stack: Vec<ResolutionScopeId>,
    exit_actions: Vec<ExitAction>,
    type_contexts: Vec<TypeContext>,
    callable_contexts: Vec<CallableContext>,
    declaration_owners: Vec<ResolutionSiteId>,
    function_literal_contexts: Vec<FunctionLiteralContext>,
    body_scopes: HashMap<usize, ResolutionScopeId>,
    type_syntax_by_node: HashMap<usize, LoweredTypeSyntax>,
    expression_slots_by_node: HashMap<usize, ResolutionTypeSlotId>,
    value_names_by_scope: HashMap<ResolutionScopeId, HashSet<String>>,
    next_parameter_ordinal: HashMap<ResolutionSiteId, u32>,
    membership_digest: Option<[u8; 32]>,
    has_build_constraints: bool,
}

pub(crate) struct GoResolutionOutput {
    pub(crate) facts: FileResolutionFacts,
    pub(crate) source_facts: SourceFactRows,
    pub(crate) go_source_facts: GoSourceFacts,
    pub(crate) site_occurrences: Vec<SourceOccurrenceId>,
    pub(crate) declaration_sources: Vec<(ResolutionSiteId, SourceDeclarationId)>,
}

#[derive(Debug, Clone, Copy)]
enum ExitAction {
    Scope,
    TypeContext,
    CallableContext,
    FunctionLiteralContext,
}

#[derive(Debug, Clone, Copy)]
struct TypeContext {
    declaration: ResolutionSiteId,
}

#[derive(Debug, Clone, Copy)]
struct CallableContext {
    declaration: ResolutionSiteId,
    scope: ResolutionScopeId,
    activation_start: usize,
    activation_end: usize,
    receiver_span: Option<(usize, usize)>,
    receiver_is_malformed: bool,
}

#[derive(Debug, Clone, Copy)]
struct FunctionLiteralContext {
    node: usize,
    scope: ResolutionScopeId,
    activation_start: usize,
    activation_end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LoweredTypeSyntax {
    input: ResolutionTypeSlotId,
    indirection_delta: i8,
}

/// Digest what the Go tool reads to place a file in a package. Build
/// constraints must precede the package clause, and go/build stops reading
/// after the import declarations, so equal bytes through the last import mean
/// equal build constraints, package name, cgo use and import spellings. A
/// malformed header, a second package clause or an import after another
/// declaration has no digest: the Go tool rejects or reclassifies such a file.
/// Top-level children are one flat list, so this is a single pass.
fn go_membership_digest(root: Node<'_>, source: &str) -> Option<[u8; 32]> {
    let mut end = None;
    let mut header_closed = false;
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.is_error() || child.is_missing() {
            if header_closed {
                continue;
            }
            return None;
        }
        match child.kind() {
            "package_clause" if end.is_none() && !header_closed => {
                if child.has_error() {
                    return None;
                }
                end = Some(child.end_byte());
            }
            "import_declaration" if end.is_some() && !header_closed => {
                if child.has_error() {
                    return None;
                }
                end = Some(child.end_byte());
            }
            "package_clause" | "import_declaration" => return None,
            "comment" => {}
            _ if child.is_named() => header_closed = true,
            _ => {}
        }
    }
    let end = end?;
    let mut hash = brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(
        b"bifrost-go-membership-header:v1",
    );
    hash.field("header", &source.as_bytes()[..end]);
    Some(hash.finish())
}

/// Build constraints are comment nodes in Go's syntax tree. Inspect only
/// leading top-level line comments; matching bytes inside a block comment or
/// later documentation cannot constrain package selection.
fn go_has_build_constraints(root: Node<'_>, source: &str) -> bool {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() == "package_clause" {
            return false;
        }
        if child.kind() != "comment" {
            continue;
        }
        let comment = &source[child.start_byte()..child.end_byte()];
        if !comment.starts_with("//") {
            continue;
        }
        for directive in ["//go:build", "// +build"] {
            if comment
                .strip_prefix(directive)
                .is_some_and(|tail| tail.chars().next().is_none_or(char::is_whitespace))
            {
                return true;
            }
        }
    }
    false
}

impl<'source, 'tree> GoResolutionBuilder<'source, 'tree> {
    pub(crate) fn new(root: Node<'tree>, source: &'source str) -> Self {
        let compilation_unit = ResolutionScopeId::new(0);
        let package = ResolutionScopeId::new(1);
        let file_scope = ResolutionScopeId::new(2);
        let mut source_collector = PrimarySourceFactCollector::new(source);
        let root_occurrence = source_collector.intern_node(root);
        let root_range = source_collector.occurrence(root_occurrence).range;
        let facts = FileResolutionFacts {
            scopes: vec![
                ResolutionScopeFact {
                    id: compilation_unit,
                    parent: None,
                    owner: None,
                    kind: ResolutionScopeKind::CompilationUnit,
                    inheritance: ResolutionScopeInheritance::Lexical,
                    start_byte: root_range.start_byte,
                    end_byte: root_range.end_byte,
                },
                ResolutionScopeFact {
                    id: package,
                    parent: Some(compilation_unit),
                    owner: None,
                    kind: ResolutionScopeKind::Package,
                    inheritance: ResolutionScopeInheritance::Lexical,
                    start_byte: root_range.start_byte,
                    end_byte: root_range.end_byte,
                },
                ResolutionScopeFact {
                    id: file_scope,
                    parent: Some(package),
                    owner: None,
                    kind: ResolutionScopeKind::File,
                    inheritance: ResolutionScopeInheritance::Lexical,
                    start_byte: root_range.start_byte,
                    end_byte: root_range.end_byte,
                },
            ],
            ..FileResolutionFacts::default()
        };
        Self {
            _tree: PhantomData,
            source,
            source_collector,
            source_properties: GoSourcePropertyCollector::new(source),
            root_occurrence,
            site_occurrences: Vec::new(),
            declaration_sources: Vec::new(),
            facts,
            name_ids: HashMap::default(),
            scope_stack: vec![compilation_unit, package, file_scope],
            exit_actions: Vec::new(),
            type_contexts: Vec::new(),
            callable_contexts: Vec::new(),
            declaration_owners: Vec::new(),
            function_literal_contexts: Vec::new(),
            body_scopes: HashMap::default(),
            type_syntax_by_node: HashMap::default(),
            expression_slots_by_node: HashMap::default(),
            value_names_by_scope: HashMap::default(),
            next_parameter_ordinal: HashMap::default(),
            membership_digest: go_membership_digest(root, source),
            has_build_constraints: go_has_build_constraints(root, source),
        }
    }

    pub(crate) fn source_collector_mut(&mut self) -> &mut PrimarySourceFactCollector<'source> {
        &mut self.source_collector
    }

    pub(crate) fn capture_source_node(&mut self, node: Node<'_>) {
        self.source_properties
            .capture_node(node, &mut self.source_collector);
    }

    pub(crate) fn capture_source_type(&mut self, node: Node<'_>) -> Option<GoSourceTypeId> {
        self.source_properties
            .capture_type(node, &mut self.source_collector)
    }

    pub(crate) fn capture_source_embedded_type(
        &mut self,
        field: Node<'_>,
        type_node: Node<'_>,
    ) -> Option<GoSourceTypeId> {
        self.source_properties
            .capture_embedded_type(field, type_node, &mut self.source_collector)
    }

    pub(crate) fn source_type_id(&self, node: Node<'_>) -> Option<GoSourceTypeId> {
        self.source_properties.type_id_for_node(node)
    }

    pub(crate) fn source_type_identity(
        &mut self,
        type_id: GoSourceTypeId,
    ) -> Option<brokk_bifrost_core::analyzer::model::StructuredTypeIdentity> {
        self.source_properties.identity_for_type(type_id)
    }

    pub(crate) fn source_properties_mut(&mut self) -> &mut GoSourcePropertyCollector<'source> {
        &mut self.source_properties
    }

    pub(crate) fn source_callable_parameters(
        &mut self,
        node: Node<'_>,
    ) -> Option<Vec<brokk_bifrost_core::analyzer::go_facts::GoCallableParameterFact>> {
        callable_parameters(
            node,
            self.source,
            &mut self.source_collector,
            &self.source_properties,
        )
    }

    pub(crate) fn source_result_parameters(
        &mut self,
        node: Node<'_>,
    ) -> (
        Vec<brokk_bifrost_core::analyzer::go_facts::GoCallableParameterFact>,
        Option<SourceOccurrenceId>,
    ) {
        result_parameters(
            node,
            self.source,
            &mut self.source_collector,
            &self.source_properties,
        )
    }

    pub(crate) fn declare_node(
        &mut self,
        node: Node<'_>,
        name: Option<Node<'_>>,
    ) -> SourceDeclarationId {
        let occurrence = self.source_collector.intern_node(node);
        let name = name.map(|name| self.source_collector.intern_node(name));
        self.source_collector.declare(occurrence, name)
    }

    #[allow(clippy::too_many_arguments)]
    fn add_declaration_identifier_site(
        &mut self,
        owner: Node<'_>,
        name: Node<'_>,
        kind: ResolutionSiteKind,
        scope: ResolutionScopeId,
        role: ResolutionIdentifierRole,
        namespace: ResolutionNamespace,
        qualifier: Option<ResolutionTypeSlotId>,
    ) -> ResolutionSiteId {
        let source_declaration = self.declare_node(owner, Some(name));
        let site = self.add_identifier_site(name, kind, scope, role, namespace, qualifier);
        self.declaration_sources.push((site, source_declaration));
        site
    }

    fn mark_lexical_declaration(&mut self, declaration: ResolutionSiteId, kind: DeclarationKind) {
        let &(last_site, source_declaration) = self
            .declaration_sources
            .last()
            .expect("lexical declaration was just constructed");
        assert_eq!(
            last_site, declaration,
            "attach lexical source metadata at construction"
        );
        self.source_collector.mark_lexical(source_declaration, kind);
    }

    pub(crate) fn finish(mut self) -> GoResolutionOutput {
        assert_eq!(
            self.scope_stack.len(),
            3,
            "Go resolution scope traversal did not balance"
        );
        assert!(self.exit_actions.is_empty());
        assert!(self.type_contexts.is_empty());
        assert!(self.callable_contexts.is_empty());
        assert!(self.declaration_owners.is_empty());
        assert!(self.function_literal_contexts.is_empty());
        self.finish_root_import_demands();
        self.finish_package_relations();
        let root = self.facts.scopes[ResolutionScopeId::new(0).get() as usize];
        assert_eq!(root.kind, ResolutionScopeKind::CompilationUnit);
        assert!(root.parent.is_none());
        let placement = ResolutionSiteId::try_from_index(self.facts.sites.len())
            .expect("resolution site count exceeds u32");
        let placement_range = self.source_collector.occurrence(self.root_occurrence).range;
        self.site_occurrences.push(self.root_occurrence);
        self.facts.sites.push(ResolutionSiteFact {
            id: placement,
            scope: root.id,
            kind: ResolutionSiteKind::UnsupportedRoute,
            start_byte: placement_range.start_byte,
            end_byte: placement_range.end_byte,
        });
        self.facts.gaps.push(ResolutionGapFact {
            site: placement,
            kind: ResolutionGapKind::UnsupportedPlacementBoundary,
        });
        validate_facts(&self.facts);
        assert_eq!(self.site_occurrences.len(), self.facts.sites.len());
        let mut go_source_facts = self.source_properties.finish();
        go_source_facts.membership_digest = self.membership_digest;
        go_source_facts.has_build_constraints = Some(self.has_build_constraints);
        GoResolutionOutput {
            facts: self.facts,
            source_facts: self.source_collector.finish(),
            go_source_facts,
            site_occurrences: self.site_occurrences,
            declaration_sources: self.declaration_sources,
        }
    }

    pub(crate) fn enter(&mut self, node: Node<'tree>) -> TreeWalkAction {
        assert_ne!(
            node.kind(),
            "import_declaration",
            "Go import nodes must enter through enter_import"
        );
        self.capture_source_node(node);
        if let Some(action) = self.enter_preamble(node) {
            return action;
        }

        self.enter_after_preamble(node)
    }

    pub(crate) fn enter_import<'node>(
        &mut self,
        node: Node<'node>,
        specs: &[GoImportSpecSyntax<'node, 'source>],
    ) -> TreeWalkAction {
        assert_eq!(node.kind(), "import_declaration");
        self.capture_source_node(node);
        if let Some(action) = self.enter_preamble(node) {
            return action;
        }
        self.lower_root_imports(specs);
        self.gap_and_skip(
            node,
            ResolutionSiteKind::UnsupportedRoute,
            ResolutionGapKind::UnsupportedRoute,
        )
    }

    fn enter_preamble(&mut self, node: Node<'_>) -> Option<TreeWalkAction> {
        if node.is_error() || node.is_missing() {
            return Some(self.gap_and_skip(
                node,
                ResolutionSiteKind::UnsupportedDeclaration,
                ResolutionGapKind::MalformedSyntax,
            ));
        }

        None
    }

    fn enter_after_preamble(&mut self, node: Node<'tree>) -> TreeWalkAction {
        if let Some(scope) = self.body_scopes.get(&node.id()).copied() {
            self.scope_stack.push(scope);
            self.exit_actions.push(ExitAction::Scope);
            return TreeWalkAction::DescendWithExit;
        }

        if node.kind() == "block" {
            let scope = self.allocate_scope(
                self.current_scope(),
                None,
                ResolutionScopeKind::Block,
                node.start_byte(),
                node.end_byte(),
            );
            self.scope_stack.push(scope);
            self.exit_actions.push(ExitAction::Scope);
            return TreeWalkAction::DescendWithExit;
        }

        match node.kind() {
            "source_file" | "package_clause" | "type_declaration" | "var_declaration"
            | "const_declaration" | "var_spec_list" | "parameter_list" => TreeWalkAction::Descend,
            "struct_type" => self.enter_struct_type(node),
            "type_spec" => {
                let Some(context) = self.lower_type_declaration(node) else {
                    return self.gap_and_skip(
                        node,
                        ResolutionSiteKind::UnsupportedDeclaration,
                        ResolutionGapKind::MalformedSyntax,
                    );
                };
                self.type_contexts.push(context);
                self.exit_actions.push(ExitAction::TypeContext);
                TreeWalkAction::DescendWithExit
            }
            "type_alias" => {
                if self.lower_type_alias(node).is_none() {
                    return self.gap_and_skip(
                        node,
                        ResolutionSiteKind::UnsupportedDeclaration,
                        ResolutionGapKind::MalformedSyntax,
                    );
                }
                TreeWalkAction::Skip
            }
            "func_literal" => self.enter_function_literal(node),
            "function_declaration" | "method_declaration" | "method_elem" => {
                let Some(context) = self.lower_callable_declaration(node) else {
                    return self.gap_and_skip(
                        node,
                        ResolutionSiteKind::UnsupportedDeclaration,
                        ResolutionGapKind::MalformedSyntax,
                    );
                };
                self.callable_contexts.push(context);
                self.exit_actions.push(ExitAction::CallableContext);
                TreeWalkAction::DescendWithExit
            }
            "field_declaration" => {
                self.lower_field_declaration(node);
                TreeWalkAction::Skip
            }
            "parameter_declaration" => {
                self.lower_parameter(node, false);
                TreeWalkAction::Skip
            }
            "variadic_parameter_declaration" => {
                self.lower_parameter(node, true);
                TreeWalkAction::Skip
            }
            "var_spec" => {
                self.lower_var_spec(node);
                TreeWalkAction::Descend
            }
            "const_spec" => {
                self.lower_const_spec(node);
                TreeWalkAction::Descend
            }
            "short_var_declaration" => {
                self.lower_short_var_declaration(node);
                TreeWalkAction::Descend
            }
            "return_statement" => {
                self.lower_return(node);
                TreeWalkAction::Descend
            }
            "assignment_statement" => {
                self.lower_assignment_statement(node);
                TreeWalkAction::Descend
            }
            "expression_statement" => {
                if let Some(expression) = first_named_child(node) {
                    self.lower_expression(expression);
                }
                TreeWalkAction::Descend
            }
            "for_statement" if self.for_statement_has_range_clause(node) => {
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
            "range_clause" => {
                self.lower_range_clause(node);
                TreeWalkAction::Skip
            }
            "if_statement" => self.enter_if_statement(node),
            "interface_type" | "type_parameter_list" | "type_parameter_declaration" => self
                .gap_and_skip(
                    node,
                    ResolutionSiteKind::UnsupportedDeclaration,
                    ResolutionGapKind::UnsupportedScopeOrBinder,
                ),
            "expression_switch_statement" => self.enter_expression_switch(node),
            "type_switch_statement" => self.enter_type_switch(node),
            "select_statement" => self.enter_block_scope(node),
            "expression_case" => self.enter_block_scope(node),
            "type_case" => self.enter_type_case(node),
            "communication_case" => self.enter_communication_case(node),
            "default_case" => self.enter_default_case(node),
            "for_statement" | "go_statement" | "defer_statement" => self.gap_and_skip(
                node,
                ResolutionSiteKind::UnsupportedExpression,
                ResolutionGapKind::UnsupportedScopeOrBinder,
            ),
            _ => TreeWalkAction::Descend,
        }
    }

    fn enter_if_statement(&mut self, node: Node<'tree>) -> TreeWalkAction {
        let scope = self.allocate_scope(
            self.current_scope(),
            None,
            ResolutionScopeKind::Block,
            node.start_byte(),
            node.end_byte(),
        );
        self.scope_stack.push(scope);
        self.exit_actions.push(ExitAction::Scope);

        if let Some(condition) = node.child_by_field_name("condition") {
            self.lower_expression(condition);
        } else {
            let site = self.add_site(node, ResolutionSiteKind::UnsupportedExpression);
            self.add_gap(site, ResolutionGapKind::MalformedSyntax);
        }
        TreeWalkAction::DescendWithExit
    }

    fn enter_struct_type(&mut self, node: Node<'_>) -> TreeWalkAction {
        let fields = named_children(node)
            .into_iter()
            .find(|child| child.kind() == "field_declaration_list");
        if fields.is_some_and(|fields| self.body_scopes.contains_key(&fields.id())) {
            TreeWalkAction::Descend
        } else {
            self.gap_and_skip(
                node,
                ResolutionSiteKind::UnsupportedDeclaration,
                ResolutionGapKind::UnsupportedTypeSyntax,
            )
        }
    }

    fn push_block_scope(&mut self, node: Node<'tree>) -> ResolutionScopeId {
        self.push_block_scope_from(node, node.start_byte())
    }

    fn push_block_scope_from(&mut self, node: Node<'tree>, start_byte: usize) -> ResolutionScopeId {
        let scope = self.allocate_scope(
            self.current_scope(),
            None,
            ResolutionScopeKind::Block,
            start_byte,
            node.end_byte(),
        );
        self.scope_stack.push(scope);
        self.exit_actions.push(ExitAction::Scope);
        scope
    }

    fn enter_block_scope(&mut self, node: Node<'tree>) -> TreeWalkAction {
        self.push_block_scope(node);
        TreeWalkAction::DescendWithExit
    }

    fn enter_expression_switch(&mut self, node: Node<'tree>) -> TreeWalkAction {
        self.push_block_scope(node);
        if let Some(value) = node.child_by_field_name("value") {
            self.lower_expression(value);
        }
        TreeWalkAction::DescendWithExit
    }

    fn enter_type_switch(&mut self, node: Node<'tree>) -> TreeWalkAction {
        self.push_block_scope(node);
        if let Some(value) = node.child_by_field_name("value") {
            self.lower_expression(value);
        }
        TreeWalkAction::DescendWithExit
    }

    fn enter_type_case(&mut self, node: Node<'tree>) -> TreeWalkAction {
        let alias = self.type_switch_alias(node);
        let scope_start = alias.map_or(node.start_byte(), |alias| alias.start_byte());
        let scope = self.push_block_scope_from(node, scope_start);
        if let Some(alias) = alias {
            let types = children_by_field(node, "type");
            let case_type = (types.len() == 1).then_some(types[0]);
            self.add_clause_binder(alias, alias, scope, node.start_byte(), case_type);
        }
        TreeWalkAction::DescendWithExit
    }

    fn enter_default_case(&mut self, node: Node<'tree>) -> TreeWalkAction {
        let alias = self.type_switch_alias(node);
        let scope_start = alias.map_or(node.start_byte(), |alias| alias.start_byte());
        let scope = self.push_block_scope_from(node, scope_start);
        if let Some(alias) = alias {
            self.add_clause_binder(alias, alias, scope, node.start_byte(), None);
        }
        TreeWalkAction::DescendWithExit
    }

    fn type_switch_alias(&self, case_clause: Node<'tree>) -> Option<Node<'tree>> {
        let mut ancestor = case_clause.parent();
        while let Some(node) = ancestor {
            if node.kind() == "type_switch_statement" {
                let alias = node.child_by_field_name("alias")?;
                let names = expression_children(alias);
                return (names.len() == 1).then_some(names[0]);
            }
            ancestor = node.parent();
        }
        None
    }

    fn enter_communication_case(&mut self, node: Node<'tree>) -> TreeWalkAction {
        let scope = self.push_block_scope(node);
        let Some(communication) = node.child_by_field_name("communication") else {
            let site = self.add_site(node, ResolutionSiteKind::UnsupportedExpression);
            self.add_gap(site, ResolutionGapKind::MalformedSyntax);
            return TreeWalkAction::DescendWithExit;
        };
        match communication.kind() {
            "receive_statement" => {
                if let Some(right) = communication.child_by_field_name("right") {
                    self.lower_expression(right);
                } else {
                    let site =
                        self.add_site(communication, ResolutionSiteKind::UnsupportedExpression);
                    self.add_gap(site, ResolutionGapKind::MalformedSyntax);
                }
                if let Some(left) = communication.child_by_field_name("left") {
                    let bindings = expression_children(left);
                    let short_declaration = (0..communication.child_count()).any(|index| {
                        communication
                            .child(index)
                            .is_some_and(|child| child.kind() == ":=")
                    });
                    if short_declaration {
                        for name in bindings {
                            self.add_clause_binder(
                                communication,
                                name,
                                scope,
                                communication.end_byte(),
                                None,
                            );
                        }
                    } else {
                        for target in bindings {
                            self.lower_expression(target);
                        }
                    }
                }
            }
            "send_statement" => {
                if let Some(channel) = communication.child_by_field_name("channel") {
                    self.lower_expression(channel);
                }
                if let Some(value) = communication.child_by_field_name("value") {
                    self.lower_expression(value);
                }
            }
            _ => {
                let site = self.add_site(communication, ResolutionSiteKind::UnsupportedExpression);
                self.add_gap(site, ResolutionGapKind::UnsupportedRoute);
            }
        }
        TreeWalkAction::DescendWithExit
    }

    fn add_clause_binder(
        &mut self,
        declaration_node: Node<'tree>,
        name: Node<'tree>,
        scope: ResolutionScopeId,
        activation_start: usize,
        declared_type: Option<Node<'tree>>,
    ) {
        if name.kind() != "identifier" {
            let site = self.add_site_in_scope(
                declaration_node,
                ResolutionSiteKind::UnsupportedDeclaration,
                scope,
            );
            self.add_gap(site, ResolutionGapKind::UnsupportedScopeOrBinder);
            return;
        }
        if go_node_text(name, self.source).trim() == "_" {
            return;
        }
        let declaration = self.add_declaration_identifier_site(
            declaration_node,
            name,
            ResolutionSiteKind::ValueDeclaration,
            scope,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
            None,
        );
        self.mark_lexical_declaration(declaration, DeclarationKind::LocalVariable);
        let scope_fact = *self.scope(scope);
        self.facts.binders.push(ResolutionBinderFact {
            declaration,
            scope,
            kind: ResolutionBinderKind::Local,
            hoisting: HoistingClass::SourceOrder,
            activation_start,
            activation_end: scope_fact.end_byte,
        });
        if let Some(type_node) = declared_type {
            self.attach_declaration_type(declaration, type_node, DeclarationTypeRole::Value, true);
        } else {
            self.add_gap(declaration, ResolutionGapKind::InferredType);
        }
        self.record_value_name(scope, name);
    }

    fn for_statement_has_range_clause(&self, node: Node<'_>) -> bool {
        named_children(node)
            .into_iter()
            .any(|child| child.kind() == "range_clause")
    }

    pub(crate) fn exit(&mut self) {
        match self
            .exit_actions
            .pop()
            .expect("every requested Go tree exit has an action")
        {
            ExitAction::Scope => {
                assert!(self.scope_stack.len() > 3, "cannot exit file scope");
                self.scope_stack.pop();
            }
            ExitAction::TypeContext => {
                self.type_contexts
                    .pop()
                    .expect("type context exit must balance");
                self.declaration_owners
                    .pop()
                    .expect("type declaration exits its reference owner");
            }
            ExitAction::CallableContext => {
                self.callable_contexts
                    .pop()
                    .expect("callable context exit must balance");
                self.declaration_owners
                    .pop()
                    .expect("callable declaration exits its reference owner");
            }
            ExitAction::FunctionLiteralContext => {
                self.function_literal_contexts
                    .pop()
                    .expect("function literal context exit must balance");
                assert!(self.scope_stack.len() > 3, "cannot exit file scope");
                self.scope_stack.pop();
            }
        }
    }

    fn enter_function_literal(&mut self, node: Node<'tree>) -> TreeWalkAction {
        let Some(body) = node.child_by_field_name("body") else {
            return self.gap_and_skip(
                node,
                ResolutionSiteKind::UnsupportedExpression,
                ResolutionGapKind::MalformedSyntax,
            );
        };
        let scope = self.allocate_scope(
            self.current_scope(),
            self.declaration_owners.last().copied(),
            ResolutionScopeKind::Executable,
            node.start_byte(),
            node.end_byte(),
        );
        let context = FunctionLiteralContext {
            node: node.id(),
            scope,
            activation_start: body.start_byte(),
            activation_end: body.end_byte(),
        };
        self.scope_stack.push(scope);
        self.function_literal_contexts.push(context);
        self.exit_actions.push(ExitAction::FunctionLiteralContext);
        TreeWalkAction::DescendWithExit
    }

    fn declaration_scope(&self) -> ResolutionScopeId {
        let current = self.current_scope();
        if self.scope(current).kind == ResolutionScopeKind::File {
            let package = self
                .scope(current)
                .parent
                .expect("file scope has its package parent");
            assert_eq!(self.scope(package).kind, ResolutionScopeKind::Package);
            package
        } else {
            current
        }
    }

    fn current_scope(&self) -> ResolutionScopeId {
        *self
            .scope_stack
            .last()
            .expect("compilation and package scopes are always present")
    }

    fn scope(&self, id: ResolutionScopeId) -> &ResolutionScopeFact {
        &self.facts.scopes[id.index()]
    }

    fn scope_for_source_node(&self, node: Node<'_>) -> ResolutionScopeId {
        let contains_node = |scope: &ResolutionScopeFact| {
            scope.start_byte <= node.start_byte() && node.end_byte() <= scope.end_byte
        };
        let current = self.current_scope();
        if contains_node(self.scope(current)) {
            return current;
        }
        self.facts
            .scopes
            .iter()
            .filter(|scope| contains_node(scope))
            .min_by_key(|scope| {
                (
                    scope.end_byte - scope.start_byte,
                    usize::MAX - scope.id.index(),
                )
            })
            .map(|scope| scope.id)
            .expect("the file scope contains every source node")
    }

    fn slot(&self, id: ResolutionTypeSlotId) -> &ResolutionTypeSlotFact {
        &self.facts.type_slots[id.index()]
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
            inheritance: ResolutionScopeInheritance::Lexical,
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

    fn intern_name(&mut self, spelling: &str) -> ResolutionNameId {
        if let Some(id) = self.name_ids.get(spelling) {
            return *id;
        }
        let id = ResolutionNameId::try_from_index(self.facts.names.len())
            .expect("resolution name count exceeds u32");
        let spelling = spelling.to_string();
        self.name_ids.insert(spelling.clone(), id);
        self.facts.names.push(ResolutionNameFact { id, spelling });
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
        let spelling = go_node_text(node, self.source).trim();
        assert!(!spelling.is_empty(), "identifier token needs a spelling");
        let name = self.intern_name(spelling);
        self.facts.identifiers.push(PositionedIdentifierFact {
            site,
            name,
            role,
            namespace,
            qualifier,
        });
        if role == ResolutionIdentifierRole::Reference {
            self.facts
                .reference_owners
                .push(ResolutionReferenceOwnerFact {
                    reference: site,
                    owner: self.declaration_owners.last().copied(),
                });
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
        indirection_delta: i8,
        value_transform: ResolutionTypeTransferValueTransform,
    ) {
        assert_ne!(input, output);
        self.facts.type_transfers.push(ResolutionTypeTransferFact {
            input,
            output,
            kind,
            indirection_delta,
            reference_indirection_delta: 0,
            value_transform,
        });
    }

    fn add_gap(&mut self, site: ResolutionSiteId, kind: ResolutionGapKind) {
        let gap = ResolutionGapFact { site, kind };
        if !self.facts.gaps.contains(&gap) {
            self.facts.gaps.push(gap);
        }
        if go_gap_blocks_reference_enumeration(kind) {
            let gap = ResolutionReferenceEnumerationGapFact { site, kind };
            if !self.facts.reference_enumeration_gaps.contains(&gap) {
                self.facts.reference_enumeration_gaps.push(gap);
            }
        }
    }

    fn gap_and_skip(
        &mut self,
        node: Node<'_>,
        site_kind: ResolutionSiteKind,
        gap_kind: ResolutionGapKind,
    ) -> TreeWalkAction {
        let site = self.add_site(node, site_kind);
        self.add_gap(site, gap_kind);
        TreeWalkAction::Skip
    }

    fn lower_root_imports<'node>(&mut self, specs: &[GoImportSpecSyntax<'node, 'source>]) {
        let root_scope = ResolutionScopeId::new(2);
        assert_eq!(
            self.current_scope(),
            root_scope,
            "a Go import declaration must occur in file scope"
        );
        assert_eq!(
            self.scope(root_scope).kind,
            ResolutionScopeKind::File,
            "the Go root-import scope must be the file scope"
        );

        for spec in specs {
            if spec.segments.is_empty() || spec.segments.iter().any(|segment| segment.is_empty()) {
                continue;
            }
            let site = self.add_site_in_scope(
                spec.node,
                ResolutionSiteKind::ImportDeclaration,
                root_scope,
            );
            self.facts.root_imports.push(ResolutionRootImportFact {
                site,
                root_scope,
                anchor: ResolutionRootImportAnchor::Lexical,
            });
            // The exact import-spec site joins canonical source_imports, which
            // retain explicit alias syntax. Default binding requires selected
            // package.Name; a path basename is not binding authority.
            self.facts
                .root_import_kinds
                .push(ResolutionRootImportKindFact {
                    import_site: site,
                    kind: if spec.alias.map(|(alias, _)| alias) == Some(".") {
                        ResolutionRootImportKind::Glob
                    } else {
                        ResolutionRootImportKind::Named
                    },
                });
            if spec.alias.map(|(alias, _)| alias) != Some(".") {
                self.facts
                    .go_package_imports
                    .push(ResolutionGoPackageImportFact {
                        import_site: site,
                        file_scope: root_scope,
                        kind: if spec.alias.map(|(alias, _)| alias) == Some("_") {
                            ResolutionGoPackageImportKind::Blank
                        } else {
                            ResolutionGoPackageImportKind::Named
                        },
                    });
            }
            for (position, segment) in spec.segments.iter().enumerate() {
                let name = self.intern_name(segment);
                self.facts
                    .root_import_segments
                    .push(ResolutionRootImportSegmentFact {
                        import_site: site,
                        position: dense_ordinal(position, "Go root import segment"),
                        name,
                    });
            }
        }
    }

    fn finish_root_import_demands(&mut self) {
        let root_terminals = self
            .facts
            .root_references
            .iter()
            .map(|route| route.reference)
            .collect::<HashSet<_>>();
        let mut seen_names = HashSet::default();
        let demanded_names = self
            .facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.qualifier.is_none()
                    && !root_terminals.contains(&identifier.site)
                    && go_identifier_is_exported(
                        &self.facts.names[identifier.name.index()].spelling,
                    )
            })
            .flat_map(|identifier| {
                go_dot_import_namespaces(identifier.namespace)
                    .iter()
                    .map(move |&namespace| (namespace, identifier.name))
            })
            .filter(|&demand| seen_names.insert(demand))
            .collect::<Vec<_>>();
        let import_sites = self
            .facts
            .root_import_kinds
            .iter()
            .filter(|import| import.kind == ResolutionRootImportKind::Glob)
            .map(|import| import.import_site)
            .collect::<Vec<_>>();
        self.facts
            .root_import_demands
            .reserve(import_sites.len().saturating_mul(demanded_names.len()));
        for import_site in import_sites {
            for &(namespace, name) in &demanded_names {
                self.facts
                    .root_import_demands
                    .push(ResolutionRootImportDemandFact {
                        import_site,
                        namespace,
                        name,
                    });
                self.facts
                    .root_import_demand_targets
                    .push(ResolutionRootImportDemandTargetFact {
                        import_site,
                        namespace,
                        name,
                        target: ResolutionRootImportDemandTarget::SameNameGlob,
                    });
            }
        }
    }

    fn finish_package_relations(&mut self) {
        let root_scope = ResolutionScopeId::new(1);
        let package_binders = self
            .facts
            .binders
            .iter()
            .filter(|binder| binder.scope == root_scope)
            .map(|binder| binder.declaration)
            .collect::<HashSet<_>>();
        let qualified = self
            .facts
            .root_references
            .iter()
            .map(|route| route.reference)
            .collect::<HashSet<_>>();
        for identifier in &self.facts.identifiers {
            if identifier.qualifier.is_some() {
                continue;
            }
            match identifier.role {
                ResolutionIdentifierRole::Declaration
                    if package_binders.contains(&identifier.site) =>
                {
                    self.facts
                        .package_members
                        .push(ResolutionPackageMemberFact {
                            root_scope,
                            declaration: identifier.site,
                            namespace: identifier.namespace,
                        });
                }
                ResolutionIdentifierRole::Reference if !qualified.contains(&identifier.site) => {
                    self.facts
                        .package_references
                        .push(ResolutionPackageReferenceFact {
                            reference: identifier.site,
                            root_scope,
                        });
                }
                _ => {}
            }
        }
        for additional in &self.facts.additional_definition_namespaces {
            if package_binders.contains(&additional.declaration) {
                self.facts
                    .package_members
                    .push(ResolutionPackageMemberFact {
                        root_scope,
                        declaration: additional.declaration,
                        namespace: additional.namespace,
                    });
            }
        }
    }

    fn publish_root_export(
        &mut self,
        declaration: ResolutionSiteId,
        name: Node<'_>,
        namespace: ResolutionNamespace,
    ) {
        let root_scope = self.facts.sites[declaration.index()].scope;
        if root_scope == ResolutionScopeId::new(1)
            && go_identifier_is_exported(go_node_text(name, self.source).trim())
        {
            self.facts.root_exports.push(ResolutionRootExportFact {
                root_scope,
                declaration,
                namespace,
            });
        }
    }

    fn add_type_binder(&mut self, declaration: ResolutionSiteId, name: Node<'_>) {
        let binding_scope = self.facts.sites[declaration.index()].scope;
        let scope = *self.scope(binding_scope);
        self.facts.binders.push(ResolutionBinderFact {
            declaration,
            scope: binding_scope,
            kind: ResolutionBinderKind::Type,
            hoisting: if scope.kind == ResolutionScopeKind::Package {
                HoistingClass::ScopeWide
            } else {
                HoistingClass::SourceOrder
            },
            activation_start: if scope.kind == ResolutionScopeKind::Package {
                scope.start_byte
            } else {
                name.start_byte()
            },
            activation_end: scope.end_byte,
        });
        self.publish_root_export(declaration, name, ResolutionNamespace::Type);
    }

    fn lower_type_alias(&mut self, node: Node<'tree>) -> Option<ResolutionSiteId> {
        let name = node.child_by_field_name("name")?;
        if name.kind() != "type_identifier" {
            return None;
        }
        let binding_scope = self.declaration_scope();
        let declaration = self.add_declaration_identifier_site(
            node,
            name,
            ResolutionSiteKind::TypeAliasDeclaration,
            binding_scope,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
            None,
        );
        self.add_type_binder(declaration, name);
        let output = self.add_slot(declaration, ResolutionTypeSlotRole::TargetTypeIdentity);
        self.facts
            .declaration_type_slots
            .push(DeclarationTypeSlotFact {
                declaration,
                slot: output,
                role: DeclarationTypeRole::Identity,
            });
        if node.child_by_field_name("type_parameters").is_some() {
            self.add_gap(declaration, ResolutionGapKind::UnsupportedTypeSyntax);
            return Some(declaration);
        }
        let Some(target) = node.child_by_field_name("type") else {
            self.add_gap(declaration, ResolutionGapKind::MalformedSyntax);
            return Some(declaration);
        };
        self.declaration_owners.push(declaration);
        let syntax = self.lower_type(target);
        assert_eq!(self.declaration_owners.pop(), Some(declaration));
        self.add_transfer(
            syntax.input,
            output,
            if syntax.indirection_delta == 0 {
                ResolutionTypeTransferKind::TypeIdentity
            } else {
                ResolutionTypeTransferKind::TypeAlias
            },
            syntax.indirection_delta,
            ResolutionTypeTransferValueTransform::Preserve,
        );
        Some(declaration)
    }

    fn lower_type_declaration(&mut self, node: Node<'tree>) -> Option<TypeContext> {
        let name = node.child_by_field_name("name")?;
        if name.kind() != "type_identifier" {
            return None;
        }
        let binding_scope = self.declaration_scope();
        let declaration = self.add_declaration_identifier_site(
            node,
            name,
            ResolutionSiteKind::TypeDeclaration,
            binding_scope,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
            None,
        );
        self.add_type_binder(declaration, name);
        self.declaration_owners.push(declaration);

        if node.child_by_field_name("type_parameters").is_some() {
            self.add_gap(declaration, ResolutionGapKind::UnsupportedTypeSyntax);
        }
        let Some(type_node) = node.child_by_field_name("type") else {
            self.add_gap(declaration, ResolutionGapKind::MalformedSyntax);
            return Some(TypeContext { declaration });
        };
        if matches!(
            type_node.kind(),
            "type_identifier"
                | "identifier"
                | "qualified_type"
                | "array_type"
                | "slice_type"
                | "implicit_length_array_type"
                | "map_type"
                | "channel_type"
                | "parenthesized_type"
        ) {
            let syntax = self.lower_type(type_node);
            let subject = self.add_slot(declaration, ResolutionTypeSlotRole::TargetTypeIdentity);
            let id =
                ResolutionTypeRelationId::try_from_index(self.facts.declared_type_relations.len())
                    .expect("Go declared type relation count exceeds u32");
            let target = self.materialize_type_syntax(syntax);
            self.facts
                .declared_type_relations
                .push(ResolutionDeclaredTypeRelationFact {
                    id,
                    subject,
                    kind: ResolutionDeclaredTypeRelationKind::UnderlyingType,
                    target_reference: None,
                    target: Some(target),
                });
        }
        match type_node.kind() {
            "struct_type" => {
                let fields = named_children(type_node)
                    .into_iter()
                    .find(|child| child.kind() == "field_declaration_list");
                if let Some(fields) = fields {
                    let body_scope = self.allocate_scope(
                        self.current_scope(),
                        Some(declaration),
                        ResolutionScopeKind::TypeBody,
                        node.start_byte(),
                        node.end_byte(),
                    );
                    assert!(self.body_scopes.insert(fields.id(), body_scope).is_none());
                } else {
                    self.add_gap(declaration, ResolutionGapKind::MalformedSyntax);
                }
            }
            "interface_type" => {
                let body_scope = self.allocate_scope(
                    self.current_scope(),
                    Some(declaration),
                    ResolutionScopeKind::TypeBody,
                    type_node.start_byte(),
                    type_node.end_byte(),
                );
                assert!(
                    self.body_scopes
                        .insert(type_node.id(), body_scope)
                        .is_none()
                );
                for element in named_children(type_node)
                    .into_iter()
                    .filter(|child| child.kind() == "type_elem")
                {
                    let terms = named_children(element);
                    let [term] = terms.as_slice() else {
                        self.add_gap(
                            declaration,
                            ResolutionGapKind::UnsupportedHierarchyTraversal,
                        );
                        continue;
                    };
                    if !matches!(term.kind(), "type_identifier" | "qualified_type") {
                        self.add_gap(
                            declaration,
                            ResolutionGapKind::UnsupportedHierarchyTraversal,
                        );
                        continue;
                    }
                    // A named element can bind an interface or a concrete type
                    // term. The selected reader classifies it after binding.
                    let syntax = self.lower_type(*term);
                    let reference = self.slot(syntax.input).site;
                    self.facts.supertypes.push(ResolutionSupertypeFact {
                        subtype: declaration,
                        supertype_reference: reference,
                        supertype_slot: syntax.input,
                        kind: ResolutionSupertypeKind::GoInterfaceElement,
                    });
                    self.add_gap(reference, ResolutionGapKind::UnsupportedHierarchyTraversal);
                }
            }
            "type_identifier"
            | "identifier"
            | "qualified_type"
            | "array_type"
            | "slice_type"
            | "implicit_length_array_type"
            | "map_type"
            | "channel_type"
            | "parenthesized_type" => {}
            _ => self.add_gap(declaration, ResolutionGapKind::UnsupportedTypeSyntax),
        }
        Some(TypeContext { declaration })
    }

    fn lower_callable_declaration(&mut self, node: Node<'tree>) -> Option<CallableContext> {
        let name = node.child_by_field_name("name")?;
        if !matches!(name.kind(), "identifier" | "field_identifier") {
            return None;
        }
        let binding_scope = self.declaration_scope();
        let declaration = self.add_declaration_identifier_site(
            node,
            name,
            ResolutionSiteKind::CallableDeclaration,
            binding_scope,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Callable,
            None,
        );
        self.declaration_owners.push(declaration);
        let signature_index = self.facts.callable_signatures.len();
        self.facts
            .callable_signatures
            .push(ResolutionCallableSignatureFact {
                callable: declaration,
                type_parameter_count: callable_type_parameter_count(node),
                result_types: Vec::new(),
            });
        let is_method = node.kind() == "method_declaration";
        if is_method {
            // Owner identity is deferred correctly below. Pointer/addressable
            // method-set applicability remains deliberately open.
            self.add_gap(declaration, ResolutionGapKind::UnsupportedCallApplicability);
        } else {
            let scope = *self.scope(binding_scope);
            self.facts.binders.push(ResolutionBinderFact {
                declaration,
                scope: binding_scope,
                kind: ResolutionBinderKind::Callable,
                hoisting: HoistingClass::ScopeWide,
                activation_start: scope.start_byte,
                activation_end: scope.end_byte,
            });
            // init functions and blank declarations cannot be referred to as values.
            if !matches!(go_node_text(name, self.source).trim(), "init" | "_") {
                self.facts.additional_definition_namespaces.push(
                    ResolutionAdditionalDefinitionNamespaceFact {
                        declaration,
                        namespace: ResolutionNamespace::Value,
                        hoisting: HoistingClass::ScopeWide,
                    },
                );
                self.publish_root_export(declaration, name, ResolutionNamespace::Value);
            }
            self.publish_root_export(declaration, name, ResolutionNamespace::Callable);
        }

        if node.kind() == "method_elem" {
            let owner = self
                .type_contexts
                .last()
                .expect("named interface method has a type owner");
            assert_eq!(
                self.scope(binding_scope).kind,
                ResolutionScopeKind::TypeBody
            );
            self.facts.member_owners.push(ResolutionMemberOwnerFact {
                member: declaration,
                owner: owner.declaration,
                kind: ResolutionMemberKind::Method,
                access: ResolutionMemberAccess::Instance,
                qualifier_compatibility: ResolutionMemberQualifierCompatibility::RuntimeOrType,
            });
        }

        if node.child_by_field_name("type_parameters").is_some() {
            self.add_gap(declaration, ResolutionGapKind::UnsupportedTypeSyntax);
        }
        let body = node.child_by_field_name("body");
        let activation_start = body.map_or(node.end_byte(), |body| body.start_byte());
        let activation_end = body.map_or(node.end_byte(), |body| body.end_byte());
        let scope_end = body.map_or(node.end_byte(), |body| body.end_byte());
        let callable_scope = self.allocate_scope(
            self.current_scope(),
            Some(declaration),
            ResolutionScopeKind::Executable,
            node.start_byte(),
            scope_end,
        );
        if let Some(body) = body {
            assert!(self.body_scopes.insert(body.id(), callable_scope).is_none());
        }

        if let Some(result) = node.child_by_field_name("result") {
            let result_types = self.lower_callable_result_types(declaration, result);
            if let [result_type] = result_types.as_slice() {
                self.facts
                    .declaration_type_slots
                    .push(DeclarationTypeSlotFact {
                        declaration,
                        slot: result_type.value_type,
                        role: DeclarationTypeRole::Return,
                    });
            }
            self.facts.callable_signatures[signature_index].result_types = result_types;
        }
        let receiver = node.child_by_field_name("receiver");
        let receiver_span = receiver.map(|receiver| (receiver.start_byte(), receiver.end_byte()));
        // The grammar reuses parameter_list for receivers, so even a tree
        // without ERROR nodes can contain zero or multiple receiver variables.
        let receiver_is_malformed = receiver.is_some_and(|receiver| {
            let mut cursor = receiver.walk();
            let mut parameters = receiver
                .named_children(&mut cursor)
                .filter(|child| child.kind() != "comment");
            parameters.next().is_none_or(|parameter| {
                parameter.kind() != "parameter_declaration"
                    || children_by_field(parameter, "name").len() > 1
                    || parameter.child_by_field_name("type").is_none()
            }) || parameters.next().is_some()
        });
        if receiver_is_malformed {
            self.add_gap(declaration, ResolutionGapKind::MalformedSyntax);
        }
        Some(CallableContext {
            declaration,
            scope: callable_scope,
            activation_start,
            activation_end,
            receiver_span,
            receiver_is_malformed,
        })
    }

    fn lower_callable_result_types(
        &mut self,
        callable: ResolutionSiteId,
        result: Node<'tree>,
    ) -> Vec<ResolutionCallableResultTypeFact> {
        if result.kind() != "parameter_list" {
            let value_type = self.add_callable_result_type(callable, result);
            return vec![ResolutionCallableResultTypeFact {
                ordinal: 0,
                value_type,
            }];
        }
        let mut result_types = Vec::new();
        for parameter in named_children(result)
            .into_iter()
            .filter(|child| child.kind() == "parameter_declaration")
        {
            let Some(type_node) = parameter.child_by_field_name("type") else {
                self.add_gap(callable, ResolutionGapKind::MalformedSyntax);
                continue;
            };
            let count = children_by_field(parameter, "name").len().max(1);
            let value_type = self.add_callable_result_type(callable, type_node);
            for _ in 0..count {
                result_types.push(ResolutionCallableResultTypeFact {
                    ordinal: dense_ordinal(result_types.len(), "Go callable result"),
                    value_type,
                });
            }
        }
        if result_types.is_empty() {
            self.add_gap(callable, ResolutionGapKind::UnsupportedTypeSyntax);
        }
        result_types
    }

    fn add_callable_result_type(
        &mut self,
        callable: ResolutionSiteId,
        type_node: Node<'tree>,
    ) -> ResolutionTypeSlotId {
        let syntax = self.lower_type(type_node);
        let value_type = self.add_slot(callable, ResolutionTypeSlotRole::DeclaredValue);
        self.add_transfer(
            syntax.input,
            value_type,
            ResolutionTypeTransferKind::DeclaredType,
            syntax.indirection_delta,
            ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
        );
        value_type
    }

    fn lower_function_value_signature(
        &mut self,
        declaration: ResolutionSiteId,
        type_node: Node<'tree>,
    ) {
        if type_node.kind() != "function_type" {
            return;
        }
        let Some(result) = type_node.child_by_field_name("result") else {
            self.add_gap(declaration, ResolutionGapKind::UnsupportedTypeSyntax);
            return;
        };
        let result_types = self.lower_callable_result_types(declaration, result);
        self.facts
            .callable_signatures
            .push(ResolutionCallableSignatureFact {
                callable: declaration,
                type_parameter_count: 0,
                result_types,
            });
    }

    fn lower_field_declaration(&mut self, node: Node<'tree>) {
        let Some(owner) = self.type_contexts.last().copied() else {
            let site = self.add_site(node, ResolutionSiteKind::UnsupportedDeclaration);
            self.add_gap(site, ResolutionGapKind::UnsupportedScopeOrBinder);
            return;
        };
        let Some(type_node) = node.child_by_field_name("type") else {
            self.add_gap(owner.declaration, ResolutionGapKind::MalformedSyntax);
            return;
        };
        let mut names = children_by_field(node, "name");
        let embedded = names.is_empty();
        if embedded {
            // An embedded field is also a directly selectable named field.
            // Promotion remains open until its distinct method-set relation
            // is supported; it must not erase this ordinary field binding.
            self.add_gap(
                owner.declaration,
                ResolutionGapKind::UnsupportedHierarchyTraversal,
            );
            let Some(name) = go_embedded_field_name_node(type_node) else {
                self.add_gap(owner.declaration, ResolutionGapKind::UnsupportedTypeSyntax);
                return;
            };
            names.push(name);
        }
        let mut syntax = self.lower_type(type_node);
        if embedded {
            let type_id = self
                .capture_source_embedded_type(node, type_node)
                .expect("embedded field has a structured source type");
            if matches!(
                self.source_properties.type_shape(type_id),
                GoSourceTypeShape::Pointer(_)
            ) {
                syntax.indirection_delta = syntax
                    .indirection_delta
                    .checked_add(1)
                    .expect("one embedded pointer fits the type indirection range");
            }
        }
        let binding_scope = self.current_scope();
        assert_eq!(
            self.scope(binding_scope).kind,
            ResolutionScopeKind::TypeBody,
            "Go struct fields must be visited in their type-body scope"
        );
        let scope = *self.scope(binding_scope);
        for name in names {
            let declaration = self.add_declaration_identifier_site(
                node,
                name,
                ResolutionSiteKind::ValueDeclaration,
                binding_scope,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Value,
                None,
            );
            self.facts.binders.push(ResolutionBinderFact {
                declaration,
                scope: binding_scope,
                kind: ResolutionBinderKind::Field,
                hoisting: HoistingClass::ScopeWide,
                activation_start: scope.start_byte,
                activation_end: scope.end_byte,
            });
            self.attach_declaration_type_syntax(
                declaration,
                syntax,
                DeclarationTypeRole::Value,
                false,
            );
            self.facts.member_owners.push(ResolutionMemberOwnerFact {
                member: declaration,
                owner: owner.declaration,
                kind: ResolutionMemberKind::Field,
                access: ResolutionMemberAccess::Instance,
                qualifier_compatibility: ResolutionMemberQualifierCompatibility::RuntimeOnly,
            });
            self.record_value_name(binding_scope, name);
        }
    }

    fn lower_parameter(&mut self, node: Node<'tree>, repeated: bool) {
        if let Some(literal) = self.function_literal_context_for_parameter(node) {
            self.lower_function_literal_parameter(node, repeated, literal);
            return;
        }
        let Some(callable) = self.callable_contexts.last().copied() else {
            let site = self.add_site(node, ResolutionSiteKind::UnsupportedDeclaration);
            self.add_gap(site, ResolutionGapKind::UnsupportedScopeOrBinder);
            return;
        };
        // The callable declaration publishes result slots before descending
        // into the shared parameter-list syntax node.
        if node.parent().is_some_and(|list| {
            list.parent()
                .and_then(|declaration| declaration.child_by_field_name("result"))
                .is_some_and(|result| result.id() == list.id())
        }) {
            return;
        }
        let is_receiver = callable
            .receiver_span
            .is_some_and(|(start, end)| start <= node.start_byte() && node.end_byte() <= end);
        if is_receiver && callable.receiver_is_malformed {
            // The callable owns the syntax gap. Do not fabricate an owner or
            // lexical receiver binding from a malformed receiver list.
            return;
        }
        let names = children_by_field(node, "name");
        let Some(type_node) = node.child_by_field_name("type") else {
            self.add_gap(callable.declaration, ResolutionGapKind::MalformedSyntax);
            return;
        };
        if repeated {
            // Variadic parameters require a slice-shape type relation. Keep
            // their incomplete inventory attached to the callable header.
            self.add_gap(
                callable.declaration,
                ResolutionGapKind::UnsupportedCallApplicability,
            );
            let site = self.add_site_in_scope(
                node,
                ResolutionSiteKind::UnsupportedDeclaration,
                callable.scope,
            );
            self.add_gap(site, ResolutionGapKind::UnsupportedTypeSyntax);
            return;
        }
        // An unnamed parameter still has one signature position and a type,
        // but introduces no lexical declaration. The common parameter schema
        // already supports identifier-free sites for parameters that bind nothing.
        for name in names
            .iter()
            .copied()
            .map(Some)
            .chain(names.is_empty().then_some(None))
        {
            let (declaration, value_type) = if let Some(name) = name {
                let declaration = self.add_declaration_identifier_site(
                    node,
                    name,
                    ResolutionSiteKind::ValueDeclaration,
                    callable.scope,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                    None,
                );
                self.mark_lexical_declaration(
                    declaration,
                    if is_receiver {
                        DeclarationKind::ReceiverParameter
                    } else {
                        DeclarationKind::Parameter
                    },
                );
                self.facts.binders.push(ResolutionBinderFact {
                    declaration,
                    scope: callable.scope,
                    kind: ResolutionBinderKind::Parameter,
                    // The executable scope includes the signature, but Go
                    // parameter and receiver names are visible only in its body.
                    hoisting: HoistingClass::SourceOrder,
                    activation_start: callable.activation_start,
                    activation_end: callable.activation_end,
                });
                let value_type = self.attach_declaration_type(
                    declaration,
                    type_node,
                    DeclarationTypeRole::Parameter,
                    true,
                );
                self.record_value_name(callable.scope, name);
                (declaration, value_type)
            } else {
                let declaration = self.add_site_in_scope(
                    node,
                    ResolutionSiteKind::ValueDeclaration,
                    callable.scope,
                );
                let syntax = self.lower_type(type_node);
                let value_type = self.add_slot(declaration, ResolutionTypeSlotRole::DeclaredValue);
                self.add_transfer(
                    syntax.input,
                    value_type,
                    ResolutionTypeTransferKind::DeclaredType,
                    syntax.indirection_delta,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                );
                (declaration, value_type)
            };
            if !is_receiver {
                let ordinal = self.next_parameter_ordinal(callable.declaration);
                self.facts
                    .callable_parameters
                    .push(ResolutionCallableParameterFact {
                        callable: callable.declaration,
                        ordinal,
                        parameter: declaration,
                        value_type,
                        repeated: false,
                    });
            }
        }
        if is_receiver {
            assert!(names.len() <= 1, "a Go method has one receiver");
            // Ownership follows the receiver type, independently of whether
            // the method body names its receiver. Pointer depth remains on
            // the receiver's value transfer for later applicability support.
            let owner_type = self.lower_type(type_node).input;
            assert_eq!(
                self.facts.type_slots[owner_type.index()].role,
                ResolutionTypeSlotRole::TargetTypeIdentity,
            );
            self.facts
                .deferred_member_owners
                .push(ResolutionDeferredMemberOwnerFact {
                    member: callable.declaration,
                    owner_type,
                    kind: ResolutionMemberKind::Method,
                    access: ResolutionMemberAccess::Instance,
                    qualifier_compatibility: ResolutionMemberQualifierCompatibility::RuntimeOnly,
                });
        }
    }

    fn function_literal_context_for_parameter(
        &self,
        node: Node<'_>,
    ) -> Option<FunctionLiteralContext> {
        let list = node.parent()?;
        let literal = list.parent()?;
        self.function_literal_contexts
            .last()
            .copied()
            .filter(|context| context.node == literal.id() && literal.kind() == "func_literal")
    }

    fn lower_function_literal_parameter(
        &mut self,
        node: Node<'tree>,
        repeated: bool,
        literal: FunctionLiteralContext,
    ) {
        let list = node
            .parent()
            .expect("function literal parameter has a list");
        let literal_node = list
            .parent()
            .expect("function literal parameter has an owner");
        if literal_node
            .child_by_field_name("result")
            .is_some_and(|result| result.id() == list.id())
        {
            let site = self.add_site_in_scope(
                node,
                ResolutionSiteKind::UnsupportedDeclaration,
                literal.scope,
            );
            self.add_gap(site, ResolutionGapKind::UnsupportedTypeSyntax);
            if let Some(type_node) = node.child_by_field_name("type") {
                self.lower_type(type_node);
            }
            return;
        }
        let Some(type_node) = node.child_by_field_name("type") else {
            let site = self.add_site_in_scope(
                node,
                ResolutionSiteKind::UnsupportedDeclaration,
                literal.scope,
            );
            self.add_gap(site, ResolutionGapKind::MalformedSyntax);
            return;
        };
        if repeated {
            let site = self.add_site_in_scope(
                node,
                ResolutionSiteKind::UnsupportedDeclaration,
                literal.scope,
            );
            self.add_gap(site, ResolutionGapKind::UnsupportedCallApplicability);
            self.lower_type(type_node);
            return;
        }

        let names = children_by_field(node, "name");
        for name in names
            .iter()
            .copied()
            .map(Some)
            .chain(names.is_empty().then_some(None))
        {
            if let Some(name) = name {
                let declaration = self.add_declaration_identifier_site(
                    node,
                    name,
                    ResolutionSiteKind::ValueDeclaration,
                    literal.scope,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                    None,
                );
                self.mark_lexical_declaration(declaration, DeclarationKind::Parameter);
                self.facts.binders.push(ResolutionBinderFact {
                    declaration,
                    scope: literal.scope,
                    kind: ResolutionBinderKind::Parameter,
                    hoisting: HoistingClass::SourceOrder,
                    activation_start: literal.activation_start,
                    activation_end: literal.activation_end,
                });
                self.attach_declaration_type(
                    declaration,
                    type_node,
                    DeclarationTypeRole::Parameter,
                    true,
                );
                self.record_value_name(literal.scope, name);
            } else {
                let declaration = self.add_site_in_scope(
                    node,
                    ResolutionSiteKind::ValueDeclaration,
                    literal.scope,
                );
                let syntax = self.lower_type(type_node);
                let value_type = self.add_slot(declaration, ResolutionTypeSlotRole::DeclaredValue);
                self.add_transfer(
                    syntax.input,
                    value_type,
                    ResolutionTypeTransferKind::DeclaredType,
                    syntax.indirection_delta,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                );
            }
        }
    }

    fn lower_value_binding(&mut self, spec: Node<'_>, name: Node<'_>) -> ResolutionSiteId {
        let binding_scope = self.declaration_scope();
        let scope = *self.scope(binding_scope);
        let package_wide = scope.kind == ResolutionScopeKind::Package;
        let declaration_kind = match spec.kind() {
            "var_spec" => "var_declaration",
            "const_spec" => "const_declaration",
            _ => unreachable!("value binding requires a var or const spec"),
        };
        let declaration_node = sole_spec_declaration_node(spec, spec.kind(), declaration_kind);
        let declaration = self.add_declaration_identifier_site(
            declaration_node,
            name,
            ResolutionSiteKind::ValueDeclaration,
            binding_scope,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
            None,
        );
        if !package_wide {
            self.mark_lexical_declaration(declaration, DeclarationKind::LocalVariable);
        }
        self.facts.binders.push(ResolutionBinderFact {
            declaration,
            scope: binding_scope,
            kind: ResolutionBinderKind::Local,
            hoisting: if package_wide {
                HoistingClass::ScopeWide
            } else {
                HoistingClass::SourceOrder
            },
            activation_start: if package_wide {
                scope.start_byte
            } else {
                spec.end_byte()
            },
            activation_end: scope.end_byte,
        });
        self.publish_root_export(declaration, name, ResolutionNamespace::Value);
        self.record_value_name(binding_scope, name);
        declaration
    }

    fn lower_const_spec(&mut self, node: Node<'tree>) {
        let names = children_by_field(node, "name")
            .into_iter()
            .filter(|name| name.kind() == "identifier")
            .collect::<Vec<_>>();
        let type_node = node.child_by_field_name("type");
        let values = node
            .child_by_field_name("value")
            .map(expression_children)
            .unwrap_or_default();
        let value_slots = values
            .iter()
            .copied()
            .map(|value| self.lower_const_initializer(value))
            .collect::<Vec<_>>();
        let one_to_one = value_slots.len() == names.len();
        for (index, name) in names.into_iter().enumerate() {
            if go_node_text(name, self.source).trim() == "_" {
                continue;
            }
            let declaration = self.lower_value_binding(node, name);
            if let Some(type_node) = type_node {
                self.attach_declaration_type(
                    declaration,
                    type_node,
                    DeclarationTypeRole::Value,
                    false,
                );
            } else if !one_to_one {
                // Untyped constants have no default runtime type. Inherited
                // const specs also require their preceding expression/type list.
                // Keep the lexical binding complete when its value expression
                // is present; that expression's own slot carries the type gap.
                self.add_gap(declaration, ResolutionGapKind::InferredType);
            }
            if one_to_one {
                let observed = self.add_slot(declaration, ResolutionTypeSlotRole::AssignmentValue);
                self.add_transfer(
                    value_slots[index],
                    observed,
                    ResolutionTypeTransferKind::Assignment,
                    0,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                );
            } else {
                // Do not invent an initializer for implicit repeated specs or
                // select one expression from a malformed cardinality mismatch.
                self.add_gap(declaration, ResolutionGapKind::UnsupportedExpression);
            }
        }
    }

    fn lower_const_initializer(&mut self, root: Node<'_>) -> ResolutionTypeSlotId {
        let mut node = root;
        while node.kind() == "parenthesized_expression" {
            let Some(inner) = first_named_child(node) else {
                break;
            };
            node = inner;
        }
        if node.kind() == "identifier" {
            // This preserves ordinary references, including a shadowed iota.
            // Constant evaluation and the predeclared iota value remain open.
            self.lower_value_reference(node);
        } else {
            // The shared intrinsic vocabulary cannot represent Go's untyped
            // constants. A default string/bool/rune seed would fabricate a type.
            self.lower_unsupported_expression(node);
        }
        let slot = self.expression_slot(node);
        self.add_gap(
            self.facts.type_slots[slot.index()].site,
            ResolutionGapKind::UnsupportedExpression,
        );
        self.expression_slots_by_node.insert(root.id(), slot);
        slot
    }

    fn lower_var_spec(&mut self, node: Node<'tree>) {
        let names = children_by_field(node, "name")
            .into_iter()
            .filter(|name| name.kind() == "identifier")
            .collect::<Vec<_>>();
        let type_node = node.child_by_field_name("type");
        let values = node
            .child_by_field_name("value")
            .map(expression_children)
            .unwrap_or_default();
        let value_slots = values
            .iter()
            .copied()
            .map(|value| self.lower_expression(value))
            .collect::<Vec<_>>();
        let one_to_one = value_slots.is_empty() || value_slots.len() == names.len();
        for (index, name) in names.into_iter().enumerate() {
            if go_node_text(name, self.source).trim() == "_" {
                continue;
            }
            let declaration = self.lower_value_binding(node, name);
            if let Some(type_node) = type_node {
                self.attach_declaration_type(
                    declaration,
                    type_node,
                    DeclarationTypeRole::Value,
                    true,
                );
            } else if one_to_one && let Some(&input) = value_slots.get(index) {
                self.attach_initializer_type(declaration, input);
            } else {
                self.add_gap(declaration, ResolutionGapKind::InferredType);
            }
            if one_to_one && let Some(&input) = value_slots.get(index) {
                let observed = self.add_slot(declaration, ResolutionTypeSlotRole::AssignmentValue);
                self.add_transfer(
                    input,
                    observed,
                    ResolutionTypeTransferKind::Assignment,
                    0,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: true },
                );
            } else if !value_slots.is_empty() {
                self.add_gap(declaration, ResolutionGapKind::UnsupportedExpression);
            }
        }
    }

    fn lower_range_clause(&mut self, node: Node<'tree>) {
        let Some(right) = node.child_by_field_name("right") else {
            let site = self.add_site(node, ResolutionSiteKind::UnsupportedExpression);
            self.add_gap(site, ResolutionGapKind::MalformedSyntax);
            return;
        };
        self.lower_expression(right);
        let left = node
            .child_by_field_name("left")
            .map(expression_children)
            .unwrap_or_default();
        let short_declaration = (0..node.child_count())
            .any(|index| node.child(index).is_some_and(|child| child.kind() == ":="));
        if !short_declaration {
            for target in left {
                self.lower_expression(target);
            }
            return;
        }

        let binding_scope = self.current_scope();
        let scope = *self.scope(binding_scope);
        for (index, name) in left.into_iter().enumerate() {
            if name.kind() != "identifier" {
                let site = self.add_site(name, ResolutionSiteKind::UnsupportedDeclaration);
                self.add_gap(site, ResolutionGapKind::MalformedSyntax);
                continue;
            }
            let spelling = go_node_text(name, self.source).trim();
            if spelling == "_" {
                continue;
            }
            let declaration = self.add_declaration_identifier_site(
                node,
                name,
                ResolutionSiteKind::ValueDeclaration,
                binding_scope,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Value,
                None,
            );
            self.mark_lexical_declaration(declaration, DeclarationKind::LocalVariable);
            self.facts.binders.push(ResolutionBinderFact {
                declaration,
                scope: binding_scope,
                kind: ResolutionBinderKind::Local,
                hoisting: HoistingClass::SourceOrder,
                activation_start: node.end_byte(),
                activation_end: scope.end_byte,
            });
            let output = self.add_slot(declaration, ResolutionTypeSlotRole::DeclaredValue);
            self.facts
                .declaration_type_slots
                .push(DeclarationTypeSlotFact {
                    declaration,
                    slot: output,
                    role: DeclarationTypeRole::Value,
                });
            self.add_transfer(
                self.expression_slot(right),
                output,
                if index == 0 {
                    ResolutionTypeTransferKind::ComponentKey
                } else {
                    ResolutionTypeTransferKind::ComponentValue
                },
                0,
                ResolutionTypeTransferValueTransform::ToRuntime { addressable: true },
            );
            self.record_value_name(binding_scope, name);
        }
    }

    fn lower_short_var_declaration(&mut self, node: Node<'tree>) {
        let Some(left) = node.child_by_field_name("left") else {
            let site = self.add_site(node, ResolutionSiteKind::UnsupportedDeclaration);
            self.add_gap(site, ResolutionGapKind::MalformedSyntax);
            return;
        };
        let Some(right) = node.child_by_field_name("right") else {
            let site = self.add_site(node, ResolutionSiteKind::UnsupportedDeclaration);
            self.add_gap(site, ResolutionGapKind::MalformedSyntax);
            return;
        };
        let lhs = expression_children(left);
        let rhs = expression_children(right);
        let lhs_count = lhs.len();
        let rhs_slots = rhs
            .iter()
            .copied()
            .map(|value| self.lower_expression(value))
            .collect::<Vec<_>>();
        let one_to_one = lhs.len() == rhs_slots.len();
        let multi_result_slots =
            if rhs.len() == 1 && lhs_count > 1 && rhs[0].kind() == "call_expression" {
                let call_node = rhs[0];
                let call_result = self.expression_slot(call_node);
                let call_site = self.slot(call_result).site;
                let (call, callee, first_result) = self
                    .facts
                    .calls
                    .iter()
                    .find(|fact| fact.call == call_site)
                    .map(|fact| (fact.call, fact.callee, fact.result))
                    .expect("lowered Go call expression has a call fact");
                let mut results = Vec::with_capacity(lhs_count);
                results.push(first_result);
                for _ in 1..lhs_count {
                    let output = self.add_slot(call, ResolutionTypeSlotRole::CallResult);
                    self.facts.binding_projections.push(BindingProjectionFact {
                        reference: callee,
                        output,
                        kind: BindingProjectionKind::TargetCallableResultType,
                    });
                    results.push(output);
                }
                self.facts
                    .calls
                    .iter_mut()
                    .find(|fact| fact.call == call)
                    .expect("the Go call fact remains present")
                    .extra_result_slots = results[1..].to_vec();
                Some(results)
            } else {
                None
            };
        let binding_scope = self.current_scope();
        let scope = *self.scope(binding_scope);
        for (index, name) in lhs.into_iter().enumerate() {
            if name.kind() != "identifier" {
                let site = self.add_site(name, ResolutionSiteKind::UnsupportedDeclaration);
                self.add_gap(site, ResolutionGapKind::UnsupportedRoute);
                continue;
            }
            let spelling = go_node_text(name, self.source).trim();
            if spelling == "_" {
                continue;
            }
            if self.value_name_is_declared(binding_scope, spelling) {
                let reference = self.add_identifier_site(
                    name,
                    ResolutionSiteKind::ValueReference,
                    binding_scope,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Value,
                    None,
                );
                self.add_gap(reference, ResolutionGapKind::UnsupportedRoute);
                continue;
            }
            let declaration = self.add_declaration_identifier_site(
                node,
                name,
                ResolutionSiteKind::ValueDeclaration,
                binding_scope,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Value,
                None,
            );
            self.mark_lexical_declaration(declaration, DeclarationKind::LocalVariable);
            self.facts.binders.push(ResolutionBinderFact {
                declaration,
                scope: binding_scope,
                kind: ResolutionBinderKind::Local,
                hoisting: HoistingClass::SourceOrder,
                activation_start: node.end_byte(),
                activation_end: scope.end_byte,
            });
            let initializer = multi_result_slots
                .as_ref()
                .and_then(|results| results.get(index).copied())
                .or_else(|| one_to_one.then(|| rhs_slots[index]));
            if let Some(initializer) = initializer {
                self.attach_initializer_type(declaration, initializer);
                let observed = self.add_slot(declaration, ResolutionTypeSlotRole::AssignmentValue);
                self.add_transfer(
                    initializer,
                    observed,
                    ResolutionTypeTransferKind::Assignment,
                    0,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: true },
                );
            } else {
                self.add_gap(declaration, ResolutionGapKind::InferredType);
                self.add_gap(declaration, ResolutionGapKind::UnsupportedExpression);
            }
            self.record_value_name(binding_scope, name);
        }
    }

    fn attach_initializer_type(
        &mut self,
        declaration: ResolutionSiteId,
        input: ResolutionTypeSlotId,
    ) {
        let output = self.add_slot(declaration, ResolutionTypeSlotRole::DeclaredValue);
        self.facts
            .declaration_type_slots
            .push(DeclarationTypeSlotFact {
                declaration,
                slot: output,
                role: DeclarationTypeRole::Value,
            });
        self.add_transfer(
            input,
            output,
            ResolutionTypeTransferKind::Initialization,
            0,
            ResolutionTypeTransferValueTransform::AddressableRuntimeOnly,
        );
    }

    fn lower_return(&mut self, node: Node<'tree>) {
        if self
            .function_literal_contexts
            .last()
            .is_some_and(|literal| {
                literal.activation_start <= node.start_byte()
                    && node.end_byte() <= literal.activation_end
            })
        {
            let site = self.add_site(node, ResolutionSiteKind::UnsupportedExpression);
            self.add_gap(site, ResolutionGapKind::UnsupportedExpression);
            if let Some(values) = first_named_child(node).map(expression_children) {
                for value in values {
                    self.lower_expression(value);
                }
            }
            return;
        }
        let Some(callable) = self.callable_contexts.last().copied() else {
            let site = self.add_site(node, ResolutionSiteKind::UnsupportedExpression);
            self.add_gap(site, ResolutionGapKind::UnsupportedRoute);
            return;
        };
        let values = first_named_child(node)
            .map(expression_children)
            .unwrap_or_default();
        if values.is_empty() {
            return;
        }
        if values.len() != 1 {
            self.add_gap(
                callable.declaration,
                ResolutionGapKind::UnsupportedExpression,
            );
            for value in values {
                self.lower_expression(value);
            }
            return;
        }
        let input = self.lower_expression(values[0]);
        let observed = self.add_slot(callable.declaration, ResolutionTypeSlotRole::ReturnValue);
        self.add_transfer(
            input,
            observed,
            ResolutionTypeTransferKind::Return,
            0,
            ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
        );
    }

    fn lower_assignment_statement(&mut self, node: Node<'tree>) {
        let left = node
            .child_by_field_name("left")
            .map(expression_children)
            .unwrap_or_default();
        let right = node
            .child_by_field_name("right")
            .map(expression_children)
            .unwrap_or_default();
        let right_count = right.len();
        for target in &left {
            self.lower_expression(*target);
        }
        for value in right {
            self.lower_expression(value);
        }
        let only_blank_targets = !left.is_empty()
            && left.iter().all(|target| {
                target.kind() == "identifier" && go_node_text(*target, self.source).trim() == "_"
            });
        let simple_assignment = (0..node.child_count())
            .any(|index| node.child(index).is_some_and(|child| child.kind() == "="));
        let references_lowered = simple_assignment && !left.is_empty() && left.len() == right_count;
        if !only_blank_targets && !references_lowered {
            let site = self.add_site(node, ResolutionSiteKind::UnsupportedExpression);
            self.add_gap(site, ResolutionGapKind::UnsupportedRoute);
        }
    }

    fn attach_declaration_type(
        &mut self,
        declaration: ResolutionSiteId,
        type_node: Node<'tree>,
        role: DeclarationTypeRole,
        addressable: bool,
    ) -> ResolutionTypeSlotId {
        if type_node.kind() == "function_type" {
            let output = self.add_declaration_type_slot(declaration, role);
            self.lower_function_value_signature(declaration, type_node);
            return output;
        }
        let syntax = self.lower_type(type_node);
        self.attach_declaration_type_syntax(declaration, syntax, role, addressable)
    }

    fn add_declaration_type_slot(
        &mut self,
        declaration: ResolutionSiteId,
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
        output
    }

    fn attach_declaration_type_syntax(
        &mut self,
        declaration: ResolutionSiteId,
        syntax: LoweredTypeSyntax,
        role: DeclarationTypeRole,
        addressable: bool,
    ) -> ResolutionTypeSlotId {
        let output = self.add_declaration_type_slot(declaration, role);
        self.add_transfer(
            syntax.input,
            output,
            ResolutionTypeTransferKind::DeclaredType,
            syntax.indirection_delta,
            ResolutionTypeTransferValueTransform::ToRuntime { addressable },
        );
        output
    }

    /// Peel only grammar-owned pointer/parenthesized wrappers. The base type
    /// remains a target-independent reference or intrinsic seed, and pointer
    /// depth stays a signed transfer delta rather than source text parsing.
    fn lower_type(&mut self, root: Node<'tree>) -> LoweredTypeSyntax {
        if let Some(syntax) = self.type_syntax_by_node.get(&root.id()) {
            return *syntax;
        }
        // Expression postorder can reach a type before the outer declaration
        // walk visits it. Capture through the same idempotent AST collector.
        let Some(root_type_id) = self.capture_source_type(root) else {
            return self.lower_gap_type(root, ResolutionGapKind::MalformedSyntax);
        };
        let mut current = root;
        let mut current_type_id = root_type_id;
        let mut pointer_depth = 0usize;
        loop {
            match self.source_properties.type_shape(current_type_id) {
                GoSourceTypeShape::Pointer(inner) => {
                    pointer_depth = pointer_depth.saturating_add(1);
                    let Some(inner_node) = first_named_child(current) else {
                        return self.lower_gap_type(root, ResolutionGapKind::MalformedSyntax);
                    };
                    current = inner_node;
                    current_type_id = *inner;
                }
                GoSourceTypeShape::Compound {
                    kind: GoTypeCompoundKind::Parenthesized,
                    children,
                } if children.len() == 1 => {
                    let Some(inner) = first_named_child(current) else {
                        return self.lower_gap_type(root, ResolutionGapKind::MalformedSyntax);
                    };
                    current = inner;
                    current_type_id = children[0];
                }
                _ => break,
            }
        }
        let Ok(indirection_delta) = i8::try_from(pointer_depth) else {
            return self.lower_gap_type(root, ResolutionGapKind::UnsupportedTypeSyntax);
        };
        let base = match (
            current.kind(),
            self.source_properties.type_shape(current_type_id),
        ) {
            // Go's universe-block type names are ordinary, shadowable
            // identifiers. Even `string` may bind a package declaration in a
            // different file, so syntax alone never makes it intrinsic.
            ("type_identifier" | "identifier", GoSourceTypeShape::Named(_)) => {
                self.lower_plain_type_reference(current)
            }
            ("qualified_type", GoSourceTypeShape::Named(_)) => self.lower_qualified_type(current),
            ("array_type" | "slice_type" | "implicit_length_array_type", _) => self
                .lower_structural_type(
                    current,
                    ResolutionTypeConstructorKind::Sequence,
                    [(ResolutionTypeComponentKind::Element, "element")],
                ),
            ("map_type", _) => self.lower_structural_type(
                current,
                ResolutionTypeConstructorKind::Map,
                [
                    (ResolutionTypeComponentKind::Key, "key"),
                    (ResolutionTypeComponentKind::Value, "value"),
                ],
            ),
            ("channel_type", _) => self.lower_structural_type(
                current,
                ResolutionTypeConstructorKind::Channel,
                [(ResolutionTypeComponentKind::Element, "value")],
            ),
            _ => self.lower_gap_type(current, ResolutionGapKind::UnsupportedTypeSyntax),
        };
        let syntax = LoweredTypeSyntax {
            input: base.input,
            indirection_delta: base
                .indirection_delta
                .checked_add(indirection_delta)
                .unwrap_or_else(|| {
                    self.add_gap(
                        self.slot(base.input).site,
                        ResolutionGapKind::UnsupportedTypeSyntax,
                    );
                    0
                }),
        };
        self.type_syntax_by_node.insert(root.id(), syntax);
        syntax
    }

    fn lower_structural_type<const N: usize>(
        &mut self,
        node: Node<'tree>,
        constructor: ResolutionTypeConstructorKind,
        components: [(ResolutionTypeComponentKind, &'static str); N],
    ) -> LoweredTypeSyntax {
        let site = self.add_site(node, ResolutionSiteKind::TypeReference);
        let container = self.add_slot(site, ResolutionTypeSlotRole::TargetTypeIdentity);
        let name = self.intern_name("structural-type");
        self.facts.intrinsic_type_seeds.push(IntrinsicTypeSeedFact {
            output: container,
            name,
            kind: IntrinsicTypeKind::Structural,
            indirection: 0,
        });
        for (kind, field) in components {
            let Some(component_node) = node.child_by_field_name(field) else {
                self.add_gap(site, ResolutionGapKind::MalformedSyntax);
                continue;
            };
            let syntax = self.lower_type(component_node);
            let component = self.materialize_type_syntax(syntax);
            self.facts
                .type_components
                .push(ResolutionTypeComponentFact {
                    container,
                    constructor,
                    kind,
                    component,
                });
        }
        LoweredTypeSyntax {
            input: container,
            indirection_delta: 0,
        }
    }

    fn materialize_type_syntax(&mut self, syntax: LoweredTypeSyntax) -> ResolutionTypeSlotId {
        if syntax.indirection_delta == 0 {
            return syntax.input;
        }
        let site = self.slot(syntax.input).site;
        let output = self.add_slot(site, ResolutionTypeSlotRole::TargetTypeIdentity);
        self.add_transfer(
            syntax.input,
            output,
            ResolutionTypeTransferKind::TypeAlias,
            syntax.indirection_delta,
            ResolutionTypeTransferValueTransform::Preserve,
        );
        output
    }

    fn lower_qualified_type(&mut self, node: Node<'_>) -> LoweredTypeSyntax {
        let (Some(package), Some(name)) = (
            node.child_by_field_name("package"),
            node.child_by_field_name("name"),
        ) else {
            return self.lower_gap_type(node, ResolutionGapKind::MalformedSyntax);
        };
        self.lower_qualifier_reference(package);
        let syntax = self.lower_plain_type_reference(name);
        let reference = self.facts.type_slots[syntax.input.index()].site;
        // Go qualified_type names a package type, not a runtime object's member.
        self.add_qualified_root_reference(package, reference);
        self.add_gap(reference, ResolutionGapKind::UnsupportedRoute);
        syntax
    }

    fn lower_qualifier_reference(&mut self, node: Node<'_>) {
        let scope = self.scope_for_source_node(node);
        let reference = self.add_identifier_site(
            node,
            ResolutionSiteKind::ValueReference,
            scope,
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::TypeOrValue,
            None,
        );
        let output = self.add_slot(reference, ResolutionTypeSlotRole::ExpressionValue);
        self.facts.binding_projections.push(BindingProjectionFact {
            reference,
            output,
            kind: BindingProjectionKind::TargetTypeOrDeclaredValueType,
        });
        self.expression_slots_by_node.insert(node.id(), output);
    }

    fn add_qualified_root_reference(&mut self, prefix: Node<'_>, reference: ResolutionSiteId) {
        let prefix_reference = self.facts.type_slots[self.expression_slot(prefix).index()].site;
        let name = self.intern_name(go_node_text(prefix, self.source).trim());
        self.facts
            .root_references
            .push(ResolutionRootReferenceFact {
                reference,
                root_scope: ResolutionScopeId::new(1),
                anchor: ResolutionRootImportAnchor::Lexical,
                prefix_reference: Some(prefix_reference),
            });
        self.facts
            .root_reference_segments
            .push(ResolutionRootReferenceSegmentFact {
                reference,
                position: 0,
                name,
            });
    }

    fn lower_plain_type_reference(&mut self, node: Node<'_>) -> LoweredTypeSyntax {
        if let Some(syntax) = self.type_syntax_by_node.get(&node.id()) {
            return *syntax;
        }
        let scope = self.scope_for_source_node(node);
        let reference = self.add_identifier_site(
            node,
            ResolutionSiteKind::TypeReference,
            scope,
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Type,
            None,
        );
        let output = self.add_slot(reference, ResolutionTypeSlotRole::TargetTypeIdentity);
        self.facts.binding_projections.push(BindingProjectionFact {
            reference,
            output,
            kind: BindingProjectionKind::TargetTypeIdentity,
        });
        let syntax = LoweredTypeSyntax {
            input: output,
            indirection_delta: 0,
        };
        self.type_syntax_by_node.insert(node.id(), syntax);
        syntax
    }

    fn lower_gap_type(&mut self, node: Node<'_>, kind: ResolutionGapKind) -> LoweredTypeSyntax {
        if let Some(syntax) = self.type_syntax_by_node.get(&node.id()) {
            return *syntax;
        }
        let scope = self.scope_for_source_node(node);
        let site = self.add_site_in_scope(node, ResolutionSiteKind::UnsupportedExpression, scope);
        let output = self.add_slot(site, ResolutionTypeSlotRole::TargetTypeIdentity);
        self.add_gap(site, kind);
        let syntax = LoweredTypeSyntax {
            input: output,
            indirection_delta: 0,
        };
        self.type_syntax_by_node.insert(node.id(), syntax);
        syntax
    }

    /// Iterative expression postorder. Each dependency is lowered before its
    /// consumer without recursive Rust calls, including arbitrarily deep Go
    /// selector chains.
    fn lower_expression(&mut self, root: Node<'tree>) -> ResolutionTypeSlotId {
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
                "selector_expression" => {
                    stack.push((node, true));
                    if let Some(operand) = node.child_by_field_name("operand") {
                        stack.push((operand, false));
                    }
                }
                "call_expression" => {
                    stack.push((node, true));
                    if let Some(arguments) = node.child_by_field_name("arguments") {
                        let values = named_children(arguments);
                        stack.extend(values.into_iter().rev().map(|value| (value, false)));
                    }
                    if let Some(function) = node.child_by_field_name("function") {
                        if function.kind() == "selector_expression" {
                            if let Some(operand) = function.child_by_field_name("operand") {
                                stack.push((operand, false));
                            }
                        } else if !matches!(
                            function.kind(),
                            "identifier" | "type_identifier" | "field_identifier"
                        ) {
                            stack.push((function, false));
                        }
                    }
                }
                "binary_expression" => {
                    stack.push((node, true));
                    if let Some(right) = node.child_by_field_name("right") {
                        stack.push((right, false));
                    }
                    if let Some(left) = node.child_by_field_name("left") {
                        stack.push((left, false));
                    }
                }
                "parenthesized_expression" | "unary_expression" => {
                    stack.push((node, true));
                    if let Some(inner) = node
                        .child_by_field_name("operand")
                        .or_else(|| first_named_child(node))
                    {
                        stack.push((inner, false));
                    }
                }
                "identifier"
                | "type_identifier"
                | "composite_literal"
                | "interpreted_string_literal"
                | "raw_string_literal"
                | "rune_literal"
                | "int_literal"
                | "float_literal"
                | "imaginary_literal"
                | "true"
                | "false"
                | "nil" => self.finish_expression(node),
                _ => self.lower_unsupported_expression(node),
            }
        }
        *self
            .expression_slots_by_node
            .get(&root.id())
            .expect("expression postorder always publishes its root slot")
    }

    fn finish_expression(&mut self, node: Node<'tree>) {
        if self.expression_slots_by_node.contains_key(&node.id()) {
            return;
        }
        match node.kind() {
            "identifier"
                if {
                    // Parentheses and stars preserve the selector's type-or-value
                    // ambiguity until binding identifies the operand category.
                    let mut current = node;
                    loop {
                        let Some(parent) = current.parent() else {
                            break false;
                        };
                        match parent.kind() {
                            "parenthesized_expression" => current = parent,
                            "unary_expression"
                                if parent
                                    .child_by_field_name("operator")
                                    .is_some_and(|operator| operator.kind() == "*") =>
                            {
                                current = parent
                            }
                            "selector_expression" => {
                                break parent
                                    .child_by_field_name("operand")
                                    .is_some_and(|operand| operand.id() == current.id());
                            }
                            _ => break false,
                        }
                    }
                } =>
            {
                self.lower_qualifier_reference(node)
            }
            "identifier" => self.lower_value_reference(node),
            "type_identifier" => self.lower_type_or_value_reference(node),
            "selector_expression" => self.finish_selector(node),
            "call_expression" => self.finish_call(node),
            "binary_expression" => self.lower_unsupported_expression(node),
            "composite_literal" => self.finish_composite_literal(node),
            "parenthesized_expression" => {
                let Some(inner) = first_named_child(node) else {
                    self.lower_unsupported_expression(node);
                    return;
                };
                let slot = self.expression_slot(inner);
                self.expression_slots_by_node.insert(node.id(), slot);
            }
            "unary_expression" => {
                if node
                    .child_by_field_name("operator")
                    .is_some_and(|operator| operator.kind() == "*")
                    && let Some(operand) = node.child_by_field_name("operand")
                {
                    let site = self.add_site(node, ResolutionSiteKind::UnaryExpression);
                    let output = self.add_slot(site, ResolutionTypeSlotRole::ExpressionValue);
                    let input = self.expression_slot(operand);
                    // Category filters are disjoint. Fixed deltas preserve the
                    // shared cycle analysis while binding decides the meaning.
                    for (delta, transform) in [
                        (1, ResolutionTypeTransferValueTransform::TypeObjectOnly),
                        (
                            -1,
                            ResolutionTypeTransferValueTransform::AddressableRuntimeOnly,
                        ),
                    ] {
                        self.add_transfer(
                            input,
                            output,
                            ResolutionTypeTransferKind::UnaryIndirection,
                            delta,
                            transform,
                        );
                    }
                    self.expression_slots_by_node.insert(node.id(), output);
                } else if node
                    .child_by_field_name("operator")
                    .is_some_and(|operator| operator.kind() == "&")
                    && let Some(operand) = node.child_by_field_name("operand")
                {
                    // Go permits taking the address of a (possibly parenthesized)
                    // composite literal even though its value is not addressable.
                    let mut unwrapped = operand;
                    while unwrapped.kind() == "parenthesized_expression" {
                        let Some(inner) = first_named_child(unwrapped) else {
                            self.lower_unsupported_expression(node);
                            return;
                        };
                        unwrapped = inner;
                    }
                    let transform = if unwrapped.kind() == "composite_literal" {
                        ResolutionTypeTransferValueTransform::RuntimeOnly
                    } else {
                        ResolutionTypeTransferValueTransform::AddressableOperandOnly
                    };
                    let site = self.add_site(node, ResolutionSiteKind::UnaryExpression);
                    let output = self.add_slot(site, ResolutionTypeSlotRole::ExpressionValue);
                    self.add_transfer(
                        self.expression_slot(operand),
                        output,
                        ResolutionTypeTransferKind::AddressOf,
                        1,
                        transform,
                    );
                    self.expression_slots_by_node.insert(node.id(), output);
                } else {
                    self.lower_unsupported_expression(node);
                }
            }
            "interpreted_string_literal" | "raw_string_literal" => {
                self.lower_intrinsic_literal(node, "string", IntrinsicTypeKind::Primitive)
            }
            "rune_literal" => {
                self.lower_intrinsic_literal(node, "rune", IntrinsicTypeKind::Primitive)
            }
            "true" | "false" => {
                self.lower_intrinsic_literal(node, "bool", IntrinsicTypeKind::Primitive)
            }
            "int_literal" | "float_literal" | "imaginary_literal" => self
                .lower_unsupported_expression_as(node, ResolutionGapKind::AmbiguousNumericLiteral),
            "nil" => self.lower_unsupported_expression(node),
            _ => self.lower_unsupported_expression(node),
        }
    }

    fn lower_value_reference(&mut self, node: Node<'_>) {
        let reference = self.add_identifier_site(
            node,
            ResolutionSiteKind::ValueReference,
            self.current_scope(),
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Value,
            None,
        );
        let output = self.add_slot(reference, ResolutionTypeSlotRole::ExpressionValue);
        self.facts.binding_projections.push(BindingProjectionFact {
            reference,
            output,
            kind: BindingProjectionKind::TargetDeclaredValueType,
        });
        self.expression_slots_by_node.insert(node.id(), output);
    }

    fn lower_type_or_value_reference(&mut self, node: Node<'_>) {
        let reference = self.add_identifier_site(
            node,
            ResolutionSiteKind::ValueReference,
            self.current_scope(),
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::TypeOrValue,
            None,
        );
        let output = self.add_slot(reference, ResolutionTypeSlotRole::ExpressionValue);
        self.facts.binding_projections.push(BindingProjectionFact {
            reference,
            output,
            kind: BindingProjectionKind::TargetTypeOrDeclaredValueType,
        });
        self.expression_slots_by_node.insert(node.id(), output);
    }

    fn finish_selector(&mut self, node: Node<'tree>) {
        let Some(operand) = node.child_by_field_name("operand") else {
            self.lower_unsupported_expression(node);
            return;
        };
        let Some(field) = node.child_by_field_name("field") else {
            self.lower_unsupported_expression(node);
            return;
        };
        let reference = self.add_site(field, ResolutionSiteKind::MemberReference);
        let receiver = self.add_slot(reference, ResolutionTypeSlotRole::Receiver);
        let type_or_value = self.is_method_expression_type_operand(node);
        self.add_transfer(
            self.expression_slot(operand),
            receiver,
            ResolutionTypeTransferKind::Receiver,
            0,
            ResolutionTypeTransferValueTransform::Preserve,
        );
        self.add_identifier_to_site(
            reference,
            field,
            ResolutionIdentifierRole::Reference,
            if type_or_value {
                ResolutionNamespace::TypeOrValue
            } else {
                ResolutionNamespace::Value
            },
            Some(receiver),
        );
        if operand.kind() == "identifier" {
            self.add_qualified_root_reference(operand, reference);
        }
        let output = self.add_slot(reference, ResolutionTypeSlotRole::ExpressionValue);
        self.facts.binding_projections.push(BindingProjectionFact {
            reference,
            output,
            kind: if type_or_value {
                BindingProjectionKind::TargetTypeOrDeclaredValueType
            } else {
                BindingProjectionKind::TargetDeclaredValueType
            },
        });
        self.expression_slots_by_node.insert(node.id(), output);
    }

    /// A selector used as the operand of a call's selector callee is
    /// structurally ambiguous between a package value and a type qualifier.
    /// Keep both possibilities in facts so selected package/type resolution
    /// can choose the right one; don't infer from the selector's spelling.
    fn is_method_expression_type_operand(&self, node: Node<'tree>) -> bool {
        let mut current = node;
        loop {
            let Some(parent) = current.parent() else {
                return false;
            };
            match parent.kind() {
                "parenthesized_expression" => current = parent,
                "unary_expression"
                    if parent
                        .child_by_field_name("operator")
                        .is_some_and(|operator| operator.kind() == "*") =>
                {
                    current = parent;
                }
                "selector_expression"
                    if parent
                        .child_by_field_name("operand")
                        .is_some_and(|operand| operand.id() == current.id()) =>
                {
                    return parent.parent().is_some_and(|call| {
                        call.kind() == "call_expression"
                            && call
                                .child_by_field_name("function")
                                .is_some_and(|function| function.id() == parent.id())
                    });
                }
                _ => return false,
            }
        }
    }

    fn finish_call(&mut self, node: Node<'tree>) {
        let call = self.add_site(node, ResolutionSiteKind::Call);
        let function = node.child_by_field_name("function");
        let (callee, receiver) = match function {
            Some(function)
                if matches!(
                    function.kind(),
                    "identifier" | "type_identifier" | "field_identifier"
                ) =>
            {
                let callee = self.add_identifier_site(
                    function,
                    ResolutionSiteKind::CallableReference,
                    self.current_scope(),
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::TypeOrValue,
                    None,
                );
                (callee, None)
            }
            Some(function) if function.kind() == "selector_expression" => {
                let Some(operand) = function.child_by_field_name("operand") else {
                    self.finish_unsupported_call(node, call);
                    return;
                };
                let Some(field) = function.child_by_field_name("field") else {
                    self.finish_unsupported_call(node, call);
                    return;
                };
                let receiver = self.add_slot(call, ResolutionTypeSlotRole::Receiver);
                self.add_transfer(
                    self.expression_slot(operand),
                    receiver,
                    ResolutionTypeTransferKind::Receiver,
                    0,
                    ResolutionTypeTransferValueTransform::Preserve,
                );
                let callee = self.add_identifier_site(
                    field,
                    ResolutionSiteKind::MemberReference,
                    self.current_scope(),
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Callable,
                    Some(receiver),
                );
                self.facts
                    .callable_receiver_origins
                    .push(ResolutionCallableReceiverOriginFact {
                        reference: callee,
                        origin: ResolutionCallableReceiverOrigin::ExplicitExpression,
                    });
                if operand.kind() == "identifier" {
                    self.add_qualified_root_reference(operand, callee);
                }
                (callee, Some(receiver))
            }
            _ => {
                self.finish_unsupported_call(node, call);
                return;
            }
        };
        // This gap belongs to invocation semantics. Go's argument-independent
        // name binding can select the callee without it; any result type still
        // comes from selected callable signature facts.
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
            extra_result_slots: Vec::new(),
            explicit_type_argument_count: explicit_type_argument_count(node),
        });
        self.facts
            .engine_rule_eligibilities
            .push(ResolutionEngineRuleEligibilityFact {
                site: call,
                rule: ResolutionEngineRuleKind::ArgumentIndependentBinding,
            });
        self.attach_call_arguments(node, call);
        self.expression_slots_by_node.insert(node.id(), result);
    }

    fn finish_unsupported_call(&mut self, node: Node<'_>, call: ResolutionSiteId) {
        let callee = self.add_site(node, ResolutionSiteKind::UnsupportedExpression);
        self.add_gap(callee, ResolutionGapKind::UnsupportedRoute);
        self.add_gap(callee, ResolutionGapKind::UnsupportedCallApplicability);
        let result = self.add_slot(call, ResolutionTypeSlotRole::CallResult);
        self.facts.calls.push(ResolutionCallFact {
            call,
            callee,
            receiver: None,
            result,
            extra_result_slots: Vec::new(),
            explicit_type_argument_count: explicit_type_argument_count(node),
        });
        self.attach_call_arguments(node, call);
        self.expression_slots_by_node.insert(node.id(), result);
    }

    fn attach_call_arguments(&mut self, node: Node<'_>, call: ResolutionSiteId) {
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        for (ordinal, argument) in named_children(arguments).into_iter().enumerate() {
            let input = self.expression_slot(argument);
            let value = self.add_slot(call, ResolutionTypeSlotRole::Argument);
            self.add_transfer(
                input,
                value,
                ResolutionTypeTransferKind::Argument,
                0,
                ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
            );
            self.facts.call_arguments.push(ResolutionCallArgumentFact {
                call,
                ordinal: dense_ordinal(ordinal, "Go call argument"),
                value,
            });
        }
    }

    fn finish_composite_literal(&mut self, node: Node<'tree>) {
        let Some(type_node) = node.child_by_field_name("type") else {
            self.lower_unsupported_expression(node);
            return;
        };
        let Some(body) = node.child_by_field_name("body") else {
            self.lower_unsupported_expression_as(node, ResolutionGapKind::MalformedSyntax);
            return;
        };
        let syntax = self.lower_type(type_node);
        let site = self.add_site(node, ResolutionSiteKind::Literal);
        let output = self.add_slot(site, ResolutionTypeSlotRole::ExpressionValue);
        self.add_transfer(
            syntax.input,
            output,
            ResolutionTypeTransferKind::Construction,
            syntax.indirection_delta,
            ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
        );
        let owner = self.materialize_type_syntax(syntax);
        self.lower_composite_literal_body(
            body,
            owner,
            match type_node.kind() {
                "map_type" => Some(ResolutionTypeConstructorKind::Map),
                "array_type" | "slice_type" | "implicit_length_array_type" => {
                    Some(ResolutionTypeConstructorKind::Sequence)
                }
                "channel_type" => Some(ResolutionTypeConstructorKind::Channel),
                _ => None,
            },
        );
        self.expression_slots_by_node.insert(node.id(), output);
    }

    fn lower_composite_literal_body(
        &mut self,
        body: Node<'tree>,
        owner_type: ResolutionTypeSlotId,
        constructor_hint: Option<ResolutionTypeConstructorKind>,
    ) {
        let mut pending = vec![(body, owner_type, constructor_hint)];
        while let Some((body, owner_type, constructor_hint)) = pending.pop() {
            for container_element in named_children(body) {
                let element = if container_element.kind() == "literal_element" {
                    first_named_child(container_element)
                } else {
                    Some(container_element)
                };
                let Some(element) = element else {
                    self.mark_unsupported_literal_element(container_element);
                    continue;
                };
                match element.kind() {
                    "keyed_element" => {
                        let (Some(key), Some(value)) = (
                            element.child_by_field_name("key"),
                            element.child_by_field_name("value"),
                        ) else {
                            self.mark_unsupported_literal_element(element);
                            continue;
                        };
                        let key = unwrap_literal_element(key);
                        let key_is_label = matches!(
                            key.kind(),
                            "identifier" | "type_identifier" | "field_identifier"
                        );
                        if constructor_hint == Some(ResolutionTypeConstructorKind::Map)
                            || !key_is_label
                        {
                            if key.kind() == "literal_value" {
                                self.lower_literal_component(
                                    key,
                                    owner_type,
                                    ResolutionTypeTransferKind::ComponentKey,
                                    &mut pending,
                                );
                            } else {
                                self.lower_expression(key);
                            }
                            self.lower_literal_component(
                                value,
                                owner_type,
                                ResolutionTypeTransferKind::ComponentValue,
                                &mut pending,
                            );
                        } else if constructor_hint == Some(ResolutionTypeConstructorKind::Sequence)
                        {
                            self.lower_expression(key);
                            self.lower_literal_component(
                                value,
                                owner_type,
                                ResolutionTypeTransferKind::ComponentElement,
                                &mut pending,
                            );
                        } else {
                            let field_type =
                                self.lower_struct_literal_field_reference(key, owner_type);
                            self.lower_elided_literal_from_value(value, field_type, &mut pending);
                        }
                    }
                    _ => {
                        self.lower_literal_component(
                            element,
                            owner_type,
                            ResolutionTypeTransferKind::ComponentElement,
                            &mut pending,
                        );
                    }
                }
            }
        }
    }

    fn lower_literal_component(
        &mut self,
        element: Node<'tree>,
        owner_type: ResolutionTypeSlotId,
        kind: ResolutionTypeTransferKind,
        pending: &mut Vec<(
            Node<'tree>,
            ResolutionTypeSlotId,
            Option<ResolutionTypeConstructorKind>,
        )>,
    ) {
        let mut value = element;
        while value.kind() == "literal_element" {
            let Some(child) = first_named_child(value) else {
                self.mark_unsupported_literal_element(value);
                return;
            };
            value = child;
        }
        if value.kind() == "literal_value" {
            let site = self.add_site(value, ResolutionSiteKind::Literal);
            let type_slot = self.add_slot(site, ResolutionTypeSlotRole::TargetTypeIdentity);
            self.add_transfer(
                owner_type,
                type_slot,
                kind,
                0,
                ResolutionTypeTransferValueTransform::Preserve,
            );
            pending.push((value, type_slot, None));
        } else {
            self.lower_expression(value);
        }
    }

    fn lower_elided_literal_from_value(
        &mut self,
        element: Node<'tree>,
        value_type: ResolutionTypeSlotId,
        pending: &mut Vec<(
            Node<'tree>,
            ResolutionTypeSlotId,
            Option<ResolutionTypeConstructorKind>,
        )>,
    ) {
        let value = unwrap_literal_element(element);
        if value.kind() != "literal_value" {
            self.lower_expression(value);
            return;
        }
        pending.push((value, value_type, None));
    }

    fn lower_struct_literal_field_reference(
        &mut self,
        field: Node<'tree>,
        owner_type: ResolutionTypeSlotId,
    ) -> ResolutionTypeSlotId {
        let reference = self.add_site(field, ResolutionSiteKind::CompositeLiteralKeyReference);
        let receiver = self.add_slot(reference, ResolutionTypeSlotRole::Receiver);
        self.add_transfer(
            owner_type,
            receiver,
            ResolutionTypeTransferKind::Receiver,
            0,
            ResolutionTypeTransferValueTransform::Preserve,
        );
        self.add_identifier_to_site(
            reference,
            field,
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Value,
            Some(receiver),
        );
        let output = self.add_slot(reference, ResolutionTypeSlotRole::ExpressionValue);
        self.facts.binding_projections.push(BindingProjectionFact {
            reference,
            output,
            kind: BindingProjectionKind::TargetDeclaredValueType,
        });
        output
    }

    fn mark_unsupported_literal_element(&mut self, node: Node<'tree>) {
        let site = self.add_site(node, ResolutionSiteKind::UnsupportedExpression);
        self.add_gap(site, ResolutionGapKind::UnsupportedExpression);
    }

    fn lower_intrinsic_literal(&mut self, node: Node<'_>, spelling: &str, kind: IntrinsicTypeKind) {
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
        self.expression_slots_by_node.insert(node.id(), output);
    }

    fn expression_slot(&self, node: Node<'_>) -> ResolutionTypeSlotId {
        *self
            .expression_slots_by_node
            .get(&node.id())
            .expect("expression dependency was lowered before its consumer")
    }

    fn record_value_name(&mut self, scope: ResolutionScopeId, node: Node<'_>) {
        let spelling = go_node_text(node, self.source).trim();
        if spelling != "_" {
            self.value_names_by_scope
                .entry(scope)
                .or_default()
                .insert(spelling.to_string());
        }
    }

    fn value_name_is_declared(&self, scope: ResolutionScopeId, spelling: &str) -> bool {
        self.value_names_by_scope
            .get(&scope)
            .is_some_and(|names| names.contains(spelling))
    }

    fn next_parameter_ordinal(&mut self, callable: ResolutionSiteId) -> u32 {
        let next = self.next_parameter_ordinal.entry(callable).or_insert(0);
        let ordinal = *next;
        *next = next
            .checked_add(1)
            .expect("Go callable parameter count exceeds u32");
        ordinal
    }
}

/// Preserve the Go producer's deliberately conservative enumeration contract.
///
/// Go has not yet separated every retained binding/type obligation from syntax
/// whose references might be skipped. Keeping this decision in the producer
/// prevents a shared lowerer from interpreting an ordinary gap kind as a
/// language-independent enumeration rule.
fn go_gap_blocks_reference_enumeration(kind: ResolutionGapKind) -> bool {
    matches!(
        kind,
        ResolutionGapKind::UnsupportedTypeSyntax
            | ResolutionGapKind::UnsupportedExpression
            | ResolutionGapKind::UnsupportedRoute
            | ResolutionGapKind::UnsupportedScopeOrBinder
            | ResolutionGapKind::MalformedSyntax
    )
}

fn expression_children(node: Node<'_>) -> Vec<Node<'_>> {
    if matches!(node.kind(), "expression_list" | "argument_list") {
        named_children(node)
    } else {
        vec![node]
    }
}

fn unwrap_literal_element(mut node: Node<'_>) -> Node<'_> {
    while node.kind() == "literal_element" {
        let Some(child) = first_named_child(node) else {
            break;
        };
        node = child;
    }
    node
}

fn dense_ordinal(index: usize, relation: &str) -> u32 {
    u32::try_from(index).unwrap_or_else(|_| panic!("{relation} count exceeds u32"))
}

fn explicit_type_argument_count(node: Node<'_>) -> u32 {
    node.child_by_field_name("type_arguments")
        .map_or(0, |arguments| {
            dense_ordinal(
                named_children(arguments).len(),
                "Go explicit invocation type argument",
            )
        })
}

fn callable_type_parameter_count(node: Node<'_>) -> u32 {
    node.child_by_field_name("type_parameters")
        .map_or(0, |parameters| {
            let declarations = named_children(parameters);
            assert!(
                declarations
                    .iter()
                    .all(|declaration| declaration.kind() == "type_parameter_declaration"),
                "Go callable type parameter list contains only declarations"
            );
            dense_ordinal(
                declarations
                    .into_iter()
                    .map(|declaration| children_by_field(declaration, "name").len())
                    .sum(),
                "Go callable type parameter",
            )
        })
}

fn go_dot_import_namespaces(namespace: ResolutionNamespace) -> &'static [ResolutionNamespace] {
    match namespace {
        ResolutionNamespace::Type
        | ResolutionNamespace::Value
        | ResolutionNamespace::Callable
        | ResolutionNamespace::TypeOrValue => &[
            ResolutionNamespace::Type,
            ResolutionNamespace::Value,
            ResolutionNamespace::Callable,
        ],
        _ => &[],
    }
}

fn validate_facts(facts: &FileResolutionFacts) {
    facts.validate_package_relations();
    for (index, name) in facts.names.iter().enumerate() {
        assert_eq!(name.id.index(), index);
        assert!(!name.spelling.is_empty());
    }
    for (index, scope) in facts.scopes.iter().enumerate() {
        assert_eq!(scope.id.index(), index);
        assert!(scope.start_byte <= scope.end_byte);
        if let Some(parent) = scope.parent {
            assert!(parent.index() < index);
            let parent = &facts.scopes[parent.index()];
            assert!(parent.start_byte <= scope.start_byte && scope.end_byte <= parent.end_byte);
        } else {
            assert_eq!(index, 0, "only the compilation-unit scope is a root");
        }
        if let Some(owner) = scope.owner {
            assert!(owner.index() < facts.sites.len());
        }
    }
    for (index, site) in facts.sites.iter().enumerate() {
        assert_eq!(site.id.index(), index);
        assert!(site.scope.index() < facts.scopes.len());
        let scope = &facts.scopes[site.scope.index()];
        assert!(scope.start_byte <= site.start_byte && site.end_byte <= scope.end_byte);
    }
    for identifier in &facts.identifiers {
        assert!(identifier.site.index() < facts.sites.len());
        assert!(identifier.name.index() < facts.names.len());
        if let Some(qualifier) = identifier.qualifier {
            assert!(qualifier.index() < facts.type_slots.len());
        }
    }
    let reference_sites = facts
        .identifiers
        .iter()
        .filter(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
        .map(|identifier| identifier.site)
        .collect::<HashSet<_>>();
    let mut owned_references = HashSet::default();
    for owner in &facts.reference_owners {
        assert!(owner.reference.index() < facts.sites.len());
        assert!(
            reference_sites.contains(&owner.reference),
            "Go reference owner must name a positioned reference"
        );
        assert!(
            owned_references.insert(owner.reference),
            "each Go reference has one source owner"
        );
        if let Some(owner_site) = owner.owner {
            assert!(owner_site.index() < facts.sites.len());
            assert!(facts.identifiers.iter().any(|identifier| {
                identifier.site == owner_site
                    && identifier.role == ResolutionIdentifierRole::Declaration
            }));
        }
    }
    assert_eq!(
        owned_references, reference_sites,
        "each Go positioned reference publishes its declaration owner"
    );
    for (index, slot) in facts.type_slots.iter().enumerate() {
        assert_eq!(slot.id.index(), index);
        assert!(slot.site.index() < facts.sites.len());
    }
    for binder in &facts.binders {
        assert!(binder.declaration.index() < facts.sites.len());
        assert!(binder.scope.index() < facts.scopes.len());
        assert!(binder.activation_start <= binder.activation_end);
    }
    let package_scope = ResolutionScopeId::new(1);
    let package = &facts.scopes[package_scope.index()];
    assert_eq!(package.kind, ResolutionScopeKind::Package);
    assert_eq!(package.parent, Some(ResolutionScopeId::new(0)));
    assert!(package.owner.is_none());

    let mut root_terminals = HashSet::default();
    for route in &facts.root_references {
        assert!(root_terminals.insert(route.reference));
        assert_eq!(route.root_scope, package_scope);
        assert_eq!(route.anchor, ResolutionRootImportAnchor::Lexical);
        let prefix = route
            .prefix_reference
            .expect("Go qualified root route has its positioned prefix");
        let identifier = facts
            .identifiers
            .iter()
            .find(|id| id.site == prefix)
            .expect("Go prefix identifier");
        assert_eq!(identifier.namespace, ResolutionNamespace::TypeOrValue);
        assert_eq!(identifier.role, ResolutionIdentifierRole::Reference);
        assert!(identifier.qualifier.is_none());
        assert_eq!(
            facts.sites[prefix.index()].scope,
            facts.sites[route.reference.index()].scope
        );
        let segments = facts
            .root_reference_segments
            .iter()
            .filter(|segment| segment.reference == route.reference)
            .collect::<Vec<_>>();
        assert_eq!(
            segments.len(),
            1,
            "Go package qualifier has one structured segment"
        );
        assert_eq!(segments[0].position, 0);
        assert_eq!(segments[0].name, identifier.name);
    }
    assert_eq!(facts.root_reference_segments.len(), root_terminals.len());

    let file_scope = ResolutionScopeId::new(2);
    assert_eq!(
        facts.scopes[file_scope.index()].kind,
        ResolutionScopeKind::File
    );
    assert_eq!(facts.scopes[file_scope.index()].parent, Some(package_scope));
    let mut import_sites = HashSet::default();
    let mut validated_import_segments = 0usize;
    for import in &facts.root_imports {
        assert!(import_sites.insert(import.site), "duplicate Go root import");
        assert_eq!(import.root_scope, file_scope);
        assert!(import.site.index() < facts.sites.len());
        let site = facts.sites[import.site.index()];
        assert_eq!(site.kind, ResolutionSiteKind::ImportDeclaration);
        assert_eq!(site.scope, file_scope);

        let segments = facts
            .root_import_segments
            .iter()
            .filter(|segment| segment.import_site == import.site)
            .collect::<Vec<_>>();
        assert!(
            !segments.is_empty(),
            "a Go root import needs at least one route segment"
        );
        for (position, segment) in segments.iter().enumerate() {
            assert_eq!(
                segment.position,
                dense_ordinal(position, "Go root import segment")
            );
            assert!(segment.name.index() < facts.names.len());
            assert!(!facts.names[segment.name.index()].spelling.is_empty());
        }
        validated_import_segments = validated_import_segments
            .checked_add(segments.len())
            .expect("Go root import segment count exceeds usize");
    }
    assert_eq!(
        validated_import_segments,
        facts.root_import_segments.len(),
        "every Go root import segment needs one route header"
    );

    let mut kinds = HashMap::default();
    for import in &facts.root_import_kinds {
        assert!(import_sites.contains(&import.import_site));
        assert!(kinds.insert(import.import_site, import.kind).is_none());
    }
    assert_eq!(
        kinds.len(),
        import_sites.len(),
        "every Go import route needs its named/dot discriminator"
    );

    let mut demanded_names = HashSet::default();
    for identifier in &facts.identifiers {
        if identifier.role == ResolutionIdentifierRole::Reference
            && identifier.qualifier.is_none()
            && !root_terminals.contains(&identifier.site)
            && go_identifier_is_exported(&facts.names[identifier.name.index()].spelling)
        {
            for &namespace in go_dot_import_namespaces(identifier.namespace) {
                demanded_names.insert((namespace, identifier.name));
            }
        }
    }
    let expected_demands = facts
        .root_imports
        .iter()
        .filter(|import| kinds[&import.site] == ResolutionRootImportKind::Glob)
        .flat_map(|import| {
            demanded_names
                .iter()
                .map(move |&(namespace, name)| (import.site, namespace, name))
        })
        .collect::<HashSet<_>>();
    let mut actual_demands = HashSet::default();
    for demand in &facts.root_import_demands {
        assert!(import_sites.contains(&demand.import_site));
        assert!(matches!(
            demand.namespace,
            ResolutionNamespace::Type | ResolutionNamespace::Value | ResolutionNamespace::Callable
        ));
        assert!(demand.name.index() < facts.names.len());
        assert!(go_identifier_is_exported(
            &facts.names[demand.name.index()].spelling
        ));
        assert!(
            actual_demands.insert((demand.import_site, demand.namespace, demand.name)),
            "duplicate Go root import demand"
        );
    }
    assert_eq!(
        actual_demands, expected_demands,
        "Go dot imports need exactly the exported unqualified namespace demands"
    );

    let mut targets = HashSet::default();
    for target in &facts.root_import_demand_targets {
        assert_eq!(
            target.target,
            ResolutionRootImportDemandTarget::SameNameGlob
        );
        assert_eq!(kinds[&target.import_site], ResolutionRootImportKind::Glob);
        assert!(targets.insert((target.import_site, target.namespace, target.name)));
    }
    assert_eq!(
        targets, actual_demands,
        "dot demands retain exact same-name targets"
    );

    let mut expected_exports = HashSet::default();
    for binder in &facts.binders {
        if binder.scope != package_scope {
            continue;
        }
        for identifier in facts.identifiers.iter().filter(|identifier| {
            identifier.site == binder.declaration
                && identifier.role == ResolutionIdentifierRole::Declaration
                && identifier.qualifier.is_none()
                && matches!(
                    identifier.namespace,
                    ResolutionNamespace::Type
                        | ResolutionNamespace::Value
                        | ResolutionNamespace::Callable
                )
                && go_identifier_is_exported(&facts.names[identifier.name.index()].spelling)
        }) {
            expected_exports.insert((package_scope, identifier.site, identifier.namespace));
            for additional in &facts.additional_definition_namespaces {
                if additional.declaration == identifier.site {
                    expected_exports.insert((package_scope, identifier.site, additional.namespace));
                }
            }
        }
    }
    let mut actual_exports = HashSet::default();
    for export in &facts.root_exports {
        assert_eq!(export.root_scope, package_scope);
        assert!(export.declaration.index() < facts.sites.len());
        let site = facts.sites[export.declaration.index()];
        let (site_kind, binder_kind) = match export.namespace {
            ResolutionNamespace::Type => {
                assert!(matches!(
                    site.kind,
                    ResolutionSiteKind::TypeDeclaration | ResolutionSiteKind::TypeAliasDeclaration
                ));
                (site.kind, ResolutionBinderKind::Type)
            }
            ResolutionNamespace::Value if site.kind == ResolutionSiteKind::CallableDeclaration => (
                ResolutionSiteKind::CallableDeclaration,
                ResolutionBinderKind::Callable,
            ),
            ResolutionNamespace::Value => (
                ResolutionSiteKind::ValueDeclaration,
                ResolutionBinderKind::Local,
            ),
            ResolutionNamespace::Callable => (
                ResolutionSiteKind::CallableDeclaration,
                ResolutionBinderKind::Callable,
            ),
            _ => panic!("unsupported Go root export namespace"),
        };
        assert_eq!(site.kind, site_kind);
        assert_eq!(site.scope, package_scope);

        let mut identifiers = facts.identifiers.iter().filter(|identifier| {
            identifier.site == export.declaration
                && identifier.role == ResolutionIdentifierRole::Declaration
        });
        let identifier = identifiers
            .next()
            .expect("a Go root export needs its declaration identifier");
        assert!(
            identifiers.next().is_none(),
            "a Go root export has one declaration identifier"
        );
        assert!(
            identifier.namespace == export.namespace
                || facts
                    .additional_definition_namespaces
                    .iter()
                    .any(|additional| {
                        additional.declaration == export.declaration
                            && additional.namespace == export.namespace
                            && additional.hoisting == HoistingClass::ScopeWide
                    })
        );
        assert!(identifier.qualifier.is_none());
        assert!(go_identifier_is_exported(
            &facts.names[identifier.name.index()].spelling
        ));

        let mut binders = facts
            .binders
            .iter()
            .filter(|binder| binder.declaration == export.declaration);
        let binder = binders
            .next()
            .expect("a Go root export needs its package-scope binder");
        assert!(
            binders.next().is_none(),
            "a Go root export has one package-scope binder"
        );
        assert_eq!(binder.scope, export.root_scope);
        assert_eq!(binder.kind, binder_kind);
        assert_eq!(binder.hoisting, HoistingClass::ScopeWide);
        assert_eq!(binder.activation_start, package.start_byte);
        assert_eq!(binder.activation_end, package.end_byte);
        assert!(
            actual_exports.insert((export.root_scope, export.declaration, export.namespace)),
            "duplicate Go root export"
        );
    }
    assert_eq!(
        actual_exports, expected_exports,
        "Go roots export exactly the supported uppercase package declarations"
    );
    for property in &facts.declaration_type_slots {
        assert!(property.declaration.index() < facts.sites.len());
        assert!(property.slot.index() < facts.type_slots.len());
        assert_eq!(
            facts.type_slots[property.slot.index()].site,
            property.declaration
        );
    }
    for projection in &facts.binding_projections {
        assert!(projection.reference.index() < facts.sites.len());
        assert!(projection.output.index() < facts.type_slots.len());
    }
    for transfer in &facts.type_transfers {
        assert!(transfer.input.index() < facts.type_slots.len());
        assert!(transfer.output.index() < facts.type_slots.len());
        assert_ne!(transfer.input, transfer.output);
    }
    for seed in &facts.intrinsic_type_seeds {
        assert!(seed.output.index() < facts.type_slots.len());
        assert!(seed.name.index() < facts.names.len());
    }
    for call in &facts.calls {
        assert!(call.call.index() < facts.sites.len());
        assert!(call.callee.index() < facts.sites.len());
        assert!(call.result.index() < facts.type_slots.len());
        if let Some(receiver) = call.receiver {
            assert!(receiver.index() < facts.type_slots.len());
        }
    }
    for argument in &facts.call_arguments {
        assert!(argument.call.index() < facts.sites.len());
        assert!(argument.value.index() < facts.type_slots.len());
    }
    let mut signature_headers = HashSet::default();
    for signature in &facts.callable_signatures {
        assert!(signature.callable.index() < facts.sites.len());
        assert!(signature_headers.insert(signature.callable));
    }
    for parameter in &facts.callable_parameters {
        assert!(parameter.callable.index() < facts.sites.len());
        assert!(parameter.parameter.index() < facts.sites.len());
        assert!(parameter.value_type.index() < facts.type_slots.len());
        assert!(signature_headers.contains(&parameter.callable));
    }
    for owner in &facts.member_owners {
        assert!(owner.member.index() < facts.sites.len());
        assert!(owner.owner.index() < facts.sites.len());
    }
    for gap in &facts.gaps {
        assert!(gap.site.index() < facts.sites.len());
    }
    let mut enumeration_rows = HashSet::default();
    for gap in &facts.reference_enumeration_gaps {
        assert!(gap.site.index() < facts.sites.len());
        assert!(go_gap_blocks_reference_enumeration(gap.kind));
        assert!(facts.gaps.contains(&ResolutionGapFact {
            site: gap.site,
            kind: gap.kind,
        }));
        assert!(enumeration_rows.insert(*gap));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn facts(source: &str) -> FileResolutionFacts {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("Go grammar");
        let tree = parser.parse(source, None).expect("Go tree");
        extract_go_resolution_facts(tree.root_node(), source)
    }

    #[test]
    fn package_members_include_private_declarations_without_exporting_them() {
        let facts = facts(
            r#"package p
            type hidden struct { field int }
            type Public struct{}
            var value hidden
            func helper(parameter hidden) hidden { var local hidden; return local }
            func (receiver hidden) method() {}
        "#,
        );
        let members = facts
            .package_members
            .iter()
            .map(|member| {
                let identifier = facts
                    .identifiers
                    .iter()
                    .find(|identifier| {
                        identifier.site == member.declaration
                            && identifier.role == ResolutionIdentifierRole::Declaration
                    })
                    .unwrap();
                (name(&facts, identifier.name), member.namespace)
            })
            .collect::<HashSet<_>>();
        assert_eq!(
            members,
            [
                ("hidden", ResolutionNamespace::Type),
                ("Public", ResolutionNamespace::Type),
                ("value", ResolutionNamespace::Value),
                ("helper", ResolutionNamespace::Callable),
                ("helper", ResolutionNamespace::Value),
            ]
            .into_iter()
            .collect::<HashSet<_>>()
        );
        let exports = facts
            .root_exports
            .iter()
            .map(|export| {
                let identifier = facts
                    .identifiers
                    .iter()
                    .find(|identifier| {
                        identifier.site == export.declaration
                            && identifier.role == ResolutionIdentifierRole::Declaration
                    })
                    .unwrap();
                name(&facts, identifier.name)
            })
            .collect::<Vec<_>>();
        assert_eq!(exports, vec!["Public"]);
        facts.validate_package_relations();
    }

    #[test]
    fn package_references_preserve_lexical_scopes_and_qualified_prefixes() {
        let facts = facts(
            r#"package p
            import named "example.test/provider"
            type hidden struct{}
            var sibling hidden
            func f(argument hidden) { var local hidden; _=argument; _=local; _=sibling; _=named.Public }
        "#,
        );
        let references = facts
            .package_references
            .iter()
            .map(|reference| {
                let identifier = facts
                    .identifiers
                    .iter()
                    .find(|identifier| {
                        identifier.site == reference.reference
                            && identifier.role == ResolutionIdentifierRole::Reference
                    })
                    .unwrap();
                (
                    name(&facts, identifier.name),
                    identifier.namespace,
                    facts.sites[reference.reference.index()].scope,
                )
            })
            .collect::<Vec<_>>();
        for spelling in ["hidden", "argument", "local", "sibling"] {
            assert!(
                references.iter().any(|(name, _, _)| *name == spelling),
                "{references:?}"
            );
        }
        assert!(
            references
                .iter()
                .any(|(name, namespace, _)| *name == "named"
                    && *namespace == ResolutionNamespace::TypeOrValue)
        );
        assert!(
            !references.iter().any(|(name, _, _)| *name == "Public"),
            "qualified terminal is not a sibling demand"
        );
        assert!(
            references
                .iter()
                .filter(|(name, _, _)| matches!(*name, "argument" | "local" | "sibling"))
                .all(|(_, _, scope)| *scope != ResolutionScopeId::new(1)),
            "local lexical scope must remain on each positioned reference"
        );
        assert!(
            facts
                .package_references
                .iter()
                .all(|reference| reference.root_scope == ResolutionScopeId::new(1))
        );
    }

    #[test]
    fn if_condition_bare_call_callee_is_a_package_reference() {
        let facts = facts(
            r#"package p

type Widget struct{}
func New() Widget { return Widget{} }
func use() { if New().Name() == "" {} }
"#,
        );
        let callee = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && facts.sites[identifier.site.index()].kind
                        == ResolutionSiteKind::CallableReference
                    && name(&facts, identifier.name) == "New"
            })
            .expect("nested call keeps its bare callee reference");
        assert!(
            facts
                .package_references
                .iter()
                .any(|reference| reference.reference == callee.site),
            "a bare callee continues from the package scope"
        );
        assert!(facts.identifiers.iter().any(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && name(&facts, identifier.name) == "Name"
                && facts.sites[identifier.site.index()].kind == ResolutionSiteKind::MemberReference
        }));
    }

    #[test]
    fn file_has_one_source_root_placement_boundary() {
        let facts = facts("package p\n");
        let placement = facts
            .gaps
            .iter()
            .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedPlacementBoundary)
            .collect::<Vec<_>>();
        assert_eq!(placement.len(), 1);
        let site = facts.sites[placement[0].site.index()];
        assert_eq!(
            facts.scopes[site.scope.index()].kind,
            ResolutionScopeKind::CompilationUnit
        );
        assert!(facts.scopes[site.scope.index()].parent.is_none());
        assert!(
            facts.reference_enumeration_gaps.is_empty(),
            "the explicit placement boundary does not omit a Go occurrence"
        );
    }

    #[test]
    fn membership_digest_covers_exactly_what_the_go_tool_reads_for_placement() {
        let digest = |source: &str| {
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_go::LANGUAGE.into())
                .expect("Go grammar");
            let tree = parser.parse(source, None).expect("Go tree");
            go_membership_digest(tree.root_node(), source)
        };
        let base =
            "//go:build linux\n\npackage p\n\nimport \"fmt\"\n\nfunc F() { fmt.Println(1) }\n";
        let base_digest = digest(base).expect("well-formed header");
        // go/build reads nothing after the imports, so body edits and body
        // syntax errors keep the file's package placement.
        for kept in [
            base.replace("Println(1)", "Println(2)"),
            base.replace("func F() { fmt.Println(1) }", "func F() { fmt.Println( }"),
            format!("{base}func G() {{}}\n"),
        ] {
            assert_eq!(digest(&kept), Some(base_digest), "{kept}");
        }
        for changed in [
            base.replace("linux", "darwin"),
            base.replace("package p", "package p_test"),
            base.replace("import \"fmt\"", "import \"C\"\nimport \"fmt\""),
            base.replace("import \"fmt\"", "import f \"fmt\""),
        ] {
            let changed_digest = digest(&changed);
            assert!(changed_digest.is_some(), "{changed}");
            assert_ne!(changed_digest, Some(base_digest), "{changed}");
        }
        for rejected in [
            "package p\nfunc F() {}\nimport \"fmt\"\n",
            "package p\npackage q\n",
            "func F() {}\n",
        ] {
            assert_eq!(digest(rejected), None, "{rejected}");
        }
    }

    #[test]
    fn build_constraint_fact_uses_only_leading_line_comment_nodes() {
        let constrained = |source: &str| {
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_go::LANGUAGE.into())
                .expect("Go grammar");
            let tree = parser.parse(source, None).expect("Go tree");
            go_has_build_constraints(tree.root_node(), source)
        };
        assert!(constrained("//go:build linux\n\npackage p\n"));
        assert!(constrained("// +build linux\n\npackage p\n"));
        assert!(!constrained("/* //go:build linux */\npackage p\n"));
        assert!(!constrained("package p\n//go:build linux\n"));
        assert!(!constrained("// ordinary comment\n\npackage p\n"));
    }

    #[test]
    fn producer_preserves_the_conservative_go_enumeration_mapping() {
        let source = "package p\n";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("Go grammar");
        let tree = parser.parse(source, None).expect("Go tree");
        let mut builder = GoResolutionBuilder::new(tree.root_node(), source);
        let site = builder.add_site(tree.root_node(), ResolutionSiteKind::UnsupportedExpression);
        for kind in [
            ResolutionGapKind::UnsupportedTypeSyntax,
            ResolutionGapKind::UnsupportedExpression,
            ResolutionGapKind::UnsupportedRoute,
            ResolutionGapKind::UnsupportedScopeOrBinder,
            ResolutionGapKind::AmbiguousQualifiedType,
            ResolutionGapKind::InferredType,
            ResolutionGapKind::PostfixArrayDimensions,
            ResolutionGapKind::AmbiguousNumericLiteral,
            ResolutionGapKind::ImplicitConstructor,
            ResolutionGapKind::UnsupportedHierarchyTraversal,
            ResolutionGapKind::UnsupportedVisibility,
            ResolutionGapKind::UnsupportedImplicitReceiver,
            ResolutionGapKind::UnsupportedCallApplicability,
            ResolutionGapKind::UnsupportedPlacementBoundary,
            ResolutionGapKind::MalformedSyntax,
        ] {
            builder.add_gap(site, kind);
        }

        assert_eq!(
            builder.facts.reference_enumeration_gaps,
            vec![
                ResolutionReferenceEnumerationGapFact {
                    site,
                    kind: ResolutionGapKind::UnsupportedTypeSyntax,
                },
                ResolutionReferenceEnumerationGapFact {
                    site,
                    kind: ResolutionGapKind::UnsupportedExpression,
                },
                ResolutionReferenceEnumerationGapFact {
                    site,
                    kind: ResolutionGapKind::UnsupportedRoute,
                },
                ResolutionReferenceEnumerationGapFact {
                    site,
                    kind: ResolutionGapKind::UnsupportedScopeOrBinder,
                },
                ResolutionReferenceEnumerationGapFact {
                    site,
                    kind: ResolutionGapKind::MalformedSyntax,
                },
            ]
        );
    }

    #[test]
    fn grouped_dot_imports_emit_dense_deduplicated_exported_spelling_demands() {
        let source = r#"package consumer

import (
    . "example.test/root/provider"
    _ "example.test/root/blank"
    named "example.test/root/named"
    . "example.test/root/other"
)

var First *Item
var Second *Item
var Third *Other
var hidden *item
"#;
        let facts = facts(source);

        assert_eq!(facts.root_imports.len(), 4);
        let dot_sites = facts
            .root_import_kinds
            .iter()
            .filter(|import| import.kind == ResolutionRootImportKind::Glob)
            .map(|import| import.import_site)
            .collect::<HashSet<_>>();
        assert_eq!(dot_sites.len(), 2);
        let expected_routes = [
            ["example.test", "root", "provider"],
            ["example.test", "root", "other"],
        ];
        for (import, expected_route) in facts
            .root_imports
            .iter()
            .filter(|import| dot_sites.contains(&import.site))
            .zip(expected_routes)
        {
            let site = facts.sites[import.site.index()];
            assert_eq!(site.kind, ResolutionSiteKind::ImportDeclaration);
            assert_eq!(site.scope, ResolutionScopeId::new(2));
            let segments = facts
                .root_import_segments
                .iter()
                .filter(|segment| segment.import_site == import.site)
                .collect::<Vec<_>>();
            assert_eq!(segments.len(), expected_route.len());
            assert_eq!(
                segments
                    .iter()
                    .map(|segment| segment.position)
                    .collect::<Vec<_>>(),
                vec![0, 1, 2]
            );
            assert_eq!(
                segments
                    .iter()
                    .map(|segment| name(&facts, segment.name))
                    .collect::<Vec<_>>(),
                expected_route
            );
            assert_eq!(
                facts
                    .root_import_demands
                    .iter()
                    .filter(|demand| demand.import_site == import.site
                        && demand.namespace == ResolutionNamespace::Type)
                    .map(|demand| {
                        assert_eq!(demand.namespace, ResolutionNamespace::Type);
                        name(&facts, demand.name)
                    })
                    .collect::<Vec<_>>(),
                vec!["Item", "Other"]
            );
        }
        assert_eq!(facts.root_import_demands.len(), 12);
        assert!(
            facts
                .root_import_demands
                .iter()
                .all(|demand| name(&facts, demand.name) != "item")
        );

        let route_gap = facts
            .gaps
            .iter()
            .find(|gap| {
                gap.kind == ResolutionGapKind::UnsupportedRoute
                    && facts.sites[gap.site.index()].kind == ResolutionSiteKind::UnsupportedRoute
            })
            .expect("the grouped import retains its unsupported-route gap");
        assert!(facts.reference_enumeration_gaps.contains(
            &ResolutionReferenceEnumerationGapFact {
                site: route_gap.site,
                kind: ResolutionGapKind::UnsupportedRoute,
            }
        ));
        assert!(facts.gaps.iter().any(|gap| {
            gap.kind == ResolutionGapKind::UnsupportedPlacementBoundary
                && facts.scopes[facts.sites[gap.site.index()].scope.index()].kind
                    == ResolutionScopeKind::CompilationUnit
        }));
    }

    #[test]
    fn package_type_exports_exclude_private_and_local_types() {
        let source = r#"package provider

type Item struct{}
type item struct{}

func use() {
    type Local struct{}
    type local struct{}
}
"#;
        let facts = facts(source);
        let item = declaration(&facts, "Item");
        let local = declaration(&facts, "Local");

        assert_eq!(
            facts.root_exports,
            vec![ResolutionRootExportFact {
                root_scope: ResolutionScopeId::new(1),
                declaration: item,
                namespace: ResolutionNamespace::Type,
            }]
        );
        assert_ne!(
            facts.sites[local.index()].scope,
            ResolutionScopeId::new(1),
            "an uppercase local type is not a package export"
        );
        assert!(facts.root_exports.iter().all(|export| {
            let identifier = facts
                .identifiers
                .iter()
                .find(|identifier| identifier.site == export.declaration)
                .expect("root export identifier");
            go_identifier_is_exported(name(&facts, identifier.name))
        }));
    }

    #[test]
    fn root_exports_include_values_and_functions_but_not_methods_or_private_names() {
        let facts = facts(
            r#"package provider
        type Item struct{}
        type hidden struct{}
        var Value *Item
        var private *Item
        const Constant = "value"
        func Function() {}
        func privateFunction() {}
        func (Item) Method() {}
        func local() { var Local *Item; _ = Local }
        "#,
        );
        let exports = facts
            .root_exports
            .iter()
            .map(|export| {
                let identifier = facts
                    .identifiers
                    .iter()
                    .find(|id| id.site == export.declaration)
                    .unwrap();
                (name(&facts, identifier.name), export.namespace)
            })
            .collect::<HashSet<_>>();
        assert_eq!(
            exports,
            HashSet::from_iter([
                ("Item", ResolutionNamespace::Type),
                ("Value", ResolutionNamespace::Value),
                ("Constant", ResolutionNamespace::Value),
                ("Function", ResolutionNamespace::Callable),
                ("Function", ResolutionNamespace::Value),
            ])
        );
        // Private package bindings remain available for selected same-package lookup.
        for spelling in ["hidden", "private", "privateFunction"] {
            let declaration = declaration(&facts, spelling);
            assert!(
                facts
                    .binders
                    .iter()
                    .any(|binder| binder.declaration == declaration
                        && binder.scope == ResolutionScopeId::new(1)
                        && binder.hoisting == HoistingClass::ScopeWide)
            );
        }
    }

    #[test]
    fn block_local_types_activate_at_the_name_and_cover_recursive_type_uses() {
        let source = r#"package p
        type Package struct{}
        func use() { var before *Local; type Local struct { Next *Local }; var after *Local }
        "#;
        let facts = facts(source);
        let local = declaration(&facts, "Local");
        let binder = facts
            .binders
            .iter()
            .find(|b| b.declaration == local)
            .unwrap();
        assert_eq!(binder.hoisting, HoistingClass::SourceOrder);
        assert_eq!(
            binder.activation_start,
            source.find("Local struct").unwrap()
        );
        let references = facts
            .identifiers
            .iter()
            .filter(|id| {
                id.role == ResolutionIdentifierRole::Reference && name(&facts, id.name) == "Local"
            })
            .map(|id| facts.sites[id.site.index()].start_byte)
            .collect::<Vec<_>>();
        assert_eq!(references.len(), 3);
        assert!(references[0] < binder.activation_start);
        assert!(references[1] >= binder.activation_start);
        assert!(references[2] >= binder.activation_start);
        let package = declaration(&facts, "Package");
        let binder = facts
            .binders
            .iter()
            .find(|b| b.declaration == package)
            .unwrap();
        assert_eq!(binder.hoisting, HoistingClass::ScopeWide);
        assert_eq!(
            binder.activation_start,
            facts.scopes[binder.scope.index()].start_byte
        );
    }

    #[test]
    fn ordinary_functions_are_values_without_fabricated_function_value_types() {
        let facts = facts(
            r#"package p
        type Item struct{}
        func F() Item { return Item{} }
        func private() {}
        func init() {}
        func _() {}
        func (Item) Method() {}
        func use() { f := F; g := private; f(); g() }
        "#,
        );
        let extra = facts
            .additional_definition_namespaces
            .iter()
            .map(|fact| {
                assert_eq!(fact.namespace, ResolutionNamespace::Value);
                assert_eq!(fact.hoisting, HoistingClass::ScopeWide);
                fact.declaration
            })
            .collect::<HashSet<_>>();
        assert_eq!(
            extra,
            HashSet::from_iter(["F", "private", "use"].map(|n| declaration(&facts, n)))
        );
        assert!(!extra.contains(&declaration(&facts, "Method")));
        for spelling in ["F", "private"] {
            let target = declaration(&facts, spelling);
            assert_eq!(
                facts
                    .binders
                    .iter()
                    .filter(|b| b.declaration == target)
                    .count(),
                1
            );
            assert!(!facts.declaration_type_slots.iter().any(|slot| {
                slot.declaration == target && slot.role == DeclarationTypeRole::Value
            }));
            assert!(facts.identifiers.iter().any(|id| {
                name(&facts, id.name) == spelling
                    && id.role == ResolutionIdentifierRole::Reference
                    && id.namespace == ResolutionNamespace::Value
            }));
        }
        for spelling in ["f", "g"] {
            let target = declaration(&facts, spelling);
            assert!(facts.type_transfers.iter().any(|transfer| {
                facts.type_slots[transfer.output.index()].site == target
                    && transfer.kind == ResolutionTypeTransferKind::Assignment
            }));
        }
        assert!(
            facts
                .gaps
                .iter()
                .any(|gap| gap.kind == ResolutionGapKind::UnsupportedCallApplicability)
        );
    }

    #[test]
    fn dot_import_demands_keep_value_callable_and_type_namespaces() {
        let facts = facts(
            r#"package consumer
        import . "example.test/provider"
        var First *Item
        var Second *Item
        func use() { _ = Value; _ = Value; Function(); _ = Item(Value); privateFunction(); _ = private }
        "#,
        );
        let demands = facts
            .root_import_demands
            .iter()
            .map(|demand| (name(&facts, demand.name), demand.namespace))
            .collect::<HashSet<_>>();
        for demand in [
            ("Item", ResolutionNamespace::Type),
            ("Value", ResolutionNamespace::Value),
            ("Function", ResolutionNamespace::Callable),
            ("Item", ResolutionNamespace::Callable),
        ] {
            assert!(
                demands.contains(&demand),
                "missing {demand:?} in {demands:?}"
            );
        }
        assert_eq!(
            demands.len(),
            facts.root_import_demands.len(),
            "demands are deduplicated"
        );
        assert!(
            demands
                .iter()
                .all(|(spelling, _)| !matches!(*spelling, "private" | "privateFunction"))
        );
    }

    #[test]
    fn constants_keep_binders_exports_and_non_addressable_declared_types() {
        let source = r#"package p
        const Typed string = "value"
        const hidden int = 1
        const _, Grouped string = "discard", "kept"
        const (
            First, Second = "first", true
            Repeated, RepeatedSecond
            Sequence = iota
        )
        func use() {
            const Local string = Typed
            _ = Local
        }
        "#;
        let facts = facts(source);
        for spelling in [
            "Typed", "hidden", "Grouped", "First", "Second", "Repeated", "Sequence", "Local",
        ] {
            let site = declaration(&facts, spelling);
            let binder = facts
                .binders
                .iter()
                .find(|binder| binder.declaration == site)
                .unwrap();
            assert_eq!(binder.kind, ResolutionBinderKind::Local);
            assert_eq!(
                binder.hoisting,
                if spelling == "Local" {
                    HoistingClass::SourceOrder
                } else {
                    HoistingClass::ScopeWide
                }
            );
            if spelling == "Local" {
                assert_eq!(
                    binder.activation_start,
                    source.find("            _ = Local").unwrap() - 1
                );
            }
            assert_eq!(
                facts
                    .root_exports
                    .iter()
                    .any(|export| export.declaration == site),
                !matches!(spelling, "hidden" | "Local")
            );
        }
        assert!(
            !facts
                .identifiers
                .iter()
                .any(|id| id.role == ResolutionIdentifierRole::Declaration
                    && name(&facts, id.name) == "_")
        );
        for spelling in ["Typed", "hidden", "Grouped", "Local"] {
            let site = declaration(&facts, spelling);
            let declared = declaration_slot(&facts, site, DeclarationTypeRole::Value);
            assert_eq!(
                transfer_to(&facts, declared).value_transform,
                ResolutionTypeTransferValueTransform::ToRuntime { addressable: false }
            );
        }
        for slot in facts
            .type_slots
            .iter()
            .filter(|slot| slot.role == ResolutionTypeSlotRole::AssignmentValue)
        {
            assert_eq!(
                transfer_to(&facts, slot.id).value_transform,
                ResolutionTypeTransferValueTransform::ToRuntime { addressable: false }
            );
        }
        assert!(
            facts
                .identifiers
                .iter()
                .any(|id| id.role == ResolutionIdentifierRole::Reference
                    && name(&facts, id.name) == "Typed")
        );
        assert!(
            facts
                .identifiers
                .iter()
                .any(|id| id.role == ResolutionIdentifierRole::Reference
                    && name(&facts, id.name) == "Local")
        );
    }

    #[test]
    fn untyped_and_implicit_constants_do_not_fabricate_types_or_initializers() {
        let facts = facts(
            r#"package p
        const (
            Text = "text"
            Repeated
            Number = 42
            Truth = true
            Rune = 'r'
            Sequence = iota
            Calculated = 1 + 2
        )
        "#,
        );
        assert!(
            facts.intrinsic_type_seeds.is_empty(),
            "untyped constants must not acquire default runtime types"
        );
        assert!(
            facts.declaration_type_slots.is_empty(),
            "no explicit constant type was written"
        );
        for spelling in [
            "Text",
            "Repeated",
            "Number",
            "Truth",
            "Rune",
            "Sequence",
            "Calculated",
        ] {
            let site = declaration(&facts, spelling);
            assert_eq!(
                facts
                    .gaps
                    .iter()
                    .any(|gap| gap.site == site && gap.kind == ResolutionGapKind::InferredType),
                spelling == "Repeated",
                "an explicit untyped constant value keeps its lexical binding complete"
            );
            let assignments = facts
                .type_slots
                .iter()
                .filter(|slot| {
                    slot.site == site && slot.role == ResolutionTypeSlotRole::AssignmentValue
                })
                .collect::<Vec<_>>();
            assert_eq!(assignments.len(), usize::from(spelling != "Repeated"));
            if let Some(slot) = assignments.first() {
                let input = transfer_to(&facts, slot.id).input;
                assert!(
                    facts
                        .gaps
                        .iter()
                        .any(|gap| gap.site == facts.type_slots[input.index()].site)
                );
            } else {
                assert!(
                    facts.gaps.iter().any(|gap| gap.site == site
                        && gap.kind == ResolutionGapKind::UnsupportedExpression)
                );
            }
        }
    }

    #[test]
    fn named_default_and_blank_import_routes_keep_exact_specs_without_guessed_bindings() {
        let source = r#"package consumer
        import (
            explicit "example.test/provider/v2"
            "example.test/different-path"
            _ "example.test/side-effects"
        )
        var Use *explicit.Item
        "#;
        let facts = facts(source);
        assert_eq!(facts.root_imports.len(), 3);
        for (import, (written, route)) in facts.root_imports.iter().zip([
            (
                "explicit \"example.test/provider/v2\"",
                vec!["example.test", "provider", "v2"],
            ),
            (
                "\"example.test/different-path\"",
                vec!["example.test", "different-path"],
            ),
            (
                "_ \"example.test/side-effects\"",
                vec!["example.test", "side-effects"],
            ),
        ]) {
            let site = facts.sites[import.site.index()];
            assert_eq!(
                &source[site.start_byte..site.end_byte],
                written,
                "canonical source-import matching must retain the exact alias-bearing spec"
            );
            assert_eq!(
                facts
                    .root_import_segments
                    .iter()
                    .filter(|segment| segment.import_site == import.site)
                    .map(|segment| name(&facts, segment.name))
                    .collect::<Vec<_>>(),
                route
            );
            assert!(
                facts
                    .root_import_kinds
                    .iter()
                    .any(|kind| kind.import_site == import.site
                        && kind.kind == ResolutionRootImportKind::Named)
            );
        }
        assert!(
            facts.root_import_demands.is_empty(),
            "package qualifiers need selected binding authority"
        );
        assert!(
            !facts
                .binders
                .iter()
                .any(|binder| binder.kind == ResolutionBinderKind::Import)
        );
        assert!(
            !facts
                .identifiers
                .iter()
                .any(|id| id.role == ResolutionIdentifierRole::Declaration
                    && matches!(
                        name(&facts, id.name),
                        "explicit" | "v2" | "different-path" | "_"
                    )),
            "an alias is not a fabricated Type/Value and an absent alias is not a basename"
        );
        assert!(
            facts
                .gaps
                .iter()
                .any(|gap| gap.kind == ResolutionGapKind::UnsupportedRoute)
        );
    }

    #[test]
    fn file_scope_owns_imports_and_reference_ancestry_but_not_package_declarations() {
        let source = r#"package p
import "example.test/default"
import alias "example.test/aliased"
import _ "example.test/effects"
import . "example.test/dotted"
type T struct{}
type Alias = T
var Value T
func use() { _ = alias.Item }
"#;
        let facts = facts(source);
        let package = ResolutionScopeId::new(1);
        let file = ResolutionScopeId::new(2);
        assert_eq!(facts.scopes[file.index()].kind, ResolutionScopeKind::File);
        assert_eq!(facts.scopes[file.index()].parent, Some(package));
        assert!(
            facts
                .root_imports
                .iter()
                .all(|import| import.root_scope == file)
        );
        assert_eq!(facts.go_package_imports.len(), 3);
        assert_eq!(
            facts
                .go_package_imports
                .iter()
                .filter(|import| import.kind == ResolutionGoPackageImportKind::Blank)
                .count(),
            1
        );
        assert!(
            facts
                .go_package_imports
                .iter()
                .all(|import| import.file_scope == file)
        );
        for identifier in &facts.identifiers {
            if identifier.role == ResolutionIdentifierRole::Declaration {
                assert_eq!(facts.sites[identifier.site.index()].scope, package);
            }
        }
        assert!(
            facts
                .scopes
                .iter()
                .filter(|scope| matches!(
                    scope.kind,
                    ResolutionScopeKind::TypeBody | ResolutionScopeKind::Executable
                ))
                .all(|scope| scope.parent == Some(file))
        );
        assert!(
            facts
                .package_members
                .iter()
                .all(|member| member.root_scope == package)
        );
        assert!(facts.go_package_imports.iter().all(|import| {
            !facts
                .package_members
                .iter()
                .any(|member| member.declaration == import.import_site)
        }));
        for import in &facts.go_package_imports {
            let site = facts.sites[import.import_site.index()];
            let spelling = &source[site.start_byte..site.end_byte];
            assert!(matches!(
                spelling,
                "\"example.test/default\""
                    | "alias \"example.test/aliased\""
                    | "_ \"example.test/effects\""
            ));
        }
    }

    #[test]
    fn ambiguous_qualifiers_probe_every_dot_import_binding_kind() {
        let facts = facts(
            r#"package consumer
        import . "example.test/provider"
        func use() { _ = Exported.Member }
        "#,
        );
        let demands = facts
            .root_import_demands
            .iter()
            .map(|demand| (name(&facts, demand.name), demand.namespace))
            .collect::<HashSet<_>>();
        assert_eq!(
            demands,
            HashSet::from_iter([
                ("Exported", ResolutionNamespace::Type),
                ("Exported", ResolutionNamespace::Value),
                ("Exported", ResolutionNamespace::Callable),
            ])
        );
    }

    #[test]
    fn package_qualifiers_keep_positioned_prefixes_and_runtime_selector_facts() {
        let source = r#"package consumer
        import pkg "example.test/provider"
        import . "example.test/other"
        var Value *pkg.Item
        type Local struct { Member string }
        func use(local Local) { _ = pkg.Member; pkg.Call(); _ = pkg.Widget{}; _ = local.Member }
        "#;
        let facts = facts(source);
        assert_eq!(facts.root_references.len(), 5);
        let mut observed = Vec::new();
        for route in &facts.root_references {
            let prefix = route
                .prefix_reference
                .expect("Go route has a positioned qualifier");
            let prefix_id = facts
                .identifiers
                .iter()
                .find(|id| id.site == prefix)
                .unwrap();
            let terminal = facts
                .identifiers
                .iter()
                .find(|id| id.site == route.reference)
                .unwrap();
            assert_eq!(prefix_id.namespace, ResolutionNamespace::TypeOrValue);
            assert_eq!(prefix_id.role, ResolutionIdentifierRole::Reference);
            assert!(prefix_id.qualifier.is_none());
            assert_eq!(
                facts.sites[prefix.index()].scope,
                facts.sites[route.reference.index()].scope
            );
            let segments = facts
                .root_reference_segments
                .iter()
                .filter(|segment| segment.reference == route.reference)
                .collect::<Vec<_>>();
            assert_eq!(segments.len(), 1);
            assert_eq!(segments[0].name, prefix_id.name);
            assert_eq!(segments[0].position, 0);
            let prefix_site = facts.sites[prefix.index()];
            assert_eq!(
                &source[prefix_site.start_byte..prefix_site.end_byte],
                name(&facts, prefix_id.name)
            );
            assert!(
                facts
                    .binding_projections
                    .iter()
                    .any(|projection| projection.reference == prefix
                        && projection.kind == BindingProjectionKind::TargetTypeOrDeclaredValueType)
            );
            if terminal.namespace == ResolutionNamespace::Type {
                assert!(
                    terminal.qualifier.is_none(),
                    "qualified type syntax is not runtime member lookup"
                );
                assert!(
                    facts
                        .binding_projections
                        .iter()
                        .any(|projection| projection.reference == route.reference
                            && projection.kind == BindingProjectionKind::TargetTypeIdentity)
                );
            } else {
                let receiver = terminal
                    .qualifier
                    .expect("selector keeps its runtime receiver");
                assert_eq!(
                    facts.type_slots[receiver.index()].role,
                    ResolutionTypeSlotRole::Receiver
                );
                assert_eq!(
                    transfer_to(&facts, receiver).value_transform,
                    ResolutionTypeTransferValueTransform::Preserve
                );
            }
            let is_call_callee = facts
                .calls
                .iter()
                .any(|call| call.callee == route.reference);
            let route_is_expected_to_remain_open =
                terminal.namespace != ResolutionNamespace::Value && !is_call_callee;
            assert_eq!(
                facts.gaps.iter().any(|gap| gap.site == route.reference
                    && gap.kind == ResolutionGapKind::UnsupportedRoute),
                route_is_expected_to_remain_open,
                "route {}.{} has incorrect unsupported status",
                name(&facts, prefix_id.name),
                name(&facts, terminal.name),
            );
            if is_call_callee {
                assert!(facts.gaps.contains(&ResolutionGapFact {
                    site: route.reference,
                    kind: ResolutionGapKind::UnsupportedCallApplicability,
                }));
            }
            observed.push((
                name(&facts, prefix_id.name),
                name(&facts, terminal.name),
                terminal.namespace,
            ));
        }
        assert_eq!(
            observed,
            [
                ("pkg", "Item", ResolutionNamespace::Type),
                ("pkg", "Member", ResolutionNamespace::Value),
                ("pkg", "Call", ResolutionNamespace::Callable),
                ("pkg", "Widget", ResolutionNamespace::Type),
                ("local", "Member", ResolutionNamespace::Value),
            ]
        );
        assert!(
            !facts
                .root_import_demands
                .iter()
                .any(|demand| name(&facts, demand.name) == "Item"),
            "qualified terminal cannot leak into dot-import demands"
        );
    }

    #[test]
    fn root_fact_validation_rejects_nondense_duplicate_and_local_rows() {
        let source = r#"package p

import . "example.test/root/provider"
var Use *Item

func use() { type Local struct{} }
"#;
        let original = facts(source);

        let mut nondense = original.clone();
        nondense.root_import_segments[0].position = 1;
        assert!(std::panic::catch_unwind(|| validate_facts(&nondense)).is_err());

        let mut duplicate = original.clone();
        let repeated_demand = duplicate.root_import_demands[0];
        duplicate.root_import_demands.push(repeated_demand);
        assert!(std::panic::catch_unwind(|| validate_facts(&duplicate)).is_err());

        let mut local_export = original.clone();
        local_export.root_exports.push(ResolutionRootExportFact {
            root_scope: ResolutionScopeId::new(1),
            declaration: declaration(&original, "Local"),
            namespace: ResolutionNamespace::Type,
        });
        assert!(std::panic::catch_unwind(|| validate_facts(&local_export)).is_err());
    }

    fn name(facts: &FileResolutionFacts, id: ResolutionNameId) -> &str {
        &facts.names[id.index()].spelling
    }

    #[test]
    fn transparent_aliases_preserve_binders_target_transfers_and_unknown_types() {
        let source = r#"package p
        type Original struct { Member int }
        type Alias = Original
        type Pointer = *Original
        type private = Alias
        type Integer = int
        type Generic[T any] = T
        type Anonymous = struct { Item int }
        func use() { type Local = Alias; var x Local; _ = x.Member }
        "#;
        let facts = facts(source);
        for spelling in [
            "Alias",
            "Pointer",
            "private",
            "Integer",
            "Generic",
            "Anonymous",
            "Local",
        ] {
            let declaration = declaration(&facts, spelling);
            assert_eq!(
                facts.sites[declaration.index()].kind,
                ResolutionSiteKind::TypeAliasDeclaration
            );
            let binder = facts
                .binders
                .iter()
                .find(|binder| binder.declaration == declaration)
                .unwrap();
            assert_eq!(binder.kind, ResolutionBinderKind::Type);
            let local = spelling == "Local";
            assert_eq!(
                binder.hoisting,
                if local {
                    HoistingClass::SourceOrder
                } else {
                    HoistingClass::ScopeWide
                }
            );
            if local {
                assert_eq!(binder.activation_start, source.find("Local =").unwrap());
            }
            assert_eq!(
                facts
                    .package_members
                    .iter()
                    .any(|member| member.declaration == declaration),
                !local
            );
            assert_eq!(
                facts
                    .root_exports
                    .iter()
                    .any(|export| export.declaration == declaration),
                !local && spelling != "private"
            );
            assert!(
                !facts
                    .declaration_type_slots
                    .iter()
                    .any(|slot| slot.declaration == declaration
                        && slot.role == DeclarationTypeRole::NominalIdentity)
            );
            assert!(
                !facts
                    .member_owners
                    .iter()
                    .any(|member| member.owner == declaration)
            );
            let output = declaration_slot(&facts, declaration, DeclarationTypeRole::Identity);
            if spelling == "Generic" {
                assert!(
                    !facts
                        .type_transfers
                        .iter()
                        .any(|transfer| transfer.output == output)
                );
                assert!(facts.gaps.iter().any(|gap| gap.site == declaration
                    && gap.kind == ResolutionGapKind::UnsupportedTypeSyntax));
                continue;
            }
            let transfer = transfer_to(&facts, output);
            assert_eq!(
                transfer.kind,
                if spelling == "Pointer" {
                    ResolutionTypeTransferKind::TypeAlias
                } else {
                    ResolutionTypeTransferKind::TypeIdentity
                }
            );
            assert_eq!(transfer.indirection_delta, i8::from(spelling == "Pointer"));
            let input = facts.type_slots[transfer.input.index()];
            assert_eq!(input.role, ResolutionTypeSlotRole::TargetTypeIdentity);
            if spelling == "Anonymous" {
                assert!(facts.gaps.iter().any(|gap| gap.site == input.site
                    && gap.kind == ResolutionGapKind::UnsupportedTypeSyntax));
            } else {
                assert!(
                    facts
                        .identifiers
                        .iter()
                        .any(|identifier| identifier.site == input.site
                            && identifier.role == ResolutionIdentifierRole::Reference
                            && identifier.namespace == ResolutionNamespace::Type)
                );
            }
        }
    }

    fn declaration(facts: &FileResolutionFacts, spelling: &str) -> ResolutionSiteId {
        let mut declarations = facts.identifiers.iter().filter(|identifier| {
            identifier.role == ResolutionIdentifierRole::Declaration
                && name(facts, identifier.name) == spelling
        });
        let declaration = declarations
            .next()
            .unwrap_or_else(|| panic!("missing declaration {spelling}"))
            .site;
        assert!(
            declarations.next().is_none(),
            "fixture declaration must be unique: {spelling}"
        );
        declaration
    }

    fn reference_owner(
        facts: &FileResolutionFacts,
        reference: ResolutionSiteId,
    ) -> Option<Option<ResolutionSiteId>> {
        facts
            .reference_owners
            .iter()
            .find(|owner| owner.reference == reference)
            .map(|owner| owner.owner)
    }

    fn declaration_slot(
        facts: &FileResolutionFacts,
        declaration: ResolutionSiteId,
        role: DeclarationTypeRole,
    ) -> ResolutionTypeSlotId {
        facts
            .declaration_type_slots
            .iter()
            .find(|property| property.declaration == declaration && property.role == role)
            .unwrap_or_else(|| panic!("missing declaration type property for {declaration}"))
            .slot
    }

    fn transfer_to(
        facts: &FileResolutionFacts,
        output: ResolutionTypeSlotId,
    ) -> ResolutionTypeTransferFact {
        let mut transfers = facts
            .type_transfers
            .iter()
            .copied()
            .filter(|transfer| transfer.output == output);
        let transfer = transfers
            .next()
            .unwrap_or_else(|| panic!("missing transfer to {output}"));
        assert!(transfers.next().is_none(), "output has one producer");
        transfer
    }

    #[test]
    fn selector_assignment_targets_are_member_references() {
        let source = r#"package p

type Row struct { ents []int }

func set(r *Row, rows []int) {
    r.ents = rows
}
"#;
        let facts = facts(source);
        let reference = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && name(&facts, identifier.name) == "ents"
            })
            .expect("selector assignment emits its field reference");
        assert_eq!(
            facts.sites[reference.site.index()].kind,
            ResolutionSiteKind::MemberReference
        );
        assert!(reference.qualifier.is_some());
        assert!(
            facts
                .root_references
                .iter()
                .any(|route| route.reference == reference.site)
        );
        assert!(facts.binding_projections.iter().any(|projection| {
            projection.reference == reference.site
                && projection.kind == BindingProjectionKind::TargetDeclaredValueType
        }));
    }

    #[test]
    fn bare_call_callees_preserve_go_type_conversion_ambiguity() {
        let facts = facts(
            r#"package p

type PackageURL struct{}

func convert(value PackageURL) PackageURL {
    return PackageURL(value)
}
"#,
        );
        // `PackageURL(value)` is a call or a conversion depending on what
        // the name binds to, so the producer emits one reference in the
        // TypeOrValue namespace and the engine decides from the bound target.
        let references = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && name(&facts, identifier.name) == "PackageURL"
                    && facts.sites[identifier.site.index()].kind
                        == ResolutionSiteKind::CallableReference
            })
            .collect::<Vec<_>>();
        assert_eq!(references.len(), 1, "one callee reference: {references:?}");
        let callee = references[0];
        assert_eq!(callee.namespace, ResolutionNamespace::TypeOrValue);
        assert!(facts.calls.iter().any(|call| call.callee == callee.site));
    }

    #[test]
    fn explicit_pointer_and_assignment_keep_declared_and_observed_values_separate() {
        let source = r#"package p

type Typ struct { field string }

func use() {
    var x *Typ
    var y string = "value"
    _ = x.field
    _ = y
}
"#;
        let facts = facts(source);
        let typ = declaration(&facts, "Typ");
        let field = declaration(&facts, "field");
        let x = declaration(&facts, "x");
        let y = declaration(&facts, "y");

        assert_eq!(
            facts.member_owners,
            vec![ResolutionMemberOwnerFact {
                member: field,
                owner: typ,
                kind: ResolutionMemberKind::Field,
                access: ResolutionMemberAccess::Instance,
                qualifier_compatibility: ResolutionMemberQualifierCompatibility::RuntimeOnly,
            }]
        );

        let x_declared = declaration_slot(&facts, x, DeclarationTypeRole::Value);
        assert_eq!(
            transfer_to(&facts, x_declared),
            ResolutionTypeTransferFact {
                input: transfer_to(&facts, x_declared).input,
                output: x_declared,
                kind: ResolutionTypeTransferKind::DeclaredType,
                indirection_delta: 1,
                reference_indirection_delta: 0,
                value_transform: ResolutionTypeTransferValueTransform::ToRuntime {
                    addressable: true,
                },
            }
        );
        assert!(
            !facts.type_slots.iter().any(|slot| {
                slot.site == x && slot.role == ResolutionTypeSlotRole::AssignmentValue
            }),
            "an uninitialized declaration has no observed assignment value"
        );

        let y_declared = declaration_slot(&facts, y, DeclarationTypeRole::Value);
        let y_observed = facts
            .type_slots
            .iter()
            .find(|slot| slot.site == y && slot.role == ResolutionTypeSlotRole::AssignmentValue)
            .expect("y assignment observation")
            .id;
        assert_ne!(y_declared, y_observed);
        let assignment = transfer_to(&facts, y_observed);
        assert_eq!(assignment.kind, ResolutionTypeTransferKind::Assignment);
        assert_eq!(assignment.indirection_delta, 0);
        assert_eq!(
            assignment.value_transform,
            ResolutionTypeTransferValueTransform::ToRuntime { addressable: true }
        );
        assert!(facts.intrinsic_type_seeds.iter().any(|seed| {
            seed.output == assignment.input && name(&facts, seed.name) == "string"
        }));

        let field_reference = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && name(&facts, identifier.name) == "field"
            })
            .expect("qualified field reference");
        let receiver = field_reference.qualifier.expect("field receiver slot");
        assert_eq!(
            facts.type_slots[receiver.index()].role,
            ResolutionTypeSlotRole::Receiver
        );
        assert!(facts.type_transfers.iter().any(|transfer| {
            transfer.output == receiver
                && transfer.kind == ResolutionTypeTransferKind::Receiver
                && transfer.value_transform == ResolutionTypeTransferValueTransform::Preserve
        }));
        assert!(!facts.gaps.contains(&ResolutionGapFact {
            site: field_reference.site,
            kind: ResolutionGapKind::UnsupportedRoute,
        }));
    }

    #[test]
    fn go_clause_binders_have_separate_case_scopes() {
        let source = r#"package consumer

import db "example.test/native/db"

func inspect(value any, input <-chan int) {
    switch db := value.(type) {
    case int:
        _ = db
    default:
        _ = db
    }
    _ = db.Value
    select {
    case db := <-input:
        _ = db
    }
    _ = db.Value
}
"#;
        let facts = facts(source);
        let references = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == ResolutionNamespace::Value
                    && name(&facts, identifier.name) == "db"
            })
            .collect::<Vec<_>>();
        assert_eq!(references.len(), 3);
        let scopes = references
            .iter()
            .map(|reference| facts.sites[reference.site.index()].scope)
            .collect::<HashSet<_>>();
        assert_eq!(scopes.len(), 3, "each clause has its own lexical scope");
        let declarations = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && name(&facts, identifier.name) == "db"
            })
            .count();
        assert_eq!(declarations, 3);
    }

    #[test]
    fn range_iteration_element_type_uses_its_source_scope() {
        let source = r#"package history

type History struct { Revision string }

func visit(history []History) {
	for _, history := range history {
		_ = history.Revision
	}
}
"#;
        let facts = facts(source);
        let reference = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && name(&facts, identifier.name) == "History"
            })
            .expect("range element type reference");
        let site = facts.sites[reference.site.index()];
        let scope = facts.scopes[site.scope.index()];
        assert!(scope.start_byte <= site.start_byte && site.end_byte <= scope.end_byte);
    }

    #[test]
    fn composite_literal_field_receiver_is_a_runtime_value() {
        let source = r#"package p

type Item struct { Field string }
var items = []Item{{Field: "value"}}
"#;
        let facts = facts(source);
        let field = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && name(&facts, identifier.name) == "Field"
            })
            .expect("composite literal field reference");
        assert_eq!(
            facts.sites[field.site.index()].kind,
            ResolutionSiteKind::CompositeLiteralKeyReference
        );
        let receiver = field.qualifier.expect("field receiver");
        let receiver_transfer = transfer_to(&facts, receiver);
        assert_eq!(receiver_transfer.kind, ResolutionTypeTransferKind::Receiver);
        let literal_type = receiver_transfer.input;
        assert_eq!(
            facts.type_slots[literal_type.index()].role,
            ResolutionTypeSlotRole::TargetTypeIdentity
        );
    }

    #[test]
    fn call_of_shadowed_type_name_keeps_value_namespace_reference() {
        let source = "package p; type PackageURL struct {}; func convert(PackageURL func(int)) { PackageURL(1) }";
        let facts = facts(source);
        assert!(facts.identifiers.iter().any(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && identifier.namespace == ResolutionNamespace::TypeOrValue
                && name(&facts, identifier.name) == "PackageURL"
                && facts.sites[identifier.site.index()].kind
                    == ResolutionSiteKind::CallableReference
        }));
    }

    #[test]
    fn builtin_max_keeps_call_result_incomplete_without_fabricated_transfer() {
        let facts = facts("package p; func f(a, b int) { _ = max(a, b) }");
        let call_site = facts
            .sites
            .iter()
            .find(|site| site.kind == ResolutionSiteKind::Call)
            .expect("max call");
        let result = facts
            .type_slots
            .iter()
            .find(|slot| {
                slot.site == call_site.id && slot.role == ResolutionTypeSlotRole::CallResult
            })
            .expect("max call result");
        assert!(
            !facts
                .type_transfers
                .iter()
                .any(|transfer| transfer.output == result.id)
        );
        assert!(
            facts
                .gaps
                .iter()
                .any(|gap| gap.kind == ResolutionGapKind::UnsupportedCallApplicability)
        );
    }

    #[test]
    fn unsupported_nested_structs_are_gapped_without_type_body_scope() {
        let source = concat!(
            "package p\n",
            "type M map[string]struct { Hidden int }\n",
            "type S []struct { Hidden int }\n",
            "type F func() interface { Hidden() }\n",
        );
        let facts = facts(source);

        assert!(facts.member_owners.is_empty());
        assert!(facts.gaps.iter().any(|gap| {
            gap.kind == ResolutionGapKind::UnsupportedTypeSyntax
                && facts.sites[gap.site.index()].kind == ResolutionSiteKind::UnsupportedDeclaration
        }));
    }

    #[test]
    fn method_receivers_publish_deferred_owners_without_inventing_targets() {
        let source = r#"package p

type Typ struct{}

func (v Typ) Value() Typ { return v }
func (p *Typ) Pointer() *Typ { return p }

func use(v Typ, p *Typ) {
    v.Value()
    p.Value()
    v.Pointer()
    p.Pointer()
    Typ{}.Pointer()
}
"#;
        let facts = facts(source);
        let method_sites = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && matches!(name(&facts, identifier.name), "Value" | "Pointer")
            })
            .map(|identifier| identifier.site)
            .collect::<Vec<_>>();
        assert_eq!(method_sites.len(), 2);
        assert!(method_sites.iter().all(|method| {
            facts.gaps.contains(&ResolutionGapFact {
                site: *method,
                kind: ResolutionGapKind::UnsupportedCallApplicability,
            })
        }));
        assert!(
            facts
                .member_owners
                .iter()
                .all(|owner| { !method_sites.contains(&owner.member) }),
            "a receiver type reference is never rewritten to a local owner target"
        );

        let receiver_declarations = facts
            .binders
            .iter()
            .filter(|binder| binder.kind == ResolutionBinderKind::Parameter)
            .filter(|binder| {
                facts.scopes[binder.scope.index()]
                    .owner
                    .is_some_and(|owner| method_sites.contains(&owner))
            })
            .map(|binder| binder.declaration)
            .collect::<Vec<_>>();
        assert_eq!(receiver_declarations.len(), 2);
        let mut receiver_deltas = receiver_declarations
            .iter()
            .map(|receiver| {
                let slot = declaration_slot(&facts, *receiver, DeclarationTypeRole::Parameter);
                let transfer = transfer_to(&facts, slot);
                assert_eq!(
                    transfer.value_transform,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: true }
                );
                transfer.indirection_delta
            })
            .collect::<Vec<_>>();
        receiver_deltas.sort_unstable();
        assert_eq!(receiver_deltas, vec![0, 1]);
        assert_eq!(facts.deferred_member_owners.len(), 2);
        assert!(facts.deferred_member_owners.iter().all(|owner| {
            method_sites.contains(&owner.member)
                && receiver_declarations.iter().any(|receiver| {
                    let value = declaration_slot(&facts, *receiver, DeclarationTypeRole::Parameter);
                    transfer_to(&facts, value).input == owner.owner_type
                })
                && owner.kind == ResolutionMemberKind::Method
                && owner.access == ResolutionMemberAccess::Instance
                && owner.qualifier_compatibility
                    == ResolutionMemberQualifierCompatibility::RuntimeOnly
        }));

        let method_references = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && matches!(name(&facts, identifier.name), "Value" | "Pointer")
            })
            .collect::<Vec<_>>();
        assert_eq!(method_references.len(), 5);
        assert!(method_references.iter().all(|reference| {
            reference.qualifier.is_some()
                && !facts.gaps.contains(&ResolutionGapFact {
                    site: reference.site,
                    kind: ResolutionGapKind::UnsupportedRoute,
                })
                && facts.gaps.contains(&ResolutionGapFact {
                    site: reference.site,
                    kind: ResolutionGapKind::UnsupportedCallApplicability,
                })
        }));
        let construction = facts
            .type_transfers
            .iter()
            .find(|transfer| transfer.kind == ResolutionTypeTransferKind::Construction)
            .expect("composite literal carries its explicit type");
        assert_eq!(
            construction.value_transform,
            ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
            "a composite literal cannot authorize an implicit pointer-method receiver"
        );
    }

    #[test]
    fn composite_literal_fields_and_explicit_type_are_both_lowered() {
        let source =
            "package p; type Typ struct{ Field *Typ }; func f(x *Typ) Typ { return Typ{Field: x} }";
        let facts = facts(source);
        let body_start = source.find("{Field:").unwrap();
        assert!(facts.reference_enumeration_gaps.iter().all(|gap| {
            facts.sites[gap.site.index()].start_byte != body_start
                || gap.kind != ResolutionGapKind::UnsupportedExpression
        }));
        let literal = facts
            .type_transfers
            .iter()
            .find(|transfer| {
                transfer.kind == ResolutionTypeTransferKind::Construction
                    && facts.sites[facts.type_slots[transfer.output.index()].site.index()]
                        .start_byte
                        == source.find("Typ{").unwrap()
            })
            .expect("literal type is independently available");
        let slot = &facts.type_slots[literal.output.index()];
        assert_eq!(slot.role, ResolutionTypeSlotRole::ExpressionValue);
        assert!(!facts.gaps.iter().any(|gap| gap.site == slot.site));
        assert!(
            facts.binding_projections.iter().any(|projection| {
                projection.output == literal.input
                    && projection.kind == BindingProjectionKind::TargetTypeIdentity
            }),
            "a type reached before the outer AST walk still has a binding producer"
        );
        assert!(facts.identifiers.iter().any(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && name(&facts, identifier.name) == "Field"
                && facts.sites[identifier.site.index()].kind
                    == ResolutionSiteKind::CompositeLiteralKeyReference
        }));
        assert!(
            !facts
                .gaps
                .iter()
                .any(|gap| { gap.kind == ResolutionGapKind::MalformedSyntax })
        );
    }

    #[test]
    fn calls_keep_argument_return_result_and_inferred_assignment_rows() {
        let source = r#"package p

type Typ struct{}

func Echo(p *Typ) *Typ { return p }

func use(x *Typ) {
    y := Echo(x)
    _ = y
}
"#;
        let facts = facts(source);
        let echo = declaration(&facts, "Echo");
        let y = declaration(&facts, "y");

        let declared_result = declaration_slot(&facts, echo, DeclarationTypeRole::Return);
        let observed_result = facts
            .type_slots
            .iter()
            .find(|slot| slot.site == echo && slot.role == ResolutionTypeSlotRole::ReturnValue)
            .expect("return observation")
            .id;
        assert_ne!(declared_result, observed_result);
        let returned = transfer_to(&facts, observed_result);
        assert_eq!(returned.kind, ResolutionTypeTransferKind::Return);
        assert_eq!(
            returned.value_transform,
            ResolutionTypeTransferValueTransform::ToRuntime { addressable: false }
        );

        assert_eq!(facts.calls.len(), 1);
        let call = &facts.calls[0];
        assert!(
            facts
                .engine_rule_eligibilities
                .contains(&ResolutionEngineRuleEligibilityFact {
                    site: call.call,
                    rule: ResolutionEngineRuleKind::ArgumentIndependentBinding,
                })
        );
        assert_eq!(call.explicit_type_argument_count, 0);
        assert_eq!(
            facts
                .callable_signatures
                .iter()
                .find(|signature| signature.callable == echo)
                .expect("Echo signature header")
                .type_parameter_count,
            0
        );
        assert_eq!(facts.call_arguments.len(), 1);
        assert_eq!(facts.call_arguments[0].call, call.call);
        let argument = transfer_to(&facts, facts.call_arguments[0].value);
        assert_eq!(argument.kind, ResolutionTypeTransferKind::Argument);
        assert_eq!(
            argument.value_transform,
            ResolutionTypeTransferValueTransform::ToRuntime { addressable: false }
        );
        assert!(facts.binding_projections.contains(&BindingProjectionFact {
            reference: call.callee,
            output: call.result,
            kind: BindingProjectionKind::TargetCallableResultType,
        }));
        assert!(!facts.gaps.contains(&ResolutionGapFact {
            site: call.callee,
            kind: ResolutionGapKind::UnsupportedRoute,
        }));
        assert!(facts.gaps.contains(&ResolutionGapFact {
            site: call.callee,
            kind: ResolutionGapKind::UnsupportedCallApplicability,
        }));

        let y_declared = declaration_slot(&facts, y, DeclarationTypeRole::Value);
        let initialization = transfer_to(&facts, y_declared);
        assert_eq!(initialization.input, call.result);
        assert_eq!(
            initialization.kind,
            ResolutionTypeTransferKind::Initialization
        );
        assert_eq!(initialization.indirection_delta, 0);
        assert_eq!(initialization.reference_indirection_delta, 0);
        assert_eq!(
            initialization.value_transform,
            ResolutionTypeTransferValueTransform::AddressableRuntimeOnly
        );
        let y_observed = facts
            .type_slots
            .iter()
            .find(|slot| slot.site == y && slot.role == ResolutionTypeSlotRole::AssignmentValue)
            .expect("short declaration assignment observation")
            .id;
        let assignment = transfer_to(&facts, y_observed);
        assert_eq!(assignment.kind, ResolutionTypeTransferKind::Assignment);
        assert_eq!(
            assignment.value_transform,
            ResolutionTypeTransferValueTransform::ToRuntime { addressable: true }
        );
        assert!(!facts.gaps.contains(&ResolutionGapFact {
            site: y,
            kind: ResolutionGapKind::InferredType,
        }));
    }

    #[test]
    fn selector_call_callees_are_routes_for_package_functions_methods_and_method_expressions() {
        let source = r#"package p

import model "example.test/model"

type Widget struct{}
func Target() {}
func (w *Widget) Method() {}

func caller(w *Widget) {
    model.Target()
    w.Method()
    model.Widget.Method(w)
    (*model.Widget).Method(w)
}
"#;
        let facts = facts(source);
        assert_eq!(facts.calls.len(), 4);
        let mut calls = facts
            .calls
            .iter()
            .map(|call| {
                let identifier = facts
                    .identifiers
                    .iter()
                    .find(|identifier| {
                        identifier.site == call.callee
                            && identifier.role == ResolutionIdentifierRole::Reference
                    })
                    .expect("positioned selector callee");
                assert_eq!(
                    facts.sites[call.callee.index()].kind,
                    ResolutionSiteKind::MemberReference
                );
                assert_eq!(identifier.namespace, ResolutionNamespace::Callable);
                assert!(!facts.gaps.contains(&ResolutionGapFact {
                    site: call.callee,
                    kind: ResolutionGapKind::UnsupportedRoute,
                }));
                assert!(facts.gaps.contains(&ResolutionGapFact {
                    site: call.callee,
                    kind: ResolutionGapKind::UnsupportedCallApplicability,
                }));
                (
                    facts.sites[call.call.index()].start_byte,
                    name(&facts, identifier.name),
                )
            })
            .collect::<Vec<_>>();
        calls.sort_by_key(|(start, _)| *start);
        assert_eq!(
            calls.into_iter().map(|(_, name)| name).collect::<Vec<_>>(),
            ["Target", "Method", "Method", "Method"]
        );

        assert!(facts.calls.iter().all(|call| {
            facts.callable_receiver_origins.iter().any(|origin| {
                origin.reference == call.callee
                    && origin.origin == ResolutionCallableReceiverOrigin::ExplicitExpression
            })
        }));

        for selector in ["model.Widget.Method", "(*model.Widget).Method"] {
            let receiver_type_start = source.find(selector).unwrap()
                + selector.find("model.Widget").unwrap()
                + "model.".len();
            let receiver_type_end = receiver_type_start + "Widget".len();
            let reference = facts
                .sites
                .iter()
                .find(|site| {
                    site.start_byte == receiver_type_start && site.end_byte == receiver_type_end
                })
                .expect("method-expression package type has a positioned site")
                .id;
            let identifier = facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.site == reference
                        && identifier.role == ResolutionIdentifierRole::Reference
                })
                .expect("method-expression package type has a reference");
            assert_eq!(identifier.namespace, ResolutionNamespace::TypeOrValue);
            assert_eq!(
                facts
                    .binding_projections
                    .iter()
                    .find(|projection| projection.reference == reference)
                    .expect("method-expression package type has a transfer")
                    .kind,
                BindingProjectionKind::TargetTypeOrDeclaredValueType,
            );
        }
    }

    #[test]
    fn reference_owners_follow_named_declarations_through_literals_and_package_initializers() {
        let source = r#"package p

type Other int
type Holder struct { Field Other }
func Target(value Other) Other { return value }
var packageValue = Target(0)

func caller() {
    Target(1)
    callback := func(parameter int) { Target(parameter); _ = parameter }
    _ = callback
}

func (receiver *Holder) Method() {
    Target(2)
    callback := func() { Target(3) }
    _ = callback
}
"#;
        let facts = facts(source);
        let caller = declaration(&facts, "caller");
        let target = declaration(&facts, "Target");
        let method = declaration(&facts, "Method");
        let holder = declaration(&facts, "Holder");
        let reference_at = |start: usize| {
            facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Reference
                        && facts.sites[identifier.site.index()].start_byte == start
                })
                .expect("reference at fixture location")
                .site
        };
        let target_call = |spelling: &str| {
            let start = source.find(spelling).expect("unique call spelling");
            reference_at(start)
        };

        assert_eq!(
            reference_owner(&facts, target_call("Target(0)")),
            Some(None),
            "package initializer references use the source-unit owner"
        );
        assert_eq!(
            reference_owner(&facts, target_call("Target(1)")),
            Some(Some(caller))
        );
        assert_eq!(
            reference_owner(&facts, target_call("Target(parameter)")),
            Some(Some(caller)),
            "function literal references retain the enclosing named function"
        );
        assert_eq!(
            reference_owner(&facts, target_call("Target(2)")),
            Some(Some(method))
        );
        assert_eq!(
            reference_owner(&facts, target_call("Target(3)")),
            Some(Some(method))
        );

        let other = source
            .match_indices("Other")
            .nth(1)
            .expect("field type name")
            .0;
        assert_eq!(
            reference_owner(&facts, reference_at(other)),
            Some(Some(holder))
        );

        let signature_type_references = source
            .match_indices("Other")
            .skip(2)
            .take(2)
            .map(|(start, _)| reference_at(start))
            .collect::<Vec<_>>();
        assert_eq!(signature_type_references.len(), 2);
        assert!(
            signature_type_references
                .iter()
                .all(|reference| { reference_owner(&facts, *reference) == Some(Some(target)) })
        );

        let receiver_type = source
            .match_indices("Holder")
            .nth(1)
            .expect("method receiver type")
            .0;
        assert_eq!(
            reference_owner(&facts, reference_at(receiver_type)),
            Some(Some(method))
        );

        let parameter = source
            .match_indices("parameter")
            .nth(1)
            .expect("function-literal parameter reference")
            .0;
        assert_eq!(
            reference_owner(&facts, reference_at(parameter)),
            Some(Some(caller))
        );
        assert!(facts.calls.iter().any(|call| {
            facts.sites[call.call.index()].start_byte
                == source.find("Target(parameter)").expect("literal call")
        }));
        assert!(facts.calls.iter().any(|call| {
            facts.sites[call.call.index()].start_byte
                == source.find("Target(3)").expect("method literal call")
        }));
    }

    #[test]
    fn generic_callable_and_invocation_arities_are_structured() {
        let source = r#"package p

func F[T, U any]() {}

func use() {
    F[int, string]()
}
"#;
        let facts = facts(source);
        let callable = declaration(&facts, "F");
        assert_eq!(
            facts
                .callable_signatures
                .iter()
                .find(|signature| signature.callable == callable)
                .expect("generic function signature header")
                .type_parameter_count,
            2
        );
        assert_eq!(facts.calls.len(), 1);
        assert_eq!(facts.calls[0].explicit_type_argument_count, 2);
    }

    #[test]
    fn unnamed_parameters_preserve_signature_positions_without_bindings() {
        let source = r#"package p

type T struct{}
func Named(value int, pointer *T) {}
func Unnamed(int, *T) {}
func Zero() {}
func Result() (int) { return 1 }
func NamedResult() (value int) { return }
func Results() (int, *T) { return 1, nil }
func (receiver *T) NamedMethod(value int) {}
func (*T) UnnamedMethod(int) {}
"#;
        let facts = facts(source);
        for (spelling, expected_depths) in [
            ("Named", vec![0, 1]),
            ("Unnamed", vec![0, 1]),
            ("Zero", vec![]),
            ("Result", vec![]),
            ("NamedResult", vec![]),
            ("Results", vec![]),
            ("NamedMethod", vec![0]),
            ("UnnamedMethod", vec![0]),
        ] {
            let callable = declaration(&facts, spelling);
            let parameters = facts
                .callable_parameters
                .iter()
                .filter(|parameter| parameter.callable == callable)
                .collect::<Vec<_>>();
            assert_eq!(parameters.len(), expected_depths.len(), "{spelling}");
            for (ordinal, (parameter, depth)) in parameters.iter().zip(expected_depths).enumerate()
            {
                assert_eq!(parameter.ordinal as usize, ordinal, "{spelling}");
                assert_eq!(
                    transfer_to(&facts, parameter.value_type).indirection_delta,
                    depth
                );
                assert!(!parameter.repeated);
                if matches!(spelling, "Unnamed" | "UnnamedMethod") {
                    assert!(
                        !facts
                            .identifiers
                            .iter()
                            .any(|id| id.site == parameter.parameter)
                    );
                    assert!(
                        !facts
                            .binders
                            .iter()
                            .any(|binder| binder.declaration == parameter.parameter)
                    );
                    assert!(
                        !facts
                            .declaration_type_slots
                            .iter()
                            .any(|property| property.declaration == parameter.parameter)
                    );
                }
            }
        }
        let unnamed = declaration(&facts, "Unnamed");
        assert!(!facts.gaps.contains(&ResolutionGapFact {
            site: unnamed,
            kind: ResolutionGapKind::UnsupportedCallApplicability,
        }));
        for spelling in ["NamedMethod", "UnnamedMethod"] {
            let method = declaration(&facts, spelling);
            let owner = facts
                .deferred_member_owners
                .iter()
                .find(|owner| owner.member == method)
                .expect("receiver owner");
            let receiver_transfer = facts
                .type_transfers
                .iter()
                .find(|transfer| {
                    transfer.input == owner.owner_type && transfer.indirection_delta == 1
                })
                .expect("pointer receiver type transfer");
            let receiver_site = facts.type_slots[receiver_transfer.output.index()].site;
            assert!(
                !facts
                    .callable_parameters
                    .iter()
                    .any(|parameter| parameter.parameter == receiver_site)
            );
            if spelling == "UnnamedMethod" {
                assert!(!facts.identifiers.iter().any(|id| id.site == receiver_site));
                assert!(
                    !facts
                        .binders
                        .iter()
                        .any(|binder| binder.declaration == receiver_site)
                );
            }
            assert!(facts.gaps.contains(&ResolutionGapFact {
                site: method,
                kind: ResolutionGapKind::UnsupportedCallApplicability,
            }));
        }
        for (spelling, expected_result_count) in [
            ("Zero", 0),
            ("Result", 1),
            ("NamedResult", 1),
            ("Results", 2),
        ] {
            let callable = declaration(&facts, spelling);
            let signature = facts
                .callable_signatures
                .iter()
                .find(|signature| signature.callable == callable)
                .expect("callable result signature");
            assert_eq!(
                signature.result_types.len(),
                expected_result_count,
                "{spelling}"
            );
            for (ordinal, result) in signature.result_types.iter().enumerate() {
                assert_eq!(result.ordinal as usize, ordinal, "{spelling}");
                assert_eq!(
                    facts.type_slots[result.value_type.index()].role,
                    ResolutionTypeSlotRole::DeclaredValue,
                    "{spelling} result {ordinal}"
                );
                assert_eq!(
                    transfer_to(&facts, result.value_type).kind,
                    ResolutionTypeTransferKind::DeclaredType,
                    "{spelling} result {ordinal}"
                );
            }
            assert!(!facts.gaps.contains(&ResolutionGapFact {
                site: callable,
                kind: ResolutionGapKind::UnsupportedTypeSyntax,
            }));
        }
    }

    #[test]
    fn function_typed_values_publish_result_signatures_without_opaque_type_gaps() {
        let facts = facts(
            r#"package p
            type Result struct{}
            func use(function func() Result) { _ = function() }
            "#,
        );
        let function = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && name(&facts, identifier.name) == "function"
            })
            .expect("function-typed parameter declaration")
            .site;
        let signature = facts
            .callable_signatures
            .iter()
            .find(|signature| signature.callable == function)
            .expect("function-valued declaration result signature");
        assert_eq!(signature.result_types.len(), 1);
        assert_eq!(signature.result_types[0].ordinal, 0);
        assert!(!facts.gaps.iter().any(|gap| gap.site == function));
    }

    #[test]
    fn malformed_receivers_keep_arguments_without_owner_guesses() {
        for (receiver, gap) in [
            ("left, right T", ResolutionGapKind::MalformedSyntax),
            ("left T, right T", ResolutionGapKind::MalformedSyntax),
            ("", ResolutionGapKind::MalformedSyntax),
        ] {
            let source =
                format!("package p\ntype T struct{{}}\nfunc ({receiver}) Method(input int) {{}}\n");
            let facts = facts(&source);
            let method = declaration(&facts, "Method");
            assert!(
                facts.gaps.contains(&ResolutionGapFact {
                    site: method,
                    kind: gap
                }),
                "{receiver}"
            );
            assert!(facts.deferred_member_owners.is_empty(), "{receiver}");
            assert!(facts.member_owners.is_empty(), "{receiver}");
            let parameters = facts
                .callable_parameters
                .iter()
                .filter(|parameter| parameter.callable == method)
                .collect::<Vec<_>>();
            assert_eq!(parameters.len(), 1, "{receiver}");
            assert_eq!(parameters[0].ordinal, 0);
            assert_eq!(parameters[0].parameter, declaration(&facts, "input"));
            assert!(facts.gaps.contains(&ResolutionGapFact {
                site: method,
                kind: ResolutionGapKind::UnsupportedCallApplicability,
            }));
        }
    }

    #[test]
    fn unsupported_receiver_types_remain_gapped_identity_frontiers() {
        for (receiver, has_structural_sequence) in [("value []T", true), ("value T[A]", false)] {
            let source =
                format!("package p\ntype T struct{{}}\nfunc ({receiver}) Method(input int) {{}}\n");
            let facts = facts(&source);
            let method = declaration(&facts, "Method");
            let owner = facts
                .deferred_member_owners
                .iter()
                .find(|owner| owner.member == method)
                .expect("deferred receiver owner");
            let owner_slot = facts.type_slots[owner.owner_type.index()];
            assert_eq!(owner_slot.role, ResolutionTypeSlotRole::TargetTypeIdentity);
            if has_structural_sequence {
                assert!(facts.type_components.iter().any(|component| {
                    component.container == owner.owner_type
                        && component.constructor == ResolutionTypeConstructorKind::Sequence
                        && component.kind == ResolutionTypeComponentKind::Element
                }));
                assert!(!facts.gaps.iter().any(|gap| {
                    gap.site == owner_slot.site
                        && gap.kind == ResolutionGapKind::UnsupportedTypeSyntax
                }));
            } else {
                assert!(facts.gaps.contains(&ResolutionGapFact {
                    site: owner_slot.site,
                    kind: ResolutionGapKind::UnsupportedTypeSyntax,
                }));
            }
            assert!(facts.member_owners.is_empty());
            assert_eq!(facts.callable_parameters.len(), 1);
            assert_eq!(
                facts.callable_parameters[0].parameter,
                declaration(&facts, "input")
            );
        }
    }

    #[test]
    fn variadic_parameter_rows_gap_the_callable_signature_inventory() {
        let source = r#"package p

func V(values ...int) {}
func U(...int) {}
"#;
        let facts = facts(source);
        for spelling in ["V", "U"] {
            let callable = declaration(&facts, spelling);
            assert!(facts.gaps.contains(&ResolutionGapFact {
                site: callable,
                kind: ResolutionGapKind::UnsupportedCallApplicability,
            }));
            assert!(
                facts
                    .callable_parameters
                    .iter()
                    .all(|parameter| parameter.callable != callable),
                "unsupported parameter rows are not fabricated for {spelling}"
            );
        }
    }

    #[test]
    fn address_of_literal_produces_pointer_before_assignment() {
        let source = r#"package p

type Typ struct{}

func use() {
    var x *Typ = &Typ{}
    _ = x
}
"#;
        let facts = facts(source);
        let x = declaration(&facts, "x");
        let x_declared = declaration_slot(&facts, x, DeclarationTypeRole::Value);
        let declared_transfer = transfer_to(&facts, x_declared);
        assert_eq!(declared_transfer.indirection_delta, 1);
        assert_eq!(
            declared_transfer.value_transform,
            ResolutionTypeTransferValueTransform::ToRuntime { addressable: true }
        );

        let address = facts
            .type_transfers
            .iter()
            .find(|transfer| transfer.kind == ResolutionTypeTransferKind::AddressOf)
            .expect("address-of transfer");
        assert_eq!(address.indirection_delta, 1);
        assert_eq!(address.reference_indirection_delta, 0);
        assert_eq!(
            address.value_transform,
            ResolutionTypeTransferValueTransform::RuntimeOnly
        );
        let assignment = facts
            .type_transfers
            .iter()
            .find(|transfer| transfer.kind == ResolutionTypeTransferKind::Assignment)
            .expect("initializer assignment boundary");
        assert_eq!(assignment.input, address.output);
        assert_eq!(assignment.indirection_delta, 0);
        assert!(facts.type_transfers.iter().all(|transfer| {
            transfer.indirection_delta == 0
                || matches!(
                    transfer.kind,
                    ResolutionTypeTransferKind::DeclaredType
                        | ResolutionTypeTransferKind::AddressOf
                )
        }));
    }

    #[test]
    fn cross_file_method_owner_is_a_deferred_receiver_type_frontier() {
        let source = r#"package p

func (p *Remote) Method() *Remote { return p }
"#;
        let facts = facts(source);
        let method = declaration(&facts, "Method");
        assert!(facts.member_owners.is_empty());
        assert!(facts.gaps.contains(&ResolutionGapFact {
            site: method,
            kind: ResolutionGapKind::UnsupportedCallApplicability,
        }));
        assert!(!facts.identifiers.iter().any(|identifier| {
            identifier.role == ResolutionIdentifierRole::Declaration
                && name(&facts, identifier.name) == "Remote"
        }));
        let remote_references = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == ResolutionNamespace::Type
                    && name(&facts, identifier.name) == "Remote"
            })
            .collect::<Vec<_>>();
        assert_eq!(remote_references.len(), 2);
        assert!(remote_references.iter().all(|reference| {
            facts.binding_projections.iter().any(|projection| {
                projection.reference == reference.site
                    && projection.kind == BindingProjectionKind::TargetTypeIdentity
            })
        }));
        let receiver = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && name(&facts, identifier.name) == "p"
            })
            .expect("receiver declaration")
            .site;
        let receiver_slot = declaration_slot(&facts, receiver, DeclarationTypeRole::Parameter);
        assert_eq!(transfer_to(&facts, receiver_slot).indirection_delta, 1);
        assert_eq!(
            facts.deferred_member_owners,
            vec![ResolutionDeferredMemberOwnerFact {
                member: method,
                owner_type: transfer_to(&facts, receiver_slot).input,
                kind: ResolutionMemberKind::Method,
                access: ResolutionMemberAccess::Instance,
                qualifier_compatibility: ResolutionMemberQualifierCompatibility::RuntimeOnly,
            }]
        );
    }

    #[test]
    fn call_syntax_preserves_callable_or_type_ambiguity_as_a_route_gap() {
        let source = r#"package p

func F(x int) int { return x }
type T int

func use(x int) {
    _ = F(x)
    _ = T(x)
}
"#;
        let facts = facts(source);
        assert_eq!(facts.calls.len(), 2);
        let callees = facts
            .calls
            .iter()
            .map(|call| {
                let identifier = facts
                    .identifiers
                    .iter()
                    .find(|identifier| identifier.site == call.callee)
                    .expect("positioned call callee");
                assert_eq!(identifier.namespace, ResolutionNamespace::TypeOrValue);
                assert!(!facts.gaps.contains(&ResolutionGapFact {
                    site: call.callee,
                    kind: ResolutionGapKind::UnsupportedRoute,
                }));
                assert!(facts.gaps.contains(&ResolutionGapFact {
                    site: call.callee,
                    kind: ResolutionGapKind::UnsupportedCallApplicability,
                }));
                name(&facts, identifier.name)
            })
            .collect::<Vec<_>>();
        assert_eq!(callees, vec!["F", "T"]);
    }

    #[test]
    fn predeclared_type_spellings_remain_revision_selected_references() {
        let ordinary = facts(
            r#"package p

func use() { var value string; _ = value }
"#,
        );
        let shadowed = facts(
            r#"package p

type string struct{}
func use() { var value string; _ = value }
"#,
        );

        for facts in [&ordinary, &shadowed] {
            let reference = facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Reference
                        && identifier.namespace == ResolutionNamespace::Type
                        && name(facts, identifier.name) == "string"
                })
                .expect("string type occurrence remains a reference");
            let projection = facts
                .binding_projections
                .iter()
                .find(|projection| projection.reference == reference.site)
                .expect("type reference projection");
            assert_eq!(projection.kind, BindingProjectionKind::TargetTypeIdentity);
            assert!(
                facts
                    .intrinsic_type_seeds
                    .iter()
                    .all(|seed| seed.output != projection.output),
                "a shadowable universe-block spelling is not an intrinsic type object"
            );
        }
        assert!(shadowed.identifiers.iter().any(|identifier| {
            identifier.role == ResolutionIdentifierRole::Declaration
                && identifier.namespace == ResolutionNamespace::Type
                && name(&shadowed, identifier.name) == "string"
        }));
    }

    #[test]
    fn extraction_is_deterministic_and_contains_no_resolved_target_relation() {
        let source = r#"package p

type Typ struct { field string }
func Echo(p *Typ) *Typ { return p }
func use(x *Typ) { y := Echo(x); _ = y.field }
"#;
        let first = facts(source);
        let second = facts(source);
        assert_eq!(first, second);
        // FileResolutionFacts intentionally has references, projections, and
        // owner properties, but no reference-to-definition target row. This
        // law catches accidental migration of the old spike's expected target
        // into the production producer by checking every relation that can
        // mention two sites has a source-owned semantic meaning.
        assert!(first.binding_projections.iter().all(|projection| {
            first.identifiers.iter().any(|identifier| {
                identifier.site == projection.reference
                    && identifier.role == ResolutionIdentifierRole::Reference
            })
        }));
        assert!(first.member_owners.iter().all(|owner| {
            first.identifiers.iter().any(|identifier| {
                identifier.site == owner.member
                    && identifier.role == ResolutionIdentifierRole::Declaration
            }) && first.identifiers.iter().any(|identifier| {
                identifier.site == owner.owner
                    && identifier.role == ResolutionIdentifierRole::Declaration
            })
        }));
    }
}
