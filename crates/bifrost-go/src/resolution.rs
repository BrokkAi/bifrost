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
#[cfg(test)]
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionReferenceEnumerationGapFact;
use brokk_bifrost_core::analyzer::resolution_facts::{
    BindingProjectionFact, BindingProjectionKind, DeclarationTypeRole, DeclarationTypeSlotFact,
    FileResolutionFacts, IntrinsicTypeKind, IntrinsicTypeSeedFact, PositionedIdentifierFact,
    ResolutionAdditionalDefinitionNamespaceFact, ResolutionBinderFact, ResolutionBinderKind,
    ResolutionCallArgumentFact, ResolutionCallTypeArgumentFact, ResolutionCallableParameterFact,
    ResolutionCallableReceiverOrigin, ResolutionCallableReceiverOriginFact,
    ResolutionCallableResultTypeFact, ResolutionCallableSignatureFact,
    ResolutionDeclaredTypeArgumentFact, ResolutionDeclaredTypeRelationFact,
    ResolutionDeclaredTypeRelationKind, ResolutionDeferredMemberOwnerFact,
    ResolutionEngineRuleEligibilityFact, ResolutionEngineRuleKind, ResolutionGapFact,
    ResolutionGapKind, ResolutionGoPackageImportFact, ResolutionGoPackageImportKind,
    ResolutionIdentifierRole, ResolutionMemberAccess, ResolutionMemberKind,
    ResolutionMemberOwnerFact, ResolutionMemberQualifierCompatibility, ResolutionNameId,
    ResolutionNamespace, ResolutionPackageMemberFact, ResolutionReferenceOwnerFact,
    ResolutionRootExportFact, ResolutionRootImportAnchor, ResolutionRootImportDemandTarget,
    ResolutionRootImportDemandTargetFact, ResolutionRootImportFact, ResolutionRootImportKind,
    ResolutionRootImportKindFact, ResolutionRootImportSegmentFact, ResolutionRootReferenceFact,
    ResolutionRootReferenceSegmentFact, ResolutionScopeFact, ResolutionScopeId,
    ResolutionScopeInheritance, ResolutionScopeKind, ResolutionSiteFact, ResolutionSiteId,
    ResolutionSiteKind, ResolutionSupertypeFact, ResolutionSupertypeKind,
    ResolutionTypeComponentFact, ResolutionTypeComponentKind, ResolutionTypeConstructorKind,
    ResolutionTypeRelationId, ResolutionTypeSlotFact, ResolutionTypeSlotId, ResolutionTypeSlotRole,
    ResolutionTypeTransferFact, ResolutionTypeTransferKind, ResolutionTypeTransferValueTransform,
    dense_ordinal,
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
    source_type_parameter_counts: HashMap<String, usize>,
    callable_contexts: Vec<CallableContext>,
    declaration_owners: Vec<ResolutionSiteId>,
    function_literal_contexts: Vec<FunctionLiteralContext>,
    body_scopes: HashMap<usize, ResolutionScopeId>,
    type_syntax_by_node: HashMap<usize, LoweredTypeSyntax>,
    function_types_by_slot: HashMap<ResolutionTypeSlotId, Node<'tree>>,
    expression_slots_by_node: HashMap<usize, ResolutionTypeSlotId>,
    const_iota_ordinal: Option<u32>,
    value_names_by_scope: HashMap<ResolutionScopeId, HashSet<String>>,
    next_parameter_ordinal: HashMap<ResolutionSiteId, u32>,
    lowered_type_parameter_lists: HashSet<usize>,
    explicit_package_import_aliases: HashSet<String>,
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

/// Recovery can produce a zero-width MISSING node whose kind is still an
/// identifier. Such a node has no spelling and cannot support a name fact.
fn is_spelled_identifier(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "identifier" | "type_identifier" | "field_identifier" | "package_identifier"
    ) && !node.is_missing()
}

#[derive(Debug, Clone, Copy)]
enum ExitAction {
    Scope,
    TypeContext,
    AnonymousTypeBody,
    CallableContext,
    FunctionLiteralContext,
}

#[derive(Debug, Clone, Copy)]
struct TypeContext {
    declaration: ResolutionSiteId,
    generic_scope: Option<ResolutionScopeId>,
}

#[derive(Debug, Clone, Copy)]
struct TypeAliasContext {
    generic_scope: Option<ResolutionScopeId>,
}

#[derive(Debug, Clone, Copy)]
struct CallableContext {
    declaration: ResolutionSiteId,
    scope: ResolutionScopeId,
    activation_start: usize,
    activation_end: usize,
    receiver_span: Option<(usize, usize)>,
    receiver_is_malformed: bool,
    receiver_name: Option<ResolutionNameId>,
}

#[derive(Debug, Clone, Copy)]
struct FunctionLiteralContext {
    node: usize,
    callable: ResolutionSiteId,
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

fn go_source_type_parameter_counts(root: Node<'_>, source: &str) -> HashMap<String, usize> {
    let mut counts = HashMap::default();
    let mut duplicates = HashSet::default();
    let mut cursor = root.walk();
    for declaration in root.named_children(&mut cursor) {
        let declarations = match declaration.kind() {
            "type_declaration" => named_children(declaration),
            "type_alias" => vec![declaration],
            _ => continue,
        };
        for declaration in declarations {
            if !matches!(declaration.kind(), "type_spec" | "type_alias") {
                continue;
            }
            let Some(name) = declaration.child_by_field_name("name") else {
                continue;
            };
            let count = declaration
                .child_by_field_name("type_parameters")
                .map(|parameters| {
                    named_children(parameters)
                        .into_iter()
                        .map(|parameter| children_by_field(parameter, "name").len())
                        .sum()
                })
                .unwrap_or(0);
            let name = go_node_text(name, source).trim().to_owned();
            if name.is_empty() || duplicates.contains(&name) {
                continue;
            }
            if counts.insert(name.clone(), count).is_some() {
                counts.remove(&name);
                duplicates.insert(name);
            }
        }
    }
    counts
}

fn go_package_value_names(root: Node<'_>, source: &str) -> HashSet<String> {
    let mut names = HashSet::default();
    for declaration in named_children(root) {
        if !matches!(declaration.kind(), "var_declaration" | "const_declaration") {
            continue;
        }
        for spec in named_children(declaration) {
            if !matches!(spec.kind(), "var_spec" | "const_spec") {
                continue;
            }
            for name in children_by_field(spec, "name") {
                if !is_spelled_identifier(name) {
                    continue;
                }
                let spelling = go_node_text(name, source).trim();
                if spelling != "_" {
                    names.insert(spelling.to_owned());
                }
            }
        }
    }
    names
}

impl<'source, 'tree> GoResolutionBuilder<'source, 'tree> {
    pub(crate) fn new(root: Node<'tree>, source: &'source str) -> Self {
        let source_type_parameter_counts = go_source_type_parameter_counts(root, source);
        let package_value_names = go_package_value_names(root, source);
        let compilation_unit = ResolutionScopeId::new(0);
        let package = ResolutionScopeId::new(1);
        let file_scope = ResolutionScopeId::new(2);
        let mut value_names_by_scope = HashMap::default();
        value_names_by_scope.insert(package, package_value_names);
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
            source_type_parameter_counts,
            callable_contexts: Vec::new(),
            declaration_owners: Vec::new(),
            function_literal_contexts: Vec::new(),
            body_scopes: HashMap::default(),
            type_syntax_by_node: HashMap::default(),
            function_types_by_slot: HashMap::default(),
            expression_slots_by_node: HashMap::default(),
            const_iota_ordinal: None,
            value_names_by_scope,
            next_parameter_ordinal: HashMap::default(),
            lowered_type_parameter_lists: HashSet::default(),
            explicit_package_import_aliases: HashSet::default(),
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
        self.source_collector.declare_node(node, name)
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
    ) -> Option<ResolutionSiteId> {
        let site = self.add_identifier_site(name, kind, scope, role, namespace, qualifier)?;
        let source_declaration = self.declare_node(owner, Some(name));
        self.declaration_sources.push((site, source_declaration));
        Some(site)
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
        if let Some(action) = self.capture_and_check_node(node) {
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
        if let Some(action) = self.capture_and_check_node(node) {
            return action;
        }
        self.lower_root_imports(specs);
        if specs.is_empty()
            || specs.iter().any(|spec| {
                spec.segments.is_empty() || spec.segments.iter().any(|segment| segment.is_empty())
            })
        {
            // Named, blank, and dot imports all have exact structured rows;
            // dot-import export demands are emitted after references are lowered.
            self.gap_and_skip(
                node,
                ResolutionSiteKind::UnsupportedRoute,
                ResolutionGapKind::UnsupportedRoute,
            )
        } else {
            // Retain the whole declaration range alongside per-spec routes.
            self.add_site(node, ResolutionSiteKind::ImportDeclaration);
            TreeWalkAction::Skip
        }
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

    fn capture_and_check_node(&mut self, node: Node<'_>) -> Option<TreeWalkAction> {
        self.capture_source_node(node);
        self.enter_preamble(node)
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
                let Some(context) = self.lower_type_alias(node) else {
                    return self.gap_and_skip(
                        node,
                        ResolutionSiteKind::UnsupportedDeclaration,
                        ResolutionGapKind::MalformedSyntax,
                    );
                };
                if context.generic_scope.is_some() {
                    self.exit_actions.push(ExitAction::Scope);
                    TreeWalkAction::DescendWithExit
                } else if has_supported_anonymous_type(node) {
                    TreeWalkAction::Descend
                } else {
                    TreeWalkAction::Skip
                }
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
                if has_supported_anonymous_type(node) {
                    TreeWalkAction::Descend
                } else {
                    TreeWalkAction::Skip
                }
            }
            "parameter_declaration" => {
                self.lower_parameter(node, false);
                if has_supported_anonymous_type(node) {
                    TreeWalkAction::Descend
                } else {
                    TreeWalkAction::Skip
                }
            }
            "variadic_parameter_declaration" => {
                self.lower_parameter(node, true);
                if has_supported_anonymous_type(node) {
                    TreeWalkAction::Descend
                } else {
                    TreeWalkAction::Skip
                }
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
            "send_statement" => {
                let (Some(channel), Some(value)) = (
                    node.child_by_field_name("channel"),
                    node.child_by_field_name("value"),
                ) else {
                    return self.gap_and_skip(
                        node,
                        ResolutionSiteKind::UnsupportedExpression,
                        ResolutionGapKind::MalformedSyntax,
                    );
                };
                self.lower_expression(channel);
                self.lower_expression(value);
                let site = self.add_site(node, ResolutionSiteKind::UnsupportedExpression);
                self.add_gap(site, ResolutionGapKind::UnsupportedExpressionType);
                TreeWalkAction::Descend
            }
            "inc_statement" | "dec_statement" => {
                let Some(operand) = first_named_child(node) else {
                    return self.gap_and_skip(
                        node,
                        ResolutionSiteKind::UnsupportedExpression,
                        ResolutionGapKind::MalformedSyntax,
                    );
                };
                self.lower_expression(operand);
                let site = self.add_site(node, ResolutionSiteKind::UnsupportedExpression);
                self.add_gap(site, ResolutionGapKind::UnsupportedExpressionType);
                TreeWalkAction::Skip
            }
            "for_statement" => self.enter_for_statement(node),
            "range_clause" => {
                self.lower_range_clause(node);
                TreeWalkAction::Descend
            }
            "if_statement" => self.enter_if_statement(node),
            "interface_type" => self.enter_anonymous_interface_type(node),
            "type_parameter_list" => {
                if self.lowered_type_parameter_lists.contains(&node.id()) {
                    TreeWalkAction::Descend
                } else {
                    self.gap_and_skip(
                        node,
                        ResolutionSiteKind::UnsupportedDeclaration,
                        ResolutionGapKind::UnsupportedScopeOrBinder,
                    )
                }
            }
            "type_parameter_declaration" => {
                if node
                    .parent()
                    .is_some_and(|list| self.lowered_type_parameter_lists.contains(&list.id()))
                {
                    TreeWalkAction::Descend
                } else {
                    self.gap_and_skip(
                        node,
                        ResolutionSiteKind::UnsupportedDeclaration,
                        ResolutionGapKind::UnsupportedScopeOrBinder,
                    )
                }
            }
            "expression_switch_statement" => self.enter_expression_switch(node),
            "type_switch_statement" => self.enter_type_switch(node),
            "select_statement" => self.enter_block_scope(node),
            "expression_case" => self.enter_expression_case(node),
            "type_case" => self.enter_type_case(node),
            "communication_case" => self.enter_communication_case(node),
            "default_case" => self.enter_default_case(node),
            "go_statement" | "defer_statement" => {
                if let Some(call) = first_named_child(node) {
                    self.lower_expression(call);
                    // Lower the call expression once, then keep walking its
                    // syntax so function-literal callees and arguments get
                    // their executable scopes and bodies lowered as well.
                    TreeWalkAction::Descend
                } else {
                    self.gap_and_skip(
                        node,
                        ResolutionSiteKind::UnsupportedExpression,
                        ResolutionGapKind::MalformedSyntax,
                    )
                }
            }
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

    fn enter_for_statement(&mut self, node: Node<'tree>) -> TreeWalkAction {
        self.push_block_scope(node);

        for child in named_children(node) {
            match child.kind() {
                "block" | "range_clause" => {}
                "for_clause" => {
                    if let Some(condition) = child.child_by_field_name("condition") {
                        self.lower_expression(condition);
                    }
                }
                _ => {
                    self.lower_expression(child);
                }
            }
        }

        TreeWalkAction::DescendWithExit
    }

    fn enter_anonymous_interface_type(&mut self, node: Node<'tree>) -> TreeWalkAction {
        let Some(syntax) = self.type_syntax_by_node.get(&node.id()).copied() else {
            return self.gap_and_skip(
                node,
                ResolutionSiteKind::UnsupportedDeclaration,
                ResolutionGapKind::UnsupportedTypeSyntax,
            );
        };
        let declaration = self.slot(syntax.input).site;
        if self.facts.sites[declaration.index()].kind != ResolutionSiteKind::TypeDeclaration {
            return TreeWalkAction::Descend;
        }
        let parent = self.scope_for_source_range(node.start_byte(), node.end_byte());
        let scope = self.allocate_scope(
            parent,
            Some(declaration),
            ResolutionScopeKind::TypeBody,
            node.start_byte(),
            node.end_byte(),
        );
        self.scope_stack.push(scope);
        self.type_contexts.push(TypeContext {
            declaration,
            generic_scope: None,
        });
        self.declaration_owners.push(declaration);
        self.exit_actions.push(ExitAction::AnonymousTypeBody);
        TreeWalkAction::DescendWithExit
    }

    fn enter_struct_type(&mut self, node: Node<'tree>) -> TreeWalkAction {
        let Some(fields) = named_children(node)
            .into_iter()
            .find(|child| child.kind() == "field_declaration_list")
        else {
            return self.gap_and_skip(
                node,
                ResolutionSiteKind::UnsupportedDeclaration,
                ResolutionGapKind::MalformedSyntax,
            );
        };
        if self.body_scopes.contains_key(&fields.id()) {
            TreeWalkAction::Descend
        } else {
            let syntax = self.lower_anonymous_struct_type(node);
            let declaration = self.slot(syntax.input).site;
            assert_eq!(
                self.facts.sites[declaration.index()].kind,
                ResolutionSiteKind::TypeDeclaration,
                "anonymous Go struct syntax owns its TypeBody"
            );
            let parent = self.scope_for_source_range(node.start_byte(), node.end_byte());
            let body_scope = self.allocate_scope(
                parent,
                Some(declaration),
                ResolutionScopeKind::TypeBody,
                node.start_byte(),
                node.end_byte(),
            );
            assert!(self.body_scopes.insert(fields.id(), body_scope).is_none());
            self.type_contexts.push(TypeContext {
                declaration,
                generic_scope: None,
            });
            // Anonymous struct fields are storage inside the enclosing named
            // declaration. Their type mentions belong to that declaration's
            // graph node, not to the synthetic type identity used to lower
            // the anonymous field layout.
            let reference_owner = self
                .declaration_owners
                .last()
                .copied()
                .unwrap_or(declaration);
            self.declaration_owners.push(reference_owner);
            self.exit_actions.push(ExitAction::TypeContext);
            TreeWalkAction::DescendWithExit
        }
    }

    fn lower_anonymous_struct_type(&mut self, node: Node<'tree>) -> LoweredTypeSyntax {
        if let Some(syntax) = self.type_syntax_by_node.get(&node.id()) {
            return *syntax;
        }
        let scope = self.scope_for_source_range(node.start_byte(), node.end_byte());
        let declaration = self.add_site_in_scope(node, ResolutionSiteKind::TypeDeclaration, scope);
        let synthetic_name = format!("$anon${}", node.start_byte());
        let name = self.intern_name(&synthetic_name);
        self.facts.identifiers.push(PositionedIdentifierFact {
            site: declaration,
            name,
            role: ResolutionIdentifierRole::Declaration,
            namespace: ResolutionNamespace::Type,
            qualifier: None,
        });
        let output = self.add_slot(declaration, ResolutionTypeSlotRole::TargetTypeIdentity);
        self.add_gap(declaration, ResolutionGapKind::UnsupportedExpressionType);
        let syntax = LoweredTypeSyntax {
            input: output,
            indirection_delta: 0,
        };
        assert!(self.type_syntax_by_node.insert(node.id(), syntax).is_none());
        syntax
    }

    fn push_block_scope(&mut self, node: Node<'tree>) -> ResolutionScopeId {
        self.push_block_scope_from(node, node.start_byte())
    }

    fn push_block_scope_from(&mut self, node: Node<'tree>, start_byte: usize) -> ResolutionScopeId {
        let parent = self.scope_for_source_range(start_byte, node.end_byte());
        let scope = self.allocate_scope(
            parent,
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

    fn enter_expression_case(&mut self, node: Node<'tree>) -> TreeWalkAction {
        self.push_block_scope(node);
        if let Some(values) = node.child_by_field_name("value") {
            for value in expression_children(values) {
                self.lower_expression(value);
            }
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
        // Repeated type fields include comma separators; only named AST nodes are types.
        let types = children_by_field(node, "type")
            .into_iter()
            .filter(|type_node| type_node.is_named())
            .collect::<Vec<_>>();
        for &case_type in &types {
            self.lower_type(case_type);
        }
        if let Some(alias) = alias {
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
        let parent = case_clause.parent()?;
        if parent.kind() != "type_switch_statement" {
            return None;
        }
        let alias = parent.child_by_field_name("alias")?;
        let names = expression_children(alias);
        (names.len() == 1).then_some(names[0])
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
        if name.kind() != "identifier" || !is_spelled_identifier(name) {
            let site = self.add_site_in_scope(
                declaration_node,
                ResolutionSiteKind::UnsupportedDeclaration,
                scope,
            );
            self.add_gap(
                site,
                if name.is_missing() {
                    ResolutionGapKind::MalformedSyntax
                } else {
                    ResolutionGapKind::UnsupportedScopeOrBinder
                },
            );
            return;
        }
        if go_node_text(name, self.source).trim() == "_" {
            return;
        }
        let Some(declaration) = self.add_declaration_identifier_site(
            declaration_node,
            name,
            ResolutionSiteKind::ValueDeclaration,
            scope,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
            None,
        ) else {
            return;
        };
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
                let context = self
                    .type_contexts
                    .pop()
                    .expect("type context exit must balance");
                if let Some(scope) = context.generic_scope {
                    assert_eq!(
                        self.scope_stack.pop(),
                        Some(scope),
                        "generic type scope exits after its type body"
                    );
                }
                self.declaration_owners
                    .pop()
                    .expect("type declaration exits its reference owner");
            }
            ExitAction::AnonymousTypeBody => {
                assert!(self.scope_stack.len() > 3, "cannot exit file scope");
                self.scope_stack.pop();
                self.type_contexts
                    .pop()
                    .expect("anonymous interface type context exits");
                self.declaration_owners
                    .pop()
                    .expect("anonymous interface type exits its reference owner");
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
        if !self.expression_slots_by_node.contains_key(&node.id()) {
            self.lower_unsupported_expression_type(node);
        }
        let callable = self.slot(self.expression_slot(node)).site;
        let scope = self.allocate_scope(
            self.current_scope(),
            Some(callable),
            ResolutionScopeKind::Executable,
            node.start_byte(),
            node.end_byte(),
        );
        let context = FunctionLiteralContext {
            node: node.id(),
            callable,
            scope,
            activation_start: body.start_byte(),
            activation_end: body.end_byte(),
        };
        self.scope_stack.push(scope);
        self.function_literal_contexts.push(context);
        self.exit_actions.push(ExitAction::FunctionLiteralContext);
        if let Some(result) = node
            .child_by_field_name("result")
            .filter(|result| result.kind() != "parameter_list")
        {
            self.lower_function_literal_result_type(result, callable);
        }
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
        brokk_bifrost_core::analyzer::resolution_facts::current_scope_id(
            &self.scope_stack,
            "compilation and package scopes are always present",
        )
    }

    fn scope(&self, id: ResolutionScopeId) -> &ResolutionScopeFact {
        self.facts.scope(id)
    }

    fn scope_for_source_node(&self, node: Node<'_>) -> ResolutionScopeId {
        self.scope_for_source_range(node.start_byte(), node.end_byte())
    }

    fn scope_for_source_range(&self, start_byte: usize, end_byte: usize) -> ResolutionScopeId {
        assert!(start_byte <= end_byte, "Go source range is ordered");
        // Signature types are predeclared while lowering a callable, then
        // visited after that temporary scope has been popped. Choose the
        // narrowest source-containing scope instead of trusting a broader
        // current scope that also contains the range.
        let contains_range = |scope: &ResolutionScopeFact| {
            scope.start_byte <= start_byte && end_byte <= scope.end_byte
        };
        self.facts
            .scopes
            .iter()
            .filter(|scope| contains_range(scope))
            .min_by_key(|scope| {
                (
                    scope.end_byte - scope.start_byte,
                    usize::MAX - scope.id.index(),
                )
            })
            .map(|scope| scope.id)
            .expect("the file scope contains every Go source range")
    }

    fn slot(&self, id: ResolutionTypeSlotId) -> &ResolutionTypeSlotFact {
        self.facts.type_slot(id)
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
        let range = self.source_collector.occurrence(occurrence).range;
        let id = self
            .facts
            .add_site(scope, kind, range.start_byte, range.end_byte);
        self.site_occurrences.push(occurrence);
        id
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
    ) -> bool {
        if !is_spelled_identifier(node) {
            self.add_gap(site, ResolutionGapKind::MalformedSyntax);
            return false;
        }
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
        true
    }

    fn add_identifier_site(
        &mut self,
        node: Node<'_>,
        kind: ResolutionSiteKind,
        scope: ResolutionScopeId,
        role: ResolutionIdentifierRole,
        namespace: ResolutionNamespace,
        qualifier: Option<ResolutionTypeSlotId>,
    ) -> Option<ResolutionSiteId> {
        let site = self.add_site_in_scope(node, kind, scope);
        self.add_identifier_to_site(site, node, role, namespace, qualifier)
            .then_some(site)
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
        indirection_delta: i8,
        value_transform: ResolutionTypeTransferValueTransform,
    ) {
        assert_ne!(input, output);
        self.facts
            .type_transfers
            .push(ResolutionTypeTransferFact::new(
                input,
                output,
                kind,
                indirection_delta,
                0,
                value_transform,
            ));
    }

    fn add_gap(&mut self, site: ResolutionSiteId, kind: ResolutionGapKind) {
        self.facts.add_gap(site, kind);
        if go_gap_blocks_reference_enumeration(kind) {
            self.facts.add_reference_enumeration_gap(site, kind);
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
            if let Some((alias, _)) = spec.alias
                && !matches!(alias, "." | "_")
            {
                self.explicit_package_import_aliases
                    .insert(alias.to_owned());
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
                position: None,
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
            .extend_root_import_demands(&import_sites, &demanded_names);
        for import_site in import_sites {
            for &(namespace, name) in &demanded_names {
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
                _ => {}
            }
        }
        self.facts.package_references.extend(
            brokk_bifrost_core::analyzer::resolution_facts::source_owned_package_references(
                &self.facts,
                |_, _| Some(root_scope),
            ),
        );
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

    fn lower_type_alias(&mut self, node: Node<'tree>) -> Option<TypeAliasContext> {
        let name = node.child_by_field_name("name")?;
        if name.kind() != "type_identifier" || !is_spelled_identifier(name) {
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
        )?;
        self.add_type_binder(declaration, name);
        let output = self.add_slot(declaration, ResolutionTypeSlotRole::TargetTypeIdentity);
        self.facts
            .declaration_type_slots
            .push(DeclarationTypeSlotFact {
                declaration,
                slot: output,
                role: DeclarationTypeRole::Identity,
            });
        let generic_scope = self.enter_owned_type_parameter_scope(node, declaration);
        let Some(target) = node.child_by_field_name("type") else {
            self.add_gap(declaration, ResolutionGapKind::MalformedSyntax);
            return Some(TypeAliasContext { generic_scope });
        };
        self.declaration_owners.push(declaration);
        let syntax = self.lower_type(target);
        assert_eq!(self.declaration_owners.pop(), Some(declaration));
        self.publish_function_type_signature(declaration, syntax.input);
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
        Some(TypeAliasContext { generic_scope })
    }

    fn enter_owned_type_parameter_scope(
        &mut self,
        owner_node: Node<'tree>,
        owner: ResolutionSiteId,
    ) -> Option<ResolutionScopeId> {
        let parameters = owner_node.child_by_field_name("type_parameters")?;
        let scope = self.allocate_scope(
            self.current_scope(),
            Some(owner),
            ResolutionScopeKind::Block,
            owner_node.start_byte(),
            owner_node.end_byte(),
        );
        self.scope_stack.push(scope);
        self.lower_go_type_parameters(parameters, owner, scope);
        Some(scope)
    }

    fn lower_go_type_parameters(
        &mut self,
        parameters: Node<'tree>,
        owner: ResolutionSiteId,
        scope: ResolutionScopeId,
    ) -> u32 {
        assert!(
            self.lowered_type_parameter_lists.insert(parameters.id()),
            "a Go type-parameter list is lowered once"
        );
        let declarations = named_children(parameters);
        if declarations.is_empty() {
            self.add_gap(owner, ResolutionGapKind::MalformedSyntax);
            return 0;
        }

        let scope_range = *self.scope(scope);
        let mut count = 0u32;
        for parameter in &declarations {
            if parameter.kind() != "type_parameter_declaration" {
                self.add_gap(owner, ResolutionGapKind::UnsupportedScopeOrBinder);
                continue;
            }
            let names = children_by_field(*parameter, "name");
            if names.is_empty() {
                let site = self.add_site(*parameter, ResolutionSiteKind::UnsupportedDeclaration);
                self.add_gap(site, ResolutionGapKind::MalformedSyntax);
                continue;
            }
            for name in names {
                if !matches!(name.kind(), "identifier" | "type_identifier") {
                    let site =
                        self.add_site(*parameter, ResolutionSiteKind::UnsupportedDeclaration);
                    self.add_gap(site, ResolutionGapKind::MalformedSyntax);
                    continue;
                }
                let Some(declaration) = self.add_declaration_identifier_site(
                    *parameter,
                    name,
                    ResolutionSiteKind::TypeDeclaration,
                    scope,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Type,
                    None,
                ) else {
                    self.add_gap(owner, ResolutionGapKind::UnsupportedScopeOrBinder);
                    continue;
                };
                self.mark_lexical_declaration(declaration, DeclarationKind::Parameter);
                self.facts.binders.push(ResolutionBinderFact {
                    declaration,
                    scope,
                    kind: ResolutionBinderKind::Type,
                    hoisting: HoistingClass::SourceOrder,
                    activation_start: name.end_byte(),
                    activation_end: scope_range.end_byte,
                });
                let identity =
                    self.add_slot(declaration, ResolutionTypeSlotRole::TargetTypeIdentity);
                self.facts
                    .declaration_type_slots
                    .push(DeclarationTypeSlotFact {
                        declaration,
                        slot: identity,
                        role: DeclarationTypeRole::Identity,
                    });
                self.facts.add_generic_formal(owner, count, declaration);
                // Navigation can bind the formal, but stage A does not infer
                // which concrete type this formal represents.
                self.add_gap(declaration, ResolutionGapKind::UnsupportedExpressionType);
                count = count
                    .checked_add(1)
                    .expect("Go type-parameter count exceeds u32");
            }
        }

        // All formals exist before constraints are lowered, so constraint
        // references use the same lexical binders as signatures and bodies.
        for parameter in declarations {
            let Some(constraint) = parameter.child_by_field_name("type") else {
                let site = self.add_site(parameter, ResolutionSiteKind::UnsupportedDeclaration);
                self.add_gap(site, ResolutionGapKind::MalformedSyntax);
                continue;
            };
            self.lower_go_type_parameter_constraint(constraint);
        }
        count
    }

    fn lower_go_type_parameter_constraint(&mut self, root: Node<'tree>) {
        let mut pending = vec![root];
        while let Some(node) = pending.pop() {
            match node.kind() {
                "type_constraint" | "type_elem" | "negated_type" => {
                    pending.extend(named_children(node).into_iter().rev());
                }
                "type_identifier"
                | "identifier"
                | "qualified_type"
                | "generic_type"
                | "interface_type"
                | "pointer_type"
                | "slice_type"
                | "array_type"
                | "implicit_length_array_type"
                | "map_type"
                | "channel_type"
                | "parenthesized_type" => {
                    self.lower_type(node);
                }
                _ => {
                    let children = named_children(node);
                    if children.is_empty() {
                        self.lower_type(node);
                    } else {
                        pending.extend(children.into_iter().rev());
                    }
                }
            }
        }
    }

    fn lower_type_declaration(&mut self, node: Node<'tree>) -> Option<TypeContext> {
        let name = node.child_by_field_name("name")?;
        if name.kind() != "type_identifier" || !is_spelled_identifier(name) {
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
        )?;
        self.add_type_binder(declaration, name);
        self.declaration_owners.push(declaration);
        let generic_scope = self.enter_owned_type_parameter_scope(node, declaration);

        let Some(type_node) = node.child_by_field_name("type") else {
            self.add_gap(declaration, ResolutionGapKind::MalformedSyntax);
            return Some(TypeContext {
                declaration,
                generic_scope,
            });
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
                | "function_type"
                | "parenthesized_type"
        ) {
            let syntax = self.lower_type(type_node);
            self.publish_function_type_signature(declaration, syntax.input);
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
                        type_node.start_byte(),
                        type_node.end_byte(),
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
                let is_constraint = self.interface_type_is_constraint(type_node);
                self.lower_interface_type_elements(declaration, type_node, is_constraint);
            }
            "type_identifier"
            | "identifier"
            | "qualified_type"
            | "array_type"
            | "slice_type"
            | "implicit_length_array_type"
            | "map_type"
            | "channel_type"
            | "function_type"
            | "parenthesized_type" => {}
            _ => self.add_gap(declaration, ResolutionGapKind::UnsupportedTypeSyntax),
        }
        Some(TypeContext {
            declaration,
            generic_scope,
        })
    }

    fn interface_type_is_constraint(&self, interface_type: Node<'tree>) -> bool {
        let mut ancestor = interface_type.parent();
        while let Some(node) = ancestor {
            if node.kind() == "type_parameter_declaration" {
                return true;
            }
            ancestor = node.parent();
        }
        false
    }

    // Type-set terms are lowered here; method elements are walked later as
    // callable declarations under the active interface TypeBody scope.
    fn lower_interface_type_elements(
        &mut self,
        owner: ResolutionSiteId,
        interface_type: Node<'tree>,
        is_constraint: bool,
    ) {
        for (parent_ordinal, element) in named_children(interface_type)
            .into_iter()
            .filter(|child| child.kind() == "type_elem")
            .enumerate()
        {
            let terms = named_children(element)
                .into_iter()
                .filter(|term| term.kind() != "method_elem")
                .collect::<Vec<_>>();
            let [term] = terms.as_slice() else {
                if !terms.is_empty() {
                    self.lower_interface_type_set(owner, terms);
                }
                continue;
            };
            if is_constraint || !matches!(term.kind(), "type_identifier" | "qualified_type") {
                self.lower_interface_type_set(owner, [*term]);
                continue;
            }
            // A named element can bind an interface or a concrete type
            // term. The selected reader classifies it after binding.
            let syntax = self.lower_type(*term);
            let reference = self.slot(syntax.input).site;
            self.facts.supertypes.push(ResolutionSupertypeFact {
                subtype: owner,
                parent_ordinal: u32::try_from(parent_ordinal)
                    .expect("a Go declaration's parent count fits u32"),
                supertype_reference: reference,
                supertype_slot: syntax.input,
                kind: ResolutionSupertypeKind::GoInterfaceElement,
            });
        }
    }

    fn lower_interface_type_set(
        &mut self,
        owner: ResolutionSiteId,
        roots: impl IntoIterator<Item = Node<'tree>>,
    ) {
        let mut pending = roots.into_iter().collect::<Vec<_>>();
        pending.reverse();
        while let Some(node) = pending.pop() {
            match node.kind() {
                "type_identifier" | "identifier" | "qualified_type" => {
                    self.lower_type(node);
                }
                "generic_type" => {
                    // The generic lowerer preserves the base and argument
                    // references while leaving application semantics open.
                    self.lower_type(node);
                }
                "type_elem" | "type_constraint" | "parenthesized_type" | "negated_type" => {
                    let mut children = named_children(node);
                    children.reverse();
                    pending.extend(children);
                }
                _ => {
                    let mut children = named_children(node);
                    if children.is_empty() {
                        self.lower_type(node);
                    } else {
                        children.reverse();
                        pending.extend(children);
                    }
                }
            }
        }
        self.add_gap(owner, ResolutionGapKind::UnsupportedHierarchyTraversal);
    }

    fn lower_callable_declaration(&mut self, node: Node<'tree>) -> Option<CallableContext> {
        let name = node.child_by_field_name("name")?;
        if !matches!(name.kind(), "identifier" | "field_identifier") || !is_spelled_identifier(name)
        {
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
        )?;
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

        let type_parameters = node.child_by_field_name("type_parameters");
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
        self.scope_stack.push(callable_scope);
        if let Some(parameters) = type_parameters {
            if node.kind() == "function_declaration" {
                let lowered =
                    self.lower_go_type_parameters(parameters, declaration, callable_scope);
                assert_eq!(
                    lowered,
                    callable_type_parameter_count(node),
                    "Go callable signature count matches its bound type parameters"
                );
            } else {
                self.add_gap(declaration, ResolutionGapKind::UnsupportedScopeOrBinder);
            }
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
            // The first result is published for every result-bearing callable, so
            // a binder of the first result of a multi-value call can read it.
            if let Some(first) = result_types.first() {
                self.facts
                    .declaration_type_slots
                    .push(DeclarationTypeSlotFact {
                        declaration,
                        slot: first.value_type,
                        role: DeclarationTypeRole::CallableFirstResult,
                    });
            }
            self.facts.callable_signatures[signature_index].result_types = result_types;
        }
        assert_eq!(
            self.scope_stack.pop(),
            Some(callable_scope),
            "callable signature lowering uses the callable's lexical scope"
        );
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
            receiver_name: None,
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
            self.add_gap(callable, ResolutionGapKind::UnsupportedExpressionType);
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
        let Some(parameters) = type_node.child_by_field_name("parameters") else {
            self.add_gap(declaration, ResolutionGapKind::MalformedSyntax);
            return;
        };
        let mut callable_parameters = Vec::new();
        for parameter in named_children(parameters).into_iter().filter(|parameter| {
            matches!(
                parameter.kind(),
                "parameter_declaration" | "variadic_parameter_declaration"
            )
        }) {
            let Some(parameter_type) = parameter.child_by_field_name("type") else {
                self.add_gap(declaration, ResolutionGapKind::MalformedSyntax);
                continue;
            };
            let syntax = self.lower_type(parameter_type);
            let names = children_by_field(parameter, "name");
            let repeated = parameter.kind() == "variadic_parameter_declaration";
            for name in names
                .iter()
                .copied()
                .map(Some)
                .chain(names.is_empty().then_some(None))
            {
                let parameter_site = self.add_site_in_scope(
                    name.unwrap_or(parameter),
                    ResolutionSiteKind::ValueDeclaration,
                    self.facts.sites[declaration.index()].scope,
                );
                let value_type =
                    self.add_slot(parameter_site, ResolutionTypeSlotRole::DeclaredValue);
                self.add_transfer(
                    syntax.input,
                    value_type,
                    ResolutionTypeTransferKind::DeclaredType,
                    syntax.indirection_delta,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                );
                callable_parameters.push(ResolutionCallableParameterFact {
                    callable: declaration,
                    list_ordinal: 0,
                    ordinal: dense_ordinal(callable_parameters.len(), "Go function-type input"),
                    parameter: parameter_site,
                    value_type,
                    repeated,
                });
            }
        }
        let result_types = type_node
            .child_by_field_name("result")
            .map(|result| self.lower_function_type_result_types(declaration, result))
            .unwrap_or_default();
        self.facts
            .callable_signatures
            .push(ResolutionCallableSignatureFact {
                callable: declaration,
                type_parameter_count: 0,
                result_types,
            });
        self.facts.callable_parameters.extend(callable_parameters);
    }

    fn lower_function_type_result_types(
        &mut self,
        declaration: ResolutionSiteId,
        result: Node<'tree>,
    ) -> Vec<ResolutionCallableResultTypeFact> {
        let mut result_types = Vec::new();
        let result_parameters = if result.kind() == "parameter_list" {
            named_children(result)
                .into_iter()
                .filter(|child| child.kind() == "parameter_declaration")
                .collect::<Vec<_>>()
        } else {
            vec![result]
        };
        for parameter in result_parameters {
            let type_node = if parameter.kind() == "parameter_declaration" {
                parameter.child_by_field_name("type")
            } else {
                Some(parameter)
            };
            let Some(type_node) = type_node else {
                self.add_gap(declaration, ResolutionGapKind::MalformedSyntax);
                continue;
            };
            let syntax = self.lower_type(type_node);
            let count = if parameter.kind() == "parameter_declaration" {
                children_by_field(parameter, "name").len().max(1)
            } else {
                1
            };
            for _ in 0..count {
                let value_type = self.add_slot(declaration, ResolutionTypeSlotRole::DeclaredValue);
                self.add_transfer(
                    syntax.input,
                    value_type,
                    ResolutionTypeTransferKind::DeclaredType,
                    syntax.indirection_delta,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                );
                result_types.push(ResolutionCallableResultTypeFact {
                    ordinal: dense_ordinal(result_types.len(), "Go function-type result"),
                    value_type,
                });
            }
        }
        result_types
    }

    fn publish_function_type_signature(
        &mut self,
        declaration: ResolutionSiteId,
        type_slot: ResolutionTypeSlotId,
    ) {
        if let Some(type_node) = self.function_types_by_slot.get(&type_slot).copied() {
            self.lower_function_value_signature(declaration, type_node);
        }
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
            // The source facts retain the embedding edge for Go's selector
            // walk; it must not erase this ordinary field binding.
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
            let Some(declaration) = self.add_declaration_identifier_site(
                node,
                name,
                ResolutionSiteKind::ValueDeclaration,
                binding_scope,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Value,
                None,
            ) else {
                continue;
            };
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
        if node.parent().is_some_and(|parameters| {
            parameters.kind() == "parameter_list"
                && parameters
                    .parent()
                    .is_some_and(|owner| owner.kind() == "function_type")
        }) {
            // Function-type parameters are signature positions, not lexical
            // binders in the enclosing executable. Their types and ordered
            // signature rows are lowered by the function-type owner.
            return;
        }
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
            self.lower_named_result_parameter(node, callable);
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
        let names = children_by_field(node, "name")
            .into_iter()
            .filter(|name| name.kind() == "identifier" || name.is_missing())
            .collect::<Vec<_>>();
        let Some(type_node) = node.child_by_field_name("type") else {
            self.add_gap(callable.declaration, ResolutionGapKind::MalformedSyntax);
            return;
        };
        if is_receiver {
            self.lower_generic_receiver_type_parameters(type_node, callable);
        }
        // `repeated` records Go's variadic arity rule on the callable
        // parameter. The callable's selected identity and result do not
        // depend on proving the parameter's slice value shape, which remains
        // open on the parameter site below.
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
                let Some(declaration) = self.add_declaration_identifier_site(
                    node,
                    name,
                    ResolutionSiteKind::ValueDeclaration,
                    callable.scope,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                    None,
                ) else {
                    continue;
                };
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
                if repeated {
                    self.add_gap(declaration, ResolutionGapKind::UnsupportedExpressionType);
                }
                self.record_value_name(callable.scope, name);
                if is_receiver {
                    let receiver_name = self.intern_name(go_node_text(name, self.source).trim());
                    self.callable_contexts
                        .last_mut()
                        .expect("receiver belongs to the active callable")
                        .receiver_name = Some(receiver_name);
                }
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
                if repeated {
                    self.add_gap(declaration, ResolutionGapKind::UnsupportedExpressionType);
                }
                (declaration, value_type)
            };
            if !is_receiver {
                let ordinal = self.next_parameter_ordinal(callable.declaration);
                self.facts
                    .callable_parameters
                    .push(ResolutionCallableParameterFact {
                        callable: callable.declaration,
                        list_ordinal: 0,
                        ordinal,
                        parameter: declaration,
                        value_type,
                        repeated,
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

    fn lower_named_result_parameter(&mut self, node: Node<'tree>, callable: CallableContext) {
        let names = children_by_field(node, "name");
        if names.is_empty() {
            return;
        }
        let Some(type_node) = node.child_by_field_name("type") else {
            self.add_gap(callable.declaration, ResolutionGapKind::MalformedSyntax);
            return;
        };
        for name in names {
            let Some(declaration) = self.add_declaration_identifier_site(
                node,
                name,
                ResolutionSiteKind::ValueDeclaration,
                callable.scope,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Value,
                None,
            ) else {
                continue;
            };
            self.mark_lexical_declaration(declaration, DeclarationKind::Parameter);
            self.facts.binders.push(ResolutionBinderFact {
                declaration,
                scope: callable.scope,
                kind: ResolutionBinderKind::Parameter,
                hoisting: HoistingClass::SourceOrder,
                activation_start: callable.activation_start,
                activation_end: callable.activation_end,
            });
            self.attach_declaration_type(
                declaration,
                type_node,
                DeclarationTypeRole::Parameter,
                true,
            );
            self.record_value_name(callable.scope, name);
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
            self.lower_function_literal_result_parameter(node, repeated, literal);
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
            self.add_gap(
                literal.callable,
                ResolutionGapKind::UnsupportedCallApplicability,
            );
        }

        let names = children_by_field(node, "name")
            .into_iter()
            .filter(|name| name.kind() == "identifier" || name.is_missing())
            .collect::<Vec<_>>();
        for name in names
            .iter()
            .copied()
            .map(Some)
            .chain(names.is_empty().then_some(None))
        {
            if let Some(name) = name {
                let Some(declaration) = self.add_declaration_identifier_site(
                    node,
                    name,
                    ResolutionSiteKind::ValueDeclaration,
                    literal.scope,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                    None,
                ) else {
                    continue;
                };
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
                if repeated {
                    self.add_gap(declaration, ResolutionGapKind::UnsupportedExpressionType);
                }
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
                if repeated {
                    self.add_gap(declaration, ResolutionGapKind::UnsupportedExpressionType);
                }
            }
        }
    }

    fn lower_function_literal_result_parameter(
        &mut self,
        node: Node<'tree>,
        repeated: bool,
        literal: FunctionLiteralContext,
    ) {
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
            self.add_gap(site, ResolutionGapKind::UnsupportedTypeSyntax);
            self.lower_type(type_node);
            return;
        }

        let names = children_by_field(node, "name");
        for _ in 0..names.len().max(1) {
            self.lower_function_literal_result_type(type_node, literal.callable);
        }

        for name in names {
            let Some(declaration) = self.add_declaration_identifier_site(
                node,
                name,
                ResolutionSiteKind::ValueDeclaration,
                literal.scope,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Value,
                None,
            ) else {
                continue;
            };
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
        }
    }

    fn lower_function_literal_result_type(
        &mut self,
        type_node: Node<'tree>,
        callable: ResolutionSiteId,
    ) {
        let syntax = self.lower_type(type_node);
        let result = self.add_slot(callable, ResolutionTypeSlotRole::DeclaredValue);
        self.add_transfer(
            syntax.input,
            result,
            ResolutionTypeTransferKind::DeclaredType,
            syntax.indirection_delta,
            ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
        );
    }

    fn lower_value_binding(&mut self, spec: Node<'_>, name: Node<'_>) -> Option<ResolutionSiteId> {
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
        )?;
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
        Some(declaration)
    }

    fn lower_const_spec(&mut self, node: Node<'tree>) {
        let names = children_by_field(node, "name")
            .into_iter()
            .filter(|name| name.kind() == "identifier" || name.is_missing())
            .collect::<Vec<_>>();
        let (type_node, values) = self.const_spec_type_and_values(node);
        let iota_ordinal = self.const_spec_ordinal(node);
        if !names.is_empty()
            && names
                .iter()
                .all(|name| go_node_text(*name, self.source).trim() == "_")
            && let Some(type_node) = type_node
        {
            self.lower_type(type_node);
        }
        let value_slots = values
            .iter()
            .copied()
            .map(|value| self.lower_const_initializer(value, iota_ordinal))
            .collect::<Vec<_>>();
        let one_to_one = value_slots.len() == names.len();
        for (index, name) in names.into_iter().enumerate() {
            if name.kind() != "identifier" || !is_spelled_identifier(name) {
                let site = self.add_site(name, ResolutionSiteKind::UnsupportedDeclaration);
                self.add_gap(site, ResolutionGapKind::MalformedSyntax);
                continue;
            }
            if go_node_text(name, self.source).trim() == "_" {
                continue;
            }
            let Some(declaration) = self.lower_value_binding(node, name) else {
                continue;
            };
            if let Some(type_node) = type_node {
                self.attach_declaration_type(
                    declaration,
                    type_node,
                    DeclarationTypeRole::Value,
                    false,
                );
            } else if one_to_one {
                self.attach_constant_initializer_type(declaration, value_slots[index]);
            } else {
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
                self.add_gap(declaration, ResolutionGapKind::UnsupportedExpressionType);
            }
        }
    }

    fn const_spec_type_and_values(
        &self,
        node: Node<'tree>,
    ) -> (Option<Node<'tree>>, Vec<Node<'tree>>) {
        if let Some(value) = node.child_by_field_name("value") {
            return (node.child_by_field_name("type"), expression_children(value));
        }
        let mut previous = node.prev_named_sibling();
        while let Some(spec) = previous {
            if spec.kind() == "const_spec"
                && let Some(value) = spec.child_by_field_name("value")
            {
                let values = expression_children(value);
                if !values.is_empty() {
                    return (spec.child_by_field_name("type"), values);
                }
            } else if spec.kind() != "const_spec" && spec.kind() != "comment" {
                break;
            }
            previous = spec.prev_named_sibling();
        }
        (None, Vec::new())
    }

    fn const_spec_ordinal(&self, node: Node<'tree>) -> u32 {
        let mut ordinal = 0usize;
        let mut previous = node.prev_named_sibling();
        while let Some(sibling) = previous {
            if sibling.kind() == "const_spec" {
                ordinal = ordinal
                    .checked_add(1)
                    .expect("a Go const declaration's spec ordinal fits usize");
            } else if sibling.kind() != "comment" {
                break;
            }
            previous = sibling.prev_named_sibling();
        }
        u32::try_from(ordinal).expect("a Go const declaration's spec ordinal fits u32")
    }

    fn lower_const_initializer(
        &mut self,
        root: Node<'tree>,
        iota_ordinal: u32,
    ) -> ResolutionTypeSlotId {
        let previous_iota_ordinal = self.const_iota_ordinal.replace(iota_ordinal);
        let slot = self.lower_expression(root);
        self.const_iota_ordinal = previous_iota_ordinal;
        slot
    }

    fn lower_var_spec(&mut self, node: Node<'tree>) {
        let names = children_by_field(node, "name")
            .into_iter()
            .filter(|name| name.kind() == "identifier" || name.is_missing())
            .collect::<Vec<_>>();
        let type_node = node.child_by_field_name("type");
        if !names.is_empty()
            && names
                .iter()
                .all(|name| go_node_text(*name, self.source).trim() == "_")
            && let Some(type_node) = type_node
        {
            self.lower_type(type_node);
        }
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
            if name.kind() != "identifier" || !is_spelled_identifier(name) {
                let site = self.add_site(name, ResolutionSiteKind::UnsupportedDeclaration);
                self.add_gap(site, ResolutionGapKind::MalformedSyntax);
                continue;
            }
            if go_node_text(name, self.source).trim() == "_" {
                continue;
            }
            let Some(declaration) = self.lower_value_binding(node, name) else {
                continue;
            };
            let mut assignment_input = value_slots.get(index).copied();
            if let Some(type_node) = type_node {
                let declared = self.attach_declaration_type(
                    declaration,
                    type_node,
                    DeclarationTypeRole::Value,
                    true,
                );
                if let (Some(&input), Some(&value)) = (value_slots.get(index), values.get(index)) {
                    self.contextualize_declared_initializer(value, input, declared, type_node);
                }
            } else if one_to_one && let Some(&input) = value_slots.get(index) {
                let default_type = values
                    .get(index)
                    .and_then(|value| go_untyped_constant_type(*value, self.source, false))
                    .and_then(go_default_type_for_untyped);
                assignment_input = Some(if let Some(spelling) = default_type {
                    self.attach_defaulted_initializer_type(declaration, spelling)
                } else {
                    self.attach_initializer_type(declaration, input);
                    input
                });
            } else {
                self.add_gap(declaration, ResolutionGapKind::InferredType);
            }
            if one_to_one && let Some(input) = assignment_input {
                let observed = self.add_slot(declaration, ResolutionTypeSlotRole::AssignmentValue);
                self.add_transfer(
                    input,
                    observed,
                    ResolutionTypeTransferKind::Assignment,
                    0,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: true },
                );
            } else if !value_slots.is_empty() {
                self.add_gap(declaration, ResolutionGapKind::UnsupportedExpressionType);
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
            if name.kind() != "identifier" || !is_spelled_identifier(name) {
                let site = self.add_site(name, ResolutionSiteKind::UnsupportedDeclaration);
                self.add_gap(site, ResolutionGapKind::MalformedSyntax);
                continue;
            }
            let spelling = go_node_text(name, self.source).trim();
            if spelling == "_" {
                continue;
            }
            let Some(declaration) = self.add_declaration_identifier_site(
                node,
                name,
                ResolutionSiteKind::ValueDeclaration,
                binding_scope,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Value,
                None,
            ) else {
                continue;
            };
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
                // The first result is the callee's declared result type. Later results
                // get a projection of their own kind, which carries no declared type
                // until an ordinal-carrying fact exists for them.
                let callee_positioned = self.facts.sites[callee.index()].kind
                    != ResolutionSiteKind::UnsupportedExpression;
                for _ in 1..lhs_count {
                    let output = self.add_slot(call, ResolutionTypeSlotRole::CallResult);
                    if callee_positioned {
                        self.facts.binding_projections.push(BindingProjectionFact {
                            reference: callee,
                            output,
                            kind: BindingProjectionKind::TargetCallableLaterResultType,
                        });
                    }
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
                // A short declaration may assign existing selectors or index
                // expressions alongside new identifier binders. These targets
                // introduce no binder, so lower their references as ordinary
                // expressions instead of making the file inventory incomplete.
                self.lower_expression(name);
                continue;
            }
            if !is_spelled_identifier(name) {
                let site = self.add_site(name, ResolutionSiteKind::UnsupportedDeclaration);
                self.add_gap(
                    site,
                    if name.is_missing() {
                        ResolutionGapKind::MalformedSyntax
                    } else {
                        ResolutionGapKind::UnsupportedRoute
                    },
                );
                continue;
            }
            let spelling = go_node_text(name, self.source).trim();
            if spelling == "_" {
                continue;
            }
            if self.value_name_is_declared(binding_scope, spelling) {
                let Some(reference) = self.add_identifier_site(
                    name,
                    ResolutionSiteKind::ValueReference,
                    binding_scope,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Value,
                    None,
                ) else {
                    continue;
                };
                self.add_gap(reference, ResolutionGapKind::UnsupportedExpressionType);
                continue;
            }
            let Some(declaration) = self.add_declaration_identifier_site(
                node,
                name,
                ResolutionSiteKind::ValueDeclaration,
                binding_scope,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Value,
                None,
            ) else {
                continue;
            };
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
                let default_type = (!multi_result_slots.is_some() && one_to_one)
                    .then(|| rhs.get(index).copied())
                    .flatten()
                    .and_then(|value| go_untyped_constant_type(value, self.source, false))
                    .and_then(go_default_type_for_untyped);
                let assignment_input = if let Some(spelling) = default_type {
                    self.attach_defaulted_initializer_type(declaration, spelling)
                } else {
                    self.attach_initializer_type(declaration, initializer);
                    initializer
                };
                let observed = self.add_slot(declaration, ResolutionTypeSlotRole::AssignmentValue);
                self.add_transfer(
                    assignment_input,
                    observed,
                    ResolutionTypeTransferKind::Assignment,
                    0,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: true },
                );
            } else {
                self.add_gap(declaration, ResolutionGapKind::InferredType);
                self.add_gap(declaration, ResolutionGapKind::UnsupportedExpressionType);
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

    fn attach_constant_initializer_type(
        &mut self,
        declaration: ResolutionSiteId,
        input: ResolutionTypeSlotId,
    ) {
        let output = self.add_declaration_type_slot(declaration, DeclarationTypeRole::Value);
        self.add_transfer(
            input,
            output,
            ResolutionTypeTransferKind::Initialization,
            0,
            ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
        );
    }

    fn attach_defaulted_initializer_type(
        &mut self,
        declaration: ResolutionSiteId,
        spelling: &str,
    ) -> ResolutionTypeSlotId {
        let defaulted = self.add_slot(declaration, ResolutionTypeSlotRole::ExpressionValue);
        self.add_intrinsic_type_seed(defaulted, spelling, IntrinsicTypeKind::Primitive);
        let output = self.add_declaration_type_slot(declaration, DeclarationTypeRole::Value);
        self.add_transfer(
            defaulted,
            output,
            ResolutionTypeTransferKind::Initialization,
            0,
            ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
        );
        defaulted
    }

    fn contextualize_nil(
        &mut self,
        expression: Node<'tree>,
        input: ResolutionTypeSlotId,
        context: ResolutionTypeSlotId,
    ) {
        if !go_is_nil_expression(expression) {
            return;
        }
        let site = self.slot(input).site;
        self.facts.gaps.retain(|gap| {
            !(gap.site == site && gap.kind == ResolutionGapKind::UnsupportedExpressionType)
        });
        self.add_transfer(
            context,
            input,
            ResolutionTypeTransferKind::Contextual,
            0,
            ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
        );
    }

    fn contextualize_declared_initializer(
        &mut self,
        expression: Node<'tree>,
        input: ResolutionTypeSlotId,
        context: ResolutionTypeSlotId,
        type_syntax: Node<'tree>,
    ) {
        if go_is_nil_expression(expression) {
            self.contextualize_nil(expression, input, context);
            return;
        }
        let Some(untyped) = go_untyped_constant_type(expression, self.source, false) else {
            return;
        };
        let Some(defaulted) = go_default_type_for_untyped(untyped) else {
            return;
        };
        if !matches!(type_syntax.kind(), "identifier" | "type_identifier")
            || go_node_text(type_syntax, self.source).trim() != defaulted
        {
            return;
        }
        self.facts
            .intrinsic_type_seeds
            .retain(|seed| seed.output != input);
        self.add_transfer(
            context,
            input,
            ResolutionTypeTransferKind::Contextual,
            0,
            ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
        );
    }

    fn callable_result_count(&self, callable: ResolutionSiteId) -> usize {
        self.facts
            .callable_signatures
            .iter()
            .find(|signature| signature.callable == callable)
            .map_or(0, |signature| signature.result_types.len())
    }

    fn callable_result_type_slot(
        &self,
        callable: ResolutionSiteId,
        ordinal: usize,
    ) -> Option<ResolutionTypeSlotId> {
        self.facts
            .callable_signatures
            .iter()
            .find(|signature| signature.callable == callable)?
            .result_types
            .get(ordinal)
            .map(|result| result.value_type)
    }

    fn lower_return(&mut self, node: Node<'tree>) {
        if let Some(literal) = self
            .function_literal_contexts
            .last()
            .copied()
            .filter(|literal| {
                literal.activation_start <= node.start_byte()
                    && node.end_byte() <= literal.activation_end
            })
        {
            let values = first_named_child(node)
                .map(expression_children)
                .unwrap_or_default();
            if values.len() > 1 {
                let site = self.add_site(node, ResolutionSiteKind::UnsupportedExpression);
                self.add_gap(site, ResolutionGapKind::UnsupportedExpressionType);
            }
            for value in values {
                let input = self.lower_expression(value);
                if let Some(context) = self.callable_result_type_slot(literal.callable, 0) {
                    self.contextualize_nil(value, input, context);
                }
                let observed = self.add_slot(literal.callable, ResolutionTypeSlotRole::ReturnValue);
                self.add_transfer(
                    input,
                    observed,
                    ResolutionTypeTransferKind::Return,
                    0,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                );
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
            // A return of several values observes each value at its own declared
            // result position. When the signature declares exactly that many
            // results, each value is contextualized against its result and
            // observed as its own return value, as separate return statements
            // are. Any other count keeps the structured gap.
            let declared = self.callable_result_count(callable.declaration) == values.len();
            if !declared {
                self.add_gap(
                    callable.declaration,
                    ResolutionGapKind::UnsupportedExpressionType,
                );
            }
            for (ordinal, value) in values.into_iter().enumerate() {
                let input = self.lower_expression(value);
                if declared {
                    if let Some(context) =
                        self.callable_result_type_slot(callable.declaration, ordinal)
                    {
                        self.contextualize_nil(value, input, context);
                    }
                    let observed =
                        self.add_slot(callable.declaration, ResolutionTypeSlotRole::ReturnValue);
                    self.add_transfer(
                        input,
                        observed,
                        ResolutionTypeTransferKind::Return,
                        0,
                        ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                    );
                }
            }
            return;
        }
        let input = self.lower_expression(values[0]);
        if let Some(context) = self.callable_result_type_slot(callable.declaration, 0) {
            self.contextualize_nil(values[0], input, context);
        }
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
        let left_slots = left
            .iter()
            .copied()
            .map(|target| self.lower_expression(target))
            .collect::<Vec<_>>();
        let right_slots = right
            .iter()
            .copied()
            .map(|value| self.lower_expression(value))
            .collect::<Vec<_>>();
        let only_blank_targets = !left.is_empty()
            && left.iter().all(|target| {
                target.kind() == "identifier"
                    && is_spelled_identifier(*target)
                    && go_node_text(*target, self.source).trim() == "_"
            });
        let simple_assignment = (0..node.child_count())
            .any(|index| node.child(index).is_some_and(|child| child.kind() == "="));
        if simple_assignment {
            for (index, value) in right.iter().copied().enumerate() {
                if let (Some(&input), Some(&context)) =
                    (right_slots.get(index), left_slots.get(index))
                {
                    self.contextualize_nil(value, input, context);
                }
            }
        }
        let references_lowered = simple_assignment && !left.is_empty() && left.len() == right_count;
        if !only_blank_targets && !references_lowered {
            let site = self.add_site(node, ResolutionSiteKind::UnsupportedExpression);
            self.add_gap(site, ResolutionGapKind::UnsupportedExpressionType);
        }
    }

    fn attach_declaration_type(
        &mut self,
        declaration: ResolutionSiteId,
        type_node: Node<'tree>,
        role: DeclarationTypeRole,
        addressable: bool,
    ) -> ResolutionTypeSlotId {
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
        self.publish_function_type_signature(declaration, syntax.input);
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
            if current.is_missing() {
                return self.lower_gap_type(root, ResolutionGapKind::MalformedSyntax);
            }
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
            return self.lower_gap_type(root, ResolutionGapKind::UnsupportedExpressionType);
        };
        let base = match (
            current.kind(),
            self.source_properties.type_shape(current_type_id),
        ) {
            // Go's universe-block type names are ordinary, shadowable
            // identifiers. Even `string` may bind a package declaration in a
            // different file, so syntax alone never makes it intrinsic.
            ("type_identifier" | "identifier", GoSourceTypeShape::Named(_))
                if is_spelled_identifier(current) =>
            {
                self.lower_plain_type_reference(current)
            }
            ("qualified_type", GoSourceTypeShape::Named(_)) => self.lower_qualified_type(current),
            ("array_type", _) => {
                let syntax = self.lower_structural_type(
                    current,
                    ResolutionTypeConstructorKind::Array,
                    [(ResolutionTypeComponentKind::Element, "element")],
                );
                if let Some(length) = current.child_by_field_name("length") {
                    self.lower_expression(length);
                    self.add_gap(
                        self.slot(syntax.input).site,
                        ResolutionGapKind::UnsupportedExpressionType,
                    );
                } else {
                    self.add_gap(
                        self.slot(syntax.input).site,
                        ResolutionGapKind::MalformedSyntax,
                    );
                }
                syntax
            }
            ("slice_type", _) => self.lower_structural_type(
                current,
                ResolutionTypeConstructorKind::Slice,
                [(ResolutionTypeComponentKind::Element, "element")],
            ),
            ("implicit_length_array_type", _) => self.lower_structural_type(
                current,
                ResolutionTypeConstructorKind::Array,
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
            ("generic_type", _) => self.lower_generic_type(current),
            ("function_type", _) => self.lower_function_type(current),
            ("struct_type", _) => self.lower_anonymous_struct_type(current),
            ("interface_type", _) => self.lower_anonymous_interface_type(current),
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
                        ResolutionGapKind::UnsupportedExpressionType,
                    );
                    0
                }),
        };
        self.type_syntax_by_node.insert(root.id(), syntax);
        syntax
    }

    fn lower_function_type(&mut self, node: Node<'tree>) -> LoweredTypeSyntax {
        let site = self.add_site(node, ResolutionSiteKind::TypeReference);
        let output = self.add_slot(site, ResolutionTypeSlotRole::TargetTypeIdentity);
        let name = self.intern_name("function-type");
        self.facts.intrinsic_type_seeds.push(IntrinsicTypeSeedFact {
            output,
            name,
            kind: IntrinsicTypeKind::Structural,
            indirection: 0,
        });
        let Some(parameters) = node.child_by_field_name("parameters") else {
            self.add_gap(site, ResolutionGapKind::MalformedSyntax);
            return LoweredTypeSyntax {
                input: output,
                indirection_delta: 0,
            };
        };
        for parameter in named_children(parameters).into_iter().filter(|parameter| {
            matches!(
                parameter.kind(),
                "parameter_declaration" | "variadic_parameter_declaration"
            )
        }) {
            if let Some(type_node) = parameter.child_by_field_name("type") {
                self.lower_type(type_node);
            } else {
                self.add_gap(site, ResolutionGapKind::MalformedSyntax);
            }
        }
        if let Some(result) = node.child_by_field_name("result") {
            let results = if result.kind() == "parameter_list" {
                named_children(result)
                    .into_iter()
                    .filter(|child| child.kind() == "parameter_declaration")
                    .map(|parameter| parameter.child_by_field_name("type"))
                    .collect::<Vec<_>>()
            } else {
                vec![Some(result)]
            };
            for result_type in results {
                if let Some(result_type) = result_type {
                    self.lower_type(result_type);
                } else {
                    self.add_gap(site, ResolutionGapKind::MalformedSyntax);
                }
            }
        }
        assert!(self.function_types_by_slot.insert(output, node).is_none());
        LoweredTypeSyntax {
            input: output,
            indirection_delta: 0,
        }
    }

    fn lower_anonymous_interface_type(&mut self, node: Node<'tree>) -> LoweredTypeSyntax {
        // Structural interface identity remains incomplete while child references
        // and method declarations are retained in the owner-scoped facts.
        if let Some(syntax) = self.type_syntax_by_node.get(&node.id()) {
            return *syntax;
        }
        let scope = self.scope_for_source_range(node.start_byte(), node.end_byte());
        let declaration = self.add_site_in_scope(node, ResolutionSiteKind::TypeDeclaration, scope);
        let synthetic_name = format!("$anon$interface${}", node.start_byte());
        let name = self.intern_name(&synthetic_name);
        self.facts.identifiers.push(PositionedIdentifierFact {
            site: declaration,
            name,
            role: ResolutionIdentifierRole::Declaration,
            namespace: ResolutionNamespace::Type,
            qualifier: None,
        });
        let output = self.add_slot(declaration, ResolutionTypeSlotRole::TargetTypeIdentity);
        self.add_gap(declaration, ResolutionGapKind::UnsupportedExpressionType);
        self.lower_interface_type_elements(
            declaration,
            node,
            self.interface_type_is_constraint(node),
        );
        let syntax = LoweredTypeSyntax {
            input: output,
            indirection_delta: 0,
        };
        assert!(self.type_syntax_by_node.insert(node.id(), syntax).is_none());
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
        // This spelling is presentation for native type lookup only. The
        // constructor and component rows remain the structured type shape.
        let spelling = go_node_text(node, self.source).trim();
        let name = self.intern_name(if spelling.is_empty() {
            "structural-type"
        } else {
            spelling
        });
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

    fn lower_generic_type(&mut self, node: Node<'tree>) -> LoweredTypeSyntax {
        if let Some(syntax) = self.type_syntax_by_node.get(&node.id()) {
            return *syntax;
        }
        let (Some(base), Some(arguments)) = (
            node.child_by_field_name("type"),
            node.child_by_field_name("type_arguments"),
        ) else {
            return self.lower_gap_type(node, ResolutionGapKind::MalformedSyntax);
        };
        let owner = self.lower_type(base);
        self.lower_declared_type_arguments(owner.input, arguments);
        // The base type name is an exact reference even when application
        // semantics remain open. Keep the frontier on the structured argument
        // clause so it does not poison navigation and usage edges for the base.
        let application = self.add_site(arguments, ResolutionSiteKind::TypeReference);
        self.add_gap(application, ResolutionGapKind::UnsupportedExpressionType);
        let syntax = LoweredTypeSyntax {
            input: owner.input,
            indirection_delta: owner.indirection_delta,
        };
        assert!(self.type_syntax_by_node.insert(node.id(), syntax).is_none());
        syntax
    }

    fn lower_declared_type_arguments(
        &mut self,
        owner: ResolutionTypeSlotId,
        arguments: Node<'tree>,
    ) {
        let mut positional = Vec::new();
        for element in named_children(arguments) {
            if element.kind() == "type_elem" {
                positional.extend(named_children(element));
            } else {
                positional.push(element);
            }
        }
        if positional.is_empty() {
            let site = self.add_site(arguments, ResolutionSiteKind::UnsupportedExpression);
            self.add_gap(site, ResolutionGapKind::MalformedSyntax);
            return;
        }
        for (ordinal, type_node) in positional.into_iter().enumerate() {
            let syntax = self.lower_type(type_node);
            let argument = self.materialize_type_syntax(syntax);
            self.facts
                .declared_type_arguments
                .push(ResolutionDeclaredTypeArgumentFact {
                    owner,
                    ordinal: dense_ordinal(ordinal, "Go declared type argument"),
                    argument,
                });
        }
    }

    fn lower_generic_receiver_type_parameters(
        &mut self,
        receiver_type: Node<'tree>,
        callable: CallableContext,
    ) -> Option<LoweredTypeSyntax> {
        let mut generic = receiver_type;
        while matches!(generic.kind(), "pointer_type" | "parenthesized_type") {
            generic = first_named_child(generic)?;
        }
        if generic.kind() != "generic_type" {
            return None;
        }
        let (Some(base), Some(arguments)) = (
            generic.child_by_field_name("type"),
            generic.child_by_field_name("type_arguments"),
        ) else {
            self.add_gap(callable.declaration, ResolutionGapKind::MalformedSyntax);
            return None;
        };
        let owner = self.lower_type(base);
        let mut positional = Vec::new();
        for element in named_children(arguments) {
            if element.kind() == "type_elem" {
                positional.extend(named_children(element));
            } else {
                positional.push(element);
            }
        }
        if positional.is_empty() {
            self.add_gap(callable.declaration, ResolutionGapKind::MalformedSyntax);
            return None;
        }
        if self
            .source_type_parameter_counts
            .get(go_node_text(base, self.source).trim())
            .is_some_and(|count| *count != positional.len())
        {
            // A same-file declaration proves that this receiver's positional
            // binders do not match the generic type's formals. Keep navigation
            // facts for the receiver syntax, but do not claim its nominal type
            // identity is modeled.
            self.add_gap(
                self.slot(owner.input).site,
                ResolutionGapKind::UnsupportedExpressionType,
            );
        }
        let scope_end = self.scope(callable.scope).end_byte;
        for (ordinal, argument_node) in positional.into_iter().enumerate() {
            let argument = if matches!(argument_node.kind(), "identifier" | "type_identifier") {
                let declaration = self.add_declaration_identifier_site(
                    argument_node,
                    argument_node,
                    ResolutionSiteKind::TypeDeclaration,
                    callable.scope,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Type,
                    None,
                )?;
                self.mark_lexical_declaration(declaration, DeclarationKind::Parameter);
                self.facts.binders.push(ResolutionBinderFact {
                    declaration,
                    scope: callable.scope,
                    kind: ResolutionBinderKind::Type,
                    hoisting: HoistingClass::SourceOrder,
                    activation_start: argument_node.end_byte(),
                    activation_end: scope_end,
                });
                let identity =
                    self.add_slot(declaration, ResolutionTypeSlotRole::TargetTypeIdentity);
                self.facts
                    .declaration_type_slots
                    .push(DeclarationTypeSlotFact {
                        declaration,
                        slot: identity,
                        role: DeclarationTypeRole::Identity,
                    });
                self.facts.add_generic_formal(
                    callable.declaration,
                    dense_ordinal(ordinal, "Go receiver formal"),
                    declaration,
                );
                self.add_gap(declaration, ResolutionGapKind::UnsupportedExpressionType);
                identity
            } else {
                self.add_gap(
                    callable.declaration,
                    ResolutionGapKind::UnsupportedScopeOrBinder,
                );
                let syntax = self.lower_type(argument_node);
                self.materialize_type_syntax(syntax)
            };
            self.facts
                .declared_type_arguments
                .push(ResolutionDeclaredTypeArgumentFact {
                    owner: owner.input,
                    ordinal: dense_ordinal(ordinal, "Go receiver type argument"),
                    argument,
                });
        }
        let syntax = LoweredTypeSyntax {
            input: owner.input,
            indirection_delta: owner.indirection_delta,
        };
        assert!(
            self.type_syntax_by_node
                .insert(generic.id(), syntax)
                .is_none()
        );
        Some(self.lower_type(receiver_type))
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
        if !is_spelled_identifier(package) || !is_spelled_identifier(name) {
            return self.lower_gap_type(node, ResolutionGapKind::MalformedSyntax);
        }
        self.lower_qualifier_reference(package);
        let syntax = self.lower_plain_type_reference(name);
        // Go qualified_type names a package type, not a runtime object's member.
        self.add_qualified_root_reference(
            package,
            self.facts.type_slots[syntax.input.index()].site,
        );
        syntax
    }

    fn lower_qualifier_reference(&mut self, node: Node<'_>) {
        let scope = self.scope_for_source_node(node);
        let Some(reference) = self.add_identifier_site(
            node,
            ResolutionSiteKind::ValueReference,
            scope,
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::TypeOrValue,
            None,
        ) else {
            self.lower_unsupported_expression_as(node, ResolutionGapKind::MalformedSyntax);
            return;
        };
        let output = self.add_slot(reference, ResolutionTypeSlotRole::ExpressionValue);
        self.facts.binding_projections.push(BindingProjectionFact {
            reference,
            output,
            kind: BindingProjectionKind::TargetTypeOrDeclaredValueType,
        });
        self.expression_slots_by_node.insert(node.id(), output);
    }

    fn is_explicit_package_import_qualifier(&self, node: Node<'_>) -> bool {
        if !is_spelled_identifier(node) {
            return false;
        }
        let spelling = go_node_text(node, self.source).trim();
        if !self.explicit_package_import_aliases.contains(spelling) {
            return false;
        }
        let file_scope = ResolutionScopeId::new(2);
        let mut scope = Some(self.current_scope());
        while let Some(current) = scope {
            if current == file_scope {
                return true;
            }
            if self
                .value_names_by_scope
                .get(&current)
                .is_some_and(|names| names.contains(spelling))
            {
                return false;
            }
            scope = self.scope(current).parent;
        }
        false
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
                owner_continued: false,
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
        if !is_spelled_identifier(node) {
            return self.lower_gap_type(node, ResolutionGapKind::MalformedSyntax);
        }
        let scope = self.scope_for_source_node(node);
        let Some(reference) = self.add_identifier_site(
            node,
            ResolutionSiteKind::TypeReference,
            scope,
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Type,
            None,
        ) else {
            return self.lower_gap_type(node, ResolutionGapKind::MalformedSyntax);
        };
        let output = self.add_slot(reference, ResolutionTypeSlotRole::TargetTypeIdentity);
        self.facts
            .binding_projections
            .push(BindingProjectionFact::target_type_identity(
                reference, output,
            ));
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
            if node.is_missing() {
                self.lower_unsupported_expression_as(node, ResolutionGapKind::MalformedSyntax);
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
                        let values = named_children(arguments)
                            .into_iter()
                            .filter(|value| value.kind() != "comment")
                            .collect::<Vec<_>>();
                        for value in &values {
                            if self.go_builtin_type_argument(node, *value) {
                                self.lower_type(*value);
                            }
                        }
                        stack.extend(
                            values
                                .into_iter()
                                .rev()
                                .filter(|value| !self.go_builtin_type_argument(node, *value))
                                .map(|value| (value, false)),
                        );
                    }
                    if let Some(function) = node.child_by_field_name("function") {
                        if is_go_conversion_type_node(function) {
                            self.lower_type(function);
                        } else if function.kind() == "selector_expression" {
                            if let Some(operand) = function.child_by_field_name("operand") {
                                stack.push((operand, false));
                            }
                        } else if (matches!(
                            function.kind(),
                            "identifier" | "type_identifier" | "field_identifier"
                        ) && !is_spelled_identifier(function))
                            || !matches!(
                                function.kind(),
                                "identifier"
                                    | "type_identifier"
                                    | "field_identifier"
                                    | "type_instantiation_expression"
                                    | "index_expression"
                            )
                        {
                            stack.push((function, false));
                        }
                    }
                }
                "type_conversion_expression" => {
                    stack.push((node, true));
                    if let Some(operand) = node.child_by_field_name("operand") {
                        stack.push((operand, false));
                    }
                    if let Some(type_node) = node.child_by_field_name("type")
                        && type_node.kind() != "generic_type"
                    {
                        self.lower_type(type_node);
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
                "index_expression" | "slice_expression" => {
                    stack.push((node, true));
                    for field in ["capacity", "end", "start", "index", "operand"] {
                        if let Some(child) = node.child_by_field_name(field) {
                            stack.push((child, false));
                        }
                    }
                }
                "type_assertion_expression" => {
                    stack.push((node, true));
                    if let Some(operand) = node.child_by_field_name("operand") {
                        stack.push((operand, false));
                    }
                }
                "variadic_argument" => {
                    stack.push((node, true));
                    if let Some(argument) = first_named_child(node) {
                        stack.push((argument, false));
                    }
                }
                "type_instantiation_expression" => {
                    self.finish_type_instantiation_expression(node);
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
                "identifier" | "type_identifier" if is_spelled_identifier(node) => {
                    self.finish_expression(node)
                }
                "composite_literal"
                | "interpreted_string_literal"
                | "raw_string_literal"
                | "rune_literal"
                | "int_literal"
                | "float_literal"
                | "imaginary_literal"
                | "iota"
                | "true"
                | "false"
                | "nil" => self.finish_expression(node),
                "func_literal" => {
                    self.lower_unsupported_expression_as(node, ResolutionGapKind::InferredType)
                }
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
        if node.is_missing() {
            self.lower_unsupported_expression_as(node, ResolutionGapKind::MalformedSyntax);
            return;
        }
        match node.kind() {
            "identifier"
                if is_spelled_identifier(node) && {
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
            "identifier"
                if is_spelled_identifier(node)
                    && self.const_iota_ordinal.is_some()
                    && go_node_text(node, self.source).trim() == "iota" =>
            {
                let Some(reference) = self.add_identifier_site(
                    node,
                    ResolutionSiteKind::ValueReference,
                    self.current_scope(),
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Value,
                    None,
                ) else {
                    self.lower_unsupported_expression_as(node, ResolutionGapKind::MalformedSyntax);
                    return;
                };
                let output = self.add_slot(reference, ResolutionTypeSlotRole::ExpressionValue);
                self.add_intrinsic_type_seed(
                    output,
                    "untyped int",
                    IntrinsicTypeKind::LanguageBuiltin,
                );
                self.expression_slots_by_node.insert(node.id(), output);
            }
            "iota" if self.const_iota_ordinal.is_some() => {
                self.lower_intrinsic_literal(
                    node,
                    "untyped int",
                    IntrinsicTypeKind::LanguageBuiltin,
                );
            }
            "iota" => self.lower_unsupported_expression_type(node),
            "identifier" if is_spelled_identifier(node) => self.lower_value_reference(node),
            "type_identifier" if is_spelled_identifier(node) => {
                self.lower_type_or_value_reference(node)
            }
            "selector_expression" => self.finish_selector(node),
            "call_expression" => self.finish_call(node),
            "type_conversion_expression" => self.finish_type_conversion_expression(node),
            "binary_expression" => self.lower_binary_expression(node),
            "index_expression" | "slice_expression" => self.lower_unsupported_expression_type(node),
            "type_assertion_expression" => {
                let Some(asserted_type) = node.child_by_field_name("type") else {
                    self.lower_unsupported_expression_as(node, ResolutionGapKind::MalformedSyntax);
                    return;
                };
                self.lower_type(asserted_type);
                self.lower_unsupported_expression_type(node);
            }
            "variadic_argument" => {
                if first_named_child(node).is_some() {
                    self.lower_unsupported_expression_type(node);
                } else {
                    self.lower_unsupported_expression_as(node, ResolutionGapKind::MalformedSyntax);
                }
            }
            "composite_literal" => self.finish_composite_literal(node),
            "parenthesized_expression" => {
                let Some(inner) = first_named_child(node) else {
                    self.lower_unsupported_expression(node);
                    return;
                };
                let slot = self.expression_slot(inner);
                self.expression_slots_by_node.insert(node.id(), slot);
            }
            "type_instantiation_expression" => self.finish_type_instantiation_expression(node),
            "func_literal" => self.lower_unsupported_expression_type(node),
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
                } else if let (Some(operator), Some(operand)) = (
                    node.child_by_field_name("operator"),
                    node.child_by_field_name("operand"),
                ) && matches!(operator.kind(), "+" | "-" | "^" | "!")
                {
                    let site = self.add_site(node, ResolutionSiteKind::UnaryExpression);
                    let output = self.add_slot(site, ResolutionTypeSlotRole::ExpressionValue);
                    let operand_type = go_untyped_constant_type(
                        operand,
                        self.source,
                        self.const_iota_ordinal.is_some(),
                    );
                    if operator.kind() == "!" {
                        let (spelling, kind) = if operand_type == Some("untyped bool") {
                            ("untyped bool", IntrinsicTypeKind::LanguageBuiltin)
                        } else {
                            ("bool", IntrinsicTypeKind::Primitive)
                        };
                        self.add_intrinsic_type_seed(output, spelling, kind);
                    } else if let Some(spelling) = operand_type {
                        self.add_intrinsic_type_seed(
                            output,
                            spelling,
                            IntrinsicTypeKind::LanguageBuiltin,
                        );
                    } else {
                        self.add_transfer(
                            self.expression_slot(operand),
                            output,
                            ResolutionTypeTransferKind::ExpressionResult,
                            0,
                            ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                        );
                    }
                    self.expression_slots_by_node.insert(node.id(), output);
                } else {
                    self.lower_unsupported_expression_as(node, ResolutionGapKind::InferredType);
                }
            }
            "interpreted_string_literal" | "raw_string_literal" => self.lower_intrinsic_literal(
                node,
                "untyped string",
                IntrinsicTypeKind::LanguageBuiltin,
            ),
            "rune_literal" => self.lower_intrinsic_literal(
                node,
                "untyped rune",
                IntrinsicTypeKind::LanguageBuiltin,
            ),
            "true" | "false" => self.lower_intrinsic_literal(
                node,
                "untyped bool",
                IntrinsicTypeKind::LanguageBuiltin,
            ),
            "int_literal" => self.lower_intrinsic_literal(
                node,
                "untyped int",
                IntrinsicTypeKind::LanguageBuiltin,
            ),
            "float_literal" => self.lower_intrinsic_literal(
                node,
                "untyped float",
                IntrinsicTypeKind::LanguageBuiltin,
            ),
            "imaginary_literal" => self.lower_intrinsic_literal(
                node,
                "untyped complex",
                IntrinsicTypeKind::LanguageBuiltin,
            ),
            "nil" => self.lower_unsupported_expression_type(node),
            _ => self.lower_unsupported_expression(node),
        }
    }

    fn lower_value_reference(&mut self, node: Node<'_>) {
        let Some(reference) = self.add_identifier_site(
            node,
            ResolutionSiteKind::ValueReference,
            self.current_scope(),
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Value,
            None,
        ) else {
            self.lower_unsupported_expression_as(node, ResolutionGapKind::MalformedSyntax);
            return;
        };
        let output = self.add_slot(reference, ResolutionTypeSlotRole::ExpressionValue);
        self.facts
            .binding_projections
            .push(BindingProjectionFact::target_declared_value_type(
                reference, output,
            ));
        self.expression_slots_by_node.insert(node.id(), output);
    }

    fn lower_binary_expression(&mut self, node: Node<'tree>) {
        let (Some(left), Some(right), Some(operator)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
            node.child_by_field_name("operator"),
        ) else {
            self.lower_unsupported_expression_as(node, ResolutionGapKind::MalformedSyntax);
            return;
        };
        let spelling = operator.kind();
        let allow_iota = self.const_iota_ordinal.is_some();
        let left_untyped = go_untyped_constant_type(left, self.source, allow_iota);
        let right_untyped = go_untyped_constant_type(right, self.source, allow_iota);
        let left_is_constant = go_is_constant_expression(left, self.source, allow_iota);
        let right_is_constant = go_is_constant_expression(right, self.source, allow_iota);
        let left_slot = self.expression_slot(left);
        let right_slot = self.expression_slot(right);
        let site = self.add_site(node, ResolutionSiteKind::BinaryExpression);
        let output = self.add_slot(site, ResolutionTypeSlotRole::ExpressionValue);

        if matches!(spelling, "==" | "!=" | "<" | "<=" | ">" | ">=") {
            if go_is_nil_expression(left) {
                self.contextualize_nil(left, left_slot, right_slot);
            } else if go_is_nil_expression(right) {
                self.contextualize_nil(right, right_slot, left_slot);
            }
            let untyped_boolean = left_is_constant
                && right_is_constant
                && left_untyped.is_some()
                && right_untyped.is_some();
            self.add_intrinsic_type_seed(
                output,
                if untyped_boolean {
                    "untyped bool"
                } else {
                    "bool"
                },
                if untyped_boolean {
                    IntrinsicTypeKind::LanguageBuiltin
                } else {
                    IntrinsicTypeKind::Primitive
                },
            );
        } else if matches!(spelling, "&&" | "||") {
            let untyped_boolean =
                left_untyped == Some("untyped bool") && right_untyped == Some("untyped bool");
            self.add_intrinsic_type_seed(
                output,
                if untyped_boolean {
                    "untyped bool"
                } else {
                    "bool"
                },
                if untyped_boolean {
                    IntrinsicTypeKind::LanguageBuiltin
                } else {
                    IntrinsicTypeKind::Primitive
                },
            );
        } else if matches!(spelling, "<<" | ">>") {
            if left_is_constant {
                if let Some(spelling) = left_untyped
                    .filter(|spelling| matches!(*spelling, "untyped int" | "untyped rune"))
                {
                    self.add_intrinsic_type_seed(
                        output,
                        spelling,
                        IntrinsicTypeKind::LanguageBuiltin,
                    );
                } else {
                    self.add_gap(site, ResolutionGapKind::UnsupportedExpressionType);
                }
            } else {
                self.add_transfer(
                    left_slot,
                    output,
                    ResolutionTypeTransferKind::ExpressionResult,
                    0,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                );
            }
        } else if matches!(
            spelling,
            "+" | "-" | "*" | "/" | "%" | "&" | "|" | "^" | "&^"
        ) {
            match (left_untyped, right_untyped) {
                (Some(left_type), Some(right_type)) if left_type == right_type => {
                    self.add_intrinsic_type_seed(
                        output,
                        left_type,
                        IntrinsicTypeKind::LanguageBuiltin,
                    );
                }
                (Some(_), Some(_)) => {
                    self.add_gap(site, ResolutionGapKind::UnsupportedExpressionType);
                }
                (Some(_), None) if left_is_constant && right_is_constant => {
                    self.add_gap(site, ResolutionGapKind::UnsupportedExpressionType);
                }
                (None, Some(_)) if left_is_constant && right_is_constant => {
                    self.add_gap(site, ResolutionGapKind::UnsupportedExpressionType);
                }
                (Some(_), None) => self.add_transfer(
                    right_slot,
                    output,
                    ResolutionTypeTransferKind::ExpressionResult,
                    0,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                ),
                (None, Some(_)) => self.add_transfer(
                    left_slot,
                    output,
                    ResolutionTypeTransferKind::ExpressionResult,
                    0,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                ),
                (None, None) => {
                    self.add_transfer(
                        left_slot,
                        output,
                        ResolutionTypeTransferKind::ExpressionResult,
                        0,
                        ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                    );
                    self.add_transfer(
                        right_slot,
                        output,
                        ResolutionTypeTransferKind::ExpressionResult,
                        0,
                        ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                    );
                }
            }
        } else {
            self.add_gap(site, ResolutionGapKind::UnsupportedExpressionType);
        }
        self.expression_slots_by_node.insert(node.id(), output);
    }

    fn lower_type_or_value_reference(&mut self, node: Node<'_>) {
        let Some(reference) = self.add_identifier_site(
            node,
            ResolutionSiteKind::ValueReference,
            self.current_scope(),
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::TypeOrValue,
            None,
        ) else {
            self.lower_unsupported_expression_as(node, ResolutionGapKind::MalformedSyntax);
            return;
        };
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
        if !is_spelled_identifier(field) {
            self.lower_unsupported_expression_as(node, ResolutionGapKind::MalformedSyntax);
            return;
        }
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
        if !self.add_identifier_to_site(
            reference,
            field,
            ResolutionIdentifierRole::Reference,
            if type_or_value {
                ResolutionNamespace::TypeOrValue
            } else {
                ResolutionNamespace::Value
            },
            Some(receiver),
        ) {
            self.lower_unsupported_expression_as(node, ResolutionGapKind::MalformedSyntax);
            return;
        }
        if operand.kind() == "identifier" && is_spelled_identifier(operand) {
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

    fn finish_type_instantiation_expression(&mut self, node: Node<'tree>) {
        if self.expression_slots_by_node.contains_key(&node.id()) {
            return;
        }
        let Some(base) = node.child_by_field_name("type") else {
            self.lower_unsupported_expression_as(node, ResolutionGapKind::MalformedSyntax);
            return;
        };
        for type_argument in type_instantiation_argument_nodes(node) {
            self.lower_type(type_argument);
        }
        let callee = match base.kind() {
            "identifier" | "type_identifier" | "field_identifier" => {
                let Some(callee) = self.add_identifier_site(
                    base,
                    ResolutionSiteKind::CallableReference,
                    self.current_scope(),
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::TypeOrValue,
                    None,
                ) else {
                    self.lower_unsupported_expression_as(node, ResolutionGapKind::MalformedSyntax);
                    return;
                };
                callee
            }
            "qualified_type" => {
                let (Some(package), Some(name)) = (
                    base.child_by_field_name("package"),
                    base.child_by_field_name("name"),
                ) else {
                    self.lower_unsupported_expression_as(node, ResolutionGapKind::MalformedSyntax);
                    return;
                };
                self.lower_qualifier_reference(package);
                if !is_spelled_identifier(name) {
                    let site = self.add_site(name, ResolutionSiteKind::MemberReference);
                    self.add_gap(site, ResolutionGapKind::MalformedSyntax);
                    return;
                }
                let callee = self.add_site(name, ResolutionSiteKind::MemberReference);
                let receiver = self.add_slot(callee, ResolutionTypeSlotRole::Receiver);
                self.add_transfer(
                    self.expression_slot(package),
                    receiver,
                    ResolutionTypeTransferKind::Receiver,
                    0,
                    ResolutionTypeTransferValueTransform::Preserve,
                );
                if !self.add_identifier_to_site(
                    callee,
                    name,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Callable,
                    Some(receiver),
                ) {
                    return;
                }
                self.facts
                    .callable_receiver_origins
                    .push(ResolutionCallableReceiverOriginFact {
                        reference: callee,
                        origin: ResolutionCallableReceiverOrigin::ExplicitExpression,
                    });
                self.add_qualified_root_reference(package, callee);
                callee
            }
            _ => {
                self.lower_type(base);
                let site = self.add_site(node, ResolutionSiteKind::UnsupportedExpression);
                self.add_gap(site, ResolutionGapKind::UnsupportedExpressionType);
                let output = self.add_slot(site, ResolutionTypeSlotRole::ExpressionValue);
                self.expression_slots_by_node.insert(node.id(), output);
                return;
            }
        };
        self.add_gap(callee, ResolutionGapKind::UnsupportedExpressionType);
        let output = self.add_slot(callee, ResolutionTypeSlotRole::ExpressionValue);
        self.expression_slots_by_node.insert(node.id(), output);
    }

    fn finish_call(&mut self, node: Node<'tree>) {
        let call = self.add_site(node, ResolutionSiteKind::Call);
        let function = node.child_by_field_name("function");
        let explicit_type_arguments = node
            .child_by_field_name("type_arguments")
            .map(go_type_argument_nodes)
            .or_else(|| {
                function
                    .filter(|function| function.kind() == "type_instantiation_expression")
                    .map(type_instantiation_argument_nodes)
            })
            .or_else(|| {
                function
                    .filter(|function| function.kind() == "index_expression")
                    .and_then(|function| {
                        let operand = function.child_by_field_name("operand")?;
                        let index = function.child_by_field_name("index")?;
                        let package_qualified = operand.kind() == "selector_expression"
                            && operand
                                .child_by_field_name("operand")
                                .is_some_and(|qualifier| {
                                    self.is_explicit_package_import_qualifier(qualifier)
                                });
                        (is_go_type_argument_node(index) || package_qualified)
                            .then_some(vec![index])
                    })
            });
        let explicit_type_argument_count = explicit_type_arguments.as_ref().map_or_else(
            || explicit_type_argument_count(node),
            |arguments| dense_ordinal(arguments.len(), "Go explicit invocation type argument"),
        );
        if let Some(arguments) = &explicit_type_arguments {
            for argument in arguments {
                self.lower_type(*argument);
            }
        }
        let (callee, receiver) = match function {
            Some(function) if is_spelled_identifier(function) => {
                let Some(callee) = self.add_identifier_site(
                    function,
                    ResolutionSiteKind::CallableReference,
                    self.current_scope(),
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::TypeOrValue,
                    None,
                ) else {
                    self.finish_unsupported_call(node, call);
                    return;
                };
                (callee, None)
            }
            Some(function) if function.kind() == "type_instantiation_expression" => {
                let Some(instantiated) = function.child_by_field_name("type") else {
                    self.finish_unsupported_call(node, call);
                    return;
                };
                match instantiated.kind() {
                    "qualified_type" => {
                        let (Some(package), Some(name)) = (
                            instantiated.child_by_field_name("package"),
                            instantiated.child_by_field_name("name"),
                        ) else {
                            self.finish_unsupported_call(node, call);
                            return;
                        };
                        let Some(callee) = self.finish_qualified_call_callee(call, package, name)
                        else {
                            self.finish_unsupported_call(node, call);
                            return;
                        };
                        callee
                    }
                    "selector_expression" => {
                        let (Some(operand), Some(field)) = (
                            instantiated.child_by_field_name("operand"),
                            instantiated.child_by_field_name("field"),
                        ) else {
                            self.finish_unsupported_call(node, call);
                            return;
                        };
                        let Some(callee) = self.finish_qualified_call_callee(call, operand, field)
                        else {
                            self.finish_unsupported_call(node, call);
                            return;
                        };
                        callee
                    }
                    "identifier" | "type_identifier" | "field_identifier" => {
                        let Some(callee) = self.add_identifier_site(
                            instantiated,
                            ResolutionSiteKind::CallableReference,
                            self.current_scope(),
                            ResolutionIdentifierRole::Reference,
                            ResolutionNamespace::TypeOrValue,
                            None,
                        ) else {
                            self.finish_unsupported_call(node, call);
                            return;
                        };
                        (callee, None)
                    }
                    _ => {
                        self.finish_unsupported_call(node, call);
                        return;
                    }
                }
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
                if !is_spelled_identifier(field) {
                    let site = self.add_site(field, ResolutionSiteKind::UnsupportedExpression);
                    self.add_gap(site, ResolutionGapKind::MalformedSyntax);
                    self.finish_unsupported_call(node, call);
                    return;
                }
                let Some(callee) = self.finish_qualified_call_callee(call, operand, field) else {
                    self.finish_unsupported_call(node, call);
                    return;
                };
                callee
            }
            Some(function) if function.kind() == "index_expression" => {
                let (Some(operand), Some(index)) = (
                    function.child_by_field_name("operand"),
                    function.child_by_field_name("index"),
                ) else {
                    self.finish_unsupported_call(node, call);
                    return;
                };
                if explicit_type_arguments.is_some() {
                    self.lower_type(index);
                } else {
                    let mut base = operand;
                    while base.kind() == "parenthesized_expression" {
                        let Some(inner) = first_named_child(base) else {
                            self.finish_unsupported_call(node, call);
                            return;
                        };
                        base = inner;
                    }
                    if is_spelled_identifier(base)
                        && self.value_name_is_visible(
                            self.current_scope(),
                            go_node_text(base, self.source).trim(),
                        )
                    {
                        self.lower_expression(function);
                        self.finish_unsupported_call(node, call);
                        return;
                    }
                    self.lower_ambiguous_call_index(index);
                }
                let Some((callee, receiver)) = self.finish_indexed_call_callee(call, operand)
                else {
                    self.finish_unsupported_call(node, call);
                    return;
                };
                (callee, receiver)
            }
            Some(function) if function.kind() == "type_instantiation_expression" => {
                let callee = self.slot(self.expression_slot(function)).site;
                let previous_receiver = self
                    .facts
                    .type_slots
                    .iter()
                    .find(|slot| {
                        slot.site == callee && slot.role == ResolutionTypeSlotRole::Receiver
                    })
                    .map(|slot| slot.id);
                let receiver = previous_receiver.map(|previous| {
                    let receiver = self.add_slot(call, ResolutionTypeSlotRole::Receiver);
                    self.add_transfer(
                        previous,
                        receiver,
                        ResolutionTypeTransferKind::Receiver,
                        0,
                        ResolutionTypeTransferValueTransform::Preserve,
                    );
                    receiver
                });
                (callee, receiver)
            }
            _ => {
                self.finish_unsupported_call(node, call);
                return;
            }
        };
        self.facts
            .engine_rule_eligibilities
            .push(ResolutionEngineRuleEligibilityFact {
                site: call,
                rule: ResolutionEngineRuleKind::ArgumentIndependentBinding,
            });
        if function.is_some_and(|function| go_node_text(function, self.source).trim() == "new")
            && let Some(type_node) = node
                .child_by_field_name("arguments")
                .and_then(first_named_child)
                .filter(|argument| self.go_builtin_type_argument(node, *argument))
        {
            // new(T) is &T{} without a literal body. Keep the construction
            // and address-of transfers identical to composite literal lowering.
            let syntax = self.lower_type(type_node);
            let value = self.add_slot(call, ResolutionTypeSlotRole::ExpressionValue);
            self.add_transfer(
                syntax.input,
                value,
                ResolutionTypeTransferKind::Construction,
                syntax.indirection_delta,
                ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
            );
            let result = self.add_call_result(call, callee, receiver, explicit_type_argument_count);
            self.add_transfer(
                value,
                result,
                ResolutionTypeTransferKind::AddressOf,
                1,
                ResolutionTypeTransferValueTransform::RuntimeOnly,
            );
            self.finish_call_arguments(node, call, result);
            return;
        }
        // This gap belongs to invocation semantics. Go's argument-independent
        // name binding can select the callee without it; any result type still
        // comes from selected callable signature facts.
        self.add_gap(callee, ResolutionGapKind::UnsupportedCallApplicability);
        let result = self.add_call_result(call, callee, receiver, explicit_type_argument_count);
        self.facts.binding_projections.push(BindingProjectionFact {
            reference: callee,
            output: result,
            kind: BindingProjectionKind::TargetCallableResultType,
        });
        if let Some(arguments) = explicit_type_arguments {
            self.attach_call_type_arguments(call, arguments);
        }
        self.finish_call_arguments(node, call, result);
    }

    /// The Go grammar represents both generic instantiation and ordinary
    /// indexing with `index_expression`. Preserve the indexed name as an
    /// ambiguous type-or-value reference; forward resolution can then decide
    /// whether the bracket contents are type arguments or runtime values.
    fn lower_ambiguous_call_index(&mut self, index: Node<'tree>) {
        if matches!(
            index.kind(),
            "identifier" | "type_identifier" | "field_identifier"
        ) {
            self.lower_type_or_value_reference(index);
        } else if index.kind() == "selector_expression" {
            let (Some(operand), Some(field)) = (
                index.child_by_field_name("operand"),
                index.child_by_field_name("field"),
            ) else {
                self.lower_expression(index);
                return;
            };
            if !self.expression_slots_by_node.contains_key(&operand.id()) {
                if operand.kind() == "package_identifier" {
                    self.lower_qualifier_reference(operand);
                } else {
                    self.lower_expression(operand);
                }
            }
            let reference = self.add_site(field, ResolutionSiteKind::MemberReference);
            let receiver = self.add_slot(reference, ResolutionTypeSlotRole::Receiver);
            self.add_transfer(
                self.expression_slot(operand),
                receiver,
                ResolutionTypeTransferKind::Receiver,
                0,
                ResolutionTypeTransferValueTransform::Preserve,
            );
            if !self.add_identifier_to_site(
                reference,
                field,
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::TypeOrValue,
                Some(receiver),
            ) {
                return;
            }
            if matches!(operand.kind(), "identifier" | "package_identifier") {
                self.add_qualified_root_reference(operand, reference);
            }
            let output = self.add_slot(reference, ResolutionTypeSlotRole::ExpressionValue);
            self.facts.binding_projections.push(BindingProjectionFact {
                reference,
                output,
                kind: BindingProjectionKind::TargetTypeOrDeclaredValueType,
            });
            self.expression_slots_by_node.insert(index.id(), output);
        } else if self.source_type_id(index).is_some() {
            self.lower_type(index);
        } else {
            self.lower_expression(index);
        }
    }

    fn finish_indexed_call_callee(
        &mut self,
        call: ResolutionSiteId,
        operand: Node<'tree>,
    ) -> Option<(ResolutionSiteId, Option<ResolutionTypeSlotId>)> {
        let mut base = operand;
        while base.kind() == "parenthesized_expression" {
            base = first_named_child(base)?;
        }
        if base.kind() == "selector_expression" {
            let (Some(receiver), Some(field)) = (
                base.child_by_field_name("operand"),
                base.child_by_field_name("field"),
            ) else {
                return None;
            };
            if !is_spelled_identifier(field) {
                return None;
            }
            return self.finish_qualified_call_callee(call, receiver, field);
        }
        if matches!(
            base.kind(),
            "identifier" | "type_identifier" | "field_identifier"
        ) {
            let callee = self.add_identifier_site(
                base,
                ResolutionSiteKind::CallableReference,
                self.current_scope(),
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::TypeOrValue,
                None,
            )?;
            return Some((callee, None));
        }
        None
    }

    fn finish_qualified_call_callee(
        &mut self,
        call: ResolutionSiteId,
        operand: Node<'tree>,
        field: Node<'tree>,
    ) -> Option<(ResolutionSiteId, Option<ResolutionTypeSlotId>)> {
        if !is_spelled_identifier(field) {
            let site = self.add_site(field, ResolutionSiteKind::MemberReference);
            self.add_gap(site, ResolutionGapKind::MalformedSyntax);
            return None;
        }
        if !self.expression_slots_by_node.contains_key(&operand.id()) {
            if operand.kind() == "package_identifier" {
                self.lower_qualifier_reference(operand);
            } else {
                self.lower_expression(operand);
            }
        }
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
        )?;
        let origin = self.callable_receiver_origin(operand);
        self.facts
            .callable_receiver_origins
            .push(ResolutionCallableReceiverOriginFact {
                reference: callee,
                origin,
            });
        if matches!(operand.kind(), "identifier" | "package_identifier") {
            self.add_qualified_root_reference(operand, callee);
        }
        Some((callee, Some(receiver)))
    }

    fn callable_receiver_origin(&self, operand: Node<'_>) -> ResolutionCallableReceiverOrigin {
        if operand.kind() == "identifier"
            && is_spelled_identifier(operand)
            && let Some(callable) = self.callable_contexts.last()
            && let Some(receiver_name) = callable.receiver_name
            && callable.activation_start <= operand.start_byte()
            && operand.end_byte() <= callable.activation_end
        {
            let spelling = go_node_text(operand, self.source).trim();
            // The nearest lexical value binding must be the named method
            // receiver, not a local or closure parameter shadowing its name.
            if self.name_ids.get(spelling) == Some(&receiver_name)
                && self.visible_value_scope(self.current_scope(), spelling) == Some(callable.scope)
            {
                return ResolutionCallableReceiverOrigin::CurrentInstance;
            }
        }
        ResolutionCallableReceiverOrigin::ExplicitExpression
    }

    fn finish_unsupported_call(&mut self, node: Node<'_>, call: ResolutionSiteId) {
        let callee = self.add_site(node, ResolutionSiteKind::UnsupportedExpression);
        self.add_gap(callee, ResolutionGapKind::UnsupportedExpressionType);
        self.add_gap(callee, ResolutionGapKind::UnsupportedCallApplicability);
        let result = self.add_call_result(call, callee, None, explicit_type_argument_count(node));
        self.finish_call_arguments(node, call, result);
    }

    fn add_call_result(
        &mut self,
        call: ResolutionSiteId,
        callee: ResolutionSiteId,
        receiver: Option<ResolutionTypeSlotId>,
        explicit_type_argument_count: u32,
    ) -> ResolutionTypeSlotId {
        let result = self.add_slot(call, ResolutionTypeSlotRole::CallResult);
        self.facts.add_single_result_call(
            call,
            callee,
            receiver,
            result,
            explicit_type_argument_count,
        );
        result
    }

    fn finish_call_arguments(
        &mut self,
        node: Node<'_>,
        call: ResolutionSiteId,
        result: ResolutionTypeSlotId,
    ) {
        self.attach_call_arguments(node, call);
        self.expression_slots_by_node.insert(node.id(), result);
    }

    fn finish_type_conversion_expression(&mut self, node: Node<'tree>) {
        let (Some(type_node), Some(operand)) = (
            node.child_by_field_name("type"),
            node.child_by_field_name("operand"),
        ) else {
            self.lower_unsupported_expression_as(node, ResolutionGapKind::MalformedSyntax);
            return;
        };
        if type_node.kind() == "generic_type" {
            self.finish_ambiguous_generic_instantiation(node, type_node, operand);
            return;
        }
        self.lower_unsupported_expression_type(node);
    }

    fn finish_ambiguous_generic_instantiation(
        &mut self,
        node: Node<'tree>,
        generic_type: Node<'tree>,
        operand: Node<'tree>,
    ) {
        let (Some(base), Some(arguments)) = (
            generic_type.child_by_field_name("type"),
            generic_type.child_by_field_name("type_arguments"),
        ) else {
            self.lower_unsupported_expression_as(node, ResolutionGapKind::MalformedSyntax);
            return;
        };
        let base_syntax = self.lower_type(base);
        let arguments = go_type_argument_nodes(arguments);
        for argument in &arguments {
            self.lower_type(*argument);
        }
        let generic_syntax = LoweredTypeSyntax {
            input: base_syntax.input,
            indirection_delta: base_syntax.indirection_delta,
        };
        assert!(
            self.type_syntax_by_node
                .insert(generic_type.id(), generic_syntax)
                .is_none()
        );

        let (callee, receiver) = match base.kind() {
            "identifier" | "type_identifier" | "field_identifier" => {
                let Some(callee) = self.add_identifier_site(
                    base,
                    ResolutionSiteKind::CallableReference,
                    self.scope_for_source_node(base),
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::TypeOrValue,
                    None,
                ) else {
                    self.lower_unsupported_expression_as(node, ResolutionGapKind::MalformedSyntax);
                    return;
                };
                (callee, None)
            }
            "qualified_type" => {
                let (Some(package), Some(name)) = (
                    base.child_by_field_name("package"),
                    base.child_by_field_name("name"),
                ) else {
                    self.lower_unsupported_expression_as(node, ResolutionGapKind::MalformedSyntax);
                    return;
                };
                self.lower_qualifier_reference(package);
                if !is_spelled_identifier(name) {
                    let site = self.add_site(name, ResolutionSiteKind::MemberReference);
                    self.add_gap(site, ResolutionGapKind::MalformedSyntax);
                    return;
                }
                let callee = self.add_site(name, ResolutionSiteKind::MemberReference);
                let receiver = self.add_slot(callee, ResolutionTypeSlotRole::Receiver);
                self.add_transfer(
                    self.expression_slot(package),
                    receiver,
                    ResolutionTypeTransferKind::Receiver,
                    0,
                    ResolutionTypeTransferValueTransform::Preserve,
                );
                if !self.add_identifier_to_site(
                    callee,
                    name,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Callable,
                    Some(receiver),
                ) {
                    return;
                }
                self.facts
                    .callable_receiver_origins
                    .push(ResolutionCallableReceiverOriginFact {
                        reference: callee,
                        origin: ResolutionCallableReceiverOrigin::ExplicitExpression,
                    });
                self.add_qualified_root_reference(package, callee);
                (callee, Some(receiver))
            }
            _ => {
                self.lower_unsupported_expression_as(
                    node,
                    ResolutionGapKind::UnsupportedCallApplicability,
                );
                return;
            }
        };
        self.add_gap(callee, ResolutionGapKind::UnsupportedCallApplicability);
        let call = self.add_site(node, ResolutionSiteKind::Call);
        let receiver = receiver.map(|previous| {
            let receiver = self.add_slot(call, ResolutionTypeSlotRole::Receiver);
            self.add_transfer(
                previous,
                receiver,
                ResolutionTypeTransferKind::Receiver,
                0,
                ResolutionTypeTransferValueTransform::Preserve,
            );
            receiver
        });
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
            dense_ordinal(arguments.len(), "Go explicit invocation type argument"),
        );
        self.attach_call_type_arguments(call, arguments);
        let argument_value = self.add_slot(call, ResolutionTypeSlotRole::Argument);
        self.add_transfer(
            self.expression_slot(operand),
            argument_value,
            ResolutionTypeTransferKind::Argument,
            0,
            ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
        );
        self.facts.call_arguments.push(ResolutionCallArgumentFact {
            call,
            list_ordinal: 0,
            ordinal: 0,
            value: argument_value,
            label: None,
        });
        self.facts
            .engine_rule_eligibilities
            .push(ResolutionEngineRuleEligibilityFact {
                site: call,
                rule: ResolutionEngineRuleKind::ArgumentIndependentBinding,
            });
        self.expression_slots_by_node.insert(node.id(), result);
    }

    fn go_builtin_type_argument(&self, call: Node<'_>, argument: Node<'_>) -> bool {
        let Some(function) = call.child_by_field_name("function") else {
            return false;
        };
        if !matches!(function.kind(), "identifier" | "type_identifier")
            || !matches!(go_node_text(function, self.source).trim(), "make" | "new")
            || !is_go_type_argument_node(argument)
        {
            return false;
        }
        call.child_by_field_name("arguments")
            .and_then(first_named_child)
            .is_some_and(|first| first.id() == argument.id())
    }

    fn attach_call_type_arguments(&mut self, call: ResolutionSiteId, positional: Vec<Node<'tree>>) {
        let has_arguments = !positional.is_empty();
        for (ordinal, type_node) in positional.into_iter().enumerate() {
            let syntax = self.lower_type(type_node);
            let value = self.add_slot(call, ResolutionTypeSlotRole::DeclaredValue);
            self.add_transfer(
                syntax.input,
                value,
                ResolutionTypeTransferKind::DeclaredType,
                syntax.indirection_delta,
                ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
            );
            self.facts
                .call_type_arguments
                .push(ResolutionCallTypeArgumentFact {
                    call,
                    ordinal: dense_ordinal(ordinal, "Go call type argument"),
                    value,
                });
        }
        if !has_arguments {
            self.add_gap(call, ResolutionGapKind::MalformedSyntax);
        }
    }

    fn attach_call_arguments(&mut self, node: Node<'_>, call: ResolutionSiteId) {
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        let values = named_children(arguments)
            .into_iter()
            .filter(|argument| {
                argument.kind() != "comment" && !self.go_builtin_type_argument(node, *argument)
            })
            .collect::<Vec<_>>();
        for (ordinal, argument) in values.into_iter().enumerate() {
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
                list_ordinal: 0,
                ordinal: dense_ordinal(ordinal, "Go call argument"),
                value,
                label: None,
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
        self.lower_composite_literal_body(body, owner, Some(type_node));
        self.expression_slots_by_node.insert(node.id(), output);
    }

    fn lower_composite_literal_body(
        &mut self,
        body: Node<'tree>,
        owner_type: ResolutionTypeSlotId,
        owner_syntax: Option<Node<'tree>>,
    ) {
        let mut pending = vec![(body, owner_type, owner_syntax)];
        while let Some((body, owner_type, owner_syntax)) = pending.pop() {
            let constructor_hint = owner_syntax.and_then(go_literal_type_constructor);
            for container_element in named_children(body)
                .into_iter()
                .filter(|child| child.kind() != "comment")
            {
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
                        let key_is_label = is_spelled_identifier(key);
                        if constructor_hint == Some(ResolutionTypeConstructorKind::Map)
                            || !key_is_label
                        {
                            if key.kind() == "literal_value" {
                                self.lower_literal_component(
                                    key,
                                    owner_type,
                                    ResolutionTypeTransferKind::ComponentKey,
                                    owner_syntax.and_then(|syntax| {
                                        go_literal_component_type(
                                            syntax,
                                            ResolutionTypeTransferKind::ComponentKey,
                                        )
                                    }),
                                    &mut pending,
                                );
                            } else {
                                self.lower_expression(key);
                            }
                            self.lower_literal_component(
                                value,
                                owner_type,
                                ResolutionTypeTransferKind::ComponentValue,
                                owner_syntax.and_then(|syntax| {
                                    go_literal_component_type(
                                        syntax,
                                        ResolutionTypeTransferKind::ComponentValue,
                                    )
                                }),
                                &mut pending,
                            );
                        } else if matches!(
                            constructor_hint,
                            Some(
                                ResolutionTypeConstructorKind::Sequence
                                    | ResolutionTypeConstructorKind::Slice
                                    | ResolutionTypeConstructorKind::Array
                            )
                        ) {
                            self.lower_expression(key);
                            self.lower_literal_component(
                                value,
                                owner_type,
                                ResolutionTypeTransferKind::ComponentElement,
                                owner_syntax.and_then(|syntax| {
                                    go_literal_component_type(
                                        syntax,
                                        ResolutionTypeTransferKind::ComponentElement,
                                    )
                                }),
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
                            owner_syntax.and_then(|syntax| {
                                go_literal_component_type(
                                    syntax,
                                    ResolutionTypeTransferKind::ComponentElement,
                                )
                            }),
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
        component_syntax: Option<Node<'tree>>,
        pending: &mut Vec<(Node<'tree>, ResolutionTypeSlotId, Option<Node<'tree>>)>,
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
            pending.push((value, type_slot, component_syntax));
        } else {
            self.lower_expression(value);
        }
    }

    fn lower_elided_literal_from_value(
        &mut self,
        element: Node<'tree>,
        value_type: ResolutionTypeSlotId,
        pending: &mut Vec<(Node<'tree>, ResolutionTypeSlotId, Option<Node<'tree>>)>,
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
        if !is_spelled_identifier(field) {
            let output = self.add_slot(reference, ResolutionTypeSlotRole::ExpressionValue);
            self.add_gap(reference, ResolutionGapKind::MalformedSyntax);
            return output;
        }
        let receiver = self.add_slot(reference, ResolutionTypeSlotRole::Receiver);
        self.add_transfer(
            owner_type,
            receiver,
            ResolutionTypeTransferKind::Receiver,
            0,
            ResolutionTypeTransferValueTransform::Preserve,
        );
        if !self.add_identifier_to_site(
            reference,
            field,
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Value,
            Some(receiver),
        ) {
            let output = self.add_slot(reference, ResolutionTypeSlotRole::ExpressionValue);
            return output;
        }
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
        self.add_intrinsic_type_seed(output, spelling, kind);
        self.expression_slots_by_node.insert(node.id(), output);
    }

    fn add_intrinsic_type_seed(
        &mut self,
        output: ResolutionTypeSlotId,
        spelling: &str,
        kind: IntrinsicTypeKind,
    ) {
        let name = self.intern_name(spelling);
        self.facts.intrinsic_type_seeds.push(IntrinsicTypeSeedFact {
            output,
            name,
            kind,
            indirection: 0,
        });
    }

    fn lower_unsupported_expression(&mut self, node: Node<'_>) {
        self.lower_unsupported_expression_as(node, ResolutionGapKind::UnsupportedExpression);
    }

    fn lower_unsupported_expression_type(&mut self, node: Node<'_>) {
        self.lower_unsupported_expression_as(node, ResolutionGapKind::UnsupportedExpressionType);
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

    fn value_name_is_visible(&self, scope: ResolutionScopeId, spelling: &str) -> bool {
        self.visible_value_scope(scope, spelling).is_some()
    }

    fn visible_value_scope(
        &self,
        mut scope: ResolutionScopeId,
        spelling: &str,
    ) -> Option<ResolutionScopeId> {
        loop {
            if self.value_name_is_declared(scope, spelling) {
                return Some(scope);
            }
            scope = self.scope(scope).parent?;
        }
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

fn go_is_nil_expression(root: Node<'_>) -> bool {
    let mut current = root;
    while current.kind() == "parenthesized_expression" {
        let Some(inner) = first_named_child(current) else {
            return false;
        };
        current = inner;
    }
    current.kind() == "nil"
}

fn go_default_type_for_untyped(spelling: &str) -> Option<&'static str> {
    match spelling {
        "untyped bool" => Some("bool"),
        "untyped int" => Some("int"),
        "untyped rune" => Some("rune"),
        "untyped float" => Some("float64"),
        "untyped complex" => Some("complex128"),
        "untyped string" => Some("string"),
        _ => None,
    }
}

fn go_is_constant_expression(root: Node<'_>, source: &str, allow_iota: bool) -> bool {
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        match node.kind() {
            "int_literal"
            | "float_literal"
            | "imaginary_literal"
            | "rune_literal"
            | "interpreted_string_literal"
            | "raw_string_literal"
            | "true"
            | "false" => {}
            "iota" if allow_iota => {}
            "identifier" if allow_iota && go_node_text(node, source).trim() == "iota" => {}
            "parenthesized_expression" => {
                let Some(inner) = first_named_child(node) else {
                    return false;
                };
                pending.push(inner);
            }
            "unary_expression" => {
                if !node
                    .child_by_field_name("operator")
                    .is_some_and(|operator| matches!(operator.kind(), "+" | "-" | "^" | "!"))
                {
                    return false;
                }
                let Some(operand) = node.child_by_field_name("operand") else {
                    return false;
                };
                pending.push(operand);
            }
            "binary_expression" => {
                if !node
                    .child_by_field_name("operator")
                    .is_some_and(|operator| {
                        matches!(
                            operator.kind(),
                            "+" | "-"
                                | "*"
                                | "/"
                                | "%"
                                | "&"
                                | "|"
                                | "^"
                                | "&^"
                                | "<<"
                                | ">>"
                                | "=="
                                | "!="
                                | "<"
                                | "<="
                                | ">"
                                | ">="
                                | "&&"
                                | "||"
                        )
                    })
                {
                    return false;
                }
                let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) else {
                    return false;
                };
                pending.push(left);
                pending.push(right);
            }
            _ => return false,
        }
    }
    true
}

fn go_untyped_constant_type(
    root: Node<'_>,
    source: &str,
    allow_iota: bool,
) -> Option<&'static str> {
    let mut pending = vec![(root, false)];
    let mut types = HashMap::<usize, Option<&'static str>>::default();
    while let Some((node, finishing)) = pending.pop() {
        if types.contains_key(&node.id()) {
            continue;
        }
        if !finishing {
            pending.push((node, true));
            match node.kind() {
                "parenthesized_expression" => {
                    if let Some(inner) = first_named_child(node) {
                        pending.push((inner, false));
                    }
                }
                "unary_expression" => {
                    if let Some(operand) = node.child_by_field_name("operand") {
                        pending.push((operand, false));
                    }
                }
                "binary_expression" => {
                    if let Some(left) = node.child_by_field_name("left") {
                        pending.push((left, false));
                    }
                    if let Some(right) = node.child_by_field_name("right") {
                        pending.push((right, false));
                    }
                }
                _ => {}
            }
            continue;
        }
        let inferred = match node.kind() {
            "int_literal" => Some("untyped int"),
            "float_literal" => Some("untyped float"),
            "imaginary_literal" => Some("untyped complex"),
            "rune_literal" => Some("untyped rune"),
            "interpreted_string_literal" | "raw_string_literal" => Some("untyped string"),
            "true" | "false" => Some("untyped bool"),
            "iota" if allow_iota => Some("untyped int"),
            "identifier" if allow_iota && go_node_text(node, source).trim() == "iota" => {
                Some("untyped int")
            }
            "parenthesized_expression" => {
                first_named_child(node).and_then(|inner| types.get(&inner.id()).copied().flatten())
            }
            "unary_expression" => {
                let operator = node
                    .child_by_field_name("operator")
                    .map(|operator| operator.kind());
                let operand = node
                    .child_by_field_name("operand")
                    .and_then(|operand| types.get(&operand.id()).copied().flatten());
                match (operator, operand) {
                    (Some("!"), Some("untyped bool")) => Some("untyped bool"),
                    (Some("+" | "-"), Some(kind))
                        if matches!(
                            kind,
                            "untyped int" | "untyped rune" | "untyped float" | "untyped complex"
                        ) =>
                    {
                        Some(kind)
                    }
                    (Some("^"), Some(kind)) if matches!(kind, "untyped int" | "untyped rune") => {
                        Some(kind)
                    }
                    _ => None,
                }
            }
            "binary_expression" => {
                let operator = node
                    .child_by_field_name("operator")
                    .map(|operator| operator.kind());
                let (left, right) = (
                    node.child_by_field_name("left")
                        .and_then(|left| types.get(&left.id()).copied().flatten()),
                    node.child_by_field_name("right")
                        .and_then(|right| types.get(&right.id()).copied().flatten()),
                );
                match (operator, left, right) {
                    (Some("==" | "!=" | "<" | "<=" | ">" | ">="), Some(_), Some(_)) => {
                        Some("untyped bool")
                    }
                    (Some("&&" | "||"), Some("untyped bool"), Some("untyped bool")) => {
                        Some("untyped bool")
                    }
                    (Some("<<" | ">>"), Some(left), Some("untyped int" | "untyped rune"))
                        if matches!(left, "untyped int" | "untyped rune") =>
                    {
                        Some(left)
                    }
                    (Some("+"), Some("untyped string"), Some("untyped string")) => {
                        Some("untyped string")
                    }
                    (
                        Some("+" | "-" | "*" | "/" | "%" | "&" | "|" | "^" | "&^"),
                        Some(left),
                        Some(right),
                    ) if left == right => Some(left),
                    _ => None,
                }
            }
            _ => None,
        };
        types.insert(node.id(), inferred);
    }
    types.get(&root.id()).copied().flatten()
}

fn expression_children(node: Node<'_>) -> Vec<Node<'_>> {
    if matches!(node.kind(), "expression_list" | "argument_list") {
        named_children(node)
    } else {
        vec![node]
    }
}

fn has_supported_anonymous_struct_type(node: Node<'_>) -> bool {
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        match current.kind() {
            "struct_type" => return true,
            "function_type" | "interface_type" | "generic_type" => continue,
            _ => pending.extend(named_children(current)),
        }
    }
    false
}

fn has_supported_anonymous_interface_type(node: Node<'_>) -> bool {
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        match current.kind() {
            "interface_type" => return true,
            "generic_type" => continue,
            _ => pending.extend(named_children(current)),
        }
    }
    false
}

fn has_supported_anonymous_type(node: Node<'_>) -> bool {
    has_supported_anonymous_struct_type(node) || has_supported_anonymous_interface_type(node)
}

fn is_go_conversion_type_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "qualified_type"
            | "pointer_type"
            | "array_type"
            | "slice_type"
            | "implicit_length_array_type"
            | "map_type"
            | "channel_type"
            | "parenthesized_type"
            | "struct_type"
    )
}

fn is_go_type_argument_node(node: Node<'_>) -> bool {
    matches!(node.kind(), "type_identifier" | "generic_type") || is_go_conversion_type_node(node)
}

fn go_literal_type_constructor(mut syntax: Node<'_>) -> Option<ResolutionTypeConstructorKind> {
    while syntax.kind() == "parenthesized_type" {
        syntax = first_named_child(syntax)?;
    }
    match syntax.kind() {
        "map_type" => Some(ResolutionTypeConstructorKind::Map),
        "array_type" | "implicit_length_array_type" => Some(ResolutionTypeConstructorKind::Array),
        "slice_type" => Some(ResolutionTypeConstructorKind::Slice),
        "channel_type" => Some(ResolutionTypeConstructorKind::Channel),
        _ => None,
    }
}

fn go_literal_component_type(
    mut syntax: Node<'_>,
    component: ResolutionTypeTransferKind,
) -> Option<Node<'_>> {
    while syntax.kind() == "parenthesized_type" {
        syntax = first_named_child(syntax)?;
    }
    match (syntax.kind(), component) {
        ("map_type", ResolutionTypeTransferKind::ComponentKey) => syntax.child_by_field_name("key"),
        ("map_type", ResolutionTypeTransferKind::ComponentValue) => {
            syntax.child_by_field_name("value")
        }
        (
            "array_type" | "slice_type" | "implicit_length_array_type",
            ResolutionTypeTransferKind::ComponentElement,
        ) => syntax.child_by_field_name("element"),
        ("channel_type", ResolutionTypeTransferKind::ComponentElement) => {
            syntax.child_by_field_name("value")
        }
        _ => None,
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

fn explicit_type_argument_count(node: Node<'_>) -> u32 {
    if let Some(arguments) = node.child_by_field_name("type_arguments") {
        return dense_ordinal(
            go_type_argument_nodes(arguments).len(),
            "Go explicit invocation type argument",
        );
    }
    node.child_by_field_name("function")
        .filter(|function| function.kind() == "type_instantiation_expression")
        .map_or(0, |function| {
            dense_ordinal(
                type_instantiation_argument_nodes(function).len(),
                "Go explicit invocation type argument",
            )
        })
}

fn go_type_argument_nodes(arguments: Node<'_>) -> Vec<Node<'_>> {
    let mut positional = Vec::new();
    for element in named_children(arguments) {
        if element.kind() == "type_elem" {
            positional.extend(named_children(element));
        } else {
            positional.push(element);
        }
    }
    positional
}

fn type_instantiation_argument_nodes(node: Node<'_>) -> Vec<Node<'_>> {
    if let Some(arguments) = node.child_by_field_name("type_arguments") {
        return go_type_argument_nodes(arguments);
    }
    let base = node.child_by_field_name("type");
    named_children(node)
        .into_iter()
        .filter(|child| base.is_none_or(|base| child.id() != base.id()))
        .flat_map(|element| {
            if element.kind() == "type_elem" {
                named_children(element)
            } else {
                vec![element]
            }
        })
        .collect()
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
            assert!(
                parent.start_byte <= scope.start_byte && scope.end_byte <= parent.end_byte,
                "scope {:?} {:?} range {}..{} escapes parent {:?} {:?} range {}..{}",
                scope.id,
                scope.kind,
                scope.start_byte,
                scope.end_byte,
                parent.id,
                parent.kind,
                parent.start_byte,
                parent.end_byte,
            );
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
    use brokk_bifrost_test_macros::hardwon;
    use std::collections::HashMap as StdHashMap;
    use std::path::{Path, PathBuf};
    use tree_sitter::{Parser, Tree};

    fn output_from_tree(tree: &Tree, source: &str) -> GoResolutionOutput {
        let mut builder = GoResolutionBuilder::new(tree.root_node(), source);
        enum Frame<'tree> {
            Enter(Node<'tree>),
            Exit,
        }
        let mut stack = vec![Frame::Enter(tree.root_node())];
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
        builder.finish()
    }

    fn facts(source: &str) -> FileResolutionFacts {
        let tree = crate::parse::parse_go(source).expect("Go tree");
        extract_go_resolution_facts(tree.root_node(), source)
    }

    #[derive(Debug, Clone, Copy)]
    enum ExpectedNameRole {
        Reference,
        Declaration,
        ReferenceOrDeclaration,
    }

    fn has_short_declaration(node: Node<'_>) -> bool {
        (0..node.child_count())
            .any(|index| node.child(index).is_some_and(|child| child.kind() == ":="))
    }

    fn is_generic_receiver_parameter(node: Node<'_>) -> bool {
        let mut ancestor = node.parent();
        while let Some(current) = ancestor {
            if current.kind() == "generic_type"
                && current
                    .child_by_field_name("type_arguments")
                    .is_some_and(|arguments| {
                        arguments.start_byte() <= node.start_byte()
                            && node.end_byte() <= arguments.end_byte()
                    })
            {
                let mut owner = current.parent();
                while let Some(parent) = owner {
                    if parent.kind() == "method_declaration" {
                        return parent
                            .child_by_field_name("receiver")
                            .is_some_and(|receiver| {
                                receiver.start_byte() <= node.start_byte()
                                    && node.end_byte() <= receiver.end_byte()
                            });
                    }
                    if matches!(parent.kind(), "function_declaration" | "source_file") {
                        break;
                    }
                    owner = parent.parent();
                }
            }
            ancestor = current.parent();
        }
        false
    }

    fn expected_name_role(node: Node<'_>, source: &str) -> Option<ExpectedNameRole> {
        if !matches!(
            node.kind(),
            "identifier" | "type_identifier" | "field_identifier" | "package_identifier"
        ) || source.get(node.start_byte()..node.end_byte()) == Some("_")
        {
            return None;
        }
        if is_generic_receiver_parameter(node) {
            return Some(ExpectedNameRole::Declaration);
        }
        let parent = node.parent()?;
        if matches!(
            parent.kind(),
            "parameter_declaration" | "variadic_parameter_declaration"
        ) && node.kind() == "identifier"
        {
            let mut ancestor = parent.parent();
            while let Some(current) = ancestor {
                if current.kind() == "function_type" {
                    return None;
                }
                if matches!(
                    current.kind(),
                    "function_declaration" | "method_declaration" | "func_literal"
                ) {
                    break;
                }
                ancestor = current.parent();
            }
        }
        match (parent.kind(), node.kind()) {
            ("package_clause", "package_identifier") => return None,
            ("import_spec", "package_identifier") => return None,
            _ => {}
        }
        if children_by_field(parent, "name")
            .iter()
            .any(|name| name.id() == node.id())
            && matches!(
                (parent.kind(), node.kind()),
                ("function_declaration", "identifier")
                    | ("type_spec", "type_identifier")
                    | ("type_alias", "type_identifier")
                    | ("var_spec", "identifier")
                    | ("const_spec", "identifier")
                    | ("parameter_declaration", "identifier")
                    | ("variadic_parameter_declaration", "identifier")
                    | ("field_declaration", "field_identifier")
                    | ("method_declaration", "field_identifier")
                    | ("method_elem", "field_identifier")
                    | ("type_parameter_declaration", "identifier")
                    | ("type_parameter_declaration", "type_identifier")
            )
        {
            return Some(ExpectedNameRole::Declaration);
        }
        if parent.kind() == "expression_list" {
            let Some(owner) = parent.parent() else {
                return Some(ExpectedNameRole::Reference);
            };
            if owner
                .child_by_field_name("left")
                .is_some_and(|left| left.id() == parent.id())
            {
                return Some(match owner.kind() {
                    "short_var_declaration" => ExpectedNameRole::ReferenceOrDeclaration,
                    "range_clause" | "receive_statement" if has_short_declaration(owner) => {
                        ExpectedNameRole::Declaration
                    }
                    "range_clause" | "receive_statement" => ExpectedNameRole::Reference,
                    _ => ExpectedNameRole::Reference,
                });
            }
            if owner
                .child_by_field_name("alias")
                .is_some_and(|alias| alias.id() == parent.id())
                && owner.kind() == "type_switch_statement"
            {
                return Some(ExpectedNameRole::Declaration);
            }
        }
        Some(ExpectedNameRole::Reference)
    }

    fn ast_reference_oracle(
        root: Node<'_>,
        source: &str,
        facts: &FileResolutionFacts,
        file: &str,
    ) -> Result<(), String> {
        let mut roles_by_range = StdHashMap::<(usize, usize), Vec<ResolutionIdentifierRole>>::new();
        for identifier in &facts.identifiers {
            let site = &facts.sites[identifier.site.index()];
            roles_by_range
                .entry((site.start_byte, site.end_byte))
                .or_default()
                .push(identifier.role);
        }
        let mut pending = vec![root];
        while let Some(node) = pending.pop() {
            if let Some(expected) = expected_name_role(node, source) {
                let roles = roles_by_range.get(&(node.start_byte(), node.end_byte()));
                let matched = roles.is_some_and(|roles| match expected {
                    ExpectedNameRole::Reference => {
                        roles.contains(&ResolutionIdentifierRole::Reference)
                    }
                    ExpectedNameRole::Declaration => {
                        roles.contains(&ResolutionIdentifierRole::Declaration)
                    }
                    ExpectedNameRole::ReferenceOrDeclaration => {
                        roles.contains(&ResolutionIdentifierRole::Reference)
                            || roles.contains(&ResolutionIdentifierRole::Declaration)
                    }
                });
                if !matched {
                    let mut context = Vec::new();
                    let mut current = node;
                    while let Some(parent) = current.parent() {
                        context.push(format!(
                            "{}[{}..{}]",
                            parent.kind(),
                            parent.start_byte(),
                            parent.end_byte()
                        ));
                        current = parent;
                        if context.len() == 8 {
                            break;
                        }
                    }
                    return Err(format!(
                        "{file}: complete Go inventory lacks {expected:?} site for {} at bytes {}..{} (ancestors: {context:?})",
                        node.kind(),
                        node.start_byte(),
                        node.end_byte()
                    ));
                }
            }
            for index in (0..node.child_count()).rev() {
                if let Some(child) = node.child(index) {
                    pending.push(child);
                }
            }
        }
        Ok(())
    }

    fn gap_construct_family<'tree>(
        root: Node<'tree>,
        site: &brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteFact,
    ) -> (&'static str, Node<'tree>) {
        let mut pending = vec![root];
        let mut construct = None;
        while let Some(node) = pending.pop() {
            if node.start_byte() <= site.start_byte && site.end_byte <= node.end_byte() {
                construct = Some(node);
                for index in (0..node.child_count()).rev() {
                    if let Some(child) = node.child(index)
                        && child.start_byte() <= site.start_byte
                        && site.end_byte <= child.end_byte()
                    {
                        pending.push(child);
                    }
                }
            }
        }
        let mut node = Some(construct.unwrap_or(root));
        while let Some(current) = node {
            let family = match current.kind() {
                "for_statement" => Some("for statement"),
                "for_clause" => Some("for clause"),
                "range_clause" => Some("range clause"),
                "go_statement" => Some("go statement"),
                "defer_statement" => Some("defer statement"),
                "field_declaration" => Some("field declaration"),
                "struct_type" => Some("struct type"),
                "variadic_parameter_declaration" => Some("variadic parameter"),
                "parameter_declaration" => Some("parameter declaration"),
                "func_literal" => Some("func literal"),
                "interface_type" => Some("interface type"),
                "type_parameter_list" | "type_parameter_declaration" => {
                    Some("type parameter binder")
                }
                "binary_expression" => Some("binary expression"),
                "unary_expression" => Some("unary expression"),
                "index_expression" => Some("index expression"),
                "slice_expression" => Some("slice expression"),
                "type_assertion_expression" => Some("type assertion"),
                "selector_expression" => Some("selector expression"),
                "call_expression" => Some("call expression"),
                "short_var_declaration" => Some("short var declaration"),
                "assignment_statement" => Some("assignment statement"),
                "return_statement" => Some("return statement"),
                "import_declaration" => Some("import declaration"),
                "type_spec" | "type_alias" => Some("type declaration"),
                "var_spec" => Some("var declaration"),
                "const_spec" => Some("const declaration"),
                "function_declaration" | "method_declaration" => Some("callable declaration"),
                "communication_case" => Some("communication case"),
                "expression_case" | "type_case" => Some("switch case"),
                _ => None,
            };
            if let Some(family) = family {
                return (family, current);
            }
            node = current.parent();
        }
        ("unclassified", root)
    }

    fn corpus_go_files(root: &Path) -> Vec<PathBuf> {
        let mut pending = vec![root.to_path_buf()];
        let mut files = Vec::new();
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(&directory)
                .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
            {
                let entry = entry.unwrap_or_else(|error| panic!("read entry: {error}"));
                let path = entry.path();
                if entry
                    .file_type()
                    .unwrap_or_else(|error| panic!("stat {}: {error}", path.display()))
                    .is_dir()
                {
                    pending.push(path);
                } else if path.extension().is_some_and(|extension| extension == "go") {
                    files.push(path);
                }
            }
        }
        files.sort_unstable();
        files
    }

    #[test]
    fn struct_embedding_uses_the_member_path_instead_of_a_hierarchy_gap() {
        let facts = facts("package p\ntype Base struct{}\ntype Outer struct{ Base }\n");

        assert!(facts.member_owners.iter().any(|owner| {
            owner.kind == ResolutionMemberKind::Field
                && facts.sites[owner.member.index()].kind == ResolutionSiteKind::ValueDeclaration
        }));
        assert!(
            facts
                .gaps
                .iter()
                .all(|gap| gap.kind != ResolutionGapKind::UnsupportedHierarchyTraversal),
            "Go struct embedding is represented by the structured member path"
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
    fn complete_expression_fixtures_match_an_independent_ast_reference_oracle() {
        let source = r#"package p
const offset = 1
const next = offset + 1
const markerSize = 1
type Marker struct{}
var _ Marker
type Fixed [markerSize]byte
type FieldShapes struct {
    pkg.Embedded
    *pkg.PointerEmbedded
    First, Second pkg.Value `json:"field"`
}
var Anonymous struct {
    pkg.AnonymousEmbedded
    First, Second pkg.AnonymousValue `json:"anonymous"`
}
var _ pkg.Box[other.Config]
func consumeInt(value int) {}
func collect(values ...pkg.Value) {}
func unnamed(...pkg.Value) {}
func check(values []int, low, high int, dynamic any, err error, channel chan int) (int, error) {
    switch low {
    case offset:
    }
    switch typed := dynamic.(type) {
    case int:
        _ = typed
        switch typed {
        case offset:
            _ = typed
        }
    case error:
        _ = typed
    }
    for index := low; index < high; index++ {
        _ = values[index]
    }
    for low < high {
        low++
    }
    go consumeInt(values[low])
    defer consumeInt(values[high])
    go collect(nil)
    go func() { _ = low; local := low; _ = local }()
    defer func() { _ = err }()
    type LocalAlias = struct { Nested pkg.Value }
    _ = func(values ...pkg.Value) { _ = values }
    channel <- func() int { _ = low; return high }()
    var first, second = low, high
    var missingTypeA, missingTypeB = low
    _ = low + high
    _ = -low
    _ = values[low]
    _ = values[low:high]
    _ = dynamic.(int)
    _ = nil
    _ = pkg.Call[other.Config]()
    _ = factory()(pkg.Value)
    channel <- low
    existing := low
    existing++
    values[low]--
    existing, fresh := existing, high
    _ = first
    _ = second
    _ = missingTypeA
    _ = missingTypeB
    _ = fresh
    return low, err
}
func namedResult() (result string) {
    _ = result
    return
}
"#;
        let tree = crate::parse::parse_go(source).expect("Go fixture tree");
        let facts = output_from_tree(&tree, source).facts;
        assert!(
            facts.reference_enumeration_gaps.is_empty(),
            "fixture must be reference-complete: {:?}",
            facts.reference_enumeration_gaps
        );
        let repeated_parameters = facts
            .callable_parameters
            .iter()
            .filter(|parameter| parameter.repeated)
            .collect::<Vec<_>>();
        assert_eq!(repeated_parameters.len(), 2);
        for parameter in repeated_parameters {
            assert!(facts.gaps.contains(&ResolutionGapFact {
                site: parameter.parameter,
                kind: ResolutionGapKind::UnsupportedExpressionType,
            }));
            assert!(
                !facts
                    .reference_enumeration_gaps
                    .iter()
                    .any(|gap| { gap.site == parameter.parameter })
            );
        }
        let mut pending = vec![tree.root_node()];
        let mut ordinary_for = None;
        while let Some(node) = pending.pop() {
            if node.kind() == "for_statement"
                && named_children(node)
                    .iter()
                    .any(|child| child.kind() == "for_clause")
            {
                ordinary_for = Some(node);
                break;
            }
            pending.extend(named_children(node));
        }
        let ordinary_for = ordinary_for.expect("fixture has an ordinary for clause");
        let index = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && name(&facts, identifier.name) == "index"
            })
            .expect("for initializer publishes the index binder");
        let index_site = &facts.sites[index.site.index()];
        assert!(ordinary_for.start_byte() <= index_site.start_byte);
        assert!(index_site.end_byte <= ordinary_for.end_byte());
        let index_binder = facts
            .binders
            .iter()
            .find(|binder| binder.declaration == index.site)
            .expect("for initializer declaration has a binder");
        let loop_scope = &facts.scopes[index_binder.scope.index()];
        assert_eq!(loop_scope.kind, ResolutionScopeKind::Block);
        assert_eq!(loop_scope.start_byte, ordinary_for.start_byte());
        assert_eq!(loop_scope.end_byte, ordinary_for.end_byte());
        ast_reference_oracle(tree.root_node(), source, &facts, "expression fixture")
            .unwrap_or_else(|error| panic!("{error}"));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#2771: builtin new(T) omitted the construction and pointer result facts used by receiver queries"
    )]
    fn conversions_and_builtin_type_operands_lower_type_positions() {
        let source = r#"package p
type Value struct{}
func exercise(value Value, input string, size int, values, more []int) {
    _ = []byte(input)
    _ = make([]Value, size)
    _ = new(Value)
    _ = &Value{}
    _ = append(values, more...)
}
"#;
        let tree = crate::parse::parse_go(source).expect("call fixture tree");
        let facts = output_from_tree(&tree, source).facts;
        let mut ast_shapes = Vec::new();
        let mut pending = vec![tree.root_node()];
        while let Some(node) = pending.pop() {
            if node.kind() == "call_expression"
                && node
                    .child_by_field_name("function")
                    .is_some_and(|function| go_node_text(function, source).trim() == "append")
            {
                ast_shapes.extend(
                    node.child_by_field_name("arguments")
                        .into_iter()
                        .flat_map(named_children)
                        .map(|argument| {
                            (
                                argument.kind(),
                                argument.parent().map(|parent| parent.kind()),
                                Some(go_node_text(argument, source)),
                            )
                        }),
                );
            }
            if facts.reference_enumeration_gaps.iter().any(|gap| {
                let site = &facts.sites[gap.site.index()];
                site.start_byte == node.start_byte() && site.end_byte == node.end_byte()
            }) {
                ast_shapes.push((
                    node.kind(),
                    node.child_by_field_name("function")
                        .map(|child| child.kind()),
                    node.child_by_field_name("type").map(|child| child.kind()),
                ));
            }
            pending.extend(named_children(node));
        }
        assert!(
            facts.reference_enumeration_gaps.is_empty(),
            "call type operands are completely lowered: {:?}; AST nodes={ast_shapes:?}",
            facts
                .reference_enumeration_gaps
                .iter()
                .map(|gap| {
                    let site = &facts.sites[gap.site.index()];
                    (
                        gap.kind,
                        site.kind,
                        source[site.start_byte..site.end_byte].to_owned(),
                    )
                })
                .collect::<Vec<_>>()
        );
        ast_reference_oracle(tree.root_node(), source, &facts, "call fixture")
            .unwrap_or_else(|error| panic!("{error}"));

        let mut calls = Vec::new();
        let mut pending = vec![tree.root_node()];
        while let Some(node) = pending.pop() {
            if node.kind() == "call_expression" {
                calls.push(node);
            }
            pending.extend(named_children(node));
        }
        let call_argument_count = |call_node: Node<'_>| {
            let call = facts
                .calls
                .iter()
                .find(|call| {
                    let site = &facts.sites[call.call.index()];
                    site.start_byte == call_node.start_byte()
                        && site.end_byte == call_node.end_byte()
                })
                .expect("call expression has a call fact");
            facts
                .call_arguments
                .iter()
                .filter(|argument| argument.call == call.call)
                .count()
        };
        let named_call = |name: &str| {
            calls
                .iter()
                .copied()
                .find(|call| {
                    call.child_by_field_name("function")
                        .is_some_and(|function| go_node_text(function, source).trim() == name)
                })
                .unwrap_or_else(|| panic!("fixture has {name} call"))
        };
        assert_eq!(call_argument_count(named_call("make")), 1);
        assert_eq!(call_argument_count(named_call("new")), 0);
        let allocation = facts
            .calls
            .iter()
            .find(|call| {
                let site = &facts.sites[call.call.index()];
                site.start_byte == named_call("new").start_byte()
            })
            .expect("builtin new has a call result");
        let allocation_address = transfer_to(&facts, allocation.result);
        let literal_address = facts
            .type_transfers
            .iter()
            .find(|transfer| {
                transfer.kind == ResolutionTypeTransferKind::AddressOf
                    && transfer.output != allocation.result
            })
            .expect("address-of literal transfer");
        for (allocation_transfer, literal_transfer) in [
            (allocation_address, *literal_address),
            (
                transfer_to(&facts, allocation_address.input),
                transfer_to(&facts, literal_address.input),
            ),
        ] {
            assert_eq!(allocation_transfer.kind, literal_transfer.kind);
            assert_eq!(
                allocation_transfer.indirection_delta,
                literal_transfer.indirection_delta
            );
            assert_eq!(
                allocation_transfer.reference_indirection_delta,
                literal_transfer.reference_indirection_delta
            );
            assert_eq!(
                allocation_transfer.value_transform,
                literal_transfer.value_transform
            );
        }
        let mut conversions = Vec::new();
        let mut pending = vec![tree.root_node()];
        while let Some(node) = pending.pop() {
            if node.kind() == "type_conversion_expression" {
                conversions.push(node);
            }
            pending.extend(named_children(node));
        }
        assert_eq!(conversions.len(), 1);
        let conversion = conversions[0];
        assert_eq!(
            conversion
                .child_by_field_name("type")
                .map(|node| node.kind()),
            Some("slice_type")
        );
        let conversion_site = facts
            .sites
            .iter()
            .find(|site| {
                site.kind == ResolutionSiteKind::UnsupportedExpression
                    && site.start_byte == conversion.start_byte()
                    && site.end_byte == conversion.end_byte()
            })
            .expect("conversion has an expression result frontier");
        assert!(facts.gaps.iter().any(|gap| {
            gap.site == conversion_site.id
                && gap.kind == ResolutionGapKind::UnsupportedExpressionType
        }));
        assert!(facts.identifiers.iter().any(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && name(&facts, identifier.name) == "input"
                && facts.sites[identifier.site.index()].start_byte
                    == conversion
                        .child_by_field_name("operand")
                        .expect("conversion operand")
                        .start_byte()
        }));
    }

    #[test]
    fn short_var_existing_selector_targets_keep_their_reference_sites() {
        let source = r#"package p
type Box struct{ Field int }
func assign(box Box, value int) {
    box.Field, created := value, value
    _ = created
}
"#;
        let tree = crate::parse::parse_go(source).expect("short-var fixture tree");
        let facts = output_from_tree(&tree, source).facts;
        assert!(
            facts.reference_enumeration_gaps.is_empty(),
            "short-var selector target has no missing binder: {:?}",
            facts.reference_enumeration_gaps
        );
        ast_reference_oracle(tree.root_node(), source, &facts, "short-var fixture")
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(facts.identifiers.iter().any(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && name(&facts, identifier.name) == "box"
        }));
        assert!(facts.identifiers.iter().any(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && name(&facts, identifier.name) == "Field"
        }));
        assert!(facts.identifiers.iter().any(|identifier| {
            identifier.role == ResolutionIdentifierRole::Declaration
                && name(&facts, identifier.name) == "created"
        }));
    }

    #[test]
    fn comments_inside_composite_literals_do_not_block_reference_enumeration() {
        let source = r#"package p
type Entry struct{ Field int }
func consume(Entry, Entry) {}
func use(seed int) {
    entries := []Entry{
        // element comment
        {Field: seed}, // trailing element comment
    }
    for index := range []int{
        // range value comment
        seed,
    } {
        _ = index
    }
    consume(Entry{
        // call argument comment
        Field: seed,
    }, // argument separator comment
        Entry{Field: seed},
    )
    _ = entries
}
"#;
        let tree = crate::parse::parse_go(source).expect("literal comment fixture tree");
        let facts = output_from_tree(&tree, source).facts;
        assert!(
            facts.reference_enumeration_gaps.is_empty(),
            "literal comments are not unsupported elements: {:?}",
            facts.reference_enumeration_gaps
        );
        assert_eq!(
            facts.call_arguments.len(),
            2,
            "comments are not call arguments"
        );
        ast_reference_oracle(tree.root_node(), source, &facts, "literal comment fixture")
            .unwrap_or_else(|error| panic!("{error}"));
    }

    #[test]
    fn function_literal_fixtures_preserve_scopes_results_and_captures() {
        let source = r#"package p
var PackageValue int
func consume(value int) {}
func use(values []int, outer int) {
    for _, loopValue := range values {
        consume(func(input int) (result int, extra int) {
            _ = result
            _ = extra
            nested := func() (first int, second int) {
                _ = first
                _ = second
                return outer, PackageValue
            }
            _ = nested
            _ = func(value int) int { return value }(input)
            {
                outer := input
                _ = outer
            }
            return outer, loopValue
        })
    }
}
"#;
        let tree = crate::parse::parse_go(source).expect("Go fixture tree");
        let facts = output_from_tree(&tree, source).facts;
        assert!(
            facts.reference_enumeration_gaps.is_empty(),
            "fixture must be reference-complete: {:?}",
            facts.reference_enumeration_gaps
        );
        ast_reference_oracle(tree.root_node(), source, &facts, "function literal fixture")
            .unwrap_or_else(|error| panic!("{error}"));

        let mut literal_nodes = Vec::new();
        let mut pending = vec![tree.root_node()];
        while let Some(node) = pending.pop() {
            if node.kind() == "func_literal" {
                literal_nodes.push(node);
            }
            for index in (0..node.child_count()).rev() {
                if let Some(child) = node.child(index) {
                    pending.push(child);
                }
            }
        }
        assert_eq!(literal_nodes.len(), 3);
        let literal_sites = literal_nodes
            .iter()
            .map(|literal| {
                facts
                    .sites
                    .iter()
                    .find(|site| {
                        site.kind == ResolutionSiteKind::UnsupportedExpression
                            && site.start_byte == literal.start_byte()
                            && site.end_byte == literal.end_byte()
                    })
                    .expect("function literal has an expression frontier")
            })
            .collect::<Vec<_>>();
        for (literal, site) in literal_nodes.iter().zip(&literal_sites) {
            let scope = facts
                .scopes
                .iter()
                .find(|scope| scope.owner == Some(site.id))
                .expect("function literal owns its executable scope");
            assert_eq!(scope.kind, ResolutionScopeKind::Executable);
            let body = literal.child_by_field_name("body").expect("literal body");
            assert!(facts.scopes.iter().any(|body_scope| {
                body_scope.parent == Some(scope.id)
                    && body_scope.kind == ResolutionScopeKind::Block
                    && body_scope.start_byte == body.start_byte()
                    && body_scope.end_byte == body.end_byte()
            }));
        }

        for marker in [
            "input int",
            "result int",
            "extra int",
            "first int",
            "second int",
        ] {
            let position = source.find(marker).unwrap_or_else(|| panic!("{marker}"));
            let declaration = facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Declaration
                        && facts.sites[identifier.site.index()].start_byte == position
                })
                .unwrap_or_else(|| panic!("function literal binder missing for {marker}"));
            assert!(facts.binders.iter().any(|binder| {
                binder.declaration == declaration.site
                    && binder.kind == ResolutionBinderKind::Parameter
            }));
        }
        let value_position = source
            .rfind("value int")
            .expect("immediately invoked parameter");
        let value_declaration = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.sites[identifier.site.index()].start_byte == value_position
            })
            .expect("immediately invoked literal parameter is a declaration");
        assert!(facts.binders.iter().any(|binder| {
            binder.declaration == value_declaration.site
                && binder.kind == ResolutionBinderKind::Parameter
        }));

        let nested_position = source.find("func() (first int").expect("nested literal");
        let nested_site = literal_sites
            .iter()
            .find(|site| site.start_byte == nested_position)
            .expect("nested literal site");
        let nested_results = facts
            .type_slots
            .iter()
            .filter(|slot| {
                slot.site == nested_site.id && slot.role == ResolutionTypeSlotRole::DeclaredValue
            })
            .collect::<Vec<_>>();
        assert_eq!(
            nested_results.len(),
            2,
            "named result slots retain source order"
        );
        assert!(nested_results[0].id < nested_results[1].id);
        let nested_returns = facts
            .type_slots
            .iter()
            .filter(|slot| {
                slot.site == nested_site.id && slot.role == ResolutionTypeSlotRole::ReturnValue
            })
            .collect::<Vec<_>>();
        assert_eq!(
            nested_returns.len(),
            2,
            "multi-value return has two ordered slots"
        );
        assert!(nested_returns[0].id < nested_returns[1].id);
        let returned_sources = facts
            .type_transfers
            .iter()
            .filter(|transfer| {
                transfer.kind == ResolutionTypeTransferKind::Return
                    && nested_returns.iter().any(|slot| slot.id == transfer.output)
            })
            .map(|transfer| facts.type_slots[transfer.input.index()].site)
            .collect::<Vec<_>>();
        assert_eq!(returned_sources.len(), 2);
        assert_eq!(
            facts.sites[returned_sources[0].index()].start_byte,
            source.find("return outer, PackageValue").unwrap() + "return ".len()
        );
        assert_eq!(
            facts.sites[returned_sources[1].index()].start_byte,
            source.match_indices("PackageValue").nth(1).unwrap().0
        );

        let immediate_call = source
            .find("func(value int)")
            .expect("immediate invocation");
        assert!(
            facts
                .calls
                .iter()
                .any(|call| { facts.sites[call.call.index()].start_byte == immediate_call })
        );
        assert!(facts.gaps.iter().any(|gap| {
            facts.sites[gap.site.index()].start_byte == immediate_call
                && gap.kind == ResolutionGapKind::UnsupportedCallApplicability
        }));
    }

    #[test]
    fn complete_indexed_go_corpora_match_the_independent_ast_reference_oracle() {
        let Some(root) = std::env::var_os("BIFROST_GO_REFERENCE_ORACLE_ROOT") else {
            return;
        };
        let root = PathBuf::from(root);
        let files = corpus_go_files(&root);
        let mut stats = std::collections::BTreeMap::<String, [usize; 5]>::new();
        let mut producer_panics = Vec::new();
        let mut parse_failures = Vec::new();
        let mut oracle_failures = Vec::new();
        let mut blocker_families_by_file = StdHashMap::<(String, String), HashSet<String>>::new();
        let mut blocker_occurrences = StdHashMap::<String, usize>::new();
        let mut blocker_examples = StdHashMap::<&'static str, Vec<String>>::new();
        for path in files {
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            let relative = path.strip_prefix(&root).unwrap_or(&path);
            let corpus = relative
                .components()
                .next()
                .map(|component| component.as_os_str().to_string_lossy().into_owned())
                .unwrap_or_else(|| "root".to_owned());
            let counts = stats.entry(corpus.clone()).or_default();
            counts[0] += 1;
            let Some(tree) = crate::parse::parse_go(&source) else {
                counts[1] += 1;
                parse_failures.push(path);
                continue;
            };
            let lowered = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                output_from_tree(&tree, &source)
            }));
            let output = match lowered {
                Ok(output) => output,
                Err(_) => {
                    counts[2] += 1;
                    producer_panics.push(path);
                    continue;
                }
            };
            counts[1] += 1;
            let relative_path = relative.to_string_lossy().replace('\\', "/");
            let file_key = (corpus.clone(), relative_path.clone());
            for gap in &output.facts.reference_enumeration_gaps {
                let site = &output.facts.sites[gap.site.index()];
                let (family, construct) = gap_construct_family(tree.root_node(), site);
                *blocker_occurrences.entry(family.to_owned()).or_default() += 1;
                if matches!(
                    family,
                    "call expression"
                        | "struct type"
                        | "field declaration"
                        | "parameter declaration"
                        | "short var declaration"
                        | "range clause"
                        | "for statement"
                        | "interface type"
                        | "import declaration"
                        | "switch case"
                ) {
                    let examples = blocker_examples.entry(family).or_default();
                    if examples.len() < 8 {
                        let line = construct.start_position().row + 1;
                        let preview = source[construct.start_byte()..construct.end_byte()]
                            .chars()
                            .take(180)
                            .collect::<String>()
                            .replace('\n', " ");
                        let mut exact_node = None;
                        let mut pending = vec![tree.root_node()];
                        while let Some(candidate) = pending.pop() {
                            if candidate.start_byte() == site.start_byte
                                && candidate.end_byte() == site.end_byte
                            {
                                exact_node = Some(candidate);
                                break;
                            }
                            if candidate.start_byte() <= site.start_byte
                                && site.end_byte <= candidate.end_byte()
                            {
                                pending.extend(named_children(candidate));
                            }
                        }
                        let gap_preview = source[site.start_byte..site.end_byte]
                            .chars()
                            .take(100)
                            .collect::<String>()
                            .replace('\n', " ");
                        examples.push(format!(
                            "{}:{} {:?} {:?} at {}:{} `{}` within {}:{} `{}`",
                            relative_path,
                            line,
                            gap.kind,
                            site.kind,
                            exact_node.map_or("range-mapped", |node| node.kind()),
                            exact_node.map_or(line, |node| node.start_position().row + 1),
                            gap_preview,
                            family,
                            line,
                            preview
                        ));
                    }
                }
                blocker_families_by_file
                    .entry(file_key.clone())
                    .or_default()
                    .insert(family.to_owned());
            }
            if output.facts.reference_enumeration_gaps.is_empty() {
                counts[3] += 1;
                if let Err(error) = ast_reference_oracle(
                    tree.root_node(),
                    &source,
                    &output.facts,
                    &path.display().to_string(),
                ) {
                    oracle_failures.push(error);
                }
            } else {
                counts[4] += 1;
            }
        }
        for (corpus, counts) in stats {
            eprintln!(
                "Go AST reference oracle {corpus}: files={} parsed={} producer_panics={} complete={} blocked={}",
                counts[0], counts[1], counts[2], counts[3], counts[4]
            );
        }
        let mut files_touched = StdHashMap::<String, usize>::new();
        let mut files_freed = StdHashMap::<String, usize>::new();
        for families in blocker_families_by_file.values() {
            for family in families {
                *files_touched.entry(family.clone()).or_default() += 1;
            }
            if let [family] = families.iter().collect::<Vec<_>>().as_slice() {
                *files_freed.entry((*family).clone()).or_default() += 1;
            }
        }
        let mut families = files_touched.keys().cloned().collect::<Vec<_>>();
        families.sort_by(|left, right| {
            files_touched[right]
                .cmp(&files_touched[left])
                .then_with(|| left.cmp(right))
        });
        eprintln!("Go AST blocker census families by occurrences: {:?}", {
            let mut ranked = blocker_occurrences.iter().collect::<Vec<_>>();
            ranked.sort_by(|(left_name, left_count), (right_name, right_count)| {
                right_count
                    .cmp(left_count)
                    .then_with(|| left_name.cmp(right_name))
            });
            ranked.into_iter().take(50).collect::<Vec<_>>()
        });
        eprintln!(
            "Go AST blocker census families by files touched / freed: {:?}",
            families
                .iter()
                .take(50)
                .map(|family| (
                    family,
                    files_touched[family],
                    files_freed.get(family).copied().unwrap_or_default()
                ))
                .collect::<Vec<_>>()
        );
        for family in [
            "call expression",
            "struct type",
            "field declaration",
            "parameter declaration",
            "short var declaration",
            "range clause",
            "for statement",
            "interface type",
            "import declaration",
            "switch case",
        ] {
            if let Some(examples) = blocker_examples.get(family) {
                eprintln!("Go AST blocker census examples {family}: {examples:?}");
            }
        }
        for path in parse_failures {
            eprintln!(
                "Go AST reference oracle parse unavailable: {}",
                path.display()
            );
        }
        for path in producer_panics {
            eprintln!("Go AST reference oracle producer panic: {}", path.display());
        }
        for failure in &oracle_failures {
            eprintln!("Go AST reference oracle missing site: {failure}");
        }
        assert!(
            oracle_failures.is_empty(),
            "{} missing reference sites",
            oracle_failures.len()
        );
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
            ResolutionGapKind::UnsupportedExpressionType,
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
        let placement_gaps = facts
            .gaps
            .iter()
            .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedPlacementBoundary)
            .collect::<Vec<_>>();
        assert_eq!(placement_gaps.len(), 1);
        assert_eq!(
            facts.sites[placement_gaps[0].site.index()].scope,
            ResolutionScopeId::new(0),
            "Go placement evidence belongs to the compilation-unit boundary"
        );
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

        assert!(!facts.gaps.iter().any(|gap| {
            gap.kind == ResolutionGapKind::UnsupportedRoute
                && facts.sites[gap.site.index()].kind == ResolutionSiteKind::UnsupportedRoute
        }));
        assert!(facts.reference_enumeration_gaps.is_empty());
        let root_scope = ResolutionScopeId::new(1);
        let expected_package_references = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.qualifier.is_none()
                    && !facts
                        .root_references
                        .iter()
                        .any(|route| route.reference == identifier.site)
            })
            .map(|identifier| identifier.site)
            .collect::<HashSet<_>>();
        assert_eq!(
            facts
                .package_references
                .iter()
                .filter(|reference| reference.root_scope == root_scope)
                .map(|reference| reference.reference)
                .collect::<HashSet<_>>(),
            expected_package_references
        );
    }

    #[test]
    fn named_imports_and_qualified_types_are_exact_while_dot_imports_keep_open_name_inventory() {
        let named = facts("package consumer\nimport dep \"example.test/provider\"\n");
        assert_eq!(named.root_imports.len(), 1);
        assert!(
            named
                .go_package_imports
                .iter()
                .any(|import| { import.kind == ResolutionGoPackageImportKind::Named })
        );
        assert!(
            !named.gaps.iter().any(|gap| {
                gap.kind == ResolutionGapKind::UnsupportedRoute
                    && named.sites[gap.site.index()].kind == ResolutionSiteKind::UnsupportedRoute
            }),
            "a named import's package path and binding kind are fully represented"
        );

        let qualified_source =
            "package consumer\nimport dep \"example.test/provider\"\ntype Value dep.Widget\n";
        let qualified = facts(qualified_source);
        let widget_position = qualified_source.find("Widget").unwrap();
        assert!(qualified.root_references.iter().any(|reference| {
            qualified.sites[reference.reference.index()].start_byte == widget_position
        }));
        assert!(
            !qualified.gaps.iter().any(|gap| {
                gap.kind == ResolutionGapKind::UnsupportedRoute
                    && qualified.sites[gap.site.index()].start_byte == widget_position
            }),
            "the structured package-root route owns qualified type resolution"
        );

        let dotted = facts("package consumer\nimport . \"example.test/provider\"\n");
        assert!(
            dotted
                .root_import_kinds
                .iter()
                .any(|import| { import.kind == ResolutionRootImportKind::Glob })
        );
        assert!(!dotted.gaps.iter().any(|gap| {
            gap.kind == ResolutionGapKind::UnsupportedRoute
                && dotted.sites[gap.site.index()].kind == ResolutionSiteKind::UnsupportedRoute
        }));
        assert!(dotted.reference_enumeration_gaps.is_empty());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "14ad4f50691e: Go local types activate at the declaration name"
    )]
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
    fn untyped_and_implicit_constants_do_not_fabricate_types_or_initializers() {
        let source = r#"package p
        const (
            Text = "text"
            Repeated
            Number = 42
            Truth = true
            Rune = 'r'
            Sequence = iota
            Calculated = 1 + 2
            Mixed = 1 + 2.0
        )
        "#;
        let facts = facts(source);
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
            assert!(!facts.gaps.iter().any(|gap| {
                gap.site == site
                    && matches!(
                        gap.kind,
                        ResolutionGapKind::InferredType
                            | ResolutionGapKind::UnsupportedExpressionType
                    )
            }));
            assert!(facts.declaration_type_slots.iter().any(|slot| {
                slot.declaration == site && slot.role == DeclarationTypeRole::Value
            }));
            let assignments = facts
                .type_slots
                .iter()
                .filter(|slot| {
                    slot.site == site && slot.role == ResolutionTypeSlotRole::AssignmentValue
                })
                .collect::<Vec<_>>();
            assert_eq!(assignments.len(), 1, "{spelling}");
        }
        assert!(
            facts
                .intrinsic_type_seeds
                .iter()
                .any(|seed| { name(&facts, seed.name) == "untyped int" })
        );
        let mixed_start = source.find("1 + 2.0").expect("mixed expression source");
        let mixed_value = facts
            .sites
            .iter()
            .find(|site| {
                site.kind == ResolutionSiteKind::BinaryExpression && site.start_byte == mixed_start
            })
            .expect("mixed constant arithmetic retains its expression site");
        assert!(facts.gaps.iter().any(|gap| {
            gap.site == mixed_value.id && gap.kind == ResolutionGapKind::UnsupportedExpressionType
        }));
    }

    #[test]
    fn const_spec_inheritance_keeps_declared_type_and_iota_expression() {
        let source = r#"package p
        type EvictionReason int
        const (
            Deleted EvictionReason = iota + 1
            CapacityReached
            Expired
        )
        "#;
        let facts = facts(source);
        for spelling in ["Deleted", "CapacityReached", "Expired"] {
            let site = declaration(&facts, spelling);
            assert!(facts.declaration_type_slots.iter().any(|slot| {
                slot.declaration == site && slot.role == DeclarationTypeRole::Value
            }));
            assert!(!facts.gaps.iter().any(|gap| {
                gap.site == site
                    && matches!(
                        gap.kind,
                        ResolutionGapKind::InferredType
                            | ResolutionGapKind::UnsupportedExpressionType
                    )
            }));
        }
        let iota_start = source.find("iota").expect("iota constant expression");
        assert!(facts.intrinsic_type_seeds.iter().any(|seed| {
            facts.sites[facts.type_slots[seed.output.index()].site.index()].start_byte == iota_start
                && name(&facts, seed.name) == "untyped int"
        }));
    }

    #[test]
    fn common_go_expression_types_preserve_untyped_and_defaulted_constants() {
        let source = r#"package p
func use(x int, y int, text string, enabled bool, pointer *int) {
    summed := x + y
    added := x + 1
    less := x < 1
    joined := text + "!"
    both := enabled && true
    either := enabled || false
    negated := -x
    positive := +x
    complement := ^x
    inverted := !enabled
    pointer = nil
    defaulted := 1
    const Exact = 1 + 2
    const Mixed = 1 + 2.0
    _ = []any{summed, added, less, joined, both, either, negated, positive, complement, inverted, pointer, defaulted, Exact, Mixed}
}
"#;
        let facts = facts(source);

        for (expression, expected) in [
            ("x + y", "int"),
            ("x + 1", "int"),
            ("x < 1", "bool"),
            ("text + \"!\"", "string"),
            ("enabled && true", "bool"),
            ("enabled || false", "bool"),
            ("-x", "int"),
            ("+x", "int"),
            ("^x", "int"),
            ("!enabled", "bool"),
        ] {
            let start = source.find(expression).expect("expression in fixture");
            let site = facts
                .sites
                .iter()
                .find(|site| {
                    matches!(
                        site.kind,
                        ResolutionSiteKind::BinaryExpression | ResolutionSiteKind::UnaryExpression
                    ) && site.start_byte == start
                })
                .unwrap_or_else(|| panic!("missing expression site for {expression}"));
            let output = facts
                .type_slots
                .iter()
                .find(|slot| {
                    slot.site == site.id && slot.role == ResolutionTypeSlotRole::ExpressionValue
                })
                .unwrap_or_else(|| panic!("missing expression output slot for {expression}"));
            let has_exact_seed = facts
                .intrinsic_type_seeds
                .iter()
                .any(|seed| seed.output == output.id && name(&facts, seed.name) == expected);
            let has_operand_result = facts.type_transfers.iter().any(|transfer| {
                transfer.output == output.id
                    && transfer.kind == ResolutionTypeTransferKind::ExpressionResult
            });
            assert!(
                has_exact_seed || has_operand_result,
                "{expression} must have a structured {expected} result type"
            );
        }

        let nil_start = source.find("nil").expect("contextual nil expression");
        let nil_site = facts
            .sites
            .iter()
            .find(|site| site.start_byte == nil_start)
            .expect("nil expression site");
        let nil_slot = facts
            .type_slots
            .iter()
            .find(|slot| {
                slot.site == nil_site.id && slot.role == ResolutionTypeSlotRole::ExpressionValue
            })
            .expect("nil expression value slot");
        assert!(facts.type_transfers.iter().any(|transfer| {
            transfer.output == nil_slot.id
                && transfer.kind == ResolutionTypeTransferKind::Contextual
        }));
        assert!(!facts.gaps.iter().any(|gap| {
            gap.site == nil_site.id && gap.kind == ResolutionGapKind::UnsupportedExpressionType
        }));

        let defaulted = declaration(&facts, "defaulted");
        assert!(facts.intrinsic_type_seeds.iter().any(|seed| {
            facts.type_slots[seed.output.index()].site == defaulted
                && name(&facts, seed.name) == "int"
        }));
        let exact = declaration(&facts, "Exact");
        let exact_initializer_start = source.find("1 + 2").expect("untyped constant initializer");
        let exact_initializer = facts
            .sites
            .iter()
            .find(|site| {
                site.kind == ResolutionSiteKind::BinaryExpression
                    && site.start_byte == exact_initializer_start
            })
            .expect("untyped constant initializer site");
        assert!(facts.intrinsic_type_seeds.iter().any(|seed| {
            facts.type_slots[seed.output.index()].site == exact_initializer.id
                && name(&facts, seed.name) == "untyped int"
        }));
        assert!(facts.type_transfers.iter().any(|transfer| {
            transfer.output == declaration_slot(&facts, exact, DeclarationTypeRole::Value)
                && transfer.kind == ResolutionTypeTransferKind::Initialization
                && facts.type_slots[transfer.input.index()].site == exact_initializer.id
        }));

        let mixed_start = source.find("1 + 2.0").expect("mixed constant expression");
        let mixed = facts
            .sites
            .iter()
            .find(|site| {
                site.kind == ResolutionSiteKind::BinaryExpression && site.start_byte == mixed_start
            })
            .expect("mixed constant expression site");
        assert!(facts.gaps.iter().any(|gap| {
            gap.site == mixed.id && gap.kind == ResolutionGapKind::UnsupportedExpressionType
        }));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "2ae7c404faaa: named and blank import routes no longer carry false unsupported-route gaps"
    )]
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
            !facts
                .gaps
                .iter()
                .any(|gap| gap.kind == ResolutionGapKind::UnsupportedRoute),
            "default, named, and blank imports are exactly represented as structured routes"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "2ae7c404faaa: package-qualified type references no longer carry false unsupported-route gaps"
    )]
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
                terminal.namespace == ResolutionNamespace::Callable && !is_call_callee;
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

    fn name(facts: &FileResolutionFacts, id: ResolutionNameId) -> &str {
        facts.name(id)
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
                    facts
                        .type_transfers
                        .iter()
                        .any(|transfer| transfer.output == output)
                );
                let formal = facts
                    .binders
                    .iter()
                    .find(|binder| {
                        binder.kind == ResolutionBinderKind::Type
                            && facts.scopes[binder.scope.index()].owner == Some(declaration)
                    })
                    .expect("generic alias type parameter binder");
                assert!(facts.gaps.iter().any(|gap| {
                    gap.site == formal.declaration
                        && gap.kind == ResolutionGapKind::UnsupportedExpressionType
                }));
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
                    && gap.kind == ResolutionGapKind::UnsupportedExpressionType));
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
    #[brokk_bifrost_test_macros::hardwon(
        "#4284: a Go map-index call must not bind its result to the map variable"
    )]
    fn multi_result_short_var_with_computed_callee_keeps_slots_without_projection() {
        // #4284: an IIFE, factory call, or index callee is an
        // UnsupportedExpression site with no positioned identifier, so the
        // extra result slots must not publish projections that name it.
        let sources = [
            "package p\nfunc f() { v, err := func() (int, error) { return 0, nil }(); _, _ = v, err }",
            "package p\nfunc mk() func() (int, error) { return nil }\nfunc f() { a, b := mk()(); _, _ = a, b }",
            "package p\nvar m = map[string]func() (int, error){}\nfunc f(k string) { a, b := m[k](); _, _ = a, b }",
            "package p\nfunc f(k string) { a, b := m[k](); _, _ = a, b }\nvar m = map[string]func() (int, error){}",
        ];
        for source in sources {
            let facts = facts(source);
            let computed_calls = facts
                .calls
                .iter()
                .filter(|call| {
                    facts.sites[call.callee.index()].kind
                        == ResolutionSiteKind::UnsupportedExpression
                })
                .collect::<Vec<_>>();
            assert_eq!(computed_calls.len(), 1, "one computed callee: {source}");
            let call = computed_calls[0];
            assert_eq!(
                call.extra_result_slots.len(),
                1,
                "the computed callee call keeps its extra result slots: {source}"
            );
            assert!(
                facts
                    .binding_projections
                    .iter()
                    .all(|projection| projection.reference != call.callee),
                "no binding projection names the unpositioned callee: {source}"
            );
        }

        let positioned = facts(
            "package p\nfunc g() (int, error) { return 0, nil }\nfunc f() { a, b := g(); _, _ = a, b }",
        );
        let call = positioned
            .calls
            .iter()
            .find(|call| !call.extra_result_slots.is_empty())
            .expect("positioned multi-result call");
        // A later result is projected under its own kind, so it never takes the
        // first result's declared type; the first result keeps the callable kind.
        assert!(positioned.binding_projections.iter().any(|projection| {
            projection.reference == call.callee
                && projection.output == call.extra_result_slots[0]
                && projection.kind == BindingProjectionKind::TargetCallableLaterResultType
        }));
        assert!(positioned.binding_projections.iter().any(|projection| {
            projection.reference == call.callee
                && projection.output == call.result
                && projection.kind == BindingProjectionKind::TargetCallableResultType
        }));
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
        assert!(
            !facts
                .intrinsic_type_seeds
                .iter()
                .any(|seed| seed.output == assignment.input)
        );
        assert!(facts.type_transfers.iter().any(|transfer| {
            transfer.input == y_declared
                && transfer.output == assignment.input
                && transfer.kind == ResolutionTypeTransferKind::Contextual
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
    #[brokk_bifrost_test_macros::hardwon(
        "81484c220124: Short declarations in switch/select clauses get distinct case scopes, so binders do not leak between cases."
    )]
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
    fn nested_switch_and_select_defaults_do_not_inherit_the_type_switch_alias() {
        // #4285: a default case nested in an expression switch or select
        // belongs to that statement, not to the enclosing type switch.
        let source = r#"package p

func f(v any, name string) {
    switch t := v.(type) {
    case int:
        switch name {
        default:
            _ = t
        }
        select {
        default:
        }
    }
}
"#;
        let facts = facts(source);
        let declarations = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && name(&facts, identifier.name) == "t"
            })
            .collect::<Vec<_>>();
        assert_eq!(declarations.len(), 1, "only the outer case binds the alias");
        let binder = facts
            .binders
            .iter()
            .find(|binder| binder.declaration == declarations[0].site)
            .expect("the alias has a clause binder");
        let reference = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && name(&facts, identifier.name) == "t"
            })
            .expect("the nested default references the alias");
        let reference_site = facts.sites[reference.site.index()];
        assert!(
            binder.activation_start <= reference_site.start_byte
                && reference_site.end_byte <= binder.activation_end,
            "the alias binder covers the nested default reference"
        );
        let mut scope = reference_site.scope;
        while scope != binder.scope {
            scope = facts.scopes[scope.index()]
                .parent
                .expect("the reference scope descends from the alias case scope");
        }

        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("Go grammar");
        let tree = parser.parse(source, None).expect("Go tree");
        let mut nested_defaults = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "default_case" {
                nested_defaults.push(node);
            }
            stack.extend(named_children(node));
        }
        assert_eq!(nested_defaults.len(), 2);
        for default in nested_defaults {
            assert!(
                facts.scopes.iter().any(|scope| {
                    scope.start_byte == default.start_byte() && scope.end_byte == default.end_byte()
                }),
                "the nested default case scope starts at its own node"
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "81484c220124: A composite-literal field receiver carries a runtime value type through member access."
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "81484c220124: A local value shadowing a type spelling keeps the call in the value namespace."
    )]
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
    #[brokk_bifrost_test_macros::hardwon(
        "81484c220124: The Go builtin max call stays explicitly incomplete when no sound result transfer is available."
    )]
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
    fn anonymous_types_own_type_bodies_under_unmodeled_container_types() {
        let source = concat!(
            "package p\n",
            "type M map[string]struct { Hidden int }\n",
            "type S []struct { Hidden int }\n",
            "type F func() interface { Hidden() }\n",
        );
        let facts = facts(source);

        let field_owners = facts
            .member_owners
            .iter()
            .filter(|owner| owner.kind == ResolutionMemberKind::Field)
            .map(|owner| owner.owner)
            .collect::<Vec<_>>();
        assert_eq!(field_owners.len(), 2);
        assert_ne!(field_owners[0], field_owners[1]);
        assert_eq!(
            facts
                .member_owners
                .iter()
                .filter(|owner| owner.kind == ResolutionMemberKind::Method)
                .count(),
            1,
            "the inline interface method also has its own owner"
        );
        for owner in field_owners {
            let declaration = &facts.sites[owner.index()];
            assert_eq!(declaration.kind, ResolutionSiteKind::TypeDeclaration);
            assert!(facts.identifiers.iter().any(|identifier| {
                identifier.site == owner
                    && identifier.role == ResolutionIdentifierRole::Declaration
                    && name(&facts, identifier.name).starts_with("$anon$")
            }));
            assert!(facts.scopes.iter().any(|scope| {
                scope.kind == ResolutionScopeKind::TypeBody
                    && scope.owner == Some(owner)
                    && scope.start_byte == declaration.start_byte
                    && scope.end_byte == declaration.end_byte
            }));
            assert!(facts.gaps.iter().any(|gap| {
                gap.site == owner && gap.kind == ResolutionGapKind::UnsupportedExpressionType
            }));
        }
        assert!(!facts.gaps.iter().any(|gap| {
            gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder
                && facts.sites[gap.site.index()].kind == ResolutionSiteKind::UnsupportedDeclaration
        }));
    }

    #[test]
    fn anonymous_struct_fields_match_the_independent_reference_oracle() {
        let source = concat!(
            "package p\n",
            "var value struct { pkg.Embedded; Field pkg.Value }\n",
            "func iterate() { for range []struct { Item pkg.Value }{{}} {} }\n",
        );
        let tree = crate::parse::parse_go(source).expect("anonymous struct fixture tree");
        let output = output_from_tree(&tree, source);
        assert!(
            output.facts.reference_enumeration_gaps.is_empty(),
            "anonymous struct fields are all lowered: {:?}",
            output.facts.reference_enumeration_gaps
        );
        ast_reference_oracle(
            tree.root_node(),
            source,
            &output.facts,
            "anonymous struct fixture",
        )
        .expect("anonymous struct AST references have exact sites");
        assert_eq!(output.facts.member_owners.len(), 3);
        assert_eq!(
            output.facts.member_owners[0].owner,
            output.facts.member_owners[1].owner
        );
        assert_ne!(
            output.facts.member_owners[0].owner,
            output.facts.member_owners[2].owner
        );
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
    #[brokk_bifrost_test_macros::hardwon(
        "81484c220124: Member lowering retains the independently known explicit composite-literal type."
    )]
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
    fn elided_nested_map_literal_keeps_key_as_value_reference() {
        let source = r#"package p

const NestedKey = "nested"
type Item struct { NestedKey string }
var maps = map[string]map[string]string{"outer": {NestedKey: "value"}}
var items = map[string]Item{"outer": {NestedKey: "field"}}
"#;
        let facts = facts(source);
        for (spelling, expected_kind) in [
            ("NestedKey: \"value\"", ResolutionSiteKind::ValueReference),
            (
                "NestedKey: \"field\"",
                ResolutionSiteKind::CompositeLiteralKeyReference,
            ),
        ] {
            let start = source.find(spelling).expect("keyed entry");
            let reference = facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Reference
                        && name(&facts, identifier.name) == "NestedKey"
                        && facts.sites[identifier.site.index()].start_byte == start
                })
                .expect("nested literal key reference");
            assert_eq!(facts.sites[reference.site.index()].kind, expected_kind);
        }
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
    #[hardwon("#2771: named Go method receiver calls were counted as external usages")]
    fn method_receiver_origin_respects_lexical_shadowing() {
        let facts = facts(
            r#"package p
type Foo struct{}
func (f *Foo) target() {}
func (f *Foo) caller(other *Foo) {
    f.target()
    other.target()
    {
        f := other
        f.target()
    }
    func(f *Foo) { f.target() }(other)
    f.target()
}
"#,
        );
        let origins = facts
            .callable_receiver_origins
            .iter()
            .map(|fact| fact.origin)
            .collect::<Vec<_>>();
        assert_eq!(
            origins,
            vec![
                ResolutionCallableReceiverOrigin::CurrentInstance,
                ResolutionCallableReceiverOrigin::ExplicitExpression,
                ResolutionCallableReceiverOrigin::ExplicitExpression,
                ResolutionCallableReceiverOrigin::ExplicitExpression,
                ResolutionCallableReceiverOrigin::CurrentInstance,
            ],
        );
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
    fn generic_qualified_call_callee_remains_a_package_route() {
        let source = r#"package consumer

import lib "example.test/transitive/lib"

func caller() { _ = lib.New[int]() }
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("Go grammar");
        let tree = parser.parse(source, None).expect("Go tree");
        let facts = extract_go_resolution_facts(tree.root_node(), source);
        assert_eq!(facts.calls.len(), 1, "{facts:#?}");
        let call = &facts.calls[0];
        let callee = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.site == call.callee
                    && identifier.role == ResolutionIdentifierRole::Reference
            })
            .expect("a generic package call keeps its terminal reference");
        assert_eq!(name(&facts, callee.name), "New");
        assert_eq!(callee.namespace, ResolutionNamespace::Callable);
        let route = facts
            .root_references
            .iter()
            .find(|route| route.reference == call.callee)
            .expect("a generic package call keeps its qualified root route");
        let prefix = route
            .prefix_reference
            .expect("a generic package route has its import qualifier");
        let prefix_identifier = facts
            .identifiers
            .iter()
            .find(|identifier| identifier.site == prefix)
            .expect("a generic package route has a positioned qualifier");
        assert_eq!(name(&facts, prefix_identifier.name), "lib");
        assert!(facts.reference_enumeration_gaps.is_empty(), "{facts:#?}");
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
    fn reference_owners_in_nested_anonymous_struct_fields_follow_named_owner() {
        let source = r#"package p

type Item[K comparable, V any] struct{}
type EvictionReason int

type Cache[K comparable, V any] struct {
    events struct {
        insertion struct {
            fns map[uint64]func(*Item[K, V])
        }
        eviction struct {
            fns map[uint64]func(EvictionReason, *Item[K, V])
        }
    }
}
"#;
        let facts = facts(source);
        let cache = declaration(&facts, "Cache");
        let expected_names = ["Item", "EvictionReason"];
        let references = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && expected_names.contains(&name(&facts, identifier.name))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            references.len(),
            3,
            "the callback signatures retain all type uses"
        );
        assert!(
            references
                .iter()
                .all(|reference| { reference_owner(&facts, reference.site) == Some(Some(cache)) }),
            "nested anonymous storage type references belong to Cache: {references:#?}"
        );
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
    fn generic_type_application_keeps_its_base_reference_exact() {
        let source = r#"package p

type Item[T any] struct{}
func New[T any]() Item[T] { return Item[T]{} }
"#;
        let facts = facts(source);
        let base_start = source
            .find("func New")
            .and_then(|start| source[start..].find("Item[T]").map(|offset| start + offset))
            .expect("generic result type argument clause");
        let application_start = base_start + "Item".len();
        let application_end = application_start + "[T]".len();
        let base_reference = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && name(&facts, identifier.name) == "Item"
                    && facts.sites[identifier.site.index()].start_byte == base_start
            })
            .expect("generic result keeps the base type reference")
            .site;
        assert!(
            !facts.gaps.iter().any(|gap| gap.site == base_reference),
            "open application semantics must not poison the named base reference: {facts:#?}"
        );
        let application = facts
            .sites
            .iter()
            .find(|site| {
                site.kind == ResolutionSiteKind::TypeReference
                    && site.start_byte == application_start
                    && site.end_byte == application_end
            })
            .expect("generic application has a structured frontier");
        assert!(facts.gaps.contains(&ResolutionGapFact {
            site: application.id,
            kind: ResolutionGapKind::UnsupportedExpressionType,
        }));
        assert!(facts.reference_enumeration_gaps.is_empty());
    }

    #[test]
    fn generic_navigation_publishes_formals_receiver_arguments_and_call_arguments() {
        let source = r#"package p

type Pair[A, B any] struct { First A; Second B }
type Box[T any] struct { Value T }
func Identity[T any](value T) T { return value }
func (pair *Pair[Key, Value]) Get() (Key, Value) { return }
func use(pair Pair[int, Box[string]]) {
    _ = Identity[int](1)
}
"#;
        let tree = crate::parse::parse_go(source).expect("Go tree");
        let facts = extract_go_resolution_facts(tree.root_node(), source);
        assert!(
            facts.reference_enumeration_gaps.is_empty(),
            "generic navigation fixture has a complete reference inventory: {:?}",
            facts
                .reference_enumeration_gaps
                .iter()
                .map(|gap| {
                    let site = facts.sites[gap.site.index()];
                    (
                        gap.kind,
                        site.kind,
                        site.start_byte,
                        site.end_byte,
                        &source[site.start_byte..site.end_byte],
                    )
                })
                .collect::<Vec<_>>()
        );
        ast_reference_oracle(tree.root_node(), source, &facts, "generic-navigation.go")
            .expect("independent tree-sitter reference oracle");

        let pair = declaration(&facts, "Pair");
        let mut pending = vec![tree.root_node()];
        let pair_struct_start = loop {
            let node = pending.pop().expect("Pair has a type declaration AST node");
            if node
                .child_by_field_name("name")
                .is_some_and(|name| name.utf8_text(source.as_bytes()).ok() == Some("Pair"))
                && node
                    .child_by_field_name("type")
                    .is_some_and(|type_node| type_node.kind() == "struct_type")
            {
                break node
                    .child_by_field_name("type")
                    .expect("Pair has a type node")
                    .start_byte();
            }
            pending.extend(named_children(node));
        };
        let pair_body_scope = facts
            .scopes
            .iter()
            .find(|scope| scope.kind == ResolutionScopeKind::TypeBody && scope.owner == Some(pair))
            .expect("Pair owns a type-body scope");
        assert_eq!(
            pair_body_scope.start_byte, pair_struct_start,
            "a generic struct body enters its parent scope after formal activation"
        );
        let formal_rows = |owner| {
            let mut rows = facts
                .generic_formals
                .iter()
                .filter(|formal| formal.owner == owner)
                .copied()
                .collect::<Vec<_>>();
            rows.sort_unstable_by_key(|formal| formal.ordinal);
            rows.into_iter()
                .map(|formal| {
                    let site = facts.sites[formal.parameter.index()];
                    (
                        formal.ordinal,
                        source[site.start_byte..site.end_byte].to_owned(),
                        site.start_byte,
                        site.end_byte,
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            formal_rows(pair)
                .into_iter()
                .map(|(ordinal, name, _, _)| (ordinal, name))
                .collect::<Vec<_>>(),
            [(0, "A".to_owned()), (1, "B".to_owned())],
            "generic type formals retain declaration identity and source order"
        );
        let pair_formals = facts
            .binders
            .iter()
            .filter(|binder| {
                binder.kind == ResolutionBinderKind::Type
                    && facts.scopes[binder.scope.index()].owner == Some(pair)
            })
            .map(|binder| {
                let site = facts.sites[binder.declaration.index()];
                (
                    site.start_byte,
                    source[site.start_byte..site.end_byte].to_owned(),
                )
            })
            .collect::<Vec<_>>();
        let mut pair_formals = pair_formals;
        pair_formals.sort_by_key(|(start, _)| *start);
        assert_eq!(
            pair_formals
                .into_iter()
                .map(|(_, name)| name)
                .collect::<Vec<_>>(),
            ["A", "B"]
        );

        let box_type = declaration(&facts, "Box");
        let box_formal = facts
            .generic_formals
            .iter()
            .find(|formal| formal.owner == box_type)
            .expect("Box has its T formal");
        let field_type_start = source.find("Value T").unwrap() + "Value ".len();
        let field_type_reference = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && facts.sites[identifier.site.index()].start_byte == field_type_start
            })
            .expect("Box.Value's T type is a reference site");
        let field_scope = facts.sites[field_type_reference.site.index()].scope;
        let formal_scope = facts.sites[box_formal.parameter.index()].scope;
        let mut scope = Some(field_scope);
        let mut formal_is_enclosing = false;
        while let Some(current) = scope {
            if current == formal_scope {
                formal_is_enclosing = true;
                break;
            }
            scope = facts.scopes[current.index()].parent;
        }
        assert!(
            formal_is_enclosing,
            "the type reference's lexical scope chain includes its generic formal scope: reference={field_type_reference:?}, formal={box_formal:?}, scopes={:?}",
            facts.scopes
        );
        assert_eq!(field_type_reference.namespace, ResolutionNamespace::Type);
        let formal_binder = facts
            .binders
            .iter()
            .find(|binder| binder.declaration == box_formal.parameter)
            .expect("Box.T is a lexical type binder");
        assert!(
            formal_binder.activation_start <= field_type_start,
            "Box.T is active at the field type reference: {formal_binder:?}, reference={field_type_reference:?}"
        );

        let get = declaration(&facts, "Get");
        let receiver_formal_rows = formal_rows(get);
        assert_eq!(
            receiver_formal_rows
                .iter()
                .map(|(ordinal, name, _, _)| (*ordinal, name.as_str()))
                .collect::<Vec<_>>(),
            [(0, "Key"), (1, "Value")],
            "renamed receiver formals map by ordinal, not spelling"
        );
        for (_, name, start, end) in &receiver_formal_rows {
            assert_eq!(&source[*start..*end], name);
        }
        let receiver_formals = facts
            .binders
            .iter()
            .filter(|binder| {
                binder.kind == ResolutionBinderKind::Type
                    && facts.scopes[binder.scope.index()].owner == Some(get)
            })
            .map(|binder| {
                let site = facts.sites[binder.declaration.index()];
                (
                    site.start_byte,
                    source[site.start_byte..site.end_byte].to_owned(),
                )
            })
            .collect::<Vec<_>>();
        let mut receiver_formals = receiver_formals;
        receiver_formals.sort_by_key(|(start, _)| *start);
        assert_eq!(
            receiver_formals
                .into_iter()
                .map(|(_, name)| name)
                .collect::<Vec<_>>(),
            ["Key", "Value"]
        );

        let mut pending = vec![tree.root_node()];
        let get_node = loop {
            let node = pending
                .pop()
                .expect("Get has a method declaration AST node");
            if node
                .child_by_field_name("name")
                .is_some_and(|name| name.utf8_text(source.as_bytes()).ok() == Some("Get"))
            {
                break node;
            }
            pending.extend(named_children(node));
        };
        let result = get_node
            .child_by_field_name("result")
            .expect("Get has a result tuple");
        let receiver_result_type = named_children(result)
            .into_iter()
            .filter_map(|parameter| parameter.child_by_field_name("type"))
            .find(|type_node| type_node.utf8_text(source.as_bytes()).ok() == Some("Value"))
            .expect("Get's second result refers to its renamed receiver formal");
        let receiver_result_start = receiver_result_type.start_byte();
        let receiver_result_reference = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && facts.sites[identifier.site.index()].start_byte == receiver_result_start
            })
            .expect("Get's receiver-formal result is a type-reference site");
        let receiver_value_formal = facts
            .generic_formals
            .iter()
            .find(|formal| {
                formal.owner == get
                    && &source[facts.sites[formal.parameter.index()].start_byte
                        ..facts.sites[formal.parameter.index()].end_byte]
                        == "Value"
            })
            .expect("Get owns a positional Value receiver formal");
        let receiver_value_binder = facts
            .binders
            .iter()
            .find(|binder| binder.declaration == receiver_value_formal.parameter)
            .expect("Get's Value receiver formal has a lexical type binder");
        assert_eq!(
            facts.sites[receiver_result_reference.site.index()].scope,
            receiver_value_binder.scope,
            "the method result and renamed receiver formal share a lexical scope"
        );
        assert!(
            receiver_value_binder.activation_start <= receiver_result_start
                && receiver_result_type.end_byte() <= receiver_value_binder.activation_end,
            "the receiver formal is active at the method result type: {receiver_value_binder:?}"
        );

        let receiver_base_start = source.find("Pair[Key, Value]").unwrap();
        let receiver_owner = facts
            .declared_type_arguments
            .iter()
            .find(|argument| {
                let owner = facts.type_slots[argument.owner.index()];
                facts.sites[owner.site.index()].start_byte == receiver_base_start
            })
            .expect("receiver generic base has positional arguments")
            .owner;
        let mut receiver_arguments = facts
            .declared_type_arguments
            .iter()
            .filter(|argument| argument.owner == receiver_owner)
            .copied()
            .collect::<Vec<_>>();
        receiver_arguments.sort_by_key(|argument| argument.ordinal);
        assert_eq!(
            receiver_arguments
                .iter()
                .map(|argument| argument.ordinal)
                .collect::<Vec<_>>(),
            [0, 1]
        );
        assert_eq!(
            receiver_arguments
                .iter()
                .map(|argument| {
                    let slot = facts.type_slots[argument.argument.index()];
                    let site = facts.sites[slot.site.index()];
                    source[site.start_byte..site.end_byte].to_owned()
                })
                .collect::<Vec<_>>(),
            ["Key", "Value"]
        );

        let application_start = source.find("Pair[int, Box[string]]").unwrap();
        let application_owner = facts
            .declared_type_arguments
            .iter()
            .find(|argument| {
                let owner = facts.type_slots[argument.owner.index()];
                facts.sites[owner.site.index()].start_byte == application_start
            })
            .expect("nested generic application has positional arguments")
            .owner;
        let mut application_arguments = facts
            .declared_type_arguments
            .iter()
            .filter(|argument| argument.owner == application_owner)
            .copied()
            .collect::<Vec<_>>();
        application_arguments.sort_by_key(|argument| argument.ordinal);
        assert_eq!(
            application_arguments
                .iter()
                .map(|argument| argument.ordinal)
                .collect::<Vec<_>>(),
            [0, 1]
        );
        assert_eq!(
            application_arguments
                .iter()
                .map(|argument| {
                    let slot = facts.type_slots[argument.argument.index()];
                    let site = facts.sites[slot.site.index()];
                    source[site.start_byte..site.end_byte].to_owned()
                })
                .collect::<Vec<_>>(),
            ["int", "Box"]
        );
        let nested_owner = facts
            .declared_type_arguments
            .iter()
            .find(|argument| {
                let owner = facts.type_slots[argument.owner.index()];
                facts.sites[owner.site.index()].start_byte == source.find("Box[string]").unwrap()
            })
            .expect("nested Box application has an argument")
            .owner;
        let nested_argument = facts
            .declared_type_arguments
            .iter()
            .find(|argument| argument.owner == nested_owner)
            .expect("nested Box argument row");
        assert_eq!(nested_argument.ordinal, 0);
        let nested_site = facts.type_slots[nested_argument.argument.index()].site;
        let nested_site = facts.sites[nested_site.index()];
        assert_eq!(
            &source[nested_site.start_byte..nested_site.end_byte],
            "string"
        );

        let call = facts
            .calls
            .iter()
            .find(|call| call.explicit_type_argument_count > 0)
            .unwrap_or_else(|| {
                let mut pending = vec![tree.root_node()];
                let mut call_nodes = Vec::new();
                while let Some(node) = pending.pop() {
                    if matches!(
                        node.kind(),
                        "call_expression" | "type_instantiation_expression"
                    ) {
                        call_nodes.push((
                            node.kind(),
                            &source[node.start_byte()..node.end_byte()],
                            node.child_by_field_name("function")
                                .map(|child| child.kind()),
                            node.child_by_field_name("type_arguments")
                                .map(|child| child.kind()),
                        ));
                    }
                    pending.extend(named_children(node));
                }
                panic!(
                    "explicitly instantiated generic call: {:?}; syntax: {call_nodes:?}; tree: {}",
                    facts.calls,
                    tree.root_node().to_sexp()
                )
            });
        assert_eq!(call.explicit_type_argument_count, 1);
        let explicit_application_start = source.find("Identity[int]").unwrap();
        let callee_site = facts.sites[call.callee.index()];
        assert_eq!(
            callee_site.start_byte, explicit_application_start,
            "the generic call's callee reference starts at its identifier"
        );
        let references_at_callee = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && facts.sites[identifier.site.index()].start_byte == explicit_application_start
                    && facts.sites[identifier.site.index()].end_byte
                        == explicit_application_start + "Identity".len()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            references_at_callee.len(),
            2,
            "ambiguous generic instantiation publishes type and callable alternatives"
        );
        assert!(references_at_callee.iter().any(|identifier| {
            facts.sites[identifier.site.index()].kind == ResolutionSiteKind::TypeReference
                && identifier.namespace == ResolutionNamespace::Type
        }));
        assert!(references_at_callee.iter().any(|identifier| {
            identifier.site == call.callee
                && facts.sites[identifier.site.index()].kind
                    == ResolutionSiteKind::CallableReference
                && identifier.namespace == ResolutionNamespace::TypeOrValue
        }));
        let call_type_arguments = facts
            .call_type_arguments
            .iter()
            .filter(|argument| argument.call == call.call)
            .collect::<Vec<_>>();
        let [argument] = call_type_arguments.as_slice() else {
            panic!(
                "one call type argument row: {:?}",
                facts.call_type_arguments
            );
        };
        assert_eq!(argument.ordinal, 0);
        let argument_node = source
            .find("Identity[int]")
            .map(|start| start + "Identity[".len())
            .expect("explicit call argument source range");
        let value = facts.type_slots[argument.value.index()];
        assert_eq!(value.site, call.call);
        assert_eq!(value.role, ResolutionTypeSlotRole::DeclaredValue);
        let type_input = facts
            .type_transfers
            .iter()
            .find(|transfer| {
                transfer.output == argument.value
                    && transfer.kind == ResolutionTypeTransferKind::DeclaredType
            })
            .expect("call type argument has a declared type transfer");
        let type_site = facts.type_slots[type_input.input.index()].site;
        let type_site = facts.sites[type_site.index()];
        assert_eq!(&source[type_site.start_byte..type_site.end_byte], "int");
        assert_eq!(type_site.start_byte, argument_node);
        assert!(
            facts.declared_type_arguments.iter().all(|argument| {
                let owner = facts.type_slots[argument.owner.index()];
                facts.sites[owner.site.index()].start_byte != explicit_application_start
            }),
            "explicit call arguments use call_type_arguments only"
        );
    }

    #[test]
    fn qualified_explicit_generic_call_keeps_its_receiver_at_the_call_site() {
        let source = "package p\nimport model \"example.test/model\"\nfunc use() { model.Identity[int](1) }\n";
        let tree = crate::parse::parse_go(source).expect("Go tree");
        let facts = extract_go_resolution_facts(tree.root_node(), source);
        assert!(facts.reference_enumeration_gaps.is_empty());
        ast_reference_oracle(
            tree.root_node(),
            source,
            &facts,
            "qualified-generic-call.go",
        )
        .expect("independent tree-sitter reference oracle");

        let call = facts
            .calls
            .iter()
            .find(|call| call.explicit_type_argument_count == 1)
            .expect("explicit generic call fact");
        let receiver = call.receiver.expect("qualified call receiver");
        assert_eq!(facts.type_slots[receiver.index()].site, call.call);
        assert_eq!(
            facts.type_slots[receiver.index()].role,
            ResolutionTypeSlotRole::Receiver
        );
        assert!(facts.type_transfers.iter().any(|transfer| {
            transfer.input != receiver
                && transfer.output == receiver
                && transfer.kind == ResolutionTypeTransferKind::Receiver
        }));
        let type_arguments = facts
            .call_type_arguments
            .iter()
            .filter(|argument| argument.call == call.call)
            .collect::<Vec<_>>();
        assert_eq!(type_arguments.len(), 1);
        assert_eq!(type_arguments[0].ordinal, 0);
        let type_input = facts
            .type_transfers
            .iter()
            .find(|transfer| {
                transfer.output == type_arguments[0].value
                    && transfer.kind == ResolutionTypeTransferKind::DeclaredType
            })
            .expect("call type argument has a declared type transfer")
            .input;
        let argument_site = facts.type_slots[type_input.index()].site;
        let argument_site = facts.sites[argument_site.index()];
        assert_eq!(
            &source[argument_site.start_byte..argument_site.end_byte],
            "int"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "0323b3104bef: Preserves parameter/result ordinals and receiver exclusion while leaving unnamed or variadic bindings explicit."
    )]
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
    fn function_typed_values_publish_ordered_parameter_and_result_signatures() {
        let source = r#"package p
type Result struct{}
type Holder struct {
    Check func(first int, values ...string) (Result, error)
    Zero func()
}
func use(function func(arg int) Result) { _ = function(1) }
"#;
        let facts = facts(source);
        let check = declaration(&facts, "Check");
        let signature = facts
            .callable_signatures
            .iter()
            .find(|signature| signature.callable == check)
            .expect("function-typed field signature");
        let parameters = facts
            .callable_parameters
            .iter()
            .filter(|parameter| parameter.callable == check)
            .collect::<Vec<_>>();
        assert_eq!(parameters.len(), 2);
        assert_eq!(parameters[0].ordinal, 0);
        assert_eq!(parameters[1].ordinal, 1);
        assert!(!parameters[0].repeated);
        assert!(parameters[1].repeated);
        assert_eq!(signature.result_types.len(), 2);
        assert_eq!(signature.result_types[0].ordinal, 0);
        assert_eq!(signature.result_types[1].ordinal, 1);
        assert!(!facts.gaps.iter().any(|gap| {
            gap.site == check
                && matches!(
                    gap.kind,
                    ResolutionGapKind::UnsupportedTypeSyntax
                        | ResolutionGapKind::UnsupportedExpressionType
                )
        }));

        let zero = declaration(&facts, "Zero");
        assert!(
            facts
                .callable_signatures
                .iter()
                .any(|signature| signature.callable == zero && signature.result_types.is_empty())
        );

        let function = declaration(&facts, "function");
        let function_signature = facts
            .callable_signatures
            .iter()
            .find(|signature| signature.callable == function)
            .expect("function-typed parameter signature");
        assert_eq!(function_signature.result_types.len(), 1);
        assert!(facts.callable_parameters.iter().any(|parameter| {
            parameter.callable == function && parameter.ordinal == 0 && !parameter.repeated
        }));
        assert!(!facts.gaps.iter().any(|gap| {
            gap.site == function
                && matches!(
                    gap.kind,
                    ResolutionGapKind::UnsupportedTypeSyntax
                        | ResolutionGapKind::UnsupportedExpressionType
                )
        }));
    }

    #[test]
    fn interface_methods_have_owners_and_type_sets_keep_references_with_a_frontier() {
        let facts = facts(
            r#"package p
type Base interface { Run() }
type Embedded interface { Base }
type Constraint interface { ~int | string }
"#,
        );
        let base = declaration(&facts, "Base");
        let embedded = declaration(&facts, "Embedded");
        let method = declaration(&facts, "Run");
        assert!(facts.member_owners.iter().any(|owner| {
            owner.member == method
                && owner.owner == base
                && owner.kind == ResolutionMemberKind::Method
        }));
        assert!(facts.supertypes.iter().any(|edge| {
            edge.subtype == embedded && edge.kind == ResolutionSupertypeKind::GoInterfaceElement
        }));
        assert!(!facts.gaps.iter().any(|gap| {
            matches!(gap.site, site if site == base || site == embedded)
                && gap.kind == ResolutionGapKind::UnsupportedHierarchyTraversal
        }));

        let constraint = declaration(&facts, "Constraint");
        assert!(facts.gaps.contains(&ResolutionGapFact {
            site: constraint,
            kind: ResolutionGapKind::UnsupportedHierarchyTraversal,
        }));
        let term_references = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && matches!(name(&facts, identifier.name), "int" | "string")
            })
            .collect::<Vec<_>>();
        assert_eq!(term_references.len(), 2);
        assert!(facts.reference_enumeration_gaps.is_empty());
        let source = "package p\ntype Base interface { Run() }\ntype Embedded interface { Base }\ntype Constraint interface { ~int | ~string }\n";
        let tree = crate::parse::parse_go(source).expect("named interface fixture tree");
        let fixture_facts = output_from_tree(&tree, source).facts;
        assert!(fixture_facts.reference_enumeration_gaps.is_empty());
        ast_reference_oracle(
            tree.root_node(),
            source,
            &fixture_facts,
            "named interface fixture",
        )
        .expect("named interface references match the independent oracle");
    }

    #[test]
    fn anonymous_interface_types_enumerate_members_and_type_references() {
        let source = r#"package p

type Input struct{}
type Output struct{}
type Base interface { ReadBase(Input) Output }
type Alias = interface { Base; CloseAlias() Output }
type Holder struct { Reader interface { Base; ReadField(Input) Output } }
func Consume(reader interface { Base; ReadParam(Input) Output }) {}
type Constraint interface { ~int | ~string }
"#;
        let tree = crate::parse::parse_go(source).expect("anonymous interface fixture tree");
        let facts = output_from_tree(&tree, source).facts;
        assert!(facts.reference_enumeration_gaps.is_empty());
        for method in ["ReadBase", "CloseAlias", "ReadField", "ReadParam"] {
            let declaration = declaration(&facts, method);
            assert!(facts.member_owners.iter().any(|owner| {
                owner.member == declaration && owner.kind == ResolutionMemberKind::Method
            }));
        }
        ast_reference_oracle(
            tree.root_node(),
            source,
            &facts,
            "anonymous interface fixture",
        )
        .expect("anonymous interface references match the independent oracle");
        assert!(facts.gaps.iter().any(|gap| {
            gap.kind == ResolutionGapKind::UnsupportedExpressionType
                && facts.sites[gap.site.index()].kind == ResolutionSiteKind::TypeDeclaration
        }));
    }

    #[test]
    fn switch_type_lists_ignore_separator_tokens_and_enumerate_each_type() {
        let source = r#"package p

type Input struct{}
type Output struct{}
func Consume(value any) {
    switch value.(type) {
    case Input, *Output:
    default:
    }
}
"#;
        let tree = crate::parse::parse_go(source).expect("switch fixture tree");
        let facts = output_from_tree(&tree, source).facts;
        assert!(facts.reference_enumeration_gaps.is_empty());
        ast_reference_oracle(tree.root_node(), source, &facts, "switch type-list fixture")
            .expect("switch type-list references match the independent oracle");
    }

    #[test]
    fn function_type_aliases_lower_signatures_without_lexical_binders() {
        let source = "package p\ntype Callback func(input pkg.Input) pkg.Result\n";
        let tree = crate::parse::parse_go(source).expect("function type fixture tree");
        let facts = output_from_tree(&tree, source).facts;
        let mut pending = vec![tree.root_node()];
        let mut function_type = None;
        let mut parameter = None;
        while let Some(node) = pending.pop() {
            match node.kind() {
                "function_type" => function_type = Some(node),
                "parameter_declaration" => parameter = Some(node),
                _ => {}
            }
            pending.extend(named_children(node));
        }
        assert!(function_type.is_some(), "type alias has a function type");
        let parameter = parameter.expect("function type has a parameter position");
        let parameter_site = facts
            .sites
            .iter()
            .find(|site| {
                site.start_byte == parameter.start_byte() && site.end_byte == parameter.end_byte()
            })
            .map(|site| site.id);
        let declaration = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && name(&facts, identifier.name) == "Callback"
            })
            .expect("function type alias declaration")
            .site;
        assert!(!facts.gaps.contains(&ResolutionGapFact {
            site: declaration,
            kind: ResolutionGapKind::UnsupportedTypeSyntax,
        }));
        assert!(!parameter_site.is_some_and(|site| {
            facts.gaps.contains(&ResolutionGapFact {
                site,
                kind: ResolutionGapKind::UnsupportedScopeOrBinder,
            })
        }));
        let signature = facts
            .callable_signatures
            .iter()
            .find(|signature| signature.callable == declaration)
            .expect("function type alias has a signature");
        let parameters = facts
            .callable_parameters
            .iter()
            .filter(|parameter| parameter.callable == declaration)
            .collect::<Vec<_>>();
        assert_eq!(parameters.len(), 1);
        assert_eq!(parameters[0].ordinal, 0);
        assert!(!parameters[0].repeated);
        assert_eq!(signature.result_types.len(), 1);
        assert_eq!(signature.result_types[0].ordinal, 0);
        assert!(facts.reference_enumeration_gaps.is_empty());
        ast_reference_oracle(
            tree.root_node(),
            source,
            &facts,
            "function-type alias fixture",
        )
        .expect("function-type alias references have exact sites");
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
                        && component.constructor == ResolutionTypeConstructorKind::Slice
                        && component.kind == ResolutionTypeComponentKind::Element
                }));
                assert!(!facts.gaps.iter().any(|gap| {
                    gap.site == owner_slot.site
                        && gap.kind == ResolutionGapKind::UnsupportedTypeSyntax
                }));
            } else {
                assert!(facts.gaps.contains(&ResolutionGapFact {
                    site: owner_slot.site,
                    kind: ResolutionGapKind::UnsupportedExpressionType,
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
    fn variadic_parameter_rows_publish_arity_without_poisoning_callable_binding() {
        let source = r#"package p

func V(values ...int) {}
func U(...int) {}
"#;
        let facts = facts(source);
        for spelling in ["V", "U"] {
            let callable = declaration(&facts, spelling);
            assert!(!facts.gaps.contains(&ResolutionGapFact {
                site: callable,
                kind: ResolutionGapKind::UnsupportedCallApplicability,
            }));
            let parameters = facts
                .callable_parameters
                .iter()
                .filter(|parameter| parameter.callable == callable)
                .collect::<Vec<_>>();
            assert_eq!(parameters.len(), 1);
            assert!(parameters[0].repeated);
            assert!(facts.gaps.contains(&ResolutionGapFact {
                site: parameters[0].parameter,
                kind: ResolutionGapKind::UnsupportedExpressionType,
            }));
            assert!(
                !facts
                    .reference_enumeration_gaps
                    .iter()
                    .any(|gap| { gap.site == parameters[0].parameter })
            );
        }
    }

    #[test]
    fn function_type_parameters_stay_with_their_signature_inside_generic_variadic_callable() {
        let source = r#"package p

type Item[K any] struct{}

func New[K any](opts ...K) {
	var callback func(*Item[K], K)
	_ = callback
}
"#;
        let tree = crate::parse::parse_go(source).expect("generic variadic fixture tree");
        let facts = facts(source);
        let constructor = declaration(&facts, "New");
        let constructor_parameters = facts
            .callable_parameters
            .iter()
            .filter(|parameter| parameter.callable == constructor)
            .collect::<Vec<_>>();
        assert_eq!(constructor_parameters.len(), 1);
        assert_eq!(constructor_parameters[0].ordinal, 0);
        assert!(constructor_parameters[0].repeated);

        let callback = declaration(&facts, "callback");
        let callback_parameters = facts
            .callable_parameters
            .iter()
            .filter(|parameter| parameter.callable == callback)
            .collect::<Vec<_>>();
        assert_eq!(callback_parameters.len(), 2);
        assert_eq!(
            callback_parameters
                .iter()
                .map(|parameter| (parameter.ordinal, parameter.repeated))
                .collect::<Vec<_>>(),
            [(0, false), (1, false)]
        );
        assert!(facts.reference_enumeration_gaps.is_empty());
        ast_reference_oracle(
            tree.root_node(),
            source,
            &facts,
            "generic variadic function-type fixture",
        )
        .expect("function-type parameter references stay enumerated");
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
    fn recovered_missing_identifiers_are_malformed_syntax_gaps() {
        let gcc_syntax = "package main\nfunc x() {}\nfunc main() { if {}\nif x(); {} }\n";
        let sources = [
            gcc_syntax,
            "package p\nfunc f() { _ = 1 + }\n",
            "package p\nfunc f(a []int) { _ = a[2 +] }\n",
            "package p\nfunc f() { _ = []int{1, 2, 3 +} }\n",
        ];
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("Go grammar");
        for (index, source) in sources.into_iter().enumerate() {
            let tree = parser.parse(source, None).expect("Go tree");
            let mut stack = vec![tree.root_node()];
            let mut has_missing_identifier = false;
            while let Some(node) = stack.pop() {
                has_missing_identifier |= node.is_missing()
                    && matches!(
                        node.kind(),
                        "identifier"
                            | "type_identifier"
                            | "field_identifier"
                            | "package_identifier"
                    );
                stack.extend((0..node.child_count()).filter_map(|index| node.child(index)));
            }
            if index == 0 {
                assert!(
                    has_missing_identifier,
                    "expected recovered identifier in GCC syntax shape: {source:?}; {}",
                    tree.root_node().to_sexp()
                );
            }

            let facts = extract_go_resolution_facts(tree.root_node(), source);
            assert!(
                facts
                    .gaps
                    .iter()
                    .any(|gap| gap.kind == ResolutionGapKind::MalformedSyntax),
                "{source:?}: {:?}",
                facts.gaps
            );
            for identifier in &facts.identifiers {
                let site = facts.sites[identifier.site.index()];
                assert!(
                    site.start_byte < site.end_byte,
                    "positioned identifier has an empty range in {source:?}: {identifier:?}"
                );
            }
        }
    }

    #[test]
    fn common_go_declarations_keep_reference_inventory_complete() {
        let fixtures = [
            (
                "blank-name function signatures",
                "package a\n\ntype i int\n\nfunc _(_ i) []bool { return nil }\nfunc _(_ []byte) i { return 0 }\n",
            ),
            (
                "interface methods",
                "package a\n\ntype first interface { common() }\ntype s struct{}\nfunc (*s) common() {}\nfunc use(x first) { x.common() }\n",
            ),
            (
                "composite literal selectors",
                "package a\n\ntype e struct { Name string }\nfunc use() { _ = e{}.Name }\n",
            ),
            (
                "function literal parameters",
                "package a\n\nvar q string\nfunc use() { q = \"hello\"; bob := func(_ string) {}; bob(q) }\n",
            ),
            (
                "loop and asynchronous statement references",
                "package a\nfunc visit(int) {}\nfunc finish(int) {}\nfunc use() { for i := 0; i < 2; i++ { go visit(i); defer finish(i) } }\n",
            ),
        ];
        let incomplete = fixtures
            .into_iter()
            .filter_map(|(label, source)| {
                let facts = facts(source);
                let gaps = facts
                    .reference_enumeration_gaps
                    .iter()
                    .map(|gap| {
                        let site = facts.sites[gap.site.index()];
                        (gap.kind, &source[site.start_byte..site.end_byte])
                    })
                    .collect::<Vec<_>>();
                (!gaps.is_empty()).then_some((label, gaps))
            })
            .collect::<Vec<_>>();
        assert!(
            incomplete.is_empty(),
            "supported Go sources were left out of the reference inventory: {incomplete:?}"
        );
        let loop_facts = facts(fixtures[4].1);
        let references = loop_facts
            .identifiers
            .iter()
            .filter(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
            .map(|identifier| {
                let site = loop_facts.sites[identifier.site.index()];
                &fixtures[4].1[site.start_byte..site.end_byte]
            })
            .collect::<Vec<_>>();
        assert!(references.contains(&"visit"));
        assert!(references.contains(&"finish"));
        assert!(references.iter().filter(|&&text| text == "i").count() >= 4);
    }
}
