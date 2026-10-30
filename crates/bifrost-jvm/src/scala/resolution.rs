//! Scala lowering for file-local, target-independent resolution facts.
//!
//! The walk records source declarations and references only. Binding across
//! files, contextual search, parent linearization and compiler-generated JVM
//! names remain selected-context work or explicit gaps.

use brokk_bifrost_core::analyzer::Range;
use brokk_bifrost_core::analyzer::fq_name::{SegmentKind, segment_interner};
use brokk_bifrost_core::analyzer::model::{CodeUnit, CodeUnitType, DeclarationKind};
use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
use brokk_bifrost_core::analyzer::resolution_facts::{
    BindingProjectionFact, BindingProjectionKind, DeclarationTypeRole, DeclarationTypeSlotFact,
    FileResolutionFacts, PositionedIdentifierFact, ResolutionAdditionalDefinitionNamespaceFact,
    ResolutionBinaryOwnerRoute, ResolutionBinderFact, ResolutionBinderKind,
    ResolutionCallArgumentListFact, ResolutionCallFact, ResolutionCallTypeArgumentFact,
    ResolutionCallableParameterFact, ResolutionCallableParameterListFact,
    ResolutionCallableParameterSemanticsFact, ResolutionCallableReceiverOrigin,
    ResolutionCallableReceiverOriginFact, ResolutionCallableSignatureFact,
    ResolutionDeclarationVisibilityFact, ResolutionDefinitionUnitFact,
    ResolutionEngineRuleEligibilityFact, ResolutionEngineRuleKind, ResolutionGapFact,
    ResolutionGapKind, ResolutionIdentifierRole, ResolutionImportRouteFact,
    ResolutionImportRouteKind, ResolutionImportRouteSegmentFact, ResolutionImportSelectorFact,
    ResolutionImportSelectorKind, ResolutionInvocationRole, ResolutionInvocationRoleFact,
    ResolutionJvmAliasFact, ResolutionJvmAliasId, ResolutionJvmAliasKind,
    ResolutionJvmAliasOwnerSegmentFact, ResolutionJvmAliasStatus, ResolutionLocalWriteFact,
    ResolutionMemberAccess, ResolutionMemberKind, ResolutionMemberOwnerFact,
    ResolutionMemberQualifierCompatibility, ResolutionNameFact, ResolutionNameId,
    ResolutionNamedArgumentLabelFact, ResolutionNamespace, ResolutionPackageFact,
    ResolutionPackageObjectExportFact, ResolutionPackageSegmentFact,
    ResolutionReferenceEnumerationGapFact, ResolutionReferenceOwnerFact, ResolutionRootExportFact,
    ResolutionRootImportAnchor, ResolutionRootImportDemandFact, ResolutionRootImportDemandTarget,
    ResolutionRootImportDemandTargetFact, ResolutionRootImportFact, ResolutionRootImportKind,
    ResolutionRootImportKindFact, ResolutionRootImportSegmentFact, ResolutionRootReferenceFact,
    ResolutionRootReferenceSegmentFact, ResolutionRouteGap, ResolutionRouteOwner,
    ResolutionScopeFact, ResolutionScopeId, ResolutionScopeInheritance, ResolutionScopeKind,
    ResolutionSingletonRelationFact, ResolutionSingletonRelationKind, ResolutionSiteFact,
    ResolutionSiteId, ResolutionSiteKind, ResolutionSupertypeFact, ResolutionSupertypeKind,
    ResolutionTypeSlotFact, ResolutionTypeSlotId, ResolutionTypeSlotRole,
    ResolutionTypeTransferFact, ResolutionTypeTransferKind, ResolutionTypeTransferValueTransform,
};
use brokk_bifrost_core::analyzer::source_facts::{
    PrimarySourceFactCollector, SourceDeclarationId, SourceOccurrenceId, SourceOccurrenceProvenance,
};
use brokk_bifrost_core::analyzer::structural::adapter_helpers::field_name_in_parent;
use brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceRole;
use brokk_bifrost_core::analyzer::structural::resolution::{
    BindingKind, DeclaredVisibility, HoistingClass,
};
use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;
use brokk_bifrost_core::analyzer::tree_walk::{
    expression_target_node, node_range, unwrap_parenthesized_expression,
};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use tree_sitter::Node;

use crate::constructor_site::ConstructorSite;
use crate::scala::imports::scala_export_info_from_node;
use crate::scala::structural::{SCALA_STRUCTURAL_SPEC, scala_occurrence_role};
use crate::scala::supertypes::{scala_self_type_lookup_nodes, scala_supertype_lookup_nodes};

pub(super) struct ScalaResolutionExtraction {
    pub facts: FileResolutionFacts,
    pub site_occurrences: Vec<SourceOccurrenceId>,
    pub declaration_sources: Vec<(ResolutionSiteId, SourceDeclarationId)>,
}

struct WalkItem<'tree> {
    node: Node<'tree>,
    scope: ResolutionScopeId,
    owner: Option<ResolutionSiteId>,
    type_owner: Option<ResolutionSiteId>,
}

struct ScalaImportRoute<'nodes, 'tree> {
    site: ResolutionSiteId,
    scope: ResolutionScopeId,
    anchor: ResolutionRootImportAnchor,
    path: &'nodes [ResolutionNameId],
    source: Option<Node<'tree>>,
    local: Option<Node<'tree>>,
    star: bool,
    activation_start: usize,
}

/// A case class whose compiler-added members are published.
struct ScalaCaseClass<'source> {
    node: Node<'source>,
    site: ResolutionSiteId,
    /// The class's synthetic constructor declaration, where its members are
    /// located.
    constructor: SourceDeclarationId,
}

/// One member the compiler adds to a case class or its companion.
struct ScalaCaseMember<'source> {
    name: &'static str,
    /// The source template used for duplicate checks and the member's anchor.
    owner: Node<'source>,
    owner_site: ResolutionSiteId,
    owner_scope: ResolutionScopeId,
    access: (
        ResolutionMemberAccess,
        ResolutionMemberQualifierCompatibility,
    ),
    /// `None` when the class's parameter lists are not modeled (curried or
    /// contextual), which leaves the member's applicability open.
    parameters: Option<Vec<ScalaCaseMemberParameter<'source>>>,
    returns_class: bool,
}

#[derive(Clone, Copy)]
struct ScalaCaseMemberParameter<'source> {
    label: &'source str,
    /// The class parameter this one mirrors; `None` for a parameter typed as
    /// the class itself.
    declared: Option<Node<'source>>,
    has_default: bool,
}

struct ScalaResolutionBuilder<'a, 'source> {
    source: &'source str,
    collector: &'a mut PrimarySourceFactCollector<'source>,
    facts: FileResolutionFacts,
    site_occurrences: Vec<SourceOccurrenceId>,
    declaration_sources: Vec<(ResolutionSiteId, SourceDeclarationId)>,
    name_ids: HashMap<String, ResolutionNameId>,
    sites_by_node: HashMap<usize, ResolutionSiteId>,
    declaration_sites: HashMap<usize, ResolutionSiteId>,
    declaration_nodes: HashMap<ResolutionSiteId, Node<'source>>,
    package_declarations: HashMap<usize, ResolutionSiteId>,
    scopes_by_node: HashMap<usize, ResolutionScopeId>,
    package_objects: Vec<(ResolutionSiteId, ResolutionScopeId)>,
    expression_slots_by_node: HashMap<usize, ResolutionTypeSlotId>,
    call_result_slots_by_node: HashMap<usize, ResolutionTypeSlotId>,
    qualified_type_prefixes: HashMap<usize, ResolutionSiteId>,
    parameter_list_ordinals: HashMap<usize, u32>,
    scope_ranges: Vec<Range>,
    /// The `apply` and `unapply` sites published for each case class, by class node.
    case_class_members: HashMap<usize, (Option<ResolutionSiteId>, Option<ResolutionSiteId>)>,
    synthesized_companions: HashMap<usize, ResolutionSiteId>,
    next_parameter_ordinal: HashMap<ResolutionSiteId, u32>,
    pending_declared_value_types: Vec<(ResolutionSiteId, ResolutionTypeSlotId, Node<'source>)>,
    pending_function_types: Vec<(ResolutionSiteId, ResolutionTypeSlotId, Node<'source>)>,
    pending_type_aliases: Vec<(ResolutionSiteId, ResolutionTypeSlotId, Node<'source>)>,
    pending_initializers: Vec<(ResolutionTypeSlotId, Node<'source>, ResolutionScopeId)>,
    pending_initializer_values: Vec<(ResolutionTypeSlotId, Node<'source>, ResolutionScopeId)>,
    pending_writes: Vec<(Node<'source>, ResolutionScopeId)>,
    /// A `super.member` receiver and the template whose parent linearization
    /// answers it. The identity slots are connected after the walk has
    /// published every supertype edge.
    super_receivers: Vec<(ResolutionSiteId, ResolutionTypeSlotId)>,
    super_receiver_slots_by_node: HashMap<usize, ResolutionTypeSlotId>,
    /// Members selected on `this`: they carry no qualifier and are looked up
    /// in the body of the template that contains `this`.
    current_instance_members: HashSet<ResolutionSiteId>,
    wildcard_imports: Vec<(ResolutionSiteId, ResolutionScopeId, usize)>,
    root_scope: ResolutionScopeId,
    placement_site: ResolutionSiteId,
}

pub(super) fn extract_scala_resolution<'source>(
    root: Node<'source>,
    source: &'source str,
    parsed: &ParsedFile,
    source_declarations: &brokk_bifrost_core::analyzer::scala_facts::ScalaSourceFacts,
    collector: &mut PrimarySourceFactCollector<'source>,
) -> ScalaResolutionExtraction {
    let root_scope = ResolutionScopeId::new(0);
    let root_occurrence = collector.intern_node(root);
    let placement_site = ResolutionSiteId::new(0);
    let root_range = collector.occurrence(root_occurrence).range;
    let mut builder = ScalaResolutionBuilder {
        source,
        collector,
        facts: FileResolutionFacts {
            scopes: vec![ResolutionScopeFact {
                id: root_scope,
                parent: None,
                owner: None,
                kind: ResolutionScopeKind::CompilationUnit,
                inheritance: ResolutionScopeInheritance::Lexical,
                start_byte: root_range.start_byte,
                end_byte: root_range.end_byte,
            }],
            ..FileResolutionFacts::default()
        },
        site_occurrences: Vec::new(),
        declaration_sources: Vec::new(),
        name_ids: HashMap::default(),
        sites_by_node: HashMap::default(),
        declaration_sites: HashMap::default(),
        declaration_nodes: HashMap::default(),
        package_declarations: HashMap::default(),
        scopes_by_node: HashMap::default(),
        package_objects: Vec::new(),
        expression_slots_by_node: HashMap::default(),
        call_result_slots_by_node: HashMap::default(),
        qualified_type_prefixes: HashMap::default(),
        parameter_list_ordinals: HashMap::default(),
        scope_ranges: vec![node_range(root)],
        case_class_members: HashMap::default(),
        synthesized_companions: HashMap::default(),
        next_parameter_ordinal: HashMap::default(),
        pending_declared_value_types: Vec::new(),
        pending_function_types: Vec::new(),
        pending_type_aliases: Vec::new(),
        pending_initializers: Vec::new(),
        pending_initializer_values: Vec::new(),
        pending_writes: Vec::new(),
        super_receivers: Vec::new(),
        super_receiver_slots_by_node: HashMap::default(),
        current_instance_members: HashSet::default(),
        wildcard_imports: Vec::new(),
        root_scope,
        placement_site,
    };
    let placement_site = builder.add_site(root, ResolutionSiteKind::UnsupportedRoute, root_scope);
    assert_eq!(placement_site, builder.placement_site);
    // Package membership, import precedence, and unqualified package requests
    // are published as source-owned facts and joined by selected context.
    builder.walk(root, parsed, source_declarations);
    builder.finish_constructors(root, parsed, source_declarations);
    builder.finish_case_class_members(root, parsed);
    builder.finish_enum_companions(root, parsed);
    builder.finish_declared_value_types();
    builder.finish_callable_result_types(root);
    builder.finish_packages(root);
    builder.finish_supertypes(root);
    builder.finish_super_receivers();
    builder.finish_calls(root);
    builder.finish_writes();
    builder.finish_import_demands();
    builder.finish_function_types();
    builder.finish_shape_dependent_gaps(root);
    builder.finish_generic_formals();
    // Companion relations and projected aliases must exist before regions are
    // copied from their canonical source declarations.
    builder.finish_access_boundaries(root, source_declarations);
    builder.validate();
    crate::implicit_supertype::publish_written_supertype_names(&mut builder.facts);
    ScalaResolutionExtraction {
        facts: builder.facts,
        site_occurrences: builder.site_occurrences,
        declaration_sources: builder.declaration_sources,
    }
}

impl<'collector, 'source> ScalaResolutionBuilder<'collector, 'source> {
    fn walk(
        &mut self,
        root: Node<'source>,
        parsed: &ParsedFile,
        source_declarations: &brokk_bifrost_core::analyzer::scala_facts::ScalaSourceFacts,
    ) {
        let mut stack = vec![WalkItem {
            node: root,
            scope: self.root_scope,
            owner: None,
            type_owner: None,
        }];
        // A template's TypeBody scope spans its whole declaration, header
        // included. A qualified parent's type-constructor path (`replica.Base` in
        // `extends replica.Base`) cannot name the template's own members,
        // inherited or declared, nor its type or value parameters, so it is
        // looked up in the scope enclosing the template. Looking it up in the
        // template's own scope made a qualified parent wait on the hierarchy
        // that the parent itself establishes (#5104). Type arguments and
        // parent constructor arguments keep the template scope. The path still
        // belongs to the template whose header contains it, so its references
        // carry explicit containment rows instead of the enclosing scope's
        // owner.
        let mut parent_path_scopes = HashMap::<usize, ResolutionScopeId>::default();
        let mut parent_paths = Vec::new();
        while let Some(item) = stack.pop() {
            let item = WalkItem {
                scope: parent_path_scopes
                    .remove(&item.node.id())
                    .unwrap_or(item.scope),
                ..item
            };
            let node = item.node;
            if node.is_error() || node.is_missing() {
                let site =
                    self.add_site(node, ResolutionSiteKind::UnsupportedDeclaration, item.scope);
                self.gap(site, ResolutionGapKind::MalformedSyntax);
                self.facts
                    .reference_enumeration_gaps
                    .push(ResolutionReferenceEnumerationGapFact {
                        site,
                        kind: ResolutionGapKind::MalformedSyntax,
                    });
                continue;
            }

            let declaration = self.lower_declaration(
                node,
                item.scope,
                item.owner,
                item.type_owner,
                parsed,
                source_declarations,
            );
            let declaration = if node.kind() == "given_definition" && declaration.is_none() {
                self.lower_anonymous_given(node, item.scope, item.type_owner)
            } else {
                declaration
            };
            let mut child_owner = declaration.or(item.owner);
            let mut child_type_owner = item.type_owner;
            if is_type_declaration(node.kind()) {
                child_type_owner = declaration;
            }

            if node.kind() == "package_clause" {
                let site = self.add_site(node, ResolutionSiteKind::PackageDeclaration, item.scope);
                if let Some(name) = node.child_by_field_name("name") {
                    let mut identifiers = Vec::new();
                    let mut names = vec![name];
                    while let Some(part) = names.pop() {
                        if matches!(part.kind(), "identifier" | "operator_identifier") {
                            identifiers.push(part);
                        } else {
                            let mut cursor = part.walk();
                            let children = part.named_children(&mut cursor).collect::<Vec<_>>();
                            names.extend(children.into_iter().rev());
                        }
                    }
                    identifiers.sort_unstable_by_key(Node::start_byte);
                    if let Some(last) = identifiers.last().copied() {
                        self.identifier(
                            site,
                            last,
                            ResolutionIdentifierRole::Declaration,
                            ResolutionNamespace::Package,
                            None,
                        );
                    }
                }
                child_owner = Some(site);
            }

            if node.kind() == "import_declaration" {
                self.lower_import(node, item.scope);
            }

            if (node.kind() == "assignment_expression" && !is_named_argument(node))
                || (node.kind() == "infix_expression"
                    && node
                        .child_by_field_name("operator")
                        .is_some_and(|operator| {
                            let name = node_text(operator, self.source);
                            operator.kind() == "operator_identifier"
                                && name.ends_with('=')
                                && !name.starts_with('=')
                                && !matches!(name, "<=" | ">=" | "!=")
                        }))
            {
                self.pending_writes.push((node, item.scope));
            }

            if node.kind() == "call_expression" || node.kind() == "infix_expression" {
                let curried_function = application_is_curried_function(node);
                // Scala parses later argument lists of `new C(first)(second)`
                // as a call_expression over the instance_expression. The
                // constructor call-shape owns those lists; treating this node
                // as an ordinary call descends into the first argument and
                // mistakes its callee for the constructed value's callee.
                let constructor_argument_list = scala_constructor_instance(node).is_some();
                if !curried_function && !constructor_argument_list {
                    // The result slot exists before any descendant is lowered,
                    // so a selection or argument written on the call's value
                    // reads this slot instead of inventing one.
                    let call = self.add_site(node, ResolutionSiteKind::Call, item.scope);
                    let result = self.add_slot(call, ResolutionTypeSlotRole::CallResult);
                    self.call_result_slots_by_node.insert(node.id(), result);
                }
            }
            if node.kind() == "context_bound" {
                let site =
                    self.add_site(node, ResolutionSiteKind::UnsupportedDeclaration, item.scope);
                self.gap(site, ResolutionGapKind::UnsupportedScopeOrBinder);
            }

            self.lower_occurrence(
                node,
                item.scope,
                item.owner,
                item.type_owner,
                parsed,
                source_declarations,
            );

            let (child_scope, child_owner, child_type_owner) =
                self.scope_for_children(node, item.scope, child_owner, child_type_owner);
            if child_scope != item.scope {
                for (_, lookup) in scala_supertype_lookup_nodes(node) {
                    // A bare parent name is resolved by the hierarchy's local
                    // lexical batch, which never waits on the owner's own
                    // inherited branch, so it keeps the template scope until
                    // the enclosing scope ranks same-unit definitions above a
                    // positioned wildcard import (#7814).
                    if lookup.kind() == "type_identifier" {
                        continue;
                    }
                    parent_path_scopes.insert(lookup.id(), item.scope);
                    let template = self
                        .scope(child_scope)
                        .owner
                        .expect("a template scope has its declaration owner");
                    parent_paths.push((lookup, template));
                }
            }
            let mut cursor = node.walk();
            let children = node.named_children(&mut cursor).collect::<Vec<_>>();
            for child in children.into_iter().rev() {
                stack.push(WalkItem {
                    node: child,
                    scope: child_scope,
                    owner: child_owner,
                    type_owner: child_type_owner,
                });
            }
        }
        let mut owned = self
            .facts
            .reference_owners
            .iter()
            .map(|row| row.reference)
            .collect::<HashSet<_>>();
        for (lookup, template) in parent_paths {
            let mut nodes = vec![lookup];
            while let Some(node) = nodes.pop() {
                nodes.extend(node.named_children(&mut node.walk()));
                for site in [
                    self.sites_by_node.get(&node.id()),
                    self.qualified_type_prefixes.get(&node.id()),
                ]
                .into_iter()
                .flatten()
                .copied()
                {
                    let is_reference = self
                        .facts
                        .identifiers
                        .iter()
                        .find(|identifier| identifier.site == site)
                        .is_some_and(|identifier| {
                            identifier.role == ResolutionIdentifierRole::Reference
                        });
                    if is_reference && owned.insert(site) {
                        self.facts
                            .reference_owners
                            .push(ResolutionReferenceOwnerFact {
                                reference: site,
                                owner: Some(template),
                            });
                    }
                }
            }
        }
    }

    fn lower_declaration(
        &mut self,
        node: Node<'source>,
        scope: ResolutionScopeId,
        _owner: Option<ResolutionSiteId>,
        type_owner: Option<ResolutionSiteId>,
        parsed: &ParsedFile,
        source_declarations: &brokk_bifrost_core::analyzer::scala_facts::ScalaSourceFacts,
    ) -> Option<ResolutionSiteId> {
        if node.kind() == "instance_expression" {
            self.lower_anonymous_type(node, scope, parsed);
            // Arguments and parent type references retain the enclosing scope.
            // Only the template body enters the anonymous owner's scope.
            return None;
        }
        let scope = if matches!(node.kind(), "function_definition" | "function_declaration") {
            enclosing_extension_definition(node)
                .filter(|extension| nearest_ancestor(*extension, "given_definition").is_none())
                .and_then(|extension| self.scopes_by_node.get(&extension.id()).copied())
                .and_then(|extension_scope| self.scope(extension_scope).parent)
                .unwrap_or(scope)
        } else {
            scope
        };
        let (kind, namespace, binder, member_kind) = match node.kind() {
            "class_definition" | "trait_definition" | "enum_definition" | "full_enum_case"
            | "package_object" => (
                ResolutionSiteKind::TypeDeclaration,
                ResolutionNamespace::Type,
                Some(ResolutionBinderKind::Type),
                Some(ResolutionMemberKind::NestedType),
            ),
            // An object is a term that owns a member scope: the declaration
            // occupies the Value namespace only, so a type position finds the
            // class beside it and not the object.
            "object_definition" => (
                ResolutionSiteKind::TypeDeclaration,
                ResolutionNamespace::Value,
                Some(ResolutionBinderKind::Type),
                Some(ResolutionMemberKind::Field),
            ),
            "type_definition" => (
                ResolutionSiteKind::TypeAliasDeclaration,
                ResolutionNamespace::Type,
                Some(ResolutionBinderKind::Type),
                Some(ResolutionMemberKind::AssociatedType),
            ),
            "function_definition" | "function_declaration" | "given_definition" => (
                ResolutionSiteKind::CallableDeclaration,
                ResolutionNamespace::Callable,
                Some(ResolutionBinderKind::Callable),
                Some(ResolutionMemberKind::Method),
            ),
            "val_definition" | "var_definition" | "val_declaration" | "var_declaration"
            | "simple_enum_case" => (
                ResolutionSiteKind::ValueDeclaration,
                ResolutionNamespace::Value,
                Some(if type_owner.is_some() {
                    ResolutionBinderKind::Field
                } else {
                    ResolutionBinderKind::Local
                }),
                Some(ResolutionMemberKind::Field),
            ),
            _ => return None,
        };
        let name = declaration_name(node);
        if name.is_none()
            && matches!(
                node.kind(),
                "val_definition"
                    | "var_definition"
                    | "val_declaration"
                    | "var_declaration"
                    | "given_definition"
            )
        {
            return None;
        }
        let names = if matches!(
            node.kind(),
            "val_definition" | "var_definition" | "val_declaration" | "var_declaration"
        ) {
            let mut cursor = node.walk();
            node.children_by_field_name("name", &mut cursor)
                .map(Some)
                .collect::<Vec<_>>()
        } else {
            vec![name]
        };
        let mut first_site = None;
        for (ordinal, name) in names.into_iter().enumerate() {
            let site_node = if ordinal == 0 {
                node
            } else {
                name.expect("additional value declaration name")
            };
            let site = self.add_site(site_node, kind, scope);
            first_site.get_or_insert(site);
            self.declaration_sites.entry(node.id()).or_insert(site);
            self.declaration_nodes.insert(site, node);
            if node.kind() == "package_object"
                && let Some(name) = name
            {
                let package_declaration =
                    self.add_site(name, ResolutionSiteKind::PackageDeclaration, scope);
                self.package_declarations
                    .insert(node.id(), package_declaration);
            }
            if let Some(name) = name {
                self.identifier(
                    site,
                    name,
                    ResolutionIdentifierRole::Declaration,
                    namespace,
                    None,
                );
                let occurrence = self.collector.intern_node(node);
                let name_occurrence = self.collector.intern_node(name);
                let declaration = self.collector.declare(occurrence, Some(name_occurrence));
                let has_source_declaration_unit = parsed
                    .source_declaration_units
                    .iter()
                    .any(|(source, _)| *source == declaration);
                if has_source_declaration_unit {
                    self.declaration_sources.push((site, declaration));
                    let unit = parsed
                        .source_declaration_units
                        .iter()
                        .find_map(|(source, unit)| {
                            if *source != declaration || unit.is_synthetic() {
                                return None;
                            }
                            let matches_declaration_kind = match node.kind() {
                                "class_definition" | "trait_definition" | "object_definition"
                                | "enum_definition" | "full_enum_case" | "package_object"
                                | "type_definition" => unit.is_class(),
                                "function_definition"
                                | "function_declaration"
                                | "given_definition" => unit.is_function(),
                                "val_definition" | "var_definition" | "val_declaration"
                                | "simple_enum_case" | "var_declaration" => unit.is_field(),
                                _ => false,
                            };
                            matches_declaration_kind.then_some(unit)
                        });
                    if let Some(unit) = unit {
                        self.facts
                            .definition_units
                            .push(ResolutionDefinitionUnitFact {
                                declaration: site,
                                unit: unit.clone(),
                            });
                    }
                    // Only a transparent alias publishes an identity slot: its
                    // value arrives through a transfer from the written type.
                    // An abstract member and an opaque alias name a type of
                    // their own, so a reference to either projects the
                    // declaration itself as the type object. Publishing an
                    // identity slot with no producer instead would leave every
                    // reference to that type without a value.
                    if node.kind() == "type_definition"
                        && let Some(target) = node.child_by_field_name("type")
                        && !has_opaque_modifier(node)
                    {
                        let slot = self.add_slot(site, ResolutionTypeSlotRole::TargetTypeIdentity);
                        self.facts
                            .declaration_type_slots
                            .push(DeclarationTypeSlotFact {
                                declaration: site,
                                slot,
                                role: DeclarationTypeRole::Identity,
                            });
                        self.pending_type_aliases.push((site, slot, target));
                    }
                    let visibility_eligible = kind == ResolutionSiteKind::TypeDeclaration
                        || namespace == ResolutionNamespace::Type
                        || namespace == ResolutionNamespace::Callable
                        || (member_kind == Some(ResolutionMemberKind::Field)
                            && type_owner.is_some()
                            && self.scope(scope).kind == ResolutionScopeKind::TypeBody);
                    if visibility_eligible {
                        self.publish_declaration_visibility(site, declaration, source_declarations);
                    }
                } else if node.kind() == "package_object" {
                    // The incumbent Scala declaration model projects package
                    // object members directly into the package. Preserve the
                    // package object itself as a native source declaration too.
                    self.declaration_sources.push((site, declaration));
                } else {
                    // A declaration the parser indexes no unit for (a local `def`,
                    // `type` or class) is still a lexical binder.
                    self.publish_unitless_declaration(
                        site,
                        declaration,
                        if matches!(node.kind(), "val_declaration" | "var_declaration") {
                            DeclarationKind::LocalVariable
                        } else {
                            DeclarationKind::BlockLocalItem
                        },
                    );
                }
                self.publish_declaration_binder(
                    node,
                    site,
                    scope,
                    type_owner,
                    namespace,
                    binder,
                    member_kind,
                );
                if matches!(node.kind(), "val_declaration" | "var_declaration") {
                    self.add_declared_value_slot(
                        site,
                        DeclarationTypeRole::Value,
                        node.child_by_field_name("type"),
                    );
                }
            }
        }
        first_site
    }

    /// Constructors share the JVM constructor namespace and publication rules.
    /// A primary constructor has its own parser declaration when parameters are
    /// written; an unwritten zero-argument constructor is anchored at its class.
    fn finish_constructors(
        &mut self,
        root: Node<'source>,
        parsed: &ParsedFile,
        source_declarations: &brokk_bifrost_core::analyzer::scala_facts::ScalaSourceFacts,
    ) {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
            let primary = matches!(node.kind(), "class_definition" | "full_enum_case");
            let auxiliary = node.kind() == "function_definition"
                && declaration_name(node)
                    .is_some_and(|name| node_text(name, self.source) == "this");
            if !primary && !auxiliary {
                continue;
            }
            let Some(&declared) = self.declaration_sites.get(&node.id()) else {
                continue;
            };
            let (site, owner, scope) = if primary {
                let scope = self.scopes_by_node[&node.id()];
                let site =
                    self.add_site_distinct(node, ResolutionSiteKind::ConstructorDeclaration, scope);
                let occurrence = self.collector.intern_node(node);
                let modifier =
                    crate::scala::graph::syntax::scala_primary_constructor_modifier(node);
                let modifier_occurrence =
                    modifier.map(|modifier| self.collector.intern_node(modifier));
                let source = if let Some((constructor, unit)) = parsed
                    .source_declaration_units
                    .iter()
                    .find(|(source, unit)| {
                        let declaration = self.collector.declaration(*source);
                        (declaration.occurrence == occurrence
                            || Some(declaration.occurrence) == modifier_occurrence)
                            && declaration.name.is_none()
                            && unit.is_function()
                    }) {
                    self.facts
                        .definition_units
                        .push(ResolutionDefinitionUnitFact {
                            declaration: site,
                            unit: unit.clone(),
                        });
                    *constructor
                } else {
                    self.declaration_sources
                        .iter()
                        .find_map(|(class, source)| (*class == declared).then_some(*source))
                        .expect("a Scala class already has its source declaration")
                };
                self.declaration_sources.push((site, source));
                let source_node =
                    if Some(self.collector.declaration(source).occurrence) == modifier_occurrence {
                        modifier.expect("a modifier-anchored constructor has its modifier")
                    } else {
                        node
                    };
                self.declaration_nodes.insert(site, source_node);
                self.publish_declaration_visibility(site, source, source_declarations);
                self.facts
                    .callable_signatures
                    .push(ResolutionCallableSignatureFact {
                        callable: site,
                        type_parameter_count: 0,
                        result_types: Vec::new(),
                    });
                let mut ordinal = 0;
                for (list_ordinal, list) in super::declarations::scala_class_parameter_lists(node)
                    .into_iter()
                    .enumerate()
                {
                    let list_ordinal =
                        u32::try_from(list_ordinal).expect("Scala constructor lists fit u32");
                    self.facts
                        .callable_parameter_lists
                        .push(ResolutionCallableParameterListFact {
                            callable: site,
                            list_ordinal,
                            contextual: scala_parameter_list_is_contextual(list),
                        });
                    let mut cursor = list.walk();
                    for parameter in list.named_children(&mut cursor).filter(|parameter| {
                        matches!(parameter.kind(), "class_parameter" | "parameter")
                    }) {
                        let Some(name) = parameter.child_by_field_name("name") else {
                            self.gap(site, ResolutionGapKind::UnsupportedCallApplicability);
                            continue;
                        };
                        let Some(&parameter_site) = self.sites_by_node.get(&name.id()) else {
                            self.gap(site, ResolutionGapKind::UnsupportedCallApplicability);
                            continue;
                        };
                        let existing = self
                            .facts
                            .declaration_type_slots
                            .iter()
                            .find(|slot| slot.declaration == parameter_site)
                            .map(|slot| slot.slot);
                        let value_type = existing.unwrap_or_else(|| {
                            self.add_declared_value_slot(
                                parameter_site,
                                DeclarationTypeRole::Parameter,
                                parameter.child_by_field_name("type"),
                            )
                        });
                        self.publish_callable_parameter(
                            site,
                            parameter_site,
                            parameter,
                            value_type,
                            list_ordinal,
                            ordinal,
                        );
                        ordinal += 1;
                    }
                }
                (site, declared, scope)
            } else {
                let scope = self.facts.sites[declared.index()].scope;
                let Some(owner) = self.scope(scope).owner else {
                    self.gap(declared, ResolutionGapKind::UnsupportedScopeOrBinder);
                    continue;
                };
                self.facts.sites[declared.index()].kind =
                    ResolutionSiteKind::ConstructorDeclaration;
                self.facts
                    .identifiers
                    .retain(|identifier| identifier.site != declared);
                self.facts
                    .binders
                    .retain(|binder| binder.declaration != declared);
                self.facts
                    .member_owners
                    .retain(|member| member.member != declared);
                (declared, owner, scope)
            };
            let owner_name = self
                .facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.site == owner
                        && identifier.role == ResolutionIdentifierRole::Declaration
                })
                .expect("Scala constructor owner has a name")
                .name;
            ConstructorSite {
                site,
                owner,
                owner_name,
                scope,
            }
            .publish(&mut self.facts);
        }
    }

    fn publish_callable_parameter(
        &mut self,
        callable: ResolutionSiteId,
        parameter: ResolutionSiteId,
        node: Node<'source>,
        value_type: ResolutionTypeSlotId,
        list_ordinal: u32,
        ordinal: u32,
    ) {
        self.facts
            .callable_parameters
            .push(ResolutionCallableParameterFact {
                callable,
                list_ordinal,
                ordinal,
                parameter,
                value_type,
                repeated: contains_kind(node, "repeated_parameter_type"),
            });
        let name = node
            .child_by_field_name("name")
            .expect("named Scala callable parameter");
        let label = self.intern_name(node_text(name, self.source));
        self.facts
            .callable_parameter_semantics
            .push(ResolutionCallableParameterSemanticsFact {
                callable,
                parameter,
                list_ordinal,
                ordinal,
                label,
                has_default: has_field_descendant(node, "default_value"),
            });
    }

    fn lower_anonymous_type(
        &mut self,
        instance: Node<'source>,
        scope: ResolutionScopeId,
        parsed: &ParsedFile,
    ) {
        let mut cursor = instance.walk();
        let Some(body) = instance
            .named_children(&mut cursor)
            .find(|child| matches!(child.kind(), "template_body" | "with_template_body"))
        else {
            return;
        };
        let occurrence = self.collector.intern_node(instance);
        let declaration = self.collector.declare(occurrence, None);
        let unit = parsed
            .source_declaration_units
            .iter()
            .find_map(|(source, unit)| {
                (*source == declaration && unit.is_class() && unit.is_synthetic()).then_some(unit)
            })
            .expect("an anonymous Scala template has its source-backed owner");
        let site = self.add_site(body, ResolutionSiteKind::TypeDeclaration, scope);
        let name = self.intern_name(unit.identifier());
        self.facts.identifiers.push(PositionedIdentifierFact {
            site,
            name,
            role: ResolutionIdentifierRole::Declaration,
            namespace: ResolutionNamespace::Type,
            qualifier: None,
        });
        self.declaration_sites.insert(instance.id(), site);
        self.declaration_nodes.insert(site, instance);
        self.declaration_sources.push((site, declaration));
        self.facts
            .definition_units
            .push(ResolutionDefinitionUnitFact {
                declaration: site,
                unit: unit.clone(),
            });
    }

    /// The visibility the source facts give a declaration. A declaration they
    /// do not describe is `Unknown`.
    fn source_visibility(
        declaration: SourceDeclarationId,
        source_declarations: &brokk_bifrost_core::analyzer::scala_facts::ScalaSourceFacts,
    ) -> DeclaredVisibility {
        use brokk_bifrost_core::analyzer::scala_facts::ScalaDeclarationVisibility;
        source_declarations
            .declarations
            .iter()
            .find(|fact| fact.declaration == declaration)
            .map(|fact| match fact.visibility {
                ScalaDeclarationVisibility::Public => DeclaredVisibility::Public,
                ScalaDeclarationVisibility::Protected => DeclaredVisibility::Protected,
                ScalaDeclarationVisibility::NonApi => DeclaredVisibility::Private,
            })
            .unwrap_or(DeclaredVisibility::Unknown)
    }

    fn finish_access_boundaries(
        &mut self,
        root: Node<'source>,
        source: &brokk_bifrost_core::analyzer::scala_facts::ScalaSourceFacts,
    ) {
        use brokk_bifrost_core::analyzer::source_facts::DeclarationAccessBoundary;
        let template_sites = self
            .facts
            .scopes
            .iter()
            .filter(|scope| scope.kind == ResolutionScopeKind::TypeBody)
            .filter_map(|scope| scope.owner)
            .collect::<HashSet<_>>();
        let templates = self
            .declaration_sources
            .iter()
            .filter(|(site, _)| template_sites.contains(site))
            .map(|(site, source)| (*source, *site))
            .collect::<HashMap<_, _>>();
        let mut declarations = HashMap::default();
        for &(site, declaration) in &self.declaration_sources {
            let Some(node) = self.declaration_nodes.get(&site) else {
                continue;
            };
            if node_range(*node)
                != self
                    .collector
                    .occurrence(self.collector.declaration(declaration).occurrence)
                    .range
            {
                continue;
            }
            // An unwritten constructor shares its class's source declaration.
            // The authored declaration remains the canonical modifier owner.
            if self.declaration_sites.get(&node.id()) == Some(&site) {
                declarations.insert(declaration, site);
            } else {
                declarations.entry(declaration).or_insert(site);
            }
        }
        let mut pending = Vec::new();
        let mut qualifier_references = HashSet::default();
        for fact in &source.declarations {
            let Some(&site) = declarations.get(&fact.declaration) else {
                continue;
            };
            let Some(&node) = self.declaration_nodes.get(&site) else {
                continue;
            };
            let modifier_owner = if self.facts.sites[site.index()].kind
                == ResolutionSiteKind::ConstructorDeclaration
                && matches!(node.kind(), "class_definition" | "full_enum_case")
            {
                let Some(modifier) =
                    crate::scala::graph::syntax::scala_primary_constructor_modifier(node)
                else {
                    continue;
                };
                modifier
            } else {
                node
            };
            let Some(qualifier) =
                crate::scala::graph::syntax::scala_access_qualifier(modifier_owner)
            else {
                continue;
            };
            // Both dialects use the ordinary access modifier for [this]. Scala
            // 2's extra instance restriction rejects invalid code but does not
            // change the declaration named by any valid program.
            if node_text(qualifier, self.source) == "this" {
                continue;
            }
            let publish_reference = qualifier_references.insert(qualifier.id());
            let scope = self.facts.sites[site.index()].scope;
            let boundary = match &fact.access_boundary {
                Some(DeclarationAccessBoundary::Package(package)) => {
                    DeclarationAccessBoundary::Package(package.clone())
                }
                Some(DeclarationAccessBoundary::Template(owner)) => {
                    let target = *templates
                        .get(owner)
                        .expect("an enclosing template has a native declaration");
                    DeclarationAccessBoundary::Template(target)
                }
                None => {
                    // This is a missing lexical owner, independent of the
                    // coarse modifier's access obligation. Ordinary private
                    // access must not discharge invalid-qualifier evidence.
                    {
                        let classified_route = ResolutionRouteGap::UnknownAlias {
                            owner: ResolutionRouteOwner::DeclarationAccess(site),
                            binary_owner: self.binary_owner_prefix(scope),
                            name: None,
                            kind: None,
                        };
                        self.facts.add_route_gap(site, classified_route);
                    };
                    if !publish_reference {
                        continue;
                    }
                    let reference =
                        self.add_site(qualifier, ResolutionSiteKind::ValueReference, scope);
                    self.identifier(
                        reference,
                        qualifier,
                        ResolutionIdentifierRole::Reference,
                        ResolutionNamespace::Value,
                        None,
                    );
                    {
                        let classified_route = ResolutionRouteGap::UnknownAlias {
                            owner: ResolutionRouteOwner::DeclarationAccess(site),
                            binary_owner: self.binary_owner_prefix(scope),
                            name: None,
                            kind: None,
                        };
                        self.facts.add_route_gap(reference, classified_route);
                    };
                    self.facts
                        .reference_owners
                        .push(ResolutionReferenceOwnerFact {
                            reference,
                            owner: Some(site),
                        });
                    self.facts.lexical_owner_references.push(
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionLexicalOwnerReferenceFact {
                            reference,
                            declaration: None,
                        },
                    );
                    continue;
                }
            };
            // Some non-public fields previously had no access row at all.
            // Publish their unchanged modifier so the explicit region can be
            // checked, instead of dropping that region on a field declaration.
            if !self
                .facts
                .declaration_visibilities
                .iter()
                .any(|row| row.declaration == site)
            {
                self.publish_visibility_rows(
                    site,
                    Self::source_visibility(fact.declaration, source),
                );
            }
            self.facts.declaration_access_boundaries.push(
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionDeclarationAccessBoundaryFact { declaration: site, boundary: boundary.clone() }
            );
            if publish_reference {
                pending.push((site, qualifier, scope, boundary));
            }
        }
        // Every native projection of one source declaration shares its region.
        // The source producer adds generated companion facts after extraction
        // by inheriting the case class/enum fact. Mirror that same inheritance
        // before projecting source boundaries onto all native declarations.
        let mut source_boundaries = source
            .declarations
            .iter()
            .filter_map(|fact| {
                let boundary = match fact.access_boundary.as_ref()? {
                    DeclarationAccessBoundary::Package(package) => {
                        DeclarationAccessBoundary::Package(package.clone())
                    }
                    DeclarationAccessBoundary::Template(owner) => {
                        DeclarationAccessBoundary::Template(templates[owner])
                    }
                };
                Some((
                    fact.declaration,
                    (boundary, Self::source_visibility(fact.declaration, source)),
                ))
            })
            .collect::<HashMap<_, _>>();
        for definition in &self.facts.definition_units {
            if !definition.unit.is_synthetic() {
                continue;
            }
            let Some(class) = self.facts.singleton_relations.iter().find_map(|relation| {
                (relation.declaration == definition.declaration && relation.kind ==
                    brokk_bifrost_core::analyzer::resolution_facts::ResolutionSingletonRelationKind::Companion)
                    .then_some(relation.enclosing_type).flatten()
            }) else { continue; };
            let companion_source = self
                .declaration_sources
                .iter()
                .find_map(|(site, source)| (*site == definition.declaration).then_some(*source))
                .expect("a generated companion has source authority");
            if source
                .declarations
                .iter()
                .any(|fact| fact.declaration == companion_source)
            {
                continue;
            }
            let class_source = self
                .declaration_sources
                .iter()
                .find_map(|(site, source)| (*site == class).then_some(*source))
                .expect("a generated companion has its class source authority");
            if let Some(boundary) = source_boundaries.get(&class_source).cloned() {
                assert!(
                    source_boundaries
                        .insert(companion_source, boundary)
                        .is_none()
                );
            }
        }
        for (site, declaration) in self.declaration_sources.clone() {
            let Some((boundary, visibility)) = source_boundaries.get(&declaration) else {
                continue;
            };
            if let Some(existing) = self
                .facts
                .declaration_access_boundaries
                .iter()
                .find(|row| row.declaration == site)
            {
                assert_eq!(&existing.boundary, boundary);
                continue;
            }
            if !self
                .facts
                .declaration_visibilities
                .iter()
                .any(|row| row.declaration == site)
            {
                self.publish_visibility_rows(site, *visibility);
            }
            self.facts.declaration_access_boundaries.push(
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionDeclarationAccessBoundaryFact {
                    declaration: site, boundary: boundary.clone(),
                }
            );
            self.facts.gaps.retain(|gap| {
                gap.site != site || gap.kind != ResolutionGapKind::UnsupportedVisibility
            });
        }
        let mut package_targets = HashMap::default();
        for (owner, qualifier, scope, boundary) in pending {
            let target = match boundary {
                DeclarationAccessBoundary::Template(target) => target,
                DeclarationAccessBoundary::Package(package) => {
                    if let Some(&target) = package_targets.get(&package) {
                        target
                    } else {
                        // Recover the already selected package owner from AST
                        // package segments. No import/type namespace participates.
                        let mut clauses = root
                            .named_children(&mut root.walk())
                            .filter(|node| {
                                node.kind() == "package_clause"
                                    && node.child_by_field_name("body").is_none()
                                    && node.start_byte() <= qualifier.start_byte()
                            })
                            .collect::<Vec<_>>();
                        let node = self.declaration_nodes[&owner];
                        clauses.extend(package_ancestor_nodes(node));
                        clauses.sort_unstable_by_key(Node::start_byte);
                        clauses.dedup_by_key(|node| node.id());
                        let mut path = Vec::new();
                        let mut selected = None;
                        for clause in clauses {
                            if let Some(name) = clause.child_by_field_name("name") {
                                for segment in package_name_nodes(name) {
                                    path.push(node_text(segment, self.source));
                                    if path.join(".") == package {
                                        selected = Some(segment);
                                    }
                                }
                            }
                        }
                        let segment = selected.expect(
                            "a source-selected package boundary has an AST package segment",
                        );
                        let target = self.add_site_distinct(
                            segment,
                            ResolutionSiteKind::PackageDeclaration,
                            self.root_scope,
                        );
                        self.identifier(
                            target,
                            segment,
                            ResolutionIdentifierRole::Declaration,
                            ResolutionNamespace::Package,
                            None,
                        );
                        let declaration = self.collector.declare_node(segment, Some(segment));
                        self.publish_unitless_declaration(
                            target,
                            declaration,
                            DeclarationKind::BlockLocalItem,
                        );
                        package_targets.insert(package, target);
                        target
                    }
                }
            };
            let namespace = self
                .facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.site == target
                        && identifier.role == ResolutionIdentifierRole::Declaration
                })
                .expect("an owner has its declaration identifier")
                .namespace;
            let reference = self.add_site(qualifier, ResolutionSiteKind::TypeReference, scope);
            self.identifier(
                reference,
                qualifier,
                ResolutionIdentifierRole::Reference,
                namespace,
                None,
            );
            self.facts
                .reference_owners
                .push(ResolutionReferenceOwnerFact {
                    reference,
                    owner: Some(owner),
                });
            self.facts.lexical_owner_references.push(brokk_bifrost_core::analyzer::resolution_facts::ResolutionLexicalOwnerReferenceFact { reference, declaration: Some(target) });
        }
    }

    fn publish_visibility_rows(&mut self, site: ResolutionSiteId, visibility: DeclaredVisibility) {
        self.facts.visibility_eligibilities.push(
            brokk_bifrost_core::analyzer::resolution_facts::ResolutionVisibilityEligibilityFact {
                declaration: site,
            },
        );
        self.facts
            .declaration_visibilities
            .push(ResolutionDeclarationVisibilityFact {
                declaration: site,
                visibility,
            });
    }

    /// Publish the declaration's exact visibility for the shared JVM access
    /// rule. The selected access policy decides Scala private/protected scope.
    fn publish_declaration_visibility(
        &mut self,
        site: ResolutionSiteId,
        declaration: SourceDeclarationId,
        source_declarations: &brokk_bifrost_core::analyzer::scala_facts::ScalaSourceFacts,
    ) {
        let visibility = Self::source_visibility(declaration, source_declarations);
        self.publish_visibility_rows(site, visibility);
        if visibility == DeclaredVisibility::Unknown {
            // Recovered declarations can have a native lexical binder without
            // a parser visibility fact. Their constructors must retain that
            // uncertainty rather than publishing an unsupported access proof.
            self.gap(site, ResolutionGapKind::UnsupportedVisibility);
        }
    }

    /// An anonymous given is a term the compiler names from its type, so a
    /// reference can only reach it through that synthesized name. Publish it
    /// as an exact callable declaration under the synthesized name. Its
    /// binder, signature and definition are not modeled, so the declaration
    /// carries an omitted-binder gap: lookups of that one name stay open and
    /// every other lookup in the scope stays exact. A type shape the naming
    /// rule does not cover leaves the binder unnamed, which opens the whole
    /// scope instead.
    fn lower_anonymous_given(
        &mut self,
        node: Node<'source>,
        scope: ResolutionScopeId,
        type_owner: Option<ResolutionSiteId>,
    ) -> Option<ResolutionSiteId> {
        let name = scala_anonymous_given_name(node, self.source);
        let site = self.add_site(
            node,
            if name.is_some() {
                ResolutionSiteKind::CallableDeclaration
            } else {
                ResolutionSiteKind::UnsupportedDeclaration
            },
            scope,
        );
        self.gap(site, ResolutionGapKind::UnsupportedScopeOrBinder);
        self.facts
            .reference_enumeration_gaps
            .push(ResolutionReferenceEnumerationGapFact {
                site,
                kind: ResolutionGapKind::UnsupportedScopeOrBinder,
            });
        let name = name?;
        self.declaration_sites.insert(node.id(), site);
        self.declaration_nodes.insert(site, node);
        let name = self.intern_name(&name);
        self.facts.identifiers.push(PositionedIdentifierFact {
            site,
            name,
            role: ResolutionIdentifierRole::Declaration,
            namespace: ResolutionNamespace::Callable,
            qualifier: None,
        });
        self.publish_declaration_binder(
            node,
            site,
            scope,
            type_owner,
            ResolutionNamespace::Callable,
            Some(ResolutionBinderKind::Callable),
            Some(ResolutionMemberKind::Method),
        );
        Some(site)
    }

    /// Publish the lexical binder and ownership facts of a declaration whose
    /// identifier is already positioned: its binder, extra namespaces, member
    /// or root-export row, and callable shape.
    #[allow(clippy::too_many_arguments)]
    fn publish_declaration_binder(
        &mut self,
        node: Node<'source>,
        site: ResolutionSiteId,
        scope: ResolutionScopeId,
        type_owner: Option<ResolutionSiteId>,
        namespace: ResolutionNamespace,
        binder: Option<ResolutionBinderKind>,
        member_kind: Option<ResolutionMemberKind>,
    ) {
        let scope_fact = self.scope(scope);
        let (binder_kind, hoisting) = match binder {
            Some(ResolutionBinderKind::Field) if type_owner.is_some() => {
                (ResolutionBinderKind::Field, HoistingClass::ScopeWide)
            }
            Some(ResolutionBinderKind::Local) => {
                (ResolutionBinderKind::Local, HoistingClass::SourceOrder)
            }
            Some(kind) => (kind, HoistingClass::ScopeWide),
            None => unreachable!(),
        };
        self.facts.binders.push(ResolutionBinderFact {
            declaration: site,
            scope,
            kind: binder_kind,
            hoisting,
            activation_start: if hoisting == HoistingClass::SourceOrder {
                node.end_byte()
            } else {
                scope_fact.start_byte
            },
            activation_end: scope_fact.end_byte,
        });
        if node.kind() == "object_definition" {
            self.facts.additional_definition_namespaces.push(
                ResolutionAdditionalDefinitionNamespaceFact {
                    declaration: site,
                    namespace: ResolutionNamespace::Value,
                    hoisting,
                },
            );
        }
        if let Some(type_owner) = type_owner
            && let Some(member_kind) = member_kind
            && self.scope(scope).kind == ResolutionScopeKind::TypeBody
        {
            let (access, compatibility) = self.member_access(type_owner, member_kind);
            self.facts.member_owners.push(ResolutionMemberOwnerFact {
                member: site,
                owner: type_owner,
                kind: member_kind,
                access,
                qualifier_compatibility: compatibility,
            });
        } else if node.kind() != "package_object"
            && matches!(
                self.scope(scope).kind,
                ResolutionScopeKind::CompilationUnit | ResolutionScopeKind::Package
            )
        {
            self.facts.root_exports.push(ResolutionRootExportFact {
                root_scope: scope,
                declaration: site,
                namespace,
            });
        }
        if namespace == ResolutionNamespace::Callable {
            self.facts
                .callable_signatures
                .push(ResolutionCallableSignatureFact {
                    callable: site,
                    type_parameter_count: type_parameter_count(node),
                    result_types: Vec::new(),
                });
            self.next_parameter_ordinal.insert(site, 0);
            let mut cursor = node.walk();
            for (ordinal, parameters) in node
                .children_by_field_name("parameters", &mut cursor)
                .filter(|child| child.kind() == "parameters")
                .enumerate()
            {
                let list_ordinal =
                    u32::try_from(ordinal).expect("Scala callable parameter-list count fits u32");
                self.parameter_list_ordinals
                    .insert(parameters.id(), list_ordinal);
                self.facts
                    .callable_parameter_lists
                    .push(ResolutionCallableParameterListFact {
                        callable: site,
                        list_ordinal,
                        contextual: scala_parameter_list_is_contextual(parameters),
                    });
            }
        }
    }

    /// A lexical binder with no parser unit (a local `def` or `type`, a type
    /// parameter, a parameter, a pattern variable) is still a located
    /// declaration: it is bridged to its source site and marked lexical, so a
    /// reference to it resolves to it exactly, as Kotlin and Go publish theirs.
    fn publish_unitless_declaration(
        &mut self,
        site: ResolutionSiteId,
        declaration: SourceDeclarationId,
        kind: DeclarationKind,
    ) {
        self.declaration_sources.push((site, declaration));
        self.collector.mark_lexical(declaration, kind);
    }

    /// How a member of `owner` is selected. A nested type belongs to the type.
    /// An `object` is a value as well as a type, so its methods and fields are
    /// reached through the object (`Owner.member`) or a value of it. The
    /// members of any other template need an instance.
    fn member_access(
        &self,
        owner: ResolutionSiteId,
        kind: ResolutionMemberKind,
    ) -> (
        ResolutionMemberAccess,
        ResolutionMemberQualifierCompatibility,
    ) {
        let singleton = self
            .declaration_nodes
            .get(&owner)
            .is_some_and(|node| node.kind() == "object_definition");
        match kind {
            ResolutionMemberKind::NestedType => (
                ResolutionMemberAccess::Type,
                ResolutionMemberQualifierCompatibility::TypeOnly,
            ),
            ResolutionMemberKind::Method | ResolutionMemberKind::Field if singleton => (
                ResolutionMemberAccess::Type,
                ResolutionMemberQualifierCompatibility::RuntimeOrType,
            ),
            _ => (
                ResolutionMemberAccess::Instance,
                ResolutionMemberQualifierCompatibility::RuntimeOnly,
            ),
        }
    }

    /// The type body scope of the template whose body contains `this`, or
    /// `None` when that template has no published declaration of its own.
    fn this_type_body_scope(&self, this: Node<'source>) -> Option<ResolutionScopeId> {
        let mut current = this.parent();
        while let Some(node) = current {
            if matches!(node.kind(), "template_body" | "with_template_body") {
                if let Some(scope) = self.scopes_by_node.get(&node.id()) {
                    return Some(*scope);
                }
                let template = node.parent().filter(|template| {
                    matches!(
                        template.kind(),
                        "class_definition"
                            | "trait_definition"
                            | "object_definition"
                            | "enum_definition"
                    )
                })?;
                return self.scopes_by_node.get(&template.id()).copied();
            }
            current = node.parent();
        }
        None
    }

    fn lower_occurrence(
        &mut self,
        node: Node<'source>,
        scope: ResolutionScopeId,
        owner: Option<ResolutionSiteId>,
        type_owner: Option<ResolutionSiteId>,
        parsed: &ParsedFile,
        source_declarations: &brokk_bifrost_core::analyzer::scala_facts::ScalaSourceFacts,
    ) {
        // The self-type header's first child is a template alias declaration,
        // not a reference. Its ascription is lowered normally; the alias is
        // published after all of those reference projections are available.
        if node.parent().is_some_and(|parent| {
            parent.kind() == "self_type"
                && parent
                    .named_child(0)
                    .is_some_and(|binder| binder.id() == node.id())
        }) {
            return;
        }
        let Some(role) = scala_occurrence_role(node) else {
            return;
        };
        if role == OccurrenceRole::DeclarationName && is_type_parameter_name(node) {
            self.lower_type_parameter(node, scope, parsed);
            return;
        }
        if role == OccurrenceRole::Binder {
            self.lower_binder(node, scope, owner, type_owner, parsed, source_declarations);
            return;
        }
        if role == OccurrenceRole::PathSegment {
            let qualified_root_route = qualified_path_segments_for_prefix(node)
                .and_then(|segments| {
                    segments
                        .last()
                        .copied()
                        .map(|terminal| (segments, terminal))
                })
                .and_then(|(segments, terminal)| {
                    let role = scala_occurrence_role(terminal)?;
                    scala_occurrence_namespace(terminal, role, self.source).map(|_| segments)
                })
                .is_some();
            if !qualified_root_route
                && nearest_ancestor(node, "import_declaration").is_none()
                && nearest_ancestor(node, "package_clause").is_none()
                && let Some(chain) = nearest_path_chain(node)
            {
                let route = self.add_site(chain, ResolutionSiteKind::UnsupportedRoute, scope);
                {
                    let classified_route = ResolutionRouteGap::OmittedReference {
                        scope,
                        terminal: terminal_identifier(chain)
                            .map(|terminal| self.intern_name(node_text(terminal, self.source))),
                        namespace: terminal_identifier(chain).and_then(|terminal| {
                            scala_occurrence_role(terminal).and_then(|role| {
                                scala_occurrence_namespace(terminal, role, self.source)
                            })
                        }),
                    };
                    self.facts.add_route_gap(route, classified_route);
                };
                if !self
                    .facts
                    .reference_enumeration_gaps
                    .iter()
                    .any(|gap| gap.site == route)
                {
                    self.facts.reference_enumeration_gaps.push(
                        ResolutionReferenceEnumerationGapFact {
                            site: route,
                            kind: ResolutionGapKind::UnsupportedRoute,
                        },
                    );
                }
            }
            return;
        }
        if node
            .parent()
            .is_some_and(|parent| parent.kind() == "access_qualifier")
        {
            return;
        }
        if self.sites_by_node.contains_key(&node.id())
            || role == OccurrenceRole::DeclarationName
            || role == OccurrenceRole::ImportAlias
            || role == OccurrenceRole::ImportTarget
            || role == OccurrenceRole::LabelOrKey
        {
            return;
        }
        if role == OccurrenceRole::Binder {
            self.lower_binder(node, scope, owner, type_owner, parsed, source_declarations);
            return;
        }
        if is_super_identifier(node, self.source) {
            return;
        }
        let import_ancestor = nearest_ancestor(node, "import_declaration");
        if import_ancestor.is_some() {
            return;
        }
        let Some(namespace) = scala_occurrence_namespace(node, role, self.source) else {
            return;
        };
        let kind = if is_call_target(node) {
            ResolutionSiteKind::CallableReference
        } else {
            match namespace {
                ResolutionNamespace::Type => ResolutionSiteKind::TypeReference,
                ResolutionNamespace::Callable => ResolutionSiteKind::CallableReference,
                _ if role == OccurrenceRole::MemberPosition => ResolutionSiteKind::MemberReference,
                _ => ResolutionSiteKind::ValueReference,
            }
        };
        let receiver = if role == OccurrenceRole::MemberPosition {
            node.parent()
                .filter(|parent| parent.kind() == "field_expression")
                .and_then(|parent| parent.child_by_field_name("value"))
        } else {
            None
        };
        let qualified_segments = if matches!(
            namespace,
            ResolutionNamespace::Type
                | ResolutionNamespace::Value
                | ResolutionNamespace::TypeOrValue
        ) || (namespace == ResolutionNamespace::Callable
            && is_call_target(node))
        {
            qualified_path_segments(node, self.source)
        } else {
            None
        }
        .filter(|_| !receiver.is_some_and(|receiver| is_this_identifier(receiver, self.source)));
        // `this.member` looks the member up in the body of the template that
        // contains `this`, with no qualifier value, as Java and Kotlin do.
        let this_scope = receiver
            .filter(|receiver| is_this_identifier(*receiver, self.source))
            .and_then(|receiver| self.this_type_body_scope(receiver));
        let namespace = if this_scope.is_some() && namespace == ResolutionNamespace::TypeOrValue {
            ResolutionNamespace::Value
        } else {
            namespace
        };
        // A stable path is a typed member chain beside its package
        // interpretation, exactly as Java's scoped type is: the terminal is a
        // member of what its qualifier names. A type path stays in the Type
        // namespace. A term path (an extractor head, a singleton type's path)
        // names a type object or a value at every segment, so it is a
        // type-or-value path. A projection `Owner#Member` keeps its root route
        // only.
        let namespace = if qualified_segments.is_some()
            && namespace != ResolutionNamespace::Type
            && !(is_call_target(node) && namespace == ResolutionNamespace::Callable)
        {
            ResolutionNamespace::TypeOrValue
        } else {
            namespace
        };
        let qualified_anchor = qualified_segments
            .as_ref()
            .map(|segments| scala_qualified_path_anchor(segments, self.source));
        let qualified_route_segments = qualified_segments.as_ref().map(|segments| {
            if qualified_anchor == Some(ResolutionRootImportAnchor::Absolute) {
                &segments[1..]
            } else {
                segments.as_slice()
            }
        });
        let mut qualifier = None;
        let mut qualified_prefix = None;
        let mut kind = kind;
        if let Some(segments) = qualified_route_segments {
            // Keep the terminal's type role so prefix lowering can retain the
            // ordinary lexical lookup of a stable type-path head.
            let prefix_namespace =
                if is_call_target(node) && namespace == ResolutionNamespace::Callable {
                    ResolutionNamespace::TypeOrValue
                } else {
                    namespace
                };
            if segments.len() > 1 && qualified_anchor != Some(ResolutionRootImportAnchor::Absolute)
            {
                let (prefix, chain_qualifier) = self.lower_qualified_prefixes(
                    segments,
                    scope,
                    owner,
                    prefix_namespace,
                    qualified_anchor.expect("qualified path has an anchor"),
                    !is_projected_selector(node),
                );
                qualified_prefix = Some(prefix);
                if let Some(chain_qualifier) = chain_qualifier {
                    qualifier = Some(chain_qualifier);
                    kind = ResolutionSiteKind::MemberReference;
                }
            }
        }
        // `super.member` is an up-call answered by the enclosing template's
        // parent linearization, never by its own override. The receiver is a
        // type identity, not a value `super` declares, so it must not lower as
        // an ordinary expression reference. Its identity slots are connected
        // once the walk has published the template's supertype edges.
        let super_receiver = if qualifier.is_none() && this_scope.is_none() {
            receiver.filter(|receiver| is_super_identifier(*receiver, self.source))
        } else {
            None
        };
        if qualifier.is_none()
            && this_scope.is_none()
            && super_receiver.is_none()
            && let Some(receiver) = receiver
        {
            qualifier = Some(self.expression_slot(receiver, scope));
        }
        let site = self.add_site(node, kind, this_scope.unwrap_or(scope));
        if let Some(receiver) = super_receiver {
            qualifier = Some(self.super_receiver_slot(receiver, site));
        }
        if this_scope.is_some() {
            self.current_instance_members.insert(site);
        }
        self.identifier(
            site,
            node,
            ResolutionIdentifierRole::Reference,
            namespace,
            qualifier,
        );
        self.facts
            .reference_owners
            .push(ResolutionReferenceOwnerFact {
                reference: site,
                owner: self.declaration_owner(owner),
            });
        // A reference that reads a value or selects a member is an expression:
        // its value is the declared type of what it binds, so a receiver or an
        // argument written as that reference has a producer.
        let reads_value = matches!(
            kind,
            ResolutionSiteKind::ValueReference | ResolutionSiteKind::MemberReference
        ) && matches!(
            namespace,
            ResolutionNamespace::Value | ResolutionNamespace::TypeOrValue
        ) && match role {
            OccurrenceRole::ValueReference | OccurrenceRole::ReceiverPosition => true,
            OccurrenceRole::MemberPosition => receiver.is_some(),
            _ => false,
        } && !is_this_or_super_identifier(node, self.source);
        if namespace == ResolutionNamespace::Type {
            self.projected_identity_slot(site, namespace);
        } else if reads_value
            || (qualified_segments.is_some() && namespace == ResolutionNamespace::TypeOrValue)
        {
            let value = self.projected_identity_slot(site, namespace);
            self.expression_slots_by_node.insert(node.id(), value);
        }
        if let (Some(segments), Some(anchor)) = (qualified_route_segments, qualified_anchor) {
            if qualifier.is_some() {
                self.gap(site, ResolutionGapKind::AmbiguousQualifiedType);
            }
            self.record_qualified_type_root_reference(
                segments,
                site,
                scope,
                qualified_prefix,
                false,
                anchor,
            );
        }
        if namespace == ResolutionNamespace::Callable {
            self.facts
                .callable_receiver_origins
                .push(ResolutionCallableReceiverOriginFact {
                    reference: site,
                    origin: if this_scope.is_some() {
                        ResolutionCallableReceiverOrigin::CurrentInstance
                    } else {
                        scala_callable_receiver_origin(node)
                    },
                });
        }
        if role == OccurrenceRole::PatternPosition
            && let Some((pattern, invocation)) = pattern_invocation(node)
        {
            // The pattern keeps its own site. The extractor role belongs to the
            // head reference, as a call's role belongs to its callee: the head
            // is what a reader resolves, and the pattern's arguments are other
            // references that carry no role.
            self.add_site(pattern, ResolutionSiteKind::Pattern, scope);
            self.facts
                .invocation_roles
                .push(ResolutionInvocationRoleFact {
                    site,
                    role: if contains_kind(pattern, "repeat_pattern") {
                        ResolutionInvocationRole::UnapplySeq
                    } else {
                        invocation
                    },
                    receiver: None,
                    result: None,
                });
        }
    }

    fn lower_type_parameter(
        &mut self,
        node: Node<'source>,
        scope: ResolutionScopeId,
        parsed: &ParsedFile,
    ) {
        let site = self.add_site(node, ResolutionSiteKind::TypeDeclaration, scope);
        self.identifier(
            site,
            node,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
            None,
        );
        let occurrence = self.collector.intern_node(node);
        let declaration = self.collector.declare(occurrence, Some(occurrence));
        if parsed
            .source_declaration_units
            .iter()
            .any(|(source, _)| *source == declaration)
        {
            self.declaration_sources.push((site, declaration));
        } else {
            self.publish_unitless_declaration(site, declaration, DeclarationKind::Parameter);
        }
        let slot = self.add_slot(site, ResolutionTypeSlotRole::TargetTypeIdentity);
        self.facts
            .declaration_type_slots
            .push(DeclarationTypeSlotFact {
                declaration: site,
                slot,
                role: DeclarationTypeRole::Identity,
            });
        let scope_fact = self.scope(scope);
        self.facts.binders.push(ResolutionBinderFact {
            declaration: site,
            scope,
            kind: ResolutionBinderKind::Type,
            hoisting: HoistingClass::ScopeWide,
            activation_start: scope_fact.start_byte,
            activation_end: scope_fact.end_byte,
        });
        // Match Go's generic-formal frontier: the identity slot is stable,
        // while its concrete type remains unknown until a call supplies an
        // explicit positional type argument.
        self.facts
            .add_gap(site, ResolutionGapKind::UnsupportedExpressionType);
    }

    fn finish_generic_formals(&mut self) {
        let signatures = self.facts.callable_signatures.clone();
        for signature in signatures {
            if signature.type_parameter_count == 0 {
                continue;
            }
            let Some(owner_node) = self.declaration_nodes.get(&signature.callable).copied() else {
                // Compiler-synthesized case-class callables share the class's
                // parameter declarations; the persisted relation assigns each
                // formal declaration to one callable owner.
                continue;
            };
            let parameters = owner_node
                .child_by_field_name("type_parameters")
                .or_else(|| {
                    let mut cursor = owner_node.walk();
                    owner_node
                        .named_children(&mut cursor)
                        .find(|child| child.kind() == "type_parameters")
                });
            let parameters = parameters.expect("generic Scala callable has type parameters");
            let mut cursor = parameters.walk();
            let names = parameters
                .named_children(&mut cursor)
                .filter_map(|parameter| {
                    if matches!(
                        parameter.kind(),
                        "covariant_type_parameter" | "contravariant_type_parameter"
                    ) {
                        parameter.child_by_field_name("name")
                    } else if field_name_in_parent(parameters, parameter) == Some("name") {
                        Some(parameter)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            assert_eq!(
                names.len(),
                usize::try_from(signature.type_parameter_count)
                    .expect("Scala type parameter count fits usize"),
                "every callable type parameter has a declaration site"
            );
            for (ordinal, node) in names.into_iter().enumerate() {
                let parameter = self
                    .sites_by_node
                    .get(&node.id())
                    .copied()
                    .expect("lowered Scala type parameter has a site");
                self.facts.add_generic_formal(
                    signature.callable,
                    u32::try_from(ordinal).expect("Scala generic formal ordinal fits u32"),
                    parameter,
                );
            }
        }
    }

    fn lower_binder(
        &mut self,
        node: Node<'source>,
        scope: ResolutionScopeId,
        owner: Option<ResolutionSiteId>,
        type_owner: Option<ResolutionSiteId>,
        parsed: &ParsedFile,
        source_declarations: &brokk_bifrost_core::analyzer::scala_facts::ScalaSourceFacts,
    ) {
        let scope_range = self.scope_ranges[scope.index()];
        let Some(activation) = SCALA_STRUCTURAL_SPEC.binding_activation(node, scope_range) else {
            let site = self.add_site(node, ResolutionSiteKind::UnsupportedDeclaration, scope);
            self.gap(site, ResolutionGapKind::UnsupportedScopeOrBinder);
            return;
        };
        let kind = match activation.kind {
            BindingKind::TypeParameter => ResolutionBinderKind::Type,
            BindingKind::Parameter => ResolutionBinderKind::Parameter,
            BindingKind::ImportBinder => ResolutionBinderKind::Import,
            BindingKind::PatternBinder | BindingKind::LoopVariable => ResolutionBinderKind::Pattern,
            BindingKind::CatchOrResource => ResolutionBinderKind::Local,
            BindingKind::Local if type_owner.is_some() && is_member_value(node) => {
                ResolutionBinderKind::Field
            }
            BindingKind::Local => ResolutionBinderKind::Local,
        };
        let namespace = match kind {
            ResolutionBinderKind::Type => ResolutionNamespace::Type,
            ResolutionBinderKind::Import => ResolutionNamespace::Value,
            _ => ResolutionNamespace::Value,
        };
        let site = self.add_site(
            node,
            if kind == ResolutionBinderKind::Type {
                ResolutionSiteKind::TypeDeclaration
            } else {
                ResolutionSiteKind::ValueDeclaration
            },
            scope,
        );
        self.identifier(
            site,
            node,
            ResolutionIdentifierRole::Declaration,
            namespace,
            None,
        );
        let declaration_node = binder_owner_node(node);
        self.declaration_nodes
            .entry(site)
            .or_insert(declaration_node);
        let declaration = self.collector.intern_node(declaration_node);
        let name = self.collector.intern_node(node);
        let source_declaration = self.collector.declare(declaration, Some(name));
        if parsed
            .source_declaration_units
            .iter()
            .any(|(source, _)| *source == source_declaration)
        {
            self.declaration_sources.push((site, source_declaration));
        } else {
            self.publish_unitless_declaration(
                site,
                source_declaration,
                scala_lexical_binder_kind(activation.kind, declaration_node),
            );
        }
        self.facts.binders.push(ResolutionBinderFact {
            declaration: site,
            scope,
            kind,
            hoisting: activation.hoisting,
            activation_start: activation.activation.start_byte,
            activation_end: activation.activation.end_byte,
        });
        // A `val`, `var` or case-class parameter is a field of its class. The
        // declaration facts give exactly those parameters a field unit.
        let class_parameter_field = kind == ResolutionBinderKind::Parameter
            && declaration_node.kind() == "class_parameter"
            && self
                .declaration_sources
                .iter()
                .any(|(declared, _)| *declared == site);
        if (kind == ResolutionBinderKind::Field || class_parameter_field)
            && let Some(type_owner) = type_owner
            && self.scope(scope).kind == ResolutionScopeKind::TypeBody
        {
            let (access, qualifier_compatibility) =
                self.member_access(type_owner, ResolutionMemberKind::Field);
            self.facts.member_owners.push(ResolutionMemberOwnerFact {
                member: site,
                owner: type_owner,
                kind: ResolutionMemberKind::Field,
                access,
                qualifier_compatibility,
            });
            if self
                .declaration_sources
                .iter()
                .any(|(declared, _)| *declared == site)
            {
                // A public member field is visible to an import. One that is
                // not stays without a row, as it was: a lexical lookup inside
                // its own owner needs no visibility, and an import of it stays
                // open.
                let visibility = Self::source_visibility(source_declaration, source_declarations);
                if visibility == DeclaredVisibility::Public {
                    self.publish_visibility_rows(site, visibility);
                }
            }
        } else if kind != ResolutionBinderKind::Parameter
            && matches!(
                self.scope(scope).kind,
                ResolutionScopeKind::CompilationUnit | ResolutionScopeKind::Package
            )
        {
            self.facts.root_exports.push(ResolutionRootExportFact {
                root_scope: scope,
                declaration: site,
                namespace,
            });
        }
        let initializer = binder_initializer(node, declaration_node);
        if kind == ResolutionBinderKind::Parameter
            && nearest_ancestor(node, "lambda_expression").is_none()
            && let Some(callable) = owner
            && self
                .facts
                .callable_signatures
                .iter()
                .any(|row| row.callable == callable)
            && let Some(parameters) = nearest_ancestor(node, "parameters")
            && !has_contextual_parameter_marker(parameters)
            && let Some(&list_ordinal) = self.parameter_list_ordinals.get(&parameters.id())
        {
            let ordinal = self
                .next_parameter_ordinal
                .get(&callable)
                .copied()
                .unwrap_or(0);
            let value_type = self.add_declared_value_slot(
                site,
                DeclarationTypeRole::Parameter,
                declaration_node.child_by_field_name("type"),
            );
            self.publish_callable_parameter(
                callable,
                site,
                declaration_node,
                value_type,
                list_ordinal,
                ordinal,
            );
            self.next_parameter_ordinal.insert(
                callable,
                ordinal
                    .checked_add(1)
                    .expect("Scala parameter count fits u32"),
            );
        } else if let Some(role) = declared_value_role(node, declaration_node) {
            self.add_declared_value_slot(site, role, declaration_node.child_by_field_name("type"));
        } else if let Some(value) =
            initializer.filter(|_| declaration_node.child_by_field_name("type").is_none())
        {
            let slot = self.add_declared_value_slot(site, DeclarationTypeRole::Value, None);
            self.pending_initializers.push((slot, value, scope));
        } else if matches!(
            kind,
            ResolutionBinderKind::Pattern | ResolutionBinderKind::Parameter
        ) {
            // A binder declares a value even when its inferred type is unknown.
            // Keep that declaration evidence without claiming a callable shape.
            let role = if kind == ResolutionBinderKind::Parameter {
                DeclarationTypeRole::Parameter
            } else {
                DeclarationTypeRole::Value
            };
            self.add_declared_value_slot(site, role, None);
        }
        if matches!(
            kind,
            ResolutionBinderKind::Local | ResolutionBinderKind::Pattern
        ) {
            if let Some(value) = initializer {
                let output = self.add_slot(site, ResolutionTypeSlotRole::AssignmentValue);
                self.pending_initializer_values.push((output, value, scope));
            } else if kind == ResolutionBinderKind::Local
                && matches!(declaration_node.kind(), "val_definition" | "var_definition")
                && declaration_node.child_by_field_name("value").is_some()
            {
                // A destructured local receives an unknown component of the
                // initializer. Do not copy the whole tuple or gap the binder.
                assert!(!direct_value_binding(node, declaration_node));
                let incoming =
                    self.add_site_distinct(node, ResolutionSiteKind::UnsupportedExpression, scope);
                assert_ne!(incoming, site);
                self.gap(incoming, ResolutionGapKind::InferredType);
                let input = self.add_slot(incoming, ResolutionTypeSlotRole::ExpressionValue);
                let output = self.add_slot(site, ResolutionTypeSlotRole::AssignmentValue);
                self.facts
                    .type_transfers
                    .push(ResolutionTypeTransferFact::new(
                        input,
                        output,
                        ResolutionTypeTransferKind::Assignment,
                        0,
                        0,
                        ResolutionTypeTransferValueTransform::Preserve,
                    ));
            }
        }
    }

    fn lower_import(&mut self, node: Node<'source>, scope: ResolutionScopeId) {
        let clauses = import_clauses(node);
        if clauses.is_empty() {
            let site = self.add_site(node, ResolutionSiteKind::ImportDeclaration, scope);
            self.facts.add_route_gap(
                site,
                ResolutionRouteGap::UnknownBinder {
                    scope,
                    name: None,
                    namespace: None,
                    may_publish: false,
                },
            );
            self.facts
                .reference_enumeration_gaps
                .push(ResolutionReferenceEnumerationGapFact {
                    site,
                    kind: ResolutionGapKind::UnsupportedRoute,
                });
            return;
        }
        for (mut path, selectors) in clauses {
            let root_anchor = if path
                .first()
                .is_some_and(|segment| node_text(*segment, self.source) == "_root_")
            {
                ResolutionRootImportAnchor::Absolute
            } else {
                ResolutionRootImportAnchor::Lexical
            };
            if root_anchor == ResolutionRootImportAnchor::Absolute {
                path.remove(0);
            }
            if !selectors.is_empty() {
                for selector in selectors {
                    let (source, local, star, unsupported) = match selector.kind() {
                        "identifier" | "operator_identifier" => {
                            (Some(selector), Some(selector), false, false)
                        }
                        "wildcard" | "namespace_wildcard" => (None, None, true, false),
                        "arrow_renamed_identifier" | "as_renamed_identifier" => {
                            let source = selector.child_by_field_name("name");
                            let alias = selector.child_by_field_name("alias");
                            let hidden = alias.is_some_and(|alias| alias.kind() == "wildcard");
                            (source, alias.filter(|_| !hidden), false, hidden)
                        }
                        _ => (None, None, false, true),
                    };
                    let site =
                        self.add_site(selector, ResolutionSiteKind::ImportDeclaration, scope);
                    if unsupported
                        || source.is_none() && !star
                        || path.is_empty() && source.is_none()
                    {
                        {
                            let classified_route = ResolutionRouteGap::UnknownBinder {
                                scope,
                                name: local
                                    .map(|local| self.intern_name(node_text(local, self.source))),
                                namespace: None,
                                may_publish: false,
                            };
                            self.facts.add_route_gap(site, classified_route);
                        };
                        self.facts.reference_enumeration_gaps.push(
                            ResolutionReferenceEnumerationGapFact {
                                site,
                                kind: ResolutionGapKind::UnsupportedRoute,
                            },
                        );
                        continue;
                    }
                    let route_names = path
                        .iter()
                        .map(|segment| self.intern_name(node_text(*segment, self.source)))
                        .collect::<Vec<_>>();
                    self.publish_import_route(ScalaImportRoute {
                        site,
                        scope,
                        anchor: root_anchor,
                        path: &route_names,
                        source,
                        local,
                        star,
                        activation_start: node.end_byte(),
                    });
                    if let Some(source) = source {
                        let mut segments = path.clone();
                        segments.push(source);
                        self.publish_import_reference(&segments, scope, root_anchor);
                    } else {
                        self.publish_import_reference(&path, scope, root_anchor);
                    }
                    let source_name =
                        source.map(|source| self.intern_name(node_text(source, self.source)));
                    let local_name =
                        local.map(|local| self.intern_name(node_text(local, self.source)));
                    self.facts
                        .import_selectors
                        .push(ResolutionImportSelectorFact {
                            site,
                            kind: if star {
                                ResolutionImportSelectorKind::Star
                            } else {
                                ResolutionImportSelectorKind::Named
                            },
                            source_name,
                            local_name,
                        });
                }
                continue;
            }
            if path.is_empty() {
                let site = self.add_site(node, ResolutionSiteKind::ImportDeclaration, scope);
                self.facts.add_route_gap(
                    site,
                    ResolutionRouteGap::UnknownBinder {
                        scope,
                        name: None,
                        namespace: None,
                        may_publish: false,
                    },
                );
                self.facts
                    .reference_enumeration_gaps
                    .push(ResolutionReferenceEnumerationGapFact {
                        site,
                        kind: ResolutionGapKind::UnsupportedRoute,
                    });
                continue;
            }
            let target = path.last().copied().expect("nonempty import path");
            let route_prefix = &path[..path.len() - 1];
            let route_names = route_prefix
                .iter()
                .map(|segment| self.intern_name(node_text(*segment, self.source)))
                .collect::<Vec<_>>();
            let site = self.add_site_distinct(node, ResolutionSiteKind::ImportDeclaration, scope);
            self.publish_import_route(ScalaImportRoute {
                site,
                scope,
                anchor: root_anchor,
                path: &route_names,
                source: Some(target),
                local: Some(target),
                star: false,
                activation_start: node.end_byte(),
            });
            self.publish_import_reference(&path, scope, root_anchor);
            let target_name = self.intern_name(node_text(target, self.source));
            self.facts
                .import_selectors
                .push(ResolutionImportSelectorFact {
                    site,
                    kind: ResolutionImportSelectorKind::Named,
                    source_name: Some(target_name),
                    local_name: Some(target_name),
                });
        }
    }

    fn publish_import_route(&mut self, route: ScalaImportRoute<'_, 'source>) {
        let ScalaImportRoute {
            site,
            scope,
            anchor,
            path,
            source,
            local,
            star,
            activation_start,
        } = route;
        let kind = if star {
            ResolutionImportRouteKind::Star
        } else {
            ResolutionImportRouteKind::Named
        };
        let bound_name = local.map(|local| self.intern_name(node_text(local, self.source)));
        let mut names = path.to_vec();
        if let Some(source) = source {
            names.push(self.intern_name(node_text(source, self.source)));
        }
        self.facts.import_routes.push(ResolutionImportRouteFact {
            site,
            root_scope: scope,
            kind,
            bound_name,
        });
        self.facts
            .import_route_segments
            .extend(names.iter().copied().enumerate().map(|(ordinal, name)| {
                ResolutionImportRouteSegmentFact {
                    import_site: site,
                    ordinal: u32::try_from(ordinal).expect("Scala import path length fits u32"),
                    name,
                }
            }));
        self.facts.root_imports.push(ResolutionRootImportFact {
            site,
            root_scope: scope,
            anchor,
            // A Scala import binds only the names written after it.
            position: Some(activation_start),
        });
        self.facts
            .root_import_kinds
            .push(ResolutionRootImportKindFact {
                import_site: site,
                kind: if star {
                    ResolutionRootImportKind::Glob
                } else {
                    ResolutionRootImportKind::Named
                },
            });
        let root_names = if star {
            names.as_slice()
        } else {
            &names[..names.len().saturating_sub(1)]
        };
        self.facts
            .root_import_segments
            .extend(
                root_names
                    .iter()
                    .copied()
                    .enumerate()
                    .map(|(position, name)| ResolutionRootImportSegmentFact {
                        import_site: site,
                        position: u32::try_from(position)
                            .expect("Scala import route length fits u32"),
                        name,
                    }),
            );
        if let Some(local) = local {
            // The positioned root route binds `bound_name` to the selected
            // symbol, including a rename. A local declaration would invent a
            // second symbol and a partial scope-wide activation.
            let demand_name = source
                .map(|source| self.intern_name(node_text(source, self.source)))
                .unwrap_or_else(|| self.intern_name(node_text(local, self.source)));
            for namespace in [
                ResolutionNamespace::Type,
                ResolutionNamespace::Value,
                ResolutionNamespace::Callable,
            ] {
                self.facts
                    .root_import_demands
                    .push(ResolutionRootImportDemandFact {
                        import_site: site,
                        namespace,
                        name: demand_name,
                    });
            }
        }
        if star {
            self.wildcard_imports.push((site, scope, activation_start));
        }
    }

    fn publish_import_reference(
        &mut self,
        segments: &[Node<'source>],
        scope: ResolutionScopeId,
        anchor: ResolutionRootImportAnchor,
    ) {
        let node = *segments.last().expect("an import reference has a target");
        let namespace = ResolutionNamespace::TypeOrValue;
        let owner = self.declaration_owner(self.scope(scope).owner);
        let (prefix, qualifier) = if segments.len() > 1 {
            let (prefix, qualifier) =
                self.lower_qualified_prefixes(segments, scope, owner, namespace, anchor, true);
            (Some(prefix), qualifier)
        } else {
            (None, None)
        };
        let reference = self.add_site_distinct(
            node,
            if qualifier.is_some() {
                ResolutionSiteKind::MemberReference
            } else {
                ResolutionSiteKind::ValueReference
            },
            scope,
        );
        self.identifier(
            reference,
            node,
            ResolutionIdentifierRole::Reference,
            namespace,
            qualifier,
        );
        self.facts
            .reference_owners
            .push(ResolutionReferenceOwnerFact { reference, owner });
        self.projected_identity_slot(reference, namespace);
        if qualifier.is_some() {
            self.gap(reference, ResolutionGapKind::AmbiguousQualifiedType);
        }
        self.record_qualified_type_root_reference(
            segments, reference, scope, prefix, false, anchor,
        );
        // SLS 4.7: an import's stable qualifier starts in the enclosing
        // lexical scope. An explicit _root_ path keeps its absolute route.
        if anchor == ResolutionRootImportAnchor::Lexical {
            let head = prefix.unwrap_or(reference);
            self.facts.sites[head.index()].kind = ResolutionSiteKind::ImportQualifierReference;
        }
    }

    fn finish_import_demands(&mut self) {
        let call_callees = self
            .facts
            .calls
            .iter()
            .map(|call| call.callee)
            .collect::<HashSet<_>>();
        for &(import_site, import_scope, activation_start) in &self.wildcard_imports {
            let references = self
                .facts
                .identifiers
                .iter()
                .filter(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
                .filter(|identifier| {
                    let site = self.facts.sites[identifier.site.index()];
                    scope_is_ancestor(&self.facts.scopes, import_scope, site.scope)
                        && site.start_byte >= activation_start
                })
                .copied()
                .collect::<Vec<_>>();
            for reference in references {
                // A path segment can name an object that the wildcard binds
                // (`import Owner.*` after `import pkg.*` demands `Owner` from
                // `pkg.*`), so a package-namespace reference demands the term and
                // type namespaces as well as the package namespace.
                let namespaces: &[ResolutionNamespace] = if call_callees.contains(&reference.site) {
                    crate::package_lookup::callee_import_namespaces(
                        brokk_bifrost_core::analyzer::Language::Scala,
                    )
                } else {
                    match reference.namespace {
                        ResolutionNamespace::Callable => {
                            &[ResolutionNamespace::Callable, ResolutionNamespace::Value]
                        }
                        ResolutionNamespace::TypeOrValue => &[
                            ResolutionNamespace::Type,
                            ResolutionNamespace::Value,
                            ResolutionNamespace::Callable,
                        ],
                        ResolutionNamespace::Package => &[
                            ResolutionNamespace::Package,
                            ResolutionNamespace::Type,
                            ResolutionNamespace::Value,
                            ResolutionNamespace::Callable,
                        ],
                        _ => std::slice::from_ref(&reference.namespace),
                    }
                };
                for &namespace in namespaces {
                    let demand = ResolutionRootImportDemandFact {
                        import_site,
                        namespace,
                        name: reference.name,
                    };
                    if !self.facts.root_import_demands.contains(&demand) {
                        self.facts.root_import_demands.push(demand);
                    }
                    let target = ResolutionRootImportDemandTargetFact {
                        import_site,
                        namespace,
                        name: reference.name,
                        target: ResolutionRootImportDemandTarget::SameNameGlob,
                    };
                    if !self.facts.root_import_demand_targets.contains(&target) {
                        self.facts.root_import_demand_targets.push(target);
                    }
                }
            }
        }
    }

    fn scope_for_children(
        &mut self,
        node: Node<'source>,
        parent: ResolutionScopeId,
        owner: Option<ResolutionSiteId>,
        type_owner: Option<ResolutionSiteId>,
    ) -> (
        ResolutionScopeId,
        Option<ResolutionSiteId>,
        Option<ResolutionSiteId>,
    ) {
        let anonymous_owner = node
            .parent()
            .filter(|parent| {
                matches!(node.kind(), "template_body" | "with_template_body")
                    && parent.kind() == "instance_expression"
            })
            .and_then(|instance| self.declaration_sites.get(&instance.id()).copied());
        let kind = match node.kind() {
            "template_body" | "with_template_body" if anonymous_owner.is_some() => Some((
                ResolutionScopeKind::TypeBody,
                ResolutionScopeInheritance::Lexical,
            )),
            "package_clause" if node.child_by_field_name("body").is_some() => Some((
                ResolutionScopeKind::Package,
                ResolutionScopeInheritance::Lexical,
            )),
            "package_object" => Some((
                ResolutionScopeKind::Package,
                ResolutionScopeInheritance::Lexical,
            )),
            "class_definition" | "trait_definition" | "object_definition" | "enum_definition"
            | "full_enum_case" => Some((
                ResolutionScopeKind::TypeBody,
                ResolutionScopeInheritance::Lexical,
            )),
            "function_definition" | "function_declaration" | "lambda_expression" => Some((
                ResolutionScopeKind::Executable,
                ResolutionScopeInheritance::Lexical,
            )),
            "block"
            | "indented_block"
            | "case_block"
            | "case_clause"
            | "for_expression"
            | "extension_definition" => Some((
                ResolutionScopeKind::Block,
                ResolutionScopeInheritance::Lexical,
            )),
            _ => None,
        };
        let Some((kind, inheritance)) = kind else {
            return (parent, owner, type_owner);
        };
        let id = ResolutionScopeId::try_from_index(self.facts.scopes.len())
            .expect("Scala scope count fits u32");
        self.facts.scopes.push(ResolutionScopeFact {
            id,
            parent: Some(parent),
            owner: anonymous_owner
                .or_else(|| self.declaration_sites.get(&node.id()).copied())
                .or(owner),
            kind,
            inheritance,
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
        });
        self.scope_ranges.push(node_range(node));
        self.scopes_by_node.insert(node.id(), id);
        if node.kind() == "package_object"
            && let Some(package_object) = self.declaration_sites.get(&node.id()).copied()
        {
            self.package_objects.push((package_object, id));
        }
        let child_owner = anonymous_owner
            .or_else(|| self.declaration_sites.get(&node.id()).copied())
            .or(owner);
        let child_type_owner = if anonymous_owner.is_some() {
            anonymous_owner
        } else if is_type_declaration(node.kind()) {
            self.declaration_sites.get(&node.id()).copied()
        } else {
            type_owner
        };
        (id, child_owner, child_type_owner)
    }

    fn finish_packages(&mut self, root: Node<'source>) {
        let mut stack = vec![root];
        let mut package_nodes = Vec::new();
        let mut root_package_clauses = Vec::new();
        while let Some(node) = stack.pop() {
            let mut cursor = node.walk();
            let children = node.named_children(&mut cursor).collect::<Vec<_>>();
            stack.extend(children.iter().copied().rev());
            if !matches!(node.kind(), "package_clause" | "package_object") {
                continue;
            }
            package_nodes.push(node);
            if node.kind() == "package_clause"
                && node.child_by_field_name("body").is_none()
                && !has_package_scope_ancestor(node)
            {
                root_package_clauses.push(node);
            }
        }
        root_package_clauses.sort_unstable_by_key(Node::start_byte);

        let root_declaration = root_package_clauses
            .last()
            .and_then(|node| self.sites_by_node.get(&node.id()).copied());
        let root_package_prefix = root_package_clauses.clone();
        let mut routes = vec![(
            self.root_scope,
            root_declaration,
            root_package_clauses,
            None,
        )];
        for node in package_nodes {
            let Some(root_scope) = self.scopes_by_node.get(&node.id()).copied() else {
                continue;
            };
            let declaration = if node.kind() == "package_object" {
                self.package_declarations.get(&node.id()).copied()
            } else {
                self.sites_by_node.get(&node.id()).copied()
            };
            routes.push((root_scope, declaration, vec![node], Some(node)));
        }

        for (root_scope, declaration, own_nodes, origin) in routes {
            self.facts.packages.push(ResolutionPackageFact {
                root_scope,
                declaration,
                placement_gap_site: self.placement_site,
            });
            let mut path_nodes = if let Some(origin) = origin {
                package_ancestor_nodes(origin)
            } else {
                Vec::new()
            };
            if origin.is_none() {
                path_nodes.extend(own_nodes);
            } else if path_nodes
                .iter()
                .filter(|node| node.kind() == "package_clause")
                .count()
                <= 1
            {
                let own_path = path_nodes;
                path_nodes = root_package_prefix.clone();
                path_nodes.extend(own_path);
            }
            let mut segments = Vec::new();
            for package_node in path_nodes {
                if let Some(name) = package_node.child_by_field_name("name") {
                    segments.extend(package_name_nodes(name));
                }
            }
            for (ordinal, segment) in segments.into_iter().enumerate() {
                let name = self.intern_name(node_text(segment, self.source));
                self.facts
                    .package_segments
                    .push(ResolutionPackageSegmentFact {
                        root_scope,
                        ordinal: u32::try_from(ordinal)
                            .expect("Scala package path length fits u32"),
                        name,
                    });
            }
        }

        let package_roots = self
            .facts
            .packages
            .iter()
            .map(|package| package.root_scope)
            .collect::<Vec<_>>();
        for export in &self.facts.root_exports {
            if package_roots.contains(&export.root_scope) {
                self.facts.package_members.push(
                    brokk_bifrost_core::analyzer::resolution_facts::ResolutionPackageMemberFact {
                        root_scope: export.root_scope,
                        declaration: export.declaration,
                        namespace: export.namespace,
                    },
                );
            }
        }
        for &(package_object, package_scope) in &self.package_objects {
            for member in self
                .facts
                .package_members
                .iter()
                .filter(|member| member.root_scope == package_scope)
            {
                self.facts
                    .package_object_exports
                    .push(ResolutionPackageObjectExportFact {
                        package_object,
                        package_scope,
                        member: member.declaration,
                    });
            }
        }
        self.facts
            .package_object_exports
            .sort_unstable_by_key(|export| (export.package_object, export.member));
        self.facts
            .package_object_exports
            .dedup_by_key(|export| (export.package_object, export.member));
        self.finish_package_references();
        self.facts.validate_package_relations();
    }

    fn finish_package_references(&mut self) {
        let mut imports_by_name: HashMap<_, Vec<_>> = HashMap::default();
        for selector in &self.facts.import_selectors {
            let Some(name) = selector.local_name else {
                continue;
            };
            let site = &self.facts.sites[selector.site.index()];
            imports_by_name
                .entry(name)
                .or_default()
                .push((site.scope, site.end_byte));
        }
        let extension_calls = self
            .facts
            .callable_receiver_origins
            .iter()
            .filter(|origin| origin.origin == ResolutionCallableReceiverOrigin::ExplicitExpression)
            .map(|origin| origin.reference)
            .collect::<HashSet<_>>();
        let references = crate::package_lookup::source_owned_package_references(
            &self.facts,
            |identifier, _| {
                identifier.qualifier.is_none()
                    || (identifier.namespace == ResolutionNamespace::Callable
                        && extension_calls.contains(&identifier.site))
            },
            |identifier, site| {
                let imported = imports_by_name
                    .get(&identifier.name)
                    .is_some_and(|imports| {
                        imports.iter().any(|(scope, activation)| {
                            site.start_byte >= *activation
                                && scope_is_ancestor(&self.facts.scopes, *scope, site.scope)
                        })
                    });
                (!imported
                    && matches!(
                        identifier.namespace,
                        ResolutionNamespace::Type
                            | ResolutionNamespace::Value
                            | ResolutionNamespace::Callable
                            | ResolutionNamespace::TypeOrValue
                    ))
                .then(|| self.package_scope_for(site.scope))
            },
        );
        self.facts.package_references.extend(references);
    }

    fn binary_owner_prefix(&self, scope: ResolutionScopeId) -> ResolutionBinaryOwnerRoute {
        let scope = self.package_scope_for(scope);
        assert!(
            self.facts
                .packages
                .iter()
                .any(|package| package.root_scope == scope),
            "an unknown binary owner needs a known source package prefix"
        );
        let mut prefix = self
            .facts
            .package_segments
            .iter()
            .filter(|segment| segment.root_scope == scope)
            .map(|segment| (segment.ordinal, segment.name))
            .collect::<Vec<_>>();
        prefix.sort_unstable_by_key(|(ordinal, _)| *ordinal);
        ResolutionBinaryOwnerRoute::UnknownWithin {
            scope,
            prefix: prefix.into_iter().map(|(_, name)| name).collect(),
        }
    }

    fn package_scope_for(&self, mut scope: ResolutionScopeId) -> ResolutionScopeId {
        loop {
            let fact = &self.facts.scopes[scope.index()];
            if fact.kind == ResolutionScopeKind::Package {
                return scope;
            }
            match fact.parent {
                Some(parent) => scope = parent,
                None => return self.root_scope,
            }
        }
    }

    fn finish_supertypes(&mut self, root: Node<'source>) {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
            if node.kind() == "self_type" {
                let mut ancestor = node.parent();
                let subtype = loop {
                    let Some(candidate) = ancestor else {
                        break None;
                    };
                    if let Some(&site) = self.declaration_sites.get(&candidate.id())
                        && (is_type_declaration(candidate.kind())
                            || candidate.kind() == "instance_expression")
                    {
                        break Some(site);
                    }
                    ancestor = candidate.parent();
                };
                if let Some(subtype) = subtype {
                    let mut parent_ordinal = self
                        .facts
                        .supertypes
                        .iter()
                        .filter(|edge| edge.subtype == subtype)
                        .count() as u32;
                    let mut identity_slots = Vec::new();
                    for (_, lookup) in scala_self_type_lookup_nodes(node) {
                        let published = terminal_identifier(lookup)
                            .and_then(|terminal| self.sites_by_node.get(&terminal.id()).copied())
                            .and_then(|reference| {
                                self.projected_slot(
                                    reference,
                                    BindingProjectionKind::TargetTypeIdentity,
                                )
                                .map(|slot| (reference, slot))
                            });
                        let Some((reference, slot)) = published else {
                            self.gap(subtype, ResolutionGapKind::UnsupportedHierarchyTraversal);
                            continue;
                        };
                        self.facts.supertypes.push(ResolutionSupertypeFact {
                            subtype,
                            parent_ordinal,
                            supertype_reference: reference,
                            supertype_slot: slot,
                            kind: ResolutionSupertypeKind::SelfType,
                        });
                        identity_slots.push(slot);
                        self.gap(reference, ResolutionGapKind::UnsupportedHierarchyTraversal);
                        parent_ordinal = parent_ordinal
                            .checked_add(1)
                            .expect("Scala self-type parent ordinal fits u32");
                    }
                    let name = node.named_child(0).expect("a self-type has a binder");
                    if node_text(name, self.source) != "this" {
                        let scope = self
                            .facts
                            .scopes
                            .iter()
                            .find(|scope| {
                                scope.owner == Some(subtype)
                                    && scope.kind == ResolutionScopeKind::TypeBody
                            })
                            .expect("a self-type belongs to its template body")
                            .id;
                        let scope_fact = *self.scope(scope);
                        let alias =
                            self.add_site(name, ResolutionSiteKind::ValueDeclaration, scope);
                        self.identifier(
                            alias,
                            name,
                            ResolutionIdentifierRole::Declaration,
                            ResolutionNamespace::Value,
                            None,
                        );
                        let occurrence = self.collector.intern_node(node);
                        let name_occurrence = self.collector.intern_node(name);
                        let declaration = self.collector.declare(occurrence, Some(name_occurrence));
                        self.publish_unitless_declaration(
                            alias,
                            declaration,
                            DeclarationKind::LocalVariable,
                        );
                        self.facts.binders.push(ResolutionBinderFact {
                            declaration: alias,
                            scope,
                            kind: ResolutionBinderKind::Local,
                            hoisting: HoistingClass::ScopeWide,
                            activation_start: scope_fact.start_byte,
                            activation_end: scope_fact.end_byte,
                        });
                        if identity_slots.is_empty() {
                            let identity = if let Some(annotation) = node.named_child(1) {
                                self.declared_type_identity_slot(alias, annotation)
                            } else {
                                // Without an ascription the alias denotes the
                                // enclosing instance's nominal type.
                                let identity = self
                                    .add_slot(subtype, ResolutionTypeSlotRole::TargetTypeIdentity);
                                self.facts
                                    .declaration_type_slots
                                    .push(DeclarationTypeSlotFact {
                                        declaration: subtype,
                                        slot: identity,
                                        role: DeclarationTypeRole::NominalIdentity,
                                    });
                                identity
                            };
                            identity_slots.push(identity);
                        }
                        let value =
                            self.add_declared_value_slot(alias, DeclarationTypeRole::Value, None);
                        // Compound bounds share the same multi-input producer
                        // family as Java type-parameter bounds. The alias value
                        // then has one ordinary declared-type producer.
                        let identity = if identity_slots.len() == 1 {
                            identity_slots[0]
                        } else {
                            let union =
                                self.add_slot(alias, ResolutionTypeSlotRole::TargetTypeIdentity);
                            for identity in identity_slots {
                                crate::call_arguments::publish_jvm_type_union_transfer(
                                    &mut self.facts,
                                    identity,
                                    union,
                                );
                            }
                            union
                        };
                        crate::call_arguments::publish_jvm_declared_type_transfer(
                            &mut self.facts,
                            identity,
                            value,
                            ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                        );
                    }
                }
                continue;
            }
            let Some(subtype) = self.declaration_sites.get(&node.id()).copied() else {
                continue;
            };
            if !is_type_declaration(node.kind()) && node.kind() != "instance_expression" {
                continue;
            }
            // The hierarchy edge reuses the identity slot that the parent
            // type reference already projects, and the traversal gap sits on
            // that reference, exactly as the Java producer publishes an
            // `extends` clause. A parent with no positioned type reference
            // gets no edge and leaves the gap on the subtype.
            let mut parent_ordinal = 0u32;
            for (ordinal, (_owner, lookup)) in
                scala_supertype_lookup_nodes(node).into_iter().enumerate()
            {
                let published = terminal_identifier(lookup)
                    .and_then(|terminal| self.sites_by_node.get(&terminal.id()).copied())
                    .and_then(|reference| {
                        self.projected_slot(reference, BindingProjectionKind::TargetTypeIdentity)
                            .map(|slot| (reference, slot))
                    });
                let Some((reference, slot)) = published else {
                    self.gap(subtype, ResolutionGapKind::UnsupportedHierarchyTraversal);
                    continue;
                };
                self.facts.supertypes.push(ResolutionSupertypeFact {
                    subtype,
                    parent_ordinal,
                    supertype_reference: reference,
                    supertype_slot: slot,
                    kind: if ordinal == 0
                        && matches!(node.kind(), "class_definition" | "instance_expression")
                    {
                        ResolutionSupertypeKind::Superclass
                    } else {
                        ResolutionSupertypeKind::Interface
                    },
                });
                parent_ordinal = parent_ordinal
                    .checked_add(1)
                    .expect("Scala parent count fits u32");
                self.gap(reference, ResolutionGapKind::UnsupportedHierarchyTraversal);
            }
            // The compiler mixes `Product with Serializable` into every case
            // class and case object after the written parents.
            if matches!(node.kind(), "class_definition" | "object_definition")
                && has_case_modifier(node)
            {
                for (name, route) in SCALA_CASE_IMPLICIT_PARENTS {
                    self.add_implicit_supertype(subtype, parent_ordinal, name, route);
                    parent_ordinal = parent_ordinal
                        .checked_add(1)
                        .expect("Scala parent count fits u32");
                }
            }
        }
    }

    /// Connect each `super.member` receiver to the enclosing template's parent
    /// identities. The identity projection reads the written parent reference,
    /// not the edge's full frontier: the enclosing type's hierarchy
    /// uncertainty does not make this receiver's type unknown. Multiple
    /// written parents form a union of the identities the linearization may
    /// select.
    fn finish_super_receivers(&mut self) {
        let pending = std::mem::take(&mut self.super_receivers);
        for (owner, receiver) in pending {
            let site = self.facts.type_slots[receiver.index()].site;
            let references = self
                .facts
                .supertypes
                .iter()
                .filter(|edge| {
                    edge.subtype == owner && edge.kind != ResolutionSupertypeKind::SelfType
                })
                .map(|edge| edge.supertype_reference)
                .collect::<Vec<_>>();
            if references.is_empty() {
                self.gap(site, ResolutionGapKind::InferredType);
                continue;
            }
            let mut identities = Vec::with_capacity(references.len());
            for reference in references {
                let identity = self.add_slot(site, ResolutionTypeSlotRole::TargetTypeIdentity);
                self.facts
                    .binding_projections
                    .push(BindingProjectionFact::target_type_identity(
                        reference, identity,
                    ));
                identities.push(identity);
            }
            let input = if let [identity] = identities.as_slice() {
                *identity
            } else {
                let union = self.add_slot(site, ResolutionTypeSlotRole::TargetTypeIdentity);
                for identity in identities {
                    crate::call_arguments::publish_jvm_type_union_transfer(
                        &mut self.facts,
                        identity,
                        union,
                    );
                }
                union
            };
            self.facts
                .type_transfers
                .push(ResolutionTypeTransferFact::new(
                    input,
                    receiver,
                    ResolutionTypeTransferKind::Receiver,
                    0,
                    0,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                ));
        }
    }

    /// A parent the language supplies without a written clause. The reference
    /// is the producer's own device: an absolute route that no source
    /// declaration can shadow, with no authored range, exactly as the Java
    /// producer supplies `java.lang.Object`. It is an ordinary interface edge
    /// that is open until the hierarchy resolves it.
    fn add_implicit_supertype(
        &mut self,
        subtype: ResolutionSiteId,
        parent_ordinal: u32,
        name: &str,
        route: &[&str],
    ) {
        let occurrence = self.site_occurrences[subtype.index()];
        let scope = self.facts.sites[subtype.index()].scope;
        let reference = self.push_site(occurrence, ResolutionSiteKind::SyntheticReference, scope);
        let name = self.intern_name(name);
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
                owner: Some(subtype),
            });
        let slot = self.projected_identity_slot(reference, ResolutionNamespace::Type);
        self.facts
            .root_references
            .push(ResolutionRootReferenceFact {
                reference,
                root_scope: self.package_scope_for(scope),
                anchor: ResolutionRootImportAnchor::Absolute,
                prefix_reference: None,
                owner_continued: false,
            });
        for (position, spelling) in route.iter().enumerate() {
            let name = self.intern_name(spelling);
            self.facts
                .root_reference_segments
                .push(ResolutionRootReferenceSegmentFact {
                    reference,
                    position: u32::try_from(position).expect("Scala implicit route fits u32"),
                    name,
                });
        }
        self.facts.supertypes.push(ResolutionSupertypeFact {
            subtype,
            parent_ordinal,
            supertype_reference: reference,
            supertype_slot: slot,
            kind: ResolutionSupertypeKind::Interface,
        });
        self.gap(reference, ResolutionGapKind::UnsupportedHierarchyTraversal);
    }

    /// The members the compiler adds to a case class: `copy` on the class, and
    /// `apply` and `unapply` (`unapplySeq` for a repeated parameter) on its
    /// companion object. A missing source companion receives a synthetic site.
    ///
    /// Each member is a callable declaration positioned at the owner's name
    /// token, with the constructor's parameters, and is located at the class's
    /// synthetic constructor declaration, the canonical identity the
    /// incumbent gives a case class's `apply` and extractor.
    fn finish_case_class_members(&mut self, root: Node<'source>, parsed: &ParsedFile) {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
            if node.kind() != "class_definition" || !has_case_modifier(node) {
                continue;
            }
            let Some(site) = self.declaration_sites.get(&node.id()).copied() else {
                continue;
            };
            self.add_case_class_members(node, site, parsed);
        }
    }

    fn add_case_class_members(
        &mut self,
        class: Node<'source>,
        class_site: ResolutionSiteId,
        parsed: &ParsedFile,
    ) {
        let companion = scala_companion_object(class, self.source);
        let (companion_node, companion_site, companion_scope, companion_access) = match companion {
            Some(object) => {
                let site = self.declaration_sites[&object.id()];
                let scope = self.scopes_by_node[&object.id()];
                (
                    object,
                    site,
                    scope,
                    (
                        ResolutionMemberAccess::Type,
                        ResolutionMemberQualifierCompatibility::RuntimeOrType,
                    ),
                )
            }
            None => {
                let (site, scope) = self.add_synthesized_companion(class, class_site, parsed);
                (
                    class,
                    site,
                    scope,
                    (
                        ResolutionMemberAccess::Type,
                        ResolutionMemberQualifierCompatibility::RuntimeOrType,
                    ),
                )
            }
        };
        let lists = super::declarations::scala_class_parameter_lists(class);
        // Without a parameter list the class has no constructor to locate the
        // members at.
        let Some(&first_list) = lists.first() else {
            return;
        };
        let source = self.source;
        // The members are located at the synthetic constructor. A class that
        // has no parser unit (a local class) has no constructor unit either,
        // and its members are located at the class's lexical declaration.
        let constructor = {
            let occurrence = self.collector.intern_node(class);
            let constructor = self.collector.declare(occurrence, None);
            if parsed
                .source_declaration_units
                .iter()
                .any(|(declaration, _)| *declaration == constructor)
            {
                constructor
            } else {
                let name = self.collector.intern_node(
                    declaration_name(class).expect("a named Scala case class declaration"),
                );
                self.collector.declare(occurrence, Some(name))
            }
        };
        let class = ScalaCaseClass {
            node: class,
            site: class_site,
            constructor,
        };
        // A curried or contextual class has further lists whose shape the
        // members do not model; their applicability stays open.
        let modeled = lists.len() == 1;
        let mut mirrored = Vec::new();
        let mut cursor = first_list.walk();
        for parameter in first_list.named_children(&mut cursor) {
            if !matches!(parameter.kind(), "parameter" | "class_parameter") {
                continue;
            }
            let Some(name) = parameter.child_by_field_name("name") else {
                continue;
            };
            mirrored.push(ScalaCaseMemberParameter {
                label: node_text(name, source).trim(),
                declared: Some(parameter),
                has_default: has_field_descendant(parameter, "default_value"),
            });
        }
        let extractor = if scala_case_class_has_repeated_parameter(class.node) {
            "unapplySeq"
        } else {
            "unapply"
        };
        let apply = self.add_case_class_member(
            &class,
            ScalaCaseMember {
                name: "apply",
                owner: companion_node,
                owner_site: companion_site,
                owner_scope: companion_scope,
                access: companion_access,
                parameters: modeled.then(|| mirrored.clone()),
                returns_class: true,
            },
        );
        let unapply = self.add_case_class_member(
            &class,
            ScalaCaseMember {
                name: extractor,
                owner: companion_node,
                owner_site: companion_site,
                owner_scope: companion_scope,
                access: companion_access,
                parameters: Some(vec![ScalaCaseMemberParameter {
                    label: "x$0",
                    declared: None,
                    has_default: false,
                }]),
                returns_class: false,
            },
        );
        self.add_case_class_member(
            &class,
            ScalaCaseMember {
                name: "copy",
                owner: class.node,
                owner_site: class.site,
                owner_scope: self.scopes_by_node[&class.node.id()],
                access: (
                    ResolutionMemberAccess::Instance,
                    ResolutionMemberQualifierCompatibility::RuntimeOnly,
                ),
                parameters: modeled.then(|| {
                    mirrored
                        .iter()
                        .map(|parameter| ScalaCaseMemberParameter {
                            has_default: true,
                            ..*parameter
                        })
                        .collect()
                }),
                returns_class: true,
            },
        );
        self.case_class_members
            .insert(class.node.id(), (apply, unapply));
    }

    fn add_synthesized_companion(
        &mut self,
        class: Node<'source>,
        class_site: ResolutionSiteId,
        parsed: &ParsedFile,
    ) -> (ResolutionSiteId, ResolutionScopeId) {
        let source_declaration = self
            .declaration_sources
            .iter()
            .find_map(|(site, declaration)| (*site == class_site).then_some(*declaration))
            .expect("a class or enum has a source declaration");
        let class_unit = parsed
            .source_declaration_units
            .iter()
            .find_map(|(declaration, unit)| (*declaration == source_declaration).then_some(unit));
        let name = declaration_name(class).expect("a named Scala class or enum");
        let name_text = node_text(name, self.source).trim();
        let parent_scope = self.facts.sites[class_site.index()].scope;
        let occurrence = self.collector.intern_subspan_bytes(
            name.start_byte(),
            name.end_byte(),
            SourceOccurrenceProvenance::ExplicitSubspan,
        );
        let declaration = self.collector.declare(occurrence, Some(occurrence));
        let site = self.push_site(
            occurrence,
            ResolutionSiteKind::TypeDeclaration,
            parent_scope,
        );
        self.identifier(
            site,
            name,
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Value,
            None,
        );
        self.publish_declaration_binder(
            class,
            site,
            parent_scope,
            self.scope(parent_scope).owner,
            ResolutionNamespace::Value,
            Some(ResolutionBinderKind::Type),
            Some(ResolutionMemberKind::Field),
        );
        // A singleton owns a type-body scope while its name binds as a term,
        // just like an explicitly written object.
        self.facts.additional_definition_namespaces.push(
            ResolutionAdditionalDefinitionNamespaceFact {
                declaration: site,
                namespace: ResolutionNamespace::Value,
                hoisting: HoistingClass::ScopeWide,
            },
        );
        self.declaration_sources.push((site, declaration));
        if let Some(class_unit) = class_unit {
            let visibility = self
                .facts
                .declaration_visibilities
                .iter()
                .find(|visibility| visibility.declaration == class_site)
                .expect("an indexed class or enum publishes its source visibility")
                .visibility;
            self.publish_visibility_rows(site, visibility);
            let companion_fq = class_unit
                .fq()
                .parent()
                .expect("a class code unit has an enclosing name")
                .with_pushed(segment_interner().intern(name_text, SegmentKind::Companion));
            let companion_unit = CodeUnit::with_signature_and_fq(
                class_unit.source().clone(),
                CodeUnitType::Class,
                class_unit.package_name(),
                format!("{}$", class_unit.short_name()),
                None,
                true,
                companion_fq,
            );
            self.facts
                .definition_units
                .push(ResolutionDefinitionUnitFact {
                    declaration: site,
                    unit: companion_unit,
                });
        } else {
            // Local templates have lexical source declarations rather than
            // indexed parser units. Their companions have the same lifetime.
            self.collector
                .mark_lexical(declaration, DeclarationKind::BlockLocalItem);
        }
        let scope = ResolutionScopeId::try_from_index(self.facts.scopes.len())
            .expect("Scala resolution scope count fits u32");
        let range = node_range(name);
        self.facts.scopes.push(ResolutionScopeFact {
            id: scope,
            parent: Some(parent_scope),
            owner: Some(site),
            kind: ResolutionScopeKind::TypeBody,
            inheritance: ResolutionScopeInheritance::Lexical,
            start_byte: range.start_byte,
            end_byte: range.end_byte,
        });
        self.scope_ranges.push(range);
        self.synthesized_companions.insert(class.id(), site);
        (site, scope)
    }

    fn finish_enum_companions(&mut self, root: Node<'source>, parsed: &ParsedFile) {
        let mut stack = vec![root];
        let mut companions = HashMap::default();
        while let Some(node) = stack.pop() {
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
            if node.kind() != "enum_definition" || declaration_name(node).is_none() {
                continue;
            }
            let Some(enum_site) = self.declaration_sites.get(&node.id()).copied() else {
                continue;
            };
            let (companion, scope) = match scala_companion_object(node, self.source) {
                Some(object) => (
                    self.declaration_sites[&object.id()],
                    self.scopes_by_node[&object.id()],
                ),
                None => {
                    let (site, scope) = self.add_synthesized_companion(node, enum_site, parsed);
                    self.facts
                        .singleton_relations
                        .push(ResolutionSingletonRelationFact {
                            declaration: site,
                            enclosing_type: Some(enum_site),
                            kind: ResolutionSingletonRelationKind::Companion,
                        });
                    (site, scope)
                }
            };
            // The virtual companion body includes cases written on the enum
            // as well as members written in an explicit companion object.
            let old_scope = *self.scope(scope);
            let enum_range = node_range(node);
            let range = &mut self.scope_ranges[scope.index()];
            range.start_byte = range.start_byte.min(enum_range.start_byte);
            range.end_byte = range.end_byte.max(enum_range.end_byte);
            range.start_line = range.start_line.min(enum_range.start_line);
            range.end_line = range.end_line.max(enum_range.end_line);
            let range = *range;
            self.facts.scopes[scope.index()].start_byte = range.start_byte;
            self.facts.scopes[scope.index()].end_byte = range.end_byte;
            for binder in self
                .facts
                .binders
                .iter_mut()
                .filter(|binder| binder.scope == scope)
            {
                if binder.activation_start == old_scope.start_byte {
                    binder.activation_start = range.start_byte;
                }
                if binder.activation_end == old_scope.end_byte {
                    binder.activation_end = range.end_byte;
                }
            }
            let route_names = self
                .facts
                .definition_units
                .iter()
                .find(|definition| definition.declaration == companion)
                .filter(|definition| {
                    definition.unit.fq().segments().iter().all(|&segment| {
                        matches!(
                            segment_interner().resolve(segment).1,
                            SegmentKind::Package | SegmentKind::Companion
                        )
                    })
                })
                .map(|definition| {
                    definition
                        .unit
                        .fq()
                        .segments()
                        .iter()
                        .map(|&segment| segment_interner().resolve(segment).0.to_string())
                        .collect::<Vec<_>>()
                });
            let route = route_names.map(|names| {
                names
                    .iter()
                    .map(|name| self.intern_name(name))
                    .collect::<Vec<_>>()
            });
            companions.insert(enum_site, (companion, scope, node, route));
        }
        // Only cases are static members of the companion. Written enum
        // methods and fields remain instance members of the enum class.
        let mut cases = Vec::new();
        for member in &mut self.facts.member_owners {
            if let Some((companion, scope, owner, _)) = companions.get(&member.owner)
                && let Some(&case) = self.declaration_nodes.get(&member.member)
                && matches!(case.kind(), "simple_enum_case" | "full_enum_case")
            {
                let enum_site = member.owner;
                member.owner = *companion;
                member.access = ResolutionMemberAccess::Type;
                member.qualifier_compatibility =
                    ResolutionMemberQualifierCompatibility::RuntimeOrType;
                cases.push((member.member, *scope, *owner, case, enum_site));
            }
        }
        for (site, companion_scope, owner, case, enum_site) in cases {
            let enum_scope = self.facts.sites[site.index()].scope;
            self.facts.sites[site.index()].scope = companion_scope;
            let scope = *self.scope(companion_scope);
            let binder = self
                .facts
                .binders
                .iter_mut()
                .find(|binder| binder.declaration == site)
                .expect("an enum case has a declaration binder");
            assert_eq!(binder.hoisting, HoistingClass::ScopeWide);
            *binder = ResolutionBinderFact::scope_wide(site, binder.kind, scope);
            // A parameterized case's body keeps the lexical context of its
            // written enum template, including its imports.

            // Enum bodies implicitly import their own cases. Use the same
            // exact named routes as written imports, rather than retaining
            // duplicate instance-member declarations on the enum class.
            let name = declaration_name(case).expect("a named enum case");
            let import =
                self.add_site_distinct(case, ResolutionSiteKind::ImportDeclaration, enum_scope);
            let Some(route) = &companions[&enum_site].3 else {
                // A local or instance-owned companion has no stable absolute
                // source route. Its written lexical owner is still exact.
                // Keep its implicit import open rather than resolving the
                // enum's name through declarations in its own body.
                {
                    let classified_route = ResolutionRouteGap::UnknownBinder {
                        scope: enum_scope,
                        name: Some(self.intern_name(node_text(name, self.source))),
                        namespace: None,
                        may_publish: false,
                    };
                    self.facts.add_route_gap(import, classified_route);
                };
                self.facts
                    .reference_enumeration_gaps
                    .push(ResolutionReferenceEnumerationGapFact {
                        site: import,
                        kind: ResolutionGapKind::UnsupportedRoute,
                    });
                continue;
            };
            self.publish_import_route(ScalaImportRoute {
                site: import,
                scope: enum_scope,
                anchor: ResolutionRootImportAnchor::Absolute,
                path: route,
                source: Some(name),
                local: Some(name),
                star: false,
                activation_start: owner.start_byte(),
            });
            let name = self.intern_name(node_text(name, self.source));
            self.facts
                .import_selectors
                .push(ResolutionImportSelectorFact {
                    site: import,
                    kind: ResolutionImportSelectorKind::Named,
                    source_name: Some(name),
                    local_name: Some(name),
                });
        }
    }

    /// Publish one compiler-added member, unless the source already declares a
    /// member of that name (and, for the companion's `apply` and `unapply`, the
    /// same parameter count) in the owner: the written member replaces it.
    fn add_case_class_member(
        &mut self,
        class: &ScalaCaseClass<'source>,
        member: ScalaCaseMember<'source>,
    ) -> Option<ResolutionSiteId> {
        let owner_site = member.owner_site;
        let owner_scope = member.owner_scope;
        let same_count = (member.owner.id() != class.node.id())
            .then(|| member.parameters.as_ref().map(Vec::len))
            .flatten();
        let member_name = self.intern_name(member.name);
        if crate::synthetic_members::declares_callable(
            &self.facts,
            owner_scope,
            member_name,
            same_count,
        ) {
            return None;
        }
        let anchor = declaration_name(member.owner).expect("a named case class or companion");
        let occurrence = self.collector.intern_node(anchor);
        let range = self.collector.occurrence(occurrence).range;
        let site = self.push_site(
            occurrence,
            ResolutionSiteKind::CallableDeclaration,
            owner_scope,
        );
        self.facts.identifiers.push(PositionedIdentifierFact {
            site,
            name: member_name,
            role: ResolutionIdentifierRole::Declaration,
            namespace: ResolutionNamespace::Callable,
            qualifier: None,
        });
        self.declaration_sources.push((site, class.constructor));
        let owner_scope_fact = *self.scope(owner_scope);
        self.facts.binders.push(ResolutionBinderFact::scope_wide(
            site,
            ResolutionBinderKind::Callable,
            owner_scope_fact,
        ));
        let (access, qualifier_compatibility) = member.access;
        self.facts.member_owners.push(ResolutionMemberOwnerFact {
            member: site,
            owner: owner_site,
            kind: ResolutionMemberKind::Method,
            access,
            qualifier_compatibility,
        });
        let signature = self.facts.callable_signatures.len();
        self.facts
            .callable_signatures
            .push(ResolutionCallableSignatureFact {
                callable: site,
                type_parameter_count: type_parameter_count(class.node),
                result_types: Vec::new(),
            });
        let Some(parameters) = member.parameters else {
            self.gap(site, ResolutionGapKind::UnsupportedCallApplicability);
            return Some(site);
        };
        self.facts
            .callable_parameter_lists
            .push(ResolutionCallableParameterListFact {
                callable: site,
                list_ordinal: 0,
                contextual: false,
            });
        // The parameters live in a scope of their own, so that their names do
        // not become binders of the owner's body.
        let scope = ResolutionScopeId::try_from_index(self.facts.scopes.len())
            .expect("Scala scope count fits u32");
        self.facts.scopes.push(ResolutionScopeFact {
            id: scope,
            parent: Some(owner_scope),
            owner: Some(site),
            kind: ResolutionScopeKind::Executable,
            inheritance: ResolutionScopeInheritance::Lexical,
            start_byte: range.start_byte,
            end_byte: range.end_byte,
        });
        self.scope_ranges.push(range);
        let scope_fact = *self.scope(scope);
        for (ordinal, parameter) in parameters.iter().enumerate() {
            let ordinal = u32::try_from(ordinal).expect("Scala parameter count fits u32");
            let parameter_site =
                self.push_site(occurrence, ResolutionSiteKind::ValueDeclaration, scope);
            let label = self.intern_name(parameter.label);
            self.facts.identifiers.push(PositionedIdentifierFact {
                site: parameter_site,
                name: label,
                role: ResolutionIdentifierRole::Declaration,
                namespace: ResolutionNamespace::Value,
                qualifier: None,
            });
            self.facts.binders.push(ResolutionBinderFact::scope_wide(
                parameter_site,
                ResolutionBinderKind::Parameter,
                scope_fact,
            ));
            let value_type = match parameter.declared {
                Some(declared) => {
                    if let Some(name) = declared.child_by_field_name("name") {
                        let declaration = self.collector.intern_node(declared);
                        let name = self.collector.intern_node(name);
                        let declaration = self.collector.declare(declaration, Some(name));
                        self.declaration_sources.push((parameter_site, declaration));
                    }
                    self.add_declared_value_slot(
                        parameter_site,
                        DeclarationTypeRole::Parameter,
                        declared.child_by_field_name("type"),
                    )
                }
                None => {
                    let value_type = self.add_declared_value_slot(
                        parameter_site,
                        DeclarationTypeRole::Parameter,
                        None,
                    );
                    let class_type = self.synthetic_class_type_slot(class, site, occurrence);
                    crate::call_arguments::publish_jvm_declared_type_transfer(
                        &mut self.facts,
                        class_type,
                        value_type,
                        ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                    );
                    value_type
                }
            };
            self.facts
                .callable_parameters
                .push(ResolutionCallableParameterFact {
                    callable: site,
                    list_ordinal: 0,
                    ordinal,
                    parameter: parameter_site,
                    value_type,
                    repeated: parameter
                        .declared
                        .is_some_and(|declared| contains_kind(declared, "repeated_parameter_type")),
                });
            self.facts.callable_parameter_semantics.push(
                ResolutionCallableParameterSemanticsFact {
                    callable: site,
                    parameter: parameter_site,
                    list_ordinal: 0,
                    ordinal,
                    label,
                    has_default: parameter.has_default,
                },
            );
        }
        if member.returns_class {
            let class_type = self.synthetic_class_type_slot(class, site, occurrence);
            let value_type = self.add_slot(site, ResolutionTypeSlotRole::DeclaredValue);
            self.facts
                .declaration_type_slots
                .push(DeclarationTypeSlotFact {
                    declaration: site,
                    slot: value_type,
                    role: DeclarationTypeRole::Return,
                });
            crate::call_arguments::publish_jvm_declared_type_transfer(
                &mut self.facts,
                class_type,
                value_type,
                ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
            );
            self.facts.callable_signatures[signature].result_types.push(
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionCallableResultTypeFact {
                    ordinal: 0,
                    value_type,
                },
            );
        }
        Some(site)
    }

    /// A reference to the case class, written by the producer for a
    /// compiler-added member's type. It is looked up from the scope that
    /// declares the class, so the class's own hierarchy does not intervene.
    fn synthetic_class_type_slot(
        &mut self,
        class: &ScalaCaseClass<'source>,
        owner: ResolutionSiteId,
        occurrence: SourceOccurrenceId,
    ) -> ResolutionTypeSlotId {
        let scope = self.facts.sites[class.site.index()].scope;
        let reference = self.push_site(occurrence, ResolutionSiteKind::SyntheticReference, scope);
        let source = self.source;
        let spelling = node_text(
            declaration_name(class.node).expect("a named case class"),
            source,
        )
        .trim();
        let name = self.intern_name(spelling);
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
                owner: Some(owner),
            });
        self.projected_identity_slot(reference, ResolutionNamespace::Type)
    }

    fn publish_call_argument_lists(
        &mut self,
        call: ResolutionSiteId,
        lists: Vec<Vec<Node<'source>>>,
    ) {
        let call_scope = self.facts.sites[call.index()].scope;
        let mut argument_ordinal = 0u32;
        for (list_ordinal, arguments) in lists.into_iter().enumerate() {
            let list_ordinal = u32::try_from(list_ordinal).expect("Scala call lists fit u32");
            self.facts
                .call_argument_lists
                .push(ResolutionCallArgumentListFact { call, list_ordinal });
            for argument in arguments {
                let named_argument = is_named_argument(argument);
                let label = if named_argument {
                    let label_node = argument
                        .child_by_field_name("left")
                        .expect("a named Scala argument has a label node");
                    let name = self.intern_name(node_text(label_node, self.source));
                    let scope = self.facts.sites[call.index()].scope;
                    let reference = self.add_site_distinct(
                        label_node,
                        ResolutionSiteKind::ValueReference,
                        scope,
                    );
                    self.identifier(
                        reference,
                        label_node,
                        ResolutionIdentifierRole::Reference,
                        ResolutionNamespace::Value,
                        None,
                    );
                    self.facts
                        .reference_owners
                        .push(ResolutionReferenceOwnerFact {
                            reference,
                            owner: self.declaration_owner(self.scope(scope).owner),
                        });
                    self.facts
                        .named_argument_labels
                        .push(ResolutionNamedArgumentLabelFact {
                            call,
                            reference,
                            label: name,
                        });
                    Some(name)
                } else {
                    None
                };
                let argument_value = if named_argument {
                    argument.child_by_field_name("right")
                } else {
                    Some(argument)
                }
                .map(expression_target_node);
                let argument_input =
                    argument_value.map(|value| self.expression_slot(value, call_scope));
                crate::call_arguments::publish_jvm_call_argument(
                    &mut self.facts,
                    call,
                    list_ordinal,
                    argument_ordinal,
                    argument_input,
                    label,
                );
                argument_ordinal = argument_ordinal
                    .checked_add(1)
                    .expect("Scala call argument count fits u32");
            }
        }
    }

    fn finish_constructor_call(&mut self, instance: Node<'source>) {
        let mut cursor = instance.walk();
        if instance
            .named_children(&mut cursor)
            .any(|node| matches!(node.kind(), "template_body" | "early_defs"))
        {
            return;
        }
        let Some(head) = instance
            .named_child(0)
            .and_then(scala_callable_result_type_head)
        else {
            return;
        };
        let Some(&type_reference) = self.sites_by_node.get(&head.id()) else {
            return;
        };
        let Some(constructed_type) =
            self.projected_slot(type_reference, BindingProjectionKind::TargetTypeIdentity)
        else {
            return;
        };
        let scope = self.facts.sites[type_reference.index()].scope;
        let call = self.add_site(instance, ResolutionSiteKind::Call, scope);
        let callee = self.add_site_distinct(head, ResolutionSiteKind::ConstructorReference, scope);
        self.identifier(
            callee,
            head,
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Constructor,
            Some(constructed_type),
        );
        self.gap(callee, ResolutionGapKind::UnsupportedCallApplicability);
        self.facts
            .reference_owners
            .push(ResolutionReferenceOwnerFact {
                reference: callee,
                owner: self.declaration_owner(self.scope(scope).owner),
            });
        let result = self.add_slot(call, ResolutionTypeSlotRole::CallResult);
        // Shared JVM construction projection takes the nominal type from the
        // qualifier, independently of which constructor's arguments apply.
        self.facts.binding_projections.push(BindingProjectionFact {
            reference: callee,
            output: result,
            kind: BindingProjectionKind::TargetConstructorOwnerType,
        });
        self.call_result_slots_by_node.insert(instance.id(), result);
        let mut argument_nodes = Vec::new();
        let mut cursor = instance.walk();
        argument_nodes.extend(instance.children_by_field_name("arguments", &mut cursor));
        let mut outer = instance;
        while let Some(parent) = outer.parent().filter(|parent| {
            parent.kind() == "call_expression"
                && parent.child_by_field_name("function") == Some(outer)
        }) {
            if let Some(arguments) = parent.child_by_field_name("arguments") {
                argument_nodes.push(arguments);
            }
            self.call_result_slots_by_node.insert(parent.id(), result);
            outer = parent;
        }
        let lists = argument_nodes
            .into_iter()
            .map(|arguments| {
                let mut cursor = arguments.walk();
                arguments.named_children(&mut cursor).collect()
            })
            .collect();
        self.publish_call_argument_lists(call, lists);
        self.facts.calls.push(ResolutionCallFact {
            call,
            callee,
            receiver: None,
            result,
            extra_result_slots: Vec::new(),
            explicit_type_argument_count: 0,
        });
        self.facts
            .invocation_roles
            .push(ResolutionInvocationRoleFact {
                site: call,
                role: ResolutionInvocationRole::Direct,
                receiver: None,
                result: Some(result),
            });
        self.facts
            .engine_rule_eligibilities
            .push(ResolutionEngineRuleEligibilityFact {
                site: call,
                rule: ResolutionEngineRuleKind::DefaultConstruction,
            });
        self.facts
            .engine_rule_eligibilities
            .push(ResolutionEngineRuleEligibilityFact {
                site: call,
                rule: ResolutionEngineRuleKind::DirectOwnerExactPrimitiveDominance,
            });
    }

    fn finish_calls(&mut self, root: Node<'source>) {
        let mut stack = vec![(root, false)];
        while let Some((node, visited)) = stack.pop() {
            if !visited {
                stack.push((node, true));
                let mut cursor = node.walk();
                let mut children = node.named_children(&mut cursor).collect::<Vec<_>>();
                children.reverse();
                stack.extend(children.into_iter().map(|child| (child, false)));
                continue;
            }
            if node.kind() == "instance_expression" {
                self.finish_constructor_call(node);
                continue;
            }
            if !matches!(node.kind(), "call_expression" | "infix_expression")
                || scala_constructor_instance(node).is_some()
            {
                continue;
            }
            let Some(call) = self.sites_by_node.get(&node.id()).copied() else {
                continue;
            };
            let mut application_nodes = Vec::new();
            let mut infix_receiver = None;
            let mut function = if node.kind() == "call_expression" {
                let mut function = node.child_by_field_name("function");
                application_nodes.push(node);
                while let Some(expression) = function {
                    // Parentheses around a curried function value, as in
                    // `(parsedxml2 \\ "book") { ... }`, do not separate the
                    // applied callee from the inner application. Both lists
                    // belong to one call fact, exactly as `f(a)(b)` does.
                    let application = unwrap_parenthesized_expression(expression);
                    match application.kind() {
                        "call_expression" => {
                            application_nodes.push(application);
                            function = application.child_by_field_name("function");
                        }
                        "infix_expression" => {
                            application_nodes.push(application);
                            infix_receiver = application.child_by_field_name("left");
                            function = application.child_by_field_name("operator");
                            break;
                        }
                        _ => {
                            function = Some(application);
                            break;
                        }
                    }
                }
                function
            } else {
                application_nodes.push(node);
                infix_receiver = node.child_by_field_name("left");
                node.child_by_field_name("operator")
            };
            application_nodes.reverse();
            let Some(function) = function.take() else {
                self.gap(call, ResolutionGapKind::UnsupportedCallApplicability);
                continue;
            };
            let generic_function = (function.kind() == "generic_function").then_some(function);
            let explicit_type_arguments = generic_function
                .and_then(|function| function.child_by_field_name("type_arguments"))
                .map(|arguments| {
                    let mut cursor = arguments.walk();
                    arguments.named_children(&mut cursor).collect::<Vec<_>>()
                });
            let callable_function = generic_function
                .and_then(|function| function.child_by_field_name("function"))
                .unwrap_or(function);
            let Some(callee_node) = terminal_identifier(callable_function) else {
                self.gap(call, ResolutionGapKind::UnsupportedCallApplicability);
                continue;
            };
            let Some(callee) = self.sites_by_node.get(&callee_node.id()).copied() else {
                self.gap(call, ResolutionGapKind::UnsupportedCallApplicability);
                continue;
            };
            let callee_kind = self.facts.sites[callee.index()].kind;
            let callee_namespace = self
                .facts
                .identifiers
                .iter()
                .find(|identifier| identifier.site == callee)
                .map(|identifier| identifier.namespace);
            let callable_projection_namespace = match callee_namespace {
                Some(ResolutionNamespace::Callable) => true,
                Some(ResolutionNamespace::Value) => matches!(
                    callee_kind,
                    ResolutionSiteKind::CallableReference | ResolutionSiteKind::MemberReference
                ),
                Some(ResolutionNamespace::TypeOrValue) => {
                    callee_kind == ResolutionSiteKind::CallableReference
                }
                _ => false,
            };
            if !callable_projection_namespace
                || !matches!(
                    callee_kind,
                    ResolutionSiteKind::CallableReference
                        | ResolutionSiteKind::ConstructorReference
                        | ResolutionSiteKind::MemberReference
                )
            {
                self.gap(call, ResolutionGapKind::UnsupportedCallApplicability);
                continue;
            }
            // This callee-owned marker carries the selected lowering provenance
            // consumed by the shared JVM callable-result projector. The typed
            // lowerer excludes this origin from lexical declaration gaps.
            self.gap(callee, ResolutionGapKind::UnsupportedCallApplicability);
            let receiver_node = infix_receiver.or_else(|| {
                (function.kind() == "field_expression")
                    .then(|| function.child_by_field_name("value"))
                    .flatten()
                    .filter(|_| !self.current_instance_members.contains(&callee))
            });
            let call_scope = self.facts.sites[call.index()].scope;
            let receiver = receiver_node.map(|receiver_node| {
                let input = self.expression_slot(receiver_node, call_scope);
                let output = self.add_slot(call, ResolutionTypeSlotRole::Receiver);
                self.add_call_input_transfer(input, output, ResolutionTypeTransferKind::Receiver);
                output
            });
            let result = *self
                .call_result_slots_by_node
                .get(&node.id())
                .expect("a Scala call site is allocated its result slot");
            self.facts.binding_projections.push(BindingProjectionFact {
                reference: callee,
                output: result,
                kind: BindingProjectionKind::TargetCallableResultType,
            });
            let invocation = if callee_namespace == Some(ResolutionNamespace::Value) {
                ResolutionInvocationRole::Apply
            } else {
                ResolutionInvocationRole::Direct
            };
            self.facts
                .invocation_roles
                .push(ResolutionInvocationRoleFact {
                    site: call,
                    role: invocation,
                    receiver,
                    result: Some(result),
                });
            let lists = application_nodes
                .into_iter()
                .map(|application| {
                    if application.kind() == "infix_expression" {
                        application
                            .child_by_field_name("right")
                            .into_iter()
                            .collect()
                    } else if let Some(arguments) = application.child_by_field_name("arguments") {
                        if arguments.kind() == "arguments" {
                            let mut cursor = arguments.walk();
                            arguments.named_children(&mut cursor).collect()
                        } else {
                            vec![arguments]
                        }
                    } else {
                        Vec::new()
                    }
                })
                .collect();
            self.publish_call_argument_lists(call, lists);
            self.facts.calls.push(ResolutionCallFact {
                call,
                callee,
                receiver,
                result,
                extra_result_slots: Vec::new(),
                explicit_type_argument_count: explicit_type_arguments.as_ref().map_or(
                    0,
                    |arguments| {
                        u32::try_from(arguments.len())
                            .expect("Scala explicit call type argument count fits u32")
                    },
                ),
            });
            if let Some(arguments) = explicit_type_arguments {
                for (ordinal, argument) in arguments.into_iter().enumerate() {
                    let identity = self.declared_type_identity_slot(call, argument);
                    let value = self.add_slot(call, ResolutionTypeSlotRole::DeclaredValue);
                    self.facts.type_transfers.push(ResolutionTypeTransferFact {
                        input: identity,
                        output: value,
                        kind: ResolutionTypeTransferKind::DeclaredType,
                        indirection_delta: 0,
                        reference_indirection_delta: 0,
                        value_transform: ResolutionTypeTransferValueTransform::ToRuntime {
                            addressable: false,
                        },
                    });
                    self.facts
                        .call_type_arguments
                        .push(ResolutionCallTypeArgumentFact {
                            call,
                            ordinal: u32::try_from(ordinal)
                                .expect("Scala explicit type argument count fits u32"),
                            value,
                        });
                }
            }
            self.facts
                .engine_rule_eligibilities
                .push(ResolutionEngineRuleEligibilityFact {
                    site: call,
                    rule: ResolutionEngineRuleKind::DirectOwnerExactPrimitiveDominance,
                });
        }
    }

    /// A written type is the identity slot of its head reference; a type
    /// whose head is not a plain, qualified, applied or projected name has no
    /// identity and keeps an `UnsupportedTypeSyntax` gap on its own site, so
    /// the gap qualifies the type and not the declaration that writes it.
    fn declared_type_identity_slot(
        &mut self,
        declaration: ResolutionSiteId,
        type_node: Node<'source>,
    ) -> ResolutionTypeSlotId {
        if let Some(name) = scala_intrinsic_declared_type_name(type_node) {
            let scope = self.facts.sites[declaration.index()].scope;
            let type_site = self.add_site(type_node, ResolutionSiteKind::TypeReference, scope);
            let slot = self.add_slot(type_site, ResolutionTypeSlotRole::TargetTypeIdentity);
            let name = self.intern_name(&name);
            self.facts.intrinsic_type_seeds.push(
                brokk_bifrost_core::analyzer::resolution_facts::IntrinsicTypeSeedFact::direct(
                    slot,
                    name,
                    brokk_bifrost_core::analyzer::resolution_facts::IntrinsicTypeKind::LanguageBuiltin,
                ),
            );
            if type_node.kind() == "function_type" {
                self.pending_function_types
                    .push((declaration, slot, type_node));
            }
            return slot;
        }
        scala_callable_result_type_head(type_node)
            .and_then(|head| self.sites_by_node.get(&head.id()).copied())
            .and_then(|reference| {
                self.projected_slot(reference, BindingProjectionKind::TargetTypeIdentity)
            })
            .unwrap_or_else(|| {
                let scope = self.facts.sites[declaration.index()].scope;
                let type_site = self.add_site(type_node, ResolutionSiteKind::TypeReference, scope);
                self.gap(type_site, ResolutionGapKind::UnsupportedTypeSyntax);
                self.add_slot(type_site, ResolutionTypeSlotRole::TargetTypeIdentity)
            })
    }

    /// The runtime value slot a declaration's written type gives it. `role`
    /// is `Value` for a val or var and `Parameter` for a parameter. The slot
    /// takes its type in `finish_declared_value_types`, once every type
    /// reference is positioned. A declaration without a written type keeps a
    /// slot with no producer for inference to fill.
    fn add_declared_value_slot(
        &mut self,
        declaration: ResolutionSiteId,
        role: DeclarationTypeRole,
        type_node: Option<Node<'source>>,
    ) -> ResolutionTypeSlotId {
        let slot = self.add_slot(declaration, ResolutionTypeSlotRole::DeclaredValue);
        self.facts
            .declaration_type_slots
            .push(DeclarationTypeSlotFact {
                declaration,
                slot,
                role,
            });
        if let Some(type_node) = type_node {
            self.pending_declared_value_types
                .push((declaration, slot, type_node));
        }
        slot
    }

    fn finish_declared_value_types(&mut self) {
        let mut explicit_functions = HashSet::default();
        for (declaration, output, type_node) in
            std::mem::take(&mut self.pending_declared_value_types)
        {
            if type_node.kind() == "function_type" {
                explicit_functions.insert(output);
            }
            let input = self.declared_type_identity_slot(declaration, type_node);
            crate::call_arguments::publish_jvm_declared_type_transfer(
                &mut self.facts,
                input,
                output,
                ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
            );
        }
        for (output, value, scope) in std::mem::take(&mut self.pending_initializers) {
            // A written function type owns its callable input and result shape.
            // Other annotations retain concrete initializer inference, including aliases.
            if explicit_functions.contains(&output) {
                continue;
            }
            let input = self.expression_slot(value, scope);
            self.facts
                .type_transfers
                .push(ResolutionTypeTransferFact::new(
                    input,
                    output,
                    ResolutionTypeTransferKind::Initialization,
                    0,
                    0,
                    ResolutionTypeTransferValueTransform::Preserve,
                ));
        }
        for (output, value, scope) in std::mem::take(&mut self.pending_initializer_values) {
            let input = self.expression_slot(value, scope);
            self.facts
                .type_transfers
                .push(ResolutionTypeTransferFact::new(
                    input,
                    output,
                    ResolutionTypeTransferKind::Assignment,
                    0,
                    0,
                    ResolutionTypeTransferValueTransform::Preserve,
                ));
        }
        for (alias, identity, target) in std::mem::take(&mut self.pending_type_aliases) {
            let input = self.declared_type_identity_slot(alias, target);
            if let Some(terminal) = scala_callable_result_type_head(target)
                && let Some(&reference) = self.sites_by_node.get(&terminal.id())
            {
                crate::implicit_supertype::publish_alias_supertype_name(&mut self.facts, reference);
            }
            self.facts
                .type_transfers
                .push(ResolutionTypeTransferFact::new(
                    input,
                    identity,
                    ResolutionTypeTransferKind::TypeAlias,
                    0,
                    0,
                    ResolutionTypeTransferValueTransform::Preserve,
                ));
        }
    }

    fn finish_writes(&mut self) {
        for (node, scope) in std::mem::take(&mut self.pending_writes) {
            let target = node.child_by_field_name("left").filter(|left| {
                matches!(left.kind(), "identifier" | "operator_identifier")
                    && !left.is_missing()
                    && !left.has_error()
            });
            let value = if node.kind() == "assignment_expression"
                && target.is_some()
                && let Some(right) = node.child_by_field_name("right")
            {
                self.expression_slot(right, scope)
            } else {
                // An assignment operator is a method application or a
                // read/modify/write operation, never a copy of its RHS.
                // An infix write already owns a call site and its receiver.
                // Keep mutation uncertainty off that supported receiver.
                let site =
                    self.add_site_distinct(node, ResolutionSiteKind::UnsupportedExpression, scope);
                self.gap(site, ResolutionGapKind::UnsupportedExpression);
                self.add_slot(site, ResolutionTypeSlotRole::ExpressionValue)
            };
            if let Some(target) = target {
                if let Some(target) = self.sites_by_node.get(&target.id()).copied() {
                    self.facts
                        .local_writes
                        .push(ResolutionLocalWriteFact { target, value });
                } else {
                    let site = self.facts.type_slots[value.index()].site;
                    self.gap(site, ResolutionGapKind::UnsupportedScopeOrBinder);
                }
            }
        }
    }

    fn finish_function_types(&mut self) {
        while let Some((declaration, owner, function)) = self.pending_function_types.pop() {
            let mut types = Vec::new();
            if let Some(parameters) = function.child_by_field_name("parameter_types") {
                let mut cursor = parameters.walk();
                types.extend(parameters.named_children(&mut cursor));
            }
            types.push(
                function
                    .child_by_field_name("return_type")
                    .expect("a function type has a result"),
            );
            let arguments = types
                .into_iter()
                .map(|ty| self.declared_type_identity_slot(declaration, ty))
                .collect::<Vec<_>>();
            let site = self.facts.type_slots[owner.index()].site;
            crate::call_arguments::publish_jvm_function_type_arguments(
                &mut self.facts,
                owner,
                site,
                &arguments,
            );
        }
    }

    fn finish_callable_result_types(&mut self, root: Node<'source>) {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
            if !matches!(
                node.kind(),
                "function_definition" | "function_declaration" | "given_definition"
            ) {
                continue;
            }
            let Some(callable) = self.declaration_sites.get(&node.id()).copied() else {
                continue;
            };
            let Some(return_type) = node.child_by_field_name("return_type") else {
                continue;
            };
            let input = self.declared_type_identity_slot(callable, return_type);
            let value_type = self.add_slot(callable, ResolutionTypeSlotRole::DeclaredValue);
            self.facts
                .declaration_type_slots
                .push(DeclarationTypeSlotFact {
                    declaration: callable,
                    slot: value_type,
                    role: DeclarationTypeRole::Return,
                });
            self.facts.type_transfers.push(ResolutionTypeTransferFact {
                input,
                output: value_type,
                kind: ResolutionTypeTransferKind::DeclaredType,
                indirection_delta: 0,
                reference_indirection_delta: 0,
                value_transform: ResolutionTypeTransferValueTransform::ToRuntime {
                    addressable: false,
                },
            });
            let signature = self
                .facts
                .callable_signatures
                .iter_mut()
                .find(|signature| signature.callable == callable)
                .expect("a Scala callable declaration has its signature row");
            assert!(
                signature.result_types.is_empty(),
                "a Scala callable starts without inferred result types"
            );
            signature.result_types.push(
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionCallableResultTypeFact {
                    ordinal: 0,
                    value_type,
                },
            );
        }
    }

    fn finish_shape_dependent_gaps(&mut self, root: Node<'source>) {
        let mut stack = vec![root];
        let mut type_declarations = Vec::new();
        let mut extensions = Vec::new();
        while let Some(node) = stack.pop() {
            let mut cursor = node.walk();
            let children = node.named_children(&mut cursor).collect::<Vec<_>>();
            stack.extend(children.iter().copied().rev());
            match node.kind() {
                "object_definition" | "trait_definition" | "class_definition"
                | "package_object" => {
                    if let Some(site) = self.declaration_sites.get(&node.id()).copied() {
                        type_declarations.push((node, site));
                    }
                }
                "extension_definition" => extensions.push(node),
                _ => {}
            }
        }

        for (node, site) in type_declarations {
            if node.kind() == "trait_definition" {
                // The source declaration and interface member names are stable.
                // Only the Scala 2.11 Trait$class implementation owner is
                // compiler-dependent, so keep that uncertainty on its JVM
                // aliases instead of blocking source routes through the trait.
                self.add_trait_jvm_aliases(node, site);
                continue;
            }
            if node.kind() == "class_definition" && has_case_modifier(node) {
                self.add_case_class_companion_aliases(node, site);
                if !scala_has_companion_object(node, self.source) {
                    let companion = self.synthesized_companions[&node.id()];
                    self.facts
                        .singleton_relations
                        .push(ResolutionSingletonRelationFact {
                            declaration: companion,
                            enclosing_type: Some(site),
                            kind: ResolutionSingletonRelationKind::Companion,
                        });
                }
            }
            if !matches!(node.kind(), "object_definition" | "package_object") {
                continue;
            }

            let companion = if node.kind() == "object_definition" {
                node.child_by_field_name("name").and_then(|name| {
                    node.parent().and_then(|parent| {
                        let mut cursor = parent.walk();
                        parent
                            .named_children(&mut cursor)
                            .filter(|sibling| {
                                sibling.id() != node.id()
                                    && matches!(
                                        sibling.kind(),
                                        "class_definition" | "trait_definition" | "enum_definition"
                                    )
                            })
                            .find(|sibling| {
                                declaration_name(*sibling).is_some_and(|sibling_name| {
                                    node_text(sibling_name, self.source)
                                        == node_text(name, self.source)
                                })
                            })
                            .and_then(|sibling| self.declaration_sites.get(&sibling.id()).copied())
                    })
                })
            } else {
                None
            };
            let enclosing_type = companion.or_else(|| {
                let owner = self.scope(self.facts.sites[site.index()].scope).owner?;
                matches!(
                    self.facts.sites[owner.index()].kind,
                    ResolutionSiteKind::TypeDeclaration
                )
                .then_some(owner)
            });
            self.facts
                .singleton_relations
                .push(ResolutionSingletonRelationFact {
                    declaration: site,
                    enclosing_type,
                    kind: if companion.is_some() {
                        ResolutionSingletonRelationKind::Companion
                    } else {
                        ResolutionSingletonRelationKind::Object
                    },
                });

            if node.kind() == "package_object" {
                let package_scope = self
                    .package_objects
                    .iter()
                    .find_map(|(package_object, scope)| (*package_object == site).then_some(*scope))
                    .expect("package object has a package scope");
                self.add_package_object_module_alias(site, package_scope);
            } else if node.kind() == "object_definition"
                && let Some(name) = declaration_name(node)
                && matches!(
                    self.scope(self.facts.sites[site.index()].scope).kind,
                    ResolutionScopeKind::CompilationUnit | ResolutionScopeKind::Package
                )
            {
                let scope = self.facts.sites[site.index()].scope;
                if !self.add_object_module_alias(site, name, scope) {
                    {
                        let classified_route = ResolutionRouteGap::UnknownAlias {
                            owner: ResolutionRouteOwner::Declaration(site),
                            binary_owner: self
                                .binary_owner_prefix(self.facts.sites[site.index()].scope),
                            name: Some(self.intern_name("MODULE$")),
                            kind: Some(ResolutionJvmAliasKind::SingletonInstance),
                        };
                        self.facts.add_route_gap(site, classified_route);
                    };
                }
            } else if node.kind() == "object_definition"
                && let Some(name) = declaration_name(node)
                && self.scope(self.facts.sites[site.index()].scope).kind
                    == ResolutionScopeKind::TypeBody
            {
                let scope = self.facts.sites[site.index()].scope;
                if !self.add_object_module_alias(site, name, scope) {
                    {
                        let classified_route = ResolutionRouteGap::UnknownAlias {
                            owner: ResolutionRouteOwner::Declaration(site),
                            binary_owner: self
                                .binary_owner_prefix(self.facts.sites[site.index()].scope),
                            name: Some(self.intern_name("MODULE$")),
                            kind: Some(ResolutionJvmAliasKind::SingletonInstance),
                        };
                        self.facts.add_route_gap(site, classified_route);
                    };
                }
            } else if node.kind() == "object_definition" {
                {
                    let classified_route = ResolutionRouteGap::UnknownAlias {
                        owner: ResolutionRouteOwner::Declaration(site),
                        binary_owner: self
                            .binary_owner_prefix(self.facts.sites[site.index()].scope),
                        name: Some(self.intern_name("MODULE$")),
                        kind: Some(ResolutionJvmAliasKind::SingletonInstance),
                    };
                    self.facts.add_route_gap(site, classified_route);
                };
            }
        }

        for extension in extensions {
            self.lower_extension_receivers(extension);
        }

        self.finish_exports(root);
    }

    fn add_object_module_alias(
        &mut self,
        declaration: ResolutionSiteId,
        name: Node<'source>,
        scope: ResolutionScopeId,
    ) -> bool {
        let Some(owner_segments) = self.jvm_type_owner_segments(scope, name, "$") else {
            return false;
        };
        let member_name = self.intern_name("MODULE$");
        let alias = ResolutionJvmAliasId::try_from_index(self.facts.jvm_aliases.len())
            .expect("Scala JVM alias count fits u32");
        self.facts.jvm_aliases.push(ResolutionJvmAliasFact {
            id: alias,
            declaration,
            member_name,
            kind: ResolutionJvmAliasKind::SingletonInstance,
            is_static: true,
            parameter_count: 0,
            status: ResolutionJvmAliasStatus::CompilerModeDependent,
        });
        self.facts
            .jvm_alias_owner_segments
            .extend(
                owner_segments
                    .into_iter()
                    .enumerate()
                    .map(|(ordinal, name)| ResolutionJvmAliasOwnerSegmentFact {
                        alias,
                        ordinal: u32::try_from(ordinal).expect("Scala JVM owner path fits u32"),
                        name,
                    }),
            );
        // The source declaration route is complete through its root exports
        // and singleton relation. Compiler-mode uncertainty remains on this
        // alias status, where selected JVM composition keeps it open.
        true
    }

    fn finish_exports(&mut self, root: Node<'source>) {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            let mut cursor = node.walk();
            let children = node.named_children(&mut cursor).collect::<Vec<_>>();
            stack.extend(children.iter().copied().rev());
            if node.kind() != "export_declaration" {
                continue;
            }

            let Some(scope) = self.enclosing_resolution_scope(node) else {
                self.unsupported_export(node);
                continue;
            };
            let scope_fact = self.scope(scope);
            if scope_fact.kind != ResolutionScopeKind::TypeBody {
                self.unsupported_export(node);
                continue;
            }
            let Some(exporter) = scope_fact.owner else {
                self.unsupported_export(node);
                continue;
            };
            let Some(export) = scala_export_info_from_node(node, self.source) else {
                self.unsupported_export(node);
                continue;
            };
            let Some(source_owner) = self.resolve_export_owner(scope, &export.owner_path) else {
                self.unsupported_export(node);
                continue;
            };
            let selector_nodes = scala_export_selector_nodes(node);
            if selector_nodes.len() != export.selectors.len() {
                self.unsupported_export(node);
                continue;
            }
            // The owner path as written, built into a typed reference chain
            // once and only when an exported type needs its identity.
            let mut owner_path_nodes = {
                let mut cursor = node.walk();
                node.children_by_field_name("path", &mut cursor)
                    .filter(Node::is_named)
                    .collect::<Vec<_>>()
            };
            owner_path_nodes.truncate(export.owner_path.len());
            let mut owner_chain = None;
            let named_sources = export
                .selectors
                .iter()
                .filter_map(|selector| match selector {
                    brokk_bifrost_core::analyzer::model::ScalaExportSelector::Named {
                        source_name,
                        ..
                    } => Some(source_name.as_str()),
                    brokk_bifrost_core::analyzer::model::ScalaExportSelector::Wildcard
                    | brokk_bifrost_core::analyzer::model::ScalaExportSelector::GivenWildcard => {
                        None
                    }
                })
                .collect::<HashSet<_>>();
            let mut complete = true;
            let mut published = false;
            // A forwarded term is reachable through its JVM spelling only. No
            // lexical or qualified binder names it, so lookups of it must stay
            // open instead of reporting an absent member.
            let mut term_open = false;
            for (selector, selector_node) in export.selectors.iter().zip(selector_nodes) {
                match selector {
                    brokk_bifrost_core::analyzer::model::ScalaExportSelector::Named {
                        visible_name: None,
                        ..
                    } => {}
                    brokk_bifrost_core::analyzer::model::ScalaExportSelector::Named {
                        source_name,
                        visible_name: Some(visible_name),
                    } => {
                        let members = self.export_members_named(source_owner, source_name);
                        if members.is_empty() {
                            complete = false;
                            continue;
                        }
                        for member in members.iter().copied() {
                            let type_member = matches!(
                                self.facts.sites[member.index()].kind,
                                ResolutionSiteKind::TypeDeclaration
                                    | ResolutionSiteKind::TypeAliasDeclaration
                            );
                            if type_member {
                                if members.len() == 1
                                    && self.publish_export_type_alias(
                                        ExportedType {
                                            member,
                                            exporter,
                                            scope,
                                            owner_path: &owner_path_nodes,
                                            owner_chain: &mut owner_chain,
                                        },
                                        selector_node,
                                        source_name,
                                        visible_name,
                                    )
                                {
                                    published = true;
                                } else {
                                    complete = false;
                                }
                            } else if self.publish_export_jvm_alias(member, exporter, visible_name)
                            {
                                published = true;
                                term_open = true;
                            } else {
                                complete = false;
                            }
                        }
                    }
                    brokk_bifrost_core::analyzer::model::ScalaExportSelector::Wildcard => {
                        // Members the owner inherits are exported too, and
                        // this producer sees only the owner's own members.
                        if self
                            .facts
                            .supertypes
                            .iter()
                            .any(|supertype| supertype.subtype == source_owner)
                        {
                            complete = false;
                        }
                        for member in self.export_members(source_owner) {
                            let Some(source_name) =
                                self.declaration_spelling(member).map(str::to_owned)
                            else {
                                complete = false;
                                continue;
                            };
                            if named_sources.contains(source_name.as_str()) {
                                continue;
                            }
                            let type_member = matches!(
                                self.facts.sites[member.index()].kind,
                                ResolutionSiteKind::TypeDeclaration
                                    | ResolutionSiteKind::TypeAliasDeclaration
                            );
                            let published_member = if type_member {
                                self.publish_export_type_alias(
                                    ExportedType {
                                        member,
                                        exporter,
                                        scope,
                                        owner_path: &owner_path_nodes,
                                        owner_chain: &mut owner_chain,
                                    },
                                    selector_node,
                                    &source_name,
                                    &source_name,
                                )
                            } else {
                                term_open = true;
                                self.publish_export_jvm_alias(member, exporter, &source_name)
                            };
                            if published_member {
                                published = true;
                            } else {
                                complete = false;
                            }
                        }
                    }
                    brokk_bifrost_core::analyzer::model::ScalaExportSelector::GivenWildcard => {
                        complete = false;
                    }
                }
            }
            if !complete || !published || term_open {
                self.unsupported_export(node);
            }
        }
    }

    fn enclosing_resolution_scope(&self, node: Node<'source>) -> Option<ResolutionScopeId> {
        let mut current = Some(node);
        while let Some(candidate) = current {
            if let Some(scope) = self.scopes_by_node.get(&candidate.id()) {
                return Some(*scope);
            }
            current = candidate.parent();
        }
        None
    }

    /// An export clause whose members are not all published leaves the
    /// exporting type's member set open, the same incompleteness an
    /// unresolved supertype leaves. Direct members still outrank that branch,
    /// so only lookups the exports could have answered stay incomplete. An
    /// export outside a type body has no member set to hold open.
    fn unsupported_export(&mut self, node: Node<'source>) {
        let scope = self
            .enclosing_resolution_scope(node)
            .unwrap_or(self.root_scope);
        let scope_fact = self.scope(scope);
        if scope_fact.kind == ResolutionScopeKind::TypeBody
            && let Some(exporter) = scope_fact.owner
        {
            self.gap(exporter, ResolutionGapKind::UnsupportedHierarchyTraversal);
            return;
        }
        let site = self.add_site(node, ResolutionSiteKind::UnsupportedRoute, scope);
        let names = scala_export_info_from_node(node, self.source).map(|export| {
            export.selectors.into_iter().filter_map(|selector| match selector {
                brokk_bifrost_core::analyzer::model::ScalaExportSelector::Named { visible_name, .. } => visible_name.map(Some),
                brokk_bifrost_core::analyzer::model::ScalaExportSelector::Wildcard
                | brokk_bifrost_core::analyzer::model::ScalaExportSelector::GivenWildcard => Some(None),
            }).collect::<Vec<_>>()
        }).unwrap_or_else(|| vec![None]);
        for name in names {
            let name = name.as_deref().map(|name| self.intern_name(name));
            self.facts.add_route_gap(
                site,
                ResolutionRouteGap::UnknownBinder {
                    scope,
                    name,
                    namespace: None,
                    may_publish: true,
                },
            );
        }
        self.facts
            .reference_enumeration_gaps
            .push(ResolutionReferenceEnumerationGapFact {
                site,
                kind: ResolutionGapKind::UnsupportedRoute,
            });
    }

    /// Resolve the stable path of an export clause to a singleton declared in
    /// this file. The first segment follows Scala's lexical rule: the nearest
    /// enclosing scope that declares an object of that name wins. Later
    /// segments are members of the previous object. A path that starts at an
    /// import, a value or another file names an owner this producer cannot
    /// see, so the caller holds the member set open.
    fn resolve_export_owner(
        &self,
        mut scope: ResolutionScopeId,
        path: &[String],
    ) -> Option<ResolutionSiteId> {
        let (first, rest) = path.split_first()?;
        let mut owner = loop {
            let mut candidates = self
                .facts
                .sites
                .iter()
                .filter(|site| site.scope == scope && self.is_singleton_declaration(site.id))
                .map(|site| site.id)
                .filter(|site| self.declaration_spelling(*site) == Some(first.as_str()))
                .collect::<Vec<_>>();
            candidates.sort_unstable();
            candidates.dedup();
            match candidates.as_slice() {
                [] => scope = self.scope(scope).parent?,
                [found] => break *found,
                _ => return None,
            }
        };
        for segment in rest {
            let mut candidates = self
                .export_members_named(owner, segment)
                .into_iter()
                .filter(|member| self.is_singleton_declaration(*member))
                .collect::<Vec<_>>();
            candidates.sort_unstable();
            candidates.dedup();
            let [next] = candidates.as_slice() else {
                return None;
            };
            owner = *next;
        }
        Some(owner)
    }

    fn is_singleton_declaration(&self, site: ResolutionSiteId) -> bool {
        self.facts.sites[site.index()].kind == ResolutionSiteKind::TypeDeclaration
            && self.facts.singleton_relations.iter().any(|relation| {
                relation.declaration == site
                    && matches!(
                        relation.kind,
                        ResolutionSingletonRelationKind::Object
                            | ResolutionSingletonRelationKind::Companion
                    )
            })
    }

    fn export_members(&self, owner: ResolutionSiteId) -> Vec<ResolutionSiteId> {
        let mut members = self
            .facts
            .member_owners
            .iter()
            .filter(|relation| relation.owner == owner)
            .map(|relation| relation.member)
            .collect::<Vec<_>>();
        members.sort_unstable();
        members.dedup();
        members
    }

    fn export_members_named(&self, owner: ResolutionSiteId, name: &str) -> Vec<ResolutionSiteId> {
        self.export_members(owner)
            .into_iter()
            .filter(|member| self.declaration_spelling(*member) == Some(name))
            .collect()
    }

    fn declaration_spelling(&self, declaration: ResolutionSiteId) -> Option<&str> {
        self.facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.site == declaration
                    && identifier.role == ResolutionIdentifierRole::Declaration
            })
            .map(|identifier| self.facts.names[identifier.name.index()].spelling.as_str())
    }

    /// Export `exported.member` under `visible_name`. The alias takes the type
    /// identity of its target through a reference to it, written as the export
    /// path qualified by the member's own name, exactly as a qualified type
    /// path in source would be.
    fn publish_export_type_alias(
        &mut self,
        exported: ExportedType<'_, 'source>,
        syntax: Node<'source>,
        source_name: &str,
        visible_name: &str,
    ) -> bool {
        let ExportedType {
            member: target,
            exporter,
            scope,
            owner_path,
            owner_chain,
        } = exported;
        if !matches!(
            self.facts.sites[target.index()].kind,
            ResolutionSiteKind::TypeDeclaration | ResolutionSiteKind::TypeAliasDeclaration
        ) || self.is_singleton_declaration(target)
        {
            return false;
        }
        let Some(source_declaration) = self
            .declaration_sources
            .iter()
            .find_map(|(site, source)| (*site == target).then_some(*source))
        else {
            return false;
        };
        let Some(target_member) = self
            .facts
            .member_owners
            .iter()
            .find(|relation| relation.member == target)
            .copied()
        else {
            return false;
        };
        let owner_slot = match *owner_chain {
            Some(slot) => slot,
            None => {
                let slot = self.lower_export_owner_chain(owner_path, scope, exporter);
                *owner_chain = Some(slot);
                slot
            }
        };
        let target_identity =
            self.lower_exported_member_reference(syntax, source_name, scope, exporter, owner_slot);
        let alias = self.add_site_distinct(syntax, ResolutionSiteKind::TypeAliasDeclaration, scope);
        let name = self.intern_name(visible_name);
        self.facts.identifiers.push(PositionedIdentifierFact {
            site: alias,
            name,
            role: ResolutionIdentifierRole::Declaration,
            namespace: ResolutionNamespace::Type,
            qualifier: None,
        });
        self.facts.binders.push(ResolutionBinderFact {
            declaration: alias,
            scope,
            kind: ResolutionBinderKind::Type,
            hoisting: HoistingClass::ScopeWide,
            activation_start: self.scope(scope).start_byte,
            activation_end: self.scope(scope).end_byte,
        });
        // The alias is a member of the exporter with the shape its target has
        // in the owner it was written in, so qualifiers reach it the same way.
        self.facts.member_owners.push(ResolutionMemberOwnerFact {
            member: alias,
            owner: exporter,
            kind: ResolutionMemberKind::AssociatedType,
            ..target_member
        });
        let identity = self.add_slot(alias, ResolutionTypeSlotRole::TargetTypeIdentity);
        self.facts
            .declaration_type_slots
            .push(DeclarationTypeSlotFact {
                declaration: alias,
                slot: identity,
                role: DeclarationTypeRole::Identity,
            });
        self.facts.type_transfers.push(ResolutionTypeTransferFact {
            input: target_identity,
            output: identity,
            kind: ResolutionTypeTransferKind::TypeAlias,
            indirection_delta: 0,
            reference_indirection_delta: 0,
            value_transform: ResolutionTypeTransferValueTransform::Preserve,
        });
        self.declaration_sources.push((alias, source_declaration));
        let visibility = self
            .facts
            .declaration_visibilities
            .iter()
            .find(|visibility| visibility.declaration == target)
            .map(|visibility| visibility.visibility)
            .unwrap_or(DeclaredVisibility::Unknown);
        self.facts.visibility_eligibilities.push(
            brokk_bifrost_core::analyzer::resolution_facts::ResolutionVisibilityEligibilityFact {
                declaration: alias,
            },
        );
        self.facts
            .declaration_visibilities
            .push(ResolutionDeclarationVisibilityFact {
                declaration: alias,
                visibility,
            });
        if visibility != DeclaredVisibility::Public {
            self.gap(alias, ResolutionGapKind::UnsupportedVisibility);
        }
        true
    }

    /// The typed chain an export path spells: its first segment is an
    /// ordinary Type reference in the exporter's body, and every later segment
    /// a member reference qualified by the segment before it. The returned
    /// slot is the identity of the exported owner. The path names a singleton
    /// declared in this file (`resolve_export_owner`), so no package reading
    /// of it exists and the chain carries no ambiguity gap.
    fn lower_export_owner_chain(
        &mut self,
        path: &[Node<'source>],
        scope: ResolutionScopeId,
        exporter: ResolutionSiteId,
    ) -> ResolutionTypeSlotId {
        let mut qualifier = None;
        for segment in path {
            // Every segment names a singleton, which is a term.
            let kind = if qualifier.is_some() {
                ResolutionSiteKind::MemberReference
            } else {
                ResolutionSiteKind::ValueReference
            };
            let site = self.add_site(*segment, kind, scope);
            self.identifier(
                site,
                *segment,
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::TypeOrValue,
                qualifier,
            );
            let output = self.reference_identity_slot(
                site,
                Some(exporter),
                ResolutionNamespace::TypeOrValue,
            );
            qualifier = Some(output);
        }
        qualifier.expect("an export has an owner path")
    }

    /// A reference, qualified by the exported owner, to the member an export
    /// selector names. Its identity slot feeds the alias the export declares.
    fn lower_exported_member_reference(
        &mut self,
        selector: Node<'source>,
        source_name: &str,
        scope: ResolutionScopeId,
        exporter: ResolutionSiteId,
        owner: ResolutionTypeSlotId,
    ) -> ResolutionTypeSlotId {
        let site = self.add_site_distinct(selector, ResolutionSiteKind::MemberReference, scope);
        let name = self.intern_name(source_name);
        self.facts.identifiers.push(PositionedIdentifierFact {
            site,
            name,
            role: ResolutionIdentifierRole::Reference,
            namespace: ResolutionNamespace::Type,
            qualifier: Some(owner),
        });
        self.reference_identity_slot(site, Some(exporter), ResolutionNamespace::Type)
    }

    /// The slot a reference projects, with the reference owned by the
    /// declaration it is written in.
    fn reference_identity_slot(
        &mut self,
        site: ResolutionSiteId,
        owner: Option<ResolutionSiteId>,
        namespace: ResolutionNamespace,
    ) -> ResolutionTypeSlotId {
        self.facts
            .reference_owners
            .push(ResolutionReferenceOwnerFact {
                reference: site,
                owner: self.declaration_owner(owner),
            });
        self.projected_identity_slot(site, namespace)
    }

    /// The slot a reference projects. A Type reference projects the identity
    /// of the type it names. A term path segment may name a type object or a
    /// value, so it projects either and a qualified member continues from
    /// whichever it is. A Value reference projects the declared type of the
    /// value it reads.
    fn projected_identity_slot(
        &mut self,
        site: ResolutionSiteId,
        namespace: ResolutionNamespace,
    ) -> ResolutionTypeSlotId {
        let (role, kind) = match namespace {
            ResolutionNamespace::Type => (
                ResolutionTypeSlotRole::TargetTypeIdentity,
                BindingProjectionKind::TargetTypeIdentity,
            ),
            ResolutionNamespace::Value => (
                ResolutionTypeSlotRole::ExpressionValue,
                BindingProjectionKind::TargetDeclaredValueType,
            ),
            ResolutionNamespace::TypeOrValue => (
                ResolutionTypeSlotRole::ExpressionValue,
                BindingProjectionKind::TargetTypeOrDeclaredValueType,
            ),
            _ => unreachable!("a reference that projects a type or value has such a namespace"),
        };
        let output = self.add_slot(site, role);
        self.facts.binding_projections.push(BindingProjectionFact {
            reference: site,
            output,
            kind,
        });
        output
    }

    fn publish_export_jvm_alias(
        &mut self,
        target: ResolutionSiteId,
        exporter: ResolutionSiteId,
        visible_name: &str,
    ) -> bool {
        let Some(exporter_node) = self.declaration_nodes.get(&exporter).copied() else {
            return false;
        };
        let Some(exporter_name) = declaration_name(exporter_node) else {
            return false;
        };
        let suffix = if exporter_node.kind() == "object_definition" {
            "$"
        } else {
            ""
        };
        let Some(owner_segments) = self.jvm_type_owner_segments(
            self.facts.sites[exporter.index()].scope,
            exporter_name,
            suffix,
        ) else {
            return false;
        };
        let Some(target_node) = self.declaration_nodes.get(&target).copied() else {
            return false;
        };
        let member_name = self.intern_name(&scala_jvm_member_name(visible_name));
        match target_node.kind() {
            "function_definition" | "function_declaration" | "given_definition" => {
                self.add_jvm_alias(
                    target,
                    member_name,
                    ResolutionJvmAliasKind::Method,
                    false,
                    scala_callable_parameter_count(target_node),
                    ResolutionJvmAliasStatus::SourceProven,
                    owner_segments,
                );
                true
            }
            "val_definition" | "var_definition" | "val_declaration" | "var_declaration" => {
                self.add_jvm_alias(
                    target,
                    member_name,
                    ResolutionJvmAliasKind::Getter,
                    false,
                    0,
                    ResolutionJvmAliasStatus::SourceProven,
                    owner_segments.clone(),
                );
                if matches!(target_node.kind(), "var_definition" | "var_declaration") {
                    let setter_name = self.intern_name(&format!("{visible_name}_$eq"));
                    self.add_jvm_alias(
                        target,
                        setter_name,
                        ResolutionJvmAliasKind::Setter,
                        false,
                        1,
                        ResolutionJvmAliasStatus::SourceProven,
                        owner_segments,
                    );
                }
                true
            }
            _ => false,
        }
    }

    fn add_package_object_module_alias(
        &mut self,
        declaration: ResolutionSiteId,
        package_scope: ResolutionScopeId,
    ) {
        assert!(
            self.facts
                .packages
                .iter()
                .any(|package| package.root_scope == package_scope)
        );
        let mut segments = self
            .facts
            .package_segments
            .iter()
            .filter(|segment| segment.root_scope == package_scope)
            .map(|segment| (segment.ordinal, segment.name))
            .collect::<Vec<_>>();
        segments.sort_unstable_by_key(|(ordinal, _)| *ordinal);
        let mut owner_segments = segments
            .into_iter()
            .map(|(_, name)| name)
            .collect::<Vec<_>>();
        owner_segments.push(self.intern_name("package$"));
        let member_name = self.intern_name("MODULE$");
        self.add_jvm_alias(
            declaration,
            member_name,
            ResolutionJvmAliasKind::SingletonInstance,
            true,
            0,
            ResolutionJvmAliasStatus::CompilerModeDependent,
            owner_segments,
        );
    }

    fn add_trait_jvm_aliases(&mut self, node: Node<'source>, declaration: ResolutionSiteId) {
        let name = declaration_name(node).expect("named Scala trait declaration");
        let scope = self.facts.sites[declaration.index()].scope;
        let Some(interface_owner) = self.jvm_type_owner_segments(scope, name, "") else {
            return;
        };
        let Some(legacy_owner) = self.jvm_type_owner_segments(scope, name, "$class") else {
            return;
        };
        let mut members = Vec::new();
        let mut stack = vec![node];
        while let Some(member_node) = stack.pop() {
            let is_callable = matches!(
                member_node.kind(),
                "function_definition" | "function_declaration"
            );
            let value_declaration = scala_enclosing_value_declaration(member_node);
            let is_field_declaration = value_declaration.is_some();
            if (is_callable || is_field_declaration)
                && let Some(member) = self
                    .declaration_sites
                    .get(&member_node.id())
                    .or_else(|| self.sites_by_node.get(&member_node.id()))
                    .copied()
                && self.facts.member_owners.iter().any(|owner| {
                    owner.member == member
                        && owner.owner == declaration
                        && owner.kind
                            == if is_callable {
                                ResolutionMemberKind::Method
                            } else {
                                ResolutionMemberKind::Field
                            }
                })
            {
                let member_name = if is_callable || member_node.kind().ends_with("declaration") {
                    declaration_name(member_node)
                        .expect("Scala trait member declaration has a name")
                } else if is_field_declaration
                    && matches!(
                        member_node.kind(),
                        "val_definition" | "var_definition" | "val_declaration" | "var_declaration"
                    )
                {
                    declaration_name(member_node).expect("Scala trait field declaration has a name")
                } else {
                    member_node
                };
                let encoded_name = scala_jvm_member_name(node_text(member_name, self.source));
                let has_body = member_node.child_by_field_name("body").is_some();
                let parameter_count = if is_callable {
                    scala_callable_parameter_count(member_node)
                } else {
                    0
                };
                members.push((
                    member,
                    encoded_name,
                    is_callable,
                    value_declaration.is_some_and(|declaration| {
                        matches!(declaration.kind(), "var_definition" | "var_declaration")
                    }),
                    has_body,
                    value_declaration.is_some_and(|declaration| {
                        matches!(declaration.kind(), "val_definition" | "var_definition")
                    }),
                    parameter_count,
                ));
            }
            let mut cursor = member_node.walk();
            stack.extend(member_node.named_children(&mut cursor));
        }

        let mut has_initializers = false;
        for (
            member,
            member_name,
            is_callable,
            is_var,
            has_body,
            has_initializer,
            parameter_count,
        ) in members
        {
            let name = self.intern_name(&member_name);
            if is_callable {
                self.add_jvm_alias(
                    member,
                    name,
                    ResolutionJvmAliasKind::Method,
                    false,
                    parameter_count,
                    ResolutionJvmAliasStatus::SourceProven,
                    interface_owner.clone(),
                );
                if has_body {
                    self.add_jvm_alias(
                        member,
                        name,
                        ResolutionJvmAliasKind::Method,
                        true,
                        parameter_count
                            .checked_add(1)
                            .expect("Scala trait receiver fits JVM parameter count"),
                        ResolutionJvmAliasStatus::CompilerModeDependent,
                        legacy_owner.clone(),
                    );
                }
            } else {
                self.add_jvm_alias(
                    member,
                    name,
                    ResolutionJvmAliasKind::Getter,
                    false,
                    0,
                    ResolutionJvmAliasStatus::SourceProven,
                    interface_owner.clone(),
                );
                if is_var {
                    let setter_name = self.intern_name(&format!("{member_name}_$eq"));
                    self.add_jvm_alias(
                        member,
                        setter_name,
                        ResolutionJvmAliasKind::Setter,
                        false,
                        1,
                        ResolutionJvmAliasStatus::SourceProven,
                        interface_owner.clone(),
                    );
                }
                has_initializers |= has_initializer;
            }
        }
        if has_initializers {
            let initializer = self.intern_name("$init$");
            self.add_jvm_alias(
                declaration,
                initializer,
                ResolutionJvmAliasKind::Method,
                true,
                1,
                ResolutionJvmAliasStatus::CompilerModeDependent,
                legacy_owner,
            );
        }
    }

    /// The JVM spellings of the companion's `apply` and `unapply`, projected back to
    /// the members published for the case class.
    fn add_case_class_companion_aliases(
        &mut self,
        node: Node<'source>,
        declaration: ResolutionSiteId,
    ) {
        let Some(&(apply, unapply)) = self.case_class_members.get(&node.id()) else {
            return;
        };
        let name = declaration_name(node).expect("named Scala case class declaration");
        let scope = self.facts.sites[declaration.index()].scope;
        let Some(owner_segments) = self.jvm_type_owner_segments(scope, name, "$") else {
            for (member, spelling) in [
                (apply, "apply"),
                (
                    unapply,
                    if scala_case_class_has_repeated_parameter(node) {
                        "unapplySeq"
                    } else {
                        "unapply"
                    },
                ),
            ] {
                if let Some(member) = member {
                    let name = self.intern_name(spelling);
                    self.facts.add_route_gap(
                        member,
                        ResolutionRouteGap::UnknownAlias {
                            owner: ResolutionRouteOwner::Declaration(declaration),
                            binary_owner: self.binary_owner_prefix(scope),
                            name: Some(name),
                            kind: Some(ResolutionJvmAliasKind::Method),
                        },
                    );
                }
            }
            return;
        };
        if let Some(apply) = apply {
            let apply_name = self.intern_name("apply");
            self.add_jvm_alias(
                apply,
                apply_name,
                ResolutionJvmAliasKind::Method,
                false,
                scala_case_class_parameter_count(node),
                ResolutionJvmAliasStatus::CompilerModeDependent,
                owner_segments.clone(),
            );
        }
        if let Some(unapply) = unapply {
            let unapply_name = self.intern_name(if scala_case_class_has_repeated_parameter(node) {
                "unapplySeq"
            } else {
                "unapply"
            });
            self.add_jvm_alias(
                unapply,
                unapply_name,
                ResolutionJvmAliasKind::Method,
                false,
                1,
                ResolutionJvmAliasStatus::CompilerModeDependent,
                owner_segments,
            );
        }
    }

    fn jvm_type_owner_segments(
        &mut self,
        scope: ResolutionScopeId,
        name: Node<'source>,
        suffix: &str,
    ) -> Option<Vec<ResolutionNameId>> {
        if !matches!(
            self.scope(scope).kind,
            ResolutionScopeKind::CompilationUnit
                | ResolutionScopeKind::Package
                | ResolutionScopeKind::TypeBody
        ) {
            return None;
        }
        let package_root_scope = self.package_scope_for(scope);
        assert!(
            self.facts
                .packages
                .iter()
                .any(|package| package.root_scope == package_root_scope)
        );
        let mut owner_names = Vec::new();
        let mut owner = self.scope(scope).owner;
        while let Some(owner_site) = owner {
            match self.facts.sites[owner_site.index()].kind {
                ResolutionSiteKind::TypeDeclaration => {}
                ResolutionSiteKind::PackageDeclaration => break,
                _ => return None,
            }
            let owner_name = self.facts.identifiers.iter().find_map(|identifier| {
                (identifier.site == owner_site
                    && identifier.role == ResolutionIdentifierRole::Declaration)
                    .then(|| self.facts.names[identifier.name.index()].spelling.clone())
            })?;
            owner_names.push(scala_identifier_spelling(&owner_name).to_owned());
            owner = self.scope(self.facts.sites[owner_site.index()].scope).owner;
        }
        owner_names.reverse();
        owner_names.push(scala_identifier_spelling(node_text(name, self.source)).to_owned());
        let binary_name = self.intern_name(&format!("{}{}", owner_names.join("$"), suffix));
        let mut segments = self
            .facts
            .package_segments
            .iter()
            .filter(|segment| segment.root_scope == package_root_scope)
            .map(|segment| (segment.ordinal, segment.name))
            .collect::<Vec<_>>();
        segments.sort_unstable_by_key(|(ordinal, _)| *ordinal);
        let mut owner_segments = segments
            .into_iter()
            .map(|(_, name)| name)
            .collect::<Vec<_>>();
        owner_segments.push(binary_name);
        Some(owner_segments)
    }

    #[allow(clippy::too_many_arguments)]
    fn add_jvm_alias(
        &mut self,
        declaration: ResolutionSiteId,
        member_name: ResolutionNameId,
        kind: ResolutionJvmAliasKind,
        is_static: bool,
        parameter_count: u32,
        status: ResolutionJvmAliasStatus,
        owner_segments: Vec<ResolutionNameId>,
    ) {
        let alias = ResolutionJvmAliasId::try_from_index(self.facts.jvm_aliases.len())
            .expect("Scala JVM alias count fits u32");
        self.facts.jvm_aliases.push(ResolutionJvmAliasFact {
            id: alias,
            declaration,
            member_name,
            kind,
            is_static,
            parameter_count,
            status,
        });
        self.facts
            .jvm_alias_owner_segments
            .extend(
                owner_segments
                    .into_iter()
                    .enumerate()
                    .map(|(ordinal, name)| ResolutionJvmAliasOwnerSegmentFact {
                        alias,
                        ordinal: u32::try_from(ordinal).expect("Scala JVM owner path fits u32"),
                        name,
                    }),
            );
    }

    /// Name the direct methods whose receiver contract is missing. Local
    /// functions inside those methods keep their independent binder identity.
    fn extension_route_binders(
        &self,
        extension: Node<'source>,
    ) -> Vec<(ResolutionScopeId, Option<ResolutionNameId>)> {
        self.facts
            .identifiers
            .iter()
            .filter_map(|identifier| {
                let site = self.facts.sites[identifier.site.index()];
                if identifier.role != ResolutionIdentifierRole::Declaration
                    || identifier.namespace != ResolutionNamespace::Callable
                    || site.start_byte < extension.start_byte()
                    || site.end_byte > extension.end_byte()
                {
                    return None;
                }
                let node = *self.declaration_nodes.get(&identifier.site)?;
                if !matches!(node.kind(), "function_definition" | "function_declaration") {
                    return None;
                }
                let enclosing_callable = node
                    .parent()
                    .and_then(|parent| nearest_ancestor(parent, "function_definition"));
                if enclosing_callable.is_some_and(|owner| {
                    extension.start_byte() <= owner.start_byte()
                        && owner.end_byte() <= extension.end_byte()
                }) {
                    return None;
                }
                Some((site.scope, Some(identifier.name)))
            })
            .collect()
    }

    fn lower_extension_receivers(&mut self, extension: Node<'source>) {
        let extension_scope = self.scopes_by_node[&extension.id()];
        let binding_scope = self
            .scope(extension_scope)
            .parent
            .expect("extension has an enclosing binding scope");
        if nearest_ancestor(extension, "given_definition").is_some() {
            // Native facts do not yet model given discovery or given imports.
            // Keep the named omission visible in the enclosing scope, without
            // exporting an ordinary callable as a substitute for that search.
            let scope = binding_scope;
            let mut stack = vec![extension];
            while let Some(node) = stack.pop() {
                if node.id() != extension.id()
                    && matches!(node.kind(), "function_definition" | "function_declaration")
                {
                    if let Some(name) = declaration_name(node) {
                        let site = self.add_site_distinct(
                            node,
                            ResolutionSiteKind::UnsupportedDeclaration,
                            scope,
                        );
                        self.identifier(
                            site,
                            name,
                            ResolutionIdentifierRole::Declaration,
                            ResolutionNamespace::Callable,
                            None,
                        );
                        self.gap(site, ResolutionGapKind::UnsupportedScopeOrBinder);
                        self.facts.reference_enumeration_gaps.push(
                            ResolutionReferenceEnumerationGapFact {
                                site,
                                kind: ResolutionGapKind::UnsupportedScopeOrBinder,
                            },
                        );
                    }
                    continue;
                }
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor));
            }
            return;
        }
        let mut cursor = extension.walk();
        let Some(parameters) = extension
            .children_by_field_name("parameters", &mut cursor)
            .find(|parameters| parameters.kind() == "parameters")
        else {
            let site = self.add_site(
                extension,
                ResolutionSiteKind::UnsupportedRoute,
                binding_scope,
            );
            let mut binders = self.extension_route_binders(extension);
            if binders.is_empty() {
                binders.push((binding_scope, None));
            }
            for (scope, name) in binders {
                self.facts.add_route_gap(
                    site,
                    ResolutionRouteGap::UnknownBinder {
                        scope,
                        name,
                        namespace: Some(ResolutionNamespace::Callable),
                        may_publish: true,
                    },
                );
            }
            return;
        };
        let mut cursor = parameters.walk();
        let receiver_parameter = parameters
            .named_children(&mut cursor)
            .find(|child| matches!(child.kind(), "parameter" | "class_parameter"));
        let receiver_type =
            receiver_parameter.and_then(|parameter| parameter.child_by_field_name("type"));
        let mut stack = vec![extension];
        let mut method_count = 0usize;
        let mut unsupported = receiver_type.is_none();
        while let Some(node) = stack.pop() {
            let mut cursor = node.walk();
            let children = node.named_children(&mut cursor).collect::<Vec<_>>();
            if node.id() != extension.id()
                && matches!(node.kind(), "function_definition" | "function_declaration")
            {
                method_count += 1;
                if let (Some(callable), Some(receiver_type)) = (
                    self.declaration_sites.get(&node.id()).copied(),
                    receiver_type,
                ) {
                    // Use the same structured type interpretation as ordinary
                    // formals: a generic receiver names its head, not its last
                    // type argument, and compound types retain their frontier.
                    let receiver_type = self.declared_type_identity_slot(callable, receiver_type);
                    self.facts.extension_receivers.push(
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionExtensionReceiverFact {
                            callable,
                            receiver_type,
                        },
                    );
                } else {
                    unsupported = true;
                }
                continue;
            }
            stack.extend(children.into_iter().rev());
        }
        if unsupported || method_count == 0 {
            let site = self.add_site(
                extension,
                ResolutionSiteKind::UnsupportedRoute,
                binding_scope,
            );
            let mut binders = self.extension_route_binders(extension);
            if binders.is_empty() {
                binders.push((binding_scope, None));
            }
            for (scope, name) in binders {
                self.facts.add_route_gap(
                    site,
                    ResolutionRouteGap::UnknownBinder {
                        scope,
                        name,
                        namespace: Some(ResolutionNamespace::Callable),
                        may_publish: true,
                    },
                );
            }
            self.facts
                .reference_enumeration_gaps
                .push(ResolutionReferenceEnumerationGapFact {
                    site,
                    kind: ResolutionGapKind::UnsupportedRoute,
                });
        }
    }

    /// The slot that holds the value of an expression. A reference or a
    /// selection owns the slot its binding projects, a call owns its result,
    /// and a literal or `new` expression seeds its own. Any other expression
    /// has no modeled type: it keeps an `InferredType` gap on its site.
    fn expression_slot(
        &mut self,
        node: Node<'source>,
        scope: ResolutionScopeId,
    ) -> ResolutionTypeSlotId {
        let expression = expression_target_node(node);
        if let Some(slot) = self.super_receiver_slots_by_node.get(&expression.id()) {
            return *slot;
        }
        if let Some(slot) = self.call_result_slots_by_node.get(&expression.id()) {
            return *slot;
        }
        // A selection `owner.member` denotes the value of its selected member
        // reference, so its value is that reference's slot.
        let value_node = if expression.kind() == "field_expression" {
            expression
                .child_by_field_name("field")
                .unwrap_or(expression)
        } else {
            expression
        };
        if let Some(slot) = self.expression_slots_by_node.get(&value_node.id()) {
            return *slot;
        }
        let slot = match expression.kind() {
            "instance_expression" => self.construction_slot(expression, scope),
            "call_expression" => self.curried_construction_slot(expression, scope),
            kind => match scala_literal_type_name(kind, expression, self.source) {
                Some(type_name) => self.literal_slot(expression, scope, type_name),
                None => self.unsupported_expression_slot(expression, scope),
            },
        };
        self.expression_slots_by_node.insert(value_node.id(), slot);
        slot
    }

    fn unsupported_expression_slot(
        &mut self,
        expression: Node<'source>,
        scope: ResolutionScopeId,
    ) -> ResolutionTypeSlotId {
        let site = self.add_site(expression, ResolutionSiteKind::UnsupportedExpression, scope);
        self.gap(site, ResolutionGapKind::InferredType);
        self.add_slot(site, ResolutionTypeSlotRole::ExpressionValue)
    }

    /// A literal's type is known from its syntax alone.
    fn literal_slot(
        &mut self,
        literal: Node<'source>,
        scope: ResolutionScopeId,
        type_name: &str,
    ) -> ResolutionTypeSlotId {
        let site = self.add_site(literal, ResolutionSiteKind::Literal, scope);
        let output = self.add_slot(site, ResolutionTypeSlotRole::ExpressionValue);
        let name = self.intern_name(type_name);
        self.facts.intrinsic_type_seeds.push(
            brokk_bifrost_core::analyzer::resolution_facts::IntrinsicTypeSeedFact::direct(
                output,
                name,
                brokk_bifrost_core::analyzer::resolution_facts::IntrinsicTypeKind::LanguageBuiltin,
            ),
        );
        output
    }

    /// `new T(...)` constructs a runtime value of the type `T` names. The
    /// constructor itself is not selected: the value type does not depend on
    /// which constructor runs. A template body (`new T { ... }`) declares an
    /// anonymous subtype. Its body owns members, but selection of the
    /// construction's result remains unsupported, as in the Java producer.
    fn construction_slot(
        &mut self,
        instance: Node<'source>,
        scope: ResolutionScopeId,
    ) -> ResolutionTypeSlotId {
        let constructed = instance.named_child(0).filter(|_| {
            let mut cursor = instance.walk();
            !instance
                .named_children(&mut cursor)
                .any(|child| matches!(child.kind(), "template_body" | "early_defs"))
        });
        let identity = constructed
            .and_then(scala_callable_result_type_head)
            .and_then(|head| self.sites_by_node.get(&head.id()).copied())
            .and_then(|reference| {
                self.projected_slot(reference, BindingProjectionKind::TargetTypeIdentity)
            });
        let Some(identity) = identity else {
            return self.unsupported_expression_slot(instance, scope);
        };
        let site = self.add_site(instance, ResolutionSiteKind::Call, scope);
        let output = self.add_slot(site, ResolutionTypeSlotRole::ExpressionValue);
        self.facts
            .type_transfers
            .push(ResolutionTypeTransferFact::new(
                identity,
                output,
                ResolutionTypeTransferKind::Construction,
                0,
                0,
                ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
            ));
        output
    }

    /// A further argument list of `new T(first)(second)` is parsed as a call
    /// over the instance expression; it constructs the same value.
    fn curried_construction_slot(
        &mut self,
        call: Node<'source>,
        scope: ResolutionScopeId,
    ) -> ResolutionTypeSlotId {
        let mut function = call.child_by_field_name("function");
        while let Some(inner) = function.filter(|inner| inner.kind() == "call_expression") {
            function = inner.child_by_field_name("function");
        }
        match function.filter(|function| function.kind() == "instance_expression") {
            Some(instance) => self.expression_slot(instance, scope),
            None => self.unsupported_expression_slot(call, scope),
        }
    }

    /// The output slot of the first projection of `kind` on `reference`.
    fn projected_slot(
        &self,
        reference: ResolutionSiteId,
        kind: BindingProjectionKind,
    ) -> Option<ResolutionTypeSlotId> {
        self.facts
            .binding_projections
            .iter()
            .find(|projection| projection.reference == reference && projection.kind == kind)
            .map(|projection| projection.output)
    }

    fn identifier(
        &mut self,
        site: ResolutionSiteId,
        node: Node<'source>,
        role: ResolutionIdentifierRole,
        namespace: ResolutionNamespace,
        qualifier: Option<ResolutionTypeSlotId>,
    ) {
        let spelling = node_text(node, self.source).trim();
        assert!(
            !spelling.is_empty(),
            "Scala identifier nodes have source text"
        );
        let name = self.intern_name(spelling);
        self.facts.identifiers.push(PositionedIdentifierFact {
            site,
            name,
            role,
            namespace,
            qualifier,
        });
        let _ = role;
    }

    /// Lower the head and the intermediate segments of a qualified path. The
    /// head is an ordinary reference that shadows the package reading. Stable
    /// type paths and term paths admit both types and terms as owners; a type
    /// path keeps its lexical head lookup beside the terminal's root route. With
    /// `typed_members`, every intermediate segment is a member reference
    /// qualified by the segment before it, with its own root route, and the
    /// slot that qualifies the terminal is returned.
    fn lower_qualified_prefixes(
        &mut self,
        segments: &[Node<'source>],
        scope: ResolutionScopeId,
        owner: Option<ResolutionSiteId>,
        namespace: ResolutionNamespace,
        anchor: ResolutionRootImportAnchor,
        typed_members: bool,
    ) -> (ResolutionSiteId, Option<ResolutionTypeSlotId>) {
        // Route publication follows the original path role, before its owner
        // namespace is widened. A package-root row on a stable type-path head
        // would suppress lexical lookup of an enclosing object's binder.
        let publishes_root = namespace == ResolutionNamespace::TypeOrValue || !typed_members;
        let namespace = if namespace == ResolutionNamespace::Type && typed_members {
            ResolutionNamespace::TypeOrValue
        } else {
            namespace
        };
        let head_kind = if namespace == ResolutionNamespace::Type {
            ResolutionSiteKind::TypeReference
        } else {
            ResolutionSiteKind::ValueReference
        };
        let prefix = segments[0];
        let prefix_site = if let Some(&site) = self.qualified_type_prefixes.get(&prefix.id()) {
            site
        } else {
            let existing = self
                .sites_by_node
                .get(&prefix.id())
                .copied()
                .filter(|site| {
                    self.facts.identifiers.iter().any(|identifier| {
                        identifier.site == *site
                            && identifier.role == ResolutionIdentifierRole::Reference
                            && identifier.namespace == namespace
                            && identifier.qualifier.is_none()
                    })
                });
            let site = existing.unwrap_or_else(|| {
                if self.sites_by_node.contains_key(&prefix.id()) {
                    self.add_site_distinct(prefix, head_kind, scope)
                } else {
                    self.add_site(prefix, head_kind, scope)
                }
            });
            if existing.is_none() {
                self.identifier(
                    site,
                    prefix,
                    ResolutionIdentifierRole::Reference,
                    namespace,
                    None,
                );
                self.reference_identity_slot(site, owner, namespace);
            }
            // A head whose root reference is published below names its owner on
            // that route, so the head is not ambiguous here. Position still
            // decides the companion's type-or-value duality in the resolver.
            if !publishes_root
                && !self.facts.gaps.iter().any(|gap| {
                    gap.site == site && gap.kind == ResolutionGapKind::AmbiguousQualifiedType
                })
            {
                self.gap(site, ResolutionGapKind::AmbiguousQualifiedType);
            }
            self.qualified_type_prefixes.insert(prefix.id(), site);
            site
        };
        if publishes_root {
            self.record_qualified_type_root_reference(
                std::slice::from_ref(&prefix),
                prefix_site,
                scope,
                None,
                anchor == ResolutionRootImportAnchor::Lexical
                    && segments.len() > 1
                    && publishes_root,
                anchor,
            );
        }
        if !typed_members {
            return (prefix_site, None);
        }
        if !self
            .facts
            .binding_projections
            .iter()
            .any(|projection| projection.reference == prefix_site)
        {
            self.projected_identity_slot(prefix_site, namespace);
        }
        let mut qualifier = self
            .facts
            .binding_projections
            .iter()
            .find(|projection| projection.reference == prefix_site)
            .map(|projection| projection.output)
            .expect("a qualified path prefix has its projected slot");
        for (position, segment) in segments.iter().enumerate().take(segments.len() - 1).skip(1) {
            let site = self.add_site(*segment, ResolutionSiteKind::MemberReference, scope);
            let existing = self
                .facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.site == site
                        && identifier.role == ResolutionIdentifierRole::Reference
                })
                .map(|identifier| (identifier.namespace, identifier.qualifier));
            if let Some((existing_namespace, existing_qualifier)) = existing {
                assert_eq!(existing_namespace, namespace);
                existing_qualifier.expect("an existing qualified path segment has a receiver");
                if !self
                    .facts
                    .binding_projections
                    .iter()
                    .any(|projection| projection.reference == site)
                {
                    self.projected_identity_slot(site, namespace);
                }
                qualifier = self
                    .facts
                    .binding_projections
                    .iter()
                    .find(|projection| projection.reference == site)
                    .map(|projection| projection.output)
                    .expect("a previously lowered qualified member has its projected slot");
                self.record_qualified_type_root_reference(
                    &segments[..=position],
                    site,
                    scope,
                    Some(prefix_site),
                    false,
                    anchor,
                );
                continue;
            }
            self.identifier(
                site,
                *segment,
                ResolutionIdentifierRole::Reference,
                namespace,
                Some(qualifier),
            );
            let output = self.reference_identity_slot(site, owner, namespace);
            self.gap(site, ResolutionGapKind::AmbiguousQualifiedType);
            self.record_qualified_type_root_reference(
                &segments[..=position],
                site,
                scope,
                Some(prefix_site),
                false,
                anchor,
            );
            qualifier = output;
        }
        (prefix_site, Some(qualifier))
    }

    /// Publish the package interpretation of a qualified type path: a root
    /// reference whose route is every segment before the terminal.
    fn record_qualified_type_root_reference(
        &mut self,
        segments: &[Node<'source>],
        reference: ResolutionSiteId,
        scope: ResolutionScopeId,
        prefix_site: Option<ResolutionSiteId>,
        owner_continued: bool,
        anchor: ResolutionRootImportAnchor,
    ) {
        let route_segments = segments[..segments.len() - 1]
            .iter()
            .map(|segment| self.intern_name(node_text(*segment, self.source)))
            .collect::<Vec<_>>();
        if let Some(existing) = self
            .facts
            .root_references
            .iter()
            .find(|existing| existing.reference == reference)
        {
            assert_eq!(existing.root_scope, self.package_scope_for(scope));
            assert_eq!(existing.anchor, anchor);
            assert_eq!(
                existing.prefix_reference,
                (anchor == ResolutionRootImportAnchor::Lexical)
                    .then_some(prefix_site)
                    .flatten()
            );
            assert_eq!(existing.owner_continued, owner_continued);
            let mut existing_segments = self
                .facts
                .root_reference_segments
                .iter()
                .filter(|segment| segment.reference == reference)
                .map(|segment| (segment.position, segment.name))
                .collect::<Vec<_>>();
            existing_segments.sort_unstable();
            let expected_segments = route_segments
                .iter()
                .copied()
                .enumerate()
                .map(|(position, name)| {
                    (
                        u32::try_from(position).expect("Scala qualified type path fits u32"),
                        name,
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(existing_segments, expected_segments);
            return;
        }
        self.facts
            .root_references
            .push(ResolutionRootReferenceFact {
                reference,
                root_scope: self.package_scope_for(scope),
                anchor,
                prefix_reference: (anchor == ResolutionRootImportAnchor::Lexical)
                    .then_some(prefix_site)
                    .flatten(),
                owner_continued,
            });
        self.facts
            .root_reference_segments
            .extend(
                route_segments
                    .into_iter()
                    .enumerate()
                    .map(|(position, name)| ResolutionRootReferenceSegmentFact {
                        reference,
                        position: u32::try_from(position)
                            .expect("Scala qualified type path fits u32"),
                        name,
                    }),
            );
    }

    fn add_site(
        &mut self,
        node: Node<'source>,
        kind: ResolutionSiteKind,
        scope: ResolutionScopeId,
    ) -> ResolutionSiteId {
        if let Some(site) = self.sites_by_node.get(&node.id()) {
            return *site;
        }
        let occurrence = self.collector.intern_node(node);
        let id = self.push_site(occurrence, kind, scope);
        self.sites_by_node.insert(node.id(), id);
        id
    }

    fn add_site_distinct(
        &mut self,
        node: Node<'source>,
        kind: ResolutionSiteKind,
        scope: ResolutionScopeId,
    ) -> ResolutionSiteId {
        let occurrence = self.collector.intern_node(node);
        let id = self.push_site(occurrence, kind, scope);
        self.sites_by_node.entry(node.id()).or_insert(id);
        id
    }

    fn push_site(
        &mut self,
        occurrence: SourceOccurrenceId,
        kind: ResolutionSiteKind,
        scope: ResolutionScopeId,
    ) -> ResolutionSiteId {
        let range = self.collector.occurrence(occurrence).range;
        let id = ResolutionSiteId::try_from_index(self.facts.sites.len())
            .expect("Scala resolution site count fits u32");
        self.facts.sites.push(ResolutionSiteFact {
            id,
            scope,
            kind,
            start_byte: range.start_byte,
            end_byte: range.end_byte,
        });
        self.site_occurrences.push(occurrence);
        id
    }

    fn add_slot(
        &mut self,
        site: ResolutionSiteId,
        role: ResolutionTypeSlotRole,
    ) -> ResolutionTypeSlotId {
        let id = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
            .expect("Scala type slot count fits u32");
        self.facts
            .type_slots
            .push(ResolutionTypeSlotFact { id, site, role });
        id
    }

    /// The receiver slot of one `super.member` selection. A second request for
    /// the same selection (the callee's qualifier and the call's receiver)
    /// reuses the slot, so both read one receiver type.
    fn super_receiver_slot(
        &mut self,
        receiver: Node<'source>,
        site: ResolutionSiteId,
    ) -> ResolutionTypeSlotId {
        if let Some(slot) = self.super_receiver_slots_by_node.get(&receiver.id()) {
            return *slot;
        }
        let slot = self.add_slot(site, ResolutionTypeSlotRole::Receiver);
        self.super_receiver_slots_by_node
            .insert(receiver.id(), slot);
        if let Some(owner) = self.enclosing_type_declaration_site(receiver) {
            self.super_receivers.push((owner, slot));
        } else {
            self.gap(site, ResolutionGapKind::InferredType);
        }
        slot
    }

    /// The innermost template whose parent linearization answers `super`.
    fn enclosing_type_declaration_site(&self, receiver: Node<'source>) -> Option<ResolutionSiteId> {
        let mut ancestor = receiver.parent();
        while let Some(node) = ancestor {
            if matches!(
                node.kind(),
                "class_definition"
                    | "trait_definition"
                    | "object_definition"
                    | "enum_definition"
                    | "instance_expression"
            ) && let Some(site) = self.declaration_sites.get(&node.id())
            {
                return Some(*site);
            }
            ancestor = node.parent();
        }
        None
    }

    fn add_call_input_transfer(
        &mut self,
        input: ResolutionTypeSlotId,
        output: ResolutionTypeSlotId,
        kind: ResolutionTypeTransferKind,
    ) {
        assert_ne!(input, output);
        assert!(matches!(
            kind,
            ResolutionTypeTransferKind::Receiver | ResolutionTypeTransferKind::Argument
        ));
        self.facts.type_transfers.push(ResolutionTypeTransferFact {
            input,
            output,
            kind,
            indirection_delta: 0,
            reference_indirection_delta: 0,
            value_transform: ResolutionTypeTransferValueTransform::Preserve,
        });
    }

    fn intern_name(&mut self, spelling: &str) -> ResolutionNameId {
        if let Some(id) = self.name_ids.get(spelling) {
            return *id;
        }
        let id = ResolutionNameId::try_from_index(self.facts.names.len())
            .expect("Scala name count fits u32");
        let spelling = spelling.to_string();
        self.name_ids.insert(spelling.clone(), id);
        self.facts.names.push(ResolutionNameFact { id, spelling });
        id
    }

    fn scope(&self, id: ResolutionScopeId) -> &ResolutionScopeFact {
        &self.facts.scopes[id.index()]
    }

    fn declaration_owner(&self, owner: Option<ResolutionSiteId>) -> Option<ResolutionSiteId> {
        owner.filter(|owner| {
            let site = self.facts.sites[owner.index()];
            matches!(
                site.kind,
                ResolutionSiteKind::TypeDeclaration
                    | ResolutionSiteKind::TypeAliasDeclaration
                    | ResolutionSiteKind::CallableDeclaration
                    | ResolutionSiteKind::ConstructorDeclaration
                    | ResolutionSiteKind::ValueDeclaration
            ) && self.facts.identifiers.iter().any(|identifier| {
                identifier.site == *owner
                    && identifier.role == ResolutionIdentifierRole::Declaration
            })
        })
    }

    fn gap(&mut self, site: ResolutionSiteId, kind: ResolutionGapKind) {
        if !self
            .facts
            .gaps
            .contains(&ResolutionGapFact::new(site, kind))
        {
            self.facts.gaps.push(ResolutionGapFact::new(site, kind));
        }
    }

    fn validate(&self) {
        assert_eq!(self.site_occurrences.len(), self.facts.sites.len());
        assert!(self.facts.scopes.first().is_some_and(|scope| {
            scope.id == self.root_scope && scope.kind == ResolutionScopeKind::CompilationUnit
        }));
        self.facts.validate_package_relations();
    }
}

fn declaration_name(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("name")
        .or_else(|| match node.kind() {
            "class_definition" | "trait_definition" | "object_definition" | "enum_definition"
            | "full_enum_case" => {
                let mut cursor = node.walk();
                node.named_children(&mut cursor)
                    .find(|child| matches!(child.kind(), "identifier" | "type_identifier"))
            }
            _ => None,
        })
}

/// The name the Scala compiler gives an anonymous given: `given_` followed by
/// the names of its parent types joined with `_` (dotty's
/// `inventGivenOrExtensionName`). The first parent shape that the rule names
/// with a plain identifier part is supported; any other shape yields `None`.
fn scala_anonymous_given_name(node: Node<'_>, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    let mut parents = node
        .children_by_field_name("return_type", &mut cursor)
        .filter(Node::is_named)
        .collect::<Vec<_>>();
    let mut cursor = node.walk();
    parents.extend(
        node.children_by_field_name("extra", &mut cursor)
            .filter(Node::is_named),
    );
    if parents.is_empty() {
        return None;
    }
    let parts = parents
        .into_iter()
        .map(|parent| scala_given_type_name(parent, source, true))
        .collect::<Option<Vec<_>>>()?;
    Some(format!("given_{}", parts.join("_")))
}

/// One type's contribution to a synthesized given name. `follow_args` is true
/// for a parent type and false inside its type arguments, where only the head
/// of an applied type counts.
fn scala_given_type_name(node: Node<'_>, source: &str, follow_args: bool) -> Option<String> {
    enum Work<'tree> {
        Visit(Node<'tree>, bool),
        Join(usize),
        Validate,
    }
    let mut work = vec![Work::Visit(node, follow_args)];
    let mut parts = Vec::<String>::new();
    while let Some(item) = work.pop() {
        match item {
            Work::Visit(node, follow_args) => {
                if node.is_error() || node.is_missing() {
                    return None;
                }
                work.push(Work::Validate);
                match node.kind() {
                    "type_identifier" => parts.push(node_text(node, source).to_owned()),
                    "stable_type_identifier" => {
                        let mut cursor = node.walk();
                        let last = node
                            .named_children(&mut cursor)
                            .filter(|child| child.kind() == "type_identifier")
                            .last()?;
                        parts.push(node_text(last, source).to_owned());
                    }
                    "generic_type" => {
                        let head = node.child_by_field_name("type")?;
                        if follow_args {
                            let arguments = node.child_by_field_name("type_arguments")?;
                            let mut cursor = arguments.walk();
                            let arguments =
                                arguments.named_children(&mut cursor).collect::<Vec<_>>();
                            work.push(Work::Join(arguments.len() + 1));
                            work.extend(
                                arguments
                                    .into_iter()
                                    .rev()
                                    .map(|argument| Work::Visit(argument, false)),
                            );
                        }
                        work.push(Work::Visit(head, false));
                    }
                    "tuple_type" => {
                        let mut cursor = node.walk();
                        let elements = node.named_children(&mut cursor).collect::<Vec<_>>();
                        work.push(Work::Join(elements.len()));
                        work.extend(
                            elements
                                .into_iter()
                                .rev()
                                .map(|element| Work::Visit(element, false)),
                        );
                    }
                    "infix_type" => {
                        parts.push(
                            node_text(node.child_by_field_name("operator")?, source).to_owned(),
                        );
                        if follow_args {
                            let left = node.child_by_field_name("left")?;
                            let right = node.child_by_field_name("right")?;
                            work.push(Work::Join(3));
                            work.push(Work::Visit(right, false));
                            work.push(Work::Visit(left, false));
                        }
                    }
                    _ => return None,
                }
            }
            Work::Join(count) => {
                let start = parts.len() - count;
                let part = parts[start..].join("_");
                parts.truncate(start);
                parts.push(part);
            }
            Work::Validate => {
                // A symbolic operator is encoded by the compiler, so only plain
                // identifier characters name a synthesized part exactly.
                let part = parts.last().expect("a visited type contributes one part");
                if part.is_empty() || !part.chars().all(|c| c.is_alphanumeric() || c == '_') {
                    return None;
                }
            }
        }
    }
    assert_eq!(parts.len(), 1);
    parts.pop()
}

/// One type member an export clause forwards, with the clause's owner path.
struct ExportedType<'a, 'source> {
    member: ResolutionSiteId,
    exporter: ResolutionSiteId,
    scope: ResolutionScopeId,
    owner_path: &'a [Node<'source>],
    /// The identity slot of the exported owner, built on first use.
    owner_chain: &'a mut Option<ResolutionTypeSlotId>,
}

fn scala_export_selector_nodes<'tree>(node: Node<'tree>) -> Vec<Node<'tree>> {
    let mut cursor = node.walk();
    let children = node.named_children(&mut cursor).collect::<Vec<_>>();
    if let Some(selectors) = children
        .iter()
        .find(|child| child.kind() == "namespace_selectors")
    {
        let mut cursor = selectors.walk();
        return selectors.named_children(&mut cursor).collect();
    }
    if let Some(selector) = children.iter().find(|child| {
        matches!(
            child.kind(),
            "namespace_wildcard" | "as_renamed_identifier" | "arrow_renamed_identifier"
        )
    }) {
        return vec![*selector];
    }
    let mut cursor = node.walk();
    node.children_by_field_name("path", &mut cursor)
        .filter(Node::is_named)
        .last()
        .into_iter()
        .collect()
}

fn is_type_parameter_name(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        matches!(
            parent.kind(),
            "type_parameters" | "covariant_type_parameter" | "contravariant_type_parameter"
        ) && field_name_in_parent(parent, node) == Some("name")
    })
}

fn scala_parameter_list_is_contextual(parameters: Node<'_>) -> bool {
    let mut cursor = parameters.walk();
    parameters
        .children(&mut cursor)
        .any(|child| matches!(child.kind(), "implicit" | "using"))
}

fn type_parameter_count(node: Node<'_>) -> u32 {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| {
            child.kind() == "type_parameters"
                && matches!(
                    field_name_in_parent(node, *child),
                    Some("type_parameters" | "parameters")
                )
        })
        .map(|parameters| {
            (0..parameters.named_child_count())
                .filter_map(|index| parameters.named_child(index))
                .filter(|child| {
                    matches!(
                        child.kind(),
                        "covariant_type_parameter" | "contravariant_type_parameter"
                    ) || field_name_in_parent(parameters, *child) == Some("name")
                })
                .count()
        })
        .sum::<usize>()
        .try_into()
        .expect("Scala type parameter count fits u32")
}

fn has_contextual_parameter_marker(node: Node<'_>) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|child| matches!(child.kind(), "implicit" | "using"))
}

fn has_field_descendant(root: Node<'_>, field: &str) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        if children
            .iter()
            .any(|child| field_name_in_parent(node, *child) == Some(field))
        {
            return true;
        }
        stack.extend(children);
    }
    false
}

/// The declaration role of the written type a binder carries in its own
/// declaration: a parameter that is not part of a callable signature (a class
/// or lambda parameter), or a val or var that names its binder directly. A
/// binder nested in a destructuring pattern is typed by the pattern as a whole
/// and has no type of its own.
fn declared_value_role(binder: Node<'_>, declaration: Node<'_>) -> Option<DeclarationTypeRole> {
    declaration.child_by_field_name("type")?;
    match declaration.kind() {
        "parameter" | "class_parameter" | "binding" => (declaration.child_by_field_name("name")
            == Some(binder))
        .then_some(DeclarationTypeRole::Parameter),
        "val_definition" | "var_definition" => {
            direct_value_binding(binder, declaration).then_some(DeclarationTypeRole::Value)
        }
        _ => None,
    }
}

fn binder_initializer<'tree>(binder: Node<'tree>, declaration: Node<'tree>) -> Option<Node<'tree>> {
    if !matches!(declaration.kind(), "val_definition" | "var_definition")
        || !direct_value_binding(binder, declaration)
    {
        return None;
    }
    declaration.child_by_field_name("value")
}

fn direct_value_binding(binder: Node<'_>, declaration: Node<'_>) -> bool {
    declaration
        .child_by_field_name("pattern")
        .is_some_and(|pattern| {
            pattern == binder
                || (pattern.kind() == "identifiers" && binder.parent() == Some(pattern))
        })
}

/// The lexical declaration kind of a binder that has no parser unit.
fn scala_lexical_binder_kind(binding: BindingKind, declaration: Node<'_>) -> DeclarationKind {
    match binding {
        // A type parameter is a parameter of its owner, as in Kotlin.
        BindingKind::TypeParameter => DeclarationKind::Parameter,
        BindingKind::Parameter if matches!(declaration.kind(), "lambda_expression" | "binding") => {
            DeclarationKind::LambdaParameter
        }
        BindingKind::Parameter => DeclarationKind::Parameter,
        BindingKind::ImportBinder => DeclarationKind::ImportAlias,
        BindingKind::PatternBinder => DeclarationKind::PatternVariable,
        BindingKind::LoopVariable => DeclarationKind::EnhancedForVariable,
        BindingKind::CatchOrResource => DeclarationKind::CatchParameter,
        BindingKind::Local => DeclarationKind::LocalVariable,
    }
}

fn binder_owner_node(node: Node<'_>) -> Node<'_> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(
            parent.kind(),
            "parameter"
                | "class_parameter"
                | "binding"
                | "context_bound"
                | "lambda_expression"
                | "val_definition"
                | "var_definition"
                | "enumerator"
        ) {
            return parent;
        }
        current = parent;
    }
    node
}

fn is_member_value(node: Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(parent.kind(), "val_definition" | "var_definition") {
            return parent.parent().is_some_and(|owner| {
                matches!(
                    owner.kind(),
                    "template_body" | "with_template_body" | "enum_body"
                )
            });
        }
        if matches!(
            parent.kind(),
            "block" | "indented_block" | "function_definition"
        ) {
            return false;
        }
        current = parent.parent();
    }
    false
}

fn has_opaque_modifier(node: Node<'_>) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor).any(|child| {
        child.kind() == "opaque_modifier" || {
            let mut modifiers = child.walk();
            child.kind() == "modifiers"
                && child
                    .children(&mut modifiers)
                    .any(|modifier| modifier.kind() == "opaque_modifier")
        }
    })
}

fn is_type_declaration(kind: &str) -> bool {
    matches!(
        kind,
        "class_definition"
            | "trait_definition"
            | "object_definition"
            | "enum_definition"
            | "full_enum_case"
            | "package_object"
    )
}

/// The parents every case class and case object has without writing them, as
/// (type name, package route). The superclass is `AnyRef`, which the implicit
/// root already supplies.
const SCALA_CASE_IMPLICIT_PARENTS: [(&str, &[&str]); 2] =
    [("Product", &["scala"]), ("Serializable", &["java", "io"])];

fn has_case_modifier(node: Node<'_>) -> bool {
    (0..node.child_count()).any(|index| {
        node.child(index)
            .is_some_and(|modifier| modifier.kind() == "case")
    }) || node
        .child_by_field_name("modifiers")
        .is_some_and(|modifiers| {
            (0..modifiers.child_count()).any(|index| {
                modifiers
                    .child(index)
                    .is_some_and(|modifier| modifier.kind() == "case")
            })
        })
}

fn scala_has_companion_object(node: Node<'_>, source: &str) -> bool {
    scala_companion_object(node, source).is_some()
}

/// The `object` beside `node` that has its name.
fn scala_companion_object<'tree>(node: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    let name = declaration_name(node)?;
    let parent = node.parent()?;
    let mut cursor = parent.walk();
    parent.named_children(&mut cursor).find(|sibling| {
        sibling.kind() == "object_definition"
            && declaration_name(*sibling).is_some_and(|sibling_name| {
                scala_identifier_spelling(node_text(sibling_name, source))
                    == scala_identifier_spelling(node_text(name, source))
            })
    })
}

fn pattern_invocation(node: Node<'_>) -> Option<(Node<'_>, ResolutionInvocationRole)> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "case_class_pattern" => {
                let target = parent.child_by_field_name("type")?;
                if terminal_identifier(target).is_some_and(|terminal| terminal.id() == node.id()) {
                    return Some((parent, ResolutionInvocationRole::Unapply));
                }
            }
            "infix_pattern" => {
                if parent
                    .child_by_field_name("operator")
                    .is_some_and(|operator| operator.id() == node.id())
                {
                    return Some((parent, ResolutionInvocationRole::Unapply));
                }
            }
            "case_clause" | "catch_clause" | "val_definition" | "var_definition" => return None,
            _ => {}
        }
        current = parent;
    }
    None
}

/// The type a literal has by its syntax alone. A numeric literal that the
/// expected type could widen still has the type its spelling gives it; the
/// call that receives it decides whether that type applies.
fn scala_literal_type_name(kind: &str, literal: Node<'_>, source: &str) -> Option<&'static str> {
    let text = node_text(literal, source);
    Some(match kind {
        "integer_literal" if text.ends_with(['l', 'L']) => "scala.Long",
        "integer_literal" => "scala.Int",
        "floating_point_literal" if text.ends_with(['f', 'F']) => "scala.Float",
        "floating_point_literal" => "scala.Double",
        "boolean_literal" => "scala.Boolean",
        "character_literal" => "scala.Char",
        "string" => "java.lang.String",
        "null_literal" => "scala.Null",
        "unit" => "scala.Unit",
        _ => return None,
    })
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}

fn scala_identifier_spelling(name: &str) -> &str {
    name.strip_prefix('`')
        .and_then(|name| name.strip_suffix('`'))
        .unwrap_or(name)
}

fn scala_jvm_member_name(name: &str) -> String {
    let name = scala_identifier_spelling(name);
    let mut encoded = String::with_capacity(name.len());
    for character in name.chars() {
        match character {
            '~' => encoded.push_str("$tilde"),
            '=' => encoded.push_str("$eq"),
            '<' => encoded.push_str("$less"),
            '>' => encoded.push_str("$greater"),
            '!' => encoded.push_str("$bang"),
            '#' => encoded.push_str("$hash"),
            '%' => encoded.push_str("$percent"),
            '^' => encoded.push_str("$up"),
            '&' => encoded.push_str("$amp"),
            '|' => encoded.push_str("$bar"),
            '*' => encoded.push_str("$times"),
            '/' => encoded.push_str("$div"),
            '+' => encoded.push_str("$plus"),
            '-' => encoded.push_str("$minus"),
            ':' => encoded.push_str("$colon"),
            '\\' => encoded.push_str("$bslash"),
            '?' => encoded.push_str("$qmark"),
            '@' => encoded.push_str("$at"),
            character => encoded.push(character),
        }
    }
    encoded
}

fn scala_callable_parameter_count(callable: Node<'_>) -> u32 {
    let mut count = 0usize;
    let mut cursor = callable.walk();
    for parameters in callable
        .children_by_field_name("parameters", &mut cursor)
        .filter(|parameters| parameters.kind() == "parameters")
    {
        let mut cursor = parameters.walk();
        count += parameters
            .named_children(&mut cursor)
            .filter(|parameter| matches!(parameter.kind(), "parameter" | "class_parameter"))
            .count();
    }
    count
        .try_into()
        .expect("Scala JVM callable parameter count fits u32")
}

fn scala_case_class_has_repeated_parameter(node: Node<'_>) -> bool {
    super::declarations::scala_class_parameter_lists(node)
        .into_iter()
        .flat_map(|parameters| {
            let mut cursor = parameters.walk();
            parameters
                .named_children(&mut cursor)
                .filter(|parameter| matches!(parameter.kind(), "parameter" | "class_parameter"))
                .collect::<Vec<_>>()
        })
        .any(|parameter| {
            parameter
                .child_by_field_name("type")
                .is_some_and(crate::scala::graph::syntax::contains_repeated_parameter_type)
        })
}

fn scala_case_class_parameter_count(node: Node<'_>) -> u32 {
    let count = super::declarations::scala_class_parameter_lists(node)
        .into_iter()
        .map(|parameters| {
            let mut cursor = parameters.walk();
            parameters
                .named_children(&mut cursor)
                .filter(|parameter| matches!(parameter.kind(), "parameter" | "class_parameter"))
                .count()
        })
        .sum::<usize>();
    count
        .try_into()
        .expect("Scala case class JVM parameter count fits u32")
}

fn scala_enclosing_value_declaration(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node;
    loop {
        if matches!(
            current.kind(),
            "val_definition" | "var_definition" | "val_declaration" | "var_declaration"
        ) {
            return Some(current);
        }
        if matches!(
            current.kind(),
            "function_definition"
                | "function_declaration"
                | "class_definition"
                | "trait_definition"
                | "object_definition"
                | "enum_definition"
                | "lambda_expression"
        ) {
            return None;
        }
        current = current.parent()?;
    }
}

fn import_clauses<'tree>(node: Node<'tree>) -> Vec<(Vec<Node<'tree>>, Vec<Node<'tree>>)> {
    let mut clauses = Vec::new();
    let mut path = Vec::new();
    let mut selectors = Vec::new();
    for index in 0..node.child_count() {
        let Some(child) = node.child(index) else {
            continue;
        };
        if child.kind() == "," {
            if !path.is_empty() || !selectors.is_empty() {
                clauses.push((std::mem::take(&mut path), std::mem::take(&mut selectors)));
            }
            continue;
        }
        if !child.is_named() {
            continue;
        }
        if field_name_in_parent(node, child) == Some("path") {
            path.push(child);
            continue;
        }
        selectors.extend(import_selector_nodes(child));
    }
    if !path.is_empty() || !selectors.is_empty() {
        clauses.push((path, selectors));
    }
    clauses
}

fn import_selector_nodes<'tree>(node: Node<'tree>) -> Vec<Node<'tree>> {
    if node.kind() == "namespace_selectors" {
        let mut cursor = node.walk();
        return node.named_children(&mut cursor).collect();
    }
    if matches!(
        node.kind(),
        "namespace_wildcard" | "as_renamed_identifier" | "arrow_renamed_identifier"
    ) {
        return vec![node];
    }
    let mut stack = vec![node];
    let mut selectors = Vec::new();
    while let Some(parent) = stack.pop() {
        let mut cursor = parent.walk();
        let children = parent.named_children(&mut cursor).collect::<Vec<_>>();
        for child in children.into_iter().rev() {
            if child.kind() == "namespace_selectors" {
                let mut cursor = child.walk();
                selectors.extend(child.named_children(&mut cursor));
            } else if matches!(
                child.kind(),
                "namespace_wildcard" | "as_renamed_identifier" | "arrow_renamed_identifier"
            ) {
                selectors.push(child);
            } else {
                stack.push(child);
            }
        }
    }
    selectors
}

fn has_package_scope_ancestor(node: Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "package_object"
            || (parent.kind() == "package_clause" && parent.child_by_field_name("body").is_some())
        {
            return true;
        }
        current = parent.parent();
    }
    false
}

fn package_ancestor_nodes<'tree>(node: Node<'tree>) -> Vec<Node<'tree>> {
    let mut packages = Vec::new();
    let mut current = Some(node);
    while let Some(candidate) = current {
        if matches!(candidate.kind(), "package_clause" | "package_object") {
            packages.push(candidate);
        }
        current = candidate.parent();
    }
    packages.reverse();
    packages
}

fn package_name_nodes<'tree>(name: Node<'tree>) -> Vec<Node<'tree>> {
    let mut stack = vec![name];
    let mut identifiers = Vec::new();
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "identifier" | "operator_identifier") {
            identifiers.push(node);
            continue;
        }
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        stack.extend(children.into_iter().rev());
    }
    identifiers.sort_unstable_by_key(Node::start_byte);
    identifiers
}

fn nearest_ancestor<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if candidate.kind() == kind {
            return Some(candidate);
        }
        current = candidate.parent();
    }
    None
}

fn nearest_path_chain(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "stable_identifier" | "stable_type_identifier" | "scoped_type_identifier"
        ) {
            return Some(parent);
        }
        if matches!(
            parent.kind(),
            "field_expression" | "call_expression" | "function_definition" | "block"
        ) {
            return None;
        }
        current = parent.parent();
    }
    None
}

fn scope_is_ancestor(
    scopes: &[ResolutionScopeFact],
    ancestor: ResolutionScopeId,
    mut descendant: ResolutionScopeId,
) -> bool {
    loop {
        if ancestor == descendant {
            return true;
        }
        let Some(parent) = scopes[descendant.index()].parent else {
            return false;
        };
        descendant = parent;
    }
}

/// `this` is an `identifier` node in this grammar, so it is told apart by its
/// spelling.
fn is_this_identifier(node: Node<'_>, source: &str) -> bool {
    node.kind() == "identifier" && node_text(node, source) == "this"
}

/// `super` is a keyword in this grammar's identifier position, not a value the
/// source declares. Only a `super.member` selection gives it a type.
fn is_super_identifier(node: Node<'_>, source: &str) -> bool {
    node.kind() == "identifier" && node_text(node, source) == "super"
}

fn is_this_or_super_identifier(node: Node<'_>, source: &str) -> bool {
    node.kind() == "identifier" && matches!(node_text(node, source), "this" | "super")
}

fn is_call_target(node: Node<'_>) -> bool {
    // Successive argument lists do not turn the constructed type into an
    // ordinary callable. Explicit creation publishes its own constructor ref.
    if super::graph::syntax::explicit_constructor_reference(node) {
        return false;
    }
    let mut child = node;
    while let Some(parent) = child.parent() {
        if parent.kind() == "call_expression" {
            let is_function = parent
                .child_by_field_name("function")
                .is_some_and(|function| function.id() == child.id());
            let callable = if child.kind() == "generic_function" {
                child
                    .child_by_field_name("function")
                    .and_then(terminal_identifier)
            } else {
                terminal_identifier(child)
            };
            return is_function && callable.is_some_and(|terminal| terminal.id() == node.id());
        }
        if matches!(
            parent.kind(),
            "function_definition" | "block" | "template_body"
        ) {
            return false;
        }
        child = parent;
    }
    false
}

fn scala_callable_receiver_origin(node: Node<'_>) -> ResolutionCallableReceiverOrigin {
    let receiver = node
        .parent()
        .filter(|parent| {
            parent.kind() == "field_expression"
                && parent
                    .child_by_field_name("field")
                    .is_some_and(|field| field.id() == node.id())
        })
        .and_then(|selection| selection.child_by_field_name("value"));
    match receiver {
        None => ResolutionCallableReceiverOrigin::Implicit,
        Some(receiver) if contains_kind(receiver, "super") => {
            ResolutionCallableReceiverOrigin::Super
        }
        Some(_) => ResolutionCallableReceiverOrigin::ExplicitExpression,
    }
}

fn scala_occurrence_namespace(
    node: Node<'_>,
    role: OccurrenceRole,
    source: &str,
) -> Option<ResolutionNamespace> {
    if is_call_target(node) {
        return Some(ResolutionNamespace::Callable);
    }
    if role == OccurrenceRole::PatternPosition
        && nearest_ancestor(node, "case_class_pattern")
            .and_then(|pattern| pattern.child_by_field_name("type"))
            .and_then(terminal_identifier)
            .is_some_and(|terminal| terminal.id() == node.id())
        && qualified_path_segments(node, source).is_none()
    {
        return Some(ResolutionNamespace::TypeOrValue);
    }
    Some(match role {
        OccurrenceRole::TypeOperand => ResolutionNamespace::Type,
        // A receiver names a value or an object (a type object whose members
        // are selected), exactly as a Java or Kotlin receiver does.
        OccurrenceRole::MemberPosition | OccurrenceRole::ReceiverPosition => {
            ResolutionNamespace::TypeOrValue
        }
        OccurrenceRole::ValueReference | OccurrenceRole::PatternPosition => {
            ResolutionNamespace::Value
        }
        _ => return None,
    })
}

/// Whether `node` is the selector of a type projection `Owner#Member`.
fn is_projected_selector(node: Node<'_>) -> bool {
    nearest_ancestor(node, "projected_type").is_some_and(|projected| {
        projected
            .child_by_field_name("selector")
            .is_some_and(|selector| selector.id() == node.id())
    })
}

fn qualified_path_segments<'source>(
    terminal: Node<'source>,
    source: &'source str,
) -> Option<Vec<Node<'source>>> {
    if let Some(projected) = nearest_ancestor(terminal, "projected_type")
        && projected
            .child_by_field_name("selector")
            .is_some_and(|selector| selector.id() == terminal.id())
    {
        let mut owner_type = projected.child_by_field_name("type")?;
        while owner_type.kind() == "generic_type" {
            owner_type = owner_type.child_by_field_name("type")?;
        }
        let owner_terminal = terminal_identifier(owner_type)?;
        let mut segments = if let Some(root) = scala_path_root(owner_terminal) {
            scala_path_segments(root)?
        } else {
            vec![owner_terminal]
        };
        if segments.last().map(Node::id) != Some(owner_terminal.id()) {
            return None;
        }
        segments.push(terminal);
        return Some(segments);
    }

    if let Some(root) = scala_path_root(terminal)
        && let Some(segments) = scala_path_segments(root)
        && segments.len() > 1
        && segments.last().is_some_and(|segment| *segment == terminal)
    {
        return Some(segments);
    }

    if !matches!(terminal.kind(), "identifier" | "type_identifier")
        || (terminal.kind() == "identifier"
            && !node_text(terminal, source)
                .chars()
                .next()
                .is_some_and(char::is_uppercase))
    {
        return None;
    }
    let mut expression = terminal.parent().filter(|parent| {
        parent.kind() == "field_expression" && parent.child_by_field_name("field") == Some(terminal)
    })?;
    let mut segments = Vec::new();
    loop {
        segments.push(expression.child_by_field_name("field")?);
        let value = expression.child_by_field_name("value")?;
        if value.kind() == "field_expression" {
            expression = value;
            continue;
        }
        if !matches!(value.kind(), "identifier" | "type_identifier") {
            return None;
        }
        segments.push(value);
        break;
    }
    segments.reverse();
    let is_intermediate_receiver = expression.parent().is_some_and(|parent| {
        parent.kind() == "field_expression"
            && parent
                .child_by_field_name("value")
                .is_some_and(|value| value.id() == expression.id())
    });
    // A two-segment selection `Owner.member` is a stable path when its head
    // names a singleton owner (an uppercase object name, such as the companion
    // of a sealed trait). Scala resolves the head as a value or a type, so the
    // selection stays on the TypeOrValue route and publishes its root reference.
    let head_names_singleton = segments.first().is_some_and(|head| {
        matches!(head.kind(), "identifier" | "type_identifier")
            && node_text(*head, source)
                .chars()
                .next()
                .is_some_and(char::is_uppercase)
    });
    (segments.last().is_some_and(|segment| *segment == terminal)
        && (segments.len() > 2 || is_intermediate_receiver || head_names_singleton))
        .then_some(segments)
}

fn qualified_path_segments_for_prefix(node: Node<'_>) -> Option<Vec<Node<'_>>> {
    let root = nearest_path_chain(node)?;
    let root = scala_path_root(root)?;
    let segments = scala_path_segments(root)?;
    (segments.len() > 1
        && segments[..segments.len() - 1]
            .iter()
            .any(|segment| segment.id() == node.id()))
    .then_some(segments)
}

fn scala_qualified_path_anchor(segments: &[Node<'_>], source: &str) -> ResolutionRootImportAnchor {
    if segments
        .first()
        .is_some_and(|segment| node_text(*segment, source) == "_root_")
    {
        ResolutionRootImportAnchor::Absolute
    } else {
        ResolutionRootImportAnchor::Lexical
    }
}

fn scala_path_root(node: Node<'_>) -> Option<Node<'_>> {
    let mut root = node;
    while let Some(parent) = root
        .parent()
        .filter(|parent| is_scala_path_kind(parent.kind()))
    {
        root = parent;
    }
    is_scala_path_kind(root.kind()).then_some(root)
}

fn scala_path_segments(root: Node<'_>) -> Option<Vec<Node<'_>>> {
    let mut segments = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if matches!(
            node.kind(),
            "identifier" | "operator_identifier" | "type_identifier"
        ) {
            segments.push(node);
            continue;
        }
        if !is_scala_path_kind(node.kind()) {
            return None;
        }
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        stack.extend(children.into_iter().rev());
    }
    Some(segments)
}

fn is_scala_path_kind(kind: &str) -> bool {
    matches!(
        kind,
        "stable_identifier" | "stable_type_identifier" | "scoped_type_identifier"
    )
}

fn terminal_identifier(root: Node<'_>) -> Option<Node<'_>> {
    let mut stack = vec![root];
    let mut last = None;
    while let Some(node) = stack.pop() {
        if matches!(
            node.kind(),
            "identifier" | "operator_identifier" | "type_identifier"
        ) {
            last = Some(node);
        }
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        stack.extend(children.into_iter().rev());
    }
    last
}

fn scala_callable_result_type_head(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node;
    loop {
        match current.kind() {
            "type_identifier" => return Some(current),
            "stable_type_identifier" | "scoped_type_identifier" | "projected_type" => {
                return terminal_identifier(current);
            }
            "generic_type" => current = current.child_by_field_name("type")?,
            "annotated_type" => {
                let mut cursor = current.walk();
                current = current
                    .named_children(&mut cursor)
                    .find(|child| child.kind() != "annotation")?;
            }
            "repeated_parameter_type" | "by_name_type" | "lazy_parameter_type" => {
                let mut cursor = current.walk();
                current = current.named_children(&mut cursor).next()?;
            }
            _ => return None,
        }
    }
}

fn scala_intrinsic_declared_type_name(node: Node<'_>) -> Option<String> {
    let arity = match node.kind() {
        "function_type" => {
            let parameters = node.child_by_field_name("parameter_types")?;
            let mut cursor = parameters.walk();
            parameters.named_children(&mut cursor).count()
        }
        "tuple_type" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor).count()
        }
        _ => return None,
    };
    let constructor = match node.kind() {
        "function_type" => "scala.Function",
        "tuple_type" => "scala.Tuple",
        _ => unreachable!(),
    };
    Some(format!("{constructor}{arity}"))
}

fn contains_kind(root: Node<'_>, kind: &str) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == kind {
            return true;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    false
}

fn is_named_argument(node: Node<'_>) -> bool {
    if node.kind() != "assignment_expression" {
        return false;
    }
    let Some(parent) = node.parent() else {
        return false;
    };
    parent.kind() == "arguments"
        && node
            .child_by_field_name("left")
            .is_some_and(|name| matches!(name.kind(), "identifier" | "operator_identifier"))
}

/// The base creation of a constructor's successive argument lists.
fn scala_constructor_instance(mut node: Node<'_>) -> Option<Node<'_>> {
    while node.kind() == "call_expression" {
        node = node.child_by_field_name("function")?;
    }
    (node.kind() == "instance_expression").then_some(node)
}

/// Does an enclosing call expression apply this application's value?
///
/// `f(a)(b)` puts the inner application directly in the outer call's function
/// field, and `(f(a))(b)` wraps it in parentheses. Both apply one source
/// callee, so the call site and call fact belong to the outer application.
/// Without this, the parenthesized spelling publishes two call facts that
/// share one callee reference, which the typed lowerer rejects.
fn application_is_curried_function(node: Node<'_>) -> bool {
    let mut expression = node;
    while let Some(parent) = expression.parent() {
        if parent.kind() == "parenthesized_expression" {
            expression = parent;
            continue;
        }
        return parent.kind() == "call_expression"
            && field_name_in_parent(parent, expression) == Some("function");
    }
    false
}

/// Only definitions directly owned by an extension group inherit its receiver.
/// A local def nested inside an extension method is an ordinary local callable.
fn enclosing_extension_definition(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        let parent = node.parent()?;
        match parent.kind() {
            "extension_definition" => return Some(parent),
            "block" | "indented_block" => node = parent,
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::model::ProjectFile;
    use brokk_bifrost_test_macros::hardwon;
    use tree_sitter::Parser;

    fn parse(source: &str) -> ParsedFile {
        let file = ProjectFile::new(
            std::env::current_dir().expect("test current directory"),
            "src/Resolution.scala",
        );
        let mut parser = Parser::new();
        parser
            .set_language(&crate::scala::language::LANGUAGE.into())
            .expect("Scala grammar");
        let tree = parser.parse(source, None).expect("Scala syntax tree");
        crate::scala::declarations::parse_scala_file(&file, source, &tree)
    }

    #[test]
    #[hardwon("#6942: scala_given_type_name recursion depth followed source nesting")]
    fn scala_given_type_name_deep_tuples_are_stack_safe() {
        let depth = 3000;
        let source = format!("type Deep = {}Int{}", "(".repeat(depth), ")".repeat(depth));
        let mut parser = Parser::new();
        parser
            .set_language(&crate::scala::language::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(&source, None).unwrap();
        assert!(!tree.root_node().has_error());
        let ty = tree
            .root_node()
            .named_child(0)
            .unwrap()
            .child_by_field_name("type")
            .unwrap();
        let mut inner = ty;
        let mut wrappers = 0;
        while inner.kind() == "tuple_type" {
            wrappers += 1;
            inner = inner.named_child(0).unwrap();
        }
        assert_eq!(wrappers, depth);
        eprintln!("scala_given_type_name: parsed {wrappers} tuple wrappers");
        std::thread::scope(|scope| {
            std::thread::Builder::new()
                .stack_size(128 * 1024)
                .spawn_scoped(scope, || {
                    assert_eq!(
                        scala_given_type_name(ty, &source, true).as_deref(),
                        Some("Int")
                    );
                })
                .unwrap()
                .join()
                .unwrap();
        });
    }

    #[test]
    #[hardwon("#5177: method-local case classes received global JVM aliases")]
    fn method_local_case_classes_publish_lexical_synthesized_companions() {
        let source = "object Example {\n\
            def first(): Unit = {\n\
              case class Same(value: Int)\n\
              Same(1)\n\
            }\n\
            def second(): Unit = {\n\
              case class Same(value: String)\n\
              Same(\"two\")\n\
            }\n\
            object NestedTemplate { case class Nested(value: Long) }\n\
          }\n";
        let parsed = parse(source);
        let facts = &parsed.resolution_facts;
        let source_facts = parsed
            .source_facts
            .as_ref()
            .expect("Scala source facts are published");

        let declaration_named_at = |name: &str, prefix: &str| {
            facts
                .identifiers
                .iter()
                .find_map(|identifier| {
                    if identifier.role != ResolutionIdentifierRole::Declaration
                        || facts.names[identifier.name.index()].spelling != name
                    {
                        return None;
                    }
                    let site = facts.sites[identifier.site.index()];
                    (site.kind == ResolutionSiteKind::TypeDeclaration
                        && source[site.start_byte..site.end_byte].starts_with(prefix))
                    .then_some(identifier.site)
                })
                .unwrap_or_else(|| panic!("missing declaration `{name}` at `{prefix}`"))
        };
        let declaration_source = |site: ResolutionSiteId| {
            let declarations = source_facts
                .native_declaration_sources
                .iter()
                .filter_map(|(candidate, declaration)| (*candidate == site).then_some(*declaration))
                .collect::<Vec<_>>();
            assert_eq!(
                declarations.len(),
                1,
                "each native site has exactly one source declaration bridge: {site:?}"
            );
            declarations[0]
        };
        let companion_for = |class: ResolutionSiteId| {
            facts
                .singleton_relations
                .iter()
                .find(|relation| {
                    relation.kind == ResolutionSingletonRelationKind::Companion
                        && relation.enclosing_type == Some(class)
                })
                .unwrap_or_else(|| panic!("missing synthesized companion for {class:?}"))
                .declaration
        };

        let first = declaration_named_at("Same", "case class Same");
        let second_offset = source
            .match_indices("case class Same")
            .nth(1)
            .expect("second local class source")
            .0;
        let second = facts
            .identifiers
            .iter()
            .find_map(|identifier| {
                if identifier.role != ResolutionIdentifierRole::Declaration
                    || facts.names[identifier.name.index()].spelling != "Same"
                {
                    return None;
                }
                let site = facts.sites[identifier.site.index()];
                (site.kind == ResolutionSiteKind::TypeDeclaration
                    && site.start_byte >= second_offset
                    && source[site.start_byte..site.end_byte].starts_with("case class Same"))
                .then_some(identifier.site)
            })
            .expect("second local case class declaration");
        let local_classes = [first, second];
        let local_companions = local_classes.map(companion_for);

        assert_ne!(
            first, second,
            "same-spelled local classes have distinct sites"
        );
        assert_ne!(
            facts.sites[first.index()].scope,
            facts.sites[second.index()].scope,
            "same-spelled local classes retain distinct method scopes"
        );
        assert_ne!(
            local_companions[0], local_companions[1],
            "same-spelled local companions have distinct sites"
        );

        for (class, companion) in local_classes.into_iter().zip(local_companions) {
            let class_declaration = declaration_source(class);
            let companion_declaration = declaration_source(companion);
            let class_scope = facts.sites[class.index()].scope;
            let companion_scope = facts
                .scopes
                .iter()
                .find(|scope| {
                    scope.owner == Some(companion) && scope.kind == ResolutionScopeKind::TypeBody
                })
                .unwrap_or_else(|| panic!("missing synthesized companion scope for {companion:?}"));

            assert_ne!(class, companion, "the companion is not the class site");
            assert_ne!(
                class_declaration, companion_declaration,
                "the companion has its own source declaration identity"
            );
            assert_eq!(
                facts.sites[companion.index()].scope,
                class_scope,
                "the companion declaration site stays in the enclosing lexical scope"
            );
            assert_eq!(
                companion_scope.parent,
                Some(class_scope),
                "the companion scope remains under the class's lexical scope"
            );
            assert_eq!(
                source_facts
                    .occurrences
                    .lexical_declaration(class_declaration)
                    .map(|fact| fact.kind),
                Some(DeclarationKind::BlockLocalItem)
            );
            assert_eq!(
                source_facts
                    .occurrences
                    .lexical_declaration(companion_declaration)
                    .map(|fact| (fact.kind, fact.identifier.as_str())),
                Some((DeclarationKind::BlockLocalItem, "Same")),
                "a unitless companion is published as its real lexical declaration"
            );
            assert!(
                !parsed
                    .source_declaration_units
                    .iter()
                    .any(|(declaration, _)| *declaration == class_declaration
                        || *declaration == companion_declaration),
                "method-local class and companion must not be assigned global parser units"
            );
            assert!(
                !facts
                    .definition_units
                    .iter()
                    .any(|definition| definition.declaration == companion),
                "the unitless companion must not publish a synthetic CodeUnit"
            );

            for member_name in ["apply", "unapply"] {
                let member = facts
                    .member_owners
                    .iter()
                    .find(|member| {
                        member.owner == companion
                            && facts.identifiers.iter().any(|identifier| {
                                identifier.site == member.member
                                    && identifier.role == ResolutionIdentifierRole::Declaration
                                    && facts.names[identifier.name.index()].spelling == member_name
                            })
                    })
                    .unwrap_or_else(|| panic!("synthesized companion must own `{member_name}`"));
                assert_eq!(
                    facts.sites[member.member.index()].scope,
                    companion_scope.id,
                    "generated `{member_name}` is in the matching companion scope"
                );
                assert_eq!(
                    declaration_source(member.member),
                    class_declaration,
                    "generated `{member_name}` is located at the local class constructor source"
                );
                assert!(
                    !facts
                        .jvm_aliases
                        .iter()
                        .any(|alias| alias.declaration == member.member),
                    "method-local `{member_name}` has no fabricated JVM alias"
                );
                assert!(facts.gaps.iter().any(|gap| {
                    gap.site == member.member
                        && matches!(
                            gap.route(),
                            Some(ResolutionRouteGap::UnknownAlias {
                                owner: ResolutionRouteOwner::Declaration(owner),
                                name: Some(name),
                                kind: Some(ResolutionJvmAliasKind::Method),
                                ..
                            }) if owner == class && facts.names[name.index()].spelling == member_name
                        )
                }), "the missing `{member_name}` JVM alias retains its classified boundary");
            }
        }

        let nested_class = declaration_named_at("Nested", "case class Nested");
        let nested_class_declaration = declaration_source(nested_class);
        let nested_companion = companion_for(nested_class);
        let nested_companion_declaration = declaration_source(nested_companion);
        let nested_class_unit = parsed
            .source_declaration_units
            .iter()
            .find_map(|(declaration, unit)| {
                (*declaration == nested_class_declaration).then_some(unit)
            })
            .expect("nested-template class retains its indexed unit");
        assert!(nested_class_unit.is_class() && !nested_class_unit.is_synthetic());
        let nested_companion_unit = facts
            .definition_units
            .iter()
            .find_map(|definition| {
                (definition.declaration == nested_companion).then_some(&definition.unit)
            })
            .expect("ordinary nested-template companion retains its synthetic unit");
        assert!(nested_companion_unit.is_class() && nested_companion_unit.is_synthetic());
        assert!(
            parsed
                .source_declaration_units
                .iter()
                .any(
                    |(declaration, unit)| *declaration == nested_companion_declaration
                        && unit == nested_companion_unit
                )
        );
    }

    #[test]
    #[hardwon("#5177: operator-named case classes lost their indexed declaration and constructor")]
    fn operator_named_top_level_case_class_keeps_its_parser_units() {
        let parsed = parse(
            "package scala.collection.immutable\nfinal case class ::[+A](head: A, tail: List[A])\n",
        );
        let classes = parsed
            .source_declaration_units
            .iter()
            .filter(|(_, unit)| unit.short_name() == "::" && unit.is_class())
            .collect::<Vec<_>>();
        assert_eq!(classes.len(), 1, "operator case class units={classes:?}");
        let (class_declaration, class_unit) = classes[0];
        assert!(!class_unit.is_synthetic());

        let constructors = parsed
            .source_declaration_units
            .iter()
            .filter(|(_, unit)| {
                unit.short_name() == "::.::" && unit.is_function() && unit.is_synthetic()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            constructors.len(),
            1,
            "primary constructor units={constructors:?}"
        );
        assert_ne!(
            *class_declaration, constructors[0].0,
            "the primary constructor keeps its own source declaration identity"
        );

        let facts = &parsed.resolution_facts;
        let class_site = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.names[identifier.name.index()].spelling == "::"
                    && facts.sites[identifier.site.index()].kind
                        == ResolutionSiteKind::TypeDeclaration
            })
            .expect("operator case class has a native type site")
            .site;
        let companion = facts
            .singleton_relations
            .iter()
            .find(|relation| {
                relation.kind == ResolutionSingletonRelationKind::Companion
                    && relation.enclosing_type == Some(class_site)
            })
            .expect("operator case class has its synthesized companion")
            .declaration;
        let companion_declaration = parsed
            .source_facts
            .as_ref()
            .expect("Scala source facts are published")
            .native_declaration_sources
            .iter()
            .find_map(|(site, declaration)| (*site == companion).then_some(*declaration))
            .expect("synthetic companion source mapping");
        let companion_unit = parsed
            .source_declaration_units
            .iter()
            .find_map(|(declaration, unit)| (*declaration == companion_declaration).then_some(unit))
            .expect("top-level synthesized companion keeps its synthetic parser unit");
        assert!(companion_unit.is_class() && companion_unit.is_synthetic());
        assert_eq!(
            companion_unit.short_name(),
            format!("{}$", class_unit.short_name())
        );
    }

    #[test]
    fn braced_package_case_class_keeps_its_jvm_companion_routes() {
        let parsed = parse("package demo.pkg { case class Point(value: Int) }\n");
        let facts = &parsed.resolution_facts;
        let companion = facts
            .singleton_relations
            .iter()
            .find(|relation| relation.kind == ResolutionSingletonRelationKind::Companion)
            .expect("the indexed case class has a companion")
            .declaration;
        for name in ["apply", "unapply"] {
            let member = facts
                .member_owners
                .iter()
                .find(|member| {
                    member.owner == companion
                        && facts.identifiers.iter().any(|identifier| {
                            identifier.site == member.member
                                && facts.names[identifier.name.index()].spelling == name
                        })
                })
                .expect("the companion owns its generated member");
            let alias = facts
                .jvm_aliases
                .iter()
                .find(|alias| alias.declaration == member.member)
                .unwrap_or_else(|| panic!("package-owned `{name}` retains its JVM alias"));
            let mut segments = facts
                .jvm_alias_owner_segments
                .iter()
                .filter(|segment| segment.alias == alias.id)
                .collect::<Vec<_>>();
            segments.sort_unstable_by_key(|segment| segment.ordinal);
            assert_eq!(
                segments
                    .iter()
                    .map(|segment| facts.names[segment.name.index()].spelling.as_str())
                    .collect::<Vec<_>>(),
                ["demo", "pkg", "Point$"],
                "a package boundary is not a local executable owner"
            );
        }
    }

    #[test]
    #[hardwon("#5177: initializer-local companions received global JVM aliases")]
    fn case_class_and_written_companion_in_initializer_block_have_no_jvm_route() {
        let source = "object Container {\n\
            {\n\
              case class LocalWithCompanion(value: Int)\n\
              object LocalWithCompanion\n\
              LocalWithCompanion(1).value\n\
            }\n\
          }\n";
        let parsed = parse(source);
        let facts = &parsed.resolution_facts;
        let source_facts = parsed
            .source_facts
            .as_ref()
            .expect("Scala source facts are published");
        let declaration_named_at = |name: &str, prefix: &str| {
            facts
                .identifiers
                .iter()
                .find_map(|identifier| {
                    if identifier.role != ResolutionIdentifierRole::Declaration
                        || facts.names[identifier.name.index()].spelling != name
                    {
                        return None;
                    }
                    let site = facts.sites[identifier.site.index()];
                    (site.kind == ResolutionSiteKind::TypeDeclaration
                        && source[site.start_byte..site.end_byte].starts_with(prefix))
                    .then_some(identifier.site)
                })
                .unwrap_or_else(|| panic!("missing declaration `{name}` at `{prefix}`"))
        };
        let declaration_source = |site: ResolutionSiteId| {
            let declarations = source_facts
                .native_declaration_sources
                .iter()
                .filter_map(|(candidate, declaration)| (*candidate == site).then_some(*declaration))
                .collect::<Vec<_>>();
            assert_eq!(
                declarations.len(),
                1,
                "each native site has exactly one source declaration bridge: {site:?}"
            );
            declarations[0]
        };

        let class = declaration_named_at("LocalWithCompanion", "case class LocalWithCompanion");
        let companion = declaration_named_at("LocalWithCompanion", "object LocalWithCompanion");
        let class_declaration = declaration_source(class);
        let companion_declaration = declaration_source(companion);
        assert!(
            !parsed
                .source_declaration_units
                .iter()
                .any(|(declaration, _)| {
                    *declaration == class_declaration || *declaration == companion_declaration
                }),
            "initializer-block declarations remain unitless"
        );

        for member_name in ["apply", "unapply"] {
            let member = facts
                .member_owners
                .iter()
                .find(|member| {
                    member.owner == companion
                        && facts.identifiers.iter().any(|identifier| {
                            identifier.site == member.member
                                && identifier.role == ResolutionIdentifierRole::Declaration
                                && facts.names[identifier.name.index()].spelling == member_name
                        })
                })
                .unwrap_or_else(|| panic!("written local companion must own `{member_name}`"));
            assert_eq!(
                declaration_source(member.member),
                class_declaration,
                "generated `{member_name}` keeps the local constructor source mapping"
            );
            assert!(
                !facts
                    .jvm_aliases
                    .iter()
                    .any(|alias| alias.declaration == member.member),
                "initializer-block `{member_name}` has no fabricated JVM alias"
            );
            assert!(facts.gaps.iter().any(|gap| {
                gap.site == member.member
                    && matches!(
                        gap.route(),
                        Some(ResolutionRouteGap::UnknownAlias {
                            owner: ResolutionRouteOwner::Declaration(owner),
                            name: Some(name),
                            kind: Some(ResolutionJvmAliasKind::Method),
                            ..
                        }) if owner == class && facts.names[name.index()].spelling == member_name
                    )
            }), "the missing `{member_name}` JVM alias retains its classified boundary");
        }
    }

    #[test]
    #[hardwon(
        "#3499: secondary val/var declaration names had no inherited member or declared-type rows"
    )]
    fn multi_name_member_declarations_share_ascription_projections() {
        let parsed = parse(
            "package app\ntrait Members { val qualifier, other: String; var current, previous: String }\n",
        );
        let facts = &parsed.resolution_facts;
        let declaration = |name: &str| {
            facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Declaration
                        && facts.names[identifier.name.index()].spelling == name
                })
                .expect("each name has a declaration")
                .site
        };
        let owner = declaration("Members");
        for names in [["qualifier", "other"], ["current", "previous"]] {
            let mut inputs = Vec::new();
            for name in names {
                let site = declaration(name);
                let member = facts
                    .member_owners
                    .iter()
                    .find(|row| row.member == site)
                    .expect("each name has a member-owner row");
                assert_eq!(member.owner, owner);
                assert_eq!(member.kind, ResolutionMemberKind::Field);
                let slot = facts
                    .declaration_type_slots
                    .iter()
                    .find(|row| row.declaration == site)
                    .expect("each name has a declared-value slot");
                assert_eq!(slot.role, DeclarationTypeRole::Value);
                let transfer = facts
                    .type_transfers
                    .iter()
                    .find(|row| row.output == slot.slot)
                    .expect("each declared value takes its ascribed type");
                assert_eq!(transfer.kind, ResolutionTypeTransferKind::DeclaredType);
                inputs.push(transfer.input);
            }
            assert_eq!(
                inputs[0], inputs[1],
                "a multi-name declaration shares its ascription projection"
            );
            assert_eq!(
                facts.type_slots[inputs[0].index()].role,
                ResolutionTypeSlotRole::TargetTypeIdentity
            );
        }
    }

    #[test]
    #[hardwon("#2771: self-type headers poisoned member lookup with an unsupported binder gap")]
    fn self_type_aliases_are_template_scoped_and_reuse_ascribed_projections() {
        let parsed = parse(
            "trait Tokens\ntrait Named { self: Tokens => }\ntrait Anonymous { this: Tokens => }\ntrait Plain { self => }\n",
        );
        let facts = &parsed.resolution_facts;
        assert!(
            !facts
                .gaps
                .iter()
                .any(|gap| gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder),
            "self-type headers have structured binder support: {:?}",
            facts.gaps
        );
        assert!(
            !facts
                .identifiers
                .iter()
                .any(|identifier| { facts.names[identifier.name.index()].spelling == "this" })
        );
        let aliases = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.names[identifier.name.index()].spelling == "self"
            })
            .collect::<Vec<_>>();
        assert_eq!(aliases.len(), 2);
        for alias in aliases {
            let binder = facts
                .binders
                .iter()
                .find(|binder| binder.declaration == alias.site)
                .expect("self alias binder");
            let scope = &facts.scopes[binder.scope.index()];
            assert_eq!(scope.kind, ResolutionScopeKind::TypeBody);
            assert_eq!(binder.hoisting, HoistingClass::ScopeWide);
            assert_eq!(binder.activation_start, scope.start_byte);
            assert_eq!(binder.activation_end, scope.end_byte);
            let value = facts
                .declaration_type_slots
                .iter()
                .find(|value| value.declaration == alias.site)
                .expect("self alias value type");
            assert_eq!(value.role, DeclarationTypeRole::Value);
            if let Some(edge) = facts
                .supertypes
                .iter()
                .find(|edge| Some(edge.subtype) == scope.owner)
            {
                assert_eq!(edge.kind, ResolutionSupertypeKind::SelfType);
                assert!(
                    facts.type_transfers.iter().any(|transfer| {
                        transfer.input == edge.supertype_slot && transfer.output == value.slot
                    }),
                    "self alias uses its parent's identity projection: {:?}",
                    facts.type_transfers
                );
            }
        }
    }

    #[test]
    fn self_type_bounds_publish_edges_without_becoming_nominal_subtypes() {
        let parsed = parse("trait Rules { this: Tokens with Audited => def run(): Unit = () }\n");
        let facts = &parsed.resolution_facts;
        let rules = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.names[identifier.name.index()].spelling == "Rules"
            })
            .expect("Rules declaration");
        let mut edges = facts
            .supertypes
            .iter()
            .filter(|edge| edge.subtype == rules.site)
            .collect::<Vec<_>>();
        edges.sort_by_key(|edge| edge.parent_ordinal);
        assert_eq!(edges.len(), 2, "self-type edges: {edges:?}");
        assert_eq!(edges[0].kind, ResolutionSupertypeKind::SelfType);
        assert_eq!(edges[1].kind, ResolutionSupertypeKind::SelfType);
        for (edge, expected_name) in edges.into_iter().zip(["Tokens", "Audited"]) {
            assert!(facts.identifiers.iter().any(|identifier| {
                identifier.site == edge.supertype_reference
                    && identifier.role == ResolutionIdentifierRole::Reference
                    && facts.names[identifier.name.index()].spelling == expected_name
            }));
            assert!(facts.binding_projections.iter().any(|projection| {
                projection.reference == edge.supertype_reference
                    && projection.output == edge.supertype_slot
                    && projection.kind == BindingProjectionKind::TargetTypeIdentity
            }));
            assert!(facts.gaps.iter().any(|gap| {
                gap.site == edge.supertype_reference
                    && gap.kind == ResolutionGapKind::UnsupportedHierarchyTraversal
            }));
        }
    }

    #[test]
    #[hardwon(
        "#3499: an uppercase selector republished its head as a second reference site on the same range, so a definition lookup there found two semantics"
    )]
    fn a_reference_range_has_one_reference_site() {
        let parsed = parse(
            "package demo\n\
             object DistF { case class Single(label: String); def single(label: String): String = label }\n\
             object Use {\n\
               val applied = DistF.Single(\"x\")\n\
               val lowered = DistF.single(\"y\")\n\
               val bare = DistF.Single\n\
               val typed: DistF.Single = null\n\
               val chained = DistF.Single(\"z\").label\n\
             }\n",
        );
        let facts = &parsed.resolution_facts;
        let mut sites_by_range =
            std::collections::BTreeMap::<(usize, usize), Vec<ResolutionSiteId>>::new();
        // A synthetic reference (the parents a case class has without writing
        // them) publishes no range, so it can share the declaration's range.
        for identifier in facts.identifiers.iter().filter(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && facts.sites[identifier.site.index()].kind
                    != ResolutionSiteKind::SyntheticReference
        }) {
            let site = facts.sites[identifier.site.index()];
            sites_by_range
                .entry((site.start_byte, site.end_byte))
                .or_default()
                .push(identifier.site);
        }
        for (range, sites) in sites_by_range {
            assert_eq!(
                sites.len(),
                1,
                "reference range {range:?} has sites {sites:?}"
            );
        }
    }

    #[test]
    #[hardwon("4edcab5d2c90: synthesized Scala companions lacked binders and exports")]
    fn synthesized_companions_have_term_binders_and_exports() {
        let parsed = parse(
            "package demo\ncase class Point(x: Int)\nobject Point {}\ncase class Solo(v: Int)\n",
        );
        let facts = &parsed.resolution_facts;
        let companions = facts
            .singleton_relations
            .iter()
            .filter(|relation| relation.kind == ResolutionSingletonRelationKind::Companion)
            .collect::<Vec<_>>();
        assert_eq!(
            companions.len(),
            2,
            "an explicit companion is merged, not duplicated"
        );
        let definition = facts
            .definition_units
            .iter()
            .find(|definition| definition.unit.is_class() && definition.unit.is_synthetic())
            .expect("Solo has a synthetic companion identity");
        let companion = definition.declaration;
        let binder = facts
            .binders
            .iter()
            .find(|binder| binder.declaration == companion)
            .expect("a synthetic companion has its own binder");
        assert_eq!(binder.kind, ResolutionBinderKind::Type);
        let identifier = facts
            .identifiers
            .iter()
            .find(|identifier| identifier.site == companion)
            .expect("a synthetic companion has a name");
        assert_eq!(identifier.namespace, ResolutionNamespace::Value);
        assert!(facts.root_exports.iter().any(|export| {
            export.declaration == companion
                && export.namespace == ResolutionNamespace::Value
                && export.root_scope == binder.scope
        }));
        assert!(facts.declaration_visibilities.iter().any(|visibility| {
            visibility.declaration == companion
                && visibility.visibility == DeclaredVisibility::Public
        }));
    }

    #[test]
    fn a_case_class_publishes_the_members_the_compiler_adds() {
        let parsed = parse(
            "package demo\n\
             case class Point(x: Int, y: Int)\n\
             object Point { def apply(x: Int, y: Int): Point = new Point(x, y) }\n\
             case class Solo(v: Int)\n",
        );
        let facts = &parsed.resolution_facts;
        let members_of = |owner: ResolutionSiteId| {
            facts
                .member_owners
                .iter()
                .filter(|member| {
                    member.owner == owner && member.kind == ResolutionMemberKind::Method
                })
                .map(|member| {
                    let name = facts
                        .identifiers
                        .iter()
                        .find(|identifier| identifier.site == member.member)
                        .map(|identifier| facts.names[identifier.name.index()].spelling.as_str())
                        .expect("a member has its declaration identifier");
                    (name, *member)
                })
                .collect::<Vec<_>>()
        };
        let parameters_of = |callable: ResolutionSiteId| {
            facts
                .callable_parameter_semantics
                .iter()
                .filter(|parameter| parameter.callable == callable)
                .map(|parameter| {
                    (
                        facts.names[parameter.label.index()].spelling.as_str(),
                        parameter.has_default,
                    )
                })
                .collect::<Vec<_>>()
        };
        let companion = facts
            .singleton_relations
            .iter()
            .find(|relation| relation.kind == ResolutionSingletonRelationKind::Companion)
            .expect("Point has an explicit companion");
        let point_object = companion.declaration;
        let point_class = companion.enclosing_type.expect("the companion's class");

        // The written `apply` replaces the compiler's of the same parameter
        // count; the extractor and `copy` are still added.
        let object_members = members_of(point_object);
        assert_eq!(
            object_members
                .iter()
                .map(|(name, _)| *name)
                .collect::<Vec<_>>(),
            ["apply", "unapply"],
            "{object_members:?}"
        );
        let (_, unapply) = object_members[1];
        assert_eq!(parameters_of(unapply.member), [("x$0", false)]);
        assert_eq!(
            (unapply.access, unapply.qualifier_compatibility),
            (
                ResolutionMemberAccess::Type,
                ResolutionMemberQualifierCompatibility::RuntimeOrType
            )
        );
        let class_members = members_of(point_class);
        let copy = class_members
            .iter()
            .find(|(name, _)| *name == "copy")
            .expect("copy is a member of the case class")
            .1;
        assert_eq!(
            parameters_of(copy.member),
            [("x", true), ("y", true)],
            "copy takes every constructor parameter, each optional"
        );
        assert_eq!(copy.access, ResolutionMemberAccess::Instance);

        // With no written companion, generated companion members have a
        // distinct synthetic owner and the class retains only instance members.
        let solo = facts
            .sites
            .iter()
            .enumerate()
            .filter(|(_, site)| site.kind == ResolutionSiteKind::TypeDeclaration)
            .map(|(index, _)| ResolutionSiteId::new(u32::try_from(index).expect("site index")))
            .filter(|site| members_of(*site).iter().any(|(name, _)| *name == "copy"))
            .find(|site| *site != point_class)
            .expect("Solo owns its members");
        let companion = facts
            .singleton_relations
            .iter()
            .find(|relation| {
                relation.kind == ResolutionSingletonRelationKind::Companion
                    && relation.enclosing_type == Some(solo)
            })
            .expect("Solo has a synthesized companion relation");
        let companion_members = members_of(companion.declaration);
        let apply = companion_members
            .iter()
            .find(|(name, _)| *name == "apply")
            .expect("the synthesized companion has apply")
            .1;
        assert_eq!(parameters_of(apply.member), [("v", false)]);
        assert_eq!(
            (apply.access, apply.qualifier_compatibility),
            (
                ResolutionMemberAccess::Type,
                ResolutionMemberQualifierCompatibility::RuntimeOrType
            )
        );
        assert_ne!(companion.declaration, solo);
        for (name, expected) in [("apply", 1), ("unapply", 2)] {
            assert_eq!(
                facts
                    .jvm_aliases
                    .iter()
                    .filter(|alias| facts.names[alias.member_name.index()].spelling == name)
                    .count(),
                expected,
                "a JVM alias of the synthesized `{name}`: the written `apply` of Point replaces its synthesized one"
            );
        }
    }

    #[test]
    #[hardwon("4edcab5d2c90: Scala enum cases were absent from companion member facts")]
    fn enum_cases_belong_to_the_companion_and_methods_to_the_class() {
        for source in [
            "package demo\nenum Color { case Red, Green; case Custom(value: Int); def rgb: Int = 0 }\n",
            "package demo\nenum Color { case Red, Green; case Custom(value: Int); def rgb: Int = 0 }\nobject Color { val default: Int = 0 }\n",
        ] {
            let parsed = parse(source);
            let facts = &parsed.resolution_facts;
            let companions = facts
                .singleton_relations
                .iter()
                .filter(|relation| relation.kind == ResolutionSingletonRelationKind::Companion)
                .collect::<Vec<_>>();
            assert_eq!(companions.len(), 1, "{companions:?}");
            let companion = companions[0].declaration;
            let companion_scope = facts
                .scopes
                .iter()
                .find(|scope| scope.owner == Some(companion))
                .expect("the companion owns its member scope")
                .id;
            let class = companions[0]
                .enclosing_type
                .expect("enum companion's class");
            let imports = facts
                .root_imports
                .iter()
                .filter(|import| facts.scopes[import.root_scope.index()].owner == Some(class))
                .collect::<Vec<_>>();
            assert_eq!(imports.len(), 3);
            for import in imports {
                assert_eq!(import.anchor, ResolutionRootImportAnchor::Absolute);
                let path = facts
                    .root_import_segments
                    .iter()
                    .filter(|segment| segment.import_site == import.site)
                    .map(|segment| facts.names[segment.name.index()].spelling.as_str())
                    .collect::<Vec<_>>();
                assert_eq!(path, ["demo", "Color"]);
            }
            let named = |name| {
                facts
                    .identifiers
                    .iter()
                    .find(|identifier| {
                        identifier.role == ResolutionIdentifierRole::Declaration
                            && facts.names[identifier.name.index()].spelling == name
                    })
                    .expect("a declared member")
                    .site
            };
            for name in ["Red", "Green", "Custom"] {
                let case = named(name);
                let member = facts
                    .member_owners
                    .iter()
                    .find(|member| member.member == case)
                    .expect("each enum case has a member-owner fact");
                assert_eq!(member.owner, companion, "{member:?}");
                assert_eq!(member.access, ResolutionMemberAccess::Type);
                assert_eq!(facts.sites[case.index()].scope, companion_scope);
                assert!(facts.binders.iter().any(|binder| {
                    binder.declaration == case && binder.scope == companion_scope
                }));
                assert!(
                    facts
                        .definition_units
                        .iter()
                        .any(|unit| unit.declaration == case)
                );
            }
            assert_eq!(
                facts
                    .member_owners
                    .iter()
                    .find(|member| member.member == named("rgb"))
                    .expect("enum method")
                    .owner,
                class
            );
            assert!(
                facts
                    .binders
                    .iter()
                    .any(|binder| binder.declaration == companion)
            );
        }
        let parsed = parse("object Holder { def run: Int = { enum Local { case Entry }; 0 } }");
        let facts = &parsed.resolution_facts;
        let companion = facts
            .singleton_relations
            .iter()
            .find(|relation| relation.kind == ResolutionSingletonRelationKind::Companion)
            .expect("a local enum has a lexical companion")
            .declaration;
        assert!(
            facts
                .binders
                .iter()
                .any(|binder| binder.declaration == companion)
        );
        assert!(
            !facts
                .definition_units
                .iter()
                .any(|unit| unit.declaration == companion)
        );
        let parsed = parse("class Holder { enum Local { case Entry } }");
        assert!(parsed.resolution_facts.root_imports.is_empty());
        assert!(
            parsed
                .resolution_facts
                .reference_enumeration_gaps
                .iter()
                .any(|gap| { gap.kind == ResolutionGapKind::UnsupportedRoute }),
            "an instance-owned companion needs a bound-owner import route"
        );
    }

    #[test]
    #[hardwon(
        "8b8fb64b96ee: a case class without a written companion had no companion relation for synthesized extractor members"
    )]
    fn case_classes_without_companions_publish_synthesized_companion_relations() {
        let parsed = parse(
            "package demo\n\
             case class Solo(v: Int)\n\
             object Outer { case class Nested(v: Int) }\n",
        );
        let facts = &parsed.resolution_facts;
        for name in ["Solo", "Nested"] {
            let class = facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Declaration
                        && facts.names[identifier.name.index()].spelling == name
                })
                .unwrap_or_else(|| panic!("missing case class {name}"))
                .site;
            let relation = facts
                .singleton_relations
                .iter()
                .find(|relation| {
                    relation.kind == ResolutionSingletonRelationKind::Companion
                        && relation.enclosing_type == Some(class)
                })
                .unwrap_or_else(|| panic!("missing synthesized companion relation for {name}"));
            assert_ne!(
                relation.declaration, class,
                "{name} needs a distinct companion identity"
            );
            assert!(
                facts.member_owners.iter().any(|member| {
                    member.owner == relation.declaration
                        && facts.identifiers.iter().any(|identifier| {
                            identifier.site == member.member
                                && facts.names[identifier.name.index()].spelling == "unapply"
                        })
                }),
                "{name}'s synthesized companion must own its extractor"
            );
        }
    }

    #[test]
    #[hardwon(
        "4edcab5d2c90: qualified generic projection owners lost every segment before the leaf"
    )]
    fn qualified_projection_preserves_the_structured_owner_path() {
        let parsed = parse("package use\nobject Use { val x: app.Schema[Int]#Focused = null }\n");
        let facts = &parsed.resolution_facts;
        let selector = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && facts.names[identifier.name.index()].spelling == "Focused"
            })
            .expect("projection selector");
        let owner_path = facts
            .root_reference_segments
            .iter()
            .filter(|segment| segment.reference == selector.site)
            .map(|segment| facts.names[segment.name.index()].spelling.as_str())
            .collect::<Vec<_>>();
        assert_eq!(owner_path, ["app", "Schema"]);
    }

    #[test]
    #[hardwon(
        "#1860: native Scala members from sibling anonymous bodies shared an enclosing owner"
    )]
    fn anonymous_templates_own_their_body_but_not_construction_arguments() {
        let source = "trait Task\nobject Holders { val argument = 1; val first = new Task(argument) { def run = 1 }; val second = new Task(argument) { def run = 2 } }\n";
        let parsed = parse(source);
        let facts = &parsed.resolution_facts;
        let methods = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.names[identifier.name.index()].spelling == "run"
            })
            .collect::<Vec<_>>();
        assert_eq!(methods.len(), 2);
        let owners = methods
            .iter()
            .map(|method| {
                let scope = &facts.scopes[facts.sites[method.site.index()].scope.index()];
                assert_eq!(scope.kind, ResolutionScopeKind::TypeBody);
                let owner = scope.owner.expect("anonymous type body owner");
                assert_eq!(
                    facts.sites[owner.index()].kind,
                    ResolutionSiteKind::TypeDeclaration
                );
                assert!(
                    facts
                        .member_owners
                        .iter()
                        .any(|member| member.member == method.site && member.owner == owner)
                );
                assert!(
                    facts
                        .supertypes
                        .iter()
                        .any(|parent| parent.subtype == owner)
                );
                owner
            })
            .collect::<Vec<_>>();
        assert_ne!(owners[0], owners[1]);
        for argument in facts.identifiers.iter().filter(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && facts.names[identifier.name.index()].spelling == "argument"
        }) {
            let scope = &facts.scopes[facts.sites[argument.site.index()].scope.index()];
            assert!(!scope.owner.is_some_and(|owner| owners.contains(&owner)));
        }
    }

    #[test]
    fn scala_parse_publishes_native_declarations_calls_imports_and_parents() {
        let parsed = parse(
            "package demo\n\
             import scala.collection.mutable\n\
             import java.util._\n\
             import scala.collection.{immutable => imm}\n\
             trait Parent\n\
             type Label = String\n\
             class Box extends Parent {\n\
               val label: String = \"x\"\n\
             def show(prefix: String): String = {\n\
                 def localMethod(value: String): String = value\n\
                 val local = prefix\n\
                 Renderer.print(local)\n\
                 local\n\
               }\n\
             }\n\
             object Renderer { def print(value: String): Unit = () }\n\
             package inner { class Nested }\n",
        );
        let facts = &parsed.resolution_facts;
        assert!(facts.scopes.len() >= 4, "scopes={:?}", facts.scopes);
        assert!(facts.packages.len() >= 2, "routes={:?}", facts.packages);
        assert!(!facts.package_members.is_empty());
        assert!(!facts.package_references.is_empty());
        let placement_site = facts.packages[0].placement_gap_site;
        assert!(!facts.gaps.iter().any(|gap| {
            gap.site == placement_site
                && matches!(
                    gap.kind,
                    ResolutionGapKind::UnsupportedPlacementBoundary
                        | ResolutionGapKind::UnsupportedRoute
                )
        }));
        assert!(
            facts
                .identifiers
                .iter()
                .any(|row| row.role == ResolutionIdentifierRole::Declaration
                    && facts.names[row.name.index()].spelling == "Box")
        );
        let declaration_named = |name: &str| {
            facts.identifiers.iter().find_map(|identifier| {
                (identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.names[identifier.name.index()].spelling == name)
                    .then_some(identifier.site)
            })
        };
        let box_declaration = declaration_named("Box").expect("class declaration");
        let box_unit = facts
            .definition_units
            .iter()
            .find(|fact| fact.declaration == box_declaration)
            .expect("class definition unit");
        assert!(box_unit.unit.is_class(), "unit={:?}", box_unit.unit);
        assert!(!box_unit.unit.is_synthetic(), "unit={:?}", box_unit.unit);
        let show_declaration = declaration_named("show").expect("method declaration");
        let show_unit = facts
            .definition_units
            .iter()
            .find(|fact| fact.declaration == show_declaration)
            .expect("method definition unit");
        assert!(show_unit.unit.is_function(), "unit={:?}", show_unit.unit);
        assert!(!show_unit.unit.is_synthetic(), "unit={:?}", show_unit.unit);
        let alias = declaration_named("Label").expect("type alias declaration");
        assert!(facts.declaration_type_slots.iter().any(|slot| {
            slot.declaration == alias && slot.role == DeclarationTypeRole::Identity
        }));
        let local_method = declaration_named("localMethod").expect("local method declaration");
        assert!(
            facts
                .member_owners
                .iter()
                .all(|member| member.member != local_method)
        );
        let nested_type = declaration_named("Nested").expect("nested package type");
        assert!(facts.root_exports.iter().any(|export| {
            export.declaration == nested_type
                && facts.scopes[export.root_scope.index()].kind == ResolutionScopeKind::Package
        }));
        assert!(facts.package_members.iter().any(|member| {
            member.declaration == nested_type
                && facts.scopes[member.root_scope.index()].kind == ResolutionScopeKind::Package
        }));
        let renderer = declaration_named("Renderer").expect("Scala object declaration");
        assert!(facts.additional_definition_namespaces.iter().any(|row| {
            row.declaration == renderer
                && row.namespace == ResolutionNamespace::Value
                && row.hoisting == HoistingClass::ScopeWide
        }));
        assert!(facts.root_exports.iter().any(|export| {
            export.declaration == renderer && export.namespace == ResolutionNamespace::Value
        }));
        assert!(facts.package_members.iter().any(|member| {
            member.declaration == renderer && member.namespace == ResolutionNamespace::Value
        }));
        assert!(
            facts
                .binders
                .iter()
                .any(|row| row.kind == ResolutionBinderKind::Parameter)
        );
        assert!(
            facts
                .binders
                .iter()
                .any(|row| row.kind == ResolutionBinderKind::Local)
        );
        assert!(
            facts
                .member_owners
                .iter()
                .any(|row| row.kind == ResolutionMemberKind::Method)
        );
        assert_eq!(facts.calls.len(), 1, "calls={:?}", facts.calls);
        assert_eq!(facts.call_argument_lists.len(), 1);
        assert_eq!(facts.invocation_roles.len(), 1);
        assert_eq!(
            facts.invocation_roles[0].role,
            ResolutionInvocationRole::Direct
        );
        assert!(facts.calls.iter().all(|call| {
            facts.binding_projections.iter().any(|projection| {
                projection.reference == call.callee
                    && projection.output == call.result
                    && projection.kind == BindingProjectionKind::TargetCallableResultType
            })
        }));
        assert_eq!(
            facts.call_arguments.len(),
            1,
            "args={:?}",
            facts.call_arguments
        );
        assert_eq!(
            facts.supertypes.len(),
            1,
            "supertypes={:?}",
            facts.supertypes
        );
        assert_eq!(facts.supertypes[0].parent_ordinal, 0);
        assert!(
            facts
                .root_import_kinds
                .iter()
                .any(|row| row.kind == ResolutionRootImportKind::Named)
        );
        assert!(
            facts
                .root_import_kinds
                .iter()
                .any(|row| row.kind == ResolutionRootImportKind::Glob)
        );
        assert!(facts.import_routes.len() >= 3);
        assert!(facts.import_selectors.iter().any(|selector| {
            selector.kind == ResolutionImportSelectorKind::Named
                && selector
                    .source_name
                    .is_some_and(|name| facts.names[name.index()].spelling == "immutable")
                && selector
                    .local_name
                    .is_some_and(|name| facts.names[name.index()].spelling == "imm")
        }));
        assert!(facts.identifiers.iter().all(|identifier| {
            identifier.role != ResolutionIdentifierRole::Declaration
                || facts.names[identifier.name.index()].spelling != "mutable"
        }));
        let immutable_alias_import = facts
            .import_selectors
            .iter()
            .find(|selector| {
                selector
                    .local_name
                    .is_some_and(|name| facts.names[name.index()].spelling == "imm")
            })
            .expect("renamed Scala import");
        assert!(facts.root_imports.iter().any(|import| {
            import.site == immutable_alias_import.site && import.position.is_some()
        }));
        assert_eq!(
            immutable_alias_import.kind,
            ResolutionImportSelectorKind::Named
        );
        assert_eq!(
            immutable_alias_import
                .source_name
                .map(|name| facts.names[name.index()].spelling.as_str()),
            Some("immutable")
        );
        assert!(facts.import_routes.iter().any(|route| {
            route.site == immutable_alias_import.site
                && route
                    .bound_name
                    .is_some_and(|name| facts.names[name.index()].spelling == "imm")
        }));
        for namespace in [
            ResolutionNamespace::Type,
            ResolutionNamespace::Value,
            ResolutionNamespace::Callable,
        ] {
            assert!(facts.root_import_demands.iter().any(|demand| {
                demand.import_site == immutable_alias_import.site
                    && demand.namespace == namespace
                    && facts.names[demand.name.index()].spelling == "immutable"
            }));
        }

        let import_segments = |kind: ResolutionRootImportKind| {
            let site = facts
                .root_import_kinds
                .iter()
                .find(|row| row.kind == kind)
                .expect("Scala import kind")
                .import_site;
            facts
                .root_import_segments
                .iter()
                .filter(|row| row.import_site == site)
                .map(|row| {
                    (
                        row.position,
                        facts.names[row.name.index()].spelling.as_str(),
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            import_segments(ResolutionRootImportKind::Named),
            vec![(0, "scala"), (1, "collection")]
        );
        assert_eq!(
            import_segments(ResolutionRootImportKind::Glob),
            vec![(0, "java"), (1, "util")]
        );
        assert!(
            facts
                .root_import_demand_targets
                .iter()
                .all(|target| { target.target == ResolutionRootImportDemandTarget::SameNameGlob })
        );
        assert!(facts.import_routes.iter().all(|route| {
            !facts.gaps.iter().any(|gap| {
                gap.site == route.site && gap.kind == ResolutionGapKind::UnsupportedRoute
            })
        }));
        let source = parsed.source_facts.as_ref().expect("Scala source facts");
        assert_eq!(source.native_site_occurrences.len(), facts.sites.len());
        assert!(!source.native_declaration_sources.is_empty());
    }

    #[test]
    #[hardwon("54074371bfc0: Scala callable signatures omitted written result types")]
    fn scala_resolution_publishes_written_callable_result_types() {
        let parsed = parse(
            "object ResultTypes {\n\
               def explicit(): String = \"x\"\n\
               def inferred() = \"x\"\n\
             }\n",
        );
        let facts = &parsed.resolution_facts;
        let declaration_named = |name: &str| {
            facts.identifiers.iter().find_map(|identifier| {
                (identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.names[identifier.name.index()].spelling == name)
                    .then_some(identifier.site)
            })
        };
        let explicit = declaration_named("explicit").expect("explicit def");
        let signature = facts
            .callable_signatures
            .iter()
            .find(|signature| signature.callable == explicit)
            .expect("explicit def signature");
        let [result] = signature.result_types.as_slice() else {
            panic!("written result type is published: {signature:?}");
        };
        assert_eq!(result.ordinal, 0);
        assert!(facts.declaration_type_slots.iter().any(|slot| {
            slot.declaration == explicit
                && slot.slot == result.value_type
                && slot.role == DeclarationTypeRole::Return
        }));
        let transfer = facts
            .type_transfers
            .iter()
            .find(|transfer| transfer.output == result.value_type)
            .expect("declared return type transfer");
        assert_eq!(transfer.kind, ResolutionTypeTransferKind::DeclaredType);
        assert_eq!(
            transfer.value_transform,
            ResolutionTypeTransferValueTransform::ToRuntime { addressable: false }
        );
        assert!(facts.binding_projections.iter().any(|projection| {
            projection.output == transfer.input
                && projection.kind == BindingProjectionKind::TargetTypeIdentity
        }));

        let inferred = declaration_named("inferred").expect("inferred def");
        let signature = facts
            .callable_signatures
            .iter()
            .find(|signature| signature.callable == inferred)
            .expect("inferred def signature");
        assert!(signature.result_types.is_empty());
        assert!(!facts.declaration_type_slots.iter().any(|slot| {
            slot.declaration == inferred && slot.role == DeclarationTypeRole::Return
        }));
    }

    #[test]
    #[hardwon("54074371bfc0: Scala call input slots were disconnected from expression results")]
    fn scala_resolution_transfers_call_results_to_argument_and_receiver_slots() {
        let parsed = parse(
            "object Transfer {\n\
               class Box { def sink(value: Box): Unit = () }\n\
               def source(): Box = new Box()\n\
               def run(box: Box): Unit = box.sink(source())\n\
             }\n",
        );
        let facts = &parsed.resolution_facts;
        let reference_named = |name: &str| {
            facts.identifiers.iter().find_map(|identifier| {
                (identifier.role == ResolutionIdentifierRole::Reference
                    && facts.names[identifier.name.index()].spelling == name)
                    .then_some(identifier.site)
            })
        };
        let source_reference = reference_named("source").expect("nested source call");
        let source_call = facts
            .calls
            .iter()
            .find(|call| call.callee == source_reference)
            .expect("source call fact");
        let sink_reference = reference_named("sink").expect("member sink call");
        let sink_call = facts
            .calls
            .iter()
            .find(|call| call.callee == sink_reference)
            .expect("sink call fact");
        let argument = facts
            .call_arguments
            .iter()
            .find(|argument| argument.call == sink_call.call)
            .expect("sink argument fact");
        assert!(facts.type_transfers.iter().any(|transfer| {
            transfer.input == source_call.result
                && transfer.output == argument.value
                && transfer.kind == ResolutionTypeTransferKind::Argument
        }));

        let receiver = sink_call.receiver.expect("call-owned receiver slot");
        assert!(facts.type_transfers.iter().any(|transfer| {
            transfer.output == receiver && transfer.kind == ResolutionTypeTransferKind::Receiver
        }));
        assert_eq!(facts.type_slots[receiver.index()].site, sink_call.call);
    }

    #[test]
    #[hardwon(
        "5020e82c89c6: Scala explicit call type arguments were omitted from applicability obligations"
    )]
    fn scala_explicit_method_type_arguments_publish_call_slots() {
        let source = "package conformance\n\
            final class GenericWorker {\n\
              def identity[A](value: A): A = value\n\
            }\n\
            object GenericCaller {\n\
              def identity[A](value: A): A = value\n\
              def root(worker: GenericWorker): Int = {\n\
                val direct = identity[Int](7)\n\
                worker.identity[Int](7)\n\
              }\n\
            }\n";
        let parsed = parse(source);
        let facts = &parsed.resolution_facts;
        let explicit_calls = facts
            .calls
            .iter()
            .filter(|call| call.explicit_type_argument_count == 1)
            .collect::<Vec<_>>();
        assert_eq!(explicit_calls.len(), 2, "calls={:?}", facts.calls);
        for call in explicit_calls {
            let arguments = facts
                .call_type_arguments
                .iter()
                .filter(|argument| argument.call == call.call)
                .collect::<Vec<_>>();
            let [argument] = arguments.as_slice() else {
                panic!("one type-argument slot for {call:?}");
            };
            assert_eq!(argument.ordinal, 0);
            let type_argument_transfer = facts
                .type_transfers
                .iter()
                .find(|transfer| {
                    transfer.output == argument.value
                        && transfer.kind == ResolutionTypeTransferKind::DeclaredType
                })
                .expect("explicit type argument has a declared-type transfer");
            assert!(facts.binding_projections.iter().any(|projection| {
                projection.output == type_argument_transfer.input
                    && projection.kind == BindingProjectionKind::TargetTypeIdentity
                    && facts.identifiers.iter().any(|identifier| {
                        identifier.site == projection.reference
                            && identifier.namespace == ResolutionNamespace::Type
                            && facts.names[identifier.name.index()].spelling == "Int"
                    })
            }));
        }
    }

    #[test]
    #[hardwon("5e43d5b1f088: bare Scala String call frontier lacked an external provider identity")]
    fn scala_external_provider_string_parameter_transfer_reaches_call_frontier() {
        let parsed = parse(
            "package dataflowbench\n\
             object DirectFlow {\n\
               def dfb_source(): String = {\n\
                 \"tainted\"\n\
               }\n\
               def dfb_sink(value: String): Unit = {}\n\
               def run(): Unit = {\n\
                 dfb_sink(dfb_source())\n\
               }\n\
             }\n",
        );
        let facts = &parsed.resolution_facts;
        let string_references = facts
            .identifiers
            .iter()
            .filter_map(|identifier| {
                (identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == ResolutionNamespace::Type
                    && facts.names[identifier.name.index()].spelling == "String")
                    .then_some(identifier.site)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            string_references.len(),
            2,
            "source result and sink parameter"
        );
        for &reference in &string_references {
            assert!(
                facts
                    .package_references
                    .iter()
                    .any(|package_reference| package_reference.reference == reference)
            );
            assert!(facts.binding_projections.iter().any(|projection| {
                projection.reference == reference
                    && projection.kind == BindingProjectionKind::TargetTypeIdentity
            }));
        }
        let sink_declaration = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.names[identifier.name.index()].spelling == "dfb_sink"
            })
            .expect("sink callable declaration");
        let parameter = facts
            .callable_parameters
            .iter()
            .find(|parameter| parameter.callable == sink_declaration.site)
            .expect("sink's typed parameter");
        assert!(
            facts.type_transfers.iter().any(|transfer| {
                transfer.output == parameter.value_type
                    && transfer.kind == ResolutionTypeTransferKind::DeclaredType
                    && string_references.iter().any(|reference| {
                        facts.binding_projections.iter().any(|projection| {
                            projection.reference == *reference
                                && projection.output == transfer.input
                        })
                    })
            }),
            "the written String type feeds the formal slot"
        );
        let reference_named = |name: &str| {
            facts.identifiers.iter().find_map(|identifier| {
                (identifier.role == ResolutionIdentifierRole::Reference
                    && facts.names[identifier.name.index()].spelling == name)
                    .then_some(identifier.site)
            })
        };
        let source_reference = reference_named("dfb_source").expect("nested source call");
        let source_call = facts
            .calls
            .iter()
            .find(|call| call.callee == source_reference)
            .expect("source call fact");
        let sink_reference = reference_named("dfb_sink").expect("bare sink call");
        let sink_call = facts
            .calls
            .iter()
            .find(|call| call.callee == sink_reference)
            .expect("sink call fact");
        let argument = facts
            .call_arguments
            .iter()
            .find(|argument| argument.call == sink_call.call)
            .expect("sink argument fact");
        assert!(facts.type_transfers.iter().any(|transfer| {
            transfer.input == source_call.result
                && transfer.output == argument.value
                && transfer.kind == ResolutionTypeTransferKind::Argument
        }));
        for callee in [source_reference, sink_reference] {
            assert!(facts.gaps.iter().any(|gap| {
                gap.site == callee && gap.kind == ResolutionGapKind::UnsupportedCallApplicability
            }));
        }
    }

    #[test]
    #[hardwon("0eab5b5eb9a4: Scala calls skipped Callable declaration candidates")]
    fn scala_function_value_call_publishes_callable_and_fallback_facts() {
        let parsed = parse(
            "package app\n\
             object Calls {\n\
               type Factory = Int\n\
               val Factory: Int => Int = value => value + 1\n\
               val result = Factory(0)\n\
               object Service { def run(): Int = 2 }\n\
               val memberResult = Service.run()\n\
             }\n",
        );
        let facts = &parsed.resolution_facts;
        let target = |name: &str| {
            let call = facts
                .calls
                .iter()
                .find(|call| {
                    facts.identifiers.iter().any(|identifier| {
                        identifier.site == call.callee
                            && identifier.role == ResolutionIdentifierRole::Reference
                            && facts.names[identifier.name.index()].spelling == name
                    })
                })
                .unwrap_or_else(|| panic!("missing call to {name}"));
            let callee = facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.site == call.callee
                        && identifier.role == ResolutionIdentifierRole::Reference
                })
                .expect("call target reference");
            (call, callee)
        };
        let (call, callee) = target("Factory");
        assert_eq!(callee.namespace, ResolutionNamespace::Callable);
        assert_eq!(
            facts.sites[call.callee.index()].kind,
            ResolutionSiteKind::CallableReference
        );
        assert_eq!(
            facts
                .callable_receiver_origins
                .iter()
                .find(|origin| origin.reference == call.callee)
                .map(|origin| origin.origin),
            Some(ResolutionCallableReceiverOrigin::Implicit)
        );
        assert!(facts.binding_projections.iter().any(|projection| {
            projection.reference == call.callee
                && projection.output == call.result
                && projection.kind == BindingProjectionKind::TargetCallableResultType
        }));
        let (member_call, member_callee) = target("run");
        assert_eq!(member_callee.namespace, ResolutionNamespace::Callable);
        assert_eq!(
            facts
                .callable_receiver_origins
                .iter()
                .find(|origin| origin.reference == member_call.callee)
                .map(|origin| origin.origin),
            Some(ResolutionCallableReceiverOrigin::ExplicitExpression)
        );
        assert!(facts.identifiers.iter().all(|identifier| {
            facts.names[identifier.name.index()].spelling != "Service"
                || identifier.namespace != ResolutionNamespace::Callable
        }));
        let roles = facts
            .invocation_roles
            .iter()
            .filter(|invocation| invocation.site == call.call)
            .map(|invocation| invocation.role)
            .collect::<Vec<_>>();
        assert_eq!(roles, [ResolutionInvocationRole::Direct]);
    }

    #[test]
    #[hardwon(
        "#5015: Scala reassignments and typed local initializers had no observed value facts"
    )]
    fn local_writes_keep_initializer_values_and_isolate_labels_and_members() {
        let source = r#"
class Box(var member: String)
object Writes {
  def consume(value: String): String = value
  def use(box: Box, items: Array[String]): Unit = {
    var typed, sibling: String = "first"
    var inferred = "second"
    var count = 0
    typed = inferred
    inferred = if (true) "then" else "else"
    consume(value = typed)
    new Box(member = typed)
    count += 1
    box.member = typed
    items(0) = inferred
    box.member += typed
    items(0) += inferred
  }
}
"#;
        let parsed = parse(source);
        let facts = &parsed.resolution_facts;
        let mut writes = facts.local_writes.iter().collect::<Vec<_>>();
        writes.sort_unstable_by_key(|write| facts.sites[write.target.index()].start_byte);
        let targets = writes
            .iter()
            .map(|write| {
                let identifier = facts
                    .identifiers
                    .iter()
                    .find(|identifier| identifier.site == write.target)
                    .expect("write keeps the positioned LHS reference");
                assert_eq!(identifier.role, ResolutionIdentifierRole::Reference);
                assert!(identifier.qualifier.is_none());
                facts.names[identifier.name.index()].spelling.as_str()
            })
            .collect::<Vec<_>>();
        assert_eq!(targets, ["typed", "inferred", "count"]);
        assert!(
            facts
                .binding_projections
                .iter()
                .any(|projection| projection.output == writes[0].value)
        );
        for write in &writes[1..] {
            let site = facts.type_slots[write.value.index()].site;
            assert!(
                facts.gaps.iter().any(|gap| gap.site == site),
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
        for (name, kind) in [
            ("typed", ResolutionTypeTransferKind::DeclaredType),
            ("sibling", ResolutionTypeTransferKind::DeclaredType),
            ("inferred", ResolutionTypeTransferKind::Initialization),
            ("count", ResolutionTypeTransferKind::Initialization),
        ] {
            let binder = facts
                .binders
                .iter()
                .find(|binder| {
                    binder.kind == ResolutionBinderKind::Local
                        && facts.identifiers.iter().any(|identifier| {
                            identifier.site == binder.declaration
                                && facts.names[identifier.name.index()].spelling == name
                        })
                })
                .expect("local binder");
            let declared = facts
                .declaration_type_slots
                .iter()
                .find(|slot| slot.declaration == binder.declaration)
                .expect("declared value");
            assert!(
                facts
                    .type_transfers
                    .iter()
                    .any(|transfer| { transfer.output == declared.slot && transfer.kind == kind })
            );
            let observations = facts
                .type_transfers
                .iter()
                .filter(|transfer| {
                    let output = facts.type_slots[transfer.output.index()];
                    transfer.kind == ResolutionTypeTransferKind::Assignment
                        && output.site == binder.declaration
                        && output.role == ResolutionTypeSlotRole::AssignmentValue
                })
                .collect::<Vec<_>>();
            assert_eq!(observations.len(), 1, "{name}: {observations:?}");
            assert_ne!(observations[0].output, declared.slot);
        }
        for spelling in [
            "box.member = typed",
            "items(0) = inferred",
            "box.member += typed",
            "items(0) += inferred",
        ] {
            let gap = facts
                .gaps
                .iter()
                .find(|gap| {
                    let site = facts.sites[gap.site.index()];
                    gap.kind == ResolutionGapKind::UnsupportedExpression
                        && &source[site.start_byte..site.end_byte] == spelling
                })
                .expect("non-bare mutation remains explicitly unsupported");
            let mutation = facts.sites[gap.site.index()];
            assert_eq!(mutation.kind, ResolutionSiteKind::UnsupportedExpression);
            for slot in facts.type_slots.iter().filter(|slot| {
                slot.role == ResolutionTypeSlotRole::Receiver
                    && facts.sites[slot.site.index()].start_byte >= mutation.start_byte
                    && facts.sites[slot.site.index()].end_byte <= mutation.end_byte
            }) {
                assert_ne!(slot.site, gap.site, "{spelling}: {slot:?}");
                assert!(
                    !facts.gaps.iter().any(|gap| {
                        gap.site == slot.site
                            && gap.kind == ResolutionGapKind::UnsupportedExpression
                    }),
                    "{spelling}: {slot:?}"
                );
            }
            assert!(
                !facts
                    .identifiers
                    .iter()
                    .any(|identifier| identifier.site == gap.site),
                "mutation gap must not reuse a member reference"
            );
            for member in facts.sites.iter().filter(|site| {
                site.kind == ResolutionSiteKind::MemberReference
                    && site.start_byte >= mutation.start_byte
                    && site.end_byte <= mutation.end_byte
            }) {
                assert!(
                    !facts.gaps.iter().any(|gap| {
                        gap.site == member.id
                            && gap.kind == ResolutionGapKind::UnsupportedExpression
                    }),
                    "{spelling}: {member:?}"
                );
            }
        }
        for spelling in ["box.member += typed", "items(0) += inferred"] {
            let call = facts
                .sites
                .iter()
                .find(|site| {
                    site.kind == ResolutionSiteKind::Call
                        && &source[site.start_byte..site.end_byte] == spelling
                })
                .expect("compound mutation retains its infix call");
            let has_receiver = facts
                .type_slots
                .iter()
                .any(|slot| slot.site == call.id && slot.role == ResolutionTypeSlotRole::Receiver);
            let has_unsupported_call_gap = facts.gaps.iter().any(|gap| {
                gap.site == call.id && gap.kind == ResolutionGapKind::UnsupportedCallApplicability
            });
            assert!(
                has_receiver || has_unsupported_call_gap,
                "{spelling}: absent receiver must retain an explicit call-applicability gap"
            );
        }
    }

    #[test]
    fn scala_named_argument_labels_and_import_segments_have_positioned_references() {
        let source = "package app\n\
                     import scala.collection.mutable\n\
                     object Args {\n\
                       def consume(value: String): Unit = ()\n\
                       def use(): Unit = consume(value = \"x\")\n\
                     }\n";
        let parsed = parse(source);
        let facts = &parsed.resolution_facts;
        let label = facts
            .named_argument_labels
            .first()
            .expect("named-argument label fact");
        assert_eq!(facts.names[label.label.index()].spelling, "value");
        assert_eq!(
            facts.sites[label.reference.index()].kind,
            ResolutionSiteKind::ValueReference
        );
        let identifier = facts
            .identifiers
            .iter()
            .find(|identifier| identifier.site == label.reference)
            .expect("label reference identity");
        assert_eq!(identifier.role, ResolutionIdentifierRole::Reference);
        let label_site = &facts.sites[label.reference.index()];
        assert_eq!(
            source.get(label_site.start_byte..label_site.end_byte),
            Some("value")
        );
        assert!(facts.call_arguments.iter().any(|argument| {
            argument.call == label.call
                && argument
                    .label
                    .is_some_and(|name| facts.names[name.index()].spelling == "value")
        }));

        for (name, offset) in [
            (
                "scala",
                source.find("import scala").expect("import path") + "import ".len(),
            ),
            (
                "collection",
                source.find("collection").expect("package segment"),
            ),
            ("mutable", source.find("mutable").expect("terminal segment")),
        ] {
            let reference = facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Reference
                        && facts.names[identifier.name.index()].spelling == name
                        && facts.sites[identifier.site.index()].start_byte == offset
                })
                .expect("positioned package path segment");
            assert_eq!(reference.namespace, ResolutionNamespace::TypeOrValue);
            let site = &facts.sites[reference.site.index()];
            assert_eq!(
                site.kind,
                if name == "scala" {
                    ResolutionSiteKind::ImportQualifierReference
                } else {
                    ResolutionSiteKind::MemberReference
                },
            );
            assert_eq!(source.get(site.start_byte..site.end_byte), Some(name));
        }
    }

    #[test]
    fn scala_import_paths_and_selector_sources_have_positioned_references() {
        let source = "package app\n\
                     import scala.collection.mutable\n\
                     import scala.collection.{immutable => imm}\n\
                     import java.util._\n";
        let parsed = parse(source);
        let facts = &parsed.resolution_facts;
        for (name, offset, namespace) in [
            (
                "scala",
                source.find("import scala").expect("first package root") + "import ".len(),
                ResolutionNamespace::TypeOrValue,
            ),
            (
                "collection",
                source.find("collection").expect("first package segment"),
                ResolutionNamespace::TypeOrValue,
            ),
            (
                "mutable",
                source.find("mutable").expect("direct import target"),
                ResolutionNamespace::TypeOrValue,
            ),
            (
                "immutable",
                source.find("immutable").expect("selector source"),
                ResolutionNamespace::TypeOrValue,
            ),
        ] {
            let reference = facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Reference
                        && identifier.namespace == namespace
                        && facts.names[identifier.name.index()].spelling == name
                        && facts.sites[identifier.site.index()].start_byte == offset
                })
                .unwrap_or_else(|| panic!("missing positioned import reference for {name}"));
            let site = &facts.sites[reference.site.index()];
            assert_eq!(
                site.kind,
                if name == "scala" {
                    ResolutionSiteKind::ImportQualifierReference
                } else {
                    ResolutionSiteKind::MemberReference
                },
            );
            assert_eq!(source.get(site.start_byte..site.end_byte), Some(name));
            assert!(
                facts
                    .reference_owners
                    .iter()
                    .any(|owner| owner.reference == reference.site)
            );
        }
        let selector = facts
            .import_selectors
            .iter()
            .find(|selector| {
                selector
                    .local_name
                    .is_some_and(|name| facts.names[name.index()].spelling == "imm")
            })
            .expect("renamed import selector");
        assert_eq!(selector.kind, ResolutionImportSelectorKind::Named);
        assert_eq!(
            selector
                .source_name
                .map(|name| facts.names[name.index()].spelling.as_str()),
            Some("immutable")
        );
        assert!(
            facts
                .root_imports
                .iter()
                .any(|import| import.site == selector.site && import.position.is_some())
        );
        assert!(facts.import_routes.iter().any(|route| {
            route.site == selector.site
                && route
                    .bound_name
                    .is_some_and(|name| facts.names[name.index()].spelling == "imm")
        }));
        for namespace in [
            ResolutionNamespace::Type,
            ResolutionNamespace::Value,
            ResolutionNamespace::Callable,
        ] {
            assert!(facts.root_import_demands.iter().any(|demand| {
                demand.import_site == selector.site
                    && demand.namespace == namespace
                    && facts.names[demand.name.index()].spelling == "immutable"
            }));
        }
        assert!(facts.import_routes.iter().all(|route| {
            !facts.gaps.iter().any(|gap| {
                gap.site == route.site && gap.kind == ResolutionGapKind::UnsupportedRoute
            })
        }));
    }

    #[test]
    fn scala_exported_type_selectors_publish_source_alias_members() {
        let source = "package library\n\
                     object Facade {\n\
                       object Core {\n\
                         class kept\n\
                         class hidden\n\
                         class original\n\
                       }\n\
                       export Core.{hidden as _, original as renamed, *}\n\
                     }\n";
        let parsed = parse(source);
        let facts = &parsed.resolution_facts;
        let source_facts = parsed.source_facts.as_ref().expect("Scala source facts");
        let declaration = |name: &str, kind: ResolutionSiteKind| {
            facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Declaration
                        && facts.names[identifier.name.index()].spelling == name
                        && facts.sites[identifier.site.index()].kind == kind
                })
                .map(|identifier| identifier.site)
                .unwrap_or_else(|| panic!("missing {kind:?} declaration {name}"))
        };
        let original = declaration("original", ResolutionSiteKind::TypeDeclaration);
        let renamed = declaration("renamed", ResolutionSiteKind::TypeAliasDeclaration);
        let kept = declaration("kept", ResolutionSiteKind::TypeAliasDeclaration);
        let hidden_aliases = facts.identifiers.iter().filter(|identifier| {
            identifier.role == ResolutionIdentifierRole::Declaration
                && facts.names[identifier.name.index()].spelling == "hidden"
                && facts.sites[identifier.site.index()].kind
                    == ResolutionSiteKind::TypeAliasDeclaration
        });
        assert_eq!(hidden_aliases.count(), 0);

        let source_declaration = |site| {
            source_facts
                .native_declaration_sources
                .iter()
                .find_map(|(candidate, declaration)| (*candidate == site).then_some(*declaration))
                .expect("type alias has a source declaration bridge")
        };
        assert_eq!(source_declaration(renamed), source_declaration(original));
        assert!(
            !facts
                .definition_units
                .iter()
                .any(|unit| { unit.declaration == renamed || unit.declaration == kept })
        );

        let facade = declaration("Facade", ResolutionSiteKind::TypeDeclaration);
        for alias in [renamed, kept] {
            assert!(facts.member_owners.iter().any(|owner| {
                owner.member == alias
                    && owner.owner == facade
                    && owner.kind == ResolutionMemberKind::AssociatedType
            }));
            assert!(facts.type_transfers.iter().any(|transfer| {
                transfer.kind == ResolutionTypeTransferKind::TypeAlias
                    && transfer.output
                        == facts
                            .type_slots
                            .iter()
                            .find(|slot| {
                                slot.site == alias
                                    && slot.role == ResolutionTypeSlotRole::TargetTypeIdentity
                            })
                            .expect("alias identity slot")
                            .id
            }));
        }
        let export_start = source.find("export Core").expect("export declaration");
        assert!(!facts.gaps.iter().any(|gap| {
            gap.kind == ResolutionGapKind::UnsupportedRoute
                && facts.sites[gap.site.index()].start_byte == export_start
        }));
    }

    #[test]
    fn scala_exports_publish_jvm_forwarder_aliases() {
        let source = "package library\n\
                     object Facade {\n\
                       object Core {\n\
                         def run(value: Int): Int = value\n\
                         val value = 1\n\
                         var count = 0\n\
                       }\n\
                       export Core.{run as forwarded, value as copied, count as forwardedCount}\n\
                     }\n";
        let parsed = parse(source);
        let facts = &parsed.resolution_facts;
        for (member_name, kind, parameter_count) in [
            ("forwarded", ResolutionJvmAliasKind::Method, 1),
            ("copied", ResolutionJvmAliasKind::Getter, 0),
            ("forwardedCount", ResolutionJvmAliasKind::Getter, 0),
            ("forwardedCount_$eq", ResolutionJvmAliasKind::Setter, 1),
        ] {
            let name = facts
                .names
                .iter()
                .find(|name| name.spelling == member_name)
                .unwrap_or_else(|| {
                    panic!(
                        "missing JVM alias name {member_name}; names={:?}; members={:?}",
                        facts
                            .names
                            .iter()
                            .map(|name| name.spelling.as_str())
                            .collect::<Vec<_>>(),
                        facts
                            .member_owners
                            .iter()
                            .map(|owner| (owner.member, owner.owner))
                            .collect::<Vec<_>>()
                    )
                })
                .id;
            let alias = facts
                .jvm_aliases
                .iter()
                .find(|alias| alias.member_name == name && alias.kind == kind)
                .expect("export JVM alias fact");
            assert!(!alias.is_static);
            assert_eq!(alias.parameter_count, parameter_count);
            assert_eq!(alias.status, ResolutionJvmAliasStatus::SourceProven);
            let owner = facts
                .jvm_alias_owner_segments
                .iter()
                .filter(|segment| segment.alias == alias.id)
                .map(|segment| {
                    (
                        segment.ordinal,
                        facts.names[segment.name.index()].spelling.as_str(),
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(owner, [(0, "library"), (1, "Facade$")]);
        }
        let export_start = source.find("export Core").expect("export declaration");
        assert!(!facts.gaps.iter().any(|gap| {
            gap.kind == ResolutionGapKind::UnsupportedRoute
                && facts.sites[gap.site.index()].start_byte == export_start
        }));
    }

    #[test]
    #[hardwon("#5015: destructured locals omitted unknown incoming values before reassignment")]
    fn destructured_local_inputs_do_not_copy_the_tuple_or_gap_static_bindings() {
        let parsed = parse(
            "class Box\nobject Inputs {\n\
             var (field, fieldNumber) = (new Box, 0)\n\
             def use(parameter: Box): Unit = {\n\
             var (current, n) = ((new Box): Box, 0)\n\
             current = new Box\n\
             var direct: Box = new Box\n\
             var pending: Box\n}\n}\n",
        );
        let facts = &parsed.resolution_facts;
        for name in ["current", "n", "direct", "pending", "field", "parameter"] {
            let declaration = facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Declaration
                        && facts.names[identifier.name.index()].spelling == name
                })
                .expect("binding declaration")
                .site;
            let observations = facts
                .type_transfers
                .iter()
                .filter(|row| {
                    row.kind == ResolutionTypeTransferKind::Assignment
                        && facts.type_slots[row.output.index()].site == declaration
                })
                .collect::<Vec<_>>();
            assert!(!facts.gaps.iter().any(|gap| gap.site == declaration));
            if matches!(name, "current" | "n") {
                assert_eq!(observations.len(), 1, "{name}: {observations:?}");
                let input = observations[0].input;
                let incoming = facts.type_slots[input.index()].site;
                assert_ne!(incoming, declaration);
                assert_eq!(
                    facts.type_slots[observations[0].output.index()].role,
                    ResolutionTypeSlotRole::AssignmentValue
                );
                assert!(facts.gaps.contains(&ResolutionGapFact::new(
                    incoming,
                    ResolutionGapKind::InferredType
                )));
                assert!(!facts.type_transfers.iter().any(|row| row.output == input));
            } else if name == "direct" {
                assert_eq!(observations.len(), 1);
                let incoming = facts.type_slots[observations[0].input.index()].site;
                assert!(!facts.gaps.iter().any(|gap| gap.site == incoming));
            } else {
                assert!(observations.is_empty(), "{name}: {observations:?}");
            }
            if matches!(name, "direct" | "pending" | "parameter") {
                let declared = facts
                    .declaration_type_slots
                    .iter()
                    .find(|row| row.declaration == declaration)
                    .expect("written type keeps its declared slot");
                assert!(facts.type_transfers.iter().any(|row| {
                    row.output == declared.slot
                        && row.kind == ResolutionTypeTransferKind::DeclaredType
                }));
            }
        }
    }

    #[test]
    fn scala_named_givens_use_callable_routes_and_anonymous_gaps_stay_local() {
        let source = "package app\n\
                     object GivenOwner {\n\
                       given namedGiven: Int = 1\n\
                       given String = \"value\"\n\
                     }\n";
        let parsed = parse(source);
        let facts = &parsed.resolution_facts;
        let named = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.names[identifier.name.index()].spelling == "namedGiven"
            })
            .expect("named given declaration");
        assert_eq!(
            facts.sites[named.site.index()].kind,
            ResolutionSiteKind::CallableDeclaration
        );
        assert!(facts.binders.iter().any(|binder| {
            binder.declaration == named.site && binder.kind == ResolutionBinderKind::Callable
        }));
        assert!(
            facts
                .definition_units
                .iter()
                .any(|unit| { unit.declaration == named.site && unit.unit.is_function() })
        );
        assert!(!facts.gaps.iter().any(|gap| {
            gap.site == named.site && gap.kind == ResolutionGapKind::UnsupportedRoute
        }));

        let owner = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.names[identifier.name.index()].spelling == "GivenOwner"
            })
            .expect("enclosing top-level object");
        assert!(!facts.gaps.iter().any(|gap| {
            gap.site == owner.site && gap.kind == ResolutionGapKind::UnsupportedRoute
        }));

        // The anonymous given is declared under the name the compiler gives
        // it. Its omitted binder opens lookups of that name only, never the
        // fragment.
        let synthesized = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.names[identifier.name.index()].spelling == "given_String"
            })
            .expect("anonymous given declaration");
        assert_eq!(
            facts.sites[synthesized.site.index()].kind,
            ResolutionSiteKind::CallableDeclaration
        );
        assert!(facts.binders.iter().any(|binder| {
            binder.declaration == synthesized.site && binder.kind == ResolutionBinderKind::Callable
        }));
        assert!(facts.gaps.iter().any(|gap| {
            gap.site == synthesized.site && gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder
        }));
        assert!(
            facts
                .gaps
                .iter()
                .all(|gap| gap.kind != ResolutionGapKind::UnsupportedRoute)
        );
    }

    #[test]
    fn scala_anonymous_given_names_follow_the_compiler_rule() {
        let source = "object Givens {\n\
                        given Context = new Context {}\n\
                        given Ord[Int] with { def x = 1 }\n\
                        given Ord[List[Int]] = ???\n\
                        given [T](using Ord[T]): Ord[List[T]] = ???\n\
                        given (Int, String) = ???\n\
                        given a.b.Foo = ???\n\
                        given Foo(using x) with { }\n\
                        given A | B = ???\n\
                        given named: Ord[Int] = ???\n\
                      }\n";
        let parsed = parse(source);
        let facts = &parsed.resolution_facts;
        let declared = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.sites[identifier.site.index()].kind
                        == ResolutionSiteKind::CallableDeclaration
            })
            .map(|identifier| facts.names[identifier.name.index()].spelling.as_str())
            .collect::<Vec<_>>();
        for expected in [
            "given_Context",
            "given_Ord_Int",
            "given_Ord_List",
            "given_Int_String",
            "given_Foo",
            "named",
        ] {
            assert!(declared.contains(&expected), "{expected} in {declared:?}");
        }
        // A symbolic infix operator is encoded by the compiler; the binder is
        // left unnamed and holds its whole scope open.
        let infix_start = source.find("given A | B").expect("infix given");
        let unnamed = facts
            .sites
            .iter()
            .find(|site| site.start_byte == infix_start)
            .expect("unnamed given site");
        assert_eq!(unnamed.kind, ResolutionSiteKind::UnsupportedDeclaration);
        assert!(facts.gaps.iter().any(|gap| {
            gap.site == unnamed.id && gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder
        }));
    }

    #[test]
    fn scala_package_references_respect_lexical_import_scope_and_activation() {
        let parsed = parse(
            "package sample\n\
             object Consumer {\n\
               val before: Remote = null\n\
               import elsewhere.Remote\n\
               val after: Remote = null\n\
             }\n\
             object Other { val remote: Remote = null }\n",
        );
        let facts = &parsed.resolution_facts;
        let references = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                let reference = &facts.sites[identifier.site.index()];
                identifier.role == ResolutionIdentifierRole::Reference
                    && facts.names[identifier.name.index()].spelling == "Remote"
                    && !facts.sites.iter().any(|site| {
                        site.kind == ResolutionSiteKind::ImportDeclaration
                            && site.start_byte <= reference.start_byte
                            && reference.end_byte <= site.end_byte
                    })
                    && facts.sites[identifier.site.index()].kind
                        == ResolutionSiteKind::TypeReference
            })
            .map(|identifier| identifier.site)
            .collect::<Vec<_>>();
        assert_eq!(references.len(), 3, "references={references:?}");
        let package_references = facts
            .package_references
            .iter()
            .map(|reference| reference.reference)
            .collect::<Vec<_>>();
        assert!(package_references.contains(&references[0]));
        assert!(!package_references.contains(&references[1]));
        assert!(package_references.contains(&references[2]));
    }

    #[test]
    fn scala_resolution_lowers_patterns_lambdas_type_parameters_and_shape_gaps() {
        let source = concat!(
            "package demo\n",
            "trait Bound\n",
            "trait Extra\n",
            "case class Pair(first: String, second: String)\n",
            "class Box[+A <: Bound] extends Bound with Extra { self: Extra =>\n",
            "  def combine(first: String)(last: String = \"x\"): String = first + last\n",
            "  def convert[T >: Bound <: Extra](left: T)(right: String = \"x\"): String = {\n",
            "    val matched = left match { case item if item.nonEmpty => item; case _ => \"fallback\" }\n",
            "    val extracted = left match { case Pair(first, second) => first; case _ => left }\n",
            "    val repeated = left match { case Pair(rest*) => rest; case _ => left }\n",
            "    val generated = for (value <- List(matched)) yield value\n",
            "    val render = (subject: T) => s\"$subject:${left}\"\n",
            "    val combined = combine(left)(last = \"y\")\n",
            "    render(generated.head)\n",
            "  }\n",
            "}\n",
            "object Box\n",
            "object Contextual {\n",
            "  import scala.concurrent.Future\n",
            "  def usingParam(using context: Bound): Unit = ()\n",
            "  def implicitParam(implicit context: Bound): Unit = ()\n",
            "}\n",
            "extension (value: Bound) { def extended: String = s\"$value\" }\n",
            "package inner { class Nested }\n",
            "package object legacy { val exported: Int = 1; object ExportedObject }\n",
        );
        let parsed = parse(source);
        let facts = &parsed.resolution_facts;
        let declaration_named = |name: &str| {
            facts.identifiers.iter().find_map(|identifier| {
                (identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.names[identifier.name.index()].spelling == name)
                    .then_some(identifier.site)
            })
        };
        let references_named = |name: &str| {
            facts
                .identifiers
                .iter()
                .filter(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Reference
                        && facts.names[identifier.name.index()].spelling == name
                })
                .map(|identifier| identifier.site)
                .collect::<Vec<_>>()
        };
        let binder_named = |name: &str| {
            declaration_named(name).and_then(|declaration| {
                facts
                    .binders
                    .iter()
                    .find(|binder| binder.declaration == declaration)
            })
        };

        for name in ["A", "T"] {
            let binder = binder_named(name).expect("type parameter binder");
            assert_eq!(binder.kind, ResolutionBinderKind::Type, "name={name}");
            assert!(facts.declaration_type_slots.iter().any(|slot| {
                slot.declaration == binder.declaration && slot.role == DeclarationTypeRole::Identity
            }));
        }
        let convert = declaration_named("convert").expect("generic callable declaration");
        let generic_formals = facts
            .generic_formals
            .iter()
            .filter(|formal| formal.owner == convert)
            .collect::<Vec<_>>();
        assert_eq!(generic_formals.len(), 1);
        assert_eq!(generic_formals[0].ordinal, 0);
        assert_eq!(
            facts.names[facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.site == generic_formals[0].parameter
                        && identifier.role == ResolutionIdentifierRole::Declaration
                })
                .expect("generic formal has declaration name")
                .name
                .index()]
            .spelling,
            "T"
        );
        assert!(
            references_named("Bound").len() >= 3,
            "type bounds and annotations"
        );
        for name in ["item", "value"] {
            assert_eq!(
                binder_named(name).expect("pattern or for binder").kind,
                ResolutionBinderKind::Pattern,
                "name={name}"
            );
            assert!(!references_named(name).is_empty(), "binder use {name}");
        }
        assert_eq!(
            binder_named("subject").expect("lambda parameter").kind,
            ResolutionBinderKind::Parameter
        );
        let lambda_parameter = binder_named("subject").unwrap();
        assert_eq!(
            facts.scopes[lambda_parameter.scope.index()].kind,
            ResolutionScopeKind::Executable
        );
        assert!(
            !facts
                .callable_parameters
                .iter()
                .any(|parameter| parameter.parameter == lambda_parameter.declaration),
            "anonymous lambdas have lexical binders but no named-callable row"
        );
        assert!(!references_named("subject").is_empty());
        assert!(
            !references_named("left").is_empty(),
            "interpolation reference"
        );

        let convert = declaration_named("convert").expect("curried method");
        assert_eq!(
            facts
                .callable_signatures
                .iter()
                .find(|signature| signature.callable == convert)
                .expect("method signature")
                .type_parameter_count,
            1
        );
        assert!(
            facts
                .callable_parameter_lists
                .iter()
                .any(|list| { list.callable == convert && list.list_ordinal == 1 })
        );
        let combine = declaration_named("combine").expect("curried callable");
        assert!(
            facts
                .callable_parameter_lists
                .iter()
                .any(|list| { list.callable == combine && list.list_ordinal == 1 })
        );
        assert!(facts.callable_parameter_semantics.iter().any(|semantics| {
            semantics.callable == combine
                && facts.names[semantics.label.index()].spelling == "last"
                && semantics.list_ordinal == 1
                && semantics.has_default
        }));
        let combined_call = facts
            .calls
            .iter()
            .find(|call| {
                call.callee
                    == facts
                        .identifiers
                        .iter()
                        .find_map(|identifier| {
                            (identifier.role == ResolutionIdentifierRole::Reference
                                && facts.names[identifier.name.index()].spelling == "combine")
                                .then_some(identifier.site)
                        })
                        .expect("combine call reference")
            })
            .expect("curried combine call");
        let combined_lists = facts
            .call_argument_lists
            .iter()
            .filter(|list| list.call == combined_call.call)
            .collect::<Vec<_>>();
        assert_eq!(combined_lists.len(), 2, "curried lists={combined_lists:?}");
        assert!(facts.call_arguments.iter().any(|argument| {
            argument.call == combined_call.call
                && argument.list_ordinal == 1
                && argument
                    .label
                    .is_some_and(|label| facts.names[label.index()].spelling == "last")
        }));
        let box_type = declaration_named("Box").expect("class or companion declaration");
        let pair_type = declaration_named("Pair").expect("case class declaration");
        let pair_companion = facts
            .singleton_relations
            .iter()
            .find(|relation| {
                relation.kind == ResolutionSingletonRelationKind::Companion
                    && relation.enclosing_type == Some(pair_type)
            })
            .map(|relation| relation.declaration)
            .expect("a case class has a distinct companion");
        assert!(!facts.gaps.iter().any(|gap| {
            matches!(gap.route(), Some(ResolutionRouteGap::UnknownAlias { owner: ResolutionRouteOwner::Declaration(owner), .. }) if owner == pair_type)
        }));
        assert_ne!(pair_type, pair_companion);
        let visibility_of = |declaration| {
            facts
                .declaration_visibilities
                .iter()
                .find(|visibility| visibility.declaration == declaration)
                .expect("a class and its real companion declare visibility")
                .visibility
        };
        assert_eq!(visibility_of(pair_companion), visibility_of(pair_type));
        assert!(facts.additional_definition_namespaces.iter().all(|fact| {
            fact.declaration != pair_type
                || !matches!(
                    fact.namespace,
                    ResolutionNamespace::Value | ResolutionNamespace::Callable
                )
        }));
        assert!(facts.identifiers.iter().any(|identifier| {
            identifier.site == pair_companion
                && identifier.role == ResolutionIdentifierRole::Declaration
                && identifier.namespace == ResolutionNamespace::Value
        }));
        assert!(facts.additional_definition_namespaces.iter().any(|fact| {
            fact.declaration == pair_companion && fact.namespace == ResolutionNamespace::Value
        }));
        for (member, parameter_count) in [("apply", 2), ("unapply", 1)] {
            assert!(
                facts.jvm_aliases.iter().any(|alias| {
                    facts.member_owners.iter().any(|owner| {
                        owner.member == alias.declaration && owner.owner == pair_companion
                    }) && alias.kind == ResolutionJvmAliasKind::Method
                        && facts.names[alias.member_name.index()].spelling == member
                        && alias.parameter_count == parameter_count
                        && alias.status == ResolutionJvmAliasStatus::CompilerModeDependent
                }),
                "missing alias {member}/{parameter_count}; aliases={:#?}",
                facts.jvm_aliases
            );
        }
        assert!(
            facts
                .supertypes
                .iter()
                .any(|parent| { parent.subtype == box_type && parent.parent_ordinal == 0 })
        );
        assert!(
            facts
                .supertypes
                .iter()
                .any(|parent| { parent.subtype == box_type && parent.parent_ordinal == 1 })
        );
        assert!(facts.singleton_relations.iter().any(|relation| {
            relation.kind == ResolutionSingletonRelationKind::Companion
                && relation.enclosing_type == Some(box_type)
        }));
        let box_object = facts
            .jvm_aliases
            .iter()
            .find(|alias| {
                facts.identifiers.iter().any(|identifier| {
                    identifier.site == alias.declaration
                        && identifier.role == ResolutionIdentifierRole::Declaration
                        && facts.names[identifier.name.index()].spelling == "Box"
                }) && alias.kind == ResolutionJvmAliasKind::SingletonInstance
            })
            .expect("companion object module alias");
        assert_eq!(
            box_object.status,
            ResolutionJvmAliasStatus::CompilerModeDependent
        );
        assert!(!facts.root_exports.iter().any(|export| {
            export.declaration == box_object.declaration
                && export.namespace == ResolutionNamespace::Type
        }));
        assert!(facts.root_exports.iter().any(|export| {
            export.declaration == box_object.declaration
                && export.namespace == ResolutionNamespace::Value
        }));
        assert!(facts.singleton_relations.iter().any(|relation| {
            relation.declaration == box_object.declaration
                && relation.kind == ResolutionSingletonRelationKind::Companion
                && relation.enclosing_type == Some(box_type)
        }));
        assert!(!facts.gaps.iter().any(|gap| {
            gap.site == box_object.declaration && gap.kind == ResolutionGapKind::UnsupportedRoute
        }));
        assert!(facts.extension_receivers.iter().any(|receiver| {
            facts.identifiers.iter().any(|identifier| {
                identifier.site == receiver.callable
                    && identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.names[identifier.name.index()].spelling == "extended"
            })
        }));
        assert!(facts.package_object_exports.iter().any(|export| {
            facts.identifiers.iter().any(|identifier| {
                identifier.site == export.member
                    && identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.names[identifier.name.index()].spelling == "exported"
            })
        }));
        let exported_object = declaration_named("ExportedObject").expect("object member");
        assert!(!facts.package_members.iter().any(|member| {
            member.declaration == exported_object && member.namespace == ResolutionNamespace::Type
        }));
        assert!(facts.package_members.iter().any(|member| {
            member.declaration == exported_object && member.namespace == ResolutionNamespace::Value
        }));
        assert_eq!(
            facts
                .package_object_exports
                .iter()
                .filter(|export| export.member == exported_object)
                .count(),
            1
        );
        let package_object = declaration_named("legacy").expect("package object source identity");
        let package_alias = facts
            .jvm_aliases
            .iter()
            .find(|alias| {
                alias.declaration == package_object
                    && alias.kind == ResolutionJvmAliasKind::SingletonInstance
            })
            .expect("package object module alias");
        assert_eq!(
            package_alias.status,
            ResolutionJvmAliasStatus::CompilerModeDependent
        );
        let mut package_owner_segments = facts
            .jvm_alias_owner_segments
            .iter()
            .filter(|segment| segment.alias == package_alias.id)
            .collect::<Vec<_>>();
        package_owner_segments.sort_unstable_by_key(|segment| segment.ordinal);
        assert_eq!(
            package_owner_segments
                .iter()
                .map(|segment| facts.names[segment.name.index()].spelling.as_str())
                .collect::<Vec<_>>(),
            ["demo", "legacy", "package$"]
        );
        assert!(!facts.gaps.iter().any(|gap| {
            gap.site == package_object && gap.kind == ResolutionGapKind::UnsupportedRoute
        }));
        let source_facts = parsed.source_facts.as_ref().expect("Scala source facts");
        assert!(
            source_facts
                .native_declaration_sources
                .iter()
                .any(|(site, _)| *site == package_object)
        );
        // An extractor pattern's role belongs to its head reference, as a
        // call's belongs to its callee; the pattern keeps a site of its own.
        let extractor_roles = references_named("Pair")
            .into_iter()
            .filter(|head| facts.sites[head.index()].kind != ResolutionSiteKind::SyntheticReference)
            .map(|head| {
                facts
                    .invocation_roles
                    .iter()
                    .find(|invocation| invocation.site == head)
                    .map(|invocation| invocation.role)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            extractor_roles,
            [
                Some(ResolutionInvocationRole::Unapply),
                Some(ResolutionInvocationRole::UnapplySeq)
            ]
        );
        assert!(
            facts
                .sites
                .iter()
                .any(|site| site.kind == ResolutionSiteKind::Pattern)
        );
        assert!(facts.invocation_roles.iter().all(|invocation| {
            facts.sites[invocation.site.index()].kind != ResolutionSiteKind::Pattern
        }));
        // A contextual list binds its named parameter like any other list: the
        // function scope keeps no scope-or-binder gap, and the parameter has a
        // declared type slot. Contextual parameters stay out of the callable's
        // explicit parameter lists, because a call does not write them.
        assert!(!facts.gaps.iter().any(|gap| {
            gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder
                && facts.sites[gap.site.index()].kind == ResolutionSiteKind::UnsupportedDeclaration
                && {
                    let text = &source[facts.sites[gap.site.index()].start_byte
                        ..facts.sites[gap.site.index()].end_byte];
                    text.starts_with("(using") || text.starts_with("(implicit")
                }
        }));
        for parameter in ["context"] {
            let declared = facts
                .identifiers
                .iter()
                .filter(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Declaration
                        && facts.names[identifier.name.index()].spelling == parameter
                })
                .map(|identifier| identifier.site)
                .collect::<Vec<_>>();
            assert_eq!(declared.len(), 2, "usingParam and implicitParam");
            for site in declared {
                assert!(facts.declaration_type_slots.iter().any(|slot| {
                    slot.declaration == site && slot.role == DeclarationTypeRole::Parameter
                }));
            }
        }
        assert!(
            facts
                .import_routes
                .iter()
                .filter(|route| {
                    facts.scopes[route.root_scope.index()].kind == ResolutionScopeKind::TypeBody
                })
                .all(|route| {
                    !facts.gaps.iter().any(|gap| {
                        gap.site == route.site && gap.kind == ResolutionGapKind::UnsupportedRoute
                    })
                })
        );
        assert!(
            facts.packages.len() >= 3,
            "package routes={:?}",
            facts.packages
        );
        assert!(facts.gaps.iter().any(|gap| {
            gap.kind == ResolutionGapKind::UnsupportedCallApplicability
                && facts.sites[gap.site.index()].kind == ResolutionSiteKind::Call
        }));
    }

    #[test]
    fn scala_projected_types_and_qualified_term_patterns_publish_root_routes() {
        let source = concat!(
            "package demo\n",
            "object Outer { case class Item(value: Int); type Alias = String }\n",
            "object Use {\n",
            "  def read(input: Any): Int = input match {\n",
            "    case Outer.Item(value) => value\n",
            "    case Item(value) => value\n",
            "    case _ => 0\n",
            "  }\n",
            "  val projected: Outer#Alias = \"\"\n",
            "}\n",
        );
        let parsed = parse(source);
        let facts = &parsed.resolution_facts;

        let projected_alias = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == ResolutionNamespace::Type
                    && facts.names[identifier.name.index()].spelling == "Alias"
            })
            .expect("projected type reference");
        let route = facts
            .root_references
            .iter()
            .find(|route| route.reference == projected_alias.site)
            .expect("projected type source-owned route");
        assert_eq!(route.anchor, ResolutionRootImportAnchor::Lexical);
        let prefix = route.prefix_reference.expect("lexical Type prefix");
        assert!(facts.identifiers.iter().any(|identifier| {
            identifier.site == prefix
                && identifier.role == ResolutionIdentifierRole::Reference
                && identifier.namespace == ResolutionNamespace::Type
                && facts.names[identifier.name.index()].spelling == "Outer"
        }));
        let route_segments = facts
            .root_reference_segments
            .iter()
            .filter(|segment| segment.reference == projected_alias.site)
            .map(|segment| facts.names[segment.name.index()].spelling.as_str())
            .collect::<Vec<_>>();
        assert_eq!(route_segments, vec!["Outer"]);

        // A qualified extractor head is a type-or-value path: its terminal
        // names a type or a value, and its route continues from a
        // type-or-value prefix that may be a package, an object or a value.
        let pattern_item = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == ResolutionNamespace::TypeOrValue
                    && identifier.qualifier.is_some()
                    && facts.names[identifier.name.index()].spelling == "Item"
            })
            .expect("qualified extractor reference");
        let item_route = facts
            .root_references
            .iter()
            .find(|route| route.reference == pattern_item.site)
            .expect("qualified extractor head publishes its root route");
        let item_prefix = facts
            .identifiers
            .iter()
            .find(|identifier| Some(identifier.site) == item_route.prefix_reference)
            .expect("qualified extractor prefix");
        assert_eq!(item_prefix.namespace, ResolutionNamespace::TypeOrValue);
        assert_eq!(facts.names[item_prefix.name.index()].spelling, "Outer");
        let unqualified_item = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == ResolutionNamespace::TypeOrValue
                    && identifier.qualifier.is_none()
                    && facts.names[identifier.name.index()].spelling == "Item"
            })
            .expect("unqualified extractor reference retains both namespaces");
        assert!(
            !facts
                .root_references
                .iter()
                .any(|route| route.reference == unqualified_item.site)
        );
        let path_has_route_gap = |spelling: &str| {
            let start = source.find(spelling).expect("path fixture");
            let end = start + spelling.len();
            facts.gaps.iter().any(|gap| {
                let site = &facts.sites[gap.site.index()];
                gap.kind == ResolutionGapKind::UnsupportedRoute
                    && site.start_byte < end
                    && start < site.end_byte
            })
        };
        assert!(!path_has_route_gap("Outer.Item"));
        assert!(!path_has_route_gap("Outer#Alias"));
    }

    #[test]
    fn scala_nested_objects_publish_their_compiler_dependent_module_aliases() {
        let parsed = parse(
            "package example\n\
             object Outer {\n\
               object Inner\n\
               class Container { object Child }\n\
             }\n",
        );
        let facts = &parsed.resolution_facts;
        let declaration_named = |name: &str| {
            facts.identifiers.iter().find_map(|identifier| {
                (identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.names[identifier.name.index()].spelling == name)
                    .then_some(identifier.site)
            })
        };
        let owner_segments = |name: &str| {
            let declaration = declaration_named(name).expect("object declaration");
            let alias = facts
                .jvm_aliases
                .iter()
                .find(|alias| {
                    alias.declaration == declaration
                        && alias.kind == ResolutionJvmAliasKind::SingletonInstance
                })
                .expect("singleton module alias");
            assert_eq!(facts.names[alias.member_name.index()].spelling, "MODULE$");
            assert_eq!(
                alias.status,
                ResolutionJvmAliasStatus::CompilerModeDependent
            );
            let mut segments = facts
                .jvm_alias_owner_segments
                .iter()
                .filter(|segment| segment.alias == alias.id)
                .collect::<Vec<_>>();
            segments.sort_unstable_by_key(|segment| segment.ordinal);
            segments
                .into_iter()
                .map(|segment| facts.names[segment.name.index()].spelling.as_str())
                .collect::<Vec<_>>()
        };
        assert_eq!(owner_segments("Outer"), ["example", "Outer$"]);
        assert_eq!(owner_segments("Inner"), ["example", "Outer$Inner$"]);
        assert_eq!(
            owner_segments("Child"),
            ["example", "Outer$Container$Child$"]
        );
        for name in ["Inner", "Child"] {
            let declaration = declaration_named(name).expect("nested object declaration");
            assert!(!facts.gaps.iter().any(|gap| {
                gap.site == declaration && gap.kind == ResolutionGapKind::UnsupportedRoute
            }));
        }
    }

    #[test]
    fn scala_trait_source_routes_remain_complete_with_compiler_scoped_jvm_aliases() {
        let parsed = parse(
            "package example\n\
             trait Codec {\n\
               def read(input: Byte): Int\n\
               def write(value: Int): Int = value\n\
               def +(other: Codec): Codec = other\n\
               val version: Int = 1\n\
               var count: Int\n\
             }\n\
             object Outer {\n\
               trait Nested { def encode(value: Int): Int = value }\n\
               case class NestedCase(value: Int)\n\
             }\n",
        );
        let facts = &parsed.resolution_facts;
        let declaration_named = |name: &str| {
            facts.identifiers.iter().find_map(|identifier| {
                (identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.names[identifier.name.index()].spelling == name)
                    .then_some(identifier.site)
            })
        };
        let alias_for = |declaration, kind| {
            facts
                .jvm_aliases
                .iter()
                .find(|alias| alias.declaration == declaration && alias.kind == kind)
                .expect("expected Scala trait JVM alias")
        };
        let owner_segments = |alias: &ResolutionJvmAliasFact| {
            let mut segments = facts
                .jvm_alias_owner_segments
                .iter()
                .filter(|segment| segment.alias == alias.id)
                .collect::<Vec<_>>();
            segments.sort_unstable_by_key(|segment| segment.ordinal);
            segments
                .into_iter()
                .map(|segment| facts.names[segment.name.index()].spelling.as_str())
                .collect::<Vec<_>>()
        };

        let codec = declaration_named("Codec").expect("trait declaration");
        assert!(
            !facts.gaps.iter().any(|gap| {
                gap.site == codec && gap.kind == ResolutionGapKind::UnsupportedRoute
            })
        );

        let read = declaration_named("read").expect("abstract trait method");
        let read_alias = alias_for(read, ResolutionJvmAliasKind::Method);
        assert_eq!(read_alias.status, ResolutionJvmAliasStatus::SourceProven);
        assert!(!read_alias.is_static);
        assert_eq!(read_alias.parameter_count, 1);
        assert_eq!(owner_segments(read_alias), ["example", "Codec"]);

        let write = declaration_named("write").expect("concrete trait method");
        let write_aliases = facts
            .jvm_aliases
            .iter()
            .filter(|alias| {
                alias.declaration == write && alias.kind == ResolutionJvmAliasKind::Method
            })
            .collect::<Vec<_>>();
        assert_eq!(write_aliases.len(), 2);
        let interface = write_aliases
            .iter()
            .find(|alias| !alias.is_static)
            .expect("interface method alias");
        assert_eq!(interface.status, ResolutionJvmAliasStatus::SourceProven);
        assert_eq!(interface.parameter_count, 1);
        assert_eq!(owner_segments(interface), ["example", "Codec"]);
        let legacy = write_aliases
            .iter()
            .find(|alias| alias.is_static)
            .expect("legacy implementation alias");
        assert_eq!(
            legacy.status,
            ResolutionJvmAliasStatus::CompilerModeDependent
        );
        assert_eq!(legacy.parameter_count, 2);
        assert_eq!(owner_segments(legacy), ["example", "Codec$class"]);

        let operator = declaration_named("+").expect("symbolic method declaration");
        let operator_alias = alias_for(operator, ResolutionJvmAliasKind::Method);
        assert_eq!(
            facts.names[operator_alias.member_name.index()].spelling,
            "$plus"
        );

        let version = declaration_named("version").expect("initialized trait val");
        assert!(facts.jvm_aliases.iter().any(|alias| {
            alias.declaration == version
                && alias.kind == ResolutionJvmAliasKind::Getter
                && alias.status == ResolutionJvmAliasStatus::SourceProven
                && owner_segments(alias) == ["example", "Codec"]
        }));
        assert!(facts.jvm_aliases.iter().any(|alias| {
            alias.declaration == codec
                && alias.kind == ResolutionJvmAliasKind::Method
                && facts.names[alias.member_name.index()].spelling == "$init$"
                && alias.status == ResolutionJvmAliasStatus::CompilerModeDependent
                && alias.parameter_count == 1
                && owner_segments(alias) == ["example", "Codec$class"]
        }));

        let nested = declaration_named("Nested").expect("nested trait declaration");
        assert!(
            !facts.gaps.iter().any(|gap| {
                gap.site == nested && gap.kind == ResolutionGapKind::UnsupportedRoute
            })
        );
        let encode = declaration_named("encode").expect("nested trait method");
        let encode_alias = alias_for(encode, ResolutionJvmAliasKind::Method);
        assert_eq!(owner_segments(encode_alias), ["example", "Outer$Nested"]);

        let nested_case = declaration_named("NestedCase").expect("nested case class");
        let nested_companion = facts
            .singleton_relations
            .iter()
            .find(|relation| {
                relation.kind == ResolutionSingletonRelationKind::Companion
                    && relation.enclosing_type == Some(nested_case)
            })
            .map(|relation| relation.declaration)
            .expect("a nested case class has a distinct companion");
        assert!(!facts.gaps.iter().any(|gap| {
            matches!(gap.route(), Some(ResolutionRouteGap::UnknownAlias { owner: ResolutionRouteOwner::Declaration(owner), .. }) if owner == nested_case)
        }));
        assert!(facts.additional_definition_namespaces.iter().any(|fact| {
            fact.declaration == nested_companion && fact.namespace == ResolutionNamespace::Value
        }));
        let nested_apply = facts
            .jvm_aliases
            .iter()
            .find(|alias| {
                facts.member_owners.iter().any(|owner| {
                    owner.member == alias.declaration && owner.owner == nested_companion
                }) && alias.kind == ResolutionJvmAliasKind::Method
                    && facts.names[alias.member_name.index()].spelling == "apply"
            })
            .expect("nested case class companion apply alias");
        assert_eq!(
            owner_segments(nested_apply),
            ["example", "Outer$NestedCase$"]
        );
    }
}
