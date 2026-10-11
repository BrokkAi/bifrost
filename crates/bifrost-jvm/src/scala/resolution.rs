//! Scala lowering for file-local, target-independent resolution facts.
//!
//! The walk records source declarations and references only. Binding across
//! files, contextual search, parent linearization and compiler-generated JVM
//! names remain selected-context work or explicit gaps.

use brokk_bifrost_core::analyzer::Range;
use brokk_bifrost_core::analyzer::model::CodeUnit;
use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
use brokk_bifrost_core::analyzer::resolution_facts::{
    BindingProjectionFact, BindingProjectionKind, DeclarationTypeRole, DeclarationTypeSlotFact,
    FileResolutionFacts, PositionedIdentifierFact, ResolutionAdditionalDefinitionNamespaceFact,
    ResolutionBinderFact, ResolutionBinderKind, ResolutionCallArgumentListFact, ResolutionCallFact,
    ResolutionCallableParameterFact, ResolutionCallableParameterListFact,
    ResolutionCallableParameterSemanticsFact, ResolutionCallableReceiverOrigin,
    ResolutionCallableReceiverOriginFact, ResolutionCallableSignatureFact,
    ResolutionDeclarationVisibilityFact, ResolutionDefinitionUnitFact, ResolutionGapFact,
    ResolutionGapKind, ResolutionIdentifierRole, ResolutionImportRouteFact,
    ResolutionImportRouteKind, ResolutionImportRouteSegmentFact, ResolutionImportSelectorFact,
    ResolutionImportSelectorKind, ResolutionInvocationRole, ResolutionInvocationRoleFact,
    ResolutionJvmAliasFact, ResolutionJvmAliasId, ResolutionJvmAliasKind,
    ResolutionJvmAliasOwnerSegmentFact, ResolutionJvmAliasStatus, ResolutionMemberAccess,
    ResolutionMemberKind, ResolutionMemberOwnerFact, ResolutionMemberQualifierCompatibility,
    ResolutionNameFact, ResolutionNameId, ResolutionNamedArgumentLabelFact, ResolutionNamespace,
    ResolutionPackageFact, ResolutionPackageObjectExportFact, ResolutionPackageSegmentFact,
    ResolutionReferenceEnumerationGapFact, ResolutionReferenceOwnerFact, ResolutionRootExportFact,
    ResolutionRootImportAnchor, ResolutionRootImportDemandFact, ResolutionRootImportDemandTarget,
    ResolutionRootImportDemandTargetFact, ResolutionRootImportFact, ResolutionRootImportKind,
    ResolutionRootImportKindFact, ResolutionRootImportSegmentFact, ResolutionRootReferenceFact,
    ResolutionRootReferenceSegmentFact, ResolutionScopeFact, ResolutionScopeId,
    ResolutionScopeInheritance, ResolutionScopeKind, ResolutionSingletonRelationFact,
    ResolutionSingletonRelationKind, ResolutionSiteFact, ResolutionSiteId, ResolutionSiteKind,
    ResolutionSupertypeFact, ResolutionSupertypeKind, ResolutionTypeSlotFact, ResolutionTypeSlotId,
    ResolutionTypeSlotRole, ResolutionTypeTransferFact, ResolutionTypeTransferKind,
    ResolutionTypeTransferValueTransform,
};
use brokk_bifrost_core::analyzer::source_facts::{
    PrimarySourceFactCollector, SourceDeclarationId, SourceOccurrenceId,
};
use brokk_bifrost_core::analyzer::structural::adapter_helpers::field_name_in_parent;
use brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceRole;
use brokk_bifrost_core::analyzer::structural::resolution::{
    BindingKind, DeclaredVisibility, HoistingClass,
};
use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;
use brokk_bifrost_core::analyzer::tree_walk::{expression_target_node, node_range};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use tree_sitter::Node;

use crate::scala::imports::scala_export_info_from_node;
use crate::scala::structural::{SCALA_STRUCTURAL_SPEC, scala_occurrence_role};
use crate::scala::supertypes::scala_supertype_lookup_nodes;

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
    path: &'nodes [Node<'tree>],
    source: Option<Node<'tree>>,
    local: Option<Node<'tree>>,
    star: bool,
    activation_start: usize,
}

struct ScalaResolutionBuilder<'a, 'source> {
    source: &'source str,
    collector: &'a mut PrimarySourceFactCollector<'source>,
    facts: FileResolutionFacts,
    site_occurrences: Vec<SourceOccurrenceId>,
    declaration_sources: Vec<(ResolutionSiteId, SourceDeclarationId)>,
    name_ids: HashMap<String, ResolutionNameId>,
    claimed_definition_units: HashSet<CodeUnit>,
    sites_by_node: HashMap<usize, ResolutionSiteId>,
    declaration_sites: HashMap<usize, ResolutionSiteId>,
    declaration_nodes: HashMap<ResolutionSiteId, Node<'source>>,
    package_declarations: HashMap<usize, ResolutionSiteId>,
    scopes_by_node: HashMap<usize, ResolutionScopeId>,
    package_objects: Vec<(ResolutionSiteId, ResolutionScopeId)>,
    receiver_slots_by_node: HashMap<usize, ResolutionTypeSlotId>,
    call_result_slots_by_node: HashMap<usize, ResolutionTypeSlotId>,
    qualified_type_prefixes: HashMap<usize, ResolutionSiteId>,
    parameter_list_ordinals: HashMap<usize, u32>,
    scope_ranges: Vec<Range>,
    next_parameter_ordinal: HashMap<ResolutionSiteId, u32>,
    pending_callable_parameter_types: Vec<(ResolutionSiteId, ResolutionTypeSlotId, Node<'source>)>,
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
        claimed_definition_units: HashSet::default(),
        sites_by_node: HashMap::default(),
        declaration_sites: HashMap::default(),
        declaration_nodes: HashMap::default(),
        package_declarations: HashMap::default(),
        scopes_by_node: HashMap::default(),
        package_objects: Vec::new(),
        receiver_slots_by_node: HashMap::default(),
        call_result_slots_by_node: HashMap::default(),
        qualified_type_prefixes: HashMap::default(),
        parameter_list_ordinals: HashMap::default(),
        scope_ranges: vec![node_range(root)],
        next_parameter_ordinal: HashMap::default(),
        pending_callable_parameter_types: Vec::new(),
        wildcard_imports: Vec::new(),
        root_scope,
        placement_site,
    };
    let placement_site = builder.add_site(root, ResolutionSiteKind::UnsupportedRoute, root_scope);
    assert_eq!(placement_site, builder.placement_site);
    // Package membership, import precedence, and unqualified package requests
    // are published as source-owned facts and joined by selected context.
    builder.walk(root, parsed, source_declarations);
    builder.finish_callable_parameter_types();
    builder.finish_callable_result_types(root);
    builder.finish_import_demands();
    builder.finish_packages(root);
    builder.finish_supertypes(root);
    builder.finish_calls(root);
    builder.finish_shape_dependent_gaps(root);
    builder.validate();
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
        while let Some(item) = stack.pop() {
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

            if node.kind() == "call_expression" || node.kind() == "infix_expression" {
                let curried_function = node.kind() == "call_expression"
                    && node.parent().is_some_and(|parent| {
                        parent.kind() == "call_expression"
                            && field_name_in_parent(parent, node) == Some("function")
                    });
                // Scala parses later argument lists of `new C(first)(second)`
                // as a call_expression over the instance_expression. The
                // constructor call-shape owns those lists; treating this node
                // as an ordinary call descends into the first argument and
                // mistakes its callee for the constructed value's callee.
                let constructor_argument_list = node.kind() == "call_expression"
                    && node
                        .child_by_field_name("function")
                        .is_some_and(|function| function.kind() == "instance_expression");
                if !curried_function && !constructor_argument_list {
                    self.add_site(node, ResolutionSiteKind::Call, item.scope);
                }
            }
            if node.kind() == "implicit_parameter" || node.kind() == "context_bound" {
                let site =
                    self.add_site(node, ResolutionSiteKind::UnsupportedDeclaration, item.scope);
                self.gap(site, ResolutionGapKind::UnsupportedScopeOrBinder);
            }
            if node.kind() == "parameters" && has_contextual_parameter_marker(node) {
                let site =
                    self.add_site(node, ResolutionSiteKind::UnsupportedDeclaration, item.scope);
                self.gap(site, ResolutionGapKind::UnsupportedScopeOrBinder);
            }
            if node.kind() == "self_type" {
                let site =
                    self.add_site(node, ResolutionSiteKind::UnsupportedDeclaration, item.scope);
                self.gap(site, ResolutionGapKind::UnsupportedScopeOrBinder);
                self.facts
                    .reference_enumeration_gaps
                    .push(ResolutionReferenceEnumerationGapFact {
                        site,
                        kind: ResolutionGapKind::UnsupportedScopeOrBinder,
                    });
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
        let (kind, namespace, binder, member_kind) = match node.kind() {
            "class_definition" | "trait_definition" | "object_definition" | "enum_definition"
            | "full_enum_case" | "package_object" => (
                ResolutionSiteKind::TypeDeclaration,
                ResolutionNamespace::Type,
                Some(ResolutionBinderKind::Type),
                Some(ResolutionMemberKind::NestedType),
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
            "val_definition" | "var_definition" | "val_declaration" | "var_declaration" => (
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
        let site = self.add_site(node, kind, scope);
        self.declaration_sites.insert(node.id(), site);
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
                            "function_definition" | "function_declaration" | "given_definition" => {
                                unit.is_function()
                            }
                            "val_definition" | "var_definition" | "val_declaration"
                            | "var_declaration" => unit.is_field(),
                            _ => false,
                        };
                        matches_declaration_kind.then_some(unit)
                    });
                if let Some(unit) = unit
                    && self.claimed_definition_units.insert(unit.clone())
                {
                    self.facts
                        .definition_units
                        .push(ResolutionDefinitionUnitFact {
                            declaration: site,
                            unit: unit.clone(),
                        });
                }
                // Only an alias publishes an identity slot: its value arrives
                // through a transfer. A nominal type has none, so a reference
                // to it projects the declaration itself as the type object.
                if node.kind() == "type_definition" {
                    let slot = self.add_slot(site, ResolutionTypeSlotRole::TargetTypeIdentity);
                    self.facts
                        .declaration_type_slots
                        .push(DeclarationTypeSlotFact {
                            declaration: site,
                            slot,
                            role: DeclarationTypeRole::Identity,
                        });
                }
                let visibility_eligible = namespace == ResolutionNamespace::Type
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
        }
        Some(site)
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
        } else if node.kind() == "class_definition"
            && has_case_modifier(node)
            && !scala_has_companion_object(node, self.source)
        {
            self.facts.additional_definition_namespaces.extend(
                [ResolutionNamespace::Value, ResolutionNamespace::Callable].map(|namespace| {
                    ResolutionAdditionalDefinitionNamespaceFact {
                        declaration: site,
                        namespace,
                        hoisting,
                    }
                }),
            );
        }
        if let Some(type_owner) = type_owner
            && let Some(member_kind) = member_kind
            && self.scope(scope).kind == ResolutionScopeKind::TypeBody
        {
            let (access, compatibility) = if member_kind == ResolutionMemberKind::NestedType {
                (
                    ResolutionMemberAccess::Type,
                    ResolutionMemberQualifierCompatibility::TypeOnly,
                )
            } else {
                (
                    ResolutionMemberAccess::Instance,
                    ResolutionMemberQualifierCompatibility::RuntimeOnly,
                )
            };
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
            if node.kind() == "object_definition" {
                self.facts.root_exports.push(ResolutionRootExportFact {
                    root_scope: scope,
                    declaration: site,
                    namespace: ResolutionNamespace::Value,
                });
            }
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
                    });
            }
        }
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
                self.gap(route, ResolutionGapKind::UnsupportedRoute);
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
        let mut qualifier = receiver.map(|receiver| {
            self.expression_slot(receiver, scope, ResolutionTypeSlotRole::Receiver)
        });
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
        let mut qualified_prefix = None;
        let mut kind = kind;
        if let Some(segments) = qualified_route_segments {
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
        let site = self.add_site(node, kind, scope);
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
        if receiver.is_some()
            && let Some(qualifier) = qualifier
        {
            self.receiver_slots_by_node.insert(node.id(), qualifier);
        }
        if namespace == ResolutionNamespace::Type
            || (qualified_segments.is_some() && namespace == ResolutionNamespace::TypeOrValue)
        {
            self.projected_identity_slot(site, namespace);
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
                    origin: scala_callable_receiver_origin(node),
                });
        }
        if role == OccurrenceRole::PatternPosition
            && let Some((pattern, invocation)) = pattern_invocation(node)
        {
            let pattern_site = self.add_site(pattern, ResolutionSiteKind::Pattern, scope);
            self.facts
                .invocation_roles
                .push(ResolutionInvocationRoleFact {
                    site: pattern_site,
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
        }
        self.facts.binders.push(ResolutionBinderFact {
            declaration: site,
            scope,
            kind,
            hoisting: activation.hoisting,
            activation_start: activation.activation.start_byte,
            activation_end: activation.activation.end_byte,
        });
        if kind == ResolutionBinderKind::Field
            && let Some(type_owner) = type_owner
            && self.scope(scope).kind == ResolutionScopeKind::TypeBody
        {
            self.facts.member_owners.push(ResolutionMemberOwnerFact {
                member: site,
                owner: type_owner,
                kind: ResolutionMemberKind::Field,
                access: ResolutionMemberAccess::Instance,
                qualifier_compatibility: ResolutionMemberQualifierCompatibility::RuntimeOnly,
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
            let value_type = self.add_slot(site, ResolutionTypeSlotRole::DeclaredValue);
            self.facts
                .declaration_type_slots
                .push(DeclarationTypeSlotFact {
                    declaration: site,
                    slot: value_type,
                    role: DeclarationTypeRole::Parameter,
                });
            if let Some(type_node) = declaration_node.child_by_field_name("type") {
                self.pending_callable_parameter_types
                    .push((site, value_type, type_node));
            }
            self.facts
                .callable_parameters
                .push(ResolutionCallableParameterFact {
                    callable,
                    list_ordinal,
                    ordinal,
                    parameter: site,
                    value_type,
                    repeated: contains_kind(declaration_node, "repeated_parameter_type"),
                });
            let label = self.intern_name(node_text(node, self.source));
            self.facts.callable_parameter_semantics.push(
                ResolutionCallableParameterSemanticsFact {
                    callable,
                    parameter: site,
                    list_ordinal,
                    ordinal,
                    label,
                    has_default: has_field_descendant(declaration_node, "default_value"),
                },
            );
            self.next_parameter_ordinal.insert(
                callable,
                ordinal
                    .checked_add(1)
                    .expect("Scala parameter count fits u32"),
            );
        }
    }

    fn lower_import(&mut self, node: Node<'source>, scope: ResolutionScopeId) {
        let clauses = import_clauses(node);
        if clauses.is_empty() {
            let site = self.add_site(node, ResolutionSiteKind::ImportDeclaration, scope);
            self.gap(site, ResolutionGapKind::UnsupportedRoute);
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
                        self.gap(site, ResolutionGapKind::UnsupportedRoute);
                        self.facts.reference_enumeration_gaps.push(
                            ResolutionReferenceEnumerationGapFact {
                                site,
                                kind: ResolutionGapKind::UnsupportedRoute,
                            },
                        );
                        continue;
                    }
                    self.publish_import_route(ScalaImportRoute {
                        site,
                        scope,
                        anchor: root_anchor,
                        path: &path,
                        source,
                        local,
                        star,
                        activation_start: node.end_byte(),
                    });
                    if let Some(source) = source {
                        self.publish_import_reference(
                            source,
                            scope,
                            if source.kind() == "type_identifier" {
                                ResolutionNamespace::Type
                            } else {
                                ResolutionNamespace::TypeOrValue
                            },
                        );
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
                for segment in &path {
                    self.publish_import_reference(
                        *segment,
                        scope,
                        if segment.kind() == "type_identifier" {
                            ResolutionNamespace::Type
                        } else {
                            ResolutionNamespace::Package
                        },
                    );
                }
                continue;
            }
            if path.is_empty() {
                let site = self.add_site(node, ResolutionSiteKind::ImportDeclaration, scope);
                self.gap(site, ResolutionGapKind::UnsupportedRoute);
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
            let site = self.add_site_distinct(node, ResolutionSiteKind::ImportDeclaration, scope);
            self.publish_import_route(ScalaImportRoute {
                site,
                scope,
                anchor: root_anchor,
                path: route_prefix,
                source: Some(target),
                local: Some(target),
                star: false,
                activation_start: node.end_byte(),
            });
            for segment in &path {
                self.publish_import_reference(
                    *segment,
                    scope,
                    if segment.kind() == "type_identifier" {
                        ResolutionNamespace::Type
                    } else {
                        ResolutionNamespace::Package
                    },
                );
            }
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
        let mut names = path
            .iter()
            .map(|segment| self.intern_name(node_text(*segment, self.source)))
            .collect::<Vec<_>>();
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
            // A name bound by its own spelling is reached by the import's
            // positioned root route alone, which shadows the scope's outward
            // lookup from its position. A renamed import binds a name the
            // route does not spell, so only a binder can introduce it; imports
            // are order sensitive, and a partial scope-wide binder is the
            // activation lowering refuses, which keeps the name incomplete.
            if source.is_some_and(|source| source.id() != local.id()) {
                let binder_site = self.add_site(local, ResolutionSiteKind::ValueDeclaration, scope);
                self.identifier(
                    binder_site,
                    local,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                    None,
                );
                let range = node_range(local);
                self.facts.binders.push(ResolutionBinderFact {
                    declaration: binder_site,
                    scope,
                    kind: ResolutionBinderKind::Import,
                    hoisting: HoistingClass::ScopeWide,
                    activation_start: range.start_byte,
                    activation_end: self.scope(scope).end_byte,
                });
                self.facts.additional_definition_namespaces.extend([
                    ResolutionAdditionalDefinitionNamespaceFact {
                        declaration: binder_site,
                        namespace: ResolutionNamespace::Type,
                        hoisting: HoistingClass::ScopeWide,
                    },
                    ResolutionAdditionalDefinitionNamespaceFact {
                        declaration: binder_site,
                        namespace: ResolutionNamespace::Callable,
                        hoisting: HoistingClass::ScopeWide,
                    },
                ]);
            }
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
        node: Node<'source>,
        scope: ResolutionScopeId,
        namespace: ResolutionNamespace,
    ) {
        let kind = if namespace == ResolutionNamespace::Type {
            ResolutionSiteKind::TypeReference
        } else {
            ResolutionSiteKind::ValueReference
        };
        let reference = self.add_site_distinct(node, kind, scope);
        self.identifier(
            reference,
            node,
            ResolutionIdentifierRole::Reference,
            namespace,
            None,
        );
        self.facts
            .reference_owners
            .push(ResolutionReferenceOwnerFact {
                reference,
                owner: self.declaration_owner(self.scope(scope).owner),
            });
        if namespace == ResolutionNamespace::Type {
            let output = self.add_slot(reference, ResolutionTypeSlotRole::TargetTypeIdentity);
            self.facts.binding_projections.push(BindingProjectionFact {
                reference,
                output,
                kind: BindingProjectionKind::TargetTypeIdentity,
            });
        }
    }

    fn finish_import_demands(&mut self) {
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
                let namespaces = match reference.namespace {
                    ResolutionNamespace::TypeOrValue => vec![
                        ResolutionNamespace::Type,
                        ResolutionNamespace::Value,
                        ResolutionNamespace::Callable,
                    ],
                    ResolutionNamespace::Package => vec![
                        ResolutionNamespace::Package,
                        ResolutionNamespace::Type,
                        ResolutionNamespace::Value,
                        ResolutionNamespace::Callable,
                    ],
                    namespace => vec![namespace],
                };
                for namespace in namespaces {
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
        let kind = match node.kind() {
            "package_clause" if node.child_by_field_name("body").is_some() => Some((
                ResolutionScopeKind::Package,
                ResolutionScopeInheritance::Root,
            )),
            "package_object" => Some((
                ResolutionScopeKind::Package,
                ResolutionScopeInheritance::Root,
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
            owner: self.declaration_sites.get(&node.id()).copied().or(owner),
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
        let child_owner = self.declaration_sites.get(&node.id()).copied().or(owner);
        let child_type_owner = if is_type_declaration(node.kind()) {
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
        let references = crate::package_lookup::source_owned_package_references(
            &self.facts,
            |identifier, _| identifier.qualifier.is_none(),
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
            let Some(subtype) = self.declaration_sites.get(&node.id()).copied() else {
                continue;
            };
            if !is_type_declaration(node.kind()) {
                continue;
            }
            let parents = scala_supertype_lookup_nodes(node);
            let has_parents = !parents.is_empty();
            for (ordinal, (owner, lookup)) in parents.into_iter().enumerate() {
                let Some(terminal) = terminal_identifier(lookup) else {
                    self.gap(subtype, ResolutionGapKind::UnsupportedTypeSyntax);
                    continue;
                };
                let Some(reference) = self.sites_by_node.get(&terminal.id()).copied() else {
                    self.gap(subtype, ResolutionGapKind::UnsupportedTypeSyntax);
                    continue;
                };
                let slot = self.add_slot(reference, ResolutionTypeSlotRole::TargetTypeIdentity);
                self.facts.binding_projections.push(BindingProjectionFact {
                    reference,
                    output: slot,
                    kind: BindingProjectionKind::TargetTypeIdentity,
                });
                self.facts.supertypes.push(ResolutionSupertypeFact {
                    subtype,
                    parent_ordinal: u32::try_from(ordinal).expect("Scala parent count fits u32"),
                    supertype_reference: reference,
                    supertype_slot: slot,
                    kind: if ordinal == 0 && node.kind() == "class_definition" {
                        ResolutionSupertypeKind::Superclass
                    } else {
                        ResolutionSupertypeKind::Interface
                    },
                });
                let _ = owner;
            }
            if has_parents {
                self.gap(subtype, ResolutionGapKind::UnsupportedHierarchyTraversal);
            }
        }
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
            if !matches!(node.kind(), "call_expression" | "infix_expression") {
                continue;
            }
            let Some(call) = self.sites_by_node.get(&node.id()).copied() else {
                continue;
            };
            let mut application_nodes = Vec::new();
            let mut function = if node.kind() == "call_expression" {
                let mut function = node.child_by_field_name("function");
                application_nodes.push(node);
                while let Some(inner) = function.filter(|inner| inner.kind() == "call_expression") {
                    application_nodes.push(inner);
                    function = inner.child_by_field_name("function");
                }
                function
            } else {
                application_nodes.push(node);
                node.child_by_field_name("operator")
            };
            application_nodes.reverse();
            let Some(function) = function.take() else {
                self.gap(call, ResolutionGapKind::UnsupportedCallApplicability);
                continue;
            };
            let Some(callee_node) = terminal_identifier(function) else {
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
            let receiver_node = if node.kind() == "infix_expression" {
                node.child_by_field_name("left")
            } else {
                function
                    .child_by_field_name("value")
                    .filter(|_| function.kind() == "field_expression")
            };
            let call_scope = self.facts.sites[call.index()].scope;
            let receiver = receiver_node.map(|receiver_node| {
                let input = self.expression_slot(
                    receiver_node,
                    call_scope,
                    ResolutionTypeSlotRole::ExpressionValue,
                );
                let output = self.add_slot(call, ResolutionTypeSlotRole::Receiver);
                self.add_call_input_transfer(input, output, ResolutionTypeTransferKind::Receiver);
                output
            });
            let result = self.add_slot(call, ResolutionTypeSlotRole::CallResult);
            assert!(
                self.call_result_slots_by_node
                    .insert(node.id(), result)
                    .is_none(),
                "one call result slot per Scala call expression"
            );
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
            let mut argument_ordinal = 0u32;
            for (list_ordinal, application) in application_nodes.into_iter().enumerate() {
                let list_ordinal =
                    u32::try_from(list_ordinal).expect("Scala call argument-list count fits u32");
                self.facts
                    .call_argument_lists
                    .push(ResolutionCallArgumentListFact { call, list_ordinal });
                let arguments = if application.kind() == "infix_expression" {
                    application
                        .child_by_field_name("right")
                        .into_iter()
                        .collect::<Vec<_>>()
                } else {
                    let Some(arguments) = application.child_by_field_name("arguments") else {
                        self.gap(call, ResolutionGapKind::UnsupportedCallApplicability);
                        continue;
                    };
                    if arguments.kind() == "arguments" {
                        let mut cursor = arguments.walk();
                        arguments.named_children(&mut cursor).collect::<Vec<_>>()
                    } else {
                        vec![arguments]
                    }
                };
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
                    let argument_input = argument_value.map(|value| {
                        self.expression_slot(
                            value,
                            call_scope,
                            ResolutionTypeSlotRole::ExpressionValue,
                        )
                    });
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
            self.facts.calls.push(ResolutionCallFact {
                call,
                callee,
                receiver,
                result,
                extra_result_slots: Vec::new(),
                explicit_type_argument_count: 0,
            });
        }
    }

    fn finish_callable_parameter_types(&mut self) {
        for (declaration, output, type_node) in
            std::mem::take(&mut self.pending_callable_parameter_types)
        {
            let input = scala_callable_result_type_head(type_node)
                .and_then(|head| self.sites_by_node.get(&head.id()).copied())
                .and_then(|reference| {
                    self.facts
                        .binding_projections
                        .iter()
                        .find(|projection| {
                            projection.reference == reference
                                && projection.kind == BindingProjectionKind::TargetTypeIdentity
                        })
                        .map(|projection| projection.output)
                });
            if let Some(input) = input {
                crate::call_arguments::publish_jvm_declared_type_transfer(
                    &mut self.facts,
                    input,
                    output,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                );
            } else {
                self.gap(declaration, ResolutionGapKind::UnsupportedTypeSyntax);
            }
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
            let input = scala_callable_result_type_head(return_type)
                .and_then(|head| self.sites_by_node.get(&head.id()).copied())
                .and_then(|reference| {
                    self.facts
                        .binding_projections
                        .iter()
                        .find(|projection| {
                            projection.reference == reference
                                && projection.kind == BindingProjectionKind::TargetTypeIdentity
                        })
                        .map(|projection| projection.output)
                })
                .unwrap_or_else(|| {
                    let scope = self.facts.sites[callable.index()].scope;
                    let type_site =
                        self.add_site(return_type, ResolutionSiteKind::TypeReference, scope);
                    self.gap(type_site, ResolutionGapKind::UnsupportedTypeSyntax);
                    self.add_slot(type_site, ResolutionTypeSlotRole::TargetTypeIdentity)
                });
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
                                        "class_definition" | "trait_definition"
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
                    self.gap(site, ResolutionGapKind::UnsupportedRoute);
                }
            } else if node.kind() == "object_definition"
                && let Some(name) = declaration_name(node)
                && self.scope(self.facts.sites[site.index()].scope).kind
                    == ResolutionScopeKind::TypeBody
            {
                let scope = self.facts.sites[site.index()].scope;
                if !self.add_object_module_alias(site, name, scope) {
                    self.gap(site, ResolutionGapKind::UnsupportedRoute);
                }
            } else if node.kind() == "object_definition" {
                self.gap(site, ResolutionGapKind::UnsupportedRoute);
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
        self.gap(site, ResolutionGapKind::UnsupportedRoute);
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
            let kind = if qualifier.is_some() {
                ResolutionSiteKind::MemberReference
            } else {
                ResolutionSiteKind::TypeReference
            };
            let site = self.add_site(*segment, kind, scope);
            self.identifier(
                site,
                *segment,
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Type,
                qualifier,
            );
            let output =
                self.reference_identity_slot(site, Some(exporter), ResolutionNamespace::Type);
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
    /// whichever it is.
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
            ResolutionNamespace::TypeOrValue => (
                ResolutionTypeSlotRole::ExpressionValue,
                BindingProjectionKind::TargetTypeOrDeclaredValueType,
            ),
            _ => unreachable!("a qualified path segment is a type or a type-or-value name"),
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

    fn add_case_class_companion_aliases(
        &mut self,
        node: Node<'source>,
        declaration: ResolutionSiteId,
    ) {
        if scala_has_companion_object(node, self.source) {
            return;
        }
        let name = declaration_name(node).expect("named Scala case class declaration");
        let scope = self.facts.sites[declaration.index()].scope;
        let Some(owner_segments) = self.jvm_type_owner_segments(scope, name, "$") else {
            self.gap(declaration, ResolutionGapKind::UnsupportedRoute);
            return;
        };
        let apply_name = self.intern_name("apply");
        let apply_parameters = scala_case_class_parameter_count(node);
        self.add_jvm_alias(
            declaration,
            apply_name,
            ResolutionJvmAliasKind::Method,
            false,
            apply_parameters,
            ResolutionJvmAliasStatus::CompilerModeDependent,
            owner_segments.clone(),
        );
        let unapply = if scala_case_class_has_repeated_parameter(node) {
            "unapplySeq"
        } else {
            "unapply"
        };
        let unapply_name = self.intern_name(unapply);
        self.add_jvm_alias(
            declaration,
            unapply_name,
            ResolutionJvmAliasKind::Method,
            false,
            1,
            ResolutionJvmAliasStatus::CompilerModeDependent,
            owner_segments,
        );
    }

    fn jvm_type_owner_segments(
        &mut self,
        scope: ResolutionScopeId,
        name: Node<'source>,
        suffix: &str,
    ) -> Option<Vec<ResolutionNameId>> {
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
            if self.facts.sites[owner_site.index()].kind != ResolutionSiteKind::TypeDeclaration {
                break;
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

    fn lower_extension_receivers(&mut self, extension: Node<'source>) {
        let mut cursor = extension.walk();
        let Some(parameters) = extension
            .children_by_field_name("parameters", &mut cursor)
            .find(|parameters| parameters.kind() == "parameters")
        else {
            let site = self.add_site(
                extension,
                ResolutionSiteKind::UnsupportedRoute,
                self.facts.scopes[0].id,
            );
            self.gap(site, ResolutionGapKind::UnsupportedRoute);
            return;
        };
        let mut cursor = parameters.walk();
        let receiver_parameter = parameters
            .named_children(&mut cursor)
            .find(|child| matches!(child.kind(), "parameter" | "class_parameter"));
        let receiver_type = receiver_parameter
            .and_then(|parameter| parameter.child_by_field_name("type"))
            .and_then(terminal_identifier)
            .and_then(|terminal| self.sites_by_node.get(&terminal.id()).copied())
            .and_then(|reference| {
                self.facts
                    .binding_projections
                    .iter()
                    .find_map(|projection| {
                        (projection.reference == reference
                            && projection.kind == BindingProjectionKind::TargetTypeIdentity)
                            .then_some(projection.output)
                    })
            });
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
            let scope = self
                .scopes_by_node
                .get(&extension.id())
                .copied()
                .unwrap_or(self.root_scope);
            let site = self.add_site(extension, ResolutionSiteKind::UnsupportedRoute, scope);
            self.gap(site, ResolutionGapKind::UnsupportedRoute);
            self.facts
                .reference_enumeration_gaps
                .push(ResolutionReferenceEnumerationGapFact {
                    site,
                    kind: ResolutionGapKind::UnsupportedRoute,
                });
        }
    }

    fn expression_slot(
        &mut self,
        node: Node<'source>,
        scope: ResolutionScopeId,
        role: ResolutionTypeSlotRole,
    ) -> ResolutionTypeSlotId {
        if let Some(slot) = self.call_result_slots_by_node.get(&node.id()) {
            return *slot;
        }
        // A selection `owner.member` denotes the value of its selected member
        // reference, so its value is that reference's site.
        let selected_member = (node.kind() == "field_expression")
            .then(|| node.child_by_field_name("field"))
            .flatten()
            .and_then(|field| self.sites_by_node.get(&field.id()).copied());
        let site = if let Some(site) = self.sites_by_node.get(&node.id()).copied() {
            site
        } else if let Some(site) = selected_member {
            site
        } else {
            let site = self.add_site(node, ResolutionSiteKind::UnsupportedExpression, scope);
            self.gap(site, ResolutionGapKind::InferredType);
            site
        };
        if let Some(slot) = self.receiver_slots_by_node.get(&node.id()) {
            return *slot;
        }
        // The selected member's own projected value is the selection's value.
        // A fresh slot on the same site would have no producer and no values.
        if let Some(member) = selected_member
            && let Some(projected) = self.facts.binding_projections.iter().find(|projection| {
                projection.reference == member
                    && projection.kind == BindingProjectionKind::TargetTypeOrDeclaredValueType
            })
        {
            let slot = projected.output;
            self.receiver_slots_by_node.insert(node.id(), slot);
            return slot;
        }
        let slot = self.add_slot(site, role);
        self.receiver_slots_by_node.insert(node.id(), slot);
        slot
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
    /// head is an ordinary reference that shadows the package reading: a Type
    /// reference for a type path, a type-or-value reference for a term path
    /// (an extractor head or a singleton type's stable path). With
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
            let publishes_root = (namespace == ResolutionNamespace::TypeOrValue || !typed_members)
                && anchor == ResolutionRootImportAnchor::Lexical;
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
        if (namespace == ResolutionNamespace::TypeOrValue || !typed_members)
            && anchor == ResolutionRootImportAnchor::Lexical
        {
            self.record_qualified_type_root_reference(
                std::slice::from_ref(&prefix),
                prefix_site,
                scope,
                None,
                segments.len() > 1
                    && (namespace == ResolutionNamespace::TypeOrValue || !typed_members),
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
        self.sites_by_node.entry(node.id()).or_insert(id);
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
        if !self.facts.gaps.contains(&ResolutionGapFact { site, kind }) {
            self.facts.gaps.push(ResolutionGapFact { site, kind });
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
    if node.is_error() || node.is_missing() {
        return None;
    }
    let part = match node.kind() {
        "type_identifier" => node_text(node, source).to_owned(),
        "stable_type_identifier" => {
            let mut cursor = node.walk();
            let last = node
                .named_children(&mut cursor)
                .filter(|child| child.kind() == "type_identifier")
                .last()?;
            node_text(last, source).to_owned()
        }
        "generic_type" => {
            let head = scala_given_type_name(node.child_by_field_name("type")?, source, false)?;
            if !follow_args {
                return Some(head);
            }
            let arguments = node.child_by_field_name("type_arguments")?;
            let mut cursor = arguments.walk();
            let names = arguments
                .named_children(&mut cursor)
                .map(|argument| scala_given_type_name(argument, source, false))
                .collect::<Option<Vec<_>>>()?;
            if names.is_empty() {
                return Some(head);
            }
            format!("{head}_{}", names.join("_"))
        }
        "tuple_type" => {
            let mut cursor = node.walk();
            let names = node
                .named_children(&mut cursor)
                .map(|element| scala_given_type_name(element, source, false))
                .collect::<Option<Vec<_>>>()?;
            names.join("_")
        }
        "infix_type" => {
            let operator = node_text(node.child_by_field_name("operator")?, source).to_owned();
            if !follow_args {
                operator
            } else {
                let left = scala_given_type_name(node.child_by_field_name("left")?, source, false)?;
                let right =
                    scala_given_type_name(node.child_by_field_name("right")?, source, false)?;
                format!("{operator}_{left}_{right}")
            }
        }
        _ => return None,
    };
    // A symbolic operator is encoded by the compiler, so only plain
    // identifier characters name a synthesized part exactly.
    (!part.is_empty() && part.chars().all(|c| c.is_alphanumeric() || c == '_')).then_some(part)
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
    let Some(name) = declaration_name(node) else {
        return false;
    };
    let Some(parent) = node.parent() else {
        return false;
    };
    let mut cursor = parent.walk();
    parent.named_children(&mut cursor).any(|sibling| {
        sibling.kind() == "object_definition"
            && declaration_name(sibling).is_some_and(|sibling_name| {
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

fn is_call_target(node: Node<'_>) -> bool {
    let mut child = node;
    while let Some(parent) = child.parent() {
        if parent.kind() == "call_expression" {
            let is_function = parent
                .child_by_field_name("function")
                .is_some_and(|function| function.id() == child.id());
            return is_function
                && terminal_identifier(child).is_some_and(|terminal| terminal.id() == node.id());
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
        Some(receiver) if receiver.kind() == "this" => {
            ResolutionCallableReceiverOrigin::CurrentInstance
        }
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
        OccurrenceRole::MemberPosition => ResolutionNamespace::TypeOrValue,
        OccurrenceRole::ReceiverPosition
        | OccurrenceRole::ValueReference
        | OccurrenceRole::PatternPosition => ResolutionNamespace::Value,
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
        let mut segments = if is_scala_path_kind(owner_terminal.kind()) {
            scala_path_segments(scala_path_root(owner_terminal)?)?
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
            _ => return None,
        }
    }
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
        let immutable_alias_binder = facts.identifiers.iter().find(|identifier| {
            identifier.role == ResolutionIdentifierRole::Declaration
                && facts.names[identifier.name.index()].spelling == "imm"
        });
        let immutable_alias_binder = immutable_alias_binder.expect("renamed import binder");
        assert_eq!(immutable_alias_binder.namespace, ResolutionNamespace::Value);
        assert!(facts.additional_definition_namespaces.iter().any(|row| {
            row.declaration == immutable_alias_binder.site
                && row.namespace == ResolutionNamespace::Type
        }));
        assert!(facts.additional_definition_namespaces.iter().any(|row| {
            row.declaration == immutable_alias_binder.site
                && row.namespace == ResolutionNamespace::Callable
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
            assert_eq!(reference.namespace, ResolutionNamespace::Package);
            let site = &facts.sites[reference.site.index()];
            assert_eq!(site.kind, ResolutionSiteKind::ValueReference);
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
                ResolutionNamespace::Package,
            ),
            (
                "collection",
                source.find("collection").expect("first package segment"),
                ResolutionNamespace::Package,
            ),
            (
                "mutable",
                source.find("mutable").expect("direct import target"),
                ResolutionNamespace::Package,
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
            assert_eq!(site.kind, ResolutionSiteKind::ValueReference);
            assert_eq!(source.get(site.start_byte..site.end_byte), Some(name));
            assert!(
                facts
                    .reference_owners
                    .iter()
                    .any(|owner| owner.reference == reference.site)
            );
        }
        assert!(facts.identifiers.iter().any(|identifier| {
            identifier.role == ResolutionIdentifierRole::Declaration
                && facts.names[identifier.name.index()].spelling == "imm"
        }));
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
        assert!(!facts.gaps.iter().any(|gap| {
            gap.site == pair_type && gap.kind == ResolutionGapKind::UnsupportedRoute
        }));
        for namespace in [ResolutionNamespace::Value, ResolutionNamespace::Callable] {
            assert!(
                facts
                    .additional_definition_namespaces
                    .iter()
                    .any(|fact| { fact.declaration == pair_type && fact.namespace == namespace })
            );
        }
        for (member, parameter_count) in [("apply", 2), ("unapply", 1)] {
            assert!(
                facts.jvm_aliases.iter().any(|alias| {
                    alias.declaration == pair_type
                        && alias.kind == ResolutionJvmAliasKind::Method
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
        assert!(facts.root_exports.iter().any(|export| {
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
        assert!(facts.gaps.iter().any(|gap| {
            gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder
                && facts.sites[gap.site.index()].kind == ResolutionSiteKind::UnsupportedDeclaration
                && source[facts.sites[gap.site.index()].start_byte
                    ..facts.sites[gap.site.index()].end_byte]
                    .starts_with("self:")
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
        assert!(facts.package_members.iter().any(|member| {
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
        assert!(facts.invocation_roles.iter().any(|invocation| {
            invocation.role == ResolutionInvocationRole::Unapply
                && facts.sites[invocation.site.index()].kind == ResolutionSiteKind::Pattern
        }));
        assert!(facts.invocation_roles.iter().any(|invocation| {
            invocation.role == ResolutionInvocationRole::UnapplySeq
                && facts.sites[invocation.site.index()].kind == ResolutionSiteKind::Pattern
        }));
        assert!(facts.gaps.iter().any(|gap| {
            gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder
                && facts.sites[gap.site.index()].kind == ResolutionSiteKind::UnsupportedDeclaration
                && source[facts.sites[gap.site.index()].start_byte
                    ..facts.sites[gap.site.index()].end_byte]
                    .starts_with("(using")
        }));
        assert!(facts.gaps.iter().any(|gap| {
            gap.kind == ResolutionGapKind::UnsupportedScopeOrBinder
                && facts.sites[gap.site.index()].kind == ResolutionSiteKind::UnsupportedDeclaration
                && source[facts.sites[gap.site.index()].start_byte
                    ..facts.sites[gap.site.index()].end_byte]
                    .starts_with("(implicit")
        }));
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
        assert!(!facts.gaps.iter().any(|gap| {
            gap.site == nested_case && gap.kind == ResolutionGapKind::UnsupportedRoute
        }));
        assert!(facts.additional_definition_namespaces.iter().any(|fact| {
            fact.declaration == nested_case && fact.namespace == ResolutionNamespace::Value
        }));
        let nested_apply = facts
            .jvm_aliases
            .iter()
            .find(|alias| {
                alias.declaration == nested_case
                    && alias.kind == ResolutionJvmAliasKind::Method
                    && facts.names[alias.member_name.index()].spelling == "apply"
            })
            .expect("nested case class companion apply alias");
        assert_eq!(
            owner_segments(nested_apply),
            ["example", "Outer$NestedCase$"]
        );
    }
}
