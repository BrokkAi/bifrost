//! Kotlin's immutable, target-independent resolution facts.
//!
//! This pass consumes the same parsed tree and canonical source collector as
//! [`super::declarations`]. It records source syntax only; selected JVM roots,
//! imports, and cross-file targets belong to the query-time context.

use super::declarations::{
    kotlin_class_like_kind, kotlin_has_modifier, kotlin_identifier_text, kotlin_is_data_class,
};
use super::syntax::{
    KOTLIN_TYPE_NODE_KINDS, KotlinScalarType, kotlin_call_with_callee, kotlin_callee,
    kotlin_declared_scalar_type, kotlin_enclosing_import_header, kotlin_first_token,
    kotlin_import_header_segments, kotlin_is_declaration_name, kotlin_is_navigation_kind,
    kotlin_literal_scalar_type, kotlin_named_argument_label, kotlin_navigation_member,
    kotlin_navigation_receiver, kotlin_owner_label_matches, kotlin_parameter_default,
    kotlin_user_type_segments,
};
use crate::constructor_site::ConstructorSite;
use brokk_bifrost_core::analyzer::model::{CodeUnit, DeclarationKind, ProjectFile};
use brokk_bifrost_core::analyzer::resolution_facts::*;
use brokk_bifrost_core::analyzer::source_facts::{
    PrimarySourceFactCollector, SourceDeclarationId, SourceOccurrenceId,
};
use brokk_bifrost_core::analyzer::structural::resolution::{DeclaredVisibility, HoistingClass};
use brokk_bifrost_core::analyzer::tree_walk::{first_named_child_of_kind, named_children};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use tree_sitter::Node;

pub(super) struct KotlinResolutionExtraction {
    pub facts: FileResolutionFacts,
    pub site_occurrences: Vec<SourceOccurrenceId>,
    pub declaration_sources: Vec<(ResolutionSiteId, SourceDeclarationId)>,
}

#[derive(Clone, Copy)]
struct WalkContext {
    scope: ResolutionScopeId,
    owner_type: Option<ResolutionSiteId>,
    callable: Option<ResolutionSiteId>,
    declaration: Option<ResolutionSiteId>,
    singleton_owner: bool,
    receiver_frame: Option<usize>,
}

/// A receiver introduced by this file's structured declaration walk. The frame
/// is extraction-local; its owner/type already use the existing fact families.
#[derive(Clone, Copy)]
struct KotlinReceiverFrame<'source> {
    parent: Option<usize>,
    label: Option<&'source str>,
    receiver: KotlinReceiver,
}

#[derive(Clone, Copy)]
enum KotlinReceiver {
    // Only source-named classes/objects have a nominal owner type slot.
    Dispatch(ResolutionSiteId),
    AnonymousDispatch(ResolutionSiteId),
    Extension(ResolutionTypeSlotId),
}

struct SyntheticParameter<'source> {
    name: &'source str,
    source: Option<Node<'source>>,
    intrinsic_type: Option<&'source str>,
    optional: bool,
}

#[derive(Default)]
struct KotlinJvmAnnotationProofs {
    explicit_imports: HashMap<String, Option<String>>,
    declared_types: HashSet<String>,
    value_classes: HashSet<String>,
    has_kotlin_jvm_star_import: bool,
    has_other_star_import: bool,
}

impl KotlinJvmAnnotationProofs {
    fn collect(root: Node<'_>, source: &str) -> Self {
        let mut proofs = Self::default();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if node.kind() == "import_header" {
                let path = kotlin_import_header_segments(node)
                    .into_iter()
                    .map(|segment| kotlin_identifier_text(segment, source).to_owned())
                    .collect::<Vec<_>>();
                if first_named_child_of_kind(node, "wildcard_import").is_some() {
                    if path.iter().map(String::as_str).eq(["kotlin", "jvm"]) {
                        proofs.has_kotlin_jvm_star_import = true;
                    } else {
                        proofs.has_other_star_import = true;
                    }
                } else if let Some(imported) = path.last() {
                    let local = first_named_child_of_kind(node, "import_alias")
                        .and_then(|alias| first_named_child_of_kind(alias, "type_identifier"))
                        .map(|alias| kotlin_identifier_text(alias, source).to_owned())
                        .unwrap_or_else(|| imported.clone());
                    let target = path.join(".");
                    if let Some(existing) = proofs.explicit_imports.get(&local) {
                        if existing.as_deref() != Some(target.as_str()) {
                            proofs.explicit_imports.insert(local, None);
                        }
                    } else {
                        proofs.explicit_imports.insert(local, Some(target));
                    }
                }
            }
            if matches!(
                node.kind(),
                "class_declaration" | "object_declaration" | "companion_object" | "type_alias"
            ) && let Some(name) = first_named_child_of_kind(node, "type_identifier")
            {
                let name = kotlin_identifier_text(name, source).to_owned();
                proofs.declared_types.insert(name.clone());
                if node.kind() == "class_declaration" && kotlin_has_modifier(node, "value") {
                    proofs.value_classes.insert(name);
                }
            }
            stack.extend(named_children(node));
        }
        proofs
    }

    fn annotation_denotes(&self, annotation: Node<'_>, expected: &[&str], source: &str) -> bool {
        let expected_path = expected.join(".");
        for user_type in annotation_user_types(annotation) {
            let segments = kotlin_user_type_segments(user_type)
                .into_iter()
                .map(|segment| kotlin_identifier_text(segment, source))
                .collect::<Vec<_>>();
            if segments.iter().copied().eq(expected.iter().copied()) {
                return true;
            }
            if segments.len() != 1 {
                continue;
            }
            let local = segments[0];
            if self.declared_types.contains(local) {
                continue;
            }
            if let Some(imported) = self.explicit_imports.get(local) {
                if imported.as_deref() == Some(expected_path.as_str()) {
                    return true;
                }
                continue;
            }
            if self.has_other_star_import {
                continue;
            }
            if expected.last() == Some(&local)
                && (self.has_kotlin_jvm_star_import || expected.first() == Some(&"kotlin"))
            {
                return true;
            }
        }
        false
    }
}

struct KotlinResolutionBuilder<'source, 'collector, 'declarations> {
    file: &'source ProjectFile,
    source: &'source str,
    collector: &'collector mut PrimarySourceFactCollector<'source>,
    source_declarations: &'declarations HashMap<(usize, Option<usize>), SourceDeclarationId>,
    units: HashMap<SourceDeclarationId, CodeUnit>,
    facts: FileResolutionFacts,
    site_occurrences: Vec<SourceOccurrenceId>,
    declaration_sources: Vec<(ResolutionSiteId, SourceDeclarationId)>,
    names: HashMap<String, ResolutionNameId>,
    sites_by_node: HashMap<usize, ResolutionSiteId>,
    initialization_scopes: HashMap<ResolutionSiteId, ResolutionScopeId>,
    constructor_headers: HashMap<ResolutionSiteId, WalkContext>,
    pending_applied_types: Vec<(
        ResolutionTypeSlotId,
        Node<'source>,
        ResolutionScopeId,
        Option<ResolutionSiteId>,
    )>,
    type_slots_by_node: HashMap<usize, ResolutionTypeSlotId>,
    expression_slots_by_node: HashMap<(usize, ResolutionTypeSlotRole), ResolutionTypeSlotId>,
    type_identity_slots: HashMap<ResolutionSiteId, ResolutionTypeSlotId>,
    receiver_frames: Vec<KotlinReceiverFrame<'source>>,
    anonymous_type_owners: HashSet<ResolutionSiteId>,
    type_sites: HashMap<usize, ResolutionSiteId>,
    type_names: HashMap<ResolutionSiteId, ResolutionNameId>,
    type_simple_names: HashMap<ResolutionSiteId, &'source str>,
    type_parents: HashMap<ResolutionSiteId, Option<ResolutionSiteId>>,
    type_scope_ranges: HashMap<ResolutionSiteId, (usize, usize)>,
    type_scope_parents: HashMap<ResolutionSiteId, ResolutionScopeId>,
    call_result_slots: HashMap<usize, ResolutionTypeSlotId>,
    handled_identifiers: HashSet<usize>,
    next_parameters: HashMap<ResolutionSiteId, u32>,
    scalar_types_by_declaration: HashMap<ResolutionSiteId, KotlinScalarType>,
    unstable_smart_cast_bindings: HashSet<ResolutionSiteId>,
    pending_calls: Vec<(
        Node<'source>,
        ResolutionSiteId,
        ResolutionTypeSlotId,
        WalkContext,
    )>,
    pending_constructor_properties: Vec<(ResolutionSiteId, ResolutionSiteId, bool)>,
    pending_constructor_aliases: Vec<(Node<'source>, ResolutionSiteId, ResolutionScopeId)>,
    pending_constructors: Vec<(ResolutionSiteId, ResolutionSiteId)>,
    /// Declared value slots whose type comes from an initializer or an
    /// expression body, with the expression and its context.
    pending_initializers: Vec<(ResolutionTypeSlotId, Node<'source>, WalkContext)>,
    pending_initializer_values: Vec<(ResolutionTypeSlotId, Node<'source>, WalkContext)>,
    pending_writes: Vec<(Node<'source>, WalkContext)>,
    package_scope: ResolutionScopeId,
    package_names: Vec<ResolutionNameId>,
    facade_name: Option<ResolutionNameId>,
    annotation_proofs: KotlinJvmAnnotationProofs,
    multifile_file: bool,
    interface_types: HashSet<ResolutionSiteId>,
    value_class_types: HashSet<ResolutionSiteId>,
    companion_types: HashSet<ResolutionSiteId>,
    /// Star imports whose root demands wait for the file's references:
    /// the import site and its scope.
    wildcard_imports: Vec<(ResolutionSiteId, ResolutionScopeId)>,
}

pub(super) fn extract_kotlin_resolution<'source>(
    root: Node<'source>,
    file: &'source ProjectFile,
    source: &'source str,
    collector: &mut PrimarySourceFactCollector<'source>,
    source_declarations: &HashMap<(usize, Option<usize>), SourceDeclarationId>,
    source_units: &[(SourceDeclarationId, CodeUnit)],
) -> KotlinResolutionExtraction {
    let builder = KotlinResolutionBuilder {
        file,
        source,
        collector,
        source_declarations,
        units: source_units.iter().cloned().collect(),
        facts: FileResolutionFacts::default(),
        site_occurrences: Vec::new(),
        declaration_sources: Vec::new(),
        names: HashMap::default(),
        sites_by_node: HashMap::default(),
        initialization_scopes: HashMap::default(),
        constructor_headers: HashMap::default(),
        pending_applied_types: Vec::new(),
        type_slots_by_node: HashMap::default(),
        expression_slots_by_node: HashMap::default(),
        type_identity_slots: HashMap::default(),
        receiver_frames: Vec::new(),
        anonymous_type_owners: HashSet::default(),
        type_sites: HashMap::default(),
        type_names: HashMap::default(),
        type_simple_names: HashMap::default(),
        type_parents: HashMap::default(),
        type_scope_ranges: HashMap::default(),
        type_scope_parents: HashMap::default(),
        call_result_slots: HashMap::default(),
        handled_identifiers: HashSet::default(),
        next_parameters: HashMap::default(),
        scalar_types_by_declaration: HashMap::default(),
        unstable_smart_cast_bindings: HashSet::default(),
        pending_calls: Vec::new(),
        pending_constructor_properties: Vec::new(),
        pending_constructor_aliases: Vec::new(),
        pending_constructors: Vec::new(),
        pending_initializers: Vec::new(),
        pending_initializer_values: Vec::new(),
        pending_writes: Vec::new(),
        package_scope: ResolutionScopeId::new(0),
        package_names: Vec::new(),
        facade_name: None,
        annotation_proofs: KotlinJvmAnnotationProofs::default(),
        multifile_file: false,
        interface_types: HashSet::default(),
        value_class_types: HashSet::default(),
        companion_types: HashSet::default(),
        wildcard_imports: Vec::new(),
    };
    builder.extract(root)
}

impl<'source, 'collector, 'declarations>
    KotlinResolutionBuilder<'source, 'collector, 'declarations>
{
    fn extract(mut self, root: Node<'source>) -> KotlinResolutionExtraction {
        let root_scope = self.package_scope;
        self.facts.scopes.push(ResolutionScopeFact {
            id: root_scope,
            parent: None,
            owner: None,
            kind: ResolutionScopeKind::CompilationUnit,
            inheritance: ResolutionScopeInheritance::Lexical,
            start_byte: 0,
            end_byte: self.source.len(),
        });
        let placement = self.add_site(root, ResolutionSiteKind::UnsupportedRoute, root_scope);
        self.facts.gaps.push(ResolutionGapFact::new(
            placement,
            ResolutionGapKind::UnsupportedPlacementBoundary,
        ));
        self.record_package(root, placement);

        let mut stack = vec![(
            root,
            WalkContext {
                scope: root_scope,
                owner_type: None,
                callable: None,
                declaration: None,
                singleton_owner: false,
                receiver_frame: None,
            },
        )];
        while let Some((node, mut context)) = stack.pop() {
            if node.kind() == "delegation_specifier"
                && node
                    .parent()
                    .is_some_and(|parent| parent.kind() == "class_declaration")
                && let Some(header) = context
                    .owner_type
                    .and_then(|owner| self.constructor_headers.get(&owner))
                    .copied()
            {
                context = header;
                // Delegation arguments share the parameter-default environment,
                // which never inherits the class's instance-member scope.
                let scope = &mut self.facts.scopes[context.scope.index()];
                scope.end_byte = scope.end_byte.max(node.end_byte());
            }
            if matches!(node.kind(), "class_body" | "enum_class_body") {
                if node
                    .parent()
                    .is_some_and(|parent| parent.kind() == "object_literal")
                {
                    let owner =
                        self.type_sites[&node.parent().expect("object body has a parent").id()];
                    let frame = self.receiver_frames.len();
                    self.receiver_frames.push(KotlinReceiverFrame {
                        parent: context.receiver_frame,
                        label: None,
                        receiver: KotlinReceiver::AnonymousDispatch(owner),
                    });
                    context.receiver_frame = Some(frame);
                    context.owner_type = Some(owner);
                    context.scope = self.ensure_type_body_scope(owner);
                    context.callable = None;
                    context.declaration = Some(owner);
                    context.singleton_owner = false;
                } else if node
                    .parent()
                    .is_some_and(|parent| parent.kind() == "enum_entry")
                {
                    // Enum-entry overrides are members of the enum class, so
                    // keep them in its canonical type-body scope.
                } else {
                    let body_scope = context.owner_type.and_then(|owner| {
                        self.initialization_scopes.get(&owner).map(|scope| {
                            self.facts.scopes[scope.index()]
                                .parent
                                .expect("a class initialization scope has a type-body parent")
                        })
                    });
                    context.scope = body_scope.unwrap_or_else(|| {
                        self.add_scope(
                            node,
                            context.scope,
                            context.owner_type,
                            ResolutionScopeKind::TypeBody,
                        )
                    });
                }
            } else if node.kind() == "when_expression" {
                context.scope = self.add_scope(
                    node,
                    context.scope,
                    context.callable,
                    ResolutionScopeKind::Block,
                );
            } else if node.kind() == "anonymous_initializer"
                && let Some(scope) = context
                    .owner_type
                    .and_then(|owner| self.initialization_scopes.get(&owner))
            {
                context.scope = *scope;
            } else if matches!(node.kind(), "block" | "statements") {
                context.scope = self.add_scope(
                    node,
                    context.scope,
                    context.callable,
                    if context.callable.is_some() {
                        ResolutionScopeKind::Block
                    } else {
                        ResolutionScopeKind::Initializer
                    },
                );
            } else if node.kind() == "lambda_literal" {
                context.scope =
                    self.add_scope(node, context.scope, None, ResolutionScopeKind::Executable);
                context.callable = None;
                context.declaration = None;
            }

            match node.kind() {
                "import_header" => self.record_import(node, context.scope),
                "object_literal" => {
                    if let Some(body) = first_named_child_of_kind(node, "class_body") {
                        let site =
                            self.add_site(body, ResolutionSiteKind::TypeDeclaration, context.scope);
                        let name =
                            self.intern_name(&crate::anonymous_type::AnonymousTypeBody::name(body));
                        let anonymous = crate::anonymous_type::AnonymousTypeBody { site, name };
                        anonymous.declare(&mut self.facts);
                        assert!(self.anonymous_type_owners.insert(site));
                        anonymous.open_scope(&mut self.facts);
                        self.type_sites.insert(node.id(), site);
                        self.type_scope_ranges
                            .insert(site, (body.start_byte(), body.end_byte()));
                        self.type_scope_parents.insert(site, context.scope);
                    }
                }
                "class_declaration" | "object_declaration" | "companion_object" => {
                    if let Some(site) = self.record_type_declaration(node, context) {
                        let frame = self.receiver_frames.len();
                        self.receiver_frames.push(KotlinReceiverFrame {
                            parent: context.receiver_frame,
                            label: Some(self.type_simple_names[&site]),
                            receiver: KotlinReceiver::Dispatch(site),
                        });
                        context.receiver_frame = Some(frame);
                        context.owner_type = Some(site);
                        context.declaration = Some(site);
                        context.singleton_owner =
                            matches!(node.kind(), "object_declaration" | "companion_object");
                        if node.kind() == "class_declaration"
                            && !self.interface_types.contains(&site)
                            && class_has_zero_parameter_primary_constructor(node)
                        {
                            self.record_default_constructor(node, context);
                        }
                    }
                }
                "type_alias" => {
                    if let Some(site) = self.record_type_alias(node, context) {
                        context.declaration = Some(site);
                    }
                }
                "function_declaration" => {
                    if let Some(site) = self.record_function(node, context) {
                        if let Some(receiver) = self.facts.extension_receivers.last()
                            && receiver.callable == site
                        {
                            let frame = self.receiver_frames.len();
                            self.receiver_frames.push(KotlinReceiverFrame {
                                parent: context.receiver_frame,
                                label: Some(kotlin_identifier_text(
                                    first_named_child_of_kind(node, "simple_identifier")
                                        .expect("a recorded function has a declaration name"),
                                    self.source,
                                )),
                                receiver: KotlinReceiver::Extension(receiver.receiver_type),
                            });
                            context.receiver_frame = Some(frame);
                        }
                        context.callable = Some(site);
                        context.declaration = Some(site);
                        context.scope = self.add_scope(
                            node,
                            context.scope,
                            Some(site),
                            ResolutionScopeKind::Executable,
                        );
                    }
                }
                "primary_constructor" | "secondary_constructor" => {
                    if let Some(site) = self.record_constructor(node, context) {
                        if node.kind() == "primary_constructor"
                            && named_children(node).into_iter().any(|parameter| {
                                parameter.kind() == "class_parameter"
                                    && first_named_child_of_kind(parameter, "binding_pattern_kind")
                                        .is_none()
                            })
                            && let Some(owner) = context.owner_type
                        {
                            self.initialization_scope(owner);
                        }
                        context.callable = Some(site);
                        context.declaration = Some(site);
                        context.scope = self.add_scope(
                            node,
                            context.scope,
                            Some(site),
                            ResolutionScopeKind::Executable,
                        );
                        if node.kind() == "primary_constructor"
                            && let Some(owner) = context.owner_type
                        {
                            self.constructor_headers.insert(owner, context);
                        }
                    }
                }
                "property_declaration" | "when_subject" => self.record_property(node, context),
                "assignment" => self.pending_writes.push((node, context)),
                "prefix_expression" | "postfix_expression"
                    if matches!(kotlin_first_token(node), Some("++" | "--")) =>
                {
                    self.pending_writes.push((node, context));
                }
                "parameter" | "class_parameter" => self.record_parameter(node, context),
                "type_parameter" => self.record_type_parameter(node, context),
                "user_type" => {
                    self.record_user_type(node, context);
                }
                "call_expression" => {
                    let site = self.add_site(node, ResolutionSiteKind::Call, context.scope);
                    self.sites_by_node.insert(node.id(), site);
                    let result = self.add_slot(site, ResolutionTypeSlotRole::CallResult);
                    self.call_result_slots.insert(node.id(), result);
                    self.pending_calls.push((node, site, result, context));
                }
                "check_expression"
                    if node
                        .child(1)
                        .is_some_and(|operator| operator.kind() == "is") => {}
                "check_expression" => {
                    let site = self.add_site(
                        node,
                        ResolutionSiteKind::UnsupportedExpression,
                        context.scope,
                    );
                    self.facts.gaps.push(ResolutionGapFact::new(
                        site,
                        ResolutionGapKind::UnsupportedExpression,
                    ));
                }
                "function_type" => {
                    self.ensure_type_slot(node, context.scope, context.declaration);
                }
                "nullable_type" => {
                    self.record_nullable_type(node, context.scope);
                }
                _ => {}
            }

            let is_this_label = node.kind() == "type_identifier"
                && node
                    .parent()
                    .is_some_and(|parent| parent.kind() == "this_expression");
            if matches!(node.kind(), "simple_identifier" | "type_identifier") && !is_this_label {
                self.record_identifier_reference(node, context);
            }

            let mut children = named_children(node);
            children.reverse();
            let initializer = (node.kind() == "property_declaration"
                && self.type_body_owner(context).is_some())
            .then(|| {
                kotlin_expression_after_equals(node)
                    .or_else(|| first_named_child_of_kind(node, "property_delegate"))
            })
            .flatten();
            for child in children {
                let mut child_context = context;
                if initializer == Some(child)
                    && let Some(scope) = context
                        .owner_type
                        .and_then(|owner| self.initialization_scopes.get(&owner))
                {
                    child_context.scope = *scope;
                }
                stack.push((child, child_context));
            }
        }

        self.finish_synthetic_members(root);
        self.finish_type_body_scopes();
        self.finish_constructor_properties();
        self.finish_constructors();
        self.finish_constructor_aliases();
        self.finish_initializers();
        self.finish_calls();
        self.finish_writes();
        self.finish_smart_casts(root);
        self.finish_import_demands();
        self.finish_supertypes(root);
        self.finish_package_references();
        self.finish_scope_wide_activations();
        self.finish_applied_type_arguments();
        assert_eq!(
            self.site_occurrences.len(),
            self.facts.sites.len(),
            "Kotlin native sites map one-to-one to canonical source occurrences"
        );
        KotlinResolutionExtraction {
            facts: self.facts,
            site_occurrences: self.site_occurrences,
            declaration_sources: self.declaration_sources,
        }
    }

    fn add_scope(
        &mut self,
        node: Node<'_>,
        parent: ResolutionScopeId,
        owner: Option<ResolutionSiteId>,
        kind: ResolutionScopeKind,
    ) -> ResolutionScopeId {
        let id = ResolutionScopeId::try_from_index(self.facts.scopes.len())
            .expect("Kotlin resolution scope count fits u32");
        self.facts.scopes.push(ResolutionScopeFact {
            id,
            parent: Some(parent),
            owner,
            kind,
            inheritance: ResolutionScopeInheritance::Lexical,
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
        });
        id
    }

    fn type_body_owner(&self, context: WalkContext) -> Option<ResolutionSiteId> {
        let scope = self.facts.scopes[context.scope.index()];
        if scope.kind != ResolutionScopeKind::TypeBody {
            return None;
        }
        let owner = scope
            .owner
            .expect("a Kotlin type-body scope has an owning declaration");
        assert_eq!(
            context.owner_type,
            Some(owner),
            "Kotlin type-body context and scope name the same owner"
        );
        Some(owner)
    }

    fn add_site(
        &mut self,
        node: Node<'_>,
        kind: ResolutionSiteKind,
        scope: ResolutionScopeId,
    ) -> ResolutionSiteId {
        let occurrence = self.collector.intern_node(node);
        let id = ResolutionSiteId::try_from_index(self.facts.sites.len())
            .expect("Kotlin resolution site count fits u32");
        self.site_occurrences.push(occurrence);
        self.facts.sites.push(ResolutionSiteFact {
            id,
            scope,
            kind,
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
        });
        id
    }

    fn intern_name(&mut self, spelling: &str) -> ResolutionNameId {
        assert!(!spelling.is_empty(), "Kotlin resolution names are nonempty");
        if let Some(id) = self.names.get(spelling) {
            return *id;
        }
        let id = ResolutionNameId::try_from_index(self.facts.names.len())
            .expect("Kotlin resolution name count fits u32");
        let spelling = spelling.to_owned();
        self.names.insert(spelling.clone(), id);
        self.facts.names.push(ResolutionNameFact { id, spelling });
        id
    }

    fn add_identifier(
        &mut self,
        node: Node<'_>,
        kind: ResolutionSiteKind,
        namespace: ResolutionNamespace,
        role: ResolutionIdentifierRole,
        scope: ResolutionScopeId,
        qualifier: Option<ResolutionTypeSlotId>,
    ) -> ResolutionSiteId {
        let site = self.add_site(node, kind, scope);
        let spelling = kotlin_identifier_text(node, self.source);
        let name = self.intern_name(spelling);
        self.handled_identifiers.insert(node.id());
        self.sites_by_node.insert(node.id(), site);
        self.facts.identifiers.push(PositionedIdentifierFact {
            site,
            name,
            role,
            namespace,
            qualifier,
        });
        site
    }

    fn add_declaration_source(
        &mut self,
        declaration_node: Node<'_>,
        name_node: Option<Node<'_>>,
        site: ResolutionSiteId,
    ) -> SourceDeclarationId {
        let key = (declaration_node.id(), name_node.map(|name| name.id()));
        let source_declaration = self
            .source_declarations
            .get(&key)
            .copied()
            .unwrap_or_else(|| {
                let occurrence = self.collector.intern_node(declaration_node);
                let name = name_node.map(|name| self.collector.intern_node(name));
                self.collector.declare(occurrence, name)
            });
        self.declaration_sources.push((site, source_declaration));
        if let Some(unit) = self.units.get(&source_declaration) {
            self.facts
                .definition_units
                .push(ResolutionDefinitionUnitFact {
                    declaration: site,
                    unit: unit.clone(),
                });
        }
        source_declaration
    }

    fn add_slot(
        &mut self,
        site: ResolutionSiteId,
        role: ResolutionTypeSlotRole,
    ) -> ResolutionTypeSlotId {
        let id = ResolutionTypeSlotId::try_from_index(self.facts.type_slots.len())
            .expect("Kotlin resolution type slot count fits u32");
        self.facts
            .type_slots
            .push(ResolutionTypeSlotFact { id, site, role });
        id
    }

    fn record_package(&mut self, root: Node<'_>, placement: ResolutionSiteId) {
        self.annotation_proofs = KotlinJvmAnnotationProofs::collect(root, self.source);
        self.multifile_file = named_children(root)
            .into_iter()
            .filter(|annotation| annotation.kind() == "file_annotation")
            .any(|annotation| {
                self.annotation_proofs.annotation_denotes(
                    annotation,
                    &["kotlin", "jvm", "JvmMultifileClass"],
                    self.source,
                )
            });
        let file_annotation = named_children(root)
            .into_iter()
            .filter(|child| child.kind() == "file_annotation")
            .find(|annotation| {
                self.annotation_proofs.annotation_denotes(
                    *annotation,
                    &["kotlin", "jvm", "JvmName"],
                    self.source,
                )
            });
        let custom_facade = file_annotation
            .and_then(|annotation| annotation_string_argument(annotation, self.source));
        let facade = custom_facade.or_else(|| {
            if file_annotation.is_some() {
                return None;
            }
            self.file
                .rel_path()
                .file_stem()
                .and_then(|stem| stem.to_str())
                .map(|stem| format!("{}Kt", uppercase_first(stem)))
        });
        self.facade_name = facade.map(|name| self.intern_name(&name));
        let declaration = first_named_child_of_kind(root, "package_header").map(|header| {
            self.add_site(
                header,
                ResolutionSiteKind::PackageDeclaration,
                self.package_scope,
            )
        });
        self.facts.packages.push(ResolutionPackageFact {
            root_scope: self.package_scope,
            declaration,
            placement_gap_site: placement,
        });
        if let Some(header) = first_named_child_of_kind(root, "package_header")
            && let Some(path) = first_named_child_of_kind(header, "identifier")
        {
            for (ordinal, segment) in named_children(path)
                .into_iter()
                .filter(|child| child.kind() == "simple_identifier")
                .enumerate()
            {
                self.handled_identifiers.insert(segment.id());
                let name = self.intern_name(kotlin_identifier_text(segment, self.source));
                self.facts
                    .package_segments
                    .push(ResolutionPackageSegmentFact {
                        root_scope: self.package_scope,
                        ordinal: u32::try_from(ordinal).expect("Kotlin package path fits u32"),
                        name,
                    });
                self.package_names.push(name);
            }
        }
        if file_annotation.is_some() && self.facade_name.is_none() {
            let binary_owner = self.binary_owner_route(None);
            self.facts.gaps.push(ResolutionGapFact::unsupported_route(
                placement,
                ResolutionRouteGap::UnknownAlias {
                    owner: ResolutionRouteOwner::JvmFacade {
                        scope: self.package_scope,
                        name: self.facade_name,
                    },
                    binary_owner,
                    name: None,
                    kind: None,
                },
            ));
        }
    }

    fn record_import(&mut self, node: Node<'_>, scope: ResolutionScopeId) {
        let Some(import) = super::imports::kotlin_import_info_from_node(node, self.source) else {
            return;
        };
        let site = self.add_site(node, ResolutionSiteKind::ImportDeclaration, scope);
        let segments = kotlin_import_header_segments(node);
        for segment in &segments {
            self.handled_identifiers.insert(segment.id());
        }
        for (ordinal, segment) in segments.iter().enumerate() {
            let namespace = if !import.is_wildcard && ordinal + 1 == segments.len() {
                ResolutionNamespace::Type
            } else {
                ResolutionNamespace::Package
            };
            self.add_identifier(
                *segment,
                if namespace == ResolutionNamespace::Type {
                    ResolutionSiteKind::TypeReference
                } else {
                    ResolutionSiteKind::ValueReference
                },
                namespace,
                ResolutionIdentifierRole::Reference,
                scope,
                None,
            );
        }
        let names = segments
            .iter()
            .map(|segment| self.intern_name(kotlin_identifier_text(*segment, self.source)))
            .collect::<Vec<_>>();
        let alias = first_named_child_of_kind(node, "import_alias")
            .and_then(|alias| first_named_child_of_kind(alias, "type_identifier"));
        if let Some(alias) = alias {
            self.handled_identifiers.insert(alias.id());
        }
        let source_name = names.last().copied();
        let local_name = alias
            .map(|name| self.intern_name(kotlin_identifier_text(name, self.source)))
            .or(source_name);
        self.facts.import_routes.push(ResolutionImportRouteFact {
            site,
            root_scope: scope,
            kind: if import.is_wildcard {
                ResolutionImportRouteKind::Star
            } else {
                ResolutionImportRouteKind::Named
            },
            bound_name: if import.is_wildcard { None } else { local_name },
        });
        self.facts
            .import_route_segments
            .extend(names.iter().copied().enumerate().map(|(ordinal, name)| {
                ResolutionImportRouteSegmentFact {
                    import_site: site,
                    ordinal: u32::try_from(ordinal).expect("Kotlin import path fits u32"),
                    name,
                }
            }));
        // The selected JVM context bridges an import through its root route:
        // the package path, then what the source names from it. A single-name
        // import has no package to route through.
        let root_names = if import.is_wildcard {
            names.as_slice()
        } else {
            &names[..names.len().saturating_sub(1)]
        };
        if !root_names.is_empty() {
            self.facts.root_imports.push(ResolutionRootImportFact {
                site,
                root_scope: scope,
                anchor: ResolutionRootImportAnchor::Lexical,
                position: None,
            });
            self.facts
                .root_import_kinds
                .push(ResolutionRootImportKindFact {
                    import_site: site,
                    kind: if import.is_wildcard {
                        ResolutionRootImportKind::Glob
                    } else {
                        ResolutionRootImportKind::Named
                    },
                });
            self.facts
                .root_import_segments
                .extend(
                    root_names
                        .iter()
                        .copied()
                        .enumerate()
                        .map(|(position, name)| ResolutionRootImportSegmentFact {
                            import_site: site,
                            position: u32::try_from(position).expect("Kotlin import path fits u32"),
                            name,
                        }),
                );
            if import.is_wildcard {
                self.wildcard_imports.push((site, scope));
            } else {
                // A Kotlin import can name a type, a value, or a callable.
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
                            name: *names.last().expect("a named import has a terminal name"),
                        });
                }
            }
        }
        if import.is_wildcard {
            self.facts
                .import_selectors
                .push(ResolutionImportSelectorFact {
                    site,
                    kind: ResolutionImportSelectorKind::Star,
                    source_name: None,
                    local_name: None,
                });
            return;
        }
        let source_name = source_name.expect("a named Kotlin import has a terminal segment");
        let local_name = local_name.expect("a named Kotlin import binds a name");
        self.facts
            .import_selectors
            .push(ResolutionImportSelectorFact {
                site,
                kind: ResolutionImportSelectorKind::Named,
                source_name: Some(source_name),
                local_name: Some(local_name),
            });
    }

    fn record_type_declaration(
        &mut self,
        node: Node<'source>,
        context: WalkContext,
    ) -> Option<ResolutionSiteId> {
        let name_node = first_named_child_of_kind(node, "type_identifier");
        let name = name_node
            .map(|name| kotlin_identifier_text(name, self.source).to_owned())
            .or_else(|| (node.kind() == "companion_object").then(|| "Companion".to_owned()))?;
        let site = if let Some(name_node) = name_node {
            self.add_identifier(
                name_node,
                ResolutionSiteKind::TypeDeclaration,
                ResolutionNamespace::Type,
                ResolutionIdentifierRole::Declaration,
                context.scope,
                None,
            )
        } else {
            let site = self.add_site(node, ResolutionSiteKind::TypeDeclaration, context.scope);
            let name_id = self.intern_name(&name);
            self.facts.identifiers.push(PositionedIdentifierFact {
                site,
                name: name_id,
                role: ResolutionIdentifierRole::Declaration,
                namespace: ResolutionNamespace::Type,
                qualifier: None,
            });
            site
        };
        self.add_declaration_source(node, name_node, site);
        self.type_sites.insert(node.id(), site);
        self.type_scope_ranges
            .insert(site, (node.start_byte(), node.end_byte()));
        self.type_scope_parents.insert(site, context.scope);
        let name_id = self.intern_name(&name);
        self.type_names.insert(site, name_id);
        self.type_simple_names.insert(
            site,
            name_node
                .map(|name_node| kotlin_identifier_text(name_node, self.source))
                .unwrap_or("Companion"),
        );
        self.type_parents.insert(site, context.owner_type);
        if declaration_is_interface(node) {
            self.interface_types.insert(site);
        }
        if self.annotation_proofs.value_classes.contains(&name) {
            self.value_class_types.insert(site);
        }
        self.add_binder(site, context.scope, ResolutionBinderKind::Type, true);
        self.add_visibility(site, node);
        self.add_package_membership(site, ResolutionNamespace::Type, context.scope, node);
        if let Some(owner) = self.type_body_owner(context) {
            self.facts.member_owners.push(ResolutionMemberOwnerFact {
                member: site,
                owner,
                kind: ResolutionMemberKind::NestedType,
                access: ResolutionMemberAccess::Type,
                qualifier_compatibility: ResolutionMemberQualifierCompatibility::TypeOnly,
            });
        }
        if matches!(node.kind(), "object_declaration" | "companion_object") {
            let kind = if node.kind() == "companion_object" {
                ResolutionSingletonRelationKind::Companion
            } else {
                ResolutionSingletonRelationKind::Object
            };
            self.facts
                .singleton_relations
                .push(ResolutionSingletonRelationFact {
                    declaration: site,
                    enclosing_type: context.owner_type,
                    kind,
                });
            let instance_name = self.intern_name("INSTANCE");
            if kind == ResolutionSingletonRelationKind::Companion {
                self.companion_types.insert(site);
                let companion_name = self.intern_name(&name);
                if let Some(owner_segments) = self.jvm_owner_segments(context.owner_type) {
                    self.add_jvm_alias(
                        site,
                        companion_name,
                        ResolutionJvmAliasKind::CompanionObject,
                        true,
                        0,
                        ResolutionJvmAliasStatus::SourceProven,
                        owner_segments,
                    );
                }
                if let Some(owner_segments) = self.jvm_owner_segments(Some(site)) {
                    self.add_jvm_alias(
                        site,
                        instance_name,
                        ResolutionJvmAliasKind::SingletonInstance,
                        true,
                        0,
                        ResolutionJvmAliasStatus::SourceProven,
                        owner_segments,
                    );
                }
            } else if let Some(owner_segments) = self.jvm_owner_segments(Some(site)) {
                self.add_jvm_alias(
                    site,
                    instance_name,
                    ResolutionJvmAliasKind::SingletonInstance,
                    true,
                    0,
                    ResolutionJvmAliasStatus::SourceProven,
                    owner_segments,
                );
            }
        }
        // Keep the source declaration id live in this branch as a construction
        // assertion: a declaration projection must always have a canonical id.
        Some(site)
    }

    /// Publish the source-backed members Kotlin synthesizes for enum and data
    /// classes. They share the class declaration's source identity, while
    /// their member owner and callable shape let native lookup see them as
    /// ordinary declarations.
    fn finish_synthetic_members(&mut self, root: Node<'source>) {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            stack.extend(named_children(node));
            if node.kind() != "class_declaration" {
                continue;
            }
            let Some(&owner) = self.type_sites.get(&node.id()) else {
                continue;
            };
            let scope = self.ensure_type_body_scope(owner);
            if kotlin_class_like_kind(node) == Some(super::declarations::KotlinClassLikeKind::Enum)
            {
                self.add_synthetic_callable(node, owner, scope, "values", &[]);
                self.add_synthetic_callable(
                    node,
                    owner,
                    scope,
                    "valueOf",
                    &[SyntheticParameter {
                        name: "value",
                        source: None,
                        intrinsic_type: Some("kotlin.String"),
                        optional: false,
                    }],
                );
                self.add_synthetic_property(node, owner, scope, "entries");
            }
            if kotlin_is_data_class(node, self.source) {
                let parameters = first_named_child_of_kind(node, "primary_constructor")
                    .map(named_children)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|parameter| parameter.kind() == "class_parameter")
                    .collect::<Vec<_>>();
                let generated = parameters
                    .iter()
                    .filter_map(|parameter| {
                        let name = first_named_child_of_kind(*parameter, "simple_identifier")?;
                        Some(SyntheticParameter {
                            name: kotlin_identifier_text(name, self.source),
                            source: Some(*parameter),
                            intrinsic_type: None,
                            optional: true,
                        })
                    })
                    .collect::<Vec<_>>();
                self.add_synthetic_callable(node, owner, scope, "copy", &generated);
                for (ordinal, parameter) in parameters.iter().enumerate() {
                    let component = format!("component{}", ordinal + 1);
                    if let Some(site) =
                        self.add_synthetic_callable(node, owner, scope, &component, &[])
                        && let Some(type_node) = super::syntax::kotlin_binding_type_node(*parameter)
                    {
                        let value_type = self.add_declared_type(
                            site,
                            type_node,
                            scope,
                            ResolutionTypeSlotRole::DeclaredValue,
                            DeclarationTypeRole::Return,
                            Some(owner),
                        );
                        self.facts
                            .callable_signatures
                            .iter_mut()
                            .find(|signature| signature.callable == site)
                            .expect("synthetic component has a callable signature")
                            .result_types
                            .push(ResolutionCallableResultTypeFact {
                                ordinal: 0,
                                value_type,
                            });
                    }
                }
            }
        }
    }

    fn synthetic_member_site(
        &mut self,
        class: Node<'source>,
        owner: ResolutionSiteId,
        scope: ResolutionScopeId,
        name: &str,
    ) -> ResolutionSiteId {
        let anchor = first_named_child_of_kind(class, "type_identifier")
            .expect("a synthetic member owner has a name");
        let name_id = self.intern_name(name);
        let site = self.add_site(anchor, ResolutionSiteKind::CallableDeclaration, scope);
        self.facts.identifiers.push(PositionedIdentifierFact {
            site,
            name: name_id,
            role: ResolutionIdentifierRole::Declaration,
            namespace: ResolutionNamespace::Callable,
            qualifier: None,
        });
        self.add_declaration_source(class, Some(anchor), site);
        self.add_binder(site, scope, ResolutionBinderKind::Callable, true);
        self.facts.member_owners.push(ResolutionMemberOwnerFact {
            member: site,
            owner,
            kind: ResolutionMemberKind::Method,
            access: if name == "values" || name == "valueOf" {
                ResolutionMemberAccess::Type
            } else {
                ResolutionMemberAccess::Instance
            },
            qualifier_compatibility: if name == "values" || name == "valueOf" {
                ResolutionMemberQualifierCompatibility::TypeOnly
            } else {
                ResolutionMemberQualifierCompatibility::RuntimeOnly
            },
        });
        self.facts
            .callable_signatures
            .push(ResolutionCallableSignatureFact {
                callable: site,
                type_parameter_count: 0,
                result_types: Vec::new(),
            });
        self.facts
            .callable_parameter_lists
            .push(ResolutionCallableParameterListFact {
                callable: site,
                list_ordinal: 0,
                contextual: false,
            });
        site
    }

    fn add_synthetic_callable(
        &mut self,
        class: Node<'source>,
        owner: ResolutionSiteId,
        scope: ResolutionScopeId,
        name: &str,
        parameters: &[SyntheticParameter<'source>],
    ) -> Option<ResolutionSiteId> {
        let name_id = self.intern_name(name);
        if crate::synthetic_members::declares_callable(
            &self.facts,
            scope,
            name_id,
            Some(parameters.len()),
        ) {
            return None;
        }
        let site = self.synthetic_member_site(class, owner, scope, name);
        let param_scope = self.add_scope(
            first_named_child_of_kind(class, "type_identifier")
                .expect("a synthetic member owner has a name"),
            scope,
            Some(site),
            ResolutionScopeKind::Executable,
        );
        for (ordinal, parameter) in parameters.iter().enumerate() {
            let anchor = first_named_child_of_kind(class, "type_identifier")
                .expect("a synthetic member owner has a name");
            let parameter_site =
                self.add_site(anchor, ResolutionSiteKind::ValueDeclaration, param_scope);
            let label = self.intern_name(parameter.name);
            self.facts.identifiers.push(PositionedIdentifierFact {
                site: parameter_site,
                name: label,
                role: ResolutionIdentifierRole::Declaration,
                namespace: ResolutionNamespace::Value,
                qualifier: None,
            });
            self.add_binder(
                parameter_site,
                param_scope,
                ResolutionBinderKind::Parameter,
                true,
            );
            let value_type = if let Some(source) = parameter.source {
                if let Some(name_node) = first_named_child_of_kind(source, "simple_identifier") {
                    self.add_declaration_source(source, Some(name_node), parameter_site);
                }
                if let Some(type_node) = super::syntax::kotlin_binding_type_node(source) {
                    self.add_declared_type(
                        parameter_site,
                        type_node,
                        scope,
                        ResolutionTypeSlotRole::DeclaredValue,
                        DeclarationTypeRole::Parameter,
                        Some(site),
                    )
                } else {
                    let value_type =
                        self.add_slot(parameter_site, ResolutionTypeSlotRole::DeclaredValue);
                    self.facts
                        .declaration_type_slots
                        .push(DeclarationTypeSlotFact {
                            declaration: parameter_site,
                            slot: value_type,
                            role: DeclarationTypeRole::Parameter,
                        });
                    value_type
                }
            } else {
                let value_type =
                    self.add_slot(parameter_site, ResolutionTypeSlotRole::DeclaredValue);
                self.facts
                    .declaration_type_slots
                    .push(DeclarationTypeSlotFact {
                        declaration: parameter_site,
                        slot: value_type,
                        role: DeclarationTypeRole::Parameter,
                    });
                if let Some(type_name) = parameter.intrinsic_type {
                    let name = self.intern_name(type_name);
                    let input =
                        self.add_slot(parameter_site, ResolutionTypeSlotRole::TargetTypeIdentity);
                    self.facts.intrinsic_type_seeds.push(IntrinsicTypeSeedFact {
                        output: input,
                        name,
                        kind: IntrinsicTypeKind::LanguageBuiltin,
                        indirection: 0,
                    });
                    crate::call_arguments::publish_jvm_declared_type_transfer(
                        &mut self.facts,
                        input,
                        value_type,
                        ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                    );
                }
                value_type
            };
            let ordinal =
                u32::try_from(ordinal).expect("Kotlin synthetic parameter count fits u32");
            self.facts
                .callable_parameters
                .push(ResolutionCallableParameterFact {
                    callable: site,
                    list_ordinal: 0,
                    ordinal,
                    parameter: parameter_site,
                    value_type,
                    repeated: false,
                });
            self.facts.callable_parameter_semantics.push(
                ResolutionCallableParameterSemanticsFact {
                    callable: site,
                    parameter: parameter_site,
                    list_ordinal: 0,
                    ordinal,
                    label,
                    has_default: parameter.optional,
                },
            );
        }
        if name == "copy" || name == "valueOf" {
            let input = self.owner_type_slot(
                first_named_child_of_kind(class, "type_identifier").expect("a class has a name"),
                owner,
                site,
            );
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
                input,
                value_type,
                ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
            );
            self.facts
                .callable_signatures
                .iter_mut()
                .find(|signature| signature.callable == site)
                .expect("synthetic callable has a signature")
                .result_types
                .push(ResolutionCallableResultTypeFact {
                    ordinal: 0,
                    value_type,
                });
        }
        Some(site)
    }

    fn owner_type_slot(
        &mut self,
        anchor: Node<'source>,
        class_site: ResolutionSiteId,
        callable: ResolutionSiteId,
    ) -> ResolutionTypeSlotId {
        let scope = *self
            .type_scope_parents
            .get(&class_site)
            .expect("a synthetic member owner has a declaring scope");
        let reference = self.add_site(anchor, ResolutionSiteKind::SyntheticReference, scope);
        let name = *self
            .type_names
            .get(&class_site)
            .expect("a synthetic member owner has a type name");
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
                owner: Some(callable),
            });
        let slot = self.add_slot(reference, ResolutionTypeSlotRole::TargetTypeIdentity);
        self.facts.binding_projections.push(BindingProjectionFact {
            reference,
            output: slot,
            kind: BindingProjectionKind::TargetTypeIdentity,
        });
        slot
    }

    fn add_synthetic_property(
        &mut self,
        class: Node<'source>,
        owner: ResolutionSiteId,
        scope: ResolutionScopeId,
        name: &str,
    ) {
        let name_id = self.intern_name(name);
        if self.facts.identifiers.iter().any(|identifier| {
            identifier.role == ResolutionIdentifierRole::Declaration
                && identifier.name == name_id
                && self.facts.sites[identifier.site.index()].scope == scope
        }) {
            return;
        }
        let anchor = first_named_child_of_kind(class, "type_identifier")
            .expect("a synthetic member owner has a name");
        let site = self.add_site(anchor, ResolutionSiteKind::ValueDeclaration, scope);
        self.facts.identifiers.push(PositionedIdentifierFact {
            site,
            name: name_id,
            role: ResolutionIdentifierRole::Declaration,
            namespace: ResolutionNamespace::Value,
            qualifier: None,
        });
        self.add_declaration_source(class, Some(anchor), site);
        self.add_binder(site, scope, ResolutionBinderKind::Field, true);
        self.facts.member_owners.push(ResolutionMemberOwnerFact {
            member: site,
            owner,
            kind: ResolutionMemberKind::Field,
            access: ResolutionMemberAccess::Type,
            qualifier_compatibility: ResolutionMemberQualifierCompatibility::TypeOnly,
        });
    }

    fn record_type_alias(
        &mut self,
        node: Node<'source>,
        context: WalkContext,
    ) -> Option<ResolutionSiteId> {
        let name_node = first_named_child_of_kind(node, "type_identifier")?;
        let site = self.add_identifier(
            name_node,
            ResolutionSiteKind::TypeAliasDeclaration,
            ResolutionNamespace::Type,
            ResolutionIdentifierRole::Declaration,
            context.scope,
            None,
        );
        self.add_declaration_source(node, Some(name_node), site);
        self.type_sites.insert(node.id(), site);
        let name = self.intern_name(kotlin_identifier_text(name_node, self.source));
        self.type_names.insert(site, name);
        self.type_parents.insert(site, context.owner_type);
        self.add_binder(site, context.scope, ResolutionBinderKind::Type, true);
        self.add_visibility(site, node);
        self.add_package_membership(site, ResolutionNamespace::Type, context.scope, node);
        let target_node = named_children(node)
            .into_iter()
            .find(|child| KOTLIN_TYPE_NODE_KINDS.contains(&child.kind()));
        if let Some(target_node) = target_node {
            let target = self.ensure_type_slot(target_node, context.scope, context.declaration);
            let identity = self.add_type_identity(site);
            self.type_identity_slots.insert(site, identity);
            self.facts.type_transfers.push(ResolutionTypeTransferFact {
                input: target,
                output: identity,
                kind: ResolutionTypeTransferKind::TypeAlias,
                indirection_delta: 0,
                reference_indirection_delta: 0,
                value_transform: ResolutionTypeTransferValueTransform::Preserve,
            });
        } else {
            self.facts.gaps.push(ResolutionGapFact::new(
                site,
                ResolutionGapKind::UnsupportedTypeSyntax,
            ));
        }
        Some(site)
    }

    fn record_function(
        &mut self,
        node: Node<'source>,
        context: WalkContext,
    ) -> Option<ResolutionSiteId> {
        let name_node = first_named_child_of_kind(node, "simple_identifier")?;
        let site = self.add_identifier(
            name_node,
            ResolutionSiteKind::CallableDeclaration,
            ResolutionNamespace::Callable,
            ResolutionIdentifierRole::Declaration,
            context.scope,
            None,
        );
        let declaration = self.add_declaration_source(node, Some(name_node), site);
        if !self.units.contains_key(&declaration) {
            // Scala uses this shared collector for every unitless callable,
            // including a method owned by an anonymous expression body.
            self.collector
                .mark_lexical(declaration, DeclarationKind::BlockLocalItem);
        }
        self.add_binder(site, context.scope, ResolutionBinderKind::Callable, true);
        self.add_visibility(site, node);
        self.add_package_membership(site, ResolutionNamespace::Callable, context.scope, node);
        if let Some(owner) = self.type_body_owner(context) {
            self.facts.member_owners.push(ResolutionMemberOwnerFact {
                member: site,
                owner,
                kind: ResolutionMemberKind::Method,
                access: if context.singleton_owner {
                    ResolutionMemberAccess::Type
                } else {
                    ResolutionMemberAccess::Instance
                },
                qualifier_compatibility: if context.singleton_owner {
                    ResolutionMemberQualifierCompatibility::RuntimeOrType
                } else {
                    ResolutionMemberQualifierCompatibility::RuntimeOnly
                },
            });
        }

        self.add_callable_signature(site, node);
        if let Some(receiver) = node.child_by_field_name("receiver") {
            let receiver_type = self.ensure_type_slot(receiver, context.scope, Some(site));
            self.facts
                .extension_receivers
                .push(ResolutionExtensionReceiverFact {
                    callable: site,
                    receiver_type,
                });
        }
        if let Some(return_type) = super::syntax::kotlin_declared_return_type_node(node) {
            let value_type = self.add_declared_type(
                site,
                return_type,
                context.scope,
                ResolutionTypeSlotRole::DeclaredValue,
                DeclarationTypeRole::Return,
                Some(site),
            );
            self.facts
                .callable_signatures
                .last_mut()
                .expect("function signature was just inserted")
                .result_types
                .push(ResolutionCallableResultTypeFact {
                    ordinal: 0,
                    value_type,
                });
        } else {
            let value_type = self.add_slot(site, ResolutionTypeSlotRole::DeclaredValue);
            self.facts
                .declaration_type_slots
                .push(DeclarationTypeSlotFact {
                    declaration: site,
                    slot: value_type,
                    role: DeclarationTypeRole::Return,
                });
            self.facts
                .callable_signatures
                .last_mut()
                .expect("function signature was just inserted")
                .result_types
                .push(ResolutionCallableResultTypeFact {
                    ordinal: 0,
                    value_type,
                });
            // Without a written return type, a block body or no body returns
            // Unit; an expression body returns the expression's type.
            let body = first_named_child_of_kind(node, "function_body");
            let expression_body = body.and_then(kotlin_expression_after_equals);
            match (body, expression_body) {
                (Some(_), Some(expression)) => {
                    self.pending_initializers
                        .push((value_type, expression, context));
                }
                (Some(body), None) if body.child(0).is_none_or(|first| first.kind() != "{") => {
                    self.facts.gaps.push(ResolutionGapFact::new(
                        site,
                        ResolutionGapKind::InferredType,
                    ));
                }
                _ => {
                    let name = self.intern_name("kotlin.Unit");
                    let seed = self.add_slot(site, ResolutionTypeSlotRole::TargetTypeIdentity);
                    self.facts.intrinsic_type_seeds.push(IntrinsicTypeSeedFact {
                        output: seed,
                        name,
                        kind: IntrinsicTypeKind::LanguageBuiltin,
                        indirection: 0,
                    });
                    self.facts.type_transfers.push(ResolutionTypeTransferFact {
                        input: seed,
                        output: value_type,
                        kind: ResolutionTypeTransferKind::DeclaredType,
                        indirection_delta: 0,
                        reference_indirection_delta: 0,
                        value_transform: ResolutionTypeTransferValueTransform::ToRuntime {
                            addressable: false,
                        },
                    });
                }
            }
        }
        self.add_callable_jvm_aliases(node, site, context, false);
        Some(site)
    }

    fn record_constructor(
        &mut self,
        node: Node<'source>,
        context: WalkContext,
    ) -> Option<ResolutionSiteId> {
        if node.kind() == "primary_constructor"
            && !named_children(node)
                .into_iter()
                .any(|child| child.kind() == "class_parameter")
        {
            // A primary constructor without written parameters belongs to the
            // class declaration and `record_default_constructor` models it.
            // Local constructors have no indexed CodeUnit either, but their
            // written parameters still need a callable and initialization scope.
            return None;
        }
        Some(self.add_constructor_site(node, node, None, context))
    }

    /// The zero-parameter primary constructor of a class that declares no
    /// constructor unit for it: the constructor Kotlin supplies when a class
    /// writes no constructor at all, and the one `class C()` writes with an
    /// empty parameter list. It is declared by the class itself, so its source
    /// declaration is the class declaration and a call that selects it
    /// navigates to the class. The class name token anchors the site. The
    /// token has no modifiers, annotations, type parameters or parameters, so
    /// the shared constructor facts read it as the empty parameter list it is.
    fn record_default_constructor(&mut self, class: Node<'source>, context: WalkContext) {
        let name = first_named_child_of_kind(class, "type_identifier")
            .expect("a Kotlin class with a recorded type site has a name");
        self.add_constructor_site(name, class, Some(name), context);
    }

    /// One constructor of `context.owner_type`: its site at `anchor`, the
    /// declaration source it stands for, its signature, its owner and its JVM
    /// aliases. The call result type comes from the constructor's owner row.
    fn add_constructor_site(
        &mut self,
        anchor: Node<'source>,
        declaration: Node<'source>,
        declaration_name: Option<Node<'source>>,
        context: WalkContext,
    ) -> ResolutionSiteId {
        let site = self.add_site(
            anchor,
            ResolutionSiteKind::ConstructorDeclaration,
            context.scope,
        );
        self.add_declaration_source(declaration, declaration_name, site);
        if let Some(owner) = context.owner_type {
            self.pending_constructors.push((site, owner));
        } else {
            self.add_binder(site, context.scope, ResolutionBinderKind::Constructor, true);
        }
        self.add_callable_signature(site, anchor);
        self.add_callable_jvm_aliases(anchor, site, context, true);
        site
    }

    fn record_property(&mut self, node: Node<'source>, context: WalkContext) {
        let member_owner = self.type_body_owner(context);
        let indirect_read = named_children(node)
            .iter()
            .any(|child| matches!(child.kind(), "property_delegate" | "getter" | "setter"));
        let variables = named_children(node)
            .into_iter()
            .flat_map(|child| match child.kind() {
                "variable_declaration" => vec![child],
                "multi_variable_declaration" => named_children(child)
                    .into_iter()
                    .filter(|entry| entry.kind() == "variable_declaration")
                    .collect(),
                _ => Vec::new(),
            })
            .collect::<Vec<_>>();
        for variable in variables {
            let Some(name_node) = first_named_child_of_kind(variable, "simple_identifier") else {
                continue;
            };
            let site = self.add_identifier(
                name_node,
                ResolutionSiteKind::ValueDeclaration,
                ResolutionNamespace::Value,
                ResolutionIdentifierRole::Declaration,
                context.scope,
                None,
            );
            let source_declaration = self.add_declaration_source(node, Some(name_node), site);
            if node.kind() == "when_subject" {
                // A when subject has no parser CodeUnit. Its selected binding
                // still needs the same located lexical presentation as a local.
                self.collector
                    .mark_lexical(source_declaration, DeclarationKind::LocalVariable);
            }
            let local = member_owner.is_none() && context.scope != self.package_scope;
            if !local || indirect_read {
                self.unstable_smart_cast_bindings.insert(site);
            }
            self.add_binder(
                site,
                context.scope,
                if member_owner.is_some() {
                    ResolutionBinderKind::Field
                } else {
                    ResolutionBinderKind::Local
                },
                !local,
            );
            self.add_visibility(site, node);
            self.add_package_membership(site, ResolutionNamespace::Value, context.scope, node);
            if let Some(owner) = member_owner {
                self.facts.member_owners.push(ResolutionMemberOwnerFact {
                    member: site,
                    owner,
                    kind: ResolutionMemberKind::Field,
                    access: if context.singleton_owner {
                        ResolutionMemberAccess::Type
                    } else {
                        ResolutionMemberAccess::Instance
                    },
                    qualifier_compatibility: if context.singleton_owner {
                        ResolutionMemberQualifierCompatibility::RuntimeOrType
                    } else {
                        ResolutionMemberQualifierCompatibility::RuntimeOnly
                    },
                });
            }
            if let Some(type_node) = super::syntax::kotlin_binding_type_node(variable) {
                if let Some(scalar) = kotlin_declared_scalar_type(type_node, self.source) {
                    self.scalar_types_by_declaration.insert(site, scalar);
                }
                self.add_declared_type(
                    site,
                    type_node,
                    context.scope,
                    ResolutionTypeSlotRole::DeclaredValue,
                    DeclarationTypeRole::Value,
                    context.declaration,
                );
            } else {
                let value_type = self.add_slot(site, ResolutionTypeSlotRole::DeclaredValue);
                self.facts
                    .declaration_type_slots
                    .push(DeclarationTypeSlotFact {
                        declaration: site,
                        slot: value_type,
                        role: DeclarationTypeRole::Value,
                    });
                // A single `val x = expression` takes the expression's type;
                // anything else (delegates, destructuring) stays inferred.
                match kotlin_expression_after_equals(node)
                    .filter(|_| variable.parent() == Some(node))
                {
                    Some(expression) => {
                        let mut initializer_context = context;
                        if let Some(scope) =
                            member_owner.and_then(|owner| self.initialization_scopes.get(&owner))
                        {
                            initializer_context.scope = *scope;
                        }
                        self.pending_initializers.push((
                            value_type,
                            expression,
                            initializer_context,
                        ));
                    }
                    None => {
                        self.facts.gaps.push(ResolutionGapFact::new(
                            site,
                            ResolutionGapKind::InferredType,
                        ));
                    }
                }
            }
            if local && let Some(expression) = kotlin_expression_after_equals(node) {
                let output = self.add_slot(site, ResolutionTypeSlotRole::AssignmentValue);
                if variable.parent() == Some(node) {
                    self.pending_initializer_values
                        .push((output, expression, context));
                } else {
                    // Each destructured entry receives a component, not the
                    // whole initializer. Keep that unknown runtime input
                    // separate from the entry's written declaration type.
                    assert!(
                        variable.parent().is_some_and(|parent| {
                            parent.kind() == "multi_variable_declaration"
                        })
                    );
                    let incoming = self.add_site(
                        name_node,
                        ResolutionSiteKind::UnsupportedExpression,
                        context.scope,
                    );
                    assert_ne!(incoming, site);
                    self.facts
                        .add_gap(incoming, ResolutionGapKind::InferredType);
                    let input = self.add_slot(incoming, ResolutionTypeSlotRole::ExpressionValue);
                    self.facts.type_transfers.push(ResolutionTypeTransferFact {
                        input,
                        output,
                        kind: ResolutionTypeTransferKind::Assignment,
                        indirection_delta: 0,
                        reference_indirection_delta: 0,
                        value_transform: ResolutionTypeTransferValueTransform::Preserve,
                    });
                }
            }
            if context.callable.is_none()
                && variable
                    .parent()
                    .is_some_and(|parent| parent.kind() == "property_declaration")
            {
                self.add_property_jvm_aliases(
                    node,
                    site,
                    context,
                    kotlin_identifier_text(name_node, self.source),
                );
            }
        }
    }

    fn record_parameter(&mut self, node: Node<'source>, context: WalkContext) {
        let Some(name_node) = first_named_child_of_kind(node, "simple_identifier") else {
            return;
        };
        let Some(callable) = context.callable else {
            return;
        };
        let constructor_property = node.kind() == "class_parameter"
            && first_named_child_of_kind(node, "binding_pattern_kind").is_some()
            && context.owner_type.is_some();
        let binding_scope = if node.kind() == "class_parameter"
            && !constructor_property
            && let Some(owner) = context.owner_type
        {
            *self
                .initialization_scopes
                .get(&owner)
                .expect("plain primary-constructor parameters have an initialization scope")
        } else {
            context.scope
        };
        let site = self.add_identifier(
            name_node,
            ResolutionSiteKind::ValueDeclaration,
            ResolutionNamespace::Value,
            ResolutionIdentifierRole::Declaration,
            binding_scope,
            None,
        );
        let source_declaration = self.add_declaration_source(node, Some(name_node), site);
        self.collector
            .mark_lexical(source_declaration, DeclarationKind::Parameter);
        if !constructor_property {
            self.add_binder(site, binding_scope, ResolutionBinderKind::Parameter, true);
        }
        if node.kind() == "class_parameter" {
            self.pending_constructor_aliases
                .push((name_node, site, context.scope));
        }
        let type_node = super::syntax::kotlin_binding_type_node(node);
        let value_type = if let Some(type_node) = type_node {
            if let Some(scalar) = kotlin_declared_scalar_type(type_node, self.source) {
                self.scalar_types_by_declaration.insert(site, scalar);
            }
            // Parameter types use the canonical declaration's classifier scope.
            // Defaults and delegation arguments keep the header context.
            self.add_declared_type(
                site,
                type_node,
                binding_scope,
                ResolutionTypeSlotRole::DeclaredValue,
                DeclarationTypeRole::Parameter,
                Some(callable),
            )
        } else {
            let value_type = self.add_slot(site, ResolutionTypeSlotRole::DeclaredValue);
            self.facts
                .declaration_type_slots
                .push(DeclarationTypeSlotFact {
                    declaration: site,
                    slot: value_type,
                    role: DeclarationTypeRole::Parameter,
                });
            self.facts.gaps.push(ResolutionGapFact::new(
                site,
                ResolutionGapKind::UnsupportedTypeSyntax,
            ));
            value_type
        };
        if constructor_property {
            let owner = context
                .owner_type
                .expect("a constructor property has an enclosing type");
            self.pending_constructor_properties
                .push((site, owner, context.singleton_owner));
            self.add_visibility(site, node);
            self.add_property_jvm_aliases(
                node,
                site,
                context,
                kotlin_identifier_text(name_node, self.source),
            );
        }
        let ordinal = self.next_parameters.entry(callable).or_default();
        let current_ordinal = *ordinal;
        *ordinal = ordinal
            .checked_add(1)
            .expect("Kotlin callable parameter count fits u32");
        self.facts
            .callable_parameters
            .push(ResolutionCallableParameterFact {
                callable,
                list_ordinal: 0,
                ordinal: current_ordinal,
                parameter: site,
                value_type,
                repeated: self.parameter_is_vararg(node),
            });
        let label = self.intern_name(kotlin_identifier_text(name_node, self.source));
        self.facts
            .callable_parameter_semantics
            .push(ResolutionCallableParameterSemanticsFact {
                callable,
                parameter: site,
                list_ordinal: 0,
                ordinal: current_ordinal,
                label,
                has_default: kotlin_parameter_default(node).is_some(),
            });
    }

    fn record_type_parameter(&mut self, node: Node<'source>, context: WalkContext) {
        let Some(name_node) = first_named_child_of_kind(node, "type_identifier") else {
            return;
        };
        let site = self.add_identifier(
            name_node,
            ResolutionSiteKind::TypeDeclaration,
            ResolutionNamespace::Type,
            ResolutionIdentifierRole::Declaration,
            context.scope,
            None,
        );
        let source_declaration = self.add_declaration_source(node, Some(name_node), site);
        self.collector
            .mark_lexical(source_declaration, DeclarationKind::Parameter);
        self.add_binder(site, context.scope, ResolutionBinderKind::Type, true);
        let identity = self.add_type_identity(site);
        self.type_identity_slots.insert(site, identity);
    }

    fn record_user_type(
        &mut self,
        node: Node<'source>,
        context: WalkContext,
    ) -> Option<ResolutionTypeSlotId> {
        if let Some(slot) = self.type_slots_by_node.get(&node.id()).copied() {
            return Some(slot);
        }
        let segments = kotlin_user_type_segments(node);
        if segments.is_empty() {
            return None;
        }
        let arguments = segments
            .last()
            .and_then(|segment| segment.next_named_sibling())
            .filter(|node| node.kind() == "type_arguments");
        let path = segments
            .iter()
            .map(|&segment| (segment, kotlin_identifier_text(segment, self.source)))
            .collect::<Vec<_>>();
        let slot = self.record_qualified_type_path(&path, context);
        for segment in segments {
            self.handled_identifiers.insert(segment.id());
        }
        self.type_slots_by_node.insert(node.id(), slot);
        if let Some(arguments) = arguments {
            self.pending_applied_types
                .push((slot, arguments, context.scope, context.declaration));
        }
        Some(slot)
    }

    // Explicit and synthetic nominal types must use the same positioned path,
    // projection and root-import machinery, including unindexed boundaries.
    fn record_qualified_type_path(
        &mut self,
        segments: &[(Node<'source>, &str)],
        context: WalkContext,
    ) -> ResolutionTypeSlotId {
        assert!(!segments.is_empty());
        let mut previous = None;
        let mut reference_sites = Vec::with_capacity(segments.len());
        for &(segment, spelling) in segments {
            let site = self.add_site(segment, ResolutionSiteKind::TypeReference, context.scope);
            let name = self.intern_name(spelling);
            self.facts.identifiers.push(PositionedIdentifierFact {
                site,
                name,
                role: ResolutionIdentifierRole::Reference,
                namespace: ResolutionNamespace::Type,
                qualifier: previous,
            });
            let slot = self.add_slot(site, ResolutionTypeSlotRole::TargetTypeIdentity);
            self.facts.binding_projections.push(BindingProjectionFact {
                reference: site,
                output: slot,
                kind: BindingProjectionKind::TargetTypeIdentity,
            });
            if let Some(owner) = context.declaration {
                self.facts
                    .reference_owners
                    .push(ResolutionReferenceOwnerFact {
                        reference: site,
                        owner: Some(owner),
                    });
            }
            self.type_slots_by_node.insert(segment.id(), slot);
            self.type_sites.insert(segment.id(), site);
            self.sites_by_node.insert(segment.id(), site);
            reference_sites.push(site);
            previous = Some(slot);
        }
        let final_slot = previous.expect("a qualified type has a segment");
        if reference_sites.len() > 1 {
            let reference = *reference_sites.last().unwrap();
            self.facts
                .root_references
                .push(ResolutionRootReferenceFact {
                    reference,
                    root_scope: self.package_scope,
                    anchor: ResolutionRootImportAnchor::Lexical,
                    prefix_reference: reference_sites.first().copied(),
                    owner_continued: false,
                });
            self.facts.root_reference_segments.extend(
                reference_sites
                    .iter()
                    .take(reference_sites.len() - 1)
                    .enumerate()
                    .map(|(position, site)| ResolutionRootReferenceSegmentFact {
                        reference,
                        position: u32::try_from(position)
                            .expect("Kotlin qualified type path fits u32"),
                        name: self
                            .facts
                            .identifiers
                            .iter()
                            .find(|identifier| identifier.site == *site)
                            .expect("type path segment has an identifier")
                            .name,
                    }),
            );
        }
        final_slot
    }

    fn ensure_type_slot(
        &mut self,
        node: Node<'source>,
        scope: ResolutionScopeId,
        owner: Option<ResolutionSiteId>,
    ) -> ResolutionTypeSlotId {
        if let Some(slot) = self.type_slots_by_node.get(&node.id()).copied() {
            return slot;
        }
        if node.kind() == "nullable_type" {
            let mut underlying = node;
            while matches!(underlying.kind(), "nullable_type" | "parenthesized_type") {
                let Some(nested) = named_children(underlying)
                    .into_iter()
                    .find(|child| KOTLIN_TYPE_NODE_KINDS.contains(&child.kind()))
                else {
                    break;
                };
                underlying = nested;
            }
            if underlying.kind() == "function_type" {
                // Nullable function syntax cannot supply a non-null intrinsic
                // invoke proof. An unknown slot keeps value application possible;
                // receiver selection carries its own incomplete frontier.
                let site = self.add_site(node, ResolutionSiteKind::TypeReference, scope);
                let slot = self.add_slot(site, ResolutionTypeSlotRole::TargetTypeIdentity);
                self.type_slots_by_node.insert(node.id(), slot);
                return slot;
            }
        }
        if node.kind() == "user_type" {
            return self
                .record_user_type(
                    node,
                    WalkContext {
                        scope,
                        owner_type: None,
                        callable: None,
                        declaration: owner,
                        singleton_owner: false,
                        receiver_frame: None,
                    },
                )
                .expect("Kotlin user type has a positioned type segment");
        }
        if node.kind() == "function_type" {
            let site = self.add_site(node, ResolutionSiteKind::TypeReference, scope);
            let slot = self.add_slot(site, ResolutionTypeSlotRole::TargetTypeIdentity);
            self.type_slots_by_node.insert(node.id(), slot);
            let arity = u32::try_from(kotlin_function_type_arity(node))
                .expect("Kotlin function type arity fits u32");
            self.pending_applied_types.push((slot, node, scope, owner));
            let function_name = self.intern_name(&format!("kotlin.Function{arity}"));
            self.facts.intrinsic_type_seeds.push(IntrinsicTypeSeedFact {
                output: slot,
                name: function_name,
                kind: IntrinsicTypeKind::LanguageBuiltin,
                indirection: 0,
            });
            return slot;
        }
        let nested = named_children(node)
            .into_iter()
            .find(|child| {
                KOTLIN_TYPE_NODE_KINDS.contains(&child.kind()) || child.kind() == "user_type"
            })
            .unwrap_or(node);
        if nested.id() != node.id() {
            let slot = self.ensure_type_slot(nested, scope, owner);
            self.type_slots_by_node.insert(node.id(), slot);
            return slot;
        }
        let site = self.add_site(node, ResolutionSiteKind::TypeReference, scope);
        let slot = self.add_slot(site, ResolutionTypeSlotRole::TargetTypeIdentity);
        self.facts.gaps.push(ResolutionGapFact::new(
            site,
            ResolutionGapKind::UnsupportedTypeSyntax,
        ));
        self.type_slots_by_node.insert(node.id(), slot);
        slot
    }

    fn finish_applied_type_arguments(&mut self) {
        while let Some((owner, function, scope, declaration)) = self.pending_applied_types.pop() {
            let types = if function.kind() == "function_type" {
                let (mut types, result) = kotlin_function_type_parts(function);
                types.push(result);
                types
            } else {
                assert_eq!(function.kind(), "type_arguments");
                let Some(types) = named_children(function)
                    .into_iter()
                    .map(|projection| {
                        named_children(projection).into_iter().find(|ty| {
                            KOTLIN_TYPE_NODE_KINDS.contains(&ty.kind()) || ty.kind() == "user_type"
                        })
                    })
                    .collect::<Option<Vec<_>>>()
                else {
                    // A star projection has no exact argument type. Do not
                    // shift the ordinals of later arguments into its place.
                    continue;
                };
                types
            };
            let arguments = types
                .into_iter()
                .map(|ty| self.ensure_type_slot(ty, scope, declaration))
                .collect::<Vec<_>>();
            let site = if function.kind() == "function_type" {
                self.facts.type_slots[owner.index()].site
            } else {
                // The nominal head already has a lexical identity producer.
                // Argument projections must not observe or rebind that name.
                self.add_site(function, ResolutionSiteKind::TypeReference, scope)
            };
            crate::call_arguments::publish_jvm_function_type_arguments(
                &mut self.facts,
                owner,
                site,
                &arguments,
            );
        }
    }

    fn add_declared_type(
        &mut self,
        declaration: ResolutionSiteId,
        type_node: Node<'source>,
        scope: ResolutionScopeId,
        slot_role: ResolutionTypeSlotRole,
        declaration_role: DeclarationTypeRole,
        owner: Option<ResolutionSiteId>,
    ) -> ResolutionTypeSlotId {
        let target = self.ensure_type_slot(type_node, scope, owner);
        let output = self.add_slot(declaration, slot_role);
        self.facts
            .declaration_type_slots
            .push(DeclarationTypeSlotFact {
                declaration,
                slot: output,
                role: declaration_role,
            });
        crate::call_arguments::publish_jvm_declared_type_transfer(
            &mut self.facts,
            target,
            output,
            ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
        );
        output
    }

    fn record_nullable_type(&mut self, node: Node<'source>, scope: ResolutionScopeId) {
        // Nominal nullable types retain their underlying navigation identity;
        // nullable function syntax cannot publish a non-null invoke proof.
        self.ensure_type_slot(node, scope, None);
    }

    fn add_type_identity(&mut self, declaration: ResolutionSiteId) -> ResolutionTypeSlotId {
        let slot = self.add_slot(declaration, ResolutionTypeSlotRole::TargetTypeIdentity);
        self.facts
            .declaration_type_slots
            .push(DeclarationTypeSlotFact {
                declaration,
                slot,
                role: DeclarationTypeRole::Identity,
            });
        slot
    }

    fn add_binder(
        &mut self,
        declaration: ResolutionSiteId,
        scope: ResolutionScopeId,
        kind: ResolutionBinderKind,
        scope_wide: bool,
    ) {
        let scope_fact = self.facts.scopes[scope.index()];
        let site = self.facts.sites[declaration.index()];
        if matches!(
            kind,
            ResolutionBinderKind::Field
                | ResolutionBinderKind::Local
                | ResolutionBinderKind::Parameter
        ) {
            // Value binders can compete in call lookup through invoke. The
            // shared reader proves applicability from their declared types.
            self.facts.additional_definition_namespaces.push(
                ResolutionAdditionalDefinitionNamespaceFact {
                    declaration,
                    namespace: ResolutionNamespace::Callable,
                    hoisting: if scope_wide {
                        HoistingClass::ScopeWide
                    } else {
                        HoistingClass::SourceOrder
                    },
                },
            );
        }
        self.facts.binders.push(ResolutionBinderFact {
            declaration,
            scope,
            kind,
            hoisting: if scope_wide {
                HoistingClass::ScopeWide
            } else {
                HoistingClass::SourceOrder
            },
            activation_start: if scope_wide {
                scope_fact.start_byte
            } else {
                site.end_byte
            },
            activation_end: scope_fact.end_byte,
        });
    }

    fn add_visibility(&mut self, declaration: ResolutionSiteId, node: Node<'_>) {
        let visibility = match super::declarations::kotlin_declared_visibility(node, self.source) {
            super::declarations::KotlinDeclaredVisibility::Public => DeclaredVisibility::Public,
            super::declarations::KotlinDeclaredVisibility::Protected => {
                DeclaredVisibility::Protected
            }
            super::declarations::KotlinDeclaredVisibility::Internal => DeclaredVisibility::Internal,
            super::declarations::KotlinDeclaredVisibility::Private => DeclaredVisibility::Private,
        };
        self.facts
            .visibility_eligibilities
            .push(ResolutionVisibilityEligibilityFact { declaration });
        self.facts
            .declaration_visibilities
            .push(ResolutionDeclarationVisibilityFact {
                declaration,
                visibility,
            });
        // Kotlin top-level private declarations are file-local. Their lexical
        // binders are visible inside this file and package-member publication
        // already excludes them, so no unsupported visibility rule remains.
        let file_private = visibility == DeclaredVisibility::Private
            && self.facts.sites[declaration.index()].scope == self.package_scope;
        if visibility != DeclaredVisibility::Public && !file_private {
            self.facts.gaps.push(ResolutionGapFact::new(
                declaration,
                ResolutionGapKind::UnsupportedVisibility,
            ));
        }
    }

    fn add_package_membership(
        &mut self,
        declaration: ResolutionSiteId,
        namespace: ResolutionNamespace,
        scope: ResolutionScopeId,
        node: Node<'_>,
    ) {
        if scope != self.package_scope {
            return;
        }
        let visibility = super::declarations::kotlin_declared_visibility(node, self.source);
        if visibility == super::declarations::KotlinDeclaredVisibility::Private {
            return;
        }
        self.facts
            .package_members
            .push(ResolutionPackageMemberFact {
                root_scope: self.package_scope,
                declaration,
                namespace,
            });
        if visibility == super::declarations::KotlinDeclaredVisibility::Public {
            self.facts.root_exports.push(ResolutionRootExportFact {
                root_scope: self.package_scope,
                declaration,
                namespace,
            });
        }
    }

    fn add_callable_signature(&mut self, callable: ResolutionSiteId, node: Node<'source>) {
        self.facts
            .callable_signatures
            .push(ResolutionCallableSignatureFact {
                callable,
                type_parameter_count: u32::try_from(
                    super::syntax::kotlin_declared_type_parameter_names(node, self.source).len(),
                )
                .expect("Kotlin type parameter count fits u32"),
                result_types: Vec::new(),
            });
        self.facts
            .callable_parameter_lists
            .push(ResolutionCallableParameterListFact {
                callable,
                list_ordinal: 0,
                contextual: false,
            });
    }

    fn jvm_owner_segments(
        &mut self,
        owner: Option<ResolutionSiteId>,
    ) -> Option<Vec<ResolutionNameId>> {
        let mut segments = self.package_names.clone();
        let Some(mut current) = owner else {
            segments.push(self.facade_name?);
            return Some(segments);
        };
        let mut nesting = Vec::new();
        loop {
            nesting.push(*self.type_names.get(&current)?);
            current = match *self.type_parents.get(&current)? {
                Some(parent) => parent,
                None => break,
            };
        }
        nesting.reverse();
        let binary_name = nesting
            .iter()
            .map(|name| self.facts.names[name.index()].spelling.as_str())
            .collect::<Vec<_>>()
            .join("$");
        segments.push(self.intern_name(&binary_name));
        Some(segments)
    }

    fn jvm_static_bridge_owner(&self, owner: Option<ResolutionSiteId>) -> Option<ResolutionSiteId> {
        owner.and_then(|owner| {
            if self.companion_types.contains(&owner) {
                self.type_parents.get(&owner).copied().flatten()
            } else {
                Some(owner)
            }
        })
    }

    fn binary_owner_route(
        &mut self,
        owner: Option<ResolutionSiteId>,
    ) -> ResolutionBinaryOwnerRoute {
        match self.jvm_owner_segments(owner) {
            Some(segments) => ResolutionBinaryOwnerRoute::Exact(segments),
            None => ResolutionBinaryOwnerRoute::UnknownWithin {
                scope: self.package_scope,
                prefix: self.package_names.clone(),
            },
        }
    }

    fn default_impls_binary_owner_route(
        &mut self,
        owner: Option<ResolutionSiteId>,
    ) -> ResolutionBinaryOwnerRoute {
        match self.binary_owner_route(owner) {
            ResolutionBinaryOwnerRoute::Exact(mut segments) => {
                let owner = segments.pop().expect("interface binary owner");
                let owner = format!("{}$DefaultImpls", self.facts.names[owner.index()].spelling);
                segments.push(self.intern_name(&owner));
                ResolutionBinaryOwnerRoute::Exact(segments)
            }
            unknown => unknown,
        }
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
        let id = ResolutionJvmAliasId::try_from_index(self.facts.jvm_aliases.len())
            .expect("Kotlin JVM alias count fits u32");
        self.facts.jvm_aliases.push(ResolutionJvmAliasFact {
            id,
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
                        alias: id,
                        ordinal: u32::try_from(ordinal).expect("Kotlin JVM owner path fits u32"),
                        name,
                    }),
            );
    }

    #[allow(clippy::too_many_arguments)]
    fn add_jvm_alias_for_owner(
        &mut self,
        declaration: ResolutionSiteId,
        member_name: ResolutionNameId,
        kind: ResolutionJvmAliasKind,
        is_static: bool,
        parameter_count: u32,
        status: ResolutionJvmAliasStatus,
        owner: Option<ResolutionSiteId>,
    ) {
        // An anonymous type and its nested declarations have no source-named
        // JVM export route. Their members remain ordinary receiver members;
        // absence of an export alias is not an unsupported source route.
        let mut enclosing = owner;
        while let Some(current) = enclosing {
            if self.anonymous_type_owners.contains(&current) {
                return;
            }
            enclosing = self.type_parents.get(&current).copied().flatten();
        }
        if let Some(owner_segments) = self.jvm_owner_segments(owner) {
            self.add_jvm_alias(
                declaration,
                member_name,
                kind,
                is_static,
                parameter_count,
                status,
                owner_segments,
            );
        } else {
            let binary_owner = self.binary_owner_route(owner);
            self.facts.add_route_gap(
                declaration,
                ResolutionRouteGap::UnknownAlias {
                    binary_owner,
                    owner: owner.map(ResolutionRouteOwner::Declaration).unwrap_or(
                        ResolutionRouteOwner::JvmFacade {
                            scope: self.package_scope,
                            name: self.facade_name,
                        },
                    ),
                    name: Some(member_name),
                    kind: Some(kind),
                },
            );
        }
        if owner.is_none() {
            self.add_multifile_part_gap(declaration, Some(member_name), Some(kind));
        }
    }

    fn jvm_alias_status(
        &self,
        node: Node<'_>,
        context: WalkContext,
        top_level: bool,
    ) -> ResolutionJvmAliasStatus {
        let owner_uses_value_class = context
            .owner_type
            .is_some_and(|owner| self.value_class_types.contains(&owner));
        let uses_value_class = if owner_uses_value_class {
            true
        } else {
            let mut stack = vec![node];
            let mut found = false;
            while let Some(current) = stack.pop() {
                if current.kind() == "user_type"
                    && kotlin_user_type_segments(current)
                        .last()
                        .is_some_and(|name| {
                            self.annotation_proofs
                                .value_classes
                                .contains(kotlin_identifier_text(*name, self.source))
                        })
                {
                    found = true;
                    break;
                }
                stack.extend(named_children(current));
            }
            found
        };
        let compiler_dependent = (top_level && self.multifile_file)
            || matches!(
                super::declarations::kotlin_declared_visibility(node, self.source),
                super::declarations::KotlinDeclaredVisibility::Internal
            )
            || kotlin_has_modifier(node, "suspend")
            || uses_value_class;
        if compiler_dependent {
            ResolutionJvmAliasStatus::CompilerModeDependent
        } else {
            ResolutionJvmAliasStatus::SourceProven
        }
    }

    fn add_callable_jvm_aliases(
        &mut self,
        node: Node<'source>,
        declaration: ResolutionSiteId,
        context: WalkContext,
        constructor: bool,
    ) {
        let source_name = if constructor {
            context
                .owner_type
                .and_then(|owner| self.type_names.get(&owner).copied())
                .map(|name| self.facts.names[name.index()].spelling.clone())
        } else {
            first_named_child_of_kind(node, "simple_identifier")
                .map(|name| kotlin_identifier_text(name, self.source).to_owned())
        };
        let Some(source_name) = source_name else {
            return;
        };
        let jvm_name = if constructor {
            None
        } else {
            self.jvm_name_override(node, None)
        };
        let member_name = match jvm_name {
            Some(Some(name)) => name,
            Some(None) => {
                self.add_unsupported_route_gap(
                    declaration,
                    context.owner_type,
                    None,
                    Some(ResolutionJvmAliasKind::Method),
                );
                if context.singleton_owner
                    && self.has_jvm_annotation(node, None, &["kotlin", "jvm", "JvmStatic"])
                {
                    let bridge_owner = context.owner_type.and_then(|owner| {
                        if self.companion_types.contains(&owner) {
                            self.type_parents.get(&owner).copied().flatten()
                        } else {
                            Some(owner)
                        }
                    });
                    self.add_unsupported_route_gap(
                        declaration,
                        bridge_owner,
                        None,
                        Some(ResolutionJvmAliasKind::Method),
                    );
                }
                if context
                    .owner_type
                    .is_some_and(|owner| self.interface_types.contains(&owner))
                    && first_named_child_of_kind(node, "function_body").is_some()
                {
                    let binary_owner = self.default_impls_binary_owner_route(context.owner_type);
                    self.facts.add_route_gap(
                        declaration,
                        ResolutionRouteGap::UnknownAlias {
                            owner: ResolutionRouteOwner::Declaration(
                                context.owner_type.expect("interface owner"),
                            ),
                            binary_owner,
                            name: None,
                            kind: Some(ResolutionJvmAliasKind::Method),
                        },
                    );
                }
                return;
            }
            None => source_name,
        };
        let parameter_nodes = callable_parameter_nodes(node);
        let source_parameters =
            u32::try_from(parameter_nodes.len()).expect("Kotlin callable parameter count fits u32");
        let extension_receiver =
            u32::from(!constructor && node.child_by_field_name("receiver").is_some());
        let base_parameter_count = source_parameters
            .checked_add(extension_receiver)
            .expect("Kotlin JVM parameter count fits u32");
        let trailing_defaults = u32::try_from(
            parameter_nodes
                .iter()
                .rev()
                .take_while(|parameter| kotlin_parameter_default(**parameter).is_some())
                .count(),
        )
        .expect("Kotlin default parameter count fits u32");
        let overloads = self.has_jvm_annotation(node, None, &["kotlin", "jvm", "JvmOverloads"]);
        let mut counts = vec![base_parameter_count];
        if overloads {
            for omitted in 1..=trailing_defaults {
                counts.push(
                    base_parameter_count
                        .checked_sub(omitted)
                        .expect("trailing defaults do not exceed Kotlin JVM parameters"),
                );
            }
        }
        let status = self.jvm_alias_status(node, context, context.owner_type.is_none());
        let name = self.intern_name(&member_name);
        let kind = if constructor {
            ResolutionJvmAliasKind::Constructor
        } else {
            ResolutionJvmAliasKind::Method
        };
        for parameter_count in counts {
            self.add_jvm_alias_for_owner(
                declaration,
                name,
                kind,
                context.owner_type.is_none(),
                parameter_count,
                status,
                context.owner_type,
            );
            if !constructor
                && context.singleton_owner
                && self.has_jvm_annotation(node, None, &["kotlin", "jvm", "JvmStatic"])
            {
                let bridge_owner = context.owner_type.and_then(|owner| {
                    if self.companion_types.contains(&owner) {
                        self.type_parents.get(&owner).copied().flatten()
                    } else {
                        Some(owner)
                    }
                });
                self.add_jvm_alias_for_owner(
                    declaration,
                    name,
                    ResolutionJvmAliasKind::Method,
                    true,
                    parameter_count,
                    status,
                    bridge_owner,
                );
            }
            if !constructor
                && context
                    .owner_type
                    .is_some_and(|owner| self.interface_types.contains(&owner))
                && first_named_child_of_kind(node, "function_body").is_some()
            {
                if let Some(mut owner_segments) = self.jvm_owner_segments(context.owner_type) {
                    let owner = owner_segments.pop().expect("interface binary owner");
                    let owner =
                        format!("{}$DefaultImpls", self.facts.names[owner.index()].spelling);
                    owner_segments.push(self.intern_name(&owner));
                    self.add_jvm_alias(
                        declaration,
                        name,
                        ResolutionJvmAliasKind::Method,
                        true,
                        parameter_count
                            .checked_add(1)
                            .expect("DefaultImpls receiver count fits u32"),
                        ResolutionJvmAliasStatus::CompilerModeDependent,
                        owner_segments,
                    );
                } else {
                    let binary_owner = self.default_impls_binary_owner_route(context.owner_type);
                    self.facts.add_route_gap(
                        declaration,
                        ResolutionRouteGap::UnknownAlias {
                            owner: context
                                .owner_type
                                .map(ResolutionRouteOwner::Declaration)
                                .expect("interface owner"),
                            binary_owner,
                            name: Some(name),
                            kind: Some(ResolutionJvmAliasKind::Method),
                        },
                    );
                }
            }
        }
    }

    fn add_property_jvm_aliases(
        &mut self,
        node: Node<'source>,
        declaration: ResolutionSiteId,
        context: WalkContext,
        source_name: &str,
    ) {
        let is_constructor_property = node.kind() == "class_parameter";
        let is_type_member =
            self.facts.scopes[context.scope.index()].kind == ResolutionScopeKind::TypeBody;
        let top_level = context.owner_type.is_none() && context.scope == self.package_scope;
        if !is_constructor_property && !top_level && !is_type_member {
            return;
        }
        let has_jvm_field = self.has_jvm_annotation(node, None, &["kotlin", "jvm", "JvmField"])
            || self.has_jvm_annotation(node, Some("field"), &["kotlin", "jvm", "JvmField"]);
        let const_property = kotlin_has_modifier(node, "const");
        let companion_owner = context
            .owner_type
            .is_some_and(|owner| self.companion_types.contains(&owner));
        let field_owner = if companion_owner {
            context
                .owner_type
                .and_then(|owner| self.type_parents.get(&owner).copied().flatten())
        } else {
            context.owner_type
        };
        let getter_annotation = first_named_child_of_kind(node, "getter");
        let setter_annotation = first_named_child_of_kind(node, "setter");
        let getter_static =
            self.has_jvm_annotation(node, Some("get"), &["kotlin", "jvm", "JvmStatic"])
                || getter_annotation.is_some_and(|getter| {
                    self.has_jvm_annotation(getter, None, &["kotlin", "jvm", "JvmStatic"])
                });
        let setter_static =
            self.has_jvm_annotation(node, Some("set"), &["kotlin", "jvm", "JvmStatic"])
                || setter_annotation.is_some_and(|setter| {
                    self.has_jvm_annotation(setter, None, &["kotlin", "jvm", "JvmStatic"])
                });
        let is_var = first_named_child_of_kind(node, "binding_pattern_kind")
            .is_some_and(|binding| binding.utf8_text(self.source.as_bytes()).ok() == Some("var"));
        let setter_visible = is_var
            && !setter_annotation.is_some_and(|setter| {
                super::declarations::kotlin_declared_visibility(setter, self.source)
                    == super::declarations::KotlinDeclaredVisibility::Private
            });
        if self.has_unresolved_jvm_annotation(node, None, &["kotlin", "jvm", "JvmField"])
            && !has_jvm_field
        {
            let name = self.intern_name(source_name);
            self.add_unsupported_route_gap(
                declaration,
                field_owner,
                Some(name),
                Some(ResolutionJvmAliasKind::Field),
            );
            // An unresolved JvmField may leave ordinary accessor projections,
            // on the property's source owner, instead of the enclosing field.
            let getter = self
                .jvm_name_override(node, Some("get"))
                .or_else(|| {
                    getter_annotation.and_then(|getter| self.jvm_name_override(getter, None))
                })
                .unwrap_or_else(|| Some(kotlin_getter_name(source_name)));
            let getter = getter.map(|name| self.intern_name(&name));
            self.add_unsupported_route_gap(
                declaration,
                context.owner_type,
                getter,
                Some(ResolutionJvmAliasKind::Getter),
            );
            if getter_static && !top_level && context.singleton_owner {
                let bridge_owner = self.jvm_static_bridge_owner(context.owner_type);
                self.add_unsupported_route_gap(
                    declaration,
                    bridge_owner,
                    getter,
                    Some(ResolutionJvmAliasKind::Getter),
                );
            }
            if setter_visible {
                let setter = self
                    .jvm_name_override(node, Some("set"))
                    .or_else(|| {
                        setter_annotation.and_then(|setter| self.jvm_name_override(setter, None))
                    })
                    .unwrap_or_else(|| Some(kotlin_setter_name(source_name)));
                let setter = setter.map(|name| self.intern_name(&name));
                self.add_unsupported_route_gap(
                    declaration,
                    context.owner_type,
                    setter,
                    Some(ResolutionJvmAliasKind::Setter),
                );
                if setter_static && !top_level && context.singleton_owner {
                    let bridge_owner = self.jvm_static_bridge_owner(context.owner_type);
                    self.add_unsupported_route_gap(
                        declaration,
                        bridge_owner,
                        setter,
                        Some(ResolutionJvmAliasKind::Setter),
                    );
                }
            }
            return;
        }
        if has_jvm_field || const_property {
            let owner = field_owner;
            let name = self.intern_name(source_name);
            self.add_jvm_alias_for_owner(
                declaration,
                name,
                ResolutionJvmAliasKind::Field,
                top_level || context.singleton_owner || companion_owner,
                0,
                self.jvm_alias_status(node, context, top_level),
                owner,
            );
            return;
        }

        let receiver_parameters = u32::from(node.child_by_field_name("receiver").is_some());
        let getter_name = self
            .jvm_name_override(node, Some("get"))
            .or_else(|| getter_annotation.and_then(|getter| self.jvm_name_override(getter, None)));
        let getter_name = match getter_name {
            Some(Some(name)) => Some(name),
            Some(None) => {
                self.add_unsupported_route_gap(
                    declaration,
                    context.owner_type,
                    None,
                    Some(ResolutionJvmAliasKind::Getter),
                );
                if getter_static && !top_level && context.singleton_owner {
                    let bridge_owner = self.jvm_static_bridge_owner(context.owner_type);
                    self.add_unsupported_route_gap(
                        declaration,
                        bridge_owner,
                        None,
                        Some(ResolutionJvmAliasKind::Getter),
                    );
                }
                None
            }
            None => Some(kotlin_getter_name(source_name)),
        };
        let status = self.jvm_alias_status(node, context, top_level);
        if let Some(getter_name) = getter_name {
            let getter_id = self.intern_name(&getter_name);
            self.add_jvm_alias_for_owner(
                declaration,
                getter_id,
                ResolutionJvmAliasKind::Getter,
                top_level,
                receiver_parameters,
                status,
                context.owner_type,
            );
            if getter_static && !top_level && context.singleton_owner {
                let bridge_owner = context.owner_type.and_then(|owner| {
                    if self.companion_types.contains(&owner) {
                        self.type_parents.get(&owner).copied().flatten()
                    } else {
                        Some(owner)
                    }
                });
                self.add_jvm_alias_for_owner(
                    declaration,
                    getter_id,
                    ResolutionJvmAliasKind::Getter,
                    true,
                    receiver_parameters,
                    status,
                    bridge_owner,
                );
            }
        }
        if !setter_visible {
            return;
        }
        let setter_name = self
            .jvm_name_override(node, Some("set"))
            .or_else(|| setter_annotation.and_then(|setter| self.jvm_name_override(setter, None)));
        let setter_name = match setter_name {
            Some(Some(name)) => name,
            Some(None) => {
                self.add_unsupported_route_gap(
                    declaration,
                    context.owner_type,
                    None,
                    Some(ResolutionJvmAliasKind::Setter),
                );
                if setter_static && !top_level && context.singleton_owner {
                    let bridge_owner = self.jvm_static_bridge_owner(context.owner_type);
                    self.add_unsupported_route_gap(
                        declaration,
                        bridge_owner,
                        None,
                        Some(ResolutionJvmAliasKind::Setter),
                    );
                }
                return;
            }
            None => kotlin_setter_name(source_name),
        };
        let setter_id = self.intern_name(&setter_name);
        let setter_parameters = receiver_parameters
            .checked_add(1)
            .expect("Kotlin property setter parameter count fits u32");
        self.add_jvm_alias_for_owner(
            declaration,
            setter_id,
            ResolutionJvmAliasKind::Setter,
            top_level,
            setter_parameters,
            status,
            context.owner_type,
        );
        if setter_static && !top_level && context.singleton_owner {
            let bridge_owner = context.owner_type.and_then(|owner| {
                if self.companion_types.contains(&owner) {
                    self.type_parents.get(&owner).copied().flatten()
                } else {
                    Some(owner)
                }
            });
            self.add_jvm_alias_for_owner(
                declaration,
                setter_id,
                ResolutionJvmAliasKind::Setter,
                true,
                setter_parameters,
                status,
                bridge_owner,
            );
        }
    }

    fn has_jvm_annotation(
        &self,
        node: Node<'_>,
        use_site: Option<&str>,
        expected: &[&str],
    ) -> bool {
        declaration_annotations(node).into_iter().any(|annotation| {
            annotation_use_site(annotation, self.source).as_deref() == use_site
                && self
                    .annotation_proofs
                    .annotation_denotes(annotation, expected, self.source)
        })
    }

    fn has_unresolved_jvm_annotation(
        &self,
        node: Node<'_>,
        use_site: Option<&str>,
        expected: &[&str],
    ) -> bool {
        declaration_annotations(node).into_iter().any(|annotation| {
            annotation_use_site(annotation, self.source).as_deref() == use_site
                && annotation_has_simple_name(
                    annotation,
                    expected.last().copied().unwrap_or(""),
                    self.source,
                )
                && !self
                    .annotation_proofs
                    .annotation_denotes(annotation, expected, self.source)
        })
    }

    fn jvm_name_override(&self, node: Node<'_>, use_site: Option<&str>) -> Option<Option<String>> {
        declaration_annotations(node)
            .into_iter()
            .find_map(|annotation| {
                if annotation_use_site(annotation, self.source).as_deref() != use_site
                    || !self.annotation_proofs.annotation_denotes(
                        annotation,
                        &["kotlin", "jvm", "JvmName"],
                        self.source,
                    )
                {
                    return None;
                }
                Some(annotation_string_argument(annotation, self.source))
            })
    }

    fn add_unsupported_route_gap(
        &mut self,
        site: ResolutionSiteId,
        owner: Option<ResolutionSiteId>,
        name: Option<ResolutionNameId>,
        kind: Option<ResolutionJvmAliasKind>,
    ) {
        let binary_owner = self.binary_owner_route(owner);
        self.facts.add_route_gap(
            site,
            ResolutionRouteGap::UnknownAlias {
                binary_owner,
                owner: owner.map(ResolutionRouteOwner::Declaration).unwrap_or(
                    ResolutionRouteOwner::JvmFacade {
                        scope: self.package_scope,
                        name: self.facade_name,
                    },
                ),
                name,
                kind,
            },
        );
        if owner.is_none() {
            self.add_multifile_part_gap(site, name, kind);
        }
    }

    fn add_multifile_part_gap(
        &mut self,
        site: ResolutionSiteId,
        name: Option<ResolutionNameId>,
        kind: Option<ResolutionJvmAliasKind>,
    ) {
        if self.multifile_file {
            self.facts.add_route_gap(
                site,
                ResolutionRouteGap::UnknownAlias {
                    owner: ResolutionRouteOwner::JvmFacade {
                        scope: self.package_scope,
                        name: self.facade_name,
                    },
                    binary_owner: ResolutionBinaryOwnerRoute::UnknownWithin {
                        scope: self.package_scope,
                        prefix: self.package_names.clone(),
                    },
                    name,
                    kind,
                },
            );
        }
    }

    fn parameter_is_vararg(&self, node: Node<'_>) -> bool {
        if let Some(modifiers) = first_named_child_of_kind(node, "modifiers") {
            return brokk_bifrost_core::analyzer::tree_walk::has_token_child(modifiers, "vararg");
        }
        node.prev_named_sibling()
            .filter(|sibling| sibling.kind() == "parameter_modifiers")
            .is_some_and(|modifiers| {
                brokk_bifrost_core::analyzer::tree_walk::has_token_child(modifiers, "vararg")
            })
    }

    fn record_identifier_reference(&mut self, node: Node<'source>, context: WalkContext) {
        if self.handled_identifiers.contains(&node.id())
            || kotlin_is_declaration_name(node)
            || kotlin_enclosing_import_header(node).is_some()
            || node
                .parent()
                .is_some_and(|parent| matches!(parent.kind(), "package_header" | "label"))
        {
            return;
        }
        if let Some(argument) = node
            .parent()
            .filter(|parent| parent.kind() == "value_argument")
            && kotlin_named_argument_label(argument, node)
        {
            self.handled_identifiers.insert(node.id());
            return;
        }
        if kotlin_identifier_text(node, self.source).is_empty() {
            let site = self.add_site(node, ResolutionSiteKind::UnsupportedRoute, context.scope);
            self.facts.gaps.push(ResolutionGapFact::new(
                site,
                ResolutionGapKind::MalformedSyntax,
            ));
            return;
        }

        let parent = node.parent();
        let is_navigation_receiver = parent.is_some_and(|parent| {
            kotlin_is_navigation_kind(parent.kind())
                && kotlin_navigation_receiver(parent)
                    .is_some_and(|receiver| receiver.id() == node.id())
        });
        let navigation = parent
            .filter(|parent| kotlin_is_navigation_kind(parent.kind()))
            .or_else(|| {
                parent
                    .filter(|parent| parent.kind() == "navigation_suffix")
                    .and_then(|suffix| suffix.parent())
                    .filter(|parent| kotlin_is_navigation_kind(parent.kind()))
            });
        let is_navigation_member = navigation.is_some_and(|navigation| {
            kotlin_navigation_member(navigation).is_some_and(|member| member.id() == node.id())
        });
        let is_call_callee = kotlin_call_with_callee(node).is_some()
            || (is_navigation_member
                && navigation
                    .is_some_and(|navigation| kotlin_call_with_callee(navigation).is_some()));
        let explicit_this_owner = if is_navigation_member {
            navigation
                .and_then(kotlin_navigation_receiver)
                .and_then(|receiver| {
                    self.this_expression_receiver(receiver, context.receiver_frame)
                        .and_then(|receiver| match receiver {
                            KotlinReceiver::Dispatch(owner)
                            | KotlinReceiver::AnonymousDispatch(owner) => Some(owner),
                            KotlinReceiver::Extension(_) => None,
                        })
                })
        } else {
            None
        };
        let (kind, namespace, qualifier) = if is_navigation_receiver {
            (
                ResolutionSiteKind::ValueReference,
                ResolutionNamespace::TypeOrValue,
                None,
            )
        } else if node.kind() == "type_identifier" {
            (
                ResolutionSiteKind::TypeReference,
                ResolutionNamespace::Type,
                None,
            )
        } else if is_navigation_member && explicit_this_owner.is_some() {
            // `this.member` is a lookup of `member` in the enclosing type's
            // body, as the receiver is the current instance: no qualifier.
            (
                ResolutionSiteKind::MemberReference,
                if is_call_callee {
                    ResolutionNamespace::Callable
                } else {
                    ResolutionNamespace::Value
                },
                None,
            )
        } else if is_navigation_member {
            let qualifier = navigation
                .and_then(kotlin_navigation_receiver)
                .map(|receiver| {
                    self.expression_slot(receiver, context, ResolutionTypeSlotRole::ExpressionValue)
                });
            (
                if is_call_callee {
                    ResolutionSiteKind::CallableReference
                } else {
                    ResolutionSiteKind::MemberReference
                },
                if is_call_callee {
                    ResolutionNamespace::Callable
                } else {
                    ResolutionNamespace::TypeOrValue
                },
                qualifier,
            )
        } else if is_call_callee {
            (
                ResolutionSiteKind::CallableReference,
                ResolutionNamespace::Callable,
                None,
            )
        } else {
            (
                ResolutionSiteKind::ValueReference,
                ResolutionNamespace::Value,
                None,
            )
        };
        let reference_scope = match explicit_this_owner {
            Some(owner) => self.ensure_type_body_scope(owner),
            None => context.scope,
        };
        let site = self.add_identifier(
            node,
            kind,
            namespace,
            ResolutionIdentifierRole::Reference,
            reference_scope,
            qualifier,
        );
        if !is_call_callee
            && matches!(
                kind,
                ResolutionSiteKind::ValueReference | ResolutionSiteKind::MemberReference
            )
        {
            let output = self.add_slot(site, ResolutionTypeSlotRole::ExpressionValue);
            self.facts.binding_projections.push(BindingProjectionFact {
                reference: site,
                output,
                kind: if (kind == ResolutionSiteKind::ValueReference && !is_navigation_receiver)
                    || explicit_this_owner.is_some()
                {
                    BindingProjectionKind::TargetDeclaredValueType
                } else {
                    BindingProjectionKind::TargetTypeOrDeclaredValueType
                },
            });
            self.expression_slots_by_node
                .insert((node.id(), ResolutionTypeSlotRole::ExpressionValue), output);
        }
        if let Some(owner) = context.declaration {
            self.facts
                .reference_owners
                .push(ResolutionReferenceOwnerFact {
                    reference: site,
                    owner: Some(owner),
                });
        }
    }

    fn expression_slot(
        &mut self,
        node: Node<'source>,
        context: WalkContext,
        role: ResolutionTypeSlotRole,
    ) -> ResolutionTypeSlotId {
        if let Some(slot) = self
            .expression_slots_by_node
            .get(&(node.id(), role))
            .copied()
        {
            return slot;
        }
        if node.kind() == "call_expression"
            && let Some(slot) = self.call_result_slots.get(&node.id()).copied()
        {
            self.expression_slots_by_node
                .insert((node.id(), role), slot);
            return slot;
        }
        let mut expression = node;
        while expression.kind() == "parenthesized_expression" {
            let children = named_children(expression);
            if let [child] = children.as_slice() {
                expression = *child;
            } else {
                break;
            }
        }
        if expression.kind() == "annotated_lambda"
            && let Some(lambda) = first_named_child_of_kind(expression, "lambda_literal")
        {
            expression = lambda;
        }
        if let Some(slot) = self
            .expression_slots_by_node
            .get(&(expression.id(), role))
            .or_else(|| self.call_result_slots.get(&expression.id()))
            .copied()
        {
            self.expression_slots_by_node
                .insert((node.id(), role), slot);
            return slot;
        }
        let scope = context.scope;
        let slot = if let Some(site) = self.sites_by_node.get(&expression.id()).copied() {
            self.add_slot(site, role)
        } else if expression.kind() == "simple_identifier" {
            let site = self.add_identifier(
                expression,
                ResolutionSiteKind::ValueReference,
                ResolutionNamespace::TypeOrValue,
                ResolutionIdentifierRole::Reference,
                scope,
                None,
            );
            if let Some(owner) = context.declaration {
                self.facts
                    .reference_owners
                    .push(ResolutionReferenceOwnerFact {
                        reference: site,
                        owner: Some(owner),
                    });
            }
            let slot = self.add_slot(site, role);
            self.facts.binding_projections.push(BindingProjectionFact {
                reference: site,
                output: slot,
                kind: BindingProjectionKind::TargetDeclaredValueType,
            });
            slot
        } else if expression.kind() == "navigation_expression"
            && let Some(member) = kotlin_navigation_member(expression)
            && let Some(site) = self.sites_by_node.get(&member.id()).copied()
        {
            // The member reference already published its slot and projection
            // in record_identifier_reference. A second slot on the same site
            // would have no producer, so the member's own value is reused.
            match self
                .expression_slots_by_node
                .get(&(member.id(), ResolutionTypeSlotRole::ExpressionValue))
                .copied()
            {
                Some(slot) if role == ResolutionTypeSlotRole::ExpressionValue => slot,
                _ => self.add_slot(site, role),
            }
        } else if expression.kind() == "callable_reference"
            && expression
                .child(expression.child_count() - 1)
                .is_some_and(|token| token.kind() == "class")
            && let Some(operand) = first_named_child_of_kind(expression, "type_identifier")
        {
            let operand_name = kotlin_identifier_text(operand, self.source);
            let argument = self.record_qualified_type_path(&[(operand, operand_name)], context);
            self.handled_identifiers.insert(operand.id());
            let identity = self.record_qualified_type_path(
                &[
                    (expression, "kotlin"),
                    (expression, "reflect"),
                    (expression, "KClass"),
                ],
                context,
            );
            // KClass is the compiler-defined reflection type, not a source
            // spelling whose `kotlin` prefix can be obscured by imports. Bind
            // its absolute package route to the selected declaration (including
            // a workspace stdlib stand-in) without a lexical prefix obligation.
            let root = self
                .facts
                .root_references
                .last_mut()
                .expect("qualified KClass root");
            assert_eq!(root.reference, self.facts.type_slots[identity.index()].site);
            root.anchor = ResolutionRootImportAnchor::Absolute;
            root.prefix_reference = None;
            self.facts
                .declared_type_arguments
                .push(ResolutionDeclaredTypeArgumentFact {
                    owner: identity,
                    ordinal: 0,
                    argument,
                });
            self.facts.type_arguments.push(ResolutionTypeArgumentFact {
                application: identity,
                ordinal: 0,
                argument,
                indirection_delta: 0,
                reference_indirection_delta: 0,
            });
            let site = self.add_site(expression, ResolutionSiteKind::Literal, scope);
            let output = self.add_slot(site, ResolutionTypeSlotRole::ExpressionValue);
            crate::call_arguments::publish_jvm_expression_type(&mut self.facts, identity, output);
            output
        } else if expression.kind() == "as_expression"
            && expression
                .child(1)
                .is_some_and(|operator| operator.kind() == "as")
            && let Some(ty) = named_children(expression)
                .into_iter()
                .rev()
                .find(|child| KOTLIN_TYPE_NODE_KINDS.contains(&child.kind()))
        {
            let identity = self.ensure_type_slot(ty, scope, context.declaration);
            let site = self.add_site(expression, ResolutionSiteKind::UnaryExpression, scope);
            let output = self.add_slot(site, ResolutionTypeSlotRole::ExpressionValue);
            crate::call_arguments::publish_jvm_expression_type(&mut self.facts, identity, output);
            output
        } else if expression.kind() == "this_expression"
            && let Some(KotlinReceiver::Dispatch(owner)) =
                self.this_expression_receiver(expression, context.receiver_frame)
        {
            // Only nominal dispatch receivers can be looked up through a type
            // name. Anonymous dispatch frames still support `this.member`, but
            // their whole-value `this` retains the unsupported-expression gap.
            // A labeled outer receiver uses the selected nominal frame.
            let site = self.add_site(expression, ResolutionSiteKind::ValueReference, scope);
            let input =
                self.owner_type_slot(expression, owner, context.declaration.unwrap_or(owner));
            let output = self.add_slot(site, ResolutionTypeSlotRole::ExpressionValue);
            crate::call_arguments::publish_jvm_expression_type(&mut self.facts, input, output);
            output
        } else if expression.kind() == "this_expression"
            && let Some(KotlinReceiver::Extension(input)) =
                self.this_expression_receiver(expression, context.receiver_frame)
        {
            let site = self.add_site(expression, ResolutionSiteKind::ValueReference, scope);
            // The extension fact describes a type identity. Materialize its
            // runtime value before using `this` as an initializer or argument.
            // Receiver slots belong to calls, not to their input expressions.
            let value = self.add_slot(site, ResolutionTypeSlotRole::DeclaredValue);
            crate::call_arguments::publish_jvm_declared_type_transfer(
                &mut self.facts,
                input,
                value,
                ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
            );
            let output = self.add_slot(site, role);
            self.facts.type_transfers.push(ResolutionTypeTransferFact {
                input: value,
                output,
                kind: ResolutionTypeTransferKind::Contextual,
                indirection_delta: 0,
                reference_indirection_delta: 0,
                value_transform: ResolutionTypeTransferValueTransform::Preserve,
            });
            output
        } else if matches!(
            expression.kind(),
            "string_literal"
                | "integer_literal"
                | "long_literal"
                | "hex_literal"
                | "bin_literal"
                | "unsigned_literal"
                | "real_literal"
                | "boolean_literal"
                | "character_literal"
                | "null_literal"
        ) {
            let site = self.add_site(expression, ResolutionSiteKind::Literal, scope);
            self.sites_by_node.insert(expression.id(), site);
            let output = self.add_slot(site, role);
            let intrinsic = match expression.kind() {
                "string_literal" => Some(("java.lang.String", IntrinsicTypeKind::LanguageBuiltin)),
                "character_literal" => Some(("kotlin.Char", IntrinsicTypeKind::LanguageBuiltin)),
                "real_literal" => {
                    let text = expression.utf8_text(self.source.as_bytes()).ok();
                    let name =
                        if text.is_some_and(|text| text.ends_with('f') || text.ends_with('F')) {
                            "kotlin.Float"
                        } else {
                            "kotlin.Double"
                        };
                    Some((name, IntrinsicTypeKind::LanguageBuiltin))
                }
                "boolean_literal" | "integer_literal" | "long_literal" => {
                    kotlin_literal_scalar_type(expression, self.source).map(|scalar| {
                        let name = match scalar {
                            super::syntax::KotlinScalarType::Int => "kotlin.Int",
                            super::syntax::KotlinScalarType::Long => "kotlin.Long",
                            super::syntax::KotlinScalarType::Short => "kotlin.Short",
                            super::syntax::KotlinScalarType::Byte => "kotlin.Byte",
                            super::syntax::KotlinScalarType::Boolean => "kotlin.Boolean",
                        };
                        (name, IntrinsicTypeKind::LanguageBuiltin)
                    })
                }
                _ => None,
            };
            if let Some((name, kind)) = intrinsic {
                let name = self.intern_name(name);
                self.facts.intrinsic_type_seeds.push(IntrinsicTypeSeedFact {
                    output,
                    name,
                    kind,
                    indirection: 0,
                });
            } else {
                self.facts.gaps.push(ResolutionGapFact::new(
                    site,
                    if matches!(
                        expression.kind(),
                        "integer_literal"
                            | "long_literal"
                            | "hex_literal"
                            | "bin_literal"
                            | "unsigned_literal"
                            | "real_literal"
                    ) {
                        ResolutionGapKind::AmbiguousNumericLiteral
                    } else {
                        ResolutionGapKind::UnsupportedExpressionType
                    },
                ));
            }
            output
        } else if expression.kind() == "lambda_literal" {
            let site = self.add_site(expression, ResolutionSiteKind::Literal, scope);
            self.sites_by_node.insert(expression.id(), site);
            let output = self.add_slot(site, role);
            if let Some(arity) = kotlin_lambda_parameter_count(expression, self.source) {
                let arity = u32::try_from(arity).expect("Kotlin lambda arity fits u32");
                let name = self.intern_name(&format!("kotlin.Function{arity}"));
                self.facts.intrinsic_type_seeds.push(IntrinsicTypeSeedFact {
                    output,
                    name,
                    kind: IntrinsicTypeKind::LanguageBuiltin,
                    indirection: 0,
                });
            } else {
                self.facts.gaps.push(ResolutionGapFact::new(
                    site,
                    ResolutionGapKind::UnsupportedExpressionType,
                ));
            }
            output
        } else if let Some((left, right)) = self.additive_scalar_operands(expression) {
            let left = self.expression_slot(left, context, ResolutionTypeSlotRole::ExpressionValue);
            let right =
                self.expression_slot(right, context, ResolutionTypeSlotRole::ExpressionValue);
            let site = self.add_site(expression, ResolutionSiteKind::BinaryExpression, scope);
            self.sites_by_node.insert(expression.id(), site);
            let output = self.add_slot(site, role);
            for input in [left, right] {
                self.facts.type_transfers.push(ResolutionTypeTransferFact {
                    input,
                    output,
                    kind: ResolutionTypeTransferKind::ExpressionResult,
                    indirection_delta: 0,
                    reference_indirection_delta: 0,
                    value_transform: ResolutionTypeTransferValueTransform::Preserve,
                });
            }
            output
        } else {
            let site = self.add_site(expression, ResolutionSiteKind::UnsupportedExpression, scope);
            self.facts.gaps.push(ResolutionGapFact::new(
                site,
                ResolutionGapKind::UnsupportedExpression,
            ));
            self.sites_by_node.insert(expression.id(), site);
            self.add_slot(site, role)
        };
        self.expression_slots_by_node
            .insert((node.id(), role), slot);
        slot
    }

    fn additive_scalar_operands(
        &self,
        expression: Node<'source>,
    ) -> Option<(Node<'source>, Node<'source>)> {
        if expression.kind() != "additive_expression" || expression.child_count() != 3 {
            return None;
        }
        let operator = expression.child(1)?;
        if !matches!(operator.kind(), "+" | "-") {
            return None;
        }
        let left = expression.child(0)?;
        let right = expression.child(2)?;
        let left_type = self.scalar_type_of_expression(left)?;
        let right_type = self.scalar_type_of_expression(right)?;
        // Restrict the operand transfer to scalar cases whose result keeps the
        // exact operand type. Other Kotlin operator overloads and promotions
        // remain open until their callable rules are represented.
        (left_type == right_type
            && matches!(left_type, KotlinScalarType::Int | KotlinScalarType::Long))
        .then_some((left, right))
    }

    fn this_expression_receiver(
        &self,
        expression: Node<'source>,
        current_frame: Option<usize>,
    ) -> Option<KotlinReceiver> {
        if expression.kind() != "this_expression" {
            return None;
        }
        let label = first_named_child_of_kind(expression, "type_identifier")
            .map(|node| kotlin_identifier_text(node, self.source));
        let mut frame = current_frame?;
        loop {
            let receiver = self.receiver_frames[frame];
            if label.is_none_or(|label| {
                receiver
                    .label
                    .is_some_and(|owner| kotlin_owner_label_matches(owner, label))
            }) {
                return Some(receiver.receiver);
            }
            frame = receiver.parent?;
        }
    }

    fn scalar_type_of_expression(&self, mut expression: Node<'source>) -> Option<KotlinScalarType> {
        while expression.kind() == "parenthesized_expression" {
            let children = named_children(expression);
            let [inner] = children.as_slice() else {
                return None;
            };
            expression = *inner;
        }
        match expression.kind() {
            "simple_identifier" => self.scalar_type_of_identifier(expression),
            "integer_literal" | "long_literal" => {
                kotlin_literal_scalar_type(expression, self.source)
            }
            _ => None,
        }
    }

    fn scalar_type_of_identifier(&self, identifier: Node<'source>) -> Option<KotlinScalarType> {
        let reference_site = *self.sites_by_node.get(&identifier.id())?;
        self.scalar_types_by_declaration
            .get(&self.local_value_binding(reference_site)?)
            .copied()
    }

    fn local_value_binding(&self, reference_site: ResolutionSiteId) -> Option<ResolutionSiteId> {
        if !matches!(
            self.facts.sites[reference_site.index()].kind,
            ResolutionSiteKind::ValueReference | ResolutionSiteKind::ValueDeclaration
        ) {
            return None;
        }
        let reference_name = self
            .facts
            .identifiers
            .iter()
            .find(|fact| fact.site == reference_site && fact.qualifier.is_none())?
            .name;
        let mut current_scope = self.facts.sites[reference_site.index()].scope;
        loop {
            let matching_binders = self
                .facts
                .binders
                .iter()
                .filter(|binder| {
                    matches!(
                        binder.kind,
                        ResolutionBinderKind::Alias { .. }
                            | ResolutionBinderKind::Field
                            | ResolutionBinderKind::Local
                            | ResolutionBinderKind::Parameter
                            | ResolutionBinderKind::Pattern
                    ) && binder.scope == current_scope
                        && binder.activation_start
                            <= self.facts.sites[reference_site.index()].start_byte
                        && self.facts.sites[reference_site.index()].start_byte
                            < binder.activation_end
                })
                .filter_map(|binder| {
                    let (role, target) = match binder.kind {
                        ResolutionBinderKind::Alias { target } => {
                            (ResolutionIdentifierRole::Alias, target)
                        }
                        ResolutionBinderKind::Field
                        | ResolutionBinderKind::Local
                        | ResolutionBinderKind::Parameter
                        | ResolutionBinderKind::Pattern => {
                            (ResolutionIdentifierRole::Declaration, binder.declaration)
                        }
                        _ => return None,
                    };
                    self.facts
                        .identifiers
                        .iter()
                        .any(|fact| {
                            fact.site == binder.declaration
                                && fact.role == role
                                && fact.namespace == ResolutionNamespace::Value
                                && fact.name == reference_name
                        })
                        .then_some(target)
                })
                .collect::<Vec<_>>();
            match matching_binders.as_slice() {
                [declaration] => {
                    return Some(*declaration);
                }
                [] => {}
                _ => return None,
            }
            current_scope = self.facts.scopes[current_scope.index()].parent?;
        }
    }

    /// Kotlin's dominated regions supply existing per-read declared-type
    /// transfers. Bindings, rather than names, govern shadowing and writes.
    fn finish_smart_casts(&mut self, root: Node<'source>) {
        let mut refinements = Vec::new();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            let children = named_children(node);
            if node.kind() == "check_expression"
                && node
                    .child(1)
                    .is_some_and(|operator| operator.kind() == "is")
                && let [subject, ty] = children.as_slice()
                && subject.kind() == "simple_identifier"
            {
                let mut condition = node;
                let mut parent = condition.parent();
                while let Some(outer) = parent {
                    if outer.kind() == "parenthesized_expression" {
                        condition = outer;
                        parent = outer.parent();
                        continue;
                    }
                    if outer.kind() == "conjunction_expression" {
                        if outer
                            .named_child(0)
                            .is_some_and(|left| left.id() == condition.id())
                            && let Some(right) = outer.named_child(1)
                        {
                            refinements.push((*subject, *ty, right.start_byte(), right.end_byte()));
                        }
                        condition = outer;
                        parent = outer.parent();
                        continue;
                    }
                    if outer.kind() == "if_expression"
                        && outer
                            .child_by_field_name("condition")
                            .is_some_and(|child| child.id() == condition.id())
                        && let Some(body) = outer.child_by_field_name("consequence")
                    {
                        refinements.push((*subject, *ty, body.start_byte(), body.end_byte()));
                    }
                    break;
                }
            } else if node.kind() == "as_expression"
                && node
                    .child(1)
                    .is_some_and(|operator| operator.kind() == "as")
                && let [subject, ty] = children.as_slice()
                && subject.kind() == "simple_identifier"
            {
                let mut statement = node;
                while let Some(parent) = statement.parent()
                    && parent.kind() == "parenthesized_expression"
                {
                    statement = parent;
                }
                if let Some(block) = statement
                    .parent()
                    .filter(|parent| matches!(parent.kind(), "block" | "statements"))
                {
                    refinements.push((*subject, *ty, statement.end_byte(), block.end_byte()));
                }
            } else if node.kind() == "when_expression"
                && let Some(subject) = first_named_child_of_kind(node, "when_subject")
                && let Some(value) = first_named_child_of_kind(subject, "variable_declaration")
                    .and_then(|variable| first_named_child_of_kind(variable, "simple_identifier"))
                    .or_else(|| {
                        named_children(subject)
                            .into_iter()
                            .find(|child| child.kind() == "simple_identifier")
                    })
            {
                for entry in children.iter().filter(|child| child.kind() == "when_entry") {
                    let conditions = named_children(*entry)
                        .into_iter()
                        .filter(|child| child.kind() == "when_condition")
                        .collect::<Vec<_>>();
                    if let [condition] = conditions.as_slice()
                        && let Some(test) = first_named_child_of_kind(*condition, "type_test")
                        && test
                            .child(0)
                            .is_some_and(|operator| operator.kind() == "is")
                        && let Some(ty) = named_children(test)
                            .into_iter()
                            .find(|child| KOTLIN_TYPE_NODE_KINDS.contains(&child.kind()))
                        && let Some(body) =
                            first_named_child_of_kind(*entry, "control_structure_body")
                    {
                        refinements.push((value, ty, body.start_byte(), body.end_byte()));
                    }
                }
            }
            stack.extend(children);
        }
        struct Region {
            declaration: ResolutionSiteId,
            execution_scope: ResolutionScopeId,
            start: usize,
            end: usize,
            input: ResolutionTypeSlotId,
        }
        let write_targets = self
            .facts
            .local_writes
            .iter()
            .map(|write| write.target)
            .collect::<HashSet<_>>();
        let mut regions = Vec::new();
        for (subject, ty, start, end) in refinements {
            let Some(&subject_site) = self.sites_by_node.get(&subject.id()) else {
                continue;
            };
            let declaration = if self.facts.identifiers.iter().any(|identifier| {
                identifier.site == subject_site
                    && identifier.role == ResolutionIdentifierRole::Declaration
            }) {
                Some(subject_site)
            } else {
                self.local_value_binding(subject_site)
            };
            let Some(declaration) = declaration.filter(|declaration| {
                !self.unstable_smart_cast_bindings.contains(declaration)
                    && !self
                        .facts
                        .member_owners
                        .iter()
                        .any(|owner| owner.member == *declaration)
                    && self.facts.binders.iter().any(|binder| {
                        binder.declaration == *declaration
                            && matches!(
                                binder.kind,
                                ResolutionBinderKind::Local
                                    | ResolutionBinderKind::Parameter
                                    | ResolutionBinderKind::Pattern
                            )
                    })
            }) else {
                continue;
            };
            let Some(execution_scope) =
                self.enclosing_execution_region(self.facts.sites[subject_site.index()].scope)
            else {
                continue;
            };
            // A captured mutable binding can change through an invocation
            // whose source position is outside this dominated region.
            if self.facts.local_writes.iter().any(|write| {
                self.local_value_binding(write.target) == Some(declaration)
                    && self.enclosing_execution_region(self.facts.sites[write.target.index()].scope)
                        != Some(execution_scope)
            }) {
                continue;
            }
            let invalidation = self
                .facts
                .local_writes
                .iter()
                .filter(|write| {
                    let site = self.facts.sites[write.target.index()];
                    start <= site.start_byte
                        && site.start_byte < end
                        && self.local_value_binding(write.target) == Some(declaration)
                })
                .map(|write| {
                    let target = self.facts.sites[write.target.index()];
                    let value =
                        self.facts.sites[self.facts.type_slots[write.value.index()].site.index()];
                    // Kotlin evaluates the RHS before the local write takes effect.
                    target.end_byte.max(value.end_byte)
                })
                .min()
                .unwrap_or(end)
                .min(end);
            let input =
                self.ensure_type_slot(ty, self.facts.sites[subject_site.index()].scope, None);
            regions.push(Region {
                declaration,
                // A nested executable may introduce an implicit binder (for
                // example lambda `it`) that this producer cannot identify.
                execution_scope,
                start,
                end: invalidation,
                input,
            });
        }
        regions.sort_by_key(|region| {
            (
                region.declaration.index(),
                region.execution_scope.index(),
                region.start,
                std::cmp::Reverse(region.end),
            )
        });
        let mut active_key = None;
        let mut active: Vec<(usize, usize, ResolutionTypeSlotId)> = Vec::new();
        let mut read_inputs = HashMap::default();
        for region in regions {
            let key = (region.declaration, region.execution_scope);
            if active_key != Some(key) {
                active.clear();
                active_key = Some(key);
            }
            while active
                .last()
                .is_some_and(|(start, end, _)| *start > region.start || *end < region.end)
            {
                active.pop();
            }
            let input = match active.last() {
                Some((_, _, parent)) if *parent != region.input => {
                    let site = self.facts.type_slots[region.input.index()].site;
                    let union = self.add_slot(site, ResolutionTypeSlotRole::TargetTypeIdentity);
                    for input in [*parent, region.input] {
                        crate::call_arguments::publish_jvm_type_union_transfer(
                            &mut self.facts,
                            input,
                            union,
                        );
                    }
                    union
                }
                _ => region.input,
            };
            active.push((region.start, region.end, input));
            for projection in &self.facts.binding_projections {
                let site = self.facts.sites[projection.reference.index()];
                if region.start <= site.start_byte
                    && site.end_byte <= region.end
                    && !write_targets.contains(&projection.reference)
                    && matches!(
                        projection.kind,
                        BindingProjectionKind::TargetDeclaredValueType
                            | BindingProjectionKind::TargetTypeOrDeclaredValueType
                    )
                    && self.local_value_binding(projection.reference) == Some(region.declaration)
                    && self.enclosing_execution_region(site.scope) == Some(region.execution_scope)
                {
                    read_inputs.insert(projection.output, input);
                }
            }
        }
        // Share the region's bound identity instead of copying every ancestor
        // bound onto every read. Allocation remains linear in the source blob.
        let mut reads = read_inputs.into_iter().collect::<Vec<_>>();
        reads.sort_unstable_by_key(|(output, _)| output.index());
        for (output, input) in reads {
            crate::call_arguments::publish_jvm_expression_refinement(
                &mut self.facts,
                input,
                output,
            );
        }
    }

    fn enclosing_execution_region(
        &self,
        mut scope: ResolutionScopeId,
    ) -> Option<ResolutionScopeId> {
        let mut initializer = None;
        loop {
            let fact = self.facts.scopes[scope.index()];
            match fact.kind {
                ResolutionScopeKind::Executable => return Some(scope),
                ResolutionScopeKind::Initializer => initializer = Some(scope),
                // A nested class is a capture boundary even inside a function.
                // Its initializer blocks have separate execution identities.
                ResolutionScopeKind::TypeBody => return Some(initializer.unwrap_or(scope)),
                _ => {}
            }
            let Some(parent) = fact.parent else {
                return initializer;
            };
            scope = parent;
        }
    }

    fn finish_calls(&mut self) {
        for (call_node, call_site, result, context) in std::mem::take(&mut self.pending_calls) {
            let Some(callee) = kotlin_callee(call_node) else {
                self.facts.gaps.push(ResolutionGapFact::new(
                    call_site,
                    ResolutionGapKind::UnsupportedExpression,
                ));
                continue;
            };
            let callee_name = if callee.kind() == "navigation_expression" {
                kotlin_navigation_member(callee).unwrap_or(callee)
            } else {
                callee
            };
            let callee_site = self
                .sites_by_node
                .get(&callee_name.id())
                .copied()
                .unwrap_or_else(|| {
                    let site = self.add_site(
                        callee_name,
                        ResolutionSiteKind::UnsupportedRoute,
                        context.scope,
                    );
                    let route = ResolutionRouteGap::OmittedReference {
                        scope: context.scope,
                        terminal: matches!(
                            callee_name.kind(),
                            "simple_identifier" | "type_identifier"
                        )
                        .then(|| {
                            self.intern_name(kotlin_identifier_text(callee_name, self.source))
                        }),
                        namespace: Some(ResolutionNamespace::Callable),
                    };
                    self.facts.add_route_gap(site, route);
                    self.facts
                        .add_reference_enumeration_gap(site, ResolutionGapKind::UnsupportedRoute);
                    site
                });
            let callee_kind = self.facts.sites[callee_site.index()].kind;
            let callee_namespace = self
                .facts
                .identifiers
                .iter()
                .find(|identifier| identifier.site == callee_site)
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
                self.facts.gaps.push(ResolutionGapFact::new(
                    call_site,
                    ResolutionGapKind::UnsupportedCallApplicability,
                ));
                continue;
            }
            self.facts.gaps.push(ResolutionGapFact::new(
                callee_site,
                ResolutionGapKind::UnsupportedCallApplicability,
            ));
            let explicit_this_dispatch =
                kotlin_navigation_receiver(callee).is_some_and(|receiver| {
                    matches!(
                        self.this_expression_receiver(receiver, context.receiver_frame),
                        Some(KotlinReceiver::Dispatch(_) | KotlinReceiver::AnonymousDispatch(_))
                    )
                });
            let receiver = (callee.kind() == "navigation_expression" && !explicit_this_dispatch)
                .then(|| kotlin_navigation_receiver(callee))
                .flatten()
                .map(|receiver| {
                    let input = self.expression_slot(
                        receiver,
                        context,
                        ResolutionTypeSlotRole::ExpressionValue,
                    );
                    let output = self.add_slot(call_site, ResolutionTypeSlotRole::Receiver);
                    self.facts.type_transfers.push(ResolutionTypeTransferFact {
                        input,
                        output,
                        kind: ResolutionTypeTransferKind::Receiver,
                        indirection_delta: 0,
                        reference_indirection_delta: 0,
                        value_transform: ResolutionTypeTransferValueTransform::Preserve,
                    });
                    output
                });
            self.facts.binding_projections.push(BindingProjectionFact {
                reference: callee_site,
                output: result,
                kind: BindingProjectionKind::TargetCallableResultType,
            });
            self.facts.calls.push(ResolutionCallFact {
                call: call_site,
                callee: callee_site,
                receiver,
                result,
                extra_result_slots: Vec::new(),
                explicit_type_argument_count: 0,
            });
            self.facts
                .invocation_roles
                .push(ResolutionInvocationRoleFact {
                    site: call_site,
                    role: ResolutionInvocationRole::Direct,
                    receiver,
                    result: Some(result),
                });
            self.facts
                .callable_receiver_origins
                .push(ResolutionCallableReceiverOriginFact {
                    reference: callee_site,
                    origin: if explicit_this_dispatch {
                        ResolutionCallableReceiverOrigin::CurrentInstance
                    } else if receiver.is_some() {
                        ResolutionCallableReceiverOrigin::ExplicitExpression
                    } else {
                        ResolutionCallableReceiverOrigin::Implicit
                    },
                });
            self.facts
                .call_argument_lists
                .push(ResolutionCallArgumentListFact {
                    call: call_site,
                    list_ordinal: 0,
                });
            let mut ordinal = 0u32;
            if let Some(arguments) = super::syntax::kotlin_value_arguments(call_node) {
                for argument in named_children(arguments)
                    .into_iter()
                    .filter(|child| child.kind() == "value_argument")
                {
                    let children = named_children(argument);
                    let label_node = children
                        .first()
                        .copied()
                        .filter(|first| kotlin_named_argument_label(argument, *first));
                    let value_node = children
                        .last()
                        .copied()
                        .expect("Kotlin value argument has an expression");
                    let label = label_node.map(|label| {
                        let name = self.intern_name(kotlin_identifier_text(label, self.source));
                        let reference = self.add_identifier(
                            label,
                            ResolutionSiteKind::ValueReference,
                            ResolutionNamespace::Value,
                            ResolutionIdentifierRole::Reference,
                            context.scope,
                            None,
                        );
                        if let Some(owner) = context.declaration {
                            self.facts
                                .reference_owners
                                .push(ResolutionReferenceOwnerFact {
                                    reference,
                                    owner: Some(owner),
                                });
                        }
                        self.facts
                            .named_argument_labels
                            .push(ResolutionNamedArgumentLabelFact {
                                call: call_site,
                                reference,
                                label: name,
                            });
                        name
                    });
                    let input = self.expression_slot(
                        value_node,
                        context,
                        ResolutionTypeSlotRole::ExpressionValue,
                    );
                    crate::call_arguments::publish_jvm_call_argument(
                        &mut self.facts,
                        call_site,
                        0,
                        ordinal,
                        Some(input),
                        label,
                    );
                    ordinal = ordinal.checked_add(1).expect("Kotlin call arity fits u32");
                }
            }
            if let Some(suffix) = first_named_child_of_kind(call_node, "call_suffix")
                && let Some(lambda) = first_named_child_of_kind(suffix, "annotated_lambda")
            {
                let input =
                    self.expression_slot(lambda, context, ResolutionTypeSlotRole::ExpressionValue);
                crate::call_arguments::publish_jvm_call_argument(
                    &mut self.facts,
                    call_site,
                    0,
                    ordinal,
                    Some(input),
                    None,
                );
            }
        }
    }

    fn finish_constructor_aliases(&mut self) {
        // Delegation specifiers finish widening the header during the walk.
        // Publish aliases before scalar inference, with their final activation
        // bounds, without changing the canonical AST node-to-site mapping.
        for (name_node, target, scope) in std::mem::take(&mut self.pending_constructor_aliases) {
            let alias = self.add_site(name_node, ResolutionSiteKind::AliasBinding, scope);
            let name = self.intern_name(kotlin_identifier_text(name_node, self.source));
            self.facts.identifiers.push(PositionedIdentifierFact {
                site: alias,
                name,
                role: ResolutionIdentifierRole::Alias,
                namespace: ResolutionNamespace::Value,
                qualifier: None,
            });
            self.add_binder(alias, scope, ResolutionBinderKind::Alias { target }, true);
        }
    }

    fn finish_constructor_properties(&mut self) {
        for (member, owner, singleton_owner) in
            std::mem::take(&mut self.pending_constructor_properties)
        {
            let scope = self.ensure_type_body_scope(owner);
            self.facts.sites[member.index()].scope = scope;
            self.add_binder(member, scope, ResolutionBinderKind::Field, true);
            self.facts.member_owners.push(ResolutionMemberOwnerFact {
                member,
                owner,
                kind: ResolutionMemberKind::Field,
                access: if singleton_owner {
                    ResolutionMemberAccess::Type
                } else {
                    ResolutionMemberAccess::Instance
                },
                qualifier_compatibility: if singleton_owner {
                    ResolutionMemberQualifierCompatibility::RuntimeOrType
                } else {
                    ResolutionMemberQualifierCompatibility::RuntimeOnly
                },
            });
        }
    }

    /// A star import demands every name the file's unqualified references
    /// could take from its package. A callee can also name a type (the engine
    /// searches both namespaces for a call), so it demands both.
    fn finish_import_demands(&mut self) {
        let explicit_receiver_calls = self
            .facts
            .callable_receiver_origins
            .iter()
            .filter(|origin| origin.origin == ResolutionCallableReceiverOrigin::ExplicitExpression)
            .map(|origin| origin.reference)
            .collect::<HashSet<_>>();
        for &(import_site, _import_scope) in &self.wildcard_imports {
            let mut demands = Vec::new();
            for identifier in &self.facts.identifiers {
                if identifier.role != ResolutionIdentifierRole::Reference
                    || (identifier.qualifier.is_some()
                        && !explicit_receiver_calls.contains(&identifier.site))
                {
                    continue;
                }
                let namespaces: &[ResolutionNamespace] = match identifier.namespace {
                    ResolutionNamespace::Type => &[ResolutionNamespace::Type],
                    ResolutionNamespace::Value => &[ResolutionNamespace::Value],
                    ResolutionNamespace::Callable => {
                        crate::package_lookup::callee_import_namespaces(
                            brokk_bifrost_core::analyzer::Language::Kotlin,
                        )
                    }
                    ResolutionNamespace::TypeOrValue => {
                        &[ResolutionNamespace::Type, ResolutionNamespace::Value]
                    }
                    _ => &[],
                };
                for &namespace in namespaces {
                    let demand = ResolutionRootImportDemandFact {
                        import_site,
                        namespace,
                        name: identifier.name,
                    };
                    if !demands.contains(&demand) {
                        demands.push(demand);
                    }
                }
            }
            self.facts.root_import_demands.extend(demands);
        }
    }

    /// A type-body scope widens to its declaration's whole range after its
    /// members were bound, so a scope-wide binder created earlier would
    /// otherwise state a narrower activation than its scope and be refused by
    /// lowering. A scope-wide binder is active over exactly its scope.
    fn finish_scope_wide_activations(&mut self) {
        for binder in &mut self.facts.binders {
            if binder.hoisting == HoistingClass::ScopeWide {
                let scope = self.facts.scopes[binder.scope.index()];
                binder.activation_start = scope.start_byte;
                binder.activation_end = scope.end_byte;
            }
        }
    }

    fn finish_initializers(&mut self) {
        for (output, expression, context) in std::mem::take(&mut self.pending_initializers) {
            let input =
                self.expression_slot(expression, context, ResolutionTypeSlotRole::ExpressionValue);
            self.facts.type_transfers.push(ResolutionTypeTransferFact {
                input,
                output,
                kind: ResolutionTypeTransferKind::Initialization,
                indirection_delta: 0,
                reference_indirection_delta: 0,
                value_transform: ResolutionTypeTransferValueTransform::Preserve,
            });
        }
        for (output, expression, context) in std::mem::take(&mut self.pending_initializer_values) {
            let input =
                self.expression_slot(expression, context, ResolutionTypeSlotRole::ExpressionValue);
            self.facts.type_transfers.push(ResolutionTypeTransferFact {
                input,
                output,
                kind: ResolutionTypeTransferKind::Assignment,
                indirection_delta: 0,
                reference_indirection_delta: 0,
                value_transform: ResolutionTypeTransferValueTransform::Preserve,
            });
        }
    }

    fn finish_writes(&mut self) {
        for (node, context) in std::mem::take(&mut self.pending_writes) {
            let children = named_children(node)
                .into_iter()
                .filter(|child| !child.is_extra())
                .collect::<Vec<_>>();
            let left = children.first().copied();
            // A directly assignable wrapper can also contain navigation,
            // indexing or postfix operators. Only its bare identifier is a
            // lexical write target; a selected member is never a local.
            let target = left
                .and_then(|left| match left.kind() {
                    "simple_identifier" => Some(left),
                    "directly_assignable_expression" if kotlin_first_token(left).is_none() => {
                        let children = named_children(left)
                            .into_iter()
                            .filter(|child| !child.is_extra())
                            .collect::<Vec<_>>();
                        match children.as_slice() {
                            [identifier] if identifier.kind() == "simple_identifier" => {
                                Some(*identifier)
                            }
                            _ => None,
                        }
                    }
                    _ => None,
                })
                .filter(|target| !target.is_missing() && !target.has_error());
            let value = if node.kind() == "assignment"
                && kotlin_first_token(node) == Some("=")
                && target.is_some()
                && let Some(right) = children.get(1).copied()
            {
                self.expression_slot(right, context, ResolutionTypeSlotRole::ExpressionValue)
            } else {
                // Compound assignments and updates do not copy the RHS.
                // Keep an empty input carrying the unsupported operation.
                let site = self.add_site(
                    node,
                    ResolutionSiteKind::UnsupportedExpression,
                    context.scope,
                );
                self.facts.gaps.push(ResolutionGapFact::new(
                    site,
                    ResolutionGapKind::UnsupportedExpression,
                ));
                self.add_slot(site, ResolutionTypeSlotRole::ExpressionValue)
            };
            if let Some(target) = target {
                if let Some(target) = self.sites_by_node.get(&target.id()).copied() {
                    self.facts
                        .local_writes
                        .push(ResolutionLocalWriteFact { target, value });
                } else {
                    let site = self.facts.type_slots[value.index()].site;
                    self.facts.gaps.push(ResolutionGapFact::new(
                        site,
                        ResolutionGapKind::UnsupportedScopeOrBinder,
                    ));
                }
            }
        }
    }

    fn initialization_scope(&mut self, owner: ResolutionSiteId) -> ResolutionScopeId {
        if let Some(scope) = self.initialization_scopes.get(&owner) {
            return *scope;
        }
        let parent = self.ensure_type_body_scope(owner);
        let id = ResolutionScopeId::try_from_index(self.facts.scopes.len())
            .expect("Kotlin resolution scope count fits u32");
        let body = self.facts.scopes[parent.index()];
        // Plain primary-constructor parameters are visible in property
        // initializers and init blocks, but are not instance members.
        self.facts.scopes.push(ResolutionScopeFact {
            id,
            parent: Some(parent),
            owner: Some(owner),
            kind: ResolutionScopeKind::Initializer,
            inheritance: ResolutionScopeInheritance::Lexical,
            start_byte: body.start_byte,
            end_byte: body.end_byte,
        });
        self.initialization_scopes.insert(owner, id);
        id
    }

    /// Every class, object and interface owns a member scope, even one that
    /// declares nothing: a lookup in an empty scope is a complete absence, and
    /// a type with no scope would leave that lookup open.
    fn finish_type_body_scopes(&mut self) {
        let mut owners = self.type_scope_ranges.keys().copied().collect::<Vec<_>>();
        owners.sort_unstable();
        for owner in owners {
            self.ensure_type_body_scope(owner);
        }
    }

    fn finish_constructors(&mut self) {
        for (site, owner) in std::mem::take(&mut self.pending_constructors) {
            let scope = self.ensure_type_body_scope(owner);
            self.facts.sites[site.index()].scope = scope;
            ConstructorSite {
                site,
                owner,
                owner_name: *self
                    .type_names
                    .get(&owner)
                    .expect("a Kotlin type declaration site has a name"),
                scope,
            }
            .publish(&mut self.facts);
        }
    }

    fn ensure_type_body_scope(&mut self, owner: ResolutionSiteId) -> ResolutionScopeId {
        let scope = self
            .facts
            .scopes
            .iter()
            .find(|scope| scope.owner == Some(owner) && scope.kind == ResolutionScopeKind::TypeBody)
            .map(|scope| scope.id)
            .unwrap_or_else(|| {
                let id = ResolutionScopeId::try_from_index(self.facts.scopes.len())
                    .expect("Kotlin resolution scope count fits u32");
                let &(start_byte, end_byte) = self
                    .type_scope_ranges
                    .get(&owner)
                    .expect("type-body owner has a source range");
                self.facts.scopes.push(ResolutionScopeFact {
                    id,
                    parent: Some(
                        *self
                            .type_scope_parents
                            .get(&owner)
                            .expect("type-body owner has a lexical parent"),
                    ),
                    owner: Some(owner),
                    kind: ResolutionScopeKind::TypeBody,
                    inheritance: ResolutionScopeInheritance::Lexical,
                    start_byte,
                    end_byte,
                });
                id
            });
        let &(type_start, type_end) = self
            .type_scope_ranges
            .get(&owner)
            .expect("type-body owner has a source range");
        let type_scope = &mut self.facts.scopes[scope.index()];
        type_scope.start_byte = type_scope.start_byte.min(type_start);
        type_scope.end_byte = type_scope.end_byte.max(type_end);
        scope
    }

    fn finish_supertypes(&mut self, root: Node<'source>) {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if let Some(subtype) = self.type_sites.get(&node.id()).copied() {
                let mut parent_ordinal = 0u32;
                let mut has_superclass = false;
                for specifier in named_children(node)
                    .into_iter()
                    .filter(|child| child.kind() == "delegation_specifier")
                {
                    let user_type = named_children(specifier).into_iter().find_map(|child| {
                        if child.kind() == "user_type" {
                            Some(child)
                        } else if matches!(
                            child.kind(),
                            "constructor_invocation" | "explicit_delegation"
                        ) {
                            first_named_child_of_kind(child, "user_type")
                        } else {
                            None
                        }
                    });
                    if let Some(user_type) = user_type {
                        let slot = self.ensure_type_slot(
                            user_type,
                            self.facts.sites[subtype.index()].scope,
                            Some(subtype),
                        );
                        let reference = self.facts.type_slots[slot.index()].site;
                        let has_constructor_arguments =
                            named_children(specifier).into_iter().any(|child| {
                                child.kind() == "constructor_invocation"
                                    && first_named_child_of_kind(child, "value_arguments").is_some()
                            });
                        let kind = if parent_ordinal == 0 && has_constructor_arguments {
                            ResolutionSupertypeKind::Superclass
                        } else {
                            ResolutionSupertypeKind::Interface
                        };
                        has_superclass |= kind == ResolutionSupertypeKind::Superclass;
                        self.facts.supertypes.push(ResolutionSupertypeFact {
                            subtype,
                            parent_ordinal,
                            supertype_reference: reference,
                            supertype_slot: slot,
                            kind,
                        });
                        self.facts.gaps.push(ResolutionGapFact::new(
                            reference,
                            ResolutionGapKind::UnsupportedHierarchyTraversal,
                        ));
                    }
                    parent_ordinal = parent_ordinal
                        .checked_add(1)
                        .expect("Kotlin supertype count fits u32");
                }
                let is_declared_any = self.type_parents.get(&subtype) == Some(&None)
                    && self.package_names.len() == 1
                    && self.facts.names[self.package_names[0].index()].spelling == "kotlin"
                    && self.type_simple_names.get(&subtype) == Some(&"Any");
                let implicit = if has_superclass || is_declared_any {
                    None
                } else if node.kind() == "object_literal" {
                    Some(("Any", ResolutionSupertypeKind::ImplicitSuperclass))
                } else {
                    match kotlin_class_like_kind(node) {
                        Some(super::declarations::KotlinClassLikeKind::Enum) => {
                            // Enum has additional members beyond Any. An unindexed
                            // Enum inventory stays open for every requested name.
                            Some(("Enum", ResolutionSupertypeKind::Superclass))
                        }
                        Some(super::declarations::KotlinClassLikeKind::Annotation) => {
                            Some(("Annotation", ResolutionSupertypeKind::Interface))
                        }
                        Some(_) => Some(("Any", ResolutionSupertypeKind::ImplicitSuperclass)),
                        None => None,
                    }
                };
                if let Some((name, kind)) = implicit {
                    let scope = self.facts.sites[subtype.index()].scope;
                    let reference =
                        self.add_site(node, ResolutionSiteKind::SyntheticReference, scope);
                    let name = self.intern_name(name);
                    let prefix = [self.intern_name("kotlin")];
                    crate::implicit_supertype::publish_implicit_supertype(
                        &mut self.facts,
                        subtype,
                        reference,
                        name,
                        &prefix,
                        kind,
                    );
                }
            }
            stack.extend(named_children(node));
        }
    }

    fn finish_package_references(&mut self) {
        let explicit_imports = self
            .facts
            .import_selectors
            .iter()
            .filter_map(|selector| selector.local_name)
            .collect::<HashSet<_>>();
        let explicit_receiver_calls = self
            .facts
            .callable_receiver_origins
            .iter()
            .filter(|origin| origin.origin == ResolutionCallableReceiverOrigin::ExplicitExpression)
            .map(|origin| origin.reference)
            .collect::<HashSet<_>>();
        let package_scope = self.package_scope;
        let package_references = crate::package_lookup::source_owned_package_references(
            &self.facts,
            |identifier, _| {
                identifier.qualifier.is_none()
                    || (identifier.namespace == ResolutionNamespace::Callable
                        && explicit_receiver_calls.contains(&identifier.site))
            },
            |identifier, _| {
                (matches!(
                    identifier.namespace,
                    ResolutionNamespace::Type
                        | ResolutionNamespace::Value
                        | ResolutionNamespace::Callable
                        | ResolutionNamespace::TypeOrValue
                ) && !explicit_imports.contains(&identifier.name))
                .then_some(package_scope)
            },
        );
        self.facts.package_references.extend(package_references);
    }
}

/// The expression written after the first `=` among a node's children.
fn kotlin_expression_after_equals(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    let mut after_equals = false;
    for child in node.children(&mut cursor) {
        if after_equals && child.is_named() && !child.is_extra() {
            return Some(child);
        }
        if !child.is_named() && child.kind() == "=" {
            after_equals = true;
        }
    }
    None
}

fn annotation_user_types(annotation: Node<'_>) -> Vec<Node<'_>> {
    named_children(annotation)
        .into_iter()
        .flat_map(|child| match child.kind() {
            "user_type" => vec![child],
            "constructor_invocation" => named_children(child)
                .into_iter()
                .filter(|inner| inner.kind() == "user_type")
                .collect(),
            _ => Vec::new(),
        })
        .collect()
}

fn declaration_annotations(node: Node<'_>) -> Vec<Node<'_>> {
    first_named_child_of_kind(node, "modifiers")
        .map(|modifiers| {
            named_children(modifiers)
                .into_iter()
                .filter(|child| child.kind() == "annotation")
                .collect()
        })
        .unwrap_or_default()
}

fn annotation_use_site(annotation: Node<'_>, source: &str) -> Option<String> {
    first_named_child_of_kind(annotation, "use_site_target")
        .and_then(|node| source.get(node.start_byte()..node.end_byte()))
        .and_then(|target| target.strip_suffix(':'))
        .map(str::to_owned)
}

fn annotation_has_simple_name(annotation: Node<'_>, expected: &str, source: &str) -> bool {
    annotation_user_types(annotation)
        .into_iter()
        .any(|user_type| {
            kotlin_user_type_segments(user_type)
                .last()
                .is_some_and(|segment| kotlin_identifier_text(*segment, source) == expected)
        })
}

fn annotation_string_argument(annotation: Node<'_>, source: &str) -> Option<String> {
    let invocation = first_named_child_of_kind(annotation, "constructor_invocation")?;
    let arguments = first_named_child_of_kind(invocation, "value_arguments")?;
    let args = named_children(arguments)
        .into_iter()
        .filter(|child| child.kind() == "value_argument")
        .collect::<Vec<_>>();
    if args.len() != 1 {
        return None;
    }
    let value = named_children(args[0]).last().copied()?;
    if value.kind() != "string_literal" {
        return None;
    }
    let mut contents = Vec::new();
    let mut stack = vec![value];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "string_content" => {
                let raw = source.get(node.start_byte()..node.end_byte())?;
                if raw.contains('\\') || raw.contains('$') {
                    return None;
                }
                contents.push(raw);
            }
            "interpolation_expression_start"
            | "interpolated_expression"
            | "interpolation_identifier_start"
            | "interpolated_identifier" => return None,
            _ => stack.extend(named_children(node)),
        }
    }
    (contents.len() == 1 && !contents[0].is_empty()).then(|| contents[0].to_owned())
}

fn callable_parameter_nodes(callable: Node<'_>) -> Vec<Node<'_>> {
    if callable.kind() == "primary_constructor" {
        return named_children(callable)
            .into_iter()
            .filter(|child| child.kind() == "class_parameter")
            .collect();
    }
    first_named_child_of_kind(callable, "function_value_parameters")
        .map(|parameters| {
            named_children(parameters)
                .into_iter()
                .filter(|child| child.kind() == "parameter")
                .collect()
        })
        .unwrap_or_default()
}

fn kotlin_function_type_parts(node: Node<'_>) -> (Vec<Node<'_>>, Node<'_>) {
    assert_eq!(node.kind(), "function_type");
    let is_type = |node: &Node<'_>| {
        KOTLIN_TYPE_NODE_KINDS.contains(&node.kind()) || node.kind() == "user_type"
    };
    let mut inputs = node
        .child_by_field_name("receiver")
        .into_iter()
        .collect::<Vec<_>>();
    if let Some(parameters) = first_named_child_of_kind(node, "function_type_parameters") {
        inputs.extend(
            named_children(parameters)
                .into_iter()
                .filter_map(|parameter| {
                    if parameter.kind() == "parameter" {
                        named_children(parameter).into_iter().find(&is_type)
                    } else {
                        is_type(&parameter).then_some(parameter)
                    }
                }),
        );
    }
    let result = named_children(node)
        .into_iter()
        .rev()
        .find(is_type)
        .expect("a function type has a result");
    (inputs, result)
}

fn kotlin_function_type_arity(node: Node<'_>) -> usize {
    kotlin_function_type_parts(node).0.len()
}

fn kotlin_lambda_parameter_count(lambda: Node<'_>, source: &str) -> Option<usize> {
    assert_eq!(lambda.kind(), "lambda_literal");
    if let Some(parameters) = first_named_child_of_kind(lambda, "lambda_parameters") {
        return Some(named_children(parameters).len());
    }

    // An implicit `it` makes the function arity depend on the expected type.
    // Do not guess zero for that lambda; keep its value type open.
    let mut stack = named_children(lambda);
    while let Some(current) = stack.pop() {
        if current.kind() == "lambda_literal" {
            continue;
        }
        if current.kind() == "simple_identifier" && kotlin_identifier_text(current, source) == "it"
        {
            return None;
        }
        stack.extend(named_children(current));
    }
    Some(0)
}

fn declaration_is_interface(node: Node<'_>) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|child| child.kind() == "interface")
}

/// Whether a class declaration has a zero-parameter primary constructor that
/// declaration extraction publishes no constructor unit for. A class with a
/// written primary constructor has one exactly when it writes no parameter
/// (`class C()`). A class that writes no primary constructor has the implicit
/// one unless it writes a secondary constructor, which replaces it.
fn class_has_zero_parameter_primary_constructor(class: Node<'_>) -> bool {
    match first_named_child_of_kind(class, "primary_constructor") {
        Some(primary) => !named_children(primary)
            .into_iter()
            .any(|child| child.kind() == "class_parameter"),
        None => !["class_body", "enum_class_body"]
            .into_iter()
            .filter_map(|body| first_named_child_of_kind(class, body))
            .flat_map(named_children)
            .any(|member| member.kind() == "secondary_constructor"),
    }
}

fn uppercase_first(name: &str) -> String {
    let mut characters = name.chars();
    let Some(first) = characters.next() else {
        return String::new();
    };
    let mut result = first.to_uppercase().collect::<String>();
    result.extend(characters);
    result
}

fn is_boolean_property_name(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix("is") else {
        return false;
    };
    suffix.chars().next().is_some_and(char::is_uppercase)
}

fn kotlin_getter_name(property: &str) -> String {
    if is_boolean_property_name(property) {
        property.to_owned()
    } else {
        format!("get{}", uppercase_first(property))
    }
}

fn kotlin_setter_name(property: &str) -> String {
    if is_boolean_property_name(property) {
        format!(
            "set{}",
            property.strip_prefix("is").expect("checked is prefix")
        )
    } else {
        format!("set{}", uppercase_first(property))
    }
}

#[cfg(test)]
mod tests {
    use super::super::declarations::parse_kotlin_file;
    use super::*;
    use brokk_bifrost_test_macros::hardwon;
    use tree_sitter::Parser;

    fn parse(
        source: &str,
        file_name: &str,
    ) -> brokk_bifrost_core::analyzer::parsed_file::ParsedFile {
        let file = ProjectFile::new(
            std::env::temp_dir().join("kotlin-native-resolution"),
            file_name,
        );
        let mut parser = Parser::new();
        parser
            .set_language(&crate::kotlin::language::LANGUAGE.into())
            .expect("load Kotlin grammar");
        let tree = parser.parse(source, None).expect("parse Kotlin source");
        assert!(
            !tree.root_node().has_error(),
            "Kotlin fixture parses without recovery errors"
        );
        parse_kotlin_file(&file, source, &tree)
    }

    #[test]
    #[hardwon(
        "#6084: a primary-constructor parameter on a local class had no initialization scope"
    )]
    fn local_class_primary_constructor_initialization_scope() {
        let parsed = parse(
            "fun outer() { class Local(input: String) { val stored = input } }",
            "Local.kt",
        );
        let facts = &parsed.resolution_facts;
        let parameter = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && spelling(facts, identifier.name) == "input"
            })
            .expect("local constructor parameter");
        let scope = facts.scopes[facts.sites[parameter.site.index()].scope.index()];
        assert_eq!(scope.kind, ResolutionScopeKind::Initializer);
        let owner = scope.owner.expect("initialization scope has a class owner");
        assert!(
            facts
                .member_owners
                .iter()
                .any(|member| member.owner == owner
                    && facts.sites[member.member.index()].kind
                        == ResolutionSiteKind::ConstructorDeclaration)
        );
    }

    fn spelling(facts: &FileResolutionFacts, name: ResolutionNameId) -> &str {
        &facts.names[name.index()].spelling
    }

    /// A declared value is an instance of the written type, so its declared-type
    /// transfer converts the type object to a runtime value. An ordinary class
    /// declares no identity slot: the engine answers a type reference to it with
    /// the declaration itself, and an unseeded slot would leave every typed
    /// flow through the class without a value.
    #[test]
    fn declared_types_are_runtime_values_and_classes_have_no_unseeded_identity_slot() {
        let parsed = parse(
            "class Service { fun run(n: Int): Int = n }\nfun use(s: Service) { s.run(1) }\n",
            "Use.kt",
        );
        let facts = &parsed.resolution_facts;
        assert!(
            facts
                .type_transfers
                .iter()
                .filter(|transfer| transfer.kind == ResolutionTypeTransferKind::DeclaredType)
                .all(|transfer| transfer.value_transform
                    == ResolutionTypeTransferValueTransform::ToRuntime { addressable: false })
        );
        let service = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && spelling(facts, identifier.name) == "Service"
            })
            .expect("class declaration");
        assert!(
            !facts
                .declaration_type_slots
                .iter()
                .any(|slot| slot.declaration == service.site
                    && slot.role == DeclarationTypeRole::Identity)
        );
    }

    #[test]
    fn call_navigation_receiver_has_type_or_value_projection() {
        let parsed = parse(
            r#"object ExactFlowFixture {
    fun relay(value: String): String = value

    fun run(input: String) {
        ExactFlowFixture.relay(input)
    }
}
"#,
            "ExactFlowFixture.kt",
        );
        let facts = &parsed.resolution_facts;
        let receiver = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && spelling(facts, identifier.name) == "ExactFlowFixture"
            })
            .expect("navigation receiver reference");
        assert_eq!(
            facts.sites[receiver.site.index()].kind,
            ResolutionSiteKind::ValueReference
        );
        assert_eq!(receiver.namespace, ResolutionNamespace::TypeOrValue);
        let receiver_value = facts
            .type_slots
            .iter()
            .find(|slot| {
                slot.site == receiver.site && slot.role == ResolutionTypeSlotRole::ExpressionValue
            })
            .expect("receiver expression-value slot");
        assert!(facts.binding_projections.iter().any(|projection| {
            projection.reference == receiver.site
                && projection.output == receiver_value.id
                && projection.kind == BindingProjectionKind::TargetTypeOrDeclaredValueType
        }));

        let callee = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && spelling(facts, identifier.name) == "relay"
            })
            .expect("terminal navigation member reference");
        assert_eq!(
            facts.sites[callee.site.index()].kind,
            ResolutionSiteKind::CallableReference
        );
        let call = facts
            .calls
            .iter()
            .find(|call| call.callee == callee.site)
            .expect("call uses the terminal navigation member");
        let call_receiver = call.receiver.expect("member call has a receiver");
        assert!(facts.type_transfers.iter().any(|transfer| {
            transfer.input == receiver_value.id
                && transfer.output == call_receiver
                && transfer.kind == ResolutionTypeTransferKind::Receiver
        }));
    }

    fn alias_owner(facts: &FileResolutionFacts, alias: ResolutionJvmAliasId) -> Vec<String> {
        let mut segments = facts
            .jvm_alias_owner_segments
            .iter()
            .filter(|segment| segment.alias == alias)
            .map(|segment| (segment.ordinal, spelling(facts, segment.name).to_owned()))
            .collect::<Vec<_>>();
        segments.sort_unstable_by_key(|(ordinal, _)| *ordinal);
        segments.into_iter().map(|(_, name)| name).collect()
    }

    fn alias_name<'a>(facts: &'a FileResolutionFacts, alias: &ResolutionJvmAliasFact) -> &'a str {
        spelling(facts, alias.member_name)
    }

    #[test]
    fn anonymous_object_body_does_not_reuse_its_named_enclosing_type_owner() {
        let parsed = parse(
            "class Task { fun make(): Runnable = object : Handler(this.toString()) { override fun run() { this.hashCode() } } }",
            "Task.kt",
        );
        let facts = &parsed.resolution_facts;
        let task = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && spelling(facts, identifier.name) == "Task"
            })
            .expect("Task declaration");
        let task_body = facts
            .scopes
            .iter()
            .find(|scope| {
                scope.owner == Some(task.site) && scope.kind == ResolutionScopeKind::TypeBody
            })
            .expect("one Task body scope");
        let run = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && spelling(facts, identifier.name) == "run"
            })
            .expect("anonymous object method");
        let run_scope = facts
            .scopes
            .iter()
            .find(|scope| scope.id == facts.sites[run.site.index()].scope)
            .expect("anonymous object method scope");
        let enclosing_function_scope = facts
            .scopes
            .iter()
            .find(|scope| Some(scope.id) == run_scope.parent)
            .expect("enclosing function scope");

        let header_receiver = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && spelling(facts, identifier.name) == "toString"
            })
            .expect("anonymous header receiver call");
        let body_receiver = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && spelling(facts, identifier.name) == "hashCode"
            })
            .expect("anonymous body receiver call");
        assert_eq!(
            facts.sites[header_receiver.site.index()].scope,
            task_body.id
        );
        assert_eq!(facts.sites[body_receiver.site.index()].scope, run_scope.id);
        assert_eq!(run_scope.kind, ResolutionScopeKind::TypeBody);
        let anonymous = run_scope
            .owner
            .expect("anonymous body owns its receiver level");
        assert_ne!(anonymous, task.site);
        assert_eq!(
            facts.sites[anonymous.index()].kind,
            ResolutionSiteKind::TypeDeclaration
        );
        assert!(
            facts
                .member_owners
                .iter()
                .any(|member| member.member == run.site && member.owner == anonymous)
        );
        assert!(
            facts
                .supertypes
                .iter()
                .any(|supertype| supertype.subtype == anonymous)
        );
        assert!(
            !facts
                .binders
                .iter()
                .any(|binder| binder.declaration == anonymous)
        );
        assert!(
            !facts
                .gaps
                .iter()
                .any(|gap| gap.site == run.site && gap.kind == ResolutionGapKind::UnsupportedRoute),
            "an anonymous member needs no source-named JVM export route"
        );
        assert_eq!(
            enclosing_function_scope.kind,
            ResolutionScopeKind::Executable
        );
        assert_eq!(enclosing_function_scope.parent, Some(task_body.id));
        assert!(
            !facts
                .member_owners
                .iter()
                .any(|member| member.member == run.site && member.owner == task.site)
        );
        assert_eq!(
            facts
                .scopes
                .iter()
                .filter(|scope| {
                    scope.owner == Some(task.site) && scope.kind == ResolutionScopeKind::TypeBody
                })
                .count(),
            1
        );
    }

    #[test]
    fn emits_kotlin_source_facts_and_jvm_aliases_for_authored_surfaces() {
        let parsed = parse(
            r#"@file:JvmName("PublicApi")
package sample

import kotlin.jvm.JvmField
import kotlin.jvm.JvmName
import kotlin.jvm.JvmOverloads
import kotlin.jvm.JvmStatic

open class Holder {
    @get:JvmName("idForJava")
    @set:JvmName("setIdForJava")
    var isReady: Boolean = false
    var isActive: Boolean = true
    var ordinary: Int = 0

    companion object {
        @JvmStatic
        @JvmOverloads
        fun of(value: String, enabled: Boolean = false): Holder = Holder()

        @JvmField
        val singleton: String = ""

        const val VERSION: Int = 1
    }
}

class Child : Holder()
typealias HolderAlias = Holder

@JvmName("decodeForJava")
@JvmOverloads
fun ByteArray.decode(count: Int = 1, strict: Boolean = false): String = ""
const val API_LEVEL: Int = 9
object Registry

fun use(bytes: ByteArray, owner: Holder?) {
    Holder.of("x", enabled = true)
    bytes.decode(count = 2)
}
"#,
            "sample/Sample.kt",
        );
        let facts = &parsed.resolution_facts;

        let getter = facts
            .jvm_aliases
            .iter()
            .find(|alias| {
                alias.kind == ResolutionJvmAliasKind::Getter
                    && alias_name(facts, alias) == "idForJava"
            })
            .expect("custom Kotlin getter alias");
        assert_eq!(alias_owner(facts, getter.id), vec!["sample", "Holder"]);
        assert_eq!(getter.parameter_count, 0);
        assert!(!getter.is_static);
        assert_eq!(getter.status, ResolutionJvmAliasStatus::SourceProven);

        let setter = facts
            .jvm_aliases
            .iter()
            .find(|alias| {
                alias.kind == ResolutionJvmAliasKind::Setter
                    && alias_name(facts, alias) == "setIdForJava"
            })
            .expect("custom Kotlin setter alias");
        assert_eq!(alias_owner(facts, setter.id), vec!["sample", "Holder"]);
        assert_eq!(setter.parameter_count, 1);
        assert!(!setter.is_static);

        assert!(facts.jvm_aliases.iter().any(|alias| {
            alias.kind == ResolutionJvmAliasKind::Getter
                && alias_name(facts, alias) == "getOrdinary"
                && alias_owner(facts, alias.id) == ["sample", "Holder"]
        }));
        assert!(facts.jvm_aliases.iter().any(|alias| {
            alias.kind == ResolutionJvmAliasKind::Setter
                && alias_name(facts, alias) == "setOrdinary"
                && alias.parameter_count == 1
        }));
        assert!(facts.jvm_aliases.iter().any(|alias| {
            alias.kind == ResolutionJvmAliasKind::Getter && alias_name(facts, alias) == "isActive"
        }));
        assert!(facts.jvm_aliases.iter().any(|alias| {
            alias.kind == ResolutionJvmAliasKind::Setter && alias_name(facts, alias) == "setActive"
        }));

        let decode = facts
            .jvm_aliases
            .iter()
            .filter(|alias| {
                alias.kind == ResolutionJvmAliasKind::Method
                    && alias_name(facts, alias) == "decodeForJava"
            })
            .collect::<Vec<_>>();
        let mut decode_counts = decode
            .iter()
            .map(|alias| alias.parameter_count)
            .collect::<Vec<_>>();
        decode_counts.sort_unstable();
        assert_eq!(decode_counts, vec![1, 2, 3]);
        assert!(decode.iter().all(|alias| {
            alias.is_static
                && alias.status == ResolutionJvmAliasStatus::SourceProven
                && alias_owner(facts, alias.id) == ["sample", "PublicApi"]
        }));
        let decode_site = decode[0].declaration;
        assert!(
            facts
                .extension_receivers
                .iter()
                .any(|receiver| receiver.callable == decode_site)
        );

        let companion = facts
            .jvm_aliases
            .iter()
            .find(|alias| alias.kind == ResolutionJvmAliasKind::CompanionObject)
            .expect("companion field alias");
        assert_eq!(alias_name(facts, companion), "Companion");
        assert_eq!(alias_owner(facts, companion.id), vec!["sample", "Holder"]);
        let companion_instance = facts
            .jvm_aliases
            .iter()
            .find(|alias| {
                alias.kind == ResolutionJvmAliasKind::SingletonInstance
                    && alias_owner(facts, alias.id) == ["sample", "Holder$Companion"]
            })
            .expect("companion INSTANCE field alias");
        assert!(companion_instance.is_static);
        assert!(facts.jvm_aliases.iter().any(|alias| {
            alias.kind == ResolutionJvmAliasKind::Field
                && alias_name(facts, alias) == "singleton"
                && alias.is_static
                && alias_owner(facts, alias.id) == ["sample", "Holder"]
        }));
        assert!(facts.jvm_aliases.iter().any(|alias| {
            alias.kind == ResolutionJvmAliasKind::Field
                && alias_name(facts, alias) == "VERSION"
                && alias.is_static
                && alias_owner(facts, alias.id) == ["sample", "Holder"]
        }));
        assert!(facts.jvm_aliases.iter().any(|alias| {
            alias.kind == ResolutionJvmAliasKind::Field
                && alias_name(facts, alias) == "API_LEVEL"
                && alias.is_static
                && alias_owner(facts, alias.id) == ["sample", "PublicApi"]
        }));
        assert!(
            facts.jvm_aliases.iter().any(|alias| {
                alias.kind == ResolutionJvmAliasKind::SingletonInstance
                    && alias_owner(facts, alias.id) == ["sample", "Registry"]
            }),
            "standalone object INSTANCE alias is present"
        );

        let of_aliases = facts
            .jvm_aliases
            .iter()
            .filter(|alias| {
                alias.kind == ResolutionJvmAliasKind::Method && alias_name(facts, alias) == "of"
            })
            .collect::<Vec<_>>();
        assert!(of_aliases.iter().any(|alias| {
            !alias.is_static
                && alias.parameter_count == 1
                && alias_owner(facts, alias.id) == ["sample", "Holder$Companion"]
        }));
        assert!(of_aliases.iter().any(|alias| {
            alias.is_static
                && alias.parameter_count == 1
                && alias_owner(facts, alias.id) == ["sample", "Holder"]
        }));

        assert!(!facts.call_arguments.is_empty());
        assert!(facts.callable_receiver_origins.iter().all(|origin| {
            facts.identifiers.iter().any(|identifier| {
                identifier.site == origin.reference
                    && identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == ResolutionNamespace::Callable
            })
        }));
        assert!(facts.callable_receiver_origins.iter().any(|origin| {
            origin.origin == ResolutionCallableReceiverOrigin::ExplicitExpression
                && facts.identifiers.iter().any(|identifier| {
                    identifier.site == origin.reference
                        && spelling(facts, identifier.name) == "decode"
                        && identifier.namespace == ResolutionNamespace::Callable
                })
        }));
        assert!(facts.identifiers.iter().any(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && facts.sites[identifier.site.index()].kind == ResolutionSiteKind::TypeReference
                && spelling(facts, identifier.name) == "Holder"
        }));
        assert!(
            !facts
                .gaps
                .iter()
                .any(|gap| gap.kind == ResolutionGapKind::UnsupportedTypeSyntax)
        );
        assert!(facts.call_arguments.iter().any(|argument| {
            argument
                .label
                .is_some_and(|label| spelling(facts, label) == "enabled")
        }));
        assert!(!facts.supertypes.is_empty());
        assert!(!facts.type_transfers.is_empty());
        assert!(facts.import_selectors.iter().any(|selector| {
            selector.kind == ResolutionImportSelectorKind::Named
                && selector
                    .local_name
                    .is_some_and(|name| spelling(facts, name) == "JvmName")
        }));
        // A named import is bridged by the selected context from its root
        // route; a lexical binder would outrank that bridge, so none exists.
        assert!(
            !facts
                .binders
                .iter()
                .any(|binder| binder.kind == ResolutionBinderKind::Import)
        );
        let jvm_name_import = facts
            .import_selectors
            .iter()
            .find(|selector| {
                selector
                    .local_name
                    .is_some_and(|name| spelling(facts, name) == "JvmName")
            })
            .expect("named import selector")
            .site;
        assert!(
            facts
                .root_imports
                .iter()
                .any(|import| import.site == jvm_name_import)
        );
        assert!(
            [
                ResolutionNamespace::Type,
                ResolutionNamespace::Value,
                ResolutionNamespace::Callable
            ]
            .into_iter()
            .all(|namespace| facts.root_import_demands.iter().any(|demand| {
                demand.import_site == jvm_name_import
                    && demand.namespace == namespace
                    && spelling(facts, demand.name) == "JvmName"
            }))
        );
        let default_facade = parse(
            "package sample\nfun plain() = 1\n",
            "sample/plain_helpers.kt",
        );
        let default_alias = default_facade
            .resolution_facts
            .jvm_aliases
            .iter()
            .find(|alias| alias_name(&default_facade.resolution_facts, alias) == "plain")
            .expect("default Kotlin file facade alias");
        assert_eq!(
            alias_owner(&default_facade.resolution_facts, default_alias.id),
            vec!["sample", "Plain_helpersKt"]
        );
    }

    #[test]
    fn supported_callable_calls_project_their_result_from_the_callee() {
        let parsed = parse(
            "fun identity(value: Boolean): Boolean = value\n\
             fun use(): Boolean = identity(true)\n",
            "CallProjection.kt",
        );
        let facts = &parsed.resolution_facts;
        assert_eq!(facts.calls.len(), 1);
        let call = &facts.calls[0];
        assert!(facts.binding_projections.iter().any(|projection| {
            projection.reference == call.callee
                && projection.output == call.result
                && projection.kind == BindingProjectionKind::TargetCallableResultType
        }));
        assert!(facts.gaps.iter().any(|gap| {
            gap.site == call.callee && gap.kind == ResolutionGapKind::UnsupportedCallApplicability
        }));
    }

    #[test]
    fn value_and_member_references_project_their_declared_types() {
        let parsed = parse(
            "class Token\n\
             class Holder(val value: Token)\n\
             fun echo(value: Token): Token = value\n\
             fun read(holder: Holder): Token = holder.value\n",
            "ValueProjection.kt",
        );
        let facts = &parsed.resolution_facts;
        let references = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && spelling(facts, identifier.name) == "value"
            })
            .collect::<Vec<_>>();
        assert_eq!(references.len(), 2, "fixture has a local and member use");
        for reference in references {
            let projection = facts
                .binding_projections
                .iter()
                .find(|projection| projection.reference == reference.site)
                .expect("value reference type projection");
            let expected = match facts.sites[reference.site.index()].kind {
                ResolutionSiteKind::ValueReference => {
                    BindingProjectionKind::TargetDeclaredValueType
                }
                ResolutionSiteKind::MemberReference => {
                    BindingProjectionKind::TargetTypeOrDeclaredValueType
                }
                kind => panic!("unexpected reference site kind: {kind:?}"),
            };
            assert_eq!(projection.kind, expected);
            assert_eq!(
                facts.type_slots[projection.output.index()].role,
                ResolutionTypeSlotRole::ExpressionValue
            );
        }
        let member = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && spelling(facts, identifier.name) == "value"
                    && facts.sites[identifier.site.index()].kind
                        == ResolutionSiteKind::MemberReference
            })
            .expect("member reference has a receiver");
        let receiver = member.qualifier.expect("member reference receiver slot");
        let holder = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && spelling(facts, identifier.name) == "holder"
            })
            .expect("member receiver is a positioned value reference");
        let holder_value = facts
            .binding_projections
            .iter()
            .find(|projection| projection.reference == holder.site)
            .expect("member receiver projects its declared value type");
        assert_eq!(receiver, holder_value.output);
        assert_eq!(
            facts.type_slots[receiver.index()].role,
            ResolutionTypeSlotRole::ExpressionValue
        );
    }

    #[test]
    #[hardwon("#5015: Kotlin assignments and typed local initializers had no observed value facts")]
    fn local_writes_keep_initializer_values_and_isolate_labels_and_members() {
        let source = r#"
class Box(var member: String)
fun consume(value: String) {}
fun use(box: Box, items: Array<String>) {
    var typed: String = "first"
    var inferred = "second"
    var count = 0
    typed /* lhs */ = /* rhs */ (inferred)
    inferred = items[0]
    consume(value = typed)
    Box(member = typed)
    count += 1
    ++count
    count--
    box.member = typed
    items[0] = inferred
}
"#;
        let parsed = parse(source, "Writes.kt");
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
                spelling(facts, identifier.name)
            })
            .collect::<Vec<_>>();
        assert_eq!(targets, ["typed", "inferred", "count", "count", "count"]);
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
                                && spelling(facts, identifier.name) == name
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
        for spelling in ["box.member = typed", "items[0] = inferred"] {
            assert!(
                facts.gaps.iter().any(|gap| {
                    let site = facts.sites[gap.site.index()];
                    gap.kind == ResolutionGapKind::UnsupportedExpression
                        && &source[site.start_byte..site.end_byte] == spelling
                }),
                "{:?}",
                facts.gaps
            );
        }
    }

    #[test]
    #[hardwon(
        "b455165d7fdd: extension this initializers published a receiver slot and panicked during lowering"
    )]
    fn inferred_kotlin_declarations_take_their_type_from_the_initializer() {
        let parsed = parse(
            "fun infer(value: String) = value\nval inferred = infer(\"x\")\nval delegated by lazy { 1 }\nfun String.retain() { val str = this }\n",
            "InferredTypes.kt",
        );
        let facts = &parsed.resolution_facts;
        let function = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && identifier.namespace == ResolutionNamespace::Callable
                    && spelling(facts, identifier.name) == "infer"
            })
            .expect("inferred function declaration");
        let result_type = facts
            .declaration_type_slots
            .iter()
            .find(|property| {
                property.declaration == function.site
                    && property.role == DeclarationTypeRole::Return
            })
            .expect("inferred function has a result slot");
        assert!(facts.callable_signatures.iter().any(|signature| {
            signature.callable == function.site
                && signature
                    .result_types
                    .iter()
                    .any(|result| result.ordinal == 0 && result.value_type == result_type.slot)
        }));
        // The expression body carries the type; no gap stands in for it.
        assert!(!facts.gaps.iter().any(|gap| {
            gap.site == function.site && gap.kind == ResolutionGapKind::InferredType
        }));
        assert!(facts.type_transfers.iter().any(|transfer| {
            transfer.output == result_type.slot
                && transfer.kind == ResolutionTypeTransferKind::Initialization
        }));

        let property = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && identifier.namespace == ResolutionNamespace::Value
                    && spelling(facts, identifier.name) == "inferred"
            })
            .expect("inferred property declaration");
        assert!(facts.declaration_type_slots.iter().any(|slot| {
            slot.declaration == property.site && slot.role == DeclarationTypeRole::Value
        }));
        let property_slot = facts
            .declaration_type_slots
            .iter()
            .find(|slot| {
                slot.declaration == property.site && slot.role == DeclarationTypeRole::Value
            })
            .expect("inferred property value slot")
            .slot;
        assert!(facts.type_transfers.iter().any(|transfer| {
            transfer.output == property_slot
                && transfer.kind == ResolutionTypeTransferKind::Initialization
        }));
        assert!(!facts.gaps.iter().any(|gap| {
            gap.site == property.site && gap.kind == ResolutionGapKind::InferredType
        }));
        // Every initializer must preserve an expression value, including an
        // extension receiver used as `val str = this` (as in KotlinPoet).
        for transfer in &facts.type_transfers {
            if transfer.kind == ResolutionTypeTransferKind::Initialization {
                assert!(matches!(
                    facts.type_slots[transfer.input.index()].role,
                    ResolutionTypeSlotRole::CallResult | ResolutionTypeSlotRole::ExpressionValue
                ));
            }
        }
        // A delegate has no initializer expression to take a type from.
        let delegated = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && spelling(facts, identifier.name) == "delegated"
            })
            .expect("delegated property declaration");
        assert!(facts.gaps.iter().any(|gap| {
            gap.site == delegated.site && gap.kind == ResolutionGapKind::InferredType
        }));
    }

    #[test]
    #[hardwon("#5015: typed destructuring lost unknown incoming values before reassignment")]
    fn destructured_local_inputs_keep_static_types_and_uninitialized_shadow_separate() {
        let parsed = parse(
            "class Box\nfun use(parameter: Box) {\n\
             var (current: Box, n) = Pair(Box(), 0)\n\
             current = Box()\n\
             run { var current: Box; current = Box() }\n\
             var pending: Box\n}\n",
            "DestructuredInputs.kt",
        );
        let facts = &parsed.resolution_facts;
        let mut currents = facts
            .binders
            .iter()
            .filter(|binder| {
                facts.identifiers.iter().any(|identifier| {
                    identifier.site == binder.declaration
                        && spelling(facts, identifier.name) == "current"
                })
            })
            .collect::<Vec<_>>();
        currents.sort_unstable_by_key(|binder| facts.sites[binder.declaration.index()].start_byte);
        assert_eq!(currents.len(), 2);
        for (index, binder) in currents.iter().enumerate() {
            let declared = facts
                .declaration_type_slots
                .iter()
                .find(|row| row.declaration == binder.declaration)
                .expect("typed binding keeps its declared slot");
            assert!(facts.type_transfers.iter().any(|row| {
                row.output == declared.slot && row.kind == ResolutionTypeTransferKind::DeclaredType
            }));
            assert!(!facts.gaps.iter().any(|gap| gap.site == binder.declaration));
            let observations = facts
                .type_transfers
                .iter()
                .filter(|row| {
                    row.kind == ResolutionTypeTransferKind::Assignment
                        && facts.type_slots[row.output.index()].site == binder.declaration
                })
                .collect::<Vec<_>>();
            assert_eq!(observations.len(), usize::from(index == 0));
            if let Some(observation) = observations.first() {
                let incoming = facts.type_slots[observation.input.index()].site;
                assert_ne!(incoming, binder.declaration);
                assert_eq!(
                    facts.type_slots[observation.output.index()].role,
                    ResolutionTypeSlotRole::AssignmentValue
                );
                assert!(facts.gaps.contains(&ResolutionGapFact::new(
                    incoming,
                    ResolutionGapKind::InferredType
                )));
                assert!(
                    !facts
                        .type_transfers
                        .iter()
                        .any(|row| row.output == observation.input)
                );
            }
        }
        for name in ["n", "pending", "parameter"] {
            let declaration = facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Declaration
                        && spelling(facts, identifier.name) == name
                })
                .expect("binding declaration")
                .site;
            if name == "n" {
                assert!(facts.gaps.contains(&ResolutionGapFact::new(
                    declaration,
                    ResolutionGapKind::InferredType
                )));
            } else {
                assert!(!facts.type_slots.iter().any(|slot| {
                    slot.site == declaration && slot.role == ResolutionTypeSlotRole::AssignmentValue
                }));
            }
        }
    }

    #[test]
    fn kotlin_literal_arguments_publish_intrinsics_or_typed_gaps() {
        let source = "fun consume(value: Any?) {}\n\
                     fun use() {\n\
                         consume(\"text\")\n\
                         consume('z')\n\
                         consume(true)\n\
                         consume(17)\n\
                         consume(23L)\n\
                         consume(1.5f)\n\
                         consume(2.5)\n\
                         consume(0x12)\n\
                         consume(null)\n\
                     }\n";
        let parsed = parse(source, "LiteralTypes.kt");
        let facts = &parsed.resolution_facts;
        let expected = [
            ("\"text\"", "java.lang.String"),
            ("'z'", "kotlin.Char"),
            ("true", "kotlin.Boolean"),
            ("17", "kotlin.Int"),
            ("23L", "kotlin.Long"),
            ("1.5f", "kotlin.Float"),
            ("2.5", "kotlin.Double"),
        ];
        for (literal, expected_type) in expected {
            let start = source.find(literal).expect("literal argument source range");
            let (argument, input) = facts
                .call_arguments
                .iter()
                .find_map(|argument| {
                    let transfer = facts.type_transfers.iter().find(|transfer| {
                        transfer.kind == ResolutionTypeTransferKind::Argument
                            && transfer.output == argument.value
                    })?;
                    (facts.sites[facts.type_slots[transfer.input.index()].site.index()].start_byte
                        == start)
                        .then_some((argument, transfer.input))
                })
                .expect("literal argument slot");
            let slot = facts.type_slots[argument.value.index()];
            assert_eq!(slot.role, ResolutionTypeSlotRole::Argument);
            let seed = facts
                .intrinsic_type_seeds
                .iter()
                .find(|seed| seed.output == input)
                .expect("literal argument has an intrinsic type seed");
            assert_eq!(facts.names[seed.name.index()].spelling, expected_type);
        }

        for (literal, expected_gap) in [
            ("0x12", ResolutionGapKind::AmbiguousNumericLiteral),
            ("null", ResolutionGapKind::UnsupportedExpressionType),
        ] {
            let start = source
                .find(literal)
                .expect("incomplete literal source range");
            let (argument, input) = facts
                .call_arguments
                .iter()
                .find_map(|argument| {
                    let transfer = facts.type_transfers.iter().find(|transfer| {
                        transfer.kind == ResolutionTypeTransferKind::Argument
                            && transfer.output == argument.value
                    })?;
                    (facts.sites[facts.type_slots[transfer.input.index()].site.index()].start_byte
                        == start)
                        .then_some((argument, transfer.input))
                })
                .expect("incomplete literal argument slot");
            let site = facts.type_slots[input.index()].site;
            assert!(
                !facts
                    .intrinsic_type_seeds
                    .iter()
                    .any(|seed| seed.output == input)
            );
            assert!(
                facts
                    .gaps
                    .iter()
                    .any(|gap| gap.site == site && gap.kind == expected_gap)
            );
            assert_eq!(
                facts.type_slots[argument.value.index()].role,
                ResolutionTypeSlotRole::Argument
            );
        }
    }

    #[test]
    fn kotlin_type_parameters_publish_identity_slots() {
        let parsed = parse("class Box<T>(val value: T)\n", "TypeParameter.kt");
        let facts = &parsed.resolution_facts;
        let parameter = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && identifier.namespace == ResolutionNamespace::Type
                    && spelling(facts, identifier.name) == "T"
            })
            .expect("type parameter declaration");
        let identity = facts
            .declaration_type_slots
            .iter()
            .find(|slot| {
                slot.declaration == parameter.site && slot.role == DeclarationTypeRole::Identity
            })
            .expect("type parameter target identity slot");
        assert_eq!(
            facts.type_slots[identity.slot.index()].role,
            ResolutionTypeSlotRole::TargetTypeIdentity
        );
        let reference = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == ResolutionNamespace::Type
                    && spelling(facts, identifier.name) == "T"
            })
            .expect("type parameter type reference");
        assert!(facts.binding_projections.iter().any(|projection| {
            projection.reference == reference.site
                && projection.kind == BindingProjectionKind::TargetTypeIdentity
        }));
    }

    #[test]
    fn named_argument_labels_and_import_segments_have_positioned_references() {
        let source = "package app\n\
                     import kotlin.collections.List\n\
                     fun consume(value: String) {}\n\
                     fun consumeQuoted(`display name`: String) {}\n\
                     fun use() { consume(value = \"x\"); consumeQuoted(`display name` = \"y\") }\n";
        let parsed = parse(source, "Positioned.kt");
        let facts = &parsed.resolution_facts;
        let label = facts
            .named_argument_labels
            .first()
            .expect("named-argument label fact");
        assert_eq!(spelling(facts, label.label), "value");
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
        assert_eq!(
            source.get(
                facts.sites[label.reference.index()].start_byte
                    ..facts.sites[label.reference.index()].end_byte
            ),
            Some("value")
        );
        assert!(facts.call_arguments.iter().any(|argument| {
            argument.call == label.call
                && argument
                    .label
                    .is_some_and(|name| spelling(facts, name) == "value")
        }));
        let quoted_label = facts
            .named_argument_labels
            .iter()
            .find(|label| spelling(facts, label.label) == "display name")
            .expect("backtick-quoted label fact");
        let quoted_range = &facts.sites[quoted_label.reference.index()];
        assert_eq!(
            source.get(quoted_range.start_byte..quoted_range.end_byte),
            Some("`display name`")
        );

        for (name, namespace, site_kind) in [
            (
                "kotlin",
                ResolutionNamespace::Package,
                ResolutionSiteKind::ValueReference,
            ),
            (
                "collections",
                ResolutionNamespace::Package,
                ResolutionSiteKind::ValueReference,
            ),
            (
                "List",
                ResolutionNamespace::Type,
                ResolutionSiteKind::TypeReference,
            ),
        ] {
            let start = source
                .find(name)
                .filter(|start| *start >= source.find("import ").expect("import"))
                .expect("import path segment");
            let reference = facts.identifiers.iter().find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && spelling(facts, identifier.name) == name
                    && facts.sites[identifier.site.index()].start_byte == start
            });
            let reference = reference.expect("positioned import segment reference");
            assert_eq!(reference.namespace, namespace, "segment={name}");
            let site = &facts.sites[reference.site.index()];
            assert_eq!(site.kind, site_kind, "segment={name}");
            assert_eq!(source.get(site.start_byte..site.end_byte), Some(name));
        }
    }

    #[test]
    fn navigation_call_receiver_slot_belongs_to_the_call_site() {
        let parsed = parse(
            "/** Widget header. */\n\
             class Widget(val name: String) {\n\
               constructor() : this(\"default\") {\n\
                 check(name.isNotEmpty())\n\
               }\n\
             }\n",
            "Widget.kt",
        );
        let facts = &parsed.resolution_facts;
        assert!(!facts.calls.is_empty());
        let mut receivers = 0;
        for call in &facts.calls {
            if let Some(receiver) = call.receiver {
                receivers += 1;
                let receiver = &facts.type_slots[receiver.index()];
                assert_eq!(receiver.site, call.call);
                assert_eq!(receiver.role, ResolutionTypeSlotRole::Receiver);
            }
        }
        assert!(receivers > 0, "fixture contains a navigation call");
        assert!(!facts.call_arguments.is_empty());
        for argument in &facts.call_arguments {
            let value = &facts.type_slots[argument.value.index()];
            assert_eq!(value.site, argument.call);
            assert_eq!(value.role, ResolutionTypeSlotRole::Argument);
        }
    }

    #[hardwon(
        "9064321f79d8: trailing lambdas lacked the function type facts used for overload applicability"
    )]
    #[test]
    fn trailing_lambda_publishes_function_type_and_argument_facts() {
        let source = "open class Base { fun run(times: Int, body: () -> Unit) {} }\n\
            class Derived : Base() { fun run(times: Int) {} fun use() { run(1) {} } }\n";
        let parsed = parse(source, "Use.kt");
        let facts = &parsed.resolution_facts;
        let call = facts
            .calls
            .iter()
            .find(|call| {
                let site = &facts.sites[call.call.index()];
                source[site.start_byte..site.end_byte].contains("run(1)")
            })
            .expect("run call");
        let mut arguments = facts
            .call_arguments
            .iter()
            .filter(|argument| argument.call == call.call)
            .collect::<Vec<_>>();
        arguments.sort_unstable_by_key(|argument| argument.ordinal);
        assert_eq!(
            arguments
                .iter()
                .map(|argument| argument.ordinal)
                .collect::<Vec<_>>(),
            [0, 1]
        );
        let trailing_transfer = facts
            .type_transfers
            .iter()
            .find(|transfer| {
                transfer.output == arguments[1].value
                    && transfer.kind == ResolutionTypeTransferKind::Argument
            })
            .expect("trailing lambda argument transfer");
        let trailing_value = facts.type_slots[trailing_transfer.input.index()];
        let trailing_site = &facts.sites[trailing_value.site.index()];
        assert_eq!(trailing_site.kind, ResolutionSiteKind::Literal);
        assert!(!facts.gaps.iter().any(|gap| gap.site == trailing_value.site));
        assert!(facts.intrinsic_type_seeds.iter().any(|seed| {
            seed.output == trailing_transfer.input
                && spelling(facts, seed.name) == "kotlin.Function0"
        }));

        let function_slot = facts
            .type_slots
            .iter()
            .find(|slot| {
                slot.role == ResolutionTypeSlotRole::TargetTypeIdentity
                    && facts.sites[slot.site.index()].kind == ResolutionSiteKind::TypeReference
                    && source[facts.sites[slot.site.index()].start_byte
                        ..facts.sites[slot.site.index()].end_byte]
                        .contains("() -> Unit")
            })
            .expect("declared function type");
        assert!(facts.intrinsic_type_seeds.iter().any(|seed| {
            seed.output == function_slot.id && spelling(facts, seed.name) == "kotlin.Function0"
        }));
    }

    #[test]
    fn leaves_compiler_dependent_and_unproven_jvm_routes_explicit() {
        let multifile = parse(
            r#"@file:JvmName("SharedApi")
@file:JvmMultifileClass
package sample

interface Contract {
    fun run(value: String): String = value
}

suspend fun later(): String = ""
fun exported(): Int = 1
"#,
            "sample/Part.kt",
        );
        let facts = &multifile.resolution_facts;
        let later = facts
            .jvm_aliases
            .iter()
            .find(|alias| alias_name(facts, alias) == "later")
            .expect("suspend callable has an incomplete JVM alias");
        assert_eq!(
            later.status,
            ResolutionJvmAliasStatus::CompilerModeDependent
        );
        assert_eq!(alias_owner(facts, later.id), vec!["sample", "SharedApi"]);
        let exported = facts
            .jvm_aliases
            .iter()
            .find(|alias| alias_name(facts, alias) == "exported")
            .expect("multifile callable alias");
        assert_eq!(
            exported.status,
            ResolutionJvmAliasStatus::CompilerModeDependent
        );
        let default_impl = facts
            .jvm_aliases
            .iter()
            .find(|alias| {
                alias_name(facts, alias) == "run"
                    && alias.status == ResolutionJvmAliasStatus::CompilerModeDependent
                    && alias_owner(facts, alias.id) == ["sample", "Contract$DefaultImpls"]
            })
            .expect("DefaultImpls stays incomplete without compiler-mode selection");
        assert!(default_impl.is_static);
        assert_eq!(default_impl.parameter_count, 2);

        let shadowed = parse(
            r#"package sample

annotation class JvmName(val name: String)

@JvmName("localName")
fun original() {}
"#,
            "sample/Shadowed.kt",
        );
        let shadowed_facts = &shadowed.resolution_facts;
        let declaration = shadowed_facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && identifier.namespace == ResolutionNamespace::Callable
                    && spelling(shadowed_facts, identifier.name) == "original"
            })
            .expect("source function declaration");
        assert!(shadowed_facts.jvm_aliases.iter().any(|alias| {
            alias.declaration == declaration.site && alias.kind == ResolutionJvmAliasKind::Method
        }));
        assert!(!shadowed_facts.gaps.iter().any(|gap| {
            gap.site == declaration.site && gap.kind == ResolutionGapKind::UnsupportedRoute
        }));
    }
}
