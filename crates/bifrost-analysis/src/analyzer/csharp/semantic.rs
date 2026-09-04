//! CSharp lowering into the language-neutral executable-semantics IR.
//!
//! This module deliberately interprets tree-sitter nodes and fields directly.
//! Graph construction, abrupt-completion routing, cleanup specialization, and
//! physical adjacency storage remain owned by the shared semantic substrate.

use tree_sitter::Node;

use crate::analyzer::lexical_definitions::formal_parameter_slots_for_owner;
use crate::analyzer::semantic::cfg::{
    CleanupRegionId, CompletionKind, CompletionRequest, CompletionRoute, ProcedureCfgBuilder,
    ScopeBinding, ScopeFrameId,
};
use crate::analyzer::semantic::service::{ProgramSemanticsLowerer, SemanticAdapterIdentity};
use crate::analyzer::semantic::*;
use crate::analyzer::tree_sitter_analyzer::{
    PreparedSyntaxTree, WalkControl, try_walk_named_tree_preorder,
};
use crate::analyzer::{CSharpAnalyzer, Language, ProjectFile};
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_core::analyzer::tree_walk::ParentIndex;

const ADAPTER_VERSION: &[u8] = b"csharp-value-semantics-v7";

impl_program_semantics_provider!(CSharpAnalyzer, CSharpSemanticLowerer);

struct CSharpSemanticLowerer;

impl ProgramSemanticsLowerer for CSharpSemanticLowerer {
    fn identity(&self) -> SemanticAdapterIdentity {
        SemanticAdapterIdentity {
            adapter: AdapterSemanticsVersion::hash_bytes("csharp", ADAPTER_VERSION)
                .expect("adapter name is non-empty"),
            configuration: ConfigurationFingerprint::hash_bytes(
                b"csharp-intrafile-execution-defaults-v1",
            ),
            dependencies: DependencyFingerprint::hash_bytes(b"no-intrafile-dependencies"),
        }
    }

    fn capabilities(&self) -> SemanticCapabilities {
        csharp_capabilities()
    }

    fn lower(
        &self,
        file: &ProjectFile,
        prepared: &PreparedSyntaxTree,
        budget: &SemanticBudget,
        cancellation: &CancellationToken,
    ) -> Result<SemanticOutcome<Vec<ProcedureSemanticsParts>>, SemanticProviderError> {
        let (procedure_inventory, initial_work) =
            match enumerate_procedures(file, prepared, budget, cancellation)? {
                ProcedureEnumeration::Complete {
                    value,
                    initial_work,
                    ..
                } => (value, initial_work),
                ProcedureEnumeration::ExceededBudget { exceeded, work } => {
                    return Ok(SemanticOutcome::ExceededBudget {
                        partial: None,
                        exceeded,
                        work,
                    });
                }
                ProcedureEnumeration::Cancelled { work } => {
                    return Ok(SemanticOutcome::Cancelled {
                        partial: None,
                        work,
                    });
                }
            };

        let ProcedureInventory {
            specs,
            static_callable_returns,
            type_receiver_shadows,
            member_declarations,
        } = procedure_inventory;
        lower_procedure_batch(
            &specs,
            initial_work,
            budget,
            cancellation,
            |spec, staged_budget, cancellation| {
                lower_procedure(
                    prepared,
                    spec,
                    &static_callable_returns,
                    &type_receiver_shadows,
                    &member_declarations,
                    staged_budget,
                    cancellation,
                )
            },
        )
    }
}

fn csharp_capabilities() -> SemanticCapabilities {
    let mut builder = SemanticCapabilities::builder();
    for capability in [
        SemanticCapability::Procedures,
        SemanticCapability::EntryBoundary,
        SemanticCapability::NormalExitBoundary,
        SemanticCapability::ExceptionalExitBoundary,
        SemanticCapability::BasicBlocks,
        SemanticCapability::ProgramPoints,
        SemanticCapability::ReturnFlow,
        SemanticCapability::NormalCallContinuation,
        SemanticCapability::ExceptionalCallContinuation,
    ] {
        builder = builder.complete(capability);
    }
    for capability in [
        SemanticCapability::NormalControlFlow,
        SemanticCapability::ExceptionalControlFlow,
        SemanticCapability::CleanupControlFlow,
        SemanticCapability::Calls,
        SemanticCapability::DynamicDispatch,
        SemanticCapability::CallableReferences,
        SemanticCapability::Values,
        SemanticCapability::Assignments,
        SemanticCapability::Allocations,
        SemanticCapability::LocalFlow,
        SemanticCapability::ParameterFlow,
        SemanticCapability::ReceiverFlow,
        // Partial, not complete: a write through a field, static, or indexer
        // target becomes a `MemoryStore` against a structured location, but
        // whether that location is the *declared* member is only known when
        // this file can resolve the base's type, so an unresolved occurrence
        // still publishes its own location-subject gap (#2661).
        SemanticCapability::FieldMemory,
        SemanticCapability::StaticMemory,
        SemanticCapability::IndexMemory,
        SemanticCapability::Captures,
        SemanticCapability::NonLocalControl,
        SemanticCapability::ResourceManagement,
        SemanticCapability::DeferredExecution,
        SemanticCapability::AsyncSuspendResume,
        SemanticCapability::GeneratorSuspension,
        SemanticCapability::GuardFacts,
    ] {
        builder = builder.partial(capability);
    }
    builder.build()
}

#[derive(Clone)]
struct ProcedureSpec<'tree> {
    id: ProcedureId,
    body: Node<'tree>,
    locator: SemanticLocator,
    lexical_parent: Option<ProcedureId>,
    kind: ProcedureKind,
    properties: ProcedureProperties,
    callable: Node<'tree>,
}

/// One member -- a method, a field, or a property -- named by the type that
/// declares it. The namespace is part of the key because two namespaces may
/// each declare a `Config` with a `Value` member and they are not the same
/// member.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TypeMemberKey {
    namespace: Box<[Box<str>]>,
    owner: Box<str>,
    name: Box<str>,
}

type StaticCallableReturnTypes = HashMap<TypeMemberKey, Option<Box<str>>>;

/// One field or property declaration, as the enumeration pass sees it.
///
/// `anchor` is the declaration's own source anchor, which is what makes two
/// occurrences of the same member in different procedures agree on one
/// [`MemoryLocationKind`] identity rather than each minting its own.
#[derive(Debug, Clone)]
struct MemberDeclaration {
    anchor: SourceAnchor,
    is_static: bool,
    /// The member's declared type spelling, when this file knows it.
    ///
    /// This is what lets a write through the member ask the same
    /// identity-preservation question a local declaration asks, instead of
    /// declining every member assignment's result on principle (#2661).
    type_spelling: Option<Box<str>>,
}

/// Declared fields and properties, keyed by owning type and member name.
///
/// A `None` value records a name that more than one declaration in this file
/// claims. Such a name resolves to no single anchor, so an occurrence of it
/// must decline rather than pick one arbitrarily -- the same collapse
/// [`StaticCallableReturnTypes`] performs for an overloaded static method.
type MemberDeclarations = HashMap<TypeMemberKey, Option<MemberDeclaration>>;

#[derive(Debug, Default)]
struct TypeReceiverShadows {
    resolution_open: bool,
    names: HashSet<Box<str>>,
}

type TypeReceiverShadowIndex = HashMap<usize, TypeReceiverShadows>;

struct ProcedureInventory<'tree> {
    specs: Vec<ProcedureSpec<'tree>>,
    static_callable_returns: StaticCallableReturnTypes,
    type_receiver_shadows: TypeReceiverShadowIndex,
    member_declarations: MemberDeclarations,
}

type ProcedureEnumeration<'tree> = ProcedureInventoryOutcome<ProcedureInventory<'tree>>;

struct ProcedureEnumerationFrame<'tree> {
    node: Node<'tree>,
    lexical_parent: Option<ProcedureId>,
    declaration_path: usize,
}

fn enumerate_procedures<'tree>(
    file: &ProjectFile,
    prepared: &'tree PreparedSyntaxTree,
    budget: &SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<ProcedureEnumeration<'tree>, SemanticProviderError> {
    let root = prepared.tree().root_node();
    let ancestry = ParentIndex::new(root);
    let mut inventory =
        ProcedureInventoryBuilder::new(file, prepared.dialect(), root, "csharp-source", budget)?;
    let mut specs = Vec::new();
    let mut static_callable_returns = StaticCallableReturnTypes::default();
    let mut type_receiver_shadows = TypeReceiverShadowIndex::default();
    let mut member_declarations = MemberDeclarations::default();
    let root_path = file_scoped_namespace_path(prepared.source(), root, &mut inventory)?;
    let mut stack = vec![ProcedureEnumerationFrame {
        node: root,
        lexical_parent: None,
        declaration_path: root_path,
    }];

    while let Some(frame) = stack.pop() {
        if cancellation.is_cancelled() {
            return Ok(inventory.cancelled());
        }
        if let Err(stop) = inventory.charge_traversal_entry() {
            return Ok(stop.into_outcome());
        }
        let mut child_path = frame.declaration_path;
        if let Some(segment_kind) = declaration_container_kind(frame.node) {
            let name = declaration_container_name(prepared.source(), frame.node);
            let anchor =
                source_anchor(frame.node, 0).map_err(SemanticProviderError::invalid_identity)?;
            child_path = inventory.push_container(
                frame.declaration_path,
                segment_kind,
                name.as_deref(),
                anchor,
            )?;
            if segment_kind == DeclarationSegmentKind::Type {
                type_receiver_shadows.insert(
                    frame.node.start_byte(),
                    TypeReceiverShadows {
                        resolution_open: has_modifier(prepared.source(), frame.node, "partial"),
                        names: HashSet::default(),
                    },
                );
            }
        }
        record_type_receiver_shadow(&mut type_receiver_shadows, frame.node, prepared.source());
        record_static_callable_return_type(
            &mut static_callable_returns,
            frame.node,
            prepared.source(),
        );
        record_member_declarations(&mut member_declarations, frame.node, prepared.source());

        let mut child_parent = frame.lexical_parent;
        if let Some((kind, segment_kind, body, properties)) =
            callable_shape(prepared.source(), frame.node, &ancestry)
        {
            let name = callable_name(prepared.source(), frame.node);
            let anchor =
                source_anchor(frame.node, 0).map_err(SemanticProviderError::invalid_identity)?;
            let identity = match inventory.allocate_procedure(
                child_path,
                segment_kind,
                name.as_deref(),
                anchor,
            )? {
                Ok(identity) => identity,
                Err(stop) => return Ok(stop.into_outcome()),
            };
            let spec = ProcedureSpec {
                id: identity.id,
                body,
                locator: identity.locator,
                lexical_parent: frame.lexical_parent,
                kind,
                properties,
                callable: frame.node,
            };
            specs.push(spec);
            child_parent = Some(identity.id);
            child_path = identity.declaration_path;
        }

        let mut cursor = frame.node.walk();
        let children = frame.node.named_children(&mut cursor).collect::<Vec<_>>();
        for child in children.into_iter().rev() {
            stack.push(ProcedureEnumerationFrame {
                node: child,
                lexical_parent: child_parent,
                declaration_path: child_path,
            });
        }
    }

    Ok(inventory.complete(ProcedureInventory {
        specs,
        static_callable_returns,
        type_receiver_shadows,
        member_declarations,
    }))
}

fn file_scoped_namespace_path(
    source: &str,
    root: Node<'_>,
    inventory: &mut ProcedureInventoryBuilder<'_>,
) -> Result<usize, SemanticProviderError> {
    let Some(namespace) = named_children(root)
        .into_iter()
        .find(|child| child.kind() == "file_scoped_namespace_declaration")
    else {
        return Ok(inventory.root_path());
    };
    let name = declaration_container_name(source, namespace);
    let anchor = source_anchor(namespace, 0).map_err(SemanticProviderError::invalid_identity)?;
    inventory.push_container(
        inventory.root_path(),
        DeclarationSegmentKind::Namespace,
        name.as_deref(),
        anchor,
    )
}

fn declaration_container_kind(node: Node<'_>) -> Option<DeclarationSegmentKind> {
    match node.kind() {
        "namespace_declaration" => Some(DeclarationSegmentKind::Namespace),
        "class_declaration"
        | "interface_declaration"
        | "struct_declaration"
        | "enum_declaration"
        | "record_declaration"
        | "record_struct_declaration" => Some(DeclarationSegmentKind::Type),
        _ => None,
    }
}

fn declaration_container_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    node.child_by_field_name("name")
        .and_then(|name| nonempty_node_text(source, name))
        .map(Box::<str>::from)
}

fn callable_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    if node.kind() == "constructor_declaration" && has_modifier(source, node, "static") {
        return Some(Box::<str>::from("<static-constructor>"));
    }
    if node.kind() == "destructor_declaration" {
        return node
            .child_by_field_name("name")
            .and_then(|name| nonempty_node_text(source, name))
            .map(|name| format!("~{name}").into_boxed_str());
    }
    if node.kind() == "accessor_declaration" {
        let accessor = node
            .child_by_field_name("name")
            .and_then(|name| nonempty_node_text(source, name))?;
        let owner = enclosing_accessor_owner(node)
            .and_then(|owner| accessor_owner_name(source, owner))
            .unwrap_or_else(|| Box::<str>::from("<accessor>"));
        return Some(format!("{owner}.{accessor}").into_boxed_str());
    }
    if matches!(node.kind(), "property_declaration" | "indexer_declaration") {
        return accessor_owner_name(source, node)
            .map(|owner| format!("{owner}.get").into_boxed_str());
    }
    if node.kind() == "operator_declaration" {
        return node
            .child_by_field_name("operator")
            .and_then(|operator| nonempty_node_text(source, operator))
            .map(|operator| format!("operator {operator}").into_boxed_str());
    }
    if node.kind() == "conversion_operator_declaration" {
        let target = node
            .child_by_field_name("type")
            .and_then(|ty| nonempty_node_text(source, ty))?;
        let flavor = if has_direct_token(node, "implicit") {
            "implicit"
        } else {
            "explicit"
        };
        return Some(format!("{flavor} operator {target}").into_boxed_str());
    }
    node.child_by_field_name("name")
        .and_then(|name| nonempty_node_text(source, name))
        .map(Box::<str>::from)
        .or_else(|| enclosing_variable_name(source, node))
}

fn record_static_callable_return_type(
    returns: &mut StaticCallableReturnTypes,
    callable: Node<'_>,
    source: &str,
) {
    if callable.kind() != "method_declaration" || !has_modifier(source, callable, "static") {
        return;
    }
    let Some(owner_node) = enclosing_type_node(callable) else {
        return;
    };
    if enclosing_type_node(owner_node).is_some() {
        return;
    }
    let Some(owner) = declaration_container_name(source, owner_node) else {
        return;
    };
    let Some(name) = callable_name(source, callable) else {
        return;
    };
    let return_type = callable
        .child_by_field_name("returns")
        .or_else(|| callable.child_by_field_name("type"))
        .and_then(|return_type| declared_type_spelling(return_type, source));
    let key = TypeMemberKey {
        namespace: enclosing_namespace_path(source, callable),
        owner,
        name,
    };
    match returns.entry(key) {
        std::collections::hash_map::Entry::Occupied(mut entry) => {
            entry.insert(None);
        }
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(return_type);
        }
    }
}

/// Index the fields and properties a type declares, so that an occurrence of
/// one can name the *declaration's* anchor rather than its own (#2661).
///
/// Two reads of `this.value` in different procedures must agree that they name
/// one location; anchoring each to its own occurrence would make them two.
///
/// A nested type is indexed like any other. The key carries only the innermost
/// type name, so a nested `Inner` and a top-level `Inner` in the same namespace
/// share one key -- but the duplicate collapse below already turns that into a
/// decline, which is the honest answer and a strictly better one than refusing
/// every nested type outright. Refusing them was how a `sealed class Holder`
/// nested in a static host ended up with each occurrence of `h.Tainted`
/// anchored to itself, so a store and a later load named two locations that
/// only looked alike and no heap fact could ever connect them (#2661).
fn record_member_declarations(members: &mut MemberDeclarations, node: Node<'_>, source: &str) {
    let names = match node.kind() {
        "field_declaration" | "event_field_declaration" => named_children(node)
            .into_iter()
            .filter(|child| child.kind() == "variable_declaration")
            .flat_map(named_children)
            .filter(|child| child.kind() == "variable_declarator")
            .filter_map(|declarator| {
                declarator
                    .child_by_field_name("name")
                    .or_else(|| first_runtime_named_child(declarator))
            })
            .collect::<Vec<_>>(),
        "property_declaration" | "event_declaration" => {
            node.child_by_field_name("name").into_iter().collect()
        }
        _ => return,
    };
    if names.is_empty() {
        return;
    }
    let Some(owner_node) = enclosing_type_node(node) else {
        return;
    };
    let Some(owner) = declaration_container_name(source, owner_node) else {
        return;
    };
    // A `const` member is class-wide storage exactly as a `static` one is; C#
    // simply implies the modifier rather than requiring it.
    let is_static = has_modifier(source, node, "static") || has_modifier(source, node, "const");
    // A field declares its type on the inner `variable_declaration`; a
    // property declares it on the declaration itself.
    let type_spelling = named_children(node)
        .into_iter()
        .find(|child| child.kind() == "variable_declaration")
        .and_then(|declaration| declaration.child_by_field_name("type"))
        .or_else(|| node.child_by_field_name("type"))
        .and_then(|type_node| declared_type_spelling(type_node, source));
    let namespace = enclosing_namespace_path(source, node);
    for name_node in names {
        let Some(name) = nonempty_node_text(source, name_node) else {
            continue;
        };
        let Ok(anchor) = source_anchor(name_node, 0) else {
            continue;
        };
        let key = TypeMemberKey {
            namespace: namespace.clone(),
            owner: owner.clone(),
            name: Box::from(name),
        };
        match members.entry(key) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(Some(MemberDeclaration {
                    anchor,
                    is_static,
                    type_spelling: type_spelling.clone(),
                }));
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                entry.insert(None);
            }
        }
    }
}

fn enclosing_namespace_path(source: &str, node: Node<'_>) -> Box<[Box<str>]> {
    let mut path = Vec::new();
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "namespace_declaration" | "file_scoped_namespace_declaration"
        ) && let Some(name) = declaration_container_name(source, parent)
        {
            path.push(name);
        }
        current = parent.parent();
    }
    path.reverse();
    path.into_boxed_slice()
}

fn enclosing_accessor_owner(node: Node<'_>) -> Option<Node<'_>> {
    let list = node.parent()?;
    (list.kind() == "accessor_list")
        .then(|| list.parent())
        .flatten()
}

fn accessor_owner_name(source: &str, owner: Node<'_>) -> Option<Box<str>> {
    match owner.kind() {
        "indexer_declaration" => Some(Box::<str>::from("this")),
        "property_declaration" | "event_declaration" => owner
            .child_by_field_name("name")
            .and_then(|name| nonempty_node_text(source, name))
            .map(Box::<str>::from),
        _ => None,
    }
}

fn enclosing_variable_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    let mut value = node;
    loop {
        let parent = value.parent()?;
        match parent.kind() {
            "parenthesized_expression" => value = parent,
            "variable_declarator" => {
                return parent
                    .child_by_field_name("name")
                    .and_then(|name| nonempty_node_text(source, name))
                    .map(Box::<str>::from);
            }
            "assignment_expression" if field_matches(parent, "right", value) => {
                return parent
                    .child_by_field_name("left")
                    .and_then(|left| nonempty_node_text(source, left))
                    .map(Box::<str>::from);
            }
            _ => return None,
        }
    }
}

fn callable_shape<'tree>(
    source: &str,
    node: Node<'tree>,
    ancestry: &ParentIndex<'tree>,
) -> Option<(
    ProcedureKind,
    DeclarationSegmentKind,
    Node<'tree>,
    ProcedureProperties,
)> {
    let (kind, segment_kind, body, is_static) = match node.kind() {
        "method_declaration" => (
            ProcedureKind::Method,
            DeclarationSegmentKind::Method,
            callable_body(node)?,
            has_modifier(source, node, "static"),
        ),
        "constructor_declaration" if has_modifier(source, node, "static") => (
            ProcedureKind::Initializer,
            DeclarationSegmentKind::Initializer,
            callable_body(node)?,
            true,
        ),
        "constructor_declaration" => (
            ProcedureKind::Constructor,
            DeclarationSegmentKind::Constructor,
            callable_body(node)?,
            false,
        ),
        "local_function_statement" => (
            ProcedureKind::LocalFunction,
            DeclarationSegmentKind::LocalFunction,
            callable_body(node)?,
            has_modifier(source, node, "static"),
        ),
        "lambda_expression" => (
            ProcedureKind::Lambda,
            DeclarationSegmentKind::Lambda,
            callable_body(node)?,
            has_modifier(source, node, "static"),
        ),
        "anonymous_method_expression" => (
            ProcedureKind::Lambda,
            DeclarationSegmentKind::AnonymousCallable,
            named_children(node)
                .into_iter()
                .find(|child| child.kind() == "block")?,
            has_modifier(source, node, "static"),
        ),
        "accessor_declaration" => (
            ProcedureKind::Accessor,
            DeclarationSegmentKind::Method,
            callable_body(node)?,
            enclosing_accessor_owner(node)
                .is_some_and(|owner| has_modifier(source, owner, "static")),
        ),
        "property_declaration" | "indexer_declaration"
            if node
                .child_by_field_name("value")
                .is_some_and(|value| value.kind() == "arrow_expression_clause") =>
        {
            (
                ProcedureKind::Accessor,
                DeclarationSegmentKind::Method,
                first_named_child(node.child_by_field_name("value")?)?,
                has_modifier(source, node, "static"),
            )
        }
        "operator_declaration" | "conversion_operator_declaration" => (
            ProcedureKind::Operator,
            DeclarationSegmentKind::Method,
            callable_body(node)?,
            true,
        ),
        "destructor_declaration" => (
            ProcedureKind::Method,
            DeclarationSegmentKind::Method,
            callable_body(node)?,
            false,
        ),
        _ => return None,
    };
    let is_generator = body_contains_yield(body);
    let dispatch_extensibility =
        brokk_bifrost_csharp::syntax::csharp_callable_dispatch_extensibility(
            source, node, is_static, ancestry,
        );
    Some((
        kind,
        segment_kind,
        body,
        ProcedureProperties {
            is_async: has_modifier(source, node, "async"),
            is_generator,
            is_static,
            is_synthetic: false,
            invocation: if is_generator {
                ProcedureInvocationKind::Deferred
            } else {
                ProcedureInvocationKind::Immediate
            },
            dispatch_extensibility,
        },
    ))
}

fn callable_body(node: Node<'_>) -> Option<Node<'_>> {
    let body = node.child_by_field_name("body")?;
    if body.kind() == "arrow_expression_clause" {
        first_named_child(body)
    } else {
        Some(body)
    }
}

fn has_modifier(source: &str, node: Node<'_>, modifier: &str) -> bool {
    named_children(node).into_iter().any(|child| {
        child.kind() == "modifier" && node_text(source, child).is_some_and(|text| text == modifier)
    })
}

fn has_direct_token(node: Node<'_>, kind: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor).any(|child| child.kind() == kind)
}

fn body_contains_yield(body: Node<'_>) -> bool {
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if node != body && is_callable_kind(node.kind()) {
            continue;
        }
        if node.kind() == "yield_statement" {
            return true;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    false
}

fn field_matches(parent: Node<'_>, field: &str, child: Node<'_>) -> bool {
    parent
        .child_by_field_name(field)
        .is_some_and(|candidate| candidate.id() == child.id())
}

type CSharpLoweringError = ProcedureLoweringError;

type EdgeTarget = ControlTarget;

#[derive(Debug, Clone, Copy)]
enum Work<'tree> {
    Statement {
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
    },
    Expression {
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
    },
    Condition {
        node: Node<'tree>,
        entry: ProgramPointId,
        when_true: EdgeTarget,
        when_false: EdgeTarget,
        scope: ScopeFrameId,
    },
}

impl<'tree> Work<'tree> {
    const fn statement(
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
    ) -> Self {
        Self::Statement {
            node,
            entry,
            next,
            scope,
        }
    }

    const fn expression(
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
    ) -> Self {
        Self::Expression {
            node,
            entry,
            next,
            scope,
        }
    }

    const fn condition(
        node: Node<'tree>,
        entry: ProgramPointId,
        when_true: EdgeTarget,
        when_false: EdgeTarget,
        scope: ScopeFrameId,
    ) -> Self {
        Self::Condition {
            node,
            entry,
            when_true,
            when_false,
            scope,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct CleanupRegion<'tree> {
    id: CleanupRegionId,
    body: CleanupBody<'tree>,
    outer_scope: ScopeFrameId,
}

#[derive(Debug, Clone, Copy)]
enum CleanupBody<'tree> {
    Statement(Node<'tree>),
    OpaqueResource(Node<'tree>),
    OpaqueFixed(Node<'tree>),
    OpaqueMonitor(Node<'tree>),
}

impl<'tree> CleanupBody<'tree> {
    const fn source_node(self) -> Node<'tree> {
        match self {
            Self::Statement(node)
            | Self::OpaqueResource(node)
            | Self::OpaqueFixed(node)
            | Self::OpaqueMonitor(node) => node,
        }
    }
}

struct LoweringContext<'tree, 'targets> {
    prepared: &'tree PreparedSyntaxTree,
    static_callable_returns: &'targets StaticCallableReturnTypes,
    type_receiver_shadows: &'targets TypeReceiverShadowIndex,
    member_declarations: &'targets MemberDeclarations,
    /// One value per distinct constant subscript spelling in this procedure.
    ///
    /// An element location is identified by its base and index *values*, so
    /// two occurrences of `values[0]` must share one index value or they
    /// address two different elements. Java canonicalizes the same way.
    constant_index_values: HashMap<Box<str>, ValueId>,
    callable_type_parameters: HashSet<Box<str>>,
    session: ProcedureLoweringSession<'targets>,
    expression_values: HashMap<usize, ValueId>,
    parameters: HashMap<Box<str>, ValueId>,
    parameter_types: HashMap<Box<str>, Box<str>>,
    locals: HashMap<Box<str>, Vec<LocalBinding>>,
    receiver: Option<ValueId>,
    cleanups: Vec<CleanupRegion<'tree>>,
}

/// One structured heap location an access expression names, together with
/// whether this file proved which declaration it addresses.
#[derive(Debug, Clone, Copy)]
struct MemoryTarget {
    location: MemoryLocationId,
    kind: MemoryAccessKind,
    resolved: bool,
}

struct LocalBinding {
    declaration_start: usize,
    visible_from: usize,
    scope_start: usize,
    scope_end: usize,
    value: ValueId,
    type_identity: Option<Box<str>>,
}

fn lower_procedure<'tree, 'targets>(
    prepared: &'tree PreparedSyntaxTree,
    spec: &ProcedureSpec<'tree>,
    static_callable_returns: &'targets StaticCallableReturnTypes,
    type_receiver_shadows: &'targets TypeReceiverShadowIndex,
    member_declarations: &'targets MemberDeclarations,
    budget: &'targets SemanticBudget,
    cancellation: &'targets CancellationToken,
) -> Result<(ProcedureSemanticsParts, SemanticWork), CSharpLoweringError> {
    let mut parts = ProcedureSemanticsParts::new(
        spec.id,
        spec.locator.clone(),
        spec.kind,
        SourceMappingId::new(0),
        EvidenceId::new(0),
    );
    parts.lexical_parent = spec.lexical_parent;
    parts.properties = spec.properties;
    let ProcedureLoweringStart {
        mut builder,
        session,
        entry,
        normal_exit,
        exceptional_exit,
        function_scope,
    } = ProcedureLoweringSession::start(parts, budget, cancellation)?;
    let mut context = LoweringContext {
        prepared,
        static_callable_returns,
        type_receiver_shadows,
        member_declarations,
        constant_index_values: HashMap::default(),
        callable_type_parameters: callable_type_parameter_names(spec.callable, prepared.source()),
        session,
        expression_values: HashMap::default(),
        parameters: HashMap::default(),
        parameter_types: HashMap::default(),
        locals: HashMap::default(),
        receiver: None,
        cleanups: Vec::new(),
    };
    context.emit_procedure_inputs(&mut builder, spec.callable, spec.kind, spec.properties)?;
    context.emit_local_bindings(&mut builder, spec.body)?;

    if spec.lexical_parent.is_some() {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::Captures,
            SemanticGapKind::Unsupported,
            "lexical captures by nested C# callables are not yet modeled",
        )?;
    }

    if spec.kind == ProcedureKind::Initializer {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::DeferredExecution,
            SemanticGapKind::Unsupported,
            "initializer scheduling and source-order composition across initializer fragments are not yet modeled",
        )?;
    }
    if spec.callable.kind() == "destructor_declaration" {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::DeferredExecution,
            SemanticGapKind::Unsupported,
            "finalizer scheduling and nondeterministic execution are not modeled",
        )?;
    }
    if spec.properties.is_async {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::AsyncSuspendResume,
            SemanticGapKind::Unsupported,
            "async method task construction, scheduling, and synchronization context are not fully modeled",
        )?;
    }
    if spec.properties.is_generator {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::GeneratorSuspension,
            SemanticGapKind::Unsupported,
            "iterator state-machine construction and suspension are not fully modeled",
        )?;
    }

    let constructor_initializer = (spec.kind == ProcedureKind::Constructor)
        .then(|| {
            named_children(spec.callable)
                .into_iter()
                .find(|child| child.kind() == "constructor_initializer")
        })
        .flatten();
    if spec.kind == ProcedureKind::Constructor && constructor_initializer.is_none() {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unsupported,
            "implicit base-constructor invocation is not represented as a call site",
        )?;
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            "implicit base-constructor invocation can complete exceptionally",
        )?;
    }

    let body_entry = context.point(&mut builder, spec.body, Vec::new())?;
    let body_work = if spec.body.kind() == "block" {
        Work::Statement {
            node: spec.body,
            entry: body_entry,
            next: EdgeTarget::normal(normal_exit),
            scope: function_scope,
        }
    } else if !callable_returns_value(prepared.source(), spec) {
        Work::Expression {
            node: spec.body,
            entry: body_entry,
            next: EdgeTarget::normal(normal_exit),
            scope: function_scope,
        }
    } else {
        let implicit_return = context.point(&mut builder, spec.body, Vec::new())?;
        let source =
            context.expression_value(&mut builder, spec.body, expression_value_kind(spec.body))?;
        let value = context.value(&mut builder, implicit_return, SemanticValueKind::Return)?;
        context.append_effect(
            &mut builder,
            implicit_return,
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Return,
                source,
                target: value,
            },
        )?;
        context.append_effect(
            &mut builder,
            implicit_return,
            SemanticEffect::ProcedureReturn { value: Some(value) },
        )?;
        context.edge(
            &mut builder,
            implicit_return,
            EdgeTarget::normal(normal_exit),
        )?;
        Work::Expression {
            node: spec.body,
            entry: body_entry,
            next: EdgeTarget::normal(implicit_return),
            scope: function_scope,
        }
    };
    let mut pending = vec![body_work];
    if let Some(initializer) = constructor_initializer {
        let initializer_entry = context.point(&mut builder, initializer, Vec::new())?;
        context.edge(&mut builder, entry, EdgeTarget::normal(initializer_entry))?;
        pending.push(Work::Expression {
            node: initializer,
            entry: initializer_entry,
            next: EdgeTarget::normal(body_entry),
            scope: function_scope,
        });
    } else {
        context.edge(&mut builder, entry, EdgeTarget::normal(body_entry))?;
    }

    drive_and_finish_procedure(
        builder,
        pending.drain(..).rev(),
        entry,
        normal_exit,
        exceptional_exit,
        cancellation,
        |builder, work, stack| context.step(builder, work, stack),
    )
}

fn callable_returns_value(source: &str, spec: &ProcedureSpec<'_>) -> bool {
    match spec.kind {
        ProcedureKind::Constructor | ProcedureKind::Initializer => false,
        ProcedureKind::Accessor => {
            if spec.callable.kind() != "accessor_declaration" {
                return true;
            }
            spec.callable
                .child_by_field_name("name")
                .and_then(|name| node_text(source, name))
                .is_some_and(|name| name == "get")
        }
        ProcedureKind::Method if spec.callable.kind() == "destructor_declaration" => false,
        ProcedureKind::Method | ProcedureKind::LocalFunction => {
            let returns = spec
                .callable
                .child_by_field_name("returns")
                .or_else(|| spec.callable.child_by_field_name("type"));
            returns
                .and_then(|returns| node_text(source, returns))
                .is_none_or(|returns| returns.trim() != "void")
        }
        ProcedureKind::Function
        | ProcedureKind::Lambda
        | ProcedureKind::Closure
        | ProcedureKind::Operator => true,
    }
}

impl<'tree, 'targets> LoweringContext<'tree, 'targets> {
    fn emit_procedure_inputs(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        callable: Node<'tree>,
        procedure_kind: ProcedureKind,
        properties: ProcedureProperties,
    ) -> Result<(), CSharpLoweringError> {
        if self.session.cancellation().is_cancelled() {
            return Err(CSharpLoweringError::Cancelled(Box::new(
                builder.prospective_work(),
            )));
        }
        let layout =
            formal_parameter_slots_for_owner(Language::CSharp, callable, self.prepared.source())
                .unwrap_or_default();
        if self.session.cancellation().is_cancelled() {
            return Err(CSharpLoweringError::Cancelled(Box::new(
                builder.prospective_work(),
            )));
        }
        let mut ordinal = 0_u32;
        for slot in layout.slots {
            if self.session.cancellation().is_cancelled() {
                return Err(CSharpLoweringError::Cancelled(Box::new(
                    builder.prospective_work(),
                )));
            }
            let node = callable
                .named_descendant_for_byte_range(
                    slot.declaration_range.start_byte,
                    slot.declaration_range.end_byte,
                )
                .unwrap_or(callable);
            let metadata = self.value_mapping(builder, node)?;
            let parameter_name = slot.unique_name().map(Box::<str>::from);
            let passing_mode = slot.passing_mode;
            let value = if slot.receiver {
                let value = self.session.add_value_with_metadata(
                    builder,
                    metadata,
                    SemanticValueKind::Receiver { dispatch: true },
                )?;
                self.receiver = Some(value);
                value
            } else {
                let value = self.session.add_value_with_metadata(
                    builder,
                    metadata,
                    SemanticValueKind::Parameter {
                        ordinal,
                        multiplicity: formal_multiplicity(slot.variadic),
                        name: parameter_name,
                        passing_mode,
                    },
                )?;
                ordinal = ordinal.checked_add(1).ok_or_else(|| {
                    CSharpLoweringError::Invalid("too many formal parameters".into())
                })?;
                value
            };
            let type_identity = (!slot.receiver)
                .then(|| node.child_by_field_name("type"))
                .flatten()
                .and_then(|type_node| declared_type_spelling(type_node, self.prepared.source()));
            for name in slot.names {
                if let Some(type_identity) = &type_identity {
                    self.parameter_types
                        .insert(name.clone().into_boxed_str(), type_identity.clone());
                }
                self.parameters.insert(name.into_boxed_str(), value);
            }
        }

        if self.receiver.is_none()
            && !properties.is_static
            && matches!(
                procedure_kind,
                ProcedureKind::Method
                    | ProcedureKind::Constructor
                    | ProcedureKind::Initializer
                    | ProcedureKind::Accessor
            )
        {
            let metadata = self.value_mapping(builder, callable)?;
            self.receiver = Some(self.session.add_value_with_metadata(
                builder,
                metadata,
                SemanticValueKind::Receiver { dispatch: true },
            )?);
        }
        if let Some(receiver) = self.receiver {
            self.parameters.insert("this".into(), receiver);
            self.parameters.insert("base".into(), receiver);
        }
        Ok(())
    }

    fn emit_local_bindings(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        body: Node<'tree>,
    ) -> Result<(), CSharpLoweringError> {
        try_walk_named_tree_preorder(body, true, |node| {
            if self.session.cancellation().is_cancelled() {
                return Err(CSharpLoweringError::Cancelled(Box::new(
                    builder.prospective_work(),
                )));
            }
            if is_csharp_nested_execution_boundary(node) {
                return Ok(WalkControl::SkipChildren);
            }
            if node.kind() == "variable_declarator"
                && is_local_variable_declarator(node)
                && let Some(name) = node.child_by_field_name("name")
                && name.kind() == "identifier"
                && let Some(text) = node_text(self.prepared.source(), name)
                && let Some((scope_start, scope_end)) = csharp_local_scope(node)
            {
                let metadata = self.value_mapping(builder, name)?;
                let value = self.session.add_value_with_metadata(
                    builder,
                    metadata,
                    SemanticValueKind::Local,
                )?;
                let type_identity = node
                    .parent()
                    .and_then(|declaration| declaration.child_by_field_name("type"))
                    .and_then(|type_node| {
                        declared_type_spelling(type_node, self.prepared.source())
                    });
                self.locals
                    .entry(text.into())
                    .or_default()
                    .push(LocalBinding {
                        declaration_start: name.start_byte(),
                        visible_from: node.end_byte(),
                        scope_start,
                        scope_end,
                        value,
                        type_identity,
                    });
            }
            Ok(WalkControl::Continue)
        })
    }

    fn local_at(&self, name: &str, byte: usize) -> Option<ValueId> {
        self.local_binding_at(name, byte)
            .map(|binding| binding.value)
    }

    fn binding_type_at(&self, name: &str, byte: usize) -> Option<&str> {
        self.local_binding_at(name, byte)
            .and_then(|binding| binding.type_identity.as_deref())
            .or_else(|| self.parameter_types.get(name).map(Box::as_ref))
    }

    fn local_binding_at(&self, name: &str, byte: usize) -> Option<&LocalBinding> {
        self.locals
            .get(name)?
            .iter()
            .filter(|binding| {
                binding.visible_from <= byte
                    && binding.scope_start <= byte
                    && byte < binding.scope_end
            })
            .min_by_key(|binding| binding.scope_end - binding.scope_start)
    }

    fn local_declaration_value(&self, name: &str, declaration_start: usize) -> Option<ValueId> {
        self.locals
            .get(name)?
            .iter()
            .find(|binding| binding.declaration_start == declaration_start)
            .map(|binding| binding.value)
    }

    fn expression_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        kind: SemanticValueKind,
    ) -> Result<ValueId, CSharpLoweringError> {
        if let Some(value) = self.expression_values.get(&node.id()) {
            return Ok(*value);
        }
        let metadata = self.value_mapping(builder, node)?;
        let value = self.session.insert_cached_value_with_metadata(
            builder,
            &mut self.expression_values,
            node.id(),
            metadata,
            kind,
        )?;
        Ok(value)
    }

    fn source_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        kind: SemanticValueKind,
    ) -> Result<ValueId, CSharpLoweringError> {
        let metadata = self.value_mapping(builder, node)?;
        self.session
            .add_value_with_metadata(builder, metadata, kind)
    }

    fn emit_lexical_input_flow(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        point: ProgramPointId,
        target: ValueId,
    ) -> Result<(), CSharpLoweringError> {
        let Some(name) = node_text(self.prepared.source(), node) else {
            return Ok(());
        };
        let (source, kind) = if matches!(node.kind(), "this" | "base") {
            (self.receiver, ValueFlowKind::Receiver)
        } else if node.kind() == "identifier" {
            if let Some(local) = self.local_at(name, node.start_byte()) {
                (Some(local), ValueFlowKind::Local)
            } else {
                (self.parameters.get(name).copied(), ValueFlowKind::Parameter)
            }
        } else {
            (None, ValueFlowKind::Local)
        };
        if let Some(source) = source
            && source != target
        {
            self.append_effect(
                builder,
                point,
                SemanticEffect::ValueFlow {
                    kind,
                    source,
                    target,
                },
            )?;
        }
        Ok(())
    }

    fn step(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        work: Work<'tree>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        if self.session.cancellation().is_cancelled() {
            return Err(CSharpLoweringError::Cancelled(Box::default()));
        }
        match work {
            Work::Statement {
                node,
                entry,
                next,
                scope,
            } => self.statement(builder, node, entry, next, scope, None, stack),
            Work::Expression {
                node,
                entry,
                next,
                scope,
            } => self.expression(builder, node, entry, next, scope, stack),
            Work::Condition {
                node,
                entry,
                when_true,
                when_false,
                scope,
            } => self.condition(builder, node, entry, when_true, when_false, scope, stack),
        }
    }

    fn local_declaration(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        declaration: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        let declared_type = declaration.child_by_field_name("type");
        let initializers = named_children(declaration)
            .into_iter()
            .filter(|child| child.kind() == "variable_declarator")
            .filter_map(|declarator| {
                let name = declarator.child_by_field_name("name")?;
                let initializer = variable_declarator_initializer(declarator)?;
                (name.kind() == "identifier").then_some((declarator, name, initializer))
            })
            .collect::<Vec<_>>();
        if initializers.is_empty() {
            return self.edge(builder, entry, next);
        }

        let expression_entries = initializers
            .iter()
            .map(|(_, _, initializer)| self.point(builder, *initializer, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        let terminals = initializers
            .iter()
            .map(|(declarator, _, _)| self.point(builder, *declarator, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        self.edge(builder, entry, EdgeTarget::normal(expression_entries[0]))?;
        for (index, (_, name, initializer)) in initializers.iter().enumerate().rev() {
            let target_name = node_text(self.prepared.source(), *name).ok_or_else(|| {
                CSharpLoweringError::Invalid("local declaration has invalid name range".into())
            })?;
            let target = self
                .local_declaration_value(target_name, name.start_byte())
                .ok_or_else(|| {
                    CSharpLoweringError::Invalid("local declaration was not preindexed".into())
                })?;
            let value =
                self.expression_value(builder, *initializer, expression_value_kind(*initializer))?;
            let identity_conversion = declared_type.is_some_and(|declared_type| {
                declared_type.kind() == "implicit_type"
                    || self.identity_is_preserved(
                        declared_type_spelling(declared_type, self.prepared.source()).as_deref(),
                        *initializer,
                    )
            });
            if identity_conversion {
                self.append_effect(
                    builder,
                    terminals[index],
                    SemanticEffect::Assignment { target, value },
                )?;
                self.append_effect(
                    builder,
                    terminals[index],
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Local,
                        source: value,
                        target,
                    },
                )?;
            } else {
                self.add_gap(
                    builder,
                    terminals[index],
                    SemanticGapSubject::Value(target),
                    SemanticCapability::Values,
                    SemanticGapKind::Unknown,
                    "explicitly typed C# local initialization may invoke a user-defined conversion",
                )?;
            }
            let following = expression_entries
                .get(index + 1)
                .copied()
                .map(EdgeTarget::normal)
                .unwrap_or(next);
            self.edge(builder, terminals[index], following)?;
            stack.push(Work::Expression {
                node: *initializer,
                entry: expression_entries[index],
                next: EdgeTarget::normal(terminals[index]),
                scope,
            });
        }
        Ok(())
    }

    /// Whether carrying `value` into a target declared as `declared` keeps the
    /// value's own identity, instead of possibly running a user-defined
    /// implicit conversion first (#2661).
    ///
    /// C# lets any type declare `implicit operator T(S)`, and such an operator
    /// is ordinary user code that returns whatever it likes -- `Service s =
    /// source;` can bind `s` to an object that the initializer never named.
    /// Connecting the two unconditionally would relabel the pre-conversion
    /// allocation as the declared type, so the connection is made only when
    /// this file proves that no conversion can intervene.
    ///
    /// `declared` is the target's declared type spelling, or `None` when this
    /// file does not know it. `None` proves nothing on its own; an expression
    /// that constructs its own value still needs no proof, because there is no
    /// prior identity for a conversion to replace.
    fn identity_is_preserved(&self, declared: Option<&str>, value: Node<'tree>) -> bool {
        if expression_constructs_its_value(value.kind()) {
            return true;
        }
        // `new()` is target-typed: it constructs the declared type itself.
        if value.kind() == "implicit_object_creation_expression" {
            return true;
        }
        // A built-in operation computes a fresh value of a predefined type.
        // There is no prior object identity for a conversion to replace, and
        // no user-defined conversion can target a predefined type, so
        // `int computed = (value * 3) + 7;` needs no further proof (#2661).
        if self.operation_is_builtin(value) {
            return true;
        }
        let source = self.prepared.source();
        let Some(declared) = declared else {
            return false;
        };
        match value.kind() {
            "object_creation_expression" | "array_creation_expression" => value
                .child_by_field_name("type")
                .and_then(|created| declared_type_spelling(created, source))
                .is_some_and(|created| created.as_ref() == declared),
            "identifier" => node_text(source, value)
                .and_then(|name| self.binding_type_at(name, value.start_byte()))
                .is_some_and(|bound| bound == declared),
            "invocation_expression" => self
                .static_invocation_return_type(value)
                .is_some_and(|returned| returned == declared),
            _ => false,
        }
    }

    fn static_invocation_return_type(&self, invocation: Node<'tree>) -> Option<&str> {
        let key = static_invocation_key(invocation, self.prepared.source())?;
        // An unqualified callee is shadowed by a same-named local, parameter,
        // or local function holding a delegate, exactly as a receiver name is
        // shadowed by a same-named value.
        for name in [&key.owner, &key.name] {
            if self.local_at(name, invocation.start_byte()).is_some()
                || self.parameters.contains_key(name.as_ref())
                || self.callable_type_parameters.contains(name.as_ref())
            {
                return None;
            }
        }
        if receiver_name_is_lexically_shadowed(invocation, &key.owner, self.type_receiver_shadows) {
            return None;
        }
        self.static_callable_returns.get(&key)?.as_deref()
    }

    /// Whether an expression provably denotes a value of a predefined type.
    ///
    /// This is a proof, not a guess: every branch either reads a declared type
    /// spelling this file recorded, or is a literal whose type the grammar
    /// fixes. An expression this cannot account for answers `false`, so an
    /// unknown type is never mistaken for a predefined one.
    fn expression_is_predefined(&self, node: Node<'tree>) -> bool {
        match node.kind() {
            kind if literal_is_predefined(kind) => true,
            "parenthesized_expression" | "checked_expression" => {
                first_runtime_named_child(node).is_some_and(|inner| {
                    // A parenthesized group denotes exactly its inner value.
                    self.expression_is_predefined(inner)
                })
            }
            "identifier" => node_text(self.prepared.source(), node)
                .and_then(|name| self.binding_type_at(name, node.start_byte()))
                .is_some_and(csharp_predefined_type),
            "invocation_expression" => self
                .static_invocation_return_type(node)
                .is_some_and(csharp_predefined_type),
            "cast_expression" => node
                .child_by_field_name("type")
                .and_then(|target| declared_type_spelling(target, self.prepared.source()))
                .is_some_and(|target| csharp_predefined_type(&target)),
            // A built-in operation over predefined operands is itself
            // predefined, which is what lets `(value * 3) + 7` compose.
            "binary_expression" | "prefix_unary_expression" | "postfix_unary_expression" => {
                self.operation_is_builtin(node)
            }
            _ => false,
        }
    }

    /// Whether an operator expression provably runs the language's own
    /// operator rather than a user-defined `operator` declaration (#2661).
    ///
    /// C# lets a type declare `public static T operator +(T, T)`, which is
    /// ordinary user code returning whatever it likes. Connecting an operand
    /// to such a result would republish the operand's object as the result --
    /// the same unsoundness a user-defined implicit conversion causes for a
    /// local initializer, and the points-to trace follows `ValueFlow` edges
    /// regardless of their kind. Operator overloading is impossible when every
    /// operand is of a predefined type, so that is the proof required here.
    ///
    /// An increment or decrement is excluded: it also writes its operand, and
    /// that write is not represented yet.
    fn operation_is_builtin(&self, node: Node<'tree>) -> bool {
        // Only an operator expression asks this question. Without the kind
        // check every node with predefined-typed children answered "built-in",
        // and `slot = ref other` fabricated value flow into an alias rebind.
        if !matches!(
            node.kind(),
            "binary_expression" | "prefix_unary_expression" | "postfix_unary_expression"
        ) {
            return false;
        }
        if is_update_expression(node) {
            return false;
        }
        let operands = runtime_expression_children(node);
        !operands.is_empty()
            && operands
                .iter()
                .all(|operand| self.expression_is_predefined(*operand))
    }

    /// The abstract location an access expression names, when this file can
    /// structure it (#2661).
    ///
    /// A member or element target is a write to a *location*, not to a value,
    /// so it publishes a `MemoryStore` and deliberately carries no
    /// `Assignment` or `ValueFlow` edge. That separation is what keeps the
    /// user-defined-conversion problem out of the heap stratum: the backward
    /// points-to trace in `workspace_oracle/heap.rs` follows only value edges,
    /// so a store cannot republish a pre-conversion allocation as the member's
    /// content the way an unguarded local assignment would. The identity
    /// question `identity_is_preserved` answers for a local therefore does not
    /// need re-asking here -- it is answered by construction.
    fn memory_access_target(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        access: Node<'tree>,
    ) -> Result<Option<MemoryTarget>, CSharpLoweringError> {
        match access.kind() {
            "member_access_expression" => self.member_location(builder, point, access),
            "element_access_expression" => self.element_location(builder, point, access),
            _ => Ok(None),
        }
    }

    fn member_location(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        access: Node<'tree>,
    ) -> Result<Option<MemoryTarget>, CSharpLoweringError> {
        let (Some(base), Some(name_node)) = (
            access.child_by_field_name("expression"),
            access.child_by_field_name("name"),
        ) else {
            return Ok(None);
        };
        let Some(name) =
            nonempty_node_text(self.prepared.source(), name_node).map(Box::<str>::from)
        else {
            return Ok(None);
        };
        let declaration = self
            .access_owner_type(base)
            .and_then(|owner| self.member_declaration_for(&owner, &name, access));
        let member = self.member_locator(name_node, declaration.as_ref())?;
        // A `static` or `const` member is one class-wide slot, addressed by
        // nothing: it has no base object for a `Field` location to name.
        if declaration
            .as_ref()
            .is_some_and(|declaration| declaration.is_static)
        {
            let location = self.session.add_memory_location(
                builder,
                point,
                MemoryLocationKind::Static { member },
            )?;
            return Ok(Some(MemoryTarget {
                location,
                kind: MemoryAccessKind::Static,
                resolved: true,
            }));
        }
        // Without a base value this is not an instance access at all -- it is
        // a member of a type this file could not resolve. Inventing a base
        // object would invent an aliasing fact, so decline.
        let Some(base_value) = self.access_base_value(builder, base)? else {
            return Ok(None);
        };
        let location = self.session.add_memory_location(
            builder,
            point,
            MemoryLocationKind::Field {
                base: base_value,
                member,
            },
        )?;
        Ok(Some(MemoryTarget {
            location,
            kind: MemoryAccessKind::Field,
            resolved: declaration.is_some(),
        }))
    }

    fn element_location(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        access: Node<'tree>,
    ) -> Result<Option<MemoryTarget>, CSharpLoweringError> {
        let Some(base) = access.child_by_field_name("expression") else {
            return Ok(None);
        };
        let Some(base_value) = self.access_base_value(builder, base)? else {
            return Ok(None);
        };
        // One subscript is the element's own index. A multi-dimensional or
        // named subscript names no single index expression, so the location
        // stays index-less rather than adopting the first argument as if it
        // were the whole address.
        let subscripts = access
            .child_by_field_name("subscript")
            .map(named_children)
            .unwrap_or_default();
        let subscript = match subscripts.as_slice() {
            [only] => call_argument_value(*only),
            _ => None,
        };
        let index = match subscript {
            Some(value) => Some(self.subscript_value(builder, value)?),
            None => None,
        };
        let location = self.session.add_memory_location(
            builder,
            point,
            MemoryLocationKind::Index {
                base: base_value,
                index,
                constant_index: None,
                identity: crate::analyzer::semantic::IndexedLocationIdentity::Element,
            },
        )?;
        Ok(Some(MemoryTarget {
            location,
            kind: MemoryAccessKind::Index,
            // An array element access runs no user code: C# arrays have no
            // user-declarable indexer, so a provably-array base addresses the
            // element directly. Any other base may resolve to a user-defined
            // `this[...]` accessor pair, and nothing here proves which one
            // runs.
            //
            // The index must also be a constant. A location is identified by
            // its index *value*, and only a constant subscript is
            // canonicalized to one value across occurrences -- so claiming
            // resolution for `values[i]` would let a store and a load address
            // two different elements while publishing no decline, and the
            // solver would read that disconnection as a proven absence rather
            // than as missing information. A confident wrong answer is worse
            // than an honest partial.
            resolved: self.base_is_array(base)
                && subscript.is_some_and(|subscript| {
                    matches!(
                        expression_value_kind(subscript),
                        SemanticValueKind::Constant
                    )
                }),
        }))
    }

    /// The value a subscript denotes, canonicalized when it is a constant so
    /// that every occurrence of `values[0]` names one element location.
    fn subscript_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<ValueId, CSharpLoweringError> {
        let kind = expression_value_kind(node);
        if kind != SemanticValueKind::Constant {
            return self.expression_value(builder, node, kind);
        }
        let Some(text) = node_text(self.prepared.source(), node) else {
            return self.expression_value(builder, node, kind);
        };
        if let Some(value) = self.constant_index_values.get(text).copied() {
            self.expression_values.insert(node.id(), value);
            return Ok(value);
        }
        let value = self.expression_value(builder, node, kind)?;
        self.constant_index_values.insert(text.into(), value);
        Ok(value)
    }

    /// Whether an access base provably denotes an array.
    ///
    /// [`declared_type_spelling`] keeps array ranks precisely so this question
    /// can be answered from a declared type: `int[]` and `int` are distinct
    /// spellings there, though `csharp_type_node_identity` collapses them.
    fn base_is_array(&self, base: Node<'tree>) -> bool {
        match base.kind() {
            "identifier" => node_text(self.prepared.source(), base)
                .and_then(|name| self.binding_type_at(name, base.start_byte()))
                .is_some_and(|declared| declared.ends_with("[]")),
            "array_creation_expression" | "implicit_array_creation_expression" => true,
            _ => false,
        }
    }

    /// The value an access is addressed through, or `None` when the base names
    /// a type rather than an object.
    fn access_base_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        base: Node<'tree>,
    ) -> Result<Option<ValueId>, CSharpLoweringError> {
        if matches!(base.kind(), "this" | "base") {
            return Ok(self.receiver);
        }
        if base.kind() == "identifier"
            && let Some(name) = node_text(self.prepared.source(), base)
            && self.local_at(name, base.start_byte()).is_none()
            && !self.parameters.contains_key(name)
        {
            return Ok(None);
        }
        self.expression_value(builder, base, expression_value_kind(base))
            .map(Some)
    }

    /// The type that declares the member an access names, when this file knows
    /// it: the enclosing type for `this`, a value's declared type spelling for
    /// an instance access, or the identifier itself for a static one.
    fn access_owner_type(&self, base: Node<'tree>) -> Option<Box<str>> {
        if matches!(base.kind(), "this" | "base") {
            return enclosing_type_node(base)
                .and_then(|owner| declaration_container_name(self.prepared.source(), owner));
        }
        if base.kind() != "identifier" {
            return None;
        }
        let name = node_text(self.prepared.source(), base)?;
        if let Some(declared) = self.binding_type_at(name, base.start_byte()) {
            return Some(Box::from(declared));
        }
        if self.local_at(name, base.start_byte()).is_some() || self.parameters.contains_key(name) {
            // A value in scope whose declared type this file does not know.
            // Its members belong to some type, but not to a named one.
            return None;
        }
        Some(Box::from(name))
    }

    fn member_declaration_for(
        &self,
        owner: &str,
        name: &str,
        access: Node<'tree>,
    ) -> Option<MemberDeclaration> {
        let key = TypeMemberKey {
            namespace: enclosing_namespace_path(self.prepared.source(), access),
            owner: Box::from(owner),
            name: Box::from(name),
        };
        self.member_declarations.get(&key)?.clone()
    }

    /// The declared type an assignment target holds, when this file knows it.
    ///
    /// A member target reads its own declaration's type; an element target
    /// reads the array's element type, which is the base spelling with one
    /// rank removed. This is what lets a write through a location ask the same
    /// identity-preservation question a local declaration asks, rather than
    /// declining every such assignment's result on principle (#2661).
    fn assignment_target_type(&self, target: Node<'tree>) -> Option<Box<str>> {
        match target.kind() {
            "member_access_expression" => {
                let base = target.child_by_field_name("expression")?;
                let name = nonempty_node_text(
                    self.prepared.source(),
                    target.child_by_field_name("name")?,
                )?;
                let owner = self.access_owner_type(base)?;
                self.member_declaration_for(&owner, name, target)?
                    .type_spelling
            }
            "element_access_expression" => {
                let base = target.child_by_field_name("expression")?;
                let declared = match base.kind() {
                    "identifier" => {
                        let name = node_text(self.prepared.source(), base)?;
                        self.binding_type_at(name, base.start_byte())?
                    }
                    _ => return None,
                };
                declared.strip_suffix("[]").map(Box::<str>::from)
            }
            _ => None,
        }
    }

    /// Anchor a member location to its *declaration* when one is known, so two
    /// occurrences of the same member agree on one identity, and to the
    /// occurrence otherwise.
    fn member_locator(
        &self,
        occurrence: Node<'tree>,
        declaration: Option<&MemberDeclaration>,
    ) -> Result<SemanticLocator, CSharpLoweringError> {
        let anchor = match declaration {
            Some(declaration) => declaration.anchor,
            None => source_anchor(occurrence, 0).map_err(CSharpLoweringError::Invalid)?,
        };
        let procedure = self.session.locator();
        Ok(SemanticLocator::new(
            procedure.mount(),
            procedure.path().clone(),
            procedure.language(),
            procedure.declaration().clone(),
            SemanticRole::MemoryLocation,
            anchor,
        ))
    }

    /// Publish a read of a member or an element as a `MemoryLoad` into the
    /// access's own value, when the location can be structured.
    ///
    /// The load is the read-side symmetry of [`Self::emit_memory_store`]: a
    /// member's identity is a location, not a value, so a read of one is a
    /// load from that location rather than a value edge from a binding.
    fn emit_memory_load(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        access: Node<'tree>,
    ) -> Result<(), CSharpLoweringError> {
        let Some(load) = self.memory_access_target(builder, point, access)? else {
            return Ok(());
        };
        let result = self.expression_value(builder, access, expression_value_kind(access))?;
        self.append_effect(
            builder,
            point,
            SemanticEffect::MemoryLoad {
                kind: load.kind,
                location: load.location,
                result,
            },
        )?;
        self.add_memory_identity_gap(builder, point, load)
    }

    fn emit_memory_store(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        store: MemoryTarget,
        value: ValueId,
    ) -> Result<(), CSharpLoweringError> {
        self.append_effect(
            builder,
            point,
            SemanticEffect::MemoryStore {
                kind: store.kind,
                location: store.location,
                value,
            },
        )?;
        self.add_memory_identity_gap(builder, point, store)
    }

    /// Publish the location's own identity gap when the occurrence was
    /// structured but its declaration was not resolved.
    ///
    /// The subject is the location, not the point: a
    /// [`SemanticGapSubject::MemoryLocation`] carries `MEMORY` impact and
    /// leaves the value stratum alone, which is the whole reason the heap
    /// stratum is separate from it.
    fn add_memory_identity_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        store: MemoryTarget,
    ) -> Result<(), CSharpLoweringError> {
        if store.resolved {
            return Ok(());
        }
        let (capability, detail) = match store.kind {
            MemoryAccessKind::Index => (
                SemanticCapability::IndexMemory,
                "indexed access is structured, but the indexer and element identity are not resolved",
            ),
            MemoryAccessKind::Static => (
                SemanticCapability::StaticMemory,
                "static member access is structured, but its declaration identity is not resolved",
            ),
            _ => (
                SemanticCapability::FieldMemory,
                "field or property access is structured, but its declaration identity is not resolved",
            ),
        };
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::MemoryLocation(store.location),
            capability,
            SemanticGapKind::Unknown,
            detail,
        )
    }

    fn assignment_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        let left = required_field(node, "left")?;
        let right = required_field(node, "right")?;
        let terminal = self.point(builder, node, Vec::new())?;
        let value = self.expression_value(builder, right, expression_value_kind(right))?;
        let result = self.expression_value(builder, node, expression_value_kind(node))?;

        let evaluations = if left.kind() == "identifier" {
            let name = node_text(self.prepared.source(), left).ok_or_else(|| {
                CSharpLoweringError::Invalid("assignment has invalid target range".into())
            })?;
            let local = self.local_at(name, left.start_byte());
            let target = local.or_else(|| self.parameters.get(name).copied());
            // The declared type of the assignment target decides whether a
            // user-defined implicit conversion can intervene, the same
            // question a declaration with an initializer asks (#2661).
            let preserved =
                self.identity_is_preserved(self.binding_type_at(name, left.start_byte()), right);
            if let Some(target) = target {
                if preserved {
                    let kind = if local.is_some() {
                        ValueFlowKind::Local
                    } else {
                        ValueFlowKind::Parameter
                    };
                    self.append_effect(
                        builder,
                        terminal,
                        SemanticEffect::Assignment { target, value },
                    )?;
                    self.append_effect(
                        builder,
                        terminal,
                        SemanticEffect::ValueFlow {
                            kind,
                            source: value,
                            target,
                        },
                    )?;
                } else {
                    self.add_gap(
                        builder,
                        terminal,
                        SemanticGapSubject::Value(target),
                        SemanticCapability::Values,
                        SemanticGapKind::Unknown,
                        "C# assignment target identity is unavailable until implicit conversion resolution is available",
                    )?;
                }
            }
            // The value of an assignment expression is the value that was
            // assigned, once no conversion can have replaced it.
            if preserved {
                self.append_effect(
                    builder,
                    terminal,
                    SemanticEffect::Assignment {
                        target: result,
                        value,
                    },
                )?;
            } else {
                self.add_gap(
                    builder,
                    terminal,
                    SemanticGapSubject::Value(result),
                    SemanticCapability::Values,
                    SemanticGapKind::Unknown,
                    "C# assignment result identity is unavailable until implicit conversion resolution is available",
                )?;
            }
            vec![right]
        } else {
            // The value of an assignment expression is the value assigned,
            // and a write through a location asks the same conversion
            // question a local declaration asks -- against the *member's*
            // declared type (#2661). Declining it unconditionally published a
            // `Values`/`Unknown` gap on a result that a statement-level write
            // never even reads, and that gap alone opened the whole
            // procedure's value-flow snapshot, so no heap fact downstream of
            // it could be proven complete.
            if self.identity_is_preserved(self.assignment_target_type(left).as_deref(), right) {
                self.append_effect(
                    builder,
                    terminal,
                    SemanticEffect::Assignment {
                        target: result,
                        value,
                    },
                )?;
            } else {
                self.add_gap(
                    builder,
                    terminal,
                    SemanticGapSubject::Value(result),
                    SemanticCapability::Values,
                    SemanticGapKind::Unknown,
                    "C# assignment result identity is unavailable until implicit conversion resolution is available",
                )?;
            }
            // A member or element target writes a location, so it becomes a
            // `MemoryStore` against a structured location (#2661). Whatever
            // this cannot structure -- a tuple, a deconstruction, a `ref`
            // target -- keeps the blanket decline it always had.
            if let Some(store) = self.memory_access_target(builder, terminal, left)? {
                self.emit_memory_store(builder, terminal, store, value)?;
            } else {
                self.add_gap(
                    builder,
                    terminal,
                    SemanticGapSubject::Point,
                    SemanticCapability::Assignments,
                    SemanticGapKind::Unsupported,
                    "tuple, deconstruction, and ref assignment targets are not yet lowered into memory flow",
                )?;
            }
            self.add_gap(
                builder,
                terminal,
                SemanticGapSubject::Point,
                SemanticCapability::Calls,
                SemanticGapKind::Unknown,
                "assignment target accessors and overloaded assignment conversions require type refinement",
            )?;
            self.implicit_exception_gap(builder, terminal, node)?;
            runtime_expression_children(node)
        };
        self.edge(builder, terminal, next)?;
        self.schedule_expressions(
            builder,
            entry,
            &evaluations,
            EdgeTarget::normal(terminal),
            scope,
            stack,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn transparent_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        value: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        let terminal = self.point(builder, node, Vec::new())?;
        let source = self.expression_value(builder, value, expression_value_kind(value))?;
        let target = self.expression_value(builder, node, expression_value_kind(node))?;
        self.append_effect(
            builder,
            terminal,
            SemanticEffect::Assignment {
                target,
                value: source,
            },
        )?;
        self.edge(builder, terminal, next)?;
        stack.push(Work::Expression {
            node: value,
            entry,
            next: EdgeTarget::normal(terminal),
            scope,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn conversion_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        value: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        let terminal = self.point(builder, node, Vec::new())?;
        let target = self.expression_value(builder, node, expression_value_kind(node))?;
        self.add_gap(
            builder,
            terminal,
            SemanticGapSubject::Value(target),
            SemanticCapability::Values,
            SemanticGapKind::Unknown,
            "C# cast/as identity is provisional until conversion resolution is available",
        )?;
        if node.kind() == "cast_expression" {
            self.implicit_exception_gap(builder, terminal, node)?;
        }
        self.edge(builder, terminal, next)?;
        stack.push(Work::Expression {
            node: value,
            entry,
            next: EdgeTarget::normal(terminal),
            scope,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn condition(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        when_true: EdgeTarget,
        when_false: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        if let Some(value) = csharp_folded_boolean_constant(self.prepared.source(), node) {
            let taken = if value { when_true } else { when_false };
            self.edge(builder, entry, taken)?;
            return self.record_guard(
                builder,
                entry,
                GuardPredicate::ConstantBoolean { value },
                None,
                value.then_some(when_true),
                (!value).then_some(when_false),
            );
        }
        match (node.kind(), binary_operator(node)) {
            ("binary_expression", Some("&&")) => {
                let left = required_field(node, "left")?;
                let right = required_field(node, "right")?;
                let right_entry = self.point(builder, right, Vec::new())?;
                schedule_short_circuit_condition(
                    stack,
                    ShortCircuitKind::And,
                    (left, entry),
                    (right, right_entry),
                    when_true,
                    when_false,
                    scope,
                    Work::condition,
                );
                Ok(())
            }
            ("binary_expression", Some("||")) => {
                let left = required_field(node, "left")?;
                let right = required_field(node, "right")?;
                let right_entry = self.point(builder, right, Vec::new())?;
                schedule_short_circuit_condition(
                    stack,
                    ShortCircuitKind::Or,
                    (left, entry),
                    (right, right_entry),
                    when_true,
                    when_false,
                    scope,
                    Work::condition,
                );
                Ok(())
            }
            ("binary_expression", Some("??")) => {
                let left = required_field(node, "left")?;
                let right = required_field(node, "right")?;
                let right_entry = self.point(builder, right, Vec::new())?;
                let left_result = self.point(builder, left, Vec::new())?;
                self.edge(builder, left_result, when_true)?;
                self.edge(builder, left_result, when_false)?;
                stack.push(Work::Condition {
                    node: right,
                    entry: right_entry,
                    when_true,
                    when_false,
                    scope,
                });
                let null_test = self.point(builder, left, Vec::new())?;
                self.edge(
                    builder,
                    null_test,
                    EdgeTarget {
                        point: left_result,
                        kind: ControlEdgeKind::ConditionalTrue,
                    },
                )?;
                self.edge(
                    builder,
                    null_test,
                    EdgeTarget {
                        point: right_entry,
                        kind: ControlEdgeKind::ConditionalFalse,
                    },
                )?;
                stack.push(Work::Expression {
                    node: left,
                    entry,
                    next: EdgeTarget::normal(null_test),
                    scope,
                });
                Ok(())
            }
            ("conditional_expression", _) => {
                let condition = required_field(node, "condition")?;
                let consequence = required_field(node, "consequence")?;
                let alternative = required_field(node, "alternative")?;
                let consequence_entry = self.point(builder, consequence, Vec::new())?;
                let alternative_entry = self.point(builder, alternative, Vec::new())?;
                schedule_conditional_choice(
                    stack,
                    (condition, entry),
                    (consequence, consequence_entry),
                    (alternative, alternative_entry),
                    when_true,
                    when_false,
                    scope,
                    Work::condition,
                );
                Ok(())
            }
            ("parenthesized_expression", _) => {
                let value = first_named_child(node).ok_or_else(|| missing_field(node, "value"))?;
                stack.push(Work::Condition {
                    node: value,
                    entry,
                    when_true,
                    when_false,
                    scope,
                });
                Ok(())
            }
            _ => {
                let decision = self.point(builder, node, Vec::new())?;
                self.edge(builder, decision, when_true)?;
                self.edge(builder, decision, when_false)?;
                let subject = self.expression_value(builder, node, expression_value_kind(node))?;
                self.record_guard(
                    builder,
                    decision,
                    GuardPredicate::Opaque {
                        digest: GuardConditionDigest::from_syntax_kind(node.kind()),
                    },
                    Some(subject),
                    Some(when_true),
                    Some(when_false),
                )?;
                stack.push(Work::Expression {
                    node,
                    entry,
                    next: EdgeTarget::normal(decision),
                    scope,
                });
                Ok(())
            }
        }
    }

    /// Publish one guard fact for a decision this lowerer just made.
    ///
    /// Arms must already have been added as edges; the IR validator enforces
    /// that. Conditions this adapter cannot normalize remain opaque.
    #[allow(clippy::too_many_arguments)]
    fn record_guard(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        predicate: GuardPredicate,
        subject: Option<ValueId>,
        when_true: Option<EdgeTarget>,
        when_false: Option<EdgeTarget>,
    ) -> Result<(), CSharpLoweringError> {
        let arm = |target: Option<EdgeTarget>| {
            target.map(|target| GuardArm {
                target_point: target.point,
                kind: target.kind,
            })
        };
        self.session.add_guard_fact(
            builder,
            point,
            predicate,
            subject,
            arm(when_true),
            arm(when_false),
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        _attached_label: Option<&'tree str>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        match node.kind() {
            "block" | "compilation_unit" => {
                let children = named_children(node)
                    .into_iter()
                    .filter(|child| is_statement_kind(child.kind()))
                    .collect::<Vec<_>>();
                self.schedule_statements(builder, entry, &children, next, scope, stack)
            }
            "expression_statement" => {
                if let Some(expression) = first_named_child(node) {
                    stack.push(Work::Expression {
                        node: expression,
                        entry,
                        next,
                        scope,
                    });
                    Ok(())
                } else {
                    self.edge(builder, entry, next)
                }
            }
            "return_statement" => {
                let terminal = if let Some(value_node) = first_named_child(node) {
                    let point = self.point(builder, node, Vec::new())?;
                    let source =
                        self.expression_value(builder, value_node, expression_value_kind(value_node))?;
                    let value = self.value(builder, point, SemanticValueKind::Return)?;
                    self.append_effect(
                        builder,
                        point,
                        SemanticEffect::ValueFlow {
                            kind: ValueFlowKind::Return,
                            source,
                            target: value,
                        },
                    )?;
                    self.append_effect(
                        builder,
                        point,
                        SemanticEffect::ProcedureReturn { value: Some(value) },
                    )?;
                    stack.push(Work::Expression {
                        node: value_node,
                        entry,
                        next: EdgeTarget::normal(point),
                        scope,
                    });
                    point
                } else {
                    self.append_effect(
                        builder,
                        entry,
                        SemanticEffect::ProcedureReturn { value: None },
                    )?;
                    entry
                };
                self.abrupt(
                    builder,
                    terminal,
                    scope,
                    CompletionKind::Return,
                    None,
                    stack,
                )
            }
            "throw_statement" => {
                let value_node = first_named_child(node);
                let terminal = if value_node.is_some() {
                    self.point(builder, node, Vec::new())?
                } else {
                    entry
                };
                let value = value_node
                    .map(|_| self.value(builder, terminal, SemanticValueKind::Exception))
                    .transpose()?;
                self.append_effect(builder, terminal, SemanticEffect::Throw { value })?;
                if let Some(value_node) = value_node {
                    stack.push(Work::Expression {
                        node: value_node,
                        entry,
                        next: EdgeTarget::normal(terminal),
                        scope,
                    });
                }
                self.abrupt(builder, terminal, scope, CompletionKind::Throw, None, stack)
            }
            "yield_statement" => {
                let value_node = first_named_child(node);
                let terminal = if value_node.is_some() {
                    self.point(builder, node, Vec::new())?
                } else {
                    entry
                };
                self.add_gap(
                    builder,
                    terminal,
                    SemanticGapSubject::Point,
                    SemanticCapability::GeneratorSuspension,
                    SemanticGapKind::Unsupported,
                    "yield suspension and resumption are not lowered",
                )?;
                if let Some(value_node) = value_node {
                    stack.push(Work::Expression {
                        node: value_node,
                        entry,
                        next: EdgeTarget::normal(terminal),
                        scope,
                    });
                }
                Ok(())
            }
            "break_statement" | "continue_statement" => {
                let kind = if node.kind() == "break_statement" {
                    CompletionKind::Break
                } else {
                    CompletionKind::Continue
                };
                self.abrupt(builder, entry, scope, kind, None, stack)
            }
            "goto_statement" => self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::NonLocalControl,
                SemanticGapKind::Unsupported,
                "goto target resolution, including goto case/default, is not lowered",
            ),
            "labeled_statement" => {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::NonLocalControl,
                    SemanticGapKind::Unsupported,
                    "incoming goto edges to this label are not lowered",
                )?;
                let body = named_children(node)
                    .into_iter()
                    .find(|child| child.kind() != "identifier")
                    .ok_or_else(|| missing_field(node, "body"))?;
                stack.push(Work::Statement {
                    node: body,
                    entry,
                    next,
                    scope,
                });
                Ok(())
            }
            "if_statement" => {
                let condition = required_field(node, "condition")?;
                let consequence = required_field(node, "consequence")?;
                let alternative = node.child_by_field_name("alternative");
                let consequence_entry = self.point(builder, consequence, Vec::new())?;
                stack.push(Work::Statement {
                    node: consequence,
                    entry: consequence_entry,
                    next,
                    scope,
                });
                let false_target = if let Some(alternative) = alternative {
                    let alternative_entry = self.point(builder, alternative, Vec::new())?;
                    stack.push(Work::Statement {
                        node: alternative,
                        entry: alternative_entry,
                        next,
                        scope,
                    });
                    EdgeTarget {
                        point: alternative_entry,
                        kind: ControlEdgeKind::ConditionalFalse,
                    }
                } else {
                    EdgeTarget {
                        point: next.point,
                        kind: ControlEdgeKind::ConditionalFalse,
                    }
                };
                stack.push(Work::Condition {
                    node: condition,
                    entry,
                    when_true: EdgeTarget {
                        point: consequence_entry,
                        kind: ControlEdgeKind::ConditionalTrue,
                    },
                    when_false: false_target,
                    scope,
                });
                Ok(())
            }
            "while_statement" => {
                let condition = required_field(node, "condition")?;
                let body = required_field(node, "body")?;
                let condition_entry = self.point(builder, condition, Vec::new())?;
                let body_entry = self.point(builder, body, Vec::new())?;
                let loop_scope = builder.push_scope(
                    Some(scope),
                    ScopeBinding::Loop {
                        label: None,
                        break_target: next.point,
                        break_edge_kind: next.kind,
                        continue_target: condition_entry,
                        continue_edge_kind: ControlEdgeKind::LoopBack,
                    },
                );
                stack.push(Work::Statement {
                    node: body,
                    entry: body_entry,
                    next: EdgeTarget {
                        point: condition_entry,
                        kind: ControlEdgeKind::LoopBack,
                    },
                    scope: loop_scope,
                });
                stack.push(Work::Condition {
                    node: condition,
                    entry: condition_entry,
                    when_true: EdgeTarget {
                        point: body_entry,
                        kind: ControlEdgeKind::ConditionalTrue,
                    },
                    when_false: EdgeTarget {
                        point: next.point,
                        kind: ControlEdgeKind::ConditionalFalse,
                    },
                    scope: loop_scope,
                });
                self.edge(builder, entry, EdgeTarget::normal(condition_entry))
            }
            "do_statement" => {
                let body = required_field(node, "body")?;
                let condition = required_field(node, "condition")?;
                let condition_entry = self.point(builder, condition, Vec::new())?;
                let loop_scope = builder.push_scope(
                    Some(scope),
                    ScopeBinding::Loop {
                        label: None,
                        break_target: next.point,
                        break_edge_kind: next.kind,
                        continue_target: condition_entry,
                        continue_edge_kind: ControlEdgeKind::Normal,
                    },
                );
                stack.push(Work::Condition {
                    node: condition,
                    entry: condition_entry,
                    when_true: EdgeTarget {
                        point: entry,
                        kind: ControlEdgeKind::LoopBack,
                    },
                    when_false: EdgeTarget {
                        point: next.point,
                        kind: ControlEdgeKind::ConditionalFalse,
                    },
                    scope: loop_scope,
                });
                stack.push(Work::Statement {
                    node: body,
                    entry,
                    next: EdgeTarget::normal(condition_entry),
                    scope: loop_scope,
                });
                Ok(())
            }
            "for_statement" => self.for_statement(builder, node, entry, next, scope, None, stack),
            "foreach_statement" => self.foreach_statement(builder, node, entry, next, scope, stack),
            "switch_statement" => self.switch_statement(builder, node, entry, next, scope, stack),
            "try_statement" => self.try_statement(builder, node, entry, next, scope, stack),
            "using_statement" => self.using_statement(builder, node, entry, next, scope, stack),
            "lock_statement" => self.lock_statement(builder, node, entry, next, scope, stack),
            "fixed_statement" => self.fixed_statement(builder, node, entry, next, scope, stack),
            "checked_statement" | "unsafe_statement" => {
                if node.kind() == "checked_statement" {
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::ExceptionalControlFlow,
                        SemanticGapKind::Unsupported,
                        "checked overflow exceptions from enclosed operators are not fully lowered",
                    )?;
                }
                let body = first_named_child(node).ok_or_else(|| missing_field(node, "body"))?;
                stack.push(Work::Statement {
                    node: body,
                    entry,
                    next,
                    scope,
                });
                Ok(())
            }
            kind if is_conditional_compilation_kind(kind) => {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::NormalControlFlow,
                    SemanticGapKind::Unsupported,
                    "conditional-compilation branch selection depends on an unavailable preprocessor configuration",
                )
            }
            "local_declaration_statement" => {
                let declaration = named_children(node)
                    .into_iter()
                    .find(|child| child.kind() == "variable_declaration")
                    .ok_or_else(|| missing_field(node, "declaration"))?;
                if has_direct_token(node, "using") {
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::ResourceManagement,
                        SemanticGapKind::Unsupported,
                        "using-declaration disposal at the enclosing scope boundary is not lowered",
                    )?;
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::CleanupControlFlow,
                        SemanticGapKind::Unsupported,
                        "using-declaration return and exception cleanup routes are not lowered",
                    )?;
                    if has_direct_token(node, "await") {
                        self.add_gap(
                            builder,
                            entry,
                            SemanticGapSubject::Point,
                            SemanticCapability::AsyncSuspendResume,
                            SemanticGapKind::Unsupported,
                            "await using disposal suspension is not lowered",
                        )?;
                    }
                }
                self.local_declaration(builder, declaration, entry, next, scope, stack)
            }
            "empty_statement"
            | "local_function_statement"
            | "method_declaration"
            | "constructor_declaration"
            | "destructor_declaration"
            | "operator_declaration"
            | "conversion_operator_declaration"
            | "property_declaration"
            | "indexer_declaration"
            | "event_declaration"
            | "accessor_declaration"
            | "class_declaration"
            | "interface_declaration"
            | "struct_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "record_struct_declaration" => self.edge(builder, entry, next),
            _ => self.unhandled_control_syntax(builder, node, entry, next),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        let result = self.expression_value(builder, node, expression_value_kind(node))?;
        if matches!(node.kind(), "identifier" | "this" | "base") {
            self.emit_lexical_input_flow(builder, node, entry, result)?;
        }
        match node.kind() {
            "object_creation_expression"
                if is_intrinsic_object_construction(node, self.prepared.source()) =>
            {
                self.intrinsic_object_construction(builder, node, entry, next, scope, stack)
            }
            "invocation_expression"
            | "object_creation_expression"
            | "implicit_object_creation_expression"
            | "constructor_initializer" => {
                self.call_expression(builder, node, entry, next, scope, stack)
            }
            "switch_expression" => self.switch_expression(builder, node, entry, next, scope, stack),
            "lambda_expression" | "anonymous_method_expression" => {
                self.callable_expression(builder, node, entry, next)
            }
            "conditional_expression" => {
                let condition = required_field(node, "condition")?;
                let consequence = required_field(node, "consequence")?;
                let alternative = required_field(node, "alternative")?;
                let consequence_entry = self.point(builder, consequence, Vec::new())?;
                let alternative_entry = self.point(builder, alternative, Vec::new())?;
                let consequence_terminal = self.point(builder, consequence, Vec::new())?;
                let alternative_terminal = self.point(builder, alternative, Vec::new())?;
                let consequence_value = self.expression_value(
                    builder,
                    consequence,
                    expression_value_kind(consequence),
                )?;
                let alternative_value = self.expression_value(
                    builder,
                    alternative,
                    expression_value_kind(alternative),
                )?;
                if conditional_branches_have_identity_preserving_construction(
                    consequence,
                    alternative,
                    self.prepared.source(),
                ) {
                    self.append_effect(
                        builder,
                        consequence_terminal,
                        SemanticEffect::Assignment {
                            target: result,
                            value: consequence_value,
                        },
                    )?;
                    self.append_effect(
                        builder,
                        alternative_terminal,
                        SemanticEffect::Assignment {
                            target: result,
                            value: alternative_value,
                        },
                    )?;
                } else {
                    self.add_gap(
                        builder,
                        consequence_terminal,
                        SemanticGapSubject::Value(result),
                        SemanticCapability::Values,
                        SemanticGapKind::Unknown,
                        "C# conditional-expression result identity is unavailable until branch conversions are resolved",
                    )?;
                }
                self.edge(builder, consequence_terminal, next)?;
                self.edge(builder, alternative_terminal, next)?;
                stack.push(Work::Expression {
                    node: alternative,
                    entry: alternative_entry,
                    next: EdgeTarget::normal(alternative_terminal),
                    scope,
                });
                stack.push(Work::Expression {
                    node: consequence,
                    entry: consequence_entry,
                    next: EdgeTarget::normal(consequence_terminal),
                    scope,
                });
                stack.push(Work::Condition {
                    node: condition,
                    entry,
                    when_true: EdgeTarget {
                        point: consequence_entry,
                        kind: ControlEdgeKind::ConditionalTrue,
                    },
                    when_false: EdgeTarget {
                        point: alternative_entry,
                        kind: ControlEdgeKind::ConditionalFalse,
                    },
                    scope,
                });
                Ok(())
            }
            "binary_expression" if matches!(binary_operator(node), Some("&&" | "||" | "??")) => {
                let left = required_field(node, "left")?;
                let right = required_field(node, "right")?;
                let right_entry = self.point(builder, right, Vec::new())?;
                stack.push(Work::Expression {
                    node: right,
                    entry: right_entry,
                    next,
                    scope,
                });
                let (when_true, when_false) = match binary_operator(node) {
                    Some("&&") => (
                        EdgeTarget {
                            point: right_entry,
                            kind: ControlEdgeKind::ConditionalTrue,
                        },
                        EdgeTarget {
                            point: next.point,
                            kind: ControlEdgeKind::ConditionalFalse,
                        },
                    ),
                    Some("||" | "??") => (
                        EdgeTarget {
                            point: next.point,
                            kind: ControlEdgeKind::ConditionalTrue,
                        },
                        EdgeTarget {
                            point: right_entry,
                            kind: ControlEdgeKind::ConditionalFalse,
                        },
                    ),
                    _ => unreachable!("guarded by short-circuit operator"),
                };
                stack.push(Work::Condition {
                    node: left,
                    entry,
                    when_true,
                    when_false,
                    scope,
                });
                Ok(())
            }
            "assignment_expression" if is_simple_assignment(node) => {
                self.assignment_expression(builder, node, entry, next, scope, stack)
            }
            "assignment_expression"
                if node
                    .child_by_field_name("operator")
                    .is_some_and(|operator| operator.kind() == "??=") =>
            {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::Assignments,
                    SemanticGapKind::Unsupported,
                    "null-coalescing assignment target flow is not yet lowered",
                )?;
                let left = required_field(node, "left")?;
                let right = required_field(node, "right")?;
                let right_entry = self.point(builder, right, Vec::new())?;
                stack.push(Work::Expression {
                    node: right,
                    entry: right_entry,
                    next,
                    scope,
                });
                stack.push(Work::Condition {
                    node: left,
                    entry,
                    when_true: EdgeTarget {
                        point: next.point,
                        kind: ControlEdgeKind::ConditionalTrue,
                    },
                    when_false: EdgeTarget {
                        point: right_entry,
                        kind: ControlEdgeKind::ConditionalFalse,
                    },
                    scope,
                });
                Ok(())
            }
            "await_expression" => self.await_expression(builder, node, entry, next, scope, stack),
            "throw_expression" => {
                let value_node = first_named_child(node)
                    .ok_or_else(|| missing_field(node, "thrown expression"))?;
                let terminal = self.point(builder, node, Vec::new())?;
                let value = self.value(builder, terminal, SemanticValueKind::Exception)?;
                self.append_effect(
                    builder,
                    terminal,
                    SemanticEffect::Throw { value: Some(value) },
                )?;
                stack.push(Work::Expression {
                    node: value_node,
                    entry,
                    next: EdgeTarget::normal(terminal),
                    scope,
                });
                self.abrupt(builder, terminal, scope, CompletionKind::Throw, None, stack)
            }
            "conditional_access_expression" => {
                let condition = required_field(node, "condition")?;
                let binding = named_children(node)
                    .into_iter()
                    .find(|child| child.id() != condition.id())
                    .ok_or_else(|| missing_field(node, "binding"))?;
                let binding_entry = self.point(builder, binding, Vec::new())?;
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::NormalControlFlow,
                    SemanticGapKind::Unsupported,
                    "conditional-access value propagation is represented only by its control split",
                )?;
                stack.push(Work::Expression {
                    node: binding,
                    entry: binding_entry,
                    next,
                    scope,
                });
                stack.push(Work::Condition {
                    node: condition,
                    entry,
                    when_true: EdgeTarget {
                        point: binding_entry,
                        kind: ControlEdgeKind::ConditionalTrue,
                    },
                    when_false: EdgeTarget {
                        point: next.point,
                        kind: ControlEdgeKind::ConditionalFalse,
                    },
                    scope,
                });
                Ok(())
            }
            "parenthesized_expression"
            | "checked_expression"
            | "ref_expression"
            | "makeref_expression"
            | "reftype_expression"
            | "refvalue_expression" => {
                if node.kind() == "checked_expression" {
                    self.implicit_exception_gap(builder, entry, node)?;
                }
                if let Some(value) = first_runtime_named_child(node) {
                    self.transparent_expression(builder, node, value, entry, next, scope, stack)
                } else {
                    self.edge(builder, entry, next)
                }
            }
            "cast_expression" | "as_expression" => {
                let value = node
                    .child_by_field_name("value")
                    .or_else(|| node.child_by_field_name("left"))
                    .or_else(|| first_runtime_named_child(node))
                    .ok_or_else(|| missing_field(node, "value"))?;
                self.conversion_expression(builder, node, value, entry, next, scope, stack)
            }
            "null_literal" | "default_expression" => {
                let value = self.expression_value(builder, node, expression_value_kind(node))?;
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Value(value),
                    SemanticCapability::Values,
                    SemanticGapKind::Unknown,
                    "null/default object identity is not represented in the semantic value domain",
                )?;
                self.edge(builder, entry, next)
            }
            "variable_declaration" => {
                self.local_declaration(builder, node, entry, next, scope, stack)
            }
            "member_access_expression"
            | "member_binding_expression"
            | "element_access_expression"
            | "element_binding_expression" => {
                // Receiver and index expressions are evaluated before the
                // access itself can throw. Keeping the exceptional boundary on
                // a terminal preserves conservative downstream control flow
                // without making the already-evaluated receiver incomplete.
                let terminal = self.point(builder, node, Vec::new())?;
                self.implicit_exception_gap(builder, terminal, node)?;
                // A read of a member or an element loads from a location
                // (#2661). A write target and a method group are not reads at
                // all: the target's own store already represents the write,
                // and `obj.Method()` names a method group whose call site the
                // invocation already publishes.
                if !access_is_write_target(node) && !access_is_call_target(node) {
                    self.emit_memory_load(builder, terminal, node)?;
                }
                self.edge(builder, terminal, next)?;
                let children = runtime_expression_children(node);
                self.schedule_expressions(
                    builder,
                    entry,
                    &children,
                    EdgeTarget::normal(terminal),
                    scope,
                    stack,
                )
            }
            "interpolated_string_expression" | "interpolation" => {
                let values = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &values, next, scope, stack)
            }
            "query_expression" => {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::DeferredExecution,
                    SemanticGapKind::Unsupported,
                    "query-expression deferred iterator execution is not lowered",
                )?;
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::Calls,
                    SemanticGapKind::Unsupported,
                    "query-expression translation into method calls is not lowered",
                )?;
                let children = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            // An operator over predefined operands runs the language's own
            // operator, so its result derives from its operands and the flow
            // is publishable (#2661). An operator that could resolve to a
            // user-defined `operator` declaration keeps its decline, because
            // such a declaration returns whatever it likes.
            "binary_expression" | "prefix_unary_expression" | "postfix_unary_expression"
                if self.operation_is_builtin(node) =>
            {
                let children = runtime_expression_children(node);
                let terminal = self.point(builder, node, Vec::new())?;
                let result = self.expression_value(builder, node, expression_value_kind(node))?;
                let operands = children
                    .iter()
                    .map(|child| {
                        self.expression_value(builder, *child, expression_value_kind(*child))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                self.session
                    .append_language_defined_value_flows(builder, terminal, operands, result)?;
                if operation_can_throw_implicitly(node) {
                    // Integral division by zero and checked-context overflow
                    // still throw. Neither embeds an operand value.
                    self.implicit_exception_gap(builder, terminal, node)?;
                }
                self.edge(builder, terminal, next)?;
                self.schedule_expressions(
                    builder,
                    entry,
                    &children,
                    EdgeTarget::normal(terminal),
                    scope,
                    stack,
                )
            }
            "assignment_expression"
            | "binary_expression"
            | "prefix_unary_expression"
            | "postfix_unary_expression"
            | "is_expression"
            | "is_pattern_expression"
            | "array_creation_expression"
            | "implicit_array_creation_expression"
            | "anonymous_object_creation_expression"
            | "initializer_expression"
            | "collection_expression"
            | "with_expression"
            | "range_expression"
            | "stackalloc_expression"
            | "implicit_stackalloc_expression"
            | "tuple_expression"
            | "argument"
            | "argument_list"
            | "bracketed_argument_list"
            | "variable_declarator"
            | "declaration_expression"
            | "sizeof_expression"
            | "typeof_expression" => {
                if node.kind() == "assignment_expression" || is_update_expression(node) {
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::Assignments,
                        SemanticGapKind::Unsupported,
                        "compound or increment/decrement assignment flow is not yet lowered",
                    )?;
                }
                if operation_can_throw_implicitly(node) {
                    self.implicit_exception_gap(builder, entry, node)?;
                }
                if may_invoke_user_code(node) {
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::Calls,
                        SemanticGapKind::Unknown,
                        "property, indexer, conversion, or overloaded-operator invocation requires type refinement",
                    )?;
                }
                let children = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            kind if is_runtime_leaf(kind) => self.edge(builder, entry, next),
            _ => self.unhandled_control_syntax(builder, node, entry, next),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn for_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        label: Option<&'tree str>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        let body = required_field(node, "body")?;
        let initializers = children_by_field_name(node, "initializer")
            .into_iter()
            .filter(Node::is_named)
            .collect::<Vec<_>>();
        let condition = node.child_by_field_name("condition");
        let updates = children_by_field_name(node, "update")
            .into_iter()
            .filter(Node::is_named)
            .collect::<Vec<_>>();
        let has_first_iteration = csharp_for_has_first_iteration(
            self.prepared.source(),
            &initializers,
            condition,
            &updates,
        );
        let condition_entry = match condition {
            Some(condition) => self.point(builder, condition, Vec::new())?,
            None => self.point(builder, node, Vec::new())?,
        };
        let body_entry = self.point(builder, body, Vec::new())?;
        let updates = updates
            .into_iter()
            .map(|update| {
                self.point(builder, update, Vec::new())
                    .map(|entry| (update, entry))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let initializers = initializers
            .into_iter()
            .map(|initializer| {
                self.point(builder, initializer, Vec::new())
                    .map(|entry| (initializer, entry))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let initial_condition_target = if has_first_iteration {
            ControlTarget::normal(body_entry)
        } else {
            ControlTarget::normal(condition_entry)
        };
        schedule_c_style_loop(
            builder,
            &self.session,
            entry,
            next,
            scope,
            label.map(Box::<str>::from),
            &initializers,
            condition.map(|payload| (payload, condition_entry)),
            condition_entry,
            initial_condition_target,
            (body, body_entry),
            &updates,
            stack,
            Work::expression,
            Work::expression,
            Work::statement,
            Work::condition,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn foreach_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        let iterable = required_field(node, "right")?;
        let binding = required_field(node, "left")?;
        let body = required_field(node, "body")?;
        let test = self.point(builder, node, Vec::new())?;
        let binding_entry = self.point(builder, binding, Vec::new())?;
        let body_entry = self.point(builder, body, Vec::new())?;
        let loop_scope = builder.push_scope(
            Some(scope),
            ScopeBinding::Loop {
                label: None,
                break_target: next.point,
                break_edge_kind: next.kind,
                continue_target: test,
                continue_edge_kind: ControlEdgeKind::LoopBack,
            },
        );
        self.add_gap(
            builder,
            test,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unsupported,
            "implicit enumerator acquisition and MoveNext calls are not represented as call sites",
        )?;
        self.add_gap(
            builder,
            test,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            "implicit enumerator acquisition and advancement exceptions are not lowered",
        )?;
        self.add_gap(
            builder,
            test,
            SemanticGapSubject::Point,
            SemanticCapability::ResourceManagement,
            SemanticGapKind::Unsupported,
            "enumerator disposal and completion-sensitive cleanup are not lowered",
        )?;
        if has_direct_token(node, "await") {
            self.add_gap(
                builder,
                test,
                SemanticGapSubject::Point,
                SemanticCapability::AsyncSuspendResume,
                SemanticGapKind::Unsupported,
                "await foreach suspension and asynchronous disposal are not lowered",
            )?;
        }
        self.edge(
            builder,
            test,
            EdgeTarget {
                point: binding_entry,
                kind: ControlEdgeKind::ConditionalTrue,
            },
        )?;
        self.edge(
            builder,
            test,
            EdgeTarget {
                point: next.point,
                kind: ControlEdgeKind::ConditionalFalse,
            },
        )?;
        self.edge(builder, binding_entry, EdgeTarget::normal(body_entry))?;
        stack.push(Work::Statement {
            node: body,
            entry: body_entry,
            next: EdgeTarget {
                point: test,
                kind: ControlEdgeKind::LoopBack,
            },
            scope: loop_scope,
        });
        stack.push(Work::Expression {
            node: iterable,
            entry,
            next: EdgeTarget::normal(test),
            scope: loop_scope,
        });
        Ok(())
    }

    fn switch_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        let value = required_field(node, "value")?;
        let body = required_field(node, "body")?;
        let dispatch = self.point(builder, node, Vec::new())?;
        let sections = named_children(body)
            .into_iter()
            .filter(|child| child.kind() == "switch_section")
            .collect::<Vec<_>>();
        if sections.is_empty() {
            self.edge(builder, dispatch, next)?;
            stack.push(Work::Expression {
                node: value,
                entry,
                next: EdgeTarget::normal(dispatch),
                scope,
            });
            return Ok(());
        }

        let switch_scope = builder.push_scope(
            Some(scope),
            ScopeBinding::Breakable {
                label: None,
                accepts_unlabeled: true,
                break_target: next.point,
                break_edge_kind: next.kind,
            },
        );
        let entries = sections
            .iter()
            .map(|section| self.point(builder, *section, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        let mut has_default = false;
        for (index, section) in sections.iter().enumerate() {
            has_default |= has_direct_token(*section, "default");
            let control = switch_section_control_nodes(*section);
            if control
                .iter()
                .any(|child| matches!(child.kind(), "pattern" | "when_clause"))
            {
                self.add_gap(
                    builder,
                    entries[index],
                    SemanticGapSubject::Point,
                    SemanticCapability::NormalControlFlow,
                    SemanticGapKind::Unsupported,
                    "switch pattern and when-clause matching require type refinement",
                )?;
                self.add_gap(
                    builder,
                    entries[index],
                    SemanticGapSubject::Point,
                    SemanticCapability::ExceptionalControlFlow,
                    SemanticGapKind::Unsupported,
                    "switch when-clause evaluation failures are not lowered",
                )?;
            }
            self.edge(
                builder,
                dispatch,
                EdgeTarget {
                    point: entries[index],
                    kind: ControlEdgeKind::SwitchCase,
                },
            )?;
            let statements = switch_section_statements(*section);
            if statements.is_empty() {
                let target = entries
                    .get(index + 1)
                    .copied()
                    .map(EdgeTarget::normal)
                    .unwrap_or(next);
                self.edge(builder, entries[index], target)?;
            } else {
                self.schedule_statements(
                    builder,
                    entries[index],
                    &statements,
                    next,
                    switch_scope,
                    stack,
                )?;
            }
        }
        if !has_default {
            self.edge(
                builder,
                dispatch,
                EdgeTarget {
                    point: next.point,
                    kind: ControlEdgeKind::ConditionalFalse,
                },
            )?;
        }
        stack.push(Work::Expression {
            node: value,
            entry,
            next: EdgeTarget::normal(dispatch),
            scope: switch_scope,
        });
        Ok(())
    }

    fn switch_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        let children = named_children(node);
        let value = children
            .iter()
            .copied()
            .find(|child| child.kind() != "switch_expression_arm")
            .ok_or_else(|| missing_field(node, "value"))?;
        let arms = children
            .into_iter()
            .filter(|child| child.kind() == "switch_expression_arm")
            .collect::<Vec<_>>();
        let dispatch = self.point(builder, node, Vec::new())?;
        let merge = self.point(builder, node, Vec::new())?;
        self.edge(builder, merge, next)?;
        self.add_gap(
            builder,
            dispatch,
            SemanticGapSubject::Point,
            SemanticCapability::NormalControlFlow,
            SemanticGapKind::Unsupported,
            "switch-expression pattern and when-clause selection require type refinement",
        )?;
        self.add_gap(
            builder,
            dispatch,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            "non-exhaustive switch-expression failure and filter exceptions are only bounded here",
        )?;

        for arm in arms {
            let arm_entry = self.point(builder, arm, Vec::new())?;
            self.edge(
                builder,
                dispatch,
                EdgeTarget {
                    point: arm_entry,
                    kind: ControlEdgeKind::SwitchCase,
                },
            )?;
            let arm_value =
                switch_expression_arm_value(arm).ok_or_else(|| missing_field(arm, "value"))?;
            stack.push(Work::Expression {
                node: arm_value,
                entry: arm_entry,
                next: EdgeTarget::normal(merge),
                scope,
            });
        }
        let unmatched = self.point(builder, node, Vec::new())?;
        self.edge(
            builder,
            dispatch,
            EdgeTarget {
                point: unmatched,
                kind: ControlEdgeKind::Exceptional,
            },
        )?;
        self.abrupt(
            builder,
            unmatched,
            scope,
            CompletionKind::Throw,
            None,
            stack,
        )?;
        stack.push(Work::Expression {
            node: value,
            entry,
            next: EdgeTarget::normal(dispatch),
            scope,
        });
        Ok(())
    }

    fn try_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        let body = required_field(node, "body")?;
        let children = named_children(node);
        let catches = children
            .iter()
            .copied()
            .filter(|child| child.kind() == "catch_clause")
            .collect::<Vec<_>>();
        let finalizer = children
            .iter()
            .copied()
            .find(|child| child.kind() == "finally_clause")
            .and_then(first_named_child);

        let (cleanup_scope, cleanup_region) = if let Some(finalizer) = finalizer {
            let region =
                CleanupRegionId::new(u32::try_from(self.cleanups.len()).map_err(|_| {
                    CSharpLoweringError::Invalid("too many cleanup regions".into())
                })?);
            self.cleanups.push(CleanupRegion {
                id: region,
                body: CleanupBody::Statement(finalizer),
                outer_scope: scope,
            });
            (
                builder.push_scope(Some(scope), ScopeBinding::Cleanup { region }),
                Some(region),
            )
        } else {
            (scope, None)
        };

        let normal_destination = if cleanup_region.is_some() && next.kind != ControlEdgeKind::Normal
        {
            let relay = self.point(builder, node, Vec::new())?;
            self.edge(builder, relay, next)?;
            relay
        } else {
            next.point
        };
        let normal_route = cleanup_region
            .map(|region| builder.normal_cleanup_completion(region, normal_destination));

        let catch_bodies = catches
            .iter()
            .map(|catch| required_field(*catch, "body"))
            .collect::<Result<Vec<_>, _>>()?;
        let catch_entries = catch_bodies
            .iter()
            .map(|body| self.point(builder, *body, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        let try_scope = if catch_entries.is_empty() {
            cleanup_scope
        } else {
            let dispatcher = self.point(builder, node, Vec::new())?;
            self.add_gap(
                builder,
                dispatcher,
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unknown,
                "catch-type compatibility and multi-catch selection require type refinement",
            )?;
            for catch_entry in &catch_entries {
                self.edge(
                    builder,
                    dispatcher,
                    EdgeTarget {
                        point: *catch_entry,
                        kind: ControlEdgeKind::SwitchCase,
                    },
                )?;
            }
            let unmatched = self.point(builder, node, Vec::new())?;
            self.edge(
                builder,
                dispatcher,
                EdgeTarget {
                    point: unmatched,
                    kind: ControlEdgeKind::Exceptional,
                },
            )?;
            self.abrupt(
                builder,
                unmatched,
                cleanup_scope,
                CompletionKind::Throw,
                None,
                stack,
            )?;
            builder.push_scope(
                Some(cleanup_scope),
                ScopeBinding::Handler { entry: dispatcher },
            )
        };

        for ((catch, catch_body), catch_entry) in
            catches.iter().zip(&catch_bodies).zip(&catch_entries)
        {
            if named_children(*catch)
                .into_iter()
                .any(|child| child.kind() == "catch_filter_clause")
            {
                self.add_gap(
                    builder,
                    *catch_entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::ExceptionalControlFlow,
                    SemanticGapKind::Unsupported,
                    "catch-filter evaluation, false routing, and filter-failure semantics are not lowered",
                )?;
            }
            if let Some(route) = &normal_route {
                let catch_exit = self.point(builder, *catch_body, Vec::new())?;
                self.route(builder, catch_exit, route, stack)?;
                stack.push(Work::Statement {
                    node: *catch_body,
                    entry: *catch_entry,
                    next: EdgeTarget::normal(catch_exit),
                    scope: cleanup_scope,
                });
            } else {
                stack.push(Work::Statement {
                    node: *catch_body,
                    entry: *catch_entry,
                    next,
                    scope: cleanup_scope,
                });
            }
        }

        if let Some(route) = normal_route.as_ref() {
            let body_exit = self.point(builder, body, Vec::new())?;
            self.route(builder, body_exit, route, stack)?;
            stack.push(Work::Statement {
                node: body,
                entry,
                next: EdgeTarget::normal(body_exit),
                scope: try_scope,
            });
        } else {
            stack.push(Work::Statement {
                node: body,
                entry,
                next,
                scope: try_scope,
            });
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn lock_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        let children = named_children(node);
        let body = children
            .iter()
            .copied()
            .find(|child| is_statement_kind(child.kind()))
            .ok_or_else(|| missing_field(node, "body"))?;
        let lock = children
            .into_iter()
            .find(|child| child.id() != body.id())
            .ok_or_else(|| missing_field(node, "lock"))?;
        let monitor = self.point(builder, lock, Vec::new())?;
        let body_entry = self.point(builder, body, Vec::new())?;
        let region = CleanupRegionId::new(
            u32::try_from(self.cleanups.len())
                .map_err(|_| CSharpLoweringError::Invalid("too many cleanup regions".into()))?,
        );
        self.cleanups.push(CleanupRegion {
            id: region,
            body: CleanupBody::OpaqueMonitor(node),
            outer_scope: scope,
        });
        let lock_scope = builder.push_scope(Some(scope), ScopeBinding::Cleanup { region });
        self.add_gap(
            builder,
            monitor,
            SemanticGapSubject::Point,
            SemanticCapability::CleanupControlFlow,
            SemanticGapKind::Unsupported,
            "Monitor ownership and reentrancy effects are represented only as opaque boundaries",
        )?;
        self.add_gap(
            builder,
            monitor,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            "implicit Monitor.Enter acquisition exceptions are not lowered",
        )?;
        self.edge(builder, monitor, EdgeTarget::normal(body_entry))?;
        let cleanup_destination = if next.kind == ControlEdgeKind::Normal {
            next.point
        } else {
            let relay = self.point(builder, node, Vec::new())?;
            self.edge(builder, relay, next)?;
            relay
        };
        let body_exit = self.point(builder, body, Vec::new())?;
        let normal_route = builder.normal_cleanup_completion(region, cleanup_destination);
        self.route(builder, body_exit, &normal_route, stack)?;
        stack.push(Work::Statement {
            node: body,
            entry: body_entry,
            next: EdgeTarget::normal(body_exit),
            scope: lock_scope,
        });
        stack.push(Work::Expression {
            node: lock,
            entry,
            next: EdgeTarget::normal(monitor),
            scope,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn using_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        let body = required_field(node, "body")?;
        let resource = named_children(node)
            .into_iter()
            .find(|child| child.id() != body.id())
            .ok_or_else(|| missing_field(node, "resource"))?;
        let boundary = self.opaque_resource_statement(
            builder,
            node,
            resource,
            body,
            entry,
            next,
            scope,
            CleanupBody::OpaqueResource(node),
            stack,
        )?;
        if has_direct_token(node, "await") {
            self.add_gap(
                builder,
                boundary,
                SemanticGapSubject::Point,
                SemanticCapability::AsyncSuspendResume,
                SemanticGapKind::Unsupported,
                "await using acquisition and asynchronous disposal suspension are not lowered",
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn fixed_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        let children = named_children(node);
        let resource = children
            .iter()
            .copied()
            .find(|child| child.kind() == "variable_declaration")
            .ok_or_else(|| missing_field(node, "declaration"))?;
        let body = children
            .into_iter()
            .find(|child| child.id() != resource.id() && is_statement_kind(child.kind()))
            .ok_or_else(|| missing_field(node, "body"))?;
        self.opaque_resource_statement(
            builder,
            node,
            resource,
            body,
            entry,
            next,
            scope,
            CleanupBody::OpaqueFixed(node),
            stack,
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn opaque_resource_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        resource: Node<'tree>,
        body: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        cleanup_body: CleanupBody<'tree>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<ProgramPointId, CSharpLoweringError> {
        let boundary = self.point(builder, resource, Vec::new())?;
        let body_entry = self.point(builder, body, Vec::new())?;
        let region = CleanupRegionId::new(
            u32::try_from(self.cleanups.len())
                .map_err(|_| CSharpLoweringError::Invalid("too many cleanup regions".into()))?,
        );
        self.cleanups.push(CleanupRegion {
            id: region,
            body: cleanup_body,
            outer_scope: scope,
        });
        let resource_scope = builder.push_scope(Some(scope), ScopeBinding::Cleanup { region });
        self.add_gap(
            builder,
            boundary,
            SemanticGapSubject::Point,
            SemanticCapability::ResourceManagement,
            SemanticGapKind::Unsupported,
            "resource acquisition, value identity, and partial-initialization cleanup are not fully lowered",
        )?;
        self.add_gap(
            builder,
            boundary,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            "resource acquisition and cleanup can raise exceptions not fully represented",
        )?;
        self.edge(builder, boundary, EdgeTarget::normal(body_entry))?;
        let cleanup_destination = if next.kind == ControlEdgeKind::Normal {
            next.point
        } else {
            let relay = self.point(builder, node, Vec::new())?;
            self.edge(builder, relay, next)?;
            relay
        };
        let body_exit = self.point(builder, body, Vec::new())?;
        let normal_route = builder.normal_cleanup_completion(region, cleanup_destination);
        self.route(builder, body_exit, &normal_route, stack)?;
        stack.push(Work::Statement {
            node: body,
            entry: body_entry,
            next: EdgeTarget::normal(body_exit),
            scope: resource_scope,
        });
        stack.push(Work::Expression {
            node: resource,
            entry,
            next: EdgeTarget::normal(boundary),
            scope,
        });
        Ok(boundary)
    }

    #[allow(clippy::too_many_arguments)]
    fn intrinsic_object_construction(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        let normal = self.point(builder, node, Vec::new())?;
        let exceptional = self.point(builder, node, Vec::new())?;
        let result = self.expression_value(builder, node, SemanticValueKind::Temporary)?;
        self.session
            .add_allocation(builder, normal, result, AllocationKind::Object)?;
        self.edge(builder, entry, EdgeTarget::normal(normal))?;
        self.edge(
            builder,
            entry,
            EdgeTarget {
                point: exceptional,
                kind: ControlEdgeKind::Exceptional,
            },
        )?;
        self.edge(builder, normal, next)?;
        self.abrupt(
            builder,
            exceptional,
            scope,
            CompletionKind::Throw,
            None,
            stack,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn call_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        let invoke = self.point(builder, node, Vec::new())?;
        let normal = self.point(builder, node, Vec::new())?;
        let exceptional = self.point(builder, node, Vec::new())?;
        let function = node.child_by_field_name("function");
        let callable_anchor = function
            .or_else(|| node.child_by_field_name("type"))
            .or_else(|| first_named_child(node))
            .unwrap_or(node);
        let callee = self.source_value(builder, callable_anchor, SemanticValueKind::Callable)?;
        let result = self.expression_value(builder, node, SemanticValueKind::Temporary)?;
        let thrown = self.source_value(builder, callable_anchor, SemanticValueKind::Exception)?;
        let receiver_node = function.and_then(csharp_call_receiver);
        let receiver = receiver_node
            .map(|receiver_node| {
                self.expression_value(builder, receiver_node, expression_value_kind(receiver_node))
            })
            .transpose()?;
        let constructor = matches!(
            node.kind(),
            "object_creation_expression"
                | "implicit_object_creation_expression"
                | "constructor_initializer"
        );
        let callable_kind = if constructor {
            CallableReferenceKind::Constructor
        } else if receiver.is_some() {
            CallableReferenceKind::BoundMethod
        } else {
            CallableReferenceKind::Function
        };
        let resolution = if matches!(
            node.kind(),
            "implicit_object_creation_expression" | "constructor_initializer"
        ) {
            CallableTargetResolution::Unsupported
        } else {
            CallableTargetResolution::Unknown
        };
        let metadata = self.metadata(invoke)?;
        self.append_effect(
            builder,
            invoke,
            SemanticEffect::CallableReference {
                result: callee,
                callable: CallableValue {
                    kind: callable_kind,
                    targets: resolution.clone(),
                    target_evidence: metadata.evidence,
                    bound_receiver: receiver,
                    environment: None,
                },
            },
        )?;

        let arguments = call_arguments(node);
        let mut argument_nodes = Vec::with_capacity(arguments.len());
        let mut argument_values = Vec::with_capacity(arguments.len());
        let mut incomplete_argument_mapping = false;
        for argument in arguments {
            let Some(value_node) = call_argument_value(argument) else {
                continue;
            };
            argument_nodes.push(value_node);
            let value =
                self.expression_value(builder, value_node, expression_value_kind(value_node))?;
            let semantic_argument = match csharp_call_argument_shape(argument) {
                CSharpCallArgumentShape::Positional => {
                    SemanticCallArgument::direct(value, ArgumentDomain::Positional)
                }
                CSharpCallArgumentShape::Named => {
                    let name = argument
                        .child_by_field_name("name")
                        .and_then(|name| node_text(self.prepared.source(), name))
                        .ok_or_else(|| {
                            CSharpLoweringError::Invalid(
                                "C# named argument is missing its structured name".into(),
                            )
                        })?;
                    SemanticCallArgument::keyword(value, name)
                }
                CSharpCallArgumentShape::ByReference => {
                    incomplete_argument_mapping = true;
                    SemanticCallArgument::unclassified(value)
                }
            };
            argument_values.push(semantic_argument);
        }
        let call_site = self.session.add_call_site(
            builder,
            CallSiteScaffold {
                point: invoke,
                callee,
                receiver,
                arguments: argument_values.into_boxed_slice(),
                normal_results: Box::new([]),
                result: Some(result),
                thrown: Some(thrown),
                declared_targets: resolution.clone(),
                normal_continuation: normal,
                exceptional_continuation: exceptional,
            },
        )?;
        if incomplete_argument_mapping {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::ParameterFlow,
                SemanticGapKind::Unsupported,
                "by-reference C# argument-to-parameter mapping is not yet lowered",
            )?;
        }
        if matches!(
            node.kind(),
            "object_creation_expression" | "implicit_object_creation_expression"
        ) {
            self.session
                .add_allocation(builder, normal, result, AllocationKind::Object)?;
        }
        self.edge(builder, invoke, EdgeTarget::normal(normal))?;
        self.edge(
            builder,
            invoke,
            EdgeTarget {
                point: exceptional,
                kind: ControlEdgeKind::Exceptional,
            },
        )?;

        if let Some(initializer) = object_initializer(node) {
            stack.push(Work::Expression {
                node: initializer,
                entry: normal,
                next,
                scope,
            });
        } else {
            self.edge(builder, normal, next)?;
        }
        self.abrupt(
            builder,
            exceptional,
            scope,
            CompletionKind::Throw,
            None,
            stack,
        )?;
        self.resolution_gaps(builder, invoke, callee, call_site, &resolution)?;

        if !constructor {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::DynamicDispatch,
                SemanticGapKind::Unknown,
                "invocation may select a virtual member or delegate target; static/final dispatch and complete override coverage require type-hierarchy refinement",
            )?;
        }

        if function.is_some_and(|function| function.kind() == "conditional_access_expression") {
            let function = function.expect("guarded conditional function");
            let condition = required_field(function, "condition")?;
            let binding = conditional_access_binding(function)
                .ok_or_else(|| missing_field(function, "binding"))?;
            let conditional_entry = self.point(builder, function, Vec::new())?;
            self.add_gap(
                builder,
                conditional_entry,
                SemanticGapSubject::Point,
                SemanticCapability::NormalControlFlow,
                SemanticGapKind::Unsupported,
                "conditional invocation uses a null-test split; conditional result values are not modeled",
            )?;
            let mut evaluations = Vec::with_capacity(argument_nodes.len() + 1);
            if binding.kind() == "element_binding_expression" {
                evaluations.push(binding);
            }
            evaluations.extend(argument_nodes.iter().copied());
            self.schedule_expressions(
                builder,
                conditional_entry,
                &evaluations,
                EdgeTarget::normal(invoke),
                scope,
                stack,
            )?;
            stack.push(Work::Condition {
                node: condition,
                entry,
                when_true: EdgeTarget {
                    point: conditional_entry,
                    kind: ControlEdgeKind::ConditionalTrue,
                },
                when_false: EdgeTarget {
                    point: next.point,
                    kind: ControlEdgeKind::ConditionalFalse,
                },
                scope,
            });
            return Ok(());
        }

        let mut evaluations = Vec::with_capacity(argument_nodes.len() + 1);
        if let Some(receiver_node) = receiver_node {
            evaluations.push(receiver_node);
        } else if let Some(function) = function
            && call_function_requires_evaluation(function)
        {
            evaluations.push(function);
        }
        evaluations.extend(argument_nodes);
        self.schedule_expressions(
            builder,
            entry,
            &evaluations,
            EdgeTarget::normal(invoke),
            scope,
            stack,
        )
    }

    fn await_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        let awaited_node = first_named_child(node);
        let AwaitScaffold {
            suspend,
            normal_resume: normal,
            exceptional_resume: exceptional,
            ..
        } = self
            .session
            .add_await_scaffold(builder, |session, builder| {
                session.add_node_mapping(builder, node)
            })?;
        self.edge(builder, normal, next)?;
        self.abrupt(
            builder,
            exceptional,
            scope,
            CompletionKind::Throw,
            None,
            stack,
        )?;
        if let Some(awaited_node) = awaited_node {
            stack.push(Work::Expression {
                node: awaited_node,
                entry,
                next: EdgeTarget::normal(suspend),
                scope,
            });
        } else {
            self.edge(builder, entry, EdgeTarget::normal(suspend))?;
        }
        Ok(())
    }

    fn callable_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
    ) -> Result<(), CSharpLoweringError> {
        let result = self.expression_value(builder, node, SemanticValueKind::Callable)?;
        let resolution = CallableTargetResolution::Unknown;
        let metadata = self.metadata(entry)?;
        let kind = CallableReferenceKind::Lambda;
        let callable = CallableValue {
            kind,
            targets: resolution,
            target_evidence: metadata.evidence,
            bound_receiver: None,
            environment: None,
        };
        self.append_effect(
            builder,
            entry,
            SemanticEffect::CallableCreation { result, callable },
        )?;
        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Value(result),
            SemanticCapability::CallableReferences,
            SemanticGapKind::Unknown,
            "nested callable target mapping is not yet published",
        )?;
        self.edge(builder, entry, next)
    }

    fn implicit_exception_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        node: Node<'tree>,
    ) -> Result<(), CSharpLoweringError> {
        let detail = match node.kind() {
            "member_access_expression" | "member_binding_expression" => {
                "implicit null, type-initialization, or property-access exceptions are not yet lowered"
            }
            "element_access_expression" | "element_binding_expression" => {
                "implicit null, bounds, or indexer-access exceptions are not yet lowered"
            }
            _ => "implicit exceptions from runtime operators are not yet lowered",
        };
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            detail,
        )
    }

    fn unhandled_control_syntax(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        _next: EdgeTarget,
    ) -> Result<(), CSharpLoweringError> {
        let detail = format!(
            "{} runtime/control syntax is not yet lowered structurally",
            node.kind()
        );
        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::NormalControlFlow,
            SemanticGapKind::Unsupported,
            &detail,
        )
    }

    fn schedule_statements(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        children: &[Node<'tree>],
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        if children.is_empty() {
            return self.edge(builder, entry, next);
        }
        let entries = children
            .iter()
            .map(|child| self.point(builder, *child, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        self.edge(builder, entry, EdgeTarget::normal(entries[0]))?;
        for index in (0..children.len()).rev() {
            let child_next = entries
                .get(index + 1)
                .copied()
                .map(EdgeTarget::normal)
                .unwrap_or(next);
            stack.push(Work::Statement {
                node: children[index],
                entry: entries[index],
                next: child_next,
                scope,
            });
        }
        Ok(())
    }

    fn schedule_expressions(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        children: &[Node<'tree>],
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        if children.is_empty() {
            return self.edge(builder, entry, next);
        }
        let entries = children
            .iter()
            .map(|child| self.point(builder, *child, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        self.edge(builder, entry, EdgeTarget::normal(entries[0]))?;
        for index in (0..children.len()).rev() {
            let child_next = entries
                .get(index + 1)
                .copied()
                .map(EdgeTarget::normal)
                .unwrap_or(next);
            stack.push(Work::Expression {
                node: children[index],
                entry: entries[index],
                next: child_next,
                scope,
            });
        }
        Ok(())
    }

    fn abrupt(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        from: ProgramPointId,
        scope: ScopeFrameId,
        kind: CompletionKind,
        label: Option<&str>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        let Some(route) = builder.resolve_completion(scope, &CompletionRequest::new(kind, label))
        else {
            if matches!(
                kind,
                CompletionKind::Break | CompletionKind::Continue | CompletionKind::Yield
            ) {
                let detail = format!(
                    "{} completion has no matching represented target",
                    completion_label(kind)
                );
                self.add_gap(
                    builder,
                    from,
                    SemanticGapSubject::Point,
                    SemanticCapability::NonLocalControl,
                    SemanticGapKind::Unsupported,
                    &detail,
                )?;
                return Ok(());
            }
            return Err(CSharpLoweringError::Invalid(format!(
                "{} completion has no matching structured continuation",
                completion_label(kind)
            )));
        };
        self.route(builder, from, &route, stack)
    }

    fn route(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        from: ProgramPointId,
        route: &CompletionRoute,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        let mut plan = CleanupRoutePlanner::new(route);
        while let Some(step) = plan.next(
            builder,
            &mut self.session,
            &self.cleanups,
            |region| region.id,
            |region| region.body.source_node(),
        )? {
            match step.region.body {
                CleanupBody::Statement(body) => {
                    let statement_next = if step.next.kind == ControlEdgeKind::Normal {
                        step.next
                    } else {
                        let relay = self.point(builder, body, Vec::new())?;
                        self.edge(builder, relay, step.next)?;
                        EdgeTarget::normal(relay)
                    };
                    stack.push(Work::Statement {
                        node: body,
                        entry: step.entry,
                        next: statement_next,
                        scope: step.region.outer_scope,
                    });
                }
                CleanupBody::OpaqueResource(_) => {
                    self.add_gap(
                        builder,
                        step.entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::ResourceManagement,
                        SemanticGapKind::Unsupported,
                        "resource close order, suppression, and value effects are not yet lowered",
                    )?;
                    self.add_gap(
                        builder,
                        step.entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::ExceptionalControlFlow,
                        SemanticGapKind::Unsupported,
                        "resource close can raise or suppress exceptions not yet represented",
                    )?;
                    self.edge(builder, step.entry, step.next)?;
                }
                CleanupBody::OpaqueFixed(_) => {
                    self.add_gap(
                            builder,
                            step.entry,
                            SemanticGapSubject::Point,
                            SemanticCapability::ResourceManagement,
                            SemanticGapKind::Unsupported,
                            "fixed-region pinning lifetime and pointer invalidation are represented only as an opaque cleanup boundary",
                        )?;
                    self.edge(builder, step.entry, step.next)?;
                }
                CleanupBody::OpaqueMonitor(_) => {
                    self.add_gap(
                            builder,
                            step.entry,
                            SemanticGapSubject::Point,
                            SemanticCapability::CleanupControlFlow,
                            SemanticGapKind::Unsupported,
                            "monitor release effects are represented only as an opaque cleanup boundary",
                        )?;
                    self.add_gap(
                        builder,
                        step.entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::ExceptionalControlFlow,
                        SemanticGapKind::Unsupported,
                        "monitor release failure behavior is not yet represented",
                    )?;
                    self.edge(builder, step.entry, step.next)?;
                }
            }
        }
        self.edge(builder, from, plan.target())
    }

    fn resolution_gaps(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        callee: ValueId,
        call_site: CallSiteId,
        resolution: &CallableTargetResolution,
    ) -> Result<(), CSharpLoweringError> {
        self.session.add_callable_resolution_gaps(
            builder,
            point,
            callee,
            call_site,
            resolution,
            "callable target requires whole-program dispatch refinement",
            "call target requires whole-program dispatch refinement",
        )
    }

    fn point(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        effects: Vec<SemanticEffect>,
    ) -> Result<ProgramPointId, CSharpLoweringError> {
        let metadata = self.mapping(builder, node)?;
        self.session.add_point(builder, metadata, effects)
    }

    fn mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<PointMetadata, CSharpLoweringError> {
        self.session.add_node_mapping(builder, node)
    }

    fn value_mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<PointMetadata, CSharpLoweringError> {
        let anchor = source_anchor(node, 0).map_err(CSharpLoweringError::Invalid)?;
        self.session
            .add_mapping(builder, anchor, SourceMappingKind::Exact)
    }

    fn metadata(&self, point: ProgramPointId) -> Result<PointMetadata, CSharpLoweringError> {
        self.session.metadata(point)
    }

    fn value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        kind: SemanticValueKind,
    ) -> Result<ValueId, CSharpLoweringError> {
        self.session.add_value(builder, point, kind)
    }

    fn append_effect(
        &self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        effect: SemanticEffect,
    ) -> Result<(), CSharpLoweringError> {
        self.session.append_effect(builder, point, effect)
    }

    fn add_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        subject: SemanticGapSubject,
        capability: SemanticCapability,
        kind: SemanticGapKind,
        detail: &str,
    ) -> Result<(), CSharpLoweringError> {
        self.session
            .add_gap(builder, point, subject, capability, kind, detail)?;
        Ok(())
    }

    fn edge(
        &self,
        builder: &mut ProcedureCfgBuilder,
        source_point: ProgramPointId,
        target: EdgeTarget,
    ) -> Result<(), CSharpLoweringError> {
        self.session
            .add_edge(builder, source_point, target.point, target.kind)
    }
}

fn runtime_expression_children(node: Node<'_>) -> Vec<Node<'_>> {
    let fields: &[&str] = match node.kind() {
        "member_access_expression" => &["expression"],
        "element_access_expression" => &["expression", "subscript"],
        "assignment_expression" | "binary_expression" => &["left", "right"],
        "cast_expression" => &["value"],
        "as_expression" | "is_expression" => &["left"],
        "is_pattern_expression" => &["expression"],
        _ => &[],
    };
    if !fields.is_empty() {
        let mut result = Vec::new();
        for field in fields {
            for child in children_by_field_name(node, field) {
                if is_type_syntax(child.kind()) || is_annotation_kind(child.kind()) {
                    continue;
                }
                if !result
                    .iter()
                    .any(|existing: &Node<'_>| existing.id() == child.id())
                {
                    result.push(child);
                }
            }
        }
        result.sort_by_key(Node::start_byte);
        return result;
    }

    named_children(node)
        .into_iter()
        .filter(|child| {
            !is_non_runtime_field(node, *child)
                && !is_type_syntax(child.kind())
                && !is_annotation_kind(child.kind())
                && !is_pattern_syntax(child.kind())
                && !matches!(
                    child.kind(),
                    "modifier"
                        | "attribute_list"
                        | "interpolation_alignment_clause"
                        | "interpolation_format_clause"
                        | "interpolation_brace"
                )
        })
        .collect()
}

fn first_runtime_named_child(node: Node<'_>) -> Option<Node<'_>> {
    named_children(node).into_iter().find(|child| {
        !is_non_runtime_field(node, *child)
            && !is_type_syntax(child.kind())
            && !is_annotation_kind(child.kind())
            && !is_pattern_syntax(child.kind())
            && child.kind() != "modifier"
    })
}

fn is_non_runtime_field(node: Node<'_>, child: Node<'_>) -> bool {
    [
        "name",
        "type",
        "returns",
        "operator",
        "parameters",
        "type_parameters",
        "pattern",
    ]
    .into_iter()
    .any(|field| field_matches(node, field, child))
}

fn is_type_syntax(kind: &str) -> bool {
    matches!(
        kind,
        "array_type"
            | "function_pointer_type"
            | "implicit_type"
            | "nullable_type"
            | "pointer_type"
            | "predefined_type"
            | "ref_type"
            | "scoped_type"
            | "tuple_type"
            | "type"
            | "type_argument_list"
            | "type_parameter"
            | "type_parameter_list"
            | "type_parameter_constraint"
            | "type_parameter_constraints_clause"
            | "base_list"
    )
}

fn is_annotation_kind(kind: &str) -> bool {
    matches!(
        kind,
        "attribute" | "attribute_argument" | "attribute_argument_list" | "attribute_list"
    )
}

fn is_pattern_syntax(kind: &str) -> bool {
    kind == "pattern"
        || kind.ends_with("_pattern")
        || matches!(
            kind,
            "discard"
                | "positional_pattern_clause"
                | "property_pattern_clause"
                | "subpattern"
                | "when_clause"
        )
}

fn expression_value_kind(node: Node<'_>) -> SemanticValueKind {
    match node.kind() {
        "lambda_expression" | "anonymous_method_expression" => SemanticValueKind::Callable,
        "integer_literal"
        | "real_literal"
        | "boolean_literal"
        | "character_literal"
        | "string_literal"
        | "verbatim_string_literal"
        | "raw_string_literal"
        | "null_literal" => SemanticValueKind::Constant,
        _ => SemanticValueKind::Temporary,
    }
}

fn is_callable_kind(kind: &str) -> bool {
    matches!(
        kind,
        "method_declaration"
            | "constructor_declaration"
            | "local_function_statement"
            | "lambda_expression"
            | "anonymous_method_expression"
            | "accessor_declaration"
            | "operator_declaration"
            | "conversion_operator_declaration"
            | "destructor_declaration"
    )
}

fn is_csharp_nested_execution_boundary(node: Node<'_>) -> bool {
    is_callable_kind(node.kind())
        || matches!(
            node.kind(),
            "class_declaration"
                | "interface_declaration"
                | "struct_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "record_struct_declaration"
        )
}

fn is_local_variable_declarator(node: Node<'_>) -> bool {
    node.parent()
        .filter(|parent| parent.kind() == "variable_declaration")
        .and_then(|declaration| declaration.parent())
        .is_none_or(|owner| {
            !matches!(
                owner.kind(),
                "field_declaration" | "event_field_declaration"
            )
        })
}

fn csharp_local_scope(node: Node<'_>) -> Option<(usize, usize)> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "block"
                | "for_statement"
                | "foreach_statement"
                | "switch_section"
                | "using_statement"
                | "fixed_statement"
                | "catch_clause"
        ) {
            return Some((parent.start_byte(), parent.end_byte()));
        }
        if is_csharp_nested_execution_boundary(parent) {
            return Some((parent.start_byte(), parent.end_byte()));
        }
        current = parent.parent();
    }
    None
}

fn is_statement_kind(kind: &str) -> bool {
    is_conditional_compilation_kind(kind)
        || matches!(
            kind,
            "block"
                | "break_statement"
                | "checked_statement"
                | "continue_statement"
                | "do_statement"
                | "empty_statement"
                | "expression_statement"
                | "fixed_statement"
                | "for_statement"
                | "foreach_statement"
                | "goto_statement"
                | "if_statement"
                | "labeled_statement"
                | "local_declaration_statement"
                | "local_function_statement"
                | "lock_statement"
                | "return_statement"
                | "switch_statement"
                | "throw_statement"
                | "try_statement"
                | "unsafe_statement"
                | "using_statement"
                | "while_statement"
                | "yield_statement"
        )
}

fn is_conditional_compilation_kind(kind: &str) -> bool {
    matches!(
        kind,
        "preproc_if" | "preproc_elif" | "preproc_else" | "preproc_if_in_attribute_list"
    )
}

fn variable_declarator_initializer(declarator: Node<'_>) -> Option<Node<'_>> {
    declarator
        .child_by_field_name("value")
        .or_else(|| declarator.child_by_field_name("initializer"))
        .or_else(|| {
            named_children(declarator)
                .into_iter()
                .find(|child| child.kind() == "equals_value_clause")
                .and_then(|clause| {
                    clause
                        .child_by_field_name("value")
                        .or_else(|| clause.named_child(0))
                })
        })
        .or_else(|| {
            let name = declarator.child_by_field_name("name")?;
            named_children(declarator)
                .into_iter()
                .find(|child| child.start_byte() > name.end_byte())
        })
}

/// Whether a C# `for` statement is known to enter its body before its first
/// condition check.
///
/// This deliberately proves only the ordinary counted-loop shape. Unknown
/// expressions, multiple initializers or updates, and all other loop forms
/// retain the shared zero-trip approximation.
fn csharp_for_has_first_iteration(
    source: &str,
    initializers: &[Node<'_>],
    condition: Option<Node<'_>>,
    updates: &[Node<'_>],
) -> bool {
    if initializers.len() != 1 || updates.len() != 1 {
        return false;
    }
    let (Some(initializer), Some(condition)) = (initializers.first().copied(), condition) else {
        return false;
    };
    let update = updates[0];
    if initializer.kind() != "variable_declaration"
        || condition.kind() != "binary_expression"
        || condition
            .child_by_field_name("operator")
            .is_none_or(|operator| operator.kind() != "<")
        || !is_update_expression_shape(update)
    {
        return false;
    }
    let declarators = named_children(initializer)
        .into_iter()
        .filter(|child| child.kind() == "variable_declarator")
        .collect::<Vec<_>>();
    let Some(declarator) = declarators.first().copied() else {
        return false;
    };
    if declarators.len() != 1 {
        return false;
    }
    let Some(name) = declarator.child_by_field_name("name") else {
        return false;
    };
    let Some(start) = variable_declarator_initializer(declarator)
        .and_then(|node| csharp_integer_literal_value(source, node))
    else {
        return false;
    };
    let Some(left) = condition
        .child_by_field_name("left")
        .filter(|node| node.kind() == "identifier")
    else {
        return false;
    };
    let Some(limit) = condition
        .child_by_field_name("right")
        .and_then(|node| csharp_integer_literal_value(source, node))
    else {
        return false;
    };
    let Some(incremented) = first_named_child(update).filter(|node| node.kind() == "identifier")
    else {
        return false;
    };
    node_text(source, name) == node_text(source, left)
        && node_text(source, name) == node_text(source, incremented)
        && start < limit
}

fn is_update_expression_shape(node: Node<'_>) -> bool {
    if !matches!(
        node.kind(),
        "prefix_unary_expression" | "postfix_unary_expression"
    ) {
        return false;
    }
    let operator = match node.kind() {
        "prefix_unary_expression" => node.child(0),
        "postfix_unary_expression" => node.child(node.child_count().saturating_sub(1)),
        _ => None,
    };
    operator.is_some_and(|operator| operator.kind() == "++")
}

fn csharp_integer_literal_value(source: &str, node: Node<'_>) -> Option<i64> {
    (node.kind() == "integer_literal")
        .then(|| node_text(source, node))
        .flatten()
        .and_then(|text| text.parse().ok())
}

/// The boolean value of a C# condition that bottoms out in a literal through
/// transparent parentheses or a prefix logical-not. The AST is the source of
/// truth here; every unsupported shape remains an opaque decision.
fn csharp_folded_boolean_constant(source: &str, node: Node<'_>) -> Option<bool> {
    let mut current = node;
    let mut negated = false;
    loop {
        match current.kind() {
            "parenthesized_expression" => current = first_runtime_named_child(current)?,
            "prefix_unary_expression" => {
                let operator = current.child(0)?;
                if operator.kind() != "!" {
                    return None;
                }
                current = first_named_child(current)?;
                negated = !negated;
            }
            _ => break,
        }
    }
    let value = match current.kind() {
        "boolean_literal" => match node_text(source, current)? {
            "true" => true,
            "false" => false,
            _ => return None,
        },
        _ => return None,
    };
    Some(value != negated)
}

/// The `(namespace, owner, method)` key an invocation names, when the owner is
/// spelled by a type name or implied by the enclosing type.
///
/// An unqualified call (`Relay(value)`) names a member of the type that
/// lexically encloses it, which is the same owner
/// [`record_static_callable_return_type`] indexes; before #2661 only the
/// explicitly qualified `Owner.Relay(value)` spelling produced a key, so a
/// sibling static call resolved to nothing at all.
fn static_invocation_key(invocation: Node<'_>, source: &str) -> Option<TypeMemberKey> {
    let function = invocation.child_by_field_name("function")?;
    let (owner, name_node) = match function.kind() {
        "member_access_expression" => {
            let receiver = csharp_call_receiver(function)?;
            if receiver.kind() != "identifier" {
                return None;
            }
            (
                Box::<str>::from(nonempty_node_text(source, receiver)?),
                function.child_by_field_name("name")?,
            )
        }
        "identifier" | "generic_name" => {
            let owner_node = enclosing_type_node(invocation)?;
            // The index itself only records members of top-level types, so a
            // nested owner can never match one of its keys.
            if enclosing_type_node(owner_node).is_some() {
                return None;
            }
            (declaration_container_name(source, owner_node)?, function)
        }
        _ => return None,
    };
    let member = super::csharp_member_name(name_node)?;
    if member.explicit_generic_arity.is_some() {
        return None;
    }
    Some(TypeMemberKey {
        namespace: enclosing_namespace_path(source, invocation),
        owner,
        name: Box::from(nonempty_node_text(source, member.identifier)?),
    })
}

fn receiver_name_is_lexically_shadowed(
    node: Node<'_>,
    name: &str,
    type_shadows: &TypeReceiverShadowIndex,
) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "class_declaration"
                | "interface_declaration"
                | "struct_declaration"
                | "record_declaration"
                | "record_struct_declaration"
        ) {
            let shadows = type_shadows
                .get(&parent.start_byte())
                .expect("every enclosing C# type must have receiver-shadow evidence");
            if shadows.resolution_open || shadows.names.contains(name) {
                return true;
            }
        }
        current = parent.parent();
    }
    false
}

fn callable_type_parameter_names(node: Node<'_>, source: &str) -> HashSet<Box<str>> {
    let mut names = HashSet::default();
    let mut current = Some(node);
    while let Some(candidate) = current {
        if is_callable_kind(candidate.kind())
            && let Some(parameters) = candidate.child_by_field_name("type_parameters")
        {
            for parameter in named_children(parameters) {
                if parameter.kind() == "type_parameter"
                    && let Some(name) = parameter
                        .child_by_field_name("name")
                        .and_then(|name| nonempty_node_text(source, name))
                {
                    names.insert(Box::from(name));
                }
            }
        }
        current = candidate.parent();
    }
    names
}

fn record_type_receiver_shadow(
    shadows: &mut TypeReceiverShadowIndex,
    node: Node<'_>,
    source: &str,
) {
    let shadow_name = match node.kind() {
        "variable_declarator"
            if node
                .parent()
                .and_then(|declaration| declaration.parent())
                .is_some_and(|owner| {
                    matches!(
                        owner.kind(),
                        "field_declaration" | "event_field_declaration"
                    )
                }) =>
        {
            node.child_by_field_name("name")
        }
        "property_declaration"
        | "event_declaration"
        | "class_declaration"
        | "interface_declaration"
        | "struct_declaration"
        | "record_declaration"
        | "record_struct_declaration" => node.child_by_field_name("name"),
        "type_parameter"
            if node
                .parent()
                .and_then(|parameters| parameters.parent())
                .is_some_and(|owner| declaration_container_kind(owner).is_some()) =>
        {
            node.child_by_field_name("name")
        }
        _ => None,
    };
    let enclosing_type = enclosing_type_node(node);
    if node.kind() == "base_list"
        && let Some(owner) = enclosing_type
        && let Some(evidence) = shadows.get_mut(&owner.start_byte())
    {
        evidence.resolution_open = true;
    }
    if let Some(name) = shadow_name.and_then(|name| nonempty_node_text(source, name))
        && let Some(owner) = enclosing_type
        && let Some(evidence) = shadows.get_mut(&owner.start_byte())
    {
        evidence.names.insert(Box::from(name));
    }
}

fn enclosing_type_node(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "class_declaration"
                | "interface_declaration"
                | "struct_declaration"
                | "record_declaration"
                | "record_struct_declaration"
        ) {
            return Some(parent);
        }
        current = parent.parent();
    }
    None
}

/// The declared spelling of a type node, array ranks included.
///
/// `csharp_type_node_identity` unwraps an `array_type` to its element type, so
/// `int[]` and `int` share a spelling there. That collapse is wrong for the
/// value-identity question this module asks -- assigning an `int` to an
/// `int[]` is not an identity-preserving initialization -- so the ranks are
/// restored here. `var` names no declared type at all and yields `None`.
fn declared_type_spelling(node: Node<'_>, source: &str) -> Option<Box<str>> {
    if node.kind() == "implicit_type" {
        return None;
    }
    let identity = super::csharp_type_node_identity(node, source);
    if identity.is_empty() {
        return None;
    }
    let mut ranks = String::new();
    let mut current = node;
    while current.kind() == "array_type" {
        ranks.push_str("[]");
        let Some(inner) = current.child_by_field_name("type") else {
            break;
        };
        current = inner;
    }
    Some(format!("{identity}{ranks}").into_boxed_str())
}

/// Whether an expression constructs its own value rather than naming one that
/// already exists.
///
/// Such an expression has no prior object identity for a user-defined
/// conversion to replace, so carrying it into a declared local is always an
/// identity-preserving initialization. `null` and `default` are deliberately
/// absent: both already publish their own value-identity gap, and neither can
/// carry a value worth connecting.
fn expression_constructs_its_value(kind: &str) -> bool {
    matches!(
        kind,
        "integer_literal"
            | "real_literal"
            | "string_literal"
            | "raw_string_literal"
            | "verbatim_string_literal"
            | "character_literal"
            | "boolean_literal"
            | "interpolated_string_expression"
            | "implicit_array_creation_expression"
            | "implicit_stackalloc_expression"
            | "anonymous_object_creation_expression"
            | "lambda_expression"
            | "anonymous_method_expression"
    )
}

fn is_intrinsic_object_construction(node: Node<'_>, source: &str) -> bool {
    node.kind() == "object_creation_expression"
        && call_arguments(node).is_empty()
        && object_initializer(node).is_none()
        && node.child_by_field_name("type").is_some_and(|type_node| {
            type_node.kind() == "predefined_type"
                && super::csharp_type_node_identity(type_node, source) == "object"
        })
}

fn conditional_branches_have_identity_preserving_construction(
    consequence: Node<'_>,
    alternative: Node<'_>,
    source: &str,
) -> bool {
    if consequence.kind() != "object_creation_expression"
        || alternative.kind() != "object_creation_expression"
    {
        return false;
    }
    let Some(consequence_type) = consequence.child_by_field_name("type") else {
        return false;
    };
    let Some(alternative_type) = alternative.child_by_field_name("type") else {
        return false;
    };
    let consequence_type = super::csharp_type_node_identity(consequence_type, source);
    !consequence_type.is_empty()
        && consequence_type == super::csharp_type_node_identity(alternative_type, source)
}

fn switch_section_control_nodes(section: Node<'_>) -> Vec<Node<'_>> {
    named_children(section)
        .into_iter()
        .filter(|child| !is_statement_kind(child.kind()))
        .collect()
}

fn switch_section_statements(section: Node<'_>) -> Vec<Node<'_>> {
    named_children(section)
        .into_iter()
        .filter(|child| is_statement_kind(child.kind()))
        .collect()
}

fn switch_expression_arm_value(arm: Node<'_>) -> Option<Node<'_>> {
    named_children(arm)
        .into_iter()
        .rfind(|child| child.kind() != "when_clause" && !is_pattern_syntax(child.kind()))
}

fn csharp_call_receiver(function: Node<'_>) -> Option<Node<'_>> {
    match function.kind() {
        "member_access_expression" => function.child_by_field_name("expression"),
        "conditional_access_expression"
            if conditional_access_binding(function)
                .is_some_and(|binding| binding.kind() == "member_binding_expression") =>
        {
            function.child_by_field_name("condition")
        }
        _ => None,
    }
}

fn conditional_access_binding(node: Node<'_>) -> Option<Node<'_>> {
    let condition = node.child_by_field_name("condition")?;
    named_children(node)
        .into_iter()
        .find(|child| child.id() != condition.id())
}

fn object_initializer(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("initializer").or_else(|| {
        named_children(node)
            .into_iter()
            .find(|child| child.kind() == "initializer_expression")
    })
}

fn call_arguments(node: Node<'_>) -> Vec<Node<'_>> {
    node.child_by_field_name("arguments")
        .or_else(|| {
            named_children(node)
                .into_iter()
                .find(|child| child.kind() == "argument_list")
        })
        .map(named_children)
        .unwrap_or_default()
}

fn call_argument_value(argument: Node<'_>) -> Option<Node<'_>> {
    if argument.kind() != "argument" {
        return Some(argument);
    }
    let keyword = argument.child_by_field_name("name");
    argument
        .child_by_field_name("value")
        .or_else(|| argument.child_by_field_name("expression"))
        .or_else(|| {
            named_children(argument)
                .into_iter()
                .find(|child| keyword.is_none_or(|keyword| child.id() != keyword.id()))
        })
}

#[derive(Clone, Copy)]
enum CSharpCallArgumentShape {
    Positional,
    Named,
    ByReference,
}

fn csharp_call_argument_shape(argument: Node<'_>) -> CSharpCallArgumentShape {
    if argument.kind() != "argument" {
        return CSharpCallArgumentShape::Positional;
    }
    if (0..argument.child_count()).any(|index| {
        argument
            .child(index)
            .is_some_and(|child| matches!(child.kind(), "ref" | "out" | "in"))
    }) {
        CSharpCallArgumentShape::ByReference
    } else if argument.child_by_field_name("name").is_some() {
        CSharpCallArgumentShape::Named
    } else {
        CSharpCallArgumentShape::Positional
    }
}

fn call_function_requires_evaluation(function: Node<'_>) -> bool {
    !matches!(
        function.kind(),
        "identifier"
            | "generic_name"
            | "qualified_name"
            | "alias_qualified_name"
            | "member_access_expression"
            | "conditional_access_expression"
    )
}

/// Whether an access expression is the target being written rather than a
/// value being read.
///
/// An assignment target is still scheduled as a child expression, so without
/// this a write would publish both its store and a spurious load of the very
/// location it overwrites. A compound assignment genuinely reads as well as
/// writes, but it represents neither yet, so it is excluded here too rather
/// than publishing half of the pair.
fn access_is_write_target(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        is_update_expression(parent)
            || (parent.kind() == "assignment_expression"
                && parent.child_by_field_name("left") == Some(node))
    })
}

/// Whether an access expression names the callee of an invocation.
///
/// `obj.Method()` reads no member: `Method` is a method group, and the call
/// site the invocation publishes already represents it.
fn access_is_call_target(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "invocation_expression"
            && parent.child_by_field_name("function") == Some(node)
    })
}

fn is_simple_assignment(node: Node<'_>) -> bool {
    node.child_by_field_name("operator")
        .is_some_and(|operator| operator.kind() == "=")
}

fn is_update_expression(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "prefix_unary_expression" | "postfix_unary_expression"
    ) && node
        .child_by_field_name("operator")
        .is_some_and(|operator| matches!(operator.kind(), "++" | "--"))
}

/// Whether a type spelling names one of C#'s predefined types.
///
/// These are the types no user code can extend: a program cannot declare
/// `operator +` on `int`, nor an `implicit operator int`'s counterpart that
/// would change what an `int`-typed expression denotes. That closure is what
/// makes an operation over them provably built-in (#2661).
///
/// `string` and `object` are included deliberately. Both are sealed against
/// user-defined *operators* on the type itself, and `+` over `string` is the
/// language's own concatenation.
fn csharp_predefined_type(spelling: &str) -> bool {
    matches!(
        spelling,
        "bool"
            | "byte"
            | "char"
            | "decimal"
            | "double"
            | "float"
            | "int"
            | "long"
            | "nint"
            | "nuint"
            | "object"
            | "sbyte"
            | "short"
            | "string"
            | "uint"
            | "ulong"
            | "ushort"
            | "void"
    )
}

/// Whether an expression's value is a literal of a predefined type.
fn literal_is_predefined(kind: &str) -> bool {
    matches!(
        kind,
        "integer_literal"
            | "real_literal"
            | "string_literal"
            | "raw_string_literal"
            | "verbatim_string_literal"
            | "character_literal"
            | "boolean_literal"
            | "interpolated_string_expression"
    )
}

fn may_invoke_user_code(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "assignment_expression"
            | "binary_expression"
            | "prefix_unary_expression"
            | "postfix_unary_expression"
            | "cast_expression"
            | "as_expression"
            | "is_expression"
            | "is_pattern_expression"
            | "with_expression"
    )
}

fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| !is_comment_kind(child.kind()))
        .collect()
}

fn first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| !is_comment_kind(child.kind()))
}

fn is_comment_kind(kind: &str) -> bool {
    matches!(kind, "line_comment" | "block_comment" | "comment")
}

fn required_field<'tree>(
    node: Node<'tree>,
    field: &str,
) -> Result<Node<'tree>, CSharpLoweringError> {
    node.child_by_field_name(field)
        .ok_or_else(|| missing_field(node, field))
}

fn missing_field(node: Node<'_>, field: &str) -> CSharpLoweringError {
    CSharpLoweringError::Invalid(format!(
        "{} node at bytes {}..{} is missing structured field {field}",
        node.kind(),
        node.start_byte(),
        node.end_byte()
    ))
}

fn binary_operator(node: Node<'_>) -> Option<&'static str> {
    match node.child_by_field_name("operator")?.kind() {
        "&&" => Some("&&"),
        "||" => Some("||"),
        "??" => Some("??"),
        _ => None,
    }
}

fn operation_can_throw_implicitly(node: Node<'_>) -> bool {
    match node.kind() {
        "prefix_unary_expression"
        | "postfix_unary_expression"
        | "binary_expression"
        | "cast_expression"
        | "checked_expression"
        | "array_creation_expression"
        | "implicit_array_creation_expression"
        | "stackalloc_expression"
        | "implicit_stackalloc_expression" => true,
        "assignment_expression" => node.child_by_field_name("left").is_some_and(|left| {
            matches!(
                left.kind(),
                "member_access_expression" | "element_access_expression"
            )
        }),
        _ => false,
    }
}

fn is_runtime_leaf(kind: &str) -> bool {
    matches!(
        kind,
        "identifier"
            | "integer_literal"
            | "real_literal"
            | "boolean_literal"
            | "character_literal"
            | "string_literal"
            | "verbatim_string_literal"
            | "raw_string_literal"
            | "null_literal"
            | "this"
            | "base"
            | "discard"
            | "comment"
            | "line_comment"
            | "block_comment"
    )
}

const fn completion_label(kind: CompletionKind) -> &'static str {
    match kind {
        CompletionKind::Normal => "normal",
        CompletionKind::Return => "return",
        CompletionKind::Throw => "throw",
        CompletionKind::Break => "break",
        CompletionKind::Continue => "continue",
        CompletionKind::Yield => "yield",
    }
}
