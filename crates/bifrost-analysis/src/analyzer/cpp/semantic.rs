//! C and C++ lowering into the language-neutral executable-semantics IR.
//!
//! This module deliberately interprets tree-sitter nodes and fields directly.
//! Graph construction, abrupt-completion routing, cleanup specialization, and
//! physical adjacency storage remain owned by the shared semantic substrate.

use brokk_bifrost_cpp::raii::CppTemporaryFreeCallIndex;
use tree_sitter::Node;

use crate::analyzer::lexical_definitions::formal_parameter_slots_for_owner;
use crate::analyzer::semantic::cfg::{
    CompletionKind, CompletionRequest, ProcedureCfgBuilder, ScopeBinding, ScopeFrameId,
};
use crate::analyzer::semantic::service::{ProgramSemanticsLowerer, SemanticAdapterIdentity};
use crate::analyzer::semantic::*;
use crate::analyzer::tree_sitter_analyzer::{
    PreparedSyntaxTree, WalkControl, try_walk_named_tree_preorder,
};
use crate::analyzer::{CppAnalyzer, Language, ProjectFile};
use crate::hash::{HashMap, HashSet};

const ADAPTER_VERSION: &[u8] = b"cpp-cfg-values-v7";

impl_program_semantics_provider!(CppAnalyzer, CppSemanticLowerer);

struct CppSemanticLowerer;

impl ProgramSemanticsLowerer for CppSemanticLowerer {
    fn identity(&self) -> SemanticAdapterIdentity {
        SemanticAdapterIdentity {
            adapter: AdapterSemanticsVersion::hash_bytes("cpp", ADAPTER_VERSION)
                .expect("adapter name is non-empty"),
            configuration: ConfigurationFingerprint::hash_bytes(
                b"cpp-intrafile-execution-defaults-v1",
            ),
            dependencies: DependencyFingerprint::hash_bytes(b"no-intrafile-dependencies"),
        }
    }

    fn capabilities(&self) -> SemanticCapabilities {
        cpp_capabilities()
    }

    fn lower(
        &self,
        file: &ProjectFile,
        prepared: &PreparedSyntaxTree,
        budget: &SemanticBudget,
        cancellation: &CancellationToken,
    ) -> Result<SemanticOutcome<Vec<ProcedureSemanticsParts>>, SemanticProviderError> {
        let (inventory, initial_work) =
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
            member_declarations,
            trivial_types,
        } = inventory;
        lower_procedure_batch(
            &specs,
            initial_work,
            budget,
            cancellation,
            |spec, staged_budget, cancellation| {
                lower_procedure(
                    prepared,
                    spec,
                    &member_declarations,
                    &trivial_types,
                    staged_budget,
                    cancellation,
                )
            },
        )
    }
}

fn cpp_capabilities() -> SemanticCapabilities {
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
        SemanticCapability::Assignments,
        SemanticCapability::Allocations,
        SemanticCapability::Calls,
        SemanticCapability::DynamicDispatch,
        SemanticCapability::Captures,
        SemanticCapability::CallableReferences,
        SemanticCapability::Values,
        SemanticCapability::LocalFlow,
        SemanticCapability::ParameterFlow,
        SemanticCapability::ReceiverFlow,
        // Partial, not complete: a write or read through a member, element, or
        // static target becomes a `MemoryStore`/`MemoryLoad` against a
        // structured location, but whether that location is the *declared*
        // member is only known when this file can resolve the base's type, and
        // an element is only addressed when the subscript is constant and the
        // base is provably an array. Every other occurrence publishes its own
        // location-subject gap (#2666, #2665).
        SemanticCapability::FieldMemory,
        SemanticCapability::StaticMemory,
        SemanticCapability::IndexMemory,
        SemanticCapability::NonLocalControl,
        SemanticCapability::ResourceManagement,
        SemanticCapability::DeferredExecution,
        SemanticCapability::ConcurrentSpawn,
        SemanticCapability::AsyncSuspendResume,
        SemanticCapability::GeneratorSuspension,
        // Partial: every decision this adapter's condition lowering reaches
        // publishes a row, and a literal constant condition publishes the
        // constant it folded on. Comparisons, null tests, and every other
        // condition are recorded `Opaque` rather than normalized (#2443).
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
    callable: Node<'tree>,
    locator: SemanticLocator,
    lexical_parent: Option<ProcedureId>,
    kind: ProcedureKind,
    properties: ProcedureProperties,
    has_implicit_object_context: bool,
    has_raii_boundaries: bool,
    has_vla_boundaries: bool,
    has_preprocessing: bool,
    has_syntax_errors: bool,
    noexcept: NoexceptSpecification,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoexceptSpecification {
    MayThrow,
    Unconditional,
    Conditional,
}

/// One data member of a class, struct, or union, as the enumeration pass sees
/// it.
///
/// `anchor` is the *declaration's* own source anchor, which is what makes two
/// occurrences of the same member -- a store in one statement and a load in
/// another -- agree on one [`MemoryLocationKind::Field`] identity instead of
/// each minting a location that only looks like the other.
#[derive(Debug, Clone)]
struct MemberDeclaration {
    anchor: SourceAnchor,
    /// A `static` data member is one class-wide slot addressed by nothing, so
    /// it is a [`MemoryLocationKind::Static`] rather than a field of a base.
    is_static: bool,
    /// Whether writing the member is the very object the written expression
    /// denotes: a pointer or reference member, or a member of fundamental
    /// type. Combined with `is_c_source` at the use site, this is the member's
    /// half of the same question [`cpp_identity_is_preserved`] asks of a local.
    identity_preserved: bool,
    /// The member's own declared type name, when it names one. This is what
    /// lets `a.b.c` find the type that declares `c` from the declaration of
    /// `b`, instead of stopping at the first hop.
    type_name: Option<Box<str>>,
}

/// Data members declared in this file, keyed by owning type and member name.
///
/// A `None` value records a name that more than one declaration in this file
/// claims. Such a name resolves to no single anchor, so an occurrence of it
/// declines rather than picking one arbitrarily.
type MemberDeclarations = HashMap<TypeMemberKey, Option<MemberDeclaration>>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TypeMemberKey {
    /// The enclosing namespace path, outermost first, so a `Holder` in two
    /// namespaces of one file stays two types.
    namespace: Box<[Box<str>]>,
    owner: Box<str>,
    name: Box<str>,
}

/// The class, struct, and union names this file declares whose construction
/// and destruction provably run no user code.
///
/// A C++ automatic object of such a type opens no RAII boundary: there is no
/// destructor to run at scope exit and no constructor or conversion function
/// to run at initialization, so the cleanup, lifetime-call, and unwinding
/// declines those boundaries publish would be claims about code that does not
/// exist. Because those declines carry value, heap, and aliasing impact, an
/// unqualified "this scope has an automatic object" made every C++ procedure
/// holding a plain aggregate unprovable (#2666).
///
/// The proof is deliberately narrow and purely structural. A name qualifies
/// only when every declaration of it in this file is a class body that
///
/// - has no base-class clause,
/// - declares nothing but data members and access specifiers, so no
///   constructor, destructor, assignment operator, or virtual function,
/// - gives no member a default member initializer, and
/// - gives every member a type that is fundamental, a pointer or reference, or
///   another name proved trivial the same way.
///
/// Anything this file cannot see -- a type from a header, a template
/// parameter, a name declared twice -- is absent from the set, and its objects
/// keep every boundary they had.
#[derive(Debug, Default)]
struct TrivialTypeIndex {
    names: HashSet<Box<str>>,
}

impl TrivialTypeIndex {
    /// Build the index by fixpoint over the file's class bodies.
    ///
    /// The dependency `Middle { Leaf c; }` is resolved by iterating: each pass
    /// admits the candidates all of whose member types are already admitted,
    /// and the loop stops when a pass admits nothing new. At most one name is
    /// admitted per pass, so the iteration is bounded by the candidate count.
    fn build(source: &str, root: Node<'_>) -> Self {
        // name -> member type names it depends on; `None` once a second,
        // conflicting declaration of the name is seen.
        let mut candidates: HashMap<Box<str>, Option<Vec<Box<str>>>> = HashMap::default();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            stack.extend(named_children(node));
            if !matches!(
                node.kind(),
                "struct_specifier" | "class_specifier" | "union_specifier"
            ) {
                continue;
            }
            let Some(name) = node
                .child_by_field_name("name")
                .and_then(|name| nonempty_node_text(source, name))
            else {
                continue;
            };
            let dependencies = trivial_body_dependencies(source, node);
            match candidates.entry(Box::from(name)) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(dependencies);
                }
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    // A forward declaration carries no body and no members, so
                    // it neither proves nor disproves anything; a second body
                    // for one name is an ambiguity this file cannot settle.
                    if node.child_by_field_name("body").is_some() {
                        entry.insert(None);
                    }
                }
            }
        }
        let mut names: HashSet<Box<str>> = HashSet::default();
        loop {
            let mut admitted = false;
            for (name, dependencies) in &candidates {
                if names.contains(name) {
                    continue;
                }
                let Some(dependencies) = dependencies else {
                    continue;
                };
                if dependencies
                    .iter()
                    .all(|dependency| names.contains(dependency))
                {
                    names.insert(name.clone());
                    admitted = true;
                }
            }
            if !admitted {
                break;
            }
        }
        Self { names }
    }

    fn contains(&self, name: &str) -> bool {
        self.names.contains(name)
    }

    /// Whether every object `declaration` declares is of a proved-trivial
    /// type, so its construction and destruction run no user code.
    fn declaration_is_trivial(&self, source: &str, declaration: Node<'_>) -> bool {
        declared_type_name(source, declaration)
            .is_some_and(|name| self.contains(&name))
            // A declarator that introduces a function is not an object at all,
            // and the `type` field then names the return type.
            && !cpp_declaration_is_function(declaration)
    }
}

/// The member type names a class body depends on for triviality, or `None`
/// when the body itself disqualifies it.
fn trivial_body_dependencies(source: &str, specifier: Node<'_>) -> Option<Vec<Box<str>>> {
    let body = specifier.child_by_field_name("body")?;
    if named_children(specifier)
        .into_iter()
        .any(|child| child.kind() == "base_class_clause")
    {
        return None;
    }
    let mut dependencies = Vec::new();
    for member in named_children(body) {
        match member.kind() {
            "access_specifier" | "comment" => continue,
            "field_declaration" => {}
            // A member function, a nested definition, a using declaration, a
            // friend, or a template is beyond what this proof inspects.
            _ => return None,
        }
        if cpp_declaration_is_function(member) {
            return None;
        }
        // A default member initializer is an expression that runs on
        // construction.
        if member.child_by_field_name("default_value").is_some() {
            return None;
        }
        let declarators = cpp_local_declarators(member);
        if declarators.is_empty() {
            return None;
        }
        let type_node = member.child_by_field_name("type")?;
        for declarator in declarators {
            if cpp_declarator_initializer(member, declarator).is_some() {
                return None;
            }
            // A pointer or reference member holds an address; destroying it
            // runs nothing whatever it points at.
            if cpp_declarator_preserves_identity(declarator) {
                continue;
            }
            if cpp_type_is_fundamental(type_node) {
                continue;
            }
            let name = declared_type_name(source, member)?;
            dependencies.push(name);
        }
    }
    Some(dependencies)
}

struct ProcedureInventory<'tree> {
    specs: Vec<ProcedureSpec<'tree>>,
    member_declarations: MemberDeclarations,
    trivial_types: TrivialTypeIndex,
}

type ProcedureEnumeration<'tree> = ProcedureInventoryOutcome<ProcedureInventory<'tree>>;

struct ProcedureEnumerationFrame<'tree> {
    node: Node<'tree>,
    lexical_parent: Option<ProcedureId>,
    declaration_path: usize,
    member_context: bool,
}

#[derive(Default)]
struct CallablePreflight {
    work: SemanticWork,
    has_raii_boundaries: bool,
    has_vla_boundaries: bool,
    has_preprocessing: bool,
    has_syntax_errors: bool,
    is_async: bool,
    is_generator: bool,
}

enum CallablePreflightStop {
    ExceededBudget {
        exceeded: SemanticBudgetExceeded,
        work: Box<SemanticWork>,
    },
    Cancelled {
        work: Box<SemanticWork>,
    },
}

fn enumerate_procedures<'tree>(
    file: &ProjectFile,
    prepared: &'tree PreparedSyntaxTree,
    budget: &SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<ProcedureEnumeration<'tree>, SemanticProviderError> {
    let is_c_source = file
        .rel_path()
        .extension()
        .and_then(|extension| extension.to_str())
        == Some("c");
    let root = prepared.tree().root_node();
    let mut inventory =
        ProcedureInventoryBuilder::new(file, prepared.dialect(), root, "cpp-source", budget)?;
    // The per-file proof that an exact local free-function call cannot
    // materialize a destructible temporary (#1984). C never opens RAII
    // boundaries, so only C++ pays for the extra walk.
    let temporary_free_calls =
        (!is_c_source).then(|| CppTemporaryFreeCallIndex::build(prepared.source(), root));
    if let Some(index) = &temporary_free_calls
        && let Err(stop) = inventory.observe_additional_work(SemanticWork {
            nested_entries: index.visited_nodes(),
            ..SemanticWork::default()
        })
    {
        return Ok(stop.into_outcome());
    }
    // Built before the enumeration walk, because a callable's RAII preflight
    // asks about a type that may be declared later in the file.
    let trivial_types = if is_c_source {
        TrivialTypeIndex::default()
    } else {
        TrivialTypeIndex::build(prepared.source(), root)
    };
    let mut specs: Vec<ProcedureSpec<'tree>> = Vec::new();
    let mut member_declarations = MemberDeclarations::default();
    let mut stack = vec![ProcedureEnumerationFrame {
        node: root,
        lexical_parent: None,
        declaration_path: inventory.root_path(),
        member_context: false,
    }];

    while let Some(frame) = stack.pop() {
        if cancellation.is_cancelled() {
            return Ok(inventory.cancelled());
        }

        // Enumeration itself is an iterative AST walk with one retained stack
        // entry per pending node. Bound that work even in files that contain no
        // callable declarations, instead of charging only when a procedure is
        // eventually discovered.
        if let Err(stop) = inventory.charge_traversal_entry() {
            return Ok(stop.into_outcome());
        }

        record_member_declarations(
            &mut member_declarations,
            frame.node,
            prepared.source(),
            is_c_source,
        );

        let mut child_path = frame.declaration_path;
        let mut child_member_context = frame.member_context;
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
            child_member_context = segment_kind == DeclarationSegmentKind::Type;
        }

        let shape = callable_shape(
            prepared.source(),
            frame.node,
            frame.lexical_parent,
            frame.member_context,
        )
        .or_else(|| {
            let synthetic_initializer = executable_initializer(frame.node)
                || (!is_c_source
                    && !frame.member_context
                    && declaration_may_construct_object(frame.node));
            (frame.lexical_parent.is_none() && synthetic_initializer).then(|| {
                (
                    ProcedureKind::Initializer,
                    DeclarationSegmentKind::Initializer,
                    frame.node,
                    ProcedureProperties {
                        is_static: !frame.member_context
                            || has_storage_class(prepared.source(), frame.node, "static"),
                        is_synthetic: true,
                        ..ProcedureProperties::default()
                    },
                )
            })
        });

        let mut callable_body_scope = None;
        if let Some((kind, segment_kind, body, mut properties)) = shape {
            let scan = match callable_preflight(
                frame.node,
                prepared.source(),
                &trivial_types,
                temporary_free_calls.as_ref(),
                budget,
                inventory.observed_work(),
                cancellation,
            ) {
                Ok(scan) => scan,
                Err(CallablePreflightStop::ExceededBudget { exceeded, work }) => {
                    return Ok(ProcedureEnumeration::ExceededBudget {
                        exceeded,
                        work: *work,
                    });
                }
                Err(CallablePreflightStop::Cancelled { work }) => {
                    return Ok(ProcedureEnumeration::Cancelled { work: *work });
                }
            };
            if let Err(stop) = inventory.observe_additional_work(scan.work) {
                return Ok(stop.into_outcome());
            }
            properties.is_async = scan.is_async;
            properties.is_generator = scan.is_generator;
            properties.invocation = if scan.is_async || scan.is_generator {
                ProcedureInvocationKind::Deferred
            } else {
                ProcedureInvocationKind::Immediate
            };
            let parent_has_implicit_object_context = frame
                .lexical_parent
                .and_then(|parent| specs.get(parent.index()))
                .is_some_and(|parent| parent.has_implicit_object_context);
            let qualified_callable = frame
                .node
                .child_by_field_name("declarator")
                .and_then(qualified_declarator)
                .is_some();
            let has_implicit_object_context = !properties.is_static
                && match kind {
                    ProcedureKind::Method | ProcedureKind::Constructor => true,
                    ProcedureKind::Operator => frame.member_context || qualified_callable,
                    ProcedureKind::Initializer => frame.member_context,
                    ProcedureKind::Lambda => parent_has_implicit_object_context,
                    _ => false,
                };
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
            specs.push(ProcedureSpec {
                id: identity.id,
                body,
                callable: frame.node,
                locator: identity.locator,
                lexical_parent: frame.lexical_parent,
                kind,
                properties,
                has_implicit_object_context,
                has_raii_boundaries: scan.has_raii_boundaries,
                has_vla_boundaries: scan.has_vla_boundaries,
                has_preprocessing: scan.has_preprocessing || has_preprocessing_ancestor(frame.node),
                has_syntax_errors: scan.has_syntax_errors,
                noexcept: noexcept_specification(frame.node),
            });
            let direct_body = (body.id() != frame.node.id()).then_some(body.id());
            callable_body_scope = Some((direct_body, identity.id, identity.declaration_path));
        }

        let children = named_children(frame.node);
        for child in children.into_iter().rev() {
            let callable_child = callable_body_scope
                .filter(|(body_id, _, _)| body_id.is_none_or(|body_id| body_id == child.id()));
            let (lexical_parent, declaration_path) = callable_child
                .map(|(_, procedure, path)| (Some(procedure), path))
                .unwrap_or((frame.lexical_parent, child_path));
            stack.push(ProcedureEnumerationFrame {
                node: child,
                lexical_parent,
                declaration_path,
                member_context: if callable_child.is_some() {
                    false
                } else {
                    child_member_context
                },
            });
        }
    }

    Ok(inventory.complete(ProcedureInventory {
        specs,
        member_declarations,
        trivial_types,
    }))
}

/// Index one node's data-member declarations, if it declares any.
///
/// A member of a nested type is indexed like any other. The key carries only
/// the innermost type name, so a nested `Inner` and a top-level `Inner` in the
/// same namespace share one key -- and the duplicate collapse below turns that
/// into a decline, which is the honest answer.
fn record_member_declarations(
    members: &mut MemberDeclarations,
    node: Node<'_>,
    source: &str,
    is_c_source: bool,
) {
    if node.kind() != "field_declaration" {
        return;
    }
    // A member function declaration is not storage.
    if cpp_declaration_is_function(node) {
        return;
    }
    let Some(owner_node) = enclosing_member_owner(node) else {
        return;
    };
    let Some(owner) = declaration_container_name(source, owner_node) else {
        return;
    };
    let is_static = has_storage_class(source, node, "static");
    let namespace = enclosing_namespace_path(source, node);
    for declarator in cpp_local_declarators(node) {
        let Some(name_node) = declarator_name_node(declarator) else {
            continue;
        };
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
        let declaration = MemberDeclaration {
            anchor,
            type_name: declared_type_name(source, node),
            is_static,
            identity_preserved: is_c_source
                || cpp_declarator_preserves_identity(declarator)
                || (!cpp_declarator_contains_kind(declarator, "array_declarator")
                    && node
                        .child_by_field_name("type")
                        .is_some_and(cpp_type_is_fundamental)),
        };
        match members.entry(key) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(Some(declaration));
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                entry.insert(None);
            }
        }
    }
}

/// The class, struct, or union declaration a member declaration belongs to.
fn enclosing_member_owner(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "struct_specifier" | "class_specifier" | "union_specifier"
        ) {
            return Some(parent);
        }
        if parent.kind() == "function_definition" {
            return None;
        }
        current = parent.parent();
    }
    None
}

/// The type a declaration's `type` field names, when it names one by name.
///
/// Read from the AST's own `type` field and the specifier's `name` field. A
/// spelled-out type that is not a named one -- a primitive, a `decltype`, an
/// `auto` placeholder -- has no member owner and yields `None`.
fn declared_type_name(source: &str, declaration: Node<'_>) -> Option<Box<str>> {
    let type_node = declaration.child_by_field_name("type")?;
    let name_node = match type_node.kind() {
        "struct_specifier" | "class_specifier" | "union_specifier" | "enum_specifier" => {
            type_node.child_by_field_name("name")?
        }
        "type_identifier" => type_node,
        "qualified_identifier" => last_named_field_child(type_node, "name")?,
        "template_type" => type_node.child_by_field_name("name")?,
        _ => return None,
    };
    // A qualified or template name resolves to its innermost identifier, which
    // is the spelling the member index is keyed by.
    let name_node = match name_node.kind() {
        "qualified_identifier" => last_named_field_child(name_node, "name")?,
        _ => name_node,
    };
    nonempty_node_text(source, name_node).map(Box::from)
}

/// The class, struct, or union definition a node lexically sits inside.
fn enclosing_type_node(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "struct_specifier" | "class_specifier" | "union_specifier"
        ) {
            return Some(parent);
        }
        current = parent.parent();
    }
    None
}

/// The single named parameter a catch clause binds, if it has one.
///
/// `catch (...)` binds nothing, and a handler that names a type without a
/// declarator binds nothing either.
fn catch_clause_parameter<'tree>(catch: Node<'tree>) -> Option<Node<'tree>> {
    let parameters = catch.child_by_field_name("parameters")?;
    match named_children(parameters).as_slice() {
        [only] if only.kind() == "parameter_declaration" => Some(*only),
        _ => None,
    }
}

/// The enclosing `namespace` names, outermost first.
fn enclosing_namespace_path(source: &str, node: Node<'_>) -> Box<[Box<str>]> {
    let mut path = Vec::new();
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "namespace_definition"
            && let Some(name) = parent
                .child_by_field_name("name")
                .and_then(|name| nonempty_node_text(source, name))
        {
            path.push(Box::<str>::from(name));
        }
        current = parent.parent();
    }
    path.reverse();
    path.into_boxed_slice()
}

fn callable_preflight(
    root: Node<'_>,
    source: &str,
    trivial_types: &TrivialTypeIndex,
    // `Some` for C++ sources; `None` for C, which never opens RAII boundaries.
    temporary_free_calls: Option<&CppTemporaryFreeCallIndex<'_>>,
    budget: &SemanticBudget,
    observed: SemanticWork,
    cancellation: &CancellationToken,
) -> Result<CallablePreflight, CallablePreflightStop> {
    let is_c_source = temporary_free_calls.is_none();
    let mut result = CallablePreflight {
        has_raii_boundaries: !is_c_source
            && callable_name_node(root).is_some_and(|name| name.kind() == "destructor_name"),
        ..CallablePreflight::default()
    };
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if cancellation.is_cancelled() {
            return Err(CallablePreflightStop::Cancelled {
                work: Box::new(sum_lowering_work(observed, result.work)),
            });
        }
        let candidate = sum_lowering_work(
            result.work,
            SemanticWork {
                nested_entries: 1,
                ..SemanticWork::default()
            },
        );
        let total = sum_lowering_work(observed, candidate);
        if let Err(exceeded) = budget.check(total) {
            return Err(CallablePreflightStop::ExceededBudget {
                exceeded,
                work: Box::new(total),
            });
        }
        result.work = candidate;

        if node.id() != root.id()
            && matches!(node.kind(), "function_definition" | "lambda_expression")
        {
            continue;
        }
        result.has_preprocessing |= node.kind().starts_with("preproc_");
        result.has_syntax_errors |= node.kind() == "ERROR";
        result.is_async |= matches!(
            node.kind(),
            "co_await_expression" | "co_return_statement" | "co_yield_statement"
        );
        result.is_generator |= node.kind() == "co_yield_statement";
        if is_c_source
            && matches!(
                node.kind(),
                "declaration" | "field_declaration" | "parameter_declaration"
            )
            && declarator_bound_expressions(node)
                .into_iter()
                .any(|bound| !matches!(bound.kind(), "number_literal" | "char_literal"))
        {
            result.has_vla_boundaries = true;
        }
        if let Some(index) = temporary_free_calls {
            // A call expression can materialize a class-typed temporary that
            // is destroyed at the end of the full expression, unless the
            // per-file index proves this exact call temporary-free (#1984).
            result.has_raii_boundaries |= (declaration_may_construct_object(node)
                && !trivial_types.declaration_is_trivial(source, node))
                || matches!(
                    node.kind(),
                    "new_expression" | "compound_literal_expression"
                )
                || (node.kind() == "call_expression"
                    && !index.call_is_provably_temporary_free(node));
        }
        stack.extend(named_children(node));
    }
    Ok(result)
}

fn declaration_container_kind(node: Node<'_>) -> Option<DeclarationSegmentKind> {
    match node.kind() {
        "namespace_definition" => Some(DeclarationSegmentKind::Namespace),
        "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier" => {
            Some(DeclarationSegmentKind::Type)
        }
        _ => None,
    }
}

fn declaration_container_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    node.child_by_field_name("name")
        .and_then(|name| nonempty_node_text(source, name))
        .map(Box::<str>::from)
}

fn callable_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    match node.kind() {
        "function_definition" => node
            .child_by_field_name("declarator")
            .and_then(declarator_name_node)
            .and_then(|name| nonempty_node_text(source, name))
            .map(Box::<str>::from),
        "lambda_expression" => enclosing_initializer_name(source, node),
        "declaration" | "field_declaration" => initializer_declarator(node)
            .and_then(declarator_name_node)
            .and_then(|name| nonempty_node_text(source, name))
            .map(Box::<str>::from)
            .map(|name| format!("<initializer:{name}>").into_boxed_str()),
        _ => None,
    }
}

fn enclosing_initializer_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    let mut value = node;
    loop {
        let parent = value.parent()?;
        match parent.kind() {
            "parenthesized_expression" => value = parent,
            "init_declarator" if field_matches(parent, "value", value) => {
                return parent
                    .child_by_field_name("declarator")
                    .and_then(declarator_name_node)
                    .and_then(|name| nonempty_node_text(source, name))
                    .map(Box::<str>::from);
            }
            "assignment_expression" if field_matches(parent, "right", value) => {
                return parent
                    .child_by_field_name("left")
                    .and_then(declarator_name_node)
                    .and_then(|name| nonempty_node_text(source, name))
                    .map(Box::<str>::from);
            }
            _ => return None,
        }
    }
}

fn callable_shape<'tree>(
    source: &str,
    node: Node<'tree>,
    lexical_parent: Option<ProcedureId>,
    member_context: bool,
) -> Option<(
    ProcedureKind,
    DeclarationSegmentKind,
    Node<'tree>,
    ProcedureProperties,
)> {
    match node.kind() {
        "function_definition" => {
            node.child_by_field_name("body")?;
            let kind = function_kind(source, node, lexical_parent, member_context);
            let segment_kind = match kind {
                ProcedureKind::Constructor => DeclarationSegmentKind::Constructor,
                ProcedureKind::Method | ProcedureKind::Operator => DeclarationSegmentKind::Method,
                ProcedureKind::LocalFunction => DeclarationSegmentKind::LocalFunction,
                _ => DeclarationSegmentKind::Function,
            };
            Some((
                kind,
                segment_kind,
                // Include constructor initializer lists and function-try-block structure.
                node,
                ProcedureProperties {
                    is_static: has_storage_class(source, node, "static"),
                    is_synthetic: false,
                    ..ProcedureProperties::default()
                },
            ))
        }
        "lambda_expression" => {
            let body = node.child_by_field_name("body")?;
            Some((
                ProcedureKind::Lambda,
                DeclarationSegmentKind::Lambda,
                body,
                ProcedureProperties {
                    is_static: false,
                    is_synthetic: false,
                    ..ProcedureProperties::default()
                },
            ))
        }
        _ => None,
    }
}

fn noexcept_specification(callable: Node<'_>) -> NoexceptSpecification {
    let mut declarator = callable.child_by_field_name("declarator");
    while let Some(node) = declarator {
        if let Some(specification) = named_children(node)
            .into_iter()
            .find(|child| child.kind() == "noexcept")
        {
            let Some(condition) = first_named_child(specification) else {
                return NoexceptSpecification::Unconditional;
            };
            return match condition.kind() {
                "true" => NoexceptSpecification::Unconditional,
                "false" => NoexceptSpecification::MayThrow,
                _ => NoexceptSpecification::Conditional,
            };
        }
        declarator = node.child_by_field_name("declarator");
    }
    NoexceptSpecification::MayThrow
}

fn function_kind(
    source: &str,
    node: Node<'_>,
    lexical_parent: Option<ProcedureId>,
    member_context: bool,
) -> ProcedureKind {
    let declarator = node.child_by_field_name("declarator");
    let name = declarator.and_then(declarator_name_node);
    if name.is_some_and(|name| matches!(name.kind(), "operator_name" | "operator_cast")) {
        return ProcedureKind::Operator;
    }
    if name.is_some_and(|name| name.kind() == "destructor_name") {
        return ProcedureKind::Method;
    }
    let scoped_member = declarator.and_then(qualified_declarator).is_some();
    if member_context || scoped_member {
        if node.child_by_field_name("type").is_none()
            && constructor_name_matches_scope(source, declarator)
        {
            ProcedureKind::Constructor
        } else {
            ProcedureKind::Method
        }
    } else if lexical_parent.is_some() {
        ProcedureKind::LocalFunction
    } else {
        ProcedureKind::Function
    }
}

fn constructor_name_matches_scope(source: &str, declarator: Option<Node<'_>>) -> bool {
    let Some(qualified) = declarator.and_then(qualified_declarator) else {
        // In-class functions without a return type are constructors.
        return true;
    };
    let scope = qualified
        .child_by_field_name("scope")
        .and_then(declarator_name_node);
    let name = qualified
        .child_by_field_name("name")
        .and_then(declarator_name_node);
    match (scope, name) {
        (Some(scope), Some(name)) => node_text(source, scope) == node_text(source, name),
        _ => false,
    }
}

fn qualified_declarator(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        match node.kind() {
            "qualified_identifier" => return Some(node),
            "function_declarator"
            | "pointer_declarator"
            | "array_declarator"
            | "init_declarator"
            | "attributed_declarator" => node = node.child_by_field_name("declarator")?,
            "reference_declarator" | "parenthesized_declarator" => {
                node = first_named_child(node)?;
            }
            _ => return None,
        }
    }
}

fn declarator_name_node(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        match node.kind() {
            "identifier"
            | "field_identifier"
            | "namespace_identifier"
            | "type_identifier"
            | "destructor_name"
            | "operator_name"
            | "operator_cast"
            | "primitive_type" => return Some(node),
            "qualified_identifier" => {
                node = last_named_field_child(node, "name")?;
            }
            "dependent_name" | "template_function" | "template_method" | "template_type" => {
                node = node.child_by_field_name("name")?;
            }
            "function_declarator"
            | "pointer_declarator"
            | "array_declarator"
            | "init_declarator"
            | "attributed_declarator" => node = node.child_by_field_name("declarator")?,
            "reference_declarator" | "parenthesized_declarator" => {
                node = first_named_child(node)?;
            }
            _ => return None,
        }
    }
}

fn last_named_field_child<'tree>(node: Node<'tree>, field: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.children_by_field_name(field, &mut cursor)
        .filter(|child| child.is_named())
        .last()
}

fn initializer_declarator(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("declarator")
        .and_then(|declarator| {
            if declarator.kind() == "init_declarator" {
                declarator.child_by_field_name("declarator")
            } else {
                Some(declarator)
            }
        })
}

fn executable_initializer(node: Node<'_>) -> bool {
    matches!(node.kind(), "declaration" | "field_declaration")
        && !initializer_values(node).is_empty()
}

fn has_storage_class(source: &str, node: Node<'_>, expected: &str) -> bool {
    named_children(node).into_iter().any(|child| {
        child.kind() == "storage_class_specifier"
            && node_text(source, child).is_some_and(|text| text == expected)
    })
}

fn has_preprocessing_ancestor(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if parent.kind().starts_with("preproc_") {
            return true;
        }
        node = parent;
    }
    false
}

fn field_matches(parent: Node<'_>, field: &str, child: Node<'_>) -> bool {
    parent
        .child_by_field_name(field)
        .is_some_and(|candidate| candidate.id() == child.id())
}

type CppLoweringError = ProcedureLoweringError;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct GapFact {
    point: ProgramPointId,
    subject: SemanticGapSubject,
    capability: SemanticCapability,
}

struct LoweringContext<'tree, 'targets> {
    source: &'tree str,
    session: ProcedureLoweringSession<'targets>,
    expression_values: HashMap<usize, ValueId>,
    parameters: HashMap<Box<str>, ValueId>,
    locals: HashMap<Box<str>, Vec<LocalBinding>>,
    identity_bindings: HashSet<ValueId>,
    /// Bindings whose declared type is fundamental, so every built-in operator
    /// written over them is the built-in operator (`cpp_binding_is_fundamental`).
    fundamental_bindings: HashSet<ValueId>,
    /// Data members declared anywhere in this file, so a store and a load of
    /// one member anchor to that member's declaration rather than to
    /// themselves (#2666).
    member_declarations: &'targets MemberDeclarations,
    /// Class names this file proves trivially constructible and destructible,
    /// so an automatic object of one opens no RAII boundary.
    trivial_types: &'targets TrivialTypeIndex,
    /// Bindings declared with a pointer declarator, whose `->` is the built-in
    /// indirection operator rather than a user-defined `operator->`.
    pointer_bindings: HashSet<ValueId>,
    /// Bindings declared with an array declarator. Subscripting one is the
    /// built-in subscript operator addressing that array's storage, which is
    /// what `operator[]` on a class type is not.
    array_bindings: HashSet<ValueId>,
    /// Bindings whose declared base type is fundamental, whatever the
    /// declarator wraps it in. This answers the identity question for an
    /// element write, whose target type is the array's element type.
    fundamental_storage_bindings: HashSet<ValueId>,
    /// The declared type name of a bound object, when its declaration named a
    /// type by name. This is what lets `holder.tainted` find the `Holder`
    /// declaration that owns `tainted`.
    binding_type_names: HashMap<ValueId, Box<str>>,
    /// One value per distinct constant subscript spelling in this procedure.
    ///
    /// An element location is identified by its base and index *values*, so
    /// two occurrences of `values[0]` must share one index value or they
    /// address two different elements. Java and C# canonicalize the same way.
    constant_index_values: HashMap<Box<str>, ValueId>,
    receiver: Option<ValueId>,
    is_c_source: bool,
    return_transfer_is_exact: bool,
    labels: HashMap<Box<str>, ProgramPointId>,
    switch_case_entries: HashMap<usize, ProgramPointId>,
    published_gaps: HashSet<GapFact>,
    root_body_id: usize,
    is_synthetic_procedure: bool,
    has_implicit_object_context: bool,
    raii_possible: bool,
    vla_possible: bool,
}

/// One structured heap location an access expression names, together with what
/// this file could establish about which declaration it addresses.
#[derive(Debug, Clone, Copy)]
struct MemoryTarget {
    location: MemoryLocationId,
    kind: MemoryAccessKind,
    identity: MemoryIdentity,
}

/// Why a structured access does or does not name a known declaration.
///
/// The two failing answers are different in kind, and the distinction is what a
/// consumer sees. `UserDefinedAccessor` is a decision: a C++ class-typed base
/// resolves its subscript through an `operator[]` this adapter does not lower,
/// and no amount of information about this program changes that. `Unresolved`
/// is missing information: the occurrence is well formed and the declaration
/// simply was not found here (#2666).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemoryIdentity {
    Resolved,
    UserDefinedAccessor,
    Unresolved,
}

#[derive(Debug, Clone, Copy)]
struct LocalBinding {
    declaration_start: usize,
    visible_from: usize,
    scope_start: usize,
    scope_end: usize,
    value: ValueId,
}

fn lower_procedure<'tree, 'targets>(
    prepared: &'tree PreparedSyntaxTree,
    spec: &ProcedureSpec<'tree>,
    member_declarations: &'targets MemberDeclarations,
    trivial_types: &'targets TrivialTypeIndex,
    budget: &'targets SemanticBudget,
    cancellation: &'targets CancellationToken,
) -> Result<(ProcedureSemanticsParts, SemanticWork), CppLoweringError> {
    let is_c_source = locator_is_c_source(&spec.locator);
    let mut parts = ProcedureSemanticsParts::new(
        spec.id,
        spec.locator.clone(),
        spec.kind,
        SourceMappingId::new(0),
        EvidenceId::new(0),
    );
    parts.lexical_parent = spec.lexical_parent;
    parts.properties = spec.properties;
    let (
        ProcedureLoweringStart {
            mut builder,
            session,
            entry,
            normal_exit,
            exceptional_exit,
            function_scope,
        },
        noexcept_termination,
    ) = ProcedureLoweringSession::start_with_function_throw_boundary(
        parts,
        budget,
        cancellation,
        spec.noexcept == NoexceptSpecification::Unconditional,
    )?;
    let mut context = LoweringContext {
        source: prepared.source(),
        session,
        expression_values: HashMap::default(),
        parameters: HashMap::default(),
        locals: HashMap::default(),
        identity_bindings: HashSet::default(),
        fundamental_bindings: HashSet::default(),
        member_declarations,
        trivial_types,
        pointer_bindings: HashSet::default(),
        array_bindings: HashSet::default(),
        fundamental_storage_bindings: HashSet::default(),
        binding_type_names: HashMap::default(),
        constant_index_values: HashMap::default(),
        receiver: None,
        is_c_source,
        return_transfer_is_exact: cpp_callable_return_transfer_is_exact(spec.callable, is_c_source),
        labels: HashMap::default(),
        switch_case_entries: HashMap::default(),
        published_gaps: HashSet::default(),
        root_body_id: spec
            .body
            .child_by_field_name("body")
            .unwrap_or(spec.body)
            .id(),
        is_synthetic_procedure: spec.properties.is_synthetic,
        has_implicit_object_context: spec.has_implicit_object_context,
        raii_possible: spec.has_raii_boundaries,
        vla_possible: spec.has_vla_boundaries,
    };

    context.emit_procedure_inputs(
        &mut builder,
        entry,
        spec.callable,
        spec.has_implicit_object_context,
    )?;
    if !spec.properties.is_synthetic {
        context.emit_local_bindings(&mut builder, spec.body)?;
    }
    context.register_labels(&mut builder, spec.body)?;

    if spec.properties.is_synthetic {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::DeferredExecution,
            SemanticGapKind::Unknown,
            "translation-unit, static, and member initialization scheduling is not stitched across initializer fragments",
        )?;
    }
    if spec.has_preprocessing {
        for (capability, detail) in [
            (
                SemanticCapability::NormalControlFlow,
                "the active preprocessor branch depends on translation-unit configuration",
            ),
            (
                SemanticCapability::Calls,
                "macro expansion and conditionally compiled calls are unavailable without an exact preprocessing configuration",
            ),
            (
                SemanticCapability::CallableReferences,
                "macro-expanded callable references are not fabricated from source text",
            ),
        ] {
            let impacts = SemanticGapImpacts::for_gap(capability, SemanticGapSubject::Procedure);
            let impacts = if matches!(
                capability,
                SemanticCapability::Calls | SemanticCapability::CallableReferences
            ) {
                impacts.with(SemanticGapImpact::DispatchCoverage)
            } else {
                impacts
            };
            context.add_gap_with_impacts(
                &mut builder,
                entry,
                SemanticGapSubject::Procedure,
                capability,
                impacts,
                SemanticGapKind::Unsupported,
                detail,
            )?;
        }
    }
    if spec.has_syntax_errors {
        for (capability, detail) in [
            (
                SemanticCapability::NormalControlFlow,
                "tree-sitter retained an ERROR node in this callable, so omitted or misclassified control syntax may affect topology",
            ),
            (
                SemanticCapability::Calls,
                "calls nested in parser-error regions may not be retained as exact semantic call sites",
            ),
            (
                SemanticCapability::ResourceManagement,
                "object and VLA lifetimes across parser-error regions cannot be delimited exactly",
            ),
        ] {
            let impacts = SemanticGapImpacts::for_gap(capability, SemanticGapSubject::Procedure);
            context.add_gap_with_impacts(
                &mut builder,
                entry,
                SemanticGapSubject::Procedure,
                capability,
                impacts,
                SemanticGapKind::Unsupported,
                detail,
            )?;
        }
    }
    if spec.properties.is_async {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::DeferredExecution,
            SemanticGapKind::Unsupported,
            "C++ coroutine invocation constructs a resumable frame; initial suspend and scheduler behavior are not stitched",
        )?;
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::AsyncSuspendResume,
            SemanticGapKind::Unsupported,
            "coroutine suspension, resumption, promise callbacks, and symmetric transfer are not lowered",
        )?;
    }
    if spec.properties.is_generator {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::GeneratorSuspension,
            SemanticGapKind::Unsupported,
            "co_yield promise interaction and repeated resumption are not lowered",
        )?;
    }

    match spec.noexcept {
        NoexceptSpecification::MayThrow => {}
        NoexceptSpecification::Unconditional => {
            let termination = noexcept_termination.expect("unconditional noexcept terminal");
            for (subject, point) in [
                (SemanticGapSubject::Procedure, entry),
                (SemanticGapSubject::Point, termination),
            ] {
                for (capability, detail) in [
                    (
                        SemanticCapability::ExceptionalControlFlow,
                        "an exception escaping an unconditional noexcept callable terminates instead of returning exceptionally",
                    ),
                    (
                        SemanticCapability::NonLocalControl,
                        "std::terminate ends ordinary control flow and its handler behavior is not expanded",
                    ),
                    (
                        SemanticCapability::Calls,
                        "the implicit std::terminate invocation and installed terminate handler are not fabricated as call sites",
                    ),
                ] {
                    context.add_gap(
                        &mut builder,
                        point,
                        subject,
                        capability,
                        SemanticGapKind::Unknown,
                        detail,
                    )?;
                }
            }
        }
        NoexceptSpecification::Conditional => {
            for (subject, point) in [
                (SemanticGapSubject::Procedure, entry),
                (SemanticGapSubject::Point, exceptional_exit),
            ] {
                for (capability, detail) in [
                    (
                        SemanticCapability::ExceptionalControlFlow,
                        "the conditional noexcept specification requires constant evaluation before deciding between exceptional return and termination",
                    ),
                    (
                        SemanticCapability::NonLocalControl,
                        "the conditionally possible std::terminate path is not selected without constant-evaluation refinement",
                    ),
                    (
                        SemanticCapability::Calls,
                        "a conditionally possible implicit std::terminate invocation and terminate handler are not fabricated as call sites",
                    ),
                ] {
                    context.add_gap(
                        &mut builder,
                        point,
                        subject,
                        capability,
                        SemanticGapKind::Unknown,
                        detail,
                    )?;
                }
            }
        }
    }

    if spec.has_raii_boundaries {
        context.add_raii_gaps(
            &mut builder,
            normal_exit,
            "automatic objects may be destroyed at normal procedure exit",
        )?;
        context.add_raii_gaps(
            &mut builder,
            exceptional_exit,
            "automatic objects may be destroyed while unwinding from the procedure",
        )?;
    }
    if spec.has_vla_boundaries {
        context.add_vla_cleanup_gaps(
            &mut builder,
            normal_exit,
            SemanticGapSubject::Point,
            "normal procedure exit may end the lifetime of variably modified automatic arrays",
        )?;
        context.add_vla_cleanup_gaps(
            &mut builder,
            exceptional_exit,
            SemanticGapSubject::Point,
            "abnormal procedure exit may end the lifetime of variably modified automatic arrays",
        )?;
        context.add_vla_cleanup_gaps(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            "variably modified declarations require runtime storage and scope-exit refinement",
        )?;
    }
    if spec.kind == ProcedureKind::Constructor {
        context.add_implicit_lifetime_call_gaps(
            &mut builder,
            entry,
            "implicit base/member construction and default member initialization",
        )?;
    }
    if callable_name_node(spec.callable).is_some_and(|name| name.kind() == "destructor_name") {
        context.add_implicit_lifetime_call_gaps(
            &mut builder,
            entry,
            "implicit base/member destruction and virtual-destructor behavior",
        )?;
    }

    let body_entry = context.point(&mut builder, spec.body, Vec::new())?;
    context.edge(&mut builder, entry, EdgeTarget::normal(body_entry))?;
    let mut pending = vec![Work::Statement {
        node: spec.body,
        entry: body_entry,
        next: EdgeTarget::normal(normal_exit),
        scope: function_scope,
    }];

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

impl<'tree, 'targets> LoweringContext<'tree, 'targets> {
    fn emit_procedure_inputs(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        callable: Node<'tree>,
        has_implicit_object_context: bool,
    ) -> Result<(), CppLoweringError> {
        let layout = formal_parameter_slots_for_owner(Language::Cpp, callable, self.source)
            .unwrap_or_default();
        let mut ordinal = 0_u32;
        for slot in layout.slots {
            if self.session.cancellation().is_cancelled() {
                return Err(CppLoweringError::Cancelled(Box::new(
                    builder.prospective_work(),
                )));
            }
            let declaration = callable
                .named_descendant_for_byte_range(
                    slot.declaration_range.start_byte,
                    slot.declaration_range.end_byte,
                )
                .unwrap_or(callable);
            let mapping_node =
                cpp_formal_name_node(declaration, self.source, &slot.names).unwrap_or(declaration);
            let metadata = self.value_mapping(builder, mapping_node)?;
            let value = if slot.receiver {
                let value = self.session.add_value_with_metadata(
                    builder,
                    metadata,
                    SemanticValueKind::Receiver { dispatch: true },
                )?;
                self.receiver = Some(value);
                self.identity_bindings.insert(value);
                value
            } else {
                let value = self.session.add_value_with_metadata(
                    builder,
                    metadata,
                    SemanticValueKind::Parameter {
                        ordinal,
                        multiplicity: formal_multiplicity(slot.variadic),
                    },
                )?;
                ordinal = ordinal.checked_add(1).ok_or_else(|| {
                    CppLoweringError::Invalid("too many C++ formal parameters".into())
                })?;
                if cpp_declaration_value_transfer_is_exact(declaration, self.is_c_source) {
                    self.identity_bindings.insert(value);
                }
                if cpp_declaration_binds_fundamental_value(declaration) {
                    self.fundamental_bindings.insert(value);
                }
                if let Some(type_name) = declared_type_name(self.source, declaration) {
                    self.binding_type_names.insert(value, type_name);
                }
                if let Some(declarator) = declaration.child_by_field_name("declarator") {
                    if cpp_declarator_contains_kind(declarator, "pointer_declarator") {
                        self.pointer_bindings.insert(value);
                    }
                    if cpp_declarator_contains_kind(declarator, "array_declarator") {
                        self.array_bindings.insert(value);
                    }
                }
                if declaration
                    .child_by_field_name("type")
                    .is_some_and(cpp_type_is_fundamental)
                {
                    self.fundamental_storage_bindings.insert(value);
                }
                // A defaulted parameter is bound by an expression the standard
                // evaluates at every call site that omits the argument. That
                // evaluation belongs to no procedure this lowering produces:
                // it is not part of this body, and the omitting call sites are
                // not visible from here. Both the value the parameter receives
                // and any call the default performs are unrepresented, so a
                // call that elides the argument must not read as complete.
                if cpp_parameter_default_value(declaration).is_some() {
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Value(value),
                        SemanticCapability::ParameterFlow,
                        SemanticGapKind::Unsupported,
                        "a defaulted parameter is bound by a default argument evaluated at each omitting call site, which is not lowered",
                    )?;
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::Calls,
                        SemanticGapKind::Unsupported,
                        "a default argument may invoke callables at each omitting call site, and those invocations are not stitched into the ICFG",
                    )?;
                }
                value
            };
            for name in slot.names {
                self.parameters.insert(name.into_boxed_str(), value);
            }
        }

        if self.receiver.is_none() && has_implicit_object_context {
            let metadata = self.value_mapping(builder, callable)?;
            let receiver = self.session.add_value_with_metadata(
                builder,
                metadata,
                SemanticValueKind::Receiver { dispatch: true },
            )?;
            self.receiver = Some(receiver);
            self.identity_bindings.insert(receiver);
        }
        if has_implicit_object_context && let Some(receiver) = self.receiver {
            self.parameters.insert("this".into(), receiver);
        }
        Ok(())
    }

    fn emit_local_bindings(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        body: Node<'tree>,
    ) -> Result<(), CppLoweringError> {
        try_walk_named_tree_preorder(body, true, |node| {
            if self.session.cancellation().is_cancelled() {
                return Err(CppLoweringError::Cancelled(Box::new(
                    builder.prospective_work(),
                )));
            }
            if node.id() != body.id() && cpp_nested_execution_boundary(node) {
                return Ok(WalkControl::SkipChildren);
            }
            // A catch clause's parameter binds the in-flight exception object.
            // It is deliberately bound without an allocation and without any
            // producing effect: an undefined local read under a handler entry
            // is exactly what the shared handler-binding derivation (#2446)
            // resolves to the value the reaching `throw` carried. Publishing a
            // definition here would hide that origin behind a value nothing
            // threw.
            if node.kind() == "catch_clause" {
                if let Some(parameter) = catch_clause_parameter(node) {
                    self.bind_catch_parameter(builder, node, parameter)?;
                }
                return Ok(WalkControl::Continue);
            }
            if node.kind() != "declaration"
                || has_storage_class(self.source, node, "extern")
                || cpp_declaration_is_function(node)
            {
                return Ok(WalkControl::Continue);
            }
            let Some((scope_start, scope_end)) = cpp_local_scope(node, body) else {
                return Ok(WalkControl::Continue);
            };
            for declarator in cpp_local_declarators(node) {
                let Some(name_node) = declarator_name_node(declarator) else {
                    continue;
                };
                let Some(name) = nonempty_node_text(self.source, name_node) else {
                    continue;
                };
                let metadata = self.value_mapping(builder, name_node)?;
                let value = self.session.add_value_with_metadata(
                    builder,
                    metadata,
                    SemanticValueKind::Local,
                )?;
                if cpp_value_transfer_is_exact(node, declarator, self.is_c_source) {
                    self.identity_bindings.insert(value);
                }
                if cpp_binding_is_fundamental(node, declarator) {
                    self.fundamental_bindings.insert(value);
                }
                if cpp_declarator_contains_kind(declarator, "array_declarator") {
                    self.array_bindings.insert(value);
                }
                if cpp_declarator_contains_kind(declarator, "pointer_declarator") {
                    self.pointer_bindings.insert(value);
                }
                if node
                    .child_by_field_name("type")
                    .is_some_and(cpp_type_is_fundamental)
                {
                    self.fundamental_storage_bindings.insert(value);
                }
                if let Some(type_name) = declared_type_name(self.source, node) {
                    self.binding_type_names.insert(value, type_name);
                }
                self.locals
                    .entry(name.into())
                    .or_default()
                    .push(LocalBinding {
                        declaration_start: name_node.start_byte(),
                        visible_from: name_node.end_byte(),
                        scope_start,
                        scope_end,
                        value,
                    });
            }
            Ok(WalkControl::Continue)
        })
    }

    /// Bind a catch clause's parameter as a local of the handler's scope.
    ///
    /// No allocation and no producing effect: see the call site.
    fn bind_catch_parameter(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        catch: Node<'tree>,
        parameter: Node<'tree>,
    ) -> Result<(), CppLoweringError> {
        let Some(declarator) = parameter.child_by_field_name("declarator") else {
            return Ok(());
        };
        let Some(name_node) = declarator_name_node(declarator) else {
            return Ok(());
        };
        let Some(name) = nonempty_node_text(self.source, name_node) else {
            return Ok(());
        };
        let metadata = self.value_mapping(builder, name_node)?;
        let value =
            self.session
                .add_value_with_metadata(builder, metadata, SemanticValueKind::Local)?;
        self.identity_bindings.insert(value);
        if cpp_binding_is_fundamental(parameter, declarator) {
            self.fundamental_bindings.insert(value);
        }
        if let Some(type_name) = declared_type_name(self.source, parameter) {
            self.binding_type_names.insert(value, type_name);
        }
        self.locals
            .entry(name.into())
            .or_default()
            .push(LocalBinding {
                declaration_start: name_node.start_byte(),
                visible_from: name_node.end_byte(),
                scope_start: catch.start_byte(),
                scope_end: catch.end_byte(),
                value,
            });
        Ok(())
    }

    fn local_at(&self, name: &str, byte: usize) -> Option<ValueId> {
        self.locals
            .get(name)?
            .iter()
            .filter(|binding| {
                binding.visible_from <= byte
                    && binding.scope_start <= byte
                    && byte < binding.scope_end
            })
            .min_by_key(|binding| {
                (
                    binding.scope_end.saturating_sub(binding.scope_start),
                    std::cmp::Reverse(binding.visible_from),
                )
            })
            .map(|binding| binding.value)
    }

    fn local_declaration_value(&self, name: &str, declaration_start: usize) -> Option<ValueId> {
        self.locals.get(name)?.iter().find_map(|binding| {
            (binding.declaration_start == declaration_start).then_some(binding.value)
        })
    }

    fn binding_value(&self, name: &str, byte: usize) -> Option<ValueId> {
        self.local_at(name, byte)
            .or_else(|| self.parameters.get(name).copied())
    }

    fn binding_flow_kind(&self, name: &str, byte: usize, value: ValueId) -> ValueFlowKind {
        if Some(value) == self.receiver {
            ValueFlowKind::Receiver
        } else if self.local_at(name, byte) == Some(value) {
            ValueFlowKind::Local
        } else {
            ValueFlowKind::Parameter
        }
    }

    fn expression_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        kind: SemanticValueKind,
    ) -> Result<ValueId, CppLoweringError> {
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
    ) -> Result<ValueId, CppLoweringError> {
        let metadata = self.value_mapping(builder, node)?;
        self.session
            .add_value_with_metadata(builder, metadata, kind)
    }

    /// Whether every leaf of `node` is provably of fundamental type, so the
    /// whole expression is built out of built-in operators only.
    ///
    /// This is the C/C++ analogue of the C# predefined-type proof: it is what
    /// separates `(value * 3) + 7` on `int` locals -- where no user code can
    /// run and the result is a pure function of the operands -- from the same
    /// spelling over class types, where `operator*` and `operator+` may be
    /// user-defined, may throw, and may return an unrelated object.
    ///
    /// `allow_update` admits `++`/`--`, whose built-in form also writes its
    /// operand; callers that need an evaluation-order-immaterial operand pass
    /// `false`.
    fn expression_is_fundamental(&self, node: Node<'tree>, allow_update: bool) -> bool {
        let mut pending = vec![node];
        while let Some(current) = pending.pop() {
            match current.kind() {
                "number_literal" | "char_literal" | "true" | "false" => {}
                "identifier" => {
                    let proven = nonempty_node_text(self.source, current)
                        .and_then(|name| self.binding_value(name, current.start_byte()))
                        .is_some_and(|value| self.fundamental_bindings.contains(&value));
                    if !proven {
                        return false;
                    }
                }
                "parenthesized_expression" => {
                    let Some(inner) = first_named_child(current) else {
                        return false;
                    };
                    pending.push(inner);
                }
                "binary_expression" => {
                    for field in ["left", "right"] {
                        let Some(child) = current.child_by_field_name(field) else {
                            return false;
                        };
                        pending.push(child);
                    }
                }
                "unary_expression" => {
                    let Some(child) = current.child_by_field_name("argument") else {
                        return false;
                    };
                    pending.push(child);
                }
                "update_expression" if allow_update => {
                    let Some(child) = current.child_by_field_name("argument") else {
                        return false;
                    };
                    pending.push(child);
                }
                _ => return false,
            }
        }
        true
    }

    /// Whether evaluating `node` can be observed by the evaluation of a
    /// sibling operand, so an unspecified relative operand order could change
    /// the program's values.
    ///
    /// Reading a named object or a literal cannot be; neither can an
    /// expression built only out of built-in operators over fundamental
    /// operands. Anything else -- a call, an assignment, an increment, an
    /// overloadable operator on a class type -- can be, and keeps the
    /// evaluation-order gap standing.
    fn operand_evaluation_is_observable(&self, node: Node<'tree>) -> bool {
        if matches!(
            node.kind(),
            "identifier"
                | "qualified_identifier"
                | "this"
                | "number_literal"
                | "char_literal"
                | "string_literal"
                | "raw_string_literal"
                | "concatenated_string"
                | "true"
                | "false"
                | "null"
                | "nullptr"
        ) {
            return false;
        }
        // Naming a member or an element evaluates its base and its subscript
        // and then computes an address. The address computation itself is not
        // an operation another operand can observe, so the access is observable
        // exactly when one of the expressions it evaluates is -- provided no
        // user code runs to produce the address. Class member access with `.`
        // never runs user code: `operator.` cannot be declared in C++ at all.
        // `->` and `[]` can be user-defined, so they qualify only where
        // `memory_access_target` would already prove the built-in operator.
        match node.kind() {
            "field_expression" => {
                let Some(base) = node.child_by_field_name("argument") else {
                    return true;
                };
                if has_direct_token(node, "->") && !self.pointer_access_is_builtin(base) {
                    return true;
                }
                return self.operand_evaluation_is_observable(base);
            }
            "subscript_expression" => {
                let Some(base) = node.child_by_field_name("argument") else {
                    return true;
                };
                if !self.base_is_array(base) {
                    return true;
                }
                return self.operand_evaluation_is_observable(base)
                    || cpp_subscript_indices(node)
                        .iter()
                        .any(|index| self.operand_evaluation_is_observable(*index));
            }
            _ => {}
        }
        !self.expression_is_fundamental(node, false)
    }

    /// Whether `base -> member` uses the built-in indirection operator.
    ///
    /// C has no `operator->` at all, and a C++ base declared with a pointer
    /// declarator is a raw pointer, whose `->` is built in. Anything else may
    /// resolve to a user-defined `operator->`, which is a call.
    fn pointer_access_is_builtin(&self, base: Node<'tree>) -> bool {
        if self.is_c_source {
            return true;
        }
        base.kind() == "identifier"
            && nonempty_node_text(self.source, base)
                .and_then(|name| self.binding_value(name, base.start_byte()))
                .is_some_and(|value| self.pointer_bindings.contains(&value))
    }

    /// Whether the unspecified relative evaluation order of `operands` can
    /// change the program's values: at most one observable operand pins the
    /// order down to a single meaning.
    fn operand_order_is_material(&self, operands: &[Node<'tree>]) -> bool {
        operands
            .iter()
            .filter(|operand| self.operand_evaluation_is_observable(**operand))
            .count()
            > 1
    }

    fn emit_lexical_input_flow(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        point: ProgramPointId,
        target: ValueId,
    ) -> Result<(), CppLoweringError> {
        let name = if node.kind() == "this" {
            "this"
        } else {
            let Some(name) = nonempty_node_text(self.source, node) else {
                return Ok(());
            };
            name
        };
        let Some(source) = self.binding_value(name, node.start_byte()) else {
            return Ok(());
        };
        if source != target {
            self.append_effect(
                builder,
                point,
                SemanticEffect::ValueFlow {
                    kind: self.binding_flow_kind(name, node.start_byte(), source),
                    source,
                    target,
                },
            )?;
        }
        Ok(())
    }

    /// The abstract location an access expression names, when this file can
    /// structure it (#2666, #2665).
    ///
    /// A member or element target is a write to a *location*, not to a value,
    /// so it publishes a `MemoryStore` and deliberately carries no
    /// `Assignment` or `ValueFlow` edge. That separation keeps the
    /// user-defined-conversion problem out of the heap stratum: the backward
    /// points-to trace in `workspace_oracle/heap.rs` follows only value edges,
    /// so a store cannot republish a pre-conversion object as the member's
    /// content the way an unguarded value assignment would. The identity
    /// question `cpp_identity_is_preserved` answers for a local therefore does
    /// not need re-asking here -- it is answered by construction.
    fn memory_access_target(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        access: Node<'tree>,
    ) -> Result<Option<MemoryTarget>, CppLoweringError> {
        match access.kind() {
            "field_expression" => self.member_location(builder, point, access),
            "subscript_expression" => self.element_location(builder, point, access),
            _ => Ok(None),
        }
    }

    fn member_location(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        access: Node<'tree>,
    ) -> Result<Option<MemoryTarget>, CppLoweringError> {
        let (Some(base), Some(name_node)) = (
            access.child_by_field_name("argument"),
            access.child_by_field_name("field"),
        ) else {
            return Ok(None);
        };
        // A `destructor_name`, `template_method`, or dependent field name does
        // not name a data member.
        if name_node.kind() != "field_identifier" {
            return Ok(None);
        }
        let Some(name) = nonempty_node_text(self.source, name_node).map(Box::<str>::from) else {
            return Ok(None);
        };
        let declaration = self
            .access_owner_type(base)
            .and_then(|owner| self.member_declaration_for(&owner, &name, access));
        let member = self.member_locator(name_node, declaration.as_ref())?;
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
                identity: MemoryIdentity::Resolved,
            }));
        }
        // Without a base value this is not an instance access at all -- it
        // names a member of a type this file could not resolve. Inventing a
        // base object would invent an aliasing fact, so decline.
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
            identity: if declaration.is_some() {
                MemoryIdentity::Resolved
            } else {
                MemoryIdentity::Unresolved
            },
        }))
    }

    fn element_location(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        access: Node<'tree>,
    ) -> Result<Option<MemoryTarget>, CppLoweringError> {
        let Some(base) = access.child_by_field_name("argument") else {
            return Ok(None);
        };
        let Some(base_value) = self.access_base_value(builder, base)? else {
            return Ok(None);
        };
        // One subscript is the element's own index. A multi-dimensional or
        // pack subscript names no single index expression, so the location
        // stays index-less rather than adopting the first as the whole address.
        let subscripts = cpp_subscript_indices(access);
        let subscript = match subscripts.as_slice() {
            [only] => Some(*only),
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
            },
        )?;
        Ok(Some(MemoryTarget {
            location,
            kind: MemoryAccessKind::Index,
            // Two independent conditions, both required.
            //
            // The subscript must run no user code. C has no operator
            // overloading at all, and a C++ base declared with an array
            // declarator has no user-declarable `operator[]` either. Any other
            // C++ base may resolve to a user-defined subscript operator, and
            // nothing here proves which one runs.
            //
            // The index must also be a constant. A location is identified by
            // its index *value*, and only a constant subscript is canonicalized
            // to one value across occurrences -- so claiming resolution for
            // `values[i]` would let a store and a load address two different
            // elements while publishing no decline, and the solver would read
            // that disconnection as a proven absence rather than as missing
            // information. A confident wrong answer is worse than an honest
            // partial.
            //
            // The two failures are reported differently: a class-typed base is
            // a non-lowering this adapter decided on, a non-constant index is
            // information this file does not have.
            identity: if !self.base_is_array(base) {
                MemoryIdentity::UserDefinedAccessor
            } else if subscript.is_some_and(|subscript| {
                cpp_expression_value_kind(subscript) == SemanticValueKind::Constant
            }) {
                MemoryIdentity::Resolved
            } else {
                MemoryIdentity::Unresolved
            },
        }))
    }

    /// The value a subscript denotes, canonicalized when it is a constant so
    /// that every occurrence of `values[0]` names one element location.
    fn subscript_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<ValueId, CppLoweringError> {
        let kind = cpp_expression_value_kind(node);
        if kind != SemanticValueKind::Constant {
            return self.expression_value(builder, node, kind);
        }
        let Some(text) = nonempty_node_text(self.source, node) else {
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

    /// Whether subscripting `base` is the built-in subscript operator.
    fn base_is_array(&self, base: Node<'tree>) -> bool {
        if self.is_c_source {
            return true;
        }
        base.kind() == "identifier"
            && nonempty_node_text(self.source, base)
                .and_then(|name| self.binding_value(name, base.start_byte()))
                .is_some_and(|value| self.array_bindings.contains(&value))
    }

    /// The value an access is addressed through, or `None` when the base names
    /// a type, a namespace, or an object this file does not bind.
    fn access_base_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        base: Node<'tree>,
    ) -> Result<Option<ValueId>, CppLoweringError> {
        if base.kind() == "this" {
            return Ok(self.receiver);
        }
        if base.kind() == "identifier"
            && let Some(name) = nonempty_node_text(self.source, base)
            && self.binding_value(name, base.start_byte()).is_none()
        {
            return Ok(None);
        }
        self.expression_value(builder, base, cpp_expression_value_kind(base))
            .map(Some)
    }

    /// The type that declares the member an access names, when this file knows
    /// it: the enclosing type for `this`, a bound object's declared type
    /// spelling, or the identifier itself for a qualified static access.
    fn access_owner_type(&self, base: Node<'tree>) -> Option<Box<str>> {
        match base.kind() {
            "this" => enclosing_type_node(base)
                .and_then(|owner| declaration_container_name(self.source, owner)),
            "parenthesized_expression" => self.access_owner_type(first_runtime_named_child(base)?),
            // `a.b.c` names the type `b` was declared with, which is what makes
            // an access path deeper than one hop resolve.
            "field_expression" => {
                let inner = base.child_by_field_name("argument")?;
                let name = nonempty_node_text(self.source, base.child_by_field_name("field")?)?;
                let owner = self.access_owner_type(inner)?;
                self.member_declaration_for(&owner, name, base)?.type_name
            }
            // `items[0].value` names the array's element type, which is the
            // base's declared type with its array declarator removed.
            "subscript_expression" => self.access_owner_type(base.child_by_field_name("argument")?),
            "identifier" => {
                let name = nonempty_node_text(self.source, base)?;
                if let Some(declared) = self.binding_type_name(name, base.start_byte()) {
                    return Some(declared);
                }
                if self.binding_value(name, base.start_byte()).is_some() {
                    // An object in scope whose declared type this file does not
                    // know. Its members belong to some type, but not a named one.
                    return None;
                }
                Some(Box::from(name))
            }
            _ => None,
        }
    }

    fn member_declaration_for(
        &self,
        owner: &str,
        name: &str,
        access: Node<'tree>,
    ) -> Option<MemberDeclaration> {
        let key = TypeMemberKey {
            namespace: enclosing_namespace_path(self.source, access),
            owner: Box::from(owner),
            name: Box::from(name),
        };
        self.member_declarations.get(&key)?.clone()
    }

    /// Anchor a member location to its *declaration* when one is known, so two
    /// occurrences of the same member agree on one identity, and to the
    /// occurrence otherwise.
    fn member_locator(
        &self,
        occurrence: Node<'tree>,
        declaration: Option<&MemberDeclaration>,
    ) -> Result<SemanticLocator, CppLoweringError> {
        let anchor = match declaration {
            Some(declaration) => declaration.anchor,
            None => source_anchor(occurrence, 0).map_err(CppLoweringError::Invalid)?,
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
    ) -> Result<(), CppLoweringError> {
        let Some(load) = self.memory_access_target(builder, point, access)? else {
            return self.decline_unstructured_access(builder, point, access);
        };
        let result = self.expression_value(builder, access, cpp_expression_value_kind(access))?;
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
        target: Node<'tree>,
        value: ValueId,
    ) -> Result<(), CppLoweringError> {
        self.append_effect(
            builder,
            point,
            SemanticEffect::MemoryStore {
                kind: store.kind,
                location: store.location,
                value,
            },
        )?;
        // Writing through a parameter or `this` mutates storage this procedure
        // did not create, so the write is a procedure *effect* its callers
        // observe. This adapter publishes no such summary, and a caller that
        // reads the same member afterwards would otherwise see a store list
        // that is silently missing this write -- which the solver would read as
        // a proven absence rather than as missing information. The decline is
        // scoped to the location, so the value stratum is untouched, and it is
        // deliberately asymmetric: *reading* a caller-owned object at a point
        // is fully represented (#2665).
        if !self.access_root_is_procedure_local(target) {
            self.add_gap(
                builder,
                point,
                SemanticGapSubject::MemoryLocation(store.location),
                match store.kind {
                    MemoryAccessKind::Index => SemanticCapability::IndexMemory,
                    MemoryAccessKind::Static => SemanticCapability::StaticMemory,
                    _ => SemanticCapability::FieldMemory,
                },
                SemanticGapKind::Unsupported,
                "this write targets storage the procedure did not create, and writes through a parameter or receiver are not summarized as procedure effects",
            )?;
        }
        self.add_memory_identity_gap(builder, point, store)
    }

    /// Whether an access names storage this procedure itself created.
    ///
    /// The walk follows the address chain to its root name: parentheses,
    /// address-of and indirection, member access, and subscripting all address
    /// into whatever their base addresses. A root that is a local binding names
    /// storage of this frame; a parameter, `this`, or anything this file does
    /// not bind names storage that outlives the call.
    fn access_root_is_procedure_local(&self, node: Node<'tree>) -> bool {
        let mut current = node;
        loop {
            match current.kind() {
                "identifier" => {
                    let Some(name) = nonempty_node_text(self.source, current) else {
                        return false;
                    };
                    return self.local_at(name, current.start_byte()).is_some();
                }
                "new_expression" | "compound_literal_expression" => return true,
                "parenthesized_expression" => {
                    let Some(inner) = first_runtime_named_child(current) else {
                        return false;
                    };
                    current = inner;
                }
                "field_expression"
                | "subscript_expression"
                | "pointer_expression"
                | "cast_expression" => {
                    let Some(base) = current.child_by_field_name("argument") else {
                        return false;
                    };
                    current = base;
                }
                _ => return false,
            }
        }
    }

    /// Decline an access whose location this file could not structure at all,
    /// scoped to the access's own value rather than to the program point.
    fn decline_unstructured_access(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        access: Node<'tree>,
    ) -> Result<(), CppLoweringError> {
        let result = self.expression_value(builder, access, cpp_expression_value_kind(access))?;
        let (capability, detail) = if access.kind() == "subscript_expression" {
            (
                SemanticCapability::IndexMemory,
                "subscripted base is not a bound object, so no element location addresses this read",
            )
        } else {
            (
                SemanticCapability::FieldMemory,
                "member access base is not a bound object, so no field location addresses this read",
            )
        };
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::Value(result),
            capability,
            SemanticGapKind::Unknown,
            detail,
        )
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
        access: MemoryTarget,
    ) -> Result<(), CppLoweringError> {
        let capability = match access.kind {
            MemoryAccessKind::Index => SemanticCapability::IndexMemory,
            MemoryAccessKind::Static => SemanticCapability::StaticMemory,
            _ => SemanticCapability::FieldMemory,
        };
        let (kind, detail) = match access.identity {
            MemoryIdentity::Resolved => return Ok(()),
            MemoryIdentity::UserDefinedAccessor => (
                SemanticGapKind::Unsupported,
                "subscripting a class-typed base resolves through a user-defined subscript operator, which is not lowered",
            ),
            MemoryIdentity::Unresolved if access.kind == MemoryAccessKind::Index => (
                SemanticGapKind::Unknown,
                "subscripted access is structured, but a non-constant index leaves the element identity unresolved",
            ),
            MemoryIdentity::Unresolved if access.kind == MemoryAccessKind::Static => (
                SemanticGapKind::Unknown,
                "static member access is structured, but its declaration identity is not resolved",
            ),
            MemoryIdentity::Unresolved => (
                SemanticGapKind::Unknown,
                "member access is structured, but its declaration identity is not resolved",
            ),
        };
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::MemoryLocation(access.location),
            capability,
            kind,
            detail,
        )
    }

    /// Whether writing `target` stores the very object the written expression
    /// denotes, so the assignment expression's own result is that object.
    ///
    /// This is the location-side half of [`cpp_identity_is_preserved`]: a
    /// member write asks its member's declared type, an element write asks the
    /// array's element type.
    fn assignment_target_identity_is_preserved(&self, target: Node<'tree>) -> bool {
        if self.is_c_source {
            return true;
        }
        match target.kind() {
            "field_expression" => {
                let (Some(base), Some(name_node)) = (
                    target.child_by_field_name("argument"),
                    target.child_by_field_name("field"),
                ) else {
                    return false;
                };
                let Some(name) = nonempty_node_text(self.source, name_node) else {
                    return false;
                };
                self.access_owner_type(base)
                    .and_then(|owner| self.member_declaration_for(&owner, name, target))
                    .is_some_and(|declaration| declaration.identity_preserved)
            }
            "subscript_expression" => target
                .child_by_field_name("argument")
                .filter(|base| base.kind() == "identifier")
                .and_then(|base| {
                    let name = nonempty_node_text(self.source, base)?;
                    self.binding_value(name, base.start_byte())
                })
                .is_some_and(|value| self.fundamental_storage_bindings.contains(&value)),
            _ => false,
        }
    }

    /// The declared type name of a bound object, when its declaration named a
    /// type by name.
    fn binding_type_name(&self, name: &str, byte: usize) -> Option<Box<str>> {
        let value = self.binding_value(name, byte)?;
        self.binding_type_names.get(&value).cloned()
    }

    fn emit_declaration_identity(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        declaration: Node<'tree>,
        terminal: ProgramPointId,
    ) -> Result<(), CppLoweringError> {
        for declarator in cpp_local_declarators(declaration) {
            let initializer = cpp_declarator_initializer(declaration, declarator);
            let target = declarator_name_node(declarator).and_then(|name_node| {
                let name = nonempty_node_text(self.source, name_node)?;
                self.local_declaration_value(name, name_node.start_byte())
            });
            let Some(target) = target else {
                // The declared object was never preindexed as a local, so no
                // effect can name it. Decline the transfer at the point.
                if initializer.is_some() {
                    self.declare_initializer_transfer_gap(builder, terminal, None)?;
                }
                continue;
            };
            if self.identity_bindings.contains(&target) {
                if let Some(initializer) = initializer {
                    let source = self.expression_value(
                        builder,
                        initializer,
                        cpp_expression_value_kind(initializer),
                    )?;
                    self.append_effect(
                        builder,
                        terminal,
                        SemanticEffect::Assignment {
                            target,
                            value: source,
                        },
                    )?;
                    self.append_effect(
                        builder,
                        terminal,
                        SemanticEffect::ValueFlow {
                            kind: ValueFlowKind::Local,
                            source,
                            target,
                        },
                    )?;
                }
                continue;
            }
            if let Some(kind) = cpp_local_allocation_kind(declaration, declarator) {
                self.session
                    .add_allocation(builder, terminal, target, kind)?;
            }
            if initializer.is_some() {
                self.declare_initializer_transfer_gap(builder, terminal, Some(target))?;
            }
        }
        Ok(())
    }

    /// Decline one declared object's initializer transfer, scoped to that
    /// object rather than to the whole declaration statement.
    ///
    /// A class-typed by-value initialization runs a constructor or a
    /// user-defined conversion, so the initializer expression's value is not
    /// the declared object and republishing it under the declared type would
    /// misattribute the object the points-to trace reaches.
    fn declare_initializer_transfer_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        terminal: ProgramPointId,
        target: Option<ValueId>,
    ) -> Result<(), CppLoweringError> {
        self.add_gap(
            builder,
            terminal,
            target.map_or(SemanticGapSubject::Point, SemanticGapSubject::Value),
            SemanticCapability::Assignments,
            // Not `Unknown`: this adapter resolves no overloads and no
            // user-defined conversions, by decision rather than for want of
            // information about this program. Naming that decision lets a
            // consumer report an explicit `unsupported (assignments)` decline
            // instead of an indistinct partial result (#2666).
            SemanticGapKind::Unsupported,
            "initializer-to-object value transfer and aliasing are not represented: a by-value initialization of a non-fundamental type may construct, convert, copy, or move a distinct object",
        )
    }

    fn step(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        work: Work<'tree>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CppLoweringError> {
        if self.session.cancellation().is_cancelled() {
            return Err(CppLoweringError::Cancelled(Box::default()));
        }
        match work {
            Work::Statement {
                node,
                entry,
                next,
                scope,
            } => self.statement(builder, node, entry, next, scope, stack),
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
    ) -> Result<(), CppLoweringError> {
        // A folded literal keeps exactly one arm. Recording the guard is what
        // keeps the fold legible: nothing else in the frozen artifact says the
        // branch was constant (#2443).
        if let Some(value) = cpp_folded_boolean_constant(self.source, node) {
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
                stack.push(Work::Condition {
                    node: right,
                    entry: right_entry,
                    when_true,
                    when_false,
                    scope,
                });
                stack.push(Work::Condition {
                    node: left,
                    entry,
                    when_true: EdgeTarget {
                        point: right_entry,
                        kind: ControlEdgeKind::ConditionalTrue,
                    },
                    when_false,
                    scope,
                });
                Ok(())
            }
            ("binary_expression", Some("||")) => {
                let left = required_field(node, "left")?;
                let right = required_field(node, "right")?;
                let right_entry = self.point(builder, right, Vec::new())?;
                stack.push(Work::Condition {
                    node: right,
                    entry: right_entry,
                    when_true,
                    when_false,
                    scope,
                });
                stack.push(Work::Condition {
                    node: left,
                    entry,
                    when_true,
                    when_false: EdgeTarget {
                        point: right_entry,
                        kind: ControlEdgeKind::ConditionalFalse,
                    },
                    scope,
                });
                Ok(())
            }
            ("conditional_expression", _) => {
                let predicate = required_field(node, "condition")?;
                let consequence = node.child_by_field_name("consequence");
                let alternative = required_field(node, "alternative")?;
                let alternative_entry = self.point(builder, alternative, Vec::new())?;
                stack.push(Work::Condition {
                    node: alternative,
                    entry: alternative_entry,
                    when_true,
                    when_false,
                    scope,
                });
                let true_target = if let Some(consequence) = consequence {
                    let consequence_entry = self.point(builder, consequence, Vec::new())?;
                    stack.push(Work::Condition {
                        node: consequence,
                        entry: consequence_entry,
                        when_true,
                        when_false,
                        scope,
                    });
                    EdgeTarget {
                        point: consequence_entry,
                        kind: ControlEdgeKind::ConditionalTrue,
                    }
                } else {
                    // GNU's omitted middle operand reuses the already evaluated predicate.
                    when_true
                };
                stack.push(Work::Condition {
                    node: predicate,
                    entry,
                    when_true: true_target,
                    when_false: EdgeTarget {
                        point: alternative_entry,
                        kind: ControlEdgeKind::ConditionalFalse,
                    },
                    scope,
                });
                Ok(())
            }
            ("condition_clause", _) => {
                let value = required_field(node, "value")?;
                if let Some(initializer) = node.child_by_field_name("initializer") {
                    let value_entry = self.point(builder, value, Vec::new())?;
                    stack.push(Work::Condition {
                        node: value,
                        entry: value_entry,
                        when_true,
                        when_false,
                        scope,
                    });
                    stack.push(self.execution_work(
                        initializer,
                        entry,
                        EdgeTarget::normal(value_entry),
                        scope,
                    ));
                } else {
                    stack.push(Work::Condition {
                        node: value,
                        entry,
                        when_true,
                        when_false,
                        scope,
                    });
                }
                Ok(())
            }
            ("declaration", _) => {
                let decision = self.point(builder, node, Vec::new())?;
                if self.declaration_runs_lifetime_code(node) {
                    self.add_implicit_operator_gaps(
                        builder,
                        decision,
                        "contextual conversion of a condition-declared object to bool may invoke user-defined code",
                    )?;
                }
                self.edge(builder, decision, when_true)?;
                self.edge(builder, decision, when_false)?;
                self.record_guard(
                    builder,
                    decision,
                    GuardPredicate::Opaque {
                        digest: GuardConditionDigest::from_syntax_kind(node.kind()),
                    },
                    None,
                    Some(when_true),
                    Some(when_false),
                )?;
                stack.push(Work::Statement {
                    node,
                    entry,
                    next: EdgeTarget::normal(decision),
                    scope,
                });
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
                // The condition's own value is the one thing an unnormalized
                // guard can honestly name: the decision tested it, whatever it
                // means.
                let subject =
                    self.expression_value(builder, node, cpp_expression_value_kind(node))?;
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
    /// that.
    #[allow(clippy::too_many_arguments)]
    fn record_guard(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        predicate: GuardPredicate,
        subject: Option<ValueId>,
        when_true: Option<EdgeTarget>,
        when_false: Option<EdgeTarget>,
    ) -> Result<(), CppLoweringError> {
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
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CppLoweringError> {
        match node.kind() {
            "function_definition" => {
                let executable = function_execution_nodes(node);
                self.schedule_execution_nodes(builder, entry, &executable, next, scope, stack)
            }
            "compound_statement" | "translation_unit" => {
                let children = named_children(node)
                    .into_iter()
                    .filter(|child| is_statement_or_declaration(child.kind()))
                    .collect::<Vec<_>>();
                let nested_scope =
                    node.kind() == "compound_statement" && node.id() != self.root_body_id;
                let has_raii_cleanup = nested_scope
                    && !self.is_c_source
                    && block_has_automatic_object(self.source, self.trivial_types, node);
                let has_vla_cleanup =
                    nested_scope && self.is_c_source && block_has_potential_vla(node);
                if has_raii_cleanup || has_vla_cleanup {
                    let scope_exit = self.point(builder, node, Vec::new())?;
                    if has_raii_cleanup {
                        self.add_raii_gaps(
                            builder,
                            scope_exit,
                            "normal block exit may destroy automatic objects declared in this lexical scope",
                        )?;
                    }
                    if has_vla_cleanup {
                        self.add_vla_cleanup_gaps(
                            builder,
                            scope_exit,
                            SemanticGapSubject::Point,
                            "normal block exit may release variably modified automatic array storage declared in this lexical scope",
                        )?;
                    }
                    self.edge(builder, scope_exit, next)?;
                    self.schedule_execution_nodes(
                        builder,
                        entry,
                        &children,
                        EdgeTarget::normal(scope_exit),
                        scope,
                        stack,
                    )
                } else {
                    self.schedule_execution_nodes(builder, entry, &children, next, scope, stack)
                }
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
            "init_statement" => {
                let children = initializer_values(node);
                self.schedule_execution_nodes(builder, entry, &children, next, scope, stack)
            }
            "declaration"
            | "field_declaration"
            | "field_initializer_list"
            | "field_initializer" => {
                let initializers = initializer_values(node);
                let values = declaration_runtime_expressions(node);
                let function_local_static = self.is_function_local_static(node, &values);
                // A plain `declaration` reaching the non-static branch below
                // publishes its transfers, or a decline scoped to the declared
                // object, from `emit_declaration_identity`. A member
                // declaration has no such lowering, and declining it is a
                // decision: a by-value member initialization may construct,
                // convert, copy, or move a distinct object.
                if !initializers.is_empty() && node.kind() == "field_declaration" {
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::Assignments,
                        SemanticGapKind::Unsupported,
                        "initializer-to-object value transfer and aliasing are not represented",
                    )?;
                }
                // A function-local static is lowered by its own branch, which
                // models no initializer transfer at all. That is missing
                // information about this program rather than a decision, so it
                // stays `Unknown`.
                if !initializers.is_empty() && node.kind() == "declaration" && function_local_static
                {
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::Assignments,
                        SemanticGapKind::Unknown,
                        "initializer-to-object value transfer and aliasing are not represented",
                    )?;
                }
                if node.kind() == "field_initializer_list" && initializers.len() > 1 {
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::NormalControlFlow,
                        SemanticGapKind::Unknown,
                        "constructor initializers execute in base/member declaration order, which is unavailable here; written order is only a bounded lowering order",
                    )?;
                }
                if self.declaration_runs_lifetime_code(node) {
                    self.add_implicit_lifetime_call_gaps(
                        builder,
                        entry,
                        "object initialization may invoke constructors or conversion functions",
                    )?;
                }
                if !self.is_c_source
                    && !initializers.is_empty()
                    && declaration_constructs_thread(self.source, node)
                {
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::ConcurrentSpawn,
                        SemanticGapKind::Unknown,
                        "thread-object construction may spawn an execution context, but its entry, scheduling, lifetime, and join relation are not stitched into the ICFG",
                    )?;
                }
                if self.is_function_local_static(node, &values) {
                    self.function_local_static_declaration(
                        builder, node, entry, &values, next, scope, stack,
                    )
                } else {
                    let terminal = if node.kind() == "declaration" {
                        let terminal = self.point(builder, node, Vec::new())?;
                        self.emit_declaration_identity(builder, node, terminal)?;
                        self.edge(builder, terminal, next)?;
                        Some(terminal)
                    } else {
                        None
                    };
                    self.schedule_expressions(
                        builder,
                        entry,
                        &values,
                        terminal.map_or(next, EdgeTarget::normal),
                        scope,
                        stack,
                    )
                }
            }
            "return_statement" | "co_return_statement" => {
                let value_node = first_runtime_named_child(node);
                let terminal = if let Some(value_node) = value_node {
                    let terminal = self.point(builder, node, Vec::new())?;
                    let source = self.expression_value(
                        builder,
                        value_node,
                        cpp_expression_value_kind(value_node),
                    )?;
                    let value = self.value(builder, terminal, SemanticValueKind::Return)?;
                    if node.kind() == "return_statement" && self.return_transfer_is_exact {
                        self.append_effect(
                            builder,
                            terminal,
                            SemanticEffect::ValueFlow {
                                kind: ValueFlowKind::Return,
                                source,
                                target: value,
                            },
                        )?;
                    } else {
                        self.session.add_gap_with_impacts(
                            builder,
                            terminal,
                            SemanticGapSubject::Value(value),
                            SemanticCapability::Values,
                            SemanticGapImpacts::single(SemanticGapImpact::ReturnTransfer),
                            SemanticGapKind::Unsupported,
                            if node.kind() == "co_return_statement" {
                                "co_return value transfer is mediated by the coroutine promise"
                            } else {
                                "C++ by-value return may construct, convert, copy, or move a distinct result object"
                            },
                        )?;
                    }
                    self.append_effect(
                        builder,
                        terminal,
                        SemanticEffect::ProcedureReturn { value: Some(value) },
                    )?;
                    stack.push(Work::Expression {
                        node: value_node,
                        entry,
                        next: EdgeTarget::normal(terminal),
                        scope,
                    });
                    terminal
                } else {
                    self.append_effect(
                        builder,
                        entry,
                        SemanticEffect::ProcedureReturn { value: None },
                    )?;
                    entry
                };
                if node.kind() == "co_return_statement" {
                    self.add_coroutine_gap(
                        builder,
                        terminal,
                        "co_return promise completion and final suspension are not lowered",
                    )?;
                }
                self.abrupt(builder, terminal, scope, CompletionKind::Return, None)
            }
            "throw_statement" => {
                let value_node = first_runtime_named_child(node);
                let terminal = if value_node.is_some() {
                    self.point(builder, node, Vec::new())?
                } else {
                    entry
                };
                let value = value_node
                    .map(|_| self.value(builder, terminal, SemanticValueKind::Exception))
                    .transpose()?;
                // The exception object is copy-initialized from the operand,
                // and its type *is* the operand's static type: unlike a
                // declaration's initializer, a throw admits no user-defined
                // conversion that could substitute an object of another type.
                // The operand's value therefore flows into the exception
                // object, which is what a handler's binding then observes.
                // A class-typed operand may still run a copy or move
                // constructor; that is declined below as an implicit lifetime
                // call, which leaves the value edge standing rather than
                // erasing it.
                if let (Some(value_node), Some(value)) = (value_node, value) {
                    let thrown = self.expression_value(
                        builder,
                        value_node,
                        cpp_expression_value_kind(value_node),
                    )?;
                    self.append_effect(
                        builder,
                        terminal,
                        SemanticEffect::ValueFlow {
                            kind: ValueFlowKind::LanguageDefined,
                            source: thrown,
                            target: value,
                        },
                    )?;
                    if !self.is_c_source
                        && !self.expression_is_fundamental(value_node, false)
                        && !self.expression_type_is_trivial(value_node)
                    {
                        self.add_implicit_lifetime_call_gaps(
                            builder,
                            terminal,
                            "throwing copy-initializes the exception object, which may invoke a copy or move constructor",
                        )?;
                    }
                }
                self.append_effect(builder, terminal, SemanticEffect::Throw { value })?;
                if let Some(value_node) = value_node {
                    stack.push(Work::Expression {
                        node: value_node,
                        entry,
                        next: EdgeTarget::normal(terminal),
                        scope,
                    });
                }
                self.abrupt(builder, terminal, scope, CompletionKind::Throw, None)
            }
            "break_statement" | "continue_statement" => {
                let kind = if node.kind() == "break_statement" {
                    CompletionKind::Break
                } else {
                    CompletionKind::Continue
                };
                self.abrupt(builder, entry, scope, kind, None)
            }
            "goto_statement" => self.goto_statement(builder, node, entry),
            "labeled_statement" => {
                let label = required_field(node, "label")?;
                let label_name = node_text(self.source, label)
                    .ok_or_else(|| missing_field(node, "label text"))?;
                let target = self.labels.get(label_name).copied().ok_or_else(|| {
                    CppLoweringError::Invalid(format!(
                        "preallocated C/C++ label {label_name:?} is missing"
                    ))
                })?;
                self.edge(builder, entry, EdgeTarget::normal(target))?;
                let body = named_children(node)
                    .into_iter()
                    .find(|child| child.id() != label.id())
                    .ok_or_else(|| missing_field(node, "body"))?;
                stack.push(self.execution_work(body, target, next, scope));
                Ok(())
            }
            "if_statement" => self.if_statement(builder, node, entry, next, scope, stack),
            "while_statement" => self.while_statement(builder, node, entry, next, scope, stack),
            "do_statement" => self.do_statement(builder, node, entry, next, scope, stack),
            "for_statement" => self.for_statement(builder, node, entry, next, scope, stack),
            "for_range_loop" => self.range_for_statement(builder, node, entry, next, scope, stack),
            "switch_statement" => self.switch_statement(builder, node, entry, next, scope, stack),
            "case_statement" => {
                let children = case_runtime_children(node);
                self.schedule_execution_nodes(builder, entry, &children, next, scope, stack)
            }
            "try_statement" => self.try_statement(builder, node, entry, next, scope, stack),
            "co_yield_statement" => {
                let value = first_runtime_named_child(node);
                let suspend = self.point(builder, node, Vec::new())?;
                self.add_coroutine_gap(
                    builder,
                    suspend,
                    "co_yield promise interaction, suspension, and resumption are not lowered",
                )?;
                self.add_gap(
                    builder,
                    suspend,
                    SemanticGapSubject::Point,
                    SemanticCapability::GeneratorSuspension,
                    SemanticGapKind::Unsupported,
                    "co_yield suspension and repeated resumption are not represented",
                )?;
                self.edge(builder, suspend, next)?;
                if let Some(value) = value {
                    stack.push(Work::Expression {
                        node: value,
                        entry,
                        next: EdgeTarget::normal(suspend),
                        scope,
                    });
                } else {
                    self.edge(builder, entry, EdgeTarget::normal(suspend))?;
                }
                Ok(())
            }
            kind if kind.starts_with("preproc_") => {
                self.preprocessor_region(builder, node, entry, next, scope, stack)
            }
            "seh_try_statement" => self.seh_try_statement(builder, node, entry, next, scope, stack),
            "seh_leave_statement" => self.seh_leave_statement(builder, entry),
            "attributed_statement" | "else_clause" => {
                if let Some(body) = first_runtime_named_child(node) {
                    stack.push(self.execution_work(body, entry, next, scope));
                    Ok(())
                } else {
                    self.edge(builder, entry, next)
                }
            }
            "empty_statement"
            | "template_declaration"
            | "namespace_definition"
            | "class_specifier"
            | "struct_specifier"
            | "union_specifier"
            | "enum_specifier"
            | "type_definition"
            | "alias_declaration"
            | "using_declaration"
            | "static_assert_declaration"
            | "attribute_declaration" => self.edge(builder, entry, next),
            _ if is_cpp_expression(node.kind()) => {
                stack.push(Work::Expression {
                    node,
                    entry,
                    next,
                    scope,
                });
                Ok(())
            }
            _ => self.unhandled_control_syntax(builder, node, entry, next),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn if_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CppLoweringError> {
        let condition = required_field(node, "condition")?;
        let completion = if !self.is_c_source
            && syntax_has_automatic_object(self.source, self.trivial_types, condition)
        {
            EdgeTarget::normal(self.normal_cleanup_boundary(
                builder,
                condition,
                next,
                "normal if-statement completion may destroy objects declared by its initializer or condition",
            )?)
        } else {
            next
        };
        if has_direct_token(node, "constexpr") || has_direct_token(node, "consteval") {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::NormalControlFlow,
                SemanticGapKind::Unsupported,
                "if constexpr/consteval discarded-statement selection requires compile-time evaluation",
            )?;
        }
        let consequence = required_field(node, "consequence")?;
        let consequence_entry = self.point(builder, consequence, Vec::new())?;
        stack.push(self.execution_work(consequence, consequence_entry, completion, scope));
        let when_false = if let Some(alternative) = node.child_by_field_name("alternative") {
            let body = first_runtime_named_child(alternative).unwrap_or(alternative);
            let alternative_entry = self.point(builder, body, Vec::new())?;
            stack.push(self.execution_work(body, alternative_entry, completion, scope));
            EdgeTarget {
                point: alternative_entry,
                kind: ControlEdgeKind::ConditionalFalse,
            }
        } else {
            EdgeTarget {
                point: completion.point,
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
            when_false,
            scope,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn while_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CppLoweringError> {
        let condition = required_field(node, "condition")?;
        let body = required_field(node, "body")?;
        let condition_entry = self.point(builder, condition, Vec::new())?;
        let body_entry = self.point(builder, body, Vec::new())?;
        let condition_declares_object = !self.is_c_source
            && syntax_has_automatic_object(self.source, self.trivial_types, condition);
        let exit_target = if condition_declares_object {
            EdgeTarget::normal(self.normal_cleanup_boundary(
                builder,
                condition,
                next,
                "leaving a while statement may destroy an object declared by its condition",
            )?)
        } else {
            next
        };
        let iteration_target = if condition_declares_object {
            EdgeTarget {
                point: self.normal_cleanup_boundary(
                    builder,
                    condition,
                    EdgeTarget {
                        point: condition_entry,
                        kind: ControlEdgeKind::LoopBack,
                    },
                    "finishing a while iteration may destroy an object declared by its condition before reevaluation",
                )?,
                kind: ControlEdgeKind::LoopBack,
            }
        } else {
            EdgeTarget {
                point: condition_entry,
                kind: ControlEdgeKind::LoopBack,
            }
        };
        let loop_scope = builder.push_scope(
            Some(scope),
            ScopeBinding::Loop {
                label: None,
                break_target: exit_target.point,
                break_edge_kind: exit_target.kind,
                continue_target: iteration_target.point,
                continue_edge_kind: ControlEdgeKind::LoopBack,
            },
        );
        stack.push(self.execution_work(body, body_entry, iteration_target, loop_scope));
        stack.push(Work::Condition {
            node: condition,
            entry: condition_entry,
            when_true: EdgeTarget {
                point: body_entry,
                kind: ControlEdgeKind::ConditionalTrue,
            },
            when_false: EdgeTarget {
                point: exit_target.point,
                kind: ControlEdgeKind::ConditionalFalse,
            },
            scope: loop_scope,
        });
        self.edge(builder, entry, EdgeTarget::normal(condition_entry))
    }

    #[allow(clippy::too_many_arguments)]
    fn do_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CppLoweringError> {
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
        stack.push(self.execution_work(
            body,
            entry,
            EdgeTarget::normal(condition_entry),
            loop_scope,
        ));
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn for_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CppLoweringError> {
        let body = required_field(node, "body")?;
        let initializer = node.child_by_field_name("initializer");
        let condition = node.child_by_field_name("condition");
        let update = node.child_by_field_name("update");
        let condition_entry = self.point(builder, condition.unwrap_or(node), Vec::new())?;
        let body_entry = self.point(builder, body, Vec::new())?;
        let update_entry = update
            .map(|update| self.point(builder, update, Vec::new()))
            .transpose()?;
        let initializer_declares_object = !self.is_c_source
            && initializer.is_some_and(|initializer| {
                syntax_has_automatic_object(self.source, self.trivial_types, initializer)
            });
        let condition_declares_object = !self.is_c_source
            && condition.is_some_and(|condition| {
                syntax_has_automatic_object(self.source, self.trivial_types, condition)
            });
        let initializer_exit = if initializer_declares_object {
            EdgeTarget::normal(self.normal_cleanup_boundary(
                builder,
                initializer.expect("object declaration requires an initializer"),
                next,
                "leaving a for statement may destroy objects declared by its initializer",
            )?)
        } else {
            next
        };
        let loop_exit = if condition_declares_object {
            EdgeTarget::normal(self.normal_cleanup_boundary(
                builder,
                condition.expect("object declaration requires a condition"),
                initializer_exit,
                "leaving a for statement may destroy an object declared by its condition",
            )?)
        } else {
            initializer_exit
        };
        let update_target = update_entry.unwrap_or(condition_entry);
        let iteration_target = if condition_declares_object {
            EdgeTarget {
                point: self.normal_cleanup_boundary(
                    builder,
                    condition.expect("object declaration requires a condition"),
                    EdgeTarget {
                        point: update_target,
                        kind: ControlEdgeKind::LoopBack,
                    },
                    "finishing a for iteration may destroy an object declared by its condition before update and reevaluation",
                )?,
                kind: ControlEdgeKind::LoopBack,
            }
        } else {
            EdgeTarget {
                point: update_target,
                kind: ControlEdgeKind::LoopBack,
            }
        };
        let loop_scope = builder.push_scope(
            Some(scope),
            ScopeBinding::Loop {
                label: None,
                break_target: loop_exit.point,
                break_edge_kind: loop_exit.kind,
                continue_target: iteration_target.point,
                continue_edge_kind: ControlEdgeKind::LoopBack,
            },
        );
        if let Some(update) = update {
            stack.push(Work::Expression {
                node: update,
                entry: update_entry.expect("allocated update entry"),
                next: EdgeTarget {
                    point: condition_entry,
                    kind: ControlEdgeKind::LoopBack,
                },
                scope: loop_scope,
            });
        }
        stack.push(self.execution_work(body, body_entry, iteration_target, loop_scope));
        if let Some(condition) = condition {
            stack.push(Work::Condition {
                node: condition,
                entry: condition_entry,
                when_true: EdgeTarget {
                    point: body_entry,
                    kind: ControlEdgeKind::ConditionalTrue,
                },
                when_false: EdgeTarget {
                    point: loop_exit.point,
                    kind: ControlEdgeKind::ConditionalFalse,
                },
                scope: loop_scope,
            });
        } else {
            self.edge(
                builder,
                condition_entry,
                EdgeTarget {
                    point: body_entry,
                    kind: ControlEdgeKind::ConditionalTrue,
                },
            )?;
        }
        // When the initializer already establishes the condition, the first
        // test cannot fail, so the zero-trip path out of the loop does not
        // exist. Entering the body directly is what lets a consumer see that
        // the body definitely ran; every later iteration still reevaluates the
        // condition and keeps the exit edge.
        let first_arrival = if condition.is_some_and(|condition| {
            cpp_for_condition_starts_true(self.source, initializer, condition)
        }) {
            EdgeTarget::normal(body_entry)
        } else {
            EdgeTarget::normal(condition_entry)
        };
        if let Some(initializer) = initializer {
            stack.push(self.execution_work(initializer, entry, first_arrival, loop_scope));
            Ok(())
        } else {
            self.edge(builder, entry, first_arrival)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn range_for_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CppLoweringError> {
        let range = required_field(node, "right")?;
        let body = required_field(node, "body")?;
        let initializer = node.child_by_field_name("initializer");
        let test = self.point(builder, node, Vec::new())?;
        let binding = self.point(builder, node, Vec::new())?;
        let body_entry = self.point(builder, body, Vec::new())?;
        let loop_exit = self.normal_cleanup_boundary(
            builder,
            node,
            next,
            "leaving a range-for statement may destroy its hidden range object and initializer-scoped objects",
        )?;
        let binding_requires_cleanup = node
            .child_by_field_name("type")
            .is_none_or(|ty| ty.kind() != "primitive_type");
        let iteration_target = if binding_requires_cleanup {
            EdgeTarget {
                point: self.normal_cleanup_boundary(
                    builder,
                    node,
                    EdgeTarget {
                        point: test,
                        kind: ControlEdgeKind::LoopBack,
                    },
                    "finishing a range-for iteration may destroy the per-iteration loop binding before increment and retest",
                )?,
                kind: ControlEdgeKind::LoopBack,
            }
        } else {
            EdgeTarget {
                point: test,
                kind: ControlEdgeKind::LoopBack,
            }
        };
        let break_target = if binding_requires_cleanup {
            EdgeTarget::normal(self.normal_cleanup_boundary(
                builder,
                node,
                EdgeTarget::normal(loop_exit),
                "breaking from a range-for iteration may destroy the per-iteration loop binding before the hidden range object",
            )?)
        } else {
            EdgeTarget::normal(loop_exit)
        };
        let loop_scope = builder.push_scope(
            Some(scope),
            ScopeBinding::Loop {
                label: None,
                break_target: break_target.point,
                break_edge_kind: break_target.kind,
                continue_target: iteration_target.point,
                continue_edge_kind: ControlEdgeKind::LoopBack,
            },
        );
        for (capability, detail) in [
            (
                SemanticCapability::Calls,
                "range-for begin/end, comparison, increment, and dereference operations may invoke user code and are not emitted as fabricated call sites",
            ),
            (
                SemanticCapability::ExceptionalControlFlow,
                "range-for protocol operations and hidden range binding can throw",
            ),
            (
                SemanticCapability::ResourceManagement,
                "the hidden range object's lifetime and destruction are not fully lowered",
            ),
        ] {
            self.add_gap(
                builder,
                test,
                SemanticGapSubject::Point,
                capability,
                SemanticGapKind::Unknown,
                detail,
            )?;
        }
        self.edge(
            builder,
            test,
            EdgeTarget {
                point: binding,
                kind: ControlEdgeKind::ConditionalTrue,
            },
        )?;
        self.edge(
            builder,
            test,
            EdgeTarget {
                point: loop_exit,
                kind: ControlEdgeKind::ConditionalFalse,
            },
        )?;
        self.edge(builder, binding, EdgeTarget::normal(body_entry))?;
        stack.push(self.execution_work(body, body_entry, iteration_target, loop_scope));
        let range_entry = if let Some(initializer) = initializer {
            let range_entry = self.point(builder, range, Vec::new())?;
            stack.push(Work::Expression {
                node: range,
                entry: range_entry,
                next: EdgeTarget::normal(test),
                scope: loop_scope,
            });
            stack.push(self.execution_work(
                initializer,
                entry,
                EdgeTarget::normal(range_entry),
                loop_scope,
            ));
            return Ok(());
        } else {
            entry
        };
        stack.push(Work::Expression {
            node: range,
            entry: range_entry,
            next: EdgeTarget::normal(test),
            scope: loop_scope,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn switch_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CppLoweringError> {
        let condition = required_field(node, "condition")?;
        let body = required_field(node, "body")?;
        let dispatch = self.point(builder, node, Vec::new())?;
        if !self.is_c_source
            && condition_value_declaration(condition).is_some_and(declaration_may_construct_object)
        {
            self.add_implicit_operator_gaps(
                builder,
                dispatch,
                "contextual integral or enumeration conversion of a switch condition-declared object may invoke user-defined code",
            )?;
        }
        let completion = if !self.is_c_source
            && syntax_has_automatic_object(self.source, self.trivial_types, condition)
        {
            EdgeTarget::normal(self.normal_cleanup_boundary(
                builder,
                condition,
                next,
                "leaving a switch statement may destroy objects declared by its initializer or condition",
            )?)
        } else {
            next
        };
        let cases = switch_cases(body);
        if cases.is_empty() {
            self.edge(builder, dispatch, completion)?;
            stack.push(Work::Expression {
                node: condition,
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
                break_target: completion.point,
                break_edge_kind: completion.kind,
            },
        );
        let mut has_default = false;
        for case in &cases {
            has_default |= case.child_by_field_name("value").is_none();
            let case_entry = if let Some(entry) = self.switch_case_entries.get(&case.id()).copied()
            {
                entry
            } else {
                let entry = self.point(builder, *case, Vec::new())?;
                self.switch_case_entries.insert(case.id(), entry);
                entry
            };
            self.edge(
                builder,
                dispatch,
                EdgeTarget {
                    point: case_entry,
                    kind: ControlEdgeKind::SwitchCase,
                },
            )?;
        }
        if !has_default {
            self.edge(
                builder,
                dispatch,
                EdgeTarget {
                    point: completion.point,
                    kind: ControlEdgeKind::ConditionalFalse,
                },
            )?;
        }
        // Lower the lexical switch body exactly once. The body entry is
        // intentionally detached from dispatch; reachability sealing removes
        // its synthetic edge to the first case while preserving the case
        // entries reached directly from the dispatcher.
        let body_entry = self.point(builder, body, Vec::new())?;
        stack.push(self.execution_work(body, body_entry, completion, switch_scope));
        stack.push(Work::Expression {
            node: condition,
            entry,
            next: EdgeTarget::normal(dispatch),
            scope: switch_scope,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn try_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CppLoweringError> {
        let body = required_field(node, "body")?;
        let catches = named_children(node)
            .into_iter()
            .filter(|child| child.kind() == "catch_clause")
            .collect::<Vec<_>>();
        let catch_bodies = catches
            .iter()
            .map(|catch| required_field(*catch, "body"))
            .collect::<Result<Vec<_>, _>>()?;
        let catch_entries = catches
            .iter()
            .map(|catch| self.point(builder, *catch, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        let try_scope = if catch_entries.is_empty() {
            scope
        } else {
            let dispatcher = self.point(builder, node, Vec::new())?;
            self.add_gap(
                builder,
                dispatcher,
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                // A deliberate non-lowering, not missing information: this
                // adapter performs no C++ type matching, so which handler a
                // thrown type selects is not decided here. It stays standing
                // wherever an abort path runs user code -- a handler body is
                // exactly such a path -- so naming it `Unsupported` surfaces the
                // decline without discharging it where it protects an answer.
                SemanticGapKind::Unsupported,
                "catch type matching, base conversions, catch-all selection, and exception copying are not lowered",
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
            self.abrupt(builder, unmatched, scope, CompletionKind::Throw, None)?;
            builder.push_scope(Some(scope), ScopeBinding::Handler { entry: dispatcher })
        };

        for ((catch, body), catch_entry) in catches.iter().zip(&catch_bodies).zip(&catch_entries) {
            if catch_clause_parameter(*catch)
                .is_some_and(|parameter| self.catch_parameter_runs_lifetime_code(parameter))
            {
                // The parameter itself is bound in `emit_local_bindings`, and
                // the shared handler-binding derivation (#2446) resolves that
                // undefined local to the value the reaching `throw` carried.
                // What is still unrepresented is the *construction* of the
                // binding -- a catch by value runs a copy constructor, a catch
                // of a base runs a derived-to-base conversion -- and that is a
                // lifetime call, not a missing value.
                self.add_implicit_lifetime_call_gaps(
                    builder,
                    *catch_entry,
                    "catch parameter construction and destruction",
                )?;
            }
            stack.push(self.execution_work(*body, *catch_entry, next, scope));
        }

        let mut try_parts = named_children(node)
            .into_iter()
            .filter(|child| child.kind() == "field_initializer_list" || child.id() == body.id())
            .collect::<Vec<_>>();
        if try_parts.is_empty() {
            try_parts.push(body);
        }
        self.schedule_execution_nodes(builder, entry, &try_parts, next, try_scope, stack)
    }

    #[allow(clippy::too_many_arguments)]
    fn seh_try_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CppLoweringError> {
        for (capability, detail) in [
            (
                SemanticCapability::NormalControlFlow,
                "SEH filter selection, handler acceptance, and leave destinations are not fully lowered",
            ),
            (
                SemanticCapability::ExceptionalControlFlow,
                "Microsoft structured exception dispatch and continuation semantics are unsupported",
            ),
            (
                SemanticCapability::CleanupControlFlow,
                "SEH finally execution during every abrupt completion requires cleanup specialization",
            ),
            (
                SemanticCapability::Calls,
                "OS exception filters and termination/unwind callbacks may invoke code outside explicit source calls",
            ),
            (
                SemanticCapability::NonLocalControl,
                "SEH leave/filter/finally non-local routing is not fully represented",
            ),
            (
                SemanticCapability::ResourceManagement,
                "resource lifetime across SEH unwinding and abnormal termination requires platform semantics",
            ),
        ] {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                capability,
                SemanticGapKind::Unsupported,
                detail,
            )?;
        }

        let body = required_field(node, "body")?;
        let body_entry = self.point(builder, body, Vec::new())?;
        self.edge(builder, entry, EdgeTarget::normal(body_entry))?;
        let clause = named_children(node)
            .into_iter()
            .find(|child| matches!(child.kind(), "seh_except_clause" | "seh_finally_clause"));

        match clause.map(|clause| (clause.kind(), clause)) {
            Some(("seh_finally_clause", clause)) => {
                let finally_body = required_field(clause, "body")?;
                let finally_entry = self.point(builder, clause, Vec::new())?;
                stack.push(self.execution_work(finally_body, finally_entry, next, scope));
                stack.push(self.execution_work(
                    body,
                    body_entry,
                    EdgeTarget::normal(finally_entry),
                    scope,
                ));
                Ok(())
            }
            Some(("seh_except_clause", clause)) => {
                let handler_body = required_field(clause, "body")?;
                let dispatcher = self.point(builder, clause, Vec::new())?;
                let handler_entry = self.point(builder, handler_body, Vec::new())?;
                self.edge(
                    builder,
                    entry,
                    EdgeTarget {
                        point: dispatcher,
                        kind: ControlEdgeKind::Exceptional,
                    },
                )?;
                let try_scope =
                    builder.push_scope(Some(scope), ScopeBinding::Handler { entry: dispatcher });
                stack.push(self.execution_work(handler_body, handler_entry, next, scope));

                if let Some(filter) = clause.child_by_field_name("filter") {
                    let unmatched = self.point(builder, clause, Vec::new())?;
                    self.abrupt(builder, unmatched, scope, CompletionKind::Throw, None)?;
                    stack.push(Work::Condition {
                        node: filter,
                        entry: dispatcher,
                        when_true: EdgeTarget {
                            point: handler_entry,
                            kind: ControlEdgeKind::ConditionalTrue,
                        },
                        when_false: EdgeTarget {
                            point: unmatched,
                            kind: ControlEdgeKind::ConditionalFalse,
                        },
                        scope,
                    });
                } else {
                    self.edge(
                        builder,
                        dispatcher,
                        EdgeTarget {
                            point: handler_entry,
                            kind: ControlEdgeKind::SwitchCase,
                        },
                    )?;
                }
                stack.push(self.execution_work(body, body_entry, next, try_scope));
                Ok(())
            }
            Some(_) | None => {
                stack.push(self.execution_work(body, body_entry, next, scope));
                Ok(())
            }
        }
    }

    fn seh_leave_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
    ) -> Result<(), CppLoweringError> {
        for (capability, detail) in [
            (
                SemanticCapability::NonLocalControl,
                "SEH __leave destination and enclosing region selection are unsupported",
            ),
            (
                SemanticCapability::CleanupControlFlow,
                "SEH __leave must run applicable finally regions before reaching its destination",
            ),
            (
                SemanticCapability::NormalControlFlow,
                "SEH __leave is retained as a terminal typed boundary rather than falling through lexically",
            ),
        ] {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                capability,
                SemanticGapKind::Unsupported,
                detail,
            )?;
        }
        Ok(())
    }

    fn goto_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
    ) -> Result<(), CppLoweringError> {
        let Some(label) = node.child_by_field_name("label") else {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::NonLocalControl,
                SemanticGapKind::Unsupported,
                "computed or malformed goto target cannot be resolved structurally",
            )?;
            return Ok(());
        };
        let Some(name) = node_text(self.source, label) else {
            return Err(missing_field(node, "label text"));
        };
        let Some(target) = self.labels.get(name).copied() else {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::NonLocalControl,
                SemanticGapKind::Unknown,
                "goto target lies outside the represented callable or is syntactically unavailable",
            )?;
            return Ok(());
        };
        // The edge itself is represented. What is not is what a jump does to
        // object lifetimes: it can leave a scope holding automatic objects
        // whose destructors run, and it can jump over a variably modified
        // declaration. A procedure with neither has no such effect to declare.
        if self.raii_possible || self.vla_possible {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::NonLocalControl,
                SemanticGapKind::Unknown,
                "goto edge is represented, but legality and variable-lifetime effects across the jump require semantic refinement",
            )?;
        }
        if self.raii_possible {
            self.add_raii_gaps(
                builder,
                entry,
                "goto may enter or leave scopes with automatic object lifetimes",
            )?;
        }
        if self.vla_possible {
            self.add_vla_cleanup_gaps(
                builder,
                entry,
                SemanticGapSubject::Point,
                "goto may enter or leave scopes containing variably modified automatic arrays",
            )?;
        }
        self.edge(builder, entry, EdgeTarget::normal(target))
    }

    #[allow(clippy::too_many_arguments)]
    fn preprocessor_region(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CppLoweringError> {
        for (capability, detail) in [
            (
                SemanticCapability::NormalControlFlow,
                "preprocessor branch selection depends on an unavailable macro configuration",
            ),
            (
                SemanticCapability::Calls,
                "macro expansion may introduce calls that are absent from the parsed structured tree",
            ),
            (
                SemanticCapability::NonLocalControl,
                "macro expansion may introduce abrupt control that is absent from the parsed structured tree",
            ),
        ] {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                capability,
                SemanticGapKind::Unsupported,
                detail,
            )?;
        }
        let branches = named_children(node)
            .into_iter()
            .filter(|child| is_statement_or_declaration(child.kind()))
            .collect::<Vec<_>>();
        if branches.is_empty() {
            return self.edge(builder, entry, next);
        }
        for branch in branches {
            let branch_entry = self.point(builder, branch, Vec::new())?;
            self.edge(
                builder,
                entry,
                EdgeTarget {
                    point: branch_entry,
                    kind: ControlEdgeKind::SwitchCase,
                },
            )?;
            stack.push(self.execution_work(branch, branch_entry, next, scope));
        }
        self.edge(
            builder,
            entry,
            EdgeTarget {
                point: next.point,
                kind: ControlEdgeKind::ConditionalFalse,
            },
        )
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
    ) -> Result<(), CppLoweringError> {
        let result = self.expression_value(builder, node, cpp_expression_value_kind(node))?;
        if matches!(node.kind(), "identifier" | "this") {
            self.emit_lexical_input_flow(builder, node, entry, result)?;
        }
        match node.kind() {
            "call_expression" if is_unevaluated_builtin_call(self.source, node) => {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::Values,
                    SemanticGapKind::Unknown,
                    "tree-sitter recovered a C++ unevaluated builtin operand as call-shaped syntax; the operand is not executed without type refinement",
                )?;
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::Calls,
                    SemanticGapKind::Unsupported,
                    "calls nested in noexcept/typeid operands are intentionally not emitted as immediate call sites",
                )?;
                self.edge(builder, entry, next)
            }
            "call_expression" | "new_expression" => {
                self.call_expression(builder, node, entry, next, scope, stack)
            }
            "lambda_expression" => {
                self.callable_expression(builder, node, entry, next, scope, stack)
            }
            "conditional_expression" => {
                let condition = required_field(node, "condition")?;
                let consequence = node.child_by_field_name("consequence");
                let alternative = required_field(node, "alternative")?;
                let alternative_entry = self.point(builder, alternative, Vec::new())?;
                stack.push(Work::Expression {
                    node: alternative,
                    entry: alternative_entry,
                    next,
                    scope,
                });
                let when_true = if let Some(consequence) = consequence {
                    let consequence_entry = self.point(builder, consequence, Vec::new())?;
                    stack.push(Work::Expression {
                        node: consequence,
                        entry: consequence_entry,
                        next,
                        scope,
                    });
                    EdgeTarget {
                        point: consequence_entry,
                        kind: ControlEdgeKind::ConditionalTrue,
                    }
                } else {
                    next
                };
                stack.push(Work::Condition {
                    node: condition,
                    entry,
                    when_true,
                    when_false: EdgeTarget {
                        point: alternative_entry,
                        kind: ControlEdgeKind::ConditionalFalse,
                    },
                    scope,
                });
                Ok(())
            }
            "binary_expression" if matches!(binary_operator(node), Some("&&" | "||")) => {
                let left = required_field(node, "left")?;
                let right = required_field(node, "right")?;
                let right_entry = self.point(builder, right, Vec::new())?;
                stack.push(Work::Expression {
                    node: right,
                    entry: right_entry,
                    next,
                    scope,
                });
                let (when_true, when_false) = if binary_operator(node) == Some("&&") {
                    (
                        EdgeTarget {
                            point: right_entry,
                            kind: ControlEdgeKind::ConditionalTrue,
                        },
                        EdgeTarget {
                            point: next.point,
                            kind: ControlEdgeKind::ConditionalFalse,
                        },
                    )
                } else {
                    (
                        EdgeTarget {
                            point: next.point,
                            kind: ControlEdgeKind::ConditionalTrue,
                        },
                        EdgeTarget {
                            point: right_entry,
                            kind: ControlEdgeKind::ConditionalFalse,
                        },
                    )
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
            "comma_expression" => {
                let left = required_field(node, "left")?;
                let right = required_field(node, "right")?;
                let right_entry = self.point(builder, right, Vec::new())?;
                stack.push(Work::Expression {
                    node: right,
                    entry: right_entry,
                    next,
                    scope,
                });
                stack.push(Work::Expression {
                    node: left,
                    entry,
                    next: EdgeTarget::normal(right_entry),
                    scope,
                });
                Ok(())
            }
            "assignment_expression" => {
                let left = required_field(node, "left")?;
                let right = required_field(node, "right")?;
                let assignment = self.point(builder, node, Vec::new())?;
                let exact_target = (assignment_operator(node) == Some("=")
                    && left.kind() == "identifier")
                    .then(|| {
                        let name = nonempty_node_text(self.source, left)?;
                        let target = self.binding_value(name, left.start_byte())?;
                        self.identity_bindings
                            .contains(&target)
                            .then_some((name, target))
                    })
                    .flatten();
                if let Some((name, target)) = exact_target {
                    let value =
                        self.expression_value(builder, right, cpp_expression_value_kind(right))?;
                    self.append_effect(
                        builder,
                        assignment,
                        SemanticEffect::Assignment { target, value },
                    )?;
                    self.append_effect(
                        builder,
                        assignment,
                        SemanticEffect::ValueFlow {
                            kind: self.binding_flow_kind(name, left.start_byte(), target),
                            source: value,
                            target,
                        },
                    )?;
                    self.append_effect(
                        builder,
                        assignment,
                        SemanticEffect::Assignment {
                            target: result,
                            value: target,
                        },
                    )?;
                } else {
                    // A member or element target writes a *location*, so it
                    // becomes a `MemoryStore` against a structured location and
                    // deliberately carries no value edge (#2666, #2665).
                    let value =
                        self.expression_value(builder, right, cpp_expression_value_kind(right))?;
                    let store = if assignment_operator(node) == Some("=") {
                        self.memory_access_target(builder, assignment, left)?
                    } else {
                        None
                    };
                    if let Some(store) = store {
                        self.emit_memory_store(builder, assignment, store, left, value)?;
                    } else {
                        self.add_gap(
                            builder,
                            assignment,
                            SemanticGapSubject::Point,
                            SemanticCapability::Assignments,
                            SemanticGapKind::Unsupported,
                            "a dereference, a compound assignment, and an unbound target are not lowered into memory flow, so this write names no structured location",
                        )?;
                    }
                    // The value of an assignment expression is the value that
                    // was assigned, once no conversion can have replaced it --
                    // the same question a declaration with an initializer asks,
                    // put to the *target's* declared type. A statement-level
                    // write never reads this result, and declining it
                    // unconditionally opened the whole procedure's value-flow
                    // snapshot over a value nothing observes.
                    if self.assignment_target_identity_is_preserved(left) {
                        self.append_effect(
                            builder,
                            assignment,
                            SemanticEffect::Assignment {
                                target: result,
                                value,
                            },
                        )?;
                    } else {
                        self.add_gap(
                            builder,
                            assignment,
                            SemanticGapSubject::Value(result),
                            SemanticCapability::Values,
                            SemanticGapKind::Unsupported,
                            "assignment result identity is not represented: this adapter resolves no user-defined conversion or assignment operator",
                        )?;
                    }
                }
                if self.operand_order_is_material(&[left, right]) {
                    self.add_gap(
                        builder,
                        assignment,
                        SemanticGapSubject::Point,
                        SemanticCapability::NormalControlFlow,
                        SemanticGapKind::Unknown,
                        "assignment operand evaluation order is C/C++-standard dependent; RHS-first lowering is only a deterministic bounded order without a configured language standard",
                    )?;
                }
                if assignment_operator(node).is_some_and(|operator| operator != "=")
                    && !(self.expression_is_fundamental(left, false)
                        && self.expression_is_fundamental(right, false))
                {
                    self.add_implicit_operator_gaps(
                        builder,
                        assignment,
                        "compound assignment may invoke an overloaded operator",
                    )?;
                }
                self.edge(builder, assignment, next)?;
                let right_entry = self.point(builder, right, Vec::new())?;
                let left_entry = self.point(builder, left, Vec::new())?;
                self.edge(builder, entry, EdgeTarget::normal(right_entry))?;
                stack.push(Work::Expression {
                    node: left,
                    entry: left_entry,
                    next: EdgeTarget::normal(assignment),
                    scope,
                });
                stack.push(Work::Expression {
                    node: right,
                    entry: right_entry,
                    next: EdgeTarget::normal(left_entry),
                    scope,
                });
                Ok(())
            }
            "co_await_expression" => {
                let argument = required_field(node, "argument")?;
                let suspend = self.point(builder, node, Vec::new())?;
                self.add_coroutine_gap(
                    builder,
                    suspend,
                    "await transformation, awaiter calls, suspension, resumption, and symmetric transfer are not lowered",
                )?;
                self.edge(builder, suspend, next)?;
                stack.push(Work::Expression {
                    node: argument,
                    entry,
                    next: EdgeTarget::normal(suspend),
                    scope,
                });
                Ok(())
            }
            "sizeof_expression"
            | "alignof_expression"
            | "decltype"
            | "noexcept"
            | "offsetof_expression"
            | "requires_expression" => {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::Values,
                    SemanticGapKind::Unknown,
                    "unevaluated or compile-time operand semantics are retained without executing operand syntax",
                )?;
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::Calls,
                    SemanticGapKind::Unsupported,
                    "potential calls in unevaluated operands are intentionally not emitted as call sites; VLA and polymorphic typeid exceptions require refinement",
                )?;
                self.edge(builder, entry, next)
            }
            "generic_expression" => {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::NormalControlFlow,
                    SemanticGapKind::Unsupported,
                    "C _Generic association selection requires type refinement; unselected expressions are not executed",
                )?;
                self.edge(builder, entry, next)
            }
            "gnu_asm_expression" => {
                for (capability, detail) in [
                    (
                        SemanticCapability::NormalControlFlow,
                        "inline assembly may branch, loop, or terminate independently of the represented fallthrough edge",
                    ),
                    (
                        SemanticCapability::NonLocalControl,
                        "asm-goto labels and machine-level transfers are not expanded into structured CFG edges",
                    ),
                    (
                        SemanticCapability::Calls,
                        "inline assembly may invoke code without a source-level call expression",
                    ),
                    (
                        SemanticCapability::Values,
                        "register constraints, clobbers, and operand value transformations require target-specific assembly semantics",
                    ),
                    (
                        SemanticCapability::Assignments,
                        "output operands and memory clobbers may mutate state beyond explicit C/C++ assignments",
                    ),
                ] {
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Point,
                        capability,
                        SemanticGapKind::Unsupported,
                        detail,
                    )?;
                }
                let children = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            "delete_expression" => {
                self.add_implicit_lifetime_call_gaps(
                    builder,
                    entry,
                    "delete may invoke a destructor and a deallocation function",
                )?;
                let children = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            "parenthesized_expression" => {
                let Some(value_node) = first_runtime_named_child(node) else {
                    return self.edge(builder, entry, next);
                };
                let terminal = self.point(builder, node, Vec::new())?;
                let value = self.expression_value(
                    builder,
                    value_node,
                    cpp_expression_value_kind(value_node),
                )?;
                self.append_effect(
                    builder,
                    terminal,
                    SemanticEffect::Assignment {
                        target: result,
                        value,
                    },
                )?;
                // Parentheses are pure grouping: the parenthesized expression
                // denotes the very value the enclosed expression denotes, so
                // the transfer is an exact flow, not only an assignment.
                self.append_effect(
                    builder,
                    terminal,
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::LanguageDefined,
                        source: value,
                        target: result,
                    },
                )?;
                self.edge(builder, terminal, next)?;
                stack.push(Work::Expression {
                    node: value_node,
                    entry,
                    next: EdgeTarget::normal(terminal),
                    scope,
                });
                Ok(())
            }
            "compound_literal_expression" => {
                self.session
                    .add_allocation(builder, entry, result, AllocationKind::Object)?;
                let children = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            // A read of a member or an element is a load from a *location*,
            // not a value edge from a binding (#2666, #2665). The load is
            // published at a terminal point the base reaches first, so the
            // location's base value is already produced when the load runs.
            "field_expression" | "subscript_expression" => {
                let terminal = self.point(builder, node, Vec::new())?;
                let children = runtime_expression_children(node);
                // `operator.` cannot be declared in C++, so a `.` member access
                // never runs user code. `->` on a raw pointer and `[]` on an
                // array are the built-in operators, which is the same proof
                // `memory_access_target` requires before it claims the location
                // is resolved.
                let base = node.child_by_field_name("argument");
                let may_invoke_overload = match (node.kind(), base) {
                    (_, None) => true,
                    ("field_expression", Some(base)) => {
                        has_direct_token(node, "->") && !self.pointer_access_is_builtin(base)
                    }
                    (_, Some(base)) => !self.base_is_array(base),
                };
                if !self.is_c_source && may_invoke_overload {
                    self.add_implicit_operator_gaps(
                        builder,
                        terminal,
                        "runtime operator or conversion may invoke user-defined code",
                    )?;
                }
                if node.kind() == "subscript_expression" && {
                    let mut operands = vec![base.unwrap_or(node)];
                    operands.extend(cpp_subscript_indices(node));
                    operands.len() > 1 && self.operand_order_is_material(&operands)
                } {
                    self.add_gap(
                        builder,
                        terminal,
                        SemanticGapSubject::Point,
                        SemanticCapability::NormalControlFlow,
                        SemanticGapKind::Unknown,
                        "relative operand evaluation order is unspecified or language-version dependent; source order is only a bounded lowering order",
                    )?;
                }
                self.emit_memory_load(builder, terminal, node)?;
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
            "binary_expression" | "unary_expression" | "update_expression"
            | "pointer_expression" | "cast_expression" | "fold_expression" => {
                // Taking an object's address denotes that object: the pointer
                // value's pointees are exactly the operand's, which is what
                // makes `p = &original; p->f` and `original.f` name one
                // location. The transfer is published as both an `Assignment`
                // and an exact `LanguageDefined` flow, exactly as
                // parenthesization is: the assignment states the denotation is
                // the operand's, which is what the access-path resolver walks
                // to root `p->f` at the object rather than at the pointer, and
                // the flow states the transfer is language-defined rather than
                // a user-written copy.
                if node.kind() == "pointer_expression"
                    && has_direct_token(node, "&")
                    && let Some(operand) = node.child_by_field_name("argument")
                {
                    let terminal = self.point(builder, node, Vec::new())?;
                    let source = self.expression_value(
                        builder,
                        operand,
                        cpp_expression_value_kind(operand),
                    )?;
                    self.append_effect(
                        builder,
                        terminal,
                        SemanticEffect::Assignment {
                            target: result,
                            value: source,
                        },
                    )?;
                    self.append_effect(
                        builder,
                        terminal,
                        SemanticEffect::ValueFlow {
                            kind: ValueFlowKind::LanguageDefined,
                            source,
                            target: result,
                        },
                    )?;
                    self.edge(builder, terminal, next)?;
                    return self.schedule_expressions(
                        builder,
                        entry,
                        &[operand],
                        EdgeTarget::normal(terminal),
                        scope,
                        stack,
                    );
                }
                let built_in_operator = self.expression_is_fundamental(node, true);
                if !self.is_c_source && expression_may_invoke_overload(node) && !built_in_operator {
                    self.add_implicit_operator_gaps(
                        builder,
                        entry,
                        "runtime operator or conversion may invoke user-defined code",
                    )?;
                }
                let children = runtime_expression_children(node);
                if matches!(
                    node.kind(),
                    "binary_expression" | "subscript_expression" | "fold_expression"
                ) && children.len() > 1
                    && self.operand_order_is_material(&children)
                {
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::NormalControlFlow,
                        SemanticGapKind::Unknown,
                        "relative operand evaluation order is unspecified or language-version dependent; source order is only a bounded lowering order",
                    )?;
                }
                if !built_in_operator {
                    return self
                        .schedule_expressions(builder, entry, &children, next, scope, stack);
                }
                // A built-in operator over fundamental operands is a pure
                // function of them: the result carries exactly what the
                // operands carry, and no user code intervenes. The transfer
                // is published at a terminal point the operands reach first,
                // so the result is defined after every operand it derives from.
                //
                // The result is *derived from* every operand, not a copy of
                // any one of them, so this is a joining `LanguageDefined`
                // flow. An `Assignment` would be wrong twice over: it kills
                // the target, so a second operand would erase what the first
                // contributed, and it would claim the result is the operand
                // object for the points-to trace.
                let terminal = self.point(builder, node, Vec::new())?;
                let operands = children
                    .iter()
                    .map(|child| {
                        self.expression_value(builder, *child, cpp_expression_value_kind(*child))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                self.session
                    .append_language_defined_value_flows(builder, terminal, operands, result)?;
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
            "condition_clause" => {
                let children = runtime_expression_children(node);
                self.schedule_execution_nodes(builder, entry, &children, next, scope, stack)
            }
            "initializer_list" => {
                let children = runtime_expression_children(node);
                if self.is_c_source
                    && children.len() > 1
                    && self.operand_order_is_material(&children)
                {
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::NormalControlFlow,
                        SemanticGapKind::Unknown,
                        "C does not specify the relative evaluation order of initializer-list expressions; source order is only a bounded lowering order",
                    )?;
                }
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            "argument_list"
            | "field_initializer"
            | "field_initializer_list"
            | "init_declarator" => {
                let children = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            "preproc_call" => {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::Calls,
                    SemanticGapKind::Unsupported,
                    "macro invocation expansion is unavailable and no textual mini-parser is used",
                )?;
                self.edge(builder, entry, next)
            }
            "lambda_capture_initializer" => {
                let children = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            "function_definition" => self.edge(builder, entry, next),
            _ if is_runtime_leaf(node.kind()) || is_type_syntax(node.kind()) => {
                self.edge(builder, entry, next)
            }
            _ => {
                let children = runtime_expression_children(node);
                if children.is_empty() {
                    self.unhandled_expression_syntax(builder, node, entry, next)
                } else {
                    self.schedule_expressions(builder, entry, &children, next, scope, stack)
                }
            }
        }
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
    ) -> Result<(), CppLoweringError> {
        let invoke = self.point(builder, node, Vec::new())?;
        let normal = self.point(builder, node, Vec::new())?;
        let exceptional = self.point(builder, node, Vec::new())?;

        let function = if node.kind() == "new_expression" {
            required_field(node, "type")?
        } else {
            required_field(node, "function")?
        };
        let callee = self.source_value(builder, function, SemanticValueKind::Callable)?;
        let result = self.expression_value(builder, node, SemanticValueKind::Temporary)?;
        let thrown = self.source_value(builder, function, SemanticValueKind::Exception)?;
        let receiver_node = cpp_call_receiver(function);
        let receiver = receiver_node
            .map(|receiver| {
                self.expression_value(builder, receiver, cpp_expression_value_kind(receiver))
            })
            .transpose()?;
        let constructor = node.kind() == "new_expression" || cpp_direct_constructor_call(function);
        let indirect = !constructor && call_target_requires_dispatch_gap(function);
        let callable_kind = if constructor {
            CallableReferenceKind::Constructor
        } else if receiver.is_some() {
            CallableReferenceKind::BoundMethod
        } else {
            CallableReferenceKind::Function
        };
        let resolution = if indirect {
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
        let argument_values = arguments
            .iter()
            .map(|argument| {
                self.expression_value(builder, *argument, cpp_expression_value_kind(*argument))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let call_site = self.session.add_call_site(
            builder,
            CallSiteScaffold {
                point: invoke,
                callee,
                receiver,
                arguments: argument_values
                    .into_iter()
                    .map(|value| SemanticCallArgument::direct(value, ArgumentDomain::Positional))
                    .collect(),
                normal_results: Box::new([]),
                result: Some(result),
                thrown: Some(thrown),
                declared_targets: resolution.clone(),
                normal_continuation: normal,
                exceptional_continuation: exceptional,
            },
        )?;
        if constructor {
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
        self.edge(builder, normal, next)?;
        self.abrupt(builder, exceptional, scope, CompletionKind::Throw, None)?;
        self.resolution_gaps(builder, invoke, callee, call_site, &resolution)?;

        if indirect {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::CallableReferences,
                SemanticGapKind::Unsupported,
                "function-pointer, pointer-to-member, or callable-object target requires type/value refinement",
            )?;
        }
        let dynamic_dispatch_unproven = (receiver_node.is_some()
            && !member_dispatch_is_explicitly_qualified(function))
            || (receiver_node.is_none()
                && self.has_implicit_object_context
                && is_structurally_unqualified_call_target(function));
        if dynamic_dispatch_unproven {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::Point,
                SemanticCapability::DynamicDispatch,
                SemanticGapKind::Unknown,
                "member dispatch, including an implicit object call where applicable, may select a virtual override; object context, virtual status, and final-overrider identity require class-hierarchy refinement",
            )?;
        }
        if is_concurrent_spawn_call(self.source, function) {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::ConcurrentSpawn,
                SemanticGapKind::Unknown,
                "thread/task creation is an explicit call, but the spawned execution context is not stitched into the ICFG",
            )?;
        }
        if is_deferred_callback_call(self.source, function) {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::DeferredExecution,
                SemanticGapKind::Unknown,
                "registered callback or asynchronously scheduled callable does not execute immediately on this control edge",
            )?;
        }
        if is_non_local_runtime_call(self.source, function) {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::NonLocalControl,
                SemanticGapKind::Unsupported,
                "setjmp/longjmp-style non-local control and restored execution state are not lowered",
            )?;
        }
        if node.kind() == "new_expression" {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::Allocations,
                SemanticGapKind::Unknown,
                "allocation-function selection, placement-new storage, array cookies, and partial-construction cleanup are not represented",
            )?;
            self.add_implicit_lifetime_call_gaps(
                builder,
                invoke,
                "new-expression allocation and partial-construction cleanup",
            )?;
        } else if constructor {
            self.add_implicit_lifetime_call_gaps(
                builder,
                invoke,
                "temporary-object construction and full-expression cleanup",
            )?;
        }
        let evaluations = call_operand_evaluations(node, function);
        if evaluations.len() > 1 && self.operand_order_is_material(&evaluations) {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::NormalControlFlow,
                SemanticGapKind::Unknown,
                "relative evaluation order of the callable/receiver and arguments is language-version and construct dependent; source order is used only as a bounded traversal order",
            )?;
        }

        self.schedule_expressions(
            builder,
            entry,
            &evaluations,
            EdgeTarget::normal(invoke),
            scope,
            stack,
        )
    }

    fn callable_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CppLoweringError> {
        let captures = lambda_capture_initializers(node);
        let creation = if captures.is_empty() {
            entry
        } else {
            self.point(builder, node, Vec::new())?
        };
        let result = self.expression_value(builder, node, SemanticValueKind::Callable)?;
        let metadata = self.metadata(creation)?;
        self.append_effect(
            builder,
            creation,
            SemanticEffect::CallableCreation {
                result,
                callable: CallableValue {
                    kind: CallableReferenceKind::Lambda,
                    targets: CallableTargetResolution::Unknown,
                    target_evidence: metadata.evidence,
                    bound_receiver: None,
                    environment: None,
                },
            },
        )?;
        self.add_gap(
            builder,
            creation,
            SemanticGapSubject::Value(result),
            SemanticCapability::CallableReferences,
            SemanticGapKind::Unknown,
            "lambda body target and closure-object identity require location-first callable refinement",
        )?;
        self.add_gap(
            builder,
            creation,
            SemanticGapSubject::Value(result),
            SemanticCapability::Captures,
            SemanticGapKind::Unknown,
            "lambda capture modes, lifetime extension, and closure storage are not represented",
        )?;
        self.edge(builder, creation, next)?;
        if captures.is_empty() {
            Ok(())
        } else {
            self.schedule_expressions(
                builder,
                entry,
                &captures,
                EdgeTarget::normal(creation),
                scope,
                stack,
            )
        }
    }

    fn register_labels(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        root: Node<'tree>,
    ) -> Result<(), CppLoweringError> {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if self.session.cancellation().is_cancelled() {
                return Err(CppLoweringError::Cancelled(Box::new(
                    builder.prospective_work(),
                )));
            }
            if node != root && matches!(node.kind(), "function_definition" | "lambda_expression") {
                continue;
            }
            if node.kind() == "labeled_statement" {
                let label = required_field(node, "label")?;
                let name = node_text(self.source, label)
                    .ok_or_else(|| missing_field(node, "label text"))?;
                let point = self.point(builder, node, Vec::new())?;
                if self.labels.insert(Box::<str>::from(name), point).is_some() {
                    return Err(CppLoweringError::Invalid(format!(
                        "duplicate C/C++ label {name:?} in one callable"
                    )));
                }
            }
            stack.extend(named_children(node).into_iter().rev());
        }
        Ok(())
    }

    fn execution_work(
        &self,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
    ) -> Work<'tree> {
        if is_statement_or_declaration(node.kind()) {
            Work::Statement {
                node,
                entry,
                next,
                scope,
            }
        } else {
            Work::Expression {
                node,
                entry,
                next,
                scope,
            }
        }
    }

    /// Whether binding a catch clause's parameter runs user code.
    ///
    /// A handler that binds by reference or pointer binds the exception object
    /// itself and constructs nothing. A handler that binds by value
    /// copy-initializes from it, which runs a copy constructor unless the
    /// handler type is fundamental or a proved-trivial class.
    fn catch_parameter_runs_lifetime_code(&self, parameter: Node<'tree>) -> bool {
        if self.is_c_source {
            return false;
        }
        let Some(declarator) = parameter.child_by_field_name("declarator") else {
            return true;
        };
        if cpp_declarator_preserves_identity(declarator) {
            return false;
        }
        !parameter
            .child_by_field_name("type")
            .is_some_and(cpp_type_is_fundamental)
            && !self
                .trivial_types
                .declaration_is_trivial(self.source, parameter)
    }

    /// Whether an expression's static type is a class this file proved
    /// trivially constructible and destructible.
    fn expression_type_is_trivial(&self, node: Node<'tree>) -> bool {
        node.kind() == "identifier"
            && nonempty_node_text(self.source, node)
                .and_then(|name| self.binding_type_name(name, node.start_byte()))
                .is_some_and(|name| self.trivial_types.contains(&name))
    }

    /// Whether initializing or destroying the objects `node` declares can run
    /// user code.
    ///
    /// C has no constructors, destructors, or conversion functions at all, and
    /// a C++ object of a proved-trivial type has none either.
    fn declaration_runs_lifetime_code(&self, node: Node<'tree>) -> bool {
        !self.is_c_source
            && declaration_may_construct_object(node)
            && !self.trivial_types.declaration_is_trivial(self.source, node)
    }

    fn normal_cleanup_boundary(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        next: EdgeTarget,
        context: &str,
    ) -> Result<ProgramPointId, CppLoweringError> {
        let cleanup = self.point(builder, node, Vec::new())?;
        self.add_raii_gaps(builder, cleanup, context)?;
        self.edge(builder, cleanup, next)?;
        Ok(cleanup)
    }

    fn execution_entry(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<ProgramPointId, CppLoweringError> {
        if node.kind() == "case_statement"
            && let Some(entry) = self.switch_case_entries.get(&node.id()).copied()
        {
            return Ok(entry);
        }
        self.point(builder, node, Vec::new())
    }

    fn schedule_execution_nodes(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        children: &[Node<'tree>],
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CppLoweringError> {
        if children.is_empty() {
            return self.edge(builder, entry, next);
        }
        let mut entries = Vec::with_capacity(children.len());
        for child in children {
            entries.push(self.execution_entry(builder, *child)?);
        }
        self.edge(builder, entry, EdgeTarget::normal(entries[0]))?;
        for index in (0..children.len()).rev() {
            let child_next = entries
                .get(index + 1)
                .copied()
                .map(EdgeTarget::normal)
                .unwrap_or(next);
            stack.push(self.execution_work(children[index], entries[index], child_next, scope));
        }
        Ok(())
    }

    fn is_function_local_static(&self, node: Node<'tree>, values: &[Node<'tree>]) -> bool {
        !self.is_synthetic_procedure
            && node.kind() == "declaration"
            && has_storage_class(self.source, node, "static")
            && (!values.is_empty() || (self.declaration_runs_lifetime_code(node)))
    }

    #[allow(clippy::too_many_arguments)]
    fn function_local_static_declaration(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        values: &[Node<'tree>],
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CppLoweringError> {
        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::DeferredExecution,
            SemanticGapKind::Unknown,
            "function-local static initialization is guarded and executes at most once rather than on every invocation",
        )?;
        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::NormalControlFlow,
            SemanticGapKind::Unknown,
            "the once-only initialization guard, concurrent initialization, recursive entry, and prior failure state are not modeled",
        )?;

        let initialize = self.point(builder, node, Vec::new())?;
        self.edge(
            builder,
            entry,
            EdgeTarget {
                point: initialize,
                kind: ControlEdgeKind::ConditionalTrue,
            },
        )?;
        self.edge(
            builder,
            entry,
            EdgeTarget {
                point: next.point,
                kind: ControlEdgeKind::ConditionalFalse,
            },
        )?;
        if values.is_empty() {
            self.edge(builder, initialize, next)
        } else {
            self.schedule_expressions(builder, initialize, values, next, scope, stack)
        }
    }

    fn schedule_expressions(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        children: &[Node<'tree>],
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CppLoweringError> {
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

    fn unhandled_control_syntax(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
    ) -> Result<(), CppLoweringError> {
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
        )?;
        self.edge(builder, entry, next)
    }

    fn unhandled_expression_syntax(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
    ) -> Result<(), CppLoweringError> {
        let detail = format!(
            "{} expression semantics are retained as an opaque source-backed point",
            node.kind()
        );
        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::Values,
            SemanticGapKind::Unsupported,
            &detail,
        )?;
        self.edge(builder, entry, next)
    }

    fn abrupt(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        from: ProgramPointId,
        scope: ScopeFrameId,
        kind: CompletionKind,
        label: Option<&str>,
    ) -> Result<(), CppLoweringError> {
        let Some(route) = builder.resolve_completion(scope, &CompletionRequest::new(kind, label))
        else {
            if matches!(kind, CompletionKind::Break | CompletionKind::Continue) {
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
            return Err(CppLoweringError::Invalid(format!(
                "{} completion has no matching structured continuation",
                completion_label(kind)
            )));
        };
        if self.raii_possible {
            self.add_raii_gaps(
                builder,
                from,
                "abrupt completion may leave scopes containing automatic objects",
            )?;
        }
        if self.vla_possible {
            self.add_vla_cleanup_gaps(
                builder,
                from,
                SemanticGapSubject::Point,
                "abrupt completion may leave scopes containing variably modified automatic arrays",
            )?;
        }
        self.edge(
            builder,
            from,
            EdgeTarget {
                point: route.destination().target(),
                kind: route.destination().edge_kind(),
            },
        )
    }

    fn resolution_gaps(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        callee: ValueId,
        call_site: CallSiteId,
        resolution: &CallableTargetResolution,
    ) -> Result<(), CppLoweringError> {
        self.session.add_callable_resolution_gaps(
            builder,
            point,
            callee,
            call_site,
            resolution,
            "callable target, including possible function-pointer or callable-object identity, requires translation-unit-aware C/C++ dispatch refinement",
            "call target, including possible indirect function-pointer dispatch and caller-side default-argument or conversion calls, requires translation-unit-aware C/C++ refinement",
        )
    }

    fn add_raii_gaps(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        context: &str,
    ) -> Result<(), CppLoweringError> {
        // Only the fabricated-call-site entry is a decision. The other three
        // depend on constructed-object state and destructor definitions this
        // file does not have, which is missing information, so they stay
        // `Unknown` (#2666).
        for (capability, kind, detail) in [
            (
                SemanticCapability::CleanupControlFlow,
                SemanticGapKind::Unknown,
                "destruction order and cleanup routing depend on constructed-object state",
            ),
            (
                SemanticCapability::ResourceManagement,
                SemanticGapKind::Unknown,
                "RAII release depends on inferred types, storage duration, and destructor definitions",
            ),
            (
                SemanticCapability::Calls,
                SemanticGapKind::Unsupported,
                "implicit destructor invocations are not emitted as fabricated call sites",
            ),
            (
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unknown,
                "destructor failure, noexcept termination, and unwinding interactions are not lowered",
            ),
        ] {
            self.add_gap(
                builder,
                point,
                SemanticGapSubject::Point,
                capability,
                kind,
                &format!("{context}; {detail}"),
            )?;
        }
        Ok(())
    }

    fn add_vla_cleanup_gaps(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        subject: SemanticGapSubject,
        context: &str,
    ) -> Result<(), CppLoweringError> {
        for (capability, detail) in [
            (
                SemanticCapability::CleanupControlFlow,
                "scope-sensitive VLA storage release and jumps across variably modified declarations require refinement",
            ),
            (
                SemanticCapability::ResourceManagement,
                "automatic variable-size storage lifetime is not represented as an explicit resource",
            ),
            (
                SemanticCapability::Allocations,
                "runtime stack allocation for a variably modified array is not emitted as an allocation row",
            ),
            (
                SemanticCapability::NormalControlFlow,
                "VLA bound evaluation failure and scope-entry legality depend on target and language semantics",
            ),
            (
                SemanticCapability::Calls,
                "calls in parameter VLA bounds and implicit storage-management operations are not fully lowered",
            ),
        ] {
            self.add_gap(
                builder,
                point,
                subject,
                capability,
                SemanticGapKind::Unknown,
                &format!("{context}; {detail}"),
            )?;
        }
        Ok(())
    }

    fn add_implicit_lifetime_call_gaps(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        context: &str,
    ) -> Result<(), CppLoweringError> {
        for (capability, kind, detail) in [
            (
                SemanticCapability::Calls,
                SemanticGapKind::Unsupported,
                "implicit constructor/destructor/allocation calls are not fabricated",
            ),
            // The abort edge stays `Unknown`. Naming it `Unsupported` would make
            // it eligible for the implicit-abort discharge, and it is the only
            // decline standing where a lifetime operation's *normal* effect is
            // also unrepresented.
            (
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unknown,
                "implicit lifetime operations may throw or terminate",
            ),
            (
                SemanticCapability::ResourceManagement,
                SemanticGapKind::Unknown,
                "object lifetime and partial construction/destruction require type refinement",
            ),
        ] {
            self.add_gap(
                builder,
                point,
                SemanticGapSubject::Point,
                capability,
                kind,
                &format!("{context}; {detail}"),
            )?;
        }
        Ok(())
    }

    fn add_implicit_operator_gaps(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        context: &str,
    ) -> Result<(), CppLoweringError> {
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unsupported,
            &format!("{context}; overload resolution is not emitted as an implicit call site"),
        )?;
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unknown,
            &format!("{context}; user-defined operators and conversions may throw"),
        )
    }

    fn add_coroutine_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        detail: &str,
    ) -> Result<(), CppLoweringError> {
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::Point,
            SemanticCapability::AsyncSuspendResume,
            SemanticGapKind::Unsupported,
            detail,
        )?;
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::Point,
            SemanticCapability::DeferredExecution,
            SemanticGapKind::Unsupported,
            "coroutine promise and frame callbacks may invoke user code not represented as immediate calls",
        )?;
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unsupported,
            "coroutine promise, awaiter, allocation, and frame callbacks are not emitted as fabricated call sites",
        )?;
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unknown,
            "coroutine callbacks, allocation, and resumption may fail or terminate",
        )
    }

    fn point(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        effects: Vec<SemanticEffect>,
    ) -> Result<ProgramPointId, CppLoweringError> {
        let metadata = self.mapping(builder, node)?;
        self.session.add_point(builder, metadata, effects)
    }

    fn mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<PointMetadata, CppLoweringError> {
        self.session.add_node_mapping(builder, node)
    }

    fn value_mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<PointMetadata, CppLoweringError> {
        let anchor = source_anchor(node, 0).map_err(CppLoweringError::Invalid)?;
        self.session
            .add_mapping(builder, anchor, SourceMappingKind::Exact)
    }

    fn metadata(&self, point: ProgramPointId) -> Result<PointMetadata, CppLoweringError> {
        self.session.metadata(point)
    }

    fn value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        kind: SemanticValueKind,
    ) -> Result<ValueId, CppLoweringError> {
        self.session.add_value(builder, point, kind)
    }

    fn append_effect(
        &self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        effect: SemanticEffect,
    ) -> Result<(), CppLoweringError> {
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
    ) -> Result<(), CppLoweringError> {
        self.add_gap_with_impacts(
            builder,
            point,
            subject,
            capability,
            SemanticGapImpacts::for_gap(capability, subject),
            kind,
            detail,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn add_gap_with_impacts(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        subject: SemanticGapSubject,
        capability: SemanticCapability,
        impacts: SemanticGapImpacts,
        kind: SemanticGapKind,
        detail: &str,
    ) -> Result<(), CppLoweringError> {
        if !self.published_gaps.insert(GapFact {
            point,
            subject,
            capability,
        }) {
            return Ok(());
        }
        self.session
            .add_gap_with_impacts(builder, point, subject, capability, impacts, kind, detail)?;
        Ok(())
    }

    fn edge(
        &self,
        builder: &mut ProcedureCfgBuilder,
        source_point: ProgramPointId,
        target: EdgeTarget,
    ) -> Result<(), CppLoweringError> {
        self.session
            .add_edge(builder, source_point, target.point, target.kind)
    }
}

fn cpp_formal_name_node<'tree>(
    declaration: Node<'tree>,
    source: &str,
    names: &[String],
) -> Option<Node<'tree>> {
    let mut stack = vec![declaration];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "identifier" | "field_identifier" | "this")
            && node_text(source, node).is_some_and(|text| names.iter().any(|name| name == text))
        {
            return Some(node);
        }
        let children = named_children(node);
        stack.extend(children.into_iter().rev());
    }
    None
}

fn cpp_nested_execution_boundary(node: Node<'_>) -> bool {
    matches!(node.kind(), "function_definition" | "lambda_expression")
}

fn cpp_local_declarators(declaration: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = declaration.walk();
    let mut declarators = declaration
        .children_by_field_name("declarator", &mut cursor)
        .collect::<Vec<_>>();
    if declarators.is_empty() {
        declarators.extend(
            named_children(declaration)
                .into_iter()
                .filter(|child| child.kind() == "init_declarator"),
        );
    }
    declarators.sort_unstable_by_key(Node::start_byte);
    declarators.dedup_by_key(|node| node.id());
    declarators
}

fn cpp_declarator_contains_kind(mut node: Node<'_>, expected: &str) -> bool {
    loop {
        if node.kind() == expected {
            return true;
        }
        if let Some(inner) = node.child_by_field_name("declarator") {
            node = inner;
        } else if matches!(
            node.kind(),
            "reference_declarator" | "parenthesized_declarator"
        ) {
            let Some(inner) = first_named_child(node) else {
                return false;
            };
            node = inner;
        } else {
            return false;
        }
    }
}

fn cpp_declarator_preserves_identity(mut node: Node<'_>) -> bool {
    loop {
        if matches!(node.kind(), "pointer_declarator" | "reference_declarator") {
            return true;
        }
        if let Some(inner) = node.child_by_field_name("declarator") {
            node = inner;
        } else if node.kind() == "parenthesized_declarator" {
            let Some(inner) = first_named_child(node) else {
                return false;
            };
            node = inner;
        } else {
            return false;
        }
    }
}

/// Whether a declared base type is a fundamental C/C++ type: an arithmetic
/// type or an enumeration.
///
/// No user-defined constructor, conversion function, assignment operator, or
/// overloaded operator can be associated with such a type. Copying an object
/// of a fundamental type therefore transfers the value itself, and every
/// operator applied to operands of fundamental type is the built-in one.
fn cpp_type_is_fundamental(type_node: Node<'_>) -> bool {
    matches!(
        type_node.kind(),
        "primitive_type" | "sized_type_specifier" | "enum_specifier"
    )
}

/// The compile-time truth value a condition names, when the condition is a
/// literal this lowering decodes exactly.
///
/// `true` and `false` are literal node kinds in both dialects: C++ spells them
/// as keywords, and a C translation unit only parses them as literals once the
/// dialect actually has them, so neither spelling can be a rebindable name
/// here. An integer literal converts to `false` exactly when its value is
/// zero. Every other condition -- including a floating literal, a character
/// literal, and a macro name -- folds nothing.
fn cpp_folded_boolean_constant(source: &str, node: Node<'_>) -> Option<bool> {
    match node.kind() {
        "true" => Some(true),
        "false" => Some(false),
        "number_literal" => cpp_integer_literal_is_nonzero(nonempty_node_text(source, node)?),
        _ => None,
    }
}

/// The digit run and radix of an integer literal token, or `None` when the
/// token is not an integer literal this function decodes.
///
/// A width or signedness suffix carries no value and is dropped. A token whose
/// remainder after the digit run is not a suffix -- a fractional part, or a
/// decimal or binary exponent -- is a floating literal and is left undecoded
/// rather than guessed at.
fn cpp_integer_literal_digits(text: &str) -> Option<(&str, u32)> {
    const SUFFIX: &str = "uUlLzZ";
    let (body, radix) = text.strip_prefix('0').map_or((text, 10), |rest| {
        match rest.as_bytes().first().map(u8::to_ascii_lowercase) {
            Some(b'x') => (&rest[1..], 16),
            Some(b'b') => (&rest[1..], 2),
            // A leading `0` is octal, and is itself a digit of the value.
            _ => (text, 8),
        }
    });
    let digit_end = body
        .find(|character: char| !character.is_digit(radix) && character != '\'')
        .unwrap_or(body.len());
    let (digits, remainder) = body.split_at(digit_end);
    (!digits.is_empty()
        && remainder
            .chars()
            .all(|character| SUFFIX.contains(character)))
    .then_some((digits, radix))
}

/// Whether an integer literal token denotes a nonzero value.
///
/// Only the digits decide, whatever the base and whatever suffix the token
/// carries, so this answers for literals far wider than any Rust integer.
fn cpp_integer_literal_is_nonzero(text: &str) -> Option<bool> {
    let (digits, radix) = cpp_integer_literal_digits(text)?;
    Some(
        digits
            .chars()
            .any(|character| character.is_digit(radix) && character != '0'),
    )
}

/// The value of an integer literal token, when it fits an `i64`.
fn cpp_integer_literal_value(text: &str) -> Option<i64> {
    let (digits, radix) = cpp_integer_literal_digits(text)?;
    i64::from_str_radix(&digits.replace('\'', ""), radix).ok()
}

/// Whether a C-style `for` condition is already true when the loop is first
/// reached, so the loop body definitely executes at least once.
///
/// The one shape recognized is the counted loop: a `<` or `<=` test whose left
/// operand is a counter the initializer declares with an integer-literal value
/// already satisfying an integer-literal limit. Every ingredient is a
/// tree-sitter field or a literal token; any other shape answers `false` and
/// keeps the zero-trip path.
fn cpp_for_condition_starts_true(
    source: &str,
    initializer: Option<Node<'_>>,
    condition: Node<'_>,
) -> bool {
    if condition.kind() != "binary_expression" {
        return false;
    }
    let Some(inclusive) = condition
        .child_by_field_name("operator")
        .and_then(|operator| match operator.kind() {
            "<" => Some(false),
            "<=" => Some(true),
            _ => None,
        })
    else {
        return false;
    };
    let Some(limit) = condition
        .child_by_field_name("right")
        .and_then(|right| nonempty_node_text(source, right))
        .and_then(cpp_integer_literal_value)
    else {
        return false;
    };
    let Some(counter) = condition
        .child_by_field_name("left")
        .filter(|left| left.kind() == "identifier")
        .and_then(|left| nonempty_node_text(source, left))
    else {
        return false;
    };
    let Some(initializer) = initializer.filter(|node| node.kind() == "declaration") else {
        return false;
    };
    cpp_local_declarators(initializer)
        .into_iter()
        .any(|declarator| {
            declarator_name_node(declarator).and_then(|name| nonempty_node_text(source, name))
                == Some(counter)
                && cpp_declarator_initializer(initializer, declarator)
                    .and_then(|value| nonempty_node_text(source, value))
                    .and_then(cpp_integer_literal_value)
                    .is_some_and(|start| {
                        if inclusive {
                            start <= limit
                        } else {
                            start < limit
                        }
                    })
        })
}

/// The default-argument expression of one formal parameter declaration.
///
/// C has no default arguments, so this only ever answers for a C++ callable.
fn cpp_parameter_default_value(declaration: Node<'_>) -> Option<Node<'_>> {
    (declaration.kind() == "optional_parameter_declaration")
        .then(|| declaration.child_by_field_name("default_value"))
        .flatten()
}

fn locator_is_c_source(locator: &SemanticLocator) -> bool {
    locator
        .path()
        .as_path()
        .extension()
        .and_then(|extension| extension.to_str())
        == Some("c")
}

/// Whether a value transfer into the object `declarator` binds reproduces the
/// transferred value exactly: the bound object is the very object its
/// initializer, assigned expression, or returned expression denotes, with no
/// user-defined constructor or conversion able to substitute a distinct object.
///
/// Three independent structural proofs, any one of which suffices:
///
/// - a pointer or reference declarator binds the operand itself;
/// - a fundamental base type (arithmetic or enumeration) admits no
///   user-defined copy constructor, conversion function, or `operator=`;
/// - a C translation unit has no user-defined conversions at all.
///
/// An array declarator, and any declarator that `cpp_local_allocation_kind`
/// reports as introducing storage, is excluded: aggregate and class-typed
/// storage is modelled by allocations and the heap stratum, not by a scalar
/// value transfer, and a whole-object initializer is not one.
fn cpp_value_transfer_is_exact(
    declaration: Node<'_>,
    declarator: Node<'_>,
    is_c_source: bool,
) -> bool {
    if cpp_declarator_preserves_identity(declarator) {
        return true;
    }
    if cpp_declarator_contains_kind(declarator, "array_declarator")
        || cpp_local_allocation_kind(declaration, declarator).is_some()
    {
        return false;
    }
    is_c_source
        || declaration
            .child_by_field_name("type")
            .is_some_and(cpp_type_is_fundamental)
}

/// Whether the value `declarator` binds always has a fundamental type, so
/// every built-in operator written over it resolves to the built-in operator
/// rather than to an overload or a user-defined conversion.
///
/// Pointer, array, and function declarators are excluded: they redeclare the
/// binding's type away from the fundamental base type, and operators over
/// pointers reach through to memory this predicate says nothing about.
fn cpp_binding_is_fundamental(declaration: Node<'_>, declarator: Node<'_>) -> bool {
    !cpp_declarator_contains_kind(declarator, "pointer_declarator")
        && !cpp_declarator_contains_kind(declarator, "array_declarator")
        && !cpp_declarator_contains_kind(declarator, "function_declarator")
        && !cpp_declarator_contains_kind(declarator, "reference_declarator")
        && declaration
            .child_by_field_name("type")
            .is_some_and(cpp_type_is_fundamental)
}

fn cpp_declaration_value_transfer_is_exact(declaration: Node<'_>, is_c_source: bool) -> bool {
    cpp_local_declarators(declaration)
        .into_iter()
        .any(|declarator| cpp_value_transfer_is_exact(declaration, declarator, is_c_source))
}

fn cpp_declaration_binds_fundamental_value(declaration: Node<'_>) -> bool {
    cpp_local_declarators(declaration)
        .into_iter()
        .any(|declarator| cpp_binding_is_fundamental(declaration, declarator))
}

/// Whether a callable's return transfer reproduces the returned value exactly.
///
/// A callable is not a storage-introducing declaration, so this asks only the
/// type-and-dialect question: a pointer or reference return declarator names
/// the operand's own object, C has no user-defined conversions, and a C++
/// fundamental return type admits no copy constructor or conversion function.
/// A C++ class, template, or deduced return type keeps its conservative gap.
fn cpp_callable_return_transfer_is_exact(callable: Node<'_>, is_c_source: bool) -> bool {
    let Some(declarator) = callable.child_by_field_name("declarator") else {
        return false;
    };
    if cpp_declarator_preserves_identity(declarator) {
        return true;
    }
    if cpp_declarator_contains_kind(declarator, "array_declarator") {
        return false;
    }
    is_c_source
        || callable
            .child_by_field_name("type")
            .is_some_and(cpp_type_is_fundamental)
}

fn cpp_declaration_is_function(declaration: Node<'_>) -> bool {
    cpp_local_declarators(declaration)
        .into_iter()
        .any(|declarator| cpp_declarator_contains_kind(declarator, "function_declarator"))
}

fn cpp_local_scope(node: Node<'_>, body: Node<'_>) -> Option<(usize, usize)> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "compound_statement"
                | "for_statement"
                | "for_range_loop"
                | "if_statement"
                | "switch_statement"
                | "while_statement"
                | "do_statement"
                | "catch_clause"
        ) {
            return Some((parent.start_byte(), parent.end_byte()));
        }
        if parent.id() == body.id() {
            return Some((body.start_byte(), body.end_byte()));
        }
        current = parent.parent();
    }
    (body.start_byte() <= node.start_byte() && node.end_byte() <= body.end_byte())
        .then_some((body.start_byte(), body.end_byte()))
}

fn cpp_declarator_initializer<'tree>(
    declaration: Node<'tree>,
    declarator: Node<'tree>,
) -> Option<Node<'tree>> {
    if declarator.kind() == "init_declarator" {
        return declarator.child_by_field_name("value");
    }
    let declarators = cpp_local_declarators(declaration);
    (declarators.len() == 1)
        .then(|| {
            declaration
                .child_by_field_name("value")
                .or_else(|| declaration.child_by_field_name("default_value"))
        })
        .flatten()
}

fn cpp_local_allocation_kind(
    declaration: Node<'_>,
    declarator: Node<'_>,
) -> Option<AllocationKind> {
    if cpp_declarator_preserves_identity(declarator) {
        return None;
    }
    // An array declarator introduces element storage whatever the element type
    // is: `int values[2]` is as much an addressable object as `Holder items[2]`,
    // and without its allocation row no element location has a base object to
    // resolve to (#2665).
    if cpp_declarator_contains_kind(declarator, "array_declarator") {
        return Some(AllocationKind::Array);
    }
    let type_node = declaration.child_by_field_name("type")?;
    if matches!(
        type_node.kind(),
        "primitive_type"
            | "sized_type_specifier"
            | "placeholder_type_specifier"
            | "decltype"
            | "enum_specifier"
    ) {
        return None;
    }
    Some(AllocationKind::Object)
}

/// The index expressions a subscript names.
///
/// The C grammar puts one index in the `index` field; the C++ grammar wraps
/// them in a `subscript_argument_list` under `indices`, which is why a walk
/// that only read named children saw one opaque node where the index is.
fn cpp_subscript_indices(access: Node<'_>) -> Vec<Node<'_>> {
    debug_assert_eq!(access.kind(), "subscript_expression");
    if let Some(indices) = access.child_by_field_name("indices") {
        return named_children(indices);
    }
    access.child_by_field_name("index").into_iter().collect()
}

fn cpp_expression_value_kind(node: Node<'_>) -> SemanticValueKind {
    match node.kind() {
        "number_literal"
        | "char_literal"
        | "string_literal"
        | "raw_string_literal"
        | "concatenated_string"
        | "true"
        | "false"
        | "null"
        | "nullptr" => SemanticValueKind::Constant,
        "lambda_expression" => SemanticValueKind::Callable,
        _ => SemanticValueKind::Temporary,
    }
}

fn cpp_direct_constructor_call(function: Node<'_>) -> bool {
    match function.kind() {
        "type_identifier" | "scoped_type_identifier" | "template_type" => true,
        "qualified_identifier" => function.child_by_field_name("name").is_some_and(|name| {
            matches!(
                name.kind(),
                "type_identifier" | "scoped_type_identifier" | "template_type"
            )
        }),
        _ => false,
    }
}

fn callable_name_node(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "function_definition" => node
            .child_by_field_name("declarator")
            .and_then(declarator_name_node),
        _ => None,
    }
}

fn function_execution_nodes(node: Node<'_>) -> Vec<Node<'_>> {
    let body = node.child_by_field_name("body");
    named_children(node)
        .into_iter()
        .filter(|child| {
            child.kind() == "field_initializer_list"
                || body.is_some_and(|body| child.id() == body.id())
        })
        .collect()
}

fn initializer_values(node: Node<'_>) -> Vec<Node<'_>> {
    match node.kind() {
        "init_declarator" => node.child_by_field_name("value").into_iter().collect(),
        "declaration" | "field_declaration" => {
            let mut values = node
                .child_by_field_name("default_value")
                .into_iter()
                .collect::<Vec<_>>();
            values.extend(node.child_by_field_name("value"));
            values.extend(
                named_children(node)
                    .into_iter()
                    .filter(|child| child.kind() == "init_declarator")
                    .filter_map(|child| child.child_by_field_name("value")),
            );
            values
        }
        "field_initializer_list" => named_children(node)
            .into_iter()
            .filter(|child| child.kind() == "field_initializer")
            .collect(),
        "field_initializer" => named_children(node)
            .into_iter()
            .filter(|child| {
                matches!(child.kind(), "argument_list" | "initializer_list")
                    || is_cpp_expression(child.kind())
            })
            .collect(),
        "init_statement" => named_children(node)
            .into_iter()
            .filter(|child| {
                is_statement_or_declaration(child.kind()) || is_cpp_expression(child.kind())
            })
            .collect(),
        _ => runtime_expression_children(node),
    }
}

fn declaration_runtime_expressions(node: Node<'_>) -> Vec<Node<'_>> {
    if !matches!(node.kind(), "declaration" | "field_declaration") {
        return initializer_values(node);
    }

    let mut expressions = declarator_bound_expressions(node);
    expressions.extend(initializer_values(node));
    expressions
}

fn declarator_bound_expressions(node: Node<'_>) -> Vec<Node<'_>> {
    let mut roots_cursor = node.walk();
    let roots = node
        .children_by_field_name("declarator", &mut roots_cursor)
        .collect::<Vec<_>>();
    let mut expressions = Vec::new();
    let mut stack = roots;
    while let Some(declarator) = stack.pop() {
        if declarator.kind() == "array_declarator"
            && let Some(size) = declarator.child_by_field_name("size")
        {
            expressions.push(size);
        }
        if let Some(inner) = declarator.child_by_field_name("declarator") {
            stack.push(inner);
        } else if matches!(
            declarator.kind(),
            "reference_declarator" | "parenthesized_declarator"
        ) && let Some(inner) = first_named_child(declarator)
        {
            stack.push(inner);
        }
    }
    expressions.sort_unstable_by_key(Node::start_byte);
    expressions
}

fn declaration_may_construct_object(node: Node<'_>) -> bool {
    if matches!(node.kind(), "field_initializer" | "field_initializer_list") {
        return true;
    }
    if !matches!(
        node.kind(),
        "declaration" | "field_declaration" | "parameter_declaration"
    ) {
        return false;
    }
    let type_node = node
        .child_by_field_name("type")
        .or_else(|| first_named_child(node));
    if type_node.is_some_and(|ty| ty.kind() == "primitive_type") {
        return false;
    }

    let mut cursor = node.walk();
    let declarators = node
        .children_by_field_name("declarator", &mut cursor)
        .collect::<Vec<_>>();
    declarators.is_empty()
        || declarators.into_iter().any(|declarator| {
            let indirect = [
                "pointer_declarator",
                "reference_declarator",
                "abstract_pointer_declarator",
                "abstract_reference_declarator",
            ]
            .into_iter()
            .any(|kind| cpp_declarator_contains_kind(declarator, kind));
            !indirect
        })
}

fn condition_value_declaration(condition: Node<'_>) -> Option<Node<'_>> {
    let value = if condition.kind() == "condition_clause" {
        condition.child_by_field_name("value")?
    } else {
        condition
    };
    (value.kind() == "declaration").then_some(value)
}

fn syntax_has_automatic_object(source: &str, trivial: &TrivialTypeIndex, root: Node<'_>) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.id() != root.id()
            && matches!(node.kind(), "function_definition" | "lambda_expression")
        {
            continue;
        }
        if matches!(node.kind(), "declaration" | "field_declaration")
            && declaration_may_construct_object(node)
            && !trivial.declaration_is_trivial(source, node)
            && !["static", "extern", "thread_local"]
                .into_iter()
                .any(|storage| has_storage_class(source, node, storage))
        {
            return true;
        }
        stack.extend(named_children(node));
    }
    false
}

fn block_has_automatic_object(source: &str, trivial: &TrivialTypeIndex, block: Node<'_>) -> bool {
    let mut stack = named_children(block);
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "declaration" | "field_declaration")
            && declaration_may_construct_object(node)
            && !trivial.declaration_is_trivial(source, node)
            && !["static", "extern", "thread_local"]
                .into_iter()
                .any(|storage| has_storage_class(source, node, storage))
        {
            return true;
        }
        if matches!(
            node.kind(),
            "case_statement" | "labeled_statement" | "attributed_statement"
        ) || node.kind().starts_with("preproc_")
        {
            stack.extend(named_children(node));
        }
    }
    false
}

fn block_has_potential_vla(block: Node<'_>) -> bool {
    let mut stack = named_children(block);
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "declaration" | "field_declaration")
            && declarator_bound_expressions(node)
                .into_iter()
                .any(|bound| !matches!(bound.kind(), "number_literal" | "char_literal"))
        {
            return true;
        }
        if matches!(
            node.kind(),
            "case_statement" | "labeled_statement" | "attributed_statement"
        ) || node.kind().starts_with("preproc_")
        {
            stack.extend(named_children(node));
        }
    }
    false
}

fn switch_cases(body: Node<'_>) -> Vec<Node<'_>> {
    let mut cases = Vec::new();
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if node != body
            && matches!(
                node.kind(),
                "switch_statement" | "function_definition" | "lambda_expression"
            )
        {
            continue;
        }
        if node != body && node.kind() == "case_statement" {
            cases.push(node);
        }
        stack.extend(named_children(node).into_iter().rev());
    }
    cases.sort_unstable_by_key(Node::start_byte);
    cases
}

fn case_runtime_children(node: Node<'_>) -> Vec<Node<'_>> {
    let value = node.child_by_field_name("value");
    named_children(node)
        .into_iter()
        .filter(|child| {
            value.is_none_or(|value| value.id() != child.id())
                && is_statement_or_declaration(child.kind())
        })
        .collect()
}

fn call_arguments(node: Node<'_>) -> Vec<Node<'_>> {
    node.child_by_field_name("arguments")
        .map(named_children)
        .unwrap_or_default()
}

fn is_unevaluated_builtin_call(source: &str, node: Node<'_>) -> bool {
    node.kind() == "call_expression"
        && node
            .child_by_field_name("function")
            .filter(|function| function.kind() == "identifier")
            .and_then(|function| node_text(source, function))
            .is_some_and(|name| matches!(name, "noexcept" | "typeid"))
}

fn is_concurrent_spawn_call(source: &str, function: Node<'_>) -> bool {
    structured_call_target_name(source, function).is_some_and(|name| {
        matches!(
            name,
            "thread" | "jthread" | "async" | "pthread_create" | "thrd_create"
        )
    })
}

fn is_deferred_callback_call(source: &str, function: Node<'_>) -> bool {
    structured_call_target_name(source, function)
        .is_some_and(|name| matches!(name, "async" | "atexit" | "at_quick_exit"))
}

fn is_non_local_runtime_call(source: &str, function: Node<'_>) -> bool {
    structured_call_target_name(source, function)
        .is_some_and(|name| matches!(name, "setjmp" | "sigsetjmp" | "longjmp" | "siglongjmp"))
}

fn structured_call_target_name<'source>(
    source: &'source str,
    mut function: Node<'_>,
) -> Option<&'source str> {
    while function.kind() == "parenthesized_expression" {
        function = first_named_child(function)?;
    }
    declarator_name_node(function).and_then(|name| node_text(source, name))
}

fn declaration_constructs_thread(source: &str, declaration: Node<'_>) -> bool {
    declaration
        .child_by_field_name("type")
        .or_else(|| first_named_child(declaration))
        .and_then(declarator_name_node)
        .and_then(|name| node_text(source, name))
        .is_some_and(|name| matches!(name, "thread" | "jthread"))
}

fn lambda_capture_initializers(node: Node<'_>) -> Vec<Node<'_>> {
    node.child_by_field_name("captures")
        .map(named_children)
        .unwrap_or_default()
        .into_iter()
        .filter(|capture| capture.kind() == "lambda_capture_initializer")
        .filter_map(|capture| capture.child_by_field_name("right"))
        .collect()
}

fn call_operand_evaluations<'tree>(node: Node<'tree>, function: Node<'tree>) -> Vec<Node<'tree>> {
    let mut evaluations = Vec::new();
    if node.kind() == "new_expression" {
        if let Some(placement) = node.child_by_field_name("placement") {
            evaluations.extend(named_children(placement));
        }
    } else if let Some(receiver) = cpp_call_receiver(function) {
        evaluations.push(receiver);
    } else if call_target_requires_dispatch_gap(function) {
        evaluations.push(function);
    }
    evaluations.extend(call_arguments(node));
    evaluations
}

fn cpp_call_receiver(mut function: Node<'_>) -> Option<Node<'_>> {
    loop {
        match function.kind() {
            "field_expression" => return function.child_by_field_name("argument"),
            "parenthesized_expression" => function = first_named_child(function)?,
            _ => return None,
        }
    }
}

fn member_dispatch_is_explicitly_qualified(mut function: Node<'_>) -> bool {
    loop {
        match function.kind() {
            "field_expression" => {
                return function
                    .child_by_field_name("field")
                    .is_some_and(|field| field.kind() == "qualified_identifier");
            }
            "parenthesized_expression" => {
                let Some(inner) = first_named_child(function) else {
                    return false;
                };
                function = inner;
            }
            _ => return false,
        }
    }
}

fn is_structurally_unqualified_call_target(mut function: Node<'_>) -> bool {
    loop {
        match function.kind() {
            "identifier" | "field_identifier" | "operator_name" | "destructor_name"
            | "template_function" | "template_method" => return true,
            "parenthesized_expression" => {
                let Some(inner) = first_named_child(function) else {
                    return false;
                };
                function = inner;
            }
            // Qualified identifiers cover both `Base::method()` and
            // namespace-qualified free functions. Neither uses the implicit
            // object dispatch form at this exact syntax point.
            _ => return false,
        }
    }
}

fn call_target_requires_dispatch_gap(mut function: Node<'_>) -> bool {
    loop {
        match function.kind() {
            "identifier"
            | "field_identifier"
            | "namespace_identifier"
            | "type_identifier"
            | "qualified_identifier"
            | "dependent_name"
            | "template_function"
            | "template_method"
            | "operator_name"
            | "destructor_name"
            | "primitive_type"
            | "field_expression" => return false,
            "parenthesized_expression" => {
                let Some(child) = first_named_child(function) else {
                    return true;
                };
                function = child;
            }
            _ => return true,
        }
    }
}

fn expression_may_invoke_overload(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "binary_expression"
            | "unary_expression"
            | "update_expression"
            | "subscript_expression"
            | "field_expression"
            | "pointer_expression"
            | "cast_expression"
            | "fold_expression"
    )
}

fn runtime_expression_children(node: Node<'_>) -> Vec<Node<'_>> {
    match node.kind() {
        "binary_expression" | "assignment_expression" | "comma_expression" => ["left", "right"]
            .into_iter()
            .filter_map(|field| node.child_by_field_name(field))
            .collect(),
        "conditional_expression" => ["condition", "consequence", "alternative"]
            .into_iter()
            .filter_map(|field| node.child_by_field_name(field))
            .collect(),
        "field_expression" => node.child_by_field_name("argument").into_iter().collect(),
        "condition_clause" => ["initializer", "value"]
            .into_iter()
            .filter_map(|field| node.child_by_field_name(field))
            .collect(),
        "call_expression"
        | "new_expression"
        | "lambda_expression"
        | "sizeof_expression"
        | "alignof_expression"
        | "decltype"
        | "noexcept"
        | "offsetof_expression"
        | "requires_expression"
        | "generic_expression" => Vec::new(),
        _ => named_children(node)
            .into_iter()
            .filter(|child| !is_non_runtime_field(node, *child))
            .collect(),
    }
}

fn is_non_runtime_field(parent: Node<'_>, child: Node<'_>) -> bool {
    if is_type_syntax(child.kind()) || is_comment_kind(child.kind()) {
        return true;
    }
    for field in [
        "type",
        "declarator",
        "name",
        "field",
        "operator",
        "label",
        "constraint",
        "template_parameters",
        "parameters",
        "captures",
    ] {
        if parent
            .child_by_field_name(field)
            .is_some_and(|candidate| candidate.id() == child.id())
        {
            return true;
        }
    }
    matches!(
        child.kind(),
        "attribute_declaration"
            | "attribute_specifier"
            | "storage_class_specifier"
            | "type_qualifier"
            | "ms_declspec_modifier"
    )
}

fn first_runtime_named_child(node: Node<'_>) -> Option<Node<'_>> {
    named_children(node)
        .into_iter()
        .find(|child| !is_non_runtime_field(node, *child))
}

fn is_statement_or_declaration(kind: &str) -> bool {
    kind.ends_with("_statement")
        || matches!(
            kind,
            "compound_statement"
                | "translation_unit"
                | "declaration"
                | "field_declaration"
                | "field_initializer"
                | "field_initializer_list"
                | "init_statement"
                | "for_range_loop"
                | "try_statement"
                | "catch_clause"
                | "function_definition"
                | "template_declaration"
                | "namespace_definition"
                | "class_specifier"
                | "struct_specifier"
                | "union_specifier"
                | "enum_specifier"
                | "type_definition"
                | "alias_declaration"
                | "using_declaration"
                | "static_assert_declaration"
                | "attributed_statement"
        )
        || kind.starts_with("preproc_")
}

fn is_cpp_expression(kind: &str) -> bool {
    kind.ends_with("_expression")
        || matches!(
            kind,
            "identifier"
                | "field_identifier"
                | "qualified_identifier"
                | "dependent_name"
                | "template_function"
                | "template_method"
                | "operator_name"
                | "destructor_name"
                | "this"
                | "nullptr"
                | "true"
                | "false"
                | "number_literal"
                | "char_literal"
                | "string_literal"
                | "raw_string_literal"
                | "concatenated_string"
                | "user_defined_literal"
                | "initializer_list"
                | "argument_list"
                | "init_declarator"
                | "condition_clause"
                | "decltype"
                | "noexcept"
        )
}

fn is_runtime_leaf(kind: &str) -> bool {
    matches!(
        kind,
        "identifier"
            | "field_identifier"
            | "qualified_identifier"
            | "dependent_name"
            | "template_function"
            | "template_method"
            | "operator_name"
            | "destructor_name"
            | "this"
            | "nullptr"
            | "null"
            | "true"
            | "false"
            | "number_literal"
            | "char_literal"
            | "string_literal"
            | "raw_string_literal"
            | "concatenated_string"
            | "user_defined_literal"
    )
}

fn is_type_syntax(kind: &str) -> bool {
    kind.ends_with("_type")
        || kind.ends_with("_specifier")
        || kind.ends_with("_declarator")
        || kind.ends_with("_parameter")
        || matches!(
            kind,
            "primitive_type"
                | "type_identifier"
                | "type_descriptor"
                | "sized_type_specifier"
                | "placeholder_type_specifier"
                | "decltype"
                | "auto"
                | "parameter_list"
                | "template_parameter_list"
                | "requires_clause"
                | "namespace_identifier"
                | "access_specifier"
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

fn has_direct_token(node: Node<'_>, kind: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor).any(|child| child.kind() == kind)
}

fn is_comment_kind(kind: &str) -> bool {
    matches!(kind, "comment" | "line_comment" | "block_comment")
}

fn required_field<'tree>(node: Node<'tree>, field: &str) -> Result<Node<'tree>, CppLoweringError> {
    node.child_by_field_name(field)
        .ok_or_else(|| missing_field(node, field))
}

fn missing_field(node: Node<'_>, field: &str) -> CppLoweringError {
    CppLoweringError::Invalid(format!(
        "{} node at bytes {}..{} is missing structured field {field}",
        node.kind(),
        node.start_byte(),
        node.end_byte()
    ))
}

fn binary_operator(node: Node<'_>) -> Option<&'static str> {
    match node.child_by_field_name("operator")?.kind() {
        "&&" | "and" => Some("&&"),
        "||" | "or" => Some("||"),
        _ => None,
    }
}

fn assignment_operator(node: Node<'_>) -> Option<&str> {
    node.child_by_field_name("operator")
        .map(|operator| operator.kind())
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::analyzer::LanguageDialect;
    use crate::analyzer::tree_sitter_analyzer::{PreparedSourceOrigin, PreparedSyntaxSource};
    use crate::text_utils::compute_line_starts;

    /// Lower one C++ fixture and return the named procedure's parts.
    fn lower_procedure_named(source: &str, procedure_name: &str) -> ProcedureSemanticsParts {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("C++ grammar is valid");
        let tree = parser.parse(source, None).expect("fixture parses");
        let prepared = PreparedSyntaxTree::new(
            PreparedSyntaxSource::Exact(Arc::<str>::from(source)),
            tree,
            compute_line_starts(source),
            LanguageDialect::Standard(Language::Cpp),
            PreparedSourceOrigin::Disk,
            None,
        );
        let file = ProjectFile::new(std::env::temp_dir(), "fixture.cpp");
        let SemanticOutcome::Complete { value, .. } = CppSemanticLowerer
            .lower(
                &file,
                &prepared,
                &SemanticBudget::default(),
                &CancellationToken::default(),
            )
            .expect("C++ lowering succeeds")
        else {
            panic!("C++ fixture lowering must complete");
        };
        value
            .into_iter()
            .find(|parts| {
                parts
                    .locator
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some(procedure_name)
            })
            .unwrap_or_else(|| panic!("fixture declares procedure {procedure_name}"))
    }

    fn effects(parts: &ProcedureSemanticsParts) -> Vec<&SemanticEffect> {
        parts
            .points
            .iter()
            .flat_map(|point| point.events.iter())
            .map(|event| &event.effect)
            .collect()
    }

    /// A by-value scalar relay is a value transfer, not a decline (#2666, #2665).
    #[test]
    fn by_value_scalar_return_and_local_publish_value_flow_without_a_gap() {
        const SOURCE: &str = r#"
int produce();

int relay(int value) {
    return value;
}

void run() {
    int result = relay(produce());
}
"#;

        let relay = lower_procedure_named(SOURCE, "relay");
        assert!(
            effects(&relay).iter().any(|effect| matches!(
                effect,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Return,
                    ..
                }
            )),
            "a by-value fundamental return transfers its operand into the returned value: {:#?}",
            relay.points
        );
        assert!(
            relay.gaps.is_empty(),
            "a fundamental-typed relay declines nothing: {:#?}",
            relay.gaps
        );

        let run = lower_procedure_named(SOURCE, "run");
        let run_effects = effects(&run);
        let assigned = run_effects
            .iter()
            .find_map(|effect| match effect {
                SemanticEffect::Assignment { target, value } => Some((*target, *value)),
                _ => None,
            })
            .unwrap_or_else(|| {
                panic!("the declared local is written by its initializer: {run_effects:#?}")
            });
        assert!(
            run_effects.iter().any(|effect| matches!(
                effect,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Local,
                    source,
                    target,
                } if (*target, *source) == assigned
            )),
            "the initializer's value also flows into the local: {run_effects:#?}"
        );
        assert!(
            !run.gaps.iter().any(|gap| matches!(
                gap.capability,
                SemanticCapability::Values | SemanticCapability::Assignments
            )),
            "a fundamental-typed local initialized from a call declines no value or assignment; \
             only the call target itself stays open to refinement: {:#?}",
            run.gaps
        );
    }

    /// A class-typed by-value initialization may construct, convert, copy or
    /// move a distinct object, so it stays declined -- but the decline is this
    /// adapter's decision (`Unsupported`), it names the declared object rather
    /// than the statement, and it leaves the proven siblings alone (#2666).
    #[test]
    fn class_typed_by_value_initializer_declines_only_its_own_object() {
        const SOURCE: &str = r#"
struct Holder {
    int value;
};

Holder produce() {
    Holder made;
    return made;
}

void run() {
    Holder held = produce();
    int plain = 1;
}
"#;

        let run = lower_procedure_named(SOURCE, "run");
        let declines: Vec<&SemanticGap> = run
            .gaps
            .iter()
            .filter(|gap| gap.capability == SemanticCapability::Assignments)
            .collect();
        assert_eq!(
            declines.len(),
            1,
            "only the class-typed initializer declines: {:#?}",
            run.gaps
        );
        let decline = declines[0];
        assert_eq!(
            decline.kind,
            SemanticGapKind::Unsupported,
            "the conversion gate is a standing decision, not missing information: {decline:#?}"
        );
        assert!(
            matches!(decline.subject, SemanticGapSubject::Value(_)),
            "the decline names the declared object, not the whole point: {decline:#?}"
        );
        let run_effects = effects(&run);
        assert!(
            run_effects.iter().any(|effect| matches!(
                effect,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Local,
                    ..
                }
            )),
            "the fundamental-typed sibling local is still written: {run_effects:#?}"
        );
    }

    /// An automatic object of a class that has no base, declares nothing but
    /// data members of trivial type, and default-initializes none of them
    /// runs no constructor and needs no destructor. Declining its cleanup or
    /// its lifetime calls would claim code exists where none does (#2666).
    #[test]
    fn a_trivially_destructible_automatic_object_opens_no_lifetime_decline() {
        const SOURCE: &str = r#"
struct Trivial {
    int value;
};

void run() {
    Trivial local;
    local.value = 1;
}
"#;

        let run = lower_procedure_named(SOURCE, "run");
        assert!(
            !run.gaps.iter().any(|gap| matches!(
                gap.capability,
                SemanticCapability::ResourceManagement | SemanticCapability::CleanupControlFlow
            )),
            "a trivially destructible automatic object opens no RAII boundary: {:#?}",
            run.gaps
        );
    }
}
