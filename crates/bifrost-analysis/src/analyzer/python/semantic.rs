//! Python lowering into the language-neutral executable-semantics IR.
//!
//! This module deliberately interprets tree-sitter nodes and fields directly.
//! Graph construction, abrupt-completion routing, cleanup specialization, and
//! physical adjacency storage remain owned by the shared semantic substrate.

use tree_sitter::Node;

use super::lexical_scope::python_lexical_scope_inventory_bounded;
use crate::analyzer::lexical_definitions::{PythonMethodBinding, formal_parameter_slots_for_owner};
use crate::analyzer::semantic::cfg::{
    CleanupRegionId, CompletionKind, CompletionRequest, CompletionRoute, ProcedureCfgBuilder,
    ScopeBinding, ScopeFrameId,
};
use crate::analyzer::semantic::service::{ProgramSemanticsLowerer, SemanticAdapterIdentity};
use crate::analyzer::semantic::*;
use crate::analyzer::semantic_model::{
    SemanticModelCallApplication, SemanticModelCallableDisposition, SemanticModelCallableKey,
    SemanticModelOverlay, TypeRef,
};
use crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree;
use crate::analyzer::{IAnalyzer, Language, ProjectFile, PythonAnalyzer, StructuredImportPathKind};
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_python::bindings::{
    PythonDirectScopeBindingKind, PythonLexicalNameResolution, PythonLexicalScopeInventory,
    python_direct_scope_bindings_bounded, python_module_or_class_scope_binds_name_bounded,
};
use brokk_bifrost_python::imports::python_import_infos_from_node;
use brokk_bifrost_python::syntax::{python_static_attribute_path, python_static_type_path};
use std::sync::Arc;

const ADAPTER_VERSION: &[u8] = b"python-value-semantics-v29";

const PYTHON_UNKNOWN_ITERATION_ELEMENT: &str = "python.unknown_iteration_element";
const PYTHON_UNKNOWN_UNPACK_ELEMENT: &str = "python.unknown_unpack_element";
const PYTHON_UNKNOWN_AUGMENTED_ASSIGNMENT: &str = "python.unknown_augmented_assignment";

impl_program_semantics_provider!(PythonAnalyzer, |analyzer| PythonSemanticLowerer::new(
    analyzer
));

struct PythonSemanticLowerer {
    overlay: Option<Arc<SemanticModelOverlay>>,
    dependencies: DependencyFingerprint,
}

impl PythonSemanticLowerer {
    fn new(analyzer: &PythonAnalyzer) -> Self {
        let snapshot = analyzer.active_semantic_model_snapshot();
        let dependencies = snapshot.as_ref().map_or_else(
            || DependencyFingerprint::hash_bytes(b"no-intrafile-dependencies"),
            |snapshot| {
                let mut identity = b"python-semantic-model-set-v1\0".to_vec();
                identity
                    .extend_from_slice(snapshot.active_models().active_model_set_hash().as_bytes());
                DependencyFingerprint::hash_bytes(&identity)
            },
        );
        Self {
            overlay: snapshot
                .as_ref()
                .and_then(|snapshot| snapshot.semantic_model_overlay().cloned()),
            dependencies,
        }
    }
}

impl ProgramSemanticsLowerer for PythonSemanticLowerer {
    fn identity(&self) -> SemanticAdapterIdentity {
        SemanticAdapterIdentity {
            adapter: AdapterSemanticsVersion::hash_bytes("python", ADAPTER_VERSION)
                .expect("adapter name is non-empty"),
            configuration: ConfigurationFingerprint::hash_bytes(
                b"python-intrafile-execution-defaults-v1",
            ),
            dependencies: self.dependencies,
        }
    }

    fn capabilities(&self) -> SemanticCapabilities {
        python_capabilities()
    }

    fn lower(
        &self,
        file: &ProjectFile,
        prepared: &PreparedSyntaxTree,
        budget: &SemanticBudget,
        cancellation: &CancellationToken,
    ) -> Result<SemanticOutcome<Vec<ProcedureSemanticsParts>>, SemanticProviderError> {
        let (
            specs,
            module_bindings,
            module_has_wildcard_import,
            class_names,
            class_constructors,
            builtin_proofs,
            initial_work,
        ) = match enumerate_procedures(file, prepared, budget, cancellation)? {
            ProcedureEnumeration::Complete {
                value,
                initial_work,
                ..
            } => (
                value.specs,
                value.module_bindings,
                value.module_has_wildcard_import,
                value.class_names,
                value.class_constructors,
                value.builtin_proofs,
                initial_work,
            ),
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

        let mut binding_inventories = HashMap::default();
        lower_procedure_batch(
            &specs,
            initial_work,
            budget,
            cancellation,
            |spec, staged_budget, cancellation| {
                lower_procedure(
                    prepared,
                    spec,
                    &module_bindings,
                    module_has_wildcard_import,
                    &class_names,
                    &class_constructors,
                    builtin_proofs,
                    self.overlay.as_deref(),
                    &mut binding_inventories,
                    staged_budget,
                    cancellation,
                )
            },
        )
    }
}

fn python_capabilities() -> SemanticCapabilities {
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
        SemanticCapability::FieldMemory,
        SemanticCapability::IndexMemory,
        SemanticCapability::LocalFlow,
        SemanticCapability::ParameterFlow,
        SemanticCapability::ReceiverFlow,
        SemanticCapability::Captures,
        SemanticCapability::ResourceManagement,
        SemanticCapability::DeferredExecution,
        SemanticCapability::AsyncSuspendResume,
        SemanticCapability::GeneratorSuspension,
    ] {
        builder = builder.partial(capability);
    }
    builder = builder.partial(SemanticCapability::GuardFacts);
    builder.build()
}

#[derive(Clone)]
struct ProcedureSpec<'tree> {
    id: ProcedureId,
    callable: Node<'tree>,
    body: Node<'tree>,
    locator: SemanticLocator,
    lexical_parent: Option<ProcedureId>,
    kind: ProcedureKind,
    properties: ProcedureProperties,
    mutable_captures: HashSet<Box<str>>,
}

struct PythonProcedureInventory<'tree> {
    specs: Vec<ProcedureSpec<'tree>>,
    module_bindings: HashMap<Box<str>, PythonModuleBinding<'tree>>,
    module_has_wildcard_import: bool,
    class_names: HashSet<Box<str>>,
    class_constructors: HashMap<Box<str>, ProcedureId>,
    builtin_proofs: PythonBuiltinProofs,
}

enum PythonModuleBinding<'tree> {
    Class,
    Function(Node<'tree>),
    Import(PythonModuleImport),
    Other,
}

struct PythonModuleImport {
    canonical_path: Box<[Box<str>]>,
    consumed_attributes: usize,
}

/// Whether each builtin this lowering reads still denotes its builtin at the
/// module level. A module binding of the same name, or a wildcard import that
/// could introduce one, removes the proof for that name alone.
#[derive(Debug, Clone, Copy)]
struct PythonBuiltinProofs {
    range: bool,
    exception: bool,
    str: bool,
    isinstance: bool,
    hasattr: bool,
    r#type: bool,
    exit: bool,
    quit: bool,
}

type ProcedureEnumeration<'tree> = ProcedureInventoryOutcome<PythonProcedureInventory<'tree>>;

struct ProcedureEnumerationFrame<'tree> {
    node: Node<'tree>,
    lexical_parent: Option<ProcedureId>,
    declaration_path: usize,
    entry_precharged: bool,
}

fn enumerate_procedures<'tree>(
    file: &ProjectFile,
    prepared: &'tree PreparedSyntaxTree,
    budget: &SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<ProcedureEnumeration<'tree>, SemanticProviderError> {
    let root = prepared.tree().root_node();
    let mut inventory =
        ProcedureInventoryBuilder::new(file, prepared.dialect(), root, "python-source", budget)?;
    let mut specs = Vec::new();
    let mut module_bindings: HashMap<Box<str>, PythonModuleBinding<'tree>> = HashMap::default();
    let mut module_wildcard_import = false;
    let mut stack = vec![ProcedureEnumerationFrame {
        node: root,
        lexical_parent: None,
        declaration_path: inventory.root_path(),
        entry_precharged: false,
    }];

    while let Some(frame) = stack.pop() {
        if cancellation.is_cancelled() {
            return Ok(inventory.cancelled());
        }
        if !frame.entry_precharged
            && let Err(stop) = inventory.charge_traversal_entry()
        {
            return Ok(stop.into_outcome());
        }

        if frame.lexical_parent.is_none() && frame.declaration_path == inventory.root_path() {
            let mut binding_scan_cancelled = false;
            let mut binding_scan_exceeded = None;
            let bindings =
                python_direct_scope_bindings_bounded(frame.node, prepared.source(), || {
                    if cancellation.is_cancelled() {
                        binding_scan_cancelled = true;
                        return false;
                    }
                    match inventory.charge_traversal_entry() {
                        Ok(()) => true,
                        Err(stop) => {
                            binding_scan_exceeded = Some(stop);
                            false
                        }
                    }
                });
            let Some(bindings) = bindings else {
                if binding_scan_cancelled {
                    return Ok(inventory.cancelled());
                }
                let stop =
                    binding_scan_exceeded.expect("bounded binding scan stopped without a cause");
                return Ok(stop.into_outcome());
            };
            if frame.node.kind() == "import_from_statement"
                && named_children(frame.node)
                    .into_iter()
                    .any(|child| child.kind() == "wildcard_import")
            {
                module_wildcard_import = true;
            }
            for binding in bindings {
                let Some(name) = node_text(prepared.source(), binding.declaration) else {
                    continue;
                };
                if let Some(existing) = module_bindings.get_mut(name) {
                    // Multiple module bindings are not a proven class identity,
                    // callable identity, or import identity.
                    *existing = PythonModuleBinding::Other;
                    continue;
                }
                if let Err(stop) = inventory.observe_additional_work(SemanticWork {
                    owned_text_bytes: name.len(),
                    ..SemanticWork::default()
                }) {
                    return Ok(stop.into_outcome());
                }
                module_bindings.insert(
                    name.into(),
                    python_module_binding(frame.node, binding.kind, name, prepared.source()),
                );
            }
        }

        let child_path = frame.declaration_path;
        let mut container_body_scope = None;
        if let Some(segment_kind) = declaration_container_kind(frame.node) {
            let name = declaration_container_name(prepared.source(), frame.node);
            let anchor =
                source_anchor(frame.node, 0).map_err(SemanticProviderError::invalid_identity)?;
            let container_path = inventory.push_container(
                frame.declaration_path,
                segment_kind,
                name.as_deref(),
                anchor,
            )?;
            if let Some(body) = frame.node.child_by_field_name("body") {
                container_body_scope = Some((body.id(), container_path));
            }
        }

        let mut callable_body_scope = None;
        if let Some((kind, segment_kind, body, properties)) =
            callable_shape(prepared.source(), frame.node, frame.lexical_parent)
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
            specs.push(ProcedureSpec {
                id: identity.id,
                callable: frame.node,
                body,
                locator: identity.locator,
                lexical_parent: frame.lexical_parent,
                kind,
                properties,
                mutable_captures: HashSet::default(),
            });
            callable_body_scope = Some((body.id(), identity.id, identity.declaration_path));
        }

        if frame.node.kind() == "nonlocal_statement"
            && let Some(callable) = frame.lexical_parent
        {
            for declaration in named_children(frame.node) {
                let Some(name) = node_text(prepared.source(), declaration) else {
                    continue;
                };
                // Capture writes are not modeled yet. Conservatively open this
                // name in enclosing callables; a nearer binding may shadow it.
                // Reuse enumeration rather than rescanning each ancestor body.
                let mut ancestor = specs[callable.index()].lexical_parent;
                while let Some(owner) = ancestor {
                    if cancellation.is_cancelled() {
                        return Ok(inventory.cancelled());
                    }
                    if let Err(stop) = inventory.observe_additional_work(SemanticWork {
                        nested_entries: 1,
                        owned_text_bytes: name.len(),
                        ..SemanticWork::default()
                    }) {
                        return Ok(stop.into_outcome());
                    }
                    let spec = &mut specs[owner.index()];
                    assert_eq!(spec.id, owner);
                    spec.mutable_captures.insert(name.into());
                    ancestor = spec.lexical_parent;
                }
            }
        }

        for child_index in (0..frame.node.child_count()).rev() {
            if cancellation.is_cancelled() {
                return Ok(inventory.cancelled());
            }
            let Some(child) = frame
                .node
                .child(child_index)
                .filter(|child| child.is_named())
            else {
                continue;
            };
            if let Err(stop) = inventory.charge_traversal_entry() {
                return Ok(stop.into_outcome());
            }
            let child_path = container_body_scope
                .filter(|(body_id, _)| *body_id == child.id())
                .map(|(_, path)| path)
                .unwrap_or(child_path);
            let (lexical_parent, declaration_path) = callable_body_scope
                .filter(|(body_id, _, _)| *body_id == child.id())
                .map(|(_, procedure, path)| (Some(procedure), path))
                .unwrap_or((frame.lexical_parent, child_path));
            stack.push(ProcedureEnumerationFrame {
                node: child,
                lexical_parent,
                declaration_path,
                entry_precharged: true,
            });
        }
    }

    if !module_wildcard_import {
        for spec in &mut specs {
            if spec.properties.call_boundary != ProcedureCallBoundary::Unknown {
                continue;
            }
            let mut stopped = None;
            let preserves = builtin_descriptor_preserves_call_boundary(
                spec.callable,
                prepared.source(),
                &module_bindings,
                || {
                    if cancellation.is_cancelled() {
                        return false;
                    }
                    match inventory.charge_traversal_entry() {
                        Ok(()) => true,
                        Err(stop) => {
                            stopped = Some(stop);
                            false
                        }
                    }
                },
            );
            let Some(preserves) = preserves else {
                if cancellation.is_cancelled() {
                    return Ok(inventory.cancelled());
                }
                return Ok(stopped
                    .expect("descriptor proof stopped without a cause")
                    .into_outcome());
            };
            if preserves {
                spec.properties.call_boundary = ProcedureCallBoundary::Direct;
            }
        }
    }

    let unshadowed = |name: &str| !module_bindings.contains_key(name) && !module_wildcard_import;
    let builtin_proofs = PythonBuiltinProofs {
        range: unshadowed("range"),
        exception: unshadowed("Exception"),
        str: unshadowed("str"),
        isinstance: unshadowed("isinstance"),
        hasattr: unshadowed("hasattr"),
        r#type: unshadowed("type"),
        exit: unshadowed("exit"),
        quit: unshadowed("quit"),
    };
    let class_names = module_bindings
        .iter()
        .filter_map(|(name, binding)| {
            matches!(binding, PythonModuleBinding::Class).then_some(name.clone())
        })
        .collect();
    let class_constructors = specs
        .iter()
        .filter(|spec| spec.kind == ProcedureKind::Constructor)
        .filter_map(|spec| {
            let class = enclosing_class_definition(spec.callable)?;
            if !class
                .parent()
                .is_some_and(|parent| parent.kind() == "module")
            {
                return None;
            }
            let name = class
                .child_by_field_name("name")
                .and_then(|name| node_text(prepared.source(), name))?;
            Some((name.into(), spec.id))
        })
        .collect();
    Ok(inventory.complete(PythonProcedureInventory {
        specs,
        module_bindings,
        module_has_wildcard_import: module_wildcard_import,
        class_names,
        class_constructors,
        builtin_proofs,
    }))
}

fn python_module_binding<'tree>(
    node: Node<'tree>,
    kind: PythonDirectScopeBindingKind,
    local_name: &str,
    source: &str,
) -> PythonModuleBinding<'tree> {
    if kind == PythonDirectScopeBindingKind::ClassDeclaration {
        return PythonModuleBinding::Class;
    }
    if node.kind() == "function_definition"
        && node
            .parent()
            .is_some_and(|parent| parent.kind() == "module")
    {
        return PythonModuleBinding::Function(node);
    }
    if !matches!(node.kind(), "import_statement" | "import_from_statement")
        || node.parent().is_none_or(|parent| parent.kind() != "module")
    {
        return PythonModuleBinding::Other;
    }
    let mut matches = python_import_infos_from_node(node, source)
        .into_iter()
        .filter(|import| !import.is_wildcard && import.local_name() == Some(local_name));
    let Some(import) = matches.next() else {
        return PythonModuleBinding::Other;
    };
    if matches.next().is_some() {
        return PythonModuleBinding::Other;
    }
    let Some(path) = import.path else {
        return PythonModuleBinding::Other;
    };
    let consumed_attributes =
        if path.kind == Some(StructuredImportPathKind::Namespace) && import.alias.is_none() {
            path.segments.len().saturating_sub(1)
        } else {
            0
        };
    PythonModuleBinding::Import(PythonModuleImport {
        canonical_path: path
            .segments
            .into_iter()
            .map(String::into_boxed_str)
            .collect(),
        consumed_attributes,
    })
}

/// The built-in descriptors keep the authored callable's parameters and
/// returns; the existing method-binding lowering accounts for their receiver.
/// Prove the built-in identity in an ordinary class namespace rather than
/// trusting the decorator's spelling. Other scopes and transformations remain
/// unknown until their name and namespace contracts are modeled.
fn builtin_descriptor_preserves_call_boundary(
    callable: Node<'_>,
    source: &str,
    module_bindings: &HashMap<Box<str>, PythonModuleBinding<'_>>,
    mut scope_step: impl FnMut() -> bool,
) -> Option<bool> {
    if !scope_step() {
        return None;
    }
    let decorated = callable.parent().expect("decorated callable has a parent");
    debug_assert_eq!(decorated.kind(), "decorated_definition");
    let Some(class) = decorated.parent().and_then(|body| body.parent()) else {
        return Some(false);
    };
    if class.kind() != "class_definition"
        || class
            .child_by_field_name("superclasses")
            .is_some_and(|bases| bases.named_child_count() != 0)
    {
        return Some(false);
    }
    let parent = class
        .parent()
        .expect("class declaration has an enclosing scope");
    let outer = if parent.kind() == "decorated_definition" {
        parent
            .parent()
            .expect("decorated class has an enclosing scope")
    } else {
        parent
    };
    if outer.kind() != "module" {
        return Some(false);
    }
    let mut expression = None;
    let mut cursor = decorated.walk();
    for child in decorated.named_children(&mut cursor) {
        if !scope_step() {
            return None;
        }
        if child.kind() == "decorator" {
            if expression.is_some() {
                return Some(false);
            }
            expression = child.named_child(0);
        }
    }
    let Some(expression) = expression.filter(|node| node.kind() == "identifier") else {
        return Some(false);
    };
    let Some(name @ ("staticmethod" | "classmethod")) = node_text(source, expression) else {
        return Some(false);
    };
    if module_bindings.contains_key(name) {
        return Some(false);
    }
    python_module_or_class_scope_binds_name_bounded(class, name, source, scope_step)
        .map(|shadowed| !shadowed)
}

fn declaration_container_kind(node: Node<'_>) -> Option<DeclarationSegmentKind> {
    (node.kind() == "class_definition").then_some(DeclarationSegmentKind::Type)
}

fn declaration_container_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    node.child_by_field_name("name")
        .and_then(|name| nonempty_node_text(source, name))
        .map(Box::<str>::from)
}

fn callable_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    node.child_by_field_name("name")
        .and_then(|name| nonempty_node_text(source, name))
        .map(Box::<str>::from)
        .or_else(|| enclosing_binding_name(source, node))
}

fn enclosing_binding_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    let mut value = node;
    loop {
        let parent = value.parent()?;
        match parent.kind() {
            "parenthesized_expression" => value = parent,
            "assignment" if field_matches(parent, "right", value) => {
                return parent
                    .child_by_field_name("left")
                    .and_then(|left| nonempty_node_text(source, left))
                    .map(Box::<str>::from);
            }
            "named_expression" if field_matches(parent, "value", value) => {
                return parent
                    .child_by_field_name("name")
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
) -> Option<(
    ProcedureKind,
    DeclarationSegmentKind,
    Node<'tree>,
    ProcedureProperties,
)> {
    let (kind, segment_kind, body) = match node.kind() {
        "function_definition" => {
            let kind = python_function_kind(node, lexical_parent);
            // `__init__` is Python's constructor: a class call `A(...)`
            // dispatches to it, and the dispatch oracle matches a class
            // definition only against Constructor-kind procedures
            // (`procedure_matches_definition`). The method-kind gate keeps a
            // module-level `def __init__` an ordinary function.
            let kind = if kind == ProcedureKind::Method
                && callable_name(source, node).as_deref() == Some("__init__")
            {
                ProcedureKind::Constructor
            } else {
                kind
            };
            let segment = match kind {
                ProcedureKind::Method => DeclarationSegmentKind::Method,
                ProcedureKind::Constructor => DeclarationSegmentKind::Constructor,
                ProcedureKind::LocalFunction => DeclarationSegmentKind::LocalFunction,
                _ => DeclarationSegmentKind::Function,
            };
            (kind, segment, callable_body(node)?)
        }
        "lambda" => (
            ProcedureKind::Lambda,
            DeclarationSegmentKind::Lambda,
            callable_body(node)?,
        ),
        _ => return None,
    };
    let is_async = has_direct_token(node, "async");
    let is_generator = body_contains_yield(body);
    // A decorator may replace the function object that callers invoke, so the
    // authored parameters and returns are not an authoritative call boundary.
    // This deliberately uses only the AST relationship: even wraps-like
    // metadata does not prove that the replacement preserves the boundary.
    let call_boundary = if node
        .parent()
        .is_some_and(|parent| parent.kind() == "decorated_definition")
    {
        ProcedureCallBoundary::Unknown
    } else {
        ProcedureCallBoundary::Direct
    };
    // PEP 591 is Python's own closed-dispatch declaration, and it is the only
    // one the language has: `@final` on a method forbids an override, and
    // `@final` on a class forbids a subclass, so no override of any of its
    // methods can exist. Java reaches the same conclusion from `final` and
    // publishes `DispatchExtensibility::Closed` for it; a Python method that
    // carries the same declaration is closed for the same reason (#2495).
    // Everything else stays `Open`, the correct default for a language whose
    // classes are extensible unless they say otherwise.
    let dispatch_extensibility =
        if matches!(kind, ProcedureKind::Method | ProcedureKind::Constructor)
            && (has_final_decorator(source, node) || enclosing_class_is_final(source, node))
        {
            DispatchExtensibility::Closed
        } else {
            DispatchExtensibility::Open
        };
    Some((
        kind,
        segment_kind,
        body,
        ProcedureProperties {
            is_async,
            is_generator,
            is_static: false,
            is_synthetic: false,
            invocation: if is_async || is_generator {
                ProcedureInvocationKind::Deferred
            } else {
                ProcedureInvocationKind::Immediate
            },
            construction_return: if kind == ProcedureKind::Constructor {
                crate::analyzer::semantic::ConstructionReturn::PreservesAllocation
            } else {
                crate::analyzer::semantic::ConstructionReturn::MayReplaceAllocation
            },
            dispatch_extensibility,
            call_boundary,
            receiver_binding: if formal_parameter_slots_for_owner(Language::Python, node, source)
                .is_some_and(|layout| layout.python_binding == Some(PythonMethodBinding::Class))
            {
                crate::analyzer::semantic::ProcedureReceiverBinding::Class
            } else {
                crate::analyzer::semantic::ProcedureReceiverBinding::Instance
            },
        },
    ))
}

/// Whether `definition` carries a `@final` decorator.
///
/// The decorator is matched by the name it is written with -- `final`, or a
/// qualified `<module>.final` -- which is the standard the structural
/// `decorators` role already applies. An intra-file lowering has no resolved
/// annotation type to consult, so an aliased import (`from typing import final
/// as sealed`) is not recognized and the method stays open. That is the safe
/// direction: a missed `@final` costs a discharge, it never manufactures one.
fn has_final_decorator(source: &str, definition: Node<'_>) -> bool {
    let Some(decorated) = definition.parent().filter(|parent| {
        parent.kind() == "decorated_definition"
            && parent.child_by_field_name("definition") == Some(definition)
    }) else {
        return false;
    };
    let mut cursor = decorated.walk();
    decorated
        .children(&mut cursor)
        .filter(|child| child.kind() == "decorator")
        .filter_map(|decorator| decorator.named_child(0))
        .any(|expression| match expression.kind() {
            "identifier" => node_text(source, expression) == Some("final"),
            "attribute" => {
                expression
                    .child_by_field_name("attribute")
                    .and_then(|attribute| node_text(source, attribute))
                    == Some("final")
            }
            _ => false,
        })
}

/// Whether the class body that lexically encloses `node` is `@final`.
///
/// The walk mirrors [`python_function_kind`]: a `function_definition` or
/// `lambda` between `node` and a class body means `node` is a local function
/// rather than that class's method, so the class's declaration says nothing
/// about it.
fn enclosing_class_is_final(source: &str, node: Node<'_>) -> bool {
    enclosing_class_definition(node).is_some_and(|class| has_final_decorator(source, class))
}

fn enclosing_class_definition(node: Node<'_>) -> Option<Node<'_>> {
    let mut parent = node.parent();
    while let Some(candidate) = parent {
        match candidate.kind() {
            "class_definition" => return Some(candidate),
            "function_definition" | "lambda" => return None,
            _ => parent = candidate.parent(),
        }
    }
    None
}

fn enclosing_class_name<'source>(source: &'source str, node: Node<'_>) -> Option<&'source str> {
    enclosing_class_definition(node)
        .and_then(|class| class.child_by_field_name("name"))
        .and_then(|name| node_text(source, name))
}

fn python_function_kind(node: Node<'_>, lexical_parent: Option<ProcedureId>) -> ProcedureKind {
    let mut parent = node.parent();
    while let Some(candidate) = parent {
        match candidate.kind() {
            "decorated_definition" | "block" => parent = candidate.parent(),
            "class_definition" => return ProcedureKind::Method,
            "function_definition" | "lambda" => return ProcedureKind::LocalFunction,
            _ => parent = candidate.parent(),
        }
    }
    if lexical_parent.is_some() {
        ProcedureKind::LocalFunction
    } else {
        ProcedureKind::Function
    }
}

fn callable_body(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("body")
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
        if node.kind() == "yield" {
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

type PythonLoweringError = ProcedureLoweringError;

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
    ComprehensionClause {
        node: Node<'tree>,
        index: usize,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
    },
    // A statement condition only routes control, preserving the shared arm
    // targets that scope conditional analysis evidence.
    Condition {
        node: Node<'tree>,
        entry: ProgramPointId,
        when_true: EdgeTarget,
        when_false: EdgeTarget,
        scope: ScopeFrameId,
    },
    // A condition evaluated as an expression must also retain the selected
    // operand value before continuing along its truth edge.
    ValueCondition {
        node: Node<'tree>,
        entry: ProgramPointId,
        when_true: EdgeTarget,
        when_false: EdgeTarget,
        scope: ScopeFrameId,
    },
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
    /// A `with` statement runs the implicit `__exit__` of every context
    /// manager it entered at the construct's own exit, so the region carries
    /// the statement whose clause names those context managers.
    WithStatement(Node<'tree>),
}

impl<'tree> CleanupBody<'tree> {
    const fn source_node(self) -> Node<'tree> {
        match self {
            Self::Statement(node) | Self::WithStatement(node) => node,
        }
    }
}

struct ComprehensionBindings<'tree> {
    values: HashMap<Box<str>, ValueId>,
    outer_iterables: Vec<Node<'tree>>,
    clauses: Vec<Node<'tree>>,
}

struct LoweringContext<'tree, 'targets> {
    prepared: &'tree PreparedSyntaxTree,
    callable: Node<'tree>,
    session: ProcedureLoweringSession<'targets>,
    expression_values: HashMap<usize, ValueId>,
    constant_index_values: HashMap<u64, ValueId>,
    field_locators: HashMap<Box<str>, SemanticLocator>,
    known_list_bindings: HashSet<Box<str>>,
    known_sequence_bindings: HashSet<Box<str>>,
    failing_tuple_mutations: HashSet<SourceSpan>,
    known_instance_bindings: HashMap<Box<str>, Box<str>>,
    known_instance_fields: HashMap<Box<str>, HashSet<Box<str>>>,
    known_binding_available_after: HashMap<Box<str>, usize>,
    /// Start byte of the first whole-value consumption of each proven
    /// allocation root, projected onto every binding that names it. A callee
    /// that receives the object can rebind its attributes or install a
    /// descriptor, so only an access that ends before this byte is proven.
    known_binding_escapes_after: HashMap<Box<str>, usize>,
    proven_instance_fields: HashMap<Box<str>, HashSet<Box<str>>>,
    catch_binders: HashMap<ProgramPointId, ValueId>,
    parameters: HashMap<Box<str>, ValueId>,
    locals: HashMap<Box<str>, ValueId>,
    comprehension_bindings: HashMap<usize, ComprehensionBindings<'tree>>,
    mutable_captures: &'targets HashSet<Box<str>>,
    receiver: Option<ValueId>,
    enclosing_class: Option<Box<str>>,
    module_bindings: &'targets HashMap<Box<str>, PythonModuleBinding<'tree>>,
    module_has_wildcard_import: bool,
    class_names: &'targets HashSet<Box<str>>,
    class_constructors: &'targets HashMap<Box<str>, ProcedureId>,
    builtin_proofs: PythonBuiltinProofs,
    overlay: Option<&'targets SemanticModelOverlay>,
    bindings: &'targets PythonLexicalScopeInventory<'tree>,
    binding_inventories: &'targets HashMap<usize, PythonLexicalScopeInventory<'tree>>,
    cleanups: Vec<CleanupRegion<'tree>>,
}

#[allow(clippy::too_many_arguments)]
fn lower_procedure<'tree, 'targets>(
    prepared: &'tree PreparedSyntaxTree,
    spec: &ProcedureSpec<'tree>,
    module_bindings: &'targets HashMap<Box<str>, PythonModuleBinding<'tree>>,
    module_has_wildcard_import: bool,
    class_names: &'targets HashSet<Box<str>>,
    class_constructors: &'targets HashMap<Box<str>, ProcedureId>,
    builtin_proofs: PythonBuiltinProofs,
    overlay: Option<&'targets SemanticModelOverlay>,
    binding_inventories: &mut HashMap<usize, PythonLexicalScopeInventory<'tree>>,
    budget: &SemanticBudget,
    cancellation: &'targets CancellationToken,
) -> Result<(ProcedureSemanticsParts, SemanticWork), PythonLoweringError> {
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
    // Inventories contain syntax nodes from this prepared file. Own them for
    // this batch only, and charge the real walk once rather than rebuilding
    // an enclosing scope for every name in every nested callable.
    let mut current = Some(spec.callable);
    while let Some(node) = current {
        charge_python_binding_step(&mut builder, cancellation)?;
        if matches!(node.kind(), "function_definition" | "lambda")
            && let std::collections::hash_map::Entry::Vacant(entry) =
                binding_inventories.entry(node.id())
        {
            entry.insert(collect_semantic_binding_inventory(
                node,
                prepared.source(),
                &mut builder,
                cancellation,
            )?);
        }
        current = node.parent();
    }
    let bindings = binding_inventories
        .get(&spec.callable.id())
        .expect("the callable inventory was prepared before lowering");
    let mut context = LoweringContext {
        prepared,
        callable: spec.callable,
        session,
        expression_values: HashMap::default(),
        constant_index_values: HashMap::default(),
        field_locators: HashMap::default(),
        known_list_bindings: HashSet::default(),
        known_sequence_bindings: HashSet::default(),
        failing_tuple_mutations: HashSet::default(),
        known_instance_bindings: HashMap::default(),
        known_instance_fields: HashMap::default(),
        known_binding_available_after: HashMap::default(),
        known_binding_escapes_after: HashMap::default(),
        proven_instance_fields: HashMap::default(),
        catch_binders: HashMap::default(),
        parameters: HashMap::default(),
        locals: HashMap::default(),
        comprehension_bindings: HashMap::default(),
        mutable_captures: &spec.mutable_captures,
        receiver: None,
        enclosing_class: enclosing_class_name(prepared.source(), spec.callable).map(Into::into),
        module_bindings,
        module_has_wildcard_import,
        class_names,
        class_constructors,
        builtin_proofs,
        overlay,
        bindings,
        binding_inventories,
        cleanups: Vec::new(),
    };
    let proven_instance_fields =
        instance_field_proofs(prepared, prepared.source(), builtin_proofs.exception);
    let HeapBindingProofs {
        known_lists,
        known_sequences,
        failing_tuple_mutations,
        known_instances,
        known_fields,
        available_after,
        escapes_after,
        ..
    } = heap_binding_proofs(
        spec.callable,
        prepared.source(),
        class_names,
        &proven_instance_fields,
        || true,
    )
    .expect("an unmetered heap proof cannot stop");
    context.known_list_bindings = known_lists;
    context.known_sequence_bindings = known_sequences;
    context.failing_tuple_mutations = failing_tuple_mutations;
    context.known_instance_bindings = known_instances;
    context.known_instance_fields = known_fields;
    context.known_binding_available_after = available_after;
    context.known_binding_escapes_after = escapes_after;
    context.proven_instance_fields = proven_instance_fields;
    context.emit_procedure_inputs(&mut builder, spec)?;
    context.emit_local_bindings(&mut builder)?;

    if spec.properties.is_async {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::AsyncSuspendResume,
            SemanticGapKind::Unsupported,
            "coroutine construction, scheduling, and event-loop behavior are not fully modeled",
        )?;
    }
    if spec.properties.is_generator {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::GeneratorSuspension,
            SemanticGapKind::Unsupported,
            "generator construction, suspension, and resumption are not fully modeled",
        )?;
    }
    if spec.lexical_parent.is_some() {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::Captures,
            SemanticGapKind::Unsupported,
            "lexical captures by nested Python callables are not yet modeled",
        )?;
    }

    let body_entry = context.point(&mut builder, spec.body, Vec::new())?;
    let mut fallthrough_return = None;
    let body_work = if spec.body.kind() == "block" {
        // Only falling off the body returns this None. Explicit returns resolve
        // to normal_exit directly and must never acquire a default alternative.
        let fallthrough = context.point(&mut builder, spec.body, Vec::new())?;
        context.edge(&mut builder, fallthrough, EdgeTarget::normal(normal_exit))?;
        fallthrough_return = Some(fallthrough);
        Work::Statement {
            node: spec.body,
            entry: body_entry,
            next: EdgeTarget::normal(fallthrough),
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
        context.publish_return(&mut builder, implicit_return, source)?;
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
    context.edge(&mut builder, entry, EdgeTarget::normal(body_entry))?;

    drive_procedure_work(
        &mut builder,
        pending.drain(..).rev(),
        cancellation,
        |builder, work, stack| context.step(builder, work, stack),
    )?;
    let reachable = builder
        .seal_unreachable_regions(entry, normal_exit, exceptional_exit, cancellation)
        .map_err(|_| ProcedureLoweringError::Cancelled(Box::new(builder.prospective_work())))?;
    if let Some(fallthrough) = fallthrough_return
        && reachable[fallthrough.index()]
    {
        context.publish_none_return(&mut builder, fallthrough)?;
    }
    let work_before_freeze = builder.prospective_work();
    builder
        .finish_with_work()
        .map_err(|error| ProcedureLoweringError::Budget(error, Box::new(work_before_freeze)))
}

struct HeapBindingProofs {
    closed_sequences: HashSet<Box<str>>,
    failing_tuple_mutations: HashSet<SourceSpan>,
    known_lists: HashSet<Box<str>>,
    known_sequences: HashSet<Box<str>>,
    known_instances: HashMap<Box<str>, Box<str>>,
    known_fields: HashMap<Box<str>, HashSet<Box<str>>>,
    available_after: HashMap<Box<str>, usize>,
    escapes_after: HashMap<Box<str>, usize>,
}

/// What one occurrence of a candidate allocation does to its proof.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HeapOccurrence {
    /// A declaration, a direct alias, a matching attribute or index base, or a
    /// direct raise: the allocation stays fully proven.
    Structured,
    /// A whole value handed to a call. It names no attribute and no element,
    /// so the members that were already written keep their identity, but the
    /// callee holds the object from here on and can rebind an attribute or
    /// install a descriptor, so later accesses are no longer proven.
    Escapes,
    /// Anything else: the allocation root is not proven at all.
    Unproven,
}

#[derive(Clone)]
enum HeapCandidateKind {
    List,
    Tuple,
    Instance(Box<str>),
}

#[derive(Clone)]
struct HeapCandidate {
    root: Box<str>,
    kind: HeapCandidateKind,
    available_after: usize,
}

struct HeapOccurrenceContext<'tree, 'source> {
    body: Node<'tree>,
    source: &'source str,
    assignments: &'source HashMap<Box<str>, Vec<(Node<'tree>, usize)>>,
    candidate_names: &'source HashSet<Box<str>>,
    candidate_kinds: &'source HashMap<Box<str>, HeapCandidateKind>,
    proven_instance_fields: &'source HashMap<Box<str>, HashSet<Box<str>>>,
    direct_field_ends: &'source HashMap<Box<str>, HashMap<Box<str>, usize>>,
}

fn heap_binding_proofs<'tree>(
    callable: Node<'tree>,
    source: &str,
    class_names: &HashSet<Box<str>>,
    proven_instance_fields: &HashMap<Box<str>, HashSet<Box<str>>>,
    mut scope_step: impl FnMut() -> bool,
) -> Option<HeapBindingProofs> {
    let body = callable.child_by_field_name("body").unwrap_or(callable);
    let mut assignments: HashMap<Box<str>, Vec<(Node<'tree>, usize)>> = HashMap::default();
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if !scope_step() {
            return None;
        }
        if node != body && is_nested_execution_boundary(node) {
            continue;
        }
        if node.kind() == "assignment"
            && is_direct_callable_statement(node, body)
            && let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            )
            && left.kind() == "identifier"
            && let Some(name) = node_text(source, left)
        {
            assignments
                .entry(name.into())
                .or_default()
                .push((right, node.end_byte()));
        }
        stack.extend(named_children(node).into_iter().rev());
    }

    let mut candidates: HashMap<Box<str>, HeapCandidate> = HashMap::default();
    let mut expanded_roots = HashSet::default();
    for (name, values) in &assignments {
        if !scope_step() {
            return None;
        }
        if values.len() != 1 {
            continue;
        }
        let (value, available_after) = values[0];
        let kind = match value.kind() {
            "list" => Some(HeapCandidateKind::List),
            "tuple" | "expression_list" => Some(HeapCandidateKind::Tuple),
            _ => constructed_local_class(value, source, class_names, proven_instance_fields)
                .map(HeapCandidateKind::Instance),
        };
        if let Some(kind) = kind {
            if matches!(kind, HeapCandidateKind::List | HeapCandidateKind::Tuple)
                && sequence_initializer_is_expanded(value)
            {
                expanded_roots.insert(name.clone());
            }
            candidates.insert(
                name.clone(),
                HeapCandidate {
                    root: name.clone(),
                    kind,
                    available_after,
                },
            );
        }
    }

    // Resolve direct local aliases to one of the two proven roots. A fixed
    // point keeps this bounded and handles an alias chain without recursive
    // source-tree or binding walks.
    for _ in 0..=assignments.len() {
        if !scope_step() {
            return None;
        }
        let mut changed = false;
        for (name, values) in &assignments {
            if !scope_step() {
                return None;
            }
            if values.len() != 1 || candidates.contains_key(name) {
                continue;
            }
            let (value, available_after) = values[0];
            let Some(source_name) = (value.kind() == "identifier")
                .then(|| node_text(source, value))
                .flatten()
            else {
                continue;
            };
            let Some(source_candidate) = candidates.get(source_name) else {
                continue;
            };
            candidates.insert(
                name.clone(),
                HeapCandidate {
                    root: source_candidate.root.clone(),
                    kind: source_candidate.kind.clone(),
                    available_after,
                },
            );
            changed = true;
        }
        if !changed {
            break;
        }
    }

    // A local allocation remains proof-safe only while every occurrence is a
    // declaration, a direct alias, or the matching field/index base. Any
    // unknown use, rebind, dynamic index, or nested capture invalidates the
    // complete allocation root. This is intentionally conservative: a unique
    // constructor/list assignment alone is not a type or alias proof.
    //
    // A whole-value call argument, positional or keyword, is the exception,
    // and it is not a weakening: it names no attribute and no element, so it
    // cannot retract the identity of an access that already ran, and it
    // records an escape byte that bounds the accesses that follow it instead.
    let candidate_names: HashSet<Box<str>> = candidates.keys().cloned().collect();
    let candidate_kinds: HashMap<Box<str>, HeapCandidateKind> = candidates
        .iter()
        .map(|(name, candidate)| (name.clone(), candidate.kind.clone()))
        .collect();
    let direct_field_ends = direct_instance_field_ends(body, source, &candidates);
    let occurrence_context = HeapOccurrenceContext {
        body,
        source,
        assignments: &assignments,
        candidate_names: &candidate_names,
        candidate_kinds: &candidate_kinds,
        proven_instance_fields,
        direct_field_ends: &direct_field_ends,
    };
    let mut invalid_roots: HashSet<Box<str>> = HashSet::default();
    let mut deleted_roots = HashSet::default();
    let mut mutated_tuple_roots = HashSet::default();
    let mut tuple_mutations = Vec::new();
    let mut root_escapes: HashMap<Box<str>, usize> = HashMap::default();
    let mut occurrences = vec![body];
    while let Some(node) = occurrences.pop() {
        if !scope_step() {
            return None;
        }
        if node != body && is_nested_execution_boundary(node) {
            occurrences.extend(heap_occurrence_children(node));
            continue;
        }
        if node.kind() == "identifier"
            && let Some(name) = node_text(source, node)
            && let Some(candidate) = candidates.get(name)
        {
            // Deletion can shift a list's remaining elements. The ordinary
            // indexing proof only concerns dispatch; it does not certify
            // those value changes as modeled stores.
            let mut ancestor = node.parent();
            while let Some(parent) = ancestor {
                if !scope_step() {
                    return None;
                }
                if matches!(candidate.kind, HeapCandidateKind::Tuple)
                    && matches!(parent.kind(), "assignment" | "augmented_assignment")
                    && parent.child_by_field_name("left").is_some_and(|left| {
                        left.start_byte() <= node.start_byte() && node.end_byte() <= left.end_byte()
                    })
                    && node.parent().is_some_and(|access| {
                        access.kind() == "subscript" && field_matches(access, "value", node)
                    })
                {
                    let access = node.parent().expect("the mutation has a subscript parent");
                    mutated_tuple_roots.insert(candidate.root.clone());
                    if access.start_byte() > candidate.available_after {
                        tuple_mutations.push((
                            candidate.root.clone(),
                            crate::analyzer::semantic::type_flow::source_span_for_node(access),
                        ));
                    }
                }
                if parent.kind() == "delete_statement" {
                    if matches!(candidate.kind, HeapCandidateKind::Tuple)
                        && let Some(access) = node.parent()
                        && access.kind() == "subscript"
                        && field_matches(access, "value", node)
                    {
                        mutated_tuple_roots.insert(candidate.root.clone());
                        if access.start_byte() > candidate.available_after {
                            tuple_mutations.push((
                                candidate.root.clone(),
                                crate::analyzer::semantic::type_flow::source_span_for_node(access),
                            ));
                        }
                    }
                    deleted_roots.insert(candidate.root.clone());
                    break;
                }
                if is_statement_kind(parent.kind()) {
                    break;
                }
                ancestor = parent.parent();
            }
            match classify_heap_occurrence(node, &occurrence_context) {
                HeapOccurrence::Structured => {}
                HeapOccurrence::Escapes => {
                    let escape = root_escapes
                        .entry(candidate.root.clone())
                        .or_insert(node.start_byte());
                    *escape = (*escape).min(node.start_byte());
                }
                HeapOccurrence::Unproven => {
                    invalid_roots.insert(candidate.root.clone());
                }
            }
        }
        occurrences.extend(heap_occurrence_children(node));
    }

    // Scan nested execution boundaries separately. The ordinary traversal
    // above deliberately skips their local scopes, but a reference captured
    // by such a boundary invalidates the outer allocation root.
    let mut nested = vec![body];
    while let Some(node) = nested.pop() {
        if !scope_step() {
            return None;
        }
        if node != body && is_nested_execution_boundary(node) {
            let mut nested_nodes = vec![node];
            while let Some(nested_node) = nested_nodes.pop() {
                if !scope_step() {
                    return None;
                }
                if nested_node.kind() == "identifier"
                    && let Some(name) = node_text(source, nested_node)
                    && let Some(candidate) = candidates.get(name)
                {
                    invalid_roots.insert(candidate.root.clone());
                }
                nested_nodes.extend(heap_occurrence_children(nested_node));
            }
            continue;
        }
        nested.extend(heap_occurrence_children(node));
    }

    let mut known_lists = HashSet::default();
    let mut known_sequences = HashSet::default();
    let mut closed_sequences = HashSet::default();
    let mut known_instances = HashMap::default();
    let mut known_fields = HashMap::default();
    let mut available_after = HashMap::default();
    let mut escapes_after = HashMap::default();
    for (name, candidate) in candidates {
        if !scope_step() {
            return None;
        }
        if invalid_roots.contains(&candidate.root) {
            continue;
        }
        if let Some(escape) = root_escapes.get(&candidate.root).copied() {
            escapes_after.insert(name.clone(), escape);
        }
        if matches!(
            candidate.kind,
            HeapCandidateKind::List | HeapCandidateKind::Tuple
        ) {
            if !root_escapes.contains_key(&candidate.root)
                && !expanded_roots.contains(&candidate.root)
                && !deleted_roots.contains(&candidate.root)
                && !mutated_tuple_roots.contains(&candidate.root)
            {
                closed_sequences.insert(name.clone());
            }
            if matches!(candidate.kind, HeapCandidateKind::List) {
                known_lists.insert(name.clone());
            }
            known_sequences.insert(name.clone());
        } else if let HeapCandidateKind::Instance(class_name) = candidate.kind {
            known_instances.insert(name.clone(), class_name);
            let fields = direct_field_ends
                .get(&name)
                .map(|fields| fields.keys().cloned().collect::<HashSet<_>>())
                .or_else(|| {
                    known_instances
                        .get(&name)
                        .and_then(|class_name| proven_instance_fields.get(class_name).cloned())
                })
                .unwrap_or_default();
            known_fields.insert(name.clone(), fields);
        }
        available_after.insert(name, candidate.available_after);
    }
    let failing_tuple_mutations = tuple_mutations
        .into_iter()
        .filter_map(|(root, span)| {
            (!invalid_roots.contains(&root)
                && !expanded_roots.contains(&root)
                && root_escapes
                    .get(&root)
                    .is_none_or(|escape| span.end_byte() as usize <= *escape))
            .then_some(span)
        })
        .collect();
    Some(HeapBindingProofs {
        closed_sequences,
        failing_tuple_mutations,
        known_lists,
        known_sequences,
        known_instances,
        known_fields,
        available_after,
        escapes_after,
    })
}

fn sequence_initializer_is_expanded(node: Node<'_>) -> bool {
    runtime_expression_children(node)
        .iter()
        .any(|child| matches!(child.kind(), "list_splat" | "parenthesized_list_splat"))
}

/// Plain local sequence loads whose full alias closure never escapes. This is
/// stronger than the source-order proof used to discharge indexing calls:
/// a later escape can run before this load on a loop's next iteration.
pub(super) fn closed_sequence_load_spans(
    callable: Node<'_>,
    source: &str,
    mut scope_step: impl FnMut() -> bool,
) -> Option<HashSet<SourceSpan>> {
    let proofs = heap_binding_proofs(
        callable,
        source,
        &HashSet::default(),
        &HashMap::default(),
        &mut scope_step,
    )?;
    let body = callable.child_by_field_name("body").unwrap_or(callable);
    let mut pending = vec![body];
    let mut spans = HashSet::default();
    while let Some(node) = pending.pop() {
        if !scope_step() {
            return None;
        }
        if node != body && is_nested_execution_boundary(node) {
            continue;
        }
        if node.kind() == "subscript"
            && let Some(value) = node.child_by_field_name("value")
            && value.kind() == "identifier"
            && let Some(name) = node_text(source, value)
            && proofs.closed_sequences.contains(name)
            && proofs
                .available_after
                .get(name)
                .is_some_and(|end| node.start_byte() > *end)
            && node
                .child_by_field_name("subscript")
                .is_some_and(|index| is_structural_constant_index(source, index).is_some())
        {
            spans.insert(crate::analyzer::semantic::type_flow::source_span_for_node(
                node,
            ));
        }
        pending.extend(named_children(node));
    }
    Some(spans)
}

fn direct_instance_field_ends<'tree>(
    body: Node<'tree>,
    source: &str,
    candidates: &HashMap<Box<str>, HeapCandidate>,
) -> HashMap<Box<str>, HashMap<Box<str>, usize>> {
    let mut fields: HashMap<Box<str>, HashMap<Box<str>, Vec<usize>>> = HashMap::default();
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if node != body && is_nested_execution_boundary(node) {
            continue;
        }
        if node.kind() == "assignment"
            && let Some(left) = node.child_by_field_name("left")
            && left.kind() == "attribute"
            && let (Some(object), Some(attribute)) = (
                left.child_by_field_name("object"),
                left.child_by_field_name("attribute"),
            )
            && object.kind() == "identifier"
            && attribute.kind() == "identifier"
            && let (Some(object_name), Some(attribute_name)) =
                (node_text(source, object), node_text(source, attribute))
            && let Some(candidate) = candidates.get(object_name)
            && node.start_byte() > candidate.available_after
            && is_direct_dominated_heap_assignment(node, body)
        {
            fields
                .entry(object_name.into())
                .or_default()
                .entry(attribute_name.into())
                .or_default()
                .push(node.end_byte());
        }
        stack.extend(named_children(node).into_iter().rev());
    }
    fields
        .into_iter()
        .filter_map(|(name, fields)| {
            let unique = fields
                .into_iter()
                .filter_map(|(field, ends)| (ends.len() == 1).then_some((field, ends[0])))
                .collect::<HashMap<_, _>>();
            (!unique.is_empty()).then_some((name, unique))
        })
        .collect()
}

fn is_direct_dominated_heap_assignment(node: Node<'_>, body: Node<'_>) -> bool {
    if !is_direct_callable_statement(node, body) {
        return false;
    }
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.id() == body.id() {
            return true;
        }
        if matches!(
            parent.kind(),
            "if_statement"
                | "for_statement"
                | "while_statement"
                | "with_statement"
                | "match_statement"
                | "lambda"
                | "function_definition"
                | "class_definition"
                | "comprehension"
        ) {
            return false;
        }
        if parent.kind() == "try_statement"
            && !parent
                .child_by_field_name("body")
                .is_some_and(|try_body| node_is_descendant_of(current, try_body))
        {
            return false;
        }
        current = parent;
    }
    false
}

fn node_is_descendant_of(node: Node<'_>, ancestor: Node<'_>) -> bool {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if candidate.id() == ancestor.id() {
            return true;
        }
        current = candidate.parent();
    }
    false
}

fn is_dominated_heap_use(node: Node<'_>, body: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.id() == body.id() {
            return true;
        }
        if matches!(
            parent.kind(),
            "if_statement"
                | "for_statement"
                | "while_statement"
                | "with_statement"
                | "match_statement"
                | "lambda"
                | "function_definition"
                | "class_definition"
                | "comprehension"
        ) {
            return false;
        }
        if parent.kind() == "try_statement"
            && !parent
                .child_by_field_name("body")
                .is_some_and(|try_body| node_is_descendant_of(current, try_body))
        {
            return false;
        }
        current = parent;
    }
    false
}

/// The children of `node` that an allocation root can occur in. A
/// `keyword_argument`'s `name` is the formal the actual binds to, not a read
/// of a local that happens to share its spelling, so `f(holder=holder)` holds
/// exactly one occurrence of `holder`. The lowering already reads only the
/// `value` field of a keyword argument, and the allocation-proof scan must
/// agree with it.
fn heap_occurrence_children(node: Node<'_>) -> Vec<Node<'_>> {
    if node.kind() == "keyword_argument" {
        return children_by_field_name(node, "value");
    }
    named_children(node)
}

fn is_nested_execution_boundary(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_definition" | "lambda" | "class_definition"
    )
}

/// Classify one identifier occurrence of a candidate allocation.
///
/// A whole-value call argument is the one occurrence that is neither fully
/// structured nor unproven. It reads the object as a whole and names no
/// member, so it must not retract the member identity of the accesses that
/// already ran; it does hand the object to a callee, so it bounds the accesses
/// that come after it. Requiring it to be a top-level use of the body is what
/// makes "after" mean execution order: every access this adapter proves is
/// itself top-level or directly dominated, so no repetition construct can put
/// a proven access between the argument and its own next run.
fn classify_heap_occurrence<'tree, 'source>(
    node: Node<'tree>,
    context: &HeapOccurrenceContext<'tree, 'source>,
) -> HeapOccurrence {
    let body = context.body;
    let source = context.source;
    let assignments = context.assignments;
    let candidate_names = context.candidate_names;
    let candidate_kinds = context.candidate_kinds;
    let proven_instance_fields = context.proven_instance_fields;
    let direct_field_ends = context.direct_field_ends;
    let Some(name) = node_text(source, node) else {
        return HeapOccurrence::Unproven;
    };
    let Some(parent) = node.parent() else {
        return HeapOccurrence::Unproven;
    };
    if parent.kind() == "assignment"
        && parent
            .child_by_field_name("left")
            .is_some_and(|left| left.id() == node.id())
    {
        return structured_when(
            assignments
                .get(name)
                .is_some_and(|values| values.len() == 1 && values[0].1 == parent.end_byte()),
        );
    }
    if parent.kind() == "assignment"
        && parent
            .child_by_field_name("right")
            .is_some_and(|right| right.id() == node.id())
    {
        let Some(target) = parent.child_by_field_name("left") else {
            return HeapOccurrence::Unproven;
        };
        let Some(target_name) = (target.kind() == "identifier")
            .then(|| node_text(source, target))
            .flatten()
        else {
            return HeapOccurrence::Unproven;
        };
        return structured_when(
            assignments
                .get(target_name)
                .is_some_and(|values| values.len() == 1 && values[0].1 == parent.end_byte())
                && candidate_names.contains(target_name),
        );
    }
    if parent.kind() == "attribute"
        && parent
            .child_by_field_name("object")
            .is_some_and(|object| object.id() == node.id())
    {
        let Some(HeapCandidateKind::Instance(class_name)) = candidate_kinds.get(name) else {
            return HeapOccurrence::Unproven;
        };
        let Some(attribute) = parent.child_by_field_name("attribute") else {
            return HeapOccurrence::Unproven;
        };
        let Some(attribute_name) = node_text(source, attribute) else {
            return HeapOccurrence::Unproven;
        };
        let class_field_proven = proven_instance_fields
            .get(class_name)
            .is_some_and(|fields| fields.contains(attribute_name));
        let direct_field_end = direct_field_ends
            .get(name)
            .and_then(|fields| fields.get(attribute_name))
            .copied();
        if !class_field_proven && direct_field_end.is_none() {
            return HeapOccurrence::Unproven;
        }
        if direct_field_end.is_some() {
            if !is_direct_dominated_heap_assignment(parent.parent().unwrap_or(parent), body)
                && !is_dominated_heap_use(node, body)
            {
                return HeapOccurrence::Unproven;
            }
        } else if !is_top_level_heap_use(node, body) {
            return HeapOccurrence::Unproven;
        }
        return structured_when(!parent.parent().is_some_and(|grandparent| {
            grandparent.kind() == "call"
                && grandparent
                    .child_by_field_name("function")
                    .is_some_and(|function| function.id() == parent.id())
        }));
    }
    if parent.kind() == "raise_statement"
        && runtime_expression_children(parent)
            .first()
            .is_some_and(|value| value.id() == node.id())
        && runtime_expression_children(parent).len() == 1
    {
        if direct_field_ends
            .get(name)
            .is_some_and(|fields| fields.values().any(|end| *end >= parent.start_byte()))
        {
            return HeapOccurrence::Unproven;
        }
        return structured_when(is_dominated_heap_use(node, body));
    }
    if parent.kind() == "subscript"
        && parent
            .child_by_field_name("value")
            .is_some_and(|value| value.id() == node.id())
    {
        if !matches!(
            candidate_kinds.get(name),
            Some(HeapCandidateKind::List | HeapCandidateKind::Tuple)
        ) || !is_top_level_heap_use(node, body)
        {
            return HeapOccurrence::Unproven;
        }
        return structured_when(
            parent
                .child_by_field_name("subscript")
                .is_some_and(|index| is_structural_constant_index(source, index).is_some()),
        );
    }
    // The whole actual of a call, positional or keyword. `f(holder)` and
    // `f(holder=holder)` hand the same object to the same callee, so both
    // escape. A `*args` or `**kwargs` splat parents the identifier under
    // `list_splat` or `dictionary_splat`, where the container and not the
    // allocation is the actual, and a comprehension or generator argument
    // parents it under its own execution boundary; neither reaches here, and
    // both keep invalidating the root.
    if is_whole_call_actual(node, parent) && is_top_level_heap_use(node, body) {
        return HeapOccurrence::Escapes;
    }
    HeapOccurrence::Unproven
}

/// Whether `node` is the entire value of one actual argument of a call: a
/// direct named child of the `argument_list`, or the `value` of a
/// `keyword_argument` that is itself a direct named child of that list.
fn is_whole_call_actual(node: Node<'_>, parent: Node<'_>) -> bool {
    let (actual, argument_list) = if parent.kind() == "keyword_argument" {
        if !parent
            .child_by_field_name("value")
            .is_some_and(|value| value.id() == node.id())
        {
            return false;
        }
        let Some(argument_list) = parent.parent() else {
            return false;
        };
        (parent, argument_list)
    } else {
        (node, parent)
    };
    argument_list.kind() == "argument_list"
        && argument_list
            .parent()
            .is_some_and(|call| call.kind() == "call")
        && named_children(argument_list)
            .into_iter()
            .any(|argument| argument.id() == actual.id())
}

fn structured_when(structured: bool) -> HeapOccurrence {
    if structured {
        HeapOccurrence::Structured
    } else {
        HeapOccurrence::Unproven
    }
}

fn is_top_level_heap_use(node: Node<'_>, body: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.id() == body.id() {
            return true;
        }
        if matches!(
            parent.kind(),
            "if_statement"
                | "for_statement"
                | "while_statement"
                | "try_statement"
                | "with_statement"
                | "match_statement"
                | "lambda"
                | "function_definition"
                | "class_definition"
                | "comprehension"
        ) {
            return false;
        }
        current = parent;
    }
    false
}

fn is_direct_callable_statement(node: Node<'_>, body: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.id() == body.id() {
            return true;
        }
        if parent.kind() == "block"
            && parent.parent().is_some_and(|grandparent| {
                grandparent.kind() == "try_statement"
                    && grandparent
                        .child_by_field_name("body")
                        .is_some_and(|try_body| try_body.id() == parent.id())
            })
        {
            current = parent;
            continue;
        }
        if parent.kind() == "expression_statement"
            && parent.parent().is_some_and(|block| {
                block.kind() == "block"
                    && block.parent().is_some_and(|try_statement| {
                        try_statement.kind() == "try_statement"
                            && try_statement
                                .child_by_field_name("body")
                                .is_some_and(|try_body| try_body.id() == block.id())
                    })
            })
        {
            current = parent;
            continue;
        }
        if is_statement_kind(parent.kind()) {
            return parent
                .parent()
                .is_some_and(|grandparent| grandparent.id() == body.id());
        }
        current = parent;
    }
    false
}

fn constructed_local_class<'tree>(
    node: Node<'tree>,
    source: &str,
    class_names: &HashSet<Box<str>>,
    proven_instance_fields: &HashMap<Box<str>, HashSet<Box<str>>>,
) -> Option<Box<str>> {
    if node.kind() != "call" {
        return None;
    }
    let function = node.child_by_field_name("function")?;
    if function.kind() != "identifier" {
        return None;
    }
    let name = node_text(source, function)?;
    (class_names.contains(name) && proven_instance_fields.contains_key(name)).then(|| name.into())
}

fn instance_field_proofs(
    prepared: &PreparedSyntaxTree,
    source: &str,
    exception_builtin_proof: bool,
) -> HashMap<Box<str>, HashSet<Box<str>>> {
    let mut proofs = HashMap::default();
    let mut stack = vec![prepared.tree().root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "class_definition"
            && let Some((class_name, fields)) =
                class_field_proof(node, source, exception_builtin_proof)
            && proofs.insert(class_name.clone(), fields).is_some()
        {
            proofs.remove(&class_name);
        }
        stack.extend(named_children(node).into_iter().rev());
    }
    proofs
}

fn class_field_proof<'tree>(
    class_node: Node<'tree>,
    source: &str,
    exception_builtin_proof: bool,
) -> Option<(Box<str>, HashSet<Box<str>>)> {
    // A base class or class decorator can replace construction, attribute
    // lookup, or assignment with arbitrary runtime behavior.
    let supported_exception_subclass =
        class_node
            .child_by_field_name("superclasses")
            .is_some_and(|superclasses| {
                let children = named_children(superclasses);
                let [superclass] = children.as_slice() else {
                    return false;
                };
                superclass.kind() == "identifier"
                    && node_text(source, *superclass) == Some("Exception")
                    && exception_builtin_proof
            });
    if (class_node.child_by_field_name("superclasses").is_some() && !supported_exception_subclass)
        || class_node
            .parent()
            .is_some_and(|parent| parent.kind() == "decorated_definition")
    {
        return None;
    }
    let class_name = node_text(source, class_node.child_by_field_name("name")?)?.into();
    let body = class_node.child_by_field_name("body")?;
    if supported_exception_subclass && !class_body_is_inert(body) {
        return None;
    }
    let direct_children = named_children(body);
    let mut initializer = None;
    let mut ambiguous = false;
    let mut class_assignments: HashSet<Box<str>> = HashSet::default();
    let mut method_names: HashSet<Box<str>> = HashSet::default();

    for child in direct_children {
        let method = if child.kind() == "function_definition" {
            Some(child)
        } else if child.kind() == "decorated_definition" {
            ambiguous = true;
            named_children(child)
                .into_iter()
                .find(|nested| nested.kind() == "function_definition")
        } else {
            None
        };
        if let Some(method) = method {
            let Some(name_node) = method.child_by_field_name("name") else {
                continue;
            };
            let Some(name) = node_text(source, name_node) else {
                continue;
            };
            method_names.insert(name.into());
            if name != "__init__"
                || name == "__getattribute__"
                || name == "__getattr__"
                || name == "__setattr__"
            {
                ambiguous = true;
            }
            if name == "__init__" {
                initializer = Some(method);
            }
            continue;
        }
        if child.kind() == "assignment"
            && let Some(left) = child.child_by_field_name("left")
            && left.kind() == "identifier"
            && let Some(name) = node_text(source, left)
        {
            class_assignments.insert(name.into());
        }
    }

    let Some(initializer) = initializer else {
        return (supported_exception_subclass
            && class_body_is_inert(body)
            && !ambiguous
            && class_assignments.is_empty())
        .then(|| (class_name, HashSet::default()));
    };
    let receiver = python_first_parameter_name(initializer, source)?;
    let init_body = initializer.child_by_field_name("body")?;
    let mut fields = HashSet::default();
    // Only direct assignments in the initializer body establish a field on
    // every normal path. Conditional, loop, nested, and exceptional writes
    // remain unproven and retain the descriptor/exception gaps.
    for statement in named_children(init_body) {
        let assignments = if statement.kind() == "assignment" {
            vec![statement]
        } else {
            named_children(statement)
        };
        for node in assignments {
            if node.kind() == "assignment"
                && let Some(left) = node.child_by_field_name("left")
                && left.kind() == "attribute"
                && let (Some(object), Some(attribute)) = (
                    left.child_by_field_name("object"),
                    left.child_by_field_name("attribute"),
                )
                && object.kind() == "identifier"
                && attribute.kind() == "identifier"
                && node_text(source, object) == Some(receiver.as_ref())
                && let Some(field) = node_text(source, attribute)
            {
                fields.insert(field.into());
            }
        }
    }

    if ambiguous {
        return None;
    }
    fields.retain(|field| !class_assignments.contains(field) && !method_names.contains(field));
    (!fields.is_empty()).then_some((class_name, fields))
}

fn class_body_is_inert(body: Node<'_>) -> bool {
    let mut saw_pass = false;
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        if !child.is_named() || child.kind() == "comment" {
            continue;
        }
        if child.kind() == "pass_statement" {
            saw_pass = true;
        } else {
            return false;
        }
    }
    saw_pass
}

fn python_first_parameter_name<'tree>(callable: Node<'tree>, source: &str) -> Option<Box<str>> {
    let parameters = callable.child_by_field_name("parameters")?;
    let first = named_children(parameters).into_iter().next()?;
    match first.kind() {
        "identifier" | "keyword_identifier" => node_text(source, first).map(Into::into),
        _ => first
            .child_by_field_name("name")
            .and_then(|name| node_text(source, name))
            .map(Into::into),
    }
}

fn collect_semantic_binding_inventory<'tree>(
    callable: Node<'tree>,
    source: &str,
    builder: &mut ProcedureCfgBuilder,
    cancellation: &CancellationToken,
) -> Result<PythonLexicalScopeInventory<'tree>, PythonLoweringError> {
    let mut stop = None;
    let inventory =
        python_lexical_scope_inventory_bounded(
            callable,
            source,
            || match charge_python_binding_step(builder, cancellation) {
                Ok(()) => true,
                Err(error) => {
                    stop = Some(error);
                    false
                }
            },
        );
    if let Some(error) = stop {
        return Err(error);
    }
    inventory.ok_or_else(|| {
        PythonLoweringError::Invalid("Python callable binding inventory was unavailable".into())
    })
}

fn charge_python_binding_step(
    builder: &mut ProcedureCfgBuilder,
    cancellation: &CancellationToken,
) -> Result<(), PythonLoweringError> {
    if cancellation.is_cancelled() {
        return Err(PythonLoweringError::Cancelled(Box::new(
            builder.prospective_work(),
        )));
    }
    let candidate = sum_lowering_work(
        builder.prospective_work(),
        SemanticWork {
            nested_entries: 1,
            ..SemanticWork::default()
        },
    );
    builder
        .descend_nested_entry()
        .map_err(|exceeded| PythonLoweringError::Budget(exceeded, Box::new(candidate)))
}

fn callable_returns_value(_source: &str, spec: &ProcedureSpec<'_>) -> bool {
    spec.kind == ProcedureKind::Lambda
}

impl<'tree, 'targets> LoweringContext<'tree, 'targets> {
    fn emit_procedure_inputs(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        spec: &ProcedureSpec<'tree>,
    ) -> Result<(), PythonLoweringError> {
        let layout = formal_parameter_slots_for_owner(
            Language::Python,
            spec.callable,
            self.prepared.source(),
        )
        .unwrap_or_default();
        let first_slot_is_receiver =
            matches!(
                spec.kind,
                ProcedureKind::Method | ProcedureKind::Constructor
            ) && !matches!(layout.python_binding, Some(PythonMethodBinding::Static));
        let mut ordinal = 0_u32;
        for (slot_index, slot) in layout.slots.into_iter().enumerate() {
            if self.session.cancellation().is_cancelled() {
                return Err(PythonLoweringError::Cancelled(Box::new(
                    builder.prospective_work(),
                )));
            }
            let declaration = spec
                .callable
                .named_descendant_for_byte_range(
                    slot.declaration_range.start_byte,
                    slot.declaration_range.end_byte,
                )
                .unwrap_or(spec.callable);
            let mapping_node = slot
                .names
                .iter()
                .find_map(|name| {
                    python_binding_name_node(declaration, self.prepared.source(), name)
                })
                .unwrap_or(declaration);
            let metadata = self.value_mapping(builder, mapping_node)?;
            let parameter_name = slot.unique_name().map(Box::<str>::from);
            let passing_mode = slot.passing_mode;
            let receiver = first_slot_is_receiver && slot_index == 0;
            let value = if receiver {
                let value = self.session.add_value_with_metadata(
                    builder,
                    metadata,
                    SemanticValueKind::Receiver { dispatch: true },
                )?;
                self.receiver = Some(value);
                value
            } else {
                if !spec
                    .callable
                    .parent()
                    .is_some_and(|parent| parent.kind() == "decorated_definition")
                    && let Some(range) = slot.default_range
                {
                    let default = spec
                        .callable
                        .named_descendant_for_byte_range(range.start_byte, range.end_byte)
                        .expect("a formal default range names a retained syntax node");
                    let metadata = self.value_mapping(builder, default)?;
                    // This is the value saved when the callable was defined,
                    // not an expression evaluated in this procedure's CFG.
                    self.session.add_value_with_metadata(
                        builder,
                        metadata,
                        SemanticValueKind::DefaultArgument { ordinal },
                    )?;
                }
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
                    PythonLoweringError::Invalid("too many Python formal parameters".into())
                })?;
                value
            };
            for name in slot.names {
                self.parameters.insert(name.into_boxed_str(), value);
            }
        }
        Ok(())
    }

    fn emit_local_bindings(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
    ) -> Result<(), PythonLoweringError> {
        let bindings = self
            .bindings
            .local_bindings()
            .map(|(name, declaration)| (Box::<str>::from(name), declaration))
            .collect::<Vec<_>>();
        for (name, declaration) in bindings {
            if self.session.cancellation().is_cancelled() {
                return Err(PythonLoweringError::Cancelled(Box::new(
                    builder.prospective_work(),
                )));
            }
            if self.parameters.contains_key(name.as_ref())
                || self.locals.contains_key(name.as_ref())
            {
                continue;
            }
            let metadata = self.value_mapping(builder, declaration)?;
            let value = self.session.add_value_with_metadata(
                builder,
                metadata,
                SemanticValueKind::Local,
            )?;
            self.locals.insert(name, value);
        }
        Ok(())
    }

    fn binding_value(&self, name: &str) -> Option<ValueId> {
        self.locals
            .get(name)
            .copied()
            .or_else(|| self.parameters.get(name).copied())
    }

    fn scoped_binding_value(
        &self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        name: &str,
    ) -> Result<Option<(ValueId, ValueFlowKind)>, PythonLoweringError> {
        // Walrus writes belong to the enclosing function, even when their
        // value expression reads comprehension-local names.
        let walrus_target = node.parent().is_some_and(|parent| {
            parent.kind() == "named_expression" && field_matches(parent, "name", node)
        });
        if !walrus_target && !self.comprehension_bindings.is_empty() {
            let mut current = node;
            while let Some(parent) = current.parent() {
                charge_python_binding_step(builder, self.session.cancellation())?;
                if let Some(bindings) = self.comprehension_bindings.get(&parent.id())
                    && !bindings.outer_iterables.iter().any(|iterable| {
                        iterable.start_byte() <= node.start_byte()
                            && node.end_byte() <= iterable.end_byte()
                    })
                    && let Some(value) = bindings.values.get(name)
                {
                    return Ok(Some((*value, ValueFlowKind::Local)));
                }
                if matches!(
                    parent.kind(),
                    "function_definition" | "lambda" | "class_definition" | "module"
                ) {
                    break;
                }
                current = parent;
            }
        }
        Ok(self.binding_value(name).map(|value| {
            let kind = if Some(value) == self.receiver {
                ValueFlowKind::Receiver
            } else if self.locals.get(name) == Some(&value) {
                ValueFlowKind::Local
            } else {
                ValueFlowKind::Parameter
            };
            (value, kind)
        }))
    }

    fn module_class_fallback_allowed(
        &self,
        builder: &mut ProcedureCfgBuilder,
        reference: Node<'tree>,
    ) -> Result<bool, PythonLoweringError> {
        let Some(name) = node_text(self.prepared.source(), reference) else {
            return Ok(false);
        };
        if self.binding_value(name).is_some() || !self.class_names.contains(name) {
            return Ok(false);
        }
        self.module_name_fallback_allowed(builder, reference, name)
    }

    fn module_name_fallback_allowed(
        &self,
        builder: &mut ProcedureCfgBuilder,
        reference: Node<'tree>,
        name: &str,
    ) -> Result<bool, PythonLoweringError> {
        match self.bindings.name_resolution_at(name, reference) {
            PythonLexicalNameResolution::Local | PythonLexicalNameResolution::Nonlocal => {
                return Ok(false);
            }
            PythonLexicalNameResolution::Global => return Ok(true),
            PythonLexicalNameResolution::Unbound => {}
        }

        let reference_start = reference.start_byte();
        let reference_end = reference.end_byte();
        let mut current = self.callable;
        while let Some(parent) = current.parent() {
            charge_python_binding_step(builder, self.session.cancellation())?;
            if matches!(parent.kind(), "function_definition" | "lambda")
                && parent.child_by_field_name("body").is_some_and(|body| {
                    body.start_byte() <= reference_start && reference_end <= body.end_byte()
                })
            {
                let inventory = self
                    .binding_inventories
                    .get(&parent.id())
                    .expect("enclosing callable inventory was prepared before lowering");
                match inventory.name_resolution_at(name, reference) {
                    PythonLexicalNameResolution::Local | PythonLexicalNameResolution::Nonlocal => {
                        return Ok(false);
                    }
                    PythonLexicalNameResolution::Global => return Ok(true),
                    PythonLexicalNameResolution::Unbound => {}
                }
            }
            current = parent;
        }
        Ok(true)
    }

    fn expression_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        kind: SemanticValueKind,
    ) -> Result<ValueId, PythonLoweringError> {
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

    fn memory_member_locator(
        &mut self,
        node: Node<'tree>,
    ) -> Result<Option<SemanticLocator>, PythonLoweringError> {
        if node.kind() != "identifier" {
            return Ok(None);
        }
        let Some(name) = node_text(self.prepared.source(), node) else {
            return Ok(None);
        };
        if let Some(locator) = self.field_locators.get(name) {
            return Ok(Some(locator.clone()));
        }
        let anchor = source_anchor(node, 0).map_err(PythonLoweringError::Invalid)?;
        let procedure = self.session.locator();
        let locator = SemanticLocator::new(
            procedure.mount(),
            procedure.path().clone(),
            procedure.language(),
            procedure.declaration().clone(),
            SemanticRole::MemoryLocation,
            anchor,
        );
        self.field_locators.insert(name.into(), locator.clone());
        Ok(Some(locator))
    }

    fn proven_instance_attribute(
        &self,
        access: Node<'tree>,
        object: Node<'tree>,
        attribute: Node<'tree>,
    ) -> bool {
        let Some(object_name) = node_text(self.prepared.source(), object) else {
            return false;
        };
        let Some(attribute_name) = node_text(self.prepared.source(), attribute) else {
            return false;
        };
        // `class_field_proof` admits a class only when direct initializer
        // stores cannot invoke a base-class, decorator, or dynamic attribute
        // hook. Reuse that structured proof for the store through the
        // constructor receiver itself. Ordinary instance proofs require the
        // constructor to have completed, so they cannot establish the stores
        // that create those fields in the first place.
        if access.kind() == "assignment"
            && self.binding_value(object_name) == self.receiver
            && self.enclosing_class.as_deref().is_some_and(|class_name| {
                self.proven_instance_fields
                    .get(class_name)
                    .is_some_and(|fields| fields.contains(attribute_name))
            })
        {
            return true;
        }
        let Some(class_name) = self.known_instance_bindings.get(object_name) else {
            return false;
        };
        let established_after = self
            .known_binding_available_after
            .get(object_name)
            .copied()
            .is_some_and(|end| access.start_byte() > end);
        let before_escape = self
            .known_binding_escapes_after
            .get(object_name)
            .copied()
            .is_none_or(|escape| access.end_byte() <= escape);
        established_after
            && before_escape
            && (self
                .known_instance_fields
                .get(object_name)
                .is_some_and(|fields| fields.contains(attribute_name))
                || self
                    .proven_instance_fields
                    .get(class_name)
                    .is_some_and(|fields| fields.contains(attribute_name)))
    }

    fn proven_tuple_mutation(&self, target: Node<'tree>) -> bool {
        target.kind() == "subscript"
            && (target
                .child_by_field_name("value")
                .is_some_and(|value| matches!(value.kind(), "tuple" | "expression_list"))
                || self.failing_tuple_mutations.contains(
                    &crate::analyzer::semantic::type_flow::source_span_for_node(target),
                ))
    }

    fn tuple_mutation_failure(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PythonLoweringError> {
        let exception = self.value(builder, point, SemanticValueKind::Exception)?;
        self.append_effect(
            builder,
            point,
            SemanticEffect::Throw {
                value: Some(exception),
            },
        )?;
        self.abrupt_throw(builder, point, scope, exception, stack)
    }

    fn proven_list_index(
        &self,
        access: Node<'tree>,
        value: Node<'tree>,
        index: Node<'tree>,
    ) -> bool {
        node_text(self.prepared.source(), value)
            .is_some_and(|name| self.known_list_bindings.contains(name))
            && self.proven_sequence_index_read(access, value, index)
    }

    fn proven_sequence_index_read(
        &self,
        access: Node<'tree>,
        value: Node<'tree>,
        index: Node<'tree>,
    ) -> bool {
        let Some(value_name) = node_text(self.prepared.source(), value) else {
            return false;
        };
        self.known_sequence_bindings.contains(value_name)
            && self
                .known_binding_available_after
                .get(value_name)
                .copied()
                .is_some_and(|end| access.start_byte() > end)
            && self
                .known_binding_escapes_after
                .get(value_name)
                .copied()
                .is_none_or(|escape| access.end_byte() <= escape)
            && is_structural_constant_index(self.prepared.source(), index).is_some()
    }

    fn constant_index_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<Option<(ValueId, u128)>, PythonLoweringError> {
        let Some(index) = is_structural_constant_index(self.prepared.source(), node) else {
            return Ok(None);
        };
        if let Some(value) = self.constant_index_values.get(&index) {
            self.expression_values.insert(node.id(), *value);
            return Ok(Some((*value, u128::from(index))));
        }
        let value = self.expression_value(builder, node, SemanticValueKind::Constant)?;
        self.constant_index_values.insert(index, value);
        Ok(Some((value, u128::from(index))))
    }

    fn add_dynamic_index_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        location: MemoryLocationId,
    ) -> Result<(), PythonLoweringError> {
        self.session.add_gap_with_impacts(
            builder,
            point,
            SemanticGapSubject::MemoryLocation(location),
            SemanticCapability::IndexMemory,
            SemanticGapImpacts::single(SemanticGapImpact::HeapRead)
                .with(SemanticGapImpact::HeapWrite)
                .with(SemanticGapImpact::Aliasing),
            SemanticGapKind::Unsupported,
            "Python dynamic index identity is not proven",
        )?;
        Ok(())
    }

    fn emit_lexical_input_flow(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        point: ProgramPointId,
        target: ValueId,
    ) -> Result<(), PythonLoweringError> {
        let Some(name) = node_text(self.prepared.source(), node) else {
            return Ok(());
        };
        let Some((source, kind)) = self.scoped_binding_value(builder, node, name)? else {
            return Ok(());
        };
        if self.mutable_captures.contains(name) && self.binding_value(name) == Some(source) {
            let unknown =
                self.unknown_target_value(builder, node, "python.unknown_capture_write")?;
            self.append_effect(
                builder,
                point,
                SemanticEffect::Assignment {
                    target,
                    value: unknown,
                },
            )?;
            self.add_gap(
                builder,
                point,
                SemanticGapSubject::Value(target),
                SemanticCapability::Captures,
                SemanticGapKind::Unknown,
                "a nested nonlocal declaration can rebind this captured value",
            )?;
            return Ok(());
        }
        if source != target {
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
    ) -> Result<(), PythonLoweringError> {
        if self.session.cancellation().is_cancelled() {
            return Err(PythonLoweringError::Cancelled(Box::default()));
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
            Work::ValueCondition {
                node,
                entry,
                when_true,
                when_false,
                scope,
            } => self.value_condition(builder, node, entry, when_true, when_false, scope, stack),
            Work::ComprehensionClause {
                node,
                index,
                entry,
                next,
                scope,
            } => self.comprehension_clause(builder, node, index, entry, next, scope, stack),
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
    ) -> Result<(), PythonLoweringError> {
        if let Some(value) = literal_truth_condition(node) {
            let taken = if value { when_true } else { when_false };
            self.edge(builder, entry, taken)?;
            self.session.add_guard_fact(
                builder,
                entry,
                GuardPredicate::ConstantBoolean { value },
                None,
                value.then_some(GuardArm {
                    target_point: when_true.point,
                    kind: when_true.kind,
                }),
                (!value).then_some(GuardArm {
                    target_point: when_false.point,
                    kind: when_false.kind,
                }),
            )?;
            return Ok(());
        }
        match (node.kind(), boolean_operator_kind(node)) {
            ("boolean_operator", Some("and")) => {
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
            ("boolean_operator", Some("or")) => {
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
            ("not_operator", _) => {
                let argument = required_field(node, "argument")?;
                stack.push(Work::Condition {
                    node: argument,
                    entry,
                    when_true: when_false,
                    when_false: when_true,
                    scope,
                });
                Ok(())
            }
            ("conditional_expression", _) => {
                let (consequence, condition, alternative) = conditional_expression_parts(node)?;
                let consequence_entry = self.point(builder, consequence, Vec::new())?;
                let alternative_entry = self.point(builder, alternative, Vec::new())?;
                stack.push(Work::Condition {
                    node: alternative,
                    entry: alternative_entry,
                    when_true,
                    when_false,
                    scope,
                });
                stack.push(Work::Condition {
                    node: consequence,
                    entry: consequence_entry,
                    when_true,
                    when_false,
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
            ("comparison_operator", _) => {
                self.comparison_control(builder, node, entry, when_true, when_false, scope, stack)
            }
            ("parenthesized_expression", _) => {
                let value =
                    first_runtime_named_child(node).ok_or_else(|| missing_field(node, "value"))?;
                stack.push(Work::Condition {
                    node: value,
                    entry,
                    when_true,
                    when_false,
                    scope,
                });
                Ok(())
            }
            _ => self.atomic_condition(builder, node, entry, when_true, when_false, scope, stack),
        }
    }

    // A condition evaluated as part of a value expression retains each
    // selected operand before continuing along its truth edge.
    #[allow(clippy::too_many_arguments)]
    fn value_condition(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        when_true: EdgeTarget,
        when_false: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PythonLoweringError> {
        let result = self.expression_value(builder, node, expression_value_kind(node))?;
        if let Some(value) = literal_truth_condition(node) {
            let taken = if value { when_true } else { when_false };
            self.edge(builder, entry, taken)?;
            self.session.add_guard_fact(
                builder,
                entry,
                GuardPredicate::ConstantBoolean { value },
                None,
                value.then_some(GuardArm {
                    target_point: when_true.point,
                    kind: when_true.kind,
                }),
                (!value).then_some(GuardArm {
                    target_point: when_false.point,
                    kind: when_false.kind,
                }),
            )?;
            return Ok(());
        }
        match (node.kind(), boolean_operator_kind(node)) {
            ("boolean_operator", Some("and")) => {
                let left = required_field(node, "left")?;
                let right = required_field(node, "right")?;
                let right_entry = self.point(builder, right, Vec::new())?;
                let right_true =
                    self.expression_result_continuation(builder, right, result, when_true)?;
                let right_false =
                    self.expression_result_continuation(builder, right, result, when_false)?;
                let left_selected =
                    self.expression_result_continuation(builder, left, result, when_false)?;
                stack.push(Work::ValueCondition {
                    node: right,
                    entry: right_entry,
                    when_true: EdgeTarget {
                        point: right_true.point,
                        ..when_true
                    },
                    when_false: EdgeTarget {
                        point: right_false.point,
                        ..when_false
                    },
                    scope,
                });
                stack.push(Work::ValueCondition {
                    node: left,
                    entry,
                    when_true: EdgeTarget {
                        point: right_entry,
                        kind: ControlEdgeKind::ConditionalTrue,
                    },
                    when_false: EdgeTarget {
                        point: left_selected.point,
                        ..when_false
                    },
                    scope,
                });
                Ok(())
            }
            ("boolean_operator", Some("or")) => {
                let left = required_field(node, "left")?;
                let right = required_field(node, "right")?;
                let right_entry = self.point(builder, right, Vec::new())?;
                let right_true =
                    self.expression_result_continuation(builder, right, result, when_true)?;
                let right_false =
                    self.expression_result_continuation(builder, right, result, when_false)?;
                let left_selected =
                    self.expression_result_continuation(builder, left, result, when_true)?;
                stack.push(Work::ValueCondition {
                    node: right,
                    entry: right_entry,
                    when_true: EdgeTarget {
                        point: right_true.point,
                        ..when_true
                    },
                    when_false: EdgeTarget {
                        point: right_false.point,
                        ..when_false
                    },
                    scope,
                });
                stack.push(Work::ValueCondition {
                    node: left,
                    entry,
                    when_true: EdgeTarget {
                        point: left_selected.point,
                        ..when_true
                    },
                    when_false: EdgeTarget {
                        point: right_entry,
                        kind: ControlEdgeKind::ConditionalFalse,
                    },
                    scope,
                });
                Ok(())
            }
            ("not_operator", _) => {
                let argument = required_field(node, "argument")?;
                let source =
                    self.expression_value(builder, argument, expression_value_kind(argument))?;
                let true_result = self.point(builder, node, Vec::new())?;
                let false_result = self.point(builder, node, Vec::new())?;
                for (terminal, next) in [(true_result, when_true), (false_result, when_false)] {
                    self.session.append_language_defined_value_flows(
                        builder,
                        terminal,
                        [source],
                        result,
                    )?;
                    self.edge(builder, terminal, next)?;
                }
                stack.push(Work::ValueCondition {
                    node: argument,
                    entry,
                    when_true: EdgeTarget {
                        point: false_result,
                        ..when_false
                    },
                    when_false: EdgeTarget {
                        point: true_result,
                        ..when_true
                    },
                    scope,
                });
                Ok(())
            }
            ("conditional_expression", _) => {
                let (consequence, condition, alternative) = conditional_expression_parts(node)?;
                let consequence_entry = self.point(builder, consequence, Vec::new())?;
                let alternative_entry = self.point(builder, alternative, Vec::new())?;
                let alternative_true =
                    self.expression_result_continuation(builder, alternative, result, when_true)?;
                let alternative_false =
                    self.expression_result_continuation(builder, alternative, result, when_false)?;
                stack.push(Work::ValueCondition {
                    node: alternative,
                    entry: alternative_entry,
                    when_true: EdgeTarget {
                        point: alternative_true.point,
                        ..when_true
                    },
                    when_false: EdgeTarget {
                        point: alternative_false.point,
                        ..when_false
                    },
                    scope,
                });
                let consequence_true =
                    self.expression_result_continuation(builder, consequence, result, when_true)?;
                let consequence_false =
                    self.expression_result_continuation(builder, consequence, result, when_false)?;
                stack.push(Work::ValueCondition {
                    node: consequence,
                    entry: consequence_entry,
                    when_true: EdgeTarget {
                        point: consequence_true.point,
                        ..when_true
                    },
                    when_false: EdgeTarget {
                        point: consequence_false.point,
                        ..when_false
                    },
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
            ("comparison_operator", _) => {
                self.comparison_control(builder, node, entry, when_true, when_false, scope, stack)
            }
            ("parenthesized_expression", _) => {
                let value =
                    first_runtime_named_child(node).ok_or_else(|| missing_field(node, "value"))?;
                let true_result =
                    self.expression_result_continuation(builder, value, result, when_true)?;
                let false_result =
                    self.expression_result_continuation(builder, value, result, when_false)?;
                stack.push(Work::ValueCondition {
                    node: value,
                    entry,
                    when_true: EdgeTarget {
                        point: true_result.point,
                        ..when_true
                    },
                    when_false: EdgeTarget {
                        point: false_result.point,
                        ..when_false
                    },
                    scope,
                });
                Ok(())
            }
            _ => self.atomic_condition(builder, node, entry, when_true, when_false, scope, stack),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn atomic_condition(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        when_true: EdgeTarget,
        when_false: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PythonLoweringError> {
        let decision = self.point(builder, node, Vec::new())?;
        self.add_gap(
            builder,
            decision,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unknown,
            "truth testing may invoke __bool__ or __len__ and requires runtime refinement",
        )?;
        self.add_gap(
            builder,
            decision,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            "truth-test dispatch and conversion failures are not lowered",
        )?;
        self.edge(builder, decision, when_true)?;
        self.edge(builder, decision, when_false)?;
        let (predicate, subject) = self.normalize_guard(builder, node)?;
        self.session.add_guard_fact(
            builder,
            decision,
            predicate,
            subject,
            Some(GuardArm {
                target_point: when_true.point,
                kind: when_true.kind,
            }),
            Some(GuardArm {
                target_point: when_false.point,
                kind: when_false.kind,
            }),
        )?;
        stack.push(Work::Expression {
            node,
            entry,
            next: EdgeTarget::normal(decision),
            scope,
        });
        Ok(())
    }

    /// The binding a condition reads when the condition is a walrus assignment.
    ///
    /// `if (origin := detect()):` and `if (m := match()) is None:` state a fact
    /// about the bound name. The walrus lowers the name and the expression's
    /// own result as two assignments from one source, so the result temporary
    /// has no path back to the binding and narrowing finds no binding to
    /// constrain. Name the binding instead.
    fn walrus_binding_value(&self, node: Node<'tree>) -> Option<ValueId> {
        let mut node = node;
        while node.kind() == "parenthesized_expression" {
            node = first_runtime_named_child(node)?;
        }
        if node.kind() != "named_expression" {
            return None;
        }
        let name = node.child_by_field_name("name")?;
        if name.kind() != "identifier" {
            return None;
        }
        self.binding_value(node_text(self.prepared.source(), name)?)
    }

    fn normalize_guard(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<(GuardPredicate, Option<ValueId>), PythonLoweringError> {
        let arguments = call_arguments(node);
        if arguments.len() == 2
            && self.proven_builtin_call(node, "isinstance", self.builtin_proofs.isinstance)
        {
            let value_node = python_argument_value_node(arguments[0]);
            let classes_node = python_argument_value_node(arguments[1]);
            let value =
                self.expression_value(builder, value_node, expression_value_kind(value_node))?;
            let classes =
                self.expression_value(builder, classes_node, expression_value_kind(classes_node))?;
            let subject = self.expression_value(builder, node, expression_value_kind(node))?;
            return Ok((GuardPredicate::InstanceOf { value, classes }, Some(subject)));
        }
        if arguments.len() == 2
            && self.proven_builtin_call(node, "hasattr", self.builtin_proofs.hasattr)
        {
            let value_node = python_argument_value_node(arguments[0]);
            let member_node = python_argument_value_node(arguments[1]);
            let value =
                self.expression_value(builder, value_node, expression_value_kind(value_node))?;
            let member =
                self.expression_value(builder, member_node, expression_value_kind(member_node))?;
            let subject = self.expression_value(builder, node, expression_value_kind(node))?;
            return Ok((GuardPredicate::HasMember { value, member }, Some(subject)));
        }
        if let Some(binding) = self.walrus_binding_value(node) {
            return Ok((GuardPredicate::Truthy { value: binding }, Some(binding)));
        }
        let subject = self.expression_value(builder, node, expression_value_kind(node))?;
        // A condition that is a reference is read for its truth, and the
        // subject value is that reference. A call or an operator names its own
        // temporary, whose truth says nothing about any operand.
        if matches!(node.kind(), "identifier" | "attribute") {
            return Ok((GuardPredicate::Truthy { value: subject }, Some(subject)));
        }
        Ok((
            GuardPredicate::Opaque {
                digest: GuardConditionDigest::from_syntax_kind(node.kind()),
            },
            Some(subject),
        ))
    }

    /// The subject and classes operands of a `type(value) is C` or
    /// `type(value) in (A, B)` condition.
    ///
    /// Only these two operators name the runtime class. The grammar spells
    /// `is not` as one operator token, and it means the opposite arm, which
    /// this predicate does not carry. `==` runs a metaclass `__eq__` that can
    /// answer anything. A comparison chain carries more than one operator
    /// token and states more than one relation, so it is not this shape.
    fn exact_class_comparison(
        &self,
        node: Node<'tree>,
    ) -> Option<(Node<'tree>, Node<'tree>, bool)> {
        if node.kind() != "comparison_operator" {
            return None;
        }
        let mut cursor = node.walk();
        let operators = node
            .children_by_field_name("operators", &mut cursor)
            .map(|operator| operator.kind())
            .collect::<Vec<_>>();
        let exact_on_true = match operators.as_slice() {
            ["is"] | ["in"] => true,
            ["is not"] | ["not in"] => false,
            _ => return None,
        };
        // The grammar gives a comparison no operand fields: its named children
        // are the operands in source order.
        let operands = named_children(node);
        let [left, right] = operands.as_slice() else {
            return None;
        };
        if !self.proven_builtin_call(*left, "type", self.builtin_proofs.r#type) {
            return None;
        }
        let arguments = call_arguments(*left);
        let [argument] = arguments.as_slice() else {
            return None;
        };
        if matches!(
            argument.kind(),
            "keyword_argument" | "list_splat" | "dictionary_splat"
        ) {
            return None;
        }
        Some((*argument, *right, exact_on_true))
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
    ) -> Result<(), PythonLoweringError> {
        match node.kind() {
            "block" | "module" => {
                let children = named_children(node)
                    .into_iter()
                    .filter(|child| is_statement_kind(child.kind()))
                    .collect::<Vec<_>>();
                self.schedule_statements(builder, entry, &children, next, scope, stack)
            }
            "expression_statement" => {
                let expressions = named_children(node);
                self.schedule_expressions(builder, entry, &expressions, next, scope, stack)
            }
            "return_statement" => {
                let values = runtime_expression_children(node);
                let terminal = if values.is_empty() {
                    entry
                } else {
                    self.point(builder, node, Vec::new())?
                };
                let route = builder
                    .resolve_completion(
                        scope,
                        &CompletionRequest::new(CompletionKind::Return, None),
                    )
                    .ok_or_else(|| {
                        PythonLoweringError::Invalid(
                            "return completion has no matching structured continuation".into(),
                        )
                    })?;
                // Evaluate the expression before cleanup, but publish its saved
                // value only if cleanup preserves this return. An abrupt cleanup
                // can replace or cancel it without reaching this continuation.
                let completion = if route.cleanups().is_empty() {
                    terminal
                } else {
                    self.point(builder, node, Vec::new())?
                };
                match values.as_slice() {
                    [] => self.publish_none_return(builder, completion)?,
                    [source_node] => {
                        let source = self.expression_value(
                            builder,
                            *source_node,
                            expression_value_kind(*source_node),
                        )?;
                        self.publish_return(builder, completion, source)?;
                    }
                    _ => {
                        let value = self.value(builder, completion, SemanticValueKind::Return)?;
                        self.add_gap(
                            builder,
                            terminal,
                            SemanticGapSubject::Point,
                            SemanticCapability::ReturnFlow,
                            SemanticGapKind::Unsupported,
                            "Python tuple return identity is not decomposed into independent values",
                        )?;
                        self.append_effect(
                            builder,
                            completion,
                            SemanticEffect::ProcedureReturn { value: Some(value) },
                        )?;
                    }
                }
                if completion == terminal {
                    self.route(builder, terminal, &route, stack)?;
                } else {
                    self.edge(
                        builder,
                        completion,
                        EdgeTarget {
                            point: route.destination().target(),
                            kind: route.destination().edge_kind(),
                        },
                    )?;
                    let route = builder.redirect_completion(route, completion);
                    self.route(builder, terminal, &route, stack)?;
                }
                if values.is_empty() {
                    Ok(())
                } else {
                    self.schedule_expressions(
                        builder,
                        entry,
                        &values,
                        EdgeTarget::normal(terminal),
                        scope,
                        stack,
                    )
                }
            }
            "raise_statement" => {
                let values = runtime_expression_children(node);
                let terminal = if values.is_empty() {
                    entry
                } else {
                    self.point(builder, node, Vec::new())?
                };
                let value = if let [source_node] = values.as_slice() {
                    let source = self.expression_value(
                        builder,
                        *source_node,
                        expression_value_kind(*source_node),
                    )?;
                    let value = self.value(builder, terminal, SemanticValueKind::Exception)?;
                    self.append_effect(
                        builder,
                        terminal,
                        SemanticEffect::ValueFlow {
                            kind: ValueFlowKind::Local,
                            source,
                            target: value,
                        },
                    )?;
                    Some(value)
                } else {
                    let detail = if values.is_empty() {
                        "bare Python re-raise has no represented active exception payload"
                    } else {
                        "Python raise forms with multiple expressions are not lowered"
                    };
                    self.add_gap(
                        builder,
                        terminal,
                        SemanticGapSubject::Point,
                        SemanticCapability::ExceptionalControlFlow,
                        SemanticGapKind::Unsupported,
                        detail,
                    )?;
                    None
                };
                self.append_effect(builder, terminal, SemanticEffect::Throw { value })?;
                if let Some(value) = value {
                    self.abrupt_throw(builder, terminal, scope, value, stack)?;
                } else {
                    self.abrupt(builder, terminal, scope, CompletionKind::Throw, None, stack)?;
                }
                if values.is_empty() {
                    Ok(())
                } else {
                    self.schedule_expressions(
                        builder,
                        entry,
                        &values,
                        EdgeTarget::normal(terminal),
                        scope,
                        stack,
                    )
                }
            }
            "break_statement" | "continue_statement" => {
                let kind = if node.kind() == "break_statement" {
                    CompletionKind::Break
                } else {
                    CompletionKind::Continue
                };
                self.abrupt(builder, entry, scope, kind, None, stack)
            }
            "if_statement" => self.if_statement(builder, node, entry, next, scope, stack),
            "while_statement" => self.while_statement(builder, node, entry, next, scope, stack),
            "for_statement" => self.for_statement(builder, node, entry, next, scope, stack),
            "try_statement" => self.try_statement(builder, node, entry, next, scope, stack),
            "with_statement" => self.with_statement(builder, node, entry, next, scope, stack),
            "match_statement" => self.match_statement(builder, node, entry, next, scope, stack),
            "assert_statement" => self.assert_statement(builder, node, entry, next, scope, stack),
            "delete_statement" => {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::ExceptionalControlFlow,
                    SemanticGapKind::Unsupported,
                    "attribute, item, and name deletion failures are not lowered",
                )?;
                let mut pending = runtime_expression_children(node);
                pending.reverse();
                let mut previous = entry;
                while let Some(target) = pending.pop() {
                    if matches!(
                        target.kind(),
                        "tuple" | "list" | "expression_list" | "parenthesized_expression"
                    ) {
                        pending.extend(runtime_expression_children(target).into_iter().rev());
                        continue;
                    }
                    let terminal = self.point(builder, target, Vec::new())?;
                    if self.proven_tuple_mutation(target) {
                        let runtime = assignment_target_runtime_nodes(target);
                        self.schedule_expressions(
                            builder,
                            previous,
                            &runtime,
                            EdgeTarget::normal(terminal),
                            scope,
                            stack,
                        )?;
                        return self.tuple_mutation_failure(builder, terminal, scope, stack);
                    }
                    self.schedule_expressions(
                        builder,
                        previous,
                        &[target],
                        EdgeTarget::normal(terminal),
                        scope,
                        stack,
                    )?;
                    previous = terminal;
                }
                self.edge(builder, previous, next)
            }
            "import_statement" | "import_from_statement" | "future_import_statement" => {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::Calls,
                    SemanticGapKind::Unsupported,
                    "module loading and import hooks are not represented as call sites",
                )?;
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::ExceptionalControlFlow,
                    SemanticGapKind::Unsupported,
                    "module loading and import failures are not lowered",
                )?;
                self.edge(builder, entry, next)
            }
            "type_alias_statement" => {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::DeferredExecution,
                    SemanticGapKind::Unsupported,
                    "type-alias evaluation and lazy type-parameter behavior are not lowered",
                )?;
                self.edge(builder, entry, next)
            }
            "pass_statement" | "global_statement" | "nonlocal_statement" => {
                self.edge(builder, entry, next)
            }
            "function_definition" => self.definition_statement(builder, entry, next, false),
            "class_definition" => self.definition_statement(builder, entry, next, true),
            "decorated_definition" => {
                let defines_class = named_children(node)
                    .into_iter()
                    .any(|child| child.kind() == "class_definition");
                self.definition_statement(builder, entry, next, defines_class)
            }
            "print_statement" | "exec_statement" => {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::Calls,
                    SemanticGapKind::Unsupported,
                    "legacy statement runtime calls are not represented as call sites",
                )?;
                let values = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &values, next, scope, stack)
            }
            _ => self.unhandled_control_syntax(builder, node, entry, next),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn assert_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PythonLoweringError> {
        let expressions = named_children(node);
        let condition = expressions
            .first()
            .copied()
            .ok_or_else(|| missing_field(node, "condition"))?;
        let messages = &expressions[1..];

        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::NormalControlFlow,
            SemanticGapKind::Unknown,
            "optimized-mode configuration may remove the assertion and all of its expression evaluation",
        )?;

        let failure = self.point(builder, node, Vec::new())?;
        let exception = self.value(builder, failure, SemanticValueKind::Exception)?;
        self.append_effect(
            builder,
            failure,
            SemanticEffect::Throw {
                value: Some(exception),
            },
        )?;
        self.abrupt(builder, failure, scope, CompletionKind::Throw, None, stack)?;

        let false_target = if messages.is_empty() {
            failure
        } else {
            let message_entry = self.point(builder, node, Vec::new())?;
            self.schedule_expressions(
                builder,
                message_entry,
                messages,
                EdgeTarget::normal(failure),
                scope,
                stack,
            )?;
            message_entry
        };
        stack.push(Work::Condition {
            node: condition,
            entry,
            when_true: EdgeTarget {
                point: next.point,
                kind: ControlEdgeKind::ConditionalTrue,
            },
            when_false: EdgeTarget {
                point: false_target,
                kind: ControlEdgeKind::ConditionalFalse,
            },
            scope,
        });
        Ok(())
    }

    fn definition_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        next: EdgeTarget,
        defines_class: bool,
    ) -> Result<(), PythonLoweringError> {
        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unsupported,
            "definition-time decorator, default, annotation, base, and metaclass calls are not represented as call sites",
        )?;
        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            "definition-time evaluation and callable or class construction failures are not lowered",
        )?;
        if defines_class {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::NormalControlFlow,
                SemanticGapKind::Unsupported,
                "class-body execution, namespace preparation, and metaclass construction are not lowered",
            )?;
        }
        self.edge(builder, entry, next)
    }

    /// Copy only the selected operand after it completes normally. Exceptional
    /// exits bypass this point, and the caller schedules each operand once.
    fn expression_result_continuation(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        operand: Node<'tree>,
        result: ValueId,
        next: EdgeTarget,
    ) -> Result<EdgeTarget, PythonLoweringError> {
        let terminal = self.point(builder, operand, Vec::new())?;
        let source = self.expression_value(builder, operand, expression_value_kind(operand))?;
        self.append_effect(
            builder,
            terminal,
            SemanticEffect::Assignment {
                target: result,
                value: source,
            },
        )?;
        self.edge(builder, terminal, next)?;
        Ok(EdgeTarget::normal(terminal))
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
    ) -> Result<(), PythonLoweringError> {
        let result = self.expression_value(builder, node, expression_value_kind(node))?;
        if node.kind() == "identifier" {
            self.emit_lexical_input_flow(builder, node, entry, result)?;
        }
        match node.kind() {
            "call" if self.proven_builtin_str_call(node) => {
                self.builtin_str_expression(builder, node, entry, next, scope, stack)
            }
            "call" => self.call_expression(builder, node, entry, next, scope, stack),
            "lambda" => self.callable_expression(builder, node, entry, next),
            "await" => self.await_expression(builder, node, entry, next, scope, stack),
            "yield" => self.yield_expression(builder, node, entry, scope, stack),
            "conditional_expression" => {
                let (consequence, condition, alternative) = conditional_expression_parts(node)?;
                let consequence_entry = self.point(builder, consequence, Vec::new())?;
                let alternative_entry = self.point(builder, alternative, Vec::new())?;
                for (arm, arm_entry) in [
                    (alternative, alternative_entry),
                    (consequence, consequence_entry),
                ] {
                    let completion =
                        self.expression_result_continuation(builder, arm, result, next)?;
                    stack.push(Work::Expression {
                        node: arm,
                        entry: arm_entry,
                        next: completion,
                        scope,
                    });
                }
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
            "boolean_operator" if matches!(boolean_operator_kind(node), Some("and" | "or")) => {
                let left = required_field(node, "left")?;
                let right = required_field(node, "right")?;
                let right_entry = self.point(builder, right, Vec::new())?;
                let left_completion =
                    self.expression_result_continuation(builder, left, result, next)?;
                let right_completion =
                    self.expression_result_continuation(builder, right, result, next)?;
                stack.push(Work::Expression {
                    node: right,
                    entry: right_entry,
                    next: right_completion,
                    scope,
                });
                let (when_true, when_false) = match boolean_operator_kind(node) {
                    Some("and") => (
                        EdgeTarget {
                            point: right_entry,
                            kind: ControlEdgeKind::ConditionalTrue,
                        },
                        EdgeTarget {
                            point: left_completion.point,
                            kind: ControlEdgeKind::ConditionalFalse,
                        },
                    ),
                    Some("or") => (
                        EdgeTarget {
                            point: left_completion.point,
                            kind: ControlEdgeKind::ConditionalTrue,
                        },
                        EdgeTarget {
                            point: right_entry,
                            kind: ControlEdgeKind::ConditionalFalse,
                        },
                    ),
                    _ => unreachable!("guarded by boolean operator"),
                };
                stack.push(Work::ValueCondition {
                    node: left,
                    entry,
                    when_true,
                    when_false,
                    scope,
                });
                Ok(())
            }
            "parenthesized_expression" => {
                if let Some(value) = first_runtime_named_child(node) {
                    let terminal = self.point(builder, node, Vec::new())?;
                    let source =
                        self.expression_value(builder, value, expression_value_kind(value))?;
                    self.append_effect(
                        builder,
                        terminal,
                        SemanticEffect::Assignment {
                            target: result,
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
                } else {
                    self.edge(builder, entry, next)
                }
            }
            "comparison_operator" => {
                self.comparison_expression(builder, node, entry, next, scope, stack)
            }
            "attribute" => {
                let object = required_field(node, "object")?;
                let attribute = required_field(node, "attribute")?;
                let proven = self.proven_instance_attribute(node, object, attribute);
                let Some(member) = self.memory_member_locator(attribute)? else {
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Value(result),
                        SemanticCapability::FieldMemory,
                        SemanticGapKind::Unknown,
                        "Python attribute name is not a structured identifier",
                    )?;
                    let continuation = if proven {
                        next
                    } else {
                        let claims = self
                            .unresolved_member_read_claims(builder, node, result, scope, stack)?;
                        self.edge(builder, claims, next)?;
                        EdgeTarget::normal(claims)
                    };
                    return self.schedule_expressions(
                        builder,
                        entry,
                        &[object],
                        continuation,
                        scope,
                        stack,
                    );
                };
                let claims = if proven {
                    None
                } else {
                    Some(self.unresolved_member_read_claims(builder, node, result, scope, stack)?)
                };
                let load = self.point(builder, node, Vec::new())?;
                let reached_load = match claims {
                    Some(claims) => {
                        self.edge(builder, claims, EdgeTarget::normal(load))?;
                        EdgeTarget::normal(claims)
                    }
                    None => EdgeTarget::normal(load),
                };
                let base = self.expression_value(builder, object, expression_value_kind(object))?;
                let location = self.session.add_memory_location(
                    builder,
                    load,
                    MemoryLocationKind::Field { base, member },
                )?;
                self.append_effect(
                    builder,
                    load,
                    SemanticEffect::MemoryLoad {
                        kind: MemoryAccessKind::Field,
                        location,
                        result,
                    },
                )?;
                self.edge(builder, load, next)?;
                self.schedule_expressions(builder, entry, &[object], reached_load, scope, stack)
            }
            "subscript" => {
                let value = required_field(node, "value")?;
                let subscript = required_field(node, "subscript")?;
                let proven = self.proven_sequence_index_read(node, value, subscript);
                // The same two claims as the attribute arm above.
                let claims = if proven {
                    None
                } else {
                    Some(self.unresolved_member_read_claims(builder, node, result, scope, stack)?)
                };
                let access = self.point(builder, node, Vec::new())?;
                let reached_access = match claims {
                    Some(claims) => {
                        self.edge(builder, claims, EdgeTarget::normal(access))?;
                        EdgeTarget::normal(claims)
                    }
                    None => EdgeTarget::normal(access),
                };
                let base = self.expression_value(builder, value, expression_value_kind(value))?;
                let index = self.constant_index_value(builder, subscript)?;
                let location = self.session.add_memory_location(
                    builder,
                    access,
                    MemoryLocationKind::Index {
                        base,
                        index: index.map(|(value, _)| value),
                        constant_index: index.map(|(_, magnitude)| magnitude),
                        identity: crate::analyzer::semantic::IndexedLocationIdentity::Element,
                    },
                )?;
                if index.is_none() {
                    self.add_dynamic_index_gap(builder, access, location)?;
                }
                self.append_effect(
                    builder,
                    access,
                    SemanticEffect::MemoryLoad {
                        kind: MemoryAccessKind::Index,
                        location,
                        result,
                    },
                )?;
                self.edge(builder, access, next)?;
                self.schedule_expressions(
                    builder,
                    entry,
                    &[value, subscript],
                    reached_access,
                    scope,
                    stack,
                )
            }
            "list_comprehension" | "set_comprehension" | "dictionary_comprehension" => {
                self.session
                    .add_allocation(builder, entry, result, AllocationKind::Object)?;
                self.eager_comprehension_expression(builder, node, entry, next, scope, stack)
            }
            "generator_expression" => {
                self.session
                    .add_allocation(builder, entry, result, AllocationKind::Object)?;
                self.generator_expression(builder, node, entry, next, scope, stack)
            }
            "assignment" | "named_expression" => {
                self.assignment_expression(builder, node, entry, next, scope, stack)
            }
            "augmented_assignment" => {
                self.augmented_assignment_expression(builder, node, entry, next, scope, stack)
            }
            "set" | "dictionary" => {
                self.session
                    .add_allocation(builder, entry, result, AllocationKind::Object)?;
                let children = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            "list" | "tuple" | "expression_list" => {
                self.sequence_literal_expression(builder, node, entry, next, scope, stack)
            }
            "binary_operator" | "unary_operator" | "not_operator" => {
                if may_invoke_user_code(node) {
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::Calls,
                        SemanticGapKind::Unknown,
                        "operator, conversion, formatting, or unpacking calls require type refinement",
                    )?;
                }
                let children = runtime_expression_children(node);
                let terminal = self.point(builder, node, Vec::new())?;
                if operation_can_throw_implicitly(node) {
                    self.implicit_abort_route(builder, node, terminal, scope, stack)?;
                }
                let operands = children
                    .iter()
                    .map(|child| {
                        self.expression_value(builder, *child, expression_value_kind(*child))
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
            "interpolation" | "format_expression" | "concatenated_string" | "string" => {
                if may_invoke_user_code(node) {
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::Calls,
                        SemanticGapKind::Unknown,
                        "operator, conversion, formatting, or unpacking calls require type refinement",
                    )?;
                }
                // A formatted string derives its value from every interpolated
                // expression, an interpolation from the expression it renders,
                // and a concatenated string from every literal part. The
                // rendering itself (__format__, conversion, the format spec)
                // stays unrefined behind the gap above, but the operands flow
                // into the result the way they do for `a + b`.
                let children = runtime_expression_children(node);
                let terminal = self.point(builder, node, Vec::new())?;
                // The abort leaves the point that performs the conversion, so
                // the operands this node formats are already evaluated on the
                // abort path.
                if operation_can_throw_implicitly(node) {
                    self.implicit_abort_route(builder, node, terminal, scope, stack)?;
                }
                let operands = children
                    .iter()
                    .map(|child| {
                        self.expression_value(builder, *child, expression_value_kind(*child))
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
            "pair"
            | "slice"
            | "argument_list"
            | "keyword_argument"
            | "list_splat"
            | "dictionary_splat"
            | "parenthesized_list_splat" => {
                if may_invoke_user_code(node) {
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::Calls,
                        SemanticGapKind::Unknown,
                        "operator, conversion, formatting, or unpacking calls require type refinement",
                    )?;
                }
                let children = runtime_expression_children(node);
                // The abort leaves the point that performs the conversion, so
                // the operands this node unpacks or formats are already
                // evaluated on the abort path.
                let next = if operation_can_throw_implicitly(node) {
                    let terminal = self.point(builder, node, Vec::new())?;
                    self.implicit_abort_route(builder, node, terminal, scope, stack)?;
                    self.edge(builder, terminal, next)?;
                    EdgeTarget::normal(terminal)
                } else {
                    next
                };
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            kind if is_runtime_leaf(kind) => self.edge(builder, entry, next),
            _ => self.unhandled_control_syntax(builder, node, entry, next),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn assignment_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PythonLoweringError> {
        let (bindings, source_node) = if node.kind() == "named_expression" {
            (
                node.child_by_field_name("name").into_iter().collect(),
                node.child_by_field_name("value"),
            )
        } else {
            let (bindings, source) = assignment_chain(node);
            (bindings, source)
        };
        let suppresses_implicit_exception = bindings.len() == 1
            && source_node.is_some_and(|source| {
                let binding = bindings[0];
                match binding.kind() {
                    "attribute" => binding
                        .child_by_field_name("object")
                        .zip(binding.child_by_field_name("attribute"))
                        .is_some_and(|(object, attribute)| {
                            self.proven_instance_attribute(node, object, attribute)
                        }),
                    "subscript" => binding
                        .child_by_field_name("value")
                        .zip(binding.child_by_field_name("subscript"))
                        .is_some_and(|(value, index)| self.proven_list_index(node, value, index)),
                    "identifier" => {
                        self.proven_local_instance_initialization(binding, source)
                            || source.kind() == "call"
                    }
                    _ => false,
                }
            });
        let boundary = self.point(builder, node, Vec::new())?;
        let completion = if let Some(source_node) = source_node
            && !bindings.is_empty()
            && bindings
                .iter()
                .all(|binding| is_assignment_target(*binding))
        {
            let mut completion = Some(boundary);
            for binding in bindings {
                let Some(previous) = completion else {
                    break;
                };
                completion = self.append_target_source_assignments(
                    builder,
                    previous,
                    node,
                    binding,
                    Some(source_node),
                    PYTHON_UNKNOWN_UNPACK_ELEMENT,
                    scope,
                    stack,
                )?;
            }
            if node.kind() == "named_expression"
                && let Some(completion) = completion
            {
                let source = self.expression_value(
                    builder,
                    source_node,
                    expression_value_kind(source_node),
                )?;
                let result = self.expression_value(builder, node, SemanticValueKind::Temporary)?;
                self.append_effect(
                    builder,
                    completion,
                    SemanticEffect::Assignment {
                        target: result,
                        value: source,
                    },
                )?;
            }
            completion
        } else {
            self.add_gap(
                builder,
                boundary,
                SemanticGapSubject::Point,
                SemanticCapability::Assignments,
                SemanticGapKind::Unsupported,
                "Python assignment is missing a structured writable target or value",
            )?;
            Some(boundary)
        };
        if operation_can_throw_implicitly(node) && !suppresses_implicit_exception {
            self.implicit_abort_route(builder, node, boundary, scope, stack)?;
        }
        if let Some(completion) = completion {
            self.edge(builder, completion, next)?;
        }
        // The entire RHS executes before unpacking or target evaluation.
        // Its own lowering publishes any call, allocation, or exceptional edge.
        let sources = source_node.into_iter().collect::<Vec<_>>();
        self.schedule_expressions(
            builder,
            entry,
            &sources,
            EdgeTarget::normal(boundary),
            scope,
            stack,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn augmented_assignment_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PythonLoweringError> {
        let target = required_field(node, "left")?;
        let rhs = required_field(node, "right")?;
        if !matches!(
            target.kind(),
            "identifier" | "keyword_identifier" | "attribute" | "subscript"
        ) {
            return self.unhandled_control_syntax(builder, node, entry, next);
        }

        let operation = self.point(builder, node, Vec::new())?;
        self.implicit_abort_route(builder, node, operation, scope, stack)?;
        self.add_gap(
            builder,
            operation,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unknown,
            "augmented-assignment operator dispatch requires type refinement",
        )?;
        // `x += y` stores a value that derives from the current target and the
        // operand, whatever the refined operator semantics turn out to be:
        // `__iadd__` mutates the target with the operand, `__add__` produces a
        // new value from both. The result stays language-defined unknown, but
        // both operands flow into it the way they do for `x = x + y`.
        let target_value = self.expression_value(builder, target, expression_value_kind(target))?;
        let rhs_value = self.expression_value(builder, rhs, expression_value_kind(rhs))?;
        let result =
            self.unknown_target_value(builder, node, PYTHON_UNKNOWN_AUGMENTED_ASSIGNMENT)?;
        self.session.append_language_defined_value_flows(
            builder,
            operation,
            [target_value, rhs_value],
            result,
        )?;
        let store = self.point(builder, target, Vec::new())?;
        if self.proven_tuple_mutation(target) {
            self.tuple_mutation_failure(builder, store, scope, stack)?;
        } else {
            self.append_target_assignment(builder, store, node, target, result)?;
            self.edge(builder, store, next)?;
        }
        self.edge(builder, operation, EdgeTarget::normal(store))?;
        self.schedule_expressions(
            builder,
            entry,
            &[target, rhs],
            EdgeTarget::normal(operation),
            scope,
            stack,
        )
    }

    fn proven_local_instance_initialization(
        &self,
        binding: Node<'tree>,
        source: Node<'tree>,
    ) -> bool {
        let Some(name) = (binding.kind() == "identifier")
            .then(|| node_text(self.prepared.source(), binding))
            .flatten()
        else {
            return false;
        };
        let Some(expected_class) = self.known_instance_bindings.get(name) else {
            return false;
        };
        constructed_local_class(
            source,
            self.prepared.source(),
            self.class_names,
            &self.proven_instance_fields,
        )
        .is_some_and(|class_name| class_name.as_ref() == expected_class.as_ref())
    }

    #[allow(clippy::too_many_arguments)]
    fn append_target_source_assignments(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        access: Node<'tree>,
        target: Node<'tree>,
        source: Option<Node<'tree>>,
        unknown_kind: &str,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<Option<ProgramPointId>, PythonLoweringError> {
        let steps = assignment_target_steps(target, source);
        if steps.is_empty()
            || !steps
                .iter()
                .any(|step| matches!(step, AssignmentTargetStep::Leaf { .. }))
        {
            self.add_gap(
                builder,
                point,
                SemanticGapSubject::Point,
                SemanticCapability::Assignments,
                SemanticGapKind::Unsupported,
                "Python assignment target has no structured writable leaves",
            )?;
            return Ok(Some(point));
        }
        let mut previous = point;
        let mut produced_sources = HashMap::default();
        for step in steps {
            match step {
                AssignmentTargetStep::UnpackBoundary {
                    target,
                    source,
                    outputs,
                    may_fail,
                } => {
                    let unpack_point = self.point(builder, target, Vec::new())?;
                    self.edge(builder, previous, EdgeTarget::normal(unpack_point))?;
                    if may_fail {
                        self.implicit_abort_route(builder, target, unpack_point, scope, stack)?;
                    }
                    if !outputs.is_empty() {
                        let base = match source {
                            AssignmentSource::Expression(source) => self.expression_value(
                                builder,
                                source,
                                expression_value_kind(source),
                            )?,
                            AssignmentSource::Produced(source) => *produced_sources
                                .get(&source)
                                .expect("an unpack element is produced before nested unpacking"),
                            AssignmentSource::Unknown => {
                                unreachable!("an unknown unpack source has no modeled outputs")
                            }
                        };
                        for output in outputs {
                            let index = self.value(
                                builder,
                                unpack_point,
                                SemanticValueKind::UnsignedInteger(output.ordinal as u128),
                            )?;
                            let result =
                                self.value(builder, unpack_point, SemanticValueKind::Temporary)?;
                            let location = self.session.add_memory_location(
                                builder,
                                unpack_point,
                                MemoryLocationKind::Index {
                                    base,
                                    index: Some(index),
                                    constant_index: Some(output.ordinal as u128),
                                    identity:
                                        crate::analyzer::semantic::IndexedLocationIdentity::Element,
                                },
                            )?;
                            self.append_effect(
                                builder,
                                unpack_point,
                                SemanticEffect::MemoryLoad {
                                    kind: MemoryAccessKind::Index,
                                    location,
                                    result,
                                },
                            )?;
                            produced_sources.insert(output.id, result);
                        }
                    }
                    previous = unpack_point;
                }
                AssignmentTargetStep::Leaf { target, source } => {
                    let target_point = self.point(builder, target, Vec::new())?;
                    if self.proven_tuple_mutation(target) {
                        let runtime = assignment_target_runtime_nodes(target);
                        self.schedule_expressions(
                            builder,
                            previous,
                            &runtime,
                            EdgeTarget::normal(target_point),
                            scope,
                            stack,
                        )?;
                        self.tuple_mutation_failure(builder, target_point, scope, stack)?;
                        return Ok(None);
                    }
                    let value = match source {
                        AssignmentSource::Expression(source) => {
                            self.expression_value(builder, source, expression_value_kind(source))?
                        }
                        AssignmentSource::Produced(source) => *produced_sources
                            .get(&source)
                            .expect("an unpack leaf is produced before it is assigned"),
                        AssignmentSource::Unknown => {
                            self.unknown_target_value(builder, target, unknown_kind)?
                        }
                    };
                    self.append_target_assignment(builder, target_point, access, target, value)?;
                    match target.kind() {
                        "attribute"
                            if !self.proven_instance_attribute(
                                access,
                                required_field(target, "object")?,
                                required_field(target, "attribute")?,
                            ) =>
                        {
                            self.implicit_abort_route(builder, target, target_point, scope, stack)?;
                        }
                        "subscript"
                            if !self.proven_list_index(
                                access,
                                required_field(target, "value")?,
                                required_field(target, "subscript")?,
                            ) =>
                        {
                            self.implicit_abort_route(builder, target, target_point, scope, stack)?;
                        }
                        _ => {}
                    }
                    let runtime = assignment_target_runtime_nodes(target);
                    self.schedule_expressions(
                        builder,
                        previous,
                        &runtime,
                        EdgeTarget::normal(target_point),
                        scope,
                        stack,
                    )?;
                    previous = target_point;
                }
            }
        }
        Ok(Some(previous))
    }

    fn unknown_target_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        target: Node<'tree>,
        kind: &str,
    ) -> Result<ValueId, PythonLoweringError> {
        let metadata = self.value_mapping(builder, target)?;
        self.session.add_value_with_metadata(
            builder,
            metadata,
            SemanticValueKind::LanguageDefined(kind.into()),
        )
    }

    fn append_target_assignment(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        access: Node<'tree>,
        target: Node<'tree>,
        value: ValueId,
    ) -> Result<(), PythonLoweringError> {
        match target.kind() {
            "identifier" | "keyword_identifier" => {
                let name = node_text(self.prepared.source(), target).ok_or_else(|| {
                    PythonLoweringError::Invalid(
                        "Python assignment has an invalid identifier range".into(),
                    )
                })?;
                let Some((target_value, kind)) =
                    self.scoped_binding_value(builder, target, name)?
                else {
                    return Ok(());
                };
                self.append_effect(
                    builder,
                    point,
                    SemanticEffect::Assignment {
                        target: target_value,
                        value,
                    },
                )?;
                self.append_effect(
                    builder,
                    point,
                    SemanticEffect::ValueFlow {
                        kind,
                        source: value,
                        target: target_value,
                    },
                )?;
            }
            "attribute" => {
                let object = required_field(target, "object")?;
                let attribute = required_field(target, "attribute")?;
                let Some(member) = self.memory_member_locator(attribute)? else {
                    self.add_gap(
                        builder,
                        point,
                        SemanticGapSubject::Point,
                        SemanticCapability::Assignments,
                        SemanticGapKind::Unsupported,
                        "Python attribute assignment requires a structured identifier member",
                    )?;
                    return Ok(());
                };
                let base = self.expression_value(builder, object, expression_value_kind(object))?;
                let location = self.session.add_memory_location(
                    builder,
                    point,
                    MemoryLocationKind::Field { base, member },
                )?;
                if !self.proven_instance_attribute(access, object, attribute) {
                    self.add_gap(
                        builder,
                        point,
                        SemanticGapSubject::MemoryLocation(location),
                        SemanticCapability::Calls,
                        SemanticGapKind::Unknown,
                        "descriptor or special-method invocation requires type refinement",
                    )?;
                }
                self.append_effect(
                    builder,
                    point,
                    SemanticEffect::MemoryStore {
                        kind: MemoryAccessKind::Field,
                        location,
                        value,
                    },
                )?;
            }
            "subscript" => {
                let value_node = required_field(target, "value")?;
                let subscript = required_field(target, "subscript")?;
                let base =
                    self.expression_value(builder, value_node, expression_value_kind(value_node))?;
                let index = self.constant_index_value(builder, subscript)?;
                let location = self.session.add_memory_location(
                    builder,
                    point,
                    MemoryLocationKind::Index {
                        base,
                        index: index.map(|(value, _)| value),
                        constant_index: index.map(|(_, magnitude)| magnitude),
                        identity: crate::analyzer::semantic::IndexedLocationIdentity::Element,
                    },
                )?;
                if !self.proven_list_index(access, value_node, subscript) {
                    self.add_gap(
                        builder,
                        point,
                        SemanticGapSubject::MemoryLocation(location),
                        SemanticCapability::Calls,
                        SemanticGapKind::Unknown,
                        "subscription special-method invocation requires type refinement",
                    )?;
                }
                if index.is_none() {
                    self.add_dynamic_index_gap(builder, point, location)?;
                }
                self.append_effect(
                    builder,
                    point,
                    SemanticEffect::MemoryStore {
                        kind: MemoryAccessKind::Index,
                        location,
                        value,
                    },
                )?;
            }
            _ => {
                self.add_gap(
                    builder,
                    point,
                    SemanticGapSubject::Point,
                    SemanticCapability::Assignments,
                    SemanticGapKind::Unsupported,
                    "Python assignment target is not a structured writable target",
                )?;
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn comparison_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PythonLoweringError> {
        let merge = self.point(builder, node, Vec::new())?;
        self.edge(builder, merge, next)?;
        self.comparison_control(
            builder,
            node,
            entry,
            EdgeTarget {
                point: merge,
                kind: ControlEdgeKind::ConditionalTrue,
            },
            EdgeTarget {
                point: merge,
                kind: ControlEdgeKind::ConditionalFalse,
            },
            scope,
            stack,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn comparison_control(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        when_true: EdgeTarget,
        when_false: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PythonLoweringError> {
        let operands = named_children(node);
        let operators = children_by_field_name(node, "operators");
        if operators.is_empty() || operands.len() != operators.len().saturating_add(1) {
            return Err(PythonLoweringError::Invalid(format!(
                "comparison_operator at bytes {}..{} has {} operand(s) and {} operator(s)",
                node.start_byte(),
                node.end_byte(),
                operands.len(),
                operators.len()
            )));
        }

        let operand_entries = operands
            .iter()
            .map(|operand| self.point(builder, *operand, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        let decisions = operators
            .iter()
            .map(|operator| self.point(builder, *operator, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;

        for (index, (operator, decision)) in operators.iter().zip(&decisions).enumerate() {
            if comparison_may_invoke_user_code(operator.kind()) {
                self.add_gap(
                    builder,
                    *decision,
                    SemanticGapSubject::Point,
                    SemanticCapability::Calls,
                    SemanticGapKind::Unknown,
                    "comparison special-method or containment dispatch requires runtime refinement",
                )?;
                self.add_gap(
                    builder,
                    *decision,
                    SemanticGapSubject::Point,
                    SemanticCapability::ExceptionalControlFlow,
                    SemanticGapKind::Unsupported,
                    "comparison dispatch and result coercion failures are not lowered",
                )?;
            }

            let true_target = operand_entries
                .get(index + 2)
                .copied()
                .map(|point| EdgeTarget {
                    point,
                    kind: ControlEdgeKind::ConditionalTrue,
                })
                .unwrap_or(when_true);
            self.edge(builder, *decision, true_target)?;
            self.edge(builder, *decision, when_false)?;
            let (predicate, subject) = match (
                operator.kind(),
                operands[index].kind(),
                operands[index + 1].kind(),
            ) {
                ("is" | "is not", "none", right) if right != "none" => {
                    let subject = match self.walrus_binding_value(operands[index + 1]) {
                        Some(binding) => binding,
                        None => self.expression_value(
                            builder,
                            operands[index + 1],
                            expression_value_kind(operands[index + 1]),
                        )?,
                    };
                    (
                        GuardPredicate::NullComparison {
                            null_on_true: operator.kind() == "is",
                        },
                        Some(subject),
                    )
                }
                ("is" | "is not", left, "none") if left != "none" => {
                    let subject = match self.walrus_binding_value(operands[index]) {
                        Some(binding) => binding,
                        None => self.expression_value(
                            builder,
                            operands[index],
                            expression_value_kind(operands[index]),
                        )?,
                    };
                    (
                        GuardPredicate::NullComparison {
                            null_on_true: operator.kind() == "is",
                        },
                        Some(subject),
                    )
                }
                _ => {
                    if let Some((value_node, classes_node, exact_on_true)) =
                        self.exact_class_comparison(node)
                    {
                        let value_node = python_argument_value_node(value_node);
                        let value = self.expression_value(
                            builder,
                            value_node,
                            expression_value_kind(value_node),
                        )?;
                        let classes = self.expression_value(
                            builder,
                            classes_node,
                            expression_value_kind(classes_node),
                        )?;
                        let subject =
                            self.expression_value(builder, node, expression_value_kind(node))?;
                        (
                            GuardPredicate::ExactClass {
                                value,
                                classes,
                                exact_on_true,
                            },
                            Some(subject),
                        )
                    } else {
                        let subject =
                            self.expression_value(builder, node, expression_value_kind(node))?;
                        (
                            GuardPredicate::Opaque {
                                digest: GuardConditionDigest::from_syntax_kind(node.kind()),
                            },
                            Some(subject),
                        )
                    }
                }
            };
            self.session.add_guard_fact(
                builder,
                *decision,
                predicate,
                subject,
                Some(GuardArm {
                    target_point: true_target.point,
                    kind: true_target.kind,
                }),
                Some(GuardArm {
                    target_point: when_false.point,
                    kind: when_false.kind,
                }),
            )?;
        }

        self.edge(builder, entry, EdgeTarget::normal(operand_entries[0]))?;
        for index in (0..operands.len()).rev() {
            let target = if index == 0 {
                operand_entries[1]
            } else {
                decisions[index - 1]
            };
            stack.push(Work::Expression {
                node: operands[index],
                entry: operand_entries[index],
                next: EdgeTarget::normal(target),
                scope,
            });
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn sequence_literal_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PythonLoweringError> {
        let result = self.expression_value(builder, node, expression_value_kind(node))?;
        let kind = if node.kind() == "list" {
            AllocationKind::Object
        } else {
            AllocationKind::Array
        };
        self.session.add_allocation(builder, entry, result, kind)?;
        let children = runtime_expression_children(node);
        let terminal = self.point(builder, node, Vec::new())?;
        if sequence_initializer_is_expanded(node) {
            self.add_gap(
                builder,
                terminal,
                SemanticGapSubject::Value(result),
                SemanticCapability::IndexMemory,
                SemanticGapKind::Unsupported,
                "expanded Python sequence initializer positions are not modeled",
            )?;
        } else {
            // Operand temporaries retain their evaluated values. Publish the
            // initialized sequence only after all operands return normally.
            for (ordinal, child) in children.iter().enumerate() {
                let value =
                    self.expression_value(builder, *child, expression_value_kind(*child))?;
                let metadata = self.value_mapping(builder, *child)?;
                let index = self.session.add_value_with_metadata(
                    builder,
                    metadata,
                    SemanticValueKind::UnsignedInteger(ordinal as u128),
                )?;
                let location = self.session.add_memory_location(
                    builder,
                    terminal,
                    MemoryLocationKind::Index {
                        base: result,
                        index: Some(index),
                        constant_index: Some(ordinal as u128),
                        identity: crate::analyzer::semantic::IndexedLocationIdentity::Element,
                    },
                )?;
                self.append_effect(
                    builder,
                    terminal,
                    SemanticEffect::MemoryStore {
                        kind: MemoryAccessKind::Index,
                        location,
                        value,
                    },
                )?;
            }
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

    fn generator_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        continuation: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PythonLoweringError> {
        let outer_iterables = first_comprehension_iterables(node)?;
        let boundary = self.point(builder, node, Vec::new())?;
        self.add_gap(
                builder,
                boundary,
                SemanticGapSubject::Point,
                SemanticCapability::DeferredExecution,
                SemanticGapKind::Unsupported,
                "generator-expression body, filters, and nested clauses execute after construction and are not lowered",
            )?;
        self.add_gap(
            builder,
            boundary,
            SemanticGapSubject::Point,
            SemanticCapability::GeneratorSuspension,
            SemanticGapKind::Unsupported,
            "generator-expression suspension and resumption are not lowered",
        )?;
        self.add_gap(
                builder,
                boundary,
                SemanticGapSubject::Point,
                SemanticCapability::Calls,
                SemanticGapKind::Unknown,
                "outer iterator acquisition and deferred generator protocol calls require runtime refinement",
            )?;
        self.add_gap(
            builder,
            boundary,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unknown,
            "outer iterator acquisition and deferred generator failures are not lowered",
        )?;
        self.edge(builder, boundary, continuation)?;
        self.schedule_expressions(
            builder,
            entry,
            &outer_iterables,
            EdgeTarget::normal(boundary),
            scope,
            stack,
        )
    }

    fn eager_comprehension_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PythonLoweringError> {
        let clauses: Vec<_> = runtime_expression_children(node)
            .into_iter()
            .filter(|child| matches!(child.kind(), "for_in_clause" | "if_clause"))
            .collect();
        let outer_iterables = first_comprehension_iterables(node)?;
        if clauses
            .iter()
            .any(|clause| has_direct_token(*clause, "async"))
        {
            let boundary = self.point(builder, node, Vec::new())?;
            for capability in [
                SemanticCapability::NormalControlFlow,
                SemanticCapability::AsyncSuspendResume,
                SemanticCapability::Calls,
                SemanticCapability::ExceptionalControlFlow,
            ] {
                self.add_gap(
                    builder,
                    boundary,
                    SemanticGapSubject::Point,
                    capability,
                    SemanticGapKind::Unsupported,
                    "async comprehension iteration is not lowered",
                )?;
            }
            return self.schedule_expressions(
                builder,
                entry,
                &outer_iterables,
                EdgeTarget::normal(boundary),
                scope,
                stack,
            );
        }
        assert!(!clauses.is_empty() && clauses[0].kind() == "for_in_clause");
        let first_clause = clauses[0];
        if !self.comprehension_bindings.contains_key(&node.id()) {
            let mut values = HashMap::default();
            for clause in &clauses {
                if clause.kind() != "for_in_clause" {
                    continue;
                }
                for step in assignment_target_steps(required_field(*clause, "left")?, None) {
                    if let AssignmentTargetStep::Leaf { target, .. } = step
                        && matches!(target.kind(), "identifier" | "keyword_identifier")
                    {
                        let name = node_text(self.prepared.source(), target)
                            .expect("valid identifier range");
                        if !values.contains_key(name) {
                            let metadata = self.value_mapping(builder, target)?;
                            let value = self.session.add_value_with_metadata(
                                builder,
                                metadata,
                                SemanticValueKind::Local,
                            )?;
                            values.insert(Box::<str>::from(name), value);
                        }
                    }
                }
            }
            self.comprehension_bindings.insert(
                node.id(),
                ComprehensionBindings {
                    values,
                    outer_iterables,
                    clauses,
                },
            );
        }
        let first = self.point(builder, first_clause, Vec::new())?;
        self.edge(builder, entry, EdgeTarget::normal(first))?;
        stack.push(Work::ComprehensionClause {
            node,
            index: 0,
            entry: first,
            next,
            scope,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn comprehension_clause(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        index: usize,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PythonLoweringError> {
        let bindings = self
            .comprehension_bindings
            .get(&node.id())
            .expect("comprehension scope precedes clause work");
        let clause = bindings.clauses.get(index).copied();
        let body = required_field(node, "body")?;
        let Some(clause) = clause else {
            let insertion = self.point(builder, node, Vec::new())?;
            let result = self.expression_value(builder, node, expression_value_kind(node))?;
            self.session.add_partitioned_gap(
                builder,
                insertion,
                SemanticGapSubject::Value(result),
                SemanticCapability::IndexMemory,
                SemanticGapImpacts::single(SemanticGapImpact::HeapWrite),
                SemanticGapKind::Unsupported,
                "comprehension result element identities are not modeled",
            )?;
            if matches!(
                node.kind(),
                "set_comprehension" | "dictionary_comprehension"
            ) {
                for capability in [
                    SemanticCapability::Calls,
                    SemanticCapability::ExceptionalControlFlow,
                ] {
                    self.add_gap(
                        builder,
                        insertion,
                        SemanticGapSubject::Point,
                        capability,
                        SemanticGapKind::Unknown,
                        "comprehension insertion can invoke hashing and equality",
                    )?;
                }
            }
            self.edge(builder, insertion, next)?;
            stack.push(Work::Expression {
                node: body,
                entry,
                next: EdgeTarget::normal(insertion),
                scope,
            });
            return Ok(());
        };
        let following_node = bindings.clauses.get(index + 1).copied().unwrap_or(body);
        if clause.kind() == "if_clause" {
            let following = self.point(builder, following_node, Vec::new())?;
            stack.push(Work::ComprehensionClause {
                node,
                index: index + 1,
                entry: following,
                next,
                scope,
            });
            stack.push(Work::Condition {
                node: first_runtime_named_child(clause).expect("filter expression"),
                entry,
                when_true: EdgeTarget::normal(following),
                when_false: next,
                scope,
            });
            return Ok(());
        }
        let target = required_field(clause, "left")?;
        let iterables = children_by_field_name(clause, "right");
        let literal = if iterables.len() == 1 {
            unpack_source_children(iterables[0])
        } else {
            None
        };
        let mut iterations = Vec::new();
        let first_iteration = if let Some(items) = literal {
            let entries = items
                .iter()
                .map(|_| self.point(builder, target, Vec::new()))
                .collect::<Result<Vec<_>, _>>()?;
            for (item_index, item) in items.into_iter().enumerate() {
                let following = entries
                    .get(item_index + 1)
                    .copied()
                    .map(EdgeTarget::normal)
                    .unwrap_or(next);
                iterations.push((Some(item), entries[item_index], following));
            }
            if entries.is_empty() {
                // Retain source facts for the unreachable body, as with a
                // constant-false branch, without an executable entry edge.
                let unreachable = self.point(builder, following_node, Vec::new())?;
                stack.push(Work::ComprehensionClause {
                    node,
                    index: index + 1,
                    entry: unreachable,
                    next,
                    scope,
                });
            }
            entries
                .first()
                .copied()
                .map(EdgeTarget::normal)
                .unwrap_or(next)
        } else {
            let test = self.point(builder, clause, Vec::new())?;
            let binding = self.point(builder, target, Vec::new())?;
            for capability in [
                SemanticCapability::Calls,
                SemanticCapability::ExceptionalControlFlow,
            ] {
                self.add_gap(
                    builder,
                    test,
                    SemanticGapSubject::Point,
                    capability,
                    SemanticGapKind::Unsupported,
                    "comprehension iterator protocol requires runtime refinement",
                )?;
            }
            self.edge(builder, test, EdgeTarget::normal(binding))?;
            self.edge(builder, test, next)?;
            iterations.push((
                None,
                binding,
                EdgeTarget {
                    point: test,
                    kind: ControlEdgeKind::LoopBack,
                },
            ));
            EdgeTarget::normal(test)
        };
        for (source, binding, continuation) in iterations {
            if binding_requires_runtime_protocol(target) {
                for capability in [
                    SemanticCapability::Calls,
                    SemanticCapability::ExceptionalControlFlow,
                ] {
                    self.add_gap(
                        builder,
                        binding,
                        SemanticGapSubject::Point,
                        capability,
                        SemanticGapKind::Unknown,
                        "comprehension target assignment may invoke runtime protocols",
                    )?;
                }
            }
            let completion = self.append_target_source_assignments(
                builder,
                binding,
                node,
                target,
                source,
                if is_unpacking_target(target) {
                    PYTHON_UNKNOWN_UNPACK_ELEMENT
                } else {
                    PYTHON_UNKNOWN_ITERATION_ELEMENT
                },
                scope,
                stack,
            )?;
            let following = self.point(builder, following_node, Vec::new())?;
            if let Some(completion) = completion {
                self.edge(builder, completion, EdgeTarget::normal(following))?;
            }
            stack.push(Work::ComprehensionClause {
                node,
                index: index + 1,
                entry: following,
                next: continuation,
                scope,
            });
        }
        self.schedule_expressions(builder, entry, &iterables, first_iteration, scope, stack)
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
    ) -> Result<(), PythonLoweringError> {
        let mut branches = vec![(
            required_field(node, "condition")?,
            required_field(node, "consequence")?,
        )];
        let mut alternative_body = None;
        for alternative in children_by_field_name(node, "alternative") {
            match alternative.kind() {
                "elif_clause" => branches.push((
                    required_field(alternative, "condition")?,
                    required_field(alternative, "consequence")?,
                )),
                "else_clause" => alternative_body = Some(required_field(alternative, "body")?),
                _ => {}
            }
        }

        let condition_entries = branches
            .iter()
            .enumerate()
            .map(|(index, (condition, _))| {
                if index == 0 {
                    Ok(entry)
                } else {
                    self.point(builder, *condition, Vec::new())
                }
            })
            .collect::<Result<Vec<_>, PythonLoweringError>>()?;
        let body_entries = branches
            .iter()
            .map(|(_, body)| self.point(builder, *body, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        let alternative_entry = alternative_body
            .map(|body| self.point(builder, body, Vec::new()))
            .transpose()?;

        if let (Some(body), Some(body_entry)) = (alternative_body, alternative_entry) {
            stack.push(Work::Statement {
                node: body,
                entry: body_entry,
                next,
                scope,
            });
        }
        for index in (0..branches.len()).rev() {
            stack.push(Work::Statement {
                node: branches[index].1,
                entry: body_entries[index],
                next,
                scope,
            });
            let false_target = condition_entries
                .get(index + 1)
                .copied()
                .map(|point| EdgeTarget {
                    point,
                    kind: ControlEdgeKind::ConditionalFalse,
                })
                .or_else(|| {
                    alternative_entry.map(|point| EdgeTarget {
                        point,
                        kind: ControlEdgeKind::ConditionalFalse,
                    })
                })
                .unwrap_or(EdgeTarget {
                    point: next.point,
                    kind: ControlEdgeKind::ConditionalFalse,
                });
            stack.push(Work::Condition {
                node: branches[index].0,
                entry: condition_entries[index],
                when_true: EdgeTarget {
                    point: body_entries[index],
                    kind: ControlEdgeKind::ConditionalTrue,
                },
                when_false: false_target,
                scope,
            });
        }
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
    ) -> Result<(), PythonLoweringError> {
        let condition = required_field(node, "condition")?;
        let body = required_field(node, "body")?;
        let alternative = node
            .child_by_field_name("alternative")
            .map(|clause| required_field(clause, "body"))
            .transpose()?;
        let condition_entry = self.point(builder, condition, Vec::new())?;
        let body_entry = self.point(builder, body, Vec::new())?;
        let alternative_entry = alternative
            .map(|body| self.point(builder, body, Vec::new()))
            .transpose()?;
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

        if let (Some(alternative), Some(alternative_entry)) = (alternative, alternative_entry) {
            stack.push(Work::Statement {
                node: alternative,
                entry: alternative_entry,
                next,
                scope,
            });
        }
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
                point: alternative_entry.unwrap_or(next.point),
                kind: ControlEdgeKind::ConditionalFalse,
            },
            scope: loop_scope,
        });
        self.edge(builder, entry, EdgeTarget::normal(condition_entry))
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
    ) -> Result<(), PythonLoweringError> {
        let iterable = required_field(node, "right")?;
        if has_direct_token(node, "async") {
            let boundary = self.point(builder, node, Vec::new())?;
            for (capability, detail) in [
                (
                    SemanticCapability::AsyncSuspendResume,
                    "async-for iteration suspension and resumption are not lowered",
                ),
                (
                    SemanticCapability::Calls,
                    "async iterator acquisition and advancement are not represented as call sites",
                ),
                (
                    SemanticCapability::ExceptionalControlFlow,
                    "async iterator acquisition and advancement failures are not lowered",
                ),
                (
                    SemanticCapability::ResourceManagement,
                    "async iterator finalization is not lowered",
                ),
            ] {
                self.add_gap(
                    builder,
                    boundary,
                    SemanticGapSubject::Point,
                    capability,
                    SemanticGapKind::Unsupported,
                    detail,
                )?;
            }
            stack.push(Work::Expression {
                node: iterable,
                entry,
                next: EdgeTarget::normal(boundary),
                scope,
            });
            return Ok(());
        }

        let binding = required_field(node, "left")?;
        let body = required_field(node, "body")?;
        let alternative = node
            .child_by_field_name("alternative")
            .map(|clause| required_field(clause, "body"))
            .transpose()?;
        let test = self.point(builder, node, Vec::new())?;
        let binding_entry = self.point(builder, binding, Vec::new())?;
        let binding_boundary = self.point(builder, binding, Vec::new())?;
        let body_entry = self.point(builder, body, Vec::new())?;
        let first_iteration = self.builtin_range_has_first_iteration(iterable);
        let alternative_entry = alternative
            .map(|body| self.point(builder, body, Vec::new()))
            .transpose()?;
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
        if !first_iteration {
            self.add_gap(
                builder,
                test,
                SemanticGapSubject::Point,
                SemanticCapability::Calls,
                SemanticGapKind::Unsupported,
                "iterator acquisition and advancement are not represented as call sites",
            )?;
            self.add_gap(
                builder,
                test,
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unsupported,
                "iterator acquisition and advancement failures are not lowered",
            )?;
        }
        if binding_requires_runtime_protocol(binding) {
            self.add_gap(
                builder,
                binding_boundary,
                SemanticGapSubject::Point,
                SemanticCapability::Calls,
                SemanticGapKind::Unknown,
                "iteration-target unpacking, descriptor assignment, or item assignment calls require runtime refinement",
            )?;
            self.add_gap(
                builder,
                binding_boundary,
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unsupported,
                "iteration-target evaluation, unpacking, and assignment failures are not lowered",
            )?;
        }
        let iteration_source = single_literal_sequence_element(iterable);
        let unknown_kind = if is_unpacking_target(binding) {
            PYTHON_UNKNOWN_UNPACK_ELEMENT
        } else {
            PYTHON_UNKNOWN_ITERATION_ELEMENT
        };
        let binding_completion = self.append_target_source_assignments(
            builder,
            binding_boundary,
            node,
            binding,
            iteration_source,
            unknown_kind,
            loop_scope,
            stack,
        )?;
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
                point: alternative_entry.unwrap_or(next.point),
                kind: ControlEdgeKind::ConditionalFalse,
            },
        )?;
        if let Some(binding_completion) = binding_completion {
            self.edge(builder, binding_completion, EdgeTarget::normal(body_entry))?;
        }
        if let (Some(alternative), Some(alternative_entry)) = (alternative, alternative_entry) {
            stack.push(Work::Statement {
                node: alternative,
                entry: alternative_entry,
                next,
                scope,
            });
        }
        stack.push(Work::Statement {
            node: body,
            entry: body_entry,
            next: EdgeTarget {
                point: test,
                kind: ControlEdgeKind::LoopBack,
            },
            scope: loop_scope,
        });
        self.edge(builder, binding_entry, EdgeTarget::normal(binding_boundary))?;
        if first_iteration {
            let arguments = call_arguments(iterable);
            self.schedule_expressions(
                builder,
                entry,
                &arguments,
                EdgeTarget::normal(binding_entry),
                scope,
                stack,
            )?;
        } else {
            stack.push(Work::Expression {
                node: iterable,
                entry,
                next: EdgeTarget::normal(test),
                scope,
            });
        }
        Ok(())
    }

    fn builtin_range_has_first_iteration(&self, iterable: Node<'tree>) -> bool {
        self.proven_builtin_range_call(iterable)
            && non_empty_python_range(self.prepared.source(), iterable)
    }

    fn proven_builtin_range_call(&self, call: Node<'tree>) -> bool {
        self.proven_builtin_call(call, "range", self.builtin_proofs.range)
            && python_range_literal_values(self.prepared.source(), call)
                .is_some_and(|values| !matches!(values.as_slice(), [_, _, step] if *step == 0))
    }

    fn proven_builtin_call(&self, call: Node<'tree>, name: &str, module_proof: bool) -> bool {
        if !module_proof || call.kind() != "call" {
            return false;
        }
        let function = match call.child_by_field_name("function") {
            Some(function) if function.kind() == "identifier" => function,
            _ => return false,
        };
        node_text(self.prepared.source(), function) == Some(name)
            && self.bindings.name_resolution_at(name, function)
                == PythonLexicalNameResolution::Unbound
    }

    /// Whether a call provably denotes the builtin `str`: the module does not
    /// rebind the name, there is no wildcard import, and the use-site resolves
    /// lexically unbound. This is the same proof shape as
    /// [`Self::proven_builtin_range_call`].
    fn proven_builtin_str_call(&self, call: Node<'tree>) -> bool {
        self.proven_builtin_call(call, "str", self.builtin_proofs.str)
    }

    fn call_has_absent_normal_continuation(
        &self,
        builder: &mut ProcedureCfgBuilder,
        call: Node<'tree>,
        function: Node<'tree>,
        arguments: &[Node<'tree>],
    ) -> Result<bool, PythonLoweringError> {
        if let Some(declaration) = self.workspace_callable_declaration(builder, function)?
            && self.workspace_callable_diverges(declaration)
        {
            return Ok(true);
        }
        let external = if self.proven_builtin_call(call, "exit", self.builtin_proofs.exit) {
            Some(("builtins".to_owned(), "exit".to_owned()))
        } else if self.proven_builtin_call(call, "quit", self.builtin_proofs.quit) {
            Some(("builtins".to_owned(), "quit".to_owned()))
        } else {
            self.imported_callable_identity(builder, function)?
        };
        Ok(external.is_some_and(|(owner, member)| {
            self.semantic_model_callable_diverges(&owner, &member, arguments)
        }))
    }

    fn workspace_callable_declaration(
        &self,
        builder: &mut ProcedureCfgBuilder,
        function: Node<'tree>,
    ) -> Result<Option<Node<'tree>>, PythonLoweringError> {
        if function.kind() != "identifier" {
            return Ok(None);
        }
        let Some(name) = node_text(self.prepared.source(), function) else {
            return Ok(None);
        };
        match self.bindings.name_resolution_at(name, function) {
            PythonLexicalNameResolution::Local => {
                Ok(self.bindings.local_function_declaration(name, function))
            }
            PythonLexicalNameResolution::Nonlocal => Ok(None),
            PythonLexicalNameResolution::Global | PythonLexicalNameResolution::Unbound => {
                if self.module_has_wildcard_import {
                    return Ok(None);
                }
                if !self.module_name_fallback_allowed(builder, function, name)? {
                    return Ok(None);
                }
                Ok(match self.module_bindings.get(name) {
                    Some(PythonModuleBinding::Function(declaration)) => Some(*declaration),
                    _ => None,
                })
            }
        }
    }

    fn workspace_callable_diverges(&self, declaration: Node<'tree>) -> bool {
        if declaration
            .parent()
            .is_some_and(|parent| parent.kind() == "decorated_definition")
            || has_direct_token(declaration, "async")
            || declaration
                .child_by_field_name("body")
                .is_some_and(body_contains_yield)
        {
            return false;
        }
        declaration
            .child_by_field_name("return_type")
            .is_some_and(|annotation| self.annotation_is_never(annotation))
    }

    fn annotation_is_never(&self, annotation: Node<'tree>) -> bool {
        if self.module_has_wildcard_import {
            return false;
        }
        let Some(path) = python_static_type_path(annotation) else {
            return false;
        };
        let Some(local) = path
            .first()
            .and_then(|segment| node_text(self.prepared.source(), *segment))
        else {
            return false;
        };
        let Some(PythonModuleBinding::Import(binding)) = self.module_bindings.get(local) else {
            return false;
        };
        let suffix_start = 1usize.saturating_add(binding.consumed_attributes);
        if suffix_start > path.len() {
            return false;
        }
        let mut canonical = binding
            .canonical_path
            .iter()
            .map(Box::as_ref)
            .collect::<Vec<_>>();
        canonical.extend(
            path[suffix_start..]
                .iter()
                .filter_map(|segment| node_text(self.prepared.source(), *segment)),
        );
        matches!(
            canonical.as_slice(),
            ["typing" | "typing_extensions", "NoReturn" | "Never"]
        )
    }

    fn imported_callable_identity(
        &self,
        builder: &mut ProcedureCfgBuilder,
        function: Node<'tree>,
    ) -> Result<Option<(String, String)>, PythonLoweringError> {
        if self.module_has_wildcard_import {
            return Ok(None);
        }
        let Some(path) = python_static_attribute_path(function) else {
            return Ok(None);
        };
        let Some(local) = path
            .first()
            .and_then(|segment| node_text(self.prepared.source(), *segment))
        else {
            return Ok(None);
        };
        if !self.module_name_fallback_allowed(builder, path[0], local)? {
            return Ok(None);
        }
        let Some(PythonModuleBinding::Import(binding)) = self.module_bindings.get(local) else {
            return Ok(None);
        };
        let mut canonical = binding
            .canonical_path
            .iter()
            .map(Box::as_ref)
            .collect::<Vec<_>>();
        if path.len() == 1 {
            if binding.consumed_attributes != 0 {
                return Ok(None);
            }
        } else {
            let attributes_after_local = path.len() - 1;
            if attributes_after_local != binding.consumed_attributes + 1 {
                return Ok(None);
            }
            let Some(member) = path
                .last()
                .and_then(|segment| node_text(self.prepared.source(), *segment))
            else {
                return Ok(None);
            };
            canonical.push(member);
        }
        let Some((member, owner)) = canonical.split_last() else {
            return Ok(None);
        };
        if owner.is_empty() {
            return Ok(None);
        }
        Ok(Some((owner.join("."), (*member).to_owned())))
    }

    fn semantic_model_callable_diverges(
        &self,
        owner: &str,
        member: &str,
        arguments: &[Node<'tree>],
    ) -> bool {
        let Some(overlay) = self.overlay else {
            return false;
        };
        let mut positional_count = 0;
        let mut named_labels = Vec::new();
        let mut has_spread = false;
        for argument in arguments {
            match argument.kind() {
                "keyword_argument" => {
                    let Some(name) = argument
                        .child_by_field_name("name")
                        .and_then(|name| node_text(self.prepared.source(), name))
                    else {
                        return false;
                    };
                    named_labels.push(name.to_owned());
                }
                "list_splat" | "dictionary_splat" => has_spread = true,
                _ => positional_count += 1,
            }
        }
        let parameter_count = match u32::try_from(arguments.len()) {
            Ok(parameter_count) => parameter_count,
            Err(_) => return false,
        };
        let matched = overlay.callable_for_application(
            SemanticModelCallableKey::new("python", owner, member, false, parameter_count),
            &SemanticModelCallApplication::structured(positional_count, named_labels, has_spread),
        );
        matches!(
            matched.disposition,
            SemanticModelCallableDisposition::Unique
                | SemanticModelCallableDisposition::CompatibleLayout
        ) && !matched.records.is_empty()
            && matched.records.iter().all(|record| {
                record
                    .structured_signature()
                    .and_then(|signature| signature.returns.as_ref())
                    .is_some_and(python_type_ref_is_never)
            })
    }

    /// Lower a proven builtin `str(...)` call as a modeled boundary instead of
    /// an unresolved call site: each argument value flows to the call result,
    /// matching how the binary-operator lowering propagates operand values.
    /// The builtin cannot be rebound once the proof holds, so no dispatch gap
    /// is published; an unproven `str` keeps the generic call path and its
    /// honest refinement gap.
    fn builtin_str_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PythonLoweringError> {
        let result = self.expression_value(builder, node, SemanticValueKind::Temporary)?;
        let terminal = self.point(builder, node, Vec::new())?;
        let arguments = call_arguments(node);
        let mut argument_values = Vec::with_capacity(arguments.len());
        for argument in &arguments {
            let value_node = python_argument_value_node(*argument);
            argument_values.push(self.expression_value(
                builder,
                value_node,
                expression_value_kind(value_node),
            )?);
        }
        for source in argument_values {
            self.append_effect(
                builder,
                terminal,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::LanguageDefined,
                    source,
                    target: result,
                },
            )?;
        }
        self.edge(builder, terminal, next)?;
        self.schedule_expressions(
            builder,
            entry,
            &arguments,
            EdgeTarget::normal(terminal),
            scope,
            stack,
        )
    }

    fn try_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PythonLoweringError> {
        let body = required_field(node, "body")?;
        let children = named_children(node);
        let catches = children
            .iter()
            .copied()
            .filter(|child| child.kind() == "except_clause")
            .collect::<Vec<_>>();
        let alternative = children
            .iter()
            .copied()
            .find(|child| child.kind() == "else_clause")
            .map(|clause| required_field(clause, "body"))
            .transpose()?;
        let finalizer = children
            .iter()
            .copied()
            .find(|child| child.kind() == "finally_clause")
            .and_then(|clause| {
                named_children(clause)
                    .into_iter()
                    .find(|child| child.kind() == "block")
            });

        let (cleanup_scope, cleanup_region) = if let Some(finalizer) = finalizer {
            let region =
                CleanupRegionId::new(u32::try_from(self.cleanups.len()).map_err(|_| {
                    PythonLoweringError::Invalid("too many cleanup regions".into())
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
            .map(|clause| {
                named_children(*clause)
                    .into_iter()
                    .find(|child| child.kind() == "block")
                    .ok_or_else(|| missing_field(*clause, "body"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let catch_entries = catches
            .iter()
            .map(|clause| self.point(builder, *clause, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        let catch_binding = catches.first().and_then(|clause| {
            (catches.len() == 1).then(|| self.precise_except_binding(*clause, body))?
        });
        let precise_single_catch = catch_binding.is_some();
        let try_scope = if catch_entries.is_empty() {
            cleanup_scope
        } else {
            let dispatcher = self.point(builder, node, Vec::new())?;
            if !precise_single_catch {
                self.add_gap(
                    builder,
                    dispatcher,
                    SemanticGapSubject::Point,
                    SemanticCapability::ExceptionalControlFlow,
                    SemanticGapKind::Unknown,
                    "except-clause type evaluation, matching, and selection require runtime refinement",
                )?;
            }
            if let Some(binding) = catch_binding {
                let binding_name = binding.name;
                self.catch_binders.insert(dispatcher, binding.value);
                self.known_instance_bindings
                    .insert(binding_name.clone(), binding.class_name.clone());
                self.known_instance_fields
                    .insert(binding_name.clone(), binding.fields);
                self.known_binding_available_after.insert(binding_name, 0);
            }
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

        for ((clause, catch_body), catch_entry) in
            catches.iter().zip(&catch_bodies).zip(&catch_entries)
        {
            if has_direct_token(*clause, "*") {
                self.add_gap(
                    builder,
                    *catch_entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::ExceptionalControlFlow,
                    SemanticGapKind::Unsupported,
                    "except-star exception-group splitting, remainder propagation, and merging are not lowered",
                )?;
                self.add_gap(
                    builder,
                    *catch_entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::NormalControlFlow,
                    SemanticGapKind::Unsupported,
                    "except-star handlers may run alongside remainder propagation, so ordinary handler completion is not assumed",
                )?;
                continue;
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

        let body_next = if let Some(alternative) = alternative {
            let alternative_entry = self.point(builder, alternative, Vec::new())?;
            if let Some(route) = &normal_route {
                let alternative_exit = self.point(builder, alternative, Vec::new())?;
                self.route(builder, alternative_exit, route, stack)?;
                stack.push(Work::Statement {
                    node: alternative,
                    entry: alternative_entry,
                    next: EdgeTarget::normal(alternative_exit),
                    scope: cleanup_scope,
                });
            } else {
                stack.push(Work::Statement {
                    node: alternative,
                    entry: alternative_entry,
                    next,
                    scope: cleanup_scope,
                });
            }
            EdgeTarget::normal(alternative_entry)
        } else if let Some(route) = &normal_route {
            let body_exit = self.point(builder, body, Vec::new())?;
            self.route(builder, body_exit, route, stack)?;
            EdgeTarget::normal(body_exit)
        } else {
            next
        };

        stack.push(Work::Statement {
            node: body,
            entry,
            next: body_next,
            scope: try_scope,
        });
        Ok(())
    }

    fn precise_except_binding(
        &self,
        clause: Node<'tree>,
        body: Node<'tree>,
    ) -> Option<PreciseExceptBinding> {
        let (type_node, alias) = precise_except_shape(clause)?;
        let type_name = node_text(self.prepared.source(), type_node)?;
        if !self.class_names.contains(type_name)
            || matches!(
                self.bindings.name_resolution_at(type_name, type_node),
                PythonLexicalNameResolution::Local | PythonLexicalNameResolution::Nonlocal
            )
        {
            return None;
        }
        let raised = direct_raise_identifier(body)?;
        let raised_name = node_text(self.prepared.source(), raised)?;
        let class_name = self.known_instance_bindings.get(raised_name)?;
        if class_name.as_ref() != type_name {
            return None;
        }
        let name = self
            .bindings
            .local_bindings()
            .find(|(_, declaration)| declaration.id() == alias.id())
            .map(|(name, _)| name)?;
        Some(PreciseExceptBinding {
            value: self.binding_value(name)?,
            name: name.into(),
            class_name: class_name.clone(),
            fields: self
                .known_instance_fields
                .get(raised_name)
                .cloned()
                .unwrap_or_default(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn with_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PythonLoweringError> {
        let body = required_field(node, "body")?;
        let items = with_items(node)?;
        let region = CleanupRegionId::new(
            u32::try_from(self.cleanups.len())
                .map_err(|_| PythonLoweringError::Invalid("too many cleanup regions".into()))?,
        );
        self.cleanups.push(CleanupRegion {
            id: region,
            body: CleanupBody::WithStatement(node),
            outer_scope: scope,
        });
        let body_scope = builder.push_scope(Some(scope), ScopeBinding::Cleanup { region });

        // The exit point resumes the statement's own continuation, so the
        // implicit exits always run before anything that follows the `with`.
        let after = self.point(builder, node, Vec::new())?;
        self.edge(builder, after, next)?;
        let normal_route = builder.normal_cleanup_completion(region, after);
        let body_exit = self.point(builder, body, Vec::new())?;
        self.route(builder, body_exit, &normal_route, stack)?;

        // `with EXPR as NAME` binds the context manager the acquisition
        // produced, so the body's uses and explicit closes reach the same
        // value the construct entered and will exit.
        let body_entry = self.point(builder, node, Vec::new())?;
        let mut contexts = Vec::with_capacity(items.len());
        for item in &items {
            let (context, binder) = with_item_parts(*item)?;
            if let Some(binder) = binder {
                let value =
                    self.expression_value(builder, context, expression_value_kind(context))?;
                self.append_target_assignment(builder, body_entry, *item, binder, value)?;
            }
            contexts.push(context);
        }
        self.schedule_expressions(
            builder,
            entry,
            &contexts,
            EdgeTarget::normal(body_entry),
            scope,
            stack,
        )?;
        stack.push(Work::Statement {
            node: body,
            entry: body_entry,
            next: EdgeTarget::normal(body_exit),
            scope: body_scope,
        });
        Ok(())
    }

    /// Lower the implicit `__exit__` of a `with` statement.
    ///
    /// Python exits the context managers the statement entered at the
    /// construct's own exit, in reverse declaration order, on both the normal
    /// and the exceptional continuation of the guarded body. Each exit is a
    /// real close operation on the context manager value the construct
    /// acquired, so the typestate engine binds it to the tracked subject
    /// identity instead of to the spelled binding.
    ///
    /// Every exit site is anchored at the `with` statement, which is the
    /// source fact the resource-lifecycle selector names for the construct,
    /// and each publishes the operation's own normal and exceptional
    /// continuations. An exit that raises still released its context manager,
    /// so its exceptional continuation enters the *next* exit in the chain,
    /// and only the last exit propagates from the enclosing scope: an earlier
    /// failure cannot skip a later release, and this region never runs twice.
    fn lower_implicit_context_manager_exits(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        step: CleanupSpecialization<CleanupRegion<'tree>>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PythonLoweringError> {
        assert_eq!(
            node.kind(),
            "with_statement",
            "only a with statement declares a context manager list"
        );
        let mut contexts = with_items(node)?
            .into_iter()
            .map(|item| with_item_parts(item).map(|(context, _)| context))
            .collect::<Result<Vec<_>, _>>()?;
        // Python exits in reverse declaration order.
        contexts.reverse();
        if contexts.is_empty() {
            // Only an error-recovered clause has no context manager at all;
            // the grammar requires at least one item. Keep the construct
            // reachable and report the gap instead of inventing an exit.
            self.add_gap(
                builder,
                step.entry,
                SemanticGapSubject::Point,
                SemanticCapability::ResourceManagement,
                SemanticGapKind::Unsupported,
                "a malformed with clause declares no context manager, so its implicit exit is not represented",
            )?;
            self.edge(builder, step.entry, step.next)?;
            return Ok(());
        }
        // The cleanup entry is the first exit Python performs, so reusing it
        // keeps one point per exit without adding a relay.
        let mut invokes = Vec::with_capacity(contexts.len());
        for index in 0..contexts.len() {
            invokes.push(if index == 0 {
                step.entry
            } else {
                self.point(builder, node, Vec::new())?
            });
        }
        let last = contexts.len() - 1;
        let mut continuations = Vec::with_capacity(contexts.len());
        for (index, context) in contexts.into_iter().enumerate() {
            let invoke = invokes[index];
            let normal = self.point(builder, node, Vec::new())?;
            let exceptional = self.point(builder, node, Vec::new())?;
            let receiver =
                self.expression_value(builder, context, expression_value_kind(context))?;
            let value_metadata = self.value_mapping(builder, context)?;
            let callee = self.session.add_value_with_metadata(
                builder,
                value_metadata,
                SemanticValueKind::Callable,
            )?;
            let thrown = self.session.add_value_with_metadata(
                builder,
                value_metadata,
                SemanticValueKind::Exception,
            )?;
            let metadata = self.metadata(invoke)?;
            self.append_effect(
                builder,
                invoke,
                SemanticEffect::CallableReference {
                    result: callee,
                    callable: CallableValue {
                        kind: CallableReferenceKind::BoundMethod,
                        targets: CallableTargetResolution::Unknown,
                        target_evidence: metadata.evidence,
                        bound_receiver: Some(receiver),
                        environment: None,
                    },
                },
            )?;
            let call_site = self.session.add_call_site(
                builder,
                CallSiteScaffold {
                    point: invoke,
                    callee,
                    receiver: Some(receiver),
                    arguments: Box::new([]),
                    normal_results: Box::new([]),
                    result: None,
                    thrown: Some(thrown),
                    declared_targets: CallableTargetResolution::Unknown,
                    normal_continuation: normal,
                    exceptional_continuation: exceptional,
                },
            )?;
            self.resolution_gaps(
                builder,
                invoke,
                callee,
                call_site,
                &CallableTargetResolution::Unknown,
            )?;
            if has_direct_token(node, "async") {
                // `async with` awaits `__aenter__`/`__aexit__`; the suspension
                // of this synthesized exit is not lowered, but the release it
                // performs is still the construct's own exit, so the gap stays
                // scoped to this call instead of opening the resource value.
                self.add_gap(
                    builder,
                    invoke,
                    SemanticGapSubject::CallSite(call_site),
                    SemanticCapability::AsyncSuspendResume,
                    SemanticGapKind::Unsupported,
                    "async context-manager exit suspension is not lowered",
                )?;
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
            continuations.push((normal, exceptional, index == last));
        }
        for (index, (normal, exceptional, is_last)) in continuations.iter().copied().enumerate() {
            let next = invokes
                .get(index + 1)
                .copied()
                .map(EdgeTarget::normal)
                .unwrap_or(step.next);
            self.edge(builder, normal, next)?;
            if is_last {
                self.abrupt(
                    builder,
                    exceptional,
                    step.region.outer_scope,
                    CompletionKind::Throw,
                    None,
                    stack,
                )?;
            } else {
                // The remaining exits run as part of the same unwinding, so the
                // edge that resumes the chain stays exceptional. Publishing it
                // as a normal edge would lose the in-flight completion here and
                // let a later exit's own class stand in for the class this hop
                // arrived with.
                self.edge(
                    builder,
                    exceptional,
                    EdgeTarget {
                        point: invokes[index + 1],
                        kind: ControlEdgeKind::Exceptional,
                    },
                )?;
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn match_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        _next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PythonLoweringError> {
        let subjects = children_by_field_name(node, "subject");
        let boundary = self.point(builder, node, Vec::new())?;
        self.add_gap(
            builder,
            boundary,
            SemanticGapSubject::Point,
            SemanticCapability::NormalControlFlow,
            SemanticGapKind::Unsupported,
            "pattern selection, guards, and case binding are not lowered",
        )?;
        self.add_gap(
            builder,
            boundary,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unknown,
            "class-pattern and mapping-pattern protocol calls require runtime refinement",
        )?;
        self.add_gap(
            builder,
            boundary,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            "pattern protocol and guard failures are not lowered",
        )?;
        self.schedule_expressions(
            builder,
            entry,
            &subjects,
            EdgeTarget::normal(boundary),
            scope,
            stack,
        )
    }

    fn yield_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PythonLoweringError> {
        let values = runtime_expression_children(node);
        let boundary = if values.is_empty() {
            entry
        } else {
            self.point(builder, node, Vec::new())?
        };
        self.add_gap(
            builder,
            boundary,
            SemanticGapSubject::Point,
            SemanticCapability::GeneratorSuspension,
            SemanticGapKind::Unsupported,
            "yield, yield-from delegation, send, throw, and generator resumption are not lowered",
        )?;
        if has_direct_token(node, "from") {
            self.add_gap(
                builder,
                boundary,
                SemanticGapSubject::Point,
                SemanticCapability::Calls,
                SemanticGapKind::Unsupported,
                "yield-from iterator protocol operations are not represented as call sites",
            )?;
        }
        if values.is_empty() {
            Ok(())
        } else {
            self.schedule_expressions(
                builder,
                entry,
                &values,
                EdgeTarget::normal(boundary),
                scope,
                stack,
            )
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
    ) -> Result<(), PythonLoweringError> {
        let function = required_field(node, "function")?;
        let arguments = call_arguments(node);
        let diverges =
            self.call_has_absent_normal_continuation(builder, node, function, &arguments)?;
        let invoke = self.point(builder, node, Vec::new())?;
        let normal = if diverges {
            None
        } else {
            Some(self.point(builder, node, Vec::new())?)
        };
        let exceptional = self.point(builder, node, Vec::new())?;
        let callee = self.expression_value(builder, function, SemanticValueKind::Callable)?;
        let result = self.expression_value(builder, node, SemanticValueKind::Temporary)?;
        let thrown = self.value(builder, invoke, SemanticValueKind::Exception)?;
        let receiver_node = python_call_receiver(function);
        let qualifier = if let Some(receiver) = receiver_node
            && receiver.kind() == "identifier"
            && self.module_class_fallback_allowed(builder, receiver)?
        {
            Some(self.expression_value(builder, receiver, expression_value_kind(receiver))?)
        } else {
            None
        };
        let receiver = if qualifier.is_some() {
            None
        } else {
            receiver_node
                .map(|receiver| {
                    self.expression_value(builder, receiver, expression_value_kind(receiver))
                })
                .transpose()?
        };
        let callable_kind = if let Some(qualifier) = qualifier {
            CallableReferenceKind::TypeQualifiedMethod { qualifier }
        } else if receiver.is_some() {
            CallableReferenceKind::BoundMethod
        } else {
            CallableReferenceKind::Function
        };
        let module_class = if function.kind() == "identifier"
            && self.module_class_fallback_allowed(builder, function)?
        {
            node_text(self.prepared.source(), function)
        } else {
            None
        };
        let constructor = module_class
            .filter(|name| self.proven_instance_fields.contains_key(*name))
            .and_then(|name| self.class_constructors.get(name))
            .copied();
        let resolution = constructor
            .map(|target| CallableTargetResolution::Proven(CallableTarget::Local(target)))
            .unwrap_or(CallableTargetResolution::Unknown);
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

        let argument_values = arguments
            .iter()
            .map(
                |argument| -> Result<SemanticCallArgument, PythonLoweringError> {
                    let value_node = python_argument_value_node(*argument);
                    let value = self.expression_value(
                        builder,
                        value_node,
                        expression_value_kind(value_node),
                    )?;
                    let expansion = match argument.kind() {
                        "list_splat" => CallArgumentExpansion::Spread(ArgumentDomain::Positional),
                        "dictionary_splat" => {
                            CallArgumentExpansion::Spread(ArgumentDomain::Keyword)
                        }
                        "keyword_argument" => {
                            CallArgumentExpansion::Direct(ArgumentDomain::Keyword)
                        }
                        _ => CallArgumentExpansion::Direct(ArgumentDomain::Positional),
                    };
                    if argument.kind() == "keyword_argument" {
                        let name = argument
                            .child_by_field_name("name")
                            .and_then(|name| node_text(self.prepared.source(), name))
                            .ok_or_else(|| {
                                PythonLoweringError::Invalid(
                                    "Python keyword argument is missing its structured name".into(),
                                )
                            })?;
                        Ok(SemanticCallArgument::keyword(value, name))
                    } else {
                        Ok(SemanticCallArgument {
                            value,
                            expansion,
                            keyword: None,
                        })
                    }
                },
            )
            .collect::<Result<Vec<_>, _>>()?;
        if module_class.is_some() {
            self.session
                .add_allocation(builder, invoke, result, AllocationKind::Object)?;
        }
        let call_site = if let Some(normal) = normal {
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
            self.edge(builder, invoke, EdgeTarget::normal(normal))?;
            self.edge(builder, normal, next)?;
            call_site
        } else {
            self.session.add_diverging_call_site(
                builder,
                DivergingCallSiteScaffold {
                    point: invoke,
                    callee,
                    receiver,
                    arguments: argument_values.into_boxed_slice(),
                    result: Some(result),
                    thrown: Some(thrown),
                    declared_targets: resolution.clone(),
                    exceptional_continuation: exceptional,
                },
            )?
        };
        self.edge(
            builder,
            invoke,
            EdgeTarget {
                point: exceptional,
                kind: ControlEdgeKind::Exceptional,
            },
        )?;
        self.abrupt(
            builder,
            exceptional,
            scope,
            CompletionKind::Throw,
            None,
            stack,
        )?;
        self.resolution_gaps(builder, invoke, callee, call_site, &resolution)?;

        // A resolver lookup names declarations, but a parameter,
        // comprehension target, or assignment supplies the callable value at
        // runtime. Keep that competing target explicit so the shared static
        // resolver discharge cannot incorrectly close the call (#1993).
        let ambiguous_target = function.kind() == "identifier"
            && node_text(self.prepared.source(), function).is_some_and(|name| {
                self.bindings
                    .has_runtime_callable_binding_at(name, function)
            });

        self.add_gap(
            builder,
            invoke,
            SemanticGapSubject::CallSite(call_site),
            SemanticCapability::DynamicDispatch,
            if ambiguous_target {
                SemanticGapKind::Ambiguous
            } else {
                SemanticGapKind::Unknown
            },
            if receiver.is_some() {
                "attribute dispatch may use descriptors, dynamic attribute lookup, or runtime mutation; complete target coverage requires value and type refinement"
            } else {
                "callable names may be rebound through globals, closures, or local assignment; complete target coverage requires lexical and value-flow refinement"
            },
        )?;

        let mut evaluations = Vec::with_capacity(arguments.len() + 1);
        if call_function_requires_evaluation(function) {
            evaluations.push(function);
        }
        evaluations.extend(arguments);
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
    ) -> Result<(), PythonLoweringError> {
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
        _node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
    ) -> Result<(), PythonLoweringError> {
        let result = self.value(builder, entry, SemanticValueKind::Callable)?;
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

    /// Lower the abort edge of a Python runtime operation that can raise
    /// implicitly.
    ///
    /// Python raises from ordinary evaluation -- an attribute or subscript
    /// read, an operator, a literal construction, or an unpacking boundary --
    /// and the raise transfers into the enclosing structured completion route
    /// exactly like an explicit `raise` or a call's exceptional continuation.
    /// `route` threads the abort through every enclosing cleanup region, a
    /// `with` statement's implicit `__exit__` chain among them, to the handler
    /// dispatcher, or to the exceptional exit when this procedure has no
    /// matching handler. The modeled edge is why an adapter-published
    /// implicit-exception gap is no longer needed here: the route, not a
    /// discharge, answers whether the abort can carry a store.
    ///
    /// The edge leaves `operation`, the point that carries the operation's own
    /// effect, so every value its operands established is already live on the
    /// abort path. The failing operation's exception object is a fresh value
    /// this adapter does not type, and the value-level effects the operation
    /// may still perform -- descriptor invocation, operator dispatch -- stay
    /// covered by the `Value`-subject claim the caller publishes beside it.
    fn implicit_abort_route(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        operation: ProgramPointId,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PythonLoweringError> {
        let Some(route) =
            builder.resolve_completion(scope, &CompletionRequest::new(CompletionKind::Throw, None))
        else {
            return Err(PythonLoweringError::Invalid(
                "implicit abort has no matching structured continuation".into(),
            ));
        };
        let abort = self.point(builder, node, Vec::new())?;
        if let Some(binder) = self
            .catch_binders
            .get(&route.destination().target())
            .copied()
        {
            let thrown = self.value(builder, abort, SemanticValueKind::Exception)?;
            self.append_effect(
                builder,
                abort,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Local,
                    source: thrown,
                    target: binder,
                },
            )?;
        }
        self.edge(
            builder,
            operation,
            EdgeTarget {
                point: abort,
                kind: ControlEdgeKind::Exceptional,
            },
        )?;
        self.route(builder, abort, &route, stack)
    }

    /// Publish the two claims an unresolved attribute or subscript read makes.
    ///
    /// The abort edge is a lowered route into the enclosing completion, so a
    /// `with` statement's implicit `__exit__` chain and a `finally` body run on
    /// it exactly as they do for a call's exceptional continuation. Publishing
    /// only a `Point`-subject implicit-exception gap instead left the abort
    /// unmodeled, and the shared discharge then opened every traced value in a
    /// procedure whose abort paths run user code: any `with` body that read an
    /// attribute reported the resource it manages as leaked (#3410).
    ///
    /// A read that abandons control never performs its load, so the claims get
    /// a point of their own ahead of the read's load point. Sharing one point
    /// between the claims and the `MemoryLoad` effect would give the load an
    /// abandoning successor, and the flow graph publishes a point's
    /// observations on every outgoing edge: the same read would be reported
    /// twice, once for the normal continuation and once for the abandon
    /// (#3410).
    ///
    /// The value-level claim -- that a descriptor or special method may
    /// produce this value -- keeps its own `Value` subject, and is discharged
    /// only when the same value is a call's callee whose target the plan
    /// resolved.
    fn unresolved_member_read_claims(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        result: ValueId,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<ProgramPointId, PythonLoweringError> {
        let claims = self.point(builder, node, Vec::new())?;
        self.implicit_abort_route(builder, node, claims, scope, stack)?;
        self.add_gap(
            builder,
            claims,
            SemanticGapSubject::Value(result),
            SemanticCapability::Calls,
            SemanticGapKind::Unknown,
            "descriptor or special-method invocation requires type refinement",
        )?;
        Ok(claims)
    }

    fn unhandled_control_syntax(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        _next: EdgeTarget,
    ) -> Result<(), PythonLoweringError> {
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
    ) -> Result<(), PythonLoweringError> {
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
    ) -> Result<(), PythonLoweringError> {
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
    ) -> Result<(), PythonLoweringError> {
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
                let capability = if kind == CompletionKind::Yield {
                    SemanticCapability::GeneratorSuspension
                } else {
                    SemanticCapability::NormalControlFlow
                };
                self.add_gap(
                    builder,
                    from,
                    SemanticGapSubject::Point,
                    capability,
                    SemanticGapKind::Unsupported,
                    &detail,
                )?;
                return Ok(());
            }
            return Err(PythonLoweringError::Invalid(format!(
                "{} completion has no matching structured continuation",
                completion_label(kind)
            )));
        };
        self.route(builder, from, &route, stack)
    }

    fn abrupt_throw(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        from: ProgramPointId,
        scope: ScopeFrameId,
        value: ValueId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PythonLoweringError> {
        let Some(route) =
            builder.resolve_completion(scope, &CompletionRequest::new(CompletionKind::Throw, None))
        else {
            return Err(PythonLoweringError::Invalid(
                "throw completion has no matching structured continuation".into(),
            ));
        };
        if let Some(target) = self
            .catch_binders
            .get(&route.destination().target())
            .copied()
        {
            self.append_effect(
                builder,
                from,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Local,
                    source: value,
                    target,
                },
            )?;
        }
        self.route(builder, from, &route, stack)
    }

    fn route(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        from: ProgramPointId,
        route: &CompletionRoute,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PythonLoweringError> {
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
                CleanupBody::WithStatement(node) => {
                    self.lower_implicit_context_manager_exits(builder, node, step, stack)?;
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
    ) -> Result<(), PythonLoweringError> {
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
    ) -> Result<ProgramPointId, PythonLoweringError> {
        let metadata = self.mapping(builder, node)?;
        self.session.add_point(builder, metadata, effects)
    }

    fn mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<PointMetadata, PythonLoweringError> {
        self.session.add_node_mapping(builder, node)
    }

    fn value_mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<PointMetadata, PythonLoweringError> {
        let anchor = source_anchor(node, 0).map_err(PythonLoweringError::Invalid)?;
        self.session
            .add_mapping(builder, anchor, SourceMappingKind::Exact)
    }

    fn metadata(&self, point: ProgramPointId) -> Result<PointMetadata, PythonLoweringError> {
        self.session.metadata(point)
    }

    fn value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        kind: SemanticValueKind,
    ) -> Result<ValueId, PythonLoweringError> {
        self.session.add_value(builder, point, kind)
    }

    fn publish_none_return(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
    ) -> Result<(), PythonLoweringError> {
        let source = self.value(builder, point, SemanticValueKind::Null)?;
        self.publish_return(builder, point, source)
    }

    fn publish_return(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        source: ValueId,
    ) -> Result<(), PythonLoweringError> {
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
        )
    }

    fn append_effect(
        &self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        effect: SemanticEffect,
    ) -> Result<(), PythonLoweringError> {
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
    ) -> Result<(), PythonLoweringError> {
        self.session
            .add_gap(builder, point, subject, capability, kind, detail)?;
        Ok(())
    }

    fn edge(
        &self,
        builder: &mut ProcedureCfgBuilder,
        source_point: ProgramPointId,
        target: EdgeTarget,
    ) -> Result<(), PythonLoweringError> {
        self.session
            .add_edge(builder, source_point, target.point, target.kind)
    }
}

struct PreciseExceptBinding {
    value: ValueId,
    name: Box<str>,
    class_name: Box<str>,
    fields: HashSet<Box<str>>,
}

fn direct_raise_identifier<'tree>(body: Node<'tree>) -> Option<Node<'tree>> {
    let raises = named_children(body)
        .into_iter()
        .filter(|child| child.kind() == "raise_statement")
        .collect::<Vec<_>>();
    let [raise] = raises.as_slice() else {
        return None;
    };
    let values = runtime_expression_children(*raise);
    let [value] = values.as_slice() else {
        return None;
    };
    (value.kind() == "identifier").then_some(*value)
}

fn precise_except_shape<'tree>(clause: Node<'tree>) -> Option<(Node<'tree>, Node<'tree>)> {
    if has_direct_token(clause, "*") {
        return None;
    }
    let values = children_by_field_name(clause, "value");
    let [value] = values.as_slice() else {
        return None;
    };
    let (type_node, alias) = if value.kind() == "as_pattern" {
        let alias = value.child_by_field_name("alias")?;
        let type_node = named_children(*value)
            .into_iter()
            .find(|child| child.id() != alias.id())?;
        let binder = as_pattern_binder(alias)?;
        (type_node, binder)
    } else {
        let alias = clause.child_by_field_name("alias")?;
        (*value, alias)
    };
    (type_node.kind() == "identifier" && alias.kind() == "identifier").then_some((type_node, alias))
}

/// The `as_pattern` binder of an `as` target, unwrapped to the bound name.
///
/// A pattern target wraps its single binding, so matching on the wrapper's
/// named children keeps the answer structural instead of reading source text.
fn as_pattern_binder(alias: Node<'_>) -> Option<Node<'_>> {
    if alias.kind() != "as_pattern_target" {
        return Some(alias);
    }
    let children = named_children(alias);
    let [binder] = children.as_slice() else {
        return None;
    };
    Some(*binder)
}

/// The context manager items of a `with` statement, in declaration order.
fn with_items(node: Node<'_>) -> Result<Vec<Node<'_>>, PythonLoweringError> {
    assert_eq!(
        node.kind(),
        "with_statement",
        "only a with statement declares a context manager list"
    );
    let clause = named_children(node)
        .into_iter()
        .find(|child| child.kind() == "with_clause")
        .ok_or_else(|| missing_field(node, "with clause"))?;
    Ok(named_children(clause)
        .into_iter()
        .filter(|child| child.kind() == "with_item")
        .collect())
}

/// The evaluated context manager and the optional `as` binder of one item.
fn with_item_parts<'tree>(
    item: Node<'tree>,
) -> Result<(Node<'tree>, Option<Node<'tree>>), PythonLoweringError> {
    assert_eq!(
        item.kind(),
        "with_item",
        "only a with item declares a context manager and its optional binder"
    );
    let value = required_field(item, "value")?;
    if value.kind() != "as_pattern" {
        return Ok((value, None));
    }

    let alias = value.child_by_field_name("alias");
    let context = named_children(value)
        .into_iter()
        .find(|child| alias.is_none_or(|alias| alias.id() != child.id()))
        .ok_or_else(|| missing_field(value, "context expression"))?;
    Ok((context, alias.and_then(as_pattern_binder)))
}

fn python_binding_name_node<'tree>(
    root: Node<'tree>,
    source: &str,
    expected: &str,
) -> Option<Node<'tree>> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "identifier" && node_text(source, node) == Some(expected) {
            return Some(node);
        }
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        stack.extend(children.into_iter().rev());
    }
    None
}

fn expression_value_kind(node: Node<'_>) -> SemanticValueKind {
    match node.kind() {
        "lambda" => SemanticValueKind::Callable,
        "true" => SemanticValueKind::Boolean(true),
        "false" => SemanticValueKind::Boolean(false),
        "integer" | "float" | "none" | "ellipsis" | "string" => SemanticValueKind::Constant,
        _ => SemanticValueKind::Temporary,
    }
}

fn is_structural_constant_index(source: &str, node: Node<'_>) -> Option<u64> {
    (node.kind() == "integer")
        .then(|| node_text(source, node))
        .flatten()
        .and_then(|text| text.parse::<u64>().ok())
}

fn runtime_expression_children(node: Node<'_>) -> Vec<Node<'_>> {
    match node.kind() {
        "attribute" => return children_by_field_name(node, "object"),
        "subscript" => {
            let mut result = children_by_field_name(node, "value");
            result.extend(children_by_field_name(node, "subscript"));
            return result;
        }
        "assignment" => {
            let mut result = children_by_field_name(node, "right");
            if let Some(left) = node.child_by_field_name("left") {
                match left.kind() {
                    "attribute" => result.extend(children_by_field_name(left, "object")),
                    "subscript" => {
                        result.extend(children_by_field_name(left, "value"));
                        result.extend(children_by_field_name(left, "subscript"));
                    }
                    _ => result.extend(assignment_target_runtime_nodes(left)),
                }
            }
            return result;
        }
        "augmented_assignment" => {
            let mut result = Vec::new();
            if let Some(left) = node.child_by_field_name("left")
                && !is_plain_binding(left.kind())
            {
                result.push(left);
            }
            result.extend(children_by_field_name(node, "right"));
            return result;
        }
        "named_expression" => return children_by_field_name(node, "value"),
        "boolean_operator" | "binary_operator" => {
            let mut result = children_by_field_name(node, "left");
            result.extend(children_by_field_name(node, "right"));
            return result;
        }
        "unary_operator" | "not_operator" => {
            return children_by_field_name(node, "argument");
        }
        "keyword_argument" => return children_by_field_name(node, "value"),
        "pair" => {
            let mut result = children_by_field_name(node, "key");
            result.extend(children_by_field_name(node, "value"));
            return result;
        }
        "interpolation" | "format_expression" => {
            return children_by_field_name(node, "expression");
        }
        "string" => {
            return named_children(node)
                .into_iter()
                .filter(|child| child.kind() == "interpolation")
                .collect();
        }
        _ => {}
    }

    named_children(node)
        .into_iter()
        .filter(|child| {
            !is_non_runtime_field(node, *child)
                && !is_type_syntax(child.kind())
                && !is_pattern_syntax(child.kind())
                && !matches!(
                    child.kind(),
                    "comment"
                        | "format_specifier"
                        | "string_content"
                        | "string_start"
                        | "string_end"
                        | "type_conversion"
                )
        })
        .collect()
}

fn assignment_target_runtime_nodes(target: Node<'_>) -> Vec<Node<'_>> {
    let mut result = Vec::new();
    let mut stack = vec![target];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "attribute" => result.extend(children_by_field_name(node, "object")),
            "subscript" => {
                result.extend(children_by_field_name(node, "value"));
                result.extend(children_by_field_name(node, "subscript"));
            }
            "identifier" | "keyword_identifier" => {}
            _ => {
                let children = named_children(node);
                for child in children.into_iter().rev() {
                    stack.push(child);
                }
            }
        }
    }
    result
}

fn is_unpacking_target(target: Node<'_>) -> bool {
    matches!(
        target.kind(),
        "pattern_list" | "tuple_pattern" | "list_pattern"
    )
}

fn is_assignment_target(target: Node<'_>) -> bool {
    matches!(
        target.kind(),
        "identifier"
            | "keyword_identifier"
            | "attribute"
            | "subscript"
            | "pattern_list"
            | "tuple_pattern"
            | "list_pattern"
    )
}

/// Flatten Python's right-recursive chained-assignment grammar into runtime
/// target order. The deepest right-hand expression executes once, followed
/// by each target from left to right.
fn assignment_chain<'tree>(node: Node<'tree>) -> (Vec<Node<'tree>>, Option<Node<'tree>>) {
    let mut targets = Vec::new();
    let mut assignment = node;
    loop {
        let Some(target) = assignment.child_by_field_name("left") else {
            return (targets, None);
        };
        targets.push(target);
        let Some(rhs) = assignment.child_by_field_name("right") else {
            return (targets, None);
        };
        if rhs.kind() != "assignment" {
            return (targets, Some(rhs));
        }
        assignment = rhs;
    }
}

#[derive(Clone, Copy)]
enum AssignmentSource<'tree> {
    Expression(Node<'tree>),
    Produced(usize),
    Unknown,
}

struct UnpackOutput {
    id: usize,
    ordinal: usize,
}

enum AssignmentTargetStep<'tree> {
    UnpackBoundary {
        target: Node<'tree>,
        source: AssignmentSource<'tree>,
        outputs: Vec<UnpackOutput>,
        may_fail: bool,
    },
    Leaf {
        target: Node<'tree>,
        source: AssignmentSource<'tree>,
    },
}

fn assignment_target_steps<'tree>(
    target: Node<'tree>,
    source: Option<Node<'tree>>,
) -> Vec<AssignmentTargetStep<'tree>> {
    let mut result = Vec::new();
    let mut next_output = 0usize;
    let mut stack = vec![(
        target,
        source.map_or(AssignmentSource::Unknown, AssignmentSource::Expression),
    )];
    while let Some((target, source)) = stack.pop() {
        match target.kind() {
            "identifier" | "keyword_identifier" | "attribute" | "subscript" => {
                result.push(AssignmentTargetStep::Leaf { target, source });
            }
            "list_splat_pattern" => {
                let children = named_children(target);
                if let Some(child) = children.first().copied() {
                    stack.push((child, AssignmentSource::Unknown));
                }
            }
            "pattern_list" | "tuple_pattern" | "list_pattern" => {
                let targets = named_children(target);
                let (sources, outputs, may_fail) =
                    assignment_target_sources(&targets, source, &mut next_output);
                result.push(AssignmentTargetStep::UnpackBoundary {
                    target,
                    source,
                    outputs,
                    may_fail,
                });
                for (target, source) in targets.into_iter().zip(sources).rev() {
                    stack.push((target, source));
                }
            }
            _ => {
                let children = named_children(target);
                for child in children.into_iter().rev() {
                    stack.push((child, AssignmentSource::Unknown));
                }
            }
        }
    }
    result
}

fn assignment_target_sources<'tree>(
    targets: &[Node<'tree>],
    source: AssignmentSource<'tree>,
    next_output: &mut usize,
) -> (Vec<AssignmentSource<'tree>>, Vec<UnpackOutput>, bool) {
    let starred = targets
        .iter()
        .enumerate()
        .filter(|(_, target)| target.kind() == "list_splat_pattern")
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if starred.len() > 1 {
        return (
            vec![AssignmentSource::Unknown; targets.len()],
            Vec::new(),
            true,
        );
    }
    if let AssignmentSource::Expression(source) = source
        && let Some(sources) = unpack_source_children(source)
    {
        return literal_assignment_target_sources(targets, sources, &starred);
    }
    if !starred.is_empty() || matches!(source, AssignmentSource::Unknown) {
        return (
            vec![AssignmentSource::Unknown; targets.len()],
            Vec::new(),
            true,
        );
    }
    let mut outputs = Vec::with_capacity(targets.len());
    let sources = targets
        .iter()
        .enumerate()
        .map(|(ordinal, _)| {
            let id = *next_output;
            *next_output += 1;
            outputs.push(UnpackOutput { id, ordinal });
            AssignmentSource::Produced(id)
        })
        .collect();
    (sources, outputs, true)
}

fn literal_assignment_target_sources<'tree>(
    targets: &[Node<'tree>],
    sources: Vec<Node<'tree>>,
    starred: &[usize],
) -> (Vec<AssignmentSource<'tree>>, Vec<UnpackOutput>, bool) {
    let Some(&starred_index) = starred.first() else {
        return if sources.len() == targets.len() {
            (
                sources
                    .into_iter()
                    .map(AssignmentSource::Expression)
                    .collect(),
                Vec::new(),
                false,
            )
        } else {
            (
                vec![AssignmentSource::Unknown; targets.len()],
                Vec::new(),
                true,
            )
        };
    };

    let fixed_count = targets.len().saturating_sub(1);
    if sources.len() < fixed_count {
        return (
            vec![AssignmentSource::Unknown; targets.len()],
            Vec::new(),
            true,
        );
    }
    let suffix_count = targets.len() - starred_index - 1;
    let mut result = vec![AssignmentSource::Unknown; targets.len()];
    for (target, source) in result.iter_mut().zip(&sources).take(starred_index) {
        *target = AssignmentSource::Expression(*source);
    }
    for index in 0..suffix_count {
        let target_index = starred_index + 1 + index;
        let source_index = sources.len() - suffix_count + index;
        result[target_index] = sources
            .get(source_index)
            .copied()
            .map_or(AssignmentSource::Unknown, AssignmentSource::Expression);
    }
    (result, Vec::new(), false)
}

fn unpack_source_children<'tree>(source: Node<'tree>) -> Option<Vec<Node<'tree>>> {
    let mut source = source;
    while source.kind() == "parenthesized_expression" {
        source = first_runtime_named_child(source)?;
    }
    if !matches!(source.kind(), "expression_list" | "list" | "tuple") {
        return None;
    }
    let children = runtime_expression_children(source);
    (!children
        .iter()
        .any(|child| matches!(child.kind(), "list_splat" | "parenthesized_list_splat")))
    .then_some(children)
}

fn single_literal_sequence_element<'tree>(source: Node<'tree>) -> Option<Node<'tree>> {
    unpack_source_children(source).and_then(|children| {
        let [child] = children.as_slice() else {
            return None;
        };
        Some(*child)
    })
}

fn binding_requires_runtime_protocol(binding: Node<'_>) -> bool {
    !matches!(binding.kind(), "identifier" | "keyword_identifier")
}

fn first_runtime_named_child(node: Node<'_>) -> Option<Node<'_>> {
    runtime_expression_children(node).into_iter().next()
}

fn is_non_runtime_field(node: Node<'_>, child: Node<'_>) -> bool {
    [
        "name",
        "type",
        "return_type",
        "operator",
        "parameters",
        "type_parameters",
        "alias",
    ]
    .into_iter()
    .any(|field| field_matches(node, field, child))
}

fn is_type_syntax(kind: &str) -> bool {
    matches!(
        kind,
        "type"
            | "generic_type"
            | "union_type"
            | "member_type"
            | "constrained_type"
            | "type_parameter"
            | "typed_parameter"
            | "typed_default_parameter"
    )
}

fn is_pattern_syntax(kind: &str) -> bool {
    kind == "pattern"
        || kind.ends_with("_pattern")
        || matches!(
            kind,
            "case_pattern"
                | "complex_pattern"
                | "pattern_list"
                | "tuple_pattern"
                | "list_pattern"
                | "dict_pattern"
                | "class_pattern"
                | "keyword_pattern"
        )
}

fn is_plain_binding(kind: &str) -> bool {
    matches!(kind, "identifier" | "keyword_identifier")
}

fn is_callable_kind(kind: &str) -> bool {
    matches!(kind, "function_definition" | "lambda")
}

fn is_statement_kind(kind: &str) -> bool {
    matches!(
        kind,
        "block"
            | "assert_statement"
            | "break_statement"
            | "continue_statement"
            | "delete_statement"
            | "exec_statement"
            | "expression_statement"
            | "for_statement"
            | "future_import_statement"
            | "global_statement"
            | "if_statement"
            | "import_from_statement"
            | "import_statement"
            | "match_statement"
            | "nonlocal_statement"
            | "pass_statement"
            | "print_statement"
            | "raise_statement"
            | "return_statement"
            | "try_statement"
            | "type_alias_statement"
            | "while_statement"
            | "with_statement"
            | "function_definition"
            | "class_definition"
            | "decorated_definition"
    )
}

fn conditional_expression_parts(
    node: Node<'_>,
) -> Result<(Node<'_>, Node<'_>, Node<'_>), PythonLoweringError> {
    let children = named_children(node);
    if children.len() != 3 {
        return Err(PythonLoweringError::Invalid(format!(
            "conditional_expression at bytes {}..{} has {} runtime children",
            node.start_byte(),
            node.end_byte(),
            children.len()
        )));
    }
    Ok((children[0], children[1], children[2]))
}

fn first_comprehension_iterables(node: Node<'_>) -> Result<Vec<Node<'_>>, PythonLoweringError> {
    let first_clause = named_children(node)
        .into_iter()
        .find(|child| child.kind() == "for_in_clause")
        .ok_or_else(|| missing_field(node, "first for-in clause"))?;
    let iterables = children_by_field_name(first_clause, "right");
    if iterables.is_empty() {
        return Err(missing_field(first_clause, "right"));
    }
    Ok(iterables)
}

fn boolean_operator_kind(node: Node<'_>) -> Option<&'static str> {
    match node.child_by_field_name("operator")?.kind() {
        "and" => Some("and"),
        "or" => Some("or"),
        _ => None,
    }
}

fn literal_truth_condition(node: Node<'_>) -> Option<bool> {
    match node.kind() {
        "true" => Some(true),
        "false" | "none" => Some(false),
        _ => None,
    }
}

fn comparison_may_invoke_user_code(operator_kind: &str) -> bool {
    !matches!(operator_kind, "is" | "is not")
}

fn python_call_receiver(function: Node<'_>) -> Option<Node<'_>> {
    (function.kind() == "attribute")
        .then(|| function.child_by_field_name("object"))
        .flatten()
}

fn call_arguments(node: Node<'_>) -> Vec<Node<'_>> {
    match node.child_by_field_name("arguments") {
        Some(arguments) if arguments.kind() == "argument_list" => named_children(arguments),
        Some(generator) => vec![generator],
        None => Vec::new(),
    }
}

fn python_type_ref_is_never(reference: &TypeRef) -> bool {
    matches!(
        reference,
        TypeRef::Named {
            name,
            arguments,
            nullable: false,
        } if arguments.is_empty() && matches!(name.as_str(), "typing.NoReturn" | "typing.Never")
    )
}

fn non_empty_python_range(source: &str, call: Node<'_>) -> bool {
    let Some(values) = python_range_literal_values(source, call) else {
        return false;
    };
    match values.as_slice() {
        [stop] => *stop > 0,
        [start, stop] => start < stop,
        [start, stop, step] if *step != 0 => {
            if *step > 0 {
                start < stop
            } else {
                start > stop
            }
        }
        _ => false,
    }
}

fn python_range_literal_values(source: &str, call: Node<'_>) -> Option<Vec<i64>> {
    let arguments = call_arguments(call);
    if arguments.is_empty() || arguments.len() > 3 {
        return None;
    }
    if arguments
        .iter()
        .any(|argument| argument.kind() != "integer")
    {
        return None;
    }
    arguments
        .into_iter()
        .map(|argument| python_integer_literal_value(source, argument))
        .collect()
}

fn python_integer_literal_value(source: &str, node: Node<'_>) -> Option<i64> {
    (node.kind() == "integer")
        .then(|| node_text(source, node))
        .flatten()
        .and_then(|text| text.parse().ok())
}

fn python_argument_value_node(argument: Node<'_>) -> Node<'_> {
    match argument.kind() {
        "keyword_argument" => argument.child_by_field_name("value").unwrap_or(argument),
        "list_splat" | "dictionary_splat" => {
            first_runtime_named_child(argument).unwrap_or(argument)
        }
        _ => argument,
    }
}

fn call_function_requires_evaluation(function: Node<'_>) -> bool {
    function.kind() != "identifier"
}

fn may_invoke_user_code(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "augmented_assignment"
            | "binary_operator"
            | "unary_operator"
            | "list_splat"
            | "dictionary_splat"
            | "interpolation"
            | "format_expression"
    )
}

fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| !is_ignored_extra_kind(child.kind()))
        .collect()
}

fn first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| !is_ignored_extra_kind(child.kind()))
}

fn is_ignored_extra_kind(kind: &str) -> bool {
    matches!(kind, "comment" | "line_continuation")
}

fn required_field<'tree>(
    node: Node<'tree>,
    field: &str,
) -> Result<Node<'tree>, PythonLoweringError> {
    node.child_by_field_name(field)
        .ok_or_else(|| missing_field(node, field))
}

fn missing_field(node: Node<'_>, field: &str) -> PythonLoweringError {
    PythonLoweringError::Invalid(format!(
        "{} node at bytes {}..{} is missing structured field {field}",
        node.kind(),
        node.start_byte(),
        node.end_byte()
    ))
}

fn operation_can_throw_implicitly(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "assignment"
            | "augmented_assignment"
            | "binary_operator"
            | "unary_operator"
            | "not_operator"
            | "list"
            | "set"
            | "tuple"
            | "dictionary"
            | "list_splat"
            | "dictionary_splat"
            | "interpolation"
            | "format_expression"
    )
}

fn is_runtime_leaf(kind: &str) -> bool {
    matches!(
        kind,
        "identifier"
            | "integer"
            | "float"
            | "true"
            | "false"
            | "none"
            | "ellipsis"
            | "string_content"
            | "string_start"
            | "string_end"
            | "comment"
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::analyzer::LanguageDialect;
    use crate::analyzer::semantic::service::ProgramSemanticsLowerer;
    use crate::analyzer::tree_sitter_analyzer::{PreparedSourceOrigin, PreparedSyntaxSource};
    use crate::text_utils::compute_line_starts;

    fn lower_fixture(source: &str) -> ProcedureSemanticsParts {
        lower_fixture_named(source, None)
    }

    fn lower_fixture_named(source: &str, procedure_name: Option<&str>) -> ProcedureSemanticsParts {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("Python grammar is valid");
        let tree = parser.parse(source, None).expect("fixture parses");
        let prepared = PreparedSyntaxTree::new(
            PreparedSyntaxSource::Exact(Arc::<str>::from(source)),
            tree,
            compute_line_starts(source),
            LanguageDialect::Standard(Language::Python),
            PreparedSourceOrigin::Disk,
            None,
        );
        let file = ProjectFile::new(std::env::temp_dir(), "fixture.py");
        let lowerer = PythonSemanticLowerer {
            overlay: None,
            dependencies: DependencyFingerprint::hash_bytes(b"no-intrafile-dependencies"),
        };
        let SemanticOutcome::Complete { mut value, .. } = lowerer
            .lower(
                &file,
                &prepared,
                &SemanticBudget::default(),
                &CancellationToken::default(),
            )
            .expect("Python lowering succeeds")
        else {
            panic!("Python fixture lowering must complete");
        };
        let selected = match procedure_name {
            Some(name) => value
                .iter()
                .position(|parts| {
                    parts
                        .locator
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some(name)
                })
                .map(|index| value.remove(index)),
            None if value.len() == 1 => Some(value.pop().expect("fixture procedure is present")),
            None => None,
        };
        selected.unwrap_or_else(|| {
            panic!(
                "expected one Python procedure {:?}, found {}",
                procedure_name,
                value.len()
            )
        })
    }

    #[test]
    fn conditional_return_and_fallthrough_each_publish_one_value() {
        let parts = lower_fixture_named(
            "def pick(flag):\n    if flag:\n        return 1\n",
            Some("pick"),
        );
        let entry = parts
            .points
            .iter()
            .find(|point| {
                point
                    .events
                    .iter()
                    .any(|event| matches!(event.effect, SemanticEffect::Entry))
            })
            .expect("entry")
            .id;
        let mut pending = vec![(entry, Vec::new())];
        let mut visited = HashSet::default();
        let mut returned = Vec::new();
        while let Some((point, mut values)) = pending.pop() {
            if !visited.insert((point, values.clone())) {
                continue;
            }
            for event in &parts.points[point.index()].events {
                match event.effect {
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Return,
                        source,
                        ..
                    } => {
                        values.push(source);
                        assert_eq!(values.len(), 1, "a normal path returns exactly once");
                    }
                    SemanticEffect::NormalExit => {
                        assert_eq!(values.len(), 1, "fallthrough must return a value");
                        returned.push(values[0]);
                    }
                    _ => {}
                }
            }
            for edge in parts
                .control_edges
                .iter()
                .filter(|edge| edge.source_point == point)
            {
                if matches!(
                    edge.kind,
                    ControlEdgeKind::Normal
                        | ControlEdgeKind::ConditionalTrue
                        | ControlEdgeKind::ConditionalFalse
                ) {
                    pending.push((edge.target_point, values.clone()));
                }
            }
        }
        assert_eq!(returned.len(), 2, "both runtime branches complete normally");
        assert_eq!(
            returned
                .iter()
                .filter(|value| matches!(parts.values[value.index()].kind, SemanticValueKind::Null))
                .count(),
            1
        );
        assert_eq!(
            returned
                .iter()
                .filter(|value| matches!(
                    parts.values[value.index()].kind,
                    SemanticValueKind::Constant
                ))
                .count(),
            1
        );
    }

    #[test]
    fn cleanup_runs_between_return_evaluation_and_publication() {
        let source =
            "def make():\n    try:\n        return evaluate()\n    finally:\n        cleanup()\n";
        let parts = lower_fixture_named(source, Some("make"));
        let mut current = parts
            .points
            .iter()
            .find(|point| {
                point
                    .events
                    .iter()
                    .any(|event| matches!(event.effect, SemanticEffect::Entry))
            })
            .expect("entry")
            .id;
        let mut visited = HashSet::default();
        let mut actions = Vec::new();
        loop {
            assert!(
                visited.insert(current),
                "straight-line fixture must not cycle"
            );
            for event in &parts.points[current.index()].events {
                match event.effect {
                    SemanticEffect::Invoke { call_site } => {
                        let call = &parts.call_sites[call_site.index()];
                        let span = parts.source_mappings[call.source.index()]
                            .locator
                            .anchor()
                            .span();
                        actions.push(&source[span.start_byte() as usize..span.end_byte() as usize]);
                    }
                    SemanticEffect::ProcedureReturn { .. } => actions.push("return"),
                    _ => {}
                }
            }
            let successors = parts
                .control_edges
                .iter()
                .filter(|edge| {
                    edge.source_point == current
                        && matches!(
                            edge.kind,
                            ControlEdgeKind::Normal | ControlEdgeKind::Cleanup
                        )
                })
                .collect::<Vec<_>>();
            match successors.as_slice() {
                [] => break,
                [edge] => current = edge.target_point,
                _ => panic!("fixture has one normal continuation: {successors:?}"),
            }
        }
        assert_eq!(actions, ["evaluate()", "cleanup()", "return"]);
    }

    #[test]
    fn continued_comparison_preserves_both_control_outcomes() {
        let parts = lower_fixture_named(
            "def compare(left, right):\n    return left == \\\n        right\n",
            Some("compare"),
        );
        for kind in [
            ControlEdgeKind::ConditionalTrue,
            ControlEdgeKind::ConditionalFalse,
        ] {
            assert!(
                parts.control_edges.iter().any(|edge| edge.kind == kind),
                "a continued comparison must preserve {kind:?}"
            );
        }
    }

    #[test]
    fn python_attribute_read_lowers_its_implicit_abort_edge() {
        let parts = lower_fixture_named("def read(value):\n    return value.field\n", Some("read"));
        let access = parts
            .gaps
            .iter()
            .find(|gap| {
                gap.capability == SemanticCapability::Calls
                    && gap.detail.as_ref()
                        == "descriptor or special-method invocation requires type refinement"
            })
            .expect("the Python attribute keeps its value-level descriptor claim")
            .point;
        assert!(
            parts.control_edges.iter().any(|edge| {
                edge.source_point == access && edge.kind == ControlEdgeKind::Exceptional
            }),
            "the attribute read must lower its implicit abort edge: {:?}",
            parts.control_edges
        );
        assert!(
            !parts.gaps.iter().any(|gap| {
                gap.capability == SemanticCapability::ExceptionalControlFlow
                    && gap.subject == SemanticGapSubject::Point
            }),
            "a lowered abort edge must not also declare the abort unmodeled: {:?}",
            parts.gaps
        );
    }

    #[test]
    fn comma_expression_allocates_a_tuple_without_parentheses() {
        let parts = lower_fixture_named("def pair():\n    return 1, 2\n", Some("pair"));
        let [allocation] = parts.allocations.as_slice() else {
            panic!(
                "comma expression must allocate one tuple: {:?}",
                parts.allocations
            );
        };
        assert_eq!(allocation.kind, AllocationKind::Array);
        let value = &parts.values[allocation.result.index()];
        let mapping = &parts.source_mappings[value.source.index()];
        let span = mapping.locator.anchor().span();
        assert_eq!(
            &"def pair():\n    return 1, 2\n"[span.start_byte() as usize..span.end_byte() as usize],
            "1, 2"
        );
    }

    #[test]
    fn comprehension_target_flow_is_distinct_from_the_enclosing_parameter() {
        let source = "def run(item):\n    return [item for item in ('local',)]\n";
        let parts = lower_fixture_named(source, Some("run"));
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let function = tree.root_node().named_child(0).unwrap();
        let comprehension = required_field(function, "body")
            .unwrap()
            .named_child(0)
            .unwrap()
            .named_child(0)
            .unwrap();
        assert_eq!(comprehension.kind(), "list_comprehension");
        let body = required_field(comprehension, "body").unwrap();
        let target = required_field(comprehension.named_child(1).unwrap(), "left").unwrap();
        let parameter = parts
            .values
            .iter()
            .find(|value| matches!(value.kind, SemanticValueKind::Parameter { ordinal: 0, .. }))
            .unwrap()
            .id;
        let target = value_for_node(&parts, target, SemanticValueKind::Local);
        let body = value_for_node(&parts, body, SemanticValueKind::Temporary);
        assert!(flow_reaches(&parts, target, body));
        assert!(!flow_reaches(&parts, parameter, body));
    }

    #[test]
    fn sequence_literal_initializers_publish_exact_indexed_stores() {
        let parts = lower_fixture_named(
            "def make(left, right):\n    return [left, right]\n",
            Some("make"),
        );
        let mut indices = parts
            .points
            .iter()
            .flat_map(|point| &point.events)
            .filter_map(|event| match event.effect {
                SemanticEffect::MemoryStore { location, .. } => {
                    match parts.memory_locations[location.index()].kind {
                        MemoryLocationKind::Index { constant_index, .. } => constant_index,
                        _ => None,
                    }
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        indices.sort_unstable();
        assert_eq!(indices, [0, 1]);
    }

    fn value_for_node(
        parts: &ProcedureSemanticsParts,
        node: Node<'_>,
        expected_kind: SemanticValueKind,
    ) -> ValueId {
        parts
            .values
            .iter()
            .find(|value| {
                value.kind == expected_kind
                    && parts
                        .source_mappings
                        .get(value.source.index())
                        .is_some_and(|mapping| {
                            let span = mapping.locator.anchor().span();
                            span.start_byte() as usize == node.start_byte()
                                && span.end_byte() as usize == node.end_byte()
                        })
            })
            .map(|value| value.id)
            .unwrap_or_else(|| {
                panic!(
                    "missing {:?} value for {} at {}..{}",
                    expected_kind,
                    node.kind(),
                    node.start_byte(),
                    node.end_byte()
                )
            })
    }

    fn flow_reaches(parts: &ProcedureSemanticsParts, source: ValueId, target: ValueId) -> bool {
        let mut pending = vec![source];
        let mut visited = HashSet::default();
        while let Some(current) = pending.pop() {
            if current == target {
                return true;
            }
            if !visited.insert(current) {
                continue;
            }
            for event in parts.points.iter().flat_map(|point| point.events.iter()) {
                if let SemanticEffect::ValueFlow { source, target, .. } = &event.effect
                    && *source == current
                {
                    pending.push(*target);
                }
            }
        }
        false
    }

    #[test]
    fn nested_arithmetic_flows_into_result_without_targeting_literal() {
        let source =
            "def compute(value):\n    result = (value * 3) + 7\n    safe = 7\n    return result\n";
        let parts = lower_fixture(source);

        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("Python grammar is valid");
        let tree = parser.parse(source, None).expect("fixture parses");
        let function = tree
            .root_node()
            .named_child(0)
            .expect("function definition is present");
        let body = function
            .child_by_field_name("body")
            .expect("function body is present");
        let assignment_statement = body
            .named_child(0)
            .expect("computed assignment statement is present");
        assert_eq!(assignment_statement.kind(), "expression_statement");
        let assignment =
            first_named_child(assignment_statement).expect("computed assignment is present");
        let outer = assignment
            .child_by_field_name("right")
            .expect("outer operator is present");
        let parenthesized = outer
            .child_by_field_name("left")
            .expect("parenthesized operand is present");
        let inner = parenthesized
            .named_child(0)
            .expect("inner operator is present");
        let source_value = inner
            .child_by_field_name("left")
            .expect("source operand is present");
        let safe_statement = body
            .named_child(1)
            .expect("unrelated constant assignment statement is present");
        assert_eq!(safe_statement.kind(), "expression_statement");
        let safe_assignment =
            first_named_child(safe_statement).expect("unrelated constant assignment is present");
        let unrelated_literal = safe_assignment
            .child_by_field_name("right")
            .expect("unrelated literal is present");

        let source_value = value_for_node(&parts, source_value, SemanticValueKind::Temporary);
        let inner = value_for_node(&parts, inner, SemanticValueKind::Temporary);
        let parenthesized = value_for_node(&parts, parenthesized, SemanticValueKind::Temporary);
        let outer = value_for_node(&parts, outer, SemanticValueKind::Temporary);
        let unrelated_literal =
            value_for_node(&parts, unrelated_literal, SemanticValueKind::Constant);
        let (flows, assignments) = parts
            .points
            .iter()
            .flat_map(|point| point.events.iter())
            .fold(
                (Vec::new(), Vec::new()),
                |(mut flows, mut assignments), event| {
                    match &event.effect {
                        SemanticEffect::ValueFlow {
                            kind: ValueFlowKind::LanguageDefined,
                            source,
                            target,
                        } => flows.push((*source, *target)),
                        SemanticEffect::Assignment { target, value } => {
                            assignments.push((*value, *target))
                        }
                        _ => {}
                    }
                    (flows, assignments)
                },
            );

        assert!(flows.contains(&(source_value, inner)));
        assert!(assignments.contains(&(inner, parenthesized)));
        assert!(flows.contains(&(parenthesized, outer)));
        assert!(flows.iter().all(|(_, target)| *target != unrelated_literal));
    }

    #[test]
    fn unpacking_assignment_publishes_rhs_values_in_target_order() {
        let source = "def swap(left, right):\n    left, right = right, left\n    return left\n";
        let parts = lower_fixture_named(source, Some("swap"));
        let tree = parse(source);
        let function = first_node_of_kind(&tree, "function_definition");
        let body = function.child_by_field_name("body").expect("function body");
        let assignment =
            first_assignment_with_left_kind(body, "pattern_list", Some("expression_list"));
        let left = assignment
            .child_by_field_name("left")
            .expect("assignment target");
        let right = assignment
            .child_by_field_name("right")
            .expect("assignment source");
        let targets = named_children(left);
        let sources = named_children(right);
        assert_eq!(targets.len(), 2);
        assert_eq!(sources.len(), 2);
        let parameters = function
            .child_by_field_name("parameters")
            .expect("function parameters");
        let parameters = named_children(parameters);
        let target_left = value_for_node(
            &parts,
            parameters[0],
            SemanticValueKind::Parameter {
                ordinal: 0,
                multiplicity: FormalMultiplicity::One,
                name: Some("left".into()),
                passing_mode: FormalParameterPassingMode::PositionalOrNamed,
            },
        );
        let target_right = value_for_node(
            &parts,
            parameters[1],
            SemanticValueKind::Parameter {
                ordinal: 1,
                multiplicity: FormalMultiplicity::One,
                name: Some("right".into()),
                passing_mode: FormalParameterPassingMode::PositionalOrNamed,
            },
        );
        let source_right = value_for_node(&parts, sources[0], SemanticValueKind::Temporary);
        let source_left = value_for_node(&parts, sources[1], SemanticValueKind::Temporary);
        let assignments = parts
            .points
            .iter()
            .flat_map(|point| point.events.iter())
            .filter_map(|event| match event.effect {
                SemanticEffect::Assignment { target, value } => Some((target, value)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(assignments.contains(&(target_left, source_right)));
        assert!(assignments.contains(&(target_right, source_left)));
    }

    #[test]
    fn literal_tuple_unpacking_retains_each_element_identity() {
        let source =
            "def unpack(left, right):\n    first, second = (left, right)\n    return first\n";
        let parts = lower_fixture_named(source, Some("unpack"));
        let tree = parse(source);
        let function = first_node_of_kind(&tree, "function_definition");
        let body = function.child_by_field_name("body").expect("function body");
        let assignment = first_assignment_with_left_kind(body, "pattern_list", Some("tuple"));
        let left = assignment
            .child_by_field_name("left")
            .expect("assignment target");
        let right = assignment
            .child_by_field_name("right")
            .expect("assignment source");
        let targets = named_children(left);
        let sources = named_children(right);
        assert_eq!(targets.len(), 2);
        assert_eq!(sources.len(), 2);
        let first = value_for_node(&parts, targets[0], SemanticValueKind::Local);
        let second = value_for_node(&parts, targets[1], SemanticValueKind::Local);
        let left_source = value_for_node(&parts, sources[0], SemanticValueKind::Temporary);
        let right_source = value_for_node(&parts, sources[1], SemanticValueKind::Temporary);
        assert!(
            parts
                .points
                .iter()
                .flat_map(|point| point.events.iter())
                .any(|event| matches!(
                    event.effect,
                    SemanticEffect::Assignment { target, value }
                        if target == first && value == left_source
                ))
        );
        assert!(
            parts
                .points
                .iter()
                .flat_map(|point| point.events.iter())
                .any(|event| matches!(
                    event.effect,
                    SemanticEffect::Assignment { target, value }
                        if target == second && value == right_source
                ))
        );
    }

    #[test]
    fn runtime_unpacking_publishes_ordered_index_loads() {
        let parts = lower_fixture_named(
            "def unpack():\n    first, second = make()\n    return first\n",
            Some("unpack"),
        );
        let result = parts
            .call_sites
            .iter()
            .find(|call| call.normal_result_values().next().is_some())
            .and_then(|call| call.normal_result_values().next())
            .expect("make() has a normal result");
        let mut loads = parts
            .points
            .iter()
            .flat_map(|point| &point.events)
            .filter_map(|event| {
                let SemanticEffect::MemoryLoad {
                    location,
                    result: loaded,
                    ..
                } = event.effect
                else {
                    return None;
                };
                let MemoryLocationKind::Index {
                    base,
                    constant_index,
                    ..
                } = parts.memory_locations[location.index()].kind
                else {
                    return None;
                };
                (base == result).then_some((constant_index, loaded))
            })
            .collect::<Vec<_>>();
        loads.sort_unstable_by_key(|(index, _)| *index);
        assert_eq!(
            loads.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
            [Some(0), Some(1)]
        );
        let assigned = parts
            .points
            .iter()
            .flat_map(|point| &point.events)
            .filter_map(|event| match event.effect {
                SemanticEffect::Assignment { value, .. } => Some(value),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(loads.iter().all(|(_, value)| assigned.contains(value)));
    }

    #[test]
    fn chained_assignment_publishes_one_rhs_for_each_target() {
        let source = "def bind():\n    first = second = \"value\"\n";
        let parts = lower_fixture_named(source, Some("bind"));
        let tree = parse(source);
        let function = first_node_of_kind(&tree, "function_definition");
        let body = function.child_by_field_name("body").expect("function body");
        let assignment = first_assignment_with_left_kind(body, "identifier", Some("assignment"));
        let (targets, rhs) = assignment_chain(assignment);
        assert_eq!(targets.len(), 2);
        let rhs = rhs.expect("the chain has a final RHS");
        let rhs = value_for_node(&parts, rhs, SemanticValueKind::Constant);
        let target_values = targets
            .into_iter()
            .map(|target| value_for_node(&parts, target, SemanticValueKind::Local))
            .collect::<Vec<_>>();
        for target in target_values {
            assert!(parts.points.iter().flat_map(|point| &point.events).any(
                |event| matches!(event.effect, SemanticEffect::Assignment { target: assigned, value } if assigned == target && value == rhs)
            ));
        }
    }

    #[test]
    fn augmented_assignment_replaces_its_binding_with_an_unknown_result() {
        let source = "def update(flag):\n    flag |= unknown()\n";
        let parts = lower_fixture_named(source, Some("update"));
        let unknown = parts
            .values
            .iter()
            .find(|value| {
                matches!(
                    &value.kind,
                    SemanticValueKind::LanguageDefined(kind)
                        if kind.as_ref() == PYTHON_UNKNOWN_AUGMENTED_ASSIGNMENT
                )
            })
            .map(|value| value.id)
            .expect("augmented assignment has an explicit unknown result");
        let parameter = parts
            .values
            .iter()
            .find(|value| matches!(value.kind, SemanticValueKind::Parameter { .. }))
            .map(|value| value.id)
            .expect("fixture parameter");
        assert!(parts.points.iter().flat_map(|point| &point.events).any(
            |event| matches!(event.effect, SemanticEffect::Assignment { target, value } if target == parameter && value == unknown)
        ));
    }

    #[test]
    fn unknown_for_element_replaces_the_preexisting_binding() {
        let parts = lower_fixture_named(
            "def consume(values):\n    for item in values:\n        use(item)\n",
            Some("consume"),
        );
        let item = parts
            .values
            .iter()
            .find(|value| {
                value.kind == SemanticValueKind::Local
                    && parts
                        .source_mappings
                        .get(value.source.index())
                        .is_some_and(|mapping| mapping.locator.anchor().span().start_byte() > 0)
            })
            .map(|value| value.id)
            .expect("loop target local");
        let unknown = parts
            .values
            .iter()
            .filter(|value| {
                matches!(
                    &value.kind,
                    SemanticValueKind::LanguageDefined(kind)
                        if kind.as_ref() == PYTHON_UNKNOWN_ITERATION_ELEMENT
                )
            })
            .map(|value| value.id)
            .collect::<Vec<_>>();
        assert_eq!(unknown.len(), 1);
        assert!(parts.points.iter().flat_map(|point| point.events.iter()).any(
            |event| matches!(event.effect, SemanticEffect::Assignment { target, value } if target == item && unknown.contains(&value))
        ));
    }

    #[test]
    fn proven_builtin_str_call_flows_argument_to_result_without_a_call_site() {
        let source = "def convert(value):\n    result = str(value)\n    return result\n";
        let parts = lower_fixture(source);

        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("Python grammar is valid");
        let tree = parser.parse(source, None).expect("fixture parses");
        let function = tree
            .root_node()
            .named_child(0)
            .expect("function definition is present");
        let body = function
            .child_by_field_name("body")
            .expect("function body is present");
        let assignment_statement = body
            .named_child(0)
            .expect("str assignment statement is present");
        let assignment =
            first_named_child(assignment_statement).expect("str assignment is present");
        let call = assignment
            .child_by_field_name("right")
            .expect("str call is present");
        assert_eq!(call.kind(), "call");
        let argument = call
            .child_by_field_name("arguments")
            .expect("str argument list is present")
            .named_child(0)
            .expect("str argument is present");

        let argument_value = value_for_node(&parts, argument, SemanticValueKind::Temporary);
        let result_value = value_for_node(&parts, call, SemanticValueKind::Temporary);
        assert!(
            flow_reaches(&parts, argument_value, result_value),
            "a proven builtin str call must flow its argument to the call result"
        );
        assert!(
            parts.call_sites.is_empty(),
            "a proven builtin str call must not retain an unresolved call site"
        );
        assert!(
            !parts
                .gaps
                .iter()
                .any(|gap| gap.capability == SemanticCapability::DynamicDispatch),
            "a proven builtin str call must not publish a dispatch gap"
        );
    }

    #[test]
    fn rebound_str_keeps_the_generic_call_path() {
        let source = "def str(value):\n    return value\n\n\ndef convert(value):\n    result = str(value)\n    return result\n";
        let parts = lower_fixture_named(source, Some("convert"));

        assert!(
            !parts.call_sites.is_empty(),
            "a rebound str keeps the generic call site"
        );
        assert!(
            parts
                .gaps
                .iter()
                .any(|gap| gap.capability == SemanticCapability::DynamicDispatch),
            "a rebound str keeps the honest dispatch gap"
        );
    }

    fn condition_literal(source: &str) -> Option<bool> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("Python grammar must load");
        let tree = parser
            .parse(source, None)
            .expect("Python source must parse");
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "if_statement" {
                let condition = node
                    .child_by_field_name("condition")
                    .expect("if condition field");
                return literal_truth_condition(condition);
            }
            stack.extend(named_children(node).into_iter().rev());
        }
        panic!("if statement missing from Python fixture");
    }

    fn range_is_non_empty(source: &str) -> bool {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("Python grammar must load");
        let tree = parser
            .parse(source, None)
            .expect("Python source must parse");
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "call"
                && node
                    .child_by_field_name("function")
                    .is_some_and(|function| node_text(source, function) == Some("range"))
            {
                return non_empty_python_range(source, node);
            }
            stack.extend(named_children(node).into_iter().rev());
        }
        panic!("range call missing from Python fixture");
    }

    #[test]
    fn literal_range_shape_proves_non_empty_first_iteration() {
        assert!(range_is_non_empty("for item in range(3):\n    pass\n"));
        assert!(!range_is_non_empty("for item in range(0):\n    pass\n"));
        assert!(!range_is_non_empty("for item in range(limit):\n    pass\n"));
    }

    #[test]
    fn literal_truth_condition_routes_only_its_feasible_edge() {
        assert_eq!(condition_literal("if True:\n    pass\n"), Some(true));
        assert_eq!(condition_literal("if False:\n    pass\n"), Some(false));
        assert_eq!(condition_literal("if None:\n    pass\n"), Some(false));
        assert_eq!(condition_literal("if value:\n    pass\n"), None);
    }

    fn parse(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("Python grammar");
        parser.parse(source, None).expect("Python source parses")
    }

    fn first_node_of_kind<'tree>(tree: &'tree tree_sitter::Tree, kind: &str) -> Node<'tree> {
        let mut stack = vec![tree.root_node()];
        first_node_of_kind_in_stack(&mut stack, kind)
    }

    fn first_node_of_kind_in<'tree>(root: Node<'tree>, kind: &str) -> Node<'tree> {
        let mut stack = vec![root];
        first_node_of_kind_in_stack(&mut stack, kind)
    }

    fn first_node_of_kind_in_stack<'tree>(stack: &mut Vec<Node<'tree>>, kind: &str) -> Node<'tree> {
        while let Some(node) = stack.pop() {
            if node.kind() == kind {
                return node;
            }
            stack.extend(named_children(node).into_iter().rev());
        }
        panic!("missing {kind} node");
    }

    fn first_assignment_with_left_kind<'tree>(
        root: Node<'tree>,
        left_kind: &str,
        right_kind: Option<&str>,
    ) -> Node<'tree> {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if node.kind() == "assignment"
                && node
                    .child_by_field_name("left")
                    .is_some_and(|left| left.kind() == left_kind)
                && right_kind.is_none_or(|kind| {
                    node.child_by_field_name("right")
                        .is_some_and(|right| right.kind() == kind)
                })
            {
                return node;
            }
            stack.extend(named_children(node).into_iter().rev());
        }
        panic!("missing assignment with {left_kind} left");
    }

    #[test]
    fn simple_initializer_proves_direct_instance_field() {
        let source = "class Holder:\n    def __init__(self):\n        self.value = 0\n";
        let tree = parse(source);
        let class = first_node_of_kind(&tree, "class_definition");
        let (name, fields) = class_field_proof(class, source, true).expect("simple class proof");
        assert_eq!(&*name, "Holder");
        assert!(fields.contains("value"));
    }

    #[test]
    fn proven_initializer_receiver_store_has_no_dynamic_attribute_gap() {
        let source = "class Holder:\n    def __init__(self):\n        self.value = 0\n";
        let parts = lower_fixture_named(source, Some("__init__"));

        assert_eq!(parts.kind, ProcedureKind::Constructor);
        assert!(!parts.gaps.iter().any(|gap| {
            gap.detail
                .contains("descriptor or special-method invocation")
                || (gap.capability == SemanticCapability::ExceptionalControlFlow
                    && gap.detail.contains("assignment"))
        }));
    }

    #[test]
    fn defaults_are_saved_values_not_callee_calls_or_allocations() {
        let source = "class Token:\n    pass\ndef target(x=Token(), *, items=[]):\n    return x\n";
        let parts = lower_fixture_named(source, Some("target"));
        let defaults = parts
            .values
            .iter()
            .filter_map(|value| match value.kind {
                SemanticValueKind::DefaultArgument { ordinal } => Some(ordinal),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(defaults, [0, 1]);
        assert!(
            parts.call_sites.is_empty(),
            "defaults are not evaluated by calling target"
        );
        assert!(
            parts.allocations.is_empty(),
            "a mutable default is not fresh on each call"
        );
    }

    #[test]
    fn enclosing_inventory_preserves_shadowing_and_explicit_global_resolution() {
        for (declaration, proven) in [("", false), ("        global Holder\n", true)] {
            let source = format!(
                "class Holder:\n    def __init__(self):\n        self.value = 0\ndef outer(Holder):\n    def inner():\n{declaration}        Holder()\n"
            );
            let parts = lower_fixture_named(&source, Some("inner"));
            let [call] = parts.call_sites.as_slice() else {
                panic!("inner must contain exactly one call")
            };
            assert_eq!(
                matches!(
                    call.declared_targets,
                    CallableTargetResolution::Proven(CallableTarget::Local(_))
                ),
                proven,
                "{source}: {:?}",
                call.declared_targets
            );
        }
    }

    #[test]
    fn proven_module_class_call_names_its_local_constructor() {
        let source = "class Holder:\n    def __init__(self):\n        self.value = 0\n\ndef run():\n    Holder()\n";
        let parts = lower_fixture_named(source, Some("run"));
        let [call] = parts.call_sites.as_slice() else {
            panic!("run must contain exactly one constructor call")
        };

        assert!(matches!(
            call.declared_targets,
            CallableTargetResolution::Proven(CallableTarget::Local(_))
        ));
        assert!(
            parts
                .allocations
                .iter()
                .any(|allocation| allocation.result == call.result.expect("constructor result"))
        );
    }

    #[test]
    fn exception_subclass_requires_inert_class_body() {
        let supported = "class FlowException(Exception):\n    # inert\n    pass\n";
        let supported_tree = parse(supported);
        let supported_class = first_node_of_kind(&supported_tree, "class_definition");
        assert!(class_field_proof(supported_class, supported, true).is_some());

        let executable = "class FlowException(Exception):\n    register_hook()\n";
        let executable_tree = parse(executable);
        let executable_class = first_node_of_kind(&executable_tree, "class_definition");
        assert!(class_field_proof(executable_class, executable, true).is_none());

        let executable_with_initializer = "class FlowException(Exception):\n    def __init__(self):\n        self.value = 0\n    register_hook()\n";
        let executable_with_initializer_tree = parse(executable_with_initializer);
        let executable_with_initializer_class =
            first_node_of_kind(&executable_with_initializer_tree, "class_definition");
        assert!(
            class_field_proof(
                executable_with_initializer_class,
                executable_with_initializer,
                true
            )
            .is_none()
        );
    }

    #[test]
    fn module_wildcard_import_does_not_prove_exception_builtin() {
        let source = r#"from providers import *

class FlowException(Exception):
    pass

def run():
    flow = FlowException()
    try:
        raise flow
    except FlowException as caught:
        return caught
"#;
        let parts = lower_fixture_named(source, Some("run"));
        let tree = parse(source);
        let clause = first_node_of_kind(&tree, "except_clause");
        let (_, binder) = precise_except_shape(clause).expect("except binder shape");
        let binder_value = value_for_node(&parts, binder, SemanticValueKind::Local);

        assert!(parts.gaps.iter().any(|gap| {
            gap.capability == SemanticCapability::ExceptionalControlFlow
                && gap.kind == SemanticGapKind::Unknown
                && gap.detail.contains("except-clause type evaluation")
        }));
        assert!(
            !parts
                .points
                .iter()
                .flat_map(|point| point.events.iter())
                .any(|event| {
                    matches!(
                        event.effect,
                        SemanticEffect::ValueFlow { target, .. } if target == binder_value
                    )
                })
        );
    }

    #[test]
    fn dynamic_hooks_and_conditional_fields_remain_unproven() {
        let source = "class Holder:\n    def __init__(self):\n        if ready():\n            self.value = 0\n    def __getattribute__(self, name):\n        return object.__getattribute__(self, name)\n";
        let tree = parse(source);
        let class = first_node_of_kind(&tree, "class_definition");
        assert!(class_field_proof(class, source, true).is_none());
    }

    #[test]
    fn closed_list_load_proofs_reject_escapes_and_expanded_initialization() {
        for (source, closed) in [
            ("def run():\n    values = [1]\n    return values[0]\n", true),
            (
                "def run():\n    values = [1]\n    alias = values\n    return alias[0]\n",
                true,
            ),
            (
                "def run(mutate):\n    values = [1]\n    mutate(values)\n    return values[0]\n",
                false,
            ),
            (
                "def run(mutate):\n    values = [1]\n    for n in (0, 1):\n        item = values[0]\n        mutate(values)\n",
                false,
            ),
            (
                "def run():\n    values = [*(1,)]\n    return values[0]\n",
                false,
            ),
            (
                "def run():\n    values = [1, 2]\n    del values[0]\n    return values[0]\n",
                false,
            ),
            ("def run(values):\n    return values[0]\n", false),
        ] {
            let tree = parse(source);
            let callable = first_node_of_kind(&tree, "function_definition");
            let spans = closed_sequence_load_spans(callable, source, || true).unwrap();
            assert_eq!(!spans.is_empty(), closed, "{source}: {spans:?}");
            assert!(closed_sequence_load_spans(callable, source, || false).is_none());
        }
    }

    #[test]
    fn closed_tuple_load_proofs_preserve_immutable_boundaries() {
        for (source, closed) in [
            (
                "def run():\n    values = (1, 2)\n    return values[0]\n",
                true,
            ),
            (
                "def run():\n    values = (1, 2)\n    alias = values\n    return alias[0]\n",
                true,
            ),
            (
                "def run():\n    values = (*(1,), 2)\n    return values[0]\n",
                false,
            ),
            (
                "def run():\n    values = (1, 2)\n    values[0] = 3\n    return values[0]\n",
                false,
            ),
            (
                "def run():\n    values = (1, 2)\n    del values[0]\n    return values[0]\n",
                false,
            ),
            (
                "def run():\n    values = (1, 2)\n    values[0] += 3\n    return values[0]\n",
                false,
            ),
            (
                "def run():\n    values = CustomTuple((1, 2))\n    return values[0]\n",
                false,
            ),
            ("def run(values):\n    return values[0]\n", false),
        ] {
            let tree = parse(source);
            let callable = first_node_of_kind(&tree, "function_definition");
            let spans = closed_sequence_load_spans(callable, source, || true).unwrap();
            assert_eq!(!spans.is_empty(), closed, "{source}: {spans:?}");
        }
    }

    #[test]
    fn tuple_mutation_evaluates_operands_in_order_and_stops_later_targets() {
        let source = "def check():\n    (left(),)[index()] = holder().value = rhs()\n    after()\n";
        let parts = lower_fixture_named(source, Some("check"));
        let mut current = parts
            .points
            .iter()
            .find(|point| {
                point
                    .events
                    .iter()
                    .any(|event| matches!(event.effect, SemanticEffect::Entry))
            })
            .expect("entry")
            .id;
        let mut visited = HashSet::default();
        let mut calls = Vec::new();
        let mut threw = false;
        loop {
            assert!(
                visited.insert(current),
                "straight-line fixture must not cycle"
            );
            let point = &parts.points[current.index()];
            for event in &point.events {
                match event.effect {
                    SemanticEffect::Invoke { call_site } => {
                        let call = &parts.call_sites[call_site.index()];
                        let span = parts.source_mappings[call.source.index()]
                            .locator
                            .anchor()
                            .span();
                        calls.push(&source[span.start_byte() as usize..span.end_byte() as usize]);
                    }
                    SemanticEffect::Throw { .. } => {
                        threw = true;
                        assert!(!point.events.iter().any(|event| matches!(
                            event.effect,
                            SemanticEffect::MemoryStore { .. }
                        )));
                    }
                    _ => {}
                }
            }
            let successors = parts
                .control_edges
                .iter()
                .filter(|edge| edge.source_point == current && edge.kind == ControlEdgeKind::Normal)
                .collect::<Vec<_>>();
            match successors.as_slice() {
                [] => break,
                [edge] => current = edge.target_point,
                _ => panic!("fixture has one normal continuation: {successors:?}"),
            }
        }
        assert!(threw, "the tuple store must abort");
        assert_eq!(calls, ["rhs()", "left()", "index()"]);
    }

    #[test]
    fn unknown_root_does_not_gain_heap_proof() {
        let source = "def run():\n    values = external()\n    sink(values[0])\n";
        let tree = parse(source);
        let callable = first_node_of_kind(&tree, "function_definition");
        let class_names = HashSet::default();
        let fields = HashMap::default();
        let HeapBindingProofs {
            known_lists,
            known_instances,
            ..
        } = heap_binding_proofs(callable, source, &class_names, &fields, || true).unwrap();
        assert!(known_lists.is_empty());
        assert!(known_instances.is_empty());
    }

    #[test]
    fn list_index_proof_accepts_only_bounded_decimal_integers() {
        let cases = [
            ("values[0]", Some(0)),
            ("values[00]", Some(0)),
            ("values[1]", Some(1)),
            ("values[01]", Some(1)),
            ("values['0']", None),
            ("values[1.0]", None),
            ("values[index]", None),
            ("values[-1]", None),
            ("values[0x1]", None),
            ("values[1_0]", None),
            ("values[18446744073709551616]", None),
        ];
        for (source, expected) in cases {
            let tree = parse(source);
            let subscript = first_node_of_kind(&tree, "subscript");
            let index = subscript
                .child_by_field_name("subscript")
                .expect("subscript index");
            assert_eq!(
                is_structural_constant_index(source, index),
                expected,
                "{source}"
            );
        }
    }

    #[test]
    fn raised_value_flows_into_precise_except_binder() {
        let source = r#"class FlowException(Exception):
    pass

def run(source):
    flow = FlowException()
    flow.value = source
    try:
        raise flow
    except FlowException as caught:
        return caught.value
"#;
        let parts = lower_fixture_named(source, Some("run"));
        let tree = parse(source);
        let function = first_node_of_kind(&tree, "function_definition");
        let body = function.child_by_field_name("body").expect("function body");
        let parameter = first_named_child(
            function
                .child_by_field_name("parameters")
                .expect("function parameters"),
        )
        .expect("source parameter");
        let field_assignment = first_assignment_with_left_kind(body, "attribute", None);
        let flow_assignment = first_assignment_with_left_kind(body, "identifier", Some("call"));
        let flow_binding = flow_assignment
            .child_by_field_name("left")
            .expect("flow binding");
        let field = field_assignment
            .child_by_field_name("left")
            .filter(|left| left.kind() == "attribute")
            .expect("field assignment");
        let field_value = field_assignment
            .child_by_field_name("right")
            .expect("field source");
        let raise = first_node_of_kind(&tree, "raise_statement");
        let thrown_expression = first_named_child(raise).expect("raise expression");
        let clause = first_node_of_kind(&tree, "except_clause");
        let (_, binder) = precise_except_shape(clause).expect("precise except shape");
        let catch_body = named_children(clause)
            .into_iter()
            .find(|child| child.kind() == "block")
            .expect("catch body");
        let loaded_field = first_named_child(first_named_child(catch_body).expect("catch return"))
            .expect("caught field load");
        let source_value = value_for_node(
            &parts,
            parameter,
            SemanticValueKind::Parameter {
                ordinal: 0,
                multiplicity: FormalMultiplicity::One,
                name: Some("source".into()),
                passing_mode: FormalParameterPassingMode::PositionalOrNamed,
            },
        );
        let flow_value = value_for_node(&parts, flow_binding, SemanticValueKind::Local);
        let field_value_value = value_for_node(&parts, field_value, SemanticValueKind::Temporary);
        let field_object = field.child_by_field_name("object").expect("field object");
        let field_object_value = value_for_node(&parts, field_object, SemanticValueKind::Temporary);
        let throw_object_value =
            value_for_node(&parts, thrown_expression, SemanticValueKind::Temporary);
        let binder_value = value_for_node(&parts, binder, SemanticValueKind::Local);
        let loaded_value = value_for_node(&parts, loaded_field, SemanticValueKind::Temporary);
        let carrier = parts
            .points
            .iter()
            .flat_map(|point| point.events.iter())
            .find_map(|event| match &event.effect {
                SemanticEffect::Throw { value: Some(value) } => Some(*value),
                _ => None,
            })
            .expect("raise publishes an exception carrier");
        let flows = parts
            .points
            .iter()
            .flat_map(|point| point.events.iter())
            .filter_map(|event| match &event.effect {
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Local,
                    source,
                    target,
                } => Some((*source, *target)),
                _ => None,
            })
            .collect::<Vec<_>>();

        assert!(flow_reaches(&parts, source_value, field_value_value));
        assert!(flow_reaches(&parts, flow_value, field_object_value));
        assert!(flow_reaches(&parts, flow_value, throw_object_value));
        assert!(flows.contains(&(throw_object_value, carrier)));
        assert!(flows.contains(&(carrier, binder_value)));
        let load_base = parts
            .points
            .iter()
            .flat_map(|point| point.events.iter())
            .find_map(|event| match &event.effect {
                SemanticEffect::MemoryLoad {
                    kind: MemoryAccessKind::Field,
                    location,
                    result,
                } if *result == loaded_value => {
                    match &parts.memory_locations[location.index()].kind {
                        MemoryLocationKind::Field { base, .. } => Some(*base),
                        _ => None,
                    }
                }
                _ => None,
            })
            .expect("caught field load base");
        assert!(flow_reaches(&parts, binder_value, load_base));
        assert!(
            !parts
                .gaps
                .iter()
                .any(|gap| gap.capability == SemanticCapability::FieldMemory)
        );
        assert!(!parts.gaps.iter().any(|gap| {
            gap.capability == SemanticCapability::ExceptionalControlFlow
                && gap.detail.contains("except-clause type evaluation")
        }));
    }

    #[test]
    fn unrelated_local_does_not_flow_into_precise_except_binder() {
        let source = r#"class FlowException(Exception):
    pass

def run(source):
    flow = FlowException()
    flow.value = "clean"
    unrelated = source
    try:
        raise flow
    except FlowException as caught:
        return caught.value
"#;
        let parts = lower_fixture_named(source, Some("run"));
        let tree = parse(source);
        let function = first_node_of_kind(&tree, "function_definition");
        let body = function.child_by_field_name("body").expect("function body");
        let parameter = first_named_child(
            function
                .child_by_field_name("parameters")
                .expect("function parameters"),
        )
        .expect("source parameter");
        let unrelated_assignment =
            first_assignment_with_left_kind(body, "identifier", Some("identifier"));
        let unrelated_binding = unrelated_assignment
            .child_by_field_name("left")
            .expect("unrelated binding");
        let field_assignment = first_assignment_with_left_kind(body, "attribute", None);
        let clean_expression = field_assignment
            .child_by_field_name("right")
            .expect("clean field value");
        let clause = first_node_of_kind(&tree, "except_clause");
        let (_, binder) = precise_except_shape(clause).expect("precise except shape");
        let source_value = value_for_node(
            &parts,
            parameter,
            SemanticValueKind::Parameter {
                ordinal: 0,
                multiplicity: FormalMultiplicity::One,
                name: Some("source".into()),
                passing_mode: FormalParameterPassingMode::PositionalOrNamed,
            },
        );
        let unrelated_value = value_for_node(&parts, unrelated_binding, SemanticValueKind::Local);
        let clean_value = value_for_node(&parts, clean_expression, SemanticValueKind::Constant);
        let binder_value = value_for_node(&parts, binder, SemanticValueKind::Local);

        assert!(flow_reaches(&parts, source_value, unrelated_value));
        assert!(!flow_reaches(&parts, source_value, binder_value));
        assert!(!flow_reaches(&parts, source_value, clean_value));
        assert!(
            !parts
                .gaps
                .iter()
                .any(|gap| gap.capability == SemanticCapability::FieldMemory)
        );
        assert!(!parts.gaps.iter().any(|gap| {
            gap.capability == SemanticCapability::ExceptionalControlFlow
                && gap.detail.contains("except-clause type evaluation")
        }));
    }

    #[test]
    fn mismatched_except_handler_remains_incomplete() {
        let source = r#"class FlowException(Exception):
    pass
class OtherException(Exception):
    pass

def run(source):
    flow = FlowException()
    flow.value = source
    try:
        raise flow
    except OtherException as caught:
        return caught.value
"#;
        let parts = lower_fixture_named(source, Some("run"));
        let tree = parse(source);
        let clause = first_node_of_kind(&tree, "except_clause");
        let (_, binder) = precise_except_shape(clause).expect("mismatched handler shape");
        let binder_value = value_for_node(&parts, binder, SemanticValueKind::Local);

        assert!(parts.gaps.iter().any(|gap| {
            gap.capability == SemanticCapability::ExceptionalControlFlow
                && gap.kind == SemanticGapKind::Unknown
                && gap.detail.contains("except-clause type evaluation")
        }));
        assert!(
            !parts
                .points
                .iter()
                .flat_map(|point| point.events.iter())
                .any(|event| {
                    matches!(
                        event.effect,
                        SemanticEffect::ValueFlow { target, .. } if target == binder_value
                    )
                })
        );
    }

    #[test]
    fn local_source_sink_exception_field_flow_is_complete() {
        let source = r#"class FlowException(Exception):
    pass

def input_value():
    return "tainted"

def consume(value):
    pass

def run():
    try:
        flow = FlowException()
        flow.value = input_value()
        raise flow
    except FlowException as caught:
        consume(caught.value)
"#;
        let parts = lower_fixture_named(source, Some("run"));
        let tree = parse(source);
        let try_statement = first_node_of_kind(&tree, "try_statement");
        let try_body = try_statement.child_by_field_name("body").expect("try body");
        let field_assignment = first_assignment_with_left_kind(try_body, "attribute", None);
        let source_expression = field_assignment
            .child_by_field_name("right")
            .expect("source call");
        let flow_assignment = first_assignment_with_left_kind(try_body, "identifier", Some("call"));
        let flow_binding = flow_assignment
            .child_by_field_name("left")
            .expect("flow binding");
        let raise = first_node_of_kind(&tree, "raise_statement");
        let thrown_expression = first_named_child(raise).expect("raised flow");
        let clause = first_node_of_kind(&tree, "except_clause");
        let (_, binder) = precise_except_shape(clause).expect("precise except shape");
        let catch_body = named_children(clause)
            .into_iter()
            .find(|child| child.kind() == "block")
            .expect("catch body");
        let sink_call = first_node_of_kind_in(catch_body, "call");
        let sink_argument = call_arguments(sink_call)
            .first()
            .copied()
            .map(python_argument_value_node)
            .expect("sink argument");
        let source_value = value_for_node(&parts, source_expression, SemanticValueKind::Temporary);
        let flow_value = value_for_node(&parts, flow_binding, SemanticValueKind::Local);
        let thrown_value = value_for_node(&parts, thrown_expression, SemanticValueKind::Temporary);
        let binder_value = value_for_node(&parts, binder, SemanticValueKind::Local);
        let sink_value = value_for_node(&parts, sink_argument, SemanticValueKind::Temporary);
        let carrier = parts
            .points
            .iter()
            .flat_map(|point| point.events.iter())
            .find_map(|event| match &event.effect {
                SemanticEffect::Throw { value: Some(value) } => Some(*value),
                _ => None,
            })
            .expect("exception carrier");
        let (store_location, store_value) = parts
            .points
            .iter()
            .flat_map(|point| point.events.iter())
            .find_map(|event| match &event.effect {
                SemanticEffect::MemoryStore {
                    kind: MemoryAccessKind::Field,
                    location,
                    value,
                    ..
                } if *value == source_value => Some((*location, *value)),
                _ => None,
            })
            .expect("source field store");
        let (load_location, load_result) = parts
            .points
            .iter()
            .flat_map(|point| point.events.iter())
            .find_map(|event| match &event.effect {
                SemanticEffect::MemoryLoad {
                    kind: MemoryAccessKind::Field,
                    location,
                    result,
                    ..
                } if *result == sink_value => Some((*location, *result)),
                _ => None,
            })
            .expect("caught field load");

        let (store_base, store_member) = match &parts.memory_locations[store_location.index()].kind
        {
            MemoryLocationKind::Field { base, member } => (*base, member),
            _ => panic!("source store is not a field access"),
        };
        let (load_base, load_member) = match &parts.memory_locations[load_location.index()].kind {
            MemoryLocationKind::Field { base, member } => (*base, member),
            _ => panic!("caught load is not a field access"),
        };

        assert_eq!(store_value, source_value);
        assert_eq!(load_result, sink_value);
        assert_eq!(store_member, load_member);
        assert!(flow_reaches(&parts, flow_value, store_base));
        assert!(flow_reaches(&parts, binder_value, load_base));
        assert!(flow_reaches(&parts, flow_value, thrown_value));
        assert!(flow_reaches(&parts, thrown_value, carrier));
        assert!(flow_reaches(&parts, carrier, binder_value));
        assert!(
            !parts
                .gaps
                .iter()
                .any(|gap| gap.capability == SemanticCapability::ExceptionalControlFlow)
        );
        assert!(
            !parts
                .gaps
                .iter()
                .any(|gap| gap.capability == SemanticCapability::FieldMemory)
        );
    }

    #[test]
    fn multiple_except_handlers_remain_incomplete() {
        let source = "def run(value):\n    try:\n        raise value\n    except ValueError as caught:\n        return caught\n    except TypeError:\n        return value\n";
        let parts = lower_fixture(source);

        assert!(parts.gaps.iter().any(|gap| {
            gap.capability == SemanticCapability::ExceptionalControlFlow
                && gap.kind == SemanticGapKind::Unknown
                && gap.detail.contains("except-clause type evaluation")
        }));
    }
}
