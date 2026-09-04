//! Go lowering into the language-neutral executable-semantics IR.
//!
//! This module deliberately interprets tree-sitter nodes and fields directly.
//! Graph construction, abrupt-completion routing, cleanup specialization, and
//! physical adjacency storage remain owned by the shared semantic substrate.

use tree_sitter::Node;

use brokk_bifrost_go::declarations::is_predeclared_go_type;
use brokk_bifrost_go::graph::ast::{clause_statement_list, is_clause};

use super::declarations::collect_go_import_infos;

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
use crate::analyzer::{GoAnalyzer, Language, ProjectFile};
use crate::hash::{HashMap, HashSet};

const ADAPTER_VERSION: &[u8] = b"go-value-semantics-v45";

impl_program_semantics_provider!(GoAnalyzer, GoSemanticLowerer);

struct GoSemanticLowerer;

impl ProgramSemanticsLowerer for GoSemanticLowerer {
    fn identity(&self) -> SemanticAdapterIdentity {
        SemanticAdapterIdentity {
            adapter: AdapterSemanticsVersion::hash_bytes("go", ADAPTER_VERSION)
                .expect("adapter name is non-empty"),
            configuration: ConfigurationFingerprint::hash_bytes(
                b"go-intrafile-execution-defaults-v1",
            ),
            dependencies: DependencyFingerprint::hash_bytes(b"no-intrafile-dependencies"),
        }
    }

    fn capabilities(&self) -> SemanticCapabilities {
        go_capabilities()
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
            package_shadowing,
            package_values,
            package_value_locators,
            direct_struct_fields,
            named_type_definitions,
            method_inventory,
            initial_work,
        ) = match enumerate_procedures(file, prepared, budget, cancellation)? {
            ProcedureEnumeration::Complete {
                value,
                initial_work,
                ..
            } => (
                value.specs,
                value.package_shadowing,
                value.package_values,
                value.package_value_locators,
                value.direct_struct_fields,
                value.named_type_definitions,
                value.method_inventory,
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

        let import_bindings = go_import_bindings(prepared.tree().root_node(), prepared.source());
        let package_functions = specs
            .iter()
            .filter(|spec| {
                spec.lexical_parent.is_none() && spec.callable.kind() == "function_declaration"
            })
            .filter_map(|spec| {
                spec.callable
                    .child_by_field_name("name")
                    .and_then(|name| nonempty_node_text(prepared.source(), name))
                    .map(Box::<str>::from)
            })
            .collect::<HashSet<_>>();
        let procedure_targets = specs
            .iter()
            .map(|spec| {
                (
                    spec.callable.id(),
                    GoProcedureTarget {
                        id: spec.id,
                        captures: spec
                            .captures
                            .iter()
                            .map(|capture| GoTargetCapture {
                                name: capture.name.clone(),
                                binding: capture.binding,
                                storage: capture.storage,
                            })
                            .collect(),
                        omitted_capture_names: spec.omitted_capture_names.clone(),
                    },
                )
            })
            .collect::<HashMap<_, _>>();
        let struct_field_anchors = go_struct_field_anchors(prepared);

        lower_procedure_batch(
            &specs,
            initial_work,
            budget,
            cancellation,
            |spec, staged_budget, cancellation| {
                lower_procedure(
                    prepared,
                    &struct_field_anchors,
                    spec,
                    package_shadowing,
                    &package_values,
                    &package_value_locators,
                    &direct_struct_fields,
                    &named_type_definitions,
                    &import_bindings,
                    &package_functions,
                    &method_inventory,
                    &procedure_targets,
                    staged_budget,
                    cancellation,
                )
            },
        )
    }
}

fn go_capabilities() -> SemanticCapabilities {
    let mut builder = SemanticCapabilities::builder();
    for capability in [
        SemanticCapability::Procedures,
        SemanticCapability::EntryBoundary,
        SemanticCapability::NormalExitBoundary,
        SemanticCapability::ExceptionalExitBoundary,
        SemanticCapability::BasicBlocks,
        SemanticCapability::ProgramPoints,
        SemanticCapability::NormalCallContinuation,
        SemanticCapability::ExceptionalCallContinuation,
        SemanticCapability::SwitchFacts,
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
        SemanticCapability::ReturnFlow,
        // Partial: a struct-field or element store and load is lowered into a
        // real memory row whenever the target shape is a single selector or a
        // single index over a value this procedure can name. A store through
        // a pointer dereference, a multi-target assignment, and a dynamic
        // index still publish their own gaps instead.
        SemanticCapability::FieldMemory,
        SemanticCapability::IndexMemory,
        SemanticCapability::StaticMemory,
        SemanticCapability::Captures,
        SemanticCapability::DeferredExecution,
        SemanticCapability::ConcurrentSpawn,
        SemanticCapability::Synchronization,
        SemanticCapability::NonLocalControl,
        // Every decision the Go lowerer represents publishes a guard row.
        // Constants, nil comparisons, and constant equality are normalized;
        // other structured conditions remain explicit opaque facts.
        SemanticCapability::GuardFacts,
    ] {
        builder = builder.partial(capability);
    }
    builder.build()
}

/// Which Go predeclared identifiers a program rebinds.
///
/// These are ordinary predeclared identifiers rather than keywords, so a
/// program may give any of them another meaning. Lowering may read the builtin
/// meaning only where it has not.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PredeclaredShadowing {
    new: bool,
    make: bool,
    append: bool,
    panic: bool,
    close: bool,
    boolean_true: bool,
    boolean_false: bool,
    nil: bool,
    iota: bool,
}

impl PredeclaredShadowing {
    fn observe(&mut self, name: &str) {
        match name {
            "new" => self.new = true,
            "make" => self.make = true,
            "append" => self.append = true,
            "panic" => self.panic = true,
            "close" => self.close = true,
            "true" => self.boolean_true = true,
            "false" => self.boolean_false = true,
            "nil" => self.nil = true,
            "iota" => self.iota = true,
            _ => {}
        }
    }

    fn merged(self, other: Self) -> Self {
        Self {
            new: self.new || other.new,
            make: self.make || other.make,
            append: self.append || other.append,
            panic: self.panic || other.panic,
            close: self.close || other.close,
            boolean_true: self.boolean_true || other.boolean_true,
            boolean_false: self.boolean_false || other.boolean_false,
            nil: self.nil || other.nil,
            iota: self.iota || other.iota,
        }
    }

    fn shadows(self, name: &str) -> bool {
        match name {
            "new" => self.new,
            "make" => self.make,
            "append" => self.append,
            "panic" => self.panic,
            "close" => self.close,
            "true" => self.boolean_true,
            "false" => self.boolean_false,
            "nil" => self.nil,
            "iota" => self.iota,
            _ => false,
        }
    }
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
    result_shadowing: PredeclaredShadowing,
    captures: Box<[GoCaptureSpec<'tree>]>,
    shared_bindings: Box<[GoSharedBindingSpec]>,
    omitted_capture_names: Box<[Box<str>]>,
    call_exposure_origins: Box<[GoCallExposureOrigin]>,
}

#[derive(Clone)]
struct GoCaptureSpec<'tree> {
    name: Box<str>,
    reference: Node<'tree>,
    binding: GoResolvedBinding,
    storage: GoCaptureStorage,
    value_storage: Option<GoStorageKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GoCaptureStorage {
    Value,
    MutableCell,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GoSharedBindingSpec {
    name: Box<str>,
    binding: GoResolvedBinding,
}

#[derive(Clone)]
struct GoProcedureTarget {
    id: ProcedureId,
    captures: Box<[GoTargetCapture]>,
    omitted_capture_names: Box<[Box<str>]>,
}

#[derive(Debug, Clone)]
struct GoTargetCapture {
    name: Box<str>,
    binding: GoResolvedBinding,
    storage: GoCaptureStorage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GoCallExposureOrigin {
    name: Box<str>,
    binding: GoResolvedBinding,
}

struct GoProcedureInventory<'tree> {
    specs: Vec<ProcedureSpec<'tree>>,
    package_shadowing: PredeclaredShadowing,
    package_values: HashSet<Box<str>>,
    package_value_locators: HashMap<Box<str>, SemanticLocator>,
    direct_struct_fields: DirectStructFields,
    named_type_definitions: GoNamedTypeDefinitions<'tree>,
    method_inventory: GoMethodInventory,
}

#[derive(Debug, Clone, Copy)]
struct GoNamedTypeDefinition<'tree> {
    declaration: usize,
    underlying: Node<'tree>,
    visible_from: usize,
    scope_start: usize,
    scope_end: usize,
}

type GoNamedTypeDefinitions<'tree> = HashMap<Box<str>, Vec<GoNamedTypeDefinition<'tree>>>;
type DirectStructFields = HashMap<usize, HashSet<Box<str>>>;
type GoMethodInventory = HashMap<(usize, Box<str>), bool>;

type ProcedureEnumeration<'tree> = ProcedureInventoryOutcome<GoProcedureInventory<'tree>>;

enum GoInventoryPrepassStop {
    Budget(ProcedureInventoryStop),
    Cancelled,
}

fn charge_go_inventory_prepass(
    inventory: &mut ProcedureInventoryBuilder<'_>,
    cancellation: &CancellationToken,
) -> Result<(), GoInventoryPrepassStop> {
    if cancellation.is_cancelled() {
        return Err(GoInventoryPrepassStop::Cancelled);
    }
    inventory
        .charge_traversal_entry()
        .map_err(GoInventoryPrepassStop::Budget)
}

struct ProcedureEnumerationFrame<'tree> {
    node: Node<'tree>,
    lexical_parent: Option<ProcedureId>,
    declaration_path: usize,
    package_binding_context: bool,
    file_type_context: bool,
    direct_struct_owner: Option<Node<'tree>>,
    named_result_owner: Option<ProcedureId>,
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
        ProcedureInventoryBuilder::new(file, prepared.dialect(), root, "go-source", budget)?;
    let mut specs: Vec<ProcedureSpec<'tree>> = Vec::new();
    let mut package_shadowing = PredeclaredShadowing::default();
    let mut package_values = HashSet::default();
    let mut package_value_locators = HashMap::default();
    let mut direct_struct_fields = DirectStructFields::default();
    let mut named_type_definitions = HashMap::default();
    let mut stack = vec![ProcedureEnumerationFrame {
        node: root,
        lexical_parent: None,
        declaration_path: inventory.root_path(),
        package_binding_context: false,
        file_type_context: false,
        direct_struct_owner: None,
        named_result_owner: None,
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

        if frame.package_binding_context
            && let Some(name) = go_package_binding_name(frame.node, prepared.source())
        {
            package_shadowing.observe(name);
        }
        if matches!(frame.node.kind(), "type_spec" | "type_alias")
            && let Some(name_node) = frame.node.child_by_field_name("name")
            && let Some(name) = nonempty_node_text(prepared.source(), name_node)
            && let Some(underlying) = frame.node.child_by_field_name("type")
        {
            let local_scope = go_local_scope(frame.node);
            let (scope_start, scope_end) =
                local_scope.unwrap_or_else(|| (root.start_byte(), root.end_byte()));
            named_type_definitions
                .entry(name.into())
                .or_insert_with(Vec::new)
                .push(GoNamedTypeDefinition {
                    declaration: frame.node.id(),
                    underlying,
                    visible_from: local_scope
                        .map(|_| name_node.start_byte())
                        .unwrap_or(root.start_byte()),
                    scope_start,
                    scope_end,
                });
            if underlying.kind() == "struct_type" {
                record_direct_struct_fields(
                    &mut direct_struct_fields,
                    frame.node.id(),
                    underlying,
                    prepared.source(),
                );
            }
        }
        let prescanned_children = if matches!(frame.node.kind(), "var_spec" | "const_spec") {
            let mut children = Vec::new();
            for child_index in 0..frame.node.child_count() {
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
                if frame.node.field_name_for_child(child_index as u32) == Some("name") {
                    if frame.package_binding_context
                        && let Some(name) = node_text(prepared.source(), child)
                    {
                        package_shadowing.observe(name);
                        if name != "_" {
                            package_values.insert(name.into());
                            if frame.node.kind() == "var_spec" {
                                let anchor = source_anchor(child, 0)
                                    .map_err(SemanticProviderError::invalid_identity)?;
                                package_value_locators.insert(
                                    name.into(),
                                    inventory.locator(
                                        frame.declaration_path,
                                        SemanticRole::MemoryLocation,
                                        anchor,
                                    )?,
                                );
                            }
                        }
                    }
                } else if child.kind() != "comment" {
                    children.push(child);
                }
            }
            Some(children)
        } else {
            None
        };
        if let Some(owner) = frame.named_result_owner
            && is_go_binding_reference_kind(frame.node.kind())
            && let Some(name) = node_text(prepared.source(), frame.node)
            && let Some(spec) = specs.get_mut(owner.index())
        {
            spec.result_shadowing.observe(name);
        }
        let child_path = frame.declaration_path;

        let mut callable_body_scope = None;
        let mut callable_result_scope = None;
        if let Some((kind, segment_kind, body, properties)) =
            callable_shape(frame.node, frame.lexical_parent)
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
                result_shadowing: PredeclaredShadowing::default(),
                captures: Box::new([]),
                shared_bindings: Box::new([]),
                omitted_capture_names: Box::new([]),
                call_exposure_origins: Box::new([]),
            });
            callable_body_scope = Some((body.id(), identity.id, identity.declaration_path));
            callable_result_scope = frame
                .node
                .child_by_field_name("result")
                .filter(|result| result.kind() == "parameter_list")
                .map(|result| (result.id(), identity.id));
        }

        let children = if let Some(children) = prescanned_children {
            children
                .into_iter()
                .map(|child| (child, false, true))
                .collect::<Vec<_>>()
        } else {
            let mut children = Vec::new();
            for child_index in 0..frame.node.child_count() {
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
                let package_binding_context = match frame.node.kind() {
                    "source_file" => true,
                    "import_declaration" | "import_spec_list" | "type_declaration"
                    | "var_declaration" | "const_declaration" => frame.package_binding_context,
                    _ => false,
                };
                children.push((child, package_binding_context, true));
            }
            children
        };
        for (child, package_binding_context, entry_precharged) in children.into_iter().rev() {
            let (lexical_parent, declaration_path) = callable_body_scope
                .filter(|(body_id, _, _)| *body_id == child.id())
                .map(|(_, procedure, path)| (Some(procedure), path))
                .unwrap_or((frame.lexical_parent, child_path));
            let named_result_owner = callable_result_scope
                .filter(|(result_id, _)| *result_id == child.id())
                .map(|(_, procedure)| procedure)
                .or(frame.named_result_owner);
            let file_type_context = match frame.node.kind() {
                "source_file" => child.kind() == "type_declaration",
                "type_declaration" if frame.file_type_context => {
                    matches!(child.kind(), "type_spec" | "type_alias" | "type_spec_list")
                }
                "type_spec_list" if frame.file_type_context => {
                    matches!(child.kind(), "type_spec" | "type_alias")
                }
                _ => false,
            };
            let direct_struct_owner = match frame.node.kind() {
                "type_spec"
                    if frame.file_type_context
                        && child.kind() == "struct_type"
                        && field_matches(frame.node, "type", child) =>
                {
                    frame.node.child_by_field_name("name")
                }
                "struct_type"
                    if frame.direct_struct_owner.is_some()
                        && child.kind() == "field_declaration_list" =>
                {
                    frame.direct_struct_owner
                }
                "field_declaration_list"
                    if frame.direct_struct_owner.is_some()
                        && child.kind() == "field_declaration" =>
                {
                    frame.direct_struct_owner
                }
                _ => None,
            };
            stack.push(ProcedureEnumerationFrame {
                node: child,
                lexical_parent,
                declaration_path,
                package_binding_context,
                file_type_context,
                direct_struct_owner,
                named_result_owner,
                entry_precharged,
            });
        }
    }

    let method_inventory = match go_same_file_method_inventory(
        &specs,
        &named_type_definitions,
        root,
        prepared.source(),
        &mut inventory,
        cancellation,
    ) {
        Ok(methods) => methods,
        Err(GoInventoryPrepassStop::Budget(stop)) => return Ok(stop.into_outcome()),
        Err(GoInventoryPrepassStop::Cancelled) => return Ok(inventory.cancelled()),
    };
    if let Err(stop) = populate_capture_specs(
        &mut specs,
        prepared.source(),
        &direct_struct_fields,
        &named_type_definitions,
        &method_inventory,
        &mut inventory,
        cancellation,
    ) {
        return Ok(match stop {
            GoInventoryPrepassStop::Budget(stop) => stop.into_outcome(),
            GoInventoryPrepassStop::Cancelled => inventory.cancelled(),
        });
    }
    Ok(inventory.complete(GoProcedureInventory {
        specs,
        package_shadowing,
        package_values,
        package_value_locators,
        direct_struct_fields,
        named_type_definitions,
        method_inventory,
    }))
}

fn record_direct_struct_fields(
    inventory: &mut DirectStructFields,
    declaration: usize,
    structure: Node<'_>,
    source: &str,
) {
    let mut names = Vec::new();
    for list in named_children(structure)
        .into_iter()
        .filter(|child| child.kind() == "field_declaration_list")
    {
        for field in named_children(list)
            .into_iter()
            .filter(|child| child.kind() == "field_declaration")
        {
            let mut field_names = named_children(field)
                .into_iter()
                .filter(|child| child.kind() == "field_identifier")
                .filter_map(|child| nonempty_node_text(source, child))
                .filter(|name| *name != "_")
                .map(Box::<str>::from)
                .collect::<Vec<_>>();
            if field_names.is_empty()
                && let Some((name, _)) =
                    super::declarations::go_embedded_struct_field(field, source)
                && name != "_"
            {
                field_names.push(name.into_boxed_str());
            }
            names.extend(field_names);
        }
    }
    if !names.is_empty() {
        inventory.entry(declaration).or_default().extend(names);
    }
}

fn go_same_file_method_inventory(
    specs: &[ProcedureSpec<'_>],
    named_types: &GoNamedTypeDefinitions<'_>,
    root: Node<'_>,
    source: &str,
    inventory: &mut ProcedureInventoryBuilder<'_>,
    cancellation: &CancellationToken,
) -> Result<GoMethodInventory, GoInventoryPrepassStop> {
    let mut methods = GoMethodInventory::default();
    for spec in specs {
        charge_go_inventory_prepass(inventory, cancellation)?;
        if spec.callable.kind() != "method_declaration" {
            continue;
        }
        let Some((receiver, pointer_receiver, _)) =
            super::artifact::method_receiver(spec.callable, source)
        else {
            continue;
        };
        let Some(definition) = named_types.get(receiver.as_str()).and_then(|definitions| {
            visible_go_binding(definitions, root.start_byte(), |definition| {
                (
                    definition.visible_from,
                    definition.scope_start,
                    definition.scope_end,
                )
            })
        }) else {
            continue;
        };
        let Some(name) = spec
            .callable
            .child_by_field_name("name")
            .and_then(|name| nonempty_node_text(source, name))
        else {
            continue;
        };
        let previous = methods.insert((definition.declaration, name.into()), pointer_receiver);
        debug_assert!(
            previous.is_none_or(|previous| previous == pointer_receiver),
            "one Go receiver type cannot declare the same method twice"
        );
    }
    Ok(methods)
}

fn callable_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    node.child_by_field_name("name")
        .and_then(|name| nonempty_node_text(source, name))
        .map(Box::<str>::from)
        .or_else(|| enclosing_binding_name(source, node))
}

/// Resolve every lexical capture to its exact declaring binding. Stable
/// short-declared locals may remain value snapshots; all other captures relay
/// one shared cell through every intervening closure.
fn populate_capture_specs<'tree>(
    specs: &mut [ProcedureSpec<'tree>],
    source: &str,
    direct_struct_fields: &DirectStructFields,
    named_type_definitions: &GoNamedTypeDefinitions<'tree>,
    method_inventory: &GoMethodInventory,
    inventory: &mut ProcedureInventoryBuilder<'_>,
    cancellation: &CancellationToken,
) -> Result<(), GoInventoryPrepassStop> {
    charge_go_inventory_prepass(inventory, cancellation)?;
    let mut lexical_bindings = Vec::with_capacity(specs.len());
    for spec in specs.iter() {
        lexical_bindings.push(go_callable_lexical_bindings(
            spec,
            source,
            named_type_definitions,
            inventory,
            cancellation,
        )?);
    }
    let (call_exposure_origins, capture_mutable_bindings) = collect_call_exposure_origins(
        specs,
        &lexical_bindings,
        source,
        direct_struct_fields,
        method_inventory,
        inventory,
        cancellation,
    )?;
    let mut captures = vec![Vec::<GoCaptureSpec<'tree>>::new(); specs.len()];
    let omitted_capture_names = vec![Vec::<Box<str>>::new(); specs.len()];
    for child in specs.iter() {
        charge_go_inventory_prepass(inventory, cancellation)?;
        let Some(parent_id) = child.lexical_parent else {
            continue;
        };
        let Some(parent) = specs.get(parent_id.index()) else {
            continue;
        };
        if !go_callable_creation_is_lowered(child.callable, parent.body, inventory, cancellation)? {
            continue;
        }
        let child_bindings = &lexical_bindings[child.id.index()];
        let mut references: HashMap<Box<str>, Node<'tree>> = HashMap::default();
        try_walk_named_tree_preorder(child.body, true, |node| {
            charge_go_inventory_prepass(inventory, cancellation)?;
            if node != child.body && is_go_callable_kind(node.kind()) {
                return Ok(WalkControl::SkipChildren);
            }
            if is_go_binding_reference_kind(node.kind())
                && let Some(name) = node_text(source, node)
                && name != "_"
                && !child_bindings.declaration_targets.contains_key(&node.id())
                && child_bindings.binding_at(name, node.start_byte()).is_none()
            {
                references
                    .entry(name.into())
                    .and_modify(|first| {
                        if node.start_byte() < first.start_byte() {
                            *first = node;
                        }
                    })
                    .or_insert(node);
            }
            Ok(WalkControl::Continue)
        })?;
        let mut captured = Vec::new();
        for (name, reference) in references {
            if let Some(binding) = resolve_go_binding(
                specs,
                &lexical_bindings,
                parent.id.index(),
                &name,
                child.callable.start_byte(),
                inventory,
                cancellation,
            )? {
                let immutable = immutable_captured_binding(
                    &lexical_bindings,
                    binding,
                    &capture_mutable_bindings,
                );
                // Only a binding resolved through an enclosing callable is a
                // capture. Package imports and package-level declarations are
                // intentionally absent so they remain available to their own
                // structured resolution paths inside the child.
                captured.push(GoCaptureSpec {
                    name,
                    reference,
                    binding,
                    storage: if immutable {
                        GoCaptureStorage::Value
                    } else {
                        GoCaptureStorage::MutableCell
                    },
                    value_storage: lexical_bindings[resolved_binding_procedure(binding).index()]
                        .storage_kind(binding),
                });
            }
        }
        charge_go_inventory_prepass(inventory, cancellation)?;
        captures[child.id.index()] = captured;
    }

    // A closure can refer directly to a grandparent binding. Closure
    // conversion still has to carry that binding through each intermediate
    // environment, even when the intermediate body never spells its name.
    for child_index in 0..specs.len() {
        let direct = captures[child_index].clone();
        for capture in direct {
            let owner = resolved_binding_procedure(capture.binding);
            let mut relay = specs[child_index].lexical_parent;
            while let Some(relay_id) = relay {
                if relay_id == owner {
                    break;
                }
                charge_go_inventory_prepass(inventory, cancellation)?;
                if !captures[relay_id.index()]
                    .iter()
                    .any(|existing| existing.binding == capture.binding)
                {
                    captures[relay_id.index()].push(capture.clone());
                }
                relay = specs[relay_id.index()].lexical_parent;
            }
            debug_assert_eq!(
                relay,
                Some(owner),
                "a resolved capture binding must be in the lexical ancestor chain"
            );
        }
    }

    let mut shared_bindings = vec![Vec::<GoSharedBindingSpec>::new(); specs.len()];
    for captured in &mut captures {
        captured.sort_by(|left, right| {
            resolved_binding_sort_key(left.binding)
                .cmp(&resolved_binding_sort_key(right.binding))
                .then_with(|| left.name.cmp(&right.name))
        });
        captured.dedup_by_key(|capture| capture.binding);
        for capture in captured.iter() {
            if capture.storage == GoCaptureStorage::MutableCell {
                shared_bindings[resolved_binding_procedure(capture.binding).index()].push(
                    GoSharedBindingSpec {
                        name: capture.name.clone(),
                        binding: capture.binding,
                    },
                );
            }
        }
    }
    for bindings in &mut shared_bindings {
        bindings.sort_by_key(|binding| resolved_binding_sort_key(binding.binding));
        bindings.dedup_by_key(|binding| binding.binding);
    }
    for ((((spec, captured), shared), omitted), exposures) in specs
        .iter_mut()
        .zip(captures)
        .zip(shared_bindings)
        .zip(omitted_capture_names)
        .zip(call_exposure_origins)
    {
        charge_go_inventory_prepass(inventory, cancellation)?;
        spec.captures = captured.into_boxed_slice();
        spec.shared_bindings = shared.into_boxed_slice();
        spec.omitted_capture_names = omitted.into_boxed_slice();
        spec.call_exposure_origins = exposures.into_boxed_slice();
    }
    Ok(())
}

fn collect_call_exposure_origins(
    specs: &[ProcedureSpec<'_>],
    lexical_bindings: &[GoCallableLexicalBindings],
    source: &str,
    direct_struct_fields: &DirectStructFields,
    method_inventory: &GoMethodInventory,
    inventory: &mut ProcedureInventoryBuilder<'_>,
    cancellation: &CancellationToken,
) -> Result<(Vec<Vec<GoCallExposureOrigin>>, HashSet<GoResolvedBinding>), GoInventoryPrepassStop> {
    let mut by_owner = (0..specs.len())
        .map(|_| HashSet::<(Box<str>, GoResolvedBinding)>::default())
        .collect::<Vec<_>>();
    let mut capture_mutable_bindings = HashSet::default();
    for (procedure_index, spec) in specs.iter().enumerate() {
        try_walk_named_tree_preorder(spec.body, true, |node| {
            charge_go_inventory_prepass(inventory, cancellation)?;
            if node != spec.body && is_go_callable_kind(node.kind()) {
                return Ok(WalkControl::SkipChildren);
            }

            for target in go_mutation_targets(node) {
                let target = transparent_parenthesized_expression(target);
                if !is_go_binding_reference_kind(target.kind())
                    && !matches!(target.kind(), "selector_expression" | "index_expression")
                {
                    continue;
                }
                let Some(root) = go_place_root_identifier(target) else {
                    continue;
                };
                let Some(name) = node_text(source, root).filter(|name| *name != "_") else {
                    continue;
                };
                let resolved = if is_go_binding_reference_kind(target.kind())
                    && matches!(node.kind(), "short_var_declaration" | "range_clause")
                    && direct_child_kind(node, ":=")
                {
                    lexical_bindings[procedure_index]
                        .declaration_targets
                        .get(&target.id())
                        .copied()
                } else {
                    resolve_go_binding(
                        specs,
                        lexical_bindings,
                        procedure_index,
                        name,
                        root.start_byte(),
                        inventory,
                        cancellation,
                    )?
                };
                if let Some(binding) = resolved {
                    let declares_binding = is_go_binding_reference_kind(target.kind())
                        && matches!(
                            binding,
                            GoResolvedBinding::Local(identity)
                                if identity.declaration == target.id()
                        );
                    let mutates_only_backing_store = target.kind() == "index_expression"
                        && matches!(
                            lexical_bindings[resolved_binding_procedure(binding).index()]
                                .storage_kind(binding),
                            Some(GoStorageKind::Slice | GoStorageKind::Map)
                        );
                    if !declares_binding && !mutates_only_backing_store {
                        // An exact value capture is sound only while the
                        // original variable's complete value is stable. An
                        // array index or field write changes that value. A
                        // slice or map index write instead changes the backing
                        // store named by a stable descriptor, so the exact
                        // descriptor value remains a sound capture.
                        capture_mutable_bindings.insert(binding);
                    }
                    if resolved_binding_procedure(binding) != spec.id {
                        by_owner[resolved_binding_procedure(binding).index()]
                            .insert((name.into(), binding));
                    }
                }
            }

            if node.kind() == "selector_expression"
                && let Some(operand) = node.child_by_field_name("operand")
                && let Some(root) = go_place_root_identifier(operand)
                && let Some(name) = node_text(source, root).filter(|name| *name != "_")
                && let Some(field_name) = node
                    .child_by_field_name("field")
                    .and_then(|field| nonempty_node_text(source, field))
                && let Some(binding) = resolve_go_binding(
                    specs,
                    lexical_bindings,
                    procedure_index,
                    name,
                    root.start_byte(),
                    inventory,
                    cancellation,
                )?
            {
                let direct_receiver = transparent_parenthesized_expression(operand);
                let receiver_type = (is_go_binding_reference_kind(direct_receiver.kind())
                    && direct_receiver.id() == root.id())
                .then(|| match binding {
                    GoResolvedBinding::Local(identity) => lexical_bindings
                        .get(identity.procedure.index())?
                        .receiver_types
                        .get(&identity)
                        .copied(),
                    GoResolvedBinding::Formal(_) => None,
                })
                .flatten();
                match go_same_file_selector_resolution(
                    receiver_type.map(|identity| identity.declaration),
                    Some(field_name),
                    direct_struct_fields,
                    method_inventory,
                ) {
                    GoSelectorResolution::Method {
                        pointer_receiver: true,
                    } if receiver_type.is_some_and(|identity| identity.pointer_depth == 0) => {
                        // A method value saves the implicit address even when
                        // its eventual invocation is outside this procedure.
                        capture_mutable_bindings.insert(binding);
                        by_owner[resolved_binding_procedure(binding).index()]
                            .insert((name.into(), binding));
                    }
                    GoSelectorResolution::Unknown => {
                        // An unresolved selector might still be a pointer
                        // method. Refuse the exact capture claim, and when the
                        // reference comes from a descendant callable retain
                        // the original binding's possible call exposure. The
                        // current type proof deliberately covers only exact
                        // short-declared locals, so formals and explicit var
                        // declarations must remain conservative here.
                        capture_mutable_bindings.insert(binding);
                        if resolved_binding_procedure(binding) != spec.id {
                            by_owner[resolved_binding_procedure(binding).index()]
                                .insert((name.into(), binding));
                        }
                    }
                    GoSelectorResolution::Package
                    | GoSelectorResolution::Field
                    | GoSelectorResolution::Method { .. } => {}
                }
            }

            if node.kind() == "unary_expression"
                && unary_operator_kind(node) == Some("&")
                && let Some(operand) = node.child_by_field_name("operand")
                && let Some(root) = go_place_root_identifier(operand)
                && let Some(name) = node_text(source, root).filter(|name| *name != "_")
                && let Some(binding) = resolve_go_binding(
                    specs,
                    lexical_bindings,
                    procedure_index,
                    name,
                    root.start_byte(),
                    inventory,
                    cancellation,
                )?
            {
                // The escaped address can update the original cell even
                // when this file contains no direct assignment to it.
                capture_mutable_bindings.insert(binding);
                by_owner[resolved_binding_procedure(binding).index()]
                    .insert((name.into(), binding));
            }

            if node.kind() == "slice_expression"
                && let Some(root) = go_place_root_identifier(node)
                && let Some(name) = node_text(source, root).filter(|name| *name != "_")
                && let Some(binding) = resolve_go_binding(
                    specs,
                    lexical_bindings,
                    procedure_index,
                    name,
                    root.start_byte(),
                    inventory,
                    cancellation,
                )?
            {
                // Slicing an array or pointer-to-array can publish an alias to
                // its storage. Without a structured aggregate-kind proof, a
                // later update through that slice can change the original
                // variable's complete value, including through an otherwise
                // unrelated call that receives the derived slice.
                capture_mutable_bindings.insert(binding);
                by_owner[resolved_binding_procedure(binding).index()]
                    .insert((name.into(), binding));
            }
            Ok(WalkControl::Continue)
        })?;
    }
    let mut ordered_by_owner = Vec::with_capacity(by_owner.len());
    for origins in by_owner {
        charge_go_inventory_prepass(inventory, cancellation)?;
        let mut origins = origins
            .into_iter()
            .map(|(name, binding)| GoCallExposureOrigin { name, binding })
            .collect::<Vec<_>>();
        origins.sort_by(|left, right| {
            left.name.cmp(&right.name).then_with(|| {
                resolved_binding_sort_key(left.binding)
                    .cmp(&resolved_binding_sort_key(right.binding))
            })
        });
        charge_go_inventory_prepass(inventory, cancellation)?;
        ordered_by_owner.push(origins);
    }
    Ok((ordered_by_owner, capture_mutable_bindings))
}

fn go_place_root_identifier(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        match node.kind() {
            "parenthesized_expression" | "literal_element" => {
                node = transparent_runtime_wrapper_child(node)?;
            }
            "selector_expression" | "index_expression" | "slice_expression" => {
                node = node.child_by_field_name("operand")?;
            }
            "identifier" | "true" | "false" | "nil" | "iota" => return Some(node),
            _ => return None,
        }
    }
}

fn resolved_binding_procedure(binding: GoResolvedBinding) -> ProcedureId {
    match binding {
        GoResolvedBinding::Local(identity) => identity.procedure,
        GoResolvedBinding::Formal(identity) => identity.procedure,
    }
}

fn resolved_binding_sort_key(binding: GoResolvedBinding) -> (usize, usize, usize) {
    match binding {
        GoResolvedBinding::Formal(identity) => {
            (identity.procedure.index(), 0, identity.declaration)
        }
        GoResolvedBinding::Local(identity) => (identity.procedure.index(), 1, identity.declaration),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct GoBindingIdentity {
    procedure: ProcedureId,
    declaration: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GoReceiverTypeProof {
    declaration: usize,
    pointer_depth: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum GoResolvedBinding {
    Local(GoBindingIdentity),
    Formal(GoBindingIdentity),
}

#[derive(Debug, Clone, Copy)]
struct GoScopedLocalBinding {
    identity: GoBindingIdentity,
    visible_from: usize,
    scope_start: usize,
    scope_end: usize,
    exact_value_candidate: bool,
}

/// Reference and mutation classification must use the binding visible at the
/// individual AST site. Go local scope begins after the declaration and a
/// later declaration may shadow only part of a child callable; a whole-body
/// name set would therefore erase an earlier outer reference. These transient
/// inventories share their scope selectors with lowering-time `LocalBinding`.
struct GoCallableLexicalBindings {
    formals: HashMap<Box<str>, GoBindingIdentity>,
    locals: HashMap<Box<str>, Vec<GoScopedLocalBinding>>,
    receiver_types: HashMap<GoBindingIdentity, GoReceiverTypeProof>,
    storage_kinds: HashMap<GoBindingIdentity, GoStorageKind>,
    declaration_targets: HashMap<usize, GoResolvedBinding>,
}

fn visible_go_binding<T>(
    bindings: &[T],
    byte: usize,
    bounds: impl Fn(&T) -> (usize, usize, usize),
) -> Option<&T> {
    bindings
        .iter()
        .filter(|binding| {
            let (visible_from, scope_start, scope_end) = bounds(binding);
            visible_from <= byte && scope_start <= byte && byte < scope_end
        })
        .min_by_key(|binding| {
            let (visible_from, scope_start, scope_end) = bounds(binding);
            (scope_end - scope_start, std::cmp::Reverse(visible_from))
        })
}

fn visible_go_named_type<'tree>(
    named_types: &GoNamedTypeDefinitions<'tree>,
    name: &str,
    byte: usize,
) -> Option<GoNamedTypeDefinition<'tree>> {
    visible_go_binding(named_types.get(name)?, byte, |definition| {
        (
            definition.visible_from,
            definition.scope_start,
            definition.scope_end,
        )
    })
    .copied()
}

fn go_binding_in_exact_scope<T>(
    bindings: &[T],
    byte: usize,
    scope_start: usize,
    scope_end: usize,
    bounds: impl Fn(&T) -> (usize, usize, usize),
) -> Option<&T> {
    bindings.iter().find(|binding| {
        let (visible_from, candidate_start, candidate_end) = bounds(binding);
        visible_from <= byte && candidate_start == scope_start && candidate_end == scope_end
    })
}

impl GoCallableLexicalBindings {
    fn binding_at(&self, name: &str, byte: usize) -> Option<GoResolvedBinding> {
        self.local_at(name, byte)
            .map(|binding| GoResolvedBinding::Local(binding.identity))
            .or_else(|| {
                self.formals
                    .get(name)
                    .copied()
                    .map(GoResolvedBinding::Formal)
            })
    }

    fn local_at(&self, name: &str, byte: usize) -> Option<GoScopedLocalBinding> {
        visible_go_binding(self.locals.get(name)?, byte, |binding| {
            (binding.visible_from, binding.scope_start, binding.scope_end)
        })
        .copied()
    }

    fn local_in_exact_scope(
        &self,
        name: &str,
        byte: usize,
        scope_start: usize,
        scope_end: usize,
    ) -> Option<GoScopedLocalBinding> {
        go_binding_in_exact_scope(
            self.locals.get(name)?,
            byte,
            scope_start,
            scope_end,
            |binding| (binding.visible_from, binding.scope_start, binding.scope_end),
        )
        .copied()
    }

    fn storage_kind(&self, binding: GoResolvedBinding) -> Option<GoStorageKind> {
        let identity = match binding {
            GoResolvedBinding::Local(identity) | GoResolvedBinding::Formal(identity) => identity,
        };
        self.storage_kinds.get(&identity).copied()
    }
}

fn go_receiver_type_proof_from_type(
    node: Node<'_>,
    source: &str,
    named_types: &GoNamedTypeDefinitions<'_>,
    byte: usize,
) -> Option<GoReceiverTypeProof> {
    let identity = go_type_identity(node, source)?;
    let definition = visible_go_named_type(named_types, identity.name.as_ref(), byte)?;
    Some(GoReceiverTypeProof {
        declaration: definition.declaration,
        pointer_depth: identity.pointer_depth,
    })
}

fn go_prepass_expression_receiver_type(
    mut node: Node<'_>,
    bindings: &GoCallableLexicalBindings,
    source: &str,
    named_types: &GoNamedTypeDefinitions<'_>,
    byte: usize,
    inventory: &mut ProcedureInventoryBuilder<'_>,
    cancellation: &CancellationToken,
) -> Result<Option<GoReceiverTypeProof>, GoInventoryPrepassStop> {
    let mut address_depth = 0usize;
    let mut dereference_depth = 0usize;
    let base = loop {
        charge_go_inventory_prepass(inventory, cancellation)?;
        match node.kind() {
            "parenthesized_expression" | "literal_element" => {
                let Some(child) = transparent_runtime_wrapper_child(node) else {
                    break None;
                };
                node = child;
            }
            "unary_expression" if unary_operator_kind(node) == Some("&") => {
                let Some(depth) = address_depth.checked_add(1) else {
                    break None;
                };
                let Some(operand) = node.child_by_field_name("operand") else {
                    break None;
                };
                address_depth = depth;
                node = operand;
            }
            "unary_expression" if unary_operator_kind(node) == Some("*") => {
                let Some(depth) = dereference_depth.checked_add(1) else {
                    break None;
                };
                let Some(operand) = node.child_by_field_name("operand") else {
                    break None;
                };
                dereference_depth = depth;
                node = operand;
            }
            "composite_literal" => {
                break node.child_by_field_name("type").and_then(|type_node| {
                    go_receiver_type_proof_from_type(type_node, source, named_types, byte)
                });
            }
            "identifier" | "true" | "false" | "nil" | "iota" => {
                let Some(name) = node_text(source, node) else {
                    break None;
                };
                break bindings
                    .local_at(name, byte)
                    .and_then(|binding| bindings.receiver_types.get(&binding.identity).copied());
            }
            _ => break None,
        }
    };
    Ok(base.and_then(|mut proof| {
        proof.pointer_depth = proof
            .pointer_depth
            .checked_add(address_depth)?
            .checked_sub(dereference_depth)?;
        Some(proof)
    }))
}

fn go_file_underlying_type<'tree>(
    mut kind: Node<'tree>,
    source: &str,
    named_types: &GoNamedTypeDefinitions<'tree>,
    use_byte: usize,
) -> Option<Node<'tree>> {
    let definition_count = named_types.values().map(Vec::len).sum::<usize>();
    for _ in 0..=definition_count {
        match kind.kind() {
            "parenthesized_type" => kind = first_named_child(kind)?,
            "generic_type" => {
                let name = kind.child_by_field_name("type")?;
                let name = node_text(source, name)?;
                kind = visible_go_named_type(named_types, name, use_byte)?.underlying;
            }
            "type_identifier" => {
                let name = node_text(source, kind)?;
                let Some(definition) = visible_go_named_type(named_types, name, use_byte) else {
                    return Some(kind);
                };
                kind = definition.underlying;
            }
            _ => return Some(kind),
        }
    }
    None
}

fn go_storage_kind_from_type(
    kind: Node<'_>,
    source: &str,
    named_types: &GoNamedTypeDefinitions<'_>,
    use_byte: usize,
) -> Option<GoStorageKind> {
    match go_file_underlying_type(kind, source, named_types, use_byte)?.kind() {
        "array_type" | "implicit_length_array_type" => Some(GoStorageKind::Array),
        "slice_type" => Some(GoStorageKind::Slice),
        "map_type" => Some(GoStorageKind::Map),
        _ => None,
    }
}

fn go_prepass_expression_storage_kind(
    mut node: Node<'_>,
    bindings: &GoCallableLexicalBindings,
    source: &str,
    named_types: &GoNamedTypeDefinitions<'_>,
    byte: usize,
) -> Option<GoStorageKind> {
    let mut sliced = false;
    loop {
        let storage = match node.kind() {
            "parenthesized_expression" | "literal_element" => {
                node = transparent_runtime_wrapper_child(node)?;
                continue;
            }
            "identifier" | "true" | "false" | "nil" | "iota" => {
                let name = node_text(source, node)?;
                bindings
                    .binding_at(name, byte)
                    .and_then(|binding| bindings.storage_kind(binding))
            }
            "composite_literal" => go_storage_kind_from_type(
                node.child_by_field_name("type")?,
                source,
                named_types,
                byte,
            ),
            "slice_expression" => {
                sliced = true;
                node = node.child_by_field_name("operand")?;
                continue;
            }
            "call_expression" => {
                let function = node.child_by_field_name("function")?;
                if function.kind() != "identifier"
                    || node_text(source, function) != Some("make")
                    || bindings.binding_at("make", byte).is_some()
                {
                    return None;
                }
                let arguments = all_call_arguments(node);
                let kind = *arguments.first()?;
                match arguments.as_slice() {
                    [_, _] | [_, _, _] if kind.kind() == "slice_type" => Some(GoStorageKind::Slice),
                    [_] | [_, _] if kind.kind() == "map_type" => Some(GoStorageKind::Map),
                    _ => None,
                }
            }
            _ => None,
        };
        return if sliced {
            matches!(storage, Some(GoStorageKind::Array | GoStorageKind::Slice))
                .then_some(GoStorageKind::Slice)
        } else {
            storage
        };
    }
}

fn go_callable_lexical_bindings(
    spec: &ProcedureSpec<'_>,
    source: &str,
    named_type_definitions: &GoNamedTypeDefinitions<'_>,
    inventory: &mut ProcedureInventoryBuilder<'_>,
    cancellation: &CancellationToken,
) -> Result<GoCallableLexicalBindings, GoInventoryPrepassStop> {
    charge_go_inventory_prepass(inventory, cancellation)?;
    let mut bindings = GoCallableLexicalBindings {
        formals: HashMap::default(),
        locals: HashMap::default(),
        receiver_types: HashMap::default(),
        storage_kinds: HashMap::default(),
        declaration_targets: HashMap::default(),
    };
    if let Some(layout) = formal_parameter_slots_for_owner(Language::Go, spec.callable, source) {
        for slot in layout.slots {
            charge_go_inventory_prepass(inventory, cancellation)?;
            let declaration = spec
                .callable
                .named_descendant_for_byte_range(
                    slot.declaration_range.start_byte,
                    slot.declaration_range.end_byte,
                )
                .unwrap_or(spec.callable);
            let storage = declaration.child_by_field_name("type").and_then(|kind| {
                go_storage_kind_from_type(
                    kind,
                    source,
                    named_type_definitions,
                    declaration.start_byte(),
                )
            });
            for name in slot.names {
                charge_go_inventory_prepass(inventory, cancellation)?;
                if name == "_" {
                    continue;
                }
                let declaration = children_by_field_name(declaration, "name")
                    .into_iter()
                    .find(|name_node| node_text(source, *name_node) == Some(name.as_str()))
                    .map(|name_node| name_node.id())
                    .unwrap_or_else(|| declaration.id());
                let identity = GoBindingIdentity {
                    procedure: spec.id,
                    declaration,
                };
                bindings.formals.insert(name.into_boxed_str(), identity);
                if let Some(storage) = storage {
                    bindings.storage_kinds.insert(identity, storage);
                }
            }
        }
    }
    if let Some(results) = spec
        .callable
        .child_by_field_name("result")
        .filter(|result| result.kind() == "parameter_list")
    {
        for declaration in named_children(results)
            .into_iter()
            .filter(|node| node.kind() == "parameter_declaration")
        {
            let storage = declaration.child_by_field_name("type").and_then(|kind| {
                go_storage_kind_from_type(
                    kind,
                    source,
                    named_type_definitions,
                    declaration.start_byte(),
                )
            });
            charge_go_inventory_prepass(inventory, cancellation)?;
            for name_node in children_by_field_name(declaration, "name") {
                charge_go_inventory_prepass(inventory, cancellation)?;
                if let Some(name) = node_text(source, name_node)
                    && name != "_"
                {
                    let identity = GoBindingIdentity {
                        procedure: spec.id,
                        declaration: name_node.id(),
                    };
                    bindings.formals.insert(name.into(), identity);
                    if let Some(storage) = storage {
                        bindings.storage_kinds.insert(identity, storage);
                    }
                }
            }
        }
    }
    try_walk_named_tree_preorder(spec.body, true, |node| {
        charge_go_inventory_prepass(inventory, cancellation)?;
        if node != spec.body && is_go_callable_kind(node.kind()) {
            return Ok(WalkControl::SkipChildren);
        }
        let (name_nodes, exact_value_candidate, value_nodes) = match node.kind() {
            "var_spec" | "const_spec" => {
                let names = children_by_field_name(node, "name");
                let values = node
                    .child_by_field_name("value")
                    .map(expression_sequence)
                    .filter(|values| values.len() == names.len())
                    .unwrap_or_default();
                (names, node.kind() == "const_spec", values)
            }
            "short_var_declaration" => {
                let left = node.child_by_field_name("left");
                let right = node.child_by_field_name("right");
                let name_nodes = left.map(expression_sequence).unwrap_or_default();
                let value_nodes = match (left, right) {
                    (Some(left), Some(right)) if names_len_matches_values(left, right) => {
                        expression_sequence(right)
                    }
                    _ => Vec::new(),
                };
                (name_nodes, true, value_nodes)
            }
            "range_clause" if direct_child_kind(node, ":=") => (
                node.child_by_field_name("left")
                    .map(expression_sequence)
                    .unwrap_or_default(),
                false,
                Vec::new(),
            ),
            _ => return Ok(WalkControl::Continue),
        };
        let Some((scope_start, scope_end)) = go_local_scope(node) else {
            return Ok(WalkControl::Continue);
        };
        for (index, name_node) in name_nodes.into_iter().enumerate() {
            if !is_go_binding_reference_kind(name_node.kind()) {
                continue;
            }
            let Some(name) = node_text(source, name_node) else {
                continue;
            };
            if name == "_" {
                continue;
            }
            let existing = (node.kind() == "short_var_declaration")
                .then(|| {
                    bindings.local_in_exact_scope(name, node.start_byte(), scope_start, scope_end)
                })
                .flatten();
            let resolved = existing
                .map(|binding| GoResolvedBinding::Local(binding.identity))
                .or_else(|| {
                    (node.kind() == "short_var_declaration"
                        && bindings.formals.contains_key(name)
                        && scope_start == spec.body.start_byte()
                        && scope_end == spec.body.end_byte())
                    .then(|| {
                        GoResolvedBinding::Formal(
                            *bindings
                                .formals
                                .get(name)
                                .expect("formal membership was checked"),
                        )
                    })
                })
                .unwrap_or_else(|| {
                    GoResolvedBinding::Local(GoBindingIdentity {
                        procedure: spec.id,
                        declaration: name_node.id(),
                    })
                });
            if let GoResolvedBinding::Local(identity) = resolved
                && existing.is_none()
            {
                let receiver_type = if exact_value_candidate {
                    match value_nodes.get(index).copied() {
                        Some(value) => go_prepass_expression_receiver_type(
                            value,
                            &bindings,
                            source,
                            named_type_definitions,
                            node.start_byte(),
                            inventory,
                            cancellation,
                        )?,
                        None => None,
                    }
                } else {
                    None
                };
                bindings
                    .locals
                    .entry(name.into())
                    .or_default()
                    .push(GoScopedLocalBinding {
                        identity,
                        visible_from: node.end_byte(),
                        scope_start,
                        scope_end,
                        exact_value_candidate,
                    });
                if let Some(receiver_type) = receiver_type {
                    bindings.receiver_types.insert(identity, receiver_type);
                }
            }
            let storage = node
                .child_by_field_name("type")
                .and_then(|kind| {
                    go_storage_kind_from_type(
                        kind,
                        source,
                        named_type_definitions,
                        node.start_byte(),
                    )
                })
                .or_else(|| {
                    value_nodes.get(index).and_then(|value| {
                        go_prepass_expression_storage_kind(
                            *value,
                            &bindings,
                            source,
                            named_type_definitions,
                            node.start_byte(),
                        )
                    })
                });
            if let Some(storage) = storage {
                let identity = match resolved {
                    GoResolvedBinding::Local(identity) | GoResolvedBinding::Formal(identity) => {
                        identity
                    }
                };
                bindings.storage_kinds.insert(identity, storage);
            }
            bindings
                .declaration_targets
                .insert(name_node.id(), resolved);
        }
        Ok(WalkControl::Continue)
    })?;
    Ok(bindings)
}

/// Exact capture identity is useful only when the parent CFG also lowers the
/// function-literal expression and can publish its capture bindings.
/// Expression-switch and select case bodies are retained, while type-switch
/// clauses still stop where their parent construct publishes an explicit gap.
fn go_callable_creation_is_lowered(
    callable: Node<'_>,
    parent_body: Node<'_>,
    inventory: &mut ProcedureInventoryBuilder<'_>,
    cancellation: &CancellationToken,
) -> Result<bool, GoInventoryPrepassStop> {
    let mut current = callable;
    while current.id() != parent_body.id() {
        charge_go_inventory_prepass(inventory, cancellation)?;
        let Some(parent) = current.parent() else {
            return Ok(false);
        };
        if is_clause(parent) {
            let lowered_clause = parent.parent().is_some_and(|owner| {
                matches!(
                    owner.kind(),
                    "expression_switch_statement" | "select_statement"
                )
            });
            if !lowered_clause {
                return Ok(false);
            }
        }
        current = parent;
    }
    Ok(true)
}

fn immutable_captured_binding(
    lexical_bindings: &[GoCallableLexicalBindings],
    binding: GoResolvedBinding,
    capture_mutable_bindings: &HashSet<GoResolvedBinding>,
) -> bool {
    let GoResolvedBinding::Local(identity) = binding else {
        return false;
    };
    lexical_bindings[identity.procedure.index()]
        .locals
        .values()
        .flatten()
        .any(|candidate| candidate.identity == identity && candidate.exact_value_candidate)
        && !capture_mutable_bindings.contains(&binding)
}

fn resolve_go_binding(
    specs: &[ProcedureSpec<'_>],
    lexical_bindings: &[GoCallableLexicalBindings],
    mut procedure_index: usize,
    name: &str,
    byte: usize,
    inventory: &mut ProcedureInventoryBuilder<'_>,
    cancellation: &CancellationToken,
) -> Result<Option<GoResolvedBinding>, GoInventoryPrepassStop> {
    loop {
        charge_go_inventory_prepass(inventory, cancellation)?;
        if let Some(binding) = lexical_bindings[procedure_index].binding_at(name, byte) {
            return Ok(Some(binding));
        }
        let Some(parent) = specs[procedure_index].lexical_parent else {
            return Ok(None);
        };
        procedure_index = parent.index();
    }
}

fn go_mutation_targets(node: Node<'_>) -> Vec<Node<'_>> {
    match node.kind() {
        "assignment_statement" | "short_var_declaration" | "range_clause" => node
            .child_by_field_name("left")
            .map(expression_sequence)
            .unwrap_or_default(),
        "inc_statement" | "dec_statement" => runtime_expression_children(node),
        _ => Vec::new(),
    }
}

fn enclosing_binding_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    let mut value = node;
    loop {
        let parent = value.parent()?;
        match parent.kind() {
            "parenthesized_expression" | "expression_list" => value = parent,
            "assignment_statement" | "short_var_declaration"
                if field_matches(parent, "right", value) =>
            {
                return parent
                    .child_by_field_name("left")
                    .and_then(single_binding_node)
                    .and_then(|name| nonempty_node_text(source, name))
                    .map(Box::<str>::from);
            }
            "var_spec" if field_matches(parent, "value", value) => {
                let names = children_by_field_name(parent, "name");
                return (names.len() == 1)
                    .then_some(names[0])
                    .and_then(|name| nonempty_node_text(source, name))
                    .map(Box::<str>::from);
            }
            _ => return None,
        }
    }
}

fn single_binding_node(node: Node<'_>) -> Option<Node<'_>> {
    if is_go_binding_reference_kind(node.kind()) || node.kind() == "field_identifier" {
        return Some(node);
    }
    let children = named_children(node);
    (children.len() == 1
        && (is_go_binding_reference_kind(children[0].kind())
            || children[0].kind() == "field_identifier"))
        .then_some(children[0])
}

fn callable_shape<'tree>(
    node: Node<'tree>,
    lexical_parent: Option<ProcedureId>,
) -> Option<(
    ProcedureKind,
    DeclarationSegmentKind,
    Node<'tree>,
    ProcedureProperties,
)> {
    let (kind, segment_kind, body) = match node.kind() {
        "function_declaration" => (
            if lexical_parent.is_some() {
                ProcedureKind::LocalFunction
            } else {
                ProcedureKind::Function
            },
            if lexical_parent.is_some() {
                DeclarationSegmentKind::LocalFunction
            } else {
                DeclarationSegmentKind::Function
            },
            callable_body(node)?,
        ),
        "method_declaration" => (
            ProcedureKind::Method,
            DeclarationSegmentKind::Method,
            callable_body(node)?,
        ),
        "func_literal" => (
            ProcedureKind::Lambda,
            DeclarationSegmentKind::Lambda,
            callable_body(node)?,
        ),
        _ => return None,
    };
    Some((
        kind,
        segment_kind,
        body,
        ProcedureProperties {
            is_async: false,
            is_generator: false,
            is_static: false,
            is_synthetic: false,
            invocation: ProcedureInvocationKind::Immediate,
            ..ProcedureProperties::default()
        },
    ))
}

fn callable_body(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("body")
}

fn field_matches(parent: Node<'_>, field: &str, child: Node<'_>) -> bool {
    parent
        .child_by_field_name(field)
        .is_some_and(|candidate| candidate.id() == child.id())
}

type GoLoweringError = ProcedureLoweringError;

type EdgeTarget = ControlTarget;

type MemoryPlaceLocation = (MemoryAccessKind, MemoryLocationId, Option<(ValueId, bool)>);

#[derive(Debug, Clone, Copy)]
enum Work<'tree> {
    Statement {
        node: Node<'tree>,
        entry: ProgramPointId,
        next: StatementNext,
        scope: ScopeFrameId,
        label: Option<Node<'tree>>,
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
    DeferredCall {
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
    },
    RetainContinuations {
        cursor: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct StatementContinuationId(u32);

impl StatementContinuationId {
    fn try_from_index(index: usize) -> Result<Self, GoLoweringError> {
        Ok(Self(u32::try_from(index).map_err(|_| {
            GoLoweringError::Invalid("too many Go statement continuations".into())
        })?))
    }

    const fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Debug, Clone, Copy)]
enum StatementNext {
    Target(EdgeTarget),
    Continuation(StatementContinuationId),
    FunctionReturn,
}

impl From<EdgeTarget> for StatementNext {
    fn from(target: EdgeTarget) -> Self {
        Self::Target(target)
    }
}

#[derive(Debug, Clone, Copy)]
struct StatementContinuation<'tree> {
    node: Node<'tree>,
    next: StatementNext,
    retention_scope: ScopeFrameId,
}

#[derive(Debug, Clone, Copy)]
struct CleanupRegion<'tree> {
    id: CleanupRegionId,
    call: Node<'tree>,
    outer_scope: ScopeFrameId,
}

#[derive(Debug, Clone)]
struct DeferredCapture {
    receiver: Option<(ValueId, ValueId)>,
    arguments: Box<[(ValueId, ValueId)]>,
}

struct LoweredCallOperands {
    callee: ValueId,
    receiver: Option<ValueId>,
    arguments: Box<[SemanticCallArgument]>,
    resolution: CallableTargetResolution,
    selector_resolution: Option<GoSelectorResolution>,
}

struct LoweringContext<'tree, 'facts, 'targets, 'imports, 'procedure> {
    procedure_id: ProcedureId,
    prepared: &'tree PreparedSyntaxTree,
    direct_struct_fields: &'facts DirectStructFields,
    named_type_definitions: &'facts GoNamedTypeDefinitions<'tree>,
    session: ProcedureLoweringSession<'targets>,
    expression_values: HashMap<usize, ValueId>,
    multi_result_values: HashMap<usize, Box<[ValueId]>>,
    parameters: HashMap<Box<str>, ValueId>,
    captured_values: HashMap<Box<str>, ValueId>,
    captured_bindings: HashMap<GoResolvedBinding, ValueId>,
    shared_binding_locations: HashMap<ValueId, (MemoryLocationId, MemoryAccessKind)>,
    locals: HashMap<Box<str>, Vec<LocalBinding>>,
    call_exposed_bindings: HashSet<ValueId>,
    value_types: HashMap<ValueId, GoTypeIdentity>,
    /// Exact local aggregate storage semantics retained from structured Go
    /// syntax. Arrays copy their elements on assignment; slices copy a view of
    /// one backing store.
    value_storage_kinds: HashMap<ValueId, GoStorageKind>,
    /// Slice lengths and capacities proven directly by structured literals or
    /// builtin `make` arguments, retained only through exact slice operations.
    exact_slice_shapes: HashMap<ValueId, ExactSliceShape>,
    /// Fresh array literals whose first binding establishes local storage
    /// rather than copying an already-owned array value.
    fresh_array_values: HashSet<ValueId>,
    /// Every `(struct type, field)` declaration this file states, shared by
    /// every procedure lowered from it.
    struct_field_anchors: &'tree HashMap<(usize, Box<str>), SourceAnchor>,
    /// The fallback memory-location identity for a field whose declaration
    /// this file does not state, interned once per name per procedure so a
    /// store and a load of the same name still meet.
    field_locators: HashMap<Box<str>, SemanticLocator>,
    static_locations: HashMap<Box<str>, MemoryLocationId>,
    /// One value per integer-literal magnitude. Go accepts several spellings
    /// for the same integer, so the cache is keyed by parsed value rather than
    /// source text.
    constant_index_values: HashMap<u128, ValueId>,
    receiver: Option<ValueId>,
    root_body: Node<'tree>,
    statement_continuations: Vec<StatementContinuation<'tree>>,
    continuation_entries: HashMap<(StatementContinuationId, ScopeFrameId), ProgramPointId>,
    materialized_continuations: HashSet<StatementContinuationId>,
    return_entries: HashMap<ScopeFrameId, ProgramPointId>,
    deferred_captures: HashMap<usize, DeferredCapture>,
    cleanups: Vec<CleanupRegion<'tree>>,
    named_results: Vec<ValueId>,
    return_shape_supported: bool,
    omitted_capture_names: &'procedure [Box<str>],
    call_exposure_origins: &'procedure [GoCallExposureOrigin],
    import_bindings: &'imports HashMap<Box<str>, Box<str>>,
    package_functions: &'imports HashSet<Box<str>>,
    package_values: &'imports HashSet<Box<str>>,
    package_value_locators: &'imports HashMap<Box<str>, SemanticLocator>,
    method_inventory: &'imports GoMethodInventory,
    procedure_targets: &'imports HashMap<usize, GoProcedureTarget>,
    package_shadowing: PredeclaredShadowing,
    predeclared_shadowed: PredeclaredShadowing,
}

#[derive(Debug, Clone)]
struct LocalBinding {
    declaration: usize,
    declaration_start: usize,
    visible_from: usize,
    scope_start: usize,
    scope_end: usize,
    value: ValueId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GoTypeIdentity {
    pointer_depth: usize,
    name: Box<str>,
    declaration: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GoStorageKind {
    Array,
    Slice,
    Map,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExactSliceShape {
    length: u128,
    capacity: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExactAppendBacking {
    Retained {
        source: ValueId,
        append_start: u128,
        result_shape: ExactSliceShape,
    },
    Replaced {
        append_start: u128,
    },
}

#[derive(Debug, Clone, Copy, Default)]
struct GoEvaluationTraits {
    runtime_read: bool,
    call_or_receive: bool,
    may_abort: bool,
    ordered_completion: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GoSelectorResolution {
    Package,
    Field,
    Method { pointer_receiver: bool },
    Unknown,
}

fn go_same_file_selector_resolution(
    receiver_declaration: Option<usize>,
    field_name: Option<&str>,
    direct_struct_fields: &DirectStructFields,
    method_inventory: &GoMethodInventory,
) -> GoSelectorResolution {
    let (Some(declaration), Some(name)) = (receiver_declaration, field_name) else {
        return GoSelectorResolution::Unknown;
    };
    if direct_struct_fields
        .get(&declaration)
        .is_some_and(|fields| fields.contains(name))
    {
        return GoSelectorResolution::Field;
    }
    method_inventory
        .get(&(declaration, name.into()))
        .copied()
        .map(|pointer_receiver| GoSelectorResolution::Method { pointer_receiver })
        .unwrap_or(GoSelectorResolution::Unknown)
}

impl GoEvaluationTraits {
    fn merge(&mut self, other: Self) {
        self.runtime_read |= other.runtime_read;
        self.call_or_receive |= other.call_or_receive;
        self.may_abort |= other.may_abort;
        self.ordered_completion = false;
    }
}

#[derive(Debug, Clone, Copy)]
enum GoLiteralNestingStep {
    Element,
    Key,
    Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GoLiteralAggregateKind {
    Map,
    NonMap,
    Unknown,
}

#[allow(clippy::too_many_arguments)]
fn lower_procedure<'tree>(
    prepared: &'tree PreparedSyntaxTree,
    struct_field_anchors: &'tree HashMap<(usize, Box<str>), SourceAnchor>,
    spec: &ProcedureSpec<'tree>,
    package_shadowing: PredeclaredShadowing,
    package_values: &HashSet<Box<str>>,
    package_value_locators: &HashMap<Box<str>, SemanticLocator>,
    direct_struct_fields: &DirectStructFields,
    named_type_definitions: &GoNamedTypeDefinitions<'tree>,
    import_bindings: &HashMap<Box<str>, Box<str>>,
    package_functions: &HashSet<Box<str>>,
    method_inventory: &GoMethodInventory,
    procedure_targets: &HashMap<usize, GoProcedureTarget>,
    budget: &SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<(ProcedureSemanticsParts, SemanticWork), GoLoweringError> {
    debug_assert!(
        spec.omitted_capture_names
            .windows(2)
            .all(|names| names[0] <= names[1]),
        "Go omitted capture names are kept in lexical-name order"
    );
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
        procedure_id: spec.id,
        prepared,
        direct_struct_fields,
        named_type_definitions,
        session,
        expression_values: HashMap::default(),
        multi_result_values: HashMap::default(),
        parameters: HashMap::default(),
        captured_values: HashMap::default(),
        captured_bindings: HashMap::default(),
        shared_binding_locations: HashMap::default(),
        locals: HashMap::default(),
        call_exposed_bindings: HashSet::default(),
        value_types: HashMap::default(),
        value_storage_kinds: HashMap::default(),
        exact_slice_shapes: HashMap::default(),
        fresh_array_values: HashSet::default(),
        struct_field_anchors,
        field_locators: HashMap::default(),
        static_locations: HashMap::default(),
        constant_index_values: HashMap::default(),
        receiver: None,
        root_body: spec.body,
        statement_continuations: Vec::new(),
        continuation_entries: HashMap::default(),
        materialized_continuations: HashSet::default(),
        return_entries: HashMap::default(),
        deferred_captures: HashMap::default(),
        cleanups: Vec::new(),
        named_results: Vec::new(),
        return_shape_supported: spec
            .callable
            .child_by_field_name("result")
            .is_some_and(|result| result.kind() != "parameter_list"),
        omitted_capture_names: &spec.omitted_capture_names,
        call_exposure_origins: &spec.call_exposure_origins,
        import_bindings,
        package_functions,
        package_values,
        package_value_locators,
        method_inventory,
        procedure_targets,
        package_shadowing,
        // Exact and omitted capture inventories below distinguish the
        // enclosing bindings a nested literal actually sees. Keep package and
        // named-result shadowing here; treating every predeclared name as
        // shadowed would discard valid builtin constants in every closure.
        predeclared_shadowed: package_shadowing.merged(spec.result_shadowing),
    };
    context.emit_procedure_inputs(&mut builder, spec.callable)?;
    context.emit_capture_inputs(&mut builder, entry, spec)?;
    context.emit_named_result_bindings(&mut builder, spec.callable, spec.body)?;
    context.emit_local_bindings(&mut builder, spec.body)?;
    context.emit_shared_binding_cells(&mut builder, entry, spec)?;
    context.collect_call_exposed_bindings(&builder)?;

    if spec.lexical_parent.is_some() && spec.captures.is_empty() {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::Captures,
            SemanticGapKind::Unsupported,
            "lexical captures by nested Go function literals are not yet modeled",
        )?;
    }
    if spec
        .callable
        .child_by_field_name("type_parameters")
        .is_some()
        || go_receiver_uses_generic_type(spec.callable)
    {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::Values,
            SemanticGapKind::Unsupported,
            "generic Go callable and receiver type substitutions are not yet represented",
        )?;
    }

    let body_entry = context.point(&mut builder, spec.body, Vec::new())?;
    let body_work = Work::Statement {
        node: spec.body,
        entry: body_entry,
        next: StatementNext::FunctionReturn,
        scope: function_scope,
        label: None,
    };
    let mut pending = vec![Work::RetainContinuations { cursor: 0 }, body_work];
    context.edge(&mut builder, entry, EdgeTarget::normal(body_entry))?;

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

impl<'tree, 'facts, 'targets, 'imports, 'procedure>
    LoweringContext<'tree, 'facts, 'targets, 'imports, 'procedure>
{
    fn emit_capture_inputs(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        spec: &ProcedureSpec<'tree>,
    ) -> Result<(), GoLoweringError> {
        let Some(lexical_parent) = spec.lexical_parent else {
            return Ok(());
        };
        for (index, capture) in spec.captures.iter().enumerate() {
            let metadata = self.value_mapping(builder, capture.reference)?;
            let value = self.session.add_value_with_metadata(
                builder,
                metadata,
                SemanticValueKind::Local,
            )?;
            let location = self.session.add_memory_location(
                builder,
                entry,
                MemoryLocationKind::Capture {
                    lexical_parent,
                    binding: Some(value),
                },
            )?;
            let expected = MemoryLocationId::new(
                u32::try_from(index)
                    .map_err(|_| GoLoweringError::Invalid("too many Go captures".into()))?,
            );
            if location != expected {
                return Err(GoLoweringError::Invalid(format!(
                    "Go capture destination must be {expected}, allocated {location}"
                )));
            }
            if capture.storage == GoCaptureStorage::Value {
                self.append_effect(
                    builder,
                    entry,
                    SemanticEffect::MemoryLoad {
                        kind: MemoryAccessKind::Capture,
                        location,
                        result: value,
                    },
                )?;
            } else {
                self.shared_binding_locations
                    .insert(value, (location, MemoryAccessKind::Capture));
            }
            if let Some(storage) = capture.value_storage {
                self.value_storage_kinds.insert(value, storage);
            }
            self.captured_values.insert(capture.name.clone(), value);
            self.captured_bindings.insert(capture.binding, value);
        }
        Ok(())
    }

    fn emit_shared_binding_cells(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        spec: &ProcedureSpec<'tree>,
    ) -> Result<(), GoLoweringError> {
        for shared in &spec.shared_bindings {
            let value = self
                .owned_binding_value(shared.name.as_ref(), shared.binding)
                .ok_or_else(|| {
                    GoLoweringError::Invalid(format!(
                        "shared Go binding `{}` has no owner-local value",
                        shared.name
                    ))
                })?;
            let location = self.session.add_memory_location(
                builder,
                entry,
                MemoryLocationKind::LexicalCell { binding: value },
            )?;
            let previous = self
                .shared_binding_locations
                .insert(value, (location, MemoryAccessKind::LexicalCell));
            debug_assert!(previous.is_none(), "one Go binding has one shared cell");
        }
        Ok(())
    }

    fn emit_procedure_inputs(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        callable: Node<'tree>,
    ) -> Result<(), GoLoweringError> {
        let layout =
            formal_parameter_slots_for_owner(Language::Go, callable, self.prepared.source())
                .unwrap_or_default();
        let mut ordinal = 0_u32;
        for slot in layout.slots {
            if self.session.cancellation().is_cancelled() {
                return Err(GoLoweringError::Cancelled(Box::new(
                    builder.prospective_work(),
                )));
            }
            let declaration = callable
                .named_descendant_for_byte_range(
                    slot.declaration_range.start_byte,
                    slot.declaration_range.end_byte,
                )
                .unwrap_or(callable);
            let mapping_node = slot
                .names
                .first()
                .and_then(|slot_name| {
                    children_by_field_name(declaration, "name")
                        .into_iter()
                        .find(|name| node_text(self.prepared.source(), *name) == Some(slot_name))
                })
                .unwrap_or(declaration);
            let metadata = self.value_mapping(builder, mapping_node)?;
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
                    GoLoweringError::Invalid("too many Go formal parameters".into())
                })?;
                value
            };
            if let Some(type_node) = declaration.child_by_field_name("type") {
                if let Some(identity) = self.type_identity(type_node, declaration.start_byte()) {
                    self.value_types.insert(value, identity);
                }
                if let Some(storage) = self.type_storage_kind(type_node, declaration.start_byte()) {
                    self.value_storage_kinds.insert(value, storage);
                }
            }
            for name in slot.names {
                if name != "_" {
                    self.parameters.insert(name.into_boxed_str(), value);
                }
            }
        }
        Ok(())
    }

    fn emit_local_bindings(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        body: Node<'tree>,
    ) -> Result<(), GoLoweringError> {
        try_walk_named_tree_preorder(body, true, |node| {
            if self.session.cancellation().is_cancelled() {
                return Err(GoLoweringError::Cancelled(Box::new(
                    builder.prospective_work(),
                )));
            }
            if node != body && is_go_callable_kind(node.kind()) {
                return Ok(WalkControl::SkipChildren);
            }
            match node.kind() {
                "var_spec" | "const_spec" => self.preindex_value_spec(builder, node)?,
                "short_var_declaration" => self.preindex_short_declaration(builder, node)?,
                "range_clause" if direct_child_kind(node, ":=") => {
                    self.preindex_range_declaration(builder, node)?;
                }
                _ => {}
            }
            Ok(WalkControl::Continue)
        })
    }

    fn emit_named_result_bindings(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        callable: Node<'tree>,
        body: Node<'tree>,
    ) -> Result<(), GoLoweringError> {
        let Some(results) = callable
            .child_by_field_name("result")
            .filter(|result| result.kind() == "parameter_list")
        else {
            return Ok(());
        };
        for declaration in named_children(results)
            .into_iter()
            .filter(|node| node.kind() == "parameter_declaration")
        {
            let identity = declaration
                .child_by_field_name("type")
                .and_then(|node| self.type_identity(node, declaration.start_byte()));
            let storage = declaration
                .child_by_field_name("type")
                .and_then(|node| self.type_storage_kind(node, declaration.start_byte()));
            for name_node in children_by_field_name(declaration, "name") {
                let Some(name) = node_text(self.prepared.source(), name_node) else {
                    continue;
                };
                if name == "_" {
                    continue;
                }
                let metadata = self.value_mapping(builder, name_node)?;
                let value = self.session.add_value_with_metadata(
                    builder,
                    metadata,
                    SemanticValueKind::Local,
                )?;
                if let Some(identity) = identity.clone() {
                    self.value_types.insert(value, identity);
                }
                if let Some(storage) = storage {
                    self.value_storage_kinds.insert(value, storage);
                }
                self.named_results.push(value);
                self.locals
                    .entry(name.into())
                    .or_default()
                    .push(LocalBinding {
                        declaration: name_node.id(),
                        declaration_start: name_node.start_byte(),
                        visible_from: body.start_byte(),
                        scope_start: body.start_byte(),
                        scope_end: body.end_byte(),
                        value,
                    });
            }
        }
        Ok(())
    }

    fn preindex_value_spec(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        spec: Node<'tree>,
    ) -> Result<(), GoLoweringError> {
        let names = children_by_field_name(spec, "name");
        if names.is_empty() {
            return Ok(());
        }
        let values = spec
            .child_by_field_name("value")
            .map(expression_sequence)
            .unwrap_or_default();
        let declared_type = spec
            .child_by_field_name("type")
            .and_then(|node| self.type_identity(node, spec.start_byte()));
        let declared_storage = spec
            .child_by_field_name("type")
            .and_then(|node| self.type_storage_kind(node, spec.start_byte()));
        for (index, name) in names.into_iter().enumerate() {
            let inferred_type = (declared_type.is_none() && values.len() == 1)
                .then(|| self.expression_type_identity(values[0], spec.start_byte()))
                .flatten()
                .or_else(|| {
                    (declared_type.is_none() && values.len() > 1)
                        .then(|| {
                            values.get(index).and_then(|value| {
                                self.expression_type_identity(*value, spec.start_byte())
                            })
                        })
                        .flatten()
                });
            let inferred_storage = values
                .get(index)
                .and_then(|value| self.expression_storage_kind(*value, spec.start_byte()));
            self.preindex_local(
                builder,
                name,
                spec,
                declared_type.clone().or(inferred_type),
                declared_storage.or(inferred_storage),
            )?;
        }
        Ok(())
    }

    fn preindex_short_declaration(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        declaration: Node<'tree>,
    ) -> Result<(), GoLoweringError> {
        let Some(left) = declaration.child_by_field_name("left") else {
            return Ok(());
        };
        let Some(right) = declaration.child_by_field_name("right") else {
            return Ok(());
        };
        let names = expression_sequence(left);
        let values = expression_sequence(right);
        for (index, name) in names.into_iter().enumerate() {
            if !is_go_binding_reference_kind(name.kind()) {
                continue;
            }
            let inferred_type = (names_len_matches_values(left, right))
                .then(|| {
                    values.get(index).and_then(|value| {
                        self.expression_type_identity(*value, declaration.start_byte())
                    })
                })
                .flatten();
            let inferred_storage = (names_len_matches_values(left, right))
                .then(|| {
                    values.get(index).and_then(|value| {
                        self.expression_storage_kind(*value, declaration.start_byte())
                    })
                })
                .flatten();
            self.preindex_local(builder, name, declaration, inferred_type, inferred_storage)?;
            if let Some(source) = values.get(index).copied()
                && let Some(shape) = self.expression_slice_shape(source, declaration.start_byte())
                && let Some(target) = self.local_declaration_value(
                    node_text(self.prepared.source(), name).unwrap_or_default(),
                    name.start_byte(),
                )
            {
                self.exact_slice_shapes.insert(target, shape);
            }
        }
        Ok(())
    }

    fn preindex_range_declaration(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        declaration: Node<'tree>,
    ) -> Result<(), GoLoweringError> {
        let Some(left) = declaration.child_by_field_name("left") else {
            return Ok(());
        };
        for name in expression_sequence(left) {
            if is_go_binding_reference_kind(name.kind()) {
                self.preindex_local(builder, name, declaration, None, None)?;
            }
        }
        Ok(())
    }

    fn preindex_local(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        name_node: Node<'tree>,
        declaration: Node<'tree>,
        identity: Option<GoTypeIdentity>,
        storage: Option<GoStorageKind>,
    ) -> Result<(), GoLoweringError> {
        let Some(name) = node_text(self.prepared.source(), name_node) else {
            return Ok(());
        };
        if name == "_" {
            return Ok(());
        }
        let Some((scope_start, scope_end)) = go_local_scope(declaration) else {
            return Ok(());
        };
        if declaration.kind() == "short_var_declaration"
            && (self
                .local_in_exact_scope(name, declaration.start_byte(), scope_start, scope_end)
                .is_some()
                || (self.parameters.contains_key(name)
                    && scope_start == self.root_body.start_byte()
                    && scope_end == self.root_body.end_byte()))
        {
            return Ok(());
        }
        let metadata = self.value_mapping(builder, name_node)?;
        let value =
            self.session
                .add_value_with_metadata(builder, metadata, SemanticValueKind::Local)?;
        if let Some(identity) = identity {
            self.value_types.insert(value, identity);
        }
        if let Some(storage) = storage {
            self.value_storage_kinds.insert(value, storage);
        }
        self.locals
            .entry(name.into())
            .or_default()
            .push(LocalBinding {
                declaration: name_node.id(),
                declaration_start: name_node.start_byte(),
                visible_from: declaration.end_byte(),
                scope_start,
                scope_end,
                value,
            });
        Ok(())
    }

    fn local_at(&self, name: &str, byte: usize) -> Option<ValueId> {
        visible_go_binding(self.locals.get(name)?, byte, |binding| {
            (binding.visible_from, binding.scope_start, binding.scope_end)
        })
        .map(|binding| binding.value)
    }

    fn local_in_exact_scope(
        &self,
        name: &str,
        byte: usize,
        scope_start: usize,
        scope_end: usize,
    ) -> Option<ValueId> {
        go_binding_in_exact_scope(
            self.locals.get(name)?,
            byte,
            scope_start,
            scope_end,
            |binding| (binding.visible_from, binding.scope_start, binding.scope_end),
        )
        .map(|binding| binding.value)
    }

    fn local_declaration_value(&self, name: &str, declaration_start: usize) -> Option<ValueId> {
        self.locals.get(name)?.iter().find_map(|binding| {
            (binding.declaration_start == declaration_start).then_some(binding.value)
        })
    }

    fn local_identity_value(&self, name: &str, declaration: usize) -> Option<ValueId> {
        self.locals
            .get(name)?
            .iter()
            .find_map(|binding| (binding.declaration == declaration).then_some(binding.value))
    }

    fn binding_value(&self, name: &str, byte: usize) -> Option<ValueId> {
        self.local_at(name, byte)
            .or_else(|| self.captured_values.get(name).copied())
            .or_else(|| self.parameters.get(name).copied())
    }

    fn owned_binding_value(&self, name: &str, binding: GoResolvedBinding) -> Option<ValueId> {
        match binding {
            GoResolvedBinding::Local(identity) if identity.procedure == self.procedure_id => {
                self.local_identity_value(name, identity.declaration)
            }
            GoResolvedBinding::Formal(identity) if identity.procedure == self.procedure_id => self
                .local_identity_value(name, identity.declaration)
                .or_else(|| self.parameters.get(name).copied()),
            GoResolvedBinding::Local(_) | GoResolvedBinding::Formal(_) => None,
        }
    }

    fn captured_or_owned_binding_value(
        &self,
        name: &str,
        binding: GoResolvedBinding,
    ) -> Option<ValueId> {
        self.owned_binding_value(name, binding)
            .or_else(|| self.captured_bindings.get(&binding).copied())
    }

    fn binding_value_for_origin(&self, origin: &GoCallExposureOrigin) -> Option<ValueId> {
        self.captured_or_owned_binding_value(origin.name.as_ref(), origin.binding)
    }

    /// Bindings whose stored value an otherwise unrelated call can observe or
    /// change. An exact local, parameter, or value capture is private until
    /// its address escapes, a descendant closure actually writes it, or Go
    /// implicitly takes its address for a pointer-receiver method value.
    /// Package values remain shared because this procedure does not own their
    /// storage.
    fn collect_call_exposed_bindings(
        &mut self,
        builder: &ProcedureCfgBuilder,
    ) -> Result<(), GoLoweringError> {
        if self.session.cancellation().is_cancelled() {
            return Err(GoLoweringError::Cancelled(Box::new(
                builder.prospective_work(),
            )));
        }
        let exposed = self
            .call_exposure_origins
            .iter()
            .filter_map(|origin| self.binding_value_for_origin(origin))
            .collect::<Vec<_>>();
        self.call_exposed_bindings.extend(exposed);

        let mut stack = vec![self.root_body];
        while let Some(node) = stack.pop() {
            if self.session.cancellation().is_cancelled() {
                return Err(GoLoweringError::Cancelled(Box::new(
                    builder.prospective_work(),
                )));
            }
            if node != self.root_body && is_go_callable_kind(node.kind()) {
                continue;
            }

            if node.kind() == "unary_expression"
                && unary_operator_kind(node) == Some("&")
                && let Some(operand) = node.child_by_field_name("operand")
                && let Some(binding) = self.place_root_binding(operand)
            {
                self.call_exposed_bindings.insert(binding);
            }
            if node.kind() == "selector_expression"
                && let Some(operand) = node.child_by_field_name("operand")
            {
                match self.selector_resolution(node) {
                    GoSelectorResolution::Method {
                        pointer_receiver: true,
                    } if self
                        .expression_type_identity(operand, node.start_byte())
                        .is_some_and(|identity| identity.pointer_depth == 0) =>
                    {
                        if let Some(binding) = self.place_root_binding(operand) {
                            // Selecting a pointer-receiver method from an
                            // addressable value saves `&value`, including when
                            // the method value is stored and called later.
                            self.call_exposed_bindings.insert(binding);
                        }
                    }
                    GoSelectorResolution::Unknown
                        if node.parent().is_some_and(|parent| {
                            parent.kind() == "call_expression"
                                && field_matches(parent, "function", node)
                        }) =>
                    {
                        if let Some(binding) = self.place_root_binding(operand) {
                            // An unresolved direct method call may still use a
                            // pointer receiver. Keep only that unknown case
                            // conservative; exact fields and value methods do
                            // not expose the receiver cell.
                            self.call_exposed_bindings.insert(binding);
                        }
                    }
                    _ => {}
                }
            }

            stack.extend(named_children(node).into_iter().rev());
        }
        Ok(())
    }

    fn place_root_binding(&self, mut node: Node<'tree>) -> Option<ValueId> {
        loop {
            match node.kind() {
                "parenthesized_expression" | "literal_element" => {
                    node = transparent_runtime_wrapper_child(node)?;
                }
                "selector_expression" | "index_expression" | "slice_expression" => {
                    node = node.child_by_field_name("operand")?;
                }
                "identifier" | "true" | "false" | "nil" | "iota" => {
                    let name = node_text(self.prepared.source(), node)?;
                    return self.binding_value(name, node.start_byte());
                }
                _ => return None,
            }
        }
    }

    fn selector_resolution(&self, selector: Node<'tree>) -> GoSelectorResolution {
        if self.is_import_qualified_selector(selector) {
            return GoSelectorResolution::Package;
        }
        let receiver_declaration = selector
            .child_by_field_name("operand")
            .and_then(|operand| self.expression_type_identity(operand, selector.start_byte()))
            .and_then(|identity| identity.declaration);
        let field_name = selector
            .child_by_field_name("field")
            .and_then(|field| nonempty_node_text(self.prepared.source(), field));
        go_same_file_selector_resolution(
            receiver_declaration,
            field_name,
            self.direct_struct_fields,
            self.method_inventory,
        )
    }

    fn identifier_is_shared_or_call_exposed(&self, node: Node<'tree>) -> bool {
        let Some(name) = node_text(self.prepared.source(), node) else {
            return true;
        };
        self.binding_value(name, node.start_byte()).map_or_else(
            || !self.package_functions.contains(name),
            |binding| self.call_exposed_bindings.contains(&binding),
        )
    }

    fn assignment_target_evaluation_nodes(&self, target: Node<'tree>) -> Vec<Node<'tree>> {
        let mut result = Vec::new();
        let mut stack = vec![target];
        while let Some(node) = stack.pop() {
            match node.kind() {
                "selector_expression" => {
                    if let Some(operand) = node.child_by_field_name("operand") {
                        result.push(operand);
                    }
                }
                "index_expression" => {
                    result.extend(runtime_expression_children(node));
                }
                "unary_expression" if unary_operator_kind(node) == Some("*") => {
                    if let Some(operand) = node.child_by_field_name("operand") {
                        result.push(operand);
                    }
                }
                "identifier" | "true" | "false" | "nil" | "iota" | "field_identifier" => {}
                _ => {
                    let children = named_children(node);
                    for child in children.into_iter().rev() {
                        if !is_go_type_syntax(child.kind()) {
                            stack.push(child);
                        }
                    }
                }
            }
        }
        result
    }

    fn assignment_target_order_nodes(&self, target: Node<'tree>) -> Vec<Node<'tree>> {
        let mut result = Vec::new();
        let mut stack = vec![target];
        while let Some(node) = stack.pop() {
            match node.kind() {
                "selector_expression" if self.is_direct_value_field(node) => {
                    // The selector itself performs no implicit dereference,
                    // but an explicitly dereferenced or otherwise structured
                    // operand can still make order observable. Descend without
                    // treating the field place as a value load.
                    if let Some(operand) = node.child_by_field_name("operand") {
                        stack.push(operand);
                    }
                }
                "index_expression" if self.is_private_constant_array_index(node) => {}
                "selector_expression" | "index_expression" => result.push(node),
                "unary_expression" if unary_operator_kind(node) == Some("*") => {
                    result.push(node);
                }
                "identifier" | "true" | "false" | "nil" | "iota" | "field_identifier" => {}
                _ => {
                    let children = named_children(node);
                    for child in children.into_iter().rev() {
                        if !is_go_type_syntax(child.kind()) {
                            stack.push(child);
                        }
                    }
                }
            }
        }
        result
    }

    /// Whether evaluating an indexed assignment place beside an RHS call has
    /// no observable ordering choice. The array binding is local to this
    /// procedure, has not escaped to a call or closure, and the index is a Go
    /// constant; evaluating either place operand is therefore inert. Slices,
    /// dynamic indices, foreign bindings, and escaped arrays fail closed.
    fn is_private_constant_array_index(&self, node: Node<'tree>) -> bool {
        let Some(operand) = node.child_by_field_name("operand") else {
            return false;
        };
        let Some(index) = node.child_by_field_name("index") else {
            return false;
        };
        self.expression_storage_kind(operand, node.start_byte()) == Some(GoStorageKind::Array)
            && self
                .place_root_binding(operand)
                .is_some_and(|binding| !self.call_exposed_bindings.contains(&binding))
            && self.is_go_constant_evaluation(index)
    }

    fn binding_requires_runtime_protocol(&self, binding: Node<'tree>) -> bool {
        !self.assignment_target_order_nodes(binding).is_empty()
    }

    fn assignment_evaluation_nodes(&self, node: Node<'tree>) -> Vec<Node<'tree>> {
        let mut result = Vec::new();
        if node.kind() == "assignment_statement"
            && let Some(left) = node.child_by_field_name("left")
        {
            result.extend(self.assignment_target_evaluation_nodes(left));
        }
        if let Some(right) = node.child_by_field_name("right") {
            result.extend(expression_sequence(right));
        }
        result
    }

    fn assignment_order_evaluation_nodes(&self, node: Node<'tree>) -> Vec<Node<'tree>> {
        let mut result = Vec::new();
        if node.kind() == "assignment_statement"
            && let Some(left) = node.child_by_field_name("left")
        {
            result.extend(self.assignment_target_order_nodes(left));
        }
        if let Some(right) = node.child_by_field_name("right") {
            result.extend(expression_sequence(right));
        }
        result
    }

    /// The flow kind for a write into an already-resolved name binding.
    ///
    /// Shared by the three statements that write one: simple assignment,
    /// compound assignment, and increment or decrement.
    fn binding_flow_kind(&self, name: &str, target: ValueId, byte: usize) -> ValueFlowKind {
        if Some(target) == self.receiver {
            ValueFlowKind::Receiver
        } else if self
            .local_at(name, byte)
            .is_some_and(|local| local == target)
            || self.captured_values.get(name).copied() == Some(target)
        {
            ValueFlowKind::Local
        } else {
            ValueFlowKind::Parameter
        }
    }

    fn append_binding_assignment(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        target: ValueId,
        value: ValueId,
        kind: ValueFlowKind,
    ) -> Result<(), GoLoweringError> {
        if let Some(identity) = self.value_types.get(&target).cloned() {
            self.value_types.insert(value, identity);
        }
        let storage = self.value_storage_kinds.get(&value).copied();
        if let Some(storage) = storage {
            self.value_storage_kinds.insert(target, storage);
        } else {
            self.value_storage_kinds.remove(&target);
        }
        if let Some(shape) = self.exact_slice_shapes.get(&value).copied() {
            self.exact_slice_shapes.insert(target, shape);
        } else {
            self.exact_slice_shapes.remove(&target);
        }
        self.append_effect(builder, point, SemanticEffect::Assignment { target, value })?;
        let kind = if kind == ValueFlowKind::Local {
            match storage {
                Some(GoStorageKind::Slice | GoStorageKind::Map) => ValueFlowKind::BackingStore {
                    offset: BackingStoreOffset::Zero,
                },
                Some(GoStorageKind::Array) if !self.fresh_array_values.contains(&value) => {
                    // A Go array assignment duplicates the whole aggregate
                    // bitwise; no distinct operation runs.
                    ValueFlowKind::Transfer(ValueTransfer {
                        kind: TransferKind::AggregateCopy,
                        operation: TransferOperation::None,
                    })
                }
                Some(GoStorageKind::Array) | None => kind,
            }
        } else {
            kind
        };
        self.append_effect(
            builder,
            point,
            SemanticEffect::ValueFlow {
                kind,
                source: value,
                target,
            },
        )?;
        if let Some((location, kind)) = self.shared_binding_locations.get(&target).copied() {
            self.append_effect(
                builder,
                point,
                SemanticEffect::MemoryStore {
                    kind,
                    location,
                    value,
                },
            )?;
        }
        Ok(())
    }

    fn assignment_conversion_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        source_node: Node<'tree>,
        source: ValueId,
    ) -> Result<ValueId, GoLoweringError> {
        let converted = self.source_value(
            builder,
            source_node,
            SemanticValueKind::LanguageDefined("go.assignment_conversion".into()),
        )?;
        self.session
            .append_language_defined_value_flows(builder, point, [source], converted)?;
        Ok(converted)
    }

    fn append_converted_binding_assignment(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        source_node: Node<'tree>,
        source: ValueId,
        target: ValueId,
        kind: ValueFlowKind,
    ) -> Result<(), GoLoweringError> {
        let converted = self.assignment_conversion_value(builder, point, source_node, source)?;
        self.append_binding_assignment(builder, point, target, converted, kind)
    }

    fn expression_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        kind: SemanticValueKind,
    ) -> Result<ValueId, GoLoweringError> {
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
        if let Some(identity) = self.expression_type_identity(node, node.start_byte()) {
            self.value_types.insert(value, identity);
        }
        if let Some(storage) = self.expression_storage_kind(node, node.start_byte()) {
            self.value_storage_kinds.insert(value, storage);
            if storage == GoStorageKind::Array
                && transparent_parenthesized_expression(node).kind() == "composite_literal"
            {
                self.fresh_array_values.insert(value);
            }
        }
        if let Some(shape) = self.expression_slice_shape(node, node.start_byte()) {
            self.exact_slice_shapes.insert(value, shape);
        }
        Ok(value)
    }

    fn source_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        kind: SemanticValueKind,
    ) -> Result<ValueId, GoLoweringError> {
        let metadata = self.value_mapping(builder, node)?;
        self.session
            .add_value_with_metadata(builder, metadata, kind)
    }

    fn multi_result_values(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        call: Node<'tree>,
        count: usize,
    ) -> Result<Box<[ValueId]>, GoLoweringError> {
        if let Some(values) = self.multi_result_values.get(&call.id()) {
            assert_eq!(values.len(), count, "one Go call has one result arity");
            return Ok(values.clone());
        }
        let mut values = Vec::with_capacity(count);
        for index in 0..count {
            values.push(self.source_value(
                builder,
                call,
                SemanticValueKind::LanguageDefined(format!("go.normal_result.{index}").into()),
            )?);
        }
        let values = values.into_boxed_slice();
        self.multi_result_values.insert(call.id(), values.clone());
        Ok(values)
    }

    fn visible_named_type_definition(
        &self,
        name: &str,
        byte: usize,
    ) -> Option<GoNamedTypeDefinition<'tree>> {
        visible_go_named_type(self.named_type_definitions, name, byte)
    }

    fn type_identity(&self, node: Node<'tree>, byte: usize) -> Option<GoTypeIdentity> {
        let mut identity = go_type_identity(node, self.prepared.source())?;
        if let Some((package, name)) = go_qualified_type_parts(node, self.prepared.source())
            && let Some(import_path) = self.import_bindings.get(package)
        {
            identity.name = format!("{import_path}.{name}").into();
        }
        identity.declaration = self
            .visible_named_type_definition(identity.name.as_ref(), byte)
            .map(|definition| definition.declaration);
        Some(identity)
    }

    fn type_storage_kind(&self, node: Node<'tree>, byte: usize) -> Option<GoStorageKind> {
        go_storage_kind_from_type(
            node,
            self.prepared.source(),
            self.named_type_definitions,
            byte,
        )
    }

    fn expression_type_identity(&self, node: Node<'tree>, byte: usize) -> Option<GoTypeIdentity> {
        match node.kind() {
            "identifier" | "true" | "false" | "nil" | "iota" => {
                let name = node_text(self.prepared.source(), node)?;
                let value = self.binding_value(name, byte)?;
                self.value_types.get(&value).cloned()
            }
            "parenthesized_expression" => first_runtime_named_child(node)
                .and_then(|child| self.expression_type_identity(child, byte)),
            "unary_expression" if unary_operator_kind(node) == Some("&") => {
                let operand = node.child_by_field_name("operand")?;
                let mut identity = self.expression_type_identity(operand, byte)?;
                identity.pointer_depth = identity.pointer_depth.checked_add(1)?;
                Some(identity)
            }
            "unary_expression" if unary_operator_kind(node) == Some("*") => {
                let operand = node.child_by_field_name("operand")?;
                let mut identity = self.expression_type_identity(operand, byte)?;
                identity.pointer_depth = identity.pointer_depth.checked_sub(1)?;
                Some(identity)
            }
            "composite_literal" => self.type_identity(node.child_by_field_name("type")?, byte),
            "call_expression" if self.is_builtin_new_call(node) => {
                let argument = all_call_arguments(node).into_iter().next()?;
                let mut identity = self.type_identity(argument, byte)?;
                identity.pointer_depth = identity.pointer_depth.checked_add(1)?;
                Some(identity)
            }
            _ => None,
        }
    }

    fn expression_storage_kind(&self, node: Node<'tree>, byte: usize) -> Option<GoStorageKind> {
        let node = transparent_parenthesized_expression(node);
        match node.kind() {
            "identifier" | "true" | "false" | "nil" | "iota" => {
                let name = node_text(self.prepared.source(), node)?;
                let value = self.binding_value(name, byte)?;
                self.value_storage_kinds.get(&value).copied()
            }
            "composite_literal" => self.type_storage_kind(node.child_by_field_name("type")?, byte),
            "selector_expression" => {
                let operand = node.child_by_field_name("operand")?;
                let field = node.child_by_field_name("field")?;
                let field_name = nonempty_node_text(self.prepared.source(), field)?;
                let declaration = self.expression_type_identity(operand, byte)?.declaration?;
                let definition = self
                    .named_type_definitions
                    .values()
                    .flatten()
                    .find(|definition| definition.declaration == declaration)?;
                let structure = go_file_underlying_type(
                    definition.underlying,
                    self.prepared.source(),
                    self.named_type_definitions,
                    byte,
                )?;
                named_children(structure)
                    .into_iter()
                    .filter(|child| child.kind() == "field_declaration_list")
                    .flat_map(named_children)
                    .filter(|child| child.kind() == "field_declaration")
                    .find(|declaration| {
                        children_by_field_name(*declaration, "name")
                            .into_iter()
                            .any(|name| {
                                nonempty_node_text(self.prepared.source(), name) == Some(field_name)
                            })
                    })
                    .and_then(|declaration| declaration.child_by_field_name("type"))
                    .and_then(|kind| self.type_storage_kind(kind, byte))
            }
            "slice_expression" => {
                let operand = node.child_by_field_name("operand")?;
                matches!(
                    self.expression_storage_kind(operand, byte),
                    Some(GoStorageKind::Array | GoStorageKind::Slice)
                )
                .then_some(GoStorageKind::Slice)
            }
            "call_expression"
                if self.builtin_make_allocation_kind(node) == Some(AllocationKind::Slice) =>
            {
                Some(GoStorageKind::Slice)
            }
            "call_expression"
                if self.builtin_make_allocation_kind(node) == Some(AllocationKind::Array) =>
            {
                Some(GoStorageKind::Map)
            }
            "call_expression" if self.exact_append_backing(node).is_some() => {
                Some(GoStorageKind::Slice)
            }
            _ => None,
        }
    }

    fn expression_slice_shape(&self, node: Node<'tree>, byte: usize) -> Option<ExactSliceShape> {
        let node = transparent_parenthesized_expression(node);
        match node.kind() {
            "identifier" | "true" | "false" | "nil" | "iota" => {
                let name = node_text(self.prepared.source(), node)?;
                let value = self.binding_value(name, byte)?;
                self.exact_slice_shapes.get(&value).copied()
            }
            "composite_literal" if node.child_by_field_name("type")?.kind() == "slice_type" => {
                let body = node.child_by_field_name("body")?;
                let elements = named_children(body)
                    .into_iter()
                    .filter(|child| child.kind() != "comment")
                    .collect::<Vec<_>>();
                if elements
                    .iter()
                    .any(|element| element.kind() == "keyed_element")
                {
                    return None;
                }
                let length = elements.len() as u128;
                Some(ExactSliceShape {
                    length,
                    capacity: length,
                })
            }
            "call_expression"
                if self.builtin_make_allocation_kind(node) == Some(AllocationKind::Slice) =>
            {
                let arguments = all_call_arguments(node);
                let length = go_integer_literal_value(self.prepared.source(), arguments[1])?;
                let capacity = match arguments.get(2) {
                    Some(capacity) => go_integer_literal_value(self.prepared.source(), *capacity)?,
                    None => length,
                };
                (length <= capacity).then_some(ExactSliceShape { length, capacity })
            }
            "slice_expression" => {
                let source = node.child_by_field_name("operand")?;
                let source_shape = self.expression_slice_shape(source, byte)?;
                let start = node
                    .child_by_field_name("start")
                    .map(|start| go_integer_literal_value(self.prepared.source(), start))
                    .unwrap_or(Some(0))?;
                let end = node
                    .child_by_field_name("end")
                    .map(|end| go_integer_literal_value(self.prepared.source(), end))
                    .unwrap_or(Some(source_shape.length))?;
                let length = end.checked_sub(start)?;
                let capacity = source_shape.capacity.checked_sub(start)?;
                (end <= source_shape.capacity).then_some(ExactSliceShape { length, capacity })
            }
            "call_expression" => match self.exact_append_backing(node)? {
                ExactAppendBacking::Retained { result_shape, .. } => Some(result_shape),
                ExactAppendBacking::Replaced { .. } => None,
            },
            _ => None,
        }
    }

    fn exact_append_backing(&self, node: Node<'tree>) -> Option<ExactAppendBacking> {
        let source_node = self.builtin_append_source(node)?;
        let source_name = node_text(self.prepared.source(), source_node)?;
        let source = self.binding_value(source_name, node.start_byte())?;
        let shape = self.exact_slice_shapes.get(&source).copied()?;
        let arguments = all_call_arguments(node);
        if !arguments[1..]
            .iter()
            .all(|argument| self.is_go_constant_evaluation(*argument))
        {
            return None;
        }
        let added = u128::try_from(arguments.len().checked_sub(1)?).ok()?;
        let length = shape.length.checked_add(added)?;
        if length <= shape.capacity {
            Some(ExactAppendBacking::Retained {
                source,
                append_start: shape.length,
                result_shape: ExactSliceShape {
                    length,
                    capacity: shape.capacity,
                },
            })
        } else {
            Some(ExactAppendBacking::Replaced {
                append_start: shape.length,
            })
        }
    }

    fn expression_has_boolean_domain(&self, node: Node<'tree>) -> bool {
        let node = transparent_parenthesized_expression(node);
        if matches!(node.kind(), "true" | "false")
            && self.predeclared_constant_has_builtin_meaning(node)
        {
            return true;
        }
        self.expression_type_identity(node, node.start_byte())
            .is_some_and(|identity| {
                identity.name.as_ref() == "bool"
                    && identity.pointer_depth == 0
                    && identity.declaration.is_none()
            })
    }

    fn is_direct_value_field(&self, selector: Node<'tree>) -> bool {
        // Reading a depth-zero field from a proven nonpointer value requires
        // no implicit dereference. Keep every selector outside this exact
        // same-file type and declaration proof conservatively unknown.
        let Some(operand) = selector.child_by_field_name("operand") else {
            return false;
        };
        let Some(identity) = self.expression_type_identity(operand, selector.start_byte()) else {
            return false;
        };
        if identity.pointer_depth != 0 {
            return false;
        }

        let Some(field_name) = selector
            .child_by_field_name("field")
            .and_then(|field| nonempty_node_text(self.prepared.source(), field))
        else {
            return false;
        };
        identity
            .declaration
            .and_then(|declaration| self.direct_struct_fields.get(&declaration))
            .is_some_and(|fields| fields.contains(field_name))
    }

    /// The memory-location identity of `operand.field`, and whether it is the
    /// field's own declaration.
    ///
    /// Go auto-dereferences a pointer to a struct, so `holder.Value` and
    /// `pointer.Value` name the same field of the same struct type; the
    /// operand's pointer depth is deliberately ignored. When the file does not
    /// state the declaration -- an unresolved operand type, an imported struct,
    /// a name two structs share -- the locator falls back to one interned
    /// per field name per procedure. That fallback still lets a store and a
    /// load of one name meet, which anchoring each occurrence separately would
    /// silently prevent, and the caller publishes a field-identity gap for it.
    fn memory_member_locator(
        &mut self,
        operand: Node<'tree>,
        field: Node<'tree>,
    ) -> Result<(SemanticLocator, bool), GoLoweringError> {
        let name = node_text(self.prepared.source(), field);
        let declaration_anchor = name.and_then(|name| {
            let identity = self.expression_type_identity(operand, operand.start_byte())?;
            let declaration = identity.declaration?;
            self.struct_field_anchors
                .get(&(declaration, name.into()))
                .copied()
        });
        if let Some(name) = name
            && declaration_anchor.is_none()
            && let Some(locator) = self.field_locators.get(name)
        {
            return Ok((locator.clone(), false));
        }
        let resolved = declaration_anchor.is_some();
        let anchor = match declaration_anchor {
            Some(anchor) => anchor,
            None => source_anchor(field, 0).map_err(GoLoweringError::Invalid)?,
        };
        let procedure = self.session.locator();
        let locator = SemanticLocator::new(
            procedure.mount(),
            procedure.path().clone(),
            procedure.language(),
            procedure.declaration().clone(),
            SemanticRole::MemoryLocation,
            anchor,
        );
        if !resolved && let Some(name) = name {
            self.field_locators.insert(name.into(), locator.clone());
        }
        Ok((locator, resolved))
    }

    fn package_static_location(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        name: &str,
    ) -> Result<Option<MemoryLocationId>, GoLoweringError> {
        if let Some(location) = self.static_locations.get(name).copied() {
            return Ok(Some(location));
        }
        let Some(member) = self.package_value_locators.get(name).cloned() else {
            return Ok(None);
        };
        let location = self.session.add_memory_location(
            builder,
            point,
            MemoryLocationKind::Static { member },
        )?;
        self.static_locations.insert(name.into(), location);
        Ok(Some(location))
    }

    /// Materialize the structured location named by one selector or index
    /// place without claiming that the place is accessed. Address-of, loads,
    /// stores, compound updates, range bindings, and multi-result assignments
    /// must share this interpretation so the same source-level place never
    /// acquires incompatible location identities.
    fn memory_place_location(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        place: Node<'tree>,
    ) -> Result<Option<MemoryPlaceLocation>, GoLoweringError> {
        let place = transparent_parenthesized_expression(place);
        match place.kind() {
            "selector_expression" if !self.selector_denotes_no_location(place) => {
                let operand =
                    transparent_parenthesized_expression(required_field(place, "operand")?);
                let field = required_field(place, "field")?;
                let base =
                    self.expression_value(builder, operand, self.expression_value_kind(operand))?;
                let (member, resolved) = self.memory_member_locator(operand, field)?;
                let location = self.session.add_memory_location(
                    builder,
                    point,
                    MemoryLocationKind::Field { base, member },
                )?;
                if !resolved {
                    self.add_field_identity_gap(builder, point, location)?;
                }
                Ok(Some((MemoryAccessKind::Field, location, None)))
            }
            "index_expression"
                if place
                    .child_by_field_name("index")
                    .is_some_and(|index| !is_go_type_syntax(index.kind())) =>
            {
                let operand = required_field(place, "operand")?;
                let index_node = required_field(place, "index")?;
                let base =
                    self.expression_value(builder, operand, self.expression_value_kind(operand))?;
                let constant_index = self.canonical_integer_index_value(builder, index_node)?;
                let index = match constant_index {
                    Some((value, _)) => value,
                    None => self.expression_value(
                        builder,
                        index_node,
                        self.expression_value_kind(index_node),
                    )?,
                };
                let location = self.session.add_memory_location(
                    builder,
                    point,
                    MemoryLocationKind::Index {
                        base,
                        index: Some(index),
                        constant_index: constant_index.map(|(_, magnitude)| magnitude),
                        identity: if self.expression_storage_kind(operand, operand.start_byte())
                            == Some(GoStorageKind::Map)
                        {
                            crate::analyzer::semantic::IndexedLocationIdentity::Aggregate
                        } else {
                            crate::analyzer::semantic::IndexedLocationIdentity::Element
                        },
                    },
                )?;
                Ok(Some((
                    MemoryAccessKind::Index,
                    location,
                    Some((index, constant_index.is_some())),
                )))
            }
            _ => Ok(None),
        }
    }

    /// Materialize a place that is actually loaded or stored and publish the
    /// remaining flow-state limitation for indexed memory. Merely taking a
    /// place's address must use `memory_place_location` directly: an address
    /// does not discharge an index identity through a fabricated access.
    fn memory_access_location(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        place: Node<'tree>,
    ) -> Result<Option<(MemoryAccessKind, MemoryLocationId)>, GoLoweringError> {
        let Some((kind, location, index)) = self.memory_place_location(builder, point, place)?
        else {
            return Ok(None);
        };
        if kind == MemoryAccessKind::Index {
            // Flow-state does not yet project indexed properties. Keep that
            // omission explicit even when the IR can prove a literal index
            // identity for value-flow consumers.
            self.add_unprojected_index_gap(
                builder,
                point,
                location,
                index.is_some_and(|(_, exact)| exact),
            )?;
        }
        Ok(Some((kind, location)))
    }

    /// Reuse one procedure-local value for each structured integer-literal
    /// magnitude. A dynamic expression, including a local rebound to a
    /// constant, deliberately remains unknown until constant propagation can
    /// prove its value.
    fn canonical_integer_index_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<Option<(ValueId, u128)>, GoLoweringError> {
        let Some(index) = go_integer_literal_value(self.prepared.source(), node) else {
            return Ok(None);
        };
        if let Some(value) = self.constant_index_values.get(&index).copied() {
            self.expression_values.insert(node.id(), value);
            return Ok(Some((value, index)));
        }
        let value =
            self.expression_value(builder, node, SemanticValueKind::UnsignedInteger(index))?;
        self.constant_index_values.insert(index, value);
        Ok(Some((value, index)))
    }

    fn add_field_identity_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        location: MemoryLocationId,
    ) -> Result<(), GoLoweringError> {
        self.session.add_gap_with_impacts(
            builder,
            point,
            SemanticGapSubject::MemoryLocation(location),
            SemanticCapability::FieldMemory,
            SemanticGapImpacts::single(SemanticGapImpact::HeapRead)
                .with(SemanticGapImpact::HeapWrite)
                .with(SemanticGapImpact::Aliasing),
            SemanticGapKind::Unknown,
            "Go field occurrence is structured, but its struct declaration identity is not yet resolved",
        )?;
        Ok(())
    }

    fn add_unprojected_index_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        location: MemoryLocationId,
        exact_index: bool,
    ) -> Result<(), GoLoweringError> {
        let discharge = if exact_index {
            // Canonical literal magnitude is the cross-occurrence identity
            // value-flow needs; this marker deliberately says nothing about
            // flow-state indexed-property projection. A dynamic structured
            // index remains available for scalar refinement without claiming
            // that discharge.
            SemanticGapDischarge::CanonicalIndexIdentity
        } else {
            SemanticGapDischarge::None
        };
        self.session.add_gap_with_impacts_and_discharge(
            builder,
            point,
            SemanticGapSubject::MemoryLocation(location),
            SemanticCapability::IndexMemory,
            SemanticGapImpacts::single(SemanticGapImpact::HeapRead)
                .with(SemanticGapImpact::HeapWrite)
                .with(SemanticGapImpact::Aliasing),
            SemanticGapKind::Unsupported,
            discharge,
            "Go index identity is deliberately unprojected from flow state",
        )?;
        Ok(())
    }

    /// Whether a selector denotes no runtime memory location.
    ///
    /// Two shapes read like a field access but are not one: a call's callee
    /// (`pkg.Func(...)`, `receiver.Method(...)`, whose selection the call site
    /// already models), and a package qualifier, whose root identifier names
    /// no value this procedure binds and carries no value type. Minting a
    /// `Field` location for either would publish an undischargeable
    /// field-memory gap on syntax that holds nothing.
    fn selector_denotes_no_location(&self, node: Node<'tree>) -> bool {
        match self.selector_resolution(node) {
            GoSelectorResolution::Package | GoSelectorResolution::Method { .. } => return true,
            GoSelectorResolution::Field => return false,
            GoSelectorResolution::Unknown => {}
        }
        let Some(operand) = node.child_by_field_name("operand") else {
            return true;
        };
        if !is_go_binding_reference_kind(operand.kind()) {
            return false;
        }
        let Some(name) = node_text(self.prepared.source(), operand) else {
            return true;
        };
        self.binding_value(name, operand.start_byte()).is_none()
            && self
                .expression_type_identity(operand, operand.start_byte())
                .is_none()
    }

    fn is_builtin_new_call(&self, node: Node<'tree>) -> bool {
        if node.kind() != "call_expression"
            || self.predeclared_shadowed.new
            || all_call_arguments(node).len() != 1
        {
            return false;
        }
        let Some(function) = node.child_by_field_name("function") else {
            return false;
        };
        if function.kind() != "identifier"
            || node_text(self.prepared.source(), function) != Some("new")
            || self.binding_value("new", node.start_byte()).is_some()
        {
            return false;
        }
        all_call_arguments(node)
            .into_iter()
            .next()
            .is_some_and(|argument| is_go_type_syntax(argument.kind()))
    }

    /// Return the runtime operand when call-shaped Go syntax is exactly a
    /// conversion to a locally visible type. Tree-sitter gives named scalar
    /// conversions such as `error(nil)` the same shape as an invocation, so
    /// the adapter must consult structured binding and type inventories before
    /// publishing a call site.
    fn call_shaped_type_conversion_operand(&self, node: Node<'tree>) -> Option<Node<'tree>> {
        if node.kind() != "call_expression" {
            return None;
        }
        let arguments = all_call_arguments(node);
        let [operand] = arguments.as_slice() else {
            return None;
        };
        let mut function = node.child_by_field_name("function")?;
        loop {
            match function.kind() {
                "parenthesized_expression" => function = first_named_child(function)?,
                "unary_expression" if unary_operator_kind(function) == Some("*") => {
                    function = required_field(function, "operand").ok()?;
                }
                _ => break,
            }
        }
        if is_go_type_syntax(function.kind()) {
            return Some(*operand);
        }
        if function.kind() != "identifier" {
            return None;
        }
        let name = node_text(self.prepared.source(), function)?;
        let byte = function.start_byte();
        let value_shadowed = self.binding_value(name, byte).is_some()
            || self.package_functions.contains(name)
            || self.package_values.contains(name)
            || self.import_bindings.contains_key(name);
        (!value_shadowed
            && (is_predeclared_go_type(name)
                || visible_go_named_type(self.named_type_definitions, name, byte).is_some()))
        .then_some(*operand)
    }

    fn builtin_make_allocation_kind(&self, node: Node<'tree>) -> Option<AllocationKind> {
        if node.kind() != "call_expression" || self.predeclared_shadowed.make {
            return None;
        }
        let function = node.child_by_field_name("function")?;
        if function.kind() != "identifier"
            || node_text(self.prepared.source(), function) != Some("make")
            || self.binding_value("make", node.start_byte()).is_some()
        {
            return None;
        }
        let arguments = all_call_arguments(node);
        match arguments.as_slice() {
            [kind, _] | [kind, _, _] if kind.kind() == "slice_type" => Some(AllocationKind::Slice),
            [kind] | [kind, _] if kind.kind() == "map_type" => Some(AllocationKind::Array),
            [kind] | [kind, _] if kind.kind() == "channel_type" => {
                Some(AllocationKind::LanguageDefined("go-channel".into()))
            }
            _ => None,
        }
    }

    fn builtin_append_source(&self, node: Node<'tree>) -> Option<Node<'tree>> {
        if node.kind() != "call_expression" || self.predeclared_shadowed.append {
            return None;
        }
        let function = node.child_by_field_name("function")?;
        if function.kind() != "identifier"
            || node_text(self.prepared.source(), function) != Some("append")
            || self.binding_value("append", node.start_byte()).is_some()
        {
            return None;
        }
        let arguments = all_call_arguments(node);
        (arguments.len() >= 2
            && arguments[1..]
                .iter()
                .all(|argument| argument.kind() != "variadic_argument"))
        .then_some(arguments[0])
    }

    fn is_import_qualifier(&self, node: Node<'tree>) -> bool {
        if node.kind() != "identifier" {
            return false;
        }
        let Some(name) = node_text(self.prepared.source(), node) else {
            return false;
        };
        self.import_bindings.contains_key(name)
            && self
                .omitted_capture_names
                .binary_search_by(|capture| capture.as_ref().cmp(name))
                .is_err()
            && self.binding_value(name, node.start_byte()).is_none()
    }

    /// The single runtime argument of a `panic(v)` that still carries the
    /// predeclared builtin meaning.
    ///
    /// `panic` is an ordinary predeclared identifier, so a program that
    /// declares its own `panic` keeps the ordinary call lowering, exactly as
    /// `new`, `true`, and `false` do.
    fn builtin_panic_argument(&self, node: Node<'tree>) -> Option<Node<'tree>> {
        if node.kind() != "call_expression" || self.predeclared_shadowed.panic {
            return None;
        }
        let function = node.child_by_field_name("function")?;
        if function.kind() != "identifier"
            || node_text(self.prepared.source(), function) != Some("panic")
            || self.binding_value("panic", node.start_byte()).is_some()
        {
            return None;
        }
        let [argument] = call_arguments(node)[..] else {
            return None;
        };
        // A spread `panic(vs...)` is not legal Go, so a variadic argument here
        // is not a builtin panic.
        (argument.kind() != "variadic_argument").then_some(argument)
    }

    /// The channel argument of an unshadowed predeclared `close(ch)` call.
    fn builtin_close_argument(&self, node: Node<'tree>) -> Option<Node<'tree>> {
        if node.kind() != "call_expression" || self.predeclared_shadowed.close {
            return None;
        }
        let function = node.child_by_field_name("function")?;
        if function.kind() != "identifier"
            || node_text(self.prepared.source(), function) != Some("close")
            || self.binding_value("close", node.start_byte()).is_some()
        {
            return None;
        }
        let [argument] = call_arguments(node)[..] else {
            return None;
        };
        (argument.kind() != "variadic_argument").then_some(argument)
    }

    fn emit_lexical_input_flow(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        point: ProgramPointId,
        target: ValueId,
    ) -> Result<(), GoLoweringError> {
        let Some(name) = node_text(self.prepared.source(), node) else {
            return Ok(());
        };
        let Some(source) = self.binding_value(name, node.start_byte()) else {
            if let Some(location) = self.package_static_location(builder, point, name)? {
                let metadata = self.value_mapping(builder, node)?;
                self.session.append_effect_with_metadata(
                    builder,
                    point,
                    metadata,
                    SemanticEffect::MemoryLoad {
                        kind: MemoryAccessKind::Static,
                        location,
                        result: target,
                    },
                )?;
            }
            return Ok(());
        };
        if let Some((location, kind)) = self.shared_binding_locations.get(&source).copied() {
            let metadata = self.value_mapping(builder, node)?;
            self.session.append_effect_with_metadata(
                builder,
                point,
                metadata,
                SemanticEffect::MemoryLoad {
                    kind,
                    location,
                    result: target,
                },
            )?;
            return Ok(());
        }
        let kind = if Some(source) == self.receiver {
            ValueFlowKind::Receiver
        } else if self.local_at(name, node.start_byte()) == Some(source)
            || self.captured_values.get(name).copied() == Some(source)
        {
            ValueFlowKind::Local
        } else {
            ValueFlowKind::Parameter
        };
        if source != target {
            // `point` is the entry selected by the enclosing evaluation and
            // may be wider than this identifier (for example `(value)`). The
            // lexical read event is spelled by the identifier itself, so keep
            // its exact mapping instead of inheriting the wrapper's metadata.
            let metadata = self.value_mapping(builder, node)?;
            self.session.append_effect_with_metadata(
                builder,
                point,
                metadata,
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
    ) -> Result<(), GoLoweringError> {
        if self.session.cancellation().is_cancelled() {
            return Err(GoLoweringError::Cancelled(Box::default()));
        }
        match work {
            Work::Statement {
                node,
                entry,
                next,
                scope,
                label,
            } => self.statement(builder, node, entry, next, scope, label, stack),
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
            Work::DeferredCall {
                node,
                entry,
                next,
                scope,
            } => self.deferred_call_expression(builder, node, entry, next, scope, stack),
            Work::RetainContinuations { mut cursor } => {
                while cursor < self.statement_continuations.len() {
                    let continuation = StatementContinuationId::try_from_index(cursor)?;
                    cursor += 1;
                    if self.materialized_continuations.contains(&continuation) {
                        continue;
                    }
                    let scope = self.statement_continuations[continuation.index()].retention_scope;
                    stack.push(Work::RetainContinuations { cursor });
                    self.materialize_statement_next(
                        builder,
                        StatementNext::Continuation(continuation),
                        scope,
                        stack,
                    )?;
                    break;
                }
                Ok(())
            }
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
    ) -> Result<(), GoLoweringError> {
        // A folded literal keeps exactly one arm. Recording the guard is what
        // keeps the fold legible: nothing else in the frozen artifact says the
        // branch was constant (#2443).
        if let Some(value) = self.folded_boolean_constant(node) {
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
        let normalized_unary =
            if node.kind() == "unary_expression" && unary_operator_kind(node) == Some("!") {
                let (operand, negated) = self.peel_condition_wrappers(node)?;
                let normalized = self.normalize_peeled_condition(builder, operand, negated)?;
                if normalized.is_none() {
                    // With no normalized outer predicate, negation changes the
                    // operand's outcome, not its identity. Peel the whole wrapper
                    // chain once, keep the terminal decision, and carry the net
                    // polarity into its continuations.
                    let (when_true, when_false) = if negated {
                        (when_false, when_true)
                    } else {
                        (when_true, when_false)
                    };
                    stack.push(Work::Condition {
                        node: operand,
                        entry,
                        when_true,
                        when_false,
                        scope,
                    });
                    return Ok(());
                }
                normalized
            } else {
                None
            };
        if let Some(value) =
            normalized_unary
                .as_ref()
                .and_then(|(predicate, subject)| match (predicate, subject) {
                    (GuardPredicate::ConstantBoolean { value }, None) => Some(*value),
                    _ => None,
                })
        {
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
        match (node.kind(), go_boolean_operator_kind(node)) {
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
            _ => {
                let decision = self.point(builder, node, Vec::new())?;
                self.edge(builder, decision, when_true)?;
                self.edge(builder, decision, when_false)?;
                let normalized = match normalized_unary {
                    Some(normalized) => Some(normalized),
                    None => self.normalize_condition(builder, node)?,
                };
                let (predicate, subject) = match normalized {
                    Some(normalized) => normalized,
                    None => (
                        GuardPredicate::Opaque {
                            digest: GuardConditionDigest::from_syntax_kind(node.kind()),
                        },
                        // The condition's own value is the one thing an
                        // unnormalized guard can honestly name: the decision
                        // tested it, whatever it means.
                        Some(self.expression_value(
                            builder,
                            node,
                            self.expression_value_kind(node),
                        )?),
                    ),
                };
                self.record_guard(
                    builder,
                    decision,
                    predicate,
                    subject,
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

    fn predeclared_constant_has_builtin_meaning(&self, node: Node<'tree>) -> bool {
        let name = node.kind();
        is_go_predeclared_constant_kind(name)
            && !self.predeclared_shadowed.shadows(name)
            && !self.package_shadowing.shadows(name)
            && self.binding_value(name, node.start_byte()).is_none()
            && !self
                .omitted_capture_names
                .iter()
                .any(|captured| captured.as_ref() == name)
    }

    fn is_go_constant_value(&self, node: Node<'tree>) -> bool {
        is_go_literal_value_kind(node.kind()) || self.predeclared_constant_has_builtin_meaning(node)
    }

    fn expression_value_kind(&self, node: Node<'tree>) -> SemanticValueKind {
        if self.is_context_done_on_formal(node) {
            SemanticValueKind::LanguageDefined("go.context_done_formal_channel".into())
        } else if node.kind() == "func_literal"
            || node.parent().is_some_and(|parent| {
                parent.kind() == "call_expression"
                    && field_matches(parent, "function", node)
                    && parent
                        .parent()
                        .is_some_and(|statement| statement.kind() == "defer_statement")
            })
            || (node.kind() == "selector_expression"
                && (matches!(
                    self.selector_resolution(node),
                    GoSelectorResolution::Method { .. }
                ) || node.parent().is_some_and(|parent| {
                    parent.kind() == "call_expression" && field_matches(parent, "function", node)
                })))
        {
            SemanticValueKind::Callable
        } else if node.kind() == "unary_expression" && unary_operator_kind(node) == Some("&") {
            SemanticValueKind::Address
        } else if node.kind() == "nil" && self.predeclared_constant_has_builtin_meaning(node) {
            SemanticValueKind::Null
        } else if let Some(value) = self.folded_boolean_constant(node) {
            SemanticValueKind::Boolean(value)
        } else if let Some(value) = go_integer_literal_value(self.prepared.source(), node) {
            SemanticValueKind::UnsignedInteger(value)
        } else if self.is_go_constant_value(node) {
            SemanticValueKind::Constant
        } else {
            SemanticValueKind::Temporary
        }
    }

    fn is_context_done_on_formal(&self, node: Node<'tree>) -> bool {
        if node.kind() != "call_expression" {
            return false;
        }
        let Some(function) = node.child_by_field_name("function") else {
            return false;
        };
        if function.kind() != "selector_expression"
            || function
                .child_by_field_name("field")
                .and_then(|field| node_text(self.prepared.source(), field))
                != Some("Done")
        {
            return false;
        }
        let Some(operand) = function.child_by_field_name("operand") else {
            return false;
        };
        let operand = transparent_parenthesized_expression(operand);
        if self
            .expression_type_identity(operand, operand.start_byte())
            .is_none_or(|identity| {
                identity.pointer_depth != 0 || identity.name.as_ref() != "context.Context"
            })
        {
            return false;
        }
        let Some(name) = node_text(self.prepared.source(), operand) else {
            return false;
        };
        let Some(value) = self.binding_value(name, operand.start_byte()) else {
            return false;
        };
        self.parameters
            .values()
            .any(|parameter| *parameter == value)
            || self.receiver == Some(value)
    }

    /// The compile-time boolean a condition names, when `true` and `false`
    /// still carry the meaning Go predeclares for them.
    ///
    /// Both are ordinary predeclared identifiers, so a program may rebind
    /// either one. A rebound spelling folds nothing and falls through to the
    /// opaque decision arm, where the decision is still recorded.
    fn folded_boolean_constant(&self, node: Node<'tree>) -> Option<bool> {
        let value = match node.kind() {
            "true" => true,
            "false" => false,
            _ => return None,
        };
        let name = if value { "true" } else { "false" };
        (node.kind() == name && self.predeclared_constant_has_builtin_meaning(node))
            .then_some(value)
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
    ) -> Result<(), GoLoweringError> {
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

    /// Peel transparent condition wrappers once. Parentheses and logical
    /// negation change no value identity; only negation changes polarity.
    fn peel_condition_wrappers(
        &self,
        condition: Node<'tree>,
    ) -> Result<(Node<'tree>, bool), GoLoweringError> {
        let mut cursor = condition;
        let mut negated = false;
        loop {
            match cursor.kind() {
                "parenthesized_expression" => {
                    cursor = first_runtime_named_child(cursor)
                        .ok_or_else(|| missing_field(cursor, "value"))?;
                }
                "unary_expression" if unary_operator_kind(cursor) == Some("!") => {
                    let operand = required_field(cursor, "operand")?;
                    negated = !negated;
                    cursor = operand;
                }
                _ => break,
            }
        }
        Ok((cursor, negated))
    }

    /// Normalize only condition shapes established by Go's tree-sitter fields.
    fn normalize_condition(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        condition: Node<'tree>,
    ) -> Result<Option<(GuardPredicate, Option<ValueId>)>, GoLoweringError> {
        let (condition, negated) = self.peel_condition_wrappers(condition)?;
        self.normalize_peeled_condition(builder, condition, negated)
    }

    fn normalize_peeled_condition(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        condition: Node<'tree>,
        negated: bool,
    ) -> Result<Option<(GuardPredicate, Option<ValueId>)>, GoLoweringError> {
        let cursor = condition;

        match cursor.kind() {
            "true" | "false" => {
                let Some(value) = self.folded_boolean_constant(cursor) else {
                    return Ok(None);
                };
                return Ok(Some((
                    GuardPredicate::ConstantBoolean {
                        value: value ^ negated,
                    },
                    None,
                )));
            }
            "binary_expression" => {}
            _ => return Ok(None),
        }

        let Some(operator) = cursor.child_by_field_name("operator") else {
            return Ok(None);
        };
        let equal_on_true = match operator.kind() {
            "==" => !negated,
            "!=" => negated,
            _ => return Ok(None),
        };
        let (Some(left), Some(right)) = (
            cursor.child_by_field_name("left"),
            cursor.child_by_field_name("right"),
        ) else {
            return Ok(None);
        };

        let nil_subject = match (
            left.kind() == "nil" && self.is_go_constant_value(left),
            right.kind() == "nil" && self.is_go_constant_value(right),
        ) {
            (true, false) => Some(right),
            (false, true) => Some(left),
            (true, true) | (false, false) => None,
        };
        if let Some(subject) = nil_subject {
            let subject =
                self.expression_value(builder, subject, self.expression_value_kind(subject))?;
            return Ok(Some((
                GuardPredicate::NullComparison {
                    null_on_true: equal_on_true,
                },
                Some(subject),
            )));
        }

        let left_constant = self.is_go_constant_value(left);
        let right_constant = self.is_go_constant_value(right);
        let (subject, constant) = match (left_constant, right_constant) {
            (true, false) => (right, left),
            (false, true) => (left, right),
            (true, true) | (false, false) => return Ok(None),
        };
        let constant =
            self.expression_value(builder, constant, self.expression_value_kind(constant))?;
        let subject =
            self.expression_value(builder, subject, self.expression_value_kind(subject))?;
        Ok(Some((
            GuardPredicate::ConstantEquality {
                negated: !equal_on_true,
                constant,
            },
            Some(subject),
        )))
    }

    #[allow(clippy::too_many_arguments)]
    fn statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: StatementNext,
        scope: ScopeFrameId,
        attached_label: Option<Node<'tree>>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), GoLoweringError> {
        match node.kind() {
            "block" => {
                let children = named_children(node);
                self.schedule_statements(builder, entry, &children, next, scope, stack)
            }
            "statement_list" => {
                let children = named_children(node);
                self.schedule_statements(builder, entry, &children, next, scope, stack)
            }
            "expression_statement" => {
                let next = self.materialize_statement_next(builder, next, scope, stack)?;
                let expressions = named_children(node);
                self.note_deterministic_evaluation_order(builder, entry, node, &expressions)?;
                self.schedule_expressions(builder, entry, &expressions, next, scope, stack)
            }
            "return_statement" => self.return_statement(builder, node, entry, scope, stack),
            "break_statement" | "continue_statement" => {
                let completion = if node.kind() == "break_statement" {
                    CompletionKind::Break
                } else {
                    CompletionKind::Continue
                };
                let label_node = control_label_node(node);
                let label = label_node.and_then(|label| node_text(self.prepared.source(), label));
                self.abrupt(builder, entry, scope, completion, label, stack)
            }
            "labeled_statement" => {
                let label = required_field(node, "label")?;
                let statement = named_children(node)
                    .into_iter()
                    .find(|child| child.id() != label.id())
                    .ok_or_else(|| missing_field(node, "statement"))?;
                stack.push(Work::Statement {
                    node: statement,
                    entry,
                    next,
                    scope,
                    label: Some(label),
                });
                Ok(())
            }
            "if_statement" => self.if_statement(builder, node, entry, next, scope, stack),
            "for_statement" => {
                let next = self.materialize_statement_next(builder, next, scope, stack)?;
                self.for_statement(builder, node, entry, next, scope, attached_label, stack)
            }
            "expression_switch_statement" => {
                let next = self.materialize_statement_next(builder, next, scope, stack)?;
                self.expression_switch_statement(
                    builder,
                    node,
                    entry,
                    next,
                    scope,
                    attached_label,
                    stack,
                )
            }
            "type_switch_statement" => {
                self.type_switch_boundary(builder, node, entry, scope, stack)
            }
            "select_statement" => {
                let next = self.materialize_statement_next(builder, next, scope, stack)?;
                self.select_boundary(builder, node, entry, next, scope, stack)
            }
            "defer_statement" | "go_statement" => {
                self.deferred_or_spawned_call(builder, node, entry, next, scope, stack)
            }
            "goto_statement" | "fallthrough_statement" => self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::NonLocalControl,
                SemanticGapKind::Unsupported,
                if node.kind() == "goto_statement" {
                    "goto label resolution and transfer are not lowered"
                } else {
                    "fallthrough outside a terminal switch-case position is invalid or not lowered"
                },
            ),
            "send_statement" | "receive_statement" => {
                let next = self.materialize_statement_next(builder, next, scope, stack)?;
                self.communication_statement(builder, node, entry, next, scope, stack)
            }
            "assignment_statement" | "short_var_declaration" => {
                let next = self.materialize_statement_next(builder, next, scope, stack)?;
                self.assignment_statement(builder, node, entry, next, scope, stack)
            }
            "inc_statement" | "dec_statement" => {
                let next = self.materialize_statement_next(builder, next, scope, stack)?;
                self.increment_statement(builder, node, entry, next, scope, stack)
            }
            "var_declaration" => {
                let next = self.materialize_statement_next(builder, next, scope, stack)?;
                self.var_declaration(builder, node, entry, next, scope, stack)
            }
            "const_declaration"
            | "type_declaration"
            | "function_declaration"
            | "method_declaration"
            | "empty_statement" => {
                let next = self.materialize_statement_next(builder, next, scope, stack)?;
                self.edge(builder, entry, next)
            }
            _ => self.unhandled_control_syntax(builder, node, entry),
        }
    }

    fn return_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), GoLoweringError> {
        let values = runtime_expression_children(node);
        let terminal = if values.is_empty() {
            entry
        } else {
            self.point(builder, node, Vec::new())?
        };
        let value = (values.len() == 1)
            .then(|| self.value(builder, terminal, SemanticValueKind::Return))
            .transpose()?;
        if let ([source_node], Some(target)) = (values.as_slice(), value) {
            let source = self.expression_value(
                builder,
                *source_node,
                self.expression_value_kind(*source_node),
            )?;
            let identity_preserving =
                self.return_shape_supported && source_node.kind() != "type_conversion_expression";
            if identity_preserving {
                self.append_effect(
                    builder,
                    terminal,
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Return,
                        source,
                        target,
                    },
                )?;
            } else {
                self.add_gap(
                    builder,
                    terminal,
                    SemanticGapSubject::Value(target),
                    SemanticCapability::ReturnFlow,
                    if self.return_shape_supported {
                        SemanticGapKind::Unknown
                    } else {
                        SemanticGapKind::Unsupported
                    },
                    if self.return_shape_supported {
                        "explicit Go return conversion result identity is intentionally not propagated"
                    } else {
                        "Go named, tuple, and multi-result return flow is not yet lowered"
                    },
                )?;
            }
        } else if values.len() > 1 {
            for (ordinal, source_node) in values.iter().copied().enumerate() {
                let target = self.value(builder, terminal, SemanticValueKind::Return)?;
                if source_node.kind() == "type_conversion_expression" {
                    self.add_gap(
                        builder,
                        terminal,
                        SemanticGapSubject::Value(target),
                        SemanticCapability::ReturnFlow,
                        SemanticGapKind::Unknown,
                        "explicit Go return conversion result identity is intentionally not propagated",
                    )?;
                    continue;
                }
                let source = self.expression_value(
                    builder,
                    source_node,
                    self.expression_value_kind(source_node),
                )?;
                self.append_effect(
                    builder,
                    terminal,
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::IndexedReturn {
                            ordinal: ordinal as u32,
                        },
                        source,
                        target,
                    },
                )?;
            }
        }
        if !values.is_empty() && !self.named_results.is_empty() {
            let assigned = if values.len() == self.named_results.len() {
                values
                    .iter()
                    .copied()
                    .map(|source| {
                        self.expression_value(builder, source, self.expression_value_kind(source))
                    })
                    .collect::<Result<Vec<_>, _>>()?
            } else if values.len() == 1 && values[0].kind() == "call_expression" {
                self.multi_result_values(builder, values[0], self.named_results.len())?
                    .into_vec()
            } else {
                Vec::new()
            };
            if assigned.len() == self.named_results.len() {
                for (target, value) in self.named_results.clone().into_iter().zip(assigned) {
                    self.append_binding_assignment(
                        builder,
                        terminal,
                        target,
                        value,
                        ValueFlowKind::Local,
                    )?;
                }
            } else {
                self.add_gap(
                    builder,
                    terminal,
                    SemanticGapSubject::Point,
                    SemanticCapability::ReturnFlow,
                    SemanticGapKind::Unsupported,
                    "Go explicit return values cannot be related to their named result bindings",
                )?;
            }
        }
        self.append_effect(builder, terminal, SemanticEffect::ProcedureReturn { value })?;
        self.abrupt(
            builder,
            terminal,
            scope,
            CompletionKind::Return,
            None,
            stack,
        )?;
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

    /// Lower `x++` and `x--`.
    ///
    /// Go's increment is a statement, not an expression, and it is exactly a
    /// compound assignment: it reads the operand, computes a value of the
    /// operand's own type, and writes it back. Modelling it that way is what
    /// lets a loop-carried value survive an induction step.
    #[allow(clippy::too_many_arguments)]
    fn increment_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), GoLoweringError> {
        let expressions = runtime_expression_children(node);
        let operand = first_runtime_named_child(node)
            .ok_or_else(|| missing_field(node, "incremented operand"))?;
        let operand = transparent_parenthesized_expression(operand);
        let binding = is_go_binding_reference_kind(operand.kind())
            .then(|| node_text(self.prepared.source(), operand))
            .flatten()
            .and_then(|name| Some((name, self.binding_value(name, node.start_byte())?)));

        let boundary = self.point(builder, node, Vec::new())?;
        let old = self.expression_value(builder, operand, self.expression_value_kind(operand))?;
        let computed = self.source_value(builder, node, SemanticValueKind::Temporary)?;
        self.session
            .append_language_defined_value_flows(builder, boundary, [old], computed)?;
        if let Some((name, target)) = binding {
            let kind = self.binding_flow_kind(name, target, node.end_byte());
            self.append_binding_assignment(builder, boundary, target, computed, kind)?;
        } else if is_go_binding_reference_kind(operand.kind())
            && let Some(name) = node_text(self.prepared.source(), operand)
            && let Some(location) = self.package_static_location(builder, boundary, name)?
        {
            self.append_effect(
                builder,
                boundary,
                SemanticEffect::MemoryStore {
                    kind: MemoryAccessKind::Static,
                    location,
                    value: computed,
                },
            )?;
        } else if let Some((kind, location)) =
            self.memory_access_location(builder, boundary, operand)?
        {
            // Scheduling the operand below emits the matching MemoryLoad;
            // this boundary stores the language-defined incremented value.
            self.append_effect(
                builder,
                boundary,
                SemanticEffect::MemoryStore {
                    kind,
                    location,
                    value: computed,
                },
            )?;
        } else if is_go_binding_reference_kind(operand.kind()) {
            self.add_gap(
                builder,
                boundary,
                SemanticGapSubject::Value(old),
                SemanticCapability::Assignments,
                SemanticGapKind::Unsupported,
                "Go increment target is not a lowered binding",
            )?;
        } else {
            let impacts = SemanticGapImpacts::single(SemanticGapImpact::HeapWrite);
            let impacts = if operand.kind() == "unary_expression"
                && unary_operator_kind(operand) == Some("*")
            {
                impacts.with(SemanticGapImpact::HeapRead)
            } else {
                impacts
            };
            self.session.add_gap_with_impacts(
                builder,
                boundary,
                SemanticGapSubject::Value(old),
                SemanticCapability::Assignments,
                impacts,
                SemanticGapKind::Unsupported,
                "Go increment target write is not a lowered field or index place",
            )?;
        }
        self.edge(builder, boundary, next)?;
        self.schedule_expressions(
            builder,
            entry,
            &expressions,
            EdgeTarget::normal(boundary),
            scope,
            stack,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn assignment_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), GoLoweringError> {
        let mut evaluations = self.assignment_evaluation_nodes(node);
        let mut order_evaluations = self.assignment_order_evaluation_nodes(node);
        let boundary = self.point(builder, node, Vec::new())?;
        let operator_is_simple = node.kind() == "short_var_declaration"
            || node
                .child_by_field_name("operator")
                .is_some_and(|operator| operator.kind() == "=");
        let left = node.child_by_field_name("left");
        let right = node.child_by_field_name("right");
        let left_items = left.map(expression_sequence).unwrap_or_default();
        let right_items = right.map(expression_sequence).unwrap_or_default();
        let simple_pair = operator_is_simple
            && left_items.len() == 1
            && right_items.len() == 1
            && is_go_binding_reference_kind(left_items[0].kind());
        let multi_result_call = operator_is_simple
            && left_items.len() > 1
            && right_items.len() == 1
            && right_items[0].kind() == "call_expression";
        let multi_result_values = multi_result_call
            .then(|| self.multi_result_values(builder, right_items[0], left_items.len()))
            .transpose()?;
        let indirect_target_address = if node.kind() == "assignment_statement"
            && left_items.len() == 1
            && right_items.len() == 1
        {
            let target = transparent_parenthesized_expression(left_items[0]);
            if target.kind() == "unary_expression" && unary_operator_kind(target) == Some("*") {
                let operand = required_field(target, "operand")?;
                let operand = transparent_parenthesized_expression(operand);
                Some(self.expression_value(
                    builder,
                    operand,
                    self.expression_value_kind(operand),
                )?)
            } else {
                None
            }
        } else {
            None
        };
        let compound_target = (!operator_is_simple
            && node.kind() == "assignment_statement"
            && left_items.len() == 1
            && right_items.len() == 1
            && is_go_binding_reference_kind(left_items[0].kind()))
        .then(|| {
            let name = node_text(self.prepared.source(), left_items[0])?;
            Some((name, self.binding_value(name, node.start_byte())?))
        })
        .flatten();
        let compound_static_target = if !operator_is_simple
            && node.kind() == "assignment_statement"
            && left_items.len() == 1
            && right_items.len() == 1
            && is_go_binding_reference_kind(left_items[0].kind())
        {
            let name = node_text(self.prepared.source(), left_items[0]);
            match name {
                Some(name) if self.binding_value(name, node.start_byte()).is_none() => self
                    .package_static_location(builder, boundary, name)?
                    .map(|location| (name, location)),
                Some(_) | None => None,
            }
        } else {
            None
        };
        // The single memory place this statement writes, when it writes one:
        // `holder.field = v` or `values[0] = v`, with any redundant
        // parentheses removed. Simple and compound updates share this place
        // identity; a dereference or multi-target assignment does not.
        let single_target = (node.kind() == "assignment_statement"
            && left_items.len() == 1
            && right_items.len() == 1)
            .then(|| unparenthesized(left_items[0]));
        let memory_target = single_target.filter(|target| {
            target.child_by_field_name("operand").is_some()
                && match target.kind() {
                    "selector_expression" => !self.selector_denotes_no_location(*target),
                    "index_expression" => target
                        .child_by_field_name("index")
                        .is_some_and(|index| !is_go_type_syntax(index.kind())),
                    _ => false,
                }
        });
        let place_target = operator_is_simple.then_some(memory_target).flatten();
        let compound_place_target = (!operator_is_simple).then_some(memory_target).flatten();
        let deref_target = single_target.is_some_and(|target| {
            target.kind() == "unary_expression" && unary_operator_kind(target) == Some("*")
        });

        if simple_pair {
            let name_node = left_items[0];
            let source_node = right_items[0];
            let name = node_text(self.prepared.source(), name_node).ok_or_else(|| {
                GoLoweringError::Invalid("Go assignment has invalid identifier range".into())
            })?;
            if name != "_" {
                let target = if node.kind() == "short_var_declaration" {
                    self.local_declaration_value(name, name_node.start_byte())
                        .or_else(|| self.binding_value(name, node.start_byte()))
                } else {
                    self.binding_value(name, node.start_byte())
                };
                if let Some(target) = target {
                    let value = self.expression_value(
                        builder,
                        source_node,
                        self.expression_value_kind(source_node),
                    )?;
                    let identity_preserving = node.kind() == "short_var_declaration"
                        && self.local_declaration_value(name, name_node.start_byte())
                            == Some(target)
                        || self
                            .exact_append_backing(source_node)
                            .and_then(|_| self.builtin_append_source(source_node))
                            .and_then(|source| node_text(self.prepared.source(), source))
                            .and_then(|source| {
                                self.binding_value(source, source_node.start_byte())
                            })
                            == Some(target)
                        || self.value_types.get(&target).is_some_and(|target_type| {
                            self.expression_type_identity(source_node, node.start_byte())
                                .is_some_and(|source_type| source_type == *target_type)
                        });
                    let kind = self.binding_flow_kind(name, target, node.end_byte());
                    if identity_preserving {
                        self.append_binding_assignment(builder, boundary, target, value, kind)?;
                    } else {
                        // Go still overwrites the target binding when an implicit
                        // conversion occurs or the source type is unresolved. Keep
                        // the conversion opaque without dropping that definite write.
                        self.append_converted_binding_assignment(
                            builder,
                            boundary,
                            source_node,
                            value,
                            target,
                            kind,
                        )?;
                    }
                } else if let Some(location) =
                    self.package_static_location(builder, boundary, name)?
                {
                    let value = self.expression_value(
                        builder,
                        source_node,
                        self.expression_value_kind(source_node),
                    )?;
                    self.append_effect(
                        builder,
                        boundary,
                        SemanticEffect::MemoryStore {
                            kind: MemoryAccessKind::Static,
                            location,
                            value,
                        },
                    )?;
                } else {
                    self.add_gap(
                        builder,
                        boundary,
                        SemanticGapSubject::Point,
                        SemanticCapability::Assignments,
                        SemanticGapKind::Unsupported,
                        "Go identifier assignment target is not a lowered local, parameter, receiver, or capture binding",
                    )?;
                }
            }
        } else if let Some(values) = multi_result_values {
            let mut unresolved_identifier_values = Vec::new();
            for (name_node, value) in left_items.iter().zip(values.iter().copied()) {
                match name_node.kind() {
                    "identifier" | "true" | "false" | "nil" | "iota" => {
                        let name =
                            node_text(self.prepared.source(), *name_node).ok_or_else(|| {
                                GoLoweringError::Invalid(
                                    "Go multi-result assignment has invalid identifier range"
                                        .into(),
                                )
                            })?;
                        if name == "_" {
                            continue;
                        }
                        let target = if node.kind() == "short_var_declaration" {
                            self.local_declaration_value(name, name_node.start_byte())
                                .or_else(|| self.binding_value(name, node.start_byte()))
                        } else {
                            self.binding_value(name, node.start_byte())
                        };
                        let Some(target) = target else {
                            unresolved_identifier_values.push(value);
                            continue;
                        };
                        let newly_declared = node.kind() == "short_var_declaration"
                            && self.local_declaration_value(name, name_node.start_byte())
                                == Some(target);
                        let kind = self.binding_flow_kind(name, target, node.end_byte());
                        if newly_declared {
                            self.append_binding_assignment(builder, boundary, target, value, kind)?;
                        } else {
                            // The intrafile call row does not publish the type of
                            // each result ordinal. Reusing an existing binding can
                            // therefore perform an assignment conversion even when
                            // the target's own type is known. Preserve the definite
                            // write, but keep its value identity behind the same
                            // explicit conversion boundary as a scalar assignment.
                            self.append_converted_binding_assignment(
                                builder,
                                boundary,
                                right_items[0],
                                value,
                                target,
                                kind,
                            )?;
                        }
                    }
                    "selector_expression" | "index_expression" => {
                        if let Some((kind, location)) =
                            self.memory_access_location(builder, boundary, *name_node)?
                        {
                            let stored = self.assignment_conversion_value(
                                builder,
                                boundary,
                                right_items[0],
                                value,
                            )?;
                            self.append_effect(
                                builder,
                                boundary,
                                SemanticEffect::MemoryStore {
                                    kind,
                                    location,
                                    value: stored,
                                },
                            )?;
                        } else {
                            self.session.add_gap_with_impacts(
                                builder,
                                boundary,
                                SemanticGapSubject::Value(value),
                                SemanticCapability::Assignments,
                                SemanticGapImpacts::single(SemanticGapImpact::HeapWrite),
                                SemanticGapKind::Unsupported,
                                "Go multi-result memory target is not a lowered field or index place",
                            )?;
                        }
                    }
                    _ => {
                        self.session.add_gap_with_impacts(
                            builder,
                            boundary,
                            SemanticGapSubject::Value(value),
                            SemanticCapability::Assignments,
                            SemanticGapImpacts::single(SemanticGapImpact::HeapWrite),
                            SemanticGapKind::Unsupported,
                            "Go multi-result assignment target write is not lowered",
                        )?;
                    }
                }
            }
            for value in unresolved_identifier_values {
                self.add_gap(
                    builder,
                    boundary,
                    SemanticGapSubject::Value(value),
                    SemanticCapability::Assignments,
                    SemanticGapKind::Unsupported,
                    "Go multi-result value has an identifier assignment target that is not a lowered local, parameter, receiver, or capture binding",
                )?;
            }
        } else if let Some((name, target)) = compound_target {
            // A compound `x op= y` reads both operands, computes a value of the
            // target's own type, and writes it back into the target binding.
            let name_node = left_items[0];
            let source_node = right_items[0];
            evaluations.insert(0, name_node);
            order_evaluations.insert(0, name_node);
            let left_value =
                self.expression_value(builder, name_node, self.expression_value_kind(name_node))?;
            let right_value = self.expression_value(
                builder,
                source_node,
                self.expression_value_kind(source_node),
            )?;
            let computed = self.source_value(builder, node, SemanticValueKind::Temporary)?;
            if let Some(identity) = self.value_types.get(&target).cloned() {
                self.value_types.insert(computed, identity);
            }
            self.session.append_language_defined_value_flows(
                builder,
                boundary,
                [left_value, right_value],
                computed,
            )?;
            let kind = self.binding_flow_kind(name, target, node.end_byte());
            self.append_binding_assignment(builder, boundary, target, computed, kind)?;
        } else if let Some((_, location)) = compound_static_target {
            let name_node = left_items[0];
            let source_node = right_items[0];
            evaluations.insert(0, name_node);
            order_evaluations.insert(0, name_node);
            let left_value =
                self.expression_value(builder, name_node, self.expression_value_kind(name_node))?;
            let right_value = self.expression_value(
                builder,
                source_node,
                self.expression_value_kind(source_node),
            )?;
            let computed = self.source_value(builder, node, SemanticValueKind::Temporary)?;
            self.session.append_language_defined_value_flows(
                builder,
                boundary,
                [left_value, right_value],
                computed,
            )?;
            self.append_effect(
                builder,
                boundary,
                SemanticEffect::MemoryStore {
                    kind: MemoryAccessKind::Static,
                    location,
                    value: computed,
                },
            )?;
        } else if let Some(place) = compound_place_target {
            // A compound field or index update reads the old place value and
            // writes the computed value back after every operand is evaluated.
            // Assignment-target expressions are not scheduled as loads, so
            // publish both memory effects explicitly at this boundary.
            let source_node = right_items[0];
            let left_value =
                self.expression_value(builder, place, self.expression_value_kind(place))?;
            let right_value = self.expression_value(
                builder,
                source_node,
                self.expression_value_kind(source_node),
            )?;
            let computed = self.source_value(builder, node, SemanticValueKind::Temporary)?;
            self.session.append_language_defined_value_flows(
                builder,
                boundary,
                [left_value, right_value],
                computed,
            )?;
            let Some((kind, location)) = self.memory_access_location(builder, boundary, place)?
            else {
                unreachable!("compound_place_target contains only memory places");
            };
            self.append_effect(
                builder,
                boundary,
                SemanticEffect::MemoryLoad {
                    kind,
                    location,
                    result: left_value,
                },
            )?;
            self.append_effect(
                builder,
                boundary,
                SemanticEffect::MemoryStore {
                    kind,
                    location,
                    value: computed,
                },
            )?;
            order_evaluations = vec![place, source_node];
        } else if let Some(place) = place_target {
            // A single selector or index target is a real store into memory.
            // The target's own operand is still evaluated, but the target node
            // itself must not be scheduled as an expression: reading it would
            // publish a load of the location this statement writes.
            let source_node = right_items[0];
            let value = self.expression_value(
                builder,
                source_node,
                self.expression_value_kind(source_node),
            )?;
            let operand = required_field(place, "operand")?;
            let Some((kind, location)) = self.memory_access_location(builder, boundary, place)?
            else {
                unreachable!("place_target contains only memory places");
            };
            let stored = self.assignment_conversion_value(builder, boundary, source_node, value)?;
            self.append_effect(
                builder,
                boundary,
                SemanticEffect::MemoryStore {
                    kind,
                    location,
                    value: stored,
                },
            )?;
            evaluations = vec![operand];
            if let Some(index) = place.child_by_field_name("index") {
                evaluations.push(index);
            }
            evaluations.push(source_node);
        } else if let Some(address) = indirect_target_address {
            // The adapter does not yet model the heap write performed through
            // this pointer. Preserve the exact dereferenced value as the gap
            // subject so alias consumers can relate the write to one address
            // without treating every unsupported assignment in the procedure
            // as a write to every binding.
            let impacts = SemanticGapImpacts::single(SemanticGapImpact::HeapWrite);
            let impacts = if operator_is_simple {
                impacts
            } else {
                impacts.with(SemanticGapImpact::HeapRead)
            };
            self.session.add_gap_with_impacts(
                builder,
                boundary,
                SemanticGapSubject::Value(address),
                SemanticCapability::Assignments,
                impacts,
                SemanticGapKind::Unsupported,
                "Go indirect assignment write is not yet lowered",
            )?;
        } else if !left_items.is_empty() || !right_items.is_empty() {
            let detail = if !operator_is_simple {
                "Go compound assignment flow is not yet lowered"
            } else if deref_target {
                "Go assignment through a pointer dereference target is not yet lowered"
            } else if single_target.is_some_and(|target| target.kind() == "selector_expression") {
                "Go assignment to a selector target whose operand names no value this procedure binds is not yet lowered"
            } else {
                "Go tuple, multi-result, and multi-target assignment flow is not yet lowered"
            };
            let may_write_memory = left_items.iter().any(|target| {
                matches!(
                    transparent_parenthesized_expression(*target).kind(),
                    "selector_expression" | "index_expression" | "unary_expression"
                )
            });
            if may_write_memory {
                self.session.add_gap_with_impacts(
                    builder,
                    boundary,
                    SemanticGapSubject::Point,
                    SemanticCapability::Assignments,
                    SemanticGapImpacts::single(SemanticGapImpact::ValueFlow)
                        .with(SemanticGapImpact::HeapWrite)
                        .with(SemanticGapImpact::Aliasing),
                    SemanticGapKind::Unsupported,
                    detail,
                )?;
            } else {
                self.add_gap(
                    builder,
                    boundary,
                    SemanticGapSubject::Point,
                    SemanticCapability::Assignments,
                    SemanticGapKind::Unsupported,
                    detail,
                )?;
            }
        }
        if node.kind() == "assignment_statement"
            && node
                .child_by_field_name("left")
                .is_some_and(|left| self.binding_requires_runtime_protocol(left))
        {
            if memory_target.is_none() {
                // A target this adapter does not lower still hides whatever
                // the update protocol would do, including a call.
                self.add_gap(
                    builder,
                    boundary,
                    SemanticGapSubject::Point,
                    SemanticCapability::Calls,
                    SemanticGapKind::Unknown,
                    "assignment through indexing or indirection requires runtime refinement",
                )?;
            }
            // The abort edge a nil operand or an out-of-range index would
            // take is not lowered. Preserve the Go proof that such a panic
            // cannot rejoin this function's body, including when a defer
            // recovers it.
            self.add_non_rejoining_exceptional_exit_gap(
                builder,
                scope,
                boundary,
                SemanticGapSubject::Point,
                SemanticGapKind::Unsupported,
                "assignment target evaluation and update panics are not lowered",
            )?;
        }
        self.edge(builder, boundary, next)?;
        self.note_deterministic_evaluation_order(builder, boundary, node, &order_evaluations)?;
        self.schedule_expressions(
            builder,
            entry,
            &evaluations,
            EdgeTarget::normal(boundary),
            scope,
            stack,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn var_declaration(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), GoLoweringError> {
        let specs = go_var_specs(node);
        if specs.is_empty() {
            return self.edge(builder, entry, next);
        }
        let mut entries = Vec::with_capacity(specs.len());
        entries.push(entry);
        for spec in specs.iter().copied().skip(1) {
            entries.push(self.point(builder, spec, Vec::new())?);
        }
        for (index, spec) in specs.iter().copied().enumerate() {
            let spec_entry = entries[index];
            let spec_next = entries
                .get(index + 1)
                .copied()
                .map(EdgeTarget::normal)
                .unwrap_or(next);
            let boundary = self.point(builder, spec, Vec::new())?;
            let names = children_by_field_name(spec, "name");
            let values = spec
                .child_by_field_name("value")
                .map(expression_sequence)
                .unwrap_or_default();
            let mut lowered_any = false;
            let mut unsupported = false;
            let mut saw_nonblank_target = false;
            let mut unresolved_any = false;
            if values.is_empty() {
                for name_node in &names {
                    let Some(name) = node_text(self.prepared.source(), *name_node) else {
                        continue;
                    };
                    if name == "_" {
                        continue;
                    }
                    saw_nonblank_target = true;
                    let Some(target) = self.local_declaration_value(name, name_node.start_byte())
                    else {
                        self.add_gap(
                            builder,
                            boundary,
                            SemanticGapSubject::Point,
                            SemanticCapability::Assignments,
                            SemanticGapKind::Unsupported,
                            "typed Go zero-value declaration has no lowered local binding",
                        )?;
                        unresolved_any = true;
                        continue;
                    };
                    if !self.value_types.contains_key(&target) {
                        self.add_gap(
                            builder,
                            boundary,
                            SemanticGapSubject::Value(target),
                            SemanticCapability::Values,
                            SemanticGapKind::Unsupported,
                            "Go zero value for an unresolved declared type is not lowered",
                        )?;
                        unresolved_any = true;
                        continue;
                    }
                    let zero_kind = if self
                        .value_types
                        .get(&target)
                        .is_some_and(|identity| identity.pointer_depth > 0)
                    {
                        SemanticValueKind::Null
                    } else {
                        SemanticValueKind::LanguageDefined("go.zero_value".into())
                    };
                    let zero = self.source_value(builder, *name_node, zero_kind)?;
                    self.append_binding_assignment(
                        builder,
                        boundary,
                        target,
                        zero,
                        ValueFlowKind::Local,
                    )?;
                    lowered_any = true;
                }
            } else {
                saw_nonblank_target |= names.iter().any(|name_node| {
                    node_text(self.prepared.source(), *name_node).is_some_and(|name| name != "_")
                });
                if names.len() > 1
                    && values.len() == 1
                    && values[0].kind() == "call_expression"
                    && spec.child_by_field_name("type").is_none()
                {
                    let results = self.multi_result_values(builder, values[0], names.len())?;
                    for (name_node, value) in names.iter().zip(results.iter().copied()) {
                        let Some(name) = node_text(self.prepared.source(), *name_node) else {
                            continue;
                        };
                        if name == "_" {
                            continue;
                        }
                        let Some(target) =
                            self.local_declaration_value(name, name_node.start_byte())
                        else {
                            self.add_gap(
                                builder,
                                boundary,
                                SemanticGapSubject::Value(value),
                                SemanticCapability::Assignments,
                                SemanticGapKind::Unsupported,
                                "Go multi-result var value has an identifier target without a lowered local binding",
                            )?;
                            continue;
                        };
                        self.append_binding_assignment(
                            builder,
                            boundary,
                            target,
                            value,
                            ValueFlowKind::Local,
                        )?;
                    }
                    lowered_any = true;
                } else if names.len() == 1 && values.len() == 1 {
                    let name_node = names[0];
                    let value_node = values[0];
                    if let Some(name) = node_text(self.prepared.source(), name_node)
                        && name != "_"
                        && let Some(target) =
                            self.local_declaration_value(name, name_node.start_byte())
                    {
                        let value = self.expression_value(
                            builder,
                            value_node,
                            self.expression_value_kind(value_node),
                        )?;
                        let inferred = spec.child_by_field_name("type").is_none();
                        let identity_preserving = inferred
                            || self.value_types.get(&target).is_some_and(|target_type| {
                                self.expression_type_identity(value_node, spec.start_byte())
                                    .is_some_and(|source_type| source_type == *target_type)
                            });
                        // As in assignment: an explicitly typed initialization still
                        // writes the value, and the structural type check only decides
                        // whether the local keeps the initializer's identity or derives
                        // from it through an implicit conversion.
                        if identity_preserving {
                            self.append_binding_assignment(
                                builder,
                                boundary,
                                target,
                                value,
                                ValueFlowKind::Local,
                            )?;
                        } else {
                            self.append_converted_binding_assignment(
                                builder,
                                boundary,
                                value_node,
                                value,
                                target,
                                ValueFlowKind::Local,
                            )?;
                        }
                        lowered_any = true;
                    }
                } else {
                    unsupported = true;
                }
            }
            if unsupported {
                self.add_gap(
                    builder,
                    boundary,
                    SemanticGapSubject::Point,
                    SemanticCapability::Assignments,
                    SemanticGapKind::Unsupported,
                    "Go multi-name, tuple, and multi-result var initialization flow is not yet lowered",
                )?;
            }
            if saw_nonblank_target && !lowered_any && !unsupported && !unresolved_any {
                self.add_gap(
                    builder,
                    boundary,
                    SemanticGapSubject::Point,
                    SemanticCapability::Values,
                    SemanticGapKind::Unknown,
                    "Go var initialization bound no analyzable local target",
                )?;
            }
            self.edge(builder, boundary, spec_next)?;
            self.note_deterministic_evaluation_order(builder, spec_entry, spec, &values)?;
            self.schedule_expressions(
                builder,
                spec_entry,
                &values,
                EdgeTarget::normal(boundary),
                scope,
                stack,
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn communication_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), GoLoweringError> {
        let evaluations = communication_evaluations(node);
        let boundary = self.point(builder, node, Vec::new())?;
        let (operation, channel) = communication_operation_and_channel(node)
            .ok_or_else(|| missing_field(node, "channel communication"))?;
        let subject =
            self.expression_value(builder, channel, self.expression_value_kind(channel))?;
        self.append_effect(
            builder,
            boundary,
            SemanticEffect::Synchronization { operation, subject },
        )?;
        self.add_gap(
            builder,
            boundary,
            SemanticGapSubject::Point,
            SemanticCapability::NormalControlFlow,
            SemanticGapKind::Unknown,
            "channel communication may block and requires scheduler refinement",
        )?;
        self.add_non_rejoining_exceptional_exit_gap(
            builder,
            scope,
            boundary,
            SemanticGapSubject::Point,
            SemanticGapKind::Unknown,
            "send on a closed channel and communication-related panics are not lowered",
        )?;
        self.edge(builder, boundary, next)?;
        // The communication boundary already owns the scheduler-dependent
        // normal-control gap. Evaluation order is a separate fact that occurs
        // before either operand is evaluated, so attach it to the statement
        // entry rather than duplicating the boundary's scoped gap.
        self.note_deterministic_evaluation_order(builder, entry, node, &evaluations)?;
        self.schedule_expressions(
            builder,
            entry,
            &evaluations,
            EdgeTarget::normal(boundary),
            scope,
            stack,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn deferred_or_spawned_call(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: StatementNext,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), GoLoweringError> {
        let operand = first_runtime_named_child(node)
            .ok_or_else(|| missing_field(node, "call expression"))?;
        let defer_call = supported_defer_call(node, self.procedure_targets);
        let inside_loop = node.kind() == "defer_statement" && self.defer_is_inside_loop(node);
        let inside_switch =
            node.kind() == "defer_statement" && self.defer_is_inside_expression_switch(node);
        let supported_defer = !inside_loop
            && !inside_switch
            && defer_call.is_some()
            && self.has_stable_deferred_callable(
                defer_call.expect("a present defer call was checked above"),
            )?;
        let evaluations = if operand.kind() == "call_expression" {
            self.call_operand_evaluations(operand, !supported_defer)?
        } else {
            vec![operand]
        };
        let continuation_scope = if supported_defer {
            if !self.deferred_captures.contains_key(&operand.id()) {
                let capture = self.prepare_deferred_capture(builder, operand)?;
                self.deferred_captures.insert(operand.id(), capture);
            }
            let id = CleanupRegionId::new(u32::try_from(self.cleanups.len()).map_err(|_| {
                GoLoweringError::Invalid("too many Go defer cleanup regions".into())
            })?);
            self.cleanups.push(CleanupRegion {
                id,
                call: operand,
                outer_scope: scope,
            });
            builder.push_scope(Some(scope), ScopeBinding::Cleanup { region: id })
        } else {
            scope
        };
        let next = self.materialize_statement_next(builder, next, continuation_scope, stack)?;
        if node.kind() == "go_statement" && operand.kind() == "call_expression" {
            let invoke = self.spawned_call_expression(builder, operand, next)?;
            self.session.add_gap_with_impacts_and_discharge(
                builder,
                invoke,
                SemanticGapSubject::Point,
                SemanticCapability::ConcurrentSpawn,
                SemanticGapImpacts::NONE,
                SemanticGapKind::Unsupported,
                SemanticGapDischarge::RetainedControlTopology,
                "goroutine scheduling, lifetime, and join behavior are not lowered",
            )?;
            self.note_deterministic_evaluation_order(builder, invoke, node, &evaluations)?;
            return self.schedule_expressions(
                builder,
                entry,
                &evaluations,
                EdgeTarget::normal(invoke),
                scope,
                stack,
            );
        }
        let boundary = self.point(builder, node, Vec::new())?;
        if node.kind() == "go_statement" {
            for (capability, detail) in [
                (
                    SemanticCapability::ConcurrentSpawn,
                    "goroutine creation, scheduling, lifetime, and join behavior are not lowered",
                ),
                (
                    SemanticCapability::Calls,
                    "the spawned operand is not an exact call expression",
                ),
            ] {
                let discharge = if capability == SemanticCapability::ConcurrentSpawn {
                    SemanticGapDischarge::RetainedControlTopology
                } else {
                    SemanticGapDischarge::None
                };
                self.session.add_gap_with_impacts_and_discharge(
                    builder,
                    boundary,
                    SemanticGapSubject::Point,
                    capability,
                    SemanticGapImpacts::NONE,
                    SemanticGapKind::Unsupported,
                    discharge,
                    detail,
                )?;
            }
        } else if !supported_defer {
            for (capability, kind, detail) in [
                (
                    SemanticCapability::DeferredExecution,
                    SemanticGapKind::Unsupported,
                    if inside_loop {
                        "defer registration inside a loop has unbounded per-iteration captures and is not lowered"
                    } else if inside_switch {
                        "defer registration inside an expression switch has branch-specific continuation state and is not lowered"
                    } else {
                        "deferred invocation timing and LIFO execution are not lowered"
                    },
                ),
                (
                    SemanticCapability::CleanupControlFlow,
                    SemanticGapKind::Unsupported,
                    if inside_loop {
                        "per-iteration deferred calls cannot be stitched into bounded cleanup control flow"
                    } else if inside_switch {
                        "branch-specific deferred calls cannot be stitched through the shared post-switch continuation"
                    } else {
                        "deferred calls on return and panic paths are not stitched into control flow"
                    },
                ),
                (
                    SemanticCapability::Calls,
                    SemanticGapKind::Unsupported,
                    "the deferred outer call is intentionally not emitted as an immediate invocation",
                ),
            ] {
                let discharge = if matches!(
                    capability,
                    SemanticCapability::DeferredExecution | SemanticCapability::CleanupControlFlow
                ) {
                    SemanticGapDischarge::ExitOnlyProcedureCompletion
                } else {
                    SemanticGapDischarge::None
                };
                self.session.add_gap_with_impacts_and_discharge(
                    builder,
                    boundary,
                    SemanticGapSubject::Point,
                    capability,
                    SemanticGapImpacts::NONE,
                    kind,
                    discharge,
                    detail,
                )?;
            }
            self.add_non_rejoining_exceptional_exit_gap(
                builder,
                scope,
                boundary,
                SemanticGapSubject::Point,
                SemanticGapKind::Unknown,
                "deferred invocation panic propagation is not lowered",
            )?;
        } else {
            let capture = self
                .deferred_captures
                .get(&operand.id())
                .cloned()
                .ok_or_else(|| {
                    GoLoweringError::Invalid("supported Go defer has no captured operands".into())
                })?;
            for (source, target) in capture.receiver.into_iter().chain(capture.arguments) {
                self.append_effect(
                    builder,
                    boundary,
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::LanguageDefined,
                        source,
                        target,
                    },
                )?;
            }
        }
        self.edge(builder, boundary, next)?;
        self.note_deterministic_evaluation_order(builder, boundary, node, &evaluations)?;
        self.schedule_expressions(
            builder,
            entry,
            &evaluations,
            EdgeTarget::normal(boundary),
            scope,
            stack,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn expression_switch_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        attached_label: Option<Node<'tree>>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), GoLoweringError> {
        let boundary = self.point(builder, node, Vec::new())?;
        let clauses = named_children(node)
            .into_iter()
            .filter(|child| is_clause(*child))
            .collect::<Vec<_>>();
        let label = attached_label
            .and_then(|label| node_text(self.prepared.source(), label))
            .map(Box::<str>::from);
        let switch_scope = builder.push_scope(
            Some(scope),
            ScopeBinding::Breakable {
                label,
                accepts_unlabeled: true,
                break_target: next.point,
                break_edge_kind: next.kind,
            },
        );
        let clause_entries = clauses
            .iter()
            .map(|clause| self.point(builder, *clause, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        for (index, clause) in clauses.iter().copied().enumerate() {
            let clause_entry = clause_entries[index];
            let statements = clause_statement_list(clause)
                .map(named_children)
                .unwrap_or_default();
            let terminal_fallthrough = statements
                .last()
                .copied()
                .filter(|statement| statement.kind() == "fallthrough_statement")
                .zip(clause_entries.get(index + 1).copied());
            if let Some((fallthrough, fallthrough_target)) = terminal_fallthrough {
                let fallthrough_entry = self.point(builder, fallthrough, Vec::new())?;
                self.edge(
                    builder,
                    fallthrough_entry,
                    EdgeTarget::normal(fallthrough_target),
                )?;
                self.schedule_statements(
                    builder,
                    clause_entry,
                    &statements[..statements.len() - 1],
                    EdgeTarget::normal(fallthrough_entry).into(),
                    switch_scope,
                    stack,
                )?;
            } else {
                self.schedule_statements(
                    builder,
                    clause_entry,
                    &statements,
                    next.into(),
                    switch_scope,
                    stack,
                )?;
            }
        }

        let tagged = node.child_by_field_name("value").is_some();
        let mut tests = Vec::new();
        for (clause_index, clause) in clauses.iter().copied().enumerate() {
            if clause.kind() != "expression_case" {
                continue;
            }
            let case_values = required_field(clause, "value")?;
            for case_value in expression_sequence(case_values) {
                let test_entry = self.point(builder, case_value, Vec::new())?;
                let comparison = tagged
                    .then(|| self.point(builder, case_value, Vec::new()))
                    .transpose()?;
                tests.push((case_value, test_entry, comparison, clause_index));
            }
        }
        let no_match_target = clauses
            .iter()
            .position(|clause| clause.kind() == "default_case")
            .map(|index| clause_entries[index])
            .unwrap_or(next.point);
        for (index, (case_value, test_entry, comparison, clause_index)) in
            tests.iter().copied().enumerate()
        {
            let when_true = EdgeTarget {
                point: clause_entries[clause_index],
                kind: ControlEdgeKind::SwitchCase,
            };
            let when_false = EdgeTarget {
                point: tests
                    .get(index + 1)
                    .map(|(_, entry, _, _)| *entry)
                    .unwrap_or(no_match_target),
                kind: ControlEdgeKind::ConditionalFalse,
            };
            if let Some(comparison) = comparison {
                self.edge(builder, comparison, when_true)?;
                self.edge(builder, comparison, when_false)?;
                self.add_non_rejoining_exceptional_exit_gap(
                    builder,
                    switch_scope,
                    comparison,
                    SemanticGapSubject::Point,
                    SemanticGapKind::Unknown,
                    "tagged switch equality may panic when an interface operand contains a dynamically incomparable value",
                )?;
                stack.push(Work::Expression {
                    node: case_value,
                    entry: test_entry,
                    next: EdgeTarget::normal(comparison),
                    scope: switch_scope,
                });
            } else {
                stack.push(Work::Condition {
                    node: case_value,
                    entry: test_entry,
                    when_true,
                    when_false,
                    scope: switch_scope,
                });
            }
        }
        if let Some((_, first_test, _, _)) = tests.first() {
            self.edge(builder, boundary, EdgeTarget::normal(*first_test))?;
        } else if let Some(default_index) = clauses
            .iter()
            .position(|clause| clause.kind() == "default_case")
        {
            self.edge(
                builder,
                boundary,
                EdgeTarget {
                    point: clause_entries[default_index],
                    kind: ControlEdgeKind::SwitchCase,
                },
            )?;
        } else {
            self.edge(builder, boundary, next)?;
        }

        let selector_node = node.child_by_field_name("value");
        let selector = selector_node
            .map(|selector| {
                self.expression_value(builder, selector, self.expression_value_kind(selector))
            })
            .transpose()?;
        let default_index = clauses
            .iter()
            .position(|clause| clause.kind() == "default_case");
        let (kind, selector_domain, cases, default_edge) =
            if let Some(selector_node) = selector_node {
                let cases = tests
                    .iter()
                    .map(|(case_value, _, comparison, clause_index)| {
                        Ok(SwitchCaseFactParts {
                            value: self.expression_value(
                                builder,
                                *case_value,
                                self.expression_value_kind(*case_value),
                            )?,
                            edge: SwitchEdgeParts {
                                source_point: comparison
                                    .expect("tagged switch tests have comparison points"),
                                arm: GuardArm {
                                    target_point: clause_entries[*clause_index],
                                    kind: ControlEdgeKind::SwitchCase,
                                },
                            },
                        })
                    })
                    .collect::<Result<Vec<_>, GoLoweringError>>()?;
                let default_edge = default_index.map(|default_index| {
                    tests.last().map_or(
                        SwitchEdgeParts {
                            source_point: boundary,
                            arm: GuardArm {
                                target_point: clause_entries[default_index],
                                kind: ControlEdgeKind::SwitchCase,
                            },
                        },
                        |(_, _, comparison, _)| SwitchEdgeParts {
                            source_point: comparison
                                .expect("tagged switch tests have comparison points"),
                            arm: GuardArm {
                                target_point: clause_entries[default_index],
                                kind: ControlEdgeKind::ConditionalFalse,
                            },
                        },
                    )
                });
                (
                    SwitchFactKind::Expression,
                    if self.expression_has_boolean_domain(selector_node) {
                        SwitchSelectorDomain::Boolean
                    } else {
                        SwitchSelectorDomain::Open
                    },
                    cases,
                    default_edge,
                )
            } else {
                (
                    SwitchFactKind::Expressionless,
                    SwitchSelectorDomain::Open,
                    Vec::new(),
                    None,
                )
            };
        self.session.add_switch_fact(
            builder,
            SwitchFactScaffold {
                point: boundary,
                kind,
                selector,
                selector_domain,
                cases,
                default_edge,
                default_present: default_index.is_some(),
            },
        )?;

        let initializer = node.child_by_field_name("initializer");
        let value = node.child_by_field_name("value");
        match (initializer, value) {
            (Some(initializer), Some(value)) => {
                let value_entry = self.point(builder, value, Vec::new())?;
                stack.push(Work::Expression {
                    node: value,
                    entry: value_entry,
                    next: EdgeTarget::normal(boundary),
                    scope,
                });
                stack.push(Work::Statement {
                    node: initializer,
                    entry,
                    next: EdgeTarget::normal(value_entry).into(),
                    scope,
                    label: None,
                });
                Ok(())
            }
            (Some(initializer), None) => {
                stack.push(Work::Statement {
                    node: initializer,
                    entry,
                    next: EdgeTarget::normal(boundary).into(),
                    scope,
                    label: None,
                });
                Ok(())
            }
            (None, Some(value)) => {
                stack.push(Work::Expression {
                    node: value,
                    entry,
                    next: EdgeTarget::normal(boundary),
                    scope,
                });
                Ok(())
            }
            (None, None) => self.edge(builder, entry, EdgeTarget::normal(boundary)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn type_switch_boundary(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), GoLoweringError> {
        let boundary = self.point(builder, node, Vec::new())?;
        self.session.add_switch_fact(
            builder,
            SwitchFactScaffold {
                point: boundary,
                kind: SwitchFactKind::Type,
                selector: None,
                selector_domain: SwitchSelectorDomain::Open,
                cases: Vec::new(),
                default_edge: None,
                default_present: named_children(node)
                    .into_iter()
                    .any(|child| child.kind() == "default_case"),
            },
        )?;
        self.add_gap(
            builder,
            boundary,
            SemanticGapSubject::Point,
            SemanticCapability::NormalControlFlow,
            SemanticGapKind::Unsupported,
            "type-switch matching, per-case bindings, case bodies, and post-switch continuation are not lowered",
        )?;
        self.add_gap(
            builder,
            boundary,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unsupported,
            "calls in selected type-switch case bodies are not lowered",
        )?;
        self.add_non_rejoining_exceptional_exit_gap(
            builder,
            scope,
            boundary,
            SemanticGapSubject::Point,
            SemanticGapKind::Unknown,
            "type-switch header evaluation panics are not fully lowered",
        )?;

        let initializer = node.child_by_field_name("initializer");
        let value = node.child_by_field_name("value");
        match (initializer, value) {
            (Some(initializer), Some(value)) => {
                let value_entry = self.point(builder, value, Vec::new())?;
                stack.push(Work::Expression {
                    node: value,
                    entry: value_entry,
                    next: EdgeTarget::normal(boundary),
                    scope,
                });
                stack.push(Work::Statement {
                    node: initializer,
                    entry,
                    next: EdgeTarget::normal(value_entry).into(),
                    scope,
                    label: None,
                });
                Ok(())
            }
            (Some(initializer), None) => {
                stack.push(Work::Statement {
                    node: initializer,
                    entry,
                    next: EdgeTarget::normal(boundary).into(),
                    scope,
                    label: None,
                });
                Ok(())
            }
            (None, Some(value)) => {
                stack.push(Work::Expression {
                    node: value,
                    entry,
                    next: EdgeTarget::normal(boundary),
                    scope,
                });
                Ok(())
            }
            (None, None) => self.edge(builder, entry, EdgeTarget::normal(boundary)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn select_boundary(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), GoLoweringError> {
        let eager = select_eager_expressions(node);
        let boundary = self.point(builder, node, Vec::new())?;
        let clauses = named_children(node)
            .into_iter()
            .filter(|child| matches!(child.kind(), "communication_case" | "default_case"))
            .collect::<Vec<_>>();
        let select_scope = builder.push_scope(
            Some(scope),
            ScopeBinding::Breakable {
                label: None,
                accepts_unlabeled: true,
                break_target: next.point,
                break_edge_kind: next.kind,
            },
        );
        let has_default = clauses.iter().any(|clause| clause.kind() == "default_case");
        if !has_default {
            self.add_retained_control_topology_gap(
                builder,
                boundary,
                "select may block while every structured communication alternative remains retained",
            )?;
        }
        for clause in clauses {
            let clause_entry = self.point(builder, clause, Vec::new())?;
            self.edge(
                builder,
                boundary,
                EdgeTarget {
                    point: clause_entry,
                    kind: ControlEdgeKind::SwitchCase,
                },
            )?;
            let body = clause_statement_list(clause);
            let body_entry = body
                .map(|body| self.point(builder, body, Vec::new()))
                .transpose()?;
            self.edge(
                builder,
                clause_entry,
                body_entry.map(EdgeTarget::normal).unwrap_or(next),
            )?;
            if let Some(body) = body {
                stack.push(Work::Statement {
                    node: body,
                    entry: body_entry.expect("select body entry was allocated"),
                    next: next.into(),
                    scope: select_scope,
                    label: None,
                });
            }
            let Some(communication) = clause.child_by_field_name("communication") else {
                continue;
            };
            let (operation, channel) = communication_operation_and_channel(communication)
                .ok_or_else(|| missing_field(communication, "channel communication"))?;
            let subject =
                self.expression_value(builder, channel, self.expression_value_kind(channel))?;
            self.append_effect(
                builder,
                clause_entry,
                SemanticEffect::Synchronization { operation, subject },
            )?;
            if communication.kind() == "receive_statement"
                && communication.child_by_field_name("left").is_some()
            {
                self.add_gap(
                    builder,
                    clause_entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::Assignments,
                    SemanticGapKind::Unsupported,
                    "selected receive assignment values are not yet related to their exact target bindings",
                )?;
            }
            if operation == SynchronizationOperation::ChannelSend {
                self.add_non_rejoining_exceptional_exit_gap(
                    builder,
                    select_scope,
                    clause_entry,
                    SemanticGapSubject::Point,
                    SemanticGapKind::Unknown,
                    "selected send on a closed channel may panic",
                )?;
            }
        }
        self.schedule_expressions(
            builder,
            entry,
            &eager,
            EdgeTarget::normal(boundary),
            scope,
            stack,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn if_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: StatementNext,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), GoLoweringError> {
        let condition = required_field(node, "condition")?;
        let consequence = required_field(node, "consequence")?;
        let alternative = node.child_by_field_name("alternative");
        let condition_entry = self.point(builder, condition, Vec::new())?;
        let consequence_entry = self.point(builder, consequence, Vec::new())?;
        let alternative_entry = alternative
            .map(|alternative| self.point(builder, alternative, Vec::new()))
            .transpose()?;
        let false_target = if alternative_entry.is_none() {
            Some(self.materialize_statement_next(builder, next, scope, stack)?)
        } else {
            None
        };

        if let (Some(alternative), Some(alternative_entry)) = (alternative, alternative_entry) {
            stack.push(Work::Statement {
                node: alternative,
                entry: alternative_entry,
                next,
                scope,
                label: None,
            });
        }
        stack.push(Work::Statement {
            node: consequence,
            entry: consequence_entry,
            next,
            scope,
            label: None,
        });
        stack.push(Work::Condition {
            node: condition,
            entry: condition_entry,
            when_true: EdgeTarget {
                point: consequence_entry,
                kind: ControlEdgeKind::ConditionalTrue,
            },
            when_false: EdgeTarget {
                point: alternative_entry
                    .or_else(|| false_target.map(|target| target.point))
                    .expect("an if statement has an alternative or a continuation"),
                kind: ControlEdgeKind::ConditionalFalse,
            },
            scope,
        });
        if let Some(initializer) = node.child_by_field_name("initializer") {
            stack.push(Work::Statement {
                node: initializer,
                entry,
                next: EdgeTarget::normal(condition_entry).into(),
                scope,
                label: None,
            });
            Ok(())
        } else {
            self.edge(builder, entry, EdgeTarget::normal(condition_entry))
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
        attached_label: Option<Node<'tree>>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), GoLoweringError> {
        let body = required_field(node, "body")?;
        let control = named_children(node)
            .into_iter()
            .find(|child| child.id() != body.id());
        let label = attached_label
            .and_then(|label| node_text(self.prepared.source(), label))
            .map(Box::<str>::from);
        match control {
            None => self.infinite_loop(builder, body, entry, next, scope, label, stack),
            Some(control) if control.kind() == "for_clause" => {
                self.for_clause_loop(builder, control, body, entry, next, scope, label, stack)
            }
            Some(control) if control.kind() == "range_clause" => {
                self.range_loop(builder, control, body, entry, next, scope, label, stack)
            }
            Some(condition) => {
                self.condition_loop(builder, condition, body, entry, next, scope, label, stack)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn infinite_loop(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        body: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        label: Option<Box<str>>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), GoLoweringError> {
        let body_entry = self.point(builder, body, Vec::new())?;
        let loop_scope = builder.push_scope(
            Some(scope),
            ScopeBinding::Loop {
                label,
                break_target: next.point,
                break_edge_kind: next.kind,
                continue_target: body_entry,
                continue_edge_kind: ControlEdgeKind::LoopBack,
            },
        );
        stack.push(Work::Statement {
            node: body,
            entry: body_entry,
            next: EdgeTarget {
                point: body_entry,
                kind: ControlEdgeKind::LoopBack,
            }
            .into(),
            scope: loop_scope,
            label: None,
        });
        self.edge(builder, entry, EdgeTarget::normal(body_entry))
    }

    #[allow(clippy::too_many_arguments)]
    fn condition_loop(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        condition: Node<'tree>,
        body: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        label: Option<Box<str>>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), GoLoweringError> {
        let condition_entry = self.point(builder, condition, Vec::new())?;
        let body_entry = self.point(builder, body, Vec::new())?;
        let loop_scope = builder.push_scope(
            Some(scope),
            ScopeBinding::Loop {
                label,
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
            }
            .into(),
            scope: loop_scope,
            label: None,
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

    #[allow(clippy::too_many_arguments)]
    fn for_clause_loop(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        clause: Node<'tree>,
        body: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        label: Option<Box<str>>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), GoLoweringError> {
        let initializer = clause.child_by_field_name("initializer");
        let condition = clause.child_by_field_name("condition");
        let update = clause.child_by_field_name("update");
        let body_entry = self.point(builder, body, Vec::new())?;
        let condition_entry = condition
            .map(|condition| self.point(builder, condition, Vec::new()))
            .transpose()?;
        let update_entry = update
            .map(|update| self.point(builder, update, Vec::new()))
            .transpose()?;
        let loop_head = condition_entry.unwrap_or(body_entry);
        let initial_target = if go_for_clause_has_first_iteration(
            self.prepared.source(),
            initializer,
            condition,
            update,
        ) {
            EdgeTarget::normal(body_entry)
        } else {
            EdgeTarget::normal(loop_head)
        };
        let continue_target = update_entry.unwrap_or(loop_head);
        let loop_scope = builder.push_scope(
            Some(scope),
            ScopeBinding::Loop {
                label,
                break_target: next.point,
                break_edge_kind: next.kind,
                continue_target,
                continue_edge_kind: ControlEdgeKind::LoopBack,
            },
        );

        if let (Some(update), Some(update_entry)) = (update, update_entry) {
            stack.push(Work::Statement {
                node: update,
                entry: update_entry,
                next: EdgeTarget {
                    point: loop_head,
                    kind: ControlEdgeKind::LoopBack,
                }
                .into(),
                scope: loop_scope,
                label: None,
            });
        }
        stack.push(Work::Statement {
            node: body,
            entry: body_entry,
            next: update_entry
                .map(EdgeTarget::normal)
                .unwrap_or(EdgeTarget {
                    point: loop_head,
                    kind: ControlEdgeKind::LoopBack,
                })
                .into(),
            scope: loop_scope,
            label: None,
        });
        if let (Some(condition), Some(condition_entry)) = (condition, condition_entry) {
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
        }
        if let Some(initializer) = initializer {
            stack.push(Work::Statement {
                node: initializer,
                entry,
                next: initial_target.into(),
                scope: loop_scope,
                label: None,
            });
            Ok(())
        } else {
            self.edge(builder, entry, EdgeTarget::normal(loop_head))
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn range_loop(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        clause: Node<'tree>,
        body: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        label: Option<Box<str>>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), GoLoweringError> {
        let right = required_field(clause, "right")?;
        let left = clause.child_by_field_name("left");
        let test = self.point(builder, clause, Vec::new())?;
        let iterable = self.expression_value(builder, right, self.expression_value_kind(right))?;
        if self.expression_storage_kind(right, right.start_byte()) == Some(GoStorageKind::Map) {
            let location = self.session.add_memory_location(
                builder,
                test,
                MemoryLocationKind::Index {
                    base: iterable,
                    index: None,
                    constant_index: None,
                    identity: IndexedLocationIdentity::Aggregate,
                },
            )?;
            let result = self.source_value(builder, clause, SemanticValueKind::Temporary)?;
            self.append_effect(
                builder,
                test,
                SemanticEffect::MemoryLoad {
                    kind: MemoryAccessKind::Index,
                    location,
                    result,
                },
            )?;
            self.add_unprojected_index_gap(builder, test, location, false)?;
        }
        let body_entry = self.point(builder, body, Vec::new())?;
        let binding_entry = left
            .map(|left| self.point(builder, left, Vec::new()))
            .transpose()?;
        let binding_boundary = left
            .map(|left| self.point(builder, left, Vec::new()))
            .transpose()?;
        let loop_scope = builder.push_scope(
            Some(scope),
            ScopeBinding::Loop {
                label,
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
            SemanticGapKind::Unknown,
            "range-over-function invocation and type-specific range mechanics require refinement",
        )?;
        self.add_retained_control_topology_gap(
            builder,
            test,
            "type-specific range progress may block or diverge, but source-local branch and loop-back topology is retained",
        )?;
        self.edge(
            builder,
            test,
            EdgeTarget {
                point: binding_entry.unwrap_or(body_entry),
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

        stack.push(Work::Statement {
            node: body,
            entry: body_entry,
            next: EdgeTarget {
                point: test,
                kind: ControlEdgeKind::LoopBack,
            }
            .into(),
            scope: loop_scope,
            label: None,
        });
        if let (Some(left), Some(binding_entry), Some(binding_boundary)) =
            (left, binding_entry, binding_boundary)
        {
            let binding_evaluations = if direct_child_kind(clause, "=") {
                self.assignment_target_evaluation_nodes(left)
            } else {
                Vec::new()
            };
            let binding_order = if direct_child_kind(clause, "=") {
                self.assignment_target_order_nodes(left)
            } else {
                Vec::new()
            };
            if self.binding_requires_runtime_protocol(left) {
                self.add_gap(
                    builder,
                    binding_boundary,
                    SemanticGapSubject::Point,
                    SemanticCapability::Calls,
                    SemanticGapKind::Unknown,
                    "range target unpacking, indexing, or indirection requires runtime refinement",
                )?;
                self.add_non_rejoining_exceptional_exit_gap(
                    builder,
                    loop_scope,
                    binding_boundary,
                    SemanticGapSubject::Point,
                    SemanticGapKind::Unsupported,
                    "range target evaluation and assignment panics are not lowered",
                )?;
            }
            // Each target is written a fresh element derived from the iterable
            // on every iteration. The element value depends on the iterable's
            // value, so a `for x := range x` binder relates to the outer `x`
            // read as same-evaluation rather than serving it.
            let declares = direct_child_kind(clause, ":=");
            for name_node in expression_sequence(left) {
                let element =
                    self.source_value(builder, name_node, SemanticValueKind::Temporary)?;
                self.session.append_language_defined_value_flows(
                    builder,
                    binding_boundary,
                    [iterable],
                    element,
                )?;
                match name_node.kind() {
                    "identifier" | "true" | "false" | "nil" | "iota" => {
                        let Some(name) = node_text(self.prepared.source(), name_node) else {
                            continue;
                        };
                        if name == "_" {
                            continue;
                        }
                        let target = if declares {
                            self.local_declaration_value(name, name_node.start_byte())
                        } else {
                            self.binding_value(name, clause.start_byte())
                        };
                        let Some(target) = target else {
                            continue;
                        };
                        let kind = self.binding_flow_kind(name, target, body.start_byte());
                        if declares {
                            self.append_binding_assignment(
                                builder,
                                binding_boundary,
                                target,
                                element,
                                kind,
                            )?;
                        } else {
                            self.append_converted_binding_assignment(
                                builder,
                                binding_boundary,
                                name_node,
                                element,
                                target,
                                kind,
                            )?;
                        }
                    }
                    "selector_expression" | "index_expression" => {
                        if let Some((kind, location)) =
                            self.memory_access_location(builder, binding_boundary, name_node)?
                        {
                            let stored = if declares {
                                element
                            } else {
                                self.assignment_conversion_value(
                                    builder,
                                    binding_boundary,
                                    name_node,
                                    element,
                                )?
                            };
                            self.append_effect(
                                builder,
                                binding_boundary,
                                SemanticEffect::MemoryStore {
                                    kind,
                                    location,
                                    value: stored,
                                },
                            )?;
                        } else {
                            self.session.add_gap_with_impacts(
                                builder,
                                binding_boundary,
                                SemanticGapSubject::Value(element),
                                SemanticCapability::Assignments,
                                SemanticGapImpacts::single(SemanticGapImpact::HeapWrite),
                                SemanticGapKind::Unsupported,
                                "Go range memory target is not a lowered field or index place",
                            )?;
                        }
                    }
                    _ => {
                        self.session.add_gap_with_impacts(
                            builder,
                            binding_boundary,
                            SemanticGapSubject::Point,
                            SemanticCapability::Assignments,
                            SemanticGapImpacts::single(SemanticGapImpact::HeapWrite),
                            SemanticGapKind::Unsupported,
                            "Go range assignment target write is not yet lowered",
                        )?;
                    }
                }
            }
            self.edge(builder, binding_boundary, EdgeTarget::normal(body_entry))?;
            self.note_deterministic_evaluation_order(
                builder,
                binding_boundary,
                clause,
                &binding_order,
            )?;
            self.schedule_expressions(
                builder,
                binding_entry,
                &binding_evaluations,
                EdgeTarget::normal(binding_boundary),
                loop_scope,
                stack,
            )?;
        }
        stack.push(Work::Expression {
            node: right,
            entry,
            next: EdgeTarget::normal(test),
            scope,
        });
        Ok(())
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
    ) -> Result<(), GoLoweringError> {
        let result = self
            .multi_result_values
            .get(&node.id())
            .and_then(|values| values.first().copied())
            .map(Ok)
            .unwrap_or_else(|| {
                self.expression_value(builder, node, self.expression_value_kind(node))
            })?;
        if is_go_binding_reference_kind(node.kind()) && !self.is_go_constant_value(node) {
            self.emit_lexical_input_flow(builder, node, entry, result)?;
        }
        match node.kind() {
            "call_expression" if self.call_shaped_type_conversion_operand(node).is_some() => {
                let operand = self
                    .call_shaped_type_conversion_operand(node)
                    .expect("guard proves one structured conversion operand");
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Value(result),
                    SemanticCapability::Values,
                    SemanticGapKind::Unsupported,
                    "Go conversion result identity is intentionally not propagated",
                )?;
                stack.push(Work::Expression {
                    node: operand,
                    entry,
                    next,
                    scope,
                });
                Ok(())
            }
            "call_expression" if self.is_builtin_new_call(node) => {
                self.session
                    .add_allocation(builder, entry, result, AllocationKind::Object)?;
                self.edge(builder, entry, next)
            }
            "call_expression" if self.builtin_make_allocation_kind(node).is_some() => {
                let kind = self
                    .builtin_make_allocation_kind(node)
                    .expect("guard proves a structured builtin make allocation");
                let boundary = self.point(builder, node, Vec::new())?;
                if kind == AllocationKind::Slice {
                    self.value_storage_kinds
                        .insert(result, GoStorageKind::Slice);
                } else if kind == AllocationKind::Array {
                    self.value_storage_kinds.insert(result, GoStorageKind::Map);
                }
                self.session
                    .add_allocation(builder, boundary, result, kind)?;
                self.add_non_rejoining_exceptional_exit_gap(
                    builder,
                    scope,
                    boundary,
                    SemanticGapSubject::Point,
                    SemanticGapKind::Unknown,
                    "builtin make may panic when its structured size arguments are invalid",
                )?;
                self.edge(builder, boundary, next)?;
                let evaluations = all_call_arguments(node)
                    .into_iter()
                    .skip(1)
                    .collect::<Vec<_>>();
                self.schedule_expressions(
                    builder,
                    entry,
                    &evaluations,
                    EdgeTarget::normal(boundary),
                    scope,
                    stack,
                )
            }
            "call_expression" if self.builtin_panic_argument(node).is_some() => {
                // `panic(v)` never returns normally, so it is a throw rather
                // than a call: no callee, no unresolved-target gap, and no
                // normal continuation. `next` is deliberately unused, the
                // same shape `return` uses.
                //
                // Go has no intraprocedural handler, so the routed completion
                // carries the panic value to the procedure's exceptional exit
                // and stops there. `recover()` inside a deferred call is a
                // separate channel this adapter does not yet model.
                let argument = self
                    .builtin_panic_argument(node)
                    .expect("guard already matched a builtin panic argument");
                let terminal = self.point(builder, node, Vec::new())?;
                let source =
                    self.expression_value(builder, argument, self.expression_value_kind(argument))?;
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
                self.append_effect(
                    builder,
                    terminal,
                    SemanticEffect::Throw { value: Some(value) },
                )?;
                self.abrupt(builder, terminal, scope, CompletionKind::Throw, None, stack)?;
                self.schedule_expressions(
                    builder,
                    entry,
                    &[argument],
                    EdgeTarget::normal(terminal),
                    scope,
                    stack,
                )
            }
            "call_expression" if self.builtin_close_argument(node).is_some() => {
                let argument = self
                    .builtin_close_argument(node)
                    .expect("guard already matched a builtin close argument");
                let boundary = self.point(builder, node, Vec::new())?;
                let subject =
                    self.expression_value(builder, argument, self.expression_value_kind(argument))?;
                self.append_effect(
                    builder,
                    boundary,
                    SemanticEffect::Synchronization {
                        operation: SynchronizationOperation::ChannelClose,
                        subject,
                    },
                )?;
                self.add_non_rejoining_exceptional_exit_gap(
                    builder,
                    scope,
                    boundary,
                    SemanticGapSubject::Point,
                    SemanticGapKind::Unknown,
                    "close of a closed channel or send-only invalid channel may panic",
                )?;
                self.edge(builder, boundary, next)?;
                stack.push(Work::Expression {
                    node: argument,
                    entry,
                    next: EdgeTarget::normal(boundary),
                    scope,
                });
                Ok(())
            }
            "call_expression" if self.exact_append_backing(node).is_some() => {
                let boundary = self.point(builder, node, Vec::new())?;
                let backing = self
                    .exact_append_backing(node)
                    .expect("guard proves an exact append backing outcome");
                let append_start = match backing {
                    ExactAppendBacking::Retained {
                        source,
                        append_start,
                        result_shape,
                    } => {
                        self.exact_slice_shapes.insert(result, result_shape);
                        self.append_effect(
                            builder,
                            boundary,
                            SemanticEffect::ValueFlow {
                                kind: ValueFlowKind::BackingStore {
                                    offset: BackingStoreOffset::Zero,
                                },
                                source,
                                target: result,
                            },
                        )?;
                        append_start
                    }
                    ExactAppendBacking::Replaced { append_start } => {
                        self.session.add_allocation(
                            builder,
                            boundary,
                            result,
                            AllocationKind::Slice,
                        )?;
                        self.session.add_gap_with_impacts(
                            builder,
                            boundary,
                            SemanticGapSubject::Value(result),
                            SemanticCapability::IndexMemory,
                            SemanticGapImpacts::single(SemanticGapImpact::HeapRead)
                                .with(SemanticGapImpact::HeapWrite)
                                .with(SemanticGapImpact::Aliasing),
                            SemanticGapKind::Unsupported,
                            "Go append proves a replacement allocation, but copying prior elements into the new backing store is not yet lowered",
                        )?;
                        append_start
                    }
                };
                for (offset, argument) in all_call_arguments(node)[1..].iter().enumerate() {
                    let index = append_start
                        .checked_add(
                            u128::try_from(offset).expect("append argument count fits u128"),
                        )
                        .expect("exact append length arithmetic was already checked");
                    let index_value =
                        self.value(builder, boundary, SemanticValueKind::UnsignedInteger(index))?;
                    let location = self.session.add_memory_location(
                        builder,
                        boundary,
                        MemoryLocationKind::Index {
                            base: result,
                            index: Some(index_value),
                            constant_index: Some(index),
                            identity: IndexedLocationIdentity::Element,
                        },
                    )?;
                    let value = self.expression_value(
                        builder,
                        *argument,
                        self.expression_value_kind(*argument),
                    )?;
                    self.append_effect(
                        builder,
                        boundary,
                        SemanticEffect::MemoryStore {
                            kind: MemoryAccessKind::Index,
                            location,
                            value,
                        },
                    )?;
                }
                self.edge(builder, boundary, next)?;
                let evaluations = all_call_arguments(node);
                self.note_deterministic_evaluation_order(builder, entry, node, &evaluations)?;
                self.schedule_expressions(
                    builder,
                    entry,
                    &evaluations,
                    EdgeTarget::normal(boundary),
                    scope,
                    stack,
                )
            }
            "call_expression" => self.call_expression(builder, node, entry, next, scope, stack),
            "func_literal" => self.callable_expression(builder, node, entry, next),
            "binary_expression" if go_boolean_operator_kind(node).is_some() => {
                let merge = self.point(builder, node, Vec::new())?;
                // Both arms of the short circuit reconvene here, and the
                // boolean this expression produces derives from whichever
                // operands were evaluated to reach it.
                let operands = runtime_expression_children(node)
                    .into_iter()
                    .map(|child| {
                        self.expression_value(builder, child, self.expression_value_kind(child))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                self.session
                    .append_language_defined_value_flows(builder, merge, operands, result)?;
                self.edge(builder, merge, next)?;
                stack.push(Work::Condition {
                    node,
                    entry,
                    when_true: EdgeTarget {
                        point: merge,
                        kind: ControlEdgeKind::ConditionalTrue,
                    },
                    when_false: EdgeTarget {
                        point: merge,
                        kind: ControlEdgeKind::ConditionalFalse,
                    },
                    scope,
                });
                Ok(())
            }
            "parenthesized_expression" => {
                if let Some(value) = first_runtime_named_child(node) {
                    if parenthesized_call_receiver(node) {
                        // The call site and deferred-capture producer both
                        // name the transparent inner receiver. Do not emit a
                        // second wrapper assignment whose unused temporary
                        // would look like another possible value transfer.
                        stack.push(Work::Expression {
                            node: value,
                            entry,
                            next,
                            scope,
                        });
                        return Ok(());
                    }
                    let terminal = self.point(builder, node, Vec::new())?;
                    let source =
                        self.expression_value(builder, value, self.expression_value_kind(value))?;
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
            "unary_expression" if unary_operator_kind(node) == Some("<-") => {
                let operand = required_field(node, "operand")?;
                let boundary = self.point(builder, node, Vec::new())?;
                let subject =
                    self.expression_value(builder, operand, self.expression_value_kind(operand))?;
                self.append_effect(
                    builder,
                    boundary,
                    SemanticEffect::Synchronization {
                        operation: SynchronizationOperation::ChannelReceive,
                        subject,
                    },
                )?;
                self.add_retained_control_topology_gap(
                    builder,
                    boundary,
                    "channel receive may block and requires scheduler refinement",
                )?;
                self.edge(builder, boundary, next)?;
                stack.push(Work::Expression {
                    node: operand,
                    entry,
                    next: EdgeTarget::normal(boundary),
                    scope,
                });
                Ok(())
            }
            "unary_expression" if unary_operator_kind(node) == Some("&") => {
                let operand = required_field(node, "operand")?;
                let terminal = self.point(builder, node, Vec::new())?;
                let referenced = transparent_parenthesized_expression(operand);
                if matches!(
                    referenced.kind(),
                    "selector_expression" | "index_expression"
                ) {
                    let impacts = SemanticGapImpacts::single(SemanticGapImpact::Aliasing)
                        .with(SemanticGapImpact::HeapRead)
                        .with(SemanticGapImpact::HeapWrite);
                    if let Some((_kind, location, _index)) =
                        self.memory_place_location(builder, terminal, referenced)?
                    {
                        self.session.add_gap_with_impacts(
                            builder,
                            terminal,
                            SemanticGapSubject::MemoryLocation(location),
                            SemanticCapability::Assignments,
                            impacts,
                            SemanticGapKind::Unsupported,
                            "Go address-of memory location is not related to the produced address value",
                        )?;
                    } else {
                        self.session.add_gap_with_impacts(
                            builder,
                            terminal,
                            SemanticGapSubject::Value(result),
                            SemanticCapability::Assignments,
                            impacts,
                            SemanticGapKind::Unsupported,
                            "Go address-of selector or index has no materializable memory location",
                        )?;
                    }
                    self.edge(builder, terminal, next)?;
                    let evaluations = self.assignment_target_evaluation_nodes(referenced);
                    return self.schedule_expressions(
                        builder,
                        entry,
                        &evaluations,
                        EdgeTarget::normal(terminal),
                        scope,
                        stack,
                    );
                }
                let exact_binding = if is_go_binding_reference_kind(referenced.kind()) {
                    node_text(self.prepared.source(), referenced)
                        .and_then(|name| self.binding_value(name, referenced.start_byte()))
                } else {
                    None
                };
                let source = if let Some(binding) = exact_binding {
                    binding
                } else {
                    self.expression_value(
                        builder,
                        referenced,
                        self.expression_value_kind(referenced),
                    )?
                };
                if is_go_binding_reference_kind(referenced.kind()) && exact_binding.is_none() {
                    self.add_gap(
                        builder,
                        terminal,
                        SemanticGapSubject::Value(source),
                        SemanticCapability::Assignments,
                        SemanticGapKind::Unsupported,
                        "Go address-of identifier is not a lowered local, parameter, receiver, or exact value capture binding",
                    )?;
                }
                self.append_effect(
                    builder,
                    terminal,
                    SemanticEffect::Assignment {
                        target: result,
                        value: source,
                    },
                )?;
                self.edge(builder, terminal, next)?;
                if exact_binding.is_some() {
                    return self.edge(builder, entry, EdgeTarget::normal(terminal));
                }
                stack.push(Work::Expression {
                    node: operand,
                    entry,
                    next: EdgeTarget::normal(terminal),
                    scope,
                });
                Ok(())
            }
            "selector_expression"
                if matches!(
                    self.selector_resolution(node),
                    GoSelectorResolution::Method { .. }
                ) && !is_assignment_target(node) =>
            {
                let operand = required_field(node, "operand")?;
                let boundary = self.point(builder, node, Vec::new())?;
                self.add_gap(
                    builder,
                    boundary,
                    SemanticGapSubject::Value(result),
                    SemanticCapability::CallableReferences,
                    SemanticGapKind::Unknown,
                    "Go method-value selection is structured but its callable target is not yet published",
                )?;
                self.add_gap(
                    builder,
                    boundary,
                    SemanticGapSubject::Value(result),
                    SemanticCapability::DynamicDispatch,
                    SemanticGapKind::Unknown,
                    "Go method-value dispatch requires complete method-set refinement",
                )?;
                self.add_non_rejoining_exceptional_exit_gap(
                    builder,
                    scope,
                    boundary,
                    SemanticGapSubject::Value(result),
                    SemanticGapKind::Unknown,
                    "method-value selection may require an implicit dereference",
                )?;
                self.edge(builder, boundary, next)?;
                self.schedule_expressions(
                    builder,
                    entry,
                    &[operand],
                    EdgeTarget::normal(boundary),
                    scope,
                    stack,
                )
            }
            "selector_expression"
                if !self.selector_denotes_no_location(node) && !is_assignment_target(node) =>
            {
                let operand = required_field(node, "operand")?;
                let access = self.point(builder, node, Vec::new())?;
                let Some((kind, location)) = self.memory_access_location(builder, access, node)?
                else {
                    unreachable!("the selector load guard proves a memory place");
                };
                debug_assert_eq!(kind, MemoryAccessKind::Field);
                self.append_effect(
                    builder,
                    access,
                    SemanticEffect::MemoryLoad {
                        kind,
                        location,
                        result,
                    },
                )?;
                if self.selector_resolution(node) == GoSelectorResolution::Unknown
                    && !is_direct_call_function(node)
                {
                    self.add_gap(
                        builder,
                        access,
                        SemanticGapSubject::Value(result),
                        SemanticCapability::CallableReferences,
                        SemanticGapKind::Unknown,
                        "Go selector load may denote a method value, but its callable interpretation is unresolved",
                    )?;
                }
                if !self.is_direct_value_field(node) {
                    self.add_non_rejoining_exceptional_exit_gap(
                        builder,
                        scope,
                        access,
                        SemanticGapSubject::Value(result),
                        SemanticGapKind::Unsupported,
                        "selection may panic on a nil operand",
                    )?;
                }
                self.edge(builder, access, next)?;
                self.schedule_expressions(
                    builder,
                    entry,
                    &[operand],
                    EdgeTarget::normal(access),
                    scope,
                    stack,
                )
            }
            "index_expression"
                if !is_assignment_target(node)
                    && node
                        .child_by_field_name("index")
                        .is_some_and(|index| !is_go_type_syntax(index.kind())) =>
            {
                let operand = required_field(node, "operand")?;
                let index_node = required_field(node, "index")?;
                let access = self.point(builder, node, Vec::new())?;
                let Some((kind, location)) = self.memory_access_location(builder, access, node)?
                else {
                    unreachable!("the index load guard proves a memory place");
                };
                debug_assert_eq!(kind, MemoryAccessKind::Index);
                self.append_effect(
                    builder,
                    access,
                    SemanticEffect::MemoryLoad {
                        kind,
                        location,
                        result,
                    },
                )?;
                self.add_non_rejoining_exceptional_exit_gap(
                    builder,
                    scope,
                    access,
                    SemanticGapSubject::Value(result),
                    SemanticGapKind::Unsupported,
                    "indexing may panic on a nil operand or an out-of-range index",
                )?;
                self.edge(builder, access, next)?;
                let children = [operand, index_node];
                self.note_deterministic_evaluation_order(builder, entry, node, &children)?;
                self.schedule_expressions(
                    builder,
                    entry,
                    &children,
                    EdgeTarget::normal(access),
                    scope,
                    stack,
                )
            }
            "slice_expression" => {
                let operand = required_field(node, "operand")?;
                let boundary = self.point(builder, node, Vec::new())?;
                let source =
                    self.expression_value(builder, operand, self.expression_value_kind(operand))?;
                let offset = match node.child_by_field_name("start") {
                    None => BackingStoreOffset::Zero,
                    Some(start) => match go_integer_literal_value(self.prepared.source(), start) {
                        Some(offset) => BackingStoreOffset::Constant(offset),
                        None => BackingStoreOffset::Value(self.expression_value(
                            builder,
                            start,
                            self.expression_value_kind(start),
                        )?),
                    },
                };
                if matches!(
                    self.value_storage_kinds.get(&source),
                    Some(GoStorageKind::Array | GoStorageKind::Slice)
                ) {
                    self.value_storage_kinds
                        .insert(result, GoStorageKind::Slice);
                    self.append_effect(
                        builder,
                        boundary,
                        SemanticEffect::ValueFlow {
                            kind: ValueFlowKind::BackingStore { offset },
                            source,
                            target: result,
                        },
                    )?;
                } else {
                    self.session.add_gap_with_impacts(
                        builder,
                        boundary,
                        SemanticGapSubject::Value(result),
                        SemanticCapability::IndexMemory,
                        SemanticGapImpacts::single(SemanticGapImpact::Aliasing)
                            .with(SemanticGapImpact::HeapRead)
                            .with(SemanticGapImpact::HeapWrite),
                        SemanticGapKind::Unknown,
                        "Go slice expression has no exact local backing store",
                    )?;
                }
                self.add_non_rejoining_exceptional_exit_gap(
                    builder,
                    scope,
                    boundary,
                    SemanticGapSubject::Value(result),
                    SemanticGapKind::Unsupported,
                    "slicing may panic on an invalid bound",
                )?;
                self.edge(builder, boundary, next)?;
                let children = runtime_expression_children(node);
                self.note_deterministic_evaluation_order(builder, entry, node, &children)?;
                self.schedule_expressions(
                    builder,
                    entry,
                    &children,
                    EdgeTarget::normal(boundary),
                    scope,
                    stack,
                )
            }
            "unary_expression" if unary_operator_kind(node) == Some("*") => {
                // A dereference reads the pointee. Its value is the pointee's
                // own, not a value derived from the pointer, which is the same
                // identity claim the `&` arm above makes in the other
                // direction.
                let operand = required_field(node, "operand")?;
                let consumed = transparent_parenthesized_expression(operand);
                let terminal = self.point(builder, node, Vec::new())?;
                let source =
                    self.expression_value(builder, consumed, self.expression_value_kind(consumed))?;
                self.append_effect(
                    builder,
                    terminal,
                    SemanticEffect::ValueUse {
                        kind: ValueUseKind::Dereference,
                        value: source,
                    },
                )?;
                self.append_effect(
                    builder,
                    terminal,
                    SemanticEffect::Assignment {
                        target: result,
                        value: source,
                    },
                )?;
                self.add_non_rejoining_exceptional_exit_gap(
                    builder,
                    scope,
                    terminal,
                    SemanticGapSubject::Point,
                    SemanticGapKind::Unknown,
                    "operator evaluation may panic",
                )?;
                self.edge(builder, terminal, next)?;
                stack.push(Work::Expression {
                    node: operand,
                    entry,
                    next: EdgeTarget::normal(terminal),
                    scope,
                });
                Ok(())
            }
            "type_assertion_expression" => {
                // `x.(T)` on an interface operand is an identity unwrap: the
                // dynamic value the interface already holds is the value the
                // assertion produces. Without this the sink argument in
                // `sink(recovered.(int))` had no history at all (#2662).
                //
                // The two-result form `v, ok := x.(T)` never reaches here; it
                // arrives through assignment lowering, which still declines a
                // multi-target write.
                let operand = required_field(node, "operand")?;
                let terminal = self.point(builder, node, Vec::new())?;
                let source =
                    self.expression_value(builder, operand, self.expression_value_kind(operand))?;
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
                        kind: ValueFlowKind::Local,
                        source,
                        target: result,
                    },
                )?;
                self.add_non_rejoining_exceptional_exit_gap(
                    builder,
                    scope,
                    terminal,
                    SemanticGapSubject::Value(result),
                    SemanticGapKind::Unsupported,
                    "single-result type assertion may panic on a failed assertion",
                )?;
                self.edge(builder, terminal, next)?;
                self.schedule_expressions(
                    builder,
                    entry,
                    &[operand],
                    EdgeTarget::normal(terminal),
                    scope,
                    stack,
                )
            }
            "selector_expression" if self.is_import_qualified_selector(node) => {
                // A package name is not an evaluated receiver, and the
                // selector does not name struct-field memory.
                self.edge(builder, entry, next)
            }
            "selector_expression" | "index_expression" => {
                let boundary = self.point(builder, node, Vec::new())?;
                self.add_non_rejoining_exceptional_exit_gap(
                    builder,
                    scope,
                    boundary,
                    SemanticGapSubject::Value(result),
                    SemanticGapKind::Unsupported,
                    "selection, indexing, or slicing may panic",
                )?;
                self.edge(builder, boundary, next)?;
                let children = runtime_expression_children(node);
                self.note_deterministic_evaluation_order(builder, entry, node, &children)?;
                self.schedule_expressions(
                    builder,
                    entry,
                    &children,
                    EdgeTarget::normal(boundary),
                    scope,
                    stack,
                )
            }
            "binary_expression" | "unary_expression" => {
                // The operator result derives from every operand. Without this
                // flow an arithmetic step silently ended the value's history.
                let children = runtime_expression_children(node);
                let terminal = self.point(builder, node, Vec::new())?;
                let operands = children
                    .iter()
                    .map(|child| {
                        self.expression_value(builder, *child, self.expression_value_kind(*child))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                self.session
                    .append_language_defined_value_flows(builder, terminal, operands, result)?;
                if go_operation_can_panic(node) {
                    self.add_non_rejoining_exceptional_exit_gap(
                        builder,
                        scope,
                        terminal,
                        SemanticGapSubject::Point,
                        SemanticGapKind::Unknown,
                        "operator evaluation may panic",
                    )?;
                }
                self.edge(builder, terminal, next)?;
                self.note_deterministic_evaluation_order(builder, entry, node, &children)?;
                self.schedule_expressions(
                    builder,
                    entry,
                    &children,
                    EdgeTarget::normal(terminal),
                    scope,
                    stack,
                )
            }
            "type_conversion_expression" => {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Value(result),
                    SemanticCapability::Values,
                    SemanticGapKind::Unsupported,
                    "Go conversion result identity is intentionally not propagated",
                )?;
                let children = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            "composite_literal" => {
                let kind = match node.child_by_field_name("type").map(|node| node.kind()) {
                    Some("slice_type") => AllocationKind::Slice,
                    Some("array_type" | "implicit_length_array_type" | "map_type") => {
                        AllocationKind::Array
                    }
                    _ => AllocationKind::Object,
                };
                self.session.add_allocation(builder, entry, result, kind)?;
                let children = runtime_expression_children(node);
                self.note_deterministic_evaluation_order(builder, entry, node, &children)?;
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            "literal_value" | "literal_element" | "keyed_element" | "expression_list"
            | "argument_list" | "variadic_argument" => {
                let children = runtime_expression_children(node);
                self.note_deterministic_evaluation_order(builder, entry, node, &children)?;
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            "type_instantiation_expression" => self.edge(builder, entry, next),
            kind if is_runtime_leaf(kind) => self.edge(builder, entry, next),
            _ => self.unhandled_control_syntax(builder, node, entry),
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
    ) -> Result<(), GoLoweringError> {
        let invoke = self.emit_call_expression(builder, node, next, scope, false, stack)?;
        let evaluations = self.call_operand_evaluations(node, false)?;
        self.note_deterministic_evaluation_order(builder, entry, node, &evaluations)?;
        self.schedule_expressions(
            builder,
            entry,
            &evaluations,
            EdgeTarget::normal(invoke),
            scope,
            stack,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn deferred_call_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), GoLoweringError> {
        if self.builtin_close_argument(node).is_some() {
            let capture = self.deferred_captures.get(&node.id()).ok_or_else(|| {
                GoLoweringError::Invalid("supported deferred close has no captured operand".into())
            })?;
            let [(_, subject)] = capture.arguments.as_ref() else {
                return Err(GoLoweringError::Invalid(
                    "builtin close must have one captured operand".into(),
                ));
            };
            let subject = *subject;
            let boundary = self.point(builder, node, Vec::new())?;
            self.append_effect(
                builder,
                boundary,
                SemanticEffect::Synchronization {
                    operation: SynchronizationOperation::ChannelClose,
                    subject,
                },
            )?;
            self.add_non_rejoining_exceptional_exit_gap(
                builder,
                scope,
                boundary,
                SemanticGapSubject::Point,
                SemanticGapKind::Unknown,
                "deferred close of a closed channel or send-only invalid channel may panic",
            )?;
            self.edge(builder, entry, EdgeTarget::normal(boundary))?;
            return self.edge(builder, boundary, next);
        }
        let invoke = self.emit_call_expression(builder, node, next, scope, true, stack)?;
        self.edge(builder, entry, EdgeTarget::normal(invoke))
    }

    fn spawned_call_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        next: EdgeTarget,
    ) -> Result<ProgramPointId, GoLoweringError> {
        let invoke = self.point(builder, node, Vec::new())?;
        let normal = self.point(builder, node, Vec::new())?;
        let operands = self.lower_call_operands(builder, node, invoke, None)?;
        let call_site = self.session.add_spawned_call_site(
            builder,
            SpawnedCallSiteScaffold {
                point: invoke,
                callee: operands.callee,
                receiver: operands.receiver,
                arguments: operands.arguments,
                declared_targets: operands.resolution.clone(),
                normal_continuation: normal,
            },
        )?;
        self.edge(builder, invoke, EdgeTarget::normal(normal))?;
        self.edge(builder, normal, next)?;
        self.resolution_gaps(
            builder,
            invoke,
            operands.callee,
            call_site,
            &operands.resolution,
        )?;
        if operands.receiver.is_some()
            || operands.selector_resolution == Some(GoSelectorResolution::Unknown)
        {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::DynamicDispatch,
                SemanticGapKind::Unknown,
                if operands.selector_resolution == Some(GoSelectorResolution::Unknown) {
                    "selector callee may be a function-valued field, interface method, or promoted method; receiver type and complete method-set coverage require refinement"
                } else {
                    "selector dispatch may target an interface method or promoted method; receiver type and complete method-set coverage require type refinement"
                },
            )?;
        }
        Ok(invoke)
    }

    fn lower_call_operands(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        invoke: ProgramPointId,
        capture: Option<&DeferredCapture>,
    ) -> Result<LoweredCallOperands, GoLoweringError> {
        let function = required_field(node, "function")?;
        let callee = self.expression_value(builder, function, SemanticValueKind::Callable)?;
        let selector_resolution =
            (function.kind() == "selector_expression").then(|| self.selector_resolution(function));
        let receiver_node = selector_resolution
            .and_then(|resolution| match resolution {
                GoSelectorResolution::Method { .. } | GoSelectorResolution::Unknown => {
                    function.child_by_field_name("operand")
                }
                GoSelectorResolution::Package | GoSelectorResolution::Field => None,
            })
            .map(transparent_parenthesized_expression);
        let receiver = if let Some(captured) =
            capture.and_then(|capture| capture.receiver.map(|(_, target)| target))
        {
            Some(captured)
        } else {
            receiver_node
                .map(|receiver| {
                    self.expression_value(builder, receiver, self.expression_value_kind(receiver))
                })
                .transpose()?
        };
        let callable_kind = if receiver.is_some() {
            CallableReferenceKind::BoundMethod
        } else {
            CallableReferenceKind::Function
        };
        let direct_function = transparent_parenthesized_expression(function);
        let resolution = if direct_function.kind() == "func_literal" {
            self.procedure_targets
                .get(&direct_function.id())
                .map(|target| CallableTargetResolution::Proven(CallableTarget::Local(target.id)))
                .unwrap_or(CallableTargetResolution::Unknown)
        } else {
            CallableTargetResolution::Unknown
        };
        let metadata = self.metadata(invoke)?;
        if selector_resolution == Some(GoSelectorResolution::Unknown) {
            // The selector can still denote a function-valued field. Retain
            // that alternative beside the bound-method interpretation so the
            // call row carries the receiver candidate without certifying that
            // one receiver binding exists.
            self.append_effect(
                builder,
                invoke,
                SemanticEffect::CallableReference {
                    result: callee,
                    callable: CallableValue {
                        kind: CallableReferenceKind::Function,
                        targets: resolution.clone(),
                        target_evidence: metadata.evidence,
                        bound_receiver: None,
                        environment: None,
                    },
                },
            )?;
        }
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
            .enumerate()
            .map(
                |(index, argument)| -> Result<SemanticCallArgument, GoLoweringError> {
                    let value_node = go_call_argument_value_node(*argument);
                    let value = if let Some(captured) = capture
                        .and_then(|capture| capture.arguments.get(index))
                        .map(|(_, target)| *target)
                    {
                        captured
                    } else {
                        self.expression_value(
                            builder,
                            value_node,
                            self.expression_value_kind(value_node),
                        )?
                    };
                    Ok(if argument.kind() == "variadic_argument" {
                        SemanticCallArgument {
                            value,
                            expansion: CallArgumentExpansion::Spread(ArgumentDomain::Positional),
                            keyword: None,
                        }
                    } else {
                        SemanticCallArgument::direct(value, ArgumentDomain::Positional)
                    })
                },
            )
            .collect::<Result<Vec<_>, _>>()?;
        Ok(LoweredCallOperands {
            callee,
            receiver,
            arguments: argument_values.into_boxed_slice(),
            resolution,
            selector_resolution,
        })
    }

    fn emit_call_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        next: EdgeTarget,
        scope: ScopeFrameId,
        deferred: bool,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<ProgramPointId, GoLoweringError> {
        let invoke = self.point(builder, node, Vec::new())?;
        let normal = self.point(builder, node, Vec::new())?;
        let exceptional = self.point(builder, node, Vec::new())?;
        let function = required_field(node, "function")?;
        let normal_results = self.multi_result_values.get(&node.id()).cloned();
        let result = if normal_results.is_none() {
            Some(if deferred {
                self.source_value(builder, node, SemanticValueKind::Temporary)?
            } else {
                self.expression_value(builder, node, SemanticValueKind::Temporary)?
            })
        } else {
            None
        };
        let thrown = self.source_value(builder, function, SemanticValueKind::Exception)?;
        let capture = deferred
            .then(|| self.deferred_captures.get(&node.id()).cloned())
            .flatten();
        let operands = self.lower_call_operands(builder, node, invoke, capture.as_ref())?;
        let scaffold = CallSiteScaffold {
            point: invoke,
            callee: operands.callee,
            receiver: operands.receiver,
            arguments: operands.arguments,
            normal_results: normal_results.unwrap_or_default(),
            result,
            thrown: Some(thrown),
            declared_targets: operands.resolution.clone(),
            normal_continuation: normal,
            exceptional_continuation: exceptional,
        };
        let call_site = if deferred {
            self.session.add_deferred_call_site(builder, scaffold)?
        } else {
            self.session.add_call_site(builder, scaffold)?
        };
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
        self.abrupt(
            builder,
            exceptional,
            scope,
            CompletionKind::Throw,
            None,
            stack,
        )?;
        self.resolution_gaps(
            builder,
            invoke,
            operands.callee,
            call_site,
            &operands.resolution,
        )?;

        if operands.receiver.is_some()
            || operands.selector_resolution == Some(GoSelectorResolution::Unknown)
        {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::DynamicDispatch,
                SemanticGapKind::Unknown,
                if operands.selector_resolution == Some(GoSelectorResolution::Unknown) {
                    "selector callee may be a function-valued field, interface method, or promoted method; receiver type and complete method-set coverage require refinement"
                } else {
                    "selector dispatch may target an interface method or promoted method; receiver type and complete method-set coverage require type refinement"
                },
            )?;
        }

        Ok(invoke)
    }

    fn callable_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
    ) -> Result<(), GoLoweringError> {
        let result = self.expression_value(builder, node, SemanticValueKind::Callable)?;
        let target = self.procedure_targets.get(&node.id()).cloned();
        let resolution = target
            .as_ref()
            .map(|target| CallableTargetResolution::Proven(CallableTarget::Local(target.id)))
            .unwrap_or(CallableTargetResolution::Unknown);
        let metadata = self.metadata(entry)?;
        let kind = CallableReferenceKind::Lambda;
        let environment = if target
            .as_ref()
            .is_some_and(|target| !target.captures.is_empty())
        {
            Some(self.session.add_allocation(
                builder,
                entry,
                result,
                AllocationKind::ClosureEnvironment,
            )?)
        } else {
            None
        };
        let callable = CallableValue {
            kind,
            targets: resolution.clone(),
            target_evidence: metadata.evidence,
            bound_receiver: None,
            environment,
        };
        self.append_effect(
            builder,
            entry,
            SemanticEffect::CallableCreation { result, callable },
        )?;
        if let (Some(target), Some(environment)) = (target.as_ref(), environment) {
            for (index, capture) in target.captures.iter().enumerate() {
                let source = self
                    .captured_or_owned_binding_value(capture.name.as_ref(), capture.binding)
                    .ok_or_else(|| {
                        GoLoweringError::Invalid(format!(
                            "precomputed Go capture `{}` has no parent binding",
                            capture.name
                        ))
                    })?;
                let destination = MemoryLocationId::new(u32::try_from(index).map_err(|_| {
                    GoLoweringError::Invalid("too many Go capture destinations".into())
                })?);
                let (captured, mode) = match capture.storage {
                    GoCaptureStorage::Value => (CaptureSource::Value(source), CaptureMode::Value),
                    GoCaptureStorage::MutableCell => {
                        let (location, _) = self
                            .shared_binding_locations
                            .get(&source)
                            .copied()
                            .ok_or_else(|| {
                                GoLoweringError::Invalid(format!(
                                    "shared Go capture `{}` has no parent cell",
                                    capture.name
                                ))
                            })?;
                        (CaptureSource::Location(location), CaptureMode::MutableCell)
                    }
                };
                self.session.add_capture(
                    builder,
                    entry,
                    result,
                    target.id,
                    environment,
                    captured,
                    destination,
                    mode,
                )?;
            }
        }
        if let Some(target) = target.as_ref() {
            for name in &target.omitted_capture_names {
                let Some(source) = self.binding_value(name, node.start_byte()) else {
                    continue;
                };
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Value(source),
                    SemanticCapability::Captures,
                    SemanticGapKind::Unsupported,
                    "Go closure captures this parent binding by reference, whose value identity is not modeled",
                )?;
            }
        }
        if resolution == CallableTargetResolution::Unknown {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Value(result),
                SemanticCapability::CallableReferences,
                SemanticGapKind::Unknown,
                "function-literal target mapping requires location-first dispatch refinement",
            )?;
        }
        self.edge(builder, entry, next)
    }

    fn unhandled_control_syntax(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
    ) -> Result<(), GoLoweringError> {
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

    fn note_deterministic_evaluation_order(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        node: Node<'tree>,
        evaluations: &[Node<'tree>],
    ) -> Result<(), GoLoweringError> {
        let Some(detail) = self.go_evaluation_order_gap_detail(node, evaluations) else {
            return Ok(());
        };
        self.session.add_gap_with_impacts_and_discharge(
            builder,
            point,
            SemanticGapSubject::Point,
            SemanticCapability::NormalControlFlow,
            SemanticGapImpacts::NONE,
            SemanticGapKind::Unknown,
            SemanticGapDischarge::RetainedEvaluationOrder,
            detail,
        )?;
        Ok(())
    }

    fn go_evaluation_order_gap_detail(
        &self,
        node: Node<'tree>,
        evaluations: &[Node<'tree>],
    ) -> Option<&'static str> {
        let unspecified = match node.kind() {
            "composite_literal" => self.composite_literal_has_unspecified_order(node),
            "literal_value" => {
                node.parent()
                    .is_none_or(|parent| parent.kind() != "composite_literal")
                    && self.literal_value_has_unspecified_order(node)
            }
            // The containing literal_value or composite_literal owns this gap
            // so selectors have one precise source-backed boundary rather
            // than one duplicate per keyed element.
            "keyed_element" => false,
            _ => self.evaluation_units_have_unspecified_order(evaluations),
        };
        unspecified.then_some(
            if matches!(node.kind(), "composite_literal" | "literal_value") {
                "Go does not fully specify composite-literal operand and element evaluation order; deterministic CFG topology uses source order while preserving the specified lexical order of calls, receives, and logical operations"
            } else {
                "Go specifies lexical left-to-right order for calls, method calls, receives, and logical operations, but not all other operand evaluations; deterministic CFG topology uses source order for the unspecified remainder"
            },
        )
    }

    fn composite_literal_has_unspecified_order(&self, node: Node<'tree>) -> bool {
        let Some(body) = node.child_by_field_name("body") else {
            return false;
        };
        self.literal_value_has_unspecified_order(body)
    }

    fn literal_value_has_unspecified_order(&self, node: Node<'tree>) -> bool {
        let elements = named_children(node);
        let aggregate_kind = self.literal_value_aggregate_kind(node);
        let element_traits = elements
            .iter()
            .map(|element| self.literal_element_evaluation_traits(*element, aggregate_kind))
            .collect::<Vec<_>>();
        self.evaluation_traits_have_unspecified_order(&element_traits)
            || elements.iter().any(|element| {
                let Some(key) = element.child_by_field_name("key") else {
                    return false;
                };
                self.literal_key_is_evaluated(key, aggregate_kind)
                    && element.child_by_field_name("value").is_some_and(|value| {
                        self.evaluation_units_have_unspecified_order(&[key, value])
                    })
            })
            || (aggregate_kind != GoLiteralAggregateKind::NonMap
                && self.map_literal_has_unordered_assignments(node, aggregate_kind))
    }

    fn literal_element_evaluation_traits(
        &self,
        element: Node<'tree>,
        aggregate_kind: GoLiteralAggregateKind,
    ) -> GoEvaluationTraits {
        if element.kind() != "keyed_element" {
            return self.go_evaluation_traits(element);
        }
        let mut traits = element
            .child_by_field_name("value")
            .map(|value| self.go_evaluation_traits(value))
            .unwrap_or_default();
        if let Some(key) = element.child_by_field_name("key")
            && self.literal_key_is_evaluated(key, aggregate_kind)
        {
            traits.merge(self.go_evaluation_traits(key));
        }
        traits
    }

    fn literal_key_is_evaluated(
        &self,
        key: Node<'tree>,
        aggregate_kind: GoLiteralAggregateKind,
    ) -> bool {
        match aggregate_kind {
            GoLiteralAggregateKind::Map => true,
            GoLiteralAggregateKind::NonMap => false,
            GoLiteralAggregateKind::Unknown => self.unknown_literal_key_is_runtime(key),
        }
    }

    /// A qualified or otherwise unresolved composite type can be either a map
    /// or a struct. Preserve a key only when its AST proves a runtime
    /// expression, or when a bare name resolves to a value this intrafile
    /// inventory knows. An unresolved bare name remains a possible static
    /// struct field label, avoiding map-order gaps for imported structs.
    fn unknown_literal_key_is_runtime(&self, mut key: Node<'tree>) -> bool {
        while let Some(inner) = transparent_runtime_wrapper_child(key) {
            key = inner;
        }
        if is_go_binding_reference_kind(key.kind()) {
            let Some(name) = node_text(self.prepared.source(), key) else {
                return false;
            };
            return self.binding_value(name, key.start_byte()).is_some()
                || self.package_values.contains(name);
        }
        key.kind() != "field_identifier"
    }

    fn evaluation_units_have_unspecified_order(&self, evaluations: &[Node<'tree>]) -> bool {
        let traits = evaluations
            .iter()
            .map(|evaluation| self.go_evaluation_traits(*evaluation))
            .collect::<Vec<_>>();
        self.evaluation_traits_have_unspecified_order(&traits)
    }

    fn evaluation_traits_have_unspecified_order(&self, traits: &[GoEvaluationTraits]) -> bool {
        for (index, earlier) in traits.iter().enumerate() {
            if !earlier.runtime_read && !earlier.call_or_receive && !earlier.may_abort {
                continue;
            }
            for later in &traits[index + 1..] {
                if !later.runtime_read && !later.call_or_receive && !later.may_abort {
                    continue;
                }
                if (earlier.may_abort && later.may_abort)
                    || (earlier.call_or_receive && (later.runtime_read || later.may_abort))
                    || ((earlier.runtime_read || earlier.may_abort)
                        && !earlier.ordered_completion
                        && later.call_or_receive)
                {
                    return true;
                }
            }
        }
        false
    }

    /// The ways one evaluation unit can make an otherwise unspecified source
    /// order observable.
    ///
    /// A call or receive may mutate or synchronize with an adjacent read, so
    /// the specification's `[]int{a, f()}` example needs only one such event.
    /// A panic-only operation beside a plain read does not expose their order,
    /// but two potentially aborting units do expose which panic wins. The walk
    /// is iterative and does not descend into a function literal whose body is
    /// evaluated only when that literal is called.
    fn go_evaluation_traits(&self, node: Node<'tree>) -> GoEvaluationTraits {
        let mut traits = GoEvaluationTraits {
            ordered_completion: go_evaluation_unit_has_ordered_completion(node),
            ..GoEvaluationTraits::default()
        };
        let mut stack = vec![node];
        while let Some(current) = stack.pop() {
            if is_comment_kind(current.kind()) || is_go_type_syntax(current.kind()) {
                continue;
            }
            if current.kind() == "func_literal" || self.is_go_constant_value(current) {
                continue;
            }
            if self.is_import_qualified_selector(current) {
                // The selected declaration can be a mutable package variable,
                // but the package qualifier is resolved syntax rather than a
                // nil-able runtime receiver.
                traits.runtime_read = true;
                continue;
            }
            match current.kind() {
                "call_expression" => {
                    traits.call_or_receive = true;
                    if let Some(function) = current.child_by_field_name("function") {
                        match function.kind() {
                            "identifier" | "true" | "false" | "nil" | "iota" => {
                                if self.identifier_is_shared_or_call_exposed(function) {
                                    traits.runtime_read = true;
                                }
                            }
                            "selector_expression" => match self.selector_resolution(function) {
                                GoSelectorResolution::Package => {}
                                GoSelectorResolution::Field | GoSelectorResolution::Unknown => {
                                    stack.push(function)
                                }
                                GoSelectorResolution::Method { .. } => {
                                    if let Some(receiver) = function.child_by_field_name("operand")
                                    {
                                        stack.push(receiver);
                                    }
                                }
                            },
                            _ => stack.push(function),
                        }
                    }
                    stack.extend(call_arguments(current).into_iter().rev());
                    continue;
                }
                "unary_expression" if unary_operator_kind(current) == Some("<-") => {
                    traits.call_or_receive = true;
                    if let Some(operand) = current.child_by_field_name("operand") {
                        stack.push(operand);
                    }
                    continue;
                }
                "binary_expression" if go_boolean_operator_kind(current).is_some() => {
                    traits.call_or_receive = true;
                }
                "unary_expression" if unary_operator_kind(current) == Some("&") => {
                    if let Some(operand) = current.child_by_field_name("operand") {
                        let target = transparent_parenthesized_expression(operand);
                        if !is_go_binding_reference_kind(target.kind())
                            && !(target.kind() == "selector_expression"
                                && self.is_direct_value_field(target))
                        {
                            stack.push(target);
                        }
                    }
                    continue;
                }
                "index_expression" | "slice_expression" | "type_assertion_expression" => {
                    traits.runtime_read = true;
                    traits.may_abort = true;
                }
                "selector_expression" => {
                    let direct_value_field = self.is_direct_value_field(current);
                    traits.may_abort |= !direct_value_field;
                    if !direct_value_field
                        || current
                            .child_by_field_name("operand")
                            .and_then(|operand| self.place_root_binding(operand))
                            .is_some_and(|binding| self.call_exposed_bindings.contains(&binding))
                    {
                        traits.runtime_read = true;
                    }
                    if let Some(operand) = current.child_by_field_name("operand") {
                        stack.push(operand);
                    }
                    continue;
                }
                "identifier" | "true" | "false" | "nil" | "iota" => {
                    traits.runtime_read |= self.identifier_is_shared_or_call_exposed(current);
                }
                "field_identifier" | "package_identifier" => {
                    traits.runtime_read = true;
                }
                _ => {}
            }
            if go_operation_can_panic(current) {
                traits.may_abort = true;
            }
            stack.extend(named_children(current));
        }
        traits
    }

    /// Map entries are assignments whose relative order Go leaves
    /// unspecified. Two entries commute only when their keys are proven
    /// distinct; valid Go source guarantees that basic constant keys do not
    /// duplicate, while any runtime key can collide with another entry.
    fn is_go_constant_evaluation(&self, mut node: Node<'tree>) -> bool {
        loop {
            if self.is_go_constant_value(node) {
                return true;
            }
            let Some(only) = transparent_runtime_wrapper_child(node) else {
                return false;
            };
            node = only;
        }
    }

    fn map_literal_has_unordered_assignments(
        &self,
        body: Node<'tree>,
        aggregate_kind: GoLiteralAggregateKind,
    ) -> bool {
        let entries = named_children(body)
            .into_iter()
            .filter(|element| element.kind() == "keyed_element")
            .collect::<Vec<_>>();
        entries.len() > 1
            && entries.into_iter().any(|entry| {
                entry.child_by_field_name("key").is_some_and(|key| {
                    self.literal_key_is_evaluated(key, aggregate_kind)
                        && !self.is_go_constant_evaluation(key)
                })
            })
    }

    fn literal_value_aggregate_kind(&self, body: Node<'tree>) -> GoLiteralAggregateKind {
        let Some(kind) = self
            .literal_value_expected_type(body)
            .and_then(|kind| self.file_underlying_type(kind, body.start_byte()))
        else {
            return GoLiteralAggregateKind::Unknown;
        };
        match kind.kind() {
            "map_type" => GoLiteralAggregateKind::Map,
            "struct_type" | "array_type" | "implicit_length_array_type" | "slice_type" => {
                GoLiteralAggregateKind::NonMap
            }
            _ => GoLiteralAggregateKind::Unknown,
        }
    }

    /// Recover the type expected by an explicit or elided literal value using
    /// only tree-sitter fields and same-file named type declarations.
    fn literal_value_expected_type(&self, mut body: Node<'tree>) -> Option<Node<'tree>> {
        let use_byte = body.start_byte();
        let mut nesting = Vec::new();
        let mut kind = loop {
            let parent = body.parent()?;
            if parent.kind() == "composite_literal" && field_matches(parent, "body", body) {
                break parent.child_by_field_name("type")?;
            }
            if parent.kind() != "literal_element" {
                return None;
            }
            let wrapper = parent;
            let container = wrapper.parent()?;
            match container.kind() {
                "literal_value" => {
                    nesting.push(GoLiteralNestingStep::Element);
                    body = container;
                }
                "keyed_element" => {
                    nesting.push(if field_matches(container, "key", wrapper) {
                        GoLiteralNestingStep::Key
                    } else if field_matches(container, "value", wrapper) {
                        GoLiteralNestingStep::Value
                    } else {
                        return None;
                    });
                    body = container
                        .parent()
                        .filter(|parent| parent.kind() == "literal_value")?;
                }
                _ => return None,
            }
        };

        for step in nesting.into_iter().rev() {
            kind = self.literal_component_type(kind, step, use_byte)?;
        }
        Some(kind)
    }

    fn literal_component_type(
        &self,
        kind: Node<'tree>,
        step: GoLiteralNestingStep,
        use_byte: usize,
    ) -> Option<Node<'tree>> {
        let kind = self.file_underlying_type(kind, use_byte)?;
        let component = match (kind.kind(), step) {
            ("array_type" | "implicit_length_array_type" | "slice_type", _) => {
                kind.child_by_field_name("element")
            }
            ("map_type", GoLiteralNestingStep::Key) => kind.child_by_field_name("key"),
            ("map_type", GoLiteralNestingStep::Element | GoLiteralNestingStep::Value) => {
                kind.child_by_field_name("value")
            }
            _ => None,
        }?;
        if component.kind() == "pointer_type" {
            first_named_child(component)
        } else {
            Some(component)
        }
    }

    fn file_underlying_type(&self, kind: Node<'tree>, use_byte: usize) -> Option<Node<'tree>> {
        go_file_underlying_type(
            kind,
            self.prepared.source(),
            self.named_type_definitions,
            use_byte,
        )
    }

    fn is_import_qualified_selector(&self, node: Node<'tree>) -> bool {
        node.kind() == "selector_expression"
            && node
                .child_by_field_name("operand")
                .is_some_and(|operand| self.is_import_qualifier(operand))
    }

    fn call_operand_evaluations(
        &self,
        call: Node<'tree>,
        include_identifier_function: bool,
    ) -> Result<Vec<Node<'tree>>, GoLoweringError> {
        let function = required_field(call, "function")?;
        let arguments = call_arguments(call);
        let mut result = Vec::with_capacity(arguments.len() + 1);
        if function.kind() == "selector_expression" {
            match self.selector_resolution(function) {
                GoSelectorResolution::Package => {}
                GoSelectorResolution::Field | GoSelectorResolution::Unknown => {
                    result.push(function)
                }
                GoSelectorResolution::Method { .. } => {
                    if let Some(receiver) = function.child_by_field_name("operand")
                        && !is_go_type_syntax(receiver.kind())
                    {
                        result.push(receiver);
                    }
                }
            }
        } else if include_identifier_function
            || !is_go_binding_reference_kind(function.kind())
            || (is_go_binding_reference_kind(function.kind())
                && self.identifier_is_shared_or_call_exposed(function))
        {
            result.push(function);
        }
        result.extend(arguments);
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    fn materialize_statement_next(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        next: StatementNext,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<EdgeTarget, GoLoweringError> {
        match next {
            StatementNext::Target(target) => Ok(target),
            StatementNext::Continuation(continuation) => {
                let key = (continuation, scope);
                if let Some(entry) = self.continuation_entries.get(&key).copied() {
                    return Ok(EdgeTarget::normal(entry));
                }
                let descriptor = *self
                    .statement_continuations
                    .get(continuation.index())
                    .ok_or_else(|| {
                        GoLoweringError::Invalid(format!(
                            "missing Go statement continuation {}",
                            continuation.index()
                        ))
                    })?;
                builder.descend_nested_entry()?;
                let entry = self.point(builder, descriptor.node, Vec::new())?;
                self.continuation_entries.insert(key, entry);
                self.materialized_continuations.insert(continuation);
                stack.push(Work::Statement {
                    node: descriptor.node,
                    entry,
                    next: descriptor.next,
                    scope,
                    label: None,
                });
                Ok(EdgeTarget::normal(entry))
            }
            StatementNext::FunctionReturn => {
                let route = builder
                    .resolve_completion(
                        scope,
                        &CompletionRequest::new(CompletionKind::Return, None),
                    )
                    .ok_or_else(|| {
                        GoLoweringError::Invalid(
                            "Go fallthrough has no function return destination".into(),
                        )
                    })?;
                if route.cleanups().is_empty() {
                    return Ok(EdgeTarget {
                        point: route.destination().target(),
                        kind: route.destination().edge_kind(),
                    });
                }
                if let Some(entry) = self.return_entries.get(&scope).copied() {
                    return Ok(EdgeTarget::normal(entry));
                }
                builder.descend_nested_entry()?;
                let entry = self.point(builder, self.root_body, Vec::new())?;
                self.return_entries.insert(scope, entry);
                self.route(builder, entry, &route, stack)?;
                Ok(EdgeTarget::normal(entry))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn schedule_statements(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        children: &[Node<'tree>],
        next: StatementNext,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), GoLoweringError> {
        let mut continuation = next;
        for child in children.iter().copied().rev() {
            builder.descend_nested_entry()?;
            let id = StatementContinuationId::try_from_index(self.statement_continuations.len())?;
            self.statement_continuations.push(StatementContinuation {
                node: child,
                next: continuation,
                retention_scope: scope,
            });
            continuation = StatementNext::Continuation(id);
        }
        let continuation = self.materialize_statement_next(builder, continuation, scope, stack)?;
        self.edge(builder, entry, continuation)
    }

    fn prepare_deferred_capture(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        call: Node<'tree>,
    ) -> Result<DeferredCapture, GoLoweringError> {
        let function = required_field(call, "function")?;
        let receiver_node = (function.kind() == "selector_expression")
            .then(|| match self.selector_resolution(function) {
                GoSelectorResolution::Method { .. } | GoSelectorResolution::Unknown => {
                    function.child_by_field_name("operand")
                }
                GoSelectorResolution::Package | GoSelectorResolution::Field => None,
            })
            .flatten()
            .map(transparent_parenthesized_expression);
        let receiver = receiver_node
            .map(|receiver| self.deferred_capture_value(builder, receiver))
            .transpose()?;
        let arguments = call_arguments(call)
            .into_iter()
            .map(|argument| {
                self.deferred_capture_value(builder, go_call_argument_value_node(argument))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(DeferredCapture {
            receiver,
            arguments: arguments.into_boxed_slice(),
        })
    }

    fn has_stable_deferred_callable(&self, call: Node<'tree>) -> Result<bool, GoLoweringError> {
        let function = required_field(call, "function")?;
        if function.kind() == "selector_expression" {
            return Ok(matches!(
                self.selector_resolution(function),
                GoSelectorResolution::Package
                    | GoSelectorResolution::Method { .. }
                    | GoSelectorResolution::Unknown
            ));
        }
        if !is_go_binding_reference_kind(function.kind()) {
            return Ok(true);
        }
        let Some(name) = node_text(self.prepared.source(), function) else {
            return Ok(false);
        };
        Ok(self.binding_value(name, function.start_byte()).is_none())
    }

    fn defer_is_inside_loop(&self, node: Node<'tree>) -> bool {
        let mut cursor = node.parent();
        while let Some(ancestor) = cursor {
            if ancestor.id() == self.root_body.id() {
                return false;
            }
            if ancestor.kind() == "for_statement" {
                return true;
            }
            cursor = ancestor.parent();
        }
        false
    }

    fn defer_is_inside_expression_switch(&self, node: Node<'tree>) -> bool {
        let mut cursor = node.parent();
        while let Some(ancestor) = cursor {
            if ancestor.id() == self.root_body.id() {
                return false;
            }
            if ancestor.kind() == "expression_switch_statement" {
                return true;
            }
            cursor = ancestor.parent();
        }
        false
    }

    fn deferred_capture_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<(ValueId, ValueId), GoLoweringError> {
        let source = self.expression_value(builder, node, self.expression_value_kind(node))?;
        let target = self.source_value(
            builder,
            node,
            SemanticValueKind::LanguageDefined("go.defer_capture".into()),
        )?;
        if let Some(identity) = self.value_types.get(&source).cloned() {
            self.value_types.insert(target, identity);
        }
        Ok((source, target))
    }

    fn schedule_expressions(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        children: &[Node<'tree>],
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), GoLoweringError> {
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
    ) -> Result<(), GoLoweringError> {
        let Some(route) = builder.resolve_completion(scope, &CompletionRequest::new(kind, label))
        else {
            if matches!(kind, CompletionKind::Break | CompletionKind::Continue) {
                let detail = format!(
                    "{} completion has no matching represented target",
                    completion_label(kind)
                );
                let capability = if label.is_some() {
                    SemanticCapability::NonLocalControl
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
            return Err(GoLoweringError::Invalid(format!(
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
    ) -> Result<(), GoLoweringError> {
        let mut plan = CleanupRoutePlanner::new(route);
        while let Some(step) = plan.next_with_lookup(
            builder,
            &mut self.session,
            |id| {
                self.cleanups
                    .get(id.index())
                    .copied()
                    .filter(|region| region.id == id)
            },
            |region| region.call,
        )? {
            let call_next = if step.next.kind == ControlEdgeKind::Normal {
                step.next
            } else {
                let relay = self.point(builder, step.region.call, Vec::new())?;
                self.edge(builder, relay, step.next)?;
                EdgeTarget::normal(relay)
            };
            stack.push(Work::DeferredCall {
                node: step.region.call,
                entry: step.entry,
                next: call_next,
                scope: step.region.outer_scope,
            });
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
    ) -> Result<(), GoLoweringError> {
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
    ) -> Result<ProgramPointId, GoLoweringError> {
        let metadata = self.mapping(builder, node)?;
        self.session.add_point(builder, metadata, effects)
    }

    fn mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<PointMetadata, GoLoweringError> {
        self.session.add_node_mapping(builder, node)
    }

    fn value_mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<PointMetadata, GoLoweringError> {
        let anchor = source_anchor(node, 0).map_err(GoLoweringError::Invalid)?;
        self.session
            .add_mapping(builder, anchor, SourceMappingKind::Exact)
    }

    fn metadata(&self, point: ProgramPointId) -> Result<PointMetadata, GoLoweringError> {
        self.session.metadata(point)
    }

    fn value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        kind: SemanticValueKind,
    ) -> Result<ValueId, GoLoweringError> {
        self.session.add_value(builder, point, kind)
    }

    fn append_effect(
        &self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        effect: SemanticEffect,
    ) -> Result<(), GoLoweringError> {
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
    ) -> Result<(), GoLoweringError> {
        self.session
            .add_gap(builder, point, subject, capability, kind, detail)?;
        Ok(())
    }

    /// Preserve the exact source-local normal successors of an evaluation
    /// whose blocking, progress, or termination remains unknown. Consumers
    /// may use the retained topology for structured positive proofs, while the
    /// raw gap continues to keep global control relations incomplete.
    fn add_retained_control_topology_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        detail: &str,
    ) -> Result<(), GoLoweringError> {
        self.session.add_gap_with_impacts_and_discharge(
            builder,
            point,
            SemanticGapSubject::Point,
            SemanticCapability::NormalControlFlow,
            SemanticGapImpacts::NONE,
            SemanticGapKind::Unknown,
            SemanticGapDischarge::RetainedControlTopology,
            detail,
        )?;
        Ok(())
    }

    /// Go panics never resume evaluation after the panicking operation. A
    /// deferred call may recover the panic, but then the panicking function
    /// returns after its deferred sequence; its normal body does not rejoin.
    /// Preserve the stronger `NonRejoiningExceptionalExit` proof when this
    /// exact evaluation scope has no already-registered deferred call. With an
    /// active cleanup, preserve only `ExitOnlyProcedureCompletion`: cleanup
    /// user code may run and observe or transfer values, but it cannot resume
    /// this function's normal body. A later defer elsewhere in the procedure
    /// must not weaken the earlier point-local proof. Value-flow, ICFG, and
    /// generic control consumers keep the active-cleanup marker open; only
    /// narrow result-specific control proofs may localize it.
    fn add_non_rejoining_exceptional_exit_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        scope: ScopeFrameId,
        point: ProgramPointId,
        subject: SemanticGapSubject,
        kind: SemanticGapKind,
        detail: &str,
    ) -> Result<(), GoLoweringError> {
        let route = builder
            .resolve_completion(scope, &CompletionRequest::new(CompletionKind::Throw, None))
            .expect("a Go evaluation scope must resolve panic completion");
        let discharge = if route.cleanups().is_empty() {
            SemanticGapDischarge::NonRejoiningExceptionalExit
        } else {
            SemanticGapDischarge::ExitOnlyProcedureCompletion
        };
        self.session.add_gap_with_impacts_and_discharge(
            builder,
            point,
            subject,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapImpacts::NONE,
            kind,
            discharge,
            detail,
        )?;
        Ok(())
    }

    fn edge(
        &self,
        builder: &mut ProcedureCfgBuilder,
        source_point: ProgramPointId,
        target: EdgeTarget,
    ) -> Result<(), GoLoweringError> {
        self.session
            .add_edge(builder, source_point, target.point, target.kind)
    }
}

fn go_evaluation_unit_has_ordered_completion(mut node: Node<'_>) -> bool {
    while let Some(inner) = transparent_runtime_wrapper_child(node) {
        node = inner;
    }
    node.kind() == "call_expression"
        || (node.kind() == "unary_expression" && unary_operator_kind(node) == Some("<-"))
        || (node.kind() == "binary_expression" && go_boolean_operator_kind(node).is_some())
}

fn transparent_runtime_wrapper_child(node: Node<'_>) -> Option<Node<'_>> {
    if !matches!(
        node.kind(),
        "parenthesized_expression" | "literal_element" | "variadic_argument"
    ) {
        return None;
    }
    let mut children = named_children(node)
        .into_iter()
        .filter(|child| !is_comment_kind(child.kind()))
        .filter(|child| !is_go_type_syntax(child.kind()));
    let only = children.next()?;
    children.next().is_none().then_some(only)
}

fn runtime_expression_children(node: Node<'_>) -> Vec<Node<'_>> {
    match node.kind() {
        "return_statement" => {
            return named_children(node)
                .into_iter()
                .flat_map(expression_sequence)
                .filter(|child| !is_go_type_syntax(child.kind()))
                .collect();
        }
        "expression_statement" | "inc_statement" | "dec_statement" => {
            return named_children(node)
                .into_iter()
                .filter(|child| !is_go_type_syntax(child.kind()))
                .collect();
        }
        "binary_expression" => {
            let mut result = children_by_field_name(node, "left");
            result.extend(children_by_field_name(node, "right"));
            return result;
        }
        "unary_expression" => return children_by_field_name(node, "operand"),
        "selector_expression" => return children_by_field_name(node, "operand"),
        "index_expression" => {
            let mut result = children_by_field_name(node, "operand");
            result.extend(children_by_field_name(node, "index"));
            return result;
        }
        "slice_expression" => {
            let mut result = children_by_field_name(node, "operand");
            result.extend(children_by_field_name(node, "start"));
            result.extend(children_by_field_name(node, "end"));
            result.extend(children_by_field_name(node, "capacity"));
            return result;
        }
        "type_assertion_expression" => return children_by_field_name(node, "operand"),
        "type_conversion_expression" => return children_by_field_name(node, "operand"),
        "parenthesized_expression" => {
            return first_named_child(node).into_iter().collect();
        }
        "keyed_element" => {
            let mut result = children_by_field_name(node, "key");
            result.extend(children_by_field_name(node, "value"));
            return result;
        }
        "variadic_argument" => return named_children(node),
        _ => {}
    }

    named_children(node)
        .into_iter()
        .filter(|child| {
            !is_go_type_syntax(child.kind())
                && ![
                    "name",
                    "type",
                    "result",
                    "receiver",
                    "parameters",
                    "type_parameters",
                    "type_arguments",
                    "operator",
                    "label",
                ]
                .into_iter()
                .any(|field| field_matches(node, field, *child))
        })
        .collect()
}

fn communication_evaluations(node: Node<'_>) -> Vec<Node<'_>> {
    match node.kind() {
        "send_statement" => {
            let mut result = children_by_field_name(node, "channel");
            result.extend(children_by_field_name(node, "value"));
            result
        }
        "receive_statement" => node
            .child_by_field_name("right")
            .and_then(|receive| {
                (receive.kind() == "unary_expression" && unary_operator_kind(receive) == Some("<-"))
                    .then(|| receive.child_by_field_name("operand"))
                    .flatten()
            })
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

fn communication_operation_and_channel(
    node: Node<'_>,
) -> Option<(SynchronizationOperation, Node<'_>)> {
    match node.kind() {
        "send_statement" => node
            .child_by_field_name("channel")
            .map(|channel| (SynchronizationOperation::ChannelSend, channel)),
        "receive_statement" => node
            .child_by_field_name("right")
            .filter(|receive| {
                receive.kind() == "unary_expression" && unary_operator_kind(*receive) == Some("<-")
            })
            .and_then(|receive| receive.child_by_field_name("operand"))
            .map(|channel| (SynchronizationOperation::ChannelReceive, channel)),
        _ => None,
    }
}

fn select_eager_expressions(node: Node<'_>) -> Vec<Node<'_>> {
    let mut result = Vec::new();
    for case in named_children(node)
        .into_iter()
        .filter(|child| child.kind() == "communication_case")
    {
        if let Some(communication) = case.child_by_field_name("communication") {
            result.extend(communication_evaluations(communication));
        }
    }
    result
}

fn call_arguments(node: Node<'_>) -> Vec<Node<'_>> {
    all_call_arguments(node)
        .into_iter()
        .filter(|argument| !is_go_type_syntax(argument.kind()))
        .collect()
}

fn go_call_argument_value_node(argument: Node<'_>) -> Node<'_> {
    if argument.kind() == "variadic_argument" {
        first_runtime_named_child(argument).unwrap_or(argument)
    } else {
        argument
    }
}

fn all_call_arguments(node: Node<'_>) -> Vec<Node<'_>> {
    node.child_by_field_name("arguments")
        .map(named_children)
        .unwrap_or_default()
}

fn supported_defer_call<'tree>(
    node: Node<'tree>,
    procedure_targets: &HashMap<usize, GoProcedureTarget>,
) -> Option<Node<'tree>> {
    if node.kind() != "defer_statement" {
        return None;
    }
    let call = first_runtime_named_child(node)?;
    if call.kind() != "call_expression" {
        return None;
    }
    let function = call.child_by_field_name("function")?;
    if is_go_binding_reference_kind(function.kind()) || function.kind() == "selector_expression" {
        return Some(call);
    }
    let direct_function = transparent_parenthesized_expression(function);
    (direct_function.kind() == "func_literal"
        && procedure_targets.contains_key(&direct_function.id()))
    .then_some(call)
}

fn expression_sequence(node: Node<'_>) -> Vec<Node<'_>> {
    if node.kind() == "expression_list" {
        named_children(node)
    } else {
        vec![node]
    }
}

fn first_runtime_named_child(node: Node<'_>) -> Option<Node<'_>> {
    runtime_expression_children(node).into_iter().next()
}

fn transparent_parenthesized_expression(mut node: Node<'_>) -> Node<'_> {
    while node.kind() == "parenthesized_expression" {
        let Some(inner) = first_runtime_named_child(node) else {
            break;
        };
        node = inner;
    }
    node
}

fn parenthesized_call_receiver(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent()
        && parent.kind() == "parenthesized_expression"
    {
        node = parent;
    }
    let Some(selector) = node.parent().filter(|parent| {
        parent.kind() == "selector_expression" && field_matches(*parent, "operand", node)
    }) else {
        return false;
    };
    selector.parent().is_some_and(|call| {
        call.kind() == "call_expression" && field_matches(call, "function", selector)
    })
}

fn control_label_node(node: Node<'_>) -> Option<Node<'_>> {
    named_children(node)
        .into_iter()
        .find(|child| child.kind() == "label_name")
}

/// Whether this expression is written by the statement that contains it.
///
/// A write target is not a read. The lowered single-target store replaces its
/// evaluation list so the target node is never scheduled, but the shapes this
/// adapter does not lower -- a multi-target assignment, a range clause's
/// assignment form -- still schedule the place itself so its operands are
/// evaluated. Minting a `MemoryLoad` there would publish a read of the very
/// location the statement overwrites.
fn is_assignment_target(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "parenthesized_expression" | "expression_list" => current = parent,
            "assignment_statement" | "short_var_declaration" | "range_clause" => {
                return field_matches(parent, "left", current);
            }
            _ => return false,
        }
    }
    false
}

/// Whether this expression is the callable evaluated by a direct call.
///
/// Parentheses preserve that role. A selector in any other context may be a
/// method value rather than a field load when its imported receiver type is
/// unresolved, so the lowering must retain that ambiguity explicitly.
fn is_direct_call_function(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "parenthesized_expression" {
            current = parent;
            continue;
        }
        return parent.kind() == "call_expression" && field_matches(parent, "function", current);
    }
    false
}

/// The expression a chain of redundant parentheses wraps.
fn unparenthesized(node: Node<'_>) -> Node<'_> {
    let mut current = node;
    while current.kind() == "parenthesized_expression" {
        let Some(inner) = first_runtime_named_child(current) else {
            return current;
        };
        current = inner;
    }
    current
}

fn direct_child_kind(node: Node<'_>, kind: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor).any(|child| child.kind() == kind)
}

fn go_boolean_operator_kind(node: Node<'_>) -> Option<&'static str> {
    match node.child_by_field_name("operator")?.kind() {
        "&&" => Some("&&"),
        "||" => Some("||"),
        _ => None,
    }
}

/// Whether a Go `for` clause is known to enter its body before its first
/// condition check.
///
/// This is intentionally limited to the structured form used by the
/// language's ordinary counted loops. Unknown expressions, multiple bindings,
/// and all other loop shapes retain the shared zero-trip approximation.
fn go_for_clause_has_first_iteration(
    source: &str,
    initializer: Option<Node<'_>>,
    condition: Option<Node<'_>>,
    update: Option<Node<'_>>,
) -> bool {
    let (Some(initializer), Some(condition), Some(update)) = (initializer, condition, update)
    else {
        return false;
    };
    if initializer.kind() != "short_var_declaration"
        || update.kind() != "inc_statement"
        || condition.kind() != "binary_expression"
        || condition
            .child_by_field_name("operator")
            .is_none_or(|operator| operator.kind() != "<")
    {
        return false;
    }
    let Some(counter) = initializer
        .child_by_field_name("left")
        .and_then(single_expression_node)
        .filter(|node| node.kind() == "identifier")
    else {
        return false;
    };
    let Some(start) = initializer
        .child_by_field_name("right")
        .and_then(single_expression_node)
        .and_then(|node| integer_literal_value(source, node))
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
        .and_then(|node| integer_literal_value(source, node))
    else {
        return false;
    };
    let Some(incremented) = first_named_child(update).filter(|node| node.kind() == "identifier")
    else {
        return false;
    };
    node_text(source, counter) == node_text(source, left)
        && node_text(source, counter) == node_text(source, incremented)
        && start < limit
}

fn single_expression_node(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() == "expression_list" {
        let children = named_children(node);
        (children.len() == 1).then_some(children[0])
    } else {
        Some(node)
    }
}

fn integer_literal_value(source: &str, node: Node<'_>) -> Option<i64> {
    (node.kind() == "int_literal")
        .then(|| node_text(source, node))
        .flatten()
        .and_then(|text| text.parse().ok())
}

fn unary_operator_kind(node: Node<'_>) -> Option<&str> {
    node.child_by_field_name("operator")
        .map(|operator| operator.kind())
}

fn go_operation_can_panic(node: Node<'_>) -> bool {
    match node.kind() {
        "unary_expression" => unary_operator_kind(node) == Some("*"),
        "binary_expression" => node
            .child_by_field_name("operator")
            .is_some_and(|operator| matches!(operator.kind(), "/" | "%" | "<<" | ">>")),
        _ => false,
    }
}

/// Whether this grammar kind carries type syntax rather than a runtime
/// operand.
///
/// The set is enumerated rather than matched by a `type_` prefix or a `_type`
/// suffix. Three of the grammar's `type_`-prefixed kinds --
/// `type_assertion_expression`, `type_conversion_expression`, and
/// `type_instantiation_expression` -- are expressions whose value the program
/// computes and can pass on, and a prefix test silently deleted them wherever
/// this predicate filters operands. `dfb_sink(recovered.(int))` and
/// `sink(int(x))` then lowered as zero-argument calls, so no taint binding
/// could name their argument (#2662). Enumerating the kinds makes a future
/// grammar addition a deliberate decision instead of an accident of spelling.
fn is_go_type_syntax(kind: &str) -> bool {
    matches!(
        kind,
        // Type expressions.
        "type_identifier"
            | "qualified_type"
            | "generic_type"
            | "pointer_type"
            | "parenthesized_type"
            | "negated_type"
            | "array_type"
            | "implicit_length_array_type"
            | "slice_type"
            | "map_type"
            | "channel_type"
            | "struct_type"
            | "interface_type"
            | "function_type"
            | "type_elem"
            | "type_constraint"
            // Type and parameter declaration syntax, which declares rather
            // than evaluates.
            | "parameter_list"
            | "parameter_declaration"
            | "variadic_parameter_declaration"
            | "type_arguments"
            | "type_parameter_list"
            | "type_parameter_declaration"
            | "type_declaration"
            | "type_alias"
            | "type_spec"
            | "type_case"
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
    kind == "comment"
}

fn required_field<'tree>(node: Node<'tree>, field: &str) -> Result<Node<'tree>, GoLoweringError> {
    node.child_by_field_name(field)
        .ok_or_else(|| missing_field(node, field))
}

fn missing_field(node: Node<'_>, field: &str) -> GoLoweringError {
    GoLoweringError::Invalid(format!(
        "{} node at bytes {}..{} is missing structured field {field}",
        node.kind(),
        node.start_byte(),
        node.end_byte()
    ))
}

fn is_runtime_leaf(kind: &str) -> bool {
    is_go_constant_value_kind(kind)
        || matches!(
            kind,
            "identifier"
                | "field_identifier"
                | "package_identifier"
                | "escape_sequence"
                | "comment"
        )
}

fn is_go_literal_value_kind(kind: &str) -> bool {
    matches!(
        kind,
        "int_literal"
            | "float_literal"
            | "imaginary_literal"
            | "rune_literal"
            | "interpreted_string_literal"
            | "raw_string_literal"
    )
}

/// The magnitude of one tree-sitter-classified Go integer literal.
///
/// Go permits binary, explicit and legacy octal, decimal, and hexadecimal
/// spellings, with underscores between digits and immediately after a base
/// prefix. Decoding the already-classified AST token through `u128`
/// canonicalizes those spellings. Malformed separators and overflowing
/// magnitudes stay unknown, which is conservative and still covers every
/// machine-representable Go index.
fn go_integer_literal_value(source: &str, node: Node<'_>) -> Option<u128> {
    if node.kind() != "int_literal" {
        return None;
    }
    let text = node_text(source, node)?;
    let (digits, radix, separator_after_prefix) =
        if let Some(digits) = text.strip_prefix("0b").or_else(|| text.strip_prefix("0B")) {
            (digits, 2, true)
        } else if let Some(digits) = text.strip_prefix("0o").or_else(|| text.strip_prefix("0O")) {
            (digits, 8, true)
        } else if let Some(digits) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            (digits, 16, true)
        } else if text.len() > 1 && text.starts_with('0') {
            (text, 8, false)
        } else {
            (text, 10, false)
        };
    let bytes = digits.as_bytes();
    let valid_digit = |byte: u8| char::from(byte).is_digit(radix);
    let mut compact = String::with_capacity(digits.len());
    for (index, byte) in bytes.iter().copied().enumerate() {
        if byte == b'_' {
            let follows_prefix = separator_after_prefix && index == 0;
            let follows_digit = index > 0 && valid_digit(bytes[index - 1]);
            let precedes_digit = bytes.get(index + 1).is_some_and(|next| valid_digit(*next));
            if !(precedes_digit && (follows_prefix || follows_digit)) {
                return None;
            }
            continue;
        }
        if !valid_digit(byte) {
            return None;
        }
        compact.push(char::from(byte));
    }
    if compact.is_empty() {
        return None;
    }
    u128::from_str_radix(&compact, radix).ok()
}

fn is_go_predeclared_constant_kind(kind: &str) -> bool {
    matches!(kind, "true" | "false" | "nil" | "iota")
}

fn is_go_constant_value_kind(kind: &str) -> bool {
    is_go_literal_value_kind(kind) || is_go_predeclared_constant_kind(kind)
}

fn is_go_binding_reference_kind(kind: &str) -> bool {
    matches!(kind, "identifier" | "true" | "false" | "nil" | "iota")
}

/// Where each `(type declaration, field)` pair of this file is declared.
///
/// A field's declaration is the identity a memory location names, so two
/// occurrences of `holder.Value` in one procedure -- and the store and the load
/// that must meet on it -- agree only when both anchor on the same declaration.
/// Declaration identity keeps a local type shadow separate from a package type
/// with the same spelling. An embedded field declares no `field_identifier`
/// and is skipped.
fn go_struct_field_anchors(
    prepared: &PreparedSyntaxTree,
) -> HashMap<(usize, Box<str>), SourceAnchor> {
    let mut anchors = HashMap::default();
    let mut stack = vec![prepared.tree().root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "type_spec"
            && let Some(declared) = node.child_by_field_name("type")
            && declared.kind() == "struct_type"
        {
            // Only this struct's own field list, one level: a field whose type
            // is itself an anonymous struct declares names that belong to that
            // inner type, not to `owner`.
            let mut fields = Vec::new();
            for list in named_children(declared) {
                if list.kind() != "field_declaration_list" {
                    continue;
                }
                for declaration in named_children(list) {
                    if declaration.kind() != "field_declaration" {
                        continue;
                    }
                    fields.extend(
                        named_children(declaration)
                            .into_iter()
                            .filter(|child| child.kind() == "field_identifier"),
                    );
                }
            }
            for field in fields {
                let Some(name) = nonempty_node_text(prepared.source(), field) else {
                    continue;
                };
                let Ok(anchor) = source_anchor(field, 0) else {
                    continue;
                };
                anchors.insert((node.id(), name.into()), anchor);
            }
        }
        stack.extend(named_children(node));
    }
    anchors
}

fn go_type_identity(node: Node<'_>, source: &str) -> Option<GoTypeIdentity> {
    let mut current = node;
    let mut pointer_depth = 0usize;
    loop {
        match current.kind() {
            "pointer_type" => {
                pointer_depth = pointer_depth.checked_add(1)?;
                current = first_named_child(current)?;
            }
            "parenthesized_type" => current = first_named_child(current)?,
            // Substituting a generic type or interface constraint can change
            // method sets and identity; leave those paths explicitly open.
            "generic_type"
            | "interface_type"
            | "type_parameter_list"
            | "type_parameter_declaration"
            | "type_constraint" => return None,
            "type_identifier" | "qualified_type" => {
                let name = nonempty_node_text(source, current)?.trim();
                return (!name.is_empty()).then(|| GoTypeIdentity {
                    pointer_depth,
                    name: name.into(),
                    declaration: None,
                });
            }
            _ => return None,
        }
    }
}

fn is_go_callable_kind(kind: &str) -> bool {
    matches!(
        kind,
        "function_declaration" | "method_declaration" | "func_literal"
    )
}

fn go_receiver_uses_generic_type(callable: Node<'_>) -> bool {
    let Some(receiver) = callable.child_by_field_name("receiver") else {
        return false;
    };
    let mut stack = vec![receiver];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "generic_type" | "type_arguments") {
            return true;
        }
        let children = named_children(node);
        stack.extend(children);
    }
    false
}

fn go_local_scope(declaration: Node<'_>) -> Option<(usize, usize)> {
    let mut child = declaration;
    let mut parent = declaration.parent();
    while let Some(node) = parent {
        let owns_header_declaration = match node.kind() {
            "for_statement" => node.child_by_field_name("body").is_none_or(|body| {
                !(body.start_byte() <= child.start_byte() && child.end_byte() <= body.end_byte())
            }),
            "if_statement" | "expression_switch_statement" | "type_switch_statement" => node
                .child_by_field_name("initializer")
                .is_some_and(|initializer| {
                    initializer.start_byte() <= declaration.start_byte()
                        && declaration.end_byte() <= initializer.end_byte()
                }),
            _ => false,
        };
        let owns_case_clause_scope =
            node.kind() == "statement_list" && node.parent().is_some_and(is_clause);
        if owns_header_declaration || owns_case_clause_scope || node.kind() == "block" {
            return Some((node.start_byte(), node.end_byte()));
        }
        child = node;
        parent = node.parent();
    }
    None
}

fn go_var_specs(node: Node<'_>) -> Vec<Node<'_>> {
    let mut specs = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "var_spec" {
            specs.push(current);
            continue;
        }
        let children = named_children(current);
        for child in children.into_iter().rev() {
            stack.push(child);
        }
    }
    specs.sort_by_key(Node::start_byte);
    specs
}

fn names_len_matches_values(left: Node<'_>, right: Node<'_>) -> bool {
    expression_sequence(left).len() == expression_sequence(right).len()
}

/// The package-level name this declaration node binds, if it binds one.
fn go_package_binding_name<'source>(node: Node<'_>, source: &'source str) -> Option<&'source str> {
    match node.kind() {
        "identifier" | "true" | "false" | "nil" | "iota" => node_text(source, node),
        "import_spec" => super::declarations::go_import_spec_binding_name(node, source),
        "function_declaration" | "type_spec" | "type_alias" => node
            .child_by_field_name("name")
            .and_then(|name| node_text(source, name)),
        _ => None,
    }
}

fn go_import_bindings(root: Node<'_>, source: &str) -> HashMap<Box<str>, Box<str>> {
    collect_go_import_infos(root, source)
        .into_iter()
        .filter_map(|info| {
            let path = info.path.as_ref()?.render_segments("/");
            let local = info.alias.or(info.identifier)?;
            (!path.is_empty() && !matches!(local.as_str(), "_" | "."))
                .then(|| (local.into_boxed_str(), path.into_boxed_str()))
        })
        .collect()
}

fn go_qualified_type_parts<'source>(
    mut node: Node<'_>,
    source: &'source str,
) -> Option<(&'source str, &'source str)> {
    loop {
        match node.kind() {
            "pointer_type" | "parenthesized_type" => node = first_named_child(node)?,
            "qualified_type" => {
                let package = node.child_by_field_name("package")?;
                let name = node.child_by_field_name("name")?;
                return Some((node_text(source, package)?, node_text(source, name)?));
            }
            _ => return None,
        }
    }
}

const fn completion_label(kind: CompletionKind) -> &'static str {
    match kind {
        CompletionKind::Normal => "normal",
        CompletionKind::Return => "return",
        CompletionKind::Throw => "throw",
        CompletionKind::Break => "break",
        CompletionKind::Continue => "continue",
        _ => "unsupported completion",
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

    fn prepared_fixture(source: &str) -> PreparedSyntaxTree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("Go grammar is valid");
        let tree = parser.parse(source, None).expect("fixture parses");
        PreparedSyntaxTree::new(
            PreparedSyntaxSource::Exact(Arc::<str>::from(source)),
            tree,
            compute_line_starts(source),
            LanguageDialect::Standard(Language::Go),
            PreparedSourceOrigin::Disk,
            None,
        )
    }

    fn lower_fixture_with_budget(
        source: &str,
        budget: &SemanticBudget,
    ) -> SemanticOutcome<Vec<ProcedureSemanticsParts>> {
        let prepared = prepared_fixture(source);
        let file = ProjectFile::new(std::env::temp_dir(), "fixture.go");
        GoSemanticLowerer
            .lower(&file, &prepared, budget, &CancellationToken::default())
            .expect("Go lowering succeeds")
    }

    fn lower_fixture(source: &str) -> Vec<ProcedureSemanticsParts> {
        let SemanticOutcome::Complete { value, .. } =
            lower_fixture_with_budget(source, &SemanticBudget::default())
        else {
            panic!("Go fixture lowering must complete");
        };
        value
    }

    fn value_source_span(procedure: &ProcedureSemanticsParts, value: ValueId) -> SourceSpan {
        procedure.source_mappings[procedure.values[value.index()].source.index()]
            .locator
            .anchor()
            .span()
    }

    fn mapping_source_span(
        procedure: &ProcedureSemanticsParts,
        source: SourceMappingId,
    ) -> SourceSpan {
        procedure.source_mappings[source.index()]
            .locator
            .anchor()
            .span()
    }

    fn source_text(source: &str, span: SourceSpan) -> &str {
        source
            .get(span.start_byte() as usize..span.end_byte() as usize)
            .expect("semantic mapping belongs to the fixture")
    }

    fn capture_source_value(
        procedure: &ProcedureSemanticsParts,
        capture: &CaptureBinding,
    ) -> ValueId {
        match capture.captured {
            CaptureSource::Value(value) => value,
            CaptureSource::Location(location) => {
                match procedure.memory_locations[location.index()].kind {
                    MemoryLocationKind::LexicalCell { binding } => binding,
                    ref kind => panic!("parent capture source is not a lexical cell: {kind:#?}"),
                }
            }
        }
    }

    fn named_procedure<'a>(
        procedures: &'a [ProcedureSemanticsParts],
        name: &str,
    ) -> &'a ProcedureSemanticsParts {
        procedures
            .iter()
            .find(|procedure| {
                procedure.lexical_parent.is_none()
                    && procedure
                        .locator
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some(name)
            })
            .unwrap_or_else(|| panic!("missing procedure {name}"))
    }

    #[test]
    fn typed_var_without_initializer_establishes_each_binding_with_its_own_zero_value() {
        const SOURCE: &str = r#"package main
func run() error {
    var first, second error
    if true {
        var first error
        _ = first
    }
    _ = second
    return first
}
"#;
        let procedures = lower_fixture(SOURCE);
        let procedure = named_procedure(&procedures, "run");
        let locals = procedure
            .values
            .iter()
            .filter(|value| value.kind == SemanticValueKind::Local)
            .map(|value| value.id)
            .collect::<Vec<_>>();
        assert_eq!(locals.len(), 3, "three source bindings: {procedure:#?}");

        let assignments = procedure
            .points
            .iter()
            .flat_map(|point| &point.events)
            .filter_map(|event| match event.effect {
                SemanticEffect::Assignment { target, value } if locals.contains(&target) => {
                    Some((target, value))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(assignments.len(), 3, "one zero establishment per binding");
        let mut zero_values = assignments
            .iter()
            .map(|(_, value)| *value)
            .collect::<Vec<_>>();
        zero_values.sort_unstable();
        zero_values.dedup();
        assert_eq!(zero_values.len(), 3, "zero identities are per binding");
        for (target, zero) in assignments {
            assert!(matches!(
                &procedure.values[zero.index()].kind,
                SemanticValueKind::LanguageDefined(kind) if kind.as_ref() == "go.zero_value"
            ));
            assert!(procedure.points.iter().any(|point| {
                point.events.iter().any(|event| {
                    matches!(
                        event.effect,
                        SemanticEffect::ValueFlow {
                            kind: ValueFlowKind::Local,
                            source,
                            target: flowed_target,
                        } if source == zero && flowed_target == target
                    )
                })
            }));
            assert_eq!(
                source_text(SOURCE, value_source_span(procedure, target)),
                source_text(SOURCE, value_source_span(procedure, zero)),
                "the language-defined value is anchored to its declaration name"
            );
        }
    }

    #[test]
    fn mixed_var_group_establishes_no_init_specs_and_ignores_blank_only_specs() {
        const SOURCE: &str = r#"package main
func run() error {
    var (
        reportedErr error
        initialized = reportedErr
        _ error
    )
    _ = initialized
    return reportedErr
}
func blankOnly() {
    var _ error
}
"#;
        let procedures = lower_fixture(SOURCE);
        let procedure = named_procedure(&procedures, "run");
        let blank_only = named_procedure(&procedures, "blankOnly");
        let local_named = |name: &str| {
            procedure
                .values
                .iter()
                .find(|value| {
                    value.kind == SemanticValueKind::Local
                        && source_text(SOURCE, value_source_span(procedure, value.id)) == name
                })
                .map(|value| value.id)
                .unwrap_or_else(|| panic!("missing local {name}: {procedure:#?}"))
        };
        let reported = local_named("reportedErr");
        let initialized = local_named("initialized");
        let assignments = procedure
            .points
            .iter()
            .flat_map(|point| &point.events)
            .filter_map(|event| match event.effect {
                SemanticEffect::Assignment { target, value }
                    if target == reported || target == initialized =>
                {
                    Some((target, value))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            assignments
                .iter()
                .filter(|(target, _)| *target == reported)
                .count(),
            1,
            "the no-init spec is established inside a mixed group"
        );
        let reported_zero = assignments
            .iter()
            .find_map(|(target, value)| (*target == reported).then_some(*value))
            .expect("reportedErr zero establishment");
        assert!(matches!(
            &procedure.values[reported_zero.index()].kind,
            SemanticValueKind::LanguageDefined(kind) if kind.as_ref() == "go.zero_value"
        ));
        assert!(assignments.iter().any(|(target, value)| {
            *target == initialized
                && !matches!(
                    &procedure.values[value.index()].kind,
                    SemanticValueKind::LanguageDefined(kind) if kind.as_ref() == "go.zero_value"
                )
        }));
        let zero_point = procedure
            .points
            .iter()
            .find(|point| {
                point.events.iter().any(|event| {
                    matches!(
                        event.effect,
                        SemanticEffect::Assignment { target, value }
                            if target == reported && value == reported_zero
                    )
                })
            })
            .map(|point| point.id)
            .expect("zero establishment point");
        let later_read_point = procedure
            .points
            .iter()
            .find(|point| {
                point.events.iter().any(|event| {
                    matches!(
                        event.effect,
                        SemanticEffect::ValueFlow { source, .. } if source == reported
                    )
                })
            })
            .map(|point| point.id)
            .expect("later initializer reads the earlier binding");
        let mut frontier = vec![zero_point];
        let mut reached = std::collections::HashSet::new();
        while let Some(point) = frontier.pop() {
            if !reached.insert(point) {
                continue;
            }
            frontier.extend(
                procedure
                    .control_edges
                    .iter()
                    .filter(|edge| edge.source_point == point)
                    .map(|edge| edge.target_point),
            );
        }
        assert!(
            reached.contains(&later_read_point),
            "the earlier spec's zero establishment precedes the later spec initializer"
        );
        assert!(
            blank_only.gaps.iter().all(|gap| !matches!(
                gap.capability,
                SemanticCapability::Values | SemanticCapability::Assignments
            )),
            "a standalone blank-only declaration adds no Values/Assignments gap: {:#?}",
            blank_only.gaps
        );
    }

    #[test]
    fn unary_not_condition_guards_the_inner_call_result_with_inverted_polarity() {
        const SOURCE: &str = r#"package main
func predicate() bool { return true }
func negated() bool {
    if !predicate() { return true }
    return false
}
"#;
        let procedures = lower_fixture(SOURCE);
        let procedure = named_procedure(&procedures, "negated");
        let [call] = procedure.call_sites.as_slice() else {
            panic!("expected one predicate call: {procedure:#?}");
        };
        let [guard] = procedure.guard_facts.as_slice() else {
            panic!("expected one predicate guard: {procedure:#?}");
        };
        let result = call.result.expect("predicate call has one result");

        assert_eq!(
            guard.subject,
            Some(result),
            "the guard must test the call result rather than a synthetic unary value"
        );
        assert_eq!(
            source_text(SOURCE, value_source_span(procedure, result)),
            "predicate()"
        );
        assert_eq!(
            source_text(
                SOURCE,
                mapping_source_span(procedure, procedure.points[guard.point.index()].source),
            ),
            "predicate()",
            "the decision point belongs to the grammar-native operand"
        );
        assert!(matches!(guard.predicate, GuardPredicate::Opaque { .. }));
        assert_eq!(
            guard.true_arm.map(|arm| arm.kind),
            Some(ControlEdgeKind::ConditionalFalse)
        );
        assert_eq!(
            guard.false_arm.map(|arm| arm.kind),
            Some(ControlEdgeKind::ConditionalTrue)
        );
    }

    #[test]
    fn double_unary_not_restores_the_inner_call_guard_polarity() {
        const SOURCE: &str = r#"package main
func predicate() bool { return true }
func doubleNegated() bool {
    if !!predicate() { return true }
    return false
}
"#;
        let procedures = lower_fixture(SOURCE);
        let procedure = named_procedure(&procedures, "doubleNegated");
        let [call] = procedure.call_sites.as_slice() else {
            panic!("expected one predicate call: {procedure:#?}");
        };
        let [guard] = procedure.guard_facts.as_slice() else {
            panic!("expected one predicate guard: {procedure:#?}");
        };

        assert_eq!(
            guard.subject, call.result,
            "both unary wrappers must peel back to the call result"
        );
        assert_eq!(
            guard.true_arm.map(|arm| arm.kind),
            Some(ControlEdgeKind::ConditionalTrue)
        );
        assert_eq!(
            guard.false_arm.map(|arm| arm.kind),
            Some(ControlEdgeKind::ConditionalFalse)
        );
    }

    #[test]
    fn unary_not_normalizes_comparisons_with_inverted_predicate_polarity() {
        const SOURCE: &str = r#"package main
func negatedNil(err error) bool {
    if !(err != nil) { return true }
    return false
}
func negatedConstant(x int) bool {
    if !((x == 7)) { return true }
    return false
}
"#;
        let procedures = lower_fixture(SOURCE);

        let nil_procedure = named_procedure(&procedures, "negatedNil");
        let [nil_guard] = nil_procedure.guard_facts.as_slice() else {
            panic!("expected one normalized nil guard: {nil_procedure:#?}");
        };
        let nil_subject = nil_guard
            .subject
            .expect("a nil comparison retains its nonconstant subject");
        assert_eq!(
            source_text(SOURCE, value_source_span(nil_procedure, nil_subject)),
            "err"
        );
        assert!(matches!(
            nil_guard.predicate,
            GuardPredicate::NullComparison { null_on_true: true }
        ));
        assert_eq!(
            nil_guard.true_arm.map(|arm| arm.kind),
            Some(ControlEdgeKind::ConditionalTrue)
        );
        assert_eq!(
            nil_guard.false_arm.map(|arm| arm.kind),
            Some(ControlEdgeKind::ConditionalFalse)
        );

        let constant_procedure = named_procedure(&procedures, "negatedConstant");
        let [constant_guard] = constant_procedure.guard_facts.as_slice() else {
            panic!("expected one normalized constant guard: {constant_procedure:#?}");
        };
        let constant_subject = constant_guard
            .subject
            .expect("a constant comparison retains its nonconstant subject");
        assert_eq!(
            source_text(
                SOURCE,
                value_source_span(constant_procedure, constant_subject),
            ),
            "x"
        );
        let GuardPredicate::ConstantEquality { negated, constant } = &constant_guard.predicate
        else {
            panic!("expected constant equality predicate: {constant_guard:#?}");
        };
        assert!(*negated, "negating equality must make inequality true");
        assert_eq!(
            source_text(SOURCE, value_source_span(constant_procedure, *constant),),
            "7"
        );
        assert_eq!(
            constant_guard.true_arm.map(|arm| arm.kind),
            Some(ControlEdgeKind::ConditionalTrue)
        );
        assert_eq!(
            constant_guard.false_arm.map(|arm| arm.kind),
            Some(ControlEdgeKind::ConditionalFalse)
        );
    }

    #[test]
    fn unary_not_composes_with_parentheses_and_short_circuit_conditions() {
        const SOURCE: &str = r#"package main
func left() bool { return true }
func right() bool { return true }
func negatedAnd() bool {
    if !(left() && right()) { return true }
    return false
}
func negatedOr() bool {
    if !(left() || right()) { return true }
    return false
}
"#;
        let procedures = lower_fixture(SOURCE);

        for (name, rightward_arm) in [("negatedAnd", true), ("negatedOr", false)] {
            let procedure = named_procedure(&procedures, name);
            assert_eq!(procedure.call_sites.len(), 2, "{procedure:#?}");
            assert_eq!(procedure.guard_facts.len(), 2, "{procedure:#?}");

            let call_result = |text: &str| {
                procedure
                    .call_sites
                    .iter()
                    .find_map(|call| {
                        let result = call.result?;
                        (source_text(SOURCE, value_source_span(procedure, result)) == text)
                            .then_some(result)
                    })
                    .unwrap_or_else(|| panic!("missing {text} result: {procedure:#?}"))
            };
            let left_result = call_result("left()");
            let right_result = call_result("right()");
            let guard_for = |result| {
                procedure
                    .guard_facts
                    .iter()
                    .find(|guard| guard.subject == Some(result))
                    .unwrap_or_else(|| panic!("missing call-result guard: {procedure:#?}"))
            };
            let left_guard = guard_for(left_result);
            let right_guard = guard_for(right_result);

            let right_entry = if rightward_arm {
                left_guard.true_arm
            } else {
                left_guard.false_arm
            }
            .expect("the short-circuit operator reaches its right operand");
            assert_eq!(
                source_text(
                    SOURCE,
                    mapping_source_span(
                        procedure,
                        procedure.points[right_entry.target_point.index()].source,
                    ),
                ),
                "right()"
            );
            assert_eq!(
                right_guard.true_arm.map(|arm| arm.kind),
                Some(ControlEdgeKind::ConditionalFalse)
            );
            assert_eq!(
                right_guard.false_arm.map(|arm| arm.kind),
                Some(ControlEdgeKind::ConditionalTrue)
            );
        }
    }

    #[test]
    fn unary_not_distinguishes_builtin_and_rebound_boolean_literals() {
        const SOURCE: &str = r#"package main
func builtin() bool {
    if !true { return true }
    return false
}
func rebound() bool {
    true := false
    if !true { return true }
    return false
}
"#;
        let procedures = lower_fixture(SOURCE);
        let builtin = named_procedure(&procedures, "builtin");
        let [builtin_guard] = builtin.guard_facts.as_slice() else {
            panic!("expected one builtin literal guard: {builtin:#?}");
        };
        assert_eq!(builtin_guard.subject, None);
        assert_eq!(
            source_text(SOURCE, mapping_source_span(builtin, builtin_guard.source)),
            "!true"
        );
        assert!(matches!(
            builtin_guard.predicate,
            GuardPredicate::ConstantBoolean { value: false }
        ));
        assert_eq!(builtin_guard.true_arm, None);
        assert_eq!(
            builtin_guard.false_arm.map(|arm| arm.kind),
            Some(ControlEdgeKind::ConditionalFalse)
        );

        let rebound = named_procedure(&procedures, "rebound");
        let [rebound_guard] = rebound.guard_facts.as_slice() else {
            panic!("expected one rebound literal guard: {rebound:#?}");
        };
        let subject = rebound_guard
            .subject
            .expect("a rebound literal is an ordinary runtime value");
        assert_eq!(
            source_text(SOURCE, value_source_span(rebound, subject)),
            "true"
        );
        assert_ne!(
            rebound.values[subject.index()].kind,
            SemanticValueKind::Constant
        );
        assert!(matches!(
            rebound_guard.predicate,
            GuardPredicate::Opaque { .. }
        ));
        assert_eq!(
            rebound_guard.true_arm.map(|arm| arm.kind),
            Some(ControlEdgeKind::ConditionalFalse)
        );
        assert_eq!(
            rebound_guard.false_arm.map(|arm| arm.kind),
            Some(ControlEdgeKind::ConditionalTrue)
        );
    }

    #[test]
    fn conditional_defer_specialization_exhausts_the_semantic_budget_typed() {
        const SOURCE: &str = r#"package main
func cleanup() {}
func bounded(a, b, c, d bool) {
    if a { defer cleanup() }
    if b { defer cleanup() }
    if c { defer cleanup() }
    if d { defer cleanup() }
    finish()
}
"#;
        let complete = lower_fixture_with_budget(SOURCE, &SemanticBudget::default());
        let SemanticOutcome::Complete { work, .. } = complete else {
            panic!("default semantic budget must lower the bounded fixture: {complete:#?}");
        };
        assert!(work.nested_entries > 1);

        let mut limits = SemanticBudget::default().limits();
        limits.nested_entries = work.nested_entries - 1;
        let budget = SemanticBudget::new(limits).expect("all semantic limits remain positive");
        let constrained = lower_fixture_with_budget(SOURCE, &budget);
        let SemanticOutcome::ExceededBudget { exceeded, .. } = constrained else {
            panic!("continuation specialization must fail typed: {constrained:#?}");
        };
        assert_eq!(exceeded.dimension(), SemanticBudgetDimension::NestedEntries);
    }

    #[test]
    fn direct_immutable_capture_prepass_exhausts_nested_entry_budget_typed() {
        const SOURCE: &str = r#"package main
func outer() {
    value := acquire()
    closure := func() { consume(value) }
    closure()
}
"#;
        let prepared = prepared_fixture(SOURCE);
        let file = ProjectFile::new(std::env::temp_dir(), "fixture.go");
        let unconstrained = enumerate_procedures(
            &file,
            &prepared,
            &SemanticBudget::default(),
            &CancellationToken::default(),
        )
        .expect("unconstrained Go inventory succeeds");
        let ProcedureInventoryOutcome::Complete {
            value:
                GoProcedureInventory {
                    mut specs,
                    direct_struct_fields,
                    named_type_definitions,
                    method_inventory,
                    ..
                },
            ..
        } = unconstrained
        else {
            panic!("unconstrained Go inventory must complete");
        };

        let mut limits = SemanticBudget::default().limits();
        limits.nested_entries = 1;
        let budget = SemanticBudget::new(limits).expect("all semantic limits remain positive");
        let mut inventory = ProcedureInventoryBuilder::new(
            &file,
            prepared.dialect(),
            prepared.tree().root_node(),
            "go-source",
            &budget,
        )
        .expect("fresh Go inventory is valid");
        let stop = populate_capture_specs(
            &mut specs,
            prepared.source(),
            &direct_struct_fields,
            &named_type_definitions,
            &method_inventory,
            &mut inventory,
            &CancellationToken::default(),
        );
        let Err(GoInventoryPrepassStop::Budget(stop)) = stop else {
            panic!("capture prepass must stop with a typed budget error");
        };
        assert_eq!(
            stop.exceeded.dimension(),
            SemanticBudgetDimension::NestedEntries
        );
    }

    #[test]
    fn immutable_direct_func_literal_capture_has_exact_value_identity() {
        let procedures = lower_fixture(
            r#"package main
func outer() {
    value := acquire()
    defer func() { consume(value) }()
}
"#,
        );
        let parent = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent.is_none())
            .expect("outer procedure");
        let child = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent == Some(parent.id))
            .expect("function-literal procedure");

        let [capture] = parent.captures.as_slice() else {
            panic!("expected one exact capture, got {:#?}", parent.captures);
        };
        assert_eq!(capture.target, child.id);
        assert_eq!(capture.mode, CaptureMode::Value);
        assert!(matches!(capture.captured, CaptureSource::Value(_)));
        assert!(parent.gaps.iter().all(|gap| {
            gap.capability != SemanticCapability::Captures
                || !matches!(gap.subject, SemanticGapSubject::Value(_))
        }));
        assert!(child.memory_locations.iter().any(|location| {
            location.id == capture.destination
                && matches!(
                    location.kind,
                    MemoryLocationKind::Capture { lexical_parent, .. } if lexical_parent == parent.id
                )
        }));
        assert!(
            child
                .points
                .iter()
                .flat_map(|point| &point.events)
                .any(|event| {
                    matches!(
                        event.effect,
                        SemanticEffect::MemoryLoad {
                            kind: MemoryAccessKind::Capture,
                            location,
                            ..
                        } if location == capture.destination
                    )
                })
        );
    }

    #[test]
    fn direct_func_literal_calls_name_their_exact_local_targets() {
        const SOURCE: &str = r#"package main
func invoke(callback func()) {
    func() {}()
    (func() {})()
    alias := func() {}
    alias()
    callback()
}
"#;
        let procedures = lower_fixture(SOURCE);
        let parent = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent.is_none())
            .expect("invoke procedure");

        let callee_span = |call: &SemanticCallSite| value_source_span(parent, call.callee);
        let callee_text = |call: &SemanticCallSite| source_text(SOURCE, callee_span(call));
        let call = |expected: &str| {
            parent
                .call_sites
                .iter()
                .find(|call| callee_text(call) == expected)
                .unwrap_or_else(|| panic!("missing `{expected}` call: {:#?}", parent.call_sites))
        };

        for expected in ["func() {}", "(func() {})"] {
            let call = call(expected);
            assert_eq!(call.execution_timing, ExecutionTiming::SameEvaluation);
            let CallableTargetResolution::Proven(CallableTarget::Local(target)) =
                call.declared_targets
            else {
                panic!("direct function literal must have a proven local target: {call:#?}");
            };
            let target = procedures
                .iter()
                .find(|procedure| procedure.id == target)
                .expect("proven local target names one published procedure");
            let target_span = target.locator.anchor().span();
            let call_span = callee_span(call);
            assert!(
                call_span.start_byte() <= target_span.start_byte()
                    && target_span.end_byte() <= call_span.end_byte(),
                "the target must be the literal invoked at this exact call site"
            );
        }

        for expected in ["alias", "callback"] {
            let call = call(expected);
            assert_eq!(
                call.declared_targets,
                CallableTargetResolution::Unknown,
                "identifier calls do not prove what callable value reaches them"
            );
        }
    }

    #[test]
    fn go_spawn_call_has_different_task_timing_and_parent_normal_successor() {
        let procedures = lower_fixture(
            r#"package main
func spawn() {
    go func() {}()
    observe()
}
func observe() {}
"#,
        );
        let parent = procedures
            .iter()
            .find(|procedure| {
                procedure.lexical_parent.is_none()
                    && procedure
                        .locator
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some("spawn")
            })
            .expect("spawn procedure");
        let spawn_gaps = parent
            .gaps
            .iter()
            .filter(|gap| gap.capability == SemanticCapability::ConcurrentSpawn)
            .collect::<Vec<_>>();
        let [spawn_gap] = spawn_gaps.as_slice() else {
            panic!("one concurrent-spawn gap: {spawn_gaps:#?}");
        };
        assert_eq!(spawn_gap.subject, SemanticGapSubject::Point);
        assert_eq!(spawn_gap.kind, SemanticGapKind::Unsupported);
        assert_eq!(
            spawn_gap.discharge,
            SemanticGapDischarge::RetainedControlTopology
        );
        assert_eq!(
            parent
                .control_edges
                .iter()
                .filter(|edge| edge.source_point == spawn_gap.point)
                .map(|edge| edge.kind)
                .collect::<Vec<_>>(),
            vec![ControlEdgeKind::Normal],
            "the parent continues through its one represented normal successor"
        );
        let spawned = parent
            .call_sites
            .iter()
            .find(|call| call.point == spawn_gap.point)
            .expect("the exact go statement emits its outer call");
        assert_eq!(spawned.invocation_mode, CallInvocationMode::Detached);
        assert_eq!(spawned.execution_timing, ExecutionTiming::DifferentTask);
        assert!(spawned.normal_continuation.target().is_some());
        assert_eq!(
            spawned.exceptional_continuation,
            ControlContinuation::Absent
        );
        assert!(spawned.normal_result_values().next().is_none());
        assert!(spawned.thrown.is_none());
        assert!(parent.gaps.iter().all(|gap| {
            gap.point != spawn_gap.point || gap.capability != SemanticCapability::Calls
        }));
    }

    #[test]
    fn malformed_go_operand_retains_control_and_explicit_call_gap() {
        let procedures = lower_fixture(
            r#"package main
func incomplete(callback func()) {
	go callback
}
"#,
        );
        let procedure = procedures
            .iter()
            .find(|procedure| {
                procedure.lexical_parent.is_none()
                    && procedure
                        .locator
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some("incomplete")
            })
            .expect("incomplete procedure");
        assert!(
            procedure.call_sites.is_empty(),
            "a non-call operand must not manufacture a spawned call: {:#?}",
            procedure.call_sites
        );
        let spawn_gap = procedure
            .gaps
            .iter()
            .find(|gap| gap.capability == SemanticCapability::ConcurrentSpawn)
            .expect("unsupported spawn remains explicit");
        assert!(procedure.gaps.iter().any(|gap| {
            gap.point == spawn_gap.point && gap.capability == SemanticCapability::Calls
        }));
        assert!(procedure.control_edges.iter().any(|edge| {
            edge.source_point == spawn_gap.point && edge.kind == ControlEdgeKind::Normal
        }));
    }

    #[test]
    fn direct_func_literal_defers_are_bounded_but_callable_values_remain_open() {
        const SOURCE: &str = r#"package main
func deferCalls(callback func(), factory func() func()) {
    defer func() {}()
    defer (func() {})()
    alias := func() {}
    defer alias()
    defer callback()
    defer factory()()
}
"#;
        let procedures = lower_fixture(SOURCE);
        let parent = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent.is_none())
            .expect("deferCalls procedure");
        let callee_span = |call: &SemanticCallSite| value_source_span(parent, call.callee);
        let callee_text = |call: &SemanticCallSite| source_text(SOURCE, callee_span(call));

        for expected in ["func() {}", "(func() {})"] {
            let call = parent
                .call_sites
                .iter()
                .find(|call| callee_text(call) == expected)
                .unwrap_or_else(|| {
                    panic!(
                        "missing deferred `{expected}` call: {:#?}",
                        parent.call_sites
                    )
                });
            assert_eq!(call.execution_timing, ExecutionTiming::SameInvocation);
            let CallableTargetResolution::Proven(CallableTarget::Local(target)) =
                call.declared_targets
            else {
                panic!("direct deferred literal must have a proven local target: {call:#?}");
            };
            let target = procedures
                .iter()
                .find(|procedure| procedure.id == target)
                .expect("deferred literal target names one published procedure");
            let target_span = target.locator.anchor().span();
            let call_span = callee_span(call);
            assert!(
                call_span.start_byte() <= target_span.start_byte()
                    && target_span.end_byte() <= call_span.end_byte(),
                "the deferred target must be the exact literal registered here"
            );
        }

        for unsupported in ["alias", "callback", "factory()"] {
            assert!(
                parent
                    .call_sites
                    .iter()
                    .all(|call| callee_text(call) != unsupported),
                "a callable value or producing expression must not fabricate a deferred call target: {:#?}",
                parent.call_sites
            );
        }
        assert_eq!(
            parent
                .gaps
                .iter()
                .filter(|gap| {
                    gap.capability == SemanticCapability::Calls
                        && gap.detail.as_ref()
                            == "the deferred outer call is intentionally not emitted as an immediate invocation"
                })
                .count(),
            3,
            "each alias, parameter, or callable-producing defer remains explicit: {:#?}",
            parent.gaps
        );
    }

    #[test]
    fn active_defer_marks_later_panics_as_exit_only_procedure_completion() {
        const SOURCE: &str = r#"package main
type item struct { value int }
func cleanup() {}
func run(input *item) {
    defer cleanup()
    _ = input.value
}
"#;
        let procedures = lower_fixture(SOURCE);
        let procedure = named_procedure(&procedures, "run");
        let gaps = procedure
            .gaps
            .iter()
            .filter(|gap| {
                gap.capability == SemanticCapability::ExceptionalControlFlow
                    && source_text(SOURCE, mapping_source_span(procedure, gap.source))
                        == "input.value"
            })
            .collect::<Vec<_>>();
        let [gap] = gaps.as_slice() else {
            panic!("the selector owns one exceptional gap: {gaps:#?}");
        };
        assert!(matches!(gap.subject, SemanticGapSubject::Value(_)));
        assert_eq!(gap.kind, SemanticGapKind::Unsupported);
        assert_eq!(
            gap.discharge,
            SemanticGapDischarge::ExitOnlyProcedureCompletion,
            "active cleanup may run during panic completion but cannot resume the normal body"
        );
    }

    #[test]
    fn side_effect_free_leaf_comparison_needs_no_evaluation_order_gap() {
        let procedures = lower_fixture(
            r#"package main
func check(err error) {
    if err != nil { return }
}
"#,
        );
        let procedure = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent.is_none())
            .expect("check procedure");

        assert!(
            procedure
                .gaps
                .iter()
                .all(|gap| { gap.discharge != SemanticGapDischarge::RetainedEvaluationOrder })
        );
    }

    #[test]
    fn selector_compared_with_stable_literal_needs_no_evaluation_order_gap() {
        let procedures = lower_fixture(
            r#"package main
type record struct { value string }
func check(item *record) bool {
    return item.value != ("")
}
"#,
        );
        let procedure = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent.is_none())
            .expect("check procedure");

        assert!(
            procedure
                .gaps
                .iter()
                .all(|gap| gap.discharge != SemanticGapDischarge::RetainedEvaluationOrder),
            "a stable literal contributes no observable evaluation order: {:#?}",
            procedure.gaps
        );
        assert!(
            procedure.gaps.iter().any(|gap| {
                gap.capability == SemanticCapability::ExceptionalControlFlow
                    && gap.discharge == SemanticGapDischarge::NonRejoiningExceptionalExit
                    && gap.detail.as_ref() == "selection may panic on a nil operand"
            }),
            "the selector panic stays explicit and records Go's non-rejoining provenance"
        );
    }

    #[test]
    fn private_constant_array_assignment_needs_no_operand_order_gap() {
        let procedures = lower_fixture(
            r#"package main
type record struct { value int }
func sideEffect() int { return 1 }
func plain(target record) {
    target.value = sideEffect()
}
func dereferenced(target *record) {
    (*target).value = sideEffect()
}
func privateArray() {
    values := [2]int{}
    values[0] = sideEffect()
}
func sliceParameter(values []int) {
    values[0] = sideEffect()
}
func dynamicArray(index int) {
    values := [2]int{}
    values[index] = sideEffect()
}
func escapedArray(consume func(*[2]int)) {
    values := [2]int{}
    consume(&values)
    values[0] = sideEffect()
}
"#,
        );
        let procedure_named = |name: &str| {
            procedures
                .iter()
                .find(|procedure| {
                    procedure.lexical_parent.is_none()
                        && procedure
                            .locator
                            .declaration()
                            .segments()
                            .last()
                            .and_then(|segment| segment.name())
                            == Some(name)
                })
                .unwrap_or_else(|| panic!("missing procedure {name}"))
        };
        let has_order_gap = |name: &str| {
            procedure_named(name)
                .gaps
                .iter()
                .any(|gap| gap.discharge == SemanticGapDischarge::RetainedEvaluationOrder)
        };

        assert!(
            !has_order_gap("plain"),
            "taking the address of a direct field on a local value has no observable read order"
        );
        assert!(
            has_order_gap("dereferenced"),
            "an explicit dereference can panic before or after the unordered RHS call"
        );
        assert!(
            !has_order_gap("privateArray"),
            "a private array binding and constant index are inert beside the RHS call"
        );
        assert!(
            has_order_gap("sliceParameter"),
            "a slice descriptor can share mutable backing storage"
        );
        assert!(
            has_order_gap("dynamicArray"),
            "a dynamic index retains a runtime operand evaluation"
        );
        assert!(
            has_order_gap("escapedArray"),
            "a call-exposed array can be changed before the indexed assignment"
        );
    }

    #[test]
    fn package_variable_is_a_nonpanicable_side_effect_free_runtime_leaf() {
        let procedures = lower_fixture(
            r#"package main
import (
    "fmt"
    "os"
)
func write(message string) {
    fmt.Fprintln(os.Stderr, message)
}
"#,
        );
        let procedure = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent.is_none())
            .expect("write procedure");

        assert!(
            procedure
                .gaps
                .iter()
                .all(|gap| gap.discharge != SemanticGapDischarge::RetainedEvaluationOrder),
            "two side-effect-free runtime reads have no material relative order: {:#?}",
            procedure.gaps
        );
        assert!(
            procedure
                .gaps
                .iter()
                .all(|gap| gap.detail.as_ref() != "selection may panic on a nil operand"),
            "a proven package qualifier is not a runtime receiver that can panic: {:#?}",
            procedure.gaps
        );
        assert!(
            procedure
                .memory_locations
                .iter()
                .all(|location| !matches!(location.kind, MemoryLocationKind::Field { .. })),
            "a package-qualified declaration is not receiver-field memory: {procedure:#?}"
        );
    }

    #[test]
    fn same_file_package_variables_publish_stable_static_memory() {
        const SOURCE: &str = r#"package main

var total int
const fixed = 1

func update() {
    total = fixed
    total += fixed
    total++
}

func read() int { return total + fixed }
"#;
        let procedures = lower_fixture(SOURCE);
        let mut members = Vec::new();
        let mut loads = 0;
        let mut stores = 0;
        for procedure in &procedures {
            for point in &procedure.points {
                for event in &point.events {
                    let (location, read, write) = match event.effect {
                        SemanticEffect::MemoryLoad {
                            kind: MemoryAccessKind::Static,
                            location,
                            ..
                        } => (location, true, false),
                        SemanticEffect::MemoryStore {
                            kind: MemoryAccessKind::Static,
                            location,
                            ..
                        } => (location, false, true),
                        _ => continue,
                    };
                    let MemoryLocationKind::Static { member } =
                        &procedure.memory_locations[location.index()].kind
                    else {
                        unreachable!("static effects use static locations")
                    };
                    members.push(member.clone());
                    loads += usize::from(read);
                    stores += usize::from(write);
                }
            }
        }
        assert_eq!((loads, stores), (3, 3), "{procedures:#?}");
        assert!(
            members.windows(2).all(|pair| pair[0] == pair[1]),
            "every occurrence and procedure uses the declaration locator: {members:#?}"
        );
        assert_eq!(
            source_text(SOURCE, members[0].anchor().span()),
            "total",
            "the static identity is anchored at the variable declaration rather than an occurrence"
        );
    }

    #[test]
    fn exact_outer_capture_shadow_is_not_a_package_qualifier() {
        let procedures = lower_fixture(
            r#"package main
import "os"

type holder struct { Stderr *os.File }

func shadowed(os *holder) func() {
    return func() { _ = os.Stderr }
}

func imported() func() {
    return func() { _ = os.Stderr }
}
"#,
        );
        let shadowed_parent = procedures
            .iter()
            .find(|procedure| {
                procedure.lexical_parent.is_none()
                    && procedure
                        .locator
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some("shadowed")
            })
            .expect("shadowed parent procedure");
        let imported_parent = procedures
            .iter()
            .find(|procedure| {
                procedure.lexical_parent.is_none()
                    && procedure
                        .locator
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some("imported")
            })
            .expect("imported parent procedure");
        let shadowed_child = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent == Some(shadowed_parent.id))
            .expect("shadowed function-literal procedure");
        let imported_child = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent == Some(imported_parent.id))
            .expect("imported function-literal procedure");

        let [capture] = shadowed_parent.captures.as_slice() else {
            panic!("the shadowing parameter is captured exactly: {shadowed_parent:#?}");
        };
        assert_eq!(capture.mode, CaptureMode::MutableCell);
        assert!(imported_parent.gaps.iter().all(|gap| {
            gap.capability != SemanticCapability::Captures
                || !matches!(gap.subject, SemanticGapSubject::Value(_))
        }));
        assert!(shadowed_child.gaps.iter().any(|gap| {
            gap.capability == SemanticCapability::ExceptionalControlFlow
                && gap.discharge == SemanticGapDischarge::NonRejoiningExceptionalExit
        }));
        assert!(
            imported_child.gaps.iter().all(|gap| {
                gap.capability != SemanticCapability::ExceptionalControlFlow
                    || gap.discharge != SemanticGapDischarge::NonRejoiningExceptionalExit
            }),
            "the genuine import remains a nonpanicable package qualifier: {imported_child:#?}"
        );
    }

    #[test]
    fn single_child_runtime_wrappers_preserve_side_effect_free_leaf_classification() {
        let procedures = lower_fixture(
            r#"package main
import (
    "fmt"
    "os"
    fixture "example.com/fixture"
)
func write(format string, args ...any) {
    fmt.Fprintf((os.Stderr), (format), args...)
}
func pair(left, right any) []any {
    return []any{os.Stderr, left, right}
}
func spread() {
    fmt.Fprintln(os.Stderr, fixture.Args...)
}
"#,
        );

        for name in ["write", "pair", "spread"] {
            let procedure = procedures
                .iter()
                .find(|procedure| {
                    procedure.lexical_parent.is_none()
                        && procedure
                            .locator
                            .declaration()
                            .segments()
                            .last()
                            .and_then(|segment| segment.name())
                            == Some(name)
                })
                .unwrap_or_else(|| panic!("missing {name} procedure"));
            assert!(
                procedure
                    .gaps
                    .iter()
                    .all(|gap| gap.discharge != SemanticGapDischarge::RetainedEvaluationOrder),
                "a grammar-native wrapper around one side-effect-free runtime leaf must not fabricate an evaluation-order gap: {procedure:#?}"
            );
        }
    }

    #[test]
    fn effectful_wrapped_or_multi_child_operands_retain_evaluation_order_gaps() {
        let procedures = lower_fixture(
            r#"package main
import (
    "fmt"
    "os"
)
func produce() []any { return nil }
func fromCall(format string) {
    fmt.Fprintf(os.Stderr, format, produce()...)
}
func fromReceive(format string, values <-chan []any) {
    fmt.Fprintf(os.Stderr, format, (<-values)...)
}
func fromIndex(format string, values []any) {
    fmt.Fprintln(os.Stderr, values[next()])
}
func next() int { return 0 }
"#,
        );

        for name in ["fromCall", "fromReceive", "fromIndex"] {
            let procedure = procedures
                .iter()
                .find(|procedure| {
                    procedure.lexical_parent.is_none()
                        && procedure
                            .locator
                            .declaration()
                            .segments()
                            .last()
                            .and_then(|segment| segment.name())
                            == Some(name)
                })
                .unwrap_or_else(|| panic!("missing {name} procedure"));
            assert!(
                procedure
                    .gaps
                    .iter()
                    .any(|gap| gap.discharge == SemanticGapDischarge::RetainedEvaluationOrder),
                "wrappers must not hide a call, receive, or multi-child expression whose evaluation order remains material: {procedure:#?}"
            );
        }
    }

    #[test]
    fn package_variable_paired_with_call_retains_evaluation_order_gap() {
        let procedures = lower_fixture(
            r#"package main
import (
    "fmt"
    "os"
)
func mutate() any { return os.Stderr }
func write() {
    fmt.Fprintln(os.Stderr, mutate())
}
"#,
        );
        let procedure = procedures
            .iter()
            .find(|procedure| {
                procedure.lexical_parent.is_none()
                    && procedure
                        .locator
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some("write")
            })
            .expect("write procedure");

        assert!(
            procedure
                .gaps
                .iter()
                .any(|gap| gap.discharge == SemanticGapDischarge::RetainedEvaluationOrder),
            "a call can mutate the package variable before its read, so their relative order remains material: {:#?}",
            procedure.gaps
        );
        assert!(
            procedure
                .gaps
                .iter()
                .all(|gap| gap.detail.as_ref() != "selection may panic on a nil operand"),
            "the retained order gap must not restore a fabricated package-selector panic: {:#?}",
            procedure.gaps
        );
    }

    #[test]
    fn unary_dereferences_emit_value_uses_without_conflating_other_star_syntax() {
        let procedures = lower_fixture(
            r#"package main
func observe(pointer *int, number int, unknown any) {
    _ = *pointer
    _ = *((pointer))
    _ = &pointer
    _ = number * number
    _ = *unknown
}
"#,
        );
        let procedure = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent.is_none())
            .expect("observe procedure");
        let dereferences = procedure
            .points
            .iter()
            .flat_map(|point| &point.events)
            .filter(|event| {
                matches!(
                    event.effect,
                    SemanticEffect::ValueUse {
                        kind: ValueUseKind::Dereference,
                        ..
                    }
                )
            })
            .count();

        assert_eq!(
            dereferences, 3,
            "only grammar-native unary stars are dereferences: {procedure:#?}"
        );
    }

    #[test]
    fn unary_address_of_emits_typed_address_values_without_conflating_wrappers() {
        let procedures = lower_fixture(
            r#"package main
func consume(value any) {}
func replace(pointer **int) {}
func observe(pointer *int) {
    consume((pointer))
    consume(any(pointer))
    replace(&pointer)
    replace(&((pointer)))
}
"#,
        );
        let procedure = procedures
            .iter()
            .find(|procedure| {
                procedure.lexical_parent.is_none()
                    && procedure
                        .locator
                        .declaration()
                        .segments()
                        .iter()
                        .any(|segment| segment.name().is_some_and(|name| name == "observe"))
            })
            .expect("observe procedure");
        let address_values = procedure
            .values
            .iter()
            .filter(|value| value.kind == SemanticValueKind::Address)
            .map(|value| value.id)
            .collect::<HashSet<_>>();
        let pointer_parameter = procedure
            .values
            .iter()
            .find_map(|value| match value.kind {
                SemanticValueKind::Parameter { ordinal: 0, .. } => Some(value.id),
                _ => None,
            })
            .expect("pointer parameter value");
        let addressed_sources = procedure
            .points
            .iter()
            .flat_map(|point| &point.events)
            .filter_map(|event| match event.effect {
                SemanticEffect::Assignment { target, value }
                    if address_values.contains(&target) =>
                {
                    Some(value)
                }
                _ => None,
            })
            .collect::<Vec<_>>();

        assert_eq!(
            address_values.len(),
            2,
            "only grammar-native unary address-of creates an address value: {procedure:#?}"
        );
        assert_eq!(
            addressed_sources,
            vec![pointer_parameter, pointer_parameter],
            "parentheses do not obscure the exact addressed binding: {procedure:#?}"
        );
    }

    #[test]
    fn address_of_a_mutable_capture_uses_its_binding_without_reading_the_cell() {
        let procedures = lower_fixture(
            r#"package main
func consume(value *int) {}
func outer() {
    value := 0
    callback := func() { consume(&value) }
    callback()
}
"#,
        );
        let child = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent.is_some())
            .expect("callback procedure");
        let capture = child
            .memory_locations
            .iter()
            .find_map(|location| match location.kind {
                MemoryLocationKind::Capture {
                    binding: Some(binding),
                    ..
                } => Some((location.id, binding)),
                _ => None,
            })
            .expect("mutable capture retains its target binding");
        let address = child
            .values
            .iter()
            .find(|value| value.kind == SemanticValueKind::Address)
            .expect("address-of creates a typed address");

        assert!(
            child
                .points
                .iter()
                .flat_map(|point| &point.events)
                .any(|event| matches!(
                    event.effect,
                    SemanticEffect::Assignment { target, value }
                        if target == address.id && value == capture.1
                ))
        );
        assert!(
            child
                .points
                .iter()
                .flat_map(|point| &point.events)
                .all(|event| !matches!(
                    event.effect,
                    SemanticEffect::MemoryLoad { location, .. } if location == capture.0
                ))
        );
    }

    #[test]
    fn unary_address_of_package_global_uses_best_effort_value_without_local_identity() {
        let procedures = lower_fixture(
            r#"package main
var global int
func consume(value *int) {}
func observe() { consume(&global) }
"#,
        );
        let procedure = procedures
            .iter()
            .find(|procedure| {
                procedure.lexical_parent.is_none()
                    && procedure
                        .locator
                        .declaration()
                        .segments()
                        .iter()
                        .any(|segment| segment.name().is_some_and(|name| name == "observe"))
            })
            .expect("observe procedure survives valid package-global address lowering");
        let address = procedure
            .values
            .iter()
            .find(|value| value.kind == SemanticValueKind::Address)
            .expect("package-global address value");
        let source = procedure
            .points
            .iter()
            .flat_map(|point| &point.events)
            .find_map(|event| match event.effect {
                SemanticEffect::Assignment { target, value } if target == address.id => Some(value),
                _ => None,
            })
            .expect("address creation retains a structured source value");
        let source_value = procedure
            .values
            .iter()
            .find(|value| value.id == source)
            .expect("address source value");

        assert_eq!(
            source_value.kind,
            SemanticValueKind::Temporary,
            "package-global identity is best effort, never a fabricated local: {procedure:#?}"
        );
        assert!(procedure.gaps.iter().any(|gap| {
            gap.subject == SemanticGapSubject::Value(source)
                && gap.capability == SemanticCapability::Assignments
                && gap.kind == SemanticGapKind::Unsupported
        }));
    }

    #[test]
    fn imported_selector_address_without_a_location_does_not_fabricate_value_assignment() {
        const SOURCE: &str = r#"package main
import "net/http"

func observe() any { return &http.DefaultClient }
"#;
        let procedures = lower_fixture(SOURCE);
        let procedure = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent.is_none())
            .expect("observe procedure");
        let address = procedure
            .values
            .iter()
            .find(|value| {
                value.kind == SemanticValueKind::Address
                    && source_text(SOURCE, value_source_span(procedure, value.id))
                        == "&http.DefaultClient"
            })
            .expect("imported selector address value");
        assert!(
            procedure
                .points
                .iter()
                .flat_map(|point| &point.events)
                .all(|event| {
                    !matches!(event.effect, SemanticEffect::Assignment { target, .. } if target == address.id)
                })
        );
        let gap = procedure
            .gaps
            .iter()
            .find(|gap| {
                gap.subject == SemanticGapSubject::Value(address.id)
                    && gap.capability == SemanticCapability::Assignments
            })
            .expect("the unmaterialized imported location remains explicit");
        for impact in [
            SemanticGapImpact::Aliasing,
            SemanticGapImpact::HeapRead,
            SemanticGapImpact::HeapWrite,
        ] {
            assert!(gap.impacts.contains(impact));
        }
        assert!(
            procedure
                .points
                .iter()
                .flat_map(|point| &point.events)
                .all(|event| !matches!(
                    event.effect,
                    SemanticEffect::MemoryLoad {
                        kind: MemoryAccessKind::Field,
                        ..
                    }
                ))
        );
    }

    #[test]
    fn indirect_assignment_gap_names_the_dereferenced_semantic_value() {
        let procedures = lower_fixture(
            r#"package main
func replace(pointer **int, replacement *int) {
    *pointer = replacement
}
"#,
        );
        let procedure = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent.is_none())
            .expect("replace procedure");
        let assignment_gaps = procedure
            .gaps
            .iter()
            .filter(|gap| gap.capability == SemanticCapability::Assignments)
            .collect::<Vec<_>>();

        assert_eq!(assignment_gaps.len(), 1, "{procedure:#?}");
        let SemanticGapSubject::Value(address) = assignment_gaps[0].subject else {
            panic!("an indirect write must be scoped to its dereferenced value: {procedure:#?}");
        };
        assert!(
            assignment_gaps[0]
                .impacts
                .contains(SemanticGapImpact::HeapWrite),
            "an omitted indirect write must retain its heap-write impact: {procedure:#?}"
        );
        assert!(
            procedure.values.iter().any(|value| value.id == address),
            "the gap subject must name a published semantic value: {procedure:#?}"
        );
    }

    #[test]
    fn identifier_compared_with_call_retains_evaluation_order_gap() {
        let procedures = lower_fixture(
            r#"package main
var observed int
func mutate() int { observed = 1; return observed }
func check() bool {
    return observed == mutate()
}
"#,
        );
        let procedure = procedures
            .iter()
            .find(|procedure| {
                procedure.lexical_parent.is_none()
                    && procedure
                        .locator
                        .declaration()
                        .segments()
                        .iter()
                        .any(|segment| segment.name().is_some_and(|name| name == "check"))
            })
            .expect("check procedure");

        assert!(
            procedure
                .gaps
                .iter()
                .any(|gap| gap.discharge == SemanticGapDischarge::RetainedEvaluationOrder),
            "the call can mutate state observed by the identifier, so their relative order remains material: {:#?}",
            procedure.gaps
        );
    }

    #[test]
    fn scalar_memory_assignments_store_conversion_values_without_target_type_proof() {
        let procedures = lower_fixture(
            r#"package main
type record struct{}
type holder struct { value any }
func field(target *holder, source *record) {
    target.value = source
}
func index(target []any, source *record) {
    target[0] = source
}
"#,
        );
        for (name, expected_kind) in [
            ("field", MemoryAccessKind::Field),
            ("index", MemoryAccessKind::Index),
        ] {
            let procedure = procedures
                .iter()
                .find(|procedure| {
                    procedure.lexical_parent.is_none()
                        && procedure
                            .locator
                            .declaration()
                            .segments()
                            .last()
                            .and_then(|segment| segment.name())
                            == Some(name)
                })
                .unwrap_or_else(|| panic!("missing {name} procedure"));
            let (location, stored) = procedure
                .points
                .iter()
                .flat_map(|point| &point.events)
                .find_map(|event| match event.effect {
                    SemanticEffect::MemoryStore {
                        kind,
                        location,
                        value,
                    } if kind == expected_kind => Some((location, value)),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("{name} has one structured memory store"));
            assert!(matches!(
                &procedure.values[stored.index()].kind,
                SemanticValueKind::LanguageDefined(kind)
                    if kind.as_ref() == "go.assignment_conversion"
            ));
            let source = procedure
                .points
                .iter()
                .flat_map(|point| &point.events)
                .find_map(|event| match event.effect {
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::LanguageDefined,
                        source,
                        target,
                    } if target == stored => Some(source),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("{name} store derives from its raw RHS"));
            assert_ne!(source, stored);
            assert!(procedure.gaps.iter().all(|gap| {
                gap.subject != SemanticGapSubject::MemoryLocation(location)
                    || gap.capability != SemanticCapability::Values
            }));
        }
    }

    #[test]
    fn channel_receive_retains_its_source_local_normal_continuation() {
        const SOURCE: &str = r#"package main

func observe() {}

func receive(ch <-chan int) int {
    value := <-ch
    observe()
    return value
}

func send(ch chan<- *int, value int) {
    ch <- &value
    observe()
}
"#;
        let procedures = lower_fixture(SOURCE);
        let named = |name: &str| {
            procedures
                .iter()
                .find(|procedure| {
                    procedure
                        .locator
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some(name)
                })
                .unwrap_or_else(|| panic!("missing procedure {name}"))
        };

        let receive = named("receive");
        let receive_sync = receive
            .points
            .iter()
            .flat_map(|point| &point.events)
            .find_map(|event| match event.effect {
                SemanticEffect::Synchronization {
                    operation: SynchronizationOperation::ChannelReceive,
                    subject,
                } => Some(subject),
                _ => None,
            })
            .expect("receive publishes its exact channel event");
        assert_eq!(
            source_text(SOURCE, value_source_span(receive, receive_sync)),
            "ch"
        );
        let gaps = receive
            .gaps
            .iter()
            .filter(|gap| gap.discharge == SemanticGapDischarge::RetainedControlTopology)
            .collect::<Vec<_>>();
        let [gap] = gaps.as_slice() else {
            panic!("receive must own exactly one retained communication-topology gap: {gaps:#?}");
        };
        assert_eq!(gap.subject, SemanticGapSubject::Point);
        assert_eq!(gap.capability, SemanticCapability::NormalControlFlow);
        assert_eq!(gap.kind, SemanticGapKind::Unknown);
        assert_eq!(
            receive
                .control_edges
                .iter()
                .filter(|edge| {
                    edge.source_point == gap.point && edge.kind == ControlEdgeKind::Normal
                })
                .count(),
            1,
            "receive keeps its one source-local normal continuation"
        );

        let send = named("send");
        let send_sync = send
            .points
            .iter()
            .flat_map(|point| &point.events)
            .find_map(|event| match event.effect {
                SemanticEffect::Synchronization {
                    operation: SynchronizationOperation::ChannelSend,
                    subject,
                } => Some(subject),
                _ => None,
            })
            .expect("send publishes its exact channel event");
        assert_eq!(
            source_text(SOURCE, value_source_span(send, send_sync)),
            "ch"
        );
        assert!(
            send.gaps.iter().any(|gap| {
                gap.capability == SemanticCapability::NormalControlFlow
                    && gap.discharge == SemanticGapDischarge::None
            }),
            "a send remains open because communicating an address can expose later mutation"
        );

        assert!(
            send.gaps.iter().any(|gap| {
                gap.capability == SemanticCapability::ExceptionalControlFlow
                    && gap.discharge == SemanticGapDischarge::NonRejoiningExceptionalExit
            }),
            "the normal-topology proof must not erase send-on-closed panic uncertainty"
        );
    }

    #[test]
    fn builtin_close_is_synchronization_while_a_shadowed_close_is_a_call() {
        let procedures = lower_fixture(
            r#"package main
func builtin(ch chan int) { close(ch) }
func shadowed(close func(chan int), ch chan int) { close(ch) }
"#,
        );
        let builtin = named_procedure(&procedures, "builtin");
        assert!(builtin.call_sites.is_empty(), "{builtin:#?}");
        assert!(
            builtin
                .points
                .iter()
                .any(|point| point.events.iter().any(|event| {
                    matches!(
                        event.effect,
                        SemanticEffect::Synchronization {
                            operation: SynchronizationOperation::ChannelClose,
                            ..
                        }
                    )
                }))
        );

        let shadowed = named_procedure(&procedures, "shadowed");
        assert_eq!(shadowed.call_sites.len(), 1, "{shadowed:#?}");
        assert!(shadowed.points.iter().all(|point| {
            point
                .events
                .iter()
                .all(|event| !matches!(event.effect, SemanticEffect::Synchronization { .. }))
        }));
    }

    #[test]
    fn context_done_on_a_formal_retains_exact_channel_provenance() {
        const SOURCE: &str = r#"package main
import stdctx "context"

type localContext interface { Done() <-chan struct{} }

func exact(ctx stdctx.Context) { <-ctx.Done() }
func copied(ctx stdctx.Context) {
    other := ctx
    <-other.Done()
}
func local(ctx localContext) { <-ctx.Done() }
"#;
        let procedures = lower_fixture(SOURCE);
        let receive_subject = |name: &str| {
            let procedure = named_procedure(&procedures, name);
            let subject = procedure
                .points
                .iter()
                .flat_map(|point| &point.events)
                .find_map(|event| match event.effect {
                    SemanticEffect::Synchronization {
                        operation: SynchronizationOperation::ChannelReceive,
                        subject,
                    } => Some(subject),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("{name} has one channel receive: {procedure:#?}"));
            procedure.values[subject.index()].kind.clone()
        };

        assert_eq!(
            receive_subject("exact"),
            SemanticValueKind::LanguageDefined("go.context_done_formal_channel".into())
        );
        assert_eq!(receive_subject("copied"), SemanticValueKind::Temporary);
        assert_eq!(receive_subject("local"), SemanticValueKind::Temporary);
    }

    #[test]
    fn select_retains_each_communication_alternative_and_case_body() {
        let procedures = lower_fixture(
            r#"package main
func observe() {}
func choose(left chan<- int, right <-chan int) {
    select {
    case left <- 1:
        observe()
    case <-right:
        observe()
    default:
        observe()
    }
    observe()
}
"#,
        );
        let procedure = named_procedure(&procedures, "choose");
        let operations = procedure
            .points
            .iter()
            .flat_map(|point| &point.events)
            .filter_map(|event| match event.effect {
                SemanticEffect::Synchronization { operation, .. } => Some(operation),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            operations,
            vec![
                SynchronizationOperation::ChannelSend,
                SynchronizationOperation::ChannelReceive,
            ]
        );
        assert_eq!(
            procedure.call_sites.len(),
            4,
            "all case bodies and continuation"
        );
        assert!(procedure.control_edges.iter().any(|edge| {
            edge.kind == ControlEdgeKind::SwitchCase
                && procedure
                    .control_edges
                    .iter()
                    .filter(|candidate| candidate.source_point == edge.source_point)
                    .filter(|candidate| candidate.kind == ControlEdgeKind::SwitchCase)
                    .count()
                    == 3
        }));
        assert!(procedure.gaps.iter().all(|gap| {
            gap.detail.as_ref()
                != "select readiness, pseudo-random case choice, blocking, and selected case body are not lowered"
        }));
    }

    #[test]
    fn range_forms_retain_all_source_local_normal_successors() {
        const SOURCE: &str = r#"package main

type sequence func(func(int) bool)
type collection struct { values map[int]int }

func observe() {}
func arrayRange(values [2]int) { for range values { observe() } }
func pointerArrayRange(values *[2]int) { for range values { observe() } }
func sliceRange(values []int) { for range values { observe() } }
func mapRange(values map[int]int) { for range values { observe() } }
func stringRange(values string) { for range values { observe() } }
func channelRange(values <-chan int) { for range values { observe() } }
func integerRange(values int) { for range values { observe() } }
func functionRange(values sequence) { for range values { observe() } }
func (values *collection) fieldMapRange() { for range values.values { observe() } }

func controls(values []int, skip bool) {
Loop:
    for range values {
        if skip { continue Loop }
        break Loop
    }
    observe()
}
"#;
        let procedures = lower_fixture(SOURCE);
        let named = |name: &str| {
            procedures
                .iter()
                .find(|procedure| {
                    procedure
                        .locator
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some(name)
                })
                .unwrap_or_else(|| panic!("missing procedure {name}"))
        };

        for name in [
            "arrayRange",
            "pointerArrayRange",
            "sliceRange",
            "mapRange",
            "stringRange",
            "channelRange",
            "integerRange",
            "functionRange",
        ] {
            let procedure = named(name);
            let gaps = procedure
                .gaps
                .iter()
                .filter(|gap| gap.discharge == SemanticGapDischarge::RetainedControlTopology)
                .collect::<Vec<_>>();
            let [gap] = gaps.as_slice() else {
                panic!("{name} must own exactly one retained range-topology gap: {gaps:#?}");
            };
            assert_eq!(gap.subject, SemanticGapSubject::Point);
            assert_eq!(gap.capability, SemanticCapability::NormalControlFlow);
            assert_eq!(gap.kind, SemanticGapKind::Unknown);
            let outgoing = procedure
                .control_edges
                .iter()
                .filter(|edge| edge.source_point == gap.point)
                .map(|edge| edge.kind)
                .collect::<Vec<_>>();
            assert_eq!(
                outgoing,
                vec![
                    ControlEdgeKind::ConditionalTrue,
                    ControlEdgeKind::ConditionalFalse,
                ],
                "{name} range decision successors"
            );
            assert!(
                procedure.control_edges.iter().any(|edge| {
                    edge.target_point == gap.point && edge.kind == ControlEdgeKind::LoopBack
                }),
                "{name} normal body completion must return to the range decision"
            );
        }

        let map_range = named("mapRange");
        let map_backing_reads = map_range
            .points
            .iter()
            .flat_map(|point| &point.events)
            .filter_map(|event| {
                let SemanticEffect::MemoryLoad {
                    kind: MemoryAccessKind::Index,
                    location,
                    ..
                } = event.effect
                else {
                    return None;
                };
                let MemoryLocationKind::Index { identity, .. } =
                    map_range.memory_locations[location.index()].kind
                else {
                    unreachable!("an index load has an index location")
                };
                (identity == IndexedLocationIdentity::Aggregate)
                    .then(|| source_text(SOURCE, mapping_source_span(map_range, event.source)))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            map_backing_reads,
            ["range values"],
            "iterating a map is an ordinary read of its aggregate backing store"
        );
        let field_map_range = named("fieldMapRange");
        let field_map_backing_reads = field_map_range
            .points
            .iter()
            .flat_map(|point| &point.events)
            .filter_map(|event| {
                let SemanticEffect::MemoryLoad {
                    kind: MemoryAccessKind::Index,
                    location,
                    ..
                } = event.effect
                else {
                    return None;
                };
                matches!(
                    field_map_range.memory_locations[location.index()].kind,
                    MemoryLocationKind::Index {
                        identity: IndexedLocationIdentity::Aggregate,
                        ..
                    }
                )
                .then(|| source_text(SOURCE, mapping_source_span(field_map_range, event.source)))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            field_map_backing_reads,
            ["range values.values"],
            "same-file field types retain map backing semantics"
        );
        for name in [
            "arrayRange",
            "pointerArrayRange",
            "sliceRange",
            "stringRange",
            "channelRange",
            "integerRange",
            "functionRange",
        ] {
            let procedure = named(name);
            assert!(
                procedure
                    .points
                    .iter()
                    .flat_map(|point| &point.events)
                    .all(|event| match event.effect {
                        SemanticEffect::MemoryLoad {
                            kind: MemoryAccessKind::Index,
                            location,
                            ..
                        } => !matches!(
                            procedure.memory_locations[location.index()].kind,
                            MemoryLocationKind::Index {
                                identity: IndexedLocationIdentity::Aggregate,
                                ..
                            }
                        ),
                        _ => true,
                    }),
                "{name} must not acquire map-backing access semantics"
            );
        }

        let controls = named("controls");
        let range_gap = controls
            .gaps
            .iter()
            .find(|gap| gap.discharge == SemanticGapDischarge::RetainedControlTopology)
            .expect("the labeled range owns its topology marker");
        let exit = controls
            .control_edges
            .iter()
            .find(|edge| {
                edge.source_point == range_gap.point
                    && edge.kind == ControlEdgeKind::ConditionalFalse
            })
            .expect("range exhaustion reaches the post-loop continuation")
            .target_point;
        assert!(
            controls.control_edges.iter().any(|edge| {
                edge.target_point == range_gap.point && edge.kind == ControlEdgeKind::LoopBack
            }),
            "labeled continue returns to the range decision"
        );
        assert!(
            controls
                .control_edges
                .iter()
                .any(|edge| { edge.target_point == exit && edge.kind == ControlEdgeKind::Normal }),
            "labeled break reaches the same post-loop continuation as exhaustion"
        );
    }

    #[test]
    fn switch_retains_case_bodies_break_fallthrough_and_post_switch_successors() {
        const SOURCE: &str = r#"package main
func observe(string) {}
func caseZero() int { return 0 }
func caseOne() int { return 1 }
func caseTwo() int { return 2 }
func controls(mode int) {
Switch:
    switch mode {
    case caseZero():
        observe("labeled break")
        break Switch
    case caseOne():
        observe("fallthrough source")
        fallthrough
    default:
        observe("fallthrough target")
        break
    case caseTwo():
        observe("normal completion")
    }
    observe("after switch")
}
func noDefault(mode int) {
    switch mode {
    case caseZero():
        observe("only case")
    }
    observe("after no default")
}
func expressionless(first bool, second bool) {
    switch {
    case first:
        observe("first condition")
    case second:
        observe("second condition")
    default:
        observe("condition default")
    }
    observe("after conditions")
}
"#;
        let procedures = lower_fixture(SOURCE);
        let controls = named_procedure(&procedures, "controls");
        let no_default = named_procedure(&procedures, "noDefault");
        let expressionless = named_procedure(&procedures, "expressionless");
        let point_text = |procedure: &ProcedureSemanticsParts, point: ProgramPointId| {
            source_text(
                SOURCE,
                mapping_source_span(procedure, procedure.points[point.index()].source),
            )
        };

        assert!(
            controls
                .gaps
                .iter()
                .all(|gap| gap.capability != SemanticCapability::NormalControlFlow),
            "expression-switch selection and case bodies are fully connected: {:#?}",
            controls.gaps
        );
        let [controls_switch] = controls.switch_facts.as_slice() else {
            panic!("controls has one switch fact: {controls:#?}")
        };
        assert_eq!(controls_switch.kind, SwitchFactKind::Expression);
        assert!(controls_switch.selector.is_some());
        assert_eq!(controls_switch.selector_domain, SwitchSelectorDomain::Open);
        assert_eq!(controls_switch.cases.len(), 3);
        assert!(controls_switch.default_present);
        assert!(controls_switch.default_edge.is_some());

        let [no_default_switch] = no_default.switch_facts.as_slice() else {
            panic!("noDefault has one switch fact: {no_default:#?}")
        };
        assert_eq!(no_default_switch.kind, SwitchFactKind::Expression);
        assert_eq!(no_default_switch.cases.len(), 1);
        assert!(!no_default_switch.default_present);
        assert!(no_default_switch.default_edge.is_none());

        let [expressionless_switch] = expressionless.switch_facts.as_slice() else {
            panic!("expressionless has one switch fact: {expressionless:#?}")
        };
        assert_eq!(expressionless_switch.kind, SwitchFactKind::Expressionless);
        assert!(expressionless_switch.selector.is_none());
        assert!(expressionless_switch.default_present);

        let comparisons = ["caseZero()", "caseOne()", "caseTwo()"].map(|text| {
            controls
                .points
                .iter()
                .find(|point| {
                    point_text(controls, point.id) == text
                        && controls.control_edges.iter().any(|edge| {
                            edge.source_point == point.id
                                && edge.kind == ControlEdgeKind::SwitchCase
                        })
                })
                .map(|point| point.id)
                .unwrap_or_else(|| panic!("missing tagged switch comparison for {text}"))
        });
        for (index, expected_false_target) in ["caseOne()", "caseTwo()", "default:"]
            .into_iter()
            .enumerate()
        {
            let outgoing = controls
                .control_edges
                .iter()
                .filter(|edge| edge.source_point == comparisons[index])
                .collect::<Vec<_>>();
            assert_eq!(outgoing.len(), 2, "{outgoing:#?}");
            assert!(
                outgoing
                    .iter()
                    .any(|edge| edge.kind == ControlEdgeKind::SwitchCase)
            );
            assert!(
                outgoing.iter().any(|edge| {
                    edge.kind == ControlEdgeKind::ConditionalFalse
                        && point_text(controls, edge.target_point)
                            .starts_with(expected_false_target)
                }),
                "case tests remain in source order and default is only the terminal no-match target: {outgoing:#?}"
            );
        }

        let call_point = |needle: &str| {
            controls
                .call_sites
                .iter()
                .find(|call| {
                    source_text(SOURCE, mapping_source_span(controls, call.source)) == needle
                })
                .map(|call| call.point)
                .unwrap_or_else(|| panic!("missing lowered case-body call {needle}: {controls:#?}"))
        };
        for call in [
            "caseZero()",
            "caseOne()",
            "caseTwo()",
            "observe(\"labeled break\")",
            "observe(\"fallthrough source\")",
            "observe(\"fallthrough target\")",
            "observe(\"normal completion\")",
            "observe(\"after switch\")",
        ] {
            call_point(call);
        }

        let fallthrough_point = controls
            .points
            .iter()
            .find(|point| point_text(controls, point.id) == "fallthrough")
            .map(|point| point.id)
            .expect("terminal fallthrough has a source-backed transfer point");
        let fallthrough_target = controls
            .control_edges
            .iter()
            .find(|edge| edge.source_point == fallthrough_point)
            .expect("terminal fallthrough reaches the following clause");
        assert_eq!(fallthrough_target.kind, ControlEdgeKind::Normal);
        assert!(
            point_text(controls, fallthrough_target.target_point).starts_with("default:"),
            "fallthrough reaches the next source clause: {fallthrough_target:#?}"
        );

        let after_switch = controls
            .points
            .iter()
            .find(|point| point_text(controls, point.id) == "observe(\"after switch\")")
            .map(|point| point.id)
            .expect("post-switch continuation entry");
        for break_text in ["break Switch", "break"] {
            let break_point = controls
                .points
                .iter()
                .find(|point| point_text(controls, point.id) == break_text)
                .map(|point| point.id)
                .unwrap_or_else(|| panic!("missing {break_text} point"));
            assert!(
                controls.control_edges.iter().any(|edge| {
                    edge.source_point == break_point
                        && edge.target_point == after_switch
                        && edge.kind == ControlEdgeKind::Normal
                }),
                "{break_text} must resolve through the switch Breakable scope"
            );
        }

        let no_default_comparison = no_default
            .points
            .iter()
            .find(|point| {
                point_text(no_default, point.id) == "caseZero()"
                    && no_default.control_edges.iter().any(|edge| {
                        edge.source_point == point.id && edge.kind == ControlEdgeKind::SwitchCase
                    })
            })
            .map(|point| point.id)
            .expect("no-default tagged comparison");
        let no_default_successors = no_default
            .control_edges
            .iter()
            .filter(|edge| edge.source_point == no_default_comparison)
            .collect::<Vec<_>>();
        assert_eq!(no_default_successors.len(), 2, "{no_default_successors:#?}");
        assert!(
            no_default_successors
                .iter()
                .any(|edge| edge.kind == ControlEdgeKind::SwitchCase)
        );
        assert!(no_default_successors.iter().any(|edge| {
            edge.kind == ControlEdgeKind::ConditionalFalse
                && point_text(no_default, edge.target_point) == "observe(\"after no default\")"
        }));

        let expressionless_guards = expressionless
            .guard_facts
            .iter()
            .filter(|guard| {
                point_text(expressionless, guard.point) == "first"
                    || point_text(expressionless, guard.point) == "second"
            })
            .collect::<Vec<_>>();
        assert_eq!(expressionless_guards.len(), 2, "{expressionless:#?}");
        let first_guard = expressionless_guards
            .iter()
            .find(|guard| point_text(expressionless, guard.point) == "first")
            .expect("first condition guard");
        assert_eq!(
            first_guard.true_arm.map(|arm| arm.kind),
            Some(ControlEdgeKind::SwitchCase)
        );
        assert!(first_guard.false_arm.is_some_and(|arm| {
            arm.kind == ControlEdgeKind::ConditionalFalse
                && point_text(expressionless, arm.target_point) == "second"
        }));
    }

    #[test]
    fn boolean_switch_facts_retain_exact_literal_cases() {
        const SOURCE: &str = r#"package main
func complete(flag bool) {
    switch flag {
    case true:
    case false:
    }
}
func missing(flag bool) {
    switch flag {
    case true:
    }
}
func alias(flag bool) {
    local := flag
    switch local {
    case true:
    case false:
    }
}
func defaulted(value int) {
    switch value {
    default:
    }
}
"#;
        let procedures = lower_fixture(SOURCE);
        for (name, expected_cases, expected_default, expected_domain) in [
            ("complete", 2, false, SwitchSelectorDomain::Boolean),
            ("missing", 1, false, SwitchSelectorDomain::Boolean),
            ("alias", 2, false, SwitchSelectorDomain::Boolean),
            ("defaulted", 0, true, SwitchSelectorDomain::Open),
        ] {
            let procedure = named_procedure(&procedures, name);
            let [fact] = procedure.switch_facts.as_slice() else {
                panic!("{name} has one switch fact: {procedure:#?}")
            };
            assert_eq!(fact.kind, SwitchFactKind::Expression);
            assert_eq!(fact.selector_domain, expected_domain);
            assert_eq!(fact.cases.len(), expected_cases);
            assert_eq!(fact.default_present, expected_default);
            for case in &fact.cases {
                assert!(matches!(
                    procedure.values[case.value.index()].kind,
                    SemanticValueKind::Boolean(_)
                ));
            }
        }
    }

    #[test]
    fn switch_case_statement_lists_own_sibling_local_scopes() {
        const SOURCE: &str = r#"package main
func acquire() int { return 0 }
func consume(int) {}
func scoped(mode int) {
    value := acquire()
    switch mode {
    case 0:
        value := acquire()
        consume(value)
    case 1:
        value := acquire()
        consume(value)
    }
    consume(value)
}
"#;
        let procedures = lower_fixture(SOURCE);
        let procedure = named_procedure(&procedures, "scoped");
        let mut consumed = procedure
            .call_sites
            .iter()
            .filter(|call| {
                source_text(SOURCE, mapping_source_span(procedure, call.source)) == "consume(value)"
            })
            .map(|call| {
                let span = mapping_source_span(procedure, call.source);
                let argument = call
                    .arguments
                    .first()
                    .map(|argument| argument.value)
                    .expect("consume has one argument");
                let binding = procedure
                    .points
                    .iter()
                    .flat_map(|point| &point.events)
                    .find_map(|event| match event.effect {
                        SemanticEffect::ValueFlow {
                            kind: ValueFlowKind::Local,
                            source,
                            target,
                        } if target == argument => Some(source),
                        _ => None,
                    })
                    .expect("identifier argument has one lexical input binding");
                (span.start_byte(), binding)
            })
            .collect::<Vec<_>>();
        consumed.sort_unstable_by_key(|(start, _)| *start);
        assert_eq!(consumed.len(), 3, "{procedure:#?}");
        assert_ne!(consumed[0].1, consumed[1].1);
        assert_ne!(consumed[1].1, consumed[2].1);
        assert_ne!(consumed[0].1, consumed[2].1);
        assert_eq!(
            source_text(SOURCE, value_source_span(procedure, consumed[2].1)),
            "value",
            "the post-switch read resolves to the outer binding after both implicit clause scopes end"
        );
    }

    #[test]
    fn switch_defer_stays_explicitly_unsupported_without_cutting_normal_flow() {
        const SOURCE: &str = r#"package main
func registrationValue() int { return 1 }
func cleanup(value int) {}
func after() {}
func run(mode int) {
    switch mode {
    case 0:
        defer cleanup(registrationValue())
    default:
    }
    after()
}
"#;
        let procedures = lower_fixture(SOURCE);
        let procedure = named_procedure(&procedures, "run");
        let defer_gaps = procedure
            .gaps
            .iter()
            .filter(|gap| {
                source_text(SOURCE, mapping_source_span(procedure, gap.source))
                    == "defer cleanup(registrationValue())"
            })
            .collect::<Vec<_>>();
        for capability in [
            SemanticCapability::DeferredExecution,
            SemanticCapability::CleanupControlFlow,
        ] {
            assert!(defer_gaps.iter().any(|gap| {
                gap.capability == capability
                    && gap.kind == SemanticGapKind::Unsupported
                    && gap.discharge == SemanticGapDischarge::ExitOnlyProcedureCompletion
            }));
        }
        assert!(defer_gaps.iter().any(|gap| {
            gap.capability == SemanticCapability::Calls
                && gap.discharge == SemanticGapDischarge::None
        }));
        assert!(procedure.call_sites.iter().any(|call| {
            source_text(SOURCE, mapping_source_span(procedure, call.source))
                == "registrationValue()"
        }));
        assert!(procedure.call_sites.iter().all(|call| {
            source_text(SOURCE, mapping_source_span(procedure, call.source))
                != "cleanup(registrationValue())"
        }));
        assert!(
            procedure
                .control_edges
                .iter()
                .all(|edge| edge.kind != ControlEdgeKind::Cleanup),
            "an unsupported branch-specific defer must not install a false cleanup route"
        );
        let after = procedure
            .call_sites
            .iter()
            .find(|call| {
                source_text(SOURCE, mapping_source_span(procedure, call.source)) == "after()"
            })
            .map(|call| call.point)
            .expect("post-switch call is lowered");
        let entry = procedure
            .points
            .iter()
            .find(|point| {
                point
                    .events
                    .iter()
                    .any(|event| event.effect == SemanticEffect::Entry)
            })
            .map(|point| point.id)
            .expect("procedure entry");
        let mut reachable = HashSet::default();
        let mut frontier = vec![entry];
        while let Some(point) = frontier.pop() {
            if !reachable.insert(point) {
                continue;
            }
            frontier.extend(
                procedure
                    .control_edges
                    .iter()
                    .filter(|edge| edge.source_point == point)
                    .map(|edge| edge.target_point),
            );
        }
        assert!(
            reachable.contains(&after),
            "unsupported defer registration retains the ordinary case and post-switch continuation"
        );
    }

    #[test]
    fn range_assignment_converts_existing_targets_but_fresh_binders_preserve_identity() {
        let procedures = lower_fixture(
            r#"package main
type record struct{}
type holder struct { value any }
func existing(values []*record) {
    var target any
    for target = range values { break }
}
func field(values []*record, target *holder) {
    for target.value = range values { break }
}
func index(values []*record, target []any) {
    for target[0] = range values { break }
}
func fresh(values []*record) {
    for target := range values { _ = target; break }
}
"#,
        );
        let named = |name: &str| {
            procedures
                .iter()
                .find(|procedure| {
                    procedure.lexical_parent.is_none()
                        && procedure
                            .locator
                            .declaration()
                            .segments()
                            .last()
                            .and_then(|segment| segment.name())
                            == Some(name)
                })
                .unwrap_or_else(|| panic!("missing {name} procedure"))
        };
        let conversion_values = |procedure: &ProcedureSemanticsParts| {
            procedure
                .values
                .iter()
                .filter_map(|value| match &value.kind {
                    SemanticValueKind::LanguageDefined(kind)
                        if kind.as_ref() == "go.assignment_conversion" =>
                    {
                        Some(value.id)
                    }
                    _ => None,
                })
                .collect::<Vec<_>>()
        };

        let existing = named("existing");
        let existing_conversions = conversion_values(existing);
        let [converted] = existing_conversions.as_slice() else {
            panic!("one existing-binding conversion: {existing:#?}");
        };
        assert!(existing.points.iter().any(|point| {
            point.events.iter().any(|event| {
                matches!(
                    event.effect,
                    SemanticEffect::Assignment { value, .. } if value == *converted
                )
            })
        }));
        assert!(
            existing
                .gaps
                .iter()
                .all(|gap| gap.capability != SemanticCapability::Values),
            "the opaque conversion flow preserves structured dependence: {existing:#?}"
        );

        for (name, expected_kind) in [
            ("field", MemoryAccessKind::Field),
            ("index", MemoryAccessKind::Index),
        ] {
            let procedure = named(name);
            let conversions = conversion_values(procedure);
            let [converted] = conversions.as_slice() else {
                panic!("one {name} memory conversion: {procedure:#?}");
            };
            assert!(procedure.points.iter().any(|point| {
                point.events.iter().any(|event| {
                    matches!(
                        event.effect,
                        SemanticEffect::MemoryStore { kind, value, .. }
                            if kind == expected_kind && value == *converted
                    )
                })
            }));
            assert!(
                procedure
                    .gaps
                    .iter()
                    .all(|gap| gap.capability != SemanticCapability::Values),
                "the {name} conversion flow preserves structured dependence: {procedure:#?}"
            );
        }

        let fresh = named("fresh");
        assert!(
            conversion_values(fresh).is_empty(),
            "a fresh range binder infers the element identity: {fresh:#?}"
        );
        let assignment = fresh
            .points
            .iter()
            .flat_map(|point| &point.events)
            .find_map(|event| match event.effect {
                SemanticEffect::Assignment { target, value } => Some((target, value)),
                _ => None,
            })
            .expect("fresh range binder has one assignment");
        assert!(fresh.points.iter().any(|point| {
            point.events.iter().any(|event| {
                matches!(
                    event.effect,
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Local,
                        source,
                        target,
                    } if source == assignment.1 && target == assignment.0
                )
            })
        }));
    }

    #[test]
    fn reassigned_go_cell_is_lowered_as_one_mutable_capture() {
        let procedures = lower_fixture(
            r#"package main
func outer() {
    value := acquire()
    value = acquire()
    defer func() { consume(value) }()
}
"#,
        );
        let parent = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent.is_none())
            .expect("outer procedure");
        let [capture] = parent.captures.as_slice() else {
            panic!("one shared-cell capture: {:#?}", parent.captures);
        };
        assert_eq!(capture.mode, CaptureMode::MutableCell);
        assert!(matches!(capture.captured, CaptureSource::Location(_)));
        let creation_point = parent
            .points
            .iter()
            .find(|point| {
                point
                    .events
                    .iter()
                    .any(|event| matches!(event.effect, SemanticEffect::CallableCreation { .. }))
            })
            .expect("function-literal creation point")
            .id;
        assert_eq!(capture.point, creation_point);
        assert!(parent.gaps.iter().all(|gap| {
            gap.capability != SemanticCapability::Captures
                || !matches!(gap.subject, SemanticGapSubject::Value(_))
        }));
    }

    #[test]
    fn escaped_and_aggregate_mutated_go_cells_are_mutable_captures() {
        const SOURCE: &str = r#"package main

func mutate(pointer *int) { *pointer = 1 }

func outer() {
    addressed := 0
    record := struct{ field int }{}
    array := [1]int{}
    stable := acquire()
    closure := func() {
        consume(addressed)
        consume(record.field)
        consume(array[0])
        consume(stable)
    }
    mutate(&addressed)
    record.field = 1
    array[0] = 1
    closure()
}
"#;
        let procedures = lower_fixture(SOURCE);
        let parent = procedures
            .iter()
            .find(|procedure| {
                procedure.lexical_parent.is_none()
                    && procedure
                        .locator
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some("outer")
            })
            .expect("outer procedure");

        let mut captures = parent
            .captures
            .iter()
            .map(|capture| {
                (
                    source_text(
                        SOURCE,
                        value_source_span(parent, capture_source_value(parent, capture)),
                    ),
                    capture.mode.clone(),
                )
            })
            .collect::<Vec<_>>();
        captures.sort_unstable_by_key(|(name, _)| *name);
        assert_eq!(
            captures,
            vec![
                ("addressed", CaptureMode::MutableCell),
                ("array", CaptureMode::MutableCell),
                ("record", CaptureMode::MutableCell),
                ("stable", CaptureMode::Value),
            ]
        );
        assert!(parent.gaps.iter().all(|gap| {
            gap.capability != SemanticCapability::Captures
                || !matches!(gap.subject, SemanticGapSubject::Value(_))
        }));
    }

    #[test]
    fn pointer_receiver_method_selection_shares_only_the_addressed_capture() {
        const SOURCE: &str = r#"package main

type Holder struct {
    callback func() int
    value int
}

func (holder *Holder) mutate() int { holder.value++; return holder.value }
func (holder Holder) read() int { return holder.value }
func stable() int { return 0 }

func outer() {
    pointerMethod := Holder{}
    valueMethod := Holder{}
    functionField := Holder{callback: stable}
    pointerValue := &Holder{}
    closure := func() {
        mutate := pointerMethod.mutate
        read := valueMethod.read
        callback := functionField.callback
        mutatePointer := pointerValue.mutate
        consume(mutate(), read(), callback(), mutatePointer())
    }
    closure()
}
"#;
        let procedures = lower_fixture(SOURCE);
        let parent = procedures
            .iter()
            .find(|procedure| {
                procedure.lexical_parent.is_none()
                    && procedure
                        .locator
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some("outer")
            })
            .expect("outer procedure");

        let mut captures = parent
            .captures
            .iter()
            .map(|capture| {
                (
                    source_text(
                        SOURCE,
                        value_source_span(parent, capture_source_value(parent, capture)),
                    ),
                    capture.mode.clone(),
                )
            })
            .collect::<Vec<_>>();
        captures.sort_unstable_by_key(|(name, _)| *name);
        assert_eq!(
            captures,
            vec![
                ("functionField", CaptureMode::Value),
                ("pointerMethod", CaptureMode::MutableCell),
                ("pointerValue", CaptureMode::Value),
                ("valueMethod", CaptureMode::Value),
            ]
        );
    }

    #[test]
    fn integer_literal_indices_share_canonical_identity_and_keep_typed_gaps() {
        const SOURCE: &str = r#"package main

func indexes(values []int, dynamic int, iota int) int {
    return values[0] +
        values[0x0] +
        values[0_0] +
        values[0b0] +
        values[10] +
        values[0xa] +
        values[0x_a] +
        values[012] +
        values[0o12] +
        values[0b1010] +
        values[1] +
        values[dynamic] +
        values[iota]
}
"#;
        let procedures = lower_fixture(SOURCE);
        let procedure = procedures
            .iter()
            .find(|procedure| {
                procedure
                    .locator
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("indexes")
            })
            .expect("indexes procedure");

        let location_for = |expected: &str| {
            procedure
                .points
                .iter()
                .find_map(|point| {
                    let span = procedure.source_mappings[point.source.index()]
                        .locator
                        .anchor()
                        .span();
                    if source_text(SOURCE, span) != expected {
                        return None;
                    }
                    point.events.iter().find_map(|event| match &event.effect {
                        SemanticEffect::MemoryLoad {
                            kind: MemoryAccessKind::Index,
                            location,
                            ..
                        } => Some(*location),
                        _ => None,
                    })
                })
                .unwrap_or_else(|| panic!("missing index load for {expected}"))
        };
        let index_for =
            |location: MemoryLocationId| match &procedure.memory_locations[location.index()].kind {
                MemoryLocationKind::Index { index, .. } => *index,
                kind => panic!("expected index location, got {kind:?}"),
            };
        let constant_for =
            |location: MemoryLocationId| match &procedure.memory_locations[location.index()].kind {
                MemoryLocationKind::Index { constant_index, .. } => *constant_index,
                kind => panic!("expected index location, got {kind:?}"),
            };

        let zero_location = location_for("values[0]");
        let zero = index_for(zero_location).expect("literal zero has exact identity");
        assert_eq!(constant_for(zero_location), Some(0));
        for spelling in ["values[0x0]", "values[0_0]", "values[0b0]"] {
            assert_eq!(
                index_for(location_for(spelling)),
                Some(zero),
                "{spelling} must share zero's canonical identity"
            );
        }

        let ten = index_for(location_for("values[10]")).expect("literal ten has exact identity");
        assert_eq!(constant_for(location_for("values[10]")), Some(10));
        for spelling in [
            "values[0xa]",
            "values[0x_a]",
            "values[012]",
            "values[0o12]",
            "values[0b1010]",
        ] {
            assert_eq!(
                index_for(location_for(spelling)),
                Some(ten),
                "{spelling} must share ten's canonical identity"
            );
        }
        let one = index_for(location_for("values[1]")).expect("literal one has exact identity");
        assert_ne!(zero, one);
        assert_ne!(ten, one);

        let dynamic_location = location_for("values[dynamic]");
        let rebound_location = location_for("values[iota]");
        let dynamic = index_for(dynamic_location).expect("dynamic index retains its value");
        let rebound = index_for(rebound_location).expect("rebound index retains its value");
        assert_ne!(dynamic, rebound);
        assert!(!procedure.values[dynamic.index()].kind.is_constant());
        assert!(!procedure.values[rebound.index()].kind.is_constant());
        assert_eq!(constant_for(dynamic_location), None);
        assert_eq!(constant_for(rebound_location), None);

        for (location, expected_discharge) in [
            (zero_location, SemanticGapDischarge::CanonicalIndexIdentity),
            (dynamic_location, SemanticGapDischarge::None),
            (rebound_location, SemanticGapDischarge::None),
        ] {
            let gaps = procedure
                .gaps
                .iter()
                .filter(|gap| {
                    gap.subject == SemanticGapSubject::MemoryLocation(location)
                        && gap.capability == SemanticCapability::IndexMemory
                        && gap.kind == SemanticGapKind::Unsupported
                })
                .collect::<Vec<_>>();
            let [gap] = gaps.as_slice() else {
                panic!("index location {location:?} must retain one typed gap: {gaps:#?}");
            };
            assert_eq!(gap.discharge, expected_discharge);
        }
    }

    #[test]
    fn captured_collections_retain_backing_and_element_identity() {
        const SOURCE: &str = r#"package main

func collectionKinds() {
    mapValues := make(map[int]int)
    arrayValues := [2]int{}
    sliceValues := make([]int, 2)
    sliceAlias := sliceValues
    func() {
        mapValues[0] = 1
        arrayValues[0] = 1
        sliceAlias[0] = 1
    }()
}
"#;
        let procedures = lower_fixture(SOURCE);
        let parent = named_procedure(&procedures, "collectionKinds");
        let mut capture_modes = parent
            .captures
            .iter()
            .map(|capture| {
                (
                    source_text(
                        SOURCE,
                        value_source_span(parent, capture_source_value(parent, capture)),
                    ),
                    capture.mode.clone(),
                )
            })
            .collect::<Vec<_>>();
        capture_modes.sort_unstable_by_key(|(name, _)| *name);
        assert_eq!(
            capture_modes,
            [
                ("arrayValues", CaptureMode::MutableCell),
                ("mapValues", CaptureMode::Value),
                ("sliceAlias", CaptureMode::Value),
            ],
            "arrays capture their variable cell while stable map and slice descriptors capture by value"
        );

        let child = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent == Some(parent.id))
            .expect("collection closure");
        let indexed_identities = child
            .points
            .iter()
            .flat_map(|point| &point.events)
            .filter_map(|event| {
                let location = match event.effect {
                    SemanticEffect::MemoryStore {
                        kind: MemoryAccessKind::Index,
                        location,
                        ..
                    } => location,
                    _ => return None,
                };
                let MemoryLocationKind::Index { identity, .. } =
                    child.memory_locations[location.index()].kind
                else {
                    unreachable!("index stores use index locations")
                };
                Some((
                    source_text(SOURCE, mapping_source_span(child, event.source)),
                    identity,
                ))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            indexed_identities,
            [
                (
                    "mapValues[0] = 1",
                    crate::analyzer::semantic::IndexedLocationIdentity::Aggregate,
                ),
                (
                    "arrayValues[0] = 1",
                    crate::analyzer::semantic::IndexedLocationIdentity::Element,
                ),
                (
                    "sliceAlias[0] = 1",
                    crate::analyzer::semantic::IndexedLocationIdentity::Element,
                ),
            ],
            "map keys share one backing-store identity while array and slice constants retain element identity"
        );
    }

    #[test]
    fn slices_publish_backing_store_relations_but_array_copies_do_not() {
        const SOURCE: &str = r#"package main

func backing() {
    array := [2]int{}
    arrayCopy := array
    slice := []int{0, 0}
    alias := slice
    window := alias[1:]
    consume(arrayCopy, alias, window)
}
"#;
        let procedures = lower_fixture(SOURCE);
        let procedure = named_procedure(&procedures, "backing");
        let allocation_kinds = procedure
            .allocations
            .iter()
            .map(|allocation| allocation.kind.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            allocation_kinds,
            vec![AllocationKind::Array, AllocationKind::Slice]
        );

        let mut backing_offsets = procedure
            .points
            .iter()
            .flat_map(|point| &point.events)
            .filter_map(|event| match event.effect {
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::BackingStore { offset },
                    ..
                } => Some(offset),
                _ => None,
            })
            .collect::<Vec<_>>();
        backing_offsets.sort_unstable();
        assert_eq!(
            backing_offsets,
            vec![
                BackingStoreOffset::Zero,
                BackingStoreOffset::Zero,
                BackingStoreOffset::Zero,
                BackingStoreOffset::Constant(1),
            ]
        );
        let binding = |name: &str| {
            procedure
                .values
                .iter()
                .find(|value| {
                    value.kind == SemanticValueKind::Local
                        && source_text(SOURCE, value_source_span(procedure, value.id)) == name
                })
                .unwrap_or_else(|| panic!("missing {name} binding"))
                .id
        };
        let flow_into = |target: ValueId| {
            procedure
                .points
                .iter()
                .flat_map(|point| &point.events)
                .find_map(|event| match event.effect {
                    SemanticEffect::ValueFlow {
                        kind,
                        target: actual,
                        ..
                    } if actual == target => Some(kind),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("binding {target} has no value flow"))
        };
        assert_eq!(
            flow_into(binding("arrayCopy")),
            ValueFlowKind::Transfer(ValueTransfer {
                kind: TransferKind::AggregateCopy,
                operation: TransferOperation::None,
            }),
            "array assignment must publish a by-value aggregate-copy transfer"
        );
        assert_eq!(
            flow_into(binding("alias")),
            ValueFlowKind::BackingStore {
                offset: BackingStoreOffset::Zero,
            },
            "slice assignment must retain exact backing-store identity"
        );
        assert_eq!(
            flow_into(binding("window")),
            ValueFlowKind::BackingStore {
                offset: BackingStoreOffset::Zero,
            },
            "binding a subslice must preserve its already-shifted backing view"
        );
    }

    #[test]
    fn slices_retain_structured_dynamic_offsets_and_builtin_make_allocations() {
        const SOURCE: &str = r#"package main

func consume(values ...any) {}

func slices(dynamic int) {
    values := make([]int, 8)
    start := 1
    exact := values[start:dynamic:dynamic]
    open := values[dynamic:]
    consume(exact, open)
}

func shadowed(make func([]int, int) []int) {
    values := make([]int, 8)
    consume(values)
}
"#;
        let procedures = lower_fixture(SOURCE);
        let slices = named_procedure(&procedures, "slices");
        assert_eq!(
            slices
                .allocations
                .iter()
                .filter(|allocation| allocation.kind == AllocationKind::Slice)
                .count(),
            1,
            "the structured predeclared make call is a fresh slice allocation: {slices:#?}"
        );
        let dynamic_offsets = slices
            .points
            .iter()
            .flat_map(|point| &point.events)
            .filter_map(|event| match event.effect {
                SemanticEffect::ValueFlow {
                    kind:
                        ValueFlowKind::BackingStore {
                            offset: BackingStoreOffset::Value(offset),
                        },
                    ..
                } => Some(source_text(SOURCE, value_source_span(slices, offset))),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(dynamic_offsets, ["start", "dynamic"], "{slices:#?}");
        assert!(
            !slices.gaps.iter().any(|gap| {
                gap.detail.as_ref() == "Go slice expression has no exact local backing store"
            }),
            "dynamic end/capacity and start expressions retain the structured backing store"
        );

        let shadowed = named_procedure(&procedures, "shadowed");
        assert!(
            shadowed.allocations.is_empty(),
            "a rebound make identifier must remain an ordinary call: {shadowed:#?}"
        );
    }

    #[test]
    fn builtin_make_allocates_maps_and_channels_from_structured_type_arguments() {
        const SOURCE: &str = r#"package main

func references() {
    values := make(map[string]int)
    unbuffered := make(chan struct{})
    buffered := make(chan int, 1)
    _, _, _ = values, unbuffered, buffered
}
"#;
        let procedures = lower_fixture(SOURCE);
        let procedure = named_procedure(&procedures, "references");
        let kinds = procedure
            .allocations
            .iter()
            .map(|allocation| allocation.kind.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            kinds,
            [
                AllocationKind::Array,
                AllocationKind::LanguageDefined("go-channel".into()),
                AllocationKind::LanguageDefined("go-channel".into()),
            ],
            "{procedure:#?}"
        );
    }

    #[test]
    fn named_type_conversions_do_not_publish_invocations() {
        const SOURCE: &str = r#"package main

func conversions() {
    type local int
    converted := error(nil)
    number := local(1)
    error := func(any) any { return nil }
    called := error(nil)
    _, _, _ = converted, number, called
}
"#;
        let procedures = lower_fixture(SOURCE);
        let procedure = named_procedure(&procedures, "conversions");
        assert_eq!(
            procedure.call_sites.len(),
            1,
            "only the lexically shadowed function value is invoked: {procedure:#?}"
        );
        assert_eq!(
            procedure
                .gaps
                .iter()
                .filter(|gap| {
                    gap.detail.as_ref()
                        == "Go conversion result identity is intentionally not propagated"
                })
                .count(),
            2,
            "both structured named conversions retain explicit value gaps"
        );
    }

    #[test]
    fn pointer_conversion_syntax_is_not_an_invocation() {
        const SOURCE: &str = r#"package main

type item struct{}

func conversion() {
    value := (*item)(nil)
    _ = value
}
"#;
        let procedures = lower_fixture(SOURCE);
        let procedure = named_procedure(&procedures, "conversion");
        assert!(
            procedure.call_sites.is_empty(),
            "a parenthesized pointer type is structured conversion syntax: {procedure:#?}"
        );
    }

    #[test]
    fn indexed_addresses_retain_places_without_fabricating_memory_accesses() {
        const SOURCE: &str = r#"package main

func consume(values ...any) {}

func addressAndRead(path, buf []byte, dynamic int) {
    first := &path[0]
    second := &buf[0]
    third := &buf[dynamic]
    value := path[0x0]
    path[0b0] = value
    consume(first, second, third, value)
}
"#;
        let procedures = lower_fixture(SOURCE);
        let procedure = named_procedure(&procedures, "addressAndRead");

        let addressed_locations = procedure
            .gaps
            .iter()
            .filter_map(|gap| {
                if gap.capability != SemanticCapability::Assignments
                    || gap.kind != SemanticGapKind::Unsupported
                    || !gap.impacts.contains(SemanticGapImpact::Aliasing)
                {
                    return None;
                }
                let SemanticGapSubject::MemoryLocation(location) = gap.subject else {
                    return None;
                };
                Some(location)
            })
            .collect::<Vec<_>>();
        assert_eq!(addressed_locations.len(), 3, "{procedure:#?}");

        let indexed_loads = procedure
            .points
            .iter()
            .flat_map(|point| &point.events)
            .filter_map(|event| match event.effect {
                SemanticEffect::MemoryLoad {
                    kind: MemoryAccessKind::Index,
                    location,
                    ..
                } => Some(location),
                _ => None,
            })
            .collect::<Vec<_>>();
        let indexed_stores = procedure
            .points
            .iter()
            .flat_map(|point| &point.events)
            .filter_map(|event| match event.effect {
                SemanticEffect::MemoryStore {
                    kind: MemoryAccessKind::Index,
                    location,
                    ..
                } => Some(location),
                _ => None,
            })
            .collect::<Vec<_>>();
        let [loaded_location] = indexed_loads.as_slice() else {
            panic!("only path[0x0] performs an indexed load: {procedure:#?}");
        };
        let [stored_location] = indexed_stores.as_slice() else {
            panic!("only path[0b0] performs an indexed store: {procedure:#?}");
        };
        assert!(
            addressed_locations.iter().all(|location| {
                !indexed_loads.contains(location) && !indexed_stores.contains(location)
            }),
            "taking an address must not fabricate a load or store: {procedure:#?}"
        );

        let index_for = |location: MemoryLocationId| {
            let MemoryLocationKind::Index { index, .. } =
                &procedure.memory_locations[location.index()].kind
            else {
                panic!("expected an indexed place: {procedure:#?}");
            };
            *index
        };
        let canonical_zero =
            index_for(*loaded_location).expect("a literal indexed load retains exact identity");
        assert_eq!(index_for(*stored_location), Some(canonical_zero));
        assert_eq!(
            addressed_locations
                .iter()
                .filter(|location| index_for(**location) == Some(canonical_zero))
                .count(),
            2,
            "equivalent literal address spellings must share canonical index identity"
        );
        let dynamic_indices = addressed_locations
            .iter()
            .filter_map(|location| index_for(*location))
            .filter(|index| !procedure.values[index.index()].kind.is_constant())
            .collect::<Vec<_>>();
        assert_eq!(
            dynamic_indices.len(),
            1,
            "a dynamic indexed address retains its structured value without inventing a constant identity"
        );

        let index_gaps = procedure
            .gaps
            .iter()
            .filter(|gap| gap.capability == SemanticCapability::IndexMemory)
            .collect::<Vec<_>>();
        assert_eq!(
            index_gaps.len(),
            2,
            "only the real load and store receive index-memory gaps: {procedure:#?}"
        );
        for location in [*loaded_location, *stored_location] {
            let gaps = index_gaps
                .iter()
                .filter(|gap| gap.subject == SemanticGapSubject::MemoryLocation(location))
                .collect::<Vec<_>>();
            let [gap] = gaps.as_slice() else {
                panic!("indexed access {location:?} must retain one typed gap: {gaps:#?}");
            };
            assert_eq!(gap.discharge, SemanticGapDischarge::CanonicalIndexIdentity);
        }
    }

    #[test]
    fn aggregate_updates_and_place_addresses_retain_memory_boundaries() {
        const SOURCE: &str = r#"package main

type Holder struct { value int }

func pair() (int, int) { return 1, 2 }
func mutate(holder *Holder) int { holder.value++; return holder.value }

func updates(values []int, index int) {
    holder := Holder{}
    holder.value++
    values[index]++
    holder.value += mutate(&holder)
    values[index] += 1
    other := 0
    values[index], other = pair()
    holder.value, values[index] = 1, 2
    _ = &holder.value
    _ = &values[index]
}

func pointerMulti(target *Holder) {
    var other int
    target.value, other = pair()
}
"#;
        let procedures = lower_fixture(SOURCE);
        let procedure = procedures
            .iter()
            .find(|procedure| {
                procedure
                    .locator
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("updates")
            })
            .expect("updates procedure");

        let effects = procedure
            .points
            .iter()
            .flat_map(|point| &point.events)
            .map(|event| &event.effect)
            .collect::<Vec<_>>();
        for kind in [MemoryAccessKind::Field, MemoryAccessKind::Index] {
            assert!(effects.iter().any(|effect| {
                matches!(effect, SemanticEffect::MemoryLoad { kind: found, .. } if *found == kind)
            }));
            assert!(effects.iter().any(|effect| {
                matches!(effect, SemanticEffect::MemoryStore { kind: found, .. } if *found == kind)
            }));
        }
        assert!(
            effects
                .iter()
                .filter(|effect| {
                    matches!(
                        effect,
                        SemanticEffect::MemoryStore {
                            kind: MemoryAccessKind::Index,
                            ..
                        }
                    )
                })
                .count()
                >= 3,
            "index increment, compound update, and multi-result target all store: {procedure:#?}"
        );
        let multi_result = procedure
            .call_sites
            .iter()
            .find(|call| call.normal_results.len() == 2)
            .expect("pair call has two normal results")
            .normal_results[0];
        let converted_multi_result = procedure
            .points
            .iter()
            .flat_map(|point| &point.events)
            .find_map(|event| match event.effect {
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::LanguageDefined,
                    source,
                    target,
                } if source == multi_result => Some(target),
                _ => None,
            })
            .expect("the indexed multi-result store has an assignment conversion");
        assert!(matches!(
            &procedure.values[converted_multi_result.index()].kind,
            SemanticValueKind::LanguageDefined(kind)
                if kind.as_ref() == "go.assignment_conversion"
        ));
        let converted_store_location = effects
            .iter()
            .find_map(|effect| match effect {
                SemanticEffect::MemoryStore {
                    kind: MemoryAccessKind::Index,
                    location,
                    value,
                } if *value == converted_multi_result => Some(*location),
                _ => None,
            })
            .expect("the indexed store writes the converted result");
        assert!(effects.iter().all(|effect| {
            !matches!(
                effect,
                SemanticEffect::MemoryStore {
                    kind: MemoryAccessKind::Index,
                    value,
                    ..
                } if *value == multi_result
            )
        }));
        assert!(procedure.gaps.iter().all(|gap| {
            gap.subject != SemanticGapSubject::MemoryLocation(converted_store_location)
                || gap.capability != SemanticCapability::Values
        }));
        assert!(procedure.gaps.iter().any(|gap| {
            gap.discharge == SemanticGapDischarge::RetainedEvaluationOrder
                && gap.capability == SemanticCapability::NormalControlFlow
        }));
        assert!(procedure.gaps.iter().any(|gap| {
            gap.subject == SemanticGapSubject::Point
                && gap.capability == SemanticCapability::Assignments
                && gap.impacts.contains(SemanticGapImpact::HeapWrite)
        }));

        let addressed_places = procedure
            .values
            .iter()
            .filter(|value| value.kind == SemanticValueKind::Address)
            .filter(|value| {
                matches!(
                    source_text(SOURCE, value_source_span(procedure, value.id)),
                    "&holder.value" | "&values[index]"
                )
            })
            .map(|value| value.id)
            .collect::<HashSet<_>>();
        assert_eq!(addressed_places.len(), 2);
        assert!(effects.iter().all(|effect| {
            !matches!(effect, SemanticEffect::Assignment { target, .. } if addressed_places.contains(target))
        }));
        let address_gaps = procedure
            .gaps
            .iter()
            .filter(|gap| {
                matches!(gap.subject, SemanticGapSubject::MemoryLocation(_))
                    && gap.capability == SemanticCapability::Assignments
            })
            .collect::<Vec<_>>();
        assert_eq!(address_gaps.len(), 2, "{procedure:#?}");
        assert!(address_gaps.iter().all(|gap| {
            gap.impacts.contains(SemanticGapImpact::Aliasing)
                && gap.impacts.contains(SemanticGapImpact::HeapRead)
                && gap.impacts.contains(SemanticGapImpact::HeapWrite)
        }));
        assert!(procedure.gaps.iter().any(|gap| {
            gap.capability == SemanticCapability::IndexMemory
                && matches!(gap.subject, SemanticGapSubject::MemoryLocation(_))
        }));

        let pointer_multi = procedures
            .iter()
            .find(|procedure| {
                procedure
                    .locator
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("pointerMulti")
            })
            .expect("pointerMulti procedure");
        assert!(
            pointer_multi
                .gaps
                .iter()
                .any(|gap| { gap.discharge == SemanticGapDischarge::RetainedEvaluationOrder })
        );
        let pointer_effects = pointer_multi
            .points
            .iter()
            .flat_map(|point| &point.events)
            .map(|event| &event.effect)
            .collect::<Vec<_>>();
        assert!(pointer_effects.iter().any(|effect| {
            matches!(
                effect,
                SemanticEffect::MemoryStore {
                    kind: MemoryAccessKind::Field,
                    ..
                }
            )
        }));
        assert!(pointer_effects.iter().all(|effect| {
            !matches!(
                effect,
                SemanticEffect::MemoryLoad {
                    kind: MemoryAccessKind::Field,
                    ..
                }
            )
        }));
    }

    #[test]
    fn dereference_read_modify_write_gaps_retain_heap_reads() {
        let procedures = lower_fixture(
            r#"package main
func update(pointer *int, replacement int) {
    *pointer = replacement
    *pointer += replacement
    (*pointer)++
}
"#,
        );
        let procedure = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent.is_none())
            .expect("update procedure");
        let gaps = procedure
            .gaps
            .iter()
            .filter(|gap| {
                gap.capability == SemanticCapability::Assignments
                    && matches!(gap.subject, SemanticGapSubject::Value(_))
                    && gap.impacts.contains(SemanticGapImpact::HeapWrite)
            })
            .collect::<Vec<_>>();
        assert_eq!(gaps.len(), 3, "{procedure:#?}");
        assert_eq!(
            gaps.iter()
                .filter(|gap| gap.impacts.contains(SemanticGapImpact::HeapRead))
                .count(),
            2,
            "only compound assignment and increment read before writing"
        );
    }

    #[test]
    fn unknown_selector_calls_remain_field_or_method_ambiguous() {
        const SOURCE: &str = r#"package main
import external "example.com/external"

type Holder struct { value int }
func (Holder) invoke() {}

func selectors(holder Holder, unknown external.Holder) {
    method := holder.invoke
    method()
    unknown.callback()
}
"#;
        let procedures = lower_fixture(SOURCE);
        let procedure = procedures
            .iter()
            .find(|procedure| {
                procedure
                    .locator
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("selectors")
            })
            .expect("selectors procedure");
        let load_results = procedure
            .points
            .iter()
            .flat_map(|point| &point.events)
            .filter_map(|event| match event.effect {
                SemanticEffect::MemoryLoad {
                    kind: MemoryAccessKind::Field,
                    result,
                    ..
                } => Some(source_text(SOURCE, value_source_span(procedure, result))),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(load_results.contains(&"unknown.callback"), "{procedure:#?}");
        assert!(!load_results.contains(&"holder.invoke"), "{procedure:#?}");
        for capability in [
            SemanticCapability::CallableReferences,
            SemanticCapability::DynamicDispatch,
        ] {
            assert!(procedure.gaps.iter().any(|gap| {
                gap.capability == capability
                    && matches!(gap.subject, SemanticGapSubject::Value(value)
                        if source_text(SOURCE, value_source_span(procedure, value)) == "holder.invoke")
            }));
        }
        assert!(procedure.gaps.iter().any(|gap| {
            gap.capability == SemanticCapability::FieldMemory
                && gap.impacts.contains(SemanticGapImpact::HeapRead)
                && gap.impacts.contains(SemanticGapImpact::Aliasing)
        }));
        let ambiguous_call = procedure
            .call_sites
            .iter()
            .find(|call| {
                source_text(SOURCE, value_source_span(procedure, call.callee)) == "unknown.callback"
            })
            .expect("unknown selector call site");
        let receiver = ambiguous_call
            .receiver
            .expect("unknown selector retains a candidate method receiver");
        let callable_alternatives = procedure.points[ambiguous_call.point.index()]
            .events
            .iter()
            .filter_map(|event| match &event.effect {
                SemanticEffect::CallableReference { result, callable }
                    if *result == ambiguous_call.callee =>
                {
                    Some((callable.kind, callable.bound_receiver))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            callable_alternatives.len(),
            2,
            "unknown selector retains exactly two callable interpretations"
        );
        assert!(
            callable_alternatives.contains(&(CallableReferenceKind::Function, None)),
            "unknown selector retains its function-valued-field interpretation"
        );
        assert!(
            callable_alternatives.contains(&(CallableReferenceKind::BoundMethod, Some(receiver))),
            "unknown selector retains its bound-method interpretation"
        );
        assert!(procedure.gaps.iter().any(|gap| {
            gap.capability == SemanticCapability::DynamicDispatch
                && gap.subject == SemanticGapSubject::CallSite(ambiguous_call.id)
        }));
    }

    #[test]
    fn deferred_unknown_selector_captures_receiver_without_losing_field_alternative() {
        const SOURCE: &str = r#"package main
import external "example.com/external"

func closeLater(resource *external.Resource) {
    defer resource.Close()
}
"#;
        let procedures = lower_fixture(SOURCE);
        let procedure = procedures
            .iter()
            .find(|procedure| {
                procedure
                    .locator
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("closeLater")
            })
            .expect("closeLater procedure");
        let call = procedure
            .call_sites
            .iter()
            .find(|call| {
                source_text(SOURCE, value_source_span(procedure, call.callee)) == "resource.Close"
            })
            .expect("deferred unknown selector call site");
        assert_eq!(
            procedure.values[call.callee.index()].kind,
            SemanticValueKind::Callable,
            "the registration-time selector value remains a valid deferred callee"
        );
        let receiver = call
            .receiver
            .expect("deferred unknown selector retains a captured candidate receiver");
        assert_eq!(
            procedure.values[receiver.index()].kind,
            SemanticValueKind::LanguageDefined("go.defer_capture".into())
        );
        let callable_alternatives = procedure.points[call.point.index()]
            .events
            .iter()
            .filter_map(|event| match &event.effect {
                SemanticEffect::CallableReference { result, callable }
                    if *result == call.callee =>
                {
                    Some((callable.kind, callable.bound_receiver))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            callable_alternatives.len(),
            2,
            "deferred unknown selector retains exactly two callable interpretations"
        );
        assert!(
            callable_alternatives.contains(&(CallableReferenceKind::Function, None)),
            "deferred selector retains its function-valued-field interpretation"
        );
        assert!(
            callable_alternatives.contains(&(CallableReferenceKind::BoundMethod, Some(receiver))),
            "deferred selector retains its bound-method interpretation with the captured receiver"
        );
        assert!(procedure.gaps.iter().all(|gap| {
            !matches!(
                gap.capability,
                SemanticCapability::DeferredExecution | SemanticCapability::CleanupControlFlow
            )
        }));
        assert!(procedure.gaps.iter().any(|gap| {
            gap.capability == SemanticCapability::DynamicDispatch
                && gap.subject == SemanticGapSubject::CallSite(call.id)
        }));
    }

    #[test]
    fn deferred_cross_file_function_evaluation_keeps_a_callable_value() {
        const SOURCE: &str = r#"package main
type Resource struct{}

func closeLater(resource *Resource) {
    defer closeResource(resource)
}
"#;
        let procedures = lower_fixture(SOURCE);
        let procedure = procedures
            .iter()
            .find(|procedure| {
                procedure
                    .locator
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("closeLater")
            })
            .expect("closeLater procedure");
        let call = procedure
            .call_sites
            .iter()
            .find(|call| {
                source_text(SOURCE, value_source_span(procedure, call.callee)) == "closeResource"
            })
            .expect("deferred cross-file function call");

        assert_eq!(
            procedure.values[call.callee.index()].kind,
            SemanticValueKind::Callable,
            "registration-time evaluation and deferred invocation share one callable row"
        );
        assert!(procedure.points.iter().any(|point| {
            point.events.iter().any(|event| {
                matches!(
                    event.effect,
                    SemanticEffect::CallableReference { result, .. } if result == call.callee
                )
            })
        }));
    }

    #[test]
    fn parenthesized_method_receivers_keep_direct_and_deferred_source_identity() {
        const SOURCE: &str = r#"package main
import external "example.com/external"

func closeBoth(resource *external.Resource) {
    (resource).Close()
    defer (resource).Close()
}
"#;
        let procedures = lower_fixture(SOURCE);
        let procedure = procedures
            .iter()
            .find(|procedure| {
                procedure
                    .locator
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("closeBoth")
            })
            .expect("closeBoth procedure");
        let receiver_calls = procedure
            .call_sites
            .iter()
            .filter_map(|call| {
                let receiver = call.receiver?;
                source_text(SOURCE, value_source_span(procedure, call.callee))
                    .ends_with(".Close")
                    .then_some((call, receiver))
            })
            .collect::<Vec<_>>();
        let [first, second] = receiver_calls.as_slice() else {
            panic!("one direct and one deferred receiver call: {procedure:#?}");
        };
        let (direct, deferred) = if procedure.values[first.1.index()].kind
            == SemanticValueKind::LanguageDefined("go.defer_capture".into())
        {
            (*second, *first)
        } else {
            (*first, *second)
        };
        assert_eq!(
            source_text(SOURCE, value_source_span(procedure, direct.1)),
            "resource",
            "transparent parentheses do not mint a direct receiver value"
        );
        let direct_read = procedure
            .points
            .iter()
            .flat_map(|point| &point.events)
            .find(|event| {
                matches!(
                    event.effect,
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Local
                            | ValueFlowKind::Parameter
                            | ValueFlowKind::Receiver,
                        target,
                        ..
                    } if target == direct.1
                )
            })
            .expect("direct receiver lexical read");
        assert_eq!(
            source_text(SOURCE, mapping_source_span(procedure, direct_read.source)),
            "resource",
            "the direct receiver read event retains the identifier mapping"
        );
        assert_eq!(
            procedure.values[deferred.1.index()].kind,
            SemanticValueKind::LanguageDefined("go.defer_capture".into())
        );
        assert_eq!(
            source_text(SOURCE, value_source_span(procedure, deferred.1)),
            "resource",
            "the deferred capture retains the transparent receiver source"
        );
        let deferred_source = procedure
            .points
            .iter()
            .flat_map(|point| &point.events)
            .find_map(|event| match event.effect {
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::LanguageDefined,
                    source,
                    target,
                } if target == deferred.1
                    && source_text(SOURCE, value_source_span(procedure, source)) == "resource" =>
                {
                    Some(source)
                }
                _ => None,
            })
            .expect("deferred receiver capture source");
        let deferred_read = procedure
            .points
            .iter()
            .flat_map(|point| &point.events)
            .find(|event| {
                matches!(
                    event.effect,
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Local
                            | ValueFlowKind::Parameter
                            | ValueFlowKind::Receiver,
                        target,
                        ..
                    } if target == deferred_source
                )
            })
            .expect("deferred receiver lexical read");
        assert_eq!(
            source_text(SOURCE, mapping_source_span(procedure, deferred_read.source)),
            "resource",
            "the deferred receiver read event retains the identifier mapping"
        );
        assert!(
            procedure.points.iter().all(|point| {
                point.events.iter().all(|event| {
                    !matches!(
                        event.effect,
                        SemanticEffect::Assignment { target, .. }
                            if source_text(SOURCE, value_source_span(procedure, target))
                                == "(resource)"
                    )
                })
            }),
            "a transparent call receiver must not publish a wrapper transfer"
        );
    }

    #[test]
    fn rebound_predeclared_constants_are_runtime_capture_references() {
        const SOURCE: &str = r#"package main
func outer() {
    true := acquire()
    false := acquire()
    nil := acquire()
    iota := acquire()
    closure := func() { consume(true, false, nil, iota) }
    closure()
}
"#;
        let procedures = lower_fixture(SOURCE);
        let parent = procedures
            .iter()
            .find(|procedure| {
                procedure.lexical_parent.is_none()
                    && procedure
                        .locator
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some("outer")
            })
            .expect("outer procedure");
        let child = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent == Some(parent.id))
            .expect("capturing literal");
        let mut captures = parent
            .captures
            .iter()
            .filter_map(|capture| match capture.captured {
                CaptureSource::Value(value) => {
                    Some(source_text(SOURCE, value_source_span(parent, value)))
                }
                CaptureSource::Location(_) => None,
            })
            .collect::<Vec<_>>();
        captures.sort_unstable();
        assert_eq!(captures, vec!["false", "iota", "nil", "true"]);
        for name in ["true", "false", "nil", "iota"] {
            let values = child
                .values
                .iter()
                .filter(|value| source_text(SOURCE, value_source_span(child, value.id)) == name)
                .collect::<Vec<_>>();
            assert!(!values.is_empty(), "missing runtime reference {name}");
            assert!(
                values
                    .iter()
                    .all(|value| value.kind != SemanticValueKind::Constant),
                "rebound {name} must not use the predeclared constant fast path: {child:#?}"
            );
        }
    }

    #[test]
    fn nested_builtin_nil_guard_excludes_a_rebound_outer_nil() {
        const SOURCE: &str = r#"package main
func acquire() any { return nil }
func consume(values ...any) {}

func builtinNil() {
    value := acquire()
    closure := func() {
        if value != nil { consume(value) }
    }
    closure()
}

func reboundNil() {
    value := acquire()
    nil := acquire()
    closure := func() {
        if value != nil { consume(value, nil) }
    }
    closure()
}
"#;
        let procedures = lower_fixture(SOURCE);
        let builtin_parent = procedures
            .iter()
            .find(|procedure| {
                procedure.lexical_parent.is_none()
                    && procedure
                        .locator
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some("builtinNil")
            })
            .expect("builtinNil procedure");
        let builtin_child = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent == Some(builtin_parent.id))
            .expect("builtinNil closure");
        assert_eq!(builtin_child.guard_facts.len(), 1, "{builtin_child:#?}");
        assert!(matches!(
            builtin_child.guard_facts[0].predicate,
            GuardPredicate::NullComparison {
                null_on_true: false
            }
        ));

        let rebound_parent = procedures
            .iter()
            .find(|procedure| {
                procedure.lexical_parent.is_none()
                    && procedure
                        .locator
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some("reboundNil")
            })
            .expect("reboundNil procedure");
        assert!(rebound_parent.captures.iter().any(|capture| {
            matches!(
                capture.captured,
                CaptureSource::Value(value)
                    if source_text(SOURCE, value_source_span(rebound_parent, value)) == "nil"
            )
        }));
        let rebound_child = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent == Some(rebound_parent.id))
            .expect("reboundNil closure");
        assert_eq!(rebound_child.guard_facts.len(), 1, "{rebound_child:#?}");
        assert!(matches!(
            rebound_child.guard_facts[0].predicate,
            GuardPredicate::Opaque { .. }
        ));
    }

    #[test]
    fn unresolved_qualified_keyed_literal_retains_possible_map_key_order() {
        let procedures = lower_fixture(
            r#"package main
import external "example.com/external"

var observed int
func keyCall() int { return observed }

func qualified() { _ = external.NamedMap{keyCall(): observed} }
func localKey(key int) { _ = external.NamedMap{key: 1, key: 2} }
func importedStruct() {
    _ = external.Record{First: keyCall(), Second: keyCall()}
}

type Record struct { Key int }
func knownStruct() { _ = Record{Key: observed} }
"#,
        );
        let named = |name: &str| {
            procedures
                .iter()
                .find(|procedure| {
                    procedure
                        .locator
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some(name)
                })
                .unwrap_or_else(|| panic!("missing procedure {name}"))
        };
        assert!(
            named("qualified")
                .gaps
                .iter()
                .any(|gap| { gap.discharge == SemanticGapDischarge::RetainedEvaluationOrder })
        );
        assert!(
            named("localKey")
                .gaps
                .iter()
                .any(|gap| { gap.discharge == SemanticGapDischarge::RetainedEvaluationOrder })
        );
        for near_miss in ["importedStruct", "knownStruct"] {
            assert!(
                named(near_miss)
                    .gaps
                    .iter()
                    .all(|gap| { gap.discharge != SemanticGapDischarge::RetainedEvaluationOrder })
            );
        }
    }

    #[test]
    fn slicing_an_exact_array_binding_uses_a_mutable_capture() {
        const SOURCE: &str = r#"package main
func consume(values ...any) {}
func mutate(view []int) int { view[0] = 1; return view[0] }

func outer() {
    array := [1]int{}
    view := array[:]
    read := func() { consume(array) }
    view[0] = 1
    read()
}

func ordered() {
    array := [1]int{}
    view := array[:]
    consume(array, mutate(view))
}
"#;
        let procedures = lower_fixture(SOURCE);
        let parent = procedures
            .iter()
            .find(|procedure| {
                procedure.lexical_parent.is_none()
                    && procedure
                        .locator
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some("outer")
            })
            .expect("outer procedure");
        let [capture] = parent.captures.as_slice() else {
            panic!("one exact array cell capture: {:#?}", parent.captures);
        };
        assert_eq!(capture.mode, CaptureMode::MutableCell);
        assert_eq!(
            source_text(
                SOURCE,
                value_source_span(parent, capture_source_value(parent, capture)),
            ),
            "array"
        );
        let ordered = procedures
            .iter()
            .find(|procedure| {
                procedure.lexical_parent.is_none()
                    && procedure
                        .locator
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some("ordered")
            })
            .expect("ordered procedure");
        assert!(
            ordered
                .gaps
                .iter()
                .any(|gap| { gap.discharge == SemanticGapDischarge::RetainedEvaluationOrder })
        );
    }

    #[test]
    fn unresolved_descendant_selector_exposes_the_original_parent_binding() {
        let procedures = lower_fixture(
            r#"package main
type Holder struct { value int }
func (holder *Holder) mutate() {}
func consume(values ...any) {}

func outer(holder Holder) {
    child := func() int { method := holder.mutate; method(); return 0 }
    consume(holder.value, child())
}
"#,
        );
        let procedure = procedures
            .iter()
            .find(|procedure| {
                procedure.lexical_parent.is_none()
                    && procedure
                        .locator
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some("outer")
            })
            .expect("outer procedure");
        assert!(
            procedure
                .gaps
                .iter()
                .any(|gap| { gap.discharge == SemanticGapDischarge::RetainedEvaluationOrder })
        );
    }

    #[test]
    fn mixed_value_and_mutable_captures_retain_per_binding_identity() {
        let procedures = lower_fixture(
            r#"package main
func outer() {
    mutable := acquire()
    stable := acquire()
    mutable = mutable
    defer func() {
        consume(stable)
        consume(mutable)
    }()
}
"#,
        );
        let parent = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent.is_none())
            .expect("outer procedure");
        let mut captures = parent
            .captures
            .iter()
            .map(|capture| (capture.mode.clone(), capture_source_value(parent, capture)))
            .collect::<Vec<_>>();
        captures.sort_unstable_by_key(|(_, value)| *value);
        assert_eq!(captures.len(), 2, "{:#?}", parent.captures);
        assert!(captures.iter().any(|(mode, _)| *mode == CaptureMode::Value));
        assert!(
            captures
                .iter()
                .any(|(mode, _)| *mode == CaptureMode::MutableCell)
        );
        assert!(parent.gaps.iter().all(|gap| {
            gap.capability != SemanticCapability::Captures
                || !matches!(gap.subject, SemanticGapSubject::Value(_))
        }));
    }

    #[test]
    fn reference_before_child_shadow_retains_its_outer_capture_identity() {
        const SOURCE: &str = r#"package main
func outer() {
    leading := acquire()
    stable := acquire()
    closure := func() {
        consume(leading)
        leading := acquire()
        consume(leading)
        consume(stable)
    }
    closure()
}
"#;
        let procedures = lower_fixture(SOURCE);
        let parent = procedures
            .iter()
            .find(|procedure| {
                procedure.lexical_parent.is_none()
                    && procedure
                        .locator
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some("outer")
            })
            .expect("outer procedure");
        let child = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent == Some(parent.id))
            .expect("function-literal procedure");

        assert_eq!(
            parent.captures.len(),
            2,
            "both the leading outer read and the unshadowed mixed capture need exact identity: {:#?}",
            parent.captures
        );
        let capture_results = child
            .points
            .iter()
            .flat_map(|point| &point.events)
            .filter_map(|event| {
                let SemanticEffect::MemoryLoad {
                    kind: MemoryAccessKind::Capture,
                    result,
                    ..
                } = event.effect
                else {
                    return None;
                };
                Some(result)
            })
            .collect::<HashSet<_>>();
        let mut captured_references = capture_results
            .iter()
            .map(|value| {
                let mapping = &child.source_mappings[child.values[value.index()].source.index()];
                let span = mapping.locator.anchor().span();
                (
                    SOURCE
                        .get(span.start_byte() as usize..span.end_byte() as usize)
                        .expect("capture mapping belongs to the fixture"),
                    span,
                )
            })
            .collect::<Vec<_>>();
        captured_references.sort_unstable_by_key(|(name, _)| *name);
        assert_eq!(
            captured_references
                .iter()
                .map(|(name, _)| *name)
                .collect::<Vec<_>>(),
            vec!["leading", "stable"]
        );
        let leading_capture = captured_references
            .iter()
            .find_map(|(name, span)| (*name == "leading").then_some(*span))
            .expect("leading capture mapping");
        let shadow_declaration = child
            .values
            .iter()
            .filter(|value| {
                value.kind == SemanticValueKind::Local && !capture_results.contains(&value.id)
            })
            .find_map(|value| {
                let mapping = &child.source_mappings[value.source.index()];
                let span = mapping.locator.anchor().span();
                (SOURCE.get(span.start_byte() as usize..span.end_byte() as usize)
                    == Some("leading"))
                .then_some(span)
            })
            .expect("child-local leading declaration mapping");
        assert!(
            leading_capture.end_byte() <= shadow_declaration.start_byte(),
            "the exact capture must come from the pre-shadow reference, not the post-shadow child local"
        );
        assert!(parent.gaps.iter().all(|gap| {
            gap.capability != SemanticCapability::Captures
                || !matches!(gap.subject, SemanticGapSubject::Value(_))
        }));
    }

    #[test]
    fn sibling_block_captures_with_the_same_name_keep_distinct_declarations() {
        let procedures = lower_fixture(
            r#"package main
func outer(first bool) {
    if first {
        f := acquire()
        defer func() { close(f) }()
    } else {
        f := acquire()
        defer func() { close(f) }()
    }
}
"#,
        );
        let parent = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent.is_none())
            .expect("outer procedure");
        let captured = parent
            .captures
            .iter()
            .map(|capture| (capture.target, capture.captured))
            .collect::<Vec<_>>();

        let [
            (first_target, CaptureSource::Value(first_value)),
            (second_target, CaptureSource::Value(second_value)),
        ] = captured.as_slice()
        else {
            panic!("two exact sibling captures: {captured:#?}");
        };
        assert_ne!(first_target, second_target);
        assert_ne!(first_value, second_value);
        assert!(parent.gaps.iter().all(|gap| {
            gap.capability != SemanticCapability::Captures
                || !matches!(gap.subject, SemanticGapSubject::Value(_))
        }));
    }

    #[test]
    fn func_literal_in_lowered_switch_case_retains_exact_capture() {
        let procedures = lower_fixture(
            r#"package main
func outer(choice int) {
    value := acquire()
    switch choice {
    default:
        closure := func() { consume(value) }
        closure()
    }
}
"#,
        );
        let parent = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent.is_none())
            .expect("outer procedure");
        let child = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent == Some(parent.id))
            .expect("function-literal procedure");

        let [capture] = parent.captures.as_slice() else {
            panic!("one exact switch-body capture: {:#?}", parent.captures);
        };
        assert_eq!(capture.target, child.id);
        assert_eq!(capture.mode, CaptureMode::Value);
        assert!(matches!(capture.captured, CaptureSource::Value(_)));
        assert!(child.memory_locations.iter().any(|location| {
            location.id == capture.destination
                && matches!(
                    location.kind,
                    MemoryLocationKind::Capture { lexical_parent, .. } if lexical_parent == parent.id
                )
        }));
        assert!(child.gaps.iter().all(|gap| {
            gap.subject != SemanticGapSubject::Procedure
                || gap.capability != SemanticCapability::Captures
        }));
    }

    #[test]
    fn binding_assigned_inside_func_literal_uses_the_shared_capture_cell() {
        let procedures = lower_fixture(
            r#"package main
func outer() {
    value := acquire()
    closure := func() {
        value = acquire()
        consume(value)
    }
    closure()
}
"#,
        );
        let parent = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent.is_none())
            .expect("outer procedure");
        let child = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent == Some(parent.id))
            .expect("function-literal procedure");

        let [capture] = parent.captures.as_slice() else {
            panic!("one mutable capture: {:#?}", parent.captures);
        };
        assert_eq!(capture.mode, CaptureMode::MutableCell);
        let CaptureSource::Location(parent_location) = capture.captured else {
            panic!("mutable capture must name its parent cell: {capture:#?}");
        };
        assert!(matches!(
            parent.memory_locations[parent_location.index()].kind,
            MemoryLocationKind::LexicalCell { .. }
        ));
        let child_effects = child
            .points
            .iter()
            .flat_map(|point| &point.events)
            .map(|event| &event.effect)
            .collect::<Vec<_>>();
        assert!(child_effects.iter().any(|effect| matches!(
            effect,
            SemanticEffect::MemoryLoad {
                kind: MemoryAccessKind::Capture,
                location,
                ..
            } if *location == capture.destination
        )));
        assert!(child_effects.iter().any(|effect| matches!(
            effect,
            SemanticEffect::MemoryStore {
                kind: MemoryAccessKind::Capture,
                location,
                ..
            } if *location == capture.destination
        )));
    }

    #[test]
    fn binding_assigned_by_nested_func_literal_relays_the_shared_cell() {
        let procedures = lower_fixture(
            r#"package main
func outer() {
    value := acquire()
    closure := func() {
        nested := func() { value = acquire() }
        nested()
        consume(value)
    }
    closure()
}
"#,
        );
        let parent = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent.is_none())
            .expect("outer procedure");

        let child = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent == Some(parent.id))
            .expect("intermediate child");
        let grandchild = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent == Some(child.id))
            .expect("nested child");
        let [outer_capture] = parent.captures.as_slice() else {
            panic!("outer-to-child relay: {parent:#?}");
        };
        let [nested_capture] = child.captures.as_slice() else {
            panic!("child-to-grandchild relay: {child:#?}");
        };
        assert_eq!(outer_capture.mode, CaptureMode::MutableCell);
        assert_eq!(nested_capture.mode, CaptureMode::MutableCell);
        assert_eq!(nested_capture.target, grandchild.id);
        assert_eq!(
            nested_capture.captured,
            CaptureSource::Location(outer_capture.destination)
        );
    }

    #[test]
    fn nested_func_literal_relays_an_immutable_ancestor_value() {
        let procedures = lower_fixture(
            r#"package main
func visit(callback func()) { callback() }
func outer() <-chan int {
    ch := make(chan int, 1)
    go func() {
        visit(func() { ch <- 1 })
        close(ch)
    }()
    return ch
}
"#,
        );
        let outer = procedures
            .iter()
            .find(|procedure| {
                procedure.lexical_parent.is_none()
                    && procedure
                        .locator
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some("outer")
            })
            .expect("outer procedure");
        let child = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent == Some(outer.id))
            .expect("intermediate child");
        let grandchild = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent == Some(child.id))
            .expect("nested child");

        let [outer_capture] = outer.captures.as_slice() else {
            panic!("one exact ancestor capture: {outer:#?}");
        };
        let [child_capture] = child.captures.as_slice() else {
            panic!("one exact relayed capture: {child:#?}");
        };
        assert_eq!(outer_capture.mode, CaptureMode::Value);
        assert_eq!(child_capture.mode, CaptureMode::Value);
        assert_eq!(outer_capture.target, child.id);
        assert_eq!(child_capture.target, grandchild.id);
        assert!(matches!(outer_capture.captured, CaptureSource::Value(_)));
        assert!(matches!(child_capture.captured, CaptureSource::Value(_)));
    }

    #[test]
    fn local_constant_capture_has_an_exact_owner_value() {
        let procedures = lower_fixture(
            r#"package main
func outer() {
    const label = "ready"
    callback := func() { consume(label) }
    callback()
}
"#,
        );
        let outer = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent.is_none())
            .expect("outer procedure");
        let child = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent == Some(outer.id))
            .expect("function-literal procedure");
        let [capture] = outer.captures.as_slice() else {
            panic!("one local constant capture: {outer:#?}");
        };
        assert_eq!(capture.target, child.id);
        assert_eq!(capture.mode, CaptureMode::Value);
        assert!(matches!(capture.captured, CaptureSource::Value(_)));
    }

    #[test]
    fn grandchild_only_read_relays_the_exact_ancestor_value() {
        let procedures = lower_fixture(
            r#"package main
func outer() {
    value := acquire()
    child := func() {
        grandchild := func() { consume(value) }
        grandchild()
    }
    child()
}
"#,
        );
        let outer = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent.is_none())
            .expect("outer procedure");
        let child = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent == Some(outer.id))
            .expect("intermediate child procedure");
        let grandchild = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent == Some(child.id))
            .expect("grandchild procedure");

        let [outer_capture] = outer.captures.as_slice() else {
            panic!("one ancestor relay into child: {outer:#?}");
        };
        let [child_capture] = child.captures.as_slice() else {
            panic!("one relay into grandchild: {child:#?}");
        };
        assert_eq!(outer_capture.mode, CaptureMode::Value);
        assert_eq!(child_capture.mode, CaptureMode::Value);
        assert_eq!(outer_capture.target, child.id);
        assert_eq!(child_capture.target, grandchild.id);
        assert!(matches!(outer_capture.captured, CaptureSource::Value(_)));
        assert!(matches!(child_capture.captured, CaptureSource::Value(_)));
        assert!(grandchild.points.iter().any(|point| {
            point.events.iter().any(|event| {
                matches!(
                    event.effect,
                    SemanticEffect::MemoryLoad {
                        kind: MemoryAccessKind::Capture,
                        location,
                        ..
                    } if location == child_capture.destination
                )
            })
        }));
    }

    #[test]
    fn explicitly_typed_scalar_var_initialization_assigns_conversion_value() {
        let procedures = lower_fixture(
            r#"package main
type record struct{}
func initialize(source *record) {
    var target any = source
    _ = target
}
"#,
        );
        let procedure = procedures
            .iter()
            .find(|procedure| procedure.lexical_parent.is_none())
            .expect("initialize procedure");
        let target = procedure
            .values
            .iter()
            .find(|value| value.kind == SemanticValueKind::Local)
            .expect("one explicitly typed local")
            .id;
        let events = procedure
            .points
            .iter()
            .flat_map(|point| &point.events)
            .collect::<Vec<_>>();
        let (initializer, converted) = events
            .iter()
            .find_map(|event| match event.effect {
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::LanguageDefined,
                    source,
                    target,
                } if matches!(
                    &procedure.values[target.index()].kind,
                    SemanticValueKind::LanguageDefined(kind)
                        if kind.as_ref() == "go.assignment_conversion"
                ) =>
                {
                    Some((source, target))
                }
                _ => None,
            })
            .expect("the initializer has an explicit assignment conversion");

        assert!(events.iter().any(|event| {
            matches!(
                event.effect,
                SemanticEffect::Assignment { target: assigned, value }
                    if assigned == target && value == converted
            )
        }));
        assert!(events.iter().any(|event| {
            matches!(
                event.effect,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Local,
                    source,
                    target: assigned,
                } if source == converted && assigned == target
            )
        }));
        assert!(events.iter().all(|event| {
            !matches!(
                event.effect,
                SemanticEffect::Assignment { target: assigned, value }
                    if assigned == target && value == initializer
            )
        }));
        assert!(procedure.gaps.iter().all(|gap| {
            gap.subject != SemanticGapSubject::Value(target)
                || gap.capability != SemanticCapability::Values
        }));
    }

    #[test]
    fn multi_result_assignment_gaps_preserve_call_result_identity() {
        let procedures = lower_fixture(
            r#"package main
type holder struct { first int }
func pair() (int, error) { return 0, nil }
func consume(value int) {}
func fieldAndDiscard(target *holder) {
    target.first, _ = pair()
    consume(target.first)
}
func outer() {
    var second error
    func() {
        var first int
        first, second = pair()
        if second != nil { return }
        consume(first)
    }()
}
"#,
        );
        let field_assignment = procedures
            .iter()
            .find(|procedure| {
                procedure.points.iter().any(|point| {
                    point
                        .events
                        .iter()
                        .any(|event| matches!(event.effect, SemanticEffect::MemoryStore { .. }))
                })
            })
            .expect("field-assignment procedure");
        let child = procedures
            .iter()
            .find(|procedure| {
                procedure.lexical_parent.is_some() && !procedure.call_sites.is_empty()
            })
            .expect("function-literal procedure");

        let field_call = field_assignment
            .call_sites
            .iter()
            .find(|call| call.normal_results.len() == 2)
            .expect("one multi-result field-assignment call");
        let [field_result, discarded_condition] = field_call.normal_results.as_ref() else {
            panic!("two field-assignment results: {field_call:#?}");
        };
        let converted_field_result = field_assignment
            .points
            .iter()
            .flat_map(|point| &point.events)
            .find_map(|event| match event.effect {
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::LanguageDefined,
                    source,
                    target,
                } if source == *field_result => Some(target),
                _ => None,
            })
            .expect("the field result has an explicit assignment conversion");
        assert!(matches!(
            &field_assignment.values[converted_field_result.index()].kind,
            SemanticValueKind::LanguageDefined(kind)
                if kind.as_ref() == "go.assignment_conversion"
        ));
        let field_assignment_point = field_assignment
            .points
            .iter()
            .find(|point| {
                point.events.iter().any(|event| {
                    matches!(
                        event.effect,
                        SemanticEffect::MemoryStore { value, .. }
                            if value == converted_field_result
                    )
                })
            })
            .expect("the converted result is stored into the receiver field");
        let field_store_location = field_assignment_point
            .events
            .iter()
            .find_map(|event| match event.effect {
                SemanticEffect::MemoryStore {
                    location, value, ..
                } if value == converted_field_result => Some(location),
                _ => None,
            })
            .expect("the converted result has one field location");
        assert!(field_assignment.points.iter().all(|point| {
            point.events.iter().all(|event| {
                !matches!(
                    event.effect,
                    SemanticEffect::MemoryStore { value, .. } if value == *field_result
                )
            })
        }));
        assert!(field_assignment.gaps.iter().any(|gap| {
            gap.point == field_assignment_point.id
                && gap.subject == SemanticGapSubject::Point
                && gap.capability == SemanticCapability::Calls
        }));
        assert!(field_assignment.gaps.iter().all(|gap| {
            gap.subject != SemanticGapSubject::MemoryLocation(field_store_location)
                || gap.capability != SemanticCapability::Values
        }));
        assert!(!field_assignment.gaps.iter().any(|gap| {
            gap.subject == SemanticGapSubject::Value(*discarded_condition)
                && gap.capability == SemanticCapability::Assignments
        }));

        let captured_call = child
            .call_sites
            .iter()
            .find(|call| call.normal_results.len() == 2)
            .expect("one multi-result captured-assignment call");
        let [local_result, captured_condition] = captured_call.normal_results.as_ref() else {
            panic!("two captured-assignment results: {captured_call:#?}");
        };
        let converted_result = child
            .points
            .iter()
            .flat_map(|point| &point.events)
            .find_map(|event| match event.effect {
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::LanguageDefined,
                    source,
                    target,
                } if source == *local_result => Some(target),
                _ => None,
            })
            .expect("the reused local receives an explicit assignment conversion");
        assert!(matches!(
            &child.values[converted_result.index()].kind,
            SemanticValueKind::LanguageDefined(kind)
                if kind.as_ref() == "go.assignment_conversion"
        ));
        assert!(child.points.iter().any(|point| {
            point.events.iter().any(|event| {
                matches!(
                    event.effect,
                    SemanticEffect::Assignment { value, .. } if value == converted_result
                )
            })
        }));
        assert!(child.points.iter().any(|point| {
            point.events.iter().any(|event| {
                matches!(
                    event.effect,
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Local,
                        source,
                        ..
                    } if source == converted_result
                )
            })
        }));
        assert!(child.points.iter().all(|point| {
            point.events.iter().all(|event| {
                !matches!(
                    event.effect,
                    SemanticEffect::Assignment { value, .. } if value == *local_result
                )
            })
        }));
        assert!(
            child
                .gaps
                .iter()
                .all(|gap| gap.capability != SemanticCapability::Values),
            "the opaque result conversion preserves structured dependence: {child:#?}"
        );
        let captured_conversion = child
            .points
            .iter()
            .flat_map(|point| &point.events)
            .find_map(|event| match event.effect {
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::LanguageDefined,
                    source,
                    target,
                } if source == *captured_condition => Some(target),
                _ => None,
            })
            .expect("the captured result receives an assignment conversion");
        assert!(child.points.iter().any(|point| {
            point.events.iter().any(|event| {
                matches!(
                    event.effect,
                    SemanticEffect::MemoryStore {
                        kind: MemoryAccessKind::Capture,
                        value,
                        ..
                    } if value == captured_conversion
                )
            })
        }));
        assert!(
            child
                .gaps
                .iter()
                .all(|gap| gap.capability != SemanticCapability::Assignments),
            "the exact captured cell no longer needs an assignment gap: {child:#?}"
        );
    }

    #[test]
    fn mixed_short_multi_result_converts_only_the_reused_binding() {
        let procedures = lower_fixture(
            r#"package main
type record struct{}
func pair() (*record, error) { return nil, nil }
func mixed() {
    var reused any
    reused, fresh := pair()
    _, _ = reused, fresh
}
"#,
        );
        let procedure = procedures
            .iter()
            .find(|procedure| {
                procedure.lexical_parent.is_none()
                    && procedure
                        .locator
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some("mixed")
            })
            .expect("mixed procedure");
        let call = procedure
            .call_sites
            .iter()
            .find(|call| call.normal_results.len() == 2)
            .expect("pair has two results");
        let [reused_result, fresh_result] = call.normal_results.as_ref() else {
            panic!("pair has two results: {call:#?}");
        };
        let events = procedure
            .points
            .iter()
            .flat_map(|point| &point.events)
            .collect::<Vec<_>>();
        let converted = events
            .iter()
            .find_map(|event| match event.effect {
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::LanguageDefined,
                    source,
                    target,
                } if source == *reused_result => Some(target),
                _ => None,
            })
            .expect("the reused interface binding keeps conversion identity open");

        assert!(events.iter().any(|event| {
            matches!(
                event.effect,
                SemanticEffect::Assignment { value, .. } if value == converted
            )
        }));
        assert!(events.iter().all(|event| {
            !matches!(
                event.effect,
                SemanticEffect::Assignment { value, .. } if value == *reused_result
            )
        }));
        assert!(events.iter().any(|event| {
            matches!(
                event.effect,
                SemanticEffect::Assignment { value, .. } if value == *fresh_result
            )
        }));
        assert!(events.iter().all(|event| {
            !matches!(
                event.effect,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::LanguageDefined,
                    source,
                    ..
                } if source == *fresh_result
            )
        }));
        assert!(
            procedure
                .gaps
                .iter()
                .all(|gap| gap.capability != SemanticCapability::Values),
            "the reused binding has an opaque conversion flow, not an uncertainty gap: {procedure:#?}"
        );
    }

    #[test]
    fn if_initializer_shadow_does_not_capture_later_multi_result_assignments() {
        const SOURCE: &str = r#"package main
type profiler struct { first, second, third int }
func create(string) (int, error) { return 0, nil }
func start(int) error { return nil }
func profile(receiver *profiler) error {
    var err error
    receiver.first, err = create("first")
    if err != nil { return err }
    if err := start(receiver.first); err != nil { return err }
    receiver.second, err = create("second")
    if err != nil { return err }
    receiver.third, err = create("third")
    if err != nil { return err }
    return nil
}
"#;
        let procedures = lower_fixture(SOURCE);
        let procedure = procedures
            .iter()
            .find(|procedure| {
                procedure.lexical_parent.is_none()
                    && procedure
                        .locator
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some("profile")
            })
            .expect("profile procedure");
        let mut error_locals = procedure
            .values
            .iter()
            .filter(|value| value.kind == SemanticValueKind::Local)
            .filter_map(|value| {
                let span = value_source_span(procedure, value.id);
                (source_text(SOURCE, span) == "err").then_some((span.start_byte(), value.id))
            })
            .collect::<Vec<_>>();
        error_locals.sort_unstable_by_key(|(start, _)| *start);
        let [(_, outer_error), (_, inner_error)] = error_locals.as_slice() else {
            panic!("one outer and one if-initializer error binding: {error_locals:#?}");
        };
        assert_ne!(outer_error, inner_error);

        let assignment_target = |result: ValueId| {
            let assigned_value = procedure
                .points
                .iter()
                .flat_map(|point| &point.events)
                .find_map(|event| match event.effect {
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::LanguageDefined,
                        source,
                        target,
                    } if source == result => Some(target),
                    _ => None,
                })
                .unwrap_or(result);
            procedure
                .points
                .iter()
                .flat_map(|point| &point.events)
                .find_map(|event| match event.effect {
                    SemanticEffect::Assignment { target, value } if value == assigned_value => {
                        Some(target)
                    }
                    _ => None,
                })
                .unwrap_or_else(|| panic!("call result {result} has one binding assignment"))
        };
        let callee_text = |call: &SemanticCallSite| {
            source_text(SOURCE, value_source_span(procedure, call.callee))
        };
        let create_calls = procedure
            .call_sites
            .iter()
            .filter(|call| callee_text(call) == "create")
            .collect::<Vec<_>>();
        assert_eq!(create_calls.len(), 3, "{:#?}", procedure.call_sites);
        for call in create_calls {
            let [_, error_result] = call.normal_results.as_ref() else {
                panic!("create has one value and one error result: {call:#?}");
            };
            assert_eq!(
                assignment_target(*error_result),
                *outer_error,
                "the if-initializer shadow ends with its if statement: {call:#?}"
            );
        }

        let start_call = procedure
            .call_sites
            .iter()
            .find(|call| callee_text(call) == "start")
            .expect("one scalar start call");
        assert_eq!(
            assignment_target(start_call.result.expect("start has one scalar result")),
            *inner_error,
            "the initializer and its guard bind the inner error"
        );

        let after_initializer = SOURCE
            .find("receiver.second")
            .expect("fixture contains a statement after the initializer shadow");
        let later_error_reads = procedure
            .points
            .iter()
            .flat_map(|point| &point.events)
            .filter_map(|event| match event.effect {
                SemanticEffect::ValueFlow { source, target, .. }
                    if procedure.values[source.index()].kind == SemanticValueKind::Local
                        && value_source_span(procedure, target).start_byte() as usize
                            > after_initializer
                        && source_text(SOURCE, value_source_span(procedure, target)) == "err" =>
                {
                    Some(source)
                }
                _ => None,
            })
            .collect::<HashSet<_>>();
        assert_eq!(
            later_error_reads,
            std::iter::once(*outer_error).collect::<HashSet<_>>(),
            "later guards and failure returns read only the restored outer binding"
        );
    }

    #[test]
    fn inferred_multi_result_var_declarations_preserve_result_ordinals() {
        let procedures = lower_fixture(
            r#"package main
func pair() (int, error) { return 0, nil }
func ints() (int, int) { return 0, 0 }
func inferred() {
    var first, second = pair()
}
func discarded() {
    var first, _ = pair()
}
func explicitlyTyped() {
    var first, second int = ints()
}
"#,
        );
        let inferred = procedures
            .iter()
            .filter_map(|procedure| {
                let call = procedure
                    .call_sites
                    .iter()
                    .find(|call| call.normal_results.len() == 2)?;
                Some((procedure, call))
            })
            .collect::<Vec<_>>();
        assert_eq!(inferred.len(), 2, "{inferred:#?}");

        let mut assignment_counts = Vec::new();
        for (procedure, call) in inferred {
            let assignment_sources = procedure
                .points
                .iter()
                .flat_map(|point| &point.events)
                .filter_map(|event| match event.effect {
                    SemanticEffect::Assignment { value, .. } => Some(value),
                    _ => None,
                })
                .collect::<HashSet<_>>();
            let flow_sources = procedure
                .points
                .iter()
                .flat_map(|point| &point.events)
                .filter_map(|event| match event.effect {
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Local,
                        source,
                        ..
                    } => Some(source),
                    _ => None,
                })
                .collect::<HashSet<_>>();
            assert!(
                procedure
                    .gaps
                    .iter()
                    .all(|gap| gap.capability != SemanticCapability::Assignments),
                "{procedure:#?}"
            );
            assert!(
                assignment_sources.contains(&call.normal_results[0])
                    && flow_sources.contains(&call.normal_results[0]),
                "{procedure:#?}"
            );
            assert_eq!(
                assignment_sources.contains(&call.normal_results[1]),
                flow_sources.contains(&call.normal_results[1]),
                "{procedure:#?}"
            );
            assignment_counts.push(assignment_sources.len());
        }
        assignment_counts.sort_unstable();
        assert_eq!(assignment_counts, vec![1, 2]);

        let explicitly_typed = procedures
            .iter()
            .find(|procedure| {
                procedure.gaps.iter().any(|gap| {
                    gap.subject == SemanticGapSubject::Point
                        && gap.capability == SemanticCapability::Assignments
                        && gap.detail.as_ref()
                            == "Go multi-name, tuple, and multi-result var initialization flow is not yet lowered"
                })
            })
            .expect("explicitly typed multi-result var stays conservative");
        assert!(
            explicitly_typed
                .call_sites
                .iter()
                .all(|call| call.normal_results.is_empty()),
            "{explicitly_typed:#?}"
        );
    }
}
