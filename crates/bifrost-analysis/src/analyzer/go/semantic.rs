//! Go lowering into the language-neutral executable-semantics IR.
//!
//! This module deliberately interprets tree-sitter nodes and fields directly.
//! Graph construction, abrupt-completion routing, cleanup specialization, and
//! physical adjacency storage remain owned by the shared semantic substrate.

use tree_sitter::Node;

use crate::analyzer::lexical_definitions::formal_parameter_slots_for_owner;
use crate::analyzer::semantic::cfg::{
    CompletionKind, CompletionRequest, CompletionRoute, ProcedureCfgBuilder, ScopeBinding,
    ScopeFrameId,
};
use crate::analyzer::semantic::service::{ProgramSemanticsLowerer, SemanticAdapterIdentity};
use crate::analyzer::semantic::*;
use crate::analyzer::tree_sitter_analyzer::{
    PreparedSyntaxTree, WalkControl, try_walk_named_tree_preorder,
};
use crate::analyzer::{GoAnalyzer, Language, ProjectFile};
use crate::hash::HashMap;

const ADAPTER_VERSION: &[u8] = b"go-value-semantics-v3";

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
        let (specs, package_shadowing, initial_work) =
            match enumerate_procedures(file, prepared, budget, cancellation)? {
                ProcedureEnumeration::Complete {
                    value,
                    initial_work,
                    ..
                } => (value.specs, value.package_shadowing, initial_work),
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
        SemanticCapability::Captures,
        SemanticCapability::DeferredExecution,
        SemanticCapability::ConcurrentSpawn,
        SemanticCapability::NonLocalControl,
        // Partial: a struct-field or element store and load is lowered into a
        // real memory row whenever the target shape is a single selector or a
        // single index over a value this procedure can name (#2662). A store
        // through a pointer dereference, a multi-target assignment, and a
        // dynamic index still publish their own gaps instead.
        SemanticCapability::FieldMemory,
        SemanticCapability::IndexMemory,
        // Partial: every decision this adapter reaches publishes a row, and a
        // predeclared `true` or `false` publishes the constant it folded on.
        // Go's comparison and nil-test syntax is still recorded `Opaque`
        // rather than normalized (#2443, #2662).
        SemanticCapability::GuardFacts,
    ] {
        builder = builder.partial(capability);
    }
    builder.build()
}

/// Which Go predeclared identifiers a program rebinds.
///
/// `new`, `panic`, `true`, and `false` are ordinary predeclared identifiers
/// rather than keywords, so a program may give any of them another meaning.
/// Lowering may read the builtin meaning only where it has not.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PredeclaredShadowing {
    new: bool,
    panic: bool,
    boolean_true: bool,
    boolean_false: bool,
}

impl PredeclaredShadowing {
    /// Every tracked identifier at once, for a context whose enclosing
    /// bindings this lowerer does not enumerate.
    const ALL: Self = Self {
        new: true,
        panic: true,
        boolean_true: true,
        boolean_false: true,
    };

    fn observe(&mut self, name: &str) {
        match name {
            "new" => self.new = true,
            "panic" => self.panic = true,
            "true" => self.boolean_true = true,
            "false" => self.boolean_false = true,
            _ => {}
        }
    }

    fn merged(self, other: Self) -> Self {
        Self {
            new: self.new || other.new,
            panic: self.panic || other.panic,
            boolean_true: self.boolean_true || other.boolean_true,
            boolean_false: self.boolean_false || other.boolean_false,
        }
    }

    fn shadows(self, name: &str) -> bool {
        match name {
            "new" => self.new,
            "panic" => self.panic,
            "true" => self.boolean_true,
            "false" => self.boolean_false,
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
}

struct GoProcedureInventory<'tree> {
    specs: Vec<ProcedureSpec<'tree>>,
    package_shadowing: PredeclaredShadowing,
}

type ProcedureEnumeration<'tree> = ProcedureInventoryOutcome<GoProcedureInventory<'tree>>;

struct ProcedureEnumerationFrame<'tree> {
    node: Node<'tree>,
    lexical_parent: Option<ProcedureId>,
    declaration_path: usize,
    package_binding_context: bool,
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
    let mut stack = vec![ProcedureEnumerationFrame {
        node: root,
        lexical_parent: None,
        declaration_path: inventory.root_path(),
        package_binding_context: false,
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
            && frame.node.kind() == "identifier"
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
            stack.push(ProcedureEnumerationFrame {
                node: child,
                lexical_parent,
                declaration_path,
                package_binding_context,
                named_result_owner,
                entry_precharged,
            });
        }
    }

    Ok(inventory.complete(GoProcedureInventory {
        specs,
        package_shadowing,
    }))
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
    if matches!(node.kind(), "identifier" | "field_identifier") {
        return Some(node);
    }
    let children = named_children(node);
    (children.len() == 1 && matches!(children[0].kind(), "identifier" | "field_identifier"))
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

#[derive(Debug, Clone, Copy)]
enum Work<'tree> {
    Statement {
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
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
}

struct LoweringContext<'tree, 'targets> {
    prepared: &'tree PreparedSyntaxTree,
    session: ProcedureLoweringSession<'targets>,
    expression_values: HashMap<usize, ValueId>,
    parameters: HashMap<Box<str>, ValueId>,
    locals: HashMap<Box<str>, Vec<LocalBinding>>,
    value_types: HashMap<ValueId, GoTypeIdentity>,
    /// Every `(struct type, field)` declaration this file states, shared by
    /// every procedure lowered from it.
    struct_field_anchors: &'tree HashMap<(Box<str>, Box<str>), Option<SourceAnchor>>,
    /// The fallback memory-location identity for a field whose declaration
    /// this file does not state, interned once per name per procedure so a
    /// store and a load of the same name still meet.
    field_locators: HashMap<Box<str>, SemanticLocator>,
    /// One value per distinct constant index text, so `values[0]` written and
    /// `values[0]` read name the same index value.
    constant_index_values: HashMap<Box<str>, ValueId>,
    receiver: Option<ValueId>,
    return_shape_supported: bool,
    predeclared_shadowed: PredeclaredShadowing,
}

#[derive(Debug, Clone)]
struct LocalBinding {
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
}

fn lower_procedure<'tree>(
    prepared: &'tree PreparedSyntaxTree,
    struct_field_anchors: &'tree HashMap<(Box<str>, Box<str>), Option<SourceAnchor>>,
    spec: &ProcedureSpec<'tree>,
    package_shadowing: PredeclaredShadowing,
    budget: &SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<(ProcedureSemanticsParts, SemanticWork), GoLoweringError> {
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
        session,
        expression_values: HashMap::default(),
        parameters: HashMap::default(),
        locals: HashMap::default(),
        value_types: HashMap::default(),
        struct_field_anchors,
        field_locators: HashMap::default(),
        constant_index_values: HashMap::default(),
        receiver: None,
        return_shape_supported: spec
            .callable
            .child_by_field_name("result")
            .is_some_and(|result| result.kind() != "parameter_list"),
        // A nested literal sees enclosing bindings this lowerer does not
        // enumerate, so no predeclared meaning can be assumed inside one.
        predeclared_shadowed: if spec.lexical_parent.is_some() {
            PredeclaredShadowing::ALL
        } else {
            package_shadowing.merged(spec.result_shadowing)
        },
    };
    context.emit_procedure_inputs(&mut builder, spec.callable)?;
    context.emit_local_bindings(&mut builder, spec.body)?;

    if spec.lexical_parent.is_some() {
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
        next: EdgeTarget::normal(normal_exit),
        scope: function_scope,
        label: None,
    };
    let mut pending = vec![body_work];
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

impl<'tree, 'targets> LoweringContext<'tree, 'targets> {
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
                    },
                )?;
                ordinal = ordinal.checked_add(1).ok_or_else(|| {
                    GoLoweringError::Invalid("too many Go formal parameters".into())
                })?;
                value
            };
            if let Some(type_node) = declaration.child_by_field_name("type")
                && let Some(identity) = go_type_identity(type_node, self.prepared.source())
            {
                self.value_types.insert(value, identity);
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
                "var_spec" => self.preindex_var_spec(builder, node)?,
                "short_var_declaration" => self.preindex_short_declaration(builder, node)?,
                "range_clause" if direct_child_kind(node, ":=") => {
                    self.preindex_range_declaration(builder, node)?;
                }
                _ => {}
            }
            Ok(WalkControl::Continue)
        })
    }

    fn preindex_var_spec(
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
            .and_then(|node| go_type_identity(node, self.prepared.source()));
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
            self.preindex_local(builder, name, spec, declared_type.clone().or(inferred_type))?;
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
            if name.kind() != "identifier" {
                continue;
            }
            let inferred_type = (names_len_matches_values(left, right))
                .then(|| {
                    values.get(index).and_then(|value| {
                        self.expression_type_identity(*value, declaration.start_byte())
                    })
                })
                .flatten();
            self.preindex_local(builder, name, declaration, inferred_type)?;
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
            if name.kind() == "identifier" {
                self.preindex_local(builder, name, declaration, None)?;
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
            && self
                .local_in_exact_scope(name, declaration.start_byte(), scope_start, scope_end)
                .is_some()
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
        self.locals
            .entry(name.into())
            .or_default()
            .push(LocalBinding {
                declaration_start: name_node.start_byte(),
                visible_from: declaration.end_byte(),
                scope_start,
                scope_end,
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
                    binding.scope_end - binding.scope_start,
                    std::cmp::Reverse(binding.visible_from),
                )
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
        self.locals.get(name)?.iter().find_map(|binding| {
            (binding.visible_from <= byte
                && binding.scope_start == scope_start
                && binding.scope_end == scope_end)
                .then_some(binding.value)
        })
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
        {
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

    fn expression_type_identity(&self, node: Node<'tree>, byte: usize) -> Option<GoTypeIdentity> {
        match node.kind() {
            "identifier" => {
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
            "composite_literal" => {
                go_type_identity(node.child_by_field_name("type")?, self.prepared.source())
            }
            "call_expression" if self.is_builtin_new_call(node) => {
                let argument = all_call_arguments(node).into_iter().next()?;
                let mut identity = go_type_identity(argument, self.prepared.source())?;
                identity.pointer_depth = identity.pointer_depth.checked_add(1)?;
                Some(identity)
            }
            _ => None,
        }
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
            self.struct_field_anchors
                .get(&(identity.name, name.into()))
                .copied()
                .flatten()
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

    /// The index value of `operand[index]`, when the index is a constant.
    ///
    /// A store and a load meet on an exact index only when both name the same
    /// value, so one value is interned per distinct index text. A non-constant
    /// index has no proven identity here and yields `None`, which the caller
    /// turns into an `Any` index plus an index-memory gap.
    fn index_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<Option<ValueId>, GoLoweringError> {
        if !matches!(expression_value_kind(node), SemanticValueKind::Constant) {
            return Ok(None);
        }
        let Some(text) = node_text(self.prepared.source(), node) else {
            return Ok(None);
        };
        if let Some(value) = self.constant_index_values.get(text) {
            let value = *value;
            self.expression_values.insert(node.id(), value);
            return Ok(Some(value));
        }
        let value = self.expression_value(builder, node, SemanticValueKind::Constant)?;
        self.constant_index_values.insert(text.into(), value);
        Ok(Some(value))
    }

    fn add_dynamic_index_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        location: MemoryLocationId,
    ) -> Result<(), GoLoweringError> {
        self.session.add_gap_with_impacts(
            builder,
            point,
            SemanticGapSubject::MemoryLocation(location),
            SemanticCapability::IndexMemory,
            SemanticGapImpacts::single(SemanticGapImpact::HeapRead)
                .with(SemanticGapImpact::HeapWrite)
                .with(SemanticGapImpact::Aliasing),
            SemanticGapKind::Unsupported,
            "Go dynamic index identity is not proven",
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
        if node
            .parent()
            .is_some_and(|parent| field_matches(parent, "function", node))
        {
            return true;
        }
        let Some(operand) = node.child_by_field_name("operand") else {
            return true;
        };
        if operand.kind() != "identifier" {
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
            return Ok(());
        };
        let kind = if Some(source) == self.receiver {
            ValueFlowKind::Receiver
        } else if self.local_at(name, node.start_byte()) == Some(source) {
            ValueFlowKind::Local
        } else {
            ValueFlowKind::Parameter
        };
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
                // The condition's own value is the one thing an unnormalized
                // guard can honestly name: the decision tested it, whatever it
                // means.
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
        (!self.predeclared_shadowed.shadows(name)
            && self.binding_value(name, node.start_byte()).is_none())
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

    #[allow(clippy::too_many_arguments)]
    fn statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
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
                self.abrupt(builder, entry, scope, completion, label)
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
                self.for_statement(builder, node, entry, next, scope, attached_label, stack)
            }
            "expression_switch_statement" | "type_switch_statement" => {
                self.switch_boundary(builder, node, entry, scope, stack)
            }
            "select_statement" => self.select_boundary(builder, node, entry, scope, stack),
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
                    "switch fallthrough transfer is not lowered"
                },
            ),
            "send_statement" | "receive_statement" => {
                self.communication_statement(builder, node, entry, next, scope, stack)
            }
            "assignment_statement" | "short_var_declaration" => {
                self.assignment_statement(builder, node, entry, next, scope, stack)
            }
            "inc_statement" | "dec_statement" => {
                self.increment_statement(builder, node, entry, next, scope, stack)
            }
            "var_declaration" => self.var_declaration(builder, node, entry, next, scope, stack),
            "const_declaration"
            | "type_declaration"
            | "function_declaration"
            | "method_declaration"
            | "empty_statement" => self.edge(builder, entry, next),
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
        let value = (!values.is_empty())
            .then(|| self.value(builder, terminal, SemanticValueKind::Return))
            .transpose()?;
        if let ([source_node], Some(target)) = (values.as_slice(), value) {
            let source =
                self.expression_value(builder, *source_node, expression_value_kind(*source_node))?;
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
            self.add_gap(
                builder,
                terminal,
                SemanticGapSubject::Point,
                SemanticCapability::ReturnFlow,
                SemanticGapKind::Unsupported,
                "Go tuple and multi-result return flow is not yet lowered",
            )?;
        }
        self.append_effect(builder, terminal, SemanticEffect::ProcedureReturn { value })?;
        self.abrupt(builder, terminal, scope, CompletionKind::Return, None)?;
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
        // Only an indexed or indirect operand can panic. A plain name cannot,
        // so the old blanket gap was reporting an impossible abrupt exit on
        // every loop counter in the language.
        if binding_requires_runtime_protocol(operand) {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unknown,
                "increment or decrement may panic through indexed or indirect operands",
            )?;
        }
        let binding = (operand.kind() == "identifier")
            .then(|| node_text(self.prepared.source(), operand))
            .flatten()
            .and_then(|name| Some((name, self.binding_value(name, node.start_byte())?)));
        let Some((name, target)) = binding else {
            return self.schedule_expressions(builder, entry, &expressions, next, scope, stack);
        };

        let boundary = self.point(builder, node, Vec::new())?;
        let old = self.expression_value(builder, operand, expression_value_kind(operand))?;
        let computed = self.source_value(builder, node, SemanticValueKind::Temporary)?;
        if let Some(identity) = self.value_types.get(&target).cloned() {
            self.value_types.insert(computed, identity);
        }
        self.session
            .append_language_defined_value_flows(builder, boundary, [old], computed)?;
        self.append_effect(
            builder,
            boundary,
            SemanticEffect::Assignment {
                target,
                value: computed,
            },
        )?;
        let kind = self.binding_flow_kind(name, target, node.end_byte());
        self.append_effect(
            builder,
            boundary,
            SemanticEffect::ValueFlow {
                kind,
                source: computed,
                target,
            },
        )?;
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
        let mut evaluations = assignment_evaluation_nodes(node);
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
            && left_items[0].kind() == "identifier";
        let compound_target = (!operator_is_simple
            && node.kind() == "assignment_statement"
            && left_items.len() == 1
            && right_items.len() == 1
            && left_items[0].kind() == "identifier")
            .then(|| {
                let name = node_text(self.prepared.source(), left_items[0])?;
                Some((name, self.binding_value(name, node.start_byte())?))
            })
            .flatten();
        // The single memory place this statement writes, when it writes one:
        // `holder.field = v` or `values[0] = v`, with any redundant
        // parentheses removed. A dereference target and a multi-target
        // assignment are not places this adapter lowers.
        let single_target = (operator_is_simple && left_items.len() == 1 && right_items.len() == 1)
            .then(|| unparenthesized(left_items[0]));
        let place_target = single_target.filter(|target| {
            target.child_by_field_name("operand").is_some()
                && match target.kind() {
                    "selector_expression" => !self.selector_denotes_no_location(*target),
                    "index_expression" => target
                        .child_by_field_name("index")
                        .is_some_and(|index| !is_go_type_syntax(index.kind())),
                    _ => false,
                }
        });
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
                        expression_value_kind(source_node),
                    )?;
                    let identity_preserving = node.kind() == "short_var_declaration"
                        && self.local_declaration_value(name, name_node.start_byte())
                            == Some(target)
                        || self.value_types.get(&target).is_some_and(|target_type| {
                            self.expression_type_identity(source_node, node.start_byte())
                                .is_some_and(|source_type| source_type == *target_type)
                        });
                    // The write happens either way. What the structural type
                    // check decides is only whether the target keeps the
                    // source's identity, or merely derives from it: an
                    // implicit Go assignment conversion changes a value's type,
                    // never its data.
                    self.append_effect(
                        builder,
                        boundary,
                        SemanticEffect::Assignment { target, value },
                    )?;
                    if identity_preserving {
                        let kind = self.binding_flow_kind(name, target, node.end_byte());
                        self.append_effect(
                            builder,
                            boundary,
                            SemanticEffect::ValueFlow {
                                kind,
                                source: value,
                                target,
                            },
                        )?;
                    } else {
                        self.session.append_language_defined_value_flows(
                            builder,
                            boundary,
                            [value],
                            target,
                        )?;
                    }
                }
            }
        } else if let Some((name, target)) = compound_target {
            // A compound `x op= y` reads both operands, computes a value of the
            // target's own type, and writes it back into the target binding.
            let name_node = left_items[0];
            let source_node = right_items[0];
            evaluations.insert(0, name_node);
            let left_value =
                self.expression_value(builder, name_node, expression_value_kind(name_node))?;
            let right_value =
                self.expression_value(builder, source_node, expression_value_kind(source_node))?;
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
            self.append_effect(
                builder,
                boundary,
                SemanticEffect::Assignment {
                    target,
                    value: computed,
                },
            )?;
            let kind = self.binding_flow_kind(name, target, node.end_byte());
            self.append_effect(
                builder,
                boundary,
                SemanticEffect::ValueFlow {
                    kind,
                    source: computed,
                    target,
                },
            )?;
        } else if let Some(place) = place_target {
            // A single selector or index target is a real store into memory.
            // The target's own operand is still evaluated, but the target node
            // itself must not be scheduled as an expression: reading it would
            // publish a load of the location this statement writes.
            let source_node = right_items[0];
            let value =
                self.expression_value(builder, source_node, expression_value_kind(source_node))?;
            let operand = required_field(place, "operand")?;
            let base = self.expression_value(builder, operand, expression_value_kind(operand))?;
            evaluations = match place.kind() {
                "selector_expression" => {
                    let field = required_field(place, "field")?;
                    let (member, resolved) = self.memory_member_locator(operand, field)?;
                    let location = self.session.add_memory_location(
                        builder,
                        boundary,
                        MemoryLocationKind::Field { base, member },
                    )?;
                    if !resolved {
                        self.add_field_identity_gap(builder, boundary, location)?;
                    }
                    self.append_effect(
                        builder,
                        boundary,
                        SemanticEffect::MemoryStore {
                            kind: MemoryAccessKind::Field,
                            location,
                            value,
                        },
                    )?;
                    vec![operand, source_node]
                }
                _ => {
                    let index_node = required_field(place, "index")?;
                    let index = self.index_value(builder, index_node)?;
                    let location = self.session.add_memory_location(
                        builder,
                        boundary,
                        MemoryLocationKind::Index { base, index },
                    )?;
                    if index.is_none() {
                        self.add_dynamic_index_gap(builder, boundary, location)?;
                    }
                    self.append_effect(
                        builder,
                        boundary,
                        SemanticEffect::MemoryStore {
                            kind: MemoryAccessKind::Index,
                            location,
                            value,
                        },
                    )?;
                    vec![operand, index_node, source_node]
                }
            };
        } else if !left_items.is_empty() || !right_items.is_empty() {
            self.add_gap(
                builder,
                boundary,
                SemanticGapSubject::Point,
                SemanticCapability::Assignments,
                SemanticGapKind::Unsupported,
                if !operator_is_simple {
                    "Go compound assignment flow is not yet lowered"
                } else if deref_target {
                    "Go assignment through a pointer dereference target is not yet lowered"
                } else if single_target
                    .is_some_and(|target| target.kind() == "selector_expression")
                {
                    "Go assignment to a selector target whose operand names no value this procedure binds is not yet lowered"
                } else {
                    "Go tuple, multi-result, and multi-target assignment flow is not yet lowered"
                },
            )?;
        }
        if node.kind() == "assignment_statement"
            && node
                .child_by_field_name("left")
                .is_some_and(binding_requires_runtime_protocol)
        {
            if place_target.is_none() {
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
            // take is not lowered. That claim is `Unsupported` rather than
            // `Unknown` on purpose: it is the exact shape the shared
            // implicit-abort discharge closes when no handler or cleanup body
            // runs user code, and a missing edge can then only remove paths
            // from a may analysis (#1952).
            self.add_gap(
                builder,
                boundary,
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unsupported,
                "assignment target evaluation and update panics are not lowered",
            )?;
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
    fn var_declaration(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), GoLoweringError> {
        let initializers = declaration_initializers(node);
        if initializers.is_empty() {
            return self.edge(builder, entry, next);
        }
        let boundary = self.point(builder, node, Vec::new())?;
        let mut lowered_any = false;
        let mut unsupported = false;
        for spec in go_var_specs(node) {
            let names = children_by_field_name(spec, "name");
            let values = spec
                .child_by_field_name("value")
                .map(expression_sequence)
                .unwrap_or_default();
            if names.len() != 1 || values.len() != 1 {
                unsupported |= !values.is_empty();
                continue;
            }
            let name_node = names[0];
            let value_node = values[0];
            let Some(name) = node_text(self.prepared.source(), name_node) else {
                continue;
            };
            if name == "_" {
                continue;
            }
            let Some(target) = self.local_declaration_value(name, name_node.start_byte()) else {
                continue;
            };
            let value =
                self.expression_value(builder, value_node, expression_value_kind(value_node))?;
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
            self.append_effect(
                builder,
                boundary,
                SemanticEffect::Assignment { target, value },
            )?;
            if identity_preserving {
                self.append_effect(
                    builder,
                    boundary,
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Local,
                        source: value,
                        target,
                    },
                )?;
            } else {
                self.session.append_language_defined_value_flows(
                    builder,
                    boundary,
                    [value],
                    target,
                )?;
            }
            lowered_any = true;
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
        if !lowered_any && !unsupported {
            self.add_gap(
                builder,
                boundary,
                SemanticGapSubject::Point,
                SemanticCapability::Values,
                SemanticGapKind::Unknown,
                "Go var initialization bound no analyzable local target",
            )?;
        }
        self.edge(builder, boundary, next)?;
        self.note_deterministic_evaluation_order(builder, boundary, node, &initializers)?;
        self.schedule_expressions(
            builder,
            entry,
            &initializers,
            EdgeTarget::normal(boundary),
            scope,
            stack,
        )
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
        self.add_gap(
            builder,
            boundary,
            SemanticGapSubject::Point,
            SemanticCapability::NormalControlFlow,
            SemanticGapKind::Unknown,
            "channel communication may block and requires scheduler refinement",
        )?;
        self.add_gap(
            builder,
            boundary,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unknown,
            "send on a closed channel and communication-related panics are not lowered",
        )?;
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
    fn deferred_or_spawned_call(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), GoLoweringError> {
        let operand = first_runtime_named_child(node)
            .ok_or_else(|| missing_field(node, "call expression"))?;
        let evaluations = if operand.kind() == "call_expression" {
            call_operand_evaluations(operand, true)?
        } else {
            vec![operand]
        };
        let boundary = self.point(builder, node, Vec::new())?;
        if node.kind() == "defer_statement" {
            for (capability, kind, detail) in [
                (
                    SemanticCapability::DeferredExecution,
                    SemanticGapKind::Unsupported,
                    "deferred invocation timing and LIFO execution are not lowered",
                ),
                (
                    SemanticCapability::CleanupControlFlow,
                    SemanticGapKind::Unsupported,
                    "deferred calls on return and panic paths are not stitched into control flow",
                ),
                (
                    SemanticCapability::Calls,
                    SemanticGapKind::Unsupported,
                    "the deferred outer call is intentionally not emitted as an immediate invocation",
                ),
                (
                    SemanticCapability::ExceptionalControlFlow,
                    SemanticGapKind::Unknown,
                    "deferred invocation panic propagation is not lowered",
                ),
            ] {
                self.add_gap(
                    builder,
                    boundary,
                    SemanticGapSubject::Point,
                    capability,
                    kind,
                    detail,
                )?;
            }
        } else {
            self.add_gap(
                builder,
                boundary,
                SemanticGapSubject::Point,
                SemanticCapability::ConcurrentSpawn,
                SemanticGapKind::Unsupported,
                "goroutine creation, scheduling, lifetime, and join behavior are not lowered",
            )?;
            self.add_gap(
                builder,
                boundary,
                SemanticGapSubject::Point,
                SemanticCapability::Calls,
                SemanticGapKind::Unsupported,
                "the spawned outer call is intentionally not emitted as a synchronous invocation",
            )?;
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
    fn switch_boundary(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), GoLoweringError> {
        let boundary = self.point(builder, node, Vec::new())?;
        self.add_gap(
            builder,
            boundary,
            SemanticGapSubject::Point,
            SemanticCapability::NormalControlFlow,
            SemanticGapKind::Unsupported,
            if node.kind() == "type_switch_statement" {
                "type-switch matching, per-case bindings, and case control are not lowered"
            } else {
                "switch case matching, default selection, and fallthrough are not lowered"
            },
        )?;
        self.add_gap(
            builder,
            boundary,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unknown,
            "unmodeled switch case expressions may contain calls",
        )?;
        self.add_gap(
            builder,
            boundary,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unknown,
            "switch header and case evaluation panics are not fully lowered",
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
                    next: EdgeTarget::normal(value_entry),
                    scope,
                    label: None,
                });
                Ok(())
            }
            (Some(initializer), None) => {
                stack.push(Work::Statement {
                    node: initializer,
                    entry,
                    next: EdgeTarget::normal(boundary),
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
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), GoLoweringError> {
        let eager = select_eager_expressions(node);
        let boundary = self.point(builder, node, Vec::new())?;
        self.add_gap(
            builder,
            boundary,
            SemanticGapSubject::Point,
            SemanticCapability::NormalControlFlow,
            SemanticGapKind::Unsupported,
            "select readiness, pseudo-random case choice, blocking, and selected case body are not lowered",
        )?;
        self.add_gap(
            builder,
            boundary,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unsupported,
            "calls in selected receive-assignment targets and selected case bodies are not lowered",
        )?;
        self.add_gap(
            builder,
            boundary,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unknown,
            "selected send on a closed channel may panic",
        )?;
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
        next: EdgeTarget,
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
                point: alternative_entry.unwrap_or(next.point),
                kind: ControlEdgeKind::ConditionalFalse,
            },
            scope,
        });
        if let Some(initializer) = node.child_by_field_name("initializer") {
            stack.push(Work::Statement {
                node: initializer,
                entry,
                next: EdgeTarget::normal(condition_entry),
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
            },
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
            },
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
                },
                scope: loop_scope,
                label: None,
            });
        }
        stack.push(Work::Statement {
            node: body,
            entry: body_entry,
            next: update_entry.map(EdgeTarget::normal).unwrap_or(EdgeTarget {
                point: loop_head,
                kind: ControlEdgeKind::LoopBack,
            }),
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
                next: EdgeTarget::normal(loop_head),
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
        self.add_gap(
            builder,
            test,
            SemanticGapSubject::Point,
            SemanticCapability::NormalControlFlow,
            SemanticGapKind::Unknown,
            "range exhaustion and channel or iterator progress depend on the ranged value",
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
            },
            scope: loop_scope,
            label: None,
        });
        if let (Some(left), Some(binding_entry), Some(binding_boundary)) =
            (left, binding_entry, binding_boundary)
        {
            let binding_runtime = if direct_child_kind(clause, "=") {
                assignment_target_runtime_nodes(left)
            } else {
                Vec::new()
            };
            if binding_requires_runtime_protocol(left) {
                self.add_gap(
                    builder,
                    binding_boundary,
                    SemanticGapSubject::Point,
                    SemanticCapability::Calls,
                    SemanticGapKind::Unknown,
                    "range target unpacking, indexing, or indirection requires runtime refinement",
                )?;
                self.add_gap(
                    builder,
                    binding_boundary,
                    SemanticGapSubject::Point,
                    SemanticCapability::ExceptionalControlFlow,
                    SemanticGapKind::Unsupported,
                    "range target evaluation and assignment panics are not lowered",
                )?;
            }
            // Each plain-identifier target is written a fresh element derived
            // from the iterable on every iteration. The element value depends
            // on the iterable's value, so a `for x := range x` binder relates
            // to the outer `x` read as same-evaluation rather than serving it.
            let declares = direct_child_kind(clause, ":=");
            let iterable = self.expression_value(builder, right, expression_value_kind(right))?;
            for name_node in expression_sequence(left) {
                if name_node.kind() != "identifier" {
                    continue;
                }
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
                let element =
                    self.source_value(builder, name_node, SemanticValueKind::Temporary)?;
                self.session.append_language_defined_value_flows(
                    builder,
                    binding_boundary,
                    [iterable],
                    element,
                )?;
                self.append_effect(
                    builder,
                    binding_boundary,
                    SemanticEffect::Assignment {
                        target,
                        value: element,
                    },
                )?;
                let kind = if Some(target) == self.receiver {
                    ValueFlowKind::Receiver
                } else if self
                    .local_at(name, body.start_byte())
                    .is_some_and(|local| local == target)
                {
                    ValueFlowKind::Local
                } else {
                    ValueFlowKind::Parameter
                };
                self.append_effect(
                    builder,
                    binding_boundary,
                    SemanticEffect::ValueFlow {
                        kind,
                        source: element,
                        target,
                    },
                )?;
            }
            self.edge(builder, binding_boundary, EdgeTarget::normal(body_entry))?;
            self.note_deterministic_evaluation_order(
                builder,
                binding_boundary,
                clause,
                &binding_runtime,
            )?;
            self.schedule_expressions(
                builder,
                binding_entry,
                &binding_runtime,
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
        let result = self.expression_value(builder, node, expression_value_kind(node))?;
        if node.kind() == "identifier" {
            self.emit_lexical_input_flow(builder, node, entry, result)?;
        }
        match node.kind() {
            "call_expression" if self.is_builtin_new_call(node) => {
                self.session
                    .add_allocation(builder, entry, result, AllocationKind::Object)?;
                self.edge(builder, entry, next)
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
                    self.expression_value(builder, argument, expression_value_kind(argument))?;
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
                self.abrupt(builder, terminal, scope, CompletionKind::Throw, None)?;
                self.schedule_expressions(
                    builder,
                    entry,
                    &[argument],
                    EdgeTarget::normal(terminal),
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
                        self.expression_value(builder, child, expression_value_kind(child))
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
            "unary_expression" if unary_operator_kind(node) == Some("<-") => {
                let operand = required_field(node, "operand")?;
                let boundary = self.point(builder, node, Vec::new())?;
                self.add_gap(
                    builder,
                    boundary,
                    SemanticGapSubject::Point,
                    SemanticCapability::NormalControlFlow,
                    SemanticGapKind::Unknown,
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
                let source =
                    self.expression_value(builder, operand, expression_value_kind(operand))?;
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
                    node: operand,
                    entry,
                    next: EdgeTarget::normal(terminal),
                    scope,
                });
                Ok(())
            }
            "selector_expression"
                if !self.selector_denotes_no_location(node) && !is_assignment_target(node) =>
            {
                let operand = required_field(node, "operand")?;
                let field = required_field(node, "field")?;
                let access = self.point(builder, node, Vec::new())?;
                let base =
                    self.expression_value(builder, operand, expression_value_kind(operand))?;
                let (member, resolved) = self.memory_member_locator(operand, field)?;
                let location = self.session.add_memory_location(
                    builder,
                    access,
                    MemoryLocationKind::Field { base, member },
                )?;
                if !resolved {
                    self.add_field_identity_gap(builder, access, location)?;
                }
                self.append_effect(
                    builder,
                    access,
                    SemanticEffect::MemoryLoad {
                        kind: MemoryAccessKind::Field,
                        location,
                        result,
                    },
                )?;
                // The nil-operand abort edge is not lowered. Like every other
                // implicit abort this adapter publishes, it is `Unsupported`
                // on a `Point` subject, which is the shape the shared
                // discharge closes when no handler or cleanup body runs user
                // code (#1952).
                self.add_gap(
                    builder,
                    access,
                    SemanticGapSubject::Point,
                    SemanticCapability::ExceptionalControlFlow,
                    SemanticGapKind::Unsupported,
                    "selection may panic on a nil operand",
                )?;
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
                let base =
                    self.expression_value(builder, operand, expression_value_kind(operand))?;
                let index = self.index_value(builder, index_node)?;
                let location = self.session.add_memory_location(
                    builder,
                    access,
                    MemoryLocationKind::Index { base, index },
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
                self.add_gap(
                    builder,
                    access,
                    SemanticGapSubject::Point,
                    SemanticCapability::ExceptionalControlFlow,
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
            "unary_expression" if unary_operator_kind(node) == Some("*") => {
                // A dereference reads the pointee. Its value is the pointee's
                // own, not a value derived from the pointer, which is the same
                // identity claim the `&` arm above makes in the other
                // direction.
                let operand = required_field(node, "operand")?;
                let terminal = self.point(builder, node, Vec::new())?;
                let source =
                    self.expression_value(builder, operand, expression_value_kind(operand))?;
                self.append_effect(
                    builder,
                    terminal,
                    SemanticEffect::Assignment {
                        target: result,
                        value: source,
                    },
                )?;
                self.add_gap(
                    builder,
                    terminal,
                    SemanticGapSubject::Point,
                    SemanticCapability::ExceptionalControlFlow,
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
                    self.expression_value(builder, operand, expression_value_kind(operand))?;
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
                // The failed-assertion abort edge is not lowered. Like every
                // other implicit abort this adapter publishes, it is
                // `Unsupported` on a `Point` subject, the shape the shared
                // discharge closes when no handler or cleanup body runs user
                // code (#1952).
                self.add_gap(
                    builder,
                    terminal,
                    SemanticGapSubject::Point,
                    SemanticCapability::ExceptionalControlFlow,
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
            "selector_expression" | "index_expression" | "slice_expression" => {
                let boundary = self.point(builder, node, Vec::new())?;
                self.add_gap(
                    builder,
                    boundary,
                    SemanticGapSubject::Point,
                    SemanticCapability::ExceptionalControlFlow,
                    SemanticGapKind::Unknown,
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
                        self.expression_value(builder, *child, expression_value_kind(*child))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                self.session
                    .append_language_defined_value_flows(builder, terminal, operands, result)?;
                if go_operation_can_panic(node) {
                    self.add_gap(
                        builder,
                        terminal,
                        SemanticGapSubject::Point,
                        SemanticCapability::ExceptionalControlFlow,
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
                    Some(
                        "array_type" | "implicit_length_array_type" | "slice_type" | "map_type",
                    ) => AllocationKind::Array,
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
        let invoke = self.point(builder, node, Vec::new())?;
        let normal = self.point(builder, node, Vec::new())?;
        let exceptional = self.point(builder, node, Vec::new())?;
        let function = required_field(node, "function")?;
        let callee = self.source_value(builder, function, SemanticValueKind::Callable)?;
        let result = self.expression_value(builder, node, SemanticValueKind::Temporary)?;
        let thrown = self.source_value(builder, function, SemanticValueKind::Exception)?;
        let receiver_node = go_call_receiver(function);
        let receiver = receiver_node
            .map(|receiver| {
                self.expression_value(builder, receiver, expression_value_kind(receiver))
            })
            .transpose()?;
        let callable_kind = if receiver.is_some() {
            CallableReferenceKind::BoundMethod
        } else {
            CallableReferenceKind::Function
        };
        let resolution = CallableTargetResolution::Unknown;
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
            .map(
                |argument| -> Result<SemanticCallArgument, GoLoweringError> {
                    let value_node = if argument.kind() == "variadic_argument" {
                        first_runtime_named_child(*argument).unwrap_or(*argument)
                    } else {
                        *argument
                    };
                    let value = self.expression_value(
                        builder,
                        value_node,
                        expression_value_kind(value_node),
                    )?;
                    Ok(if argument.kind() == "variadic_argument" {
                        SemanticCallArgument {
                            value,
                            expansion: CallArgumentExpansion::Spread(ArgumentDomain::Positional),
                        }
                    } else {
                        SemanticCallArgument::direct(value, ArgumentDomain::Positional)
                    })
                },
            )
            .collect::<Result<Vec<_>, _>>()?;
        let call_site = self.session.add_call_site(
            builder,
            CallSiteScaffold {
                point: invoke,
                callee,
                receiver,
                arguments: argument_values.into_boxed_slice(),
                result: Some(result),
                thrown: Some(thrown),
                declared_targets: resolution.clone(),
                normal_continuation: normal,
                exceptional_continuation: exceptional,
            },
        )?;
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

        if receiver.is_some() {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::DynamicDispatch,
                SemanticGapKind::Unknown,
                "selector dispatch may target an interface method or promoted method; receiver type and complete method-set coverage require type refinement",
            )?;
        }

        let evaluations = call_operand_evaluations(node, false)?;
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

    fn callable_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
    ) -> Result<(), GoLoweringError> {
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
            "function-literal target mapping requires location-first dispatch refinement",
        )?;
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
        let Some(detail) = go_evaluation_order_gap_detail(node, evaluations) else {
            return Ok(());
        };
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::Point,
            SemanticCapability::NormalControlFlow,
            SemanticGapKind::Unknown,
            detail,
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
            stack.push(Work::Statement {
                node: children[index],
                entry: entries[index],
                next: child_next,
                scope,
                label: None,
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
        self.route(builder, from, &route)
    }

    fn route(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        from: ProgramPointId,
        route: &CompletionRoute,
    ) -> Result<(), GoLoweringError> {
        if !route.cleanups().is_empty() {
            return Err(GoLoweringError::Invalid(
                "Go dynamic defer must not install lexical cleanup scopes".into(),
            ));
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

fn go_evaluation_order_gap_detail(
    node: Node<'_>,
    evaluations: &[Node<'_>],
) -> Option<&'static str> {
    let unspecified = match node.kind() {
        "composite_literal" => composite_literal_has_unspecified_order(node),
        "literal_value" => {
            node.parent()
                .is_none_or(|parent| parent.kind() != "composite_literal")
                && literal_value_has_unspecified_order(node)
        }
        // The containing literal_value or composite_literal owns this gap so
        // selectors have one precise source-backed boundary rather than one
        // duplicate per keyed element.
        "keyed_element" => false,
        _ => evaluation_units_have_unspecified_order(evaluations),
    };
    unspecified.then_some(
        if matches!(node.kind(), "composite_literal" | "literal_value") {
            "Go does not fully specify composite-literal operand and element evaluation order; deterministic CFG topology uses source order while preserving the specified lexical order of calls, receives, and logical operations"
        } else {
            "Go specifies lexical left-to-right order for calls, method calls, receives, and logical operations, but not all other operand evaluations; deterministic CFG topology uses source order for the unspecified remainder"
        },
    )
}

fn composite_literal_has_unspecified_order(node: Node<'_>) -> bool {
    node.child_by_field_name("body")
        .is_some_and(literal_value_has_unspecified_order)
}

fn literal_value_has_unspecified_order(node: Node<'_>) -> bool {
    let elements = named_children(node);
    evaluation_units_have_unspecified_order(&elements)
        || elements.into_iter().any(|element| {
            element.kind() == "keyed_element"
                && evaluation_units_have_unspecified_order(&runtime_expression_children(element))
        })
}

/// Whether the source order this lowerer chose could be observed.
///
/// Go leaves the evaluation order of most operands unspecified, but an
/// unspecified order is only observable when at least two units can call,
/// receive, or panic. Two pure reads happen in whichever order the
/// implementation picks and no program can tell, so reporting a gap there
/// buried the real cases -- and every ordinary call -- in noise.
fn evaluation_units_have_unspecified_order(evaluations: &[Node<'_>]) -> bool {
    let observable = evaluations
        .iter()
        .copied()
        .filter(|evaluation| go_evaluation_is_observable(*evaluation))
        .collect::<Vec<_>>();
    observable.len() > 1
        && observable
            .iter()
            .any(|evaluation| !go_spec_orders_evaluation(*evaluation))
}

/// Whether evaluating this unit can be observed by the rest of the program:
/// it calls, receives from a channel, or can panic.
///
/// The walk is iterative and does not descend into a nested function literal,
/// whose body runs where the literal is called rather than where it appears.
fn go_evaluation_is_observable(node: Node<'_>) -> bool {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        match current.kind() {
            "call_expression"
            | "index_expression"
            | "slice_expression"
            | "type_assertion_expression"
            | "selector_expression" => return true,
            "unary_expression" if unary_operator_kind(current) == Some("<-") => return true,
            "func_literal" => continue,
            _ => {}
        }
        if go_operation_can_panic(current) {
            return true;
        }
        stack.extend(named_children(current));
    }
    false
}

fn go_spec_orders_evaluation(mut node: Node<'_>) -> bool {
    loop {
        match node.kind() {
            "call_expression" => return true,
            "unary_expression" => return unary_operator_kind(node) == Some("<-"),
            "binary_expression" => return go_boolean_operator_kind(node).is_some(),
            "parenthesized_expression" | "literal_element" | "variadic_argument" => {
                let children = runtime_expression_children(node);
                let [only] = children.as_slice() else {
                    return false;
                };
                node = *only;
            }
            _ => return false,
        }
    }
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

fn assignment_target_runtime_nodes(target: Node<'_>) -> Vec<Node<'_>> {
    let mut result = Vec::new();
    let mut stack = vec![target];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "selector_expression" | "index_expression" => result.push(node),
            "unary_expression" if unary_operator_kind(node) == Some("*") => result.push(node),
            "identifier" | "field_identifier" => {}
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

fn binding_requires_runtime_protocol(binding: Node<'_>) -> bool {
    !assignment_target_runtime_nodes(binding).is_empty()
}

fn assignment_evaluation_nodes(node: Node<'_>) -> Vec<Node<'_>> {
    let mut result = Vec::new();
    if node.kind() == "assignment_statement"
        && let Some(left) = node.child_by_field_name("left")
    {
        result.extend(assignment_target_runtime_nodes(left));
    }
    if let Some(right) = node.child_by_field_name("right") {
        result.extend(expression_sequence(right));
    }
    result
}

fn declaration_initializers(node: Node<'_>) -> Vec<Node<'_>> {
    let mut result = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "var_spec" {
            if let Some(value) = current.child_by_field_name("value") {
                result.extend(expression_sequence(value));
            }
            continue;
        }
        let children = named_children(current);
        for child in children.into_iter().rev() {
            if !is_go_type_syntax(child.kind()) {
                stack.push(child);
            }
        }
    }
    result
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

fn call_operand_evaluations(
    call: Node<'_>,
    include_identifier_function: bool,
) -> Result<Vec<Node<'_>>, GoLoweringError> {
    let function = required_field(call, "function")?;
    let arguments = call_arguments(call);
    let mut result = Vec::with_capacity(arguments.len() + 1);
    if include_identifier_function || function.kind() != "identifier" {
        result.push(function);
    }
    result.extend(arguments);
    Ok(result)
}

fn call_arguments(node: Node<'_>) -> Vec<Node<'_>> {
    all_call_arguments(node)
        .into_iter()
        .filter(|argument| !is_go_type_syntax(argument.kind()))
        .collect()
}

fn all_call_arguments(node: Node<'_>) -> Vec<Node<'_>> {
    node.child_by_field_name("arguments")
        .map(named_children)
        .unwrap_or_default()
}

fn go_call_receiver(function: Node<'_>) -> Option<Node<'_>> {
    (function.kind() == "selector_expression")
        .then(|| function.child_by_field_name("operand"))
        .flatten()
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
    matches!(
        kind,
        "identifier"
            | "field_identifier"
            | "package_identifier"
            | "int_literal"
            | "float_literal"
            | "imaginary_literal"
            | "rune_literal"
            | "interpreted_string_literal"
            | "raw_string_literal"
            | "true"
            | "false"
            | "nil"
            | "iota"
            | "escape_sequence"
            | "comment"
    )
}

fn expression_value_kind(node: Node<'_>) -> SemanticValueKind {
    match node.kind() {
        "func_literal" => SemanticValueKind::Callable,
        "int_literal"
        | "float_literal"
        | "imaginary_literal"
        | "rune_literal"
        | "interpreted_string_literal"
        | "raw_string_literal"
        | "true"
        | "false"
        | "nil"
        | "iota" => SemanticValueKind::Constant,
        _ => SemanticValueKind::Temporary,
    }
}

/// Where each `(struct type, field)` pair of this file is declared.
///
/// A field's declaration is the identity a memory location names, so two
/// occurrences of `holder.Value` in one procedure -- and the store and the load
/// that must meet on it -- agree only when both anchor on the same declaration.
/// A name declared by more than one struct in the file collapses to `None`:
/// the occurrence alone no longer picks a declaration, so the location falls
/// back to the procedure-local name and publishes a field-identity gap. This
/// is Java's rule (`JavaDeclarationInventory`), restated for Go's syntax.
/// An embedded field declares no `field_identifier` and is skipped.
fn go_struct_field_anchors(
    prepared: &PreparedSyntaxTree,
) -> HashMap<(Box<str>, Box<str>), Option<SourceAnchor>> {
    let mut anchors: HashMap<(Box<str>, Box<str>), Option<SourceAnchor>> = HashMap::default();
    let mut stack = vec![prepared.tree().root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "type_spec"
            && let Some(declared) = node.child_by_field_name("type")
            && declared.kind() == "struct_type"
            && let Some(owner) = node
                .child_by_field_name("name")
                .and_then(|name| nonempty_node_text(prepared.source(), name))
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
                match anchors.entry((owner.into(), name.into())) {
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(Some(anchor));
                    }
                    std::collections::hash_map::Entry::Occupied(mut entry) => {
                        entry.insert(None);
                    }
                }
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
        if owns_header_declaration || node.kind() == "block" {
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
        "identifier" => node_text(source, node),
        "import_spec" => super::declarations::go_import_spec_binding_name(node, source),
        "function_declaration" | "type_spec" | "type_alias" => node
            .child_by_field_name("name")
            .and_then(|name| node_text(source, name)),
        _ => None,
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
