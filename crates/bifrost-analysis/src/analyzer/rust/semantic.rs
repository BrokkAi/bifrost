//! Rust lowering into the language-neutral executable-semantics IR.
//!
//! Tree-sitter nodes and fields describe Rust syntax here; graph mechanics,
//! abrupt-completion routing, and immutable adjacency storage stay in the
//! shared semantic substrate.

use tree_sitter::Node;

use crate::analyzer::lexical_definitions::formal_parameter_slots_for_owner;
use crate::analyzer::semantic::cfg::{
    CleanupRegionId, CompletionKind, CompletionRequest, CompletionRoute, ProcedureCfgBuilder,
    ScopeBinding, ScopeFrameId,
};
use crate::analyzer::semantic::lowering::formal_multiplicity;
use crate::analyzer::semantic::service::{ProgramSemanticsLowerer, SemanticAdapterIdentity};
use crate::analyzer::semantic::*;
use crate::analyzer::tree_sitter_analyzer::{
    PreparedSyntaxTree, WalkControl, try_walk_named_tree_preorder,
};
use crate::analyzer::{DispatchExtensibility, Language, ProjectFile, RustAnalyzer};
use crate::hash::{HashMap, HashSet};

const ADAPTER_VERSION: &[u8] = b"rust-value-semantics-v6";

impl_program_semantics_provider!(RustAnalyzer, RustSemanticLowerer);

struct RustSemanticLowerer;

impl ProgramSemanticsLowerer for RustSemanticLowerer {
    fn identity(&self) -> SemanticAdapterIdentity {
        SemanticAdapterIdentity {
            adapter: AdapterSemanticsVersion::hash_bytes("rust", ADAPTER_VERSION)
                .expect("adapter name is non-empty"),
            configuration: ConfigurationFingerprint::hash_bytes(
                b"rust-intrafile-execution-defaults-v1",
            ),
            dependencies: DependencyFingerprint::hash_bytes(b"no-intrafile-dependencies"),
        }
    }

    fn capabilities(&self) -> SemanticCapabilities {
        rust_capabilities()
    }

    fn lower(
        &self,
        file: &ProjectFile,
        prepared: &PreparedSyntaxTree,
        budget: &SemanticBudget,
        cancellation: &CancellationToken,
    ) -> Result<SemanticOutcome<Vec<ProcedureSemanticsParts>>, SemanticProviderError> {
        let (specs, initial_work) =
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

        // One file prescan, shared by every procedure: what this file states
        // about its own functions' return types, its struct declarations, and
        // which of those structs run no destructor.
        let facts = rust_file_facts(prepared);

        lower_procedure_batch(
            &specs,
            initial_work,
            budget,
            cancellation,
            |spec, staged_budget, cancellation| {
                lower_procedure(prepared, &facts, spec, staged_budget, cancellation)
            },
        )
    }
}

fn rust_capabilities() -> SemanticCapabilities {
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
        SemanticCapability::Captures,
        SemanticCapability::AsyncSuspendResume,
        SemanticCapability::GeneratorSuspension,
        SemanticCapability::DeferredExecution,
        SemanticCapability::NonLocalControl,
        SemanticCapability::ResourceManagement,
        // Partial: a field or element store and load is lowered into a real
        // memory row whenever the place is a single selector or a single
        // constant index over a value this procedure can name (#2667). A
        // dereference target, a destructuring target, a dynamic index, and a
        // field whose declaring struct this file does not state each publish
        // their own gap instead.
        SemanticCapability::FieldMemory,
        SemanticCapability::IndexMemory,
    ] {
        builder = builder.partial(capability);
    }
    // Partial: this adapter normalizes exactly one condition shape, a literal
    // `true` or `false`, and publishes nothing for any other decision. An
    // absent guard row therefore means "not normalized here", never "this
    // procedure has no decision" (#2443).
    builder = builder.partial(SemanticCapability::GuardFacts);
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

type ProcedureEnumeration<'tree> = ProcedureInventoryOutcome<Vec<ProcedureSpec<'tree>>>;

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
    let mut inventory =
        ProcedureInventoryBuilder::new(file, prepared.dialect(), root, "rust-source", budget)?;
    let mut specs = Vec::new();
    let mut stack = vec![ProcedureEnumerationFrame {
        node: root,
        lexical_parent: None,
        declaration_path: inventory.root_path(),
    }];

    while let Some(frame) = stack.pop() {
        if cancellation.is_cancelled() {
            return Ok(inventory.cancelled());
        }
        if let Err(stop) = inventory.charge_traversal_entry() {
            return Ok(stop.into_outcome());
        }
        let child_path = frame.declaration_path;
        let mut callable_body_scope = None;

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
                body,
                locator: identity.locator,
                lexical_parent: frame.lexical_parent,
                kind,
                properties,
                callable: frame.node,
            });
            callable_body_scope = Some((body.id(), identity.id, identity.declaration_path));
        }

        let children = named_children(frame.node);
        for child in children.into_iter().rev() {
            let (lexical_parent, declaration_path) = callable_body_scope
                .filter(|(body_id, _, _)| *body_id == child.id())
                .map(|(_, procedure, path)| (Some(procedure), path))
                .unwrap_or((frame.lexical_parent, child_path));
            stack.push(ProcedureEnumerationFrame {
                node: child,
                lexical_parent,
                declaration_path,
            });
        }
    }

    Ok(inventory.complete(specs))
}

fn callable_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    node.child_by_field_name("name")
        .and_then(|name| nonempty_node_text(source, name))
        .map(Box::<str>::from)
        .or_else(|| enclosing_let_name(source, node))
}

fn enclosing_let_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    let mut value = node;
    loop {
        let parent = value.parent()?;
        match parent.kind() {
            "parenthesized_expression" => value = parent,
            "let_declaration" if field_matches(parent, "value", value) => {
                return parent
                    .child_by_field_name("pattern")
                    .and_then(single_binding_identifier)
                    .and_then(|name| nonempty_node_text(source, name))
                    .map(Box::<str>::from);
            }
            _ => return None,
        }
    }
}

fn single_binding_identifier(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        match node.kind() {
            "identifier" => return Some(node),
            "mut_pattern" | "ref_pattern" | "captured_pattern" => {
                let children = named_children(node);
                if children.len() != 1 {
                    return None;
                }
                node = children[0];
            }
            _ => return None,
        }
    }
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
    let (kind, segment_kind, body, is_async, is_generator, is_static) = match node.kind() {
        "function_item" => {
            let is_method = lexical_parent.is_none() && has_impl_or_trait_parent(node);
            let (kind, segment_kind) = if lexical_parent.is_some() {
                (
                    ProcedureKind::LocalFunction,
                    DeclarationSegmentKind::LocalFunction,
                )
            } else if is_method {
                (ProcedureKind::Method, DeclarationSegmentKind::Method)
            } else {
                (ProcedureKind::Function, DeclarationSegmentKind::Function)
            };
            (
                kind,
                segment_kind,
                node.child_by_field_name("body")?,
                function_is_async(node),
                false,
                is_method && !function_has_self_parameter(node),
            )
        }
        "closure_expression" => (
            ProcedureKind::Closure,
            DeclarationSegmentKind::Closure,
            node.child_by_field_name("body")?,
            direct_child_kind(node, "async"),
            false,
            false,
        ),
        "async_block" => (
            ProcedureKind::Closure,
            DeclarationSegmentKind::AnonymousCallable,
            first_named_child(node)?,
            true,
            false,
            false,
        ),
        "gen_block" => (
            ProcedureKind::Closure,
            DeclarationSegmentKind::AnonymousCallable,
            first_named_child(node)?,
            false,
            true,
            false,
        ),
        _ => return None,
    };
    Some((
        kind,
        segment_kind,
        body,
        ProcedureProperties {
            is_async,
            is_generator,
            is_static,
            is_synthetic: false,
            invocation: if is_async || is_generator {
                ProcedureInvocationKind::Deferred
            } else {
                ProcedureInvocationKind::Immediate
            },
            dispatch_extensibility: rust_callable_dispatch_extensibility(node),
        },
    ))
}

fn rust_callable_dispatch_extensibility(node: Node<'_>) -> DispatchExtensibility {
    if node.kind() != "function_item" {
        return DispatchExtensibility::Closed;
    }
    let mut parent = node.parent();
    while let Some(candidate) = parent {
        match candidate.kind() {
            "trait_item" => return DispatchExtensibility::Open,
            "impl_item" => {
                return if candidate.child_by_field_name("trait").is_some() {
                    DispatchExtensibility::Open
                } else {
                    DispatchExtensibility::Closed
                };
            }
            "function_item" | "closure_expression" | "source_file" => break,
            _ => parent = candidate.parent(),
        }
    }
    DispatchExtensibility::Closed
}

fn has_impl_or_trait_parent(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        match parent.kind() {
            "impl_item" | "trait_item" => return true,
            "function_item" | "closure_expression" | "source_file" => return false,
            _ => node = parent,
        }
    }
    false
}

fn function_is_async(node: Node<'_>) -> bool {
    named_children(node)
        .into_iter()
        .find(|child| child.kind() == "function_modifiers")
        .is_some_and(|modifiers| direct_child_kind(modifiers, "async"))
}

fn function_has_self_parameter(node: Node<'_>) -> bool {
    node.child_by_field_name("parameters")
        .map(named_children)
        .is_some_and(|parameters| {
            parameters
                .into_iter()
                .any(|parameter| parameter.kind() == "self_parameter")
        })
}

fn field_matches(parent: Node<'_>, field: &str, child: Node<'_>) -> bool {
    parent
        .child_by_field_name(field)
        .is_some_and(|candidate| candidate.id() == child.id())
}

type RustLoweringError = ProcedureLoweringError;

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

struct LoweringContext<'tree, 'targets> {
    source: &'tree str,
    session: ProcedureLoweringSession<'targets>,
    expression_values: HashMap<usize, ValueId>,
    parameters: HashMap<Box<str>, ValueId>,
    locals: HashMap<Box<str>, Vec<LocalBinding>>,
    definitely_non_dropping: HashSet<ValueId>,
    /// What this file states about its own functions, structs, and destructors.
    facts: &'targets RustFileFacts,
    /// The struct or array shape each value provably holds, which is what lets
    /// a field or index place name a memory location this procedure owns.
    value_shapes: HashMap<ValueId, RustValueShape>,
    /// The fallback memory-location identity for a field whose declaring
    /// struct this file does not state, interned once per name per procedure
    /// so a store and a load of the same name still meet.
    field_locators: HashMap<Box<str>, SemanticLocator>,
    /// One value per distinct constant index text, so `values[0]` written and
    /// `values[0]` read name the same index value.
    constant_index_values: HashMap<Box<str>, ValueId>,
    parameter_cleanup_required: bool,
    receiver: Option<ValueId>,
    next_cleanup_region: usize,
}

/// The shape a value provably holds, as far as one file can state it.
///
/// Only two shapes matter to the heap stratum: a value of a struct this file
/// declares, whose field declarations then identify a `Field` location and
/// prove the projection needs no user `Deref`; and a fixed-size array, whose
/// subscript is the language's own indexing rather than an `Index`
/// implementation. Anything else has no shape here and keeps its gaps.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RustValueShape {
    Struct(Box<str>),
    Array { primitive_elements: bool },
}

#[derive(Debug, Clone, Copy)]
struct LocalBinding {
    declaration_start: usize,
    visible_from: usize,
    scope_start: usize,
    scope_end: usize,
    value: ValueId,
}

fn lower_procedure<'tree>(
    prepared: &'tree PreparedSyntaxTree,
    facts: &RustFileFacts,
    spec: &ProcedureSpec<'tree>,
    budget: &SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<(ProcedureSemanticsParts, SemanticWork), RustLoweringError> {
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
        source: prepared.source(),
        session,
        expression_values: HashMap::default(),
        parameters: HashMap::default(),
        locals: HashMap::default(),
        definitely_non_dropping: HashSet::default(),
        facts,
        value_shapes: HashMap::default(),
        field_locators: HashMap::default(),
        constant_index_values: HashMap::default(),
        parameter_cleanup_required: rust_parameters_may_require_drop(spec.callable),
        receiver: None,
        next_cleanup_region: 0,
    };
    context.emit_procedure_inputs(&mut builder, spec.callable)?;
    let body_scope = if context.parameter_cleanup_required {
        context.next_cleanup_region = 1;
        builder.push_scope(
            Some(function_scope),
            ScopeBinding::Cleanup {
                region: CleanupRegionId::new(0),
            },
        )
    } else {
        function_scope
    };
    context.emit_local_bindings(&mut builder, spec.body)?;

    if context.parameter_cleanup_required {
        context.add_drop_omission_gaps(
            &mut builder,
            normal_exit,
            "parameter values may require implicit Drop at normal procedure exit",
        )?;
        context.add_drop_omission_gaps(
            &mut builder,
            exceptional_exit,
            "parameter values may require implicit Drop while unwinding from the procedure",
        )?;
    }

    if spec.properties.is_async {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::DeferredExecution,
            SemanticGapKind::Unsupported,
            "invoking this async Rust callable creates a deferred future; polling and executor scheduling are not stitched into control flow",
        )?;
    }
    if spec.properties.is_generator {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::GeneratorSuspension,
            SemanticGapKind::Unsupported,
            "invoking this generator block creates deferred resumable state; construction and resumption are not stitched into control flow",
        )?;
    }

    let body_entry = context.point(&mut builder, spec.body, Vec::new())?;
    let return_source = if spec.body.kind() == "block" {
        block_tail_expression(spec.body)
    } else {
        Some(spec.body)
    };
    let body_next = if let Some(return_source) = return_source {
        let implicit_return = context.point(&mut builder, spec.body, Vec::new())?;
        let source = context.expression_value(
            &mut builder,
            return_source,
            expression_value_kind(return_source),
        )?;
        let return_value =
            context.value(&mut builder, implicit_return, SemanticValueKind::Return)?;
        context.append_effect(
            &mut builder,
            implicit_return,
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Return,
                source,
                target: return_value,
            },
        )?;
        if !rust_expression_has_direct_value_evidence(return_source) {
            context.add_gap(
                &mut builder,
                implicit_return,
                SemanticGapSubject::Value(return_value),
                SemanticCapability::Values,
                SemanticGapKind::Unknown,
                "tail-expression result transfer requires value refinement",
            )?;
        }
        context.append_effect(
            &mut builder,
            implicit_return,
            SemanticEffect::ProcedureReturn {
                value: Some(return_value),
            },
        )?;
        context.edge(
            &mut builder,
            implicit_return,
            EdgeTarget::normal(normal_exit),
        )?;
        EdgeTarget::normal(implicit_return)
    } else {
        EdgeTarget::normal(normal_exit)
    };
    let initial = if spec.body.kind() == "block" {
        Work::Statement {
            node: spec.body,
            entry: body_entry,
            next: body_next,
            scope: body_scope,
        }
    } else {
        Work::Expression {
            node: spec.body,
            entry: body_entry,
            next: body_next,
            scope: body_scope,
        }
    };
    let mut pending = vec![initial];
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
    ) -> Result<(), RustLoweringError> {
        let layout = formal_parameter_slots_for_owner(Language::Rust, callable, self.source)
            .unwrap_or_default();
        let mut ordinal = 0_u32;
        for slot in layout.slots {
            if self.session.cancellation().is_cancelled() {
                return Err(RustLoweringError::Cancelled(Box::new(
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
                ordinal = ordinal
                    .checked_add(1)
                    .ok_or_else(|| RustLoweringError::Invalid("too many parameters".into()))?;
                value
            };
            if rust_parameter_is_definitely_non_dropping(node) {
                self.definitely_non_dropping.insert(value);
            }
            // The declared parameter type states the shape directly. A
            // receiver declares none, so it takes the shape of the type its
            // enclosing `impl` block names.
            let declared_shape = if slot.receiver {
                rust_impl_self_type(callable)
                    .and_then(|ty| rust_declared_type_shape(self.source, ty))
            } else {
                node.child_by_field_name("type")
                    .and_then(|ty| rust_declared_type_shape(self.source, ty))
            };
            if let Some(shape) = declared_shape {
                self.value_shapes.insert(value, shape);
            }
            for name in slot.names {
                self.parameters.insert(name.into_boxed_str(), value);
            }
        }
        if let Some(receiver) = self.receiver {
            self.parameters.insert("self".into(), receiver);
        }
        Ok(())
    }

    fn emit_local_bindings(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        body: Node<'tree>,
    ) -> Result<(), RustLoweringError> {
        try_walk_named_tree_preorder(body, true, |node| {
            if self.session.cancellation().is_cancelled() {
                return Err(RustLoweringError::Cancelled(Box::new(
                    builder.prospective_work(),
                )));
            }
            if node.id() != body.id() && is_rust_nested_execution_boundary(node) {
                return Ok(WalkControl::SkipChildren);
            }
            if node.kind() == "let_declaration"
                && let Some(pattern) = node.child_by_field_name("pattern")
                && let Some(name) = identity_binding_identifier(pattern)
                && let Some(text) = node_text(self.source, name)
                && let Some((scope_start, scope_end)) = rust_local_scope(node)
            {
                let metadata = self.value_mapping(builder, name)?;
                let value = self.session.add_value_with_metadata(
                    builder,
                    metadata,
                    SemanticValueKind::Local,
                )?;
                self.locals
                    .entry(text.into())
                    .or_default()
                    .push(LocalBinding {
                        declaration_start: name.start_byte(),
                        visible_from: node.end_byte(),
                        scope_start,
                        scope_end,
                        value,
                    });
                // The declared type states the shape when there is one;
                // otherwise the initializer does. The walk is preorder, so a
                // local this initializer names was already classified, which
                // is what lets `let alias = &original;` take `original`'s own
                // struct shape.
                if let Some(shape) = node
                    .child_by_field_name("type")
                    .and_then(|ty| rust_declared_type_shape(self.source, ty))
                    .or_else(|| {
                        node.child_by_field_name("value")
                            .and_then(|initializer| self.expression_shape(initializer))
                    })
                {
                    self.value_shapes.insert(value, shape);
                }
                // An explicit primitive annotation decides the question on its
                // own; otherwise the initializer has to prove it. The walk is
                // preorder, so a local this initializer names was already
                // classified.
                if node
                    .child_by_field_name("type")
                    .is_some_and(|ty| ty.kind() == "primitive_type")
                    || node
                        .child_by_field_name("value")
                        .is_some_and(|initializer| {
                            self.expression_is_definitely_non_dropping(initializer)
                        })
                {
                    self.definitely_non_dropping.insert(value);
                }
            }
            // A `for` pattern binds a local too. Without it the loop variable
            // resolved to nothing inside the body, so an element read there
            // began a fresh unrelated value.
            if node.kind() == "for_expression"
                && let Some(pattern) = node.child_by_field_name("pattern")
                && let Some(name) = identity_binding_identifier(pattern)
                && let Some(text) = node_text(self.source, name)
                && let Some(body) = node.child_by_field_name("body")
            {
                let metadata = self.value_mapping(builder, name)?;
                let value = self.session.add_value_with_metadata(
                    builder,
                    metadata,
                    SemanticValueKind::Local,
                )?;
                self.locals
                    .entry(text.into())
                    .or_default()
                    .push(LocalBinding {
                        declaration_start: name.start_byte(),
                        visible_from: body.start_byte(),
                        scope_start: body.start_byte(),
                        scope_end: body.end_byte(),
                        value,
                    });
                if node
                    .child_by_field_name("value")
                    .is_some_and(rust_iteration_element_is_definitely_non_dropping)
                {
                    self.definitely_non_dropping.insert(value);
                }
            }
            Ok(WalkControl::Continue)
        })
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
                    std::cmp::Reverse(binding.declaration_start),
                )
            })
            .map(|binding| binding.value)
    }

    fn local_declaration_value(&self, name: &str, declaration_start: usize) -> Option<ValueId> {
        self.locals
            .get(name)?
            .iter()
            .find(|binding| binding.declaration_start == declaration_start)
            .map(|binding| binding.value)
    }

    /// The shape this expression's value provably holds.
    ///
    /// A reference is transparent on purpose: Rust auto-dereferences a
    /// reference to a struct, so `holder.value` and `alias.value` project the
    /// same field of the same struct type, and `&` is the language's own
    /// borrow rather than a user `Deref` implementation.
    fn expression_shape(&self, node: Node<'_>) -> Option<RustValueShape> {
        // A borrow, a parenthesis chain, and an access path are all unbounded
        // in source, so the walk down to the root is a loop and the selectors
        // it collected are applied afterwards rather than by recursion.
        let mut selectors = Vec::new();
        let mut current = node;
        let root = loop {
            match current.kind() {
                "identifier" | "self" => {
                    let name = node_text(self.source, current)?;
                    let value = self
                        .local_at(name, current.start_byte())
                        .or_else(|| self.parameters.get(name).copied())?;
                    break self.value_shapes.get(&value).cloned()?;
                }
                "parenthesized_expression" | "reference_expression" => {
                    current = first_named_child(current)?;
                }
                "field_expression" => {
                    selectors.push(node_text(
                        self.source,
                        current.child_by_field_name("field")?,
                    )?);
                    current = current.child_by_field_name("value")?;
                }
                "struct_expression" => {
                    break rust_declared_type_shape(
                        self.source,
                        current.child_by_field_name("name")?,
                    )?;
                }
                "array_expression" => {
                    break RustValueShape::Array {
                        primitive_elements: runtime_expression_children(current)
                            .into_iter()
                            .all(|element| self.expression_is_definitely_non_dropping(element)),
                    };
                }
                _ => return None,
            }
        };
        let mut shape = root;
        for selector in selectors.into_iter().rev() {
            let RustValueShape::Struct(owner) = shape else {
                return None;
            };
            shape = self
                .facts
                .struct_fields
                .get(&(owner, selector.into()))?
                .as_ref()?
                .shape
                .clone()?;
        }
        Some(shape)
    }

    /// What this file declares about the field `base.field` names, when the
    /// base's shape picks exactly one struct declaration.
    fn field_declaration(&self, base: Node<'_>, field: Node<'_>) -> Option<RustFieldDeclaration> {
        let RustValueShape::Struct(name) = self.expression_shape(base)? else {
            return None;
        };
        let field = node_text(self.source, field)?;
        self.facts
            .struct_fields
            .get(&(name, field.into()))
            .cloned()
            .flatten()
    }

    /// Whether a field expression denotes no runtime memory location.
    ///
    /// One shape reads like a field access but is not one: a method call's
    /// callee (`receiver.method(...)`), whose selection the call site already
    /// models. Minting a `Field` location for it would publish an
    /// undischargeable field-memory gap on syntax that holds nothing.
    fn field_denotes_no_location(&self, node: Node<'tree>) -> bool {
        let mut current = node;
        while let Some(parent) = current.parent() {
            match parent.kind() {
                "generic_function" => current = parent,
                "call_expression" => return field_matches(parent, "function", current),
                _ => return false,
            }
        }
        false
    }

    /// Whether reading or writing this place runs only the language's own
    /// projection.
    ///
    /// A field of a struct this file declares is a direct projection: no
    /// autoderef step past a user `Deref`, and no `DerefMut` on the write
    /// side. A subscript of a fixed-size array is the language's own indexing,
    /// not an `Index` or `IndexMut` implementation. Any other place keeps the
    /// `Calls` gap that says an implicit trait method may run here.
    fn place_access_is_language_defined(&self, place: Node<'_>) -> bool {
        match place.kind() {
            "field_expression" => place
                .child_by_field_name("value")
                .zip(place.child_by_field_name("field"))
                .and_then(|(base, field)| self.field_declaration(base, field))
                .is_some(),
            "index_expression" => {
                let children = runtime_expression_children(place);
                let [base, _] = children.as_slice() else {
                    return false;
                };
                matches!(
                    self.expression_shape(*base),
                    Some(RustValueShape::Array { .. })
                )
            }
            _ => false,
        }
    }

    /// The memory-location identity of `base.field`, and whether it is the
    /// field's own declaration.
    ///
    /// When this file does not state the declaration -- an unresolved base
    /// shape, an imported struct, a name two structs share -- the locator
    /// falls back to one interned per field name per procedure. That fallback
    /// still lets a store and a load of one name meet, which anchoring each
    /// occurrence separately would silently prevent, and the caller publishes
    /// a field-identity gap for it.
    fn memory_member_locator(
        &mut self,
        base: Node<'tree>,
        field: Node<'tree>,
    ) -> Result<(SemanticLocator, bool), RustLoweringError> {
        let name = node_text(self.source, field);
        let declaration = self.field_declaration(base, field);
        if let Some(name) = name
            && declaration.is_none()
            && let Some(locator) = self.field_locators.get(name)
        {
            return Ok((locator.clone(), false));
        }
        let anchor = match declaration {
            Some(ref declaration) => declaration.anchor,
            None => source_anchor(field, 0).map_err(RustLoweringError::Invalid)?,
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
        if declaration.is_none()
            && let Some(name) = name
        {
            self.field_locators.insert(name.into(), locator.clone());
        }
        Ok((locator, declaration.is_some()))
    }

    fn add_field_identity_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        location: MemoryLocationId,
    ) -> Result<(), RustLoweringError> {
        self.session.add_gap_with_impacts(
            builder,
            point,
            SemanticGapSubject::MemoryLocation(location),
            SemanticCapability::FieldMemory,
            SemanticGapImpacts::single(SemanticGapImpact::HeapRead)
                .with(SemanticGapImpact::HeapWrite)
                .with(SemanticGapImpact::Aliasing),
            SemanticGapKind::Unknown,
            "Rust field occurrence is structured, but its struct declaration identity is not yet resolved",
        )?;
        Ok(())
    }

    /// The index value of `base[index]`, when the index is a constant.
    ///
    /// A store and a load meet on an exact index only when both name the same
    /// value, so one value is interned per distinct index text. A non-constant
    /// index has no proven identity here and yields `None`, which the caller
    /// turns into an `Any` index plus an index-memory gap.
    fn index_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<Option<ValueId>, RustLoweringError> {
        if !matches!(expression_value_kind(node), SemanticValueKind::Constant) {
            return Ok(None);
        }
        let Some(text) = node_text(self.source, node) else {
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
    ) -> Result<(), RustLoweringError> {
        self.session.add_gap_with_impacts(
            builder,
            point,
            SemanticGapSubject::MemoryLocation(location),
            SemanticCapability::IndexMemory,
            SemanticGapImpacts::single(SemanticGapImpact::HeapRead)
                .with(SemanticGapImpact::HeapWrite)
                .with(SemanticGapImpact::Aliasing),
            SemanticGapKind::Unsupported,
            "Rust dynamic index identity is not proven",
        )?;
        Ok(())
    }

    /// Whether this expression names storage this procedure already holds,
    /// rather than producing a fresh temporary.
    ///
    /// An identifier qualifies only when it resolves to a local or a
    /// parameter. A bare path that names a unit struct or a constant --
    /// `Guard`, `None` -- is spelled the same way and produces a new value, so
    /// borrowing it does extend a temporary's lifetime.
    fn is_place(&self, node: Node<'_>) -> bool {
        let mut current = node;
        loop {
            match current.kind() {
                "identifier" | "self" => {
                    let Some(name) = node_text(self.source, current) else {
                        return false;
                    };
                    return self
                        .local_at(name, current.start_byte())
                        .or_else(|| self.parameters.get(name).copied())
                        .is_some();
                }
                "field_expression" => {
                    let Some(base) = current.child_by_field_name("value") else {
                        return false;
                    };
                    current = base;
                }
                "index_expression" | "parenthesized_expression" => {
                    let Some(inner) = first_named_child(current) else {
                        return false;
                    };
                    current = inner;
                }
                _ => return false,
            }
        }
    }

    /// Whether this expression's value provably owns no `Drop`.
    ///
    /// A literal, a binding already proven non-dropping, a borrow of a place,
    /// an operator applied to non-dropping operands, a cast to a primitive, a
    /// call to a same-file `fn` with a non-dropping return type, an array or
    /// struct literal whose parts are themselves proven, and a read of a
    /// primitive field or element all produce a value that runs no destructor.
    /// Anything else answers `false`, which keeps the drop-omission gaps.
    ///
    /// The walk is an explicit worklist rather than recursion: operator nesting
    /// in a source file is unbounded.
    fn expression_is_definitely_non_dropping(&self, node: Node<'_>) -> bool {
        let mut pending = vec![node];
        while let Some(node) = pending.pop() {
            if matches!(expression_value_kind(node), SemanticValueKind::Constant) {
                continue;
            }
            match node.kind() {
                "identifier" => {
                    let proven = node_text(self.source, node)
                        .and_then(|name| {
                            self.local_at(name, node.start_byte())
                                .or_else(|| self.parameters.get(name).copied())
                        })
                        .is_some_and(|value| self.definitely_non_dropping.contains(&value));
                    if !proven {
                        return false;
                    }
                }
                // Borrowing a place -- a local, a field, an element -- owns
                // nothing and extends nothing: the referent already lives as
                // long as whatever binds it, and its own binding answers the
                // drop question. Borrowing anything else produces a temporary
                // whose lifetime the borrow extends to the end of the
                // enclosing block, so `&Guard::new()` does run a `Drop` there
                // and keeps the gaps.
                "reference_expression" => {
                    if !first_named_child(node).is_some_and(|operand| self.is_place(operand)) {
                        return false;
                    }
                }
                "binary_expression" | "unary_expression" | "parenthesized_expression" => {
                    let operands = runtime_expression_children(node);
                    if operands.is_empty() {
                        return false;
                    }
                    pending.extend(operands);
                }
                "type_cast_expression" => {
                    if !node
                        .child_by_field_name("type")
                        .is_some_and(|ty| ty.kind() == "primitive_type")
                    {
                        return false;
                    }
                }
                // An array owns whatever its elements own and nothing else:
                // `[T; N]` has no user `Drop` implementation of its own.
                "array_expression" => {
                    pending.extend(runtime_expression_children(node));
                }
                // A struct literal of a struct this file proves plain: every
                // field is a primitive or another plain struct, and this file
                // states no `impl Drop` for it.
                "struct_expression" => {
                    let plain = node
                        .child_by_field_name("name")
                        .filter(|name| name.kind() == "type_identifier")
                        .and_then(|name| node_text(self.source, name))
                        .is_some_and(|name| self.facts.plain_structs.contains(name));
                    if !plain {
                        return false;
                    }
                    pending.extend(runtime_expression_children(node));
                }
                // The initializer list itself carries no value; what it holds
                // are the field values, and those decide.
                "field_initializer_list"
                | "field_initializer"
                | "shorthand_field_initializer"
                | "base_field_initializer" => {
                    pending.extend(runtime_expression_children(node));
                }
                // Reading a field or an element whose declared type is a
                // primitive produces a primitive.
                "field_expression" => {
                    let primitive = node
                        .child_by_field_name("value")
                        .zip(node.child_by_field_name("field"))
                        .and_then(|(base, field)| self.field_declaration(base, field))
                        .is_some_and(|declaration| declaration.primitive);
                    if !primitive {
                        return false;
                    }
                }
                "index_expression" => {
                    let children = runtime_expression_children(node);
                    let [base, _] = children.as_slice() else {
                        return false;
                    };
                    if !matches!(
                        self.expression_shape(*base),
                        Some(RustValueShape::Array {
                            primitive_elements: true
                        })
                    ) {
                        return false;
                    }
                }
                "call_expression" => {
                    let non_dropping_result = node
                        .child_by_field_name("function")
                        .filter(|function| function.kind() == "identifier")
                        .and_then(|function| node_text(self.source, function))
                        .and_then(|name| self.facts.non_dropping_return_functions.get(name))
                        .copied()
                        .unwrap_or(false);
                    if !non_dropping_result {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        true
    }

    /// Whether writing over this assignment target can run a destructor.
    ///
    /// Assignment drops the value it replaces. When the target is a binding
    /// this procedure already proved holds no `Drop`, or a field or element
    /// whose declared type is a primitive, nothing is dropped, and the
    /// drop-omission gaps would be claiming a cleanup that cannot happen. Any
    /// other target -- a dereference, a destructuring pattern, a name this
    /// procedure does not bind -- keeps them.
    fn assignment_replaces_droppable_value(&self, left: Node<'_>) -> bool {
        match left.kind() {
            "identifier" => {
                let Some(name) = node_text(self.source, left) else {
                    return true;
                };
                self.local_at(name, left.start_byte())
                    .or_else(|| self.parameters.get(name).copied())
                    .is_none_or(|target| !self.definitely_non_dropping.contains(&target))
            }
            // Overwriting a field or an element whose declared type is a
            // primitive drops nothing: a primitive is `Copy` and cannot
            // implement `Drop`.
            "field_expression" | "index_expression" => {
                !self.expression_is_definitely_non_dropping(left)
            }
            _ => true,
        }
    }

    fn let_declaration_may_require_drop(&self, node: Node<'_>) -> bool {
        let Some(pattern) = node.child_by_field_name("pattern") else {
            return true;
        };
        if is_wildcard_pattern(pattern) {
            return false;
        }
        let Some(name) = identity_binding_identifier(pattern) else {
            return true;
        };
        let Some(name_text) = node_text(self.source, name) else {
            return true;
        };
        self.local_declaration_value(name_text, name.start_byte())
            .is_none_or(|value| !self.definitely_non_dropping.contains(&value))
    }

    fn expression_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        kind: SemanticValueKind,
    ) -> Result<ValueId, RustLoweringError> {
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
    ) -> Result<ValueId, RustLoweringError> {
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
    ) -> Result<(), RustLoweringError> {
        let Some(name) = node_text(self.source, node) else {
            return Ok(());
        };
        let (source, kind) = if node.kind() == "self" {
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
    ) -> Result<(), RustLoweringError> {
        if self.session.cancellation().is_cancelled() {
            return Err(RustLoweringError::Cancelled(Box::default()));
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
    ) -> Result<(), RustLoweringError> {
        match (node.kind(), rust_boolean_operator(node)) {
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
            ("let_chain", _) => {
                let conditions = runtime_expression_children(node);
                self.schedule_condition_chain(
                    builder,
                    entry,
                    &conditions,
                    when_true,
                    when_false,
                    scope,
                    stack,
                )
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
                // A literal condition fixes its outcome at compile time. Both
                // arms stay represented -- the dead one still holds call sites
                // and declarations a consumer asks about -- and the guard row
                // is what tells a solver which of them cannot execute.
                if let Some(value) = rust_constant_condition(node) {
                    let arm = |target: EdgeTarget| {
                        Some(GuardArm {
                            target_point: target.point,
                            kind: target.kind,
                        })
                    };
                    self.session.add_guard_fact(
                        builder,
                        decision,
                        GuardPredicate::ConstantBoolean { value },
                        None,
                        arm(when_true),
                        arm(when_false),
                    )?;
                }
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

    #[allow(clippy::too_many_arguments)]
    fn schedule_condition_chain(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        conditions: &[Node<'tree>],
        when_true: EdgeTarget,
        when_false: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        if conditions.is_empty() {
            return self.edge(builder, entry, when_true);
        }
        let entries = conditions
            .iter()
            .map(|condition| self.point(builder, *condition, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        self.edge(builder, entry, EdgeTarget::normal(entries[0]))?;
        for index in (0..conditions.len()).rev() {
            let success = entries
                .get(index + 1)
                .copied()
                .map(|point| EdgeTarget {
                    point,
                    kind: ControlEdgeKind::ConditionalTrue,
                })
                .unwrap_or(when_true);
            stack.push(Work::Condition {
                node: conditions[index],
                entry: entries[index],
                when_true: success,
                when_false,
                scope,
            });
        }
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
    ) -> Result<(), RustLoweringError> {
        match node.kind() {
            "block" => self.block(builder, node, entry, next, scope, stack),
            "expression_statement" => {
                let expression =
                    first_named_child(node).ok_or_else(|| missing_field(node, "expression"))?;
                stack.push(Work::Expression {
                    node: expression,
                    entry,
                    next,
                    scope,
                });
                Ok(())
            }
            "let_declaration" => self.let_declaration(builder, node, entry, next, scope, stack),
            "function_item"
            | "function_signature_item"
            | "type_item"
            | "struct_item"
            | "enum_item"
            | "union_item"
            | "trait_item"
            | "impl_item"
            | "mod_item"
            | "use_declaration"
            | "extern_crate_declaration"
            | "macro_definition"
            | "foreign_mod_item"
            | "const_item"
            | "static_item"
            | "empty_statement"
            | "attribute_item"
            | "inner_attribute_item" => self.edge(builder, entry, next),
            _ if is_rust_expression(node.kind()) => {
                stack.push(Work::Expression {
                    node,
                    entry,
                    next,
                    scope,
                });
                Ok(())
            }
            _ => self.unhandled_control_syntax(builder, node, entry),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn block(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let has_drop_obligations = named_children(node)
            .into_iter()
            .filter(|child| child.kind() == "let_declaration")
            .any(|child| self.let_declaration_may_require_drop(child));
        let scope_exit = has_drop_obligations
            .then(|| self.point(builder, node, Vec::new()))
            .transpose()?;
        let effective_next = scope_exit.map(EdgeTarget::normal).unwrap_or(next);
        if let Some(scope_exit) = scope_exit {
            self.add_drop_omission_gaps(
                builder,
                scope_exit,
                "values introduced by direct let bindings may require implicit Drop at this lexical scope exit",
            )?;
            self.edge(builder, scope_exit, next)?;
        }
        let label = direct_named_child_kind(node, "label");
        let labeled_scope = if let Some(label) = label {
            let label = node_text(self.source, label).map(Box::<str>::from);
            builder.push_scope(
                Some(scope),
                ScopeBinding::Breakable {
                    label,
                    accepts_unlabeled: false,
                    break_target: next.point,
                    break_edge_kind: next.kind,
                },
            )
        } else {
            scope
        };
        let block_scope = if has_drop_obligations {
            self.push_cleanup_scope(builder, labeled_scope)?
        } else {
            labeled_scope
        };
        let children = named_children(node)
            .into_iter()
            .filter(|child| child.kind() != "label")
            .collect::<Vec<_>>();
        self.schedule_nodes(
            builder,
            entry,
            &children,
            effective_next,
            block_scope,
            stack,
        )
    }

    fn push_cleanup_scope(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        parent: ScopeFrameId,
    ) -> Result<ScopeFrameId, RustLoweringError> {
        let region = CleanupRegionId::new(
            u32::try_from(self.next_cleanup_region)
                .map_err(|_| RustLoweringError::Invalid("too many Rust cleanup regions".into()))?,
        );
        self.next_cleanup_region += 1;
        Ok(builder.push_scope(Some(parent), ScopeBinding::Cleanup { region }))
    }

    fn add_drop_omission_gaps(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        context: &str,
    ) -> Result<(), RustLoweringError> {
        for (capability, kind, detail) in [
            (
                SemanticCapability::CleanupControlFlow,
                SemanticGapKind::Unknown,
                "implicit Drop order and cleanup routing are not lowered",
            ),
            (
                SemanticCapability::ResourceManagement,
                SemanticGapKind::Unknown,
                "resource release depends on inferred types and Drop implementations",
            ),
            (
                SemanticCapability::Calls,
                SemanticGapKind::Unknown,
                "implicit Drop::drop invocations are not emitted as fabricated call sites",
            ),
            // The unwind edge a panicking destructor would take is simply not
            // lowered, which is `Unsupported` rather than `Unknown`: it is the
            // exact shape the shared implicit-abort discharge closes when no
            // handler or cleanup body runs user code (#1952). Stating it as
            // `Unknown` made every Rust snapshot uncertain forever.
            (
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unsupported,
                "destructor unwinding and destructor panic routing are not lowered",
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

    #[allow(clippy::too_many_arguments)]
    fn let_declaration(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let value = node.child_by_field_name("value");
        let alternative = node.child_by_field_name("alternative");
        let Some(value) = value else {
            return self.edge(builder, entry, next);
        };
        let binding = self.point(builder, node, Vec::new())?;
        if let Some(pattern) = node.child_by_field_name("pattern") {
            if is_wildcard_pattern(pattern) {
                // `_` binds and moves nothing. A place expression such as a
                // local parameter therefore creates neither local value flow
                // nor a lexical-scope cleanup obligation. A fresh temporary
                // can still be dropped at the end of this statement; retain
                // that distinct omission at the binding point.
                if !self.is_place(value) && !self.expression_is_definitely_non_dropping(value) {
                    self.add_drop_omission_gaps(
                        builder,
                        binding,
                        "a temporary discarded by a wildcard let may require immediate Drop at the end of the statement",
                    )?;
                }
            } else if let Some(name) = identity_binding_identifier(pattern) {
                let name_text = node_text(self.source, name).ok_or_else(|| {
                    RustLoweringError::Invalid("Rust binding has an invalid name range".into())
                })?;
                let target = self
                    .local_declaration_value(name_text, name.start_byte())
                    .ok_or_else(|| {
                        RustLoweringError::Invalid(
                            "Rust local declaration was not preindexed".into(),
                        )
                    })?;
                let source = self.expression_value(builder, value, expression_value_kind(value))?;
                self.append_effect(
                    builder,
                    binding,
                    SemanticEffect::Assignment {
                        target,
                        value: source,
                    },
                )?;
                self.append_effect(
                    builder,
                    binding,
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Local,
                        source,
                        target,
                    },
                )?;
            } else {
                self.add_gap(
                    builder,
                    binding,
                    SemanticGapSubject::Point,
                    SemanticCapability::LocalFlow,
                    SemanticGapKind::Unsupported,
                    "destructuring and by-reference Rust let patterns are not lowered as identity-preserving local flow",
                )?;
            }
        }
        if let Some(alternative) = alternative {
            let success = self.point(builder, node, Vec::new())?;
            let alternative_entry = self.point(builder, alternative, Vec::new())?;
            // No control-flow gap: the matched and diverging successors are
            // both represented as edges below. What the pattern binds is a
            // value question, already published by the `LocalFlow` gap above
            // for any pattern this adapter does not lower as identity flow.
            self.edge(
                builder,
                binding,
                EdgeTarget {
                    point: success,
                    kind: ControlEdgeKind::ConditionalTrue,
                },
            )?;
            self.edge(
                builder,
                binding,
                EdgeTarget {
                    point: alternative_entry,
                    kind: ControlEdgeKind::ConditionalFalse,
                },
            )?;
            self.edge(builder, success, next)?;
            stack.push(Work::Statement {
                node: alternative,
                entry: alternative_entry,
                next,
                scope,
            });
        } else {
            self.edge(builder, binding, next)?;
        }
        stack.push(Work::Expression {
            node: value,
            entry,
            next: EdgeTarget::normal(binding),
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
    ) -> Result<(), RustLoweringError> {
        match node.kind() {
            "call_expression" => self.call_expression(builder, node, entry, next, scope, stack),
            "struct_expression" => self.allocation_expression(
                builder,
                node,
                AllocationKind::Object,
                entry,
                next,
                scope,
                stack,
            ),
            "array_expression" => self.allocation_expression(
                builder,
                node,
                AllocationKind::Array,
                entry,
                next,
                scope,
                stack,
            ),
            "assignment_expression" => {
                self.assignment_expression(builder, node, entry, next, scope, stack)
            }
            "parenthesized_expression" | "reference_expression" => {
                let value = first_named_child(node).ok_or_else(|| missing_field(node, "value"))?;
                self.transparent_expression(builder, node, value, entry, next, scope, stack)
            }
            "type_cast_expression" => {
                let value = required_field(node, "value")?;
                self.conversion_expression(builder, node, value, entry, next, scope, stack)
            }
            "closure_expression" | "async_block" | "gen_block" => {
                self.callable_expression(builder, node, entry, next)
            }
            "if_expression" => self.if_expression(builder, node, entry, next, scope, stack),
            "match_expression" => self.match_expression(builder, node, entry, next, scope, stack),
            "loop_expression" => self.loop_expression(builder, node, entry, next, scope, stack),
            "while_expression" => self.while_expression(builder, node, entry, next, scope, stack),
            "for_expression" => self.for_expression(builder, node, entry, next, scope, stack),
            "break_expression" => self.break_expression(builder, node, entry, scope, stack),
            "continue_expression" => self.continue_expression(builder, node, entry, scope),
            "return_expression" => self.return_expression(builder, node, entry, scope, stack),
            "try_expression" => self.try_expression(builder, node, entry, next, scope, stack),
            "try_block" => self.try_block(builder, node, entry, scope, stack),
            "await_expression" => self.await_expression(builder, node, entry, next, scope, stack),
            "yield_expression" => self.yield_expression(builder, node, entry, scope, stack),
            "macro_invocation" => self.macro_boundary(builder, node, entry),
            "block" => self.block(builder, node, entry, next, scope, stack),
            "unsafe_block" => {
                let block = first_named_child(node).ok_or_else(|| missing_field(node, "block"))?;
                stack.push(Work::Statement {
                    node: block,
                    entry,
                    next,
                    scope,
                });
                Ok(())
            }
            "const_block" => {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::Values,
                    SemanticGapKind::Unsupported,
                    "inline const evaluation happens at compile time and is not represented as runtime control flow",
                )?;
                self.edge(builder, entry, next)
            }
            "binary_expression" if rust_boolean_operator(node).is_some() => {
                let merge = self.point(builder, node, Vec::new())?;
                // Both arms of the short circuit reconvene here, and the
                // boolean this expression produces derives from whichever
                // operands were evaluated to reach it.
                let result = self.expression_value(builder, node, expression_value_kind(node))?;
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
            "binary_expression" | "unary_expression" => {
                self.operator_expression(builder, node, entry, next, scope, stack)
            }
            "field_expression"
                if !self.field_denotes_no_location(node) && !is_rust_assignment_target(node) =>
            {
                self.field_load(builder, node, entry, next, scope, stack)
            }
            "index_expression"
                if !is_rust_assignment_target(node)
                    && runtime_expression_children(node).len() == 2 =>
            {
                self.index_load(builder, node, entry, next, scope, stack)
            }
            kind if implicit_runtime_call_reason(kind).is_some() => {
                self.implicit_call_expression(builder, node, entry, next, scope, stack)
            }
            "let_condition" => {
                let value = required_field(node, "value")?;
                stack.push(Work::Expression {
                    node: value,
                    entry,
                    next,
                    scope,
                });
                Ok(())
            }
            "let_chain" => {
                let merge = self.point(builder, node, Vec::new())?;
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
            "generic_function" => {
                let function = required_field(node, "function")?;
                stack.push(Work::Expression {
                    node: function,
                    entry,
                    next,
                    scope,
                });
                Ok(())
            }
            kind if is_runtime_leaf(kind) => {
                let value = self.expression_value(builder, node, expression_value_kind(node))?;
                self.emit_lexical_input_flow(builder, node, entry, value)?;
                self.edge(builder, entry, next)
            }
            kind if is_runtime_container(kind) => {
                let children = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            _ => self.unhandled_control_syntax(builder, node, entry),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn allocation_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        kind: AllocationKind,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let terminal = self.point(builder, node, Vec::new())?;
        let result = self.expression_value(builder, node, SemanticValueKind::Temporary)?;
        self.session
            .add_allocation(builder, terminal, result, kind)?;
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

    #[allow(clippy::too_many_arguments)]
    fn assignment_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let left = required_field(node, "left")?;
        let right = required_field(node, "right")?;
        let terminal = self.point(builder, node, Vec::new())?;
        if left.kind() == "identifier" {
            let name = node_text(self.source, left).ok_or_else(|| {
                RustLoweringError::Invalid("Rust assignment has an invalid target range".into())
            })?;
            let target = self
                .local_at(name, left.start_byte())
                .or_else(|| self.parameters.get(name).copied());
            if let Some(target) = target {
                let value = self.expression_value(builder, right, expression_value_kind(right))?;
                self.append_effect(
                    builder,
                    terminal,
                    SemanticEffect::Assignment { target, value },
                )?;
                self.append_effect(
                    builder,
                    terminal,
                    SemanticEffect::ValueFlow {
                        kind: if self.local_at(name, left.start_byte()).is_some() {
                            ValueFlowKind::Local
                        } else {
                            ValueFlowKind::Parameter
                        },
                        source: value,
                        target,
                    },
                )?;
            } else {
                self.add_gap(
                    builder,
                    terminal,
                    SemanticGapSubject::Point,
                    SemanticCapability::Assignments,
                    SemanticGapKind::Unknown,
                    "assignment target does not name a represented Rust local or parameter",
                )?;
            }
            if self.assignment_replaces_droppable_value(left) {
                self.add_drop_omission_gaps(
                    builder,
                    terminal,
                    "assignment may replace a live value",
                )?;
            }
            self.edge(builder, terminal, next)?;
            stack.push(Work::Expression {
                node: right,
                entry,
                next: EdgeTarget::normal(terminal),
                scope,
            });
            return Ok(());
        }

        // A single field or index target is a real store into memory. The
        // target's own base is still evaluated, but the target node itself is
        // never scheduled as an expression: reading it would publish a load of
        // the location this statement writes.
        let place = matches!(left.kind(), "field_expression" | "index_expression")
            .then_some(left)
            .filter(|place| {
                place.kind() != "field_expression" || !self.field_denotes_no_location(*place)
            });
        let evaluations = if let Some(place) = place {
            let value = self.expression_value(builder, right, expression_value_kind(right))?;
            let mut evaluations = vec![right];
            match place.kind() {
                "field_expression" => {
                    let base = required_field(place, "value")?;
                    let field = required_field(place, "field")?;
                    let base_value =
                        self.expression_value(builder, base, expression_value_kind(base))?;
                    let (member, resolved) = self.memory_member_locator(base, field)?;
                    let location = self.session.add_memory_location(
                        builder,
                        terminal,
                        MemoryLocationKind::Field {
                            base: base_value,
                            member,
                        },
                    )?;
                    if !resolved {
                        self.add_field_identity_gap(builder, terminal, location)?;
                    }
                    self.append_effect(
                        builder,
                        terminal,
                        SemanticEffect::MemoryStore {
                            kind: MemoryAccessKind::Field,
                            location,
                            value,
                        },
                    )?;
                    evaluations.insert(0, base);
                }
                _ => {
                    let children = runtime_expression_children(place);
                    let [base, index_node] = children.as_slice() else {
                        return Err(RustLoweringError::Invalid(
                            "Rust index place does not have a base and an index".into(),
                        ));
                    };
                    let base_value =
                        self.expression_value(builder, *base, expression_value_kind(*base))?;
                    let index = self.index_value(builder, *index_node)?;
                    let location = self.session.add_memory_location(
                        builder,
                        terminal,
                        MemoryLocationKind::Index {
                            base: base_value,
                            index,
                            constant_index: None,
                            identity: crate::analyzer::semantic::IndexedLocationIdentity::Element,
                        },
                    )?;
                    if index.is_none() {
                        self.add_dynamic_index_gap(builder, terminal, location)?;
                    }
                    self.append_effect(
                        builder,
                        terminal,
                        SemanticEffect::MemoryStore {
                            kind: MemoryAccessKind::Index,
                            location,
                            value,
                        },
                    )?;
                    evaluations.insert(0, *index_node);
                    evaluations.insert(0, *base);
                }
            }
            evaluations
        } else {
            self.add_gap(
                builder,
                terminal,
                SemanticGapSubject::Point,
                SemanticCapability::Assignments,
                SemanticGapKind::Unsupported,
                "dereferenced, destructuring, and call-selector Rust assignment targets are not yet lowered into memory flow",
            )?;
            runtime_expression_children(node)
        };
        // One scoped fact per point: the place-evaluation traits a field, index,
        // or dereference target may invoke are reported alongside the drop
        // omissions this same terminal already publishes rather than as a
        // second Point/Calls row. A place whose access is the language's own
        // projection, replacing a value that provably owns no `Drop`, invokes
        // neither and publishes nothing.
        if !self.place_access_is_language_defined(left)
            || self.assignment_replaces_droppable_value(left)
        {
            self.add_drop_omission_gaps(
                builder,
                terminal,
                "place assignment may invoke custom DerefMut or IndexMut behavior and may replace a live value",
            )?;
        } else if left.kind() == "index_expression" {
            // The abort edge an out-of-range index would take is not lowered.
            // `Unsupported` on a `Point` subject is the exact shape the shared
            // implicit-abort discharge closes when no handler or cleanup body
            // runs user code (#1952). A place that also publishes the
            // drop-omission family already carries this exact scoped fact in
            // that family's own `ExceptionalControlFlow` row, and #2638's
            // contract allows only one row per (point, subject, capability).
            self.add_gap(
                builder,
                terminal,
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unsupported,
                "an index store may abort on an out-of-range index; that abort edge is not lowered",
            )?;
        }
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
    ) -> Result<(), RustLoweringError> {
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
        // Parenthesizing a value, or taking a reference to it, does not change
        // what the value is. The assignment alone records only that the write
        // happened; this flow records that the result *is* the operand.
        self.append_effect(
            builder,
            terminal,
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Local,
                source,
                target,
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
    ) -> Result<(), RustLoweringError> {
        let terminal = self.point(builder, node, Vec::new())?;
        let target = self.expression_value(builder, node, expression_value_kind(node))?;
        // A cast changes a value's type, never where its data came from. The
        // result therefore derives from the operand rather than keeping the
        // operand's identity, which is exactly a language-defined flow. Ending
        // the operand's history here instead published a gap the conversion
        // does not actually have.
        let source = self.expression_value(builder, value, expression_value_kind(value))?;
        self.session
            .append_language_defined_value_flows(builder, terminal, [source], target)?;
        self.edge(builder, terminal, next)?;
        stack.push(Work::Expression {
            node: value,
            entry,
            next: EdgeTarget::normal(terminal),
            scope,
        });
        Ok(())
    }

    /// An operator application: `a + b`, `!flag`, `*handle`.
    ///
    /// The operator's result derives from every operand it evaluates. Without
    /// that flow an arithmetic or comparison step silently ended the value's
    /// history, which is what left every computed Rust tail expression
    /// unknown.
    #[allow(clippy::too_many_arguments)]
    fn operator_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let terminal = self.point(builder, node, Vec::new())?;
        let result = self.expression_value(builder, node, expression_value_kind(node))?;
        let children = runtime_expression_children(node);
        let operands = children
            .iter()
            .map(|child| self.expression_value(builder, *child, expression_value_kind(*child)))
            .collect::<Result<Vec<_>, _>>()?;
        self.session
            .append_language_defined_value_flows(builder, terminal, operands, result)?;
        self.add_gap(
            builder,
            terminal,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unknown,
            implicit_runtime_call_reason(node.kind())
                .expect("operator expressions carry an implicit-call reason"),
        )?;
        if rust_operation_can_abort(node) {
            self.add_non_rejoining_exceptional_exit_gap(
                builder,
                terminal,
                scope,
                "arithmetic overflow, division by zero, or an invalid dereference may abort here; that abort edge is not lowered",
            )?;
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

    /// `base.field` read as a value: a load from the field's own location.
    #[allow(clippy::too_many_arguments)]
    fn field_load(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let base = required_field(node, "value")?;
        let field = required_field(node, "field")?;
        let access = self.point(builder, node, Vec::new())?;
        let result = self.expression_value(builder, node, expression_value_kind(node))?;
        let base_value = self.expression_value(builder, base, expression_value_kind(base))?;
        let (member, resolved) = self.memory_member_locator(base, field)?;
        let location = self.session.add_memory_location(
            builder,
            access,
            MemoryLocationKind::Field {
                base: base_value,
                member,
            },
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
        // Projecting a field of a struct this file declares is the language's
        // own projection: no autoderef step reaches a user `Deref`, and the
        // projection itself cannot abort. Any other base keeps both claims.
        if !self.place_access_is_language_defined(node) {
            self.add_gap(
                builder,
                access,
                SemanticGapSubject::Point,
                SemanticCapability::Calls,
                SemanticGapKind::Unknown,
                "field projection may require implicit autoderef operations that are not emitted as call sites",
            )?;
            self.add_gap(
                builder,
                access,
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unsupported,
                "an implicit Rust autoderef may abort here; that abort edge is not lowered",
            )?;
        }
        self.edge(builder, access, next)?;
        self.schedule_expressions(
            builder,
            entry,
            &[base],
            EdgeTarget::normal(access),
            scope,
            stack,
        )
    }

    /// `base[index]` read as a value: a load from the element's own location.
    #[allow(clippy::too_many_arguments)]
    fn index_load(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let children = runtime_expression_children(node);
        let [base, index_node] = children.as_slice() else {
            return Err(RustLoweringError::Invalid(
                "Rust index expression does not have a base and an index".into(),
            ));
        };
        let access = self.point(builder, node, Vec::new())?;
        let result = self.expression_value(builder, node, expression_value_kind(node))?;
        let base_value = self.expression_value(builder, *base, expression_value_kind(*base))?;
        let index = self.index_value(builder, *index_node)?;
        let location = self.session.add_memory_location(
            builder,
            access,
            MemoryLocationKind::Index {
                base: base_value,
                index,
                constant_index: None,
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
        if !self.place_access_is_language_defined(node) {
            self.add_gap(
                builder,
                access,
                SemanticGapSubject::Point,
                SemanticCapability::Calls,
                SemanticGapKind::Unknown,
                "indexing may invoke Index or IndexMut implicitly; no fabricated trait call site is emitted",
            )?;
        }
        // Built in or not, an index read may abort on an out-of-range index.
        self.add_gap(
            builder,
            access,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            "indexing may abort on an out-of-range index; that abort edge is not lowered",
        )?;
        self.edge(builder, access, next)?;
        self.schedule_expressions(
            builder,
            entry,
            &children,
            EdgeTarget::normal(access),
            scope,
            stack,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn implicit_call_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let boundary = self.point(builder, node, Vec::new())?;
        let reason = implicit_runtime_call_reason(node.kind())
            .expect("implicit-call expressions are dispatched by node kind");
        self.add_gap(
            builder,
            boundary,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unknown,
            reason,
        )?;
        if rust_operation_can_abort(node) {
            // Not lowering the abort edge is `Unsupported`, the shape the
            // shared implicit-abort discharge closes; an operation that cannot
            // abort publishes nothing at all.
            self.add_gap(
                builder,
                boundary,
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unsupported,
                "an implicit Rust built-in check may abort here; that abort edge is not lowered",
            )?;
        }
        if matches!(
            node.kind(),
            "assignment_expression" | "compound_assignment_expr"
        ) && node
            .child_by_field_name("left")
            .is_none_or(|left| self.assignment_replaces_droppable_value(left))
        {
            self.add_gap(
                builder,
                boundary,
                SemanticGapSubject::Point,
                SemanticCapability::CleanupControlFlow,
                SemanticGapKind::Unknown,
                "assignment may replace a live value, but its implicit Drop order and cleanup control are not lowered",
            )?;
            self.add_gap(
                builder,
                boundary,
                SemanticGapSubject::Point,
                SemanticCapability::ResourceManagement,
                SemanticGapKind::Unknown,
                "resource release for the value replaced by assignment depends on its inferred type and Drop implementation",
            )?;
        }
        self.edge(builder, boundary, next)?;
        let children = runtime_expression_children(node);
        self.schedule_expressions(
            builder,
            entry,
            &children,
            EdgeTarget::normal(boundary),
            scope,
            stack,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn if_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let condition = required_field(node, "condition")?;
        let consequence = required_field(node, "consequence")?;
        let alternative = node
            .child_by_field_name("alternative")
            .and_then(first_named_child);
        let condition_entry = self.point(builder, condition, Vec::new())?;
        let consequence_has_bindings = condition_introduces_pattern_bindings(condition);
        let consequence_scope = if consequence_has_bindings {
            self.push_cleanup_scope(builder, scope)?
        } else {
            scope
        };
        let consequence_entry =
            self.schedule_branch(builder, consequence, next, consequence_scope, stack)?;
        if consequence_has_bindings {
            self.add_drop_omission_gaps(
                builder,
                consequence_entry.expect("scheduled branch has an entry"),
                "values introduced by an if-let condition may require implicit Drop when the consequence completes",
            )?;
        }
        let alternative_entry = alternative
            .map(|alternative| self.schedule_branch(builder, alternative, next, scope, stack))
            .transpose()?
            .flatten();
        stack.push(Work::Condition {
            node: condition,
            entry: condition_entry,
            when_true: EdgeTarget {
                point: consequence_entry.unwrap_or(next.point),
                kind: ControlEdgeKind::ConditionalTrue,
            },
            when_false: EdgeTarget {
                point: alternative_entry.unwrap_or(next.point),
                kind: ControlEdgeKind::ConditionalFalse,
            },
            scope,
        });
        self.edge(builder, entry, EdgeTarget::normal(condition_entry))
    }

    fn schedule_branch(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<Option<ProgramPointId>, RustLoweringError> {
        let entry = self.point(builder, node, Vec::new())?;
        if node.kind() == "block" {
            stack.push(Work::Statement {
                node,
                entry,
                next,
                scope,
            });
        } else {
            stack.push(Work::Expression {
                node,
                entry,
                next,
                scope,
            });
        }
        Ok(Some(entry))
    }

    #[allow(clippy::too_many_arguments)]
    fn match_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let value = required_field(node, "value")?;
        let body = required_field(node, "body")?;
        let arms = named_children(body)
            .into_iter()
            .filter(|child| child.kind() == "match_arm")
            .collect::<Vec<_>>();
        let decision = self.point(builder, node, Vec::new())?;
        // No point-wide control-flow gap: every arm gets a case edge below and
        // the last arm's guard-false edge continues past the match, so the
        // represented successor set is a superset of the real one. What a
        // selected pattern *binds* is still unknown, and that is published per
        // arm, on the value it binds.
        if arms.is_empty() {
            self.edge(builder, decision, next)?;
        } else {
            let candidates = arms
                .iter()
                .map(|arm| {
                    arm.child_by_field_name("pattern")
                        .map(|pattern| self.point(builder, pattern, Vec::new()))
                        .unwrap_or_else(|| self.point(builder, *arm, Vec::new()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let mut arm_scopes = Vec::with_capacity(arms.len());
            for (index, candidate) in candidates.iter().enumerate() {
                arm_scopes.push(self.push_cleanup_scope(builder, scope)?);
                // Only an arm that actually binds a name introduces a value
                // whose identity and drop obligation are unresolved. A literal
                // or wildcard arm introduces neither.
                let binds = arms[index]
                    .child_by_field_name("pattern")
                    .is_some_and(rust_pattern_binds_value);
                if !binds {
                    continue;
                }
                let bound = self.value(builder, *candidate, SemanticValueKind::Local)?;
                self.add_gap(
                    builder,
                    *candidate,
                    SemanticGapSubject::Value(bound),
                    SemanticCapability::Values,
                    SemanticGapKind::Unknown,
                    "what a selected Rust match pattern binds depends on the scrutinee's runtime shape",
                )?;
                self.add_drop_omission_gaps(
                    builder,
                    *candidate,
                    "values introduced by a selected match pattern may require implicit Drop when the arm completes",
                )?;
            }
            for candidate in &candidates {
                self.edge(
                    builder,
                    decision,
                    EdgeTarget {
                        point: *candidate,
                        kind: ControlEdgeKind::SwitchCase,
                    },
                )?;
            }
            for index in (0..arms.len()).rev() {
                let arm = arms[index];
                let arm_value = required_field(arm, "value")?;
                let arm_entry = self.point(builder, arm_value, Vec::new())?;
                stack.push(Work::Expression {
                    node: arm_value,
                    entry: arm_entry,
                    next,
                    scope: arm_scopes[index],
                });
                let pattern = required_field(arm, "pattern")?;
                if let Some(guard) = pattern.child_by_field_name("condition") {
                    stack.push(Work::Condition {
                        node: guard,
                        entry: candidates[index],
                        when_true: EdgeTarget {
                            point: arm_entry,
                            kind: ControlEdgeKind::ConditionalTrue,
                        },
                        when_false: EdgeTarget {
                            point: candidates.get(index + 1).copied().unwrap_or(next.point),
                            kind: ControlEdgeKind::ConditionalFalse,
                        },
                        scope: arm_scopes[index],
                    });
                } else {
                    self.edge(
                        builder,
                        candidates[index],
                        EdgeTarget {
                            point: arm_entry,
                            kind: ControlEdgeKind::SwitchCase,
                        },
                    )?;
                }
            }
        }
        stack.push(Work::Expression {
            node: value,
            entry,
            next: EdgeTarget::normal(decision),
            scope,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn loop_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let body = required_field(node, "body")?;
        let body_entry = self.point(builder, body, Vec::new())?;
        let label = control_label(node, self.source);
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
        });
        self.edge(builder, entry, EdgeTarget::normal(body_entry))
    }

    #[allow(clippy::too_many_arguments)]
    fn while_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let condition = required_field(node, "condition")?;
        let body = required_field(node, "body")?;
        let condition_entry = self.point(builder, condition, Vec::new())?;
        let body_entry = self.point(builder, body, Vec::new())?;
        let loop_scope = builder.push_scope(
            Some(scope),
            ScopeBinding::Loop {
                label: control_label(node, self.source),
                break_target: next.point,
                break_edge_kind: next.kind,
                continue_target: condition_entry,
                continue_edge_kind: ControlEdgeKind::LoopBack,
            },
        );
        let body_has_bindings = condition_introduces_pattern_bindings(condition);
        let body_scope = if body_has_bindings {
            self.push_cleanup_scope(builder, loop_scope)?
        } else {
            loop_scope
        };
        if body_has_bindings {
            self.add_drop_omission_gaps(
                builder,
                body_entry,
                "values introduced by a while-let condition may require implicit Drop after each selected iteration",
            )?;
        }
        stack.push(Work::Statement {
            node: body,
            entry: body_entry,
            next: EdgeTarget {
                point: condition_entry,
                kind: ControlEdgeKind::LoopBack,
            },
            scope: body_scope,
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
    fn for_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let iterable = required_field(node, "value")?;
        let body = required_field(node, "body")?;
        let test = self.point(builder, node, Vec::new())?;
        let body_entry = self.point(builder, body, Vec::new())?;
        let loop_scope = builder.push_scope(
            Some(scope),
            ScopeBinding::Loop {
                label: control_label(node, self.source),
                break_target: next.point,
                break_edge_kind: next.kind,
                continue_target: test,
                continue_edge_kind: ControlEdgeKind::LoopBack,
            },
        );
        let body_scope = self.push_cleanup_scope(builder, loop_scope)?;
        // The element the pattern binds is a value of this procedure like any
        // other: it derives from the iterable. Publishing that element-of
        // relation is what carries a tainted collection into a loop body.
        let pattern = node.child_by_field_name("pattern");
        let element = pattern
            .and_then(identity_binding_identifier)
            .and_then(|name| {
                node_text(self.source, name)
                    .and_then(|text| self.local_declaration_value(text, name.start_byte()))
            });
        if let Some(element) = element {
            let iterable_value =
                self.expression_value(builder, iterable, expression_value_kind(iterable))?;
            self.session.append_language_defined_value_flows(
                builder,
                body_entry,
                [iterable_value],
                element,
            )?;
        }
        // A pattern that binds a primitive element runs no destructor, exactly
        // as for a `let`.
        let element_may_drop =
            element.is_none_or(|element| !self.definitely_non_dropping.contains(&element));
        if element_may_drop {
            self.add_drop_omission_gaps(
                builder,
                body_entry,
                "the per-iteration for-pattern value may require implicit Drop after the selected iteration",
            )?;
        }
        self.add_gap(
            builder,
            test,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unknown,
            "IntoIterator conversion and Iterator::next are implicit calls not emitted as fabricated call sites",
        )?;
        // No `NormalControlFlow` gap: both successors of the exhaustion test
        // are represented below, so claiming the loop's control flow is
        // unknown over-states what is missing.
        self.edge(
            builder,
            test,
            EdgeTarget {
                point: body_entry,
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
            scope: body_scope,
        });
        // When the iterable provably yields at least one element, the first
        // iteration enters the body without consulting the exhaustion test.
        // Routing the entry through the test instead would keep a
        // zero-iteration path that this loop does not have, and a kill inside
        // the body would then look avoidable. Java's counted `for` states the
        // same fact through `for_condition_starts_true`.
        let first_iteration = if rust_iteration_yields_an_element(iterable, self.source) {
            EdgeTarget::normal(body_entry)
        } else {
            EdgeTarget::normal(test)
        };
        stack.push(Work::Expression {
            node: iterable,
            entry,
            next: first_iteration,
            scope,
        });
        Ok(())
    }

    fn break_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let label_node = direct_named_child_kind(node, "label");
        let value = named_children(node)
            .into_iter()
            .find(|child| child.kind() != "label");
        let terminal = if value.is_some() {
            self.point(builder, node, Vec::new())?
        } else {
            entry
        };
        if value.is_some() {
            self.add_gap(
                builder,
                terminal,
                SemanticGapSubject::Point,
                SemanticCapability::Values,
                SemanticGapKind::Unknown,
                "break value transfer into the loop or labeled-block result is not represented",
            )?;
        }
        let label = label_node.and_then(|label| node_text(self.source, label));
        self.abrupt(builder, terminal, scope, CompletionKind::Break, label)?;
        if let Some(value) = value {
            stack.push(Work::Expression {
                node: value,
                entry,
                next: EdgeTarget::normal(terminal),
                scope,
            });
        }
        Ok(())
    }

    fn continue_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        scope: ScopeFrameId,
    ) -> Result<(), RustLoweringError> {
        let label =
            direct_named_child_kind(node, "label").and_then(|label| node_text(self.source, label));
        self.abrupt(builder, entry, scope, CompletionKind::Continue, label)
    }

    fn return_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let value_node = first_named_child(node);
        let terminal = if value_node.is_some() {
            self.point(builder, node, Vec::new())?
        } else {
            entry
        };
        let value = value_node
            .map(|_| self.value(builder, terminal, SemanticValueKind::Return))
            .transpose()?;
        if let (Some(value_node), Some(value)) = (value_node, value) {
            let source =
                self.expression_value(builder, value_node, expression_value_kind(value_node))?;
            self.append_effect(
                builder,
                terminal,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Return,
                    source,
                    target: value,
                },
            )?;
        }
        self.append_effect(builder, terminal, SemanticEffect::ProcedureReturn { value })?;
        self.abrupt(builder, terminal, scope, CompletionKind::Return, None)?;
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

    #[allow(clippy::too_many_arguments)]
    fn try_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let operand = first_named_child(node).ok_or_else(|| missing_field(node, "operand"))?;
        let branch = self.point(builder, node, Vec::new())?;
        let residual = self.point(builder, node, Vec::new())?;
        let residual_value = self.value(builder, residual, SemanticValueKind::Return)?;
        // No control-flow gap: both Try outcomes -- continue with the value,
        // or return the residual -- are represented as edges below, so the
        // successor set is complete. Which one runs is a value question, and
        // the unlowered `Try::branch` and `FromResidual` calls below already
        // state that the value question is open.
        self.add_gap(
            builder,
            branch,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unknown,
            "Try::branch and FromResidual conversion are implicit calls not emitted as fabricated call sites",
        )?;
        self.edge(
            builder,
            branch,
            EdgeTarget {
                point: next.point,
                kind: ControlEdgeKind::ConditionalTrue,
            },
        )?;
        self.edge(
            builder,
            branch,
            EdgeTarget {
                point: residual,
                kind: ControlEdgeKind::ConditionalFalse,
            },
        )?;
        self.append_effect(
            builder,
            residual,
            SemanticEffect::ProcedureReturn {
                value: Some(residual_value),
            },
        )?;
        self.add_gap(
            builder,
            residual,
            SemanticGapSubject::Value(residual_value),
            SemanticCapability::CleanupControlFlow,
            SemanticGapKind::Unknown,
            "the ? residual path may drop temporaries and enclosing locals before returning",
        )?;
        self.add_gap(
            builder,
            residual,
            SemanticGapSubject::Value(residual_value),
            SemanticCapability::Values,
            SemanticGapKind::Unknown,
            "FromResidual result conversion is not represented as value flow",
        )?;
        self.abrupt(builder, residual, scope, CompletionKind::Return, None)?;
        stack.push(Work::Expression {
            node: operand,
            entry,
            next: EdgeTarget::normal(branch),
            scope,
        });
        Ok(())
    }

    fn try_block(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        _scope: ScopeFrameId,
        _stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        first_named_child(node).ok_or_else(|| missing_field(node, "block"))?;
        let boundary = self.point(builder, node, Vec::new())?;
        self.edge(builder, entry, EdgeTarget::normal(boundary))?;
        for (capability, kind, detail) in [
            (
                SemanticCapability::NormalControlFlow,
                SemanticGapKind::Unsupported,
                "try-block success and residual propagation are not yet lowered",
            ),
            (
                SemanticCapability::Calls,
                SemanticGapKind::Unknown,
                "calls and Try/FromResidual conversions inside the unsupported try block are not emitted",
            ),
            (
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unknown,
                "panic and residual behavior inside the unsupported try block are not lowered",
            ),
            (
                SemanticCapability::CleanupControlFlow,
                SemanticGapKind::Unknown,
                "temporary and lexical Drop behavior inside the unsupported try block is not lowered",
            ),
            (
                SemanticCapability::ResourceManagement,
                SemanticGapKind::Unknown,
                "resource release inside the unsupported try block depends on inferred types and Drop implementations",
            ),
            (
                SemanticCapability::Values,
                SemanticGapKind::Unsupported,
                "the try-block result value is not represented",
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
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn await_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
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
        self.abrupt(builder, exceptional, scope, CompletionKind::Throw, None)?;
        self.add_gap(
            builder,
            suspend,
            SemanticGapSubject::Point,
            SemanticCapability::AsyncSuspendResume,
            SemanticGapKind::Unsupported,
            "Future::poll, executor scheduling, wakeups, pinning, repeated pending states, and the conservative exceptional boundary require async refinement",
        )?;
        self.add_gap(
            builder,
            suspend,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unknown,
            "IntoFuture::into_future and Future::poll are implicit calls not emitted as fabricated call sites",
        )?;
        self.add_gap(
            builder,
            suspend,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unknown,
            "implicit future conversion and polling may panic, but their exceptional behavior is not refined",
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

    fn yield_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        let value = first_named_child(node);
        let suspend = if value.is_some() {
            self.point(builder, node, Vec::new())?
        } else {
            entry
        };
        self.add_gap(
            builder,
            suspend,
            SemanticGapSubject::Point,
            SemanticCapability::GeneratorSuspension,
            SemanticGapKind::Unsupported,
            "yield suspension, saved generator state, and resume value are not lowered",
        )?;
        if let Some(value) = value {
            stack.push(Work::Expression {
                node: value,
                entry,
                next: EdgeTarget::normal(suspend),
                scope,
            });
        }
        Ok(())
    }

    fn macro_boundary(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        _node: Node<'tree>,
        entry: ProgramPointId,
    ) -> Result<(), RustLoweringError> {
        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::NormalControlFlow,
            SemanticGapKind::Unsupported,
            "macro token-tree expansion is unavailable; control after this invocation is intentionally not fabricated",
        )?;
        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unsupported,
            "calls produced by macro expansion are unavailable and no textual macro parser is used",
        )?;
        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            "macro expansion may introduce panic or other exceptional behavior that is unavailable",
        )?;
        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::NonLocalControl,
            SemanticGapKind::Unsupported,
            "macro expansion may introduce return, break, continue, or other non-local control that is unavailable",
        )?;
        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::CleanupControlFlow,
            SemanticGapKind::Unsupported,
            "macro expansion may introduce scope exits or cleanup control that is unavailable",
        )?;
        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::ResourceManagement,
            SemanticGapKind::Unsupported,
            "resource acquisition and release produced by macro expansion are unavailable",
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
    ) -> Result<(), RustLoweringError> {
        let invoke = self.point(builder, node, Vec::new())?;
        let normal = self.point(builder, node, Vec::new())?;
        let exceptional = self.point(builder, node, Vec::new())?;
        let function = required_field(node, "function")?;
        let callable_anchor = rust_callable_anchor(function);
        let callee = self.source_value(builder, callable_anchor, SemanticValueKind::Callable)?;
        let result = self.expression_value(builder, node, SemanticValueKind::Temporary)?;
        let thrown = self.source_value(builder, callable_anchor, SemanticValueKind::Exception)?;
        let receiver_node = rust_call_receiver(function);
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
            .map(|argument| {
                self.expression_value(builder, *argument, expression_value_kind(*argument))
                    .map(|value| SemanticCallArgument::direct(value, ArgumentDomain::Positional))
            })
            .collect::<Result<Vec<_>, _>>()?;
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
        let generic_call = function.kind() == "generic_function";
        let dispatch_detail = match (generic_call, receiver_node.is_some()) {
            (true, true) => Some(
                "generic Rust method applicability depends on unresolved type arguments and bounds, while dispatch may use a trait implementation after autoderef",
            ),
            (true, false) => Some(
                "generic Rust call applicability depends on unresolved type arguments and bounds",
            ),
            (false, true) => Some(
                "method dispatch may use a trait implementation after autoderef; receiver type and complete implementation coverage require type refinement",
            ),
            (false, false) => None,
        };
        if let Some(detail) = dispatch_detail {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::DynamicDispatch,
                SemanticGapKind::Unknown,
                detail,
            )?;
        }
        if receiver_node.is_some() {
            self.session.add_gap_with_impacts(
                builder,
                invoke,
                SemanticGapSubject::Point,
                SemanticCapability::Calls,
                SemanticGapImpacts::single(SemanticGapImpact::CallEvaluation),
                SemanticGapKind::Unknown,
                "method receiver autoderef and autoref adjustments may invoke Deref or DerefMut and are not emitted as call sites",
            )?;
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unsupported,
                "implicit method receiver adjustments may abort; that abort edge is not lowered",
            )?;
        }

        let evaluations = call_operand_evaluations(node)?;
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
    ) -> Result<(), RustLoweringError> {
        let result = self.value(builder, entry, SemanticValueKind::Callable)?;
        let metadata = self.metadata(entry)?;
        let callable = CallableValue {
            kind: CallableReferenceKind::Lambda,
            targets: CallableTargetResolution::Unknown,
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
            "closure target and captured environment require location-first callable refinement",
        )?;
        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Value(result),
            SemanticCapability::Captures,
            SemanticGapKind::Unknown,
            "closure capture identities and capture modes require lexical capture refinement",
        )?;
        if matches!(node.kind(), "async_block" | "gen_block")
            || (node.kind() == "closure_expression" && direct_child_kind(node, "async"))
        {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::DeferredExecution,
                SemanticGapKind::Unsupported,
                "creating this callable does not immediately execute its deferred body",
            )?;
        }
        self.edge(builder, entry, next)
    }

    fn unhandled_control_syntax(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
    ) -> Result<(), RustLoweringError> {
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

    fn schedule_nodes(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        children: &[Node<'tree>],
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), RustLoweringError> {
        if children.is_empty() {
            return self.edge(builder, entry, next);
        }
        let entries = children
            .iter()
            .map(|child| self.point(builder, execution_node(*child), Vec::new()))
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
    ) -> Result<(), RustLoweringError> {
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
    ) -> Result<(), RustLoweringError> {
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
                    if label.is_some() {
                        SemanticCapability::NonLocalControl
                    } else {
                        SemanticCapability::NormalControlFlow
                    },
                    SemanticGapKind::Unsupported,
                    &detail,
                )?;
                return Ok(());
            }
            return Err(RustLoweringError::Invalid(format!(
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
    ) -> Result<(), RustLoweringError> {
        if !route.cleanups().is_empty() {
            let detail = format!(
                "{} lexical scope(s) with possible implicit Drop are exited by this abrupt completion",
                route.cleanups().len()
            );
            for (capability, kind, reason) in [
                (
                    SemanticCapability::CleanupControlFlow,
                    SemanticGapKind::Unknown,
                    "implicit Drop order and cleanup routing are not lowered",
                ),
                (
                    SemanticCapability::ResourceManagement,
                    SemanticGapKind::Unknown,
                    "RAII resource release depends on inferred local types and Drop implementations",
                ),
                (
                    SemanticCapability::Calls,
                    SemanticGapKind::Unknown,
                    "implicit Drop::drop invocations are not emitted as fabricated call sites",
                ),
                // As in `add_drop_omission_gaps`: an unlowered destructor
                // unwind edge is `Unsupported`, the shape the shared
                // implicit-abort discharge can close.
                (
                    SemanticCapability::ExceptionalControlFlow,
                    SemanticGapKind::Unsupported,
                    "destructor unwinding and destructor panic routing are not lowered",
                ),
            ] {
                self.add_gap(
                    builder,
                    from,
                    SemanticGapSubject::Point,
                    capability,
                    kind,
                    &format!("{detail}; {reason}"),
                )?;
            }
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
    ) -> Result<(), RustLoweringError> {
        self.session.add_callable_resolution_gaps(
            builder,
            point,
            callee,
            call_site,
            resolution,
            "callable target requires whole-program Rust dispatch refinement",
            "call target requires whole-program Rust dispatch refinement",
        )
    }

    fn point(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        effects: Vec<SemanticEffect>,
    ) -> Result<ProgramPointId, RustLoweringError> {
        let metadata = self.mapping(builder, node)?;
        self.session.add_point(builder, metadata, effects)
    }

    fn mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<PointMetadata, RustLoweringError> {
        self.session.add_node_mapping(builder, node)
    }

    fn value_mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<PointMetadata, RustLoweringError> {
        let range = node.byte_range();
        let occurrence = self.session.next_source_occurrence(range.start, range.end);
        let anchor = source_anchor(node, occurrence).map_err(RustLoweringError::Invalid)?;
        self.session
            .add_mapping(builder, anchor, SourceMappingKind::Exact)
    }

    fn metadata(&self, point: ProgramPointId) -> Result<PointMetadata, RustLoweringError> {
        self.session.metadata(point)
    }

    fn value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        kind: SemanticValueKind,
    ) -> Result<ValueId, RustLoweringError> {
        self.session.add_value(builder, point, kind)
    }

    fn append_effect(
        &self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        effect: SemanticEffect,
    ) -> Result<(), RustLoweringError> {
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
    ) -> Result<(), RustLoweringError> {
        self.session
            .add_gap(builder, point, subject, capability, kind, detail)?;
        Ok(())
    }

    /// Rust aborts do not resume normal evaluation after the failing
    /// operation. Preserve that proof on this exceptional-flow gap only when
    /// the exact evaluation scope has no already-active cleanup user code.
    fn add_non_rejoining_exceptional_exit_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        scope: ScopeFrameId,
        detail: &str,
    ) -> Result<(), RustLoweringError> {
        let route = builder
            .resolve_completion(scope, &CompletionRequest::new(CompletionKind::Throw, None))
            .expect("a Rust evaluation scope must resolve abort completion");
        let discharge = if route.cleanups().is_empty() {
            SemanticGapDischarge::NonRejoiningExceptionalExit
        } else {
            SemanticGapDischarge::None
        };
        self.session.add_gap_with_impacts_and_discharge(
            builder,
            point,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapImpacts::NONE,
            SemanticGapKind::Unsupported,
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
    ) -> Result<(), RustLoweringError> {
        self.session
            .add_edge(builder, source_point, target.point, target.kind)
    }
}

fn call_operand_evaluations(call: Node<'_>) -> Result<Vec<Node<'_>>, RustLoweringError> {
    let function = required_field(call, "function")?;
    let mut result = Vec::new();
    let runtime_function = unwrap_generic_function(function);
    match runtime_function.kind() {
        "identifier" | "scoped_identifier" => {}
        "field_expression" => {
            if let Some(receiver) = runtime_function.child_by_field_name("value") {
                result.push(receiver);
            }
        }
        _ => result.push(runtime_function),
    }
    result.extend(call_arguments(call));
    Ok(result)
}

fn call_arguments(node: Node<'_>) -> Vec<Node<'_>> {
    node.child_by_field_name("arguments")
        .map(named_children)
        .unwrap_or_default()
        .into_iter()
        .filter(|argument| !is_compile_time_syntax(argument.kind()))
        .collect()
}

fn unwrap_generic_function(mut function: Node<'_>) -> Node<'_> {
    while function.kind() == "generic_function" {
        let Some(inner) = function.child_by_field_name("function") else {
            break;
        };
        function = inner;
    }
    function
}

fn rust_callable_anchor(function: Node<'_>) -> Node<'_> {
    let function = unwrap_generic_function(function);
    match function.kind() {
        "field_expression" => function.child_by_field_name("field").unwrap_or(function),
        "scoped_identifier" | "scoped_type_identifier" => {
            function.child_by_field_name("name").unwrap_or(function)
        }
        _ => function,
    }
}

fn rust_call_receiver(function: Node<'_>) -> Option<Node<'_>> {
    let function = unwrap_generic_function(function);
    (function.kind() == "field_expression")
        .then(|| function.child_by_field_name("value"))
        .flatten()
}

fn identity_binding_identifier(mut pattern: Node<'_>) -> Option<Node<'_>> {
    loop {
        match pattern.kind() {
            "identifier" => return Some(pattern),
            "mut_pattern" | "captured_pattern" => {
                let children = named_children(pattern);
                if children.len() != 1 {
                    return None;
                }
                pattern = children[0];
            }
            _ => return None,
        }
    }
}

fn is_wildcard_pattern(pattern: Node<'_>) -> bool {
    pattern.kind() == "_"
}

/// Whether this pattern introduces a binding.
///
/// A bare `identifier` in pattern position binds; a path that names a variant
/// or constant reaches the tree as the `type` field of a struct or
/// tuple-struct pattern, or as a `scoped_identifier`, and binds nothing. A
/// unit variant written bare (`None`) is indistinguishable from a binding in
/// the syntax alone and is counted as binding, which only adds a gap.
fn rust_pattern_binds_value(pattern: Node<'_>) -> bool {
    let mut pending = vec![pattern];
    while let Some(current) = pending.pop() {
        match current.kind() {
            "identifier" => return true,
            "scoped_identifier" => continue,
            _ => {}
        }
        // A `match_pattern`'s `condition` is a guard expression, not a pattern,
        // and a struct or tuple-struct pattern's `type` names the variant.
        let excluded = ["type", "condition"]
            .into_iter()
            .filter_map(|field| current.child_by_field_name(field))
            .map(|node| node.id())
            .collect::<Vec<_>>();
        pending.extend(
            named_children(current)
                .into_iter()
                .filter(|child| !excluded.contains(&child.id())),
        );
    }
    false
}

fn rust_local_scope(node: Node<'_>) -> Option<(usize, usize)> {
    let mut parent = node.parent();
    while let Some(candidate) = parent {
        if matches!(
            candidate.kind(),
            "block" | "closure_expression" | "function_item" | "async_block" | "gen_block"
        ) {
            return Some((candidate.start_byte(), candidate.end_byte()));
        }
        parent = candidate.parent();
    }
    None
}

fn is_rust_nested_execution_boundary(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_item" | "closure_expression" | "async_block" | "gen_block"
    )
}

fn expression_value_kind(node: Node<'_>) -> SemanticValueKind {
    match node.kind() {
        "closure_expression" | "async_block" | "gen_block" => SemanticValueKind::Callable,
        kind if kind.ends_with("_literal")
            || matches!(kind, "true" | "false" | "unit_expression") =>
        {
            SemanticValueKind::Constant
        }
        _ => SemanticValueKind::Temporary,
    }
}

/// Whether this expression's lowering already publishes where its value came
/// from, so a tail-expression return needs no value-refinement gap.
fn rust_expression_has_direct_value_evidence(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "call_expression"
            | "struct_expression"
            | "array_expression"
            | "parenthesized_expression"
            | "reference_expression"
            | "binary_expression"
            | "unary_expression"
            | "type_cast_expression"
    ) || is_runtime_leaf(node.kind())
}

/// A declared type that proves the value it describes owns no `Drop`.
///
/// A reference never runs a destructor when it goes out of scope, and a
/// primitive (`i32`, `bool`, `char`, ...) is `Copy` and cannot implement
/// `Drop`. Both facts are read from the declared type node, never from the
/// spelling of the source text.
fn rust_type_is_definitely_non_dropping(ty: Node<'_>) -> bool {
    matches!(ty.kind(), "reference_type" | "primitive_type")
}

/// The shape a declared type states, read from the type node itself.
///
/// A reference is transparent for the same reason it is in `expression_shape`:
/// `&Holder` and `&mut Holder` both project `Holder`'s own fields.
fn rust_declared_type_shape(source: &str, ty: Node<'_>) -> Option<RustValueShape> {
    let mut current = ty;
    loop {
        match current.kind() {
            "type_identifier" => {
                return node_text(source, current).map(|name| RustValueShape::Struct(name.into()));
            }
            "reference_type" => current = current.child_by_field_name("type")?,
            "array_type" => {
                return Some(RustValueShape::Array {
                    primitive_elements: current
                        .child_by_field_name("element")
                        .is_some_and(|element| element.kind() == "primitive_type"),
                });
            }
            _ => return None,
        }
    }
}

/// The `Self` type of the `impl` block this callable is declared in.
/// Whether this expression is written by the assignment that contains it.
///
/// A write target is not a read. The lowered store replaces its own evaluation
/// list so the target node is never scheduled, but a compound assignment --
/// whose update this adapter does not lower -- still schedules its place, and
/// minting a `MemoryLoad` there would publish a read of the very location the
/// statement overwrites.
fn is_rust_assignment_target(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "parenthesized_expression" => current = parent,
            "assignment_expression" | "compound_assignment_expr" => {
                return field_matches(parent, "left", current);
            }
            _ => return false,
        }
    }
    false
}

/// The `Self` type of the `impl` block this callable is declared in.
fn rust_impl_self_type(callable: Node<'_>) -> Option<Node<'_>> {
    let mut current = callable;
    while let Some(parent) = current.parent() {
        if parent.kind() == "impl_item" {
            return parent.child_by_field_name("type");
        }
        if is_rust_nested_execution_boundary(parent) {
            return None;
        }
        current = parent;
    }
    None
}

fn rust_parameter_is_definitely_non_dropping(node: Node<'_>) -> bool {
    node.child_by_field_name("type")
        .is_some_and(rust_type_is_definitely_non_dropping)
        || rust_type_is_definitely_non_dropping(node)
}

/// What one struct declaration in this file states about one of its fields.
#[derive(Debug, Clone)]
struct RustFieldDeclaration {
    /// The field's own `field_identifier`, which is the identity two
    /// occurrences of that field must agree on to name one memory location.
    anchor: SourceAnchor,
    /// Whether the declared field type is a primitive, so overwriting the
    /// field drops nothing.
    primitive: bool,
    /// The shape the declared field type states, which is what lets a nested
    /// access path resolve its next selector.
    shape: Option<RustValueShape>,
}

/// Everything one Rust file states that every procedure lowered from it reads.
///
/// All three tables are file-scoped by construction: this adapter lowers one
/// file at a time and never consults another. That is the same posture the
/// Python adapter's `instance_field_proofs` takes, and it is stated here so a
/// reader does not mistake any of these for a whole-crate proof.
struct RustFileFacts {
    /// Same-file `fn` names whose declared return type owns no `Drop`.
    non_dropping_return_functions: HashMap<Box<str>, bool>,
    /// Every `(struct, field)` this file declares. `None` marks a pair the
    /// file states more than once, which no longer picks a declaration.
    struct_fields: HashMap<(Box<str>, Box<str>), Option<RustFieldDeclaration>>,
    /// Structs this file declares whose values provably run no destructor:
    /// every field is a primitive or another such struct, the struct takes no
    /// type parameters, and this file states no `impl Drop` for it.
    plain_structs: HashSet<Box<str>>,
}

fn rust_file_facts(prepared: &PreparedSyntaxTree) -> RustFileFacts {
    let source = prepared.source();
    let mut non_dropping_return_functions: HashMap<Box<str>, bool> = HashMap::default();
    let mut struct_fields: HashMap<(Box<str>, Box<str>), Option<RustFieldDeclaration>> =
        HashMap::default();
    // Every struct this file declares, with the field types it states, plus
    // the names this file declares more than once and the names it implements
    // `Drop` for. Both disqualify a struct from the plainness fixpoint below.
    let mut declared_fields: HashMap<Box<str>, Vec<Node<'_>>> = HashMap::default();
    let mut disqualified: HashSet<Box<str>> = HashSet::default();
    let mut every_struct_drops = false;
    let mut stack = vec![prepared.tree().root_node()];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "function_item" => {
                if let Some(name) = node
                    .child_by_field_name("name")
                    .and_then(|name| node_text(source, name))
                {
                    let non_dropping = node
                        .child_by_field_name("return_type")
                        .is_some_and(rust_type_is_definitely_non_dropping);
                    non_dropping_return_functions
                        .entry(name.into())
                        .and_modify(|agreed| *agreed = *agreed && non_dropping)
                        .or_insert(non_dropping);
                }
            }
            "struct_item" => {
                if let Some(name) = node
                    .child_by_field_name("name")
                    .and_then(|name| node_text(source, name))
                {
                    let fields = node
                        .child_by_field_name("body")
                        .filter(|body| body.kind() == "field_declaration_list")
                        .map(named_children)
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|child| child.kind() == "field_declaration")
                        .collect::<Vec<_>>();
                    for field in &fields {
                        let Some(field_name) = field
                            .child_by_field_name("name")
                            .and_then(|name| node_text(source, name))
                        else {
                            continue;
                        };
                        let declaration = field
                            .child_by_field_name("name")
                            .and_then(|name| source_anchor(name, 0).ok())
                            .map(|anchor| RustFieldDeclaration {
                                anchor,
                                primitive: field
                                    .child_by_field_name("type")
                                    .is_some_and(|ty| ty.kind() == "primitive_type"),
                                shape: field
                                    .child_by_field_name("type")
                                    .and_then(|ty| rust_declared_type_shape(source, ty)),
                            });
                        match struct_fields.entry((name.into(), field_name.into())) {
                            std::collections::hash_map::Entry::Vacant(entry) => {
                                entry.insert(declaration);
                            }
                            std::collections::hash_map::Entry::Occupied(mut entry) => {
                                entry.insert(None);
                            }
                        }
                    }
                    if node.child_by_field_name("type_parameters").is_some()
                        || declared_fields.insert(name.into(), fields).is_some()
                    {
                        disqualified.insert(name.into());
                    }
                }
            }
            "impl_item" => {
                let implements_drop = node
                    .child_by_field_name("trait")
                    .and_then(|declared| node_text(source, declared))
                    .is_some_and(|declared| declared.trim_end_matches('>').ends_with("Drop"));
                if implements_drop {
                    match node
                        .child_by_field_name("type")
                        .filter(|declared| declared.kind() == "type_identifier")
                        .and_then(|declared| node_text(source, declared))
                    {
                        Some(name) => {
                            disqualified.insert(name.into());
                        }
                        // A `Drop` implementation whose subject is not a plain
                        // name -- a generic instantiation, a path, a tuple --
                        // names a type this prescan does not identify, so no
                        // struct in this file keeps its plainness proof.
                        None => every_struct_drops = true,
                    }
                }
            }
            _ => {}
        }
        stack.extend(named_children(node));
    }

    // A struct is plain when every field is a primitive or another plain
    // struct. The fixpoint grows the proven set until it stops changing, which
    // terminates because the set only grows and is bounded by the file's
    // declarations. A cyclic `struct A { b: B }`/`struct B { a: A }` is
    // impossible in Rust without indirection, and indirection is not a
    // primitive type, so a cycle simply never enters the set.
    let mut plain_structs: HashSet<Box<str>> = HashSet::default();
    if !every_struct_drops {
        loop {
            let mut grew = false;
            for (name, fields) in &declared_fields {
                if disqualified.contains(name) || plain_structs.contains(name) {
                    continue;
                }
                let plain = fields.iter().all(|field| {
                    field.child_by_field_name("type").is_some_and(|ty| {
                        ty.kind() == "primitive_type"
                            || node_text(source, ty)
                                .is_some_and(|declared| plain_structs.contains(declared))
                    })
                });
                if plain {
                    plain_structs.insert(name.clone());
                    grew = true;
                }
            }
            if !grew {
                break;
            }
        }
    }

    RustFileFacts {
        non_dropping_return_functions,
        struct_fields,
        plain_structs,
    }
}

/// Whether iterating this expression yields elements that own no `Drop`.
///
/// A range is the case that decides: `Range<T>` implements `Iterator` only for
/// `T: Step`, and every `Step` type is a `Copy` primitive (an integer or
/// `char`). Iterating any other expression yields elements of a type this
/// adapter cannot see, so it answers `false`.
fn rust_iteration_element_is_definitely_non_dropping(iterable: Node<'_>) -> bool {
    iterable.kind() == "range_expression"
}

/// The outcome a literal branch condition fixes, when it is literal.
///
/// `if true` and `if false` -- and the same wrapped in parentheses -- decide
/// their branch at compile time.
fn rust_constant_condition(condition: Node<'_>) -> Option<bool> {
    let mut cursor = condition;
    loop {
        match cursor.kind() {
            "true" => return Some(true),
            "false" => return Some(false),
            // `boolean_literal` wraps the `true`/`false` keyword, which the
            // grammar spells as an anonymous token.
            "boolean_literal" => cursor = cursor.child(0)?,
            "parenthesized_expression" => cursor = first_named_child(cursor)?,
            _ => return None,
        }
    }
}

/// Whether iterating this expression provably yields at least one element.
///
/// Only a literal integer range answers `true`: `0..3` has three elements and
/// `0..=3` has four, both known from the two literal bounds and the range
/// operator. A suffixed or separated literal (`3u32`, `1_000`) does not parse
/// here and answers `false`, which only keeps a zero-iteration path the loop
/// may not have.
fn rust_iteration_yields_an_element(iterable: Node<'_>, source: &str) -> bool {
    if iterable.kind() != "range_expression" || iterable.child_count() != 3 {
        return false;
    }
    let literal = |index: usize| {
        iterable
            .child(index)
            .filter(|node| node.kind() == "integer_literal")
            .and_then(|node| node_text(source, node))
            .and_then(|text| text.parse::<i128>().ok())
    };
    let (Some(start), Some(end)) = (literal(0), literal(2)) else {
        return false;
    };
    match iterable.child(1).map(|operator| operator.kind()) {
        Some("..") => start < end,
        Some("..=") => start <= end,
        _ => false,
    }
}

/// Whether this operator can abort the procedure.
///
/// Rust arithmetic aborts on overflow in a debug profile and on division by
/// zero in every profile; a shift aborts when the amount exceeds the operand
/// width; a dereference aborts on an invalid pointer. Comparison, boolean,
/// bitwise, and negation-free operators cannot. The operator is read from the
/// node, not matched against source text.
fn rust_operation_can_abort(node: Node<'_>) -> bool {
    match node.kind() {
        "binary_expression" => node
            .child_by_field_name("operator")
            .is_some_and(|operator| {
                matches!(operator.kind(), "+" | "-" | "*" | "/" | "%" | "<<" | ">>")
            }),
        // `unary_expression` spells its operator as an anonymous first child.
        "unary_expression" => node
            .child(0)
            .is_some_and(|operator| matches!(operator.kind(), "-" | "*")),
        "compound_assignment_expr" => {
            node.child_by_field_name("operator")
                .is_some_and(|operator| {
                    matches!(
                        operator.kind(),
                        "+=" | "-=" | "*=" | "/=" | "%=" | "<<=" | ">>="
                    )
                })
        }
        // Indexing aborts on an out-of-range index, and a field projection
        // reaches its field through an autoderef chain whose `Deref`
        // implementation this adapter has not resolved and cannot rule out.
        "index_expression" | "field_expression" => true,
        _ => false,
    }
}

fn rust_parameters_may_require_drop(callable: Node<'_>) -> bool {
    callable
        .child_by_field_name("parameters")
        .map(named_children)
        .is_some_and(|parameters| {
            parameters
                .into_iter()
                .any(|parameter| !rust_parameter_is_definitely_non_dropping(parameter))
        })
}

fn runtime_expression_children(node: Node<'_>) -> Vec<Node<'_>> {
    match node.kind() {
        "binary_expression" | "assignment_expression" | "compound_assignment_expr" => [
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ]
        .into_iter()
        .flatten()
        .collect(),
        "field_expression" | "reference_expression" | "type_cast_expression" => {
            node.child_by_field_name("value").into_iter().collect()
        }
        "let_condition" => node.child_by_field_name("value").into_iter().collect(),
        "unary_expression"
        | "parenthesized_expression"
        | "await_expression"
        | "try_expression"
        | "yield_expression"
        | "return_expression" => first_named_child(node).into_iter().collect(),
        "generic_function" => node.child_by_field_name("function").into_iter().collect(),
        "struct_expression" => node
            .child_by_field_name("body")
            .map(runtime_expression_children)
            .unwrap_or_default(),
        "field_initializer" => node.child_by_field_name("value").into_iter().collect(),
        "base_field_initializer" => first_named_child(node).into_iter().collect(),
        "index_expression"
        | "array_expression"
        | "tuple_expression"
        | "range_expression"
        | "field_initializer_list"
        | "let_chain"
        | "arguments" => named_children(node)
            .into_iter()
            .filter(|child| !is_compile_time_syntax(child.kind()))
            .collect(),
        _ => Vec::new(),
    }
}

fn execution_node(node: Node<'_>) -> Node<'_> {
    if node.kind() == "expression_statement" {
        first_named_child(node)
            .filter(|expression| {
                !matches!(
                    expression.kind(),
                    "return_expression" | "break_expression" | "continue_expression"
                )
            })
            .unwrap_or(node)
    } else {
        node
    }
}

fn block_tail_expression(block: Node<'_>) -> Option<Node<'_>> {
    let tail = named_children(block)
        .into_iter()
        .rfind(|child| child.kind() != "label")?;
    if tail.kind() == "expression_statement" {
        if direct_child_kind(tail, ";") {
            None
        } else {
            first_named_child(tail).filter(|expression| is_rust_expression(expression.kind()))
        }
    } else {
        is_rust_expression(tail.kind()).then_some(tail)
    }
}

fn rust_boolean_operator(node: Node<'_>) -> Option<&'static str> {
    match node.child_by_field_name("operator")?.kind() {
        "&&" => Some("&&"),
        "||" => Some("||"),
        _ => None,
    }
}

fn control_label(node: Node<'_>, source: &str) -> Option<Box<str>> {
    direct_named_child_kind(node, "label")
        .and_then(|label| node_text(source, label))
        .map(Box::<str>::from)
}

fn direct_named_child_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}

fn direct_child_kind(node: Node<'_>, kind: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor).any(|child| child.kind() == kind)
}

fn condition_introduces_pattern_bindings(node: Node<'_>) -> bool {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "let_condition" {
            return true;
        }
        if current.id() != node.id()
            && matches!(
                current.kind(),
                "function_item" | "closure_expression" | "async_block" | "gen_block"
            )
        {
            continue;
        }
        stack.extend(named_children(current));
    }
    false
}

fn is_rust_expression(kind: &str) -> bool {
    is_runtime_leaf(kind)
        || is_runtime_container(kind)
        || matches!(
            kind,
            "call_expression"
                | "closure_expression"
                | "async_block"
                | "gen_block"
                | "if_expression"
                | "match_expression"
                | "loop_expression"
                | "while_expression"
                | "for_expression"
                | "break_expression"
                | "continue_expression"
                | "return_expression"
                | "try_expression"
                | "try_block"
                | "await_expression"
                | "yield_expression"
                | "macro_invocation"
                | "block"
                | "unsafe_block"
                | "const_block"
                | "let_condition"
                | "let_chain"
                | "generic_function"
        )
}

fn is_runtime_container(kind: &str) -> bool {
    matches!(
        kind,
        "binary_expression"
            | "assignment_expression"
            | "compound_assignment_expr"
            | "field_expression"
            | "index_expression"
            | "array_expression"
            | "tuple_expression"
            | "range_expression"
            | "reference_expression"
            | "unary_expression"
            | "parenthesized_expression"
            | "type_cast_expression"
            | "struct_expression"
            | "field_initializer_list"
            | "field_initializer"
            | "shorthand_field_initializer"
            | "base_field_initializer"
            | "arguments"
    )
}

fn implicit_runtime_call_reason(kind: &str) -> Option<&'static str> {
    match kind {
        "binary_expression" => Some(
            "operator traits and comparison traits may be invoked implicitly; no fabricated trait call site is emitted",
        ),
        "assignment_expression" => Some(
            "assignment place evaluation may invoke DerefMut or IndexMut and replacing the old value may invoke Drop::drop; no fabricated call sites are emitted",
        ),
        "compound_assignment_expr" => Some(
            "compound assignment may invoke an operator-assignment trait, implicit place adjustments, and Drop::drop for a replaced value; no fabricated call sites are emitted",
        ),
        "field_expression" => Some(
            "field projection may require implicit autoderef operations that are not emitted as call sites",
        ),
        "index_expression" => Some(
            "indexing may invoke Index or IndexMut implicitly; no fabricated trait call site is emitted",
        ),
        "unary_expression" => Some(
            "unary operators and dereference may invoke operator or Deref traits that are not emitted as call sites",
        ),
        _ => None,
    }
}

fn is_runtime_leaf(kind: &str) -> bool {
    kind.ends_with("_literal")
        || matches!(
            kind,
            "identifier"
                | "scoped_identifier"
                | "field_identifier"
                | "self"
                | "super"
                | "crate"
                | "metavariable"
                | "unit_expression"
                | "true"
                | "false"
        )
}

fn is_compile_time_syntax(kind: &str) -> bool {
    kind.starts_with("type_")
        || kind.ends_with("_type")
        || matches!(
            kind,
            "type_identifier"
                | "scoped_type_identifier"
                | "generic_type"
                | "generic_type_with_turbofish"
                | "type_arguments"
                | "type_parameters"
                | "where_clause"
                | "attribute_item"
                | "inner_attribute_item"
                | "visibility_modifier"
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
    matches!(kind, "line_comment" | "block_comment")
}

fn required_field<'tree>(node: Node<'tree>, field: &str) -> Result<Node<'tree>, RustLoweringError> {
    node.child_by_field_name(field)
        .ok_or_else(|| missing_field(node, field))
}

fn missing_field(node: Node<'_>, field: &str) -> RustLoweringError {
    RustLoweringError::Invalid(format!(
        "{} node at bytes {}..{} is missing structured field {field}",
        node.kind(),
        node.start_byte(),
        node.end_byte()
    ))
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
