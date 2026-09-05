//! Scala lowering into the language-neutral executable-semantics IR.

use brokk_bifrost_jvm::scala::graph::syntax::is_scala_named_argument_assignment;
use brokk_bifrost_jvm::scala::structural::named_argument_parts;
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
use crate::analyzer::tree_walk::{named_children, subtree_contains};
use crate::analyzer::{DispatchExtensibility, Language, ProjectFile, ScalaAnalyzer};
use crate::hash::HashMap;
use std::sync::Arc;

const ADAPTER_VERSION: &[u8] = b"scala-value-semantics-v8";

/// Bound on the expression nodes examined while proving that a result
/// expression already carries the callable's declared result type. The
/// congruence is structurally finite, but a pathological body must not make
/// each return proof walk an unbounded subtree.
const SCALA_RESULT_IDENTITY_NODE_BUDGET: usize = 64;

impl_program_semantics_provider!(ScalaAnalyzer, ScalaSemanticLowerer);

struct ScalaSemanticLowerer;

impl ProgramSemanticsLowerer for ScalaSemanticLowerer {
    fn identity(&self) -> SemanticAdapterIdentity {
        SemanticAdapterIdentity {
            adapter: AdapterSemanticsVersion::hash_bytes("scala", ADAPTER_VERSION)
                .expect("adapter name is non-empty"),
            configuration: ConfigurationFingerprint::hash_bytes(
                b"scala-intrafile-execution-defaults-v1",
            ),
            dependencies: DependencyFingerprint::hash_bytes(b"no-intrafile-dependencies"),
        }
    }

    fn capabilities(&self) -> SemanticCapabilities {
        scala_capabilities()
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

        lower_procedure_batch(
            &specs,
            initial_work,
            budget,
            cancellation,
            |spec, staged_budget, cancellation| {
                lower_procedure(prepared, spec, staged_budget, cancellation)
            },
        )
    }
}

fn scala_capabilities() -> SemanticCapabilities {
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
        SemanticCapability::FieldMemory,
        SemanticCapability::StaticMemory,
        SemanticCapability::IndexMemory,
        SemanticCapability::Captures,
        SemanticCapability::DeferredExecution,
        SemanticCapability::ConcurrentSpawn,
        SemanticCapability::NonLocalControl,
        SemanticCapability::ResourceManagement,
        // `Partial` states the exact limit: a condition that folds to a
        // constant boolean -- through any number of `!` and parenthesis
        // wrappers -- publishes one row naming the single arm the fold kept,
        // and no other Scala condition publishes a row at all. An absent row
        // therefore means "not a constant fold", never "no decision" (#2443).
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
}

type ProcedureEnumeration<'tree> = ProcedureInventoryOutcome<Vec<ProcedureSpec<'tree>>>;

struct ProcedureEnumerationFrame<'tree> {
    node: Node<'tree>,
    lexical_parent: Option<ProcedureId>,
    declaration_path: usize,
    member_context: bool,
    synthetic_body_scope: Option<SyntheticBodyScope>,
}

#[derive(Debug, Clone, Copy)]
struct SyntheticBodyScope {
    procedure: ProcedureId,
    callable_path: usize,
}

fn enumerate_procedures<'tree>(
    file: &ProjectFile,
    prepared: &'tree PreparedSyntaxTree,
    budget: &SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<ProcedureEnumeration<'tree>, SemanticProviderError> {
    let root = prepared.tree().root_node();
    let mut inventory =
        ProcedureInventoryBuilder::new(file, prepared.dialect(), root, "scala-source", budget)?;
    let mut specs = Vec::new();
    let mut stack = vec![ProcedureEnumerationFrame {
        node: root,
        lexical_parent: None,
        declaration_path: inventory.root_path(),
        member_context: false,
        synthetic_body_scope: None,
    }];

    while let Some(frame) = stack.pop() {
        if cancellation.is_cancelled() {
            return Ok(inventory.cancelled());
        }
        if let Err(stop) = inventory.charge_traversal_entry() {
            return Ok(stop.into_outcome());
        }

        let mut child_path = frame.declaration_path;
        let mut child_member_context = frame.member_context;
        if let Some(segment_kind) = declaration_container_kind(frame.node) {
            let name = callable_name(prepared.source(), frame.node);
            let anchor =
                source_anchor(frame.node, 0).map_err(SemanticProviderError::invalid_identity)?;
            child_path =
                inventory.push_container(child_path, segment_kind, name.as_deref(), anchor)?;
            child_member_context = segment_kind == DeclarationSegmentKind::Type;
        }

        let mut callable_body_scope = None;
        let mut self_callable_scope = None;
        if let Some((kind, segment_kind, body, properties, attach_lexical_parent)) = callable_shape(
            prepared.source(),
            frame.node,
            frame.lexical_parent,
            frame.member_context,
        ) {
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
            });
            let callable_path = identity.declaration_path;
            if body.id() == frame.node.id() && attach_lexical_parent {
                self_callable_scope = Some((identity.id, callable_path));
            } else {
                callable_body_scope =
                    Some((body.id(), identity.id, callable_path, attach_lexical_parent));
            }
        }

        let children = named_children(frame.node);
        for child in children.into_iter().rev() {
            let (lexical_parent, declaration_path, member_context, synthetic_body_scope) =
                if let Some((_, procedure, path, attach)) =
                    callable_body_scope.filter(|(body_id, _, _, _)| *body_id == child.id())
                {
                    if attach {
                        (Some(procedure), path, false, None)
                    } else {
                        (
                            frame.lexical_parent,
                            child_path,
                            child_member_context,
                            Some(SyntheticBodyScope {
                                procedure,
                                callable_path: path,
                            }),
                        )
                    }
                } else if let Some(synthetic) = frame.synthetic_body_scope {
                    if is_template_member_declaration(child) {
                        (frame.lexical_parent, frame.declaration_path, true, None)
                    } else {
                        (
                            Some(synthetic.procedure),
                            synthetic.callable_path,
                            false,
                            None,
                        )
                    }
                } else if let Some((procedure, path)) = self_callable_scope {
                    (Some(procedure), path, false, None)
                } else {
                    (frame.lexical_parent, child_path, child_member_context, None)
                };
            stack.push(ProcedureEnumerationFrame {
                node: child,
                lexical_parent,
                declaration_path,
                member_context,
                synthetic_body_scope,
            });
        }
    }

    Ok(inventory.complete(specs))
}

fn declaration_container_kind(node: Node<'_>) -> Option<DeclarationSegmentKind> {
    match node.kind() {
        "class_definition" | "object_definition" | "trait_definition" | "enum_definition" => {
            Some(DeclarationSegmentKind::Type)
        }
        "package_clause" | "package_object" => Some(DeclarationSegmentKind::Namespace),
        _ => None,
    }
}

fn is_template_member_declaration(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_definition"
            | "function_declaration"
            | "type_definition"
            | "class_definition"
            | "object_definition"
            | "trait_definition"
            | "enum_definition"
            | "enum_case_definitions"
            | "full_enum_case"
            | "simple_enum_case"
            | "given_definition"
            | "extension_definition"
            | "import_declaration"
            | "export_declaration"
            | "package_clause"
            | "package_object"
    )
}

fn callable_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    let name = node
        .child_by_field_name("name")
        .and_then(|name| node_text(source, name))
        .filter(|name| !name.is_empty());
    if name == Some("this") {
        let mut parent = node.parent();
        while let Some(candidate) = parent {
            if matches!(
                candidate.kind(),
                "class_definition" | "object_definition" | "trait_definition"
            ) {
                return candidate
                    .child_by_field_name("name")
                    .and_then(|name| node_text(source, name))
                    .map(Box::<str>::from);
            }
            parent = candidate.parent();
        }
    }
    name.map(Box::<str>::from)
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
    bool,
)> {
    let (kind, segment_kind, body, invocation, synthetic, attach_lexical_parent) = match node.kind()
    {
        "function_definition" => {
            let body = node.child_by_field_name("body")?;
            let is_secondary_constructor = node
                .child_by_field_name("name")
                .and_then(|name| node_text(source, name))
                == Some("this");
            let (kind, segment_kind) = if is_secondary_constructor {
                (
                    ProcedureKind::Constructor,
                    DeclarationSegmentKind::Constructor,
                )
            } else if member_context {
                (ProcedureKind::Method, DeclarationSegmentKind::Method)
            } else if lexical_parent.is_some() {
                (
                    ProcedureKind::LocalFunction,
                    DeclarationSegmentKind::LocalFunction,
                )
            } else {
                (ProcedureKind::Function, DeclarationSegmentKind::Function)
            };
            (
                kind,
                segment_kind,
                body,
                ProcedureInvocationKind::Immediate,
                false,
                true,
            )
        }
        "lambda_expression" => (
            ProcedureKind::Lambda,
            DeclarationSegmentKind::Lambda,
            lambda_body(node)?,
            ProcedureInvocationKind::Immediate,
            false,
            true,
        ),
        "case_block" if case_block_is_partial_function(node) => (
            ProcedureKind::Closure,
            DeclarationSegmentKind::Closure,
            node,
            ProcedureInvocationKind::Immediate,
            false,
            true,
        ),
        "class_definition" => (
            ProcedureKind::Constructor,
            DeclarationSegmentKind::Constructor,
            node.child_by_field_name("body").unwrap_or(node),
            ProcedureInvocationKind::Immediate,
            true,
            false,
        ),
        "object_definition" | "trait_definition" => (
            ProcedureKind::Initializer,
            DeclarationSegmentKind::Initializer,
            node.child_by_field_name("body").unwrap_or(node),
            ProcedureInvocationKind::Deferred,
            true,
            false,
        ),
        "given_definition" => {
            let body = node.child_by_field_name("body")?;
            let parameterized = !children_by_field_name(node, "parameters").is_empty();
            (
                if parameterized {
                    ProcedureKind::Function
                } else {
                    ProcedureKind::Initializer
                },
                if parameterized {
                    DeclarationSegmentKind::Function
                } else {
                    DeclarationSegmentKind::Initializer
                },
                body,
                if parameterized {
                    ProcedureInvocationKind::Immediate
                } else {
                    ProcedureInvocationKind::Deferred
                },
                false,
                true,
            )
        }
        _ => return None,
    };
    let enclosing_template = enclosing_template_kind(node);
    let object_member = enclosing_template == Some("object_definition");
    let is_static = matches!(
        kind,
        ProcedureKind::Function
            | ProcedureKind::LocalFunction
            | ProcedureKind::Lambda
            | ProcedureKind::Closure
    ) || object_member;
    let dispatch_extensibility = if matches!(
        kind,
        ProcedureKind::Constructor
            | ProcedureKind::Function
            | ProcedureKind::LocalFunction
            | ProcedureKind::Lambda
            | ProcedureKind::Closure
    ) || object_member
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
            is_async: false,
            is_generator: false,
            is_static,
            is_synthetic: synthetic,
            invocation,
            dispatch_extensibility,
        },
        attach_lexical_parent,
    ))
}

fn enclosing_template_kind(mut node: Node<'_>) -> Option<&'static str> {
    while let Some(parent) = node.parent() {
        match parent.kind() {
            "class_definition" => return Some("class_definition"),
            "object_definition" => return Some("object_definition"),
            "trait_definition" => return Some("trait_definition"),
            "enum_definition" => return Some("enum_definition"),
            "function_definition" | "lambda_expression" | "case_block" => return None,
            _ => node = parent,
        }
    }
    None
}

fn case_block_is_partial_function(node: Node<'_>) -> bool {
    !node.parent().is_some_and(|parent| {
        matches!(
            parent.kind(),
            "match_expression" | "catch_clause" | "try_expression"
        )
    })
}

fn lambda_body(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("body")
        .or_else(|| named_children(node).into_iter().next_back())
}

type ScalaLoweringError = ProcedureLoweringError;

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

#[derive(Debug, Clone, Copy)]
struct CleanupRegion<'tree> {
    id: CleanupRegionId,
    body: Node<'tree>,
    outer_scope: ScopeFrameId,
}

struct LoweringContext<'tree, 'targets> {
    prepared: &'tree PreparedSyntaxTree,
    session: ProcedureLoweringSession<'targets>,
    callable: Node<'tree>,
    procedure_kind: ProcedureKind,
    procedure_body_node_id: usize,
    expression_values: HashMap<usize, ValueId>,
    parameters: HashMap<Box<str>, ValueId>,
    parameter_types: HashMap<Box<str>, ScalaTypeIdentityId>,
    type_identities: Vec<Arc<[String]>>,
    type_identity_ids: HashMap<Arc<[String]>, ScalaTypeIdentityId>,
    locals: HashMap<Box<str>, Vec<LocalBinding>>,
    receiver: Option<ValueId>,
    cleanups: Vec<CleanupRegion<'tree>>,
    /// One value per distinct constant index spelling, so a store through
    /// `x(0)` and a load from `x(0)` name the same index operand. Java's
    /// `index_value` keeps the same interning for `a[0]`.
    constant_index_values: HashMap<Box<str>, ValueId>,
    /// The exception binder each catch dispatcher binds the thrown value to,
    /// for the precise single-catch shape only. Java keeps the same map.
    catch_binders: HashMap<ProgramPointId, ValueId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScalaTypeIdentityId(usize);

struct LocalBinding {
    declaration_start: usize,
    visible_from: usize,
    scope_start: usize,
    scope_end: usize,
    value: ValueId,
    type_identity: Option<ScalaTypeIdentityId>,
    /// For a binding whose type is `Array[T]`, the identity of `T`. Scala's
    /// arrays are invariant and their element type is exactly the written
    /// type argument, so a selection on `values(i)` resolves against it.
    element_identity: Option<ScalaTypeIdentityId>,
}

fn lower_procedure<'tree>(
    prepared: &'tree PreparedSyntaxTree,
    spec: &ProcedureSpec<'tree>,
    budget: &SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<(ProcedureSemanticsParts, SemanticWork), ScalaLoweringError> {
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
        callable: spec.callable,
        procedure_kind: spec.kind,
        procedure_body_node_id: spec.body.id(),
        expression_values: HashMap::default(),
        parameters: HashMap::default(),
        parameter_types: HashMap::default(),
        type_identities: Vec::new(),
        type_identity_ids: HashMap::default(),
        locals: HashMap::default(),
        receiver: None,
        cleanups: Vec::new(),
        constant_index_values: HashMap::default(),
        catch_binders: HashMap::default(),
    };
    context.emit_procedure_inputs(&mut builder, entry, spec.callable, spec.kind)?;
    context.emit_local_bindings(&mut builder, spec.body)?;

    if callable_has_by_name_parameter(spec.callable) {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::DeferredExecution,
            SemanticGapKind::Unsupported,
            "by-name parameter evaluation and repeated invocation are not lowered",
        )?;
    }
    if spec.properties.invocation == ProcedureInvocationKind::Deferred {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::DeferredExecution,
            SemanticGapKind::Unsupported,
            "Scala object, trait, or unconditional-given initialization is demand scheduled",
        )?;
    }
    let extends_clause = if spec.properties.is_synthetic {
        spec.callable.child_by_field_name("extend")
    } else {
        None
    };
    let parent_arguments = extends_clause
        .map(parent_argument_expressions)
        .unwrap_or_default();
    if spec.properties.is_synthetic
        && (spec.kind == ProcedureKind::Constructor || extends_clause.is_some())
    {
        // An unemitted implicit parent-constructor call is the same omission
        // whether or not the template spells its parents: the call site is
        // missing, which `Calls`/`Point` already states, and nothing about
        // the caller-side evaluation of a *represented* call is incomplete.
        // Java's twin (`java/semantic/control.rs`, the
        // `explicit_constructor_invocation` branch) publishes exactly this
        // pair with the default impacts; the extra `CALL_EVALUATION` profile
        // this branch used to attach made every template with an extends
        // clause value-flow-open with no fact behind it (#2664).
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unsupported,
            "implicit superclass and mixin initialization calls are not emitted as call sites",
        )?;
        // The honest content is "this lowering does not emit the implicit
        // initialization call, so its abort edge is missing", not "an unknown
        // fact makes the represented route uncertain". `Unsupported` is what
        // makes it dischargeable when no abort path in the constructor runs
        // user code, exactly as Java states the same omission.
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            "the unemitted implicit constructor and template initialization calls can complete exceptionally",
        )?;
    }

    let body_entry = context.point(&mut builder, spec.body, Vec::new())?;
    let body_next = if matches!(
        spec.kind,
        ProcedureKind::Constructor | ProcedureKind::Initializer
    ) {
        EdgeTarget::normal(normal_exit)
    } else {
        let implicit_return = context.point(&mut builder, spec.body, Vec::new())?;
        let result_node = implicit_result_node(spec.body);
        let result = result_node
            .map(|node| context.expression_value(&mut builder, node, expression_value_kind(node)))
            .transpose()?;
        let value = context.value(&mut builder, implicit_return, SemanticValueKind::Return)?;
        if let Some(result) = result
            && result_node.is_some_and(|node| context.callable_result_has_identity_conversion(node))
        {
            context.append_effect(
                &mut builder,
                implicit_return,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Return,
                    source: result,
                    target: value,
                },
            )?;
        } else if result.is_some()
            && !callable_declares_unit_result(spec.callable, context.prepared.source())
        {
            // A declared `Unit` result is a value discard: the body value is
            // dropped, no conversion applies, and the return carries nothing,
            // so omitting both the flow and the gap is the proven lowering.
            context.session.add_gap_with_impacts(
                &mut builder,
                entry,
                SemanticGapSubject::Value(value),
                SemanticCapability::Values,
                SemanticGapImpacts::single(SemanticGapImpact::ReturnTransfer),
                SemanticGapKind::Unknown,
                "Scala result adaptation may apply an implicit conversion before the method returns",
            )?;
        }
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
        EdgeTarget::normal(implicit_return)
    };
    // `callable_shape` retains a bodyless template's declaration as its source
    // anchor. Its structured parent-constructor arguments still execute before
    // the template body, while the declaration itself is not an expression.
    let bodyless_template = spec.properties.is_synthetic && spec.body.id() == spec.callable.id();
    let mut pending = if bodyless_template {
        context.edge(&mut builder, body_entry, body_next)?;
        Vec::new()
    } else {
        vec![Work::Expression {
            node: spec.body,
            entry: body_entry,
            next: body_next,
            scope: function_scope,
        }]
    };
    context.schedule_expressions(
        &mut builder,
        entry,
        &parent_arguments,
        EdgeTarget::normal(body_entry),
        function_scope,
        &mut pending,
    )?;
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
        procedure_kind: ProcedureKind,
    ) -> Result<(), ScalaLoweringError> {
        let layout =
            formal_parameter_slots_for_owner(Language::Scala, callable, self.prepared.source())
                .unwrap_or_default();
        let mut ordinal = 0_u32;
        for slot in layout.slots {
            if self.session.cancellation().is_cancelled() {
                return Err(ScalaLoweringError::Cancelled(Box::new(
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
                    SemanticValueKind::Receiver { dispatch: false },
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
                    ScalaLoweringError::Invalid("too many formal parameters".into())
                })?;
                value
            };
            let type_identity = (!slot.receiver)
                .then(|| node.child_by_field_name("type"))
                .flatten()
                .and_then(|type_node| self.intern_type_identity(type_node));
            for name in slot.names {
                if let Some(type_identity) = type_identity {
                    self.parameter_types
                        .insert(name.clone().into_boxed_str(), type_identity);
                }
                self.parameters.insert(name.into_boxed_str(), value);
            }
            if contains_token(node, "using") || contains_token(node, "implicit") {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Value(value),
                    SemanticCapability::ParameterFlow,
                    SemanticGapKind::Unsupported,
                    "Scala contextual parameter binding requires implicit or given resolution",
                )?;
            }
        }

        if self.receiver.is_none()
            && matches!(
                procedure_kind,
                ProcedureKind::Method | ProcedureKind::Constructor | ProcedureKind::Initializer
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
            self.parameters.insert("super".into(), receiver);
        }

        if enclosing_extension_definition(callable).is_some() {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Procedure,
                SemanticCapability::ParameterFlow,
                SemanticGapKind::Unsupported,
                "Scala extension receiver and contextual argument binding require extension resolution",
            )?;
        }
        Ok(())
    }

    fn emit_local_bindings(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        body: Node<'tree>,
    ) -> Result<(), ScalaLoweringError> {
        try_walk_named_tree_preorder(body, true, |node| {
            if self.session.cancellation().is_cancelled() {
                return Err(ScalaLoweringError::Cancelled(Box::new(
                    builder.prospective_work(),
                )));
            }
            if node.id() != body.id() && is_scala_nested_execution_boundary(node) {
                return Ok(WalkControl::SkipChildren);
            }
            if matches!(node.kind(), "val_definition" | "var_definition")
                && let Some(pattern) = node.child_by_field_name("pattern")
                && pattern.kind() == "identifier"
                && let Some(name) = node_text(self.prepared.source(), pattern)
                && let Some((scope_start, scope_end)) = scala_local_scope(node, body)
            {
                let metadata = self.value_mapping(builder, pattern)?;
                let value = self.session.add_value_with_metadata(
                    builder,
                    metadata,
                    SemanticValueKind::Local,
                )?;
                // An unannotated binding takes the type its initializer
                // determines, so a later reassignment or operator application
                // can be proven against it. The preorder walk has already
                // registered every binding an initializer can name.
                let declared = node.child_by_field_name("type");
                let initializer = node.child_by_field_name("value");
                let inferred =
                    initializer.and_then(|initializer| self.expression_type_identity(initializer));
                let type_identity = declared
                    .and_then(|type_node| self.intern_type_identity(type_node))
                    .or_else(|| inferred.map(|identity| self.intern_type_segments(identity)));
                let declared_element = declared.and_then(|type_node| {
                    scala_array_element_type_node(type_node, self.prepared.source())
                });
                let element_identity = declared_element
                    .and_then(|element| self.intern_type_identity(element))
                    .or_else(|| {
                        initializer
                            .and_then(|initializer| self.array_element_identity(initializer))
                            .map(|identity| self.intern_type_segments(identity))
                    });
                self.locals
                    .entry(name.into())
                    .or_default()
                    .push(LocalBinding {
                        declaration_start: pattern.start_byte(),
                        visible_from: node.end_byte(),
                        scope_start,
                        scope_end,
                        value,
                        type_identity,
                        element_identity,
                    });
            }
            // A `case caught: T =>` arm binds the thrown or matched value to
            // `caught` with a written type. Registering it as a local is what
            // lets a selection on the binder resolve its member, and what
            // gives the catch binder a value for the throw to flow into.
            if node.kind() == "case_clause"
                && let Some(pattern) = node.child_by_field_name("pattern")
                && let Some((binder, declared)) = typed_pattern_binding(pattern)
                && let Some(name) = node_text(self.prepared.source(), binder)
                && let Some((scope_start, scope_end)) = scala_local_scope(binder, body)
            {
                let metadata = self.value_mapping(builder, binder)?;
                let value = self.session.add_value_with_metadata(
                    builder,
                    metadata,
                    SemanticValueKind::Local,
                )?;
                let type_identity = self.intern_type_identity(declared);
                let declared_element =
                    scala_array_element_type_node(declared, self.prepared.source());
                let element_identity =
                    declared_element.and_then(|element| self.intern_type_identity(element));
                self.locals
                    .entry(name.into())
                    .or_default()
                    .push(LocalBinding {
                        declaration_start: binder.start_byte(),
                        visible_from: binder.end_byte(),
                        scope_start,
                        scope_end,
                        value,
                        type_identity,
                        element_identity,
                    });
            }
            Ok(WalkControl::Continue)
        })
    }

    fn local_at(&self, name: &str, byte: usize) -> Option<ValueId> {
        self.local_binding_at(name, byte)
            .map(|binding| binding.value)
    }

    fn binding_type_id_at(&self, name: &str, byte: usize) -> Option<ScalaTypeIdentityId> {
        if let Some(binding) = self.local_binding_at(name, byte) {
            return binding.type_identity;
        }
        self.parameter_types.get(name).copied()
    }

    fn intern_type_identity(&mut self, node: Node<'tree>) -> Option<ScalaTypeIdentityId> {
        let identity = scala_type_identity(node, self.prepared.source())?;
        Some(self.intern_type_segments(identity))
    }

    fn intern_type_segments(&mut self, identity: Arc<[String]>) -> ScalaTypeIdentityId {
        if let Some(id) = self.type_identity_ids.get(&identity) {
            return *id;
        }
        let id = ScalaTypeIdentityId(self.type_identities.len());
        self.type_identities.push(Arc::clone(&identity));
        self.type_identity_ids.insert(identity, id);
        id
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
    ) -> Result<ValueId, ScalaLoweringError> {
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
    ) -> Result<ValueId, ScalaLoweringError> {
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
    ) -> Result<(), ScalaLoweringError> {
        let Some(name) = node_text(self.prepared.source(), node) else {
            return Ok(());
        };
        let (source, kind) =
            if matches!(node.kind(), "this" | "super") || matches!(name, "this" | "super") {
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

    fn leaf_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
    ) -> Result<(), ScalaLoweringError> {
        let value = self.expression_value(builder, node, expression_value_kind(node))?;
        self.emit_lexical_input_flow(builder, node, entry, value)?;
        self.edge(builder, entry, next)
    }

    fn identifier_is_lexical(&self, node: Node<'tree>) -> bool {
        let Some(name) = node_text(self.prepared.source(), node) else {
            return false;
        };
        self.local_at(name, node.start_byte()).is_some() || self.parameters.contains_key(name)
    }

    fn step(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        work: Work<'tree>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), ScalaLoweringError> {
        if self.session.cancellation().is_cancelled() {
            return Err(ScalaLoweringError::Cancelled(Box::default()));
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
    ) -> Result<(), ScalaLoweringError> {
        // A folded literal keeps exactly one arm, so an `if (false)` body is
        // never reachable and the shared kill on the join is the honest
        // answer. Recording the guard is the other half of the fold: after it,
        // nothing else in the artifact says the branch was constant (#2443).
        //
        // Java folds the `true`/`false` node kinds directly
        // (`java/semantic/control.rs`); Scala's grammar spells the literal the
        // way Kotlin's does -- one `boolean_literal` node whose value is bare
        // leaf text -- so the value is read the way
        // `kotlin/semantic/control.rs` reads it, and the `!` and parenthesis
        // wrappers are peeled the way its `normalize_condition` peels them.
        if let Some(value) = constant_boolean_condition(self.prepared.source(), node) {
            let taken = if value { when_true } else { when_false };
            self.edge(builder, entry, taken)?;
            return self.record_constant_guard(builder, entry, value, taken);
        }
        match (node.kind(), infix_operator(self.prepared.source(), node)) {
            ("infix_expression", Some("&&")) => {
                let left = required_field(node, "left")?;
                let right = required_runtime_field(node, "right")?;
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
            ("infix_expression", Some("||")) => {
                let left = required_field(node, "left")?;
                let right = required_runtime_field(node, "right")?;
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
                let value = first_runtime_named_child(node)
                    .ok_or_else(|| missing_field(node, "expression"))?;
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
                if is_runtime_leaf(node.kind()) {
                    self.edge(builder, entry, when_true)?;
                    self.edge(builder, entry, when_false)?;
                    return Ok(());
                }
                let decision = self.point(builder, node, Vec::new())?;
                self.edge(builder, decision, when_true)?;
                self.edge(builder, decision, when_false)?;
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

    /// Publish the one guard fact this adapter normalizes: the constant boolean
    /// a condition fold just decided (#2443).
    ///
    /// Only the folded arm exists as an edge, so only that arm is declared.
    /// The predicate needs no subject: a constant tests nothing. Every other
    /// Scala condition publishes no row at all, which is exactly what the
    /// `Partial` [`SemanticCapability::GuardFacts`] entry claims.
    fn record_constant_guard(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        value: bool,
        taken: EdgeTarget,
    ) -> Result<(), ScalaLoweringError> {
        let arm = GuardArm {
            target_point: taken.point,
            kind: taken.kind,
        };
        let (true_arm, false_arm) = if value {
            (Some(arm), None)
        } else {
            (None, Some(arm))
        };
        self.session.add_guard_fact(
            builder,
            point,
            GuardPredicate::ConstantBoolean { value },
            None,
            true_arm,
            false_arm,
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
    ) -> Result<(), ScalaLoweringError> {
        match node.kind() {
            "block" | "indented_block" | "template_body" | "with_template_body" => {
                let children = runtime_statement_children(node);
                self.schedule_statements(builder, entry, &children, next, scope, stack)
            }
            "function_definition" | "lambda_expression" => {
                self.callable_value(builder, entry, next)
            }
            "given_definition" => {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::DeferredExecution,
                    SemanticGapKind::Unsupported,
                    "given initialization or factory execution occurs at use, not declaration",
                )?;
                self.callable_value(builder, entry, next)
            }
            "val_definition" | "var_definition" => {
                self.definition(builder, node, entry, next, scope, stack)
            }
            "function_declaration"
            | "type_definition"
            | "class_definition"
            | "object_definition"
            | "trait_definition"
            | "enum_definition"
            | "import_declaration"
            | "export_declaration" => self.edge(builder, entry, next),
            _ => self.expression(builder, node, entry, next, scope, stack),
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
    ) -> Result<(), ScalaLoweringError> {
        match node.kind() {
            "block" | "indented_block" | "template_body" | "with_template_body" => {
                let children = runtime_statement_children(node);
                self.schedule_statements(builder, entry, &children, next, scope, stack)
            }
            "if_expression" => self.if_expression(builder, node, entry, next, scope, stack),
            "while_expression" => self.while_expression(builder, node, entry, next, scope, stack),
            "do_while_expression" => {
                self.do_while_expression(builder, node, entry, next, scope, stack)
            }
            "match_expression" => self.match_expression(builder, node, entry, next, scope, stack),
            "try_expression" => self.try_expression(builder, node, entry, next, scope, stack),
            "for_expression" => self.for_expression(builder, node, entry, next, scope, stack),
            "case_block"
                if case_block_is_partial_function(node)
                    && !(self.procedure_kind == ProcedureKind::Closure
                        && node.id() == self.procedure_body_node_id) =>
            {
                self.callable_value(builder, entry, next)
            }
            "case_block" | "indented_cases" => {
                let arms = case_arms(node);
                self.case_dispatch(
                    builder,
                    node,
                    &arms,
                    entry,
                    next,
                    scope,
                    "an unmatched partial-function case raises MatchError",
                    stack,
                )
            }
            "case_clause" | "catch_clause" => {
                let body = case_body_nodes(node);
                self.schedule_statements(builder, entry, &body, next, scope, stack)
            }
            "return_expression" => self.return_expression(builder, node, entry, scope, stack),
            "throw_expression" => self.throw_expression(builder, node, entry, scope, stack),
            "call_expression" => self.call_expression(builder, node, entry, next, scope, stack),
            "instance_expression" => {
                self.instance_expression(builder, node, entry, next, scope, stack)
            }
            "generic_function" => {
                // A type application yields exactly the value its function
                // expression yields, so it relays that identity rather than
                // leaving the applied node's own value undefined.
                let function = required_field(node, "function")?;
                self.transparent_expression(builder, node, function, entry, next, scope, stack)
            }
            "postfix_expression" => {
                self.postfix_expression(builder, node, entry, next, scope, stack)
            }
            "prefix_expression" => self.prefix_expression(builder, node, entry, next, scope, stack),
            "function_definition" | "lambda_expression" => {
                self.callable_value(builder, entry, next)
            }
            "parenthesized_expression" => {
                if let Some(value) = first_runtime_named_child(node) {
                    self.transparent_expression(builder, node, value, entry, next, scope, stack)
                } else {
                    self.edge(builder, entry, next)
                }
            }
            "typed_expression" => {
                let value =
                    first_runtime_named_child(node).ok_or_else(|| missing_field(node, "value"))?;
                let terminal = self.point(builder, node, Vec::new())?;
                let target = self.expression_value(builder, node, expression_value_kind(node))?;
                self.add_gap(
                    builder,
                    terminal,
                    SemanticGapSubject::Value(target),
                    SemanticCapability::Values,
                    SemanticGapKind::Unknown,
                    "Scala type ascription may require value adaptation or an implicit conversion",
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
            "assignment_expression" => {
                self.assignment_expression(builder, node, entry, next, scope, stack)
            }
            "field_expression" => self.field_expression(builder, node, entry, next, scope, stack),
            "tuple_expression" | "arguments" | "colon_argument" => {
                let children = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            "interpolated_string_expression" => {
                for (capability, detail) in [
                    (
                        SemanticCapability::Calls,
                        "string interpolation invokes an interpolator and may invoke formatting or conversion protocols",
                    ),
                    (
                        SemanticCapability::ExceptionalControlFlow,
                        "interpolator resolution, formatting, or implicit conversion may complete exceptionally",
                    ),
                    (
                        SemanticCapability::Values,
                        "interpolator selection and formatted result values are not represented",
                    ),
                ] {
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Point,
                        capability,
                        SemanticGapKind::Unknown,
                        detail,
                    )?;
                }
                let children = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            "infix_expression" => {
                if matches!(
                    infix_operator(self.prepared.source(), node),
                    Some("&&" | "||")
                ) {
                    let right = required_runtime_field(node, "right")?;
                    let right_entry = self.point(builder, right, Vec::new())?;
                    stack.push(Work::Expression {
                        node: right,
                        entry: right_entry,
                        next,
                        scope,
                    });
                    let (when_true, when_false) =
                        if infix_operator(self.prepared.source(), node) == Some("&&") {
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
                        node: required_field(node, "left")?,
                        entry,
                        when_true,
                        when_false,
                        scope,
                    });
                    Ok(())
                } else {
                    self.infix_expression(builder, node, entry, next, scope, stack)
                }
            }
            "identifier"
                if identifier_has_auto_application_ambiguity(node)
                    && !self.identifier_is_lexical(node) =>
            {
                for (capability, kind, detail) in [
                    (
                        SemanticCapability::Calls,
                        SemanticGapKind::Unknown,
                        "unqualified identifier may auto-apply a parameterless method",
                    ),
                    (
                        // Whether the identifier applies anything is the
                        // unknown above. What this gap states is narrower and
                        // certain: no call site is emitted for a possible
                        // auto-application, so its abort edge is missing --
                        // the same omission the implicit constructor call
                        // publishes, and dischargeable on the same terms.
                        SemanticCapability::ExceptionalControlFlow,
                        SemanticGapKind::Unsupported,
                        "no call site is emitted for a possible auto-application or implicit conversion, so its abort edge is not lowered",
                    ),
                    (
                        SemanticCapability::CallableReferences,
                        SemanticGapKind::Unknown,
                        "unqualified identifier may denote a value, method application, or eta-expanded callable",
                    ),
                ] {
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Point,
                        capability,
                        kind,
                        detail,
                    )?;
                }
                self.leaf_expression(builder, node, entry, next)
            }
            kind if is_runtime_leaf(kind) => self.leaf_expression(builder, node, entry, next),
            _ => self.unsupported_expression(
                builder,
                node,
                entry,
                next,
                "Scala executable syntax is retained at a typed semantic boundary",
            ),
        }
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
    ) -> Result<(), ScalaLoweringError> {
        let condition = required_runtime_field(node, "condition")?;
        let consequence = required_field(node, "consequence")?;
        let alternative = node.child_by_field_name("alternative");
        let consequence_entry = self.point(builder, consequence, Vec::new())?;
        // A two-armed Scala `if` is an expression: the chosen arm's value is
        // the conditional's value. Each arm therefore leaves through its own
        // merge point, which carries that one flow ordered after the arm's
        // own effects. A one-armed `if` yields `Unit` and joins nothing.
        let when_false = if let Some(alternative) = alternative {
            let alternative_entry = self.point(builder, alternative, Vec::new())?;
            let consequence_merge = self.point(builder, consequence, Vec::new())?;
            let alternative_merge = self.point(builder, alternative, Vec::new())?;
            let result = self.expression_value(builder, node, expression_value_kind(node))?;
            for (merge, arm) in [
                (consequence_merge, consequence),
                (alternative_merge, alternative),
            ] {
                // A braced arm yields its own trailing expression, which is
                // the value the arm's lowering actually populates.
                let arm_result = implicit_result_node(arm).unwrap_or(arm);
                let source =
                    self.expression_value(builder, arm_result, expression_value_kind(arm_result))?;
                self.append_effect(
                    builder,
                    merge,
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Local,
                        source,
                        target: result,
                    },
                )?;
                self.edge(builder, merge, next)?;
            }
            stack.push(Work::Expression {
                node: consequence,
                entry: consequence_entry,
                next: EdgeTarget::normal(consequence_merge),
                scope,
            });
            stack.push(Work::Expression {
                node: alternative,
                entry: alternative_entry,
                next: EdgeTarget::normal(alternative_merge),
                scope,
            });
            EdgeTarget {
                point: alternative_entry,
                kind: ControlEdgeKind::ConditionalFalse,
            }
        } else {
            stack.push(Work::Expression {
                node: consequence,
                entry: consequence_entry,
                next,
                scope,
            });
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
            when_false,
            scope,
        });
        Ok(())
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
    ) -> Result<(), ScalaLoweringError> {
        let condition = required_runtime_field(node, "condition")?;
        let body = required_field(node, "body")?;
        let condition_entry = self.point(builder, condition, Vec::new())?;
        let body_entry = self.point(builder, body, Vec::new())?;
        // First-iteration peel: when the guard is provably true on entry, the
        // zero-trip path does not exist and must not be lowered as if it did.
        // Entry then reaches the body directly; the header stays reachable
        // through the body's own loop-back edge, so every later iteration is
        // still decided by the guard. This is the while-header analogue of
        // Java's `for_condition_starts_true`.
        let entry_target = if while_guard_is_true_on_entry(self.prepared.source(), node, condition)
        {
            body_entry
        } else {
            condition_entry
        };
        self.edge(builder, entry, EdgeTarget::normal(entry_target))?;
        stack.push(Work::Expression {
            node: body,
            entry: body_entry,
            next: EdgeTarget {
                point: condition_entry,
                kind: ControlEdgeKind::LoopBack,
            },
            scope,
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
            scope,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn do_while_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), ScalaLoweringError> {
        let body = required_field(node, "body")?;
        let condition = required_field(node, "condition")?;
        let body_entry = self.point(builder, body, Vec::new())?;
        let condition_entry = self.point(builder, condition, Vec::new())?;
        self.edge(builder, entry, EdgeTarget::normal(body_entry))?;
        stack.push(Work::Condition {
            node: condition,
            entry: condition_entry,
            when_true: EdgeTarget {
                point: body_entry,
                kind: ControlEdgeKind::LoopBack,
            },
            when_false: EdgeTarget {
                point: next.point,
                kind: ControlEdgeKind::ConditionalFalse,
            },
            scope,
        });
        stack.push(Work::Expression {
            node: body,
            entry: body_entry,
            next: EdgeTarget::normal(condition_entry),
            scope,
        });
        Ok(())
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
    ) -> Result<(), ScalaLoweringError> {
        let subject = required_field(node, "value")?;
        let body = required_field(node, "body")?;
        let arms = case_arms(body);
        let dispatch = self.point(builder, node, Vec::new())?;
        self.case_dispatch(
            builder,
            node,
            &arms,
            dispatch,
            next,
            scope,
            "an unmatched Scala match raises MatchError unless refinement proves an irrefutable arm",
            stack,
        )?;
        stack.push(Work::Expression {
            node: subject,
            entry,
            next: EdgeTarget::normal(dispatch),
            scope,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn case_dispatch(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        container: Node<'tree>,
        arms: &[Node<'tree>],
        dispatch: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        unmatched_detail: &str,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), ScalaLoweringError> {
        let unmatched = self.point(builder, container, Vec::new())?;
        let exception = self.value(builder, unmatched, SemanticValueKind::Exception)?;
        self.append_effect(
            builder,
            unmatched,
            SemanticEffect::Throw {
                value: Some(exception),
            },
        )?;
        self.add_gap(
            builder,
            unmatched,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unknown,
            unmatched_detail,
        )?;
        self.abrupt(builder, unmatched, scope, CompletionKind::Throw, stack)?;

        if arms.is_empty() {
            return self.edge(
                builder,
                dispatch,
                EdgeTarget {
                    point: unmatched,
                    kind: ControlEdgeKind::Exceptional,
                },
            );
        }

        let decisions = arms
            .iter()
            .map(|arm| {
                let pattern = case_pattern(*arm).unwrap_or(*arm);
                self.point(builder, pattern, Vec::new())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let body_entries = arms
            .iter()
            .map(|arm| self.point(builder, *arm, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        self.edge(builder, dispatch, EdgeTarget::normal(decisions[0]))?;

        for index in (0..arms.len()).rev() {
            let arm = arms[index];
            let no_match = decisions
                .get(index + 1)
                .copied()
                .map(|point| EdgeTarget {
                    point,
                    kind: ControlEdgeKind::ConditionalFalse,
                })
                .unwrap_or(EdgeTarget {
                    point: unmatched,
                    kind: ControlEdgeKind::ConditionalFalse,
                });
            self.add_gap(
                builder,
                decisions[index],
                SemanticGapSubject::Point,
                SemanticCapability::Calls,
                SemanticGapKind::Unknown,
                "pattern matching may invoke extractor, equality, or type-test protocols",
            )?;
            self.add_gap(
                builder,
                decisions[index],
                SemanticGapSubject::Point,
                SemanticCapability::Values,
                SemanticGapKind::Unknown,
                "pattern bindings and type refinement are not represented in control topology",
            )?;
            self.add_gap(
                builder,
                decisions[index],
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unknown,
                "extractor, equality, or type-test protocols may complete exceptionally",
            )?;
            if let Some(guard) = case_guard(arm) {
                let guard_value = first_runtime_named_child(guard).unwrap_or(guard);
                let guard_entry = self.point(builder, guard_value, Vec::new())?;
                self.edge(
                    builder,
                    decisions[index],
                    EdgeTarget {
                        point: guard_entry,
                        kind: ControlEdgeKind::SwitchCase,
                    },
                )?;
                self.edge(builder, decisions[index], no_match)?;
                stack.push(Work::Condition {
                    node: guard_value,
                    entry: guard_entry,
                    when_true: EdgeTarget {
                        point: body_entries[index],
                        kind: ControlEdgeKind::ConditionalTrue,
                    },
                    when_false: no_match,
                    scope,
                });
            } else {
                self.edge(
                    builder,
                    decisions[index],
                    EdgeTarget {
                        point: body_entries[index],
                        kind: ControlEdgeKind::SwitchCase,
                    },
                )?;
                self.edge(builder, decisions[index], no_match)?;
            }
            stack.push(Work::Expression {
                node: arm,
                entry: body_entries[index],
                next,
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
    ) -> Result<(), ScalaLoweringError> {
        let body = required_field(node, "body")?;
        let children = named_children(node);
        let catch_clause = children
            .iter()
            .copied()
            .find(|child| child.kind() == "catch_clause");
        let finalizer = children
            .iter()
            .copied()
            .find(|child| child.kind() == "finally_clause")
            .and_then(first_runtime_named_child);

        let (cleanup_scope, cleanup_region) = if let Some(finalizer) = finalizer {
            let region = CleanupRegionId::new(
                u32::try_from(self.cleanups.len())
                    .map_err(|_| ScalaLoweringError::Invalid("too many cleanup regions".into()))?,
            );
            self.cleanups.push(CleanupRegion {
                id: region,
                body: finalizer,
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

        let try_scope = if let Some(catch_clause) = catch_clause {
            let dispatcher = self.point(builder, catch_clause, Vec::new())?;
            let arms = catch_arms(catch_clause);
            let catch_exit = self.point(builder, catch_clause, Vec::new())?;
            if let Some(route) = &normal_route {
                self.route(builder, catch_exit, route, stack)?;
            } else {
                self.edge(builder, catch_exit, next)?;
            }
            // A single unguarded `case name: T =>` arm is Java's
            // `precise_single_catch`: the handler's selection is one written
            // type test, and the binder is a registered local. Nothing about
            // the dispatch is unrepresented, so the arm is wired directly and
            // the thrown value binds to the parameter, exactly as Java's
            // `catch_binders` and `abrupt_throw` do. Any other catch shape
            // keeps the pattern-dispatch lowering and its gaps.
            let precise_binder = match arms.as_slice() {
                [arm] => case_guard(*arm)
                    .is_none()
                    .then(|| case_pattern(*arm))
                    .flatten()
                    .and_then(typed_pattern_binding)
                    .and_then(|(binder, _)| {
                        node_text(self.prepared.source(), binder).and_then(|name| {
                            self.local_declaration_value(name, binder.start_byte())
                        })
                    }),
                _ => None,
            };
            if let (Some(binder), [arm]) = (precise_binder, arms.as_slice()) {
                self.catch_binders.insert(dispatcher, binder);
                let arm_entry = self.point(builder, *arm, Vec::new())?;
                self.edge(
                    builder,
                    dispatcher,
                    EdgeTarget {
                        point: arm_entry,
                        kind: ControlEdgeKind::SwitchCase,
                    },
                )?;
                let unmatched = self.point(builder, catch_clause, Vec::new())?;
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
                    stack,
                )?;
                stack.push(Work::Expression {
                    node: *arm,
                    entry: arm_entry,
                    next: EdgeTarget::normal(catch_exit),
                    scope: cleanup_scope,
                });
            } else {
                self.add_gap(
                    builder,
                    dispatcher,
                    SemanticGapSubject::Point,
                    SemanticCapability::ExceptionalControlFlow,
                    SemanticGapKind::Unknown,
                    "catch pattern compatibility and exception binding require type refinement",
                )?;
                self.case_dispatch(
                    builder,
                    catch_clause,
                    &arms,
                    dispatcher,
                    EdgeTarget::normal(catch_exit),
                    cleanup_scope,
                    "an unmatched catch pattern rethrows the original exception",
                    stack,
                )?;
            }
            builder.push_scope(
                Some(cleanup_scope),
                ScopeBinding::Handler { entry: dispatcher },
            )
        } else {
            cleanup_scope
        };

        let body_exit = self.point(builder, body, Vec::new())?;
        if let Some(route) = &normal_route {
            self.route(builder, body_exit, route, stack)?;
        } else {
            self.edge(builder, body_exit, next)?;
        }
        stack.push(Work::Expression {
            node: body,
            entry,
            next: EdgeTarget::normal(body_exit),
            scope: try_scope,
        });
        Ok(())
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
    ) -> Result<(), ScalaLoweringError> {
        let body = required_field(node, "body")?;
        let enumerators = required_runtime_field(node, "enumerators")?;
        let enumerator_nodes = named_children(enumerators)
            .into_iter()
            .filter(|child| child.kind() == "enumerator")
            .collect::<Vec<_>>();
        let first_source = enumerator_nodes
            .first()
            .and_then(|item| enumerator_rhs(*item));
        let decision = self.point(builder, enumerators, Vec::new())?;
        let body_entry = self.point(builder, body, Vec::new())?;
        for (capability, kind, detail) in [
            (
                SemanticCapability::Calls,
                SemanticGapKind::Unsupported,
                "for-comprehension map, flatMap, withFilter, and foreach protocol calls are not emitted as synthetic call sites",
            ),
            (
                SemanticCapability::DeferredExecution,
                SemanticGapKind::Unsupported,
                "later enumerators, guards, and the body execute inside desugared closures",
            ),
            (
                SemanticCapability::NormalControlFlow,
                SemanticGapKind::Unsupported,
                "collection protocol iteration count and filtering require dispatch and value refinement",
            ),
            (
                // The protocol calls and the pattern filtering this gap names
                // are exactly the ones the two gaps above state are not
                // emitted, so what is missing is their abort edges.
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unsupported,
                "no call sites are emitted for the for-comprehension protocol calls or pattern filtering, so their abort edges are not lowered",
            ),
        ] {
            self.add_gap(
                builder,
                decision,
                SemanticGapSubject::Point,
                capability,
                kind,
                detail,
            )?;
        }
        if has_direct_token(node, "yield") {
            self.add_gap(
                builder,
                decision,
                SemanticGapSubject::Point,
                SemanticCapability::Values,
                SemanticGapKind::Unsupported,
                "yielded collection construction and element value flow are not lowered",
            )?;
        }
        self.edge(
            builder,
            decision,
            EdgeTarget {
                point: body_entry,
                kind: ControlEdgeKind::ConditionalTrue,
            },
        )?;
        self.edge(
            builder,
            decision,
            EdgeTarget {
                point: next.point,
                kind: ControlEdgeKind::ConditionalFalse,
            },
        )?;
        stack.push(Work::Expression {
            node: body,
            entry: body_entry,
            next: EdgeTarget {
                point: decision,
                kind: ControlEdgeKind::LoopBack,
            },
            scope,
        });
        if let Some(first_source) = first_source {
            stack.push(Work::Expression {
                node: first_source,
                entry,
                next: EdgeTarget::normal(decision),
                scope,
            });
            Ok(())
        } else {
            self.edge(builder, entry, EdgeTarget::normal(decision))
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn definition(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), ScalaLoweringError> {
        let value = required_field(node, "value")?;
        if contains_token(node, "lazy") {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::DeferredExecution,
                SemanticGapKind::Unsupported,
                "lazy value initialization, synchronization, retry, and memoization are not lowered eagerly",
            )?;
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::Calls,
                SemanticGapKind::Unknown,
                "the deferred lazy initializer may contain calls",
            )?;
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unknown,
                "lazy initialization may throw and be retried",
            )?;
            return self.edge(builder, entry, next);
        }
        let pattern = node.child_by_field_name("pattern");
        if pattern.is_some_and(|pattern| pattern.kind() != "identifier") {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::Values,
                SemanticGapKind::Unknown,
                "destructuring definition bindings are not represented in value flow",
            )?;
        }
        let terminal = self.point(builder, node, Vec::new())?;
        if let Some(pattern) = pattern.filter(|pattern| pattern.kind() == "identifier")
            && let Some(name) = node_text(self.prepared.source(), pattern)
            && let Some(target) = self.local_declaration_value(name, pattern.start_byte())
        {
            let source = self.expression_value(builder, value, expression_value_kind(value))?;
            if self.definition_has_identity_initializer(node, value) {
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
                // A `val`/`var` written directly in a template body is that
                // template's member, and the primary constructor is where its
                // initializer runs. Without this store a later
                // `outer.middle.inner` load has no defining write anywhere,
                // which is what kept every access path through a
                // constructor-initialized member open (#2664). Java reaches
                // the same place through its per-field `Initializer`
                // procedures.
                if let Some(base) = self.receiver
                    && matches!(
                        self.procedure_kind,
                        ProcedureKind::Constructor | ProcedureKind::Initializer
                    )
                    && is_scala_template_member(node)
                {
                    let member = self.declared_member_locator(pattern)?;
                    let location = self.session.add_memory_location(
                        builder,
                        terminal,
                        MemoryLocationKind::Field { base, member },
                    )?;
                    self.append_effect(
                        builder,
                        terminal,
                        SemanticEffect::MemoryStore {
                            kind: MemoryAccessKind::Field,
                            location,
                            value: source,
                        },
                    )?;
                }
            } else {
                self.add_gap(
                    builder,
                    terminal,
                    SemanticGapSubject::Value(target),
                    SemanticCapability::Values,
                    SemanticGapKind::Unknown,
                    "Scala typed value initialization may apply an implicit conversion",
                )?;
            }
        }
        if contains_token(node, "implicit") || contains_token(node, "given") {
            self.add_gap(
                builder,
                terminal,
                SemanticGapSubject::Point,
                SemanticCapability::Values,
                SemanticGapKind::Unsupported,
                "implicit or given value selection requires contextual resolution",
            )?;
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
    fn assignment_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), ScalaLoweringError> {
        let left = required_field(node, "left").or_else(|_| required_field(node, "target"))?;
        let right = required_field(node, "right").or_else(|_| required_field(node, "value"))?;
        let terminal = self.point(builder, node, Vec::new())?;
        let mut evaluations = vec![left, right];
        let lexical_target = (left.kind() == "identifier")
            .then(|| node_text(self.prepared.source(), left))
            .flatten()
            .and_then(|name| {
                self.local_at(name, left.start_byte())
                    .map(|target| (target, ValueFlowKind::Local))
                    .or_else(|| {
                        self.parameters
                            .get(name)
                            .copied()
                            .map(|target| (target, ValueFlowKind::Parameter))
                    })
            });
        if let Some((target, kind)) = lexical_target {
            // A Scala assignment evaluates to `Unit`, so its own result needs
            // no identity gap. What can still adapt is the stored value, and
            // only when the target's type differs from the assigned type.
            if self.assigned_value_has_target_identity(left, right) {
                let source = self.expression_value(builder, right, expression_value_kind(right))?;
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
                        kind,
                        source,
                        target,
                    },
                )?;
            } else {
                self.add_gap(
                    builder,
                    terminal,
                    SemanticGapSubject::Value(target),
                    SemanticCapability::Assignments,
                    SemanticGapKind::Unknown,
                    "Scala variable reassignment is retained without assuming identity-preserving adaptation",
                )?;
            }
        } else if left.kind() == "field_expression" && self.selection_base_is_value(left) {
            // A member store, lowered exactly as Java lowers `field_access`
            // on the left of an assignment: the base is an operand, the
            // member is a located field, and the store is a heap effect.
            let object = required_field(left, "value")?;
            let field = required_field(left, "field")?;
            let source = self.expression_value(builder, right, expression_value_kind(right))?;
            let base = self.expression_value(builder, object, expression_value_kind(object))?;
            let (member, resolved) = self.memory_member_locator(field, object)?;
            let location = self.session.add_memory_location(
                builder,
                terminal,
                MemoryLocationKind::Field { base, member },
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
                    value: source,
                },
            )?;
            evaluations = vec![object, right];
        } else if let Some((base_node, index_node)) = self.array_index_access(left) {
            // `values(i) = v` is Scala's update sugar. On an `Array` receiver
            // that is the language's own element store, so it lowers as index
            // memory, matching Java's `array_access` assignment target.
            let source = self.expression_value(builder, right, expression_value_kind(right))?;
            let base =
                self.expression_value(builder, base_node, expression_value_kind(base_node))?;
            let index = self.index_value(builder, index_node)?;
            let location = self.session.add_memory_location(
                builder,
                terminal,
                MemoryLocationKind::Index {
                    base,
                    index: Some(index),
                    constant_index: None,
                    identity: crate::analyzer::semantic::IndexedLocationIdentity::Element,
                },
            )?;
            self.append_effect(
                builder,
                terminal,
                SemanticEffect::MemoryStore {
                    kind: MemoryAccessKind::Index,
                    location,
                    value: source,
                },
            )?;
            evaluations = vec![base_node, index_node, right];
        } else {
            let result = self.expression_value(builder, node, expression_value_kind(node))?;
            self.add_gap(
                builder,
                terminal,
                SemanticGapSubject::Value(result),
                SemanticCapability::Values,
                SemanticGapKind::Unknown,
                "Scala assignment identity requires the declared target type and implicit conversion resolution",
            )?;
            self.add_gap(
                builder,
                terminal,
                SemanticGapSubject::Point,
                SemanticCapability::Assignments,
                SemanticGapKind::Unsupported,
                "Scala destructuring or user-defined update assignment is not lowered into memory flow",
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

    /// Lower a selection.
    ///
    /// A selection whose base is a package or type qualifier denotes no
    /// runtime value at all, so it mints neither a memory location nor an
    /// undischargeable `FieldMemory` gap -- the #2363 rule Java applies to
    /// `field_access` type qualifiers. `asInstanceOf` and `isInstanceOf` are
    /// the language's own type operations rather than members. Everything
    /// else is a member read: a located field load, with the identity gap and
    /// the parameterless-method gaps raised only when this compilation unit
    /// does not settle which declaration the member names. A member that does
    /// resolve to a `val` or `var` declaration is a stored field, and Scala's
    /// uniform access does not make reading one a call.
    #[allow(clippy::too_many_arguments)]
    fn field_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), ScalaLoweringError> {
        let object = required_field(node, "value")?;
        let field = required_field(node, "field")?;
        if !self.selection_base_is_value(object) {
            return self.edge(builder, entry, next);
        }
        let member_name = node_text(self.prepared.source(), field);
        if matches!(member_name, Some("asInstanceOf" | "isInstanceOf")) {
            let terminal = self.point(builder, node, Vec::new())?;
            if member_name == Some("asInstanceOf") {
                // A checked cast yields the operand itself; only its runtime
                // check can fail, and that abort edge is not lowered.
                let result = self.expression_value(builder, node, expression_value_kind(node))?;
                let source =
                    self.expression_value(builder, object, expression_value_kind(object))?;
                self.session.append_language_defined_value_flows(
                    builder,
                    terminal,
                    vec![source],
                    result,
                )?;
                self.add_gap(
                    builder,
                    terminal,
                    SemanticGapSubject::Point,
                    SemanticCapability::ExceptionalControlFlow,
                    SemanticGapKind::Unsupported,
                    "the checked-cast abort edge of a type ascription is not lowered",
                )?;
            }
            self.edge(builder, terminal, next)?;
            stack.push(Work::Expression {
                node: object,
                entry,
                next: EdgeTarget::normal(terminal),
                scope,
            });
            return Ok(());
        }
        let access = self.point(builder, node, Vec::new())?;
        let result = self.expression_value(builder, node, expression_value_kind(node))?;
        let base = self.expression_value(builder, object, expression_value_kind(object))?;
        let (member, resolved) = self.memory_member_locator(field, object)?;
        let location = self.session.add_memory_location(
            builder,
            access,
            MemoryLocationKind::Field { base, member },
        )?;
        if !resolved {
            self.add_field_identity_gap(builder, access, location)?;
            self.add_gap(
                builder,
                access,
                SemanticGapSubject::Value(result),
                SemanticCapability::Calls,
                SemanticGapKind::Unknown,
                "selection may denote a parameterless method or require an implicit conversion",
            )?;
            self.add_gap(
                builder,
                access,
                SemanticGapSubject::Value(result),
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unknown,
                "parameterless method selection or an implicit conversion may complete exceptionally",
            )?;
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
        self.edge(builder, access, next)?;
        stack.push(Work::Expression {
            node: object,
            entry,
            next: EdgeTarget::normal(access),
            scope,
        });
        Ok(())
    }

    /// Whether `new T(...)` allocates one of Scala's own arrays.
    fn constructs_language_defined_array(&self, function: Node<'tree>) -> bool {
        let source = self.prepared.source();
        let Some(constructed) = scala_constructed_type_node(function) else {
            return false;
        };
        if super::scala_type_lookup_segments(constructed, source)
            .last()
            .map(String::as_str)
            != Some("Array")
        {
            return false;
        }
        scala_type_definitions_named(compilation_unit_root(self.callable), "Array", source)
            .is_empty()
    }

    /// Lower `new Array[T](n)` as the array allocation it is.
    ///
    /// Scala's array creation is the JVM's own `newarray`, not a method
    /// application: there is no callee body anywhere for a whole-program
    /// resolver to bind, so minting a call site here would publish a boundary
    /// that can never close. Java lowers `array_creation_expression` the same
    /// way, as an allocation with no call.
    #[allow(clippy::too_many_arguments)]
    fn array_allocation(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        lengths: &[Node<'tree>],
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), ScalaLoweringError> {
        let terminal = self.point(builder, node, Vec::new())?;
        let result = self.expression_value(builder, node, SemanticValueKind::Temporary)?;
        self.session
            .add_allocation(builder, terminal, result, AllocationKind::Array)?;
        self.edge(builder, terminal, next)?;
        self.schedule_expressions(
            builder,
            entry,
            lengths,
            EdgeTarget::normal(terminal),
            scope,
            stack,
        )
    }

    /// Lower `values(i)` on an `Array` receiver as an element read.
    #[allow(clippy::too_many_arguments)]
    fn array_element_load(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        base_node: Node<'tree>,
        index_node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), ScalaLoweringError> {
        let access = self.point(builder, node, Vec::new())?;
        let result = self.expression_value(builder, node, expression_value_kind(node))?;
        let base = self.expression_value(builder, base_node, expression_value_kind(base_node))?;
        let index = self.index_value(builder, index_node)?;
        let location = self.session.add_memory_location(
            builder,
            access,
            MemoryLocationKind::Index {
                base,
                index: Some(index),
                constant_index: None,
                identity: crate::analyzer::semantic::IndexedLocationIdentity::Element,
            },
        )?;
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
            "the bounds-check abort edge of an array element access is not lowered",
        )?;
        self.edge(builder, access, next)?;
        self.schedule_expressions(
            builder,
            entry,
            &[base_node, index_node],
            EdgeTarget::normal(access),
            scope,
            stack,
        )
    }

    /// Whether an annotated `val`/`var` initializer provably already has the
    /// declared type, so the binding applies no implicit conversion.
    ///
    /// The three arms are the same identity discipline the return proof uses:
    /// an unannotated binding takes whatever the initializer yields, a `new
    /// T(...)` initializer names its own type, a literal names the type its
    /// spelling fixes, and anything else must have a structurally determined
    /// identity equal to the declared one. Everything else keeps its gap.
    fn definition_has_identity_initializer(
        &self,
        definition: Node<'tree>,
        initializer: Node<'tree>,
    ) -> bool {
        let Some(declared) = definition.child_by_field_name("type") else {
            return true;
        };
        let source = self.prepared.source();
        if scala_constructed_type_node(initializer).is_some_and(|constructed| {
            scala_type_nodes_have_same_identity(declared, constructed, source)
        }) || scala_literal_has_declared_identity_type(declared, initializer, source)
        {
            return true;
        }
        let Some(declared_identity) = scala_type_identity(declared, source) else {
            return false;
        };
        self.expression_type_identity(initializer)
            .is_some_and(|identity| identity == declared_identity)
    }

    /// Whether the value stored by `left = right` provably already has the
    /// target's type, so the store applies no implicit conversion.
    fn assigned_value_has_target_identity(&self, left: Node<'tree>, right: Node<'tree>) -> bool {
        let Some(name) = node_text(self.prepared.source(), left) else {
            return false;
        };
        let Some(target) = self
            .binding_type_id_at(name, left.start_byte())
            .and_then(|id| self.type_identities.get(id.0))
        else {
            return false;
        };
        self.expression_type_identity(right)
            .is_some_and(|identity| identity == *target)
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
    ) -> Result<(), ScalaLoweringError> {
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

    fn return_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), ScalaLoweringError> {
        let argument = first_runtime_named_child(node);
        let terminal = if argument.is_some() {
            self.point(builder, node, Vec::new())?
        } else {
            entry
        };
        if matches!(
            self.procedure_kind,
            ProcedureKind::Lambda | ProcedureKind::Closure
        ) {
            self.add_gap(
                builder,
                terminal,
                SemanticGapSubject::Point,
                SemanticCapability::NonLocalControl,
                SemanticGapKind::Unsupported,
                "return inside a Scala anonymous function is non-local control and is not a return from that anonymous procedure",
            )?;
            self.add_gap(
                builder,
                terminal,
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unsupported,
                "non-local return boundary propagation is not lowered",
            )?;
        } else {
            let value = argument
                .map(|argument| {
                    let source =
                        self.expression_value(builder, argument, expression_value_kind(argument))?;
                    let value = self.value(builder, terminal, SemanticValueKind::Return)?;
                    if self.callable_result_has_identity_conversion(argument) {
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
                            SemanticGapKind::Unknown,
                            "Scala explicit return may apply an implicit conversion to the declared result type",
                        )?;
                    }
                    Ok::<_, ScalaLoweringError>(value)
                })
                .transpose()?;
            self.append_effect(builder, terminal, SemanticEffect::ProcedureReturn { value })?;
            self.abrupt(builder, terminal, scope, CompletionKind::Return, stack)?;
        }
        if let Some(argument) = argument {
            stack.push(Work::Expression {
                node: argument,
                entry,
                next: EdgeTarget::normal(terminal),
                scope,
            });
        }
        Ok(())
    }

    /// Whether `result` provably already has the callable's declared result
    /// type, so returning it applies no implicit conversion.
    ///
    /// The proof is structural and congruent: a conditional, block, or match
    /// carries its declared identity when every value it can yield does, and
    /// a call to a definition in this compilation unit carries it when that
    /// definition declares the same result type. Type identity remains the
    /// discipline -- a widened or shadowed result still fails here and keeps
    /// its `ReturnTransfer` gap.
    fn callable_result_has_identity_conversion(&self, result: Node<'tree>) -> bool {
        let Some(declared) = self.callable.child_by_field_name("return_type") else {
            return true;
        };
        let source = self.prepared.source();
        let declared_identity = super::scala_type_lookup_segments(declared, source);
        if declared_identity.is_empty() {
            return false;
        }
        let mut pending = vec![result];
        let mut examined = 0_usize;
        while let Some(node) = pending.pop() {
            examined += 1;
            if examined > SCALA_RESULT_IDENTITY_NODE_BUDGET {
                return false;
            }
            if self.result_node_has_declared_identity(declared, &declared_identity, node) {
                continue;
            }
            match node.kind() {
                "parenthesized_expression" => match first_runtime_named_child(node) {
                    Some(inner) => pending.push(inner),
                    None => return false,
                },
                "block" | "indented_block" => match implicit_result_node(node) {
                    Some(inner) if inner.id() != node.id() => pending.push(inner),
                    _ => return false,
                },
                "if_expression" => {
                    // A one-armed `if` yields `Unit` on the missing arm, so
                    // only a complete conditional can carry a declared type.
                    let (Some(consequence), Some(alternative)) = (
                        node.child_by_field_name("consequence"),
                        node.child_by_field_name("alternative"),
                    ) else {
                        return false;
                    };
                    pending.push(consequence);
                    pending.push(alternative);
                }
                "match_expression" => {
                    let arms = case_arms(node);
                    if arms.is_empty() {
                        return false;
                    }
                    for arm in arms {
                        match case_body_nodes(arm).last() {
                            Some(body) => pending.push(*body),
                            None => return false,
                        }
                    }
                }
                _ => return false,
            }
        }
        true
    }

    fn result_node_has_declared_identity(
        &self,
        declared: Node<'tree>,
        declared_identity: &[String],
        node: Node<'tree>,
    ) -> bool {
        let source = self.prepared.source();
        scala_constructed_type_node(node).is_some_and(|constructed| {
            scala_type_nodes_have_same_identity(declared, constructed, source)
        }) || scala_literal_has_declared_identity_type(declared, node, source)
            // A type parameter or a second parameter list can make the
            // declared result type depend on the application, which this
            // file-local inference does not model.
            || (callable_has_simple_parameter_shape(self.callable)
                && self
                    .expression_type_identity(node)
                    .is_some_and(|identity| identity.as_ref() == declared_identity))
    }

    /// The structurally determined type identity of an expression, or `None`
    /// when this compilation unit's structure does not determine it.
    ///
    /// This is deliberately narrow: it reads literals, lexical binding types,
    /// same-file callable result declarations, and the operand types of
    /// operators built from Scala's operator characters. It never guesses. A
    /// `None` answer keeps every caller on its conservative path.
    fn expression_type_identity(&self, node: Node<'tree>) -> Option<Arc<[String]>> {
        let source = self.prepared.source();
        // A selection chain is walked down to its base and then applied back
        // outwards through the declared member types, so `outer.middle.inner`
        // answers without recursing once per access-path segment.
        let mut members: Vec<&str> = Vec::new();
        let mut current = node;
        let mut examined = 0_usize;
        let base = loop {
            examined += 1;
            if examined > SCALA_RESULT_IDENTITY_NODE_BUDGET {
                return None;
            }
            // `new T(...)` names its own type, whatever else the expression
            // shape is; nothing about the application can change it.
            if let Some(constructed) = scala_constructed_type_node(current) {
                break scala_type_identity(constructed, source)?;
            }
            match current.kind() {
                "parenthesized_expression" => current = first_runtime_named_child(current)?,
                "generic_function" => current = current.child_by_field_name("function")?,
                "field_expression" => {
                    members.push(node_text(source, current.child_by_field_name("field")?)?);
                    current = current.child_by_field_name("value")?;
                }
                "identifier" => {
                    let name = node_text(source, current)?;
                    let identity = self.binding_type_id_at(name, current.start_byte())?;
                    break self.type_identities.get(identity.0).cloned()?;
                }
                "call_expression" => {
                    break self
                        .array_element_type_identity(current)
                        .or_else(|| self.call_result_type_identity(current))?;
                }
                "infix_expression" => break self.infix_result_type_identity(current)?,
                _ => {
                    break scala_literal_type_name(current)
                        .map(|name| Arc::from(vec![name.to_string()].into_boxed_slice()))?;
                }
            }
        };
        let mut identity = base;
        while let Some(member) = members.pop() {
            identity = self.member_declared_type_identity(&identity, member)?;
        }
        Some(identity)
    }

    /// The unique `val` or `var` member declaration this compilation unit
    /// shows for `member` on `owner`.
    ///
    /// Deliberately narrow, and `None` whenever the file does not settle the
    /// answer: no such template, several same-named templates, a template
    /// that declares parents whose members this file never shows, or no such
    /// member. Java's `memory_member_locator` resolves against the same
    /// same-file evidence.
    fn template_value_member(&self, owner: &[String], member: &str) -> Option<Node<'tree>> {
        let source = self.prepared.source();
        let name = owner.last()?;
        let mut templates =
            scala_type_definitions_named(compilation_unit_root(self.callable), name, source);
        let template = templates.pop()?;
        if !templates.is_empty() {
            return None;
        }
        // A member the template declares for itself is the one a selection
        // names, whether or not the template also declares parents: Scala
        // requires `override` for an inherited redeclaration, so a local
        // declaration is never a silently shadowed inherited member.
        scala_template_value_member(template, member, source)
    }

    /// The written type of a resolved member declaration.
    fn member_declared_type_identity(
        &self,
        owner: &[String],
        member: &str,
    ) -> Option<Arc<[String]>> {
        let definition = self.template_value_member(owner, member)?;
        scala_type_identity(
            definition.child_by_field_name("type")?,
            self.prepared.source(),
        )
    }

    /// The base and index of an application that Scala's `apply`/`update`
    /// sugar makes an element access on an `Array`.
    ///
    /// Only an `Array`-typed lexical base qualifies. `Array` is the language's
    /// own array type, so `values(i)` and `values(i) = v` are its element read
    /// and write exactly as `a[i]` is in Java; any other receiver's `apply` is
    /// an ordinary member and stays a call site.
    fn array_index_access(&self, node: Node<'tree>) -> Option<(Node<'tree>, Node<'tree>)> {
        let (function, argument_lists) = flattened_call_parts(node).ok()?;
        let [arguments] = argument_lists.as_slice() else {
            return None;
        };
        let indices = semantic_argument_nodes(*arguments);
        let [index] = indices.as_slice() else {
            return None;
        };
        let base = normalized_callable_expression(function).ok()?;
        if base.kind() != "identifier" {
            return None;
        }
        let identity = self.expression_type_identity(base)?;
        (identity.last().map(String::as_str) == Some("Array")).then_some((base, *index))
    }

    /// The element type of an `Array` element read.
    fn array_element_type_identity(&self, node: Node<'tree>) -> Option<Arc<[String]>> {
        let (base, _) = self.array_index_access(node)?;
        let name = node_text(self.prepared.source(), base)?;
        let binding = self.local_binding_at(name, base.start_byte())?;
        self.type_identities
            .get(binding.element_identity?.0)
            .cloned()
    }

    /// The element identity an `Array` initializer determines: the written
    /// type argument of `new Array[T](n)`, or the single identity every
    /// element of an `Array(...)` factory application carries.
    fn array_element_identity(&self, initializer: Node<'tree>) -> Option<Arc<[String]>> {
        let source = self.prepared.source();
        if let Some(constructed) = scala_constructed_type_node(initializer) {
            return scala_array_element_type_node(constructed, source)
                .and_then(|element| scala_type_identity(element, source));
        }
        let (function, argument_lists) = flattened_call_parts(initializer).ok()?;
        if !self.names_language_defined_array(function) {
            return None;
        }
        let [arguments] = argument_lists.as_slice() else {
            return None;
        };
        let mut identity: Option<Arc<[String]>> = None;
        for element in runtime_expression_children(*arguments) {
            let element_identity = self.expression_type_identity(element)?;
            match &identity {
                Some(previous) if *previous != element_identity => return None,
                Some(_) => {}
                None => identity = Some(element_identity),
            }
        }
        identity
    }

    /// Whether an application's callee is Scala's own `Array` companion: an
    /// unqualified `Array` that is neither a lexical binding here nor a
    /// function or type this compilation unit declares for itself.
    fn names_language_defined_array(&self, function: Node<'tree>) -> bool {
        let source = self.prepared.source();
        let Ok(callable) = normalized_callable_expression(function) else {
            return false;
        };
        if callable.kind() != "identifier"
            || node_text(source, callable) != Some("Array")
            || self.identifier_is_lexical(callable)
        {
            return false;
        }
        let root = compilation_unit_root(self.callable);
        scala_function_definitions_named(root, "Array", source).is_empty()
            && scala_type_definitions_named(root, "Array", source).is_empty()
    }

    /// The locator naming the member a selection reads or writes, and whether
    /// its declaration resolved.
    ///
    /// Mirrors Java's `memory_member_locator`: the base's structurally known
    /// type identity selects the declaring template in this compilation unit,
    /// and the member's own declaration anchors the location. An unresolved
    /// member keeps the occurrence anchor and its caller publishes the
    /// identity gap.
    fn memory_member_locator(
        &self,
        member: Node<'tree>,
        base: Node<'tree>,
    ) -> Result<(SemanticLocator, bool), ScalaLoweringError> {
        let procedure = self.session.locator();
        let occurrence = source_anchor(member, 0).map_err(ScalaLoweringError::Invalid)?;
        let declaration = node_text(self.prepared.source(), member)
            .zip(self.expression_type_identity(base))
            .and_then(|(name, owner)| self.template_value_member(&owner, name))
            .and_then(|definition| definition.child_by_field_name("pattern"))
            .map(|pattern| source_anchor(pattern, 0))
            .transpose()
            .map_err(ScalaLoweringError::Invalid)?;
        let resolved = declaration.is_some();
        Ok((
            SemanticLocator::new(
                procedure.mount(),
                procedure.path().clone(),
                procedure.language(),
                procedure.declaration().clone(),
                SemanticRole::MemoryLocation,
                declaration.unwrap_or(occurrence),
            ),
            resolved,
        ))
    }

    /// The locator for a member declared here, anchored exactly where
    /// [`Self::memory_member_locator`] anchors a resolved selection of it.
    fn declared_member_locator(
        &self,
        declaration: Node<'tree>,
    ) -> Result<SemanticLocator, ScalaLoweringError> {
        let procedure = self.session.locator();
        let anchor = source_anchor(declaration, 0).map_err(ScalaLoweringError::Invalid)?;
        Ok(SemanticLocator::new(
            procedure.mount(),
            procedure.path().clone(),
            procedure.language(),
            procedure.declaration().clone(),
            SemanticRole::MemoryLocation,
            anchor,
        ))
    }

    fn add_field_identity_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        location: MemoryLocationId,
    ) -> Result<(), ScalaLoweringError> {
        self.session.add_gap_with_impacts(
            builder,
            point,
            SemanticGapSubject::MemoryLocation(location),
            SemanticCapability::FieldMemory,
            SemanticGapImpacts::single(SemanticGapImpact::HeapRead)
                .with(SemanticGapImpact::HeapWrite)
                .with(SemanticGapImpact::Aliasing),
            SemanticGapKind::Unknown,
            "field occurrence is structured, but its declaration identity is not yet resolved",
        )?;
        Ok(())
    }

    /// Whether a selection's base denotes a runtime value rather than the
    /// package or type prefix of a qualified name (#2363). A qualifier
    /// denotes no value, so it must not mint a memory location or an
    /// undischargeable `FieldMemory` gap.
    fn selection_base_is_value(&self, base: Node<'tree>) -> bool {
        let mut current = base;
        loop {
            match current.kind() {
                "field_expression" => match current.child_by_field_name("value") {
                    Some(inner) => current = inner,
                    None => return false,
                },
                "identifier" => return self.identifier_is_lexical(current),
                "this" | "super" => return true,
                kind => return is_runtime_node(kind),
            }
        }
    }

    /// One value per distinct constant index spelling, so a store through
    /// `x(0)` and a load from `x(0)` name the same index operand.
    fn index_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<ValueId, ScalaLoweringError> {
        let kind = expression_value_kind(node);
        if kind != SemanticValueKind::Constant {
            return self.expression_value(builder, node, kind);
        }
        let Some(text) = node_text(self.prepared.source(), node) else {
            return self.expression_value(builder, node, kind);
        };
        if let Some(value) = self.constant_index_values.get(text) {
            self.expression_values.insert(node.id(), *value);
            return Ok(*value);
        }
        let value = self.expression_value(builder, node, kind)?;
        self.constant_index_values.insert(text.into(), value);
        Ok(value)
    }

    /// The declared result type of an unqualified application in this
    /// compilation unit.
    ///
    /// The applied name must resolve to `function_definition`s that all
    /// declare the same explicit result type. Requiring every same-named
    /// definition in the file to agree covers overloads and lexical shadowing
    /// without modelling Scala's selection rules. An enclosing template that
    /// declares parents can inherit a same-named overload this file never
    /// shows, so no answer is offered there.
    fn call_result_type_identity(&self, node: Node<'tree>) -> Option<Arc<[String]>> {
        let source = self.prepared.source();
        let (function, _) = flattened_call_parts(node).ok()?;
        if self.names_language_defined_array(function) {
            return Some(Arc::from(vec!["Array".to_string()].into_boxed_slice()));
        }
        let callable = normalized_callable_expression(function).ok()?;
        if callable.kind() != "identifier" || enclosing_template_declares_parents(self.callable) {
            return None;
        }
        let name = node_text(source, callable)?;
        let mut declared: Option<Arc<[String]>> = None;
        for definition in
            scala_function_definitions_named(compilation_unit_root(self.callable), name, source)
        {
            let identity =
                scala_type_identity(definition.child_by_field_name("return_type")?, source)?;
            match &declared {
                Some(previous) if *previous != identity => return None,
                Some(_) => {}
                None => declared = Some(identity),
            }
        }
        declared
    }

    /// The result type of an operator application that Scala's own value
    /// classes define. Only an operator spelled entirely from Scala's
    /// operator characters over a receiver whose type is a primitive or
    /// `String` selects a language-defined member, so anything else is left
    /// undetermined.
    fn infix_result_type_identity(&self, node: Node<'tree>) -> Option<Arc<[String]>> {
        let source = self.prepared.source();
        let operator = node_text(source, node.child_by_field_name("operator")?)?;
        if !scala_operator_is_language_defined(operator) {
            return None;
        }
        let left = self.expression_type_identity(node.child_by_field_name("left")?)?;
        let [receiver] = left.as_ref() else {
            return None;
        };
        if !scala_type_name_is_language_defined(receiver) {
            return None;
        }
        if scala_operator_yields_boolean(operator) {
            return Some(Arc::from(vec!["Boolean".to_string()].into_boxed_slice()));
        }
        // Widening (`Int + Double`) and `String + Any` both change the
        // result type, so only an operation over one type answers.
        let right = self.expression_type_identity(required_runtime_field(node, "right").ok()?)?;
        (right == left).then_some(left)
    }

    fn throw_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), ScalaLoweringError> {
        let argument = first_runtime_named_child(node)
            .ok_or_else(|| missing_field(node, "exception expression"))?;
        let terminal = self.point(builder, node, Vec::new())?;
        let source = self.expression_value(builder, argument, expression_value_kind(argument))?;
        let value = self.value(builder, terminal, SemanticValueKind::Exception)?;
        self.append_effect(
            builder,
            terminal,
            SemanticEffect::Assignment {
                target: value,
                value: source,
            },
        )?;
        self.append_effect(
            builder,
            terminal,
            SemanticEffect::Throw { value: Some(value) },
        )?;
        self.abrupt_throw(builder, terminal, scope, value, stack)?;
        stack.push(Work::Expression {
            node: argument,
            entry,
            next: EdgeTarget::normal(terminal),
            scope,
        });
        Ok(())
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
    ) -> Result<(), ScalaLoweringError> {
        if let Some((base_node, index_node)) = self.array_index_access(node) {
            return self.array_element_load(
                builder, node, base_node, index_node, entry, next, scope, stack,
            );
        }
        let (function, mut argument_lists) = flattened_call_parts(node)?;
        let constructor_application = function.kind() == "instance_expression";
        if constructor_application && self.constructs_language_defined_array(function) {
            let mut lengths = function
                .child_by_field_name("arguments")
                .map(runtime_expression_children)
                .unwrap_or_default();
            for arguments in &argument_lists {
                lengths.extend(runtime_expression_children(*arguments));
            }
            return self.array_allocation(builder, node, &lengths, entry, next, scope, stack);
        }
        if constructor_application
            && let Some(arguments) = function.child_by_field_name("arguments")
        {
            argument_lists.insert(0, arguments);
        }
        let callable = normalized_callable_expression(function)?;
        let argument_nodes = argument_lists
            .iter()
            .flat_map(|arguments| semantic_argument_nodes(*arguments))
            .collect::<Vec<_>>();
        let has_structured_argument = argument_lists
            .iter()
            .any(|arguments| has_structured_by_name_argument(*arguments));
        let curried = argument_lists.len() > 1;
        let has_implicit_arguments = argument_lists
            .iter()
            .any(|arguments| contains_token(*arguments, "using"));
        let invoke = self.point(builder, node, Vec::new())?;
        let normal = self.point(builder, node, Vec::new())?;
        let exceptional = self.point(builder, node, Vec::new())?;
        let callee = self.source_value(builder, callable, SemanticValueKind::Callable)?;
        let result = self.expression_value(builder, node, SemanticValueKind::Temporary)?;
        let thrown = self.source_value(builder, callable, SemanticValueKind::Exception)?;
        let receiver_node = (!constructor_application)
            .then(|| scala_bound_receiver(callable))
            .flatten();
        let receiver = receiver_node
            .map(|receiver| {
                self.expression_value(builder, receiver, expression_value_kind(receiver))
            })
            .transpose()?;
        let callable_kind = if constructor_application {
            CallableReferenceKind::Constructor
        } else if receiver.is_some() {
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
        let arguments = argument_nodes
            .iter()
            .map(
                |argument| -> Result<SemanticCallArgument, ScalaLoweringError> {
                    let written = self.call_argument(builder, *argument)?;
                    // A contextual (`using`) list inserts arguments this syntax
                    // never wrote, so the written rows carry no proven domain.
                    Ok(if has_implicit_arguments {
                        SemanticCallArgument::unclassified(written.value)
                    } else {
                        written
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
                arguments: arguments.into(),
                normal_results: Box::new([]),
                result: Some(result),
                thrown: Some(thrown),
                declared_targets: resolution.clone(),
                normal_continuation: normal,
                exceptional_continuation: exceptional,
            },
        )?;
        if constructor_application {
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
        self.abrupt(builder, exceptional, scope, CompletionKind::Throw, stack)?;
        self.resolution_gaps(builder, invoke, callee, call_site, &resolution)?;

        if !constructor_application {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::DynamicDispatch,
                SemanticGapKind::Unknown,
                "application may dispatch through a virtual member or callable value; static/final dispatch and complete override coverage require type refinement",
            )?;
        }

        if curried || has_implicit_arguments {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::Point,
                SemanticCapability::Values,
                SemanticGapKind::Unknown,
                "actual-to-formal binding across curried or contextual parameter lists is not represented",
            )?;
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::Point,
                SemanticCapability::Calls,
                SemanticGapKind::Unknown,
                "curried application and contextual argument insertion require dispatch refinement",
            )?;
        }

        if !argument_nodes.is_empty() {
            if has_structured_argument {
                self.session.add_gap_with_impacts(
                    builder,
                    invoke,
                    SemanticGapSubject::CallSite(call_site),
                    SemanticCapability::DeferredExecution,
                    SemanticGapImpacts::CALL_EVALUATION,
                    SemanticGapKind::Unknown,
                    "trailing block, case, or colon syntax does not prove by-name evaluation; execution is withheld until parameter strictness is resolved",
                )?;
            } else {
                // Ordinary arguments are lowered strictly: every expression
                // is scheduled before the invoke. The resolved signature
                // answers whether that is right, so the gap declares a
                // call-resolution discharge; a callee that defers evaluation
                // (a by-name parameter) carries its own procedure-level gap,
                // which keeps every binding to it open and the discharge
                // unearned.
                self.session.add_gap_with_impacts_and_discharge(
                    builder,
                    invoke,
                    SemanticGapSubject::CallSite(call_site),
                    SemanticCapability::DeferredExecution,
                    SemanticGapImpacts::NONE,
                    SemanticGapKind::Unknown,
                    SemanticGapDischarge::CallResolution,
                    "argument evaluation strictness depends on the resolved Scala parameter signature",
                )?;
            }
        }
        if is_future_like_call(self.prepared.source(), callable) {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::ConcurrentSpawn,
                SemanticGapKind::Unknown,
                "Future-style execution-context scheduling is not lowered",
            )?;
            if argument_nodes.is_empty() {
                self.session.add_gap_with_impacts(
                    builder,
                    invoke,
                    SemanticGapSubject::CallSite(call_site),
                    SemanticCapability::DeferredExecution,
                    SemanticGapImpacts::CALL_EVALUATION,
                    SemanticGapKind::Unknown,
                    "Future body execution timing is not lowered",
                )?;
            }
        }

        let mut evaluations = Vec::with_capacity(argument_nodes.len() + 1);
        if !constructor_application {
            // A selection in callee position is the call's own member
            // selection, which the call site already represents; only its
            // receiver is a separate operand to evaluate. Lowering it as a
            // member read instead would mint a second, unresolvable field
            // location for the method the call already names -- Java's
            // `method_invocation` schedules the `object`, never a synthetic
            // field access.
            evaluations.push(receiver_node.unwrap_or(function));
        }
        for arguments in &argument_lists {
            if !has_structured_by_name_argument(*arguments) {
                // A named argument evaluates its right-hand side. Scheduling
                // the `assignment_expression` itself lowered the label as a
                // store to a same-named binding in the caller's scope.
                evaluations.extend(
                    runtime_expression_children(*arguments)
                        .into_iter()
                        .map(call_argument_value_node),
                );
            }
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

    #[allow(clippy::too_many_arguments)]
    fn instance_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), ScalaLoweringError> {
        let arguments = node
            .child_by_field_name("arguments")
            .map(runtime_expression_children)
            .unwrap_or_default();
        if self.constructs_language_defined_array(node) {
            return self.array_allocation(builder, node, &arguments, entry, next, scope, stack);
        }
        self.call_like_expression(
            builder,
            node,
            entry,
            next,
            scope,
            node,
            CallableReferenceKind::Constructor,
            &arguments,
            &arguments,
            stack,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn infix_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), ScalaLoweringError> {
        let left = required_field(node, "left")?;
        let right = required_runtime_field(node, "right")?;
        // An operator that Scala itself defines on a value-class receiver
        // dispatches nowhere: its result is a language-defined function of its
        // operands, exactly as Java lowers `binary_expression`. Minting a call
        // site for it would publish a callee that no whole-program refinement
        // can ever resolve, which keeps every enclosing procedure open.
        if self.infix_result_type_identity(node).is_some() {
            return self.language_defined_operation(
                builder,
                node,
                entry,
                next,
                scope,
                &[left, right],
                stack,
            );
        }
        if left.kind() == "infix_expression" || right.kind() == "infix_expression" {
            let terminal = self.point(builder, node, Vec::new())?;
            let result = self.expression_value(builder, node, expression_value_kind(node))?;
            self.add_gap(
                builder,
                terminal,
                SemanticGapSubject::Value(result),
                SemanticCapability::Values,
                SemanticGapKind::Unknown,
                "compound infix result identity requires precedence and dispatch refinement",
            )?;
            self.add_gap(
                builder,
                terminal,
                SemanticGapSubject::Point,
                SemanticCapability::Calls,
                SemanticGapKind::Unsupported,
                "compound infix method dispatch is not emitted from an unrefined parse grouping",
            )?;
            self.add_gap(
                builder,
                terminal,
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unknown,
                "exceptions from compound infix dispatch require precedence and target refinement",
            )?;
            // The grouping's dispatch stays unproven, but its operands do
            // execute and the group does complete normally. Withholding the
            // edge instead severed the procedure's control flow below this
            // point, which is a strictly worse claim than an open result.
            self.edge(builder, terminal, next)?;
            return self.schedule_expressions(
                builder,
                entry,
                &[left, right],
                EdgeTarget::normal(terminal),
                scope,
                stack,
            );
        }
        let operator = required_field(node, "operator")?;
        let right_associative =
            node_text(self.prepared.source(), operator).is_some_and(|name| name.ends_with(':'));
        let arguments = if right_associative {
            vec![left]
        } else {
            vec![right]
        };
        let evaluations = vec![left, right];
        self.call_like_expression(
            builder,
            node,
            entry,
            next,
            scope,
            operator,
            CallableReferenceKind::BoundMethod,
            &arguments,
            &evaluations,
            stack,
        )
    }

    /// Lower an operator whose meaning the language fixes: each operand flows
    /// into the result at one terminal point, no call site is minted, and no
    /// callable-reference gap is opened.
    #[allow(clippy::too_many_arguments)]
    fn language_defined_operation(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        operands: &[Node<'tree>],
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), ScalaLoweringError> {
        let terminal = self.point(builder, node, Vec::new())?;
        let result = self.expression_value(builder, node, expression_value_kind(node))?;
        let sources = operands
            .iter()
            .map(|operand| {
                self.expression_value(builder, *operand, expression_value_kind(*operand))
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.session
            .append_language_defined_value_flows(builder, terminal, sources, result)?;
        self.edge(builder, terminal, next)?;
        self.schedule_expressions(
            builder,
            entry,
            operands,
            EdgeTarget::normal(terminal),
            scope,
            stack,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn postfix_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), ScalaLoweringError> {
        let children = runtime_expression_children(node);
        let operator = children
            .last()
            .copied()
            .ok_or_else(|| missing_field(node, "postfix operator"))?;
        let evaluations = children[..children.len().saturating_sub(1)].to_vec();
        self.call_like_expression(
            builder,
            node,
            entry,
            next,
            scope,
            operator,
            CallableReferenceKind::BoundMethod,
            &[],
            &evaluations,
            stack,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn prefix_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), ScalaLoweringError> {
        let operand =
            first_runtime_named_child(node).ok_or_else(|| missing_field(node, "prefix operand"))?;
        self.call_like_expression(
            builder,
            node,
            entry,
            next,
            scope,
            node,
            CallableReferenceKind::BoundMethod,
            &[],
            &[operand],
            stack,
        )
    }

    /// Lower one written call argument into its call-site row.
    ///
    /// Scala spells a named argument as an `assignment_expression` inside the
    /// invocation's argument list. The label names a formal at the callee and
    /// the passed value is the right-hand side, so the row binds that value
    /// and carries the label; binding the assignment node instead published a
    /// value identity no formal ever receives (#2959). Every other argument,
    /// including an assignment whose left side is not a plain name and is
    /// therefore a unit-typed assignment expression, stays positional and
    /// binds the argument node itself.
    fn call_argument(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        argument: Node<'tree>,
    ) -> Result<SemanticCallArgument, ScalaLoweringError> {
        let Some((keyword, passed)) = named_call_argument_parts(argument) else {
            let value =
                self.expression_value(builder, argument, expression_value_kind(argument))?;
            return Ok(SemanticCallArgument::direct(
                value,
                ArgumentDomain::Positional,
            ));
        };
        let value = self.expression_value(builder, passed, expression_value_kind(passed))?;
        let name = node_text(self.prepared.source(), keyword).ok_or_else(|| {
            ScalaLoweringError::Invalid(
                "Scala named argument label does not lie on a source boundary".into(),
            )
        })?;
        Ok(SemanticCallArgument::keyword(value, name))
    }

    #[allow(clippy::too_many_arguments)]
    fn call_like_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        source_node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        function: Node<'tree>,
        callable_kind: CallableReferenceKind,
        argument_nodes: &[Node<'tree>],
        evaluations: &[Node<'tree>],
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), ScalaLoweringError> {
        let invoke = self.point(builder, source_node, Vec::new())?;
        let normal = self.point(builder, source_node, Vec::new())?;
        let exceptional = self.point(builder, source_node, Vec::new())?;
        let callee = self.source_value(builder, function, SemanticValueKind::Callable)?;
        let result = self.expression_value(builder, source_node, SemanticValueKind::Temporary)?;
        let thrown = self.source_value(builder, function, SemanticValueKind::Exception)?;
        let receiver_node = (callable_kind == CallableReferenceKind::BoundMethod)
            .then(|| scala_call_like_receiver(source_node, function, self.prepared.source()))
            .flatten();
        let receiver = receiver_node
            .map(|receiver| {
                self.expression_value(builder, receiver, expression_value_kind(receiver))
            })
            .transpose()?;
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
        let arguments = argument_nodes
            .iter()
            .map(|argument| self.call_argument(builder, *argument))
            .collect::<Result<Vec<_>, _>>()?;
        let call_site = self.session.add_call_site(
            builder,
            CallSiteScaffold {
                point: invoke,
                callee,
                receiver,
                arguments: arguments.into(),
                normal_results: Box::new([]),
                result: Some(result),
                thrown: Some(thrown),
                declared_targets: resolution.clone(),
                normal_continuation: normal,
                exceptional_continuation: exceptional,
            },
        )?;
        if callable_kind == CallableReferenceKind::Constructor {
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
        self.abrupt(builder, exceptional, scope, CompletionKind::Throw, stack)?;
        self.resolution_gaps(builder, invoke, callee, call_site, &resolution)?;
        if receiver.is_some() {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::DynamicDispatch,
                SemanticGapKind::Unknown,
                "operator or postfix dispatch may select an override; receiver type and complete target coverage require type refinement",
            )?;
        }
        if !argument_nodes.is_empty() {
            // Strict operator/postfix argument evaluation with the same
            // call-resolution discharge as in `call_expression`.
            self.session.add_gap_with_impacts_and_discharge(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::DeferredExecution,
                SemanticGapImpacts::NONE,
                SemanticGapKind::Unknown,
                SemanticGapDischarge::CallResolution,
                "argument evaluation strictness depends on the resolved Scala parameter signature",
            )?;
        }
        let evaluations = evaluations
            .iter()
            .copied()
            .map(call_argument_value_node)
            .collect::<Vec<_>>();
        self.schedule_expressions(
            builder,
            entry,
            &evaluations,
            EdgeTarget::normal(invoke),
            scope,
            stack,
        )
    }

    fn callable_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        next: EdgeTarget,
    ) -> Result<(), ScalaLoweringError> {
        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::CallableReferences,
            SemanticGapKind::Unknown,
            "nested callable target and captured environment mapping require dispatch refinement",
        )?;
        self.edge(builder, entry, next)
    }

    fn unsupported_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        detail: &str,
    ) -> Result<(), ScalaLoweringError> {
        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::NormalControlFlow,
            SemanticGapKind::Unsupported,
            detail,
        )?;
        if node.named_child_count() > 0 {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::Calls,
                SemanticGapKind::Unknown,
                "unlowered structured children may contain implicit or explicit calls",
            )?;
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unknown,
                "exceptions from unlowered structured children require refinement",
            )?;
        }
        self.edge(builder, entry, next)
    }

    fn schedule_statements(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        children: &[Node<'tree>],
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), ScalaLoweringError> {
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
    ) -> Result<(), ScalaLoweringError> {
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
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), ScalaLoweringError> {
        let route = builder
            .resolve_completion(scope, &CompletionRequest::new(kind, None))
            .ok_or_else(|| {
                ScalaLoweringError::Invalid(format!(
                    "{kind:?} completion has no structured continuation"
                ))
            })?;
        self.route(builder, from, &route, stack)
    }

    /// Route a `throw` to its structured continuation, binding the thrown
    /// value to the destination handler's catch parameter when that handler
    /// registered one. Java's `abrupt_throw` performs the same binding.
    fn abrupt_throw(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        from: ProgramPointId,
        scope: ScopeFrameId,
        value: ValueId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), ScalaLoweringError> {
        let route = builder
            .resolve_completion(scope, &CompletionRequest::new(CompletionKind::Throw, None))
            .ok_or_else(|| {
                ScalaLoweringError::Invalid(
                    "throw completion has no structured continuation".to_string(),
                )
            })?;
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
    ) -> Result<(), ScalaLoweringError> {
        let mut plan = CleanupRoutePlanner::new(route);
        while let Some(step) = plan.next(
            builder,
            &mut self.session,
            &self.cleanups,
            |region| region.id,
            |region| region.body,
        )? {
            let cleanup_next = if step.next.kind == ControlEdgeKind::Normal {
                step.next
            } else {
                let relay = self.point(builder, step.region.body, Vec::new())?;
                self.edge(builder, relay, step.next)?;
                EdgeTarget::normal(relay)
            };
            stack.push(Work::Expression {
                node: step.region.body,
                entry: step.entry,
                next: cleanup_next,
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
    ) -> Result<(), ScalaLoweringError> {
        self.session.add_callable_resolution_gaps(
            builder,
            point,
            callee,
            call_site,
            resolution,
            "callable target requires whole-program Scala dispatch refinement",
            "call target requires whole-program Scala dispatch refinement",
        )
    }

    fn point(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        effects: Vec<SemanticEffect>,
    ) -> Result<ProgramPointId, ScalaLoweringError> {
        let metadata = self.mapping(builder, node)?;
        self.session.add_point(builder, metadata, effects)
    }

    fn mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<PointMetadata, ScalaLoweringError> {
        self.session.add_node_mapping(builder, node)
    }

    fn value_mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<PointMetadata, ScalaLoweringError> {
        let anchor = source_anchor(node, 0).map_err(ScalaLoweringError::Invalid)?;
        self.session
            .add_mapping(builder, anchor, SourceMappingKind::Exact)
    }

    fn metadata(&self, point: ProgramPointId) -> Result<PointMetadata, ScalaLoweringError> {
        self.session.metadata(point)
    }

    fn value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        kind: SemanticValueKind,
    ) -> Result<ValueId, ScalaLoweringError> {
        self.session.add_value(builder, point, kind)
    }

    fn append_effect(
        &self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        effect: SemanticEffect,
    ) -> Result<(), ScalaLoweringError> {
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
    ) -> Result<(), ScalaLoweringError> {
        self.session
            .add_gap(builder, point, subject, capability, kind, detail)?;
        Ok(())
    }

    fn edge(
        &self,
        builder: &mut ProcedureCfgBuilder,
        source_point: ProgramPointId,
        target: EdgeTarget,
    ) -> Result<(), ScalaLoweringError> {
        self.session
            .add_edge(builder, source_point, target.point, target.kind)
    }
}

fn is_scala_nested_execution_boundary(node: Node<'_>) -> bool {
    // A `match` or `catch` case block executes inline in the enclosing
    // procedure -- `expression` lowers exactly those through `case_dispatch`
    // rather than through `callable_value` -- so its arms' bindings belong to
    // the enclosing procedure's binding table, not behind a boundary.
    if node.kind() == "case_block" {
        return case_block_is_partial_function(node);
    }
    matches!(
        node.kind(),
        "function_definition"
            | "lambda_expression"
            | "class_definition"
            | "object_definition"
            | "trait_definition"
            | "enum_definition"
            | "given_definition"
    )
}

fn scala_local_scope(node: Node<'_>, procedure_body: Node<'_>) -> Option<(usize, usize)> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "block"
                | "indented_block"
                | "case_clause"
                | "catch_clause"
                | "for_expression"
                | "while_expression"
                | "do_while_expression"
        ) || parent.id() == procedure_body.id()
        {
            return Some((parent.start_byte(), parent.end_byte()));
        }
        if is_scala_nested_execution_boundary(parent) {
            return Some((parent.start_byte(), parent.end_byte()));
        }
        current = parent.parent();
    }
    None
}

fn enclosing_extension_definition(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        match parent.kind() {
            "extension_definition" => return Some(parent),
            "class_definition"
            | "object_definition"
            | "trait_definition"
            | "enum_definition"
            | "function_definition"
            | "lambda_expression" => return None,
            _ => node = parent,
        }
    }
    None
}

fn implicit_result_node(mut body: Node<'_>) -> Option<Node<'_>> {
    loop {
        if !matches!(
            body.kind(),
            "block" | "indented_block" | "template_body" | "with_template_body"
        ) {
            return Some(body);
        }
        body = runtime_statement_children(body).into_iter().next_back()?;
    }
}

fn scala_constructed_type_node(node: Node<'_>) -> Option<Node<'_>> {
    let instance = match node.kind() {
        "instance_expression" => node,
        "call_expression" => node
            .child_by_field_name("function")
            .filter(|function| function.kind() == "instance_expression")?,
        _ => return None,
    };
    instance.child_by_field_name("type").or_else(|| {
        named_children(instance).into_iter().find(|child| {
            !matches!(
                child.kind(),
                "arguments" | "template_body" | "block" | "indented_block"
            )
        })
    })
}

fn scala_type_nodes_have_same_identity(left: Node<'_>, right: Node<'_>, source: &str) -> bool {
    let left = super::scala_type_lookup_segments(left, source);
    !left.is_empty() && left == super::scala_type_lookup_segments(right, source)
}

fn scala_type_identity(node: Node<'_>, source: &str) -> Option<Arc<[String]>> {
    let segments = super::scala_type_lookup_segments(node, source);
    (!segments.is_empty()).then(|| Arc::from(segments.into_boxed_slice()))
}

fn callable_has_simple_parameter_shape(callable: Node<'_>) -> bool {
    let mut parameter_lists = 0;
    for child in named_children(callable) {
        match child.kind() {
            "type_parameters" => return false,
            "parameters" => {
                parameter_lists += 1;
                if parameter_lists > 1 {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

fn scala_literal_has_declared_identity_type(
    declared: Node<'_>,
    expression: Node<'_>,
    source: &str,
) -> bool {
    let Some(expected) = scala_literal_type_name(expression) else {
        return false;
    };
    super::scala_type_lookup_segments(declared, source)
        .last()
        .is_some_and(|segment| segment == expected)
}

fn scala_literal_type_name(node: Node<'_>) -> Option<&'static str> {
    match node.kind() {
        "integer_literal" => Some("Int"),
        "floating_point_literal" => Some("Double"),
        "boolean_literal" => Some("Boolean"),
        "character_literal" => Some("Char"),
        "string" | "string_literal" => Some("String"),
        "unit" => Some("Unit"),
        _ => None,
    }
}

/// Whether a type names one of the Scala value classes (or `String`) whose
/// operator members the language defines, rather than a user type that can
/// give an operator its own meaning.
fn scala_type_name_is_language_defined(name: &str) -> bool {
    matches!(
        name,
        "Int" | "Long" | "Short" | "Byte" | "Double" | "Float" | "Char" | "Boolean" | "String"
    )
}

/// Whether an operator is spelled entirely from Scala's operator characters,
/// so that on a value-class receiver it names a language-defined member.
///
/// `/` and `%` are excluded: integral division aborts on a zero divisor, and
/// that abort edge is only lowered on the dispatched-call path.
fn scala_operator_is_language_defined(operator: &str) -> bool {
    !operator.is_empty()
        && !matches!(operator, "/" | "%")
        && operator
            .chars()
            .all(|character| "+-*/%<>=!&|^~".contains(character))
}

fn scala_operator_yields_boolean(operator: &str) -> bool {
    matches!(
        operator,
        "<" | ">" | "<=" | ">=" | "==" | "!=" | "&&" | "||"
    )
}

fn compilation_unit_root(node: Node<'_>) -> Node<'_> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        current = parent;
    }
    current
}

/// Whether the nearest template enclosing `callable` declares parents, whose
/// members this compilation unit does not show.
fn enclosing_template_declares_parents(callable: Node<'_>) -> bool {
    let mut current = callable;
    while let Some(parent) = current.parent() {
        if matches!(
            parent.kind(),
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition"
        ) {
            return parent.child_by_field_name("extend").is_some();
        }
        current = parent;
    }
    false
}

fn scala_function_definitions_named<'tree>(
    root: Node<'tree>,
    name: &str,
    source: &str,
) -> Vec<Node<'tree>> {
    let mut found = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "function_definition"
            && node
                .child_by_field_name("name")
                .and_then(|declared| node_text(source, declared))
                == Some(name)
        {
            found.push(node);
        }
        stack.extend(named_children(node));
    }
    found
}

/// Whether a definition is written directly in a template body, which makes
/// it that template's member rather than a block-local binding.
fn is_scala_template_member(node: Node<'_>) -> bool {
    node.parent()
        .is_some_and(|parent| matches!(parent.kind(), "template_body" | "with_template_body"))
}

/// The class-like definitions this compilation unit declares under `name`.
fn scala_type_definitions_named<'tree>(
    root: Node<'tree>,
    name: &str,
    source: &str,
) -> Vec<Node<'tree>> {
    let mut found = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if matches!(
            node.kind(),
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition"
        ) && node
            .child_by_field_name("name")
            .and_then(|declared| node_text(source, declared))
            == Some(name)
        {
            found.push(node);
        }
        stack.extend(named_children(node));
    }
    found
}

/// The `val` or `var` definition a template declares directly for `member`.
fn scala_template_value_member<'tree>(
    template: Node<'tree>,
    member: &str,
    source: &str,
) -> Option<Node<'tree>> {
    let body = template.child_by_field_name("body")?;
    let mut declarations = named_children(body)
        .into_iter()
        .filter(|child| {
            matches!(child.kind(), "val_definition" | "var_definition")
                && child
                    .child_by_field_name("pattern")
                    .and_then(|pattern| node_text(source, pattern))
                    == Some(member)
        })
        .collect::<Vec<_>>();
    let declaration = declarations.pop()?;
    declarations.is_empty().then_some(declaration)
}

/// The element type argument of a written `Array[T]` type node.
fn scala_array_element_type_node<'tree>(node: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    if node.kind() != "generic_type" {
        return None;
    }
    let base = node.child_by_field_name("type")?;
    if super::scala_type_lookup_segments(base, source)
        .last()
        .map(String::as_str)
        != Some("Array")
    {
        return None;
    }
    let arguments = node.child_by_field_name("type_arguments")?;
    named_children(arguments).into_iter().next()
}

/// The binder and its written type in a `case name: T =>` pattern.
fn typed_pattern_binding(pattern: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    if pattern.kind() != "typed_pattern" {
        return None;
    }
    let binder = pattern.child_by_field_name("pattern")?;
    if binder.kind() != "identifier" {
        return None;
    }
    Some((binder, pattern.child_by_field_name("type")?))
}

fn scala_bound_receiver(callable: Node<'_>) -> Option<Node<'_>> {
    (callable.kind() == "field_expression")
        .then(|| callable.child_by_field_name("value"))
        .flatten()
}

fn scala_call_like_receiver<'tree>(
    source_node: Node<'tree>,
    function: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    if let Some(receiver) = scala_bound_receiver(function) {
        return Some(receiver);
    }
    match source_node.kind() {
        "infix_expression" => {
            let field =
                if infix_operator(source, source_node).is_some_and(|name| name.ends_with(':')) {
                    "right"
                } else {
                    "left"
                };
            source_node.child_by_field_name(field)
        }
        "postfix_expression" => {
            let mut cursor = source_node.walk();
            source_node
                .named_children(&mut cursor)
                .find(|child| child.end_byte() <= function.start_byte())
        }
        "prefix_expression" => first_runtime_named_child(source_node),
        _ => None,
    }
}

fn expression_value_kind(node: Node<'_>) -> SemanticValueKind {
    match node.kind() {
        "function_definition" | "lambda_expression" | "case_block" => SemanticValueKind::Callable,
        "integer_literal"
        | "floating_point_literal"
        | "boolean_literal"
        | "character_literal"
        | "string"
        | "symbol_literal"
        | "null_literal"
        | "unit" => SemanticValueKind::Constant,
        _ => SemanticValueKind::Temporary,
    }
}

fn first_runtime_named_child(node: Node<'_>) -> Option<Node<'_>> {
    named_children(node)
        .into_iter()
        .find(|child| is_runtime_node(child.kind()))
}

fn required_field<'tree>(
    node: Node<'tree>,
    field: &str,
) -> Result<Node<'tree>, ScalaLoweringError> {
    node.child_by_field_name(field)
        .ok_or_else(|| missing_field(node, field))
}

fn required_runtime_field<'tree>(
    node: Node<'tree>,
    field: &str,
) -> Result<Node<'tree>, ScalaLoweringError> {
    children_by_field_name(node, field)
        .into_iter()
        .find(|child| child.is_named() && is_runtime_node(child.kind()))
        .ok_or_else(|| missing_field(node, field))
}

fn missing_field(node: Node<'_>, field: &str) -> ScalaLoweringError {
    ScalaLoweringError::Invalid(format!(
        "{} node at bytes {}..{} is missing structured field {field}",
        node.kind(),
        node.start_byte(),
        node.end_byte()
    ))
}

fn infix_operator<'source>(source: &'source str, node: Node<'_>) -> Option<&'source str> {
    node.child_by_field_name("operator")
        .and_then(|operator| node_text(source, operator))
}

fn flattened_call_parts<'tree>(
    node: Node<'tree>,
) -> Result<(Node<'tree>, Vec<Node<'tree>>), ScalaLoweringError> {
    let mut current = node;
    let mut argument_lists = Vec::new();
    loop {
        argument_lists.push(required_field(current, "arguments")?);
        let function = required_field(current, "function")?;
        if function.kind() == "call_expression" {
            current = function;
        } else {
            argument_lists.reverse();
            return Ok((function, argument_lists));
        }
    }
}

fn normalized_callable_expression(mut node: Node<'_>) -> Result<Node<'_>, ScalaLoweringError> {
    while node.kind() == "generic_function" {
        node = required_field(node, "function")?;
    }
    Ok(node)
}

/// The label and passed value of a Scala named call argument.
///
/// The shape test is structural and belongs to the shared Scala layer: the
/// assignment must sit directly in an invocation's argument list
/// (`is_scala_named_argument_assignment`) and its left side must be a plain
/// name (`named_argument_parts`). `x.y = 1` written as an argument satisfies
/// neither and stays the unit-typed assignment expression it is.
fn named_call_argument_parts<'tree>(argument: Node<'tree>) -> Option<(Node<'tree>, Node<'tree>)> {
    is_scala_named_argument_assignment(argument)
        .then(|| named_argument_parts(argument))
        .flatten()
}

/// The expression a written call argument evaluates.
fn call_argument_value_node(argument: Node<'_>) -> Node<'_> {
    named_call_argument_parts(argument).map_or(argument, |(_, passed)| passed)
}

fn semantic_argument_nodes(arguments: Node<'_>) -> Vec<Node<'_>> {
    if has_structured_by_name_argument(arguments) {
        vec![arguments]
    } else {
        runtime_expression_children(arguments)
    }
}

fn runtime_statement_children(node: Node<'_>) -> Vec<Node<'_>> {
    named_children(node)
        .into_iter()
        .filter(|child| {
            !matches!(
                child.kind(),
                "comment" | "line_comment" | "block_comment" | "self_type"
            )
        })
        .collect()
}

fn runtime_expression_children(node: Node<'_>) -> Vec<Node<'_>> {
    named_children(node)
        .into_iter()
        .filter(|child| is_runtime_node(child.kind()))
        .collect()
}

/// Return executable expressions from structured parent-constructor argument
/// lists. Curried trailing lists are unfielded children of `extends_clause`,
/// so collect every direct `arguments` child in source order.
fn parent_argument_expressions(extends_clause: Node<'_>) -> Vec<Node<'_>> {
    named_children(extends_clause)
        .into_iter()
        .filter(|child| child.kind() == "arguments")
        .flat_map(runtime_expression_children)
        .collect()
}

fn case_arms(node: Node<'_>) -> Vec<Node<'_>> {
    let mut arms = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "case_clause" {
            arms.push(current);
            continue;
        }
        let children = named_children(current);
        for child in children.into_iter().rev() {
            if matches!(
                child.kind(),
                "case_block" | "indented_cases" | "case_clause"
            ) {
                stack.push(child);
            }
        }
    }
    arms.sort_by_key(Node::start_byte);
    arms
}

fn catch_arms(catch_clause: Node<'_>) -> Vec<Node<'_>> {
    let nested = case_arms(catch_clause);
    if nested.is_empty()
        && (catch_clause.child_by_field_name("body").is_some()
            || catch_clause.child_by_field_name("pattern").is_some())
    {
        vec![catch_clause]
    } else {
        nested
    }
}

fn case_pattern(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("pattern")
}

fn case_guard(node: Node<'_>) -> Option<Node<'_>> {
    named_children(node)
        .into_iter()
        .find(|child| child.kind() == "guard")
}

fn case_body_nodes(node: Node<'_>) -> Vec<Node<'_>> {
    let bodies = children_by_field_name(node, "body")
        .into_iter()
        .filter(|child| child.is_named() && is_runtime_node(child.kind()))
        .collect::<Vec<_>>();
    if !bodies.is_empty() {
        return bodies;
    }
    named_children(node)
        .into_iter()
        .filter(|child| {
            child.kind() != "guard"
                && case_pattern(node).is_none_or(|pattern| child.id() != pattern.id())
                && is_runtime_node(child.kind())
        })
        .collect()
}

fn enumerator_rhs(enumerator: Node<'_>) -> Option<Node<'_>> {
    let children = named_children(enumerator);
    children
        .into_iter()
        .rev()
        .find(|child| child.kind() != "guard" && is_runtime_node(child.kind()))
}

fn has_direct_token(node: Node<'_>, kind: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor).any(|child| child.kind() == kind)
}

fn contains_token(node: Node<'_>, kind: &str) -> bool {
    subtree_contains(node, |current| has_direct_token(current, kind))
}

fn is_runtime_node(kind: &str) -> bool {
    !matches!(
        kind,
        "type_identifier"
            | "type_arguments"
            | "type_parameters"
            | "parameters"
            | "parameter"
            | "annotation"
            | "modifiers"
            | "access_modifier"
            | "variance_parameter"
            | "function_type"
            | "generic_type"
            | "infix_type"
            | "annotated_type"
            | "applied_constructor_type"
    )
}

/// The value of a `boolean_literal`, which the grammar spells as bare text
/// rather than as two node kinds -- the same shape Kotlin's adapter reads.
fn boolean_literal_value(source: &str, node: Node<'_>) -> Option<bool> {
    if node.kind() != "boolean_literal" {
        return None;
    }
    match node_text(source, node)? {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// The value of an `integer_literal`, or `None` when it is not a plain decimal
/// the adapter can read exactly. A suffixed, underscored, or radix-prefixed
/// literal answers `None` rather than a guessed number.
fn integer_literal_value(source: &str, node: Node<'_>) -> Option<i64> {
    (node.kind() == "integer_literal")
        .then(|| node_text(source, node))
        .flatten()
        .and_then(|text| text.parse().ok())
}

/// The constant value of a condition, once parentheses and `!` are peeled.
///
/// `!` inverts the outcome rather than deciding one of its own, so peeling it
/// is a rewrite, not a lost evaluation: `Boolean.unary_!` is language-defined
/// and cannot be overridden for a literal. Anything else answers `None` and
/// keeps the ordinary two-armed lowering.
fn constant_boolean_condition(source: &str, node: Node<'_>) -> Option<bool> {
    let mut cursor = node;
    let mut negated = false;
    loop {
        match cursor.kind() {
            "parenthesized_expression" => cursor = first_runtime_named_child(cursor)?,
            "prefix_expression" if has_direct_token(cursor, "!") => {
                negated = !negated;
                cursor = first_runtime_named_child(cursor)?;
            }
            _ => break,
        }
    }
    Some(boolean_literal_value(source, cursor)? != negated)
}

/// Whether a `while` guard is provably true the first time it is tested, so
/// the loop body runs before the exit test is ever taken.
///
/// This is the while-header analogue of Java's `for_condition_starts_true`
/// (`java/semantic/control.rs`) and of `kotlin_range_has_first_iteration`.
/// Java gets the proof cheaply because a counted `for` initializes its counter
/// inside the header; Scala's counter is a sibling statement, so the binding
/// has to be found in the enclosing block. The proof is deliberately narrow
/// and purely structural:
///
/// * the loop is a direct runtime statement of a block;
/// * the guard compares an identifier with an integer literal through one of
///   `<`, `<=`, `>`, `>=`;
/// * exactly one preceding statement of that block binds the identifier, as a
///   `val`/`var` definition whose value is an integer literal, and no other
///   preceding statement mentions the identifier at all -- any intervening
///   write, call that could observe or rebind it, or nested shadowing
///   disqualifies the proof;
/// * the comparison over the two literals decides true.
///
/// Anything unproven answers `false`, which keeps the ordinary zero-trip
/// shape. That shape is an over-approximation, never a wrong answer.
fn while_guard_is_true_on_entry(source: &str, loop_node: Node<'_>, condition: Node<'_>) -> bool {
    let mut guard = condition;
    while guard.kind() == "parenthesized_expression" {
        let Some(inner) = first_runtime_named_child(guard) else {
            return false;
        };
        guard = inner;
    }
    if guard.kind() != "infix_expression" {
        return false;
    }
    let (Some(left), Some(right), Some(operator)) = (
        guard.child_by_field_name("left"),
        guard.child_by_field_name("right"),
        infix_operator(source, guard),
    ) else {
        return false;
    };
    if !matches!(operator, "<" | "<=" | ">" | ">=") {
        return false;
    }
    // One side names the counter, the other bounds it. Both sides literal is
    // not this shape, and neither is both sides identifier.
    let (counter, bound, counter_on_left) = match (
        left.kind(),
        integer_literal_value(source, right),
        integer_literal_value(source, left),
        right.kind(),
    ) {
        ("identifier", Some(bound), _, _) => (left, bound, true),
        (_, _, Some(bound), "identifier") => (right, bound, false),
        _ => return false,
    };
    let Some(name) = node_text(source, counter) else {
        return false;
    };
    let Some(block) = loop_node.parent() else {
        return false;
    };
    if !matches!(block.kind(), "block" | "indented_block") {
        return false;
    }
    let preceding = runtime_statement_children(block)
        .into_iter()
        .take_while(|statement| statement.start_byte() < loop_node.start_byte())
        .collect::<Vec<_>>();
    let mut initial = None;
    for statement in preceding {
        if let Some((bound_name, bound_value)) = literal_integer_binding(source, statement)
            && bound_name == name
        {
            if initial.replace(bound_value).is_some() {
                return false;
            }
            continue;
        }
        // Any other mention of the counter before the loop -- a write, a call
        // that could observe it, a nested rebinding -- ends the proof.
        if mentions_identifier(source, statement, name) {
            return false;
        }
    }
    let Some(initial) = initial else {
        return false;
    };
    let (left_value, right_value) = if counter_on_left {
        (initial, bound)
    } else {
        (bound, initial)
    };
    match operator {
        "<" => left_value < right_value,
        "<=" => left_value <= right_value,
        ">" => left_value > right_value,
        ">=" => left_value >= right_value,
        _ => false,
    }
}

/// The name and value a statement binds, when it is a `val`/`var` definition
/// of one plain identifier to an integer literal.
fn literal_integer_binding<'source>(
    source: &'source str,
    statement: Node<'_>,
) -> Option<(&'source str, i64)> {
    if !matches!(statement.kind(), "val_definition" | "var_definition") {
        return None;
    }
    let pattern = statement.child_by_field_name("pattern")?;
    if pattern.kind() != "identifier" {
        return None;
    }
    let value = statement.child_by_field_name("value")?;
    Some((
        node_text(source, pattern)?,
        integer_literal_value(source, value)?,
    ))
}

/// Whether an identifier of this name occurs anywhere in the statement.
fn mentions_identifier(source: &str, statement: Node<'_>, name: &str) -> bool {
    let mut stack = vec![statement];
    while let Some(node) = stack.pop() {
        if node.kind() == "identifier" && node_text(source, node) == Some(name) {
            return true;
        }
        stack.extend(named_children(node));
    }
    false
}

fn is_runtime_leaf(kind: &str) -> bool {
    matches!(
        kind,
        "identifier"
            | "operator_identifier"
            | "integer_literal"
            | "floating_point_literal"
            | "boolean_literal"
            | "character_literal"
            | "string"
            | "symbol_literal"
            | "null_literal"
            | "unit"
            | "this"
            | "super"
            | "wildcard"
    )
}

fn identifier_has_auto_application_ambiguity(node: Node<'_>) -> bool {
    !node.parent().is_some_and(|parent| {
        matches!(
            parent.kind(),
            "call_expression"
                | "arguments"
                | "field_expression"
                | "infix_expression"
                | "postfix_expression"
                | "prefix_expression"
                | "case_clause"
                | "guard"
                | "parameters"
                | "parameter"
                | "type_parameters"
                | "type_arguments"
        )
    })
}

/// Whether the callable declares a `Unit` (or `scala.Unit`) result type.
/// Adaptation to `Unit` is a value discard, never an implicit conversion.
fn callable_declares_unit_result(callable: Node<'_>, source: &str) -> bool {
    callable
        .child_by_field_name("return_type")
        .is_some_and(|declared| {
            let segments = super::scala_type_lookup_segments(declared, source);
            matches!(
                segments
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .as_slice(),
                ["Unit"] | ["scala", "Unit"]
            )
        })
}

fn callable_has_by_name_parameter(callable: Node<'_>) -> bool {
    let mut stack = children_by_field_name(callable, "parameters");
    while let Some(node) = stack.pop() {
        if node.kind() == "lazy_parameter_type" {
            return true;
        }
        stack.extend(named_children(node));
    }
    false
}

fn has_structured_by_name_argument(arguments: Node<'_>) -> bool {
    matches!(arguments.kind(), "block" | "case_block" | "colon_argument")
}

fn is_future_like_call(source: &str, function: Node<'_>) -> bool {
    matches!(function.kind(), "identifier" | "field_expression")
        && node_text(source, function)
            .is_some_and(|text| text == "Future" || text.ends_with(".Future"))
}
