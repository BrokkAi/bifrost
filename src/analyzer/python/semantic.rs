//! Python lowering into the language-neutral executable-semantics IR.
//!
//! This module deliberately interprets tree-sitter nodes and fields directly.
//! Graph construction, abrupt-completion routing, cleanup specialization, and
//! physical adjacency storage remain owned by the shared semantic substrate.

use tree_sitter::Node;

use super::bindings::{
    PythonDirectScopeBindingKind, PythonLexicalNameResolution, PythonLexicalScopeInventory,
    python_direct_scope_bindings_bounded,
};
use crate::analyzer::lexical_definitions::{PythonMethodBinding, formal_parameter_slots_for_owner};
use crate::analyzer::semantic::cfg::{
    CleanupRegionId, CompletionKind, CompletionRequest, CompletionRoute, DriveError,
    ProcedureCfgBuilder, ScopeBinding, ScopeFrameId,
};
use crate::analyzer::semantic::service::{ProgramSemanticsLowerer, SemanticAdapterIdentity};
use crate::analyzer::semantic::*;
use crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree;
use crate::analyzer::{Language, ProjectFile, PythonAnalyzer, Range};
use crate::hash::{HashMap, HashSet};

const ADAPTER_VERSION: &[u8] = b"python-value-semantics-v3";

impl_program_semantics_provider!(PythonAnalyzer, PythonSemanticLowerer);

struct PythonSemanticLowerer;

impl ProgramSemanticsLowerer for PythonSemanticLowerer {
    fn identity(&self) -> SemanticAdapterIdentity {
        SemanticAdapterIdentity {
            adapter: AdapterSemanticsVersion::hash_bytes("python", ADAPTER_VERSION)
                .expect("adapter name is non-empty"),
            configuration: ConfigurationFingerprint::hash_bytes(
                b"python-intrafile-execution-defaults-v1",
            ),
            dependencies: DependencyFingerprint::hash_bytes(b"no-intrafile-dependencies"),
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
        let (specs, class_names, enumeration_work) =
            match enumerate_procedures(file, prepared, budget, cancellation)? {
                ProcedureEnumeration::Complete {
                    specs,
                    class_names,
                    work,
                } => (specs, class_names, work),
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
            enumeration_work,
            budget,
            cancellation,
            |spec, staged_budget, cancellation| {
                lower_procedure(prepared, spec, &class_names, staged_budget, cancellation)
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
}

enum ProcedureEnumeration<'tree> {
    Complete {
        specs: Vec<ProcedureSpec<'tree>>,
        class_names: HashSet<Box<str>>,
        work: SemanticWork,
    },
    ExceededBudget {
        exceeded: SemanticBudgetExceeded,
        work: SemanticWork,
    },
    Cancelled {
        work: SemanticWork,
    },
}

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
    let mount = WorkspaceMountId::from_root(file.root());
    let path = WorkspaceRelativePath::try_from_path(file.rel_path())
        .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;
    let language = prepared.dialect();
    let root = prepared.tree().root_node();
    let file_anchor = source_anchor(root, 0).map_err(SemanticProviderError::invalid_identity)?;
    let file_name = file
        .rel_path()
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("python-source");
    let file_segment =
        DeclarationSegment::named(DeclarationSegmentKind::File, file_name, file_anchor, 0)
            .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;

    type SiblingKey = (usize, DeclarationSegmentKind, Option<Box<str>>);
    let mut specs = Vec::new();
    let mut siblings: HashMap<SiblingKey, u32> = HashMap::default();
    let mut declaration_paths = vec![DeclarationPathEntry {
        parent: None,
        segment: file_segment,
    }];
    let mut preflight = SemanticWork::default();
    let mut traversal_work = SemanticWork::default();
    let mut module_bindings: HashMap<Box<str>, PythonDirectScopeBindingKind> = HashMap::default();
    let mut stack = vec![ProcedureEnumerationFrame {
        node: root,
        lexical_parent: None,
        declaration_path: 0,
        entry_precharged: false,
    }];

    while let Some(frame) = stack.pop() {
        if cancellation.is_cancelled() {
            return Ok(ProcedureEnumeration::Cancelled {
                work: sum_lowering_work(preflight, traversal_work),
            });
        }
        if !frame.entry_precharged {
            let traversal = sum_lowering_work(
                traversal_work,
                SemanticWork {
                    nested_entries: 1,
                    ..SemanticWork::default()
                },
            );
            let traversal_candidate = sum_lowering_work(preflight, traversal);
            if let Err(exceeded) = budget.check(traversal_candidate) {
                return Ok(ProcedureEnumeration::ExceededBudget {
                    exceeded,
                    work: traversal_candidate,
                });
            }
            traversal_work = traversal;
        }

        if frame.lexical_parent.is_none() && frame.declaration_path == 0 {
            let mut binding_scan_cancelled = false;
            let mut binding_scan_exceeded = None;
            let bindings =
                python_direct_scope_bindings_bounded(frame.node, prepared.source(), || {
                    if cancellation.is_cancelled() {
                        binding_scan_cancelled = true;
                        return false;
                    }
                    let next = sum_lowering_work(
                        traversal_work,
                        SemanticWork {
                            nested_entries: 1,
                            ..SemanticWork::default()
                        },
                    );
                    let candidate = sum_lowering_work(preflight, next);
                    match budget.check(candidate) {
                        Ok(()) => {
                            traversal_work = next;
                            true
                        }
                        Err(exceeded) => {
                            binding_scan_exceeded = Some((exceeded, candidate));
                            false
                        }
                    }
                });
            let Some(bindings) = bindings else {
                if binding_scan_cancelled {
                    return Ok(ProcedureEnumeration::Cancelled {
                        work: sum_lowering_work(preflight, traversal_work),
                    });
                }
                let (exceeded, work) =
                    binding_scan_exceeded.expect("bounded binding scan stopped without a cause");
                return Ok(ProcedureEnumeration::ExceededBudget { exceeded, work });
            };
            for binding in bindings {
                let Some(name) = node_text(prepared.source(), binding.declaration) else {
                    continue;
                };
                if let Some(existing) = module_bindings.get_mut(name) {
                    // Multiple module bindings are not a proven class identity,
                    // even when more than one of them is a class declaration.
                    *existing = PythonDirectScopeBindingKind::Other;
                    continue;
                }
                let inventory = sum_lowering_work(
                    traversal_work,
                    SemanticWork {
                        owned_text_bytes: name.len(),
                        ..SemanticWork::default()
                    },
                );
                let inventory_candidate = sum_lowering_work(preflight, inventory);
                if let Err(exceeded) = budget.check(inventory_candidate) {
                    return Ok(ProcedureEnumeration::ExceededBudget {
                        exceeded,
                        work: inventory_candidate,
                    });
                }
                traversal_work = inventory;
                module_bindings.insert(name.into(), binding.kind);
            }
        }

        let child_path = frame.declaration_path;
        let mut container_body_scope = None;
        if let Some(segment_kind) = declaration_container_kind(frame.node) {
            let name = declaration_container_name(prepared.source(), frame.node);
            let ordinal = next_sibling_ordinal(
                &mut siblings,
                frame.declaration_path,
                segment_kind,
                name.as_deref(),
            );
            let anchor =
                source_anchor(frame.node, 0).map_err(SemanticProviderError::invalid_identity)?;
            let segment = declaration_segment(segment_kind, name.as_deref(), anchor, ordinal)
                .map_err(SemanticProviderError::invalid_identity)?;
            let container_path =
                push_declaration_path(&mut declaration_paths, frame.declaration_path, segment);
            if let Some(body) = frame.node.child_by_field_name("body") {
                container_body_scope = Some((body.id(), container_path));
            }
        }

        let mut callable_body_scope = None;
        if let Some((kind, segment_kind, body, properties)) =
            callable_shape(frame.node, frame.lexical_parent)
        {
            let id = ProcedureId::try_from_index(specs.len())
                .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
            let name = callable_name(prepared.source(), frame.node);
            let ordinal =
                next_sibling_ordinal(&mut siblings, child_path, segment_kind, name.as_deref());
            let anchor =
                source_anchor(frame.node, 0).map_err(SemanticProviderError::invalid_identity)?;
            let segment = declaration_segment(segment_kind, name.as_deref(), anchor, ordinal)
                .map_err(SemanticProviderError::invalid_identity)?;
            let mut segments = collect_declaration_path(&declaration_paths, child_path);
            segments.push(segment.clone());
            let declaration = DeclarationLocator::new(segments)
                .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;
            let locator = SemanticLocator::new(
                mount,
                path.clone(),
                language,
                declaration,
                SemanticRole::Procedure,
                anchor,
            );
            let candidate = sum_lowering_work(preflight, procedure_identity_preflight(&locator));
            let candidate_with_traversal = sum_lowering_work(candidate, traversal_work);
            if let Err(exceeded) = budget.check(candidate_with_traversal) {
                return Ok(ProcedureEnumeration::ExceededBudget {
                    exceeded,
                    work: candidate_with_traversal,
                });
            }
            preflight = candidate;
            specs.push(ProcedureSpec {
                id,
                callable: frame.node,
                body,
                locator,
                lexical_parent: frame.lexical_parent,
                kind,
                properties,
            });
            let callable_path = push_declaration_path(&mut declaration_paths, child_path, segment);
            callable_body_scope = Some((body.id(), id, callable_path));
        }

        for child_index in (0..frame.node.child_count()).rev() {
            if cancellation.is_cancelled() {
                return Ok(ProcedureEnumeration::Cancelled {
                    work: sum_lowering_work(preflight, traversal_work),
                });
            }
            let Some(child) = frame
                .node
                .child(child_index)
                .filter(|child| child.is_named())
            else {
                continue;
            };
            let traversal = sum_lowering_work(
                traversal_work,
                SemanticWork {
                    nested_entries: 1,
                    ..SemanticWork::default()
                },
            );
            let traversal_candidate = sum_lowering_work(preflight, traversal);
            if let Err(exceeded) = budget.check(traversal_candidate) {
                return Ok(ProcedureEnumeration::ExceededBudget {
                    exceeded,
                    work: traversal_candidate,
                });
            }
            traversal_work = traversal;
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

    let class_names = module_bindings
        .into_iter()
        .filter_map(|(name, kind)| {
            (kind == PythonDirectScopeBindingKind::ClassDeclaration).then_some(name)
        })
        .collect();
    Ok(ProcedureEnumeration::Complete {
        specs,
        class_names,
        // Procedure lowering accounts retained locator identity. Seed only the
        // one-time file inventory to avoid charging that identity twice.
        work: traversal_work,
    })
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
            let segment = match kind {
                ProcedureKind::Method => DeclarationSegmentKind::Method,
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
            ..ProcedureProperties::default()
        },
    ))
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

#[derive(Debug, Clone, Copy)]
struct EdgeTarget {
    point: ProgramPointId,
    kind: ControlEdgeKind,
}

impl EdgeTarget {
    const fn normal(point: ProgramPointId) -> Self {
        Self {
            point,
            kind: ControlEdgeKind::Normal,
        }
    }
}

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
    body: CleanupBody<'tree>,
    outer_scope: ScopeFrameId,
}

#[derive(Debug, Clone, Copy)]
enum CleanupBody<'tree> {
    Statement(Node<'tree>),
}

impl<'tree> CleanupBody<'tree> {
    const fn source_node(self) -> Node<'tree> {
        match self {
            Self::Statement(node) => node,
        }
    }
}

struct LoweringContext<'tree, 'targets> {
    prepared: &'tree PreparedSyntaxTree,
    callable: Node<'tree>,
    session: ProcedureLoweringSession<'targets>,
    expression_values: HashMap<usize, ValueId>,
    parameters: HashMap<Box<str>, ValueId>,
    locals: HashMap<Box<str>, ValueId>,
    receiver: Option<ValueId>,
    class_names: &'targets HashSet<Box<str>>,
    bindings: PythonLexicalScopeInventory<'tree>,
    cleanups: Vec<CleanupRegion<'tree>>,
}

fn lower_procedure<'tree, 'targets>(
    prepared: &'tree PreparedSyntaxTree,
    spec: &ProcedureSpec<'tree>,
    class_names: &'targets HashSet<Box<str>>,
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
    let bindings = collect_semantic_binding_inventory(
        spec.callable,
        prepared.source(),
        &mut builder,
        cancellation,
    )?;
    let mut context = LoweringContext {
        prepared,
        callable: spec.callable,
        session,
        expression_values: HashMap::default(),
        parameters: HashMap::default(),
        locals: HashMap::default(),
        receiver: None,
        class_names,
        bindings,
        cleanups: Vec::new(),
    };
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
        let value = context.value(&mut builder, implicit_return, SemanticValueKind::Return)?;
        let source =
            context.expression_value(&mut builder, spec.body, expression_value_kind(spec.body))?;
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
    context.edge(&mut builder, entry, EdgeTarget::normal(body_entry))?;

    let mut drive_error = None;
    while let Some(initial) = pending.pop() {
        if let Err(error) =
            builder.drive_iteratively(initial, cancellation, |builder, work, stack| {
                context.step(builder, work, stack)
            })
        {
            drive_error = Some(error);
            break;
        }
    }
    if let Some(error) = drive_error {
        let work = builder.prospective_work();
        return match error {
            DriveError::Cancelled | DriveError::Step(PythonLoweringError::Cancelled(_)) => {
                Err(PythonLoweringError::Cancelled(Box::new(work)))
            }
            DriveError::ExceededBudget(exceeded) => {
                Err(PythonLoweringError::Budget(exceeded, Box::new(work)))
            }
            DriveError::Step(PythonLoweringError::Budget(exceeded, _)) => {
                Err(PythonLoweringError::Budget(exceeded, Box::new(work)))
            }
            DriveError::Step(PythonLoweringError::Invalid(detail)) => {
                Err(PythonLoweringError::Invalid(detail))
            }
        };
    }

    if builder
        .seal_unreachable_regions(entry, normal_exit, exceptional_exit, cancellation)
        .is_err()
    {
        return Err(PythonLoweringError::Cancelled(Box::new(
            builder.prospective_work(),
        )));
    }
    let work_before_freeze = builder.prospective_work();
    builder
        .finish_with_work()
        .map_err(|error| PythonLoweringError::Budget(error, Box::new(work_before_freeze)))
}

fn collect_semantic_binding_inventory<'tree>(
    callable: Node<'tree>,
    source: &str,
    builder: &mut ProcedureCfgBuilder,
    cancellation: &CancellationToken,
) -> Result<PythonLexicalScopeInventory<'tree>, PythonLoweringError> {
    let mut stop = None;
    let inventory = PythonLexicalScopeInventory::collect_bounded(callable, source, || {
        match charge_python_binding_step(builder, cancellation) {
            Ok(()) => true,
            Err(error) => {
                stop = Some(error);
                false
            }
        }
    });
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
        let declaration_range = node_range(spec.callable);
        let layout = formal_parameter_slots_for_owner(
            Language::Python,
            spec.callable,
            self.prepared.source(),
            &declaration_range,
        )
        .unwrap_or_default();
        let first_slot_is_receiver = spec.kind == ProcedureKind::Method
            && !matches!(layout.python_binding, Some(PythonMethodBinding::Static));
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
            let receiver = first_slot_is_receiver && slot_index == 0;
            let value = if receiver {
                let value = self.session.add_value_with_metadata(
                    builder,
                    metadata,
                    SemanticValueKind::Receiver,
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
                let inventory = collect_semantic_binding_inventory(
                    parent,
                    self.prepared.source(),
                    builder,
                    self.session.cancellation(),
                )?;
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
        let value = self
            .session
            .add_value_with_metadata(builder, metadata, kind)?;
        self.expression_values.insert(node.id(), value);
        Ok(value)
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
        let Some(source) = self.binding_value(name) else {
            return Ok(());
        };
        let kind = if Some(source) == self.receiver {
            ValueFlowKind::Receiver
        } else if self.locals.get(name) == Some(&source) {
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
            _ => {
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
                let value = (!values.is_empty())
                    .then(|| self.value(builder, terminal, SemanticValueKind::Return))
                    .transpose()?;
                if let ([source_node], Some(target)) = (values.as_slice(), value) {
                    let source = self.expression_value(
                        builder,
                        *source_node,
                        expression_value_kind(*source_node),
                    )?;
                    self.append_effect(
                        builder,
                        terminal,
                        SemanticEffect::ValueFlow {
                            kind: ValueFlowKind::Return,
                            source,
                            target,
                        },
                    )?;
                } else if values.len() > 1 {
                    self.add_gap(
                        builder,
                        terminal,
                        SemanticGapSubject::Point,
                        SemanticCapability::ReturnFlow,
                        SemanticGapKind::Unsupported,
                        "Python tuple return identity is not decomposed into independent values",
                    )?;
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
            "raise_statement" => {
                let values = runtime_expression_children(node);
                let terminal = if values.is_empty() {
                    entry
                } else {
                    self.point(builder, node, Vec::new())?
                };
                let value = (!values.is_empty())
                    .then(|| self.value(builder, terminal, SemanticValueKind::Exception))
                    .transpose()?;
                self.append_effect(builder, terminal, SemanticEffect::Throw { value })?;
                self.abrupt(builder, terminal, scope, CompletionKind::Throw, None, stack)?;
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
                let values = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &values, next, scope, stack)
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
            "call" => self.call_expression(builder, node, entry, next, scope, stack),
            "lambda" => self.callable_expression(builder, node, entry, next),
            "await" => self.await_expression(builder, node, entry, next, scope, stack),
            "yield" => self.yield_expression(builder, node, entry, scope, stack),
            "conditional_expression" => {
                let (consequence, condition, alternative) = conditional_expression_parts(node)?;
                let consequence_entry = self.point(builder, consequence, Vec::new())?;
                let alternative_entry = self.point(builder, alternative, Vec::new())?;
                stack.push(Work::Expression {
                    node: alternative,
                    entry: alternative_entry,
                    next,
                    scope,
                });
                stack.push(Work::Expression {
                    node: consequence,
                    entry: consequence_entry,
                    next,
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
            "boolean_operator" if matches!(boolean_operator_kind(node), Some("and" | "or")) => {
                let left = required_field(node, "left")?;
                let right = required_field(node, "right")?;
                let right_entry = self.point(builder, right, Vec::new())?;
                stack.push(Work::Expression {
                    node: right,
                    entry: right_entry,
                    next,
                    scope,
                });
                let (when_true, when_false) = match boolean_operator_kind(node) {
                    Some("and") => (
                        EdgeTarget {
                            point: right_entry,
                            kind: ControlEdgeKind::ConditionalTrue,
                        },
                        EdgeTarget {
                            point: next.point,
                            kind: ControlEdgeKind::ConditionalFalse,
                        },
                    ),
                    Some("or") => (
                        EdgeTarget {
                            point: next.point,
                            kind: ControlEdgeKind::ConditionalTrue,
                        },
                        EdgeTarget {
                            point: right_entry,
                            kind: ControlEdgeKind::ConditionalFalse,
                        },
                    ),
                    _ => unreachable!("guarded by boolean operator"),
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
            "attribute" | "subscript" => {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Value(result),
                    SemanticCapability::ExceptionalControlFlow,
                    SemanticGapKind::Unsupported,
                    implicit_exception_detail(node),
                )?;
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Value(result),
                    SemanticCapability::Calls,
                    SemanticGapKind::Unknown,
                    "descriptor or special-method invocation requires type refinement",
                )?;
                let children = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            "list_comprehension" | "set_comprehension" | "dictionary_comprehension" => {
                self.session
                    .add_allocation(builder, entry, result, AllocationKind::Object)?;
                self.comprehension_expression(builder, node, entry, None, scope, stack)
            }
            "generator_expression" => {
                self.session
                    .add_allocation(builder, entry, result, AllocationKind::Object)?;
                self.comprehension_expression(builder, node, entry, Some(next), scope, stack)
            }
            "assignment" | "named_expression" => {
                self.assignment_expression(builder, node, entry, next, scope, stack)
            }
            "list" | "set" | "dictionary" => {
                self.session
                    .add_allocation(builder, entry, result, AllocationKind::Object)?;
                let children = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            "tuple" => {
                self.session
                    .add_allocation(builder, entry, result, AllocationKind::Array)?;
                let children = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            "augmented_assignment"
            | "binary_operator"
            | "unary_operator"
            | "not_operator"
            | "expression_list"
            | "pair"
            | "slice"
            | "argument_list"
            | "keyword_argument"
            | "list_splat"
            | "dictionary_splat"
            | "parenthesized_list_splat"
            | "interpolation"
            | "format_expression"
            | "concatenated_string"
            | "string" => {
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
                        "operator, conversion, formatting, or unpacking calls require type refinement",
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
    fn assignment_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PythonLoweringError> {
        let (binding, source_node) = if node.kind() == "named_expression" {
            (
                node.child_by_field_name("name"),
                node.child_by_field_name("value"),
            )
        } else {
            (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            )
        };
        let boundary = self.point(builder, node, Vec::new())?;
        match (binding, source_node) {
            (Some(binding), Some(source_node)) if binding.kind() == "identifier" => {
                let name = node_text(self.prepared.source(), binding).ok_or_else(|| {
                    PythonLoweringError::Invalid(
                        "Python assignment has an invalid identifier range".into(),
                    )
                })?;
                if let Some(target) = self.binding_value(name) {
                    let source = self.expression_value(
                        builder,
                        source_node,
                        expression_value_kind(source_node),
                    )?;
                    self.append_effect(
                        builder,
                        boundary,
                        SemanticEffect::Assignment {
                            target,
                            value: source,
                        },
                    )?;
                    let kind = if Some(target) == self.receiver {
                        ValueFlowKind::Receiver
                    } else if self.locals.get(name) == Some(&target) {
                        ValueFlowKind::Local
                    } else {
                        ValueFlowKind::Parameter
                    };
                    self.append_effect(
                        builder,
                        boundary,
                        SemanticEffect::ValueFlow {
                            kind,
                            source,
                            target,
                        },
                    )?;
                    if node.kind() == "named_expression" {
                        let result =
                            self.expression_value(builder, node, SemanticValueKind::Temporary)?;
                        self.append_effect(
                            builder,
                            boundary,
                            SemanticEffect::Assignment {
                                target: result,
                                value: source,
                            },
                        )?;
                    }
                }
            }
            (Some(_), Some(_)) => {
                self.add_gap(
                    builder,
                    boundary,
                    SemanticGapSubject::Point,
                    SemanticCapability::Assignments,
                    SemanticGapKind::Unsupported,
                    "Python unpacking, attribute, and item assignment identity is not yet lowered",
                )?;
            }
            _ => {
                self.add_gap(
                    builder,
                    boundary,
                    SemanticGapSubject::Point,
                    SemanticCapability::Assignments,
                    SemanticGapKind::Unknown,
                    "Python assignment is missing a structured binding or value",
                )?;
            }
        }
        if operation_can_throw_implicitly(node) {
            self.implicit_exception_gap(builder, boundary, node)?;
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
    fn comprehension_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        continuation: Option<EdgeTarget>,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PythonLoweringError> {
        let outer_iterables = first_comprehension_iterables(node)?;
        let boundary = self.point(builder, node, Vec::new())?;
        if let Some(continuation) = continuation {
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
        } else {
            self.add_gap(
                builder,
                boundary,
                SemanticGapSubject::Point,
                SemanticCapability::NormalControlFlow,
                SemanticGapKind::Unsupported,
                "eager comprehension iteration, filtering, and nested scope are not lowered",
            )?;
            self.add_gap(
                builder,
                boundary,
                SemanticGapSubject::Point,
                SemanticCapability::Calls,
                SemanticGapKind::Unknown,
                "eager comprehension iterator protocol calls require runtime refinement",
            )?;
            self.add_gap(
                builder,
                boundary,
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unknown,
                "eager comprehension iteration and filtering failures are not lowered",
            )?;
        }
        self.schedule_expressions(
            builder,
            entry,
            &outer_iterables,
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
        let binding_runtime = assignment_target_runtime_nodes(binding);
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
        self.edge(builder, binding_boundary, EdgeTarget::normal(body_entry))?;
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
        self.schedule_expressions(
            builder,
            binding_entry,
            &binding_runtime,
            EdgeTarget::normal(binding_boundary),
            loop_scope,
            stack,
        )?;
        stack.push(Work::Expression {
            node: iterable,
            entry,
            next: EdgeTarget::normal(test),
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
                "except-clause type evaluation, matching, and selection require runtime refinement",
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

    #[allow(clippy::too_many_arguments)]
    fn with_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        _next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PythonLoweringError> {
        let clause = named_children(node)
            .into_iter()
            .find(|child| child.kind() == "with_clause")
            .ok_or_else(|| missing_field(node, "with clause"))?;
        let values = named_children(clause)
            .into_iter()
            .filter(|child| child.kind() == "with_item")
            .map(context_manager_expression)
            .collect::<Result<Vec<_>, _>>()?;
        let boundary = self.point(builder, clause, Vec::new())?;
        for (capability, detail) in [
            (
                SemanticCapability::ResourceManagement,
                "context-manager enter/exit ordering and suppression are not lowered",
            ),
            (
                SemanticCapability::Calls,
                "context-manager protocol operations are not represented as call sites",
            ),
            (
                SemanticCapability::ExceptionalControlFlow,
                "context acquisition, enter, exit, and suppression failures are not lowered",
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
        if has_direct_token(node, "async") {
            self.add_gap(
                builder,
                boundary,
                SemanticGapSubject::Point,
                SemanticCapability::AsyncSuspendResume,
                SemanticGapKind::Unsupported,
                "async context-manager enter/exit suspension is not lowered",
            )?;
        }
        self.schedule_expressions(
            builder,
            entry,
            &values,
            EdgeTarget::normal(boundary),
            scope,
            stack,
        )
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
        let invoke = self.point(builder, node, Vec::new())?;
        let normal = self.point(builder, node, Vec::new())?;
        let exceptional = self.point(builder, node, Vec::new())?;
        let function = required_field(node, "function")?;
        let callee = self.expression_value(builder, function, SemanticValueKind::Callable)?;
        let result = self.expression_value(builder, node, SemanticValueKind::Temporary)?;
        let thrown = self.value(builder, invoke, SemanticValueKind::Exception)?;
        let receiver_node = python_call_receiver(function);
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
                    Ok(SemanticCallArgument { value, expansion })
                },
            )
            .collect::<Result<Vec<_>, _>>()?;
        if function.kind() == "identifier"
            && self.module_class_fallback_allowed(builder, function)?
        {
            self.session
                .add_allocation(builder, invoke, result, AllocationKind::Object)?;
        }
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
        self.abrupt(
            builder,
            exceptional,
            scope,
            CompletionKind::Throw,
            None,
            stack,
        )?;
        self.resolution_gaps(builder, invoke, callee, call_site, &resolution)?;

        self.add_gap(
            builder,
            invoke,
            SemanticGapSubject::CallSite(call_site),
            SemanticCapability::DynamicDispatch,
            SemanticGapKind::Unknown,
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
        let suspend = self.point(builder, node, Vec::new())?;
        let normal = self.point(builder, node, Vec::new())?;
        let exceptional = self.point(builder, node, Vec::new())?;
        let awaited = self.value(builder, suspend, SemanticValueKind::Temporary)?;
        let result = self.value(builder, normal, SemanticValueKind::AwaitResult)?;
        self.append_effect(
            builder,
            suspend,
            SemanticEffect::AsyncSuspend {
                awaited: Some(awaited),
                normal_resume: ControlContinuation::Target(normal),
                exceptional_resume: ControlContinuation::Target(exceptional),
            },
        )?;
        self.append_effect(
            builder,
            normal,
            SemanticEffect::AsyncResume {
                suspend,
                kind: AsyncResumeKind::Normal,
                result: Some(result),
            },
        )?;
        self.append_effect(
            builder,
            exceptional,
            SemanticEffect::AsyncResume {
                suspend,
                kind: AsyncResumeKind::Exceptional,
                result: None,
            },
        )?;
        self.edge(
            builder,
            suspend,
            EdgeTarget {
                point: normal,
                kind: ControlEdgeKind::AsyncNormal,
            },
        )?;
        self.edge(
            builder,
            suspend,
            EdgeTarget {
                point: exceptional,
                kind: ControlEdgeKind::AsyncExceptional,
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

    fn implicit_exception_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        node: Node<'tree>,
    ) -> Result<(), PythonLoweringError> {
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            implicit_exception_detail(node),
        )
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

    fn route(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        from: ProgramPointId,
        route: &CompletionRoute,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PythonLoweringError> {
        if route.cleanups().is_empty() {
            return self.edge(
                builder,
                from,
                EdgeTarget {
                    point: route.destination().target(),
                    kind: route.destination().edge_kind(),
                },
            );
        }

        let mut next = EdgeTarget {
            point: route.destination().target(),
            kind: route.destination().edge_kind(),
        };
        let mut first = None;
        for index in (0..route.cleanups().len()).rev() {
            let region_id = route.cleanups()[index];
            let region = *self
                .cleanups
                .iter()
                .find(|region| region.id == region_id)
                .ok_or_else(|| PythonLoweringError::Invalid("missing cleanup region".into()))?;
            let metadata = self.mapping(builder, region.body.source_node())?;
            let (entry, created) =
                builder.cleanup_specialization(route, index, metadata.source, metadata.evidence)?;
            if created {
                self.session.register_point(
                    entry,
                    metadata,
                    "cleanup specialization broke dense point allocation",
                )?;
                let CleanupBody::Statement(body) = region.body;
                let statement_next = if next.kind == ControlEdgeKind::Normal {
                    next
                } else {
                    let relay = self.point(builder, body, Vec::new())?;
                    self.edge(builder, relay, next)?;
                    EdgeTarget::normal(relay)
                };
                stack.push(Work::Statement {
                    node: body,
                    entry,
                    next: statement_next,
                    scope: region.outer_scope,
                });
            }
            next = EdgeTarget {
                point: entry,
                kind: ControlEdgeKind::Cleanup,
            };
            first = Some(entry);
        }
        self.edge(
            builder,
            from,
            EdgeTarget {
                point: first.expect("route has cleanups"),
                kind: ControlEdgeKind::Cleanup,
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
    ) -> Result<(), PythonLoweringError> {
        let kind = match resolution {
            CallableTargetResolution::Proven(_) => return Ok(()),
            CallableTargetResolution::Ambiguous(_) => SemanticGapKind::Ambiguous,
            CallableTargetResolution::Unknown => SemanticGapKind::Unknown,
            CallableTargetResolution::Unsupported => SemanticGapKind::Unsupported,
            CallableTargetResolution::Unproven(_) => SemanticGapKind::Unproven,
            CallableTargetResolution::ExceededBudget(_) => SemanticGapKind::ExceededBudget,
        };
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::Value(callee),
            SemanticCapability::CallableReferences,
            kind,
            "callable target requires whole-program dispatch refinement",
        )?;
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::CallSite(call_site),
            SemanticCapability::Calls,
            kind,
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
        let range = node.byte_range();
        let occurrence = self.session.next_source_occurrence(range.start, range.end);
        let anchor = source_anchor(node, occurrence).map_err(PythonLoweringError::Invalid)?;
        self.session
            .add_mapping(builder, anchor, SourceMappingKind::Exact)
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

fn context_manager_expression(item: Node<'_>) -> Result<Node<'_>, PythonLoweringError> {
    let value = required_field(item, "value")?;
    if value.kind() != "as_pattern" {
        return Ok(value);
    }

    let alias = value.child_by_field_name("alias");
    named_children(value)
        .into_iter()
        .find(|child| alias.is_none_or(|alias| alias.id() != child.id()))
        .ok_or_else(|| missing_field(value, "context expression"))
}

fn node_range(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    }
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
        "integer" | "float" | "true" | "false" | "none" | "ellipsis" | "string" => {
            SemanticValueKind::Constant
        }
        _ => SemanticValueKind::Temporary,
    }
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
                result.extend(assignment_target_runtime_nodes(left));
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
            "attribute" | "subscript" => result.push(node),
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

fn implicit_exception_detail(node: Node<'_>) -> &'static str {
    match node.kind() {
        "attribute" => {
            "attribute lookup, descriptor execution, and missing-attribute failures are not lowered"
        }
        "subscript" => {
            "subscription special-method, key, index, and bounds failures are not lowered"
        }
        _ => "implicit exceptions from Python runtime operations are not lowered",
    }
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
