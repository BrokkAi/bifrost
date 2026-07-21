//! Rust lowering into the language-neutral executable-semantics IR.
//!
//! Tree-sitter nodes and fields describe Rust syntax here; graph mechanics,
//! abrupt-completion routing, and immutable adjacency storage stay in the
//! shared semantic substrate.

use std::sync::Arc;

use tree_sitter::Node;

use crate::analyzer::semantic::cfg::{
    CleanupRegionId, CompletionKind, CompletionRequest, CompletionRoute, DriveError,
    ProcedureCfgBuilder, ScopeBinding, ScopeFrameId,
};
use crate::analyzer::semantic::service::{ProgramSemanticsLowerer, SemanticAdapterIdentity};
use crate::analyzer::semantic::*;
use crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree;
use crate::analyzer::{ProjectFile, RustAnalyzer};
use crate::hash::HashMap;

const ADAPTER_VERSION: &[u8] = b"rust-cfg-v1";

impl ProgramSemanticsProvider for RustAnalyzer {
    fn current_artifact_key(
        &self,
        file: &ProjectFile,
        max_source_bytes: usize,
    ) -> Result<Option<SemanticArtifactKey>, SemanticProviderError> {
        self.inner.current_semantic_artifact_key_with_lowerer(
            &RustSemanticLowerer,
            file,
            max_source_bytes,
        )
    }

    fn materialize(
        &self,
        file: &ProjectFile,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError> {
        self.inner
            .materialize_semantics_with_lowerer(&RustSemanticLowerer, file, request)
    }
}

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
        let specs = match enumerate_procedures(file, prepared, budget, cancellation)? {
            ProcedureEnumeration::Complete(specs) => specs,
            ProcedureEnumeration::ExceededBudget { exceeded, work } => {
                return Ok(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work,
                });
            }
            ProcedureEnumeration::Cancelled => {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: SemanticWork::default(),
                });
            }
        };

        lower_procedure_batch(
            &specs,
            SemanticWork::default(),
            budget,
            cancellation,
            |spec, staged_budget, cancellation| {
                lower_procedure(prepared, spec, staged_budget, cancellation)
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
        SemanticCapability::AsyncSuspendResume,
        SemanticCapability::GeneratorSuspension,
        SemanticCapability::DeferredExecution,
        SemanticCapability::NonLocalControl,
        SemanticCapability::ResourceManagement,
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
    has_parameter_bindings: bool,
}

enum ProcedureEnumeration<'tree> {
    Complete(Vec<ProcedureSpec<'tree>>),
    ExceededBudget {
        exceeded: SemanticBudgetExceeded,
        work: SemanticWork,
    },
    Cancelled,
}

struct ProcedureEnumerationFrame<'tree> {
    node: Node<'tree>,
    lexical_parent: Option<ProcedureId>,
    declaration_path: usize,
}

struct DeclarationPathEntry {
    parent: Option<usize>,
    segment: DeclarationSegment,
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
        .unwrap_or("rust-source");
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
    let mut stack = vec![ProcedureEnumerationFrame {
        node: root,
        lexical_parent: None,
        declaration_path: 0,
    }];

    while let Some(frame) = stack.pop() {
        if cancellation.is_cancelled() {
            return Ok(ProcedureEnumeration::Cancelled);
        }
        let child_path = frame.declaration_path;
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
            if let Err(exceeded) = budget.check(candidate) {
                return Ok(ProcedureEnumeration::ExceededBudget {
                    exceeded,
                    work: candidate,
                });
            }
            preflight = candidate;
            specs.push(ProcedureSpec {
                id,
                body,
                locator,
                lexical_parent: frame.lexical_parent,
                kind,
                properties,
                has_parameter_bindings: callable_has_parameter_bindings(frame.node),
            });
            let callable_path = push_declaration_path(&mut declaration_paths, child_path, segment);
            callable_body_scope = Some((body.id(), id, callable_path));
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

    Ok(ProcedureEnumeration::Complete(specs))
}

fn procedure_identity_preflight(locator: &SemanticLocator) -> SemanticWork {
    let segments = locator.declaration().segments();
    let locator_text = locator.path().as_str().len().saturating_add(
        segments
            .iter()
            .filter_map(|segment| segment.name())
            .fold(0usize, |total, name| total.saturating_add(name.len())),
    );
    SemanticWork {
        procedures: 1,
        source_mappings: 1,
        evidence: 1,
        nested_entries: 3usize.saturating_add(segments.len().saturating_mul(3)),
        owned_text_bytes: locator_text.saturating_mul(3),
        ..SemanticWork::default()
    }
}

fn push_declaration_path(
    paths: &mut Vec<DeclarationPathEntry>,
    parent: usize,
    segment: DeclarationSegment,
) -> usize {
    let id = paths.len();
    paths.push(DeclarationPathEntry {
        parent: Some(parent),
        segment,
    });
    id
}

fn collect_declaration_path(
    paths: &[DeclarationPathEntry],
    mut path: usize,
) -> Vec<DeclarationSegment> {
    let mut segments = Vec::new();
    loop {
        let entry = &paths[path];
        segments.push(entry.segment.clone());
        let Some(parent) = entry.parent else {
            break;
        };
        path = parent;
    }
    segments.reverse();
    segments
}

fn next_sibling_ordinal(
    siblings: &mut HashMap<(usize, DeclarationSegmentKind, Option<Box<str>>), u32>,
    scope: usize,
    kind: DeclarationSegmentKind,
    name: Option<&str>,
) -> u32 {
    let key = (scope, kind, name.map(Box::<str>::from));
    let ordinal = *siblings.entry(key.clone()).or_default();
    *siblings.get_mut(&key).expect("inserted sibling ordinal") += 1;
    ordinal
}

fn declaration_segment(
    kind: DeclarationSegmentKind,
    name: Option<&str>,
    anchor: SourceAnchor,
    sibling_ordinal: u32,
) -> Result<DeclarationSegment, String> {
    match name {
        Some(name) => DeclarationSegment::named(kind, name, anchor, sibling_ordinal)
            .map_err(|error| error.to_string()),
        None => Ok(DeclarationSegment::anonymous(kind, anchor, sibling_ordinal)),
    }
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
            ..ProcedureProperties::default()
        },
    ))
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

fn callable_has_parameter_bindings(node: Node<'_>) -> bool {
    node.child_by_field_name("parameters")
        .map(named_children)
        .is_some_and(|parameters| !parameters.is_empty())
}

fn field_matches(parent: Node<'_>, field: &str, child: Node<'_>) -> bool {
    parent
        .child_by_field_name(field)
        .is_some_and(|candidate| candidate.id() == child.id())
}

fn nonempty_node_text<'source>(source: &'source str, node: Node<'_>) -> Option<&'source str> {
    node_text(source, node).filter(|text| !text.is_empty())
}

type RustLoweringError = ProcedureLoweringError;

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

struct LoweringContext<'tree, 'targets> {
    source: &'tree str,
    session: ProcedureLoweringSession<'targets>,
    next_cleanup_region: usize,
}

fn lower_procedure<'tree>(
    prepared: &'tree PreparedSyntaxTree,
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
    let body_scope = if spec.has_parameter_bindings {
        builder.push_scope(
            Some(function_scope),
            ScopeBinding::Cleanup {
                region: CleanupRegionId::new(0),
            },
        )
    } else {
        function_scope
    };
    let mut context = LoweringContext {
        source: prepared.source(),
        session,
        next_cleanup_region: usize::from(spec.has_parameter_bindings),
    };

    if spec.has_parameter_bindings {
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
    let body_returns_value =
        spec.body.kind() != "block" || block_tail_expression(spec.body).is_some();
    let body_next = if body_returns_value {
        let implicit_return = context.point(&mut builder, spec.body, Vec::new())?;
        let return_value =
            context.value(&mut builder, implicit_return, SemanticValueKind::Return)?;
        context.append_effect(
            &mut builder,
            implicit_return,
            SemanticEffect::ProcedureReturn {
                value: Some(return_value),
            },
        )?;
        context.add_gap(
            &mut builder,
            implicit_return,
            SemanticGapSubject::Value(return_value),
            SemanticCapability::Values,
            SemanticGapKind::Unknown,
            "tail-expression result transfer into the procedure return value is not represented",
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
            DriveError::Cancelled | DriveError::Step(RustLoweringError::Cancelled(_)) => {
                Err(RustLoweringError::Cancelled(Box::new(work)))
            }
            DriveError::ExceededBudget(exceeded) => {
                Err(RustLoweringError::Budget(exceeded, Box::new(work)))
            }
            DriveError::Step(RustLoweringError::Budget(exceeded, _)) => {
                Err(RustLoweringError::Budget(exceeded, Box::new(work)))
            }
            DriveError::Step(RustLoweringError::Invalid(detail)) => {
                Err(RustLoweringError::Invalid(detail))
            }
        };
    }

    if builder
        .seal_unreachable_regions(entry, normal_exit, exceptional_exit, cancellation)
        .is_err()
    {
        return Err(RustLoweringError::Cancelled(Box::new(
            builder.prospective_work(),
        )));
    }
    let work_before_freeze = builder.prospective_work();
    builder
        .finish_with_work()
        .map_err(|error| RustLoweringError::Budget(error, Box::new(work_before_freeze)))
}

impl<'tree, 'targets> LoweringContext<'tree, 'targets> {
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
        let has_lexical_locals = named_children(node)
            .into_iter()
            .any(|child| child.kind() == "let_declaration");
        let scope_exit = has_lexical_locals
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
        let block_scope = if has_lexical_locals {
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
        for (capability, detail) in [
            (
                SemanticCapability::CleanupControlFlow,
                "implicit Drop order and cleanup routing are not lowered",
            ),
            (
                SemanticCapability::ResourceManagement,
                "resource release depends on inferred types and Drop implementations",
            ),
            (
                SemanticCapability::Calls,
                "implicit Drop::drop invocations are not emitted as fabricated call sites",
            ),
            (
                SemanticCapability::ExceptionalControlFlow,
                "destructor unwinding and destructor panic routing are not lowered",
            ),
        ] {
            self.add_gap(
                builder,
                point,
                SemanticGapSubject::Point,
                capability,
                SemanticGapKind::Unknown,
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
        if let Some(alternative) = alternative {
            let success = self.point(builder, node, Vec::new())?;
            let alternative_entry = self.point(builder, alternative, Vec::new())?;
            self.add_gap(
                builder,
                binding,
                SemanticGapSubject::Point,
                SemanticCapability::NormalControlFlow,
                SemanticGapKind::Unknown,
                "let-else pattern matching and binding details require value refinement",
            )?;
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
            kind if is_runtime_leaf(kind) => self.edge(builder, entry, next),
            kind if is_runtime_container(kind) => {
                let children = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            _ => self.unhandled_control_syntax(builder, node, entry),
        }
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
        self.add_gap(
            builder,
            boundary,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unknown,
            "implicit Rust trait operations or built-in checks may panic, but their exceptional behavior is not refined",
        )?;
        if matches!(
            node.kind(),
            "assignment_expression" | "compound_assignment_expr"
        ) {
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
        self.add_gap(
            builder,
            decision,
            SemanticGapSubject::Point,
            SemanticCapability::NormalControlFlow,
            SemanticGapKind::Unknown,
            "match pattern selection and binding depend on runtime values; represented case edges are a conservative choice set",
        )?;
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
            for candidate in &candidates {
                arm_scopes.push(self.push_cleanup_scope(builder, scope)?);
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
        self.add_drop_omission_gaps(
            builder,
            body_entry,
            "the per-iteration for-pattern value may require implicit Drop after the selected iteration",
        )?;
        self.add_gap(
            builder,
            test,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unknown,
            "IntoIterator conversion and Iterator::next are implicit calls not emitted as fabricated call sites",
        )?;
        self.add_gap(
            builder,
            test,
            SemanticGapSubject::Point,
            SemanticCapability::NormalControlFlow,
            SemanticGapKind::Unknown,
            "iterator exhaustion and per-iteration pattern binding require type and value refinement",
        )?;
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
        stack.push(Work::Expression {
            node: iterable,
            entry,
            next: EdgeTarget::normal(test),
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
        self.add_gap(
            builder,
            branch,
            SemanticGapSubject::Point,
            SemanticCapability::NormalControlFlow,
            SemanticGapKind::Unknown,
            "the Try branch chosen by ? depends on the operand value and Try implementation",
        )?;
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
        let callee = self.value(builder, invoke, SemanticValueKind::Callable)?;
        let result = self.value(builder, invoke, SemanticValueKind::Temporary)?;
        let thrown = self.value(builder, invoke, SemanticValueKind::Exception)?;
        let function = required_field(node, "function")?;
        let receiver_node = rust_call_receiver(function);
        let receiver = receiver_node
            .map(|_| self.value(builder, invoke, SemanticValueKind::Receiver))
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
            .map(|_| self.value(builder, invoke, SemanticValueKind::Temporary))
            .collect::<Result<Vec<_>, _>>()?;
        let call_site = self.session.add_call_site(
            builder,
            CallSiteScaffold {
                point: invoke,
                callee,
                receiver,
                arguments: argument_values.into_iter().map(Into::into).collect(),
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
        if receiver_node.is_some() {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::DynamicDispatch,
                SemanticGapKind::Unknown,
                "method dispatch may use a trait implementation after autoderef; receiver type and complete implementation coverage require type refinement",
            )?;
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::Point,
                SemanticCapability::Calls,
                SemanticGapKind::Unknown,
                "method receiver autoderef and autoref adjustments may invoke Deref or DerefMut and are not emitted as call sites",
            )?;
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unknown,
                "implicit method receiver adjustments may panic, but their exceptional behavior is not refined",
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
            for (capability, reason) in [
                (
                    SemanticCapability::CleanupControlFlow,
                    "implicit Drop order and cleanup routing are not lowered",
                ),
                (
                    SemanticCapability::ResourceManagement,
                    "RAII resource release depends on inferred local types and Drop implementations",
                ),
                (
                    SemanticCapability::Calls,
                    "implicit Drop::drop invocations are not emitted as fabricated call sites",
                ),
                (
                    SemanticCapability::ExceptionalControlFlow,
                    "destructor unwinding and destructor panic routing are not lowered",
                ),
            ] {
                self.add_gap(
                    builder,
                    from,
                    SemanticGapSubject::Point,
                    capability,
                    SemanticGapKind::Unknown,
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
            "callable target requires whole-program Rust dispatch refinement",
        )?;
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::CallSite(call_site),
            SemanticCapability::Calls,
            kind,
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

fn rust_call_receiver(function: Node<'_>) -> Option<Node<'_>> {
    let function = unwrap_generic_function(function);
    (function.kind() == "field_expression")
        .then(|| function.child_by_field_name("value"))
        .flatten()
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

fn node_text<'source>(source: &'source str, node: Node<'_>) -> Option<&'source str> {
    source.get(node.byte_range())
}

fn source_anchor(node: Node<'_>, occurrence: u32) -> Result<SourceAnchor, String> {
    let start = node.start_position();
    let end = node.end_position();
    let start = SourcePosition::new(
        u32::try_from(node.start_byte()).map_err(|_| "source start exceeds u32")?,
        u32::try_from(start.row).map_err(|_| "source start line exceeds u32")?,
        u32::try_from(start.column).map_err(|_| "source start column exceeds u32")?,
    );
    let end = SourcePosition::new(
        u32::try_from(node.end_byte()).map_err(|_| "source end exceeds u32")?,
        u32::try_from(end.row).map_err(|_| "source end line exceeds u32")?,
        u32::try_from(end.column).map_err(|_| "source end column exceeds u32")?,
    );
    let span = SourceSpan::new(start, end).map_err(|error| error.to_string())?;
    Ok(SourceAnchor::new(span, occurrence))
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
