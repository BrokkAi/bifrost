//! Scala lowering into the language-neutral executable-semantics IR.

use std::sync::Arc;

use tree_sitter::Node;

use crate::analyzer::semantic::cfg::{
    CleanupRegionId, CompletionKind, CompletionRequest, CompletionRoute, DriveError,
    ProcedureCfgBuilder, ScopeBinding, ScopeFrameId,
};
use crate::analyzer::semantic::service::{ProgramSemanticsLowerer, SemanticAdapterIdentity};
use crate::analyzer::semantic::*;
use crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree;
use crate::analyzer::{ProjectFile, ScalaAnalyzer};
use crate::hash::HashMap;

const ADAPTER_VERSION: &[u8] = b"scala-cfg-v1";

impl ProgramSemanticsProvider for ScalaAnalyzer {
    fn current_artifact_key(
        &self,
        file: &ProjectFile,
        max_source_bytes: usize,
    ) -> Result<Option<SemanticArtifactKey>, SemanticProviderError> {
        self.inner.current_semantic_artifact_key_with_lowerer(
            &ScalaSemanticLowerer,
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
            .materialize_semantics_with_lowerer(&ScalaSemanticLowerer, file, request)
    }
}

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
        SemanticCapability::DeferredExecution,
        SemanticCapability::ConcurrentSpawn,
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
    callable: Node<'tree>,
    locator: SemanticLocator,
    lexical_parent: Option<ProcedureId>,
    kind: ProcedureKind,
    properties: ProcedureProperties,
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
    member_context: bool,
    synthetic_body_scope: Option<SyntheticBodyScope>,
}

#[derive(Debug, Clone, Copy)]
struct SyntheticBodyScope {
    procedure: ProcedureId,
    callable_path: usize,
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
        .unwrap_or("scala-source");
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
        member_context: false,
        synthetic_body_scope: None,
    }];

    while let Some(frame) = stack.pop() {
        if cancellation.is_cancelled() {
            return Ok(ProcedureEnumeration::Cancelled);
        }

        let mut child_path = frame.declaration_path;
        let mut child_member_context = frame.member_context;
        if let Some(segment_kind) = declaration_container_kind(frame.node) {
            let name = callable_name(prepared.source(), frame.node);
            let ordinal =
                next_sibling_ordinal(&mut siblings, child_path, segment_kind, name.as_deref());
            let anchor =
                source_anchor(frame.node, 0).map_err(SemanticProviderError::invalid_identity)?;
            let segment = declaration_segment(segment_kind, name.as_deref(), anchor, ordinal)
                .map_err(SemanticProviderError::invalid_identity)?;
            child_path = push_declaration_path(&mut declaration_paths, child_path, segment);
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
                callable: frame.node,
                locator,
                lexical_parent: frame.lexical_parent,
                kind,
                properties,
            });
            let callable_path = push_declaration_path(&mut declaration_paths, child_path, segment);
            if body.id() == frame.node.id() && attach_lexical_parent {
                self_callable_scope = Some((id, callable_path));
            } else {
                callable_body_scope = Some((body.id(), id, callable_path, attach_lexical_parent));
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
    Some((
        kind,
        segment_kind,
        body,
        ProcedureProperties {
            is_async: false,
            is_generator: false,
            is_static: false,
            is_synthetic: synthetic,
            invocation,
            ..ProcedureProperties::default()
        },
        attach_lexical_parent,
    ))
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
    body: Node<'tree>,
    outer_scope: ScopeFrameId,
}

struct LoweringContext<'tree, 'targets> {
    source: &'tree str,
    session: ProcedureLoweringSession<'targets>,
    procedure_kind: ProcedureKind,
    procedure_body_node_id: usize,
    cleanups: Vec<CleanupRegion<'tree>>,
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
        source: prepared.source(),
        session,
        procedure_kind: spec.kind,
        procedure_body_node_id: spec.body.id(),
        cleanups: Vec::new(),
    };

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
    if spec.kind == ProcedureKind::Constructor && spec.properties.is_synthetic {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unsupported,
            "implicit superclass and mixin constructor invocations are not emitted as call sites",
        )?;
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unknown,
            "implicit constructor and template initialization may complete exceptionally",
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
        let value = context.value(&mut builder, implicit_return, SemanticValueKind::Return)?;
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
    context.edge(&mut builder, entry, EdgeTarget::normal(body_entry))?;

    let mut pending = vec![Work::Expression {
        node: spec.body,
        entry: body_entry,
        next: body_next,
        scope: function_scope,
    }];
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
            DriveError::Cancelled | DriveError::Step(ScalaLoweringError::Cancelled(_)) => {
                Err(ScalaLoweringError::Cancelled(Box::new(work)))
            }
            DriveError::ExceededBudget(exceeded) => {
                Err(ScalaLoweringError::Budget(exceeded, Box::new(work)))
            }
            DriveError::Step(ScalaLoweringError::Budget(exceeded, _)) => {
                Err(ScalaLoweringError::Budget(exceeded, Box::new(work)))
            }
            DriveError::Step(ScalaLoweringError::Invalid(detail)) => {
                Err(ScalaLoweringError::Invalid(detail))
            }
        };
    }

    if builder
        .seal_unreachable_regions(entry, normal_exit, exceptional_exit, cancellation)
        .is_err()
    {
        return Err(ScalaLoweringError::Cancelled(Box::new(
            builder.prospective_work(),
        )));
    }
    let work_before_freeze = builder.prospective_work();
    builder
        .finish_with_work()
        .map_err(|error| ScalaLoweringError::Budget(error, Box::new(work_before_freeze)))
}

impl<'tree, 'targets> LoweringContext<'tree, 'targets> {
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
        match (node.kind(), infix_operator(self.source, node)) {
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
                let function = required_field(node, "function")?;
                stack.push(Work::Expression {
                    node: function,
                    entry,
                    next,
                    scope,
                });
                Ok(())
            }
            "postfix_expression" => {
                self.postfix_expression(builder, node, entry, next, scope, stack)
            }
            "prefix_expression" => self.prefix_expression(builder, node, entry, next, scope, stack),
            "function_definition" | "lambda_expression" => {
                self.callable_value(builder, entry, next)
            }
            "parenthesized_expression" | "typed_expression" => {
                if let Some(value) = first_runtime_named_child(node) {
                    stack.push(Work::Expression {
                        node: value,
                        entry,
                        next,
                        scope,
                    });
                    Ok(())
                } else {
                    self.edge(builder, entry, next)
                }
            }
            "field_expression" => {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::Calls,
                    SemanticGapKind::Unknown,
                    "selection may denote a parameterless method or require an implicit conversion",
                )?;
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::ExceptionalControlFlow,
                    SemanticGapKind::Unknown,
                    "parameterless method selection or an implicit conversion may complete exceptionally",
                )?;
                let children = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
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
                if matches!(infix_operator(self.source, node), Some("&&" | "||")) {
                    let right = required_runtime_field(node, "right")?;
                    let right_entry = self.point(builder, right, Vec::new())?;
                    stack.push(Work::Expression {
                        node: right,
                        entry: right_entry,
                        next,
                        scope,
                    });
                    let (when_true, when_false) = if infix_operator(self.source, node) == Some("&&")
                    {
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
            "identifier" if identifier_has_auto_application_ambiguity(node) => {
                for (capability, detail) in [
                    (
                        SemanticCapability::Calls,
                        "unqualified identifier may auto-apply a parameterless method",
                    ),
                    (
                        SemanticCapability::ExceptionalControlFlow,
                        "auto-application or implicit conversion of an unqualified identifier may complete exceptionally",
                    ),
                    (
                        SemanticCapability::CallableReferences,
                        "unqualified identifier may denote a value, method application, or eta-expanded callable",
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
                self.edge(builder, entry, next)
            }
            kind if is_runtime_leaf(kind) => self.edge(builder, entry, next),
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
        stack.push(Work::Expression {
            node: consequence,
            entry: consequence_entry,
            next,
            scope,
        });
        let when_false = if let Some(alternative) = alternative {
            let alternative_entry = self.point(builder, alternative, Vec::new())?;
            stack.push(Work::Expression {
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
        self.edge(builder, entry, EdgeTarget::normal(condition_entry))?;
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
            self.add_gap(
                builder,
                dispatcher,
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unknown,
                "catch pattern compatibility and exception binding require type refinement",
            )?;
            let arms = catch_arms(catch_clause);
            let catch_exit = self.point(builder, catch_clause, Vec::new())?;
            if let Some(route) = &normal_route {
                self.route(builder, catch_exit, route, stack)?;
            } else {
                self.edge(builder, catch_exit, next)?;
            }
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
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unknown,
                "for-comprehension protocol calls and pattern filtering may throw",
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
        if pattern.is_some_and(|pattern| !matches!(pattern.kind(), "identifier" | "identifiers")) {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::Values,
                SemanticGapKind::Unknown,
                "destructuring definition bindings are not represented in value flow",
            )?;
        }
        stack.push(Work::Expression {
            node: value,
            entry,
            next,
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
                .map(|_| self.value(builder, terminal, SemanticValueKind::Return))
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
        let value = self.value(builder, terminal, SemanticValueKind::Exception)?;
        self.append_effect(
            builder,
            terminal,
            SemanticEffect::Throw { value: Some(value) },
        )?;
        self.abrupt(builder, terminal, scope, CompletionKind::Throw, stack)?;
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
        let (function, mut argument_lists) = flattened_call_parts(node)?;
        let constructor_application = function.kind() == "instance_expression";
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
        let callee = self.value(builder, invoke, SemanticValueKind::Callable)?;
        let result = self.value(builder, invoke, SemanticValueKind::Temporary)?;
        let thrown = self.value(builder, invoke, SemanticValueKind::Exception)?;
        let receiver = (!constructor_application
            && matches!(
                callable.kind(),
                "field_expression" | "infix_expression" | "postfix_expression"
            ))
        .then(|| self.value(builder, invoke, SemanticValueKind::Receiver))
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
            .map(|_| self.value(builder, invoke, SemanticValueKind::Temporary))
            .collect::<Result<Vec<_>, _>>()?;
        let call_site = self.session.add_call_site(
            builder,
            CallSiteScaffold {
                point: invoke,
                callee,
                receiver,
                arguments: arguments.into_iter().map(Into::into).collect(),
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
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::DeferredExecution,
                SemanticGapKind::Unknown,
                if has_structured_argument {
                    "trailing block, case, or colon syntax does not prove by-name evaluation; execution is withheld until parameter strictness is resolved"
                } else {
                    "argument evaluation strictness depends on the resolved Scala parameter signature"
                },
            )?;
        }
        if is_future_like_call(self.source, callable) {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::ConcurrentSpawn,
                SemanticGapKind::Unknown,
                "Future-style execution-context scheduling is not lowered",
            )?;
            if argument_nodes.is_empty() {
                self.add_gap(
                    builder,
                    invoke,
                    SemanticGapSubject::CallSite(call_site),
                    SemanticCapability::DeferredExecution,
                    SemanticGapKind::Unknown,
                    "Future body execution timing is not lowered",
                )?;
            }
        }

        let mut evaluations = Vec::with_capacity(argument_nodes.len() + 1);
        if !constructor_application {
            evaluations.push(function);
        }
        for arguments in &argument_lists {
            if !has_structured_by_name_argument(*arguments) {
                evaluations.extend(runtime_expression_children(*arguments));
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
        if left.kind() == "infix_expression" || right.kind() == "infix_expression" {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::NormalControlFlow,
                SemanticGapKind::Unsupported,
                "compound Scala infix precedence and associativity are retained as a terminal boundary",
            )?;
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::Calls,
                SemanticGapKind::Unsupported,
                "compound infix method dispatch is not emitted from an unrefined parse grouping",
            )?;
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unknown,
                "exceptions from compound infix dispatch require precedence and target refinement",
            )?;
            // Deliberately terminal: connecting this boundary to `next` would assert a
            // normal completion whose evaluation and dispatch ordering are not proven.
            return Ok(());
        }
        let operator = required_field(node, "operator")?;
        let right_associative =
            node_text(self.source, operator).is_some_and(|name| name.ends_with(':'));
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

    #[allow(clippy::too_many_arguments)]
    fn call_like_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        source_node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        _function: Node<'tree>,
        callable_kind: CallableReferenceKind,
        argument_nodes: &[Node<'tree>],
        evaluations: &[Node<'tree>],
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), ScalaLoweringError> {
        let invoke = self.point(builder, source_node, Vec::new())?;
        let normal = self.point(builder, source_node, Vec::new())?;
        let exceptional = self.point(builder, source_node, Vec::new())?;
        let callee = self.value(builder, invoke, SemanticValueKind::Callable)?;
        let result = self.value(builder, invoke, SemanticValueKind::Temporary)?;
        let thrown = self.value(builder, invoke, SemanticValueKind::Exception)?;
        let receiver = (callable_kind == CallableReferenceKind::BoundMethod)
            .then(|| self.value(builder, invoke, SemanticValueKind::Receiver))
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
            .map(|_| self.value(builder, invoke, SemanticValueKind::Temporary))
            .collect::<Result<Vec<_>, _>>()?;
        let call_site = self.session.add_call_site(
            builder,
            CallSiteScaffold {
                point: invoke,
                callee,
                receiver,
                arguments: arguments.into_iter().map(Into::into).collect(),
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
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::DeferredExecution,
                SemanticGapKind::Unknown,
                "argument evaluation strictness depends on the resolved Scala parameter signature",
            )?;
        }
        self.schedule_expressions(
            builder,
            entry,
            evaluations,
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

    fn route(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        from: ProgramPointId,
        route: &CompletionRoute,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), ScalaLoweringError> {
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
                .ok_or_else(|| ScalaLoweringError::Invalid("missing cleanup region".into()))?;
            let metadata = self.mapping(builder, region.body)?;
            let (entry, created) =
                builder.cleanup_specialization(route, index, metadata.source, metadata.evidence)?;
            if created {
                self.session.register_point(
                    entry,
                    metadata,
                    "cleanup specialization broke dense point allocation",
                )?;
                let cleanup_next = if next.kind == ControlEdgeKind::Normal {
                    next
                } else {
                    let relay = self.point(builder, region.body, Vec::new())?;
                    self.edge(builder, relay, next)?;
                    EdgeTarget::normal(relay)
                };
                stack.push(Work::Expression {
                    node: region.body,
                    entry,
                    next: cleanup_next,
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
    ) -> Result<(), ScalaLoweringError> {
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
            "callable target requires whole-program Scala dispatch refinement",
        )?;
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::CallSite(call_site),
            SemanticCapability::Calls,
            kind,
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
        let range = node.byte_range();
        let occurrence = self.session.next_source_occurrence(range.start, range.end);
        let anchor = source_anchor(node, occurrence).map_err(ScalaLoweringError::Invalid)?;
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

fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn children_by_field_name<'tree>(node: Node<'tree>, field: &str) -> Vec<Node<'tree>> {
    let mut cursor = node.walk();
    node.children_by_field_name(field, &mut cursor).collect()
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

fn node_text<'source>(source: &'source str, node: Node<'_>) -> Option<&'source str> {
    source.get(node.byte_range())
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
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        let mut cursor = current.walk();
        let children = current.children(&mut cursor).collect::<Vec<_>>();
        if children.iter().any(|child| child.kind() == kind) {
            return true;
        }
        stack.extend(children.into_iter().filter(|child| child.is_named()));
    }
    false
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

fn source_anchor(node: Node<'_>, occurrence: u32) -> Result<SourceAnchor, String> {
    let start_position = node.start_position();
    let end_position = node.end_position();
    let start = SourcePosition::new(
        u32::try_from(node.start_byte()).map_err(|_| "source start exceeds u32")?,
        u32::try_from(start_position.row).map_err(|_| "source start line exceeds u32")?,
        u32::try_from(start_position.column).map_err(|_| "source start column exceeds u32")?,
    );
    let end = SourcePosition::new(
        u32::try_from(node.end_byte()).map_err(|_| "source end exceeds u32")?,
        u32::try_from(end_position.row).map_err(|_| "source end line exceeds u32")?,
        u32::try_from(end_position.column).map_err(|_| "source end column exceeds u32")?,
    );
    let span = SourceSpan::new(start, end).map_err(|error| error.to_string())?;
    Ok(SourceAnchor::new(span, occurrence))
}
