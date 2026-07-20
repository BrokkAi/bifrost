//! Go lowering into the language-neutral executable-semantics IR.
//!
//! This module deliberately interprets tree-sitter nodes and fields directly.
//! Graph construction, abrupt-completion routing, cleanup specialization, and
//! physical adjacency storage remain owned by the shared semantic substrate.

use std::sync::Arc;

use tree_sitter::Node;

use crate::analyzer::semantic::cfg::{
    CompletionKind, CompletionRequest, CompletionRoute, DriveError, ProcedureCfgBuilder,
    ScopeBinding, ScopeFrameId,
};
use crate::analyzer::semantic::service::{ProgramSemanticsLowerer, SemanticAdapterIdentity};
use crate::analyzer::semantic::*;
use crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree;
use crate::analyzer::{GoAnalyzer, ProjectFile};
use crate::hash::HashMap;

const ADAPTER_VERSION: &[u8] = b"go-cfg-v1";

impl ProgramSemanticsProvider for GoAnalyzer {
    fn materialize(
        &self,
        file: &ProjectFile,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError> {
        self.inner
            .materialize_semantics_with_lowerer(&GoSemanticLowerer, file, request)
    }
}

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

        let mut procedures = Vec::with_capacity(specs.len());
        let mut observed = SemanticWork::default();
        for spec in &specs {
            if cancellation.is_cancelled() {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: observed,
                });
            }
            let mut staged_budget = budget.clone();
            if let Err(exceeded) = staged_budget.charge(observed) {
                return Ok(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work: observed,
                });
            }
            match lower_procedure(prepared, spec, &staged_budget, cancellation) {
                Ok((parts, work)) => {
                    let candidate = sum_work(observed, work);
                    if let Err(exceeded) = budget.check(candidate) {
                        return Ok(SemanticOutcome::ExceededBudget {
                            partial: None,
                            exceeded,
                            work: candidate,
                        });
                    }
                    observed = candidate;
                    procedures.push(parts);
                }
                Err(GoLoweringError::Cancelled(work)) => {
                    return Ok(SemanticOutcome::Cancelled {
                        partial: None,
                        work: sum_work(observed, *work),
                    });
                }
                Err(GoLoweringError::Budget(exceeded, work)) => {
                    let work = sum_work(observed, *work);
                    let exceeded = budget.check(work).err().unwrap_or(exceeded);
                    return Ok(SemanticOutcome::ExceededBudget {
                        partial: None,
                        exceeded,
                        work,
                    });
                }
                Err(GoLoweringError::Invalid(detail)) => {
                    return Err(SemanticProviderError::internal(detail));
                }
            }
        }

        Ok(SemanticOutcome::Complete {
            value: procedures,
            work: observed,
        })
    }
}

fn sum_work(left: SemanticWork, right: SemanticWork) -> SemanticWork {
    left.checked_add(right)
        .unwrap_or_else(|| SemanticWork::uniform(usize::MAX))
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
        .unwrap_or("go-source");
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
            let candidate = sum_work(preflight, procedure_identity_preflight(&locator));
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
            });
            let callable_path = push_declaration_path(&mut declaration_paths, child_path, segment);
            callable_body_scope = Some((body.id(), id, callable_path));
        }

        let mut cursor = frame.node.walk();
        let children = frame.node.named_children(&mut cursor).collect::<Vec<_>>();
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

fn nonempty_node_text<'source>(source: &'source str, node: Node<'_>) -> Option<&'source str> {
    node_text(source, node).filter(|text| !text.is_empty())
}

#[derive(Debug)]
enum GoLoweringError {
    Cancelled(Box<SemanticWork>),
    Budget(SemanticBudgetExceeded, Box<SemanticWork>),
    Invalid(String),
}

impl From<SemanticBudgetExceeded> for GoLoweringError {
    fn from(error: SemanticBudgetExceeded) -> Self {
        Self::Budget(error, Box::default())
    }
}

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

#[derive(Debug, Clone, Copy)]
struct PointMetadata {
    source: SourceMappingId,
    evidence: EvidenceId,
}

struct LoweringContext<'tree, 'targets> {
    source: &'tree str,
    locator: SemanticLocator,
    point_metadata: Vec<PointMetadata>,
    next_source: usize,
    next_evidence: usize,
    next_value: usize,
    next_call_site: usize,
    next_gap: usize,
    source_occurrences: HashMap<(usize, usize), u32>,
    cancellation: &'targets CancellationToken,
}

fn lower_procedure<'tree>(
    prepared: &'tree PreparedSyntaxTree,
    spec: &ProcedureSpec<'tree>,
    budget: &SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<(ProcedureSemanticsParts, SemanticWork), GoLoweringError> {
    let base_source = SourceMappingId::new(0);
    let base_evidence = EvidenceId::new(0);
    let mut parts = ProcedureSemanticsParts::new(
        spec.id,
        spec.locator.clone(),
        spec.kind,
        base_source,
        base_evidence,
    );
    parts.lexical_parent = spec.lexical_parent;
    parts.properties = spec.properties;
    parts.source_mappings.push(SourceMapping {
        id: base_source,
        locator: spec.locator.clone(),
        kind: SourceMappingKind::Exact,
    });
    parts.evidence_rows.push(Evidence {
        id: base_evidence,
        proof: ProofStatus::Proven,
        completeness: EvidenceCompleteness::Complete,
        sources: Box::new([base_source]),
    });

    let mut builder = ProcedureCfgBuilder::new(parts, budget)?;
    let entry = builder.add_point(
        vec![SemanticEvent::new(
            SemanticEffect::Entry,
            base_source,
            base_evidence,
        )],
        base_source,
        base_evidence,
    )?;
    let normal_exit = builder.add_point(
        vec![SemanticEvent::new(
            SemanticEffect::NormalExit,
            base_source,
            base_evidence,
        )],
        base_source,
        base_evidence,
    )?;
    let exceptional_exit = builder.add_point(
        vec![SemanticEvent::new(
            SemanticEffect::ExceptionalExit,
            base_source,
            base_evidence,
        )],
        base_source,
        base_evidence,
    )?;
    let function_scope = builder.push_scope(
        None,
        ScopeBinding::Function {
            return_target: normal_exit,
            throw_target: exceptional_exit,
        },
    );
    let mut context = LoweringContext {
        source: prepared.source(),
        locator: spec.locator.clone(),
        point_metadata: vec![
            PointMetadata {
                source: base_source,
                evidence: base_evidence,
            };
            3
        ],
        next_source: 1,
        next_evidence: 1,
        next_value: 0,
        next_call_site: 0,
        next_gap: 0,
        source_occurrences: HashMap::default(),
        cancellation,
    };

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
            DriveError::Cancelled | DriveError::Step(GoLoweringError::Cancelled(_)) => {
                Err(GoLoweringError::Cancelled(Box::new(work)))
            }
            DriveError::ExceededBudget(exceeded) => {
                Err(GoLoweringError::Budget(exceeded, Box::new(work)))
            }
            DriveError::Step(GoLoweringError::Budget(exceeded, _)) => {
                Err(GoLoweringError::Budget(exceeded, Box::new(work)))
            }
            DriveError::Step(GoLoweringError::Invalid(detail)) => {
                Err(GoLoweringError::Invalid(detail))
            }
        };
    }

    if builder
        .seal_unreachable_regions(entry, normal_exit, exceptional_exit, cancellation)
        .is_err()
    {
        return Err(GoLoweringError::Cancelled(Box::new(
            builder.prospective_work(),
        )));
    }
    let work_before_freeze = builder.prospective_work();
    builder
        .finish_with_work()
        .map_err(|error| GoLoweringError::Budget(error, Box::new(work_before_freeze)))
}

impl<'tree, 'targets> LoweringContext<'tree, 'targets> {
    fn step(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        work: Work<'tree>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), GoLoweringError> {
        if self.cancellation.is_cancelled() {
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
                let label = label_node.and_then(|label| node_text(self.source, label));
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
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::ExceptionalControlFlow,
                    SemanticGapKind::Unknown,
                    "increment or decrement may panic through indexed or indirect operands",
                )?;
                let expressions = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &expressions, next, scope, stack)
            }
            "var_declaration" => {
                let initializers = declaration_initializers(node);
                self.note_deterministic_evaluation_order(builder, entry, node, &initializers)?;
                self.schedule_expressions(builder, entry, &initializers, next, scope, stack)
            }
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
        let evaluations = assignment_evaluation_nodes(node);
        let boundary = self.point(builder, node, Vec::new())?;
        if node.kind() == "assignment_statement"
            && node
                .child_by_field_name("left")
                .is_some_and(binding_requires_runtime_protocol)
        {
            self.add_gap(
                builder,
                boundary,
                SemanticGapSubject::Point,
                SemanticCapability::Calls,
                SemanticGapKind::Unknown,
                "assignment through indexing or indirection requires runtime refinement",
            )?;
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
            .and_then(|label| node_text(self.source, label))
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
        match node.kind() {
            "call_expression" => self.call_expression(builder, node, entry, next, scope, stack),
            "func_literal" => self.callable_expression(builder, node, entry, next),
            "binary_expression" if go_boolean_operator_kind(node).is_some() => {
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
            "parenthesized_expression" => {
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
            "selector_expression"
            | "index_expression"
            | "slice_expression"
            | "type_assertion_expression" => {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::ExceptionalControlFlow,
                    SemanticGapKind::Unknown,
                    "selection, indexing, slicing, or type assertion may panic",
                )?;
                let children = runtime_expression_children(node);
                self.note_deterministic_evaluation_order(builder, entry, node, &children)?;
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            "binary_expression" | "unary_expression" => {
                if go_operation_can_panic(node) {
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::ExceptionalControlFlow,
                        SemanticGapKind::Unknown,
                        "operator evaluation may panic",
                    )?;
                }
                let children = runtime_expression_children(node);
                self.note_deterministic_evaluation_order(builder, entry, node, &children)?;
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            "type_conversion_expression"
            | "composite_literal"
            | "literal_value"
            | "literal_element"
            | "keyed_element"
            | "expression_list"
            | "argument_list"
            | "variadic_argument" => {
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
        let callee = self.value(builder, invoke, SemanticValueKind::Callable)?;
        let result = self.value(builder, invoke, SemanticValueKind::Temporary)?;
        let thrown = self.value(builder, invoke, SemanticValueKind::Exception)?;
        let function = required_field(node, "function")?;
        let receiver_node = go_call_receiver(function);
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

        let call_site = CallSiteId::new(
            u32::try_from(self.next_call_site)
                .map_err(|_| GoLoweringError::Invalid("too many call sites".into()))?,
        );
        let arguments = call_arguments(node);
        let argument_values = arguments
            .iter()
            .map(|_| self.value(builder, invoke, SemanticValueKind::Temporary))
            .collect::<Result<Vec<_>, _>>()?;
        builder.add_call_site(SemanticCallSite {
            id: call_site,
            point: invoke,
            callee,
            receiver,
            arguments: argument_values.into_boxed_slice(),
            result: Some(result),
            thrown: Some(thrown),
            declared_targets: resolution.clone(),
            target_evidence: metadata.evidence,
            normal_continuation: ControlContinuation::Target(normal),
            exceptional_continuation: ControlContinuation::Target(exceptional),
            source: metadata.source,
            evidence: metadata.evidence,
        })?;
        self.next_call_site += 1;
        self.append_effect(builder, invoke, SemanticEffect::Invoke { call_site })?;
        self.append_effect(
            builder,
            normal,
            SemanticEffect::CallContinuation {
                call_site,
                kind: CallContinuationKind::Normal,
            },
        )?;
        self.append_effect(
            builder,
            exceptional,
            SemanticEffect::CallContinuation {
                call_site,
                kind: CallContinuationKind::Exceptional,
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
        _node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
    ) -> Result<(), GoLoweringError> {
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
    ) -> Result<ProgramPointId, GoLoweringError> {
        let metadata = self.mapping(builder, node)?;
        let events = effects
            .into_iter()
            .map(|effect| SemanticEvent::new(effect, metadata.source, metadata.evidence))
            .collect();
        let point = builder.add_point(events, metadata.source, metadata.evidence)?;
        if point.index() != self.point_metadata.len() {
            return Err(GoLoweringError::Invalid(
                "program-point allocation is not dense".into(),
            ));
        }
        self.point_metadata.push(metadata);
        Ok(point)
    }

    fn mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<PointMetadata, GoLoweringError> {
        let range = node.byte_range();
        let occurrence = self
            .source_occurrences
            .entry((range.start, range.end))
            .or_default();
        let anchor = source_anchor(node, *occurrence).map_err(GoLoweringError::Invalid)?;
        *occurrence += 1;
        let source = SourceMappingId::new(
            u32::try_from(self.next_source)
                .map_err(|_| GoLoweringError::Invalid("too many source mappings".into()))?,
        );
        let evidence = EvidenceId::new(
            u32::try_from(self.next_evidence)
                .map_err(|_| GoLoweringError::Invalid("too many evidence rows".into()))?,
        );
        let locator = SemanticLocator::new(
            self.locator.mount(),
            self.locator.path().clone(),
            self.locator.language(),
            self.locator.declaration().clone(),
            SemanticRole::ProgramPoint,
            anchor,
        );
        builder.add_source_mapping(SourceMapping {
            id: source,
            locator,
            kind: SourceMappingKind::Exact,
        })?;
        builder.add_evidence(Evidence {
            id: evidence,
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Complete,
            sources: Box::new([source]),
        })?;
        self.next_source += 1;
        self.next_evidence += 1;
        Ok(PointMetadata { source, evidence })
    }

    fn metadata(&self, point: ProgramPointId) -> Result<PointMetadata, GoLoweringError> {
        self.point_metadata
            .get(point.index())
            .copied()
            .ok_or_else(|| {
                GoLoweringError::Invalid(format!("missing metadata for program point {point}"))
            })
    }

    fn value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        kind: SemanticValueKind,
    ) -> Result<ValueId, GoLoweringError> {
        let metadata = self.metadata(point)?;
        let id = ValueId::new(
            u32::try_from(self.next_value)
                .map_err(|_| GoLoweringError::Invalid("too many semantic values".into()))?,
        );
        builder.add_value(SemanticValue {
            id,
            kind,
            source: metadata.source,
            evidence: metadata.evidence,
        })?;
        self.next_value += 1;
        Ok(id)
    }

    fn append_effect(
        &self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        effect: SemanticEffect,
    ) -> Result<(), GoLoweringError> {
        let metadata = self.metadata(point)?;
        builder.append_event(
            point,
            SemanticEvent::new(effect, metadata.source, metadata.evidence),
        )?;
        Ok(())
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
        let metadata = self.metadata(point)?;
        let id = SemanticGapId::new(
            u32::try_from(self.next_gap)
                .map_err(|_| GoLoweringError::Invalid("too many semantic gaps".into()))?,
        );
        builder.add_gap(SemanticGap {
            id,
            point,
            subject,
            capability,
            kind,
            budget: None,
            detail: detail.into(),
            source: metadata.source,
            evidence: metadata.evidence,
        })?;
        self.next_gap += 1;
        self.append_effect(builder, point, SemanticEffect::Gap { gap: id })
    }

    fn edge(
        &self,
        builder: &mut ProcedureCfgBuilder,
        source_point: ProgramPointId,
        target: EdgeTarget,
    ) -> Result<(), GoLoweringError> {
        let metadata = self.metadata(source_point)?;
        builder.add_edge(ControlEdge {
            source_point,
            target_point: target.point,
            kind: target.kind,
            source: metadata.source,
            evidence: metadata.evidence,
        })?;
        Ok(())
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

fn evaluation_units_have_unspecified_order(evaluations: &[Node<'_>]) -> bool {
    evaluations.len() > 1
        && evaluations
            .iter()
            .any(|evaluation| !go_spec_orders_evaluation(*evaluation))
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
        "expression_statement" | "return_statement" | "inc_statement" | "dec_statement" => {
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
    node.child_by_field_name("arguments")
        .map(named_children)
        .unwrap_or_default()
        .into_iter()
        .filter(|argument| !is_go_type_syntax(argument.kind()))
        .collect()
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

fn is_go_type_syntax(kind: &str) -> bool {
    kind.starts_with("type_")
        || kind.ends_with("_type")
        || matches!(
            kind,
            "type_identifier"
                | "qualified_type"
                | "generic_type"
                | "pointer_type"
                | "array_type"
                | "implicit_length_array_type"
                | "slice_type"
                | "map_type"
                | "channel_type"
                | "struct_type"
                | "interface_type"
                | "function_type"
                | "parameter_list"
                | "parameter_declaration"
                | "variadic_parameter_declaration"
                | "type_arguments"
                | "type_parameter_list"
                | "type_parameter_declaration"
                | "type_constraint"
        )
}

fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| !is_comment_kind(child.kind()))
        .collect()
}

fn children_by_field_name<'tree>(node: Node<'tree>, field: &str) -> Vec<Node<'tree>> {
    let mut cursor = node.walk();
    node.children_by_field_name(field, &mut cursor).collect()
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
