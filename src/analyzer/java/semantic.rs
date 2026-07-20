//! Java lowering into the language-neutral executable-semantics IR.
//!
//! This module deliberately interprets tree-sitter nodes and fields directly.
//! Graph construction, abrupt-completion routing, cleanup specialization, and
//! physical adjacency storage remain owned by the shared semantic substrate.

use std::sync::Arc;

use tree_sitter::Node;

use crate::analyzer::semantic::cfg::{
    CleanupRegionId, CompletionKind, CompletionRequest, CompletionRoute, DriveError,
    ProcedureCfgBuilder, ScopeBinding, ScopeFrameId,
};
use crate::analyzer::semantic::service::{ProgramSemanticsLowerer, SemanticAdapterIdentity};
use crate::analyzer::semantic::*;
use crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree;
use crate::analyzer::{JavaAnalyzer, ProjectFile};
use crate::hash::HashMap;

const ADAPTER_VERSION: &[u8] = b"java-cfg-v1";

impl ProgramSemanticsProvider for JavaAnalyzer {
    fn materialize(
        &self,
        file: &ProjectFile,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError> {
        self.inner
            .materialize_semantics_with_lowerer(&JavaSemanticLowerer, file, request)
    }
}

struct JavaSemanticLowerer;

impl ProgramSemanticsLowerer for JavaSemanticLowerer {
    fn identity(&self) -> SemanticAdapterIdentity {
        SemanticAdapterIdentity {
            adapter: AdapterSemanticsVersion::hash_bytes("java", ADAPTER_VERSION)
                .expect("adapter name is non-empty"),
            configuration: ConfigurationFingerprint::hash_bytes(
                b"java-intrafile-execution-defaults-v1",
            ),
            dependencies: DependencyFingerprint::hash_bytes(b"no-intrafile-dependencies"),
        }
    }

    fn capabilities(&self) -> SemanticCapabilities {
        java_capabilities()
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
                Err(JavaLoweringError::Cancelled(work)) => {
                    return Ok(SemanticOutcome::Cancelled {
                        partial: None,
                        work: sum_work(observed, *work),
                    });
                }
                Err(JavaLoweringError::Budget(exceeded, work)) => {
                    let work = sum_work(observed, *work);
                    let exceeded = budget.check(work).err().unwrap_or(exceeded);
                    return Ok(SemanticOutcome::ExceededBudget {
                        partial: None,
                        exceeded,
                        work,
                    });
                }
                Err(JavaLoweringError::Invalid(detail)) => {
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

fn java_capabilities() -> SemanticCapabilities {
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
        SemanticCapability::NonLocalControl,
        SemanticCapability::ResourceManagement,
        SemanticCapability::DeferredExecution,
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
        .unwrap_or("java-source");
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
        let mut child_path = frame.declaration_path;
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
            child_path =
                push_declaration_path(&mut declaration_paths, frame.declaration_path, segment);
        }

        let mut child_parent = frame.lexical_parent;
        if let Some((kind, segment_kind, body, properties)) = callable_shape(frame.node) {
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
            child_parent = Some(id);
            child_path = push_declaration_path(&mut declaration_paths, child_path, segment);
        }

        let mut cursor = frame.node.walk();
        let children = frame.node.named_children(&mut cursor).collect::<Vec<_>>();
        for child in children.into_iter().rev() {
            stack.push(ProcedureEnumerationFrame {
                node: child,
                lexical_parent: child_parent,
                declaration_path: child_path,
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
        "class_declaration"
        | "interface_declaration"
        | "enum_declaration"
        | "record_declaration"
        | "annotation_type_declaration" => Some(DeclarationSegmentKind::Type),
        "class_body"
            if node
                .parent()
                .is_some_and(|parent| parent.kind() == "object_creation_expression") =>
        {
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
    node.child_by_field_name("name")
        .and_then(|name| nonempty_node_text(source, name))
        .map(Box::<str>::from)
        .or_else(|| enclosing_variable_name(source, node))
}

fn enclosing_variable_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    let parent = node.parent()?;
    if parent.kind() != "variable_declarator" || !field_matches(parent, "value", node) {
        return None;
    }
    parent
        .child_by_field_name("name")
        .and_then(|name| nonempty_node_text(source, name))
        .map(Box::<str>::from)
}

fn callable_shape<'tree>(
    node: Node<'tree>,
) -> Option<(
    ProcedureKind,
    DeclarationSegmentKind,
    Node<'tree>,
    ProcedureProperties,
)> {
    let (kind, segment_kind, body, is_static) = match node.kind() {
        "method_declaration" => (
            ProcedureKind::Method,
            DeclarationSegmentKind::Method,
            node.child_by_field_name("body")?,
            has_modifier(node, "static"),
        ),
        "constructor_declaration" => (
            ProcedureKind::Constructor,
            DeclarationSegmentKind::Constructor,
            node.child_by_field_name("body")?,
            false,
        ),
        "compact_constructor_declaration" => (
            ProcedureKind::Constructor,
            DeclarationSegmentKind::Constructor,
            node.child_by_field_name("body")?,
            false,
        ),
        "lambda_expression" => (
            ProcedureKind::Lambda,
            DeclarationSegmentKind::Lambda,
            node.child_by_field_name("body")?,
            false,
        ),
        "static_initializer" => (
            ProcedureKind::Initializer,
            DeclarationSegmentKind::Initializer,
            first_named_child(node)?,
            true,
        ),
        "block"
            if node
                .parent()
                .is_some_and(|parent| parent.kind() == "class_body") =>
        {
            (
                ProcedureKind::Initializer,
                DeclarationSegmentKind::Initializer,
                node,
                false,
            )
        }
        "variable_declarator"
            if node.parent().is_some_and(|parent| {
                matches!(parent.kind(), "field_declaration" | "constant_declaration")
            }) =>
        {
            let field = node.parent().expect("guarded field-declaration parent");
            (
                ProcedureKind::Initializer,
                DeclarationSegmentKind::Initializer,
                node.child_by_field_name("value")?,
                field.kind() == "constant_declaration" || has_modifier(field, "static"),
            )
        }
        "enum_constant" => (
            ProcedureKind::Initializer,
            DeclarationSegmentKind::Initializer,
            node,
            true,
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
            is_static,
            is_synthetic: false,
            invocation: ProcedureInvocationKind::Immediate,
        },
    ))
}

fn has_modifier(node: Node<'_>, modifier: &str) -> bool {
    node.child_by_field_name("modifiers")
        .or_else(|| {
            named_children(node)
                .into_iter()
                .find(|child| child.kind() == "modifiers")
        })
        .is_some_and(|modifiers| {
            let mut cursor = modifiers.walk();
            modifiers
                .children(&mut cursor)
                .any(|child| child.kind() == modifier)
        })
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
enum JavaLoweringError {
    Cancelled(Box<SemanticWork>),
    Budget(SemanticBudgetExceeded, Box<SemanticWork>),
    Invalid(String),
}

impl From<SemanticBudgetExceeded> for JavaLoweringError {
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
    },
    LabeledStatement {
        node: Node<'tree>,
        label: &'tree str,
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
struct PointMetadata {
    source: SourceMappingId,
    evidence: EvidenceId,
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
    OpaqueResource(Node<'tree>),
    OpaqueMonitor(Node<'tree>),
}

impl<'tree> CleanupBody<'tree> {
    const fn source_node(self) -> Node<'tree> {
        match self {
            Self::Statement(node) | Self::OpaqueResource(node) | Self::OpaqueMonitor(node) => node,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JavaSwitchArmKind {
    Group,
    Rule,
}

struct JavaSwitchArm<'tree> {
    node: Node<'tree>,
    labels: Vec<Node<'tree>>,
    body: Vec<Node<'tree>>,
    kind: JavaSwitchArmKind,
}

struct LoweringContext<'tree, 'targets> {
    prepared: &'tree PreparedSyntaxTree,
    locator: SemanticLocator,
    point_metadata: Vec<PointMetadata>,
    next_source: usize,
    next_evidence: usize,
    next_value: usize,
    next_call_site: usize,
    next_gap: usize,
    source_occurrences: HashMap<(usize, usize), u32>,
    cleanups: Vec<CleanupRegion<'tree>>,
    cancellation: &'targets CancellationToken,
}

fn lower_procedure<'tree>(
    prepared: &'tree PreparedSyntaxTree,
    spec: &ProcedureSpec<'tree>,
    budget: &SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<(ProcedureSemanticsParts, SemanticWork), JavaLoweringError> {
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
        prepared,
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
        cleanups: Vec::new(),
        cancellation,
    };

    if spec.kind == ProcedureKind::Initializer {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::DeferredExecution,
            SemanticGapKind::Unsupported,
            "initializer scheduling and source-order composition across initializer fragments are not yet modeled",
        )?;
    }
    if spec.kind == ProcedureKind::Constructor
        && !named_children(spec.body)
            .into_iter()
            .any(|child| child.kind() == "explicit_constructor_invocation")
    {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unsupported,
            "implicit super-constructor invocation is not yet represented as a call site",
        )?;
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            "implicit super-constructor invocation can complete exceptionally",
        )?;
    }

    let body_entry = context.point(&mut builder, spec.body, Vec::new())?;
    let initial = if matches!(spec.body.kind(), "block" | "constructor_body") {
        Work::Statement {
            node: spec.body,
            entry: body_entry,
            next: EdgeTarget::normal(normal_exit),
            scope: function_scope,
        }
    } else if spec.kind == ProcedureKind::Initializer {
        Work::Expression {
            node: spec.body,
            entry: body_entry,
            next: EdgeTarget::normal(normal_exit),
            scope: function_scope,
        }
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
        Work::Expression {
            node: spec.body,
            entry: body_entry,
            next: EdgeTarget::normal(implicit_return),
            scope: function_scope,
        }
    };
    context.edge(&mut builder, entry, EdgeTarget::normal(body_entry))?;

    if let Err(error) = builder.drive_iteratively(initial, cancellation, |builder, work, stack| {
        context.step(builder, work, stack)
    }) {
        let work = builder.prospective_work();
        return match error {
            DriveError::Cancelled | DriveError::Step(JavaLoweringError::Cancelled(_)) => {
                Err(JavaLoweringError::Cancelled(Box::new(work)))
            }
            DriveError::ExceededBudget(exceeded) => {
                Err(JavaLoweringError::Budget(exceeded, Box::new(work)))
            }
            DriveError::Step(JavaLoweringError::Budget(exceeded, _)) => {
                Err(JavaLoweringError::Budget(exceeded, Box::new(work)))
            }
            DriveError::Step(JavaLoweringError::Invalid(detail)) => {
                Err(JavaLoweringError::Invalid(detail))
            }
        };
    }

    if builder
        .seal_unreachable_regions(entry, normal_exit, exceptional_exit, cancellation)
        .is_err()
    {
        return Err(JavaLoweringError::Cancelled(Box::new(
            builder.prospective_work(),
        )));
    }
    let work_before_freeze = builder.prospective_work();
    builder
        .finish_with_work()
        .map_err(|error| JavaLoweringError::Budget(error, Box::new(work_before_freeze)))
}

impl<'tree, 'targets> LoweringContext<'tree, 'targets> {
    fn step(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        work: Work<'tree>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), JavaLoweringError> {
        if self.cancellation.is_cancelled() {
            return Err(JavaLoweringError::Cancelled(Box::default()));
        }
        match work {
            Work::Statement {
                node,
                entry,
                next,
                scope,
            } => self.statement(builder, node, entry, next, scope, None, stack),
            Work::LabeledStatement {
                node,
                label,
                entry,
                next,
                scope,
            } => self.statement(builder, node, entry, next, scope, Some(label), stack),
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
    ) -> Result<(), JavaLoweringError> {
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
            ("ternary_expression", _) => {
                let condition = required_field(node, "condition")?;
                let consequence = required_field(node, "consequence")?;
                let alternative = required_field(node, "alternative")?;
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
    fn statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        attached_label: Option<&'tree str>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), JavaLoweringError> {
        let scope = if let Some(label) = attached_label
            && !matches!(
                node.kind(),
                "while_statement"
                    | "do_statement"
                    | "for_statement"
                    | "enhanced_for_statement"
                    | "switch_expression"
            ) {
            builder.push_scope(
                Some(scope),
                ScopeBinding::Breakable {
                    label: Some(Box::<str>::from(label)),
                    accepts_unlabeled: false,
                    break_target: next.point,
                    break_edge_kind: next.kind,
                },
            )
        } else {
            scope
        };

        match node.kind() {
            "block" | "constructor_body" | "program" => {
                let children = named_children(node)
                    .into_iter()
                    .filter(|child| child.kind() != "comment")
                    .collect::<Vec<_>>();
                self.schedule_statements(builder, entry, &children, next, scope, stack)
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
            "return_statement" => {
                let terminal = if let Some(value_node) = first_named_child(node) {
                    let point = self.point(builder, node, Vec::new())?;
                    let value = self.value(builder, point, SemanticValueKind::Return)?;
                    self.append_effect(
                        builder,
                        point,
                        SemanticEffect::ProcedureReturn { value: Some(value) },
                    )?;
                    stack.push(Work::Expression {
                        node: value_node,
                        entry,
                        next: EdgeTarget::normal(point),
                        scope,
                    });
                    point
                } else {
                    self.append_effect(
                        builder,
                        entry,
                        SemanticEffect::ProcedureReturn { value: None },
                    )?;
                    entry
                };
                self.abrupt(
                    builder,
                    terminal,
                    scope,
                    CompletionKind::Return,
                    None,
                    stack,
                )
            }
            "throw_statement" => {
                let value_node = first_named_child(node)
                    .ok_or_else(|| missing_field(node, "thrown expression"))?;
                let terminal = self.point(builder, node, Vec::new())?;
                let value = self.value(builder, terminal, SemanticValueKind::Exception)?;
                self.append_effect(
                    builder,
                    terminal,
                    SemanticEffect::Throw { value: Some(value) },
                )?;
                stack.push(Work::Expression {
                    node: value_node,
                    entry,
                    next: EdgeTarget::normal(terminal),
                    scope,
                });
                self.abrupt(builder, terminal, scope, CompletionKind::Throw, None, stack)
            }
            "yield_statement" => {
                let value_node = first_named_child(node)
                    .ok_or_else(|| missing_field(node, "yield expression"))?;
                let terminal = self.point(builder, node, Vec::new())?;
                stack.push(Work::Expression {
                    node: value_node,
                    entry,
                    next: EdgeTarget::normal(terminal),
                    scope,
                });
                self.abrupt(builder, terminal, scope, CompletionKind::Yield, None, stack)
            }
            "break_statement" | "continue_statement" => {
                let label = first_named_child(node)
                    .and_then(|label| node_text(self.prepared.source(), label));
                let kind = if node.kind() == "break_statement" {
                    CompletionKind::Break
                } else {
                    CompletionKind::Continue
                };
                self.abrupt(builder, entry, scope, kind, label, stack)
            }
            "if_statement" => {
                let condition = required_field(node, "condition")?;
                let consequence = required_field(node, "consequence")?;
                let alternative = node.child_by_field_name("alternative");
                let consequence_entry = self.point(builder, consequence, Vec::new())?;
                stack.push(Work::Statement {
                    node: consequence,
                    entry: consequence_entry,
                    next,
                    scope,
                });
                let false_target = if let Some(alternative) = alternative {
                    let alternative_entry = self.point(builder, alternative, Vec::new())?;
                    stack.push(Work::Statement {
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
                    when_false: false_target,
                    scope,
                });
                Ok(())
            }
            "while_statement" => {
                let condition = required_field(node, "condition")?;
                let body = required_field(node, "body")?;
                let body_entry = self.point(builder, body, Vec::new())?;
                let loop_scope = builder.push_scope(
                    Some(scope),
                    ScopeBinding::Loop {
                        label: attached_label.map(Box::<str>::from),
                        break_target: next.point,
                        break_edge_kind: next.kind,
                        continue_target: entry,
                        continue_edge_kind: ControlEdgeKind::LoopBack,
                    },
                );
                stack.push(Work::Statement {
                    node: body,
                    entry: body_entry,
                    next: EdgeTarget {
                        point: entry,
                        kind: ControlEdgeKind::LoopBack,
                    },
                    scope: loop_scope,
                });
                stack.push(Work::Condition {
                    node: condition,
                    entry,
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
                Ok(())
            }
            "do_statement" => {
                let body = required_field(node, "body")?;
                let condition = required_field(node, "condition")?;
                let condition_entry = self.point(builder, condition, Vec::new())?;
                let loop_scope = builder.push_scope(
                    Some(scope),
                    ScopeBinding::Loop {
                        label: attached_label.map(Box::<str>::from),
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
                stack.push(Work::Statement {
                    node: body,
                    entry,
                    next: EdgeTarget::normal(condition_entry),
                    scope: loop_scope,
                });
                Ok(())
            }
            "for_statement" => {
                self.for_statement(builder, node, entry, next, scope, attached_label, stack)
            }
            "enhanced_for_statement" => self.enhanced_for_statement(
                builder,
                node,
                entry,
                next,
                scope,
                attached_label,
                stack,
            ),
            "switch_expression" => self.switch(
                builder,
                node,
                entry,
                next,
                scope,
                attached_label,
                false,
                stack,
            ),
            "try_statement" | "try_with_resources_statement" => {
                self.try_statement(builder, node, entry, next, scope, stack)
            }
            "synchronized_statement" => {
                self.synchronized_statement(builder, node, entry, next, scope, stack)
            }
            "labeled_statement" => {
                let children = named_children(node);
                let label_node = children
                    .iter()
                    .copied()
                    .find(|child| child.kind() == "identifier")
                    .ok_or_else(|| missing_field(node, "label"))?;
                let body = children
                    .into_iter()
                    .find(|child| child.id() != label_node.id())
                    .ok_or_else(|| missing_field(node, "body"))?;
                let label = node_text(self.prepared.source(), label_node).ok_or_else(|| {
                    JavaLoweringError::Invalid("labeled statement has invalid source range".into())
                })?;
                stack.push(Work::LabeledStatement {
                    node: body,
                    label,
                    entry,
                    next,
                    scope,
                });
                Ok(())
            }
            "local_variable_declaration" => {
                let initializers = children_by_field_name(node, "declarator")
                    .into_iter()
                    .filter_map(|declarator| declarator.child_by_field_name("value"))
                    .collect::<Vec<_>>();
                self.schedule_expressions(builder, entry, &initializers, next, scope, stack)
            }
            "explicit_constructor_invocation" => {
                self.call_expression(builder, node, entry, next, scope, stack)
            }
            "assert_statement" => {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::NormalControlFlow,
                    SemanticGapKind::Unsupported,
                    "assert enablement and conditional message evaluation are not yet lowered",
                )?;
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::ExceptionalControlFlow,
                    SemanticGapKind::Unsupported,
                    "assert enablement and AssertionError construction are not yet lowered",
                )?;
                let values = named_children(node);
                self.schedule_expressions(builder, entry, &values, next, scope, stack)
            }
            "empty_statement"
            | "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "annotation_type_declaration"
            | "method_declaration"
            | "constructor_declaration"
            | "compact_constructor_declaration"
            | "static_initializer" => self.edge(builder, entry, next),
            _ => self.unhandled_control_syntax(builder, node, entry),
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
    ) -> Result<(), JavaLoweringError> {
        match node.kind() {
            "method_invocation" | "object_creation_expression" | "enum_constant" => {
                self.call_expression(builder, node, entry, next, scope, stack)
            }
            "switch_expression" => {
                self.switch(builder, node, entry, next, scope, None, true, stack)
            }
            "lambda_expression" => self.callable_expression(builder, node, entry, next),
            "method_reference" => self.method_reference(builder, node, entry, next, scope, stack),
            "ternary_expression" => {
                let condition = required_field(node, "condition")?;
                let consequence = required_field(node, "consequence")?;
                let alternative = required_field(node, "alternative")?;
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
            "parenthesized_expression" => {
                if let Some(value) = first_named_child(node) {
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
            "field_access" | "array_access" => {
                self.implicit_exception_gap(builder, entry, node)?;
                let children = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            "string_literal" => {
                let interpolations = named_children(node)
                    .into_iter()
                    .filter(|child| child.kind() == "string_interpolation")
                    .collect::<Vec<_>>();
                self.schedule_expressions(builder, entry, &interpolations, next, scope, stack)
            }
            "string_interpolation" => {
                let values = named_children(node);
                self.schedule_expressions(builder, entry, &values, next, scope, stack)
            }
            "assignment_expression"
            | "binary_expression"
            | "unary_expression"
            | "update_expression"
            | "cast_expression"
            | "instanceof_expression"
            | "array_creation_expression"
            | "array_initializer"
            | "dimensions_expr"
            | "template_expression" => {
                if operation_can_throw_implicitly(node) {
                    self.implicit_exception_gap(builder, entry, node)?;
                }
                let children = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            kind if is_runtime_leaf(kind) => self.edge(builder, entry, next),
            _ => self.unhandled_control_syntax(builder, node, entry),
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
        label: Option<&'tree str>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), JavaLoweringError> {
        let body = required_field(node, "body")?;
        let initializers = children_by_field_name(node, "init");
        let condition = node.child_by_field_name("condition");
        let updates = children_by_field_name(node, "update");
        let condition_entry = match condition {
            Some(condition) => self.point(builder, condition, Vec::new())?,
            None => self.point(builder, node, Vec::new())?,
        };
        let body_entry = self.point(builder, body, Vec::new())?;
        let update_entries = updates
            .iter()
            .map(|update| self.point(builder, *update, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        let continue_target = update_entries.first().copied().unwrap_or(condition_entry);
        let loop_scope = builder.push_scope(
            Some(scope),
            ScopeBinding::Loop {
                label: label.map(Box::<str>::from),
                break_target: next.point,
                break_edge_kind: next.kind,
                continue_target,
                continue_edge_kind: if updates.is_empty() {
                    ControlEdgeKind::LoopBack
                } else {
                    ControlEdgeKind::Normal
                },
            },
        );

        for index in (0..updates.len()).rev() {
            stack.push(Work::Expression {
                node: updates[index],
                entry: update_entries[index],
                next: update_entries
                    .get(index + 1)
                    .copied()
                    .map(EdgeTarget::normal)
                    .unwrap_or(EdgeTarget {
                        point: condition_entry,
                        kind: ControlEdgeKind::LoopBack,
                    }),
                scope: loop_scope,
            });
        }
        stack.push(Work::Statement {
            node: body,
            entry: body_entry,
            next: EdgeTarget {
                point: continue_target,
                kind: if updates.is_empty() {
                    ControlEdgeKind::LoopBack
                } else {
                    ControlEdgeKind::Normal
                },
            },
            scope: loop_scope,
        });
        if let Some(condition) = condition {
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
        } else {
            self.edge(builder, condition_entry, EdgeTarget::normal(body_entry))?;
        }

        if initializers.is_empty() {
            if entry != condition_entry {
                self.edge(builder, entry, EdgeTarget::normal(condition_entry))?;
            }
        } else {
            let init_entries = initializers
                .iter()
                .map(|initializer| self.point(builder, *initializer, Vec::new()))
                .collect::<Result<Vec<_>, _>>()?;
            self.edge(builder, entry, EdgeTarget::normal(init_entries[0]))?;
            for index in (0..initializers.len()).rev() {
                let next = init_entries
                    .get(index + 1)
                    .copied()
                    .map(EdgeTarget::normal)
                    .unwrap_or_else(|| EdgeTarget::normal(condition_entry));
                if initializers[index].kind() == "local_variable_declaration" {
                    stack.push(Work::Statement {
                        node: initializers[index],
                        entry: init_entries[index],
                        next,
                        scope: loop_scope,
                    });
                } else {
                    stack.push(Work::Expression {
                        node: initializers[index],
                        entry: init_entries[index],
                        next,
                        scope: loop_scope,
                    });
                }
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn enhanced_for_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        label: Option<&'tree str>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), JavaLoweringError> {
        let iterable = required_field(node, "value")?;
        let binding = required_field(node, "name")?;
        let body = required_field(node, "body")?;
        let test = self.point(builder, node, Vec::new())?;
        let binding_entry = self.point(builder, binding, Vec::new())?;
        let body_entry = self.point(builder, body, Vec::new())?;
        let loop_scope = builder.push_scope(
            Some(scope),
            ScopeBinding::Loop {
                label: label.map(Box::<str>::from),
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
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            "implicit iterator acquisition and advancement exceptions are not yet lowered",
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
                point: next.point,
                kind: ControlEdgeKind::ConditionalFalse,
            },
        )?;
        self.edge(builder, binding_entry, EdgeTarget::normal(body_entry))?;
        stack.push(Work::Statement {
            node: body,
            entry: body_entry,
            next: EdgeTarget {
                point: test,
                kind: ControlEdgeKind::LoopBack,
            },
            scope: loop_scope,
        });
        stack.push(Work::Expression {
            node: iterable,
            entry,
            next: EdgeTarget::normal(test),
            scope: loop_scope,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn switch(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        label: Option<&'tree str>,
        expression_mode: bool,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), JavaLoweringError> {
        let condition = required_field(node, "condition")?;
        let body = required_field(node, "body")?;
        let dispatch = self.point(builder, node, Vec::new())?;
        let switch_next = if expression_mode {
            let merge = self.point(builder, node, Vec::new())?;
            self.edge(builder, merge, next)?;
            EdgeTarget::normal(merge)
        } else {
            next
        };
        let switch_scope = if expression_mode {
            builder.push_scope(
                Some(scope),
                ScopeBinding::Yieldable {
                    yield_target: switch_next.point,
                    yield_edge_kind: switch_next.kind,
                },
            )
        } else {
            builder.push_scope(
                Some(scope),
                ScopeBinding::Breakable {
                    label: label.map(Box::<str>::from),
                    accepts_unlabeled: true,
                    break_target: next.point,
                    break_edge_kind: next.kind,
                },
            )
        };
        let arms = java_switch_arms(body);
        if arms.is_empty() {
            if expression_mode {
                self.add_gap(
                    builder,
                    dispatch,
                    SemanticGapSubject::Point,
                    SemanticCapability::NormalControlFlow,
                    SemanticGapKind::Unsupported,
                    "empty switch expression has no represented result",
                )?;
            } else {
                self.edge(builder, dispatch, switch_next)?;
            }
            stack.push(Work::Expression {
                node: condition,
                entry,
                next: EdgeTarget::normal(dispatch),
                scope: switch_scope,
            });
            return Ok(());
        }

        let arm_entries = arms
            .iter()
            .map(|arm| self.point(builder, arm.node, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        for index in (0..arms.len()).rev() {
            let arm = &arms[index];
            match arm.kind {
                JavaSwitchArmKind::Group => {
                    let fallthrough = if let Some(entry) = arm_entries.get(index + 1).copied() {
                        EdgeTarget::normal(entry)
                    } else if expression_mode {
                        let missing_yield = self.point(builder, arm.node, Vec::new())?;
                        self.add_gap(
                            builder,
                            missing_yield,
                            SemanticGapSubject::Point,
                            SemanticCapability::NormalControlFlow,
                            SemanticGapKind::Unsupported,
                            "switch-expression statement group can complete without a represented yield",
                        )?;
                        EdgeTarget::normal(missing_yield)
                    } else {
                        switch_next
                    };
                    self.schedule_statements(
                        builder,
                        arm_entries[index],
                        &arm.body,
                        fallthrough,
                        switch_scope,
                        stack,
                    )?;
                }
                JavaSwitchArmKind::Rule => {
                    let action = arm.body.first().copied();
                    match action {
                        Some(action)
                            if expression_mode && action.kind() == "expression_statement" =>
                        {
                            if let Some(value) = first_named_child(action) {
                                stack.push(Work::Expression {
                                    node: value,
                                    entry: arm_entries[index],
                                    next: switch_next,
                                    scope: switch_scope,
                                });
                            } else {
                                self.add_gap(
                                    builder,
                                    arm_entries[index],
                                    SemanticGapSubject::Point,
                                    SemanticCapability::NormalControlFlow,
                                    SemanticGapKind::Unsupported,
                                    "switch-expression rule has no result expression",
                                )?;
                            }
                        }
                        Some(action) if expression_mode && action.kind() == "block" => {
                            let missing_yield = self.point(builder, action, Vec::new())?;
                            self.add_gap(
                                builder,
                                missing_yield,
                                SemanticGapSubject::Point,
                                SemanticCapability::NormalControlFlow,
                                SemanticGapKind::Unsupported,
                                "switch-expression block rule can complete without a represented yield",
                            )?;
                            stack.push(Work::Statement {
                                node: action,
                                entry: arm_entries[index],
                                next: EdgeTarget::normal(missing_yield),
                                scope: switch_scope,
                            });
                        }
                        Some(action) => {
                            stack.push(Work::Statement {
                                node: action,
                                entry: arm_entries[index],
                                next: switch_next,
                                scope: switch_scope,
                            });
                        }
                        None => {
                            self.add_gap(
                                builder,
                                arm_entries[index],
                                SemanticGapSubject::Point,
                                SemanticCapability::NormalControlFlow,
                                SemanticGapKind::Unsupported,
                                "switch rule has no executable body",
                            )?;
                        }
                    }
                }
            }
        }

        let default_target = arms.iter().enumerate().find_map(|(index, arm)| {
            arm.labels
                .iter()
                .any(|label| switch_label_is_default(*label))
                .then_some(EdgeTarget::normal(arm_entries[index]))
        });
        let mut no_match = if let Some(default_target) = default_target {
            default_target
        } else if expression_mode {
            let missing_match = self.point(builder, node, Vec::new())?;
            self.add_gap(
                builder,
                missing_match,
                SemanticGapSubject::Point,
                SemanticCapability::NormalControlFlow,
                SemanticGapKind::Unknown,
                "switch-expression exhaustiveness requires type and pattern refinement",
            )?;
            EdgeTarget::normal(missing_match)
        } else {
            switch_next
        };

        for (arm_index, arm) in arms.iter().enumerate().rev() {
            for switch_label in arm.labels.iter().rev() {
                if switch_label_is_default(*switch_label) {
                    continue;
                }
                let comparison = self.point(builder, *switch_label, Vec::new())?;
                if switch_label_has_pattern(*switch_label) {
                    self.add_gap(
                        builder,
                        comparison,
                        SemanticGapSubject::Point,
                        SemanticCapability::NormalControlFlow,
                        SemanticGapKind::Unsupported,
                        "pattern compatibility requires type refinement",
                    )?;
                }
                if let Some(guard) = switch_label_guard(*switch_label) {
                    let guard_entry = self.point(builder, guard, Vec::new())?;
                    self.edge(
                        builder,
                        comparison,
                        EdgeTarget {
                            point: guard_entry,
                            kind: ControlEdgeKind::ConditionalTrue,
                        },
                    )?;
                    stack.push(Work::Condition {
                        node: guard,
                        entry: guard_entry,
                        when_true: EdgeTarget {
                            point: arm_entries[arm_index],
                            kind: ControlEdgeKind::SwitchCase,
                        },
                        when_false: EdgeTarget {
                            point: no_match.point,
                            kind: ControlEdgeKind::ConditionalFalse,
                        },
                        scope: switch_scope,
                    });
                } else {
                    self.edge(
                        builder,
                        comparison,
                        EdgeTarget {
                            point: arm_entries[arm_index],
                            kind: ControlEdgeKind::SwitchCase,
                        },
                    )?;
                }
                self.edge(
                    builder,
                    comparison,
                    EdgeTarget {
                        point: no_match.point,
                        kind: ControlEdgeKind::ConditionalFalse,
                    },
                )?;
                no_match = EdgeTarget::normal(comparison);
            }
        }
        self.edge(builder, dispatch, no_match)?;
        stack.push(Work::Expression {
            node: condition,
            entry,
            next: EdgeTarget::normal(dispatch),
            scope: switch_scope,
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
    ) -> Result<(), JavaLoweringError> {
        let body = required_field(node, "body")?;
        let children = named_children(node);
        let catches = children
            .iter()
            .copied()
            .filter(|child| child.kind() == "catch_clause")
            .collect::<Vec<_>>();
        let finalizer = children
            .iter()
            .copied()
            .find(|child| child.kind() == "finally_clause")
            .and_then(first_named_child);

        let (cleanup_scope, cleanup_region) = if let Some(finalizer) = finalizer {
            let region = CleanupRegionId::new(
                u32::try_from(self.cleanups.len())
                    .map_err(|_| JavaLoweringError::Invalid("too many cleanup regions".into()))?,
            );
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
            .map(|catch| required_field(*catch, "body"))
            .collect::<Result<Vec<_>, _>>()?;
        let catch_entries = catch_bodies
            .iter()
            .map(|body| self.point(builder, *body, Vec::new()))
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
                "catch-type compatibility and multi-catch selection require type refinement",
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

        for (catch_body, catch_entry) in catch_bodies.iter().zip(&catch_entries) {
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

        let (body_entry, body_scope, resource_normal_route) = if node.kind()
            == "try_with_resources_statement"
        {
            let resource_region = CleanupRegionId::new(
                u32::try_from(self.cleanups.len())
                    .map_err(|_| JavaLoweringError::Invalid("too many cleanup regions".into()))?,
            );
            self.cleanups.push(CleanupRegion {
                id: resource_region,
                body: CleanupBody::OpaqueResource(node),
                outer_scope: try_scope,
            });
            let body_scope = builder.push_scope(
                Some(try_scope),
                ScopeBinding::Cleanup {
                    region: resource_region,
                },
            );
            let after_resource = self.point(builder, node, Vec::new())?;
            if let Some(route) = &normal_route {
                self.route(builder, after_resource, route, stack)?;
            } else {
                self.edge(builder, after_resource, next)?;
            }
            let resource_normal_route =
                builder.normal_cleanup_completion(resource_region, after_resource);
            let resource_boundary = self.point(builder, node, Vec::new())?;
            self.add_gap(
                builder,
                resource_boundary,
                SemanticGapSubject::Point,
                SemanticCapability::ResourceManagement,
                SemanticGapKind::Unsupported,
                    "resource acquisition and partial-initialization cleanup are not yet lowered exactly",
            )?;
            self.add_gap(
                builder,
                resource_boundary,
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unsupported,
                "resource acquisition can raise implicit exceptions not yet represented",
            )?;
            let resources = node
                .child_by_field_name("resources")
                .map(named_children)
                .unwrap_or_default();
            let initializers = resources
                .into_iter()
                .filter_map(|resource| {
                    resource
                        .child_by_field_name("value")
                        .or_else(|| first_runtime_named_child(resource))
                })
                .collect::<Vec<_>>();
            if initializers.is_empty() {
                self.edge(builder, entry, EdgeTarget::normal(resource_boundary))?;
            } else {
                self.schedule_expressions(
                    builder,
                    entry,
                    &initializers,
                    EdgeTarget::normal(resource_boundary),
                    try_scope,
                    stack,
                )?;
            }
            (resource_boundary, body_scope, Some(resource_normal_route))
        } else {
            (entry, try_scope, None)
        };

        if let Some(route) = resource_normal_route.as_ref().or(normal_route.as_ref()) {
            let body_exit = self.point(builder, body, Vec::new())?;
            self.route(builder, body_exit, route, stack)?;
            stack.push(Work::Statement {
                node: body,
                entry: body_entry,
                next: EdgeTarget::normal(body_exit),
                scope: body_scope,
            });
        } else {
            stack.push(Work::Statement {
                node: body,
                entry: body_entry,
                next,
                scope: body_scope,
            });
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn synchronized_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), JavaLoweringError> {
        let lock = named_children(node)
            .into_iter()
            .find(|child| child.kind() == "parenthesized_expression")
            .ok_or_else(|| missing_field(node, "lock"))?;
        let body = required_field(node, "body")?;
        let monitor = self.point(builder, node, Vec::new())?;
        let body_entry = self.point(builder, body, Vec::new())?;
        let region = CleanupRegionId::new(
            u32::try_from(self.cleanups.len())
                .map_err(|_| JavaLoweringError::Invalid("too many cleanup regions".into()))?,
        );
        self.cleanups.push(CleanupRegion {
            id: region,
            body: CleanupBody::OpaqueMonitor(node),
            outer_scope: scope,
        });
        let synchronized_scope = builder.push_scope(Some(scope), ScopeBinding::Cleanup { region });
        self.add_gap(
            builder,
            monitor,
            SemanticGapSubject::Point,
            SemanticCapability::CleanupControlFlow,
            SemanticGapKind::Unsupported,
            "monitor ownership and reentrancy effects are represented only as opaque boundaries",
        )?;
        self.add_gap(
            builder,
            monitor,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            "implicit monitor acquisition exceptions are not yet lowered",
        )?;
        self.edge(builder, monitor, EdgeTarget::normal(body_entry))?;
        let cleanup_destination = if next.kind == ControlEdgeKind::Normal {
            next.point
        } else {
            let relay = self.point(builder, node, Vec::new())?;
            self.edge(builder, relay, next)?;
            relay
        };
        let body_exit = self.point(builder, body, Vec::new())?;
        let normal_route = builder.normal_cleanup_completion(region, cleanup_destination);
        self.route(builder, body_exit, &normal_route, stack)?;
        stack.push(Work::Statement {
            node: body,
            entry: body_entry,
            next: EdgeTarget::normal(body_exit),
            scope: synchronized_scope,
        });
        stack.push(Work::Expression {
            node: lock,
            entry,
            next: EdgeTarget::normal(monitor),
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
    ) -> Result<(), JavaLoweringError> {
        let invoke = self.point(builder, node, Vec::new())?;
        let normal = self.point(builder, node, Vec::new())?;
        let exceptional = self.point(builder, node, Vec::new())?;
        let callee = self.value(builder, invoke, SemanticValueKind::Callable)?;
        let result = self.value(builder, invoke, SemanticValueKind::Temporary)?;
        let thrown = self.value(builder, invoke, SemanticValueKind::Exception)?;
        let receiver_node = match node.kind() {
            "method_invocation" | "explicit_constructor_invocation" => {
                node.child_by_field_name("object")
            }
            "object_creation_expression" => object_creation_qualifier(node),
            _ => None,
        };
        let receiver = receiver_node
            .map(|_| self.value(builder, invoke, SemanticValueKind::Receiver))
            .transpose()?;
        let callable_kind = match node.kind() {
            "object_creation_expression" | "explicit_constructor_invocation" | "enum_constant" => {
                CallableReferenceKind::Constructor
            }
            "method_invocation" if receiver.is_some() => CallableReferenceKind::BoundMethod,
            "method_invocation" => CallableReferenceKind::UnboundMethod,
            _ => CallableReferenceKind::Function,
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
                .map_err(|_| JavaLoweringError::Invalid("too many call sites".into()))?,
        );
        let arguments = node
            .child_by_field_name("arguments")
            .map(named_children)
            .unwrap_or_default();
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
        self.abrupt(
            builder,
            exceptional,
            scope,
            CompletionKind::Throw,
            None,
            stack,
        )?;
        self.resolution_gaps(builder, invoke, callee, call_site, &resolution)?;

        if node.kind() == "method_invocation" {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::DynamicDispatch,
                SemanticGapKind::Unknown,
                "method invocation may select an override; static/final dispatch and complete override coverage require type-hierarchy refinement",
            )?;
        }

        let mut evaluations =
            Vec::with_capacity(arguments.len() + usize::from(receiver_node.is_some()));
        if let Some(receiver_node) = receiver_node {
            evaluations.push(receiver_node);
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

    fn callable_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
    ) -> Result<(), JavaLoweringError> {
        let result = self.value(builder, entry, SemanticValueKind::Callable)?;
        let resolution = CallableTargetResolution::Unknown;
        let metadata = self.metadata(entry)?;
        let kind = if node.kind() == "lambda_expression" {
            CallableReferenceKind::Lambda
        } else {
            CallableReferenceKind::UnboundMethod
        };
        let callable = CallableValue {
            kind,
            targets: resolution,
            target_evidence: metadata.evidence,
            bound_receiver: None,
            environment: None,
        };
        let effect = if node.kind() == "lambda_expression" {
            SemanticEffect::CallableCreation { result, callable }
        } else {
            SemanticEffect::CallableReference { result, callable }
        };
        self.append_effect(builder, entry, effect)?;
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

    fn method_reference(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), JavaLoweringError> {
        let reference = self.point(builder, node, Vec::new())?;
        let constructor_reference = has_child_kind(node, "new");
        let qualifier = (!constructor_reference)
            .then(|| method_reference_qualifier(node))
            .flatten();
        let result = self.value(builder, reference, SemanticValueKind::Callable)?;
        let receiver = qualifier
            .map(|_| self.value(builder, reference, SemanticValueKind::Receiver))
            .transpose()?;
        let metadata = self.metadata(reference)?;
        self.append_effect(
            builder,
            reference,
            SemanticEffect::CallableReference {
                result,
                callable: CallableValue {
                    kind: if constructor_reference {
                        CallableReferenceKind::Constructor
                    } else if receiver.is_some() {
                        CallableReferenceKind::BoundMethod
                    } else {
                        CallableReferenceKind::UnboundMethod
                    },
                    targets: CallableTargetResolution::Unknown,
                    target_evidence: metadata.evidence,
                    bound_receiver: receiver,
                    environment: None,
                },
            },
        )?;
        self.add_gap(
            builder,
            reference,
            SemanticGapSubject::Value(result),
            SemanticCapability::CallableReferences,
            SemanticGapKind::Unknown,
            "method-reference target and receiver binding require dispatch refinement",
        )?;
        if qualifier.is_some() {
            self.add_gap(
                builder,
                reference,
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unsupported,
                "bound method-reference creation can fail its implicit receiver null check",
            )?;
        }
        self.edge(builder, reference, next)?;

        if let Some(qualifier) = qualifier {
            stack.push(Work::Expression {
                node: qualifier,
                entry,
                next: EdgeTarget::normal(reference),
                scope,
            });
        } else {
            self.edge(builder, entry, EdgeTarget::normal(reference))?;
        }
        Ok(())
    }

    fn implicit_exception_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        node: Node<'tree>,
    ) -> Result<(), JavaLoweringError> {
        let detail = match node.kind() {
            "field_access" | "array_access" => {
                "implicit null, bounds, or initialization exceptions are not yet lowered"
            }
            _ => "implicit exceptions from runtime operators are not yet lowered",
        };
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            detail,
        )
    }

    fn unhandled_control_syntax(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
    ) -> Result<(), JavaLoweringError> {
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
    ) -> Result<(), JavaLoweringError> {
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
    ) -> Result<(), JavaLoweringError> {
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
    ) -> Result<(), JavaLoweringError> {
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
            return Err(JavaLoweringError::Invalid(format!(
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
    ) -> Result<(), JavaLoweringError> {
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
                .ok_or_else(|| JavaLoweringError::Invalid("missing cleanup region".into()))?;
            let metadata = self.mapping(builder, region.body.source_node())?;
            let (entry, created) =
                builder.cleanup_specialization(route, index, metadata.source, metadata.evidence)?;
            if created {
                if entry.index() != self.point_metadata.len() {
                    return Err(JavaLoweringError::Invalid(
                        "cleanup specialization broke dense point allocation".into(),
                    ));
                }
                self.point_metadata.push(metadata);
                match region.body {
                    CleanupBody::Statement(body) => {
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
                    CleanupBody::OpaqueResource(_) => {
                        self.add_gap(
                            builder,
                            entry,
                            SemanticGapSubject::Point,
                            SemanticCapability::ResourceManagement,
                            SemanticGapKind::Unsupported,
                            "resource close order, suppression, and value effects are not yet lowered",
                        )?;
                        self.add_gap(
                            builder,
                            entry,
                            SemanticGapSubject::Point,
                            SemanticCapability::ExceptionalControlFlow,
                            SemanticGapKind::Unsupported,
                            "resource close can raise or suppress exceptions not yet represented",
                        )?;
                        self.edge(builder, entry, next)?;
                    }
                    CleanupBody::OpaqueMonitor(_) => {
                        self.add_gap(
                            builder,
                            entry,
                            SemanticGapSubject::Point,
                            SemanticCapability::CleanupControlFlow,
                            SemanticGapKind::Unsupported,
                            "monitor release effects are represented only as an opaque cleanup boundary",
                        )?;
                        self.add_gap(
                            builder,
                            entry,
                            SemanticGapSubject::Point,
                            SemanticCapability::ExceptionalControlFlow,
                            SemanticGapKind::Unsupported,
                            "monitor release failure behavior is not yet represented",
                        )?;
                        self.edge(builder, entry, next)?;
                    }
                }
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
    ) -> Result<(), JavaLoweringError> {
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
    ) -> Result<ProgramPointId, JavaLoweringError> {
        let metadata = self.mapping(builder, node)?;
        let events = effects
            .into_iter()
            .map(|effect| SemanticEvent::new(effect, metadata.source, metadata.evidence))
            .collect();
        let point = builder.add_point(events, metadata.source, metadata.evidence)?;
        if point.index() != self.point_metadata.len() {
            return Err(JavaLoweringError::Invalid(
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
    ) -> Result<PointMetadata, JavaLoweringError> {
        let range = node.byte_range();
        let occurrence = self
            .source_occurrences
            .entry((range.start, range.end))
            .or_default();
        let anchor = source_anchor(node, *occurrence).map_err(JavaLoweringError::Invalid)?;
        *occurrence += 1;
        let source = SourceMappingId::new(
            u32::try_from(self.next_source)
                .map_err(|_| JavaLoweringError::Invalid("too many source mappings".into()))?,
        );
        let evidence = EvidenceId::new(
            u32::try_from(self.next_evidence)
                .map_err(|_| JavaLoweringError::Invalid("too many evidence rows".into()))?,
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

    fn metadata(&self, point: ProgramPointId) -> Result<PointMetadata, JavaLoweringError> {
        self.point_metadata
            .get(point.index())
            .copied()
            .ok_or_else(|| {
                JavaLoweringError::Invalid(format!("missing metadata for program point {point}"))
            })
    }

    fn value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        kind: SemanticValueKind,
    ) -> Result<ValueId, JavaLoweringError> {
        let metadata = self.metadata(point)?;
        let id = ValueId::new(
            u32::try_from(self.next_value)
                .map_err(|_| JavaLoweringError::Invalid("too many semantic values".into()))?,
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
    ) -> Result<(), JavaLoweringError> {
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
    ) -> Result<(), JavaLoweringError> {
        let metadata = self.metadata(point)?;
        let id = SemanticGapId::new(
            u32::try_from(self.next_gap)
                .map_err(|_| JavaLoweringError::Invalid("too many semantic gaps".into()))?,
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
    ) -> Result<(), JavaLoweringError> {
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

fn java_switch_arms(body: Node<'_>) -> Vec<JavaSwitchArm<'_>> {
    named_children(body)
        .into_iter()
        .filter_map(|node| {
            let kind = match node.kind() {
                "switch_block_statement_group" => JavaSwitchArmKind::Group,
                "switch_rule" => JavaSwitchArmKind::Rule,
                _ => return None,
            };
            let children = named_children(node);
            let labels = children
                .iter()
                .copied()
                .filter(|child| child.kind() == "switch_label")
                .collect::<Vec<_>>();
            let body = children
                .into_iter()
                .filter(|child| child.kind() != "switch_label")
                .collect::<Vec<_>>();
            Some(JavaSwitchArm {
                node,
                labels,
                body,
                kind,
            })
        })
        .collect()
}

fn switch_label_is_default(label: Node<'_>) -> bool {
    let mut cursor = label.walk();
    label
        .children(&mut cursor)
        .any(|child| child.kind() == "default")
}

fn switch_label_has_pattern(label: Node<'_>) -> bool {
    named_children(label)
        .into_iter()
        .any(|child| child.kind() == "pattern" || child.kind().ends_with("_pattern"))
}

fn switch_label_guard(label: Node<'_>) -> Option<Node<'_>> {
    named_children(label)
        .into_iter()
        .find(|child| child.kind() == "guard")
        .and_then(first_named_child)
}

fn object_creation_qualifier(node: Node<'_>) -> Option<Node<'_>> {
    let type_node = node.child_by_field_name("type");
    let arguments = node.child_by_field_name("arguments");
    named_children(node).into_iter().find(|child| {
        type_node.is_none_or(|candidate| candidate.id() != child.id())
            && arguments.is_none_or(|candidate| candidate.id() != child.id())
            && child.kind() != "class_body"
            && !is_annotation_kind(child.kind())
            && !is_type_syntax(child.kind())
    })
}

fn method_reference_qualifier(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    let separator = node
        .children(&mut cursor)
        .find(|child| child.kind() == "::")?;
    named_children(node).into_iter().rfind(|child| {
        child.end_byte() <= separator.start_byte()
            && !is_type_syntax(child.kind())
            && child.kind() != "type_arguments"
            && !is_annotation_kind(child.kind())
    })
}

fn has_child_kind(node: Node<'_>, kind: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor).any(|child| child.kind() == kind)
}

fn runtime_expression_children(node: Node<'_>) -> Vec<Node<'_>> {
    let fields: &[&str] = match node.kind() {
        "field_access" => &["object"],
        "array_access" => &["array", "index"],
        "assignment_expression" | "binary_expression" => &["left", "right"],
        "unary_expression" => &["operand"],
        "cast_expression" => &["value"],
        "instanceof_expression" => &["left"],
        "array_creation_expression" => &["dimensions", "value"],
        _ => &[],
    };
    if !fields.is_empty() {
        let mut result = Vec::new();
        for field in fields {
            for child in children_by_field_name(node, field) {
                if is_type_syntax(child.kind()) || is_annotation_kind(child.kind()) {
                    continue;
                }
                if !result
                    .iter()
                    .any(|existing: &Node<'_>| existing.id() == child.id())
                {
                    result.push(child);
                }
            }
        }
        result.sort_by_key(Node::start_byte);
        return result;
    }

    named_children(node)
        .into_iter()
        .filter(|child| {
            !is_type_syntax(child.kind())
                && !is_annotation_kind(child.kind())
                && !matches!(child.kind(), "modifiers" | "class_body")
        })
        .collect()
}

fn first_runtime_named_child(node: Node<'_>) -> Option<Node<'_>> {
    named_children(node).into_iter().find(|child| {
        !is_type_syntax(child.kind())
            && !is_annotation_kind(child.kind())
            && child.kind() != "modifiers"
    })
}

fn is_type_syntax(kind: &str) -> bool {
    matches!(
        kind,
        "type_identifier"
            | "scoped_type_identifier"
            | "generic_type"
            | "array_type"
            | "integral_type"
            | "floating_point_type"
            | "boolean_type"
            | "void_type"
            | "wildcard"
            | "type_arguments"
            | "type_parameters"
            | "annotated_type"
            | "dimensions"
    )
}

fn is_annotation_kind(kind: &str) -> bool {
    matches!(kind, "annotation" | "marker_annotation")
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
    matches!(kind, "line_comment" | "block_comment" | "comment")
}

fn required_field<'tree>(node: Node<'tree>, field: &str) -> Result<Node<'tree>, JavaLoweringError> {
    node.child_by_field_name(field)
        .ok_or_else(|| missing_field(node, field))
}

fn missing_field(node: Node<'_>, field: &str) -> JavaLoweringError {
    JavaLoweringError::Invalid(format!(
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

fn binary_operator(node: Node<'_>) -> Option<&'static str> {
    match node.child_by_field_name("operator")?.kind() {
        "&&" => Some("&&"),
        "||" => Some("||"),
        _ => None,
    }
}

fn operation_can_throw_implicitly(node: Node<'_>) -> bool {
    match node.kind() {
        "unary_expression"
        | "update_expression"
        | "binary_expression"
        | "cast_expression"
        | "template_expression" => true,
        "assignment_expression" => node
            .child_by_field_name("left")
            .is_some_and(|left| matches!(left.kind(), "field_access" | "array_access")),
        "array_creation_expression" => true,
        _ => false,
    }
}

fn is_runtime_leaf(kind: &str) -> bool {
    matches!(
        kind,
        "identifier"
            | "decimal_integer_literal"
            | "hex_integer_literal"
            | "octal_integer_literal"
            | "binary_integer_literal"
            | "decimal_floating_point_literal"
            | "hex_floating_point_literal"
            | "character_literal"
            | "string_literal"
            | "null_literal"
            | "true"
            | "false"
            | "this"
            | "super"
            | "class_literal"
            | "comment"
            | "line_comment"
            | "block_comment"
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
