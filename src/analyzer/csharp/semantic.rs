//! CSharp lowering into the language-neutral executable-semantics IR.
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
use crate::analyzer::{CSharpAnalyzer, ProjectFile};
use crate::hash::HashMap;

const ADAPTER_VERSION: &[u8] = b"csharp-cfg-v1";

impl ProgramSemanticsProvider for CSharpAnalyzer {
    fn materialize(
        &self,
        file: &ProjectFile,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError> {
        self.inner
            .materialize_semantics_with_lowerer(&CSharpSemanticLowerer, file, request)
    }
}

struct CSharpSemanticLowerer;

impl ProgramSemanticsLowerer for CSharpSemanticLowerer {
    fn identity(&self) -> SemanticAdapterIdentity {
        SemanticAdapterIdentity {
            adapter: AdapterSemanticsVersion::hash_bytes("csharp", ADAPTER_VERSION)
                .expect("adapter name is non-empty"),
            configuration: ConfigurationFingerprint::hash_bytes(
                b"csharp-intrafile-execution-defaults-v1",
            ),
            dependencies: DependencyFingerprint::hash_bytes(b"no-intrafile-dependencies"),
        }
    }

    fn capabilities(&self) -> SemanticCapabilities {
        csharp_capabilities()
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
                Err(CSharpLoweringError::Cancelled(work)) => {
                    return Ok(SemanticOutcome::Cancelled {
                        partial: None,
                        work: sum_work(observed, *work),
                    });
                }
                Err(CSharpLoweringError::Budget(exceeded, work)) => {
                    let work = sum_work(observed, *work);
                    let exceeded = budget.check(work).err().unwrap_or(exceeded);
                    return Ok(SemanticOutcome::ExceededBudget {
                        partial: None,
                        exceeded,
                        work,
                    });
                }
                Err(CSharpLoweringError::Invalid(detail)) => {
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

fn csharp_capabilities() -> SemanticCapabilities {
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
        SemanticCapability::CallableReferences,
        SemanticCapability::Values,
        SemanticCapability::NonLocalControl,
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
    body: Node<'tree>,
    locator: SemanticLocator,
    lexical_parent: Option<ProcedureId>,
    kind: ProcedureKind,
    properties: ProcedureProperties,
    callable: Node<'tree>,
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
        .unwrap_or("csharp-source");
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
    let root_path = file_scoped_namespace_path(prepared.source(), root, &mut declaration_paths)
        .map_err(SemanticProviderError::invalid_identity)?;
    let mut stack = vec![ProcedureEnumerationFrame {
        node: root,
        lexical_parent: None,
        declaration_path: root_path,
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
        if let Some((kind, segment_kind, body, properties)) =
            callable_shape(prepared.source(), frame.node)
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
                callable: frame.node,
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

fn file_scoped_namespace_path(
    source: &str,
    root: Node<'_>,
    declaration_paths: &mut Vec<DeclarationPathEntry>,
) -> Result<usize, String> {
    let Some(namespace) = named_children(root)
        .into_iter()
        .find(|child| child.kind() == "file_scoped_namespace_declaration")
    else {
        return Ok(0);
    };
    let name = declaration_container_name(source, namespace);
    let anchor = source_anchor(namespace, 0)?;
    let segment = declaration_segment(
        DeclarationSegmentKind::Namespace,
        name.as_deref(),
        anchor,
        0,
    )?;
    Ok(push_declaration_path(declaration_paths, 0, segment))
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
        "namespace_declaration" => Some(DeclarationSegmentKind::Namespace),
        "class_declaration"
        | "interface_declaration"
        | "struct_declaration"
        | "enum_declaration"
        | "record_declaration"
        | "record_struct_declaration" => Some(DeclarationSegmentKind::Type),
        _ => None,
    }
}

fn declaration_container_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    node.child_by_field_name("name")
        .and_then(|name| nonempty_node_text(source, name))
        .map(Box::<str>::from)
}

fn callable_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    if node.kind() == "constructor_declaration" && has_modifier(source, node, "static") {
        return Some(Box::<str>::from("<static-constructor>"));
    }
    if node.kind() == "destructor_declaration" {
        return node
            .child_by_field_name("name")
            .and_then(|name| nonempty_node_text(source, name))
            .map(|name| format!("~{name}").into_boxed_str());
    }
    if node.kind() == "accessor_declaration" {
        let accessor = node
            .child_by_field_name("name")
            .and_then(|name| nonempty_node_text(source, name))?;
        let owner = enclosing_accessor_owner(node)
            .and_then(|owner| accessor_owner_name(source, owner))
            .unwrap_or_else(|| Box::<str>::from("<accessor>"));
        return Some(format!("{owner}.{accessor}").into_boxed_str());
    }
    if matches!(node.kind(), "property_declaration" | "indexer_declaration") {
        return accessor_owner_name(source, node)
            .map(|owner| format!("{owner}.get").into_boxed_str());
    }
    if node.kind() == "operator_declaration" {
        return node
            .child_by_field_name("operator")
            .and_then(|operator| nonempty_node_text(source, operator))
            .map(|operator| format!("operator {operator}").into_boxed_str());
    }
    if node.kind() == "conversion_operator_declaration" {
        let target = node
            .child_by_field_name("type")
            .and_then(|ty| nonempty_node_text(source, ty))?;
        let flavor = if has_direct_token(node, "implicit") {
            "implicit"
        } else {
            "explicit"
        };
        return Some(format!("{flavor} operator {target}").into_boxed_str());
    }
    node.child_by_field_name("name")
        .and_then(|name| nonempty_node_text(source, name))
        .map(Box::<str>::from)
        .or_else(|| enclosing_variable_name(source, node))
}

fn enclosing_accessor_owner(node: Node<'_>) -> Option<Node<'_>> {
    let list = node.parent()?;
    (list.kind() == "accessor_list")
        .then(|| list.parent())
        .flatten()
}

fn accessor_owner_name(source: &str, owner: Node<'_>) -> Option<Box<str>> {
    match owner.kind() {
        "indexer_declaration" => Some(Box::<str>::from("this")),
        "property_declaration" | "event_declaration" => owner
            .child_by_field_name("name")
            .and_then(|name| nonempty_node_text(source, name))
            .map(Box::<str>::from),
        _ => None,
    }
}

fn enclosing_variable_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    let mut value = node;
    loop {
        let parent = value.parent()?;
        match parent.kind() {
            "parenthesized_expression" => value = parent,
            "variable_declarator" => {
                return parent
                    .child_by_field_name("name")
                    .and_then(|name| nonempty_node_text(source, name))
                    .map(Box::<str>::from);
            }
            "assignment_expression" if field_matches(parent, "right", value) => {
                return parent
                    .child_by_field_name("left")
                    .and_then(|left| nonempty_node_text(source, left))
                    .map(Box::<str>::from);
            }
            _ => return None,
        }
    }
}

fn callable_shape<'tree>(
    source: &str,
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
            callable_body(node)?,
            has_modifier(source, node, "static"),
        ),
        "constructor_declaration" if has_modifier(source, node, "static") => (
            ProcedureKind::Initializer,
            DeclarationSegmentKind::Initializer,
            callable_body(node)?,
            true,
        ),
        "constructor_declaration" => (
            ProcedureKind::Constructor,
            DeclarationSegmentKind::Constructor,
            callable_body(node)?,
            false,
        ),
        "local_function_statement" => (
            ProcedureKind::LocalFunction,
            DeclarationSegmentKind::LocalFunction,
            callable_body(node)?,
            has_modifier(source, node, "static"),
        ),
        "lambda_expression" => (
            ProcedureKind::Lambda,
            DeclarationSegmentKind::Lambda,
            callable_body(node)?,
            has_modifier(source, node, "static"),
        ),
        "anonymous_method_expression" => (
            ProcedureKind::Lambda,
            DeclarationSegmentKind::AnonymousCallable,
            named_children(node)
                .into_iter()
                .find(|child| child.kind() == "block")?,
            has_modifier(source, node, "static"),
        ),
        "accessor_declaration" => (
            ProcedureKind::Accessor,
            DeclarationSegmentKind::Method,
            callable_body(node)?,
            enclosing_accessor_owner(node)
                .is_some_and(|owner| has_modifier(source, owner, "static")),
        ),
        "property_declaration" | "indexer_declaration"
            if node
                .child_by_field_name("value")
                .is_some_and(|value| value.kind() == "arrow_expression_clause") =>
        {
            (
                ProcedureKind::Accessor,
                DeclarationSegmentKind::Method,
                first_named_child(node.child_by_field_name("value")?)?,
                has_modifier(source, node, "static"),
            )
        }
        "operator_declaration" | "conversion_operator_declaration" => (
            ProcedureKind::Operator,
            DeclarationSegmentKind::Method,
            callable_body(node)?,
            true,
        ),
        "destructor_declaration" => (
            ProcedureKind::Method,
            DeclarationSegmentKind::Method,
            callable_body(node)?,
            false,
        ),
        _ => return None,
    };
    Some((
        kind,
        segment_kind,
        body,
        ProcedureProperties {
            is_async: has_modifier(source, node, "async"),
            is_generator: body_contains_yield(body),
            is_static,
            is_synthetic: false,
        },
    ))
}

fn callable_body(node: Node<'_>) -> Option<Node<'_>> {
    let body = node.child_by_field_name("body")?;
    if body.kind() == "arrow_expression_clause" {
        first_named_child(body)
    } else {
        Some(body)
    }
}

fn has_modifier(source: &str, node: Node<'_>, modifier: &str) -> bool {
    named_children(node).into_iter().any(|child| {
        child.kind() == "modifier" && node_text(source, child).is_some_and(|text| text == modifier)
    })
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
        if node.kind() == "yield_statement" {
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

fn nonempty_node_text<'source>(source: &'source str, node: Node<'_>) -> Option<&'source str> {
    node_text(source, node).filter(|text| !text.is_empty())
}

#[derive(Debug)]
enum CSharpLoweringError {
    Cancelled(Box<SemanticWork>),
    Budget(SemanticBudgetExceeded, Box<SemanticWork>),
    Invalid(String),
}

impl From<SemanticBudgetExceeded> for CSharpLoweringError {
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
    OpaqueFixed(Node<'tree>),
    OpaqueMonitor(Node<'tree>),
}

impl<'tree> CleanupBody<'tree> {
    const fn source_node(self) -> Node<'tree> {
        match self {
            Self::Statement(node)
            | Self::OpaqueResource(node)
            | Self::OpaqueFixed(node)
            | Self::OpaqueMonitor(node) => node,
        }
    }
}

struct LoweringContext<'tree, 'targets> {
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
) -> Result<(ProcedureSemanticsParts, SemanticWork), CSharpLoweringError> {
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
    if spec.callable.kind() == "destructor_declaration" {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::DeferredExecution,
            SemanticGapKind::Unsupported,
            "finalizer scheduling and nondeterministic execution are not modeled",
        )?;
    }
    if spec.properties.is_async {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::AsyncSuspendResume,
            SemanticGapKind::Unsupported,
            "async method task construction, scheduling, and synchronization context are not fully modeled",
        )?;
    }
    if spec.properties.is_generator {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::GeneratorSuspension,
            SemanticGapKind::Unsupported,
            "iterator state-machine construction and suspension are not fully modeled",
        )?;
    }

    let constructor_initializer = (spec.kind == ProcedureKind::Constructor)
        .then(|| {
            named_children(spec.callable)
                .into_iter()
                .find(|child| child.kind() == "constructor_initializer")
        })
        .flatten();
    if spec.kind == ProcedureKind::Constructor && constructor_initializer.is_none() {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unsupported,
            "implicit base-constructor invocation is not represented as a call site",
        )?;
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            "implicit base-constructor invocation can complete exceptionally",
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
    if let Some(initializer) = constructor_initializer {
        let initializer_entry = context.point(&mut builder, initializer, Vec::new())?;
        context.edge(&mut builder, entry, EdgeTarget::normal(initializer_entry))?;
        pending.push(Work::Expression {
            node: initializer,
            entry: initializer_entry,
            next: EdgeTarget::normal(body_entry),
            scope: function_scope,
        });
    } else {
        context.edge(&mut builder, entry, EdgeTarget::normal(body_entry))?;
    }

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
            DriveError::Cancelled | DriveError::Step(CSharpLoweringError::Cancelled(_)) => {
                Err(CSharpLoweringError::Cancelled(Box::new(work)))
            }
            DriveError::ExceededBudget(exceeded) => {
                Err(CSharpLoweringError::Budget(exceeded, Box::new(work)))
            }
            DriveError::Step(CSharpLoweringError::Budget(exceeded, _)) => {
                Err(CSharpLoweringError::Budget(exceeded, Box::new(work)))
            }
            DriveError::Step(CSharpLoweringError::Invalid(detail)) => {
                Err(CSharpLoweringError::Invalid(detail))
            }
        };
    }

    if builder
        .seal_unreachable_regions(entry, normal_exit, exceptional_exit, cancellation)
        .is_err()
    {
        return Err(CSharpLoweringError::Cancelled(Box::new(
            builder.prospective_work(),
        )));
    }
    let work_before_freeze = builder.prospective_work();
    builder
        .finish_with_work()
        .map_err(|error| CSharpLoweringError::Budget(error, Box::new(work_before_freeze)))
}

fn callable_returns_value(source: &str, spec: &ProcedureSpec<'_>) -> bool {
    match spec.kind {
        ProcedureKind::Constructor | ProcedureKind::Initializer => false,
        ProcedureKind::Accessor => {
            if spec.callable.kind() != "accessor_declaration" {
                return true;
            }
            spec.callable
                .child_by_field_name("name")
                .and_then(|name| node_text(source, name))
                .is_some_and(|name| name == "get")
        }
        ProcedureKind::Method if spec.callable.kind() == "destructor_declaration" => false,
        ProcedureKind::Method | ProcedureKind::LocalFunction => {
            let returns = spec
                .callable
                .child_by_field_name("returns")
                .or_else(|| spec.callable.child_by_field_name("type"));
            returns
                .and_then(|returns| node_text(source, returns))
                .is_none_or(|returns| returns.trim() != "void")
        }
        ProcedureKind::Function
        | ProcedureKind::Lambda
        | ProcedureKind::Closure
        | ProcedureKind::Operator => true,
    }
}

impl<'tree, 'targets> LoweringContext<'tree, 'targets> {
    fn step(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        work: Work<'tree>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        if self.cancellation.is_cancelled() {
            return Err(CSharpLoweringError::Cancelled(Box::default()));
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
    ) -> Result<(), CSharpLoweringError> {
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
            ("binary_expression", Some("??")) => {
                let left = required_field(node, "left")?;
                let right = required_field(node, "right")?;
                let right_entry = self.point(builder, right, Vec::new())?;
                let left_result = self.point(builder, left, Vec::new())?;
                self.edge(builder, left_result, when_true)?;
                self.edge(builder, left_result, when_false)?;
                stack.push(Work::Condition {
                    node: right,
                    entry: right_entry,
                    when_true,
                    when_false,
                    scope,
                });
                let null_test = self.point(builder, left, Vec::new())?;
                self.edge(
                    builder,
                    null_test,
                    EdgeTarget {
                        point: left_result,
                        kind: ControlEdgeKind::ConditionalTrue,
                    },
                )?;
                self.edge(
                    builder,
                    null_test,
                    EdgeTarget {
                        point: right_entry,
                        kind: ControlEdgeKind::ConditionalFalse,
                    },
                )?;
                stack.push(Work::Expression {
                    node: left,
                    entry,
                    next: EdgeTarget::normal(null_test),
                    scope,
                });
                Ok(())
            }
            ("conditional_expression", _) => {
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
        _attached_label: Option<&'tree str>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        match node.kind() {
            "block" | "compilation_unit" => {
                let children = named_children(node)
                    .into_iter()
                    .filter(|child| is_statement_kind(child.kind()))
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
                let value_node = first_named_child(node);
                let terminal = if value_node.is_some() {
                    self.point(builder, node, Vec::new())?
                } else {
                    entry
                };
                let value = value_node
                    .map(|_| self.value(builder, terminal, SemanticValueKind::Exception))
                    .transpose()?;
                self.append_effect(builder, terminal, SemanticEffect::Throw { value })?;
                if let Some(value_node) = value_node {
                    stack.push(Work::Expression {
                        node: value_node,
                        entry,
                        next: EdgeTarget::normal(terminal),
                        scope,
                    });
                }
                self.abrupt(builder, terminal, scope, CompletionKind::Throw, None, stack)
            }
            "yield_statement" => {
                let value_node = first_named_child(node);
                let terminal = if value_node.is_some() {
                    self.point(builder, node, Vec::new())?
                } else {
                    entry
                };
                self.add_gap(
                    builder,
                    terminal,
                    SemanticGapSubject::Point,
                    SemanticCapability::GeneratorSuspension,
                    SemanticGapKind::Unsupported,
                    "yield suspension and resumption are not lowered",
                )?;
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
            "break_statement" | "continue_statement" => {
                let kind = if node.kind() == "break_statement" {
                    CompletionKind::Break
                } else {
                    CompletionKind::Continue
                };
                self.abrupt(builder, entry, scope, kind, None, stack)
            }
            "goto_statement" => self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::NonLocalControl,
                SemanticGapKind::Unsupported,
                "goto target resolution, including goto case/default, is not lowered",
            ),
            "labeled_statement" => {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::NonLocalControl,
                    SemanticGapKind::Unsupported,
                    "incoming goto edges to this label are not lowered",
                )?;
                let body = named_children(node)
                    .into_iter()
                    .find(|child| child.kind() != "identifier")
                    .ok_or_else(|| missing_field(node, "body"))?;
                stack.push(Work::Statement {
                    node: body,
                    entry,
                    next,
                    scope,
                });
                Ok(())
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
                let condition_entry = self.point(builder, condition, Vec::new())?;
                let body_entry = self.point(builder, body, Vec::new())?;
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
                        point: next.point,
                        kind: ControlEdgeKind::ConditionalFalse,
                    },
                    scope: loop_scope,
                });
                self.edge(builder, entry, EdgeTarget::normal(condition_entry))
            }
            "do_statement" => {
                let body = required_field(node, "body")?;
                let condition = required_field(node, "condition")?;
                let condition_entry = self.point(builder, condition, Vec::new())?;
                let loop_scope = builder.push_scope(
                    Some(scope),
                    ScopeBinding::Loop {
                        label: None,
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
            "for_statement" => self.for_statement(builder, node, entry, next, scope, None, stack),
            "foreach_statement" => self.foreach_statement(builder, node, entry, next, scope, stack),
            "switch_statement" => self.switch_statement(builder, node, entry, next, scope, stack),
            "try_statement" => self.try_statement(builder, node, entry, next, scope, stack),
            "using_statement" => self.using_statement(builder, node, entry, next, scope, stack),
            "lock_statement" => self.lock_statement(builder, node, entry, next, scope, stack),
            "fixed_statement" => self.fixed_statement(builder, node, entry, next, scope, stack),
            "checked_statement" | "unsafe_statement" => {
                if node.kind() == "checked_statement" {
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::ExceptionalControlFlow,
                        SemanticGapKind::Unsupported,
                        "checked overflow exceptions from enclosed operators are not fully lowered",
                    )?;
                }
                let body = first_named_child(node).ok_or_else(|| missing_field(node, "body"))?;
                stack.push(Work::Statement {
                    node: body,
                    entry,
                    next,
                    scope,
                });
                Ok(())
            }
            kind if is_conditional_compilation_kind(kind) => {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::NormalControlFlow,
                    SemanticGapKind::Unsupported,
                    "conditional-compilation branch selection depends on an unavailable preprocessor configuration",
                )
            }
            "local_declaration_statement" => {
                let declaration = named_children(node)
                    .into_iter()
                    .find(|child| child.kind() == "variable_declaration")
                    .ok_or_else(|| missing_field(node, "declaration"))?;
                if has_direct_token(node, "using") {
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::ResourceManagement,
                        SemanticGapKind::Unsupported,
                        "using-declaration disposal at the enclosing scope boundary is not lowered",
                    )?;
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::CleanupControlFlow,
                        SemanticGapKind::Unsupported,
                        "using-declaration return and exception cleanup routes are not lowered",
                    )?;
                    if has_direct_token(node, "await") {
                        self.add_gap(
                            builder,
                            entry,
                            SemanticGapSubject::Point,
                            SemanticCapability::AsyncSuspendResume,
                            SemanticGapKind::Unsupported,
                            "await using disposal suspension is not lowered",
                        )?;
                    }
                }
                let initializers = variable_initializers(declaration);
                self.schedule_expressions(builder, entry, &initializers, next, scope, stack)
            }
            "empty_statement"
            | "local_function_statement"
            | "method_declaration"
            | "constructor_declaration"
            | "destructor_declaration"
            | "operator_declaration"
            | "conversion_operator_declaration"
            | "property_declaration"
            | "indexer_declaration"
            | "event_declaration"
            | "accessor_declaration"
            | "class_declaration"
            | "interface_declaration"
            | "struct_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "record_struct_declaration" => self.edge(builder, entry, next),
            _ => self.unhandled_control_syntax(builder, node, entry, next),
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
    ) -> Result<(), CSharpLoweringError> {
        match node.kind() {
            "invocation_expression"
            | "object_creation_expression"
            | "implicit_object_creation_expression"
            | "constructor_initializer" => {
                self.call_expression(builder, node, entry, next, scope, stack)
            }
            "switch_expression" => self.switch_expression(builder, node, entry, next, scope, stack),
            "lambda_expression" | "anonymous_method_expression" => {
                self.callable_expression(builder, node, entry, next)
            }
            "conditional_expression" => {
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
            "binary_expression" if matches!(binary_operator(node), Some("&&" | "||" | "??")) => {
                let left = required_field(node, "left")?;
                let right = required_field(node, "right")?;
                let right_entry = self.point(builder, right, Vec::new())?;
                stack.push(Work::Expression {
                    node: right,
                    entry: right_entry,
                    next,
                    scope,
                });
                let (when_true, when_false) = match binary_operator(node) {
                    Some("&&") => (
                        EdgeTarget {
                            point: right_entry,
                            kind: ControlEdgeKind::ConditionalTrue,
                        },
                        EdgeTarget {
                            point: next.point,
                            kind: ControlEdgeKind::ConditionalFalse,
                        },
                    ),
                    Some("||" | "??") => (
                        EdgeTarget {
                            point: next.point,
                            kind: ControlEdgeKind::ConditionalTrue,
                        },
                        EdgeTarget {
                            point: right_entry,
                            kind: ControlEdgeKind::ConditionalFalse,
                        },
                    ),
                    _ => unreachable!("guarded by short-circuit operator"),
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
            "assignment_expression"
                if node
                    .child_by_field_name("operator")
                    .is_some_and(|operator| operator.kind() == "??=") =>
            {
                let left = required_field(node, "left")?;
                let right = required_field(node, "right")?;
                let right_entry = self.point(builder, right, Vec::new())?;
                stack.push(Work::Expression {
                    node: right,
                    entry: right_entry,
                    next,
                    scope,
                });
                stack.push(Work::Condition {
                    node: left,
                    entry,
                    when_true: EdgeTarget {
                        point: next.point,
                        kind: ControlEdgeKind::ConditionalTrue,
                    },
                    when_false: EdgeTarget {
                        point: right_entry,
                        kind: ControlEdgeKind::ConditionalFalse,
                    },
                    scope,
                });
                Ok(())
            }
            "await_expression" => self.await_expression(builder, node, entry, next, scope, stack),
            "throw_expression" => {
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
            "conditional_access_expression" => {
                let condition = required_field(node, "condition")?;
                let binding = named_children(node)
                    .into_iter()
                    .find(|child| child.id() != condition.id())
                    .ok_or_else(|| missing_field(node, "binding"))?;
                let binding_entry = self.point(builder, binding, Vec::new())?;
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::NormalControlFlow,
                    SemanticGapKind::Unsupported,
                    "conditional-access value propagation is represented only by its control split",
                )?;
                stack.push(Work::Expression {
                    node: binding,
                    entry: binding_entry,
                    next,
                    scope,
                });
                stack.push(Work::Condition {
                    node: condition,
                    entry,
                    when_true: EdgeTarget {
                        point: binding_entry,
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
            "parenthesized_expression"
            | "checked_expression"
            | "ref_expression"
            | "makeref_expression"
            | "reftype_expression"
            | "refvalue_expression" => {
                if node.kind() == "checked_expression" {
                    self.implicit_exception_gap(builder, entry, node)?;
                }
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
            "member_access_expression"
            | "member_binding_expression"
            | "element_access_expression"
            | "element_binding_expression" => {
                self.implicit_exception_gap(builder, entry, node)?;
                let children = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            "interpolated_string_expression" | "interpolation" => {
                let values = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &values, next, scope, stack)
            }
            "query_expression" => {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::DeferredExecution,
                    SemanticGapKind::Unsupported,
                    "query-expression deferred iterator execution is not lowered",
                )?;
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::Calls,
                    SemanticGapKind::Unsupported,
                    "query-expression translation into method calls is not lowered",
                )?;
                let children = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            "assignment_expression"
            | "binary_expression"
            | "prefix_unary_expression"
            | "postfix_unary_expression"
            | "cast_expression"
            | "as_expression"
            | "is_expression"
            | "is_pattern_expression"
            | "array_creation_expression"
            | "implicit_array_creation_expression"
            | "anonymous_object_creation_expression"
            | "initializer_expression"
            | "collection_expression"
            | "with_expression"
            | "range_expression"
            | "stackalloc_expression"
            | "implicit_stackalloc_expression"
            | "tuple_expression"
            | "argument"
            | "argument_list"
            | "bracketed_argument_list"
            | "variable_declarator"
            | "variable_declaration"
            | "declaration_expression"
            | "default_expression"
            | "sizeof_expression"
            | "typeof_expression" => {
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
                        "property, indexer, conversion, or overloaded-operator invocation requires type refinement",
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
    fn for_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        label: Option<&'tree str>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        let body = required_field(node, "body")?;
        let initializers = children_by_field_name(node, "initializer");
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
                stack.push(Work::Expression {
                    node: initializers[index],
                    entry: init_entries[index],
                    next,
                    scope: loop_scope,
                });
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn foreach_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        let iterable = required_field(node, "right")?;
        let binding = required_field(node, "left")?;
        let body = required_field(node, "body")?;
        let test = self.point(builder, node, Vec::new())?;
        let binding_entry = self.point(builder, binding, Vec::new())?;
        let body_entry = self.point(builder, body, Vec::new())?;
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
            "implicit enumerator acquisition and MoveNext calls are not represented as call sites",
        )?;
        self.add_gap(
            builder,
            test,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            "implicit enumerator acquisition and advancement exceptions are not lowered",
        )?;
        self.add_gap(
            builder,
            test,
            SemanticGapSubject::Point,
            SemanticCapability::ResourceManagement,
            SemanticGapKind::Unsupported,
            "enumerator disposal and completion-sensitive cleanup are not lowered",
        )?;
        if has_direct_token(node, "await") {
            self.add_gap(
                builder,
                test,
                SemanticGapSubject::Point,
                SemanticCapability::AsyncSuspendResume,
                SemanticGapKind::Unsupported,
                "await foreach suspension and asynchronous disposal are not lowered",
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

    fn switch_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        let value = required_field(node, "value")?;
        let body = required_field(node, "body")?;
        let dispatch = self.point(builder, node, Vec::new())?;
        let sections = named_children(body)
            .into_iter()
            .filter(|child| child.kind() == "switch_section")
            .collect::<Vec<_>>();
        if sections.is_empty() {
            self.edge(builder, dispatch, next)?;
            stack.push(Work::Expression {
                node: value,
                entry,
                next: EdgeTarget::normal(dispatch),
                scope,
            });
            return Ok(());
        }

        let switch_scope = builder.push_scope(
            Some(scope),
            ScopeBinding::Breakable {
                label: None,
                break_target: next.point,
                break_edge_kind: next.kind,
            },
        );
        let entries = sections
            .iter()
            .map(|section| self.point(builder, *section, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        let mut has_default = false;
        for (index, section) in sections.iter().enumerate() {
            has_default |= has_direct_token(*section, "default");
            let control = switch_section_control_nodes(*section);
            if control
                .iter()
                .any(|child| matches!(child.kind(), "pattern" | "when_clause"))
            {
                self.add_gap(
                    builder,
                    entries[index],
                    SemanticGapSubject::Point,
                    SemanticCapability::NormalControlFlow,
                    SemanticGapKind::Unsupported,
                    "switch pattern and when-clause matching require type refinement",
                )?;
                self.add_gap(
                    builder,
                    entries[index],
                    SemanticGapSubject::Point,
                    SemanticCapability::ExceptionalControlFlow,
                    SemanticGapKind::Unsupported,
                    "switch when-clause evaluation failures are not lowered",
                )?;
            }
            self.edge(
                builder,
                dispatch,
                EdgeTarget {
                    point: entries[index],
                    kind: ControlEdgeKind::SwitchCase,
                },
            )?;
            let statements = switch_section_statements(*section);
            if statements.is_empty() {
                let target = entries
                    .get(index + 1)
                    .copied()
                    .map(EdgeTarget::normal)
                    .unwrap_or(next);
                self.edge(builder, entries[index], target)?;
            } else {
                self.schedule_statements(
                    builder,
                    entries[index],
                    &statements,
                    next,
                    switch_scope,
                    stack,
                )?;
            }
        }
        if !has_default {
            self.edge(
                builder,
                dispatch,
                EdgeTarget {
                    point: next.point,
                    kind: ControlEdgeKind::ConditionalFalse,
                },
            )?;
        }
        stack.push(Work::Expression {
            node: value,
            entry,
            next: EdgeTarget::normal(dispatch),
            scope: switch_scope,
        });
        Ok(())
    }

    fn switch_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        let children = named_children(node);
        let value = children
            .iter()
            .copied()
            .find(|child| child.kind() != "switch_expression_arm")
            .ok_or_else(|| missing_field(node, "value"))?;
        let arms = children
            .into_iter()
            .filter(|child| child.kind() == "switch_expression_arm")
            .collect::<Vec<_>>();
        let dispatch = self.point(builder, node, Vec::new())?;
        let merge = self.point(builder, node, Vec::new())?;
        self.edge(builder, merge, next)?;
        self.add_gap(
            builder,
            dispatch,
            SemanticGapSubject::Point,
            SemanticCapability::NormalControlFlow,
            SemanticGapKind::Unsupported,
            "switch-expression pattern and when-clause selection require type refinement",
        )?;
        self.add_gap(
            builder,
            dispatch,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            "non-exhaustive switch-expression failure and filter exceptions are only bounded here",
        )?;

        for arm in arms {
            let arm_entry = self.point(builder, arm, Vec::new())?;
            self.edge(
                builder,
                dispatch,
                EdgeTarget {
                    point: arm_entry,
                    kind: ControlEdgeKind::SwitchCase,
                },
            )?;
            let arm_value =
                switch_expression_arm_value(arm).ok_or_else(|| missing_field(arm, "value"))?;
            stack.push(Work::Expression {
                node: arm_value,
                entry: arm_entry,
                next: EdgeTarget::normal(merge),
                scope,
            });
        }
        let unmatched = self.point(builder, node, Vec::new())?;
        self.edge(
            builder,
            dispatch,
            EdgeTarget {
                point: unmatched,
                kind: ControlEdgeKind::Exceptional,
            },
        )?;
        self.abrupt(
            builder,
            unmatched,
            scope,
            CompletionKind::Throw,
            None,
            stack,
        )?;
        stack.push(Work::Expression {
            node: value,
            entry,
            next: EdgeTarget::normal(dispatch),
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
    ) -> Result<(), CSharpLoweringError> {
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
            let region =
                CleanupRegionId::new(u32::try_from(self.cleanups.len()).map_err(|_| {
                    CSharpLoweringError::Invalid("too many cleanup regions".into())
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

        for ((catch, catch_body), catch_entry) in
            catches.iter().zip(&catch_bodies).zip(&catch_entries)
        {
            if named_children(*catch)
                .into_iter()
                .any(|child| child.kind() == "catch_filter_clause")
            {
                self.add_gap(
                    builder,
                    *catch_entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::ExceptionalControlFlow,
                    SemanticGapKind::Unsupported,
                    "catch-filter evaluation, false routing, and filter-failure semantics are not lowered",
                )?;
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

        if let Some(route) = normal_route.as_ref() {
            let body_exit = self.point(builder, body, Vec::new())?;
            self.route(builder, body_exit, route, stack)?;
            stack.push(Work::Statement {
                node: body,
                entry,
                next: EdgeTarget::normal(body_exit),
                scope: try_scope,
            });
        } else {
            stack.push(Work::Statement {
                node: body,
                entry,
                next,
                scope: try_scope,
            });
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn lock_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        let children = named_children(node);
        let body = children
            .iter()
            .copied()
            .find(|child| is_statement_kind(child.kind()))
            .ok_or_else(|| missing_field(node, "body"))?;
        let lock = children
            .into_iter()
            .find(|child| child.id() != body.id())
            .ok_or_else(|| missing_field(node, "lock"))?;
        let monitor = self.point(builder, lock, Vec::new())?;
        let body_entry = self.point(builder, body, Vec::new())?;
        let region = CleanupRegionId::new(
            u32::try_from(self.cleanups.len())
                .map_err(|_| CSharpLoweringError::Invalid("too many cleanup regions".into()))?,
        );
        self.cleanups.push(CleanupRegion {
            id: region,
            body: CleanupBody::OpaqueMonitor(node),
            outer_scope: scope,
        });
        let lock_scope = builder.push_scope(Some(scope), ScopeBinding::Cleanup { region });
        self.add_gap(
            builder,
            monitor,
            SemanticGapSubject::Point,
            SemanticCapability::CleanupControlFlow,
            SemanticGapKind::Unsupported,
            "Monitor ownership and reentrancy effects are represented only as opaque boundaries",
        )?;
        self.add_gap(
            builder,
            monitor,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            "implicit Monitor.Enter acquisition exceptions are not lowered",
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
            scope: lock_scope,
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
    fn using_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        let body = required_field(node, "body")?;
        let resource = named_children(node)
            .into_iter()
            .find(|child| child.id() != body.id())
            .ok_or_else(|| missing_field(node, "resource"))?;
        let boundary = self.opaque_resource_statement(
            builder,
            node,
            resource,
            body,
            entry,
            next,
            scope,
            CleanupBody::OpaqueResource(node),
            stack,
        )?;
        if has_direct_token(node, "await") {
            self.add_gap(
                builder,
                boundary,
                SemanticGapSubject::Point,
                SemanticCapability::AsyncSuspendResume,
                SemanticGapKind::Unsupported,
                "await using acquisition and asynchronous disposal suspension are not lowered",
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn fixed_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CSharpLoweringError> {
        let children = named_children(node);
        let resource = children
            .iter()
            .copied()
            .find(|child| child.kind() == "variable_declaration")
            .ok_or_else(|| missing_field(node, "declaration"))?;
        let body = children
            .into_iter()
            .find(|child| child.id() != resource.id() && is_statement_kind(child.kind()))
            .ok_or_else(|| missing_field(node, "body"))?;
        self.opaque_resource_statement(
            builder,
            node,
            resource,
            body,
            entry,
            next,
            scope,
            CleanupBody::OpaqueFixed(node),
            stack,
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn opaque_resource_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        resource: Node<'tree>,
        body: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        cleanup_body: CleanupBody<'tree>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<ProgramPointId, CSharpLoweringError> {
        let boundary = self.point(builder, resource, Vec::new())?;
        let body_entry = self.point(builder, body, Vec::new())?;
        let region = CleanupRegionId::new(
            u32::try_from(self.cleanups.len())
                .map_err(|_| CSharpLoweringError::Invalid("too many cleanup regions".into()))?,
        );
        self.cleanups.push(CleanupRegion {
            id: region,
            body: cleanup_body,
            outer_scope: scope,
        });
        let resource_scope = builder.push_scope(Some(scope), ScopeBinding::Cleanup { region });
        self.add_gap(
            builder,
            boundary,
            SemanticGapSubject::Point,
            SemanticCapability::ResourceManagement,
            SemanticGapKind::Unsupported,
            "resource acquisition, value identity, and partial-initialization cleanup are not fully lowered",
        )?;
        self.add_gap(
            builder,
            boundary,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            "resource acquisition and cleanup can raise exceptions not fully represented",
        )?;
        self.edge(builder, boundary, EdgeTarget::normal(body_entry))?;
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
            scope: resource_scope,
        });
        stack.push(Work::Expression {
            node: resource,
            entry,
            next: EdgeTarget::normal(boundary),
            scope,
        });
        Ok(boundary)
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
    ) -> Result<(), CSharpLoweringError> {
        let invoke = self.point(builder, node, Vec::new())?;
        let normal = self.point(builder, node, Vec::new())?;
        let exceptional = self.point(builder, node, Vec::new())?;
        let callee = self.value(builder, invoke, SemanticValueKind::Callable)?;
        let result = self.value(builder, invoke, SemanticValueKind::Temporary)?;
        let thrown = self.value(builder, invoke, SemanticValueKind::Exception)?;
        let function = node.child_by_field_name("function");
        let receiver_node = function.and_then(csharp_call_receiver);
        let receiver = receiver_node
            .map(|_| self.value(builder, invoke, SemanticValueKind::Receiver))
            .transpose()?;
        let constructor = matches!(
            node.kind(),
            "object_creation_expression"
                | "implicit_object_creation_expression"
                | "constructor_initializer"
        );
        let callable_kind = if constructor {
            CallableReferenceKind::Constructor
        } else if receiver.is_some() {
            CallableReferenceKind::BoundMethod
        } else {
            CallableReferenceKind::Function
        };
        let resolution = if matches!(
            node.kind(),
            "implicit_object_creation_expression" | "constructor_initializer"
        ) {
            CallableTargetResolution::Unsupported
        } else {
            CallableTargetResolution::Unknown
        };
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
                .map_err(|_| CSharpLoweringError::Invalid("too many call sites".into()))?,
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

        if let Some(initializer) = object_initializer(node) {
            stack.push(Work::Expression {
                node: initializer,
                entry: normal,
                next,
                scope,
            });
        } else {
            self.edge(builder, normal, next)?;
        }
        self.abrupt(
            builder,
            exceptional,
            scope,
            CompletionKind::Throw,
            None,
            stack,
        )?;
        self.resolution_gaps(builder, invoke, callee, call_site, &resolution)?;

        if function.is_some_and(|function| function.kind() == "conditional_access_expression") {
            let function = function.expect("guarded conditional function");
            let condition = required_field(function, "condition")?;
            let binding = conditional_access_binding(function)
                .ok_or_else(|| missing_field(function, "binding"))?;
            let conditional_entry = self.point(builder, function, Vec::new())?;
            self.add_gap(
                builder,
                conditional_entry,
                SemanticGapSubject::Point,
                SemanticCapability::NormalControlFlow,
                SemanticGapKind::Unsupported,
                "conditional invocation uses a null-test split; conditional result values are not modeled",
            )?;
            let mut evaluations = Vec::with_capacity(arguments.len() + 1);
            if binding.kind() == "element_binding_expression" {
                evaluations.push(binding);
            }
            evaluations.extend(arguments.iter().copied());
            self.schedule_expressions(
                builder,
                conditional_entry,
                &evaluations,
                EdgeTarget::normal(invoke),
                scope,
                stack,
            )?;
            stack.push(Work::Condition {
                node: condition,
                entry,
                when_true: EdgeTarget {
                    point: conditional_entry,
                    kind: ControlEdgeKind::ConditionalTrue,
                },
                when_false: EdgeTarget {
                    point: next.point,
                    kind: ControlEdgeKind::ConditionalFalse,
                },
                scope,
            });
            return Ok(());
        }

        let mut evaluations = Vec::with_capacity(arguments.len() + 1);
        if let Some(receiver_node) = receiver_node {
            evaluations.push(receiver_node);
        } else if let Some(function) = function
            && call_function_requires_evaluation(function)
        {
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
    ) -> Result<(), CSharpLoweringError> {
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
    ) -> Result<(), CSharpLoweringError> {
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
    ) -> Result<(), CSharpLoweringError> {
        let detail = match node.kind() {
            "member_access_expression" | "member_binding_expression" => {
                "implicit null, type-initialization, or property-access exceptions are not yet lowered"
            }
            "element_access_expression" | "element_binding_expression" => {
                "implicit null, bounds, or indexer-access exceptions are not yet lowered"
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
        _next: EdgeTarget,
    ) -> Result<(), CSharpLoweringError> {
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
    ) -> Result<(), CSharpLoweringError> {
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
    ) -> Result<(), CSharpLoweringError> {
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
    ) -> Result<(), CSharpLoweringError> {
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
            return Err(CSharpLoweringError::Invalid(format!(
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
    ) -> Result<(), CSharpLoweringError> {
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
                .ok_or_else(|| CSharpLoweringError::Invalid("missing cleanup region".into()))?;
            let metadata = self.mapping(builder, region.body.source_node())?;
            let (entry, created) =
                builder.cleanup_specialization(route, index, metadata.source, metadata.evidence)?;
            if created {
                if entry.index() != self.point_metadata.len() {
                    return Err(CSharpLoweringError::Invalid(
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
                    CleanupBody::OpaqueFixed(_) => {
                        self.add_gap(
                            builder,
                            entry,
                            SemanticGapSubject::Point,
                            SemanticCapability::ResourceManagement,
                            SemanticGapKind::Unsupported,
                            "fixed-region pinning lifetime and pointer invalidation are represented only as an opaque cleanup boundary",
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
    ) -> Result<(), CSharpLoweringError> {
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
    ) -> Result<ProgramPointId, CSharpLoweringError> {
        let metadata = self.mapping(builder, node)?;
        let events = effects
            .into_iter()
            .map(|effect| SemanticEvent::new(effect, metadata.source, metadata.evidence))
            .collect();
        let point = builder.add_point(events, metadata.source, metadata.evidence)?;
        if point.index() != self.point_metadata.len() {
            return Err(CSharpLoweringError::Invalid(
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
    ) -> Result<PointMetadata, CSharpLoweringError> {
        let range = node.byte_range();
        let occurrence = self
            .source_occurrences
            .entry((range.start, range.end))
            .or_default();
        let anchor = source_anchor(node, *occurrence).map_err(CSharpLoweringError::Invalid)?;
        *occurrence += 1;
        let source = SourceMappingId::new(
            u32::try_from(self.next_source)
                .map_err(|_| CSharpLoweringError::Invalid("too many source mappings".into()))?,
        );
        let evidence = EvidenceId::new(
            u32::try_from(self.next_evidence)
                .map_err(|_| CSharpLoweringError::Invalid("too many evidence rows".into()))?,
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

    fn metadata(&self, point: ProgramPointId) -> Result<PointMetadata, CSharpLoweringError> {
        self.point_metadata
            .get(point.index())
            .copied()
            .ok_or_else(|| {
                CSharpLoweringError::Invalid(format!("missing metadata for program point {point}"))
            })
    }

    fn value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        kind: SemanticValueKind,
    ) -> Result<ValueId, CSharpLoweringError> {
        let metadata = self.metadata(point)?;
        let id = ValueId::new(
            u32::try_from(self.next_value)
                .map_err(|_| CSharpLoweringError::Invalid("too many semantic values".into()))?,
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
    ) -> Result<(), CSharpLoweringError> {
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
    ) -> Result<(), CSharpLoweringError> {
        let metadata = self.metadata(point)?;
        let id = SemanticGapId::new(
            u32::try_from(self.next_gap)
                .map_err(|_| CSharpLoweringError::Invalid("too many semantic gaps".into()))?,
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
    ) -> Result<(), CSharpLoweringError> {
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

fn runtime_expression_children(node: Node<'_>) -> Vec<Node<'_>> {
    let fields: &[&str] = match node.kind() {
        "member_access_expression" => &["expression"],
        "element_access_expression" => &["expression", "subscript"],
        "assignment_expression" | "binary_expression" => &["left", "right"],
        "cast_expression" => &["value"],
        "as_expression" | "is_expression" => &["left"],
        "is_pattern_expression" => &["expression"],
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
            !is_non_runtime_field(node, *child)
                && !is_type_syntax(child.kind())
                && !is_annotation_kind(child.kind())
                && !is_pattern_syntax(child.kind())
                && !matches!(
                    child.kind(),
                    "modifier"
                        | "attribute_list"
                        | "interpolation_alignment_clause"
                        | "interpolation_format_clause"
                        | "interpolation_brace"
                )
        })
        .collect()
}

fn first_runtime_named_child(node: Node<'_>) -> Option<Node<'_>> {
    named_children(node).into_iter().find(|child| {
        !is_non_runtime_field(node, *child)
            && !is_type_syntax(child.kind())
            && !is_annotation_kind(child.kind())
            && !is_pattern_syntax(child.kind())
            && child.kind() != "modifier"
    })
}

fn is_non_runtime_field(node: Node<'_>, child: Node<'_>) -> bool {
    [
        "name",
        "type",
        "returns",
        "operator",
        "parameters",
        "type_parameters",
        "pattern",
    ]
    .into_iter()
    .any(|field| field_matches(node, field, child))
}

fn is_type_syntax(kind: &str) -> bool {
    matches!(
        kind,
        "array_type"
            | "function_pointer_type"
            | "implicit_type"
            | "nullable_type"
            | "pointer_type"
            | "predefined_type"
            | "ref_type"
            | "scoped_type"
            | "tuple_type"
            | "type"
            | "type_argument_list"
            | "type_parameter"
            | "type_parameter_list"
            | "type_parameter_constraint"
            | "type_parameter_constraints_clause"
            | "base_list"
    )
}

fn is_annotation_kind(kind: &str) -> bool {
    matches!(
        kind,
        "attribute" | "attribute_argument" | "attribute_argument_list" | "attribute_list"
    )
}

fn is_pattern_syntax(kind: &str) -> bool {
    kind == "pattern"
        || kind.ends_with("_pattern")
        || matches!(
            kind,
            "discard"
                | "positional_pattern_clause"
                | "property_pattern_clause"
                | "subpattern"
                | "when_clause"
        )
}

fn is_callable_kind(kind: &str) -> bool {
    matches!(
        kind,
        "method_declaration"
            | "constructor_declaration"
            | "local_function_statement"
            | "lambda_expression"
            | "anonymous_method_expression"
            | "accessor_declaration"
            | "operator_declaration"
            | "conversion_operator_declaration"
            | "destructor_declaration"
    )
}

fn is_statement_kind(kind: &str) -> bool {
    is_conditional_compilation_kind(kind)
        || matches!(
            kind,
            "block"
                | "break_statement"
                | "checked_statement"
                | "continue_statement"
                | "do_statement"
                | "empty_statement"
                | "expression_statement"
                | "fixed_statement"
                | "for_statement"
                | "foreach_statement"
                | "goto_statement"
                | "if_statement"
                | "labeled_statement"
                | "local_declaration_statement"
                | "local_function_statement"
                | "lock_statement"
                | "return_statement"
                | "switch_statement"
                | "throw_statement"
                | "try_statement"
                | "unsafe_statement"
                | "using_statement"
                | "while_statement"
                | "yield_statement"
        )
}

fn is_conditional_compilation_kind(kind: &str) -> bool {
    matches!(
        kind,
        "preproc_if" | "preproc_elif" | "preproc_else" | "preproc_if_in_attribute_list"
    )
}

fn variable_initializers(declaration: Node<'_>) -> Vec<Node<'_>> {
    named_children(declaration)
        .into_iter()
        .filter(|child| child.kind() == "variable_declarator")
        .flat_map(runtime_expression_children)
        .collect()
}

fn switch_section_control_nodes(section: Node<'_>) -> Vec<Node<'_>> {
    named_children(section)
        .into_iter()
        .filter(|child| !is_statement_kind(child.kind()))
        .collect()
}

fn switch_section_statements(section: Node<'_>) -> Vec<Node<'_>> {
    named_children(section)
        .into_iter()
        .filter(|child| is_statement_kind(child.kind()))
        .collect()
}

fn switch_expression_arm_value(arm: Node<'_>) -> Option<Node<'_>> {
    named_children(arm)
        .into_iter()
        .rfind(|child| child.kind() != "when_clause" && !is_pattern_syntax(child.kind()))
}

fn csharp_call_receiver(function: Node<'_>) -> Option<Node<'_>> {
    match function.kind() {
        "member_access_expression" => function.child_by_field_name("expression"),
        "conditional_access_expression"
            if conditional_access_binding(function)
                .is_some_and(|binding| binding.kind() == "member_binding_expression") =>
        {
            function.child_by_field_name("condition")
        }
        _ => None,
    }
}

fn conditional_access_binding(node: Node<'_>) -> Option<Node<'_>> {
    let condition = node.child_by_field_name("condition")?;
    named_children(node)
        .into_iter()
        .find(|child| child.id() != condition.id())
}

fn object_initializer(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("initializer").or_else(|| {
        named_children(node)
            .into_iter()
            .find(|child| child.kind() == "initializer_expression")
    })
}

fn call_arguments(node: Node<'_>) -> Vec<Node<'_>> {
    node.child_by_field_name("arguments")
        .or_else(|| {
            named_children(node)
                .into_iter()
                .find(|child| child.kind() == "argument_list")
        })
        .map(named_children)
        .unwrap_or_default()
}

fn call_function_requires_evaluation(function: Node<'_>) -> bool {
    !matches!(
        function.kind(),
        "identifier"
            | "generic_name"
            | "qualified_name"
            | "alias_qualified_name"
            | "member_access_expression"
            | "conditional_access_expression"
    )
}

fn may_invoke_user_code(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "assignment_expression"
            | "binary_expression"
            | "prefix_unary_expression"
            | "postfix_unary_expression"
            | "cast_expression"
            | "as_expression"
            | "is_expression"
            | "is_pattern_expression"
            | "with_expression"
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
    matches!(kind, "line_comment" | "block_comment" | "comment")
}

fn required_field<'tree>(
    node: Node<'tree>,
    field: &str,
) -> Result<Node<'tree>, CSharpLoweringError> {
    node.child_by_field_name(field)
        .ok_or_else(|| missing_field(node, field))
}

fn missing_field(node: Node<'_>, field: &str) -> CSharpLoweringError {
    CSharpLoweringError::Invalid(format!(
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
        "??" => Some("??"),
        _ => None,
    }
}

fn operation_can_throw_implicitly(node: Node<'_>) -> bool {
    match node.kind() {
        "prefix_unary_expression"
        | "postfix_unary_expression"
        | "binary_expression"
        | "cast_expression"
        | "checked_expression"
        | "array_creation_expression"
        | "implicit_array_creation_expression"
        | "stackalloc_expression"
        | "implicit_stackalloc_expression" => true,
        "assignment_expression" => node.child_by_field_name("left").is_some_and(|left| {
            matches!(
                left.kind(),
                "member_access_expression" | "element_access_expression"
            )
        }),
        _ => false,
    }
}

fn is_runtime_leaf(kind: &str) -> bool {
    matches!(
        kind,
        "identifier"
            | "integer_literal"
            | "real_literal"
            | "boolean_literal"
            | "character_literal"
            | "string_literal"
            | "verbatim_string_literal"
            | "raw_string_literal"
            | "null_literal"
            | "this"
            | "base"
            | "discard"
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
