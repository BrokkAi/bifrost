//! JavaScript, JSX, TypeScript, and TSX lowering into the shared executable-semantics IR.

use tree_sitter::Node;

use crate::analyzer::semantic::cfg::{
    CleanupRegionId, CompletionKind, CompletionRequest, CompletionRoute, DriveError,
    ProcedureCfgBuilder, ScopeBinding, ScopeFrameId,
};
use crate::analyzer::semantic::service::{ProgramSemanticsLowerer, SemanticAdapterIdentity};
use crate::analyzer::semantic::*;
use crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree;
use crate::analyzer::{Language, ProjectFile};
use crate::hash::HashMap;

const JAVASCRIPT_ADAPTER_VERSION: &[u8] = b"javascript-cfg-v1";
const TYPESCRIPT_ADAPTER_VERSION: &[u8] = b"typescript-cfg-v1";

#[derive(Debug, Clone, Copy)]
enum JsTsSemanticFlavor {
    JavaScript,
    TypeScript,
}

impl JsTsSemanticFlavor {
    const fn language(self) -> Language {
        match self {
            Self::JavaScript => Language::JavaScript,
            Self::TypeScript => Language::TypeScript,
        }
    }

    const fn adapter_name(self) -> &'static str {
        match self {
            Self::JavaScript => "javascript",
            Self::TypeScript => "typescript",
        }
    }

    const fn adapter_version(self) -> &'static [u8] {
        match self {
            Self::JavaScript => JAVASCRIPT_ADAPTER_VERSION,
            Self::TypeScript => TYPESCRIPT_ADAPTER_VERSION,
        }
    }

    const fn configuration(self) -> &'static [u8] {
        match self {
            Self::JavaScript => b"javascript-intrafile-execution-defaults-v1",
            Self::TypeScript => b"typescript-intrafile-execution-defaults-v1",
        }
    }
}

pub(crate) struct JsTsSemanticLowerer {
    flavor: JsTsSemanticFlavor,
}

impl JsTsSemanticLowerer {
    pub(crate) const fn javascript() -> Self {
        Self {
            flavor: JsTsSemanticFlavor::JavaScript,
        }
    }

    pub(crate) const fn typescript() -> Self {
        Self {
            flavor: JsTsSemanticFlavor::TypeScript,
        }
    }
}

impl ProgramSemanticsLowerer for JsTsSemanticLowerer {
    fn identity(&self) -> SemanticAdapterIdentity {
        SemanticAdapterIdentity {
            adapter: AdapterSemanticsVersion::hash_bytes(
                self.flavor.adapter_name(),
                self.flavor.adapter_version(),
            )
            .expect("adapter name is non-empty"),
            configuration: ConfigurationFingerprint::hash_bytes(self.flavor.configuration()),
            dependencies: DependencyFingerprint::hash_bytes(b"no-intrafile-dependencies"),
        }
    }

    fn capabilities(&self) -> SemanticCapabilities {
        js_ts_capabilities()
    }

    fn lower(
        &self,
        file: &ProjectFile,
        prepared: &PreparedSyntaxTree,
        budget: &SemanticBudget,
        cancellation: &CancellationToken,
    ) -> Result<SemanticOutcome<Vec<ProcedureSemanticsParts>>, SemanticProviderError> {
        if prepared.dialect().language() != self.flavor.language() {
            return Err(SemanticProviderError::invalid_identity(format!(
                "{} semantic lowerer received {} syntax",
                self.flavor.adapter_name(),
                prepared.dialect()
            )));
        }
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
        if cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
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
                Err(TsLoweringError::Cancelled(work)) => {
                    return Ok(SemanticOutcome::Cancelled {
                        partial: None,
                        work: sum_work(observed, *work),
                    });
                }
                Err(TsLoweringError::Budget(exceeded, work)) => {
                    let work = sum_work(observed, *work);
                    let exceeded = budget.check(work).err().unwrap_or(exceeded);
                    return Ok(SemanticOutcome::ExceededBudget {
                        partial: None,
                        exceeded,
                        work,
                    });
                }
                Err(TsLoweringError::Invalid(detail)) => {
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

fn js_ts_capabilities() -> SemanticCapabilities {
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
        SemanticCapability::ExceptionalControlFlow,
        SemanticCapability::CleanupControlFlow,
        SemanticCapability::Calls,
        SemanticCapability::DynamicDispatch,
        SemanticCapability::CallableReferences,
        SemanticCapability::Values,
        SemanticCapability::NormalControlFlow,
        SemanticCapability::GeneratorSuspension,
        SemanticCapability::NonLocalControl,
        SemanticCapability::ResourceManagement,
        SemanticCapability::AsyncSuspendResume,
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
    let file_anchor = source_anchor(prepared.tree().root_node(), 0)
        .map_err(SemanticProviderError::invalid_identity)?;
    let fallback_file_name = match language.language() {
        Language::JavaScript => "javascript-source",
        Language::TypeScript => "typescript-source",
        _ => unreachable!("the shared lowerer validates a JavaScript or TypeScript dialect"),
    };
    let file_name = file
        .rel_path()
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(fallback_file_name);
    let file_segment =
        DeclarationSegment::named(DeclarationSegmentKind::File, file_name, file_anchor, 0)
            .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;

    type SiblingKey = (usize, DeclarationSegmentKind, Option<Box<str>>);
    let mut specs: Vec<ProcedureSpec<'tree>> = Vec::new();
    let mut siblings: HashMap<SiblingKey, u32> = HashMap::default();
    let mut declaration_paths = vec![DeclarationPathEntry {
        parent: None,
        segment: file_segment,
    }];
    let mut preflight = SemanticWork::default();
    let root = prepared.tree().root_node();
    let mut stack = vec![ProcedureEnumerationFrame {
        node: root,
        lexical_parent: None,
        declaration_path: 0,
    }];
    while let Some(frame) = stack.pop() {
        if cancellation.is_cancelled() {
            return Ok(ProcedureEnumeration::Cancelled);
        }
        let ProcedureEnumerationFrame {
            node,
            lexical_parent,
            declaration_path,
        } = frame;
        let mut child_path = declaration_path;
        if let Some(segment_kind) = declaration_container_kind(node) {
            let name = declaration_container_name(prepared.source(), node);
            let sibling_ordinal = next_sibling_ordinal(
                &mut siblings,
                declaration_path,
                segment_kind,
                name.as_deref(),
            );
            let anchor = source_anchor(node, 0).map_err(SemanticProviderError::invalid_identity)?;
            let segment =
                declaration_segment(segment_kind, name.as_deref(), anchor, sibling_ordinal)
                    .map_err(SemanticProviderError::invalid_identity)?;
            child_path = push_declaration_path(&mut declaration_paths, declaration_path, segment);
        }

        let mut child_parent = lexical_parent;
        if let Some((mut kind, mut segment_kind, body, properties)) = callable_shape(node) {
            let id = ProcedureId::try_from_index(specs.len())
                .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
            let name = callable_name(prepared.source(), node);
            if name.as_deref() == Some("constructor") {
                kind = ProcedureKind::Constructor;
                segment_kind = DeclarationSegmentKind::Constructor;
            }
            let sibling_ordinal =
                next_sibling_ordinal(&mut siblings, child_path, segment_kind, name.as_deref());
            let anchor = source_anchor(node, 0).map_err(SemanticProviderError::invalid_identity)?;
            let segment =
                declaration_segment(segment_kind, name.as_deref(), anchor, sibling_ordinal)
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
                lexical_parent,
                kind,
                properties,
                callable: node,
            });
            child_parent = Some(id);
            child_path = push_declaration_path(&mut declaration_paths, child_path, segment);
        }

        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
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

/// Minimum retained identity work reserved by `ProcedureCfgBuilder::new` for
/// one enumerated procedure. This is a preflight only: the builder accounts
/// the same rows and strings exactly when lowering, so callers must not add
/// this estimate to the returned artifact work.
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
        // Two empty adjacency offset arrays, one evidence source, and three
        // retained locator copies (procedure, locator index, source mapping).
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
        "internal_module" => Some(DeclarationSegmentKind::Namespace),
        "class"
        | "class_declaration"
        | "abstract_class_declaration"
        | "interface_declaration"
        | "enum_declaration"
        | "type_alias_declaration" => Some(DeclarationSegmentKind::Type),
        _ => None,
    }
}

fn declaration_container_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    node.child_by_field_name("name")
        .and_then(|name| nonempty_node_text(source, name))
        .map(Box::<str>::from)
        .or_else(|| enclosing_binding(source, node).map(|binding| binding.name))
}

struct EnclosingBinding {
    name: Box<str>,
}

fn callable_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    if let Some(name) = node
        .child_by_field_name("name")
        .and_then(|name| nonempty_node_text(source, name))
        .map(Box::<str>::from)
    {
        return Some(name);
    }

    enclosing_binding(source, node).map(|binding| binding.name)
}

fn enclosing_binding(source: &str, node: Node<'_>) -> Option<EnclosingBinding> {
    let mut value = node;
    loop {
        let parent = value.parent()?;
        match parent.kind() {
            "parenthesized_expression" => {
                if first_named_child(parent).is_some_and(|child| child.id() == value.id()) {
                    value = parent;
                    continue;
                }
                return None;
            }
            "as_expression" | "satisfies_expression" | "non_null_expression" | "type_assertion" => {
                if first_named_child(parent).is_some_and(|child| child.id() == value.id()) {
                    value = parent;
                    continue;
                }
                return None;
            }
            "variable_declarator" => {
                if !field_matches(parent, "value", value) {
                    return None;
                }
                let name = parent.child_by_field_name("name")?;
                return simple_binding_name(source, name).map(|name| EnclosingBinding { name });
            }
            "assignment_expression" => {
                if !field_matches(parent, "right", value) {
                    return None;
                }
                let left = parent.child_by_field_name("left")?;
                return assignment_binding(source, left);
            }
            "pair" => {
                if !field_matches(parent, "value", value) {
                    return None;
                }
                let key = parent.child_by_field_name("key")?;
                return simple_binding_name(source, key).map(|name| EnclosingBinding { name });
            }
            "public_field_definition" | "field_definition" => {
                if !field_matches(parent, "value", value) {
                    return None;
                }
                let name = parent
                    .child_by_field_name("name")
                    .or_else(|| parent.child_by_field_name("property"))?;
                return simple_binding_name(source, name).map(|name| EnclosingBinding { name });
            }
            _ => return None,
        }
    }
}

fn assignment_binding(source: &str, left: Node<'_>) -> Option<EnclosingBinding> {
    if left.kind() == "identifier" {
        return simple_binding_name(source, left).map(|name| EnclosingBinding { name });
    }
    if left.kind() == "member_expression" {
        let property = left.child_by_field_name("property")?;
        return simple_binding_name(source, property).map(|name| EnclosingBinding { name });
    }
    None
}

fn field_matches(parent: Node<'_>, field: &str, child: Node<'_>) -> bool {
    parent
        .child_by_field_name(field)
        .is_some_and(|candidate| candidate.id() == child.id())
}

fn simple_binding_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    matches!(
        node.kind(),
        "identifier" | "property_identifier" | "private_property_identifier" | "type_identifier"
    )
    .then(|| nonempty_node_text(source, node))
    .flatten()
    .map(Box::<str>::from)
}

fn nonempty_node_text<'source>(source: &'source str, node: Node<'_>) -> Option<&'source str> {
    node_text(source, node).filter(|text| !text.is_empty())
}

fn callable_shape<'tree>(
    node: Node<'tree>,
) -> Option<(
    ProcedureKind,
    DeclarationSegmentKind,
    Node<'tree>,
    ProcedureProperties,
)> {
    let (kind, segment_kind, generator) = match node.kind() {
        "function_declaration" | "function_expression" => (
            ProcedureKind::Function,
            DeclarationSegmentKind::Function,
            false,
        ),
        "generator_function_declaration" | "generator_function" => (
            ProcedureKind::Function,
            DeclarationSegmentKind::Function,
            true,
        ),
        "arrow_function" => (ProcedureKind::Lambda, DeclarationSegmentKind::Lambda, false),
        "method_definition" => (
            ProcedureKind::Method,
            DeclarationSegmentKind::Method,
            has_child_kind(node, "*"),
        ),
        "class_static_block" => (
            ProcedureKind::Initializer,
            DeclarationSegmentKind::Initializer,
            false,
        ),
        _ => return None,
    };
    let body = node.child_by_field_name("body")?;
    let mut cursor = node.walk();
    let is_async = node
        .children(&mut cursor)
        .any(|child| child.kind() == "async");
    Some((
        kind,
        segment_kind,
        body,
        ProcedureProperties {
            is_async,
            is_generator: generator,
            is_static: node.kind() == "class_static_block"
                || (node.kind() == "method_definition"
                    && (has_child_kind(node, "static") || has_child_kind(node, "static get"))),
            is_synthetic: false,
            invocation: if generator {
                ProcedureInvocationKind::Deferred
            } else {
                ProcedureInvocationKind::Immediate
            },
        },
    ))
}

#[derive(Debug)]
enum TsLoweringError {
    Cancelled(Box<SemanticWork>),
    Budget(SemanticBudgetExceeded, Box<SemanticWork>),
    Invalid(String),
}

impl From<SemanticBudgetExceeded> for TsLoweringError {
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
    ChainedExpression {
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        skip: EdgeTarget,
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
    body: Node<'tree>,
    outer_scope: ScopeFrameId,
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
    abruptness: HashMap<usize, bool>,
    cleanups: Vec<CleanupRegion<'tree>>,
    cancellation: &'targets CancellationToken,
}

fn lower_procedure<'tree>(
    prepared: &'tree PreparedSyntaxTree,
    spec: &ProcedureSpec<'tree>,
    budget: &SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<(ProcedureSemanticsParts, SemanticWork), TsLoweringError> {
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
        abruptness: HashMap::default(),
        cleanups: Vec::new(),
        cancellation,
    };
    if spec.properties.is_generator {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::GeneratorSuspension,
            SemanticGapKind::Unsupported,
            "generator suspension is not yet lowered",
        )?;
    }
    if spec.callable.kind() == "class_static_block" {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::DeferredExecution,
            SemanticGapKind::Unsupported,
            "class static block scheduling during class evaluation is not yet modeled",
        )?;
    }
    let body_entry = context.point(&mut builder, spec.body, Vec::new())?;
    let initial = if spec.body.kind() == "statement_block" {
        Work::Statement {
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

    let mut pending = vec![initial];
    context.schedule_default_parameters(
        &mut builder,
        spec.callable,
        entry,
        EdgeTarget::normal(body_entry),
        function_scope,
        &mut pending,
    )?;
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
            DriveError::Cancelled | DriveError::Step(TsLoweringError::Cancelled(_)) => {
                Err(TsLoweringError::Cancelled(Box::new(work)))
            }
            DriveError::ExceededBudget(exceeded) => {
                Err(TsLoweringError::Budget(exceeded, Box::new(work)))
            }
            DriveError::Step(TsLoweringError::Budget(exceeded, _)) => {
                Err(TsLoweringError::Budget(exceeded, Box::new(work)))
            }
            DriveError::Step(TsLoweringError::Invalid(detail)) => {
                Err(TsLoweringError::Invalid(detail))
            }
        };
    }
    if builder
        .seal_unreachable_regions(entry, normal_exit, exceptional_exit, cancellation)
        .is_err()
    {
        return Err(TsLoweringError::Cancelled(Box::new(
            builder.prospective_work(),
        )));
    }
    let work_before_freeze = builder.prospective_work();
    let (parts, work) = builder
        .finish_with_work()
        .map_err(|error| TsLoweringError::Budget(error, Box::new(work_before_freeze)))?;
    Ok((parts, work))
}

impl<'tree, 'targets> LoweringContext<'tree, 'targets> {
    fn schedule_default_parameters(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        callable: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), TsLoweringError> {
        if has_nested_parameter_defaults(callable) {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Procedure,
                SemanticCapability::NormalControlFlow,
                SemanticGapKind::Unsupported,
                "nested destructuring parameter defaults are not yet lowered",
            )?;
        }
        let defaults = default_parameter_values(callable);
        if defaults.is_empty() {
            return self.edge(builder, entry, next);
        }

        let mut following = next.point;
        for default in defaults.into_iter().rev() {
            let decision = self.point(builder, default, Vec::new())?;
            let evaluation = self.point(builder, default, Vec::new())?;
            self.edge(
                builder,
                decision,
                EdgeTarget {
                    point: evaluation,
                    kind: ControlEdgeKind::ConditionalTrue,
                },
            )?;
            self.edge(
                builder,
                decision,
                EdgeTarget {
                    point: following,
                    kind: ControlEdgeKind::ConditionalFalse,
                },
            )?;
            stack.push(Work::Expression {
                node: default,
                entry: evaluation,
                next: EdgeTarget::normal(following),
                scope,
            });
            following = decision;
        }
        self.edge(builder, entry, EdgeTarget::normal(following))
    }

    fn step(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        work: Work<'tree>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), TsLoweringError> {
        if self.cancellation.is_cancelled() {
            return Err(TsLoweringError::Cancelled(Box::default()));
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
            } => self.expression(builder, node, entry, next, scope, None, stack),
            Work::ChainedExpression {
                node,
                entry,
                next,
                scope,
                skip,
            } => self.expression(builder, node, entry, next, scope, Some(skip), stack),
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
    ) -> Result<(), TsLoweringError> {
        match (node.kind(), short_circuit_operator(node)) {
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
                let left_truthiness = self.point(builder, left, Vec::new())?;
                self.edge(builder, left_truthiness, when_true)?;
                self.edge(builder, left_truthiness, when_false)?;
                stack.push(Work::Condition {
                    node: right,
                    entry: right_entry,
                    when_true,
                    when_false,
                    scope,
                });
                // The first decision represents nullishness: non-nullish values use the
                // already-evaluated left value's truthiness; nullish values evaluate right.
                let nullish = self.point(builder, left, Vec::new())?;
                self.edge(
                    builder,
                    nullish,
                    EdgeTarget {
                        point: left_truthiness,
                        kind: ControlEdgeKind::ConditionalTrue,
                    },
                )?;
                self.edge(
                    builder,
                    nullish,
                    EdgeTarget {
                        point: right_entry,
                        kind: ControlEdgeKind::ConditionalFalse,
                    },
                )?;
                stack.push(Work::Expression {
                    node: left,
                    entry,
                    next: EdgeTarget::normal(nullish),
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
            (
                "parenthesized_expression"
                | "non_null_expression"
                | "as_expression"
                | "satisfies_expression"
                | "type_assertion",
                _,
            ) => {
                let value = node
                    .child_by_field_name("expression")
                    .or_else(|| first_named_child(node))
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
    ) -> Result<(), TsLoweringError> {
        let scope = if let Some(label) = attached_label
            && !matches!(
                node.kind(),
                "while_statement"
                    | "do_statement"
                    | "for_statement"
                    | "for_in_statement"
                    | "switch_statement"
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
            "statement_block" | "program" => {
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
                let terminal = if let Some(value_node) = node
                    .child_by_field_name("argument")
                    .or_else(|| first_named_child(node))
                {
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
                let terminal = if let Some(value_node) = node
                    .child_by_field_name("argument")
                    .or_else(|| first_named_child(node))
                {
                    let point = self.point(builder, node, Vec::new())?;
                    let value = self.value(builder, point, SemanticValueKind::Exception)?;
                    self.append_effect(
                        builder,
                        point,
                        SemanticEffect::Throw { value: Some(value) },
                    )?;
                    stack.push(Work::Expression {
                        node: value_node,
                        entry,
                        next: EdgeTarget::normal(point),
                        scope,
                    });
                    point
                } else {
                    self.append_effect(builder, entry, SemanticEffect::Throw { value: None })?;
                    entry
                };
                self.abrupt(builder, terminal, scope, CompletionKind::Throw, None, stack)
            }
            "break_statement" | "continue_statement" => {
                let label = node
                    .child_by_field_name("label")
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
                let alternative = node.child_by_field_name("alternative").map(|alternative| {
                    if alternative.kind() == "else_clause" {
                        first_named_child(alternative).unwrap_or(alternative)
                    } else {
                        alternative
                    }
                });
                let consequence_entry = self.point(builder, consequence, Vec::new())?;
                stack.push(Work::Statement {
                    node: consequence,
                    entry: consequence_entry,
                    next,
                    scope,
                });
                let alternative_target = if let Some(alternative) = alternative {
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
                    when_false: alternative_target,
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
            "for_in_statement" => {
                self.for_in_statement(builder, node, entry, next, scope, attached_label, stack)
            }
            "switch_statement" => {
                self.switch_statement(builder, node, entry, next, scope, attached_label, stack)
            }
            "try_statement" => self.try_statement(builder, node, entry, next, scope, stack),
            "labeled_statement" => {
                let body = required_field(node, "body")?;
                let label_node = required_field(node, "label")?;
                let label = node_text(self.prepared.source(), label_node).ok_or_else(|| {
                    TsLoweringError::Invalid("labeled statement has invalid source range".into())
                })?;
                if attached_label.is_some() {
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::NonLocalControl,
                        SemanticGapKind::Unsupported,
                        "multiple labels attached to one statement are not yet represented exactly",
                    )?;
                }
                stack.push(Work::LabeledStatement {
                    node: body,
                    label,
                    entry,
                    next,
                    scope,
                });
                Ok(())
            }
            "using_declaration" => self.resource_declaration(builder, node, entry, scope, stack),
            "lexical_declaration" | "variable_declaration" => {
                if has_child_kind(node, "using") {
                    self.add_resource_cleanup_gaps(
                        builder,
                        entry,
                        "explicit resource-management cleanup is not yet lowered",
                    )?;
                }
                let initializers = declaration_initializers(node);
                self.schedule_expressions(builder, entry, &initializers, next, scope, stack)
            }
            "function_declaration"
            | "generator_function_declaration"
            | "function_expression"
            | "generator_function"
            | "arrow_function" => self.callable_expression(builder, node, entry, next),
            "method_definition"
            | "empty_statement"
            | "debugger_statement"
            | "ambient_declaration"
            | "function_signature"
            | "interface_declaration"
            | "type_alias_declaration"
            | "import_alias" => self.edge(builder, entry, next),
            "with_statement" => {
                let object = required_field(node, "object")?;
                let body = required_field(node, "body")?;
                let body_entry = self.point(builder, body, Vec::new())?;
                stack.push(Work::Statement {
                    node: body,
                    entry: body_entry,
                    next,
                    scope,
                });
                stack.push(Work::Expression {
                    node: object,
                    entry,
                    next: EdgeTarget::normal(body_entry),
                    scope,
                });
                Ok(())
            }
            "export_statement" => {
                if let Some(declaration) = node.child_by_field_name("declaration") {
                    stack.push(Work::Statement {
                        node: declaration,
                        entry,
                        next,
                        scope,
                    });
                    Ok(())
                } else if let Some(value) = node.child_by_field_name("value") {
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
            "import_statement" => self.edge(builder, entry, next),
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
        chain_skip: Option<EdgeTarget>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), TsLoweringError> {
        let chain_skip = chain_skip.or_else(|| continuous_optional_chain(node).then_some(next));
        match node.kind() {
            "call_expression" | "new_expression" => {
                self.call_expression(builder, node, entry, next, scope, chain_skip, stack)
            }
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
            "binary_expression" if short_circuit_operator(node).is_some() => {
                let left = required_field(node, "left")?;
                let right = required_field(node, "right")?;
                let right_entry = self.point(builder, right, Vec::new())?;
                stack.push(Work::Expression {
                    node: right,
                    entry: right_entry,
                    next,
                    scope,
                });
                let (when_true, when_false) = match short_circuit_operator(node) {
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
                    Some("||") | Some("??") => (
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
            "await_expression" => self.await_expression(builder, node, entry, next, scope, stack),
            "yield_expression" => {
                let terminal = if node
                    .child_by_field_name("argument")
                    .or_else(|| first_named_child(node))
                    .is_some()
                {
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
                    "yield suspension and resumption are not yet lowered",
                )?;
                let argument = node
                    .child_by_field_name("argument")
                    .or_else(|| first_named_child(node));
                if let Some(argument) = argument {
                    let argument_entry = self.point(builder, argument, Vec::new())?;
                    self.edge(builder, entry, EdgeTarget::normal(argument_entry))?;
                    stack.push(Work::Expression {
                        node: argument,
                        entry: argument_entry,
                        next: EdgeTarget::normal(terminal),
                        scope,
                    });
                    Ok(())
                } else {
                    Ok(())
                }
            }
            kind if is_callable_kind(kind) => self.callable_expression(builder, node, entry, next),
            "parenthesized_expression" => {
                let value = node
                    .child_by_field_name("expression")
                    .or_else(|| first_named_child(node));
                if let Some(value) = value {
                    // Parentheses end a continuous optional chain. The nested
                    // expression may start a new chain whose skip target is
                    // this wrapper's normal continuation.
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
            "non_null_expression"
            | "as_expression"
            | "satisfies_expression"
            | "type_assertion"
            | "instantiation_expression" => {
                let value = node
                    .child_by_field_name("expression")
                    .or_else(|| first_named_child(node));
                if let Some(value) = value {
                    self.push_chain_expression(stack, value, entry, next, scope, chain_skip);
                    Ok(())
                } else {
                    self.edge(builder, entry, next)
                }
            }
            "augmented_assignment_expression" if logical_assignment_operator(node).is_some() => {
                let operator = logical_assignment_operator(node).expect("guarded logical operator");
                let detail = format!(
                    "logical assignment operator {operator} is not yet lowered with conditional evaluation"
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
            "assignment_expression" if has_child_kind(node, "using") => {
                self.resource_assignment(builder, node, entry, scope, stack)
            }
            "member_expression" | "subscript_expression" => {
                self.member_expression(builder, node, entry, next, scope, chain_skip, stack)
            }
            "assignment_expression"
            | "augmented_assignment_expression"
            | "unary_expression"
            | "update_expression"
            | "binary_expression"
            | "sequence_expression"
            | "array"
            | "object"
            | "pair"
            | "spread_element"
            | "template_string"
            | "template_substitution"
            | "computed_property_name"
            | "jsx_expression"
            | "jsx_attribute"
            | "jsx_opening_element"
            | "jsx_closing_element" => {
                if operation_can_throw_implicitly(node) {
                    self.implicit_exception_gap(builder, entry, node)?;
                }
                self.expression_children(builder, node, entry, next, scope, stack)
            }
            "jsx_element" | "jsx_self_closing_element" | "jsx_fragment" => {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::Calls,
                    SemanticGapKind::Unsupported,
                    "JSX runtime construction depends on the configured JSX transform",
                )?;
                self.expression_children(builder, node, entry, next, scope, stack)
            }
            kind if is_runtime_leaf(kind) => self.edge(builder, entry, next),
            _ => self.unhandled_control_syntax(builder, node, entry, next),
        }
    }

    fn push_chain_expression(
        &self,
        stack: &mut Vec<Work<'tree>>,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        chain_skip: Option<EdgeTarget>,
    ) {
        if let Some(skip) = chain_skip
            && continuous_optional_chain(node)
        {
            stack.push(Work::ChainedExpression {
                node,
                entry,
                next,
                scope,
                skip,
            });
        } else {
            stack.push(Work::Expression {
                node,
                entry,
                next,
                scope,
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn member_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        chain_skip: Option<EdgeTarget>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), TsLoweringError> {
        let object = required_field(node, "object")?;
        let access = self.point(builder, node, Vec::new())?;
        self.implicit_exception_gap(builder, access, node)?;
        self.edge(builder, access, next)?;

        let index = (node.kind() == "subscript_expression")
            .then(|| required_field(node, "index"))
            .transpose()?;
        let after_object = if node.child_by_field_name("optional_chain").is_some()
            || has_child_kind(node, "optional_chain")
        {
            let decision = self.point(builder, node, Vec::new())?;
            let skip = chain_skip.unwrap_or(next);
            self.edge(
                builder,
                decision,
                EdgeTarget {
                    point: skip.point,
                    kind: ControlEdgeKind::ConditionalFalse,
                },
            )?;
            if let Some(index) = index {
                let index_entry = self.point(builder, index, Vec::new())?;
                self.edge(
                    builder,
                    decision,
                    EdgeTarget {
                        point: index_entry,
                        kind: ControlEdgeKind::ConditionalTrue,
                    },
                )?;
                stack.push(Work::Expression {
                    node: index,
                    entry: index_entry,
                    next: EdgeTarget::normal(access),
                    scope,
                });
            } else {
                self.edge(
                    builder,
                    decision,
                    EdgeTarget {
                        point: access,
                        kind: ControlEdgeKind::ConditionalTrue,
                    },
                )?;
            }
            decision
        } else if let Some(index) = index {
            let index_entry = self.point(builder, index, Vec::new())?;
            stack.push(Work::Expression {
                node: index,
                entry: index_entry,
                next: EdgeTarget::normal(access),
                scope,
            });
            index_entry
        } else {
            access
        };

        let object_entry = self.point(builder, object, Vec::new())?;
        self.edge(builder, entry, EdgeTarget::normal(object_entry))?;
        self.push_chain_expression(
            stack,
            object,
            object_entry,
            EdgeTarget::normal(after_object),
            scope,
            chain_skip,
        );
        Ok(())
    }

    fn implicit_exception_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        node: Node<'tree>,
    ) -> Result<(), TsLoweringError> {
        let detail = match node.kind() {
            "member_expression" | "subscript_expression" => {
                "implicit exceptions from property access, accessors, or proxies are not yet lowered"
            }
            _ => {
                "implicit exceptions from runtime coercion or operator dispatch are not yet lowered"
            }
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

    fn resource_assignment(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), TsLoweringError> {
        let initializer = required_field(node, "right")?;
        let terminal = self.point(builder, node, Vec::new())?;
        self.add_resource_cleanup_gaps(
            builder,
            terminal,
            "using declaration disposal and cleanup are not yet lowered",
        )?;
        if node
            .parent()
            .is_some_and(|parent| parent.kind() == "await_expression")
        {
            self.add_gap(
                builder,
                terminal,
                SemanticGapSubject::Point,
                SemanticCapability::AsyncSuspendResume,
                SemanticGapKind::Unsupported,
                "await-using asynchronous disposal suspension and resumption are not yet lowered",
            )?;
        }
        let initializer_entry = self.point(builder, initializer, Vec::new())?;
        self.edge(builder, entry, EdgeTarget::normal(initializer_entry))?;
        stack.push(Work::Expression {
            node: initializer,
            entry: initializer_entry,
            next: EdgeTarget::normal(terminal),
            scope,
        });
        Ok(())
    }

    fn resource_declaration(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), TsLoweringError> {
        let terminal = self.point(builder, node, Vec::new())?;
        self.add_resource_cleanup_gaps(
            builder,
            terminal,
            "using declaration disposal and cleanup are not yet lowered",
        )?;
        if has_child_kind(node, "await") {
            self.add_gap(
                builder,
                terminal,
                SemanticGapSubject::Point,
                SemanticCapability::AsyncSuspendResume,
                SemanticGapKind::Unsupported,
                "await-using asynchronous disposal suspension and resumption are not yet lowered",
            )?;
        }
        let initializers = declaration_initializers(node);
        self.schedule_expressions(
            builder,
            entry,
            &initializers,
            EdgeTarget::normal(terminal),
            scope,
            stack,
        )
    }

    fn unhandled_control_syntax(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        _next: EdgeTarget,
    ) -> Result<(), TsLoweringError> {
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
    ) -> Result<(), TsLoweringError> {
        let body = required_field(node, "body")?;
        let initializer = node
            .child_by_field_name("initializer")
            .filter(|initializer| initializer.kind() != "empty_statement");
        let condition = node
            .child_by_field_name("condition")
            .filter(|condition| condition.kind() != "empty_statement");
        let increment = node.child_by_field_name("increment");
        let condition_entry = match condition {
            Some(condition) => self.point(builder, condition, Vec::new())?,
            None => self.point(builder, node, Vec::new())?,
        };
        let body_entry = self.point(builder, body, Vec::new())?;
        let increment_entry = increment
            .map(|increment| self.point(builder, increment, Vec::new()))
            .transpose()?;
        let continue_target = increment_entry.unwrap_or(condition_entry);
        let loop_scope = builder.push_scope(
            Some(scope),
            ScopeBinding::Loop {
                label: label.map(Box::<str>::from),
                break_target: next.point,
                break_edge_kind: next.kind,
                continue_target,
                continue_edge_kind: if increment.is_some() {
                    ControlEdgeKind::Normal
                } else {
                    ControlEdgeKind::LoopBack
                },
            },
        );
        if let Some(increment) = increment {
            stack.push(Work::Expression {
                node: increment,
                entry: increment_entry.expect("increment entry exists"),
                next: EdgeTarget {
                    point: condition_entry,
                    kind: ControlEdgeKind::LoopBack,
                },
                scope: loop_scope,
            });
        }
        stack.push(Work::Statement {
            node: body,
            entry: body_entry,
            next: EdgeTarget {
                point: continue_target,
                kind: if increment.is_some() {
                    ControlEdgeKind::Normal
                } else {
                    ControlEdgeKind::LoopBack
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
        if let Some(initializer) = initializer {
            if matches!(
                initializer.kind(),
                "lexical_declaration" | "variable_declaration"
            ) {
                stack.push(Work::Statement {
                    node: initializer,
                    entry,
                    next: EdgeTarget::normal(condition_entry),
                    scope: loop_scope,
                });
            } else {
                stack.push(Work::Expression {
                    node: initializer,
                    entry,
                    next: EdgeTarget::normal(condition_entry),
                    scope: loop_scope,
                });
            }
        } else if entry != condition_entry {
            self.edge(builder, entry, EdgeTarget::normal(condition_entry))?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn for_in_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        label: Option<&'tree str>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), TsLoweringError> {
        if node.child_by_field_name("value").is_some() {
            return self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::NormalControlFlow,
                SemanticGapKind::Unsupported,
                "legacy for-in binding initializers are not yet lowered in specification order",
            );
        }
        let body = required_field(node, "body")?;
        let left = required_field(node, "left")?;
        let right = required_field(node, "right")?;
        let test = self.point(builder, node, Vec::new())?;
        let left_entry = self.point(builder, left, Vec::new())?;
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
            node: left,
            entry: left_entry,
            next: EdgeTarget::normal(body_entry),
            scope: loop_scope,
        });
        let is_await = has_child_kind(node, "await");
        let is_using = has_child_kind(node, "using");
        if is_using {
            self.add_resource_cleanup_gaps(
                builder,
                test,
                "for-using per-iteration disposal and cleanup are not yet lowered",
            )?;
            if is_await {
                self.add_gap(
                    builder,
                    test,
                    SemanticGapSubject::Point,
                    SemanticCapability::AsyncSuspendResume,
                    SemanticGapKind::Unsupported,
                    "for-await-using asynchronous disposal suspension and resumption are not yet lowered",
                )?;
            }
        } else if is_await {
            self.add_gap(
                builder,
                test,
                SemanticGapSubject::Point,
                SemanticCapability::AsyncSuspendResume,
                SemanticGapKind::Unsupported,
                "for-await async-iterator suspension and resumption are not yet lowered",
            )?;
        } else {
            self.edge(
                builder,
                test,
                EdgeTarget {
                    point: left_entry,
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
        }
        stack.push(Work::Expression {
            node: right,
            entry,
            next: EdgeTarget::normal(test),
            scope: loop_scope,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn switch_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        label: Option<&'tree str>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), TsLoweringError> {
        let value = required_field(node, "value")?;
        let body = required_field(node, "body")?;
        let dispatch = self.point(builder, node, Vec::new())?;
        let switch_scope = builder.push_scope(
            Some(scope),
            ScopeBinding::Breakable {
                label: label.map(Box::<str>::from),
                accepts_unlabeled: true,
                break_target: next.point,
                break_edge_kind: next.kind,
            },
        );
        let cases = named_children(body)
            .into_iter()
            .filter(|child| matches!(child.kind(), "switch_case" | "switch_default"))
            .collect::<Vec<_>>();
        if cases.is_empty() {
            self.edge(builder, dispatch, next)?;
        } else {
            let mut entries = Vec::with_capacity(cases.len());
            for case in &cases {
                entries.push(self.point(builder, *case, Vec::new())?);
            }

            // Bodies retain source-order fallthrough, independently of predicate dispatch.
            for (index, case) in cases.iter().enumerate().rev() {
                let statements = children_by_field_name(*case, "body")
                    .into_iter()
                    .filter(|child| child.kind() != "comment")
                    .collect::<Vec<_>>();
                let fallthrough = entries
                    .get(index + 1)
                    .copied()
                    .map(EdgeTarget::normal)
                    .unwrap_or(next);
                self.schedule_statements(
                    builder,
                    entries[index],
                    &statements,
                    fallthrough,
                    switch_scope,
                    stack,
                )?;
            }

            // JavaScript evaluates case predicates in source order until one matches.  A
            // default clause is selected only after every predicate failed, even when the
            // default appears before a later case in source order.
            let mut no_match = cases
                .iter()
                .position(|case| case.kind() == "switch_default")
                .map(|index| EdgeTarget::normal(entries[index]))
                .unwrap_or(next);
            for (index, case) in cases.iter().enumerate().rev() {
                if case.kind() != "switch_case" {
                    continue;
                }
                let predicate = required_field(*case, "value")?;
                let predicate_entry = self.point(builder, predicate, Vec::new())?;
                let comparison = self.point(builder, *case, Vec::new())?;
                self.edge(
                    builder,
                    comparison,
                    EdgeTarget {
                        point: entries[index],
                        kind: ControlEdgeKind::SwitchCase,
                    },
                )?;
                self.edge(
                    builder,
                    comparison,
                    EdgeTarget {
                        point: no_match.point,
                        kind: ControlEdgeKind::ConditionalFalse,
                    },
                )?;
                stack.push(Work::Expression {
                    node: predicate,
                    entry: predicate_entry,
                    next: EdgeTarget::normal(comparison),
                    scope: switch_scope,
                });
                no_match = EdgeTarget::normal(predicate_entry);
            }
            self.edge(builder, dispatch, no_match)?;
        }
        stack.push(Work::Expression {
            node: value,
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
    ) -> Result<(), TsLoweringError> {
        let body = required_field(node, "body")?;
        let handler = node.child_by_field_name("handler").or_else(|| {
            named_children(node)
                .into_iter()
                .find(|child| child.kind() == "catch_clause")
        });
        let finalizer = node
            .child_by_field_name("finalizer")
            .or_else(|| {
                named_children(node)
                    .into_iter()
                    .find(|child| child.kind() == "finally_clause")
            })
            .and_then(|clause| {
                if clause.kind() == "finally_clause" {
                    clause.child_by_field_name("body")
                } else {
                    Some(clause)
                }
            });

        let (cleanup_scope, cleanup_region) = if let Some(finalizer) = finalizer {
            let region = CleanupRegionId::new(
                u32::try_from(self.cleanups.len())
                    .map_err(|_| TsLoweringError::Invalid("too many cleanup regions".into()))?,
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
        let catch_body = handler.and_then(|handler| handler.child_by_field_name("body"));
        let catch_entry = catch_body
            .map(|body| self.point(builder, body, Vec::new()))
            .transpose()?;
        let try_scope = if let Some(catch_entry) = catch_entry {
            builder.push_scope(
                Some(cleanup_scope),
                ScopeBinding::Handler { entry: catch_entry },
            )
        } else {
            cleanup_scope
        };

        if let Some(catch_body) = catch_body {
            let catch_entry = catch_entry.expect("catch entry exists");
            if let Some(route) = &normal_route {
                let catch_exit = self.point(builder, catch_body, Vec::new())?;
                self.route(builder, catch_exit, route, stack)?;
                stack.push(Work::Statement {
                    node: catch_body,
                    entry: catch_entry,
                    next: EdgeTarget::normal(catch_exit),
                    scope: cleanup_scope,
                });
            } else {
                stack.push(Work::Statement {
                    node: catch_body,
                    entry: catch_entry,
                    next,
                    scope: cleanup_scope,
                });
            }
        }

        if let Some(route) = normal_route {
            let body_exit = self.point(builder, body, Vec::new())?;
            self.route(builder, body_exit, &route, stack)?;
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
    fn call_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        chain_skip: Option<EdgeTarget>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), TsLoweringError> {
        let function = node
            .child_by_field_name("function")
            .or_else(|| node.child_by_field_name("constructor"))
            .ok_or_else(|| missing_field(node, "function/constructor"))?;
        let invoke = self.point(builder, node, Vec::new())?;
        let normal = self.point(builder, node, Vec::new())?;
        let exceptional = self.point(builder, node, Vec::new())?;
        let callee = self.value(builder, invoke, SemanticValueKind::Callable)?;
        let result = self.value(builder, invoke, SemanticValueKind::Temporary)?;
        let thrown = self.value(builder, invoke, SemanticValueKind::Exception)?;
        let (callable_kind, receiver) = if node.kind() == "new_expression" {
            (CallableReferenceKind::Constructor, None)
        } else if function.kind() == "member_expression"
            || function.kind() == "subscript_expression"
        {
            (
                CallableReferenceKind::BoundMethod,
                Some(self.value(builder, invoke, SemanticValueKind::Receiver)?),
            )
        } else {
            (CallableReferenceKind::Function, None)
        };
        // Local name matching is not a sound dispatch proof in JavaScript or TypeScript:
        // lexical shadowing, imports, hoisting, and declaration merging can all change the
        // target.  The location-first DispatchOracle owns refinement in the ICFG layer.
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
                .map_err(|_| TsLoweringError::Invalid("too many call sites".into()))?,
        );
        let argument_nodes = node
            .child_by_field_name("arguments")
            .map(named_children)
            .unwrap_or_default();
        let mut arguments = Vec::with_capacity(argument_nodes.len());
        for _ in &argument_nodes {
            arguments.push(self.value(builder, invoke, SemanticValueKind::Temporary)?);
        }
        builder.add_call_site(SemanticCallSite {
            id: call_site,
            point: invoke,
            callee,
            receiver,
            arguments: arguments.into_boxed_slice(),
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
        self.edge(
            builder,
            invoke,
            EdgeTarget {
                point: normal,
                kind: ControlEdgeKind::Normal,
            },
        )?;
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
                "property dispatch may resolve through a prototype, accessor, proxy, or runtime mutation; complete target coverage requires value and type refinement"
            } else {
                "callable bindings and imports may be rebound or replaced at runtime; complete target coverage requires lexical and value-flow refinement"
            },
        )?;

        if has_child_kind(node, "?.") {
            let decision = self.point(builder, node, Vec::new())?;
            let skip = chain_skip.unwrap_or(next);
            self.edge(
                builder,
                decision,
                EdgeTarget {
                    point: skip.point,
                    kind: ControlEdgeKind::ConditionalFalse,
                },
            )?;
            if argument_nodes.is_empty() {
                self.edge(
                    builder,
                    decision,
                    EdgeTarget {
                        point: invoke,
                        kind: ControlEdgeKind::ConditionalTrue,
                    },
                )?;
            } else {
                let argument_entries = argument_nodes
                    .iter()
                    .map(|expression| self.point(builder, *expression, Vec::new()))
                    .collect::<Result<Vec<_>, _>>()?;
                self.edge(
                    builder,
                    decision,
                    EdgeTarget {
                        point: argument_entries[0],
                        kind: ControlEdgeKind::ConditionalTrue,
                    },
                )?;
                for index in (0..argument_nodes.len()).rev() {
                    stack.push(Work::Expression {
                        node: argument_nodes[index],
                        entry: argument_entries[index],
                        next: argument_entries
                            .get(index + 1)
                            .copied()
                            .map(EdgeTarget::normal)
                            .unwrap_or_else(|| EdgeTarget::normal(invoke)),
                        scope,
                    });
                }
            }
            self.push_chain_expression(
                stack,
                function,
                entry,
                EdgeTarget::normal(decision),
                scope,
                chain_skip,
            );
            Ok(())
        } else {
            let argument_entries = argument_nodes
                .iter()
                .map(|argument| self.point(builder, *argument, Vec::new()))
                .collect::<Result<Vec<_>, _>>()?;
            for index in (0..argument_nodes.len()).rev() {
                stack.push(Work::Expression {
                    node: argument_nodes[index],
                    entry: argument_entries[index],
                    next: argument_entries
                        .get(index + 1)
                        .copied()
                        .map(EdgeTarget::normal)
                        .unwrap_or_else(|| EdgeTarget::normal(invoke)),
                    scope,
                });
            }
            let function_next = argument_entries
                .first()
                .copied()
                .map(EdgeTarget::normal)
                .unwrap_or_else(|| EdgeTarget::normal(invoke));
            self.push_chain_expression(stack, function, entry, function_next, scope, chain_skip);
            Ok(())
        }
    }

    fn await_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), TsLoweringError> {
        let awaited_node = node
            .child_by_field_name("argument")
            .or_else(|| first_named_child(node));
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
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
    ) -> Result<(), TsLoweringError> {
        let result = self.value(builder, entry, SemanticValueKind::Callable)?;
        let resolution = CallableTargetResolution::Unknown;
        let metadata = self.metadata(entry)?;
        let kind = if node.kind() == "arrow_function" {
            CallableReferenceKind::Lambda
        } else {
            CallableReferenceKind::Function
        };
        let effect = SemanticEffect::CallableCreation {
            result,
            callable: CallableValue {
                kind,
                targets: resolution.clone(),
                target_evidence: metadata.evidence,
                bound_receiver: None,
                environment: None,
            },
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

    fn expression_children(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), TsLoweringError> {
        let children = named_children(node)
            .into_iter()
            .filter(|child| child.kind() != "comment")
            .collect::<Vec<_>>();
        self.schedule_expressions(builder, entry, &children, next, scope, stack)
    }

    fn schedule_statements(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        children: &[Node<'tree>],
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), TsLoweringError> {
        if children.is_empty() {
            return self.edge(builder, entry, next);
        }
        let entries = children
            .iter()
            .map(|child| self.point(builder, *child, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        self.edge(builder, entry, EdgeTarget::normal(entries[0]))?;
        let mut dead_start = None;
        for (index, child) in children.iter().enumerate() {
            if self.statement_is_guaranteed_abrupt(*child)? && index + 1 < children.len() {
                dead_start = Some(index + 1);
                break;
            }
        }
        let dead_region = if let Some(dead_start) = dead_start {
            let dead_normal = self.point(builder, children[dead_start], Vec::new())?;
            let dead_exceptional = self.point(builder, children[dead_start], Vec::new())?;
            let dead_scope = builder.push_scope(
                Some(scope),
                ScopeBinding::Disconnected {
                    normal_target: dead_normal,
                    exceptional_target: dead_exceptional,
                    control_target: dead_normal,
                },
            );
            Some((dead_start, dead_normal, dead_scope))
        } else {
            None
        };
        for index in (0..children.len()).rev() {
            let (child_next, child_scope) = match dead_region {
                Some((dead_start, dead_normal, dead_scope)) if index >= dead_start => (
                    entries
                        .get(index + 1)
                        .copied()
                        .map(EdgeTarget::normal)
                        .unwrap_or_else(|| EdgeTarget::normal(dead_normal)),
                    dead_scope,
                ),
                _ => (
                    entries
                        .get(index + 1)
                        .copied()
                        .map(EdgeTarget::normal)
                        .unwrap_or(next),
                    scope,
                ),
            };
            stack.push(Work::Statement {
                node: children[index],
                entry: entries[index],
                next: child_next,
                scope: child_scope,
            });
        }
        Ok(())
    }

    fn statement_is_guaranteed_abrupt(
        &mut self,
        node: Node<'tree>,
    ) -> Result<bool, TsLoweringError> {
        if let Some(result) = self.abruptness.get(&node.id()).copied() {
            return Ok(result);
        }
        let mut stack = vec![(node, false)];
        while let Some((current, expanded)) = stack.pop() {
            if self.cancellation.is_cancelled() {
                return Err(TsLoweringError::Cancelled(Box::default()));
            }
            if self.abruptness.contains_key(&current.id()) {
                continue;
            }
            if !expanded {
                stack.push((current, true));
                for child in abrupt_dependencies(current).into_iter().rev() {
                    if !self.abruptness.contains_key(&child.id()) {
                        stack.push((child, false));
                    }
                }
                continue;
            }
            let abrupt = match current.kind() {
                "return_statement" | "throw_statement" | "break_statement"
                | "continue_statement" => true,
                "statement_block" | "program" => abrupt_dependencies(current)
                    .into_iter()
                    .any(|child| self.abruptness.get(&child.id()).copied().unwrap_or(false)),
                "if_statement" => {
                    let consequence = current.child_by_field_name("consequence");
                    let alternative =
                        current
                            .child_by_field_name("alternative")
                            .map(|alternative| {
                                if alternative.kind() == "else_clause" {
                                    first_named_child(alternative).unwrap_or(alternative)
                                } else {
                                    alternative
                                }
                            });
                    consequence.is_some_and(|child| {
                        self.abruptness.get(&child.id()).copied().unwrap_or(false)
                    }) && alternative.is_some_and(|child| {
                        self.abruptness.get(&child.id()).copied().unwrap_or(false)
                    })
                }
                "try_statement" => {
                    let body = current.child_by_field_name("body");
                    let handler = current
                        .child_by_field_name("handler")
                        .and_then(|handler| handler.child_by_field_name("body"));
                    let finalizer = current
                        .child_by_field_name("finalizer")
                        .and_then(|finalizer| finalizer.child_by_field_name("body"));
                    let body_abrupt = body.is_some_and(|body| {
                        self.abruptness.get(&body.id()).copied().unwrap_or(false)
                    });
                    let handler_abrupt = handler.is_none_or(|handler| {
                        self.abruptness.get(&handler.id()).copied().unwrap_or(false)
                    });
                    let finalizer_abrupt = finalizer.is_some_and(|finalizer| {
                        self.abruptness
                            .get(&finalizer.id())
                            .copied()
                            .unwrap_or(false)
                    });
                    finalizer_abrupt || (body_abrupt && handler_abrupt)
                }
                "for_statement" => {
                    let has_condition = current
                        .child_by_field_name("condition")
                        .is_some_and(|condition| condition.kind() != "empty_statement");
                    if has_condition {
                        false
                    } else if let Some(body) = current.child_by_field_name("body") {
                        !self.has_potential_break(body)?
                    } else {
                        false
                    }
                }
                "labeled_statement" => {
                    let body_abrupt = abrupt_dependencies(current).first().is_some_and(|child| {
                        self.abruptness.get(&child.id()).copied().unwrap_or(false)
                    });
                    body_abrupt && !self.has_matching_labeled_break(current)?
                }
                "else_clause" | "export_statement" => {
                    abrupt_dependencies(current).first().is_some_and(|child| {
                        self.abruptness.get(&child.id()).copied().unwrap_or(false)
                    })
                }
                _ => false,
            };
            self.abruptness.insert(current.id(), abrupt);
        }
        Ok(self.abruptness.get(&node.id()).copied().unwrap_or(false))
    }

    fn has_matching_labeled_break(&self, labeled: Node<'tree>) -> Result<bool, TsLoweringError> {
        let Some(label) = labeled
            .child_by_field_name("label")
            .and_then(|label| node_text(self.prepared.source(), label))
        else {
            return Ok(false);
        };
        let Some(body) = labeled.child_by_field_name("body") else {
            return Ok(false);
        };
        let mut stack = vec![body];
        while let Some(current) = stack.pop() {
            if self.cancellation.is_cancelled() {
                return Err(TsLoweringError::Cancelled(Box::default()));
            }
            if current.kind() == "break_statement"
                && current
                    .child_by_field_name("label")
                    .and_then(|candidate| node_text(self.prepared.source(), candidate))
                    == Some(label)
            {
                return Ok(true);
            }
            if current.id() != body.id() && is_callable_kind(current.kind()) {
                continue;
            }
            stack.extend(named_children(current));
        }
        Ok(false)
    }

    fn has_potential_break(&self, body: Node<'tree>) -> Result<bool, TsLoweringError> {
        let mut stack = vec![body];
        while let Some(current) = stack.pop() {
            if self.cancellation.is_cancelled() {
                return Err(TsLoweringError::Cancelled(Box::default()));
            }
            if current.kind() == "break_statement" {
                return Ok(true);
            }
            if current.id() != body.id() && is_callable_kind(current.kind()) {
                continue;
            }
            stack.extend(named_children(current));
        }
        Ok(false)
    }

    fn schedule_expressions(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        children: &[Node<'tree>],
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), TsLoweringError> {
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
    ) -> Result<(), TsLoweringError> {
        let Some(route) = builder.resolve_completion(scope, &CompletionRequest::new(kind, label))
        else {
            if matches!(kind, CompletionKind::Break | CompletionKind::Continue) {
                let detail = format!(
                    "{} completion has no matching represented label target",
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
            return Err(TsLoweringError::Invalid(format!(
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
    ) -> Result<(), TsLoweringError> {
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
                .ok_or_else(|| TsLoweringError::Invalid("missing cleanup region".into()))?;
            let metadata = self.mapping(builder, region.body)?;
            let (entry, created) =
                builder.cleanup_specialization(route, index, metadata.source, metadata.evidence)?;
            if created {
                if entry.index() != self.point_metadata.len() {
                    return Err(TsLoweringError::Invalid(
                        "cleanup specialization broke dense point allocation".into(),
                    ));
                }
                self.point_metadata.push(metadata);
                let body_next = if next.kind == ControlEdgeKind::Normal {
                    next
                } else {
                    let relay = self.point(builder, region.body, Vec::new())?;
                    self.edge(builder, relay, next)?;
                    EdgeTarget::normal(relay)
                };
                stack.push(Work::Statement {
                    node: region.body,
                    entry,
                    next: body_next,
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
    ) -> Result<(), TsLoweringError> {
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
    ) -> Result<ProgramPointId, TsLoweringError> {
        let metadata = self.mapping(builder, node)?;
        let events = effects
            .into_iter()
            .map(|effect| SemanticEvent::new(effect, metadata.source, metadata.evidence))
            .collect();
        let point = builder.add_point(events, metadata.source, metadata.evidence)?;
        if point.index() != self.point_metadata.len() {
            return Err(TsLoweringError::Invalid(
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
    ) -> Result<PointMetadata, TsLoweringError> {
        let range = node.byte_range();
        let occurrence = self
            .source_occurrences
            .entry((range.start, range.end))
            .or_default();
        let anchor = source_anchor(node, *occurrence).map_err(TsLoweringError::Invalid)?;
        *occurrence += 1;
        let source = SourceMappingId::new(
            u32::try_from(self.next_source)
                .map_err(|_| TsLoweringError::Invalid("too many source mappings".into()))?,
        );
        let evidence = EvidenceId::new(
            u32::try_from(self.next_evidence)
                .map_err(|_| TsLoweringError::Invalid("too many evidence rows".into()))?,
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

    fn metadata(&self, point: ProgramPointId) -> Result<PointMetadata, TsLoweringError> {
        self.point_metadata
            .get(point.index())
            .copied()
            .ok_or_else(|| {
                TsLoweringError::Invalid(format!("missing metadata for program point {point}"))
            })
    }

    fn value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        kind: SemanticValueKind,
    ) -> Result<ValueId, TsLoweringError> {
        let metadata = self.metadata(point)?;
        let id = ValueId::new(
            u32::try_from(self.next_value)
                .map_err(|_| TsLoweringError::Invalid("too many semantic values".into()))?,
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
    ) -> Result<(), TsLoweringError> {
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
    ) -> Result<(), TsLoweringError> {
        let metadata = self.metadata(point)?;
        let id = SemanticGapId::new(
            u32::try_from(self.next_gap)
                .map_err(|_| TsLoweringError::Invalid("too many semantic gaps".into()))?,
        );
        builder.add_gap(SemanticGap {
            id,
            point,
            subject,
            capability,
            impacts: SemanticGapImpacts::for_gap(capability, subject),
            kind,
            budget: None,
            detail: detail.into(),
            source: metadata.source,
            evidence: metadata.evidence,
        })?;
        self.next_gap += 1;
        self.append_effect(builder, point, SemanticEffect::Gap { gap: id })
    }

    fn add_resource_cleanup_gaps(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        context: &str,
    ) -> Result<(), TsLoweringError> {
        for (capability, omission) in [
            (
                SemanticCapability::ResourceManagement,
                "resource acquisition, lifetime, and disposal are incomplete",
            ),
            (
                SemanticCapability::CleanupControlFlow,
                "disposal is not stitched onto every scope-completion path",
            ),
            (
                SemanticCapability::ExceptionalControlFlow,
                "disposal failure and suppressed-error behavior are not lowered",
            ),
        ] {
            self.add_gap(
                builder,
                point,
                SemanticGapSubject::Point,
                capability,
                SemanticGapKind::Unsupported,
                &format!("{context}; {omission}"),
            )?;
        }
        Ok(())
    }

    fn edge(
        &self,
        builder: &mut ProcedureCfgBuilder,
        source_point: ProgramPointId,
        target: EdgeTarget,
    ) -> Result<(), TsLoweringError> {
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

fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn children_by_field_name<'tree>(node: Node<'tree>, field: &str) -> Vec<Node<'tree>> {
    let mut cursor = node.walk();
    node.children_by_field_name(field, &mut cursor).collect()
}

fn default_parameter_values(node: Node<'_>) -> Vec<Node<'_>> {
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return Vec::new();
    };
    named_children(parameters)
        .into_iter()
        .filter_map(|parameter| match parameter.kind() {
            "required_parameter" | "optional_parameter" => parameter.child_by_field_name("value"),
            "assignment_pattern" => parameter.child_by_field_name("right"),
            _ => None,
        })
        .collect()
}

fn has_nested_parameter_defaults(node: Node<'_>) -> bool {
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return false;
    };
    for parameter in named_children(parameters) {
        let binding = match parameter.kind() {
            "required_parameter" | "optional_parameter" => parameter.child_by_field_name("pattern"),
            "assignment_pattern" => parameter.child_by_field_name("left"),
            _ => Some(parameter),
        };
        let Some(binding) = binding else {
            continue;
        };
        let mut stack = vec![binding];
        while let Some(current) = stack.pop() {
            if current.kind() == "assignment_pattern" {
                return true;
            }
            stack.extend(named_children(current));
        }
    }
    false
}

fn declaration_initializers(node: Node<'_>) -> Vec<Node<'_>> {
    named_children(node)
        .into_iter()
        .filter(|child| child.kind() == "variable_declarator")
        .filter_map(|declarator| declarator.child_by_field_name("value"))
        .collect()
}

fn abrupt_dependencies(node: Node<'_>) -> Vec<Node<'_>> {
    match node.kind() {
        "statement_block" | "program" => named_children(node)
            .into_iter()
            .filter(|child| child.kind() != "comment")
            .collect(),
        "if_statement" => {
            let mut children = Vec::with_capacity(2);
            if let Some(consequence) = node.child_by_field_name("consequence") {
                children.push(consequence);
            }
            if let Some(alternative) = node.child_by_field_name("alternative") {
                children.push(if alternative.kind() == "else_clause" {
                    first_named_child(alternative).unwrap_or(alternative)
                } else {
                    alternative
                });
            }
            children
        }
        "try_statement" => {
            let mut children = Vec::with_capacity(3);
            if let Some(body) = node.child_by_field_name("body") {
                children.push(body);
            }
            if let Some(handler) = node
                .child_by_field_name("handler")
                .and_then(|handler| handler.child_by_field_name("body"))
            {
                children.push(handler);
            }
            if let Some(finalizer) = node
                .child_by_field_name("finalizer")
                .and_then(|finalizer| finalizer.child_by_field_name("body"))
            {
                children.push(finalizer);
            }
            children
        }
        "labeled_statement" => node.child_by_field_name("body").into_iter().collect(),
        "else_clause" => first_named_child(node).into_iter().collect(),
        "export_statement" => node
            .child_by_field_name("declaration")
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

fn first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).next()
}

fn required_field<'tree>(node: Node<'tree>, field: &str) -> Result<Node<'tree>, TsLoweringError> {
    node.child_by_field_name(field)
        .ok_or_else(|| missing_field(node, field))
}

fn missing_field(node: Node<'_>, field: &str) -> TsLoweringError {
    TsLoweringError::Invalid(format!(
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

fn is_callable_kind(kind: &str) -> bool {
    matches!(
        kind,
        "function_declaration"
            | "function_expression"
            | "generator_function_declaration"
            | "generator_function"
            | "arrow_function"
            | "method_definition"
    )
}

fn is_runtime_leaf(kind: &str) -> bool {
    matches!(
        kind,
        "identifier"
            | "property_identifier"
            | "private_property_identifier"
            | "statement_identifier"
            | "type_identifier"
            | "jsx_identifier"
            | "jsx_namespace_name"
            | "jsx_text"
            | "html_character_reference"
            | "string"
            | "string_fragment"
            | "escape_sequence"
            | "number"
            | "regex"
            | "true"
            | "false"
            | "null"
            | "undefined"
            | "this"
            | "super"
            | "meta_property"
            | "optional_chain"
            | "comment"
    )
}

fn has_child_kind(node: Node<'_>, kind: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor).any(|child| child.kind() == kind)
}

fn short_circuit_operator(node: Node<'_>) -> Option<&'static str> {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .find_map(|child| match child.kind() {
            "&&" => Some("&&"),
            "||" => Some("||"),
            "??" => Some("??"),
            _ => None,
        })
}

/// Whether an expression belongs to one continuous optional-chain spine.
/// Only callee/object and transparent TypeScript wrappers are followed: an
/// argument, computed key, or parenthesized expression starts an independent
/// evaluation region and therefore cannot propagate a nullish skip outward.
fn continuous_optional_chain(mut node: Node<'_>) -> bool {
    loop {
        if has_child_kind(node, "?.")
            || node.child_by_field_name("optional_chain").is_some()
            || has_child_kind(node, "optional_chain")
        {
            return true;
        }
        node = match node.kind() {
            "call_expression" => match node.child_by_field_name("function") {
                Some(function) => function,
                None => return false,
            },
            "member_expression" | "subscript_expression" => {
                match node.child_by_field_name("object") {
                    Some(object) => object,
                    None => return false,
                }
            }
            "non_null_expression"
            | "as_expression"
            | "satisfies_expression"
            | "type_assertion"
            | "instantiation_expression" => match node
                .child_by_field_name("expression")
                .or_else(|| first_named_child(node))
            {
                Some(expression) => expression,
                None => return false,
            },
            // Parentheses deliberately terminate propagation. `(value?.x).y`
            // attempts `.y` even when the nested chain produces undefined.
            _ => return false,
        };
    }
}

fn logical_assignment_operator(node: Node<'_>) -> Option<&'static str> {
    let operator = node.child_by_field_name("operator")?;
    match operator.kind() {
        "&&=" => Some("&&="),
        "||=" => Some("||="),
        "??=" => Some("??="),
        _ => None,
    }
}

fn operation_can_throw_implicitly(node: Node<'_>) -> bool {
    match node.kind() {
        "unary_expression"
        | "update_expression"
        | "binary_expression"
        | "augmented_assignment_expression"
        | "template_string" => true,
        "assignment_expression" => node.child_by_field_name("left").is_some_and(|left| {
            matches!(left.kind(), "member_expression" | "subscript_expression")
        }),
        _ => false,
    }
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
