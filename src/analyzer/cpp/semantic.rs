//! C and C++ lowering into the language-neutral executable-semantics IR.
//!
//! This module deliberately interprets tree-sitter nodes and fields directly.
//! Graph construction, abrupt-completion routing, cleanup specialization, and
//! physical adjacency storage remain owned by the shared semantic substrate.

use std::sync::Arc;

use tree_sitter::Node;

use crate::analyzer::semantic::cfg::{
    CompletionKind, CompletionRequest, DriveError, ProcedureCfgBuilder, ScopeBinding, ScopeFrameId,
};
use crate::analyzer::semantic::service::{ProgramSemanticsLowerer, SemanticAdapterIdentity};
use crate::analyzer::semantic::*;
use crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree;
use crate::analyzer::{CppAnalyzer, ProjectFile};
use crate::hash::{HashMap, HashSet};

const ADAPTER_VERSION: &[u8] = b"cpp-cfg-v1";

impl ProgramSemanticsProvider for CppAnalyzer {
    fn current_artifact_key(
        &self,
        file: &ProjectFile,
        max_source_bytes: usize,
    ) -> Result<Option<SemanticArtifactKey>, SemanticProviderError> {
        self.inner.current_semantic_artifact_key_with_lowerer(
            &CppSemanticLowerer,
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
            .materialize_semantics_with_lowerer(&CppSemanticLowerer, file, request)
    }
}

struct CppSemanticLowerer;

impl ProgramSemanticsLowerer for CppSemanticLowerer {
    fn identity(&self) -> SemanticAdapterIdentity {
        SemanticAdapterIdentity {
            adapter: AdapterSemanticsVersion::hash_bytes("cpp", ADAPTER_VERSION)
                .expect("adapter name is non-empty"),
            configuration: ConfigurationFingerprint::hash_bytes(
                b"cpp-intrafile-execution-defaults-v1",
            ),
            dependencies: DependencyFingerprint::hash_bytes(b"no-intrafile-dependencies"),
        }
    }

    fn capabilities(&self) -> SemanticCapabilities {
        cpp_capabilities()
    }

    fn lower(
        &self,
        file: &ProjectFile,
        prepared: &PreparedSyntaxTree,
        budget: &SemanticBudget,
        cancellation: &CancellationToken,
    ) -> Result<SemanticOutcome<Vec<ProcedureSemanticsParts>>, SemanticProviderError> {
        let (specs, enumeration_work) =
            match enumerate_procedures(file, prepared, budget, cancellation)? {
                ProcedureEnumeration::Complete { specs, work } => (specs, work),
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
                lower_procedure(prepared, spec, staged_budget, cancellation)
            },
        )
    }
}

fn cpp_capabilities() -> SemanticCapabilities {
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
        SemanticCapability::Assignments,
        SemanticCapability::Allocations,
        SemanticCapability::Calls,
        SemanticCapability::DynamicDispatch,
        SemanticCapability::Captures,
        SemanticCapability::CallableReferences,
        SemanticCapability::Values,
        SemanticCapability::NonLocalControl,
        SemanticCapability::ResourceManagement,
        SemanticCapability::DeferredExecution,
        SemanticCapability::ConcurrentSpawn,
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
    callable: Node<'tree>,
    locator: SemanticLocator,
    lexical_parent: Option<ProcedureId>,
    kind: ProcedureKind,
    properties: ProcedureProperties,
    has_implicit_object_context: bool,
    has_raii_boundaries: bool,
    has_vla_boundaries: bool,
    has_preprocessing: bool,
    has_syntax_errors: bool,
    noexcept: NoexceptSpecification,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoexceptSpecification {
    MayThrow,
    Unconditional,
    Conditional,
}

enum ProcedureEnumeration<'tree> {
    Complete {
        specs: Vec<ProcedureSpec<'tree>>,
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
    member_context: bool,
}

#[derive(Default)]
struct CallablePreflight {
    work: SemanticWork,
    has_raii_boundaries: bool,
    has_vla_boundaries: bool,
    has_preprocessing: bool,
    has_syntax_errors: bool,
    is_async: bool,
    is_generator: bool,
}

enum CallablePreflightStop {
    ExceededBudget {
        exceeded: SemanticBudgetExceeded,
        work: Box<SemanticWork>,
    },
    Cancelled {
        work: Box<SemanticWork>,
    },
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
    let is_c_source = file
        .rel_path()
        .extension()
        .and_then(|extension| extension.to_str())
        == Some("c");
    let root = prepared.tree().root_node();
    let file_anchor = source_anchor(root, 0).map_err(SemanticProviderError::invalid_identity)?;
    let file_name = file
        .rel_path()
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("cpp-source");
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
    let mut traversal_work = SemanticWork::default();
    let mut stack = vec![ProcedureEnumerationFrame {
        node: root,
        lexical_parent: None,
        declaration_path: 0,
        member_context: false,
    }];

    while let Some(frame) = stack.pop() {
        if cancellation.is_cancelled() {
            return Ok(ProcedureEnumeration::Cancelled {
                work: sum_lowering_work(preflight, traversal_work),
            });
        }

        // Enumeration itself is an iterative AST walk with one retained stack
        // entry per pending node. Bound that work even in files that contain no
        // callable declarations, instead of charging only when a procedure is
        // eventually discovered.
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

        let mut child_path = frame.declaration_path;
        let mut child_member_context = frame.member_context;
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
            child_member_context = segment_kind == DeclarationSegmentKind::Type;
        }

        let shape = callable_shape(
            prepared.source(),
            frame.node,
            frame.lexical_parent,
            frame.member_context,
        )
        .or_else(|| {
            let synthetic_initializer = executable_initializer(frame.node)
                || (!is_c_source
                    && !frame.member_context
                    && declaration_may_construct_object(frame.node));
            (frame.lexical_parent.is_none() && synthetic_initializer).then(|| {
                (
                    ProcedureKind::Initializer,
                    DeclarationSegmentKind::Initializer,
                    frame.node,
                    ProcedureProperties {
                        is_static: !frame.member_context
                            || has_storage_class(prepared.source(), frame.node, "static"),
                        is_synthetic: true,
                        ..ProcedureProperties::default()
                    },
                )
            })
        });

        let mut callable_body_scope = None;
        if let Some((kind, segment_kind, body, mut properties)) = shape {
            let scan = match callable_preflight(
                frame.node,
                is_c_source,
                budget,
                sum_lowering_work(preflight, traversal_work),
                cancellation,
            ) {
                Ok(scan) => scan,
                Err(CallablePreflightStop::ExceededBudget { exceeded, work }) => {
                    return Ok(ProcedureEnumeration::ExceededBudget {
                        exceeded,
                        work: *work,
                    });
                }
                Err(CallablePreflightStop::Cancelled { work }) => {
                    return Ok(ProcedureEnumeration::Cancelled { work: *work });
                }
            };
            traversal_work = sum_lowering_work(traversal_work, scan.work);
            properties.is_async = scan.is_async;
            properties.is_generator = scan.is_generator;
            properties.invocation = if scan.is_async || scan.is_generator {
                ProcedureInvocationKind::Deferred
            } else {
                ProcedureInvocationKind::Immediate
            };
            let parent_has_implicit_object_context = frame
                .lexical_parent
                .and_then(|parent| specs.get(parent.index()))
                .is_some_and(|parent| parent.has_implicit_object_context);
            let qualified_callable = frame
                .node
                .child_by_field_name("declarator")
                .and_then(qualified_declarator)
                .is_some();
            let has_implicit_object_context = !properties.is_static
                && match kind {
                    ProcedureKind::Method | ProcedureKind::Constructor => true,
                    ProcedureKind::Operator => frame.member_context || qualified_callable,
                    ProcedureKind::Initializer => frame.member_context,
                    ProcedureKind::Lambda => parent_has_implicit_object_context,
                    _ => false,
                };
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
            let total_candidate = sum_lowering_work(traversal_work, candidate);
            if let Err(exceeded) = budget.check(total_candidate) {
                return Ok(ProcedureEnumeration::ExceededBudget {
                    exceeded,
                    work: total_candidate,
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
                has_implicit_object_context,
                has_raii_boundaries: scan.has_raii_boundaries,
                has_vla_boundaries: scan.has_vla_boundaries,
                has_preprocessing: scan.has_preprocessing || has_preprocessing_ancestor(frame.node),
                has_syntax_errors: scan.has_syntax_errors,
                noexcept: noexcept_specification(frame.node),
            });
            let callable_path = push_declaration_path(&mut declaration_paths, child_path, segment);
            let direct_body = (body.id() != frame.node.id()).then_some(body.id());
            callable_body_scope = Some((direct_body, id, callable_path));
        }

        let children = named_children(frame.node);
        for child in children.into_iter().rev() {
            let callable_child = callable_body_scope
                .filter(|(body_id, _, _)| body_id.is_none_or(|body_id| body_id == child.id()));
            let (lexical_parent, declaration_path) = callable_child
                .map(|(_, procedure, path)| (Some(procedure), path))
                .unwrap_or((frame.lexical_parent, child_path));
            stack.push(ProcedureEnumerationFrame {
                node: child,
                lexical_parent,
                declaration_path,
                member_context: if callable_child.is_some() {
                    false
                } else {
                    child_member_context
                },
            });
        }
    }

    Ok(ProcedureEnumeration::Complete {
        specs,
        work: sum_lowering_work(preflight, traversal_work),
    })
}

fn callable_preflight(
    root: Node<'_>,
    is_c_source: bool,
    budget: &SemanticBudget,
    observed: SemanticWork,
    cancellation: &CancellationToken,
) -> Result<CallablePreflight, CallablePreflightStop> {
    let mut result = CallablePreflight {
        has_raii_boundaries: !is_c_source
            && callable_name_node(root).is_some_and(|name| name.kind() == "destructor_name"),
        ..CallablePreflight::default()
    };
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if cancellation.is_cancelled() {
            return Err(CallablePreflightStop::Cancelled {
                work: Box::new(sum_lowering_work(observed, result.work)),
            });
        }
        let candidate = sum_lowering_work(
            result.work,
            SemanticWork {
                nested_entries: 1,
                ..SemanticWork::default()
            },
        );
        let total = sum_lowering_work(observed, candidate);
        if let Err(exceeded) = budget.check(total) {
            return Err(CallablePreflightStop::ExceededBudget {
                exceeded,
                work: Box::new(total),
            });
        }
        result.work = candidate;

        if node.id() != root.id()
            && matches!(node.kind(), "function_definition" | "lambda_expression")
        {
            continue;
        }
        result.has_preprocessing |= node.kind().starts_with("preproc_");
        result.has_syntax_errors |= node.kind() == "ERROR";
        result.is_async |= matches!(
            node.kind(),
            "co_await_expression" | "co_return_statement" | "co_yield_statement"
        );
        result.is_generator |= node.kind() == "co_yield_statement";
        if is_c_source
            && matches!(
                node.kind(),
                "declaration" | "field_declaration" | "parameter_declaration"
            )
            && declarator_bound_expressions(node)
                .into_iter()
                .any(|bound| !matches!(bound.kind(), "number_literal" | "char_literal"))
        {
            result.has_vla_boundaries = true;
        }
        if !is_c_source {
            result.has_raii_boundaries |= matches!(
                node.kind(),
                "declaration"
                    | "field_declaration"
                    | "init_declarator"
                    | "call_expression"
                    | "new_expression"
                    | "compound_literal_expression"
            );
            if node.kind() == "parameter_declaration" {
                let ty = node
                    .child_by_field_name("type")
                    .or_else(|| first_named_child(node));
                result.has_raii_boundaries |= ty.is_none_or(|ty| ty.kind() != "primitive_type");
            }
        }
        stack.extend(named_children(node));
    }
    Ok(result)
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
        "namespace_definition" => Some(DeclarationSegmentKind::Namespace),
        "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier" => {
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
    match node.kind() {
        "function_definition" => node
            .child_by_field_name("declarator")
            .and_then(declarator_name_node)
            .and_then(|name| nonempty_node_text(source, name))
            .map(Box::<str>::from),
        "lambda_expression" => enclosing_initializer_name(source, node),
        "declaration" | "field_declaration" => initializer_declarator(node)
            .and_then(declarator_name_node)
            .and_then(|name| nonempty_node_text(source, name))
            .map(Box::<str>::from)
            .map(|name| format!("<initializer:{name}>").into_boxed_str()),
        _ => None,
    }
}

fn enclosing_initializer_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    let mut value = node;
    loop {
        let parent = value.parent()?;
        match parent.kind() {
            "parenthesized_expression" => value = parent,
            "init_declarator" if field_matches(parent, "value", value) => {
                return parent
                    .child_by_field_name("declarator")
                    .and_then(declarator_name_node)
                    .and_then(|name| nonempty_node_text(source, name))
                    .map(Box::<str>::from);
            }
            "assignment_expression" if field_matches(parent, "right", value) => {
                return parent
                    .child_by_field_name("left")
                    .and_then(declarator_name_node)
                    .and_then(|name| nonempty_node_text(source, name))
                    .map(Box::<str>::from);
            }
            _ => return None,
        }
    }
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
)> {
    match node.kind() {
        "function_definition" => {
            node.child_by_field_name("body")?;
            let kind = function_kind(source, node, lexical_parent, member_context);
            let segment_kind = match kind {
                ProcedureKind::Constructor => DeclarationSegmentKind::Constructor,
                ProcedureKind::Method | ProcedureKind::Operator => DeclarationSegmentKind::Method,
                ProcedureKind::LocalFunction => DeclarationSegmentKind::LocalFunction,
                _ => DeclarationSegmentKind::Function,
            };
            Some((
                kind,
                segment_kind,
                // Include constructor initializer lists and function-try-block structure.
                node,
                ProcedureProperties {
                    is_static: has_storage_class(source, node, "static"),
                    is_synthetic: false,
                    ..ProcedureProperties::default()
                },
            ))
        }
        "lambda_expression" => {
            let body = node.child_by_field_name("body")?;
            Some((
                ProcedureKind::Lambda,
                DeclarationSegmentKind::Lambda,
                body,
                ProcedureProperties {
                    is_static: false,
                    is_synthetic: false,
                    ..ProcedureProperties::default()
                },
            ))
        }
        _ => None,
    }
}

fn noexcept_specification(callable: Node<'_>) -> NoexceptSpecification {
    let mut declarator = callable.child_by_field_name("declarator");
    while let Some(node) = declarator {
        if let Some(specification) = named_children(node)
            .into_iter()
            .find(|child| child.kind() == "noexcept")
        {
            let Some(condition) = first_named_child(specification) else {
                return NoexceptSpecification::Unconditional;
            };
            return match condition.kind() {
                "true" => NoexceptSpecification::Unconditional,
                "false" => NoexceptSpecification::MayThrow,
                _ => NoexceptSpecification::Conditional,
            };
        }
        declarator = node.child_by_field_name("declarator");
    }
    NoexceptSpecification::MayThrow
}

fn function_kind(
    source: &str,
    node: Node<'_>,
    lexical_parent: Option<ProcedureId>,
    member_context: bool,
) -> ProcedureKind {
    let declarator = node.child_by_field_name("declarator");
    let name = declarator.and_then(declarator_name_node);
    if name.is_some_and(|name| matches!(name.kind(), "operator_name" | "operator_cast")) {
        return ProcedureKind::Operator;
    }
    if name.is_some_and(|name| name.kind() == "destructor_name") {
        return ProcedureKind::Method;
    }
    let scoped_member = declarator.and_then(qualified_declarator).is_some();
    if member_context || scoped_member {
        if node.child_by_field_name("type").is_none()
            && constructor_name_matches_scope(source, declarator)
        {
            ProcedureKind::Constructor
        } else {
            ProcedureKind::Method
        }
    } else if lexical_parent.is_some() {
        ProcedureKind::LocalFunction
    } else {
        ProcedureKind::Function
    }
}

fn constructor_name_matches_scope(source: &str, declarator: Option<Node<'_>>) -> bool {
    let Some(qualified) = declarator.and_then(qualified_declarator) else {
        // In-class functions without a return type are constructors.
        return true;
    };
    let scope = qualified
        .child_by_field_name("scope")
        .and_then(declarator_name_node);
    let name = qualified
        .child_by_field_name("name")
        .and_then(declarator_name_node);
    match (scope, name) {
        (Some(scope), Some(name)) => node_text(source, scope) == node_text(source, name),
        _ => false,
    }
}

fn qualified_declarator(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        match node.kind() {
            "qualified_identifier" => return Some(node),
            "function_declarator"
            | "pointer_declarator"
            | "array_declarator"
            | "init_declarator"
            | "attributed_declarator" => node = node.child_by_field_name("declarator")?,
            "reference_declarator" | "parenthesized_declarator" => {
                node = first_named_child(node)?;
            }
            _ => return None,
        }
    }
}

fn declarator_name_node(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        match node.kind() {
            "identifier"
            | "field_identifier"
            | "namespace_identifier"
            | "type_identifier"
            | "destructor_name"
            | "operator_name"
            | "operator_cast"
            | "primitive_type" => return Some(node),
            "qualified_identifier" => {
                node = last_named_field_child(node, "name")?;
            }
            "dependent_name" | "template_function" | "template_method" | "template_type" => {
                node = node.child_by_field_name("name")?;
            }
            "function_declarator"
            | "pointer_declarator"
            | "array_declarator"
            | "init_declarator"
            | "attributed_declarator" => node = node.child_by_field_name("declarator")?,
            "reference_declarator" | "parenthesized_declarator" => {
                node = first_named_child(node)?;
            }
            _ => return None,
        }
    }
}

fn last_named_field_child<'tree>(node: Node<'tree>, field: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.children_by_field_name(field, &mut cursor)
        .filter(|child| child.is_named())
        .last()
}

fn initializer_declarator(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("declarator")
        .and_then(|declarator| {
            if declarator.kind() == "init_declarator" {
                declarator.child_by_field_name("declarator")
            } else {
                Some(declarator)
            }
        })
}

fn executable_initializer(node: Node<'_>) -> bool {
    matches!(node.kind(), "declaration" | "field_declaration")
        && !initializer_values(node).is_empty()
}

fn has_storage_class(source: &str, node: Node<'_>, expected: &str) -> bool {
    named_children(node).into_iter().any(|child| {
        child.kind() == "storage_class_specifier"
            && node_text(source, child).is_some_and(|text| text == expected)
    })
}

fn has_preprocessing_ancestor(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if parent.kind().starts_with("preproc_") {
            return true;
        }
        node = parent;
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

type CppLoweringError = ProcedureLoweringError;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct GapFact {
    point: ProgramPointId,
    subject: SemanticGapSubject,
    capability: SemanticCapability,
}

struct LoweringContext<'tree, 'targets> {
    source: &'tree str,
    session: ProcedureLoweringSession<'targets>,
    labels: HashMap<Box<str>, ProgramPointId>,
    switch_case_entries: HashMap<usize, ProgramPointId>,
    published_gaps: HashSet<GapFact>,
    root_body_id: usize,
    is_synthetic_procedure: bool,
    has_implicit_object_context: bool,
    raii_possible: bool,
    vla_possible: bool,
}

fn lower_procedure<'tree>(
    prepared: &'tree PreparedSyntaxTree,
    spec: &ProcedureSpec<'tree>,
    budget: &SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<(ProcedureSemanticsParts, SemanticWork), CppLoweringError> {
    let mut parts = ProcedureSemanticsParts::new(
        spec.id,
        spec.locator.clone(),
        spec.kind,
        SourceMappingId::new(0),
        EvidenceId::new(0),
    );
    parts.lexical_parent = spec.lexical_parent;
    parts.properties = spec.properties;
    let (
        ProcedureLoweringStart {
            mut builder,
            session,
            entry,
            normal_exit,
            exceptional_exit,
            function_scope,
        },
        noexcept_termination,
    ) = ProcedureLoweringSession::start_with_function_throw_boundary(
        parts,
        budget,
        cancellation,
        spec.noexcept == NoexceptSpecification::Unconditional,
    )?;
    let mut context = LoweringContext {
        source: prepared.source(),
        session,
        labels: HashMap::default(),
        switch_case_entries: HashMap::default(),
        published_gaps: HashSet::default(),
        root_body_id: spec
            .body
            .child_by_field_name("body")
            .unwrap_or(spec.body)
            .id(),
        is_synthetic_procedure: spec.properties.is_synthetic,
        has_implicit_object_context: spec.has_implicit_object_context,
        raii_possible: spec.has_raii_boundaries,
        vla_possible: spec.has_vla_boundaries,
    };

    context.register_labels(&mut builder, spec.body)?;

    if spec.properties.is_synthetic {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::DeferredExecution,
            SemanticGapKind::Unknown,
            "translation-unit, static, and member initialization scheduling is not stitched across initializer fragments",
        )?;
    }
    if spec.has_preprocessing {
        for (capability, detail) in [
            (
                SemanticCapability::NormalControlFlow,
                "the active preprocessor branch depends on translation-unit configuration",
            ),
            (
                SemanticCapability::Calls,
                "macro expansion and conditionally compiled calls are unavailable without an exact preprocessing configuration",
            ),
            (
                SemanticCapability::CallableReferences,
                "macro-expanded callable references are not fabricated from source text",
            ),
        ] {
            let impacts = SemanticGapImpacts::for_gap(capability, SemanticGapSubject::Procedure);
            let impacts = if matches!(
                capability,
                SemanticCapability::Calls | SemanticCapability::CallableReferences
            ) {
                impacts.with(SemanticGapImpact::DispatchCoverage)
            } else {
                impacts
            };
            context.add_gap_with_impacts(
                &mut builder,
                entry,
                SemanticGapSubject::Procedure,
                capability,
                impacts,
                SemanticGapKind::Unsupported,
                detail,
            )?;
        }
    }
    if spec.has_syntax_errors {
        for (capability, detail) in [
            (
                SemanticCapability::NormalControlFlow,
                "tree-sitter retained an ERROR node in this callable, so omitted or misclassified control syntax may affect topology",
            ),
            (
                SemanticCapability::Calls,
                "calls nested in parser-error regions may not be retained as exact semantic call sites",
            ),
            (
                SemanticCapability::ResourceManagement,
                "object and VLA lifetimes across parser-error regions cannot be delimited exactly",
            ),
        ] {
            let impacts = SemanticGapImpacts::for_gap(capability, SemanticGapSubject::Procedure);
            context.add_gap_with_impacts(
                &mut builder,
                entry,
                SemanticGapSubject::Procedure,
                capability,
                impacts,
                SemanticGapKind::Unsupported,
                detail,
            )?;
        }
    }
    if spec.properties.is_async {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::DeferredExecution,
            SemanticGapKind::Unsupported,
            "C++ coroutine invocation constructs a resumable frame; initial suspend and scheduler behavior are not stitched",
        )?;
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::AsyncSuspendResume,
            SemanticGapKind::Unsupported,
            "coroutine suspension, resumption, promise callbacks, and symmetric transfer are not lowered",
        )?;
    }
    if spec.properties.is_generator {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::GeneratorSuspension,
            SemanticGapKind::Unsupported,
            "co_yield promise interaction and repeated resumption are not lowered",
        )?;
    }

    match spec.noexcept {
        NoexceptSpecification::MayThrow => {}
        NoexceptSpecification::Unconditional => {
            let termination = noexcept_termination.expect("unconditional noexcept terminal");
            for (subject, point) in [
                (SemanticGapSubject::Procedure, entry),
                (SemanticGapSubject::Point, termination),
            ] {
                for (capability, detail) in [
                    (
                        SemanticCapability::ExceptionalControlFlow,
                        "an exception escaping an unconditional noexcept callable terminates instead of returning exceptionally",
                    ),
                    (
                        SemanticCapability::NonLocalControl,
                        "std::terminate ends ordinary control flow and its handler behavior is not expanded",
                    ),
                    (
                        SemanticCapability::Calls,
                        "the implicit std::terminate invocation and installed terminate handler are not fabricated as call sites",
                    ),
                ] {
                    context.add_gap(
                        &mut builder,
                        point,
                        subject,
                        capability,
                        SemanticGapKind::Unknown,
                        detail,
                    )?;
                }
            }
        }
        NoexceptSpecification::Conditional => {
            for (subject, point) in [
                (SemanticGapSubject::Procedure, entry),
                (SemanticGapSubject::Point, exceptional_exit),
            ] {
                for (capability, detail) in [
                    (
                        SemanticCapability::ExceptionalControlFlow,
                        "the conditional noexcept specification requires constant evaluation before deciding between exceptional return and termination",
                    ),
                    (
                        SemanticCapability::NonLocalControl,
                        "the conditionally possible std::terminate path is not selected without constant-evaluation refinement",
                    ),
                    (
                        SemanticCapability::Calls,
                        "a conditionally possible implicit std::terminate invocation and terminate handler are not fabricated as call sites",
                    ),
                ] {
                    context.add_gap(
                        &mut builder,
                        point,
                        subject,
                        capability,
                        SemanticGapKind::Unknown,
                        detail,
                    )?;
                }
            }
        }
    }

    if spec.has_raii_boundaries {
        context.add_raii_gaps(
            &mut builder,
            normal_exit,
            "automatic objects may be destroyed at normal procedure exit",
        )?;
        context.add_raii_gaps(
            &mut builder,
            exceptional_exit,
            "automatic objects may be destroyed while unwinding from the procedure",
        )?;
    }
    if spec.has_vla_boundaries {
        context.add_vla_cleanup_gaps(
            &mut builder,
            normal_exit,
            SemanticGapSubject::Point,
            "normal procedure exit may end the lifetime of variably modified automatic arrays",
        )?;
        context.add_vla_cleanup_gaps(
            &mut builder,
            exceptional_exit,
            SemanticGapSubject::Point,
            "abnormal procedure exit may end the lifetime of variably modified automatic arrays",
        )?;
        context.add_vla_cleanup_gaps(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            "variably modified declarations require runtime storage and scope-exit refinement",
        )?;
    }
    if spec.kind == ProcedureKind::Constructor {
        context.add_implicit_lifetime_call_gaps(
            &mut builder,
            entry,
            "implicit base/member construction and default member initialization",
        )?;
    }
    if callable_name_node(spec.callable).is_some_and(|name| name.kind() == "destructor_name") {
        context.add_implicit_lifetime_call_gaps(
            &mut builder,
            entry,
            "implicit base/member destruction and virtual-destructor behavior",
        )?;
    }

    let body_entry = context.point(&mut builder, spec.body, Vec::new())?;
    context.edge(&mut builder, entry, EdgeTarget::normal(body_entry))?;
    let mut pending = vec![Work::Statement {
        node: spec.body,
        entry: body_entry,
        next: EdgeTarget::normal(normal_exit),
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
            DriveError::Cancelled | DriveError::Step(CppLoweringError::Cancelled(_)) => {
                Err(CppLoweringError::Cancelled(Box::new(work)))
            }
            DriveError::ExceededBudget(exceeded) => {
                Err(CppLoweringError::Budget(exceeded, Box::new(work)))
            }
            DriveError::Step(CppLoweringError::Budget(exceeded, _)) => {
                Err(CppLoweringError::Budget(exceeded, Box::new(work)))
            }
            DriveError::Step(CppLoweringError::Invalid(detail)) => {
                Err(CppLoweringError::Invalid(detail))
            }
        };
    }

    if builder
        .seal_unreachable_regions(entry, normal_exit, exceptional_exit, cancellation)
        .is_err()
    {
        return Err(CppLoweringError::Cancelled(Box::new(
            builder.prospective_work(),
        )));
    }
    let work_before_freeze = builder.prospective_work();
    builder
        .finish_with_work()
        .map_err(|error| CppLoweringError::Budget(error, Box::new(work_before_freeze)))
}

impl<'tree, 'targets> LoweringContext<'tree, 'targets> {
    fn step(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        work: Work<'tree>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CppLoweringError> {
        if self.session.cancellation().is_cancelled() {
            return Err(CppLoweringError::Cancelled(Box::default()));
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
    ) -> Result<(), CppLoweringError> {
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
            ("conditional_expression", _) => {
                let predicate = required_field(node, "condition")?;
                let consequence = node.child_by_field_name("consequence");
                let alternative = required_field(node, "alternative")?;
                let alternative_entry = self.point(builder, alternative, Vec::new())?;
                stack.push(Work::Condition {
                    node: alternative,
                    entry: alternative_entry,
                    when_true,
                    when_false,
                    scope,
                });
                let true_target = if let Some(consequence) = consequence {
                    let consequence_entry = self.point(builder, consequence, Vec::new())?;
                    stack.push(Work::Condition {
                        node: consequence,
                        entry: consequence_entry,
                        when_true,
                        when_false,
                        scope,
                    });
                    EdgeTarget {
                        point: consequence_entry,
                        kind: ControlEdgeKind::ConditionalTrue,
                    }
                } else {
                    // GNU's omitted middle operand reuses the already evaluated predicate.
                    when_true
                };
                stack.push(Work::Condition {
                    node: predicate,
                    entry,
                    when_true: true_target,
                    when_false: EdgeTarget {
                        point: alternative_entry,
                        kind: ControlEdgeKind::ConditionalFalse,
                    },
                    scope,
                });
                Ok(())
            }
            ("condition_clause", _) => {
                let value = required_field(node, "value")?;
                if let Some(initializer) = node.child_by_field_name("initializer") {
                    let value_entry = self.point(builder, value, Vec::new())?;
                    stack.push(Work::Condition {
                        node: value,
                        entry: value_entry,
                        when_true,
                        when_false,
                        scope,
                    });
                    stack.push(self.execution_work(
                        initializer,
                        entry,
                        EdgeTarget::normal(value_entry),
                        scope,
                    ));
                } else {
                    stack.push(Work::Condition {
                        node: value,
                        entry,
                        when_true,
                        when_false,
                        scope,
                    });
                }
                Ok(())
            }
            ("declaration", _) => {
                let decision = self.point(builder, node, Vec::new())?;
                if !self.is_c_source() && declaration_may_construct_object(node) {
                    self.add_implicit_operator_gaps(
                        builder,
                        decision,
                        "contextual conversion of a condition-declared object to bool may invoke user-defined code",
                    )?;
                }
                self.edge(builder, decision, when_true)?;
                self.edge(builder, decision, when_false)?;
                stack.push(Work::Statement {
                    node,
                    entry,
                    next: EdgeTarget::normal(decision),
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
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CppLoweringError> {
        match node.kind() {
            "function_definition" => {
                let executable = function_execution_nodes(node);
                self.schedule_execution_nodes(builder, entry, &executable, next, scope, stack)
            }
            "compound_statement" | "translation_unit" => {
                let children = named_children(node)
                    .into_iter()
                    .filter(|child| is_statement_or_declaration(child.kind()))
                    .collect::<Vec<_>>();
                let nested_scope =
                    node.kind() == "compound_statement" && node.id() != self.root_body_id;
                let has_raii_cleanup = nested_scope
                    && !self.is_c_source()
                    && block_has_automatic_object(self.source, node);
                let has_vla_cleanup =
                    nested_scope && self.is_c_source() && block_has_potential_vla(node);
                if has_raii_cleanup || has_vla_cleanup {
                    let scope_exit = self.point(builder, node, Vec::new())?;
                    if has_raii_cleanup {
                        self.add_raii_gaps(
                            builder,
                            scope_exit,
                            "normal block exit may destroy automatic objects declared in this lexical scope",
                        )?;
                    }
                    if has_vla_cleanup {
                        self.add_vla_cleanup_gaps(
                            builder,
                            scope_exit,
                            SemanticGapSubject::Point,
                            "normal block exit may release variably modified automatic array storage declared in this lexical scope",
                        )?;
                    }
                    self.edge(builder, scope_exit, next)?;
                    self.schedule_execution_nodes(
                        builder,
                        entry,
                        &children,
                        EdgeTarget::normal(scope_exit),
                        scope,
                        stack,
                    )
                } else {
                    self.schedule_execution_nodes(builder, entry, &children, next, scope, stack)
                }
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
            "init_statement" => {
                let children = initializer_values(node);
                self.schedule_execution_nodes(builder, entry, &children, next, scope, stack)
            }
            "declaration"
            | "field_declaration"
            | "field_initializer_list"
            | "field_initializer" => {
                let initializers = initializer_values(node);
                let values = declaration_runtime_expressions(node);
                if !initializers.is_empty()
                    && matches!(node.kind(), "declaration" | "field_declaration")
                {
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::Assignments,
                        SemanticGapKind::Unknown,
                        "initializer-to-object value transfer and aliasing are not represented",
                    )?;
                }
                if node.kind() == "field_initializer_list" && initializers.len() > 1 {
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::NormalControlFlow,
                        SemanticGapKind::Unknown,
                        "constructor initializers execute in base/member declaration order, which is unavailable here; written order is only a bounded lowering order",
                    )?;
                }
                if !self.is_c_source() && declaration_may_construct_object(node) {
                    self.add_implicit_lifetime_call_gaps(
                        builder,
                        entry,
                        "object initialization may invoke constructors or conversion functions",
                    )?;
                }
                if !self.is_c_source()
                    && !initializers.is_empty()
                    && declaration_constructs_thread(self.source, node)
                {
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::ConcurrentSpawn,
                        SemanticGapKind::Unknown,
                        "thread-object construction may spawn an execution context, but its entry, scheduling, lifetime, and join relation are not stitched into the ICFG",
                    )?;
                }
                if self.is_function_local_static(node, &values) {
                    self.function_local_static_declaration(
                        builder, node, entry, &values, next, scope, stack,
                    )
                } else {
                    self.schedule_expressions(builder, entry, &values, next, scope, stack)
                }
            }
            "return_statement" | "co_return_statement" => {
                let value_node = first_runtime_named_child(node);
                let terminal = if let Some(value_node) = value_node {
                    let terminal = self.point(builder, node, Vec::new())?;
                    let value = self.value(builder, terminal, SemanticValueKind::Return)?;
                    self.append_effect(
                        builder,
                        terminal,
                        SemanticEffect::ProcedureReturn { value: Some(value) },
                    )?;
                    stack.push(Work::Expression {
                        node: value_node,
                        entry,
                        next: EdgeTarget::normal(terminal),
                        scope,
                    });
                    terminal
                } else {
                    self.append_effect(
                        builder,
                        entry,
                        SemanticEffect::ProcedureReturn { value: None },
                    )?;
                    entry
                };
                if node.kind() == "co_return_statement" {
                    self.add_coroutine_gap(
                        builder,
                        terminal,
                        "co_return promise completion and final suspension are not lowered",
                    )?;
                }
                self.abrupt(builder, terminal, scope, CompletionKind::Return, None)
            }
            "throw_statement" => {
                let value_node = first_runtime_named_child(node);
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
                self.abrupt(builder, terminal, scope, CompletionKind::Throw, None)
            }
            "break_statement" | "continue_statement" => {
                let kind = if node.kind() == "break_statement" {
                    CompletionKind::Break
                } else {
                    CompletionKind::Continue
                };
                self.abrupt(builder, entry, scope, kind, None)
            }
            "goto_statement" => self.goto_statement(builder, node, entry),
            "labeled_statement" => {
                let label = required_field(node, "label")?;
                let label_name = node_text(self.source, label)
                    .ok_or_else(|| missing_field(node, "label text"))?;
                let target = self.labels.get(label_name).copied().ok_or_else(|| {
                    CppLoweringError::Invalid(format!(
                        "preallocated C/C++ label {label_name:?} is missing"
                    ))
                })?;
                self.edge(builder, entry, EdgeTarget::normal(target))?;
                let body = named_children(node)
                    .into_iter()
                    .find(|child| child.id() != label.id())
                    .ok_or_else(|| missing_field(node, "body"))?;
                stack.push(self.execution_work(body, target, next, scope));
                Ok(())
            }
            "if_statement" => self.if_statement(builder, node, entry, next, scope, stack),
            "while_statement" => self.while_statement(builder, node, entry, next, scope, stack),
            "do_statement" => self.do_statement(builder, node, entry, next, scope, stack),
            "for_statement" => self.for_statement(builder, node, entry, next, scope, stack),
            "for_range_loop" => self.range_for_statement(builder, node, entry, next, scope, stack),
            "switch_statement" => self.switch_statement(builder, node, entry, next, scope, stack),
            "case_statement" => {
                let children = case_runtime_children(node);
                self.schedule_execution_nodes(builder, entry, &children, next, scope, stack)
            }
            "try_statement" => self.try_statement(builder, node, entry, next, scope, stack),
            "co_yield_statement" => {
                let value = first_runtime_named_child(node);
                let suspend = self.point(builder, node, Vec::new())?;
                self.add_coroutine_gap(
                    builder,
                    suspend,
                    "co_yield promise interaction, suspension, and resumption are not lowered",
                )?;
                self.add_gap(
                    builder,
                    suspend,
                    SemanticGapSubject::Point,
                    SemanticCapability::GeneratorSuspension,
                    SemanticGapKind::Unsupported,
                    "co_yield suspension and repeated resumption are not represented",
                )?;
                self.edge(builder, suspend, next)?;
                if let Some(value) = value {
                    stack.push(Work::Expression {
                        node: value,
                        entry,
                        next: EdgeTarget::normal(suspend),
                        scope,
                    });
                } else {
                    self.edge(builder, entry, EdgeTarget::normal(suspend))?;
                }
                Ok(())
            }
            kind if kind.starts_with("preproc_") => {
                self.preprocessor_region(builder, node, entry, next, scope, stack)
            }
            "seh_try_statement" => self.seh_try_statement(builder, node, entry, next, scope, stack),
            "seh_leave_statement" => self.seh_leave_statement(builder, entry),
            "attributed_statement" | "else_clause" => {
                if let Some(body) = first_runtime_named_child(node) {
                    stack.push(self.execution_work(body, entry, next, scope));
                    Ok(())
                } else {
                    self.edge(builder, entry, next)
                }
            }
            "empty_statement"
            | "template_declaration"
            | "namespace_definition"
            | "class_specifier"
            | "struct_specifier"
            | "union_specifier"
            | "enum_specifier"
            | "type_definition"
            | "alias_declaration"
            | "using_declaration"
            | "static_assert_declaration"
            | "attribute_declaration" => self.edge(builder, entry, next),
            _ if is_cpp_expression(node.kind()) => {
                stack.push(Work::Expression {
                    node,
                    entry,
                    next,
                    scope,
                });
                Ok(())
            }
            _ => self.unhandled_control_syntax(builder, node, entry, next),
        }
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
    ) -> Result<(), CppLoweringError> {
        let condition = required_field(node, "condition")?;
        let completion = if !self.is_c_source()
            && syntax_has_automatic_object(self.source, condition)
        {
            EdgeTarget::normal(self.normal_cleanup_boundary(
                builder,
                condition,
                next,
                "normal if-statement completion may destroy objects declared by its initializer or condition",
            )?)
        } else {
            next
        };
        if has_direct_token(node, "constexpr") || has_direct_token(node, "consteval") {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::NormalControlFlow,
                SemanticGapKind::Unsupported,
                "if constexpr/consteval discarded-statement selection requires compile-time evaluation",
            )?;
        }
        let consequence = required_field(node, "consequence")?;
        let consequence_entry = self.point(builder, consequence, Vec::new())?;
        stack.push(self.execution_work(consequence, consequence_entry, completion, scope));
        let when_false = if let Some(alternative) = node.child_by_field_name("alternative") {
            let body = first_runtime_named_child(alternative).unwrap_or(alternative);
            let alternative_entry = self.point(builder, body, Vec::new())?;
            stack.push(self.execution_work(body, alternative_entry, completion, scope));
            EdgeTarget {
                point: alternative_entry,
                kind: ControlEdgeKind::ConditionalFalse,
            }
        } else {
            EdgeTarget {
                point: completion.point,
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
    fn while_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CppLoweringError> {
        let condition = required_field(node, "condition")?;
        let body = required_field(node, "body")?;
        let condition_entry = self.point(builder, condition, Vec::new())?;
        let body_entry = self.point(builder, body, Vec::new())?;
        let condition_declares_object =
            !self.is_c_source() && syntax_has_automatic_object(self.source, condition);
        let exit_target = if condition_declares_object {
            EdgeTarget::normal(self.normal_cleanup_boundary(
                builder,
                condition,
                next,
                "leaving a while statement may destroy an object declared by its condition",
            )?)
        } else {
            next
        };
        let iteration_target = if condition_declares_object {
            EdgeTarget {
                point: self.normal_cleanup_boundary(
                    builder,
                    condition,
                    EdgeTarget {
                        point: condition_entry,
                        kind: ControlEdgeKind::LoopBack,
                    },
                    "finishing a while iteration may destroy an object declared by its condition before reevaluation",
                )?,
                kind: ControlEdgeKind::LoopBack,
            }
        } else {
            EdgeTarget {
                point: condition_entry,
                kind: ControlEdgeKind::LoopBack,
            }
        };
        let loop_scope = builder.push_scope(
            Some(scope),
            ScopeBinding::Loop {
                label: None,
                break_target: exit_target.point,
                break_edge_kind: exit_target.kind,
                continue_target: iteration_target.point,
                continue_edge_kind: ControlEdgeKind::LoopBack,
            },
        );
        stack.push(self.execution_work(body, body_entry, iteration_target, loop_scope));
        stack.push(Work::Condition {
            node: condition,
            entry: condition_entry,
            when_true: EdgeTarget {
                point: body_entry,
                kind: ControlEdgeKind::ConditionalTrue,
            },
            when_false: EdgeTarget {
                point: exit_target.point,
                kind: ControlEdgeKind::ConditionalFalse,
            },
            scope: loop_scope,
        });
        self.edge(builder, entry, EdgeTarget::normal(condition_entry))
    }

    #[allow(clippy::too_many_arguments)]
    fn do_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CppLoweringError> {
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
        stack.push(self.execution_work(
            body,
            entry,
            EdgeTarget::normal(condition_entry),
            loop_scope,
        ));
        Ok(())
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
    ) -> Result<(), CppLoweringError> {
        let body = required_field(node, "body")?;
        let initializer = node.child_by_field_name("initializer");
        let condition = node.child_by_field_name("condition");
        let update = node.child_by_field_name("update");
        let condition_entry = self.point(builder, condition.unwrap_or(node), Vec::new())?;
        let body_entry = self.point(builder, body, Vec::new())?;
        let update_entry = update
            .map(|update| self.point(builder, update, Vec::new()))
            .transpose()?;
        let initializer_declares_object = !self.is_c_source()
            && initializer
                .is_some_and(|initializer| syntax_has_automatic_object(self.source, initializer));
        let condition_declares_object = !self.is_c_source()
            && condition
                .is_some_and(|condition| syntax_has_automatic_object(self.source, condition));
        let initializer_exit = if initializer_declares_object {
            EdgeTarget::normal(self.normal_cleanup_boundary(
                builder,
                initializer.expect("object declaration requires an initializer"),
                next,
                "leaving a for statement may destroy objects declared by its initializer",
            )?)
        } else {
            next
        };
        let loop_exit = if condition_declares_object {
            EdgeTarget::normal(self.normal_cleanup_boundary(
                builder,
                condition.expect("object declaration requires a condition"),
                initializer_exit,
                "leaving a for statement may destroy an object declared by its condition",
            )?)
        } else {
            initializer_exit
        };
        let update_target = update_entry.unwrap_or(condition_entry);
        let iteration_target = if condition_declares_object {
            EdgeTarget {
                point: self.normal_cleanup_boundary(
                    builder,
                    condition.expect("object declaration requires a condition"),
                    EdgeTarget {
                        point: update_target,
                        kind: ControlEdgeKind::LoopBack,
                    },
                    "finishing a for iteration may destroy an object declared by its condition before update and reevaluation",
                )?,
                kind: ControlEdgeKind::LoopBack,
            }
        } else {
            EdgeTarget {
                point: update_target,
                kind: ControlEdgeKind::LoopBack,
            }
        };
        let loop_scope = builder.push_scope(
            Some(scope),
            ScopeBinding::Loop {
                label: None,
                break_target: loop_exit.point,
                break_edge_kind: loop_exit.kind,
                continue_target: iteration_target.point,
                continue_edge_kind: ControlEdgeKind::LoopBack,
            },
        );
        if let Some(update) = update {
            stack.push(Work::Expression {
                node: update,
                entry: update_entry.expect("allocated update entry"),
                next: EdgeTarget {
                    point: condition_entry,
                    kind: ControlEdgeKind::LoopBack,
                },
                scope: loop_scope,
            });
        }
        stack.push(self.execution_work(body, body_entry, iteration_target, loop_scope));
        if let Some(condition) = condition {
            stack.push(Work::Condition {
                node: condition,
                entry: condition_entry,
                when_true: EdgeTarget {
                    point: body_entry,
                    kind: ControlEdgeKind::ConditionalTrue,
                },
                when_false: EdgeTarget {
                    point: loop_exit.point,
                    kind: ControlEdgeKind::ConditionalFalse,
                },
                scope: loop_scope,
            });
        } else {
            self.edge(
                builder,
                condition_entry,
                EdgeTarget {
                    point: body_entry,
                    kind: ControlEdgeKind::ConditionalTrue,
                },
            )?;
        }
        if let Some(initializer) = initializer {
            stack.push(self.execution_work(
                initializer,
                entry,
                EdgeTarget::normal(condition_entry),
                loop_scope,
            ));
            Ok(())
        } else {
            self.edge(builder, entry, EdgeTarget::normal(condition_entry))
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn range_for_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CppLoweringError> {
        let range = required_field(node, "right")?;
        let body = required_field(node, "body")?;
        let initializer = node.child_by_field_name("initializer");
        let test = self.point(builder, node, Vec::new())?;
        let binding = self.point(builder, node, Vec::new())?;
        let body_entry = self.point(builder, body, Vec::new())?;
        let loop_exit = self.normal_cleanup_boundary(
            builder,
            node,
            next,
            "leaving a range-for statement may destroy its hidden range object and initializer-scoped objects",
        )?;
        let binding_requires_cleanup = node
            .child_by_field_name("type")
            .is_none_or(|ty| ty.kind() != "primitive_type");
        let iteration_target = if binding_requires_cleanup {
            EdgeTarget {
                point: self.normal_cleanup_boundary(
                    builder,
                    node,
                    EdgeTarget {
                        point: test,
                        kind: ControlEdgeKind::LoopBack,
                    },
                    "finishing a range-for iteration may destroy the per-iteration loop binding before increment and retest",
                )?,
                kind: ControlEdgeKind::LoopBack,
            }
        } else {
            EdgeTarget {
                point: test,
                kind: ControlEdgeKind::LoopBack,
            }
        };
        let break_target = if binding_requires_cleanup {
            EdgeTarget::normal(self.normal_cleanup_boundary(
                builder,
                node,
                EdgeTarget::normal(loop_exit),
                "breaking from a range-for iteration may destroy the per-iteration loop binding before the hidden range object",
            )?)
        } else {
            EdgeTarget::normal(loop_exit)
        };
        let loop_scope = builder.push_scope(
            Some(scope),
            ScopeBinding::Loop {
                label: None,
                break_target: break_target.point,
                break_edge_kind: break_target.kind,
                continue_target: iteration_target.point,
                continue_edge_kind: ControlEdgeKind::LoopBack,
            },
        );
        for (capability, detail) in [
            (
                SemanticCapability::Calls,
                "range-for begin/end, comparison, increment, and dereference operations may invoke user code and are not emitted as fabricated call sites",
            ),
            (
                SemanticCapability::ExceptionalControlFlow,
                "range-for protocol operations and hidden range binding can throw",
            ),
            (
                SemanticCapability::ResourceManagement,
                "the hidden range object's lifetime and destruction are not fully lowered",
            ),
        ] {
            self.add_gap(
                builder,
                test,
                SemanticGapSubject::Point,
                capability,
                SemanticGapKind::Unknown,
                detail,
            )?;
        }
        self.edge(
            builder,
            test,
            EdgeTarget {
                point: binding,
                kind: ControlEdgeKind::ConditionalTrue,
            },
        )?;
        self.edge(
            builder,
            test,
            EdgeTarget {
                point: loop_exit,
                kind: ControlEdgeKind::ConditionalFalse,
            },
        )?;
        self.edge(builder, binding, EdgeTarget::normal(body_entry))?;
        stack.push(self.execution_work(body, body_entry, iteration_target, loop_scope));
        let range_entry = if let Some(initializer) = initializer {
            let range_entry = self.point(builder, range, Vec::new())?;
            stack.push(Work::Expression {
                node: range,
                entry: range_entry,
                next: EdgeTarget::normal(test),
                scope: loop_scope,
            });
            stack.push(self.execution_work(
                initializer,
                entry,
                EdgeTarget::normal(range_entry),
                loop_scope,
            ));
            return Ok(());
        } else {
            entry
        };
        stack.push(Work::Expression {
            node: range,
            entry: range_entry,
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
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CppLoweringError> {
        let condition = required_field(node, "condition")?;
        let body = required_field(node, "body")?;
        let dispatch = self.point(builder, node, Vec::new())?;
        if !self.is_c_source()
            && condition_value_declaration(condition).is_some_and(declaration_may_construct_object)
        {
            self.add_implicit_operator_gaps(
                builder,
                dispatch,
                "contextual integral or enumeration conversion of a switch condition-declared object may invoke user-defined code",
            )?;
        }
        let completion = if !self.is_c_source()
            && syntax_has_automatic_object(self.source, condition)
        {
            EdgeTarget::normal(self.normal_cleanup_boundary(
                builder,
                condition,
                next,
                "leaving a switch statement may destroy objects declared by its initializer or condition",
            )?)
        } else {
            next
        };
        let cases = switch_cases(body);
        if cases.is_empty() {
            self.edge(builder, dispatch, completion)?;
            stack.push(Work::Expression {
                node: condition,
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
                accepts_unlabeled: true,
                break_target: completion.point,
                break_edge_kind: completion.kind,
            },
        );
        let mut has_default = false;
        for case in &cases {
            has_default |= case.child_by_field_name("value").is_none();
            let case_entry = if let Some(entry) = self.switch_case_entries.get(&case.id()).copied()
            {
                entry
            } else {
                let entry = self.point(builder, *case, Vec::new())?;
                self.switch_case_entries.insert(case.id(), entry);
                entry
            };
            self.edge(
                builder,
                dispatch,
                EdgeTarget {
                    point: case_entry,
                    kind: ControlEdgeKind::SwitchCase,
                },
            )?;
        }
        if !has_default {
            self.edge(
                builder,
                dispatch,
                EdgeTarget {
                    point: completion.point,
                    kind: ControlEdgeKind::ConditionalFalse,
                },
            )?;
        }
        // Lower the lexical switch body exactly once. The body entry is
        // intentionally detached from dispatch; reachability sealing removes
        // its synthetic edge to the first case while preserving the case
        // entries reached directly from the dispatcher.
        let body_entry = self.point(builder, body, Vec::new())?;
        stack.push(self.execution_work(body, body_entry, completion, switch_scope));
        stack.push(Work::Expression {
            node: condition,
            entry,
            next: EdgeTarget::normal(dispatch),
            scope: switch_scope,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn try_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CppLoweringError> {
        let body = required_field(node, "body")?;
        let catches = named_children(node)
            .into_iter()
            .filter(|child| child.kind() == "catch_clause")
            .collect::<Vec<_>>();
        let catch_bodies = catches
            .iter()
            .map(|catch| required_field(*catch, "body"))
            .collect::<Result<Vec<_>, _>>()?;
        let catch_entries = catches
            .iter()
            .map(|catch| self.point(builder, *catch, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        let try_scope = if catch_entries.is_empty() {
            scope
        } else {
            let dispatcher = self.point(builder, node, Vec::new())?;
            self.add_gap(
                builder,
                dispatcher,
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unknown,
                "catch type matching, base conversions, catch-all selection, and exception copying require type refinement",
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
            self.abrupt(builder, unmatched, scope, CompletionKind::Throw, None)?;
            builder.push_scope(Some(scope), ScopeBinding::Handler { entry: dispatcher })
        };

        for ((catch, body), catch_entry) in catches.iter().zip(&catch_bodies).zip(&catch_entries) {
            if catch
                .child_by_field_name("parameters")
                .is_some_and(|parameters| parameters.named_child_count() != 0)
            {
                self.add_gap(
                    builder,
                    *catch_entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::Values,
                    SemanticGapKind::Unknown,
                    "exception object binding, reference semantics, and copy construction are not represented",
                )?;
                self.add_implicit_lifetime_call_gaps(
                    builder,
                    *catch_entry,
                    "catch parameter construction and destruction",
                )?;
            }
            stack.push(self.execution_work(*body, *catch_entry, next, scope));
        }

        let mut try_parts = named_children(node)
            .into_iter()
            .filter(|child| child.kind() == "field_initializer_list" || child.id() == body.id())
            .collect::<Vec<_>>();
        if try_parts.is_empty() {
            try_parts.push(body);
        }
        self.schedule_execution_nodes(builder, entry, &try_parts, next, try_scope, stack)
    }

    #[allow(clippy::too_many_arguments)]
    fn seh_try_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CppLoweringError> {
        for (capability, detail) in [
            (
                SemanticCapability::NormalControlFlow,
                "SEH filter selection, handler acceptance, and leave destinations are not fully lowered",
            ),
            (
                SemanticCapability::ExceptionalControlFlow,
                "Microsoft structured exception dispatch and continuation semantics are unsupported",
            ),
            (
                SemanticCapability::CleanupControlFlow,
                "SEH finally execution during every abrupt completion requires cleanup specialization",
            ),
            (
                SemanticCapability::Calls,
                "OS exception filters and termination/unwind callbacks may invoke code outside explicit source calls",
            ),
            (
                SemanticCapability::NonLocalControl,
                "SEH leave/filter/finally non-local routing is not fully represented",
            ),
            (
                SemanticCapability::ResourceManagement,
                "resource lifetime across SEH unwinding and abnormal termination requires platform semantics",
            ),
        ] {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                capability,
                SemanticGapKind::Unsupported,
                detail,
            )?;
        }

        let body = required_field(node, "body")?;
        let body_entry = self.point(builder, body, Vec::new())?;
        self.edge(builder, entry, EdgeTarget::normal(body_entry))?;
        let clause = named_children(node)
            .into_iter()
            .find(|child| matches!(child.kind(), "seh_except_clause" | "seh_finally_clause"));

        match clause.map(|clause| (clause.kind(), clause)) {
            Some(("seh_finally_clause", clause)) => {
                let finally_body = required_field(clause, "body")?;
                let finally_entry = self.point(builder, clause, Vec::new())?;
                stack.push(self.execution_work(finally_body, finally_entry, next, scope));
                stack.push(self.execution_work(
                    body,
                    body_entry,
                    EdgeTarget::normal(finally_entry),
                    scope,
                ));
                Ok(())
            }
            Some(("seh_except_clause", clause)) => {
                let handler_body = required_field(clause, "body")?;
                let dispatcher = self.point(builder, clause, Vec::new())?;
                let handler_entry = self.point(builder, handler_body, Vec::new())?;
                self.edge(
                    builder,
                    entry,
                    EdgeTarget {
                        point: dispatcher,
                        kind: ControlEdgeKind::Exceptional,
                    },
                )?;
                let try_scope =
                    builder.push_scope(Some(scope), ScopeBinding::Handler { entry: dispatcher });
                stack.push(self.execution_work(handler_body, handler_entry, next, scope));

                if let Some(filter) = clause.child_by_field_name("filter") {
                    let unmatched = self.point(builder, clause, Vec::new())?;
                    self.abrupt(builder, unmatched, scope, CompletionKind::Throw, None)?;
                    stack.push(Work::Condition {
                        node: filter,
                        entry: dispatcher,
                        when_true: EdgeTarget {
                            point: handler_entry,
                            kind: ControlEdgeKind::ConditionalTrue,
                        },
                        when_false: EdgeTarget {
                            point: unmatched,
                            kind: ControlEdgeKind::ConditionalFalse,
                        },
                        scope,
                    });
                } else {
                    self.edge(
                        builder,
                        dispatcher,
                        EdgeTarget {
                            point: handler_entry,
                            kind: ControlEdgeKind::SwitchCase,
                        },
                    )?;
                }
                stack.push(self.execution_work(body, body_entry, next, try_scope));
                Ok(())
            }
            Some(_) | None => {
                stack.push(self.execution_work(body, body_entry, next, scope));
                Ok(())
            }
        }
    }

    fn seh_leave_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
    ) -> Result<(), CppLoweringError> {
        for (capability, detail) in [
            (
                SemanticCapability::NonLocalControl,
                "SEH __leave destination and enclosing region selection are unsupported",
            ),
            (
                SemanticCapability::CleanupControlFlow,
                "SEH __leave must run applicable finally regions before reaching its destination",
            ),
            (
                SemanticCapability::NormalControlFlow,
                "SEH __leave is retained as a terminal typed boundary rather than falling through lexically",
            ),
        ] {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                capability,
                SemanticGapKind::Unsupported,
                detail,
            )?;
        }
        Ok(())
    }

    fn goto_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
    ) -> Result<(), CppLoweringError> {
        let Some(label) = node.child_by_field_name("label") else {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::NonLocalControl,
                SemanticGapKind::Unsupported,
                "computed or malformed goto target cannot be resolved structurally",
            )?;
            return Ok(());
        };
        let Some(name) = node_text(self.source, label) else {
            return Err(missing_field(node, "label text"));
        };
        let Some(target) = self.labels.get(name).copied() else {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::NonLocalControl,
                SemanticGapKind::Unknown,
                "goto target lies outside the represented callable or is syntactically unavailable",
            )?;
            return Ok(());
        };
        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::NonLocalControl,
            SemanticGapKind::Unknown,
            "goto edge is represented, but legality and variable-lifetime effects across the jump require semantic refinement",
        )?;
        if self.raii_possible {
            self.add_raii_gaps(
                builder,
                entry,
                "goto may enter or leave scopes with automatic object lifetimes",
            )?;
        }
        if self.vla_possible {
            self.add_vla_cleanup_gaps(
                builder,
                entry,
                SemanticGapSubject::Point,
                "goto may enter or leave scopes containing variably modified automatic arrays",
            )?;
        }
        self.edge(builder, entry, EdgeTarget::normal(target))
    }

    #[allow(clippy::too_many_arguments)]
    fn preprocessor_region(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CppLoweringError> {
        for (capability, detail) in [
            (
                SemanticCapability::NormalControlFlow,
                "preprocessor branch selection depends on an unavailable macro configuration",
            ),
            (
                SemanticCapability::Calls,
                "macro expansion may introduce calls that are absent from the parsed structured tree",
            ),
            (
                SemanticCapability::NonLocalControl,
                "macro expansion may introduce abrupt control that is absent from the parsed structured tree",
            ),
        ] {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                capability,
                SemanticGapKind::Unsupported,
                detail,
            )?;
        }
        let branches = named_children(node)
            .into_iter()
            .filter(|child| is_statement_or_declaration(child.kind()))
            .collect::<Vec<_>>();
        if branches.is_empty() {
            return self.edge(builder, entry, next);
        }
        for branch in branches {
            let branch_entry = self.point(builder, branch, Vec::new())?;
            self.edge(
                builder,
                entry,
                EdgeTarget {
                    point: branch_entry,
                    kind: ControlEdgeKind::SwitchCase,
                },
            )?;
            stack.push(self.execution_work(branch, branch_entry, next, scope));
        }
        self.edge(
            builder,
            entry,
            EdgeTarget {
                point: next.point,
                kind: ControlEdgeKind::ConditionalFalse,
            },
        )
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
    ) -> Result<(), CppLoweringError> {
        match node.kind() {
            "call_expression" if is_unevaluated_builtin_call(self.source, node) => {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::Values,
                    SemanticGapKind::Unknown,
                    "tree-sitter recovered a C++ unevaluated builtin operand as call-shaped syntax; the operand is not executed without type refinement",
                )?;
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::Calls,
                    SemanticGapKind::Unsupported,
                    "calls nested in noexcept/typeid operands are intentionally not emitted as immediate call sites",
                )?;
                self.edge(builder, entry, next)
            }
            "call_expression" | "new_expression" => {
                self.call_expression(builder, node, entry, next, scope, stack)
            }
            "lambda_expression" => {
                self.callable_expression(builder, node, entry, next, scope, stack)
            }
            "conditional_expression" => {
                let condition = required_field(node, "condition")?;
                let consequence = node.child_by_field_name("consequence");
                let alternative = required_field(node, "alternative")?;
                let alternative_entry = self.point(builder, alternative, Vec::new())?;
                stack.push(Work::Expression {
                    node: alternative,
                    entry: alternative_entry,
                    next,
                    scope,
                });
                let when_true = if let Some(consequence) = consequence {
                    let consequence_entry = self.point(builder, consequence, Vec::new())?;
                    stack.push(Work::Expression {
                        node: consequence,
                        entry: consequence_entry,
                        next,
                        scope,
                    });
                    EdgeTarget {
                        point: consequence_entry,
                        kind: ControlEdgeKind::ConditionalTrue,
                    }
                } else {
                    next
                };
                stack.push(Work::Condition {
                    node: condition,
                    entry,
                    when_true,
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
            "comma_expression" => {
                let left = required_field(node, "left")?;
                let right = required_field(node, "right")?;
                let right_entry = self.point(builder, right, Vec::new())?;
                stack.push(Work::Expression {
                    node: right,
                    entry: right_entry,
                    next,
                    scope,
                });
                stack.push(Work::Expression {
                    node: left,
                    entry,
                    next: EdgeTarget::normal(right_entry),
                    scope,
                });
                Ok(())
            }
            "assignment_expression" => {
                let left = required_field(node, "left")?;
                let right = required_field(node, "right")?;
                let assignment = self.point(builder, node, Vec::new())?;
                let target = self.value(builder, assignment, SemanticValueKind::Local)?;
                let value = self.value(builder, assignment, SemanticValueKind::Temporary)?;
                self.append_effect(
                    builder,
                    assignment,
                    SemanticEffect::Assignment { target, value },
                )?;
                self.add_gap(
                    builder,
                    assignment,
                    SemanticGapSubject::Point,
                    SemanticCapability::Values,
                    SemanticGapKind::Unknown,
                    "assignment target/value identity, aliasing, and overloaded assignment require type refinement",
                )?;
                self.add_gap(
                    builder,
                    assignment,
                    SemanticGapSubject::Point,
                    SemanticCapability::NormalControlFlow,
                    SemanticGapKind::Unknown,
                    "assignment operand evaluation order is C/C++-standard dependent; RHS-first lowering is only a deterministic bounded order without a configured language standard",
                )?;
                if assignment_operator(node).is_some_and(|operator| operator != "=") {
                    self.add_implicit_operator_gaps(
                        builder,
                        assignment,
                        "compound assignment may invoke an overloaded operator",
                    )?;
                }
                self.edge(builder, assignment, next)?;
                let right_entry = self.point(builder, right, Vec::new())?;
                let left_entry = self.point(builder, left, Vec::new())?;
                self.edge(builder, entry, EdgeTarget::normal(right_entry))?;
                stack.push(Work::Expression {
                    node: left,
                    entry: left_entry,
                    next: EdgeTarget::normal(assignment),
                    scope,
                });
                stack.push(Work::Expression {
                    node: right,
                    entry: right_entry,
                    next: EdgeTarget::normal(left_entry),
                    scope,
                });
                Ok(())
            }
            "co_await_expression" => {
                let argument = required_field(node, "argument")?;
                let suspend = self.point(builder, node, Vec::new())?;
                self.add_coroutine_gap(
                    builder,
                    suspend,
                    "await transformation, awaiter calls, suspension, resumption, and symmetric transfer are not lowered",
                )?;
                self.edge(builder, suspend, next)?;
                stack.push(Work::Expression {
                    node: argument,
                    entry,
                    next: EdgeTarget::normal(suspend),
                    scope,
                });
                Ok(())
            }
            "sizeof_expression"
            | "alignof_expression"
            | "decltype"
            | "noexcept"
            | "offsetof_expression"
            | "requires_expression" => {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::Values,
                    SemanticGapKind::Unknown,
                    "unevaluated or compile-time operand semantics are retained without executing operand syntax",
                )?;
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::Calls,
                    SemanticGapKind::Unsupported,
                    "potential calls in unevaluated operands are intentionally not emitted as call sites; VLA and polymorphic typeid exceptions require refinement",
                )?;
                self.edge(builder, entry, next)
            }
            "generic_expression" => {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::NormalControlFlow,
                    SemanticGapKind::Unsupported,
                    "C _Generic association selection requires type refinement; unselected expressions are not executed",
                )?;
                self.edge(builder, entry, next)
            }
            "gnu_asm_expression" => {
                for (capability, detail) in [
                    (
                        SemanticCapability::NormalControlFlow,
                        "inline assembly may branch, loop, or terminate independently of the represented fallthrough edge",
                    ),
                    (
                        SemanticCapability::NonLocalControl,
                        "asm-goto labels and machine-level transfers are not expanded into structured CFG edges",
                    ),
                    (
                        SemanticCapability::Calls,
                        "inline assembly may invoke code without a source-level call expression",
                    ),
                    (
                        SemanticCapability::Values,
                        "register constraints, clobbers, and operand value transformations require target-specific assembly semantics",
                    ),
                    (
                        SemanticCapability::Assignments,
                        "output operands and memory clobbers may mutate state beyond explicit C/C++ assignments",
                    ),
                ] {
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Point,
                        capability,
                        SemanticGapKind::Unsupported,
                        detail,
                    )?;
                }
                let children = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            "delete_expression" => {
                self.add_implicit_lifetime_call_gaps(
                    builder,
                    entry,
                    "delete may invoke a destructor and a deallocation function",
                )?;
                let children = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            "binary_expression"
            | "unary_expression"
            | "update_expression"
            | "subscript_expression"
            | "field_expression"
            | "pointer_expression"
            | "cast_expression"
            | "compound_literal_expression"
            | "fold_expression" => {
                if !self.is_c_source() && expression_may_invoke_overload(node) {
                    self.add_implicit_operator_gaps(
                        builder,
                        entry,
                        "runtime operator or conversion may invoke user-defined code",
                    )?;
                }
                let children = runtime_expression_children(node);
                if matches!(
                    node.kind(),
                    "binary_expression" | "subscript_expression" | "fold_expression"
                ) && children.len() > 1
                {
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::NormalControlFlow,
                        SemanticGapKind::Unknown,
                        "relative operand evaluation order is unspecified or language-version dependent; source order is only a bounded lowering order",
                    )?;
                }
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            "condition_clause" => {
                let children = runtime_expression_children(node);
                self.schedule_execution_nodes(builder, entry, &children, next, scope, stack)
            }
            "initializer_list" => {
                let children = runtime_expression_children(node);
                if self.is_c_source() && children.len() > 1 {
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::NormalControlFlow,
                        SemanticGapKind::Unknown,
                        "C does not specify the relative evaluation order of initializer-list expressions; source order is only a bounded lowering order",
                    )?;
                }
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            "argument_list"
            | "parenthesized_expression"
            | "field_initializer"
            | "field_initializer_list"
            | "init_declarator" => {
                let children = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            "preproc_call" => {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::Calls,
                    SemanticGapKind::Unsupported,
                    "macro invocation expansion is unavailable and no textual mini-parser is used",
                )?;
                self.edge(builder, entry, next)
            }
            "lambda_capture_initializer" => {
                let children = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            "function_definition" => self.edge(builder, entry, next),
            _ if is_runtime_leaf(node.kind()) || is_type_syntax(node.kind()) => {
                self.edge(builder, entry, next)
            }
            _ => {
                let children = runtime_expression_children(node);
                if children.is_empty() {
                    self.unhandled_expression_syntax(builder, node, entry, next)
                } else {
                    self.schedule_expressions(builder, entry, &children, next, scope, stack)
                }
            }
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
    ) -> Result<(), CppLoweringError> {
        let invoke = self.point(builder, node, Vec::new())?;
        let normal = self.point(builder, node, Vec::new())?;
        let exceptional = self.point(builder, node, Vec::new())?;
        let callee = self.value(builder, invoke, SemanticValueKind::Callable)?;
        let result = self.value(builder, invoke, SemanticValueKind::Temporary)?;
        let thrown = self.value(builder, invoke, SemanticValueKind::Exception)?;

        let function = if node.kind() == "new_expression" {
            required_field(node, "type")?
        } else {
            required_field(node, "function")?
        };
        let receiver_node = cpp_call_receiver(function);
        let receiver = receiver_node
            .map(|_| self.value(builder, invoke, SemanticValueKind::Receiver))
            .transpose()?;
        let constructor = node.kind() == "new_expression";
        let indirect = !constructor && call_target_requires_dispatch_gap(function);
        let callable_kind = if constructor {
            CallableReferenceKind::Constructor
        } else if receiver.is_some() {
            CallableReferenceKind::BoundMethod
        } else {
            CallableReferenceKind::Function
        };
        let resolution = if indirect {
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
        for (capability, detail) in [
            (
                SemanticCapability::ExceptionalControlFlow,
                "caller-side default arguments, implicit conversions, and copy/move construction may throw before callee entry",
            ),
            (
                SemanticCapability::CleanupControlFlow,
                "temporaries created by default arguments and implicit conversions may require cleanup before or after the represented call",
            ),
        ] {
            let subject = SemanticGapSubject::CallSite(call_site);
            self.add_gap_with_impacts(
                builder,
                invoke,
                subject,
                capability,
                SemanticGapImpacts::for_gap(capability, subject)
                    .with(SemanticGapImpact::CallEvaluation),
                SemanticGapKind::Unknown,
                detail,
            )?;
        }

        if indirect {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::CallableReferences,
                SemanticGapKind::Unsupported,
                "function-pointer, pointer-to-member, or callable-object target requires type/value refinement",
            )?;
        }
        let dynamic_dispatch_unproven = (receiver_node.is_some()
            && !member_dispatch_is_explicitly_qualified(function))
            || (receiver_node.is_none()
                && self.has_implicit_object_context
                && is_structurally_unqualified_call_target(function));
        if dynamic_dispatch_unproven {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::Point,
                SemanticCapability::DynamicDispatch,
                SemanticGapKind::Unknown,
                "member dispatch, including an implicit object call where applicable, may select a virtual override; object context, virtual status, and final-overrider identity require class-hierarchy refinement",
            )?;
        }
        if is_concurrent_spawn_call(self.source, function) {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::ConcurrentSpawn,
                SemanticGapKind::Unknown,
                "thread/task creation is an explicit call, but the spawned execution context is not stitched into the ICFG",
            )?;
        }
        if is_deferred_callback_call(self.source, function) {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::DeferredExecution,
                SemanticGapKind::Unknown,
                "registered callback or asynchronously scheduled callable does not execute immediately on this control edge",
            )?;
        }
        if is_non_local_runtime_call(self.source, function) {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::NonLocalControl,
                SemanticGapKind::Unsupported,
                "setjmp/longjmp-style non-local control and restored execution state are not lowered",
            )?;
        }
        if constructor {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::Allocations,
                SemanticGapKind::Unknown,
                "allocation-function selection, placement-new storage, array cookies, and partial-construction cleanup are not represented",
            )?;
            self.add_implicit_lifetime_call_gaps(
                builder,
                invoke,
                "new-expression allocation and partial-construction cleanup",
            )?;
        }
        let evaluations = call_operand_evaluations(node, function);
        if evaluations.len() > 1 {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::NormalControlFlow,
                SemanticGapKind::Unknown,
                "relative evaluation order of the callable/receiver and arguments is language-version and construct dependent; source order is used only as a bounded traversal order",
            )?;
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

    fn callable_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CppLoweringError> {
        let captures = lambda_capture_initializers(node);
        let creation = if captures.is_empty() {
            entry
        } else {
            self.point(builder, node, Vec::new())?
        };
        let result = self.value(builder, creation, SemanticValueKind::Callable)?;
        let metadata = self.metadata(creation)?;
        self.append_effect(
            builder,
            creation,
            SemanticEffect::CallableCreation {
                result,
                callable: CallableValue {
                    kind: CallableReferenceKind::Lambda,
                    targets: CallableTargetResolution::Unknown,
                    target_evidence: metadata.evidence,
                    bound_receiver: None,
                    environment: None,
                },
            },
        )?;
        self.add_gap(
            builder,
            creation,
            SemanticGapSubject::Value(result),
            SemanticCapability::CallableReferences,
            SemanticGapKind::Unknown,
            "lambda body target and closure-object identity require location-first callable refinement",
        )?;
        self.add_gap(
            builder,
            creation,
            SemanticGapSubject::Value(result),
            SemanticCapability::Captures,
            SemanticGapKind::Unknown,
            "lambda capture modes, lifetime extension, and closure storage are not represented",
        )?;
        self.edge(builder, creation, next)?;
        if captures.is_empty() {
            Ok(())
        } else {
            self.schedule_expressions(
                builder,
                entry,
                &captures,
                EdgeTarget::normal(creation),
                scope,
                stack,
            )
        }
    }

    fn register_labels(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        root: Node<'tree>,
    ) -> Result<(), CppLoweringError> {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if self.session.cancellation().is_cancelled() {
                return Err(CppLoweringError::Cancelled(Box::new(
                    builder.prospective_work(),
                )));
            }
            if node != root && matches!(node.kind(), "function_definition" | "lambda_expression") {
                continue;
            }
            if node.kind() == "labeled_statement" {
                let label = required_field(node, "label")?;
                let name = node_text(self.source, label)
                    .ok_or_else(|| missing_field(node, "label text"))?;
                let point = self.point(builder, node, Vec::new())?;
                if self.labels.insert(Box::<str>::from(name), point).is_some() {
                    return Err(CppLoweringError::Invalid(format!(
                        "duplicate C/C++ label {name:?} in one callable"
                    )));
                }
            }
            stack.extend(named_children(node).into_iter().rev());
        }
        Ok(())
    }

    fn execution_work(
        &self,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
    ) -> Work<'tree> {
        if is_statement_or_declaration(node.kind()) {
            Work::Statement {
                node,
                entry,
                next,
                scope,
            }
        } else {
            Work::Expression {
                node,
                entry,
                next,
                scope,
            }
        }
    }

    fn is_c_source(&self) -> bool {
        self.session
            .locator()
            .path()
            .as_path()
            .extension()
            .and_then(|extension| extension.to_str())
            == Some("c")
    }

    fn normal_cleanup_boundary(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        next: EdgeTarget,
        context: &str,
    ) -> Result<ProgramPointId, CppLoweringError> {
        let cleanup = self.point(builder, node, Vec::new())?;
        self.add_raii_gaps(builder, cleanup, context)?;
        self.edge(builder, cleanup, next)?;
        Ok(cleanup)
    }

    fn execution_entry(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<ProgramPointId, CppLoweringError> {
        if node.kind() == "case_statement"
            && let Some(entry) = self.switch_case_entries.get(&node.id()).copied()
        {
            return Ok(entry);
        }
        self.point(builder, node, Vec::new())
    }

    fn schedule_execution_nodes(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        children: &[Node<'tree>],
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CppLoweringError> {
        if children.is_empty() {
            return self.edge(builder, entry, next);
        }
        let mut entries = Vec::with_capacity(children.len());
        for child in children {
            entries.push(self.execution_entry(builder, *child)?);
        }
        self.edge(builder, entry, EdgeTarget::normal(entries[0]))?;
        for index in (0..children.len()).rev() {
            let child_next = entries
                .get(index + 1)
                .copied()
                .map(EdgeTarget::normal)
                .unwrap_or(next);
            stack.push(self.execution_work(children[index], entries[index], child_next, scope));
        }
        Ok(())
    }

    fn is_function_local_static(&self, node: Node<'tree>, values: &[Node<'tree>]) -> bool {
        !self.is_synthetic_procedure
            && node.kind() == "declaration"
            && has_storage_class(self.source, node, "static")
            && (!values.is_empty()
                || (!self.is_c_source() && declaration_may_construct_object(node)))
    }

    #[allow(clippy::too_many_arguments)]
    fn function_local_static_declaration(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        values: &[Node<'tree>],
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CppLoweringError> {
        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::DeferredExecution,
            SemanticGapKind::Unknown,
            "function-local static initialization is guarded and executes at most once rather than on every invocation",
        )?;
        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::NormalControlFlow,
            SemanticGapKind::Unknown,
            "the once-only initialization guard, concurrent initialization, recursive entry, and prior failure state are not modeled",
        )?;

        let initialize = self.point(builder, node, Vec::new())?;
        self.edge(
            builder,
            entry,
            EdgeTarget {
                point: initialize,
                kind: ControlEdgeKind::ConditionalTrue,
            },
        )?;
        self.edge(
            builder,
            entry,
            EdgeTarget {
                point: next.point,
                kind: ControlEdgeKind::ConditionalFalse,
            },
        )?;
        if values.is_empty() {
            self.edge(builder, initialize, next)
        } else {
            self.schedule_expressions(builder, initialize, values, next, scope, stack)
        }
    }

    fn schedule_expressions(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        children: &[Node<'tree>],
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), CppLoweringError> {
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

    fn unhandled_control_syntax(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
    ) -> Result<(), CppLoweringError> {
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
        )?;
        self.edge(builder, entry, next)
    }

    fn unhandled_expression_syntax(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
    ) -> Result<(), CppLoweringError> {
        let detail = format!(
            "{} expression semantics are retained as an opaque source-backed point",
            node.kind()
        );
        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::Values,
            SemanticGapKind::Unsupported,
            &detail,
        )?;
        self.edge(builder, entry, next)
    }

    fn abrupt(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        from: ProgramPointId,
        scope: ScopeFrameId,
        kind: CompletionKind,
        label: Option<&str>,
    ) -> Result<(), CppLoweringError> {
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
                    SemanticCapability::NonLocalControl,
                    SemanticGapKind::Unsupported,
                    &detail,
                )?;
                return Ok(());
            }
            return Err(CppLoweringError::Invalid(format!(
                "{} completion has no matching structured continuation",
                completion_label(kind)
            )));
        };
        if self.raii_possible {
            self.add_raii_gaps(
                builder,
                from,
                "abrupt completion may leave scopes containing automatic objects",
            )?;
        }
        if self.vla_possible {
            self.add_vla_cleanup_gaps(
                builder,
                from,
                SemanticGapSubject::Point,
                "abrupt completion may leave scopes containing variably modified automatic arrays",
            )?;
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
    ) -> Result<(), CppLoweringError> {
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
            "callable target, including possible function-pointer or callable-object identity, requires translation-unit-aware C/C++ dispatch refinement",
        )?;
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::CallSite(call_site),
            SemanticCapability::Calls,
            kind,
            "call target, including possible indirect function-pointer dispatch and caller-side default-argument or conversion calls, requires translation-unit-aware C/C++ refinement",
        )
    }

    fn add_raii_gaps(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        context: &str,
    ) -> Result<(), CppLoweringError> {
        for (capability, detail) in [
            (
                SemanticCapability::CleanupControlFlow,
                "destruction order and cleanup routing depend on constructed-object state",
            ),
            (
                SemanticCapability::ResourceManagement,
                "RAII release depends on inferred types, storage duration, and destructor definitions",
            ),
            (
                SemanticCapability::Calls,
                "implicit destructor invocations are not emitted as fabricated call sites",
            ),
            (
                SemanticCapability::ExceptionalControlFlow,
                "destructor failure, noexcept termination, and unwinding interactions are not lowered",
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

    fn add_vla_cleanup_gaps(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        subject: SemanticGapSubject,
        context: &str,
    ) -> Result<(), CppLoweringError> {
        for (capability, detail) in [
            (
                SemanticCapability::CleanupControlFlow,
                "scope-sensitive VLA storage release and jumps across variably modified declarations require refinement",
            ),
            (
                SemanticCapability::ResourceManagement,
                "automatic variable-size storage lifetime is not represented as an explicit resource",
            ),
            (
                SemanticCapability::Allocations,
                "runtime stack allocation for a variably modified array is not emitted as an allocation row",
            ),
            (
                SemanticCapability::NormalControlFlow,
                "VLA bound evaluation failure and scope-entry legality depend on target and language semantics",
            ),
            (
                SemanticCapability::Calls,
                "calls in parameter VLA bounds and implicit storage-management operations are not fully lowered",
            ),
        ] {
            self.add_gap(
                builder,
                point,
                subject,
                capability,
                SemanticGapKind::Unknown,
                &format!("{context}; {detail}"),
            )?;
        }
        Ok(())
    }

    fn add_implicit_lifetime_call_gaps(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        context: &str,
    ) -> Result<(), CppLoweringError> {
        for (capability, detail) in [
            (
                SemanticCapability::Calls,
                "implicit constructor/destructor/allocation calls are not fabricated",
            ),
            (
                SemanticCapability::ExceptionalControlFlow,
                "implicit lifetime operations may throw or terminate",
            ),
            (
                SemanticCapability::ResourceManagement,
                "object lifetime and partial construction/destruction require type refinement",
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

    fn add_implicit_operator_gaps(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        context: &str,
    ) -> Result<(), CppLoweringError> {
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unknown,
            &format!("{context}; overload resolution is not emitted as an implicit call site"),
        )?;
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unknown,
            &format!("{context}; user-defined operators and conversions may throw"),
        )
    }

    fn add_coroutine_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        detail: &str,
    ) -> Result<(), CppLoweringError> {
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::Point,
            SemanticCapability::AsyncSuspendResume,
            SemanticGapKind::Unsupported,
            detail,
        )?;
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::Point,
            SemanticCapability::DeferredExecution,
            SemanticGapKind::Unsupported,
            "coroutine promise and frame callbacks may invoke user code not represented as immediate calls",
        )?;
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unknown,
            "coroutine promise, awaiter, allocation, and frame callbacks are not emitted as fabricated call sites",
        )?;
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unknown,
            "coroutine callbacks, allocation, and resumption may fail or terminate",
        )
    }

    fn point(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        effects: Vec<SemanticEffect>,
    ) -> Result<ProgramPointId, CppLoweringError> {
        let metadata = self.mapping(builder, node)?;
        self.session.add_point(builder, metadata, effects)
    }

    fn mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<PointMetadata, CppLoweringError> {
        let range = node.byte_range();
        let occurrence = self.session.next_source_occurrence(range.start, range.end);
        let anchor = source_anchor(node, occurrence).map_err(CppLoweringError::Invalid)?;
        self.session
            .add_mapping(builder, anchor, SourceMappingKind::Exact)
    }

    fn metadata(&self, point: ProgramPointId) -> Result<PointMetadata, CppLoweringError> {
        self.session.metadata(point)
    }

    fn value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        kind: SemanticValueKind,
    ) -> Result<ValueId, CppLoweringError> {
        self.session.add_value(builder, point, kind)
    }

    fn append_effect(
        &self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        effect: SemanticEffect,
    ) -> Result<(), CppLoweringError> {
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
    ) -> Result<(), CppLoweringError> {
        self.add_gap_with_impacts(
            builder,
            point,
            subject,
            capability,
            SemanticGapImpacts::for_gap(capability, subject),
            kind,
            detail,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn add_gap_with_impacts(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        subject: SemanticGapSubject,
        capability: SemanticCapability,
        impacts: SemanticGapImpacts,
        kind: SemanticGapKind,
        detail: &str,
    ) -> Result<(), CppLoweringError> {
        if !self.published_gaps.insert(GapFact {
            point,
            subject,
            capability,
        }) {
            return Ok(());
        }
        self.session
            .add_gap_with_impacts(builder, point, subject, capability, impacts, kind, detail)?;
        Ok(())
    }

    fn edge(
        &self,
        builder: &mut ProcedureCfgBuilder,
        source_point: ProgramPointId,
        target: EdgeTarget,
    ) -> Result<(), CppLoweringError> {
        self.session
            .add_edge(builder, source_point, target.point, target.kind)
    }
}

fn callable_name_node(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "function_definition" => node
            .child_by_field_name("declarator")
            .and_then(declarator_name_node),
        _ => None,
    }
}

fn function_execution_nodes(node: Node<'_>) -> Vec<Node<'_>> {
    let body = node.child_by_field_name("body");
    named_children(node)
        .into_iter()
        .filter(|child| {
            child.kind() == "field_initializer_list"
                || body.is_some_and(|body| child.id() == body.id())
        })
        .collect()
}

fn initializer_values(node: Node<'_>) -> Vec<Node<'_>> {
    match node.kind() {
        "init_declarator" => node.child_by_field_name("value").into_iter().collect(),
        "declaration" | "field_declaration" => {
            let mut values = node
                .child_by_field_name("default_value")
                .into_iter()
                .collect::<Vec<_>>();
            values.extend(node.child_by_field_name("value"));
            values.extend(
                named_children(node)
                    .into_iter()
                    .filter(|child| child.kind() == "init_declarator")
                    .filter_map(|child| child.child_by_field_name("value")),
            );
            values
        }
        "field_initializer_list" => named_children(node)
            .into_iter()
            .filter(|child| child.kind() == "field_initializer")
            .collect(),
        "field_initializer" => named_children(node)
            .into_iter()
            .filter(|child| {
                matches!(child.kind(), "argument_list" | "initializer_list")
                    || is_cpp_expression(child.kind())
            })
            .collect(),
        "init_statement" => named_children(node)
            .into_iter()
            .filter(|child| {
                is_statement_or_declaration(child.kind()) || is_cpp_expression(child.kind())
            })
            .collect(),
        _ => runtime_expression_children(node),
    }
}

fn declaration_runtime_expressions(node: Node<'_>) -> Vec<Node<'_>> {
    if !matches!(node.kind(), "declaration" | "field_declaration") {
        return initializer_values(node);
    }

    let mut expressions = declarator_bound_expressions(node);
    expressions.extend(initializer_values(node));
    expressions
}

fn declarator_bound_expressions(node: Node<'_>) -> Vec<Node<'_>> {
    let mut roots_cursor = node.walk();
    let roots = node
        .children_by_field_name("declarator", &mut roots_cursor)
        .collect::<Vec<_>>();
    let mut expressions = Vec::new();
    let mut stack = roots;
    while let Some(declarator) = stack.pop() {
        if declarator.kind() == "array_declarator"
            && let Some(size) = declarator.child_by_field_name("size")
        {
            expressions.push(size);
        }
        if let Some(inner) = declarator.child_by_field_name("declarator") {
            stack.push(inner);
        } else if matches!(
            declarator.kind(),
            "reference_declarator" | "parenthesized_declarator"
        ) && let Some(inner) = first_named_child(declarator)
        {
            stack.push(inner);
        }
    }
    expressions.sort_unstable_by_key(Node::start_byte);
    expressions
}

fn declaration_may_construct_object(node: Node<'_>) -> bool {
    if matches!(node.kind(), "field_initializer" | "field_initializer_list") {
        return true;
    }
    if !matches!(node.kind(), "declaration" | "field_declaration") {
        return false;
    }
    let type_node = node
        .child_by_field_name("type")
        .or_else(|| first_named_child(node));
    type_node.is_none_or(|ty| ty.kind() != "primitive_type")
}

fn condition_value_declaration(condition: Node<'_>) -> Option<Node<'_>> {
    let value = if condition.kind() == "condition_clause" {
        condition.child_by_field_name("value")?
    } else {
        condition
    };
    (value.kind() == "declaration").then_some(value)
}

fn syntax_has_automatic_object(source: &str, root: Node<'_>) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.id() != root.id()
            && matches!(node.kind(), "function_definition" | "lambda_expression")
        {
            continue;
        }
        if matches!(node.kind(), "declaration" | "field_declaration")
            && declaration_may_construct_object(node)
            && !["static", "extern", "thread_local"]
                .into_iter()
                .any(|storage| has_storage_class(source, node, storage))
        {
            return true;
        }
        stack.extend(named_children(node));
    }
    false
}

fn block_has_automatic_object(source: &str, block: Node<'_>) -> bool {
    let mut stack = named_children(block);
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "declaration" | "field_declaration")
            && declaration_may_construct_object(node)
            && !["static", "extern", "thread_local"]
                .into_iter()
                .any(|storage| has_storage_class(source, node, storage))
        {
            return true;
        }
        if matches!(
            node.kind(),
            "case_statement" | "labeled_statement" | "attributed_statement"
        ) || node.kind().starts_with("preproc_")
        {
            stack.extend(named_children(node));
        }
    }
    false
}

fn block_has_potential_vla(block: Node<'_>) -> bool {
    let mut stack = named_children(block);
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "declaration" | "field_declaration")
            && declarator_bound_expressions(node)
                .into_iter()
                .any(|bound| !matches!(bound.kind(), "number_literal" | "char_literal"))
        {
            return true;
        }
        if matches!(
            node.kind(),
            "case_statement" | "labeled_statement" | "attributed_statement"
        ) || node.kind().starts_with("preproc_")
        {
            stack.extend(named_children(node));
        }
    }
    false
}

fn switch_cases(body: Node<'_>) -> Vec<Node<'_>> {
    let mut cases = Vec::new();
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if node != body
            && matches!(
                node.kind(),
                "switch_statement" | "function_definition" | "lambda_expression"
            )
        {
            continue;
        }
        if node != body && node.kind() == "case_statement" {
            cases.push(node);
        }
        stack.extend(named_children(node).into_iter().rev());
    }
    cases.sort_unstable_by_key(Node::start_byte);
    cases
}

fn case_runtime_children(node: Node<'_>) -> Vec<Node<'_>> {
    let value = node.child_by_field_name("value");
    named_children(node)
        .into_iter()
        .filter(|child| {
            value.is_none_or(|value| value.id() != child.id())
                && is_statement_or_declaration(child.kind())
        })
        .collect()
}

fn call_arguments(node: Node<'_>) -> Vec<Node<'_>> {
    node.child_by_field_name("arguments")
        .map(named_children)
        .unwrap_or_default()
}

fn is_unevaluated_builtin_call(source: &str, node: Node<'_>) -> bool {
    node.kind() == "call_expression"
        && node
            .child_by_field_name("function")
            .filter(|function| function.kind() == "identifier")
            .and_then(|function| node_text(source, function))
            .is_some_and(|name| matches!(name, "noexcept" | "typeid"))
}

fn is_concurrent_spawn_call(source: &str, function: Node<'_>) -> bool {
    structured_call_target_name(source, function).is_some_and(|name| {
        matches!(
            name,
            "thread" | "jthread" | "async" | "pthread_create" | "thrd_create"
        )
    })
}

fn is_deferred_callback_call(source: &str, function: Node<'_>) -> bool {
    structured_call_target_name(source, function)
        .is_some_and(|name| matches!(name, "async" | "atexit" | "at_quick_exit"))
}

fn is_non_local_runtime_call(source: &str, function: Node<'_>) -> bool {
    structured_call_target_name(source, function)
        .is_some_and(|name| matches!(name, "setjmp" | "sigsetjmp" | "longjmp" | "siglongjmp"))
}

fn structured_call_target_name<'source>(
    source: &'source str,
    mut function: Node<'_>,
) -> Option<&'source str> {
    while function.kind() == "parenthesized_expression" {
        function = first_named_child(function)?;
    }
    declarator_name_node(function).and_then(|name| node_text(source, name))
}

fn declaration_constructs_thread(source: &str, declaration: Node<'_>) -> bool {
    declaration
        .child_by_field_name("type")
        .or_else(|| first_named_child(declaration))
        .and_then(declarator_name_node)
        .and_then(|name| node_text(source, name))
        .is_some_and(|name| matches!(name, "thread" | "jthread"))
}

fn lambda_capture_initializers(node: Node<'_>) -> Vec<Node<'_>> {
    node.child_by_field_name("captures")
        .map(named_children)
        .unwrap_or_default()
        .into_iter()
        .filter(|capture| capture.kind() == "lambda_capture_initializer")
        .filter_map(|capture| capture.child_by_field_name("right"))
        .collect()
}

fn call_operand_evaluations<'tree>(node: Node<'tree>, function: Node<'tree>) -> Vec<Node<'tree>> {
    let mut evaluations = Vec::new();
    if node.kind() == "new_expression" {
        if let Some(placement) = node.child_by_field_name("placement") {
            evaluations.extend(named_children(placement));
        }
    } else if let Some(receiver) = cpp_call_receiver(function) {
        evaluations.push(receiver);
    } else if call_target_requires_dispatch_gap(function) {
        evaluations.push(function);
    }
    evaluations.extend(call_arguments(node));
    evaluations
}

fn cpp_call_receiver(mut function: Node<'_>) -> Option<Node<'_>> {
    loop {
        match function.kind() {
            "field_expression" => return function.child_by_field_name("argument"),
            "parenthesized_expression" => function = first_named_child(function)?,
            _ => return None,
        }
    }
}

fn member_dispatch_is_explicitly_qualified(mut function: Node<'_>) -> bool {
    loop {
        match function.kind() {
            "field_expression" => {
                return function
                    .child_by_field_name("field")
                    .is_some_and(|field| field.kind() == "qualified_identifier");
            }
            "parenthesized_expression" => {
                let Some(inner) = first_named_child(function) else {
                    return false;
                };
                function = inner;
            }
            _ => return false,
        }
    }
}

fn is_structurally_unqualified_call_target(mut function: Node<'_>) -> bool {
    loop {
        match function.kind() {
            "identifier" | "field_identifier" | "operator_name" | "destructor_name"
            | "template_function" | "template_method" => return true,
            "parenthesized_expression" => {
                let Some(inner) = first_named_child(function) else {
                    return false;
                };
                function = inner;
            }
            // Qualified identifiers cover both `Base::method()` and
            // namespace-qualified free functions. Neither uses the implicit
            // object dispatch form at this exact syntax point.
            _ => return false,
        }
    }
}

fn call_target_requires_dispatch_gap(mut function: Node<'_>) -> bool {
    loop {
        match function.kind() {
            "identifier"
            | "field_identifier"
            | "namespace_identifier"
            | "type_identifier"
            | "qualified_identifier"
            | "dependent_name"
            | "template_function"
            | "template_method"
            | "operator_name"
            | "destructor_name"
            | "primitive_type"
            | "field_expression" => return false,
            "parenthesized_expression" => {
                let Some(child) = first_named_child(function) else {
                    return true;
                };
                function = child;
            }
            _ => return true,
        }
    }
}

fn expression_may_invoke_overload(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "binary_expression"
            | "unary_expression"
            | "update_expression"
            | "subscript_expression"
            | "field_expression"
            | "pointer_expression"
            | "cast_expression"
            | "fold_expression"
    )
}

fn runtime_expression_children(node: Node<'_>) -> Vec<Node<'_>> {
    match node.kind() {
        "binary_expression" | "assignment_expression" | "comma_expression" => ["left", "right"]
            .into_iter()
            .filter_map(|field| node.child_by_field_name(field))
            .collect(),
        "conditional_expression" => ["condition", "consequence", "alternative"]
            .into_iter()
            .filter_map(|field| node.child_by_field_name(field))
            .collect(),
        "field_expression" => node.child_by_field_name("argument").into_iter().collect(),
        "condition_clause" => ["initializer", "value"]
            .into_iter()
            .filter_map(|field| node.child_by_field_name(field))
            .collect(),
        "call_expression"
        | "new_expression"
        | "lambda_expression"
        | "sizeof_expression"
        | "alignof_expression"
        | "decltype"
        | "noexcept"
        | "offsetof_expression"
        | "requires_expression"
        | "generic_expression" => Vec::new(),
        _ => named_children(node)
            .into_iter()
            .filter(|child| !is_non_runtime_field(node, *child))
            .collect(),
    }
}

fn is_non_runtime_field(parent: Node<'_>, child: Node<'_>) -> bool {
    if is_type_syntax(child.kind()) || is_comment_kind(child.kind()) {
        return true;
    }
    for field in [
        "type",
        "declarator",
        "name",
        "field",
        "operator",
        "label",
        "constraint",
        "template_parameters",
        "parameters",
        "captures",
    ] {
        if parent
            .child_by_field_name(field)
            .is_some_and(|candidate| candidate.id() == child.id())
        {
            return true;
        }
    }
    matches!(
        child.kind(),
        "attribute_declaration"
            | "attribute_specifier"
            | "storage_class_specifier"
            | "type_qualifier"
            | "ms_declspec_modifier"
    )
}

fn first_runtime_named_child(node: Node<'_>) -> Option<Node<'_>> {
    named_children(node)
        .into_iter()
        .find(|child| !is_non_runtime_field(node, *child))
}

fn is_statement_or_declaration(kind: &str) -> bool {
    kind.ends_with("_statement")
        || matches!(
            kind,
            "compound_statement"
                | "translation_unit"
                | "declaration"
                | "field_declaration"
                | "field_initializer"
                | "field_initializer_list"
                | "init_statement"
                | "for_range_loop"
                | "try_statement"
                | "catch_clause"
                | "function_definition"
                | "template_declaration"
                | "namespace_definition"
                | "class_specifier"
                | "struct_specifier"
                | "union_specifier"
                | "enum_specifier"
                | "type_definition"
                | "alias_declaration"
                | "using_declaration"
                | "static_assert_declaration"
                | "attributed_statement"
        )
        || kind.starts_with("preproc_")
}

fn is_cpp_expression(kind: &str) -> bool {
    kind.ends_with("_expression")
        || matches!(
            kind,
            "identifier"
                | "field_identifier"
                | "qualified_identifier"
                | "dependent_name"
                | "template_function"
                | "template_method"
                | "operator_name"
                | "destructor_name"
                | "this"
                | "nullptr"
                | "true"
                | "false"
                | "number_literal"
                | "char_literal"
                | "string_literal"
                | "raw_string_literal"
                | "concatenated_string"
                | "user_defined_literal"
                | "initializer_list"
                | "argument_list"
                | "init_declarator"
                | "condition_clause"
                | "decltype"
                | "noexcept"
        )
}

fn is_runtime_leaf(kind: &str) -> bool {
    matches!(
        kind,
        "identifier"
            | "field_identifier"
            | "qualified_identifier"
            | "dependent_name"
            | "template_function"
            | "template_method"
            | "operator_name"
            | "destructor_name"
            | "this"
            | "nullptr"
            | "null"
            | "true"
            | "false"
            | "number_literal"
            | "char_literal"
            | "string_literal"
            | "raw_string_literal"
            | "concatenated_string"
            | "user_defined_literal"
    )
}

fn is_type_syntax(kind: &str) -> bool {
    kind.ends_with("_type")
        || kind.ends_with("_specifier")
        || kind.ends_with("_declarator")
        || kind.ends_with("_parameter")
        || matches!(
            kind,
            "primitive_type"
                | "type_identifier"
                | "type_descriptor"
                | "sized_type_specifier"
                | "placeholder_type_specifier"
                | "decltype"
                | "auto"
                | "parameter_list"
                | "template_parameter_list"
                | "requires_clause"
                | "namespace_identifier"
                | "access_specifier"
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

fn has_direct_token(node: Node<'_>, kind: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor).any(|child| child.kind() == kind)
}

fn is_comment_kind(kind: &str) -> bool {
    matches!(kind, "comment" | "line_comment" | "block_comment")
}

fn required_field<'tree>(node: Node<'tree>, field: &str) -> Result<Node<'tree>, CppLoweringError> {
    node.child_by_field_name(field)
        .ok_or_else(|| missing_field(node, field))
}

fn missing_field(node: Node<'_>, field: &str) -> CppLoweringError {
    CppLoweringError::Invalid(format!(
        "{} node at bytes {}..{} is missing structured field {field}",
        node.kind(),
        node.start_byte(),
        node.end_byte()
    ))
}

fn node_text<'source>(source: &'source str, node: Node<'_>) -> Option<&'source str> {
    source.get(node.byte_range())
}

fn binary_operator(node: Node<'_>) -> Option<&'static str> {
    match node.child_by_field_name("operator")?.kind() {
        "&&" | "and" => Some("&&"),
        "||" | "or" => Some("||"),
        _ => None,
    }
}

fn assignment_operator(node: Node<'_>) -> Option<&str> {
    node.child_by_field_name("operator")
        .map(|operator| operator.kind())
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
        CompletionKind::Yield => "yield",
    }
}
