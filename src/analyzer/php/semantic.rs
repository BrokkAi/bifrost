//! PHP lowering into the language-neutral executable-semantics IR.
//!
//! This adapter reads tree-sitter structure directly. Graph construction,
//! abrupt-completion routing, cleanup specialization, and immutable adjacency
//! storage remain owned by the shared semantic substrate.

use tree_sitter::Node;

use crate::analyzer::lexical_definitions::formal_parameter_slots_for_owner;
use crate::analyzer::semantic::cfg::{
    CleanupRegionId, CompletionKind, CompletionRequest, CompletionRoute, DriveError,
    ProcedureCfgBuilder, ScopeBinding, ScopeFrameId,
};
use crate::analyzer::semantic::service::{ProgramSemanticsLowerer, SemanticAdapterIdentity};
use crate::analyzer::semantic::*;
use crate::analyzer::tree_sitter_analyzer::{
    PreparedSyntaxTree, WalkControl, try_walk_named_tree_preorder,
};
use crate::analyzer::{DispatchExtensibility, Language, PhpAnalyzer, ProjectFile, Range};
use crate::hash::HashMap;

const ADAPTER_VERSION: &[u8] = b"php-value-semantics-v2";

impl_program_semantics_provider!(PhpAnalyzer, PhpSemanticLowerer);

struct PhpSemanticLowerer;

impl ProgramSemanticsLowerer for PhpSemanticLowerer {
    fn identity(&self) -> SemanticAdapterIdentity {
        SemanticAdapterIdentity {
            adapter: AdapterSemanticsVersion::hash_bytes("php", ADAPTER_VERSION)
                .expect("adapter name is non-empty"),
            configuration: ConfigurationFingerprint::hash_bytes(
                b"php-intrafile-execution-defaults-v1",
            ),
            dependencies: DependencyFingerprint::hash_bytes(b"no-intrafile-dependencies"),
        }
    }

    fn capabilities(&self) -> SemanticCapabilities {
        php_capabilities()
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

fn php_capabilities() -> SemanticCapabilities {
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
    callable: Node<'tree>,
    body: Node<'tree>,
    locator: SemanticLocator,
    lexical_parent: Option<ProcedureId>,
    kind: ProcedureKind,
    properties: ProcedureProperties,
    returns_value: bool,
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
        .unwrap_or("php-source");
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
        if let Some((kind, segment_kind, body, properties, returns_value)) =
            callable_shape(prepared.source(), frame.node, frame.lexical_parent)
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
                callable: frame.node,
                body,
                locator,
                lexical_parent: frame.lexical_parent,
                kind,
                properties,
                returns_value,
            });
            let callable_path = push_declaration_path(&mut declaration_paths, child_path, segment);
            callable_body_scope = Some((body.id(), id, callable_path));
        }

        let mut cursor = frame.node.walk();
        let children = frame.node.named_children(&mut cursor).collect::<Vec<_>>();
        for child in children.into_iter().rev() {
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
            });
        }
    }

    Ok(ProcedureEnumeration::Complete(specs))
}

fn declaration_container_kind(node: Node<'_>) -> Option<DeclarationSegmentKind> {
    match node.kind() {
        "namespace_definition" => Some(DeclarationSegmentKind::Namespace),
        "class_declaration"
        | "interface_declaration"
        | "trait_declaration"
        | "enum_declaration"
        | "anonymous_class" => Some(DeclarationSegmentKind::Type),
        _ => None,
    }
}

fn declaration_container_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    node.child_by_field_name("name")
        .and_then(|name| nonempty_node_text(source, name))
        .map(Box::<str>::from)
}

fn callable_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    if node.kind() == "property_hook" {
        let hook = property_hook_name(node).and_then(|name| nonempty_node_text(source, name))?;
        let property =
            enclosing_property_name(source, node).unwrap_or_else(|| Box::<str>::from("<property>"));
        return Some(format!("{property}.{hook}").into_boxed_str());
    }
    node.child_by_field_name("name")
        .and_then(|name| nonempty_node_text(source, name))
        .map(Box::<str>::from)
        .or_else(|| enclosing_binding_name(source, node))
}

fn enclosing_property_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    let mut parent = node.parent();
    while let Some(candidate) = parent {
        if candidate.kind() == "property_declaration" {
            return named_children(candidate)
                .into_iter()
                .find(|child| child.kind() == "property_element")
                .and_then(|element| {
                    element
                        .child_by_field_name("name")
                        .or_else(|| element.named_child(0))
                })
                .and_then(|name| nonempty_node_text(source, name))
                .map(Box::<str>::from);
        }
        parent = candidate.parent();
    }
    None
}

fn enclosing_binding_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    let mut value = node;
    loop {
        let parent = value.parent()?;
        match parent.kind() {
            "parenthesized_expression" => value = parent,
            "assignment_expression" if field_matches(parent, "right", value) => {
                return parent
                    .child_by_field_name("left")
                    .and_then(|left| nonempty_node_text(source, left))
                    .map(Box::<str>::from);
            }
            "argument" | "return_statement" => return None,
            _ => return None,
        }
    }
}

fn callable_shape<'tree>(
    source: &str,
    node: Node<'tree>,
    lexical_parent: Option<ProcedureId>,
) -> Option<(
    ProcedureKind,
    DeclarationSegmentKind,
    Node<'tree>,
    ProcedureProperties,
    bool,
)> {
    let body = node.child_by_field_name("body")?;
    let (kind, segment_kind, is_static, returns_value) = match node.kind() {
        "function_definition" => (
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
            false,
            false,
        ),
        "method_declaration" => {
            let constructor = node
                .child_by_field_name("name")
                .and_then(|name| node_text(source, name))
                .is_some_and(|name| name.eq_ignore_ascii_case("__construct"));
            (
                if constructor {
                    ProcedureKind::Constructor
                } else {
                    ProcedureKind::Method
                },
                if constructor {
                    DeclarationSegmentKind::Constructor
                } else {
                    DeclarationSegmentKind::Method
                },
                has_direct_named_child(node, "static_modifier"),
                false,
            )
        }
        "anonymous_function" => (
            ProcedureKind::Closure,
            DeclarationSegmentKind::Closure,
            has_direct_named_child(node, "static_modifier"),
            false,
        ),
        "arrow_function" => (
            ProcedureKind::Lambda,
            DeclarationSegmentKind::Lambda,
            has_direct_named_child(node, "static_modifier"),
            true,
        ),
        "property_hook" => {
            let hook_returns = property_hook_name(node)
                .and_then(|name| node_text(source, name))
                .is_some_and(|name| name.eq_ignore_ascii_case("get"));
            (
                ProcedureKind::Accessor,
                DeclarationSegmentKind::Method,
                enclosing_property_is_static(node),
                body.kind() != "compound_statement" && hook_returns,
            )
        }
        _ => return None,
    };
    let is_generator = body_contains_yield(body);
    let dispatch_extensibility = if is_static
        || matches!(
            kind,
            ProcedureKind::Constructor
                | ProcedureKind::Function
                | ProcedureKind::LocalFunction
                | ProcedureKind::Closure
                | ProcedureKind::Lambda
        )
        || has_direct_named_child(node, "final_modifier")
        || has_private_visibility(node, source)
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
            is_generator,
            is_static,
            is_synthetic: false,
            invocation: if is_generator {
                ProcedureInvocationKind::Deferred
            } else {
                ProcedureInvocationKind::Immediate
            },
            dispatch_extensibility,
        },
        returns_value,
    ))
}

fn has_private_visibility(node: Node<'_>, source: &str) -> bool {
    named_children(node).into_iter().any(|child| {
        child.kind() == "visibility_modifier"
            && node_text(source, child).is_some_and(|text| text.eq_ignore_ascii_case("private"))
    })
}

fn enclosing_trait(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if parent.kind() == "trait_declaration" {
            return true;
        }
        if matches!(
            parent.kind(),
            "class_declaration" | "interface_declaration" | "enum_declaration"
        ) {
            return false;
        }
        node = parent;
    }
    false
}

fn enclosing_property_is_static(node: Node<'_>) -> bool {
    let mut parent = node.parent();
    while let Some(candidate) = parent {
        if candidate.kind() == "property_declaration" {
            return has_direct_named_child(candidate, "static_modifier");
        }
        parent = candidate.parent();
    }
    false
}

fn property_hook_name(node: Node<'_>) -> Option<Node<'_>> {
    named_children(node)
        .into_iter()
        .find(|child| child.kind() == "name")
}

fn body_contains_yield(body: Node<'_>) -> bool {
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if node != body && is_callable_kind(node.kind()) {
            continue;
        }
        if node.kind() == "yield_expression" {
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

type PhpLoweringError = ProcedureLoweringError;

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
        /// Destination for a nullsafe dereference that aborts the surrounding
        /// PHP dereference chain. Arguments, subscript indices, and dynamic
        /// member names intentionally start fresh sub-chains.
        chain_short_circuit: Option<ProgramPointId>,
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

#[derive(Debug, Clone)]
enum PhpControlKind {
    Loop,
    Switch,
}

#[derive(Debug, Clone)]
struct PhpControlFrame {
    label: Box<str>,
    kind: PhpControlKind,
}

struct LoweringContext<'tree, 'targets> {
    prepared: &'tree PreparedSyntaxTree,
    session: ProcedureLoweringSession<'targets>,
    expression_values: HashMap<usize, ValueId>,
    parameters: HashMap<Box<str>, ValueId>,
    locals: HashMap<Box<str>, LocalBinding>,
    receiver: Option<ValueId>,
    next_control_label: usize,
    cleanups: Vec<CleanupRegion<'tree>>,
    controls: HashMap<ScopeFrameId, Box<[PhpControlFrame]>>,
}

#[derive(Debug, Clone, Copy)]
struct LocalBinding {
    declaration_start: usize,
    value: ValueId,
}

fn lower_procedure<'tree>(
    prepared: &'tree PreparedSyntaxTree,
    spec: &ProcedureSpec<'tree>,
    budget: &SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<(ProcedureSemanticsParts, SemanticWork), PhpLoweringError> {
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
    let mut controls = HashMap::default();
    controls.insert(function_scope, Box::default());
    let mut context = LoweringContext {
        prepared,
        session,
        expression_values: HashMap::default(),
        parameters: HashMap::default(),
        locals: HashMap::default(),
        receiver: None,
        next_control_label: 0,
        cleanups: Vec::new(),
        controls,
    };
    context.emit_procedure_inputs(
        &mut builder,
        entry,
        spec.callable,
        spec.kind,
        spec.properties,
    )?;
    context.emit_local_bindings(&mut builder, spec.body)?;

    if spec.properties.is_generator {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::GeneratorSuspension,
            SemanticGapKind::Unsupported,
            "generator construction, suspension, delegation, send, and resumption are not fully modeled",
        )?;
    }
    if spec.lexical_parent.is_some() {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::Captures,
            SemanticGapKind::Unsupported,
            "PHP closure use-lists, implicit by-value captures, and bound current receivers are not fully modeled",
        )?;
    }
    if enclosing_trait(spec.callable) {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::DynamicDispatch,
            SemanticGapKind::Unknown,
            "trait composition, conflict resolution, and consuming-class refinement require workspace dispatch evidence",
        )?;
    }

    let body_entry = context.point(&mut builder, spec.body, Vec::new())?;
    let body_work = if spec.body.kind() == "compound_statement" {
        Work::Statement {
            node: spec.body,
            entry: body_entry,
            next: EdgeTarget::normal(normal_exit),
            scope: function_scope,
        }
    } else if spec.returns_value {
        let implicit_return = context.point(&mut builder, spec.body, Vec::new())?;
        let source =
            context.expression_value(&mut builder, spec.body, expression_value_kind(spec.body))?;
        let value = context.value(&mut builder, implicit_return, SemanticValueKind::Return)?;
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
            chain_short_circuit: None,
        }
    } else {
        Work::Expression {
            node: spec.body,
            entry: body_entry,
            next: EdgeTarget::normal(normal_exit),
            scope: function_scope,
            chain_short_circuit: None,
        }
    };
    context.edge(&mut builder, entry, EdgeTarget::normal(body_entry))?;

    let mut drive_error = None;
    if let Err(error) =
        builder.drive_iteratively(body_work, cancellation, |builder, work, stack| {
            context.step(builder, work, stack)
        })
    {
        drive_error = Some(error);
    }
    if let Some(error) = drive_error {
        let work = builder.prospective_work();
        return match error {
            DriveError::Cancelled | DriveError::Step(PhpLoweringError::Cancelled(_)) => {
                Err(PhpLoweringError::Cancelled(Box::new(work)))
            }
            DriveError::ExceededBudget(exceeded) => {
                Err(PhpLoweringError::Budget(exceeded, Box::new(work)))
            }
            DriveError::Step(PhpLoweringError::Budget(exceeded, _)) => {
                Err(PhpLoweringError::Budget(exceeded, Box::new(work)))
            }
            DriveError::Step(PhpLoweringError::Invalid(detail)) => {
                Err(PhpLoweringError::Invalid(detail))
            }
        };
    }

    if builder
        .seal_unreachable_regions(entry, normal_exit, exceptional_exit, cancellation)
        .is_err()
    {
        return Err(PhpLoweringError::Cancelled(Box::new(
            builder.prospective_work(),
        )));
    }
    let work_before_freeze = builder.prospective_work();
    builder
        .finish_with_work()
        .map_err(|error| PhpLoweringError::Budget(error, Box::new(work_before_freeze)))
}

impl<'tree, 'targets> LoweringContext<'tree, 'targets> {
    fn emit_procedure_inputs(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        callable: Node<'tree>,
        procedure_kind: ProcedureKind,
        properties: ProcedureProperties,
    ) -> Result<(), PhpLoweringError> {
        let declaration_range = node_range(callable);
        let layout = formal_parameter_slots_for_owner(
            Language::Php,
            callable,
            self.prepared.source(),
            &declaration_range,
        )
        .unwrap_or_default();
        let mut ordinal = 0_u32;
        for slot in layout.slots {
            if self.session.cancellation().is_cancelled() {
                return Err(PhpLoweringError::Cancelled(Box::new(
                    builder.prospective_work(),
                )));
            }
            let declaration = callable
                .named_descendant_for_byte_range(
                    slot.declaration_range.start_byte,
                    slot.declaration_range.end_byte,
                )
                .unwrap_or(callable);
            let mapping_node = slot
                .names
                .first()
                .and_then(|name| {
                    declaration.child_by_field_name("name").filter(|candidate| {
                        php_variable_name(self.prepared.source(), *candidate)
                            == normalize_php_name(name)
                    })
                })
                .unwrap_or(declaration);
            let metadata = self.value_mapping(builder, mapping_node)?;
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
                .ok_or_else(|| PhpLoweringError::Invalid("too many PHP parameters".into()))?;
            for name in slot.names {
                let name = normalize_php_name(&name);
                if !name.is_empty() {
                    self.parameters.insert(name.into(), value);
                }
            }
            if slot.variadic.is_some() || has_direct_named_child(declaration, "reference_modifier")
            {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Value(value),
                    SemanticCapability::ParameterFlow,
                    SemanticGapKind::Unsupported,
                    "PHP variadic expansion and by-reference parameter aliasing are not fully modeled",
                )?;
            }
        }

        if !properties.is_static
            && matches!(
                procedure_kind,
                ProcedureKind::Method | ProcedureKind::Constructor | ProcedureKind::Accessor
            )
        {
            let metadata = self.value_mapping(builder, callable)?;
            let receiver = self.session.add_value_with_metadata(
                builder,
                metadata,
                SemanticValueKind::Receiver,
            )?;
            self.receiver = Some(receiver);
            self.parameters.insert("this".into(), receiver);
        }
        Ok(())
    }

    fn emit_local_bindings(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        body: Node<'tree>,
    ) -> Result<(), PhpLoweringError> {
        try_walk_named_tree_preorder(body, true, |node| {
            if self.session.cancellation().is_cancelled() {
                return Err(PhpLoweringError::Cancelled(Box::new(
                    builder.prospective_work(),
                )));
            }
            if node.id() != body.id() && is_callable_kind(node.kind()) {
                return Ok(WalkControl::SkipChildren);
            }
            if node.kind() == "assignment_expression"
                && let Some(left) = node.child_by_field_name("left")
                && left.kind() == "variable_name"
            {
                let name = php_variable_name(self.prepared.source(), left);
                if name.is_empty()
                    || name == "this"
                    || self.parameters.contains_key(name)
                    || self.locals.contains_key(name)
                {
                    return Ok(WalkControl::Continue);
                }
                let metadata = self.value_mapping(builder, left)?;
                let value = self.session.add_value_with_metadata(
                    builder,
                    metadata,
                    SemanticValueKind::Local,
                )?;
                self.locals.insert(
                    name.into(),
                    LocalBinding {
                        declaration_start: left.start_byte(),
                        value,
                    },
                );
            }
            Ok(WalkControl::Continue)
        })
    }

    fn binding_value(&self, name: &str) -> Option<(ValueId, ValueFlowKind)> {
        if let Some(binding) = self.locals.get(name) {
            Some((binding.value, ValueFlowKind::Local))
        } else {
            self.parameters.get(name).map(|value| {
                (
                    *value,
                    if Some(*value) == self.receiver {
                        ValueFlowKind::Receiver
                    } else {
                        ValueFlowKind::Parameter
                    },
                )
            })
        }
    }

    fn local_declaration_value(&self, name: &str, start_byte: usize) -> Option<ValueId> {
        self.locals
            .get(name)
            .filter(|binding| binding.declaration_start == start_byte)
            .map(|binding| binding.value)
    }

    fn expression_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        kind: SemanticValueKind,
    ) -> Result<ValueId, PhpLoweringError> {
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

    fn source_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        kind: SemanticValueKind,
    ) -> Result<ValueId, PhpLoweringError> {
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
    ) -> Result<(), PhpLoweringError> {
        if node.kind() != "variable_name" {
            return Ok(());
        }
        let name = php_variable_name(self.prepared.source(), node);
        let Some((source, kind)) = self.binding_value(name) else {
            return Ok(());
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

    fn leaf_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
    ) -> Result<(), PhpLoweringError> {
        let value = self.expression_value(builder, node, expression_value_kind(node))?;
        self.emit_lexical_input_flow(builder, node, entry, value)?;
        self.edge(builder, entry, next)
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
    ) -> Result<(), PhpLoweringError> {
        let left = required_field(node, "left")?;
        let right = required_field(node, "right")?;
        let terminal = self.point(builder, node, Vec::new())?;
        if left.kind() == "variable_name" {
            let name = php_variable_name(self.prepared.source(), left);
            let target = self
                .local_declaration_value(name, left.start_byte())
                .or_else(|| self.binding_value(name).map(|(value, _)| value));
            if let Some(target) = target {
                let value = self.expression_value(builder, right, expression_value_kind(right))?;
                self.append_effect(
                    builder,
                    terminal,
                    SemanticEffect::Assignment { target, value },
                )?;
                if matches!(
                    right.kind(),
                    "match_expression" | "conditional_expression" | "binary_expression"
                ) {
                    let children = runtime_expression_children(node);
                    self.note_unspecified_evaluation_order(builder, terminal, node, &children)?;
                    self.add_magic_dispatch_gaps(
                        builder,
                        terminal,
                        "branching expression assignment",
                    )?;
                    self.add_gap(
                        builder,
                        terminal,
                        SemanticGapSubject::Value(target),
                        SemanticCapability::Values,
                        SemanticGapKind::Unknown,
                        "PHP branch and coalescing value joins are not yet lowered into explicit alternatives",
                    )?;
                }
            } else {
                self.add_gap(
                    builder,
                    terminal,
                    SemanticGapSubject::Point,
                    SemanticCapability::Assignments,
                    SemanticGapKind::Unknown,
                    "dynamic or unbound PHP assignment target is not represented as a stable local",
                )?;
            }
            self.edge(builder, terminal, next)?;
            return self.schedule_expressions(
                builder,
                entry,
                &[right],
                EdgeTarget::normal(terminal),
                scope,
                stack,
            );
        }

        self.add_magic_dispatch_gaps(builder, terminal, "property or indexed assignment")?;
        self.add_gap(
            builder,
            terminal,
            SemanticGapSubject::Point,
            SemanticCapability::Assignments,
            SemanticGapKind::Unsupported,
            "PHP property, index, destructuring, and dynamic-variable assignment flow is not lowered",
        )?;
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

    fn step(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        work: Work<'tree>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PhpLoweringError> {
        if self.session.cancellation().is_cancelled() {
            return Err(PhpLoweringError::Cancelled(Box::default()));
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
                chain_short_circuit,
            } => self.expression(
                builder,
                node,
                entry,
                next,
                scope,
                chain_short_circuit,
                stack,
            ),
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
    ) -> Result<(), PhpLoweringError> {
        match (node.kind(), php_short_circuit_operator(node)) {
            ("binary_expression", Some("&&" | "and")) => {
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
            ("binary_expression", Some("||" | "or")) => {
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
                let nullish_decision = self.point(builder, left, Vec::new())?;
                let nonnull_truthiness = self.point(builder, left, Vec::new())?;
                self.edge(
                    builder,
                    nullish_decision,
                    EdgeTarget {
                        point: nonnull_truthiness,
                        kind: ControlEdgeKind::ConditionalTrue,
                    },
                )?;
                self.edge(
                    builder,
                    nullish_decision,
                    EdgeTarget {
                        point: right_entry,
                        kind: ControlEdgeKind::ConditionalFalse,
                    },
                )?;
                self.edge(builder, nonnull_truthiness, when_true)?;
                self.edge(builder, nonnull_truthiness, when_false)?;
                stack.push(Work::Condition {
                    node: right,
                    entry: right_entry,
                    when_true,
                    when_false,
                    scope,
                });
                stack.push(Work::Expression {
                    node: left,
                    entry,
                    next: EdgeTarget::normal(nullish_decision),
                    scope,
                    chain_short_circuit: None,
                });
                Ok(())
            }
            ("conditional_expression", _) => {
                let condition = required_field(node, "condition")?;
                let body = node.child_by_field_name("body");
                let alternative = required_field(node, "alternative")?;
                let body_entry = body
                    .map(|body| self.point(builder, body, Vec::new()))
                    .transpose()?;
                let alternative_entry = self.point(builder, alternative, Vec::new())?;
                stack.push(Work::Condition {
                    node: alternative,
                    entry: alternative_entry,
                    when_true,
                    when_false,
                    scope,
                });
                if let (Some(body), Some(body_entry)) = (body, body_entry) {
                    stack.push(Work::Condition {
                        node: body,
                        entry: body_entry,
                        when_true,
                        when_false,
                        scope,
                    });
                }
                stack.push(Work::Condition {
                    node: condition,
                    entry,
                    when_true: EdgeTarget {
                        point: body_entry.unwrap_or(when_true.point),
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
                    chain_short_circuit: None,
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
    ) -> Result<(), PhpLoweringError> {
        match node.kind() {
            "compound_statement" | "colon_block" => {
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
            "return_statement" => self.return_statement(builder, node, entry, scope, stack),
            "break_statement" | "continue_statement" => {
                self.break_or_continue(builder, node, entry, scope, stack)
            }
            "if_statement" => self.if_statement(builder, node, entry, next, scope, stack),
            "while_statement" => self.while_statement(builder, node, entry, next, scope, stack),
            "do_statement" => self.do_statement(builder, node, entry, next, scope, stack),
            "for_statement" => self.for_statement(builder, node, entry, next, scope, stack),
            "foreach_statement" => self.foreach_statement(builder, node, entry, next, scope, stack),
            "switch_statement" => self.switch_statement(builder, node, entry, next, scope, stack),
            "try_statement" => self.try_statement(builder, node, entry, next, scope, stack),
            "exit_statement" => self.exit_boundary(builder, node, entry, scope, stack),
            "goto_statement" => self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::NonLocalControl,
                SemanticGapKind::Unsupported,
                "goto label resolution and non-local transfer are not lowered",
            ),
            "named_label_statement" => {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::NonLocalControl,
                    SemanticGapKind::Unsupported,
                    "label reachability from goto is not lowered",
                )?;
                self.edge(builder, entry, next)
            }
            "echo_statement" | "unset_statement" => {
                let boundary = self.point(builder, node, Vec::new())?;
                if node.kind() == "unset_statement" {
                    for (capability, detail) in [
                        (
                            SemanticCapability::ResourceManagement,
                            "unset and destructor/resource lifetime effects are not lowered",
                        ),
                        (
                            SemanticCapability::Calls,
                            "magic __unset dispatch is not represented as a fabricated call site",
                        ),
                        (
                            SemanticCapability::ExceptionalControlFlow,
                            "magic __unset and operand failures are not lowered",
                        ),
                    ] {
                        self.add_gap(
                            builder,
                            boundary,
                            SemanticGapSubject::Point,
                            capability,
                            SemanticGapKind::Unknown,
                            detail,
                        )?;
                    }
                }
                self.edge(builder, boundary, next)?;
                let expressions = runtime_expression_children(node);
                self.schedule_expressions(
                    builder,
                    entry,
                    &expressions,
                    EdgeTarget::normal(boundary),
                    scope,
                    stack,
                )
            }
            "global_declaration"
            | "static_variable_declaration"
            | "const_declaration"
            | "property_declaration" => {
                let initializers = declaration_initializers(node);
                self.schedule_expressions(builder, entry, &initializers, next, scope, stack)
            }
            "function_static_declaration" => {
                self.function_static_declaration(builder, node, entry, next, scope, stack)
            }
            "declare_statement" => self.declare_statement(builder, node, entry, next, scope, stack),
            "function_definition" => self.function_definition_statement(builder, entry, next),
            "class_declaration"
            | "interface_declaration"
            | "trait_declaration"
            | "enum_declaration" => self.declaration_boundary(builder, entry, next),
            "namespace_definition" => {
                if let Some(body) = node.child_by_field_name("body") {
                    stack.push(Work::Statement {
                        node: body,
                        entry,
                        next,
                        scope,
                    });
                    Ok(())
                } else {
                    self.edge(builder, entry, next)
                }
            }
            "empty_statement" | "namespace_use_declaration" => self.edge(builder, entry, next),
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
    ) -> Result<(), PhpLoweringError> {
        let values = runtime_expression_children(node);
        let terminal = if values.is_empty() {
            entry
        } else {
            self.point(builder, node, Vec::new())?
        };
        let value = if let [returned] = values.as_slice() {
            let source =
                self.expression_value(builder, *returned, expression_value_kind(*returned))?;
            let target = self.value(builder, terminal, SemanticValueKind::Return)?;
            self.append_effect(
                builder,
                terminal,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Return,
                    source,
                    target,
                },
            )?;
            Some(target)
        } else {
            None
        };
        if values.len() > 1 {
            self.add_gap(
                builder,
                terminal,
                SemanticGapSubject::Point,
                SemanticCapability::ReturnFlow,
                SemanticGapKind::Unsupported,
                "PHP return statement contained an unexpected multi-expression value shape",
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

    fn throw_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PhpLoweringError> {
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

    fn break_or_continue(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PhpLoweringError> {
        let requested = if node.kind() == "break_statement" {
            CompletionKind::Break
        } else {
            CompletionKind::Continue
        };
        let level = if let Some(level_node) = first_runtime_named_child(node) {
            let Some(level) = node_text(self.prepared.source(), level_node)
                .and_then(|text| text.parse::<usize>().ok())
            else {
                return self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::NonLocalControl,
                    SemanticGapKind::Unsupported,
                    "dynamic or non-decimal break/continue levels are not lowered",
                );
            };
            level
        } else {
            1
        };
        if level == 0 {
            return self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::NonLocalControl,
                SemanticGapKind::Unsupported,
                "zero break/continue level is invalid and has no represented transfer",
            );
        }
        let Some(frame) = self
            .controls
            .get(&scope)
            .and_then(|frames| frames.iter().rev().nth(level - 1))
            .cloned()
        else {
            return self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::NonLocalControl,
                SemanticGapKind::Unsupported,
                "break/continue level exceeds represented loop and switch nesting",
            );
        };
        let completion = match (requested, frame.kind) {
            (CompletionKind::Continue, PhpControlKind::Switch) => CompletionKind::Break,
            _ => requested,
        };
        self.abrupt(builder, entry, scope, completion, Some(&frame.label), stack)
    }

    fn function_definition_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        next: EdgeTarget,
    ) -> Result<(), PhpLoweringError> {
        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::DeferredExecution,
            SemanticGapKind::Unknown,
            "conditional function declaration timing and redeclaration behavior require runtime context",
        )?;
        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            "conditional function redeclaration failures are not lowered",
        )?;
        self.edge(builder, entry, next)
    }

    #[allow(clippy::too_many_arguments)]
    fn function_static_declaration(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PhpLoweringError> {
        let initializers = declaration_initializers(node);
        if initializers.is_empty() {
            return self.edge(builder, entry, next);
        }
        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::NormalControlFlow,
            SemanticGapKind::Unknown,
            "function-static initializers execute only on first initialization; both initialized and uninitialized states are represented",
        )?;
        let first = self.point(builder, initializers[0], Vec::new())?;
        self.edge(
            builder,
            entry,
            EdgeTarget {
                point: first,
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
        self.schedule_expressions_from_first(builder, first, &initializers, next, scope, stack)
    }

    #[allow(clippy::too_many_arguments)]
    fn declare_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PhpLoweringError> {
        for (capability, detail) in [
            (
                SemanticCapability::NormalControlFlow,
                "declare directive scope and tick scheduling require runtime/configuration refinement",
            ),
            (
                SemanticCapability::Calls,
                "tick callbacks introduced by declare are not represented as fabricated call sites",
            ),
            (
                SemanticCapability::ExceptionalControlFlow,
                "tick callback failures and directive-specific runtime errors are not lowered",
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
        let statements = named_children(node)
            .into_iter()
            .filter(|child| is_statement_kind(child.kind()))
            .collect::<Vec<_>>();
        self.schedule_statements(builder, entry, &statements, next, scope, stack)
    }

    fn declaration_boundary(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        next: EdgeTarget,
    ) -> Result<(), PhpLoweringError> {
        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::DeferredExecution,
            SemanticGapKind::Unknown,
            "conditional type declaration and registration timing require runtime context",
        )?;
        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            "type declaration, trait composition, and redeclaration failures are not lowered",
        )?;
        self.edge(builder, entry, next)
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
    ) -> Result<(), PhpLoweringError> {
        let condition = required_field(node, "condition")?;
        let body = required_field(node, "body")?;
        let alternatives = children_by_field_name(node, "alternative");
        let mut conditional_arms = vec![(condition, body, entry)];
        let mut final_alternative = None;
        for alternative in alternatives {
            match alternative.kind() {
                "else_if_clause" => {
                    let condition = required_field(alternative, "condition")?;
                    let body = required_field(alternative, "body")?;
                    let condition_entry = self.point(builder, condition, Vec::new())?;
                    conditional_arms.push((condition, body, condition_entry));
                }
                "else_clause" => {
                    final_alternative = Some(required_field(alternative, "body")?);
                }
                _ => {}
            }
        }

        let alternative_entry = final_alternative
            .map(|alternative| self.point(builder, alternative, Vec::new()))
            .transpose()?;
        if let (Some(alternative), Some(alternative_entry)) = (final_alternative, alternative_entry)
        {
            stack.push(Work::Statement {
                node: alternative,
                entry: alternative_entry,
                next,
                scope,
            });
        }

        let body_entries = conditional_arms
            .iter()
            .map(|(_, body, _)| self.point(builder, *body, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        for (index, ((condition, body, condition_entry), body_entry)) in
            conditional_arms.iter().zip(&body_entries).enumerate().rev()
        {
            let false_target = conditional_arms
                .get(index + 1)
                .map(|(_, _, entry)| EdgeTarget {
                    point: *entry,
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
            stack.push(Work::Statement {
                node: *body,
                entry: *body_entry,
                next,
                scope,
            });
            stack.push(Work::Condition {
                node: *condition,
                entry: *condition_entry,
                when_true: EdgeTarget {
                    point: *body_entry,
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
    ) -> Result<(), PhpLoweringError> {
        let condition = required_field(node, "condition")?;
        let body = required_field(node, "body")?;
        let condition_entry = self.point(builder, condition, Vec::new())?;
        let body_entry = self.point(builder, body, Vec::new())?;
        let loop_scope = self.push_loop_scope(
            builder,
            scope,
            next,
            condition_entry,
            ControlEdgeKind::LoopBack,
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
        self.edge(builder, entry, EdgeTarget::normal(condition_entry))?;
        Ok(())
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
    ) -> Result<(), PhpLoweringError> {
        let condition = required_field(node, "condition")?;
        let body = required_field(node, "body")?;
        let condition_entry = self.point(builder, condition, Vec::new())?;
        let body_entry = self.point(builder, body, Vec::new())?;
        let loop_scope = self.push_loop_scope(
            builder,
            scope,
            next,
            condition_entry,
            ControlEdgeKind::Normal,
        );
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
            scope: loop_scope,
        });
        stack.push(Work::Statement {
            node: body,
            entry: body_entry,
            next: EdgeTarget::normal(condition_entry),
            scope: loop_scope,
        });
        self.edge(builder, entry, EdgeTarget::normal(body_entry))?;
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
    ) -> Result<(), PhpLoweringError> {
        let bodies = children_by_field_name(node, "body");
        let initializer = node.child_by_field_name("initialize");
        let condition = node.child_by_field_name("condition");
        let update = node.child_by_field_name("update");
        let condition_entry = match condition {
            Some(condition) => self.point(builder, condition, Vec::new())?,
            None => self.point(builder, node, Vec::new())?,
        };
        let body_anchor = if let [body] = bodies.as_slice() {
            *body
        } else {
            node
        };
        let body_entry = self.point(builder, body_anchor, Vec::new())?;
        let update_entry = update
            .map(|update| self.point(builder, update, Vec::new()))
            .transpose()?;
        let continue_target = update_entry.unwrap_or(condition_entry);
        let loop_scope = self.push_loop_scope(
            builder,
            scope,
            next,
            continue_target,
            if update.is_some() {
                ControlEdgeKind::Normal
            } else {
                ControlEdgeKind::LoopBack
            },
        );

        if let Some(update) = update {
            stack.push(Work::Expression {
                node: update,
                entry: update_entry.expect("update entry exists"),
                next: EdgeTarget {
                    point: condition_entry,
                    kind: ControlEdgeKind::LoopBack,
                },
                scope: loop_scope,
                chain_short_circuit: None,
            });
        }
        let body_next = EdgeTarget {
            point: continue_target,
            kind: if update.is_some() {
                ControlEdgeKind::Normal
            } else {
                ControlEdgeKind::LoopBack
            },
        };
        if let [body] = bodies.as_slice() {
            stack.push(Work::Statement {
                node: *body,
                entry: body_entry,
                next: body_next,
                scope: loop_scope,
            });
        } else {
            self.schedule_statements(builder, body_entry, &bodies, body_next, loop_scope, stack)?;
        }
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
            stack.push(Work::Expression {
                node: initializer,
                entry,
                next: EdgeTarget::normal(condition_entry),
                scope: loop_scope,
                chain_short_circuit: None,
            });
        } else if entry != condition_entry {
            self.edge(builder, entry, EdgeTarget::normal(condition_entry))?;
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
    ) -> Result<(), PhpLoweringError> {
        let body = node.child_by_field_name("body");
        let mut operands = named_children(node)
            .into_iter()
            .filter(|child| body.is_none_or(|body| child.id() != body.id()))
            .filter(|child| child.kind() != "by_ref")
            .collect::<Vec<_>>();
        let iterable = operands
            .first()
            .copied()
            .ok_or_else(|| missing_field(node, "iterable"))?;
        operands.remove(0);
        let test = self.point(builder, node, Vec::new())?;
        let binding = self.point(builder, node, Vec::new())?;
        let body_entry = self.point(builder, body.unwrap_or(node), Vec::new())?;
        let loop_scope =
            self.push_loop_scope(builder, scope, next, test, ControlEdgeKind::LoopBack);
        for (capability, kind, detail) in [
            (
                SemanticCapability::Calls,
                SemanticGapKind::Unknown,
                "foreach iterator acquisition and advancement calls require runtime refinement",
            ),
            (
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unsupported,
                "foreach iterator and destructuring failures are not lowered",
            ),
        ] {
            self.add_gap(
                builder,
                test,
                SemanticGapSubject::Point,
                capability,
                kind,
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
                point: next.point,
                kind: ControlEdgeKind::ConditionalFalse,
            },
        )?;
        let body_next = EdgeTarget {
            point: test,
            kind: ControlEdgeKind::LoopBack,
        };
        if let Some(body) = body {
            stack.push(Work::Statement {
                node: body,
                entry: body_entry,
                next: body_next,
                scope: loop_scope,
            });
        } else {
            self.edge(builder, body_entry, body_next)?;
        }
        self.schedule_expressions(
            builder,
            binding,
            &operands,
            EdgeTarget::normal(body_entry),
            loop_scope,
            stack,
        )?;
        stack.push(Work::Expression {
            node: iterable,
            entry,
            next: EdgeTarget::normal(test),
            scope: loop_scope,
            chain_short_circuit: None,
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
    ) -> Result<(), PhpLoweringError> {
        let value = required_field(node, "condition")?;
        let body = required_field(node, "body")?;
        let dispatch = self.point(builder, node, Vec::new())?;
        let switch_scope = self.push_switch_scope(builder, scope, next);
        let cases = named_children(body)
            .into_iter()
            .filter(|child| matches!(child.kind(), "case_statement" | "default_statement"))
            .collect::<Vec<_>>();
        if cases.is_empty() {
            self.edge(builder, dispatch, next)?;
        } else {
            let entries = cases
                .iter()
                .map(|case| self.point(builder, *case, Vec::new()))
                .collect::<Result<Vec<_>, _>>()?;
            for (index, case) in cases.iter().enumerate().rev() {
                let statements = named_children(*case)
                    .into_iter()
                    .filter(|child| is_statement_kind(child.kind()))
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

            let mut no_match = cases
                .iter()
                .position(|case| case.kind() == "default_statement")
                .map(|index| EdgeTarget::normal(entries[index]))
                .unwrap_or(next);
            for (index, case) in cases.iter().enumerate().rev() {
                if case.kind() != "case_statement" {
                    continue;
                }
                let predicate = required_field(*case, "value")?;
                let predicate_entry = self.point(builder, predicate, Vec::new())?;
                let comparison = self.point(builder, *case, Vec::new())?;
                self.add_magic_dispatch_gaps(
                    builder,
                    comparison,
                    "switch loose comparison and conversion",
                )?;
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
                    chain_short_circuit: None,
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
            chain_short_circuit: None,
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
    ) -> Result<(), PhpLoweringError> {
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
            .map(|clause| required_field(clause, "body"))
            .transpose()?;

        let (cleanup_scope, cleanup_region) = if let Some(finalizer) = finalizer {
            let region = CleanupRegionId::new(
                u32::try_from(self.cleanups.len())
                    .map_err(|_| PhpLoweringError::Invalid("too many cleanup regions".into()))?,
            );
            self.cleanups.push(CleanupRegion {
                id: region,
                body: finalizer,
                outer_scope: scope,
            });
            let cleanup_scope = builder.push_scope(Some(scope), ScopeBinding::Cleanup { region });
            self.copy_controls(scope, cleanup_scope);
            (cleanup_scope, Some(region))
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
            .map(|clause| required_field(*clause, "body"))
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
                "catch type matching, union selection, and throwable binding require runtime refinement",
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
            let handler_scope = builder.push_scope(
                Some(cleanup_scope),
                ScopeBinding::Handler { entry: dispatcher },
            );
            self.copy_controls(cleanup_scope, handler_scope);
            handler_scope
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
    fn expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        chain_short_circuit: Option<ProgramPointId>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PhpLoweringError> {
        match node.kind() {
            "function_call_expression"
            | "member_call_expression"
            | "nullsafe_member_call_expression"
            | "scoped_call_expression"
            | "object_creation_expression" => {
                if is_first_class_callable(node) {
                    self.first_class_callable(
                        builder,
                        node,
                        entry,
                        next,
                        scope,
                        chain_short_circuit,
                        stack,
                    )
                } else {
                    self.call_expression(
                        builder,
                        node,
                        entry,
                        next,
                        scope,
                        chain_short_circuit,
                        stack,
                    )
                }
            }
            "anonymous_function" | "arrow_function" => {
                self.callable_expression(builder, node, entry, next)
            }
            "throw_expression" => self.throw_expression(builder, node, entry, scope, stack),
            "yield_expression" => self.yield_expression(builder, node, entry, scope, stack),
            "match_expression" => self.match_expression(builder, node, entry, next, scope, stack),
            "conditional_expression" => {
                self.conditional_expression(builder, node, entry, next, scope, stack)
            }
            "binary_expression" if php_short_circuit_operator(node).is_some() => {
                self.short_circuit_expression(builder, node, entry, next, scope, stack)
            }
            "include_expression"
            | "include_once_expression"
            | "require_expression"
            | "require_once_expression" => {
                self.include_boundary(builder, node, entry, next, scope, stack)
            }
            "exit_statement" => self.exit_boundary(builder, node, entry, scope, stack),
            "member_access_expression"
            | "nullsafe_member_access_expression"
            | "scoped_property_access_expression"
            | "subscript_expression"
            | "class_constant_access_expression" => self.chain_access_expression(
                builder,
                node,
                entry,
                next,
                scope,
                chain_short_circuit,
                stack,
            ),
            "clone_expression" => {
                let boundary = self.point(builder, node, Vec::new())?;
                self.add_magic_dispatch_gaps(
                    builder,
                    boundary,
                    "clone and magic __clone dispatch",
                )?;
                self.add_gap(
                    builder,
                    boundary,
                    SemanticGapSubject::Point,
                    SemanticCapability::ResourceManagement,
                    SemanticGapKind::Unknown,
                    "cloned object lifetime and destructor/resource effects are not lowered",
                )?;
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
            "assignment_expression" => {
                self.assignment_expression(builder, node, entry, next, scope, stack)
            }
            "augmented_assignment_expression"
            | "reference_assignment_expression"
            | "binary_expression"
            | "unary_op_expression"
            | "update_expression"
            | "cast_expression" => {
                let boundary = self.point(builder, node, Vec::new())?;
                let children = runtime_expression_children(node);
                self.note_unspecified_evaluation_order(builder, boundary, node, &children)?;
                self.add_magic_dispatch_gaps(builder, boundary, "operator or assignment dispatch")?;
                self.edge(builder, boundary, next)?;
                self.schedule_expressions(
                    builder,
                    entry,
                    &children,
                    EdgeTarget::normal(boundary),
                    scope,
                    stack,
                )
            }
            "array_creation_expression"
            | "list_literal"
            | "pair"
            | "array_element_initializer"
            | "sequence_expression"
            | "argument"
            | "arguments"
            | "variadic_unpacking"
            | "dynamic_variable_name"
            | "encapsed_string"
            | "heredoc"
            | "nowdoc"
            | "string_value"
            | "print_intrinsic"
            | "error_suppression_expression" => {
                let children = runtime_expression_children(node);
                self.note_unspecified_evaluation_order(builder, entry, node, &children)?;
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            "parenthesized_expression" => {
                let children = runtime_expression_children(node);
                self.schedule_expressions_with_first_chain_short_circuit(
                    builder,
                    entry,
                    &children,
                    next,
                    scope,
                    chain_short_circuit,
                    stack,
                )
            }
            kind if is_runtime_leaf(kind) => self.leaf_expression(builder, node, entry, next),
            _ => self.unhandled_control_syntax(builder, node, entry),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn short_circuit_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PhpLoweringError> {
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

    #[allow(clippy::too_many_arguments)]
    fn chain_access_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        chain_short_circuit: Option<ProgramPointId>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PhpLoweringError> {
        let boundary = self.point(builder, node, Vec::new())?;
        let detail = match node.kind() {
            "subscript_expression" => "array access and ArrayAccess protocol dispatch",
            "class_constant_access_expression" => {
                "class constant resolution, autoload, and access checks"
            }
            _ => "property access and magic property dispatch",
        };
        self.add_magic_dispatch_gaps(builder, boundary, detail)?;
        self.edge(builder, boundary, next)?;

        let chain_destination = chain_short_circuit.unwrap_or(next.point);
        if node.kind() == "nullsafe_member_access_expression" {
            let object = required_field(node, "object")?;
            let object_entry = self.point(builder, object, Vec::new())?;
            let decision = self.point(builder, node, Vec::new())?;
            let remaining = runtime_expression_children(node)
                .into_iter()
                .filter(|child| child.id() != object.id())
                .collect::<Vec<_>>();
            self.edge(
                builder,
                decision,
                EdgeTarget {
                    point: chain_destination,
                    kind: ControlEdgeKind::ConditionalFalse,
                },
            )?;
            self.schedule_nullable_tail(builder, decision, &remaining, boundary, scope, stack)?;
            self.edge(builder, entry, EdgeTarget::normal(object_entry))?;
            stack.push(Work::Expression {
                node: object,
                entry: object_entry,
                next: EdgeTarget::normal(decision),
                scope,
                chain_short_circuit: Some(chain_destination),
            });
            return Ok(());
        }

        let children = runtime_expression_children(node);
        self.schedule_expressions_with_first_chain_short_circuit(
            builder,
            entry,
            &children,
            EdgeTarget::normal(boundary),
            scope,
            Some(chain_destination),
            stack,
        )
    }

    fn schedule_nullable_tail(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        decision: ProgramPointId,
        remaining: &[Node<'tree>],
        boundary: ProgramPointId,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PhpLoweringError> {
        if remaining.is_empty() {
            return self.edge(
                builder,
                decision,
                EdgeTarget {
                    point: boundary,
                    kind: ControlEdgeKind::ConditionalTrue,
                },
            );
        }
        let first = self.point(builder, remaining[0], Vec::new())?;
        self.edge(
            builder,
            decision,
            EdgeTarget {
                point: first,
                kind: ControlEdgeKind::ConditionalTrue,
            },
        )?;
        self.schedule_expressions_from_first(
            builder,
            first,
            remaining,
            EdgeTarget::normal(boundary),
            scope,
            stack,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn conditional_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PhpLoweringError> {
        let condition = required_field(node, "condition")?;
        let body = node.child_by_field_name("body");
        let alternative = required_field(node, "alternative")?;
        let merge = self.point(builder, node, Vec::new())?;
        let alternative_entry = self.point(builder, alternative, Vec::new())?;
        self.edge(builder, merge, next)?;
        stack.push(Work::Expression {
            node: alternative,
            entry: alternative_entry,
            next: EdgeTarget::normal(merge),
            scope,
            chain_short_circuit: None,
        });
        let true_target = if let Some(body) = body {
            let body_entry = self.point(builder, body, Vec::new())?;
            stack.push(Work::Expression {
                node: body,
                entry: body_entry,
                next: EdgeTarget::normal(merge),
                scope,
                chain_short_circuit: None,
            });
            body_entry
        } else {
            merge
        };
        stack.push(Work::Condition {
            node: condition,
            entry,
            when_true: EdgeTarget {
                point: true_target,
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

    #[allow(clippy::too_many_arguments)]
    fn match_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PhpLoweringError> {
        let subject = required_field(node, "condition")?;
        let body = required_field(node, "body")?;
        let arms = named_children(body);
        let merge = self.point(builder, node, Vec::new())?;
        self.edge(builder, merge, next)?;

        let mut conditional_candidates = Vec::new();
        let mut default_entry = None;
        for arm in arms {
            let result = required_field(arm, "return_expression")?;
            let result_entry = self.point(builder, result, Vec::new())?;
            stack.push(Work::Expression {
                node: result,
                entry: result_entry,
                next: EdgeTarget::normal(merge),
                scope,
                chain_short_circuit: None,
            });
            match arm.kind() {
                "match_conditional_expression" => {
                    let conditions = required_field(arm, "conditional_expressions")?;
                    for predicate in named_children(conditions) {
                        conditional_candidates.push((predicate, result_entry));
                    }
                }
                "match_default_expression" => default_entry = Some(result_entry),
                _ => {}
            }
        }

        let unmatched = if let Some(default_entry) = default_entry {
            EdgeTarget::normal(default_entry)
        } else {
            let unmatched = self.point(builder, node, Vec::new())?;
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
                "non-exhaustive match throws UnhandledMatchError; allocation and runtime details are not refined",
            )?;
            self.abrupt(
                builder,
                unmatched,
                scope,
                CompletionKind::Throw,
                None,
                stack,
            )?;
            EdgeTarget {
                point: unmatched,
                kind: ControlEdgeKind::Exceptional,
            }
        };

        let mut no_match = unmatched;
        for (predicate, result_entry) in conditional_candidates.into_iter().rev() {
            let predicate_entry = self.point(builder, predicate, Vec::new())?;
            let comparison = self.point(builder, predicate, Vec::new())?;
            self.edge(
                builder,
                comparison,
                EdgeTarget {
                    point: result_entry,
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
                scope,
                chain_short_circuit: None,
            });
            no_match = EdgeTarget::normal(predicate_entry);
        }
        stack.push(Work::Expression {
            node: subject,
            entry,
            next: no_match,
            scope,
            chain_short_circuit: None,
        });
        Ok(())
    }

    fn yield_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PhpLoweringError> {
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
            "yield suspension, sent values, thrown exceptions, and resumption are not lowered",
        )?;
        if has_direct_token(node, "from") {
            self.add_gap(
                builder,
                boundary,
                SemanticGapSubject::Point,
                SemanticCapability::Calls,
                SemanticGapKind::Unsupported,
                "yield-from iterator and delegation operations are not represented as call sites",
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
    fn include_boundary(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PhpLoweringError> {
        let boundary = self.point(builder, node, Vec::new())?;
        for (capability, kind, detail) in [
            (
                SemanticCapability::Calls,
                SemanticGapKind::Unsupported,
                "include/require file execution is not represented as a fabricated call site",
            ),
            (
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unsupported,
                "include warnings, require failures, and included-code exceptions are not lowered",
            ),
            (
                SemanticCapability::NormalControlFlow,
                SemanticGapKind::Unknown,
                "included code may define declarations, return a value, or terminate execution",
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
        self.edge(builder, boundary, next)?;
        let values = runtime_expression_children(node);
        self.schedule_expressions(
            builder,
            entry,
            &values,
            EdgeTarget::normal(boundary),
            scope,
            stack,
        )
    }

    fn exit_boundary(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PhpLoweringError> {
        let values = runtime_expression_children(node);
        let boundary = if values.is_empty() {
            entry
        } else {
            self.point(builder, node, Vec::new())?
        };
        for (capability, detail) in [
            (
                SemanticCapability::NonLocalControl,
                "exit/die process termination has no procedure-local continuation",
            ),
            (
                SemanticCapability::CleanupControlFlow,
                "shutdown functions, output flushing, and finalization during exit are not lowered",
            ),
            (
                SemanticCapability::ResourceManagement,
                "process-exit resource and destructor cleanup is not lowered",
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
        chain_short_circuit: Option<ProgramPointId>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PhpLoweringError> {
        let invoke = self.point(builder, node, Vec::new())?;
        let normal = self.point(builder, node, Vec::new())?;
        let exceptional = self.point(builder, node, Vec::new())?;
        let callable_anchor = php_callable_anchor(node).unwrap_or(node);
        let callee = self.source_value(builder, callable_anchor, SemanticValueKind::Callable)?;
        let result = self.expression_value(builder, node, SemanticValueKind::Temporary)?;
        let thrown = self.source_value(builder, callable_anchor, SemanticValueKind::Exception)?;
        let receiver_node = matches!(
            node.kind(),
            "member_call_expression" | "nullsafe_member_call_expression"
        )
        .then(|| node.child_by_field_name("object"))
        .flatten();
        let receiver = receiver_node
            .map(|receiver| {
                self.expression_value(builder, receiver, expression_value_kind(receiver))
            })
            .transpose()?;
        let callable_kind = match node.kind() {
            "member_call_expression" | "nullsafe_member_call_expression" => {
                CallableReferenceKind::BoundMethod
            }
            "scoped_call_expression" => CallableReferenceKind::StaticMethod,
            "object_creation_expression" => CallableReferenceKind::Constructor,
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

        let mut arguments = Vec::new();
        let mut incomplete_argument_mapping = false;
        for argument in call_arguments(node) {
            let Some(value_node) = php_call_argument_value(argument) else {
                incomplete_argument_mapping = true;
                continue;
            };
            let value =
                self.expression_value(builder, value_node, expression_value_kind(value_node))?;
            let semantic = match php_call_argument_shape(argument) {
                PhpCallArgumentShape::Positional => {
                    SemanticCallArgument::direct(value, ArgumentDomain::Positional)
                }
                PhpCallArgumentShape::Named => {
                    incomplete_argument_mapping = true;
                    SemanticCallArgument::direct(value, ArgumentDomain::Keyword)
                }
                PhpCallArgumentShape::ByReferenceOrSpread => {
                    incomplete_argument_mapping = true;
                    SemanticCallArgument::unclassified(value)
                }
            };
            arguments.push(semantic);
        }
        let call_site = self.session.add_call_site(
            builder,
            CallSiteScaffold {
                point: invoke,
                callee,
                receiver,
                arguments: arguments.into_boxed_slice(),
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
        if incomplete_argument_mapping {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::ParameterFlow,
                SemanticGapKind::Unsupported,
                "PHP named, unpacked, and by-reference arguments require resolved parameter binding",
            )?;
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
        self.abrupt(
            builder,
            exceptional,
            scope,
            CompletionKind::Throw,
            None,
            stack,
        )?;
        self.resolution_gaps(builder, invoke, callee, call_site, &resolution)?;
        let uses_runtime_class_dispatch =
            runtime_class_dispatch_scope(self.prepared.source(), node);
        if receiver.is_some() || uses_runtime_class_dispatch {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::DynamicDispatch,
                SemanticGapKind::Unknown,
                "member, late-static, or runtime-class dispatch may select an override, constructor, or magic method; receiver/runtime class and complete target coverage require class-hierarchy refinement",
            )?;
        }
        if node.kind() == "object_creation_expression" {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::Point,
                SemanticCapability::ResourceManagement,
                SemanticGapKind::Unknown,
                "object destructor timing and resource lifetime are not lowered",
            )?;
        }

        if node.kind() == "nullsafe_member_call_expression" {
            let object = required_field(node, "object")?;
            let object_entry = self.point(builder, object, Vec::new())?;
            let decision = self.point(builder, node, Vec::new())?;
            let remaining = nullsafe_call_tail(node);
            let chain_destination = chain_short_circuit.unwrap_or(next.point);
            self.edge(
                builder,
                decision,
                EdgeTarget {
                    point: chain_destination,
                    kind: ControlEdgeKind::ConditionalFalse,
                },
            )?;
            if remaining.is_empty() {
                self.edge(
                    builder,
                    decision,
                    EdgeTarget {
                        point: invoke,
                        kind: ControlEdgeKind::ConditionalTrue,
                    },
                )?;
            } else {
                let first = self.point(builder, remaining[0], Vec::new())?;
                self.edge(
                    builder,
                    decision,
                    EdgeTarget {
                        point: first,
                        kind: ControlEdgeKind::ConditionalTrue,
                    },
                )?;
                self.schedule_expressions_from_first(
                    builder,
                    first,
                    &remaining,
                    EdgeTarget::normal(invoke),
                    scope,
                    stack,
                )?;
            }
            self.edge(builder, entry, EdgeTarget::normal(object_entry))?;
            stack.push(Work::Expression {
                node: object,
                entry: object_entry,
                next: EdgeTarget::normal(decision),
                scope,
                chain_short_circuit: Some(chain_destination),
            });
            Ok(())
        } else {
            let evaluations = call_operand_evaluations(node);
            let first_chain_short_circuit = matches!(
                node.kind(),
                "member_call_expression" | "scoped_call_expression"
            )
            .then_some(chain_short_circuit.unwrap_or(next.point));
            self.schedule_expressions_with_first_chain_short_circuit(
                builder,
                entry,
                &evaluations,
                EdgeTarget::normal(invoke),
                scope,
                first_chain_short_circuit,
                stack,
            )
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn first_class_callable(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        chain_short_circuit: Option<ProgramPointId>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PhpLoweringError> {
        let boundary = self.point(builder, node, Vec::new())?;
        let result = self.value(builder, boundary, SemanticValueKind::Callable)?;
        let receiver = matches!(
            node.kind(),
            "member_call_expression" | "nullsafe_member_call_expression"
        )
        .then(|| self.value(builder, boundary, SemanticValueKind::Receiver))
        .transpose()?;
        let kind = match node.kind() {
            "member_call_expression" | "nullsafe_member_call_expression" => {
                CallableReferenceKind::BoundMethod
            }
            "scoped_call_expression" => CallableReferenceKind::StaticMethod,
            _ => CallableReferenceKind::Function,
        };
        let metadata = self.metadata(boundary)?;
        self.append_effect(
            builder,
            boundary,
            SemanticEffect::CallableReference {
                result,
                callable: CallableValue {
                    kind,
                    targets: CallableTargetResolution::Unknown,
                    target_evidence: metadata.evidence,
                    bound_receiver: receiver,
                    environment: None,
                },
            },
        )?;
        self.add_gap(
            builder,
            boundary,
            SemanticGapSubject::Value(result),
            SemanticCapability::CallableReferences,
            SemanticGapKind::Unknown,
            "first-class callable target requires location-first dispatch refinement",
        )?;
        self.edge(builder, boundary, next)?;
        if node.kind() == "nullsafe_member_call_expression" {
            let object = required_field(node, "object")?;
            let object_entry = self.point(builder, object, Vec::new())?;
            let decision = self.point(builder, node, Vec::new())?;
            let remaining = nullsafe_callable_reference_tail(node);
            let chain_destination = chain_short_circuit.unwrap_or(next.point);
            self.edge(
                builder,
                decision,
                EdgeTarget {
                    point: chain_destination,
                    kind: ControlEdgeKind::ConditionalFalse,
                },
            )?;
            self.schedule_nullable_tail(builder, decision, &remaining, boundary, scope, stack)?;
            self.edge(builder, entry, EdgeTarget::normal(object_entry))?;
            stack.push(Work::Expression {
                node: object,
                entry: object_entry,
                next: EdgeTarget::normal(decision),
                scope,
                chain_short_circuit: Some(chain_destination),
            });
            Ok(())
        } else {
            let evaluations = callable_reference_evaluations(node);
            let first_chain_short_circuit = matches!(
                node.kind(),
                "member_call_expression" | "scoped_call_expression"
            )
            .then_some(chain_short_circuit.unwrap_or(next.point));
            self.schedule_expressions_with_first_chain_short_circuit(
                builder,
                entry,
                &evaluations,
                EdgeTarget::normal(boundary),
                scope,
                first_chain_short_circuit,
                stack,
            )
        }
    }

    fn callable_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
    ) -> Result<(), PhpLoweringError> {
        let result = self.value(builder, entry, SemanticValueKind::Callable)?;
        let metadata = self.metadata(entry)?;
        self.append_effect(
            builder,
            entry,
            SemanticEffect::CallableCreation {
                result,
                callable: CallableValue {
                    kind: if node.kind() == "arrow_function" {
                        CallableReferenceKind::Lambda
                    } else {
                        CallableReferenceKind::Function
                    },
                    targets: CallableTargetResolution::Unknown,
                    target_evidence: metadata.evidence,
                    bound_receiver: None,
                    environment: None,
                },
            },
        )?;
        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Value(result),
            SemanticCapability::CallableReferences,
            SemanticGapKind::Unknown,
            "closure body target and capture environment require location-first refinement",
        )?;
        self.edge(builder, entry, next)
    }

    fn unhandled_control_syntax(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
    ) -> Result<(), PhpLoweringError> {
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

    fn add_magic_dispatch_gaps(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        operation: &str,
    ) -> Result<(), PhpLoweringError> {
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unknown,
            &format!("{operation} may invoke magic methods or runtime protocols"),
        )?;
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unknown,
            &format!("{operation} failures and implicit exceptions are not lowered"),
        )
    }

    fn note_unspecified_evaluation_order(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        node: Node<'tree>,
        evaluations: &[Node<'tree>],
    ) -> Result<(), PhpLoweringError> {
        if evaluations.len() < 2
            || !matches!(
                node.kind(),
                "binary_expression"
                    | "assignment_expression"
                    | "augmented_assignment_expression"
                    | "reference_assignment_expression"
            )
        {
            return Ok(());
        }
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::Point,
            SemanticCapability::NormalControlFlow,
            SemanticGapKind::Unknown,
            "PHP does not generally specify multi-operand evaluation order; the rendered sequence is a deterministic approximation",
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
    ) -> Result<(), PhpLoweringError> {
        if children.is_empty() {
            return self.edge(builder, entry, next);
        }
        let entries = children
            .iter()
            .map(|child| self.point(builder, *child, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        self.edge(builder, entry, EdgeTarget::normal(entries[0]))?;
        let dead_start = children
            .iter()
            .position(|child| statement_is_directly_abrupt(*child))
            .and_then(|index| (index + 1 < children.len()).then_some(index + 1));
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
            self.controls.insert(dead_scope, Box::default());
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

    fn schedule_expressions(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        children: &[Node<'tree>],
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PhpLoweringError> {
        self.schedule_expressions_with_first_chain_short_circuit(
            builder, entry, children, next, scope, None, stack,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn schedule_expressions_with_first_chain_short_circuit(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        children: &[Node<'tree>],
        next: EdgeTarget,
        scope: ScopeFrameId,
        first_chain_short_circuit: Option<ProgramPointId>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PhpLoweringError> {
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
                chain_short_circuit: (index == 0).then_some(first_chain_short_circuit).flatten(),
            });
        }
        Ok(())
    }

    fn schedule_expressions_from_first(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        first: ProgramPointId,
        children: &[Node<'tree>],
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PhpLoweringError> {
        if children.is_empty() {
            return self.edge(builder, first, next);
        }
        let mut entries = Vec::with_capacity(children.len());
        entries.push(first);
        for child in &children[1..] {
            entries.push(self.point(builder, *child, Vec::new())?);
        }
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
                chain_short_circuit: None,
            });
        }
        Ok(())
    }

    fn push_loop_scope(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        parent: ScopeFrameId,
        break_target: EdgeTarget,
        continue_target: ProgramPointId,
        continue_edge_kind: ControlEdgeKind,
    ) -> ScopeFrameId {
        let label = self.next_control_label();
        let scope = builder.push_scope(
            Some(parent),
            ScopeBinding::Loop {
                label: Some(label.clone()),
                break_target: break_target.point,
                break_edge_kind: break_target.kind,
                continue_target,
                continue_edge_kind,
            },
        );
        self.extend_controls(
            parent,
            scope,
            PhpControlFrame {
                label,
                kind: PhpControlKind::Loop,
            },
        );
        scope
    }

    fn push_switch_scope(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        parent: ScopeFrameId,
        break_target: EdgeTarget,
    ) -> ScopeFrameId {
        let label = self.next_control_label();
        let scope = builder.push_scope(
            Some(parent),
            ScopeBinding::Breakable {
                label: Some(label.clone()),
                accepts_unlabeled: true,
                break_target: break_target.point,
                break_edge_kind: break_target.kind,
            },
        );
        self.extend_controls(
            parent,
            scope,
            PhpControlFrame {
                label,
                kind: PhpControlKind::Switch,
            },
        );
        scope
    }

    fn next_control_label(&mut self) -> Box<str> {
        let label = format!("<php-control-{}>", self.next_control_label).into_boxed_str();
        self.next_control_label += 1;
        label
    }

    fn copy_controls(&mut self, parent: ScopeFrameId, child: ScopeFrameId) {
        let controls = self.controls.get(&parent).cloned().unwrap_or_default();
        self.controls.insert(child, controls);
    }

    fn extend_controls(
        &mut self,
        parent: ScopeFrameId,
        child: ScopeFrameId,
        frame: PhpControlFrame,
    ) {
        let mut controls = self
            .controls
            .get(&parent)
            .map(|controls| controls.to_vec())
            .unwrap_or_default();
        controls.push(frame);
        self.controls.insert(child, controls.into_boxed_slice());
    }

    fn abrupt(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        from: ProgramPointId,
        scope: ScopeFrameId,
        kind: CompletionKind,
        label: Option<&str>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), PhpLoweringError> {
        let Some(route) = builder.resolve_completion(scope, &CompletionRequest::new(kind, label))
        else {
            if matches!(kind, CompletionKind::Break | CompletionKind::Continue) {
                let detail = format!(
                    "{} completion has no matching represented target",
                    completion_label(kind)
                );
                return self.add_gap(
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
                );
            }
            return Err(PhpLoweringError::Invalid(format!(
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
    ) -> Result<(), PhpLoweringError> {
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
                .ok_or_else(|| PhpLoweringError::Invalid("missing cleanup region".into()))?;
            let metadata = self.mapping(builder, region.body)?;
            let (cleanup_entry, created) =
                builder.cleanup_specialization(route, index, metadata.source, metadata.evidence)?;
            if created {
                self.session.register_point(
                    cleanup_entry,
                    metadata,
                    "cleanup specialization broke dense point allocation",
                )?;
                let statement_next = if next.kind == ControlEdgeKind::Normal {
                    next
                } else {
                    let relay = self.point(builder, region.body, Vec::new())?;
                    self.edge(builder, relay, next)?;
                    EdgeTarget::normal(relay)
                };
                stack.push(Work::Statement {
                    node: region.body,
                    entry: cleanup_entry,
                    next: statement_next,
                    scope: region.outer_scope,
                });
            }
            next = EdgeTarget {
                point: cleanup_entry,
                kind: ControlEdgeKind::Cleanup,
            };
            first = Some(cleanup_entry);
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
    ) -> Result<(), PhpLoweringError> {
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
    ) -> Result<ProgramPointId, PhpLoweringError> {
        let metadata = self.mapping(builder, node)?;
        self.session.add_point(builder, metadata, effects)
    }

    fn mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<PointMetadata, PhpLoweringError> {
        let range = node.byte_range();
        let occurrence = self.session.next_source_occurrence(range.start, range.end);
        let anchor = source_anchor(node, occurrence).map_err(PhpLoweringError::Invalid)?;
        self.session
            .add_mapping(builder, anchor, SourceMappingKind::Exact)
    }

    fn value_mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<PointMetadata, PhpLoweringError> {
        let anchor = source_anchor(node, 0).map_err(PhpLoweringError::Invalid)?;
        self.session
            .add_mapping(builder, anchor, SourceMappingKind::Exact)
    }

    fn metadata(&self, point: ProgramPointId) -> Result<PointMetadata, PhpLoweringError> {
        self.session.metadata(point)
    }

    fn value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        kind: SemanticValueKind,
    ) -> Result<ValueId, PhpLoweringError> {
        self.session.add_value(builder, point, kind)
    }

    fn append_effect(
        &self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        effect: SemanticEffect,
    ) -> Result<(), PhpLoweringError> {
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
    ) -> Result<(), PhpLoweringError> {
        self.session
            .add_gap(builder, point, subject, capability, kind, detail)?;
        Ok(())
    }

    fn edge(
        &self,
        builder: &mut ProcedureCfgBuilder,
        source_point: ProgramPointId,
        target: EdgeTarget,
    ) -> Result<(), PhpLoweringError> {
        self.session
            .add_edge(builder, source_point, target.point, target.kind)
    }
}

fn php_short_circuit_operator(node: Node<'_>) -> Option<&'static str> {
    let operator = node.child_by_field_name("operator")?;
    match operator.kind() {
        "&&" => Some("&&"),
        "and" => Some("and"),
        "||" => Some("||"),
        "or" => Some("or"),
        "??" => Some("??"),
        _ => None,
    }
}

fn statement_is_directly_abrupt(node: Node<'_>) -> bool {
    match node.kind() {
        "return_statement" | "break_statement" | "continue_statement" | "goto_statement"
        | "exit_statement" => true,
        "expression_statement" => first_named_child(node).is_some_and(|expression| {
            matches!(expression.kind(), "throw_expression" | "exit_statement")
        }),
        _ => false,
    }
}

fn completion_label(kind: CompletionKind) -> &'static str {
    match kind {
        CompletionKind::Normal => "normal",
        CompletionKind::Return => "return",
        CompletionKind::Throw => "throw",
        CompletionKind::Break => "break",
        CompletionKind::Continue => "continue",
        CompletionKind::Yield => "yield",
    }
}

fn declaration_initializers(node: Node<'_>) -> Vec<Node<'_>> {
    let mut initializers = Vec::new();
    let mut stack = named_children(node);
    while let Some(current) = stack.pop() {
        if is_callable_kind(current.kind()) || current.kind() == "property_hook_list" {
            continue;
        }
        if current.kind() == "property_initializer" {
            initializers.extend(runtime_expression_children(current));
            continue;
        }
        if matches!(
            current.kind(),
            "assignment_expression"
                | "const_element"
                | "property_element"
                | "static_variable_declaration"
        ) && let Some(value) = current
            .child_by_field_name("value")
            .or_else(|| current.child_by_field_name("right"))
        {
            initializers.push(value);
            continue;
        }
        stack.extend(named_children(current));
    }
    initializers.sort_unstable_by_key(Node::start_byte);
    initializers
}

fn is_first_class_callable(node: Node<'_>) -> bool {
    call_arguments_node(node).is_some_and(|arguments| {
        let arguments = named_children(arguments);
        matches!(arguments.as_slice(), [argument] if argument.kind() == "variadic_placeholder")
    })
}

fn call_arguments(node: Node<'_>) -> Vec<Node<'_>> {
    call_arguments_node(node)
        .map(named_children)
        .unwrap_or_default()
        .into_iter()
        .filter(|argument| argument.kind() != "variadic_placeholder")
        .collect()
}

fn call_arguments_node(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("arguments").or_else(|| {
        named_children(node)
            .into_iter()
            .find(|child| child.kind() == "arguments")
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PhpCallArgumentShape {
    Positional,
    Named,
    ByReferenceOrSpread,
}

fn php_call_argument_value(argument: Node<'_>) -> Option<Node<'_>> {
    argument
        .child_by_field_name("value")
        .or_else(|| first_runtime_named_child(argument))
        .or_else(|| {
            (!matches!(
                argument.kind(),
                "argument" | "named_argument" | "variadic_unpacking"
            ))
            .then_some(argument)
        })
}

fn php_call_argument_shape(argument: Node<'_>) -> PhpCallArgumentShape {
    if argument.kind() == "named_argument" {
        PhpCallArgumentShape::Named
    } else if argument.kind() == "variadic_unpacking"
        || has_direct_token(argument, "&")
        || has_direct_named_child(argument, "reference_modifier")
    {
        PhpCallArgumentShape::ByReferenceOrSpread
    } else {
        PhpCallArgumentShape::Positional
    }
}

fn php_callable_anchor(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "function_call_expression" => node.child_by_field_name("function"),
        "member_call_expression" | "nullsafe_member_call_expression" | "scoped_call_expression" => {
            node.child_by_field_name("name")
        }
        "object_creation_expression" => php_object_creation_type(node),
        _ => None,
    }
}

fn php_object_creation_type(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("class").or_else(|| {
        named_children(node)
            .into_iter()
            .find(|child| matches!(child.kind(), "name" | "qualified_name" | "relative_scope"))
    })
}

fn call_operand_evaluations(node: Node<'_>) -> Vec<Node<'_>> {
    let mut evaluations = callable_reference_evaluations(node);
    evaluations.extend(call_arguments(node));
    evaluations
}

fn callable_reference_evaluations(node: Node<'_>) -> Vec<Node<'_>> {
    match node.kind() {
        "function_call_expression" => node.child_by_field_name("function").into_iter().collect(),
        "member_call_expression" | "nullsafe_member_call_expression" => {
            let mut values = Vec::new();
            if let Some(object) = node.child_by_field_name("object") {
                values.push(object);
            }
            if let Some(name) = node.child_by_field_name("name")
                && is_dynamic_name(name)
            {
                values.push(name);
            }
            values
        }
        "scoped_call_expression" => {
            let mut values = Vec::new();
            if let Some(scope) = node
                .child_by_field_name("scope")
                .filter(|scope| class_scope_requires_runtime_evaluation(*scope))
            {
                values.push(scope);
            }
            if let Some(name) = node.child_by_field_name("name")
                && is_dynamic_name(name)
            {
                values.push(name);
            }
            values
        }
        "object_creation_expression" => named_children(node)
            .into_iter()
            .filter(|child| {
                child.kind() != "arguments"
                    && child.kind() != "anonymous_class"
                    && !is_modifier_or_type_syntax(child.kind())
                    && class_scope_requires_runtime_evaluation(*child)
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn runtime_class_dispatch_scope(source: &str, node: Node<'_>) -> bool {
    let scope = match node.kind() {
        "scoped_call_expression" => node.child_by_field_name("scope"),
        "object_creation_expression" => node.child_by_field_name("class").or_else(|| {
            named_children(node).into_iter().find(|child| {
                child.kind() == "relative_scope"
                    || (!matches!(child.kind(), "arguments" | "anonymous_class")
                        && !is_modifier_or_type_syntax(child.kind()))
            })
        }),
        _ => None,
    };
    let Some(scope) = scope else {
        return false;
    };
    let text = node_text(source, scope);
    if text.is_some_and(|text| text.eq_ignore_ascii_case("static")) {
        return true;
    }
    match scope.kind() {
        "name" | "qualified_name" => false,
        "relative_scope" => false, // `self` and `parent`; `static` was handled above.
        _ => true,
    }
}

fn class_scope_requires_runtime_evaluation(scope: Node<'_>) -> bool {
    !matches!(scope.kind(), "name" | "qualified_name" | "relative_scope")
}

fn nullsafe_call_tail(node: Node<'_>) -> Vec<Node<'_>> {
    let mut values = Vec::new();
    if let Some(name) = node.child_by_field_name("name")
        && is_dynamic_name(name)
    {
        values.push(name);
    }
    values.extend(call_arguments(node));
    values
}

fn nullsafe_callable_reference_tail(node: Node<'_>) -> Vec<Node<'_>> {
    node.child_by_field_name("name")
        .filter(|name| is_dynamic_name(*name))
        .into_iter()
        .collect()
}

fn is_dynamic_name(node: Node<'_>) -> bool {
    node.kind() != "name"
}

fn runtime_expression_children(node: Node<'_>) -> Vec<Node<'_>> {
    named_children(node)
        .into_iter()
        .filter(|child| child_is_runtime(node, *child))
        .collect()
}

fn child_is_runtime(parent: Node<'_>, child: Node<'_>) -> bool {
    if is_comment_kind(child.kind())
        || is_modifier_or_type_syntax(child.kind())
        || child.kind() == "anonymous_class"
        || child.kind() == "property_hook_list"
    {
        return false;
    }
    for field in ["attributes", "parameters", "return_type", "type"] {
        if field_matches(parent, field, child) {
            return false;
        }
    }
    if field_matches(parent, "name", child) {
        return is_dynamic_name(child);
    }
    if field_matches(parent, "body", child) && is_callable_kind(parent.kind()) {
        return false;
    }
    true
}

fn is_modifier_or_type_syntax(kind: &str) -> bool {
    matches!(
        kind,
        "attribute_list"
            | "abstract_modifier"
            | "final_modifier"
            | "readonly_modifier"
            | "static_modifier"
            | "var_modifier"
            | "visibility_modifier"
            | "reference_modifier"
            | "by_ref"
            | "formal_parameters"
            | "simple_parameter"
            | "variadic_parameter"
            | "property_promotion_parameter"
            | "type"
            | "type_list"
            | "bottom_type"
            | "named_type"
            | "optional_type"
            | "union_type"
            | "intersection_type"
            | "primitive_type"
            | "relative_scope"
    )
}

fn is_callable_kind(kind: &str) -> bool {
    matches!(
        kind,
        "function_definition"
            | "method_declaration"
            | "anonymous_function"
            | "arrow_function"
            | "property_hook"
    )
}

fn is_statement_kind(kind: &str) -> bool {
    matches!(
        kind,
        "compound_statement"
            | "colon_block"
            | "expression_statement"
            | "return_statement"
            | "break_statement"
            | "continue_statement"
            | "if_statement"
            | "while_statement"
            | "do_statement"
            | "for_statement"
            | "foreach_statement"
            | "switch_statement"
            | "try_statement"
            | "goto_statement"
            | "named_label_statement"
            | "echo_statement"
            | "unset_statement"
            | "global_declaration"
            | "function_static_declaration"
            | "static_variable_declaration"
            | "declare_statement"
            | "const_declaration"
            | "property_declaration"
            | "function_definition"
            | "class_declaration"
            | "interface_declaration"
            | "trait_declaration"
            | "enum_declaration"
            | "namespace_definition"
            | "namespace_use_declaration"
            | "empty_statement"
            | "exit_statement"
    )
}

fn first_runtime_named_child(node: Node<'_>) -> Option<Node<'_>> {
    named_children(node)
        .into_iter()
        .find(|child| child_is_runtime(node, *child))
}

fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).next()
}

fn has_direct_named_child(node: Node<'_>, kind: &str) -> bool {
    named_children(node)
        .into_iter()
        .any(|child| child.kind() == kind)
}

fn has_direct_token(node: Node<'_>, kind: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor).any(|child| child.kind() == kind)
}

fn is_comment_kind(kind: &str) -> bool {
    matches!(kind, "comment" | "php_tag" | "text")
}

fn required_field<'tree>(node: Node<'tree>, field: &str) -> Result<Node<'tree>, PhpLoweringError> {
    node.child_by_field_name(field)
        .ok_or_else(|| missing_field(node, field))
}

fn missing_field(node: Node<'_>, field: &str) -> PhpLoweringError {
    PhpLoweringError::Invalid(format!(
        "{} node at bytes {}..{} is missing structured field {field}",
        node.kind(),
        node.start_byte(),
        node.end_byte()
    ))
}

fn php_variable_name<'source>(source: &'source str, node: Node<'_>) -> &'source str {
    node_text(source, node)
        .unwrap_or_default()
        .trim_start_matches('$')
}

fn normalize_php_name(name: &str) -> &str {
    name.trim_start_matches('$')
}

fn node_range(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row + 1,
        end_line: node.end_position().row + 1,
    }
}

fn expression_value_kind(node: Node<'_>) -> SemanticValueKind {
    match node.kind() {
        "anonymous_function" | "arrow_function" => SemanticValueKind::Callable,
        "integer" | "float" | "boolean" | "null" | "string" | "string_content"
        | "magic_constant" => SemanticValueKind::Constant,
        _ => SemanticValueKind::Temporary,
    }
}

fn is_runtime_leaf(kind: &str) -> bool {
    matches!(
        kind,
        "name"
            | "qualified_name"
            | "namespace_name"
            | "variable_name"
            | "integer"
            | "float"
            | "boolean"
            | "null"
            | "string"
            | "string_content"
            | "escape_sequence"
            | "magic_constant"
            | "variadic_placeholder"
            | "comment"
    )
}
