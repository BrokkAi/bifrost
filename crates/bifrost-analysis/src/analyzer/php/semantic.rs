//! PHP lowering into the language-neutral executable-semantics IR.
//!
//! This adapter reads tree-sitter structure directly. Graph construction,
//! abrupt-completion routing, cleanup specialization, and immutable adjacency
//! storage remain owned by the shared semantic substrate.

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
use crate::analyzer::{DispatchExtensibility, Language, PhpAnalyzer, ProjectFile};
use crate::hash::HashMap;

const ADAPTER_VERSION: &[u8] = b"php-value-semantics-v3";

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

        let classes = php_class_inventory(prepared);

        lower_procedure_batch(
            &specs,
            initial_work,
            budget,
            cancellation,
            |spec, staged_budget, cancellation| {
                lower_procedure(prepared, &classes, spec, staged_budget, cancellation)
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
        // `Partial` states the exact limit: every decision the condition
        // lowering reaches publishes a row, but only a constant `true` or
        // `false` -- through any number of `!` and parenthesis wrappers -- is
        // normalized, and everything else is recorded `Opaque`. Conditional
        // edges this adapter synthesizes outside condition lowering, such as
        // the `??` null gate, the `foreach` header's exhaustion test, and
        // `switch`/`match` arm dispatch, publish no guard row at all (#2443).
        SemanticCapability::GuardFacts,
        // Partial: a property write and read spelled `$o->name`, and an element
        // write and read spelled `$a[k]`, lower into real memory rows whenever
        // the target is a single such place (#2663). A dynamic property name,
        // a static property, a destructuring target, a reference assignment,
        // and a variable-variable still publish their own gaps instead, and a
        // non-constant element key publishes an index-memory gap on the
        // location it could not identify.
        SemanticCapability::FieldMemory,
        SemanticCapability::IndexMemory,
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

type ProcedureEnumeration<'tree> = ProcedureInventoryOutcome<Vec<ProcedureSpec<'tree>>>;

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
    let root = prepared.tree().root_node();
    let mut inventory =
        ProcedureInventoryBuilder::new(file, prepared.dialect(), root, "php-source", budget)?;
    let mut specs = Vec::new();
    let mut stack = vec![ProcedureEnumerationFrame {
        node: root,
        lexical_parent: None,
        declaration_path: inventory.root_path(),
    }];

    while let Some(frame) = stack.pop() {
        if cancellation.is_cancelled() {
            return Ok(inventory.cancelled());
        }
        if let Err(stop) = inventory.charge_traversal_entry() {
            return Ok(stop.into_outcome());
        }
        let child_path = frame.declaration_path;
        let mut container_body_scope = None;
        if let Some(segment_kind) = declaration_container_kind(frame.node) {
            let name = declaration_container_name(prepared.source(), frame.node);
            let anchor =
                source_anchor(frame.node, 0).map_err(SemanticProviderError::invalid_identity)?;
            let container_path = inventory.push_container(
                frame.declaration_path,
                segment_kind,
                name.as_deref(),
                anchor,
            )?;
            if let Some(body) = frame.node.child_by_field_name("body") {
                container_body_scope = Some((body.id(), container_path));
            }
        }

        let mut callable_body_scope = None;
        if let Some((kind, segment_kind, body, properties, returns_value)) =
            callable_shape(prepared.source(), frame.node, frame.lexical_parent)
        {
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
                callable: frame.node,
                body,
                locator: identity.locator,
                lexical_parent: frame.lexical_parent,
                kind,
                properties,
                returns_value,
            });
            callable_body_scope = Some((body.id(), identity.id, identity.declaration_path));
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

    Ok(inventory.complete(specs))
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
    let dispatch_extensibility = if matches!(
        kind,
        ProcedureKind::Function
            | ProcedureKind::LocalFunction
            | ProcedureKind::Closure
            | ProcedureKind::Lambda
    ) || has_direct_named_child(node, "final_modifier")
        || has_private_visibility(node, source)
        || enclosing_type_closes_dispatch(node)
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

fn enclosing_type_closes_dispatch(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        match parent.kind() {
            "class_declaration" => {
                return has_direct_named_child(parent, "final_modifier");
            }
            // PHP enums and anonymous classes cannot be subclassed, so their
            // methods and constructors have no overriding dispatch arm.
            "enum_declaration" | "anonymous_class" => return true,
            "interface_declaration" | "trait_declaration" => return false,
            _ => node = parent,
        }
    }
    false
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

type PhpLoweringError = ProcedureLoweringError;

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
    /// Every class-like declaration this file states, shared by every
    /// procedure lowered from it.
    classes: &'tree PhpClassInventory,
    /// The class this procedure is written in, which is what `$this` holds.
    enclosing_class: Option<Box<str>>,
    /// What each local name of this procedure holds.
    local_types: HashMap<Box<str>, PhpLocalType>,
    /// The memory-location identity of a property whose declaration this file
    /// does not state, interned once per name per procedure so a store and a
    /// load of the same name still meet.
    field_locators: HashMap<Box<str>, SemanticLocator>,
    /// One value per distinct constant element key, so `$a["k"]` written and
    /// `$a["k"]` read name the same index value.
    constant_index_values: HashMap<Box<str>, ValueId>,
}

#[derive(Debug, Clone, Copy)]
struct LocalBinding {
    declaration_start: usize,
    value: ValueId,
}

fn lower_procedure<'tree>(
    prepared: &'tree PreparedSyntaxTree,
    classes: &'tree PhpClassInventory,
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
    let enclosing_class = enclosing_class_name(prepared.source(), spec.callable);
    let local_types = php_local_types(
        prepared,
        classes,
        spec.callable,
        spec.body,
        enclosing_class.as_deref(),
    );
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
        classes,
        enclosing_class,
        local_types,
        field_locators: HashMap::default(),
        constant_index_values: HashMap::default(),
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

    drive_and_finish_procedure(
        builder,
        [body_work],
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
        properties: ProcedureProperties,
    ) -> Result<(), PhpLoweringError> {
        let layout =
            formal_parameter_slots_for_owner(Language::Php, callable, self.prepared.source())
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
                SemanticValueKind::Receiver { dispatch: true },
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
            // A `foreach` clause binds its targets exactly as an assignment
            // does, and the loop body reads them, so they are locals of this
            // procedure too.
            let bound = if node.kind() == "foreach_statement" {
                php_foreach_targets(node).0
            } else if node.kind() == "assignment_expression" {
                node.child_by_field_name("left")
                    .filter(|left| left.kind() == "variable_name")
                    .into_iter()
                    .collect()
            } else {
                Vec::new()
            };
            for left in bound {
                let name = php_variable_name(self.prepared.source(), left);
                if name.is_empty()
                    || name == "this"
                    || self.parameters.contains_key(name)
                    || self.locals.contains_key(name)
                {
                    continue;
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

        if let Some(place) = php_place(left) {
            let value = self.expression_value(builder, right, expression_value_kind(right))?;
            let evaluations = self.emit_memory_store(builder, terminal, &place, value, right)?;
            self.edge(builder, terminal, next)?;
            return self.schedule_expressions(
                builder,
                entry,
                &evaluations,
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
            php_declined_assignment_detail(left),
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
        // A folded literal keeps exactly one arm, so an `if (false)` body is
        // never reachable. Recording the guard is what keeps the fold legible:
        // after it, nothing else in the frozen artifact says the branch was
        // constant (#2443).
        if let Some(value) = php_folded_boolean_constant(self.prepared.source(), node) {
            let taken = if value { when_true } else { when_false };
            self.edge(builder, entry, taken)?;
            return self.record_guard(
                builder,
                entry,
                GuardPredicate::ConstantBoolean { value },
                None,
                value.then_some(when_true),
                (!value).then_some(when_false),
            );
        }
        // A negated guard is the same guard with its outcome swapped rather
        // than a decision of its own, so `!` is peeled instead of minting a
        // decision point that tests the negation's own value.
        if let Some(operand) = php_logical_not_operand(node) {
            stack.push(Work::Condition {
                node: operand,
                entry,
                when_true: when_false,
                when_false: when_true,
                scope,
            });
            return Ok(());
        }
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
                // The condition's own value is the one thing an opaque guard
                // can honestly name: the decision tested it, whatever it means.
                let subject = self.expression_value(builder, node, expression_value_kind(node))?;
                self.record_guard(
                    builder,
                    decision,
                    GuardPredicate::Opaque {
                        digest: GuardConditionDigest::from_syntax_kind(node.kind()),
                    },
                    Some(subject),
                    Some(when_true),
                    Some(when_false),
                )?;
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

    /// Publish one guard fact for a decision this lowerer just made.
    ///
    /// Only a constant boolean is normalized today. Everything else this
    /// lowerer decides is recorded `Opaque` rather than guessed, so an absent
    /// guard row means the condition lowering made no decision at that point
    /// at all -- which is what makes the [`SemanticCapability::GuardFacts`]
    /// entry readable. Arms must already have been added as edges; the IR
    /// validator enforces that.
    #[allow(clippy::too_many_arguments)]
    fn record_guard(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        predicate: GuardPredicate,
        subject: Option<ValueId>,
        when_true: Option<EdgeTarget>,
        when_false: Option<EdgeTarget>,
    ) -> Result<(), PhpLoweringError> {
        let arm = |target: Option<EdgeTarget>| {
            target.map(|target| GuardArm {
                target_point: target.point,
                kind: target.kind,
            })
        };
        self.session.add_guard_fact(
            builder,
            point,
            predicate,
            subject,
            arm(when_true),
            arm(when_false),
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
        self.emit_foreach_binding(builder, node, binding, iterable)?;
        let body_entry = self.point(builder, body.unwrap_or(node), Vec::new())?;
        let loop_scope =
            self.push_loop_scope(builder, scope, next, test, ControlEdgeKind::LoopBack);
        // A native PHP array is traversed by the language itself: acquiring
        // and advancing the foreach cursor invokes no user-defined iterator
        // methods. The simple targets accepted by `php_foreach_targets` also
        // need no destructuring or by-reference assignment protocol. Their
        // value flow was emitted above, so this exact structured shape has no
        // omitted call or exceptional transfer. Objects, references, and
        // destructuring retain the gaps because their runtime protocols can
        // execute user code or fail.
        let (_, unlowered_target) = php_foreach_targets(node);
        let locally_bound_array = iterable.kind() == "variable_name" && {
            let name = php_variable_name(self.prepared.source(), iterable);
            self.locals
                .get(name)
                .is_some_and(|binding| binding.declaration_start < iterable.start_byte())
                && self.local_type_of(iterable) == Some(PhpLocalType::Array)
        };
        let native_array_iteration = !unlowered_target
            && (iterable.kind() == "array_creation_expression" || locally_bound_array);
        if !native_array_iteration {
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
        // A write target is not a read: a declined store still schedules its
        // own operands, and the target itself must mint no load of the
        // location that statement overwrites.
        match php_place(node).filter(|_| !is_php_assignment_target(node)) {
            Some(place) => self.emit_memory_load(builder, boundary, &place, node)?,
            None => {
                let detail = match node.kind() {
                    "subscript_expression" => "array access and ArrayAccess protocol dispatch",
                    "class_constant_access_expression" => {
                        "class constant resolution, autoload, and access checks"
                    }
                    "scoped_property_access_expression" => {
                        "static property resolution, autoload, and access checks"
                    }
                    _ => "computed property access and magic property dispatch",
                };
                self.add_magic_dispatch_gaps(builder, boundary, detail)?;
            }
        }
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
        let arms = named_children_without_comments(body);
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
                    for predicate in named_children_without_comments(conditions) {
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
        // A class this file states in full, with no supertype, no interface,
        // no trait use, and no `__destruct`, runs no user code when its
        // instance is released. There is then no destructor timing to lower
        // and nothing for the gap to refine, so publishing one would hold
        // every allocation's snapshot open on a question the source answers.
        if node.kind() == "object_creation_expression" && !self.creation_lifetime_is_closed(node) {
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
        .then(|| {
            self.value(
                builder,
                boundary,
                SemanticValueKind::Receiver { dispatch: true },
            )
        })
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

    /// What one local name or expression holds at this occurrence.
    fn local_type_of(&self, node: Node<'tree>) -> Option<PhpLocalType> {
        php_expression_local_type(
            self.prepared.source(),
            self.classes,
            &self.local_types,
            self.enclosing_class.as_deref(),
            node,
            0,
        )
    }

    /// Whether releasing what this creation expression allocates runs no user
    /// code, so its lifetime holds nothing left to model.
    fn creation_lifetime_is_closed(&self, node: Node<'tree>) -> bool {
        let Some(PhpLocalType::Class(class)) = php_expression_local_type(
            self.prepared.source(),
            self.classes,
            &self.local_types,
            self.enclosing_class.as_deref(),
            node,
            0,
        ) else {
            return false;
        };
        self.classes
            .get(&class)
            .is_some_and(|facts| facts.lifetime_is_closed)
    }

    /// Whether an access to this place can run no user code.
    ///
    /// PHP reaches for `__get`/`__set` only when the property is not an
    /// accessible declared one, and reaches for the `ArrayAccess` protocol
    /// only when the base is an object. A declared property of a class this
    /// file states in full, and an element of a value this procedure proved to
    /// be a PHP array, are therefore settled by the syntax alone.
    fn access_is_closed(&self, place: &PhpPlace<'tree>) -> bool {
        match place {
            PhpPlace::Field { object, name } => {
                let Some(PhpLocalType::Class(class)) = self.local_type_of(*object) else {
                    return false;
                };
                let Some(property) = nonempty_node_text(self.prepared.source(), *name) else {
                    return false;
                };
                self.classes.get(&class).is_some_and(|facts| {
                    facts.access_is_closed && facts.properties.contains_key(property)
                })
            }
            PhpPlace::Element { object, .. } => {
                object.kind() == "array_creation_expression"
                    || self.local_type_of(*object) == Some(PhpLocalType::Array)
            }
        }
    }

    /// The memory-location identity of `$object->name`, and whether it is the
    /// property's own declaration.
    ///
    /// A property is looked up by name at run time, so every occurrence of one
    /// name on one object names the same location whatever the static type
    /// says. The declaration is still the identity that lets two procedures of
    /// a file agree; when this file does not state it -- an unresolved object
    /// class, an imported class, a name two classes share -- the locator falls
    /// back to one interned per property name per procedure, and the caller
    /// publishes a field-identity gap for it.
    fn memory_member_locator(
        &mut self,
        object: Node<'tree>,
        name: Node<'tree>,
    ) -> Result<(SemanticLocator, bool), PhpLoweringError> {
        let property = nonempty_node_text(self.prepared.source(), name);
        let declaration_anchor = property.and_then(|property| {
            let PhpLocalType::Class(class) = self.local_type_of(object)? else {
                return None;
            };
            self.classes
                .get(&class)?
                .properties
                .get(property)
                .copied()
                .flatten()
        });
        if let Some(property) = property
            && declaration_anchor.is_none()
            && let Some(locator) = self.field_locators.get(property)
        {
            return Ok((locator.clone(), false));
        }
        let resolved = declaration_anchor.is_some();
        let anchor = match declaration_anchor {
            Some(anchor) => anchor,
            None => source_anchor(name, 0).map_err(PhpLoweringError::Invalid)?,
        };
        let procedure = self.session.locator();
        let locator = SemanticLocator::new(
            procedure.mount(),
            procedure.path().clone(),
            procedure.language(),
            procedure.declaration().clone(),
            SemanticRole::MemoryLocation,
            anchor,
        );
        if !resolved && let Some(property) = property {
            self.field_locators.insert(property.into(), locator.clone());
        }
        Ok((locator, resolved))
    }

    /// The key value of `$array[key]`, when the key is a constant.
    ///
    /// A store and a load meet on an exact element only when both name the
    /// same value, so one value is interned per distinct key text. A computed
    /// key has no proven identity here and yields `None`, which the caller
    /// turns into an any-element location plus an index-memory gap.
    fn index_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<Option<ValueId>, PhpLoweringError> {
        let Some(key) = php_constant_key(self.prepared.source(), node) else {
            return Ok(None);
        };
        if let Some(value) = self.constant_index_values.get(&key) {
            let value = *value;
            self.expression_values.insert(node.id(), value);
            return Ok(Some(value));
        }
        let value = self.expression_value(builder, node, SemanticValueKind::Constant)?;
        self.constant_index_values.insert(key, value);
        Ok(Some(value))
    }

    fn add_field_identity_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        location: MemoryLocationId,
    ) -> Result<(), PhpLoweringError> {
        self.session.add_gap_with_impacts(
            builder,
            point,
            SemanticGapSubject::MemoryLocation(location),
            SemanticCapability::FieldMemory,
            SemanticGapImpacts::single(SemanticGapImpact::HeapRead)
                .with(SemanticGapImpact::HeapWrite)
                .with(SemanticGapImpact::Aliasing),
            SemanticGapKind::Unknown,
            "PHP property occurrence is structured, but the class that declares it is not resolved",
        )?;
        Ok(())
    }

    fn add_dynamic_index_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        location: MemoryLocationId,
        detail: &str,
    ) -> Result<(), PhpLoweringError> {
        self.session.add_gap_with_impacts(
            builder,
            point,
            SemanticGapSubject::MemoryLocation(location),
            SemanticCapability::IndexMemory,
            SemanticGapImpacts::single(SemanticGapImpact::HeapRead)
                .with(SemanticGapImpact::HeapWrite)
                .with(SemanticGapImpact::Aliasing),
            SemanticGapKind::Unsupported,
            detail,
        )?;
        Ok(())
    }

    /// The memory location a place names, plus its own identity gaps.
    fn memory_location(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        place: &PhpPlace<'tree>,
    ) -> Result<(MemoryLocationId, MemoryAccessKind), PhpLoweringError> {
        match place {
            PhpPlace::Field { object, name } => {
                let base =
                    self.expression_value(builder, *object, expression_value_kind(*object))?;
                let (member, resolved) = self.memory_member_locator(*object, *name)?;
                let location = self.session.add_memory_location(
                    builder,
                    point,
                    MemoryLocationKind::Field { base, member },
                )?;
                if !resolved {
                    self.add_field_identity_gap(builder, point, location)?;
                }
                Ok((location, MemoryAccessKind::Field))
            }
            PhpPlace::Element { object, key } => {
                let base =
                    self.expression_value(builder, *object, expression_value_kind(*object))?;
                let index = match key {
                    Some(key) => self.index_value(builder, *key)?,
                    None => None,
                };
                let location = self.session.add_memory_location(
                    builder,
                    point,
                    MemoryLocationKind::Index {
                        base,
                        index,
                        constant_index: None,
                        identity: crate::analyzer::semantic::IndexedLocationIdentity::Element,
                    },
                )?;
                if index.is_none() {
                    self.add_dynamic_index_gap(
                        builder,
                        point,
                        location,
                        if key.is_some() {
                            "PHP computed element key identity is not proven"
                        } else {
                            "PHP append writes an element whose key the source does not state"
                        },
                    )?;
                }
                Ok((location, MemoryAccessKind::Index))
            }
        }
    }

    /// The runtime protocols an access to this place may still reach.
    ///
    /// A settled access publishes only the implicit-abort claim, `Unsupported`
    /// on a `Point` subject, which is the shape the shared discharge closes
    /// when no handler or cleanup body runs user code (#1952). An unsettled
    /// one keeps the magic-dispatch pair it published before.
    fn emit_access_dispatch_gaps(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        place: &PhpPlace<'tree>,
    ) -> Result<(), PhpLoweringError> {
        if !self.access_is_closed(place) {
            return self.add_magic_dispatch_gaps(builder, point, php_place_detail(place));
        }
        if matches!(place, PhpPlace::Element { .. }) {
            // A missing element of a PHP array is a warning and a null read,
            // not an abort, and an array is not an object, so nothing else
            // remains.
            return Ok(());
        }
        self.add_gap(
            builder,
            point,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            "PHP property access may abort on a null base",
        )
    }

    /// Lower `place = value` into a real store, and answer what the statement
    /// still evaluates. The target node itself is deliberately absent: reading
    /// it would publish a load of the very location the statement writes.
    fn emit_memory_store(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        place: &PhpPlace<'tree>,
        value: ValueId,
        right: Node<'tree>,
    ) -> Result<Vec<Node<'tree>>, PhpLoweringError> {
        let (location, kind) = self.memory_location(builder, point, place)?;
        self.emit_access_dispatch_gaps(builder, point, place)?;
        self.append_effect(
            builder,
            point,
            SemanticEffect::MemoryStore {
                kind,
                location,
                value,
            },
        )?;
        let mut evaluations = match place {
            PhpPlace::Field { object, .. } => vec![*object],
            PhpPlace::Element { object, key } => {
                let mut evaluations = vec![*object];
                evaluations.extend(*key);
                evaluations
            }
        };
        evaluations.push(right);
        Ok(evaluations)
    }

    /// Lower a read of `place` into a real load whose result is the access
    /// expression's own value.
    fn emit_memory_load(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        place: &PhpPlace<'tree>,
        node: Node<'tree>,
    ) -> Result<(), PhpLoweringError> {
        let result = self.expression_value(builder, node, expression_value_kind(node))?;
        let (location, kind) = self.memory_location(builder, point, place)?;
        self.emit_access_dispatch_gaps(builder, point, place)?;
        self.append_effect(
            builder,
            point,
            SemanticEffect::MemoryLoad {
                kind,
                location,
                result,
            },
        )
    }

    /// Lower what one `foreach` iteration binds.
    ///
    /// An iteration reads an element of the collection, so the loop variable
    /// is loaded from the collection's any-element cell. That wildcard is not
    /// an approximation here the way an unpinned subscript is one: the loop
    /// visits every element, so the cell it reads is exactly all of them, and
    /// the load publishes no index-identity gap. The key side is loaded from
    /// the same cell, which over-approximates -- a key carries at most what
    /// the collection carries -- and never removes a path.
    fn emit_foreach_binding(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        point: ProgramPointId,
        iterable: Node<'tree>,
    ) -> Result<(), PhpLoweringError> {
        let (targets, unlowered) = php_foreach_targets(node);
        if unlowered {
            self.add_gap(
                builder,
                point,
                SemanticGapSubject::Point,
                SemanticCapability::Assignments,
                SemanticGapKind::Unsupported,
                "PHP foreach by-reference and destructuring targets are not lowered",
            )?;
        }
        let slots = targets
            .into_iter()
            .filter_map(|target| {
                let name = php_variable_name(self.prepared.source(), target);
                self.local_declaration_value(name, target.start_byte())
                    .or_else(|| self.binding_value(name).map(|(value, _)| value))
            })
            .collect::<Vec<_>>();
        if slots.is_empty() {
            return Ok(());
        }
        let base = self.expression_value(builder, iterable, expression_value_kind(iterable))?;
        let location = self.session.add_memory_location(
            builder,
            point,
            MemoryLocationKind::Index {
                base,
                index: None,
                constant_index: None,
                identity: crate::analyzer::semantic::IndexedLocationIdentity::Aggregate,
            },
        )?;
        for result in slots {
            self.append_effect(
                builder,
                point,
                SemanticEffect::MemoryLoad {
                    kind: MemoryAccessKind::Index,
                    location,
                    result,
                },
            )?;
        }
        Ok(())
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
        let mut plan = CleanupRoutePlanner::new(route);
        while let Some(step) = plan.next(
            builder,
            &mut self.session,
            &self.cleanups,
            |region| region.id,
            |region| region.body,
        )? {
            let statement_next = if step.next.kind == ControlEdgeKind::Normal {
                step.next
            } else {
                let relay = self.point(builder, step.region.body, Vec::new())?;
                self.edge(builder, relay, step.next)?;
                EdgeTarget::normal(relay)
            };
            stack.push(Work::Statement {
                node: step.region.body,
                entry: step.entry,
                next: statement_next,
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
    ) -> Result<(), PhpLoweringError> {
        self.session.add_callable_resolution_gaps(
            builder,
            point,
            callee,
            call_site,
            resolution,
            "callable target requires whole-program dispatch refinement",
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
        self.session.add_node_mapping(builder, node)
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

/// The operand of a logical negation, or `None` when the node is any other
/// unary operator.
fn php_logical_not_operand(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "unary_op_expression" {
        return None;
    }
    let operator = node.child_by_field_name("operator")?;
    (operator.kind() == "!")
        .then(|| node.child_by_field_name("argument"))
        .flatten()
}

/// The value a PHP boolean literal names.
///
/// PHP spells both constants case-insensitively, so `FALSE` and `False` are
/// the same literal as `false`; the grammar folds every spelling into one
/// `boolean` node whose token text is the only thing that distinguishes them.
fn php_boolean_literal_value(source: &str, node: Node<'_>) -> Option<bool> {
    if node.kind() != "boolean" {
        return None;
    }
    let text = node_text(source, node)?;
    if text.eq_ignore_ascii_case("true") {
        Some(true)
    } else if text.eq_ignore_ascii_case("false") {
        Some(false)
    } else {
        None
    }
}

/// The constant value of a condition, when its parenthesis and `!` wrappers
/// bottom out in a boolean literal.
///
/// The wrappers are peeled through tree-sitter structure -- a named child for
/// the parentheses, the `operator` and `argument` fields for the negation --
/// so a shape this does not recognize stays a real decision rather than a
/// guessed constant.
fn php_folded_boolean_constant(source: &str, node: Node<'_>) -> Option<bool> {
    let mut cursor = node;
    let mut negated = false;
    loop {
        match cursor.kind() {
            "parenthesized_expression" => cursor = first_runtime_named_child(cursor)?,
            "unary_op_expression" => {
                cursor = php_logical_not_operand(cursor)?;
                negated = !negated;
            }
            _ => break,
        }
    }
    php_boolean_literal_value(source, cursor).map(|value| value != negated)
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

/// The named children that are program text rather than commentary.
///
/// A `comment` is a tree-sitter extra, so the grammar admits one between any
/// two children of any node and makes it a *named* child there. Every other
/// child walk in this file already screens its children by kind -- statements
/// through [`is_statement_kind`], switch bodies through their two case kinds,
/// expression operands through [`child_is_runtime`] -- so only a walk over a
/// list the grammar states exhaustively needs this. A match body is such a
/// list: reading a comment in one as an arm asked it for a `return_expression`
/// it cannot have, and the resulting lowering failure cost the whole file its
/// semantics.
fn named_children_without_comments(node: Node<'_>) -> Vec<Node<'_>> {
    named_children(node)
        .into_iter()
        .filter(|child| !is_comment_kind(child.kind()))
        .collect()
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

/// What one class-like declaration in this file states about its own members.
///
/// PHP resolves `$o->name` by the property's name at run time, so a memory
/// location is identified by the object plus that name. The declaration is
/// still what gives the name a stable identity across the procedures of a
/// file, which is why the anchor is recorded here rather than at each
/// occurrence.
#[derive(Debug, Default)]
struct PhpClassFacts {
    /// Where each property this class declares is written down. A name the
    /// class states more than once collapses to `None`: the occurrence alone
    /// no longer picks a declaration.
    properties: HashMap<Box<str>, Option<SourceAnchor>>,
    /// The class each typed property holds, so a nested access path can name
    /// the next class in the chain.
    property_classes: HashMap<Box<str>, Box<str>>,
    /// Whether an access to a declared property of this class is settled by
    /// the declaration alone. A magic accessor, a trait use, a supertype, or
    /// an implemented interface can all introduce behaviour this file does not
    /// state, so any of them reopens the question.
    access_is_closed: bool,
    /// Whether this class's own body runs nothing when an instance is
    /// released: this file states the class in full, it uses no trait, and it
    /// declares no `__destruct`. This is only the class's own contribution --
    /// what its properties hold is settled separately.
    owns_no_release_code: bool,
    /// Whether some declared property may hold an object this file cannot
    /// follow. An untyped property, a namespace-qualified or otherwise
    /// unresolved type, a nullable object, a union, an intersection, an
    /// array, `object`, `mixed`, `iterable`, `callable`, `self`, and
    /// `static` all qualify: any of them can hold something whose release
    /// runs a destructor this file never sees.
    holds_unfollowable: bool,
    /// The in-file classes this class's properties hold. Releasing an
    /// instance releases them too, so each must itself be release-closed.
    released_classes: Vec<Box<str>>,
    /// Whether releasing an instance of this class runs no user code at all.
    /// Settled by [`php_resolve_lifetime_closure`] once every class in the
    /// file is known, because the answer depends on what the properties hold.
    lifetime_is_closed: bool,
}

type PhpClassInventory = HashMap<Box<str>, PhpClassFacts>;

/// Whether this method name is one of PHP's property-access magic hooks.
fn php_property_magic_method(name: &str) -> bool {
    matches!(
        name,
        "__get" | "__set" | "__isset" | "__unset" | "__call" | "__callStatic"
    )
}

/// The class an occurrence names, when the occurrence names one this file can
/// be sure of.
///
/// Only a bare `name` answers. A `qualified_name` states a namespace path, and
/// this intrafile lowering resolves no `namespace` statement and no `use`
/// import, so it can prove neither that `\Vendor\Holder` is the `class Holder`
/// declared here nor that it is not. Binding the local class's facts to it
/// would hand a foreign class the local declaration's property anchors and,
/// worse, its "declares no `__get`" claim -- suppressing a magic-dispatch gap
/// for a class that may well declare one. An unresolved name keeps those gaps,
/// which is the answer that cannot be wrong.
fn php_unqualified_class_name<'source>(
    source: &'source str,
    node: Node<'_>,
) -> Option<&'source str> {
    if node.kind() != "name" {
        return None;
    }
    nonempty_node_text(source, node)
}

/// The class a `type` node names, when it names exactly one class this file
/// can be sure of.
///
/// A union, an intersection, a primitive, and a namespace-qualified name all
/// name no single in-file class, so the property they declare carries no chain
/// identity.
fn php_declared_class(source: &str, type_node: Node<'_>) -> Option<Box<str>> {
    let mut current = type_node;
    loop {
        match current.kind() {
            "type" | "optional_type" | "named_type" => {
                current = first_named_child(current)?;
            }
            // A `catch` states its caught types as a list. One entry names one
            // class; several name a choice this pass does not resolve.
            "type_list" => {
                let entries = named_children(current);
                if entries.len() != 1 {
                    return None;
                }
                current = entries[0];
            }
            _ => return php_unqualified_class_name(source, current).map(Box::<str>::from),
        }
    }
}

/// Every class-like declaration this file states, keyed by its own name.
///
/// A name two declarations share is poisoned rather than resolved: neither
/// declaration can then claim an occurrence, and the accesses fall back to the
/// procedure-local interned locator with a published field-identity gap.
fn php_class_inventory(prepared: &PreparedSyntaxTree) -> PhpClassInventory {
    let source = prepared.source();
    let mut inventory: PhpClassInventory = HashMap::default();
    let mut stack = vec![prepared.tree().root_node()];
    while let Some(node) = stack.pop() {
        stack.extend(named_children(node));
        if !matches!(
            node.kind(),
            "class_declaration" | "trait_declaration" | "enum_declaration"
        ) {
            continue;
        }
        let Some(name) = node
            .child_by_field_name("name")
            .and_then(|name| nonempty_node_text(source, name))
        else {
            continue;
        };
        let facts = php_class_facts(source, node);
        match inventory.entry(name.into()) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(facts);
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                entry.insert(PhpClassFacts::default());
            }
        }
    }
    php_resolve_lifetime_closure(&mut inventory);
    inventory
}

/// Settle, for every class in the file at once, whether releasing an instance
/// of it runs user code.
///
/// A class is release-closed when its own body runs nothing on release and
/// every object its properties hold is itself release-closed. That is a
/// property of the whole file, not of one declaration: `class Plain { public
/// Closing $c; }` runs `Closing::__destruct` when a `Plain` goes away, even
/// though `Plain` states no destructor of its own.
///
/// The answer is the greatest fixpoint. Every class whose own body is clean
/// and whose property types this file can follow starts closed, and a class is
/// then falsified whenever something it holds is not closed -- including a
/// class this file does not declare, which is absent from the inventory and so
/// never closed. Starting optimistic is what makes a cycle come out right:
/// `A { public B $b; }` and `B { public A $a; }` with no destructor anywhere
/// really does run nothing on release. Each pass falsifies at least one class
/// or stops, so the loop is bounded by the number of classes and needs no
/// recursion or visited set.
fn php_resolve_lifetime_closure(inventory: &mut PhpClassInventory) {
    let mut closed = inventory
        .iter()
        .map(|(name, facts)| {
            (
                name.clone(),
                facts.owns_no_release_code && !facts.holds_unfollowable,
            )
        })
        .collect::<HashMap<Box<str>, bool>>();
    loop {
        let mut falsified = Vec::new();
        for (name, facts) in inventory.iter() {
            if closed.get(name) != Some(&true) {
                continue;
            }
            if facts
                .released_classes
                .iter()
                .any(|held| closed.get(held) != Some(&true))
            {
                falsified.push(name.clone());
            }
        }
        if falsified.is_empty() {
            break;
        }
        for name in falsified {
            closed.insert(name, false);
        }
    }
    for (name, facts) in inventory.iter_mut() {
        facts.lifetime_is_closed = closed.get(name) == Some(&true);
    }
}

/// What a declared property may hold, as far as its written type states.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PhpPropertyRelease {
    /// Every value of this type is a scalar, so releasing it runs nothing.
    NoObject,
    /// Exactly this in-file class, whose own release closure decides.
    Class(Box<str>),
    /// This file cannot follow what the property holds.
    Unfollowable,
}

/// The scalar type names whose values are never objects.
///
/// The list is deliberately a whitelist. `array`, `object`, `mixed`,
/// `iterable`, `callable`, `self`, `static`, and `parent` are all spelled the
/// same way in this position and can every one of them hold an object, so
/// anything absent here is unfollowable rather than assumed harmless.
fn php_scalar_type_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "int" | "float" | "string" | "bool" | "true" | "false" | "null" | "void" | "never"
    )
}

/// What the `type` node of a property declaration states it may hold.
///
/// An absent type node is unfollowable, and so is a nullable object, a union,
/// and an intersection: this pass settles a whole-file question and answers it
/// conservatively rather than reasoning about arms.
fn php_property_release(source: &str, type_node: Option<Node<'_>>) -> PhpPropertyRelease {
    let Some(mut current) = type_node else {
        return PhpPropertyRelease::Unfollowable;
    };
    loop {
        match current.kind() {
            "type" | "named_type" => {
                let Some(inner) = first_named_child(current) else {
                    return PhpPropertyRelease::Unfollowable;
                };
                current = inner;
            }
            "primitive_type" | "bottom_type" => {
                return match nonempty_node_text(source, current) {
                    Some(name) if php_scalar_type_name(name) => PhpPropertyRelease::NoObject,
                    _ => PhpPropertyRelease::Unfollowable,
                };
            }
            "name" => {
                return match nonempty_node_text(source, current) {
                    Some(name) if php_scalar_type_name(name) => PhpPropertyRelease::NoObject,
                    Some(name) => PhpPropertyRelease::Class(name.into()),
                    None => PhpPropertyRelease::Unfollowable,
                };
            }
            _ => return PhpPropertyRelease::Unfollowable,
        }
    }
}

fn php_class_facts(source: &str, node: Node<'_>) -> PhpClassFacts {
    let fully_stated = !named_children(node)
        .into_iter()
        .any(|child| matches!(child.kind(), "base_clause" | "class_interface_clause"));
    let mut facts = PhpClassFacts {
        access_is_closed: fully_stated,
        owns_no_release_code: fully_stated,
        ..PhpClassFacts::default()
    };
    let Some(body) = node.child_by_field_name("body") else {
        // A class whose body this adapter cannot read states nothing it can
        // rely on, including about what its properties hold.
        facts.holds_unfollowable = true;
        return facts;
    };
    for member in named_children(body) {
        match member.kind() {
            "use_declaration" => {
                // A used trait can state properties, magic accessors, and a
                // destructor this class body does not.
                facts.access_is_closed = false;
                facts.owns_no_release_code = false;
            }
            "property_declaration" => {
                let type_node = member.child_by_field_name("type");
                for element in named_children(member) {
                    if element.kind() != "property_element" {
                        continue;
                    }
                    let Some(name) = element.child_by_field_name("name") else {
                        continue;
                    };
                    php_record_property(source, &mut facts, name, type_node);
                }
            }
            "method_declaration" => {
                let method = member
                    .child_by_field_name("name")
                    .and_then(|name| nonempty_node_text(source, name));
                if method.is_some_and(php_property_magic_method) {
                    facts.access_is_closed = false;
                }
                if method == Some("__destruct") {
                    facts.owns_no_release_code = false;
                }
                // Constructor property promotion declares properties in the
                // parameter list rather than in the class body.
                for parameter in member
                    .child_by_field_name("parameters")
                    .map(named_children)
                    .unwrap_or_default()
                {
                    if parameter.kind() != "property_promotion_parameter" {
                        continue;
                    }
                    let Some(name) = parameter.child_by_field_name("name") else {
                        continue;
                    };
                    php_record_property(
                        source,
                        &mut facts,
                        name,
                        parameter.child_by_field_name("type"),
                    );
                }
            }
            _ => {}
        }
    }
    facts
}

fn php_record_property(
    source: &str,
    facts: &mut PhpClassFacts,
    name: Node<'_>,
    type_node: Option<Node<'_>>,
) {
    let property = php_variable_name(source, name);
    if property.is_empty() {
        return;
    }
    let anchor = source_anchor(name, 0).ok();
    match facts.properties.entry(property.into()) {
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(anchor);
        }
        std::collections::hash_map::Entry::Occupied(mut entry) => {
            entry.insert(None);
        }
    }
    if let Some(declared) = type_node.and_then(|type_node| php_declared_class(source, type_node)) {
        facts.property_classes.insert(property.into(), declared);
    }
    match php_property_release(source, type_node) {
        PhpPropertyRelease::NoObject => {}
        PhpPropertyRelease::Class(held) => facts.released_classes.push(held),
        PhpPropertyRelease::Unfollowable => facts.holds_unfollowable = true,
    }
}

/// The memory place an expression names, when this adapter lowers it.
#[derive(Debug, Clone, Copy)]
enum PhpPlace<'tree> {
    /// `$object->name`, whose property name the source writes down.
    Field {
        object: Node<'tree>,
        name: Node<'tree>,
    },
    /// `$array[key]`, or the append form `$array[]` whose key the source does
    /// not state.
    Element {
        object: Node<'tree>,
        key: Option<Node<'tree>>,
    },
}

/// Why one assignment target is still declined, said in that target's own
/// terms rather than as one list of every shape this adapter does not lower.
fn php_declined_assignment_detail(left: Node<'_>) -> &'static str {
    match left.kind() {
        "member_access_expression" | "nullsafe_member_access_expression" => {
            "PHP assignment to a computed property name is not lowered: the name is a value, so the occurrence identifies no member"
        }
        "scoped_property_access_expression" => {
            "PHP static property assignment is not lowered: the scope expression names no resolved class here"
        }
        "list_literal" | "array_creation_expression" => {
            "PHP list and array destructuring assignment is not lowered"
        }
        "dynamic_variable_name" => {
            "PHP variable-variable assignment is not lowered: the target name is a value, not a binding this procedure states"
        }
        "function_call_expression"
        | "member_call_expression"
        | "nullsafe_member_call_expression"
        | "scoped_call_expression" => {
            "PHP assignment through a call result requires a resolved reference return"
        }
        _ => "PHP assignment to this target shape is not lowered",
    }
}

/// The value a PHP integer literal denotes.
///
/// PHP writes an integer in decimal, hexadecimal, octal -- both the legacy
/// leading-zero form and the explicit `0o` one -- or binary, and since 7.4 may
/// separate any of their digits with underscores. Two spellings of one value
/// name one array cell, so the answer is the value rather than the text. A
/// spelling this function cannot read, or one that does not fit, yields `None`
/// and the caller treats the key as non-constant.
fn php_integer_literal(text: &str) -> Option<i64> {
    let digits = text.replace('_', "");
    let (radix, body) = if let Some(rest) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        (16, rest)
    } else if let Some(rest) = digits
        .strip_prefix("0b")
        .or_else(|| digits.strip_prefix("0B"))
    {
        (2, rest)
    } else if let Some(rest) = digits
        .strip_prefix("0o")
        .or_else(|| digits.strip_prefix("0O"))
    {
        (8, rest)
    } else if digits.len() > 1 && digits.starts_with('0') {
        (8, &digits[1..])
    } else {
        (10, digits.as_str())
    };
    if body.is_empty() {
        return None;
    }
    i64::from_str_radix(body, radix).ok()
}

/// The integer a PHP array key string is cast to, when PHP casts it.
///
/// PHP casts a string key to an integer only when the string is the canonical
/// decimal representation of one: an optional `-`, then digits with no leading
/// zero unless the whole number is `0`, no `+`, no whitespace, and a value
/// that fits. So `"0"` and `0` are one cell while `"007"`, `"-0"`, `" 7"`, and
/// `"1_000"` all stay strings -- the underscore separator is a source-literal
/// spelling, not part of a string's value.
fn php_integer_string_key(text: &str) -> Option<i64> {
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if digits.len() > 1 && digits.starts_with('0') {
        return None;
    }
    if negative && digits == "0" {
        return None;
    }
    let value = digits.parse::<i64>().ok()?;
    Some(if negative { -value } else { value })
}

/// The cell an element key names, when the key is a constant.
///
/// PHP normalizes every array key to an integer or a string, and the source
/// spelling is not part of it: `$a['k']` and `$a["k"]` are one cell, and so
/// are `$a["0"]` and `$a[0]`. The answer is therefore the normalized key
/// rather than the text, so a store and a load written differently still meet.
///
/// A string that interpolates, or that carries an escape this adapter does not
/// decode, names no proven cell. Neither does a float: PHP truncates it toward
/// zero, and rather than reimplement that cast the key is declined and the
/// caller publishes its scoped index-memory gap. `true`, `false`, and `null`
/// are cast exactly, to `1`, `0`, and the empty string.
fn php_constant_key(source: &str, node: Node<'_>) -> Option<Box<str>> {
    match node.kind() {
        "integer" => {
            let value = php_integer_literal(nonempty_node_text(source, node)?)?;
            Some(format!("i:{value}").into())
        }
        "boolean" => {
            let text = nonempty_node_text(source, node)?;
            if text.eq_ignore_ascii_case("true") {
                Some("i:1".into())
            } else if text.eq_ignore_ascii_case("false") {
                Some("i:0".into())
            } else {
                None
            }
        }
        "null" => Some("s:".into()),
        "string" | "encapsed_string" => {
            let mut content = None;
            for child in named_children(node) {
                match child.kind() {
                    "string_content" if content.is_none() => {
                        content = Some(node_text(source, child)?);
                    }
                    _ => return None,
                }
            }
            let content = content.unwrap_or_default();
            Some(match php_integer_string_key(content) {
                Some(value) => format!("i:{value}").into(),
                None => format!("s:{content}").into(),
            })
        }
        _ => None,
    }
}

fn php_place_detail(place: &PhpPlace<'_>) -> &'static str {
    match place {
        PhpPlace::Field { .. } => "property access and magic property dispatch",
        PhpPlace::Element { .. } => "array access and ArrayAccess protocol dispatch",
    }
}

/// The place an expression names, when the shape is one this adapter lowers.
///
/// A property whose name is computed -- `$o->$name`, `$o->{expr}` -- names no
/// place here: the name is a value, so the occurrence identifies no member,
/// and lowering it as an any-member access would let one write meet an
/// unrelated read. A static property, a destructuring pattern, and a
/// variable-variable are declined for their own reasons at the call site.
fn php_place(node: Node<'_>) -> Option<PhpPlace<'_>> {
    match node.kind() {
        "member_access_expression" | "nullsafe_member_access_expression" => {
            let object = node.child_by_field_name("object")?;
            let name = node.child_by_field_name("name")?;
            (name.kind() == "name").then_some(PhpPlace::Field { object, name })
        }
        "subscript_expression" => {
            let children = runtime_expression_children(node);
            let object = *children.first()?;
            Some(PhpPlace::Element {
                object,
                key: children.get(1).copied(),
            })
        }
        _ => None,
    }
}

/// The names a `foreach` clause binds, and whether it also binds a shape this
/// adapter does not lower.
///
/// The clause's first child is the collection, which is read; everything after
/// it is a target. `as $value` binds one name, `as $key => $value` binds the
/// two sides of a `pair`. A by-reference target writes back into the
/// collection, and a destructuring target spreads one element across several
/// names; neither is lowered, and the caller declines for them.
fn php_foreach_targets(node: Node<'_>) -> (Vec<Node<'_>>, bool) {
    let body = node.child_by_field_name("body");
    let mut pending = named_children(node)
        .into_iter()
        .filter(|child| body.is_none_or(|body| child.id() != body.id()))
        .collect::<Vec<_>>();
    if pending.is_empty() {
        return (Vec::new(), false);
    }
    pending.remove(0);
    let mut targets = Vec::new();
    let mut unlowered = false;
    while let Some(target) = pending.pop() {
        match target.kind() {
            "variable_name" => targets.push(target),
            "pair" => pending.extend(named_children(target)),
            _ => unlowered = true,
        }
    }
    (targets, unlowered)
}

/// Whether this expression is written by the assignment that contains it.
///
/// A write target is not a read. A lowered store replaces its evaluation list
/// so the target is never scheduled, but a declined one -- a destructuring
/// pattern, a target this adapter does not lower -- still schedules its own
/// operands. Minting a `MemoryLoad` there would publish a read of the very
/// location the statement overwrites.
fn is_php_assignment_target(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "parenthesized_expression"
            | "list_literal"
            | "array_creation_expression"
            | "array_element_initializer" => current = parent,
            "assignment_expression" | "reference_assignment_expression" => {
                return field_matches(parent, "left", current);
            }
            _ => return false,
        }
    }
    false
}

/// What one local name of a procedure holds, when every binding of it agrees.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PhpLocalType {
    /// An instance of exactly this class.
    Class(Box<str>),
    /// A PHP array. An array is not an object, so no `ArrayAccess` dispatch or
    /// magic accessor can run behind an element access on it.
    Array,
}

/// The class name of the type-like declaration this callable is written in.
fn enclosing_class_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    let mut parent = node.parent();
    while let Some(candidate) = parent {
        if matches!(
            candidate.kind(),
            "class_declaration" | "trait_declaration" | "enum_declaration"
        ) {
            return declaration_container_name(source, candidate);
        }
        parent = candidate.parent();
    }
    None
}

/// What each local name of one procedure holds.
///
/// The pass is a single source-order sweep, which is enough for the shape it
/// serves: a name is bound before it is read, and `$alias = $original` carries
/// the class the earlier binding proved. A name two bindings disagree about is
/// removed rather than guessed, so an access through it falls back to the
/// interned locator and publishes its own field-identity gap.
fn php_local_types(
    prepared: &PreparedSyntaxTree,
    inventory: &PhpClassInventory,
    callable: Node<'_>,
    body: Node<'_>,
    enclosing_class: Option<&str>,
) -> HashMap<Box<str>, PhpLocalType> {
    let source = prepared.source();
    let mut types: HashMap<Box<str>, PhpLocalType> = HashMap::default();
    let mut conflicting: Vec<Box<str>> = Vec::new();

    for parameter in callable
        .child_by_field_name("parameters")
        .map(named_children)
        .unwrap_or_default()
    {
        if !matches!(
            parameter.kind(),
            "simple_parameter" | "property_promotion_parameter"
        ) {
            continue;
        }
        let (Some(name), Some(class)) = (
            parameter.child_by_field_name("name"),
            parameter
                .child_by_field_name("type")
                .and_then(|type_node| php_declared_class(source, type_node)),
        ) else {
            continue;
        };
        let name = php_variable_name(source, name);
        if !name.is_empty() {
            types.insert(name.into(), PhpLocalType::Class(class));
        }
    }

    let bind = |types: &mut HashMap<Box<str>, PhpLocalType>,
                conflicting: &mut Vec<Box<str>>,
                name: &str,
                inferred: Option<PhpLocalType>| {
        if name.is_empty() || name == "this" {
            return;
        }
        match inferred {
            Some(inferred) if types.get(name) == Some(&inferred) => {}
            Some(inferred) if !types.contains_key(name) => {
                types.insert(name.into(), inferred);
            }
            _ => {
                types.remove(name);
                conflicting.push(name.into());
            }
        }
    };

    let mut stack = vec![body];
    let mut ordered = Vec::new();
    while let Some(node) = stack.pop() {
        if node.id() != body.id() && is_callable_kind(node.kind()) {
            continue;
        }
        ordered.push(node);
        stack.extend(named_children(node));
    }
    ordered.sort_by_key(|node| (node.start_byte(), node.end_byte()));
    for node in ordered {
        match node.kind() {
            "assignment_expression" | "reference_assignment_expression" => {
                let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) else {
                    continue;
                };
                if left.kind() != "variable_name" {
                    continue;
                }
                let inferred =
                    php_expression_local_type(source, inventory, &types, enclosing_class, right, 0);
                bind(
                    &mut types,
                    &mut conflicting,
                    php_variable_name(source, left),
                    inferred,
                );
            }
            "catch_clause" => {
                let (Some(name), Some(class)) = (
                    node.child_by_field_name("name"),
                    node.child_by_field_name("type")
                        .and_then(|type_node| php_declared_class(source, type_node)),
                ) else {
                    continue;
                };
                bind(
                    &mut types,
                    &mut conflicting,
                    php_variable_name(source, name),
                    Some(PhpLocalType::Class(class)),
                );
            }
            "foreach_statement" => {
                // A loop variable takes whatever the iterated collection
                // yields, which this pass does not model. The collection
                // itself is read, not bound, and keeps what it held.
                for target in php_foreach_targets(node).0 {
                    bind(
                        &mut types,
                        &mut conflicting,
                        php_variable_name(source, target),
                        None,
                    );
                }
            }
            _ => {}
        }
    }
    for name in conflicting {
        types.remove(&name);
    }
    types
}

/// The local type an expression produces, when its syntax states one.
fn php_expression_local_type(
    source: &str,
    inventory: &PhpClassInventory,
    types: &HashMap<Box<str>, PhpLocalType>,
    enclosing_class: Option<&str>,
    node: Node<'_>,
    depth: usize,
) -> Option<PhpLocalType> {
    // A property chain is finite in practice; the bound keeps a pathological
    // source from walking one occurrence per nesting level.
    if depth > 16 {
        return None;
    }
    match node.kind() {
        "array_creation_expression" => Some(PhpLocalType::Array),
        "object_creation_expression" => named_children(node)
            .into_iter()
            .find(|child| {
                matches!(
                    child.kind(),
                    "name" | "qualified_name" | "anonymous_class" | "variable_name"
                )
            })
            .and_then(|child| php_unqualified_class_name(source, child))
            .map(|name| PhpLocalType::Class(name.into())),
        "parenthesized_expression" | "clone_expression" => {
            let inner = first_runtime_named_child(node)?;
            php_expression_local_type(source, inventory, types, enclosing_class, inner, depth + 1)
        }
        "variable_name" => {
            let name = php_variable_name(source, node);
            if name == "this" {
                return enclosing_class.map(|class| PhpLocalType::Class(class.into()));
            }
            types.get(name).cloned()
        }
        "member_access_expression" | "nullsafe_member_access_expression" => {
            let object = node.child_by_field_name("object")?;
            let name = node.child_by_field_name("name")?;
            if name.kind() != "name" {
                return None;
            }
            let property = nonempty_node_text(source, name)?;
            let PhpLocalType::Class(class) = php_expression_local_type(
                source,
                inventory,
                types,
                enclosing_class,
                object,
                depth + 1,
            )?
            else {
                return None;
            };
            inventory
                .get(&class)?
                .property_classes
                .get(property)
                .cloned()
                .map(PhpLocalType::Class)
        }
        _ => None,
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::analyzer::LanguageDialect;
    use crate::analyzer::tree_sitter_analyzer::{PreparedSourceOrigin, PreparedSyntaxSource};
    use crate::text_utils::compute_line_starts;

    /// Lower one inline PHP file and return the procedures the adapter built.
    ///
    /// A lowering failure is not a partial result: the provider drops the whole
    /// file's semantics, so every query over any procedure in it disappears.
    /// That is what makes the shape of this harness the point -- an `expect`
    /// here stands for a file that a campaign would find silently unqueryable.
    fn lower_php(source: &str) -> Vec<ProcedureSemanticsParts> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
            .expect("PHP grammar must load");
        let tree = parser.parse(source, None).expect("PHP source must parse");
        let prepared = PreparedSyntaxTree::new(
            PreparedSyntaxSource::Exact(Arc::<str>::from(source)),
            tree,
            compute_line_starts(source),
            LanguageDialect::Standard(Language::Php),
            PreparedSourceOrigin::Disk,
            None,
        );
        let file = ProjectFile::new(std::env::temp_dir(), "fixture.php");
        let outcome = PhpSemanticLowerer
            .lower(
                &file,
                &prepared,
                &SemanticBudget::default(),
                &CancellationToken::default(),
            )
            .expect("PHP lowering must not fail");
        let SemanticOutcome::Complete { value, .. } = outcome else {
            panic!("the fixture is small enough to lower completely");
        };
        value
    }

    /// The one procedure's program point and control edge counts, which say
    /// that the arms were lowered and how many decisions the body kept.
    fn lowered_shape(source: &str) -> (usize, usize) {
        let mut procedures = lower_php(source);
        assert_eq!(
            procedures.len(),
            1,
            "the fixture declares exactly one procedure"
        );
        let parts = procedures.remove(0);
        (parts.points.len(), parts.control_edges.len())
    }

    /// `comment` is a tree-sitter extra, so the grammar admits one anywhere in
    /// a `match_block` and makes it a named child there. Asking a comment for
    /// the `return_expression` every arm has failed the lowering, and because a
    /// provider failure is per file rather than per procedure, one `//` in one
    /// match body cost that whole file its semantics. Every position the
    /// grammar allows a comment in must lower to the same procedure as the
    /// comment-free spelling.
    #[test]
    fn commented_match_bodies_lower_like_their_comment_free_spelling() {
        let baseline = lowered_shape(
            "<?php\nfunction pick(string $t): int {\n    return match ($t) {\n        'a', 'b' => 1,\n        default => 0,\n    };\n}\n",
        );

        for (position, source) in [
            (
                "leading line comment",
                "<?php\nfunction pick(string $t): int {\n    return match ($t) {\n        // leading\n        'a', 'b' => 1,\n        default => 0,\n    };\n}\n",
            ),
            (
                "between-arm block comment",
                "<?php\nfunction pick(string $t): int {\n    return match ($t) {\n        'a', 'b' => 1,\n        /* between */\n        default => 0,\n    };\n}\n",
            ),
            (
                "trailing line comment",
                "<?php\nfunction pick(string $t): int {\n    return match ($t) {\n        'a', 'b' => 1,\n        default => 0, // trailing\n    };\n}\n",
            ),
            (
                "comment inside the condition list",
                "<?php\nfunction pick(string $t): int {\n    return match ($t) {\n        'a', /* mid */ 'b' => 1,\n        default => 0,\n    };\n}\n",
            ),
        ] {
            assert_eq!(
                lowered_shape(source),
                baseline,
                "a {position} must not change what the match body lowers to"
            );
        }
    }

    /// The near miss the defect report contrasted against: a `switch` body
    /// screens its children by case kind, so a comment there was always
    /// harmless. It must stay harmless.
    #[test]
    fn commented_switch_bodies_lower_like_their_comment_free_spelling() {
        let baseline = lowered_shape(
            "<?php\nfunction pick(string $t): int {\n    switch ($t) {\n        case 'a':\n            return 1;\n    }\n    return 0;\n}\n",
        );
        let commented = lowered_shape(
            "<?php\nfunction pick(string $t): int {\n    switch ($t) {\n        // leading\n        case 'a':\n            return 1; // trailing\n    }\n    return 0;\n}\n",
        );
        assert_eq!(commented, baseline);
    }

    /// The constant the condition lowering folds `if (<condition>)` to, or
    /// `None` when it keeps the decision and lowers the condition instead.
    fn folded_condition(condition: &str) -> Option<bool> {
        let source = format!(
            "<?php\nfunction run(): void {{\n    if ({condition}) {{\n        noop();\n    }}\n}}\n"
        );
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
            .expect("PHP grammar must load");
        let tree = parser
            .parse(source.as_str(), None)
            .expect("PHP source must parse");
        let mut statement = None;
        crate::analyzer::tree_sitter_analyzer::walk_named_tree_preorder(
            tree.root_node(),
            true,
            |node| {
                if node.kind() == "if_statement" {
                    statement = Some(node);
                    WalkControl::Break
                } else {
                    WalkControl::Continue
                }
            },
        );
        let statement = statement.expect("if statement");
        let condition = statement
            .child_by_field_name("condition")
            .expect("if condition");
        php_folded_boolean_constant(source.as_str(), condition)
    }

    #[test]
    fn constant_boolean_conditions_fold_through_their_wrappers() {
        for (condition, value) in [
            ("false", false),
            ("true", true),
            ("!false", true),
            ("!true", false),
            ("!!false", false),
            ("(false)", false),
            ("((true))", true),
            ("(!(false))", true),
            // PHP spells both constants case-insensitively.
            ("FALSE", false),
            ("False", false),
            ("TRUE", true),
            ("!FALSE", true),
        ] {
            assert_eq!(
                folded_condition(condition),
                Some(value),
                "`if ({condition})` is the constant {value}"
            );
        }
    }

    #[test]
    fn non_constant_conditions_keep_their_decision() {
        for condition in [
            "$flag",
            "!$flag",
            "$flag === false",
            "is_ready()",
            "!is_ready()",
            "$flag && false",
            // Truthiness of a non-boolean literal is a separate normalization
            // this adapter does not claim.
            "-1",
            "0",
            "\"false\"",
        ] {
            assert_eq!(
                folded_condition(condition),
                None,
                "`if ({condition})` is not a folded constant"
            );
        }
    }

    #[test]
    fn guard_facts_are_partially_supported() {
        assert_eq!(
            php_capabilities().support(SemanticCapability::GuardFacts),
            CapabilitySupport::Partial,
            "PHP folds constant boolean conditions and records every other decision opaque"
        );
    }

    /// PHP casts an array key string to an integer only when the string is the
    /// canonical decimal representation of one. The pairs that must meet and
    /// the near misses that must not are both part of the contract: an
    /// over-eager cast merges cells PHP keeps apart, and a missing one splits
    /// a cell PHP keeps together.
    #[test]
    fn php_array_key_strings_cast_exactly_when_php_casts_them() {
        for (text, expected) in [
            ("0", Some(0)),
            ("7", Some(7)),
            ("-1", Some(-1)),
            ("1234567890", Some(1_234_567_890)),
            // A leading zero is not canonical, so the key stays a string and
            // never meets the integer 7.
            ("07", None),
            ("007", None),
            ("00", None),
            // Negative zero, a leading plus, whitespace, and a separator are
            // all spellings PHP leaves as strings.
            ("-0", None),
            ("+1", None),
            (" 7", None),
            ("7 ", None),
            ("1_000", None),
            // Not a decimal integer at all.
            ("", None),
            ("k", None),
            ("0x1F", None),
            ("1.0", None),
            ("-", None),
            // Beyond what an integer key can hold.
            ("99999999999999999999", None),
        ] {
            assert_eq!(
                php_integer_string_key(text),
                expected,
                "PHP array key string {text:?} cast wrongly"
            );
        }
    }

    /// Two spellings of one integer name one cell, so a literal is read for
    /// its value and not its text.
    #[test]
    fn php_integer_literals_are_read_by_value() {
        for (text, expected) in [
            ("0", Some(0)),
            ("7", Some(7)),
            ("1000", Some(1000)),
            ("1_000", Some(1000)),
            ("0x1F", Some(31)),
            ("0X1f", Some(31)),
            ("0b1010", Some(10)),
            ("0B1_010", Some(10)),
            ("0o17", Some(15)),
            ("017", Some(15)),
            ("0_1_7", Some(15)),
            // Spellings this reader refuses rather than guesses.
            ("", None),
            ("0x", None),
            ("0b2", None),
            ("019", None),
            ("99999999999999999999", None),
        ] {
            assert_eq!(
                php_integer_literal(text),
                expected,
                "PHP integer literal {text:?} read wrongly"
            );
        }
    }

    /// The scalar list is a whitelist because every name absent from it can
    /// hold an object whose release runs a destructor this file never sees.
    #[test]
    fn only_whitelisted_scalar_type_names_hold_no_object() {
        for name in ["int", "float", "string", "bool", "INT", "Never", "void"] {
            assert!(
                php_scalar_type_name(name),
                "{name} states a scalar and holds no object"
            );
        }
        for name in [
            "array", "object", "mixed", "iterable", "callable", "self", "static", "parent",
            "Closing",
        ] {
            assert!(
                !php_scalar_type_name(name),
                "{name} can hold an object and must not be treated as a scalar"
            );
        }
    }
}
