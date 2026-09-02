use super::syntax::*;
use super::*;

#[derive(Clone)]
pub(super) struct ProcedureSpec<'tree> {
    pub(super) id: ProcedureId,
    pub(super) callable: Node<'tree>,
    pub(super) body: ProcedureBody<'tree>,
    pub(super) locator: SemanticLocator,
    pub(super) lexical_parent: Option<ProcedureId>,
    pub(super) kind: ProcedureKind,
    pub(super) properties: ProcedureProperties,
    pub(super) is_suspend: bool,
    pub(super) delegated: bool,
    pub(super) captures_receiver: bool,
    pub(super) captures: Box<[LexicalCaptureSpec<'tree>]>,
}

#[derive(Clone, Copy)]
pub(super) struct LexicalCaptureSpec<'tree> {
    pub(super) name: &'tree str,
    pub(super) declaration_start: usize,
    pub(super) reference: Node<'tree>,
}

/// What a procedure executes, already classified by the inventory so control
/// lowering never has to re-ask how a Kotlin body is spelled.
#[derive(Clone, Copy)]
pub(super) enum ProcedureBody<'tree> {
    /// A `statements` list: a `{ … }` function body, `init { … }`, a lambda, a
    /// `try`'s body, or a secondary constructor's block.
    Statements(Node<'tree>),
    /// One expression whose value is the procedure's result: `= expr`, a
    /// property initializer, a property delegate, or a lambda with a tail
    /// expression.
    Expression(Node<'tree>),
    /// Executable syntax that is neither, such as an `enum_entry`'s argument
    /// list, lowered as an ordinary statement.
    Statement(Node<'tree>),
    /// `{}` — nothing to lower between entry and normal exit.
    Empty(Node<'tree>),
}

impl<'tree> ProcedureBody<'tree> {
    /// The node body-local scans (local bindings, free `this`) start from.
    pub(super) const fn scan_root(self) -> Node<'tree> {
        match self {
            Self::Statements(node)
            | Self::Expression(node)
            | Self::Statement(node)
            | Self::Empty(node) => node,
        }
    }
}

impl ReceiverCaptureSpec for ProcedureSpec<'_> {
    fn lexical_parent(&self) -> Option<ProcedureId> {
        self.lexical_parent
    }

    fn relays_receiver_capture(&self) -> bool {
        self.kind == ProcedureKind::Lambda
    }

    fn captures_receiver(&self) -> bool {
        self.captures_receiver
    }

    fn require_receiver_capture(&mut self) {
        self.captures_receiver = true;
    }
}

#[derive(Clone)]
pub(super) struct NestedProcedureTarget {
    pub(super) id: ProcedureId,
    pub(super) receiver_capture_destination: Option<MemoryLocationId>,
    pub(super) captures: Box<[LexicalCaptureSource]>,
}

#[derive(Clone)]
pub(super) struct LexicalCaptureSource {
    pub(super) name: Box<str>,
    pub(super) declaration_start: usize,
}

pub(super) type ProcedureEnumeration<'tree> = ProcedureInventoryOutcome<Vec<ProcedureSpec<'tree>>>;

enum KotlinInventoryPrepassStop {
    Budget(ProcedureInventoryStop),
    Cancelled,
}

fn charge_kotlin_inventory_prepass(
    inventory: &mut ProcedureInventoryBuilder<'_>,
    cancellation: &CancellationToken,
) -> Result<(), KotlinInventoryPrepassStop> {
    if cancellation.is_cancelled() {
        return Err(KotlinInventoryPrepassStop::Cancelled);
    }
    inventory
        .charge_traversal_entry()
        .map_err(KotlinInventoryPrepassStop::Budget)
}

struct ProcedureEnumerationFrame<'tree> {
    node: Node<'tree>,
    lexical_parent: Option<ProcedureId>,
    declaration_path: usize,
}

pub(super) fn enumerate_procedures<'tree>(
    file: &ProjectFile,
    prepared: &'tree PreparedSyntaxTree,
    budget: &SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<ProcedureEnumeration<'tree>, SemanticProviderError> {
    let source = prepared.source();
    let root = prepared.tree().root_node();
    let mut inventory =
        ProcedureInventoryBuilder::new(file, prepared.dialect(), root, "kotlin-source", budget)?;
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
        let mut child_path = frame.declaration_path;
        if let Some(segment_kind) = declaration_container_kind(frame.node) {
            let name = declaration_container_name(source, frame.node);
            let anchor =
                source_anchor(frame.node, 0).map_err(SemanticProviderError::invalid_identity)?;
            child_path = inventory.push_container(
                frame.declaration_path,
                segment_kind,
                name.as_deref(),
                anchor,
            )?;
        }

        let mut child_parent = frame.lexical_parent;
        if let Some(shape) = callable_shape(source, frame.node, frame.lexical_parent.is_some()) {
            let name = callable_name(source, frame.node, shape.kind);
            let anchor =
                source_anchor(frame.node, 0).map_err(SemanticProviderError::invalid_identity)?;
            let identity = match inventory.allocate_procedure(
                child_path,
                shape.segment_kind,
                name.as_deref(),
                anchor,
            )? {
                Ok(identity) => identity,
                Err(stop) => return Ok(stop.into_outcome()),
            };
            let captures_receiver = if shape.kind == ProcedureKind::Lambda {
                match body_contains_free_this(shape.body.scan_root(), cancellation) {
                    Ok(captures_receiver) => captures_receiver,
                    Err(LoweringCancelled) => return Ok(inventory.cancelled()),
                }
            } else {
                false
            };
            specs.push(ProcedureSpec {
                id: identity.id,
                callable: frame.node,
                body: shape.body,
                locator: identity.locator,
                lexical_parent: frame.lexical_parent,
                kind: shape.kind,
                properties: shape.properties,
                is_suspend: shape.is_suspend,
                delegated: shape.delegated,
                captures_receiver,
                captures: Box::new([]),
            });
            child_parent = Some(identity.id);
            child_path = identity.declaration_path;
        }

        for child in named_children(frame.node).into_iter().rev() {
            stack.push(ProcedureEnumerationFrame {
                node: child,
                lexical_parent: child_parent,
                declaration_path: child_path,
            });
        }
    }

    match populate_lexical_capture_specs(&mut specs, source, &mut inventory, cancellation) {
        Ok(()) => {}
        Err(KotlinInventoryPrepassStop::Budget(stop)) => return Ok(stop.into_outcome()),
        Err(KotlinInventoryPrepassStop::Cancelled) => return Ok(inventory.cancelled()),
    }
    Ok(inventory.complete(specs))
}

/// Inventory the exact Kotlin capture subset represented by the shared IR:
/// one immutable `val` declared in the direct lexical parent before the
/// nested callable, read by that child without a child-local declaration of
/// the same name. Kotlin forbids reassignment of a `val`, so the declaration
/// node and its lexical scope are the stable storage identity.
fn populate_lexical_capture_specs<'tree>(
    specs: &mut [ProcedureSpec<'tree>],
    source: &'tree str,
    inventory: &mut ProcedureInventoryBuilder<'_>,
    cancellation: &CancellationToken,
) -> Result<(), KotlinInventoryPrepassStop> {
    #[derive(Clone, Copy)]
    struct ParentBinding<'tree> {
        name: &'tree str,
        declaration_start: usize,
        visible_from: usize,
        scope_start: usize,
        scope_end: usize,
    }

    let mut bindings = vec![Vec::<ParentBinding<'tree>>::new(); specs.len()];
    for spec in specs.iter() {
        let mut found = Vec::new();
        try_walk_named_tree_preorder(spec.body.scan_root(), true, |node| {
            charge_kotlin_inventory_prepass(inventory, cancellation)?;
            if node.id() != spec.body.scan_root().id() && is_kotlin_nested_execution_boundary(node)
            {
                return Ok(WalkControl::SkipChildren);
            }
            if node.kind() == "property_declaration"
                && child_of_kind(node, "binding_pattern_kind")
                    .and_then(|kind| node_text(source, kind))
                    == Some("val")
                && let Some(binding) = binding_node(node)
                && binding.kind() == "variable_declaration"
                && let Some(name_node) = binding_names(binding).first().copied()
                && let Some(name) = node_text(source, name_node)
                && property_initializer(node).is_some()
                && let Some((scope_start, scope_end)) = kotlin_local_scope(name_node)
            {
                found.push(ParentBinding {
                    name,
                    declaration_start: name_node.start_byte(),
                    visible_from: node.end_byte(),
                    scope_start,
                    scope_end,
                });
            }
            Ok(WalkControl::Continue)
        })?;
        bindings[spec.id.index()] = found;
    }

    let mut captures = vec![Vec::<LexicalCaptureSpec<'tree>>::new(); specs.len()];
    for child in specs.iter() {
        let Some(parent) = child.lexical_parent else {
            continue;
        };
        let mut child_bindings = HashSet::<Box<str>>::default();
        try_walk_named_tree_preorder(child.callable, true, |node| {
            charge_kotlin_inventory_prepass(inventory, cancellation)?;
            if node.id() == child.body.scan_root().id() {
                return Ok(WalkControl::SkipChildren);
            }
            if matches!(
                node.kind(),
                "parameter" | "class_parameter" | "parameter_with_optional_type"
            ) && let Some(name) =
                child_of_kind(node, "simple_identifier").and_then(|name| node_text(source, name))
            {
                child_bindings.insert(name.into());
            }
            Ok(WalkControl::Continue)
        })?;
        try_walk_named_tree_preorder(child.body.scan_root(), true, |node| {
            charge_kotlin_inventory_prepass(inventory, cancellation)?;
            if node.id() != child.body.scan_root().id() && is_kotlin_nested_execution_boundary(node)
            {
                return Ok(WalkControl::SkipChildren);
            }
            if matches!(
                node.kind(),
                "variable_declaration" | "multi_variable_declaration"
            ) {
                for name in binding_names(node) {
                    if let Some(text) = node_text(source, name) {
                        child_bindings.insert(text.into());
                    }
                }
            }
            Ok(WalkControl::Continue)
        })?;

        let mut first_references = HashMap::<Box<str>, Node<'tree>>::default();
        try_walk_named_tree_preorder(child.body.scan_root(), true, |node| {
            charge_kotlin_inventory_prepass(inventory, cancellation)?;
            if node.id() != child.body.scan_root().id() && is_kotlin_nested_execution_boundary(node)
            {
                return Ok(WalkControl::SkipChildren);
            }
            if node.kind() == "simple_identifier"
                && let Some(name) = node_text(source, node)
                && !child_bindings.contains(name)
            {
                first_references.entry(name.into()).or_insert(node);
            }
            Ok(WalkControl::Continue)
        })?;

        for (name, reference) in first_references {
            let Some(binding) = bindings[parent.index()]
                .iter()
                .filter(|binding| {
                    binding.name == name.as_ref()
                        && binding.visible_from <= child.callable.start_byte()
                        && binding.scope_start <= child.callable.start_byte()
                        && child.callable.start_byte() < binding.scope_end
                })
                .min_by_key(|binding| binding.scope_end - binding.scope_start)
            else {
                continue;
            };
            captures[child.id.index()].push(LexicalCaptureSpec {
                name: binding.name,
                declaration_start: binding.declaration_start,
                reference,
            });
        }
        captures[child.id.index()].sort_by_key(|capture| capture.declaration_start);
    }
    for (spec, captures) in specs.iter_mut().zip(captures) {
        spec.captures = captures.into_boxed_slice();
    }
    Ok(())
}

/// The class names this file declares that a bare call can construct.
///
/// Kotlin has no `new`: `Box(input)` is spelled exactly like a function call,
/// so nothing in the call's own syntax says whether it allocates. Without
/// whole-program resolution the constructions this adapter can *prove* are the
/// ones naming a class declared in the same file; every other call stays an
/// ordinary call site whose target the shared dispatch oracle resolves, rather
/// than being guessed at from the callee's spelling.
///
/// Interfaces are excluded because they are not constructible, and `object`
/// declarations because their name denotes the singleton rather than a
/// constructor.
pub(super) fn collect_constructible_types(
    prepared: &PreparedSyntaxTree,
    cancellation: &CancellationToken,
) -> Result<HashSet<Box<str>>, LoweringCancelled> {
    let source = prepared.source();
    let mut names = HashSet::default();
    try_walk_named_tree_preorder(prepared.tree().root_node(), true, |node| {
        if cancellation.is_cancelled() {
            return Err(LoweringCancelled);
        }
        if node.kind() == "class_declaration"
            && !has_token(node, "interface")
            && let Some(name) = declaration_container_name(source, node)
        {
            names.insert(name);
        }
        Ok(WalkControl::Continue)
    })?;
    Ok(names)
}

struct CallableShape<'tree> {
    kind: ProcedureKind,
    segment_kind: DeclarationSegmentKind,
    body: ProcedureBody<'tree>,
    properties: ProcedureProperties,
    is_suspend: bool,
    delegated: bool,
}

/// Classify one node as a Kotlin callable with its own executable body.
///
/// `inside_procedure` distinguishes a local `fun` from a member or top-level
/// one; the declaration site (a type body or the file) distinguishes a property
/// initializer, getter, or setter from an ordinary local statement that reuses
/// the same grammar node.
fn callable_shape<'tree>(
    source: &str,
    node: Node<'tree>,
    inside_procedure: bool,
) -> Option<CallableShape<'tree>> {
    // An accessor answers for the property that owns it, which the grammar
    // nests either inside the `property_declaration` or beside it.
    let declaration = match node.kind() {
        "getter" | "setter" => accessor_property(node).unwrap_or(node),
        _ => node,
    };
    let is_file_level = declaration
        .parent()
        .is_some_and(|parent| parent.kind() == "source_file");
    let (kind, segment_kind, body) = match node.kind() {
        "function_declaration" => {
            let body = body_from_function_body(child_of_kind(node, "function_body")?);
            let (kind, segment_kind) = if inside_procedure && !is_declaration_site(node) {
                (
                    ProcedureKind::LocalFunction,
                    DeclarationSegmentKind::Function,
                )
            } else if is_file_level {
                (ProcedureKind::Function, DeclarationSegmentKind::Function)
            } else {
                (ProcedureKind::Method, DeclarationSegmentKind::Method)
            };
            (kind, segment_kind, body)
        }
        "secondary_constructor" => (
            ProcedureKind::Constructor,
            DeclarationSegmentKind::Constructor,
            child_of_kind(node, "statements")
                .map_or(ProcedureBody::Empty(node), ProcedureBody::Statements),
        ),
        "anonymous_initializer" => (
            ProcedureKind::Initializer,
            DeclarationSegmentKind::Initializer,
            child_of_kind(node, "statements")
                .map_or(ProcedureBody::Empty(node), ProcedureBody::Statements),
        ),
        "property_declaration" if is_declaration_site(node) => {
            let value =
                property_delegate_expression(node).or_else(|| property_initializer(node))?;
            (
                ProcedureKind::Initializer,
                DeclarationSegmentKind::Initializer,
                ProcedureBody::Expression(value),
            )
        }
        "getter" | "setter" => {
            let body = body_from_function_body(child_of_kind(node, "function_body")?);
            (
                ProcedureKind::Accessor,
                DeclarationSegmentKind::Method,
                body,
            )
        }
        "lambda_literal" => (
            ProcedureKind::Lambda,
            DeclarationSegmentKind::Lambda,
            lambda_body(node),
        ),
        "anonymous_function" => {
            let body = body_from_function_body(child_of_kind(node, "function_body")?);
            (
                ProcedureKind::Lambda,
                DeclarationSegmentKind::AnonymousCallable,
                body,
            )
        }
        // A primary-constructor parameter default is executable syntax with no
        // body node of its own: it runs once per construction that omits the
        // argument. Giving it an `Initializer` procedure is what lets the
        // expression — and any call inside it — be lowered at all; when it runs
        // relative to property initializers and `init` blocks stays a
        // procedure-scoped gap, the same one every Kotlin initializer carries.
        "class_parameter" => (
            ProcedureKind::Initializer,
            DeclarationSegmentKind::Initializer,
            ProcedureBody::Expression(class_parameter_default(node)?),
        ),
        "enum_entry" => {
            let arguments = child_of_kind(node, "value_arguments")?;
            (
                ProcedureKind::Initializer,
                DeclarationSegmentKind::Initializer,
                ProcedureBody::Statement(arguments),
            )
        }
        _ => return None,
    };

    // Only file-level functions and file-level property initializers execute
    // without a receiver. A `companion object` or `object` member still has
    // one: its singleton instance.
    let is_static = is_file_level
        && matches!(
            kind,
            ProcedureKind::Function | ProcedureKind::Initializer | ProcedureKind::Accessor
        );
    let is_suspend = has_modifier(source, node, "suspend");
    let delegated =
        node.kind() == "property_declaration" && property_delegate_expression(node).is_some();
    Some(CallableShape {
        kind,
        segment_kind,
        body,
        properties: ProcedureProperties {
            // `suspend` is a modifier on an ordinary immediate call: the body
            // begins executing at the call. The continuation-passing rewrite is
            // compiler-generated and is reported as a procedure-scoped gap
            // rather than by claiming Rust's deferred-invocation semantics.
            is_async: false,
            is_generator: false,
            is_static,
            is_synthetic: false,
            invocation: ProcedureInvocationKind::Immediate,
            dispatch_extensibility: dispatch_extensibility(source, node, kind, is_static),
        },
        is_suspend,
        delegated,
    })
}

fn body_from_function_body(function_body: Node<'_>) -> ProcedureBody<'_> {
    match function_body_shape(function_body) {
        BodyShape::Block(statements) => ProcedureBody::Statements(statements),
        BodyShape::Expression(expression) => ProcedureBody::Expression(expression),
        BodyShape::Empty => ProcedureBody::Empty(function_body),
    }
}

/// A lambda's body is its `statements` list, whose trailing expression — when
/// it is one — is the lambda's result.
fn lambda_body(node: Node<'_>) -> ProcedureBody<'_> {
    child_of_kind(node, "statements").map_or(ProcedureBody::Empty(node), ProcedureBody::Statements)
}

/// Kotlin inverts Java's default: classes and members are final unless opened.
fn dispatch_extensibility(
    source: &str,
    node: Node<'_>,
    kind: ProcedureKind,
    is_static: bool,
) -> DispatchExtensibility {
    if is_static
        || matches!(
            kind,
            ProcedureKind::Constructor
                | ProcedureKind::Lambda
                | ProcedureKind::LocalFunction
                | ProcedureKind::Initializer
        )
    {
        return DispatchExtensibility::Closed;
    }
    if has_modifier(source, node, "private") || has_modifier(source, node, "final") {
        return DispatchExtensibility::Closed;
    }
    if has_modifier(source, node, "open")
        || has_modifier(source, node, "abstract")
        || has_modifier(source, node, "override")
    {
        return DispatchExtensibility::Open;
    }
    // An accessor is overridable exactly when the property that owns it is, and
    // the property's own modifiers sit on the enclosing declaration.
    let owner = if kind == ProcedureKind::Accessor {
        accessor_property(node).unwrap_or(node)
    } else {
        node
    };
    if owner.id() != node.id()
        && (has_modifier(source, owner, "open")
            || has_modifier(source, owner, "abstract")
            || has_modifier(source, owner, "override"))
    {
        return DispatchExtensibility::Open;
    }
    enclosing_type_declaration(node)
        .filter(|declaration| type_admits_overrides(source, *declaration))
        .map_or(DispatchExtensibility::Closed, |_| {
            DispatchExtensibility::Open
        })
}

/// The property a `getter`/`setter` belongs to.
///
/// The grammar admits both nestings: an accessor written on the same line is a
/// child of the `property_declaration`, while one written on the following line
/// becomes its next sibling in the class body.
fn accessor_property<'tree>(accessor: Node<'tree>) -> Option<Node<'tree>> {
    let parent = accessor.parent()?;
    if parent.kind() == "property_declaration" {
        return Some(parent);
    }
    let mut previous = accessor.prev_named_sibling();
    while let Some(candidate) = previous {
        match candidate.kind() {
            "property_declaration" => return Some(candidate),
            "getter" | "setter" => previous = candidate.prev_named_sibling(),
            _ => return None,
        }
    }
    None
}

fn callable_name(source: &str, node: Node<'_>, kind: ProcedureKind) -> Option<Box<str>> {
    match node.kind() {
        "function_declaration" | "enum_entry" | "class_parameter" => {
            child_of_kind(node, "simple_identifier")
                .and_then(|name| nonempty_node_text(source, name))
                .map(Box::<str>::from)
        }
        "property_declaration" => binding_node(node)
            .and_then(|binding| binding_names(binding).first().copied())
            .and_then(|name| nonempty_node_text(source, name))
            .map(Box::<str>::from),
        "getter" => Some(Box::<str>::from("get")),
        "setter" => Some(Box::<str>::from("set")),
        "secondary_constructor" => enclosing_type_declaration(node)
            .and_then(|owner| declaration_container_name(source, owner)),
        "lambda_literal" | "anonymous_function" => enclosing_property_name(source, node),
        _ => {
            let _ = kind;
            None
        }
    }
}

/// The property a callable literal initializes, so `val handler = { … }` names
/// its lambda rather than leaving it anonymous.
fn enclosing_property_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    let parent = node
        .parent()
        .filter(|parent| parent.kind() == "property_declaration")?;
    if property_initializer(parent).is_none_or(|value| value.id() != node.id()) {
        return None;
    }
    binding_node(parent)
        .and_then(|binding| binding_names(binding).first().copied())
        .and_then(|name| nonempty_node_text(source, name))
        .map(Box::<str>::from)
}
