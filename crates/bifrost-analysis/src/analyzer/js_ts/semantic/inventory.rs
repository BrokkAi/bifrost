use super::syntax::*;
use super::*;

pub(super) struct ProcedureSpec<'tree> {
    pub(super) id: ProcedureId,
    pub(super) body: Node<'tree>,
    pub(super) locator: SemanticLocator,
    pub(super) lexical_parent: Option<ProcedureId>,
    pub(super) kind: ProcedureKind,
    pub(super) properties: ProcedureProperties,
    pub(super) callable: Node<'tree>,
    pub(super) captures_receiver: bool,
    /// Whether this procedure publishes a `this` receiver formal: the body
    /// reads `this` directly, or a nested callable captures the receiver from
    /// it (propagated in `lower` after capture demand is settled). A plain
    /// function whose `this` is dead has no receiver formal, so a receiverless
    /// call to it binds completely.
    pub(super) owns_receiver: bool,
    /// Direct immutable bindings read from the immediate lexical parent. The
    /// declaration-token range is the durable identity shared by parent and
    /// child lowering; the reference supplies child-local source evidence.
    pub(super) captures: Box<[LexicalCaptureSpec<'tree>]>,
    /// Enclosing bindings that are real captures but are not representable by
    /// this adapter's direct immutable value-capture subset.
    pub(super) omitted_captures: Box<[LexicalCaptureSpec<'tree>]>,
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

#[derive(Clone, Copy)]
pub(super) struct LexicalCaptureSpec<'tree> {
    pub(super) binding: Range,
    pub(super) reference: Node<'tree>,
}

#[derive(Clone)]
pub(super) struct NestedProcedureTarget {
    pub(super) id: ProcedureId,
    pub(super) direct_invocation_supported: bool,
    pub(super) receiver_capture_destination: Option<MemoryLocationId>,
    pub(super) captures: Box<[Range]>,
}

#[derive(Clone, Copy)]
pub(super) struct LexicalCallableTarget {
    pub(super) id: ProcedureId,
    pub(super) available_after: usize,
}

pub(super) struct JsTsProcedureInventory<'tree> {
    pub(super) specs: Vec<ProcedureSpec<'tree>>,
    pub(super) lexical_bindings: JsTsLexicalBindingIndex,
    pub(super) callable_bindings: HashMap<Range, LexicalCallableTarget>,
}

pub(super) type ProcedureEnumeration<'tree> =
    ProcedureInventoryOutcome<JsTsProcedureInventory<'tree>>;

enum JsTsInventoryPrepassStop {
    Budget(ProcedureInventoryStop),
    Cancelled,
}

fn charge_js_ts_inventory_prepass(
    inventory: &mut ProcedureInventoryBuilder<'_>,
    cancellation: &CancellationToken,
) -> Result<(), JsTsInventoryPrepassStop> {
    if cancellation.is_cancelled() {
        return Err(JsTsInventoryPrepassStop::Cancelled);
    }
    inventory
        .charge_traversal_entry()
        .map_err(JsTsInventoryPrepassStop::Budget)
}

#[derive(Clone, Copy)]
struct DirectLocalBinding<'tree> {
    owner: ProcedureId,
    declarator: Node<'tree>,
    stable: bool,
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
    let language = prepared.dialect();
    let fallback_file_name = match language.language() {
        Language::JavaScript => "javascript-source",
        Language::TypeScript => "typescript-source",
        _ => unreachable!("the shared lowerer validates a JavaScript or TypeScript dialect"),
    };
    let root = prepared.tree().root_node();
    let mut inventory =
        ProcedureInventoryBuilder::new(file, language, root, fallback_file_name, budget)?;
    let mut specs: Vec<ProcedureSpec<'tree>> = Vec::new();
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
        let ProcedureEnumerationFrame {
            node,
            lexical_parent,
            declaration_path,
        } = frame;
        let mut outer_path = declaration_path;
        if let Some(segment_kind) = declaration_container_kind(node) {
            let name = declaration_container_name(prepared.source(), node);
            let anchor = source_anchor(node, 0).map_err(SemanticProviderError::invalid_identity)?;
            outer_path = inventory.push_container(
                declaration_path,
                segment_kind,
                name.as_deref(),
                anchor,
            )?;
        }

        let mut procedure_context = None;
        if let Some((mut kind, mut segment_kind, body, mut properties)) = callable_shape(node) {
            let name = callable_name(prepared.source(), node);
            if name.as_deref() == Some("constructor") {
                kind = ProcedureKind::Constructor;
                segment_kind = DeclarationSegmentKind::Constructor;
            }
            // A private constructor is TypeScript's closed-dispatch statement:
            // the class cannot be extended, so no override of its members
            // exists (#2717). JavaScript has no accessibility modifiers, so
            // the dialect gate is exact, not conservative.
            if language.language() == Language::TypeScript
                && node.kind() == "method_definition"
                && enclosing_class_has_private_constructor(prepared.source(), node)
            {
                properties.dispatch_extensibility = DispatchExtensibility::Closed;
            }
            let anchor = source_anchor(node, 0).map_err(SemanticProviderError::invalid_identity)?;
            let identity = match inventory.allocate_procedure(
                outer_path,
                segment_kind,
                name.as_deref(),
                anchor,
            )? {
                Ok(identity) => identity,
                Err(stop) => return Ok(stop.into_outcome()),
            };
            let receiver_eligible =
                kind == ProcedureKind::Lambda || procedure_owns_receiver(kind, properties);
            let direct_free_this = if receiver_eligible {
                match body_contains_free_this(body, cancellation) {
                    Ok(direct_free_this) => direct_free_this,
                    Err(LoweringCancelled) => return Ok(inventory.cancelled()),
                }
            } else {
                false
            };
            specs.push(ProcedureSpec {
                id: identity.id,
                body,
                locator: identity.locator,
                lexical_parent,
                kind,
                properties,
                callable: node,
                captures_receiver: kind == ProcedureKind::Lambda && direct_free_this,
                owns_receiver: kind != ProcedureKind::Lambda
                    && receiver_eligible
                    && direct_free_this,
                captures: Box::new([]),
                omitted_captures: Box::new([]),
            });
            procedure_context = Some((identity.id, identity.declaration_path));
        }

        if node.kind() == "decorator" {
            continue;
        }

        let mut cursor = node.walk();
        let children = node
            .children(&mut cursor)
            .enumerate()
            .filter(|(_, child)| child.is_named())
            .map(|(index, child)| (child, node.field_name_for_child(index as u32)))
            .collect::<Vec<_>>();
        for (child, field) in children.into_iter().rev() {
            let (child_parent, child_path) = match procedure_context {
                Some((procedure, procedure_path))
                    if callable_field_belongs_to_procedure(node.kind(), field) =>
                {
                    (Some(procedure), procedure_path)
                }
                _ => (lexical_parent, outer_path),
            };
            stack.push(ProcedureEnumerationFrame {
                node: child,
                lexical_parent: child_parent,
                declaration_path: child_path,
            });
        }
    }
    let lexical_bindings =
        JsTsLexicalBindingIndex::build(prepared.tree().root_node(), prepared.source());
    let callable_bindings = match populate_lexical_capture_specs(
        &mut specs,
        prepared.source(),
        &lexical_bindings,
        &mut inventory,
        cancellation,
    ) {
        Ok(callable_bindings) => callable_bindings,
        Err(JsTsInventoryPrepassStop::Budget(stop)) => return Ok(stop.into_outcome()),
        Err(JsTsInventoryPrepassStop::Cancelled) => return Ok(inventory.cancelled()),
    };
    Ok(inventory.complete(JsTsProcedureInventory {
        specs,
        lexical_bindings,
        callable_bindings,
    }))
}

/// Inventory the intentionally small exact subset of JavaScript closure
/// semantics: a nested callable may snapshot a direct parent's initialized
/// `const` binding, and a call may target a nested callable stored in one such
/// binding. Everything else remains an explicit capture or dispatch gap.
fn populate_lexical_capture_specs<'tree>(
    specs: &mut [ProcedureSpec<'tree>],
    source: &str,
    lexical_bindings: &JsTsLexicalBindingIndex,
    inventory: &mut ProcedureInventoryBuilder<'_>,
    cancellation: &CancellationToken,
) -> Result<HashMap<Range, LexicalCallableTarget>, JsTsInventoryPrepassStop> {
    let mut direct_locals = HashMap::<Range, DirectLocalBinding<'tree>>::default();
    let mut binding_owners = HashMap::<Range, ProcedureId>::default();
    for spec in specs.iter() {
        if let Some(parameters) = spec
            .callable
            .child_by_field_name("parameters")
            .or_else(|| spec.callable.child_by_field_name("parameter"))
        {
            try_walk_named_tree_preorder(parameters, true, |node| {
                charge_js_ts_inventory_prepass(inventory, cancellation)?;
                if node.kind() == "identifier"
                    && is_declaration_identifier(node)
                    && let Some(binding) = exact_binding_range(lexical_bindings, source, node)
                {
                    binding_owners.insert(binding, spec.id);
                }
                Ok(WalkControl::Continue)
            })?;
        }
        try_walk_named_tree_preorder(spec.body, true, |node| {
            charge_js_ts_inventory_prepass(inventory, cancellation)?;
            if is_js_ts_nested_execution_boundary(node, spec.body) {
                if matches!(
                    node.kind(),
                    "function_declaration" | "generator_function_declaration"
                ) && let Some(name) = node.child_by_field_name("name")
                    && let Some(binding) = exact_binding_range(lexical_bindings, source, name)
                {
                    binding_owners.insert(binding, spec.id);
                }
                return Ok(WalkControl::SkipChildren);
            }
            if node.kind() == "identifier"
                && is_declaration_identifier(node)
                && let Some(binding) = exact_binding_range(lexical_bindings, source, node)
            {
                binding_owners.insert(binding, spec.id);
                return Ok(WalkControl::Continue);
            }
            if node.kind() != "variable_declarator" {
                return Ok(WalkControl::Continue);
            }
            let Some(name) = node
                .child_by_field_name("name")
                .filter(|name| name.kind() == "identifier")
            else {
                return Ok(WalkControl::Continue);
            };
            let Some(text) = node_text(source, name) else {
                return Ok(WalkControl::Continue);
            };
            let active_ranges =
                lexical_bindings.binding_identifier_ranges_at(text, name.start_byte());
            let Some(binding) = active_ranges.iter().copied().find(|range| {
                range.start_byte == name.start_byte() && range.end_byte == name.end_byte()
            }) else {
                return Ok(WalkControl::Continue);
            };
            let stable = active_ranges.len() == 1
                && node.child_by_field_name("value").is_some()
                && node
                    .parent()
                    .is_some_and(|declaration| has_child_kind(declaration, "const"))
                && !lexical_bindings.is_binding_reassigned_at(text, name.start_byte());
            direct_locals.insert(
                binding,
                DirectLocalBinding {
                    owner: spec.id,
                    declarator: node,
                    stable,
                },
            );
            binding_owners.insert(binding, spec.id);
            Ok(WalkControl::Continue)
        })?;
    }

    let mut captures = vec![Vec::<LexicalCaptureSpec<'tree>>::new(); specs.len()];
    let mut omitted = vec![Vec::<LexicalCaptureSpec<'tree>>::new(); specs.len()];
    for child in specs.iter() {
        charge_js_ts_inventory_prepass(inventory, cancellation)?;
        let Some(parent) = child.lexical_parent else {
            continue;
        };
        let mut references = HashMap::<Range, Node<'tree>>::default();
        try_walk_named_tree_preorder(child.body, true, |node| {
            charge_js_ts_inventory_prepass(inventory, cancellation)?;
            if is_js_ts_nested_execution_boundary(node, child.body) {
                return Ok(WalkControl::SkipChildren);
            }
            if node.kind() != "identifier" || is_declaration_identifier(node) {
                return Ok(WalkControl::Continue);
            }
            let Some(name) = node_text(source, node) else {
                return Ok(WalkControl::Continue);
            };
            for binding in lexical_bindings.binding_identifier_ranges_at(name, node.start_byte()) {
                let Some(owner) = binding_owners.get(&binding) else {
                    continue;
                };
                if *owner != child.id {
                    references
                        .entry(binding)
                        .and_modify(|first| {
                            if node.start_byte() < first.start_byte() {
                                *first = node;
                            }
                        })
                        .or_insert(node);
                }
            }
            Ok(WalkControl::Continue)
        })?;

        for (binding, reference) in references {
            let capture = LexicalCaptureSpec { binding, reference };
            if direct_locals.get(&binding).is_some_and(|local| {
                local.owner == parent
                    && local.stable
                    && local.declarator.end_byte() <= child.callable.start_byte()
            }) {
                captures[child.id.index()].push(capture);
            } else {
                omitted[child.id.index()].push(capture);
            }
        }
        captures[child.id.index()].sort_by_key(|capture| capture.binding);
        omitted[child.id.index()].sort_by_key(|capture| capture.binding);
    }

    let mut callable_bindings = HashMap::default();
    for spec in specs.iter() {
        charge_js_ts_inventory_prepass(inventory, cancellation)?;
        if spec.properties.is_async
            || spec.properties.is_generator
            || !omitted[spec.id.index()].is_empty()
        {
            continue;
        }
        let Some(parent) = spec.lexical_parent else {
            continue;
        };
        let Some(declarator) = enclosing_variable_declarator(spec.callable) else {
            continue;
        };
        let Some(name) = declarator
            .child_by_field_name("name")
            .filter(|name| name.kind() == "identifier")
        else {
            continue;
        };
        let Some(text) = node_text(source, name) else {
            continue;
        };
        let active_ranges = lexical_bindings.binding_identifier_ranges_at(text, name.start_byte());
        let Some(binding) = active_ranges.iter().copied().find(|range| {
            range.start_byte == name.start_byte() && range.end_byte == name.end_byte()
        }) else {
            continue;
        };
        let Some(local) = direct_locals.get(&binding) else {
            continue;
        };
        if active_ranges.len() != 1
            || local.owner != parent
            || local.declarator.id() != declarator.id()
            || !local.stable
        {
            continue;
        }
        let previous = callable_bindings.insert(
            binding,
            LexicalCallableTarget {
                id: spec.id,
                available_after: declarator.end_byte(),
            },
        );
        debug_assert!(
            previous.is_none(),
            "one lexical binding has one const initializer"
        );
    }

    for ((spec, captures), omitted) in specs.iter_mut().zip(captures).zip(omitted) {
        charge_js_ts_inventory_prepass(inventory, cancellation)?;
        spec.captures = captures.into_boxed_slice();
        spec.omitted_captures = omitted.into_boxed_slice();
    }
    Ok(callable_bindings)
}

fn exact_binding_range(
    lexical_bindings: &JsTsLexicalBindingIndex,
    source: &str,
    node: Node<'_>,
) -> Option<Range> {
    let name = node_text(source, node)?;
    lexical_bindings
        .binding_identifier_ranges_at(name, node.start_byte())
        .into_iter()
        .find(|range| range.start_byte == node.start_byte() && range.end_byte == node.end_byte())
}

fn enclosing_variable_declarator(mut callable: Node<'_>) -> Option<Node<'_>> {
    loop {
        let parent = callable.parent()?;
        match parent.kind() {
            "parenthesized_expression"
            | "as_expression"
            | "satisfies_expression"
            | "non_null_expression"
            | "type_assertion" => {
                let expression = parent
                    .child_by_field_name("expression")
                    .or_else(|| first_named_child(parent))?;
                if expression.id() != callable.id() {
                    return None;
                }
                callable = parent;
            }
            "variable_declarator" => {
                return parent
                    .child_by_field_name("value")
                    .is_some_and(|value| value.id() == callable.id())
                    .then_some(parent);
            }
            _ => return None,
        }
    }
}
