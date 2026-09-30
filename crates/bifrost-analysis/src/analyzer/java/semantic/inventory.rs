use super::syntax::*;
use super::*;

#[derive(Clone)]
pub(super) struct ProcedureSpec<'tree> {
    pub(super) id: ProcedureId,
    pub(super) callable: Node<'tree>,
    pub(super) body: Node<'tree>,
    pub(super) locator: SemanticLocator,
    pub(super) lexical_parent: Option<ProcedureId>,
    pub(super) kind: ProcedureKind,
    pub(super) properties: ProcedureProperties,
    pub(super) captures_receiver: bool,
    pub(super) captures: Vec<JavaCaptureSpec<'tree>>,
    pub(super) captures_incomplete: bool,
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
pub(super) struct JavaCaptureSpec<'tree> {
    pub(super) binding: JavaLocalBindingSyntax<'tree>,
    pub(super) reference: Node<'tree>,
}

#[derive(Clone)]
pub(super) struct NestedProcedureTarget<'tree> {
    pub(super) id: ProcedureId,
    pub(super) receiver_capture_destination: Option<MemoryLocationId>,
    pub(super) captures: Vec<JavaCaptureSpec<'tree>>,
    pub(super) captures_incomplete: bool,
}

pub(super) type ProcedureEnumeration<'tree> = ProcedureInventoryOutcome<Vec<ProcedureSpec<'tree>>>;

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
    let root = prepared.tree().root_node();
    let mut inventory =
        ProcedureInventoryBuilder::new(file, prepared.dialect(), root, "java-source", budget)?;
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
            let name = declaration_container_name(prepared.source(), frame.node);
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
        if let Some((kind, segment_kind, body, properties)) = callable_shape(frame.node) {
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
            let captures_receiver = if kind == ProcedureKind::Lambda {
                match body_contains_free_this(body, cancellation) {
                    Ok(captures_receiver) => captures_receiver,
                    Err(LoweringCancelled) => return Ok(inventory.cancelled()),
                }
            } else {
                false
            };
            specs.push(ProcedureSpec {
                id: identity.id,
                callable: frame.node,
                body,
                locator: identity.locator,
                lexical_parent: frame.lexical_parent,
                kind,
                properties,
                captures_receiver,
                captures: Vec::new(),
                captures_incomplete: false,
            });
            child_parent = Some(identity.id);
            child_path = identity.declaration_path;
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

    match populate_lexical_captures(&mut specs, prepared.source(), &mut inventory, cancellation) {
        Ok(()) => {}
        Err(JavaCaptureInventoryStop::Budget(stop)) => return Ok(stop.into_outcome()),
        Err(JavaCaptureInventoryStop::Cancelled) => return Ok(inventory.cancelled()),
    }
    Ok(inventory.complete(specs))
}

enum JavaCaptureInventoryStop {
    Budget(ProcedureInventoryStop),
    Cancelled,
}

fn charge_capture_inventory(
    inventory: &mut ProcedureInventoryBuilder<'_>,
    cancellation: &CancellationToken,
) -> Result<(), JavaCaptureInventoryStop> {
    if cancellation.is_cancelled() {
        return Err(JavaCaptureInventoryStop::Cancelled);
    }
    inventory
        .charge_traversal_entry()
        .map_err(JavaCaptureInventoryStop::Budget)
}

fn populate_lexical_captures<'tree>(
    specs: &mut [ProcedureSpec<'tree>],
    source: &str,
    inventory: &mut ProcedureInventoryBuilder<'_>,
    cancellation: &CancellationToken,
) -> Result<(), JavaCaptureInventoryStop> {
    use crate::analyzer::lexical_definitions::{
        LexicalBindingResolution, resolve_lexical_binding_from_focus,
    };
    use brokk_bifrost_jvm::java::structural::java_pattern_binding_name;

    if !specs.iter().any(|spec| spec.kind == ProcedureKind::Lambda) {
        return Ok(());
    }
    let mut bindings = HashMap::default();
    let mut pattern_names = Vec::new();
    let mut writes = Vec::new();
    for spec in specs.iter() {
        charge_capture_inventory(inventory, cancellation)?;
        let mut names = HashSet::default();
        for (slot, node) in
            formal_parameter_slots_for_owner_with_nodes(Language::Java, spec.callable, source)
                .unwrap_or_default()
        {
            charge_capture_inventory(inventory, cancellation)?;
            if slot.receiver || slot.unique_name().is_none() {
                continue;
            }
            let name = node.child_by_field_name("name").unwrap_or(node);
            if name.kind() == "identifier" {
                bindings.insert(
                    (name.start_byte(), name.end_byte()),
                    (
                        spec.id,
                        JavaLocalBindingSyntax {
                            declaration: node,
                            name,
                            visible_from: spec.body.start_byte(),
                            scope_start: spec.body.start_byte(),
                            scope_end: spec.body.end_byte(),
                        },
                    ),
                );
            }
        }
        try_walk_named_tree_preorder(spec.body, true, |node| {
            charge_capture_inventory(inventory, cancellation)?;
            if is_java_nested_execution_boundary(node) {
                return Ok(WalkControl::SkipChildren);
            }
            if matches!(node.kind(), "assignment_expression" | "update_expression") {
                writes.push((spec.id, node));
            }
            if let Some(name) = java_pattern_binding_name(node) {
                names.insert(node_text(source, name).expect("pattern binder is source-backed"));
            }
            if let Some(binding) = java_local_binding(node) {
                bindings.insert(
                    (binding.name.start_byte(), binding.name.end_byte()),
                    (spec.id, binding),
                );
            }
            Ok(WalkControl::Continue)
        })?;
        pattern_names.push(names);
    }

    let mut binding_writes = HashMap::<(usize, usize), Vec<(ProcedureId, Node<'tree>)>>::default();
    for (owner, write) in writes {
        charge_capture_inventory(inventory, cancellation)?;
        let Some(mut target) = write
            .child_by_field_name("left")
            .or_else(|| first_named_child(write))
        else {
            continue;
        };
        while target.kind() == "parenthesized_expression" {
            charge_capture_inventory(inventory, cancellation)?;
            let Some(inner) = first_named_child(target) else {
                break;
            };
            target = inner;
        }
        if target.kind() != "identifier" {
            continue;
        }
        let name = node_text(source, target).expect("write target is source-backed");
        if let Some(resolution) = resolve_lexical_binding_from_focus(
            Language::Java,
            target,
            source,
            target.start_byte(),
            name,
        ) {
            let definition = match resolution {
                LexicalBindingResolution::Parameter(definition)
                | LexicalBindingResolution::OtherLocal(definition) => definition,
            };
            let key = (
                definition.name_range.start_byte,
                definition.name_range.end_byte,
            );
            binding_writes.entry(key).or_default().push((owner, write));
        }
    }
    let mut stable = HashSet::default();
    for (&key, &(owner, binding)) in &bindings {
        charge_capture_inventory(inventory, cancellation)?;
        let writes = binding_writes.get(&key).map_or(&[][..], Vec::as_slice);
        let initialized = binding.declaration.kind() != "variable_declarator"
            || binding.declaration.child_by_field_name("value").is_some();
        if initialized {
            if writes.is_empty() {
                stable.insert(key);
            }
            continue;
        }
        // A blank local with one simple establishment outside any loop that
        // reuses its declaration is also effectively final. Multiple branch
        // establishments require a definite-assignment proof and stay open.
        let [(writer, write)] = writes else { continue };
        if *writer != owner
            || !write
                .child_by_field_name("operator")
                .is_some_and(|op| op.kind() == "=")
        {
            continue;
        }
        let mut ancestor = write.parent();
        let mut repeats = false;
        while let Some(node) = ancestor {
            charge_capture_inventory(inventory, cancellation)?;
            if node == specs[owner.index()].callable {
                break;
            }
            if matches!(
                node.kind(),
                "while_statement" | "do_statement" | "for_statement" | "enhanced_for_statement"
            ) && node.child_by_field_name("body").is_none_or(|body| {
                binding.name.start_byte() < body.start_byte()
                    || binding.name.end_byte() > body.end_byte()
            }) {
                repeats = true;
                break;
            }
            ancestor = node.parent();
        }
        if !repeats {
            stable.insert(key);
        }
    }

    let mut captures = vec![HashMap::default(); specs.len()];
    let mut incomplete = vec![false; specs.len()];
    for spec in specs
        .iter()
        .filter(|spec| spec.kind == ProcedureKind::Lambda)
    {
        let mut stack = vec![spec.body];
        while let Some(node) = stack.pop() {
            charge_capture_inventory(inventory, cancellation)?;
            if is_java_nested_execution_boundary(node) {
                continue;
            }
            if node.kind() != "identifier" {
                stack.extend(runtime_expression_children(node));
                continue;
            }
            if node.parent().is_some_and(|parent| {
                parent.child_by_field_name("name") == Some(node)
                    || parent.child_by_field_name("field") == Some(node)
                    || matches!(
                        parent.kind(),
                        "break_statement" | "continue_statement" | "labeled_statement"
                    )
                    || (parent.kind() == "method_reference"
                        && first_named_child(parent) != Some(node))
            }) {
                continue;
            }
            let Some(name) = node_text(source, node) else {
                continue;
            };
            // The common lexical resolver deliberately omits Java pattern
            // binders. Do not accidentally bind such a name to an outer local.
            let mut ancestor = Some(spec.id);
            let mut pattern_open = false;
            while let Some(id) = ancestor {
                charge_capture_inventory(inventory, cancellation)?;
                if pattern_names[id.index()].contains(name) {
                    pattern_open = true;
                }
                ancestor = specs[id.index()].lexical_parent;
            }
            if pattern_open {
                incomplete[spec.id.index()] = true;
                continue;
            }
            let Some(resolution) = resolve_lexical_binding_from_focus(
                Language::Java,
                node,
                source,
                node.start_byte(),
                name,
            ) else {
                continue;
            };
            let definition = match resolution {
                LexicalBindingResolution::Parameter(definition)
                | LexicalBindingResolution::OtherLocal(definition) => definition,
            };
            let key = (
                definition.name_range.start_byte,
                definition.name_range.end_byte,
            );
            let Some((owner, binding)) = bindings.get(&key).copied() else {
                incomplete[spec.id.index()] = true;
                continue;
            };
            if owner == spec.id {
                continue;
            }
            let mut relay = spec.id;
            let mut path = Vec::new();
            while relay != owner {
                charge_capture_inventory(inventory, cancellation)?;
                let relay_spec = &specs[relay.index()];
                if relay_spec.kind != ProcedureKind::Lambda {
                    break;
                }
                path.push(relay);
                let Some(parent) = relay_spec.lexical_parent else {
                    break;
                };
                relay = parent;
            }
            if relay != owner
                || !stable.contains(&key)
                || binding.visible_from > spec.callable.start_byte()
                || binding.scope_start > node.start_byte()
                || node.end_byte() > binding.scope_end
            {
                for id in path {
                    incomplete[id.index()] = true;
                }
                incomplete[spec.id.index()] = true;
                continue;
            }
            let mut reference = node;
            for id in path {
                captures[id.index()]
                    .entry(key)
                    .or_insert(JavaCaptureSpec { binding, reference });
                reference = specs[id.index()].callable;
            }
        }
    }
    // An incomplete child inventory also limits its parent's construction
    // effects; never turn a missing relay into a clean outer procedure.
    for index in (0..specs.len()).rev() {
        if incomplete[index]
            && specs[index].kind == ProcedureKind::Lambda
            && let Some(parent) = specs[index].lexical_parent
            && specs[parent.index()].kind == ProcedureKind::Lambda
        {
            incomplete[parent.index()] = true;
        }
    }
    for (index, spec) in specs.iter_mut().enumerate() {
        spec.captures = captures[index]
            .drain()
            .map(|(_, capture)| capture)
            .collect();
        spec.captures
            .sort_by_key(|capture| capture.binding.name.start_byte());
        spec.captures_incomplete = incomplete[index];
    }
    Ok(())
}
