use crate::analyzer::java::semantic::syntax::*;

use crate::analyzer::java::semantic::*;

#[derive(Clone)]
pub(in crate::analyzer::java::semantic) struct ProcedureSpec<'tree> {
    pub(in crate::analyzer::java::semantic) id: ProcedureId,
    pub(in crate::analyzer::java::semantic) callable: Node<'tree>,
    pub(in crate::analyzer::java::semantic) body: Node<'tree>,
    pub(in crate::analyzer::java::semantic) locator: SemanticLocator,
    pub(in crate::analyzer::java::semantic) lexical_parent: Option<ProcedureId>,
    pub(in crate::analyzer::java::semantic) kind: ProcedureKind,
    pub(in crate::analyzer::java::semantic) properties: ProcedureProperties,
    pub(in crate::analyzer::java::semantic) captures_receiver: bool,
    pub(in crate::analyzer::java::semantic) captures: Vec<JavaCaptureSpec<'tree>>,
    pub(in crate::analyzer::java::semantic) captures_incomplete: bool,
}

impl ReceiverCaptureSpec for ProcedureSpec<'_> {
    fn lexical_parent(&self) -> Option<ProcedureId> {
        self.lexical_parent
    }

    fn relays_receiver_capture(&self) -> bool {
        brokk_bifrost_analysis::analyzer::semantic::procedure_relays_receiver_capture(self.kind)
    }

    fn captures_receiver(&self) -> bool {
        self.captures_receiver
    }

    fn captures_receiver_mut(&mut self) -> &mut bool {
        &mut self.captures_receiver
    }
}

#[derive(Clone, Copy)]
pub(in crate::analyzer::java::semantic) struct JavaCaptureSpec<'tree> {
    pub(in crate::analyzer::java::semantic) binding: JavaLocalBindingSyntax<'tree>,
    pub(in crate::analyzer::java::semantic) reference: Node<'tree>,
}

#[derive(Clone)]
pub(in crate::analyzer::java::semantic) struct NestedProcedureTarget<'tree> {
    pub(in crate::analyzer::java::semantic) id: ProcedureId,
    pub(in crate::analyzer::java::semantic) receiver_capture_destination: Option<MemoryLocationId>,
    pub(in crate::analyzer::java::semantic) captures: Vec<JavaCaptureSpec<'tree>>,
    pub(in crate::analyzer::java::semantic) captures_incomplete: bool,
}

pub(in crate::analyzer::java::semantic) type ProcedureEnumeration<'tree> =
    ProcedureInventoryOutcome<Vec<ProcedureSpec<'tree>>>;

struct ProcedureEnumerationFrame<'tree> {
    node: Node<'tree>,
    lexical_parent: Option<ProcedureId>,
    declaration_path: usize,
}

pub(in crate::analyzer::java::semantic) fn enumerate_procedures<'tree>(
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

use brokk_bifrost_analysis::analyzer::semantic::inventory::ProcedureInventoryPrepassStop as JavaCaptureInventoryStop;

fn charge_capture_inventory(
    inventory: &mut ProcedureInventoryBuilder<'_>,
    cancellation: &CancellationToken,
) -> Result<(), JavaCaptureInventoryStop> {
    brokk_bifrost_analysis::analyzer::semantic::inventory::charge_prepass(inventory, cancellation)
}

fn populate_lexical_captures<'tree>(
    specs: &mut [ProcedureSpec<'tree>],
    source: &str,
    inventory: &mut ProcedureInventoryBuilder<'_>,
    cancellation: &CancellationToken,
) -> Result<(), JavaCaptureInventoryStop> {
    use brokk_bifrost_analysis::analyzer::lexical_definitions::LexicalBindingResolution;

    use brokk_bifrost_analysis::analyzer::lexical_definitions::resolve_lexical_binding_from_focus;
    use brokk_bifrost_analysis::analyzer::lexical_definitions::resolve_lexical_binding_from_focus_with_visibility;

    if !specs.iter().any(|spec| spec.kind == ProcedureKind::Lambda) {
        return Ok(());
    }
    let mut bindings = HashMap::default();
    let mut writes = Vec::new();
    for spec in specs.iter() {
        charge_capture_inventory(inventory, cancellation)?;
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
            if let Some(binding) = java_local_binding(node) {
                bindings.insert(
                    (binding.name.start_byte(), binding.name.end_byte()),
                    (spec.id, binding),
                );
            }
            Ok(WalkControl::Continue)
        })?;
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
            let resolution = match resolve_lexical_binding_from_focus_with_visibility(
                Language::Java,
                node,
                source,
                node.start_byte(),
                name,
            ) {
                Ok(Some(resolution)) => resolution,
                Ok(None) => continue,
                Err(_) => {
                    incomplete[spec.id.index()] = true;
                    continue;
                }
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
            if brokk_bifrost_jvm::java::structural::java_pattern_binding_name(binding.declaration)
                .is_some()
                && !java_pattern_has_value(binding.declaration)
            {
                incomplete[spec.id.index()] = true;
                continue;
            }
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
