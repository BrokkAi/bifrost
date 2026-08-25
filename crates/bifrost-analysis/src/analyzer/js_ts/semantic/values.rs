use super::syntax::*;
use super::*;

impl<'tree, 'targets> LoweringContext<'tree, 'targets> {
    pub(super) fn emit_captured_receiver(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        spec: &ProcedureSpec<'tree>,
        capture_binding_expected: bool,
    ) -> Result<(), TsLoweringError> {
        let Some(lexical_parent) = spec.lexical_parent.filter(|_| spec.captures_receiver) else {
            return Ok(());
        };
        let metadata = self.value_mapping(builder, spec.callable)?;
        let (value, location) =
            self.session
                .add_receiver_capture_input(builder, entry, metadata, lexical_parent)?;
        if !capture_binding_expected {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::MemoryLocation(location),
                SemanticCapability::Captures,
                SemanticGapKind::Unsupported,
                "lexical receiver capture source is not represented by the parent procedure",
            )?;
        }
        self.captured_receiver = Some(value);
        Ok(())
    }

    pub(super) fn emit_local_bindings(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        body: Node<'tree>,
    ) -> Result<(), TsLoweringError> {
        try_walk_named_tree_preorder(body, true, |node| {
            if self.session.cancellation().is_cancelled() {
                return Err(TsLoweringError::Cancelled(Box::new(
                    builder.prospective_work(),
                )));
            }
            if is_js_ts_nested_execution_boundary(node, body) {
                return Ok(WalkControl::SkipChildren);
            }
            if node.kind() == "variable_declarator"
                && let Some(name) = node.child_by_field_name("name")
                && name.kind() == "identifier"
                && let Some(text) = node_text(self.prepared.source(), name)
                && let Some((scope_start, scope_end)) = js_ts_local_scope(node)
            {
                if self.locals.get(text).is_some_and(|bindings| {
                    bindings.iter().any(|binding| {
                        binding.scope_start == scope_start && binding.scope_end == scope_end
                    })
                }) {
                    return Ok(WalkControl::SkipChildren);
                }
                let metadata = self.value_mapping(builder, name)?;
                let value = self.session.add_value_with_metadata(
                    builder,
                    metadata,
                    SemanticValueKind::Local,
                )?;
                self.locals
                    .entry(text.into())
                    .or_default()
                    .push(LocalBinding {
                        scope_start,
                        scope_end,
                        value,
                    });
            }
            Ok(WalkControl::Continue)
        })
    }

    /// Identify locals that hold a proven allocation for their whole extent,
    /// so field accesses on them can be lowered without capability gaps.
    /// Runs after [`Self::emit_local_bindings`] so `local_at` resolves.
    ///
    /// A candidate is a declarator whose initializer is a plain object
    /// literal or a proven unshadowed built-in `Error` allocation.
    /// Allocation-rooted aliases are retained when their only uses are
    /// further aliases, direct throws, or non-`__proto__` member accesses
    /// outside call-callee position. A rebind, subscript base, shorthand
    /// property, nested capture, or any other unrecognized use invalidates the
    /// whole allocation root.
    ///
    /// A plain whole-value call argument is the one use that neither proves
    /// nor invalidates: it names no member, so it cannot retract the identity
    /// of an access that already ran, and it hands the object to a callee, so
    /// it records an `escapes_after` bound for the accesses that follow it.
    pub(super) fn collect_plain_object_locals(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        body: Node<'tree>,
    ) -> Result<(), TsLoweringError> {
        #[derive(Clone, Copy)]
        struct Candidate {
            root: ValueId,
            declaration_parent: usize,
            available_after: usize,
        }
        let source = self.prepared.source();
        let mut candidates: HashMap<ValueId, Candidate> = HashMap::default();
        let mut field_locators: HashMap<ValueId, HashMap<Box<str>, SemanticLocator>> =
            HashMap::default();
        try_walk_named_tree_preorder(body, true, |node| {
            if self.session.cancellation().is_cancelled() {
                return Err(TsLoweringError::Cancelled(Box::new(
                    builder.prospective_work(),
                )));
            }
            if is_js_ts_nested_execution_boundary(node, body) {
                return Ok(WalkControl::SkipChildren);
            }
            if node.kind() == "variable_declarator"
                && let Some(name) = node.child_by_field_name("name")
                && name.kind() == "identifier"
                && let Some(initializer) = node.child_by_field_name("value")
                && (is_plain_object_literal(source, initializer)
                    || (self.is_proven_error_constructor(initializer)
                        && self.is_statically_nothrow_error_constructor(initializer)))
                && let Some(text) = node_text(source, name)
                && let Some(value) = self.local_at(text, name.start_byte())
                && let Some(declaration_parent) =
                    node.parent().and_then(|declaration| declaration.parent())
            {
                candidates.entry(value).or_insert(Candidate {
                    root: value,
                    declaration_parent: declaration_parent.id(),
                    available_after: node.end_byte(),
                });
                let fields = field_locators.entry(value).or_default();
                for member in named_children(initializer) {
                    let Some(key) = member.child_by_field_name("key") else {
                        continue;
                    };
                    let Some(field) = stable_member_key(source, key) else {
                        continue;
                    };
                    fields
                        .entry(field)
                        .or_insert(self.memory_member_locator(key)?);
                }
            }
            Ok(WalkControl::Continue)
        })?;
        if candidates.is_empty() {
            return Ok(());
        }

        // A local alias is a structured assignment edge to another local. Add
        // aliases iteratively so a chain can retain the same allocation root,
        // while keeping the declaration point of each alias for dominance.
        let mut aliases = Vec::new();
        try_walk_named_tree_preorder(body, true, |node| {
            if self.session.cancellation().is_cancelled() {
                return Err(TsLoweringError::Cancelled(Box::new(
                    builder.prospective_work(),
                )));
            }
            if is_js_ts_nested_execution_boundary(node, body) {
                return Ok(WalkControl::SkipChildren);
            }
            let (target, value) = match node.kind() {
                "variable_declarator" => (
                    node.child_by_field_name("name"),
                    node.child_by_field_name("value"),
                ),
                "assignment_expression" => (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ),
                _ => (None, None),
            };
            if let (Some(target), Some(value)) = (target, value)
                && target.kind() == "identifier"
                && value.kind() == "identifier"
                && let (Some(target_name), Some(value_name)) =
                    (node_text(source, target), node_text(source, value))
                && let (Some(target_value), Some(value_value)) = (
                    self.local_at(target_name, target.start_byte()),
                    self.local_at(value_name, value.start_byte()),
                )
            {
                aliases.push((
                    target_value,
                    value_value,
                    node.parent()
                        .and_then(|parent| parent.parent())
                        .unwrap_or(node)
                        .id(),
                    node.end_byte(),
                ));
            }
            Ok(WalkControl::Continue)
        })?;
        for _ in 0..=aliases.len() {
            let mut changed = false;
            for &(target, value, declaration_parent, available_after) in &aliases {
                let Some(source_candidate) = candidates.get(&value).copied() else {
                    continue;
                };
                if candidates.contains_key(&target) {
                    continue;
                }
                candidates.insert(
                    target,
                    Candidate {
                        root: source_candidate.root,
                        declaration_parent,
                        available_after,
                    },
                );
                changed = true;
            }
            if !changed {
                break;
            }
        }

        // Occurrence scan over the full body, nested procedures included: a
        // capture invalidates the candidate exactly like a local escape does.
        let mut invalid_roots = HashSet::default();
        let mut escapes: HashMap<ValueId, usize> = HashMap::default();
        let mut boundary_ends: Vec<usize> = Vec::new();
        try_walk_named_tree_preorder(body, true, |node| {
            if self.session.cancellation().is_cancelled() {
                return Err(TsLoweringError::Cancelled(Box::new(
                    builder.prospective_work(),
                )));
            }
            while boundary_ends
                .last()
                .is_some_and(|end| node.start_byte() >= *end)
            {
                boundary_ends.pop();
            }
            let inside_nested = !boundary_ends.is_empty();
            if is_js_ts_nested_execution_boundary(node, body) {
                boundary_ends.push(node.end_byte());
            }
            if !matches!(
                node.kind(),
                "identifier"
                    | "shorthand_property_identifier"
                    | "shorthand_property_identifier_pattern"
            ) {
                return Ok(WalkControl::Continue);
            }
            let Some(text) = node_text(source, node) else {
                return Ok(WalkControl::Continue);
            };
            let Some(value) = self.local_at(text, node.start_byte()) else {
                return Ok(WalkControl::Continue);
            };
            let Some(candidate) = candidates.get(&value) else {
                return Ok(WalkControl::Continue);
            };
            let alias_use = allocation_alias_use(node).is_some_and(|(target, value)| {
                let target_name = node_text(source, target);
                let value_name = node_text(source, value);
                let target_value =
                    target_name.and_then(|name| self.local_at(name, target.start_byte()));
                let value_value =
                    value_name.and_then(|name| self.local_at(name, value.start_byte()));
                target_value
                    .zip(value_value)
                    .and_then(|(target, value)| {
                        candidates
                            .get(&target)
                            .zip(candidates.get(&value))
                            .filter(|(target, value)| target.root == value.root)
                    })
                    .is_some()
            });
            // A whole-value argument names no member of the allocation, so it
            // leaves the object's member identity intact and must not open a
            // member-resolution gap on the stores that already ran. It is
            // still an escape: the callee holds the object and may install an
            // accessor or a proxy on it, so it bounds every later access
            // through `escapes_after` instead of invalidating the root.
            let whole_value_argument = !inside_nested
                && is_whole_value_call_argument(node)
                && executes_once_within(node, candidate.declaration_parent);
            if whole_value_argument {
                let escape = escapes.entry(candidate.root).or_insert(node.start_byte());
                *escape = (*escape).min(node.start_byte());
                return Ok(WalkControl::Continue);
            }
            let survives = !inside_nested
                && (is_variable_binding_name(node)
                    || plain_member_base_use(source, node)
                    || alias_use
                    || is_direct_throw_value(node));
            if !survives {
                invalid_roots.insert(candidate.root);
            }
            Ok(WalkControl::Continue)
        })?;
        candidates.retain(|_, candidate| !invalid_roots.contains(&candidate.root));
        field_locators.retain(|root, _| !invalid_roots.contains(root));
        self.plain_object_locals = candidates
            .into_iter()
            .map(|(value, candidate)| {
                (
                    value,
                    PlainObjectLocal {
                        root: candidate.root,
                        declaration_parent: candidate.declaration_parent,
                        available_after: candidate.available_after,
                        escapes_after: escapes.get(&candidate.root).copied(),
                    },
                )
            })
            .collect();
        self.plain_object_fields = field_locators;
        Ok(())
    }

    /// Identify local array-literal allocations whose indexed identity can be
    /// proved from this procedure alone. Only declaration aliases and
    /// nonnegative decimal constant subscripts are retained, plus the
    /// whole-value call argument the plain-object scan admits on the same
    /// terms. Every other occurrence invalidates the allocation root, so a
    /// later constant access cannot accidentally turn an incomplete heap path
    /// into a clean one.
    pub(super) fn collect_array_locals(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        body: Node<'tree>,
    ) -> Result<(), TsLoweringError> {
        #[derive(Clone, Copy)]
        struct Candidate {
            root: ValueId,
            declaration_parent: usize,
            available_after: usize,
        }

        let source = self.prepared.source();
        let mut candidates: HashMap<ValueId, Candidate> = HashMap::default();
        try_walk_named_tree_preorder(body, true, |node| {
            if self.session.cancellation().is_cancelled() {
                return Err(TsLoweringError::Cancelled(Box::new(
                    builder.prospective_work(),
                )));
            }
            if is_js_ts_nested_execution_boundary(node, body) {
                return Ok(WalkControl::SkipChildren);
            }
            if node.kind() == "variable_declarator"
                && let Some(name) = node.child_by_field_name("name")
                && name.kind() == "identifier"
                && let Some(initializer) = node.child_by_field_name("value")
                && initializer.kind() == "array"
                && let Some(text) = node_text(source, name)
                && let Some(value) = self.local_at(text, name.start_byte())
                && let Some(declaration_parent) =
                    node.parent().and_then(|declaration| declaration.parent())
            {
                candidates.entry(value).or_insert(Candidate {
                    root: value,
                    declaration_parent: declaration_parent.id(),
                    available_after: node.end_byte(),
                });
            }
            Ok(WalkControl::Continue)
        })?;
        if candidates.is_empty() {
            return Ok(());
        }

        // Declaration aliases are the only aliasing channel that does not
        // rebind an already-live local. Assignment aliases are deliberately
        // excluded, because they can execute after an earlier access.
        let mut aliases = Vec::new();
        try_walk_named_tree_preorder(body, true, |node| {
            if self.session.cancellation().is_cancelled() {
                return Err(TsLoweringError::Cancelled(Box::new(
                    builder.prospective_work(),
                )));
            }
            if is_js_ts_nested_execution_boundary(node, body) {
                return Ok(WalkControl::SkipChildren);
            }
            if node.kind() == "variable_declarator"
                && let (Some(target), Some(value)) = (
                    node.child_by_field_name("name"),
                    node.child_by_field_name("value"),
                )
                && target.kind() == "identifier"
                && value.kind() == "identifier"
                && let (Some(target_name), Some(value_name)) =
                    (node_text(source, target), node_text(source, value))
                && let (Some(target_value), Some(value_value)) = (
                    self.local_at(target_name, target.start_byte()),
                    self.local_at(value_name, value.start_byte()),
                )
            {
                aliases.push((
                    target_value,
                    value_value,
                    node.parent()
                        .and_then(|parent| parent.parent())
                        .unwrap_or(node)
                        .id(),
                    node.end_byte(),
                ));
            }
            Ok(WalkControl::Continue)
        })?;
        for _ in 0..=aliases.len() {
            let mut changed = false;
            for &(target, value, declaration_parent, available_after) in &aliases {
                let Some(source_candidate) = candidates.get(&value).copied() else {
                    continue;
                };
                if candidates.contains_key(&target) {
                    continue;
                }
                candidates.insert(
                    target,
                    Candidate {
                        root: source_candidate.root,
                        declaration_parent,
                        available_after,
                    },
                );
                changed = true;
            }
            if !changed {
                break;
            }
        }

        let mut invalid_roots = HashSet::default();
        let mut escapes: HashMap<ValueId, usize> = HashMap::default();
        let mut boundary_ends = Vec::new();
        try_walk_named_tree_preorder(body, true, |node| {
            if self.session.cancellation().is_cancelled() {
                return Err(TsLoweringError::Cancelled(Box::new(
                    builder.prospective_work(),
                )));
            }
            while boundary_ends
                .last()
                .is_some_and(|end| node.start_byte() >= *end)
            {
                boundary_ends.pop();
            }
            let inside_nested = !boundary_ends.is_empty();
            if is_js_ts_nested_execution_boundary(node, body) {
                boundary_ends.push(node.end_byte());
            }
            if !matches!(
                node.kind(),
                "identifier"
                    | "shorthand_property_identifier"
                    | "shorthand_property_identifier_pattern"
            ) {
                return Ok(WalkControl::Continue);
            }
            let Some(text) = node_text(source, node) else {
                return Ok(WalkControl::Continue);
            };
            let Some(value) = self.local_at(text, node.start_byte()) else {
                return Ok(WalkControl::Continue);
            };
            let Some(candidate) = candidates.get(&value) else {
                return Ok(WalkControl::Continue);
            };
            let supported_index = array_subscript_base_use(node)
                .and_then(|index| constant_array_index(source, index))
                .is_some();
            let alias_use = array_alias_use(node).is_some_and(|(target, source_node)| {
                let target_value = node_text(source, target)
                    .and_then(|name| self.local_at(name, target.start_byte()));
                let source_value = node_text(source, source_node)
                    .and_then(|name| self.local_at(name, source_node.start_byte()));
                target_value
                    .zip(source_value)
                    .and_then(|(target, source)| {
                        candidates
                            .get(&target)
                            .zip(candidates.get(&source))
                            .filter(|(target, source)| target.root == source.root)
                    })
                    .is_some()
            });
            // The same whole-value rule the plain-object scan applies: an
            // argument that names no element bounds later accesses instead of
            // invalidating the allocation root.
            let whole_value_argument = !inside_nested
                && is_whole_value_call_argument(node)
                && executes_once_within(node, candidate.declaration_parent);
            if whole_value_argument {
                let escape = escapes.entry(candidate.root).or_insert(node.start_byte());
                *escape = (*escape).min(node.start_byte());
                return Ok(WalkControl::Continue);
            }
            let survives =
                !inside_nested && (is_variable_binding_name(node) || supported_index || alias_use);
            if !survives {
                invalid_roots.insert(candidate.root);
            }
            Ok(WalkControl::Continue)
        })?;
        candidates.retain(|_, candidate| !invalid_roots.contains(&candidate.root));
        self.array_locals = candidates
            .into_iter()
            .map(|(value, candidate)| {
                (
                    value,
                    ArrayLocal {
                        declaration_parent: candidate.declaration_parent,
                        available_after: candidate.available_after,
                        escapes_after: escapes.get(&candidate.root).copied(),
                    },
                )
            })
            .collect();
        Ok(())
    }

    /// Whether `access` is a field access whose base identifier resolves to a
    /// plain object local and executes only after the declarator has run and
    /// before any whole-value consumption of the allocation: the declaration
    /// statement's parent must be an ancestor of the access, the access must
    /// start after the declarator ends, so no path reaches the access without
    /// establishing the binding first, and it must end before the first byte
    /// at which a callee could hold the object.
    pub(super) fn established_plain_object_base(
        &self,
        access: Node<'tree>,
        object: Node<'tree>,
    ) -> bool {
        if object.kind() != "identifier" {
            return false;
        }
        let Some(name) = node_text(self.prepared.source(), object) else {
            return false;
        };
        let Some(value) = self.local_at(name, object.start_byte()) else {
            return false;
        };
        let Some(plain) = self.plain_object_locals.get(&value) else {
            return false;
        };
        if access.start_byte() < plain.available_after {
            return false;
        }
        if plain
            .escapes_after
            .is_some_and(|escape| access.end_byte() > escape)
        {
            return false;
        }
        let mut current = access.parent();
        while let Some(node) = current {
            if node.id() == plain.declaration_parent {
                return true;
            }
            current = node.parent();
        }
        false
    }

    /// A direct throw preserves the identity of a proven local allocation.
    /// The throw carrier receives that identity before an ordinary catch
    /// binder is populated, so field accesses after the catch can reuse the
    /// allocation's established member locators.
    pub(super) fn transfer_plain_object_identity_from_node(
        &mut self,
        node: Node<'tree>,
        target: ValueId,
    ) {
        if node.kind() != "identifier" {
            return;
        }
        let Some(name) = node_text(self.prepared.source(), node) else {
            return;
        };
        let Some(source) = self.local_at(name, node.start_byte()) else {
            return;
        };
        self.transfer_plain_object_identity(source, target);
    }

    pub(super) fn transfer_plain_object_identity(&mut self, source: ValueId, target: ValueId) {
        if let Some(mut identity) = self.plain_object_locals.get(&source).copied() {
            if let Some((declaration_parent, available_after)) =
                self.catch_binder_scopes.get(&target).copied()
            {
                identity.declaration_parent = declaration_parent;
                identity.available_after = available_after;
            }
            self.plain_object_locals.insert(target, identity);
        }
    }

    pub(super) fn established_array_base(
        &self,
        access: Node<'tree>,
        object: Node<'tree>,
        index: Node<'tree>,
    ) -> bool {
        if object.kind() != "identifier"
            || constant_array_index(self.prepared.source(), index).is_none()
        {
            return false;
        }
        let Some(name) = node_text(self.prepared.source(), object) else {
            return false;
        };
        let Some(value) = self.local_at(name, object.start_byte()) else {
            return false;
        };
        let Some(array) = self.array_locals.get(&value) else {
            return false;
        };
        if access.start_byte() < array.available_after {
            return false;
        }
        if array
            .escapes_after
            .is_some_and(|escape| access.end_byte() > escape)
        {
            return false;
        }
        let mut current = access.parent();
        while let Some(node) = current {
            if node.id() == array.declaration_parent {
                return true;
            }
            current = node.parent();
        }
        false
    }

    pub(super) fn plain_object_member_locator(
        &mut self,
        object: Node<'tree>,
        property: Node<'tree>,
    ) -> Result<SemanticLocator, TsLoweringError> {
        let Some(name) = node_text(self.prepared.source(), object) else {
            return self.memory_member_locator(property);
        };
        let Some(value) = self.local_at(name, object.start_byte()) else {
            return self.memory_member_locator(property);
        };
        let Some(plain) = self.plain_object_locals.get(&value) else {
            return self.memory_member_locator(property);
        };
        let Some(field) = stable_member_key(self.prepared.source(), property) else {
            return self.memory_member_locator(property);
        };
        if let Some(locator) = self
            .plain_object_fields
            .get(&plain.root)
            .and_then(|fields| fields.get(&field))
        {
            return Ok(locator.clone());
        }
        let locator = self.memory_member_locator(property)?;
        self.plain_object_fields
            .entry(plain.root)
            .or_default()
            .insert(field, locator.clone());
        Ok(locator)
    }

    pub(super) fn local_at(&self, name: &str, byte: usize) -> Option<ValueId> {
        self.locals
            .get(name)?
            .iter()
            .filter(|binding| binding.scope_start <= byte && byte < binding.scope_end)
            .min_by_key(|binding| binding.scope_end - binding.scope_start)
            .map(|binding| binding.value)
    }

    pub(super) fn emit_procedure_inputs(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        spec: &ProcedureSpec<'tree>,
    ) -> Result<(), TsLoweringError> {
        let callable = spec.callable;
        let declaration_range = node_range(callable);
        let layout = if spec.kind == ProcedureKind::Initializer {
            Default::default()
        } else {
            formal_parameter_slots(
                self.prepared.dialect().language(),
                self.prepared.tree().root_node(),
                self.prepared.source(),
                &declaration_range,
            )
            .unwrap_or_default()
        };
        let mut ordinal = 0_u32;
        for slot in layout.slots {
            let node = callable
                .named_descendant_for_byte_range(
                    slot.declaration_range.start_byte,
                    slot.declaration_range.end_byte,
                )
                .unwrap_or(callable);
            let metadata = self.value_mapping(builder, node)?;
            let receiver_slot = slot.receiver || slot.names.iter().any(|name| name == "this");
            if receiver_slot {
                let receiver = self.session.add_value_with_metadata(
                    builder,
                    metadata,
                    SemanticValueKind::Receiver { dispatch: true },
                )?;
                self.receiver = Some(receiver);
            } else {
                let parameter = self.session.add_value_with_metadata(
                    builder,
                    metadata,
                    SemanticValueKind::Parameter {
                        ordinal,
                        multiplicity: formal_multiplicity(slot.variadic),
                    },
                )?;
                for name in slot.names {
                    self.parameters.insert(name.into_boxed_str(), parameter);
                }
                ordinal = ordinal
                    .checked_add(1)
                    .ok_or_else(|| TsLoweringError::Invalid("too many formal parameters".into()))?;
            }
        }

        if self.receiver.is_none() && spec.owns_receiver {
            let metadata = self.value_mapping(builder, callable)?;
            self.receiver = Some(self.session.add_value_with_metadata(
                builder,
                metadata,
                SemanticValueKind::Receiver { dispatch: true },
            )?);
        }
        Ok(())
    }

    pub(super) fn expression_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        kind: SemanticValueKind,
    ) -> Result<ValueId, TsLoweringError> {
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

    /// Reuse one procedure-local value for each structurally constant decimal
    /// array index. Dynamic, string, and noncanonical numeric expressions
    /// intentionally retain their own values, so their access paths remain
    /// incomplete.
    pub(super) fn index_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<ValueId, TsLoweringError> {
        let Some(index) = constant_array_index(self.prepared.source(), node) else {
            return self.expression_value(builder, node, expression_value_kind(node));
        };
        if let Some(value) = self.constant_index_values.get(&index) {
            self.expression_values.insert(node.id(), *value);
            return Ok(*value);
        }
        let value = self.expression_value(builder, node, SemanticValueKind::Constant)?;
        self.constant_index_values.insert(index, value);
        Ok(value)
    }

    pub(super) fn emit_lexical_input_flow(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        point: ProgramPointId,
        target: ValueId,
    ) -> Result<(), TsLoweringError> {
        let source = if node.kind() == "this" {
            self.captured_receiver
                .map(|source| (source, ValueFlowKind::Local))
                .or_else(|| {
                    self.receiver
                        .map(|source| (source, ValueFlowKind::Receiver))
                })
        } else if node.kind() == "identifier" {
            let name = node_text(self.prepared.source(), node);
            name.and_then(|name| {
                self.local_at(name, node.start_byte())
                    .map(|source| (source, ValueFlowKind::Local))
                    .or_else(|| {
                        self.parameters
                            .get(name)
                            .copied()
                            .map(|source| (source, ValueFlowKind::Parameter))
                    })
            })
        } else {
            None
        };
        if let Some((source, kind)) = source
            && source != target
        {
            // The read is spelled by the identifier occurrence itself. `point`
            // is whatever entry the enclosing evaluation scheduled this
            // expression at -- for a `return` argument that is the statement
            // point -- so the event carries its own identifier-anchored
            // mapping instead of inheriting the point's (#2014).
            let metadata = self.session.add_node_mapping(builder, node)?;
            self.session.append_effect_with_metadata(
                builder,
                point,
                metadata,
                SemanticEffect::ValueFlow {
                    kind,
                    source,
                    target,
                },
            )?;
        }
        Ok(())
    }

    pub(super) fn resolution_gaps(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        callee: ValueId,
        call_site: CallSiteId,
        resolution: &CallableTargetResolution,
    ) -> Result<(), TsLoweringError> {
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

    pub(super) fn point(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        effects: Vec<SemanticEffect>,
    ) -> Result<ProgramPointId, TsLoweringError> {
        let metadata = self.mapping(builder, node)?;
        self.session.add_point(builder, metadata, effects)
    }

    pub(super) fn mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<PointMetadata, TsLoweringError> {
        self.session.add_node_mapping(builder, node)
    }

    fn value_mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<PointMetadata, TsLoweringError> {
        let anchor = source_anchor(node, 0).map_err(TsLoweringError::Invalid)?;
        self.session
            .add_mapping(builder, anchor, SourceMappingKind::Exact)
    }

    pub(super) fn memory_member_locator(
        &self,
        node: Node<'tree>,
    ) -> Result<SemanticLocator, TsLoweringError> {
        let procedure = self.session.locator();
        let anchor = source_anchor(node, 0).map_err(TsLoweringError::Invalid)?;
        Ok(SemanticLocator::new(
            procedure.mount(),
            procedure.path().clone(),
            procedure.language(),
            procedure.declaration().clone(),
            SemanticRole::MemoryLocation,
            anchor,
        ))
    }

    pub(super) fn add_field_identity_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        location: MemoryLocationId,
    ) -> Result<(), TsLoweringError> {
        self.session.add_gap_with_impacts(
            builder,
            point,
            SemanticGapSubject::MemoryLocation(location),
            SemanticCapability::FieldMemory,
            SemanticGapImpacts::single(SemanticGapImpact::HeapRead)
                .with(SemanticGapImpact::HeapWrite)
                .with(SemanticGapImpact::Aliasing),
            SemanticGapKind::Unknown,
            "field occurrence is structured, but its declaration identity is not yet resolved",
        )?;
        Ok(())
    }

    pub(super) fn add_index_identity_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        location: MemoryLocationId,
    ) -> Result<(), TsLoweringError> {
        self.session.add_gap_with_impacts(
            builder,
            point,
            SemanticGapSubject::MemoryLocation(location),
            SemanticCapability::IndexMemory,
            SemanticGapImpacts::single(SemanticGapImpact::HeapRead)
                .with(SemanticGapImpact::HeapWrite)
                .with(SemanticGapImpact::Aliasing),
            SemanticGapKind::Unknown,
            "array index is structured, but its allocation or constant index identity is not proven",
        )?;
        Ok(())
    }

    pub(super) fn metadata(&self, point: ProgramPointId) -> Result<PointMetadata, TsLoweringError> {
        self.session.metadata(point)
    }

    pub(super) fn value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        kind: SemanticValueKind,
    ) -> Result<ValueId, TsLoweringError> {
        self.session.add_value(builder, point, kind)
    }

    pub(super) fn append_effect(
        &self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        effect: SemanticEffect,
    ) -> Result<(), TsLoweringError> {
        self.session.append_effect(builder, point, effect)
    }

    pub(super) fn add_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        subject: SemanticGapSubject,
        capability: SemanticCapability,
        kind: SemanticGapKind,
        detail: &str,
    ) -> Result<(), TsLoweringError> {
        self.session
            .add_gap(builder, point, subject, capability, kind, detail)?;
        Ok(())
    }
}

/// Whether this identifier occurrence is a whole value handed to a call: a
/// direct element of a call's or a `new` expression's argument list.
///
/// Such an occurrence reads the allocation as a whole and names no member of
/// it, so it needs no member identity and must not open a member-resolution
/// gap on the accesses that already ran. A spread element (`f(...values)`), a
/// callee position, and every other shape are deliberately absent: they are
/// not plain whole-value reads, so they keep invalidating the root.
fn is_whole_value_call_argument(node: Node<'_>) -> bool {
    let Some(arguments) = node.parent() else {
        return false;
    };
    if arguments.kind() != "arguments" {
        return false;
    }
    if !named_children(arguments)
        .into_iter()
        .any(|argument| argument.id() == node.id())
    {
        return false;
    }
    arguments
        .parent()
        .is_some_and(|call| matches!(call.kind(), "call_expression" | "new_expression"))
}

/// Whether `node` executes at most once for each execution of the declarator
/// that established `declaration_parent`'s allocation, so byte order between
/// this node and an access under the same declaration is execution order.
///
/// A repetition construct between the two is what breaks that: a consumption
/// inside a loop the declarator sits outside of can run before a textually
/// earlier access on the loop's next iteration.
fn executes_once_within(node: Node<'_>, declaration_parent: usize) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.id() == declaration_parent {
            return true;
        }
        if matches!(
            parent.kind(),
            "for_statement" | "for_in_statement" | "while_statement" | "do_statement"
        ) {
            return false;
        }
        current = parent;
    }
    false
}

/// Whether this identifier occurrence is the object of a member access that
/// preserves the plain-object guarantee: not a `__proto__` access (a
/// non-computed `__proto__` store replaces the prototype), and not the callee
/// of a call (the receiver escapes into the called procedure).
pub(super) fn plain_member_base_use(source: &str, node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() != "member_expression" {
        return false;
    }
    if parent
        .child_by_field_name("object")
        .is_none_or(|object| object.id() != node.id())
    {
        return false;
    }
    let property_is_plain = parent
        .child_by_field_name("property")
        .and_then(|property| node_text(source, property))
        .is_some_and(|text| text != "__proto__");
    if !property_is_plain {
        return false;
    }
    if let Some(grandparent) = parent.parent()
        && matches!(grandparent.kind(), "call_expression" | "new_expression")
        && grandparent
            .child_by_field_name("function")
            .is_some_and(|function| function.id() == parent.id())
    {
        return false;
    }
    true
}

fn is_direct_throw_value(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() != "throw_statement" {
        return false;
    }
    parent
        .child_by_field_name("argument")
        .map(|argument| argument.id() == node.id())
        .unwrap_or_else(|| {
            first_named_child(parent).is_some_and(|argument| argument.id() == node.id())
        })
}

impl<'tree, 'targets> LoweringContext<'tree, 'targets> {
    pub(super) fn is_proven_error_constructor(&self, initializer: Node<'tree>) -> bool {
        if initializer.kind() != "new_expression" {
            return false;
        }
        let Some(constructor) = initializer.child_by_field_name("constructor") else {
            return false;
        };
        constructor.kind() == "identifier"
            && node_text(self.prepared.source(), constructor) == Some("Error")
            && !self
                .lexical_bindings
                .is_bound_at("Error", constructor.start_byte())
    }

    pub(super) fn is_statically_nothrow_error_constructor(&self, initializer: Node<'tree>) -> bool {
        let Some(arguments) = initializer.child_by_field_name("arguments") else {
            return true;
        };
        named_children(arguments).into_iter().all(|argument| {
            matches!(
                argument.kind(),
                "string" | "number" | "true" | "false" | "null" | "regex"
            )
        })
    }
}

pub(super) fn stable_member_key(source: &str, node: Node<'_>) -> Option<Box<str>> {
    match node.kind() {
        "property_identifier" | "private_property_identifier" => {
            let text = node_text(source, node)?;
            Some(format!("{}:{text}", node.kind()).into_boxed_str())
        }
        "number" => constant_array_index(source, node)
            .map(|index| format!("number:{index}").into_boxed_str()),
        _ => None,
    }
}

/// The only array index syntax this lowering can prove to be a stable
/// property identity: a leaf decimal, nonnegative integer token. Parsing the
/// leaf directly also normalizes equivalent spellings such as `0` and `00`.
pub(super) fn constant_array_index(source: &str, node: Node<'_>) -> Option<u64> {
    (node.kind() == "number" && node.named_child_count() == 0)
        .then(|| node_text(source, node))
        .flatten()?
        .parse::<u64>()
        .ok()
}

fn array_subscript_base_use(node: Node<'_>) -> Option<Node<'_>> {
    let parent = node.parent()?;
    (parent.kind() == "subscript_expression")
        .then(|| {
            parent
                .child_by_field_name("object")
                .filter(|object| object.id() == node.id())
                .and_then(|_| parent.child_by_field_name("index"))
        })
        .flatten()
}

fn array_alias_use(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    let parent = node.parent()?;
    if parent.kind() != "variable_declarator"
        || parent
            .child_by_field_name("value")
            .is_none_or(|value| value.id() != node.id())
    {
        return None;
    }
    let target = parent.child_by_field_name("name")?;
    (target.kind() == "identifier" && node.kind() == "identifier").then_some((target, node))
}

fn is_variable_binding_name(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "variable_declarator"
            && parent
                .child_by_field_name("name")
                .is_some_and(|name| name.id() == node.id())
    })
}

pub(super) fn allocation_alias_use(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    let parent = node.parent()?;
    let (target, value) = match parent.kind() {
        "variable_declarator"
            if parent
                .child_by_field_name("value")
                .is_some_and(|value| value.id() == node.id()) =>
        {
            (parent.child_by_field_name("name"), Some(node))
        }
        "assignment_expression"
            if parent
                .child_by_field_name("right")
                .is_some_and(|value| value.id() == node.id()) =>
        {
            (parent.child_by_field_name("left"), Some(node))
        }
        "assignment_expression"
            if parent
                .child_by_field_name("left")
                .is_some_and(|left| left.id() == node.id()) =>
        {
            (Some(node), parent.child_by_field_name("right"))
        }
        _ => (None, None),
    };
    let (Some(target), Some(value)) = (target, value) else {
        return None;
    };
    if target.kind() != "identifier" || value.kind() != "identifier" {
        return None;
    }
    Some((target, value))
}
