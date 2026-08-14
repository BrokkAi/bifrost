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

    /// Identify locals that hold a plain object literal for their whole
    /// extent, so field accesses on them can be lowered without capability
    /// gaps. Runs after [`Self::emit_local_bindings`] so `local_at` resolves.
    ///
    /// A candidate is a declarator whose initializer is a plain object
    /// literal. It survives only when every occurrence of the name inside the
    /// binding's scope is the base of a non-`__proto__` member access outside
    /// call-callee position: any other use (a call argument, a return, an
    /// assignment in either direction, a subscript base, a shorthand
    /// property, a capture inside a nested procedure) creates an alias,
    /// rebind, or mutation channel this lowering does not track, so the
    /// binding keeps the conservative gaps.
    pub(super) fn collect_plain_object_locals(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        body: Node<'tree>,
    ) -> Result<(), TsLoweringError> {
        struct Candidate {
            name_node: usize,
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
                && is_plain_object_literal(source, initializer)
                && let Some(text) = node_text(source, name)
                && let Some(value) = self.local_at(text, name.start_byte())
                && let Some(declaration_parent) =
                    node.parent().and_then(|declaration| declaration.parent())
            {
                candidates.entry(value).or_insert(Candidate {
                    name_node: name.id(),
                    declaration_parent: declaration_parent.id(),
                    available_after: node.end_byte(),
                });
            }
            Ok(WalkControl::Continue)
        })?;
        if candidates.is_empty() {
            return Ok(());
        }

        // Occurrence scan over the full body, nested procedures included: a
        // capture invalidates the candidate exactly like a local escape does.
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
            if node.id() == candidate.name_node {
                return Ok(WalkControl::Continue);
            }
            let survives = !inside_nested
                && node.kind() == "identifier"
                && plain_member_base_use(source, node);
            if !survives {
                candidates.remove(&value);
                if candidates.is_empty() {
                    return Ok(WalkControl::Break);
                }
            }
            Ok(WalkControl::Continue)
        })?;
        self.plain_object_locals = candidates
            .into_iter()
            .map(|(value, candidate)| {
                (
                    value,
                    PlainObjectLocal {
                        declaration_parent: candidate.declaration_parent,
                        available_after: candidate.available_after,
                    },
                )
            })
            .collect();
        Ok(())
    }

    /// Whether `access` is a field access whose base identifier resolves to a
    /// plain object local and executes only after the declarator has run:
    /// the declaration statement's parent must be an ancestor of the access,
    /// and the access must start after the declarator ends, so no path
    /// reaches the access without establishing the binding first.
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
        let mut current = access.parent();
        while let Some(node) = current {
            if node.id() == plain.declaration_parent {
                return true;
            }
            current = node.parent();
        }
        false
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

/// Whether this identifier occurrence is the object of a member access that
/// preserves the plain-object guarantee: not a `__proto__` access (a
/// non-computed `__proto__` store replaces the prototype), and not the callee
/// of a call (the receiver escapes into the called procedure).
fn plain_member_base_use(source: &str, node: Node<'_>) -> bool {
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
