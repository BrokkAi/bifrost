use super::syntax::*;
use super::*;

impl<'tree, 'targets> LoweringContext<'tree, 'targets> {
    pub(super) fn emit_captured_receiver(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        spec: &ProcedureSpec<'tree>,
    ) -> Result<(), KotlinLoweringError> {
        let Some(lexical_parent) = spec.lexical_parent.filter(|_| spec.captures_receiver) else {
            return Ok(());
        };
        let metadata = self.value_mapping(builder, spec.callable)?;
        let (value, _) =
            self.session
                .add_receiver_capture_input(builder, entry, metadata, lexical_parent)?;
        self.captured_receiver = Some(value);
        Ok(())
    }

    /// Pre-index every local a procedure body introduces, plus the nested
    /// callables a bare name can denote.
    ///
    /// Kotlin spells locals with the same `property_declaration` node it uses
    /// for members, and a `for` binding or destructuring introduces its names
    /// without an initializer, so all of them are collected in one bounded scan
    /// rather than discovered while lowering.
    pub(super) fn emit_local_bindings(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        body: Node<'tree>,
    ) -> Result<(), KotlinLoweringError> {
        let mut pending = Vec::new();
        let mut local_callables = Vec::new();
        try_walk_named_tree_preorder(body, true, |node| {
            if self.session.cancellation().is_cancelled() {
                return Err(KotlinLoweringError::Cancelled(Box::new(
                    builder.prospective_work(),
                )));
            }
            if node.id() != body.id() && is_kotlin_nested_execution_boundary(node) {
                if let Some(target) = self.procedure_targets.get(&node.id()).copied()
                    && node.kind() == "function_declaration"
                    && let Some(name) = child_of_kind(node, "simple_identifier")
                        .and_then(|name| node_text(self.prepared.source(), name))
                {
                    local_callables.push((Box::<str>::from(name), target));
                }
                return Ok(WalkControl::SkipChildren);
            }
            match node.kind() {
                "variable_declaration" => {
                    let visible_from = node
                        .parent()
                        .filter(|parent| parent.kind() == "property_declaration")
                        .map_or(node.end_byte(), |parent| parent.end_byte());
                    for name in binding_names(node) {
                        pending.push((name, visible_from));
                    }
                }
                "catch_block" => {
                    if let Some(name) = child_of_kind(node, "simple_identifier") {
                        pending.push((name, name.end_byte()));
                    }
                }
                "property_declaration" => {
                    if let Some(value) = property_initializer(node)
                        && let Some(target) = self.procedure_targets.get(&value.id()).copied()
                        && let Some(name) = binding_node(node)
                            .and_then(|binding| binding_names(binding).first().copied())
                            .and_then(|name| node_text(self.prepared.source(), name))
                    {
                        local_callables.push((Box::<str>::from(name), target));
                    }
                }
                _ => {}
            }
            Ok(WalkControl::Continue)
        })?;

        for (name, visible_from) in pending {
            let Some(text) = node_text(self.prepared.source(), name) else {
                continue;
            };
            let Some((scope_start, scope_end)) = kotlin_local_scope(name) else {
                continue;
            };
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
                    declaration_start: name.start_byte(),
                    visible_from,
                    scope_start,
                    scope_end,
                    value,
                });
        }
        for (name, target) in local_callables {
            self.local_callables.entry(name).or_insert(target);
        }
        Ok(())
    }

    pub(super) fn local_at(&self, name: &str, byte: usize) -> Option<ValueId> {
        self.locals
            .get(name)?
            .iter()
            .filter(|binding| {
                binding.visible_from <= byte
                    && binding.scope_start <= byte
                    && byte < binding.scope_end
            })
            .min_by_key(|binding| binding.scope_end - binding.scope_start)
            .map(|binding| binding.value)
    }

    pub(super) fn local_declaration_value(
        &self,
        name: &str,
        declaration_start: usize,
    ) -> Option<ValueId> {
        self.locals
            .get(name)?
            .iter()
            .find(|binding| binding.declaration_start == declaration_start)
            .map(|binding| binding.value)
    }

    pub(super) fn emit_procedure_inputs(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        callable: Node<'tree>,
        procedure_kind: ProcedureKind,
        properties: ProcedureProperties,
    ) -> Result<(), KotlinLoweringError> {
        let declaration_range = node_range(callable);
        let layout = formal_parameter_slots(
            Language::Kotlin,
            self.prepared.tree().root_node(),
            self.prepared.source(),
            &declaration_range,
        )
        .unwrap_or_default();
        let mut ordinal = 0_u32;
        for slot in layout.slots {
            let node = callable
                .named_descendant_for_byte_range(
                    slot.declaration_range.start_byte,
                    slot.declaration_range.end_byte,
                )
                .unwrap_or(callable);
            let metadata = self.value_mapping(builder, node)?;
            let value = if slot.receiver {
                let value = self.session.add_value_with_metadata(
                    builder,
                    metadata,
                    SemanticValueKind::Receiver { dispatch: false },
                )?;
                self.receiver = Some(value);
                value
            } else {
                let multiplicity = formal_multiplicity(slot.variadic);
                let value = self.session.add_value_with_metadata(
                    builder,
                    metadata,
                    SemanticValueKind::Parameter {
                        ordinal,
                        multiplicity,
                    },
                )?;
                ordinal = ordinal.checked_add(1).ok_or_else(|| {
                    KotlinLoweringError::Invalid("too many formal parameters".into())
                })?;
                value
            };
            for name in slot.names {
                self.parameters.insert(name.into_boxed_str(), value);
            }
        }

        // An extension's receiver is the one parameter Kotlin spells as a type
        // rather than as a name, so the shared slot layout — which keys a
        // parameter on the identifier it binds — cannot see it. The `receiver`
        // field is structured, so the value is published from there directly.
        // A top-level extension stays `is_static`, matching how it executes:
        // the receiver is passed in, not dispatched on.
        if self.receiver.is_none()
            && let Some(node) = callable.child_by_field_name("receiver")
        {
            let metadata = self.value_mapping(builder, node)?;
            self.receiver = Some(self.session.add_value_with_metadata(
                builder,
                metadata,
                SemanticValueKind::Receiver { dispatch: false },
            )?);
        }

        if self.receiver.is_none()
            && !properties.is_static
            && matches!(
                procedure_kind,
                ProcedureKind::Method
                    | ProcedureKind::Constructor
                    | ProcedureKind::Initializer
                    | ProcedureKind::Accessor
            )
        {
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
    ) -> Result<ValueId, KotlinLoweringError> {
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

    /// Flow a name occurrence from the local, parameter, or receiver it reads.
    pub(super) fn emit_lexical_input_flow(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        point: ProgramPointId,
        target: ValueId,
    ) -> Result<(), KotlinLoweringError> {
        let (source, kind) = if node.kind() == "this_expression" {
            if let Some(captured) = self.captured_receiver {
                (Some(captured), ValueFlowKind::Local)
            } else {
                (self.receiver, ValueFlowKind::Receiver)
            }
        } else if node.kind() == "simple_identifier" {
            let Some(name) = node_text(self.prepared.source(), node) else {
                return Ok(());
            };
            if let Some(local) = self.local_at(name, node.start_byte()) {
                (Some(local), ValueFlowKind::Local)
            } else {
                (self.parameters.get(name).copied(), ValueFlowKind::Parameter)
            }
        } else {
            (None, ValueFlowKind::Local)
        };
        if let Some(source) = source
            && source != target
        {
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

    /// Whether a callee names a class this file declares, and no nearer binding
    /// of the same name shadows it.
    ///
    /// Kotlin resolves a bare name against locals, parameters, and nested
    /// callables before it reaches a type, so each of those is consulted first;
    /// a qualified callee (`other.Box(…)`) is deliberately not claimed, because
    /// the qualifier's meaning needs whole-program resolution.
    pub(super) fn names_constructible_class(&self, callee: Node<'tree>) -> bool {
        if callee.kind() != "simple_identifier" {
            return false;
        }
        let Some(name) = node_text(self.prepared.source(), callee) else {
            return false;
        };
        if self.local_at(name, callee.start_byte()).is_some()
            || self.parameters.contains_key(name)
            || self.local_callables.contains_key(name)
        {
            return false;
        }
        self.constructible_types.contains(name)
    }

    pub(super) fn resolution_gaps(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        callee: ValueId,
        call_site: CallSiteId,
        resolution: &CallableTargetResolution,
    ) -> Result<(), KotlinLoweringError> {
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
    ) -> Result<ProgramPointId, KotlinLoweringError> {
        let metadata = self.mapping(builder, node)?;
        self.session.add_point(builder, metadata, effects)
    }

    pub(super) fn mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<PointMetadata, KotlinLoweringError> {
        self.session.add_node_mapping(builder, node)
    }

    fn value_mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<PointMetadata, KotlinLoweringError> {
        let anchor = source_anchor(node, 0).map_err(KotlinLoweringError::Invalid)?;
        self.session
            .add_mapping(builder, anchor, SourceMappingKind::Exact)
    }

    pub(super) fn memory_member_locator(
        &self,
        node: Node<'tree>,
    ) -> Result<SemanticLocator, KotlinLoweringError> {
        let procedure = self.session.locator();
        let anchor = source_anchor(node, 0).map_err(KotlinLoweringError::Invalid)?;
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
    ) -> Result<(), KotlinLoweringError> {
        self.session.add_gap_with_impacts(
            builder,
            point,
            SemanticGapSubject::MemoryLocation(location),
            SemanticCapability::FieldMemory,
            SemanticGapImpacts::single(SemanticGapImpact::HeapRead)
                .with(SemanticGapImpact::HeapWrite)
                .with(SemanticGapImpact::Aliasing),
            SemanticGapKind::Unknown,
            "property occurrence is structured, but its declaration identity and accessor dispatch are not yet resolved",
        )?;
        Ok(())
    }

    pub(super) fn metadata(
        &self,
        point: ProgramPointId,
    ) -> Result<PointMetadata, KotlinLoweringError> {
        self.session.metadata(point)
    }

    pub(super) fn value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        kind: SemanticValueKind,
    ) -> Result<ValueId, KotlinLoweringError> {
        self.session.add_value(builder, point, kind)
    }

    pub(super) fn append_effect(
        &self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        effect: SemanticEffect,
    ) -> Result<(), KotlinLoweringError> {
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
    ) -> Result<(), KotlinLoweringError> {
        self.session
            .add_gap(builder, point, subject, capability, kind, detail)?;
        Ok(())
    }
}
