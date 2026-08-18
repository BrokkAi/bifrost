use super::syntax::*;
use super::*;

pub(super) fn field_declaration_anchors(
    prepared: &PreparedSyntaxTree,
) -> HashMap<(Box<str>, Box<str>), Option<SourceAnchor>> {
    let mut anchors = HashMap::default();
    let mut stack = vec![prepared.tree().root_node()];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "field_declaration" | "constant_declaration") {
            for declarator in children_by_field_name(node, "declarator") {
                let Some(name) = declarator.child_by_field_name("name") else {
                    continue;
                };
                let Some(text) = node_text(prepared.source(), name) else {
                    continue;
                };
                let Ok(anchor) = source_anchor(name, 0) else {
                    continue;
                };
                let Some(owner) = enclosing_type_name(prepared.source(), node) else {
                    continue;
                };
                match anchors.entry((owner, text.into())) {
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(Some(anchor));
                    }
                    std::collections::hash_map::Entry::Occupied(mut entry) => {
                        entry.insert(None);
                    }
                }
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    anchors
}

fn enclosing_type_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    let mut current = node.parent();
    while let Some(candidate) = current {
        if matches!(
            candidate.kind(),
            "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "annotation_type_declaration"
        ) {
            return candidate
                .child_by_field_name("name")
                .and_then(|name| node_text(source, name))
                .map(Into::into);
        }
        current = candidate.parent();
    }
    None
}

impl<'tree, 'targets> LoweringContext<'tree, 'targets> {
    pub(super) fn emit_captured_receiver(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        spec: &ProcedureSpec<'tree>,
    ) -> Result<(), JavaLoweringError> {
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

    pub(super) fn emit_local_bindings(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        body: Node<'tree>,
    ) -> Result<(), JavaLoweringError> {
        try_walk_named_tree_preorder(body, true, |node| {
            if self.session.cancellation().is_cancelled() {
                return Err(JavaLoweringError::Cancelled(Box::new(
                    builder.prospective_work(),
                )));
            }
            if is_java_nested_execution_boundary(node) {
                return Ok(WalkControl::SkipChildren);
            }
            let binding = match node.kind() {
                "variable_declarator" | "catch_formal_parameter" => {
                    node.child_by_field_name("name").zip(java_local_scope(node))
                }
                _ => None,
            };
            if let Some((name, (scope_start, scope_end))) = binding
                && name.kind() == "identifier"
                && let Some(text) = node_text(self.prepared.source(), name)
            {
                let metadata = self.value_mapping(builder, name)?;
                let value = self.session.add_value_with_metadata(
                    builder,
                    metadata,
                    SemanticValueKind::Local,
                )?;
                if let Some(type_name) = node
                    .child_by_field_name("type")
                    .or_else(|| {
                        node.parent()
                            .and_then(|declaration| declaration.child_by_field_name("type"))
                    })
                    .or_else(|| {
                        named_children(node)
                            .into_iter()
                            .find(|child| child.kind() == "catch_type")
                    })
                    .and_then(|type_node| node_text(self.prepared.source(), type_node))
                {
                    self.local_types.insert(value, type_name.into());
                }
                if node.kind() == "catch_formal_parameter" {
                    self.non_null_values.insert(value);
                }
                self.locals
                    .entry(text.into())
                    .or_default()
                    .push(LocalBinding {
                        declaration_start: name.start_byte(),
                        visible_from: node.end_byte(),
                        scope_start,
                        scope_end,
                        value,
                    });
            }
            Ok(WalkControl::Continue)
        })
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
    ) -> Result<(), JavaLoweringError> {
        let declaration_range = node_range(callable);
        let layout = formal_parameter_slots(
            Language::Java,
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
                    SemanticValueKind::Receiver { dispatch: true },
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
                    JavaLoweringError::Invalid("too many formal parameters".into())
                })?;
                value
            };
            for name in slot.names {
                self.parameters.insert(name.into_boxed_str(), value);
            }
        }

        if self.receiver.is_none()
            && !properties.is_static
            && matches!(
                procedure_kind,
                ProcedureKind::Method | ProcedureKind::Constructor | ProcedureKind::Initializer
            )
        {
            let metadata = self.value_mapping(builder, callable)?;
            self.receiver = Some(self.session.add_value_with_metadata(
                builder,
                metadata,
                SemanticValueKind::Receiver { dispatch: true },
            )?);
        }
        if let Some(receiver) = self.receiver {
            self.parameters.insert("this".into(), receiver);
        }
        Ok(())
    }

    pub(super) fn expression_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        kind: SemanticValueKind,
    ) -> Result<ValueId, JavaLoweringError> {
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

    pub(super) fn index_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<ValueId, JavaLoweringError> {
        if !matches!(expression_value_kind(node), SemanticValueKind::Constant) {
            return self.expression_value(builder, node, expression_value_kind(node));
        }
        let Some(text) = node_text(self.prepared.source(), node) else {
            return self.expression_value(builder, node, SemanticValueKind::Constant);
        };
        if let Some(value) = self.constant_index_values.get(text) {
            self.expression_values.insert(node.id(), *value);
            return Ok(*value);
        }
        let value = self.expression_value(builder, node, SemanticValueKind::Constant)?;
        self.constant_index_values.insert(text.into(), value);
        Ok(value)
    }

    pub(super) fn expression_is_non_null(&self, node: Node<'tree>) -> bool {
        match node.kind() {
            "object_creation_expression" | "array_creation_expression" => true,
            "identifier" => node_text(self.prepared.source(), node).is_some_and(|name| {
                self.local_at(name, node.start_byte())
                    .is_some_and(|value| self.non_null_values.contains(&value))
            }),
            "parenthesized_expression" => {
                first_named_child(node).is_some_and(|inner| self.expression_is_non_null(inner))
            }
            _ => false,
        }
    }

    pub(super) fn emit_lexical_input_flow(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        point: ProgramPointId,
        target: ValueId,
    ) -> Result<(), JavaLoweringError> {
        let Some(name) = node_text(self.prepared.source(), node) else {
            return Ok(());
        };
        let (source, kind) = if node.kind() == "this" {
            if let Some(captured) = self.captured_receiver {
                (Some(captured), ValueFlowKind::Local)
            } else {
                (self.receiver, ValueFlowKind::Receiver)
            }
        } else if node.kind() == "identifier" {
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

    pub(super) fn resolution_gaps(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        callee: ValueId,
        call_site: CallSiteId,
        resolution: &CallableTargetResolution,
    ) -> Result<(), JavaLoweringError> {
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
    ) -> Result<ProgramPointId, JavaLoweringError> {
        let metadata = self.mapping(builder, node)?;
        self.session.add_point(builder, metadata, effects)
    }

    pub(super) fn mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<PointMetadata, JavaLoweringError> {
        self.session.add_node_mapping(builder, node)
    }

    fn value_mapping(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
    ) -> Result<PointMetadata, JavaLoweringError> {
        let anchor = source_anchor(node, 0).map_err(JavaLoweringError::Invalid)?;
        self.session
            .add_mapping(builder, anchor, SourceMappingKind::Exact)
    }

    pub(super) fn memory_member_locator(
        &self,
        node: Node<'tree>,
        object: Node<'tree>,
    ) -> Result<(SemanticLocator, bool), JavaLoweringError> {
        let procedure = self.session.locator();
        let occurrence_anchor = source_anchor(node, 0).map_err(JavaLoweringError::Invalid)?;
        let declaration_anchor = node_text(self.prepared.source(), object)
            .and_then(|name| self.local_at(name, object.start_byte()))
            .and_then(|base| {
                self.local_types
                    .get(&base)
                    .zip(node_text(self.prepared.source(), node))
            })
            .and_then(|(owner, name)| {
                self.field_declaration_anchors
                    .get(&(owner.clone(), name.into()))
            })
            .and_then(|anchor| *anchor);
        let resolved = declaration_anchor.is_some();
        let anchor = declaration_anchor.unwrap_or(occurrence_anchor);
        Ok((
            SemanticLocator::new(
                procedure.mount(),
                procedure.path().clone(),
                procedure.language(),
                procedure.declaration().clone(),
                SemanticRole::MemoryLocation,
                anchor,
            ),
            resolved,
        ))
    }

    pub(super) fn add_field_identity_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        location: MemoryLocationId,
    ) -> Result<(), JavaLoweringError> {
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

    pub(super) fn metadata(
        &self,
        point: ProgramPointId,
    ) -> Result<PointMetadata, JavaLoweringError> {
        self.session.metadata(point)
    }

    pub(super) fn value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        kind: SemanticValueKind,
    ) -> Result<ValueId, JavaLoweringError> {
        self.session.add_value(builder, point, kind)
    }

    pub(super) fn append_effect(
        &self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        effect: SemanticEffect,
    ) -> Result<(), JavaLoweringError> {
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
    ) -> Result<(), JavaLoweringError> {
        self.session
            .add_gap(builder, point, subject, capability, kind, detail)?;
        Ok(())
    }
}
