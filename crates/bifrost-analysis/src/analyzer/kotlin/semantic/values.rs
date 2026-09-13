use super::syntax::*;
use super::*;

impl<'tree, 'targets> LoweringContext<'tree, 'targets> {
    pub(super) fn emit_capture_inputs(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        spec: &ProcedureSpec<'tree>,
    ) -> Result<(), KotlinLoweringError> {
        let Some(lexical_parent) = spec.lexical_parent else {
            return Ok(());
        };
        if spec.captures_receiver {
            let metadata = self.value_mapping(builder, spec.callable)?;
            let (value, _) = self.session.add_receiver_capture_input(
                builder,
                entry,
                metadata,
                lexical_parent,
            )?;
            self.captured_receiver = Some(value);
        }
        for (index, capture) in spec.captures.iter().enumerate() {
            let metadata = self.value_mapping(builder, capture.reference)?;
            let value = self.session.add_value_with_metadata(
                builder,
                metadata,
                SemanticValueKind::Local,
            )?;
            let location = self.session.add_memory_location(
                builder,
                entry,
                MemoryLocationKind::Capture {
                    lexical_parent,
                    binding: Some(value),
                },
            )?;
            let expected = lexical_capture_destination(spec.captures_receiver, index)?;
            if location != expected {
                return Err(KotlinLoweringError::Invalid(format!(
                    "Kotlin capture destination must be {expected}, allocated {location}"
                )));
            }
            self.append_effect(
                builder,
                entry,
                SemanticEffect::MemoryLoad {
                    kind: MemoryAccessKind::Capture,
                    location,
                    result: value,
                },
            )?;
            self.captured_bindings.insert(capture.name.into(), value);
        }
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
                if let Some(target) = self.procedure_targets.get(&node.id()).cloned()
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
                    if child_of_kind(node, "binding_pattern_kind")
                        .and_then(|kind| node_text(self.prepared.source(), kind))
                        == Some("val")
                        && let Some(value) = property_initializer(node)
                        && let Some(target) = self.procedure_targets.get(&value.id()).cloned()
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
            // A written type decides the binding's JVM carrier whether or not
            // the declaration has an initializer, so it is recorded with the
            // binding rather than when an initializer is lowered. A catch
            // binder names itself directly and writes no type.
            if let Some(binding) = name
                .parent()
                .filter(|parent| parent.kind() == "variable_declaration")
                && let Some(written) = kotlin_binding_type_node(binding)
            {
                self.bind_carrier(value, Some(written), KotlinCarrier::Unrelated);
            }
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
            let parameter_name = slot.unique_name().map(Box::<str>::from);
            let passing_mode = slot.passing_mode;
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
                        name: parameter_name,
                        passing_mode,
                    },
                )?;
                ordinal = ordinal.checked_add(1).ok_or_else(|| {
                    KotlinLoweringError::Invalid("too many formal parameters".into())
                })?;
                value
            };
            // A formal's written type is what decides which JVM carrier the
            // parameter holds, so it is recorded with the binding itself.
            self.bind_carrier(
                value,
                kotlin_binding_type_node(node),
                KotlinCarrier::Unrelated,
            );
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
            if let Some(captured) = self.captured_bindings.get(name).copied() {
                (Some(captured), ValueFlowKind::Local)
            } else if let Some(local) = self.local_at(name, node.start_byte()) {
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

/// Kotlin's `@JvmInline` value-class carrier adaptations (#2851).
///
/// A value class has two runtime carriers: the underlying value itself, which
/// is what an ordinary `Money` slot holds, and a wrapper object, which is what
/// a nullable, generic, or supertype slot holds. Logical value dependence
/// survives both directions, but the wrapper is not the value and carries no
/// stable identity, so every adaptation is published as an identity-separating
/// transfer rather than as ordinary local flow.
///
/// Everything here answers from one file. A destination the file does not
/// declare -- a Java signature, a cross-file Kotlin type -- and a generic slot
/// whose specialization is written elsewhere stay typed incomplete.
impl<'tree, 'targets> LoweringContext<'tree, 'targets> {
    /// The JVM carrier an expression holds.
    ///
    /// Only shapes whose carrier this file proves answer with a value class:
    /// a bound name, a construction of a declared value class, and the
    /// wrappers (`!!`, parentheses) that do not change what an expression
    /// denotes. Everything else is [`KotlinCarrier::Unrelated`], which claims
    /// nothing.
    pub(super) fn expression_carrier(&self, node: Node<'tree>) -> KotlinCarrier {
        let node = kotlin_unwrap_receiver(node);
        match node.kind() {
            "simple_identifier" => self
                .bound_value(node)
                .and_then(|value| self.carriers.get(&value).copied())
                .unwrap_or(KotlinCarrier::Unrelated),
            "call_expression" => self.constructed_carrier(node),
            // A member of a value class reads its own underlying property
            // through the receiver, so the receiver carries the class the
            // member is declared in.
            "this_expression" => self
                .captured_receiver
                .or(self.receiver)
                .and_then(|value| self.carriers.get(&value).copied())
                .unwrap_or(KotlinCarrier::Unrelated),
            _ => KotlinCarrier::Unrelated,
        }
    }

    /// Record the value class a dispatching receiver carries, when the
    /// procedure is declared inside one.
    pub(super) fn bind_receiver_carrier(&mut self, callable: Node<'tree>) {
        let Some(receiver) = self.receiver else {
            return;
        };
        let mut enclosing = callable.parent();
        while let Some(node) = enclosing {
            if node.kind() == "class_declaration"
                && let Some(name) = child_of_kind(node, "type_identifier")
                    .and_then(|name| node_text(self.prepared.source(), name))
                && let carrier @ KotlinCarrier::Unboxed(_) =
                    self.value_classes.declared_value_class(name)
            {
                self.carriers.insert(receiver, carrier);
                return;
            }
            enclosing = node.parent();
        }
    }

    /// The carrier a construction produces.
    ///
    /// A call produces a value class's unboxed carrier only when the whole
    /// construction is proven, because a spelling that selects something else
    /// -- an invokable binding, a factory function, a companion `invoke` --
    /// produces whatever *that* callable returns.
    pub(super) fn constructed_carrier(&self, call: Node<'tree>) -> KotlinCarrier {
        match self.construction_proof(call) {
            KotlinConstructionProof::Proven { class, .. } => KotlinCarrier::Unboxed(class),
            KotlinConstructionProof::Incomplete(reason) => KotlinCarrier::Incomplete(reason),
            KotlinConstructionProof::Unrelated => KotlinCarrier::Unrelated,
        }
    }

    /// Whether a call provably runs a value class's primary constructor on an
    /// argument this file proves the type of.
    ///
    /// Three things have to hold, and each is proved from structure rather
    /// than from the spelling: the callee must denote the class and nothing
    /// else in scope, the call must pass exactly the one argument the carrier
    /// takes, and the actual must provably fit the underlying type.
    pub(super) fn construction_proof(&self, call: Node<'tree>) -> KotlinConstructionProof {
        let Some(callee) =
            kotlin_callee(call).filter(|callee| callee.kind() == "simple_identifier")
        else {
            return KotlinConstructionProof::Unrelated;
        };
        let Some(name) = node_text(self.prepared.source(), callee) else {
            return KotlinConstructionProof::Unrelated;
        };
        let class = match self
            .value_classes
            .constructor_selection(name, self.callee_binding(callee, name))
        {
            KotlinConstructorSelection::Primary(class) => class,
            KotlinConstructorSelection::Incomplete(reason) => {
                return KotlinConstructionProof::Incomplete(reason);
            }
            KotlinConstructorSelection::Unrelated => return KotlinConstructionProof::Unrelated,
        };
        let arguments = call_arguments(call);
        let Some(index) = underlying_argument_index(
            &arguments,
            self.prepared.source(),
            self.value_classes.value_class(class).underlying().name(),
        ) else {
            return KotlinConstructionProof::Incomplete(
                KotlinAdaptationIncomplete::UnderlyingProperty,
            );
        };
        let actual = arguments[index].value;
        match self.value_classes.underlying_match(
            class,
            self.actual_evidence(actual),
            self.prepared.source(),
        ) {
            KotlinUnderlyingMatch::Proven => KotlinConstructionProof::Proven { class, index },
            KotlinUnderlyingMatch::Mismatched => KotlinConstructionProof::Incomplete(
                KotlinAdaptationIncomplete::UnderlyingTypeMismatch,
            ),
            // A unique callee does not prove that the actual fits its carrier.
            // Keep missing type evidence separate from overload ambiguity.
            KotlinUnderlyingMatch::Unknown
                if self
                    .value_classes
                    .competing_constructor(class, arguments.len()) =>
            {
                KotlinConstructionProof::Incomplete(
                    KotlinAdaptationIncomplete::AmbiguousConstructor,
                )
            }
            KotlinUnderlyingMatch::Unknown => KotlinConstructionProof::Incomplete(
                KotlinAdaptationIncomplete::UnderlyingTypeUnknown,
            ),
        }
    }

    /// What the call site's own scope proves about a callee spelling.
    fn callee_binding(&self, callee: Node<'tree>, name: &str) -> KotlinCalleeBinding {
        // A local `fun` and a local `val` bound to a lambda are both callables
        // the enclosing body declares, so either answers the call itself.
        if self.local_callables.contains_key(name) {
            return KotlinCalleeBinding::Invokable;
        }
        let Some(value) = self
            .local_at(name, callee.start_byte())
            .or_else(|| self.parameters.get(name).copied())
            .or_else(|| self.captured_bindings.get(name).copied())
        else {
            return KotlinCalleeBinding::Free;
        };
        match self.declared_types.get(&value) {
            Some(written) if kotlin_written_type_is_function(*written) => {
                KotlinCalleeBinding::Invokable
            }
            // A binding whose type is inferred, or whose type may carry an
            // `invoke` operator, leaves the selection open.
            _ => KotlinCalleeBinding::Opaque,
        }
    }

    /// The type evidence this file has for one actual argument.
    ///
    /// The walk is one level deep on purpose: a nested construction answers
    /// with the class its own callee selects, which needs no second argument
    /// proof and so cannot recurse.
    fn actual_evidence(&self, actual: Node<'tree>) -> KotlinActualEvidence<'tree> {
        let actual = kotlin_unwrap_receiver(actual);
        if !literal_type_names(actual.kind()).is_empty() || actual.kind() == "null_literal" {
            return KotlinActualEvidence::Literal(actual);
        }
        match actual.kind() {
            "simple_identifier" => {
                let Some(value) = self.bound_value(actual) else {
                    return KotlinActualEvidence::Unknown;
                };
                if let Some(written) = self.declared_types.get(&value) {
                    return KotlinActualEvidence::Written(*written);
                }
                match self.carriers.get(&value) {
                    Some(KotlinCarrier::Unboxed(class)) => KotlinActualEvidence::ValueClass(*class),
                    _ => KotlinActualEvidence::Unknown,
                }
            }
            "this_expression" => match self
                .captured_receiver
                .or(self.receiver)
                .and_then(|value| self.carriers.get(&value))
            {
                Some(KotlinCarrier::Unboxed(class)) => KotlinActualEvidence::ValueClass(*class),
                _ => KotlinActualEvidence::Unknown,
            },
            "call_expression" => {
                let Some(callee) =
                    kotlin_callee(actual).filter(|callee| callee.kind() == "simple_identifier")
                else {
                    return KotlinActualEvidence::Unknown;
                };
                let Some(name) = node_text(self.prepared.source(), callee) else {
                    return KotlinActualEvidence::Unknown;
                };
                match self
                    .value_classes
                    .constructor_selection(name, self.callee_binding(callee, name))
                {
                    KotlinConstructorSelection::Primary(class) => {
                        KotlinActualEvidence::ValueClass(class)
                    }
                    _ => KotlinActualEvidence::Unknown,
                }
            }
            _ => KotlinActualEvidence::Unknown,
        }
    }

    /// The local or parameter a bare name reads.
    pub(super) fn bound_value(&self, node: Node<'tree>) -> Option<ValueId> {
        let name = node_text(self.prepared.source(), node)?;
        self.local_at(name, node.start_byte())
            .or_else(|| self.parameters.get(name).copied())
    }

    /// Record what a binding's written type says it carries, and what its type
    /// node is, so a later store through it can be resolved.
    pub(super) fn bind_carrier(
        &mut self,
        value: ValueId,
        written: Option<Node<'tree>>,
        inferred: KotlinCarrier,
    ) {
        let carrier = match written {
            Some(written) => {
                let classified =
                    self.value_classes
                        .written_type(written, self.prepared.source(), written);
                self.declared_types.insert(value, written);
                self.value_classes
                    .carrier_of(classified, inferred.value_class())
            }
            // Kotlin infers the declaration's type from its initializer, so an
            // unwritten type carries exactly what the initializer carried.
            None => inferred,
        };
        if carrier != KotlinCarrier::Unrelated {
            self.carriers.insert(value, carrier);
        }
    }

    /// The carrier a slot with the written type `written` holds for a value of
    /// `carried`'s class.
    pub(super) fn written_carrier(
        &self,
        written: Option<Node<'tree>>,
        carried: KotlinCarrier,
    ) -> KotlinCarrier {
        let Some(class) = carried.value_class() else {
            return KotlinCarrier::Unrelated;
        };
        let classified = match written {
            Some(written) => {
                self.value_classes
                    .written_type(written, self.prepared.source(), written)
            }
            None => KotlinWrittenType::Absent,
        };
        self.value_classes.carrier_of(classified, Some(class))
    }

    /// What carrying `source`'s value into a slot of the written type
    /// `written` does.
    ///
    /// An unwritten type is *inferred* from the value, so it carries exactly
    /// what the value carried and adapts nothing. That is why an absent type
    /// here is not the same answer as a member whose type this file cannot
    /// read.
    pub(super) fn written_adaptation(
        &self,
        source: Node<'tree>,
        written: Option<Node<'tree>>,
    ) -> KotlinAdaptationOutcome {
        let Some(written) = written else {
            return KotlinAdaptationOutcome::Unrelated;
        };
        let carried = self.expression_carrier(source);
        let destination = self.written_carrier(Some(written), carried);
        self.value_classes.adaptation(carried, destination)
    }

    /// What carrying `source`'s value into an already-bound local or parameter
    /// does.
    ///
    /// A slot whose written type is a supertype or a type parameter carries
    /// whichever value class reaches it, so the destination is read from the
    /// written type at each assignment rather than fixed when the binding was
    /// created. Only an inferred binding falls back to what it was bound
    /// holding, because that is all Kotlin itself says about it.
    pub(super) fn binding_adaptation(
        &self,
        source: Node<'tree>,
        target: ValueId,
    ) -> KotlinAdaptationOutcome {
        let carried = self.expression_carrier(source);
        let destination = match self.declared_types.get(&target) {
            Some(written) => self.written_carrier(Some(*written), carried),
            None => self
                .carriers
                .get(&target)
                .copied()
                .unwrap_or(KotlinCarrier::Unrelated),
        };
        self.value_classes.adaptation(carried, destination)
    }

    /// What storing `source`'s value into `base.member` does.
    ///
    /// The member's slot is read from the declaration the receiver's written
    /// type names. A receiver whose type this file does not declare, and a
    /// member that writes no type, each leave the slot's carrier unproven
    /// rather than assumed.
    pub(super) fn member_adaptation(
        &self,
        base: Node<'tree>,
        member: Node<'tree>,
        source: Node<'tree>,
    ) -> KotlinAdaptationOutcome {
        let carried = self.expression_carrier(source);
        if carried.value_class().is_none() {
            return KotlinAdaptationOutcome::Unrelated;
        }
        let Some(written) = self.member_written_type(base, member) else {
            return KotlinAdaptationOutcome::Incomplete(
                KotlinAdaptationIncomplete::ForeignDestination,
            );
        };
        let destination = self.written_carrier(Some(written), carried);
        self.value_classes.adaptation(carried, destination)
    }

    /// The type the declaration behind `base`'s written type writes for
    /// `member`.
    fn member_written_type(&self, base: Node<'tree>, member: Node<'tree>) -> Option<Node<'tree>> {
        let base = kotlin_unwrap_receiver(base);
        if base.kind() != "simple_identifier" {
            return None;
        }
        let value = self.bound_value(base)?;
        let declared = self.declared_types.get(&value)?;
        let owner = self
            .value_classes
            .declared_type_owner(*declared, self.prepared.source())?;
        let member = node_text(self.prepared.source(), member)?;
        self.value_classes.member_written_type(owner, member)
    }

    /// The projection of a value class's underlying value out of
    /// `receiver.member`, when that is what the read is.
    pub(super) fn underlying_projection(
        &self,
        receiver: Node<'tree>,
        member: Node<'tree>,
    ) -> Option<KotlinAdaptationOutcome> {
        let class = self.expression_carrier(receiver).value_class()?;
        let member = node_text(self.prepared.source(), member)?;
        self.value_classes
            .projects_underlying(class, member)
            .then(|| self.value_classes.projection(class))
    }

    /// Append the assignment and the flow that carries `source` into `target`,
    /// publishing a proven carrier adaptation as an identity-separating
    /// transfer and an unproven one as a typed gap.
    pub(super) fn append_carried_assignment(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        target: ValueId,
        source: ValueId,
        outcome: &KotlinAdaptationOutcome,
        flow: ValueFlowKind,
    ) -> Result<(), KotlinLoweringError> {
        self.append_effect(
            builder,
            point,
            SemanticEffect::Assignment {
                target,
                value: source,
            },
        )?;
        match outcome {
            KotlinAdaptationOutcome::Adapted(fact) => {
                self.append_effect(
                    builder,
                    point,
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Transfer(value_carrier_transfer(fact)),
                        source,
                        target,
                    },
                )?;
            }
            KotlinAdaptationOutcome::Incomplete(reason) => {
                self.append_effect(
                    builder,
                    point,
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::LanguageDefined,
                        source,
                        target,
                    },
                )?;
                self.add_carrier_gap(builder, point, SemanticGapSubject::Value(target), *reason)?;
            }
            KotlinAdaptationOutcome::Unchanged | KotlinAdaptationOutcome::Unrelated => {
                self.append_effect(
                    builder,
                    point,
                    SemanticEffect::ValueFlow {
                        kind: flow,
                        source,
                        target,
                    },
                )?;
            }
        }
        Ok(())
    }

    /// The value that reaches a destination which is not itself a binding: a
    /// field slot or a returned result.
    ///
    /// A proven adaptation lands in its own storage, because the wrapper a
    /// boundary requires is not the value the source held.
    pub(super) fn adapted_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        source: ValueId,
        outcome: &KotlinAdaptationOutcome,
    ) -> Result<ValueId, KotlinLoweringError> {
        match outcome {
            KotlinAdaptationOutcome::Adapted(fact) => {
                let adapted = self.value(builder, point, SemanticValueKind::Temporary)?;
                self.append_effect(
                    builder,
                    point,
                    SemanticEffect::Assignment {
                        target: adapted,
                        value: source,
                    },
                )?;
                self.append_effect(
                    builder,
                    point,
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Transfer(value_carrier_transfer(fact)),
                        source,
                        target: adapted,
                    },
                )?;
                Ok(adapted)
            }
            KotlinAdaptationOutcome::Incomplete(reason) => {
                self.add_carrier_gap(builder, point, SemanticGapSubject::Value(source), *reason)?;
                Ok(source)
            }
            KotlinAdaptationOutcome::Unchanged | KotlinAdaptationOutcome::Unrelated => Ok(source),
        }
    }

    pub(super) fn add_carrier_gap(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        subject: SemanticGapSubject,
        reason: KotlinAdaptationIncomplete,
    ) -> Result<(), KotlinLoweringError> {
        self.add_gap(
            builder,
            point,
            subject,
            SemanticCapability::Values,
            SemanticGapKind::Unknown,
            reason.detail(),
        )
    }
}

/// Which argument supplies a value class's underlying value.
///
/// A JVM inline value class has exactly one constructor slot. A call that
/// passes a different number of arguments, or names a keyword that is not the
/// underlying property, does not construct one, and is reported rather than
/// matched positionally anyway.
pub(super) fn underlying_argument_index(
    arguments: &[CallArgumentNode<'_>],
    source: &str,
    underlying: &str,
) -> Option<usize> {
    let [argument] = arguments else {
        return None;
    };
    if matches!(argument.expansion(), CallArgumentExpansion::Spread(_)) {
        return None;
    }
    match argument.keyword {
        Some(keyword) => (node_text(source, keyword) == Some(underlying)).then_some(0),
        None => Some(0),
    }
}

/// Whether a call runs a value class's primary constructor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum KotlinConstructionProof {
    /// The constructor runs on the argument at this index.
    Proven {
        class: KotlinValueClassId,
        index: usize,
    },
    /// A value class is named but the construction is not proven.
    Incomplete(KotlinAdaptationIncomplete),
    /// Nothing about this call constructs a value class this file declares.
    Unrelated,
}

/// The shared transfer one Kotlin carrier adaptation publishes.
///
/// Construction is a conversion rather than a boxing: the unboxed carrier is
/// the underlying value itself, so no wrapper object exists and no runtime
/// class is established. Boxing and unboxing name the wrapper explicitly, and
/// an underlying projection extracts the carried value out of whichever
/// carrier held it.
fn value_carrier_transfer(fact: &KotlinValueAdaptationFact) -> ValueTransfer {
    let kind = match fact.adaptation() {
        KotlinValueAdaptation::Construction => TransferKind::Conversion {
            preservation: ValuePreservation::Preserving,
        },
        KotlinValueAdaptation::UnderlyingProjection | KotlinValueAdaptation::Unboxing(_) => {
            TransferKind::Unboxing
        }
        KotlinValueAdaptation::Boxing(_) => TransferKind::Boxing,
    };
    ValueTransfer {
        kind,
        operation: TransferOperation::ValueCarrierAdaptation(value_carrier_operation(fact)),
    }
}

/// The content-addressed identity of one carrier adaptation witness.
///
/// The witness is the whole reason the transfer is trustworthy, so the
/// producer's own length-delimited encoding of it -- adapting declaration,
/// carrying property, direction, boundary -- is what the operation identifies.
fn value_carrier_operation(fact: &KotlinValueAdaptationFact) -> StableDigest {
    StableDigest::sha256(fact.witness_bytes())
}
