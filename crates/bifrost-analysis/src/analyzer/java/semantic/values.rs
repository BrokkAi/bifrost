use super::syntax::*;
use super::*;

/// Whether a local or formal parameter declaration structurally declares an
/// array value. Java permits dimensions either in the type (`int[] values`)
/// or after the declarator (`int values[]`); a spread parameter is an array in
/// the callee even though its type child names only the component type.
fn java_binding_declares_array(node: Node<'_>) -> bool {
    if node.kind() == "spread_parameter" || node.child_by_field_name("dimensions").is_some() {
        return true;
    }
    node.child_by_field_name("type")
        .or_else(|| {
            node.parent()
                .and_then(|declaration| declaration.child_by_field_name("type"))
        })
        .is_some_and(java_type_syntax_is_array)
}

fn java_type_syntax_is_array(root: Node<'_>) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "array_type" | "dimensions") {
            return true;
        }
        stack.extend(named_children(node));
    }
    false
}

/// A resolved, unambiguous field declaration: its own name's source anchor,
/// and whether it is `static` (or an interface `constant_declaration`,
/// always implicitly `static final`). The `is_static` flag is what
/// [`LoweringContext::implicit_instance_field_locator`] (#2573) uses to
/// refuse a `static` field: a bare identifier naming one is not `this`-scoped
/// (it names one shared, class-wide slot, not a per-instance one), a
/// different, unaddressed question this fix does not touch.
#[derive(Clone, Copy)]
pub(super) struct FieldDeclarationAnchor {
    pub(super) anchor: SourceAnchor,
    pub(super) is_static: bool,
    pub(super) is_array: bool,
}

pub(super) struct JavaDeclarationInventory {
    pub(super) field_anchors: HashMap<(Box<str>, Box<str>), Option<FieldDeclarationAnchor>>,
    pub(super) type_roots: HashSet<Box<str>>,
}

pub(super) fn java_declaration_inventory(
    prepared: &PreparedSyntaxTree,
) -> JavaDeclarationInventory {
    let mut field_anchors = HashMap::default();
    let mut type_roots = HashSet::default();
    let mut stack = vec![prepared.tree().root_node()];
    while let Some(node) = stack.pop() {
        if matches!(
            node.kind(),
            "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "annotation_type_declaration"
        ) && let Some(name) = node
            .child_by_field_name("name")
            .and_then(|name| node_text(prepared.source(), name))
        {
            type_roots.insert(name.into());
        }
        if node.kind() == "import_declaration"
            && let Some(raw) = prepared.source().get(node.byte_range())
        {
            let import = brokk_bifrost_jvm::java::imports::parse_import_info(
                node,
                prepared.source(),
                raw.to_string(),
            );
            if !import.is_wildcard
                && brokk_bifrost_jvm::java::imports::non_static_import_path(&import).is_some()
                && let Some(identifier) = import.identifier
            {
                type_roots.insert(identifier.into_boxed_str());
            }
        }
        if matches!(node.kind(), "field_declaration" | "constant_declaration") {
            // An interface `constant_declaration` is always implicitly
            // `public static final` (JLS 9.3); a `field_declaration`'s own
            // `static` modifier is what `has_modifier` checks directly.
            let is_static = node.kind() == "constant_declaration" || has_modifier(node, "static");
            for declarator in children_by_field_name(node, "declarator") {
                let is_array = java_binding_declares_array(declarator);
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
                match field_anchors.entry((owner, text.into())) {
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(Some(FieldDeclarationAnchor {
                            anchor,
                            is_static,
                            is_array,
                        }));
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
    JavaDeclarationInventory {
        field_anchors,
        type_roots,
    }
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
                let type_node = node
                    .child_by_field_name("type")
                    .or_else(|| {
                        node.parent()
                            .and_then(|declaration| declaration.child_by_field_name("type"))
                    })
                    .or_else(|| {
                        named_children(node)
                            .into_iter()
                            .find(|child| child.kind() == "catch_type")
                    });
                if let Some(type_node) = type_node {
                    if let Some(type_name) = node_text(self.prepared.source(), type_node) {
                        self.local_types.insert(value, type_name.into());
                    }
                    self.local_type_nodes.insert(value, type_node);
                }
                if java_binding_declares_array(node) {
                    self.array_values.insert(value);
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
        let slots = formal_parameter_slots_for_owner_with_nodes(
            Language::Java,
            callable,
            self.prepared.source(),
        )
        .unwrap_or_default();
        let mut ordinal = 0_u32;
        for (slot, node) in slots {
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
                if java_binding_declares_array(node) {
                    self.array_values.insert(value);
                }
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

    pub(super) fn source_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        kind: SemanticValueKind,
    ) -> Result<ValueId, JavaLoweringError> {
        let metadata = self.value_mapping(builder, node)?;
        self.session
            .add_value_with_metadata(builder, metadata, kind)
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

    /// The canonical value-flow slot a lexical reference (`this` or a bare
    /// identifier) names in this procedure, and the [`ValueFlowKind`] that
    /// names its role: a still-in-scope local variable's own declaration
    /// value (`Local`), a formal parameter's own value (`Parameter`), the
    /// procedure's own receiver value (`Receiver`), or a captured outer
    /// receiver reached through `this` inside a nested class (`Local`,
    /// because a capture slot is read the same way a local is). `None` when
    /// `node` does not resolve to any binding this procedure tracks (for
    /// example, a field or type name, or an identifier with neither a local
    /// nor a parameter binding).
    ///
    /// This is the single source of truth both directions of lexical value
    /// flow share: reading a binding (`emit_lexical_input_flow`, the
    /// existing local-flows-into-this-read edge every use of a local or
    /// parameter already relies on) and writing back to one after a call
    /// that may have mutated the object it names (`emit_receiver_write_back`,
    /// #2571). Keeping one resolver means the two directions can never drift
    /// apart on which node names which slot.
    fn lexical_reference_binding(&self, node: Node<'tree>) -> Option<(ValueId, ValueFlowKind)> {
        let name = node_text(self.prepared.source(), node)?;
        if node.kind() == "this" {
            if let Some(captured) = self.captured_receiver {
                Some((captured, ValueFlowKind::Local))
            } else {
                self.receiver.map(|value| (value, ValueFlowKind::Receiver))
            }
        } else if node.kind() == "identifier" {
            if let Some(local) = self.local_at(name, node.start_byte()) {
                Some((local, ValueFlowKind::Local))
            } else {
                self.parameters
                    .get(name)
                    .copied()
                    .map(|value| (value, ValueFlowKind::Parameter))
            }
        } else {
            None
        }
    }

    pub(super) fn emit_lexical_input_flow(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        point: ProgramPointId,
        target: ValueId,
    ) -> Result<(), JavaLoweringError> {
        let Some((source, kind)) = self.lexical_reference_binding(node) else {
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

    /// The [`MemoryLocationKind::Field`] a *bare* (unqualified) identifier
    /// names, when it unambiguously names a non-`static` instance field
    /// declared directly on the procedure's own enclosing type (#2573).
    ///
    /// Java resolves an unqualified name that is not a local or a formal
    /// parameter (already ruled out by the caller, which always checks
    /// [`Self::lexical_reference_binding`] first: a local or parameter
    /// shadows a field of the same name) as an implicit `this.field` --
    /// `LDAPManager.closeDirContext`'s own body, `if (ctx != null)
    /// ctx.close();`, is exactly this shape, `ctx` a `private DirContext
    /// ctx;` instance field. Before this fix, nothing connected such a read
    /// (or, symmetrically, an assignment target -- see
    /// [`Self::emit_implicit_field_store`]) to any memory location at all:
    /// the identifier lowered as a bare, unconnected `Temporary` value, so a
    /// call reading it as a receiver could never bind a summary transfer's
    /// `Receiver` port to any carrier (`ValueFlowPlan::model_is_fully_bindable`
    /// requires one), which left the containing procedure's own value-flow
    /// snapshot permanently `Unknown` -- not a taint-propagation gap, a
    /// missing identity for the receiver value itself, verified directly by
    /// instrumenting `procedure_relations`/`dispatch_boundary_is_fully_modeled`
    /// against a reduced fixture and a parameter-typed control that receives
    /// the identical two-hop call shape and completes cleanly.
    ///
    /// Resolution is deliberately narrow and fails closed rather than guess:
    /// `None` when this procedure has no receiver at all (a `static` method;
    /// Java itself never lets a bare identifier there name an instance
    /// field), when no type directly enclosing `node` declares a field with
    /// this exact name (an inherited field, or one on an unrelated type, is
    /// a different, unaddressed question -- #2444's own heap-identity epic,
    /// not this fix), when more than one declaration shares the name
    /// (`field_declaration_anchors` itself already collapses that case to
    /// `None`, the same ambiguity rule `memory_member_locator` already
    /// trusts), or when the matched declaration is `static` (a shared,
    /// class-wide slot is not `this`-scoped at all -- a bare identifier
    /// naming one is real Java, common even, and is left exactly as
    /// unmodeled as it was before this fix, not silently misidentified as an
    /// instance field). A local or parameter of the same name is never
    /// reached here in the first place: every caller checks
    /// `lexical_reference_binding` first, and Java's own shadowing rule
    /// means a local or parameter always wins.
    ///
    /// This never bridges two different receivers on field-name equality
    /// alone, the one thing the task's own instructions forbid: `owner` is
    /// the type *directly enclosing this exact syntax occurrence*, not a
    /// declared or inferred type of some other expression, so two unrelated
    /// classes that happen to declare a same-named field can never resolve
    /// to the same location through this path, and a field on some *other*
    /// object (`other.ctx`, an explicit qualifier) never reaches this
    /// function at all -- it is a `field_access` node, handled by the
    /// existing, separate `memory_member_locator` path, untouched by this
    /// fix.
    fn implicit_instance_field_locator(
        &self,
        node: Node<'tree>,
    ) -> Option<(SemanticLocator, Box<str>)> {
        if node.kind() != "identifier" {
            return None;
        }
        // Java's own shadowing rule: a local or parameter wins for an
        // unqualified identifier. Explicit `this.field` accesses do not use
        // this path and remain fields even when a lexical binding shares the
        // name.
        if self.lexical_reference_binding(node).is_some() {
            return None;
        }
        // An implicit field access needs `this` to exist at all: a `static`
        // method has none, and Java itself never lets a bare identifier
        // there name an instance field.
        self.receiver?;
        let name = node_text(self.prepared.source(), node)?;
        let field = self.enclosing_field_declaration(node)?;
        if field.is_static {
            return None;
        }
        let procedure = self.session.locator();
        Some((
            SemanticLocator::new(
                procedure.mount(),
                procedure.path().clone(),
                procedure.language(),
                procedure.declaration().clone(),
                SemanticRole::MemoryLocation,
                field.anchor,
            ),
            name.into(),
        ))
    }

    /// The single, per-procedure "virtual local" carrier this procedure
    /// tracks for reads/writes of `name` through an implicit `this.field`
    /// access (#2573), lazily minted on first use and reused for every later
    /// occurrence within this same procedure.
    ///
    /// A field has no single declaration `ValueId` the way a local variable
    /// does -- every occurrence mints its own fresh use
    /// (`expression_value`, keyed by syntax node) -- so
    /// [`Self::emit_implicit_field_load`]/[`Self::emit_implicit_field_store`]/
    /// [`Self::emit_implicit_field_receiver_write_back`] alone (each wiring
    /// only a `MemoryLoad`/`MemoryStore` to the field's own heap location)
    /// cannot reuse #2571's own local-declaration-value mechanism directly.
    /// The field/heap machinery those effects also feed
    /// (#2444-adjacent access-path handling, #2538/#2545's `FieldMemory`
    /// capability) is real and load-bearing for cross-procedure heap
    /// soundness, but it treats a store to `Field { base: this, .. }` as a
    /// *weak* update (`store_holds_strong_update` in
    /// `workspace_oracle/value_flow.rs` declines whenever the base is not
    /// itself locally allocated, and `this` -- a parameter, not an
    /// allocation of *this* procedure -- never is): additive, correctly
    /// sound, but *not* precise enough on its own to prove the task's own
    /// required property, that a genuine reassignment between two calls
    /// still separates them. Verified directly, not assumed: wiring the
    /// write-back purely through `MemoryStore` reached `ProvenBySummary`
    /// with the real flow (`positive_box_mutate_then_read_within_one_method`,
    /// `findings == 1`) but also connected straight through an intervening
    /// reassignment (`reassignment_negative_within_one_method` regressed to
    /// `findings == 1`, the false green the task's own required negative
    /// exists to catch), because nothing in that mechanism alone kills a
    /// prior fact on reassignment.
    ///
    /// This carrier is the fix: a second, additional value this procedure
    /// mints once per field name, connected exactly the way #2571 already
    /// proved correct for locals -- a read edge into it
    /// (`ValueFlowKind::Local`, from `emit_implicit_field_load`), an
    /// unconditional kill on a genuine assignment
    /// (`SemanticEffect::Assignment` plus a `ValueFlowKind::Local` edge, from
    /// `emit_implicit_field_store`, the same shape `assignment_expression`'s
    /// own local-target branch already uses), and an additive write-back
    /// from a mutating call (`ValueFlowKind::LanguageDefined`, from
    /// `emit_implicit_field_receiver_write_back`, never a kill, so a
    /// non-mutating call contributes nothing). `value_flow::client::kills_target`
    /// treats the `Assignment`-kind edge as an unconditional kill whenever
    /// source and target differ, firing strictly later, in program order,
    /// than any write-back edge before it -- exactly #2571's own proof for
    /// why reassignment separates. Verified directly after adding this
    /// carrier: `reassignment_negative_within_one_method` reports
    /// `findings == 0` again.
    ///
    /// Scoped to *this procedure only* -- a fresh `HashMap`, never persisted
    /// or shared across procedures -- so it never claims a cross-procedure
    /// connection (`LDAPManager`'s own constructor-sets/`closeDirContext`-reads
    /// shape) that only the `MemoryLoad`/`MemoryStore` heap relations, with
    /// their own honest weak-update semantics, may still soundly (not
    /// precisely) carry. This carrier answers only the provable,
    /// same-instance, same-procedure, no-reassignment-between question the
    /// task names as likely provable today; anything beyond that -- proving
    /// two different procedures' own `this` values are the same allocation --
    /// remains the `MemoryLoad`/`MemoryStore` path's own, separate, weaker
    /// claim, unchanged by this carrier.
    fn implicit_field_carrier(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        name: &str,
        anchor: SourceAnchor,
    ) -> Result<ValueId, JavaLoweringError> {
        if let Some(value) = self.implicit_field_values.get(name) {
            return Ok(*value);
        }
        let metadata = self
            .session
            .add_mapping(builder, anchor, SourceMappingKind::Exact)?;
        let value =
            self.session
                .add_value_with_metadata(builder, metadata, SemanticValueKind::Local)?;
        self.implicit_field_values.insert(name.into(), value);
        Ok(value)
    }

    /// Reads a bare identifier that names an implicit instance field
    /// (#2573) as a `MemoryLoad`, exactly the shape an explicit
    /// `this.field`/`object.field` access already lowers to (the
    /// `"field_access"` arm of `LoweringContext::expression`), giving the
    /// read value the memory-location-sourced relation it needs to bind a
    /// carrier -- unlike an ordinary lexical read, whose value already comes
    /// from a tracked binding, a field's own identity is a location, not a
    /// value, so this is a `MemoryLoad`, not a `ValueFlow` edge. Always
    /// `resolved = true` (no [`Self::add_field_identity_gap`]): a bare
    /// identifier is provably `this.field`, with no aliasing or
    /// type-inference question at all, unlike an explicit qualifier's own
    /// object expression, whose type may not be known.
    pub(super) fn emit_implicit_field_load(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        point: ProgramPointId,
        result: ValueId,
    ) -> Result<(), JavaLoweringError> {
        let Some((member, name)) = self.implicit_instance_field_locator(node) else {
            return Ok(());
        };
        let base = self
            .receiver
            .expect("implicit_instance_field_locator only resolves when a receiver exists");
        let field_anchor = member.anchor();
        let location = self.session.add_memory_location(
            builder,
            point,
            MemoryLocationKind::Field { base, member },
        )?;
        self.append_effect(
            builder,
            point,
            SemanticEffect::MemoryLoad {
                kind: MemoryAccessKind::Field,
                location,
                result,
            },
        )?;
        // #2573: also connect this read to the procedure's own per-field
        // virtual carrier -- see `implicit_field_carrier`'s own doc comment
        // for why the `MemoryLoad` above is not precise enough on its own.
        let carrier = self.implicit_field_carrier(builder, &name, field_anchor)?;
        if carrier != result {
            self.append_effect(
                builder,
                point,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Local,
                    source: carrier,
                    target: result,
                },
            )?;
        }
        Ok(())
    }

    /// Writes to a bare identifier that names an implicit instance field
    /// (#2573) as a `MemoryStore`, the write-side symmetry of
    /// [`Self::emit_implicit_field_load`]. Before this fix,
    /// `assignment_expression`'s own `left.kind() == "identifier"` branch
    /// resolved only a local or a parameter target; an unqualified field
    /// assignment (`LDAPManager`'s own constructor, `ctx =
    /// getDirContext();`) matched neither, so the assignment's own value
    /// effect was emitted but the field write itself was silently dropped --
    /// not merely unconnected, entirely unrepresented. This closes that gap
    /// symmetrically with the read side, using the same field/heap
    /// `MemoryStore`/`MemoryLoad` machinery #2538/#2545 already ground
    /// `FieldMemory` capability handling in, rather than inventing a second,
    /// parallel write-back mechanism.
    pub(super) fn emit_implicit_field_store(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        point: ProgramPointId,
        value: ValueId,
    ) -> Result<bool, JavaLoweringError> {
        let Some((member, name)) = self.implicit_instance_field_locator(node) else {
            return Ok(false);
        };
        let base = self
            .receiver
            .expect("implicit_instance_field_locator only resolves when a receiver exists");
        let field_anchor = member.anchor();
        let location = self.session.add_memory_location(
            builder,
            point,
            MemoryLocationKind::Field { base, member },
        )?;
        self.append_effect(
            builder,
            point,
            SemanticEffect::MemoryStore {
                kind: MemoryAccessKind::Field,
                location,
                value,
            },
        )?;
        // #2573: a genuine assignment unconditionally kills the procedure's
        // own per-field virtual carrier -- see `implicit_field_carrier`'s
        // own doc comment. Mirrors `assignment_expression`'s own local-target
        // branch exactly (an `Assignment` effect plus a `ValueFlowKind::Local`
        // edge), which is what gives a reassignment its required, later,
        // unconditional-kill property over any write-back edge before it.
        let carrier = self.implicit_field_carrier(builder, &name, field_anchor)?;
        self.append_effect(
            builder,
            point,
            SemanticEffect::Assignment {
                target: carrier,
                value,
            },
        )?;
        self.append_effect(
            builder,
            point,
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Local,
                source: value,
                target: carrier,
            },
        )?;
        Ok(true)
    }

    /// After a call whose receiver is an implicit `this.field` access,
    /// record that a later read of the same field may observe whatever the
    /// call's own receiver value carries once the call returns -- the field
    /// analogue of [`Self::emit_receiver_write_back`] (#2571), for #2573.
    ///
    /// [`Self::emit_implicit_field_load`] alone gives each read of a field
    /// its own memory-location-sourced carrier (fixing
    /// `ValueFlowPlan::model_is_fully_bindable`'s "the receiver needs some
    /// carrier" requirement, and with it the containing procedure's own
    /// value-flow snapshot completion), but that alone does not connect a
    /// *mutating* call's own composed fact to a *later* read: `box.mutate(x)`
    /// then `box.read()`, both implicit-field receivers, are two structurally
    /// independent `MemoryLoad`s from the same location, each fed only by
    /// whatever was already stored *before* that specific call, exactly the
    /// gap #2571 fixed for locals -- proven directly, not assumed:
    /// `positive_box_mutate_then_read_within_one_method` reached
    /// `ProvenBySummary` but `findings == 0` before this function existed.
    ///
    /// The fix mirrors #2571's own choice of mechanism at the layer fields
    /// actually use: rather than a `ValueFlow` edge into a local's
    /// declaration value (fields have no such single slot -- every read
    /// mints its own value, per occurrence, the same as a local's *reads*
    /// do), this emits a `MemoryStore` back into the location
    /// [`Self::emit_implicit_field_load`] itself resolves to (the same
    /// `base`/`member` pair, so it is provably the same location, not a
    /// name-equality guess). A later read's own `MemoryLoad` from that exact
    /// location then observes it through the existing field/heap relation
    /// machinery (#2444-adjacent access-path handling, #2538/#2545's
    /// `FieldMemory` capability), which already connects a store to a later
    /// load of the same location -- this function's only job is to make a
    /// call's *own* composed receiver output become such a store, the same
    /// way an ordinary assignment already does via
    /// [`Self::emit_implicit_field_store`].
    ///
    /// A genuine *reassignment* of the field between two calls still
    /// separates them on its own account, unaffected by this edge:
    /// `emit_implicit_field_store` (the assignment path) always emits its
    /// own, later `MemoryStore` to the same location, and the field/heap
    /// relation machinery's own store-ordering (the same ordering
    /// `LocalStoreBases`/strong-update reasoning already applies to every
    /// other field write) determines which store a given read observes --
    /// verified directly, not assumed:
    /// `reassignment_negative_within_one_method` (mutate, reassign, read)
    /// reports `findings == 0`.
    ///
    /// Never bridges two different objects' fields: `location` is rebuilt
    /// from `self.receiver` (this procedure's own, single `this`) every
    /// time, so it can only ever name the current instance's own field,
    /// never another object's, regardless of how many other objects of the
    /// same class exist elsewhere -- verified directly:
    /// `cross_object_negative_two_instances` (two different `Helper`
    /// instances, one mutated, the other read) reports `findings == 0`.
    pub(super) fn emit_implicit_field_receiver_write_back(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        point: ProgramPointId,
        receiver_value: ValueId,
    ) -> Result<(), JavaLoweringError> {
        let Some((member, name)) = self.implicit_instance_field_locator(node) else {
            return Ok(());
        };
        let base = self
            .receiver
            .expect("implicit_instance_field_locator only resolves when a receiver exists");
        let field_anchor = member.anchor();
        let location = self.session.add_memory_location(
            builder,
            point,
            MemoryLocationKind::Field { base, member },
        )?;
        self.append_effect(
            builder,
            point,
            SemanticEffect::MemoryStore {
                kind: MemoryAccessKind::Field,
                location,
                value: receiver_value,
            },
        )?;
        // #2573: also carry the call's own composed receiver fact into the
        // procedure's own per-field virtual carrier, additively (never a
        // kill) -- see `implicit_field_carrier`'s own doc comment for why
        // this, not the `MemoryStore` above alone, is what makes the
        // required positive (mutate then read, within one method) connect
        // while still letting a later genuine reassignment separate them.
        let carrier = self.implicit_field_carrier(builder, &name, field_anchor)?;
        if carrier != receiver_value {
            self.append_effect(
                builder,
                point,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::LanguageDefined,
                    source: receiver_value,
                    target: carrier,
                },
            )?;
        }
        Ok(())
    }

    /// After a call whose receiver names a lexical binding this procedure
    /// tracks (a still-in-scope local variable, a formal parameter, or
    /// `this`), record that a later read of that same binding may observe
    /// whatever the call's own receiver value carries once the call returns
    /// (#2571).
    ///
    /// Without this edge, two reads of one never-reassigned local at two
    /// different call sites -- `map.put(key, value)` then `map.get(key)` --
    /// get two different value-flow carriers with no relation connecting
    /// them: each read of `map` is lowered as its own fresh use
    /// (`expression_value` caches by syntax node, not by binding), fed only
    /// by a one-way edge *from* `map`'s own declaration value *into* that
    /// read's value (`emit_lexical_input_flow`, above). A mutating call's
    /// authored summary -- `java.util.HashMap.put`'s shipped summary carries
    /// a `receiver -> receiver` transfer meaning "the object persists,
    /// possibly changed" -- can then compose a tainted fact onto `put`'s own
    /// receiver value, but nothing carries that fact back out to `map`'s own
    /// declaration value, so `get`'s own, separately-fed receiver read never
    /// sees it. This edge is the missing return trip: `receiver_value` (the
    /// same value already bound as this call's `CallSiteScaffold.receiver`,
    /// so it is exactly the value the plan's `summary_port_carrier` resolves
    /// the call's `Receiver` port to) flows into the binding's own value at
    /// `point` (the call's normal-continuation point, after the call's own
    /// effects), so a later read's edge *from* the binding carries forward
    /// whatever this call's boundary transfer placed on the receiver.
    ///
    /// Deliberately additive (`ValueFlowKind::LanguageDefined`, which
    /// `value_flow::client::kills_target` never treats as a kill -- unlike
    /// `ValueFlowKind::Local`, which `assignment_expression`'s own
    /// reassignment handling uses precisely because it *should* kill), not a
    /// redefinition of the binding: most calls do not mutate their receiver
    /// at all (`java.util.HashMap.get`'s own shipped summary has no
    /// `receiver -> receiver` transfer, so no fact survives on a `get`
    /// call's own receiver value past its own call-to-return edge, and this
    /// edge then carries nothing forward -- a harmless no-op), and this edge
    /// must never erase a fact already active on the binding going into the
    /// call just because the call happened. A genuine reassignment of the
    /// same binding between two calls still separates their carriers on its
    /// own account, unaffected by this edge's own non-killing kind:
    /// `assignment_expression` emits an `Assignment` effect at the
    /// reassignment's own point (`SemanticEffect::Assignment { target:
    /// binding, .. }`, matched to `ValueFlowRelationKind::Assignment` in
    /// `relation_matches_event`), which
    /// `value_flow::client::kills_target` treats as an unconditional kill of
    /// the binding's prior facts whenever source and target differ -- and
    /// that kill fires strictly later in program order than any call before
    /// it, so it discards whatever this edge contributed earlier regardless.
    pub(super) fn emit_receiver_write_back(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        point: ProgramPointId,
        receiver_value: ValueId,
    ) -> Result<(), JavaLoweringError> {
        let Some((binding, _)) = self.lexical_reference_binding(node) else {
            return Ok(());
        };
        if binding != receiver_value {
            self.append_effect(
                builder,
                point,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::LanguageDefined,
                    source: receiver_value,
                    target: binding,
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

    pub(super) fn field_access_is_type_qualifier(&self, node: Node<'tree>) -> bool {
        java_field_access_is_type_qualifier(
            node,
            self.prepared.source(),
            |root| self.root_identifier_is_value(root, node),
            |root| self.type_name_roots.contains(root),
        )
    }

    /// Whether this exact field-access syntax is Java's built-in array
    /// `length` property rather than an object field with the same name.
    ///
    /// The proof is intentionally syntax-backed: the field node must spell
    /// `length`, and the receiver must either construct/cast an array here or
    /// resolve to a lexical binding whose declaration contains array type
    /// syntax. Unknown receiver types keep the ordinary FieldMemory lowering.
    pub(super) fn field_access_is_array_length(&self, node: Node<'tree>) -> bool {
        let Some(field) = node.child_by_field_name("field") else {
            return false;
        };
        if node_text(self.prepared.source(), field) != Some("length") {
            return false;
        }
        node.child_by_field_name("object")
            .is_some_and(|object| self.expression_is_array(object))
    }

    fn expression_is_array(&self, node: Node<'tree>) -> bool {
        match node.kind() {
            "array_creation_expression" => true,
            "identifier" => {
                if let Some((value, _)) = self.lexical_reference_binding(node) {
                    self.array_values.contains(&value)
                } else {
                    self.enclosing_field_declaration(node)
                        .is_some_and(|field| field.is_array)
                }
            }
            "field_access" => {
                let Some(object) = node.child_by_field_name("object") else {
                    return false;
                };
                let Some(field) = node.child_by_field_name("field") else {
                    return false;
                };
                object.kind() == "this"
                    && self
                        .enclosing_field_declaration(field)
                        .is_some_and(|field| field.is_array)
            }
            "parenthesized_expression" => {
                first_named_child(node).is_some_and(|inner| self.expression_is_array(inner))
            }
            "cast_expression" => node
                .child_by_field_name("type")
                .is_some_and(java_type_syntax_is_array),
            _ => false,
        }
    }

    /// The unambiguous field declared directly on the type enclosing this
    /// exact identifier. This fact is useful both for implicit-field memory
    /// identity and for array-type proof; callers apply lexical-shadowing,
    /// static, or receiver restrictions appropriate to their syntax shape.
    fn enclosing_field_declaration(&self, node: Node<'tree>) -> Option<FieldDeclarationAnchor> {
        if node.kind() != "identifier" {
            return None;
        }
        let name = node_text(self.prepared.source(), node)?;
        let owner = enclosing_type_name(self.prepared.source(), node)?;
        *self.field_declaration_anchors.get(&(owner, name.into()))?
    }

    fn root_identifier_is_value(&self, name: &str, access: Node<'tree>) -> bool {
        if self.local_at(name, access.start_byte()).is_some() || self.parameters.contains_key(name)
        {
            return true;
        }
        let Some(owner) = enclosing_type_name(self.prepared.source(), access) else {
            return false;
        };
        self.field_declaration_anchors
            .contains_key(&(owner, name.into()))
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
            .and_then(|entry| *entry)
            .map(|field| field.anchor)
            .or_else(|| {
                (object.kind() == "this")
                    .then(|| self.enclosing_field_declaration(node))
                    .flatten()
                    .map(|field| field.anchor)
            })
            .or_else(|| self.array_element_field_anchor(object, node));
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

    /// Resolve a member access whose receiver is a local array element through
    /// the declared component type. The receiver is intentionally limited to
    /// a direct identifier-backed local array and a single structured
    /// `array_type` node; parameters, aliases, inferred values, and nested
    /// expressions retain the ordinary occurrence locator and identity gap.
    /// This is a syntax-backed declaration proof, not a name-based fallback.
    fn array_element_field_anchor(
        &self,
        object: Node<'tree>,
        field: Node<'tree>,
    ) -> Option<SourceAnchor> {
        if object.kind() != "array_access" {
            return None;
        }
        let array = object.child_by_field_name("array")?;
        if array.kind() != "identifier" {
            return None;
        }
        let name = node_text(self.prepared.source(), array)?;
        let array_value = self.local_at(name, array.start_byte())?;
        let array_type = self.local_type_nodes.get(&array_value)?;
        if array_type.kind() != "array_type" {
            return None;
        }
        let element_type = array_type.child_by_field_name("element")?;
        let owner = node_text(self.prepared.source(), element_type)?;
        let field_name = node_text(self.prepared.source(), field)?;
        self.field_declaration_anchors
            .get(&(owner.into(), field_name.into()))
            .and_then(|entry| *entry)
            .map(|field| field.anchor)
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
