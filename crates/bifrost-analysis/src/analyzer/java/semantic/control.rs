use super::syntax::*;
use super::values::java_declaration_inventory;
use super::*;

pub(super) fn lower_procedure<'tree, 'targets>(
    prepared: &'tree PreparedSyntaxTree,
    spec: &ProcedureSpec<'tree>,
    procedure_targets: &'targets HashMap<usize, NestedProcedureTarget>,
    budget: &SemanticBudget,
    cancellation: &'targets CancellationToken,
) -> Result<(ProcedureSemanticsParts, SemanticWork), JavaLoweringError> {
    let mut parts = ProcedureSemanticsParts::new(
        spec.id,
        spec.locator.clone(),
        spec.kind,
        SourceMappingId::new(0),
        EvidenceId::new(0),
    );
    parts.lexical_parent = spec.lexical_parent;
    parts.properties = spec.properties;
    let ProcedureLoweringStart {
        mut builder,
        session,
        entry,
        normal_exit,
        exceptional_exit,
        function_scope,
    } = ProcedureLoweringSession::start(parts, budget, cancellation)?;
    let declaration_inventory = java_declaration_inventory(prepared);
    let mut context = LoweringContext {
        prepared,
        session,
        expression_values: HashMap::default(),
        constant_index_values: HashMap::default(),
        field_declaration_anchors: declaration_inventory.field_anchors,
        type_name_roots: declaration_inventory.type_roots,
        local_types: HashMap::default(),
        non_null_values: HashSet::default(),
        catch_binders: HashMap::default(),
        parameters: HashMap::default(),
        locals: HashMap::default(),
        implicit_field_values: HashMap::default(),
        receiver: None,
        captured_receiver: None,
        procedure_targets,
        cleanups: Vec::new(),
    };
    context.emit_procedure_inputs(&mut builder, spec.callable, spec.kind, spec.properties)?;
    context.emit_captured_receiver(&mut builder, entry, spec)?;
    context.emit_local_bindings(&mut builder, spec.body)?;

    // #2553: "source-order composition across initializer fragments" is the
    // gap's own documented reason (JLS 12.4.2/12.5 compose every static-or-
    // instance field initializer and initializer block in one class body
    // into one ordered sequence). That reason cannot apply when this
    // fragment is provably the only member of its scheduling group: there is
    // nothing to compose it with, so its value is exactly what it computes.
    // Emitting the gap unconditionally made it the single most common gap in
    // the whole OWASP corpus census (#2545) -- dominated by the ordinary
    // `private static final long serialVersionUID = 1L;` boilerplate, which
    // has no sibling to interleave with. A genuine multi-fragment class (two
    // field initializers, a field initializer plus an initializer block, and
    // so on) still gets the gap on every one of its fragments.
    if spec.kind == ProcedureKind::Initializer
        && !is_sole_initializer_fragment(spec.callable, spec.properties.is_static)
    {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::DeferredExecution,
            SemanticGapKind::Unsupported,
            "initializer scheduling and source-order composition across initializer fragments are not yet modeled",
        )?;
    }
    if spec.kind == ProcedureKind::Constructor
        && !named_children(spec.body)
            .into_iter()
            .any(|child| child.kind() == "explicit_constructor_invocation")
    {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unsupported,
            "implicit super-constructor invocation is not yet represented as a call site",
        )?;
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            "implicit super-constructor invocation can complete exceptionally",
        )?;
    }

    let body_entry = context.point(&mut builder, spec.body, Vec::new())?;
    let initial = if matches!(spec.body.kind(), "block" | "constructor_body") {
        Work::Statement {
            node: spec.body,
            entry: body_entry,
            next: EdgeTarget::normal(normal_exit),
            scope: function_scope,
        }
    } else if spec.kind == ProcedureKind::Initializer {
        Work::Expression {
            node: spec.body,
            entry: body_entry,
            next: EdgeTarget::normal(normal_exit),
            scope: function_scope,
        }
    } else {
        let implicit_return = context.point(&mut builder, spec.body, Vec::new())?;
        let source =
            context.expression_value(&mut builder, spec.body, expression_value_kind(spec.body))?;
        let value = context.value(&mut builder, implicit_return, SemanticValueKind::Return)?;
        context.append_effect(
            &mut builder,
            implicit_return,
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Return,
                source,
                target: value,
            },
        )?;
        context.append_effect(
            &mut builder,
            implicit_return,
            SemanticEffect::ProcedureReturn { value: Some(value) },
        )?;
        context.edge(
            &mut builder,
            implicit_return,
            EdgeTarget::normal(normal_exit),
        )?;
        Work::Expression {
            node: spec.body,
            entry: body_entry,
            next: EdgeTarget::normal(implicit_return),
            scope: function_scope,
        }
    };
    context.edge(&mut builder, entry, EdgeTarget::normal(body_entry))?;

    drive_and_finish_procedure(
        builder,
        [initial],
        entry,
        normal_exit,
        exceptional_exit,
        cancellation,
        |builder, work, stack| context.step(builder, work, stack),
    )
}

impl<'tree, 'targets> LoweringContext<'tree, 'targets> {
    fn local_declaration(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), JavaLoweringError> {
        let initializers = children_by_field_name(node, "declarator")
            .into_iter()
            .filter_map(|declarator| {
                let name = declarator.child_by_field_name("name")?;
                let initializer = declarator.child_by_field_name("value")?;
                (name.kind() == "identifier").then_some((declarator, name, initializer))
            })
            .collect::<Vec<_>>();
        if initializers.is_empty() {
            return self.edge(builder, entry, next);
        }

        let expression_entries = initializers
            .iter()
            .map(|(_, _, initializer)| self.point(builder, *initializer, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        let terminals = initializers
            .iter()
            .map(|(declarator, _, _)| self.point(builder, *declarator, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        self.edge(builder, entry, EdgeTarget::normal(expression_entries[0]))?;
        for (index, (_, name, initializer)) in initializers.iter().enumerate().rev() {
            let target_name = node_text(self.prepared.source(), *name).ok_or_else(|| {
                JavaLoweringError::Invalid("local declaration has invalid name range".into())
            })?;
            let target = self
                .local_declaration_value(target_name, name.start_byte())
                .ok_or_else(|| {
                    JavaLoweringError::Invalid("local declaration was not preindexed".into())
                })?;
            if self.expression_is_non_null(*initializer) {
                self.non_null_values.insert(target);
            }
            let value =
                self.expression_value(builder, *initializer, expression_value_kind(*initializer))?;
            self.append_effect(
                builder,
                terminals[index],
                SemanticEffect::Assignment { target, value },
            )?;
            self.append_effect(
                builder,
                terminals[index],
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Local,
                    source: value,
                    target,
                },
            )?;
            let following = expression_entries
                .get(index + 1)
                .copied()
                .map(EdgeTarget::normal)
                .unwrap_or(next);
            self.edge(builder, terminals[index], following)?;
            stack.push(Work::Expression {
                node: *initializer,
                entry: expression_entries[index],
                next: EdgeTarget::normal(terminals[index]),
                scope,
            });
        }
        Ok(())
    }

    fn assignment_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), JavaLoweringError> {
        let left = required_field(node, "left")?;
        let right = required_field(node, "right")?;
        let terminal = self.point(builder, node, Vec::new())?;
        let value = self.expression_value(builder, right, expression_value_kind(right))?;
        let result = self.expression_value(builder, node, expression_value_kind(node))?;
        self.append_effect(
            builder,
            terminal,
            SemanticEffect::Assignment {
                target: result,
                value,
            },
        )?;

        let evaluations = if left.kind() == "identifier" {
            let name = node_text(self.prepared.source(), left).ok_or_else(|| {
                JavaLoweringError::Invalid("assignment has invalid target range".into())
            })?;
            let local = self.local_at(name, left.start_byte());
            let target = local.or_else(|| self.parameters.get(name).copied());
            if let Some(target) = target {
                if local.is_some() && self.expression_is_non_null(right) {
                    self.non_null_values.insert(target);
                }
                let kind = if local.is_some() {
                    ValueFlowKind::Local
                } else {
                    ValueFlowKind::Parameter
                };
                self.append_effect(
                    builder,
                    terminal,
                    SemanticEffect::Assignment { target, value },
                )?;
                self.append_effect(
                    builder,
                    terminal,
                    SemanticEffect::ValueFlow {
                        kind,
                        source: value,
                        target,
                    },
                )?;
            } else {
                // #2573: not a local or a parameter -- may still be an
                // implicit `this.field` write (`LDAPManager`'s own
                // constructor, `ctx = getDirContext();`). Symmetric with the
                // read side (`emit_implicit_field_load`); a no-op when
                // `left` does not unambiguously name a non-`static` instance
                // field on the enclosing type.
                self.emit_implicit_field_store(builder, left, terminal, value)?;
            }
            vec![right]
        } else if left.kind() == "field_access" && !self.field_access_is_type_qualifier(left) {
            let object = required_field(left, "object")?;
            let field = required_field(left, "field")?;
            let base = self.expression_value(builder, object, expression_value_kind(object))?;
            let (member, resolved) = self.memory_member_locator(field, object)?;
            let location = self.session.add_memory_location(
                builder,
                terminal,
                MemoryLocationKind::Field { base, member },
            )?;
            if !resolved {
                self.add_field_identity_gap(builder, terminal, location)?;
            }
            self.append_effect(
                builder,
                terminal,
                SemanticEffect::MemoryStore {
                    kind: MemoryAccessKind::Field,
                    location,
                    value,
                },
            )?;
            vec![object, right]
        } else if left.kind() == "array_access" {
            let array = required_field(left, "array")?;
            let index = required_field(left, "index")?;
            let base = self.expression_value(builder, array, expression_value_kind(array))?;
            let index_value = self.index_value(builder, index)?;
            let location = self.session.add_memory_location(
                builder,
                terminal,
                MemoryLocationKind::Index {
                    base,
                    index: Some(index_value),
                },
            )?;
            self.append_effect(
                builder,
                terminal,
                SemanticEffect::MemoryStore {
                    kind: MemoryAccessKind::Index,
                    location,
                    value,
                },
            )?;
            vec![array, index, right]
        } else {
            runtime_expression_children(node)
        };
        self.edge(builder, terminal, next)?;
        self.schedule_expressions(
            builder,
            entry,
            &evaluations,
            EdgeTarget::normal(terminal),
            scope,
            stack,
        )
    }

    fn step(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        work: Work<'tree>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), JavaLoweringError> {
        if self.session.cancellation().is_cancelled() {
            return Err(JavaLoweringError::Cancelled(Box::default()));
        }
        match work {
            Work::Statement {
                node,
                entry,
                next,
                scope,
            } => self.statement(builder, node, entry, next, scope, None, stack),
            Work::LabeledStatement {
                node,
                label,
                entry,
                next,
                scope,
            } => self.statement(builder, node, entry, next, scope, Some(label), stack),
            Work::Expression {
                node,
                entry,
                next,
                scope,
            } => self.expression(builder, node, entry, next, scope, stack),
            Work::Condition {
                node,
                entry,
                when_true,
                when_false,
                scope,
            } => self.condition(builder, node, entry, when_true, when_false, scope, stack),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn condition(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        when_true: EdgeTarget,
        when_false: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), JavaLoweringError> {
        match (node.kind(), binary_operator(node)) {
            // A folded literal keeps exactly one arm. Recording the guard is
            // the whole point of this slice: after the fold, nothing else in
            // the artifact says the branch was constant (#2443).
            ("true", _) => {
                self.edge(builder, entry, when_true)?;
                self.record_guard(builder, entry, node, Some(when_true), None)
            }
            ("false", _) => {
                self.edge(builder, entry, when_false)?;
                self.record_guard(builder, entry, node, None, Some(when_false))
            }
            ("binary_expression", Some("&&")) => {
                let left = required_field(node, "left")?;
                let right = required_field(node, "right")?;
                let right_entry = self.point(builder, right, Vec::new())?;
                schedule_short_circuit_condition(
                    stack,
                    ShortCircuitKind::And,
                    (left, entry),
                    (right, right_entry),
                    when_true,
                    when_false,
                    scope,
                    Work::condition,
                );
                Ok(())
            }
            ("binary_expression", Some("||")) => {
                let left = required_field(node, "left")?;
                let right = required_field(node, "right")?;
                let right_entry = self.point(builder, right, Vec::new())?;
                schedule_short_circuit_condition(
                    stack,
                    ShortCircuitKind::Or,
                    (left, entry),
                    (right, right_entry),
                    when_true,
                    when_false,
                    scope,
                    Work::condition,
                );
                Ok(())
            }
            ("ternary_expression", _) => {
                let condition = required_field(node, "condition")?;
                let consequence = required_field(node, "consequence")?;
                let alternative = required_field(node, "alternative")?;
                let consequence_entry = self.point(builder, consequence, Vec::new())?;
                let alternative_entry = self.point(builder, alternative, Vec::new())?;
                schedule_conditional_choice(
                    stack,
                    (condition, entry),
                    (consequence, consequence_entry),
                    (alternative, alternative_entry),
                    when_true,
                    when_false,
                    scope,
                    Work::condition,
                );
                Ok(())
            }
            ("parenthesized_expression", _) => {
                let value = first_named_child(node).ok_or_else(|| missing_field(node, "value"))?;
                stack.push(Work::Condition {
                    node: value,
                    entry,
                    when_true,
                    when_false,
                    scope,
                });
                Ok(())
            }
            _ => {
                let decision = self.point(builder, node, Vec::new())?;
                self.edge(builder, decision, when_true)?;
                self.edge(builder, decision, when_false)?;
                self.record_guard(builder, decision, node, Some(when_true), Some(when_false))?;
                stack.push(Work::Expression {
                    node,
                    entry,
                    next: EdgeTarget::normal(decision),
                    scope,
                });
                Ok(())
            }
        }
    }

    /// Publish one normalized guard fact for a decision the lowerer just made.
    ///
    /// A predicate is published only when Java's own structured syntax
    /// establishes it. Anything represented but not normalizable is recorded
    /// `Opaque` rather than guessed, so an absent guard row means the lowerer
    /// made no decision here at all -- which is what makes the
    /// [`SemanticCapability::GuardFacts`] entry readable.
    fn record_guard(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        condition: Node<'tree>,
        when_true: Option<EdgeTarget>,
        when_false: Option<EdgeTarget>,
    ) -> Result<(), JavaLoweringError> {
        let arm = |target: Option<EdgeTarget>| {
            target.map(|target| GuardArm {
                target_point: target.point,
                kind: target.kind,
            })
        };
        let (predicate, subject) = match self.normalize_condition(builder, condition)? {
            Some(normalized) => normalized,
            None => (
                GuardPredicate::Opaque {
                    digest: GuardConditionDigest::from_syntax_kind(condition.kind()),
                },
                // The condition's own value is the one thing an opaque guard
                // can honestly name: the decision tested it, whatever it means.
                Some(self.expression_value(
                    builder,
                    condition,
                    expression_value_kind(condition),
                )?),
            ),
        };
        self.session.add_guard_fact(
            builder,
            point,
            predicate,
            subject,
            arm(when_true),
            arm(when_false),
        )?;
        Ok(())
    }

    /// Normalize one Java condition into a guard predicate, or answer `None`
    /// when the syntax is represented but not normalizable.
    ///
    /// Every ingredient is a tree-sitter field: `operator`, `left`, `right`,
    /// `operand`. Nothing here reads source text, and a shape this function
    /// does not recognize becomes an explicit `Opaque` row rather than a
    /// guessed one.
    ///
    /// `!` and parentheses are peeled iteratively before the match, because a
    /// negated guard is the same guard with its outcome swapped rather than a
    /// decision of its own.
    fn normalize_condition(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        condition: Node<'tree>,
    ) -> Result<Option<(GuardPredicate, Option<ValueId>)>, JavaLoweringError> {
        let mut cursor = condition;
        let mut negated = false;
        loop {
            match cursor.kind() {
                "parenthesized_expression" => {
                    let Some(inner) = first_named_child(cursor) else {
                        return Ok(None);
                    };
                    cursor = inner;
                }
                "unary_expression"
                    if cursor
                        .child_by_field_name("operator")
                        .is_some_and(|operator| operator.kind() == "!") =>
                {
                    let Some(operand) = cursor.child_by_field_name("operand") else {
                        return Ok(None);
                    };
                    negated = !negated;
                    cursor = operand;
                }
                _ => break,
            }
        }

        match cursor.kind() {
            "true" => {
                return Ok(Some((
                    GuardPredicate::ConstantBoolean { value: !negated },
                    None,
                )));
            }
            "false" => {
                return Ok(Some((
                    GuardPredicate::ConstantBoolean { value: negated },
                    None,
                )));
            }
            "binary_expression" => {}
            _ => return Ok(None),
        }

        let Some(operator) = cursor.child_by_field_name("operator") else {
            return Ok(None);
        };
        let equal_on_true = match operator.kind() {
            "==" => !negated,
            "!=" => negated,
            _ => return Ok(None),
        };
        let (Some(left), Some(right)) = (
            cursor.child_by_field_name("left"),
            cursor.child_by_field_name("right"),
        ) else {
            return Ok(None);
        };

        // The null literal is itself a constant, so the null comparison has to
        // be decided before the general constant comparison.
        let null_subject = match (
            left.kind() == "null_literal",
            right.kind() == "null_literal",
        ) {
            (true, false) => Some(right),
            (false, true) => Some(left),
            (true, true) | (false, false) => None,
        };
        if let Some(subject) = null_subject {
            let subject =
                self.expression_value(builder, subject, expression_value_kind(subject))?;
            return Ok(Some((
                GuardPredicate::NullComparison {
                    null_on_true: equal_on_true,
                },
                Some(subject),
            )));
        }

        let left_constant = matches!(expression_value_kind(left), SemanticValueKind::Constant);
        let right_constant = matches!(expression_value_kind(right), SemanticValueKind::Constant);
        // Two constants compared with each other name no subject, so the
        // comparison is not a guard over anything and stays opaque.
        let (subject, constant) = match (left_constant, right_constant) {
            (true, false) => (right, left),
            (false, true) => (left, right),
            (true, true) | (false, false) => return Ok(None),
        };
        let constant = self.expression_value(builder, constant, SemanticValueKind::Constant)?;
        let subject = self.expression_value(builder, subject, expression_value_kind(subject))?;
        Ok(Some((
            GuardPredicate::ConstantEquality {
                negated: !equal_on_true,
                constant,
            },
            Some(subject),
        )))
    }

    #[allow(clippy::too_many_arguments)]
    fn statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        attached_label: Option<&'tree str>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), JavaLoweringError> {
        let scope = if let Some(label) = attached_label
            && !matches!(
                node.kind(),
                "while_statement"
                    | "do_statement"
                    | "for_statement"
                    | "enhanced_for_statement"
                    | "switch_expression"
            ) {
            builder.push_scope(
                Some(scope),
                ScopeBinding::Breakable {
                    label: Some(Box::<str>::from(label)),
                    accepts_unlabeled: false,
                    break_target: next.point,
                    break_edge_kind: next.kind,
                },
            )
        } else {
            scope
        };

        match node.kind() {
            "block" | "constructor_body" | "program" => {
                let children = named_children(node)
                    .into_iter()
                    .filter(|child| child.kind() != "comment")
                    .collect::<Vec<_>>();
                self.schedule_statements(builder, entry, &children, next, scope, stack)
            }
            "expression_statement" => {
                if let Some(expression) = first_named_child(node) {
                    stack.push(Work::Expression {
                        node: expression,
                        entry,
                        next,
                        scope,
                    });
                    Ok(())
                } else {
                    self.edge(builder, entry, next)
                }
            }
            "return_statement" => {
                let terminal = if let Some(value_node) = first_named_child(node) {
                    let point = self.point(builder, node, Vec::new())?;
                    let source = self.expression_value(
                        builder,
                        value_node,
                        expression_value_kind(value_node),
                    )?;
                    let value = self.value(builder, point, SemanticValueKind::Return)?;
                    self.append_effect(
                        builder,
                        point,
                        SemanticEffect::ValueFlow {
                            kind: ValueFlowKind::Return,
                            source,
                            target: value,
                        },
                    )?;
                    self.append_effect(
                        builder,
                        point,
                        SemanticEffect::ProcedureReturn { value: Some(value) },
                    )?;
                    stack.push(Work::Expression {
                        node: value_node,
                        entry,
                        next: EdgeTarget::normal(point),
                        scope,
                    });
                    point
                } else {
                    self.append_effect(
                        builder,
                        entry,
                        SemanticEffect::ProcedureReturn { value: None },
                    )?;
                    entry
                };
                self.abrupt(
                    builder,
                    terminal,
                    scope,
                    CompletionKind::Return,
                    None,
                    stack,
                )
            }
            "throw_statement" => {
                let value_node = first_named_child(node)
                    .ok_or_else(|| missing_field(node, "thrown expression"))?;
                let terminal = self.point(builder, node, Vec::new())?;
                let expression =
                    self.expression_value(builder, value_node, expression_value_kind(value_node))?;
                let value = self.value(builder, terminal, SemanticValueKind::Exception)?;
                self.append_effect(
                    builder,
                    terminal,
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Local,
                        source: expression,
                        target: value,
                    },
                )?;
                self.append_effect(
                    builder,
                    terminal,
                    SemanticEffect::Throw { value: Some(value) },
                )?;
                stack.push(Work::Expression {
                    node: value_node,
                    entry,
                    next: EdgeTarget::normal(terminal),
                    scope,
                });
                self.abrupt_throw(builder, terminal, scope, value, stack)
            }
            "yield_statement" => {
                let value_node = first_named_child(node)
                    .ok_or_else(|| missing_field(node, "yield expression"))?;
                let terminal = self.point(builder, node, Vec::new())?;
                stack.push(Work::Expression {
                    node: value_node,
                    entry,
                    next: EdgeTarget::normal(terminal),
                    scope,
                });
                self.abrupt(builder, terminal, scope, CompletionKind::Yield, None, stack)
            }
            "break_statement" | "continue_statement" => {
                let label = first_named_child(node)
                    .and_then(|label| node_text(self.prepared.source(), label));
                let kind = if node.kind() == "break_statement" {
                    CompletionKind::Break
                } else {
                    CompletionKind::Continue
                };
                self.abrupt(builder, entry, scope, kind, label, stack)
            }
            "if_statement" => {
                let condition = required_field(node, "condition")?;
                let consequence = required_field(node, "consequence")?;
                let alternative = node.child_by_field_name("alternative");
                let consequence_entry = self.point(builder, consequence, Vec::new())?;
                stack.push(Work::Statement {
                    node: consequence,
                    entry: consequence_entry,
                    next,
                    scope,
                });
                let false_target = if let Some(alternative) = alternative {
                    let alternative_entry = self.point(builder, alternative, Vec::new())?;
                    stack.push(Work::Statement {
                        node: alternative,
                        entry: alternative_entry,
                        next,
                        scope,
                    });
                    EdgeTarget {
                        point: alternative_entry,
                        kind: ControlEdgeKind::ConditionalFalse,
                    }
                } else {
                    EdgeTarget {
                        point: next.point,
                        kind: ControlEdgeKind::ConditionalFalse,
                    }
                };
                stack.push(Work::Condition {
                    node: condition,
                    entry,
                    when_true: EdgeTarget {
                        point: consequence_entry,
                        kind: ControlEdgeKind::ConditionalTrue,
                    },
                    when_false: false_target,
                    scope,
                });
                Ok(())
            }
            "while_statement" => {
                let condition = required_field(node, "condition")?;
                let body = required_field(node, "body")?;
                let body_entry = self.point(builder, body, Vec::new())?;
                let loop_scope = builder.push_scope(
                    Some(scope),
                    ScopeBinding::Loop {
                        label: attached_label.map(Box::<str>::from),
                        break_target: next.point,
                        break_edge_kind: next.kind,
                        continue_target: entry,
                        continue_edge_kind: ControlEdgeKind::LoopBack,
                    },
                );
                stack.push(Work::Statement {
                    node: body,
                    entry: body_entry,
                    next: EdgeTarget {
                        point: entry,
                        kind: ControlEdgeKind::LoopBack,
                    },
                    scope: loop_scope,
                });
                stack.push(Work::Condition {
                    node: condition,
                    entry,
                    when_true: EdgeTarget {
                        point: body_entry,
                        kind: ControlEdgeKind::ConditionalTrue,
                    },
                    when_false: EdgeTarget {
                        point: next.point,
                        kind: ControlEdgeKind::ConditionalFalse,
                    },
                    scope: loop_scope,
                });
                Ok(())
            }
            "do_statement" => {
                let body = required_field(node, "body")?;
                let condition = required_field(node, "condition")?;
                let condition_entry = self.point(builder, condition, Vec::new())?;
                let loop_scope = builder.push_scope(
                    Some(scope),
                    ScopeBinding::Loop {
                        label: attached_label.map(Box::<str>::from),
                        break_target: next.point,
                        break_edge_kind: next.kind,
                        continue_target: condition_entry,
                        continue_edge_kind: ControlEdgeKind::Normal,
                    },
                );
                stack.push(Work::Condition {
                    node: condition,
                    entry: condition_entry,
                    when_true: EdgeTarget {
                        point: entry,
                        kind: ControlEdgeKind::LoopBack,
                    },
                    when_false: EdgeTarget {
                        point: next.point,
                        kind: ControlEdgeKind::ConditionalFalse,
                    },
                    scope: loop_scope,
                });
                stack.push(Work::Statement {
                    node: body,
                    entry,
                    next: EdgeTarget::normal(condition_entry),
                    scope: loop_scope,
                });
                Ok(())
            }
            "for_statement" => {
                self.for_statement(builder, node, entry, next, scope, attached_label, stack)
            }
            "enhanced_for_statement" => self.enhanced_for_statement(
                builder,
                node,
                entry,
                next,
                scope,
                attached_label,
                stack,
            ),
            "switch_expression" => self.switch(
                builder,
                node,
                entry,
                next,
                scope,
                attached_label,
                false,
                stack,
            ),
            "try_statement" | "try_with_resources_statement" => {
                self.try_statement(builder, node, entry, next, scope, stack)
            }
            "synchronized_statement" => {
                self.synchronized_statement(builder, node, entry, next, scope, stack)
            }
            "labeled_statement" => {
                let children = named_children(node);
                let label_node = children
                    .iter()
                    .copied()
                    .find(|child| child.kind() == "identifier")
                    .ok_or_else(|| missing_field(node, "label"))?;
                let body = children
                    .into_iter()
                    .find(|child| child.id() != label_node.id())
                    .ok_or_else(|| missing_field(node, "body"))?;
                let label = node_text(self.prepared.source(), label_node).ok_or_else(|| {
                    JavaLoweringError::Invalid("labeled statement has invalid source range".into())
                })?;
                stack.push(Work::LabeledStatement {
                    node: body,
                    label,
                    entry,
                    next,
                    scope,
                });
                Ok(())
            }
            "local_variable_declaration" => {
                self.local_declaration(builder, node, entry, next, scope, stack)
            }
            "explicit_constructor_invocation" => {
                self.call_expression(builder, node, entry, next, scope, stack)
            }
            "assert_statement" => {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::NormalControlFlow,
                    SemanticGapKind::Unsupported,
                    "assert enablement and conditional message evaluation are not yet lowered",
                )?;
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::ExceptionalControlFlow,
                    SemanticGapKind::Unsupported,
                    "assert enablement and AssertionError construction are not yet lowered",
                )?;
                let values = named_children(node);
                self.schedule_expressions(builder, entry, &values, next, scope, stack)
            }
            "empty_statement"
            | "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "annotation_type_declaration"
            | "method_declaration"
            | "constructor_declaration"
            | "compact_constructor_declaration"
            | "static_initializer" => self.edge(builder, entry, next),
            _ => self.unhandled_control_syntax(builder, node, entry),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), JavaLoweringError> {
        let result = self.expression_value(builder, node, expression_value_kind(node))?;
        if matches!(node.kind(), "identifier" | "this") {
            self.emit_lexical_input_flow(builder, node, entry, result)?;
        }
        if node.kind() == "identifier" {
            // #2573: a bare identifier that is not a local or a parameter
            // (the only case `emit_lexical_input_flow` above leaves as a
            // no-op) may still name an implicit `this.field` access.
            self.emit_implicit_field_load(builder, node, entry, result)?;
        }
        match node.kind() {
            "method_invocation" | "object_creation_expression" | "enum_constant" => {
                self.call_expression(builder, node, entry, next, scope, stack)
            }
            "switch_expression" => {
                self.switch(builder, node, entry, next, scope, None, true, stack)
            }
            "lambda_expression" => self.callable_expression(builder, node, entry, next),
            "method_reference" => self.method_reference(builder, node, entry, next, scope, stack),
            "ternary_expression" => {
                let condition = required_field(node, "condition")?;
                let consequence = required_field(node, "consequence")?;
                let alternative = required_field(node, "alternative")?;
                let consequence_entry = self.point(builder, consequence, Vec::new())?;
                let alternative_entry = self.point(builder, alternative, Vec::new())?;
                // The chosen branch's value is the conditional's value. Each
                // branch therefore leaves through its own merge point, which
                // carries that one flow. The merge point exists because the
                // flow has to be ordered after the branch produced its value,
                // and the branch's own effects land on the points between its
                // entry and this one.
                let consequence_merge = self.point(builder, consequence, Vec::new())?;
                let alternative_merge = self.point(builder, alternative, Vec::new())?;
                let consequence_value = self.expression_value(
                    builder,
                    consequence,
                    expression_value_kind(consequence),
                )?;
                let alternative_value = self.expression_value(
                    builder,
                    alternative,
                    expression_value_kind(alternative),
                )?;
                self.append_effect(
                    builder,
                    consequence_merge,
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Local,
                        source: consequence_value,
                        target: result,
                    },
                )?;
                self.append_effect(
                    builder,
                    alternative_merge,
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Local,
                        source: alternative_value,
                        target: result,
                    },
                )?;
                self.edge(builder, consequence_merge, next)?;
                self.edge(builder, alternative_merge, next)?;
                stack.push(Work::Expression {
                    node: alternative,
                    entry: alternative_entry,
                    next: EdgeTarget::normal(alternative_merge),
                    scope,
                });
                stack.push(Work::Expression {
                    node: consequence,
                    entry: consequence_entry,
                    next: EdgeTarget::normal(consequence_merge),
                    scope,
                });
                stack.push(Work::Condition {
                    node: condition,
                    entry,
                    when_true: EdgeTarget {
                        point: consequence_entry,
                        kind: ControlEdgeKind::ConditionalTrue,
                    },
                    when_false: EdgeTarget {
                        point: alternative_entry,
                        kind: ControlEdgeKind::ConditionalFalse,
                    },
                    scope,
                });
                Ok(())
            }
            "binary_expression" if matches!(binary_operator(node), Some("&&" | "||")) => {
                let left = required_field(node, "left")?;
                let right = required_field(node, "right")?;
                let right_entry = self.point(builder, right, Vec::new())?;
                stack.push(Work::Expression {
                    node: right,
                    entry: right_entry,
                    next,
                    scope,
                });
                let (when_true, when_false) = if binary_operator(node) == Some("&&") {
                    (
                        EdgeTarget {
                            point: right_entry,
                            kind: ControlEdgeKind::ConditionalTrue,
                        },
                        EdgeTarget {
                            point: next.point,
                            kind: ControlEdgeKind::ConditionalFalse,
                        },
                    )
                } else {
                    (
                        EdgeTarget {
                            point: next.point,
                            kind: ControlEdgeKind::ConditionalTrue,
                        },
                        EdgeTarget {
                            point: right_entry,
                            kind: ControlEdgeKind::ConditionalFalse,
                        },
                    )
                };
                stack.push(Work::Condition {
                    node: left,
                    entry,
                    when_true,
                    when_false,
                    scope,
                });
                Ok(())
            }
            "parenthesized_expression" => {
                if let Some(value) = first_named_child(node) {
                    let terminal = self.point(builder, node, Vec::new())?;
                    let inner =
                        self.expression_value(builder, value, expression_value_kind(value))?;
                    self.append_effect(
                        builder,
                        terminal,
                        SemanticEffect::ValueFlow {
                            kind: ValueFlowKind::Local,
                            source: inner,
                            target: result,
                        },
                    )?;
                    self.edge(builder, terminal, next)?;
                    stack.push(Work::Expression {
                        node: value,
                        entry,
                        next: EdgeTarget::normal(terminal),
                        scope,
                    });
                    Ok(())
                } else {
                    self.edge(builder, entry, next)
                }
            }
            "field_access" if self.field_access_is_type_qualifier(node) => {
                // A package-or-type qualifier (`java.net.URLDecoder`) denotes
                // no runtime value (#2363). Do not mint a Field location or
                // an undischargeable FieldMemory gap.
                self.edge(builder, entry, next)
            }
            "field_access" => {
                let object = required_field(node, "object")?;
                let field = required_field(node, "field")?;
                let access = self.point(builder, node, Vec::new())?;
                let base = self.expression_value(builder, object, expression_value_kind(object))?;
                let (member, resolved) = self.memory_member_locator(field, object)?;
                let location = self.session.add_memory_location(
                    builder,
                    access,
                    MemoryLocationKind::Field { base, member },
                )?;
                if !resolved {
                    self.add_field_identity_gap(builder, access, location)?;
                }
                self.append_effect(
                    builder,
                    access,
                    SemanticEffect::MemoryLoad {
                        kind: MemoryAccessKind::Field,
                        location,
                        result,
                    },
                )?;
                self.edge(builder, access, next)?;
                if !self.expression_is_non_null(object) {
                    // NullPointerException. Its message names the expression,
                    // not the receiver's value, so the exception carries none.
                    self.implicit_abort_edge(builder, node, access, scope, None, stack)?;
                }
                self.schedule_expressions(
                    builder,
                    entry,
                    &[object],
                    EdgeTarget::normal(access),
                    scope,
                    stack,
                )
            }
            "array_access" => {
                let array = required_field(node, "array")?;
                let index = required_field(node, "index")?;
                let access = self.point(builder, node, Vec::new())?;
                let base = self.expression_value(builder, array, expression_value_kind(array))?;
                let index_value = self.index_value(builder, index)?;
                let location = self.session.add_memory_location(
                    builder,
                    access,
                    MemoryLocationKind::Index {
                        base,
                        index: Some(index_value),
                    },
                )?;
                self.append_effect(
                    builder,
                    access,
                    SemanticEffect::MemoryLoad {
                        kind: MemoryAccessKind::Index,
                        location,
                        result,
                    },
                )?;
                self.edge(builder, access, next)?;
                // NullPointerException carries nothing, but the message of an
                // ArrayIndexOutOfBoundsException embeds the offending index,
                // so a handler that reads the message observes that value.
                self.implicit_abort_edge(builder, node, access, scope, Some(index_value), stack)?;
                self.schedule_expressions(
                    builder,
                    entry,
                    &[array, index],
                    EdgeTarget::normal(access),
                    scope,
                    stack,
                )
            }
            "string_literal" => {
                let interpolations = named_children(node)
                    .into_iter()
                    .filter(|child| child.kind() == "string_interpolation")
                    .collect::<Vec<_>>();
                self.schedule_expressions(builder, entry, &interpolations, next, scope, stack)
            }
            "string_interpolation" => {
                let values = named_children(node);
                self.schedule_expressions(builder, entry, &values, next, scope, stack)
            }
            "assignment_expression" => {
                self.assignment_expression(builder, node, entry, next, scope, stack)
            }
            "binary_expression" | "unary_expression" => {
                let children = runtime_expression_children(node);
                let terminal = self.point(builder, node, Vec::new())?;
                let operands = children
                    .iter()
                    .map(|child| {
                        self.expression_value(builder, *child, expression_value_kind(*child))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                self.session
                    .append_language_defined_value_flows(builder, terminal, operands, result)?;
                self.edge(builder, terminal, next)?;
                if operation_can_throw_implicitly(node) {
                    // ArithmeticException on integral division, and
                    // NullPointerException on unboxing. Neither message embeds
                    // an operand value.
                    self.implicit_abort_edge(builder, node, terminal, scope, None, stack)?;
                }
                self.schedule_expressions(
                    builder,
                    entry,
                    &children,
                    EdgeTarget::normal(terminal),
                    scope,
                    stack,
                )
            }
            "update_expression"
            | "cast_expression"
            | "instanceof_expression"
            | "array_creation_expression"
            | "array_initializer"
            | "dimensions_expr"
            | "template_expression" => {
                let children = runtime_expression_children(node);
                if !operation_can_throw_implicitly(node) {
                    return self
                        .schedule_expressions(builder, entry, &children, next, scope, stack);
                }
                // ClassCastException, NegativeArraySizeException, and
                // NullPointerException on unboxing. This arm appends no effect
                // of its own, so the abort leaves a terminal point that the
                // operands reach first.
                let terminal = self.point(builder, node, Vec::new())?;
                self.edge(builder, terminal, next)?;
                self.implicit_abort_edge(builder, node, terminal, scope, None, stack)?;
                self.schedule_expressions(
                    builder,
                    entry,
                    &children,
                    EdgeTarget::normal(terminal),
                    scope,
                    stack,
                )
            }
            kind if is_runtime_leaf(kind) => self.edge(builder, entry, next),
            _ => self.unhandled_control_syntax(builder, node, entry),
        }
    }

    fn for_condition_starts_true(
        &self,
        initializers: &[Node<'tree>],
        condition: Node<'tree>,
    ) -> bool {
        let Some(operator) = condition.child_by_field_name("operator") else {
            return false;
        };
        if operator.kind() != "<" {
            return false;
        }
        let Some(left) = condition.child_by_field_name("left") else {
            return false;
        };
        let Some(right) = condition.child_by_field_name("right") else {
            return false;
        };
        let Some(left_name) = node_text(self.prepared.source(), left) else {
            return false;
        };
        let Some(limit) = decimal_integer_value(self.prepared.source(), right) else {
            return false;
        };
        initializers.iter().any(|initializer| {
            if initializer.kind() != "local_variable_declaration" {
                return false;
            }
            named_children(*initializer)
                .into_iter()
                .filter(|child| child.kind() == "variable_declarator")
                .any(|declarator| {
                    let Some(name) = declarator.child_by_field_name("name") else {
                        return false;
                    };
                    let Some(value) = declarator.child_by_field_name("value") else {
                        return false;
                    };
                    node_text(self.prepared.source(), name) == Some(left_name)
                        && decimal_integer_value(self.prepared.source(), value)
                            .is_some_and(|start| start < limit)
                })
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn for_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        label: Option<&'tree str>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), JavaLoweringError> {
        let body = required_field(node, "body")?;
        let initializers = children_by_field_name(node, "init")
            .into_iter()
            .filter(Node::is_named)
            .collect::<Vec<_>>();
        let condition = node.child_by_field_name("condition");
        let updates = children_by_field_name(node, "update")
            .into_iter()
            .filter(Node::is_named)
            .collect::<Vec<_>>();
        let condition_entry = match condition {
            Some(condition) => self.point(builder, condition, Vec::new())?,
            None => self.point(builder, node, Vec::new())?,
        };
        let body_entry = self.point(builder, body, Vec::new())?;
        let initial_condition_target = condition
            .filter(|condition| self.for_condition_starts_true(&initializers, *condition))
            .map_or(EdgeTarget::normal(condition_entry), |_| {
                EdgeTarget::normal(body_entry)
            });
        let updates = updates
            .into_iter()
            .map(|update| {
                self.point(builder, update, Vec::new())
                    .map(|entry| (update, entry))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let initializers = initializers
            .into_iter()
            .map(|initializer| {
                self.point(builder, initializer, Vec::new())
                    .map(|entry| (initializer, entry))
            })
            .collect::<Result<Vec<_>, _>>()?;
        schedule_c_style_loop(
            builder,
            &self.session,
            entry,
            next,
            scope,
            label.map(Box::<str>::from),
            &initializers,
            condition.map(|payload| (payload, condition_entry)),
            condition_entry,
            initial_condition_target,
            (body, body_entry),
            &updates,
            stack,
            |node, entry, next, scope| {
                if node.kind() == "local_variable_declaration" {
                    Work::Statement {
                        node,
                        entry,
                        next,
                        scope,
                    }
                } else {
                    Work::Expression {
                        node,
                        entry,
                        next,
                        scope,
                    }
                }
            },
            Work::expression,
            Work::statement,
            Work::condition,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn enhanced_for_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        label: Option<&'tree str>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), JavaLoweringError> {
        let iterable = required_field(node, "value")?;
        let binding = required_field(node, "name")?;
        let body = required_field(node, "body")?;
        let test = self.point(builder, node, Vec::new())?;
        let binding_entry = self.point(builder, binding, Vec::new())?;
        let body_entry = self.point(builder, body, Vec::new())?;
        let loop_scope = builder.push_scope(
            Some(scope),
            ScopeBinding::Loop {
                label: label.map(Box::<str>::from),
                break_target: next.point,
                break_edge_kind: next.kind,
                continue_target: test,
                continue_edge_kind: ControlEdgeKind::LoopBack,
            },
        );
        self.add_gap(
            builder,
            test,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            "implicit iterator acquisition and advancement exceptions are not yet lowered",
        )?;
        self.edge(
            builder,
            test,
            EdgeTarget {
                point: binding_entry,
                kind: ControlEdgeKind::ConditionalTrue,
            },
        )?;
        self.edge(
            builder,
            test,
            EdgeTarget {
                point: next.point,
                kind: ControlEdgeKind::ConditionalFalse,
            },
        )?;
        self.edge(builder, binding_entry, EdgeTarget::normal(body_entry))?;
        stack.push(Work::Statement {
            node: body,
            entry: body_entry,
            next: EdgeTarget {
                point: test,
                kind: ControlEdgeKind::LoopBack,
            },
            scope: loop_scope,
        });
        stack.push(Work::Expression {
            node: iterable,
            entry,
            next: EdgeTarget::normal(test),
            scope: loop_scope,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn switch(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        label: Option<&'tree str>,
        expression_mode: bool,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), JavaLoweringError> {
        let condition = required_field(node, "condition")?;
        let body = required_field(node, "body")?;
        let dispatch = self.point(builder, node, Vec::new())?;
        let switch_next = if expression_mode {
            let merge = self.point(builder, node, Vec::new())?;
            self.edge(builder, merge, next)?;
            EdgeTarget::normal(merge)
        } else {
            next
        };
        let switch_scope = if expression_mode {
            builder.push_scope(
                Some(scope),
                ScopeBinding::Yieldable {
                    yield_target: switch_next.point,
                    yield_edge_kind: switch_next.kind,
                },
            )
        } else {
            builder.push_scope(
                Some(scope),
                ScopeBinding::Breakable {
                    label: label.map(Box::<str>::from),
                    accepts_unlabeled: true,
                    break_target: next.point,
                    break_edge_kind: next.kind,
                },
            )
        };
        let arms = java_switch_arms(body);
        if arms.is_empty() {
            if expression_mode {
                self.add_gap(
                    builder,
                    dispatch,
                    SemanticGapSubject::Point,
                    SemanticCapability::NormalControlFlow,
                    SemanticGapKind::Unsupported,
                    "empty switch expression has no represented result",
                )?;
            } else {
                self.edge(builder, dispatch, switch_next)?;
            }
            stack.push(Work::Expression {
                node: condition,
                entry,
                next: EdgeTarget::normal(dispatch),
                scope: switch_scope,
            });
            return Ok(());
        }

        let arm_entries = arms
            .iter()
            .map(|arm| self.point(builder, arm.node, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        for index in (0..arms.len()).rev() {
            let arm = &arms[index];
            match arm.kind {
                JavaSwitchArmKind::Group => {
                    let fallthrough = if let Some(entry) = arm_entries.get(index + 1).copied() {
                        EdgeTarget::normal(entry)
                    } else if expression_mode {
                        let missing_yield = self.point(builder, arm.node, Vec::new())?;
                        self.add_gap(
                            builder,
                            missing_yield,
                            SemanticGapSubject::Point,
                            SemanticCapability::NormalControlFlow,
                            SemanticGapKind::Unsupported,
                            "switch-expression statement group can complete without a represented yield",
                        )?;
                        EdgeTarget::normal(missing_yield)
                    } else {
                        switch_next
                    };
                    self.schedule_statements(
                        builder,
                        arm_entries[index],
                        &arm.body,
                        fallthrough,
                        switch_scope,
                        stack,
                    )?;
                }
                JavaSwitchArmKind::Rule => {
                    let action = arm.body.first().copied();
                    match action {
                        Some(action)
                            if expression_mode && action.kind() == "expression_statement" =>
                        {
                            if let Some(value) = first_named_child(action) {
                                stack.push(Work::Expression {
                                    node: value,
                                    entry: arm_entries[index],
                                    next: switch_next,
                                    scope: switch_scope,
                                });
                            } else {
                                self.add_gap(
                                    builder,
                                    arm_entries[index],
                                    SemanticGapSubject::Point,
                                    SemanticCapability::NormalControlFlow,
                                    SemanticGapKind::Unsupported,
                                    "switch-expression rule has no result expression",
                                )?;
                            }
                        }
                        Some(action) if expression_mode && action.kind() == "block" => {
                            let missing_yield = self.point(builder, action, Vec::new())?;
                            self.add_gap(
                                builder,
                                missing_yield,
                                SemanticGapSubject::Point,
                                SemanticCapability::NormalControlFlow,
                                SemanticGapKind::Unsupported,
                                "switch-expression block rule can complete without a represented yield",
                            )?;
                            stack.push(Work::Statement {
                                node: action,
                                entry: arm_entries[index],
                                next: EdgeTarget::normal(missing_yield),
                                scope: switch_scope,
                            });
                        }
                        Some(action) => {
                            stack.push(Work::Statement {
                                node: action,
                                entry: arm_entries[index],
                                next: switch_next,
                                scope: switch_scope,
                            });
                        }
                        None => {
                            self.add_gap(
                                builder,
                                arm_entries[index],
                                SemanticGapSubject::Point,
                                SemanticCapability::NormalControlFlow,
                                SemanticGapKind::Unsupported,
                                "switch rule has no executable body",
                            )?;
                        }
                    }
                }
            }
        }

        let default_target = arms.iter().enumerate().find_map(|(index, arm)| {
            arm.labels
                .iter()
                .any(|label| switch_label_is_default(*label))
                .then_some(EdgeTarget::normal(arm_entries[index]))
        });
        let mut no_match = if let Some(default_target) = default_target {
            default_target
        } else if expression_mode {
            let missing_match = self.point(builder, node, Vec::new())?;
            self.add_gap(
                builder,
                missing_match,
                SemanticGapSubject::Point,
                SemanticCapability::NormalControlFlow,
                SemanticGapKind::Unknown,
                "switch-expression exhaustiveness requires type and pattern refinement",
            )?;
            EdgeTarget::normal(missing_match)
        } else {
            switch_next
        };

        for (arm_index, arm) in arms.iter().enumerate().rev() {
            for switch_label in arm.labels.iter().rev() {
                if switch_label_is_default(*switch_label) {
                    continue;
                }
                let comparison = self.point(builder, *switch_label, Vec::new())?;
                if switch_label_has_pattern(*switch_label) {
                    self.add_gap(
                        builder,
                        comparison,
                        SemanticGapSubject::Point,
                        SemanticCapability::NormalControlFlow,
                        SemanticGapKind::Unsupported,
                        "pattern compatibility requires type refinement",
                    )?;
                }
                if let Some(guard) = switch_label_guard(*switch_label) {
                    let guard_entry = self.point(builder, guard, Vec::new())?;
                    self.edge(
                        builder,
                        comparison,
                        EdgeTarget {
                            point: guard_entry,
                            kind: ControlEdgeKind::ConditionalTrue,
                        },
                    )?;
                    stack.push(Work::Condition {
                        node: guard,
                        entry: guard_entry,
                        when_true: EdgeTarget {
                            point: arm_entries[arm_index],
                            kind: ControlEdgeKind::SwitchCase,
                        },
                        when_false: EdgeTarget {
                            point: no_match.point,
                            kind: ControlEdgeKind::ConditionalFalse,
                        },
                        scope: switch_scope,
                    });
                } else {
                    self.edge(
                        builder,
                        comparison,
                        EdgeTarget {
                            point: arm_entries[arm_index],
                            kind: ControlEdgeKind::SwitchCase,
                        },
                    )?;
                }
                self.edge(
                    builder,
                    comparison,
                    EdgeTarget {
                        point: no_match.point,
                        kind: ControlEdgeKind::ConditionalFalse,
                    },
                )?;
                no_match = EdgeTarget::normal(comparison);
            }
        }
        self.edge(builder, dispatch, no_match)?;
        stack.push(Work::Expression {
            node: condition,
            entry,
            next: EdgeTarget::normal(dispatch),
            scope: switch_scope,
        });
        Ok(())
    }

    fn try_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), JavaLoweringError> {
        let body = required_field(node, "body")?;
        let children = named_children(node);
        let catches = children
            .iter()
            .copied()
            .filter(|child| child.kind() == "catch_clause")
            .collect::<Vec<_>>();
        let finalizer = children
            .iter()
            .copied()
            .find(|child| child.kind() == "finally_clause")
            .and_then(first_named_child);

        let (cleanup_scope, cleanup_region) = if let Some(finalizer) = finalizer {
            let region = CleanupRegionId::new(
                u32::try_from(self.cleanups.len())
                    .map_err(|_| JavaLoweringError::Invalid("too many cleanup regions".into()))?,
            );
            self.cleanups.push(CleanupRegion {
                id: region,
                body: CleanupBody::Statement(finalizer),
                outer_scope: scope,
            });
            (
                builder.push_scope(Some(scope), ScopeBinding::Cleanup { region }),
                Some(region),
            )
        } else {
            (scope, None)
        };

        let normal_destination = if cleanup_region.is_some() && next.kind != ControlEdgeKind::Normal
        {
            let relay = self.point(builder, node, Vec::new())?;
            self.edge(builder, relay, next)?;
            relay
        } else {
            next.point
        };
        let normal_route = cleanup_region
            .map(|region| builder.normal_cleanup_completion(region, normal_destination));

        let catch_bodies = catches
            .iter()
            .map(|catch| required_field(*catch, "body"))
            .collect::<Result<Vec<_>, _>>()?;
        let catch_entries = catch_bodies
            .iter()
            .map(|body| self.point(builder, *body, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        let catch_binders = catches
            .iter()
            .map(|catch| {
                let parameter = named_children(*catch)
                    .into_iter()
                    .find(|child| child.kind() == "catch_formal_parameter")?;
                let name = parameter.child_by_field_name("name")?;
                let text = node_text(self.prepared.source(), name)?;
                self.local_declaration_value(text, name.start_byte())
            })
            .collect::<Vec<_>>();
        let precise_single_catch = catches.len() == 1
            && catch_binders.first().copied().flatten().is_some()
            && catches
                .first()
                .and_then(|catch| {
                    named_children(*catch)
                        .into_iter()
                        .find(|child| child.kind() == "catch_formal_parameter")
                })
                .is_some_and(catch_parameter_has_precise_type);
        let try_scope = if catch_entries.is_empty() {
            cleanup_scope
        } else {
            let dispatcher = self.point(builder, node, Vec::new())?;
            if !precise_single_catch {
                self.add_gap(
                    builder,
                    dispatcher,
                    SemanticGapSubject::Point,
                    SemanticCapability::ExceptionalControlFlow,
                    SemanticGapKind::Unknown,
                    "catch-type compatibility and multi-catch selection require type refinement",
                )?;
            }
            if precise_single_catch && let Some(Some(binder)) = catch_binders.first() {
                self.catch_binders.insert(dispatcher, *binder);
            }
            for catch_entry in &catch_entries {
                self.edge(
                    builder,
                    dispatcher,
                    EdgeTarget {
                        point: *catch_entry,
                        kind: ControlEdgeKind::SwitchCase,
                    },
                )?;
            }
            let unmatched = self.point(builder, node, Vec::new())?;
            self.edge(
                builder,
                dispatcher,
                EdgeTarget {
                    point: unmatched,
                    kind: ControlEdgeKind::Exceptional,
                },
            )?;
            self.abrupt(
                builder,
                unmatched,
                cleanup_scope,
                CompletionKind::Throw,
                None,
                stack,
            )?;
            builder.push_scope(
                Some(cleanup_scope),
                ScopeBinding::Handler { entry: dispatcher },
            )
        };

        for (catch_body, catch_entry) in catch_bodies.iter().zip(&catch_entries) {
            if let Some(route) = &normal_route {
                let catch_exit = self.point(builder, *catch_body, Vec::new())?;
                self.route(builder, catch_exit, route, stack)?;
                stack.push(Work::Statement {
                    node: *catch_body,
                    entry: *catch_entry,
                    next: EdgeTarget::normal(catch_exit),
                    scope: cleanup_scope,
                });
            } else {
                stack.push(Work::Statement {
                    node: *catch_body,
                    entry: *catch_entry,
                    next,
                    scope: cleanup_scope,
                });
            }
        }

        let (body_entry, body_scope, resource_normal_route) = if node.kind()
            == "try_with_resources_statement"
        {
            let resource_region = CleanupRegionId::new(
                u32::try_from(self.cleanups.len())
                    .map_err(|_| JavaLoweringError::Invalid("too many cleanup regions".into()))?,
            );
            self.cleanups.push(CleanupRegion {
                id: resource_region,
                body: CleanupBody::OpaqueResource(node),
                outer_scope: try_scope,
            });
            let body_scope = builder.push_scope(
                Some(try_scope),
                ScopeBinding::Cleanup {
                    region: resource_region,
                },
            );
            let after_resource = self.point(builder, node, Vec::new())?;
            if let Some(route) = &normal_route {
                self.route(builder, after_resource, route, stack)?;
            } else {
                self.edge(builder, after_resource, next)?;
            }
            let resource_normal_route =
                builder.normal_cleanup_completion(resource_region, after_resource);
            let resource_boundary = self.point(builder, node, Vec::new())?;
            self.add_gap(
                builder,
                resource_boundary,
                SemanticGapSubject::Point,
                SemanticCapability::ResourceManagement,
                SemanticGapKind::Unsupported,
                    "resource acquisition and partial-initialization cleanup are not yet lowered exactly",
            )?;
            self.add_gap(
                builder,
                resource_boundary,
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unsupported,
                "resource acquisition can raise implicit exceptions not yet represented",
            )?;
            let resources = node
                .child_by_field_name("resources")
                .map(named_children)
                .unwrap_or_default();
            let initializers = resources
                .into_iter()
                .filter_map(|resource| {
                    resource
                        .child_by_field_name("value")
                        .or_else(|| first_runtime_named_child(resource))
                })
                .collect::<Vec<_>>();
            if initializers.is_empty() {
                self.edge(builder, entry, EdgeTarget::normal(resource_boundary))?;
            } else {
                self.schedule_expressions(
                    builder,
                    entry,
                    &initializers,
                    EdgeTarget::normal(resource_boundary),
                    try_scope,
                    stack,
                )?;
            }
            (resource_boundary, body_scope, Some(resource_normal_route))
        } else {
            (entry, try_scope, None)
        };

        if let Some(route) = resource_normal_route.as_ref().or(normal_route.as_ref()) {
            let body_exit = self.point(builder, body, Vec::new())?;
            self.route(builder, body_exit, route, stack)?;
            stack.push(Work::Statement {
                node: body,
                entry: body_entry,
                next: EdgeTarget::normal(body_exit),
                scope: body_scope,
            });
        } else {
            stack.push(Work::Statement {
                node: body,
                entry: body_entry,
                next,
                scope: body_scope,
            });
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn synchronized_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), JavaLoweringError> {
        let lock = named_children(node)
            .into_iter()
            .find(|child| child.kind() == "parenthesized_expression")
            .ok_or_else(|| missing_field(node, "lock"))?;
        let body = required_field(node, "body")?;
        let monitor = self.point(builder, node, Vec::new())?;
        let body_entry = self.point(builder, body, Vec::new())?;
        let region = CleanupRegionId::new(
            u32::try_from(self.cleanups.len())
                .map_err(|_| JavaLoweringError::Invalid("too many cleanup regions".into()))?,
        );
        self.cleanups.push(CleanupRegion {
            id: region,
            body: CleanupBody::OpaqueMonitor(node),
            outer_scope: scope,
        });
        let synchronized_scope = builder.push_scope(Some(scope), ScopeBinding::Cleanup { region });
        self.add_gap(
            builder,
            monitor,
            SemanticGapSubject::Point,
            SemanticCapability::CleanupControlFlow,
            SemanticGapKind::Unsupported,
            "monitor ownership and reentrancy effects are represented only as opaque boundaries",
        )?;
        self.add_gap(
            builder,
            monitor,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            "implicit monitor acquisition exceptions are not yet lowered",
        )?;
        self.edge(builder, monitor, EdgeTarget::normal(body_entry))?;
        let cleanup_destination = if next.kind == ControlEdgeKind::Normal {
            next.point
        } else {
            let relay = self.point(builder, node, Vec::new())?;
            self.edge(builder, relay, next)?;
            relay
        };
        let body_exit = self.point(builder, body, Vec::new())?;
        let normal_route = builder.normal_cleanup_completion(region, cleanup_destination);
        self.route(builder, body_exit, &normal_route, stack)?;
        stack.push(Work::Statement {
            node: body,
            entry: body_entry,
            next: EdgeTarget::normal(body_exit),
            scope: synchronized_scope,
        });
        stack.push(Work::Expression {
            node: lock,
            entry,
            next: EdgeTarget::normal(monitor),
            scope,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn call_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), JavaLoweringError> {
        let invoke = self.point(builder, node, Vec::new())?;
        let normal = self.point(builder, node, Vec::new())?;
        let exceptional = self.point(builder, node, Vec::new())?;
        // Keep transient callable/exception values anchored to the callable
        // spelling. The whole call expression denotes `result`; giving all
        // three values the whole-expression span makes source-level
        // points-to queries observe internal call scaffolding as if it were
        // the expression value.
        let callable_anchor = node
            .child_by_field_name("name")
            .or_else(|| node.child_by_field_name("type"))
            .or_else(|| first_named_child(node))
            .unwrap_or(node);
        let callee = self.source_value(builder, callable_anchor, SemanticValueKind::Callable)?;
        let result = self.expression_value(builder, node, SemanticValueKind::Temporary)?;
        let thrown = self.source_value(builder, callable_anchor, SemanticValueKind::Exception)?;
        let receiver_node = match node.kind() {
            "method_invocation" | "explicit_constructor_invocation" => {
                node.child_by_field_name("object")
            }
            "object_creation_expression" => object_creation_qualifier(node),
            _ => None,
        };
        let receiver = receiver_node
            .map(|receiver_node| {
                self.expression_value(builder, receiver_node, expression_value_kind(receiver_node))
            })
            .transpose()?;
        let callable_kind = match node.kind() {
            "object_creation_expression" | "explicit_constructor_invocation" | "enum_constant" => {
                CallableReferenceKind::Constructor
            }
            "method_invocation" if receiver.is_some() => CallableReferenceKind::BoundMethod,
            "method_invocation" => CallableReferenceKind::UnboundMethod,
            _ => CallableReferenceKind::Function,
        };
        let resolution = CallableTargetResolution::Unknown;
        let metadata = self.metadata(invoke)?;
        self.append_effect(
            builder,
            invoke,
            SemanticEffect::CallableReference {
                result: callee,
                callable: CallableValue {
                    kind: callable_kind,
                    targets: resolution.clone(),
                    target_evidence: metadata.evidence,
                    bound_receiver: receiver,
                    environment: None,
                },
            },
        )?;

        let arguments = node
            .child_by_field_name("arguments")
            .map(named_children)
            .unwrap_or_default();
        let argument_values = arguments
            .iter()
            .map(|argument| {
                self.expression_value(builder, *argument, expression_value_kind(*argument))
                    .map(|value| SemanticCallArgument::direct(value, ArgumentDomain::Positional))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let call_site = self.session.add_call_site(
            builder,
            CallSiteScaffold {
                point: invoke,
                callee,
                receiver,
                arguments: argument_values.into_boxed_slice(),
                result: Some(result),
                thrown: Some(thrown),
                declared_targets: resolution.clone(),
                normal_continuation: normal,
                exceptional_continuation: exceptional,
            },
        )?;
        // #2571: if this call's receiver names a lexical binding this
        // procedure tracks (a local variable, a formal parameter, or
        // `this`), carry whatever the call's own receiver value holds after
        // the call back into that binding, so a later read of the same
        // binding observes what a mutating call (for example
        // `java.util.HashMap.put`, whose shipped summary chains a tainted
        // argument onto its own `receiver -> receiver` transfer) did to it.
        // See `emit_receiver_write_back`'s own doc comment for the full
        // rationale, including why this is additive rather than a kill and
        // why a reassignment of the binding between two calls still
        // separates their carriers regardless.
        if let (Some(receiver_node), Some(receiver_value)) = (receiver_node, receiver) {
            self.emit_receiver_write_back(builder, receiver_node, normal, receiver_value)?;
            // #2573: the field analogue of the write-back above, for a
            // receiver that is an implicit `this.field` access rather than a
            // lexical binding. See `emit_implicit_field_receiver_write_back`'s
            // own doc comment for the full rationale.
            self.emit_implicit_field_receiver_write_back(
                builder,
                receiver_node,
                normal,
                receiver_value,
            )?;
        }
        if node.kind() == "object_creation_expression" {
            self.session
                .add_allocation(builder, normal, result, AllocationKind::Object)?;
        }
        self.edge(builder, invoke, EdgeTarget::normal(normal))?;
        self.edge(
            builder,
            invoke,
            EdgeTarget {
                point: exceptional,
                kind: ControlEdgeKind::Exceptional,
            },
        )?;
        self.edge(builder, normal, next)?;
        self.abrupt(
            builder,
            exceptional,
            scope,
            CompletionKind::Throw,
            None,
            stack,
        )?;
        self.resolution_gaps(builder, invoke, callee, call_site, &resolution)?;

        if node.kind() == "method_invocation" {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::DynamicDispatch,
                SemanticGapKind::Unknown,
                "method invocation may select an override; static/final dispatch and complete override coverage require type-hierarchy refinement",
            )?;
        }

        let mut evaluations =
            Vec::with_capacity(arguments.len() + usize::from(receiver_node.is_some()));
        if let Some(receiver_node) = receiver_node {
            evaluations.push(receiver_node);
        }
        evaluations.extend(arguments);
        self.schedule_expressions(
            builder,
            entry,
            &evaluations,
            EdgeTarget::normal(invoke),
            scope,
            stack,
        )
    }

    fn callable_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
    ) -> Result<(), JavaLoweringError> {
        let result = self.expression_value(builder, node, SemanticValueKind::Callable)?;
        let target = self.procedure_targets.get(&node.id()).copied();
        let resolution = target
            .map(|target| CallableTargetResolution::Proven(CallableTarget::Local(target.id)))
            .unwrap_or(CallableTargetResolution::Unknown);
        let metadata = self.metadata(entry)?;
        let kind = if node.kind() == "lambda_expression" {
            CallableReferenceKind::Lambda
        } else {
            CallableReferenceKind::UnboundMethod
        };
        let environment =
            if target.is_some_and(|target| target.receiver_capture_destination.is_some()) {
                Some(self.session.add_allocation(
                    builder,
                    entry,
                    result,
                    AllocationKind::ClosureEnvironment,
                )?)
            } else {
                None
            };
        let callable = CallableValue {
            kind,
            targets: resolution.clone(),
            target_evidence: metadata.evidence,
            bound_receiver: None,
            environment,
        };
        let effect = if node.kind() == "lambda_expression" {
            SemanticEffect::CallableCreation { result, callable }
        } else {
            SemanticEffect::CallableReference { result, callable }
        };
        self.append_effect(builder, entry, effect)?;
        if let (Some(target), Some(environment), Some(captured), Some(destination)) = (
            target,
            environment,
            self.receiver.or(self.captured_receiver),
            target.and_then(|target| target.receiver_capture_destination),
        ) {
            self.session.add_capture(
                builder,
                entry,
                result,
                target.id,
                environment,
                CaptureSource::Value(captured),
                destination,
                CaptureMode::Value,
            )?;
        }
        if resolution == CallableTargetResolution::Unknown {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Value(result),
                SemanticCapability::CallableReferences,
                SemanticGapKind::Unknown,
                "nested callable target mapping is not yet published",
            )?;
        }
        self.edge(builder, entry, next)
    }

    fn method_reference(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), JavaLoweringError> {
        let reference = self.point(builder, node, Vec::new())?;
        let constructor_reference = has_child_kind(node, "new");
        let qualifier = (!constructor_reference)
            .then(|| method_reference_qualifier(node))
            .flatten();
        let result = self.expression_value(builder, node, SemanticValueKind::Callable)?;
        let receiver = qualifier
            .map(|qualifier| {
                self.expression_value(builder, qualifier, expression_value_kind(qualifier))
            })
            .transpose()?;
        let metadata = self.metadata(reference)?;
        self.append_effect(
            builder,
            reference,
            SemanticEffect::CallableReference {
                result,
                callable: CallableValue {
                    kind: if constructor_reference {
                        CallableReferenceKind::Constructor
                    } else if receiver.is_some() {
                        CallableReferenceKind::BoundMethod
                    } else {
                        CallableReferenceKind::UnboundMethod
                    },
                    targets: CallableTargetResolution::Unknown,
                    target_evidence: metadata.evidence,
                    bound_receiver: receiver,
                    environment: None,
                },
            },
        )?;
        self.add_gap(
            builder,
            reference,
            SemanticGapSubject::Value(result),
            SemanticCapability::CallableReferences,
            SemanticGapKind::Unknown,
            "method-reference target and receiver binding require dispatch refinement",
        )?;
        if qualifier.is_some() {
            self.add_gap(
                builder,
                reference,
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unsupported,
                "bound method-reference creation can fail its implicit receiver null check",
            )?;
        }
        self.edge(builder, reference, next)?;

        if let Some(qualifier) = qualifier {
            stack.push(Work::Expression {
                node: qualifier,
                entry,
                next: EdgeTarget::normal(reference),
                scope,
            });
        } else {
            self.edge(builder, entry, EdgeTarget::normal(reference))?;
        }
        Ok(())
    }

    /// Lower the abort edge of a runtime operation that can fault implicitly:
    /// a null dereference, an out-of-bounds index, a bad cast, a negative
    /// array length, or a division by zero.
    ///
    /// The edge leaves `operation`, the point that carries the operation's own
    /// effect, so every value the operands established is already live on the
    /// abort path. `route` then threads the abort through the enclosing
    /// cleanup regions to the handler dispatcher, or to the exceptional exit
    /// when this procedure has no handler for it. This is the same shape
    /// `call_expression` uses for the exceptional continuation of a call.
    ///
    /// The implicitly thrown exception is a fresh object. `carried` names the
    /// program value the JVM embeds in it, which is the offending index of an
    /// `ArrayIndexOutOfBoundsException`; the other faults report only source
    /// text or type names, so they carry nothing.
    ///
    /// Effects are appended only when the destination binds the exception to a
    /// catch parameter. An abort that can only unwind must leave the abort
    /// point empty, because `abort_paths_run_user_code` discharges the
    /// implicit-exception gaps that the remaining emitters still raise exactly
    /// when no abort path runs user code.
    fn implicit_abort_edge(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        operation: ProgramPointId,
        scope: ScopeFrameId,
        carried: Option<ValueId>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), JavaLoweringError> {
        let Some(route) =
            builder.resolve_completion(scope, &CompletionRequest::new(CompletionKind::Throw, None))
        else {
            return Err(JavaLoweringError::Invalid(
                "implicit abort has no matching structured continuation".into(),
            ));
        };
        let abort = self.point(builder, node, Vec::new())?;
        if let Some(binder) = self
            .catch_binders
            .get(&route.destination().target())
            .copied()
        {
            let thrown = self.value(builder, abort, SemanticValueKind::Exception)?;
            if let Some(carried) = carried {
                self.append_effect(
                    builder,
                    abort,
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Local,
                        source: carried,
                        target: thrown,
                    },
                )?;
            }
            self.append_effect(
                builder,
                abort,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Local,
                    source: thrown,
                    target: binder,
                },
            )?;
        }
        self.edge(
            builder,
            operation,
            EdgeTarget {
                point: abort,
                kind: ControlEdgeKind::Exceptional,
            },
        )?;
        self.route(builder, abort, &route, stack)
    }

    fn unhandled_control_syntax(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
    ) -> Result<(), JavaLoweringError> {
        let detail = format!(
            "{} runtime/control syntax is not yet lowered structurally",
            node.kind()
        );
        self.add_gap(
            builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::NormalControlFlow,
            SemanticGapKind::Unsupported,
            &detail,
        )
    }

    fn schedule_statements(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        children: &[Node<'tree>],
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), JavaLoweringError> {
        if children.is_empty() {
            return self.edge(builder, entry, next);
        }
        let entries = children
            .iter()
            .map(|child| self.point(builder, *child, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        self.edge(builder, entry, EdgeTarget::normal(entries[0]))?;
        for index in (0..children.len()).rev() {
            let child_next = entries
                .get(index + 1)
                .copied()
                .map(EdgeTarget::normal)
                .unwrap_or(next);
            stack.push(Work::Statement {
                node: children[index],
                entry: entries[index],
                next: child_next,
                scope,
            });
        }
        Ok(())
    }

    fn schedule_expressions(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        children: &[Node<'tree>],
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), JavaLoweringError> {
        if children.is_empty() {
            return self.edge(builder, entry, next);
        }
        let entries = children
            .iter()
            .map(|child| self.point(builder, *child, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        self.edge(builder, entry, EdgeTarget::normal(entries[0]))?;
        for index in (0..children.len()).rev() {
            let child_next = entries
                .get(index + 1)
                .copied()
                .map(EdgeTarget::normal)
                .unwrap_or(next);
            stack.push(Work::Expression {
                node: children[index],
                entry: entries[index],
                next: child_next,
                scope,
            });
        }
        Ok(())
    }

    fn abrupt(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        from: ProgramPointId,
        scope: ScopeFrameId,
        kind: CompletionKind,
        label: Option<&str>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), JavaLoweringError> {
        let Some(route) = builder.resolve_completion(scope, &CompletionRequest::new(kind, label))
        else {
            if matches!(
                kind,
                CompletionKind::Break | CompletionKind::Continue | CompletionKind::Yield
            ) {
                let detail = format!(
                    "{} completion has no matching represented target",
                    completion_label(kind)
                );
                self.add_gap(
                    builder,
                    from,
                    SemanticGapSubject::Point,
                    SemanticCapability::NonLocalControl,
                    SemanticGapKind::Unsupported,
                    &detail,
                )?;
                return Ok(());
            }
            return Err(JavaLoweringError::Invalid(format!(
                "{} completion has no matching structured continuation",
                completion_label(kind)
            )));
        };
        self.route(builder, from, &route, stack)
    }

    fn abrupt_throw(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        from: ProgramPointId,
        scope: ScopeFrameId,
        value: ValueId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), JavaLoweringError> {
        let Some(route) =
            builder.resolve_completion(scope, &CompletionRequest::new(CompletionKind::Throw, None))
        else {
            return Err(JavaLoweringError::Invalid(
                "throw completion has no matching structured continuation".into(),
            ));
        };
        if let Some(target) = self
            .catch_binders
            .get(&route.destination().target())
            .copied()
        {
            self.append_effect(
                builder,
                from,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Local,
                    source: value,
                    target,
                },
            )?;
        }
        self.route(builder, from, &route, stack)
    }

    fn route(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        from: ProgramPointId,
        route: &CompletionRoute,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), JavaLoweringError> {
        let mut plan = CleanupRoutePlanner::new(route);
        while let Some(step) = plan.next(
            builder,
            &mut self.session,
            &self.cleanups,
            |region| region.id,
            |region| region.body.source_node(),
        )? {
            match step.region.body {
                CleanupBody::Statement(body) => {
                    let statement_next = if step.next.kind == ControlEdgeKind::Normal {
                        step.next
                    } else {
                        let relay = self.point(builder, body, Vec::new())?;
                        self.edge(builder, relay, step.next)?;
                        EdgeTarget::normal(relay)
                    };
                    stack.push(Work::Statement {
                        node: body,
                        entry: step.entry,
                        next: statement_next,
                        scope: step.region.outer_scope,
                    });
                }
                CleanupBody::OpaqueResource(_) => {
                    self.add_gap(
                        builder,
                        step.entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::ResourceManagement,
                        SemanticGapKind::Unsupported,
                        "resource close order, suppression, and value effects are not yet lowered",
                    )?;
                    self.add_gap(
                        builder,
                        step.entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::ExceptionalControlFlow,
                        SemanticGapKind::Unsupported,
                        "resource close can raise or suppress exceptions not yet represented",
                    )?;
                    self.edge(builder, step.entry, step.next)?;
                }
                CleanupBody::OpaqueMonitor(_) => {
                    self.add_gap(
                            builder,
                            step.entry,
                            SemanticGapSubject::Point,
                            SemanticCapability::CleanupControlFlow,
                            SemanticGapKind::Unsupported,
                            "monitor release effects are represented only as an opaque cleanup boundary",
                        )?;
                    self.add_gap(
                        builder,
                        step.entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::ExceptionalControlFlow,
                        SemanticGapKind::Unsupported,
                        "monitor release failure behavior is not yet represented",
                    )?;
                    self.edge(builder, step.entry, step.next)?;
                }
            }
        }
        self.edge(builder, from, plan.target())
    }

    fn edge(
        &self,
        builder: &mut ProcedureCfgBuilder,
        source_point: ProgramPointId,
        target: EdgeTarget,
    ) -> Result<(), JavaLoweringError> {
        self.session
            .add_edge(builder, source_point, target.point, target.kind)
    }
}

fn decimal_integer_value(source: &str, node: Node<'_>) -> Option<i64> {
    (node.kind() == "decimal_integer_literal")
        .then(|| node_text(source, node))
        .flatten()
        .and_then(|text| text.parse().ok())
}
