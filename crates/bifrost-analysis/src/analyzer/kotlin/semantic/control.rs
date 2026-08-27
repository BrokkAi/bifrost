use super::syntax::*;
use super::*;

pub(super) fn lower_procedure<'tree, 'targets>(
    prepared: &'tree PreparedSyntaxTree,
    spec: &ProcedureSpec<'tree>,
    procedure_targets: &'targets HashMap<usize, NestedProcedureTarget>,
    constructible_types: &'targets HashSet<Box<str>>,
    budget: &SemanticBudget,
    cancellation: &'targets CancellationToken,
) -> Result<(ProcedureSemanticsParts, SemanticWork), KotlinLoweringError> {
    let mut parts = ProcedureSemanticsParts::new(
        spec.id,
        spec.locator.clone(),
        spec.kind,
        SourceMappingId::new(0),
        EvidenceId::new(0),
    );
    parts.lexical_parent = spec.lexical_parent;
    parts.properties = spec.properties;
    let (
        ProcedureLoweringStart {
            mut builder,
            session,
            entry,
            normal_exit,
            exceptional_exit,
            function_scope,
        },
        _,
    ) = ProcedureLoweringSession::start_with_function_throw_boundary(
        parts,
        budget,
        cancellation,
        false,
    )?;
    let mut context = LoweringContext {
        prepared,
        session,
        expression_values: HashMap::default(),
        parameters: HashMap::default(),
        locals: HashMap::default(),
        local_callables: HashMap::default(),
        constructible_types,
        receiver: None,
        captured_receiver: None,
        boundary_label: lambda_boundary_label(prepared.source(), spec.callable),
        is_lambda: spec.callable.kind() == "lambda_literal",
        procedure_targets,
        cleanups: Vec::new(),
    };
    context.emit_procedure_inputs(&mut builder, spec.callable, spec.kind, spec.properties)?;
    context.emit_captured_receiver(&mut builder, entry, spec)?;
    context.emit_local_bindings(&mut builder, spec.body.scan_root())?;

    if spec.kind == ProcedureKind::Initializer {
        // One scoped fact per procedure: a delegated property is an initializer
        // too, so its generated accessor dispatch is reported alongside the
        // scheduling the adapter does not model rather than as a second row.
        let detail = if spec.callable.kind() == "class_parameter" {
            "a primary-constructor parameter default runs only at a construction that omits the argument, and its order against property initializers and init blocks is not yet modeled"
        } else if spec.delegated {
            "delegated property getValue/setValue dispatch is compiler-generated, and initializer scheduling across property initializers and init blocks is not yet modeled"
        } else {
            "initializer scheduling and source-order composition across property initializers and init blocks are not yet modeled"
        };
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::DeferredExecution,
            SemanticGapKind::Unsupported,
            detail,
        )?;
    }
    if spec.is_suspend {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Procedure,
            SemanticCapability::AsyncSuspendResume,
            SemanticGapKind::Unsupported,
            "suspend bodies are rewritten into continuation-passing form by the compiler, so suspension and resumption points are not source-backed",
        )?;
    }
    let delegation_call = (spec.kind == ProcedureKind::Constructor)
        .then(|| child_of_kind(spec.callable, "constructor_delegation_call"))
        .flatten();
    if spec.kind == ProcedureKind::Constructor && delegation_call.is_none() {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unsupported,
            "implicit primary-constructor delegation is not yet represented as a call site",
        )?;
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            "implicit primary-constructor delegation can complete exceptionally",
        )?;
    }

    let body_entry = context.point(&mut builder, spec.body.scan_root(), Vec::new())?;
    let mut initial = Vec::new();
    match spec.body {
        ProcedureBody::Statements(statements) => {
            let tail = context.result_tail(&mut builder, spec, statements, normal_exit)?;
            initial.push(Work::Statement {
                node: statements,
                entry: body_entry,
                next: tail,
                scope: function_scope,
            });
        }
        ProcedureBody::Expression(expression) => {
            let next = if spec.kind == ProcedureKind::Initializer {
                EdgeTarget::normal(normal_exit)
            } else {
                context.implicit_return(&mut builder, expression, normal_exit)?
            };
            initial.push(Work::Expression {
                node: expression,
                entry: body_entry,
                next,
                scope: function_scope,
            });
        }
        ProcedureBody::Statement(node) => {
            initial.push(Work::Statement {
                node,
                entry: body_entry,
                next: EdgeTarget::normal(normal_exit),
                scope: function_scope,
            });
        }
        ProcedureBody::Empty(_) => {
            context.edge(&mut builder, body_entry, EdgeTarget::normal(normal_exit))?;
        }
    }

    if let Some(delegation) = delegation_call {
        let delegation_entry = context.point(&mut builder, delegation, Vec::new())?;
        context.edge(&mut builder, entry, EdgeTarget::normal(delegation_entry))?;
        initial.push(Work::Expression {
            node: delegation,
            entry: delegation_entry,
            next: EdgeTarget::normal(body_entry),
            scope: function_scope,
        });
    } else {
        context.edge(&mut builder, entry, EdgeTarget::normal(body_entry))?;
    }

    drive_and_finish_procedure(
        builder,
        initial,
        entry,
        normal_exit,
        exceptional_exit,
        cancellation,
        |builder, work, stack| context.step(builder, work, stack),
    )
}

impl<'tree, 'targets> LoweringContext<'tree, 'targets> {
    /// Where a `statements` body flows when it completes normally.
    ///
    /// A lambda's trailing expression is its result, so the block flows through
    /// an implicit return that carries that expression's value. Every other
    /// block falls through to the normal exit, matching Kotlin's implicit
    /// `Unit` result.
    fn result_tail(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        spec: &ProcedureSpec<'tree>,
        statements: Node<'tree>,
        normal_exit: ProgramPointId,
    ) -> Result<EdgeTarget, KotlinLoweringError> {
        if spec.kind != ProcedureKind::Lambda {
            return Ok(EdgeTarget::normal(normal_exit));
        }
        let Some(tail) = named_children(statements)
            .last()
            .copied()
            .filter(|node| !is_inert_statement(node.kind()) && node.kind() != "assignment")
        else {
            return Ok(EdgeTarget::normal(normal_exit));
        };
        self.implicit_return(builder, tail, normal_exit)
    }

    /// An implicit return that publishes `expression`'s value as the result.
    fn implicit_return(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        expression: Node<'tree>,
        normal_exit: ProgramPointId,
    ) -> Result<EdgeTarget, KotlinLoweringError> {
        let point = self.point(builder, expression, Vec::new())?;
        let source =
            self.expression_value(builder, expression, expression_value_kind(expression))?;
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
        self.edge(builder, point, EdgeTarget::normal(normal_exit))?;
        Ok(EdgeTarget::normal(point))
    }

    fn step(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        work: Work<'tree>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), KotlinLoweringError> {
        if self.session.cancellation().is_cancelled() {
            return Err(KotlinLoweringError::Cancelled(Box::default()));
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
    ) -> Result<(), KotlinLoweringError> {
        match node.kind() {
            // A folded literal keeps exactly one arm, so an `if (false)` body
            // is never reachable. The guard row is what still says the branch
            // was constant after the fold removed the other edge (#2443).
            "boolean_literal" => match boolean_literal_value(self.prepared.source(), node) {
                Some(true) => {
                    self.edge(builder, entry, when_true)?;
                    self.record_guard(builder, entry, node, Some(when_true), None)
                }
                Some(false) => {
                    self.edge(builder, entry, when_false)?;
                    self.record_guard(builder, entry, node, None, Some(when_false))
                }
                None => {
                    self.opaque_condition(builder, node, entry, when_true, when_false, scope, stack)
                }
            },
            "conjunction_expression" | "disjunction_expression" => {
                let operands = binary_operands(node);
                let (Some(left), Some(right)) =
                    (operands.first().copied(), operands.get(1).copied())
                else {
                    return self.opaque_condition(
                        builder, node, entry, when_true, when_false, scope, stack,
                    );
                };
                let right_entry = self.point(builder, right, Vec::new())?;
                let kind = if node.kind() == "conjunction_expression" {
                    ShortCircuitKind::And
                } else {
                    ShortCircuitKind::Or
                };
                schedule_short_circuit_condition(
                    stack,
                    kind,
                    (left, entry),
                    (right, right_entry),
                    when_true,
                    when_false,
                    scope,
                    Work::condition,
                );
                Ok(())
            }
            "prefix_expression" if has_token(node, "!") => {
                let Some(operand) = unary_operand(node) else {
                    return self.opaque_condition(
                        builder, node, entry, when_true, when_false, scope, stack,
                    );
                };
                stack.push(Work::Condition {
                    node: operand,
                    entry,
                    when_true: when_false,
                    when_false: when_true,
                    scope,
                });
                Ok(())
            }
            "parenthesized_expression" => {
                let Some(inner) = first_named_child(node) else {
                    return self.opaque_condition(
                        builder, node, entry, when_true, when_false, scope, stack,
                    );
                };
                stack.push(Work::Condition {
                    node: inner,
                    entry,
                    when_true,
                    when_false,
                    scope,
                });
                Ok(())
            }
            "if_expression" => {
                let condition = required_child(node, "condition")?;
                let (Some(consequence), Some(alternative)) = (
                    node.child_by_field_name("consequence"),
                    node.child_by_field_name("alternative"),
                ) else {
                    return self.opaque_condition(
                        builder, node, entry, when_true, when_false, scope, stack,
                    );
                };
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
            _ => self.opaque_condition(builder, node, entry, when_true, when_false, scope, stack),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn opaque_condition(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        when_true: EdgeTarget,
        when_false: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), KotlinLoweringError> {
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

    /// Publish one normalized guard fact for a decision the condition lowering
    /// just made.
    ///
    /// Only a constant boolean is normalized today. Everything else this
    /// lowerer decides is recorded `Opaque` rather than guessed, so an absent
    /// guard row means the condition lowering made no decision at that point
    /// at all -- which is what makes the [`SemanticCapability::GuardFacts`]
    /// entry readable.
    fn record_guard(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        condition: Node<'tree>,
        when_true: Option<EdgeTarget>,
        when_false: Option<EdgeTarget>,
    ) -> Result<(), KotlinLoweringError> {
        let arm = |target: Option<EdgeTarget>| {
            target.map(|target| GuardArm {
                target_point: target.point,
                kind: target.kind,
            })
        };
        let (predicate, subject) = match self.normalize_condition(condition) {
            Some(predicate) => (predicate, None),
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

    /// Normalize one Kotlin condition into a guard predicate, or answer `None`
    /// when the syntax is represented but not normalizable.
    ///
    /// `!` and parentheses are peeled iteratively before the match, because a
    /// negated guard is the same guard with its outcome swapped rather than a
    /// decision of its own. [`Self::condition`] already peels both by
    /// recursion, so this loop only matters on the fallback paths that reach
    /// [`Self::opaque_condition`] with a wrapper still attached.
    fn normalize_condition(&self, condition: Node<'tree>) -> Option<GuardPredicate> {
        let mut cursor = condition;
        let mut negated = false;
        loop {
            match cursor.kind() {
                "parenthesized_expression" => cursor = first_named_child(cursor)?,
                "prefix_expression" if has_token(cursor, "!") => {
                    negated = !negated;
                    cursor = unary_operand(cursor)?;
                }
                _ => break,
            }
        }
        let value = boolean_literal_value(self.prepared.source(), cursor)?;
        Some(GuardPredicate::ConstantBoolean {
            value: value != negated,
        })
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
    ) -> Result<(), KotlinLoweringError> {
        let scope = if let Some(label) = attached_label
            && !matches!(
                node.kind(),
                "while_statement" | "do_while_statement" | "for_statement"
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
            "statements" | "source_file" => {
                let children = named_children(node);
                self.schedule_statements(builder, entry, &children, next, scope, stack)
            }
            "control_structure_body" => {
                let Some(content) = control_structure_body_content(node) else {
                    return self.edge(builder, entry, next);
                };
                stack.push(Work::Statement {
                    node: content,
                    entry,
                    next,
                    scope,
                });
                Ok(())
            }
            "property_declaration" | "destructuring_declaration" => {
                self.local_declaration(builder, node, entry, next, scope, stack)
            }
            "assignment" => self.assignment(builder, node, entry, next, scope, stack),
            "while_statement" => {
                self.while_statement(builder, node, entry, next, scope, attached_label, stack)
            }
            "do_while_statement" => {
                self.do_while_statement(builder, node, entry, next, scope, attached_label, stack)
            }
            "for_statement" => {
                self.for_statement(builder, node, entry, next, scope, attached_label, stack)
            }
            kind if is_inert_statement(kind) => self.edge(builder, entry, next),
            _ => self.expression(builder, node, entry, next, scope, stack),
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
    ) -> Result<(), KotlinLoweringError> {
        let result = self.expression_value(builder, node, expression_value_kind(node))?;
        if matches!(node.kind(), "simple_identifier" | "this_expression") {
            self.emit_lexical_input_flow(builder, node, entry, result)?;
        }
        match node.kind() {
            "call_expression" => {
                match kotlin_callee(node).filter(|callee| is_safe_navigation(*callee)) {
                    Some(navigation) => {
                        self.safe_call(builder, node, navigation, entry, next, scope, stack)
                    }
                    None => self.call(builder, node, entry, next, scope, false, stack),
                }
            }
            "constructor_invocation" | "constructor_delegation_call" => {
                self.call(builder, node, entry, next, scope, false, stack)
            }
            "navigation_expression" => self.navigation(builder, node, entry, next, scope, stack),
            "indexing_expression" => self.indexing(builder, node, entry, next, scope, stack),
            "if_expression" => self.if_expression(builder, node, entry, next, scope, stack),
            "when_expression" => self.when_expression(builder, node, entry, next, scope, stack),
            "try_expression" => self.try_expression(builder, node, entry, next, scope, stack),
            "elvis_expression" => self.elvis(builder, node, entry, next, scope, stack),
            "postfix_expression" => self.postfix(builder, node, entry, next, scope, stack),
            "jump_expression" => self.jump(builder, node, entry, next, scope, stack),
            "lambda_literal" | "anonymous_function" => {
                self.callable_expression(builder, node, entry, next)
            }
            "callable_reference" => self.callable_reference(builder, node, entry, next),
            "object_literal" => self.object_literal(builder, node, entry, next, scope, stack),
            "conjunction_expression" | "disjunction_expression" => {
                let operands = binary_operands(node);
                let (Some(left), Some(right)) =
                    (operands.first().copied(), operands.get(1).copied())
                else {
                    return self.opaque_operation(builder, node, entry, next, scope, stack);
                };
                let right_entry = self.point(builder, right, Vec::new())?;
                stack.push(Work::Expression {
                    node: right,
                    entry: right_entry,
                    next,
                    scope,
                });
                let (when_true, when_false) = if node.kind() == "conjunction_expression" {
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
            "parenthesized_expression" | "spread_expression" | "interpolated_expression" => {
                // A wrapper mints a result temporary like any other expression,
                // and the parent reads that temporary rather than the inner
                // one. Forwarding the inner value into it is what keeps
                // `(value * 3)` and `"a${value}"` carrying the value they
                // wrap instead of a slot nothing ever wrote.
                match first_named_child(node) {
                    Some(inner) => {
                        let terminal = self.point(builder, node, Vec::new())?;
                        let source =
                            self.expression_value(builder, inner, expression_value_kind(inner))?;
                        self.append_effect(
                            builder,
                            terminal,
                            SemanticEffect::ValueFlow {
                                kind: ValueFlowKind::Local,
                                source,
                                target: result,
                            },
                        )?;
                        self.edge(builder, terminal, next)?;
                        stack.push(Work::Expression {
                            node: inner,
                            entry,
                            next: EdgeTarget::normal(terminal),
                            scope,
                        });
                        Ok(())
                    }
                    None => self.edge(builder, entry, next),
                }
            }
            "string_literal" => {
                let interpolations = named_children(node)
                    .into_iter()
                    .filter(|child| child.kind() == "interpolated_expression")
                    .collect::<Vec<_>>();
                if interpolations.is_empty() {
                    return self.edge(builder, entry, next);
                }
                let terminal = self.point(builder, node, Vec::new())?;
                let operands = interpolations
                    .iter()
                    .map(|child| {
                        self.expression_value(builder, *child, expression_value_kind(*child))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                self.session
                    .append_language_defined_value_flows(builder, terminal, operands, result)?;
                self.edge(builder, terminal, next)?;
                self.schedule_expressions(
                    builder,
                    entry,
                    &interpolations,
                    EdgeTarget::normal(terminal),
                    scope,
                    stack,
                )
            }
            "assignment" => self.assignment(builder, node, entry, next, scope, stack),
            "value_arguments" => {
                if node
                    .parent()
                    .is_some_and(|parent| parent.kind() == "enum_entry")
                {
                    self.add_gap(
                        builder,
                        entry,
                        SemanticGapSubject::Point,
                        SemanticCapability::Calls,
                        SemanticGapKind::Unsupported,
                        "enum entry construction is not yet represented as a call site",
                    )?;
                }
                let arguments = named_children(node)
                    .into_iter()
                    .filter(|child| child.kind() == "value_argument")
                    .filter_map(value_argument_value)
                    .collect::<Vec<_>>();
                self.schedule_expressions(builder, entry, &arguments, next, scope, stack)
            }
            kind if is_runtime_leaf(kind) => self.edge(builder, entry, next),
            _ => self.opaque_operation(builder, node, entry, next, scope, stack),
        }
    }

    /// Evaluate an operation whose result the adapter does not model exactly.
    ///
    /// Kotlin resolves `a + b`, `a to b`, `a[i]`, and `a++` through operator
    /// conventions, which are ordinary member calls the source does not spell.
    /// The operands stay real and the missing call is reported at the point
    /// rather than published as a call row no dispatch could ever resolve.
    fn opaque_operation(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), KotlinLoweringError> {
        if is_operator_convention(node) {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Point,
                SemanticCapability::Calls,
                SemanticGapKind::Unsupported,
                "infix and operator-convention calls are not yet call sites",
            )?;
        } else if !is_structured_operation(node.kind()) {
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
            )?;
        }
        let children = runtime_expression_children(node);
        if children.is_empty() {
            return self.edge(builder, entry, next);
        }
        let result = self.expression_value(builder, node, expression_value_kind(node))?;
        let terminal = self.point(builder, node, Vec::new())?;
        let operands = children
            .iter()
            .map(|child| self.expression_value(builder, *child, expression_value_kind(*child)))
            .collect::<Result<Vec<_>, _>>()?;
        self.session
            .append_language_defined_value_flows(builder, terminal, operands, result)?;
        self.edge(builder, terminal, next)?;
        self.schedule_expressions(
            builder,
            entry,
            &children,
            EdgeTarget::normal(terminal),
            scope,
            stack,
        )
    }

    fn local_declaration(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), KotlinLoweringError> {
        let delegate = property_delegate_expression(node);
        let Some(initializer) = delegate.or_else(|| property_initializer(node)) else {
            return self.edge(builder, entry, next);
        };
        let Some(binding) = binding_node(node) else {
            return self.edge(builder, entry, next);
        };
        let terminal = self.point(builder, node, Vec::new())?;
        if delegate.is_some() {
            self.add_gap(
                builder,
                terminal,
                SemanticGapSubject::Point,
                SemanticCapability::DeferredExecution,
                SemanticGapKind::Unsupported,
                "delegated property getValue/setValue dispatch is compiler-generated",
            )?;
        }
        let names = binding_names(binding);
        if binding.kind() == "multi_variable_declaration" {
            self.add_gap(
                builder,
                terminal,
                SemanticGapSubject::Point,
                SemanticCapability::Calls,
                SemanticGapKind::Unsupported,
                "destructuring componentN operator calls are compiler-generated",
            )?;
        }
        let value =
            self.expression_value(builder, initializer, expression_value_kind(initializer))?;
        for name in names {
            let Some(text) = node_text(self.prepared.source(), name) else {
                continue;
            };
            let Some(target) = self.local_declaration_value(text, name.start_byte()) else {
                continue;
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
                    kind: ValueFlowKind::Local,
                    source: value,
                    target,
                },
            )?;
        }
        self.edge(builder, terminal, next)?;
        stack.push(Work::Expression {
            node: initializer,
            entry,
            next: EdgeTarget::normal(terminal),
            scope,
        });
        Ok(())
    }

    fn assignment(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), KotlinLoweringError> {
        let Some((target_node, value_node)) = assignment_parts(node) else {
            return self.edge(builder, entry, next);
        };
        let Some(value_node) = value_node else {
            return self.edge(builder, entry, next);
        };
        let terminal = self.point(builder, node, Vec::new())?;
        let value =
            self.expression_value(builder, value_node, expression_value_kind(value_node))?;
        let mut evaluations = Vec::new();
        match assignment_target(target_node) {
            AssignmentTarget::Name(name) => {
                if let Some(text) = node_text(self.prepared.source(), name) {
                    let local = self.local_at(text, name.start_byte());
                    let target = local.or_else(|| self.parameters.get(text).copied());
                    if let Some(target) = target {
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
                    }
                }
            }
            AssignmentTarget::Field { base, member } => {
                let base_value =
                    self.expression_value(builder, base, expression_value_kind(base))?;
                let location = self.session.add_memory_location(
                    builder,
                    terminal,
                    MemoryLocationKind::Field {
                        base: base_value,
                        member: self.memory_member_locator(member)?,
                    },
                )?;
                self.add_field_identity_gap(builder, terminal, location)?;
                self.append_effect(
                    builder,
                    terminal,
                    SemanticEffect::MemoryStore {
                        kind: MemoryAccessKind::Field,
                        location,
                        value,
                    },
                )?;
                evaluations.push(base);
            }
            AssignmentTarget::Index { base, index } => {
                let base_value =
                    self.expression_value(builder, base, expression_value_kind(base))?;
                let index_value = index
                    .map(|index| {
                        self.expression_value(builder, index, expression_value_kind(index))
                    })
                    .transpose()?;
                let location = self.session.add_memory_location(
                    builder,
                    terminal,
                    MemoryLocationKind::Index {
                        base: base_value,
                        index: index_value,
                    },
                )?;
                self.add_gap(
                    builder,
                    terminal,
                    SemanticGapSubject::Point,
                    SemanticCapability::Calls,
                    SemanticGapKind::Unsupported,
                    "indexed assignment resolves through the `set` operator convention, which is not yet a call site",
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
                evaluations.push(base);
                evaluations.extend(index);
            }
            AssignmentTarget::Opaque(target) => evaluations.push(target),
        }
        evaluations.push(value_node);
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

    #[allow(clippy::too_many_arguments)]
    fn if_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), KotlinLoweringError> {
        let condition = required_child(node, "condition")?;
        let consequence = node.child_by_field_name("consequence");
        let alternative = node.child_by_field_name("alternative");
        let joins_value = value_is_used(node) && consequence.is_some() && alternative.is_some();
        let arm_next = if joins_value {
            let merge = self.point(builder, node, Vec::new())?;
            self.edge(builder, merge, next)?;
            EdgeTarget::normal(merge)
        } else {
            next
        };

        let when_true = match consequence {
            Some(consequence) => {
                let consequence_entry = self.point(builder, consequence, Vec::new())?;
                if joins_value {
                    self.join_arm_value(builder, node, consequence, arm_next.point)?;
                }
                stack.push(Work::Statement {
                    node: consequence,
                    entry: consequence_entry,
                    next: arm_next,
                    scope,
                });
                EdgeTarget {
                    point: consequence_entry,
                    kind: ControlEdgeKind::ConditionalTrue,
                }
            }
            None => EdgeTarget {
                point: arm_next.point,
                kind: ControlEdgeKind::ConditionalTrue,
            },
        };
        let when_false = match alternative {
            Some(alternative) => {
                let alternative_entry = self.point(builder, alternative, Vec::new())?;
                if joins_value {
                    self.join_arm_value(builder, node, alternative, arm_next.point)?;
                }
                stack.push(Work::Statement {
                    node: alternative,
                    entry: alternative_entry,
                    next: arm_next,
                    scope,
                });
                EdgeTarget {
                    point: alternative_entry,
                    kind: ControlEdgeKind::ConditionalFalse,
                }
            }
            None => EdgeTarget {
                point: arm_next.point,
                kind: ControlEdgeKind::ConditionalFalse,
            },
        };
        stack.push(Work::Condition {
            node: condition,
            entry,
            when_true,
            when_false,
            scope,
        });
        Ok(())
    }

    /// Flow the value one arm of a value-producing `if`/`when`/`try` produces
    /// into the shared result at the join point.
    fn join_arm_value(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        owner: Node<'tree>,
        arm: Node<'tree>,
        join: ProgramPointId,
    ) -> Result<(), KotlinLoweringError> {
        let Some(expression) = result_expression(arm) else {
            return Ok(());
        };
        let result = self.expression_value(builder, owner, expression_value_kind(owner))?;
        let source =
            self.expression_value(builder, expression, expression_value_kind(expression))?;
        if source == result {
            return Ok(());
        }
        self.append_effect(
            builder,
            join,
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::LanguageDefined,
                source,
                target: result,
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn when_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), KotlinLoweringError> {
        let subject = when_subject_expression(node);
        let entries = when_entries(node);
        let dispatch = self.point(builder, node, Vec::new())?;
        let merge = self.point(builder, node, Vec::new())?;
        self.edge(builder, merge, next)?;
        let arm_next = EdgeTarget::normal(merge);
        let joins_value = value_is_used(node);

        // Bodies first, so every arm has an entry point before the condition
        // chain is stitched backwards through them.
        let mut arm_entries = Vec::with_capacity(entries.len());
        for arm in &entries {
            let body = when_entry_body(*arm);
            let arm_entry = self.point(builder, body.unwrap_or(*arm), Vec::new())?;
            arm_entries.push(arm_entry);
        }
        for (index, arm) in entries.iter().enumerate().rev() {
            match when_entry_body(*arm) {
                Some(body) => {
                    if joins_value {
                        self.join_arm_value(builder, node, body, merge)?;
                    }
                    stack.push(Work::Statement {
                        node: body,
                        entry: arm_entries[index],
                        next: arm_next,
                        scope,
                    });
                }
                None => self.edge(builder, arm_entries[index], arm_next)?,
            }
        }

        let else_index = entries
            .iter()
            .position(|arm| when_entry_conditions(*arm).is_empty());
        let mut no_match = match else_index {
            Some(index) => EdgeTarget::normal(arm_entries[index]),
            None => {
                let unmatched = self.point(builder, node, Vec::new())?;
                if joins_value {
                    self.add_gap(
                        builder,
                        unmatched,
                        SemanticGapSubject::Point,
                        SemanticCapability::ExceptionalControlFlow,
                        SemanticGapKind::Unknown,
                        "an unmatched when subject in value position throws; exhaustiveness requires type refinement",
                    )?;
                }
                self.edge(builder, unmatched, arm_next)?;
                EdgeTarget::normal(unmatched)
            }
        };

        for (index, arm) in entries.iter().enumerate().rev() {
            if else_index == Some(index) {
                continue;
            }
            let conditions = when_entry_conditions(*arm);
            let success = match when_entry_guard(*arm) {
                Some(guard) => {
                    let guard_entry = self.point(builder, guard, Vec::new())?;
                    stack.push(Work::Condition {
                        node: guard,
                        entry: guard_entry,
                        when_true: EdgeTarget {
                            point: arm_entries[index],
                            kind: ControlEdgeKind::ConditionalTrue,
                        },
                        when_false: EdgeTarget {
                            point: no_match.point,
                            kind: ControlEdgeKind::ConditionalFalse,
                        },
                        scope,
                    });
                    EdgeTarget {
                        point: guard_entry,
                        kind: ControlEdgeKind::SwitchCase,
                    }
                }
                None => EdgeTarget {
                    point: arm_entries[index],
                    kind: ControlEdgeKind::SwitchCase,
                },
            };
            // Comma-separated conditions are an OR chain: the first match wins,
            // and the last failure falls through to the next entry.
            for condition in conditions.iter().rev() {
                let condition_entry = self.point(builder, *condition, Vec::new())?;
                let decision = self.point(builder, *condition, Vec::new())?;
                self.edge(builder, decision, success)?;
                self.edge(
                    builder,
                    decision,
                    EdgeTarget {
                        point: no_match.point,
                        kind: ControlEdgeKind::ConditionalFalse,
                    },
                )?;
                match when_condition_operand(*condition) {
                    Some(operand) => stack.push(Work::Expression {
                        node: operand,
                        entry: condition_entry,
                        next: EdgeTarget::normal(decision),
                        scope,
                    }),
                    None => self.edge(builder, condition_entry, EdgeTarget::normal(decision))?,
                }
                no_match = EdgeTarget::normal(condition_entry);
            }
        }
        self.edge(builder, dispatch, no_match)?;
        match subject {
            Some(subject) => stack.push(Work::Expression {
                node: subject,
                entry,
                next: EdgeTarget::normal(dispatch),
                scope,
            }),
            None => self.edge(builder, entry, EdgeTarget::normal(dispatch))?,
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn while_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        label: Option<&'tree str>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), KotlinLoweringError> {
        let (condition, body) =
            while_statement_parts(node).ok_or_else(|| missing_slot(node, "loop condition"))?;
        let body_entry = self.point(builder, body.unwrap_or(node), Vec::new())?;
        let loop_scope = builder.push_scope(
            Some(scope),
            ScopeBinding::Loop {
                label: label.map(Box::<str>::from),
                break_target: next.point,
                break_edge_kind: next.kind,
                continue_target: entry,
                continue_edge_kind: ControlEdgeKind::LoopBack,
            },
        );
        let loop_back = EdgeTarget {
            point: entry,
            kind: ControlEdgeKind::LoopBack,
        };
        match body {
            Some(body) => stack.push(Work::Statement {
                node: body,
                entry: body_entry,
                next: loop_back,
                scope: loop_scope,
            }),
            None => self.edge(builder, body_entry, loop_back)?,
        }
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

    #[allow(clippy::too_many_arguments)]
    fn do_while_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        label: Option<&'tree str>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), KotlinLoweringError> {
        let (body, condition) =
            do_while_statement_parts(node).ok_or_else(|| missing_slot(node, "loop condition"))?;
        let condition_entry = self.point(builder, condition, Vec::new())?;
        let loop_scope = builder.push_scope(
            Some(scope),
            ScopeBinding::Loop {
                label: label.map(Box::<str>::from),
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
        match body {
            Some(body) => stack.push(Work::Statement {
                node: body,
                entry,
                next: EdgeTarget::normal(condition_entry),
                scope: loop_scope,
            }),
            None => self.edge(builder, entry, EdgeTarget::normal(condition_entry))?,
        }
        Ok(())
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
    ) -> Result<(), KotlinLoweringError> {
        let (binding, iterable, body) =
            for_statement_parts(node).ok_or_else(|| missing_slot(node, "for-in parts"))?;
        let header = self.point(builder, binding, Vec::new())?;
        // An integer-literal-bounded range provably yields a first element, and
        // the compiler lowers such a `for` into a counted loop with no iterator
        // object at all. Entering at the binding rather than at the header is
        // what keeps a zero-trip path from claiming the body never ran. Without
        // the proof the header keeps carrying the rebinding itself, so an
        // unprovable iterable lowers exactly as before.
        let first_iteration = kotlin_range_has_first_iteration(self.prepared.source(), iterable);
        let binding_point = if first_iteration {
            self.point(builder, binding, Vec::new())?
        } else {
            header
        };
        let body_entry = self.point(builder, body.unwrap_or(node), Vec::new())?;
        let loop_scope = builder.push_scope(
            Some(scope),
            ScopeBinding::Loop {
                label: label.map(Box::<str>::from),
                break_target: next.point,
                break_edge_kind: next.kind,
                continue_target: header,
                continue_edge_kind: ControlEdgeKind::LoopBack,
            },
        );
        let destructures = binding.kind() == "multi_variable_declaration";
        if !first_iteration {
            self.add_gap(
                builder,
                header,
                SemanticGapSubject::Point,
                SemanticCapability::Calls,
                SemanticGapKind::Unsupported,
                if destructures {
                    "implicit iterator()/hasNext()/next() and destructuring componentN operator calls are compiler-generated"
                } else {
                    "implicit iterator()/hasNext()/next() operator calls are compiler-generated"
                },
            )?;
            self.add_gap(
                builder,
                header,
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unsupported,
                "implicit iterator acquisition and advancement exceptions are not yet lowered",
            )?;
        }
        let names = binding_names(binding);
        // Each iteration rebinds the loop variables to a value the iterator
        // produces, which no source expression names.
        for name in names {
            let Some(text) = node_text(self.prepared.source(), name) else {
                continue;
            };
            let Some(target) = self.local_declaration_value(text, name.start_byte()) else {
                continue;
            };
            let element = self.value(builder, binding_point, SemanticValueKind::Temporary)?;
            self.append_effect(
                builder,
                binding_point,
                SemanticEffect::Assignment {
                    target,
                    value: element,
                },
            )?;
            self.append_effect(
                builder,
                binding_point,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Local,
                    source: element,
                    target,
                },
            )?;
        }
        self.edge(
            builder,
            header,
            EdgeTarget {
                point: if first_iteration {
                    binding_point
                } else {
                    body_entry
                },
                kind: ControlEdgeKind::ConditionalTrue,
            },
        )?;
        if first_iteration {
            self.edge(builder, binding_point, EdgeTarget::normal(body_entry))?;
        }
        self.edge(
            builder,
            header,
            EdgeTarget {
                point: next.point,
                kind: ControlEdgeKind::ConditionalFalse,
            },
        )?;
        let loop_back = EdgeTarget {
            point: header,
            kind: ControlEdgeKind::LoopBack,
        };
        match body {
            Some(body) => stack.push(Work::Statement {
                node: body,
                entry: body_entry,
                next: loop_back,
                scope: loop_scope,
            }),
            None => self.edge(builder, body_entry, loop_back)?,
        }
        stack.push(Work::Expression {
            node: iterable,
            entry,
            next: EdgeTarget::normal(if first_iteration {
                binding_point
            } else {
                header
            }),
            scope: loop_scope,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn try_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), KotlinLoweringError> {
        let children = named_children(node);
        let body = children
            .iter()
            .copied()
            .find(|child| child.kind() == "statements");
        let catches = children
            .iter()
            .copied()
            .filter(|child| child.kind() == "catch_block")
            .collect::<Vec<_>>();
        let finalizer = children
            .iter()
            .copied()
            .find(|child| child.kind() == "finally_block")
            .and_then(|clause| child_of_kind(clause, "statements"));
        let joins_value = value_is_used(node);

        let (cleanup_scope, cleanup_region) = if let Some(finalizer) = finalizer {
            let region =
                CleanupRegionId::new(u32::try_from(self.cleanups.len()).map_err(|_| {
                    KotlinLoweringError::Invalid("too many cleanup regions".into())
                })?);
            self.cleanups.push(CleanupRegion {
                id: region,
                body: finalizer,
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
            .map(|catch| (*catch, child_of_kind(*catch, "statements")))
            .collect::<Vec<_>>();
        let catch_entries = catch_bodies
            .iter()
            .map(|(catch, body)| self.point(builder, body.unwrap_or(*catch), Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        let try_scope = if catch_entries.is_empty() {
            cleanup_scope
        } else {
            let dispatcher = self.point(builder, node, Vec::new())?;
            self.add_gap(
                builder,
                dispatcher,
                SemanticGapSubject::Point,
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unknown,
                "catch pattern compatibility and exception binding require type refinement",
            )?;
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
                None,
                stack,
            )?;
            builder.push_scope(
                Some(cleanup_scope),
                ScopeBinding::Handler { entry: dispatcher },
            )
        };

        for ((catch, catch_body), catch_entry) in catch_bodies.iter().zip(&catch_entries) {
            let catch_exit = self.point(builder, *catch, Vec::new())?;
            if joins_value && let Some(body) = catch_body {
                self.join_arm_value(builder, node, *body, catch_exit)?;
            }
            if let Some(route) = &normal_route {
                self.route(builder, catch_exit, route, stack)?;
            } else {
                self.edge(builder, catch_exit, next)?;
            }
            match catch_body {
                Some(body) => stack.push(Work::Statement {
                    node: *body,
                    entry: *catch_entry,
                    next: EdgeTarget::normal(catch_exit),
                    scope: cleanup_scope,
                }),
                None => self.edge(builder, *catch_entry, EdgeTarget::normal(catch_exit))?,
            }
        }

        let body_exit = self.point(builder, body.unwrap_or(node), Vec::new())?;
        if joins_value && let Some(body) = body {
            self.join_arm_value(builder, node, body, body_exit)?;
        }
        if let Some(route) = &normal_route {
            self.route(builder, body_exit, route, stack)?;
        } else {
            self.edge(builder, body_exit, next)?;
        }
        match body {
            Some(body) => stack.push(Work::Statement {
                node: body,
                entry,
                next: EdgeTarget::normal(body_exit),
                scope: try_scope,
            }),
            None => self.edge(builder, entry, EdgeTarget::normal(body_exit))?,
        }
        Ok(())
    }

    /// `lhs ?: rhs` — the right operand runs only when the left is null.
    fn elvis(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), KotlinLoweringError> {
        let operands = binary_operands(node);
        let (Some(left), Some(right)) = (operands.first().copied(), operands.get(1).copied())
        else {
            return self.opaque_operation(builder, node, entry, next, scope, stack);
        };
        let result = self.expression_value(builder, node, expression_value_kind(node))?;
        let test = self.point(builder, node, Vec::new())?;
        let present = self.point(builder, node, Vec::new())?;
        let right_entry = self.point(builder, right, Vec::new())?;
        let right_exit = self.point(builder, right, Vec::new())?;
        let join = self.point(builder, node, Vec::new())?;
        self.edge(builder, join, next)?;
        self.edge(builder, present, EdgeTarget::normal(join))?;
        self.edge(builder, right_exit, EdgeTarget::normal(join))?;
        self.edge(
            builder,
            test,
            EdgeTarget {
                point: present,
                kind: ControlEdgeKind::ConditionalTrue,
            },
        )?;
        self.edge(
            builder,
            test,
            EdgeTarget {
                point: right_entry,
                kind: ControlEdgeKind::ConditionalFalse,
            },
        )?;
        let left_value = self.expression_value(builder, left, expression_value_kind(left))?;
        let right_value = self.expression_value(builder, right, expression_value_kind(right))?;
        self.session
            .append_language_defined_value_flows(builder, present, [left_value], result)?;
        self.session.append_language_defined_value_flows(
            builder,
            right_exit,
            [right_value],
            result,
        )?;
        stack.push(Work::Expression {
            node: right,
            entry: right_entry,
            next: EdgeTarget::normal(right_exit),
            scope,
        });
        stack.push(Work::Expression {
            node: left,
            entry,
            next: EdgeTarget::normal(test),
            scope,
        });
        Ok(())
    }

    /// `a!!` completes normally or raises, and `a++`/`a--` are operator calls.
    fn postfix(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), KotlinLoweringError> {
        if !has_token(node, "!!") {
            return self.opaque_operation(builder, node, entry, next, scope, stack);
        }
        let Some(operand) = unary_operand(node) else {
            return self.edge(builder, entry, next);
        };
        let result = self.expression_value(builder, node, expression_value_kind(node))?;
        let check = self.point(builder, node, Vec::new())?;
        let raise = self.point(builder, node, Vec::new())?;
        let operand_value =
            self.expression_value(builder, operand, expression_value_kind(operand))?;
        self.session.append_language_defined_value_flows(
            builder,
            check,
            [operand_value],
            result,
        )?;
        self.edge(builder, check, next)?;
        self.edge(
            builder,
            check,
            EdgeTarget {
                point: raise,
                kind: ControlEdgeKind::Exceptional,
            },
        )?;
        let thrown = self.value(builder, raise, SemanticValueKind::Exception)?;
        self.append_effect(
            builder,
            raise,
            SemanticEffect::Throw {
                value: Some(thrown),
            },
        )?;
        self.abrupt(
            builder,
            raise,
            scope,
            CompletionKind::Throw,
            None,
            None,
            stack,
        )?;
        stack.push(Work::Expression {
            node: operand,
            entry,
            next: EdgeTarget::normal(check),
            scope,
        });
        Ok(())
    }

    fn jump(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), KotlinLoweringError> {
        let keyword = first_token(node).ok_or_else(|| missing_slot(node, "jump keyword"))?;
        let label = jump_label(node)
            .and_then(|label| node_text(self.prepared.source(), label))
            .filter(|label| !label.is_empty());
        match keyword {
            "throw" => {
                let operand =
                    jump_operand(node).ok_or_else(|| missing_slot(node, "thrown expression"))?;
                let terminal = self.point(builder, node, Vec::new())?;
                let value = self.value(builder, terminal, SemanticValueKind::Exception)?;
                self.append_effect(
                    builder,
                    terminal,
                    SemanticEffect::Throw { value: Some(value) },
                )?;
                stack.push(Work::Expression {
                    node: operand,
                    entry,
                    next: EdgeTarget::normal(terminal),
                    scope,
                });
                self.abrupt(
                    builder,
                    terminal,
                    scope,
                    CompletionKind::Throw,
                    None,
                    None,
                    stack,
                )
            }
            "return" | "return@" => {
                let terminal = if let Some(operand) = jump_operand(node) {
                    let point = self.point(builder, node, Vec::new())?;
                    let source =
                        self.expression_value(builder, operand, expression_value_kind(operand))?;
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
                        node: operand,
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
                // Inside a lambda, only `return@label` naming this lambda's own
                // boundary returns from it; every other form returns from an
                // enclosing inline caller this adapter does not model.
                let returns_from_this_lambda = !self.is_lambda
                    || label.is_some_and(|label| self.boundary_label == Some(label));
                if !returns_from_this_lambda {
                    self.add_gap(
                        builder,
                        terminal,
                        SemanticGapSubject::Point,
                        SemanticCapability::NonLocalControl,
                        SemanticGapKind::Unsupported,
                        "non-local return through an inline caller is not modeled",
                    )?;
                }
                self.abrupt(
                    builder,
                    terminal,
                    scope,
                    CompletionKind::Return,
                    None,
                    None,
                    stack,
                )
            }
            "break" | "break@" | "continue" | "continue@" => {
                let kind = if keyword.starts_with("break") {
                    CompletionKind::Break
                } else {
                    CompletionKind::Continue
                };
                self.abrupt(builder, entry, scope, kind, label, Some(next), stack)
            }
            _ => {
                let detail = format!("{keyword} jump syntax is not yet lowered structurally");
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Point,
                    SemanticCapability::NormalControlFlow,
                    SemanticGapKind::Unsupported,
                    &detail,
                )?;
                self.edge(builder, entry, next)
            }
        }
    }

    /// `receiver?.member` and `receiver?.member(…)` skip the whole selection
    /// when the receiver is null, so the selection sits on the non-null arm and
    /// both arms join on one result.
    #[allow(clippy::too_many_arguments)]
    fn safe_call(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        navigation: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), KotlinLoweringError> {
        let receiver = kotlin_navigation_receiver(navigation)
            .ok_or_else(|| missing_slot(navigation, "navigation receiver"))?;
        let gate = self.null_gate(builder, node, next)?;
        self.call(
            builder,
            node,
            gate.gated,
            EdgeTarget::normal(gate.join),
            scope,
            true,
            stack,
        )?;
        stack.push(Work::Expression {
            node: receiver,
            entry,
            next: EdgeTarget::normal(gate.test),
            scope,
        });
        Ok(())
    }

    fn navigation(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), KotlinLoweringError> {
        let receiver = kotlin_navigation_receiver(node)
            .ok_or_else(|| missing_slot(node, "navigation receiver"))?;
        let Some(member) = navigation_member(node) else {
            return self.opaque_operation(builder, node, entry, next, scope, stack);
        };
        if is_safe_navigation(node) {
            let gate = self.null_gate(builder, node, next)?;
            let access = self.property_load(
                builder,
                node,
                receiver,
                member,
                EdgeTarget::normal(gate.join),
            )?;
            self.edge(builder, gate.gated, EdgeTarget::normal(access))?;
            stack.push(Work::Expression {
                node: receiver,
                entry,
                next: EdgeTarget::normal(gate.test),
                scope,
            });
            return Ok(());
        }
        let access = self.property_load(builder, node, receiver, member, next)?;
        self.schedule_expressions(
            builder,
            entry,
            &[receiver],
            EdgeTarget::normal(access),
            scope,
            stack,
        )
    }

    /// One property read, published as a field access whose exact declaration
    /// identity — instance member, top-level property, or `object` member —
    /// stays an explicit gap.
    fn property_load(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        receiver: Node<'tree>,
        member: Node<'tree>,
        next: EdgeTarget,
    ) -> Result<ProgramPointId, KotlinLoweringError> {
        let result = self.expression_value(builder, node, expression_value_kind(node))?;
        let access = self.point(builder, node, Vec::new())?;
        let base = self.expression_value(builder, receiver, expression_value_kind(receiver))?;
        let location = self.session.add_memory_location(
            builder,
            access,
            MemoryLocationKind::Field {
                base,
                member: self.memory_member_locator(member)?,
            },
        )?;
        self.add_field_identity_gap(builder, access, location)?;
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
        Ok(access)
    }

    fn indexing(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), KotlinLoweringError> {
        let Some((base, index)) = indexing_parts(node) else {
            return self.opaque_operation(builder, node, entry, next, scope, stack);
        };
        let result = self.expression_value(builder, node, expression_value_kind(node))?;
        let access = self.point(builder, node, Vec::new())?;
        self.add_gap(
            builder,
            access,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unsupported,
            "indexed access resolves through the `get` operator convention, which is not yet a call site",
        )?;
        let base_value = self.expression_value(builder, base, expression_value_kind(base))?;
        let index_value = index
            .map(|index| self.expression_value(builder, index, expression_value_kind(index)))
            .transpose()?;
        let location = self.session.add_memory_location(
            builder,
            access,
            MemoryLocationKind::Index {
                base: base_value,
                index: index_value,
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
        let mut evaluations = vec![base];
        evaluations.extend(index);
        self.schedule_expressions(
            builder,
            entry,
            &evaluations,
            EdgeTarget::normal(access),
            scope,
            stack,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn call(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        receiver_already_evaluated: bool,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), KotlinLoweringError> {
        let invoke = self.point(builder, node, Vec::new())?;
        let normal = self.point(builder, node, Vec::new())?;
        let exceptional = self.point(builder, node, Vec::new())?;
        let callee = self.value(builder, invoke, SemanticValueKind::Callable)?;
        let result = self.expression_value(builder, node, SemanticValueKind::Temporary)?;
        let thrown = self.value(builder, invoke, SemanticValueKind::Exception)?;
        let callee_node = kotlin_callee(node);
        let receiver_node = callee_node
            .filter(|callee| callee.kind() == "navigation_expression")
            .and_then(kotlin_navigation_receiver);
        let receiver = receiver_node
            .map(|receiver_node| {
                self.expression_value(builder, receiver_node, expression_value_kind(receiver_node))
            })
            .transpose()?;
        // `Box(input)` is spelled as an ordinary call, so a construction is
        // recognised from the callee naming a class this file declares.
        let constructs_declared_class = node.kind() == "call_expression"
            && callee_node.is_some_and(|callee| self.names_constructible_class(callee));
        let is_constructor = matches!(
            node.kind(),
            "constructor_invocation" | "constructor_delegation_call"
        ) || constructs_declared_class;
        let callable_kind = if is_constructor {
            CallableReferenceKind::Constructor
        } else if receiver.is_some() {
            CallableReferenceKind::BoundMethod
        } else {
            CallableReferenceKind::UnboundMethod
        };
        let resolution = callee_node
            .filter(|callee| callee.kind() == "simple_identifier")
            .and_then(|callee| node_text(self.prepared.source(), callee))
            .and_then(|name| self.local_callables.get(name).copied())
            .map_or(CallableTargetResolution::Unknown, |target| {
                CallableTargetResolution::Proven(CallableTarget::Local(target.id))
            });
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

        let arguments = call_arguments(node);
        let argument_values = arguments
            .iter()
            .map(|argument| {
                self.expression_value(
                    builder,
                    argument.value,
                    expression_value_kind(argument.value),
                )
                .map(|value| SemanticCallArgument {
                    value,
                    expansion: argument.expansion(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        debug_assert_eq!(
            arguments.len(),
            kotlin_call_arity(node),
            "argument evaluation and call arity must agree about the trailing lambda"
        );
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
        if node.kind() == "constructor_invocation" || constructs_declared_class {
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
            None,
            stack,
        )?;
        self.resolution_gaps(builder, invoke, callee, call_site, &resolution)?;
        if !is_constructor && resolution == CallableTargetResolution::Unknown {
            self.add_gap(
                builder,
                invoke,
                SemanticGapSubject::CallSite(call_site),
                SemanticCapability::DynamicDispatch,
                SemanticGapKind::Unknown,
                "a Kotlin call may select an override; open/final dispatch and complete override coverage require type-hierarchy refinement",
            )?;
        }

        let mut evaluations = Vec::with_capacity(arguments.len() + 1);
        if !receiver_already_evaluated {
            evaluations.extend(receiver_node);
        }
        evaluations.extend(arguments.iter().map(|argument| argument.value));
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
    ) -> Result<(), KotlinLoweringError> {
        let result = self.expression_value(builder, node, SemanticValueKind::Callable)?;
        let target = self.procedure_targets.get(&node.id()).copied();
        let resolution = target
            .map(|target| CallableTargetResolution::Proven(CallableTarget::Local(target.id)))
            .unwrap_or(CallableTargetResolution::Unknown);
        let metadata = self.metadata(entry)?;
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
        self.append_effect(
            builder,
            entry,
            SemanticEffect::CallableCreation {
                result,
                callable: CallableValue {
                    kind: CallableReferenceKind::Lambda,
                    targets: resolution.clone(),
                    target_evidence: metadata.evidence,
                    bound_receiver: None,
                    environment,
                },
            },
        )?;
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

    fn callable_reference(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
    ) -> Result<(), KotlinLoweringError> {
        let reference = self.point(builder, node, Vec::new())?;
        let result = self.expression_value(builder, node, SemanticValueKind::Callable)?;
        let qualified = child_of_kind(node, "type_identifier").is_some();
        let metadata = self.metadata(reference)?;
        self.append_effect(
            builder,
            reference,
            SemanticEffect::CallableReference {
                result,
                callable: CallableValue {
                    kind: if qualified {
                        CallableReferenceKind::UnboundMethod
                    } else {
                        CallableReferenceKind::Function
                    },
                    targets: CallableTargetResolution::Unknown,
                    target_evidence: metadata.evidence,
                    bound_receiver: None,
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
            "callable-reference target and receiver binding require dispatch refinement",
        )?;
        self.edge(builder, entry, EdgeTarget::normal(reference))?;
        self.edge(builder, reference, next)
    }

    fn object_literal(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), KotlinLoweringError> {
        let result = self.expression_value(builder, node, SemanticValueKind::Temporary)?;
        let allocation = self.point(builder, node, Vec::new())?;
        self.session
            .add_allocation(builder, allocation, result, AllocationKind::Object)?;
        let supertypes = named_children(node)
            .into_iter()
            .filter(|child| child.kind() == "delegation_specifier")
            .filter_map(first_named_child)
            .filter(|child| {
                matches!(
                    child.kind(),
                    "constructor_invocation" | "explicit_delegation"
                )
            })
            .collect::<Vec<_>>();
        self.edge(builder, allocation, next)?;
        self.schedule_expressions(
            builder,
            entry,
            &supertypes,
            EdgeTarget::normal(allocation),
            scope,
            stack,
        )
    }

    /// Allocate the shared skeleton of a `?.` selection.
    fn null_gate(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        next: EdgeTarget,
    ) -> Result<NullGate, KotlinLoweringError> {
        let test = self.point(builder, node, Vec::new())?;
        let gated = self.point(builder, node, Vec::new())?;
        let skip = self.point(builder, node, Vec::new())?;
        let join = self.point(builder, node, Vec::new())?;
        let result = self.expression_value(builder, node, expression_value_kind(node))?;
        let absent = self.value(builder, skip, SemanticValueKind::Constant)?;
        self.session
            .append_language_defined_value_flows(builder, skip, [absent], result)?;
        self.edge(builder, join, next)?;
        self.edge(
            builder,
            test,
            EdgeTarget {
                point: gated,
                kind: ControlEdgeKind::ConditionalTrue,
            },
        )?;
        self.edge(
            builder,
            test,
            EdgeTarget {
                point: skip,
                kind: ControlEdgeKind::ConditionalFalse,
            },
        )?;
        self.edge(builder, skip, EdgeTarget::normal(join))?;
        Ok(NullGate { test, gated, join })
    }

    fn schedule_statements(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        entry: ProgramPointId,
        children: &[Node<'tree>],
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), KotlinLoweringError> {
        // A statement label is a preceding sibling of the statement it names,
        // so it is peeled here and carried into that statement's work item.
        let mut items: Vec<(Node<'tree>, Option<&'tree str>)> = Vec::with_capacity(children.len());
        let mut pending_label = None;
        for child in children {
            if child.kind() == "label" {
                pending_label = label_text(self.prepared.source(), *child);
                continue;
            }
            items.push((*child, pending_label.take()));
        }
        if items.is_empty() {
            return self.edge(builder, entry, next);
        }
        let entries = items
            .iter()
            .map(|(child, _)| self.point(builder, *child, Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        self.edge(builder, entry, EdgeTarget::normal(entries[0]))?;
        for index in (0..items.len()).rev() {
            let child_next = entries
                .get(index + 1)
                .copied()
                .map(EdgeTarget::normal)
                .unwrap_or(next);
            let (node, label) = items[index];
            stack.push(match label {
                Some(label) => Work::LabeledStatement {
                    node,
                    label,
                    entry: entries[index],
                    next: child_next,
                    scope,
                },
                None => Work::Statement {
                    node,
                    entry: entries[index],
                    next: child_next,
                    scope,
                },
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
    ) -> Result<(), KotlinLoweringError> {
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

    #[allow(clippy::too_many_arguments)]
    fn abrupt(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        from: ProgramPointId,
        scope: ScopeFrameId,
        kind: CompletionKind,
        label: Option<&str>,
        fallback: Option<EdgeTarget>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), KotlinLoweringError> {
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
                if let Some(fallback) = fallback {
                    self.edge(builder, from, fallback)?;
                }
                return Ok(());
            }
            return Err(KotlinLoweringError::Invalid(format!(
                "{} completion has no matching structured continuation",
                completion_label(kind)
            )));
        };
        self.route(builder, from, &route, stack)
    }

    fn route(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        from: ProgramPointId,
        route: &CompletionRoute,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), KotlinLoweringError> {
        let mut plan = CleanupRoutePlanner::new(route);
        while let Some(step) = plan.next(
            builder,
            &mut self.session,
            &self.cleanups,
            |region| region.id,
            |region| region.body,
        )? {
            let statement_next = if step.next.kind == ControlEdgeKind::Normal {
                step.next
            } else {
                let relay = self.point(builder, step.region.body, Vec::new())?;
                self.edge(builder, relay, step.next)?;
                EdgeTarget::normal(relay)
            };
            stack.push(Work::Statement {
                node: step.region.body,
                entry: step.entry,
                next: statement_next,
                scope: step.region.outer_scope,
            });
        }
        self.edge(builder, from, plan.target())
    }

    fn edge(
        &self,
        builder: &mut ProcedureCfgBuilder,
        source_point: ProgramPointId,
        target: EdgeTarget,
    ) -> Result<(), KotlinLoweringError> {
        self.session
            .add_edge(builder, source_point, target.point, target.kind)
    }
}

#[derive(Debug, Clone, Copy)]
struct NullGate {
    test: ProgramPointId,
    gated: ProgramPointId,
    join: ProgramPointId,
}

/// The value of a `boolean_literal`, which the grammar spells as bare text
/// rather than as two node kinds.
fn boolean_literal_value(source: &str, node: Node<'_>) -> Option<bool> {
    if node.kind() != "boolean_literal" {
        return None;
    }
    match node_text(source, node)? {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// The value of an `integer_literal`, or `None` when it is not a plain decimal
/// the adapter can read exactly.
fn integer_literal_value(source: &str, node: Node<'_>) -> Option<i64> {
    (node.kind() == "integer_literal")
        .then(|| node_text(source, node))
        .flatten()
        .and_then(|text| text.parse().ok())
}

/// Whether an integer-literal-bounded Kotlin range provably yields at least one
/// element, so the loop body runs before the header's exit test is ever taken.
///
/// Only the three range builders the grammar gives structure to are proven:
/// `A..B` (and `A..<B`) as a `range_expression`, and `A until B` / `A downTo B`
/// as an `infix_expression` whose middle child is the operator name. Anything
/// else -- a `step`-wrapped range, a collection, an arbitrary expression --
/// answers `false`, which keeps the shared zero-trip over-approximation.
pub(super) fn kotlin_range_has_first_iteration(source: &str, iterable: Node<'_>) -> bool {
    let operands = binary_operands(iterable);
    match iterable.kind() {
        "range_expression" => {
            let (Some(start), Some(end)) = (operands.first(), operands.get(1)) else {
                return false;
            };
            let (Some(start), Some(end)) = (
                integer_literal_value(source, *start),
                integer_literal_value(source, *end),
            ) else {
                return false;
            };
            // `..` is inclusive of its end, `..<` is not.
            if has_token(iterable, "..<") {
                start < end
            } else {
                start <= end
            }
        }
        "infix_expression" => {
            let [start, operator, end] = operands.as_slice() else {
                return false;
            };
            if operator.kind() != "simple_identifier" {
                return false;
            }
            let (Some(start), Some(end)) = (
                integer_literal_value(source, *start),
                integer_literal_value(source, *end),
            ) else {
                return false;
            };
            match node_text(source, *operator) {
                Some("until") => start < end,
                Some("downTo") => start >= end,
                _ => false,
            }
        }
        _ => false,
    }
}

/// Operations Kotlin resolves through an operator convention: a member call the
/// source never spells.
fn is_operator_convention(node: Node<'_>) -> bool {
    match node.kind() {
        "infix_expression"
        | "additive_expression"
        | "multiplicative_expression"
        | "comparison_expression"
        | "equality_expression"
        | "range_expression" => true,
        "prefix_expression" | "postfix_expression" => {
            has_token(node, "++") || has_token(node, "--") || has_token(node, "-")
        }
        "check_expression" => has_token(node, "in"),
        _ => false,
    }
}

/// Syntax the adapter evaluates opaquely on purpose, with no missing call
/// behind it.
fn is_structured_operation(kind: &str) -> bool {
    matches!(
        kind,
        "prefix_expression"
            | "postfix_expression"
            | "as_expression"
            | "check_expression"
            | "collection_literal"
            | "spread_expression"
            | "annotated_lambda"
            | "call_suffix"
            | "value_argument"
            | "navigation_suffix"
            | "indexing_suffix"
            | "delegation_specifier"
            | "explicit_delegation"
            | "when_subject"
            | "when_condition"
            | "range_test"
            | "modifiers"
            | "annotation"
    )
}
