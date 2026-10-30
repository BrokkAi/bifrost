use brokk_bifrost_semantic::analyzer::semantic::lowering::schedule_sequential_work;

use crate::analyzer::java::semantic::numeric::JavaFloatingType;

use crate::analyzer::java::semantic::numeric::JavaNumericLiteral;

use crate::analyzer::java::semantic::numeric::integral_domain_contains;

use crate::analyzer::java::semantic::numeric::java_numeric_literal;

use crate::analyzer::java::semantic::syntax::*;

use crate::analyzer::java::semantic::values::java_declaration_inventory;

use crate::analyzer::java::semantic::*;

use brokk_bifrost_analysis::analyzer::java_integral_parameter::JavaIntegralDomain;

use brokk_bifrost_analysis::analyzer::java_integral_parameter::JavaScalarType;

use brokk_bifrost_analysis::analyzer::java_integral_parameter::decimal_integer_value;

/// How many elements of one array initializer are stored. A generated lookup
/// table can hold far more, and every stored element is a memory location the
/// flow solver tracks, so the elements past the cap are left to a write gap.
const JAVA_ARRAY_INITIALIZER_ELEMENT_CAP: usize = 1024;

#[derive(Clone, Copy)]
enum JavaCompoundType {
    Primitive(JavaScalarType),
    Boxed(JavaScalarType),
    String,
    Null,
    Unknown,
}

impl JavaCompoundType {
    fn is_floating(self) -> bool {
        matches!(
            self,
            Self::Primitive(JavaScalarType::Float | JavaScalarType::Double)
                | Self::Boxed(JavaScalarType::Float | JavaScalarType::Double)
        )
    }

    fn may_unbox(self) -> bool {
        !matches!(self, Self::Primitive(_))
    }
}

#[derive(Clone, Copy)]
struct JavaCompoundContext {
    left: JavaCompoundType,
    right: JavaCompoundType,
    divisor_nonzero: bool,
    concatenation_call_free: bool,
}

fn java_numeric_compound_can_throw(context: JavaCompoundContext) -> bool {
    // The left operand was already unboxed before evaluation of the RHS.
    context.right.may_unbox()
}

fn java_add_compound_can_throw(context: JavaCompoundContext) -> bool {
    if matches!(context.left, JavaCompoundType::String) {
        !context.concatenation_call_free
    } else {
        java_numeric_compound_can_throw(context)
    }
}

fn java_divide_compound_can_throw(context: JavaCompoundContext) -> bool {
    java_numeric_compound_can_throw(context)
        || (!context.left.is_floating() && !context.right.is_floating() && !context.divisor_nonzero)
}

const JAVA_COMPOUND_OPERATORS: &[CompoundAssignmentOperator<JavaCompoundContext>] = &[
    CompoundAssignmentOperator {
        compound: "+=",
        can_throw: java_add_compound_can_throw,
    },
    CompoundAssignmentOperator {
        compound: "-=",
        can_throw: java_numeric_compound_can_throw,
    },
    CompoundAssignmentOperator {
        compound: "*=",
        can_throw: java_numeric_compound_can_throw,
    },
    CompoundAssignmentOperator {
        compound: "/=",
        can_throw: java_divide_compound_can_throw,
    },
    CompoundAssignmentOperator {
        compound: "%=",
        can_throw: java_divide_compound_can_throw,
    },
    CompoundAssignmentOperator {
        compound: "<<=",
        can_throw: java_numeric_compound_can_throw,
    },
    CompoundAssignmentOperator {
        compound: ">>=",
        can_throw: java_numeric_compound_can_throw,
    },
    CompoundAssignmentOperator {
        compound: ">>>=",
        can_throw: java_numeric_compound_can_throw,
    },
    CompoundAssignmentOperator {
        compound: "&=",
        can_throw: java_numeric_compound_can_throw,
    },
    CompoundAssignmentOperator {
        compound: "|=",
        can_throw: java_numeric_compound_can_throw,
    },
    CompoundAssignmentOperator {
        compound: "^=",
        can_throw: java_numeric_compound_can_throw,
    },
];

pub(in crate::analyzer::java::semantic) fn lower_procedure<'tree, 'targets>(
    prepared: &'tree PreparedSyntaxTree,
    spec: &ProcedureSpec<'tree>,
    procedure_targets: &'targets HashMap<usize, NestedProcedureTarget<'tree>>,
    structural_node_index: &'targets StructuralNodeIndex,
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
        structural_node_index,
        session,
        expression_values: HashMap::default(),
        constant_index_values: HashMap::default(),
        field_declaration_anchors: declaration_inventory.field_anchors,
        source_type_nodes: declaration_inventory.type_nodes,
        type_name_roots: declaration_inventory.type_roots,
        local_types: HashMap::default(),
        local_type_nodes: HashMap::default(),
        array_values: HashSet::default(),
        non_null_values: HashSet::default(),
        catch_binders: HashMap::default(),
        yield_results: HashMap::default(),
        pattern_variable_names: declaration_inventory.pattern_names,
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
    context.emit_lexical_capture_inputs(&mut builder, entry, spec)?;
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
    let implicit_super = spec.kind == ProcedureKind::Constructor
        && !named_children(spec.body)
            .into_iter()
            .any(|child| child.kind() == "explicit_constructor_invocation");
    if implicit_super {
        context.add_gap(
            &mut builder,
            entry,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unsupported,
            "implicit super-constructor invocation is not yet represented as a call site",
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
    let mut pending = vec![initial];
    // The implicit `super()` runs before the body, outside every handler the
    // body declares, so its exception leaves the constructor.
    if implicit_super {
        context.implicit_abort_edge(
            &mut builder,
            spec.callable,
            entry,
            function_scope,
            None,
            &mut pending,
        )?;
    }

    drive_and_finish_procedure(
        builder,
        pending,
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
            let kind = self.assignment_literal_kind(target, *initializer);
            let value = self.expression_value(builder, *initializer, kind)?;
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
        if required_field(node, "operator")?.kind() != "=" {
            return self.compound_assignment_expression(builder, node, entry, next, scope, stack);
        }
        let left = brokk_bifrost_core::analyzer::tree_walk::unwrap_parenthesized_expression(
            required_field(node, "left")?,
        );
        let right = required_field(node, "right")?;
        let lexical_target = self.lexical_reference_binding(left);
        let terminal = self.point(builder, node, Vec::new())?;
        // putstatic initializes after the RHS and writes only on success.
        let evaluation_terminal = if self.static_field_may_initialize(left) {
            let initialize = self.point(builder, left, Vec::new())?;
            self.edge(builder, initialize, EdgeTarget::normal(terminal))?;
            self.implicit_abort_edge(builder, left, initialize, scope, None, stack)?;
            initialize
        } else {
            terminal
        };
        let kind = lexical_target
            .map(|(target, _)| self.assignment_literal_kind(target, right))
            .unwrap_or_else(|| expression_value_kind(right));
        let value = self.expression_value(builder, right, kind)?;
        let result = self.expression_value(builder, node, expression_value_kind(node))?;
        self.append_effect(
            builder,
            terminal,
            SemanticEffect::Assignment {
                target: result,
                value,
            },
        )?;
        if let Some((target, flow)) = lexical_target
            && matches!(flow, ValueFlowKind::Local)
            && self.expression_is_non_null(right)
        {
            self.non_null_values.insert(target);
        }
        if let Some((target, carrier)) = self.assignment_target(builder, terminal, left)? {
            match target {
                CompoundAssignmentTarget::Binding {
                    value: target,
                    flow,
                } => {
                    self.append_effect(
                        builder,
                        terminal,
                        SemanticEffect::Assignment { target, value },
                    )?;
                    self.append_effect(
                        builder,
                        terminal,
                        SemanticEffect::ValueFlow {
                            kind: flow,
                            source: value,
                            target,
                        },
                    )?;
                }
                CompoundAssignmentTarget::Memory { location, kind } => {
                    self.append_effect(
                        builder,
                        terminal,
                        SemanticEffect::MemoryStore {
                            kind,
                            location,
                            value,
                        },
                    )?;
                }
            }
            if let Some(carrier) = carrier {
                self.assign_implicit_field_carrier(builder, terminal, carrier, value)?;
            }
        }
        let evaluations = match left.kind() {
            "identifier" => vec![right],
            "field_access" => vec![required_field(left, "object")?, right],
            "array_access" => vec![
                required_field(left, "array")?,
                required_field(left, "index")?,
                right,
            ],
            _ => runtime_expression_children(node),
        };
        self.edge(builder, terminal, next)?;
        self.schedule_expressions(
            builder,
            entry,
            &evaluations,
            EdgeTarget::normal(evaluation_terminal),
            scope,
            stack,
        )
    }

    /// Java selects the storage address once. Shared lowering owns the
    /// compound write; an implicit instance field additionally updates its
    /// existing procedure-local carrier on that same normal continuation.
    fn assignment_target(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        left: Node<'tree>,
    ) -> Result<Option<(CompoundAssignmentTarget, Option<ValueId>)>, JavaLoweringError> {
        let target = match left.kind() {
            "identifier" => {
                if let Some((value, flow)) = self.lexical_reference_binding(left) {
                    Some((CompoundAssignmentTarget::Binding { value, flow }, None))
                } else if let Some((member, _)) = self.static_field_locator(left) {
                    let location = self.session.add_memory_location(
                        builder,
                        point,
                        MemoryLocationKind::Static { member },
                    )?;
                    Some((
                        CompoundAssignmentTarget::Memory {
                            location,
                            kind: MemoryAccessKind::Static,
                        },
                        None,
                    ))
                } else if let Some((location, carrier)) =
                    self.implicit_instance_field_storage(builder, left, point)?
                {
                    Some((
                        CompoundAssignmentTarget::Memory {
                            location,
                            kind: MemoryAccessKind::Field,
                        },
                        Some(carrier),
                    ))
                } else {
                    None
                }
            }
            "field_access" if !self.field_access_is_type_qualifier(left) => {
                let object = required_field(left, "object")?;
                let base = self.expression_value(builder, object, expression_value_kind(object))?;
                let (location, kind) = self.field_memory_location(builder, point, left, base)?;
                Some((CompoundAssignmentTarget::Memory { location, kind }, None))
            }
            "array_access" => {
                let array = required_field(left, "array")?;
                let base = self.expression_value(builder, array, expression_value_kind(array))?;
                let index = self.index_value(builder, required_field(left, "index")?)?;
                let location = self.session.add_memory_location(builder, point, MemoryLocationKind::Index {
                    base, index: Some(index), constant_index: None,
                    identity: brokk_bifrost_analysis::analyzer::semantic::IndexedLocationIdentity::Element,
                })?;
                Some((
                    CompoundAssignmentTarget::Memory {
                        location,
                        kind: MemoryAccessKind::Index,
                    },
                    None,
                ))
            }
            _ => None,
        };
        if target.is_none() {
            self.add_gap(
                builder,
                point,
                SemanticGapSubject::Point,
                SemanticCapability::Assignments,
                SemanticGapKind::Unknown,
                "assignment target has no resolved lexical or field binding",
            )?;
        }
        Ok(target)
    }

    fn compound_assignment_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), JavaLoweringError> {
        let left = brokk_bifrost_core::analyzer::tree_walk::unwrap_parenthesized_expression(
            required_field(node, "left")?,
        );
        let right = required_field(node, "right")?;
        let operator = required_field(node, "operator")?.kind();
        let operation = self.point(builder, node, Vec::new())?;
        let write = self.point(builder, node, Vec::new())?;
        let old = self.expression_value(builder, left, expression_value_kind(left))?;
        let operand = self.expression_value(builder, right, expression_value_kind(right))?;
        let computed = self.value(builder, operation, SemanticValueKind::Temporary)?;
        let result = self.expression_value(builder, node, expression_value_kind(node))?;
        let left_type = self.compound_value_type(left);
        let concatenation_call_free = self.string_compound_assignment_is_call_free(left, right);
        if operator == "+="
            && matches!(
                left_type,
                JavaCompoundType::String | JavaCompoundType::Unknown
            )
            && !concatenation_call_free
        {
            self.session.add_gap_with_impacts(
                builder,
                operation,
                SemanticGapSubject::Point,
                SemanticCapability::Calls,
                SemanticGapImpacts::CALL_EVALUATION,
                SemanticGapKind::Unknown,
                "string compound assignment can invoke user-defined toString during conversion",
            )?;
        }
        if let Some((target, carrier)) = self.assignment_target(builder, write, left)? {
            let offset = self.compound_integer_offset(node, left, right);
            let can_throw = self.session.append_compound_assignment(
                builder,
                JAVA_COMPOUND_OPERATORS,
                operator,
                JavaCompoundContext {
                    left: left_type,
                    right: self.compound_value_type(right),
                    divisor_nonzero: java_numeric_literal(self.prepared.source(), right)
                        .and_then(JavaNumericLiteral::integer)
                        .is_some_and(|value| value != 0),
                    concatenation_call_free,
                },
                CompoundAssignment {
                    operation,
                    write,
                    old,
                    right: operand,
                    result: computed,
                    target,
                },
                |session, builder, point, old, right, result| {
                    if let Some(offset) = offset {
                        session.append_effect(
                            builder,
                            point,
                            SemanticEffect::ValueFlow {
                                kind: ValueFlowKind::IntegerOffset { offset },
                                source: old,
                                target: result,
                            },
                        )
                    } else {
                        compute_language_defined_compound_assignment(
                            session, builder, point, old, right, result,
                        )
                    }
                },
            )?;
            if let Some(carrier) = carrier {
                self.assign_implicit_field_carrier(builder, write, carrier, computed)?;
            }
            if can_throw {
                self.implicit_abort_edge(builder, node, operation, scope, None, stack)?;
            }
        } else {
            compute_language_defined_compound_assignment(
                &self.session,
                builder,
                operation,
                old,
                operand,
                computed,
            )?;
            self.edge(builder, operation, EdgeTarget::normal(write))?;
        }
        self.append_effect(
            builder,
            write,
            SemanticEffect::Assignment {
                target: result,
                value: computed,
            },
        )?;
        self.edge(builder, write, next)?;
        // The old value (including numeric unboxing) is saved before the RHS.
        // Reuse its receiver/index values for the write even if the RHS mutates
        // a binding used by that address.
        let right_entry = self.point(builder, right, Vec::new())?;
        let after_left = if left_type.may_unbox() && !matches!(left_type, JavaCompoundType::String)
        {
            let unbox = self.point(builder, left, Vec::new())?;
            self.edge(builder, unbox, EdgeTarget::normal(right_entry))?;
            self.implicit_abort_edge(builder, left, unbox, scope, None, stack)?;
            unbox
        } else {
            right_entry
        };
        self.schedule_expressions(
            builder,
            right_entry,
            &[right],
            EdgeTarget::normal(operation),
            scope,
            stack,
        )?;
        self.schedule_expressions(
            builder,
            entry,
            &[left],
            EdgeTarget::normal(after_left),
            scope,
            stack,
        )
    }

    fn compound_declared_type(&self, mut node: Node<'tree>) -> Option<Node<'tree>> {
        let mut indexes = 0;
        while node.kind() == "array_access" {
            indexes += 1;
            node = node.child_by_field_name("array")?;
        }
        let (ty, array) = if let Some((value, _)) = self.lexical_reference_binding(node) {
            (
                *self.local_type_nodes.get(&value)?,
                self.array_values.contains(&value),
            )
        } else {
            let (_, field) = self.source_field_declaration(node)?;
            (java_binding_type(field.declaration)?, field.is_array)
        };
        if indexes == 0 && array {
            return None;
        }
        if indexes == 0 {
            return Some(ty);
        }
        let dimensions = ty.child_by_field_name("dimensions")?;
        let rank = (0..dimensions.child_count())
            .filter(|index| {
                dimensions
                    .child(*index)
                    .is_some_and(|node| node.kind() == "[")
            })
            .count();
        (rank == indexes)
            .then(|| ty.child_by_field_name("element"))
            .flatten()
    }

    fn compound_value_type(&self, mut node: Node<'tree>) -> JavaCompoundType {
        loop {
            match node.kind() {
                "parenthesized_expression" => {
                    node = first_named_child(node).expect("parenthesized value");
                }
                "assignment_expression" => {
                    node = node.child_by_field_name("left").expect("assignment left");
                }
                "update_expression" => {
                    node = first_runtime_named_child(node).expect("update operand");
                }
                _ => break,
            }
        }
        if let Some(literal) = java_numeric_literal(self.prepared.source(), node) {
            return JavaCompoundType::Primitive(match literal {
                JavaNumericLiteral::Int(_) => {
                    JavaScalarType::Integral(JavaIntegralDomain::Signed(32))
                }
                JavaNumericLiteral::Long(_) => {
                    JavaScalarType::Integral(JavaIntegralDomain::Signed(64))
                }
                JavaNumericLiteral::Float(_) => JavaScalarType::Float,
                JavaNumericLiteral::Double(_) => JavaScalarType::Double,
            });
        }
        match node.kind() {
            "string_literal" => return JavaCompoundType::String,
            "null_literal" => return JavaCompoundType::Null,
            "true" | "false" => return JavaCompoundType::Primitive(JavaScalarType::Boolean),
            "character_literal" => {
                return JavaCompoundType::Primitive(JavaScalarType::Integral(
                    JavaIntegralDomain::Unsigned(16),
                ));
            }
            _ => {}
        }
        let ty = if node.kind() == "cast_expression" {
            node.child_by_field_name("type")
        } else {
            self.compound_declared_type(node)
        };
        let Some(ty) = ty else {
            return JavaCompoundType::Unknown;
        };
        if let Some(scalar) = JavaScalarType::from_type(ty) {
            return JavaCompoundType::Primitive(scalar);
        }
        if matches!(ty.kind(), "type_identifier" | "scoped_type_identifier")
            && matches!(
                node_text(self.prepared.source(), ty),
                Some("String" | "java.lang.String")
            )
        {
            return JavaCompoundType::String;
        }
        JavaScalarType::from_wrapper_type(ty, self.prepared.source())
            .map(JavaCompoundType::Boxed)
            .unwrap_or(JavaCompoundType::Unknown)
    }

    fn string_compound_assignment_is_call_free(
        &self,
        left: Node<'tree>,
        right: Node<'tree>,
    ) -> bool {
        let is_string = |node| matches!(self.compound_value_type(node), JavaCompoundType::String);
        if !is_string(left) {
            return false;
        }
        let mut pending = vec![right];
        while let Some(node) = pending.pop() {
            match node.kind() {
                _ if matches!(
                    self.compound_value_type(node),
                    JavaCompoundType::Primitive(_) | JavaCompoundType::Null
                ) => {}
                _ if is_string(node) => {}
                "binary_expression"
                    if node
                        .child_by_field_name("operator")
                        .is_some_and(|operator| operator.kind() == "+") =>
                {
                    let (Some(left), Some(right)) = (
                        node.child_by_field_name("left"),
                        node.child_by_field_name("right"),
                    ) else {
                        return false;
                    };
                    pending.extend([left, right]);
                }
                _ => return false,
            }
        }
        true
    }

    fn update_expression(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), JavaLoweringError> {
        let operand = first_runtime_named_child(node)
            .ok_or_else(|| JavaLoweringError::Invalid("update expression has no operand".into()))?;
        let operation = self.point(builder, node, Vec::new())?;
        let terminal = self.point(builder, node, Vec::new())?;
        let old = self.expression_value(builder, operand, expression_value_kind(operand))?;
        let computed = self.value(builder, terminal, SemanticValueKind::Temporary)?;
        // `x++` on a primitive integral binding adds exactly one. The
        // consumer applies it in the binding's domain, where overflow wraps
        // and becomes unknown; any other operand stays language-defined.
        let step = self
            .lexical_reference_binding(operand)
            .filter(|(binding, _)| self.is_primitive_integral_binding(*binding))
            .map(|_| SignedIntegerMagnitude::new(has_child_kind(node, "--"), 1));
        match step {
            Some(offset) => self.append_effect(
                builder,
                terminal,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::IntegerOffset { offset },
                    source: old,
                    target: computed,
                },
            )?,
            None => self.session.append_language_defined_value_flows(
                builder,
                terminal,
                [old],
                computed,
            )?,
        }

        let result = self.expression_value(builder, node, expression_value_kind(node))?;
        let is_prefix = node
            .child(0)
            .is_some_and(|first| matches!(first.kind(), "++" | "--"));
        self.append_effect(
            builder,
            terminal,
            SemanticEffect::Assignment {
                target: result,
                value: if is_prefix { computed } else { old },
            },
        )?;

        if operand.kind() == "identifier" {
            if let Some((target, kind)) = self.lexical_reference_binding(operand) {
                self.append_effect(
                    builder,
                    terminal,
                    SemanticEffect::Assignment {
                        target,
                        value: computed,
                    },
                )?;
                self.append_effect(
                    builder,
                    terminal,
                    SemanticEffect::ValueFlow {
                        kind,
                        source: computed,
                        target,
                    },
                )?;
            } else if !self.emit_implicit_field_store(builder, operand, terminal, computed)? {
                self.add_gap(
                    builder,
                    terminal,
                    SemanticGapSubject::Point,
                    SemanticCapability::Assignments,
                    SemanticGapKind::Unknown,
                    "update target has no resolved lexical or field binding",
                )?;
            }
        } else if operand.kind() == "field_access" && !self.field_access_is_type_qualifier(operand)
        {
            let object = required_field(operand, "object")?;
            let base = self.expression_value(builder, object, expression_value_kind(object))?;
            let (location, kind) = self.field_memory_location(builder, terminal, operand, base)?;
            self.append_effect(
                builder,
                terminal,
                SemanticEffect::MemoryStore {
                    kind,
                    location,
                    value: computed,
                },
            )?;
        } else if operand.kind() == "array_access" {
            let array = required_field(operand, "array")?;
            let index = required_field(operand, "index")?;
            let base = self.expression_value(builder, array, expression_value_kind(array))?;
            let index_value = self.index_value(builder, index)?;
            let location = self.session.add_memory_location(
                builder,
                terminal,
                MemoryLocationKind::Index {
                    base,
                    index: Some(index_value),
                    constant_index: None,
                    identity: brokk_bifrost_analysis::analyzer::semantic::IndexedLocationIdentity::Element,
                },
            )?;
            self.append_effect(
                builder,
                terminal,
                SemanticEffect::MemoryStore {
                    kind: MemoryAccessKind::Index,
                    location,
                    value: computed,
                },
            )?;
        } else {
            self.add_gap(
                builder,
                terminal,
                SemanticGapSubject::Point,
                SemanticCapability::Assignments,
                SemanticGapKind::Unknown,
                "update target has unsupported storage form",
            )?;
        }

        self.edge(builder, operation, EdgeTarget::normal(terminal))?;
        if !self
            .static_field_locator(operand)
            .is_some_and(|(_, primitive)| primitive.is_some())
        {
            self.implicit_abort_edge(builder, node, operation, scope, None, stack)?;
        }
        self.edge(builder, terminal, next)?;
        self.schedule_expressions(
            builder,
            entry,
            &[operand],
            EdgeTarget::normal(operation),
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
            } => {
                self.session.record_statement_entry(builder, node, entry)?;
                self.statement(builder, node, entry, next, scope, None, stack)
            }
            Work::LabeledStatement {
                node,
                label,
                entry,
                next,
                scope,
            } => {
                self.session.record_statement_entry(builder, node, entry)?;
                self.statement(builder, node, entry, next, scope, Some(label), stack)
            }
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
            ("binary_expression", Some(operator @ ("&&" | "||"))) => {
                let left = required_field(node, "left")?;
                let right = required_field(node, "right")?;
                let right_entry = self.point(builder, right, Vec::new())?;
                let kind = match operator {
                    "&&" => ShortCircuitKind::And,
                    "||" => ShortCircuitKind::Or,
                    _ => unreachable!("the match arm selects Java boolean operators"),
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
            ("unary_expression", _)
                if node
                    .child_by_field_name("operator")
                    .is_some_and(|operator| operator.kind() == "!")
                    && condition_requires_branch_lowering(node) =>
            {
                let operand = required_field(node, "operand")?;
                stack.push(Work::Condition {
                    node: operand,
                    entry,
                    when_true: when_false,
                    when_false: when_true,
                    scope,
                });
                Ok(())
            }
            ("instanceof_expression", _) if java_pattern_has_value(node) => {
                let operand = required_field(node, "left")?;
                let value =
                    self.expression_value(builder, operand, expression_value_kind(operand))?;
                let bound = self.establish_pattern_binding(builder, node, value, when_true)?;
                let matched = EdgeTarget {
                    point: bound,
                    kind: when_true.kind,
                };
                let decision = self.point(builder, node, Vec::new())?;
                self.edge(builder, decision, matched)?;
                self.edge(builder, decision, when_false)?;
                self.record_guard(builder, decision, node, Some(matched), Some(when_false))?;
                stack.push(Work::Expression {
                    node,
                    entry,
                    next: EdgeTarget::normal(decision),
                    scope,
                });
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
                if !self.is_primitive_boolean_expression(node) {
                    // Boolean conversion happens after expression side effects,
                    // including inside a short-circuit operand.
                    self.implicit_abort_edge(builder, node, decision, scope, None, stack)?;
                }
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

    /// Pattern bindings receive the saved tested value only on the selected
    /// successful edge. The non-null fact belongs to that establishment, not
    /// to a procedure-global assumption that could outlive reassignment.
    fn establish_pattern_binding(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        pattern: Node<'tree>,
        value: ValueId,
        next: EdgeTarget,
    ) -> Result<ProgramPointId, JavaLoweringError> {
        let name = brokk_bifrost_jvm::java::structural::java_pattern_binding_name(pattern)
            .expect("simple pattern binder");
        let text = node_text(self.prepared.source(), name).expect("source-backed pattern name");
        let target = self
            .local_declaration_value(text, name.start_byte())
            .expect("pattern local was inventoried");
        let point = self.point(builder, pattern, Vec::new())?;
        self.append_effect(builder, point, SemanticEffect::Assignment { target, value })?;
        self.append_effect(
            builder,
            point,
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Local,
                source: value,
                target,
            },
        )?;
        self.edge(builder, point, next)?;
        self.session.add_guard_fact(
            builder,
            point,
            GuardPredicate::NullComparison {
                null_on_true: false,
            },
            Some(target),
            Some(GuardArm {
                target_point: next.point,
                kind: next.kind,
            }),
            None,
        )?;
        Ok(point)
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
        let guard = match self.normalize_condition(builder, condition)? {
            Some(normalized) => normalized,
            None => NormalizedConditionGuard::folded(
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
        // A guard's true arm is the edge taken when its predicate holds.
        let (holds, fails) = guard.arms(when_true, when_false);
        self.session.add_guard_fact(
            builder,
            point,
            guard.predicate,
            guard.subject,
            arm(holds),
            arm(fails),
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
    /// decision of its own. A predicate folds the negation into its own
    /// polarity when it has one; otherwise the guard keeps the un-negated
    /// predicate and swaps its arms.
    fn normalize_condition(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        condition: Node<'tree>,
    ) -> Result<Option<NormalizedConditionGuard>, JavaLoweringError> {
        use brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge;
        let syntax = brokk_bifrost_jvm::JavaKnowledge
            .guard_condition_syntax()
            .expect("Java supplies guard grammar shapes");
        let Ok((cursor, negated)) = peel_guard_condition(condition, syntax) else {
            return Ok(None);
        };
        // This rule is disjoint from local, literal and comparison rules by
        // the peeled terminal's node kind. A null boxed Boolean exits through
        // the existing exceptional path before either decision arm is taken.
        if let Some(guard) = normalize_direct_call_guard(condition, syntax, |call| {
            self.expression_value(builder, call, expression_value_kind(call))
        })? {
            return Ok(Some(guard));
        }

        match cursor.kind() {
            "true" => {
                return Ok(Some(NormalizedConditionGuard::folded(
                    GuardPredicate::ConstantBoolean { value: !negated },
                    None,
                )));
            }
            "false" => {
                return Ok(Some(NormalizedConditionGuard::folded(
                    GuardPredicate::ConstantBoolean { value: negated },
                    None,
                )));
            }
            // A primitive or boxed Boolean local is tested for its own value;
            // a null boxed one throws before the guard decides.
            "identifier" => {
                let Some((binding, _)) = self.lexical_reference_binding(cursor) else {
                    return Ok(None);
                };
                if self.unboxed_scalar_type(binding) != Some(JavaScalarType::Boolean) {
                    return Ok(None);
                }
                let subject =
                    self.expression_value(builder, cursor, expression_value_kind(cursor))?;
                return Ok(Some(NormalizedConditionGuard {
                    predicate: GuardPredicate::Truthy { value: subject },
                    subject: Some(subject),
                    holds_on_false_arm: negated,
                }));
            }
            "binary_expression" => {}
            _ => return Ok(None),
        }

        let Some(operator) = cursor.child_by_field_name("operator") else {
            return Ok(None);
        };
        let (Some(left), Some(right)) = (
            cursor.child_by_field_name("left"),
            cursor.child_by_field_name("right"),
        ) else {
            return Ok(None);
        };
        let same_binding = self.same_lexical_binding(left, right);
        if let Some(binding) = same_binding {
            // Ordering unboxes a boxed operand, so it compares numbers either
            // way. `==` and `!=` on a boxed operand compare references and
            // are left to the identity rule below.
            let integral = self.unboxed_integral_domain(binding).is_some();
            let floating = self.unboxed_floating_type(binding).is_some();
            let primitive_floating = self.primitive_floating_type(binding).is_some();
            // NaN is unordered and unequal to itself, so strict self-ordering
            // is false for every number, while self-equality and non-strict
            // self-ordering are true for every integral value and for every
            // floating value except NaN. `!=` alone accepts NaN.
            let value = match operator.kind() {
                "<" | ">" if integral || floating => Some(false),
                "<=" | ">=" if integral => Some(true),
                _ => None,
            };
            if let Some(value) = value {
                return Ok(Some(NormalizedConditionGuard::folded(
                    GuardPredicate::ConstantBoolean {
                        value: value != negated,
                    },
                    None,
                )));
            }
            let nan_on_true = match operator.kind() {
                "<=" | ">=" if floating => Some(false),
                "==" if primitive_floating => Some(false),
                "!=" if primitive_floating => Some(true),
                _ => None,
            };
            if let Some(nan_on_true) = nan_on_true {
                let subject = self.expression_value(builder, left, expression_value_kind(left))?;
                return Ok(Some(NormalizedConditionGuard::folded(
                    GuardPredicate::NanComparison {
                        nan_on_true: nan_on_true != negated,
                    },
                    Some(subject),
                )));
            }
        }
        let source = self.prepared.source();
        let left_literal = java_numeric_literal(source, left);
        let right_literal = java_numeric_literal(source, right);
        let ordered_relation = match operator.kind() {
            "<" => Some(IntegerComparison::LessThan),
            "<=" => Some(IntegerComparison::LessThanOrEqual),
            ">" => Some(IntegerComparison::GreaterThan),
            ">=" => Some(IntegerComparison::GreaterThanOrEqual),
            _ => None,
        };
        if let Some(relation) = ordered_relation {
            let (subject, constant, literal, relation) = match (left_literal, right_literal) {
                (Some(literal), None) => (right, left, literal, relation.reverse()),
                (None, Some(literal)) => (left, right, literal, relation),
                _ => return Ok(None),
            };
            // A Java `<` expression can compare values of any numeric type,
            // and a boxed operand unboxes first; a `null` one throws before
            // the guard decides. Require the exact lexical binding's declared
            // primitive or wrapper type before publishing a guard.
            let Some((binding, _)) = self.lexical_reference_binding(subject) else {
                return Ok(None);
            };
            let (constant_kind, floating) = if self.unboxed_integral_domain(binding).is_some() {
                (literal.integer_kind(), false)
            } else if let Some(subject_type) = self.unboxed_floating_type(binding) {
                (literal.floating_kind(subject_type), true)
            } else {
                (None, false)
            };
            let Some(constant_kind) = constant_kind else {
                return Ok(None);
            };
            let constant = self.expression_value(builder, constant, constant_kind)?;
            let subject =
                self.expression_value(builder, subject, expression_value_kind(subject))?;
            if floating {
                // A NaN subject fails both `x < c` and the negated relation
                // `x >= c`, so `!(x < c)` keeps `x < c` on swapped arms.
                return Ok(Some(NormalizedConditionGuard {
                    predicate: GuardPredicate::OrderedFloatComparison { relation, constant },
                    subject: Some(subject),
                    holds_on_false_arm: negated,
                }));
            }
            return Ok(Some(NormalizedConditionGuard::folded(
                GuardPredicate::OrderedIntegerComparison {
                    relation: if negated { relation.negate() } else { relation },
                    constant,
                },
                Some(subject),
            )));
        }
        let equal_on_true = match operator.kind() {
            "==" => !negated,
            "!=" => negated,
            _ => return Ok(None),
        };
        // Reading one local twice performs no intervening operation. Primitive
        // floating values are excluded because NaN is not equal to itself.
        // Two reads of the same reference, including a boxed value, compare
        // by identity without unboxing.
        if same_binding.is_some_and(|binding| self.has_reflexive_equality_binding(binding)) {
            return Ok(Some(NormalizedConditionGuard::folded(
                GuardPredicate::ConstantBoolean {
                    value: equal_on_true,
                },
                None,
            )));
        }
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
            return Ok(Some(NormalizedConditionGuard::folded(
                GuardPredicate::NullComparison {
                    null_on_true: equal_on_true,
                },
                Some(subject),
            )));
        }

        let left_constant = left_literal.is_some()
            || matches!(expression_value_kind(left), SemanticValueKind::Constant);
        let right_constant = right_literal.is_some()
            || matches!(expression_value_kind(right), SemanticValueKind::Constant);
        // Two constants compared with each other name no subject, so the
        // comparison is not a guard over anything and stays opaque.
        let (subject, constant, literal) = match (left_constant, right_constant) {
            (true, false) => (right, left, left_literal),
            (false, true) => (left, right, right_literal),
            (true, true) | (false, false) => return Ok(None),
        };
        // A numeric constant is typed only for a primitive or boxed numeric
        // subject: against a numeric literal a boxed subject unboxes, so the
        // comparison is numeric after promotion. Anything else stays an
        // unrepresented constant.
        let constant_kind = literal
            .zip(self.lexical_reference_binding(subject))
            .and_then(|(literal, (binding, _))| {
                if self.unboxed_integral_domain(binding).is_some() {
                    literal.integer_kind()
                } else {
                    self.unboxed_floating_type(binding)
                        .and_then(|subject_type| literal.floating_kind(subject_type))
                }
            })
            .unwrap_or(SemanticValueKind::Constant);
        let constant = self.expression_value(builder, constant, constant_kind)?;
        let subject = self.expression_value(builder, subject, expression_value_kind(subject))?;
        Ok(Some(NormalizedConditionGuard::folded(
            GuardPredicate::ConstantEquality {
                negated: !equal_on_true,
                constant,
            },
            Some(subject),
        )))
    }

    fn is_primitive_integral_binding(&self, binding: ValueId) -> bool {
        self.primitive_integral_domain(binding).is_some()
    }

    fn same_lexical_binding(&self, left: Node<'tree>, right: Node<'tree>) -> Option<ValueId> {
        if left.kind() != "identifier" || right.kind() != "identifier" {
            return None;
        }
        let (binding, _) = self.lexical_reference_binding(left)?;
        self.lexical_reference_binding(right)
            .filter(|(other, _)| *other == binding)
            .map(|_| binding)
    }

    fn has_reflexive_equality_binding(&self, binding: ValueId) -> bool {
        let Some(ty) = self.local_type_nodes.get(&binding).copied() else {
            return false;
        };
        if ty.has_error() {
            return false;
        }
        if self.array_values.contains(&binding) {
            return true;
        }
        self.is_primitive_integral_binding(binding)
            || matches!(
                ty.kind(),
                "boolean_type" | "generic_type" | "scoped_type_identifier"
            )
            || (ty.kind() == "type_identifier"
                && node_text(self.prepared.source(), ty) != Some("var"))
    }

    fn primitive_integral_domain(&self, binding: ValueId) -> Option<JavaIntegralDomain> {
        (!self.array_values.contains(&binding))
            .then(|| self.local_type_nodes.get(&binding).copied())
            .flatten()
            .and_then(JavaIntegralDomain::from_type)
    }

    fn primitive_floating_type(&self, binding: ValueId) -> Option<JavaFloatingType> {
        (!self.array_values.contains(&binding))
            .then(|| self.local_type_nodes.get(&binding).copied())
            .flatten()
            .and_then(JavaFloatingType::from_type)
    }

    /// The primitive numeric type a comparison or a store reads `binding`
    /// as: its declared primitive type, or the type its numeric wrapper type
    /// unboxes to. See [`JavaScalarType::from_wrapper_type`] for why a
    /// wrapper name suffices where the value is unboxed.
    fn unboxed_scalar_type(&self, binding: ValueId) -> Option<JavaScalarType> {
        let type_node = (!self.array_values.contains(&binding))
            .then(|| self.local_type_nodes.get(&binding).copied())
            .flatten()?;
        JavaScalarType::from_type(type_node)
            .or_else(|| JavaScalarType::from_wrapper_type(type_node, self.prepared.source()))
    }

    fn unboxed_integral_domain(&self, binding: ValueId) -> Option<JavaIntegralDomain> {
        match self.unboxed_scalar_type(binding)? {
            JavaScalarType::Integral(domain) => Some(domain),
            JavaScalarType::Float | JavaScalarType::Double | JavaScalarType::Boolean => None,
        }
    }

    fn unboxed_floating_type(&self, binding: ValueId) -> Option<JavaFloatingType> {
        match self.unboxed_scalar_type(binding)? {
            JavaScalarType::Float => Some(JavaFloatingType::Float),
            JavaScalarType::Double => Some(JavaFloatingType::Double),
            JavaScalarType::Integral(_) | JavaScalarType::Boolean => None,
        }
    }

    /// The value kind for `expression` stored into the lexical binding
    /// `target`. A numeric literal the assignment converts without changing
    /// its value (JLS 5.2) publishes its typed constant: an integer literal
    /// keeps its integer value even for a floating target, whose conversion
    /// the scalar solver applies from the target's declared type.
    fn assignment_literal_kind(
        &self,
        target: ValueId,
        expression: Node<'tree>,
    ) -> SemanticValueKind {
        if matches!(expression.kind(), "true" | "false")
            && self.unboxed_scalar_type(target) == Some(JavaScalarType::Boolean)
        {
            return SemanticValueKind::Boolean(expression.kind() == "true");
        }
        let typed = java_numeric_literal(self.prepared.source(), expression).and_then(|literal| {
            if let Some(domain) = self.unboxed_integral_domain(target) {
                literal
                    .assignable_to_integral(domain)
                    .then(|| literal.integer_kind())
                    .flatten()
            } else {
                let target_type = self.unboxed_floating_type(target)?;
                match literal {
                    JavaNumericLiteral::Int(_) | JavaNumericLiteral::Long(_) => {
                        literal.integer_kind()
                    }
                    JavaNumericLiteral::Float(_) => literal.floating_kind(target_type),
                    JavaNumericLiteral::Double(_) => (target_type == JavaFloatingType::Double)
                        .then(|| literal.floating_kind(target_type))
                        .flatten(),
                }
            }
        });
        typed.unwrap_or_else(|| expression_value_kind(expression))
    }

    /// The operand and exact offset of `x + c`, `c + x` or `x - c`, where `x`
    /// is a lexical reference to a primitive integral binding and `c` is an
    /// integer literal. Binary numeric promotion can widen the computation
    /// beyond `x`'s type; a consumer that applies the offset in `x`'s domain
    /// and treats overflow as unknown stays sound.
    fn integer_offset_operand(
        &self,
        node: Node<'tree>,
    ) -> Option<(Node<'tree>, SignedIntegerMagnitude)> {
        if node.kind() != "binary_expression" {
            return None;
        }
        let subtract = match node.child_by_field_name("operator")?.kind() {
            "+" => false,
            "-" => true,
            _ => return None,
        };
        let left = node.child_by_field_name("left")?;
        let right = node.child_by_field_name("right")?;
        let source = self.prepared.source();
        let integer = |operand| java_numeric_literal(source, operand)?.integer();
        let (operand, constant) = match (integer(left), integer(right)) {
            (None, Some(constant)) => (left, constant),
            (Some(constant), None) if !subtract => (right, constant),
            _ => return None,
        };
        let (binding, _) = self.lexical_reference_binding(operand)?;
        self.primitive_integral_domain(binding)?;
        Some((operand, literal_offset(constant, subtract)))
    }

    /// The exact offset of `x += c` or `x -= c`, where `x` is a lexical
    /// reference to a primitive integral binding and `c` is an integer
    /// literal. The implicit narrowing back to `x`'s type only matters on
    /// overflow, which a consumer applying the offset in `x`'s domain treats
    /// as unknown.
    fn compound_integer_offset(
        &self,
        node: Node<'tree>,
        left: Node<'tree>,
        right: Node<'tree>,
    ) -> Option<SignedIntegerMagnitude> {
        let subtract = match node.child_by_field_name("operator")?.kind() {
            "+=" => false,
            "-=" => true,
            _ => return None,
        };
        if left.kind() != "identifier" {
            return None;
        }
        let (binding, _) = self.lexical_reference_binding(left)?;
        self.primitive_integral_domain(binding)?;
        let constant = java_numeric_literal(self.prepared.source(), right)?.integer()?;
        Some(literal_offset(constant, subtract))
    }

    /// The operand of a cast that converts a lexical reference to a primitive
    /// binding by identity or widening without changing its value: a wider
    /// or equal integral type (`char` only to `char`, `int` or `long`), or
    /// `float` to `double`.
    fn value_preserving_cast_operand(&self, node: Node<'tree>) -> Option<Node<'tree>> {
        let target = node.child_by_field_name("type")?;
        let operand = node.child_by_field_name("value")?;
        let (binding, _) = self.lexical_reference_binding(operand)?;
        let preserves = if let Some(target) = JavaIntegralDomain::from_type(target) {
            self.primitive_integral_domain(binding)
                .is_some_and(|source| integral_domain_contains(target, source))
        } else if let Some(target) = JavaFloatingType::from_type(target) {
            self.primitive_floating_type(binding).is_some_and(|source| {
                source == JavaFloatingType::Float || target == JavaFloatingType::Double
            })
        } else {
            false
        };
        preserves.then_some(operand)
    }

    /// Publish the transfer of an expression that hands its operand on
    /// unchanged: the result is the operand's own value, so the flow is a
    /// local copy and the assignment is the identity transfer used by
    /// local-copy proofs.
    fn emit_identity_flow(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        source: ValueId,
        target: ValueId,
    ) -> Result<(), JavaLoweringError> {
        self.append_effect(
            builder,
            point,
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Local,
                source,
                target,
            },
        )?;
        self.append_effect(
            builder,
            point,
            SemanticEffect::Assignment {
                target,
                value: source,
            },
        )
    }

    /// Lower an expression whose result is computed from its operands: each
    /// operand is evaluated in order, then the result takes a language-defined
    /// flow from every one of them. The flows sit on the returned terminal
    /// point, so a caller attaches whatever else the evaluation does, such as
    /// an abort edge or a gap, to that same point.
    #[allow(clippy::too_many_arguments)]
    fn derive_result_from_operands(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        operands: &[Node<'tree>],
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<ProgramPointId, JavaLoweringError> {
        let result = self.expression_value(builder, node, expression_value_kind(node))?;
        let terminal = self.point(builder, node, Vec::new())?;
        let sources = operands
            .iter()
            .map(|operand| {
                self.expression_value(builder, *operand, expression_value_kind(*operand))
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.session
            .append_language_defined_value_flows(builder, terminal, sources, result)?;
        self.edge(builder, terminal, next)?;
        self.schedule_expressions(
            builder,
            entry,
            operands,
            EdgeTarget::normal(terminal),
            scope,
            stack,
        )?;
        Ok(terminal)
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
                    | "switch_statement"
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
                // The operand is the value of the switch expression the yield
                // completes (JLS 14.21). Java evaluates it before any `finally`
                // on the way out runs, so the flow sits ahead of the route.
                if let Some(route) = builder
                    .resolve_completion(scope, &CompletionRequest::new(CompletionKind::Yield, None))
                    && let Some(result) = self
                        .yield_results
                        .get(&route.destination().target())
                        .copied()
                {
                    let operand = self.expression_value(
                        builder,
                        value_node,
                        expression_value_kind(value_node),
                    )?;
                    self.append_effect(
                        builder,
                        terminal,
                        SemanticEffect::ValueFlow {
                            kind: ValueFlowKind::Local,
                            source: operand,
                            target: result,
                        },
                    )?;
                }
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
                self.session
                    .record_loop_site(builder, node, entry, body_entry)?;
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
                // A do body starts every iteration, so it is its own header.
                self.session.record_loop_site(builder, node, entry, entry)?;
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
            "switch_statement" | "switch_expression" => self.switch(
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
                // The label and its statement have distinct source identities.
                // In particular, a labeled loop must retain its own header span.
                let body_entry = self.point(builder, body, Vec::new())?;
                self.edge(builder, entry, EdgeTarget::normal(body_entry))?;
                stack.push(Work::LabeledStatement {
                    node: body,
                    label,
                    entry: body_entry,
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
                self.assertion_statement(builder, node, entry, next, scope, stack)
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

    fn is_primitive_boolean_expression(&self, node: Node<'tree>) -> bool {
        match node.kind() {
            "true" | "false" | "instanceof_expression" => true,
            "binary_expression" => matches!(
                binary_operator(node),
                Some("&&" | "||" | "==" | "!=" | "<" | "<=" | ">" | ">=" | "&" | "|" | "^")
            ),
            "unary_expression" => node
                .child_by_field_name("operator")
                .is_some_and(|operator| operator.kind() == "!"),
            "identifier" => self
                .lexical_reference_binding(node)
                .and_then(|(binding, _)| self.local_type_nodes.get(&binding))
                .is_some_and(|ty| ty.kind() == "boolean_type"),
            _ => false,
        }
    }

    fn assertion_statement(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), JavaLoweringError> {
        let operands = named_children(node);
        let (condition, detail) = match operands.as_slice() {
            [condition] => (*condition, None),
            [condition, detail] => (*condition, Some(*detail)),
            _ => return self.unhandled_control_syntax(builder, node, entry),
        };
        // Keep a caller-supplied loop-back continuation on its own edge.
        let continuation = self.point(builder, node, Vec::new())?;
        self.edge(builder, continuation, next)?;
        let enabled = self.point(builder, condition, Vec::new())?;
        let failure = self.point(builder, node, Vec::new())?;
        let throwing = self.point(builder, node, Vec::new())?;
        let enabled_arm = EdgeTarget {
            point: enabled,
            kind: ControlEdgeKind::ConditionalTrue,
        };
        let disabled_arm = EdgeTarget {
            point: continuation,
            kind: ControlEdgeKind::ConditionalFalse,
        };
        self.edge(builder, entry, enabled_arm)?;
        self.edge(builder, entry, disabled_arm)?;
        // Assertion enablement belongs to the analyzed class/host. Retaining
        // both paths also covers execution during class initialization.
        self.session.add_guard_fact(
            builder,
            entry,
            GuardPredicate::Opaque {
                digest: GuardConditionDigest::from_syntax_kind(node.kind()),
            },
            None,
            Some(GuardArm {
                target_point: enabled,
                kind: enabled_arm.kind,
            }),
            Some(GuardArm {
                target_point: continuation,
                kind: disabled_arm.kind,
            }),
        )?;
        let success_arm = EdgeTarget {
            point: continuation,
            kind: ControlEdgeKind::ConditionalTrue,
        };
        let failure_arm = EdgeTarget {
            point: failure,
            kind: ControlEdgeKind::ConditionalFalse,
        };
        stack.push(Work::Condition {
            node: condition,
            entry: enabled,
            when_true: success_arm,
            when_false: failure_arm,
            scope,
        });
        let thrown = self.value(builder, throwing, SemanticValueKind::Exception)?;
        if let Some(detail) = detail {
            let detail_value =
                self.expression_value(builder, detail, expression_value_kind(detail))?;
            self.append_effect(
                builder,
                throwing,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Local,
                    source: detail_value,
                    target: thrown,
                },
            )?;
            stack.push(Work::Expression {
                node: detail,
                entry: failure,
                next: EdgeTarget::normal(throwing),
                scope,
            });
        } else {
            self.edge(builder, failure, EdgeTarget::normal(throwing))?;
        }
        // Construction can throw as well; either outcome is abrupt here.
        // Its implicit calls (including reference-detail conversion) remain
        // explicitly unmodeled effects, not an invented pure constructor.
        self.add_gap(
            builder,
            throwing,
            SemanticGapSubject::Point,
            SemanticCapability::Calls,
            SemanticGapKind::Unsupported,
            "implicit AssertionError construction effects are not yet modeled",
        )?;
        self.append_effect(
            builder,
            throwing,
            SemanticEffect::Throw {
                value: Some(thrown),
            },
        )?;
        self.abrupt_throw(builder, throwing, scope, thrown, stack)
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
            if self.static_field_may_initialize(node) {
                self.implicit_abort_edge(builder, node, entry, scope, None, stack)?;
            }
            // A lexical pattern identity does not manufacture a value when
            // record extraction or a capture relay was not established.
            if self.lexical_reference_binding(node).is_none()
                && (self.pattern_definition_at(node).is_some()
                    || self.pattern_visibility_unproven(node)
                    || (node_text(self.prepared.source(), node)
                        .is_some_and(|name| self.pattern_variable_names.contains(name))
                        && self.source_field_declaration(node).is_none()))
            {
                self.add_gap(
                    builder,
                    entry,
                    SemanticGapSubject::Value(result),
                    SemanticCapability::Values,
                    SemanticGapKind::Unsupported,
                    "pattern value establishment or record component extraction is not represented",
                )?;
            }
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
                // The result is the left operand when it decides the outcome
                // and the right operand otherwise (JLS 15.23, 15.24). Each way
                // out therefore leaves through its own point, which carries
                // that one flow, as the conditional expression's branches do.
                // The left operand is lowered as a condition, so a nested
                // `&&`, `||`, conditional or parenthesized operand has no
                // value of its own; the leaves that can decide it stand in.
                let decided = self.point(builder, node, Vec::new())?;
                let right_merge = self.point(builder, node, Vec::new())?;
                let deciders = short_circuit_decider_leaves(left)
                    .into_iter()
                    .map(|leaf| self.expression_value(builder, leaf, expression_value_kind(leaf)))
                    .collect::<Result<Vec<_>, _>>()?;
                self.session
                    .append_language_defined_value_flows(builder, decided, deciders, result)?;
                let right_value =
                    self.expression_value(builder, right, expression_value_kind(right))?;
                self.session.append_language_defined_value_flows(
                    builder,
                    right_merge,
                    [right_value],
                    result,
                )?;
                self.edge(builder, decided, next)?;
                self.edge(builder, right_merge, next)?;
                stack.push(Work::Expression {
                    node: right,
                    entry: right_entry,
                    next: EdgeTarget::normal(right_merge),
                    scope,
                });
                let (when_true, when_false) = if binary_operator(node) == Some("&&") {
                    (
                        EdgeTarget {
                            point: right_entry,
                            kind: ControlEdgeKind::ConditionalTrue,
                        },
                        EdgeTarget {
                            point: decided,
                            kind: ControlEdgeKind::ConditionalFalse,
                        },
                    )
                } else {
                    (
                        EdgeTarget {
                            point: decided,
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
                    // Parentheses preserve the evaluated value without a conversion.
                    self.emit_identity_flow(builder, terminal, inner, result)?;
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
            "field_access" if self.field_access_is_array_length(node) => {
                let object = required_field(node, "object")?;
                let access = self.point(builder, node, Vec::new())?;
                let base = self.expression_value(builder, object, expression_value_kind(object))?;
                self.append_effect(
                    builder,
                    access,
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::LanguageDefined,
                        source: base,
                        target: result,
                    },
                )?;
                self.edge(builder, access, next)?;
                if !self.expression_is_non_null(object) {
                    // Reading an array length still dereferences the array and
                    // can throw NullPointerException. Only the pseudo-field
                    // memory operation is removed.
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
            "field_access" => {
                let object = required_field(node, "object")?;
                let access = self.point(builder, node, Vec::new())?;
                let base = self.expression_value(builder, object, expression_value_kind(object))?;
                let (location, kind) = self.field_memory_location(builder, access, node, base)?;
                self.append_effect(
                    builder,
                    access,
                    SemanticEffect::MemoryLoad {
                        kind,
                        location,
                        result,
                    },
                )?;
                self.edge(builder, access, next)?;
                if (kind == MemoryAccessKind::Static && self.static_field_may_initialize(node))
                    || (kind != MemoryAccessKind::Static && !self.expression_is_non_null(object))
                {
                    // Static access can initialize another declaring class.
                    // Only an instance access dereferences the qualifier.
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
                        constant_index: None,
                        identity: brokk_bifrost_analysis::analyzer::semantic::IndexedLocationIdentity::Element,
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
            "string_literal" | "string_interpolation" => {
                // The embedded expressions are the only runtime parts of a
                // template fragment. The joined text derives from each of them.
                let embedded = if node.kind() == "string_literal" {
                    named_children(node)
                        .into_iter()
                        .filter(|child| child.kind() == "string_interpolation")
                        .collect::<Vec<_>>()
                } else {
                    named_children(node)
                };
                if embedded.is_empty() {
                    return self.edge(builder, entry, next);
                }
                self.derive_result_from_operands(
                    builder, node, entry, next, scope, &embedded, stack,
                )?;
                Ok(())
            }
            "assignment_expression" => {
                self.assignment_expression(builder, node, entry, next, scope, stack)
            }
            "update_expression" => self.update_expression(builder, node, entry, next, scope, stack),
            "binary_expression" | "unary_expression" => {
                let children = runtime_expression_children(node);
                let terminal = self.point(builder, node, Vec::new())?;
                if let Some((operand, offset)) = self.integer_offset_operand(node) {
                    let source =
                        self.expression_value(builder, operand, expression_value_kind(operand))?;
                    self.append_effect(
                        builder,
                        terminal,
                        SemanticEffect::ValueFlow {
                            kind: ValueFlowKind::IntegerOffset { offset },
                            source,
                            target: result,
                        },
                    )?;
                } else {
                    let operands = children
                        .iter()
                        .map(|child| {
                            self.expression_value(builder, *child, expression_value_kind(*child))
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    self.session
                        .append_language_defined_value_flows(builder, terminal, operands, result)?;
                }
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
            "cast_expression" if self.value_preserving_cast_operand(node).is_some() => {
                // An identity or widening primitive conversion of a primitive
                // binding keeps its value and cannot throw.
                let operand = self
                    .value_preserving_cast_operand(node)
                    .expect("guarded by the match arm");
                let terminal = self.point(builder, node, Vec::new())?;
                let source =
                    self.expression_value(builder, operand, expression_value_kind(operand))?;
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
                self.schedule_expressions(
                    builder,
                    entry,
                    &[operand],
                    EdgeTarget::normal(terminal),
                    scope,
                    stack,
                )
            }
            "cast_expression" => {
                // Every cast the arm above does not take checks or converts
                // its operand: a reference cast, a narrowing, a boxing and an
                // unboxing. JLS 15.16/5.5: the result derives from the
                // operand, and none of them is an identity transfer. Use the
                // shared conversion-flow emitter, as Kotlin and C/C++ do.
                // Publish the result only after the check succeeds, so a
                // ClassCastException or an unboxing NullPointerException does
                // not manufacture a normal result.
                let operand = required_field(node, "value")?;
                let source =
                    self.expression_value(builder, operand, expression_value_kind(operand))?;
                let checked = self.point(builder, node, Vec::new())?;
                let normal = self.point(builder, node, Vec::new())?;
                self.session.append_language_defined_value_flows(
                    builder,
                    normal,
                    [source],
                    result,
                )?;
                self.edge(builder, checked, EdgeTarget::normal(normal))?;
                self.edge(builder, normal, next)?;
                self.implicit_abort_edge(builder, node, checked, scope, None, stack)?;
                self.schedule_expressions(
                    builder,
                    entry,
                    &[operand],
                    EdgeTarget::normal(checked),
                    scope,
                    stack,
                )
            }
            "instanceof_expression" => {
                // The test yields a boolean computed from its operand, as a
                // comparison does (JLS 15.20.2). It cannot throw. A pattern
                // also binds the operand to new variables; a reference to one
                // of them carries the gap, not the test.
                let operand = required_field(node, "left")?;
                self.derive_result_from_operands(
                    builder,
                    node,
                    entry,
                    next,
                    scope,
                    &[operand],
                    stack,
                )?;
                Ok(())
            }
            "array_creation_expression" => {
                // NegativeArraySizeException leaves from the terminal point
                // that the dimension expressions reach first.
                let children = runtime_expression_children(node);
                let terminal = self.point(builder, node, Vec::new())?;
                if let Some(initializer) = node.child_by_field_name("value") {
                    // `new T[] { ... }` is the array its initializer builds.
                    let source = self.expression_value(
                        builder,
                        initializer,
                        expression_value_kind(initializer),
                    )?;
                    self.emit_identity_flow(builder, terminal, source, result)?;
                } else {
                    // A fresh array. Its length derives from the dimension
                    // expressions, which `length` reads back from the array.
                    self.session.add_allocation(
                        builder,
                        terminal,
                        result,
                        AllocationKind::Array,
                    )?;
                    let lengths = children
                        .iter()
                        .flat_map(|dimension| runtime_expression_children(*dimension))
                        .map(|length| {
                            self.expression_value(builder, length, expression_value_kind(length))
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    self.session
                        .append_language_defined_value_flows(builder, terminal, lengths, result)?;
                }
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
            "array_initializer" => {
                // A fresh array whose element `i` is initialized as if by
                // `array[i] = element` (JLS 10.6). The stores follow the
                // elements' evaluation, so they sit on the terminal point.
                let terminal = self.point(builder, node, Vec::new())?;
                self.session
                    .add_allocation(builder, terminal, result, AllocationKind::Array)?;
                let elements = runtime_expression_children(node);
                for (ordinal, element) in elements
                    .iter()
                    .take(JAVA_ARRAY_INITIALIZER_ELEMENT_CAP)
                    .enumerate()
                {
                    let mut value =
                        self.expression_value(builder, *element, expression_value_kind(*element))?;
                    if element.kind() == "array_initializer" {
                        // An initializer nested in an initializer is an
                        // implicit array creation (JLS 10.6), so the element
                        // is the creation's result: the nested array through
                        // an identity transfer, as `new T[] { ... }` gives.
                        let creation =
                            self.value(builder, terminal, SemanticValueKind::Temporary)?;
                        self.emit_identity_flow(builder, terminal, value, creation)?;
                        value = creation;
                    }
                    let index = self.ordinal_index_value(builder, terminal, ordinal)?;
                    let location = self.session.add_memory_location(
                        builder,
                        terminal,
                        MemoryLocationKind::Index {
                            base: result,
                            index: Some(index),
                            constant_index: None,
                            identity: brokk_bifrost_analysis::analyzer::semantic::IndexedLocationIdentity::Element,
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
                }
                if elements.len() > JAVA_ARRAY_INITIALIZER_ELEMENT_CAP {
                    // The array is complete as an allocation, but its later
                    // elements are not stored. The gap is discharged when
                    // nothing ever reads or publishes the array.
                    self.session.add_partitioned_gap(
                        builder,
                        terminal,
                        SemanticGapSubject::Value(result),
                        SemanticCapability::IndexMemory,
                        SemanticGapImpacts::single(SemanticGapImpact::HeapWrite),
                        SemanticGapKind::Unsupported,
                        "array initializer elements past the per-initializer cap are not stored",
                    )?;
                }
                self.edge(builder, terminal, next)?;
                self.schedule_expressions(
                    builder,
                    entry,
                    &elements,
                    EdgeTarget::normal(terminal),
                    scope,
                    stack,
                )
            }
            "dimensions_expr" => {
                let children = runtime_expression_children(node);
                self.schedule_expressions(builder, entry, &children, next, scope, stack)
            }
            "template_expression" => {
                // The processor's `process` call produces the result from the
                // template. The call is not lowered, so the result keeps the
                // flow of both operands and a gap that the result's own
                // reachability can discharge.
                let processor = required_field(node, "template_processor")?;
                let template = required_field(node, "template_argument")?;
                let terminal = self.derive_result_from_operands(
                    builder,
                    node,
                    entry,
                    next,
                    scope,
                    &[processor, template],
                    stack,
                )?;
                self.add_gap(
                    builder,
                    terminal,
                    SemanticGapSubject::Value(result),
                    SemanticCapability::Calls,
                    SemanticGapKind::Unknown,
                    "string template processor invocation is not yet lowered as a call",
                )?;
                self.implicit_abort_edge(builder, node, terminal, scope, None, stack)
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
        // Updates run before the condition, which starts every iteration.
        self.session
            .record_loop_site(builder, node, condition_entry, body_entry)?;
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
        schedule_loop_flow(
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
        .map(|_| ())
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
        // Every test acquires or advances the iteration (JLS 14.14.2), and
        // each can abort: a null array or `Iterable`, or an exception from
        // `iterator()`, `hasNext()` or `next()`. The binding assignment after
        // a successful test changes nothing an abort could observe.
        self.implicit_abort_edge(builder, node, test, scope, None, stack)?;
        // Array iteration runs no user code. `Iterable` iteration calls user
        // methods whose value and effect semantics are not modeled.
        if !self.expression_is_array(iterable) {
            self.add_gap(
                builder,
                test,
                SemanticGapSubject::Point,
                SemanticCapability::Calls,
                SemanticGapKind::Unknown,
                "enhanced-for iteration calls iterator(), hasNext() and next() user code whose value and effect semantics are not modeled",
            )?;
        }
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
        self.establish_enhanced_for_variable(builder, iterable, binding, binding_entry)?;
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

    /// Establish an enhanced-`for` loop variable on each iteration (JLS
    /// 14.14.2). The variable receives a fresh element of the array or
    /// `Iterable` every time the loop test succeeds, so it is an ordinary
    /// local initialized before its body runs. The element read is a
    /// language-defined value that depends on the iterable value. The loop
    /// test carries the iteration's abort edge and, for an `Iterable`, its
    /// user-code call gap.
    fn establish_enhanced_for_variable(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        iterable: Node<'tree>,
        binding: Node<'tree>,
        point: ProgramPointId,
    ) -> Result<(), JavaLoweringError> {
        // An unnamed variable (`_`) declares no local.
        if binding.kind() != "identifier" {
            return Ok(());
        }
        let name = node_text(self.prepared.source(), binding).ok_or_else(|| {
            JavaLoweringError::Invalid("enhanced-for variable has invalid name range".into())
        })?;
        let target = self
            .local_declaration_value(name, binding.start_byte())
            .ok_or_else(|| {
                JavaLoweringError::Invalid("enhanced-for variable was not preindexed".into())
            })?;
        let source = self.expression_value(builder, iterable, expression_value_kind(iterable))?;
        let element = self.source_value(
            builder,
            binding,
            SemanticValueKind::LanguageDefined("java.enhanced_for.element".into()),
        )?;
        self.append_effect(
            builder,
            point,
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::LanguageDefined,
                source,
                target: element,
            },
        )?;
        self.append_effect(
            builder,
            point,
            SemanticEffect::Assignment {
                target,
                value: element,
            },
        )?;
        self.append_effect(
            builder,
            point,
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Local,
                source: element,
                target,
            },
        )
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
        let selector =
            self.expression_value(builder, condition, expression_value_kind(condition))?;
        let switch_next = if expression_mode {
            let merge = self.point(builder, node, Vec::new())?;
            self.edge(builder, merge, next)?;
            EdgeTarget::normal(merge)
        } else {
            next
        };
        // The value of a switch expression is the operand of the rule or
        // `yield` that completes it (JLS 15.28.1, 14.21). A `yield` finds the
        // result through the point its completion route ends at.
        let switch_result = if expression_mode {
            let result = self.expression_value(builder, node, expression_value_kind(node))?;
            let previous = self.yield_results.insert(switch_next.point, result);
            assert!(
                previous.is_none(),
                "every switch expression has its own merge point"
            );
            Some(result)
        } else {
            None
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
            self.session.add_switch_fact(
                builder,
                SwitchFactScaffold {
                    point: dispatch,
                    kind: SwitchFactKind::Expression,
                    selector: Some(selector),
                    selector_domain: SwitchSelectorDomain::Open,
                    cases: Vec::new(),
                    default_edge: None,
                    default_present: false,
                },
            )?;
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
                        // A last group that ends in `yield` or `throw` cannot
                        // complete normally, so nothing reaches this point.
                        if !ends_in_yield_or_throw(arm.body.last().copied()) {
                            self.add_gap(
                                builder,
                                missing_yield,
                                SemanticGapSubject::Point,
                                SemanticCapability::NormalControlFlow,
                                SemanticGapKind::Unsupported,
                                "switch-expression statement group can complete without a represented yield",
                            )?;
                        }
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
                                // The rule's operand is the switch's value, so
                                // it leaves through its own point, which
                                // carries that one flow.
                                let rule_merge = self.point(builder, value, Vec::new())?;
                                let operand = self.expression_value(
                                    builder,
                                    value,
                                    expression_value_kind(value),
                                )?;
                                self.append_effect(
                                    builder,
                                    rule_merge,
                                    SemanticEffect::ValueFlow {
                                        kind: ValueFlowKind::Local,
                                        source: operand,
                                        target: switch_result
                                            .expect("a rule value exists in expression mode"),
                                    },
                                )?;
                                self.edge(builder, rule_merge, switch_next)?;
                                stack.push(Work::Expression {
                                    node: value,
                                    entry: arm_entries[index],
                                    next: EdgeTarget::normal(rule_merge),
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
                            // A block that ends in `yield` or `throw` cannot
                            // complete normally, so nothing reaches this point.
                            if !ends_in_yield_or_throw(Some(action)) {
                                self.add_gap(
                                    builder,
                                    missing_yield,
                                    SemanticGapSubject::Point,
                                    SemanticCapability::NormalControlFlow,
                                    SemanticGapKind::Unsupported,
                                    "switch-expression block rule can complete without a represented yield",
                                )?;
                            }
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

        let default_arm = arms.iter().enumerate().find_map(|(index, arm)| {
            arm.labels
                .iter()
                .any(|label| switch_label_is_default(*label))
                .then_some(index)
        });
        let default_point = default_arm.map(|index| arm_entries[index]);
        let mut no_match = if let Some(default_point) = default_point {
            EdgeTarget::normal(default_point)
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
        let mut cases = Vec::new();
        let mut default_edge_source = None;

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
                let mut pattern_stack = vec![*switch_label];
                let mut simple_patterns = Vec::new();
                while let Some(pattern) = pattern_stack.pop() {
                    if java_pattern_has_value(pattern) {
                        simple_patterns.push(pattern);
                    }
                    pattern_stack.extend(named_children(pattern));
                }
                let selected = if simple_patterns.is_empty() {
                    comparison
                } else {
                    self.point(builder, *switch_label, Vec::new())?
                };
                let case_edge_source = if let Some(guard) = switch_label_guard(*switch_label) {
                    let guard_entry = self.point(builder, guard, Vec::new())?;
                    self.edge(
                        builder,
                        selected,
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
                    if default_point == Some(no_match.point) {
                        default_edge_source = Some(guard_entry);
                    }
                    guard_entry
                } else {
                    self.edge(
                        builder,
                        selected,
                        EdgeTarget {
                            point: arm_entries[arm_index],
                            kind: ControlEdgeKind::SwitchCase,
                        },
                    )?;
                    if default_point == Some(no_match.point) {
                        default_edge_source = Some(comparison);
                    }
                    selected
                };
                if selected != comparison {
                    let mut next = EdgeTarget::normal(selected);
                    for pattern in simple_patterns.into_iter().rev() {
                        next = EdgeTarget::normal(
                            self.establish_pattern_binding(builder, pattern, selector, next)?,
                        );
                    }
                    self.edge(
                        builder,
                        comparison,
                        EdgeTarget {
                            point: next.point,
                            kind: ControlEdgeKind::ConditionalTrue,
                        },
                    )?;
                }
                for case_value in named_children(*switch_label)
                    .into_iter()
                    .filter(|child| child.kind() != "guard")
                {
                    cases.push(SwitchCaseFactParts {
                        value: self.expression_value(
                            builder,
                            case_value,
                            expression_value_kind(case_value),
                        )?,
                        edge: SwitchEdgeParts {
                            source_point: case_edge_source,
                            arm: GuardArm {
                                target_point: arm_entries[arm_index],
                                kind: ControlEdgeKind::SwitchCase,
                            },
                        },
                    });
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
        let default_edge = default_point.map(|target_point| {
            let (source_point, kind) = default_edge_source
                .map_or((dispatch, ControlEdgeKind::SwitchCase), |source_point| {
                    (source_point, ControlEdgeKind::ConditionalFalse)
                });
            SwitchEdgeParts {
                source_point,
                arm: GuardArm { target_point, kind },
            }
        });
        self.session.add_switch_fact(
            builder,
            SwitchFactScaffold {
                point: dispatch,
                kind: SwitchFactKind::Expression,
                selector: Some(selector),
                selector_domain: SwitchSelectorDomain::Open,
                cases,
                default_edge,
                default_present: default_point.is_some(),
            },
        )?;
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
            let initializers = try_with_resources_values(node);
            // A resource that another initializer follows can also be closed by
            // that later initializer's failure: Java releases every resource
            // that already initialized. That partial-initialization close chain
            // is not lowered, so it opens exactly the values it can close and
            // nothing else. The last resource has no later initializer, and a
            // single-resource statement has no partial-initialization close at
            // all, so those acquisitions stay exact.
            for initializer in initializers
                .iter()
                .take(initializers.len().saturating_sub(1))
            {
                let value = self.expression_value(
                    builder,
                    *initializer,
                    expression_value_kind(*initializer),
                )?;
                self.add_gap(
                    builder,
                    resource_boundary,
                    SemanticGapSubject::Value(value),
                    SemanticCapability::ResourceManagement,
                    SemanticGapKind::Unsupported,
                    "a later resource initializer can fail and close this resource, and that partial-initialization close chain is not yet lowered",
                )?;
            }
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
        let cleanup_destination = self.session.cleanup_next_target(builder, node, next)?.point;
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
        // Only a method invocation dispatches on a receiver. A constructor
        // call never does: the qualifier of `outer.new Inner()` or of
        // `outer.super(...)` names the enclosing instance, which the JVM
        // passes as the constructor's hidden leading parameter, so it lowers
        // as the call's implicit first argument below. Lowering it as a bound
        // receiver instead contradicts the callable IR contract, which
        // accepts `bound_receiver` only on a `BoundMethod` callable, and
        // refused the whole file's materialization (#1910).
        let receiver_node = (node.kind() == "method_invocation")
            .then(|| node.child_by_field_name("object"))
            .flatten();
        let enclosing_instance_node = match node.kind() {
            "explicit_constructor_invocation" => node.child_by_field_name("object"),
            "object_creation_expression" => object_creation_qualifier(node),
            _ => None,
        };
        let receiver = receiver_node
            .map(|receiver_node| {
                self.expression_value(builder, receiver_node, expression_value_kind(receiver_node))
            })
            .transpose()?;
        let enclosing_instance = enclosing_instance_node
            .map(|qualifier| {
                self.expression_value(builder, qualifier, expression_value_kind(qualifier))
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
        let mut argument_values =
            Vec::with_capacity(arguments.len() + usize::from(enclosing_instance.is_some()));
        argument_values.extend(
            enclosing_instance
                .map(|value| SemanticCallArgument::direct(value, ArgumentDomain::Positional)),
        );
        for argument in &arguments {
            let value =
                self.expression_value(builder, *argument, expression_value_kind(*argument))?;
            argument_values.push(SemanticCallArgument::direct(
                value,
                ArgumentDomain::Positional,
            ));
        }
        let call_site = self.session.add_call_site(
            builder,
            CallSiteScaffold {
                point: invoke,
                callee,
                receiver,
                member_selection: None,
                arguments: argument_values.into_boxed_slice(),
                normal_results: Box::new([]),
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
        // The call's thrown value binds a catch parameter that handles it,
        // like any other throw.
        self.abrupt_throw(builder, exceptional, scope, thrown, stack)?;
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

        // Java evaluates the receiver or the enclosing-instance qualifier
        // before the argument list.
        let mut evaluations = Vec::with_capacity(
            arguments.len()
                + usize::from(receiver_node.is_some())
                + usize::from(enclosing_instance_node.is_some()),
        );
        evaluations.extend(receiver_node);
        evaluations.extend(enclosing_instance_node);
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
        let target = self.procedure_targets.get(&node.id()).cloned();
        let resolution = target
            .as_ref()
            .map(|target| CallableTargetResolution::Proven(CallableTarget::Local(target.id)))
            .unwrap_or(CallableTargetResolution::Unknown);
        let metadata = self.metadata(entry)?;
        let kind = if node.kind() == "lambda_expression" {
            CallableReferenceKind::Lambda
        } else {
            CallableReferenceKind::UnboundMethod
        };
        let environment = if target.as_ref().is_some_and(|target| {
            target.receiver_capture_destination.is_some() || !target.captures.is_empty()
        }) {
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
        if node.kind() == "lambda_expression"
            && target
                .as_ref()
                .is_none_or(|target| target.captures_incomplete)
        {
            self.add_gap(
                builder,
                entry,
                SemanticGapSubject::Procedure,
                SemanticCapability::Captures,
                SemanticGapKind::Unsupported,
                "lambda capture inventory includes an unsupported binding or enclosing-class boundary",
            )?;
        }
        if let (Some(target), Some(environment), Some(captured), Some(destination)) = (
            target.as_ref(),
            environment,
            self.receiver.or(self.captured_receiver),
            target
                .as_ref()
                .and_then(|target| target.receiver_capture_destination),
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
        if let (Some(target), Some(environment)) = (target.as_ref(), environment) {
            for (index, capture) in target.captures.iter().enumerate() {
                let name = node_text(self.prepared.source(), capture.binding.name)
                    .expect("inventoried capture has a source name");
                let source = self
                    .local_declaration_value(name, capture.binding.name.start_byte())
                    .or_else(|| self.parameters.get(name).copied())
                    .expect("inventoried capture has an exact parent binding");
                let destination =
                    java_capture_destination(target.receiver_capture_destination.is_some(), index)?;
                self.session.add_capture(
                    builder,
                    entry,
                    result,
                    target.id,
                    environment,
                    CaptureSource::Value(source),
                    destination,
                    CaptureMode::Value,
                )?;
            }
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
        let Some((route, abort)) = self.session.prepare_implicit_abort(builder, node, scope)?
        else {
            return Err(JavaLoweringError::Invalid(
                "implicit abort has no matching structured continuation".into(),
            ));
        };
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
            self.bind_catch_parameter(builder, abort, binder, thrown)?;
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
        schedule_sequential_work(
            stack,
            children,
            &entries,
            next,
            scope,
            |_, node, entry, next, scope| Work::Statement {
                node,
                entry,
                next,
                scope,
            },
        );
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
        schedule_sequential_work(
            stack,
            children,
            &entries,
            next,
            scope,
            |_, node, entry, next, scope| Work::Expression {
                node,
                entry,
                next,
                scope,
            },
        );
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
                    kind.label()
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
                kind.label()
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
            self.bind_catch_parameter(builder, from, target, value)?;
        }
        self.route(builder, from, &route, stack)
    }

    /// Assign the thrown value to the catch parameter on one path into its
    /// handler. Like a local initializer, this is both the binding's
    /// establishment and its value flow, so the parameter is initialized in
    /// the catch body on every path that binds it.
    fn bind_catch_parameter(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        point: ProgramPointId,
        binder: ValueId,
        thrown: ValueId,
    ) -> Result<(), JavaLoweringError> {
        self.append_effect(
            builder,
            point,
            SemanticEffect::Assignment {
                target: binder,
                value: thrown,
            },
        )?;
        self.append_effect(
            builder,
            point,
            SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Local,
                source: thrown,
                target: binder,
            },
        )
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
                CleanupBody::OpaqueResource(node) => {
                    self.lower_implicit_resource_closes(builder, node, step, stack)?;
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

    /// Lower the implicit close of a try-with-resources statement.
    ///
    /// Java releases every successfully initialized resource at the
    /// construct's own exit, in reverse declaration order, on both the normal
    /// and the exceptional continuation of the guarded body. Each release is a
    /// real close operation on the resource value the construct acquired, so
    /// the typestate engine binds it to the tracked subject identity instead
    /// of to the spelled resource variable.
    ///
    /// Every close site is anchored at the try statement, which is the source
    /// fact the resource-lifecycle selector names for the construct, and each
    /// publishes the close operation's own normal and exceptional
    /// continuations. A close that throws still released its resource, so its
    /// exceptional continuation enters the *next* close in the chain, and only
    /// the last release in the chain propagates from the enclosing scope: an
    /// earlier failure cannot skip a later release, and this region never runs
    /// twice.
    fn lower_implicit_resource_closes(
        &mut self,
        builder: &mut ProcedureCfgBuilder,
        node: Node<'tree>,
        step: CleanupSpecialization<CleanupRegion<'tree>>,
        stack: &mut Vec<Work<'tree>>,
    ) -> Result<(), JavaLoweringError> {
        let mut values = try_with_resources_values(node);
        // Java closes in reverse declaration order, so the execution order runs
        // from the last declared resource to the first.
        values.reverse();
        if values.is_empty() {
            // Only an error-recovered resource specification has no resource
            // value at all; the grammar requires at least one resource. Keep
            // the construct reachable and report the gap instead of inventing a
            // close.
            self.add_gap(
                builder,
                step.entry,
                SemanticGapSubject::Point,
                SemanticCapability::ResourceManagement,
                SemanticGapKind::Unsupported,
                "a malformed resource specification declares no resource value, so its implicit close is not represented",
            )?;
            self.edge(builder, step.entry, step.next)?;
            return Ok(());
        }
        // The cleanup entry is the first release Java performs, so reusing it
        // keeps one point per release without adding a relay.
        let mut invokes = Vec::with_capacity(values.len());
        for index in 0..values.len() {
            invokes.push(if index == 0 {
                step.entry
            } else {
                self.point(builder, node, Vec::new())?
            });
        }
        let last = values.len() - 1;
        let mut continuations = Vec::with_capacity(values.len());
        for (index, value_node) in values.into_iter().enumerate() {
            let invoke = invokes[index];
            let normal = self.point(builder, node, Vec::new())?;
            let exceptional = self.point(builder, node, Vec::new())?;
            let receiver =
                self.expression_value(builder, value_node, expression_value_kind(value_node))?;
            let callee = self.source_value(builder, value_node, SemanticValueKind::Callable)?;
            let thrown = self.source_value(builder, value_node, SemanticValueKind::Exception)?;
            let metadata = self.metadata(invoke)?;
            self.append_effect(
                builder,
                invoke,
                SemanticEffect::CallableReference {
                    result: callee,
                    callable: CallableValue {
                        kind: CallableReferenceKind::BoundMethod,
                        targets: CallableTargetResolution::Unknown,
                        target_evidence: metadata.evidence,
                        bound_receiver: Some(receiver),
                        environment: None,
                    },
                },
            )?;
            let call_site = self.session.add_call_site(
                builder,
                CallSiteScaffold {
                    point: invoke,
                    callee,
                    receiver: Some(receiver),
                    member_selection: None,
                    arguments: Box::new([]),
                    normal_results: Box::new([]),
                    result: None,
                    thrown: Some(thrown),
                    declared_targets: CallableTargetResolution::Unknown,
                    normal_continuation: normal,
                    exceptional_continuation: exceptional,
                },
            )?;
            self.resolution_gaps(
                builder,
                invoke,
                callee,
                call_site,
                &CallableTargetResolution::Unknown,
            )?;
            self.edge(builder, invoke, EdgeTarget::normal(normal))?;
            self.edge(
                builder,
                invoke,
                EdgeTarget {
                    point: exceptional,
                    kind: ControlEdgeKind::Exceptional,
                },
            )?;
            continuations.push((normal, exceptional, index == last));
        }
        // A close that throws still released its resource, so its exceptional
        // continuation continues with the releases that remain and then
        // propagates from the enclosing scope.
        for (index, (normal, exceptional, is_last)) in continuations.iter().copied().enumerate() {
            let next = invokes
                .get(index + 1)
                .copied()
                .map(EdgeTarget::normal)
                .unwrap_or(step.next);
            self.edge(builder, normal, next)?;
            if is_last {
                self.abrupt(
                    builder,
                    exceptional,
                    step.region.outer_scope,
                    CompletionKind::Throw,
                    None,
                    stack,
                )?;
            } else {
                // The remaining releases run as part of the same unwinding, so
                // the edge that resumes the chain stays exceptional. Publishing
                // it as a normal edge would lose the in-flight completion here
                // and let a later release's own exit class stand in for the
                // class this hop arrived with.
                self.edge(
                    builder,
                    exceptional,
                    EdgeTarget {
                        point: invokes[index + 1],
                        kind: ControlEdgeKind::Exceptional,
                    },
                )?;
            }
        }
        Ok(())
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

/// The exact offset that adds (or, when `subtract`, removes) an integer
/// literal's value.
fn literal_offset(constant: i64, subtract: bool) -> SignedIntegerMagnitude {
    let offset = if subtract {
        -i128::from(constant)
    } else {
        i128::from(constant)
    };
    SignedIntegerMagnitude::from_i128(offset)
}

/// The resource value expressions of a try-with-resources statement, in
/// declaration order.
///
/// A resource is a `variable_declarator` (or a bare access expression naming
/// an existing resource), so its value is the declarator's `value` field, or,
/// for the access form, its own expression. Java closes the resources in
/// reverse declaration order, and both the acquisition lowering and the
/// implicit-close lowering need the same list, so it is derived once here.
fn try_with_resources_values(node: Node<'_>) -> Vec<Node<'_>> {
    assert_eq!(
        node.kind(),
        "try_with_resources_statement",
        "only a try-with-resources statement declares a resource specification"
    );
    node.child_by_field_name("resources")
        .map(named_children)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|resource| {
            resource
                .child_by_field_name("value")
                .or_else(|| first_runtime_named_child(resource))
        })
        .collect()
}

/// The operands that can decide the value of the left operand of a
/// short-circuit `&&` or `||`.
///
/// `condition` splits a nested `&&`, `||`, conditional expression, or
/// parenthesized expression into control edges and never evaluates the nested
/// node as a value, so only its leaves have values to flow from. A literal
/// `true` or `false` is folded away and contributes no operand.
fn short_circuit_decider_leaves(operand: Node<'_>) -> Vec<Node<'_>> {
    let mut leaves = Vec::new();
    let mut pending = vec![operand];
    while let Some(node) = pending.pop() {
        match (node.kind(), binary_operator(node)) {
            ("true" | "false", _) => {}
            ("parenthesized_expression", _) => pending.extend(first_named_child(node)),
            ("binary_expression", Some("&&" | "||")) => {
                pending.extend(node.child_by_field_name("right"));
                pending.extend(node.child_by_field_name("left"));
            }
            ("ternary_expression", _) => {
                pending.extend(node.child_by_field_name("alternative"));
                pending.extend(node.child_by_field_name("consequence"));
            }
            _ => leaves.push(node),
        }
    }
    leaves
}

/// Whether `statement`, the last statement of a switch-expression rule block
/// or statement group, completes abruptly whenever control reaches it. A rule
/// block or last group that can complete normally is a compile-time error
/// (JLS 15.28.1), so such a statement means the fall-off-the-end path has no
/// predecessor.
///
/// The answer is `true` only when every path ends in `yield` or `throw`, so
/// the walk follows a block's last statement, both branches of an `if` with an
/// `else`, and the body and every `catch` of a `try`. A `finally` that itself
/// cannot complete normally is not credited. Anything else stays unproven.
fn ends_in_yield_or_throw(statement: Option<Node<'_>>) -> bool {
    let Some(statement) = statement else {
        return false;
    };
    let mut pending = vec![statement];
    while let Some(node) = pending.pop() {
        match node.kind() {
            "yield_statement" | "throw_statement" => {}
            "block" => match named_children(node).last() {
                Some(last) => pending.push(*last),
                None => return false,
            },
            "if_statement" => {
                let (Some(consequence), Some(alternative)) = (
                    node.child_by_field_name("consequence"),
                    node.child_by_field_name("alternative"),
                ) else {
                    return false;
                };
                pending.push(consequence);
                pending.push(alternative);
            }
            "try_statement" | "try_with_resources_statement" => {
                let Some(body) = node.child_by_field_name("body") else {
                    return false;
                };
                pending.push(body);
                pending.extend(
                    named_children(node)
                        .into_iter()
                        .filter(|child| child.kind() == "catch_clause")
                        .filter_map(|catch| catch.child_by_field_name("body")),
                );
            }
            "synchronized_statement" => match node.child_by_field_name("body") {
                Some(body) => pending.push(body),
                None => return false,
            },
            _ => return false,
        }
    }
    true
}
