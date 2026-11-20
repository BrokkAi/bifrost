//! Interior-mutability proof owned by RustTypeProof. No std-name absence table.
use super::*;
use crate::analyzer::semantic::partial_flow::guard_bindings::{
    GuardBindingReason, GuardInteriorMutability as Interior, GuardStorageExclusivity as Storage,
};
use crate::analyzer::semantic::{
    BarrierObservation, ReceiverMode, SemanticRequest, SemanticValueKind, SourceMappingKind,
};
use crate::analyzer::semantic_model::{
    GenericParameterDefault, GenericParameterKind, TypeInteriorMutability,
};

pub(crate) fn for_observation(
    analyzer: &dyn IAnalyzer,
    observation: &BarrierObservation,
    observed: Option<&crate::analyzer::semantic::ObservedValueType>,
    request: &mut SemanticRequest<'_>,
) -> Interior {
    if request.cancellation.is_cancelled() {
        return Interior::Unknown;
    }
    // The context certifies primitive identity through selected intrinsic rows;
    // this is not a classification of source text or of a nominal std name.
    if let Some(crate::analyzer::semantic::ObservedValueType::Named { canonical }) = observed
        && matches!(
            canonical.as_str(),
            "bool"
                | "char"
                | "str"
                | "&str"
                | "i8"
                | "i16"
                | "i32"
                | "i64"
                | "i128"
                | "isize"
                | "u8"
                | "u16"
                | "u32"
                | "u64"
                | "u128"
                | "usize"
                | "f16"
                | "f32"
                | "f64"
                | "f128"
        )
    {
        return Interior::Absent;
    }
    with_selected_observation(
        analyzer,
        observation,
        request,
        |proof, source, expression, _request| {
            proof.guard_expression_interior(source, expression, PROOF_DEPTH)
        },
    )
    .unwrap_or(Interior::Unknown)
}

pub(crate) fn storage_exclusivity(
    analyzer: &dyn IAnalyzer,
    observation: &BarrierObservation,
    request: &mut SemanticRequest<'_>,
) -> Storage {
    match observation
        .point()
        .procedure()
        .semantics()
        .value(observation.value())
        .map(|value| &value.kind)
    {
        Some(SemanticValueKind::Receiver {
            mode: ReceiverMode::SharedBorrow | ReceiverMode::MutableBorrow,
            ..
        }) => return Storage::NotExclusive,
        Some(
            SemanticValueKind::Local
            | SemanticValueKind::Parameter { .. }
            | SemanticValueKind::Receiver {
                mode: ReceiverMode::Owned,
                ..
            },
        ) => {}
        _ => return Storage::Unknown,
    }
    with_selected_observation(
        analyzer,
        observation,
        request,
        |proof, source, expression, request| {
            proof.guard_expression_storage(source, expression, PROOF_DEPTH, request)
        },
    )
    .unwrap_or(Storage::Unknown)
}

/// Source-native operand identity, independent of semantic-pack primitive
/// markers. Nominal comparisons (including derives) need a selected semantic
/// certificate that this capability does not currently provide.
pub(crate) fn comparison_semantics(
    analyzer: &dyn IAnalyzer,
    procedure: &crate::analyzer::semantic::ProcedureHandle,
    guard: &crate::analyzer::semantic::GuardFact,
    request: &mut SemanticRequest<'_>,
) -> Result<(), GuardBindingReason> {
    use brokk_bifrost_analysis::analyzer::usages::call_conversion::{
        ConversionUnknown, RustConversionType,
    };
    if request.cancellation.is_cancelled() {
        return Err(GuardBindingReason::Cancelled);
    }
    if !request.charge_execution_traversal(2) {
        return Err(GuardBindingReason::BudgetExceeded);
    }
    let mut inference_stop = None;
    let mut prove = || -> Option<()> {
        let mapping = procedure
            .semantics()
            .source_mapping(guard.source)
            .filter(|mapping| mapping.kind == SourceMappingKind::Exact)?;
        let mut proof = RustTypeProof::new(analyzer)?;
        proof.resolver.cancellation = Some(request.cancellation.clone());
        let file = ProjectFile::new(
            proof.rust.inner.project().root(),
            mapping.locator.path().as_path(),
        );
        let source = proof.source(&file)?;
        if !proof
            .rust
            .inner
            .source_matches_selected_native_content(&file, source.text())
        {
            return None;
        }
        let span = mapping.locator.anchor().span();
        let node = source.tree().root_node().named_descendant_for_byte_range(
            span.start_byte() as usize,
            span.end_byte() as usize,
        )?;
        if node.byte_range() != (span.start_byte() as usize..span.end_byte() as usize)
            || node.has_error()
            || node.kind() != "binary_expression"
            || !matches!(
                node.child_by_field_name("operator")?.kind(),
                "==" | "!=" | "<" | "<=" | ">" | ">="
            )
        {
            return None;
        }
        let operands = [
            node.child_by_field_name("left")?,
            node.child_by_field_name("right")?,
        ];
        let types = operands.map(|operand| {
            super::super::call_conversion::expression_conversion_type(
                analyzer,
                &file,
                source.text(),
                operand,
            )
        });
        // Conversion inference owns depth/work bounds separate from the
        // SemanticRequest ledger. Preserve those stops before a content-only
        // literal fallback or comparison decline can erase their provenance.
        if types
            .iter()
            .any(|ty| matches!(ty, Err(ConversionUnknown::Cancelled)))
        {
            inference_stop = Some(GuardBindingReason::Cancelled);
            return None;
        }
        if types.iter().any(|ty| {
            matches!(
                ty,
                Err(ConversionUnknown::BudgetExhausted | ConversionUnknown::FixedLimit)
            )
        }) {
            inference_stop = Some(GuardBindingReason::BudgetExceeded);
            return None;
        }
        let types = types.map(Result::ok);
        for side in 0..2 {
            let builtin = match types[side].as_ref() {
                Some(RustConversionType::Primitive(_)) => true,
                Some(RustConversionType::Reference {
                    mutable: false,
                    referent,
                }) => matches!(**referent, RustConversionType::Primitive(_)),
                None => match types[1 - side].as_ref() {
                    // Only a proven native numeric peer supplies inference.
                    // A nominal peer could overload comparison with a literal.
                    Some(RustConversionType::Primitive(primitive)) => {
                        inferred_numeric_comparison_literal(
                            &source,
                            operands[side],
                            *primitive,
                            request,
                        )
                    }
                    _ => false,
                },
                _ => false,
            };
            if !builtin {
                return None;
            }
        }
        Some(())
    };
    let result = prove();
    if request.cancellation.is_cancelled() || inference_stop == Some(GuardBindingReason::Cancelled)
    {
        Err(GuardBindingReason::Cancelled)
    } else if request.stop_observed() {
        Err(GuardBindingReason::BudgetExceeded)
    } else if let Some(reason) = inference_stop {
        Err(reason)
    } else {
        result.ok_or(GuardBindingReason::UnprovenComparisonSemantics)
    }
}

/// Unsuffixed literals get their scalar type from the proven opposite operand,
/// never from a guessed default or from the spelling of a nominal type.
fn inferred_numeric_comparison_literal(
    source: &RustSource,
    mut operand: Node<'_>,
    peer: brokk_bifrost_analysis::analyzer::usages::call_conversion::RustPrimitive,
    request: &mut SemanticRequest<'_>,
) -> bool {
    use brokk_bifrost_analysis::analyzer::usages::call_conversion::RustPrimitive;
    use brokk_bifrost_rust::syntax::{RustLiteralType, rust_literal_type};
    let mut negative = false;
    loop {
        if request.cancellation.is_cancelled() || !request.charge_execution_traversal(1) {
            return false;
        }
        match operand.kind() {
            "parenthesized_expression" => {
                let Some(inner) = operand.named_child(0) else {
                    return false;
                };
                operand = inner;
            }
            "unary_expression"
                if !negative
                    && operand
                        .child(0)
                        .is_some_and(|operator| operator.kind() == "-") =>
            {
                let Some(inner) = operand.named_child(0) else {
                    return false;
                };
                negative = true;
                operand = inner;
            }
            _ => break,
        }
    }
    if !matches!(
        rust_literal_type(operand, source.text()),
        Some(RustLiteralType::InferredNumeric)
    ) {
        return false;
    }
    match operand.kind() {
        "float_literal" => matches!(peer, RustPrimitive::F32 | RustPrimitive::F64),
        "integer_literal" => {
            matches!(
                peer,
                RustPrimitive::I8
                    | RustPrimitive::I16
                    | RustPrimitive::I32
                    | RustPrimitive::I64
                    | RustPrimitive::I128
                    | RustPrimitive::Isize
            ) || (!negative
                && matches!(
                    peer,
                    RustPrimitive::U8
                        | RustPrimitive::U16
                        | RustPrimitive::U32
                        | RustPrimitive::U64
                        | RustPrimitive::U128
                        | RustPrimitive::Usize
                ))
        }
        _ => false,
    }
}

pub(crate) fn argument_nonmutating(
    analyzer: &dyn IAnalyzer,
    observation: &BarrierObservation,
    request: &mut SemanticRequest<'_>,
) -> Result<(), GuardBindingReason> {
    let result = with_selected_observation(
        analyzer,
        observation,
        request,
        |proof, source, expression, _request| {
            let ty = if expression.kind() == "parameter" {
                expression.child_by_field_name("type")
            } else {
                binding_pattern_owner(expression, expression.byte_range())
                    .and_then(|owner| owner.child_by_field_name("type"))
                    .or_else(|| proof.declared_binding_type(source, expression))
            }
            .ok_or(GuardBindingReason::UnknownBorrow)?;
            proof.guard_argument_syntax_nonmutating(source, ty, PROOF_DEPTH)
        },
    )
    .unwrap_or(Err(GuardBindingReason::UnknownBorrow));
    if request.cancellation.is_cancelled() {
        Err(GuardBindingReason::Cancelled)
    } else if request.stop_observed() {
        Err(GuardBindingReason::BudgetExceeded)
    } else {
        result
    }
}

fn with_selected_observation<T>(
    analyzer: &dyn IAnalyzer,
    observation: &BarrierObservation,
    request: &mut SemanticRequest<'_>,
    inspect: impl FnOnce(&RustTypeProof<'_>, &RustSource, Node<'_>, &mut SemanticRequest<'_>) -> T,
) -> Option<T> {
    if request.cancellation.is_cancelled() || !request.charge_execution_traversal(1) {
        return None;
    }
    let ir = observation.point().procedure().semantics();
    let value = ir.value(observation.value())?;
    let mapping = ir
        .source_mapping(value.source)
        .filter(|mapping| mapping.kind == SourceMappingKind::Exact)?;
    let mut proof = RustTypeProof::new(analyzer)?;
    proof.resolver.cancellation = Some(request.cancellation.clone());
    let file = ProjectFile::new(
        proof.rust.inner.project().root(),
        mapping.locator.path().as_path(),
    );
    let source = proof.source(&file)?;
    if !proof
        .rust
        .inner
        .source_matches_selected_native_content(&file, source.text())
    {
        return None;
    }
    let span = mapping.locator.anchor().span();
    let expression = source
        .tree()
        .root_node()
        .named_descendant_for_byte_range(span.start_byte() as usize, span.end_byte() as usize)
        .filter(|node| {
            node.start_byte() == span.start_byte() as usize
                && node.end_byte() == span.end_byte() as usize
                && !node.has_error()
        })?;
    let result = inspect(&proof, &source, expression, request);
    if request.cancellation.is_cancelled()
        || brokk_bifrost_analysis::analyzer::i_analyzer::current_captured_proof_stop().is_some()
    {
        None
    } else {
        Some(result)
    }
}

fn combine(values: impl IntoIterator<Item = Interior>) -> Interior {
    let mut result = Interior::Absent;
    for value in values {
        match value {
            Interior::Present => return Interior::Present,
            Interior::Unknown => result = Interior::Unknown,
            Interior::Absent => {}
        }
    }
    result
}

fn combine_storage(values: impl IntoIterator<Item = Storage>) -> Storage {
    let mut result = Storage::Exclusive;
    for value in values {
        match value {
            Storage::NotExclusive => return Storage::NotExclusive,
            Storage::Unknown => result = Storage::Unknown,
            Storage::Exclusive => {}
        }
    }
    result
}

impl<R: RustTypeProofResolver> RustTypeProof<'_, R> {
    fn guard_expression_storage(
        &self,
        source: &RustSource,
        expression: Node<'_>,
        depth: usize,
        request: &mut SemanticRequest<'_>,
    ) -> Storage {
        if depth == 0
            || request.cancellation.is_cancelled()
            || !request.charge_execution_traversal(1)
        {
            return Storage::Unknown;
        }
        let owner = binding_pattern_owner(expression, expression.byte_range());
        let declared = if expression.kind() == "parameter" {
            expression.child_by_field_name("type")
        } else {
            owner
                .and_then(|owner| owner.child_by_field_name("type"))
                .or_else(|| self.declared_binding_type(source, expression))
        };
        if let Some(ty) = declared {
            return self.guard_syntax_storage(source, ty, depth - 1, request);
        }
        // Infer an unannotated local from its own initializer, never a shadowed
        // name outside the declaration. Selected types preserve reference form.
        let value = owner
            .and_then(|owner| owner.child_by_field_name("value"))
            .unwrap_or(expression);
        self.modeled_receiver_type_bounded(source, value, depth - 1)
            .map_or(Storage::Unknown, |ty| {
                self.guard_type_ref_storage(&ty, depth - 1, request)
            })
    }

    fn guard_syntax_storage(
        &self,
        source: &RustSource,
        ty: Node<'_>,
        depth: usize,
        request: &mut SemanticRequest<'_>,
    ) -> Storage {
        if depth == 0
            || ty.has_error()
            || request.cancellation.is_cancelled()
            || !request.charge_execution_traversal(1)
        {
            return Storage::Unknown;
        }
        match ty.kind() {
            "reference_type" | "pointer_type" => Storage::NotExclusive,
            "unit_type" | "never_type" => Storage::Exclusive,
            "tuple_type" => combine_storage(
                named_children(ty)
                    .into_iter()
                    .map(|ty| self.guard_syntax_storage(source, ty, depth - 1, request)),
            ),
            "array_type" => ty
                .child_by_field_name("element")
                .map_or(Storage::Unknown, |ty| {
                    self.guard_syntax_storage(source, ty, depth - 1, request)
                }),
            "primitive_type" | "type_identifier" | "scoped_type_identifier" => {
                if let Some(unit) = self.workspace_definition(source, ty) {
                    let cancellation = request.cancellation.clone();
                    return self
                        .with_guard_aggregate_fields(&unit, &cancellation, |source, fields| {
                            if !request.charge_execution_traversal(fields.len()) {
                                return Storage::Unknown;
                            }
                            combine_storage(fields.iter().map(|ty| {
                                self.guard_syntax_storage(source, *ty, depth - 1, request)
                            }))
                        })
                        .unwrap_or(Storage::Unknown);
                }
                if ty.kind() == "primitive_type"
                    && self.guard_syntax_interior(source, ty, depth - 1) == Interior::Absent
                {
                    Storage::Exclusive
                } else {
                    // No ownership-by-name certificate for opaque heap/model types.
                    Storage::Unknown
                }
            }
            _ => Storage::Unknown,
        }
    }

    fn guard_type_ref_storage(
        &self,
        ty: &TypeRef,
        depth: usize,
        request: &mut SemanticRequest<'_>,
    ) -> Storage {
        if depth == 0
            || request.cancellation.is_cancelled()
            || !request.charge_execution_traversal(1)
        {
            return Storage::Unknown;
        }
        match ty {
            TypeRef::ByRef { .. } | TypeRef::Pointer { .. } => Storage::NotExclusive,
            TypeRef::Array { element } => self.guard_type_ref_storage(element, depth - 1, request),
            TypeRef::Tuple { elements } => combine_storage(
                elements
                    .iter()
                    .map(|ty| self.guard_type_ref_storage(ty, depth - 1, request)),
            ),
            _ => self
                .analyzer
                .semantic_model_overlay()
                .map_or(Storage::Unknown, |overlay| {
                    if is_intrinsic_primitive_type(&overlay, ty) {
                        Storage::Exclusive
                    } else {
                        Storage::Unknown
                    }
                }),
        }
    }

    fn guard_expression_interior(
        &self,
        source: &RustSource,
        expression: Node<'_>,
        depth: usize,
    ) -> Interior {
        if depth == 0 {
            return Interior::Unknown;
        }
        match expression.kind() {
            "boolean_literal" | "integer_literal" | "float_literal" | "char_literal"
            | "string_literal" | "raw_string_literal" | "unit_expression" => Interior::Absent,
            "reference_expression" | "parenthesized_expression" => expression
                .child_by_field_name("value")
                .or_else(|| expression.named_child(0))
                .map_or(Interior::Unknown, |inner| {
                    self.guard_expression_interior(source, inner, depth - 1)
                }),
            "parameter" => expression
                .child_by_field_name("type")
                .map_or(Interior::Unknown, |ty| {
                    self.guard_syntax_interior(source, ty, depth - 1)
                }),
            "identifier" | "self" => {
                // At its own declaration the name resolves past the `let`, so an
                // unannotated declaration never takes a shadowed binding's type.
                let declaration = binding_pattern_owner(expression, expression.byte_range())
                    .filter(|owner| {
                        owner.child_by_field_name("pattern").is_some_and(|pattern| {
                            pattern.kind() == "identifier"
                                && pattern.byte_range() == expression.byte_range()
                        })
                    });
                let declared = match declaration {
                    Some(owner) => owner.child_by_field_name("type"),
                    None => self.declared_binding_type(source, expression),
                };
                if let Some(ty) = declared {
                    return self.guard_syntax_interior(source, ty, depth - 1);
                }
                // An unannotated declaration has no type to read here, and the
                // receiver-type lookup below resolves past the `let`.
                if declaration.is_some() {
                    return Interior::Unknown;
                }
                self.modeled_receiver_type_bounded(source, expression, depth - 1)
                    .map_or(Interior::Unknown, |ty| {
                        self.guard_type_ref_interior(&ty, depth - 1)
                    })
            }
            "call_expression" => self
                .selected_call_result_type(source, expression, depth - 1)
                .map_or(Interior::Unknown, |ty| {
                    self.guard_type_ref_interior(&ty, depth - 1)
                }),
            _ => Interior::Unknown,
        }
    }

    fn guard_syntax_interior(&self, source: &RustSource, ty: Node<'_>, depth: usize) -> Interior {
        if depth == 0 || ty.has_error() {
            return Interior::Unknown;
        }
        match ty.kind() {
            // This follows the payload; &Cell<T> must not become Absent simply
            // because the outer reference has no drop glue or is Copy.
            "reference_type" => ty
                .child_by_field_name("type")
                .map_or(Interior::Unknown, |inner| {
                    self.guard_syntax_interior(source, inner, depth - 1)
                }),
            "tuple_type" => combine(
                named_children(ty)
                    .into_iter()
                    .map(|inner| self.guard_syntax_interior(source, inner, depth - 1)),
            ),
            "array_type" => ty
                .child_by_field_name("element")
                .map_or(Interior::Unknown, |inner| {
                    self.guard_syntax_interior(source, inner, depth - 1)
                }),
            "unit_type" | "never_type" | "function_type" => Interior::Absent,
            // Shared access to a raw pointer still permits mutation of its
            // pointee. It cannot certify a stable guarded value.
            "pointer_type" => Interior::Unknown,
            "type_identifier" | "scoped_type_identifier"
                if ty.child_by_field_name("type_arguments").is_none() =>
            {
                if let Some(unit) = self.workspace_definition(source, ty) {
                    return self.guard_source_aggregate_interior(&unit, depth - 1);
                }
                self.guard_modeled_syntax_interior(source, ty, depth - 1)
            }
            "primitive_type" => {
                let Some(spelling) = source.node_text(ty) else {
                    return Interior::Unknown;
                };
                if !matches!(
                    spelling,
                    "bool"
                        | "char"
                        | "str"
                        | "i8"
                        | "i16"
                        | "i32"
                        | "i64"
                        | "i128"
                        | "isize"
                        | "u8"
                        | "u16"
                        | "u32"
                        | "u64"
                        | "u128"
                        | "usize"
                        | "f16"
                        | "f32"
                        | "f64"
                        | "f128"
                ) {
                    return Interior::Unknown;
                }
                if let Some(unit) = self.workspace_definition(source, ty) {
                    return self.guard_source_aggregate_interior(&unit, depth - 1);
                }
                if self.prelude_name_is_unbound(source, ty.start_byte(), spelling, "type") {
                    Interior::Absent
                } else {
                    Interior::Unknown
                }
            }
            "generic_type" => self.guard_modeled_syntax_interior(source, ty, depth - 1),
            _ => Interior::Unknown,
        }
    }

    fn guard_modeled_syntax_interior(
        &self,
        source: &RustSource,
        ty: Node<'_>,
        depth: usize,
    ) -> Interior {
        let Some(overlay) = self.analyzer.semantic_model_overlay() else {
            return Interior::Unknown;
        };
        let Some(active) = self.analyzer.active_semantic_models() else {
            return Interior::Unknown;
        };
        let mut applicability = super::super::trait_applicability::ModelApplicability::new(
            self.analyzer,
            self.rust,
            &overlay,
            &active,
            &self.resolver,
        );
        let selected = applicability.receiver_type(&source.file, source.text(), ty);
        selected.map_or(Interior::Unknown, |ty| {
            self.guard_type_ref_interior(&ty, depth)
        })
    }

    fn guard_source_aggregate_interior(&self, unit: &CodeUnit, depth: usize) -> Interior {
        if depth == 0 {
            return Interior::Unknown;
        }
        let cancellation = self
            .analyzer
            .active_query_cancellation()
            .unwrap_or_default();
        self.with_guard_aggregate_fields(unit, &cancellation, |source, fields| {
            combine(
                fields
                    .iter()
                    .map(|ty| self.guard_syntax_interior(source, *ty, depth - 1)),
            )
        })
        .unwrap_or(Interior::Unknown)
    }

    fn with_guard_aggregate_fields<T>(
        &self,
        unit: &CodeUnit,
        cancellation: &CancellationToken,
        inspect: impl FnOnce(&RustSource, &[Node<'_>]) -> T,
    ) -> Option<T> {
        let source = self.source(unit.source())?;
        let item = self.declaration(&source, unit)?;
        if !matches!(item.kind(), "struct_item" | "enum_item" | "union_item")
            || item.child_by_field_name("type_parameters").is_some()
            || item_or_enclosing_item_attributed(item)
            || item.has_error()
        {
            return None;
        }
        let Some(body) = item.child_by_field_name("body") else {
            return if item.kind() == "struct_item" {
                Some(inspect(&source, &[]))
            } else {
                None
            };
        };
        let mut fields = Vec::new();
        let mut pending = vec![body];
        while let Some(node) = pending.pop() {
            if cancellation.is_cancelled() {
                return None;
            }
            match node.kind() {
                "field_declaration" => {
                    fields.push(node.child_by_field_name("type")?);
                }
                "ordered_field_declaration_list" => fields.extend(
                    named_children(node)
                        .into_iter()
                        .filter(|child| child.kind() != "visibility_modifier"),
                ),
                "field_declaration_list" | "enum_variant_list" | "enum_variant" => {
                    pending.extend(named_children(node))
                }
                "identifier" | "type_identifier" | "visibility_modifier" | "integer_literal" => {}
                // Macro-produced, attributed or unavailable field surfaces are
                // not an exhaustive absence certificate.
                _ => return None,
            }
        }
        Some(inspect(&source, &fields))
    }

    fn guard_argument_syntax_nonmutating(
        &self,
        source: &RustSource,
        ty: Node<'_>,
        depth: usize,
    ) -> Result<(), GuardBindingReason> {
        if depth == 0 || ty.has_error() {
            return Err(GuardBindingReason::UnknownBorrow);
        }
        match ty.kind() {
            "reference_type" => {
                if named_children(ty)
                    .iter()
                    .any(|child| child.kind() == "mutable_specifier")
                {
                    return Err(GuardBindingReason::MutableBorrow);
                }
                let referent = ty
                    .child_by_field_name("type")
                    .ok_or(GuardBindingReason::UnknownBorrow)?;
                match self.guard_syntax_interior(source, referent, depth - 1) {
                    Interior::Absent => Ok(()),
                    Interior::Present => Err(GuardBindingReason::InteriorMutabilityPresent),
                    Interior::Unknown => Err(GuardBindingReason::InteriorMutabilityUnknown),
                }
            }
            "pointer_type" => Err(GuardBindingReason::RawAlias),
            "primitive_type" => match self.guard_syntax_interior(source, ty, depth - 1) {
                Interior::Absent => Ok(()),
                _ => Err(GuardBindingReason::UnknownBorrow),
            },
            "unit_type" | "never_type" | "function_type" => Ok(()),
            "tuple_type" => named_children(ty).into_iter().try_for_each(|inner| {
                self.guard_argument_syntax_nonmutating(source, inner, depth - 1)
            }),
            "array_type" => self.guard_argument_syntax_nonmutating(
                source,
                ty.child_by_field_name("element")
                    .ok_or(GuardBindingReason::UnknownBorrow)?,
                depth - 1,
            ),
            "type_identifier" | "scoped_type_identifier" => {
                let unit = self
                    .workspace_definition(source, ty)
                    .ok_or(GuardBindingReason::UnknownBorrow)?;
                let cancellation = self
                    .analyzer
                    .active_query_cancellation()
                    .unwrap_or_default();
                self.with_guard_aggregate_fields(&unit, &cancellation, |source, fields| {
                    fields.iter().try_for_each(|ty| {
                        self.guard_argument_syntax_nonmutating(source, *ty, depth - 1)
                    })
                })
                .unwrap_or(Err(GuardBindingReason::UnknownBorrow))
            }
            // Aliases, generic substitutions and unavailable payloads do not
            // certify that by-value access cannot carry a mutable capability.
            _ => Err(GuardBindingReason::UnknownBorrow),
        }
    }

    pub(super) fn guard_type_ref_interior(&self, ty: &TypeRef, depth: usize) -> Interior {
        if depth == 0 {
            return Interior::Unknown;
        }
        match ty {
            TypeRef::Pointer { .. } => Interior::Unknown,
            TypeRef::ByRef { element, .. } | TypeRef::Array { element } => {
                self.guard_type_ref_interior(element, depth - 1)
            }
            TypeRef::Tuple { elements } => combine(
                elements
                    .iter()
                    .map(|ty| self.guard_type_ref_interior(ty, depth - 1)),
            ),
            TypeRef::Named {
                name, arguments, ..
            } => {
                let primitive = name
                    .strip_prefix("core.primitive.")
                    .or_else(|| name.strip_prefix("std.primitive."))
                    .unwrap_or(name);
                if arguments.is_empty()
                    && matches!(
                        primitive,
                        "bool"
                            | "char"
                            | "str"
                            | "i8"
                            | "i16"
                            | "i32"
                            | "i64"
                            | "i128"
                            | "isize"
                            | "u8"
                            | "u16"
                            | "u32"
                            | "u64"
                            | "u128"
                            | "usize"
                            | "f16"
                            | "f32"
                            | "f64"
                            | "f128"
                    )
                {
                    return Interior::Absent;
                }
                let Some(overlay) = self.analyzer.semantic_model_overlay() else {
                    return Interior::Unknown;
                };
                let Some(symbol) = overlay
                    .symbols_named_in_family(name, "rust", SemanticModelNamespace::TypeOrModule)
                    .unique()
                else {
                    return Interior::Unknown;
                };
                self.guard_model_claim_interior(&symbol, arguments, depth - 1)
            }
            TypeRef::Declared { id, arguments, .. } => {
                let Some(overlay) = self.analyzer.semantic_model_overlay() else {
                    return Interior::Unknown;
                };
                let Some(symbol) = overlay.symbols_with_id_in_family(id, "rust").unique() else {
                    return Interior::Unknown;
                };
                self.guard_model_claim_interior(&symbol, arguments, depth - 1)
            }
            _ => Interior::Unknown,
        }
    }

    fn guard_model_claim_interior(
        &self,
        symbol: &SemanticModelSymbol,
        arguments: &[TypeRef],
        depth: usize,
    ) -> Interior {
        if depth == 0 || symbol.provenance.ambiguous {
            return Interior::Unknown;
        }
        let Some(active) = self.analyzer.active_semantic_models() else {
            return Interior::Unknown;
        };
        let Some(declaration) =
            brokk_bifrost_analysis::analyzer::semantic_model::overlay::owner_declaration(
                &active, symbol,
            )
        else {
            return Interior::Unknown;
        };
        let claim = declaration
            .value_semantics
            .as_ref()
            .and_then(|semantics| semantics.interior_mutability.as_ref());
        match claim {
            Some(TypeInteriorMutability::Absent) => Interior::Absent,
            Some(TypeInteriorMutability::Present) => Interior::Present,
            Some(TypeInteriorMutability::DependsOnTypeArguments { which }) => {
                combine(which.iter().map(|index| {
                    let index = *index as usize;
                    if declaration.type_parameter_kind(index) != GenericParameterKind::Type {
                        return Interior::Unknown;
                    }
                    arguments
                        .get(index)
                        .or_else(|| {
                            match declaration.type_parameter_defaults.get(index)?.as_ref()? {
                                GenericParameterDefault::Type { r#type } => Some(r#type),
                                _ => None,
                            }
                        })
                        .map_or(Interior::Unknown, |ty| {
                            self.guard_type_ref_interior(ty, depth - 1)
                        })
                }))
            }
            None => Interior::Unknown,
        }
    }
}
