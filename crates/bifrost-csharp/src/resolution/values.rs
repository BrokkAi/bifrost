//! ECMA-334 12.19, 12.21 and 13.6: observed values and inferred locals.
use super::*;

impl Producer<'_, '_> {
    pub(super) fn value_reference(&mut self, node: Node<'_>, ctx: Context) -> ResolutionSiteId {
        self.reference(node, ctx, ResolutionNamespace::Value)
    }

    pub(super) fn initialize_value(
        &mut self,
        node: Node<'_>,
        declaration: ResolutionSiteId,
        ctx: Context,
    ) {
        let Some(value) = crate::syntax::variable_declarator_initializer(node) else {
            return;
        };
        let input = self.expression_value(value, ctx);
        let output = self
            .facts
            .allocate_type_slot(declaration, ResolutionTypeSlotRole::AssignmentValue);
        self.transfer_value(input, output, ResolutionTypeTransferKind::Assignment);
        if node
            .parent()
            .and_then(|parent| parent.child_by_field_name("type"))
            .is_some_and(|ty| ty.kind() == "implicit_type")
        {
            let output = self
                .facts
                .allocate_type_slot(declaration, ResolutionTypeSlotRole::DeclaredValue);
            self.facts
                .declaration_type_slots
                .push(DeclarationTypeSlotFact {
                    declaration,
                    slot: output,
                    role: DeclarationTypeRole::Value,
                });
            // ECMA-334 12.18: the runtime union is not the static type.
            // M6d decides branch conversions, including the equal-type case.
            let mut initializer = value;
            while initializer.kind() == "parenthesized_expression" {
                let Some(inner) = named_children(initializer)
                    .into_iter()
                    .find(|child| !child.is_extra())
                else {
                    break;
                };
                initializer = inner;
            }
            if initializer.kind() == "conditional_expression" {
                self.facts
                    .add_gap(declaration, ResolutionGapKind::InferredType);
                // The declared slot still has a producer: an expression slot
                // with no producer of its own, so its type stays unknown.
                // Leaving the slot unproduced would let the shared local-write
                // normalization fill it from later assignments, which never
                // decide the type of a C# implicitly typed local (ECMA-334).
                let unknown = self
                    .facts
                    .allocate_type_slot(declaration, ResolutionTypeSlotRole::ExpressionValue);
                self.transfer_value(unknown, output, ResolutionTypeTransferKind::Initialization);
            } else {
                self.transfer_value(input, output, ResolutionTypeTransferKind::Initialization);
            }
        }
    }

    fn transfer_value(
        &mut self,
        input: ResolutionTypeSlotId,
        output: ResolutionTypeSlotId,
        kind: ResolutionTypeTransferKind,
    ) {
        self.facts
            .type_transfers
            .push(ResolutionTypeTransferFact::new(
                input,
                output,
                kind,
                0,
                0,
                ResolutionTypeTransferValueTransform::Preserve,
            ));
    }

    pub(super) fn expression_value(
        &mut self,
        root: Node<'_>,
        ctx: Context,
    ) -> ResolutionTypeSlotId {
        let mut pending = vec![(root, false)];
        let mut slots = HashMap::default();
        while let Some((node, visited)) = pending.pop() {
            if matches!(
                node.kind(),
                "member_access_expression" | "parenthesized_expression"
            ) && let Some(output) = self.member_expression(node, ctx)
            {
                slots.insert(node.id(), output);
                continue;
            }
            let branches = match node.kind() {
                "conditional_expression" => vec![
                    node.child_by_field_name("consequence"),
                    node.child_by_field_name("alternative"),
                ],
                "parenthesized_expression" => vec![
                    named_children(node)
                        .into_iter()
                        .find(|child| !child.is_extra()),
                ],
                _ => Vec::new(),
            };
            if !visited && !branches.is_empty() {
                pending.push((node, true));
                pending.extend(branches.iter().flatten().map(|&child| (child, false)));
                continue;
            }
            let site = if node.kind() == "identifier" {
                self.value_reference(node, ctx)
            } else {
                self.site(
                    node,
                    ctx.scope,
                    if node.kind() == "conditional_expression" {
                        ResolutionSiteKind::ConditionalExpression
                    } else {
                        ResolutionSiteKind::UnsupportedExpression
                    },
                )
            };
            let output = self
                .facts
                .allocate_type_slot(site, ResolutionTypeSlotRole::ExpressionValue);
            slots.insert(node.id(), output);
            if !branches.is_empty() {
                for child in branches {
                    if let Some(child) = child {
                        self.transfer_value(
                            slots[&child.id()],
                            output,
                            ResolutionTypeTransferKind::ValueJoin,
                        );
                    } else {
                        self.facts
                            .add_gap(site, ResolutionGapKind::UnsupportedExpression);
                        self.facts.add_reference_enumeration_gap(
                            site,
                            ResolutionGapKind::UnsupportedExpression,
                        );
                    }
                }
            } else if node.kind() == "identifier" {
                self.facts.binding_projections.push(BindingProjectionFact {
                    reference: site,
                    output,
                    kind: BindingProjectionKind::TargetDeclaredValueType,
                });
            } else {
                self.facts
                    .add_gap(site, ResolutionGapKind::UnsupportedExpression);
                // This is a value-type limitation. The main syntax walk still
                // enumerates this expression and records any omitted references.
            }
        }
        slots[&root.id()]
    }
}
