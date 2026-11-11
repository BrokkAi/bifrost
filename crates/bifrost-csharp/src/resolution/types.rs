//! ECMA-334 8.2: file-local declared type syntax, without value inference.
use super::*;

impl Producer<'_, '_> {
    pub(super) fn attach_declared_type(
        &mut self,
        declaration: ResolutionSiteId,
        input: ResolutionTypeSlotId,
        node: Node<'_>,
        role: DeclarationTypeRole,
    ) -> ResolutionTypeSlotId {
        let output = self
            .facts
            .allocate_type_slot(declaration, ResolutionTypeSlotRole::DeclaredValue);
        self.facts
            .declaration_type_slots
            .push(DeclarationTypeSlotFact {
                declaration,
                slot: output,
                role,
            });
        let transform = if node.kind() == "predefined_type"
            && csharp_identifier_text(node, self.source) == "void"
        {
            ResolutionTypeTransferValueTransform::ToNoValue
        } else {
            ResolutionTypeTransferValueTransform::ToRuntime { addressable: false }
        };
        self.facts
            .type_transfers
            .push(ResolutionTypeTransferFact::new(
                input,
                output,
                ResolutionTypeTransferKind::DeclaredType,
                0,
                0,
                transform,
            ));
        output
    }

    pub(super) fn declared_type(&mut self, root: Node<'_>, ctx: Context) -> ResolutionTypeSlotId {
        // A shared declaration head (Item first, second) is one written
        // type occurrence, with a separate declared-value slot per binder.
        if let Some(&slot) = self.declared_types.get(&(root.id(), ctx.scope)) {
            return slot;
        }
        // Explicit postorder keeps deeply nested type syntax off the Rust stack.
        let mut pending = vec![(root, false)];
        let mut slots = HashMap::default();
        while let Some((node, visited)) = pending.pop() {
            if !visited {
                pending.push((node, true));
                match node.kind() {
                    "array_type" => {
                        if let Some(element) = node.child_by_field_name("type") {
                            pending.push((element, false));
                        }
                    }
                    "generic_name" | "qualified_name" | "alias_qualified_name" => {
                        if let Some(parts) = self.path(node) {
                            for part in parts {
                                if let Some(arguments) =
                                    first_named_child_of_kind(part, "type_argument_list")
                                {
                                    pending.extend(
                                        crate::syntax::map_csharp_type_arguments(
                                            Some(arguments),
                                            Some,
                                        )
                                        .expect("argument list exists")
                                        .into_iter()
                                        .map(|argument| (argument, false)),
                                    );
                                }
                            }
                        }
                    }
                    _ => {}
                }
                continue;
            }
            let site = self.site(node, ctx.scope, ResolutionSiteKind::TypeReference);
            let output = self
                .facts
                .allocate_type_slot(site, ResolutionTypeSlotRole::TargetTypeIdentity);
            slots.insert(node.id(), output);
            match node.kind() {
                "identifier"
                    if matches!(
                        brokk_bifrost_core::analyzer::common::node_source_text(node, self.source,),
                        "dynamic" | "nint" | "nuint"
                    ) =>
                {
                    self.facts
                        .add_gap(site, ResolutionGapKind::UnsupportedTypeSyntax);
                }
                "predefined_type" => {
                    let keyword = csharp_identifier_text(node, self.source);
                    if let Some(&(_, system_type)) = crate::syntax::CSHARP_PREDEFINED_SYSTEM_TYPES
                        .iter()
                        .find(|&&(keyword_name, _)| keyword_name == keyword)
                    {
                        let mut names = Vec::new();
                        for part in ["System", system_type] {
                            let reference =
                                self.site(node, ctx.scope, ResolutionSiteKind::TypeReference);
                            let name = self.facts.intern_name(&mut self.names, part);
                            self.facts.identifiers.push(PositionedIdentifierFact {
                                site: reference,
                                name,
                                role: ResolutionIdentifierRole::Reference,
                                namespace: ResolutionNamespace::Type,
                                qualifier: None,
                            });
                            self.rooted_type_path_reference(
                                reference,
                                ctx.package,
                                ResolutionRootImportAnchor::Absolute,
                                None,
                                &names,
                            );
                            names.push(name);
                            if part == system_type {
                                self.facts.binding_projections.push(BindingProjectionFact {
                                    reference,
                                    output,
                                    kind: BindingProjectionKind::TargetTypeIdentity,
                                });
                            }
                        }
                    } else if keyword != "void" {
                        self.facts
                            .add_gap(site, ResolutionGapKind::UnsupportedTypeSyntax);
                    }
                }
                "identifier" | "generic_name" | "qualified_name" | "alias_qualified_name" => {
                    let before = self.facts.identifiers.len();
                    self.reference_path(node, ctx);
                    let references = self.facts.identifiers[before..]
                        .iter()
                        .map(|identifier| identifier.site)
                        .collect::<Vec<_>>();
                    if let Some(&terminal) = references.last() {
                        let reference = terminal;
                        self.facts.binding_projections.push(BindingProjectionFact {
                            reference,
                            output,
                            kind: BindingProjectionKind::TargetTypeIdentity,
                        });
                        if let Some(parts) = self.path(node) {
                            // An alias-qualified path's first part is the alias, which
                            // `reference_path` keeps as a route segment, not a reference.
                            let alias = usize::from(
                                Self::path_anchor(node, self.source)
                                    == ResolutionRootImportAnchor::AliasQualified,
                            );
                            debug_assert_eq!(parts.len(), references.len() + alias);
                            for (part, reference) in parts.into_iter().skip(alias).zip(references) {
                                let Some(arguments) =
                                    first_named_child_of_kind(part, "type_argument_list")
                                else {
                                    continue;
                                };
                                let application = if reference == terminal {
                                    output
                                } else {
                                    let slot = self.facts.allocate_type_slot(
                                        reference,
                                        ResolutionTypeSlotRole::TargetTypeIdentity,
                                    );
                                    self.facts.binding_projections.push(BindingProjectionFact {
                                        reference,
                                        output: slot,
                                        kind: BindingProjectionKind::TargetTypeIdentity,
                                    });
                                    slot
                                };
                                for (ordinal, argument) in
                                    crate::syntax::map_csharp_type_arguments(Some(arguments), Some)
                                        .expect("argument list exists")
                                        .into_iter()
                                        .enumerate()
                                {
                                    let argument = slots[&argument.id()];
                                    self.facts.declared_type_arguments.push(
                                        ResolutionDeclaredTypeArgumentFact {
                                            owner: application,
                                            ordinal: dense_ordinal(ordinal, "C# type argument"),
                                            argument,
                                        },
                                    );
                                    self.facts.type_arguments.push(ResolutionTypeArgumentFact {
                                        application,
                                        ordinal: dense_ordinal(ordinal, "C# type argument"),
                                        argument,
                                        indirection_delta: 0,
                                        reference_indirection_delta: 0,
                                    });
                                }
                            }
                        }
                    } else {
                        self.facts
                            .add_gap(site, ResolutionGapKind::UnsupportedTypeSyntax);
                    }
                }
                "array_type" => {
                    let ranks = named_children(node)
                        .into_iter()
                        .filter(|child| child.kind() == "array_rank_specifier")
                        .collect::<Vec<_>>();
                    let rectangular = ranks.iter().any(|rank| {
                        let mut cursor = rank.walk();
                        rank.children(&mut cursor).any(|child| child.kind() == ",")
                    });
                    if rectangular || ranks.is_empty() || node.child_by_field_name("type").is_none()
                    {
                        self.facts
                            .add_gap(site, ResolutionGapKind::UnsupportedTypeSyntax);
                    } else {
                        let mut element = slots[&node.child_by_field_name("type").unwrap().id()];
                        for index in 0..ranks.len() {
                            let container = if index + 1 == ranks.len() {
                                output
                            } else {
                                self.facts.allocate_type_slot(
                                    site,
                                    ResolutionTypeSlotRole::TargetTypeIdentity,
                                )
                            };
                            let name = self.facts.intern_name(&mut self.names, "structural-type");
                            self.facts.intrinsic_type_seeds.push(IntrinsicTypeSeedFact {
                                output: container,
                                name,
                                kind: IntrinsicTypeKind::Structural,
                                indirection: 0,
                            });
                            self.facts
                                .type_components
                                .push(ResolutionTypeComponentFact {
                                    container,
                                    constructor: ResolutionTypeConstructorKind::Sequence,
                                    kind: ResolutionTypeComponentKind::Element,
                                    component: element,
                                });
                            element = container;
                        }
                    }
                }
                _ => self
                    .facts
                    .add_gap(site, ResolutionGapKind::UnsupportedTypeSyntax),
            }
            if self.facts.gaps.last().is_some_and(|gap| {
                gap.site == site && gap.kind == ResolutionGapKind::UnsupportedTypeSyntax
            }) {
                // The type slot is open, and claiming its syntax also omits
                // nested name occurrences. Never certify their enumeration.
                self.facts
                    .add_reference_enumeration_gap(site, ResolutionGapKind::UnsupportedTypeSyntax);
            }
        }
        self.claim_tree(root);
        let output = slots[&root.id()];
        self.declared_types.insert((root.id(), ctx.scope), output);
        output
    }
}
