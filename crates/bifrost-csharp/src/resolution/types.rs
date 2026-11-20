//! ECMA-334 8.2: file-local declared type syntax, without value inference.
use super::*;

impl Producer<'_, '_> {
    /// The source application carries its own positional formals, without
    /// fabricating a same-name reference or a callable result.
    pub(super) fn owner_application(
        &mut self,
        node: Node<'_>,
        owner: ResolutionSiteId,
        ctx: Context,
    ) {
        if node.kind() == "delegate_declaration" {
            return;
        }
        let list = first_named_child_of_kind(node, "type_parameter_list");
        let parameters = list
            .map(named_children)
            .unwrap_or_default()
            .into_iter()
            .filter(|parameter| !parameter.is_extra())
            .collect::<Vec<_>>();
        if list.is_some_and(|list| list.has_error())
            || parameters.iter().any(|parameter| {
                parameter.kind() != "type_parameter"
                    || self.is_excluded(*parameter)
                    || parameter.child_by_field_name("name").is_none()
            })
        {
            self.facts
                .add_gap(owner, ResolutionGapKind::UnsupportedTypeSyntax);
            return;
        }
        let application = (!ctx.unsupported_enclosing_application).then(|| {
            self.facts
                .allocate_type_slot(owner, ResolutionTypeSlotRole::TargetTypeIdentity)
        });
        let formal_start = self.facts.generic_formals.len();
        let argument_start = self.facts.type_arguments.len();
        let parameter_count = parameters.len();
        for (ordinal, parameter) in parameters.into_iter().enumerate() {
            let name = parameter
                .child_by_field_name("name")
                .expect("checked parameter name");
            let declaration = self.declare(
                parameter,
                name,
                Context {
                    scope: ctx.type_parameters.expect("own formal scope"),
                    ..ctx
                },
                ResolutionSiteKind::TypeDeclaration,
                ResolutionNamespace::Type,
                ResolutionBinderKind::Type,
            );
            self.claimed.insert(parameter.id());
            let identity = self
                .facts
                .allocate_type_slot(declaration, ResolutionTypeSlotRole::TargetTypeIdentity);
            self.facts
                .declaration_type_slots
                .push(DeclarationTypeSlotFact {
                    declaration,
                    slot: identity,
                    role: DeclarationTypeRole::Identity,
                });
            // Bounds describe possible members, never a concrete replacement for T.
            self.facts
                .add_gap(declaration, ResolutionGapKind::InferredType);
            let ordinal = u32::try_from(ordinal).expect("formal ordinal fits u32");
            self.facts
                .generic_formals
                .push(ResolutionGenericFormalFact {
                    owner,
                    ordinal,
                    parameter: declaration,
                });
            if let Some(application) = application {
                self.facts.type_arguments.push(ResolutionTypeArgumentFact {
                    application,
                    ordinal,
                    argument: identity,
                    indirection_delta: 0,
                    reference_indirection_delta: 0,
                });
            }
        }
        assert_eq!(
            self.facts.generic_formals.len() - formal_start,
            parameter_count
        );
        let Some(application) = application else {
            return;
        };
        assert_eq!(
            self.facts.type_arguments.len() - argument_start,
            parameter_count
        );
        // This affirmative property is published only with the complete dense
        // formal/application inventory, including proven zero arity.
        self.facts
            .declaration_type_slots
            .push(DeclarationTypeSlotFact {
                declaration: owner,
                slot: application,
                role: DeclarationTypeRole::NominalIdentity,
            });
        if !csharp_has_modifier(self.source, node, "partial")
            && !csharp_has_modifier(self.source, node, "static")
        {
            self.owner_applications.insert(owner, application);
        }
    }

    pub(super) fn root_candidate(
        &mut self,
        node: Node<'_>,
        definition: ResolutionSiteId,
        ctx: Context,
    ) {
        use brokk_bifrost_core::analyzer::model::ClassLikeKind;
        self.facts
            .declaration_modifiers
            .push(ResolutionDeclarationModifierFact {
                definition,
                partial: csharp_has_modifier(self.source, node, "partial"),
            });
        if node.kind() == "delegate_declaration" {
            self.facts
                .add_gap(definition, ResolutionGapKind::UnsupportedHierarchyTraversal);
            return;
        }
        let terminal = match crate::syntax::csharp_nominal_kind(node) {
            ClassLikeKind::Class | ClassLikeKind::Interface => "Object",
            ClassLikeKind::Struct => "ValueType",
            ClassLikeKind::Enum => "Enum",
        };
        let reference = self.site(node, ctx.scope, ResolutionSiteKind::SyntheticReference);
        let name = self
            .facts
            .intern_name(&mut self.names, terminal)
            .expect("static non-empty literal");
        let system = self
            .facts
            .intern_name(&mut self.names, "System")
            .expect("static non-empty literal");
        let frontier = publish_absolute_synthetic_type_reference(
            &mut self.facts,
            definition,
            reference,
            name,
            &[system],
        );
        self.facts
            .implicit_root_candidates
            .push(ResolutionImplicitRootCandidateFact {
                definition,
                reference,
                frontier,
            });
    }

    pub(super) fn authored_parents(
        &mut self,
        node: Node<'_>,
        subtype: ResolutionSiteId,
        ctx: Context,
    ) {
        let Some(list) = first_named_child_of_kind(node, "base_list") else {
            return;
        };
        // Enum storage types are not nominal parents. Claim them so the
        // ordinary name walk cannot reinterpret the underlying type.
        if node.kind() == "enum_declaration" {
            self.claim_tree(list);
            return;
        }
        let kind = match crate::syntax::csharp_nominal_kind(node) {
            brokk_bifrost_core::analyzer::model::ClassLikeKind::Class => {
                ResolutionSupertypeKind::AuthoredNominalParent
            }
            brokk_bifrost_core::analyzer::model::ClassLikeKind::Struct
            | brokk_bifrost_core::analyzer::model::ClassLikeKind::Interface => {
                ResolutionSupertypeKind::Interface
            }
            _ => return,
        };
        for (ordinal, parent) in named_children(list)
            .into_iter()
            .filter(|child| !child.is_extra() && child.kind() != "argument_list")
            .enumerate()
        {
            let type_node = if parent.kind() == "primary_constructor_base_type" {
                parent
                    .child_by_field_name("type")
                    .expect("primary constructor base has a type")
            } else {
                parent
            };
            let (slot, reference) = self.declared_type_with_reference(type_node, ctx);
            let Some(reference) = reference else {
                continue; // declared_type already records unsupported syntax.
            };
            debug_assert_eq!(ctx.owner, Some(subtype));
            self.facts.supertypes.push(ResolutionSupertypeFact {
                subtype,
                parent_ordinal: u32::try_from(ordinal).expect("base ordinal fits u32"),
                supertype_reference: reference,
                supertype_slot: slot,
                kind,
            });
        }
    }

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
        self.declared_type_with_reference(root, ctx).0
    }

    fn declared_type_with_reference(
        &mut self,
        root: Node<'_>,
        ctx: Context,
    ) -> (ResolutionTypeSlotId, Option<ResolutionSiteId>) {
        // A shared declaration head (Item first, second) is one written
        // type occurrence, with a separate declared-value slot per binder.
        if let Some(&slot) = self.declared_types.get(&(root.id(), ctx.scope)) {
            return slot;
        }
        let projection_start = self.facts.binding_projections.len();
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
                            let name = self
                                .facts
                                .intern_name(&mut self.names, part)
                                .expect("static non-empty literal");
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
                    // An alias-qualified path's first part is the alias, which
                    // `reference_path` keeps as a route segment, not a reference.
                    let alias = usize::from(
                        Self::path_anchor(node, self.source)
                            == ResolutionRootImportAnchor::AliasQualified,
                    );
                    let parts = self.path(node);
                    if parts
                        .as_ref()
                        .is_some_and(|parts| parts.len() != references.len() + alias)
                    {
                        // A MISSING part (`A. f`) has no name, so `reference` left a
                        // gap and no identifier for it. The last identifier then names
                        // an earlier part, and projecting it would give `f` type `A`.
                        self.facts.add_gap(site, ResolutionGapKind::MalformedSyntax);
                    } else if let Some(&terminal) = references.last() {
                        let reference = terminal;
                        self.facts.binding_projections.push(BindingProjectionFact {
                            reference,
                            output,
                            kind: BindingProjectionKind::TargetTypeIdentity,
                        });
                        if let Some(parts) = parts {
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
                            let name = self
                                .facts
                                .intern_name(&mut self.names, "structural-type")
                                .expect("static non-empty literal");
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
        // Search only this written type's projections, then retain the pair
        // so a reused syntax slot never scans unrelated file facts.
        let reference = self.facts.binding_projections[projection_start..]
            .iter()
            .find(|projection| {
                projection.output == output
                    && projection.kind == BindingProjectionKind::TargetTypeIdentity
            })
            .map(|projection| projection.reference);
        let result = (output, reference);
        self.declared_types.insert((root.id(), ctx.scope), result);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authored_parent_grammar_retains_record_struct_and_generic_bases() {
        let source = "record struct S : I<int>; record R : N.B<int>, I<int>; enum E : byte { A } class C(int x) : B<int>(x) {}";
        let tree = crate::test_support::parse_raw_csharp(source);
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        let declarations = named_children(tree.root_node());
        assert_eq!(
            declarations
                .iter()
                .map(|node| node.kind())
                .collect::<Vec<_>>(),
            [
                "record_declaration",
                "record_declaration",
                "enum_declaration",
                "class_declaration"
            ]
        );
        let mut cursor = declarations[0].walk();
        assert!(
            declarations[0]
                .children(&mut cursor)
                .any(|node| node.kind() == "struct")
        );
        assert_eq!(
            declarations[0].child_by_field_name("name").unwrap().kind(),
            "identifier"
        );
        let bases = first_named_child_of_kind(declarations[1], "base_list").unwrap();
        let parents = named_children(bases);
        assert_eq!(
            parents.iter().map(|node| node.kind()).collect::<Vec<_>>(),
            ["qualified_name", "generic_name"]
        );
        assert_eq!(
            parents[0].child_by_field_name("name").unwrap().kind(),
            "generic_name"
        );
        assert!(first_named_child_of_kind(parents[1], "type_argument_list").is_some());
        let underlying = first_named_child_of_kind(declarations[2], "base_list").unwrap();
        assert_eq!(named_children(underlying)[0].kind(), "predefined_type");
        let primary = first_named_child_of_kind(declarations[3], "base_list").unwrap();
        let children = named_children(primary);
        assert_eq!(
            children.iter().map(|node| node.kind()).collect::<Vec<_>>(),
            ["generic_name", "argument_list"]
        );
    }
}
