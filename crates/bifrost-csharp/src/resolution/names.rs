use super::*;

pub(super) fn spelling(node: Node<'_>, source: &str) -> String {
    if node.kind() != "generic_name" {
        return crate::syntax::csharp_lookup_identifier(csharp_identifier_text(node, source));
    }
    let identity = crate::syntax::csharp_type_node_identity(node, source);
    let base = crate::syntax::strip_csharp_generic_arity(&identity);
    format!(
        "{}{}",
        crate::syntax::csharp_lookup_identifier(base),
        &identity[base.len()..]
    )
}

pub(super) fn declaration_spelling(node: Node<'_>, name: Node<'_>, source: &str) -> String {
    let arity = first_named_child_of_kind(node, "type_parameter_list")
        .map_or(0, crate::declarations::count_type_parameters);
    let name = crate::syntax::csharp_lookup_identifier(csharp_identifier_text(name, source));
    if arity == 0 {
        name
    } else {
        format!("{name}`{arity}")
    }
}

impl Producer<'_, '_> {
    /// Interpret path structure only; generic arguments are separate type syntax.
    pub(super) fn path<'t>(&self, node: Node<'t>) -> Option<Vec<Node<'t>>> {
        let mut stack = vec![node];
        let mut parts = Vec::new();
        while let Some(node) = stack.pop() {
            match node.kind() {
                "identifier" | "generic_name" => {
                    if self.is_excluded(node)
                        || node.is_missing()
                        || (node.kind() == "generic_name"
                            && first_named_child_of_kind(node, "identifier")
                                .is_none_or(|name| name.is_missing() || self.is_excluded(name)))
                    {
                        return None;
                    }
                    parts.push(node);
                }
                "qualified_name" | "member_access_expression" => {
                    let left = node
                        .child_by_field_name("qualifier")
                        .or_else(|| node.child_by_field_name("expression"))?;
                    let right = node.child_by_field_name("name")?;
                    stack.push(right);
                    stack.push(left);
                }
                "alias_qualified_name" => {
                    let alias = node.child_by_field_name("alias")?;
                    if crate::syntax::csharp_lookup_identifier(csharp_identifier_text(
                        alias,
                        self.source,
                    )) != "global"
                    {
                        stack.push(node.child_by_field_name("name")?);
                        stack.push(alias);
                    } else {
                        stack.push(node.child_by_field_name("name")?);
                    }
                }
                _ => return None,
            }
        }
        Some(parts)
    }

    pub(super) fn reference(
        &mut self,
        node: Node<'_>,
        ctx: Context,
        namespace: ResolutionNamespace,
    ) -> ResolutionSiteId {
        let kind = match namespace {
            ResolutionNamespace::Type => ResolutionSiteKind::TypeReference,
            ResolutionNamespace::Callable => ResolutionSiteKind::CallableReference,
            _ => ResolutionSiteKind::ValueReference,
        };
        let positioned = if node.kind() == "generic_name" {
            first_named_child_of_kind(node, "identifier")
                .expect("generic reference has a name token")
        } else {
            node
        };
        let site = self.site(positioned, ctx.scope, kind);
        let name = if namespace == ResolutionNamespace::Callable && node.kind() == "generic_name" {
            self.name(
                first_named_child_of_kind(node, "identifier").expect("generic callable has a name"),
            )
        } else {
            self.name(node)
        };
        if let Some(name) = name {
            self.facts.identifiers.push(PositionedIdentifierFact {
                site,
                name,
                role: ResolutionIdentifierRole::Reference,
                namespace,
                qualifier: None,
            });
            // Ownership is independent of lookup scope, including type headers.
            // A published None is affirmative outside-type source authority.
            self.facts
                .reference_owners
                .push(ResolutionReferenceOwnerFact {
                    reference: site,
                    owner: ctx.owner,
                });
        } else {
            self.facts.add_gap(site, ResolutionGapKind::MalformedSyntax);
        }
        self.claimed.insert(node.id());
        if node.kind() == "generic_name"
            && let Some(name) = first_named_child_of_kind(node, "identifier")
        {
            self.claimed.insert(name.id());
        }
        site
    }

    pub(super) fn path_anchor(node: Node<'_>, source: &str) -> ResolutionRootImportAnchor {
        let mut pending = vec![node];
        while let Some(node) = pending.pop() {
            if node.kind() == "alias_qualified_name" {
                let alias = node
                    .child_by_field_name("alias")
                    .expect("alias-qualified name has alias");
                return if crate::syntax::csharp_lookup_identifier(csharp_identifier_text(
                    alias, source,
                )) == "global"
                {
                    ResolutionRootImportAnchor::Absolute
                } else {
                    ResolutionRootImportAnchor::AliasQualified
                };
            }
            if node.kind() != "generic_name" {
                pending.extend(named_children(node));
            }
        }
        ResolutionRootImportAnchor::Lexical
    }

    // Accept interned path segments independently of source nodes: predefined
    // keyword aliases have one source token but a two-segment absolute path.
    pub(super) fn rooted_type_path_reference(
        &mut self,
        reference: ResolutionSiteId,
        root_scope: ResolutionScopeId,
        anchor: ResolutionRootImportAnchor,
        prefix_reference: Option<ResolutionSiteId>,
        names: &[ResolutionNameId],
    ) {
        self.facts
            .root_references
            .push(ResolutionRootReferenceFact {
                reference,
                root_scope,
                anchor,
                prefix_reference,
                owner_continued: false,
            });
        for (position, &name) in names.iter().enumerate() {
            self.facts
                .root_reference_segments
                .push(ResolutionRootReferenceSegmentFact {
                    reference,
                    position: dense_ordinal(position, "root reference segment"),
                    name,
                });
        }
    }

    /// Only member-access spines rooted in the already supported this/base
    /// receiver have an expression producer here. Parentheses preserve that
    /// exact output; arbitrary expression operands remain unsupported.
    pub(super) fn member_expression(
        &mut self,
        root: Node<'_>,
        ctx: Context,
    ) -> Option<ResolutionTypeSlotId> {
        let mut pending = Vec::new();
        let mut node = root;
        let mut input = loop {
            if let Some(&output) = self.member_expression_outputs.get(&node.id()) {
                break output;
            }
            if self.is_excluded(node) || node.is_missing() || node.has_error() {
                return None;
            }
            match node.kind() {
                "parenthesized_expression" => {
                    let children = named_children(node)
                        .into_iter()
                        .filter(|child| !child.is_extra())
                        .collect::<Vec<_>>();
                    let [inner] = children.as_slice() else {
                        return None;
                    };
                    pending.push(node);
                    node = *inner;
                }
                "member_access_expression" => {
                    let receiver = node.child_by_field_name("expression")?;
                    let name = node.child_by_field_name("name")?;
                    if name.is_missing() || self.is_excluded(name) {
                        return None;
                    }
                    if matches!(receiver.kind(), "this" | "base") {
                        break self.instance_member(node, ctx);
                    }
                    pending.push(node);
                    node = receiver;
                }
                _ => return None,
            }
        };
        while let Some(node) = pending.pop() {
            if node.kind() == "parenthesized_expression" {
                self.member_expression_outputs.insert(node.id(), input);
                continue;
            }
            let name = node
                .child_by_field_name("name")
                .expect("checked member name");
            let namespace = reference_namespace(node);
            let reference = self.reference(name, ctx, namespace);
            self.facts.sites[reference.index()].kind = ResolutionSiteKind::MemberReference;
            let receiver = self
                .facts
                .allocate_type_slot(reference, ResolutionTypeSlotRole::Receiver);
            self.facts
                .identifiers
                .last_mut()
                .expect("new member identifier")
                .qualifier = Some(receiver);
            self.facts
                .type_transfers
                .push(ResolutionTypeTransferFact::new(
                    input,
                    receiver,
                    ResolutionTypeTransferKind::Receiver,
                    0,
                    0,
                    ResolutionTypeTransferValueTransform::Preserve,
                ));
            input = self.member_projection(reference, namespace);
            self.facts
                .callable_receiver_origins
                .push(ResolutionCallableReceiverOriginFact {
                    reference,
                    origin: ResolutionCallableReceiverOrigin::ExplicitExpression,
                });
            // This qualifier is an actual published expression value, not a
            // lexical or namespace prefix. Its own uncertainty travels with it.
            self.facts.typed_receiver_prefix_absences.push(reference);
            self.member_expression_outputs.insert(node.id(), input);
            self.claimed.insert(node.id());
        }
        Some(input)
    }

    fn member_projection(
        &mut self,
        reference: ResolutionSiteId,
        namespace: ResolutionNamespace,
    ) -> ResolutionTypeSlotId {
        let (kind, role) = match namespace {
            ResolutionNamespace::Callable => (
                BindingProjectionKind::BindingOnlyMemberReference,
                ResolutionTypeSlotRole::ExpressionValue,
            ),
            ResolutionNamespace::Value => (
                BindingProjectionKind::TargetDeclaredValueType,
                ResolutionTypeSlotRole::ExpressionValue,
            ),
            ResolutionNamespace::TypeOrValue => (
                BindingProjectionKind::TargetTypeOrDeclaredValueType,
                ResolutionTypeSlotRole::ExpressionValue,
            ),
            ResolutionNamespace::Type => (
                BindingProjectionKind::TargetTypeIdentity,
                ResolutionTypeSlotRole::TargetTypeIdentity,
            ),
            _ => unreachable!("instance member namespace: {namespace:?}"),
        };
        let output = self.facts.allocate_type_slot(reference, role);
        self.facts.binding_projections.push(BindingProjectionFact {
            reference,
            output,
            kind,
        });
        output
    }

    // ECMA-334 (7th ed.) 12.8.13 and 12.8.14: instance access starts at the
    // enclosing type, independently of locals in the executable scope.
    fn instance_member(&mut self, node: Node<'_>, ctx: Context) -> ResolutionTypeSlotId {
        let receiver = node
            .child_by_field_name("expression")
            .expect("instance receiver");
        let name = node.child_by_field_name("name").expect("member name");
        let mut scope = ctx.scope;
        loop {
            let row = &self.facts.scopes[scope.index()];
            if row.kind == ResolutionScopeKind::TypeBody && row.owner == ctx.owner {
                break;
            }
            let Some(parent) = row.parent else { break };
            scope = parent;
        }
        let namespace = reference_namespace(node);
        let reference = self.reference(name, Context { scope, ..ctx }, namespace);
        let site = self.facts.sites.last_mut().expect("new member site");
        debug_assert_eq!(site.id, reference);
        site.kind = ResolutionSiteKind::MemberReference;

        let base = receiver.kind() == "base";
        // The exact owner seeds the receiver in selected evaluation. Keep
        // the qualifier and open gap until that evaluation proves its type.
        let slot = self
            .facts
            .allocate_type_slot(reference, ResolutionTypeSlotRole::Receiver);
        self.facts
            .identifiers
            .last_mut()
            .expect("member identifier")
            .qualifier = Some(slot);
        let output = self.member_projection(reference, namespace);
        self.facts
            .add_gap(reference, ResolutionGapKind::UnsupportedTypeSyntax);
        let mut invalid_static = false;
        let mut ancestor = node.parent();
        while let Some(parent) = ancestor {
            if matches!(
                parent.kind(),
                "class_declaration"
                    | "struct_declaration"
                    | "record_declaration"
                    | "record_struct_declaration"
                    | "interface_declaration"
            ) {
                break;
            }
            if csharp_has_modifier(self.source, parent, "static") {
                invalid_static = true;
                self.facts
                    .add_gap(reference, ResolutionGapKind::UnsupportedExpression);
                break;
            }
            ancestor = parent.parent();
        }
        if !base && ctx.unsupported_enclosing_application {
            // Scope uncertainty to this receiver, not the nested declaration.
            self.facts
                .add_gap(reference, ResolutionGapKind::UnsupportedImplicitReceiver);
        }
        if !base
            && !invalid_static
            && let Some(application) = ctx
                .owner
                .and_then(|owner| self.owner_applications.get(&owner))
                .copied()
        {
            self.facts
                .type_transfers
                .push(ResolutionTypeTransferFact::new(
                    application,
                    slot,
                    ResolutionTypeTransferKind::Receiver,
                    0,
                    0,
                    ResolutionTypeTransferValueTransform::ToRuntime { addressable: false },
                ));
        }
        self.facts
            .callable_receiver_origins
            .push(ResolutionCallableReceiverOriginFact {
                reference,
                origin: if base {
                    ResolutionCallableReceiverOrigin::Super
                } else {
                    ResolutionCallableReceiverOrigin::CurrentInstance
                },
            });
        self.claimed.insert(receiver.id());
        self.claimed.insert(node.id());
        self.member_expression_outputs.insert(node.id(), output);
        output
    }

    pub(super) fn reference_path(&mut self, node: Node<'_>, ctx: Context) {
        let Some(parts) = self.path(node) else {
            return;
        };
        if parts.is_empty() {
            return;
        }
        let namespace = reference_namespace(node);
        let anchor = Self::path_anchor(node, self.source);
        let absolute = anchor != ResolutionRootImportAnchor::Lexical;
        if parts.len() == 1 && !absolute {
            let reference = self.reference(parts[0], ctx, namespace);
            // ECMA-334 14.7: free namespace members supply types, not methods.
            if matches!(
                namespace,
                ResolutionNamespace::Type | ResolutionNamespace::TypeOrValue
            ) {
                if namespace == ResolutionNamespace::Type {
                    self.facts
                        .root_references
                        .push(ResolutionRootReferenceFact {
                            reference,
                            root_scope: ctx.scope,
                            anchor: ResolutionRootImportAnchor::Lexical,
                            prefix_reference: None,
                            owner_continued: false,
                        });
                }
                self.facts
                    .package_references
                    .push(ResolutionPackageReferenceFact {
                        reference,
                        root_scope: ctx.package,
                    });
            }
            return;
        }
        // Java's record_qualified_type_root (java/resolution.rs) keeps a lexical
        // head and rooted continuations, so namespace syntax never wins by case.
        let prefix = (!absolute).then(|| {
            self.reference(
                parts[0],
                ctx,
                if namespace == ResolutionNamespace::Type {
                    ResolutionNamespace::Type
                } else {
                    ResolutionNamespace::TypeOrValue
                },
            )
        });
        if let Some(reference) = prefix {
            if namespace == ResolutionNamespace::Type {
                self.facts
                    .root_references
                    .push(ResolutionRootReferenceFact {
                        reference,
                        root_scope: ctx.scope,
                        anchor: ResolutionRootImportAnchor::Lexical,
                        prefix_reference: None,
                        owner_continued: false,
                    });
            }
            if namespace != ResolutionNamespace::Type {
                self.facts
                    .add_gap(reference, ResolutionGapKind::AmbiguousQualifiedType);
            }
            self.facts
                .package_references
                .push(ResolutionPackageReferenceFact {
                    reference,
                    root_scope: ctx.package,
                });
        }
        let start = usize::from(prefix.is_some());
        for index in start.max(usize::from(
            anchor == ResolutionRootImportAnchor::AliasQualified,
        ))..parts.len()
        {
            let terminal_namespace = if index + 1 == parts.len() {
                namespace
            } else if namespace == ResolutionNamespace::Type {
                ResolutionNamespace::Type
            } else {
                ResolutionNamespace::TypeOrValue
            };
            let reference = self.reference(parts[index], ctx, terminal_namespace);
            if namespace != ResolutionNamespace::Type {
                self.facts
                    .add_gap(reference, ResolutionGapKind::AmbiguousQualifiedType);
            }
            let names = parts[..index]
                .iter()
                .map(|&part| self.name(part))
                .collect::<Option<Vec<_>>>();
            if let Some(names) = names {
                self.rooted_type_path_reference(reference, ctx.package, anchor, prefix, &names);
            } else {
                self.facts
                    .add_gap(reference, ResolutionGapKind::MalformedSyntax);
            }
        }
        // Claim only the path spine: type arguments must still be visited.
        let mut pending = vec![node];
        while let Some(n) = pending.pop() {
            self.claimed.insert(n.id());
            if n.kind() == "generic_name" {
                if let Some(name) = first_named_child_of_kind(n, "identifier") {
                    self.claimed.insert(name.id());
                }
            } else {
                pending.extend(named_children(n));
            }
        }
    }
}

fn reference_namespace(node: Node<'_>) -> ResolutionNamespace {
    if crate::syntax::csharp_type_reference_root(node).is_some() {
        return ResolutionNamespace::Type;
    }
    let mut child = node;
    while let Some(parent) = child.parent() {
        if parent.kind() == "invocation_expression"
            && parent
                .child_by_field_name("function")
                .is_some_and(|n| n.id() == child.id())
        {
            return ResolutionNamespace::Callable;
        }
        if matches!(
            parent.kind(),
            "qualified_name"
                | "alias_qualified_name"
                | "generic_name"
                | "nullable_type"
                | "array_type"
                | "pointer_type"
        ) {
            child = parent;
        } else {
            break;
        }
    }
    ResolutionNamespace::TypeOrValue
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#7314: expression-rooted C# member chains omitted the terminal reference"
    )]
    fn expression_member_grammar_links_real_outputs_once() {
        let source = "class C { C Self => this; void Identity() {} void Generic<U>() {} void Probe() { this.Self.Generic<C>(); this.Self.Identity(); (this.Self).Identity(); var value = this.Self; } static void Invalid() { this.Self.Identity(); } }";
        let tree = crate::test_support::parse_raw_csharp(source);
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        let mut pending = vec![tree.root_node()];
        let mut chains = Vec::new();
        while let Some(node) = pending.pop() {
            if node.kind() == "member_access_expression"
                && node.child_by_field_name("name").is_some_and(|name| {
                    matches!(name.kind(), "generic_name")
                        || csharp_identifier_text(name, source) == "Identity"
                })
            {
                let mut receiver = node.child_by_field_name("expression").unwrap();
                if receiver.kind() == "parenthesized_expression" {
                    receiver = named_children(receiver)
                        .into_iter()
                        .find(|child| !child.is_extra())
                        .unwrap();
                }
                assert_eq!(receiver.kind(), "member_access_expression");
                assert_eq!(
                    receiver.child_by_field_name("expression").unwrap().kind(),
                    "this"
                );
                chains.push((
                    {
                        let name = node.child_by_field_name("name").unwrap();
                        if name.kind() == "generic_name" {
                            named_children(name)[0]
                        } else {
                            name
                        }
                    },
                    receiver.child_by_field_name("name").unwrap(),
                ));
            }
            pending.extend(named_children(node));
        }
        assert_eq!(chains.len(), 4);
        let file =
            brokk_bifrost_core::analyzer::ProjectFile::new(std::env::temp_dir(), "Chains.cs");
        let facts = crate::declarations::parse_csharp_file_with_native_facts(
            &file,
            source,
            &tree,
            &crate::preprocessor::scan_preprocessor(source),
        )
        .resolution_facts;
        for (terminal, inner) in chains {
            let reference_at = |name: Node<'_>| {
                let rows = facts
                    .identifiers
                    .iter()
                    .filter(|row| {
                        row.role == ResolutionIdentifierRole::Reference
                            && facts.sites[row.site.index()].start_byte == name.start_byte()
                            && facts.sites[row.site.index()].end_byte == name.end_byte()
                    })
                    .collect::<Vec<_>>();
                assert_eq!(rows.len(), 1, "{}", csharp_identifier_text(name, source));
                rows[0]
            };
            let outer = reference_at(terminal);
            let inner = reference_at(inner);
            assert_eq!(
                facts.sites[outer.site.index()].kind,
                ResolutionSiteKind::MemberReference
            );
            let qualifier = outer.qualifier.expect("published expression receiver");
            let [projection] = facts
                .binding_projections
                .iter()
                .filter(|row| row.reference == inner.site)
                .collect::<Vec<_>>()[..]
            else {
                panic!("one inner property output");
            };
            let [transfer] = facts
                .type_transfers
                .iter()
                .filter(|row| row.output == qualifier)
                .collect::<Vec<_>>()[..]
            else {
                panic!("one receiver producer");
            };
            assert_eq!(transfer.input, projection.output);
            assert_eq!(transfer.kind, ResolutionTypeTransferKind::Receiver);
            assert_eq!(
                transfer.value_transform,
                ResolutionTypeTransferValueTransform::Preserve
            );
            assert!(
                facts
                    .binding_projections
                    .iter()
                    .any(|row| row.reference == outer.site
                        && row.kind == BindingProjectionKind::BindingOnlyMemberReference)
            );
            assert!(
                facts
                    .callable_receiver_origins
                    .iter()
                    .any(|row| row.reference == outer.site
                        && row.origin == ResolutionCallableReceiverOrigin::ExplicitExpression)
            );
            assert!(facts.typed_receiver_prefix_absences.contains(&outer.site));
            assert!(
                !facts
                    .root_references
                    .iter()
                    .any(|row| row.reference == outer.site)
            );
            assert_eq!(
                facts
                    .reference_owners
                    .iter()
                    .filter(|row| row.reference == outer.site)
                    .count(),
                1
            );
        }
        let argument = source.find("<C>").unwrap() + 1;
        assert_eq!(
            facts
                .identifiers
                .iter()
                .filter(|row| row.role == ResolutionIdentifierRole::Reference
                    && facts.sites[row.site.index()].start_byte == argument
                    && facts.sites[row.site.index()].end_byte == argument + 1)
                .count(),
            1,
            "outer generic argument is traversed once"
        );
        let static_member = facts
            .sites
            .iter()
            .find(|site| site.start_byte == source.rfind("Self.Identity").unwrap())
            .unwrap();
        assert!(facts.gaps.iter().any(|gap| gap.site == static_member.id
            && gap.kind == ResolutionGapKind::UnsupportedExpression));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#7314: ordinary qualified C# references lacked affirmative enclosing-type ownership"
    )]
    fn reference_owner_grammar_preserves_headers_and_instance_owner_rows() {
        let source = "class Base {} class Outer : Base { delegate void D(); Outer field; void Probe(Outer d) { Outer local = d; d.Probe(d); this.Probe(d); var action = () => { Outer captured = d; }; D other = delegate { Outer delegated = d; }; void Local(Outer argument) { Outer inner = argument; } } class Nested : Base { void N() { base.ToString(); } } }";
        let tree = crate::test_support::parse_raw_csharp(source);
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        let file =
            brokk_bifrost_core::analyzer::ProjectFile::new(std::env::temp_dir(), "Owners.cs");
        let parsed = crate::declarations::parse_csharp_file_with_native_facts(
            &file,
            source,
            &tree,
            &crate::preprocessor::scan_preprocessor(source),
        );
        let facts = parsed.resolution_facts;
        let type_site = |name: &str| {
            facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Declaration
                        && facts.sites[identifier.site.index()].kind
                            == ResolutionSiteKind::TypeDeclaration
                        && facts.names[identifier.name.index()].spelling == name
                })
                .expect("actual type declaration")
                .site
        };
        let outer = type_site("Outer");
        let nested = type_site("Nested");
        for (marker, offset, expected) in [
            ("d.Probe", 2, Some(outer)),
            ("this.Probe", 5, Some(outer)),
            ("base.ToString", 5, Some(nested)),
        ] {
            let start = source.find(marker).unwrap() + offset;
            let site = facts
                .sites
                .iter()
                .find(|site| {
                    site.start_byte == start
                        && facts.identifiers.iter().any(|identifier| {
                            identifier.site == site.id
                                && identifier.role == ResolutionIdentifierRole::Reference
                        })
                })
                .expect("actual positioned reference");
            let owners = facts
                .reference_owners
                .iter()
                .filter(|owner| owner.reference == site.id)
                .collect::<Vec<_>>();
            assert_eq!(
                owners,
                [&ResolutionReferenceOwnerFact {
                    reference: site.id,
                    owner: expected
                }],
                "{marker}"
            );
        }
        // Real annotations pass through declare(), including nested callable
        // bodies. They belong to the lexical type, never a fabricated Outside.
        for marker in [
            "Outer field",
            "Outer d",
            "Outer local",
            "Outer captured",
            "Outer delegated",
            "Outer argument",
            "Outer inner",
        ] {
            let start = source.find(marker).unwrap();
            let reference = facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Reference
                        && facts.sites[identifier.site.index()].start_byte == start
                        && facts.names[identifier.name.index()].spelling == "Outer"
                })
                .expect("actual annotation reference")
                .site;
            assert_eq!(
                facts
                    .reference_owners
                    .iter()
                    .filter(|row| row.reference == reference)
                    .collect::<Vec<_>>(),
                [&ResolutionReferenceOwnerFact {
                    reference,
                    owner: Some(outer)
                }],
                "{marker}"
            );
        }
        assert_eq!(facts.supertypes.len(), 2);
        for parent in &facts.supertypes {
            let expected = ResolutionReferenceOwnerFact {
                reference: parent.supertype_reference,
                owner: Some(parent.subtype),
            };
            assert_eq!(
                facts
                    .reference_owners
                    .iter()
                    .filter(|row| row.reference == parent.supertype_reference)
                    .collect::<Vec<_>>(),
                [&expected]
            );
            let body = facts
                .scopes
                .iter()
                .find(|scope| {
                    scope.kind == ResolutionScopeKind::TypeBody
                        && scope.owner == Some(parent.subtype)
                })
                .unwrap();
            assert_eq!(
                Some(facts.sites[parent.supertype_reference.index()].scope),
                body.parent,
                "authored parents keep their enclosing header lookup scope"
            );
        }
        println!(
            "CENTRAL_CSHARP_REFERENCE_OWNERS {:#?}",
            facts.reference_owners
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#7314: instance member references lacked the projection that demands their receiver"
    )]
    fn instance_member_source_facts_publish_binding_without_invocation() {
        let source = "class G<T> { public int Field; public void M() {} int F() { this.M(); return this.Field; } static int S() { return this.Field; } } class B { public int Field; public void M() {} } class Z : B { int F() { base.M(); return base.Field; } }";
        let tree = crate::test_support::parse_raw_csharp(source);
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        let file =
            brokk_bifrost_core::analyzer::ProjectFile::new(std::env::temp_dir(), "Member.cs");
        let parsed = crate::declarations::parse_csharp_file_with_native_facts(
            &file,
            source,
            &tree,
            &crate::preprocessor::scan_preprocessor(source),
        );
        let facts = parsed.resolution_facts;
        let mut members = 0;
        for identifier in &facts.identifiers {
            if facts.sites[identifier.site.index()].kind != ResolutionSiteKind::MemberReference {
                continue;
            }
            members += 1;
            let projections = facts
                .binding_projections
                .iter()
                .filter(|projection| projection.reference == identifier.site)
                .collect::<Vec<_>>();
            let [projection] = projections.as_slice() else {
                panic!("member projections: {projections:?}")
            };
            let output = &facts.type_slots[projection.output.index()];
            assert_eq!(output.site, identifier.site);
            assert_eq!(output.role, ResolutionTypeSlotRole::ExpressionValue);
            assert_ne!(Some(projection.output), identifier.qualifier);
            assert_eq!(
                projection.kind,
                if identifier.namespace == ResolutionNamespace::Callable {
                    BindingProjectionKind::BindingOnlyMemberReference
                } else {
                    assert_eq!(identifier.namespace, ResolutionNamespace::TypeOrValue);
                    BindingProjectionKind::TargetTypeOrDeclaredValueType
                }
            );
            assert!(
                facts
                    .calls
                    .iter()
                    .all(|call| call.callee != identifier.site)
            );
        }
        assert_eq!(members, 5);
        assert_eq!(
            facts
                .callable_receiver_origins
                .iter()
                .filter(|origin| origin.origin == ResolutionCallableReceiverOrigin::Super)
                .count(),
            2
        );
        assert_eq!(
            facts
                .callable_receiver_origins
                .iter()
                .filter(|origin| origin.origin == ResolutionCallableReceiverOrigin::CurrentInstance)
                .count(),
            3
        );
        assert!(
            facts
                .gaps
                .iter()
                .any(|gap| gap.kind == ResolutionGapKind::UnsupportedExpression)
        );
    }

    #[test]
    fn static_owner_base_reference_keeps_receiver_open_without_transfer() {
        use brokk_bifrost_core::analyzer::model::ClassLikeKind;

        let source = "static class StaticOwner { int M() { return base.Shared; } }";
        let tree = crate::test_support::parse_raw_csharp(source);
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        let file =
            brokk_bifrost_core::analyzer::ProjectFile::new(std::env::temp_dir(), "StaticOwner.cs");
        let parsed = crate::declarations::parse_csharp_file_with_native_facts(
            &file,
            source,
            &tree,
            &crate::preprocessor::scan_preprocessor(source),
        );
        let class = parsed
            .signature_metadata
            .iter()
            .find(|(unit, _)| unit.short_name() == "StaticOwner")
            .expect("static owner metadata");
        assert!(class.1.iter().any(|metadata| {
            metadata.class_like_kind() == Some(ClassLikeKind::Class)
                && metadata.class_like_is_static()
        }));
        let facts = parsed.resolution_facts;
        let members = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                facts.sites[identifier.site.index()].kind == ResolutionSiteKind::MemberReference
            })
            .collect::<Vec<_>>();
        let [member] = members.as_slice() else {
            panic!(
                "expected one base member reference: {:?}",
                facts.identifiers
            )
        };
        let receiver = member.qualifier.expect("base receiver slot");
        assert!(facts.gaps.iter().any(|gap| {
            gap.site == member.site && gap.kind == ResolutionGapKind::UnsupportedTypeSyntax
        }));
        assert!(
            facts
                .type_transfers
                .iter()
                .all(|transfer| transfer.output != receiver)
        );
        assert!(facts.callable_receiver_origins.iter().any(|origin| {
            origin.reference == member.site
                && origin.origin == ResolutionCallableReceiverOrigin::Super
        }));
    }
}
