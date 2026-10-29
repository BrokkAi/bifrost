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
                        return None;
                    }
                    stack.push(node.child_by_field_name("name")?);
                }
                _ => return None,
            }
        }
        Some(parts)
    }

    fn reference(
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
        self.facts.identifiers.push(PositionedIdentifierFact {
            site,
            name,
            role: ResolutionIdentifierRole::Reference,
            namespace,
            qualifier: None,
        });
        self.claimed.insert(node.id());
        if node.kind() == "generic_name"
            && let Some(name) = first_named_child_of_kind(node, "identifier")
        {
            self.claimed.insert(name.id());
        }
        site
    }

    pub(super) fn reference_path(&mut self, node: Node<'_>, ctx: Context) {
        let Some(parts) = self.path(node) else {
            return;
        };
        if parts.is_empty() {
            return;
        }
        let namespace = reference_namespace(node);
        let absolute = {
            let mut pending = vec![node];
            let mut absolute = false;
            while let Some(n) = pending.pop() {
                if n.kind() == "alias_qualified_name" {
                    absolute = true;
                    break;
                }
                if n.kind() != "generic_name" {
                    pending.extend(named_children(n));
                }
            }
            absolute
        };
        if parts.len() == 1 && !absolute {
            let reference = self.reference(parts[0], ctx, namespace);
            // ECMA-334 14.7: free namespace members supply types, not methods.
            if matches!(
                namespace,
                ResolutionNamespace::Type | ResolutionNamespace::TypeOrValue
            ) {
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
        for index in start..parts.len() {
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
            self.facts
                .root_references
                .push(ResolutionRootReferenceFact {
                    reference,
                    root_scope: ctx.package,
                    anchor: if absolute {
                        ResolutionRootImportAnchor::Absolute
                    } else {
                        ResolutionRootImportAnchor::Lexical
                    },
                    prefix_reference: prefix,
                    owner_continued: false,
                });
            for (position, &part) in parts[..index].iter().enumerate() {
                let name = self.name(part);
                self.facts
                    .root_reference_segments
                    .push(ResolutionRootReferenceSegmentFact {
                        reference,
                        position: dense_ordinal(position, "root reference segment"),
                        name,
                    });
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
