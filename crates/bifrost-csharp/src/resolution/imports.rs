use super::*;
use crate::syntax::{
    csharp_using_directive_is_global, csharp_using_directive_is_static,
    csharp_using_directive_target_node, map_csharp_type_arguments,
};

impl Producer<'_, '_> {
    pub(super) fn using(&mut self, node: Node<'_>, ctx: Context) {
        let site = self.site(node, ctx.scope, ResolutionSiteKind::ImportDeclaration);
        let alias = node.child_by_field_name("name");
        let Some(parts) = csharp_using_directive_target_node(node).and_then(|n| self.path(n))
        else {
            self.omit(node, ctx.scope, ResolutionGapKind::UnsupportedRoute);
            return;
        };
        if parts.is_empty() {
            self.omit(node, ctx.scope, ResolutionGapKind::UnsupportedRoute);
            return;
        }
        let is_static = csharp_using_directive_is_static(node);
        let is_global = csharp_using_directive_is_global(node);
        let names = parts
            .iter()
            .map(|&part| self.name(part))
            .collect::<Vec<_>>();
        let bound = alias.map(|n| self.name(n));
        self.facts.import_routes.push(ResolutionImportRouteFact {
            site,
            root_scope: ctx.scope,
            kind: if alias.is_some() {
                ResolutionImportRouteKind::Named
            } else if is_static {
                ResolutionImportRouteKind::StaticOnDemand
            } else {
                ResolutionImportRouteKind::TypeOnDemand
            },
            bound_name: bound,
        });
        for (ordinal, &name) in names.iter().enumerate() {
            self.facts
                .import_route_segments
                .push(ResolutionImportRouteSegmentFact {
                    import_site: site,
                    ordinal: dense_ordinal(ordinal, "using route segment"),
                    name,
                });
        }
        // ECMA-334 14.6.1 / 7.7.1: own using directives do not see one
        // another. The last directive of the complete scope is set at finish.
        self.facts.root_imports.push(ResolutionRootImportFact {
            site,
            root_scope: ctx.scope,
            anchor: ResolutionRootImportAnchor::Lexical,
            position: None,
        });
        if is_global {
            self.facts
                .compilation_imports
                .push(ResolutionCompilationImportFact { import_site: site });
        }
        let route = if bound.is_some() {
            &names[..names.len() - 1]
        } else {
            &names[..]
        };
        for (position, &name) in route.iter().enumerate() {
            self.facts
                .root_import_segments
                .push(ResolutionRootImportSegmentFact {
                    import_site: site,
                    position: dense_ordinal(position, "using root segment"),
                    name,
                });
        }
        self.facts
            .root_import_kinds
            .push(ResolutionRootImportKindFact {
                import_site: site,
                kind: if bound.is_some() {
                    ResolutionRootImportKind::Named
                } else {
                    ResolutionRootImportKind::Glob
                },
            });
        self.facts
            .import_selectors
            .push(ResolutionImportSelectorFact {
                site,
                kind: if bound.is_some() {
                    ResolutionImportSelectorKind::Named
                } else {
                    ResolutionImportSelectorKind::Star
                },
                source_name: bound.map(|_| *names.last().unwrap()),
                local_name: bound,
            });
        if let Some(bound) = bound {
            self.facts.identifiers.push(PositionedIdentifierFact {
                site,
                name: bound,
                role: ResolutionIdentifierRole::Alias,
                namespace: ResolutionNamespace::Type,
                qualifier: None,
            });
        }
        // Closed alias applications retain ordered argument slots and exact
        // syntax ranges. M6 supplies their type interpretation and substitution.
        for part in parts.iter().filter(|n| n.kind() == "generic_name") {
            let application = self
                .facts
                .allocate_type_slot(site, ResolutionTypeSlotRole::TargetTypeIdentity);
            let arguments = first_named_child_of_kind(*part, "type_argument_list")
                .expect("generic name has arguments");
            let arguments = map_csharp_type_arguments(Some(arguments), |argument| {
                if self.is_excluded(argument) {
                    return Some(None);
                }
                let argument_site =
                    self.site(argument, ctx.scope, ResolutionSiteKind::TypeReference);
                let argument = self
                    .facts
                    .allocate_type_slot(argument_site, ResolutionTypeSlotRole::TargetTypeIdentity);
                self.facts
                    .add_gap(argument_site, ResolutionGapKind::UnsupportedTypeSyntax);
                self.facts.add_reference_enumeration_gap(
                    argument_site,
                    ResolutionGapKind::UnsupportedTypeSyntax,
                );
                Some(Some(argument))
            })
            .expect("generic arguments have structured children");
            for (ordinal, argument) in arguments.into_iter().flatten().enumerate() {
                self.facts.type_arguments.push(ResolutionTypeArgumentFact {
                    application,
                    ordinal: dense_ordinal(ordinal, "alias type argument"),
                    argument,
                    indirection_delta: 0,
                    reference_indirection_delta: 0,
                });
            }
            self.facts
                .add_gap(site, ResolutionGapKind::UnsupportedTypeSyntax);
        }
        self.imports.push((site, is_static, bound));
        self.claim_tree(node);
    }

    pub(super) fn finish_imports(&mut self) {
        // ECMA-334 14.6.1 / 7.7.1 requires using directives before every
        // member of a compilation unit or namespace body, so the last
        // directive's end is the producer-side activation point. A global
        // using is visited in compilation-unit scope and precedes the other
        // usings there; it contributes to that same scope position.
        for import in &mut self.facts.root_imports {
            import.position = Some(self.directive_ends[&import.root_scope]);
        }
        let rooted = self
            .facts
            .root_references
            .iter()
            .map(|r| r.reference)
            .collect::<HashSet<_>>();
        let mut demands = HashSet::default();
        for identifier in &self.facts.identifiers {
            if identifier.role == ResolutionIdentifierRole::Reference
                && identifier.qualifier.is_none()
                && !rooted.contains(&identifier.site)
            {
                let namespaces: &[_] = match identifier.namespace {
                    ResolutionNamespace::TypeOrValue => {
                        &[ResolutionNamespace::Type, ResolutionNamespace::Value]
                    }
                    ResolutionNamespace::Type => &[ResolutionNamespace::Type],
                    ResolutionNamespace::Callable => &[ResolutionNamespace::Callable],
                    _ => &[ResolutionNamespace::Value],
                };
                for &namespace in namespaces {
                    demands.insert((namespace, identifier.name));
                }
            }
        }
        let mut demands = demands.into_iter().collect::<Vec<_>>();
        demands.sort();
        for &(site, is_static, bound) in &self.imports {
            let selected = demands
                .iter()
                .copied()
                .filter(|&(namespace, name)| {
                    (is_static || namespace == ResolutionNamespace::Type)
                        && bound.is_none_or(|bound| bound == name)
                })
                .collect::<Vec<_>>();
            if bound.is_some() {
                let name = self
                    .facts
                    .import_route_segments
                    .iter()
                    .rfind(|segment| segment.import_site == site)
                    .unwrap()
                    .name;
                self.facts
                    .extend_root_import_demands(&[site], &[(ResolutionNamespace::Type, name)]);
            } else {
                self.facts.extend_same_name_glob_demands(&[site], &selected);
            }
        }
    }
}
