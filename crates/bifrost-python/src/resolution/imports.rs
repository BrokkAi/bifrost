use super::*;
use crate::imports::{python_import_identifier_nodes, python_import_syntaxes_from_node};

pub(super) fn produce(
    p: &mut Producer<'_, '_>,
    node: Node<'_>,
    scope: ResolutionScopeId,
    events: &HashMap<usize, u32>,
) {
    let leaves = python_import_syntaxes_from_node(node, p.source);
    if leaves.is_empty() || node.has_error() {
        p.omitted_reference(node, scope);
    }
    for leaf in leaves {
        let site = p.site(leaf.leaf, scope, ResolutionSiteKind::ImportDeclaration);
        // All import routes are source syntax only until environment and
        // temporal readers can prove successful activation and availability.
        p.facts.add_gap(site, ResolutionGapKind::UnprovenActivation);
        let module = python_import_identifier_nodes(leaf.module);
        let relative_level = named_children_iter(leaf.module)
            .find(|part| part.kind() == "import_prefix")
            .map_or(0, |prefix| {
                let mut cursor = prefix.walk();
                prefix
                    .children(&mut cursor)
                    .map(|punctuation| match punctuation.kind() {
                        "." => 1,
                        "..." => 3,
                        _ => 0,
                    })
                    .sum()
            });
        let module_count = dense_ordinal(module.len(), "Python module segments");
        let star = leaf.info.is_wildcard;
        let form = if star {
            PythonNativeImportForm::Star
        } else if leaf.member.is_some() {
            PythonNativeImportForm::From
        } else {
            PythonNativeImportForm::Module
        };
        let mut route = module.clone();
        if let Some(member) = leaf.member {
            route.extend(python_import_identifier_nodes(member));
        }
        let binding = leaf.alias.or(leaf.target);
        let event = binding.and_then(|token| events.get(&token.id()).copied());
        if !star && (route.is_empty() || event.is_none()) {
            p.omitted_reference(leaf.leaf, scope);
            continue;
        }
        let local_name = binding.map(|token| {
            p.facts
                .intern_name(&mut p.names, &p.source[token.byte_range()])
        });
        let names = route
            .iter()
            .map(|token| {
                p.facts
                    .intern_name(&mut p.names, &p.source[token.byte_range()])
            })
            .collect::<Vec<_>>();
        p.facts.import_routes.push(ResolutionImportRouteFact {
            site,
            root_scope: scope,
            kind: if star {
                ResolutionImportRouteKind::Star
            } else {
                ResolutionImportRouteKind::Named
            },
            bound_name: local_name,
        });
        for (ordinal, &name) in names.iter().enumerate() {
            p.facts
                .import_route_segments
                .push(ResolutionImportRouteSegmentFact {
                    import_site: site,
                    ordinal: dense_ordinal(ordinal, "Python import segments"),
                    name,
                });
        }
        if relative_level != 0 {
            p.facts
                .add_route_gap(site, ResolutionRouteGap::UnknownPlacement);
        }
        p.facts.python_imports.push(PythonNativeImportFact {
            import_site: site,
            form,
            relative_level,
            module_segment_count: module_count,
            binding_event: event,
        });
        let anchor = if relative_level == 0 {
            ResolutionRootImportAnchor::Absolute
        } else {
            ResolutionRootImportAnchor::Lexical
        };
        p.facts.root_imports.push(ResolutionRootImportFact {
            site,
            root_scope: scope,
            anchor,
            position: Some(node.end_byte()),
        });
        p.facts
            .root_import_kinds
            .push(ResolutionRootImportKindFact {
                import_site: site,
                kind: if star {
                    ResolutionRootImportKind::Glob
                } else {
                    ResolutionRootImportKind::Named
                },
            });
        let bound_index = if form == PythonNativeImportForm::Module && leaf.alias.is_none() {
            0
        } else {
            names.len().saturating_sub(1)
        };
        let prefix = if star {
            names.as_slice()
        } else {
            &names[..bound_index]
        };
        for (position, &name) in prefix.iter().enumerate() {
            p.facts
                .root_import_segments
                .push(ResolutionRootImportSegmentFact {
                    import_site: site,
                    position: dense_ordinal(position, "Python root route"),
                    name,
                });
        }
        p.facts.import_selectors.push(ResolutionImportSelectorFact {
            site,
            kind: if star {
                ResolutionImportSelectorKind::Star
            } else {
                ResolutionImportSelectorKind::Named
            },
            source_name: (!star).then(|| names[bound_index]),
            local_name,
        });
        if star {
            p.facts.add_route_gap(
                site,
                ResolutionRouteGap::UnknownBinder {
                    scope,
                    name: None,
                    namespace: Some(ResolutionNamespace::Value),
                    may_publish: p.facts.scopes[scope.index()].kind
                        == ResolutionScopeKind::CompilationUnit,
                },
            );
        } else {
            let reference = p.identifier(
                route[bound_index],
                scope,
                ResolutionSiteKind::ModuleReference,
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Value,
            );
            p.facts
                .add_gap(reference, ResolutionGapKind::UnprovenActivation);
            p.facts.root_references.push(ResolutionRootReferenceFact {
                reference,
                root_scope: ResolutionScopeId::new(0),
                anchor,
                prefix_reference: None,
                owner_continued: false,
            });
            for (position, &name) in prefix.iter().enumerate() {
                p.facts
                    .root_reference_segments
                    .push(ResolutionRootReferenceSegmentFact {
                        reference,
                        position: dense_ordinal(position, "Python target route"),
                        name,
                    });
            }
            p.facts
                .root_import_demands
                .push(ResolutionRootImportDemandFact {
                    import_site: site,
                    namespace: ResolutionNamespace::Value,
                    name: names[bound_index],
                });
            p.facts
                .root_import_demand_targets
                .push(ResolutionRootImportDemandTargetFact {
                    import_site: site,
                    namespace: ResolutionNamespace::Value,
                    name: names[bound_index],
                    target: ResolutionRootImportDemandTarget::NamedReference(reference),
                });
        }
    }
}

pub(super) fn finish(p: &mut Producer<'_, '_>) {
    let mut seen = HashSet::default();
    let demands = p
        .facts
        .identifiers
        .iter()
        .filter(|id| {
            id.role == ResolutionIdentifierRole::Reference
                && id.qualifier.is_none()
                && id.namespace == ResolutionNamespace::Value
        })
        .map(|id| (id.namespace, id.name))
        .filter(|&name| seen.insert(name))
        .collect::<Vec<_>>();
    let stars = p
        .facts
        .root_import_kinds
        .iter()
        .filter(|kind| kind.kind == ResolutionRootImportKind::Glob)
        .map(|kind| kind.import_site)
        .collect::<Vec<_>>();
    p.facts.extend_same_name_glob_demands(&stars, &demands);
}
