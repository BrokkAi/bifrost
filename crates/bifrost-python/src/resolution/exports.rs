use super::*;
use crate::syntax::{python_contains_all_identifier, python_plain_string_literal};

pub(super) fn produce(
    p: &mut Producer<'_, '_>,
    nodes: &[Node<'_>],
    scopes: &HashMap<usize, ResolutionScopeId>,
    events: &HashMap<usize, u32>,
) {
    let module = ResolutionScopeId::new(0);
    let slots = p
        .facts
        .binding_slots
        .iter()
        .filter(|slot| p.facts.sites[slot.declaration.index()].scope == module)
        .map(|slot| slot.declaration)
        .collect::<Vec<_>>();
    for declaration in slots {
        // Ordered canonical slots use the shared definition-authority row:
        // export membership must not promote their lexical hoisting to ScopeWide.
        p.facts.additional_definition_namespaces.push(
            ResolutionAdditionalDefinitionNamespaceFact {
                declaration,
                namespace: ResolutionNamespace::Value,
                hoisting: HoistingClass::SourceOrder,
            },
        );
        // A source inventory is not a selected initialized module attribute.
        let name = p
            .facts
            .identifiers
            .iter()
            .find(|id| id.site == declaration)
            .expect("slot identifier")
            .name;
        p.facts.add_route_gap(
            declaration,
            ResolutionRouteGap::UnknownBinder {
                scope: module,
                name: Some(name),
                namespace: Some(ResolutionNamespace::Value),
                may_publish: true,
            },
        );
        p.facts.root_exports.push(ResolutionRootExportFact {
            root_scope: module,
            declaration,
            namespace: ResolutionNamespace::Value,
        });
    }
    let all_slot = p
        .facts
        .identifiers
        .iter()
        .find(|id| {
            id.role == ResolutionIdentifierRole::Declaration
                && p.facts.sites[id.site.index()].scope == module
                && p.facts.names[id.name.index()].spelling == "__all__"
        })
        .map(|id| id.site);
    let mut curated = PythonNativeCuratedSurface::Absent;
    let mut list = false;
    // Deferred global writes cannot be reduced to a final literal surface.
    let mut deferred_mutation = false;
    for &node in nodes {
        let scope = scopes[&node.id()];
        let names_all = |node: Node<'_>| {
            node.kind() == "identifier" && &p.source[node.byte_range()] == "__all__"
        };
        let other_write = events.get(&node.id()).is_some_and(|&ordinal| {
            let event = p.facts.binding_events[ordinal as usize];
            Some(event.slot) == all_slot
                && event.kind != ResolutionBindingEventKind::Annotation
                && !matches!(
                    binding_operation(node).1.kind(),
                    "assignment" | "augmented_assignment" | "delete_statement"
                )
        });
        let mut kind = PythonNativeExportOperationKind::Unknown;
        let mut value = None;
        let mut affected = false;
        match node.kind() {
            "assignment" | "augmented_assignment" => {
                if let Some(left) = node.child_by_field_name("left") {
                    affected = names_all(left)
                        || python_contains_all_identifier(left, p.source)
                        || node
                            .child_by_field_name("right")
                            .is_some_and(|right| python_contains_all_identifier(right, p.source));
                    if names_all(left) {
                        value = node.child_by_field_name("right");
                        if value.is_none()
                            && node.child_by_field_name("type").is_some()
                            && !node.has_error()
                        {
                            continue;
                        }
                        let augment = node.kind() == "augmented_assignment";
                        let plus = !augment
                            || node
                                .child_by_field_name("operator")
                                .is_some_and(|op| op.kind() == "+=");
                        if plus {
                            kind = match (augment, value.map(|value| value.kind())) {
                                (false, Some("list")) => {
                                    PythonNativeExportOperationKind::ReplaceList
                                }
                                (false, Some("tuple")) => {
                                    PythonNativeExportOperationKind::ReplaceTuple
                                }
                                (true, Some("list")) => {
                                    PythonNativeExportOperationKind::AugmentList
                                }
                                (true, Some("tuple")) => {
                                    PythonNativeExportOperationKind::AugmentTuple
                                }
                                _ => PythonNativeExportOperationKind::Unknown,
                            };
                        }
                    }
                }
            }
            "call" => {
                if let Some(function) = node.child_by_field_name("function") {
                    if function.kind() == "attribute"
                        && function
                            .child_by_field_name("object")
                            .is_some_and(names_all)
                    {
                        affected = true;
                        let method = function
                            .child_by_field_name("attribute")
                            .map(|attr| &p.source[attr.byte_range()]);
                        kind = match method {
                            Some("extend") => PythonNativeExportOperationKind::Extend,
                            Some("append") => PythonNativeExportOperationKind::Append,
                            _ => PythonNativeExportOperationKind::Unknown,
                        };
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let args = named_children_iter(args)
                                .filter(|arg| arg.kind() != "comment")
                                .collect::<Vec<_>>();
                            if args.len() == 1 {
                                value = Some(args[0]);
                            }
                        }
                    } else if node
                        .child_by_field_name("arguments")
                        .is_some_and(|args| python_contains_all_identifier(args, p.source))
                    {
                        affected = true;
                    }
                }
            }
            "delete_statement" => {
                affected = python_contains_all_identifier(node, p.source);
                kind = PythonNativeExportOperationKind::Delete;
            }
            "ERROR" => affected = python_contains_all_identifier(node, p.source),
            _ => affected = other_write,
        }
        if !affected {
            continue;
        }
        if scope != module {
            // Function-local and class-local __all__ are not module exports.
            // Directives are produced after this fold; use the canonical
            // attributed event instead of requiring a particular pass order.
            let writes_module_all = p.facts.binding_events.iter().any(|event| {
                let target = p.facts.sites[event.target.index()];
                target.scope == scope
                    && node.start_byte() <= target.start_byte
                    && target.end_byte <= node.end_byte()
                    && p.facts.sites[event.slot.index()].scope == module
                    && p.facts.identifiers.iter().any(|id| {
                        id.site == event.slot
                            && p.facts.names[id.name.index()].spelling == "__all__"
                    })
            });
            let local_all = p.facts.binding_slots.iter().any(|slot| {
                p.facts.sites[slot.declaration.index()].scope == scope
                    && p.facts.identifiers.iter().any(|id| {
                        id.site == slot.declaration
                            && p.facts.names[id.name.index()].spelling == "__all__"
                    })
            });
            if writes_module_all || !local_all {
                deferred_mutation = true;
            }
            continue;
        }
        let site = p.site(node, module, ResolutionSiteKind::UnsupportedExpression);
        let ordinal = dense_ordinal(
            p.facts.python_export_operations.len(),
            "Python export operations",
        );
        let mut readable = !node.has_error() && !p.node_guards.contains_key(&node.id());
        let mut members = Vec::new();
        if let Some(value) = value {
            if kind == PythonNativeExportOperationKind::Append {
                members.push(value);
            } else if matches!(value.kind(), "list" | "tuple") {
                members
                    .extend(named_children_iter(value).filter(|child| child.kind() != "comment"));
            } else {
                readable = false;
            }
        } else {
            readable = false;
        }
        for (index, member) in members.into_iter().enumerate() {
            if let Some(name) = python_plain_string_literal(member, p.source) {
                let name = p.facts.intern_name(&mut p.names, name);
                let literal_site = p.site(member, module, ResolutionSiteKind::Literal);
                p.facts
                    .python_export_members
                    .push(PythonNativeExportMemberFact {
                        operation_ordinal: ordinal,
                        ordinal: dense_ordinal(index, "Python export members"),
                        name,
                        literal_site,
                    });
            } else {
                readable = false;
            }
        }
        use PythonNativeExportOperationKind::*;
        let replaces = matches!(kind, ReplaceList | ReplaceTuple);
        readable &= match kind {
            ReplaceList | ReplaceTuple => true,
            AugmentList => curated == PythonNativeCuratedSurface::Listed && list,
            AugmentTuple => curated == PythonNativeCuratedSurface::Listed,
            Extend | Append => curated == PythonNativeCuratedSurface::Listed && list,
            Delete | Unknown => false,
        };
        if replaces {
            list = kind == ReplaceList;
        }
        curated = if readable {
            PythonNativeCuratedSurface::Listed
        } else {
            PythonNativeCuratedSurface::Unreadable
        };
        p.facts
            .python_export_operations
            .push(PythonNativeExportOperationFact {
                ordinal,
                site,
                module_scope: module,
                kind,
                readable,
            });
        if !readable {
            p.facts
                .add_gap(site, ResolutionGapKind::UnsupportedScopeOrBinder);
        }
    }
    if deferred_mutation {
        curated = PythonNativeCuratedSurface::Unreadable;
    }
    let wildcard_policy = match curated {
        PythonNativeCuratedSurface::Absent => PythonNativeWildcardPolicy::PublicNames,
        PythonNativeCuratedSurface::Listed => PythonNativeWildcardPolicy::Curated,
        PythonNativeCuratedSurface::Unreadable => PythonNativeWildcardPolicy::Unknown,
    };
    p.facts
        .python_export_surfaces
        .push(PythonNativeExportSurfaceFact {
            module_scope: module,
            curated,
            wildcard_policy,
        });
}
