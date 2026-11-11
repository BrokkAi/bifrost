//! Evaluation coordinates retained independently of canonical slot anchors.
use super::*;

pub(super) fn timing(
    p: &mut Producer<'_, '_>,
    event: u32,
    operation: Node<'_>,
    scope: ResolutionScopeId,
    cleanup: bool,
) {
    let commit = if cleanup {
        operation.end_byte()
    } else {
        match operation.kind() {
            "for_statement" | "with_statement" | "except_clause" => operation
                .child_by_field_name("body")
                .or_else(|| named_children_iter(operation).find(|child| child.kind() == "block"))
                .map_or(operation.end_byte(), |body| body.start_byte()),
            "for_in_clause" => {
                let mut cursor = operation.walk();
                operation
                    .children_by_field_name("right", &mut cursor)
                    .last()
                    .map_or(operation.end_byte(), |iterable| iterable.end_byte())
            }
            "with_item" => operation.end_byte(),
            "function_definition" | "class_definition" => operation
                .parent()
                .filter(|parent| parent.kind() == "decorated_definition")
                .map_or(operation.end_byte(), |decorated| decorated.end_byte()),
            "case_clause" => operation
                .child_by_field_name("guard")
                .or_else(|| operation.child_by_field_name("consequence"))
                .map_or(operation.end_byte(), |body| body.start_byte()),
            "parameters" | "lambda_parameters" => operation.start_byte(),
            _ => operation.end_byte(),
        }
    };
    p.facts
        .binding_event_timings
        .push(ResolutionBindingEventTimingFact {
            event,
            execution_scope: scope,
            entry_byte: operation.start_byte(),
            commit_byte: commit,
            // Tree-sitter byte coordinates fit u32. At one commit boundary,
            // ordered target tokens distinguish chained/destructuring writes.
            commit_phase: dense_ordinal(
                p.facts.sites[p.facts.binding_events[event as usize].target.index()].start_byte,
                "Python write phase",
            ),
        });
}

pub(super) fn finish(
    p: &mut Producer<'_, '_>,
    scopes: &[Scope<'_>],
    future_annotations: bool,
    generic_annotation_scopes: &HashMap<ResolutionScopeId, ResolutionScopeId>,
    generic_runtime_scopes: &HashSet<ResolutionScopeId>,
) {
    let write_points = p
        .facts
        .binding_event_timings
        .iter()
        .filter_map(|timing| {
            let event = p.facts.binding_events[timing.event as usize];
            // Import targets retain their entry observation: retiming them
            // creates extra inbound uses and incomplete self-import demands.
            matches!(
                event.kind,
                ResolutionBindingEventKind::Assign
                    | ResolutionBindingEventKind::Class
                    | ResolutionBindingEventKind::Function
            )
            .then_some((event.target, timing.commit_byte))
        })
        .collect::<HashMap<_, _>>();
    let module_end = scopes[0].node.end_byte();
    let module_scope = p
        .facts
        .scopes
        .iter()
        .find(|scope| scope.kind == ResolutionScopeKind::CompilationUnit && scope.parent.is_none())
        .expect("Python source module scope")
        .id;
    // PEP 563 function annotations use globals plus visible PEP 695 type
    // parameters. A nested generic's runtime formal Block can also reach
    // enclosing function locals. Until a separate annotation scope tree can
    // represent just the type parameters, withhold that route.
    let mut function_annotations = if future_annotations {
        p.facts
            .python_annotations
            .iter()
            .filter(|annotation| annotation.mode != PythonNativeAnnotationMode::Eager)
            .filter_map(|annotation| {
                let slot = p.facts.type_slots[annotation.type_slot.index()];
                let site = p.facts.sites[slot.site.index()];
                let node = scopes[0]
                    .node
                    .descendant_for_byte_range(site.start_byte, site.end_byte)?;
                let function = find_ancestor(node, |parent| {
                    parent.kind() == "function_definition"
                        && parent
                            .child_by_field_name("body")
                            .is_some_and(|body| site.end_byte <= body.start_byte())
                })?;
                // A type slot for a dotted annotation names its terminal token.
                // Route the entire annotation expression, including qualifiers.
                let mut annotation_node = node;
                while let Some(parent) = annotation_node.parent() {
                    if parent == function {
                        break;
                    }
                    if parent.child_by_field_name("type") == Some(annotation_node)
                        || parent.child_by_field_name("return_type") == Some(annotation_node)
                    {
                        break;
                    }
                    annotation_node = parent;
                }
                let mut current = Some(site.scope);
                let mut route = module_scope;
                let mut crosses_executable = false;
                while let Some(scope) = current {
                    if route == module_scope {
                        if let Some(&runtime) = generic_annotation_scopes.get(&scope) {
                            route = runtime;
                        } else if generic_runtime_scopes.contains(&scope) {
                            route = scope;
                        }
                    }
                    let row = p.facts.scopes[scope.index()];
                    if row.kind == ResolutionScopeKind::Executable {
                        crosses_executable = true;
                    }
                    current = row.parent;
                }
                let unsupported = route != module_scope && crosses_executable;
                Some((
                    annotation_node.start_byte(),
                    annotation_node.end_byte(),
                    if unsupported { module_scope } else { route },
                    unsupported,
                ))
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    function_annotations.sort_unstable();
    let mut function_ranges: Vec<(usize, usize, ResolutionScopeId, bool)> = Vec::new();
    for (start, end, route, unsupported) in function_annotations {
        if let Some(previous) = function_ranges.last_mut().filter(|previous| {
            start <= previous.1 && route == previous.2 && unsupported == previous.3
        }) {
            previous.1 = previous.1.max(end);
        } else {
            function_ranges.push((start, end, route, unsupported));
        }
    }
    let mut postponed = p
        .facts
        .python_annotations
        .iter()
        .filter(|annotation| annotation.mode != PythonNativeAnnotationMode::Eager)
        .map(|annotation| {
            // The syntax site can name only a generic head for member lookup.
            // Timing covers every reference in the complete annotation value.
            let slot = p.facts.type_slots[annotation.type_slot.index()];
            let site = p.facts.sites[slot.site.index()];
            (site.start_byte, site.end_byte)
        })
        .collect::<Vec<_>>();
    postponed.sort_unstable();
    // Merge containing/overlapping annotation ranges so membership is a binary
    // search rather than a scan of all annotations for every source reference.
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for (start, end) in postponed {
        if let Some(previous) = ranges.last_mut().filter(|previous| start <= previous.1) {
            previous.1 = previous.1.max(end);
        } else {
            ranges.push((start, end));
        }
    }
    let function_route = |site: ResolutionSiteFact| {
        function_ranges
            .partition_point(|range| range.0 <= site.start_byte)
            .checked_sub(1)
            .and_then(|index| {
                (site.end_byte <= function_ranges[index].1)
                    .then_some((function_ranges[index].2, function_ranges[index].3))
            })
    };
    // A lexical root and its qualified terminal form one route. The prefix
    // selects that route; intermediate qualified prefixes follow the same one.
    let mut chain_routes = HashMap::default();
    for root in &p.facts.root_references {
        if let Some(prefix) = root.prefix_reference
            && let Some(route) = function_route(p.facts.sites[prefix.index()])
        {
            chain_routes.insert(root.reference, route);
        }
    }
    let mut unsupported_annotations = Vec::new();
    for identifier in &p.facts.identifiers {
        if identifier.role != ResolutionIdentifierRole::Reference {
            continue;
        }
        let site = &mut p.facts.sites[identifier.site.index()];
        let function_annotation = chain_routes
            .get(&identifier.site)
            .copied()
            .or_else(|| function_route(*site));
        if let Some((route, _)) = function_annotation {
            site.scope = route;
        }
        let site = *site;
        if function_annotation.is_some_and(|(_, unsupported)| unsupported) {
            unsupported_annotations.push(identifier.site);
        }
        let annotation = ranges
            .partition_point(|range| range.0 <= site.start_byte)
            .checked_sub(1)
            .is_some_and(|index| site.end_byte <= ranges[index].1);
        let deferred = annotation
            || find_scope_in_chain(
                Some(site.scope),
                |id| p.facts.scopes[id.index()].parent,
                |id| {
                    matches!(
                        scopes[id.index()].node.kind(),
                        "function_definition" | "lambda" | "generator_expression"
                    )
                },
            )
            .is_some();
        p.facts
            .binding_observations
            .push(ResolutionBindingObservationFact {
                reference: identifier.site,
                execution_scope: site.scope,
                // A write token denotes the binding it establishes, rather
                // than a read of the binding visible before its RHS executes.
                point_byte: if annotation {
                    // Postponed type syntax observes the completed module,
                    // independently of the source occurrence's coordinates.
                    module_end
                } else {
                    write_points
                        .get(&identifier.site)
                        .copied()
                        .unwrap_or(site.start_byte)
                },
                kind: if deferred {
                    ResolutionBindingObservationKind::Deferred
                } else {
                    ResolutionBindingObservationKind::Immediate
                },
            });
    }
    for site in unsupported_annotations {
        p.facts
            .add_gap(site, ResolutionGapKind::UnsupportedScopeOrBinder);
    }
    // Observed lexical reads are source-owned demands. Existing root-reference
    // lowering suppresses their canonical checkpoint path, so a slot cannot
    // bypass temporal selection. Import target routes keep their own anchors.
    let root_scope = p
        .facts
        .scopes
        .iter()
        .find(|scope| scope.kind == ResolutionScopeKind::CompilationUnit && scope.parent.is_none())
        .expect("Python source module scope")
        .id;
    let mut routed = p
        .facts
        .root_references
        .iter()
        .map(|root| root.reference)
        .collect::<HashSet<_>>();
    let lexical = p
        .facts
        .identifiers
        .iter()
        .filter(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference && identifier.qualifier.is_none()
        })
        .map(|identifier| identifier.site)
        .collect::<HashSet<_>>();
    for observation in &p.facts.binding_observations {
        if lexical.contains(&observation.reference) && routed.insert(observation.reference) {
            p.facts.root_references.push(ResolutionRootReferenceFact {
                reference: observation.reference,
                root_scope,
                anchor: ResolutionRootImportAnchor::Lexical,
                prefix_reference: None,
                owner_continued: false,
            });
        }
    }
    // Predicate operands are exact structured references at the same AST range;
    // no name matching is used to find an expression in source text.
    let mut references = HashMap::default();
    for identifier in &p.facts.identifiers {
        if identifier.role == ResolutionIdentifierRole::Reference {
            let site = p.facts.sites[identifier.site.index()];
            references
                .entry((site.start_byte, site.end_byte))
                .or_insert(identifier.site);
        }
    }
    for predicate in &mut p.facts.python_predicates {
        let site = p.facts.sites[predicate.predicate.index()];
        let node = scopes[0]
            .node
            .descendant_for_byte_range(site.start_byte, site.end_byte)
            .expect("predicate AST node");
        let operand = if predicate.kind == PythonNativePredicateKind::Attribute {
            let attribute = node.child_by_field_name("attribute");
            if !attribute.is_some_and(|field| &p.source[field.byte_range()] == "TYPE_CHECKING") {
                predicate.kind = PythonNativePredicateKind::Unknown;
            }
            node.child_by_field_name("object").unwrap_or(node)
        } else {
            node
        };
        predicate.operand = references
            .get(&(operand.start_byte(), operand.end_byte()))
            .copied();
    }
}

pub(super) fn predicate(p: &mut Producer<'_, '_>, node: Node<'_>, site: ResolutionSiteId) {
    let kind = match node.kind() {
        "identifier" => PythonNativePredicateKind::Name,
        "attribute" => PythonNativePredicateKind::Attribute,
        "true" => PythonNativePredicateKind::True,
        "false" => PythonNativePredicateKind::False,
        _ => PythonNativePredicateKind::Unknown,
    };
    p.facts.python_predicates.push(PythonNativePredicateFact {
        predicate: site,
        kind,
        operand: None,
    });
}
