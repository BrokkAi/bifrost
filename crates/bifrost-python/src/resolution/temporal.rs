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

pub(super) fn finish(p: &mut Producer<'_, '_>, scopes: &[Scope<'_>]) {
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
    for identifier in &p.facts.identifiers {
        if identifier.role != ResolutionIdentifierRole::Reference {
            continue;
        }
        let site = p.facts.sites[identifier.site.index()];
        let deferred = find_scope_in_chain(
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
                point_byte: write_points
                    .get(&identifier.site)
                    .copied()
                    .unwrap_or(site.start_byte),
                kind: if deferred {
                    ResolutionBindingObservationKind::Deferred
                } else {
                    ResolutionBindingObservationKind::Immediate
                },
            });
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
