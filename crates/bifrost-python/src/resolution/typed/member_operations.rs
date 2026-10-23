//! Narrow dynamic member observations. Syntax nominates; consumers prove API authority.
use super::*;
use crate::syntax::python_plain_string_literal;
use std::collections::VecDeque;

fn named_form(node: Node<'_>, source: &str) -> Option<PythonMemberForm> {
    let name = match node.kind() {
        "identifier" => node,
        "attribute" => node.child_by_field_name("attribute")?,
        _ => return None,
    };
    match name.utf8_text(source.as_bytes()).ok()? {
        "getattr" => Some(PythonMemberForm::Getattr),
        "setattr" => Some(PythonMemberForm::Setattr),
        "delattr" => Some(PythonMemberForm::Delattr),
        "patch" => Some(PythonMemberForm::PatchPath),
        "object"
            if node.kind() == "attribute"
                && node
                    .child_by_field_name("object")
                    .and_then(|object| {
                        if object.kind() == "identifier" {
                            Some(object)
                        } else {
                            object.child_by_field_name("attribute")
                        }
                    })
                    .is_some_and(|name| name.utf8_text(source.as_bytes()) == Ok("patch")) =>
        {
            Some(PythonMemberForm::PatchObject)
        }
        _ => None,
    }
}

fn bound_scope(
    parents: &[Option<ResolutionScopeId>],
    bindings: &HashMap<ResolutionScopeId, HashSet<String>>,
    scope: ResolutionScopeId,
    name: &str,
) -> ResolutionScopeId {
    find_scope_in_chain(
        Some(scope),
        |scope| parents[scope.index()],
        |scope| {
            bindings
                .get(&scope)
                .is_some_and(|names| names.contains(name))
        },
    )
    .unwrap_or(ResolutionScopeId::new(0))
}

fn reference(t: &Typed<'_, '_, '_>, node: Node<'_>) -> Option<ResolutionSiteId> {
    let node = if node.kind() == "attribute" {
        node.child_by_field_name("attribute")?
    } else {
        node
    };
    t.references
        .get(&(node.start_byte(), node.end_byte()))
        .copied()
}

// API authority asks for the callee value, not the result of invoking it.
// Keep the original call reference and publish an independent binding read at
// the structurally selected token, using the ordinary value/member contracts.
fn callee_binding_reference(t: &mut Typed<'_, '_, '_>, node: Node<'_>) -> Option<ResolutionSiteId> {
    let original = reference(t, node)?;
    let mut identifier =
        *t.p.facts
            .identifiers
            .iter()
            .find(|id| id.site == original)
            .expect("callee reference identifier");
    let token = if node.kind() == "attribute" {
        node.child_by_field_name("attribute")?
    } else {
        node
    };
    let site = t.p.site(
        token,
        t.scopes[&token.id()],
        ResolutionSiteKind::ValueReference,
    );
    identifier.site = site;
    identifier.namespace = ResolutionNamespace::Value;
    let qualified = identifier.qualifier.is_some();
    t.p.facts.identifiers.push(identifier);
    if qualified {
        let slot =
            t.p.facts
                .allocate_type_slot(site, ResolutionTypeSlotRole::ExpressionValue);
        t.p.facts
            .binding_projections
            .push(BindingProjectionFact::target_declared_value_type(
                site, slot,
            ));
    }
    Some(site)
}

fn names(t: &mut Typed<'_, '_, '_>, node: Node<'_>) -> PythonMemberNames {
    let literal = python_plain_string_literal(node, t.p.source).map(str::to_owned);
    if let Some(literal) = literal {
        return PythonMemberNames::Exact(vec![t.p.facts.intern_name(&mut t.p.names, &literal)]);
    }
    if node.kind() == "binary_operator"
        && node
            .child_by_field_name("operator")
            .is_some_and(|op| op.utf8_text(t.p.source.as_bytes()) == Ok("+"))
        && let Some(prefix) = node
            .child_by_field_name("left")
            .and_then(|left| python_plain_string_literal(left, t.p.source))
            .filter(|prefix| !prefix.is_empty())
            .map(str::to_owned)
    {
        return PythonMemberNames::Prefix(t.p.facts.intern_name(&mut t.p.names, &prefix));
    }
    PythonMemberNames::Any
}

fn call_arguments(call: Node<'_>) -> Vec<Node<'_>> {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    if arguments.kind() == "generator_expression" {
        vec![arguments]
    } else {
        named_children_iter(arguments)
            .filter(|argument| !argument.is_extra())
            .collect()
    }
}

fn dictionary_owner<'tree>(node: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    if node.kind() == "call"
        && node
            .child_by_field_name("function")
            .is_some_and(|function| {
                function.kind() == "identifier"
                    && function.utf8_text(source.as_bytes()) == Ok("vars")
            })
    {
        return call_arguments(node).first().copied().filter(|argument| {
            !matches!(
                argument.kind(),
                "keyword_argument" | "list_splat" | "dictionary_splat"
            )
        });
    }
    (node.kind() == "attribute"
        && node
            .child_by_field_name("attribute")?
            .utf8_text(source.as_bytes())
            .ok()?
            == "__dict__")
        .then(|| node.child_by_field_name("object"))
        .flatten()
}

fn mapping_names(t: &mut Typed<'_, '_, '_>, args: &[Node<'_>]) -> PythonMemberNames {
    let mut keys = Vec::new();
    let mut seen = HashSet::default();
    for arg in args {
        match arg.kind() {
            "dictionary" => {
                for pair in named_children_iter(*arg) {
                    let Some(key) = (pair.kind() == "pair")
                        .then(|| pair.child_by_field_name("key"))
                        .flatten()
                        .and_then(|key| python_plain_string_literal(key, t.p.source))
                    else {
                        return PythonMemberNames::Any;
                    };
                    let key = t.p.facts.intern_name(&mut t.p.names, key);
                    if seen.insert(key) {
                        keys.push(key);
                    }
                }
            }
            "keyword_argument" => {
                let key = arg
                    .child_by_field_name("name")
                    .expect("keyword name")
                    .utf8_text(t.p.source.as_bytes())
                    .expect("UTF-8 keyword");
                let key = t.p.facts.intern_name(&mut t.p.names, key);
                if seen.insert(key) {
                    keys.push(key);
                }
            }
            _ => return PythonMemberNames::Any,
        }
    }
    PythonMemberNames::Exact(keys)
}

pub(super) fn produce(t: &mut Typed<'_, '_, '_>, nodes: &[Node<'_>], events: &HashMap<usize, u32>) {
    let mut parents: Vec<_> = t.p.facts.scopes.iter().map(|scope| scope.parent).collect();
    for continuation in &t.p.facts.scope_continuations {
        parents[continuation.scope.index()] = continuation.parent;
    }
    let identifiers: HashMap<_, _> =
        t.p.facts
            .identifiers
            .iter()
            .map(|id| (id.site, id.name))
            .collect();
    let mut bindings: HashMap<ResolutionScopeId, HashSet<String>> = HashMap::default();
    for slot in &t.p.facts.binding_slots {
        let scope = t.p.facts.sites[slot.declaration.index()].scope;
        bindings.entry(scope).or_default().insert(
            t.p.facts.names[identifiers[&slot.declaration].index()]
                .spelling
                .clone(),
        );
    }
    // Edges come only from direct assignment events. Rebinding does not prove that
    // an alias is live; all of these observations still need forward selection.
    let mut aliases: HashMap<(ResolutionScopeId, String), Vec<PythonMemberForm>> =
        HashMap::default();
    let mut edges: HashMap<(ResolutionScopeId, String), Vec<(ResolutionScopeId, String)>> =
        HashMap::default();
    for token in nodes
        .iter()
        .copied()
        .filter(|node| events.contains_key(&node.id()))
    {
        let event = t.p.facts.binding_events[events[&token.id()] as usize];
        if event.kind != ResolutionBindingEventKind::Assign {
            continue;
        }
        let assignment = binding_operation(token).1;
        if assignment.child_by_field_name("left") != Some(token) {
            continue;
        }
        let Some(rhs) = assignment.child_by_field_name("right") else {
            continue;
        };
        let target = (
            t.p.facts.sites[event.slot.index()].scope,
            token
                .utf8_text(t.p.source.as_bytes())
                .expect("UTF-8 binding")
                .to_owned(),
        );
        if let Some(form) = named_form(rhs, t.p.source) {
            let forms = aliases.entry(target.clone()).or_default();
            if !forms.contains(&form) {
                forms.push(form);
            }
        }
        if rhs.kind() == "identifier" {
            let name = rhs.utf8_text(t.p.source.as_bytes()).expect("UTF-8 alias");
            edges
                .entry((
                    bound_scope(&parents, &bindings, t.scopes[&rhs.id()], name),
                    name.to_owned(),
                ))
                .or_default()
                .push(target);
        }
    }
    let mut queue: VecDeque<_> = aliases
        .iter()
        .flat_map(|(key, forms)| forms.iter().map(|form| (key.clone(), *form)))
        .collect();
    while let Some((source, form)) = queue.pop_front() {
        for target in edges.get(&source).into_iter().flatten() {
            let forms = aliases.entry(target.clone()).or_default();
            if !forms.contains(&form) {
                forms.push(form);
                queue.push_back((target.clone(), form));
            }
        }
    }
    for node in nodes.iter().copied() {
        if python_node_is_in_annotation(node) {
            continue;
        }
        if crate::source_facts::python_module_dynamic_write_candidate(node, t.p.source) {
            let site = t.p.site(
                node,
                t.scopes[&node.id()],
                ResolutionSiteKind::UnsupportedRoute,
            );
            t.p.facts.add_route_gap(
                site,
                ResolutionRouteGap::UnknownBinder {
                    scope: ResolutionScopeId::new(0),
                    name: None,
                    namespace: Some(ResolutionNamespace::Value),
                    may_publish: true,
                },
            );
        }
        if node.kind() == "delete_statement" {
            use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, walk_named_tree_preorder};
            let mut targets = Vec::new();
            walk_named_tree_preorder(node, false, |target| match target.kind() {
                "attribute" => {
                    targets.push(target);
                    WalkControl::SkipChildren
                }
                "subscript" => WalkControl::SkipChildren,
                _ => WalkControl::Continue,
            });
            for target in targets {
                let output = t.expression(target);
                let site = t.p.facts.type_slots[output.index()].site;
                let receiver =
                    t.p.facts
                        .identifiers
                        .iter()
                        .find(|identifier| identifier.site == site)
                        .expect("deleted attribute reference")
                        .qualifier
                        .expect("deleted attribute receiver");
                t.p.facts
                    .python_receiver_writes
                    .push(PythonNativeReceiverWriteFact {
                        site,
                        receiver,
                        value: None,
                    });
            }
        }
        let mut observations = Vec::new();
        if node.kind() == "call" {
            let Some(function) = node.child_by_field_name("function") else {
                continue;
            };
            let mut forms = named_form(function, t.p.source)
                .into_iter()
                .collect::<Vec<_>>();
            if function.kind() == "identifier" {
                let name = function
                    .utf8_text(t.p.source.as_bytes())
                    .expect("UTF-8 callee");
                if let Some(local) = aliases.get(&(
                    bound_scope(&parents, &bindings, t.scopes[&function.id()], name),
                    name.to_owned(),
                )) {
                    for form in local {
                        if !forms.contains(form) {
                            forms.push(*form);
                        }
                    }
                }
            } else if function.kind() == "attribute" {
                let member = function
                    .child_by_field_name("attribute")
                    .expect("attribute name");
                let object = function
                    .child_by_field_name("object")
                    .expect("attribute receiver");
                if member.utf8_text(t.p.source.as_bytes()) == Ok("object")
                    && object.kind() == "identifier"
                {
                    let name = object
                        .utf8_text(t.p.source.as_bytes())
                        .expect("UTF-8 alias");
                    if aliases
                        .get(&(
                            bound_scope(&parents, &bindings, t.scopes[&object.id()], name),
                            name.to_owned(),
                        ))
                        .is_some_and(|forms| forms.contains(&PythonMemberForm::PatchPath))
                        && !forms.contains(&PythonMemberForm::PatchObject)
                    {
                        forms.push(PythonMemberForm::PatchObject);
                    }
                }
                if let Some(receiver) = dictionary_owner(object, t.p.source) {
                    let args = call_arguments(node);
                    match member
                        .utf8_text(t.p.source.as_bytes())
                        .expect("UTF-8 member")
                    {
                        "update" => observations.push((
                            PythonMemberForm::DictUpdate,
                            Some(receiver),
                            node,
                            mapping_names(t, &args),
                        )),
                        "setdefault" | "__setitem__" => {
                            if let Some(name) = args.first() {
                                observations.push((
                                    PythonMemberForm::DictWrite,
                                    Some(receiver),
                                    *name,
                                    names(t, *name),
                                ));
                            }
                        }
                        _ => {}
                    }
                }
            }
            forms.sort_unstable_by_key(|form| match form {
                PythonMemberForm::Getattr => 0,
                PythonMemberForm::Setattr => 1,
                PythonMemberForm::Delattr => 2,
                PythonMemberForm::DictWrite => 3,
                PythonMemberForm::DictUpdate => 4,
                PythonMemberForm::PatchObject => 5,
                PythonMemberForm::PatchPath => 6,
            });
            let args = if forms.is_empty() {
                Vec::new()
            } else {
                call_arguments(node)
            };
            for form in forms {
                let path = form == PythonMemberForm::PatchPath;
                // Spread/keyword argument binding is not guessed. Keep its operation
                // and unknown name rather than fabricating the second actual.
                let positional = args.iter().all(|arg| {
                    !matches!(
                        arg.kind(),
                        "keyword_argument" | "list_splat" | "dictionary_splat"
                    )
                });
                let name = positional
                    .then(|| args.get(usize::from(!path)).copied())
                    .flatten();
                let receiver = (!path && positional)
                    .then(|| args.first().copied())
                    .flatten();
                let set = match (form, name) {
                    (PythonMemberForm::PatchPath, Some(name)) => {
                        // This is a decoded API string value, not Python source
                        // syntax. Index the member; name_site retains the full
                        // target literal for selected-owner confirmation.
                        python_plain_string_literal(name, t.p.source)
                            .and_then(|value| value.rsplit_once('.'))
                            .filter(|(owner, member)| !owner.is_empty() && !member.is_empty())
                            .map_or(PythonMemberNames::Any, |(_, member)| {
                                PythonMemberNames::Exact(vec![
                                    t.p.facts.intern_name(&mut t.p.names, member),
                                ])
                            })
                    }
                    (PythonMemberForm::PatchPath, None) => PythonMemberNames::Any,
                    (_, Some(name)) => names(t, name),
                    (_, None) => PythonMemberNames::Any,
                };
                observations.push((form, receiver, name.unwrap_or(node), set));
            }
        } else if matches!(node.kind(), "assignment" | "augmented_assignment")
            && let Some(left) = node
                .child_by_field_name("left")
                .filter(|left| left.kind() == "subscript")
            && let Some(receiver) = left
                .child_by_field_name("value")
                .and_then(|value| dictionary_owner(value, t.p.source))
            && let Some(name) = left.child_by_field_name("subscript")
        {
            observations.push((
                PythonMemberForm::DictWrite,
                Some(receiver),
                name,
                names(t, name),
            ));
        }
        let callee_reference = (!observations.is_empty())
            .then(|| {
                node.child_by_field_name("function")
                    .and_then(|callee| callee_binding_reference(t, callee))
            })
            .flatten();
        for (form, receiver, name, names) in observations {
            let mut receiver_reference = receiver.and_then(|receiver| reference(t, receiver));
            let receiver_slot = receiver.map(|receiver| t.expression(receiver));
            let site = t.p.site(
                node,
                t.scopes[&node.id()],
                ResolutionSiteKind::UnsupportedExpression,
            );
            let name_site = t.p.site(
                name,
                t.scopes[&name.id()],
                ResolutionSiteKind::UnsupportedExpression,
            );
            if form == PythonMemberForm::PatchPath {
                use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;
                if let Some(value) =
                    crate::structural::PYTHON_STRUCTURAL_SPEC.string_literal_value(name, t.p.source)
                    && let Some((owner, member)) = value.rsplit_once('.')
                    && !owner.is_empty()
                    && !member.is_empty()
                    && owner.split('.').all(|part| !part.is_empty())
                {
                    // A selected API string value denotes an absolute module/
                    // attribute route, not Python expression syntax. Its real
                    // literal site is a prerequisite, never a proved operation.
                    let mut parts = owner.split('.').collect::<Vec<_>>();
                    let terminal = parts.pop().expect("nonempty owner");
                    let name_id = t.p.facts.intern_name(&mut t.p.names, terminal);
                    let reference = t.p.site(
                        name,
                        t.scopes[&name.id()],
                        ResolutionSiteKind::ModuleReference,
                    );
                    t.p.facts.identifiers.push(PositionedIdentifierFact {
                        site: reference,
                        name: name_id,
                        role: ResolutionIdentifierRole::Reference,
                        namespace: ResolutionNamespace::Value,
                        qualifier: None,
                    });
                    t.p.facts.root_references.push(ResolutionRootReferenceFact {
                        reference,
                        root_scope: ResolutionScopeId::new(0),
                        anchor: ResolutionRootImportAnchor::Absolute,
                        prefix_reference: None,
                        owner_continued: false,
                    });
                    for (position, part) in parts.into_iter().enumerate() {
                        let name = t.p.facts.intern_name(&mut t.p.names, part);
                        t.p.facts.root_reference_segments.push(
                            ResolutionRootReferenceSegmentFact {
                                reference,
                                position: dense_ordinal(position, "Python patch target route"),
                                name,
                            },
                        );
                    }
                    receiver_reference = Some(reference);
                }
            }
            let effect = match form {
                PythonMemberForm::Getattr => PythonMemberEffect::Read,
                PythonMemberForm::Delattr => PythonMemberEffect::Delete,
                _ => PythonMemberEffect::Write,
            };
            t.p.facts
                .python_member_operations
                .push(PythonNativeMemberOperationFact {
                    site,
                    form,
                    effect,
                    callee_reference,
                    receiver_reference,
                    receiver_slot,
                    name_site,
                    names,
                });
        }
    }
}
