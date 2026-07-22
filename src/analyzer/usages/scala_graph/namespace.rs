use crate::analyzer::CodeUnit;
use crate::hash::HashSet;
use tree_sitter::Node;

pub(crate) fn scala_type_reference_is_singleton(node: Node<'_>) -> bool {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if candidate.kind() == "singleton_type" {
            return true;
        }
        current = candidate.parent().filter(|parent| {
            matches!(
                parent.kind(),
                "singleton_type" | "stable_type_identifier" | "generic_type"
            )
        });
    }
    false
}

/// Expand a terminal type identifier to the structured qualified-type node
/// which owns it. Type-argument nodes interrupt this walk, so `T` in
/// `Outer[T]` remains its own lookup while `Outer.Member` is considered as one
/// qualified path.
pub(crate) fn scala_qualified_type_root(mut node: Node<'_>) -> Node<'_> {
    while let Some(parent) = node.parent().filter(|parent| {
        matches!(
            parent.kind(),
            "stable_type_identifier"
                | "projected_type"
                | "singleton_type"
                | "generic_type"
                | "applied_constructor_type"
                | "annotated_type"
        )
    }) {
        node = parent;
    }
    node
}

/// Exact outcome for a Scala type-namespace lookup.
///
/// `NoMatch` is the only outcome that permits a caller to continue into an
/// import or package tier. `AuthoritativeMiss` represents a parser-proven
/// local type binding which deliberately has no indexed `CodeUnit`, while
/// `Ambiguous` preserves two or more distinct physical declarations instead
/// of collapsing them through their shared rendered fqn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ScalaTypeNamespaceResolution {
    NoMatch,
    Resolved(CodeUnit),
    Ambiguous,
    AuthoritativeMiss,
}

/// Exact root namespace selected for a structured qualified Scala type path.
///
/// Stable objects retain their physical declaration identity. Packages have
/// no declaration `CodeUnit`, so their canonical namespace name is retained
/// instead. Callers must treat every non-resolved outcome as terminal except
/// `NoMatch`, which alone permits a lower-precedence tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ScalaQualifiedTypeRootBinding {
    StableObjects(Vec<CodeUnit>),
    Package(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ScalaQualifiedTypeRootResolution {
    NoMatch,
    Resolved(ScalaQualifiedTypeRootBinding),
    Ambiguous,
    AuthoritativeMiss,
}

pub(crate) enum ScalaDirectAncestorResolution {
    Resolved(Vec<CodeUnit>),
    Ambiguous,
}

/// Resolve an unqualified Scala type name against exact enclosing owners.
///
/// Enclosing owners must be supplied nearest-first. A direct declaration wins
/// regardless of source order. If no direct declaration exists, inherited
/// members are considered breadth-first so a nearer ancestor tier wins. The
/// exact `CodeUnit` is retained throughout: the same base reached through a
/// diamond is deduplicated, while distinct declarations at the winning tier
/// are ambiguous even when they render the same fqn.
pub(crate) fn resolve_exact_lexical_type_namespace<Owners, DirectMembers, DirectAncestors>(
    owners_nearest_first: Owners,
    name: &str,
    authoritative_local_barrier: bool,
    mut direct_members: DirectMembers,
    mut direct_ancestors: DirectAncestors,
) -> ScalaTypeNamespaceResolution
where
    Owners: IntoIterator<Item = CodeUnit>,
    DirectMembers: FnMut(&CodeUnit, &str) -> Vec<CodeUnit>,
    DirectAncestors: FnMut(&CodeUnit) -> ScalaDirectAncestorResolution,
{
    if authoritative_local_barrier {
        return ScalaTypeNamespaceResolution::AuthoritativeMiss;
    }

    for owner in owners_nearest_first {
        let direct = unique_units(direct_members(&owner, name));
        match direct.as_slice() {
            [declaration] => {
                return ScalaTypeNamespaceResolution::Resolved(declaration.clone());
            }
            [_, _, ..] => return ScalaTypeNamespaceResolution::Ambiguous,
            [] => {}
        }

        let mut level = match direct_ancestors(&owner) {
            ScalaDirectAncestorResolution::Resolved(ancestors) => ancestors,
            ScalaDirectAncestorResolution::Ambiguous => {
                return ScalaTypeNamespaceResolution::Ambiguous;
            }
        };
        let mut seen = HashSet::from_iter([owner]);
        while !level.is_empty() {
            let mut matches = Vec::new();
            let mut next = Vec::new();
            let mut next_is_ambiguous = false;
            for ancestor in level {
                if !seen.insert(ancestor.clone()) {
                    continue;
                }
                matches.extend(direct_members(&ancestor, name));
                match direct_ancestors(&ancestor) {
                    ScalaDirectAncestorResolution::Resolved(ancestors) => next.extend(ancestors),
                    ScalaDirectAncestorResolution::Ambiguous => next_is_ambiguous = true,
                }
            }
            let matches = unique_units(matches);
            match matches.as_slice() {
                [declaration] => {
                    return ScalaTypeNamespaceResolution::Resolved(declaration.clone());
                }
                [_, _, ..] => return ScalaTypeNamespaceResolution::Ambiguous,
                [] if next_is_ambiguous => return ScalaTypeNamespaceResolution::Ambiguous,
                [] => level = next,
            }
        }
    }

    ScalaTypeNamespaceResolution::NoMatch
}

fn unique_units(units: Vec<CodeUnit>) -> Vec<CodeUnit> {
    let mut seen = HashSet::default();
    units
        .into_iter()
        .filter(|unit| seen.insert(unit.clone()))
        .collect()
}

/// The nearest parser-proven type binding which intentionally has no stable
/// `CodeUnit` identity of its own.
///
/// Type parameters and local aliases are authoritative barriers. A type alias
/// directly inside an anonymous instance may instead refine an indexed member
/// of the exact constructed base; the inverse scanner retains the instance node
/// so it can prove that relationship without inventing an anonymous identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScalaUnindexedTypeBinding<'tree> {
    Authoritative,
    AnonymousRefinement(Node<'tree>),
}

pub(crate) fn scala_nearest_unindexed_type_binding<'tree>(
    source: &str,
    reference: Node<'tree>,
    root_name: &str,
) -> Option<ScalaUnindexedTypeBinding<'tree>> {
    if root_name.is_empty() {
        return None;
    }
    let name = root_name;

    let mut current = Some(reference);
    while let Some(node) = current {
        let parameters = node.child_by_field_name("type_parameters").or_else(|| {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find(|child| child.kind() == "type_parameters")
        });
        if let Some(parameters) = parameters
            && scala_type_parameters_declare(parameters, source, name)
        {
            return Some(ScalaUnindexedTypeBinding::Authoritative);
        }

        if node.kind() == "template_body"
            && let Some(instance) = scala_anonymous_instance_for_template(node)
        {
            let mut cursor = node.walk();
            let matches = node
                .named_children(&mut cursor)
                .filter(|child| matches!(child.kind(), "type_definition" | "type_declaration"))
                .filter(|child| {
                    child.child_by_field_name("name").is_some_and(|declared| {
                        source
                            .get(declared.byte_range())
                            .is_some_and(|text| text.trim() == name)
                    })
                })
                .collect::<Vec<_>>();
            return match matches.as_slice() {
                [definition] if definition.kind() == "type_definition" => {
                    let declaration_name = definition.child_by_field_name("name");
                    if declaration_name.is_some_and(|declared| declared == reference) {
                        Some(ScalaUnindexedTypeBinding::Authoritative)
                    } else {
                        Some(ScalaUnindexedTypeBinding::AnonymousRefinement(instance))
                    }
                }
                [_] | [_, _, ..] => Some(ScalaUnindexedTypeBinding::Authoritative),
                [] => {
                    current = node.parent();
                    continue;
                }
            };
        }

        if matches!(node.kind(), "block" | "indented_block") {
            let mut cursor = node.walk();
            if node.named_children(&mut cursor).any(|child| {
                matches!(child.kind(), "type_definition" | "type_declaration")
                    && child.start_byte() < reference.start_byte()
                    && child.child_by_field_name("name").is_some_and(|alias| {
                        source
                            .get(alias.byte_range())
                            .is_some_and(|text| text.trim() == name)
                    })
            }) {
                return Some(ScalaUnindexedTypeBinding::Authoritative);
            }
        }
        current = node.parent();
    }
    None
}

pub(crate) fn scala_anonymous_instance_for_template<'tree>(
    template: Node<'tree>,
) -> Option<Node<'tree>> {
    let parent = template.parent()?;
    if parent.kind() == "instance_expression" {
        return Some(parent);
    }
    parent
        .parent()
        .filter(|grandparent| grandparent.kind() == "instance_expression")
}

/// Compatibility predicate for definition lookup, which already knows how to
/// resolve anonymous refinements through its forward path. Only ordinary local
/// bindings should prevent that path from continuing.
pub(crate) fn scala_unindexed_type_binding_shadows(
    source: &str,
    reference: Node<'_>,
    root_name: &str,
) -> bool {
    matches!(
        scala_nearest_unindexed_type_binding(source, reference, root_name),
        Some(ScalaUnindexedTypeBinding::Authoritative)
    )
}

fn scala_type_parameters_declare(parameters: Node<'_>, source: &str, name: &str) -> bool {
    let mut cursor = parameters.walk();
    parameters.named_children(&mut cursor).any(|child| {
        let declared_name = child.child_by_field_name("name").unwrap_or(child);
        matches!(
            declared_name.kind(),
            "identifier" | "operator_identifier" | "type_identifier"
        ) && source
            .get(declared_name.byte_range())
            .is_some_and(|text| text.trim() == name)
    })
}
