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

/// Whether an indexed lexical type lookup is blocked by a parser-proven local
/// type binding which intentionally has no stable `CodeUnit` identity.
///
/// Type parameters are visible throughout their owner. Local type aliases are
/// visible after their declaration in the active block. Both are authoritative
/// type-namespace bindings: callers must not fall through to an indexed class,
/// import, or package declaration with the same spelling.
pub(crate) fn scala_unindexed_type_binding_shadows(
    source: &str,
    reference: Node<'_>,
    root_name: &str,
) -> bool {
    if root_name.is_empty() {
        return false;
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
            return true;
        }

        if matches!(node.kind(), "block" | "indented_block") {
            let mut cursor = node.walk();
            if node.named_children(&mut cursor).any(|child| {
                child.kind() == "type_definition"
                    && child.start_byte() < reference.start_byte()
                    && child.child_by_field_name("name").is_some_and(|alias| {
                        source
                            .get(alias.byte_range())
                            .is_some_and(|text| text.trim() == name)
                    })
            }) {
                return true;
            }
        }
        current = node.parent();
    }
    false
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
