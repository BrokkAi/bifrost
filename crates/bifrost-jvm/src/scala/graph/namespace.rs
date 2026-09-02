use brokk_bifrost_core::analyzer::CodeUnit;
use brokk_bifrost_core::hash::HashSet;
use tree_sitter::Node;

pub fn scala_type_reference_is_singleton(node: Node<'_>) -> bool {
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
pub fn scala_qualified_type_root(mut node: Node<'_>) -> Node<'_> {
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
///
/// `Ambiguous` carries the competing declarations themselves (#2167). The
/// resolver computed them to decide it could not choose, so an answer that
/// drops them is strictly less useful than what the resolver knew. The list is
/// empty in exactly one case: the tie was inherited from a supertype whose own
/// NAME is ambiguous AND whose competing declarations the producer could not
/// name, so this level never held a declaration of the name being resolved and
/// there is nothing about that name to report. A tie whose declarations ARE
/// known is decided per name instead, and reaches this outcome only when more
/// than one of them declares that name (#2229).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScalaTypeNamespaceResolution {
    NoMatch,
    Resolved(CodeUnit),
    Ambiguous(Vec<CodeUnit>),
    AuthoritativeMiss,
}

/// Exact root namespace selected for a structured qualified Scala type path.
///
/// Stable objects retain their physical declaration identity. Packages have
/// no declaration `CodeUnit`, so their canonical namespace name is retained
/// instead. Callers must treat every non-resolved outcome as terminal except
/// `NoMatch`, which alone permits a lower-precedence tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScalaQualifiedTypeRootBinding {
    StableObjects(Vec<CodeUnit>),
    Package(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScalaQualifiedTypeRootResolution {
    NoMatch,
    Resolved(ScalaQualifiedTypeRootBinding),
    Ambiguous,
    AuthoritativeMiss,
}

/// The competing declarations behind one owner's ambiguous supertype name.
///
/// `Named` lets a walk ask the question #2229 turns on: does this tie declare
/// the one name being looked up? `Unnamed` is the honest answer of a producer
/// that proved the tie from a name table and never held the declarations, so
/// that question cannot be asked of it and the walk must fail closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScalaTiedSupertypes {
    Named(Vec<CodeUnit>),
    Unnamed,
}

/// Outcome of resolving one owner's direct supertypes to exact declarations.
///
/// The two negative outcomes are not the same thing, and conflating them was
/// the #1849/#1851 defect. `Ambiguous` means a supertype NAME has more than one
/// indexed declaration: the workspace holds the member, it just cannot say
/// which declaration owns it. `Incomplete` means a supertype is not indexed
/// here at all: it can never contribute a member this workspace could name, so
/// a walk carries on over the ancestors it did resolve. Only a caller that must
/// report why an answer is unproven needs to tell `Incomplete` from `Resolved`.
///
/// `Ambiguous` keeps the tier whole: `resolved` holds the supertypes at that
/// tier whose names DID single out one declaration, and `tied` holds the
/// competing declarations of the one that did not. A tie is disqualifying only
/// for the names its declarations could supply (#2229), so a walk needs both
/// halves to decide one name at that tier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScalaDirectAncestorResolution {
    Resolved(Vec<CodeUnit>),
    Ambiguous {
        resolved: Vec<CodeUnit>,
        tied: ScalaTiedSupertypes,
    },
    Incomplete(Vec<CodeUnit>),
}

/// What a tied supertype tier declares for one looked-up name.
///
/// This is the whole of the #2229 rule, stated once for every walk that meets a
/// tie. A tie between supertype declarations says nothing about a name none of
/// them declares, so ask each tied declaration for the name exactly as the walk
/// asks a resolved ancestor at the same tier, and hand the answers back to that
/// tier's ordinary one/many decision: none declares it and the walk continues
/// outward, exactly one declares it and that declaration is the answer, more
/// than one declares it and the tier is genuinely ambiguous with those
/// declarations as its contenders (#2167).
///
/// Tied declarations answer for their own tier and are never expanded past it:
/// which of them the compiler actually sees is unknown, so their own
/// hierarchies are not this workspace's to walk.
pub fn scala_tied_tier_declarations<DirectMembers>(
    tied: &[CodeUnit],
    name: &str,
    mut direct_members: DirectMembers,
) -> Vec<CodeUnit>
where
    DirectMembers: FnMut(&CodeUnit, &str) -> Vec<CodeUnit>,
{
    tied.iter()
        .flat_map(|declaration| direct_members(declaration, name))
        .collect()
}

/// Resolve an unqualified Scala type name against exact enclosing owners.
///
/// Enclosing owners must be supplied nearest-first. A direct declaration wins
/// regardless of source order. If no direct declaration exists, inherited
/// members are considered breadth-first so a nearer ancestor tier wins. The
/// exact `CodeUnit` is retained throughout: the same base reached through a
/// diamond is deduplicated, while distinct declarations at the winning tier
/// are ambiguous even when they render the same fqn.
///
/// A tier whose supertype name tied is not a stop: its tied declarations join
/// that tier through [`scala_tied_tier_declarations`] and the same one/many
/// rule decides (#2229).
pub fn resolve_exact_lexical_type_namespace<Owners, DirectMembers, DirectAncestors>(
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
            [_, _, ..] => return ScalaTypeNamespaceResolution::Ambiguous(direct),
            [] => {}
        }

        let (mut level, mut tied) = match direct_ancestors(&owner) {
            ScalaDirectAncestorResolution::Resolved(ancestors)
            | ScalaDirectAncestorResolution::Incomplete(ancestors) => (ancestors, Vec::new()),
            ScalaDirectAncestorResolution::Ambiguous {
                resolved,
                tied: ScalaTiedSupertypes::Named(tied),
            } => (resolved, tied),
            // no contenders: the tie is the SUPERTYPE name's, not this name's,
            // and this producer cannot name the declarations behind it, so
            // whether they declare `name` is unknowable here (#2167).
            ScalaDirectAncestorResolution::Ambiguous {
                tied: ScalaTiedSupertypes::Unnamed,
                ..
            } => {
                return ScalaTypeNamespaceResolution::Ambiguous(Vec::new());
            }
        };
        let mut seen = HashSet::from_iter([owner]);
        while !level.is_empty() || !tied.is_empty() {
            let mut matches = scala_tied_tier_declarations(&tied, name, &mut direct_members);
            let mut next = Vec::new();
            let mut next_tied = Vec::new();
            let mut next_tie_is_unnamed = false;
            for ancestor in level {
                if !seen.insert(ancestor.clone()) {
                    continue;
                }
                matches.extend(direct_members(&ancestor, name));
                match direct_ancestors(&ancestor) {
                    ScalaDirectAncestorResolution::Resolved(ancestors)
                    | ScalaDirectAncestorResolution::Incomplete(ancestors) => {
                        next.extend(ancestors)
                    }
                    ScalaDirectAncestorResolution::Ambiguous {
                        resolved,
                        tied: ScalaTiedSupertypes::Named(tied),
                    } => {
                        next.extend(resolved);
                        next_tied.extend(tied);
                    }
                    ScalaDirectAncestorResolution::Ambiguous {
                        tied: ScalaTiedSupertypes::Unnamed,
                        ..
                    } => next_tie_is_unnamed = true,
                }
            }
            let matches = unique_units(matches);
            match matches.as_slice() {
                [declaration] => {
                    return ScalaTypeNamespaceResolution::Resolved(declaration.clone());
                }
                [_, _, ..] => return ScalaTypeNamespaceResolution::Ambiguous(matches),
                // no contenders: see the direct-ancestor arm above.
                [] if next_tie_is_unnamed => {
                    return ScalaTypeNamespaceResolution::Ambiguous(Vec::new());
                }
                [] => {
                    level = next;
                    tied = next_tied;
                }
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
pub enum ScalaUnindexedTypeBinding<'tree> {
    Authoritative,
    AnonymousRefinement(Node<'tree>),
}

pub fn scala_nearest_unindexed_type_binding<'tree>(
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

pub fn scala_anonymous_instance_for_template<'tree>(template: Node<'tree>) -> Option<Node<'tree>> {
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
pub fn scala_unindexed_type_binding_shadows(
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
