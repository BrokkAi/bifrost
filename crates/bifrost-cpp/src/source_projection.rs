//! Exact construction-ID projection of one coordinated extraction into a dialect.
//!
//! Recovery trees belong to their requesting dialect. Their allocations must
//! not shift another dialect's content IDs when both readings are requested.
//! Primary nodes are ordered by the shared driver's AST event ordinal; other
//! occurrences retain this dialect's construction order. No ranges are joined.

use brokk_bifrost_core::analyzer::CodeUnit;
use brokk_bifrost_core::analyzer::parsed_file::{ParsedSourceFacts, SourceDeclarationMetadataLink};
use brokk_bifrost_core::analyzer::source_facts::{
    SourceDeclaration, SourceDeclarationId, SourceFactRows, SourceOccurrenceId,
};
use brokk_bifrost_core::analyzer::structural::facts::StructuralFactRows;
use brokk_bifrost_core::compact_graph::CompactRowsBuilder;
use brokk_bifrost_core::hash::{HashMap, HashSet};

pub(crate) fn finalize_dialect(
    shared: &ParsedSourceFacts,
    declarations: &HashSet<SourceDeclarationId>,
    primary_ordinals: &HashMap<SourceOccurrenceId, usize>,
    units: &mut Vec<(SourceDeclarationId, CodeUnit)>,
    metadata: &mut Vec<SourceDeclarationMetadataLink>,
) -> ParsedSourceFacts {
    assert!(shared.native_site_occurrences.is_empty());
    assert!(shared.native_declaration_sources.is_empty());
    let mut facts = shared.clone();
    let cpp = facts.cpp.as_mut().expect("C++ coordinated family");
    cpp.declarations
        .retain(|fact| declarations.contains(&fact.declaration));
    let mut needed = HashSet::default();
    for &id in declarations {
        let declaration = shared.occurrences.declaration(id);
        needed.insert(declaration.occurrence);
        needed.extend(declaration.name);
    }
    for fact in &cpp.declarations {
        needed.extend(fact.conditional_family);
        needed.extend(fact.exhaustive_conditional_family);
        needed.extend(fact.displaced_namespace_closing_brace);
    }
    for include in &cpp.includes {
        needed.extend([include.declaration, include.target]);
    }
    needed.extend(cpp.using_namespaces.iter().map(|(id, _)| *id));
    for import in &shared.imports {
        needed.insert(import.declaration);
        needed.extend(import.target);
        needed.extend(import.alias_occurrence);
        if let Some(path) = &import.path {
            needed.extend(path.lexical_scopes.iter().copied());
        }
    }
    for (index, node) in shared.structural.nodes().iter().enumerate() {
        needed.insert(node.occurrence);
        needed.extend(node.name);
        for role in shared.structural.roles(index as u32) {
            needed.insert(role.occurrence);
            needed.extend(role.name);
            needed.extend(role.keyword);
        }
    }
    let mut occurrence_ids: Vec<_> = needed.into_iter().collect();
    occurrence_ids.sort_unstable_by_key(|id| {
        primary_ordinals
            .get(id)
            .map_or((1, id.index()), |ordinal| (0, *ordinal))
    });
    let occurrence_map: HashMap<_, _> = occurrence_ids
        .iter()
        .enumerate()
        .map(|(index, &old)| {
            (
                old,
                SourceOccurrenceId::try_from_index(index).expect("source occurrence ID"),
            )
        })
        .collect();
    let occurrence = |id: SourceOccurrenceId| occurrence_map[&id];
    let mut declaration_ids: Vec<_> = declarations.iter().copied().collect();
    declaration_ids.sort_unstable_by_key(|id| {
        let declaration = shared.occurrences.declaration(*id);
        (
            occurrence(declaration.occurrence).get(),
            declaration.name.map(|name| occurrence(name).get()),
        )
    });
    let declaration_map: HashMap<_, _> = declaration_ids
        .iter()
        .enumerate()
        .map(|(index, &old)| {
            (
                old,
                SourceDeclarationId::try_from_index(index).expect("source declaration ID"),
            )
        })
        .collect();
    facts.occurrences = SourceFactRows::new(
        occurrence_ids
            .iter()
            .map(|&id| *shared.occurrences.occurrence(id))
            .collect(),
        declaration_ids
            .iter()
            .map(|&id| {
                let old = shared.occurrences.declaration(id);
                SourceDeclaration {
                    occurrence: occurrence(old.occurrence),
                    name: old.name.map(occurrence),
                }
            })
            .collect(),
    );
    let mut nodes = shared.structural.nodes().to_vec();
    let mut roles = CompactRowsBuilder::with_capacity(nodes.len(), shared.structural.role_count());
    let mut occurrence_roles =
        CompactRowsBuilder::with_capacity(nodes.len(), shared.structural.occurrence_role_count());
    for (index, node) in nodes.iter_mut().enumerate() {
        node.occurrence = occurrence(node.occurrence);
        node.name = node.name.map(occurrence);
        roles.push_row(
            shared
                .structural
                .roles(index as u32)
                .iter()
                .cloned()
                .map(|mut role| {
                    role.occurrence = occurrence(role.occurrence);
                    role.name = role.name.map(occurrence);
                    role.keyword = role.keyword.map(occurrence);
                    role
                }),
        );
        occurrence_roles.push_row(
            shared
                .structural
                .occurrence_roles(index as u32)
                .iter()
                .copied(),
        );
    }
    facts.structural = StructuralFactRows::new(nodes, roles.finish(), occurrence_roles.finish());
    for import in &mut facts.imports {
        import.declaration = occurrence(import.declaration);
        import.target = import.target.map(occurrence);
        import.alias_occurrence = import.alias_occurrence.map(occurrence);
        if let Some(path) = &mut import.path {
            for scope in &mut path.lexical_scopes {
                *scope = occurrence(*scope);
            }
        }
    }
    for fact in &mut cpp.declarations {
        fact.declaration = declaration_map[&fact.declaration];
        fact.conditional_family = fact.conditional_family.map(occurrence);
        fact.exhaustive_conditional_family = fact.exhaustive_conditional_family.map(occurrence);
        fact.displaced_namespace_closing_brace =
            fact.displaced_namespace_closing_brace.map(occurrence);
    }
    cpp.declarations
        .sort_unstable_by_key(|fact| fact.declaration.get());
    for include in &mut cpp.includes {
        include.declaration = occurrence(include.declaration);
        include.target = occurrence(include.target);
    }
    for (id, _) in &mut cpp.using_namespaces {
        *id = occurrence(*id);
    }
    let mounted: HashSet<_> = units.iter().cloned().collect();
    metadata.retain(|link| mounted.contains(&(link.declaration, link.unit.clone())));
    for (id, _) in units {
        *id = declaration_map[id];
    }
    for link in metadata {
        link.declaration = declaration_map[&link.declaration];
    }
    assert!(cpp.valid_links(&facts.occurrences));
    facts
}
