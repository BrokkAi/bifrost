//! Generation-wide C# runnable-test classification.
//!
//! C# test runners inherit attributed virtual methods. A concrete provider
//! suite may therefore contain no local `[Fact]` even though its base
//! declaration makes it runnable. The file graph needs that fact in bulk: a
//! per-file parser can identify the type that directly owns a runner method,
//! and this module propagates those owner identities through the structured
//! C# type hierarchy without invoking the interactive definition resolver.

use super::CSharpAnalyzer;
use crate::analyzer::tree_sitter_analyzer::HierarchyDeclarationFacts;
use crate::analyzer::{CodeUnit, CodeUnitType, ProjectFile};
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_csharp::graph_support::{
    first_logical_type_fqn, logical_type_count, supertype_candidates_with_lookups,
    visible_type_candidates_with_lookups,
};
use brokk_bifrost_csharp::imports::{csharp_using_alias_from_import, csharp_using_namespace};
use brokk_bifrost_csharp::syntax::{csharp_arity_preserving_full_name, csharp_normalize_full_name};
use std::collections::VecDeque;
use std::sync::Arc;

impl CSharpAnalyzer {
    pub(super) fn hierarchy_test_files(&self) -> Arc<HashSet<ProjectFile>> {
        self.memo_caches
            .hierarchy_test_files
            .get_or_build_on_dedicated_pool(|| {
                let Some(mut facts) = self
                    .inner
                    .hierarchy_declaration_facts_by_kind(CodeUnitType::Class)
                else {
                    return HashSet::default();
                };
                if self
                    .inner
                    .hydrate_hierarchy_declaration_facts(&mut facts)
                    .is_none()
                {
                    return directly_classified_files(&facts);
                }
                inherited_test_files(&facts)
            })
    }
}

fn directly_classified_files(facts: &[HierarchyDeclarationFacts]) -> HashSet<ProjectFile> {
    facts
        .iter()
        .filter(|fact| fact.in_test_region)
        .map(|fact| fact.declaration.source().clone())
        .collect()
}

fn inherited_test_files(facts: &[HierarchyDeclarationFacts]) -> HashSet<ProjectFile> {
    let mut types_by_normalized_fqn: HashMap<String, Vec<CodeUnit>> = HashMap::default();
    let mut declared_namespaces = HashSet::default();
    let mut global_namespaces = Vec::new();
    let mut global_aliases = HashMap::default();
    for fact in facts {
        types_by_normalized_fqn
            .entry(csharp_normalize_full_name(&fact.declaration.fq_name()))
            .or_default()
            .push(fact.declaration.clone());
        if !fact.declaration.package_name().is_empty() {
            declared_namespaces.insert(fact.declaration.package_name().to_string());
        }
        for import in fact.imports.iter().filter(|import| import.is_global) {
            if let Some(namespace) = csharp_using_namespace(import) {
                global_namespaces.push(namespace);
            }
            if let Some((alias, target)) = csharp_using_alias_from_import(import) {
                global_aliases.entry(alias).or_insert(target);
            }
        }
    }
    for declarations in types_by_normalized_fqn.values_mut() {
        declarations.sort();
        declarations.dedup();
    }
    global_namespaces.sort();
    global_namespaces.dedup();

    let candidates_for_fqn = |fqn: &str| {
        let normalized = csharp_normalize_full_name(fqn);
        let arity_key = csharp_arity_preserving_full_name(fqn);
        types_by_normalized_fqn
            .get(&normalized)
            .into_iter()
            .flatten()
            .filter(|candidate| {
                csharp_arity_preserving_full_name(&candidate.fq_name()) == arity_key
            })
            .cloned()
            .collect::<Vec<_>>()
    };

    let mut descendants_by_ancestor: HashMap<String, HashSet<String>> = HashMap::default();
    for fact in facts {
        if fact.raw_supertypes.is_empty() {
            continue;
        }
        let mut aliases = global_aliases.clone();
        let mut file_namespaces = Vec::new();
        for import in fact.imports.iter().filter(|import| !import.is_global) {
            if let Some(namespace) = csharp_using_namespace(import) {
                file_namespaces.push(namespace);
            }
            if let Some((alias, target)) = csharp_using_alias_from_import(import) {
                aliases.insert(alias, target);
            }
        }
        file_namespaces.sort();
        file_namespaces.dedup();
        let aliases = Arc::new(aliases);
        let namespace = fact.declaration.package_name().to_string();

        for raw_supertype in fact.raw_supertypes.iter() {
            let mut enclosing_candidates = |fqn: &str| Some(candidates_for_fqn(fqn));
            let mut visible_candidates = |name: &str| {
                visible_type_candidates_with_lookups(
                    name,
                    true,
                    &mut || Some(Arc::clone(&aliases)),
                    &mut || Some(namespace.clone()),
                    &mut || Some(file_namespaces.clone()),
                    &mut || Some(global_namespaces.clone()),
                    &mut |candidate_namespace| declared_namespaces.contains(candidate_namespace),
                    &mut |fqn| Some(candidates_for_fqn(fqn)),
                )
            };
            let candidates = supertype_candidates_with_lookups(
                &fact.declaration.fq_name(),
                raw_supertype,
                &mut enclosing_candidates,
                &mut visible_candidates,
            );
            if logical_type_count(&candidates) != 1 {
                continue;
            }
            let Some(ancestor) = first_logical_type_fqn(&candidates) else {
                continue;
            };
            let descendant = fact.declaration.fq_name();
            if ancestor != descendant {
                descendants_by_ancestor
                    .entry(ancestor)
                    .or_default()
                    .insert(descendant);
            }
        }
    }

    let mut reached_types = facts
        .iter()
        .filter(|fact| fact.in_test_region)
        .map(|fact| fact.declaration.fq_name())
        .collect::<HashSet<_>>();
    let mut queue = reached_types.iter().cloned().collect::<VecDeque<_>>();
    while let Some(ancestor) = queue.pop_front() {
        let Some(descendants) = descendants_by_ancestor.get(&ancestor) else {
            continue;
        };
        for descendant in descendants {
            if reached_types.insert(descendant.clone()) {
                queue.push_back(descendant.clone());
            }
        }
    }

    facts
        .iter()
        .filter(|fact| reached_types.contains(&fact.declaration.fq_name()))
        .map(|fact| fact.declaration.source().clone())
        .collect()
}
