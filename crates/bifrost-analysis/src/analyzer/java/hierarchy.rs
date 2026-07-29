use super::imports::non_static_import_path;
use super::*;
use crate::analyzer::tree_sitter_analyzer::HierarchyDeclarationFacts;
use crate::analyzer::{CodeUnitType, DirectDescendantIndex, ImportInfo, Range};
use std::sync::Arc;

const HIERARCHY_FACT_BATCH_SIZE: usize = 4_096;

struct JavaHierarchyTypeBucket {
    winner: usize,
    declarations: Vec<usize>,
}

impl TypeHierarchyProvider for JavaAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if let Some(cached) = self.memo_caches.direct_ancestors.get(code_unit) {
            return (*cached).clone();
        }

        let ancestors: Vec<_> = self
            .inner
            .raw_supertypes_of(code_unit)
            .iter()
            .filter_map(|raw_name| self.resolve_forward_type_name(code_unit.source(), raw_name))
            .collect();
        self.memo_caches
            .direct_ancestors
            .insert(code_unit.clone(), Arc::new(ancestors.clone()));
        ancestors
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        self.memo_caches
            .direct_descendant_index
            .get_or_init(|| self.build_direct_descendant_index())
            .descendants(code_unit)
    }
}

impl JavaAnalyzer {
    pub(crate) fn is_interface(&self, code_unit: &CodeUnit) -> bool {
        code_unit.is_class()
            && self.signatures(code_unit).iter().any(|signature| {
                signature
                    .split_whitespace()
                    .any(|token| token == "interface")
            })
    }

    fn build_direct_descendant_index(&self) -> DirectDescendantIndex {
        let _scope = crate::profiling::scope("JavaAnalyzer::build_direct_descendant_index");
        let mut candidates = self
            .inner
            .hierarchy_declaration_facts_by_kind(CodeUnitType::Class)
            .unwrap_or_default();
        candidates.sort_by(|left, right| {
            left.declaration
                .source()
                .cmp(right.declaration.source())
                .then_with(|| left.declaration.cmp(&right.declaration))
        });
        let mut types_by_fq_name: HashMap<String, JavaHierarchyTypeBucket> = HashMap::default();
        for (index, facts) in candidates.iter().enumerate() {
            let candidate = &facts.declaration;
            let fq_name = candidate.fq_name();
            if let Some(bucket) = types_by_fq_name.get_mut(&fq_name) {
                let winner = &candidates[bucket.winner];
                if java_definition_sort_key(candidate, facts.primary_range.as_ref())
                    < java_definition_sort_key(&winner.declaration, winner.primary_range.as_ref())
                {
                    bucket.winner = index;
                }
                bucket.declarations.push(index);
            } else {
                types_by_fq_name.insert(
                    fq_name,
                    JavaHierarchyTypeBucket {
                        winner: index,
                        declarations: vec![index],
                    },
                );
            }
        }

        let mut index_by_node = HashMap::default();
        for (index, facts) in candidates.iter().enumerate() {
            index_by_node.insert(
                facts.declaration.clone(),
                u32::try_from(index).expect("Java hierarchy declarations must fit in a u32"),
            );
        }

        let mut edges = Vec::new();
        for batch_start in (0..candidates.len()).step_by(HIERARCHY_FACT_BATCH_SIZE) {
            let batch_end = (batch_start + HIERARCHY_FACT_BATCH_SIZE).min(candidates.len());
            let mut batch = candidates[batch_start..batch_end].to_vec();
            if self
                .inner
                .hydrate_hierarchy_declaration_facts(&mut batch)
                .is_none()
            {
                continue;
            }
            for (offset, facts) in batch.iter().enumerate() {
                let candidate_index = batch_start + offset;
                let candidate = &facts.declaration;
                let descendant = u32::try_from(candidate_index)
                    .expect("Java hierarchy declarations must fit in a u32");
                for raw in facts.raw_supertypes.iter() {
                    let Some(resolved) = resolve_hierarchy_type_index(
                        raw,
                        candidate.package_name(),
                        &facts.imports,
                        &types_by_fq_name,
                    ) else {
                        continue;
                    };
                    let ancestor = same_source_hierarchy_identity(
                        resolved,
                        candidate,
                        &candidates,
                        &types_by_fq_name,
                    );
                    edges.push((
                        u32::try_from(ancestor)
                            .expect("Java hierarchy declarations must fit in a u32"),
                        descendant,
                    ));
                }
            }
        }

        let nodes = candidates
            .into_iter()
            .map(|facts| facts.declaration)
            .collect();
        DirectDescendantIndex::from_indexed_nodes(nodes, index_by_node, edges)
    }

    #[doc(hidden)]
    pub fn reset_hierarchy_query_counts_for_test(&self) {
        self.inner.reset_enclosing_parent_query_counts_for_test();
        self.inner.reset_full_hydration_count_for_test();
    }

    #[doc(hidden)]
    pub fn hierarchy_definition_query_count_for_test(&self) -> usize {
        self.inner.sql_definitions_query_count_for_test()
    }

    #[doc(hidden)]
    pub fn hierarchy_full_hydration_count_for_test(&self) -> usize {
        self.inner.full_hydration_count_for_test()
    }

    #[doc(hidden)]
    pub fn hierarchy_bulk_hydration_count_for_test(&self) -> usize {
        self.inner.bulk_hydration_count_for_test()
    }

    #[doc(hidden)]
    pub fn reset_definition_query_count_for_test(&self) {
        self.inner.reset_enclosing_parent_query_counts_for_test();
    }

    #[doc(hidden)]
    pub fn definition_query_count_for_test(&self) -> usize {
        self.inner.sql_definitions_query_count_for_test()
    }
}

fn java_definition_sort_key(
    candidate: &CodeUnit,
    range: Option<&Range>,
) -> (usize, String, String, String, String) {
    (
        range.map_or(usize::MAX, |range| range.start_byte),
        candidate.source().to_string().to_ascii_lowercase(),
        candidate.fq_name().to_ascii_lowercase(),
        candidate.signature().unwrap_or("").to_ascii_lowercase(),
        format!("{:?}", candidate.kind()),
    )
}

fn resolve_hierarchy_type_index(
    raw_name: &str,
    package_name: &str,
    imports: &[ImportInfo],
    types_by_fq_name: &HashMap<String, JavaHierarchyTypeBucket>,
) -> Option<usize> {
    let normalized = raw_name.trim();
    if normalized.is_empty() {
        return None;
    }

    if normalized.contains('.')
        && let Some(index) = hierarchy_type_index(types_by_fq_name, normalized)
    {
        return Some(index);
    }

    for import in imports {
        let Some(import_path) = non_static_import_path(import) else {
            continue;
        };
        if import.is_wildcard {
            continue;
        }
        let Some(imported_name) = import.identifier.as_deref() else {
            continue;
        };
        if normalized == imported_name
            && let Some(index) = hierarchy_type_index(types_by_fq_name, import_path)
        {
            return Some(index);
        }
        if let Some(rest) = normalized
            .strip_prefix(imported_name)
            .and_then(|rest| rest.strip_prefix('.'))
        {
            let nested_fqn = format!("{import_path}.{rest}");
            if let Some(index) = hierarchy_type_index(types_by_fq_name, &nested_fqn) {
                return Some(index);
            }
        }
    }

    for import in imports {
        let Some(import_path) = non_static_import_path(import) else {
            continue;
        };
        if !import.is_wildcard {
            continue;
        }
        let package = import_path.trim_end_matches(".*");
        let fqn = format!("{package}.{normalized}");
        if let Some(index) = hierarchy_type_index(types_by_fq_name, &fqn) {
            return Some(index);
        }
    }

    let same_package_fqn = if package_name.is_empty() {
        normalized.to_string()
    } else {
        format!("{package_name}.{normalized}")
    };
    hierarchy_type_index(types_by_fq_name, &same_package_fqn)
        .or_else(|| hierarchy_type_index(types_by_fq_name, normalized))
}

fn hierarchy_type_index(
    types_by_fq_name: &HashMap<String, JavaHierarchyTypeBucket>,
    fq_name: &str,
) -> Option<usize> {
    types_by_fq_name.get(fq_name).map(|bucket| bucket.winner)
}

fn same_source_hierarchy_identity(
    resolved: usize,
    descendant: &CodeUnit,
    candidates: &[HierarchyDeclarationFacts],
    types_by_fq_name: &HashMap<String, JavaHierarchyTypeBucket>,
) -> usize {
    let bucket = &types_by_fq_name[&candidates[resolved].declaration.fq_name()];
    let mut same_source = bucket
        .declarations
        .iter()
        .copied()
        .filter(|index| candidates[*index].declaration.source() == descendant.source());
    let Some(exact) = same_source.next() else {
        return resolved;
    };
    if same_source.next().is_none() {
        exact
    } else {
        resolved
    }
}
