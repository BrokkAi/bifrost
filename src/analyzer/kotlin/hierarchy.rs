//! Kotlin type hierarchy (#1237).
//!
//! Ancestors come from the dotted supertype paths recorded at index time,
//! resolved through Kotlin's name-resolution ladder. Descendants are the
//! inverse, built once per analyzer generation over the shared batched
//! declaration-facts path that Java's hierarchy already uses — the facts carry
//! each candidate's supertype paths and imports together, so inverting the
//! whole workspace costs one hydration pass rather than one per class.

use crate::analyzer::{
    CodeUnit, CodeUnitType, DirectDescendantIndex, ImportInfo, TypeHierarchyProvider,
};
use crate::hash::{HashMap, HashSet};
use std::sync::Arc;

use super::KotlinAnalyzer;
use super::types::{KotlinNameScope, KotlinTypeName, resolve_kotlin_type_name};

/// How many declarations are hydrated per store round-trip while inverting the
/// hierarchy. Matches the Java hierarchy's batch size for the same reason:
/// large enough to amortize the query, small enough to bound peak memory.
const HIERARCHY_FACT_BATCH_SIZE: usize = 4_096;

impl TypeHierarchyProvider for KotlinAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if let Some(cached) = self.direct_ancestors.get(code_unit) {
            return (*cached).clone();
        }
        let ancestors = self.resolve_direct_ancestors(code_unit);
        self.direct_ancestors
            .insert(code_unit.clone(), Arc::new(ancestors.clone()));
        ancestors
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        self.direct_descendant_index
            .get_or_init(|| self.build_direct_descendant_index())
            .descendants(code_unit)
    }
}

impl KotlinAnalyzer {
    fn resolve_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if !code_unit.is_class() {
            return Vec::new();
        }
        let mut ancestors = Vec::new();
        let mut seen = HashSet::default();
        for spelled in self.inner.raw_supertypes_of(code_unit) {
            let Some(resolution) = self.resolve_type_name_for_owner(code_unit, &spelled) else {
                // An unresolvable supertype yields no ancestor. Kotlin code
                // routinely extends types from dependencies that are not on the
                // configured classpath, and inventing a declaration for one
                // would put a name in the hierarchy that no query can open.
                continue;
            };
            if let super::types::KotlinTypeResolution::Source(unit) = resolution
                && seen.insert(unit.fq_name())
            {
                ancestors.push(unit);
            }
        }
        ancestors
    }

    fn build_direct_descendant_index(&self) -> DirectDescendantIndex {
        let _scope = crate::profiling::scope("KotlinAnalyzer::build_direct_descendant_index");
        let mut candidates = self
            .inner
            .hierarchy_declaration_facts_by_kind(CodeUnitType::Class)
            .unwrap_or_default();
        candidates.sort_by(|left, right| left.declaration.cmp(&right.declaration));

        // Resolving a supertype needs the whole candidate set as its existence
        // oracle, so the fq-name view is built first and the batched hydration
        // below only supplies each candidate's own spelled supertypes and
        // imports.
        let mut ancestors_by_owner: HashMap<CodeUnit, Vec<CodeUnit>> = HashMap::default();
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
            for facts in &batch {
                let resolved = self.resolve_ancestors_from_facts(
                    &facts.declaration,
                    &facts.raw_supertypes,
                    &facts.imports,
                );
                if !resolved.is_empty() {
                    ancestors_by_owner.insert(facts.declaration.clone(), resolved);
                }
            }
        }

        crate::analyzer::capabilities::build_direct_descendant_index_from_candidates(
            candidates
                .into_iter()
                .map(|facts| facts.declaration)
                .collect(),
            |candidate| {
                ancestors_by_owner
                    .get(candidate)
                    .cloned()
                    .unwrap_or_default()
            },
        )
    }

    /// Resolve one declaration's ancestors from facts already in hand, without
    /// re-reading its file.
    fn resolve_ancestors_from_facts(
        &self,
        owner: &CodeUnit,
        raw_supertypes: &[String],
        imports: &[ImportInfo],
    ) -> Vec<CodeUnit> {
        if raw_supertypes.is_empty() {
            return Vec::new();
        }
        let scope = KotlinNameScope {
            package_name: owner.package_name(),
            imports,
            scope_owners: self.scope_owners_for(owner),
        };
        let mut ancestors = Vec::new();
        let mut seen = HashSet::default();
        for spelled in raw_supertypes {
            let KotlinTypeName::Resolved(fqn) =
                resolve_kotlin_type_name(spelled, &scope, |candidate| {
                    self.source_type_exists(candidate)
                })
            else {
                continue;
            };
            if let Some(unit) = self.source_type_by_fqn(&fqn)
                && seen.insert(unit.fq_name())
            {
                ancestors.push(unit);
            }
        }
        ancestors
    }
}
