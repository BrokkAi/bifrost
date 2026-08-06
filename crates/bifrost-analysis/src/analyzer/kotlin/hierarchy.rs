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
use brokk_bifrost_jvm::realm::JvmSourceRealm;
use std::sync::Arc;

use super::KotlinAnalyzer;
use super::types::{KotlinNameScope, KotlinTypeName, resolve_kotlin_type_name};

/// How many declarations are hydrated per store round-trip while inverting the
/// hierarchy. Matches the Java hierarchy's batch size for the same reason:
/// large enough to amortize the query, small enough to bound peak memory.
const HIERARCHY_FACT_BATCH_SIZE: usize = 4_096;

impl TypeHierarchyProvider for KotlinAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.direct_ancestors_in_realm(code_unit, None)
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        self.direct_descendants_in_realm(code_unit, None)
    }
}

impl KotlinAnalyzer {
    /// Direct ancestors of a Kotlin declaration, widened to the whole JVM
    /// source realm when a realm view is supplied.
    ///
    /// The realm-aware and realm-less answers are cached separately: they are
    /// different questions, and a Kotlin-only cache entry must never be served
    /// to a caller that can see Java and Scala declarations too.
    pub(crate) fn direct_ancestors_in_realm(
        &self,
        code_unit: &CodeUnit,
        realm: Option<&JvmSourceRealm<'_>>,
    ) -> Vec<CodeUnit> {
        let cache = match realm {
            Some(_) => &self.realm_direct_ancestors,
            None => &self.direct_ancestors,
        };
        if let Some(cached) = cache.get(code_unit) {
            return (*cached).clone();
        }
        let ancestors = self.resolve_direct_ancestors(code_unit, realm);
        cache.insert(code_unit.clone(), Arc::new(ancestors.clone()));
        ancestors
    }

    pub(crate) fn direct_descendants_in_realm(
        &self,
        code_unit: &CodeUnit,
        realm: Option<&JvmSourceRealm<'_>>,
    ) -> HashSet<CodeUnit> {
        let index = match realm {
            Some(_) => &self.realm_direct_descendant_index,
            None => &self.direct_descendant_index,
        };
        index
            .get_or_init(|| self.build_direct_descendant_index(realm))
            .descendants(code_unit)
    }

    fn resolve_direct_ancestors(
        &self,
        code_unit: &CodeUnit,
        realm: Option<&JvmSourceRealm<'_>>,
    ) -> Vec<CodeUnit> {
        if !code_unit.is_class() {
            return Vec::new();
        }
        let raw_supertypes = self.inner.raw_supertypes_of(code_unit);
        if raw_supertypes.is_empty() {
            // Most classes declare nothing, and the scope below is the
            // expensive part — it walks the owner chain and every inherited
            // nested scope — so it is never built for them.
            return Vec::new();
        }
        let imports = self.inner.import_info_of(code_unit.source());
        self.resolve_ancestors_from_facts(code_unit, &raw_supertypes, &imports, realm)
    }

    fn build_direct_descendant_index(
        &self,
        realm: Option<&JvmSourceRealm<'_>>,
    ) -> DirectDescendantIndex {
        let _scope = crate::profiling::scope("KotlinAnalyzer::build_direct_descendant_index");
        let mut candidates = self
            .inner
            .hierarchy_declaration_facts_by_kind(CodeUnitType::Class)
            .unwrap_or_default();
        candidates.sort_by(|left, right| left.declaration.cmp(&right.declaration));

        // Hydration is batched because each candidate needs two facts that are
        // not in the candidate row itself — the supertypes it spells and the
        // file's imports — and fetching those one declaration at a time would
        // be a store round-trip per class.
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
                    realm,
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

    /// Resolve one declaration's ancestors from facts already in hand.
    ///
    /// A supertype that does not resolve yields no ancestor. Kotlin code
    /// routinely extends types from dependencies that are not on the configured
    /// classpath, and inventing a declaration for one would put a name in the
    /// hierarchy that no query can open.
    fn resolve_ancestors_from_facts(
        &self,
        owner: &CodeUnit,
        raw_supertypes: &[String],
        imports: &[ImportInfo],
        realm: Option<&JvmSourceRealm<'_>>,
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
                    self.realm_type_exists(candidate, realm)
                })
            else {
                continue;
            };
            if let Some(unit) = self.realm_type_by_fqn(&fqn, realm)
                && seen.insert(unit.fq_name())
            {
                ancestors.push(unit);
            }
        }
        ancestors
    }
}
