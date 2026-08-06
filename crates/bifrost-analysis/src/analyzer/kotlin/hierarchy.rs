//! `KotlinAnalyzer`'s `TypeHierarchyProvider` impl and the four realm-keyed
//! cells behind it.
//!
//! The supertype-name resolution and the ancestor-to-descendant inversion moved
//! to [`brokk_bifrost_jvm::kotlin::hierarchy`]. What stays is the two moka
//! ancestor caches, the two `OnceLock` descendant indexes, and the persisted
//! hierarchy row type the walk reads through [`KotlinHierarchyFact`]. Each pair
//! is realm-keyed because the realm-aware and realm-less answers are different
//! questions, and a Kotlin-only entry must never be served to a caller that can
//! see Java and Scala declarations too.

use crate::analyzer::tree_sitter_analyzer::HierarchyDeclarationFacts;
use crate::analyzer::{
    CodeUnit, CodeUnitType, DirectDescendantIndex, ImportInfo, TypeHierarchyProvider,
};
use crate::hash::HashSet;
use brokk_bifrost_jvm::kotlin::hierarchy::{
    KotlinHierarchyFact, build_kotlin_direct_descendant_index, kotlin_resolve_direct_ancestors,
};
use brokk_bifrost_jvm::realm::JvmSourceRealm;
use std::sync::Arc;

use super::KotlinAnalyzer;

impl KotlinHierarchyFact for HierarchyDeclarationFacts {
    fn declaration(&self) -> &CodeUnit {
        &self.declaration
    }

    fn imports(&self) -> &[ImportInfo] {
        &self.imports
    }

    fn raw_supertypes(&self) -> &[String] {
        &self.raw_supertypes
    }
}

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
        let ancestors = kotlin_resolve_direct_ancestors(self, code_unit, realm);
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

    fn build_direct_descendant_index(
        &self,
        realm: Option<&JvmSourceRealm<'_>>,
    ) -> DirectDescendantIndex {
        let _scope = crate::profiling::scope("KotlinAnalyzer::build_direct_descendant_index");
        let candidates = self
            .inner
            .hierarchy_declaration_facts_by_kind(CodeUnitType::Class)
            .unwrap_or_default();
        build_kotlin_direct_descendant_index(
            candidates,
            |batch| {
                self.inner
                    .hydrate_hierarchy_declaration_facts(batch)
                    .is_some()
            },
            self,
            realm,
        )
    }
}
