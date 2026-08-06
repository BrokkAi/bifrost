//! Java's `TypeHierarchyProvider` impl and the two cells behind it.
//!
//! The supertype-name resolution and the ancestor-to-descendant walk moved to
//! [`brokk_bifrost_jvm::java::hierarchy`]. What stays is the moka ancestor
//! cache, the `OnceLock` descendant index, the persisted hierarchy row type the
//! walk reads through [`JavaHierarchyFact`], and the query-count test hooks.

use super::*;
use crate::analyzer::tree_sitter_analyzer::HierarchyDeclarationFacts;
use crate::analyzer::{CodeUnitType, DirectDescendantIndex, ImportInfo, Range};
use brokk_bifrost_jvm::java::hierarchy::{
    JavaHierarchyFact, build_java_direct_descendant_index, java_direct_ancestors,
};
use std::sync::Arc;

impl JavaHierarchyFact for HierarchyDeclarationFacts {
    fn declaration(&self) -> &CodeUnit {
        &self.declaration
    }

    fn primary_range(&self) -> Option<&Range> {
        self.primary_range.as_ref()
    }

    fn imports(&self) -> &[ImportInfo] {
        &self.imports
    }

    fn raw_supertypes(&self) -> &[String] {
        &self.raw_supertypes
    }
}

impl TypeHierarchyProvider for JavaAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if let Some(cached) = self.memo_caches.direct_ancestors.get(code_unit) {
            return (*cached).clone();
        }

        let ancestors = java_direct_ancestors(self, code_unit);
        self.memo_caches
            .direct_ancestors
            .insert(code_unit.clone(), Arc::new(ancestors.clone()));
        ancestors
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        // The builder itself is serial, so the same closure serves both memo
        // arms; the memo's value here is the non-blocking claim protocol.
        self.memo_caches
            .direct_descendant_index
            .get_or_build(
                || self.build_direct_descendant_index(),
                || self.build_direct_descendant_index(),
            )
            .descendants(code_unit)
    }
}

impl JavaAnalyzer {
    fn build_direct_descendant_index(&self) -> DirectDescendantIndex {
        let _scope = crate::profiling::scope("JavaAnalyzer::build_direct_descendant_index");
        let candidates = self
            .inner
            .hierarchy_declaration_facts_by_kind(CodeUnitType::Class)
            .unwrap_or_default();
        build_java_direct_descendant_index(candidates, |batch| {
            self.inner
                .hydrate_hierarchy_declaration_facts(batch)
                .is_some()
        })
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
