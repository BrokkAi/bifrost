//! Java's `TypeHierarchyProvider` impl and the two cells behind it.
//!
//! The supertype-name resolution and the ancestor-to-descendant walk moved to
//! [`brokk_bifrost_jvm::java::hierarchy`]. What stays is the moka ancestor
//! cache, the `OnceLock` descendant index, the persisted hierarchy row type the
//! walk reads through [`JavaHierarchyFact`], and the query-count test hooks.

use super::*;
use crate::analyzer::read_ledger::{LookupKind, LookupQuestion, ReadKey, declaration_set_digest};
use crate::analyzer::tree_sitter_analyzer::HierarchyDeclarationFacts;
use crate::analyzer::{
    CodeUnitType, DescendantIndexScope, DirectDescendantIndex, ImportInfo, Range,
    descendants_from_variant_index,
};
use crate::cancellation::CancellationToken;
use brokk_bifrost_jvm::java::hierarchy::{
    JavaHierarchyFact, build_java_direct_descendant_index, java_direct_ancestors,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

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
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        if let Some(cached) = self.memo_caches.direct_ancestors.get(code_unit) {
            return (*cached).clone();
        }

        let ancestors = java_direct_ancestors(self, token, code_unit);
        self.memo_caches
            .direct_ancestors
            .insert(code_unit.clone(), Arc::new(ancestors.clone()));
        ancestors
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        let uncancelled = CancellationToken::default();
        self.get_direct_descendants_within(
            code_unit,
            &DescendantIndexScope::whole_workspace(&uncancelled),
        )
        .expect("a descendant index that cannot stop always completes")
    }

    fn get_direct_descendants_within(
        &self,
        code_unit: &CodeUnit,
        scope: &DescendantIndexScope<'_>,
    ) -> Option<HashSet<CodeUnit>> {
        let descendants = descendants_from_variant_index(
            &self.memo_caches.direct_descendant_index,
            scope,
            code_unit,
            || self.build_direct_descendant_index(scope),
        );
        if !scope.cancellation().is_cancelled()
            && let Some(descendants) = descendants.as_ref()
        {
            self.inner.record_read_key(ReadKey::lookup(
                LookupKind::Descendants,
                LookupQuestion::declaration(code_unit),
                declaration_set_digest(descendants),
            ));
        }
        descendants
    }
}

impl JavaAnalyzer {
    fn build_direct_descendant_index(
        &self,
        scope: &DescendantIndexScope<'_>,
    ) -> Option<DirectDescendantIndex> {
        let _scope = crate::profiling::scope("JavaAnalyzer::build_direct_descendant_index");
        let candidates = self
            .inner
            .hierarchy_declaration_facts_by_kind_for_descendant_lookup(CodeUnitType::Class)?;
        let hydration_complete = AtomicBool::new(true);
        let index = build_java_direct_descendant_index(
            candidates,
            |batch| {
                let complete = self
                    .inner
                    .hydrate_hierarchy_declaration_facts_for_descendant_lookup(batch)
                    .is_some();
                if !complete {
                    hydration_complete.store(false, Ordering::Relaxed);
                }
                complete
            },
            scope,
        );
        if !hydration_complete.load(Ordering::Relaxed) || scope.cancellation().is_cancelled() {
            None
        } else {
            index
        }
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
