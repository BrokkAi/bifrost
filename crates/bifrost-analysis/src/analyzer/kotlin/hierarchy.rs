//! `KotlinAnalyzer`'s `TypeHierarchyProvider` impl and the four realm-keyed
//! cells behind it.
//!
//! The supertype-name resolution and the ancestor-to-descendant inversion moved
//! to [`brokk_bifrost_jvm::kotlin::hierarchy`]. What stays is the two moka
//! ancestor caches, the two memoized descendant indexes, and the persisted
//! hierarchy row type the walk reads through [`KotlinHierarchyFact`]. Each pair
//! is realm-keyed because the realm-aware and realm-less answers are different
//! questions, and a Kotlin-only entry must never be served to a caller that can
//! see Java and Scala declarations too.

use crate::analyzer::tree_sitter_analyzer::HierarchyDeclarationFacts;
use crate::analyzer::{
    CodeUnit, CodeUnitType, DescendantIndexScope, DirectDescendantIndex, ImportInfo,
    TypeHierarchyProvider, descendants_from_variant_index,
};
use crate::cancellation::CancellationToken;
use crate::hash::HashSet;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_jvm::kotlin::hierarchy::{
    KotlinHierarchyFact, build_kotlin_direct_descendant_index, kotlin_resolve_direct_ancestors,
};
use brokk_bifrost_jvm::realm::JvmSourceRealm;
use std::sync::Arc;

use super::KotlinAnalyzer;
use crate::analyzer::{AnalyzerQueryScope, QueryScope};

impl KotlinHierarchyFact for HierarchyDeclarationFacts {
    fn declaration(&self) -> &CodeUnit {
        &self.declaration
    }

    fn primary_range(&self) -> Option<crate::analyzer::Range> {
        self.primary_range
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
        let query_scope = AnalyzerQueryScope::new(self);
        let token = query_scope.token();
        self.direct_ancestors_in_realm(token, code_unit, None)
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        let query_scope = AnalyzerQueryScope::new(self);
        let token = query_scope.token();
        let uncancelled = CancellationToken::default();
        self.direct_descendants_in_realm(
            token,
            code_unit,
            None,
            &DescendantIndexScope::whole_workspace(&uncancelled),
        )
        .expect("a descendant index that cannot stop always completes")
    }

    fn get_direct_descendants_within(
        &self,
        code_unit: &CodeUnit,
        scope: &DescendantIndexScope<'_>,
    ) -> Option<HashSet<CodeUnit>> {
        let query_scope = AnalyzerQueryScope::new(self);
        let token = query_scope.token();
        self.direct_descendants_in_realm(token, code_unit, None, scope)
    }
}

impl KotlinAnalyzer {
    /// Direct ancestors of a Kotlin declaration, widened to the whole JVM
    /// source realm when a realm view is supplied.
    pub(crate) fn direct_ancestors_in_realm(
        &self,
        token: QueryToken<'_>,
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
        let ancestors = kotlin_resolve_direct_ancestors(self, token, code_unit, realm);
        cache.insert(code_unit.clone(), Arc::new(ancestors.clone()));
        ancestors
    }

    pub(crate) fn direct_descendants_in_realm(
        &self,
        token: QueryToken<'_>,
        code_unit: &CodeUnit,
        realm: Option<&JvmSourceRealm<'_>>,
        scope: &DescendantIndexScope<'_>,
    ) -> Option<HashSet<CodeUnit>> {
        let index = match realm {
            Some(_) => &self.realm_direct_descendant_index,
            None => &self.direct_descendant_index,
        };
        descendants_from_variant_index(index, scope, code_unit, || {
            self.build_direct_descendant_index(token, realm, scope)
        })
    }

    fn build_direct_descendant_index(
        &self,
        token: QueryToken<'_>,
        realm: Option<&JvmSourceRealm<'_>>,
        scope: &DescendantIndexScope<'_>,
    ) -> Option<DirectDescendantIndex> {
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
            scope,
            token,
        )
    }
}
