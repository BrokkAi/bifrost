//! C#'s `TypeHierarchyProvider` impl and the two memo cells behind it.
//!
//! Attribute-class evidence and the direct-ancestor walk moved to
//! [`brokk_bifrost_csharp::hierarchy`]; the `direct_ancestors` moka cache and
//! the memoized `direct_descendant_index` stay on the analyzer, and
//! `build_direct_descendant_index` is generic over `IAnalyzer`, so the impl
//! stays here.

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::capabilities::DescendantIndexScope;

use brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider;

use brokk_bifrost_core::analyzer::capabilities::build_direct_descendant_index;

use brokk_bifrost_core::analyzer::capabilities::descendants_from_variant_index;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_csharp::hierarchy::logical_direct_ancestors;
use std::sync::Arc;

use crate::analyzer::csharp::CSharpAnalyzer;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::query_token::QueryScope;

impl TypeHierarchyProvider for CSharpAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        if let Some(cached) = self.memo_caches.direct_ancestors.get(code_unit) {
            return (*cached).clone();
        }
        let persistent_fill_guard =
            brokk_bifrost_analysis::analyzer::common::PersistentCacheFill::new(
                self,
                "crates/bifrost-csharp-analysis/src/analyzer/csharp/hierarchy_provider.rs",
            );

        let ancestors = logical_direct_ancestors(self, token, code_unit, false);
        {
            let cache_key = code_unit.clone();
            let cache_value = Arc::new(ancestors.clone());
            persistent_fill_guard.installed("direct_ancestors");
            self.memo_caches
                .direct_ancestors
                .insert(cache_key, cache_value);
        };
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
        descendants_from_variant_index(
            &self.memo_caches.direct_descendant_index,
            scope,
            code_unit,
            || {
                brokk_bifrost_analysis::analyzer::common::complete_query_cache_fill(self, || {
                    build_direct_descendant_index(self, self, scope)
                })
                .ok()
                .flatten()
            },
        )
    }
}
