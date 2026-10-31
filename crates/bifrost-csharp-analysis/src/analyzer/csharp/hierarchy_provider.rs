//! C#'s `TypeHierarchyProvider` impl and the two memo cells behind it.
//!
//! Attribute-class evidence and the direct-ancestor walk moved to
//! [`brokk_bifrost_csharp::hierarchy`]; the `direct_ancestors` moka cache and
//! the memoized `direct_descendant_index` stay on the analyzer, and
//! `build_direct_descendant_index` is generic over `IAnalyzer`, so the impl
//! stays here.

use brokk_bifrost_analysis::analyzer::workspace_authority::{AuthorityInputs, memo_attribution};

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::capabilities::DescendantIndexScope;

use brokk_bifrost_core::analyzer::capabilities::{HierarchyAnswer, TypeHierarchyProvider};

use brokk_bifrost_core::analyzer::capabilities::build_direct_descendant_index;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_csharp::hierarchy::logical_direct_ancestors;
use std::sync::Arc;

use crate::analyzer::csharp::CSharpAnalyzer;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::query_token::QueryScope;

impl TypeHierarchyProvider for CSharpAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> HierarchyAnswer {
        let scope = AnalyzerQueryScope::new(self);
        let token = scope.token();
        let cache_fill = brokk_bifrost_analysis::analyzer::common::QueryCacheFill::new(self);
        let ancestors = self
            .memo_caches
            .direct_ancestors
            .read(&memo_attribution(self), |cache, capture| {
                Ok::<_, std::convert::Infallible>(cache.get(code_unit).unwrap_or_else(|| {
                    let entry = Arc::new(capture.build_weighted(|| {
                        let ancestors = logical_direct_ancestors(self, token, code_unit, false);
                        let bytes = super::cache::estimate_code_unit_vec(&ancestors) as usize;
                        (Arc::new(ancestors), bytes)
                    }));
                    if cache_fill.is_complete() {
                        cache.insert(code_unit.clone(), Arc::clone(&entry));
                    }
                    entry
                }))
            })
            .expect("ancestor memo build is infallible");
        HierarchyAnswer::complete((**ancestors).clone())
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HierarchyAnswer {
        let uncancelled = CancellationToken::default();
        self.get_direct_descendants_within(
            code_unit,
            &DescendantIndexScope::whole_workspace(&uncancelled),
        )
        .expect("an uncancelled descendant query cannot be cancelled")
    }
    fn get_direct_descendants_within(
        &self,
        code_unit: &CodeUnit,
        scope: &DescendantIndexScope<'_>,
    ) -> Result<HierarchyAnswer, brokk_bifrost_core::analyzer::capabilities::Cancelled> {
        self.memo_caches.direct_descendant_index.read(
            &memo_attribution(self),
            |direct_descendant_index_memo| {
                brokk_bifrost_analysis::analyzer::common::complete_descendant_query(
                    self,
                    scope,
                    code_unit,
                    direct_descendant_index_memo,
                    || build_direct_descendant_index(self, self, scope),
                    |_| {},
                )
            },
            |_| AuthorityInputs::SourceOf(&[brokk_bifrost_core::analyzer::model::Language::CSharp]),
        )
    }
}
