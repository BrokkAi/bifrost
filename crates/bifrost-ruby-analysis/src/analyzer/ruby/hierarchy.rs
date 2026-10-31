//! Ruby's `TypeHierarchyProvider` impl: the memo shell around
//! [`brokk_bifrost_ruby::hierarchy`].

use crate::analyzer::ruby::*;
use brokk_bifrost_core::analyzer::capabilities::HierarchyAnswer;

use brokk_bifrost_core::analyzer::capabilities::DescendantIndexScope;

use brokk_bifrost_core::analyzer::capabilities::build_direct_descendant_index;

use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_ruby::hierarchy::{
    build_ruby_types_by_identifier, ruby_direct_ancestors, ruby_supports_type_hierarchy,
};
use std::sync::Arc;

impl RubyAnalyzer {
    pub(crate) fn types_by_identifier(&self) -> std::sync::Arc<HashMap<String, Vec<CodeUnit>>> {
        self.types_by_identifier.read(
            &memo_attribution(self),
            |memo| {
                brokk_bifrost_analysis::analyzer::common::complete_query_cache_arc_cell(
                    self,
                    memo,
                    || build_ruby_types_by_identifier(self),
                )
            },
            |_| AuthorityInputs::SourceOf(&[Language::Ruby]),
        )
    }
}

impl TypeHierarchyProvider for RubyAnalyzer {
    fn supports_type_hierarchy(&self, code_unit: &CodeUnit) -> bool {
        ruby_supports_type_hierarchy(code_unit)
    }

    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> HierarchyAnswer {
        let ancestors = self
            .direct_ancestors
            .read(&memo_attribution(self), |cache, capture| {
                Ok::<_, std::convert::Infallible>(cache.get(code_unit).unwrap_or_else(|| {
                    let cache_fill =
                        brokk_bifrost_analysis::analyzer::common::QueryCacheFill::new(self);
                    let entry = Arc::new(capture.build_weighted(|| {
                        let ancestors: Vec<CodeUnit> = ruby_direct_ancestors(self, code_unit);
                        let ancestors = Arc::new(ancestors);
                        let bytes = weight_code_unit_vec(code_unit, &ancestors) as usize;
                        (ancestors, bytes)
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
        .expect("a whole-workspace descendant query cannot be cancelled")
    }
    fn get_direct_descendants_within(
        &self,
        code_unit: &CodeUnit,
        scope: &DescendantIndexScope<'_>,
    ) -> Result<HierarchyAnswer, brokk_bifrost_core::analyzer::capabilities::Cancelled> {
        self.direct_descendant_index.read(
            &memo_attribution(self),
            |memo| {
                brokk_bifrost_analysis::analyzer::common::complete_descendant_query(
                    self,
                    scope,
                    code_unit,
                    memo,
                    || build_direct_descendant_index(self, self, scope),
                    |_| {},
                )
            },
            |_| self.authority_inputs(),
        )
    }
}
