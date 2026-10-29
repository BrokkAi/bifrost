//! Ruby's `TypeHierarchyProvider` impl: the memo shell around
//! [`brokk_bifrost_ruby::hierarchy`].

use crate::analyzer::ruby::*;

use brokk_bifrost_core::analyzer::capabilities::DescendantIndexScope;

use brokk_bifrost_core::analyzer::capabilities::build_direct_descendant_index;

use brokk_bifrost_core::analyzer::capabilities::descendants_from_variant_index;

use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_ruby::hierarchy::{
    build_ruby_types_by_identifier, ruby_direct_ancestors, ruby_supports_type_hierarchy,
};
use std::sync::Arc;

impl RubyAnalyzer {
    pub(crate) fn types_by_identifier(&self) -> &HashMap<String, Vec<CodeUnit>> {
        self.types_by_identifier.get_or_init(|| {
            brokk_bifrost_analysis::analyzer::common::persistent_cache_fill(
                self,
                "ruby.types_by_identifier",
                || build_ruby_types_by_identifier(self),
            )
        })
    }
}

impl TypeHierarchyProvider for RubyAnalyzer {
    fn supports_type_hierarchy(&self, code_unit: &CodeUnit) -> bool {
        ruby_supports_type_hierarchy(code_unit)
    }

    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if let Some(cached) = self.direct_ancestors.get(code_unit) {
            return (*cached).clone();
        }
        let persistent_fill_guard =
            brokk_bifrost_analysis::analyzer::common::PersistentCacheFill::new(
                self,
                "crates/bifrost-ruby-analysis/src/analyzer/ruby/hierarchy.rs",
            );

        let ancestors = ruby_direct_ancestors(self, code_unit);
        {
            let cache_key = code_unit.clone();
            let cache_value = Arc::new(ancestors.clone());
            persistent_fill_guard.installed("direct_ancestors");
            self.direct_ancestors.insert(cache_key, cache_value);
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
        descendants_from_variant_index(&self.direct_descendant_index, scope, code_unit, || {
            brokk_bifrost_analysis::analyzer::common::complete_query_cache_fill(self, || {
                build_direct_descendant_index(self, self, scope)
            })
            .ok()
            .flatten()
        })
    }
}
