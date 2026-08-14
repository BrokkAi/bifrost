//! C#'s `TypeHierarchyProvider` impl and the two memo cells behind it.
//!
//! Attribute-class evidence and the direct-ancestor walk moved to
//! [`brokk_bifrost_csharp::hierarchy`]; the `direct_ancestors` moka cache and
//! the memoized `direct_descendant_index` stay on the analyzer, and
//! `build_direct_descendant_index` is generic over `IAnalyzer`, so the impl
//! stays here.

use crate::analyzer::{
    CodeUnit, DescendantIndexScope, TypeHierarchyProvider, build_direct_descendant_index,
    descendants_from_variant_index,
};
use crate::cancellation::CancellationToken;
use crate::hash::HashSet;
use brokk_bifrost_csharp::hierarchy::logical_direct_ancestors;
use std::sync::Arc;

use super::CSharpAnalyzer;

impl TypeHierarchyProvider for CSharpAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if let Some(cached) = self.memo_caches.direct_ancestors.get(code_unit) {
            return (*cached).clone();
        }

        let ancestors = logical_direct_ancestors(self, code_unit, false);
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
        descendants_from_variant_index(
            &self.memo_caches.direct_descendant_index,
            scope,
            code_unit,
            || build_direct_descendant_index(self, self, scope),
        )
    }
}
