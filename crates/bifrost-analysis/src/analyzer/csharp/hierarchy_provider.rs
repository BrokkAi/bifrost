//! C#'s `TypeHierarchyProvider` impl and the two memo cells behind it.
//!
//! Attribute-class evidence and the direct-ancestor walk moved to
//! [`brokk_bifrost_csharp::hierarchy`]; the `direct_ancestors` moka cache and
//! the memoized `direct_descendant_index` stay on the analyzer, and
//! `build_direct_descendant_index` is generic over `IAnalyzer`, so the impl
//! stays here.

use crate::analyzer::{CodeUnit, TypeHierarchyProvider, build_direct_descendant_index};
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
        // The builder itself is serial, so the same closure serves both memo
        // arms; the memo's value here is the non-blocking claim protocol.
        self.memo_caches
            .direct_descendant_index
            .get_or_build(
                || build_direct_descendant_index(self, self),
                || build_direct_descendant_index(self, self),
            )
            .descendants(code_unit)
    }
}
