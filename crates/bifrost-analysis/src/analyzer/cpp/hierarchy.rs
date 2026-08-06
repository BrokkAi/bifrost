//! The `CppAnalyzer` half of C++ type-hierarchy resolution.
//!
//! Every decision -- the include-closure class-table walk, the namespace search
//! order, base-specifier normalization and the alias canonicalization loop --
//! moved to [`brokk_bifrost_cpp::hierarchy`]. What stays is the
//! `TypeHierarchyProvider` impl, the two moka caches it answers through, the
//! memoized descendant index and the `test-support` build counter.

use super::*;
use crate::analyzer::build_direct_descendant_index;
use brokk_bifrost_cpp::hierarchy::{build_cpp_visible_type_units, cpp_resolve_direct_ancestors};

impl CppAnalyzer {
    pub(super) fn visible_type_units(&self, file: &ProjectFile) -> Arc<Vec<CodeUnit>> {
        self.visible_type_units_by_file.get_with_by_ref(file, || {
            #[cfg(any(test, feature = "test-support"))]
            self.record_visible_type_units_build_for_test();
            Arc::new(build_cpp_visible_type_units(self, file))
        })
    }
}

impl TypeHierarchyProvider for CppAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.direct_ancestors
            .get_with_by_ref(code_unit, || {
                Arc::new(cpp_resolve_direct_ancestors(self, code_unit))
            })
            .as_ref()
            .clone()
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        // The builder itself is serial, so the same closure serves both memo
        // arms; the memo's value here is the non-blocking claim protocol.
        self.direct_descendant_index
            .get_or_build(
                || build_direct_descendant_index(self, self),
                || build_direct_descendant_index(self, self),
            )
            .descendants(code_unit)
    }
}
