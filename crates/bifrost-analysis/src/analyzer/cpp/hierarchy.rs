//! The `CppAnalyzer` half of C++ type-hierarchy resolution.
//!
//! Every decision -- the include-closure class-table walk, the namespace search
//! order, base-specifier normalization and the alias canonicalization loop --
//! moved to [`brokk_bifrost_cpp::hierarchy`]. What stays is the
//! `TypeHierarchyProvider` impl, the two moka caches it answers through, the
//! memoized descendant index and the `test-support` build counter.

use super::*;
use crate::analyzer::{
    DescendantIndexScope, build_direct_descendant_index, descendants_from_variant_index,
};
use crate::cancellation::CancellationToken;
use brokk_bifrost_cpp::hierarchy::{build_cpp_visible_type_units, cpp_resolve_direct_ancestors};

/// The predicate an uncancellable caller passes down. Named rather than spelled
/// inline at each site so the `expect`s below can point at one reason: with
/// this predicate a walk cannot stop, so `None` cannot happen.
const ALWAYS: &dyn Fn() -> bool = &|| true;

impl CppAnalyzer {
    pub(super) fn visible_type_units(&self, file: &ProjectFile) -> Arc<Vec<CodeUnit>> {
        self.visible_type_units_by_file.get_with_by_ref(file, || {
            #[cfg(any(test, feature = "test-support"))]
            self.record_visible_type_units_build_for_test();
            Arc::new(
                build_cpp_visible_type_units(self, file, ALWAYS)
                    .expect("an include-closure walk that cannot stop always completes"),
            )
        })
    }

    /// [`Self::visible_type_units`] under a caller's deadline.
    ///
    /// A stopped walk is not memoized. A truncated class table is
    /// indistinguishable from a file that genuinely sees fewer types, so every
    /// base specifier resolved against it afterwards would silently lose its
    /// ancestor -- the failure the complete-or-nothing rule exists to prevent.
    ///
    /// This path deliberately does not single-flight, unlike the uncancellable
    /// one above. moka's `try_get_with` hands the leader's failure to every
    /// waiter, so one request whose budget had expired would report a stopped
    /// walk to an unrelated request that still had time. A race costs one
    /// duplicate include-closure walk; the misreport would cost a correct
    /// answer. `None` therefore means exactly one thing: *this* caller's
    /// `keep_going` said stop.
    pub(super) fn visible_type_units_while(
        &self,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Option<Arc<Vec<CodeUnit>>> {
        if let Some(cached) = self.visible_type_units_by_file.get(file) {
            return Some(cached);
        }
        #[cfg(any(test, feature = "test-support"))]
        self.record_visible_type_units_build_for_test();
        let built = Arc::new(build_cpp_visible_type_units(self, file, keep_going)?);
        self.visible_type_units_by_file
            .insert(file.clone(), Arc::clone(&built));
        Some(built)
    }

    /// [`TypeHierarchyProvider::get_direct_ancestors`] under a deadline, sharing
    /// the same memo: a resolution that completes is worth keeping whether or
    /// not the caller that paid for it was on a clock.
    fn direct_ancestors_while(
        &self,
        code_unit: &CodeUnit,
        keep_going: &dyn Fn() -> bool,
    ) -> Option<Vec<CodeUnit>> {
        if let Some(cached) = self.direct_ancestors.get(code_unit) {
            return Some((*cached).clone());
        }
        let resolved = cpp_resolve_direct_ancestors(self, code_unit, keep_going)?;
        self.direct_ancestors
            .insert(code_unit.clone(), Arc::new(resolved.clone()));
        Some(resolved)
    }
}

impl TypeHierarchyProvider for CppAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.direct_ancestors
            .get_with_by_ref(code_unit, || {
                Arc::new(
                    cpp_resolve_direct_ancestors(self, code_unit, ALWAYS)
                        .expect("an ancestor resolution that cannot stop always completes"),
                )
            })
            .as_ref()
            .clone()
    }

    fn get_direct_ancestors_within(
        &self,
        code_unit: &CodeUnit,
        scope: &DescendantIndexScope<'_>,
    ) -> Option<Vec<CodeUnit>> {
        self.direct_ancestors_while(code_unit, &scope.keep_going())
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
            build_direct_descendant_index(self, self, scope)
        })
    }
}
