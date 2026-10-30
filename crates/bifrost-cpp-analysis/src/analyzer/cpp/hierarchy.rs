//! The `CppAnalyzer` half of C++ type-hierarchy resolution.
//!
//! Every decision -- the include-closure class-table walk, the namespace search
//! order, base-specifier normalization and the alias canonicalization loop --
//! moved to [`brokk_bifrost_cpp::hierarchy`]. What stays is the
//! `TypeHierarchyProvider` impl, the two moka caches it answers through, the
//! memoized descendant index and the `test-support` build counter.

use crate::analyzer::cpp::*;

use brokk_bifrost_core::analyzer::capabilities::DescendantIndexScope;

use brokk_bifrost_core::analyzer::capabilities::build_direct_descendant_index;

use brokk_bifrost_core::analyzer::capabilities::descendants_from_variant_index;

use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_cpp::hierarchy::{build_cpp_visible_type_units, cpp_resolve_direct_ancestors};

/// The predicate an uncancellable caller passes down. Dependency reads can
/// still be incomplete even though this predicate never stops the walk.
const ALWAYS: &dyn Fn() -> bool = &|| true;

impl CppAnalyzer {
    pub(crate) fn visible_type_units(&self, file: &ProjectFile) -> Arc<Vec<CodeUnit>> {
        self.cached_complete_read(&self.visible_type_units_by_file, file, || {
            #[cfg(any(test, feature = "test-support"))]
            self.record_visible_type_units_build_for_test();
            let scope = AnalyzerQueryScope::new(self);
            build_cpp_visible_type_units(self, scope.token(), file, ALWAYS).unwrap_or_else(|| {
                assert!(
                    scope.read_completion().is_err(),
                    "an unstopped visible-type walk must report an incomplete dependency"
                );
                Vec::new()
            })
        })
    }

    /// [`Self::visible_type_units`] under a caller's deadline.
    ///
    /// A stopped walk is not memoized. A truncated class table is
    /// indistinguishable from a file that genuinely sees fewer types, so every
    /// base specifier resolved against it afterwards would silently lose its
    /// ancestor -- the failure the complete-or-nothing rule exists to prevent.
    ///
    /// This path deliberately does not single-flight. moka's `try_get_with` hands the leader's failure to every
    /// waiter, so one request whose budget had expired would report a stopped
    /// walk to an unrelated request that still had time. A race costs one
    /// duplicate include-closure walk; the misreport would cost a correct
    /// answer. `None` means this walk stopped, either at `keep_going` or at an
    /// incomplete dependency read retained by the request's completion ledger.
    pub(crate) fn visible_type_units_while(
        &self,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Option<Arc<Vec<CodeUnit>>> {
        if let Some(cached) = self.visible_type_units_by_file.get(file) {
            cached.replay(self);
            return cached
                .incompleteness
                .is_empty()
                .then(|| Arc::clone(&cached.value));
        }
        #[cfg(any(test, feature = "test-support"))]
        self.record_visible_type_units_build_for_test();
        let scope = AnalyzerQueryScope::new(self);
        let (built, reads) = capture_query_reads(self, || {
            build_cpp_visible_type_units(self, scope.token(), file, keep_going)
        });
        let built = Arc::new(built?);
        if scope.read_completion().is_err() {
            return None;
        }
        self.visible_type_units_by_file.insert(
            file.clone(),
            CachedFileRead::complete(Arc::clone(&built), &reads),
        );
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
            cached.replay(self);
            return cached
                .incompleteness
                .is_empty()
                .then(|| (*cached.value).clone());
        }
        let cache_fill = brokk_bifrost_analysis::analyzer::common::QueryCacheFill::new(self);
        let scope = AnalyzerQueryScope::new(self);
        let (resolved, reads) = capture_query_reads(self, || {
            cpp_resolve_direct_ancestors(self, scope.token(), code_unit, keep_going)
        });
        let resolved = resolved?;
        if scope.read_completion().is_err() {
            return None;
        }
        if cache_fill.is_complete() {
            self.direct_ancestors.insert(
                code_unit.clone(),
                CachedFileRead::complete(Arc::new(resolved.clone()), &reads),
            );
        }
        Some(resolved)
    }
}

impl TypeHierarchyProvider for CppAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.cached_complete_read(&self.direct_ancestors, code_unit, || {
            let scope = AnalyzerQueryScope::new(self);
            cpp_resolve_direct_ancestors(self, scope.token(), code_unit, ALWAYS).unwrap_or_else(
                || {
                    assert!(
                        scope.read_completion().is_err(),
                        "an unstopped ancestor walk must report an incomplete dependency"
                    );
                    // cached_complete_read propagates the recorded reason and
                    // retains its incompleteness with this compatibility value.
                    Vec::new()
                },
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
        self.direct_descendant_index.read(
            &memo_attribution(self),
            |memo| {
                descendants_from_variant_index(memo, scope, code_unit, || {
                    brokk_bifrost_analysis::analyzer::common::complete_query_cache_fill(
                        self,
                        || build_direct_descendant_index(self, self, scope),
                    )
                    .ok()
                    .flatten()
                })
            },
            |_| AuthorityInputs::SourceOf(&[Language::Cpp]),
        )
    }
}
