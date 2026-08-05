//! The analyzer-owned half of Rust's graph support: the lazy per-file memo
//! cells, and the five forwards `bifrost-lsp` and the SPI block reach through.
//!
//! Everything these methods call lives in [`brokk_bifrost_rust::graph_support`];
//! the caches are moka and the analyzer type is analysis-owned, so the cells and
//! their accessors cannot leave. `RustAnalyzer` implements
//! [`brokk_bifrost_rust::brokk_bifrost_rust::graph_support::RustAnalysisSource`] out of exactly
//! these accessors, which is how the free functions below reach back for the
//! products they need without naming the analyzer.

use crate::analyzer::usages::{ExportIndex, ImportBinder};
use crate::analyzer::{CodeUnit, CodeUnitIndex, ProjectFile};
use crate::hash::HashSet;
use brokk_bifrost_rust::graph_support::{
    RustPackageFileIndex, RustReferenceContext, build_reference_context_with_progress,
    exact_member, export_index_of_declarations, is_rust_trait_declaration,
    reference_context_checkpoint, resolve_module_files, rust_trait_member_implementations,
    rust_usage_candidate_files,
};
use brokk_bifrost_rust::lexical_scope::insert_rust_import_binding;
use std::sync::Arc;

use super::RustAnalyzer;

impl RustAnalyzer {
    /// The cached per-file export index. Shared by handle: the index is
    /// immutable for the analyzer instance's lifetime, and callers ask for it
    /// once per export name per pending file, so deep-cloning the whole map on
    /// every cache hit was pure waste (#1230 item 5).
    pub fn export_index_of(&self, file: &ProjectFile) -> Arc<ExportIndex> {
        if let Some(cached) = self.export_indexes.get(file) {
            return cached;
        }
        let declarations = self.declarations(file);
        let index = Arc::new(export_index_of_declarations(self, file, &declarations));
        self.export_indexes.insert(file.clone(), index.clone());
        index
    }

    pub fn import_binder_of(&self, file: &ProjectFile) -> ImportBinder {
        let mut binder = ImportBinder::empty();

        for import in self.inner.import_info_of(file) {
            insert_rust_import_binding(&mut binder, &import);
        }

        binder
    }

    /// The cached per-file [`RustReferenceContext`] — the one primitive both the
    /// inverted usage-graph builder and the forward scan resolve references
    /// through. Built once per file from its import binder + same-file
    /// declarations; the cache is dropped on `update`/`update_all`, so a changed
    /// file rebuilds it.
    pub fn reference_context_of(&self, file: &ProjectFile) -> Arc<RustReferenceContext> {
        self.reference_context_of_with_progress(file, &|| true)
            .expect("uninterrupted Rust reference-context construction")
    }

    pub fn reference_context_of_with_progress(
        &self,
        file: &ProjectFile,
        progress: &dyn Fn() -> bool,
    ) -> Option<Arc<RustReferenceContext>> {
        reference_context_checkpoint(progress).ok()?;
        if let Some(cached) = self.reference_contexts.get(file) {
            return Some(cached);
        }
        let context =
            Arc::new(build_reference_context_with_progress(self, file, false, progress).ok()?);
        reference_context_checkpoint(progress).ok()?;
        self.reference_contexts
            .insert(file.clone(), context.clone());
        Some(context)
    }

    pub fn forward_reference_context_of(&self, file: &ProjectFile) -> Arc<RustReferenceContext> {
        self.forward_reference_context_of_with_progress(file, &|| true)
            .expect("uninterrupted Rust reference-context construction")
    }

    pub fn forward_reference_context_of_with_progress(
        &self,
        file: &ProjectFile,
        progress: &dyn Fn() -> bool,
    ) -> Option<Arc<RustReferenceContext>> {
        reference_context_checkpoint(progress).ok()?;
        if let Some(cached) = self.forward_reference_contexts.get(file) {
            return Some(cached);
        }
        let context =
            Arc::new(build_reference_context_with_progress(self, file, true, progress).ok()?);
        reference_context_checkpoint(progress).ok()?;
        self.forward_reference_contexts
            .insert(file.clone(), context.clone());
        Some(context)
    }

    /// The analyzed-file listing bucketed by path-derived Rust package name,
    /// built at most once per analyzer instance. Same lifetime and invalidation
    /// as `cargo_routes` — both are pure projections of the analyzed-file set,
    /// so both are rebuilt by `update`/`update_all`/`clone_with_project` and by
    /// nothing else (#1230 item 3).
    pub fn package_file_index(&self) -> Arc<RustPackageFileIndex> {
        self.package_file_index
            .get_or_init(|| Arc::new(RustPackageFileIndex::build(self.get_analyzed_files())))
            .clone()
    }

    pub fn resolve_module_files(
        &self,
        importing_file: &ProjectFile,
        module_specifier: &str,
    ) -> Vec<ProjectFile> {
        resolve_module_files(self, importing_file, module_specifier)
    }

    pub fn exact_member(
        &self,
        source_file: &ProjectFile,
        owner_name: &str,
        member_name: &str,
        instance_receiver: bool,
    ) -> Option<CodeUnit> {
        exact_member(
            self,
            source_file,
            owner_name,
            member_name,
            instance_receiver,
        )
    }

    pub fn rust_usage_candidate_files(
        &self,
        export_names: HashSet<String>,
        target: &CodeUnit,
    ) -> HashSet<ProjectFile> {
        rust_usage_candidate_files(self, export_names, target)
    }

    /// Reached from `bifrost-lsp`'s goto-type-definition handler, which holds a
    /// downcast analyzer rather than this module's source trait.
    pub fn rust_trait_member_implementations(
        &self,
        trait_member: &CodeUnit,
    ) -> Option<Vec<CodeUnit>> {
        rust_trait_member_implementations(self, trait_member)
    }

    /// Reached from `bifrost-lsp`; see
    /// [`Self::rust_trait_member_implementations`].
    pub fn is_rust_trait_declaration(&self, code_unit: &CodeUnit) -> bool {
        is_rust_trait_declaration(self, code_unit)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{IAnalyzer, Language};
    use crate::test_support::AnalyzerFixture;
    use std::cell::Cell;
    use std::collections::BTreeSet;

    #[test]
    fn forward_reference_context_is_reused_within_analyzer_generation() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Rust,
            &[
                ("src/lib.rs", "pub mod exports;\n"),
                ("src/exports.rs", "pub use std::collections::HashMap;\n"),
            ],
        );
        let analyzer = RustAnalyzer::from_project(fixture.test_project().clone());
        let file = ProjectFile::new(fixture.project_root(), "src/exports.rs");

        let first = analyzer.forward_reference_context_of(&file);
        let second = analyzer.forward_reference_context_of(&file);

        assert!(Arc::ptr_eq(&first, &second));
        assert!(analyzer.export_indexes.get(&file).is_some());

        let unrelated_watcher_noise = ProjectFile::new(
            fixture.project_root(),
            format!(".bifrost/cache/{}", crate::cache_db::cache_db_file_name()),
        );
        let updated = analyzer.update(&BTreeSet::from([file.clone(), unrelated_watcher_noise]));
        let after_noop_update = updated.forward_reference_context_of(&file);

        assert!(Arc::ptr_eq(&first, &after_noop_update));
        assert!(updated.export_indexes.get(&file).is_some());
    }

    #[test]
    fn issue_1228_interrupted_forward_reference_context_is_not_cached() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Rust,
            &[
                (
                    "src/lib.rs",
                    "pub mod exports;\nuse exports::{Alias, helper};\npub fn call(value: Alias) { helper(value); }\n",
                ),
                (
                    "src/exports.rs",
                    "pub struct Alias;\npub fn helper(_: Alias) {}\n",
                ),
            ],
        );
        let analyzer = RustAnalyzer::from_project(fixture.test_project().clone());
        let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
        let checks = Cell::new(0usize);

        let interrupted = analyzer.forward_reference_context_of_with_progress(&file, &|| {
            let next = checks.get() + 1;
            checks.set(next);
            next < 4
        });

        assert!(interrupted.is_none());
        assert!(
            analyzer.forward_reference_contexts.get(&file).is_none(),
            "an interrupted context must not be published"
        );

        let complete = analyzer
            .forward_reference_context_of_with_progress(&file, &|| true)
            .expect("subsequent request should build a complete context");
        let cached = analyzer
            .forward_reference_context_of_with_progress(&file, &|| true)
            .expect("complete context should be cached");

        assert!(Arc::ptr_eq(&complete, &cached));
        assert_eq!(complete.resolve_bare("Alias"), Some("exports.Alias"));
        assert_eq!(complete.resolve_bare("helper"), Some("exports.helper"));
    }

    #[test]
    fn issue_1304_interrupted_inverted_reference_context_is_not_cached() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Rust,
            &[
                (
                    "src/lib.rs",
                    "pub mod exports;\nuse exports::{Alias, helper};\npub fn call(value: Alias) { helper(value); }\n",
                ),
                (
                    "src/exports.rs",
                    "pub struct Alias;\npub fn helper(_: Alias) {}\n",
                ),
            ],
        );
        let analyzer = RustAnalyzer::from_project(fixture.test_project().clone());
        let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
        let checks = Cell::new(0usize);

        let interrupted = analyzer.reference_context_of_with_progress(&file, &|| {
            let next = checks.get() + 1;
            checks.set(next);
            next < 4
        });

        assert!(interrupted.is_none());
        assert!(
            analyzer.reference_contexts.get(&file).is_none(),
            "an interrupted inverted context must not be published"
        );

        let complete = analyzer
            .reference_context_of_with_progress(&file, &|| true)
            .expect("subsequent request should build a complete context");
        let cached = analyzer
            .reference_context_of_with_progress(&file, &|| true)
            .expect("complete context should be cached");

        assert!(Arc::ptr_eq(&complete, &cached));
        assert_eq!(complete.resolve_bare("Alias"), Some("exports.Alias"));
        assert_eq!(complete.resolve_bare("helper"), Some("exports.helper"));
    }
}
