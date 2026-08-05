//! The analyzer-owned half of Rust's usage index: the `PoolSafeMemo` cell and
//! the warm path.
//!
//! [`brokk_bifrost_rust::usage_index::RustUsageIndex::build`] takes the
//! `parallel` flag that fixed the #1416 rayon self-deadlock: the cell is a
//! `PoolSafeMemo` rather than a `OnceLock` precisely because it is reached from
//! inside rayon workers, and the pool-inside path must build sequentially. Both
//! halves of that contract stay here with the cell.

use crate::analyzer::{CodeUnitIndex, ProjectFile};
use brokk_bifrost_rust::usage_index::RustUsageIndex;
use rayon::prelude::*;
use std::sync::Arc;

use super::RustAnalyzer;

impl RustAnalyzer {
    /// The cached re-export/importer index, built once per analyzer generation.
    ///
    /// `PoolSafeMemo`, not `OnceLock`: the build's per-file phase uses rayon,
    /// and this accessor is reached from inside rayon workers during
    /// whole-workspace scans. A blocking `get_or_init` there deadlocks -- the
    /// initializing worker's join steals a sibling scan job that re-enters
    /// this same cell (observed wedging `suite_semantic`'s
    /// reference-differential scan after #1416 parallelized the build).
    pub fn usage_index(&self) -> Arc<RustUsageIndex> {
        self.usage_index.get_or_build(
            || RustUsageIndex::build(self, true),
            || RustUsageIndex::build(self, false),
        )
    }

    /// [`Self::usage_index`], abandoning the build once `keep_going` stops
    /// permitting it. The same #1416 split applies -- pool-outside builds
    /// parallel, pool-inside builds serial -- and a stopped build is not
    /// published, so the cell stays empty for the next complete build.
    pub fn usage_index_while(
        &self,
        keep_going: &(dyn Fn() -> bool + Sync),
    ) -> Option<Arc<RustUsageIndex>> {
        self.usage_index.get_or_build_while(
            &|| keep_going(),
            || RustUsageIndex::build_while(self, true, &|| keep_going()),
            || RustUsageIndex::build_while(self, false, &|| keep_going()),
        )
    }

    #[cfg(test)]
    pub(crate) fn usage_index_ready_for_test(&self) -> bool {
        self.usage_index.is_ready()
    }

    /// Force the lazy usage index and the per-file reference contexts to exist
    /// now, so a background warmer can pay their build cost instead of the
    /// first interactive usage query (which otherwise spends most of a warm
    /// scan constructing reference contexts one file at a time).
    pub fn warm_usage_analysis(&self) {
        let _scope = brokk_bifrost_core::profiling::scope("RustAnalyzer::warm_usage_analysis");
        self.usage_index();
        let files: Vec<ProjectFile> = self.get_analyzed_files().into_iter().collect();
        files.par_iter().for_each(|file| {
            self.reference_context_of(file);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::usages::{ExportEntry, ExportIndex};
    use crate::analyzer::{CodeUnit, CodeUnitType, Language, TestProject};
    use crate::hash::HashMap;
    use brokk_bifrost_rust::cargo_routes::RustCargoRouteIndex;
    use brokk_bifrost_rust::usage_index::RustModuleFiles;
    use brokk_bifrost_rust::usage_index::{
        ModuleKey, RustReferenceResolution, RustSymbolIdentity, RustSymbolNamespace,
    };
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn project_file(root: &std::path::Path, index: usize) -> ProjectFile {
        ProjectFile::new(root.to_path_buf(), format!("src/m{index}.rs"))
    }

    fn analyzer_for(root: &std::path::Path) -> RustAnalyzer {
        RustAnalyzer::from_project(TestProject::new(root.to_path_buf(), Language::Rust))
    }

    #[test]
    fn cancelled_usage_index_build_is_not_published() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "src/lib.rs")
            .write("pub mod worker;\npub fn root() {}\n")
            .expect("write lib.rs");
        ProjectFile::new(root.clone(), "src/worker.rs")
            .write("use crate::root;\npub fn run() { root(); }\n")
            .expect("write worker.rs");
        let analyzer = analyzer_for(&root);

        let checks = AtomicUsize::new(0);
        assert!(
            analyzer
                .usage_index_while(&|| checks.fetch_add(1, Ordering::AcqRel) < 3)
                .is_none()
        );
        assert!(checks.load(Ordering::Acquire) >= 4);
        assert!(!analyzer.usage_index_ready_for_test());

        assert!(analyzer.usage_index_while(&|| true).is_some());
        assert!(analyzer.usage_index_ready_for_test());
    }

    fn reexport_chain(
        root: &std::path::Path,
        len: usize,
        cyclic: bool,
    ) -> (RustUsageIndex, Vec<ProjectFile>) {
        let files = (0..len)
            .map(|index| project_file(root, index))
            .collect::<Vec<_>>();
        let mut exports_by_file = HashMap::default();
        let mut by_package = HashMap::default();
        for (index, file) in files.iter().enumerate() {
            by_package.insert(format!("m{index}"), vec![index]);
            let entry = if index + 1 < len {
                ExportEntry::ReexportedNamed {
                    module_specifier: format!("crate::m{}", index + 1),
                    imported_name: "Value".to_string(),
                }
            } else if cyclic {
                ExportEntry::ReexportedNamed {
                    module_specifier: "crate::m0".to_string(),
                    imported_name: "Value".to_string(),
                }
            } else {
                ExportEntry::Local {
                    local_name: "Value".to_string(),
                }
            };
            exports_by_file.insert(
                file.clone(),
                ExportIndex {
                    exports_by_name: [("Value".to_string(), entry)].into_iter().collect(),
                    reexport_stars: Vec::new(),
                },
            );
        }
        (
            RustUsageIndex {
                exports_by_file,
                module_files: RustModuleFiles {
                    files: files.clone(),
                    by_package,
                    inline_by_name: HashMap::default(),
                    cargo_routes: Arc::new(RustCargoRouteIndex::default()),
                },
                ..RustUsageIndex::default()
            },
            files,
        )
    }

    #[test]
    fn export_target_walk_handles_deep_reexport_chains_without_recursion() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let analyzer = analyzer_for(&root);
        let (index, files) = reexport_chain(&root, 5_000, false);

        assert_eq!(
            index.export_targets_from_files(&analyzer, &files[..1], "Value"),
            BTreeSet::from([(files[4_999].clone(), "Value".to_string())])
        );
    }

    #[test]
    fn export_target_walk_terminates_on_deep_reexport_cycle() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let analyzer = analyzer_for(&root);
        let (index, files) = reexport_chain(&root, 5_000, true);

        assert!(
            index
                .export_targets_from_files(&analyzer, &files[..1], "Value")
                .is_empty()
        );
    }
    #[test]
    fn fallback_binding_identity_remains_an_exact_root() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let analyzer = analyzer_for(&root);
        let source = ProjectFile::new(root, "src/db.rs");
        let target = CodeUnit::new(
            source.clone(),
            CodeUnitType::Function,
            "crate.src.db",
            "get_connection",
        );
        let roots = BTreeSet::from([target.clone()]);
        let index = RustUsageIndex::default();
        let seeds = index.binding_seeds(&analyzer, &roots);
        let resolution = RustReferenceResolution::Exact(RustSymbolIdentity {
            file: source,
            module: ModuleKey::new(target.source(), target.package_name()),
            name: target.identifier().to_string(),
            namespace: RustSymbolNamespace::Value,
        });

        assert_eq!(
            index.exact_root_for_resolution(&resolution, &seeds),
            Some(target)
        );
    }
}
