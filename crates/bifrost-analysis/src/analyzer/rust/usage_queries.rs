//! Query-time composition over the persisted per-file Rust usage facts.
//!
//! This is the read side of the tables Milestone 1 of
//! `.agents/plans/rust-usage-index-v2.md` added. Where `RustUsageIndex` answers
//! a usage question from seventeen workspace-wide maps built wholesale into
//! heap, `RustUsageQueries` answers it from rows: the file's own facts for a
//! per-file question, and one indexed lookup plus per-candidate verification
//! for a name question.
//!
//! Two contracts govern everything here, both taken from IntelliJ (see
//! `.agents/docs/intellij-indexing-research-2026-08.md`):
//!
//! An inverted lookup returns CANDIDATES, never answers. "This file mentions
//! the name `foo`" is all `rust_identifier_occurrences` claims; deciding
//! whether that mention is a usage of a particular declaration is the caller's
//! verification step. IntelliJ states the same contract on `IdIndex`, where it
//! is forced by hash collisions; here it is forced by the fact that a name is
//! not an identity.
//!
//! Nothing persisted is path-derived, because blob rows are content-keyed and
//! two byte-identical files share one row set. The stored module names are
//! relative to each file's own root, and this module composes them with the
//! live file's package name on the way out. That composition is the only place
//! a path enters, and it is why `facts_of` takes a `ProjectFile` rather than an
//! `Oid`.

use std::sync::Arc;

use git2::Oid;

use crate::analyzer::ProjectFile;
use crate::hash::HashSet;

use super::RustAnalyzer;
use super::declarations::rust_package_name;
use super::facts::{RUST_OCCURRENCE_CODE, RustExportFact, RustImportTargetFact, RustUsageFacts};
use super::imports::RustVisibility;
use super::usage_index::{ModuleKey, RustImportExtent};

/// One `use` binding of one file, with its module names composed against the
/// live path and its lexical reach in the shape the usage graph consumes.
///
/// This is the persisted `rust_import_targets` row plus that composition. It is
/// deliberately narrower than `RustProjectedImport`: the rendered snippet and
/// the structured import path that value also carries are not usage facts, and
/// reproducing them would mean re-parsing the file, which is the cost this
/// design exists to remove.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub(super) struct RustImportBinding {
    /// The leaf path as written, split into segments. For a glob this is the
    /// module path; for a named import it is the module path plus the imported
    /// name, which is exactly `RustProjectedImport::import.path`.
    pub(super) path: Vec<String>,
    /// The name the import binds locally, empty for a glob -- matching what
    /// `ImportInfo::local_name().unwrap_or_default()` yields today.
    pub(super) local_name: String,
    pub(super) is_glob: bool,
    pub(super) visibility: RustVisibility,
    /// The enclosing module as a dotted package name, composed with the live
    /// file's package.
    pub(super) owner_module: String,
    pub(super) importer_module: ModuleKey,
    pub(super) extent: RustImportExtent,
}

/// A stateless view over the store, borrowing the analyzer for its store
/// handle, its live path mapping, and its bounded per-file fact cache.
pub(super) struct RustUsageQueries<'a> {
    analyzer: &'a RustAnalyzer,
}

/// The query surface. Two products are already served from here --
/// `module_at_byte` (from `usage_index.rs`) and the re-export half of
/// `export_index_of_declarations` (from `graph_support.rs`) -- and the rest is
/// the surface the remaining `RustUsageIndex` consumers move onto. The allow
/// covers only that not-yet-consumed remainder; every method below is exercised
/// by the tests at the bottom of this file, so none of it is speculative.
#[allow(dead_code)]
impl<'a> RustUsageQueries<'a> {
    pub(super) fn new(analyzer: &'a RustAnalyzer) -> Self {
        Self { analyzer }
    }

    /// Every persisted fact for `file`, memoized per `(generation, blob)`.
    ///
    /// `None` when the file has no live blob or its blob has no rows -- a file
    /// outside the analyzed set, or one whose analysis has not been persisted
    /// yet. Callers treat that as "no facts", not as an error: the catch-up
    /// policy that makes it impossible is Milestone 3.
    pub(super) fn facts_of(&self, file: &ProjectFile) -> Option<Arc<RustUsageFacts>> {
        let oid = self.oid_of(file)?;
        self.analyzer.rust_usage_facts_of_blob(oid)
    }

    fn oid_of(&self, file: &ProjectFile) -> Option<Oid> {
        self.analyzer.live_path_snapshot().oid_for_path(file)
    }

    /// The modules `file` introduces, as `(module, start_byte, end_byte)` with
    /// the file's package composed in.
    ///
    /// Only extents whose body is in this file are returned, because the
    /// question this answers is "which module encloses a byte of this file".
    /// A `mod name;` declaration has no body here; resolving it to another file
    /// is a separate, cross-file question.
    pub(super) fn module_extents_of(&self, file: &ProjectFile) -> Vec<(ModuleKey, usize, usize)> {
        let Some(facts) = self.facts_of(file) else {
            return Vec::new();
        };
        let package = rust_package_name(file);
        facts
            .modules
            .iter()
            .filter(|module| module.is_inline)
            .map(|module| {
                (
                    ModuleKey::new(file, &compose_module(&package, &module.module_name)),
                    module.start_byte,
                    module.end_byte,
                )
            })
            .collect()
    }

    /// The narrowest module of `file` whose body contains `byte`.
    pub(super) fn module_at_byte(&self, file: &ProjectFile, byte: usize) -> Option<ModuleKey> {
        self.module_extents_of(file)
            .into_iter()
            .filter(|(_, start, end)| *start <= byte && byte < *end)
            .min_by_key(|(_, start, end)| end.saturating_sub(*start))
            .map(|(module, _, _)| module)
    }

    /// The `mod name;` declarations of `file`, as dotted package names.
    pub(super) fn declared_file_modules_of(&self, file: &ProjectFile) -> Vec<String> {
        let Some(facts) = self.facts_of(file) else {
            return Vec::new();
        };
        let package = rust_package_name(file);
        facts
            .modules
            .iter()
            .filter(|module| !module.is_inline)
            .map(|module| compose_module(&package, &module.module_name))
            .collect()
    }

    /// Every `use` binding of `file`, in source order.
    pub(super) fn import_bindings_of(&self, file: &ProjectFile) -> Vec<RustImportBinding> {
        let Some(facts) = self.facts_of(file) else {
            return Vec::new();
        };
        let package = rust_package_name(file);
        facts
            .import_targets
            .iter()
            .map(|target| binding_from_fact(file, &package, target))
            .collect()
    }

    /// The names `file` re-exports through a non-private root `use`.
    pub(super) fn re_exports_of(&self, file: &ProjectFile) -> Vec<RustExportFact> {
        self.facts_of(file)
            .map(|facts| facts.exports.clone())
            .unwrap_or_default()
    }

    /// Live files that import `module_path`, spelled exactly as they write it.
    ///
    /// One indexed lookup. The result is a candidate set: an importer that
    /// writes `crate::a` and one that writes `super::a` may name the same
    /// module, and two crates may both write `alpha`. Verification is the
    /// caller's.
    pub(super) fn files_importing_module_path(&self, module_path: &str) -> Vec<ProjectFile> {
        self.live_files(
            self.analyzer
                .analyzer_store()
                .rust_import_target_blobs("rust", module_path)
                .unwrap_or_default(),
        )
    }

    /// Live files that re-export `exported_name`. The seed of an export-chain
    /// walk, and a candidate set for the same reason as above.
    pub(super) fn files_exporting(&self, exported_name: &str) -> Vec<ProjectFile> {
        self.live_files(
            self.analyzer
                .analyzer_store()
                .rust_export_blobs("rust", exported_name)
                .unwrap_or_default(),
        )
    }

    /// Live files whose text mentions `identifier` in at least one of the
    /// contexts in `context_mask`.
    ///
    /// This is the `IdIndex` analogue and the entry point of a name search.
    /// Pass [`RUST_OCCURRENCE_CODE`] to exclude comments and string literals,
    /// which is what a reference search wants.
    pub(super) fn files_mentioning(&self, identifier: &str, context_mask: u32) -> Vec<ProjectFile> {
        let snapshot = self.analyzer.live_path_snapshot();
        let mut files = Vec::new();
        for (oid, mask) in self
            .analyzer
            .analyzer_store()
            .rust_identifier_occurrence_blobs("rust", identifier)
            .unwrap_or_default()
        {
            if mask & context_mask == 0 {
                continue;
            }
            files.extend(snapshot.paths_for_oid(oid).iter().cloned());
        }
        dedup_files(files)
    }

    /// Whether any live file mentioning `identifier` in code satisfies
    /// `accept`, stopping at the first one that does.
    ///
    /// The early-out half of IntelliJ's query-cost mitigation: a caller asking
    /// "is there at least one" must not pay for verifying the rest. Candidates
    /// are visited in locality order around `near`, so the common answer is
    /// found in the first bucket.
    pub(super) fn any_file_mentioning(
        &self,
        identifier: &str,
        near: &ProjectFile,
        accept: impl FnMut(&ProjectFile) -> bool,
    ) -> bool {
        self.bucket_by_locality(
            near,
            self.files_mentioning(identifier, RUST_OCCURRENCE_CODE),
        )
        .iter()
        .any(accept)
    }

    /// Order `candidates` so the ones most likely to verify come first: the
    /// anchor file itself, then its directory, then everything else.
    ///
    /// This is a heuristic over the candidate set, never a filter -- every
    /// candidate is still returned. It mirrors
    /// `PsiSearchHelperImpl.collectFiles`'s target / near-directory / rest
    /// bucketing, and it pays off exactly when the caller stops early.
    pub(super) fn bucket_by_locality(
        &self,
        anchor: &ProjectFile,
        candidates: Vec<ProjectFile>,
    ) -> Vec<ProjectFile> {
        let anchor_directory = anchor.abs_path().parent().map(std::path::Path::to_path_buf);
        let mut bucketed = candidates;
        bucketed.sort_by_key(|candidate| {
            if candidate == anchor {
                0
            } else if anchor_directory.is_some()
                && candidate
                    .abs_path()
                    .parent()
                    .map(std::path::Path::to_path_buf)
                    == anchor_directory
            {
                1
            } else {
                2
            }
        });
        bucketed
    }

    fn live_files(&self, oids: Vec<Oid>) -> Vec<ProjectFile> {
        let snapshot = self.analyzer.live_path_snapshot();
        dedup_files(
            oids.into_iter()
                .flat_map(|oid| snapshot.paths_for_oid(oid).to_vec())
                .collect(),
        )
    }
}

/// Compose a stored, file-root-relative module name with the live file's
/// package name. The empty stored name is the file root itself.
fn compose_module(package: &str, stored: &str) -> String {
    if stored.is_empty() {
        package.to_string()
    } else if package.is_empty() {
        stored.to_string()
    } else {
        format!("{package}.{stored}")
    }
}

#[allow(dead_code)]
fn binding_from_fact(
    file: &ProjectFile,
    package: &str,
    target: &RustImportTargetFact,
) -> RustImportBinding {
    let mut path: Vec<String> = target
        .module_path
        .split("::")
        .filter(|segment| !segment.is_empty())
        .map(str::to_string)
        .collect();
    if let Some(imported_name) = &target.imported_name {
        path.push(imported_name.clone());
    }
    let owner_module = compose_module(package, &target.owner_module);
    let extent = match target.local_extent {
        Some((start, end)) => RustImportExtent::LocalOnly {
            module_start: target.owner_start,
            module_end: target.owner_end,
            start,
            end,
        },
        None => RustImportExtent::Module {
            start: target.owner_start,
            end: target.owner_end,
        },
    };
    RustImportBinding {
        path,
        local_name: target.bound_name.clone().unwrap_or_default(),
        is_glob: target.is_glob,
        visibility: target.visibility.clone(),
        importer_module: ModuleKey::new(file, &owner_module),
        owner_module,
        extent,
    }
}

#[allow(dead_code)]
fn dedup_files(files: Vec<ProjectFile>) -> Vec<ProjectFile> {
    let mut seen = HashSet::default();
    let mut out = Vec::with_capacity(files.len());
    for file in files {
        if seen.insert(file.clone()) {
            out.push(file);
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::rust::declarations::rust_package_name;
    use crate::analyzer::rust::imports::rust_module_extents;
    use crate::analyzer::{IAnalyzer, Language, TestProject};

    /// Two files with modules, imports, a re-export, and a name that occurs in
    /// one file's code and another file's comment only.
    fn analyzer_with_fixture() -> (tempfile::TempDir, RustAnalyzer, ProjectFile, ProjectFile) {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let lib = ProjectFile::new(root.clone(), "src/lib.rs");
        lib.write(
            "pub mod worker;\n\
             pub use worker::Job as Task;\n\
             use std::fmt::Debug;\n\
             pub fn root() {}\n\
             mod inner {\n    \
                 pub fn nested() {}\n\
             }\n",
        )
        .expect("write lib.rs");
        let worker = ProjectFile::new(root.clone(), "src/worker.rs");
        worker
            .write(
                "use crate::root;\n\
                 // mentions nested only in prose\n\
                 pub struct Job;\n\
                 pub fn run() { root(); }\n",
            )
            .expect("write worker.rs");
        // A file whose package name is non-empty, so the composition of a
        // stored file-root-relative module name with the live path is actually
        // exercised rather than trivially the identity.
        ProjectFile::new(root.clone(), "src/deep/leaf.rs")
            .write("pub mod twig {\n    pub fn tip() {}\n}\n")
            .expect("write leaf.rs");
        let analyzer = RustAnalyzer::from_project(TestProject::new(root, Language::Rust));
        // Force the analysis pass that persists the fact rows.
        let _ = analyzer.get_analyzed_files();
        (temp, analyzer, lib, worker)
    }

    fn analyzed_file(analyzer: &RustAnalyzer, suffix: &str) -> ProjectFile {
        analyzer
            .get_analyzed_files()
            .into_iter()
            .find(|file| file.rel_path().ends_with(suffix))
            .unwrap_or_else(|| panic!("{suffix} is analyzed"))
    }

    /// The store rows must reproduce the projection the v1 index built from a
    /// live syntax tree. If this drifts, `module_at_byte` silently changes
    /// answers, which is the migration's whole risk.
    #[test]
    fn module_extents_from_the_store_match_the_syntax_tree_projection() {
        let (_temp, analyzer, lib, _worker) = analyzer_with_fixture();
        let prepared = analyzer.prepared_syntax(&lib).expect("prepared syntax");
        let expected: Vec<_> = rust_module_extents(
            prepared.tree().root_node(),
            prepared.source(),
            &rust_package_name(&lib),
        )
        .into_iter()
        .map(|(module, start, end)| (ModuleKey::new(&lib, &module), start, end))
        .collect();

        let actual = RustUsageQueries::new(&analyzer).module_extents_of(&lib);

        assert_eq!(actual.len(), expected.len(), "actual {actual:?}");
        for entry in &expected {
            assert!(actual.contains(entry), "{entry:?} missing from {actual:?}");
        }
    }

    /// The same equivalence for a file whose package name is non-empty: the
    /// stored names are relative to the file root, so getting the composition
    /// wrong here produces a module key that resolves to the wrong crate path.
    #[test]
    fn module_extents_compose_the_live_package_into_the_stored_relative_names() {
        let (_temp, analyzer, _lib, _worker) = analyzer_with_fixture();
        let leaf = analyzed_file(&analyzer, "leaf.rs");
        let package = rust_package_name(&leaf);
        assert!(!package.is_empty(), "fixture must have a nested package");
        let prepared = analyzer.prepared_syntax(&leaf).expect("prepared syntax");
        let expected: Vec<_> =
            rust_module_extents(prepared.tree().root_node(), prepared.source(), &package)
                .into_iter()
                .map(|(module, start, end)| (ModuleKey::new(&leaf, &module), start, end))
                .collect();

        let actual = RustUsageQueries::new(&analyzer).module_extents_of(&leaf);

        assert_eq!(actual.len(), expected.len(), "actual {actual:?}");
        for entry in &expected {
            assert!(actual.contains(entry), "{entry:?} missing from {actual:?}");
        }
    }

    #[test]
    fn module_at_byte_picks_the_narrowest_enclosing_module() {
        let (_temp, analyzer, lib, _worker) = analyzer_with_fixture();
        let queries = RustUsageQueries::new(&analyzer);
        let source = lib.read_to_string().expect("read lib.rs");
        let nested = source.find("nested").expect("nested function present");
        let root_fn = source.find("pub fn root").expect("root function present");

        assert_eq!(
            queries.module_at_byte(&lib, nested),
            Some(ModuleKey::new(
                &lib,
                &compose_module(&rust_package_name(&lib), "inner")
            ))
        );
        assert_eq!(
            queries.module_at_byte(&lib, root_fn),
            Some(ModuleKey::new(&lib, &rust_package_name(&lib)))
        );
    }

    #[test]
    fn declared_file_modules_and_re_exports_come_from_the_rows() {
        let (_temp, analyzer, lib, _worker) = analyzer_with_fixture();
        let queries = RustUsageQueries::new(&analyzer);

        assert_eq!(
            queries.declared_file_modules_of(&lib),
            vec![compose_module(&rust_package_name(&lib), "worker")]
        );
        let exports = queries.re_exports_of(&lib);
        assert_eq!(exports.len(), 1, "exports were {exports:?}");
        assert_eq!(exports[0].exported_name.as_deref(), Some("Task"));
        assert_eq!(exports[0].source_path, "worker");
        assert_eq!(exports[0].imported_name.as_deref(), Some("Job"));
        assert!(
            queries
                .re_exports_of(&analyzed_file(&analyzer, "worker.rs"))
                .is_empty(),
            "a private `use` is not a re-export"
        );
    }

    #[test]
    fn import_bindings_reproduce_the_paths_and_lexical_reach() {
        let (_temp, analyzer, lib, worker) = analyzer_with_fixture();
        let queries = RustUsageQueries::new(&analyzer);

        let lib_bindings = queries.import_bindings_of(&lib);
        let described: Vec<_> = lib_bindings
            .iter()
            .map(|binding| (binding.path.join("::"), binding.local_name.as_str()))
            .collect();
        assert_eq!(
            described,
            vec![
                ("worker::Job".to_string(), "Task"),
                ("std::fmt::Debug".to_string(), "Debug"),
            ],
            "lib bindings were {lib_bindings:?}"
        );

        let worker_bindings = queries.import_bindings_of(&worker);
        assert_eq!(worker_bindings.len(), 1);
        assert_eq!(
            worker_bindings[0].importer_module,
            ModuleKey::new(&worker, &rust_package_name(&worker))
        );
        assert!(
            matches!(worker_bindings[0].extent, RustImportExtent::Module { .. }),
            "a module-scope `use` has module reach: {:?}",
            worker_bindings[0].extent
        );
    }

    /// The inverted lookups are the candidate half of the design. They must
    /// find the files that mention a name, filter by context so a prose
    /// mention is not offered to a reference search, and stay one indexed
    /// lookup rather than a workspace walk.
    #[test]
    fn inverted_lookups_return_live_candidate_files_filtered_by_context() {
        let (_temp, analyzer, lib, worker) = analyzer_with_fixture();
        let queries = RustUsageQueries::new(&analyzer);

        assert_eq!(
            queries.files_mentioning("nested", RUST_OCCURRENCE_CODE),
            vec![lib.clone()],
            "the prose mention in worker.rs must not answer a code search"
        );
        let prose = queries.files_mentioning("nested", u32::MAX);
        assert!(
            prose.contains(&worker),
            "the prose mention is still recorded: {prose:?}"
        );

        assert_eq!(queries.files_exporting("Task"), vec![lib.clone()]);
        assert!(
            queries.files_exporting("Debug").is_empty(),
            "a private import is not an export"
        );
        assert_eq!(queries.files_importing_module_path("crate"), vec![worker]);
        assert_eq!(queries.files_importing_module_path("worker"), vec![lib]);
    }

    #[test]
    fn locality_bucketing_orders_candidates_without_dropping_any() {
        let (_temp, analyzer, lib, worker) = analyzer_with_fixture();
        let queries = RustUsageQueries::new(&analyzer);
        let far = ProjectFile::new(lib.root().to_path_buf(), "vendor/other/thing.rs");

        let ordered =
            queries.bucket_by_locality(&lib, vec![far.clone(), worker.clone(), lib.clone()]);

        assert_eq!(ordered, vec![lib.clone(), worker, far]);

        let mut visited = 0;
        assert!(queries.any_file_mentioning("root", &lib, |_| {
            visited += 1;
            true
        }));
        assert_eq!(visited, 1, "an early-out caller verifies one candidate");
    }
}
