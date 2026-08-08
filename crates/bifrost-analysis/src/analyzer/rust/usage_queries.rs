//! Query-time composition over the persisted per-file Rust usage facts.
//!
//! This is the read side of the tables Milestone 1 of
//! `.agents/plans/rust-usage-index-v2.md` added. Where Rust usage analysis
//! used to answer a question from seventeen workspace-wide maps built
//! wholesale into heap, `RustUsageQueries` answers it from rows: the file's own
//! facts for a per-file question, and one indexed lookup plus per-candidate
//! verification for a name question.
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

use std::collections::BTreeSet;
use std::sync::Arc;

use git2::Oid;

use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile};
use crate::hash::HashSet;

use super::RustAnalyzer;
use super::declarations::rust_package_name;
use super::facts::{RustExportFact, RustImportTargetFact, RustUsageFacts};
use super::graph_support::rust_value_constructor_visibilities;
use super::imports::RustVisibility;
use super::usage::{
    Domain, ModuleKey, RustImportExtent, RustSymbolIdentity, RustSymbolNamespace,
    direct_import_scope_for_module,
};

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

/// Every symbol identity one file introduces, with the visibility domain each
/// identity carries.
///
/// A per-file product in the plan's classification: deriving it needs the
/// file's own declarations, their structural parents and their visibility, and
/// nothing from any other file. The v1 index folded exactly this derivation
/// into its workspace-wide build; both callers now go through
/// [`rust_declaration_facts`], so the workspace map and the query-time answer
/// cannot drift apart.
#[derive(Debug, Default)]
pub(super) struct RustDeclarationFacts {
    /// Declaration -> the identity it introduces, in declaration order. A
    /// declaration whose visibility does not resolve to a domain still appears
    /// here; it simply contributes no entry to `domains`.
    pub(super) identities: Vec<(CodeUnit, RustSymbolIdentity)>,
    /// Tuple-struct and tuple-variant constructors, which bind a
    /// value-namespace identity of the declaration's own name under the
    /// constructor's (possibly narrower) visibility.
    pub(super) value_constructors: Vec<(CodeUnit, RustSymbolIdentity)>,
    /// `mod name` declarations of this file, as (declared module, domain).
    pub(super) declared_module_domains: Vec<(ModuleKey, Domain)>,
    /// Identity -> the domains it was declared with, grouped in first-appearance
    /// order. Two declarations can share one identity (a `#[cfg]`-duplicated
    /// item, say), so the value is a list rather than a single domain.
    pub(super) domains: Vec<(RustSymbolIdentity, Vec<Domain>)>,
}

/// Derive one file's declaration facts.
///
/// `declarations` is passed in rather than fetched, because both callers
/// already hold the file's declaration set and re-reading it would double the
/// store work on the build path.
///
/// `None` only when `keep_going` asked to stop.
pub(super) fn rust_declaration_facts(
    analyzer: &RustAnalyzer,
    file: &ProjectFile,
    declarations: &BTreeSet<CodeUnit>,
    keep_going: &impl Fn() -> bool,
) -> Option<RustDeclarationFacts> {
    let mut facts = RustDeclarationFacts::default();
    let mut ordered_domains: Vec<(RustSymbolIdentity, Domain)> = Vec::new();
    let prepared = analyzer.prepared_syntax(file);
    for declaration in declarations {
        keep_going().then_some(())?;
        let (owner, declared_module) = if declaration.is_module() {
            let declared = ModuleKey::new(file, &declaration.fq_name());
            let owner = declared
                .parent()
                .unwrap_or_else(|| ModuleKey::new(file, &rust_package_name(file)));
            (owner, Some(declared))
        } else {
            let owner = match analyzer.structural_parent_of(declaration) {
                None => ModuleKey::new(file, &rust_package_name(file)),
                Some(parent) if parent.is_module() => ModuleKey::new(file, &parent.fq_name()),
                Some(_) => continue,
            };
            (owner, None)
        };
        let Some(namespace) = RustSymbolNamespace::of(analyzer, declaration) else {
            continue;
        };
        let identity = RustSymbolIdentity {
            file: file.clone(),
            module: owner.clone(),
            name: declaration.identifier().to_string(),
            namespace,
        };
        facts
            .identities
            .push((declaration.clone(), identity.clone()));
        let constructor_domain = prepared.as_ref().and_then(|syntax| {
            let node = analyzer.rust_named_declaration_node(
                declaration,
                syntax.tree().root_node(),
                syntax.source(),
            )?;
            rust_value_constructor_visibilities(node, syntax.source())?
                .into_iter()
                .map(|visibility| {
                    direct_import_scope_for_module(file, &owner.package(), visibility)
                })
                .try_fold(Domain::Public, |effective, domain| {
                    effective.intersect(&domain?)
                })
        });
        let declaration_domain = if namespace == RustSymbolNamespace::Macro
            && analyzer.is_rust_macro_export_declaration(declaration)
        {
            Some(Domain::Public)
        } else {
            direct_import_scope_for_module(
                file,
                &owner.package(),
                analyzer.rust_declaration_visibility(declaration),
            )
        };
        let Some(domain) = declaration_domain else {
            continue;
        };
        if let Some(declared_module) = declared_module {
            facts
                .declared_module_domains
                .push((declared_module, domain.clone()));
        }
        ordered_domains.push((identity.clone(), domain));
        if let Some(constructor_domain) = constructor_domain {
            let constructor = RustSymbolIdentity {
                namespace: RustSymbolNamespace::Value,
                ..identity
            };
            ordered_domains.push((constructor.clone(), constructor_domain));
            facts
                .value_constructors
                .push((declaration.clone(), constructor));
        }
    }
    for (identity, domain) in ordered_domains {
        keep_going().then_some(())?;
        match facts
            .domains
            .iter_mut()
            .find(|(existing, _)| *existing == identity)
        {
            Some((_, domains)) => domains.push(domain),
            None => facts.domains.push((identity, vec![domain])),
        }
    }
    Some(facts)
}

/// A stateless view over the store, borrowing the analyzer for its store
/// handle, its live path mapping, and its bounded per-file fact cache.
pub(super) struct RustUsageQueries<'a> {
    analyzer: &'a RustAnalyzer,
}

/// The query surface every Rust usage answer reads through: `usage.rs` for
/// `module_at_byte`, `graph_support.rs` for the re-export half of
/// `export_index_of_declarations`, and `usage_walks.rs` for everything
/// cross-file.
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

    /// One file's declaration identities and their domains, memoized.
    pub(super) fn declaration_facts_of(&self, file: &ProjectFile) -> Arc<RustDeclarationFacts> {
        self.analyzer.rust_declaration_facts_of(file)
    }

    /// The identities `file` declares under `name`, with their domains.
    ///
    /// A per-file question despite looking like a name search: the caller
    /// already knows which file it means, so no inverted lookup is involved.
    pub(super) fn identities_in_file_named(
        &self,
        file: &ProjectFile,
        name: &str,
    ) -> Vec<(RustSymbolIdentity, Vec<Domain>)> {
        self.declaration_facts_of(file)
            .domains
            .iter()
            .filter(|(identity, _)| identity.name == name)
            .cloned()
            .collect()
    }

    /// Every declaration identity in the workspace named `name`, with its
    /// domains.
    ///
    /// Candidate lookup plus verification, replacing the v1 index's
    /// `identities_by_name` map. `lookup_candidates_by_identifier` is the
    /// store's indexed short-name lookup over `code_units`, so the candidate
    /// set is the handful of files that declare this identifier rather than
    /// the workspace; each candidate is then verified against its own
    /// declaration facts, which decide whether an identity of that name really
    /// exists there and what visibility it carries. A candidate whose only
    /// declaration of `name` has no resolvable domain contributes nothing,
    /// exactly as it contributed no `declaration_domains` key in v1.
    pub(super) fn identities_named(&self, name: &str) -> Vec<(RustSymbolIdentity, Vec<Domain>)> {
        let mut candidates: Vec<ProjectFile> = self
            .analyzer
            .lookup_candidates_by_identifier(name)
            .into_iter()
            .map(|declaration| declaration.source().clone())
            .filter(|file| self.analyzer.is_analyzed(file))
            .collect();
        candidates.sort();
        candidates.dedup();
        candidates
            .iter()
            .flat_map(|file| self.identities_in_file_named(file, name))
            .collect()
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

    /// Live files whose text mentions `identifier` in at least one of the
    /// contexts in `context_mask`.
    ///
    /// This is the `IdIndex` analogue and the entry point of a name search.
    /// Pass [`RUST_OCCURRENCE_CODE`](super::facts::RUST_OCCURRENCE_CODE) to
    /// exclude comments and string literals,
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
    use super::super::facts::RUST_OCCURRENCE_CODE;
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
    fn re_exports_come_from_the_rows() {
        let (_temp, analyzer, lib, _worker) = analyzer_with_fixture();
        let queries = RustUsageQueries::new(&analyzer);

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

        assert_eq!(queries.files_importing_module_path("crate"), vec![worker]);
        assert_eq!(queries.files_importing_module_path("worker"), vec![lib]);
    }

    /// An inverted hit is a candidate, never an answer. The store's short-name
    /// index offers every file declaring the identifier, including one whose
    /// only declaration of that name is a method -- an associated item, not a
    /// module-scope identity, so v1 never gave it a `declaration_domains` key.
    /// Returning the candidate unverified would invent an identity in a module
    /// that does not declare the name.
    #[test]
    fn a_candidate_file_without_a_module_scope_identity_is_rejected() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let owner = ProjectFile::new(root.clone(), "src/lib.rs");
        owner
            .write("pub mod holder;\npub fn compute() {}\n")
            .expect("write lib.rs");
        let holder = ProjectFile::new(root.clone(), "src/holder.rs");
        holder
            .write("pub struct Holder;\nimpl Holder {\n    pub fn compute(&self) {}\n}\n")
            .expect("write holder.rs");
        let analyzer = RustAnalyzer::from_project(TestProject::new(root, Language::Rust));
        let _ = analyzer.get_analyzed_files();
        let queries = RustUsageQueries::new(&analyzer);

        assert!(
            analyzer
                .lookup_candidates_by_identifier("compute")
                .iter()
                .any(|candidate| candidate.source() == &holder),
            "the method must be offered as a candidate, or the test proves nothing"
        );
        let named = queries.identities_named("compute");
        assert_eq!(named.len(), 1, "identities were {named:?}");
        assert_eq!(named[0].0.file, owner);
        assert!(
            queries
                .identities_in_file_named(&holder, "compute")
                .is_empty(),
            "an associated function declares no module-scope identity"
        );
        let holder_identities = queries.identities_in_file_named(&holder, "Holder");
        assert_eq!(
            holder_identities
                .iter()
                .map(|(identity, _)| identity.namespace)
                .collect::<HashSet<_>>(),
            HashSet::from_iter([RustSymbolNamespace::Type, RustSymbolNamespace::Value]),
            "the module-scope unit struct still declares a type and its \
             value-namespace constructor: {holder_identities:?}"
        );
    }
}
