//! The analyzer-owned half of Rust's graph support: retained bounded indexes
//! and the forwards `bifrost-lsp` and the SPI block reach through.
//!
//! Everything these methods call lives in [`brokk_bifrost_rust::graph_support`];
//! The analyzer type and its caches are analysis-owned, while reference
//! contexts are query-scoped views implemented in `bifrost-rust`.

use crate::analyzer::usages::{ExportIndex, ImportBinder};
use crate::analyzer::{AnalyzerQueryScope, QueryScope, QueryToken};
use crate::analyzer::{CodeUnit, CodeUnitIndex, ProjectFile};
use crate::hash::HashSet;
use brokk_bifrost_rust::graph_support::{
    RustPackageFileIndex, RustReferenceContext, exact_member, export_index_of_declarations,
    forward_reference_context_of, forward_reference_context_of_while, is_rust_trait_declaration,
    reference_context_of, reference_context_of_while, resolve_module_files,
    rust_trait_member_implementations, rust_usage_candidate_files,
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
        let scope = AnalyzerQueryScope::new(self);
        let index = Arc::new(export_index_of_declarations(
            self,
            scope.token(),
            file,
            &declarations,
        ));
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

    pub fn reference_context_of<'a>(
        &'a self,
        token: QueryToken<'a>,
        file: &ProjectFile,
    ) -> RustReferenceContext<'a> {
        reference_context_of(self, token, file)
    }

    pub fn reference_context_of_while<'a>(
        &'a self,
        token: QueryToken<'a>,
        file: &ProjectFile,
        keep_going: impl Fn() -> bool + 'a,
    ) -> RustReferenceContext<'a> {
        reference_context_of_while(self, token, file, keep_going)
    }

    pub fn forward_reference_context_of<'a>(
        &'a self,
        token: QueryToken<'a>,
        file: &ProjectFile,
    ) -> RustReferenceContext<'a> {
        forward_reference_context_of(self, token, file)
    }

    pub fn forward_reference_context_of_while<'a>(
        &'a self,
        token: QueryToken<'a>,
        file: &ProjectFile,
        keep_going: impl Fn() -> bool + 'a,
    ) -> RustReferenceContext<'a> {
        forward_reference_context_of_while(self, token, file, keep_going)
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
        let scope = AnalyzerQueryScope::new(self);
        resolve_module_files(self, scope.token(), importing_file, module_specifier)
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
        let scope = AnalyzerQueryScope::new(self);
        rust_trait_member_implementations(self, scope.token(), trait_member)
    }

    /// Reached from `bifrost-lsp`; see
    /// [`Self::rust_trait_member_implementations`].
    pub fn is_rust_trait_declaration(&self, code_unit: &CodeUnit) -> bool {
        is_rust_trait_declaration(self, code_unit)
    }
}

/// Frozen closure-enumerating reference resolver from before the per-site
/// rewrite. It is intentionally test-only: the live implementation must never
/// enumerate a namespace or glob export surface just to resolve one source
/// name, while this oracle does exactly that to pin answer equivalence.
#[cfg(test)]
mod frozen {
    use super::*;
    use crate::hash::HashMap;
    use brokk_bifrost_core::analyzer::usages::model::{ExportEntry, ImportKind};
    use brokk_bifrost_rust::declarations::rust_package_name;
    use brokk_bifrost_rust::graph_support::{
        canonical_export_fqn_from_files, resolve_module_package,
    };
    use brokk_bifrost_rust::imports::{
        resolve_rust_module_path_with_crate, rust_crate_root_package,
    };

    #[derive(Debug, Default)]
    pub(super) struct FrozenReferenceContext {
        package: String,
        crate_package: String,
        named: HashMap<String, String>,
        namespace: HashMap<String, String>,
        scoped: HashMap<String, String>,
        glob: HashMap<String, String>,
        same_file: HashMap<String, String>,
    }

    impl FrozenReferenceContext {
        pub(super) fn resolve_bare(&self, name: &str) -> Option<&str> {
            self.named
                .get(name)
                .or_else(|| self.namespace.get(name))
                .or_else(|| self.same_file.get(name))
                .or_else(|| self.glob.get(name))
                .map(String::as_str)
        }

        pub(super) fn bare_names_resolving_to(&self, target: &str) -> HashSet<String> {
            self.named
                .iter()
                .chain(self.namespace.iter())
                .chain(self.same_file.iter())
                .chain(self.glob.iter())
                .filter(|(_, fqn)| fqn.as_str() == target)
                .map(|(name, _)| name.clone())
                .collect()
        }

        pub(super) fn resolve_scoped(&self, path: &str, name: &str) -> Option<String> {
            self.resolve_scoped_owner(path)
                .map(|owner| join(&owner, name))
        }

        pub(super) fn resolve_scoped_owner(&self, path: &str) -> Option<String> {
            if let Some(canonical) = self.scoped.get(path) {
                return Some(canonical.clone());
            }
            if let Some((parent, item)) = path.rsplit_once("::")
                && let Some(owner) = self.resolve_scoped_owner(parent)
            {
                return Some(join(&owner, item));
            }
            if let Some(package) = self.namespace.get(path) {
                return Some(package.clone());
            }
            if rooted(path)
                && let Some(package) =
                    resolve_rust_module_path_with_crate(&self.package, &self.crate_package, path)
            {
                return Some(package);
            }
            self.named
                .get(path)
                .or_else(|| self.same_file.get(path))
                .or_else(|| self.glob.get(path))
                .cloned()
        }
    }

    pub(super) fn build(
        analyzer: &RustAnalyzer,
        token: QueryToken<'_>,
        file: &ProjectFile,
        forward: bool,
    ) -> FrozenReferenceContext {
        let binder = analyzer.import_binder_of(file);
        let same_file = analyzer
            .declarations(file)
            .into_iter()
            .map(|unit| (unit.identifier().to_string(), unit.fq_name()))
            .collect();
        let mut named = HashMap::default();
        let mut namespace = HashMap::default();
        let mut scoped = HashMap::default();
        let mut glob_candidates: HashMap<String, HashSet<String>> = HashMap::default();

        for (local, binding) in &binder.bindings {
            match binding.kind {
                ImportKind::Named => {
                    if let Some(imported) = binding.imported_name.as_deref() {
                        let files = analyzer.resolve_module_files(file, &binding.module_specifier);
                        let resolved = canonical(analyzer, token, &files, imported, forward)
                            .or_else(|| {
                                resolve_module_package(
                                    analyzer,
                                    token,
                                    file,
                                    &binding.module_specifier,
                                )
                                .map(|package| join(&package, imported))
                            });
                        if let Some(resolved) = resolved {
                            named.insert(local.clone(), resolved);
                        }
                    }
                }
                ImportKind::Namespace => {
                    if let Some(package) =
                        resolve_module_package(analyzer, token, file, &binding.module_specifier)
                    {
                        namespace.insert(local.clone(), package);
                    }
                    let files = analyzer.resolve_module_files(file, &binding.module_specifier);
                    for name in export_names(analyzer, &files) {
                        if let Some(fqn) = canonical(analyzer, token, &files, &name, forward) {
                            scoped.insert(format!("{local}::{name}"), fqn);
                        }
                    }
                }
                ImportKind::Glob => {
                    let files = analyzer.resolve_module_files(file, &binding.module_specifier);
                    for name in export_names(analyzer, &files) {
                        if let Some(fqn) = canonical(analyzer, token, &files, &name, forward) {
                            glob_candidates.entry(name).or_default().insert(fqn);
                        }
                    }
                }
                ImportKind::Default | ImportKind::CommonJsRequire => {}
            }
        }

        let own_files = [file.clone()];
        let own_index = analyzer.export_index_of(file);
        let mut own_names: HashSet<String> = own_index.exports_by_name.keys().cloned().collect();
        for star in &own_index.reexport_stars {
            let files = analyzer.resolve_module_files(file, &star.module_specifier);
            own_names.extend(export_names(analyzer, &files));
        }
        for name in own_names {
            if matches!(
                own_index.exports_by_name.get(&name),
                Some(ExportEntry::Local { .. })
            ) {
                continue;
            }
            if let Some(fqn) = canonical(analyzer, token, &own_files, &name, forward) {
                named.entry(name).or_insert(fqn);
            }
        }

        let glob = glob_candidates
            .into_iter()
            .filter_map(|(name, mut candidates)| {
                (candidates.len() == 1)
                    .then(|| (name, candidates.drain().next().expect("one glob candidate")))
            })
            .collect();
        FrozenReferenceContext {
            package: rust_package_name(file),
            crate_package: rust_crate_root_package(file),
            named,
            namespace,
            scoped,
            glob,
            same_file,
        }
    }

    fn canonical(
        analyzer: &RustAnalyzer,
        token: QueryToken<'_>,
        files: &[ProjectFile],
        name: &str,
        forward: bool,
    ) -> Option<String> {
        canonical_export_fqn_from_files(analyzer, token, files, name, forward, &|| true)
            .expect("uninterrupted frozen export traversal")
    }

    fn export_names(analyzer: &RustAnalyzer, files: &[ProjectFile]) -> HashSet<String> {
        let mut names = HashSet::default();
        let mut visited = HashSet::default();
        let mut pending = files.to_vec();
        while let Some(file) = pending.pop() {
            if !visited.insert(file.clone()) {
                continue;
            }
            let index = analyzer.export_index_of(&file);
            names.extend(index.exports_by_name.keys().cloned());
            for star in &index.reexport_stars {
                pending.extend(analyzer.resolve_module_files(&file, &star.module_specifier));
            }
        }
        names
    }

    fn join(owner: &str, name: &str) -> String {
        if owner.is_empty() {
            name.to_string()
        } else {
            format!("{owner}.{name}")
        }
    }

    fn rooted(path: &str) -> bool {
        matches!(path.split("::").next(), Some("crate" | "self" | "super"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{IAnalyzer, Language};
    use crate::test_support::AnalyzerFixture;
    use std::cell::Cell;
    use std::collections::BTreeSet;

    const EQUIVALENCE_FIXTURE: &[(&str, &str)] = &[
        (
            "Cargo.toml",
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        ),
        (
            "src/lib.rs",
            "pub mod wide;\npub mod barrel;\npub mod consumer;\npub mod cyclic_a;\npub mod cyclic_b;\npub mod macros;\npub struct RootType;\n",
        ),
        (
            "src/wide.rs",
            "pub struct Widget;\npub struct Gadget;\npub fn make_widget() -> Widget { Widget }\npub const LIMIT: usize = 3;\npub enum Mode { On, Off }\nfn private_helper() {}\n",
        ),
        (
            "src/barrel.rs",
            "pub use crate::wide::Widget;\npub use crate::wide::Gadget as Renamed;\npub use crate::cyclic_a::*;\n",
        ),
        (
            "src/cyclic_a.rs",
            "pub use crate::cyclic_b::*;\npub struct AlphaItem;\n",
        ),
        (
            "src/cyclic_b.rs",
            "pub use crate::cyclic_a::*;\npub struct BetaItem;\n",
        ),
        (
            "src/macros.rs",
            "#[macro_export]\nmacro_rules! shout { () => {} }\npub fn use_macro() { crate::shout!(); }\n",
        ),
        (
            "src/consumer.rs",
            "use crate::wide;\nuse crate::barrel;\nuse crate::wide::Widget;\nuse crate::wide::Gadget as Alias;\nuse crate::barrel::Renamed;\nuse crate::barrel::*;\npub struct AlphaItem;\npub fn consume() { let _a = Widget; let _b = wide::make_widget(); let _c = Alias; let _d = Renamed; let _e = wide::LIMIT; let _h = barrel::Widget; let _i = barrel::Renamed; let _f = AlphaItem; let _g = BetaItem; }\n",
        ),
    ];

    const EQUIVALENCE_FILES: &[&str] = &[
        "src/lib.rs",
        "src/wide.rs",
        "src/barrel.rs",
        "src/cyclic_a.rs",
        "src/cyclic_b.rs",
        "src/macros.rs",
        "src/consumer.rs",
    ];
    const EQUIVALENCE_NAMES: &[&str] = &[
        "Widget",
        "Gadget",
        "Renamed",
        "Alias",
        "AlphaItem",
        "BetaItem",
        "RootType",
        "Mode",
        "LIMIT",
        "wide",
        "barrel",
        "consumer",
        "cyclic_a",
        "cyclic_b",
        "macros",
        "make_widget",
        "private_helper",
        "use_macro",
        "consume",
        "shout",
        "crate",
        "self",
        "super",
        "absent_name",
    ];
    const EQUIVALENCE_PREFIXES: &[&str] = &[
        "wide",
        "barrel",
        "cyclic_a",
        "cyclic_b",
        "macros",
        "crate",
        "crate::wide",
        "crate::barrel",
        "self",
        "super",
        "Widget",
        "Alias",
        "absent_prefix",
        "wide::Widget",
        "wide::make_widget",
        "wide::absent_name",
        "barrel::Widget",
        "barrel::Renamed",
        "barrel::AlphaItem",
        "barrel::BetaItem",
        "barrel::absent_name",
        "cyclic_a::BetaItem",
        "crate::wide::Widget",
        "self::AlphaItem",
    ];
    const EQUIVALENCE_TARGETS: &[&str] = &[
        "fixture.wide.Widget",
        "fixture.wide.Gadget",
        "fixture.wide.make_widget",
        "fixture.wide.LIMIT",
        "fixture.cyclic_a.AlphaItem",
        "fixture.cyclic_b.BetaItem",
        "fixture.consumer.AlphaItem",
        "fixture.wide",
        "fixture.barrel",
        "absent.Fqn",
    ];

    #[test]
    fn reference_resolution_matches_the_frozen_closure_algorithm() {
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, EQUIVALENCE_FIXTURE);
        let analyzer = RustAnalyzer::from_project(fixture.test_project().clone());
        let root = fixture.project_root();
        let consumer = ProjectFile::new(root.clone(), "src/consumer.rs");
        let scope = AnalyzerQueryScope::new(&analyzer);
        let anchors = analyzer.reference_context_of(scope.token(), &consumer);
        assert_eq!(
            anchors.resolve_scoped_owner("barrel::Widget").as_deref(),
            Some("fixture.wide.Widget")
        );
        assert_eq!(
            anchors.resolve_scoped_owner("barrel::Renamed").as_deref(),
            Some("fixture.wide.Gadget")
        );
        assert_eq!(
            anchors.resolve_bare("BetaItem").as_deref(),
            Some("fixture.cyclic_b.BetaItem")
        );
        assert_eq!(
            anchors.resolve_bare("Alias").as_deref(),
            Some("fixture.wide.Gadget")
        );
        assert_eq!(
            anchors.resolve_bare("AlphaItem").as_deref(),
            Some("fixture.consumer.AlphaItem")
        );

        for relative in EQUIVALENCE_FILES {
            let file = ProjectFile::new(root.clone(), relative);
            for forward in [false, true] {
                let frozen = frozen::build(&analyzer, scope.token(), &file, forward);
                let live = if forward {
                    analyzer.forward_reference_context_of(scope.token(), &file)
                } else {
                    analyzer.reference_context_of(scope.token(), &file)
                };
                for name in EQUIVALENCE_NAMES {
                    assert_eq!(
                        live.resolve_bare(name),
                        frozen.resolve_bare(name).map(str::to_string),
                        "bare: file={relative} forward={forward} name={name}"
                    );
                }
                for prefix in EQUIVALENCE_PREFIXES {
                    assert_eq!(
                        live.resolve_scoped_owner(prefix),
                        frozen.resolve_scoped_owner(prefix),
                        "owner: file={relative} forward={forward} prefix={prefix}"
                    );
                    for name in EQUIVALENCE_NAMES {
                        assert_eq!(
                            live.resolve_scoped(prefix, name),
                            frozen.resolve_scoped(prefix, name),
                            "scoped: file={relative} forward={forward} prefix={prefix} name={name}"
                        );
                    }
                }
                for target in EQUIVALENCE_TARGETS {
                    let mut live_names: Vec<_> =
                        live.bare_names_resolving_to(target).into_iter().collect();
                    let mut frozen_names: Vec<_> =
                        frozen.bare_names_resolving_to(target).into_iter().collect();
                    live_names.sort();
                    frozen_names.sort();
                    assert_eq!(
                        live_names, frozen_names,
                        "inverse: file={relative} forward={forward} target={target}"
                    );
                }
            }
        }
    }

    #[test]
    fn export_index_is_reused_while_reference_contexts_are_query_scoped() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Rust,
            &[
                ("src/lib.rs", "pub mod exports;\n"),
                ("src/exports.rs", "pub use std::collections::HashMap;\n"),
            ],
        );
        let analyzer = RustAnalyzer::from_project(fixture.test_project().clone());
        let file = ProjectFile::new(fixture.project_root(), "src/exports.rs");

        let first = analyzer.export_index_of(&file);
        let second = analyzer.export_index_of(&file);

        assert!(Arc::ptr_eq(&first, &second));
        let scope = AnalyzerQueryScope::new(&analyzer);
        assert_eq!(
            analyzer
                .forward_reference_context_of(scope.token(), &file)
                .resolve_bare("HashMap"),
            Some("std.collections.HashMap".to_string())
        );

        let unrelated_watcher_noise = ProjectFile::new(
            fixture.project_root(),
            format!(".bifrost/cache/{}", crate::cache_db::cache_db_file_name()),
        );
        let updated = analyzer.update(&BTreeSet::from([file.clone(), unrelated_watcher_noise]));
        let after_noop_update = updated.export_index_of(&file);

        assert!(Arc::ptr_eq(&first, &after_noop_update));
        assert!(updated.export_indexes.get(&file).is_some());
    }

    #[test]
    fn issue_1228_forward_reference_query_observes_cancellation() {
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
        let scope = AnalyzerQueryScope::new(&analyzer);
        let checks = Cell::new(0usize);

        let interrupted = analyzer.forward_reference_context_of_while(scope.token(), &file, || {
            let next = checks.get() + 1;
            checks.set(next);
            false
        });

        assert_eq!(interrupted.resolve_bare("Alias"), None);
        assert_eq!(checks.get(), 1);

        let complete = analyzer.forward_reference_context_of(scope.token(), &file);

        assert_eq!(
            complete.resolve_bare("Alias"),
            Some("exports.Alias".to_string())
        );
        assert_eq!(
            complete.resolve_bare("helper"),
            Some("exports.helper".to_string())
        );
    }

    #[test]
    fn issue_1304_inverted_reference_query_observes_cancellation() {
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
        let scope = AnalyzerQueryScope::new(&analyzer);
        let checks = Cell::new(0usize);

        let interrupted = analyzer.reference_context_of_while(scope.token(), &file, || {
            let next = checks.get() + 1;
            checks.set(next);
            false
        });

        assert_eq!(interrupted.resolve_bare("Alias"), None);
        assert_eq!(checks.get(), 1);

        let complete = analyzer.reference_context_of(scope.token(), &file);

        assert_eq!(
            complete.resolve_bare("Alias"),
            Some("exports.Alias".to_string())
        );
        assert_eq!(
            complete.resolve_bare("helper"),
            Some("exports.helper".to_string())
        );
    }
}
