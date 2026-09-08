//! The Rust usage-query tests that need a live analyzer.
//!
//! `RustUsageQueries` lives in [`brokk_bifrost_rust::usage_queries`]; every one
//! of these tests builds a real `RustAnalyzer` so that analysis writes the fact
//! rows the queries read, which `brokk-bifrost-rust` cannot do because it may
//! not name an analyzer.

#[cfg(test)]
mod tests {
    use crate::analyzer::CodeUnitIndex;
    use crate::analyzer::rust::RustAnalyzer;
    use crate::analyzer::rust::rust_package_name;
    use crate::analyzer::{AnalyzerQueryScope, QueryScope};
    use crate::analyzer::{Language, ProjectFile, TestProject};
    use crate::hash::HashSet;
    use brokk_bifrost_core::analyzer::rust_facts::RUST_OCCURRENCE_CODE;
    use brokk_bifrost_rust::imports::rust_module_extents;
    use brokk_bifrost_rust::usage::{ModuleKey, RustImportExtent, RustSymbolNamespace};
    use brokk_bifrost_rust::usage_queries::RustUsageQueries;
    use brokk_bifrost_rust::usage_queries::compose_module;
    use std::sync::Arc;
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
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn module_extents_from_the_store_match_the_syntax_tree_projection() {
        let (_temp, analyzer, lib, _worker) = analyzer_with_fixture();
        let scope = AnalyzerQueryScope::new(&analyzer);
        let prepared = analyzer
            .prepared_syntax(scope.token(), &lib)
            .expect("prepared syntax");
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
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn module_extents_compose_the_live_package_into_the_stored_relative_names() {
        let (_temp, analyzer, _lib, _worker) = analyzer_with_fixture();
        let leaf = analyzed_file(&analyzer, "leaf.rs");
        let package = rust_package_name(&leaf);
        assert!(!package.is_empty(), "fixture must have a nested package");
        let scope = AnalyzerQueryScope::new(&analyzer);
        let prepared = analyzer
            .prepared_syntax(scope.token(), &leaf)
            .expect("prepared syntax");
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

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
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

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
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

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn import_bindings_reproduce_the_paths_and_lexical_reach() {
        let (_temp, analyzer, lib, worker) = analyzer_with_fixture();
        let queries = RustUsageQueries::new(&analyzer);

        let lib_bindings = queries.import_bindings_of(&lib);
        let described: Vec<_> = lib_bindings
            .iter()
            .map(|binding| (binding.path.join("::"), binding.local_name.named()))
            .collect();
        assert_eq!(
            described,
            vec![
                ("worker::Job".to_string(), Some("Task")),
                ("std::fmt::Debug".to_string(), Some("Debug")),
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

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn repeated_import_binding_reads_decode_one_file_once() {
        let (_temp, analyzer, lib, _worker) = analyzer_with_fixture();
        let queries = RustUsageQueries::new(&analyzer);

        let first = queries.import_bindings_of(&lib);
        let second = queries.import_bindings_of(&lib);

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(queries.import_binding_computations(), 1);
    }

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn prederived_module_keys_match_the_canonical_constructor() {
        let (_temp, analyzer, lib, worker) = analyzer_with_fixture();
        let leaf = analyzed_file(&analyzer, "leaf.rs");
        let queries = RustUsageQueries::new(&analyzer);

        for file in [&lib, &worker, &leaf] {
            let identity = queries.path_identity_of(file);
            for module in [
                identity.package.as_str(),
                identity.crate_root_package.as_str(),
                "unrelated.relative.module",
                "",
            ] {
                assert_eq!(
                    queries.module_key_of(file, module),
                    ModuleKey::new(file, module),
                    "prederived key differs for {file:?} and {module:?}"
                );
            }
        }
    }

    /// The inverted lookups are the candidate half of the design. They must
    /// find the files that mention a name, filter by context so a prose
    /// mention is not offered to a reference search, and stay one indexed
    /// lookup rather than a workspace walk.
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
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

        assert_eq!(
            queries.files_importing_module_path("crate"),
            vec![worker.clone()]
        );
        assert_eq!(
            queries.files_importing_module_path("worker"),
            vec![lib.clone()]
        );
        assert_eq!(
            queries.files_importing_module_component("worker"),
            vec![lib],
            "the module component is the written path for a named import"
        );
        assert_eq!(
            queries.files_importing_module_component("root"),
            vec![worker],
            "a namespace import records the module as its imported name"
        );
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
#[cfg(test)]
mod issue_3080_phase_two {
    use crate::analyzer::rust::RustAnalyzer;
    use crate::analyzer::{AnalyzerQueryScope, QueryScope};
    use crate::analyzer::{CodeUnitIndex, Language};
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_rust::lexical_scope::RustCfgCondition;
    use brokk_bifrost_rust::usage::{
        RustImportEdgeKind, RustSymbolNamespace, usage_binding_local_names, usage_binding_names,
        usage_binding_seeds_while, usage_candidate_files_from_binding_seeds_while,
    };
    use brokk_bifrost_rust::usage_queries::RustUsageQueries;
    use brokk_bifrost_rust::usage_walks::RustUsageWalks;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn fixture() -> (crate::inline_project::BuiltInlineTestProject, RustAnalyzer) {
        let project = InlineTestProject::with_language(Language::Rust)
        .file("Cargo.toml", "[package]\nname = \"unnamed_probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
        .file("src/lib.rs", "pub mod model; pub mod barrel; pub mod consumer; pub mod named; pub mod namespace; pub mod glob;\n")
        .file("src/model.rs", "pub trait Trait { fn ping(&self); }\npub struct Value;\nimpl Trait for Value { fn ping(&self) {} }\n#[cfg(feature = \"a\")] pub struct Pair<T>(pub T);\n#[cfg(not(feature = \"a\"))] pub struct Pair<T, U>(T, U);\n")
        .file("src/barrel.rs", "pub use crate::model::Trait as _;\n")
        .file("src/consumer.rs", "use crate::barrel::*;\nfn call(value: crate::model::Value) { value.ping(); }\n")
        .file("src/named.rs", "use crate::model::Trait as Alias;\nfn call(value: crate::model::Value) { value.ping(); }\n")
        .file("src/namespace.rs", "use crate::model as ns;\nfn call(value: ns::Value) { ns::Trait::ping(&value); }\n")
        .file("src/glob.rs", "use crate::model::*;\nfn call(value: Value) { value.ping(); }\n")
        .build();
        let analyzer = RustAnalyzer::from_project(project.project().clone());
        (project, analyzer)
    }

    #[test]
    fn unnamed_glob_consumers_are_candidates_without_reference_names() {
        let (project, analyzer) = fixture();
        let roots = analyzer
            .declarations(&project.file("src/model.rs"))
            .into_iter()
            .filter(|unit| unit.identifier() == "Trait")
            .collect();
        let scope = AnalyzerQueryScope::new(&analyzer);
        let seeds = usage_binding_seeds_while(&analyzer, scope.token(), &roots, &|| true)
            .expect("complete seeds");
        let consumer = project.file("src/consumer.rs");
        assert!(
            seeds
                .verified_importer_files()
                .any(|file| file == &consumer)
        );
        let candidates = usage_candidate_files_from_binding_seeds_while(
            &analyzer,
            scope.token(),
            &seeds,
            &|| true,
        )
        .expect("complete candidates");
        assert!(candidates.contains(&consumer), "{candidates:?}");
        assert!(
            seeds
                .unnamed_visibility()
                .any(|route| route.importer == consumer && route.target.name == "Trait")
        );
        assert!(
            !usage_binding_local_names(&analyzer, scope.token(), &consumer, &seeds).contains("_")
        );
        assert!(
            usage_binding_local_names(
                &analyzer,
                scope.token(),
                &project.file("src/named.rs"),
                &seeds
            )
            .contains("Alias")
        );
        assert!(
            usage_binding_local_names(
                &analyzer,
                scope.token(),
                &project.file("src/glob.rs"),
                &seeds
            )
            .contains("Trait")
        );
        let (_, qualified) = usage_binding_names(
            &analyzer,
            scope.token(),
            &project.file("src/namespace.rs"),
            &seeds,
        );
        assert!(qualified.contains("ns::Trait"), "{qualified:?}");
        let walks = RustUsageWalks::new(&analyzer, scope.token());
        assert!(walks.forward_import_edges_of(&project.file("src/barrel.rs")).iter().any(|edge| matches!(&edge.kind, RustImportEdgeKind::Unnamed { imported_name } if imported_name == "Trait")));
        assert!(walks.forward_import_edges_of(&project.file("src/named.rs")).iter().any(|edge| matches!(&edge.kind, RustImportEdgeKind::Named { imported_name, local_name } if imported_name == "Trait" && local_name == "Alias")));
        assert!(walks.forward_import_edges_of(&project.file("src/namespace.rs")).iter().any(|edge| matches!(&edge.kind, RustImportEdgeKind::Namespace { local_name } if local_name == "ns")));
        assert!(
            walks
                .forward_import_edges_of(&consumer)
                .iter()
                .any(|edge| matches!(&edge.kind, RustImportEdgeKind::Glob))
        );
    }

    #[test]
    fn declaration_and_constructor_guards_remain_paired() {
        let (project, analyzer) = fixture();
        let queries = RustUsageQueries::new(&analyzer);
        let facts = queries.declaration_facts_of(&project.file("src/model.rs"));
        for namespace in [RustSymbolNamespace::Type, RustSymbolNamespace::Value] {
            let (_, occurrences) = facts
                .domain_cfg_occurrences
                .iter()
                .find(|(identity, _)| identity.name == "Pair" && identity.namespace == namespace)
                .expect("paired identity");
            assert_eq!(occurrences.len(), 2, "{occurrences:?}");
            for (domain, guard) in occurrences {
                let public_expected = namespace == RustSymbolNamespace::Type
                    || matches!(guard, RustCfgCondition::Atom(_));
                assert_eq!(
                    *domain == brokk_bifrost_rust::usage::Domain::Public,
                    public_expected,
                    "visibility must remain paired with its occurrence guard: {occurrences:?}"
                );
            }
            assert!(
                occurrences
                    .iter()
                    .any(|(_, guard)| matches!(guard, RustCfgCondition::Atom(_))),
                "{occurrences:?}"
            );
            assert!(
                occurrences
                    .iter()
                    .any(|(_, guard)| matches!(guard, RustCfgCondition::NotAtom(_))),
                "{occurrences:?}"
            );
        }
    }

    #[test]
    fn cancelled_seed_or_candidate_walk_publishes_no_partial_set() {
        let (project, analyzer) = fixture();
        let roots = analyzer
            .declarations(&project.file("src/model.rs"))
            .into_iter()
            .filter(|unit| unit.identifier() == "Trait")
            .collect();
        let scope = AnalyzerQueryScope::new(&analyzer);
        assert!(usage_binding_seeds_while(&analyzer, scope.token(), &roots, &|| false).is_none());
        let calls = AtomicUsize::new(0);
        assert!(
            usage_binding_seeds_while(&analyzer, scope.token(), &roots, &|| calls
                .fetch_add(1, Ordering::Relaxed)
                < 8)
            .is_none()
        );
        let seeds = usage_binding_seeds_while(&analyzer, scope.token(), &roots, &|| true)
            .expect("complete seeds after cancellation");
        assert!(
            usage_candidate_files_from_binding_seeds_while(
                &analyzer,
                scope.token(),
                &seeds,
                &|| false
            )
            .is_none()
        );
    }
    #[test]
    fn macro_item_occurrences_preserve_both_guards() {
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"macro_probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file(
                "src/lib.rs",
                r#"
macro_rules! items { ($($item:item)*) => { $($item)* }; }
items! {
    #[cfg(feature = "a")] pub struct Pair(pub u8);
    #[cfg(not(feature = "a"))] pub struct Pair(pub u16);
}
"#,
            )
            .build();
        let analyzer = RustAnalyzer::from_project(project.project().clone());
        let queries = RustUsageQueries::new(&analyzer);
        let facts = queries.declaration_facts_of(&project.file("src/lib.rs"));
        for namespace in [RustSymbolNamespace::Type, RustSymbolNamespace::Value] {
            let (_, occurrences) = facts
                .domain_cfg_occurrences
                .iter()
                .find(|(identity, _)| identity.name == "Pair" && identity.namespace == namespace)
                .expect("macro item identity");
            assert_eq!(occurrences.len(), 2, "{occurrences:?}");
            assert!(
                occurrences
                    .iter()
                    .any(|(_, guard)| matches!(guard, RustCfgCondition::Atom(_))),
                "{occurrences:?}"
            );
            assert!(
                occurrences
                    .iter()
                    .any(|(_, guard)| matches!(guard, RustCfgCondition::NotAtom(_))),
                "{occurrences:?}"
            );
        }
    }
}
