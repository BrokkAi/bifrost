//! The Rust cargo-route tests that need a live analyzer.
//!
//! `RustCargoRouteIndex` and the canonical module-route fact reader it consumes
//! live in [`brokk_bifrost_rust::cargo_routes`]; only the assertions that reach
//! the analyzer's live summary queries and the store rows analysis wrote for
//! them to read -- have to be built from a real `RustAnalyzer`, so they stay
//! here (the Go block-2 precedent).
//!
//! The direct half of passthrough-macro discovery -- that coordinated
//! `parse_rust_file` facts plus `module_child_edges` replay only faithful item
//! macros -- is pinned inside the Rust crate by
//! `the_module_route_fixture_exercises_every_declaration_shape` and
//! `module_child_edges_use_coordinated_route_facts`, over the same shapes.

#[cfg(test)]
mod tests {

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationInput;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome;

    use brokk_bifrost_analysis::analyzer::store::resolution_publication::SelectedResolutionOverlayInputsOutcome;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadIncomplete;

    use crate::analyzer::RustAnalyzer;
    use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
    use brokk_bifrost_core::analyzer::CodeUnitIndex;
    use brokk_bifrost_rust::cargo_routes::RustCargoTargetRelation;
    use brokk_bifrost_rust::graph_support::RustCargoRouteError;
    use brokk_bifrost_rust::test_helpers::write_fixture_file as write;
    use std::path::PathBuf;

    fn readiness_fixture() -> BuiltInlineTestProject {
        InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"routes\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "pub mod part;\n")
            .file("src/part.rs", "pub fn target() {}\n")
            .build()
    }

    fn module_route_fixture(temp: &tempfile::TempDir) -> PathBuf {
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[package]\nname = \"routes\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        write(&root, "src/lib.rs", "pub mod plain;\n");
        write(&root, "src/plain.rs", "pub struct Marker;\n");
        root
    }

    #[test]
    fn incomplete_live_blob_is_not_filtered_out_of_route_readiness() {
        let fixture = readiness_fixture();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/part.rs");
        let oid = analyzer
            .live_path_snapshot()
            .oid_for_path(&file)
            .expect("live file identity");
        analyzer
            .analyzer_store()
            .mark_parsed_blob_incomplete_for_test(oid, "rust");
        {
            let scope = AnalyzerQueryScope::new(&analyzer);
            assert!(matches!(
                analyzer.cargo_routes_while(&|| true),
                Err(RustCargoRouteError::Unavailable)
            ));
            assert!(scope.store_error().is_some());
        }
        analyzer.warm_usage_facts();
        assert!(analyzer.rust_usage_facts_ready());
        let routes = analyzer
            .cargo_routes_while(&|| true)
            .expect("repaired live publication");
        assert_eq!(
            routes.target_roots_for_file(&file),
            vec![fixture.file("src/lib.rs")]
        );
    }

    #[test]
    fn cancelled_route_read_can_be_retried() {
        let fixture = readiness_fixture();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        assert!(matches!(
            analyzer.cargo_routes_while(&|| false),
            Err(RustCargoRouteError::Cancelled)
        ));
        assert!(analyzer.cargo_routes_while(&|| true).is_ok());
    }
    #[test]
    fn unparseable_live_rust_files_do_not_break_canonical_routes() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"routes\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "pub mod part;\n")
            .file("src/part.rs", "pub fn target() {}\n")
            .file("tests/ui/rust-macro.rs", "fn main() {\0}\n")
            .build();
        let file = fixture.file("tests/ui/rust-macro.rs");
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let scope = AnalyzerQueryScope::new(&analyzer);

        let routes = analyzer
            .cargo_routes()
            .expect("unparseable source does not withhold published routes");

        assert_eq!(
            routes.target_roots_for_file(&fixture.file("src/part.rs")),
            vec![fixture.file("src/lib.rs")]
        );
        assert!(
            analyzer
                .rust_files_without_facts()
                .expect("unparseable source is outside the catch-up set")
                .is_empty()
        );
        let snapshots = analyzer.inner.selected_workspace_snapshots();
        let overlays = analyzer
            .inner
            .selected_rust_resolution_overlay_inputs(
                snapshots.as_ref(),
                &brokk_bifrost_core::cancellation::CancellationToken::default(),
            )
            .expect("selected overlays are available");
        let SelectedResolutionOverlayInputsOutcome::Ready {
            masks,
            content_mounts,
        } = overlays
        else {
            panic!("unparseable source does not withhold selected overlays");
        };
        assert!(
            content_mounts
                .iter()
                .all(|mount| mount.persisted_relative_path() != "tests/ui/rust-macro.rs")
        );
        let languages = [SelectedResolutionLanguage::new("rust", Language::Rust)];
        let input = SelectedResolutionOperationInput::new(
            analyzer.inner.project(),
            analyzer.inner.workspace_id(),
            snapshots.as_ref(),
            &languages,
            &masks,
        )
        .with_content_mounts(content_mounts);
        let selected_operation = analyzer
            .inner
            .analyzer_store()
            .open_selected_resolution_operation(
                input,
                &brokk_bifrost_core::cancellation::CancellationToken::default(),
            )
            .expect("selected operation is available");
        assert!(
            matches!(
                &selected_operation,
                SelectedResolutionOperationOpenOutcome::Ready(_)
            ),
            "selected operation outcome: {selected_operation:?}"
        );
        assert!(matches!(
            scope.read_completion(),
            Err(QueryReadIncomplete::StructureUnavailable(unavailable)) if unavailable == file
        ));
        assert!(scope.store_error().is_none());
        analyzer.warm_usage_facts();
        assert!(analyzer.rust_usage_facts_ready());
    }

    #[test]
    fn malformed_empty_inner_attribute_keeps_canonical_route_publication() {
        let malformed = "#![]\n#![p = ]\n#![p::]\n#![p:: =]\n#![unsafe]\n#![unsafe =]\n";
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"routes\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "pub mod part;\n")
            .file("src/part.rs", "pub fn target() {}\n")
            .file("tests/ui/rust-macro.rs", malformed)
            .build();
        let file = fixture.file("tests/ui/rust-macro.rs");
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let scope = AnalyzerQueryScope::new(&analyzer);

        let routes = analyzer
            .cargo_routes()
            .expect("recovered syntax still publishes the file-root route facts");

        assert_eq!(
            routes.target_roots_for_file(&fixture.file("src/part.rs")),
            vec![fixture.file("src/lib.rs")]
        );
        assert!(
            scope.store_error().is_none(),
            "store error for {file:?}: {:?}",
            scope.store_error()
        );
    }

    #[test]
    fn duplicate_rust_declarations_keep_visibility_specific_metadata_rows() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"routes\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "pub struct Duplicate;\nstruct Duplicate;\n")
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let scope = AnalyzerQueryScope::new(&analyzer);

        analyzer
            .cargo_routes()
            .expect("source declarations with distinct visibility publish independently");

        assert!(
            scope.store_error().is_none(),
            "store error: {:?}",
            scope.store_error()
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "36d2ca4645e4: passthrough item macros must preserve their Cargo route and lexical visibility"
    )]
    fn passthrough_macro_routes_require_faithful_item_replay_and_lexical_visibility() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[package]\nname = \"macros\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        let source = r#"
macro_rules! replay {
    ($($item:item)*) => { $( #[cfg(any())] $item )* };
}
replay! { mod replayed; }

late! { mod defined_too_late; }
macro_rules! late {
    ($($item:item)*) => { $($item)* };
}

macro_rules! feature_items {
    (#![$meta:meta] $($item:item)*) => { $( #[$meta] $item )* };
}
feature_items! { #![cfg(any())] mod feature_replayed; }

macro_rules! delegated_items {
    ($($item:item)*) => { $( #[cfg(any())] $item )* };
}
macro_rules! nested_delegated_items {
    ($($item:item)*) => {
        #[cfg(unix)]
        delegated_items! { $($item)* }
    };
}
nested_delegated_items! { mod transitively_replayed; }

macro_rules! dropped {
    ($($left:item)* $($right:item)*) => { $($left)* };
}
dropped! { mod dropped_left; mod dropped_right; }

macro_rules! stringified {
    ($($item:item)*) => { stringify!($($item)*) };
}
stringified! { mod stringified_item; }

macro_rules! nested {
    ($($item:item)*) => { wrapper! { $($item)* } };
}
nested! { mod nested_item; }

macro_rules! mixed {
    ($name:ident, $item:item) => { $item };
}
mixed! { marker, mod mixed_item; }

macro_rules! shadowed {
    ($($item:item)*) => { $($item)* };
}
shadowed! { mod before_shadow; }
macro_rules! shadowed {
    (mod $name:ident;) => {};
}
shadowed! { mod after_shadow; }

macro_rules! scoped {
    ($($item:item)*) => { $($item)* };
}
mod inline_scope {
    macro_rules! scoped {
        (mod $name:ident;) => {};
    }
    scoped! { mod inner_shadowed; }

    macro_rules! inline_only {
        ($($item:item)*) => { $($item)* };
    }
    inline_only! { mod inline_replayed; }
}
scoped! { mod outer_replayed; }
inline_only! { mod escaped_inline; }
"#;
        write(&root, "src/lib.rs", source);
        for module in [
            "replayed",
            "feature_replayed",
            "transitively_replayed",
            "defined_too_late",
            "dropped_left",
            "dropped_right",
            "stringified_item",
            "nested_item",
            "mixed_item",
            "before_shadow",
            "after_shadow",
            "inner_shadowed",
            "inline_scope/inline_replayed",
            "outer_replayed",
            "escaped_inline",
        ] {
            write(&root, &format!("src/{module}.rs"), "pub struct Marker;\n");
        }

        let library = ProjectFile::new(root.clone(), "src/lib.rs");
        let analyzer = crate::analyzer::RustAnalyzer::from_project(
            brokk_bifrost_core::analyzer::project::TestProject::new(
                root.clone(),
                brokk_bifrost_core::analyzer::model::Language::Rust,
            ),
        );
        let routes = analyzer.cargo_routes().expect("published Cargo routes");

        // `feature_items` decorates each item with `#[$meta]`, which can be
        // any attribute: the crate does not decide its invocations
        // (`source_rust_item_macros.decoration_cfg` is NULL), so the route
        // index does not claim the module either. A `cfg` decoration, even
        // one no profile activates (`cfg(any())`), is decided; the index
        // evaluates no profile and leaves that to the crate's module walk.
        for module in [
            "replayed",
            "transitively_replayed",
            "before_shadow",
            "inline_scope/inline_replayed",
            "outer_replayed",
        ] {
            let file = ProjectFile::new(root.clone(), format!("src/{module}.rs"));
            assert_eq!(
                routes.target_roots_for_file(&file),
                std::slice::from_ref(&library),
                "{module} should be emitted by the latest visible passthrough macro"
            );
        }
        for module in [
            "feature_replayed",
            "dropped_left",
            "dropped_right",
            "stringified_item",
            "nested_item",
            "mixed_item",
            "after_shadow",
            "inner_shadowed",
            "escaped_inline",
            "defined_too_late",
        ] {
            let file = ProjectFile::new(root.clone(), format!("src/{module}.rs"));
            assert!(
                routes.target_roots_for_file(&file).is_empty(),
                "{module} must not be claimed through an unproven passthrough macro"
            );
        }
    }
    /// A file inside a dependency package belongs to that package's root even
    /// when another workspace member depends on it; test-only reach also
    /// crosses an external module declaration in the app's test target.
    #[test]
    fn cargo_routes_compose_from_rows_across_a_multi_crate_workspace() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[workspace]\nmembers = [\"app\", \"engine\", \"devonly\"]\nresolver = \"2\"\n",
        );
        write(
            &root,
            "engine/Cargo.toml",
            "[package]\nname = \"engine\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        write(&root, "engine/src/lib.rs", "pub mod part;\n");
        write(&root, "engine/src/part.rs", "pub struct Part;\n");
        write(
            &root,
            "devonly/Cargo.toml",
            "[package]\nname = \"devonly\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        write(&root, "devonly/src/lib.rs", "pub struct DevOnly;\n");
        write(
            &root,
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\ntest = false\n\n[dependencies]\nengine = { path = \"../engine\" }\n\n[dev-dependencies]\ndevonly = { path = \"../devonly\" }\n",
        );
        write(
            &root,
            "app/src/lib.rs",
            "pub mod feature;\n#[cfg(test)]\nmod tests;\n",
        );
        write(&root, "app/src/feature.rs", "pub struct Feature;\n");
        write(&root, "app/src/tests.rs", "mod helpers;\n");
        write(&root, "app/src/tests/helpers.rs", "pub fn helper() {}\n");

        let analyzer = crate::analyzer::RustAnalyzer::from_project(
            brokk_bifrost_core::analyzer::project::TestProject::new(
                root.clone(),
                brokk_bifrost_core::analyzer::model::Language::Rust,
            ),
        );
        let routes = analyzer.cargo_routes().expect("published Cargo routes");

        let app_library = ProjectFile::new(root.clone(), "app/src/lib.rs");
        let engine_library = ProjectFile::new(root.clone(), "engine/src/lib.rs");
        let feature = ProjectFile::new(root.clone(), "app/src/feature.rs");
        let tests = ProjectFile::new(root.clone(), "app/src/tests.rs");
        let helpers = ProjectFile::new(root.clone(), "app/src/tests/helpers.rs");
        let part = ProjectFile::new(root.clone(), "engine/src/part.rs");

        assert_eq!(
            routes.target_roots_for_file(&feature),
            std::slice::from_ref(&app_library)
        );
        assert_eq!(
            routes.target_roots_for_file(&part),
            std::slice::from_ref(&engine_library)
        );
        assert_eq!(
            routes.resolve_crate_root_file(&feature, "engine"),
            Some(engine_library.clone()),
            "a path dependency still resolves across crates"
        );
        assert_eq!(
            routes.resolve_crate_root_file(&feature, "devonly"),
            None,
            "a library with test routing disabled cannot resolve a dev dependency"
        );
        assert_eq!(
            routes.target_relation(&feature, &part),
            RustCargoTargetRelation::Disjoint
        );
        assert!(
            routes.file_is_test_only(&tests) && routes.file_is_test_only(&helpers),
            "test-only reachability still propagates through the module graph"
        );
        assert!(
            !routes.file_is_test_only(&feature),
            "a production module must stay production"
        );
        let declared: Vec<_> = routes
            .external_module_declarations()
            .iter()
            .map(|declaration| {
                (
                    declaration.declaring_file.rel_path().to_path_buf(),
                    declaration.declaring_module.clone(),
                    declaration.target_file.rel_path().to_path_buf(),
                    declaration.test_gated,
                )
            })
            .collect();
        assert!(
            declared.contains(&(
                PathBuf::from("app/src/lib.rs"),
                "app".to_string(),
                PathBuf::from("app/src/tests.rs"),
                true,
            )),
            "declarations: {declared:?}"
        );
        assert!(
            declared.contains(&(
                PathBuf::from("app/src/tests.rs"),
                "app.tests".to_string(),
                PathBuf::from("app/src/tests/helpers.rs"),
                false,
            )),
            "declarations: {declared:?}"
        );
    }

    #[test]
    fn missing_canonical_routes_are_unavailable_and_retry_after_preparation() {
        let fixture = readiness_fixture();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        assert_eq!(analyzer.get_analyzed_files().len(), 2);
        analyzer.analyzer_store().delete_rust_facts_for_test("rust");
        {
            let scope = AnalyzerQueryScope::new(&analyzer);
            assert!(matches!(
                analyzer.cargo_routes_while(&|| true),
                Err(RustCargoRouteError::Unavailable)
            ));
            assert!(matches!(
                analyzer.cargo_routes(),
                Err(RustCargoRouteError::Unavailable)
            ));
            assert!(scope.store_error().is_some());
        }
        assert_eq!(analyzer.module_route_fact_fallback_count_for_test(), 0);
        assert!(!analyzer.rust_usage_facts_ready());
        analyzer.warm_usage_facts();
        assert!(analyzer.rust_usage_facts_ready());
        let routes = analyzer
            .cargo_routes_while(&|| true)
            .expect("retry after canonical preparation");
        assert_eq!(
            routes.target_roots_for_file(&fixture.file("src/part.rs")),
            vec![fixture.file("src/lib.rs")]
        );
    }

    #[test]
    fn failed_canonical_route_read_never_publishes_a_partial_index() {
        let fixture = readiness_fixture();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        assert_eq!(analyzer.get_analyzed_files().len(), 2);
        analyzer.analyzer_store().drop_rust_modules_table_for_test();
        let scope = AnalyzerQueryScope::new(&analyzer);
        assert!(matches!(
            analyzer.cargo_routes_while(&|| true),
            Err(RustCargoRouteError::Unavailable)
        ));
        let error = scope
            .store_error()
            .expect("route SQL error must reach the query boundary");
        assert!(
            error
                .to_string()
                .contains("canonical Rust Cargo-route publication"),
            "{error}"
        );
        assert_eq!(analyzer.module_route_fact_fallback_count_for_test(), 0);
    }

    #[test]
    fn published_files_without_cargo_have_valid_empty_routes() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", "pub fn target() {}\n")
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let routes = analyzer
            .cargo_routes_while(&|| true)
            .expect("no manifest is not missing publication");
        assert!(
            routes
                .target_roots_for_file(&fixture.file("src/lib.rs"))
                .is_empty()
        );
    }

    #[test]
    fn composing_the_cargo_route_index_parses_no_workspace_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = module_route_fixture(&temp);
        let analyzer = crate::analyzer::RustAnalyzer::from_project(
            brokk_bifrost_core::analyzer::project::TestProject::new(
                root.clone(),
                brokk_bifrost_core::analyzer::model::Language::Rust,
            ),
        );
        // Analysis is what writes the fact rows. A freshly analyzed workspace
        // does not need the catch-up that repairs a live blob analysis did not
        // reach.
        analyzer.reset_module_route_fact_fallback_count_for_test();

        let routes = analyzer.cargo_routes().expect("published Cargo routes");

        let library = ProjectFile::new(root.clone(), "src/lib.rs");
        assert_eq!(
            routes.target_roots_for_file(&ProjectFile::new(root.clone(), "src/plain.rs")),
            std::slice::from_ref(&library),
            "the index still answers from rows"
        );
        assert_eq!(
            analyzer.module_route_fact_fallback_count_for_test(),
            0,
            "composing the Cargo routes must not parse a single workspace file"
        );
    }
}
