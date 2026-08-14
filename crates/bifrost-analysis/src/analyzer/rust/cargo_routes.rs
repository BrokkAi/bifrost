//! The Rust cargo-route tests that need a live analyzer.
//!
//! `RustCargoRouteIndex` and the module-route fact extraction it composes from
//! live in [`brokk_bifrost_rust::cargo_routes`]; only the assertions that reach
//! the analyzer -- its `cargo_routes()` memo, and the store rows analysis wrote
//! for it to read -- have to be built from a real `RustAnalyzer`, so they stay
//! here (the Go block-2 precedent).
//!
//! The direct half of passthrough-macro discovery -- that
//! `extract_rust_module_route_facts` plus `module_child_edges` replay only the
//! faithful item macros -- is pinned inside the Rust crate by
//! `the_module_route_fixture_exercises_every_declaration_shape` and
//! `module_child_edges_reproduce_the_frozen_syntax_walk`, over the same shapes.

#[cfg(test)]
mod tests {
    use crate::analyzer::ProjectFile;
    use brokk_bifrost_rust::cargo_routes::RustCargoTargetRelation;
    use std::path::{Path, PathBuf};

    #[test]
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
            crate::analyzer::TestProject::new(root.clone(), crate::analyzer::Language::Rust),
        );
        let routes = analyzer.cargo_routes();

        for module in [
            "replayed",
            "feature_replayed",
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

    /// The point of issue #1793: composing the index reads rows, and parses
    /// nothing. The counter is the `2ba5dda4` structural-pin idiom.
    #[test]
    fn composing_the_cargo_route_index_parses_no_workspace_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = module_route_fixture(&temp);
        let analyzer = crate::analyzer::RustAnalyzer::from_project(
            crate::analyzer::TestProject::new(root.clone(), crate::analyzer::Language::Rust),
        );
        // Analysis is what writes the fact rows. The catch-up that repairs a
        // live blob analysis did not reach is restored in Phase 2 step 2b of
        // `.agents/plans/port-optimization-arc-to-upstream.md`; a freshly
        // analyzed workspace does not need it.
        analyzer.reset_module_route_fact_fallback_count_for_test();

        let routes = analyzer.cargo_routes();

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

    /// The index answers the same questions across a multi-crate workspace
    /// when it is composed from rows: target membership, cross-crate route
    /// resolution, the module-declaration list the usage walks read, and the
    /// test-only classification that only the module graph can decide.
    #[test]
    fn cargo_routes_compose_from_rows_across_a_multi_crate_workspace() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[workspace]\nmembers = [\"app\", \"engine\"]\nresolver = \"2\"\n",
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
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nengine = { path = \"../engine\" }\n",
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
            crate::analyzer::TestProject::new(root.clone(), crate::analyzer::Language::Rust),
        );
        let routes = analyzer.cargo_routes();

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

    const MODULE_ROUTE_FIXTURE: &str = r####"
macro_rules! replay {
    ($($item:item)*) => { $($item)* };
}
macro_rules! swallow {
    ($($item:item)*) => {};
}

mod plain;
mod directory_backed;
#[path = "relocated/target.rs"]
mod relocated_declaration;
#[macro_use]
mod macro_source;
#[cfg(test)]
mod gated;
#[cfg(any(test, feature = "fixtures"))]
mod composed_gate;
pub mod published;

mod outer {
    pub mod inner {
        mod nested_child;
    }
    #[path = "elsewhere"]
    mod relocated_scope {
        mod deep_child;
    }
}

#[path = "shared.rs"]
mod first_alias;
#[macro_use]
#[path = "shared.rs"]
mod second_alias;

replay! { mod replayed; }
swallow! { mod swallowed; }
replay! { replay! { mod doubly_replayed; } }
"####;

    /// Lay the fixture's declared files down on disk. Returns the workspace
    /// root, whose `Cargo.toml` makes it a single-crate workspace.
    fn module_route_fixture(temp: &tempfile::TempDir) -> PathBuf {
        let root = temp.path().canonicalize().expect("canonical root");
        write(
            &root,
            "Cargo.toml",
            "[package]\nname = \"routes\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        write(&root, "src/lib.rs", MODULE_ROUTE_FIXTURE);
        for relative in [
            "src/plain.rs",
            "src/directory_backed/mod.rs",
            "src/relocated/target.rs",
            "src/macro_source.rs",
            "src/gated.rs",
            "src/composed_gate.rs",
            "src/published.rs",
            "src/outer/inner/nested_child.rs",
            "src/elsewhere/deep_child.rs",
            "src/shared.rs",
            "src/replayed.rs",
            "src/swallowed.rs",
            "src/doubly_replayed.rs",
            // A file the crate root does not declare, used to exercise a
            // non-crate-root declaring file.
            "src/sub.rs",
            "src/sub/child.rs",
        ] {
            write(&root, relative, "pub struct Marker;\n");
        }
        write(
            &root,
            "src/sub.rs",
            "mod child;\n#[path = \"../shared.rs\"]\nmod escaped;\n",
        );
        root
    }

    fn write(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
        std::fs::write(path, contents).expect("write fixture");
    }
}
