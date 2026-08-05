//! The one Rust cargo-route test that needs a live analyzer.
//!
//! `RustCargoRouteIndex` and the passthrough-macro discovery it exercises live
//! in [`brokk_bifrost_rust::cargo_routes`]; only the assertion that the
//! analyzer's `cargo_routes()` memo reflects them has to be built from a real
//! `RustAnalyzer`, so it stays here (the Go block-2 precedent).

#[cfg(test)]
mod tests {
    use crate::analyzer::ProjectFile;
    use crate::hash::HashMap;
    use brokk_bifrost_rust::cargo_routes::{
        RustVisibleItemMacroDefinition, rust_external_module_child_edges,
    };
    use brokk_bifrost_rust::declarations::rust_rules_item_macro_definitions;
    use std::path::Path;
    use tree_sitter::Parser;

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
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust parser language");
        let tree = parser.parse(source, None).expect("parse Rust fixture");
        let bindings = rust_rules_item_macro_definitions(tree.root_node(), source)
            .into_iter()
            .fold(HashMap::default(), |mut bindings, definition| {
                bindings
                    .entry(definition.name)
                    .or_insert_with(Vec::new)
                    .push(RustVisibleItemMacroDefinition {
                        visible_after: definition.visible_after,
                        scope_start: definition.scope_start,
                        scope_end: definition.scope_end,
                        passthrough: definition.passthrough,
                    });
                bindings
            });
        let direct_edges =
            rust_external_module_child_edges(&library, source, tree.root_node(), true, &bindings);
        assert!(
            direct_edges
                .iter()
                .any(|edge| edge.file.rel_path() == Path::new("src/replayed.rs")),
            "direct structured macro discovery should replay the positive rule"
        );
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

    fn write(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
        std::fs::write(path, contents).expect("write fixture");
    }
}
