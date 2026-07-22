use std::path::Path;

fn main() {
    let source_dir = Path::new("vendor/tree-sitter-scala/src");
    let parser = source_dir.join("parser.c");
    let scanner = source_dir.join("scanner.c");
    let headers = [
        source_dir.join("tree_sitter/alloc.h"),
        source_dir.join("tree_sitter/array.h"),
        source_dir.join("tree_sitter/parser.h"),
    ];

    let mut build = cc::Build::new();
    build
        .std("c11")
        .include(source_dir)
        .flag_if_supported("-Wno-unused")
        .file(&parser)
        .file(&scanner);

    #[cfg(target_env = "msvc")]
    build.flag("-utf-8");

    // A downstream crate may also link the published tree-sitter-scala crate.
    // Keep every native symbol private so link order cannot substitute that
    // parser (or its scanner) for Bifrost's pinned snapshot.
    for (upstream, private) in [
        ("tree_sitter_scala", "brokk_bifrost_tree_sitter_scala"),
        (
            "tree_sitter_scala_external_scanner_create",
            "brokk_bifrost_tree_sitter_scala_external_scanner_create",
        ),
        (
            "tree_sitter_scala_external_scanner_destroy",
            "brokk_bifrost_tree_sitter_scala_external_scanner_destroy",
        ),
        (
            "tree_sitter_scala_external_scanner_scan",
            "brokk_bifrost_tree_sitter_scala_external_scanner_scan",
        ),
        (
            "tree_sitter_scala_external_scanner_serialize",
            "brokk_bifrost_tree_sitter_scala_external_scanner_serialize",
        ),
        (
            "tree_sitter_scala_external_scanner_deserialize",
            "brokk_bifrost_tree_sitter_scala_external_scanner_deserialize",
        ),
    ] {
        build.define(upstream, Some(private));
    }

    build.compile("brokk-bifrost-tree-sitter-scala");

    for path in [parser, scanner].into_iter().chain(headers) {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}
