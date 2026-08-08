use std::path::Path;

fn compile_vendored_grammar(
    source_dir: &str,
    library_name: &str,
    private_symbols: &[(&str, &str)],
) {
    let source_dir = Path::new(source_dir);
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

    for &(upstream, private) in private_symbols {
        build.define(upstream, Some(private));
    }

    build.compile(library_name);

    for path in [parser, scanner].into_iter().chain(headers) {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

fn main() {
    compile_vendored_grammar(
        "vendor/tree-sitter-kotlin/src",
        "brokk-bifrost-tree-sitter-kotlin",
        &[
            ("tree_sitter_kotlin", "brokk_bifrost_tree_sitter_kotlin"),
            (
                "tree_sitter_kotlin_external_scanner_create",
                "brokk_bifrost_tree_sitter_kotlin_external_scanner_create",
            ),
            (
                "tree_sitter_kotlin_external_scanner_destroy",
                "brokk_bifrost_tree_sitter_kotlin_external_scanner_destroy",
            ),
            (
                "tree_sitter_kotlin_external_scanner_scan",
                "brokk_bifrost_tree_sitter_kotlin_external_scanner_scan",
            ),
            (
                "tree_sitter_kotlin_external_scanner_serialize",
                "brokk_bifrost_tree_sitter_kotlin_external_scanner_serialize",
            ),
            (
                "tree_sitter_kotlin_external_scanner_deserialize",
                "brokk_bifrost_tree_sitter_kotlin_external_scanner_deserialize",
            ),
        ],
    );
}
