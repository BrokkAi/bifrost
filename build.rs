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

    build.compile("tree-sitter-scala");

    for path in [parser, scanner].into_iter().chain(headers) {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}
