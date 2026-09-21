fn main() {
    let grammar = std::path::Path::new("src/scala/grammar/src");
    println!("cargo:rerun-if-changed={}", grammar.display());
    cc::Build::new()
        .std("c11")
        .include(grammar)
        .flag_if_supported("-Wno-unused")
        .flag_if_supported("/utf-8")
        .file(grammar.join("parser.c"))
        .file(grammar.join("scanner.c"))
        .compile("tree-sitter-scala");
}
