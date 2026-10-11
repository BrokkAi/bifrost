pub(crate) fn parse_raw_csharp(source: &str) -> tree_sitter::Tree {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
        .expect("C# grammar loads");
    parser
        .parse(source, None)
        .expect("C# parser returns a tree")
}
