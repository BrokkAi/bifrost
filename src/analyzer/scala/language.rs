use tree_sitter_language::LanguageFn;

unsafe extern "C" {
    fn brokk_bifrost_tree_sitter_scala() -> *const ();
}

/// The vendored tree-sitter Scala grammar.
pub(crate) const LANGUAGE: LanguageFn =
    unsafe { LanguageFn::from_raw(brokk_bifrost_tree_sitter_scala) };

#[cfg(test)]
mod tests {
    use super::LANGUAGE;

    #[test]
    fn extension_is_contextual_between_identifier_and_definition() {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&LANGUAGE.into())
            .expect("load Bifrost Scala grammar");

        let scala2 = r#"trait Enrichments {
  implicit class Path(filename: String) {
    def extension: String = "json"
    def isJson: Boolean = extension == "json"
  }
}"#;
        let scala2_tree = parser.parse(scala2, None).expect("parse Scala 2");
        assert!(
            !scala2_tree.root_node().has_error(),
            "Scala 2 extension identifier must parse without recovery:\n{}",
            scala2_tree.root_node().to_sexp()
        );

        let scala3 = r#"object Syntax:
  extension (value: String)
    def twice: String = value + value
"#;
        let scala3_tree = parser.parse(scala3, None).expect("parse Scala 3");
        assert!(
            !scala3_tree.root_node().has_error(),
            "Scala 3 extension definition must parse without recovery:\n{}",
            scala3_tree.root_node().to_sexp()
        );
        assert!(
            scala3_tree
                .root_node()
                .to_sexp()
                .contains("extension_definition"),
            "Scala 3 syntax must retain its structured extension node"
        );
    }
}
