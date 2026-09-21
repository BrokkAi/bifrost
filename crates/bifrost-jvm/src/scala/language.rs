use tree_sitter_language::LanguageFn;

unsafe extern "C" {
    fn tree_sitter_scala() -> *const ();
}

/// Scala grammar with the contextual field-selector correction described in grammar/README.md.
// SAFETY: build.rs compiles the generated tree-sitter language function linked here.
pub const LANGUAGE: LanguageFn = unsafe { LanguageFn::from_raw(tree_sitter_scala) };

#[cfg(test)]
mod tests {
    use super::LANGUAGE;

    fn parse_without_recovery(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&LANGUAGE.into())
            .expect("load Bifrost Scala grammar");
        let tree = parser.parse(source, None).expect("parse Scala");
        assert!(
            !tree.root_node().has_error(),
            "Scala source must parse without recovery:\n{}",
            tree.root_node().to_sexp()
        );
        tree
    }

    #[test]
    fn scala2_export_selector_preserves_enclosing_class_and_scala3_exports() {
        let tree = parse_without_recovery(
            r#"class Dialog {
  var selection = 0
  def write(): Unit = {
    try {
      Export.export(project, file)
    } catch {
      case failure: Exception => throw failure
    }
  }
  def accept(): Boolean = selection == 0
}"#,
        );
        let class = tree.root_node().named_child(0).expect("class");
        let body = class.child_by_field_name("body").expect("class body");
        let mut cursor = body.walk();
        assert_eq!(
            body.named_children(&mut cursor)
                .filter(|node| node.kind() == "function_definition")
                .count(),
            2,
            "both methods must belong to the class"
        );
        let tree = parse_without_recovery("object API { export implementation.member }");
        assert!(tree.root_node().to_sexp().contains("(export_declaration"));
    }

    #[test]
    fn extension_is_contextual_between_identifier_and_definition() {
        let scala2 = r#"trait Enrichments {
  implicit class Path(filename: String) {
    def extension: String = "json"
    def isJson: Boolean = extension == "json"
  }
}"#;
        parse_without_recovery(scala2);

        let scala3 = r#"object Syntax:
  extension (value: String)
    def twice: String = value + value
"#;
        let scala3_tree = parse_without_recovery(scala3);
        assert!(
            scala3_tree
                .root_node()
                .to_sexp()
                .contains("extension_definition"),
            "Scala 3 syntax must retain its structured extension node"
        );
    }

    #[test]
    fn empty_block_lambda_does_not_consume_enclosing_template() {
        let tree = parse_without_recovery(
            r#"class SimulationSpec {
  val before = 1
  simulation.run() { _ => }
  val after = before + 1
}"#,
        );
        let sexp = tree.root_node().to_sexp();
        assert!(
            sexp.contains("(lambda_expression") && sexp.contains("(wildcard)"),
            "empty lambda must remain structured:\n{sexp}"
        );
        assert!(
            sexp.matches("(val_definition").count() == 2,
            "definitions after the empty lambda must remain in the class body:\n{sexp}"
        );
    }

    #[test]
    fn self_type_only_template_bodies_remain_unambiguous() {
        for source in [
            "trait Braced { self: Product => }",
            "trait Indented:\n  self: Product =>\nobject Next",
        ] {
            let tree = parse_without_recovery(source);
            assert!(
                tree.root_node().to_sexp().contains("(self_type"),
                "self type must remain structured:\n{}",
                tree.root_node().to_sexp()
            );
        }
    }

    #[test]
    fn enum_body_accepts_self_type_and_modified_case() {
        let tree = parse_without_recovery(
            r#"enum SymbolKind:
  self: Product =>
  case Value
  private case External(name: String)
"#,
        );
        let sexp = tree.root_node().to_sexp();
        assert!(
            sexp.contains("(self_type"),
            "missing enum self type:\n{sexp}"
        );
        assert!(
            sexp.contains("(modifiers"),
            "missing enum case modifier:\n{sexp}"
        );
    }
}
