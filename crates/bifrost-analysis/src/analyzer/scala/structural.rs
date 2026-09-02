//! Scala's structural-spec coverage, kept beside the engine it exercises.
//!
//! The spec itself is
//! [`brokk_bifrost_jvm::scala::structural::SCALA_STRUCTURAL_SPEC`]. These
//! assertions run through `structural::adapter_helpers`, the analysis-owned
//! test support, so they stay on this side of the crate line -- exactly as
//! Java's, C++'s, C#'s, PHP's, Python's and Rust's did.

#[cfg(test)]
mod structural_spec_tests {
    use crate::analyzer::structural::adapter_helpers::{
        assert_occurrence_role, occurrence_roles_of,
    };
    use brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceRole;
    use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;
    use brokk_bifrost_jvm::scala::structural::{SCALA_KIND_TABLE, SCALA_STRUCTURAL_SPEC};

    fn roles_of(source: &str) -> Vec<(usize, &str, OccurrenceRole)> {
        occurrence_roles_of(
            &SCALA_STRUCTURAL_SPEC,
            &brokk_bifrost_jvm::scala::language::LANGUAGE.into(),
            source,
        )
    }

    /// The declaration, binding, type and import positions #1473 names, in one
    /// file: a package clause, a renaming import, a plain import, a class and
    /// its constructor parameter, a method and its parameters, a local
    /// definition, a selection, and a named argument.
    #[test]
    fn scala_classifies_declaration_binder_type_and_import_positions() {
        let source = concat!(
            "package app.model\n",
            "\n",
            "import scala.collection.mutable.{Buffer => Items}\n",
            "import java.util.List\n",
            "\n",
            "class Widget(size: Int) extends Base {\n",
            "  def render(prefix: String, rows: List[String]): String = {\n",
            "    val trimmed = prefix.trim()\n",
            "    helper.build(name = trimmed)\n",
            "  }\n",
            "}\n",
        );
        let found = roles_of(source);
        let at = |needle: &str| source.find(needle).expect("fixture token");

        // The package clause names its own tail and scopes the rest.
        assert_occurrence_role(&found, at("app.model"), OccurrenceRole::PathSegment);
        assert_occurrence_role(&found, at("model"), OccurrenceRole::DeclarationName);

        // A selector list moves the imported name off the path, so every path
        // segment is a scope segment and the selector carries target and alias.
        assert_occurrence_role(&found, at("scala.collection"), OccurrenceRole::PathSegment);
        assert_occurrence_role(&found, at("collection"), OccurrenceRole::PathSegment);
        assert_occurrence_role(&found, at("mutable"), OccurrenceRole::PathSegment);
        assert_occurrence_role(&found, at("Buffer"), OccurrenceRole::ImportTarget);
        assert_occurrence_role(&found, at("Items"), OccurrenceRole::ImportAlias);

        // Without a selector the last path segment is the imported name.
        assert_occurrence_role(&found, at("java"), OccurrenceRole::PathSegment);
        assert_occurrence_role(&found, at("util"), OccurrenceRole::PathSegment);
        assert_occurrence_role(&found, at("List\n"), OccurrenceRole::ImportTarget);

        assert_occurrence_role(&found, at("Widget"), OccurrenceRole::DeclarationName);
        assert_occurrence_role(&found, at("size"), OccurrenceRole::Binder);
        assert_occurrence_role(&found, at("Int)"), OccurrenceRole::TypeOperand);
        assert_occurrence_role(&found, at("Base"), OccurrenceRole::TypeOperand);

        assert_occurrence_role(&found, at("render"), OccurrenceRole::DeclarationName);
        assert_occurrence_role(&found, at("prefix: String"), OccurrenceRole::Binder);
        assert_occurrence_role(&found, at("String,"), OccurrenceRole::TypeOperand);
        assert_occurrence_role(&found, at("rows"), OccurrenceRole::Binder);
        assert_occurrence_role(&found, at("List[String]"), OccurrenceRole::TypeOperand);
        assert_occurrence_role(&found, at("String]"), OccurrenceRole::TypeOperand);
        assert_occurrence_role(&found, at("String ="), OccurrenceRole::TypeOperand);

        assert_occurrence_role(&found, at("trimmed ="), OccurrenceRole::Binder);
        assert_occurrence_role(&found, at("prefix.trim"), OccurrenceRole::ReceiverPosition);
        assert_occurrence_role(&found, at("trim()"), OccurrenceRole::MemberPosition);
        assert_occurrence_role(&found, at("helper"), OccurrenceRole::ReceiverPosition);
        assert_occurrence_role(&found, at("build"), OccurrenceRole::MemberPosition);
        assert_occurrence_role(&found, at("name ="), OccurrenceRole::LabelOrKey);
        assert_occurrence_role(&found, at("trimmed)"), OccurrenceRole::ValueReference);
    }

    /// A qualified name spells its scope and its tail with the same node kind,
    /// and only the tail is what the chain denotes (#1644).
    ///
    /// Scala uses two different shapes for the same-looking source. A type
    /// path is a left-nested `stable_type_identifier` chain with no grammar
    /// fields at all, so the classifier reads each link's own segment
    /// positionally; a value path is a `field_expression` selection, where the
    /// receiver and member split is spelled in fields. Both must leave the
    /// package segments as segments so a package never becomes an edge target.
    #[test]
    fn scala_qualified_tails_carry_the_role_and_their_scopes_stay_segments() {
        let source = concat!(
            "object Store {\n",
            "  val items: scala.collection.Seq[Int] = null\n",
            "  val head = Outer.Inner.value\n",
            "  def make(): Unit = scala.util.Try(1)\n",
            "}\n",
        );
        let found = roles_of(source);
        let at = |needle: &str| source.find(needle).expect("fixture token");

        assert_occurrence_role(&found, at("scala.collection"), OccurrenceRole::PathSegment);
        assert_occurrence_role(&found, at("collection.Seq"), OccurrenceRole::PathSegment);
        assert_occurrence_role(&found, at("Seq[Int]"), OccurrenceRole::TypeOperand);
        assert_occurrence_role(&found, at("Int]"), OccurrenceRole::TypeOperand);

        assert_occurrence_role(&found, at("Outer"), OccurrenceRole::ReceiverPosition);
        assert_occurrence_role(&found, at("Inner"), OccurrenceRole::MemberPosition);
        assert_occurrence_role(&found, at("value"), OccurrenceRole::MemberPosition);

        assert_occurrence_role(&found, at("scala.util"), OccurrenceRole::ReceiverPosition);
        assert_occurrence_role(&found, at("util.Try"), OccurrenceRole::MemberPosition);
        assert_occurrence_role(&found, at("Try"), OccurrenceRole::MemberPosition);
    }

    /// Patterns and `for` comprehensions are where Scala separates a name it
    /// binds from a name it matches.
    ///
    /// A bare identifier in a pattern slot binds, and the grammar spells
    /// `case other =>` exactly like `case Other =>`, so this classifier never
    /// reads a spelling to tell them apart. What it does read is structure: an
    /// extractor's own name, an infix extractor's operator and a qualified
    /// constant all name something declared elsewhere, which is what
    /// `pattern_position` states.
    #[test]
    fn scala_patterns_and_comprehensions_separate_binders_from_matched_names() {
        let source = concat!(
            "object Match {\n",
            "  def pick(value: Any, rows: List[String]): Any = {\n",
            "    val lengths = for (row <- rows if row.nonEmpty) yield row.length\n",
            "    value match {\n",
            "      case whole @ Widget(inner) => inner\n",
            "      case Colors.Red => lengths\n",
            "      case head :: rest => rest\n",
            "      case other => other\n",
            "    }\n",
            "  }\n",
            "}\n",
        );
        let found = roles_of(source);
        let at = |needle: &str| source.find(needle).expect("fixture token");

        assert_occurrence_role(&found, at("lengths ="), OccurrenceRole::Binder);
        assert_occurrence_role(&found, at("row <-"), OccurrenceRole::Binder);
        assert_occurrence_role(&found, at("rows if"), OccurrenceRole::ValueReference);
        assert_occurrence_role(&found, at("row.nonEmpty"), OccurrenceRole::ReceiverPosition);
        assert_occurrence_role(&found, at("nonEmpty"), OccurrenceRole::MemberPosition);
        assert_occurrence_role(&found, at("row.length"), OccurrenceRole::ReceiverPosition);
        assert_occurrence_role(&found, at("length\n"), OccurrenceRole::MemberPosition);

        assert_occurrence_role(&found, at("value match"), OccurrenceRole::ValueReference);
        assert_occurrence_role(&found, at("whole @"), OccurrenceRole::Binder);
        assert_occurrence_role(&found, at("Widget(inner)"), OccurrenceRole::PatternPosition);
        assert_occurrence_role(&found, at("inner)"), OccurrenceRole::Binder);
        assert_occurrence_role(&found, at("Colors"), OccurrenceRole::PathSegment);
        assert_occurrence_role(&found, at("Red"), OccurrenceRole::PatternPosition);
        assert_occurrence_role(&found, at("head ::"), OccurrenceRole::Binder);
        assert_occurrence_role(&found, at("::"), OccurrenceRole::PatternPosition);
        assert_occurrence_role(&found, at("rest =>"), OccurrenceRole::Binder);
        assert_occurrence_role(&found, at("other =>"), OccurrenceRole::Binder);
    }

    /// Support is a declaration, not a description of what happened to be
    /// emitted: every role Scala emits must be one it declares.
    #[test]
    fn scala_emits_only_roles_it_declares_as_supported() {
        let source = concat!(
            "package app\n",
            "import java.util.{List => L}\n",
            "class A(b: Int) extends C {\n",
            "  def f(g: Int): Int = h.i(j = g) match { case D(k) => k; case _ => 0 }\n",
            "}\n",
        );
        let found = roles_of(source);
        assert!(!found.is_empty());
        for (_, text, role) in &found {
            assert!(
                SCALA_STRUCTURAL_SPEC
                    .occurrence_role_support()
                    .is_supported(*role),
                "scala emitted undeclared role {role:?} for {text:?}"
            );
        }
    }

    #[test]
    fn scala_kind_table_matches_grammar() {
        crate::analyzer::structural::adapter_helpers::assert_kind_table_matches_grammar(
            brokk_bifrost_jvm::scala::language::LANGUAGE.into(),
            "tree-sitter-scala",
            SCALA_KIND_TABLE,
        );
    }
}
