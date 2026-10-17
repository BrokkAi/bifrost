//! Python's structural-spec coverage, kept beside the engine it exercises.
//!
//! The spec itself is
//! [`brokk_bifrost_python::structural::PYTHON_STRUCTURAL_SPEC`]. These
//! assertions run through `structural::extract` and
//! `structural::adapter_helpers`, the analysis-owned fact engine, so the tests
//! stay on this side of the crate line -- exactly as Rust's did.

#[cfg(test)]
mod structural_spec_tests {
    use crate::analyzer::structural::OccurrenceRole;
    use crate::analyzer::structural::adapter_helpers::{
        assert_occurrence_role, occurrence_roles_of,
    };
    use brokk_bifrost_core::analyzer::common::parse_source_region;
    use brokk_bifrost_python::structural::{PYTHON_KIND_TABLE, PYTHON_STRUCTURAL_SPEC};
    use brokk_bifrost_python::syntax::python_node_is_in_annotation;

    use brokk_bifrost_test_macros::hardwon;
    #[test]
    #[hardwon(
        "#1612: The nested tree-sitter parse for a deferred annotation must map identifiers back to exact original source byte ranges"
    )]
    fn deferred_annotation_region_parse_preserves_source_positions() {
        let source = "def render(widget: \"Widget | list[Gadget]\") -> None:\n    pass\n";
        let language = tree_sitter_python::LANGUAGE.into();
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&language).expect("Python grammar");
        let tree = parser.parse(source, None).expect("Python source parses");

        let mut content = None;
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "string_content" {
                content = Some(node);
                break;
            }
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    stack.push(child);
                }
            }
        }
        let content = content.expect("deferred annotation content");
        let string = content.parent().expect("annotation string");
        assert!(python_node_is_in_annotation(string));
        let inner =
            parse_source_region(&language, source, content.start_byte(), content.end_byte())
                .expect("annotation region parses");
        assert!(!inner.root_node().has_error());

        let mut identifiers = Vec::new();
        let mut stack = vec![inner.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "identifier" {
                identifiers.push((
                    &source[node.start_byte()..node.end_byte()],
                    node.start_byte(),
                    node.end_byte(),
                ));
            }
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    stack.push(child);
                }
            }
        }

        assert_eq!(
            identifiers,
            vec![
                (
                    "Widget",
                    source.find("Widget").expect("Widget offset"),
                    source.find("Widget").expect("Widget offset") + "Widget".len(),
                ),
                (
                    "list",
                    source.find("list").expect("list offset"),
                    source.find("list").expect("list offset") + "list".len(),
                ),
                (
                    "Gadget",
                    source.find("Gadget").expect("Gadget offset"),
                    source.find("Gadget").expect("Gadget offset") + "Gadget".len(),
                ),
            ]
        );
    }

    #[test]
    #[hardwon(
        "#1612: Real Python annotation ASTs distinguish deferred type expressions from ordinary, malformed, escaped, and concatenated strings"
    )]
    fn deferred_annotations_emit_type_operands_but_ordinary_strings_do_not() {
        let source = concat!(
            "class Widget:\n",
            "    pass\n",
            "class Gadget:\n",
            "    pass\n",
            "def render(widget: \"Widget | list[Gadget]\") -> None:\n",
            "    return \"Widget\"\n",
            "def malformed(widget: \"Widget[\") -> None:\n",
            "    pass\n",
            "def escaped(widget: \"Wid\\x67et\") -> None:\n",
            "    pass\n",
            "def concatenated(widget: \"Wid\" \"get\") -> None:\n",
            "    pass\n",
        );
        let found = occurrence_roles_of(
            &PYTHON_STRUCTURAL_SPEC,
            &tree_sitter_python::LANGUAGE.into(),
            source,
        );

        let at = |needle: &str| source.find(needle).expect("fixture token");
        assert_occurrence_role(&found, at("Widget |"), OccurrenceRole::TypeOperand);
        assert_occurrence_role(&found, at("list["), OccurrenceRole::TypeOperand);
        assert_occurrence_role(&found, at("Gadget]"), OccurrenceRole::TypeOperand);

        for absent in [
            source.rfind("Widget\"").expect("ordinary string content"),
            at("Widget["),
            at("Wid\\x67et"),
            source.rfind("Wid\"").expect("concatenated first content"),
            source.rfind("get\"").expect("concatenated second content"),
        ] {
            assert!(
                found.iter().all(|(start, _, _)| *start != absent),
                "unstructured or non-annotation string content must stay absent: {found:?}"
            );
        }
    }

    /// The Python adapter's declared node kinds must remain names present in
    /// the live grammar. The producer crate references this test as the
    /// synchronization check for its kind table.
    #[test]
    fn python_kind_table_matches_grammar() {
        crate::analyzer::structural::adapter_helpers::assert_kind_table_matches_grammar(
            tree_sitter_python::LANGUAGE.into(),
            "tree-sitter-python",
            PYTHON_KIND_TABLE,
        );
    }

    #[test]
    #[hardwon("5ebc6164ef10: Literal values were misread as deferred type operands")]
    fn literal_string_values_are_not_deferred_type_operands() {
        let source = concat!(
            "import typing\n",
            "import typing_extensions\n",
            "from typing import Literal\n",
            "class NOASSERTION:\n",
            "    pass\n",
            "def deferred(value: \"NOASSERTION\") -> None:\n",
            "    pass\n",
            "def direct(value: Literal[\"NOASSERTION\"]) -> None:\n",
            "    pass\n",
            "def qualified(value: typing.Literal[\"NOASSERTION\"]) -> None:\n",
            "    pass\n",
            "def extension(value: typing_extensions.Literal[\"NOASSERTION\"]) -> None:\n",
            "    pass\n",
        );
        let found = occurrence_roles_of(
            &PYTHON_STRUCTURAL_SPEC,
            &tree_sitter_python::LANGUAGE.into(),
            source,
        );
        let occurrences: Vec<_> = source.match_indices("NOASSERTION").collect();
        assert_eq!(occurrences.len(), 5);
        assert_occurrence_role(&found, occurrences[1].0, OccurrenceRole::TypeOperand);
        for (offset, _) in occurrences.into_iter().skip(2) {
            assert!(
                found.iter().all(|(start, _, _)| *start != offset),
                "Literal value at {offset} must not become a type operand: {found:?}"
            );
        }
    }
}
