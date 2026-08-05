//! Python's structural-spec coverage, kept beside the engine it exercises.
//!
//! The spec itself is
//! [`brokk_bifrost_python::structural::PYTHON_STRUCTURAL_SPEC`]. These
//! assertions run through `structural::extract` and
//! `structural::adapter_helpers`, the analysis-owned fact engine, so the tests
//! stay on this side of the crate line -- exactly as Rust's did.

#[cfg(test)]
mod structural_spec_tests {
    use crate::analyzer::structural::adapter_helpers::{
        assert_occurrence_role, block_facts_of, occurrence_roles_of,
    };
    use crate::analyzer::structural::{OccurrenceRole, StructuralSpec};
    use brokk_bifrost_core::analyzer::common::parse_source_region;
    use brokk_bifrost_python::structural::{PYTHON_KIND_TABLE, PYTHON_STRUCTURAL_SPEC};
    use brokk_bifrost_python::syntax::python_node_is_in_annotation;

    #[test]
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

    /// Python scopes with the indented suite its grammar calls `block`. The
    /// module node is deliberately not a block: a file scope is not a
    /// statement list nested inside another one.
    #[test]
    fn python_indented_suites_become_scope_facts_but_the_module_does_not() {
        let source = concat!("def demo(flag):\n", "    if flag:\n", "        work()\n",);

        assert_eq!(
            block_facts_of(
                &PYTHON_STRUCTURAL_SPEC,
                &tree_sitter_python::LANGUAGE.into(),
                source,
            ),
            // A suite spans its statements only: neither the indentation that
            // opens it nor the newline that closes it belongs to the scope.
            vec![concat!("if flag:\n", "        work()"), "work()"]
        );
    }

    /// Python's role trap is the annotation: `label: str` puts a binder and a
    /// type operand one token apart, distinguished only by the `type` node the
    /// parser wraps the annotation in.
    #[test]
    fn python_separates_annotations_from_the_parameters_they_annotate() {
        let source = concat!(
            "import os.path\n",
            "from typing import List as Sequence\n",
            "\n",
            "class Widget:\n",
            "    def render(self, label: str, count: int = 0) -> Sequence:\n",
            "        return os.path.join(label, key=count)\n",
        );
        let found = occurrence_roles_of(
            &PYTHON_STRUCTURAL_SPEC,
            &tree_sitter_python::LANGUAGE.into(),
            source,
        );

        let at = |needle: &str| source.find(needle).expect("fixture token");
        assert_occurrence_role(&found, at("os.path"), OccurrenceRole::PathSegment);
        assert_occurrence_role(&found, at("path\n"), OccurrenceRole::ImportTarget);
        assert_occurrence_role(&found, at("List as"), OccurrenceRole::ImportTarget);
        assert_occurrence_role(&found, at("Sequence\n"), OccurrenceRole::ImportAlias);
        assert_occurrence_role(&found, at("Widget"), OccurrenceRole::DeclarationName);
        assert_occurrence_role(&found, at("render"), OccurrenceRole::DeclarationName);
        assert_occurrence_role(&found, at("label: str"), OccurrenceRole::Binder);
        assert_occurrence_role(&found, at("str,"), OccurrenceRole::TypeOperand);
        assert_occurrence_role(&found, at("count: int"), OccurrenceRole::Binder);
        assert_occurrence_role(&found, at("int ="), OccurrenceRole::TypeOperand);
        assert_occurrence_role(&found, at("Sequence:"), OccurrenceRole::TypeOperand);
        assert_occurrence_role(&found, at("os.path.join"), OccurrenceRole::ReceiverPosition);
        assert_occurrence_role(&found, at("join"), OccurrenceRole::MemberPosition);
        assert_occurrence_role(&found, at("label,"), OccurrenceRole::ValueReference);
        assert_occurrence_role(&found, at("key="), OccurrenceRole::LabelOrKey);
    }

    #[test]
    fn python_emits_only_roles_it_declares_as_supported() {
        let source = "def f(a):\n    return a.b(a)\n";
        let found = occurrence_roles_of(
            &PYTHON_STRUCTURAL_SPEC,
            &tree_sitter_python::LANGUAGE.into(),
            source,
        );
        assert!(!found.is_empty());
        for (_, text, role) in &found {
            assert!(
                PYTHON_STRUCTURAL_SPEC
                    .occurrence_role_support()
                    .is_supported(*role),
                "python emitted undeclared role {role:?} for {text:?}"
            );
        }
    }

    /// Every node-type name in the kind table must exist in the grammar, so a
    /// tree-sitter-python bump that renames nodes fails here instead of
    /// silently dropping facts.
    #[test]
    fn python_kind_table_matches_grammar() {
        crate::analyzer::structural::adapter_helpers::assert_kind_table_matches_grammar(
            tree_sitter_python::LANGUAGE.into(),
            "tree-sitter-python",
            PYTHON_KIND_TABLE,
        );
    }
}
