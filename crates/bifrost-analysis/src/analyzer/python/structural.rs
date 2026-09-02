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
    use crate::analyzer::structural::{OccurrenceRole, RouteHopKind, StructuralSpec};
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

    #[test]
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

    /// The indirection relation the adapter states for the identifier that
    /// spells `name` inside the first occurrence of `context`, read with the
    /// curated export surface of the whole file.
    fn indirection_relation_at(source: &str, context: &str, name: &str) -> Option<RouteHopKind> {
        let language = tree_sitter_python::LANGUAGE.into();
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&language).expect("Python grammar");
        let tree = parser.parse(source, None).expect("Python source parses");
        let root = tree.root_node();
        let surface = PYTHON_STRUCTURAL_SPEC.curated_export_surface(root, source);
        let context_start = source.find(context).expect("fixture contains the context");
        let start = context_start + context.find(name).expect("context contains the name");
        let token = root
            .descendant_for_byte_range(start, start + name.len())
            .expect("token at the named offset");
        assert_eq!(token.kind(), "identifier", "expected an identifier token");
        PYTHON_STRUCTURAL_SPEC.indirection_relation(token, source, &surface)
    }

    /// A package facade that curates `__all__` re-exports exactly the names it
    /// lists. `helper`, imported into the same facade but left off the list,
    /// stays an ordinary import, and the module the names come from is a
    /// module reference rather than a binding this file forwards.
    #[test]
    fn python_all_members_re_export_and_unlisted_imports_do_not() {
        let source = concat!(
            "__all__ = [\"Widget\", \"build\"]\n",
            "from .impl import Widget, build, helper\n",
        );
        let import = "from .impl import Widget, build, helper";
        assert_eq!(
            indirection_relation_at(source, import, "Widget"),
            Some(RouteHopKind::ReExport)
        );
        assert_eq!(
            indirection_relation_at(source, import, "build"),
            Some(RouteHopKind::ReExport)
        );
        assert_eq!(
            indirection_relation_at(source, import, "helper"),
            Some(RouteHopKind::Import)
        );
        assert_eq!(
            indirection_relation_at(source, import, "impl"),
            Some(RouteHopKind::Import)
        );
    }

    /// A tuple `__all__` and an `+=` extension of it are the same statement of
    /// the surface as one list literal, so both names re-export.
    #[test]
    fn python_all_reads_tuples_and_augmented_extensions() {
        let source = concat!(
            "__all__ = (\"Widget\",)\n",
            "__all__ += [\"build\"]\n",
            "from .impl import Widget, build, helper\n",
        );
        let import = "from .impl import Widget, build, helper";
        assert_eq!(
            indirection_relation_at(source, import, "Widget"),
            Some(RouteHopKind::ReExport)
        );
        assert_eq!(
            indirection_relation_at(source, import, "build"),
            Some(RouteHopKind::ReExport)
        );
        assert_eq!(
            indirection_relation_at(source, import, "helper"),
            Some(RouteHopKind::Import)
        );
    }

    /// The redundant-alias forms are re-exports without any `__all__`, which
    /// is the rule PEP 484 stub semantics state and pyright and mypy enforce.
    /// The same import written without the redundant alias is not.
    #[test]
    fn python_redundant_alias_forms_re_export() {
        let source = concat!(
            "from .impl import Widget as Widget\n",
            "from .impl import build as make\n",
            "import gadget as gadget\n",
            "import trinket as bauble\n",
        );
        assert_eq!(
            indirection_relation_at(source, "import Widget as Widget", "Widget"),
            Some(RouteHopKind::ReExport)
        );
        assert_eq!(
            indirection_relation_at(source, "import build as make", "build"),
            Some(RouteHopKind::Import)
        );
        assert_eq!(
            indirection_relation_at(source, "import gadget as gadget", "gadget"),
            Some(RouteHopKind::ReExport)
        );
        assert_eq!(
            indirection_relation_at(source, "import trinket as bauble", "trinket"),
            Some(RouteHopKind::Import)
        );
    }

    /// `from x import *` forwards the public surface of `x` as one star hop on
    /// the module reference; nothing is enumerated here, so the expansion
    /// stays the import machinery's answer.
    #[test]
    fn python_star_import_is_one_re_export_hop_on_the_module() {
        let source = "from .impl import *\n";
        assert_eq!(
            indirection_relation_at(source, "from .impl import *", "impl"),
            Some(RouteHopKind::ReExport)
        );
    }

    /// The facade convention on its own is not a re-export: a package
    /// `__init__.py` that states no `__all__` and imports plainly publishes
    /// nothing a type checker would call public, and a consumer that wants
    /// every name the facade imports already has the import relation.
    #[test]
    fn python_a_plain_facade_import_without_all_is_only_an_import() {
        let source = "from .impl import Widget, helper\n";
        let import = "from .impl import Widget, helper";
        assert_eq!(
            indirection_relation_at(source, import, "Widget"),
            Some(RouteHopKind::Import)
        );
        assert_eq!(
            indirection_relation_at(source, import, "helper"),
            Some(RouteHopKind::Import)
        );
    }

    /// A computed `__all__` settles no name's membership, so the adapter says
    /// it cannot classify rather than guessing either way. The forms that do
    /// not depend on `__all__` still answer.
    #[test]
    fn python_a_computed_all_leaves_plain_imports_unclassified() {
        let computed = concat!(
            "__all__ = build_exports()\n",
            "from .impl import Widget, helper\n",
            "from .impl import Gadget as Gadget\n",
            "from .other import *\n",
        );
        assert_eq!(
            indirection_relation_at(computed, "from .impl import Widget, helper", "Widget"),
            None
        );
        assert_eq!(
            indirection_relation_at(computed, "import Gadget as Gadget", "Gadget"),
            Some(RouteHopKind::ReExport)
        );
        assert_eq!(
            indirection_relation_at(computed, "from .other import *", "other"),
            Some(RouteHopKind::ReExport)
        );

        // Mutating a readable list is just as unreadable: the members after
        // the mutation are a value this reader cannot see.
        let mutated = concat!(
            "__all__ = [\"Widget\"]\n",
            "__all__.extend(other.__all__)\n",
            "from .impl import Widget, helper\n",
        );
        assert_eq!(
            indirection_relation_at(mutated, "from .impl import Widget, helper", "Widget"),
            None
        );
    }

    /// A dotted `import a.b.c` binds the top package, so the curated surface
    /// is consulted for `a` rather than for the segment the target token
    /// spells.
    #[test]
    fn python_dotted_import_reads_the_package_it_binds() {
        let source = concat!("__all__ = [\"gadget\"]\n", "import gadget.parts.bolt\n");
        assert_eq!(
            indirection_relation_at(source, "import gadget.parts.bolt", "bolt"),
            Some(RouteHopKind::ReExport)
        );

        let unlisted = concat!("__all__ = [\"bolt\"]\n", "import gadget.parts.bolt\n");
        assert_eq!(
            indirection_relation_at(unlisted, "import gadget.parts.bolt", "bolt"),
            Some(RouteHopKind::Import)
        );
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
