# Bifrost patch provenance

This directory is derived from the official `tree-sitter/tree-sitter-scala`
release `v0.25.1`, commit
`a067c39163b62b19e76cea17476f3188da8c9e51`. The upstream MIT license
remains in `LICENSE`.

Bifrost carries three declarative grammar fixes that are not available together
in a published crate:

1. Issue #1073 declares a generalized-LR conflict between
   `extension_definition` and `_soft_identifier`, then adds `"extension"` to
   `_soft_identifier`. This preserves Scala 3 extension definitions while
   allowing valid Scala 2 expressions such as `extension == "json"`.
2. Issue #1016 applies upstream commit
   `6f9d7bc93ee153719d0d785e63e0fc77d333dad7`. Its
   `_constructor_annotation` rule limits an annotation to at most one
   immediately adjacent argument list, so a following list is parsed as the
   class constructor. Upstream generated-parser commit
   `a68000002745b94eec61cef741efe7cede4ff465` is the immutable reference for
   that fix.
3. Issue #1068 applies upstream pull request
   `tree-sitter-scala#551`, merged as
   `88a12d30bd14edfab6d4552af22f6d3a5f5000e9`. It permits empty block-lambda
   bodies such as `{ _ => }` without consuming their enclosing class body,
   while preserving self-type-only template bodies and supporting enum self
   types and modifiers.

The private build can be removed once an official upstream release contains
all three fixes and passes these regressions. The latest published release,
`v0.26.0`, predates the issue #1068 fix.

The generated files under `src/` were produced from the checked-in
`grammar.js` with `tree-sitter-cli 0.25.9`.

To regenerate, work from this directory and run:

    npx --yes tree-sitter-cli@0.25.9 generate

Then run the focused acceptance tests from the repository root:

    cargo test --lib analyzer::scala::language::tests
    cargo test --test scala_extension_soft_keyword_test
    cargo test --test scala_analyzer_test issue_1016_scala_annotated_constructor_whitespace_forms_keep_parameters_and_bodies
    cargo test --test mcp_property_fuzzer issue_1016_i1_accepts_annotated_constructor_jobctrl_scala_fixture
    cargo test --test searchtools_definition_selectors issue_1016_scala_annotated_constructor_supports_sources_and_body_reference_context
