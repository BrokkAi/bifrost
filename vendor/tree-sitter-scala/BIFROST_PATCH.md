# Bifrost patch provenance

This directory is derived from the official `tree-sitter/tree-sitter-scala` release `v0.25.1`, commit `a067c39163b62b19e76cea17476f3188da8c9e51`. The upstream MIT license remains in `LICENSE`.

Bifrost vendors the grammar for issue #1073 because no official release, including `v0.26.0`, parses the valid Scala 2 expression `extension == "json"` as an identifier. Upstream master `3991ad1a56036435cc3350837b2155ebeab9695b` was also tested on 2026-07-22 and still emitted an `ERROR` for that expression.

The declarative patch in `grammar.js` has exactly two semantic changes:

1. Declare a generalized-LR conflict between `extension_definition` and `_soft_identifier`.
2. Add `"extension"` to `_soft_identifier`.

This retains Scala 3 `extension` definitions while allowing Scala 2 identifier use when the following syntax cannot form an extension definition. The generated files under `src/` were produced with `tree-sitter-cli 0.25.9`.

To regenerate after changing `grammar.js`, install that CLI version, work from this directory, and run:

    XDG_CACHE_HOME=/tmp/bifrost-tree-sitter-cache tree-sitter generate

Then run Bifrost's focused acceptance test from the repository root:

    cargo test --features nlp,python --test scala_extension_soft_keyword_test
