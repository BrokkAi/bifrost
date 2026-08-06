# Bifrost Kotlin grammar provenance

This directory contains the build and regeneration surface from an upstream
source snapshot of
[`fwcd/tree-sitter-kotlin`](https://github.com/fwcd/tree-sitter-kotlin) at
commit `c8ac3d2627240160b999a2c100de3babbdb8f419` (upstream source package
version `0.4.0`). The upstream MIT license and its 2019 fwcd copyright remain
in `LICENSE`.

Bifrost selected this revision after comparing it with
`tree-sitter-grammars/tree-sitter-kotlin@3dea6dfa9c0129deb7c4315afbda806c85c41667`.
The measured decision is recorded in
`.agents/docs/kotlin-tree-sitter-grammar-evaluation.md` in the Bifrost source
repository. The selected generated parser declares Tree-sitter language ABI
version 14 and is loaded through Bifrost's shared Tree-sitter 0.25.10 runtime.

## Temporary vendoring and exit condition

This snapshot is vendored only because upstream source version `0.4.0` has not
been published to crates.io. The available `tree-sitter-kotlin` `0.3.8` crate
uses the older Tree-sitter 0.21-0.22 Rust API and does not expose the modern
`tree_sitter_language::LanguageFn` used by this revision. Upstream publication
is tracked by [`fwcd/tree-sitter-kotlin#242`](https://github.com/fwcd/tree-sitter-kotlin/issues/242).

Once upstream publishes `0.4.0` or a newer compatible release, replace this
snapshot with an exact registry dependency after the release passes the same
`.kt`, `.kts`, malformed-recovery, incremental-reparse, and representative
corpus checks recorded here. The migration must also remove the native build
and supplemental vendored-source notice, verify coexistence with another
Kotlin grammar dependency, and re-run the crate-package inventory gate.

Bifrost does not patch `grammar.js`, the generated files, the query contents,
or the scanner. The upstream highlight and tag queries live under
`resources/treesitter/kotlin/`, alongside the location reserved for future
Bifrost-owned Kotlin indexing queries; they are reference material and are not
loaded by the analyzer. The paths in `tree-sitter.json` are the sole source
snapshot adjustment, pointing at that repository location.

`build.rs` supplies C preprocessor definitions that rename the parser and
external-scanner exports to `brokk_bifrost_*` symbols. This link isolation does
not alter the compiled sources and prevents a downstream Kotlin grammar crate
from substituting a different parser through native link order.

The upstream lock file at this revision resolves `tree-sitter-cli` 0.24.7. To
regenerate the checked-in native sources, run the following from this
directory:

    npx --yes tree-sitter-cli@0.24.7 generate

Regeneration is not part of a normal Cargo build. Review the resulting
`src/parser.c`, `src/grammar.json`, and `src/node-types.json` changes before
accepting them; a generator change can create a large opaque diff even when
`grammar.js` is unchanged.

After importing or regenerating the snapshot, run these focused checks from
the Bifrost repository root:

    cargo test --lib analyzer::kotlin::language::tests
    node scripts/generate-supplemental-third-party-notices.mjs /tmp/SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt
    cmp licenses/SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt /tmp/SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt
    scripts/check-crate-package.sh

The reviewed snapshot files have these SHA-256 digests:

    e131e6814ae84fc14528ed52be4cdd4d091f3196f3b4548c9efb09541c6a5bf2  grammar.js
    04f52fe1c452c396eaeccf135700c4f3367098c093dffb9d86796807db9d3fb7  src/parser.c
    6369123ff1892c5bf811ecb2e5f0b22b1c58c814cab28aa6ad4fef2101c814fc  src/scanner.c
    1c3b024db65748d8e61b0bc461f6b6f0e20eccfc1d3e16582013ada9dabdc150  src/node-types.json
    8405b4fb37ec046efc98b2b49d4426ec0dc690e4da4b6de7520d2d4c8749fa63  src/grammar.json
    7d543dd96fa7430ac204988516b6933c300e2df94c597477f6ee285ba5013b21  tree-sitter.json
    34523c8d1508a3932095f1e591aa866c1abc0a046bcc569f9d92642327d9c152  ../../resources/treesitter/kotlin/highlights.scm
    8e7a33f68e154cfff250089e2a6984c42e0c421f55d5d024a647058fe676e7f8  ../../resources/treesitter/kotlin/tags.scm
    948495f61768f7de26bcc61113d8cd95f50bbc15adb678c28c941c6c8fcd5903  LICENSE
