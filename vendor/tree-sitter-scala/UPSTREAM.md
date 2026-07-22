# Vendored tree-sitter-scala parser

Bifrost vendors the generated runtime parser from tree-sitter-scala commit
`a68000002745b94eec61cef741efe7cede4ff465`:

https://github.com/tree-sitter/tree-sitter-scala/commit/a68000002745b94eec61cef741efe7cede4ff465

That is the first generated-parser commit containing the constructor-annotation
grammar fix from `6f9d7bc93ee153719d0d785e63e0fc77d333dad7`:

https://github.com/tree-sitter/tree-sitter-scala/commit/6f9d7bc93ee153719d0d785e63e0fc77d333dad7

The upstream project is MIT licensed. Its unmodified `LICENSE` is stored beside
this file.

Only the generated runtime inputs used by Bifrost are copied:

- `src/parser.c`
- `src/scanner.c`
- `src/tree_sitter/alloc.h`
- `src/tree_sitter/array.h`
- `src/tree_sitter/parser.h`

The SHA-256 checksums at this snapshot are:

| File | SHA-256 |
| --- | --- |
| `src/parser.c` | `5ef0403825bea3849fa11ef33e70d32826b5663e1c9de5733c46d60d3c5f5050` |
| `src/scanner.c` | `e4ba242568ee3493015598997bf60f613802616eade62717c21109287ef64752` |
| `src/tree_sitter/alloc.h` | `b29c1c9fb7cc82f58c84b376df1297d6e2737a1d655fd356db0859e3c29c2fea` |
| `src/tree_sitter/array.h` | `31e60a1bff6f715afacce03b5b70efe42b58371b4f9595dd4af52a577ff9608c` |
| `src/tree_sitter/parser.h` | `180b893c8734778fd32f372dfbc27bd6ad1cd2221f26150b31256ff6716320d2` |
| `LICENSE` | `1f95ed26e1f4074074c9c7083e61c0a9e4c3b9f435745044995f3beb4ed28575` |

To update the snapshot, check out an immutable upstream commit that contains
generated parser output, copy exactly those files and `LICENSE`, update both
commit identifiers above when appropriate, then run the Scala regression tests,
the license checks, and `cargo package --allow-dirty`. Do not regenerate these
files locally from a moving branch or an unpinned tree-sitter CLI.
