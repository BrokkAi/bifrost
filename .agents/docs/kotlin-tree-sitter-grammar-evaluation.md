# Kotlin Tree-sitter grammar evaluation

Status: selected for Bifrost issue #1235 on 2026-07-28.

## Decision

Bifrost will use an immutable vendored snapshot of
`fwcd/tree-sitter-kotlin@c8ac3d2627240160b999a2c100de3babbdb8f419`.
The snapshot is MIT-licensed, exposes a `tree_sitter_language::LanguageFn`,
declares Tree-sitter language ABI 14, and includes a stateful C external
scanner. Bifrost compiles it directly with private native symbols and loads it
through the existing `tree-sitter = 0.25.10` runtime.

The alternative was
`tree-sitter-grammars/tree-sitter-kotlin@3dea6dfa9c0129deb7c4315afbda806c85c41667`,
published as `tree-sitter-kotlin-ng` 1.1.0. It is also MIT and ABI-compatible,
and it is smaller and faster on the comparison corpus. It was rejected because
the selected grammar has much deeper upstream validation and produced fewer
error-bearing and missing-node parses on the same pinned Kotlin sources. Those
properties are more important for the later indexing and semantic adapters
than the alternative's roughly 27% parse-time advantage in this small spike.

The published `tree-sitter-kotlin` crate was not selected. Its newest release
is 0.3.8, while the evaluated upstream source declares 0.4.0 and contains the
modern `LanguageFn` binding and recent grammar work. Bifrost therefore vendors
the exact source snapshot instead of depending on a stale release or an
unpublishable Cargo git dependency.

## Candidates and legal review

| Candidate | Exact revision | Rust package | License | Copyright | ABI | Scanner |
| --- | --- | --- | --- | --- | ---: | --- |
| `fwcd/tree-sitter-kotlin` | `c8ac3d2627240160b999a2c100de3babbdb8f419` | source version 0.4.0; current crate release trails at 0.3.8 | MIT | Copyright (c) 2019 fwcd | 14 | Stateful C scanner; serializes a delimiter/interpolation-prefix stack |
| `tree-sitter-grammars/tree-sitter-kotlin` | `3dea6dfa9c0129deb7c4315afbda806c85c41667` | `tree-sitter-kotlin-ng` 1.1.0 | MIT | Copyright (c) 2024 Amaan Qureshi | 14 | Stateless C scanner |

Both licenses are compatible with Bifrost's reviewed policy. Because the
selected C sources are incorporated directly rather than resolved as a Cargo
package, their MIT text is retained in `vendor/tree-sitter-kotlin/LICENSE` and
is copied into `SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt` by the native-source
notice generator.

The selected repository's upstream `highlights.scm` and `tags.scm` are retained
unchanged under `resources/treesitter/kotlin/`, not under `vendor/`. They are
reference/editor queries and are not loaded as Bifrost analyzer queries. The
highlight file retains its attribution to the Apache-licensed nvim-treesitter
source from which upstream derived it; the files remain excluded from the Rust
crate until Bifrost deliberately adopts a consumer for them.

## Reproducible inputs

Both candidates were shallow-checked out at the revisions above and built by a
single disposable Rust probe with `tree-sitter = "=0.25.10"`. The probe
selected exactly one candidate per build so their identical upstream
`tree_sitter_kotlin` symbols could not collide. It iteratively counted total,
named, error, and missing nodes; checked `root_node().has_error()`; exercised a
correct `InputEdit`; compared incremental and cold S-expressions; and recorded
per-corpus parse duration.

The same inputs were used for both candidates:

* Three hand-written probes: modern `.kt`, Gradle-shaped `.kts`, and a
  scanner-heavy script with nested comments and a raw interpolated string.
* 17 `.kt` files from
  `Kotlin/kotlin-examples@b1f83f080429d639765fccd72dba5ac5b24e3f76`.
* 36 `.kts` files from
  `Kotlin/kotlin-script-examples@09d4ca4f9add10faa5d9402a465a820754f1a82f`.
* 228 JetBrains Kotlin PSI source fixtures pinned by the selected upstream at
  `JetBrains/kotlin@fd4c284006a3095ac142b6b4e4bc82171a9b25b1`.
* One deliberately malformed function followed by a valid sibling, plus one
  structural edit reparsed incrementally and from scratch.

The JetBrains PSI directory intentionally contains negative and recovery
fixtures, including `_ERR` files. Its error totals are comparative evidence,
not a claim that every file should parse cleanly.

## Measured results

| Measure | `fwcd` | `-ng` |
| --- | ---: | ---: |
| Generated `parser.c` | 33,716,905 bytes | 22,443,237 bytes |
| External `scanner.c` | 34,940 bytes | 15,179 bytes |
| Gzip-9 complete source bundle used for projection | 1,865,677 bytes | 1,113,002 bytes |
| Named grammar node kinds exposed by runtime | 378 | 289 |
| Hand-authored upstream corpus cases | 257 across 14 files | 22 across 3 files |
| Ordinary project files (`.kt` + `.kts`) | 53/53 clean, 0 missing | 53/53 clean, 0 missing |
| All 281 pinned files with error-bearing roots | 106 | 115 |
| All 281 pinned files with missing nodes | 9 | 20 |
| Median parse time for all 281 files, 11 warm runs | 32.434 ms | 23.719 ms |
| Malformed fixture flags recovery and retains trailing function | yes | yes |
| Incremental parse is clean and structurally equal to cold parse | yes | yes |

The selected grammar uniquely parsed nine additional fixtures without a root
error after accounting for the three fixtures on which `-ng` did better. The
12 `-ng`-only error files include valid-looking scanner and modern-syntax cases
such as `BlockCommentAtBeginningOfFile1.kt` through `4.kt`,
`FloatingPointLiteral.kt`, `EnumInline.kt`, `TypeModifiers.kt`, and
`destructuringInLambdas.kt`. `fwcd` produced unique root errors for
`CommentsBinding.kt`, `LocalDeclarations.kt`, and
`annotationsOnNullableTypes.kt`. These are known limitations to retain when
later Kotlin analyzer fixtures are assembled.

The selected scanner carries real incremental state: a two-byte entry per
string delimiter records ordinary versus triple-quoted strings and the Kotlin
2.1 multi-dollar interpolation prefix. Its serialize/deserialize functions
copy that bounded stack into Tree-sitter's scanner buffer and reject odd-length
state. The smoke inputs cover nested multiline comments and string
interpolation; later corpus expansion should keep those forms represented.

## Packaging and portability

Before Kotlin, `scripts/check-crate-package.sh` measured the Bifrost crate at
9,331,190 bytes against its 10,000,000-byte gate. Directly adding either
generated parser would exceed that gate. The repository was also packaging
large animated documentation demos that Cargo consumers do not use. Kotlin's
vendoring therefore excludes `docs/src/assets/*.gif` from the Rust archive
while leaving those files in the repository and documentation site. The
selected grammar's build-required source, license, and provenance remain
mandatory package contents, checked by `scripts/check-crate-package.sh`.

The native build follows the already proven Scala pattern: C11, the source
directory on the include path, `-utf-8` under MSVC, and compile-time private
prefixes for the language function and all five scanner lifecycle/state
functions. After integration and query relocation, the verified publishable crate is 9,603,624
bytes, below the unchanged 10,000,000-byte gate, and contains the Kotlin
license, provenance, grammar source, parser, scanner, and all required headers.

The parser and scanner build and all four grammar smokes pass locally with
Rust 1.96.0 on `aarch64-apple-darwin` through the shared Tree-sitter 0.25
runtime. Direct C cross-compiles also pass with Zig for `x86_64-linux-gnu`,
`aarch64-linux-gnu`, and `x86_64-windows-gnu`. An attempted local
`x86_64-windows-msvc` compile reached the vendored sources but could not start
because this Mac has no MSVC SDK standard headers; that is a host-toolchain
limitation rather than a parser diagnostic. Bifrost's existing CI matrix is
therefore the final compilation evidence for Windows MSVC x64/arm64, Linux
x64/arm64, and Android; nightly macOS CI provides the repository's second
macOS gate. No runtime download or Node step is part of the Cargo build.

## Reproduction outline

Resolve the four source commits above, build each candidate in a separate
probe feature against Tree-sitter 0.25.10, and pass the two project roots plus
the pinned PSI fixture root as arguments. For performance, build release mode
once and invoke the binary 11 times, taking the median of the aggregate
`parse_us` value. Measure source bundles with gzip-9 for a conservative
approximation of `.crate` impact, then use `scripts/check-crate-package.sh` for
the actual post-integration archive.

The disposable probe is not retained as production code. Its enduring
contracts are the focused tests in `src/analyzer/kotlin/language.rs`, the exact
source digests in `vendor/tree-sitter-kotlin/BIFROST_PROVENANCE.md`, and the
package/notice gates.
