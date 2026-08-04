# Make CodeUnit identity fully structured

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this document in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost must index declarations whose directory, package, module, namespace, type, or member names contain punctuation without losing the original hierarchy. After this change, `CodeUnit` has one authoritative identity: its structured `FqName`, plus an integer boundary identifying the package/module prefix. It no longer stores duplicate `package_name` and `short_name` strings, and neither cold extraction nor cache hydration rebuilds structured identity by splitting a rendered string. The motivating repository path `.github/workflows/generate-release-yml.rs` initializes successfully in a debug build instead of failing the `FqName` invariant.

## Progress

- [x] (2026-08-04 18:30Z) Confirmed that `FqName` already contains the complete package/module and declaration hierarchy, while `CodeUnit` duplicates the package and short portions as strings.
- [x] (2026-08-04 18:30Z) Confirmed that the Rust cold extractor and generic persistence hydration flatten and then split package names, and that the earlier Python hidden-directory repair is a language-specific exception around the same architectural defect.
- [x] (2026-08-04 20:10Z) Replaced `CodeUnit`'s duplicate identity strings with `FqName` plus a package-prefix segment count and renderings derived solely from that structure.
- [x] (2026-08-04 20:10Z) Made Python, Rust, and Go path-derived package adapters produce structured prefixes without persistence reparsing rendered names; Rust filesystem components now stay atomic.
- [x] (2026-08-04 20:10Z) Changed persistence encoding and hydration to slice and compose structured segments directly, including content-addressed blobs mounted at different paths.
- [x] (2026-08-04 20:10Z) Added the Rust hidden-directory cold/warm regression and retained the cross-language structured-identity round trip.
- [x] (2026-08-04 07:49Z) Ran formatting, focused regressions, the no-stringly-name policy test, the isolated all-features workspace Clippy gate, and the featureless 8,209-test workspace matrix outside the restricted sandbox. Clippy passed; 8,208 tests passed and the sole failure is the pre-existing Java fixture's JDK-8-incompatible `jar --version` availability probe.
- [x] (2026-08-04 23:25Z) Integrated the concurrent `bifrost-core` extraction from `origin/master`, moved the authoritative `FqName` and `CodeUnit` implementation with it, and passed the merged-tree analysis test compilation.
- [x] (2026-08-04 23:42Z) Re-ran the merged-tree analyzer and persistence suites, doctests, isolated all-features workspace Clippy, and the complete 8,210-test featureless workspace matrix. All 8,209 runnable tests passed; only the unchanged JDK-8-incompatible `jar --version` probe failed.
- [ ] Commit the scoped changes, push the commit to `origin/master`, and close GitHub issue #1555 with validation evidence.

## Surprises & Discoveries

- Observation: The prior interned-name migration deliberately retained one flatten/reparse bridge for persistence and documented moving it behind `LanguageAdapter` as deferred work.
  Evidence: `.agents/plans/fqname-interned-segments.md` describes `package_prefix_fq(lang, package_name, interner)` as a sanctioned bridge and says an adapter method could retire it.

- Observation: The bridge's assumption that dotted package components cannot themselves contain a dot is false for path-derived modules such as `.github` and `.agent`.
  Evidence: Rust constructs `.github.workflows`, then `rust_package_fq` filters the empty component produced by `split('.')`, rendering `github.workflows` and triggering the construction invariant.

- Observation: Making structured identity authoritative exposed a Rust early-`impl` path that rendered identically while tagging a lexical module as a type.
  Evidence: The 706-test analyzer suite initially failed `rust_inline_module_impl_before_type_uses_the_declared_owner_identity`; constructing non-terminal resolved owner components as `Package` segments removed the equal-rendering orphan and the suite then passed 706/706.

- Observation: Ruby singleton fields encoded `$singleton` and the field identifier in one atomic member segment even though `$singleton` is an owner scope.
  Evidence: The workspace matrix initially reported `identifier()` as `$singleton.@last_build`; emitting separate synthetic-scope and member segments restored `@last_build` as the terminal identifier and made analyzer, definition, and usage regressions pass.

- Observation: LSP constructor classification was still recovering the owner by splitting the rendered `short_name`.
  Evidence: Once `identifier()` became structurally terminal, the Java constructor regression exposed the split. A structural `CodeUnit::owner_identifier()` projection now supplies the penultimate FqName segment without reparsing display text.

- Observation: The only remaining workspace-test failure is host-tool detection, not this change.
  Evidence: The unrestricted matrix passed 8,208 of 8,209 tests. The host's JDK 8 `javac` works, but `jar --version` exits nonzero, causing the existing Java producer fixture's `tool_available("jar")` assertion to fail before exercising Bifrost code.

- Observation: `origin/master` extracted the shared analyzer model into `bifrost-core` while this work was being prepared for publication.
  Evidence: Integrating master relocated `fq_name.rs`, `model.rs`, and cache migrations into `crates/bifrost-core`; resolving the merge there and rechecking `brokk-bifrost-analysis` preserved the structured identity implementation at the new crate seam.

## Decision Log

- Decision: Use the existing `FqName` as the only hierarchy representation; do not introduce another package hierarchy structure.
  Rationale: `FqName` already stores ordered, kind-tagged, punctuation-safe segments and already supports prefix and suffix operations. A second hierarchy type would recreate the redundancy being removed.
  Date/Author: 2026-08-04 / Codex.

- Decision: Store the package/module boundary as a segment count on `CodeUnit`.
  Rationale: The full `FqName` contains both prefix and tail, but segment kinds cannot always identify the boundary because package-kind segments can legitimately occur in a declaration tail. A boundary count adds the missing structural fact without duplicating segment data.
  Date/Author: 2026-08-04 / Codex.

- Decision: Textual package, short, and fully qualified names are projections, not stored identity fields.
  Rationale: Extractor entry points may use textual projections to validate and locate the explicit package boundary, but they discard those inputs. Rendering thereafter comes from one structured value, making stored disagreement impossible.
  Date/Author: 2026-08-04 / Codex.

- Decision: Keep one immutable fully rendered name plus byte offsets for borrowed textual projections.
  Rationale: Existing APIs return borrowed `&str` values. One FqName-derived display allocation with package, short, terminal, and owner offsets preserves those APIs without storing duplicate identity strings or introducing interior mutability into a hash key.
  Date/Author: 2026-08-04 / Codex.

- Decision: Preserve content-addressed cache sharing by persisting the content-stable tail and composing it with a structured per-path prefix during hydration.
  Rationale: The same blob can be mounted at multiple paths, so persisting a full path-derived FQName would attach the first path's prefix to every mount. The existing tail/prefix split is sound; only its string reconstruction is defective.
  Date/Author: 2026-08-04 / Codex.

## Outcomes & Retrospective

Implementation and validation are complete pending publication. `CodeUnitInner` now has one structured hierarchy plus a package boundary; textual names are projections from one immutable rendering; cache hydration no longer consumes SQL string projections as identity; hidden Rust path components survive cold and warm analysis; Ruby singleton owner scope and LSP constructor owner matching are structural; the all-features workspace Clippy gate and doctests are clean; and the unrestricted post-merge featureless workspace matrix is green for every runnable test (8,209 passed, one host-JDK probe failure). The remaining work is commit/push and closing #1555.

## Context and Orientation

`crates/bifrost-core/src/analyzer/fq_name.rs` defines `FqName`, an ordered small vector of interned segment identifiers. Each segment identifier resolves to punctuation-safe text and a semantic kind such as package, path, type, or member. `crates/bifrost-core/src/analyzer/model.rs` defines `CodeUnit`, the declaration handle used throughout analysis. At the start of this work it stores `package_name: String`, `short_name: String`, and a complete `fq: FqName`; the strings and the structured value describe the same identity. These types moved from `bifrost-analysis` into `bifrost-core` during the final integration with master.

Language extractors under `crates/bifrost-analysis/src/analyzer/<language>/` create `CodeUnit` values. Several extractors first flatten package or module components into a delimiter-joined string and then split that string to build `FqName`. The Rust implementation in `rust/declarations.rs` loses the literal leading dot of a `.github` path component this way. Python has a local exception that reconstructs from original `ProjectFile` components.

`crates/bifrost-analysis/src/analyzer/store/mod.rs` persists a declaration's content-stable `FqName` tail in `code_units.fq_segments`, with its schema migrations under `crates/bifrost-core/migrations/cache`. It intentionally omits path-derived package segments because identical file content can occur at different paths. On hydration it rebuilds the prefix from `package_name` using `package_prefix_fq`, which again splits a rendered string. This plan retains content-stable tail persistence but makes the prefix structured at every point.

A package-prefix segment count is the number of leading segments in a declaration's full `FqName` that belong to the package, namespace, module, or import path. It lets code obtain a structured prefix or tail by slicing without guessing from delimiters or segment kinds.

## Plan of Work

First extend `FqName` with range rendering and prefix/suffix composition operations needed by `CodeUnit` and persistence. Refactor `CodeUnitInner` in `model.rs` to hold only the full `FqName`, a package-prefix segment count, source, kind, signature, synthetic marker, and lazily derived textual renderings if borrowing string slices remains necessary for hot existing APIs. Any rendering cache must be computed solely from `FqName`; it is not identity and cannot be supplied by constructors. Equality, ordering, and hashing must use the structured identity and boundary rather than former strings.

Next change construction APIs so production extractors provide a complete structured name and package boundary. Where a file path determines the package, derive a structured prefix directly from `Path::components`. Syntax-derived package helpers may tokenize grammar-defined separators at the extractor boundary, where those separators cannot occur inside an identifier; persistence must never tokenize a rendered identity. Parent-derived declarations inherit their parent's package boundary. Remove `rust_package_fq(package_name)`, generic `package_prefix_fq`, and `python_package_prefix_fq` once no caller needs them.

Then change `LanguageAdapter` and the analyzer store so hydration obtains a structured prefix. Path-derived adapters compute it from the live `ProjectFile`; content-derived package segments remain content-stable persisted data. Encoding slices the unit's `FqName` at its recorded boundary rather than reconstructing a prefix from text. Hydration appends the decoded content-stable tail to the adapter-provided prefix and records the new prefix length. Change the cache schema and epoch directly where necessary; no backward-compatible decoding path is required.

Finally add behavior-focused tests. A Rust file at `.github/workflows/generate-release-yml.rs` must produce an FQName whose first package segment is the literal text `.github`. Closing and reopening the analyzer must reproduce identical segment text, kinds, and package boundary without reparsing. Existing Python hidden-directory coverage and multi-path identical-blob coverage must remain green. Add contract cases for literal dots, Unicode, and punctuation where the relevant language permits them.

## Concrete Steps

Work from `/home/jonathan/Projects/bifrost/.worktrees/issue-1553-binary-source`.

Inspect and edit the model, FQName, language adapters/extractors, store, migrations, and tests named above. Use `cargo check -p brokk-bifrost-analysis --tests` after each coherent compiler-driven migration step. Run `cargo fmt --all -- --check` after formatting and the focused test commands discovered from the touched suites. Before pushing, run `scripts/pre-push-gate.sh` outside the restricted sandbox as required by `AGENTS.md`.

The motivating direct verification is a debug analyzer initialization over `.github/workflows/generate-release-yml.rs`; it must complete without the former `FqName does not round-trip` assertion and expose `.github` as one package segment through `fq_segments_debug()`.

## Validation and Acceptance

Acceptance requires all of the following observable behavior. The Rust hidden-directory regression passes cold and warm. The warm analyzer performs zero source reparses for the fixture. `fq_segments_debug()` reports `.github` as one `Package` segment rather than an empty segment plus `github` or a dropped leading dot. The identical-content-at-two-paths persistence test proves that each hydrated unit receives the prefix of its live path. Repository searches find no generic persistence/hydration function that constructs an FQName package prefix by splitting `package_name`, `content_qualifier`, or another rendered identity string. Formatting, focused tests, Clippy, and the pre-push gate pass.

## Idempotence and Recovery

Source edits and tests are repeatable. Cache schema changes are guarded by the analyzer epoch and development caches may be discarded because the project does not require backward compatibility. Commit only files changed for this plan. If the worktree's remote master advances before publication, fetch and integrate it without discarding local changes, rerun validation, then push the tested commit to `origin/master` as explicitly requested.

## Artifacts and Notes

The original panic reported:

    language=Rust, package_name=".github.workflows", short_name="Pattern"
    structured rendering="github.workflows.Pattern"
    legacy rendering=".github.workflows.Pattern"

The required structured prefix is:

    [(Package, ".github"), (Package, "workflows")]

not either of these lossy reconstructions:

    [(Package, "github"), (Package, "workflows")]
    [(Package, ""), (Package, "github"), (Package, "workflows")]

## Interfaces and Dependencies

`FqName` remains the hierarchy type and `SegmentInterner` remains the process-global text/kind interner. `CodeUnit` must expose structured prefix and tail accessors suitable for persistence without rendering. The package boundary is an integer validated to be no larger than `fq.len()`. Language adapters must expose structured hydration behavior; they must not return a string that another layer parses into segments. No new third-party dependency is required.

Revision note (2026-08-04): Created the initial implementation plan after confirming that the hidden Rust path failure is an incomplete `FqName` migration rather than a missing hierarchy abstraction.

Revision note (2026-08-04): Updated after implementation and broad analyzer/persistence regression testing; narrowed the no-splitting invariant to rendered identity reconstruction rather than grammar-defined separators at extractor boundaries.

Revision note (2026-08-04): Recorded final workspace validation, the Ruby singleton and LSP owner-projection follow-ups, and the unrelated JDK 8 fixture limitation before publication.

Revision note (2026-08-04): Integrated the concurrent `bifrost-core` extraction from master and updated ownership paths and validation notes for the merged architecture.
