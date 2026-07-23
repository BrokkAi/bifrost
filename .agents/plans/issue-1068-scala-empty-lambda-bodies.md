# Parse Scala empty-bodied block lambdas without truncating declarations

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this document in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

After this change, Bifrost will parse valid Scala calls such as `simulation.run() { _ => }` without turning the enclosing class body into a tree-sitter `ERROR`. In the Chisel reproduction from issue #1068, `svsimTests.VCSSpec` will span its complete body, its fields will be independently indexed, and the declarations following it in `BackendSpec.scala` will remain visible through SearchTools. A user can observe the repair by asking `get_symbol_sources` for `svsimTests.VCSSpec` at Chisel commit `e639b4f69e90ecf3f14c25b898fda9d1eadf3cc1`: the result must include lines 16 through 234 instead of only the class header on line 16.

## Progress

- [x] (2026-07-23 06:19Z) Refreshed `origin`, confirmed the issue branch is clean at `1a5a9a72`, and verified that the five newer `origin/master` commits do not touch Scala or the vendored grammar.
- [x] (2026-07-23 06:19Z) Confirmed that GitHub and crates.io still publish only `tree-sitter-scala` 0.26.0 from 2026-04-18, while the required upstream fix merged later as PR #551 / commit `88a12d30bd14edfab6d4552af22f6d3a5f5000e9`.
- [x] (2026-07-23 06:19Z) Reproduced current behavior against the exact Chisel commit: the raw parser emits an `ERROR` at bytes `410..22749`, `get_symbol_sources` returns only `class VCSSpec extends BackendSpec`, and `search_symbols` reports no fields from the file.
- [x] (2026-07-23 06:19Z) Regenerated upstream PR #551 in a temporary checkout with `tree-sitter-cli` 0.25.9 and proved that the exact Chisel file then parses with `root_has_error=false`.
- [ ] Port the coherent upstream grammar patch, regenerate Bifrost's pinned parser, document provenance, and add parser-shape controls.
- [ ] Add analyzer, SearchTools, property-fuzzer, and persisted-cache regressions, then replay the exact Chisel witness.
- [ ] Run focused and repository-wide validation, review the final diff, and record outcomes.

## Surprises & Discoveries

- Observation: The required fix exists upstream but is not in any published crate.
  Evidence: GitHub reports `v0.26.0`, published 2026-04-18, as the latest release; crates.io reports `tree-sitter-scala = "0.26.0"`; upstream PR #551 merged on 2026-07-21.

- Observation: The Chisel failure is caused by valid empty-bodied block lambdas, not by the class header or declaration extraction.
  Evidence: The current grammar requires `$._block` after `=>` in `_block_lambda_expression`. Chisel contains `simulation.run(...) { _ => }` at lines 75, 226, and 327. Adding upstream's optional body production makes the complete 680-line file error-free.

- Observation: The empty-lambda change is coupled to self-type parsing.
  Evidence: `{ self: Base => }` is lexically ambiguous with an empty-bodied lambda. Upstream PR #551 adds explicit empty self-type-only template alternatives so dynamic precedence can select `self_type` instead of silently accepting the wrong lambda tree.

- Observation: The connected Bifrost MCP server is unavailable in this task session.
  Evidence: Tool discovery exposes no Bifrost analyzer calls in this turn. The checked-out `target/debug/bifrost` one-shot CLI remains available and reproduced the public SearchTools failure directly.

## Decision Log

- Decision: Keep the current v0.25.1 vendored base and port upstream PR #551 rather than waiting for a release or updating to an unreleased master snapshot.
  Rationale: No published package contains the fix. The existing vendor already carries #1016 and #1073, and a bounded upstream patch preserves that known base while providing immutable provenance.
  Date/Author: 2026-07-23 / Codex

- Decision: Port PR #551 as one coherent grammar patch, including its empty self-type and enum changes, rather than changing only `_block_lambda_expression`.
  Rationale: Making the lambda body optional by itself creates new successful but structurally wrong parses for self-type-only template bodies. The merged upstream patch resolves those ambiguities and supplies corpus controls.
  Date/Author: 2026-07-23 / Codex

- Decision: Keep the full Chisel checkout as an ephemeral validation corpus and commit a compact behavior-focused regression.
  Rationale: The repository guidance favors `InlineTestProject` for small test projects, while the exact 680-line upstream file is still valuable as an end-to-end acceptance replay without permanently duplicating an external corpus.
  Date/Author: 2026-07-23 / Codex

- Decision: Do not rebase the issue branch onto the newer `origin/master`.
  Rationale: Repository policy prohibits rebasing without an explicit request, and the intervening commits do not overlap this work.
  Date/Author: 2026-07-23 / Codex

## Outcomes & Retrospective

Implementation is in progress. The desired end state is a source-controlled parser derived from v0.25.1 plus the documented #1016, #1073, and upstream #551 changes, with a clear path to remove the private parser once an official release contains all required behavior.

## Context and Orientation

Bifrost compiles its Scala parser from `vendor/tree-sitter-scala` in `build.rs`. It deliberately private-prefixes every native parser and scanner symbol so a downstream dependency on the published `tree-sitter-scala` crate cannot substitute a different parser at link time. `vendor/tree-sitter-scala/grammar.js` is the human-readable grammar; `src/grammar.json`, `src/node-types.json`, and `src/parser.c` are generated with `tree-sitter-cli` 0.25.9 and are checked into the repository so builds require no network or JavaScript tooling.

A block lambda is a function literal passed inside braces, such as `{ value => consume(value) }`. Scala also permits an empty body, such as `{ _ => }`, which evaluates to `Unit`. The current `_block_lambda_expression` rule requires a non-empty `$._block`, so tree-sitter enters error recovery at the arrow. In a sufficiently large class, recovery consumes the class body and every following top-level declaration.

Scala self types use similar syntax inside a class, trait, or enum body, for example `trait A { self: Base => }`. Upstream PR #551 makes empty lambda bodies legal while adding explicit productions that retain such forms as `self_type`. The same patch also allows modifiers on enum cases used by its production witness. These rules must be adopted together.

`src/analyzer/store/epoch.rs` computes a per-language analysis epoch. Node and field names are automatically fingerprinted, but parser-table-only behavior can change without altering either. The Scala epoch therefore has an explicit salt naming the vendored parser patches. That salt must add #1068 so old persisted parse results are discarded.

The relevant public behavior is exercised through `SearchToolsService`. Tests should use `tests/common/inline_project.rs` rather than manually creating temporary projects. The MCP property fuzzer's I1 invariant already recognizes a class declaration immediately adjacent to a large parser `ERROR` as `declaration-truncated-at-parse-error`.

## Plan of Work

First, apply the declarative changes from upstream tree-sitter-scala PR #551 to `vendor/tree-sitter-scala/grammar.js`. Preserve the existing contextual `extension` conflict and constructor-annotation fix. Add the empty lambda body, empty braced and indented self-type bodies, enum self types, and enum-case modifiers exactly as represented by upstream merge commit `88a12d30bd14edfab6d4552af22f6d3a5f5000e9`. Update `BIFROST_PATCH.md` to identify that commit and explain that the private parser may be removed after an official release contains #1016, #1073, and #551 together. Regenerate the generated grammar files with CLI 0.25.9.

Add parser-level tests in `src/analyzer/scala/language.rs`. One test must parse an empty-bodied wildcard lambda without errors and observe a `lambda_expression`. Additional controls must prove that braced and indented self-type-only traits produce `self_type`, that the enum witness produces a self type and a private enum case, and that the existing Scala 2 `extension` identifier and Scala 3 extension definition remain valid.

Add a compact Chisel-shaped source to the existing Scala integration tests through `InlineTestProject`. It must contain an enclosing class, nested callbacks with `{ _ => }`, members after the callbacks, and a following top-level declaration. Assert that the class source includes its closing body, the post-callback members are independently indexed with the class as parent, and the following declaration remains top-level. Exercise the same fixture through `get_symbol_sources` and the property fuzzer's I1 invariant so both analyzer and public-service behavior are protected.

Before changing the Scala epoch salt, record the current pre-#1068 epoch hash. Update the salt in `src/analyzer/store/epoch.rs`, rename the existing narrowly #1073-named cache test to describe parser-table changes generally, and seed the recorded pre-#1068 epoch so the test proves that the new grammar invalidates old Scala blobs.

Finally, validate the exact Chisel checkout at commit `e639b4f69e90ecf3f14c25b898fda9d1eadf3cc1`. Run the raw parser or property fuzzer in ephemeral mode and the one-shot `get_symbol_sources`, `search_symbols`, and `get_summaries` tools against only `svsim/src/test/scala/BackendSpec.scala`. Confirm that `VCSSpec` covers lines 16 through 234, that `finishRe`, `backend`, and `compilationSettings` are indexed, and that later classes remain visible.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/498d/bifrost`.

Regenerate the vendored grammar after editing `grammar.js`:

    cd vendor/tree-sitter-scala
    npx --yes tree-sitter-cli@0.25.9 generate

The generated files must be deterministic on a second run. Inspect `git diff --stat` and confirm that only the expected grammar, generated parser, provenance, epoch, plan, and test files changed.

Run focused tests as they are added:

    cargo test --lib analyzer::scala::language::tests
    cargo test --test scala_analyzer_test issue_1068
    cargo test --test searchtools_definition_selectors issue_1068
    cargo test --test mcp_property_fuzzer issue_1068
    cargo test --lib scala_parser_epoch

Use the exact Chisel checkout and the one-shot CLI:

    cargo run --bin bifrost -- \
      --root /path/to/chisel \
      --tool get_symbol_sources \
      --sources svsim/src/test/scala/BackendSpec.scala \
      --args '{"symbols":["svsimTests.VCSSpec"]}'

The source result must start on line 16, end on line 234, and include the body. Repeat with `search_symbols` for `VCSSpec`, `finishRe`, `backend`, and `compilationSettings`; fields must no longer be empty.

Run the package and CI-equivalent validation:

    cargo fmt --all -- --check
    scripts/check-crate-package.sh
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python

The package check must remain under its configured compressed-size budget. Clippy must emit no warnings, and the feature-enabled test suite must pass.

## Validation and Acceptance

Acceptance requires the compact empty-lambda source and the exact Chisel file to parse without `ERROR` or missing nodes. The empty callback must be represented as a `lambda_expression` whose parameter is the wildcard and whose body is absent, not as recovery syntax.

Self-type-only braced and indented templates must remain `self_type` nodes. The enum control from upstream PR #551 must retain its self type and private case. Existing #1016 annotated constructors and #1073 contextual `extension` tests must remain green.

`get_symbol_sources("svsimTests.VCSSpec")` must return the complete class body rather than line 16 only. `search_symbols` must independently return `finishRe`, `backend`, and `compilationSettings`, and `get_summaries` must list later declarations in `BackendSpec.scala`. The MCP property fuzzer must report no `(I1, scala, index, declaration-truncated-at-parse-error)` violation for the compact fixture or exact Chisel witness.

Persisted analysis created under the pre-#1068 Scala epoch must be treated as missing after the new parser is installed. Other language epochs and blobs must remain untouched.

## Idempotence and Recovery

The grammar generator is deterministic when run with 0.25.9. If a second generation changes files, stop and identify toolchain or source drift rather than accepting nondeterministic output. Do not use a globally installed unpinned CLI.

The exact Chisel replay must use ephemeral cache mode or a one-shot source-restricted workspace so it does not leave `.brokk/bifrost_cache.db` in the clone. Cargo validation should use `scripts/with-isolated-cargo-target.sh` where specified so temporary build directories are removed automatically.

If an official tree-sitter-scala release containing PR #551 appears before completion, test that release together with the #1073 behavior before changing course. Remove private compilation only if the published parser passes the empty-lambda, self-type, annotated-constructor, and contextual-`extension` controls.

## Artifacts and Notes

Current failure:

    {"sources":[{"start_line":16,"end_line":16,
      "text":"class VCSSpec extends BackendSpec"}]}

Current symbol search:

    {"classes":[{"symbol":"svsimTests.VCSSpec"}],"fields":[],"functions":[]}

Raw current parser:

    root_has_error=true
    ERROR bytes=410..22749

Regenerated upstream PR #551 parser:

    root_has_error=false

Upstream release state checked on 2026-07-23:

    latest GitHub release: v0.26.0, published 2026-04-18
    latest crates.io package: tree-sitter-scala = "0.26.0"
    required fix merged: 88a12d30, 2026-07-21

## Interfaces and Dependencies

There are no public Rust, MCP, RQL, or serialized schema changes. The `tree_sitter_scala::LANGUAGE` development dependency remains pinned at 0.25.1 as a coexistence control, while production continues to use the private `brokk_bifrost_tree_sitter_scala` symbol compiled from `vendor/tree-sitter-scala`.

The only dependency used to regenerate source remains `tree-sitter-cli` 0.25.9. Builds and tests consume checked-in generated C and require no Node.js or network access.

Revision note: 2026-07-23 created this ExecPlan after confirming the issue on current Bifrost, verifying that no published upstream package contains the fix, and proving the merged upstream grammar against the exact Chisel witness.
