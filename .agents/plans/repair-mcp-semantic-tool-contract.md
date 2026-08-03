# Repair the MCP semantic-tool contract tests

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

The `MCP contract` GitHub Actions job on `master` is red even though the server is honoring its runtime configuration. After this repair, the end-to-end contract tests will distinguish an executable compiled with semantic-search support from a session where semantic indexing is actually enabled. A session started with `BIFROST_SEMANTIC_INDEX=off` will be proven not to advertise `semantic_search`; the existing enabled-path coverage will continue to prove that an opted-in, NLP-capable server does advertise and dispatch that tool. The result is a green contract job without starting semantic indexers in ordinary MCP integration tests or weakening the production availability gate.

## Progress

- [x] (2026-08-03 19:25Z) Fetched `origin/master`, created `investigate-master-mcp-contract-failures` at `59dfb80c3`, and preserved the pre-existing untracked analyzer databases.
- [x] (2026-08-03 19:25Z) Inspected master run `30840294719` and isolated the two reported failures to stale `semantic_search` tool-list expectations.
- [x] (2026-08-03 19:25Z) Traced descriptor construction, test process configuration, enabled-path coverage, and relevant history; no production MCP protocol failure was found.
- [x] (2026-08-03 19:28Z) Received approval to implement the ExecPlan and push the validated repair directly to `master`.
- [x] (2026-08-03 19:28Z) Updated the disabled-session tool-list expectations and exposed the latent `nlp`-only disabled-session assertion.
- [x] (2026-08-03 19:43Z) Ran focused featureless and NLP-enabled contract tests, the enabled semantic registry and missing-model tests, and the full MCP contract command used by CI; all test and doctest targets passed.
- [x] (2026-08-03 19:43Z) Ran formatting, strict package Clippy, and the required repository policy selection; no changed-file policy finding or diagnostic remains.
- [x] (2026-08-03 19:46Z) Refreshed `origin/master`; committed only the MCP test and this ExecPlan and pushed the validated commit directly to `master`.

## Surprises & Discoveries

- Observation: The CI job compiles `brokk-bifrost-mcp` with `--features nlp`, but both failing subprocesses explicitly set `BIFROST_SEMANTIC_INDEX=off`.
  Evidence: `.github/workflows/ci.yml` runs `cargo test -p brokk-bifrost-mcp --features nlp`; `bifrost_searchtools_server_speaks_mcp_stdio` and the shared `spawn_server` helper set the environment variable to `off`.

- Observation: Compile-time support is only one of three production conditions for advertising `semantic_search`.
  Evidence: `crates/bifrost-mcp/src/mcp_nlp.rs::nlp_tool_descriptors` returns no descriptor unless the root is a Git repository, semantic indexing is enabled at runtime, and an accelerator is available or CPU execution is forced.

- Observation: The second reported failure masks a third stale expectation in the same test.
  Evidence: `bifrost_split_servers_publish_expected_tool_sets` originally panicked while checking `core` before reaching its NLP-only assertion. After correcting the core expectation, the NLP-only process correctly rejected startup with `server mode expression produced no tools`; an empty server is not a valid MCP mode.

- Observation: The enabled surface already has hardware-independent structural coverage and a failure-path subprocess test.
  Evidence: `crates/bifrost-mcp/src/mcp_registry.rs` forces semantic indexing and CPU execution while checking the `nlp` descriptor and hidden status tool; `bifrost_semantic_search_fails_cleanly_without_models` opts in explicitly and proves a semantic call fails cleanly with a nonexistent local model directory.

- Observation: The host PATH mixed rustup's `rustc` with Homebrew's `rustdoc` and `cargo-clippy`, whose LLVM builds are artifact-incompatible despite sharing the Rust 1.96 version and commit hash.
  Evidence: the first full test run passed 161 Rust tests and then failed doctests with `E0514`; selecting rustup's `rustdoc` made the complete command pass. The first Clippy attempts failed similarly until the rustup Cargo, compiler, rustdoc, and Clippy driver were selected together.

- Observation: Full workspace Clippy reaches one unrelated current-master lint in `crates/bifrost-analysis/src/analyzer/python/imports.rs:219`.
  Evidence: `clippy::collapsible_if` is reported with no branch diff in that file. Strict all-target NLP Clippy for the changed `brokk-bifrost-mcp` package passes.

- Observation: The policy gate is reliable but reports existing repository-wide prompts.
  Evidence: all 12 `bifrost.code-smells` policies completed with zero diagnostics, 285 total findings, and zero findings whose primary path is `crates/bifrost-mcp/tests/bifrost_mcp_server.rs`.

## Decision Log

- Decision: Keep the production descriptor gate unchanged and repair the test expectations.
  Rationale: Advertising a tool that a session explicitly disabled would make discovery untruthful. The server's observed tool list matches its documented runtime state; the tests currently infer runtime availability from the Cargo feature alone.
  Date/Author: 2026-08-03 / Codex

- Decision: Keep ordinary subprocess helpers on `BIFROST_SEMANTIC_INDEX=off`.
  Rationale: Repository guidance forbids routine tests from downloading models or starting semantic indexing work. Contract tests unrelated to semantic execution need a deterministic, resource-light server.
  Date/Author: 2026-08-03 / Codex

- Decision: Test disabled and enabled discovery in different existing test layers instead of adding a mode flag to the server helper.
  Rationale: The subprocess contract tests already provide isolated disabled-session behavior, while registry unit tests can construct the enabled descriptor surface without starting an indexer. This avoids global environment races and keeps each test's setup explicit.
  Date/Author: 2026-08-03 / Codex

- Decision: Assert startup rejection for the disabled `nlp`-only mode instead of expecting a running server with an empty tool list.
  Rationale: Registry resolution intentionally rejects every mode expression that produces no tools. The observable disabled-state contract for `core` is a list without `semantic_search`; for `nlp` alone it is a bounded startup error.
  Date/Author: 2026-08-03 / Codex

## Outcomes & Retrospective

Investigation, the approved test correction, and validation are complete. Disabled `searchtools` and `core` sessions now advertise their truthful non-semantic surfaces in both featureless and NLP builds, while disabled `nlp`-only startup is verified to fail clearly and enabled semantic discovery/dispatch coverage still passes. The CI-equivalent MCP suite passes 130 unit tests, 31 integration tests, and doctests. The policy gate completed reliably with no finding in the changed file. The only incomplete repository-wide gate is an unrelated pre-existing Python Clippy finding on current master; strict Clippy for the changed MCP package passes. The validated files are ready to commit and push directly to `master`.

## Context and Orientation

The MCP, or Model Context Protocol, server publishes a list of callable tools during `tools/list`. The executable can be compiled with the optional Cargo feature named `nlp`, which contains semantic-search code, while runtime configuration still decides whether a particular server session may use that code.

`.github/workflows/ci.yml` defines the `MCP contract` job. It runs `cargo test -p brokk-bifrost-mcp --features nlp`, so Rust expressions guarded by `#[cfg(feature = "nlp")]` are active in the failing job.

`crates/bifrost-mcp/src/mcp_nlp.rs` builds the semantic tool descriptors. Its `nlp_tool_descriptors` function omits `semantic_search` if the workspace is not a Git repository, if `BIFROST_SEMANTIC_INDEX` is not an enabled value, or if no accelerator is available and CPU execution was not forced. This is the production truth that MCP discovery must reflect.

`crates/bifrost-mcp/tests/bifrost_mcp_server.rs` contains process-level contract tests. `bifrost_searchtools_server_speaks_mcp_stdio` starts a complete `searchtools` server, and `bifrost_split_servers_publish_expected_tool_sets` checks the composed toolsets such as `core` and `nlp`. Both paths set `BIFROST_SEMANTIC_INDEX=off`; they also pass `--force-semantic-cpu`, but the CPU override cannot override an explicitly disabled index. The current expectations nevertheless insert `semantic_search` whenever the test crate was compiled with the `nlp` feature. Master run `30840294719` therefore observed a correct list without `semantic_search` and compared it with an incorrect list containing that name.

`crates/bifrost-mcp/src/mcp_registry.rs` contains structural registry tests. Its helper enables semantic indexing and forces CPU availability before resolving toolsets, so those tests cover the enabled descriptor composition without starting the MCP server or an indexer. The process-level `bifrost_semantic_search_fails_cleanly_without_models` test separately enables the index for a deliberately unavailable local model and verifies that dispatch fails cleanly rather than hanging or downloading anything.

## Plan of Work

Milestone 1 corrects disabled-session discovery. In `crates/bifrost-mcp/tests/bifrost_mcp_server.rs`, collapse the two compile-feature-specific expected lists inside `bifrost_searchtools_server_speaks_mcp_stdio` into the single list that matches `BIFROST_SEMANTIC_INDEX=off`. In `bifrost_split_servers_publish_expected_tool_sets`, stop inserting `semantic_search` into the `core` expectation merely because the test was compiled with NLP. Assert that an NLP-only mode fails startup with `server mode expression produced no tools` when the helper has disabled indexing. Keep the exact list assertions because toolset membership and ordering are the user-visible contract under test.

At the end of this milestone, both named CI failures will pass, and the previously unreachable `nlp`-only check will prove the same disabled-state rule rather than revealing another failure. No production source, Cargo feature, workflow, or tool registry should change.

Milestone 2 confirms that disabled-session corrections did not erase enabled-session coverage. Run the registry unit tests under the `nlp` feature and confirm that `nlp_accepts_status_without_advertising_it` still sees `semantic_search` as advertised and `semantic_search_status` as accepted but hidden. Run the existing `bifrost_semantic_search_fails_cleanly_without_models` process test and confirm that an explicitly opted-in server still accepts the semantic tool call and returns a bounded availability error. Do not enable indexing in the general spawn helper and do not introduce a model download.

Milestone 3 validates the complete MCP contract. Run the two corrected tests without `nlp` and with `nlp`, then run the exact CI command. Run `cargo fmt --check`. Finally, use the installed `bifrost-policy-checking` skill to execute `bifrost.code-smells` together with every executable repository policy root named by the active workspace in one request, review every finding, and require a reliable result. Record commands, counts, and any unrelated pre-existing findings in this living plan.

## Concrete Steps

All commands run from the repository root on branch `investigate-master-mcp-contract-failures`.

First edit only `crates/bifrost-mcp/tests/bifrost_mcp_server.rs` as described above, then format and run the focused disabled-session contracts:

    cargo fmt --check
    cargo test -p brokk-bifrost-mcp --test bifrost_mcp_server bifrost_searchtools_server_speaks_mcp_stdio -- --exact
    cargo test -p brokk-bifrost-mcp --test bifrost_mcp_server bifrost_split_servers_publish_expected_tool_sets -- --exact
    cargo test -p brokk-bifrost-mcp --features nlp --test bifrost_mcp_server bifrost_searchtools_server_speaks_mcp_stdio -- --exact
    cargo test -p brokk-bifrost-mcp --features nlp --test bifrost_mcp_server bifrost_split_servers_publish_expected_tool_sets -- --exact

Then run the enabled-path tests:

    cargo test -p brokk-bifrost-mcp --features nlp mcp_registry::tests::nlp_accepts_status_without_advertising_it -- --exact
    cargo test -p brokk-bifrost-mcp --features nlp --test bifrost_mcp_server bifrost_semantic_search_fails_cleanly_without_models -- --exact

Finally run the CI-equivalent contract suite:

    cargo test -p brokk-bifrost-mcp --features nlp

The two currently failing integration tests should report `ok`. The enabled registry test should continue to advertise `semantic_search`, and the missing-model process test should exit successfully after observing a clean semantic-index availability error.

## Validation and Acceptance

Acceptance requires all of the following observable behavior.

With `BIFROST_SEMANTIC_INDEX=off`, `tools/list` for `searchtools` and `core` must omit `semantic_search` even when the executable is compiled with `--features nlp`. All other tools must remain in their current order and toolset membership. An `nlp`-only server has no remaining tools and must fail startup with `server mode expression produced no tools`.

With semantic indexing explicitly enabled and CPU execution forced in the existing controlled tests, resolving the `nlp` toolset must advertise `semantic_search`, accept the hidden `semantic_search_status` companion, and dispatching `semantic_search` against the nonexistent test model directory must produce the existing clean availability error rather than an unknown-tool error, download, hang, or crash.

The exact CI command `cargo test -p brokk-bifrost-mcp --features nlp` must pass. `cargo fmt --check` must report no diff. The combined policy run must be reliable; any finding caused by this change must be fixed before completion.

## Idempotence and Recovery

The proposed edit changes assertions only and is safe to repeat. The tests create temporary repositories and child processes and do not mutate the working repository. If an NLP build is interrupted, rerun the same Cargo command; do not create a manually named temporary Cargo target. If disk isolation becomes necessary, use `scripts/with-isolated-cargo-target.sh`, which removes its managed directory when the command exits.

The pre-existing untracked `.bifrost/analyzer.db` and `src/lsp/.bifrost/analyzer.db` belong to the environment and must remain untouched. If new evidence shows that production discovery is wrong, stop and revise this plan's Decision Log before changing `mcp_nlp.rs` or the runtime configuration contract.

## Artifacts and Notes

The decisive CI excerpt from run `30840294719` is:

    bifrost_searchtools_server_speaks_mcp_stdio: actual list omitted semantic_search; expected list included it
    bifrost_split_servers_publish_expected_tool_sets: core actual list omitted semantic_search; expected list included it
    test result: FAILED. 29 passed; 2 failed

The relevant runtime predicate is conceptually:

    advertise semantic_search = git repository
        AND semantic indexing enabled
        AND accelerator available or CPU forced

The failing tests satisfy the first and third terms but explicitly make the second false.

Final local validation evidence is:

    featureless focused contracts: 1 passed and 1 passed
    NLP focused contracts: 1 passed and 1 passed
    enabled registry contract: 1 passed
    missing-model semantic dispatch: 1 passed
    CI-equivalent MCP suite: 130 unit passed; 31 integration passed; 0 doctests failed
    cargo fmt --all --check: passed
    strict brokk-bifrost-mcp all-target NLP Clippy: passed
    bifrost.code-smells: finding; 12 complete; 0 diagnostics; 285 existing; 0 in changed file

## Interfaces and Dependencies

No public interface or dependency should change. The repair uses the existing `BIFROST_SEMANTIC_INDEX` runtime contract, `nlp_tool_descriptors` production predicate, `spawn_server` process helper, `assert_server_tool_names` assertion helper, and registry unit tests. The final diff should be confined to `crates/bifrost-mcp/tests/bifrost_mcp_server.rs` plus this ExecPlan's living progress updates.

Revision note (2026-08-03 19:28Z): Marked approval and the test edit complete after the user authorized implementation and a direct push to `master`; validation remains pending.

Revision note (2026-08-03 19:31Z): Updated the disabled NLP-only acceptance behavior after the focused test proved that registry resolution rejects an empty server instead of serving an empty tool list.

Revision note (2026-08-03 19:43Z): Recorded completed validation, the mixed local Rust-toolchain recovery, the unrelated current-master Clippy finding, and the reliable policy result before the authorized direct-to-master commit.

Revision note (2026-08-03 19:46Z): Closed the final delivery step immediately before creating and pushing the exact validated commit to `master`; if delivery fails, this entry must be reverted and the failure recorded.
