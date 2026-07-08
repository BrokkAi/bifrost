# Split get_definition Into Location and Reference APIs

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agents/PLANS.md` in this repository. It is self-contained so a contributor can restart from only this file and the current working tree.

## Purpose / Big Picture

The current `get_definition` tool requires callers to identify a reference by line/column or byte offset. That works for editor integrations but is awkward for large language models that often have nearby source text and a target token but should not be trusted to count lines. After this change, Bifrost exposes two explicit APIs backed by the same resolver: `get_definition_by_location` for exact location workflows and `get_definition_by_reference` for context plus target workflows. A human can see the feature by starting the MCP server normally and observing `get_definition_by_location`, then starting it with `--no-line-numbers` and observing `get_definition_by_reference`.

## Progress

- [x] (2026-06-18) Read `.agents/PLANS.md`, inspected the current MCP registry, service dispatch, public response structs, and internal resolver shape.
- [x] (2026-06-18) Created this ExecPlan before implementation.
- [x] (2026-06-18) Added public request/response structs and wrapper functions for location and reference modes.
- [x] (2026-06-18) Updated MCP descriptors and registry construction so `--no-line-numbers` selects the reference tool while normal line-number mode selects the location tool.
- [x] (2026-06-18) Updated service dispatch, tests, and benchmark callers to the new tool names; benchmark scenario labels remain `get_definition` for report continuity while the invoked tool is `get_definition_by_location`.
- [x] (2026-06-18) Ran formatting, focused tests, clippy, and `git diff --check`; all passed.
- [x] (2026-06-18) Commit the completed feature.
- [x] (2026-06-18) Removed the leftover `include_tests` parameter from both definition APIs so exact reference lookup always resolves against the full analyzed workspace.

## Surprises & Discoveries

- Observation: The MCP descriptor still advertised the removed `symbol` property even though the Rust request type no longer accepted it.
  Evidence: `src/mcp_core.rs` contained a `symbol` field inside the old `get_definition` schema while `DefinitionReferenceQuery` in `src/searchtools.rs` did not.
- Observation: Internal resolver output contains byte ranges needed by language-specific resolution, but the public `reference` field is only constructed at the final `searchtools.rs` rendering boundary.
  Evidence: `ResolvedReferenceSite` in `src/analyzer/usages/get_definition.rs` retains `range`, `focus_start_byte`, and `focus_end_byte`; `DefinitionReferenceSite` in `src/searchtools.rs` is the serialized public shape.
- Observation: Clippy rejects the raw semantic comparison tuple as too complex under this repository's `-D warnings` policy.
  Evidence: `cargo clippy --all-targets --all-features -- -D warnings` reported `clippy::type-complexity` for `semantic_outcome_key`; factoring the tuple into `DefinitionCandidateKey` and `DefinitionOutcomeKey` made clippy pass.

## Decision Log

- Decision: Keep internal byte/range tracking unchanged and simplify only serialized output.
  Rationale: Language-specific resolvers still need exact byte spans to inspect syntax trees and qualified expressions. Removing byte fields from the public response should not affect resolver correctness.
  Date/Author: 2026-06-18 / Codex.
- Decision: Use exact `context` and `target` matching for `get_definition_by_reference` v1.
  Rationale: Exact matching is deterministic and fail-closed. Fuzzy or whitespace-normalized matching can be added later if real usage shows it is needed.
  Date/Author: 2026-06-18 / Codex.
- Decision: Report semantically different candidate target matches as `ambiguous`, not `invalid_location`.
  Rationale: The text locator found valid references; the problem is multiple valid semantic answers, so `ambiguous` is the clearer terminal state.
  Date/Author: 2026-06-18 / Codex.
- Decision: Remove `include_tests` from definition lookup.
  Rationale: Unlike broad discovery tools, exact definition lookup starts from a concrete reference site and should resolve what that reference means rather than applying a test filtering policy.
  Date/Author: 2026-06-18 / Codex.

## Outcomes & Retrospective

The API split is implemented and validated. Direct service callers can use `get_definition_by_location` for exact line/column or byte-offset lookups and `get_definition_by_reference` for exact copied context plus target text. MCP now exposes only one of those tools per server process: normal line-number mode exposes location lookup, and `--no-line-numbers` exposes reference lookup. The public location-mode `reference` echo is reduced to `{ path, target }`, reference mode omits `reference` entirely, and neither definition API exposes `include_tests`.

Validation completed from `/home/jonathan/Projects/bifrost`:

    cargo fmt
    cargo test --test get_definition_test
    cargo test --test bifrost_mcp_server
    cargo test --test bifrost_tool_cli
    cargo test --test bifrost_benchmark_run
    cargo test --test benchmark_manifest
    cargo clippy --all-targets --all-features -- -D warnings
    git diff --check

The known unrelated untracked file `src/bin/semantic_index_profile.rs` remained unstaged.

## Context and Orientation

`src/searchtools.rs` owns the public JSON request and response structs plus the `get_definition` function that adapts public queries into internal resolver requests. `src/analyzer/usages/get_definition.rs` owns the actual language-aware resolver; it accepts a `DefinitionLookupRequest` with a `ProjectFile` and either line/column or byte offsets. `src/searchtools_service.rs` maps tool names to Rust functions. `src/mcp_core.rs` defines MCP tool descriptors, and `src/mcp_registry.rs` builds the allowed tool list for server modes such as `core` and `searchtools`. `src/bin/bifrost.rs` parses `--no-line-numbers`, currently only affecting text rendering.

In this plan, a "location" lookup means the caller identifies a reference using line/column or byte offsets. A "reference" lookup means the caller provides a source `context` string and a `target` string inside that context. The reference lookup implementation finds all exact target occurrences in all exact context occurrences, resolves each candidate with the existing location resolver, and collapses them only when they produce the same semantic result.

## Plan of Work

First, rename the existing public entrypoint to `get_definition_by_location` while keeping its input shape. Change its serialized `reference` from detailed byte/line fields to `{ path, target }`, where `target` is the normalized source text the resolver selected.

Second, add `get_definition_by_reference` in `src/searchtools.rs`. Define a request type with `references: Vec<{ path, context, target }>` and no test-filtering option. For each query, resolve the file path, load source text from the project file, find all exact context matches, find all exact target matches within each context, create byte-offset `DefinitionLookupRequest` values for those candidates, and run them through `resolve_definition_batch`. Collapse candidate outcomes when they are semantically equivalent by comparing status plus definition candidate identity. If valid candidates produce different definition sets or statuses, return an `ambiguous` result with diagnostics. If no context or target can be found, return `invalid_location` with diagnostics.

Third, update service dispatch and descriptors. The service should accept both `get_definition_by_location` and `get_definition_by_reference`. The MCP registry should build the symbol toolset with either the location descriptor or the reference descriptor depending on `McpRenderOptions.render_line_numbers`; `true` selects location and `false` selects reference. The MCP server should reject the unlisted variant because allowed tool names come from the selected descriptor list.

Fourth, update tests and benchmark callers. Existing `get_definition` tests and benchmark code should use `get_definition_by_location`. Add direct reference API tests for unique target resolution, repeated target occurrences collapsing to the same definition, and repeated target occurrences resolving differently with `ambiguous`. Update MCP server tests to assert normal mode lists location only and `--no-line-numbers` lists reference only.

## Concrete Steps

Run all commands from `/home/jonathan/Projects/bifrost`.

Use `rg` and `sed` to inspect the files named above. Edit with `apply_patch`. After edits, run:

    cargo fmt
    cargo test --test get_definition_test
    cargo test --test bifrost_mcp_server
    cargo test --test bifrost_tool_cli
    cargo test --test bifrost_benchmark_run
    cargo test --test benchmark_manifest
    cargo clippy --all-targets --all-features -- -D warnings

Then inspect `git status --short`, update this plan with validation evidence, and commit all files touched by this feature while leaving unrelated untracked files alone.

## Validation and Acceptance

The change is accepted when the focused tests pass and behavior is observable through MCP. In normal MCP mode, `tools/list` for `core` or `searchtools` includes `get_definition_by_location` and omits `get_definition_by_reference`. In `--no-line-numbers` MCP mode, `tools/list` includes `get_definition_by_reference` and omits `get_definition_by_location`. Calling the omitted tool through MCP returns the existing out-of-registry tool error. Direct service tests prove that `get_definition_by_reference` resolves a `context` plus `target` query and returns `ambiguous` when repeated target occurrences resolve to different definitions.

## Idempotence and Recovery

The edits are additive or renaming at the public API boundary and can be safely retried. If a test fails, inspect the failing assertion, patch the relevant source or test, and rerun only the focused test before continuing. Do not delete or revert unrelated files; the known unrelated untracked file is `src/bin/semantic_index_profile.rs`.

## Artifacts and Notes

Initial inspection showed:

    git status --short --branch
    ## master...origin/master [ahead 1]
    ?? src/bin/semantic_index_profile.rs

This untracked file is unrelated and must not be staged.

## Interfaces and Dependencies

At completion, `src/searchtools.rs` must provide `get_definition_by_location(analyzer: &dyn IAnalyzer, params: GetDefinitionParams) -> GetDefinitionResult` and `get_definition_by_reference(analyzer: &dyn IAnalyzer, params: GetDefinitionByReferenceParams) -> GetDefinitionByReferenceResult`. `src/searchtools_service.rs` must dispatch both new tool names. `src/mcp_registry.rs` must expose an option-aware server spec resolver, and `src/bin/bifrost.rs`, `src/mcp_core.rs`, or both must use it so the existing `--no-line-numbers` flag chooses the MCP-visible definition API.
