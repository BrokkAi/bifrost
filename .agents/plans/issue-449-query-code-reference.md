# Rename the structural query surface to `query_code` and complete issue #449

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document must be maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost's normalized structural matcher is already broader than raw AST search: callers ask for language-neutral code shapes such as calls, assignments, imports, and decorators. The current public name, `search_ast`, becomes misleading as the same query surface grows to request existing call/type analysis and future control-flow or data-flow facets. This work performs a clean public rename to `query_code`, while keeping version 1 limited to the current normalized syntactic matcher and leaving the existing structural adapters intact.

After the change, a caller can run `bifrost --tool query_code --args '{"match":{"kind":"call","callee":{"name":"eval"}}}'`, use `SearchToolsClient.query_code(...)`, or enter the unchanged RQL expression `(call :callee (name "eval"))` in `bifrost --repl`. The documentation explains the complete version-1 query contract, accurately compares it with symbol, usage, graph, semantic, and text tools, and makes clear that graph and flow predicates are future facets rather than current behavior.

## Progress

- [x] (2026-07-10 09:56Z) Confirmed the issue branch is clean and current with its upstream after fetching remote refs.
- [x] (2026-07-10 09:56Z) Audited the MCP, CLI, Rust, Python, REPL, docs, tests, and generated skill surfaces carrying the old name.
- [x] (2026-07-10 10:07Z) Renamed the MCP/CLI, Rust, Python, and REPL surfaces to `query_code` / `CodeQuery` without an alias; added explicit old-name rejection and one-shot success coverage.
- [x] (2026-07-10 10:07Z) Validated the executable rename: 55 structural lib tests, 106 service tests, 75 structural integration tests, 35 MCP/CLI tests, and all 37 Python tests passed.
- [ ] Complete the #449 reference pages, help discoverability, and agent-skill guidance.
- [ ] Add executable documentation-example validation and checkpoint the documentation milestone.
- [ ] Run the full Rust, Python, plugin, docs-build, clippy, and rendered-preview gates.
- [ ] Update GitHub issues #328, #449, and #598 after all local validation passes.

## Surprises & Discoveries

- Observation: `search_ast` is already a released public contract across MCP, the one-shot CLI, Rust exports, the Python client, and generated plugin bundles, so the rename must be atomic rather than documentation-only.
  Evidence: `src/mcp_extended.rs`, `src/searchtools_service.rs`, `bifrost_searchtools/client.py`, and the v0.7.4 tag all expose the old name.

- Observation: the canonical JSON guide currently documents invalid `name_regex` and `text_regex` fields and incorrectly says `text` accepts exact shorthand.
  Evidence: `docs/src/content/docs/search-ast-json.md` disagrees with `src/analyzer/structural/query/decode.rs`, whose only string-predicate fields are `name` and `text`; regex is nested as `{ "regex": ... }`, and exact shorthand is enabled only for `name`.

- Observation: the canonical code-intelligence skill does not yet teach agents to use structural querying, and Amp's explicit tool allowlist omits it.
  Evidence: `plugins/bifrost-agent/skills/bifrost-codebase-search/SKILL.md` and `scripts/generate-amp-skill-bundle.mjs`.

- Observation: the Python test script uses a separate PyO3 target and host-level `uv` cache, so a cold validation rebuild is substantially longer than the focused Rust rename tests.
  Evidence: `scripts/test_python.sh` rebuilt the wheel in 2m52s, then passed all 37 tests; sandboxed access to `~/.cache/uv` required the normal approved escalation.

## Decision Log

- Decision: The public tool is `query_code`; the canonical Rust IR is `CodeQuery`; result and Python types use the `CodeQuery*` prefix.
  Rationale: the name describes one versioned query surface that can later compose syntax, call/type, and flow facets without claiming that version 1 already implements them.
  Date/Author: 2026-07-10 / dave + Codex.

- Decision: This is a hard rename. `search_ast`, `AstQuery`, and `SearchAst*` receive no compatibility aliases.
  Rationale: Bifrost explicitly does not require backward compatibility yet, and an alias would keep the misleading name in schemas, host configurations, and generated clients.
  Date/Author: 2026-07-10 / dave.

- Decision: JSON schema version 1, its fields, result wire shape, RQL syntax, and `--repl` behavior remain unchanged.
  Rationale: the change names the query surface and completes its reference; it does not alter matching semantics.
  Date/Author: 2026-07-10 / dave.

- Decision: Keep `src/analyzer/structural/`, `StructuralSpec`, `StructuralSearchProvider`, and structural test filenames as the version-1 syntax facet.
  Rationale: moving or generalizing the structural engine before a second facet exists would blur the current adapter boundary and expand the refactor without user-visible benefit.
  Date/Author: 2026-07-10 / dave + Codex.

- Decision: Detailed per-language tutorials stay in issue #598. Issue #449 delivers the cross-language reference, capability notes, and tested baseline examples.
  Rationale: the reference must stabilize before eleven language cookbooks duplicate it.
  Date/Author: 2026-07-10 / dave.

## Outcomes & Retrospective

Not yet complete. At completion, summarize the renamed public surfaces, documentation coverage, validation evidence, GitHub issue updates, and any deferred follow-ups.

## Context and Orientation

`src/analyzer/structural/query/` owns the typed query IR and the JSON/RQL frontends. `src/analyzer/structural/search.rs` executes the query over per-language structural facts. `src/mcp_extended.rs`, `src/searchtools_service.rs`, and `src/tool_arguments.rs` expose and dispatch the MCP/CLI tool. `src/bin/bifrost.rs` and its REPL module provide the one-shot and interactive CLI surfaces. `bifrost_searchtools/` exposes typed Python calls and results.

The public docs live under `docs/src/content/docs/`. `code-querying.md` is the overview. The current `search-ast-json.md` and `search-ast-repl.md` become `code-query-json.md` and `rune-query-language.md`. Canonical agent instructions live under `plugins/bifrost-agent/skills/`; Codex and Amp copies are generated by repository scripts and must not be hand-edited.

Version 1 matches normalized syntactic facts. `usage_graph` remains a separate existing tool. This plan must not add call-graph, type, control-flow, data-flow, or taint query fields; the docs may describe those only as a non-contractual future direction.

## Plan of Work

First, rename the public API atomically. Change the MCP descriptor and advertised extended-tool name to `query_code`; update service dispatch, path normalization, CLI help, one-shot examples, and tests so the old name returns the normal unknown-tool error. Rename `AstQuery` to `CodeQuery`, `SearchAstResultDetail` to `CodeQueryResultDetail`, and every public `SearchAst*` result type to the corresponding `CodeQuery*` type. Rename the direct service method and Python client method to `query_code`. Rename the REPL module, implementation identifiers, welcome/help text, and private history filename while keeping `--repl` and RQL syntax unchanged.

Second, update every current public consumer. Change Python exports, models, README, tests, MCP registry assertions, and CLI/service tests. Keep structural module, provider, adapter, and integration-test filenames unchanged because they still describe the current execution facet. Run focused validation, update this plan, and commit the executable rename as the first checkpoint.

Third, complete the documentation reference. Keep `code-querying.md` as the overview and add a decision guide for `query_code`, `search_symbols`, `scan_usages`, `usage_graph`, semantic search, and text search. State the current syntax-only boundary and the future progressive-facet direction without inventing future fields. Preserve concise per-adapter mapping notes and link the later cookbook issue rather than writing tutorials here.

Rename the JSON and RQL pages and update the Starlight sidebar and all links. The JSON reference must document every top-level and pattern field, the full kind hierarchy, role cardinality/validity, exact and regex predicate syntax, ordered-subsequence argument matching, captures and duplicate-capture equality, containment and negation, planner behavior, diagnostics, limits, pathful failures, compact/full results, and enclosing symbols. It must contain valid examples for every shape requested by issue #449. Put a minimal valid query and the published guide URL into the MCP descriptor so `bifrost --help query_code` is self-sufficient.

Fourth, make examples executable. Mark query JSON and RQL fences explicitly and add an integration test that reads the three public pages, extracts only marked examples, and parses them through `CodeQuery::from_json` or `CodeQuery::from_sexp`. Failures must name the document and line. The test also asserts that the required example categories are represented, without treating output JSON as input queries.

Fifth, update the canonical codebase-search skill with `query_code`, regenerate Codex and Amp bundles, and add the tool to Amp's explicit allowlist. Run the full validation suite, render the docs from a fresh server, inspect all three pages, update this plan, and commit the documentation checkpoint. Only after local evidence is green should GitHub issues #328, #449, and #598 be renamed/commented/closed as specified.

## Concrete Steps

Work from the repository root `/Users/dave/.codex/worktrees/499c/bifrost`.

For the executable rename, run focused checks after formatting:

    cargo fmt
    BIFROST_SEMANTIC_INDEX=off cargo test structural --lib
    BIFROST_SEMANTIC_INDEX=off cargo test --test structural_search_python --test structural_search_planner --test structural_search_cross_language
    BIFROST_SEMANTIC_INDEX=off cargo test --test bifrost_mcp_server --test bifrost_tool_cli --test searchtools_service
    scripts/test_python.sh

For generated skills and docs:

    node scripts/generate-codex-skill-bundle.mjs
    node scripts/generate-amp-skill-bundle.mjs
    node scripts/check-codex-plugin-manifest.mjs
    npm --prefix docs run check
    npm --prefix docs run build

For final validation:

    cargo clippy-no-cuda
    git diff --check

Start a fresh docs server on a confirmed-free port and inspect `/code-querying/`, `/code-query-json/`, and `/rune-query-language/`. Do not trust a stale Astro process.

## Validation and Acceptance

The MCP `extended` and `searchtools` catalogs advertise `query_code` and do not advertise `search_ast`. Calling `query_code` with the existing v1 JSON returns the same structured fields and rendered matches as before. Calling `search_ast` returns an unknown-tool error.

The one-shot CLI accepts `--tool query_code`; `--help query_code` identifies the extended toolset, includes a valid minimal query, links the guide, and states the syntax-only v1 boundary. The REPL accepts the unchanged RQL forms, prints canonical `CodeQuery` JSON, and uses the renamed private history path.

Rust callers compile against `CodeQuery` and `CodeQuery*` result types. Python callers use `SearchToolsClient.query_code(...)` and receive `CodeQueryResult` with the unchanged serialized fields. No public alias exposes the old names.

Every marked docs query parses in tests. The rendered docs show working navigation, correct syntax highlighting, readable tables and examples, and no broken old slugs. A search over current public docs, descriptors, SDKs, help, and generated skills finds no `search_ast`, `AstQuery`, or `SearchAst` reference. Historical plans may retain the old terms as history.

## Idempotence and Recovery

The rename is mechanical and safe to retry before checkpoint commits. If a generated bundle differs unexpectedly, edit its canonical skill or generator and regenerate; never patch generated output directly. If docs validation finds a bad example, correct the example rather than weakening the parser. GitHub mutations occur only after local validation, so a failed local gate cannot leave issue state falsely claiming completion.

## Artifacts and Notes

The existing `docs/src/content/docs/search-ast-json.md` example using `name_regex` is known-invalid and must become `"name": {"regex": "eval|exec"}`. The descriptor in `src/mcp_extended.rs` already reflects the correct predicate encoding and is the best compact source for limits and vocabulary.

## Interfaces and Dependencies

No new runtime dependency is required. The final public names are:

    query_code                              # MCP and --tool name
    CodeQuery                               # canonical Rust IR
    CodeQueryResultDetail
    CodeQueryResult
    CodeQueryMatch
    CodeQueryCapture
    CodeQueryRange
    CodeQueryDiagnostic
    CodeQueryExecutionLimits
    SearchToolsClient.query_code(...)       # Python method

The version-1 JSON schema and serialized result field names remain unchanged. Documentation-example validation should use a small test-only marked-fence extractor rather than adding a Markdown parser dependency.

## Revision Notes

- 2026-07-10: Initial plan written after the user selected `query_code`, a hard rename, and reference-first scope. The plan preserves RQL and structural internals while making future graph/flow facets an explicit architectural direction rather than current API.
