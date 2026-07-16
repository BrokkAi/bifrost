# Add typed set composition to CodeQuery pipelines

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this document in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

After this work, `query_code` callers can combine complete typed queries with `union`, `intersect`, and `except`, then continue traversing the combined values through the existing semantic pipeline. A caller can ask for files importing either of two modules, files importing both, or callers of a legacy API excluding callers that also reach its replacement. JSON and Rune Query Language (RQL) compile to the same canonical recursive query plan, incompatible branch result domains fail before execution with an exact branch path, and duplicate endpoints retain bounded provenance from every contributing branch.

The behavior is visible through ordinary `query_code` execution and the executable cookbook under `docs/src/content/docs/code-query-tutorials/set-composition.md`. The cookbook contains equivalent JSON and RQL examples for all three operators and exact expected results, ordering, provenance branch labels, diagnostics, and truncation.

## Progress

- [x] (2026-07-16 08:05Z) Fetched the live issue and comment, confirmed the clean issue branch is exactly aligned with current `origin/master`, and inspected the typed query IR, decoder, RQL/schema registries, executor, result/provenance model, public clients, and executable documentation harness.
- [x] (2026-07-16 08:35Z) Chose the recursive plan-node representation and deterministic set semantics described below.
- [x] (2026-07-16 08:55Z) Implemented recursive canonical IR, JSON/RQL parsing and rendering, path-specific typed validation, source diagnostics/help, TextMate vocabulary, recursive MCP schema, and focused frontend tests.
- [x] (2026-07-16 09:45Z) Implemented shared-context recursive execution, typed endpoint set algebra, nested branch provenance/diagnostics, fair immediate-branch budgets, root-only limits, cancellation propagation, truncation, and identical canonical-seed reuse.
- [x] (2026-07-16 11:20Z) Updated Rust text output, Python request/result models, VS Code provenance types, and focused public-client coverage.
- [x] (2026-07-16 11:30Z) Added the executable JSON/RQL set-composition cookbook, updated query references and navigation, built and link-checked all docs, and visually verified the styled page and formatted exact outputs.
- [x] (2026-07-16 12:45Z) Completed adversarial diff review and final validation: formatting and diff checks, strict all-target/all-feature Clippy, the complete Rust `nlp` suite, the supported Python extension suite, VS Code tests, and Astro check/build all pass. The rendered cookbook was rechecked in the in-app browser.

## Surprises & Discoveries

- Observation: The current executor already deduplicates every linear pipeline stage by a typed `PipelineKey` and caps combined provenance at sixteen traces.
  Evidence: `src/analyzer/structural/search.rs` uses `insert_pipeline_row` for all step outputs, with `MAX_PROVENANCE_TRACES = 16`.

- Observation: The structural provider cache prevents a second parse after identical seed work, but the current top-level executor has no request-wide seed cache and would still rescan candidates independently if branches were executed as separate `CodeQuery` requests.
  Evidence: `StructuralSearchProvider::structural_facts` is cache-backed, while `execute_internal` currently rebuilds candidate scopes and scans sources once per call.

- Observation: Composition must be able to feed later typed steps, not merely combine terminal rendered results.
  Evidence: the useful files/import examples naturally require either branch-local `file_of` plus set composition or a common `file_of` after combining compatible declaration or site branches. A recursive source node with a step suffix supports both without introducing a second pipeline model.

- Observation: The installed Bifrost code-navigation skills have no corresponding MCP tools in this Codex session.
  Evidence: the active tool catalog contains no `search_symbols`, `get_symbol_sources`, `scan_usages`, or related Bifrost tool, so research uses the skill-prescribed narrow `rg` and direct-file fallback.

- Observation: Reusing a cached seed must still charge row-cloning work, but must not charge source scanning or fact materialization a second time.
  Evidence: the identical-seed integration test completes two union branches with a one-file scan limit and retains both branch-labeled provenance traces.

- Observation: Running Rust integration tests with the `python` feature directly does not link on this macOS extension-module configuration because Cargo attempts to build the `cdylib` without Python symbols.
  Evidence: `cargo test --test code_query_docs --test code_query_tutorials --features nlp,python` failed while linking `libbrokk_bifrost.dylib`; the supported `scripts/test_python.sh` path built the wheel and passed all 41 Python tests, while the two Rust docs suites passed without that feature combination.

- Observation: This machine had a stale Homebrew `cargo-clippy` ahead of the rustup toolchain in `PATH`, which initially produced an incompatible-rustc error rather than a project diagnostic.
  Evidence: rerunning with `/Users/dave/.cargo/bin` first exposed one real `large_enum_variant` warning; boxing the seed variant fixed it, and `cargo clippy --all-targets --all-features -- -D warnings` then passed.

- Observation: Several full-suite tests need process-control, GPG, and linked-worktree access unavailable in the managed sandbox.
  Evidence: the sandboxed `cargo test --features nlp` run passed 876 library tests but reported six permission/environment failures; the exact full command outside the sandbox passed every non-ignored unit, integration, and doc test.

## Decision Log

- Decision: Represent a query as one root `CodeQueryPlan`; a plan has either one structural seed or one set-composition source, followed by zero or more existing typed `QueryStep` values.
  Rationale: this preserves the current linear pipeline as the leaf case and permits steps after composition, including `(file-of (union ...))`, without treating rendered JSON results as executable values.
  Date/Author: 2026-07-16 / Codex

- Decision: Canonical JSON uses exactly one of `match`, `union`, `intersect`, or `except` at each plan node. The three composition fields contain arrays of at least two child plan objects. Only the root accepts `schema_version`, `limit`, and `result_detail`; structural scope fields belong only to nodes containing `match`.
  Rationale: mutually exclusive source fields make invalid mixed forms path-specific and easy to explain. Root-wide rendering and result limits avoid ambiguous branch-local output contracts.
  Date/Author: 2026-07-16 / Codex

- Decision: Keep CodeQuery schema version 2.
  Rationale: composition is an additive capability of the version-2 typed pipeline, and all existing version-2 leaf queries remain canonical without migration.
  Date/Author: 2026-07-16 / Codex

- Decision: RQL spells the operations `(union query query ...)`, `(intersect query query ...)`, and `(except query query ...)`. Existing step wrappers may wrap a set form, while `where`, `language`, `inside`, and `not-inside` remain structural-seed wrappers and therefore must be inside individual branches.
  Rationale: the forms mirror mathematical set operations, lower directly to the canonical arrays, and do not invent implicit distribution of structural scopes across branches.
  Date/Author: 2026-07-16 / Codex

- Decision: All branches of a composition must produce exactly the same `QueryValueKind`. `union` and `intersect` are variadic; `except` retains the first branch minus the union of all later branches.
  Rationale: exact domain equality prevents implicit conversion among matches, declarations, files, sites, and receiver analyses. Variadic operations avoid artificial nesting while retaining conventional left-source subtraction semantics.
  Date/Author: 2026-07-16 / Codex

- Decision: Union ordering is first appearance by branch order and then each branch's deterministic row order. Intersection and except preserve the first branch's order. Endpoint equality uses the existing per-domain `PipelineKey`.
  Rationale: these rules are deterministic, avoid extra sorting, preserve the most useful anchor ordering, and reuse the executor's exact typed identity rather than rendered strings.
  Date/Author: 2026-07-16 / Codex

- Decision: Each provenance trace and diagnostic produced under composition carries a zero-based `branch` path such as `[1]` or `[0, 2]`; non-composed queries omit the field. Union and intersection aggregate bounded traces in branch order, while except returns only provenance from retained first-branch rows.
  Rationale: users must be able to distinguish which branch contributed a duplicate endpoint or a capability omission. Nested integer paths are compact, deterministic, and do not require named bindings.
  Date/Author: 2026-07-16 / Codex

- Decision: Apply the public `limit` only after the complete root plan is evaluated. Intermediate branch and step rows are bounded by execution limits, not by the result limit. Any incomplete branch makes the root result `truncated`; cancellation keeps the existing all-or-empty result contract.
  Rationale: limiting a branch before intersection or subtraction can produce a wrong set. A root-wide limit preserves semantics, while `truncated: true` honestly reports when budgets prevent a complete result.
  Date/Author: 2026-07-16 / Codex

- Decision: A set node partitions the remaining request budget fairly among its immediate branches, reserving a share for every branch, and all branches share seed, import, declaration, reference, call, receiver, and render caches. Identical canonical structural seeds execute once and clone their internal rows for later branches without recharging scan/parse work.
  Rationale: one expensive branch must not starve every later operand, global caps must still bound the request, and the issue explicitly requires identical seed work not to be reparsed.
  Date/Author: 2026-07-16 / Codex

## Outcomes & Retrospective

All four milestones are complete. Schema-version-2 JSON and RQL now express recursive `union`, `intersect`, and `except` nodes, allow ordinary typed steps after composition, and reject mixed sources, too few branches, branch-local output controls, incompatible domains, and inconsistent named captures at exact paths. Live source validation, hover metadata, TextMate highlighting, REPL summaries, and the MCP schema all recognize the new vocabulary.

The executor now evaluates recursive plans over internal typed rows in one shared request context. Union, intersection, and subtraction use existing exact `PipelineKey` identities and deterministic operand order; union/intersection aggregate capped branch-labeled provenance, subtraction retains the first branch's evidence, nested paths are preserved, fair quotas reserve work for later operands, and the public result limit is applied only after composition. Identical canonical seeds reuse structural rows without rescanning files. The complete 68-test pipeline integration suite passes, including new set algebra, nesting, common suffix, provenance, cache reuse, fairness, diagnostic attribution, and global-limit coverage.

Python callers can choose exactly one of `pattern`, `union`, `intersect`, or `except_`, and both Python and VS Code surface typed branch provenance. Human Rust/REPL output labels contributing branches and branch diagnostics. The new cookbook executes import-graph union, intersection, and subtraction in equivalent JSON and RQL and asserts the complete serialized results. All 41 Python tests, 54 VS Code tests, 68 pipeline tests, 3 query-doc tests, and 21 executable tutorial tests pass; focused coverage exercises exact composition identity in all seven terminal domains, branch capability diagnostics, and cancellation. Astro check/build and all 4,270 internal link checks pass, and the rendered page was inspected in the in-app browser with readable formatted outputs and the expected navigation placement.

Final repository validation is green. `cargo fmt --all`, strict all-target/all-feature Clippy, and the full `cargo test --features nlp` matrix pass; the latter includes 882 library tests plus every non-ignored binary, integration, and doc test. The Python feature is validated through the repository's supported wheel-building script because a direct combined Rust `nlp,python` test build attempts to link the extension `cdylib` without Python symbols on this host. No compatibility fallback or text parser was introduced, and the final Clippy-driven boxing change keeps the recursive source enum compact without suppressing the lint.

## Context and Orientation

The canonical query model lives under `src/analyzer/structural/query/`. `ir.rs` defines `CodeQuery`, typed pipeline domains, and `QueryStep`; `decode.rs` validates canonical JSON; `json.rs` renders canonical JSON; `sexp.rs` lowers RQL; `schema.rs` owns every visible field, form, spelling, value shape, signature, and description; and `source.rs` provides precise editor diagnostics and hover metadata. Visible RQL vocabulary must also be added conservatively to `editors/vscode/syntaxes/bifrost-rql.tmLanguage.json`.

Today `CodeQuery` directly owns one structural seed (`where_globs`, `languages`, `root`, `inside`, and `not_inside`) plus a linear `steps` suffix and root-wide `limit` and `result_detail`. This plan replaces those direct seed fields with a root `CodeQueryPlan`. `CodeQueryPlan` owns a `CodeQueryPlanSource` and a `Vec<QueryStep>`. The source is either a `CodeQuerySeed` containing the former structural fields or a `CodeQuerySet` containing a `SetOperator` and child plans. `CodeQuery` continues to own schema version, public result limit, and output detail.

`src/analyzer/structural/planner.rs` and `matcher.rs` inspect only structural seed fields and should accept `&CodeQuerySeed`. `query/features.rs` likewise collects kinds and roles from one seed. The recursive plan validator computes each child output domain before accepting a set node, then validates the node's suffix steps. When a receiver operation names a capture and its input is a composed structural-match set, that capture is valid only if every contributing child exposes the positive capture name.

`src/analyzer/structural/search.rs` currently scans candidates, materializes seed matches, applies steps, deduplicates by `PipelineKey`, and renders results in one function. Refactor it into a request context plus recursive `execute_plan`. The context owns sorted structural providers/candidates, global work counters, a structural-seed row cache, the lazily built import graph, declaration/reference/call caches, and the final render cache. `execute_plan` evaluates a seed or recursively evaluates set children, combines internal `PipelineRow` values by `PipelineKey`, then applies the node's suffix steps using the existing expansion functions. Do not combine already rendered `CodeQueryResultItem` values.

The public result types live at the top of `search.rs`. `CodeQueryProvenance` and `CodeQueryDiagnostic` gain an omitted-when-empty branch path. Existing non-composed result JSON remains byte-for-byte equivalent apart from ordinary map serialization order. Python models live in `bifrost_searchtools/models.py` and request construction in `client.py`; VS Code result types live in `editors/vscode/src/rql_query.ts`; the MCP input schema is built in `src/mcp_extended.rs`.

Executable documentation blocks are parsed by `tests/code_query_docs.rs` and fully executed by `tests/code_query_tutorials.rs`. Add `set-composition.md` to both harnesses and to the Starlight navigation. Prefer `InlineTestProject` for focused Rust fixtures.

## Plan of Work

Milestone 1 introduces the recursive public IR and frontends. Add `SetOperator`, `CodeQuerySeed`, `CodeQueryPlanSource`, and `CodeQueryPlan` in `ir.rs`; move structural validation helpers to the seed; recursively validate branch domains and suffix steps with exact paths. Extend the declarative schema with query fields and RQL forms for all three operators, then update JSON decoding/rendering, RQL lowering, source diagnostics/help/completions, TextMate syntax, and MCP JSON Schema. Add focused query tests for leaf compatibility, nesting, steps after composition, canonical JSON/RQL parity, too few branches, mixed source fields, illegal branch-root fields, incompatible domains, and composed capture validation. Run the focused query/source/MCP tests, format, update this plan, review the milestone diff, and commit only the milestone files with a multiline rationale.

Milestone 2 refactors execution around internal recursive rows and shared request state. Move leaf scanning into a helper that accepts `CodeQuerySeed`, returns `PipelineRow` values, and caches identical canonical seeds. Evaluate set children with deterministic fair quotas derived from remaining global limits. Combine rows by `PipelineKey`, merge bounded provenance for union/intersection, retain only first-branch provenance for except, attach nested branch paths to traces and diagnostics, and apply suffix steps after composition. Apply `query.limit` once at the root. Preserve all-or-empty cancellation and aggregate truncation/diagnostics in deterministic branch order. Add test-only extraction counters or provider evidence proving identical seed branches materialize structural facts once. Add integration tests for empty result branches, duplicate endpoints, overlapping provenance, nested branch paths, all typed domains, incompatible direct-Rust plans, global limits, tiny per-branch budgets, mixed supported/unsupported diagnostics, cancellation, and truncation. Run the focused executor suites, format, update the plan, review, and commit the milestone.

Milestone 3 completes public surfaces and executable documentation. Extend the Python client with mutually exclusive `match`, `union`, `intersect`, and `except_` request construction and parse branch-labeled provenance/diagnostics. Update Rust exports, CLI/RQL help, VS Code types and rendering where needed, JSON/RQL reference pages, overview/safety/limits text, Python docs, and the new cookbook. The cookbook must execute at least one semantic graph composition and exact expected output for union, intersection, and except in both syntaxes. Add public-contract tests rather than exact registry-order mirrors. Run Rust docs/tutorial tests, Python tests, VS Code tests, Astro check/build, start a fresh docs preview, and inspect the new page and navigation. Update the plan, review, and commit the milestone.

Milestone 4 performs adversarial final review and complete validation. Inspect for implicit cross-domain conversion, rendered-string identities, lost or mislabeled provenance, unfair or multiplicative budgets, duplicate parsing, nondeterministic HashMap iteration, recursion in untrusted plan traversal, branch-local limits that change set semantics, cancellation leaks, diagnostic drift, source-diagnostic gaps, unsupported recursive MCP schema, Python keyword mistakes, and stale documentation. Fix every finding and add regressions. Run all focused suites, `cargo fmt`, strict all-target/all-feature Clippy, the full Rust `cargo test --features nlp` matrix, the supported Python extension suite, VS Code checks, docs check/build, and `git diff --check`. Record exact evidence and the final retrospective, then commit the reviewed checkpoint without pushing or opening a pull request.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/176a/bifrost` on `720-add-typed-set-composition-to-codequery-pipelines`. The branch started clean at `4051809a`, equal to both `origin/master` and the issue branch.

After every milestone, update this file, inspect `git status --short` and `git diff --check`, stage only files changed for this issue, and commit a multiline checkpoint explaining the design reason. Do not push or open a pull request.

Run focused implementation tests with commands such as:

    cargo test analyzer::structural::query
    cargo test --test code_query_pipelines
    cargo test --test structural_search_planner
    cargo test --test code_query_docs --test code_query_tutorials --features nlp,python
    cargo test mcp_extended
    scripts/test_python.sh
    npm --prefix editors/vscode test

Run final repository gates:

    cargo fmt
    cargo clippy --all-targets --all-features -- -D warnings
    cargo test --features nlp
    scripts/test_python.sh
    npm --prefix docs run check
    npm --prefix docs run build
    git diff --check

If an isolated target is required, use `scripts/with-isolated-cargo-target.sh`; do not create a manually named Cargo target directory. Start a fresh Astro preview only after the docs build and inspect the rendered set-composition tutorial plus navigation.

## Validation and Acceptance

Canonical JSON and RQL must parse to identical plans for every operator. A union of declaration and file branches must fail at the second branch's path with both actual domains in the message. A set node followed by a legal common step must execute; an illegal common step must fail at that node's `steps[index]` path. Fewer than two operands, a node containing more than one source field, or a branch containing root-only output fields must fail at the narrowest attributable path.

Union returns every endpoint once in first-contributing-branch order. Intersection returns only endpoints present in every branch, in first-branch order. Except returns first-branch endpoints absent from every later branch, again in first-branch order. Endpoint equality is exact for structural matches, declarations, files, reference sites, call sites, expression sites, and receiver-analysis rows.

A duplicate union endpoint and every retained intersection endpoint carry bounded traces labeled with each contributing branch path. Except rows carry only the first branch's evidence. More than sixteen total traces set `provenance_truncated` without exceeding the bound. Unsupported language or capability messages identify their branch path and appear in deterministic evaluation order.

The public limit is applied after set evaluation. A limited intersection or subtraction must still find retained endpoints that occur after the first `limit` rows of an operand when execution budgets allow. Tiny branch budgets reserve work for later operands, set top-level `truncated`, and emit branch-specific diagnostics. Cancellation at any branch returns no partial rows, `truncated: true`, and the existing cancellation diagnostic.

Two branches with the exact same structural seed but different semantic suffixes must cause only one structural-facts cache miss for each candidate file. Shared semantic caches must avoid rediscovering identical import/reference/call work where the current cache keys permit it. All traversal remains iterative or bounded by the existing maximum query depth; do not introduce unbounded Rust recursion over user input.

The executable cookbook must include JSON and RQL for union, intersection, and except, with exact expected end-to-end results. At least one recipe composes import, reference, or call traversal. The rendered page must explain compatible domains, identity, order, global limits, fair branch budgets, cancellation, diagnostics, truncation, and branch provenance.

## Idempotence and Recovery

Query execution is read-only over the analyzer and cached structural facts. Re-running tests is safe and writes only normal build artifacts and temporary inline projects. Canonical seed-cache keys come from structured IR serialization, never source parsing or hand-written string splitting.

If recursive plan execution cannot preserve a complete set under an exhausted branch, retain only the bounded partial set with `truncated: true`; never claim completeness. If recursive `$ref` is rejected by the MCP schema consumer, use a finite schema matching the enforced maximum composition depth and record that limitation rather than dropping runtime validation. If a milestone exposes a design flaw, revise this plan and Decision Log before continuing.

## Artifacts and Notes

Canonical composed JSON shape:

    {
      "union": [
        {"match": {"kind": "callable", "name": "legacy"}, "steps": [{"op": "enclosing_decl"}]},
        {"match": {"kind": "callable", "name": "replacement"}, "steps": [{"op": "enclosing_decl"}]}
      ],
      "steps": [{"op": "file_of"}],
      "limit": 20
    }

Equivalent RQL shape:

    (limit 20
      (file-of
        (union
          (enclosing-decl (callable :name "legacy"))
          (enclosing-decl (callable :name "replacement")))))

Domain flow at a plan node:

    structural seed or compatible set branches -> common typed domain -> node steps -> node output domain

Revision note (2026-07-16): Created the initial self-contained plan after reading live issue #720, confirming the exact issue branch and remote state, and tracing the current schema-version-2 query and execution pipeline. The plan chooses recursive source nodes with step suffixes so composition remains typed and can feed later traversal.

Revision note (2026-07-16): Completed Milestone 1. The final frontend shape keeps output controls root-only, supports suffix steps on every recursive node, intersects structural capture names across compatible branches, and publishes the recursive branch shape through JSON Schema `$defs`.

Revision note (2026-07-16): Completed Milestone 2. Recursive execution shares structural and semantic caches and global counters, partitions remaining work across immediate branches with roll-forward, combines exact typed endpoint keys before rendering, labels nested provenance and diagnostics, and preserves the existing plain-leaf response shape.

Revision note (2026-07-16): Completed Milestone 3. Public clients expose set plans and branch paths, textual result surfaces identify branch provenance, and a rendered, executable cookbook documents exact import-graph set algebra plus completeness rules.

Revision note (2026-07-16): Completed Milestone 4. Adversarial review found and fixed the recursive source enum's Clippy size warning. Strict all-feature linting, the full supported Rust and Python test matrices, client tests, docs checks, link validation, and visual QA are green; direct combined Rust `nlp,python` testing is recorded as a host extension-linking limitation rather than silently treated as coverage.
