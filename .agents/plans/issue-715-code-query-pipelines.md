# Add typed CodeQuery pipelines and import-graph traversal

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this document in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

`query_code` currently returns only syntax matches. After this work a caller can start with the same normalized syntax query and apply typed semantic steps to find the containing declaration, convert a match or declaration to its file, and walk direct project import edges in either direction. JSON and the RQL shorthand compile to the same ordered pipeline, terminal values are returned as tagged results, and every derived result carries enough provenance to explain which seed and edges produced it.

The behavior is visible through the existing `query_code` MCP/CLI surface. A JSON query containing `"steps":[{"op":"file_of"},{"op":"imports_of"}]` returns directly imported workspace files, while the equivalent nested RQL expression `(imports-of (file-of ...))` returns the same ordered results. The executable documentation examples under `docs/src/content/docs/code-query-tutorials/` prove the public examples against real inline projects.

## Progress

- [x] (2026-07-13 10:08Z) Confirmed the clean tracked issue branch, fetched its upstream, and rebased it without changes.
- [x] (2026-07-13 10:08Z) Inspected the existing query IR, decoder, structural executor, import-provider contracts, Python models, and documentation test harness.
- [x] (2026-07-13 10:42Z) Implemented schema version 2, typed steps, canonical JSON, RQL lowering, and path-aware domain validation.
- [x] (2026-07-13 10:42Z) Implemented typed row execution, exact enclosing declarations, direct import edges, deduplication, provenance, and budgets.
- [x] (2026-07-13 11:36Z) Updated the MCP schema, CLI rendering/help, and Python client/models for typed `results` and pipeline `steps`.
- [x] (2026-07-13 11:36Z) Added behavior-focused integration tests and executable cookbook examples for every new step, including repeated direct import traversal.
- [x] (2026-07-13) Ran formatting, the 114-test focused Rust matrix, all 38 Python tests, Clippy with every feature and target, the full `nlp,python` Rust unit/integration matrix, and the CI-equivalent `nlp` doctest gate.
- [x] (2026-07-13) Recorded final validation evidence and completed the retrospective.
- [x] (2026-07-13) Ran the guided review against the four issue-715 commits and fixed all eight findings: terminal-type preservation on budget exhaustion, non-synthetic enclosing ancestors, reverse-provider ownership, declaration-free imports, bounded lazy graph construction, canonical newline coordinates, programmatic step validation, and cached full provenance rendering.
- [x] (2026-07-13) Added focused regression coverage for every guided-review finding; the 21-test pipeline suite, 34 query-IR tests, render-cache unit test, mixed-newline unit test, and 71 related import/docs/tutorial/cross-language tests pass.
- [x] (2026-07-13) Re-ran all repository gates after the guided-review fixes: formatting and diff checks pass, Clippy passes with every target and feature, all 38 Python tests pass, the full `nlp,python` Rust unit/integration matrix passes, and the CI-equivalent `nlp` doctest gate passes.

## Surprises & Discoveries

- Observation: The Bifrost MCP navigation tools named by the installed skills are not exposed in this Codex workspace session.
  Evidence: the active tool catalog contains no `search_symbols`, `get_symbol_sources`, or related Bifrost tools, so code inspection uses the skill-prescribed `rg` and direct-file fallback.

- Observation: `ImportAnalysisProvider::referencing_files_of` is not uniformly a direct-edge API.
  Evidence: the Ruby provider intentionally computes transitive referencing files for usage candidate discovery. Query pipelines must instead build direct forward edges from structured import information and invert that graph for `importers-of`.

- Observation: Not every syntax declaration is an indexed `CodeUnit`; for example, a nested Python local function is currently enclosed by its indexed outer declaration.
  Evidence: the initial nested-local fixture returned `app.outer`, while a class method fixture returned the exact `Outer.inner` declaration. The step therefore correctly promises the smallest indexed declaration rather than an arbitrary AST declaration node.

- Observation: This workstation has Cargo/Rustc and Rustdoc/Clippy installations built against different LLVM patch releases, and the user-local Rust installation has no `rustdoc` binary.
  Evidence: mixing the installations produced Rust metadata error E0514, while pinning Clippy and doctests to `/opt/homebrew/bin` succeeded. The complete `nlp,python` unit/integration run passed with the user-local Cargo/Rustc and macOS Python dynamic-link flags; the CI-equivalent `nlp` doctest run then passed independently with the Homebrew toolchain.

- Observation: The repository-wide service suite found one v1-shaped assertion that the focused query tests did not exercise.
  Evidence: `service_normalizes_query_code_absolute_where_globs` still indexed `value["matches"]`; changing that assertion to the schema-v2 `value["results"]` shape made the focused service test and the subsequent full unit/integration matrix pass.

- Observation: Provider support belongs to the file whose imports are being resolved, not the terminal file reached by a reverse edge.
  Evidence: a Ruby source can directly import a PHP target even though PHP has no import provider; `importers-of` must inspect and invert supported source edges rather than reject the target language.

- Observation: Declaration-derived import resolution is incomplete for imports that intentionally bind no declarations.
  Evidence: JavaScript/TypeScript side-effect imports, Go blank imports, and C++ includes of empty headers have valid direct file edges but no imported `CodeUnit`; the shared resolver now prefers structured file resolution and uses code units only as a structured fallback.

- Observation: Building the complete import graph before executing a pipeline defeats both empty-seed short-circuiting and query budgets.
  Evidence: forward traversal only needs the current file frontier, while reverse traversal needs a bounded workspace inversion. The executor now constructs the graph lazily, batches import parsing by language, and accounts separately for scanned files and stored edges.

- Observation: Rejecting a synthetic nearest declaration is not equivalent to finding the nearest real declaration.
  Evidence: a C++ call in a synthetic member prototype is still enclosed by its real class declaration. Candidate selection now filters synthetic and file-scope units before choosing the smallest containing range.

## Decision Log

- Decision: Name the declaration step `enclosing-decl`, not `enclosing-symbol`, `enclosing-parent`, or an AST-parent term.
  Rationale: The public value is an indexed semantic declaration rather than an arbitrary syntax-tree ancestor.
  Date/Author: 2026-07-13 / user and Codex

- Decision: `enclosing-decl` is inclusive and returns the smallest real declaration containing the exact seed range, including the declaration itself when it is the matched node.
  Rationale: Inclusive containment is useful for both expression and declaration seeds and avoids inventing a separate strict-parent operation.
  Date/Author: 2026-07-13 / user and Codex

- Decision: Schema version 2 keeps the top-level `match` pattern and adds an ordered `steps` array. RQL wrappers lower into that same IR.
  Rationale: This leaves the normalized syntax language intact while making semantic traversal explicit and statically typed.
  Date/Author: 2026-07-13 / user and Codex

- Decision: Replace the result object's `matches` array with a tagged `results` array whose variants are `structural_match`, `declaration`, and `file`.
  Rationale: A pipeline can terminate in different semantic domains, so the output must describe the actual value type rather than pretending every result is a syntax match.
  Date/Author: 2026-07-13 / user and Codex

- Decision: Remove the legacy Rust `matches` storage as well as its serialized form; existing Rust assertions use a typed `structural_matches()` view over `results`.
  Rationale: Schema v2 is an intentional clean break, and maintaining two result collections would create two sources of truth.
  Date/Author: 2026-07-13 / Codex

- Decision: Include minimal seed-and-step provenance in compact and full output; full output adds richer identity and range details.
  Rationale: Derived graph results need to remain explainable even under the default compact rendering.
  Date/Author: 2026-07-13 / user and Codex

- Decision: Import steps expose only direct, project-local file edges. Multi-hop traversal is expressed by repeating a step.
  Rationale: Direct edges compose predictably, keep the language primitive small, and avoid Ruby's usage-specific transitive reverse semantics.
  Date/Author: 2026-07-13 / Codex

- Decision: Validate step count and domain transitions through one shared IR validator used by both decoding and execution.
  Rationale: Public Rust callers can construct `CodeQuery` directly, so decoder-only validation left execution invariants vulnerable to panics.
  Date/Author: 2026-07-13 / Codex guided review

- Decision: Exhausting a pipeline budget before the terminal stage returns no intermediate-domain rows; exhausting it during the terminal stage may return the bounded partial terminal set.
  Rationale: Every serialized item must still satisfy the statically declared terminal result type, even when traversal is truncated.
  Date/Author: 2026-07-13 / Codex guided review

- Decision: Use the shared canonical byte-offset converter and cache indexed source, line starts, and declaration ranges for full provenance rendering.
  Rationale: CR, LF, and CRLF coordinates must agree everywhere, and provenance fan-out must not repeatedly clone and rescan the same source file.
  Date/Author: 2026-07-13 / Codex guided review

## Outcomes & Retrospective

The query IR, executor, public surface, and cookbook milestones are complete. Version-2 JSON and RQL steps validate into one ordered typed IR. Integration tests prove inclusive method declarations, full-detail stable identities, file deduplication, sixteen-trace provenance caps, direct Ruby forward/reverse edges, repeated multi-hop traversal, cycles, unsupported-provider diagnostics, terminal limits, and pipeline-budget truncation. Guided-review regressions additionally prove that truncated pipelines never serialize an intermediate result domain, synthetic nearest units fall through to the smallest real declaration, reverse traversal is governed by source providers, and declaration-free JavaScript/TypeScript/Go/C++ imports still produce direct file edges. The MCP schema, CLI and saved-query mode, Python models/client, and executable tutorial examples now agree on tagged `results`.

Final validation is green after the guided-review fixes: the focused pipeline suite passes 21 tests; the query-IR suite passes 34 tests; the render-cache and mixed-newline unit regressions pass; and 71 related import, documentation, tutorial, and cross-language tests pass. `scripts/test_python.sh` passes all 38 Python tests; `cargo clippy --all-targets --all-features -- -D warnings` passes; and every Rust unit and integration target passes with `--features nlp,python`. Because the local Cargo/Rustc installation lacks `rustdoc` and cannot consume the Homebrew toolchain's differently-versioned metadata, doctests were run separately with the Homebrew toolchain and the CI Rust feature set, `--doc --features nlp`; that gate also passes. No regex or text-search import fallback was introduced, all eight guided-review findings are fixed and verified, and no known issue-715 work remains.

## Context and Orientation

The query language lives in `src/analyzer/structural/query/`. `ir.rs` defines `CodeQuery` and syntax `Pattern` values, `decode.rs` validates canonical JSON, `json.rs` serializes the IR, and `sexp.rs` parses the RQL shorthand. Before this work the schema version was 1 and a query had one root syntax pattern plus filters such as `inside`, `where`, and `languages`.

`src/analyzer/structural/search.rs` executes a planned syntax query. It scans candidate files in deterministic order, produces internal pending matches, renders them into `CodeQueryMatch`, and returns `CodeQueryResult { matches, truncated, diagnostics }`. `src/analyzer/structural/planner.rs` selects source anchors and required structural capabilities. `src/searchtools_service.rs` connects decoding and execution to the public tool, and `src/mcp_extended.rs` publishes the JSON tool schema.

A `CodeUnit` is Bifrost's exact indexed identity for a declaration such as a class, function, field, or module. An analyzer can find the smallest `CodeUnit` containing a byte range. It also creates synthetic file-scope units internally; those are bookkeeping containers and must not be returned by `enclosing-decl`.

Language analyzers that support structured imports expose `ImportAnalysisProvider`. The provider can parse import information in bulk and resolve that information to imported files or imported `CodeUnit` values. `src/analyzer/usages/candidates.rs` demonstrates the required structured fallback sequence. Query traversal must use these structured APIs and must not scan source text or call reverse APIs whose contract is designed for transitive usage discovery.

The Python package in `bifrost_searchtools/` mirrors Rust result objects. Documentation lives under `docs/src/content/docs/`; `tests/code_query_docs.rs` validates marked examples and `tests/code_query_tutorials.rs` executes tutorial cases against inline fixture projects.

## Plan of Work

First, extend `src/analyzer/structural/query/ir.rs` with schema version 2, `QueryStep`, and the three value domains: structural match, declaration, and file. Add `steps` to `CodeQuery`. Update `decode.rs` to require version 2, accept an optional array of at most sixteen step objects containing only `op`, and validate the domain transition at each `steps[i]`. Update `json.rs` and `sexp.rs` so snake-case JSON operations and kebab-case RQL wrappers produce identical ordered IR. The legal transitions are `enclosing_decl` from a structural match, `file_of` from a structural match or declaration, and either import operation from a file.

Second, refactor `src/analyzer/structural/search.rs` around an internal typed row that owns an exact syntax seed, declaration `CodeUnit`, or `ProjectFile` plus bounded provenance traces. The syntax scan supplies seed rows. Each step consumes and produces only its declared domain, deduplicates by exact identity while preserving first-discovery order, and merges at most sixteen deterministic provenance traces. Apply the public `limit` only after the last step. Count seed rows and edge expansions against a 50,000-row pipeline budget; budget exhaustion makes the top-level result truncated and adds one diagnostic.

For `enclosing-decl`, ask the analyzer for the smallest declaration containing the seed's exact byte range. Accept the result when it is non-synthetic and not `FileScope`; otherwise emit no row. For `file-of`, retain the exact `ProjectFile` from the syntax seed or declaration source. For imports, build direct forward project-file edges using bulk `ImportInfo`, `imported_files_from_infos`, and the imported-code-unit fallback already used by usage candidate selection. Sort and deduplicate each adjacency list by normalized workspace-relative path. Build reverse edges by inverting those forward edges instead of calling `referencing_files_of`. Group unsupported-provider diagnostics by language and step while continuing supported rows; unresolved external packages are normal omissions.

Third, replace `CodeQueryResult.matches` with `results` and add tagged serialized variants. A structural match retains the existing fields plus `result_type: "structural_match"`. A declaration includes `result_type: "declaration"`, exact stable identity, fully qualified name, declaration kind, language, path, range, and optional signature. A file includes `result_type: "file"`, path, and language. Derived results include `provenance`, an array of traces containing a minimal seed reference and ordered `{ op, result }` step references, plus `provenance_truncated`. Compact traces contain identifying path/name/location data; full traces add stable IDs and precise ranges. Top-level `truncated` describes an incomplete terminal set, while provenance loss is reported per result.

Update the public MCP schema, CLI/RQL help and rendering, `bifrost_searchtools/client.py`, `bifrost_searchtools/models.py`, package exports, and Python README. The Python client accepts `steps: list[dict] | None`, parses the three tagged result dataclasses, exposes `CodeQueryResult.results`, and renders structural matches, declarations, and files without assuming every item has source text.

Finally, add inline-project integration coverage and update every schema-version marker and result example that is part of the public v1 surface. Add executable cookbook examples for `enclosing-decl`, `file-of`, `imports-of`, and `importers-of`, including repeated traversal. Keep the documentation concise but make each example assert a real result through the existing tutorial harness.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/b86e/bifrost` on the existing `715-add-typed-codequery-pipelines-and-import-graph-traversal` branch.

Implement and validate the query IR milestone with:

    cargo test analyzer::structural::query

Implement the executor and run its focused unit and integration tests. Discover the exact new integration-test target after adding the file with:

    cargo test --test <new-query-pipeline-test-target> --features nlp,python

Validate documentation examples and Python models with:

    cargo test --test code_query_docs --test code_query_tutorials --features nlp,python
    python -m unittest discover -s bifrost_searchtools/tests

Run repository gates from the same directory:

    cargo fmt
    cargo clippy --all-targets --all-features -- -D warnings
    cargo test --features nlp,python

Update this ExecPlan after each milestone and checkpoint the milestone by staging only the files changed for issue 715.

## Validation and Acceptance

A canonical version-2 JSON query without steps must still return syntax results, now tagged `structural_match`. A query matching a call and applying `enclosing_decl` must return its smallest real containing declaration, and matching that declaration directly must return the declaration itself. No result may expose a synthetic file scope.

Applying `file_of` to many matches in one file must return one file result with deterministic merged provenance. Applying `imports_of` must return only directly imported workspace files. Applying `importers_of` to C in a Ruby A-to-B-to-C fixture must return B after one hop and A after a repeated second hop; it must not jump directly to A. Repeated traversal across a cycle must terminate and return stable ordering.

Invalid pipelines must fail before execution with an error path naming the exact `steps[i]`. Unsupported language import providers must produce an aggregated diagnostic without suppressing results from supported languages. A terminal limit must be applied after deduplication, and exhausting the 50,000-row pipeline budget must set `truncated` with a diagnostic. More than sixteen provenance paths must preserve the first sixteen in deterministic order and set `provenance_truncated` on that result.

The MCP schema, Rust JSON, RQL, Python client, rendered text, and executable documentation must agree on schema version 2 and the tagged `results` shape. The focused tests, Clippy with warnings denied, and the full feature test suite must pass.

## Idempotence and Recovery

All source edits and tests are safe to repeat. Import graph construction is read-only and scoped to the analyzer's indexed workspace. If a milestone fails, inspect the focused test before advancing; do not mask missing structured analysis with source-text fallbacks. Checkpoint commits contain only issue-715 files, so a failed later milestone can be diagnosed without disturbing unrelated work.

## Artifacts and Notes

The canonical operation names are:

    JSON: enclosing_decl, file_of, imports_of, importers_of
    RQL:  enclosing-decl, file-of, imports-of, importers-of

The result domains and legal transitions are:

    structural_match --enclosing_decl--> declaration
    structural_match --file_of---------> file
    declaration      --file_of---------> file
    file             --imports_of------> file
    file             --importers_of----> file

Revision note (2026-07-13): Created the initial self-contained plan after confirming the issue branch and inspecting the current query, import-analysis, client, and documentation architecture.

Revision note (2026-07-13 10:42Z): Marked the typed IR and executor milestones complete, recorded the indexed-declaration boundary discovered by testing, and captured the passing focused integration evidence.

Revision note (2026-07-13 11:36Z): Marked the public API and executable cookbook milestones complete, recorded the clean removal of the legacy Rust `matches` collection, and captured the passing 114-test focused Rust matrix.

Revision note (2026-07-13): Completed repository-wide validation, documented the split local Rust toolchain required to run the full-feature unit/integration and doctest gates, fixed the final stale v1 service assertion, and closed the retrospective.

Revision note (2026-07-13): Reopened validation after the guided review, documented all eight findings and their fixes, and expanded focused coverage for pipeline invariants, import-edge completeness, graph bounds, source-coordinate consistency, and rendering efficiency.

Revision note (2026-07-13): Completed post-review validation and closed the retrospective with all eight findings applied and verified.

## Interfaces and Dependencies

The query IR must expose a serializable `QueryStep` enum and a `Vec<QueryStep>` on `CodeQuery`. The decoder owns static domain validation; execution must therefore never receive an ill-typed chain.

The executor must expose one `CodeQueryResult` containing `Vec<CodeQueryResultItem>`, where the item is a tagged enum or equivalent serialization-safe Rust representation. Internal pipeline values retain `CodeUnit` and `ProjectFile` rather than public strings. Provenance references use the same tagged domains but a bounded compact representation to avoid recursive full result objects.

No new third-party dependency is required. Use existing analyzer APIs, `ImportAnalysisProvider`, normalized project paths, serde/serde_json, and the current structural fact providers. Preserve cross-platform path handling through `Path`, `PathBuf`, and `ProjectFile`; convert to stable slash-separated workspace-relative strings only at the public serialization boundary.
