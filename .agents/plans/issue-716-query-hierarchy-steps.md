# Add hierarchy and member traversal to query_code

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This plan is maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

After this change, a `query_code` structural match can be projected to its exact indexed declaration and then traversed through Bifrost's existing type hierarchy or declaration ownership graph. Users can ask for direct, depth-bounded, or transitive supertypes and subtypes, list a type's direct members, and recover a member's declaring type. Results remain restricted to declarations indexed by the workspace analyzer: observing a usage of library code does not imply that Bifrost can return the library declaration itself.

The feature is observable through JSON and RQL queries, exact tagged declaration results with provenance, schema-driven editor help, and executable recipes on every language cookbook page.

## Progress

- [x] (2026-07-14 07:56Z) Rebased the clean issue branch onto current `origin/master` and inspected the existing typed-pipeline, schema, execution, and documentation seams.
- [x] (2026-07-14 07:56Z) Created this self-contained ExecPlan with the agreed public syntax and milestones.
- [x] (2026-07-14 08:15Z) Milestone 1: added the configured public query IR, JSON/RQL syntax, declarative step-field registry, schema/help/MCP/grammar surfaces, CLI example, and parser/editor tests.
- [x] (2026-07-14 08:40Z) Milestone 2: implemented budgeted exact hierarchy/member execution, diagnostics, provenance, and focused integration tests.
- [x] (2026-07-14 10:30Z) Milestone 3: added executable examples for all four operations to all eleven language cookbooks and updated public reference documentation.
- [x] (2026-07-14 10:45Z) Milestone 4: ran the Rust and docs validation bundle, reviewed the full diff, tightened public help and validation ranges, added mixed-input coverage, and recorded the outcome.

## Surprises & Discoveries

- Observation: `MultiAnalyzer::supports_type_hierarchy` currently reports only whether a delegate exposes a hierarchy provider; it does not call the delegate provider's declaration-specific `supports_type_hierarchy` method.
  Evidence: `src/analyzer/multi_analyzer.rs` returns `.is_some()` after provider lookup.

- Observation: configured hierarchy steps make `QueryStep` non-`Copy`, while the existing executor and provenance structs currently copy each step by value.
  Evidence: `src/analyzer/structural/query/ir.rs` defines only four fieldless variants and `src/analyzer/structural/search.rs` iterates with `for (step_index, &step)`.

- Observation: invoking clippy against the shared target directory selects Homebrew's clippy driver while existing artifacts came from rustup's identically labelled 1.96 compiler, producing incompatible-crate errors despite matching release labels.
  Evidence: `which -a` reports `/opt/homebrew/bin/cargo-clippy` and `/opt/homebrew/bin/clippy-driver` ahead of rustup's binaries; focused tests pass, and final clippy validation must put the rustup toolchain first in `PATH` and use an isolated target directory.

- Observation: the in-app browser runtime could not initialize for the rendered-preview pass because its bootstrap attempted to redefine Node's `process` property.
  Evidence: both fresh initialization attempts failed with `Cannot redefine property: process`; the Astro check/build still passed, and generated HTML was inspected for the new navigation heading, examples, and precision-boundary text.

- Observation: macOS tests that link the Python feature require the same dynamic-lookup linker flags used by CI, and the sandbox cannot access uv's user cache for the sidecar smoke test.
  Evidence: the feature-focused and clippy gates passed with `RUSTFLAGS='-C link-arg=-undefined -C link-arg=dynamic_lookup'`; the complete suite progressed after an elevated rerun allowed the existing uv cache.

- Observation: the elevated complete-suite run suffered a single `SIGKILL` in `lsp_server_drop_cleanup_exits_cleanly_after_initialize` after 178 sibling LSP tests passed.
  Evidence: rerunning that exact test with the same features and linker flags passed 1/1, indicating resource pressure in the fully parallel integration run rather than a reproducible test failure.

## Decision Log

- Decision: retain CodeQuery schema version 2 and add named step options rather than introducing a new schema version.
  Rationale: this is an additive continuation of the typed version-2 pipeline introduced by issue #715, and old version-2 queries remain valid.
  Date/Author: 2026-07-14 / Codex

- Decision: represent traversal as public `HierarchyTraversal::{Direct, Depth(NonZeroUsize), Transitive}` values on `QueryStep::Supertypes` and `QueryStep::Subtypes`.
  Rationale: invalid zero depth cannot be constructed accidentally, while direct and transitive intent remain explicit.
  Date/Author: 2026-07-14 / Codex

- Decision: JSON uses optional `depth` or `transitive: true`; RQL uses `:depth N` or `:transitive true`. The options are mutually exclusive, and omission means one direct edge.
  Rationale: named options are self-describing in both syntaxes and leave room for future traversal controls without positional ambiguity.
  Date/Author: 2026-07-14 / Codex

- Decision: bounded depth returns all declarations reachable at distances one through N, not only declarations exactly N edges away.
  Rationale: users can repeat a direct step when they need exact-hop composition; a depth option naturally denotes a bounded closure.
  Date/Author: 2026-07-14 / Codex

- Decision: all semantic outputs must be exact members of `IAnalyzer::all_declarations` and have a renderable indexed range.
  Rationale: the feature must not manufacture library declarations from names or usages when the analyzer has not indexed those declarations.
  Date/Author: 2026-07-14 / Codex

## Outcomes & Retrospective

Milestone 1 now provides the complete public syntax without execution semantics. JSON and RQL canonicalize named hierarchy options identically, invalid configurations point to their exact fields, and the declarative registries drive help for the new forms and fields.

Milestone 2 projects semantic results through the analyzer's bulk indexed-declaration/range API and traverses hierarchy relations iteratively under the existing pipeline budget. Exact identity survives same-name declarations and overloads; path-local cycle guards retain diamond provenance; invalid input shapes are aggregated by operation and language while legitimate leaves and unindexed external declarations remain silent. The 28 focused pipeline tests and the existing Go, Rust, Ruby, and multi-analyzer hierarchy suites pass.

Milestone 3 adds two executable hierarchy/ownership recipes to every language cookbook, including exact declaration results and per-edge provenance. Bounded and transitive options are distributed across the languages, and a coverage assertion now prevents any cookbook from omitting one of the four operations. The overview, JSON/RQL references, CLI, MCP/Python client documentation, and package README explain direct/bounded/transitive semantics and the indexed-declarations-only precision boundary. Rust docs tests, Astro check, Astro build, and generated-HTML inspection pass.

Milestone 4's review synchronized the MCP description with the literal public operation names, narrowed the JSON depth/transitive conflict diagnostic to the `transitive` value, and added a mixed valid/invalid input regression proving that valid hierarchy rows survive an aggregated shape diagnostic. Formatting, the 71-test focused feature gate, all-target/all-feature clippy, Astro check, and Astro build pass. The complete feature suite was also exercised: its sandbox-only uv cache failure was cleared by rerunning with normal host cache access, then one highly parallel LSP test process was killed after 178 sibling tests passed; the exact failed test passed immediately in isolation. No compatibility shim, textual resolver fallback, duplicate schema vocabulary, or unrelated file change remains in the branch diff.

## Context and Orientation

`src/analyzer/structural/query/ir.rs` contains `CodeQuery`, the `QueryStep` enum, and static input/output-domain validation. `decode.rs`, `json.rs`, and `sexp.rs` translate public JSON and RQL into that IR. `schema.rs` is the declarative vocabulary authority, while `source.rs` uses the schema for validation ranges, hover text, and editor help. Visible RQL forms must also be added to `editors/vscode/syntaxes/bifrost-rql.tmLanguage.json`.

`src/analyzer/structural/search.rs` executes structural matching and then applies typed pipeline steps. A pipeline row contains a structural match, exact declaration, or file plus up to sixteen provenance traces. The executor already deduplicates terminal rows and counts produced candidates against `max_pipeline_rows`; hierarchy expansion must use the same budget and preserve the existing rule that a truncated nonterminal stage cannot be rendered as if it reached the validated final domain.

`src/analyzer/capabilities.rs` defines `TypeHierarchyProvider`, including direct ancestors, direct descendants, and transitive helpers. Concrete analyzers implement these relations. `src/analyzer/i_analyzer.rs` exposes exact `direct_children` and `parent_of` relations. `src/analyzer/multi_analyzer.rs` routes both capability and declaration operations to the language delegate that owns a `CodeUnit`.

An indexed declaration is a `CodeUnit` returned by `IAnalyzer::all_declarations`. The executor renders declarations with an exact analyzer range. A declaration mentioned by source or usage analysis but absent from that iterator is outside this milestone's precision boundary and must be omitted without a false capability diagnostic.

## Plan of Work

Milestone 1 changes the public query shape. Replace fieldless hierarchy-incompatible step handling with a configured `QueryStep` and `HierarchyTraversal`. Update static declaration-to-declaration domain validation, JSON decoding and canonical serialization, and RQL wrapper lowering. Add `supertypes`, `subtypes`, `members`, and `owner` to the declarative RQL registry, schema-driven source validation and hover descriptions, MCP JSON schema and operation lists, CLI help/examples, and the VS Code grammar. Tests must prove direct defaults, canonical depth/transitive forms, invalid option combinations, exact diagnostic ranges, and help/hover recognition.

Milestone 2 adds execution. Build one exact indexed-declaration lookup for semantic pipeline use. Convert hierarchy outputs to declaration values only when exact identity and a primary range exist. Traverse hierarchy edges iteratively in deterministic order, with a queue carrying accumulated edge provenance and a path-local visited set for cycle safety. Emit all nodes within a bounded depth or every reachable node in transitive mode. Count each examined candidate edge against the pipeline-row budget, deduplicate terminal values, and merge traces through the existing sixteen-trace cap.

For `members`, accept real type declarations and return real direct declaration children. For `owner`, accept declarations whose immediate exact parent is a real type and return that parent. This makes `owner` applied after `members` round-trip exactly. Invalid shapes or missing capabilities omit only affected rows and emit one deterministic diagnostic per language, operation, and reason. A supported hierarchy leaf with no edges emits no diagnostic. Change the default hierarchy eligibility to class-like declarations, explicitly support Ruby modules, preserve Go/Rust custom eligibility, and make `MultiAnalyzer` forward the delegate provider's eligibility result.

Milestone 3 extends each existing cookbook fixture with a small language-idiomatic hierarchy and executable JSON/RQL cases. Every page must visibly cover all four operations; composition such as `members(subtypes(...))` may cover two operations in one case. Spread depth-bounded and transitive examples across Python, Java, JavaScript, TypeScript, Go, C++, Rust, PHP, Scala, C#, and Ruby while keeping direct traversal observable everywhere. Update the overview and JSON/RQL references, MCP/Python-client descriptions, and tutorial index with the indexed-declarations-only boundary.

Milestone 4 runs formatting, focused tests, full clippy and feature-complete tests, and Astro validation. Review the complete diff for accidental text parsing, name-based fallback, duplicate schema tables, missing public operation lists, and unrelated changes. Fix findings, update this plan, and commit the final reviewed state if needed.

## Concrete Steps

All commands run from `/Users/dave/.codex/worktrees/0fca/bifrost`.

After each implementation milestone, run its focused tests, inspect `git diff --check` and `git diff`, update this ExecPlan, stage only files changed for the milestone, and create a multiline checkpoint commit explaining both behavior and rationale. Do not push or open a pull request.

At final validation run:

    cargo fmt
    cargo test --features nlp,python --test code_query_pipelines --test code_query_tutorials --test code_query_docs --test bifrost_tool_cli
    cargo clippy --all-targets --all-features -- -D warnings
    cargo test --features nlp,python
    npm --prefix docs run check
    npm --prefix docs run build

## Validation and Acceptance

Parser tests must demonstrate the four new operations and both traversal options round-trip identically from JSON and RQL. Invalid fields, zero depth, false transitive mode, mutually exclusive traversal options, and non-declaration pipeline domains must fail at the exact relevant source range.

Pipeline tests must demonstrate direct, depth-bounded, and transitive hierarchy results; iterative cycle termination; diamond-path provenance aggregation; exact same-name and overload identity; deterministic ordering; capability and shape diagnostics; partial mixed-input success; terminal and nonterminal budget exhaustion; direct member/owner round-trips; and omission of an unavailable library declaration.

Every cookbook page must continue to pass `tests/code_query_tutorials.rs`, proving that its JSON and RQL queries canonicalize identically and return exact expected results. Reference examples and all public operation enumerations must remain synchronized. All final validation commands must pass without ignore annotations or reduced feature coverage.

## Idempotence and Recovery

Parser, tests, and documentation edits are repeatable. Hierarchy traversal reads analyzer state and does not mutate the workspace. If a milestone fails, retain the working tree, update `Progress` with the exact completed and remaining work, and rerun only the failed focused command after fixing the root cause. Commits are checkpoint boundaries; do not reset or discard unrelated user changes.

## Artifacts and Notes

The branch started from `fc9bfcf9`, current `origin/master`, after a clean rebase on 2026-07-14. The Bifrost MCP code-intelligence endpoints were not exposed during planning, so source orientation used `rg` and direct reads; retry the structured tools when available before falling back.

## Interfaces and Dependencies

In `src/analyzer/structural/query/ir.rs`, expose:

    pub enum HierarchyTraversal {
        Direct,
        Depth(NonZeroUsize),
        Transitive,
    }

    pub enum QueryStep {
        EnclosingDecl,
        FileOf,
        ImportsOf,
        ImportersOf,
        Supertypes(HierarchyTraversal),
        Subtypes(HierarchyTraversal),
        Members,
        Owner,
    }

The serialized JSON step objects are exactly `{ "op": "supertypes" }`, `{ "op": "supertypes", "depth": N }`, or `{ "op": "supertypes", "transitive": true }`, with the equivalent forms for `subtypes`. `members` and `owner` accept only `op`. No compatibility alias or secondary keyword registry is added.

Revision note (2026-07-14 07:56Z): Created the initial implementation-ready plan from issue #716, the approved implementation plan, and current repository structure.

Revision note (2026-07-14 08:15Z): Marked the public-syntax milestone complete after adding configured IR, shared schema metadata, MCP/editor/CLI surfaces, and passing 53 focused query parser/source tests plus the MCP schema test.

Revision note (2026-07-14 08:40Z): Marked execution milestone complete after reviewing exact projection, replacing per-declaration range lookups with the bulk primary-range API, and passing focused pipeline and hierarchy-provider suites.

Revision note (2026-07-14 10:30Z): Marked the documentation milestone complete after executing all JSON/RQL cookbook recipes, recording exact provenance-bearing outputs, updating public references and clients, and validating the rendered static site.

Revision note (2026-07-14 10:45Z): Completed final review and validation, including precise conflict ranges, synchronized MCP operation help, mixed-input execution coverage, and documentation of the one non-reproducible parallel-suite `SIGKILL`.
