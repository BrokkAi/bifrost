# Deliver deterministic semantic-model authoring and review tools

This ExecPlan is a living document. Maintain it under `.agents/PLANS.md`. Keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` current.

## Purpose / Big Picture

After this work, a pack author can validate, lint, compile, inspect, and debug one semantic-model source through stable library and CLI contracts. The tools use the production schema, compiler, catalog, activation resolver, matcher, and overlay. A repository can opt in to reviewed rules under `.bifrost/semantic-models/`. The loader hashes exact content, rejects links and path escape, and never executes code.

The CLI will keep the existing `generate`, `verify`, and `install` release commands. It will add authoring commands with human output by default and versioned JSON through `--format json`. Invalid source, incompatible activation, unreliable conformance, and exhausted bounds return a nonzero status.

## Progress

- [x] (2026-08-04 10:18Z) Read `AGENTS.md` and `.agents/PLANS.md`, inspected the clean attached `master`, checked `BIFROST_MCP_RMCP=on`, and fetched origin.
- [x] (2026-08-04 10:18Z) Live-checked issue #1151 and confirmed prerequisites #1145, #1147, and #1148 are closed.
- [x] (2026-08-04 10:18Z) Inventoried the existing CLI, compiler, catalog, activation, matcher, overlay, schema, tests, and documentation.
- [x] (2026-08-04 10:42Z) Milestone 1: added canonical source inspection, semantic linting, deterministic artifact writing, and trusted workspace-rule discovery.
- [x] (2026-08-04 10:52Z) Milestone 2: added bounded installed and active pack inventory with activation evidence and provenance.
- [x] (2026-08-04 11:42Z) Milestone 3: added production-path match explanation, emission preview, bounded unmapped-site scanning, and golden conformance reports.
- [x] (2026-08-04 12:42Z) Milestone 4: extended the CLI and documentation, added end-to-end CLI tests, ran final checks, and completed review.

## Surprises & Discoveries

- Observation: The existing `bifrost-semantic-pack` binary is release-only tooling.
  Evidence: `crates/bifrost-semantic-packs/src/bin/bifrost-semantic-pack.rs` accepts only `generate`, `verify`, and `install`.

- Observation: Production rule matching and emission are private functions in the overlay module.
  Evidence: `generated_overlay_facts`, `rule_trigger_matches`, `rule_capture_values`, and `emit_rule_match` in `crates/bifrost-analysis/src/analyzer/semantic_model/overlay.rs` form one production path.

- Observation: Schema validation already finds duplicate record IDs and missing capture references. It does not supply author guidance for broad or currently inactive rules.
  Evidence: `validate.rs::Validator::rule` validates triggers, capture bindings, templates, and emissions. Runtime support still excludes resolved-owner, resolved-call, repeated-argument, and resolved-owner captures.

- Observation: One warm RMCP `get_symbol_sources` call took 10.051 seconds when two of five symbols were missing.
  Evidence: Bifrost issue #1565 records plugin 0.8.21, revision `16c2d2963`, exact arguments, and result.

- Observation: The attached branch is one commit behind `origin/master`.
  Evidence: `origin/master` adds policy work in commit `4fb436a91`; the user prohibited branch changes and rebases, so work remains on attached `master` at `16c2d2963`.

- Observation: Direct Clippy uses Homebrew `clippy-driver` with local wrappers and rejects artifacts made by the other Rust 1.96 installation.
  Evidence: focused tests pass, but direct Clippy reports E0514 for `cc`, `tree_sitter`, and other crates. Later Clippy checks must use the isolated-target helper.

- Observation: Normalized Java facts expose the test call as a `Call`, but the Rust fixture did not expose the tested macro invocation as one.
  Evidence: the structured scan finds `makeWidget()` through `RuleTrigger::MacroInvocation` in Java. It does not use source text to infer a Rust macro site.

- Observation: The local rustup compiler and Homebrew Clippy have the same Rust commit but different LLVM builds.
  Evidence: direct and initially isolated Clippy runs rejected metadata with E0514. Setting both `RUSTC` and `RUSTDOC` to the Homebrew toolchain in the isolated-target helper gives one compatible toolchain.

- Observation: The final code-smell policy run remains `finding` because the repository has existing unsuppressed fixture and baseline findings.
  Evidence: all 12 policies completed with no diagnostics. The run reported 287 findings and 93 unsuppressed findings. In changed code, one per-file read and two per-pack sorts remain. Each processes distinct data. A fourth new sort finding was corrected by caching each provider's ordered file list outside the selector loop.

## Decision Log

- Decision: Put reusable authoring contracts in `brokk-bifrost-analysis` and keep presentation in `brokk-bifrost-semantic-packs`.
  Rationale: Analysis owns the canonical schema, compiler, catalog, matcher, and overlay. The distribution crate already owns the CLI without changing the low-level dependency graph.
  Date/Author: 2026-08-04 / Codex

- Decision: Define the workspace contract as direct files under `.bifrost/semantic-models/` with explicit host opt-in.
  Rationale: The location is reviewable in Git. Direct-child discovery avoids hidden recursive scope. Canonical paths, regular-file checks, and exact content hashes enforce the trust boundary.
  Date/Author: 2026-08-04 / Codex

- Decision: Keep one matcher implementation and add structured trace data at its predicate boundaries.
  Rationale: A separate explanation evaluator could drift from production and give false match or miss reasons.
  Date/Author: 2026-08-04 / Codex

- Decision: Classify currently unsupported structured triggers or captures as unreachable lint findings.
  Rationale: The runtime deliberately fails closed for these forms. An author must see this before installation.
  Date/Author: 2026-08-04 / Codex

- Decision: Use featureless focused validation for routine milestones.
  Rationale: This work does not use semantic search, Python, or the NLP dependency stack.
  Date/Author: 2026-08-04 / Codex

- Decision: Make unmapped-site classification an explicit property of each structured selector.
  Rationale: Production normalized facts can identify a selected node shape. They cannot prove whether an arbitrary generator is safe to model. The host must classify known generator families without text heuristics.
  Date/Author: 2026-08-04 / Codex

- Decision: Keep analyzer-bound explanation, preview, scanning, and conformance as public library APIs.
  Rationale: Creating analyzers inside the pack distribution binary would add a second host and configuration path. The CLI owns source, catalog, and workspace operations that do not need an analyzer.
  Date/Author: 2026-08-04 / Codex

- Decision: Use one small version-one JSON activation input for the `list` command.
  Rationale: The input maps directly to production evidence and controls. It does not create a second activation model or infer evidence from installed packs.
  Date/Author: 2026-08-04 / Codex

## Outcomes & Retrospective

Issue #1151 is implemented with one canonical authoring and runtime path. The binary now supplies `validate`, `lint`, `compile`, `list`, and `workspace-check`. Analyzer hosts use public explanation, emission preview, bounded scan, and conformance APIs. All outputs have versioned JSON forms. Human output is the default. Exit status distinguishes success, authored findings, and invalid or incomplete input.

The workspace contract is `.bifrost/semantic-models/`. It is explicit and opt-in. It accepts direct reviewed YAML or JSON files only. It rejects links and path escape, enforces bounds, and reports exact source hashes. The host must register and activate accepted packs through the production catalog and runtime. It never executes or downloads code.

Focused semantic tests, 32 catalog tests, five semantic-pack crate tests, documentation fixture tests, package archive inventory, formatting, and diff checks pass. The final policy run completed without unreliable diagnostics. It corrected one new scan sort. Three remaining changed-file findings are reviewed per-item operations, not repeated invariant work. No #1151 acceptance criterion is deferred. The comprehensive NLP/Python gate was not justified because this change does not touch those features.

## Context and Orientation

`crates/bifrost-analysis/src/analyzer/semantic_model/model.rs` defines the version-one authored schema. `source.rs` safely parses YAML and JSON. `validate.rs` checks the complete typed model. `compiler.rs` normalizes it and writes canonical manifest and shard bytes in memory. `artifact.rs` defensively decodes those bytes.

`catalog/mod.rs` stores installed packs and source attribution. `runtime.rs` selects compatible candidates from complete activation evidence. It retains pack, source, selector, and matched-evidence data in `ResolvedActiveSemanticModels`. Exact workspace source and artifact facts have priority over modeled facts. Workspace-produced, installed, and shipped model precedence is already encoded in catalog and runtime source ranking.

`overlay.rs` converts active declaration facts into typed symbols and relations. It also evaluates generator rules against normalized `FileFacts`. It emits model URIs and provenance without fake source. This production evaluation path must become traceable, not duplicated.

`crates/bifrost-semantic-packs/src/bin/bifrost-semantic-pack.rs` is the existing binary. `release_bundle.rs` owns release generation, verification, and installation. New commands must extend this binary and preserve those commands.

The main semantic integration harness is `tests/suite_semantic/main.rs`. Small source projects use `tests/common/inline_project.rs::InlineTestProject`. Existing fixtures under `tests/fixtures/semantic-model-packs/` cover declarations, generator rules, procedure summaries, canonical artifacts, runtime activation, overlay projection, provenance, and summary binding.

## Plan of Work

Milestone 1 adds `authoring.rs` under the semantic-model module. It will expose versioned, serializable diagnostics and reports. `inspect_source` will call the existing safe parser and compiler. `lint_pack` will include compiler diagnostics and deterministic semantic findings for duplicate IDs, unsupported or shadow-equivalent rules, overlapping trigger selectors, unbound or unused captures, language-wide activation, broad language constructs, and emissions with the same identity but different typed content. Diagnostics have stable codes, severities, JSON paths, and messages. Deterministic artifact writing will write the compiler's canonical manifest and exact shard bytes through atomic temporary files.

The same milestone defines `WORKSPACE_SEMANTIC_MODEL_DIRECTORY` as `.bifrost/semantic-models`. `discover_workspace_semantic_models` accepts an explicit canonical workspace root. It reads only regular direct children with `.json`, `.yaml`, or `.yml` suffixes. It rejects symbolic links, non-UTF-8 relative names, path escape, source-byte excess, and duplicate resolved paths. Each result includes a slash-normalized workspace-relative path, SHA-256 of exact bytes, source format, and compiled semantic digest. Calling this function is the opt-in action. There is no ambient loading.

Milestone 2 adds a bounded catalog inventory method because current candidate lookup requires activation coordinates and cannot list all installed sources. The catalog query returns immutable manifest, shard, source, and active-set rows in stable precedence and identity order. A higher-level inventory projection can combine these rows with a `ResolvedActiveSemanticModels` value. Active rows include matched evidence, status, reason, source, provenance, completeness, and semantic hashes. It uses catalog SQL only during explicit inventory and never during AST matching.

Milestone 3 instruments the production overlay evaluator. A shared predicate evaluator returns capture values or the first failed predicate. Normal overlay construction consumes the same result without extra output. Public bounded functions explain one line-addressed site, preview typed emissions, and scan caller-selected structured generator trigger kinds. Scan results distinguish `model_eligible_generator` from `inspectable_source_macro`; they do not execute generators or use text search. Limits cover explanations, files, nodes, sites, and conformance assertions. Shadowing comes from the runtime match disposition and activation evidence comes from the resolved active shard.

Milestone 3 also adds a versioned conformance fixture and report. The runner uses the production overlay and asserts symbols, owners, signatures, hierarchy, relations, forward definitions, inverse usages, authored anchors or portable model URIs, provenance, completeness, positive matches, and negative matches. Fixtures identify source locations and expected stable fields. They do not copy complete implementation registries.

Milestone 4 adds CLI commands: `validate SOURCE`, `lint SOURCE`, `compile SOURCE OUTPUT`, `list CATALOG [ACTIVATION]`, `explain-match ...`, `show-emissions ...`, `scan-unmapped ...`, `conformance ...`, and `workspace-check WORKSPACE`. Commands that need an analyzer will use the normal workspace analyzer construction already used by the Bifrost one-shot CLI, or remain a documented library entry if that construction would add a parallel host path. All commands support stable human output and `--format json`. The process returns 0 only for complete valid results, 1 for authored findings or conformance mismatch, and 2 for invalid arguments, incompatible inputs, cancellation, or unreliable bounded execution.

Update `docs/src/content/docs/semantic-model-packs.md` and `crates/bifrost-semantic-packs/README.md`. Documentation will show a minimal rule, dependency-qualified activation, workspace override, conformance workflow, match debugging, exit codes, and trust limits. Add doc-fixture tests where examples must stay exact.

After each milestone, run `cargo fmt`, focused unit tests, the affected `suite_semantic` modules, and CLI/package tests. Review the diff and commit only milestone files with a multiline checkpoint message. At completion, run catalog, activation, overlay, semantic-model, CLI, docs, and package checks. Run featureless workspace Clippy if practical. Do not enable NLP because the changed surface does not use it.

Before completion, call Bifrost `list_policies`. Then run one `run_policy` request with `bifrost.code-smells`, evaluation date `2026-08-04`, and `fail_on: warning`. Repository records say there are no canonical executable repository policy roots, but verify this from current instructions. Treat `finding` as review work and `unreliable` as failure. Run the same selection after fixes.

## Concrete Steps

Work from `/Users/dave/Workspace/BrokkAi/bifrost` on the current attached branch.

For milestone 1, edit the semantic-model module and add focused tests:

    cargo fmt
    cargo test --test suite_semantic -- semantic_model_authoring

For milestone 2, run catalog and runtime tests:

    cargo test --test suite_persistence -- semantic_pack_catalog
    cargo test --test suite_semantic -- semantic_model_runtime

For milestone 3, run overlay, authoring, and conformance tests:

    cargo test --test suite_semantic -- semantic_model_overlay semantic_model_authoring semantic_model_conformance

For milestone 4, run the binary and package surface:

    cargo test -p brokk-bifrost-semantic-packs --features release-tooling
    cargo run -p brokk-bifrost-semantic-packs --features release-tooling --bin bifrost-semantic-pack -- validate tests/fixtures/semantic-model-packs/generator-rules-v1.yaml --format json
    scripts/check-workspace-packages.sh

Final validation includes:

    cargo fmt --all -- --check
    cargo test --test suite_semantic -- semantic_model_pack semantic_model_runtime semantic_model_overlay semantic_model_docs semantic_model_authoring semantic_model_conformance
    cargo test --test suite_persistence -- semantic_pack_catalog
    cargo test -p brokk-bifrost-semantic-packs --features release-tooling
    scripts/with-isolated-cargo-target.sh cargo clippy --workspace --all-targets -- -D warnings
    git diff --check

## Validation and Acceptance

Validation succeeds when the checked generator fixture validates and compiles twice to byte-identical outputs. A malformed fixture must return nonzero and versioned JSON diagnostics. Lint output must exercise every issue category with stable order.

Catalog inventory must show installed source attribution. When an activation request is supplied, it must show active, shadowed, incompatible, or disabled evidence from the production report. It must not infer activation from installation alone.

Match explanation must name the pack and rule, show matched activation evidence and captures, list typed emitted symbols and relations, show runtime shadowing, and identify the first failed structured predicate for a miss. Emission preview and conformance must use the same production evaluator.

Bounded scanning must stop at its configured limit and mark the result incomplete. It must label model-eligible generator sites separately from inspectable source macros. It must not scan text, execute code, or download content.

The workspace loader must accept reviewed direct files under `.bifrost/semantic-models/`. It must reject symbolic links and any resolved path outside the canonical workspace. A content edit must change the reported source hash. The compiler artifact format remains unchanged.

Golden conformance must prove symbols and owners, members and signatures, hierarchy and relationships, definitions and inverse usages, anchors or model URIs, provenance, completeness, and positive and negative matches.

## Idempotence and Recovery

Validation, lint, list, explain, scan, and conformance are read-only. Compilation writes to a caller-selected output directory through atomic replacement. Repeating it with the same input produces the same bytes. If writing fails, retry after removing only the incomplete caller-selected output. Do not remove catalog or workspace data.

Milestone commits make recovery explicit. Stage only files changed by the milestone. Do not push, rebase, switch branches, or open a pull request.

## Artifacts and Notes

Live GitHub state on 2026-08-04:

    #1151 open
    #1145 closed
    #1147 closed
    #1148 closed

Initial Git state:

    HEAD 16c2d2963715eb627bfa699792d4e5d1d46a8562 master
    origin/master 4fb436a91
    clean, attached, behind 1

RMCP latency evidence:

    get_symbol_sources: 10.051 seconds
    follow-up: https://github.com/BrokkAi/bifrost/issues/1565

## Interfaces and Dependencies

The semantic-model module will expose authoring report types that derive `Serialize` and have explicit format strings such as `bifrost_semantic_model_lint/v1`. APIs accept `AuthoredSemanticModelPack`, `CompiledSemanticModelPack`, `SemanticPackCatalog`, `ResolvedActiveSemanticModels`, `IAnalyzer`, `CancellationToken`, and explicit bounded option types. They do not accept executable callbacks for parsing or matching.

Workspace discovery uses `Path` and `PathBuf`, `std::fs::symlink_metadata`, `std::fs::canonicalize`, and `sha2`. Portable report paths use workspace-relative components and forward slashes only at the output boundary. It does not add a new parser, runtime artifact, or configuration language.

The CLI uses `serde_json` for machine output and the existing analysis APIs. It keeps `release-tooling` as the feature gate because the binary already requires it. No new NLP, Python, network, GUI, generator, or AI dependency is permitted.

Plan revision note (2026-08-04): Created the initial plan after live issue checks and production-surface inventory. The plan selects one shared matcher trace, an explicit `.bifrost/semantic-models/` trust boundary, and analysis-owned public contracts.

Plan revision note (2026-08-04): Completed milestone 1. Added exact validation and lint formats, the workspace trust boundary, idempotent artifact writes, test evidence, and the mixed-toolchain Clippy discovery.

Plan revision note (2026-08-04): Completed milestone 2. Added bounded catalog rows and a production-runtime inventory projection that reports matched evidence and activation explanations without treating installation as activation.

Plan revision note (2026-08-04): Completed milestone 3. Added shared production evaluation, explanation and preview reports, explicit structured scan selectors, and two golden conformance fixtures. Post-milestone review added fail-closed validation for missing preview captures and direct hierarchy and anchor coverage.

Plan revision note (2026-08-04): Completed milestone 4. Added stable CLI commands and activation input, end-to-end command tests, the workspace trust and debugging documentation, package checks, and final policy review. The policy review removed one repeated provider sort.
