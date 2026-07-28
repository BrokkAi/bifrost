# Ship the first built-in code-smell policy pack

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document is maintained in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

After this change, an installed Bifrost binary can list and run a release-bundled `bifrost.code-smells` policy pack without downloading files or having a Bifrost checkout. The first pack contains twelve reviewed `.rqlp` policies for conventional correctness and performance smells, with explicit language and capability scope, deterministic identities, positive and realistic near-miss fixtures, and the same canonical report through the command line and MCP.

The work also turns policy dogfooding into a durable maintenance practice. `AGENTS.md` will require agents to consider a structured RQL policy whenever review exposes a recurring smell, to add behavior-focused positive and negative coverage when a rule is viable, and to file or link a minimized issue instead of using source-text workarounds when RQL or an analyzer cannot express the rule. The same guidance treats Bifrost plugin calls over five seconds as performance defects and supports a daily active-development release cadence with small releasable increments.

## Progress

- [x] (2026-07-28 07:10Z) Fetched `origin`, confirmed the existing issue branch is clean and exactly aligned with `origin/master`, and read live issue #1204 plus related issues #824, #1205, #1207, #1228, and #1071.
- [x] (2026-07-28 07:10Z) Confirmed the shared policy coordinator, schema-2 report, durable suppression path, explicit-file CLI, and explicit-file MCP runner are already present on `master`.
- [x] (2026-07-28 07:10Z) Confirmed open #1228 already covers current-plugin calls exceeding five seconds; observed a six-pattern `search_symbols` call taking 35.241 seconds and an exact `get_symbol_sources` call taking 18.220 seconds after the slow search.
- [ ] Add the embedded pack manifest, source catalog, selection model, and mixed workspace/embedded coordinator inputs.
- [ ] Add twelve reviewed `.rqlp` policies and one reusable multi-language fixture corpus with a positive and near miss for every claimed language/rule pair.
- [ ] Add deterministic CLI listing plus pack/category/policy selection, including mixed built-in and workspace batches.
- [ ] Add MCP `list_policies` and extend `run_policy` with the same selectors while preserving active-snapshot, suppression, cancellation, and canonical-report behavior.
- [ ] Extend crate/release smoke validation to prove the manifest and sources are shipped and executable from an installed artifact.
- [ ] Document the code-review workflow and update root `AGENTS.md` with the durable rule-authoring, gap-filing, latency, and release-cadence protocol.
- [ ] Profile the structural selectors on a pinned repository snapshot, record findings/near misses honestly, and link any uncovered capability gaps to existing or new focused issues.
- [ ] Run formatting, focused tests, the full all-feature Clippy gate, relevant integration suites, package smoke, and specialist review; fix all confirmed release blockers.

## Surprises & Discoveries

- Observation: `run_policy` is already part of the current extended MCP toolset because #1207 landed after #1204 was written.
  Evidence: `src/mcp_extended.rs` registers `run_policy`, `src/searchtools_service.rs` prepares it against an immutable workspace snapshot, and `tests/bifrost_mcp_server.rs` proves suppression and active-root behavior.

- Observation: match policies deliberately reject analysis-only terminal domains such as procedures, program points, control edges, typestate findings, typestate witnesses, and receiver-analysis rows.
  Evidence: `evaluate_match_query_candidates()` in `src/analyzer/policy/evaluator.rs` returns `InvalidExecutionPlan` for those domains. Projecting them through `file_of` is legal but usually too coarse to make a release-quality code-smell finding.

- Observation: public schema version 4 still does not expose the value-flow client; receiver `points_to` is structured receiver provenance, not general local or interprocedural data flow.
  Evidence: the CodeQuery documentation says schema v4 adds registered typestate to schema v3 CFG while value-flow and taint remain outside the public query surface. Open #824 owns this exposure and #1205 owns the source-backed conformance gate.

- Observation: current plugin latency remains well above the desired five-second interaction budget for ordinary bounded navigation calls.
  Evidence: this session observed 35.241 seconds for one six-pattern `search_symbols` request and 18.220 seconds for an exact four-symbol source request queued after it. Open #1228 already records the same class of head-of-line blocking and common-query latency regression.

## Decision Log

- Decision: Keep work on the already-checked-out `1204-epic-ship-a-built-in-rqlp-code-smell-and-performance-policy-pack` branch.
  Rationale: Repository instructions prohibit creating or switching branches without an explicit request, and the current branch is clean and synchronized with `origin/master`.
  Date/Author: 2026-07-28 / Codex

- Decision: Store canonical rules as checked-in `.rqlp` files beneath `policy-packs/bifrost.code-smells/` and embed them into the binary at compile time.
  Rationale: This keeps rules human-reviewable and offline while making the installed binary independent of a repository checkout. A checked-in JSON manifest records pack metadata; Rust only supplies the compile-time inclusion bridge and validates that the embedded set exactly matches the manifest.
  Date/Author: 2026-07-28 / Codex

- Decision: Introduce one owned policy-input model shared by file-backed and embedded sources, then route both through the existing coordinator.
  Rationale: Built-ins must reuse policy parsing, semantic hashes, duplicate-ID handling, suppression, reporting, budgets, cancellation, and failure semantics. A parallel built-in evaluator would drift and violate the issue intent.
  Date/Author: 2026-07-28 / Codex

- Decision: The first pack will contain twelve structured matcher policies: dynamic evaluation, unsafe deserialization, sorting in loops, regular-expression compilation in loops, file reads in loops, serialization in loops, parsing in loops, database calls in loops, network calls in loops, subprocess calls in loops, sleeps in loops, and expensive operations in nested loops.
  Rationale: These are review-relevant and expressible using normalized kinds, roles, lexical containment, descendants, language filters, and exact structured names. The inventory avoids source-text parsing and documents API-specific scope where required.
  Date/Author: 2026-07-28 / Codex

- Decision: Do not pretend the current pack has meaningful CFG or value-flow rules merely by projecting analysis rows to files.
  Rationale: Such findings would be file-level and could not express the semantic predicate that makes the smell actionable. Open #824 and #1205 already own the missing typed exposure and readiness work; this plan will link exact minimized gaps discovered during authoring and keep engine work out of rule changes.
  Date/Author: 2026-07-28 / Codex

- Decision: Interpret the requested daily release cadence as a repository practice and release-readiness requirement, not authorization to auto-increment versions, create tags, or publish packages from this branch.
  Rationale: The current release pipeline is tag- and version-gated across several privileged publishers. Automatic daily versioning is a separate externally mutating design choice. This branch will keep every milestone releasable and extend package smoke so a daily release can safely include the pack.
  Date/Author: 2026-07-28 / Codex

## Outcomes & Retrospective

Implementation is in progress. At completion this section will compare the shipped catalog, host parity, package proof, profiling evidence, and linked follow-ups against the purpose above.

## Context and Orientation

RQL is Bifrost's S-expression frontend for the typed `CodeQuery` engine. An `.rqlp` file wraps an RQL selector with stable policy identity, severity, message, description, tags, reporting behavior, and optional richer analysis configuration. Raw queries are diagnostic-neutral; a match policy turns structured query results into `PolicyFinding` values with stable anchors and canonical reporting.

The policy model lives under `src/analyzer/policy/`. `definition.rs` defines policy syntax and metadata. `source.rs` parses `.rqlp`. `registry.rs` loads and hashes policies. `coordinator.rs` accepts requested policy inputs, builds or reuses a workspace analyzer, evaluates policies, joins suppressions, and constructs one canonical `PolicyReportDocument`. `evaluator.rs` runs match selectors through `CodeQuery` and projects exact results into findings. `report.rs` and `render/` provide canonical JSON, human output, and SARIF.

`src/bin/bifrost.rs` implements the manual CLI argument parser. Policy mode currently requires one or more `--policy-file` values. `src/mcp_extended.rs` declares the extended MCP tool schemas. `src/mcp_common.rs` dispatches MCP calls, and `src/searchtools_service.rs` prepares `run_policy` against the active immutable workspace snapshot. These surfaces must use the same selection and coordinator APIs so their policy IDs, semantic hashes, findings, completion, and suppression outcomes are identical.

The new directory `policy-packs/bifrost.code-smells/` will contain `manifest.json` and a `policies/` subdirectory. The manifest schema is repository-owned and versioned. It records pack identity and version, then each policy's source path, policy ID, semantic hash, category, supported languages, required query capabilities, severity rationale, and remediation. `src/analyzer/policy/builtin.rs` will embed and validate this material, expose the manifest for listing, and select a deterministic union of policies by pack, category, or exact policy ID.

Tests should use `tests/common/inline_project.rs` unless a reusable multi-file corpus is clearer. The catalog needs at least one cross-language rule that runs unchanged across Python, Java, and TypeScript. Positive and near-miss source examples must exercise production analyzers. Assertions must inspect canonical policy/run/finding behavior rather than duplicating manifest construction order as an implementation detail.

## Plan of Work

First add `src/analyzer/policy/builtin.rs`, the pack directory, manifest, and twelve source files. Define serializable manifest structures and a bounded validation error. Embed each source with `include_str!`, require the embedded path set to equal the manifest path set, load all sources through an in-memory `PolicyRegistry`, and verify every manifest policy ID and semantic hash against the parsed policy. Selection is a union: any selected pack, category, or policy contributes its matching entries, duplicates collapse, and final order follows manifest order. Unknown selectors are errors, and an empty selector set yields no built-in inputs.

Next refactor `src/analyzer/policy/coordinator.rs` to expose an owned `PolicyEvaluationInput` that can be a workspace-relative file or an embedded source identity plus source bytes. Keep `evaluate_policy_files()` and `evaluate_policy_files_with_analyzer()` as compatibility wrappers. Add mixed-input counterparts and rename the current private prepared-input function so there is no ambiguous API. The shared batch budget counts every selected embedded or file-backed policy. Duplicate policy IDs across built-ins and workspace files produce the same canonical diagnostics as duplicate workspace files.

Then extend `src/bin/bifrost.rs`. Add `--list-policies`, `--policy-pack ID`, `--policy-category ID`, and `--policy-id ID`; keep `--policy-file` repeatable. Listing prints the deterministic manifest without constructing a workspace analyzer. Execution requires at least one file or built-in selector, resolves all selectors before analysis, and runs one mixed batch. Existing human/JSON/SARIF, suppression, fail threshold, output, color, verbose, and explicit-schema behavior stays unchanged.

Extend MCP in `src/mcp_extended.rs`, `src/mcp_common.rs`, and `src/searchtools_service.rs`. Register a read-only `list_policies` tool that returns the manifest. Let `run_policy` accept optional bounded arrays named `policy_files`, `policy_packs`, `policy_categories`, and `policy_ids`, while still requiring `evaluation_date` and at least one policy source after resolution. Preparation resolves selectors and captures the active workspace snapshot; execution passes mixed inputs through the same coordinator and retains current cancellation behavior. Update `EXTENDED_TOOL_NAMES`, toolset expectations, and documentation.

Build the rule corpus with normalized structural queries only. Prefer exact names and explicit language/receiver constraints. Use structured `inside` and `has` for loop relationships. Do not use `text/regex`, source scanning, delimiter parsing, or private engine workarounds. Name regex is allowed only when the policy itself documents a finite API family and exact branches would be unreadable; exact names are preferred. Every policy pins policy schema version 1 and RQL schema version 2 because this first wave is intentionally structural.

Add integration coverage in `tests/builtin_policy_pack.rs`, `tests/bifrost_policy_cli.rs`, and `tests/bifrost_mcp_server.rs`. The pack test builds one inferred-language inline workspace and reuses its `WorkspaceAnalyzer`; every selected policy must produce the expected positive finding and no finding for its near miss in each claimed language. Additional assertions cover semantic-hash validation, unknown selection, deterministic mixed input, CLI list and selection, MCP list and selection, canonical CLI/MCP identity parity, incomplete results, and duplicate IDs.

Extend `scripts/check-crate-package.sh` to require the manifest and every canonical `.rqlp` source in the crate archive. Extend packaged binary or plugin smoke coverage to invoke `--list-policies` and run one built-in policy against a disposable workspace, proving release artifacts do not rely on checkout files or network access.

Finally update `docs/src/content/docs/static-analysis-policies.md`, `docs/src/content/docs/cli.md`, `docs/src/content/docs/mcp.md`, and root `AGENTS.md`. Document explicit selection, mixed batches, suppression behavior, rule metadata, and the review-to-policy lifecycle. Record the exact #824/#1205 gap rather than claiming CFG/data-flow coverage. Add the observed latency evidence to #1228 if it adds a distinct reproduction. Keep release-related edits limited to smoke/readiness and durable guidance; do not create a tag or publish a release without a separate explicit instruction.

## Concrete Steps

Run all commands from `/Users/dave/.codex/worktrees/fd62/bifrost`.

After the manifest and rules exist, format and run the catalog tests:

    cargo fmt
    scripts/with-isolated-cargo-target.sh cargo test --test builtin_policy_pack

After CLI and MCP integration:

    scripts/with-isolated-cargo-target.sh cargo test --test bifrost_policy_cli
    scripts/with-isolated-cargo-target.sh cargo test --test bifrost_mcp_server

Exercise the user-visible surface with a disposable workspace and the locally built binary. Expected listing contains pack `bifrost.code-smells` and twelve policies; the selected policy run emits one canonical schema-2 report:

    target/debug/bifrost --list-policies
    target/debug/bifrost --root /absolute/path/to/smoke --policy-id bifrost.correctness.dynamic-evaluation --evaluation-date 2026-07-28 --format json --fail-on never

Run package validation and inspect the archive for the pack:

    scripts/with-isolated-cargo-target.sh scripts/check-crate-package.sh

Run the core Rust gates required by repository instructions:

    cargo fmt --check
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python

The complete suite can be long. Keep the plan updated with exact focused and full-suite results, failures, and reruns. Do not use manually named temporary Cargo target directories.

## Validation and Acceptance

The implementation is accepted when `bifrost --list-policies` succeeds from an installed/package-built binary and lists one versioned `bifrost.code-smells` pack with twelve policies and verified semantic hashes. No checkout-relative read occurs during listing or built-in execution.

Running the full pack, one category, one policy, and a mixed built-in/workspace batch must be possible through the CLI. The MCP tools must list the same manifest and run the same selections against the active immutable workspace. For one pinned fixture, CLI and MCP canonical reports must contain equal rule IDs, policy hashes, finding IDs, primary locations, completion states, and suppression outcomes.

Every rule must have an actionable message and description, explicit category/language/capability/remediation metadata, a production-analyzer positive fixture, and a realistic near miss. The cross-language sort-in-loop policy must run unchanged and find only the intended call in Python, Java, and TypeScript fixtures. Unsupported or incomplete analysis must remain visible and must not become a complete clean result.

The crate package test must prove the manifest and all source policies are present. A packaged-binary smoke must list and execute a built-in rule offline. `cargo fmt --check`, all-target/all-feature Clippy with warnings denied, and the all-feature test gate must pass or have an exact documented external blocker.

The final review must contain no untriaged critical or high findings. Every discovered RQL/analyzer capability gap must link to an existing issue or a new minimized follow-up. Every Bifrost plugin call over five seconds must likewise be covered; this session's observations are already within #1228.

## Idempotence and Recovery

Manifest loading and selection are read-only and deterministic. Repeating listing or policy evaluation does not modify the workspace except for normal analyzer cache behavior under `.bifrost/cache/`. Tests use temporary workspaces and the isolated Cargo-target helper, which cleans managed targets on success, failure, or interruption.

If a manifest hash changes after an intentional policy edit, regenerate it by evaluating the checked-in source through the same policy registry, review the semantic diff, and update only that manifest entry. A hash mismatch is a hard validation error; never silently accept it.

If a rule produces excessive false positives, narrow or remove it and update its fixtures and manifest. Do not repair it with source-text scanning. If the structured capability is missing, keep the rule out of the shipped selection and file/link a focused issue with a minimal fixture and RQL reproducer.

Milestone commits stage only files changed for that milestone. Do not use `git add -A`. If a later milestone fails, retain prior validated commits and update `Progress` with the exact remaining work rather than rewriting unrelated history.

## Artifacts and Notes

Live baseline at plan creation:

    branch: 1204-epic-ship-a-built-in-rqlp-code-smell-and-performance-policy-pack
    HEAD: b60688de
    origin/master: b60688de
    worktree: clean

Relevant open issues:

    #824  typed CFG, flow, taint, and typestate query/policy exposure
    #1205 source-backed cross-language value-flow conformance gate
    #1228 sub-five-second common code-intelligence latency and cancellation

Related completed foundation:

    #709  policy envelope, matching, reporting
    #1207 / #1217 durable suppressions, tracked .bifrost layout, MCP run_policy

## Interfaces and Dependencies

In `src/analyzer/policy/coordinator.rs`, define an owned input type equivalent to:

    pub enum PolicyEvaluationInput {
        WorkspaceFile(PathBuf),
        Embedded {
            identity: PolicySourceIdentity,
            source: String,
        },
    }

Expose mixed-input evaluation functions for caller-built and supplied `WorkspaceAnalyzer` cases. Compatibility file-only functions delegate to them.

In `src/analyzer/policy/builtin.rs`, expose serializable manifest values, a deterministic catalog loader, and selection by pack/category/policy. The exact names may be refined during implementation, but callers must not need to know source filenames or duplicate the manifest.

`RunPolicyParams` in `src/searchtools_service.rs` gains defaulted bounded arrays for packs, categories, and policy IDs. `PreparedRunPolicy` owns the fully resolved `Vec<PolicyEvaluationInput>` so the execution phase cannot observe manifest drift.

The implementation uses existing `serde`, `serde_json`, policy registries, analyzers, coordinator budgets, cancellation tokens, and report types. It adds no network dependency and no alternate query or policy engine.

Revision note (2026-07-28): Initial plan created after reconciling live issue, repository, related-issue, and plugin-latency state. The plan deliberately ships a structural first pack and links semantic-rule gaps to #824/#1205 instead of manufacturing file-level CFG/data-flow findings.
