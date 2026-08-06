# ASD-STE100 Simplified Technical English

Always respond using ASD-STE100 Simplified Technical English. It is a controlled writing standard. Aerospace and defense groups made it. It helps people write clear technical text.

Key rules:
- **Use approved words only.** The standard gives a word list. Each word has one meaning.
- **Use one word for one idea.** Do not use two words for the same thing.
- **Write short sentences.** Use 20 words or less for instructions.
- **Use active voice.** Write "Turn the switch", not "The switch must be turned".
- **Write short paragraphs.** Keep one topic in each paragraph.

# ExecPlans

Use an ExecPlan for a complex feature or a significant refactor. Follow `.agents/PLANS.md` from design through implementation.

Use `.agents/` as the only repository namespace for planning and design artifacts that agents own. Do not create `.agent/`.

Store each ExecPlan in `.agents/plans/`.

Keep `.agents/PLANS.md` as the standard for ExecPlans. Do not store individual ExecPlans next to `.agents/PLANS.md`.

Store design notes for LLMs or agents in `.agents/docs/`. These notes can include agent context, publication runbooks, parity notes, and similar internal information. Do not publish these notes as product documentation.

Reserve `docs/` for future documentation for human readers. Do not store ExecPlans, agent runbooks, or LLM-only context in `docs/`.

# Git / version control

Commit directly to the current branch. This rule also applies when the current branch is `master`.

Do not create a branch, change branches, rebase, or open a pull request unless the user gives an explicit instruction.

Do not run `git checkout -b`.

The instruction "commit" means that you must commit on the current branch. It does not mean that you must create a branch first. This rule overrides other default branch procedures.

Stage and commit only the files that you changed. Do not run `git add -A`. Do not include unrelated working-tree changes in the commit.

# Expectations

Continue when there is a clear next step toward the goal. This rule applies inside and outside an ExecPlan. Do not stop to ask for approval.

If you made material progress, first make a multiline checkpoint commit. Explain the work to this point. Give detailed reasons for the changes. The diff shows the changes themselves.

# Release tasks

For release preparation, tagging, publication, recovery, and version policy, follow the canonical [Release Process](CONTRIBUTING.md#release-process) and [Version Policy](CONTRIBUTING.md#version-policy) in `CONTRIBUTING.md`. A release task still requires explicit user authorization for version changes, tags, publication, or deployment.

# Crate dependency boundaries

Do not create a new workspace crate only to reorganize code. Create one only
when a clear dependency, compilation, publication, or ownership boundary
requires it. Record the reason in the change that adds the crate.

When a change adds a publishable crate, update the release crate inventory in
`CONTRIBUTING.md`. Bootstrap the crate on crates.io before the next version
release. Configure its trusted publisher at the same time.

## Do not reintroduce the nlp dependency stack into brokk-bifrost-analysis

Issue #1548 prevents a change to the `nlp` feature from invalidating the largest workspace compilation unit.

`scripts/check-workspace-dependencies.mjs` enforces this rule. It prohibits these dependencies in `brokk-bifrost-analysis` and `brokk-bifrost-core`:

- `hf-hub`
- `tokenizers`
- `fastrq`

If a change needs one of these dependencies, put the code in `brokk-bifrost-nlp`. Do not relax the dependency check.

## Keep brokk-bifrost-core at the bottom of the graph

Issue #1549 prevents the analyzer model layer from being recompiled as part of the largest workspace unit.

To keep this result, `brokk-bifrost-core` must not depend on another Bifrost crate.

`scripts/check-workspace-dependencies.mjs` gives `brokk-bifrost-core` an empty allowed-dependency set. Its unit test rejects a `core -> analysis` dependency.

Put code in `brokk-bifrost-analysis` when the code needs one or more of these items:

- An `IAnalyzer`
- A store
- A grammar
- A language module

Do not move such code to `brokk-bifrost-core`, even when the move appears convenient.

`analyzer/capabilities.rs` is the standard example. It remains in analysis because `TypeHierarchyProvider::get_polymorphic_matches` and `build_direct_descendant_index` are generic over `IAnalyzer`.

# Analyzer Test Guidance

When you add or refactor analyzer tests for small temporary projects, use the shared inline test harness in `tests/common/inline_project.rs`. Do not use a hand-written `tempdir` and `ProjectFile::write(...)` setup unless it is necessary.

Use `InlineTestProject` by default when a test defines a small number of files inline.

`InlineTestProject` does these tasks:

- It manages the temporary root automatically.
- It hides absolute-path handling.
- It can infer analyzer languages from file extensions.
- It can accept an explicit language for a single-language test.

Use hand-written fixture directories or custom setup only when the test needs one of these items:

- A large reusable corpus
- File-system behavior that is difficult to express inline

Do not add low-value tests that only copy implementation lists. For example, do not assert each registry or toolset expansion in exact name order unless that order or membership is part of the user-visible contract that changes.

Prefer behavior tests that prove the advertised interface works from start to finish. For example, list a tool and call it successfully. Do not duplicate registry construction logic in tests.

Put each new integration test in `tests/<suite>/<name>.rs`. Add one `mod <name>;` line to that harness's `main.rs`.

The file `.agents/docs/test-harness-consolidation-2026-07.md` lists the suites and their members.

Do not add a new `tests/*.rs` file at the root.

Use a new standalone `tests/*.rs` binary only when the test needs process isolation. Examples include these conditions:

- Process-global counters
- Environment changes in the process
- Clean rayon state
- Clean `OnceLock` state that concurrent in-process tests can change

For each standalone test binary, add a keep-separate entry to the manifest. Explain the reason in that entry.

# Rust CI Checks

Before you push Rust changes, run the main CI checks locally when practical.

For the full pre-push gate, use `scripts/pre-push-gate.sh` from #1454.

The script does these tasks:

- It runs fmt.
- It runs the featureless workspace test suites with cargo-nextest.
- It uses one cross-binary scheduler.
- It applies the per-test slow timeout in `.config/nextest.toml`.
- It identifies and stops a test that does not complete.
- It runs doctests because nextest does not run doctests.
- It runs all-features clippy in an isolated target.
- It runs clippy at the same time as the tests, not after the tests.

Install `cargo-nextest` before you use the script:

    cargo install cargo-nextest --locked

Use the individual commands below for focused validation of a specific task.

Do not enable `nlp` for routine task validation unless one of these conditions is true:

- The change affects semantic search or NLP.
- The user explicitly requests the comprehensive gate.
- You are running an actual pre-push, merge, or release gate.

An NLP build can use tens of GiB in each worktree. Concurrent NLP builds in multiple worktrees can fill the host disk.

For a change that is not related to NLP, run focused featureless Rust tests. Add `--features python` only when the Rust Python interface needs test coverage.

An ExecPlan does not by itself require an NLP build. A code-review request does not by itself require an NLP build.

For a pre-push gate, run at least these commands:

    cargo fmt
    cargo clippy --workspace --all-targets --all-features -- -D warnings

You must include `--workspace`.

The root manifest sets `default-members = ["."]`. Without `--workspace`, clippy lints only the facade package. It compiles the `crates/*` members as dependencies, but it does not lint their `#[cfg(test)]` unit-test targets.

A broken crate test module can therefore pass. On 2026-08-02, an E0599 probe showed this difference. The command without `--workspace` did not find the error. The command with `--workspace` found it.

There is no compile-time GPU backend. `--all-features` enables only `nlp,python`. The embedding sidecar selects CUDA or Metal at run time. Therefore, this command is valid on all machines.

The `clippy-no-cuda` alias is a legacy form of the same command without `--workspace`. It has the same coverage problem.

The alias also fails in nested worktrees under `.claude/worktrees/*`. Cargo merges duplicate alias arrays from the two `.cargo/config.toml` files. Use the full command in a nested worktree.

If clippy fails, correct the failure locally before you push. Do not wait for the CI matrix to report it.

When a comprehensive full-suite gate is required, it must pass with `--features nlp,python`.

`default = []`. Therefore, a featureless `cargo test` skips each integration suite that has `#![cfg(feature = "nlp")]`. These suites report `ok. 0 passed`, which can appear to be a successful full test.

Do not use the comprehensive command as the default validation for an unrelated change.

Run local Rust tests that enable the `python` feature through the uv Python 3.12 environment:

    uv run --python 3.12 -- cargo test --features nlp,python

PyO3 selects its interpreter from the process environment. If you run Cargo directly, you bypass uv. Cargo can then select an incompatible system Python or a Python installation without the development library that Rust test executables need for linking.

Do not enable `extension-module` for tests.

`extension-module` disables libpython linking. This behavior is correct for the wheel because the host interpreter supplies the `Py*` symbols at load time. This behavior is not correct for an executable. A test build then fails during linking because `_Py*` symbols are undefined.

Maturin enables `extension-module` for the wheel through `pyproject.toml`. Keep this feature disabled in all other cases.

Therefore, `cargo test --all-features` is not a substitute for `--features nlp,python`.

You can use `allow(clippy::too_many_arguments)` when the arguments are necessary. Do not put the arguments in a struct only to remove the clippy message.

# Temporary validation storage

Do not create manually named `CARGO_TARGET_DIR=/tmp/bifrost-*` or `/private/tmp/bifrost-*` directories. Cargo does not remove these directories.

Run an isolated build through `scripts/with-isolated-cargo-target.sh`. For example:

    scripts/with-isolated-cargo-target.sh cargo clippy --workspace --all-targets --all-features -- -D warnings

The helper removes its unique target after success, failure, or interruption.

Set `BIFROST_KEEP_TARGET=1` only when you intentionally need the artifacts after the command. The helper marks retained targets so that automatic cleanup does not remove them.

Before an authorized all-features or NLP build, check the available disk space. Do not run another NLP build at the same time in a sibling worktree.

The helper controls cleanup. It cannot reduce the maximum disk space that the build uses.

Use `scripts/cleanup-bifrost-tmp.sh` to inspect old Bifrost temporary directories.

The script performs a dry run by default. Review the candidates before you run the script with `--apply`.

The script skips these items:

- New directories
- Live helper process IDs
- Open directories
- Symbolic links
- Intentionally retained targets

In apply mode, the script automatically removes only directories that have the helper's managed-target marker.

Old manually named `bifrost-*` directories remain report-only. To remove them, first review them and then explicitly add `--include-unmanaged`.

For `bifrost_reference_differential`, use `--cache-mode ephemeral` for a one-time smoke test that must not write `.bifrost/cache/bifrost_cache.v<N>.db`.

Use the default `--cache-mode persisted` for an intentionally warmed or resumable corpus campaign.

# RQL syntax maintenance

Add all new CodeQuery JSON fields, RQL forms, properties, roles, kinds, aliases, and constrained values through one of these declarative registries:

- `crates/bifrost-analysis/src/analyzer/structural/query/schema.rs`
- The kind and role registries in `crates/bifrost-core/src/analyzer/structural/kinds.rs`

Each entry must include these items:

- Accepted spellings
- Value shape
- Signature
- Description
- Complete parser handling
- Complete decoder handling
- Complete validator handling

Do not add private keyword lists. Do not add documentation tables that only the editor uses.

When visible RQL vocabulary changes, add the applicable behavior tests:

- Parser tests
- Validation-range tests
- Hover tests
- Execution tests

Also update the conservative TextMate grammar in `editors/vscode/syntaxes/bifrost-rql.tmLanguage.json`.

Do not include ordinary JSON documents in the RQL editor integration. Recognize JSON-shaped CodeQuery source only after the host identifies the document as `bifrost-rql`.

Do not mint a new RQL schema version for an additive or compatible vocabulary change. Keep the current version. Add a new version only when an existing query stops parsing or changes meaning. Apply the same rule to the policy document schema.

# Review findings as RQL regressions

When a code review identifies a recurring smell that tools can detect, first reduce the smell to a structured RQL query.

If the query is useful in multiple repositories, add or extend a checked-in `.rqlp` rule under `policy-packs/`.

The rule must include these items:

- A stable policy ID
- Explicit policy schema versions
- Explicit RQL schema versions
- Inventory metadata
- A semantic hash in the pack manifest

A rule that is ready for release must have behavior-based positive tests and realistic near-miss tests for each claimed language.

Include these near-miss cases when applicable:

- APIs with similar names
- The same operation outside the applicable structural context
- Nested or deferred bodies when containment is part of the rule

If current containment cannot distinguish a deferred body, use one of these options:

- Do not include the rule.
- Make the deferred case an explicit tested lexical positive. State this boundary in the message and description.

A match that is based on a name can identify an item for review. Do not present the match as proof of execution, run-time cost, or invariance.

Do not replace a missing RQL or analyzer relation with a regular expression, source-text matching, or a coarse `file_of` projection.

If the reduced query cannot express the review condition, or if it gives an incomplete or misleading result, search the open issues first.

If an issue already covers the gap, link it. Otherwise, create a focused follow-up issue.

Record these details:

- The smallest fixture
- The query
- The expected result
- The actual result
- Diagnostics and completion behavior
- The language
- The exact Bifrost commit

Do not put the candidate in the built-in pack until it reliably passes positive and near-miss tests.

Treat Bifrost plugin latency as a product regression.

Measure code-intelligence calls during normal agent work. If a call takes more than five seconds, search the open issues.

If an issue already covers the slow path, add new and material timing evidence. Otherwise, create an issue.

Include these details:

- The exact tool and arguments
- The workspace, revision, and scope
- The wall-clock time
- The cold or warm state, when known
- The result or cancellation state
- A profile or small reproducer, when practical

During active development, keep each day's policy work ready for release.

Do these tasks:

- Keep each change small.
- Update the embedded manifest.
- Update the package checks.
- Run the staged-binary policy smoke test.

This work schedule does not authorize a version change, tag, publication, or deployment. You need an explicit instruction for those actions.

Before you complete a task that changes code, use the `bifrost-policy-checking` skill when it is installed.

Use one MCP `run_policy` request against the active workspace. In the request, run these policy sources together:

- The `bifrost.code-smells` pack
- Each executable repository policy root that the project explicitly identifies

Treat `finding` as work that you must review or correct.

Treat `unreliable` as a failed validation result.

After changes, run the same policy selection again.

Do not infer success only because the skill is visible. The `list_policies` and `run_policy` MCP tools must be available.

# Design philosophy

Build for correctness and general use.

A narrow fallback usually indicates a design problem. Find the source of the problem and correct the root cause, even when the correction affects a larger area.

For analyzer resolution and usage analysis, do not add regular-expression or text-search fallbacks that hide missing structured support.

Report the structured failure. Correct the graph or resolver.

The prohibition applies to string scanning that replaces available structure. Do not use regular expressions, `split`, or substring matching instead of the tree-sitter AST or analyzer structures that contain the answer.

This rule does not prohibit a structured best-effort result when information is incomplete.

For example, a receiver type can be unknown, or a name can resolve to more than one declaration. In these cases, you can use a structured, name-based best-effort result from AST nodes and CodeUnits.

Do not use a best-effort result to hide a structured failure that you can correct.

Use this rule: Do not use a regular expression instead of tree-sitter. You can make a best-effort result from the structure that is available.

Do not replace parser support with a small source-text parser that uses string splitting, regular expressions, or delimiter scanning.

For example, do not parse Rust paths or type syntax with `split("::")`, `split_once(':')`, or manual generic-delimiter walks when these sources can provide the structure:

- Tree-sitter nodes
- Analyzer declaration ranges
- Import binders
- Existing resolver helpers

Read AST fields such as `path`, `name`, `type`, `value`, and `field`.

If more than one location needs the same interpretation, add a shared structured helper.

Backward compatibility is not yet a requirement. When requirements change, simplify or correct the APIs instead.

# Implementation details

- Bifrost builds and tests on Windows and on Unix-like systems. Keep file and path handling independent of the operating system. Use `Path` and `PathBuf`. Use temporary and project roots that are absolute on the current system. Normalize slashes only at API or rendering boundaries that require a stable workspace-relative string.
- Use stack-safe iterative traversal instead of recursive Rust calls for analyzer tree and graph walks. This rule is especially important during workspace initialization, parser declaration collection, usage analysis, and other operations that can process many files or deeply nested ASTs. Use an explicit stack, an explicit queue, or a shared traversal helper unless you can prove that recursion depth is small and bounded.
- Design APIs to minimize cloning, especially in hot loops. Use iterators and slices when possible.
- Use a lighter data structure such as `HashMap` instead of a sorted data structure such as `BTreeMap` unless semantic correctness requires ordering. You can also use a sorted structure when one insertion-time ordering cost is better than repeated sorting later.
- Do not use reference counting by default. In graph domains, prefer explicit IDs and arena allocation.
- Cloning and reference counting are permitted when they are the best design. Select them intentionally. Do not select them only from habit.

# Coding conventions

- Use assertions to validate assumptions. Prefer a reasonable assumption with `assert!`, or `debug_assert!` on a hot path, instead of a defensive `if` check. Do not return `Result` or `Option` for a state that cannot occur. Use the FqName round-trip debug assertion from #1189 as the model. Fail at the construction point instead of passing corrupted state to other code.
- Apply DRY, but do not add a flag parameter only to share code. A `mode`-type Boolean or enum parameter usually indicates a design problem. Write separate functions instead.
- Use one general case when it also gives correct results for special cases such as empty input, maximum size, or one element. Add a special case only when it is necessary.
- Apply YAGNI. Implement the simplest solution that meets the requirements. Use a more robust solution only when you have specific information about a near-future requirement.
- Keep related code together. Do not move a short computation to a separate function, module, or file unless the computation is self-contained and is significantly complex or called from multiple locations. Declare a small single-use struct or enum next to the code that creates or returns it. Do not put it in a separate module.
- Do not use a mocking framework or dependency-injection framework. Use hand-written test fakes such as `FakeEngineProvider` and `new_without_semantic_index`. Use traits with default implementations. `unimplemented!()` is permitted. Keep test setup small.
- Do not add error handling without a specific recovery action. Do not match or catch an error unless you can apply context-specific handling. Propagate the error with `?` and let caller logging report it. Do not write `let _ = fallible()`. Report results and panics from spawned threads or rayon tasks. Do not silently discard them.
- When you log or format diagnostics, include complete collections. Use their Debug implementations. Do not include only counts.
- Use plain ASCII in code and comments. Do not use typographic quotation marks, long dashes, or nonstandard spaces.
- Before you add a local helper that interprets strings, paths, or common shapes, search for an existing shared helper. If more than one location needs the helper, add it to the shared location.

# Semantic search (nlp toolset)

The optional `nlp` Cargo feature has `default = []`. It adds `semantic_search`.

The PyTorch SDPA sidecar provides voyage-4-nano embeddings. The sidecar selects CUDA or Metal at run time. There are no compile-time backend features.

Tests must not download models. Tests must not start indexer threads.

Use one of these test methods:

- Create services with `SearchToolsService::new_without_semantic_index`.
- Start the binary with `BIFROST_SEMANTIC_INDEX=off`.
- Inject `FakeEngineProvider` or `FakeHashEmbedder` from `nlp::engine` or `nlp::indexer`.

The real-model smoke test is optional. Run it only with this command:

    BIFROST_NLP_MODEL_TESTS=1 cargo test --test nlp_semantic_search_models -- --ignored
