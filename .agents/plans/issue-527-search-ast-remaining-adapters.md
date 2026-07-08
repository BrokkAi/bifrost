# Implement remaining search_ast structural adapters for issue #527

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document must be maintained in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

`search_ast` lets users ask language-neutral structural questions such as "find calls to `eval`", "find assignments to `password`", or "find classes decorated with `route`" without knowing tree-sitter grammar node names. Today the engine and normalized query model exist, and Python, Java, JavaScript, and TypeScript expose structural adapters, but Go, C++, Rust, PHP, Scala, C#, and Ruby still report unsupported-adapter diagnostics. After this plan is complete, every language in `Language::ANALYZABLE` can answer representative `search_ast` queries through the same normalized kinds and roles, while still reporting explicit diagnostics for roles a particular language cannot model precisely.

The observable behavior is that a mixed-language inline project containing all eleven analyzable languages can run a shared call query and return matches from every language without messages such as `no structural adapter for go yet; its files were not searched`.

## Progress

- [x] (2026-07-08 00:00Z) Initial ExecPlan created from issue #527 and the user's milestone/review/commit requirements.
- [x] (2026-07-08 00:16Z) Baseline milestone: added `remaining_languages_report_missing_structural_adapters_before_issue_527_rollout`, proving current unsupported-adapter diagnostics for Go, C++, Rust, PHP, Scala, C#, and Ruby. Focused and structural regression checks passed; Brokk guided review across security, duplication, senior-dev, devops, and architecture perspectives reported no findings.
- [ ] Go milestone: implement and register Go structural search; add focused tests; run checks, Brokk guided review, accepted fixes, rerun checks, and commit.
- [ ] C++ milestone: implement and register C++ structural search; add focused tests; run checks, Brokk guided review, accepted fixes, rerun checks, and commit.
- [ ] Rust milestone: implement and register Rust structural search; add focused tests; run checks, Brokk guided review, accepted fixes, rerun checks, and commit.
- [ ] PHP milestone: implement and register PHP structural search; add focused tests; run checks, Brokk guided review, accepted fixes, rerun checks, and commit.
- [ ] Scala milestone: implement and register Scala structural search; add focused tests; run checks, Brokk guided review, accepted fixes, rerun checks, and commit.
- [ ] C# milestone: implement and register C# structural search; add focused tests; run checks, Brokk guided review, accepted fixes, rerun checks, and commit.
- [ ] Ruby milestone: implement and register Ruby structural search; add focused tests; run checks, Brokk guided review, accepted fixes, rerun checks, and commit.
- [ ] Final integration milestone: run full structural-search coverage across all analyzable languages, confirm unsupported-adapter diagnostics are gone, run Brokk guided review on the accumulated result, fix accepted findings, rerun checks, and commit final cleanup if needed.

## Surprises & Discoveries

- Observation: `cargo clippy-no-cuda` can pick a mismatched Homebrew `cargo-clippy` / `clippy-driver` when `/opt/homebrew/bin` wins over the rustup toolchain for those binaries while `cargo` and `rustc` come from `/Users/dave/.cargo/bin`. The symptom is repeated `E0514` "found crate compiled by an incompatible version of rustc" for many dependencies, even after `cargo clean`.
  Evidence: `which cargo` and `which rustc` resolved through `/Users/dave/.local/bin` to rustup, while `which cargo-clippy` and `which clippy-driver` resolved to `/opt/homebrew/bin`. Rerunning as `PATH=/Users/dave/.cargo/bin:$PATH cargo clippy-no-cuda` completed successfully.

## Decision Log

- Decision: Implement issue #527 as one independently reviewed and committed milestone per missing language, preceded by a baseline diagnostic milestone and followed by final integration.
  Rationale: Each adapter is grammar-specific and can be validated independently; committing after each reviewed milestone keeps the branch bisectable and satisfies the user's explicit requirement.
  Date/Author: 2026-07-08 / Codex.

- Decision: Keep `AstQuery`, RQL, MCP output, normalized kinds, and normalized roles unchanged unless a discovered bug forces a separately logged decision.
  Rationale: Issue #527 asks for adapter coverage over the existing normalized structural schema, not a query-language redesign. The existing `search_ast` diagnostics already support partial capability reporting.
  Date/Author: 2026-07-08 / Codex.

- Decision: A role edge may be emitted only from tree-sitter nodes and fields or existing structured nodes selected by the parser. Regexes, source splitting, delimiter scanning, and source-text mini-parsers are out of scope.
  Rationale: The repository design philosophy requires structured analyzer support instead of text fallbacks, and the existing `StructuralSpec` boundary is designed for AST-field-based extraction.
  Date/Author: 2026-07-08 / Codex.

## Outcomes & Retrospective

- Baseline milestone outcome (2026-07-08 / Codex): The current unsupported language set is now captured in `tests/structural_search_cross_language.rs`. The test builds a real inferred-language workspace for Go, C++, Rust, PHP, Scala, C#, and Ruby, runs a shared `audit` call query, asserts there are no matches, and asserts the seven exact unsupported-adapter diagnostics. This gives each language milestone a concrete diagnostic to remove. Verification passed with `BIFROST_SEMANTIC_INDEX=off cargo test --test structural_search_cross_language remaining_languages_report_missing_structural_adapters_before_issue_527_rollout -- --nocapture`, `BIFROST_SEMANTIC_INDEX=off cargo test structural --lib`, `BIFROST_SEMANTIC_INDEX=off cargo test --test structural_search_python --test structural_search_planner --test structural_search_cross_language`, `cargo fmt --check`, and `PATH=/Users/dave/.cargo/bin:$PATH cargo clippy-no-cuda`. Brokk guided review found no issues and required no fixes.

## Context and Orientation

All commands in this plan run from the repository root, `/Users/dave/.codex/worktrees/473b/bifrost`, on the existing branch `527-implement-search_ast-structural-adapters-for-remaining-languages`. Do not create or switch branches for this work. Because the repo instruction says not to rebase unless explicitly asked, refresh remote state with `git fetch origin` when needed but do not run `git rebase` as part of this plan.

`search_ast` is Bifrost's structural-query tool. It accepts an `AstQuery`, a typed Rust query model serialized as JSON and also produced by the RQL S-expression REPL. The normalized vocabulary lives in `src/analyzer/structural/kinds.rs`. A normalized kind is a language-neutral node category such as `call`, `assignment`, `field_access`, `function`, `method`, `class`, `import`, `literal`, `return`, `throw`, `catch`, `if`, and `loop`. A role is a language-neutral edge from one matched node to a sub-node, such as `callee`, `receiver`, `args`, `left`, `right`, `module`, `object`, and `field`.

The per-language adapter boundary is `StructuralSpec` in `src/analyzer/structural/spec.rs`. A `StructuralSpec` provides a static tree-sitter node-kind table, optional kind refinement, optional `supports_role`/`supports_kind` capability limits, and an `extract` method that attaches fact names and role edges through `RoleSink`. `RoleSink` stores spans and links to facts discovered during structural extraction. It is the correct way to attach roles; do not construct search results directly inside adapters.

Existing reference implementations:

- `src/analyzer/python/structural.rs` is the reference for compact adapter shape, method refinement, keyword arguments, decorators, and Python tests.
- `src/analyzer/java/structural.rs` shows Java declarations, method calls, object creation, field access, annotations, and imports.
- `src/analyzer/js_ts/structural.rs` shows a shared adapter for two languages, constructor refinement, TypeScript-only kind entries, decorators, and grammar assertion tests for both TypeScript and TSX.

Registration happens through each language's existing tree-sitter adapter. For example, `PythonAdapter::structural_spec()` returns `Some(&super::structural::PYTHON_STRUCTURAL_SPEC)`, and `TreeSitterAnalyzer` exposes that provider through `structural_search_providers`. For each missing language, add a `mod structural;` declaration in its module, add a static `StructuralSpec`, and override `structural_spec()` in the corresponding adapter.

The missing languages are Go, C++, Rust, PHP, Scala, C#, and Ruby. The existing `Language::ANALYZABLE` list in `src/analyzer/model.rs` defines the full supported language set. `search_ast` currently emits unsupported-adapter diagnostics from `src/analyzer/structural/search.rs` whenever a scoped language has analyzed files but no structural provider.

Tests should use `tests/common/inline_project.rs` and `InlineTestProject` for small ad hoc projects. This keeps file creation OS-agnostic and matches repo test guidance.

## Plan of Work

First, create a baseline milestone that codifies the current unsupported behavior. Add tests in the structural-search integration suite that build a mixed-language inline project containing Go, C++, Rust, PHP, Scala, C#, and Ruby files, run a simple `call` query with a callee name present in each file, and assert that each missing language produces an unsupported-adapter diagnostic. This milestone should not implement adapters; it protects the starting point and gives each later milestone a diagnostic to remove.

For each language milestone, add a new `src/analyzer/<language>/structural.rs` file. The file should define a `LanguageStructuralSpec` type, a static instance, a `KIND_TABLE`, an `expression_name_node` helper that follows only tree-sitter AST nodes/fields, and an `impl StructuralSpec`. Keep helpers local unless two adapters genuinely need the same helper and the shared helper is grammar-neutral.

Each adapter should cover the same v1 behavioral surface where the language grammar supports it precisely:

- calls with `callee`, `receiver` where there is an object/member-call shape, and positional `args`;
- declarations for functions, methods, constructors when present, classes or class-like declarations, and imports;
- assignments with `left` and `right` roles only when the assignment has a value;
- field/member access with `object` and `field` roles;
- identifiers and string/numeric/boolean/null literals;
- return, throw/raise/panic-equivalent where the grammar has a statement node, catch/rescue clauses, if statements, and loop statements;
- decorators/annotations only for languages with a precise structural form in the grammar.

Do not make unsupported constructs pretend to work. If a language cannot precisely model a role in v1, return `false` from `supports_role` for that role. A query that asks for such a role should produce a capability diagnostic and still search what the adapter can model.

Use this order and commit after each milestone:

1. Baseline diagnostics.
2. Go.
3. C++.
4. Rust.
5. PHP.
6. Scala.
7. C#.
8. Ruby.
9. Final integration cleanup.

After every milestone implementation and focused test pass, run Brokk guided review on the milestone diff before committing. The review is scoped only to changes introduced by that milestone. Fix accepted findings, rerun that milestone's checks, then stage only milestone files and commit with a multiline checkpoint message explaining both what changed and why.

## Concrete Steps

Start by confirming the branch and upstream state:

    git fetch origin
    git status --short --branch
    git rev-list --left-right --count HEAD...@{upstream}

Expected starting point:

    ## 527-implement-search_ast-structural-adapters-for-remaining-languages...origin/527-implement-search_ast-structural-adapters-for-remaining-languages
    0 0

For every milestone, use this loop:

    # inspect changed files
    git status --short
    git diff --stat
    git diff

    # run focused structural tests for the milestone
    BIFROST_SEMANTIC_INDEX=off cargo test structural --lib
    BIFROST_SEMANTIC_INDEX=off cargo test --test structural_search_cross_language

    # run broader existing structural-search regressions when the milestone touches shared tests
    BIFROST_SEMANTIC_INDEX=off cargo test --test structural_search_python --test structural_search_planner --test structural_search_cross_language

    # run formatting/lint checks before review/commit
    cargo fmt --check
    cargo clippy-no-cuda

Then run Brokk guided review against the uncommitted milestone diff. Use the guided-review workflow for uncommitted changes: collect `git diff` and `git diff --staged`, spawn the security, duplication, senior-dev, devops, and architect reviewer perspectives, and filter findings to issues introduced or worsened by the milestone diff. Apply accepted fixes only when they are technically justified by the changed code, then rerun the focused checks above.

Commit after each milestone:

    git add <only files changed for this milestone>
    git commit -m "<concise milestone title>" -m "<why this milestone changed the adapter coverage and how it was verified>"

At the final integration milestone, run the full structural-search coverage:

    BIFROST_SEMANTIC_INDEX=off cargo test structural --lib
    BIFROST_SEMANTIC_INDEX=off cargo test --test structural_search_python --test structural_search_planner --test structural_search_cross_language
    cargo fmt --check
    cargo clippy-no-cuda

If a command fails, fix the root cause before continuing. If the failure is unrelated and pre-existing, prove that with a clean comparison or a narrow rerun and record the evidence in `Surprises & Discoveries` before proceeding.

## Validation and Acceptance

The feature is complete when:

- `search_ast` has registered providers for all entries in `Language::ANALYZABLE` except `Language::None`.
- A mixed-language `InlineTestProject` query that asks for `{"match": {"kind": "call", "callee": {"name": "audit"}}}` returns one match from Java, Go, C++, JavaScript, TypeScript, Python, Rust, PHP, Scala, C#, and Ruby.
- The final cross-language test reports no `no structural adapter for ... yet` diagnostics.
- Every new adapter has a grammar assertion test using `assert_kind_table_matches_grammar`.
- Each language has focused tests for call matching, assignments, field/member access, imports/modules, literals, declarations, and unsupported-role diagnostics where applicable.
- Every milestone has a Brokk guided-review gate recorded in this ExecPlan and a corresponding commit.
- `cargo fmt --check` and `cargo clippy-no-cuda` pass after the final milestone.

## Idempotence and Recovery

All tests and checks are safe to rerun. `InlineTestProject` creates temporary projects and cleans them up automatically. If a milestone review recommends a change that overlaps the next language, keep the fix in the current milestone only when it affects current milestone files or shared structural-search tests; otherwise record it in `Surprises & Discoveries` and defer it to the relevant later milestone.

Do not use `git add -A`. Stage explicit milestone files only. If a test command writes build artifacts under `target/`, leave them untracked. If a commit fails because unrelated user changes are present, inspect `git status --short`, stage only this plan's files, and leave unrelated changes untouched.

## Artifacts and Notes

Record short evidence snippets after each milestone: the focused test counts, guided-review summary, accepted fixes, and commit hash. Keep the snippets concise enough that the plan remains readable.

## Interfaces and Dependencies

Each new adapter must implement:

    impl StructuralSpec for <Language>StructuralSpec {
        fn language(&self) -> Language;
        fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)];
        fn supports_role(&self, role: Role) -> bool;
        fn supports_kind(&self, kind: NormalizedKind) -> bool; // only when refined kinds need it
        fn should_extract(&self, node: Node<'_>, kind: NormalizedKind) -> bool; // only for value-bearing assignments
        fn refine_kind(&self, node: Node<'_>, kind: NormalizedKind, enclosing: Option<NormalizedKind>, source: &str) -> NormalizedKind; // only when grammar context changes kind
        fn extract(&self, node: Node<'_>, kind: NormalizedKind, sink: &mut RoleSink<'_>);
    }

Each language adapter must expose:

    fn structural_spec(&self) -> Option<&'static dyn crate::analyzer::structural::StructuralSpec> {
        Some(&super::structural::<LANGUAGE>_STRUCTURAL_SPEC)
    }

Use only existing dependencies: `tree_sitter`, the language grammar crates already listed in `Cargo.toml`, and the structural-search helpers under `src/analyzer/structural/`. Do not add dependencies for this work.

Revision note, 2026-07-08: Initial plan created to make issue #527 executable with one reviewed, committed milestone per missing language, matching the user's explicit commit-after-each-milestone requirement.

Revision note, 2026-07-08: Updated after the baseline milestone to record the new unsupported-adapter diagnostic test, passing validation commands, guided-review result, and the local clippy toolchain-path discovery.
