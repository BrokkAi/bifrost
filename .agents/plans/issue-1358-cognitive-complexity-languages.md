# Add cognitive-complexity support for every requested parsed language

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this document in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

After this change, callers of the `compute_cognitive_complexity` MCP tool can analyze Go, C and C++, JavaScript and JSX, TypeScript and TSX, PHP, Scala, and C# functions instead of receiving a silently incomplete report. The analyzer will score each language through its tree-sitter abstract syntax tree using the same SonarSource-style rules already used for Java, Python, Rust, and Ruby. Focused tests will demonstrate nesting, logical-operator sequences, language-specific control flow, default branches, and nested callable boundaries, while an MCP integration test will prove that one mixed-language request includes findings from every newly supported language. Kotlin remains intentionally unsupported here because issue #1243 owns that work.

## Progress

- [x] (2026-07-30 17:55Z) Diagnosed the empty-result path, verified the issue branch and current remote state, inspected the current language adapters and grammar metadata, and ran the 31-test cognitive-complexity baseline successfully.
- [x] (2026-07-30 17:55Z) Located Brokk's reference configurations and fixtures for Go, C/C++, JavaScript/TypeScript, PHP, and Scala; confirmed that Brokk does not contain a C# cognitive-complexity implementation.
- [x] (2026-07-30 18:08Z) Ported the Brokk-backed language configurations and added focused positive and near-miss tests for Go, C/C++, JavaScript/JSX, TypeScript/TSX, PHP, and Scala; formatting and all 50 focused cognitive-complexity tests pass.
- [ ] Derive and validate the C# configuration from its tree-sitter grammar with parser-backed tests for statements, switch forms, logical sequences, defaults, and callable boundaries.
- [ ] Add a mixed-language MCP call test and update the tool description to state the supported language boundary.
- [ ] Run formatting, focused and broader featureless tests, repository policy checks, and adversarial review; resolve all correctness findings.

## Surprises & Discoveries

- Observation: The current generic scorer already represents every scoring category needed by the requested languages, including separate counted case nodes and non-counted default-case containers.
  Evidence: `crates/bifrost-analysis/src/analyzer/cognitive_complexity.rs` defines configuration fields for if/alternate-if, loops, catch, conditionals, cases, defaults, binary operators, labeled jumps, named boundaries, anonymous boundaries, and else clauses.

- Observation: Brokk supplies reference mappings and tests for all requested languages except C#.
  Evidence: `/Users/dave/Workspace/BrokkAi/brokk/brokk-shared/src/main/java/ai/brokk/analyzer/{go,cpp,javascript,php,scala}/CognitiveComplexityAnalysis.java` exist, and JavaScript's shared configuration is used by both JavaScript and TypeScript analyzers; no C# counterpart exists.

- Observation: One Bifrost C++ adapter serves C source and header extensions as well as C++.
  Evidence: `Language::Cpp` maps `c`, `cc`, `cpp`, `cxx`, `h`, `hpp`, `hh`, and `hxx` in `crates/bifrost-analysis/src/analyzer/model.rs`, so one configuration and explicit `.c` plus `.cpp` tests cover the issue's C/C++ scope.

- Observation: Bifrost's current tree-sitter-cpp grammar represents both ordinary cases and the default branch as `case_statement`; the Brokk reference's `default_statement` node does not exist here.
  Evidence: A first focused run scored the C default branch one point too high. The current grammar exposes an optional `value` field on `case_statement`, so `cpp_is_default_case` now recognizes default structurally through the absent field. The rerun passed all 50 focused tests.

## Decision Log

- Decision: Port Brokk's AST mappings exactly where Bifrost uses the same grammar node vocabulary, then add acceptance-focused near-miss tests rather than blindly copying every reference fixture.
  Rationale: Brokk is the intended semantic reference, while Bifrost's acceptance criteria require specific evidence for nesting, logical runs, language-specific nodes, and false-positive boundaries.
  Date/Author: 2026-07-30 / Codex

- Decision: Keep Kotlin's adapter defaulting to no cognitive-complexity configuration.
  Rationale: Issue #1358 explicitly excludes Kotlin and issue #1243 owns that capability.
  Date/Author: 2026-07-30 / Codex

- Decision: Derive C# behavior from tree-sitter nodes and existing C# structured helpers, not from source-text parsing.
  Rationale: Brokk has no C# implementation, and repository policy requires structured analyzer support. A language-local AST predicate can distinguish `default` switch sections and discard-pattern switch arms without adding a string scanner.
  Date/Author: 2026-07-30 / Codex

- Decision: Put language scoring tests in the existing `crates/bifrost-analysis/src/analyzer/cognitive_complexity_tests.rs` module and the mixed transport test in the existing `crates/bifrost-mcp/tests/bifrost_mcp_server.rs` integration binary.
  Rationale: These are the established behavior-test locations; no new root-level integration test binary is justified.
  Date/Author: 2026-07-30 / Codex

## Outcomes & Retrospective

The first implementation milestone is complete. Six reference-backed language families, including their C/JSX/TSX dialect routes, now return scores through explicit adapter configurations. No shared-scorer change was needed. C#, MCP transport coverage, documentation, and final validation remain.

## Context and Orientation

Cognitive complexity is a heuristic score that adds one for control-flow breaks such as an `if`, loop, catch, conditional expression, or non-default switch case, adds the current nesting depth to nested control flow, counts runs of logical operators, and adds one for labeled jumps. `crates/bifrost-analysis/src/analyzer/cognitive_complexity.rs` contains the language-independent, iterative tree walker. A `Config` maps language-specific tree-sitter node kinds, such as Go's `for_statement` or PHP's `else_if_clause`, to those generic categories.

Each parsed language implements `LanguageAdapter` in its adapter or analyzer module. The optional `LanguageAdapter::cognitive_complexity_config()` method defaults to `None` in `crates/bifrost-analysis/src/analyzer/tree_sitter_analyzer.rs`. `TreeSitterAnalyzer::compute_cognitive_complexities()` returns an empty vector when it sees `None`, which is why the requested languages silently disappear. Java, Python, Rust, and Ruby already return static `Config` values and demonstrate the intended integration pattern.

The requested adapters are `crates/bifrost-analysis/src/analyzer/go/adapter.rs`, `cpp/adapter.rs`, `javascript/mod.rs`, `typescript/mod.rs`, `php/adapter.rs`, `scala/adapter.rs`, and `csharp/adapter.rs`. JavaScript's adapter parses `.js` and `.jsx`; TypeScript chooses the TypeScript or TSX grammar by file extension; `Language::Cpp` covers both C and C++ extensions. `crates/bifrost-analysis/src/analyzer/cognitive_complexity_tests.rs` builds inline projects and asks the analyzer for a named function's score. `crates/bifrost-analysis/src/code_quality/cognitive.rs` renders the typed tool result, and `crates/bifrost-mcp/src/searchtools_service.rs` exposes that handler over MCP. `crates/bifrost-mcp/src/mcp_slopcop.rs` supplies the user-visible tool description.

Brokk's reference code lives in the sibling repository under `/Users/dave/Workspace/BrokkAi/brokk/brokk-shared`. Its `ai/brokk/analyzer/{go,cpp,javascript,php,scala}/CognitiveComplexityAnalysis.java` files define mappings to port. `JavascriptCognitiveComplexityAnalysis` is shared by Brokk's JavaScript and TypeScript analyzer. The corresponding tests are under `src/test/java/ai/brokk/analyzer/complexity`. These references do not cover C#.

## Plan of Work

The first milestone ports the reference-backed mappings. Add one lazily initialized static `cognitive_complexity::Config` next to each affected adapter, import `crate::analyzer::cognitive_complexity` and `std::sync::LazyLock`, and override `cognitive_complexity_config()` to return it. JavaScript and TypeScript should share a single configuration defined in their existing shared `js_ts` module rather than duplicating the mapping. Preserve Brokk's callable-boundary semantics: JS/TS callable forms are named boundaries and nested callables do not contribute to an enclosing function, while Go function literals, C++ lambdas, PHP anonymous/arrow functions, and Scala lambdas are anonymous boundaries that add nesting inside their enclosing function. Add tests in `cognitive_complexity_tests.rs` for each source and variant. Each language needs at least a simple zero, nested/else-if behavior, a logical sequence, a language-specific control-flow construct with a default near-miss, and a nested callable boundary. Add explicit `.c`, `.jsx`, and `.tsx` cases so extension routing is demonstrated rather than inferred.

The second milestone implements C#. Define a static config in `csharp/adapter.rs` for `if_statement`; `for_statement`, `foreach_statement`, `while_statement`, and `do_statement`; `catch_clause`; `conditional_expression`; `switch_section` and `switch_expression_arm`; `binary_expression`; `&&` and `||`; `break_statement` and `continue_statement`; named method/local-function boundaries; and lambda/anonymous-method nesting. Add a small AST predicate beside the config that identifies a switch section containing the direct anonymous `default` token and a switch expression arm whose direct pattern is a discard. Reuse existing structured child traversal patterns; do not inspect source text. Tests must distinguish regular cases from defaults/discards, labeled from unlabeled jumps, nested local functions from enclosing methods, and logical sequences from unrelated binary arithmetic.

The third milestone adds transport-level proof. Extend `crates/bifrost-mcp/tests/bifrost_mcp_server.rs` with one featureless `slopcop` server test that writes compact functions above a threshold for Go, C, C++, JavaScript, JSX, TypeScript, TSX, PHP, Scala, and C#. Send one `tools/call` request for `compute_cognitive_complexity` with all paths and a low positive threshold, then assert the returned report contains the expected function from every file. Include a Kotlin file in a separate assertion only if needed to prove the documented exclusion; do not make Kotlin support part of this issue. Update `crates/bifrost-mcp/src/mcp_slopcop.rs` so the tool description explicitly lists Java, Python, Rust, Ruby, Go, C/C++, JavaScript/JSX, TypeScript/TSX, PHP, Scala, and C#, and states that Kotlin is tracked separately. Update published MCP documentation only if it currently makes a stronger language claim than tool discovery; avoid duplicating a long support matrix in list-only documentation.

The final milestone formats and validates the entire change, runs policy checks, and reviews the diff. Fix any test, clippy, policy, or review finding at its root. Keep the ExecPlan's progress, discoveries, decisions, evidence, and retrospective current after each milestone.

## Concrete Steps

Run all commands from `/Users/dave/.codex/worktrees/227d/bifrost`.

Before editing, the focused baseline is:

    cargo test -p brokk-bifrost-analysis cognitive_complexity --lib

The observed baseline is 31 passed, 0 failed.

After the reference-backed milestone, run:

    cargo fmt --all -- --check
    cargo test -p brokk-bifrost-analysis cognitive_complexity --lib

After the C# milestone, rerun the same commands and also run any focused C# analyzer test filter added during parser-shape validation.

After MCP coverage, run:

    cargo test -p brokk-bifrost-mcp --test bifrost_mcp_server cognitive_complexity

At the final gate, run featureless validation appropriate to this non-NLP change:

    cargo fmt --all -- --check
    cargo clippy -p brokk-bifrost-analysis -p brokk-bifrost-mcp --all-targets -- -D warnings
    cargo test -p brokk-bifrost-analysis
    cargo test -p brokk-bifrost-mcp

Use the installed `bifrost-policy-checking` skill to run the built-in `bifrost.code-smells` pack and every executable repository policy root exposed for this workspace in one request. A `finding` must be reviewed or fixed; `unreliable` is a failed gate. If the policy tools remain unavailable in this session, record that limitation rather than claiming a clean result.

## Validation and Acceptance

The analyzer tests are accepted when every requested language returns an explicit score for a discovered function, nested flow produces a higher score than flat flow, adjacent logical operator runs change the score as expected, default branches do not contribute, ordinary arithmetic and unlabeled jumps remain near-misses, and nested named callables do not leak their body into an enclosing function. Variant routing must be directly covered for C, C++, JSX, TypeScript, and TSX rather than relying only on the base adapter.

The MCP test is accepted when a single `compute_cognitive_complexity` request includes findings from each requested language in its report and returns `truncated: false`. The user-visible tool description must accurately enumerate supported languages while leaving Kotlin excluded. Existing Java, Python, Rust, and Ruby scores and threshold rendering must remain unchanged.

All focused tests, package tests, formatting, clippy, and available policy checks must pass. No NLP feature is required because this change does not touch semantic search.

## Idempotence and Recovery

All source and test edits are repeatable and local to the current issue branch. Cargo commands reuse the worktree's normal target directory and do not mutate source files. If a language fixture fails, inspect its tree-sitter node shape and correct the adapter mapping or fixture; do not add regex or source-text fallback parsing. Commits are milestone checkpoints on the existing branch and should stage only files changed for that milestone. Do not switch branches, rebase, push, or open a pull request unless explicitly requested.

## Artifacts and Notes

The empty-result gate is:

    let Some(config) = self.adapter.cognitive_complexity_config() else {
        return Vec::new();
    };

Brokk's reference mappings use the same high-level categories as Bifrost's `Config`. The one known reference gap is C#, whose switch default behavior must be proven from the grammar and tests.

## Interfaces and Dependencies

No new crate dependencies or public APIs are expected. Every affected adapter must implement:

    fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config>

The implementation must return a lazily initialized static config. Shared JS/TS configuration may expose a crate-private accessor from `crates/bifrost-analysis/src/analyzer/js_ts` so both adapters return the same static value. C# may add a private function matching `cognitive_complexity::DefaultCasePredicate`, with signature:

    fn csharp_is_default_case(node: tree_sitter::Node<'_>, source: &str) -> bool

The `source` parameter may be named `_source` because the implementation must decide from AST node kinds and direct tokens. The shared scorer's `Config`, `compute`, and report result types should remain source compatible unless a failing behavior test proves a generic semantic gap.

Plan revision note (2026-07-30): Created the initial self-contained plan after issue diagnosis, Brokk reference inspection, grammar inspection, and a clean focused baseline.

Plan revision note (2026-07-30): Recorded completion of the reference-backed milestone and the tree-sitter-cpp default-case grammar difference discovered by focused tests.
