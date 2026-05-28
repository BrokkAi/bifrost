# Replace analyzer and usage graph mini parsers with tree-sitter classification

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md`. It is self-contained and describes how to audit and break down GitHub issue `BrokkAi/bifrost#141`, "Epic: Replace analyzer and usage graph mini parsers with tree-sitter classification."

## Purpose / Big Picture

Bifrost uses tree-sitter parsers to understand source code, but some analyzer and usage graph paths still classify syntax by reading raw source text with regular expressions, prefix and suffix checks, operator probes, or manual token scanning. Those mini parsers are brittle because they duplicate facts that the syntax tree already knows, such as whether a PHP name is part of a function call, a constructor call, a constant declaration, a member access, or a type reference.

After this work, the team should have an evidence-backed inventory of the important mini-parser clusters and a sequence of focused language-scoped follow-up issues or small pull requests. A human can see progress by reading this plan, then checking the linked follow-up issues or the focused regression tests added for each cleanup. The goal is not to remove every text operation from the analyzer. The goal is to replace source-text syntax classification when tree-sitter already exposes the same structure more robustly.

## Progress

- [x] (2026-05-28 16:48Z) Read `.agent/PLANS.md`, confirmed this issue branch is attached to `141-epic-replace-analyzer-and-usage-graph-mini-parsers-with-tree-sitter-classification`, and rebased against `origin/master`.
- [x] (2026-05-28 16:48Z) Recorded the initial mini-parser definition, PHP seed area, language order, and validation policy in this ExecPlan.
- [x] (2026-05-28 16:48Z) Captured initial audit evidence for PHP, Python, Rust, and Go usage graph mini-parser clusters.
- [x] (2026-05-28 16:57Z) Audited PHP usage graph mini parsers and replaced the small constructor/function/constant classification probes with tree-sitter parent-node checks.
- [x] (2026-05-28 16:57Z) Created PHP follow-up issues for the larger receiver/member regex and hierarchy regex clusters: `#154` and `#155`.
- [x] (2026-05-28 17:09Z) Audited Python usage graph mini parsers and replaced regex/line-based receiver fact extraction with tree-sitter event collection.
- [x] (2026-05-28 17:18Z) Audited Rust usage graph mini parsers and replaced receiver-inference regexes with tree-sitter traversal.
- [x] (2026-05-28 17:23Z) Audited Go usage graph mini parsers and replaced typed local receiver regex inference with tree-sitter `var_spec` traversal.
- [x] (2026-05-28 17:35Z) Audited C++/C# usage graph and analyzer mini parsers and replaced comment-sensitive arity classification with tree-sitter argument/initializer node counting.
- [x] (2026-05-28 17:47Z) Audited JS/TS usage graph and analyzer mini parsers and replaced ES import clause string parsing with tree-sitter import-node extraction.
- [x] (2026-05-28 17:56Z) Audited Scala/Java usage graph and analyzer mini parsers and replaced Scala typed-parameter receiver inference with tree-sitter `parameter` node extraction.
- [x] (2026-05-28 17:56Z) Summarized the follow-up issue set in `Outcomes & Retrospective`; all audited language clusters are now implemented, tracked, or intentionally deferred.

## Surprises & Discoveries

- Observation: The first PHP seed area is broader than the three small helper names in the issue. It also includes regex-driven receiver inference and hierarchy parsing.
  Evidence: `rg` found `TYPE_DECLARATION_RE` in `src/analyzer/usages/php_graph/resolver.rs`, plus `PARAMETER_VARIABLE_RE`, `ASSIGNMENT_RE`, `INSTANCE_MEMBER_RE`, and `STATIC_MEMBER_RE` in `src/analyzer/usages/php_graph/extractor.rs`.

- Observation: Python and Rust already have concentrated receiver/type inference mini parsers inside usage graph extractors, making them good follow-up milestones after PHP.
  Evidence: `src/analyzer/usages/python_graph/extractor.rs` defines `PARAM_ANNOTATION_RE`, `PARAM_NAME_RE`, and `ASSIGNMENT_RE`; `src/analyzer/usages/rust_graph/extractor.rs` defines `LET_TYPED_RE`, `LET_CONSTRUCTED_RE`, `LET_ALIAS_RE`, `PARAM_TYPED_RE`, `TYPE_ALIAS_RE`, `OPTION_FIELD_RE`, and `SELF_FIELD_AS_REF_LET_ELSE_RE`.

- Observation: Not every regex or string check is a mini parser that should be replaced. Generic fallback search and text rendering are intentionally text-based.
  Evidence: `src/analyzer/usages/regex_analyzer.rs` is the documented fallback path for languages or cases without graph strategy support, and usage hit snippets must still read source text for display.

- Observation: PHP tree-sitter keeps comments between tokens inside semantic parent nodes, so parent-node classification is more robust than adjacency checks.
  Evidence: `new /* constructor target */ Target()` parses with `Target` under `object_creation_expression`, and `helper /* call target */ ()` parses with `helper` under `function_call_expression`; `cargo test --test usages_php_graph_test` passed with `php_graph_uses_parse_tree_for_commented_constructor_and_function_calls`.

- Observation: The remaining PHP mini-parser clusters are too broad for the first narrow cleanup.
  Evidence: `STATIC_MEMBER_RE`, `INSTANCE_MEMBER_RE`, `ASSIGNMENT_RE`, and `PARAMETER_VARIABLE_RE` cooperate with ordered local receiver inference in `scan_instance_members_in_order`, while `TYPE_DECLARATION_RE` feeds `PhpHierarchyIndex`; both areas need dedicated follow-up issues or PRs.

- Observation: Python receiver inference has an actionable narrow cleanup because tree-sitter exposes the same syntax facts that the regexes were extracting.
  Evidence: `parameters`, `typed_parameter`, `typed_default_parameter`, `assignment`, `type`, `attribute`, and `call` nodes cover the old `PARAM_NAME_RE`, `PARAM_ANNOTATION_RE`, and `ASSIGNMENT_RE` roles; `cargo test --test usages_python_graph_test` passed with `multiline_constructed_local_receiver_resolves_member_usage`.

- Observation: Python type-expression normalization remains intentionally text-based in this pass.
  Evidence: `normalized_receiver_type` and `receiver_annotation_matches_target` still enforce the existing supported annotation subset, including `Optional[...]` unwrapping and rejection of unions or complex generic expressions.

- Observation: Rust receiver inference has a safe tree-sitter cleanup, but other Rust mini-parser clusters are separate follow-up work.
  Evidence: `type_item`, `parameter`, `let_declaration`, `field_declaration`, `struct_expression`, `call_expression`, `scoped_identifier`, and `tuple_struct_pattern` nodes cover `TYPE_ALIAS_RE`, `PARAM_TYPED_RE`, `LET_TYPED_RE`, `LET_CONSTRUCTED_RE`, `LET_ALIAS_RE`, `OPTION_FIELD_RE`, and `SELF_FIELD_AS_REF_LET_ELSE_RE`; `detect_shadowed_names`, member hit regex matching, `TRAIT_IMPL_RE`, and visibility prefix checks remain intentionally untouched in this pass.

- Observation: Go had one actionable usage-graph regex cleanup in typed local receiver inference; most other Go text operations are import-path or display/signature handling.
  Evidence: `var_spec` exposes repeated `name` fields and an optional `type` field, replacing `VAR_TYPED_LIST_RE`; Go import path parsing in `src/analyzer/usages/go_graph/resolver.rs` and declaration signature/source shaping in `src/analyzer/go/declarations.rs` still operate on rendered strings and are intentionally text-based.

- Observation: C++/C# had a small actionable arity cleanup, but most remaining text paths are broader fallback or rendering behavior.
  Evidence: C# `argument_list` exposes direct `argument` children, and C++ declaration `init_declarator` values expose `argument_list` or `initializer_list` nodes. C++ text constructor/operator/member fallback scans, textual owner context, alias statement fallback parsing, and analyzer signature rendering need dedicated follow-up work if they are replaced. C# declaration literal/signature rendering and using/import string parsing are intentionally text-based.

- Observation: JS/TS usage graph import/export extraction already uses tree-sitter, but analyzer import-info extraction still string-parsed ES import clauses.
  Evidence: `compute_import_binder` and `compute_export_index` walk `import_statement` and `export_statement` nodes; `JavascriptAnalyzer` and `TypescriptAnalyzer` previously called `parse_js_import_infos` for `import_statement` raw text. ES import clauses now use tree-sitter `import_clause`, `namespace_import`, `named_imports`, and `import_specifier` nodes. CommonJS `require(...)`, module specifier/path strings, analyzer signature rendering, JSX/test detection, and clone/test regexes remain intentionally text-based or follow-up-only.

- Observation: Scala had a narrow actionable receiver-inference cleanup in function parameters, while Java's usage graph is already mostly node-driven.
  Evidence: `src/analyzer/usages/scala_graph/extractor.rs` parsed `parameters` text with comma splitting and `split_once(':')`; tree-sitter Scala exposes direct `parameter` children with `name` and `type` fields. `src/analyzer/usages/java_graph/extractor.rs` already seeds parameters, variables, constructors, methods, and fields from tree-sitter nodes. Java static import strings, signature arity strings, type-name normalization, analyzer rendering, and import path logic are intentionally text-based or broader follow-up-only concerns.

## Decision Log

- Decision: Treat GitHub issue `BrokkAi/bifrost#141` as an audit-and-follow-up epic before attempting broad rewrites.
  Rationale: The issue acceptance criteria ask for an inventory and focused follow-up issues, and explicitly warn against large language-specific rewrites unless a change is small and self-contained.
  Date/Author: 2026-05-28 / Codex.

- Decision: Start with PHP, then audit Python, Rust, Go, C++/C#, JS/TS, and Scala/Java one language group at a time.
  Rationale: PHP is the first known example from PR `#133`. Python, Rust, and Go have concentrated usage graph regex clusters that can be audited independently. The paired language groups share implementation patterns and review risk.
  Date/Author: 2026-05-28 / Codex.

- Decision: Prefer language-local helper replacements until at least two languages need the same tree-sitter abstraction.
  Rationale: The current mini-parser clusters are language-specific. A premature shared abstraction could hide important tree-sitter grammar differences and make later language work harder to review.
  Date/Author: 2026-05-28 / Codex.

- Decision: Keep `RegexUsageAnalyzer` out of scope.
  Rationale: It is an intentional best-effort fallback for unsupported graph cases. This plan targets language graph and analyzer code that already has a parsed tree but still uses source-text probes to classify syntax.
  Date/Author: 2026-05-28 / Codex.

- Decision: Replace PHP adjacency helpers with language-local tree-sitter parent checks, but leave receiver/member regexes and hierarchy regex parsing for dedicated follow-ups.
  Rationale: Constructor, function-call, member/scoped-access, const-declaration, and function-declaration classification can be answered by immediate semantic parent nodes after ascending through `namespace_name` and `qualified_name`. Receiver inference and hierarchy parsing have wider behavior and ordering implications.
  Date/Author: 2026-05-28 / Codex.

- Decision: Replace Python scope-fact discovery with tree-sitter event collection while preserving the existing fixed-point local inference loop.
  Rationale: The brittle part was discovering parameters, annotations, and assignments from source lines. The fixed-point alias behavior is a semantic policy already covered by tests and should stay unchanged.
  Date/Author: 2026-05-28 / Codex.

- Decision: Replace only Rust receiver-inference regexes in this milestone and leave Rust shadowing, member-hit regex matching, trait implementation discovery, and visibility classification for later focused work.
  Rationale: Receiver inference has direct node equivalents and focused test coverage. The remaining clusters affect graph seeding, hit localization, trait ownership, or export visibility and should not be folded into the same review.
  Date/Author: 2026-05-28 / Codex.

- Decision: Replace Go's `VAR_TYPED_LIST_RE` path with `var_spec` traversal, but leave Go import-path parsing and declaration rendering unchanged.
  Rationale: `var_spec` gives the exact receiver names and declared type without line-sensitive regex parsing. Import module strings and user-facing signatures are not syntax classification in this milestone.
  Date/Author: 2026-05-28 / Codex.

- Decision: Limit the C++/C# milestone to parsed argument/initializer arity counting and record the larger source-text fallback clusters as follow-up candidates.
  Rationale: Comment-only argument lists are direct syntax facts and safe to classify from tree-sitter nodes. The remaining C++ fallback scans and analyzer rendering paths affect hit recovery, symbol spelling, and display output and should not be folded into this narrow cleanup.
  Date/Author: 2026-05-28 / Codex.

- Decision: Replace analyzer ES import clause parsing with tree-sitter node extraction, but leave CommonJS `require(...)` and import path strings on existing text logic.
  Rationale: ES import binding shape is available directly from `import_statement` children. CommonJS assignment/destructuring and path resolution are broader string-semantics areas and should not be mixed into this small cleanup.
  Date/Author: 2026-05-28 / Codex.

- Decision: Replace Scala typed-parameter receiver inference with tree-sitter `parameter` node extraction, and leave Java code unchanged in this milestone.
  Rationale: Scala parameter names and types are direct node fields, so this removes a brittle comma/colon text parser without changing receiver-inference policy. Java's remaining string logic is static import/path/signature normalization or analyzer display behavior rather than a small duplicated syntax classification path.
  Date/Author: 2026-05-28 / Codex.

## Outcomes & Retrospective

Initial outcome 2026-05-28: This ExecPlan exists and defines the epic as a sequence of evidence-backed language audits. No Rust behavior has changed yet. The next useful milestone is the PHP audit because it can turn the issue's seed examples into concrete follow-up issues or a first small cleanup PR.

PHP milestone outcome 2026-05-28: The first small PHP cleanup is implemented. `qualified_candidate_text` now ascends by PHP syntax node kinds instead of checking whether ancestor text looks like a qualified name, and constructor/function/constant classification uses tree-sitter parent nodes instead of raw adjacency helpers. The focused PHP usage graph test suite passed. Remaining PHP work should be split into follow-up issues for receiver/member regex inference and `TYPE_DECLARATION_RE` hierarchy parsing.

PHP follow-up issue outcome 2026-05-28: Created `#154`, "Replace PHP usage graph receiver/member regex scans with tree-sitter traversal", for `PARAMETER_VARIABLE_RE`, `ASSIGNMENT_RE`, `INSTANCE_MEMBER_RE`, `STATIC_MEMBER_RE`, and ordered local receiver inference. Created `#155`, "Replace PHP usage graph hierarchy regex with tree-sitter declaration traversal", for `TYPE_DECLARATION_RE` and `PhpHierarchyIndex::extend_file`.

Python milestone outcome 2026-05-28: The Python receiver fact collector now parses code-unit snippets with tree-sitter and collects parameter, annotation, and assignment events from syntax nodes. The old regexes `PARAM_NAME_RE`, `PARAM_ANNOTATION_RE`, and `ASSIGNMENT_RE` are no longer needed. The focused Python usage graph test suite passed, including a new regression for `x = Foo(\n)` followed by `x.bar()`.

Rust milestone outcome 2026-05-28: Rust member receiver inference now parses source with tree-sitter to collect type aliases, typed parameters, typed lets, constructor lets, simple aliases, `Option<T>` field types, and `let Some(name) = self.field.as_ref() else ...` bindings. The old receiver-inference regexes are no longer needed. The focused Rust usage graph test suite passed, including a new regression for `let a = Foo::new(\n); a.bar();`.

Go milestone outcome 2026-05-28: Go typed local receiver inference now walks tree-sitter `var_spec` nodes, including grouped and multiline declarations, instead of scanning declaration text with `VAR_TYPED_LIST_RE`. Import-path parsing and analyzer signature/source rendering remain intentionally text-based. The focused Go usage graph test suite passed, including a regression for multiline names with an inline comment before the receiver type.

C++/C# milestone outcome 2026-05-28: C# overload arity and C++ declaration constructor arity now count parsed argument/initializer nodes instead of scanning argument-list text. Comment-only constructor and method argument lists now stay zero-arity. Remaining C++ source-text fallback scans and analyzer display rendering are documented follow-up candidates rather than part of this cleanup.

JS/TS milestone outcome 2026-05-28: JavaScript and TypeScript analyzer import-info extraction now reads ES import bindings from tree-sitter nodes instead of splitting import clause text. CommonJS `require(...)` parsing, module path resolution, signature rendering, JSX/test detection, and clone/test regexes remain text-based or follow-up-only. The focused JS/TS import and usage graph suites passed.

Scala/Java milestone outcome 2026-05-28: Scala typed-parameter receiver inference now walks tree-sitter `parameters` and `parameter` nodes, reading `name` and `type` fields instead of splitting parameter-list text. The Scala cleanup preserves existing owner-visibility and shadowing policy while handling comments between `:` and the type. Java was audited and left unchanged because its usage graph already relies on tree-sitter for receiver/type/member syntax; static import strings, signature arity strings, type-name normalization, import paths, analyzer rendering, and test/clone heuristics remain intentionally text-based or broader follow-up-only areas.

Epic outcome 2026-05-28: The implemented small cleanups are PHP parent-node classification, Python receiver fact collection, Rust receiver inference, Go typed `var_spec` inference, C++/C# parsed arity counting, JS/TS ES import parsing, and Scala typed-parameter receiver inference. Dedicated PHP follow-up issues `#154` and `#155` track the two concrete larger PHP clusters. Remaining non-PHP follow-up issues are `#156` for Rust shadow/member/trait/visibility classification, `#157` for Scala qualifier/call-arity/value-binding/import helper cleanup, `#158` for JS/TS CommonJS `require(...)` parsing, and `#159` for C++ fallback scans and alias parsing. Import-path/rendering/test-smell string logic remains intentionally text-based unless a focused future bug shows otherwise.

## Context and Orientation

The repository root is the current `bifrost` checkout. The usage graph code lives under `src/analyzer/usages`. A usage graph strategy tries to find references to a target symbol by walking language-specific import, export, and syntax relationships. A tree-sitter node is a parsed syntax-tree node from the `tree_sitter` crate. It has a `kind`, byte range, parent, children, named children, and sometimes named fields supplied by the language grammar.

In this plan, a mini parser means source-text classification that decides syntax meaning with a regular expression, prefix or suffix probe, operator probe, manual character scanning, or brace and parenthesis splitting when tree-sitter already exposes the same fact through node kind, parent kind, child fields, sibling relationships, or an existing analyzer parse abstraction. A text operation is intentionally text-based when it renders snippets, normalizes symbol names, manipulates import paths or module strings, performs fallback search, or extracts exact source ranges after tree-sitter has already identified the syntax.

The key issue says to audit usage graph strategies under `src/analyzer/usages`, especially language-specific extractor and resolver modules, and analyzer implementations under `src/analyzer` where source regex or token probes duplicate information available from tree-sitter. The issue names the PHP helpers `has_token_before`, `has_operator_before`, `has_open_paren_after`, `qualified_candidate_text`, and related reference classification helpers as the first known example.

## Plan of Work

Begin every implementation session from the issue branch. If the worktree is detached, reattach it with:

    git checkout 141-epic-replace-analyzer-and-usage-graph-mini-parsers-with-tree-sitter-classification

Then update the branch:

    git fetch
    git rebase origin/master

Milestone 1 is the PHP audit. This milestone has completed its first narrow cleanup: source adjacency helpers for constructor, function, constant, member/scoped, and declaration classification have been replaced with tree-sitter parent-node checks. The remaining PHP work is now tracked in issue `#154` for receiver/member regex inference and issue `#155` for `TYPE_DECLARATION_RE` hierarchy parsing.

Milestone 2 is the Python audit. This milestone has completed its cleanup: `collect_scope_facts_from_source` now uses tree-sitter to collect parameter, annotation, assignment, constructor, and alias events while preserving the existing fixed-point local inference behavior. Remaining Python text handling in `normalized_receiver_type`, `receiver_annotation_matches_target`, module-name resolution, and import strings is intentional normalization rather than syntax discovery.

Milestone 3 is the Rust audit. This milestone has completed its receiver-inference cleanup: `LET_TYPED_RE`, `LET_CONSTRUCTED_RE`, `LET_ALIAS_RE`, `PARAM_TYPED_RE`, `TYPE_ALIAS_RE`, `OPTION_FIELD_RE`, and `SELF_FIELD_AS_REF_LET_ELSE_RE` have been replaced by tree-sitter traversal. Remaining Rust follow-up candidates are tracked in `#156`: `detect_shadowed_names`, member call/static hit regex matching, `TRAIT_IMPL_RE`, and string-prefix visibility/trait checks in `src/analyzer/usages/rust_graph/resolver.rs` and `src/analyzer/rust/graph_support.rs`.

Milestone 4 is the Go audit. This milestone has completed its cleanup: `VAR_TYPED_LIST_RE` has been replaced with tree-sitter `var_spec` traversal for typed local receiver inference. Remaining Go text handling in import-path resolution, module name derivation, and analyzer declaration signature/source rendering is intentional string semantics or display shaping rather than syntax discovery.

Milestone 5 is the C++ and C# audit. This milestone has completed its narrow cleanup: C# argument counting and C++ declaration constructor arity now use tree-sitter argument/initializer nodes. Remaining C++ follow-up candidates are tracked in `#159`: text constructor/operator/member fallback scans, textual owner context, alias statement fallback parsing, and analyzer signature rendering if a focused bug requires it. C# declaration signature/literal rendering and using/import string parsing remain intentionally text-based.

Milestone 6 is the JS/TS audit. This milestone has completed its narrow cleanup: analyzer ES import clause extraction now uses tree-sitter `import_statement` nodes. The usage graph import/export binder was already node-based. Remaining CommonJS `require(...)` import parsing is tracked in `#158`. Module specifier/path resolution, analyzer signature rendering, JSX/test detection, and clone/test regexes remain intentionally text-based.

Milestone 7 is the Scala and Java audit. This milestone has completed its narrow cleanup: Scala typed-parameter receiver inference now reads tree-sitter `parameter` node `name` and `type` fields. Remaining Scala follow-up candidates are tracked in `#157`: qualifier-before source scans, call-arity text parsing, value-binding text fallback parsing, constructor type-name text normalization, and Scala import group/path string parsing. Java remains unchanged because the usage graph already uses tree-sitter for the direct receiver/type/member syntax in scope; Java static import strings, signature arity strings, type-name normalization, import path logic, analyzer rendering, and test/clone heuristics are intentionally text-based or broader follow-up-only areas.

When a candidate becomes a follow-up issue, include the language, affected files, the brittle text operation, a short example of syntax it is trying to classify, the suggested tree-sitter replacement direction, and the focused test command. If using `gh issue create`, do it only after the audit has enough concrete evidence.

## Concrete Steps

Use these commands from the repository root:

    git status --short --branch
    git fetch
    git rebase origin/master

To refresh the initial inventory, run:

    rg -n "has_token_before|has_operator_before|has_open_paren_after|qualified_candidate_text|PARAMETER_VARIABLE_RE|ASSIGNMENT_RE|INSTANCE_MEMBER_RE|STATIC_MEMBER_RE|TYPE_DECLARATION_RE" src/analyzer/usages/php_graph
    rg -n "PARAM_ANNOTATION_RE|PARAM_NAME_RE|ASSIGNMENT_RE|LET_TYPED_RE|LET_CONSTRUCTED_RE|LET_ALIAS_RE|PARAM_TYPED_RE|TYPE_ALIAS_RE|OPTION_FIELD_RE|SELF_FIELD_AS_REF_LET_ELSE_RE|VAR_TYPED_LIST_RE" src/analyzer/usages/{python_graph,rust_graph,go_graph}
    rg -n "LazyLock<Regex>|Regex::new|trim_start\\(\\)\\.starts_with|split\\('\\{|split\\(\"\\{\" src/analyzer/usages src/analyzer -g '*.rs'

During each milestone, update `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` before stopping. If the milestone creates follow-up issues, paste the issue URLs or numbers into `Outcomes & Retrospective` and keep the summary short enough that a future contributor can resume from this file alone.

## Validation and Acceptance

The ExecPlan-only change is accepted when this file exists, follows `.agent/PLANS.md`, and contains enough concrete audit evidence for the next contributor to start with PHP without external context.

For a language cleanup that edits Rust code, run the focused test for that language. The expected result is that the new or existing regression test fails before the cleanup if it exposes a bug, then passes after the cleanup, or that existing focused tests continue to pass for behavior-preserving refactors. Use these commands as the default focused validations:

    cargo test --test usages_php_graph_test
    cargo test --test usages_python_graph_test
    cargo test --test usages_rust_graph_test
    cargo test --test usages_go_graph_test
    cargo test --test usages_cpp_graph_test
    cargo test --test usages_csharp_graph_test
    cargo test --test usages_js_ts_graph_test
    cargo test --test usages_scala_graph_test
    cargo test --test usages_java_graph_test

If analyzer implementation files under `src/analyzer/<language>` change, also run the matching analyzer tests, such as:

    cargo test --test php_analyzer_test --test php_analyzer_update_test

At the end of a cleanup PR, run:

    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings

Do not run the full clippy command for a documentation-only update unless the branch already contains Rust code changes that need final validation.

## Idempotence and Recovery

The audit steps are safe to repeat. `rg` commands only read files, and the language test commands only build and run tests. If a rebase fails, resolve the conflict by preserving the newest `origin/master` behavior and then reapply this plan's documentation or language-local cleanup. Do not use `git reset --hard` or discard unrelated user changes.

When replacing a mini parser, keep the old behavior visible in tests before removing the helper. Prefer additive tests first, then change the implementation. If a tree-sitter rewrite changes hit ranges, enclosing code-unit selection, or fallback behavior unexpectedly, stop and record the discovery in this plan before continuing.

## Artifacts and Notes

Initial PHP inventory:

    src/analyzer/usages/php_graph/resolver.rs:158 TYPE_DECLARATION_RE
    src/analyzer/usages/php_graph/resolver.rs:241 qualified_candidate_text
    src/analyzer/usages/php_graph/resolver.rs:343 has_token_before
    src/analyzer/usages/php_graph/resolver.rs:351 has_operator_before
    src/analyzer/usages/php_graph/resolver.rs:359 has_open_paren_after
    src/analyzer/usages/php_graph/extractor.rs:75 PARAMETER_VARIABLE_RE
    src/analyzer/usages/php_graph/extractor.rs:82 ASSIGNMENT_RE
    src/analyzer/usages/php_graph/extractor.rs:87 INSTANCE_MEMBER_RE
    src/analyzer/usages/php_graph/extractor.rs:92 STATIC_MEMBER_RE

PHP cleanup validation:

    cargo test --test usages_php_graph_test
    test result: ok. 26 passed; 0 failed; 0 ignored

Initial Python, Rust, and Go inventory:

    src/analyzer/usages/python_graph/extractor.rs:580 PARAM_ANNOTATION_RE
    src/analyzer/usages/python_graph/extractor.rs:582 PARAM_NAME_RE
    src/analyzer/usages/python_graph/extractor.rs:585 ASSIGNMENT_RE
    src/analyzer/usages/rust_graph/extractor.rs:291 LET_TYPED_RE
    src/analyzer/usages/rust_graph/extractor.rs:295 LET_CONSTRUCTED_RE
    src/analyzer/usages/rust_graph/extractor.rs:301 LET_ALIAS_RE
    src/analyzer/usages/rust_graph/extractor.rs:305 PARAM_TYPED_RE
    src/analyzer/usages/rust_graph/extractor.rs:309 TYPE_ALIAS_RE
    src/analyzer/usages/rust_graph/extractor.rs:313 OPTION_FIELD_RE
    src/analyzer/usages/rust_graph/extractor.rs:317 SELF_FIELD_AS_REF_LET_ELSE_RE
    src/analyzer/usages/go_graph/extractor.rs:544 VAR_TYPED_LIST_RE

Python cleanup validation:

    cargo test --test usages_python_graph_test
    test result: ok. 53 passed; 0 failed; 3 ignored

Rust cleanup validation:

    cargo test --test usages_rust_graph_test
    test result: ok. 57 passed; 0 failed; 0 ignored

Go cleanup validation:

    cargo test --test usages_go_graph_test
    test result: ok. 29 passed; 0 failed; 0 ignored

C++/C# cleanup validation:

    cargo test --test usages_csharp_graph_test
    test result: ok. 25 passed; 0 failed; 0 ignored
    cargo test --test usages_cpp_graph_test
    test result: ok. 25 passed; 0 failed; 0 ignored

JS/TS cleanup validation:

    cargo test --test javascript_import_test
    test result: ok. 6 passed; 0 failed; 0 ignored
    cargo test --test typescript_import_test
    test result: ok. 3 passed; 0 failed; 0 ignored
    cargo test --test usages_js_ts_graph_test
    test result: ok. 23 passed; 0 failed; 3 ignored

## Interfaces and Dependencies

This plan does not require a public API change. Future cleanup issues should prefer private helper functions inside the language module being changed. A helper should accept `tree_sitter::Node` when it needs syntax structure and should accept `&str` source only when it needs exact source text for byte ranges, rendered snippets, or names that tree-sitter stores only as source spans.

If a shared abstraction becomes justified after at least two language cleanups need the same shape, place it under `src/analyzer/usages` only when it is usage-graph-specific. Place it under `src/analyzer` only when normal analyzer implementations outside the usage graph also need it. Keep any new helper small, object-free, and explicit about the tree-sitter node kinds it expects.

Revision note 2026-05-28: Created this ExecPlan from the GitHub issue and initial repository audit so the epic can proceed language by language instead of as an omnibus rewrite.

Revision note 2026-05-28: Recorded the first PHP cleanup, its validation result, and the remaining PHP follow-up clusters after replacing raw adjacency checks with tree-sitter parent-node classification.

Revision note 2026-05-28: Added the GitHub issue numbers for the two PHP follow-up clusters created from the completed PHP audit.

Revision note 2026-05-28: Recorded the Python cleanup, its validation result, and the decision to keep receiver type-expression normalization text-based while replacing syntax discovery with tree-sitter traversal.

Revision note 2026-05-28: Recorded the Rust receiver-inference cleanup, its validation result, and the remaining Rust mini-parser follow-up candidates.

Revision note 2026-05-28: Recorded the Go typed local receiver cleanup, its validation result, and the decision to keep Go import-path and declaration rendering text-based.

Revision note 2026-05-28: Recorded the C++/C# arity cleanup and the remaining C++ source-text fallback follow-up candidates.

Revision note 2026-05-28: Recorded the JS/TS ES import-node cleanup and the decision to keep CommonJS, path, signature, JSX/test, and clone/test text handling out of this pass.
