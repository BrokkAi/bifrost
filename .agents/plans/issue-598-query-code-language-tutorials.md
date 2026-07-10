# Build proven per-language `query_code` tutorials for issue #598

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document must be maintained in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

Bifrost users can already query a normalized, language-neutral syntax model through `query_code`, but the public documentation does not teach how recognizable source constructs in each supported language map to that model. After this work, users can open a tutorial for any current structural adapter, copy either an RQL or JSON query, and compare the result with an output that is continuously exercised against the real matcher.

The tutorial suite covers Python, Java, JavaScript, TypeScript, Go, C and C++ through the shared `cpp` adapter, Rust, PHP, Scala, C#, and Ruby. Across the suite, every public normalized kind and role is used in a positive executable query. Each page records the date on which its fixtures, queries, exact output, and rendered layout were last verified.

## Progress

- [x] (2026-07-10 13:17Z) Milestone 0: added this ExecPlan, the tutorial index/navigation, and the executable Markdown harness; focused Rust/docs tests, Astro check/build, and a fresh styled preview passed.
- [x] (2026-07-10 13:21Z) Milestone 1: published and verified the Python tutorial with exact filtered-call, decorated-assignment, and callable-exclusion results; focused/docs/build/render checks passed.
- [x] (2026-07-10 13:25Z) Milestone 2: published and verified the Java tutorial with member-call narrowing, annotated constructors, exception/control-flow descendants, and the exact unsupported-kwargs diagnostic.
- [x] (2026-07-10 13:28Z) Milestone 3: published and verified the JavaScript tutorial with receiver/context narrowing, arrow/new matching, anonymous class-expression field access, and unsupported kwargs.
- [x] (2026-07-10 13:31Z) Milestone 4: published and verified TypeScript-only declarations/class-like forms, decorated callable exclusions, and TSX path/language scoping.
- [x] (2026-07-10 13:34Z) Milestone 5: published and verified Go call exclusion with `not_has`, multi-value assignment roles, grouped import paths, and keyword/decorator diagnostics.
- [x] (2026-07-10 13:36Z) Milestone 6: published and verified shared C/C++ filtering, initializer roles/literals, C++ member calls, out-of-line constructors, and includes through `cpp`.
- [ ] Milestone 7: publish and verify the Rust tutorial.
- [ ] Milestone 8: publish and verify the PHP tutorial.
- [ ] Milestone 9: publish and verify the Scala tutorial.
- [ ] Milestone 10: publish and verify the C# tutorial.
- [ ] Milestone 11: publish and verify the Ruby tutorial.
- [ ] Milestone 12: enforce aggregate kind/role/page coverage and complete publication validation.

## Surprises & Discoveries

- Observation: The Bifrost MCP code-intelligence endpoints named by the repository skills were not exposed in the planning session.
  Evidence: Repository exploration used the skills' documented `rg` and exact-source fallback instead.

- Observation: `npm --prefix docs run dev` left a listening Astro process that served stale content even though `astro dev status` reported no active server.
  Evidence: The browser still showed a removed duplicate heading. Killing that process, rebuilding with `PUBLIC_DOCS_BASE=/`, and serving the fresh static output produced the current single-heading styled page.

- Observation: Python does not advertise `constructor` precision, so putting `constructor` in `not_kind` produces a capability diagnostic even when the intended match is a method.
  Evidence: The first callable example returned `structural adapter for python does not support kind(s): constructor`; narrowing the exclusion to `lambda` preserved the intended named-callable lesson without an unrelated diagnostic.

- Observation: JavaScript class expressions assigned to variables are emitted as `class` facts but do not inherit the variable binding as their normalized `name`.
  Evidence: `kind: class, name: Inline` returned no match, while `text: {regex: "^class \\{"}` plus a structured field-access descendant matched the class expression and returned enclosing symbol `app.js.Inline`.

- Observation: Go import `module` roles expose the imported path, not the local alias.
  Evidence: The grouped `log "fmt"` fixture did not match module `log`; module `fmt` matched the enclosing grouped import exactly.

## Decision Log

- Decision: Publish one page per structural adapter entry, with C and C++ sharing one page.
  Rationale: Each page remains focused and independently verifiable, while accurately reflecting that C-family files use the `cpp` adapter and filter.
  Date/Author: 2026-07-10 / dave + Codex.

- Decision: “Every node type” means every public `NormalizedKind`, not every grammar-specific tree-sitter node.
  Rationale: `query_code` deliberately hides grammar node names behind normalized adapters; documenting raw grammar nodes would teach an interface users cannot query.
  Date/Author: 2026-07-10 / dave + Codex.

- Decision: Every published case contains source, paired RQL and JSON, and exact serialized output linked by Markdown markers.
  Rationale: Parsing examples alone would not prove adapter behavior, exclusions, captures, enclosing symbols, or diagnostics.
  Date/Author: 2026-07-10 / dave + Codex.

- Decision: Real adapter or query-language defects stop tutorial work and land separately from current master before this branch is rebased and resumed.
  Rationale: Tutorials must not normalize bugs or recommend filters that mask missing structured support.
  Date/Author: 2026-07-10 / dave + Codex.

## Outcomes & Retrospective

Milestone 0 established the publication and proof infrastructure. The marker-contract test reached the real Python adapter and caught a deliberately omitted module-level `enclosing_symbol`, proving exact output comparison rather than parse-only validation. The tutorial index builds without diagnostics and was visually verified with current navigation, one page title, and loaded styles.

Milestone 1 published Python's tutorial with three exact cases. The member-call case proves simultaneous path/language/receiver/callee/argument/keyword/containment filtering; the decorated method case proves decorators plus nested assignment left/right roles; the callable case proves subtype-aware matching and lambda exclusion. Its focused executable test, existing docs tests, Astro check/build, and fresh styled preview with ten non-overflowing code blocks passed.

Milestone 2 published Java's tutorial with six exact cases. It distinguishes two same-name calls by receiver, captures an annotated constructor, queries catch/if/loop nodes by throw/return descendants, and records the adapter's precise unsupported-kwargs diagnostic. Focused and existing docs tests, Astro check/build, and a fresh rendered-page check passed; expected output was expanded from authoring-friendly one-line JSON to readable blocks, reducing horizontal overflow from seven blocks to two unavoidable source/query lines.

Milestone 3 published JavaScript's tutorial with four exact cases: same-name call narrowing by receiver and enclosing method, a captured arrow containing a normalized `new` call, an anonymous class expression containing a specific field access, and the unsupported-kwargs diagnostic. Focused/docs tests, Astro check/build, and a fresh route/navigation/date/code-block inspection passed.

Milestone 4 published TypeScript's tutorial with exact type-alias, interface/enum/abstract-class, decorated callable, and TSX call results. It proves `.tsx` participates in the `typescript` filter and uses path scoping to isolate it. Focused/docs tests, both production and root-based preview builds, and a fresh rendered route/navigation/date/code-block inspection passed.

Milestone 5 published Go's tutorial with exact `not_has` call exclusion, ordered captures, structured multi-value assignment left/right roles, grouped import-path matching, and separate unsupported kwargs/decorators diagnostics. Focused/docs tests, production and root-preview builds, and the fresh rendered Go route passed.

Milestone 6 published the shared C/C++ tutorial with exact cross-extension `cpp` results, C and C++ initializer assignments with identifier/numeric roles, a `.cpp`-scoped member call, an out-of-line constructor, and a preprocessor include. Focused/docs tests, production/root-preview builds, and the fresh C/C++ route/navigation/date inspection passed.

## Context and Orientation

The public structural vocabulary lives in `src/analyzer/structural/kinds.rs`. `CodeQuery` and its JSON/RQL decoders live under `src/analyzer/structural/query/`; execution and serialized output live in `src/analyzer/structural/search.rs`. Each language maps tree-sitter syntax into normalized facts in `src/analyzer/<language>/structural.rs`, with JavaScript and TypeScript sharing `src/analyzer/js_ts/structural.rs`.

The existing reference documentation is `docs/src/content/docs/code-querying.md`, `docs/src/content/docs/code-query-json.md`, and `docs/src/content/docs/rune-query-language.md`. The new cookbook lives under `docs/src/content/docs/code-query-tutorials/`. `tests/code_query_docs.rs` validates the reference examples; `tests/code_query_tutorials.rs` validates the new executable tutorial contract using the shared `InlineTestProject` harness from `tests/common/inline_project.rs`.

A normalized kind is a language-neutral syntax category such as `call`, `method`, or `string_literal`. A role is a named relationship from a fact to another syntax node, such as `callee`, `receiver`, `args`, or `right`. Abstract kinds are subtype-aware: a query for `callable` can match a function or method, and a query for `literal` can match a string or numeric literal.

## Plan of Work

Milestone 0 adds this living document, an index linked from the Code Querying overview and sidebar, and a Markdown harness. Marked fixture blocks become an `InlineTestProject`. Each named case must provide RQL, JSON, and expected JSON blocks. The harness parses both query representations, compares canonical JSON, executes both against one analyzer snapshot, compares their serialized results, and finally compares the result with the documented exact output.

Milestones 1 through 11 add one language page and one focused integration test apiece. Every page contains realistic distractors so exact output proves both inclusion and exclusion. The examples progress from a broad query to meaningful narrowing and include captures, enclosing symbols, supported language-specific roles, and explicit diagnostics or precision boundaries. After its test and a fresh rendered-page inspection pass, the page receives its visible last-verified date and the milestone is committed.

Milestone 12 adds aggregate assertions for the exact tutorial page set, all entries of `ALL_KINDS`, and all entries of `ALL_ROLES`. The index gains a coverage matrix mapping kinds and roles to executable cases. Final validation exercises structural unit and integration suites, the complete Rust suite with semantic indexing disabled, no-CUDA clippy, Astro checking/building, and every rendered tutorial route.

## Milestones

Python teaches decorators, methods, keyword arguments, imports, assignments, literals, containment, receiver/callee filtering, and callable subtype exclusions. Java teaches annotations, constructors, object creation, member calls, exceptions, control flow, and the unsupported-kwargs diagnostic. JavaScript teaches functions, methods, constructors, arrows, class expressions, imports, member access, and receiver/context exclusions. TypeScript adds interfaces, enums, abstract classes, type aliases, decorators, constructors, TSX, and `not_kind` callable refinement.

Go teaches selector calls, grouped imports, multi-value and short assignments, methods, type declarations, function literals, scoping, and unsupported keyword/decorator roles. C/C++ proves that `.c` and `.cpp` both use `languages: ["cpp"]`, then teaches path isolation, member and scoped calls, `new`, includes, aliases, lambdas, methods, and constructors. Rust teaches turbofish/scoped calls, method receivers, grouped uses, traits, closures, const/static/compound assignments, signed literals, and its unsupported kinds/roles.

PHP teaches instance/nullsafe/static/object-creation calls, named arguments, attributes, namespace imports, constructors, assignment forms, and why trait `use` is not an import. Scala teaches generic/receiver/named/block calls, annotations, imports, methods, lambdas, and why named arguments are not assignments. C# teaches object creation, null-conditional access, named arguments, attributes, constructors, local functions, properties, records, and aliases. Ruby teaches receiver/keyword calls, blocks, singleton and instance methods, qualified declarations, static imports, and the boundaries around receiver `require`, interpolated imports, and decorators.

## Concrete Steps

At the beginning and after any separately landed fix, run from the repository root:

    git fetch origin
    git rebase origin/master
    git status --short --branch

For each language milestone, run:

    BIFROST_SEMANTIC_INDEX=off cargo test --test code_query_tutorials <language>_tutorial -- --nocapture
    BIFROST_SEMANTIC_INDEX=off cargo test --test code_query_docs
    npm --prefix docs run check
    npm --prefix docs run build
    cargo fmt --check
    git diff --check

Inspect the new page from a fresh Astro server on a confirmed-free port. Update this plan's living sections, stage only that milestone's files, and commit with a multiline message explaining the behavior and proof.

For final validation, run:

    BIFROST_SEMANTIC_INDEX=off cargo test structural --lib
    BIFROST_SEMANTIC_INDEX=off cargo test --test code_query_docs --test code_query_tutorials --test structural_search_python --test structural_search_planner --test structural_search_cross_language
    BIFROST_SEMANTIC_INDEX=off cargo test
    PATH=/Users/dave/.cargo/bin:$PATH cargo clippy-no-cuda
    npm --prefix docs run check
    npm --prefix docs run build
    git diff --check

## Validation and Acceptance

All eleven pages must be reachable from the overview, index, and sidebar. Every marked query must parse in both representations, lower identically, execute identically, and match its complete documented output. The aggregate test must prove that every public normalized kind appears in a positive `kind` predicate and every role is exercised. C and C++ must both be found through `cpp`. Unsupported behavior must produce the documented capability diagnostic. Each page's visible date must reflect the day its executable and rendered checks passed.

## Defect Stop-the-Line Workflow

When a case disagrees with expected behavior, first reduce it to a minimal fixture and decide whether the prose/query is wrong or the engine is wrong. Correct documentation mistakes in the active milestone. For an engine defect, record the evidence here, pause the milestone, and create a separate worktree and focused branch from current `origin/master`. Add a failing behavior test, fix the structured root cause without text scanning, validate and land the fix, then fetch/rebase this branch and rerun every completed tutorial test before resuming.

## Idempotence and Recovery

All tutorial tests use temporary inline projects and are safe to rerun. Docs builds write only ignored artifacts. Keep the branch bisectable through one verified commit per milestone. Do not use `git add -A`; stage only explicit files. If a rebase conflict would change documented semantics, stop and resolve the underlying behavioral decision before continuing.

## Artifacts and Notes

The branch began implementation after rebasing onto `origin/master` commit `0118fc9b`. Store concise test counts, rendered-route checks, important output discoveries, and milestone commit hashes in the living sections above.

## Interfaces and Dependencies

No production API or dependency changes are planned. The test-only Markdown contract uses fixture markers, named RQL/JSON/expected case markers, and the existing `CodeQuery`, `execute`, `WorkspaceAnalyzer`, `InlineTestProject`, and `serde_json` APIs. The final public additions are documentation routes only.

Revision note, 2026-07-10: Initial ExecPlan created from issue #598, current adapter/reference sources, and the decisions to use separate pages, exhaustive normalized-kind coverage, exact executable outputs, and separately landed engine fixes.

Revision note, 2026-07-10: Updated after Milestone 0 with the passing harness/docs evidence and stale-preview discovery.

Revision note, 2026-07-10: Updated after Milestone 1 with Python's exact outputs, constructor-capability discovery, and rendered-page evidence.

Revision note, 2026-07-10: Updated after Milestone 2 with Java's exact call/constructor/control-flow/diagnostic results and rendered readability check.

Revision note, 2026-07-10: Updated after Milestone 3 with JavaScript's exact outputs, anonymous-class name boundary, and rendered-page evidence.

Revision note, 2026-07-10: Updated after Milestone 4 with TypeScript declaration/refinement/TSX results and rendered-page evidence.

Revision note, 2026-07-10: Updated after Milestone 5 with Go's exact results, import-path/alias boundary, and rendered-page evidence.

Revision note, 2026-07-10: Updated after Milestone 6 with the shared `cpp` filter, exact C/C++ results, and rendered-page evidence.
