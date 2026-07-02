# Issue #328: `search_ast` — normalized structural query language and matcher (v1)

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document must be maintained in accordance with `.agent/PLANS.md` (repository root: `.agent/PLANS.md`).

Upstream discussion: https://github.com/BrokkAi/bifrost/issues/328


## Purpose / Big Picture

Bifrost can find declarations and usages of *named symbols*, but it cannot answer *structural* questions: "find every call to `eval`", "find every function decorated with `@route`", "find every assignment of a string literal to a variable named `password`", across all supported languages, without the caller knowing each tree-sitter grammar's node names (`call` vs `call_expression` vs `method_invocation`).

After this change, a user or agent can run:

    bifrost --tool search_ast --args '{
      "match": { "kind": "call", "callee": { "name": "eval" }, "args": [{ "capture": "code" }] }
    }'

against any workspace and get back structured matches: file path, line range, matched text, named captures, and the enclosing symbol — for every language whose structural adapter is implemented (Python first, then Java and JS/TS in this plan; other languages are additive follow-ups).

This is the foundation ("shared structural substrate") that a later rules engine (`bifrost --rules`, Semgrep-lite YAML) and a later `refactor_ast` edit layer will compile into. Those layers are explicitly *out of scope* here, but every design decision below is made so they can be added without reworking the matcher.

The query language is **JSON-first**. An S-expression surface for humans in a shell/REPL is a deferred final milestone; both syntaxes must parse into the *same* typed Rust IR (`AstQuery`), so the S-expression frontend is purely additive.


## Progress

- [x] (2026-07-02) Read issue #328 thread; surveyed analyzer/tool architecture; wrote this plan.
- [x] (2026-07-02) Milestone 1: kind vocabulary + query IR + JSON frontend + validation. `src/analyzer/structural/{mod,kinds,query}.rs` landed with 17 unit tests (`cargo test --lib analyzer::structural`); fmt + clippy clean.
- [x] (2026-07-02) Milestone 2: Python structural adapter + matcher + captures + containment; `search_ast` wired end-to-end (MCP descriptor in extended toolset, dispatch arm, provider capability on `IAnalyzer` with `MultiAnalyzer` fan-out). New files: `src/analyzer/structural/{facts,spec,extract,matcher,provider,search}.rs`, `src/analyzer/python/structural.rs`, `tests/structural_search_python.rs` (8 tests). CLI verified: `bifrost --tool search_ast --args '{"match":{"kind":"call","callee":{"name":"eval"},"args":[{"capture":"code"}]},"inside":{"kind":"callable","capture":"fn"}}'` returns the match with `$code`/`$fn` captures and `enclosing_symbol`; malformed queries return path-precise errors.
- [ ] Milestone 3: workspace planner — candidate pruning, parallel parse, moka facts cache, limits, enclosing symbols, capability diagnostics.
- [ ] Milestone 4: Java and JS/TS structural adapters; kwargs/decorators/annotations; cross-language acceptance tests.
- [ ] Milestone 5 (deferred): S-expression frontend compiling to the same `AstQuery`, with `--print-json` style canonical echo.


## Surprises & Discoveries

- Observation: every `TreeSitterAnalyzer` already retains the full source text of every analyzed file in memory (`FileState.source` in `src/analyzer/tree_sitter_analyzer.rs`), but drops parse trees after declaration indexing.
  Evidence: `FileState { pub(crate) source: String, ... }` at `src/analyzer/tree_sitter_analyzer.rs:150`; on-demand re-parse helper `parse_tree_sitter_file` in `src/analyzer/usages/parsed_tree.rs` reads from disk today.
  Implication: re-parsing on a facts-cache miss costs CPU only (no disk IO if we parse from `FileState.source`), and tree-sitter parses are typically well under a millisecond per average file. The "lots of re-parsing" worry is bounded by prune-then-parse plus a facts cache; we should not cache `tree_sitter::Tree`s (roughly 10x source size in memory).

- Observation: on this macOS machine the `cargo clippy-no-cuda` alias fails with `error: Unrecognized option: 'all-targets'` (the alias leaks `--all-targets` into clippy-driver), while the identical spelled-out command `cargo clippy --all-targets --features nlp,python -- -D warnings` — run with the rustup 1.96.0 toolchain bin first on PATH so homebrew's cargo/clippy-driver do not shadow it — passes cleanly.
  Evidence: M1 verification runs, 2026-07-02.


## Decision Log

- Decision: One canonical typed IR (`AstQuery` / `Pattern`); JSON and (later) S-expressions are peer *frontends* that parse into it. Neither syntax is the semantic authority.
  Rationale: agreed in the issue thread; avoids two matchers and makes `parse(json) == parse(sexp)` a testable property.
  Date/Author: 2026-07-02 / dave + issue thread.

- Decision: JSON is the v1 external surface (MCP, CLI, Python client). S-expressions are Milestone 5 and must not block v1.
  Rationale: agents/MCP/schema validation benefit from JSON; humans get S-expressions once the IR is stable. Explicit user direction.
  Date/Author: 2026-07-02 / dave.

- Decision: Normalized kinds form an explicit subtype hierarchy encoded in Rust (`NormalizedKind::parent()`), and kind matching is subtype-aware by default (`literal` matches `string_literal`); `kind_exact` opts out. The v1 hierarchy is deliberately shallow: two real branches (`declaration → callable → {function, method, constructor, lambda}`, and `literal → {string_literal, numeric_literal, boolean_literal, null_literal}`); everything else hangs off the implicit root.
  Rationale: exercises the subtype machinery that tree-sitter grammars also model (cf. Java `declaration` supertype in node-types.json) without over-modeling `expression`/`statement` splits that differ per language (e.g. assignment is an expression in JS, a statement in Python). Deepen only when a query needs it.
  Date/Author: 2026-07-02 / dave + issue thread ("Add normalized subtypes only when they unlock useful user queries").

- Decision: Orthogonal properties (anonymous, closure-ness, string interpolation, class-like form struct/interface/trait/enum) are *not* subtypes; they become optional predicate fields on patterns/facts in later iterations.
  Rationale: issue thread analysis — `lambda` vs `anonymous` vs `closure` answer different questions; forcing them into one inheritance chain breaks.
  Date/Author: 2026-07-02 / issue thread.

- Decision: Per-language mapping from normalized kind to tree-sitter node types is a static table of `(&'static str, NormalizedKind)` pairs per language, compiled once per grammar into a `Vec<Option<NormalizedKind>>` indexed by tree-sitter's numeric node-kind id (`Language::id_for_node_kind`), stored in a `OnceLock`. A unit test per language asserts every mapped node-kind name exists in the grammar (id != 0), so grammar bumps that rename nodes fail loudly.
  Rationale: O(1) per node during extraction walks; table-driven means adding a language is data plus a small role extractor, not new engine code.
  Date/Author: 2026-07-02 / dave.

- Decision: Role edges (callee/receiver/args/left/right/module/...) are extracted per language using tree-sitter AST *fields* (`child_by_field_name`) in a per-language `StructuralSpec`; no string splitting of source text, ever, per the design philosophy in CLAUDE.md.
  Rationale: repository design philosophy; fields carry the answer.
  Date/Author: 2026-07-02 / dave.

- Decision: Execution model is prune-then-verify. Cheap pruning (path globs, requested languages, and — for declaration kinds with a `name` equality predicate — the existing definition index) selects candidate files; candidates are parsed/extracted in a rayon per-file walk (trees dropped immediately, mirroring `src/analyzer/usages/inverted_edges.rs`); the matcher is the only thing that decides a match. Extracted per-file facts are cached in a moka byte-budget cache keyed by file and validated by a hash of the in-memory source, following the `JavaMemoCaches` idiom in `src/analyzer/java/cache.rs`.
  Rationale: matches Bifrost's "index declarations up front, everything else on demand" philosophy; the facts cache amortizes repeated agent queries; source-hash validation makes staleness harmless across analyzer updates.
  Date/Author: 2026-07-02 / dave.

- Decision: An optional literal-substring prefilter over the in-memory `FileState.source` (e.g. skip files that don't contain `eval` when the query anchors on `callee.name == "eval"`) is permitted as *candidate pruning only*, in Milestone 3. It can only ever skip files that provably cannot match a positive equality anchor; every surviving candidate is still structurally verified. It must never be used to *produce* results.
  Rationale: this is the standard Semgrep planning trick and does not violate CLAUDE.md's ban on regex/text fallbacks — the ban targets text scanning used *in place of* structured resolution; a conservative prefilter that only prunes cannot mask a structured failure. Negation (`not_has`, `not_inside`) must never prune — negative constraints are verifier-only.
  Date/Author: 2026-07-02 / dave + issue thread (jbellis: "Positive anchors ... should prune candidates. Negation ... verified after candidate files are reparsed").

- Decision: v1 languages are Python (M2), then Java and JS/TS (M4). Queries against workspaces containing other languages return per-language capability diagnostics ("no structural adapter for ruby yet") instead of silently returning nothing.
  Rationale: degraded support must be explicit (issue thread); three adapters prove the cross-language abstraction without boiling the ocean.
  Date/Author: 2026-07-02 / dave.

- Decision: Rules engine (`--rules`, YAML), `refactor_ast`, dataflow, and MCP rule-pack orchestration are out of scope for this plan.
  Rationale: issue thread layering agreement; `search_ast` is the substrate.
  Date/Author: 2026-07-02 / issue thread.

- Decision: Query JSON decoding is hand-rolled over `serde_json::Value` rather than serde-derived, and every `QueryError` carries the JSON path of the offending field (`match.callee.name.regex`).
  Rationale: precise error paths are the agent-self-correction story; cross-field rules (kind/kind_exact exclusivity, role-valid-for-kind, root-must-be-constrained) are validation logic serde derive cannot express cleanly.
  Date/Author: 2026-07-02 / dave (M1 implementation).

- Decision: Role sub-patterns require the pattern to *declare* a kind, and each role is validated against that kind (`callee` requires `call`; `decorators` accepts any callable/class/declaration kind). A role on a kindless pattern is rejected with a message telling the caller to add `kind`.
  Rationale: inferring `kind: call` from the presence of `callee` is tempting sugar but makes error cases ambiguous; explicit is cheaper for agents than clever.
  Date/Author: 2026-07-02 / dave (M1 implementation).

- Decision: Extraction is two-pass per file: pass 1 walks the tree iteratively creating facts with parent links and a tree-node→fact map, pass 2 re-visits each fact's node for role extraction so role edges can resolve to fact ids regardless of source order. Role targets carry `node: Option<u32>` (fact id) plus a raw span and derived name span; sub-pattern evaluation uses full fact semantics when the target is a fact, and degrades to name/text/capture-only against the span otherwise (kind or nested constraints then fail, they never guess).
  Rationale: keeps the matcher exact without normalizing every expression form; un-normalized targets (e.g. a dotted module path, a subscript callee) still support the predicates that make sense for them.
  Date/Author: 2026-07-02 / dave (M2 implementation).

- Decision: A call fact's own `name` is its callee's derived name, and Python `def`s directly inside a `class` body are refined from `function` to `method` via the spec's `refine_kind` hook (nearest-enclosing-fact kind, not raw tree parentage).
  Rationale: `{ "kind": "call", "name": "eval" }` reads naturally as sugar for the callee constraint; method-vs-function is exactly the "context property" the issue thread wanted without a per-language subtype fork.
  Date/Author: 2026-07-02 / dave (M2 implementation).

- Decision: `search_ast` lives in the `extended` toolset, first descriptor in the list; match/capture snippets in results are first-line-only, capped at 160 chars.
  Rationale: extended is the low-risk home while the tool stabilizes (the `symbol` toolset is the curated core surface); snippet caps keep rendered output within tool budgets — full content is always reachable via the returned line range.
  Date/Author: 2026-07-02 / dave (M2 implementation).


## Outcomes & Retrospective

(To be filled in as milestones complete.)


## Context and Orientation

Bifrost is a Rust workspace analyzer (`brokk-bifrost` crate, sources under `src/`). Key facts a novice needs:

- A *workspace* is a project root directory. `WorkspaceAnalyzer::build` (`src/analyzer/workspace.rs`) constructs one analyzer per detected language. Each language analyzer is `TreeSitterAnalyzer<A>` (`src/analyzer/tree_sitter_analyzer.rs`) parameterized by a `LanguageAdapter` (e.g. `src/analyzer/python/adapter.rs`) that supplies the tree-sitter grammar (`parser_language()`) and per-file declaration extraction. At build time every source file is parsed once; *declarations* are indexed as `CodeUnit`s (`src/analyzer/model.rs` — a symbol with file, kind Class/Function/Field/Module, package, short name); the parse tree is dropped but the file's full source text is retained in `FileState.source`.
- `CodeUnitType` (Class/Function/Field/Module/Macro/FileScope) is the *declaration* vocabulary. The normalized query kinds defined here are a *separate, finer* vocabulary covering expressions and statements too; where they overlap (function/class), the matcher can use the declaration index for pruning.
- Everything beyond declarations is computed on demand: usage graphs re-parse candidate files per query (`src/analyzer/usages/parsed_tree.rs`, `inverted_edges.rs`) inside rayon walks, and per-language memoization uses moka byte-weighted caches (`src/analyzer/java/cache.rs`).
- Optional per-language capabilities surface through accessor methods on the `IAnalyzer` trait (`src/analyzer/i_analyzer.rs`), e.g. `import_analysis_provider() -> Option<&dyn ImportAnalysisProvider>`; `MultiAnalyzer` (`src/analyzer/multi_analyzer.rs`) fans these out across languages.
- Search tools are exposed three ways from one dispatch point: MCP server, CLI (`bifrost --tool <name> --args '<json>'`, see `src/bin/bifrost.rs`), and PyO3. A tool is (a) a descriptor (name + JSON schema) in `src/mcp_core.rs` / `src/mcp_extended.rs`, registered per toolset in `src/mcp_registry.rs`, and (b) a match arm in `SearchToolsService::call_tool_output` (`src/searchtools_service.rs`) that decodes params and calls a function taking `&dyn IAnalyzer`-ish state. Tools return `ToolOutput` (structured JSON + rendered text; see `src/searchtools_render.rs`).
- Tests: integration tests live in `tests/`; small ad hoc multi-file projects use the shared inline harness `tests/common/inline_project.rs` (`InlineTestProject`) per CLAUDE.md. Never let tests spawn the semantic indexer: construct services with `SearchToolsService::new_without_semantic_index` or set `BIFROST_SEMANTIC_INDEX=off` when spawning the binary.
- CI checks: `cargo fmt` and, on machines without CUDA (macOS), `cargo clippy-no-cuda` (alias; do NOT use `--all-features` on macOS).

Terms used below:

- *Normalized kind*: a language-neutral node category (`call`, `function`, `string_literal`, ...) that each language maps its grammar-specific node types onto.
- *Role*: a named edge from a matched node to a sub-node (`callee`, `receiver`, `args`, `left`, `right`, `module`, ...), extracted from tree-sitter AST fields.
- *Fact*: one normalized node occurrence in a file (kind + range + name + role edges). *FileFacts* is the arena of all facts for one file.
- *Capture*: a user-chosen label on a sub-pattern; matches report the captured node's text and range under that label.


## The v1 query language (canonical JSON)

A query is a single JSON object:

    {
      "where": ["src/**/*.py"],          // optional path globs, relative to workspace root
      "languages": ["python"],           // optional language filter (config labels from Language::config_label)
      "match": { <pattern> },            // required root pattern
      "inside": { <pattern> },           // optional: root match must be lexically contained in a node matching this
      "not_inside": { <pattern> },       // optional: verifier-only negative containment
      "limit": 100                       // optional result cap (default 100, hard max 1000)
    }

A `<pattern>` is a JSON object with the fields below, all optional. The *root* `match` pattern must constrain at least one of `kind`/`kind_exact`/`name`/`text` (a wildcard root would match every node in the workspace); *nested* patterns (role sub-patterns, `args` entries) may be capture-only or even empty — the issue's own example uses `"args": [{ "capture": "code" }]`, and an empty `args` entry means "some argument exists". `inside`/`not_inside`/`has`/`not_has` patterns must be non-empty (an empty one would be vacuous).

    {
      "kind": "call",                    // subtype-aware normalized kind
      "kind_exact": "literal",           // exact-kind variant; mutually exclusive with "kind"
      "name": "eval",                    // string = exact match; or { "regex": "^handle.*" }
      "text": { "regex": "TODO" },       // predicate on the node's source text (regex only; use sparingly)
      "capture": "code",                 // label this node in results
      "has": { <pattern> },              // some descendant matches
      "not_has": { <pattern> },          // verifier-only: no descendant matches
      // role fields, valid only for kinds that define them:
      "callee": { <pattern> },           // call
      "receiver": { <pattern> },         // call
      "args": [ { <pattern> }, ... ],    // call: each listed pattern must match some positional arg,
                                         // in order but not necessarily contiguously (v1 semantics)
      "kwargs": { "shell": { <pattern> } },  // call: named/keyword arguments, where the language has them
      "left": { <pattern> },             // assignment
      "right": { <pattern> },            // assignment
      "module": { <pattern> },           // import
      "decorators": [ { <pattern> } ],   // function/method/class: each must match some decorator/annotation
      "object": { <pattern> },           // field_access
      "field": { <pattern> }             // field_access
    }

`name` semantics: for a declaration, its declared identifier; for an identifier node, its text; for a call's `callee` sub-pattern, the rightmost name component (so `subprocess.run(...)` has callee name `run` and receiver name `subprocess`) — derived from AST fields by the language adapter, never by splitting strings.

The v1 normalized kind hierarchy (subtype-aware matching walks child → parent):

    declaration
      callable
        function
        method
        constructor
        lambda
      class
      import
    call
    assignment
    field_access
    identifier
    literal
      string_literal
      numeric_literal
      boolean_literal
      null_literal
    return
    throw
    catch
    if
    loop
    decorator

Result shape (structured JSON; also rendered as text per SearchTools conventions):

    {
      "matches": [
        {
          "path": "src/app.py",
          "language": "python",
          "kind": "call",
          "range": { "start_line": 42, "end_line": 42 },
          "text": "eval(user_input)",
          "captures": { "code": { "text": "user_input", "start_line": 42 } },
          "enclosing_symbol": "app.handle_request"
        }
      ],
      "truncated": false,
      "diagnostics": [
        { "language": "ruby", "message": "no structural adapter; files skipped", "files_skipped": 12 }
      ]
    }

Malformed queries fail with a structured error naming the offending path in the JSON (e.g. `match.callee: role "callee" is not valid for kind "assignment"`), so agents can self-correct.


## Plan of Work

All new engine code lives in a new module `src/analyzer/structural/` with submodules; per-language mapping tables live next to each language's analyzer; tool glue follows the existing descriptor + dispatch pattern. In prose, the sequence is:

Milestone 1 builds the language-independent core: `kinds.rs` (the `NormalizedKind` enum, `Role` enum, `parent()` hierarchy, serde snake_case labels, `is_subtype_of`), and `query.rs` (the `AstQuery`/`Pattern` IR, `serde_json`-based decoding with strict unknown-field rejection, validation of role-vs-kind combinations, name/regex predicates using the `regex` crate, and canonical-form serialization back to JSON for the future `--print-json`). No matching yet.

Milestone 2 makes it real for Python: `facts.rs` (arena `FileFacts { nodes: Vec<NormalizedNode> }` with `u32` ids, parent ids for containment, role edge lists; no `Arc` per node), `extract.rs` (an iterative stack-based walk — CLAUDE.md forbids recursive tree walks — that consults a `StructuralSpec` for kind mapping and role extraction), `spec.rs` (the `StructuralSpec` trait: `kind_table() -> &'static [(&'static str, NormalizedKind)]`, `extract_roles(node, kind, ctx)`), the Python spec (`src/analyzer/python/structural.rs`), and `matcher.rs` (evaluate a `Pattern` against `FileFacts`, top-down with role recursion via explicit work stack; captures collected per match; `inside`/`has` via parent links / subtree scans). Wire a minimal `search_ast` tool (descriptor in `src/mcp_extended.rs`, dispatch arm in `src/searchtools_service.rs`, `StructuralSearchProvider` capability accessor on `IAnalyzer` implemented by `TreeSitterAnalyzer<A>` when `A` provides a spec, fan-out in `MultiAnalyzer`) that at this milestone parses every file of the language on each query — correctness first.

Milestone 3 adds the planner (`planner.rs`): apply `where` globs and `languages`; for declaration-kind roots with exact `name`, prune via the existing definition/lookup index; optional positive-anchor substring prefilter over `FileState.source`; rayon per-file execute; moka byte-budget facts cache keyed by `ProjectFile` with stored source-hash validation (hash the in-memory source with the crate's fast hash; compare on hit); `limit` with deterministic ordering (path, then start byte); enclosing symbol via `IAnalyzer::enclosing_code_unit_for_lines`; per-language capability diagnostics.

Milestone 4 adds Java (`src/analyzer/java/structural.rs`: `method_invocation` → call with `object`/`name`/`arguments` fields, annotations → decorator, etc.) and JS/TS (`src/analyzer/js_ts/structural.rs`, shared for both grammars, selecting the grammar per file via `js_ts_tree_sitter_language_for_file`), plus `kwargs` where languages have them (Python keyword arguments; none in Java — querying `kwargs` against Java yields a capability diagnostic, not silence).

Milestone 5 (deferred, do not start until M1–M4 land and the IR has survived contact with reality): S-expression frontend as a peer parser producing the same `AstQuery`, keyword-style regular syntax (`(:kind call :callee (:name "eval"))`), plus canonical-JSON echo. No macros, no evaluation, no programmability.


## Concrete Steps

Work from the repository root. After each milestone: `cargo fmt`, `cargo clippy-no-cuda`, run the tests below, then commit on the current branch with a multiline message explaining the why.

Milestone 1:

- Create `src/analyzer/structural/mod.rs`, `kinds.rs`, `query.rs`; register `pub mod structural;` in `src/analyzer/mod.rs`.
- Unit tests colocated (`#[cfg(test)]`) covering: every kind's serde label round-trips; subtype matching (`string_literal` satisfies `kind: "literal"`; `function` satisfies `callable` and `declaration`); JSON decode of the issue's example queries; rejection with precise error paths for unknown fields, unknown kinds, invalid role-for-kind, bad regex, `kind`+`kind_exact` conflict.
- Run: `cargo test structural` — expect the new tests to pass; the same command fails to compile before this milestone (module absent), which is the before/after signal.

Milestone 2:

- Files as per Plan of Work; add integration test `tests/structural_search_python.rs` using `InlineTestProject` with a few inline Python files; assert: `eval` call query returns the right file/line/capture; `inside` a function works; `args` capture text is exact; `assignment` with `right.kind = string_literal` finds `password = "hunter2"`; kind-table validation test asserts every Python table entry resolves via `Language::id_for_node_kind` (id != 0).
- Run: `cargo test structural` and `cargo test --test structural_search_python`.
- CLI smoke: in any scratch Python project, `bifrost --tool search_ast --args '{"match":{"kind":"call","callee":{"name":"eval"}}}'` prints matches (build the binary with `cargo build`; set `BIFROST_SEMANTIC_INDEX=off` in the environment).

Milestone 3:

- Planner + cache + diagnostics as above; tests in `tests/structural_search_planner.rs`: `where` glob excludes files; `limit` truncates with `truncated: true`; second identical query hits the facts cache (assert via a counter hook or by timing-free cache stats API); a workspace containing an unsupported language reports the diagnostic; negation (`not_inside`) never prunes (construct a case where the anchor prefilter would wrongly skip if applied to negation).

Milestone 4:

- Java + JS/TS specs and role extractors; extend the cross-language test to assert the *same* JSON query (`call` with `callee.name = "eval"`; `assignment` of string literal to `password`; `decorators` on functions) finds the expected shapes in `.py`, `.java`, `.ts` inline files in one `InlineTestProject`.

Milestone 5 (deferred): S-expression parser + `parse(json) == parse(sexp)` property tests over the documented mapping table from the issue thread.


## Validation and Acceptance

Acceptance for the plan as a whole (after M4): in a workspace containing Python, Java, and TypeScript files, running the single query

    bifrost --tool search_ast --args '{"match":{"kind":"call","callee":{"name":"eval"},"args":[{"capture":"code"}]},"inside":{"kind":"callable","capture":"fn"}}'

returns, for each language, the call sites with the `code` capture bound to the first argument's source text, `fn` bound to the enclosing callable, correct line ranges, and `enclosing_symbol` set — plus a diagnostics entry for any workspace language lacking an adapter. All of `cargo fmt --check`, `cargo clippy-no-cuda`, and `cargo test` pass.


## Idempotence and Recovery

All milestones are additive (new module, new tool name, new test files); nothing rewrites existing behavior, so any milestone can be re-run or reverted file-by-file. If a grammar bump renames node kinds, the per-language kind-table test fails and pinpoints the stale entry. The facts cache is validated by source hash, so stale entries are self-healing; deleting the cache is never required for correctness.


## Interfaces and Dependencies

No new crate dependencies: `serde`/`serde_json` (IR + frontend), `regex` (predicates), `tree-sitter` + existing grammar crates (extraction), `moka` (facts cache), `rayon` (parallel walk), `glob` (where-clauses) are all already in `Cargo.toml`.

Key signatures that must exist at the end of M2 (names may be refined, semantics may not):

In `src/analyzer/structural/kinds.rs`:

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum NormalizedKind { Declaration, Callable, Function, Method, Constructor, Lambda, Class, Import, Call, Assignment, FieldAccess, Identifier, Literal, StringLiteral, NumericLiteral, BooleanLiteral, NullLiteral, Return, Throw, Catch, If, Loop, Decorator }

    impl NormalizedKind {
        pub fn parent(self) -> Option<NormalizedKind>;
        pub fn satisfies(self, query_kind: NormalizedKind) -> bool; // walks parent chain
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum Role { Callee, Receiver, Arg, Kwarg, Left, Right, Module, Decorator, Object, Field, Name }

In `src/analyzer/structural/query.rs`:

    pub struct AstQuery { pub where_globs: Vec<String>, pub languages: Vec<Language>, pub root: Pattern, pub inside: Option<Pattern>, pub not_inside: Option<Pattern>, pub limit: usize }
    pub struct Pattern { /* kind selector, name/text predicates, capture, has/not_has, role sub-patterns */ }
    impl AstQuery {
        pub fn from_json(value: &serde_json::Value) -> Result<Self, QueryError>; // QueryError carries a JSON path string
        pub fn to_canonical_json(&self) -> serde_json::Value;
    }

In `src/analyzer/structural/spec.rs` (implemented by each language's `structural.rs`):

    pub trait StructuralSpec: Send + Sync + 'static {
        fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)];
        fn extract_roles(&self, node: tree_sitter::Node<'_>, kind: NormalizedKind, out: &mut RoleSink<'_>);
    }

In `src/analyzer/i_analyzer.rs` (default `None`; implemented by `TreeSitterAnalyzer<A>` when the adapter provides a spec; fan-out in `MultiAnalyzer`):

    fn structural_search_provider(&self) -> Option<&dyn StructuralSearchProvider>;

`StructuralSearchProvider` exposes the language, the file list, per-file facts (through the cache), and access to in-memory source for parsing — the planner in `src/analyzer/structural/planner.rs` is the only consumer.
