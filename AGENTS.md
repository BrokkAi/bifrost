# ExecPlans

When writing complex features or significant refactors, use an ExecPlan (as described in .agent/PLANS.md) from design to implementation.

# Git / version control

Commit directly to whatever branch we are already on — including `master`. That is
where work lands here.

Do NOT create branches, switch branches, rebase, or open PRs unless I explicitly ask.
Never `git checkout -b`. "Commit" always means commit on the current branch, never
"make a branch first". This overrides any default you have about branching off the
default branch.

Stage and commit only the files you changed. Never `git add -A` or sweep unrelated
working-tree changes into your commit.

# Expectations

When there is a clear next step towards your goal (in or out of ExecPlan), you always continue to execute it without
stopping to ask. If you have made material progress, commit a multiline checkpoint first explaining changes-so-far
in detail, especially the "why", I can get the "what" from the diff.

# Analyzer Test Guidance

When adding or refactoring analyzer tests that need small ad hoc projects, prefer the shared inline test harness in
`tests/common/inline_project.rs` over handwritten `tempdir` plus `ProjectFile::write(...)` setup.

Use `InlineTestProject` by default for tests that define a few files inline. It keeps temp-root management automatic,
hides absolute-path handling, and can infer analyzer languages from file extensions or accept an explicit language when
the test should stay single-language.

Prefer handwritten fixture directories or bespoke setup only when the test genuinely needs a larger reusable corpus or
filesystem behavior that is awkward to express inline.

# Rust CI Checks

Before pushing Rust changes, run the same core checks that CI enforces locally when practical.

At minimum, run `cargo fmt` and `cargo clippy --all-targets --all-features -- -D warnings` on CUDA-capable environments. On macOS or any machine without `nvcc`, do not use `--all-features`: it enables `nlp-gpu` and Candle's CUDA backend. Use `cargo clippy-no-cuda` instead to check all targets with the non-CUDA optional features enabled. If clippy fails, fix that locally before pushing rather than waiting for the CI matrix to report it back.

We are okay with allow(clippy::too_many_arguments) rather than packing necessary parms into a struct just to
make clippy shut up.

# Design philosophy

We build for correctness and generality. Adding narrow "fallbacks" is a smell. Always follow problems
to their source and fix the root cause, even when that increases the blast radius.

For analyzer resolution and usage analysis, do not add regex/text-search fallbacks that mask missing structured support.
Surface the structured failure and fix the graph/resolver instead.

To be precise about what this bans: the prohibition is on *hacking around a gap with string scanning* — using regexes, `split`, or substring matching in place of the tree-sitter AST / analyzer structures that already carry the answer. It is NOT a prohibition on principled best-effort resolution when the information genuinely is incomplete. When a precise answer is unavailable (e.g. a receiver whose type cannot be inferred, or a name that may resolve to one of several declarations), it is fine — often correct — to fall back to a structured, name-based best-effort built on AST nodes and CodeUnits, as long as it does not silently mask a structured failure we could have resolved. "Don't use a regex instead of tree-sitter" is the rule; "never make a best-effort guess from the structure you do have" is not.

Do not replace parser support with small source-text "mini parsers" built from string splitting, regexes, or delimiter
scanning. For example, do not parse Rust paths or type syntax with `split("::")`, `split_once(':')`, or manual generic
delimiter walks when tree-sitter nodes, analyzer declaration ranges, import binders, or existing resolver helpers can
provide the structure. Prefer reading AST fields such as `path`, `name`, `type`, `value`, and `field`, and add a shared
structured helper if the same interpretation is needed in more than one place.

Backwards compatibility is not yet a concern. Clean up APIs instead when our requirements change.

# Implementation details

- Prefer stack-safe iterative traversal over recursive Rust calls for analyzer tree/graph walks, especially during
  workspace initialization, parser declaration collection, usage analysis, and other paths that may touch many files or
  deeply nested ASTs. Use an explicit stack/queue or shared traversal helper unless the recursion depth is provably
  bounded and small.
- Design APIs to avoid cloning, especially in hot loops; prefer iterators/slices where possible.
- Avoid sorted data structures (e.g. BTreeMap) in favor of lighter-weight alternatives
  (HashMap) unless ordering is required for semantic correctness, or when it is preferable
  to pay the ordering cost once at insertion rather than repeatedly sorting later.
- Avoid naive use of reference counting; prefer e.g. explicit IDs and arena allocation in
  graph domains.
- The above should not be interpreted as a blanket prohibition on clone or refcounting
  when these are genuinely the best option, just be intentional rather than reaching for these
  out of habit.

# Semantic search (nlp toolset)

The `nlp` cargo feature (default-on) adds `semantic_search` and pulls in onnxruntime via `gte-rs`/`ort`; `ort` and
`ort-sys` are pinned to the exact rc that `gte-rs` requires — do not bump one without the others. Tests must never
download models or spawn indexer threads: construct services with `SearchToolsService::new_without_semantic_index`,
spawn the binary with `BIFROST_SEMANTIC_INDEX=off`, or inject `FakeEngineProvider`/`FakeHashEmbedder` from
`nlp::engine`/`nlp::indexer`. The real-model smoke test is opt-in:
`BIFROST_NLP_MODEL_TESTS=1 cargo test --test nlp_semantic_search_models -- --ignored`.
