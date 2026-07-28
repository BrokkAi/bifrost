# ExecPlans

When writing complex features or significant refactors, use an ExecPlan (as described in `.agents/PLANS.md`) from design to implementation.

Use `.agents/` as the only repository namespace for agent-owned planning and design artifacts. Do not create or recreate `.agent/`.

Store ExecPlans under `.agents/plans/`. Keep `.agents/PLANS.md` as the canonical instructions for how ExecPlans are written; do not place individual ExecPlans beside it.

Store LLM-facing or agent-facing design notes under `.agents/docs/`. These are internal working documents for agent context, publication runbooks, parity notes, and similar material that is not meant to be rendered as public product documentation.

Reserve `docs/` for future human-readable documentation intended for publication. Do not put ExecPlans, agent runbooks, or LLM-only context there.

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

Avoid low-value tests that only mirror implementation-shaped lists, such as asserting every registry or toolset
expansion by exact name order, unless that order or membership is itself the user-visible contract being changed.
Prefer behavior-focused coverage that proves the advertised surface works end to end, for example listing a tool and
successfully calling it, over tests that duplicate registry construction logic.

# Rust CI Checks

Before pushing Rust changes, run the same core checks that CI enforces locally when practical.

At minimum, run `cargo fmt` and `cargo clippy --all-targets --all-features -- -D warnings`. There is no longer any
compile-time GPU backend: `--all-features` just means `nlp,python` (the embedding sidecar selects CUDA/Metal at
runtime), so this is safe on every machine. The `clippy-no-cuda` alias is a legacy equivalent of the same command;
note it is broken inside nested worktrees (`.claude/worktrees/*`) because cargo merges the duplicate alias arrays
from both `.cargo/config.toml` files — use the expanded command there. If clippy fails, fix that locally before
pushing rather than waiting for the CI matrix to report it back.

Full test-suite gates must pass `--features nlp,python`: `default = []`, so a featureless `cargo test` silently
skips every `#![cfg(feature = "nlp")]` integration suite (they report `ok. 0 passed`, which looks green).

We are okay with allow(clippy::too_many_arguments) rather than packing necessary parms into a struct just to
make clippy shut up.

# Temporary validation storage

Do not create manually named `CARGO_TARGET_DIR=/tmp/bifrost-*` or `/private/tmp/bifrost-*` directories. Cargo does
not remove them. Run isolated builds through `scripts/with-isolated-cargo-target.sh`, for example:

    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings

The helper removes its unique target on success, failure, or interruption. Set `BIFROST_KEEP_TARGET=1` only when the
artifacts are deliberately needed after the command; retained targets are marked so automated cleanup skips them.

Use `scripts/cleanup-bifrost-tmp.sh` to inspect stale Bifrost temporary directories. It is a dry run by default; review
its candidates before rerunning with `--apply`. The command skips young directories, live helper PIDs, open directories,
symlinks, and intentionally retained targets. Apply mode automatically removes only directories carrying the helper's
managed-target marker. Historical manually named `bifrost-*` directories remain report-only unless you explicitly add
`--include-unmanaged` after reviewing them.

For `bifrost_reference_differential`, use `--cache-mode ephemeral` for one-off smoke runs that should not write
`.bifrost/cache/bifrost_cache.db`. Keep the default `--cache-mode persisted` for deliberately warmed or resumable corpus
campaigns.

# RQL syntax maintenance

All new CodeQuery JSON fields, RQL forms, properties, roles, kinds, aliases, and constrained values must enter through
the declarative schema registries under `src/analyzer/structural/query/schema.rs` or the kind/role registries in
`src/analyzer/structural/kinds.rs`. Every entry must provide its accepted spellings, value shape, signature, description,
and exhaustive parser/decoder/validator handling; do not add private keyword lists or editor-only documentation tables.

When visible RQL vocabulary changes, add behavior-focused parser, validation-range, hover, and execution tests as
appropriate, and update the conservative TextMate grammar in `editors/vscode/syntaxes/bifrost-rql.tmLanguage.json`.
Keep ordinary JSON documents outside the RQL editor integration: JSON-shaped CodeQuery source is recognized only after
the host has identified the document as `bifrost-rql`.

# Review findings as RQL regressions

When code review exposes a recurring, mechanically detectable smell, first minimize it into a structured RQL query.
If the query is useful across repositories, add or extend a checked-in `.rqlp` rule under `policy-packs/` with a stable
policy ID, explicit policy/RQL schema versions, inventory metadata, and a semantic hash in the pack manifest. A shippable
rule needs behavior-focused positive and realistic near-miss coverage for every language it claims, including similarly
named APIs, the same operation outside the relevant structural context, and nested/deferred bodies where containment is
part of the rule. If current containment cannot distinguish a deferred body, either keep the rule out or make the deferred
case an explicit tested lexical positive and state that boundary in the message and description. Phrase name-based
performance matches as review prompts rather than proof of execution, runtime cost, or invariance.

Do not replace a missing RQL/analyzer relation with regexes, source-text matching, or a coarse `file_of` projection. When
the minimized query cannot express the review condition or produces an incomplete/misleading result, search open issues
first, then link the existing owner or file a focused follow-up. Record the smallest fixture and query, expected versus
actual result, diagnostics/completion, language, and exact Bifrost commit. Keep the candidate out of the built-in pack
until it can pass positive and near-miss tests reliably.

Treat Bifrost plugin latency as a product regression. Time code-intelligence calls during normal agent work; any call
longer than five seconds warrants an open-issue search. If an issue already owns the slow path, add materially new timing
evidence there; otherwise file one. Include the exact tool and arguments, workspace/revision and scope, wall-clock time,
cold/warm state when known, result or cancellation state, and a profile or minimized reproducer when practical.

During active development, leave each day's policy work release-ready: keep increments small, update the embedded
manifest and package checks, and run the staged-binary policy smoke. This cadence does not authorize version bumps,
tags, publishing, or deployment without an explicit request.

Before completing a code-changing task, use the `bifrost-policy-checking` skill when it is installed. Run the
`bifrost.code-smells` pack together with every executable repository policy root explicitly named by the project, using
one MCP `run_policy` request against the active workspace. Treat `finding` as work to review or fix and `unreliable` as a
failed validation result; rerun the same selection after changes. Never infer success merely because the skill is visible
when its `list_policies` or `run_policy` MCP tools are absent.

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

- Bifrost builds and tests on Windows as well as Unix-like targets. Keep file and path handling OS-agnostic: use
  `Path`/`PathBuf`, temp/project roots that are absolute on the current platform, and explicit slash normalization only
  at API/rendering boundaries where a stable workspace-relative string is required.
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

The `nlp` cargo feature (opt-in; `default = []`) adds `semantic_search`, with voyage-4-nano embeddings served by the
PyTorch SDPA sidecar (CUDA/Metal selected at runtime inside the sidecar — no compile-time backend features). Tests must never
download models or spawn indexer threads: construct services with `SearchToolsService::new_without_semantic_index`,
spawn the binary with `BIFROST_SEMANTIC_INDEX=off`, or inject `FakeEngineProvider`/`FakeHashEmbedder` from
`nlp::engine`/`nlp::indexer`. The real-model smoke test is opt-in:
`BIFROST_NLP_MODEL_TESTS=1 cargo test --test nlp_semantic_search_models -- --ignored`.
