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

# Scheduled release preparation

## Before the next release: bootstrap `brokk-bifrost-core`, `brokk-bifrost-policy`, and `brokk-bifrost-nlp` on crates.io

Issue #1548 split `analyzer/policy` and `nlp` out of `brokk-bifrost-analysis`, and #1549 split the
model/utility layer out beneath it as `brokk-bifrost-core`. All three are new published workspace
packages. The release workflow already packages them, publishes `brokk-bifrost-core` before
`brokk-bifrost-analysis` and policy/nlp after it, and makes `brokk-bifrost-runtime` (policy) and
`brokk-bifrost-mcp` (nlp) wait for them, but crates.io trusted publishing cannot create a crate:
the first version of each must be uploaded with an API token.

All three are genuinely publish-relevant, not internal. `brokk-bifrost-core` is a public
dependency of the published `brokk-bifrost-analysis` -- every analyzer type a consumer touches
(`CodeUnit`, `Language`, `ProjectFile`, `Project`) is defined there and re-exported -- and it
carries the unified cache DB's `migrations/cache/` via `include_str!`. `brokk-bifrost-policy` is a
public dependency of the published `brokk-bifrost-runtime`, `brokk-bifrost-mcp`, and
`brokk-bifrost-lsp`, and the facade re-exports it as `brokk_bifrost::policy`; the built-in
`policy-packs/` ship inside it via `include_str!`. `brokk-bifrost-nlp` is an optional dependency of
the published facade and `brokk-bifrost-mcp` behind their `nlp` features. A published crate cannot
depend on an unpublished one, so none of them can stay path-only.

Before creating the next release tag, bootstrap all three from a clean, reviewed commit using a
narrowly scoped crates.io API token. Order is forced by the graph: `brokk-bifrost-core` first,
since `brokk-bifrost-analysis` names it with an exact `=` requirement; then policy and nlp, each
publishing a version whose exact `brokk-bifrost-analysis` dependency is already visible on
crates.io. Publish `brokk-bifrost-policy` before nlp if you intend to verify the runtime/mcp/lsp
resolution end to end. Run the normal package gate and inspect `cargo package --list -p
brokk-bifrost-core`, `-p brokk-bifrost-policy` and `-p brokk-bifrost-nlp` before those irreversible
first uploads; in particular confirm `migrations/cache/` is present in the core archive and
`policy-packs/bifrost.code-smells/` in the policy archive, since
`scripts/check-workspace-packages.sh` now asserts each there rather than in the analysis archive.

After the first versions are visible, align their crates.io owners with the other Bifrost crates
and configure GitHub trusted publishing for repository `BrokkAi/bifrost`, workflow filename
`release.yml`, and environment `release`. Verify that configuration before tagging.

## Do not reintroduce the nlp dependency stack into brokk-bifrost-analysis

The measurable win from #1548 is that toggling the `nlp` feature no longer invalidates the
workspace's largest compilation unit. `scripts/check-workspace-dependencies.mjs` enforces this by
listing `hf-hub`, `tokenizers`, and `fastrq` as forbidden dependencies of
`brokk-bifrost-analysis`, and of `brokk-bifrost-core` beneath it. If a change appears to need one
of them there, the correct move is to put the code in `brokk-bifrost-nlp`, not to relax the check.

## Keep brokk-bifrost-core at the bottom of the graph

#1549 exists so the analyzer's model layer stops being recompiled as part of the workspace's
largest unit. That only holds while `brokk-bifrost-core` depends on no other Bifrost crate;
`scripts/check-workspace-dependencies.mjs` gives it an empty allowed-dependency set and its unit
test asserts a `core -> analysis` edge is rejected. Anything that needs an `IAnalyzer`, a store, a
grammar, or a language module belongs in `brokk-bifrost-analysis`, however convenient the move
looks. `analyzer/capabilities.rs` is the standing example: it stayed behind because
`TypeHierarchyProvider::get_polymorphic_matches` and `build_direct_descendant_index` are generic
over `IAnalyzer`.

# Scheduled removals

Carry these out when the stated release has shipped. They are recorded here rather than as
tracker items because development here is agentic: an agent reads this file every session and
will not go looking for an issue it was never told about.

## After v0.9.0: delete the hand-written MCP stack

`crates/bifrost-mcp/src/mcp_common.rs` still contains Bifrost's pre-`rmcp` MCP implementation.
It is currently the default; `BIFROST_MCP_RMCP=on` selects the `rmcp` host. Two steps precede the
removal below: flip the default to `on`, then let it ride. Both exist because `rmcp` 3.0 was days
old when issue #1328 adopted it, and neither is meant to outlive that caution.

Remove the protocol half: `dispatch_message`, `dispatch_request`, `handle_notification`,
`handle_response`, `McpConnectionState`, `McpRequestCancellations`, `OutboundMcpResponse` and
`try_queue_response`, `initialize_result`, `success_response`/`error_response`, the duplicated
`prepare_tool_call` and `reconcile_codex_sandbox_workspace`, the JSON-RPC constants,
`run_stdio_server_with_build_identity` and the `MCP_RMCP_HOST_ENV` switch, their unit tests, and
the `McpHost` matrix in `crates/bifrost-mcp/tests/bifrost_mcp_server.rs`.

Keep the Bifrost half, which the `rmcp` host already calls rather than copies: `McpServerSpec`,
`McpRenderOptions`, `build_server_spec*`, the `tool_descriptor` family,
`fit_get_summaries_output_to_budget` and its budgeting block, `client_root_to_path`,
`file_uri_to_path`, `serial_tool_request`, `mcp_analyzer_request_budget`, and the benchmark
constants. The crate's entry point currently dispatches *from* the old module *into*
`rmcp_host`, so deletion also means moving that entry point and re-homing the kept helpers.

Do this promptly rather than when convenient. While both hosts exist the Codex sandbox
authorization boundary has two copies that must be fixed in lockstep, and that duplication is
exactly how the pre-handshake bypass in `09e37dd1` reached a green test suite: a security
predicate was hand-copied and quietly lost a conjunct. It is not a one-off risk either: the very
first upstream sync after the hosts diverged landed a `run_policy` feature (#1394) on the
hand-written host alone, and it had to be ported across by hand. Until the deletion, treat any
change to MCP behaviour as a change to two implementations, and prefer sharing a function over
copying it.

# Dogfooding the rmcp MCP host

Bifrost's own MCP server can run on either of two protocol stacks (see `Scheduled removals`). The
`rmcp`-backed one is opt-in and needs real usage before it can become the default, and the people
best placed to give it that are us, through this plugin.

At the start of a session that will use Bifrost's code-intelligence tools, check
`echo "${BIFROST_MCP_RMCP:-unset}"`. If it is not `on`, tell the user once, with the fix: the
launcher passes its environment through unchanged, so exporting the variable in the shell that
starts the agent is enough, for example `BIFROST_MCP_RMCP=on claude` or `BIFROST_MCP_RMCP=on
codex`. GUI-launched desktop apps do not inherit a shell environment, so mention that this applies
to CLI-launched sessions. Say it once and move on; do not repeat it or block work on it, and do not
set it yourself -- it changes which protocol stack serves the session, which is the user's call.

Treat anything that smells like an MCP failure as a finding worth surfacing, not noise to route
around. Bifrost tool calls that hang, return a protocol error, report an unexpected "not bound to a
workspace", lose a response, come back with the wrong workspace's results, or fail immediately after
a folder or roots change are all candidates. Report them to the user with which stack was serving
(`BIFROST_MCP_RMCP`), the exact tool and arguments, what came back, and whether retrying or
switching stacks changes it -- the two implementations differing on the same input is the single
most useful signal available while both exist. Then search open issues and file one if nothing owns
it. This complements the latency rule under `Review findings as RQL regressions`: that one covers
calls that are slow, this one covers calls that are wrong.

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

New integration tests go in `tests/<suite>/<name>.rs` plus one `mod <name>;` line in that harness's `main.rs` (the
suites and their members are listed in `.agents/docs/test-harness-consolidation-2026-07.md`); do not add a new
`tests/*.rs` file at the root. A new standalone `tests/*.rs` binary is reserved for tests that need process
isolation — process-global counters, in-process env mutation, or pristine rayon/`OnceLock` state that concurrent
in-process tests would perturb — and requires a keep-separate entry in that manifest explaining the reason.

# Rust CI Checks

Before pushing Rust changes, run the same core checks that CI enforces locally when practical.

For the full pre-push gate, prefer `scripts/pre-push-gate.sh` (#1454): it runs fmt, then the featureless
workspace test suites under cargo-nextest (one cross-binary scheduler plus the per-test slow-timeout in
`.config/nextest.toml`, so a hung test is named and killed instead of stalling silently), a doctest step
(nextest does not run doctests), and the isolated-target all-features clippy concurrently with the tests
rather than after them. It needs `cargo-nextest` installed (`cargo install cargo-nextest --locked`).
The individual commands below remain the reference for focused, task-scoped validation.

Do not enable `nlp` for routine task-scoped validation unless the change touches semantic search/NLP, the user
explicitly requests the comprehensive gate, or an actual pre-push/merge/release gate is being performed. NLP builds
can consume tens of GiB per worktree, so running them opportunistically across several worktrees can exhaust the host
disk. For changes unrelated to NLP, run the focused featureless Rust tests; add `--features python` only when the Rust
Python surface needs coverage. The existence of an ExecPlan or a request for code review does not by itself justify an
NLP build.

For those pre-push gates, at minimum run `cargo fmt` and
`cargo clippy --workspace --all-targets --all-features -- -D warnings`. `--workspace` is load-bearing: the root
manifest sets `default-members = ["."]`, so without it clippy lints only the facade package and merely *compiles* the
`crates/*` members as dependencies, never linting their `#[cfg(test)]` unit-test targets — a broken crate test module
sails through green (demonstrated 2026-08-02 by a probe E0599 that the no-`--workspace` form missed and the
`--workspace` form caught). There is no longer any
compile-time GPU backend: `--all-features` just means `nlp,python` (the embedding sidecar selects CUDA/Metal at
runtime), so this is safe on every machine. The `clippy-no-cuda` alias is a legacy equivalent of the same command
minus `--workspace`, and so shares that blind spot;
note it is broken inside nested worktrees (`.claude/worktrees/*`) because cargo merges the duplicate alias arrays
from both `.cargo/config.toml` files — use the expanded command there. If clippy fails, fix that locally before
pushing rather than waiting for the CI matrix to report it back.

When a comprehensive full-suite gate is actually required, it must pass `--features nlp,python`: `default = []`, so a
featureless `cargo test` silently skips every `#![cfg(feature = "nlp")]` integration suite (they report `ok. 0 passed`,
which looks green). Do not promote this comprehensive command into the default validation for an unrelated change.

Run local Rust tests that enable the `python` feature through uv's Python 3.12 environment:

    uv run --python 3.12 -- cargo test --features nlp,python

PyO3 resolves its interpreter from the process environment; running Cargo directly bypasses uv and may select an
incompatible system Python or one without the development library needed to link Rust test executables.

Do not enable `extension-module` for tests. It suppresses libpython linkage, which is right for the wheel (the host
interpreter supplies `Py*` at load time) and fatal for any executable, so a test build fails with undefined `_Py*`
symbols while linking the cdylib. Maturin turns it on for the wheel via `pyproject.toml`; leave it off everywhere else.
This also means `cargo test --all-features` is not a substitute for `--features nlp,python`.

We are okay with allow(clippy::too_many_arguments) rather than packing necessary parms into a struct just to
make clippy shut up.

# Temporary validation storage

Do not create manually named `CARGO_TARGET_DIR=/tmp/bifrost-*` or `/private/tmp/bifrost-*` directories. Cargo does
not remove them. Run isolated builds through `scripts/with-isolated-cargo-target.sh`, for example:

    scripts/with-isolated-cargo-target.sh cargo clippy --workspace --all-targets --all-features -- -D warnings

The helper removes its unique target on success, failure, or interruption. Set `BIFROST_KEEP_TARGET=1` only when the
artifacts are deliberately needed after the command; retained targets are marked so automated cleanup skips them.
Before an authorized all-feature/NLP build, check available disk space and avoid running another NLP build concurrently
in a sibling worktree. The helper controls cleanup but cannot reduce the build's peak disk footprint.

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
the declarative schema registries under `crates/bifrost-analysis/src/analyzer/structural/query/schema.rs` or the kind/role registries in
`crates/bifrost-core/src/analyzer/structural/kinds.rs`. Every entry must provide its accepted spellings, value shape, signature, description,
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

# Coding conventions

- Use asserts to validate assumptions: prefer reasonable assumptions backed by `assert!` (or `debug_assert!` on hot
  paths) to defensive `if` checks, and never return `Result`/`Option` for can't-happen states. The FqName round-trip
  debug assert catching #1189 is the model: fail loudly at the construction site instead of propagating corrupt state.
- DRY, but flag parameters are a design smell: if factoring out shared code would require adding a `mode`-style
  boolean/enum parameter, write separate functions instead.
- Parsimony: when a general case also produces correct results for the special cases (empty input, maximum size,
  single element), write only the general case. Don't write special cases unless they are necessary.
- YAGNI: implement the simplest solution that meets the requirements unless you have specific knowledge that a more
  robust solution is needed for near-future requirements.
- Keep related code together: don't split a short computation into a separate function, module, or file unless it is
  self-contained and either significantly complex or called from multiple sites. Declare small single-use structs and
  enums next to the code that produces or returns them, not in standalone modules.
- No mocking frameworks, no dependency-injection scaffolding: test doubles are hand-rolled fakes
  (`FakeEngineProvider`, `new_without_semantic_index`) and traits with default implementations
  (`unimplemented!()` is fine) to keep test boilerplate minimal.
- No overcautious error handling: don't match/catch an error unless you have context-specific handling to apply;
  propagate with `?` and let the caller's logging surface it. Never `let _ = fallible()`. Results and panics from
  spawned threads or rayon tasks must be surfaced, never silently dropped.
- When logging or formatting diagnostics, include the full collections (trust the Debug impls), not just counts.
- Plain ASCII in code and comments: no fancy quotes, dashes, or spaces.
- Before adding a local helper that interprets strings, paths, or common shapes, look for an existing shared helper
  first; add to the shared location if one is needed in more than one place.

# Semantic search (nlp toolset)

The `nlp` cargo feature (opt-in; `default = []`) adds `semantic_search`, with voyage-4-nano embeddings served by the
PyTorch SDPA sidecar (CUDA/Metal selected at runtime inside the sidecar — no compile-time backend features). Tests must never
download models or spawn indexer threads: construct services with `SearchToolsService::new_without_semantic_index`,
spawn the binary with `BIFROST_SEMANTIC_INDEX=off`, or inject `FakeEngineProvider`/`FakeHashEmbedder` from
`nlp::engine`/`nlp::indexer`. The real-model smoke test is opt-in:
`BIFROST_NLP_MODEL_TESTS=1 cargo test --test nlp_semantic_search_models -- --ignored`.
