# Add too-broad scope guards to searchtools fan-out tools

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md` at the repository root.

## Purpose / Big Picture

Bifrost exposes code-intelligence tools to LLM agents over MCP (Model Context Protocol, a JSON tool-call protocol; the server lives in `crates/bifrost-mcp`). Three of those tools can be asked a question whose answer is "most of the repository": a glob target such as `src/**` handed to `get_summaries` or `get_symbol_sources`, or a broad name pattern handed to `search_symbols`. Today the tools do all of that work before replying. On a repository the size of Firefox (about 401,804 tracked files, 4.2 GB), this was measured during the CodeScaleBench grep-hard evaluation (2026-08-06 checkpoint, `.agents/docs/codescale-grep-hard-checkpoint-2026-08-06.md`) at 83-132 seconds for a broad six-pattern `search_symbols` call before SQL batching, and roughly 90 seconds after.

After this change, a tool that can see -- cheaply, before its expensive phase -- that a request matched far more code than any caller can use stops immediately and returns a structured "too broad" answer: how much matched, what the cap is, a small sample, and how to narrow. The agent gets an honest sub-second reply instead of a two-minute stall, and nothing is silently dropped. The repository already has this pattern in one tool: `scan_usages` returns a `TooManyCallsites` result carrying the true total, the cap, and `complete = false` (see `crates/bifrost-analysis/src/searchtools/scan_usages.rs`, around lines 428 and 865). This plan extends the same idea to the remaining unguarded fan-out paths.

You can see it working by running the new behavior tests (each fails before its guard exists and passes after), and by calling `get_summaries` with a glob that matches more files than the cap on a small inline test project: the reply arrives with a `too_broad` block instead of a summary per file.

## Progress

- [x] (2026-08-06) Audit of every searchtools entry point completed; unguarded fan-out paths identified (recorded in Context and Orientation below).
- [ ] Milestone 1: shared `TooBroadScope` type and the `get_summaries` per-target guard, with render support and behavior tests.
- [ ] Milestone 2: `get_symbol_sources` glob-arm guard, with behavior tests.
- [ ] Milestone 3: `search_symbols` post-resolution candidate cap, with behavior tests and a provisional cap value.
- [ ] Milestone 4: investigate workspace-root `get_summaries` latency (the 127 s `all_files()` walk); outcome is a fix or a filed issue with evidence.
- [ ] Milestone 5: tool description updates, full gate, checkpoint commit(s) verified.

## Surprises & Discoveries

- Observation: the 126.98 s `get_summaries("/")` call observed on Firefox is not a summarization fan-out. A directory target routes to `directory_listing`, which lists only direct children; the cost is `analyzer.project().all_files()`, a full ignore-aware traversal of the workspace, materialized only to answer "what are the children of this directory".
  Evidence: `crates/bifrost-analysis/src/searchtools/summaries.rs` lines 236-248 (the directory arm calls `workspace_files.get_or_init(|| analyzer.project().all_files()...)`), and the comment at lines 194-201 recording that this same walk cost 4-9 s per call on a 2,700-file tree (#1325). A pre-flight count guard cannot help here: computing the count is the walk. This is why Milestone 4 is an investigation, not a cap.
- Observation: the glob arm of `get_symbol_sources` is the heaviest unguarded path, heavier than `get_summaries`, because it returns full source text for every matched file.
  Evidence: `crates/bifrost-analysis/src/searchtools/sources.rs` lines 355-369: `resolve_file_patterns` matches are fed to `source_blocks_for_files` with no cap.
- Observation: `list_symbols` is already safe and is the model to imitate: it bounds its expensive work, not just its output. `skim_files_for_files` selects at most `FILE_SKIM_LIMIT` (20) files before the per-file symbol-listing loop runs, and reports `truncated` plus the true `total_files`.
  Evidence: `crates/bifrost-analysis/src/searchtools/summaries.rs` lines 601-637.
- Observation: `search_symbols` clamps only its output (top `FILE_SEARCH_LIMIT` = 100 files), after resolving and ranking the entire matching universe. On Firefox the measured split was about 54.6 s resolution, 34.0 s ranking, 0.8 s rendering. A post-resolution candidate cap therefore bounds ranking but not resolution; bounding resolution would require early-stop inside `search_symbol_candidates`, which has ten-plus per-language implementations.
  Evidence: `crates/bifrost-analysis/src/searchtools/navigation.rs` lines 330-460 (resolve, filter, rank, then clamp at line 404); `rg -n "fn search_symbol_candidates" crates/` lists implementations in `tree_sitter_analyzer.rs` and nine language modules.

## Decision Log

- Decision: guard at the two shared choke points (`resolve_file_patterns` consumers, `search_symbols` post-resolution), not per tool surface.
  Rationale: every unguarded path flows through one of these two places; guarding there covers `get_summaries` and `get_symbol_sources` with one mechanism and leaves already-guarded tools (`list_symbols`, `scan_usages`, `most_relevant_files`) untouched.
  Date/Author: 2026-08-06, Fable (plan author).
- Decision: the guard for glob targets is per-target, applied where a single target's `resolve_file_patterns` matches are about to be consumed, and it skips that target rather than truncating it.
  Rationale: per-target attribution makes the reply actionable (the agent learns which pattern exploded). Skipping rather than truncating is honest: a summary of an arbitrary 20-file subset of a 40,000-file match would look complete while being meaningless. The sample in the reply gives the agent concrete paths to re-request. Explicit file targets (one target, one file) can never trip the guard.
  Date/Author: 2026-08-06, Fable.
- Decision: `search_symbols` gets a candidate-count cap applied after resolution and deduplication, before ranking. When tripped, ranking is skipped entirely and the reply reports the total candidate count, the cap, and per-pattern match counts when cheaply attributable.
  Rationale: this converts the 34 s ranking phase into an instant honest answer. The cap must be generous (provisionally 10,000 candidates) because broad multi-pattern search with ranking is this tool's normal, intended use; only pathological explosions should trip it. Bounding the 54.6 s resolution phase is explicitly out of scope for this plan (see the non-goals paragraph in Context and Orientation) because it requires touching every per-language `search_symbol_candidates` implementation; if measurement in Milestone 3 shows resolution alone still gates, file a follow-up issue rather than expanding this plan.
  Date/Author: 2026-08-06, Fable.
- Decision: do not unify the new guard results with `scan_usages`' existing `TooManyCallsites` / `ScanUsagesIncompleteReason` machinery, and do not build a general incompleteness framework.
  Rationale: YAGNI, per repository conventions. `scan_usages` has a richer domain (proof tiers, interruption reasons) and works today. The new shared type `TooBroadScope` is small and used by the two glob consumers; `search_symbols` needs different fields (per-pattern counts) and gets its own small struct. Three small honest types beat one speculative framework.
  Date/Author: 2026-08-06, Fable.
- Decision: leave the opt-in per-request time deadline (`mcp_analyzer_request_budget`, `crates/bifrost-mcp/src/mcp_common.rs` line 182 area) exactly as it is.
  Rationale: the time deadline is a blunt backstop that fires after the wall clock is already spent. Count-based guards prevent the work instead. The two mechanisms compose; neither replaces the other.
  Date/Author: 2026-08-06, Fable.
- Decision: cap constants live next to the existing cap constants in `crates/bifrost-analysis/src/searchtools/mod.rs`, and the internal functions that enforce them take the cap as a parameter so tests can exercise tiny caps on tiny fixtures, following the existing `scan_usages` test pattern (`crates/bifrost-analysis/src/searchtools/tests.rs` line 861 passes `limit: 1000` explicitly).
  Rationale: keeps tests on `InlineTestProject`-scale fixtures without environment knobs or mode flags.
  Date/Author: 2026-08-06, Fable.

## Outcomes & Retrospective

(To be written at milestone completions.)

## Context and Orientation

This repository is Bifrost, a multi-language code analyzer written in Rust. The crate `crates/bifrost-analysis` contains the analyzer and, in `src/searchtools/`, the implementations of the code-intelligence tools. The crate `crates/bifrost-mcp` wraps those functions as MCP tools: `crates/bifrost-mcp/src/searchtools_service.rs` decodes tool arguments, calls the `searchtools` function, and renders the result struct into the text the LLM agent sees (find the render site for a tool by searching for its name string in that file, for example `rg -n '"get_summaries"' crates/bifrost-mcp/src/searchtools_service.rs`). Tool descriptions (the schema text the agent reads) live in `crates/bifrost-mcp/src/mcp_core.rs` and `mcp_extended.rs`.

Terms used below. "Fan-out" means the number of files or symbols a single request expands to. A "choke point" is the one function through which a fan-out flows, where a guard covers every caller. A "cap" is a constant limiting fan-out. A "structured result" is a typed field in the tool's result struct (serialized to the agent), as opposed to prose in a note string. `resolve_file_patterns` (defined in the searchtools module; find it with `rg -n "fn resolve_file_patterns" crates/bifrost-analysis/src`) expands a glob-like target string into the set of matching workspace files. `InlineTestProject` (`tests/common/inline_project.rs`) is the shared test harness for small inline fixtures.

The audit that motivates this plan, so it does not have to be redone: `scan_usages_by_reference` / `scan_usages_by_location` are guarded by `SCAN_USAGES_MAX_CALLSITES` and friends and return `TooManyCallsites`. `list_symbols` bounds its work with `FILE_SKIM_LIMIT` before the expensive loop. `most_relevant_files` has an interactive budget and a `limit` parameter. The by-location and by-reference definition/declaration/type tools are bounded by their single keyed symbol plus output caps (`TYPE_LOOKUP_MAX_REFERENCES`, `DEFINITION_LOOKUP_MAX_REFERENCES`, `AMBIGUOUS_SYMBOL_MATCH_LIMIT`). The unguarded paths are exactly three:

1. `get_summaries` glob targets: `crates/bifrost-analysis/src/searchtools/summaries.rs`, function `route_summary_targets_with_cancellation`, lines 262-270: `resolve_file_patterns` matches are extended into `file_targets` without a cap, and `summarize_files_with_cancellation` (line 702) then runs a parallel per-file summary extraction over all of them.
2. `get_symbol_sources` glob targets: `crates/bifrost-analysis/src/searchtools/sources.rs`, lines 355-369: per-symbol glob matches go to `source_blocks_for_files` without a cap, returning full file sources.
3. `search_symbols` candidates: `crates/bifrost-analysis/src/searchtools/navigation.rs`, `search_symbols_with_cancellation` (line 330): all resolved candidates are filtered and then ranked by `rank_search_symbol_candidates` (line 2038, a per-candidate loop) before any output clamp.

Non-goals, stated so a later reader does not widen scope: this plan does not bound the resolution phase inside per-language `search_symbol_candidates` implementations; does not change `scan_usages`; does not make the opt-in time deadline default; and does not fix the workspace-walk cost of directory listings beyond the Milestone 4 investigation.

## Plan of Work

### Milestone 1: shared type and the get_summaries guard

Scope: after this milestone, `get_summaries` with a glob target matching more files than the cap returns instantly with a structured `too_broad` entry for that target, while explicit file targets and small globs behave exactly as before. This is the first guard and it establishes the shared type the next milestone reuses.

In `crates/bifrost-analysis/src/searchtools/mod.rs`, next to the existing cap constants around line 220, add:

    pub const FILE_PATTERN_FANOUT_SAMPLE: usize = 10;
    pub const GET_SUMMARIES_MAX_FILES_PER_TARGET: usize = 20;

and the shared struct (deriving Debug, Clone, Serialize like its neighbors):

    /// A single request target that matched more of the workspace than the
    /// tool will process. The work was skipped, not truncated: `sample`
    /// holds the first `FILE_PATTERN_FANOUT_SAMPLE` matched paths so the
    /// caller can narrow, and `matched` is the true total.
    pub struct TooBroadScope {
        pub target: String,
        pub matched: usize,
        pub cap: usize,
        pub sample: Vec<String>,
    }

The cap value 20 mirrors `FILE_SKIM_LIMIT`, the bound `list_symbols` already applies to the same kind of expansion; a summary block is strictly larger than a skim listing, so a larger cap is not defensible without new evidence.

In `crates/bifrost-analysis/src/searchtools/summaries.rs`: add a `too_broad: Vec<TooBroadScope>` field to both `SummaryTargets` (the routing result, around line 291) and `SummaryResult` (around line 31, with `#[serde(skip_serializing_if = "Vec::is_empty", default)]` like `ambiguous_paths`). In `route_summary_targets_with_cancellation`, at the site where glob matches are consumed (lines 267-270), compare `matches.files.len()` against the cap; when over, push a `TooBroadScope` (target string, count, cap, first `FILE_PATTERN_FANOUT_SAMPLE` workspace-relative paths, sorted for determinism) instead of extending `file_targets`. Thread the cap in as a parameter of the routing function (the public `get_summaries` entry passes the constant) so tests can pass a tiny cap. In `summarize_routed_targets_with_cancellation` (line 856), copy `too_broad` from targets into the result the same way `listings` is copied.

In `crates/bifrost-mcp/src/searchtools_service.rs`, find the `get_summaries` render site and render each `too_broad` entry as an explicit paragraph naming the target, the matched count, the cap, the sample paths, and the instruction to narrow to a subdirectory, an explicit file list, or `list_symbols` (which self-truncates). Also note there is special-case handling for `get_summaries` output in `crates/bifrost-mcp/src/mcp_common.rs` around line 1365; read it and keep it consistent.

Tests, using `InlineTestProject` in the existing suite file `tests/suite_symbols/searchtools_service.rs` (or a new `tests/suite_symbols/<name>.rs` registered in that suite's `main.rs` if the file is crowded): (a) behavior: a fixture with, say, 6 files and a glob target, cap of 3 passed to the internal routing function, asserts the reply has one `too_broad` entry with `matched = 6`, `cap = 3`, a 3-element sorted sample, and no summaries for those files; (b) non-regression: the same glob under a cap of 10 summarizes all 6 files and `too_broad` is empty; (c) explicit file targets never trip the guard even when more targets than the cap are given; (d) an MCP-level render assertion that the too-broad paragraph appears in the tool text. Do not assert exact prose beyond the load-bearing tokens (target, counts).

Acceptance: the new tests fail before the guard exists (compile failure for the new field counts; the behavior assertion fails if you stub the field in first) and pass after; the full focused suite passes.

### Milestone 2: get_symbol_sources guard

Scope: after this milestone, a glob-shaped symbol argument matching more files than a (smaller) cap returns a structured too-broad outcome instead of the full text of every matched file.

In `mod.rs` add `pub const GET_SYMBOL_SOURCES_MAX_FILES_PER_TARGET: usize = 10;` -- smaller than the summaries cap because this tool returns full source text, the heaviest payload per file.

In `crates/bifrost-analysis/src/searchtools/sources.rs`: add a `TooBroad(TooBroadScope)` variant to `SourceLookupOutcome`, and a `too_broad: Vec<TooBroadScope>` field to `SymbolSourcesResult` (same serde attributes as in Milestone 1). At the glob arm (lines 355-369), when `file_matches.files.len()` exceeds the cap, return the new outcome instead of calling `source_blocks_for_files`. Collect it in the outcome loop at lines 447-454. Thread the cap as a parameter the same way as Milestone 1. Update the render site in `searchtools_service.rs` (note `get_symbol_sources` has bespoke handling around lines 1496 and 2976; read both before editing).

Tests mirror Milestone 1 in the appropriate `tests/suite_symbols/` file: glob over cap yields `too_broad` and no source blocks; glob under cap yields sources; an exact symbol name and an explicit single-file path are unaffected.

Acceptance: tests fail before, pass after; focused suite green.

### Milestone 3: search_symbols candidate cap

Scope: after this milestone, a pattern set that resolves to more deduplicated candidates than the cap skips ranking and returns a structured too-many-matches reply, and normal broad searches (the tool's intended use) are unaffected.

In `mod.rs` add `pub const SEARCH_SYMBOLS_MAX_RANKED_CANDIDATES: usize = 10_000;` with a comment stating it is provisional: on Firefox, ranking took about 34 s for a six-pattern broad search, and the cap should be tuned once a candidate count for that workload is measured (Milestone 4's environment can measure it; record the number here when known).

In `crates/bifrost-analysis/src/searchtools/navigation.rs`, in `search_symbols_with_cancellation` after the `filtered` vector is built (line 383) and before `rank_search_symbol_candidates` (line 386): if `filtered.len()` exceeds the cap, skip ranking, git-tier lookup, and the semantic-model overlay work, and produce a result whose new optional field describes the overload. Define next to `SearchSymbolsResult`:

    pub struct TooManySymbolMatches {
        pub total_candidates: usize,
        pub cap: usize,
        /// Candidate counts per input pattern, when attribution is cheap
        /// (a candidate can match several patterns; counts may overlap).
        pub per_pattern: Vec<(String, usize)>,
    }

and add `pub too_many_matches: Option<TooManySymbolMatches>` to `SearchSymbolsResult`, setting `complete = false` when it is set. For `per_pattern`, check whether `SearchSymbolPatternBatch` exposes a way to test one candidate name against one compiled pattern; if it does, count in one pass over `filtered`; if it does not and adding one is invasive, ship total-only and record that in the Decision Log. Thread the cap as a parameter. Render in `searchtools_service.rs`: state the totals and instruct the agent to add more specific patterns or set `include_tests`/narrower spellings. Note the warmup call in `crates/bifrost-mcp/src/mcp_common.rs` line 2965 uses pattern `__warmup__`; it matches nothing and cannot trip the cap, but confirm.

Tests: with a tiny cap parameter (for example 3) on an `InlineTestProject` with 5 matching symbols, assert `too_many_matches` is set with `total_candidates = 5`, `complete = false`, and the ranked file list is empty; with the cap above the count, assert unchanged normal output. Add a render assertion.

Acceptance: tests fail before, pass after; focused suite green.

### Milestone 4: workspace-root get_summaries latency investigation

Scope: this is an investigation milestone, not a code milestone; its deliverable is either a root-cause fix or a filed issue with evidence. The 126.98 s `get_summaries` call on Firefox requested `/`; that path builds `analyzer.project().all_files()` (summaries.rs line 239) purely to list the root's direct children. Per the repository latency rule, first search open issues (`gh issue list --search "get_summaries latency"` and variants; the 2026-08-06 checkpoint's item 4 may already be tracked). If untracked, reproduce against a large workspace -- the CodeScaleBench Firefox clone with the shared DW10 cache at `/mnt/T9/repo-clones/.codescale-cache-dw10/bifrost_cache.v15.db` is the known environment; a large local checkout also works -- and split the time between the ignore-aware walk, cache hydration, and listing construction using the existing `profiling::scope` spans (`searchtools::route_summary_targets` and its callees). If the walk dominates and a cheap fix exists (for example, deriving the root listing from the analyzer's already-indexed file set instead of a fresh traversal), implement it in this plan; otherwise file the issue with the exact tool and arguments, workspace and revision, wall-clock, cold/warm state, and the span breakdown, and link it here.

Acceptance: either a measured before/after on the same workspace showing the root listing no longer pays a full walk, or an issue URL recorded in this plan's Progress section.

### Milestone 5: descriptions, gate, and wrap-up

Update the tool descriptions in `crates/bifrost-mcp/src/mcp_core.rs` / `mcp_extended.rs` for the three tools so the schema text tells the agent the guard exists and how the reply asks it to narrow (one sentence each; the existing `get_summaries` description already warns against repository-root targets -- keep that sentence and add the guard sentence). Update `Outcomes & Retrospective`. Run the full local gate (commands below). Commit per repository convention (checkpoint commits along the way are expected; commit only files this plan touched).

## Concrete Steps

All commands run from the repository root `/mnt/optane/bifrost-nlp` (or the active worktree root).

Focused iteration while implementing (featureless; none of this plan touches NLP):

    cargo check -p brokk-bifrost-analysis
    cargo nextest run -p brokk-bifrost-analysis
    cargo nextest run --workspace -E 'test(/searchtools|summaries|symbol_sources|search_symbols/)'

Before each push (per repository CI rules; `--workspace` is mandatory -- without it clippy skips the crates' unit-test targets):

    cargo fmt
    cargo clippy --workspace --all-targets --all-features -- -D warnings

The clippy command is valid on all machines (`--all-features` enables only `nlp,python`; there is no compile-time GPU backend). If running in a nested worktree under `.claude/worktrees/*`, use this exact expanded command, not the `clippy-no-cuda` alias. Doctests are not run by nextest; `scripts/pre-push-gate.sh` covers the full pre-push gate when needed. Do not run an NLP-feature build for this plan; it is not NLP-related.

If the `bifrost-policy-checking` skill and its MCP tools (`list_policies`, `run_policy`) are available in the session, run the `bifrost.code-smells` pack against the workspace after the changes and treat findings as work to review.

## Validation and Acceptance

Each milestone's tests are the acceptance instrument, and each must be demonstrated to fail before its guard is implemented (comment out the guard call or run the test against the pre-milestone commit) and pass after. End-to-end acceptance: on an `InlineTestProject` fixture with more files than a test-supplied cap, `get_summaries` with a glob target returns within ordinary test time a result whose rendered text names the matched count, the cap, and sample paths, and contains no per-file summaries for the skipped target; `get_symbol_sources` with a glob behaves likewise with no source blocks; `search_symbols` over the candidate cap returns `complete = false` with the too-many block and no ranked files. Existing suites must stay green: the guards must not change behavior for explicit file targets, exact symbol names, or under-cap globs.

## Idempotence and Recovery

All changes are additive fields, new constants, and new early-return branches; re-running any step is safe. If a milestone lands broken, revert its commit; no data, cache, or schema formats change (result structs gain optional/empty-default fields only, and nothing persists them). Tests introduce no fixtures outside `InlineTestProject` temporary roots. Milestone 4's measurements must use `scripts/with-isolated-cargo-target.sh` for any isolated build and must not run concurrent large builds in sibling worktrees.

## Artifacts and Notes

Evidence anchoring the audit (2026-08-06, commit family around `250f6549`):

    summaries.rs:262-270   glob matches extend file_targets, no cap
    summaries.rs:702-725   summarize_files_with_cancellation: unbounded par_iter
    summaries.rs:601-637   list_symbols work-bounding precedent (FILE_SKIM_LIMIT)
    sources.rs:355-369     glob arm returns full sources, no cap
    navigation.rs:330-460  search_symbols: resolve -> filter -> rank -> clamp(100)
    scan_usages.rs:428,865 TooManyCallsites precedent (cap + true total + complete=false)
    mod.rs:219-261         existing cap constants; new caps go here

Firefox-scale measurements from `.agents/docs/codescale-grep-hard-checkpoint-2026-08-06.md`: broad six-pattern `search_symbols` 83-132 s before SQL batching; after batching, profile split 54.6 s resolution / 34.0 s ranking / 0.8 s rendering; first broad `get_summaries` (target `/`) 126.98 s.

## Interfaces and Dependencies

No new crates or external dependencies. At the end of the plan these exist:

In `crates/bifrost-analysis/src/searchtools/mod.rs`:

    pub const FILE_PATTERN_FANOUT_SAMPLE: usize = 10;
    pub const GET_SUMMARIES_MAX_FILES_PER_TARGET: usize = 20;
    pub const GET_SYMBOL_SOURCES_MAX_FILES_PER_TARGET: usize = 10;
    pub const SEARCH_SYMBOLS_MAX_RANKED_CANDIDATES: usize = 10_000;

    #[derive(Debug, Clone, Serialize)]
    pub struct TooBroadScope {
        pub target: String,
        pub matched: usize,
        pub cap: usize,
        pub sample: Vec<String>,
    }

In `summaries.rs`: `SummaryTargets` and `SummaryResult` gain `too_broad: Vec<TooBroadScope>`. In `sources.rs`: `SymbolSourcesResult` gains `too_broad: Vec<TooBroadScope>`; `SourceLookupOutcome` gains a `TooBroad` variant. In `navigation.rs`: `SearchSymbolsResult` gains `too_many_matches: Option<TooManySymbolMatches>` with the struct as specified in Milestone 3. Internal enforcement functions take the cap as a `usize` parameter; public tool entry points pass the constants. Rendering lives in `crates/bifrost-mcp/src/searchtools_service.rs`; descriptions in `crates/bifrost-mcp/src/mcp_core.rs` / `mcp_extended.rs`.
