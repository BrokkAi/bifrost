# Add too-broad scope guards to searchtools fan-out tools

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md` at the repository root.

## Purpose / Big Picture

Bifrost exposes code-intelligence tools to LLM agents over MCP (Model Context Protocol, a JSON tool-call protocol; the server lives in `crates/bifrost-mcp`). Three of those tools can be asked a question whose answer is "most of the repository": a glob target such as `src/**` handed to `get_summaries` or `get_symbol_sources`, or a broad name pattern handed to `search_symbols`. Today the tools do all of that work before replying. On a repository the size of Firefox (about 401,804 tracked files, 4.2 GB), this was measured during the CodeScaleBench grep-hard evaluation (2026-08-06 checkpoint, `.agents/docs/codescale-grep-hard-checkpoint-2026-08-06.md`) at 83-132 seconds for a broad six-pattern `search_symbols` call before SQL batching, and roughly 90 seconds after.

After this change, a tool that can see -- cheaply, before its expensive phase -- that a request matched far more code than any caller can use stops immediately and returns a structured "too broad" answer: how much matched, what the cap is, a small sample, and how to narrow. The agent gets an honest sub-second reply instead of a two-minute stall, and nothing is silently dropped. The repository already has this pattern in one tool: `scan_usages` returns a `TooManyCallsites` result carrying the true total, the cap, and `complete = false` (see `crates/bifrost-analysis/src/searchtools/scan_usages.rs`, around lines 428 and 865). This plan extends the same idea to the remaining unguarded fan-out paths.

You can see it working by running the new behavior tests (each fails before its guard exists and passes after), and by calling `get_summaries` with a glob that matches more files than the cap on a small inline test project: the reply arrives with a `too_broad` block instead of a summary per file.

## Progress

- [x] (2026-08-06) Audit of every searchtools entry point completed; unguarded fan-out paths identified (recorded in Context and Orientation below).
- [x] (2026-08-06 18:22Z) Milestone 1: shared `TooBroadScope` type and the `get_summaries` per-target guard, with render support and behavior tests. Landed in `crates/bifrost-analysis/src/searchtools/mod.rs` (constants and type), `summaries.rs` (routing guard, `too_broad` on `SummaryTargets` and `SummaryResult`), `crates/bifrost-analysis/src/searchtools_render.rs` (`render_too_broad_scope`), `crates/bifrost-mcp/src/mcp_common.rs` (`render_too_broad_json` for the budgeted path), and four tests in `tests/suite_symbols/searchtools_too_broad_scope.rs`.
- [x] (2026-08-06 18:40Z) Milestone 2: `get_symbol_sources` glob-arm guard, with render support and behavior tests. Landed in `crates/bifrost-analysis/src/searchtools/mod.rs` (`GET_SYMBOL_SOURCES_MAX_FILES_PER_TARGET`, plus `too_broad_scope` moved here from `summaries.rs` so both glob consumers share it), `sources.rs` (`SourceLookupOutcome::TooBroad`, `too_broad` on `SymbolSourcesResult`, the guard in `get_symbol_sources_with_cap`), `crates/bifrost-analysis/src/searchtools_render.rs` (reuses `render_too_broad_scope`), and four more tests in `tests/suite_symbols/searchtools_too_broad_scope.rs`.
- [x] (2026-08-06 19:05Z) Milestone 3: `search_symbols` post-resolution candidate cap, with behavior tests and a provisional cap value. Landed in `crates/bifrost-analysis/src/searchtools/mod.rs` (`SEARCH_SYMBOLS_MAX_RANKED_CANDIDATES`), `navigation.rs` (`TooManySymbolMatches`, `too_many_matches` on `SearchSymbolsResult`, the guard in `search_symbols_with_cap`), `crates/bifrost-analysis/src/searchtools_render.rs` (`render_too_many_symbol_matches`), and two unit tests in `crates/bifrost-analysis/src/searchtools/tests.rs` that pass a tiny cap. Shipped total-only, without `per_pattern`; see the Decision Log.
- [x] (2026-08-06 19:25Z) Milestone 4: workspace-root `get_summaries` latency. Read-only investigation completed and filed as https://github.com/BrokkAi/bifrost/issues/1738 (18:40Z), which owns the dominant-cost question. The two bounded code items landed here: `profiling::scope` spans named `project::collect_workspace_files` (`crates/bifrost-core/src/analyzer/project.rs`), `gitblob::dirty_worktree_paths` (`crates/bifrost-core/src/gitblob.rs`), and `searchtools::directory_listing` (`summaries.rs`); and the `all_files()` -> `all_files_shared()` swap in `route_summary_targets_with_cancellation`.
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
- Observation: `get_summaries` result text is not rendered in `crates/bifrost-mcp/src/searchtools_service.rs`, as this plan first stated. That file only decodes arguments and calls `RenderText::render_text`; the implementation is `impl RenderText for SummaryResult` in `crates/bifrost-analysis/src/searchtools_render.rs`. A second, independent renderer exists in `crates/bifrost-mcp/src/mcp_common.rs` (`render_budgeted_get_summaries_text`), which rebuilds the text from the serialized JSON whenever the response exceeds `GET_SUMMARIES_RESPONSE_BUDGET_BYTES`. Milestone 1 therefore edits two render sites, not one; Milestones 2 and 3 should expect the same shape.
  Evidence: `searchtools_service.rs` `decode_render_and_run` calls `result.render_text(render_options)`; `mcp_common.rs` line 2109 area `render_container_listings_json` already re-implements `render_container_listing` against JSON for the same reason.
- Observation: three pre-existing test failures in `cargo nextest run -p brokk-bifrost-analysis` and six in the focused `--workspace` searchtools selection are unrelated to this work; they fail identically with the Milestone 1 changes stashed. They are `analyzer::jvm::java_artifact::tests::source_and_class_jars_share_declaration_ids_and_keep_distinct_origins` (panics with "Java producer parity tests require javac and jar"), the two `analyzer::tree_sitter_analyzer::tests::live_oid_resolution_*` rendezvous tests, and `csharp_generic_type_resolves_without_arity_spelling`, `summaries_route_file_anchored_selector_with_extension_like_symbol_member`, `summaries_and_ancestors_accept_js_file_anchored_selectors`, `scan_usages_resolves_public_typescript_static_method_symbol`, `manual_service_sees_change_after_explicit_update_paths`, `bifrost_searchtools_server_speaks_mcp_stdio`.
  Evidence: `git stash push` of the four changed source files, rerun of the same selection, same six failures; `git stash pop` restored the work.
- Observation (Milestone 4 investigation, 2026-08-06): the #1325 stat guard provides zero protection for the workspace-root target. `directory_listing_root("/")` yields the empty relative path (`summaries.rs:305-313`), and `FilesystemProject::has_directory` is `self.root.join(rel_path).is_dir()` (`crates/bifrost-core/src/analyzer/project.rs:681-683`); `root.join("")` is always the root, so the guard is trivially true and the full listing path always executes.
- Observation (Milestone 4 investigation): `Project::all_files()` deep-clones the cached `BTreeSet<ProjectFile>` on every call (`project.rs:650-656`), while the zero-copy accessor `all_files_shared` (`project.rs:658-664`) has no callers anywhere in the workspace. Separately, under `UpdateStrategy::Manual` (`crates/bifrost-mcp/src/searchtools_service.rs:791-798`, used by batch/localizer consumers) `listing_cache_for` returns `None`, so there is no session-level listing cache at all and every `all_files()` call performs a fresh walk; the git fast path of that walk shells out to `git status --porcelain=v1 -z --untracked-files=all` over the whole tree (`crates/bifrost-core/src/gitblob.rs:476-516`).
  Evidence: static reading with citations above; which of walk, clone, per-call `directory_listing()` reconstruction, or cold-session overhead dominates the measured 126.98 s is genuinely unknown, because neither `project.rs` nor `gitblob.rs` carries a `profiling::scope`.

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

- Decision: Milestone 1's behavior tests exercise the shipped constant `GET_SUMMARIES_MAX_FILES_PER_TARGET` on a 25-file inline fixture instead of passing a tiny cap, even though the routing function does take the cap as a parameter.
  Rationale: `route_summary_targets_with_cancellation` is private to `crates/bifrost-analysis`, so an integration test in `tests/suite_symbols/` cannot reach it, and adding a public test-only entry point to `get_summaries` would be a worse trade than writing 25 one-line Java files (the fixture builds and runs in under a quarter second). Testing through the public MCP tool also proves the whole path -- routing, result assembly, serialization, and rendering -- rather than the routing function alone. The cap parameter stays because Milestone 2 reuses the shape and because the constant belongs at the tool entry point, not buried in routing.
  Date/Author: 2026-08-06, implementation.
- Decision: render the too-broad paragraph twice -- once in `impl RenderText for SummaryResult` and once in `render_too_broad_json` in `crates/bifrost-mcp/src/mcp_common.rs` -- rather than share one function.
  Rationale: the MCP budgeting path has already lost the typed result by the time it rebuilds text; it works from `serde_json::Value` and `TooBroadScope` derives only `Serialize`. `render_container_listings_json` in the same file duplicates `render_container_listing` for exactly this reason, so the duplication follows the established local idiom instead of adding a `Deserialize` derive to a result type purely to undo a serialization. A skipped target must survive the byte-budget degradation, so the budgeted renderer cannot simply drop it.
  Date/Author: 2026-08-06, implementation.
- Decision: the guard trips on `matches.files.len() > cap`, not `>=`.
  Rationale: a target matching exactly the cap is inside the advertised bound and is summarized normally; the reported `cap` then reads as "at most this many", which is what the rendered instruction tells the agent.
  Date/Author: 2026-08-06, implementation.
- Decision: Milestone 4's deliverable is the filed issue https://github.com/BrokkAi/bifrost/issues/1738, not an in-plan root-cause fix.
  Rationale: the investigation confirmed four layered costs on the root-listing path (git-status walk, per-call deep clone, per-call listing reconstruction, possible cold-session overhead) but could not establish which dominates the 126.98 s measurement, because the path has no fine-grained profiling spans and the known reproduction environment (the shared DW10 cache) was in use by a live evaluation. Claiming a fix without that split would violate the plan's own honesty standard. No existing issue covered the path exactly: #1325 produced today's stat guard and stops at file targets, #1401's session walk cache does not exist under `UpdateStrategy::Manual` and does not cover the clone or reconstruction, #1334 is a different tool's walk repetition.
  Date/Author: 2026-08-06, Fable.
- Decision: fold two bounded code items into Milestone 4's remaining scope: `profiling::scope` spans at the listing-path cost points, and the same-semantics swap of `all_files()` to `all_files_shared()` in `route_summary_targets_with_cancellation`.
  Rationale: the spans are the prerequisite for the measurement #1738 needs, and are additive. The swap removes one confirmed real cost (rebuilding a ~401,804-node `BTreeSet` of `Arc` pointers per call) with no semantic change: it is the same `Project` instance's own listing behind an `Arc` instead of a deep clone. Neither item claims to be "the fix"; the dominant-cost question stays with #1738.
  Date/Author: 2026-08-06, Fable.
- Decision: `too_broad_scope` moved from `summaries.rs` into `searchtools/mod.rs`, next to `TooBroadScope` itself, rather than being duplicated or re-exported.
  Rationale: Milestone 2 is the second caller, and both callers already reach `mod.rs` through `use super::*`. The helper only needs `ProjectFile` and `rel_path_string`, both already imported there. Keeping it private (no `pub(super)`) matches the existing `FILE_SEARCH_LIMIT` idiom: child modules see their ancestors' private items, so no visibility widening is needed.
  Date/Author: 2026-08-06, implementation.
- Decision: `get_symbol_sources` threads its cap through a private `get_symbol_sources_with_cap(analyzer, params, max_files_per_target)`, with the public entry point supplying the constant.
  Rationale: unlike `get_summaries`, this tool has no routing function to hang the parameter on -- the glob arm lives inside the per-symbol rayon closure. A thin private wrapper is the smallest shape that keeps the constant at the entry point, matches Milestone 1's structure, and leaves the public signature unchanged.
  Date/Author: 2026-08-06, implementation.
- Decision: `get_symbol_sources` needed only one render site, not two.
  Rationale: `render_budgeted_get_summaries_text` and `GET_SUMMARIES_RESPONSE_BUDGET_BYTES` in `crates/bifrost-mcp/src/mcp_common.rs` are specific to `get_summaries`; `rg -n "RESPONSE_BUDGET_BYTES" crates/bifrost-mcp/src/mcp_common.rs` finds no other tool. `get_symbol_sources` budgets in `SearchToolsService::symbol_sources_output` (`searchtools_service.rs`), which rejects an over-budget response outright instead of rebuilding text from JSON, and otherwise calls `result.render_text(...)`. So the `RenderText` impl is the whole surface, and it reuses `render_too_broad_scope` unchanged -- the Milestone 1 wording ("target X matched N files, over the C file limit for one target, so it was skipped", plus the sample and the narrowing instruction) is already tool-neutral.
  Date/Author: 2026-08-06, implementation.
- Decision: collapse the five-arm identity `match` that re-wrapped `resolve_file_anchored_symbol_sources`' `SourceLookupOutcome` into `return (index, outcome)`.
  Rationale: adding `TooBroad` would have required a fifth arm that maps a variant to itself. The match never did anything but rebuild what it destructured, so the new variant made an existing redundancy load-bearing; removing it is smaller than extending it and cannot change behavior.
  Date/Author: 2026-08-06, implementation.
- Decision: `TooManySymbolMatches` ships total-only. The `per_pattern: Vec<(String, usize)>` field the plan specified is not implemented, and the field is removed rather than always-empty.
  Rationale: attribution is not cheaply available and, worse, cannot be made honest from `search_symbols`. `SearchSymbolPatternBatch::is_match` (`crates/bifrost-analysis/src/analyzer/i_analyzer.rs:140`) tests the whole batch, and its `compiled` form is a `RegexSet` built only from the patterns that compiled, so set-match indices do not map back to input positions. More decisively, whether a candidate matched is decided by `self.fq_matches(&code_unit, |name| patterns.is_match(name))` (`tree_sitter_analyzer.rs:6732`), which tries a language-specific set of name spellings that `search_symbols` cannot reach through `&dyn IAnalyzer`. Re-deriving counts here from `fq_name()` alone would produce per-pattern numbers that disagree with `total_candidates` -- an incomplete-and-misleading structured result, which repository convention forbids. The plan anticipated this outcome and authorized it.
  Date/Author: 2026-08-06, implementation.
- Decision: when the cap trips, the counts live in the typed `too_many_matches` block and the "what do I do now" guidance lives in the existing `note` field (`too_many_symbol_matches_note`).
  Rationale: `note` is already this result's channel for explaining a partial answer (`search_symbols_note`), and `TooManyCallsitesInfo` sets the same precedent by carrying its own note next to its counts. Splitting counts from guidance keeps the prose in one place: the renderer formats the counts and prints the note verbatim, so there is no second copy of either to drift.
  Date/Author: 2026-08-06, implementation.
- Decision: Milestone 3's tests are crate-internal unit tests in `crates/bifrost-analysis/src/searchtools/tests.rs` passing an explicit cap of 3, not MCP-level integration tests on a shipped-constant-sized fixture.
  Rationale: the opposite of Milestone 1's trade. Reaching a 10,001-candidate fixture through the public MCP tool is not something an `InlineTestProject` can do in test time, whereas `search_symbols_with_cap` is `pub(super)` and directly reachable from the crate's own test module, exactly as `scan_usages` tests pass `limit: 1000` explicitly. Driving it needed one data field on the existing hand-written `CountingAnalyzer` fake (`search_definition_results`, empty by default, so no existing test changes behavior) plus a `ranges` override, because the default `IAnalyzer::search_symbol_candidates` builds candidates out of `search_definitions` and `ranges`. Note `ranges_of` defaults to `ranges`, so only `ranges` needed overriding; overriding `ranges_of` alone silently did nothing and was the first attempt's failure.
  Date/Author: 2026-08-06, implementation.
- Decision: reject the single-level `readdir` listing (Option B of the investigation) for this plan.
  Rationale: today's `directory_listing` emits a child entry only when at least one actual project file exists beneath it (`summaries.rs:322-345`). A single-level `readdir` cannot know that without recursing, so it would either list directories whose contents are entirely ignored (a user-visible contract regression) or reintroduce a partial walk. It also does not compose with the git-index fast path, which returns a flat path set with no per-directory enumeration primitive. If #1738's measurement shows the walk dominates, that issue owns the redesign.
  Date/Author: 2026-08-06, Fable.

## Outcomes & Retrospective

Milestone 1 (2026-08-06): `get_summaries` now answers a too-broad glob target instantly with a structured `too_broad` entry naming the target, the true match count, the cap, and the first ten matched paths, plus an instruction to narrow to a subdirectory, an explicit file list, or `list_symbols`. Nothing else changed: an under-cap glob still summarizes every file, and explicit file targets are exempt no matter how many are given.

Proof, on a 25-file inline fixture with `GET_SUMMARIES_MAX_FILES_PER_TARGET = 20`:

    cargo nextest run --test suite_symbols -E 'test(too_broad)'
    Summary [0.209s] 4 tests run: 4 passed, 1200 skipped

With the guard branch in `route_summary_targets_with_cancellation` commented out, the same command reports:

    Summary [0.231s] 4 tests run: 2 passed, 2 failed
    FAIL searchtools_too_broad_scope::get_summaries_glob_over_cap_reports_too_broad_and_skips_summaries
         assertion `left == right` failed ... left: 1  right: 0
    FAIL searchtools_too_broad_scope::get_summaries_too_broad_render_names_target_counts_and_narrowing

The two non-regression tests (under-cap glob, 25 explicit file targets) pass in both states, which is the point: the guard adds a branch and changes nothing else.

Remaining after Milestone 1: Milestones 2 through 5. Lesson for the next milestone: the plan's render-site pointer was one file off, and the MCP byte-budget renderer is a second, JSON-shaped copy of the same text; check both when adding a new result field that must reach the agent.

Milestone 2 (2026-08-06): `get_symbol_sources` now answers a glob-shaped symbol argument matching more than `GET_SYMBOL_SOURCES_MAX_FILES_PER_TARGET` (10) files with the same structured `too_broad` entry and no source blocks at all, instead of the full text of every matched file. The cap is half the summaries cap because a source block is the heaviest per-file payload the searchtools produce. Exact symbol names, path-qualified selectors, and explicit single-file paths resolve before the glob arm and are untouched, as is any glob at or under the cap.

Proof, on the same 25-file / 5-file inline fixture:

    cargo nextest run --test suite_symbols -E 'test(too_broad)'
    Summary [0.238s] 8 tests run: 8 passed, 1200 skipped

With the guard branch in `get_symbol_sources_with_cap` removed, the same command reports:

    Summary [0.247s] 8 tests run: 6 passed, 2 failed
    FAIL searchtools_too_broad_scope::get_symbol_sources_glob_over_cap_reports_too_broad_and_skips_sources
         assertion `left == right` failed ... left: 1  right: 0   (25 file-outline source blocks came back instead)
    FAIL searchtools_too_broad_scope::get_symbol_sources_too_broad_render_names_target_counts_and_narrowing

The four Milestone 1 tests and the two new non-regression tests (under-cap glob, exact name plus explicit path) pass in both states. The wider selection `cargo nextest run --workspace -E 'test(/searchtools|summaries|symbol_sources|search_symbols/)'` reports only failures from the pre-existing list in `Surprises & Discoveries`.

Milestone 3 (2026-08-06): `search_symbols` now stops before ranking when the resolved, deduplicated candidate set exceeds `SEARCH_SYMBOLS_MAX_RANKED_CANDIDATES` (10,000, provisional). It skips ranking, the git-tier lookup, and the semantic-model overlay, returns `truncated = true` with no files, and reports the true candidate count and the cap through the typed `too_many_matches` block plus a narrowing note. Below the cap nothing changed at all. The `__warmup__` call the plan flagged is `crates/bifrost-mcp/src/mcp_common.rs:2994`, inside a test, against a one-file temporary project; it matches nothing and cannot approach the cap. `rg -n "__warmup__" crates/` finds no other occurrence.

Proof, with a five-candidate fake analyzer and an explicit cap of 3:

    cargo nextest run -p brokk-bifrost-analysis \
      -E 'test(search_symbols_over_candidate_cap) + test(search_symbols_under_candidate_cap)'
    Summary [0.020s] 2 tests run: 2 passed, 1785 skipped

With the guard branch disabled (`if false && filtered.len() > max_ranked_candidates`):

    Summary [0.021s] 2 tests run: 1 passed, 1 failed
    FAIL searchtools::tests::search_symbols_over_candidate_cap_skips_ranking_and_reports_the_totals
         panicked: five candidates over a cap of three must report the overload

The non-regression test (same five candidates, cap 10: one file, five ranked classes, `too_many_matches` absent) passes in both states.

Milestone 4 code items (2026-08-06): the listing path is now instrumented and the per-call deep clone is gone. `bifrost-core` needed no new dependency for the spans: it owns `profiling` (`crates/bifrost-core/src/lib.rs:26`), so `collect_workspace_files` and `dirty_worktree_paths` carry `crate::profiling::scope` directly and the crate-dependency rule in `CLAUDE.md` is untouched. `route_summary_targets_with_cancellation` now holds `OnceCell<Arc<BTreeSet<ProjectFile>>>` filled by `all_files_shared()`, which had no callers in the workspace before this change.

Proof that all three spans are reachable from a directory-target `get_summaries` (the two runs differ only in whether the fixture's project is a filesystem project, which is what decides whether the walk runs at all):

    BIFROST_TIMING=1 cargo nextest run --test suite_symbols --no-capture \
      -E 'test(get_summaries_directory_target_stays_narrow_on_service_path)'
    [bifrost-timing]   BEGIN project::collect_workspace_files
    [bifrost-timing]   END project::collect_workspace_files (6.4 ms)
    [bifrost-timing]     BEGIN searchtools::directory_listing
    [bifrost-timing]     END searchtools::directory_listing (0.2 ms)

    BIFROST_TIMING=1 cargo nextest run --test suite_symbols --no-capture \
      -E 'test(get_summaries_lists_workspace_root_directory_target)'
    [bifrost-timing]           BEGIN gitblob::dirty_worktree_paths
    [bifrost-timing]           END gitblob::dirty_worktree_paths (11.9 ms)
    [bifrost-timing]     BEGIN searchtools::directory_listing
    [bifrost-timing]     END searchtools::directory_listing (0.0 ms)

`cargo nextest run --workspace -E 'test(/director|listing|summaries/)'` reports 158 of 160 passing, the two failures being the pre-existing `summaries_route_file_anchored_selector_with_extension_like_symbol_member` and `summaries_and_ancestors_accept_js_file_anchored_selectors` from the list above. Neither span nor the swap changes any assertion.

Gate for Milestones 2 through 4: `cargo clippy --workspace --all-targets -- -D warnings` is clean (featureless; nothing here touches NLP), after two lint fixes in the new test code -- a needless borrow around a `format!` argument and an `assert!` over two constants that clippy wants as `const { assert!(..) }`. `cargo nextest run -p brokk-bifrost-analysis` reports 1777 of 1780 passing; the three failures are the pre-existing `java_artifact` javac/jar test and the two `live_oid_resolution_*` rendezvous tests already listed in `Surprises & Discoveries`.

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

There are two render sites, not one. The tool text an agent normally sees comes from `impl RenderText for SummaryResult` in `crates/bifrost-analysis/src/searchtools_render.rs`; `crates/bifrost-mcp/src/searchtools_service.rs` only calls it (`decode_render_and_run`). Render each `too_broad` entry there as an explicit paragraph naming the target, the matched count, the cap, the sample paths, and the instruction to narrow to a subdirectory, an explicit file list, or `list_symbols` (which self-truncates). The second site is the byte-budget path: `crates/bifrost-mcp/src/mcp_common.rs` special-cases `get_summaries` output around line 1365 and, when the response exceeds `GET_SUMMARIES_RESPONSE_BUDGET_BYTES`, rebuilds the text from JSON in `render_budgeted_get_summaries_text`. Add the same paragraph there (as implemented: `render_too_broad_json`), otherwise a skipped target disappears exactly when the response was large.

Tests, using `InlineTestProject` in `tests/suite_symbols/searchtools_too_broad_scope.rs` (registered in that suite's `main.rs`; `searchtools_service.rs` is over ten thousand lines): (a) behavior: `wide/**` over a 25-file directory asserts the reply has one `too_broad` entry with `matched = 25`, `cap = GET_SUMMARIES_MAX_FILES_PER_TARGET`, a ten-element sorted sample, and no summaries at all; (b) non-regression: `narrow/**` over five files summarizes all five and `too_broad` is empty; (c) explicit file targets never trip the guard even when more targets than the cap are given (25 explicit paths, 25 summaries); (d) an MCP-level render assertion that the too-broad paragraph appears in the tool text. Do not assert exact prose beyond the load-bearing tokens (target, counts, sample path, `list_symbols`). Note that `too_broad` is `skip_serializing_if = "Vec::is_empty"`, so a test helper must treat an absent key as an empty list.

Acceptance: the new tests fail before the guard exists (comment out the guard branch in `route_summary_targets_with_cancellation`: the two guard tests fail, the two non-regression tests keep passing) and pass after; the full focused suite passes.

### Milestone 2: get_symbol_sources guard

Scope: after this milestone, a glob-shaped symbol argument matching more files than a (smaller) cap returns a structured too-broad outcome instead of the full text of every matched file.

In `mod.rs` add `pub const GET_SYMBOL_SOURCES_MAX_FILES_PER_TARGET: usize = 10;` -- smaller than the summaries cap because this tool returns full source text, the heaviest payload per file.

In `crates/bifrost-analysis/src/searchtools/sources.rs`: add a `TooBroad(TooBroadScope)` variant to `SourceLookupOutcome`, and a `too_broad: Vec<TooBroadScope>` field to `SymbolSourcesResult` (same serde attributes as in Milestone 1). At the glob arm (lines 355-369), when `file_matches.files.len()` exceeds the cap, return the new outcome instead of calling `source_blocks_for_files`. Collect it in the outcome loop at lines 447-454. Thread the cap as a parameter the same way as Milestone 1. Update the render site, which for this tool as for `get_summaries` is the `RenderText` impl in `crates/bifrost-analysis/src/searchtools_render.rs`, not `searchtools_service.rs` (note `get_symbol_sources` also has bespoke handling in `searchtools_service.rs` around lines 1496 and 2976; read both before editing).

Tests mirror Milestone 1 in the appropriate `tests/suite_symbols/` file: glob over cap yields `too_broad` and no source blocks; glob under cap yields sources; an exact symbol name and an explicit single-file path are unaffected.

Acceptance: tests fail before, pass after; focused suite green.

### Milestone 3: search_symbols candidate cap

Scope: after this milestone, a pattern set that resolves to more deduplicated candidates than the cap skips ranking and returns a structured too-many-matches reply, and normal broad searches (the tool's intended use) are unaffected.

In `mod.rs` add `pub const SEARCH_SYMBOLS_MAX_RANKED_CANDIDATES: usize = 10_000;` with a comment stating it is provisional: on Firefox, ranking took about 34 s for a six-pattern broad search, and the cap should be tuned once a candidate count for that workload is measured (Milestone 4's environment can measure it; record the number here when known).

In `crates/bifrost-analysis/src/searchtools/navigation.rs`, in `search_symbols_with_cancellation` after the `filtered` vector is built (line 383) and before `rank_search_symbol_candidates` (line 386): if `filtered.len()` exceeds the cap, skip ranking, git-tier lookup, and the semantic-model overlay work, and produce a result whose new optional field describes the overload. Define next to `SearchSymbolsResult`:

    pub struct TooManySymbolMatches {
        pub total_candidates: usize,
        pub cap: usize,
    }

and add `pub too_many_matches: Option<TooManySymbolMatches>` to `SearchSymbolsResult`, setting `complete = false` when it is set. As implemented, there is no `per_pattern` field: attribution is neither cheap nor honestly derivable from `search_symbols` (Decision Log). Thread the cap as a parameter (`search_symbols_with_cap`, with `search_symbols_with_cancellation` supplying the constant). Render in `impl RenderText for SearchSymbolsResult` in `crates/bifrost-analysis/src/searchtools_render.rs` (not `searchtools_service.rs`, which only calls `render_text`): state the totals and print the note that instructs the agent to use more specific patterns. There is no budgeted JSON renderer for this tool. The warmup call in `crates/bifrost-mcp/src/mcp_common.rs` (line 2994, a test) uses pattern `__warmup__`; confirmed it matches nothing and cannot trip the cap.

Tests: with a tiny cap parameter (3) and a five-candidate `CountingAnalyzer` in `crates/bifrost-analysis/src/searchtools/tests.rs`, assert `too_many_matches` is set with `total_candidates = 5`, `truncated = true`, and the ranked file list is empty; with the cap above the count, assert unchanged normal output. Add a render assertion.

Acceptance: tests fail before, pass after; focused suite green.

### Milestone 4: workspace-root get_summaries latency

The investigation half is complete (2026-08-06). The 126.98 s `get_summaries` call on Firefox requested `/`; that path builds `analyzer.project().all_files()` (summaries.rs line 253 area, inside `route_summary_targets_with_cancellation`) purely to list the root's direct children. The issue search found no exact coverage, and the root cause could not be attributed to a single dominant cost by static reading (the four candidate costs and the citations are in `Surprises & Discoveries`), so the deliverable is the filed issue https://github.com/BrokkAi/bifrost/issues/1738, which carries the full evidence: the trivially-true `has_directory("")` guard, the per-call deep clone in `all_files()`, the unused `all_files_shared()` accessor, the absent listing cache under `UpdateStrategy::Manual`, and the whole-tree `git status --untracked-files=all` subprocess in the git fast path.

Two bounded code items remain in this plan (see the Decision Log for why exactly these two and nothing more):

First, instrumentation. Add `profiling::scope` spans so a later measurement can split the cost: one inside `collect_workspace_files` in `crates/bifrost-core/src/analyzer/project.rs` (covering the walk itself), one inside `dirty_worktree_paths` in `crates/bifrost-core/src/gitblob.rs` (covering the `git status` subprocess), and one wrapping the body of `directory_listing` in `crates/bifrost-analysis/src/searchtools/summaries.rs` (covering the per-call listing reconstruction). Follow the naming style of the existing spans (`searchtools::route_summary_targets`).

As implemented: `bifrost-core` owns the profiling facility itself (`pub mod profiling;` in `crates/bifrost-core/src/lib.rs`, and `gitblob.rs` already calls `crate::profiling::enabled()`), so both lower spans go where the plan asked and no dependency question arises. `brokk-bifrost-analysis` reaches the same module by re-export. The three spans are named `project::collect_workspace_files`, `gitblob::dirty_worktree_paths`, and `searchtools::directory_listing`.

Second, the zero-copy swap. In `route_summary_targets_with_cancellation`, change the lazily-built listing cell from `OnceCell<BTreeSet<ProjectFile>>` holding `all_files()` (a deep clone per call when the cache is warm) to `OnceCell<Arc<BTreeSet<ProjectFile>>>` holding `all_files_shared()`. `directory_listing` already takes `&BTreeSet<ProjectFile>`, so `&Arc<BTreeSet<ProjectFile>>` deref-coerces at the call site with no explicit `&*`. This is the same `Project` instance's own listing with the clone removed; no semantics change. Do not chase other `all_files()` callers (for example `WorkspaceFileIndex::build`); #1738 owns the broader question.

Acceptance: the spans appear in profiling output for a directory-target `get_summaries` call (a unit or integration observation is enough; no Firefox-scale run is required in this plan), the swap compiles with no behavior change in the existing directory-listing tests, and the issue URL is recorded in Progress (done).

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

In `summaries.rs`: `SummaryTargets` and `SummaryResult` gain `too_broad: Vec<TooBroadScope>`. In `sources.rs`: `SymbolSourcesResult` gains `too_broad: Vec<TooBroadScope>`; `SourceLookupOutcome` gains a `TooBroad` variant. In `navigation.rs`: `SearchSymbolsResult` gains `too_many_matches: Option<TooManySymbolMatches>` with the struct as specified in Milestone 3 (total-only, no `per_pattern`). Internal enforcement functions take the cap as a `usize` parameter; public tool entry points pass the constants. As implemented in Milestone 1, `route_summary_targets_with_cancellation(analyzer, targets, max_files_per_target, cancellation)` is that function for `get_summaries`, `get_symbol_sources_with_cap(analyzer, params, max_files_per_target)` is that function for `get_symbol_sources`, and the module-private helper `too_broad_scope(target, matched, cap) -> TooBroadScope` in `searchtools/mod.rs` builds the report for both. Rendering lives in `crates/bifrost-analysis/src/searchtools_render.rs` (the `RenderText` impls) with a second JSON-shaped copy in `crates/bifrost-mcp/src/mcp_common.rs` for the byte-budget path; descriptions in `crates/bifrost-mcp/src/mcp_core.rs` / `mcp_extended.rs`.

## Revision notes

- 2026-08-06 (Milestone 1 implementation): corrected the render-site pointer from `crates/bifrost-mcp/src/searchtools_service.rs` to `crates/bifrost-analysis/src/searchtools_render.rs`, and added the second render site in `crates/bifrost-mcp/src/mcp_common.rs`, because that is where the text is actually produced; a plan that sent the next contributor to the wrong file would cost them the same search. Replaced the tiny-cap test recipe with the shipped-constant recipe and named the real test file, because the routing function is crate-private and unreachable from an integration suite; the reasoning is in the Decision Log. Recorded the pre-existing unrelated test failures in `Surprises & Discoveries` so a later contributor does not attribute them to this plan.
- 2026-08-06 (Milestone 2 implementation): corrected the Milestone 2 render-site expectation. The section warned that `get_symbol_sources` might need a second, JSON-shaped renderer like `get_summaries`; it does not, because the MCP byte budget for this tool rejects rather than degrades. Recorded where the helper `too_broad_scope` now lives (`searchtools/mod.rs`) and the private-wrapper shape used to thread the cap, so Milestone 3 does not rediscover either.
- 2026-08-06 (Milestone 4 code items): recorded that `bifrost-core` owns the profiling module, so the milestone's conditional fallback (spans at higher-layer call sites if core cannot reach profiling) never applied and no Decision Log entry was needed for it. Replaced the `&*shared` instruction with the deref coercion the compiler actually accepts, and added the observed span output to `Outcomes & Retrospective` so a later reader does not have to re-derive which fixture shape exercises which span.
- 2026-08-06 (Milestone 3 implementation): dropped `per_pattern` from `TooManySymbolMatches` and rewrote the milestone's render and test recipes. The render pointer said `searchtools_service.rs` for the third milestone running; it is the `RenderText` impl, as Milestone 1 already discovered. The test recipe said `InlineTestProject` with a tiny cap, which is not reachable for this tool: the cap-taking function is crate-internal, so the tests are crate-internal unit tests instead -- the mirror image of Milestone 1's trade, and worth stating so the pattern does not read as inconsistent.
- 2026-08-06 (Milestone 4 investigation): rewrote Milestone 4 from an open investigation into its outcome. The read-only investigation confirmed the mechanism (trivially-true `has_directory("")`, per-call deep clone, no listing cache under `UpdateStrategy::Manual`, whole-tree `git status` subprocess) but could not attribute the 126.98 s to one dominant cost without new profiling spans, so the deliverable became issue #1738 plus two bounded code items kept in this plan: the spans that make the measurement possible, and the semantics-preserving `all_files_shared()` swap. The single-level `readdir` alternative was evaluated and rejected; reasons in the Decision Log.
