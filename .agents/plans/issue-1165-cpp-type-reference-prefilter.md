# Issue 1165 C++ type-reference prefilter

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agents/PLANS.md](/mnt/optane/bifrost-fird/.agents/PLANS.md).

## Purpose / Big Picture

Issue #1165 reports that broad C/C++ type inverse queries can spend many minutes rescanning a header-dense repository. The initial hypothesis blamed repeated declaration-side guard normalization, but isolated libgit2 experiments rejected four cache boundaries, including a final per-reference visibility-decision cache. The current goal is to remove irrelevant target-specific lexical work before it begins: use the structured type-reference components and the visibility index to prove cheaply whether a node could resolve to the queried target, while preserving all existing exact alias, scope, guard, and macro checks for plausible nodes. The behavior is observable through focused alias/scope regressions, a scan-count test with many unrelated types, and a completed 796-target libgit2 replay.

## Progress

- [x] (2026-07-24 22:10Z) Read `.agents/PLANS.md`, located `external_type_candidate_visible_in_context`, and audited the existing include/guard helper caches and tests.
- [x] (2026-07-24 22:42Z) Implemented a request-scoped resolver cache for normalized external type visibility evidence plus a test-only build counter.
- [x] (2026-07-24 22:51Z) Added focused repeated-guarded-reference coverage in both the resolver unit tests and the public/authoritative C++ integration suite.
- [x] (2026-07-24 23:19Z) Ran formatting, the two new tests, the existing conditional-guard regressions, and the complete `usages_cpp_graph_test` integration target; all 146 integration tests passed.
- [x] (2026-07-25 00:19Z) Strengthened the cache-counter test so later references after `#undef FEATURE` must remain rejected while reusing the same normalized evidence.
- [x] (2026-07-25 00:27Z) Rejected the first eager flat-evidence cache after an isolated libgit2 replay showed a severe forward regression: the unmodified head completed 312 files in 264.9 seconds, while the candidate reached only 311 files in 1,618.6 seconds.
- [x] (2026-07-25 01:24Z) Rejected a cached ordered peer-list revision after it left `src/libgit2/merge.c` running for minutes even though the unmodified run completed that file inside its first 309 completions.
- [x] (2026-07-25 01:58Z) Rejected exact-peer flattened route evidence after `merge.c` and `object_api.c` remained unfinished at 257 seconds; both completed before 63 seconds on the unmodified head.
- [x] (2026-07-25 02:23Z) Memoized only the already-eager declaration guard requirement vector and restored every legacy route short circuit verbatim; forward completed in 223.8 seconds and the run reached 170 inverse targets at 1,031.3 seconds versus 1,147.9 seconds unmodified.
- [x] (2026-07-25 03:08Z) Replaced the guard cache's parent `Mutex` with a read-concurrent `RwLock` and added a two-thread same-peer initialization test.
- [x] (2026-07-25 04:18Z) Rejected the declaration-guard-only cache after a clean isolated replay still stalled with eight broad inverse targets in flight; it reached 360 of 796 targets in 2,822 seconds, then emitted no completion for more than twelve minutes and failed to match the pre-fix run's 365 targets in 3,034 seconds.
- [x] (2026-07-25 04:54Z) Profiled only the eight outstanding broad targets with a batch-only final visibility-decision cache. All eight remained unfinished for roughly twelve inverse minutes, so the candidate and temporary target-filter seam were removed.
- [x] (2026-07-25 05:06Z) Traced the authoritative extractor statically and found that each target still scans every candidate file and resolves essentially every type-shaped node for that target, even when its structured terminal name cannot identify the target or one of its aliases.
- [x] (2026-07-25 05:23Z) Ran `git_diff` as the only inverse target. It still failed to finish after twelve inverse minutes, proving that the pathological work exists inside one ordinary symbols query rather than arising primarily from eight-worker contention.
- [x] (2026-07-25) Added a two-stage conservative structured prefilter ahead of expensive target-specific lexical resolution. The target-independent stage rejects impossible bare type names from visible indexed declarations and parser aliases; the target-specific stage preserves direct, qualified, template, indexed-alias, parser-alias, class-owned, inherited-alias, unresolved, and cyclic possibilities.
- [x] (2026-07-25) Confined the new prefilter to actual type-reference queries after the first full integration run showed that applying it to static qualifier and method-owner classification weakened three unrelated proofs. The corrected implementation leaves those owner-classification paths unchanged.
- [x] (2026-07-25) Added behavior-focused exactness coverage for direct, global-qualified, file alias, class alias, inherited alias, and template alias hits, plus a work-count test proving repeated unrelated bare types perform zero lexical-scope reconstructions and zero target-preserving resolution entries while building and parsing the visible alias-name set once.
- [x] (2026-07-25) Ran the focused tests and the complete `usages_cpp_graph_test` target after the semantic confinement fix; all 147 integration tests passed.
- [x] (2026-07-25) Completed the full unfiltered libgit2 replay. Forward finished 312/312 files in 202.9 seconds; inverse reached 365/796 at 1,011.5 seconds versus 3,034.3 seconds pre-fix, then completed 796/796 at 3,060.9 seconds with zero missing rows and every envelope invariant satisfied.
- [x] (2026-07-25) Removed an eager global alias-identifier classification pass after the first repository-wide gate exposed provider-backed scaling of 140 first-run and 137 warm-run calls against bounds of 20 and 10. The final filter remains name-bounded and lazy; the focused scale test, all 147 C/C++ usage tests, and isolated all-feature Clippy pass.
- [x] (2026-07-25) Delegated a final read-only correctness and cache-concurrency review. Oldskool found no actionable issue and confirmed that uncertain parser aliases, templates, unresolved chains, and cycles bypass pruning.
- [x] (2026-07-26) Passed formatting, `git diff --check`, all-target/all-feature
  Clippy with warnings denied, and the complete pre-merge substantive library
  target. The separately isolated MCP integration target passed 28/28.
- [x] (2026-07-26) Merged current `origin/master` at `09771a77`, including its
  cache-schema and FqName refactors. The complete normal-permission
  `cargo test --features nlp,python` matrix then passed on merged head
  `5a54b026`, including all 147 C/C++ usage tests and the symbols MCP/CLI and
  LSP surfaces. Cargo ran outside the sandbox with its normal repository target
  at niceness 10.
- [x] (2026-07-26) Published head `d9df6f92` to `origin/master`, completed the
  exact pushed-head Libgit2 replay at niceness 10 with all 796 inverse targets
  and zero actionable residuals, and closed assigned issue #1165 with the
  production evidence.

## Surprises & Discoveries

- Observation: The expensive path already has reusable primitives for include activation and conditional include projections, but it still recomputes peer filtering and declaration guard extraction for every reference occurrence.
  Evidence: `src/analyzer/usages/cpp_graph/resolver.rs` currently performs `visible_identifier_candidates(...).filter(same_logical_symbol).any(...)` directly inside `external_type_candidate_visible_in_context`.
- Observation: A conventional check-then-insert cache could allow two inverse workers to normalize the same file/symbol key concurrently.
  Evidence: Review of the first implementation found that the expensive build occurred outside the map lock before insertion.
- Observation: Repeated-positive coverage alone did not directly prove that the memoized declaration-side evidence leaves later macro-mutation checks occurrence-local.
  Evidence: Delegated review identified the missing mixed-outcome case, so the resolver test now places two references after `#undef FEATURE` and requires them to remain invisible without rebuilding the evidence.
- Observation: Eagerly flattening all peers, declarations, direct includes, and conditional projections destroys an important forward-resolution fast path.
  Evidence: The pre-fix libgit2 forward phase completed all 312 files in 264.9 seconds. The first cache candidate completed the first 306 in 61 seconds but then spent 1,558 more seconds normalizing broad tail cases and still had one file left when interrupted. The preserved log is `/mnt/optane/tmp/bifrost-fird/c-libgit2-issue1165-dirty-37412679-aborted-eager-cache.log` with SHA-256 `6ababe2798e1ebe4531e5d17133fad02346307b7c3ac8e164134dde668183785`.
- Observation: Eagerly collecting the complete same-logical-symbol peer list also loses too much of the legacy outer iterator's short circuit, even when each peer's guard/projection evidence is lazy.
  Evidence: The peer-list candidate reached 311 of 312 files in 321 seconds, then remained on `src/libgit2/merge.c`; the unmodified run completed that file before its first 309 completions. The preserved log is `/mnt/optane/tmp/bifrost-fird/c-libgit2-issue1165-lazy-dirty-37412679-aborted-peer-list.log` with SHA-256 `33299b2acecbbf937ccf34ed1919ba6bbc0ea0d2b4d4e452c50f43f5b876e3bb`.
- Observation: Even an exact-peer cell is too broad if its initializer flattens every declaration's direct and conditional include routes.
  Evidence: The exact-peer candidate restored the outer iterator but still had `merge.c` and `object_api.c` outstanding at 257 seconds. The unmodified head completed `merge.c` as file 221 at 41.1 seconds and `object_api.c` before its 310th completion at 62.3 seconds. The preserved log is `/mnt/optane/tmp/bifrost-fird/c-libgit2-issue1165-exact-peer-dirty-37412679-aborted-route-flatten.log` with SHA-256 `fd5e36b33a316d103f18f26df1179174ccb04a73d31fa66e8e034d0e7cd2410c`.
- Observation: Parallel target completion is bursty enough that a single same-count checkpoint can be misleading.
  Evidence: The guard-vector run was behind at 134 completed targets (970.3 seconds versus 811.5 seconds), then finished several concurrent broad scans and was ahead at 170 (1,031.3 seconds versus 1,147.9 seconds). The preserved interrupted log is `/mnt/optane/tmp/bifrost-fird/c-libgit2-issue1165-guard-cache-dirty-37412679-aborted-mutex.log` with SHA-256 `c7b810e40178f201048362d9cc0a6c477f17be0faff7699441ad577cefaf1239`. Future acceptance decisions require a completed envelope rather than an intermediate count.
- Observation: Memoizing only `declaration_guard_requirements` is semantically safe and helps some early checkpoints, but it does not remove the pathological broad-target tail.
  Evidence: In the clean isolated `RwLock` replay, forward completed in 237.5 seconds versus 264.9 seconds pre-fix, and inverse reached 100 targets in 664.8 seconds versus 782.6 seconds pre-fix. The run later fell behind, reached 360 targets in 2,822.3 seconds, and then made no progress for more than twelve minutes. The eight in-flight targets at interruption were `git_diff`, `git_vector`, `git_str`, `git_index_entry`, `git_iterator_status_t`, `git_diff_options`, `git_config`, and `checkout_data`. The rejected log is `/mnt/optane/tmp/bifrost-fird/c-libgit2-issue1165-guard-rwlock-dirty-37412679-aborted-insufficient-tail.log`.
- Observation: Delegated read-only preflight/review tasks accidentally started two additional libgit2 runners, contaminating one attempted timing replay.
  Evidence: Those agents reported runner sessions after interruption. Root stopped the agents, confirmed their logs stopped changing, relabeled the artifacts as `aborted-concurrent-interference` and `aborted-delegated-duplicate`, and excluded both from acceptance evidence.
- Observation: Caching the final visibility boolean for an exact `(consumer file, candidate, reference span)` did not remove the broad-target tail.
  Evidence: A profile restricted to the exact eight outstanding targets completed the 312-file forward phase in 216.1 seconds, then left all eight inverse queries unfinished for roughly twelve minutes. The rejected evidence is `/mnt/optane/tmp/bifrost-fird/c-libgit2-issue1165-final-visibility-eight-target-profile.log`; the earlier `BIFROST_TIMING` attempt is separately preserved as `c-libgit2-issue1165-final-visibility-eight-target-profile-aborted-noisy-timing.log`.
- Observation: The authoritative batch shares prepared syntax and one visibility index, but a single type query still invokes a full scan of every candidate file and target-specific lexical resolution for every type-shaped node.
  Evidence: `CppQueryResolver::find_usages_with_visibility` calls `scan_prepared_file` per file/spec, and `maybe_record_type_hit` calls `resolve_type_node_lexically_for_target` before its late terminal-name fallback. The exact-span cache was therefore both too late and too narrow.
- Observation: The broad-target tail is not primarily parallel contention.
  Evidence: With the inverse phase restricted to `git_diff`, the run completed forward in 227.1 seconds and then emitted no inverse completion for twelve minutes before interruption. The log is `/mnt/optane/tmp/bifrost-fird/c-libgit2-issue1165-final-visibility-git-diff-solo-profile.log` with SHA-256 `23cafb515136ad20b78e83c4de28f28234f5a6372245d433195c623e27db96eb`.
- Observation: Rejecting impossible type names before lexical reconstruction removes the pathological tail without regressing forward analysis.
  Evidence: The accepted dirty-candidate replay completed forward in 202.9 seconds and 365 inverse targets in 1,011.5 seconds, compared with 264.9 and 3,034.3 seconds respectively on the unmodified run. It completed all 796 inverse targets in 3,060.9 seconds with 6.55 effective CPU cores and 677,860 KiB peak RSS. The completed envelope is `/mnt/optane/tmp/bifrost-fird/c-libgit2-issue1165-structured-prefilter-dirty-37412679.jsonl` (SHA-256 `5802510147b8a6261f40734c3f0c63defe6c327980fdb9637a724473a1d3d5c1`); its log is the same stem with `.log` (SHA-256 `0258ba341e045a83700cac1c685bd09f4de0ea6cf36bffba3793c757b65bee54`).
- Observation: The completed envelope has no hidden truncation or accounting gap.
  Evidence: It contains one completed record at repository head `32b564e63f9639eaf5ee90fb7a95b3a650156cbd`, covers 326 of 326 eligible files and 10,000 of 10,000 sampled sites, has 796 queried plus zero skipped targets, zero candidate-limit files, zero target-truncated sites, zero file errors, and classification totals of 1,249 consistent, 13 unproven, 8,738 inconclusive, and zero missing.
- Observation: Eagerly deriving a global set of every type-alias identifier defeats provider-backed declaration locality even though the runtime query is cheap afterward.
  Evidence: The first full gate failed `cpp_type_definition_routing_classifies_only_name_bounded_candidates` with 140 provider calls on the first pass and 137 on the warm pass, versus allowed maxima of 20 and 10. Removing the global set restored the test; the accepted implementation now initializes parser-alias names only for a queried file's visible closure and asks indexed declarations only for the reference's terminal name.

## Decision Log

- Decision: Cache only declaration-side normalized evidence keyed by consumer file plus logical symbol, and keep reference-local guard subset and stability checks outside the cache.
  Rationale: This is the smallest change that removes repeated normalization work without weakening exact preprocessor semantics or coupling cache entries to reference byte positions.
  Date/Author: 2026-07-24 / Codex
- Decision: Store an `Arc<OnceLock<Arc<[NormalizedTypeVisibilityEvidence]>>>` per key instead of building before a plain map insertion.
  Rationale: The cell preserves short map-lock critical sections while guaranteeing that concurrent workers build each expensive normalized evidence set only once.
  Date/Author: 2026-07-24 / Codex
- Decision: Reject the eager flat cell and retain a race-safe cell per ordered logical peer instead.
  Rationale: Peer-level initialization can memoize declaration-side guards and projections while retaining the legacy outer `.any()` behavior, so a successful early peer does not force normalization of every later route.
  Date/Author: 2026-07-25 / Codex
- Decision: Do not cache or collect the outer peer list; key memo cells by `(consumer file, exact CodeUnit)` and reach them only through the unchanged legacy iterator.
  Rationale: This preserves the full outer short circuit, including avoiding later peer filtering/cloning work, while still deduplicating the expensive declaration guards and include projections for peers actually examined repeatedly.
  Date/Author: 2026-07-25 / Codex
- Decision: Cache only `declaration_guard_requirements` by exact `CodeUnit`.
  Rationale: That helper already builds its complete vector before the legacy `.any()` loop begins, so memoizing it cannot make a formerly lazy route eager. Include activation, conditional projection merging, and all nested short circuits remain byte-for-byte legacy behavior.
  Date/Author: 2026-07-25 / Codex
- Decision: Use a read-concurrent parent map with one `OnceLock` per exact declaration peer.
  Rationale: Once warmed, inverse workers overwhelmingly hit existing cells. Concurrent reads avoid serializing those hit lookups, while the write path remains limited to cell insertion and the per-key cell still prevents duplicate normalization.
  Date/Author: 2026-07-25 / Codex
- Decision: Reject the declaration-guard-only cache as the issue fix, despite its semantic tests and favorable early checkpoints.
  Rationale: The clean isolated replay failed the practical tail criterion and never produced a completed repository envelope. Publishing a narrow cache on partial timing evidence would leave the actual eight-target bottleneck intact.
  Date/Author: 2026-07-25 / Codex
- Decision: Reject the batch-only final visibility-decision cache.
  Rationale: It was semantically confined and race-safe, but nearly every broad-target reference span was unique and the expensive extractor/lexical work happened before or around that predicate. The isolated eight-target profile showed no practical tail improvement.
  Date/Author: 2026-07-25 / Codex
- Decision: Move the optimization boundary ahead of target-specific lexical resolution with a conservative structured may-resolve test.
  Rationale: A real resolution must begin with the reference's tree-sitter-derived type components and a visible declaration or alias with the same terminal identifier. Rejecting only nodes for which neither the target name nor any structured/parser alias can match avoids repeated full lexical work on unrelated types without weakening exact proof for plausible nodes.
  Date/Author: 2026-07-25 / Codex
- Decision: Accept the two-stage structured type-reference prefilter as the #1165 implementation, subject to the repository-wide publication gates.
  Rationale: Focused work counters prove the common negative path exits before lexical scope or target-specific resolution, the complete 147-test C/C++ usage suite preserves exact behavior, and the decisive full-workload replay completed every inverse target while improving the comparable 365-target checkpoint by about threefold. Parser-only, unresolved, cyclic, and template cases deliberately remain conservative.
  Date/Author: 2026-07-25 / Codex

## Outcomes & Retrospective

Four cache boundaries were rejected rather than published: eager flattened evidence, cached peer/route collections that destroyed legacy short circuits, the semantically safe declaration-guard-only cache, and an exact-span final-decision cache. Those experiments localized the remaining waste above visibility normalization, where target-specific lexical resolution ran for large numbers of unrelated type nodes. The accepted two-stage structured prefilter removes that work before scope reconstruction while conservatively retaining every plausible alias and type shape. A fifth eager global alias-name set was removed during repository-wide validation because it regressed provider-backed declaration scaling; the final implementation stays lazy and terminal-name bounded. All 147 C/C++ usage integration tests, all-feature Clippy, and the complete merged-head all-feature test matrix pass, and the full unfiltered libgit2 replay completed all 796 inverse targets with zero missing rows and exact envelope accounting. Publication and the clean pushed-head corpus proof remain before this plan is complete.

## Context and Orientation

The relevant hot path lives in `src/analyzer/usages/cpp_graph/resolver.rs`. `VisibilityIndex::external_type_candidate_visible_in_context` answers whether a type declaration from another file is visible at a specific reference site after accounting for includes, conditional includes, declaration guards, and macro mutations between the declaration and the reference. `src/analyzer/usages/cpp_graph/extractor.rs` calls this helper while scanning type references. The focused user-facing regression coverage lives in `tests/usages_cpp_graph_test.rs`, while `resolver.rs` also contains local unit tests for internal counters and small cache invariants.

The critical distinction is between declaration-side evidence and reference-side proof. Declaration-side evidence is stable for a given consumer file and logical symbol: which same-file declarations exist, which included donor files contribute declarations, and which declaration guards or conditional include guards they require. Reference-side proof is not stable: it depends on the reference byte position, the active guards around that reference, and whether relevant guard macros remained stable up to that specific byte. This plan memoizes only the first part.

## Plan of Work

Add a resolver helper that accepts tree-sitter-derived type-reference components and answers only whether the reference may resolve to the target. It must be conservative: return true for the target's own terminal identifier, for visible indexed aliases whose structured alias chain can preserve the target, and for parser aliases whose structured alias metadata names the target. Missing or ambiguous component shapes must bypass the optimization rather than fail closed.

Call this helper in `maybe_record_type_hit` after special declaration/out-of-line-owner cases but before the normal target-specific lexical resolver. A false result may skip the node; a true result continues through the existing lexical, visibility, guard, macro, and hit-classification logic unchanged.

Keep the repeated guarded-reference integration test as exactness coverage. Add behavior-focused fixtures for direct names, namespace-qualified names, file-scope aliases, class-owned/inherited aliases, templates, and unrelated types. Add a test-only counter at the expensive lexical-resolution boundary so a fixture with many unrelated type nodes proves they are rejected before target-specific resolution.

## Concrete Steps

From `/mnt/optane/bifrost-fird`:

    cargo test repeated_guarded -- --nocapture

From `/mnt/optane/bifrost-fird` after implementation:

    cargo fmt -- src/analyzer/usages/cpp_graph/resolver.rs src/analyzer/usages/cpp_graph/extractor.rs tests/usages_cpp_graph_test.rs

    cargo test authoritative_cpp_repeated_guarded_type_references_remain_exact

    cargo test cpp_type_reference_prefilter_

## Validation and Acceptance

Acceptance requires the complete `usages_cpp_graph_test` target to preserve every direct, qualified, alias, inherited-alias, template, guard, and macro-mutation result. The focused work-count test must show that unrelated type nodes do not enter target-specific lexical resolution while every plausible reference still does. Finally, the isolated libgit2 replay must complete all 796 inverse targets materially faster than the pre-fix 3,034-second incomplete checkpoint and produce a completed envelope with unchanged exactness classifications.

## Idempotence and Recovery

The prefilter is internal to the C/C++ usage extractor, so rerunning tests is safe. If a regression appears, remove only the new may-resolve gate and its counter; no migrations or persistent artifacts are involved.

## Artifacts and Notes

Implementation will live in `src/analyzer/usages/cpp_graph/resolver.rs` and `src/analyzer/usages/cpp_graph/extractor.rs`, with user-facing coverage in `tests/usages_cpp_graph_test.rs`. Focused and integration test output is summarized in `Progress`; performance and full-gate results will be added after they complete.

## Interfaces and Dependencies

Keep the public Rust, Python, and MCP symbols interfaces unchanged. The implementation is internal to `VisibilityIndex`, `TargetSpec`, and the C/C++ extractor. Use tree-sitter nodes, indexed `CodeUnit`s, structured alias metadata, and existing parser-alias records only; do not add source-text scanning or a second type parser.

Revision note: created the initial ExecPlan after auditing the hot path so the implementation can proceed with the required living-plan record.

Revision note (2026-07-26): Recorded the broad gate evidence and the need to
merge the schema-12 `origin/master` before the final integration pass. Per
direct user instruction, later Cargo and Bifrost commands run normally outside
the sandbox at niceness 10 and do not create Cargo targets under `/tmp`.
