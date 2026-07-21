# Audit the five most-tasked eligible C and C++ repositories

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` current while the work proceeds. Maintain it in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost's forward-versus-inverse reference differential checks a public symbols invariant: when definition lookup resolves a source reference to a declaration group, the inverse usage query should recover that same source range. This campaign audits the five repositories with the most fully filtered SFT tasks for C and separately for C++, as selected through `/home/jonathan/Projects/brokkbench/tasks.py` after its `large-repos.csv` exclusion and the rest of its runnable-task gates.

The observable result is ten accepted repository records selected by exact descending filtered task count. Every raw `missing` site receives an evidence-backed disposition based on the live source bytes, tree-sitter role, forward target identity, inverse completeness, and an exact-site rerun. Every legitimate in-scope analyzer defect is searched on GitHub, assigned only to `jbellis` before implementation, reduced with structured behavior tests, fixed, locally validated, published directly to `origin/master`, and closed after clean production proof. An issue assigned to anyone else is recorded and skipped. The acceptance surface is the MCP `symbols` toolset and the associated Rust and Python APIs; LSP shares analyzer code but is not the focus. GitHub CI is not a blocking gate after the complete local test gate passes.

## Progress

- [x] (2026-07-20 14:35Z) Read `.agents/PLANS.md`, the operator runbook, the earlier LOC-ranked C/C++ campaign, the completed top-five campaign conventions, and the authoritative `tasks.py` predicate implementation.
- [x] (2026-07-20 14:45Z) Delegated three independent read-only reviews of selector semantics, runbook operation, repository state, and prior artifacts; root reconciled their findings against the sibling task-ranked campaign correction.
- [x] (2026-07-20 14:50Z) Selected the exact C and C++ sets through `task_repos(SFT_PREDICATES, langs=[language])`, sorted by `(-task_count, repo_slug)`, and verified that `SFT_PREDICATES.not_overlarge` reads and filters `large-repos.csv`.
- [x] (2026-07-20 14:55Z) Verified all ten canonical clones exist at the pinned heads recorded below and have no tracked changes. Their only apparent dirtiness is analyzer cache directories that must be locally excluded before accepted runs.
- [x] (2026-07-20 15:00Z) Verified GitHub issues #924 through #932 remain open and are each assigned only to `jbellis`; their fixes and local gates are already present in the current history, but clean task-ranked corpus proof and closure remain outstanding.
- [x] (2026-07-20 15:20Z) Published the campaign-start plan directly to `origin/master` at `6a51a712`, locally excluded analyzer cache directories in all ten clones, built the clean release runner, recorded SHA-256 `fa4d74323afe1e1a4a22beb8ec9008b0f7fa8274a67bec20a086a745c8726cbf`, and dry-ran both explicit selections.
- [x] (2026-07-20 17:05Z) Sealed the clean Go-Ethereum C discovery record with zero missing rows, then proved its sole candidate-limit exclusion contains 121,349 candidates and that a 250,000 ceiling clears the complete file with zero file errors.
- [x] (2026-07-20 17:10Z) Re-probed both #932 QGIS witnesses on the frozen clean head: each retained an exact inverse hit as `unproven`; traced this to sound macro uncertainty from the missing generated `qgis_core.h`, not a remaining default-argument defect.
- [x] (2026-07-20 17:15Z) Diagnosed pathological Libgit2/JerryScript inverse progress as a distinct macro-environment cursor contention/replay defect, created GitHub issue #996, and verified it is assigned only to `jbellis` before delegating implementation.
- [x] (2026-07-20 18:05Z) Integrated and published the per-worker macro cursor fix through clean master head `df753a15`; formatting, all-target/all-feature Clippy, and the complete feature-enabled test suite passed locally.
- [x] (2026-07-20 18:30Z) Completed all five literal task-selected C records on release runner `df753a15` (SHA-256 `9ac6ffd57833f2940d900ba1f79f8c0b0041aa6479bae17c8c73a90829ee9d17`) with one fingerprint, exact clean heads, zero file errors, and no skipped inverse targets.
- [x] (2026-07-20 18:35Z) Closed #996 after Libgit2 completed 667/667 targets in 602.9 seconds with an 84.0-second maximum completion gap and JerryScript completed 332/332 in 763.6 seconds with a 192.9-second maximum gap, versus incomplete old runs and 816.4/900.7-second stalls.
- [x] (2026-07-20 18:40Z) Exhaustively extracted and exact-reran all eight raw C residuals. Seven Chibicc sites are typedef declarators and the Libgit2 site is a secondary local declarator; inverse omission is correct, but public forward lookup incorrectly treated each declaration token as a reference.
- [x] (2026-07-20 18:45Z) Created issue #997, verified it is assigned only to `jbellis`, and delegated a structured shared declaration-name fix plus behavior regressions.
- [x] (2026-07-20 19:10Z) Root-reviewed #997, passed 70 focused C/C++ definition tests, formatting, all-target/all-feature Clippy, and the complete feature-enabled test suite, reconciled remote changes, and published the fix in clean master head `7c1a16e0`.
- [x] (2026-07-20 19:15Z) Exact-reran all eight #997 witnesses on the rebuilt `7c1a16e0` release runner; every declaration byte now returns structured `no_definition`/`declaration_or_import_site`, with zero missing rows.
- [x] (2026-07-20 20:10Z) Completed and independently integrity-checked the five literal task-selected C records plus the rank-six `aws__s2n-tls` supplement: one fingerprint, exact clean heads, 50,000 substantive sampled sites, all 2,283 targets queried, and zero missing, file errors, candidate exclusions, skipped targets, or target truncations.
- [x] (2026-07-20 20:15Z) Posted production evidence and closed assigned issues #997, #924, and #928; published the compact C manifest and requested C-language summary.
- [x] Complete the five-repository C baseline, integrity-check every record, exhaustively disposition every raw missing row, and give the user the requested C-language summary.
- [x] File/assign, implement, review, test, publish, and exact-prove every legitimate C root cause not owned by somebody else; rebuild and rerun the complete C set after any fix.
- [x] (2026-07-20 20:35Z) Built and checksummed the clean release runner at published head `e21d1d3e`, verified all five pinned C++ clones are clean, and dry-ran the explicit task-selected set.
- [x] (2026-07-20 20:45Z) Completed five clean C++ discovery records with one fingerprint, zero file or candidate errors, and 135 raw missing rows; ESPHome's explicit 1,000-target budget left 934 targets and 1,222 sites visibly inconclusive rather than silently omitted.
- [x] (2026-07-20 21:00Z) Extracted and checksummed all 135 raw C++ rows and exact-reran every coordinate with ephemeral cache; all 135 reproduced without operational failure.
- [x] (2026-07-20 21:12Z) Reconciled all 135 exact C++ rows: 78 are product discrepancies (ESPHome 15, libcbor 3, qpid-proton 60) and 57 are non-product or soundly inconclusive (ESPHome 2, Circl 4, qpid-proton 51). Reused assigned issue #940, created #1000 through #1005, and verified every worked issue is open and assigned only to `jbellis` before implementation.
- [x] (2026-07-21 05:35Z) Integrated the structured fixes for #940 and #1000 through #1005, root-reviewed the combined resolver/declaration/hierarchy behavior, and exact-proved all 78 product witnesses on the working release runner; the final nine previously unresolved coordinates now classify as five `consistent`, two correct import-boundary `inconclusive`, one exact two-definition `editor_only`, and one `consistent` constructor call.
- [x] (2026-07-21 06:05Z) Passed formatting, `git diff --check`, 43 C++ analyzer tests, 76 C++ definition tests, 141 C++ graph tests, 16 C++ hierarchy tests, isolated all-target/all-feature Clippy, and the complete serialized `cargo test --features nlp,python` suite. The full suite passed after independently confirming that an `EPERM` under the filesystem sandbox and one parallel SQLite lock were environmental concurrency artifacts.
- [ ] Complete the five-repository C++ baseline, integrity-check every record, exhaustively disposition every raw missing row, and give the user the requested C++-language summary.
- [ ] File/assign, implement, review, test, publish, and exact-prove every legitimate C++ root cause not owned by somebody else; rebuild and rerun the complete C++ set after any fix.
- [ ] Publish compact manifests and summaries, comment on and close every assigned issue proven fixed, run the final local gates, and verify the clean local head, `origin/master`, and remote master agree.

## Surprises & Discoveries

- Observation: `task_repos` does not natively order repositories by exact task count.
  Evidence: `/home/jonathan/Projects/brokkbench/tasks.py::_select` ranks by a logarithmic task-count band, then build time and slug. Exact “most tasks” selection therefore requires sorting returned `RepoRef` values by descending `task_count`, with slug as the deterministic tie breaker.

- Observation: The user's expected C/C++ overlap is absent in the current authoritative selection.
  Evidence: The exact filtered top fives below have zero shared slugs. `tasks.py` canonicalizes a multi-language repository to one preferred language before `task_repos` returns it, and an independent per-language membership/count cross-check also produced no top-five overlap. The campaign must report the measured zero overlap rather than substitute a different selector.

- Observation: The earlier C/C++ plan does not satisfy this objective.
  Evidence: `.agents/plans/reference-differential-c-cpp-top-five.md` selected large repositories by `code_loc` and explicitly excluded Chromium. Its records and nine fixes remain valuable regression evidence, but task-ranked acceptance requires a new explicit ten-repository run.

- Observation: A release runner can report checkout metadata newer than the code it contains.
  Evidence: revision and dirtiness fields are read dynamically. The repository must remain frozen while a corpus runner built from it is active, and every changed/pushed head requires a fresh release build and new head-scoped artifacts.

- Observation: The requested external Oldskool launch is not allowed by the execution environment.
  Evidence: the named role is not exposed through the internal collaboration API, and an attempted equivalent GPT-5.4/medium CLI delegation was denied because it would transmit private workspace contents externally. Internal read-only subagents remain available for parallel research and triage.

- Observation: Go-Ethereum's generated secp256k1 table exceeds the standard 50,000-candidate ceiling without exceeding the 4 MiB source ceiling.
  Evidence: `crypto/secp256k1/libsecp256k1/src/precomputed_ecmult.c` contributes exactly 121,349 deduplicated structured candidates. A focused inventory at 250,000 reported 153,269 total candidates across the repository and zero file errors, while the 50,000 discovery record reported the file as excluded.

- Observation: The two current-head QGIS #932 sites are exact inverse hits but cannot soundly be promoted from `unproven` with the indexed facts available.
  Evidence: QGIS omits generated quoted header `qgis_core.h`. The qualified enum argument terminal could therefore be an object-like macro that changes call arity before C++ lookup. Both clean exact probes have the right target and exact range with zero missing rows; inverse resolution correctly retains preprocessor uncertainty.

- Observation: A shared macro-environment forward cursor serializes concurrent inverse targets and thrashes on interleaved source frontiers.
  Evidence: during the C discovery run, eight workers blocked in `VisibilityIndex::call_arity_evidence` on the same per-file cursor mutex while two workers replayed recursive include events through `mark_macro_events_ambiguous`. The cursor resets whenever a target requests a lower byte frontier, so concurrent target scans repeatedly replay the prefix under lock. This is issue #996 and is distinct from #929's class-strength parse cache.

- Observation: The literal fourth-ranked C selection has no C implementation files or C-task evidence.
  Evidence: `tasks.py` reports 42 fully filtered tasks for `bernardladenthin__BitcoinAddressFinder`, but all 42 task change sets touch Java and none touches C/C++ headers or sources. The pinned clone contains 276 Java files, ten OpenCL kernels, eight headers, and zero `.c`, `.cc`, `.cpp`, or `.cxx` files, so the differential correctly completed a clean zero-eligible-file record. `task_repos` canonicalizes a multi-language repository by a fixed language preference before applying `langs=["c"]`; it does not validate the task-touched language.

- Observation: All eight C residuals share declaration-site forward filtering gaps rather than inverse omissions.
  Evidence: the Libgit2 byte is the second direct declarator in `size_t i, j;`, and the seven Chibicc bytes are the second names in `typedef struct X X;`. Tree-sitter exposes repeated `declarator` fields, but forward lookup inspected only one field and the type path used an even narrower `name`-only guard. Exact probes reproduce the wrong forward results; inverse correctly excludes declarations. This is assigned issue #997.

- Observation: The accepted C rerun has no residual raw disagreement.
  Evidence: five clean task-selected records at `7c1a16e0` share fingerprint `830e9a0f239fcaa3e8f0a0b9d7831aa8f3ca8917a6b39e24d70e84cb601223d6`; all 40,000 sampled sites partition into 6,215 consistent and 33,785 inconclusive rows with zero missing. The rank-six substantive supplement adds 10,000 sites, 1,698 consistent, two soundly unproven, 8,300 inconclusive, and zero missing.

- Observation: The literal fourth-ranked C++ selection also has no eligible C++ files.
  Evidence: `ljharb__qs` completed a clean zero-file record. The selector contract is still preserved; unlike C, the other four task-selected C++ repositories all provide substantive analyzer coverage, so no additional replacement policy is needed unless final coverage proves inadequate.

- Observation: The 135 C++ raw rows contain concentrated product families, differential-only rows, and sound uncertainty that require public-path reconciliation.
  Evidence: 135 clean exact probes reproduced. Qpid-proton and libcbor establish 40 macro-prefixed declaration type omissions and 23 forward lookup errors; ESPHome establishes six inherited-member omissions and nine guarded type omissions. The remaining 57 rows are non-product or soundly inconclusive: 46 differential-batch-only rows retained by the public targeted API, five declaration-sampler leaks in the existing #969 family, four malformed Go/Plan 9 assembly tokens parsed as C++, and two `unproven_cpp_link_unit` cases.

- Observation: ESPHome exceeds the configured inverse-target budget without invalidating the sampled partition.
  Evidence: 1,934 distinct target groups were discovered, 1,000 were queried, 934 were explicitly skipped, and 1,222 affected sites were marked inconclusive. Every one of ESPHome's 17 raw missing rows belongs to a queried target with a complete inverse result, so the cap does not explain any actionable witness.

- Observation: The C++ product rows were not one fallback-shaped gap; they exposed six interacting structured-resolution boundaries.
  Evidence: the fixes recover macro-decorated declarator types, model conditional include visibility without evaluating arbitrary source text, preserve qualified/template owners, resolve relative inherited members, distinguish direct `this` from chained member receivers, and keep callable identity ahead of same-named nested types. Exact production probes clear all 78 product witnesses without weakening the 57 deliberately conservative outcomes.

- Observation: The full feature-enabled suite has two host-sensitive tests that require their intended execution environment.
  Evidence: a sandboxed run passed 1,464 library tests but three stderr-pipe cases received `EPERM`; those five focused tests passed outside the sandbox. A parallel unsandboxed run passed 1,466 library tests but one fresh-cache migration stress case encountered a transient SQLite lock; it passed focused and the complete unsandboxed serialized suite then exited zero.

## Decision Log

- Decision: Interpret “tasks” as fully filtered primary SFT tasks and use `tasks.SFT_PREDICATES`.
  Rationale: This is the established sibling campaign correction and the public selector that combines `not_overlarge=True` with build, testsome, not-skipped, binding, generated-prompt, and non-fragile-test gates. Raw scan candidates are not runnable SFT tasks.
  Date/Author: 2026-07-20 / Codex

- Decision: Sort the selector result by `(-task_count, repo_slug)` before taking five.
  Rationale: The user asked for the repositories with the most tasks. Native selector order uses coarse bands and can omit a repository with a larger exact count.
  Date/Author: 2026-07-20 / Codex

- Decision: Pass all selected slugs through repeated explicit `--repo` options.
  Rationale: `run-corpus --repos-per-language` ranks by unrelated repository LOC and would silently violate the task-ranked contract.
  Date/Author: 2026-07-20 / Codex

- Decision: Complete and summarize C before starting the authoritative C++ leg.
  Rationale: The user explicitly requested a summary after an entire language is finished. Repository-level concurrency within a language may increase after measuring memory, but the language boundary remains observable.
  Date/Author: 2026-07-20 / Codex

- Decision: Treat every `missing` row as triage input rather than a defect.
  Rationale: A valid issue needs a semantically correct forward identity, complete inverse query, exact focused token, clean reproducibility, and a structured reduction. Wrong forward targets, declarations, qualifiers, parser-recovery frontiers, and explicit limits are comparison artifacts.
  Date/Author: 2026-07-20 / Codex

- Decision: Root owns the plan, final source/identity adjudication, GitHub state, review, commits, pushes, and closure; internal subagents may own disjoint read-only source reviews and substantial implementations after an assigned issue and failing reduction exist.
  Rationale: This preserves the requested delegation model within the available safe runtime while keeping mutation authority and correctness review centralized.
  Date/Author: 2026-07-20 / Codex

- Decision: Do not wait for GitHub CI after the complete local gate passes.
  Rationale: The user explicitly made local tests the transition boundary. Formatting, all-target/all-feature Clippy, focused tests, and the full `cargo test --features nlp,python` suite remain mandatory.
  Date/Author: 2026-07-20 / Codex

- Decision: Raise the final C acceptance ceiling to 250,000 structured candidates per file and rerun the complete five-repository language set with one shared fingerprint.
  Rationale: The measured Go-Ethereum maximum is 121,349 for one 2.4 MiB generated file. A 250,000 probe clears it with more than twofold headroom and remains bounded; mixing one raised-ceiling record with four standard records would violate the single-fingerprint acceptance contract.
  Date/Author: 2026-07-20 / Codex

- Decision: Treat #932's current exact `unproven` hits as an honest acceptance refinement, not as grounds to weaken macro proof.
  Rationale: The original false negatives are gone and the exact sites are retained. Claiming `consistent` despite an unresolved generated-header macro boundary would mask structured uncertainty and violate the analyzer's fail-closed contract. Closure evidence must state this explicitly rather than claim literal consistency.
  Date/Author: 2026-07-20 / Codex

- Decision: Interrupt the discovery corpus after filing and assigning #996, then resume only from a clean fixed runner.
  Rationale: Libgit2 and JerryScript had no durable records, the live stack proved they were exercising the defect, and continuing would spend hours producing evidence that must be rerun after the fix. The append-only Go-Ethereum record remains intact as discovery evidence.
  Date/Author: 2026-07-20 / Codex

- Decision: Preserve BitcoinAddressFinder as the literal task-ranked fourth record, and supplement rather than replace it with rank-six `aws__s2n-tls` after #997 is fixed.
  Rationale: Substituting a different repository would violate the user's exact `tasks.py` selector contract, while calling a zero-file record meaningful C coverage would be misleading. The supplement keeps selector provenance intact and produces five substantive C audits; it will be labeled extra rather than silently promoted into the top five.
  Date/Author: 2026-07-20 / Codex

- Decision: Publish the six C++ issue families as one reviewed checkpoint before the final corpus rerun.
  Rationale: the production witnesses overlap in owner recovery, declaration identity, hierarchy, and forward/inverse candidate selection. Landing the coherent stack once avoids accepting evidence from intermediate resolver combinations, while each issue retains focused reductions and exact coordinates for closure proof.
  Date/Author: 2026-07-21 / Codex

## Outcomes & Retrospective

The C milestone is complete. The literal selector contract produced five accepted clean records, including the honest zero-file BitcoinAddressFinder result; a separately labeled `aws__s2n-tls` run supplied the fifth substantive C audit. Across those substantive records, 50,000 sampled sites yielded 7,913 consistent, two soundly unproven, 42,085 inconclusive, and zero missing or actionable residuals. #996 fixed the operational macro-cursor contention found during the campaign, and #997 fixed all eight declaration-name forward errors. #996, #997, and the previously fixed C issues #924 and #928 are closed with clean production evidence. C++ remains outstanding.

## Context and Orientation

Work in `/mnt/optane/tmp/bifrost-burndown-a3` on the existing `bifrost-burndown-a3` branch. Do not create or switch branches and do not open a pull request. Commit directly on the current branch. At publication boundaries fetch `origin/master`, merge it without rebasing if it advanced, rerun proportionate gates, and push with `git push origin HEAD:master`. Stage only campaign files changed here.

The operator runbook is `.agents/docs/reference-differential-runbook.md`. The CLI is `src/bin/bifrost_reference_differential.rs`, and the engine/report schema is `src/reference_differential/mod.rs`. The runner samples structured reference sites, resolves each site forward to a declaration group, asks inverse usage lookup for that group, and checks whether the original exact byte range returns.

Canonical task selection is owned by `/home/jonathan/Projects/brokkbench/tasks.py`. The exact reproducer, run from `/home/jonathan/Projects/brokkbench`, is:

    import tasks
    for language in ("c", "cpp"):
        repos = tasks.task_repos(tasks.SFT_PREDICATES, langs=[language])
        selected = sorted(repos, key=lambda repo: (-repo.task_count, repo.repo_slug))[:5]
        print(language, [(repo.repo_slug, repo.task_count) for repo in selected])

`SFT_PREDICATES` sets `not_overlarge=True`, so `tasks.py` reads `/home/jonathan/Projects/brokkbench/sft-tools-commits/large-repos.csv` and excludes its members before counting. It also requires a recorded build and testsome run, a non-skipped repository, a binding outcome, a generated primary prompt, and a strict `non_fragile_tests=True` task marker.

The selected C repositories are:

1. `roseteromeo56-cb-id__go-ethereum`, 105 tasks, pinned clone head `a7bf6f691a113013a1dc96bd4e5f4a88c3e9a28a`.
2. `rui314__chibicc`, 77 tasks, pinned clone head `90d1f7f199cc55b13c7fdb5839d1409806633fdb`.
3. `libgit2__libgit2`, 60 tasks, pinned clone head `32b564e63f9639eaf5ee90fb7a95b3a650156cbd`.
4. `bernardladenthin__BitcoinAddressFinder`, 42 tasks, pinned clone head `69160cbba1aa0d29873f44df522bafe0a21a234a`.
5. `jerryscript-project__jerryscript`, 41 tasks, pinned clone head `b7069350c2e52e7dc721dfb75f067147bd79b39b`.

The selected C++ repositories are:

1. `esphome__esphome`, 151 tasks, pinned clone head `9327d011fc95dbb710e46917218cce09b86f2cbe`.
2. `cloudflare__circl`, 68 tasks, pinned clone head `901199c7d4fcefc8c43e8ad46397439ccd3a0ed0`.
3. `PJK__libcbor`, 32 tasks, pinned clone head `9b78da40511f86df53e8541b646bad042dd785da`.
4. `ljharb__qs`, 32 tasks, pinned clone head `9198d2bc3d5c90c2e12f514204ca2121ddb4ad7b`.
5. `apache__qpid-proton`, 27 tasks, pinned clone head `976e2181c4c1daa6b84fd81465a0ca5cb98b39b8`.

Clone paths are `/home/jonathan/Projects/brokkbench/clones/<slug>`. Durable raw evidence belongs under `/mnt/optane/tmp/reference-differential/`. Large JSONL payloads and logs are not committed. Compact manifests and narrative summaries belong under `.agents/docs/reference-differential/`.

## Plan of Work

First publish this plan from a clean Bifrost checkpoint. Add `.bifrost/` and `.brokk/` to each selected clone's local `.git/info/exclude` when present, without touching tracked clone content or deleting caches. Verify all ten clone heads and tracked cleanliness. Build a fresh release runner from the published clean Bifrost head, record its SHA-256, and run an explicit no-write `run-corpus --dry-run` for each language. Freeze the Bifrost worktree while any accepted corpus process is active.

Run the complete C set first with repeated explicit repositories, persisted cache mode, strict reporting, 1,000 sampled files, 10,000 sampled sites, 250,000 candidates per file, 4 MiB source files, 1,000 inverse target groups, 1,000 usage files per target, 100,000 usages per target, and seed zero. The raised candidate ceiling is required by the measured Go-Ethereum generated table and must be shared by all five records. Start at one active repository with eight inner workers. If host measurements show ample memory and I/O headroom, increase only outer repository concurrency while preserving every semantic limit and recording the change. Store append-only head-scoped JSONL and logs. A strict status of two is expected if raw `missing` rows exist; acceptance requires five completed clean records.

Integrity-check heads, clean flags, one semantic fingerprint, completion status, limits, file errors, and truncation. Extract every raw missing row into a stable ledger keyed by repository, path, byte range, and ordered targets. Delegate disjoint repository source review while root verifies every exact token, AST role, forward identity, and inverse completeness. Rerun every suspicious site exactly with ephemeral cache mode. Group legitimate witnesses by root cause, search the GitHub ledger, and inspect assignees. Skip an issue assigned to anybody else. Otherwise create or reuse an issue assigned only to `jbellis` before product edits.

Use `tests/common/inline_project.rs::InlineTestProject` for small reductions. Put forward identity behavior in definition tests, targeted inverse behavior in C++ usage graph tests, whole-workspace parity in inverted graph tests, and public symbols/Python coverage where their contract changes. Use tree-sitter nodes and analyzer graph structures; do not add regex, source splitting, substring matching, delimiter scanning, or other source-text mini parsers. Delegate substantial implementations only after the issue and failing structured reduction exist. Root reviews every patch and adds adversarial controls for scope, owners, aliases, imports, overloads, receiver types, inheritance, shadowing, duplicate declarations, macros, templates, and C/C++ partition as relevant.

After every fix stack, run focused suites, formatting, all-target/all-feature Clippy, and the complete feature-enabled test suite. Commit a multiline why-oriented checkpoint, reconcile and push directly to `origin/master`, rebuild from that exact clean pushed head, exact-prove accepted witnesses, and rerun the entire affected language into new head-scoped output. Audit all new residuals independently. Give the user the C summary only when all five C records and fixes are complete, then repeat the entire lifecycle for C++ and provide the C++ summary.

At full closure, publish compact checked-in manifests and summaries, comment on and close assigned issues proven fixed, repeat the local gates if the final documentation changes affect code-sensitive checks, and verify local head, local `origin/master`, and the remote `master` ref agree.

## Concrete Steps

From `/mnt/optane/tmp/bifrost-burndown-a3`, record and publish the campaign checkpoint, then build the exact clean runner:

    git status --short
    git rev-parse HEAD
    git rev-parse origin/master
    cargo build --release --bin bifrost_reference_differential
    sha256sum target/release/bifrost_reference_differential

The C command shape is:

    set -o pipefail
    /usr/bin/time -v target/release/bifrost_reference_differential run-corpus \
      --clones-root /home/jonathan/Projects/brokkbench/clones \
      --commits-root /home/jonathan/Projects/brokkbench/sft-tools-commits \
      --language c \
      --repo roseteromeo56-cb-id__go-ethereum \
      --repo rui314__chibicc \
      --repo libgit2__libgit2 \
      --repo bernardladenthin__BitcoinAddressFinder \
      --repo jerryscript-project__jerryscript \
      --repo-jobs 1 --jobs 8 --cache-mode persisted --strict \
      --max-files 1000 --max-sites 10000 \
      --max-candidates-per-file 250000 --max-source-bytes 4194304 \
      --max-targets 1000 --max-usage-files 1000 --max-usages 100000 \
      --seed 0 \
      --output /mnt/optane/tmp/reference-differential/c-task-top5-BIFROST_HEAD.jsonl \
      2>&1 | tee -a /mnt/optane/tmp/reference-differential/c-task-top5-BIFROST_HEAD.log

The C++ command is identical except for `--language cpp`, a `cpp-task-top5-BIFROST_HEAD` prefix, and these repositories:

    --repo esphome__esphome
    --repo cloudflare__circl
    --repo PJK__libcbor
    --repo ljharb__qs
    --repo apache__qpid-proton

Use the same commands with `--dry-run` before launch. Do not use `--repos-per-language`, `--include-tests`, or routine `--force`. Resume an interrupted run by confirming no process owns a selected clone and repeating the identical command/output without `--force`; completed repository keys are skipped.

For an exact site, use a unique output and ephemeral cache:

    target/release/bifrost_reference_differential run-repo \
      --root /home/jonathan/Projects/brokkbench/clones/REPOSITORY \
      --language LANGUAGE --output /mnt/optane/tmp/reference-differential/ISSUE-exact-HEAD.jsonl \
      --jobs 8 --cache-mode ephemeral --strict \
      --path WORKSPACE_RELATIVE_PATH --start-byte START --end-byte END

Before publishing a product fix, run at minimum:

    cargo fmt --all -- --check
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    UV_CACHE_DIR=/tmp/bifrost-uv-cache BIFROST_SEMANTIC_INDEX=off \
      scripts/with-isolated-cargo-target.sh cargo test --features nlp,python

## Validation and Acceptance

A language baseline is valid only when its five selected pinned repositories have completed records for one exact clean Bifrost head and configuration, both dirtiness flags are false, JSON parses, one semantic fingerprint is shared, and every file error, skipped target, and explicit truncation is accounted for. Strict exit two is acceptable only when all completed records were durably appended.

A defect is accepted only with a semantically valid forward identity, complete inverse query, faithful failing structured reduction, assigned issue ownership, root-reviewed implementation, focused green tests, and exact production proof. Closure requires a fresh complete language run after the integrated pushed fix, not subtraction from a baseline or dirty exact probes.

The campaign is complete only when all ten task-ranked repositories have clean accepted final records, every final raw missing row has a reviewed ledger disposition, zero legitimate in-scope discrepancies remain, every worked issue is assigned only to `jbellis` and closed with evidence, formatting and all-feature Clippy pass, the complete `cargo test --features nlp,python` suite passes, compact reports are checked in, and local/remote master plus the clean worktree agree.

## Idempotence and Recovery

`run-corpus` is append-only and resume-safe at repository granularity. Repeat an unchanged command without `--force` to skip completed keys and rerun incomplete repositories. Preserve partial JSONL, logs, and persisted caches. Never truncate evidence or delete `.brokk` as a retry strategy. If a process stops, verify it is gone, inspect the terminal log, and repeat the exact command.

If Bifrost changes while a corpus process is active, stop accepting that evidence, rebuild from a clean checkpoint, and use new head-scoped filenames. If `origin/master` advances, fetch and merge without rebasing, rerun proportionate local gates, publish, rebuild, and restart acceptance against the new head. Never combine records from different Bifrost heads into one final language matrix.

## Artifacts and Notes

Raw resumable evidence uses `/mnt/optane/tmp/reference-differential/{c,cpp}-task-top5-<head>.{jsonl,log}`. Derived exhaustive audit files use `-missing-audit.{jsonl,tsv,summary.json,sha256}` and `-missing-ledger.{jsonl,tsv,sha256}`. Compact durable deliverables will be `.agents/docs/reference-differential/task-top5-c-cpp.jsonl` and `.agents/docs/reference-differential/task-top5-c-cpp-summary.md`.

At launch the host has 120 logical processors, 98 GiB RAM with about 58 GiB available, 255 GiB swap, about 796 GiB free on `/mnt/optane`, 768 GiB on `/mnt/T9`, and 536 GiB on `/tmp`. These measurements justify starting conservatively and revising only outer concurrency after observing actual workspace memory.

## Interfaces and Dependencies

No product interface change is assumed. Preserve the differential CLI and report schema, public symbol identity, Rust APIs, Python bindings, and existing MCP tool names unless a reduced defect requires a deliberate change recorded here. C and C++ share the C++ analyzer and persisted metadata; declaration or identity changes may require a C++ analysis epoch bump so warmed caches cannot retain stale facts. Avoid new dependencies and avoid cloning in hot loops unless evidence shows it is the correct tradeoff.

Revision note (2026-07-20 15:00Z): Created this task-ranked C/C++ plan after proving the earlier LOC-ranked campaign did not satisfy the selector contract. Pinned the exact `SFT_PREDICATES` call, descending-count tie break, ten repository heads, zero-overlap discovery, existing issue ownership, frozen-runner discipline, language-summary boundaries, delegation limits, local gates, direct-master workflow, and clean full-language closure requirement before launching analyzers.

Revision note (2026-07-20 17:18Z): Recorded the clean runner and first C discovery record, raised the final C candidate ceiling from measured evidence, documented #932's sound exact-but-unproven boundary, and added assigned issue #996 after a live production stack proved cross-target macro cursor serialization and replay thrash.

Revision note (2026-07-20 18:45Z): Recorded #996 publication, gates, production proof, and closure; completed and integrity-checked the literal five-repository C discovery corpus; documented the BitcoinAddressFinder selector mismatch and supplemental real-C policy; and added assigned issue #997 from exhaustive adjudication of all eight declaration-site residuals.

Revision note (2026-07-20 20:17Z): Recorded #997's structured fix, local gates, publication, eight exact proofs, the clean zero-missing five-record C rerun, the matching rank-six substantive supplement, independent acceptance audit, closures for #997/#924/#928, and the compact C milestone artifacts.

Revision note (2026-07-20 21:05Z): Recorded the clean five-record C++ discovery run, explicit ESPHome cap accounting, all 135 exact reproductions, the confirmed 74/57 product-versus-non-product partition with four ESPHome rows still under public-path review, and assigned issue ledger #940/#1000-#1005 before parallel implementation.

Revision note (2026-07-20 21:12Z): Finished public-path reconciliation of all four pending ESPHome rows, freezing the 78-product/57-non-product partition and allocating the final ESPHome witnesses to #940 and #1000.

Revision note (2026-07-21 06:05Z): Recorded the integrated #940/#1000-#1005 structured fix stack, exact working-runner proof for all product witnesses, focused gates, isolated all-feature Clippy, the environmental interpretation of sandbox/parallel flakes, and the authoritative green serialized full-feature test suite before publication.
