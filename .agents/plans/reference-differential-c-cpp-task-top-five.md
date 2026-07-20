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
- [ ] Publish this campaign-start plan directly to `origin/master`, locally exclude analyzer cache directories in the ten clones, build the exact clean release runner, record its checksum, and validate the explicit selection with `run-corpus --dry-run`.
- [ ] Complete the five-repository C baseline, integrity-check every record, exhaustively disposition every raw missing row, and give the user the requested C-language summary.
- [ ] File/assign, implement, review, test, publish, and exact-prove every legitimate C root cause not owned by somebody else; rebuild and rerun the complete C set after any fix.
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

## Outcomes & Retrospective

The campaign has selected and pinned its exact task-ranked corpus but has not yet produced accepted C or C++ records. The prior LOC-ranked work contributed nine assigned fixes (#924–#932) already present in current history; this campaign will independently test their generality and provide the clean final evidence needed to close them. Update this section after the C milestone, after the C++ milestone, and at full closure.

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

Run the complete C set first with repeated explicit repositories, persisted cache mode, strict reporting, 1,000 sampled files, 10,000 sampled sites, 50,000 candidates per file, 4 MiB source files, 1,000 inverse target groups, 1,000 usage files per target, 100,000 usages per target, and seed zero. Start at one active repository with eight inner workers. If host measurements show ample memory and I/O headroom, increase only outer repository concurrency while preserving every semantic limit and recording the change. Store append-only head-scoped JSONL and logs. A strict status of two is expected if raw `missing` rows exist; acceptance requires five completed clean records.

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
      --max-candidates-per-file 50000 --max-source-bytes 4194304 \
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
