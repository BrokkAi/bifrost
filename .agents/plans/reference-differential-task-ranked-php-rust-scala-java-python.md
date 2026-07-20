# Complete the task-ranked PHP, Rust, Scala, Java, and Python reference differential

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` current while work proceeds. Maintain it in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost's public MCP `symbols` toolset and associated Rust and Python APIs support both forward definition lookup and inverse reference lookup. When a source reference resolves forward to a workspace declaration group, a complete inverse query for that declaration should recover the same source range. This campaign tests that contract on the five repositories with the most eligible tasks in PHP, Rust, Scala, Java, and Python.

The repository membership is selected only through `/home/jonathan/Projects/brokkbench/tasks.py`: call `task_repos(SFT_PREDICATES, langs=[LANG])`, order the returned repositories by descending `task_count` while preserving the selector's order for equal counts, and retain five. `SFT_PREDICATES` excludes `large-repos.csv` entries and applies the build, testsome, skip, binding, generated-prompt, and non-fragile-test gates. The differential runner must receive the resulting slugs as explicit repeated `--repo` arguments; its `--repos-per-language` option ranks by code size and is not valid for this objective.

The observable result is twenty-five clean completed repository records, five per language, with every raw `missing` row exhaustively dispositioned. Each legitimate defect must have a GitHub issue assigned to `jbellis` before implementation unless an existing issue is assigned to somebody else, in which case the campaign records and skips it. Owned fixes receive structured behavior tests, exact production proof, local formatting, all-feature Clippy, the complete `cargo test --features nlp,python` gate, direct publication to `origin/master`, and issue closure. LSP shares the implementation and comes through the local gate, but editor-protocol behavior is not the focus.

## Progress

- [x] (2026-07-20 09:15-05:00) Read the repository instructions, `.agents/PLANS.md`, and `/home/jonathan/Projects/bifrost/.agents/docs/reference-differential-runbook.md`; created the persistent goal and established root ownership of planning, GitHub state, review, gates, commits, and publication.
- [x] (2026-07-20 09:25-05:00) Delegated read-only campaign reconciliation to the requested Oldskool research role. The review proved that every earlier PHP/Rust/Scala/Java/Python top-five artifact used code-LOC membership rather than the requested `tasks.py` task-count membership. Those artifacts and their closed fixes remain regression evidence but do not complete this objective.
- [x] (2026-07-20 09:28-05:00) Recomputed all five language sets through `task_repos(SFT_PREDICATES, langs=[LANG])`, sorted by descending task count with stable selector ordering for ties, and independently confirmed all twenty-five clones exist with clean tracked state.
- [x] (2026-07-20 09:20-05:00) Transplanted the previously reviewed PHP #904/#905 structured fix and its behavior tests into this current branch as `fdb7ae8d`; 49 targeted PHP usage tests, 16 whole-workspace graph tests, formatting, diff hygiene, and isolated all-target/all-feature Clippy pass. This remains regression/fix evidence until the task-ranked PHP corpus and clean publication proof are complete.
- [x] (2026-07-20 09:45-05:00) Ran the complete isolated `cargo test --features nlp,python` gate. The sandboxed attempt reached 1,459 passing library tests but denied three benchmark process-I/O tests with `Operation not permitted`; the required unsandboxed rerun then passed the complete unit, integration, and doc-test matrix with zero failures.
- [x] (2026-07-20 09:50-05:00) Committed the corrected task-ranked plan as `c0e01ba9`, forced a release-runner relink so its compile-time manifest path names this worktree, and recorded runner SHA-256 `c98f6b8a649eb0f838942de2de3818f20dcb103bdce7520f29144b53ca2f5682`.
- [x] (2026-07-20 10:00-05:00) Ran the authoritative PHP baseline over the five explicit task-ranked repositories. All five records completed cleanly at `c0e01ba9`; the JSONL SHA-256 is `0e1fb71713e0fe0d9e6b4ab77da36730f58e15f0e801a5f3b288df8c41652ebd`. Raw missing counts were Snipe-IT 0, Laravel 33, CakePHP 46, CodeIgniter4 31, and PhpSpreadsheet 188.
- [x] (2026-07-20 10:18-05:00) Delegated the four nonzero PHP repositories as three disjoint Oldskool triage partitions and independently reviewed the result. All 298 rows are legitimate and exhaustively reduce to 96 owner-relative class references, 200 call-return receiver chains, and four nullsafe calls, with two rows requiring both chain and nullsafe support.
- [x] (2026-07-20 10:22-05:00) Reproduced clean minimal production witnesses and created assigned issues #960, #961, and #962 before implementation. Exact baseline SHA-256 values are `1305e84e...` for Laravel `self`, `4669d644...` for the CakePHP call chain, and `fa77f406...` for the CakePHP nullsafe call.
- [x] (2026-07-20 10:50-05:00) Integrated and reviewed Oldskool's #960 implementation, then implemented #961/#962 with one shared stack-safe structured receiver evaluator, nearest declaring-owner lookup, and targeted/inverted behavior coverage. All 51 targeted PHP tests, all 18 PHP usage-graph tests, formatting, diff hygiene, and isolated all-target/all-feature Clippy pass.
- [x] (2026-07-20 13:05-05:00) Completed the PHP publication boundary. Commit `14aa44cb` was integrated with current `origin/master`, the resulting head was published at `64de341e`, and the exact release runner SHA-256 was `c2ab9b150125c6467ae5809511be4fdbc59381f60b1d6ed92786105703dbc7fc`. All three exact witnesses and all five authoritative task-ranked repositories completed with zero missing, inconclusive, diagnostics, or file errors. The final corpus SHA-256 is `12e80e0c30b982e54440c2ecf1e43b9e3bc05d632199067b6e57539337cd1e68`; assigned issues #960, #961, and #962 are closed with evidence. See `.agents/docs/reference-differential/php-task-ranked-64de341e-summary.md`.
- [ ] Complete, publish, close owned issues for, and summarize the Rust task-ranked leg.
- [ ] Complete, publish, close owned issues for, and summarize the Scala task-ranked leg.
- [ ] Complete, publish, close owned issues for, and summarize the Java task-ranked leg.
- [ ] Complete, publish, close owned issues for, and summarize the Python task-ranked leg.
- [ ] Verify the twenty-five-record matrix, compact manifests, issue states, clean worktree, and equality of local HEAD, local `origin/master`, and remote `refs/heads/master`.

## Surprises & Discoveries

- Observation: The earlier campaigns' repository sets are materially different from the requested task-ranked sets.
  Evidence: The old PHP campaign selected Moodle, Magento, Psalm, EduSoho, and Symfony by `repos.csv::code_loc`; the requested selector returns Laravel, CakePHP, PhpSpreadsheet, Snipe-IT, and CodeIgniter4 by filtered task count. Java, Python, Rust, and Scala have the same mismatch.

- Observation: `task_repos` applies the required `large-repos.csv` exclusion through `SFT_PREDICATES`, but its native ranking is a coarse count band plus build time rather than exact task-count order.
  Evidence: `tasks.py::_select` returns `RepoRef.task_count` and sorts first by `-int(log2(task_count))`; this plan explicitly stable-sorts those returned records by descending `task_count` before taking five. Scala's fifth place is tied at 62 tasks; stable selector order chooses `typelevel__fs2` ahead of `zio__zio-http`.

- Observation: The advanced historical Scala stack is large and touches shared analyzer, persistence, definition, and import infrastructure.
  Evidence: The detached `4e984fd9` lineage differs from this branch in 59 files and more than 32,000 inserted lines. It cannot be treated as accepted current-head evidence or integrated without deliberate conflict review and the full local gate.

- Observation: The restricted sandbox cannot execute three benchmark stderr-drain process tests, but the code is healthy outside that process sandbox.
  Evidence: The sandboxed full suite failed only `benchmark::mcp_session::{stderr_boundary_waits_for_delayed_marker_consumption,stderr_drain_bounds_an_unterminated_stream,stderr_drain_continuously_consumes_and_keeps_bounded_tail}` with OS error 1. The identical isolated feature-enabled command outside the sandbox passed the complete repository suite.

- Observation: An unrelated concurrent JS/TS campaign began modifying five tracked JS/TS files in this same worktree while the PHP full gate was running.
  Evidence: The PHP gate passed every library and integration target through the final usage-graph group, including all PHP tests, then failed `usage_graph_ts_test::qualified_type_references_create_exact_workspace_edges`; an isolated rerun reproduced it and exposed warnings in concurrently dirty `js_ts_graph/inverted.rs`. Those files are not part of the PHP change and will not be staged into its checkpoint.

- Observation: The shared branch advanced twice during the PHP publication gate, first with the completed TypeScript parity change and then with its lint-only follow-up, while `origin/master` also gained an LSP cache-isolation commit.
  Evidence: The final integrated PHP acceptance head is `64de341e`, containing `14aa44cb`, `de27750d`, `c5e4e3d2`, and `64de341e`. A clean detached build embedded that exact Bifrost head and source path. The unrestricted full gate passed every library test; 186 of 187 LSP tests passed in the suite, and the sole resource-contention SIGKILL (`lsp_server_drop_cleanup_exits_cleanly_after_initialize`) passed immediately when rerun alone.

## Decision Log

- Decision: Treat all previous LOC-ranked language records as regression evidence only and rerun all five requested languages.
  Rationale: Repository membership is part of the requested acceptance contract. Exact fixes found in other repositories remain legitimate product work, but they cannot substitute for the selected twenty-five-repository matrix.
  Date/Author: 2026-07-20 / Codex

- Decision: Use `task_repos(SFT_PREDICATES, langs=[LANG])`, then a stable descending `task_count` sort, and pass explicit repository slugs to the differential runner.
  Rationale: This preserves every `tasks.py` eligibility filter, including `large-repos.csv`, while implementing the user's exact "most tasks" ordering. Explicit `--repo` arguments prevent the runner's unrelated LOC ranking from changing membership.
  Date/Author: 2026-07-20 / Codex

- Decision: Process PHP, Rust, Scala, Java, then Python, with a publication and summary boundary after each language.
  Rationale: This follows the requested order, limits cross-language dirty state, and makes issue closure and final-corpus evidence attributable to one integrated head at a time.
  Date/Author: 2026-07-20 / Codex

- Decision: Retain the already-reviewed #904/#905 PHP implementation on the branch but require task-ranked corpus proof before declaring the PHP language complete.
  Rationale: The fixes are structured and independently tested, yet the prior source witnesses came from an invalid membership set for this goal. The new corpus may expose additional roots and must be audited independently.
  Date/Author: 2026-07-20 / Codex

- Decision: Partition the 298 PHP residuals into three issues with explicit overlap rather than force them into disjoint symptom buckets.
  Rationale: Nullsafe node dispatch (#962) and call-return receiver inference (#961) are independent structured requirements; two PhpSpreadsheet sites need both. Owner-relative type identity (#960) is separate. The issue ledgers record 96, 200, and 4 affected rows respectively and identify the two-row overlap.
  Date/Author: 2026-07-20 / Codex

## Outcomes & Retrospective

PHP is complete. Its task-ranked baseline contained 298 legitimate misses: 96 owner-relative type references, 200 call-return receiver chains, and four nullsafe calls, with two chain/nullsafe overlaps. Structured fixes for #960, #961, and #962 reduced all five final repositories to zero actionable and zero inconclusive rows at pushed head `64de341e`; the three issues are closed. Historical #904/#905 remain integrated regression fixes. The focused PHP suites, formatting, diff hygiene, isolated all-feature Clippy, full feature-enabled Cargo gate, exact witnesses, and production corpus all passed. The final artifact and hashes are recorded in `.agents/docs/reference-differential/php-task-ranked-64de341e-summary.md`.

Rust, Scala, Java, and Python remain. Historical fixes and issue closures in those languages remain regression inputs only until their task-ranked repository sets receive the same baseline, exhaustive triage, publication, and final-corpus treatment.

## Context and Orientation

Work in `/mnt/optane/tmp/bifrost-burndown-3` on the existing `bifrost-burndown-3` branch. Do not create or switch branches, rebase, or open a pull request. Commit only files changed for this campaign. Before publication, fetch `origin/master`, merge it into the current branch without rebasing if necessary, repeat proportionate local gates, and push the integrated `HEAD` directly to `origin/master`.

The differential CLI is `src/bin/bifrost_reference_differential.rs`; the engine and JSONL schema are in `src/reference_differential/mod.rs`. Forward definition resolution lives under `src/analyzer/usages/get_definition/`; inverse reference logic lives in `src/analyzer/usages/` and its language modules. `tests/common/inline_project.rs::InlineTestProject` is the preferred harness for small behavior reductions.

Canonical clones are below `/home/jonathan/Projects/brokkbench/clones`, which resolves to `/mnt/T9/repo-clones`. Task selection and all corpus eligibility reads go through `/home/jonathan/Projects/brokkbench/tasks.py`; do not manually read or reimplement filters over its task stores. Durable differential artifacts and logs belong under `/mnt/optane/tmp/reference-differential`; compact manifests and narrative summaries belong under `.agents/docs/reference-differential/`.

The authoritative task-ranked selections are:

- PHP: `laravel__framework` (126), `cakephp__cakephp` (95), `PHPOffice__PhpSpreadsheet` (84), `grokability__snipe-it` (82), `codeigniter4__CodeIgniter4` (74).
- Rust: `tokio-rs__tokio` (142), `kivikakk__comrak` (59), `ordian__toml_edit` (44), `tokio-rs__tracing` (40), `foobarto__stado` (37).
- Scala: `scala-steward-org__scala-steward` (147), `zio__zio` (106), `linkerd__linkerd` (72), `scalameta__metals` (71), `typelevel__fs2` (62). `zio__zio-http` also has 62; stable `tasks.py` order selects `typelevel__fs2`.
- Java: `alibaba__fastjson2` (328), `chinabugotech__hutool` (208), `languagetool-org__languagetool` (192), `halo-dev__halo` (163), `apache__dubbo` (126).
- Python: `bytedance__deer-flow` (208), `kornia__kornia` (112), `quantumlib__Cirq` (105), `mahmoud__glom` (90), `caikit__caikit` (84).

All twenty-five clone paths exist and their tracked worktrees were clean at selection time. Generated `.brokk/` cache state is operational, not source corpus content; exclude it in each clone's local `.git/info/exclude` if it would otherwise appear as untracked dirtiness.

## Plan of Work

Freeze a clean plan checkpoint and rebuild the release runner from that exact head. Record the Bifrost head, binary SHA-256, selector output, selected clone heads, and cleanliness. Run one language at a time with the five explicit task-ranked slugs, one repository job, eight inner workers, persisted cache mode, strict classification, and the runbook's established bounds.

For each completed language baseline, verify five completed repository envelopes, exact Bifrost and repository heads, clean flags, one semantic fingerprint, JSON integrity, configured limits, and file errors. Extract every raw `missing` site to a checksummed row ledger. Delegate disjoint source/row research where useful; root verifies source bytes, focused token and tree-sitter role, forward declaration group, inverse completeness, and exact-site reproducibility.

For each legitimate defect, search open and closed GitHub issues outside the restricted sandbox. If a matching issue is assigned to somebody other than `jbellis`, record it and skip implementation. Otherwise assign an existing issue to `jbellis` or create it already assigned before changing product code. Build a faithful `InlineTestProject` reduction with appropriate negative controls, delegate substantial structured diagnosis/implementation, independently review the diff, and run focused tests. Do not add regex, substring, delimiter-splitting, or source-text mini-parser fallbacks.

When all legitimate roots for a language are resolved or correctly skipped, run formatting, isolated all-target/all-feature Clippy, and the isolated complete `cargo test --features nlp,python` gate. Commit the relevant files with a multiline why-oriented message. Fetch and merge current `origin/master` if needed, repeat proportionate gates, and push directly to `origin/master` without waiting for CI.

Rebuild the release runner from the exact clean pushed head. Rerun every fixed exact witness and the full task-ranked five-repository language corpus into new head-scoped artifacts. Exhaustively audit all residuals. Only then comment on and close the owned issues, commit compact evidence, verify local/remote head agreement, give the user the language summary, and proceed immediately to the next language.

## Concrete Steps

Regenerate the selection without manually reading task stores:

    cd /mnt/optane/tmp/bifrost-burndown-3
    PYTHONDONTWRITEBYTECODE=1 python3 -c 'import sys; sys.path.insert(0,"/home/jonathan/Projects/brokkbench"); import tasks; print(sorted(tasks.task_repos(tasks.SFT_PREDICATES, langs=["php"]), key=lambda r: -r.task_count)[:5])'

Build and fingerprint the runner from a clean checkpoint:

    cargo build --release --bin bifrost_reference_differential
    git rev-parse HEAD
    sha256sum target/release/bifrost_reference_differential

The PHP command shape is:

    set -o pipefail
    /usr/bin/time -v target/release/bifrost_reference_differential run-corpus \
      --clones-root /home/jonathan/Projects/brokkbench/clones \
      --commits-root /home/jonathan/Projects/brokkbench/sft-tools-commits \
      --language php \
      --repo laravel__framework --repo cakephp__cakephp \
      --repo PHPOffice__PhpSpreadsheet --repo grokability__snipe-it \
      --repo codeigniter4__CodeIgniter4 \
      --repo-jobs 1 --jobs 8 --cache-mode persisted --strict \
      --max-files 1000 --max-sites 10000 \
      --max-candidates-per-file 50000 --max-source-bytes 4194304 \
      --max-targets 1000 --max-usage-files 1000 --max-usages 100000 \
      --seed 0 \
      --output /mnt/optane/tmp/reference-differential/php-task-top5-HEAD8.jsonl \
      2>&1 | tee -a /mnt/optane/tmp/reference-differential/php-task-top5-HEAD8.log

Repeat with the exact Rust, Scala, Java, and Python slug lists above and matching `--language` (`rust`, `scala`, `java`, `py`). Do not use `--repos-per-language`, `--include-tests`, or routine `--force`. Resume interrupted runs by confirming the old process is gone and repeating the identical command/output path.

Before each code publication, run:

    cargo fmt --all -- --check
    git diff --check
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    UV_CACHE_DIR=/tmp/bifrost-uv-cache BIFROST_SEMANTIC_INDEX=off \
      scripts/with-isolated-cargo-target.sh cargo test --features nlp,python

## Validation and Acceptance

A language is complete only when exactly its five selected repositories have completed records on one clean pushed Bifrost head, every repository head is pinned and clean, the configuration is uniform, every error and limit is accounted for, and every raw missing row has a reviewed disposition. Each owned legitimate defect must have an assigned issue, structured regression, fixing commit on `origin/master`, clean exact witness, clean final corpus proof, and closed issue. An issue assigned to another user is an explicit documented skip and is not modified.

The campaign is complete only when all five language boundaries pass, the compact evidence is committed, every accepted fixing head is an ancestor of final `origin/master`, the complete local gate passes after the final integration, and local HEAD, local `origin/master`, and remote master agree. GitHub CI is not a blocking gate.

## Idempotence and Recovery

`run-corpus` appends one completed repository envelope and skips an identical completion key on resume. Preserve JSONL, logs, and caches after interruption; repeat the exact command without `--force`. If Bifrost source changes, rebuild the runner and use a new head-scoped artifact. Do not mutate selected clone sources or delete caches to hide migration failures. Use `scripts/with-isolated-cargo-target.sh` for isolated Cargo targets and `scripts/cleanup-bifrost-tmp.sh` for reviewed cleanup.

## Artifacts and Notes

Keep raw JSONL, logs, exact records, row ledgers, and checksums under `/mnt/optane/tmp/reference-differential`. Check in only compact manifests and narrative summaries under `.agents/docs/reference-differential/`. Historical LOC-ranked artifacts and their issue fixes remain valuable regression inputs, but every final manifest must label them non-authoritative for this task-ranked objective.

## Interfaces and Dependencies

Reuse `reference_differential::run_reference_differential`, `WorkspaceAnalyzer`, `UsageFinder`, language-specific structured forward resolvers and inverse graphs, `AnalyzerStore`, and `InlineTestProject`. Preserve explicit target/file/usage limits and honest `unproven` or `inconclusive` outcomes. Add public SearchTools or Python binding coverage only when the exposed surface changes. Avoid new dependencies unless a reduced root cause requires them and this plan records why.

Revision note (2026-07-20): Created this task-ranked plan after an independent audit proved the prior campaigns used LOC-ranked repository membership. It pins the exact `tasks.py`/`SFT_PREDICATES` selection, invalidates old artifacts only as objective completion evidence, preserves their regression value, and records the issue, delegation, test, publication, and per-language summary boundaries.

Revision note (2026-07-20): Completed the PHP language boundary at pushed head `64de341e`, recorded its zero-residual production evidence, and closed assigned issues #960-#962.
