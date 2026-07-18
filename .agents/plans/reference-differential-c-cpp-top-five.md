# Audit the five largest non-Chromium C and C++ corpora through the public symbols surface

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` current while the work proceeds. Maintain it in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost's forward-vs-inverse reference differential asks whether a source reference that resolves through the public symbols API can be recovered by the inverse usage query for that declaration. The Chromium C and C++ campaign is complete; this campaign tests whether those fixes generalize by auditing the five largest valid canonical local clones for C and the five largest for C++, excluding Chromium.

The observable result is ten completed repository records from a clean, integrated Bifrost head. Every raw `missing` site receives an exhaustive disposition based on its live source bytes, forward identity, inverse limits, and an exact-site rerun. Every legitimate analyzer defect is either covered by an existing issue already owned by `jbellis`, or is filed and assigned only to `jbellis` before implementation. Issues owned by somebody else are recorded and skipped. Accepted fixes receive behavior-focused structured reductions, exact production proofs, formatting, all-target/all-feature Clippy, the complete `cargo test --features nlp,python` gate, a direct push to `origin/master`, and a fresh all-ten confirmation. GitHub CI is not a blocking gate after local tests pass.

The acceptance surface is the MCP `symbols` toolset and its associated Rust and Python APIs. LSP behavior shares analyzer code and must remain green, but editor-protocol behavior is incidental rather than the campaign target.

## Progress

- [x] (2026-07-18 19:30Z) Reconciled the clean detached worktree with live `origin/master` at `d4e81dab27cca8fd5905fc10d56a19741ad78331`; the recent Chromium C/C++ closure commits are present and no campaign files are dirty.
- [x] (2026-07-18 19:30Z) Read `.agents/PLANS.md`, the canonical N=1 campaign, and the completed Java/Go/Python top-five plan so this campaign preserves their evidence, recovery, and issue-ownership discipline.
- [x] (2026-07-18 19:30Z) Used the canonical corpus metadata and a no-write runner dry-run to select the exact five C and five non-Chromium C++ repositories. Verified their clone heads and identified RMerl's unignored `.brokk/` as the only apparent dirtiness.
- [x] (2026-07-18 19:30Z) Completed independent read-only runner and GitHub audits. The safe initial resource shape is one C and one C++ corpus process concurrently, each with one active repository and eight inner workers. Open issue #894 is assigned to another user and covers CFG/ICFG rather than symbols; it must not be absorbed into this campaign.
- [x] (2026-07-18 19:34Z) Published the campaign-start plan and run manifest on `origin/master` at `31853f8485f68fce41a99b3c4155a57f467d3e79`, locally excluded `.brokk/` from all selected clones, and built the frozen release runner (`sha256 709bd0f4a4e1c668c9891d78e6fb5002fe1e5588d1f943624150b0d0d0179fcb`).
- [x] (2026-07-18 22:47Z) Completed and integrity-checked all five C and five C++ baseline records: 100,000 sampled sites, 12,279 consistent, 234 editor-only, 541 unproven, 86,147 inconclusive, and 799 raw missing. Both language JSONL files have five clean pinned-head records with one shared fingerprint.
- [x] (2026-07-19 03:25Z) Exhaustively ledgered and classified all 799 raw missing rows. The final baseline disposition is 529 genuine defects and 270 comparison artifacts: C contributes eight genuine and four artifacts; C++ contributes 521 genuine and 266 artifacts. OceanBase's 168 rows resolve to 142 genuine and 26 artifacts with a checksummed row ledger.
- [ ] File or reuse issues assigned only to `jbellis`, delegate substantial implementations to Oldskool, root-review each change, and prove fixes with focused tests and exact production reruns. (Completed: filed and assigned #924 through #932; committed reviewed fixes for #924, #927, #928, #929, and #930; exact clean-head production witnesses for #924 and both #928 shapes are now consistent. #925 is undergoing conditional-preprocessor and cache-cardinality hardening; #926 returned for callable-precedence correction; #931 and #932 are delegated and active. Remaining: accept those implementations, reduce any residual receiver/type-environment families not covered by the filed issues, and run the remaining production proofs.)
- [ ] Pass formatting, all-target/all-feature Clippy, focused suites, and the complete feature-enabled Cargo suite; integrate and push directly to `origin/master` without waiting for CI.
- [ ] Rebuild the runner and complete a fresh clean all-ten confirmation, audit every final residual, close assigned issues with evidence, publish compact checked-in reports, and verify a clean worktree equal to `origin/master`.

## Surprises & Discoveries

- Observation: Whole-repository LOC ranking can select a polyglot repository with relatively few C seed files.
  Evidence: `DeusData__codebase-memory-mcp` ranks second at 36,291,013 recorded LOC but has about 747 tracked `.c` files. The selection is nevertheless canonical because membership comes from `c/*.jsonl` and ranking comes from `repos.csv::code_loc`; it must not be replaced by a hand-picked C-heavy repository.

- Observation: C and C++ share `Language::Cpp` analyzer implementation but have deliberately different corpus seed frontiers.
  Evidence: C samples only `.c`; C++ excludes `.c` and admits `cc`, `cpp`, `cxx`, `h`, `hpp`, `hh`, and `hxx`. This preserves the requested language labels while exercising the shared analyzer.

- Observation: A release binary can report a newer repository HEAD than the code it actually contains.
  Evidence: Bifrost revision metadata is read dynamically from the worktree, while the executable may have been built earlier. Every baseline and final corpus therefore requires a fresh build from a frozen clean head and a new head-scoped output.

- Observation: Persisted analyzer caches can make an otherwise clean clone appear dirty.
  Evidence: RMerl currently reports only untracked `.brokk/` and contains an approximately 11-GiB warm cache. Local `.git/info/exclude` entries are required for all ten clones before accepted persisted-mode records; tracked-source cleanliness remains mandatory.

- Observation: The canonical C++ top five would include Chromium if selected only by count.
  Evidence: Chromium is ranked first in the C++ dry-run. The campaign must use explicit repository filters for WebKit, Node.js, QGIS, LLVM, and OceanBase rather than `--repos-per-language 5`.

- Observation: Chromium's fixes generalized strongly to large C corpora.
  Evidence: Across 50,000 C sites, only 12 rows were raw missing; exhaustive review found eight genuine misses in three structured families and four artifacts. ASUSWRT and the WSL kernel had zero genuine misses.

- Observation: Non-Chromium C++ misses are concentrated rather than a long tail of unrelated parser shapes.
  Evidence: The first four C++ repositories produced 619 raw rows, of which exhaustive second-pass review classified 379 as genuine. Effective ordinary and namespace imports account for 262 of those 379 rows; the remaining rows cluster around lexical type, template alias, receiver/member, construction, field-declaration, and hierarchy seams.

- Observation: The shared authoritative visibility batch has a large single-threaded setup cost on OceanBase.
  Evidence: OceanBase completed its 746-file forward phase at 4,736.4 seconds, then spent about 30 minutes in `CppAuthoritativeUsageBatch::new` before the first inverse-target progress event. Host observation showed one active setup thread and about 12--15 GiB resident memory. The complete repository record took 7,701.9 seconds and 14,882,120 KiB peak RSS.

- Observation: A single inverse target can dominate a large-repository run after the shared batch is built.
  Evidence: QGIS had one target take about 1,560 seconds because the same large source was parsed once per 113 sibling candidates. OceanBase likewise paused at 971/1,000 while one worker consumed a full core, then released 24 queued targets. Issue #929 carries the exact 113-to-zero reparse reduction.

- Observation: OceanBase confirms that the apparent C++ long tail is still dominated by shared environment resolution.
  Evidence: Of OceanBase's 142 genuine misses, 117 are type-environment/type-usage rows, including 53 explicit `using namespace` witnesses. Across all five C++ repositories, explicit import witnesses alone provide a conservative lower bound of 315 rows for #926, about 60% of every genuine baseline miss across both languages.

- Observation: High-coverage import and macro patches still require adversarial precedence and resource controls before integration.
  Evidence: A direct `local::Build` declaration plus `using namespace alpha` passed the initial #926 suite but a root-added public-surface control proved the patch incorrectly selected `alpha::Build` on forward, targeted, and whole lookup. The first hardened #925 design also cached one full macro environment per call byte and linearly selected mutually exclusive conditional definitions; both were returned for structured fail-closed and bounded-cache correction.

## Decision Log

- Decision: Select repositories from canonical language membership, ordered by whole-repository `code_loc`, while explicitly excluding Chromium only from C++.
  Rationale: This is deterministic, reproducible, and matches the prior top-five campaign's selection contract. Chromium is not a canonical C member, so no additional C exclusion is needed.
  Date/Author: 2026-07-18 / Codex

- Decision: Run C and C++ concurrently as two independent resumable processes, each with `--repo-jobs 1 --jobs 8`.
  Rationale: At most two enormous workspaces are active at once, avoiding the memory and I/O risk of ten-repository fan-out while still overlapping the two language legs. Separate JSONL files keep recovery and per-language accounting simple.
  Date/Author: 2026-07-18 / Codex

- Decision: Use persisted cache mode and never delete a clone's `.brokk` directory as a retry strategy.
  Rationale: These are deliberately resumable corpus campaigns and warm cache behavior is part of the production symbols path. Epoch or migration failures must be diagnosed rather than erased.
  Date/Author: 2026-07-18 / Codex

- Decision: Treat `missing` as a triage input, not as proof of a defect.
  Rationale: A valid ticket requires a semantically valid forward declaration group, a complete non-truncated inverse query, live source confirmation, exact reproduction, and a faithful structured reduction. Wrong owners, qualifiers, declaration roles, duplicate identities, explicit limits, `unproven`, and `inconclusive` outcomes are not inverse defects.
  Date/Author: 2026-07-18 / Codex

- Decision: File one issue per legitimate root-cause family when it has two independent witnesses, one witness plus a structured source survey proving recurrence, or a singleton that clearly violates a broad public API invariant.
  Rationale: This retains Chromium's protection against parser-recovery whack-a-mole without hiding a real general symbols invariant merely because deterministic sampling found it once. All isolated non-general parser artifacts remain explicitly documented in the final ledger.
  Date/Author: 2026-07-18 / Codex

- Decision: Root owns planning, source/identity adjudication, GitHub mutations, review, acceptance gates, integration, and closure; substantial implementations go to synchronous Oldskool when available.
  Rationale: This is the user's requested division of labor and keeps authority for tickets and correctness in the root session.
  Date/Author: 2026-07-18 / Codex

- Decision: Require a fresh all-ten run after the integrated fixing head, even if exact probes and per-language reruns are already clean.
  Rationale: C and C++ share analyzer and persistence machinery. A later C++ fix can affect earlier C evidence, and sampled target composition can change after a correction; subtracting exact-site deltas is not a closure proof.
  Date/Author: 2026-07-18 / Codex

- Decision: Freeze every workspace file while a baseline runner is active, including planning documents.
  Rationale: The release runner reads Bifrost HEAD and dirtiness dynamically for each repository record. Mutating even an agent-owned plan would make executable provenance and recorded provenance disagree. All research and patch preparation therefore stayed under `/tmp` until OceanBase's fifth record was durable.
  Date/Author: 2026-07-18 / Codex

- Decision: Accept resumed outer concurrency of two C repositories and three C++ repositories after measuring host headroom, while preserving eight inner workers and every semantic limit.
  Rationale: The original one-repository launch was safely resumable but unnecessarily serialized independent repositories. The completed records retain the same head, fingerprint, per-repository limits, and inner parallelism; only orchestration concurrency changed. This launch history is recorded rather than retroactively claiming the original setting.
  Date/Author: 2026-07-18 / Codex

- Decision: Stop reopening isolated Chromium residuals unless a non-Chromium witness establishes recurrence.
  Rationale: Chromium's final C++ tail contained no recurring unfixed family. The top-five campaign is the generalization test; importing one-off Chromium parser shapes without a new witness would turn the campaign into whack-a-mole.
  Date/Author: 2026-07-18 / Codex

- Decision: Do not wait for GitHub CI after the complete local gate passes.
  Rationale: The user explicitly made local `cargo test` the transition boundary. Formatting, Clippy, focused tests, and `cargo test --features nlp,python` remain mandatory.
  Date/Author: 2026-07-18 / Codex

## Outcomes & Retrospective

The clean `31853f84` baseline and exhaustive disposition milestones are complete. All ten repositories contributed one accepted 10,000-site record. C produced 12 raw missing rows, eight genuine defects, and four artifacts. C++ produced 787 raw missing rows, 521 genuine defects, and 266 artifacts; OceanBase's share is 142 genuine and 26 artifacts. The aggregate baseline classifications are 12,279 consistent, 234 editor-only, 541 unproven, 86,147 inconclusive, and 799 raw missing. Checksummed C and OceanBase ledgers preserve the exact row evidence.

The strongest interim conclusion is that the Chromium work generalized: large C is nearly closed, and C++ misses concentrate in a small number of cross-repository resolver environments rather than recurring Chromium-only parser recovery. The baseline also exposed two concrete performance costs: the shared visibility batch's OceanBase setup and repeated per-candidate class-strength parsing (#929). #924, #927, #928, #929, and #930 now have committed fixes with focused behavior, persistence, or scale proofs. Exact clean-head reruns moved the FreeBSD #924 witness and both RavynOS #928 witnesses from missing to consistent. This section remains incomplete until the rest of the fix stack, remaining production proofs, the clean all-ten confirmation, issue closure, reports, and final master synchronization are complete.

## Context and Orientation

Work in `/mnt/optane/tmp/bifrost-scala-residuals`. The worktree is detached by design. Do not create or switch branches and do not open a pull request. At clean publication boundaries fetch `origin/master`, merge it with `git merge --no-edit origin/master` if it advanced, never rebase, and push with `git push origin HEAD:master`. Stage only files changed for this campaign.

The driver is `src/bin/bifrost_reference_differential.rs`; the engine and report schema are in `src/reference_differential/mod.rs`. `run-corpus` appends one JSON object per completed repository. Its completion key includes language, repository slug/head, Bifrost head, and the configuration fingerprint. `--repo-jobs` controls outer repository concurrency; `--jobs` controls analyzer and audit concurrency inside a repository.

Canonical metadata lives at `/home/jonathan/Projects/brokkbench/sft-tools-commits`: language membership comes from `c/*.jsonl` and `cpp/*.jsonl`, and ranking comes from `repos.csv::code_loc`. Clone paths under `/home/jonathan/Projects/brokkbench/clones` resolve to `/mnt/T9/repo-clones`.

The selected C repositories are:

1. `RMerl__asuswrt-merlin.ng`, head `e7c1391253597c1d5d813e420486a823835f5ab2`, 49,660,873 LOC, about 170,093 `.c` files.
2. `DeusData__codebase-memory-mcp`, head `63e3f2c7a6ba0ae444967d1f777254e9df5e381a`, 36,291,013 LOC, about 747 `.c` files.
3. `microsoft__WSL2-Linux-Kernel`, head `ceac005095dab3350884935aafb0b115f183ecb9`, 19,159,158 LOC, about 35,994 `.c` files.
4. `freebsd__freebsd-src`, head `4179f1d9deed83977f159c8afea204293ef4c7d7`, 13,946,264 LOC, about 22,414 `.c` files.
5. `ravynsoft__ravynos`, head `04d903b97e3d6a13792a2701c284d99441803ec8`, 10,305,429 LOC, about 17,656 `.c` files.

The selected C++ repositories, after excluding Chromium, are:

1. `WebKit__WebKit`, head `6350c54363c185145ff0457d6d8d5c1f299bbddd`, 14,958,466 LOC, about 41,590 eligible files.
2. `nodejs__node`, head `2f2b81095bdc2fa30afdd33389fbbe292010a5c4`, 11,009,467 LOC, about 11,879 eligible files.
3. `qgis__QGIS`, head `115eeaa78a7862d12b5fd291dee146e56dccf04a`, 8,765,993 LOC, about 7,747 eligible files.
4. `llvm__llvm-project`, head `64381998961b4b9324ab5a6f6015b285b59d6bb6`, 8,434,989 LOC, about 55,706 eligible files.
5. `oceanbase__oceanbase`, head `3fcbf54020a36a67f74313a8766396bcabf9d633`, 7,389,367 LOC, about 13,892 eligible files.

The prior Chromium closure and its known false-forward, declaration-frontier, parser-recovery, alias, receiver, qualifier, and redeclaration families are recorded in `.agents/plans/reference-differential-corpus.md`. They are duplicate-search guidance, not permission to copy a disposition without checking the new repository's exact bytes, target identity, and diagnostics. The directly adjacent open issue owned elsewhere is #894, C/C++ callable CFG/ICFG conformance; CFG/ICFG findings are outside this symbols campaign and must be skipped.

## Plan of Work

First publish this plan from a clean Bifrost checkpoint. Add `.brokk/` to each selected clone's local `.git/info/exclude` without modifying tracked clone content, then verify all ten clones report `repo_dirty=false` under the runner's rules and still match the pinned heads. Build a fresh release runner from the published Bifrost head and do not modify the Bifrost source tree while either baseline process runs.

Start one explicit C `run-corpus` command and one explicit C++ command concurrently. Each process begins with one active repository and eight inner workers, persisted cache mode, the established 1,000-file/10,000-site/1,000-target budgets, and `--strict`. After measuring host headroom, resumable recovery may increase only outer repository concurrency; the accepted run used two C repositories and three C++ repositories concurrently without changing any semantic limit. Store head-scoped JSONL and logs below `/mnt/optane/tmp/reference-differential`. A strict exit status of two is expected when raw missing sites exist; acceptance depends on five completed repository records, not the shell status alone. If interrupted, confirm no process still owns a selected clone and repeat the identical command without `--force` so completed semantic keys are skipped.

After both baselines finish, verify JSON integrity, exact Bifrost and repository heads, clean flags, configuration fingerprints, record counts, and any file errors or explicit truncation. Extract every raw missing row into a stable ledger keyed by repository, path, start/end byte, and ordered declaration identities. Preserve the original `text`, source evidence, targets, note, and diagnostics. Partition read-only source review by repository among research agents and Oldskool; root checks source bytes and adjudicates every row.

For each suspicious row, rerun `run-repo` against the exact path and byte range on the same clean Bifrost head. Confirm the forward declaration group is semantically valid, inverse limits are complete, and the focused token is the referenced terminal. Reproduce every surviving defect with a behavior-focused `InlineTestProject` reduction. Forward identity bugs belong in definition tests; targeted inverse bugs in C++ usage graph tests; whole-workspace parity bugs in inverted graph tests; public surface changes need symbols service and Python API coverage as appropriate. Include negative controls for owners, namespaces, aliases, overload/arity, receiver type and inheritance, lexical shadowing, duplicate declarations, includes/visibility, templates, macro recovery, and C-vs-C++ language partition as relevant. Use tree-sitter and analyzer structures only; do not introduce regex, substring, delimiter-splitting, or source-text mini-parser fallbacks.

Only after a faithful reduction fails should root search open and closed GitHub issues by language, symbol, and root cause, inspect assignees, and mutate issue state. Reuse an unassigned issue only after assigning it exclusively to `jbellis`; otherwise create a new issue already assigned to `jbellis`. If a matching issue belongs to another user, record the skip and do not implement it. Group witnesses by root cause under the ticket threshold in the Decision Log.

Delegate substantial implementation to synchronous Oldskool with the issue and failing behavior test as its contract. Root reviews every diff, rejects structured-correctness shortcuts or broad candidate amplification, adds missing negative coverage, and runs focused tests. Exact production probes on a dirty tree are provisional only. If emitted C/C++ declarations or identities change, bump the appropriate analysis epoch and prove persisted-mode behavior rather than relying on an ephemeral exact run.

After the complete fix stack is reviewed, run formatting, all-target/all-feature Clippy, all affected focused suites, and `UV_CACHE_DIR=/tmp/bifrost-uv-cache cargo test --features nlp,python`. Update this plan and the compact report, commit only campaign files with a multiline why-oriented message, fetch and merge current master if necessary, repeat proportionate gates after the merge, and push `HEAD:master`. Do not wait for CI.

Finally rebuild the release runner from the clean pushed head and run both complete five-repository commands into new head-scoped outputs. Exhaustively audit every final raw missing row; exact probes alone or subtraction from the baseline are insufficient. Publish `.agents/docs/reference-differential/top5-c-cpp.jsonl` as the compact machine-readable manifest and `.agents/docs/reference-differential/top5-c-cpp-summary.md` as the human-readable evidence summary. Comment on and close assigned issues only after clean production proof. Verify the worktree is clean and local HEAD, local `origin/master`, and remote `refs/heads/master` are identical.

## Concrete Steps

From `/mnt/optane/tmp/bifrost-scala-residuals`, publish the plan checkpoint and build the exact clean runner:

    git status --short
    git rev-parse HEAD
    git rev-parse origin/master
    cargo build --release --bin bifrost_reference_differential

The C command uses these explicit repositories:

    set -o pipefail
    /usr/bin/time -v target/release/bifrost_reference_differential run-corpus \
      --clones-root /home/jonathan/Projects/brokkbench/clones \
      --commits-root /home/jonathan/Projects/brokkbench/sft-tools-commits \
      --language c \
      --repo RMerl__asuswrt-merlin.ng \
      --repo DeusData__codebase-memory-mcp \
      --repo microsoft__WSL2-Linux-Kernel \
      --repo freebsd__freebsd-src \
      --repo ravynsoft__ravynos \
      --repo-jobs 1 --jobs 8 --cache-mode persisted --strict \
      --max-files 1000 --max-sites 10000 \
      --max-candidates-per-file 50000 --max-source-bytes 4194304 \
      --max-targets 1000 --max-usage-files 1000 --max-usages 100000 \
      --seed 0 \
      --output /mnt/optane/tmp/reference-differential/c-top5-BIFROST_HEAD.jsonl \
      2>&1 | tee /mnt/optane/tmp/reference-differential/c-top5-BIFROST_HEAD.log

The C++ command is identical except for language, explicit repositories, and output names:

    set -o pipefail
    /usr/bin/time -v target/release/bifrost_reference_differential run-corpus \
      --clones-root /home/jonathan/Projects/brokkbench/clones \
      --commits-root /home/jonathan/Projects/brokkbench/sft-tools-commits \
      --language cpp \
      --repo WebKit__WebKit \
      --repo nodejs__node \
      --repo qgis__QGIS \
      --repo llvm__llvm-project \
      --repo oceanbase__oceanbase \
      --repo-jobs 1 --jobs 8 --cache-mode persisted --strict \
      --max-files 1000 --max-sites 10000 \
      --max-candidates-per-file 50000 --max-source-bytes 4194304 \
      --max-targets 1000 --max-usage-files 1000 --max-usages 100000 \
      --seed 0 \
      --output /mnt/optane/tmp/reference-differential/cpp-top5-BIFROST_HEAD.jsonl \
      2>&1 | tee /mnt/optane/tmp/reference-differential/cpp-top5-BIFROST_HEAD.log

Do not use `--force` except after proving an existing record for the same semantic key is invalid. Do not use `--include-tests`. Run the two pipelines under separate managed sessions so one expected strict exit does not terminate the other. The accepted filenames substitute the exact eight-character Bifrost head.

Extract repository summaries and raw rows with structured JSON queries:

    jq -c 'select(.record_type == "repository") | {repo_slug,repo_head,bifrost_head,bifrost_dirty,repo_dirty,elapsed_seconds,summary:.report.summary,file_errors:.report.file_errors}' FILE.jsonl

    jq -c 'select(.record_type == "repository") as $r | $r.report.sites[] | select(.classification == "missing") | {repo_slug:$r.repo_slug,path,start_byte,end_byte,line,text,source_evidence,targets,note,diagnostics}' FILE.jsonl

Before the integration push, run at minimum:

    cargo fmt --all -- --check
    cargo clippy --all-targets --all-features -- -D warnings
    UV_CACHE_DIR=/tmp/bifrost-uv-cache cargo test --features nlp,python --test get_definition_test
    UV_CACHE_DIR=/tmp/bifrost-uv-cache cargo test --features nlp,python --test usages_cpp_graph_test
    UV_CACHE_DIR=/tmp/bifrost-uv-cache cargo test --features nlp,python --test usage_graph_cpp_test
    UV_CACHE_DIR=/tmp/bifrost-uv-cache cargo test --features nlp,python

If target names have changed, inspect `tests/` and run the actual equivalent rather than silently omitting coverage. Use `scripts/with-isolated-cargo-target.sh` only when an isolated build is deliberately required; do not create manually named Cargo target directories.

## Validation and Acceptance

The baseline is valid only when all ten pinned repositories have successful records for one exact clean Bifrost head and configuration, both clean flags are false for dirtiness, JSON parses, and every engine/file error or explicit limit is accounted for. A strict exit of two is acceptable only because it reports raw missing rows after all repository records were written.

A fixed defect is accepted only with a pre-fix failing behavior reduction, issue ownership consistent with this plan, focused green tests, an exact production rerun, and root review of the implementation. An inverse hit must cover the exact original byte range with the intended declaration identity; making forward lookup honestly return `no_definition` is acceptable only when the former identity was semantically invalid.

The campaign is complete only when the fresh integrated all-ten run meets the same integrity boundary, every final raw missing row has a reviewed ledger disposition, zero legitimate in-scope defects remain, every worked issue is assigned only to `jbellis` and closed with fixing evidence, formatting and all-target/all-feature Clippy pass, the complete `cargo test --features nlp,python` suite passes, compact reports are checked in, and local/remote master plus the clean worktree agree. CI is deliberately not awaited.

## Idempotence and Recovery

`run-corpus` is append-only and resume-safe. Repeating an unchanged command without `--force` skips completed semantic keys and reruns only incomplete repositories. Records arrive in completion order, so JSONL order is not meaningful. Preserve partial outputs and logs; never truncate them during recovery.

If a process stops, first verify no differential or analyzer process still owns the clone, inspect the log's terminal error, and repeat the exact command. Do not delete `.brokk`. If a persisted-cache migration fails, retain the database and diagnose its epoch, ownership, and schema state. If Bifrost source changes while a corpus process is active, the evidence is invalid because executable code and dynamically reported head can diverge; stop safely, build from a new clean checkpoint, and use new head-scoped outputs.

Research delegation may inspect source while corpus runs are active but must not mutate Bifrost or selected clones. Implementation begins only after the relevant analyzers stop and a failing reduction exists. Never combine records from different Bifrost heads into a claimed final matrix.

## Artifacts and Notes

Raw resumable evidence lives below `/mnt/optane/tmp/reference-differential/` with `c-top5-<head>` and `cpp-top5-<head>` prefixes. Derived exhaustive audit files should follow the established `-missing-audit.{jsonl,tsv,summary.json,sha256}` and `-missing-ledger.{jsonl,tsv,sha256}` conventions. Raw multi-megabyte site payloads and analyzer logs are not committed.

The durable repository deliverables are `.agents/docs/reference-differential/top5-c-cpp.jsonl`, `.agents/docs/reference-differential/top5-c-cpp-summary.md`, this living ExecPlan, and the canonical N=1 campaign update if shared C/C++ conclusions materially change. The compact manifest must pin repository and Bifrost heads, configuration fingerprint, summary counters, runtime, file errors, audit checksums, issue ledger, and artifact paths.

At campaign start the host has 120 logical processors, 98 GiB RAM, 255 GiB swap, about 601 GiB free on `/mnt/optane`, 798 GiB free on `/mnt/T9`, and 791 GiB free on `/tmp`. These are capacity observations, not performance requirements. Record actual wall time, CPU, and peak RSS per process so resource choices can be revised based on measurements rather than guesswork.

## Interfaces and Dependencies

No production interface change is planned in advance. Preserve the existing differential CLI, append-only report schema, stable declaration identity, and public symbols behavior. Changes should stay in the shared structured analyzers and resolvers, with `InlineTestProject` coverage from `tests/common/inline_project.rs`.

C and C++ both use the C++ parser/analyzer and persisted metadata. Any declaration-emission or identity correction may require a C++-local analysis epoch bump so warm caches cannot silently retain stale facts. Avoid new dependencies, persistence schemas, or public API shapes unless a reduced root cause requires them and this plan records the decision first.

Revision note (2026-07-18 19:30Z): Created the self-contained C/C++ top-five plan after the Chromium closure, pinned the canonical ten-repository matrix and clone heads, completed independent runner and GitHub audits, selected bounded two-repository concurrency, and recorded the clean-head, issue-ownership, delegation, local-gate, no-CI-wait, exhaustive-ledger, and final-all-ten acceptance boundaries before any cache or analyzer mutation.

Revision note (2026-07-18 22:47Z): Recorded the accepted ten-repository `31853f84` baseline, actual resumable outer concurrency, per-language triage progress, assigned issues #924--#929, frozen-workspace provenance rule, concentrated C++ families, and measured OceanBase/QGIS performance surprises before implementation began.

Revision note (2026-07-19 03:25Z): Closed the exhaustive 799-row baseline disposition at 529 genuine and 270 artifacts, recorded OceanBase's checksummed 142/26 split and the 315-row explicit-import lower bound, added assigned issues #930--#932, and recorded the first three committed fixes while the delegated fix stack remains active.

Revision note (2026-07-19 04:20Z): Recorded committed #927/#930 fixes, exact clean production proofs for #924/#928, active #931/#932 delegation, and the adversarial review controls that returned #925/#926 for correctness and bounded-resource hardening.
