# Complete the PHP, Rust, and Scala top-five reference differential

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept current as work proceeds. Maintain it in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost exposes forward symbol lookup and inverse reference lookup through the MCP `symbols` toolset and the corresponding Rust and Python APIs. These two directions should agree: when a source reference resolves forward to a workspace declaration, an inverse query for that declaration should return the original source range unless the operation is explicitly incomplete, editor-only, or semantically ambiguous. This campaign exercises that contract on the five largest available PHP, Rust, and Scala corpus clones, audits every raw disagreement, fixes every genuine product defect, and publishes clean commit-pinned evidence for each language.

The observable result is three definitive JSONL artifacts under `/mnt/optane/tmp/reference-differential`, one for PHP, one for Rust, and one for Scala. Each contains five completed repository records from a clean pushed Bifrost head. Every raw `missing` site is either eliminated by a root-cause fix or exhaustively documented as non-actionable with source and identity evidence. Every genuine defect has an issue assigned to `jbellis` before implementation, behavior-focused regression coverage, a pushed fix on `origin/master`, and a closed issue containing final evidence. LSP shares analyzer code and remains covered by the full repository gate, but editor protocol behavior is not the acceptance focus.

## Progress

- [x] (2026-07-17) Read `AGENTS.md`, `.agents/PLANS.md`, the original N=1 campaign plan, and the completed Java/Go/Python top-five plan. Verified the worktree is clean, detached at `b0d6a31f`, and exactly matches `origin/master`.
- [x] (2026-07-17) Deterministically selected and validated all fifteen PHP/Rust/Scala clones through `run-corpus --dry-run`. Every clone is clean. Moodle, GritQL, and IntelliJ Scala have persisted caches of 685 MiB, 30 MiB, and 167 MiB; the other twelve are cold. The clone volume has 803 GiB free and Optane has 642 GiB free.
- [x] (2026-07-17) Delegated read-only prior-campaign reconciliation and high-risk production-shape research to the Oldskool subagent while the root session owns this plan, GitHub mutations, acceptance decisions, gates, commits, merges, and pushes.
- [x] (2026-07-17) Committed the initial plan as detached `4b61d137` and rebuilt the release runner from that clean head. Direct publication was not attempted a second time after the managed approval layer rejected the first `HEAD:master` push as lacking fresh explicit approval for this new campaign. Corpus work continues from the commit-pinned clean head; integration still requires approval.
- [ ] Complete, integrate, prove, and summarize the PHP top-five leg. Baseline `php-top5-4b61d137.jsonl` completed all five repositories in 8m15s with 4.0 GiB peak RSS. Its seven raw rows reconcile to one wrong-forward artifact covered by assigned #890 and six genuine inverse misses filed as assigned issues #904 and #905. Oldskool implemented both inverse roots; independent review, 49 targeted graph tests, 16 whole-workspace graph tests, formatting, all-target/all-feature Clippy, the complete feature-enabled suite, and all six dirty-tree production exact witnesses pass. A host-wide inotify instance ceiling required running the aggregate suite with one test thread while excluding the 43 selector tests, then running every excluded selector test in a fresh process; all coverage passed. Commit, current-master merge, repeated gates, push, and clean-head proof remain.
- [ ] Complete, integrate, prove, and summarize the Rust top-five leg.
- [ ] Complete, integrate, prove, and summarize the Scala top-five leg.
- [ ] Reconcile all final artifacts, issue states, local gates, and `origin/master`; leave the detached worktree clean.

## Surprises & Discoveries

- Observation: The metadata-selected Scala top five excludes three larger repositories because their expected clones are absent.
  Evidence: dry-run reported missing clones for `JohnSnowLabs__spark-nlp`, `apache__spark`, and `joernio__joern`, then selected the next five valid clones. Selection remains deterministic and must not be hand-edited.

- Observation: Most of this expansion is genuinely cold despite the completed N=1 campaign.
  Evidence: only one selected clone per language currently contains `.brokk`; twelve repositories require initial persisted analyzer construction. The available disk headroom is ample, but cache growth and free space must still be checked after each language.

- Observation: Prior N=1 work is a source of exact preflight leads, not proof about the current five-repository result.
  Evidence: the earlier campaign fixed PHP #671-#674, Rust #643-#660, and Scala #651/#661-#664 on older Bifrost heads. Current code and different sampled repositories can expose new shapes, so every retained raw row still requires current source/identity review.

- Observation: The PHP top-five baseline is already actionable-zero in three repositories and has only seven raw rows overall.
  Evidence: Moodle, Magento, and EduSoho reported zero `missing`; Psalm reported five and Symfony two. All five JSONL records are `status=completed`, name clean Bifrost head `4b61d137`, and match the selected repository heads.

- Observation: One Psalm raw row is a wrong forward identity, not an inverse omission.
  Evidence: `ArithmeticOpAnalyzer.php:754` is inside an outer `TLiteralString` refinement and a mutually exclusive nested `elseif`, but linear forward binding replay imports the preceding branch's `TLiteralInt` assignment and reports `TLiteralInt.value`. The open PHP CFG/branch-modeling issue #890 is assigned to David, so the campaign records and skips it under the ownership rule.

- Observation: The six legitimate PHP inverse misses form two structured roots.
  Evidence: four `$x = $x->method()` sites mutate or shadow `$x` before visiting the RHS; two variables assigned from `self::method()` lose the declared return type because targeted scoped-call inference sends `self` through ordinary namespace type resolution. Exact baseline reproductions were preserved for a representative of each family.

- Observation: PHP assignment extraction must observe evaluation order, and static scope words are owner-relative rather than namespace-relative types.
  Evidence: the accepted implementation records assignment RHS references before applying the new binding in both targeted and whole-workspace graph traversals. A shared structured helper maps `self`/`static` to the enclosing declaration owner and `parent` to its declared direct class parent. The four #904 and two #905 production exact reruns all changed from one actionable miss to zero.

- Observation: The host's fixed `fs.inotify.max_user_instances=1024` ceiling can make a highly parallel full suite fail before a temporary workspace watcher starts even when the test behavior is correct.
  Evidence: the sole aggregate failure passed immediately in an isolated one-thread process. The complete suite then passed with `--test-threads=1` while excluding the 43 `searchtools_definition_selectors` cases, and all 43 excluded cases passed individually in fresh processes. Managed approval rejected a temporary host-wide sysctl increase, so the coverage-preserving process partition is the recorded local gate.

## Decision Log

- Decision: Process PHP, Rust, and Scala in that order, publishing a clean language boundary before starting the next.
  Rationale: This is the user-requested order. A clean pushed checkpoint prevents one language's experimental edits from changing the next language's embedded Bifrost identity or corpus resume key.
  Date/Author: 2026-07-17 / Codex

- Decision: Run one language at a time with five repository jobs and twenty-four analyzer/audit workers per repository.
  Rationale: `--repo-jobs 5 --jobs 24` uses the host's 120 logical CPUs without deliberately oversubscribing across languages. It is the proven configuration from the immediately preceding top-five campaign and bounds aggregate memory better than launching all fifteen repositories together.
  Date/Author: 2026-07-17 / Codex

- Decision: Use persisted caches for full top-five records and ephemeral caches for one-off exact probes when a persisted rebuild is not intentionally required.
  Rationale: full records must be resumable and should exercise the production persisted analyzer path. Exact probes should not create unrelated cache state unless they are specifically validating an epoch or warmed-cache behavior.
  Date/Author: 2026-07-17 / Codex

- Decision: Treat only a valid forward identity plus a complete, non-truncated inverse query with no covering proven or unproven hit as a candidate product defect.
  Rationale: owner/receiver focus ranges, wrong forward targets, declaration roles, external boundaries, and explicit limits must not be “fixed” by teaching inverse lookup to agree with an invalid identity. The raw `missing` label is an audit lead, not the verdict.
  Date/Author: 2026-07-17 / Codex

- Decision: Delegate broad source inspection, clustering, reduced-boundary research, and substantial implementation to Oldskool while the root session retains all authority over GitHub, design acceptance, review, gates, commits, integration, and issue closure.
  Rationale: this follows the user's requested division of labor and preserves an independent review boundary around delegated work.
  Date/Author: 2026-07-17 / Codex

- Decision: Do not wait for GitHub CI after a language push.
  Rationale: the user explicitly made the complete local feature-enabled test suite the blocking gate and will report later CI regressions separately.
  Date/Author: 2026-07-17 / Codex

- Decision: Treat the Psalm `ArithmeticOpAnalyzer.php:754` row as a wrong-forward artifact covered by #890 and do not implement it in this campaign.
  Rationale: the semantic receiver is `TLiteralString`; making inverse lookup agree with the reported `TLiteralInt.value` would cement a false identity. The required branch-sensitive control-flow work is already assigned to another owner, and the campaign rule requires skipping such work.
  Date/Author: 2026-07-17 / Codex

- Decision: Track the six genuine PHP inverse misses in #904 and #905, both assigned to `jbellis` before implementation.
  Rationale: repository-wide open/closed issue searches found no duplicate for either concrete behavior. Keeping RHS evaluation order separate from scoped static-return inference gives each root a precise acceptance boundary and production witnesses.
  Date/Author: 2026-07-17 / Codex

- Decision: Accept Oldskool's PHP fix after independent structural review and preserve the shared static-scope resolver in the PHP syntax layer.
  Rationale: applying assignments after traversing their RHS follows PHP evaluation order in targeted and whole-workspace extraction, while resolving `self`, `static`, and `parent` from declaration structure avoids a second ad hoc namespace/type interpretation. Behavior tests cover reassignment, positive static factories, and the negative parent-owner boundary.
  Date/Author: 2026-07-17 / Codex

- Decision: Satisfy the full local gate by process partition instead of changing the host-wide inotify limit.
  Rationale: one-thread execution removes concurrent watcher pressure, and individually running all 43 excluded selector cases preserves the exact test surface. The approval layer rejected the global sysctl mutation, so no host configuration was changed.
  Date/Author: 2026-07-17 / Codex

## Outcomes & Retrospective

The campaign started from clean `origin/master` at `b0d6a31f`; the initial plan is committed locally at `4b61d137`. During the PHP run, `origin/master` advanced to merge `ab0af33f` with unrelated C++ changes. The PHP baseline is complete and exhaustively reconciled. The #904/#905 implementation and integration-candidate validation are complete: candidate artifacts `php-exact-904-cast-4b61d137-dirty.jsonl`, `php-exact-904-reconciler-4b61d137-dirty.jsonl`, `php-exact-904-symfony-descriptor-4b61d137-dirty.jsonl`, `php-exact-904-symfony-dump-4b61d137-dirty.jsonl`, `php-exact-905-function-call-4b61d137-dirty.jsonl`, and `php-exact-905-type-hint-4b61d137-dirty.jsonl` are actionable-zero. Commit, merge, repeated gates, publication approval, clean pushed-head proof, issue closure, and the final PHP summary remain outstanding. Rust and Scala have not run.

## Context and Orientation

Work from `/mnt/optane/tmp/bifrost-java-n10`. The worktree is detached by design. Repository rules forbid creating or switching branches, rebasing, or opening pull requests. Commits land on detached HEAD; before each push fetch current `origin/master` and merge it with `git merge --no-edit origin/master`, never rebase. Publish with `git push origin HEAD:master`. Stage only campaign files.

The differential engine lives in `src/reference_differential/mod.rs`; the command-line driver is `src/bin/bifrost_reference_differential.rs`. The driver reads corpus metadata below `/home/jonathan/Projects/brokkbench/sft-tools-commits`, validates clones below `/home/jonathan/Projects/brokkbench/clones` (a symlink to `/mnt/T9/repo-clones`), ranks valid clones by recorded `code_loc`, and appends one JSON object per completed repository. A record includes the Bifrost source head and dirtiness, target repository head and dirtiness, configuration fingerprint, sampled sites, forward results, inverse classifications, limits, errors, and timings.

`src/analyzer/usages/get_definition/` implements forward source-location resolution. `src/analyzer/usages/finder.rs` and the language graph modules under `src/analyzer/usages/` implement inverse usage resolution. Public symbols behavior is exercised through `SearchToolsService`, location/reference APIs, and the Python bindings where relevant. A `CodeUnit` is the stable declaration identity used to group a forward target; a `UsageHit` is an inverse result with path, byte range, kind, and proof strength. `consistent` means a proven inverse hit covers the sampled site. `unproven` means a covering best-effort hit exists without exact semantic proof. `inconclusive` covers missing/ambiguous/external forward identity, explicit limits, errors, and incompatible evidence. Only a complete inverse query with no covering proven or unproven hit is `missing`.

The deterministic selected repositories are:

PHP: `moodle__moodle` at `99f18504470cd3618d06820e7f5fe109a57d6636` (4,155,681 LOC), `magento__magento2` at `dd3a2bd7fbc8a7d3314c4ef4bbd94f75e117b913` (2,863,421), `vimeo__psalm` at `be7afcfe9d7f65301c32d4bc156efa31a6caa39f` (2,162,797), `edusoho__edusoho` at `ec046e7e6e9c0c8ef1ca97d90da4057a8a1b8505` (1,805,513), and `symfony__symfony` at `6e2a0fed44e0cbe6542924c69144c51682b2543a` (1,764,307).

Rust: `biomejs__gritql` at `c80b3026471b229f41b279c3eb0c162dcdacfdb1` (5,863,967 LOC), `swc-project__swc` at `a71c8eba7b0ef4280b8866cd8e6eebc5be10f0dc` (3,920,160), `servo__servo` at `2c39d765858aeb720a942471184828ed2b124eb7` (3,056,397), `rust-lang__rust` at `a1e52fc1cf67929a7c01ed9c037520e276ec98fd` (2,850,074), and `Wilfred__difftastic` at `49e5cff6b035431421709dc1f74363d8d14638b9` (2,667,051).

Scala: `JetBrains__intellij-scala` at `00bd317070498d433ce19f6279783a253402e2a3` (749,890 LOC), `scala__scala3` at `5d6ed42a24a1346e07523eac3e2cdff25211487e` (630,705), `getkyo__kyo` at `64db0fdbd904b1b9fb5ea119b0739e21fece3132` (574,333), `akka__akka-core` at `58f1f6db2e505e87f5dc115ee9476833872e7ae0` (535,567), and `scalatest__scalatest` at `866d7ab432e7f6a4eed2d4ebac63d5598c08a213` (448,417).

The prior N=1 plan `.agents/plans/reference-differential-corpus.md` records historical root causes and exact shapes. Use it only to choose preflight witnesses and recognize known non-defect categories. Do not transfer residual ledgers across a changed Bifrost head or repository sample without exact site-key, target, classification, and diagnostic equality.

## Plan of Work

First publish this plan as a clean checkpoint and rebuild the release runner so its embedded Git metadata matches the pushed head. For each language, run the deterministic five-repository corpus with five outer jobs, twenty-four inner jobs, persisted caches, a maximum of 1,000 files, 10,000 sites, 50,000 structured candidates per file, 4 MiB source files, 1,000 inverse target groups, 1,000 candidate files per inverse query, and 100,000 usage hits. Preserve stderr and `/usr/bin/time -v` output in an adjacent log, enable shell `pipefail`, and verify both exit status and exactly five completed JSONL records.

Exhaustively inspect every raw missing row. Cluster by exact forward target, source AST role, focus token, diagnostics, and inverse outcome, but retain a row-level ledger whose counts reconcile exactly to each repository summary. Use direct source bytes, tree-sitter/analyzer structures, public symbols probes, and exact `run-repo --path --start-byte --end-byte` reruns. Do not infer a product issue merely from name similarity or a missing inverse range.

For each legitimate root, search open and closed GitHub issues before filing. If a duplicate is assigned to anyone other than `jbellis`, document it and skip implementation. Otherwise create or reuse an issue assigned to `jbellis` before changing production code. Add a behavior-focused reduction using `tests/common/inline_project.rs` when possible and cover the public symbols surface affected by the defect. Delegate substantial root-cause research and implementation to Oldskool; independently review all changes for structured AST use, exact identity, scope, caps, stack safety, platform-independent paths, and hot-loop allocation behavior.

After focused tests pass, run formatting, diff checks, `cargo clippy --all-targets --all-features -- -D warnings`, and `UV_CACHE_DIR=/tmp/bifrost-uv-cache cargo test --features nlp,python`. Commit only campaign files with a multiline checkpoint message. Fetch and merge current `origin/master`; if it changes code, repeat all required gates on the merge. Push detached HEAD directly to `master` without waiting for CI.

Rebuild the release runner from the clean pushed fixing head. Repeat every exact production witness and the complete top-five corpus. Exhaustively audit any remaining raw missing rows or prove exact semantic equality with the already audited integration candidate. Only then post fixing heads, exact artifacts, corpus evidence, and gates to assigned issues and close them. Update this plan and `.agents/plans/reference-differential-corpus.md`, publish the plan-only checkpoint if needed, give the user the language summary, and immediately begin the next language.

## Concrete Steps

From `/mnt/optane/tmp/bifrost-java-n10`, publish the initial checkpoint and build the runner:

    git status --short
    git add .agents/plans/reference-differential-top-five-php-rust-scala.md
    git commit
    git fetch origin master
    git merge --no-edit origin/master
    git push origin HEAD:master
    cargo build --release --bin bifrost_reference_differential

For `LANG` equal to `php`, `rust`, or `scala`, and `HEAD8` equal to the clean pushed Bifrost head, use:

    set -o pipefail
    /usr/bin/time -v target/release/bifrost_reference_differential run-corpus \
      --clones-root /home/jonathan/Projects/brokkbench/clones \
      --commits-root /home/jonathan/Projects/brokkbench/sft-tools-commits \
      --language LANG \
      --repos-per-language 5 \
      --repo-jobs 5 \
      --jobs 24 \
      --cache-mode persisted \
      --max-files 1000 \
      --max-sites 10000 \
      --max-candidates-per-file 50000 \
      --max-source-bytes 4194304 \
      --max-targets 1000 \
      --max-usage-files 1000 \
      --max-usages 100000 \
      --seed 0 \
      --output /mnt/optane/tmp/reference-differential/LANG-top5-HEAD8.jsonl \
      2>&1 | tee /mnt/optane/tmp/reference-differential/LANG-top5-HEAD8.log

For an exact witness, use one file and an ephemeral cache unless the proof explicitly concerns persisted state:

    target/release/bifrost_reference_differential run-repo \
      --root /mnt/T9/repo-clones/SLUG \
      --language LANG \
      --output /mnt/optane/tmp/reference-differential/LANG-exact-ISSUE-HEAD8.jsonl \
      --jobs 24 --cache-mode ephemeral --force \
      --path RELATIVE_PATH --start-byte START --end-byte END

Before every code push, run and expect zero failures:

    cargo fmt --all -- --check
    git diff --check
    cargo clippy --all-targets --all-features -- -D warnings
    UV_CACHE_DIR=/tmp/bifrost-uv-cache cargo test --features nlp,python

Also run the affected language definition, targeted usage, whole-workspace graph, public SearchTools, and Python-binding tests selected by the changed surface. Record exact test targets and pass counts in `Progress`.

## Validation and Acceptance

A language is complete only when its definitive artifact contains exactly five `status=completed` records from the expected repository heads, every record names the same clean pushed Bifrost head with `bifrost_dirty=false`, and all configured limits and errors are interpreted honestly. Every raw missing row must appear in an exhaustive disjoint ledger. A genuine defect requires a valid forward identity, a complete inverse query, and no covering proven or unproven hit; unless it is explicitly skipped because an existing issue is assigned to another owner, it must have an issue assigned to `jbellis`, a structured root-cause fix, behavior-focused regression coverage, a clean exact production proof, and final corpus proof before closure. An owned skip remains in the ledger with the covering issue and assignee; it is never disguised as inverse parity.

The full campaign is complete only when PHP, Rust, and Scala each satisfy that language boundary; every legitimate issue is assigned to `jbellis`, fixed on `origin/master`, and closed with evidence; all three fixing heads are ancestors of final `origin/master`; the complete local feature-enabled gate passed after every code integration; both campaign plans describe current reality; and the worktree is clean. Do not use GitHub CI as a blocking gate.

## Idempotence and Recovery

`run-corpus` is append-only and resume-safe. Its completion key includes language, target repository/head, Bifrost head, and configuration fingerprint, so repeating an interrupted command without `--force` skips already completed semantic keys. Records may arrive in completion order; line order is not meaningful. Verify record count and producer exit status because a successful `tee` alone does not prove the runner succeeded.

Do not delete or reset corpus caches. Do not modify clone worktrees. If a process is interrupted, rerun the identical command. If a Bifrost fix changes the source head, use a new output filename and rebuild the release runner. Preserve unrelated worktree edits and stop for user direction only if they overlap files required by the campaign and cannot be safely separated.

## Artifacts and Notes

The durable artifact root is `/mnt/optane/tmp/reference-differential`. Keep each JSONL beside its `.log`. Exact filenames must include language, issue/root identifier, and the Bifrost short head. This ExecPlan is the canonical PHP/Rust/Scala top-five ledger; `.agents/plans/reference-differential-corpus.md` remains the cross-language historical campaign record and should receive concise milestone/closure entries.

Initial dry-run selection transcript:

    php   moodle__moodle, magento__magento2, vimeo__psalm, edusoho__edusoho, symfony__symfony
    rust  biomejs__gritql, swc-project__swc, servo__servo, rust-lang__rust, Wilfred__difftastic
    scala JetBrains__intellij-scala, scala__scala3, getkyo__kyo, akka__akka-core, scalatest__scalatest

## Interfaces and Dependencies

Do not add a second differential engine or a second cache. Reuse `reference_differential::run_reference_differential`, `WorkspaceAnalyzer`, `UsageFinder`, language-specific forward resolvers, language-specific usage graphs, the persisted `AnalyzerStore`, `InlineTestProject`, and existing public SearchTools/Python API fixtures. New resolver vocabulary must come from tree-sitter nodes and shared structured indexes; do not use regex, string splitting, substring scans, or delimiter mini-parsers in place of analyzer structure. Preserve configured usage/file/target caps and explicit `unproven`/`inconclusive` outcomes.

Revision note (2026-07-17): Created the self-contained PHP/Rust/Scala top-five campaign plan from clean `origin/master`, recorded deterministic selection and cache/disk preflight, and established the Oldskool/root division of labor and per-language acceptance workflow.

Revision note (2026-07-17): Recorded the exhaustive PHP baseline audit, assigned #904/#905, the reviewed Oldskool implementation, six actionable-zero integration-candidate production proofs, and the complete coverage-preserving local gate under the host inotify ceiling.
