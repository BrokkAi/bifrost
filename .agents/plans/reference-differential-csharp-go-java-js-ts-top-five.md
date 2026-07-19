# Complete the C#, Go, Java, JavaScript, and TypeScript top-five reference differential

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` current while the work proceeds. Maintain it in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost's forward-vs-inverse reference differential checks a public symbols invariant: when definition lookup resolves a source reference to a declaration group, the inverse usage query should recover the same source range. This campaign completes that audit for the five largest valid canonical local repositories in C#, Go, Java, JavaScript, and TypeScript.

The observable result is 25 accepted repository records. Java and Go already have authoritative completed top-five records whose raw findings were exhaustively reviewed and whose legitimate issues were fixed and closed. C#, JavaScript, and TypeScript require new uniform five-repository records. Every new raw `missing` site is checked against live source bytes, the tree-sitter role, forward identity, inverse limits, and an exact-site rerun. A legitimate defect receives a GitHub issue assigned to `jbellis` before implementation; an issue assigned to anybody else is recorded and skipped. Accepted fixes receive structured behavior tests, exact production evidence, formatting, all-target/all-feature Clippy, the complete `cargo test --features nlp,python` gate, direct integration to `origin/master`, and a clean final corpus confirmation. GitHub CI is not a blocking gate after local tests pass.

The acceptance surface is the MCP `symbols` toolset and its associated Rust and Python APIs. LSP shares analyzer implementation and remains covered by the full test suite, but editor-protocol behavior is not the focus.

## Progress

- [x] (2026-07-19 18:30Z) Reconciled the clean current worktree with `origin/master` at `b20da06f6ed1646289dc8bbd6ee9a6ca5b9fcc0d` and read `.agents/PLANS.md` plus the operator runbook at `/home/jonathan/Projects/bifrost/.agents/docs/reference-differential-runbook.md`.
- [x] (2026-07-19 18:35Z) Independently audited durable campaign evidence and GitHub state. Java has five accepted records at `431f1292`; Go has five accepted records at `20fec8af`; all campaign-created Java and Go issues are assigned to `jbellis` and closed.
- [x] (2026-07-19 18:38Z) Ran the current runner's no-write dry-run and pinned the canonical 25-repository selection. All 15 C#/JS/TS clone heads match corpus metadata and have no tracked dirtiness; no analyzer process owns a selected clone.
- [x] (2026-07-19 18:45Z) Committed the campaign-start plan as `127c5817`, locally excluded generated `.brokk/` state in all 15 selected C#/JS/TS clones, verified their tracked cleanliness, rebuilt the release runner, and recorded SHA-256 `4fcf6bf7c500906cb6ad1e845eac5a450e6b3a14608b22bd34ddcc8c3eb81edf`.
- [ ] Complete and integrity-check the C# top-five baseline, then exhaustively classify every raw missing row.
- [ ] File/assign, implement, review, test, and exact-prove every legitimate C# root cause not owned by another user.
- [ ] Complete the same baseline, disposition, issue, implementation, and proof lifecycle for JavaScript. Completed: all five `127c5817` records and the exhaustive 23-row baseline audit; filed assigned #942/#943; implemented and independently reviewed both fixes; exact-proved all three DevSpace witnesses cleanly at `9547d828`; dispositioned all six Node contract probes; reopened assigned #665 and created assigned #944; implemented and reviewed both Node fixes; passed the combined feature-enabled JS/public-service suites plus all-target/all-feature Clippy. Remaining: clean exact proof for #665/#944, clean full rerun, integration, and issue closure.
- [ ] Complete the same baseline, disposition, issue, implementation, and proof lifecycle for TypeScript.
- [ ] Run final local gates, integrate directly to `origin/master`, rebuild from the clean pushed head, rerun every affected top-five leg, close assigned issues with evidence, and publish compact checked-in reports.
- [ ] Perform a 25-repository completion audit against the authoritative artifacts, issue state, clean worktree, and remote master, then record the final retrospective.

## Surprises & Discoveries

- Observation: The canonical C#/JS/TS N=1 repositories have prior semantic coverage, but those records cannot substitute for uniform top-five evidence.
  Evidence: `.agents/docs/reference-differential/n1-summary.md` records Azure PowerShell, Node.js, and Kibana, but the original raw C# JSONL was lost and the three records do not share a current clean head/fingerprint with the remaining twelve repositories.

- Observation: Java and Go already meet the requested top-five acceptance boundary.
  Evidence: `/mnt/optane/tmp/reference-differential/java-top5-431f1292.jsonl` has five clean completed records and an exhaustive 601-row zero-genuine-residue review; `/mnt/optane/tmp/reference-differential/go-top5-20fec8af.jsonl` has five clean completed records and an exhaustive 1,114-row zero-genuine-residue review. The evidence and closed issue ledger are recorded in `.agents/plans/reference-differential-top-five-jgp.md`.

- Observation: Several nominally large JavaScript repositories are polyglot repositories with JavaScript corpus membership.
  Evidence: Canonical LOC ranking selects Kubernetes, KubeEdge, Karmada, and DevSpace after Node.js. This campaign preserves metadata-defined membership and ranking rather than replacing it with hand-picked JavaScript-heavy projects.

- Observation: One selected C# clone has generated cache state visible to Git.
  Evidence: `Azure__azure-powershell` reports only untracked `.brokk/`; the other 14 C#/JS/TS clones are clean. A local `.git/info/exclude` entry is required before accepted persisted-mode evidence.

- Observation: The first JavaScript five-repository record was semantically complete but failed the cleanliness gate for one empty-frontier repository.
  Evidence: `/mnt/optane/tmp/reference-differential/js-top5-127c5817.jsonl` has five completed pinned-head records, one fingerprint, no file errors, 11,609 total sampled sites, and 23 raw missing rows. Kubernetes reports `repo_dirty=true` solely because its newly generated `.brokk/` was not yet excluded; the local exclude now makes all five checkouts clean, so a fixing-head full rerun is required.

- Observation: Three canonical JavaScript top-five repositories have an empty current JavaScript frontier.
  Evidence: Kubernetes, KubeEdge, and Karmada each have zero tracked `.js`, `.jsx`, `.mjs`, or `.cjs` files at their pinned heads. The runbook and runner define top-N by language metadata membership, LOC rank, valid clone, and pinned head rather than by a nonempty current frontier. Their completed zero-site records are vacuous but contract-valid and must be disclosed rather than replaced with hand-picked repositories.

- Observation: DevSpace exposed two independent symbols defects despite auditing only 25 eligible JavaScript files.
  Evidence: `typeof Promise` forward-resolves to the same global property assigned as `window.Promise` but inverse lookup omits the bare read (#942). Two independent `module.exports` sites forward-resolve the CommonJS runtime host binding to an unrelated exported configuration property named `module` (#943). Both issues were created assigned to `jbellis` before implementation.

- Observation: A browser-global alias cannot be inferred from the declaration name alone.
  Evidence: Independent review of the first #942 draft found false-positive paths through local/imported `window`, later lexical `Promise` declarations (including TDZ and `var` hoisting), and a missing whole-graph edge for explicit `window.Promise`. The accepted implementation builds a shared tree-sitter lexical index only for files with exact same-file JavaScript `window.<one segment>` field/function candidates, validates the declaration receiver structurally, and covers both targeted and whole-graph paths.

- Observation: The clean fixing-head exact probes split the six unresolved Node rows into one forward and one inverse root.
  Evidence: At clean Bifrost `9547d828` and Node `2f2b81095bdc`, bare `foo()` and nested bare `pause()` incorrectly resolve to unrelated `__v_0.foo` and `Readable.prototype.pause`; four direct property reads correctly resolve to `node.quoteMark`, `node.operator`, `safer.kStringMaxLength`, and `meta.shortCircuited` but remain absent from complete inverse results. All six exact records are completed with both dirty flags false, one queried target, no truncation, and no file errors.

- Observation: Definition-lookup-only local properties are an intentional declaration boundary, not disposable symbols.
  Evidence: Plain-local member assignments and object-literal fields remain outside the public declaration graph to prevent arbitrary `obj.x` pollution, but bounded forward lookup retains their exact ranges and lexical receiver identity. #944 must recover direct same-binding reads without promoting those units into declarations or weakening the closed #386 boundary owned by another user.

## Decision Log

- Decision: Accept the completed Java and Go top-five legs as authoritative rather than rerunning them merely because later unrelated language work exists.
  Rationale: Each leg has exactly five clean completed records, a shared per-language fingerprint, exhaustive final residual dispositions, closed assigned issues, and complete local gates. They will be rerun only if new work changes shared behavior that can affect their evidence.
  Date/Author: 2026-07-19 / Codex

- Decision: Run complete uniform top-five legs for C#, JavaScript, and TypeScript, including their previously audited N=1 repository.
  Rationale: Mixing a historical single-repository summary with four current records would weaken provenance and fingerprint integrity. One five-record leg per language is straightforward, resumable, and auditable.
  Date/Author: 2026-07-19 / Codex

- Decision: Begin each new language with one active repository and eight inner workers in persisted cache mode; increase only outer concurrency after measuring memory and I/O headroom.
  Rationale: Azure PowerShell, Azure SDK, .NET runtime, Roslyn, Node.js, and Kibana are large workspaces. The runbook's conservative shape minimizes simultaneous cache and prepared-tree pressure while retaining resumability.
  Date/Author: 2026-07-19 / Codex

- Decision: Treat `missing` as triage input, not proof of a defect.
  Rationale: A ticket requires a semantically correct forward group, the actual referenced terminal, a complete inverse query, live clean source, exact reproduction, and a structured reduction. Qualifier focus, declaration roles, invalid forward identity, explicit limits, and parser recovery boundaries are not inverse defects.
  Date/Author: 2026-07-19 / Codex

- Decision: Root owns planning, source/identity adjudication, GitHub mutation, review, tests, integration, and closure; substantial research and implementation are delegated to Oldskool-compatible subagents when independent work exists.
  Rationale: This is the user's requested division of labor and preserves a single authority for issue ownership and acceptance.
  Date/Author: 2026-07-19 / Codex

- Decision: Do not implement an issue assigned to another user and do not wait for GitHub CI.
  Rationale: Both boundaries are explicit user instructions. Formatting, Clippy, focused tests, and `cargo test --features nlp,python` remain mandatory local gates.
  Date/Author: 2026-07-19 / Codex

- Decision: Retain canonical zero-frontier repositories in the JavaScript top five.
  Rationale: `run-corpus --repos-per-language 5` is the authoritative membership and ranking operation. Substituting the next repository with current JS files would silently change the contract to an unstated rule and contradict prior accepted polyglot corpus precedent.
  Date/Author: 2026-07-19 / Codex

- Decision: Reject the first #942 implementation until lexical `window`, hoisted/TDZ shadowing, explicit-member parity, and parent-lookup cost are covered.
  Rationale: Independent review found real false-positive and performance risks not exercised by the first parameter-shadow control. Focused green tests are evidence only for the cases they cover, not acceptance of a broader alias rule.
  Date/Author: 2026-07-19 / Codex

- Decision: Accept the revised #942 and narrow #943 implementations for fixing-head production proof.
  Rationale: #942 now gates all added indexing and parent lookup behind exact JavaScript browser-global candidates, rejects lexical receiver/property shadows, and preserves explicit-member parity. #943 follows assignment/member AST fields and retains explicit lexical CommonJS bindings and exported-property consumer resolution. The focused targeted suite passed 80 tests with two pre-existing ignores, the whole graph suite passed 21 tests, all-feature focused Clippy passed, and the feature-enabled JavaScript definition slice passed 23 tests.
  Date/Author: 2026-07-19 / Codex

- Decision: Reopen #665 for the Node bare-call forward regression and create #944 for direct reads of definition-only local properties.
  Rationale: #665 is the exact closed, unassigned lexical-precedence issue and was assigned solely to `jbellis` before reopening and renewed implementation. No exact duplicate exists for the #944 inverse boundary; the new issue was created assigned to `jbellis`. Closed #667 concerns alias propagation, while #386 is owned by another user and concerns over-declaration rather than inverse recovery.
  Date/Author: 2026-07-19 / Codex

- Decision: Accept the #665 and #944 implementations for clean production proof without promoting local properties into the declaration graph.
  Rationale: #665 recognizes hoisted function/generator/class declaration bindings and restricts bare same-file fallback to true bare declarations, preserving #942 only through exact unbound `window.<name>` validation. #944 mirrors forward lookup with a prior structured assignment/object-key range plus equal innermost lexical receiver scope. Its bounded location fallback runs only after ordinary declaration matching fails and accepts only exact same-file parentless fields absent from declarations. The root gate passed 503 definition, 151 public service, 25 JavaScript analyzer, 21 whole-graph, and 81 targeted usage tests (two existing ignores), plus formatting, diff checks, and all-target/all-feature Clippy.
  Date/Author: 2026-07-19 / Codex

## Outcomes & Retrospective

The evidence audit establishes 10 of the requested 25 accepted repository records before new execution: all five Java repositories at clean head `431f1292` and all five Go repositories at clean head `20fec8af`. Their legitimate issue families are closed and assigned to `jbellis`. The first JavaScript leg completed five records in 2m41s at 2.45 GiB peak RSS and found 23 raw rows: 20 reproduce the exact accepted Node N=1 sample, while three DevSpace rows reduce to assigned issues #942 and #943. Fourteen Node rows are declaration/frontier or wrong-forward artifacts, two are likely forward identity defects, and four require clean exact public-contract probes before final disposition. Both assigned DevSpace fixes have passed independent review and focused local gates, and all three production witnesses are cleanly exact-proven at `9547d828`: the Promise row is consistent and both CommonJS host rows now return the explicit `commonjs_host_binding` diagnostic. The six exact Node probes exposed two further assigned roots, #665 and #944. Both now have structured, reviewed implementations and broad local green coverage; clean production exacts and the full fixing-head JS leg remain outstanding. C#, TypeScript, final JavaScript confirmation, issue closures, and master integration remain incomplete.

## Context and Orientation

Work in `/mnt/optane/tmp/bifrost-burndown-3` on the existing branch `bifrost-burndown-3`. Do not create or switch branches, rebase, or open a pull request. Commit only campaign files on the current branch. At the final publication boundary fetch `origin/master`, merge it with `git merge --no-edit origin/master` if needed, never rebase, and push the integrated `HEAD` directly to `origin/master`.

The operator runbook is `/home/jonathan/Projects/bifrost/.agents/docs/reference-differential-runbook.md`. The CLI driver is `src/bin/bifrost_reference_differential.rs`; the engine and report schema are `src/reference_differential/mod.rs`. `run-corpus` appends one repository JSON object after a repository finishes. Its completion key includes language, repository slug and head, Bifrost head, and a semantic configuration fingerprint. `--repo-jobs` bounds active repositories and `--jobs` bounds analyzer and forward/inverse work inside each repository.

Canonical corpus metadata lives in `/home/jonathan/Projects/brokkbench/sft-tools-commits`. Language membership comes from `<language>/*.jsonl`; ranking comes from `repos.csv::code_loc`; clone paths under `/home/jonathan/Projects/brokkbench/clones` resolve to `/mnt/T9/repo-clones`. Missing clones and invalid LOC entries are reported and skipped before selecting five valid repositories.

The selected C# repositories are Azure PowerShell at `409b39eb8c26`, Azure SDK for .NET at `a54cb128cf3d`, Mono at `0f53e9e151d9`, .NET runtime at `a0311b3485a8`, and Roslyn at `f219cabdd558`. The selected JavaScript repositories are Node.js at `2f2b81095bdc`, Kubernetes at `d7eae6c8fded`, KubeEdge at `de82fd3ed95c`, Karmada at `ffbade988fc3`, and DevSpace at `8ff6260787ed`. The selected TypeScript repositories are Kibana at `3a186638c45f`, Eliza at `03f8dcdcf9d0`, KEDA at `875675ce5cd1`, NativeScript at `d41dcd7a93b0`, and OpenMetadata at `5e31ae5871a3`.

The accepted Java record is `/mnt/optane/tmp/reference-differential/java-top5-431f1292.jsonl`; the accepted Go record is `/mnt/optane/tmp/reference-differential/go-top5-20fec8af.jsonl`. Their selection, raw-row review, fixes, tests, and issue closures are documented in `.agents/plans/reference-differential-top-five-jgp.md`. That plan is prior evidence, while this file is the authoritative plan for completing the requested five-language matrix.

Open CFG/ICFG issues #886, #887, and #889 are assigned to another user and are outside the symbols scope. Open issue #895 concerns Java outer-type qualifier usages and is currently unassigned; reuse it only if a new matching production witness exists, and assign it to `jbellis` before any implementation.

## Plan of Work

First commit this plan so the worktree is clean. Add `.brokk/` to the Azure PowerShell clone's local `.git/info/exclude`, verify all selected tracked heads and cleanliness, build the release runner from that exact Bifrost head, and record `sha256sum target/release/bifrost_reference_differential`. Do not mutate Bifrost source or selected clone content while a corpus process is active, because revision and dirtiness metadata are read dynamically.

Run C#, JavaScript, and TypeScript sequentially as independent resumable corpus processes. Each uses five canonical repositories, one active repository, eight inner workers, persisted cache mode, strict reporting, 1,000 sampled files, 10,000 sites, 50,000 candidates per file, 4 MiB source files, 1,000 inverse target groups, 1,000 usage files per target, 100,000 hits per target, and seed zero. Preserve head-scoped JSONL and logs under `/mnt/optane/tmp/reference-differential`. A strict exit status of two is expected when raw missing sites exist; accepted evidence requires five completed JSON objects.

After each baseline, verify JSON parsing, exact Bifrost and pinned repository heads, clean flags, one fingerprint, completed status, summary limits, and file errors. Extract every raw `missing` site to a stable ledger keyed by repository, path, byte range, and target declarations. Delegate disjoint read-only source partitions, while root verifies the focused bytes and exact tree-sitter role and adjudicates every disposition.

Exact-rerun suspicious sites against the same clone head. A surviving defect needs a behavior-focused `InlineTestProject` reduction. Put forward identity bugs in definition tests, targeted inverse bugs in language usage-graph tests, whole-workspace parity bugs in inverted graph tests, and public surface changes in symbols-service and Python API coverage as appropriate. Include negative controls for owners, module/package identity, aliases, arity, receiver type, inheritance, lexical shadowing/rebinding, duplicate declarations, JSX/TSX boundaries, generated declarations, and external imports as relevant. Use tree-sitter nodes and analyzer graph structures; never replace structured support with regex, substring search, delimiter splitting, or a source-text mini-parser.

Only after a faithful reduction fails should root search open and closed GitHub issues, inspect assignees, and mutate issue state. Reuse an unassigned issue only after assigning it solely to `jbellis`; otherwise create a new issue already assigned to `jbellis`. If a duplicate is assigned to another user, record and skip it. Delegate substantial implementation with the issue and failing behavior as the contract. Root reviews every diff, rejects text-scanning shortcuts or broad ambiguous candidate amplification, adds missing controls, and runs focused tests. Dirty-tree exact probes are provisional.

When a language has no unclassified genuine sites, run formatting, all-target/all-feature Clippy, affected focused suites, and `UV_CACHE_DIR=/tmp/bifrost-uv-cache cargo test --features nlp,python`. Commit only relevant files with a multiline why-oriented message. Continue directly to the next language without waiting for CI.

At final integration, fetch and merge current `origin/master` into the current branch if needed, repeat proportionate local gates, and push the integrated `HEAD` directly to `origin/master`. Rebuild the runner from the exact clean pushed head and rerun every C#/JS/TS leg affected by accepted changes. If common analyzer code could affect Java or Go, rerun those affected legs too. Exhaustively classify all final residuals, comment on and close assigned issues with the fixing commit and production evidence, check in compact manifests and summaries, and verify the worktree is clean and local HEAD, `origin/master`, and remote master agree.

## Concrete Steps

From `/mnt/optane/tmp/bifrost-burndown-3`, build the frozen runner after the plan checkpoint:

    git status --short
    git rev-parse HEAD
    cargo build --release --bin bifrost_reference_differential
    sha256sum target/release/bifrost_reference_differential

The C# command is:

    set -o pipefail
    /usr/bin/time -v target/release/bifrost_reference_differential run-corpus \
      --clones-root /home/jonathan/Projects/brokkbench/clones \
      --commits-root /home/jonathan/Projects/brokkbench/sft-tools-commits \
      --language csharp --repos-per-language 5 --repo-jobs 1 --jobs 8 \
      --cache-mode persisted --strict \
      --max-files 1000 --max-sites 10000 \
      --max-candidates-per-file 50000 --max-source-bytes 4194304 \
      --max-targets 1000 --max-usage-files 1000 --max-usages 100000 \
      --seed 0 \
      --output /mnt/optane/tmp/reference-differential/csharp-top5-BIFROST_HEAD.jsonl \
      2>&1 | tee -a /mnt/optane/tmp/reference-differential/csharp-top5-BIFROST_HEAD.log

Repeat with `--language js` and `js-top5-BIFROST_HEAD` for JavaScript, then `--language ts` and `ts-top5-BIFROST_HEAD` for TypeScript. Do not use `--include-tests`. Do not use `--force` unless an existing record for the same semantic completion key is proven invalid. Resume an interrupted run by confirming no process owns a selected clone and repeating the identical command without `--force`.

Extract structured repository summaries and raw rows with:

    jq -c 'select(.record_type == "repository") | {repo_slug,repo_head,bifrost_head,bifrost_dirty,repo_dirty,status,elapsed_seconds,summary:.report.summary,file_errors:.report.file_errors}' FILE.jsonl

    jq -c 'select(.record_type == "repository") as $r | $r.report.sites[] | select(.classification == "missing") | {repo_slug:$r.repo_slug,path,start_byte,end_byte,line,text,source_evidence,targets,note,diagnostics}' FILE.jsonl

Before integration, run at minimum:

    cargo fmt --all -- --check
    cargo clippy --all-targets --all-features -- -D warnings
    UV_CACHE_DIR=/tmp/bifrost-uv-cache cargo test --features nlp,python --test get_definition_test
    UV_CACHE_DIR=/tmp/bifrost-uv-cache cargo test --features nlp,python

Also run the actual C#, JavaScript, and TypeScript targeted and whole-workspace usage test binaries found under `tests/`; never silently omit equivalent coverage because a guessed target name differs.

## Validation and Acceptance

A language leg is valid only when exactly five selected repositories have completed records for one exact clean Bifrost head and configuration, both dirtiness flags are false, every repository head matches metadata, JSON parses, and every engine/file error or explicit limit is accounted for. A strict exit of two is acceptable only after all records are durable.

A fixed defect is accepted only with a pre-fix failing structured behavior reduction, compliant issue ownership, focused green tests, root review, and an exact clean production rerun. A covering inverse hit must include the original byte range for the intended declaration identity. Honest `no_definition`, `unproven`, or `inconclusive` is acceptable only when the former comparison was semantically invalid or incomplete.

The campaign is complete only when all 25 requested repositories have accepted evidence, every final raw missing row has an explicit reviewed disposition, zero legitimate unowned in-scope defects remain, every worked issue was assigned to `jbellis` before implementation and is closed with evidence, formatting and all-target/all-feature Clippy pass, the complete `cargo test --features nlp,python` suite passes, compact reports are checked in, and the clean integrated worktree plus local and remote master agree. CI is deliberately not awaited.

## Idempotence and Recovery

`run-corpus` is append-only and resume-safe. Repeating an unchanged command without `--force` skips completed semantic keys and reruns incomplete repositories. Preserve partial JSONL and logs; record order is completion order and has no semantic meaning. Never truncate accepted evidence or delete `.brokk` to retry.

If a process stops, verify no differential/analyzer process still owns the clone, inspect the terminal log, and repeat the exact command. Retain cache databases when diagnosing migrations or epochs. If Bifrost source changes while a process is active, stop and rerun from a new clean checkpoint because the executable and dynamically reported revision can diverge. Research agents may inspect source during a run but must not mutate Bifrost or selected clones.

## Artifacts and Notes

Raw evidence and logs live under `/mnt/optane/tmp/reference-differential/` with `csharp-top5-<head>`, `js-top5-<head>`, and `ts-top5-<head>` prefixes. Derived exhaustive ledgers should use `-missing-ledger.{jsonl,tsv,sha256}` and summaries should preserve artifact checksums. Raw multi-megabyte site payloads and analyzer logs are not committed.

The durable repository deliverables are this plan, `.agents/docs/reference-differential/top5-csharp-js-ts.jsonl`, and `.agents/docs/reference-differential/top5-csharp-js-ts-summary.md`. The compact manifest must pin Bifrost and repository heads, configuration fingerprints, summary counters, elapsed time, file errors, ledger checksums, issue ledger, and raw artifact paths.

## Interfaces and Dependencies

No production interface change is planned in advance. Preserve the existing differential CLI, append-only JSONL schema, stable declaration identity, and public symbols contract. Fixes belong in existing structured analyzers and resolvers, with small project coverage using `tests/common/inline_project.rs::InlineTestProject`.

C# uses the C# tree-sitter analyzer; JavaScript and TypeScript have distinct language frontiers but share substantial ECMAScript resolution and usage machinery. Declaration-emission or identity changes may require a language-local analysis epoch bump so persisted caches cannot retain stale facts. Avoid new dependencies, persistence schemas, or public API shapes unless a reduced production root cause requires them and this plan records the decision.

Revision note (2026-07-19 18:40Z): Created this self-contained five-language completion plan after auditing accepted Java/Go evidence and issue state, pinning all 25 canonical repositories, proving the remaining 15 C#/JS/TS clone heads and tracked cleanliness, and recording the user's issue-assignment, delegation, symbols-scope, local-test, no-CI-wait, direct-master, exhaustive-triage, and final-confirmation boundaries before analyzer mutation.

Revision note (2026-07-19 19:25Z): Recorded the published clean campaign checkpoint and runner checksum, the five-record JavaScript baseline and its single invalid dirtiness flag, the canonical zero-frontier decision, exhaustive 23-row partition, assigned #942/#943 defects, clone-local cache exclusions, and the independent review controls required before accepting #942.

Revision note (2026-07-19 20:10Z): Recorded acceptance of the revised candidate-gated #942 browser-global implementation and narrow #943 CommonJS host-binding correction after independent review, structured shadowing/parity controls, focused targeted and whole-graph suites, focused all-feature Clippy, feature-enabled JavaScript definition tests, formatting, and diff checks.

Revision note (2026-07-19 20:45Z): Recorded clean `9547d828` exact proof for #942/#943, the six Node exact-probe dispositions, assigned/reopened #665, newly assigned #944, and the requirement to preserve definition-only local-property identity without reopening the over-declaration boundary owned in #386.

Revision note (2026-07-19 21:30Z): Recorded acceptance of the structured #665 lexical-precedence correction and #944 lookup-only local-property inverse/location path after independent implementation, root review, combined feature-enabled public/analyzer regressions, formatting, diff checks, and all-target/all-feature Clippy.
