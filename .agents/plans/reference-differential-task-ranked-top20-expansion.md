# Expand the task-ranked reference differential with repositories eleven through twenty

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`,
`Decision Log`, and `Outcomes & Retrospective` current while work proceeds.
Maintain it in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost's public MCP `symbols` tools and the associated Rust and Python APIs
provide both forward definition lookup and inverse reference lookup. When a
source reference resolves forward to a workspace declaration group, a complete
inverse query for that declaration should recover the same exact source range.
The task-ranked campaigns through repository rank ten are already complete for
all eleven languages recognized by `/home/jonathan/Projects/brokkbench/tasks.py`.
This distinct campaign audits ranks eleven through twenty, adding ten new
repositories per language and 110 new completed repository envelopes.

Repository membership comes only from
`tasks.task_repos(tasks.SFT_PREDICATES, langs=[LANG])`, followed by a stable
descending `task_count` sort that preserves the selector's order for ties and
slice `[10:20]`. `SFT_PREDICATES.not_overlarge` is true, so this path applies
the required `large-repos.csv` exclusion as well as build, testsome, binding,
generated-prompt, non-fragile-test, and skip gates. The runner receives every
selected slug explicitly. Its `--repos-per-language` option ranks by code size
and cannot select this task-ranked corpus.

Work is language-depth-first and, within each language, repository-depth-first.
For repository X, run its baseline, triage every raw `missing` row, search the
issue tracker, and assign every legitimate unowned root cause to `jbellis`
before editing product code. Fix, test, push, replay, and close all owned issues
for X before running repository Y. An issue assigned to somebody else is
recorded and skipped. A language-wide selector dry-run and final certification
are allowed because they create no tickets and do not defer a repository's
triage. Oldskool agents may audit independent rows or implement disjoint owned
fixes within the one active repository, but root owns selection, planning,
review, git integration, publication, and closure.

The observable final result is 110 completed clean repository envelopes with
every raw residual exhaustively dispositioned and zero actionable discrepancy
left in owned scope. Each finished language receives a compact manifest and
narrative summary under `.agents/docs/reference-differential/` and an immediate
user summary. Every legitimate owned issue is closed only after clean pushed-
head production evidence. The final campaign manifest pins all repository and
Bifrost heads, run fingerprints, counters, residual ledgers, checksums, issue
states, and raw artifact provenance. Large scratch artifacts live only under
`/mnt/optane/tmp/bifrost-fird/` and are removed after their compact evidence is
published. LSP shares analyzer code and comes through local tests, but it is not
the focus.

## Progress

- [x] (2026-08-01 05:21Z) Reconciled a clean `bifrost-fird` worktree with
  `origin/master` at `cfa73404`, confirmed the dedicated Optane scratch
  directory is empty, and read all of `.agents/PLANS.md` and
  `.agents/docs/reference-differential-runbook.md`.
- [x] (2026-08-01 05:21Z) Recomputed all eleven rank-eleven-through-twenty
  selections through the live `SFT_PREDICATES` path and confirmed
  `not_overlarge=true`. The 110 exact ranks and task counts are recorded below.
- [x] (2026-08-01 05:21Z) Delegated independent Oldskool reviews of the full
  selector, the campaign method, and the C preflight. No product edits or
  cross-language baseline work were delegated.
- [x] (2026-08-01 05:34Z) Independently verified all 110 selector rows: every
  selected slug is outside `large-repos.csv`, exists as a canonical clone, and
  has zero tracked modifications. The selector, exclusion, and repository CSV
  SHA-256 values are recorded below. Generated untracked `.bifrost/`/`.brokk/`
  state will be ignored through clone-local metadata as each language becomes
  active, without deleting warm caches.
- [x] (2026-08-01 05:34Z) Verified all ten C clone HEADs against their pinned
  corpus sidecars and found no tracked source changes. Three clones are already
  clean and seven contain only untracked `.bifrost/analyzer.db` state.
- [ ] Verify the remaining active-language pinned clone heads and corpus inputs,
  and complete the eleven explicit runner dry-runs.
- [ ] Complete C ranks eleven through twenty and publish its evidence and user
  summary.
- [ ] Complete C++ ranks eleven through twenty and publish its evidence and
  user summary.
- [ ] Complete C# ranks eleven through twenty and publish its evidence and user
  summary.
- [ ] Complete Go ranks eleven through twenty and publish its evidence and user
  summary.
- [ ] Complete Java ranks eleven through twenty and publish its evidence and
  user summary.
- [ ] Complete JavaScript ranks eleven through twenty and publish its evidence
  and user summary.
- [ ] Complete PHP ranks eleven through twenty and publish its evidence and
  user summary.
- [ ] Complete Python ranks eleven through twenty and publish its evidence and
  user summary.
- [ ] Complete Rust ranks eleven through twenty and publish its evidence and
  user summary.
- [ ] Complete Scala ranks eleven through twenty and publish its evidence and
  user summary.
- [ ] Complete TypeScript ranks eleven through twenty and publish its evidence
  and user summary.
- [ ] Publish the 110-envelope campaign manifest, run the final comprehensive
  local gate, prove all fixing history is on final `origin/master`, re-audit
  issue ownership/state, and remove the campaign scratch outputs.

## Surprises & Discoveries

- Observation: `task_repos` does not itself return exact task-count order.
  Evidence: its `_select` helper ranks by task-count band, build time, and slug;
  this campaign therefore applies a stable exact descending `task_count` sort
  before taking `[10:20]`, matching the completed task-ranked campaigns.

- Observation: language membership is corpus membership, not a guess from the
  repository's primary implementation language.
  Evidence: C ranks include `sudo-rs`, Byte Buddy, and LMCache, while C++ ranks
  include cJSON; these are live selector results and must not be silently
  replaced because a repository name suggests another language.

- Observation: 101 of the 110 selected clones contain only untracked generated
  analyzer state, while all 110 have zero tracked modifications.
  Evidence: independent `git status --porcelain --untracked-files=all` checks
  found `.bifrost/` in 100 clones, `.brokk/` in 15 clones, and one unrelated
  untracked script in `Textualize__rich`. Generated cache directories must be
  clone-locally ignored rather than deleted; unrelated untracked files remain
  visible and must be dispositioned before accepting that repository.

## Decision Log

- Decision: Treat this as a new ranks-eleven-through-twenty expansion rather
  than rerunning or reclassifying the completed top ten.
  Rationale: The user explicitly preserved the top-ten result and requested
  the next ten repositories. Completion therefore requires exactly 110 new
  envelopes selected from slice `[10:20]`.
  Date/Author: 2026-08-01 / root.

- Decision: Use language-depth-first ordering `c`, `cpp`, `csharp`, `go`,
  `java`, `js`, `php`, `py`, `rust`, `scala`, `ts`.
  Rationale: This is `tasks.DEFAULT_LANGUAGES` order and satisfies the user's
  explicit requirement to finish issue creation and fixes for language A
  before proceeding to language B. Parallel work is restricted to independent
  repositories, residual audits, or disjoint fixes within the active language.
  Date/Author: 2026-08-01 / root.

- Decision: Within the active language, complete one repository through clean
  replay and issue closure before beginning the next repository.
  Rationale: The user prefers depth-first closure at repository granularity.
  This prevents speculative ticket batching and keeps each baseline, triage,
  fix, pushed witness, and closure as one auditable transition. Only read-only
  selector dry-runs and the final ten-repository language certification span
  multiple repositories.
  Date/Author: 2026-08-01 / root.

- Decision: Run Cargo and Bifrost outside the restricted sandbox at niceness
  10, using normal repository Cargo caches and targets.
  Rationale: The user and repository instructions explicitly prohibit moving
  Cargo targets or shared build caches into `/tmp`. The runbook's historical
  isolated-target and `/tmp` cache examples are superseded for this campaign.
  Date/Author: 2026-08-01 / root.

- Decision: Use persisted clone caches for resumable language corpus runs and
  ephemeral cache mode for one-site probes.
  Rationale: This matches the runbook, preserves expensive workspace work
  across interruptions, and avoids mutating accepted cache state for exact
  smoke probes.
  Date/Author: 2026-08-01 / root.

## Outcomes & Retrospective

The expansion is in progress. The exact 110-repository scope has been derived
from the live filtered selector, but no rank-eleven-through-twenty repository
envelope is accepted until the preflight, clean baseline, exhaustive residual
audit, and language closure process below prove it.

## Context and Orientation

The runner executable is `src/bin/bifrost_reference_differential.rs`; its
engine and JSON report schema are in `src/reference_differential/mod.rs`. The
operator runbook is `.agents/docs/reference-differential-runbook.md`. The prior
expansion plan is
`.agents/plans/reference-differential-task-ranked-top10-expansion.md`, and the
top-ten campaign summary and manifest are
`.agents/docs/reference-differential/task-ranks6-10-final-summary.md` and
`.agents/docs/reference-differential/task-ranks6-10-final-manifest.jsonl`.
Those checked-in artifacts are historical evidence and issue-family guidance;
they do not substitute for any new envelope.

The canonical clone root is
`/home/jonathan/Projects/brokkbench/clones`, a symlink to the installed corpus.
Pinned corpus metadata is under
`/home/jonathan/Projects/brokkbench/sft-tools-commits`. The exact selector code
is `/home/jonathan/Projects/brokkbench/tasks.py`. A repository envelope is the
one completed JSON object the corpus runner appends after auditing a repository.
A raw `missing` row means forward lookup found a declaration group but inverse
lookup did not return the original range; it is a triage input, not proof of a
defect. A legitimate defect requires correct forward identity, a complete
inverse query, the actual reference token, exact-site reproduction, and no
limit or file error that invalidates the comparison.

The selection inputs for this campaign are pinned by SHA-256:

    tasks.py:         3aae9889b13266592ecd022a00ac022cbf17eec70131454d0fa2bdb88f2642f3
    large-repos.csv:  4ebc9abc75e7fea6a7742cfb6081e3937421f4cd8c48a35ed88ce2f5d40876e8
    repos.csv:        eff8be3980c76086b0b6dec624f2954751bbb046d8aebf0a5522b0ba5e101434

The new selection has zero same-language overlap with the committed ranks
six-through-ten manifest, and every one of its 110 records is outside the live
large-repository exclusion set. Regenerate the live selection immediately
before each language begins; if these inputs or its rank slice change, update
the plan and manifest rather than silently using a stale snapshot.

The exact selected ranks are:

    c: 11 24 trifectatechfoundation__sudo-rs; 12 24 raphw__byte-buddy;
      13 24 LMCache__LMCache; 14 23 DaveGamble__cJSON;
      15 23 unicorn-engine__unicorn; 16 22 igraph__igraph;
      17 20 libuv__libuv; 18 19 Mbed-TLS__mbedtls;
      19 19 ClusterLabs__pacemaker; 20 18 getvictor__fleet-edr.

    cpp: 11 20 libarchive__libarchive; 12 19 DaveGamble__cJSON;
      13 19 open62541__open62541; 14 18 google__wuffs;
      15 18 BehaviorTree__BehaviorTree.CPP;
      16 17 GoogleCloudPlatform__esp-v2; 17 16 abseil__abseil-cpp;
      18 16 Mbed-TLS__mbedtls; 19 13 pyro-ppl__pyro;
      20 13 cppcheck-opensource__cppcheck.

    csharp: 11 33 NLog__NLog; 12 32 openbullet__OpenBullet2;
      13 31 ThreeMammals__Ocelot; 14 28 commandlineparser__commandline;
      15 28 sebastienros__jint; 16 28 qdraw__starsky; 17 27 nunit__nunit;
      18 27 MudBlazor__MudBlazor; 19 26 xoofx__markdig;
      20 26 cyanfish__naps2.

    go: 11 168 gofiber__fiber; 12 159 jaegertracing__jaeger;
      13 140 pb33f__libopenapi; 14 124 aquasecurity__trivy;
      15 123 zeromicro__go-zero; 16 109 google__go-github;
      17 98 IBM__sarama; 18 94 linkerd__linkerd2;
      19 92 syncthing__syncthing; 20 90 labstack__echo.

    java: 11 47 FasterXML__jackson; 12 44 alibaba__fastjson;
      13 40 google__gson; 14 39 apache__pdfbox;
      15 36 graphhopper__graphhopper; 16 33 swagger-api__swagger-core;
      17 28 apache__poi; 18 25 TNG__ArchUnit;
      19 25 apache__felix-dev; 20 23 spring-projects__spring-security.

    js: 11 39 WeblateOrg__weblate; 12 38 TheAlgorithms__JavaScript;
      13 37 roseteromeo56-cb-id__go-ethereum;
      14 37 aws-powertools__powertools-lambda-typescript;
      15 36 mui__base-ui; 16 32 bigskysoftware__htmx;
      17 30 yarnpkg__yarn; 18 30 AndreaB2000__ASW-project;
      19 30 IBM__CRAIG; 20 28 AlaSQL__alasql.

    php: 11 44 api-platform__core; 12 42 composer__composer;
      13 40 symfony__http-kernel; 14 38 symfony__console;
      15 34 bobthecow__psysh; 16 30 Seldaek__monolog;
      17 29 coollabsio__coolify; 18 29 archtechx__tenancy;
      19 28 briannesbitt__Carbon; 20 26 nikic__PHP-Parser.

    py: 11 49 django__django; 12 48 prometheus__prometheus;
      13 47 gaphor__gaphor; 14 46 freqtrade__freqtrade;
      15 44 aaugustin__websockets; 16 44 quodlibet__mutagen;
      17 43 langchain-ai__langchain; 18 39 getsentry__sentry-python;
      19 36 mesa__mesa; 20 34 Textualize__rich.

    rust: 11 21 godot-rust__gdext; 12 20 uutils__coreutils;
      13 17 askama-rs__askama; 14 13 rayon-rs__rayon;
      15 12 casey__just; 16 11 PyO3__pyo3;
      17 10 neon-bindings__neon; 18 9 rust-lang__rust-analyzer;
      19 9 linkerd__linkerd2; 20 8 Geal__nom.

    scala: 11 35 awslabs__deequ; 12 35 wvlet__airframe;
      13 32 chipsalliance__chisel; 14 31 twitter__util;
      15 29 simerplaha__SwayDB; 16 29 apalache-mc__apalache;
      17 27 sangria-graphql__sangria; 18 27 TheHive-Project__TheHive;
      19 25 laurilehmijoki__s3_website; 20 25 typelevel__doobie.

    ts: 11 30 nestjs__nest; 12 29 vuejs__vue; 13 28 strapi__strapi;
      14 21 appwrite__appwrite; 15 21 fastify__fastify;
      16 21 motiondivision__motion;
      17 17 globaleaks__globaleaks-whistleblowing-software;
      18 14 aws-powertools__powertools-lambda-typescript;
      19 12 trpc__trpc; 20 11 outline__outline.

Each tuple is `rank task_count repo_slug`. Ties retain the order returned by
`task_repos`; do not replace that order with slug sorting.

## Plan of Work

First independently verify the live selector and corpus installation. For each
language, record the ten explicit slugs, task counts, pinned metadata commit,
clone HEAD, tracked cleanliness, and presence of the canonical corpus JSONL and
testsome sidecar. Build the release runner from a clean published Bifrost head,
record its SHA-256, and run eleven separate `run-corpus --dry-run` invocations
with explicit slugs. Each dry-run must return exactly the expected ten records.

Then process languages strictly in the Decision Log order. Freeze the clean
published Bifrost head and process the active language's repositories serially
in rank order. Run repository X alone into a head-scoped artifact, fully triage
it, handle its issues, replay it cleanly, and close its owned issues before
starting repository Y. Do not use repository concurrency for these transitions.
Preserve one completed record for each selected clone, with clean heads, one
intended fingerprint, no invalid file/candidate exclusions, and complete
accounting of target caps.

Extract every raw `missing` row for the one active repository to a checksummed
audit ledger. For each row,
inspect the live bytes and tree-sitter role, verify forward target identity and
inverse completeness, run an exact ephemeral probe, and search open and closed
issues for the root-cause family. Group only structurally proven shared causes.
Create or reuse issues only for legitimate root causes found in that active
repository. Assignment to `jbellis` must be visible before any code edit; an
issue assigned to another user is recorded and skipped. Do not pre-file issues
for a later repository.

Implement owned fixes only for the active language. Use structured analyzer
data: tree-sitter fields, declaration ranges, import binders, visibility
indexes, type facts, and usage graphs. Do not add regex, substring, delimiter-
splitting, source-text scanning, or mini-parser fallbacks. Small fixtures use
`tests/common/inline_project.rs::InlineTestProject`; public behavior coverage
belongs in the consolidated test suites named by repository instructions.
Oldskool workers receive disjoint file or root-cause ownership and must not
revert other edits. Root reviews every diff and owns integration.

For each fix, run focused regressions and a local featureless `cargo test`
outside the sandbox at niceness 10. Fetch and merge current `origin/master`
without changing branches or rebasing, commit only owned files, push directly
to `origin/master`, rebuild the release runner, and replay the exact production
witness or affected repository on that pushed head. Close the assigned issue
only after that clean proof. Continue until every owned active-language issue
is closed or every externally owned issue is explicitly skipped.

At language closure, rebuild from the final clean pushed head and run all ten
repositories into new head-scoped JSONL and log files. Exhaustively audit every
final residual rather than subtracting baseline rows. Publish a compact
language manifest, residual ledger checksum, and narrative summary under
`.agents/docs/reference-differential/`; commit and push them, verify the issue
set, and give the user the language summary before starting the next language.

After eleven languages, assemble one compact campaign manifest containing 110
rank records and aggregate counters. Run formatting, strict all-target/all-
feature Clippy, focused affected tests, and the comprehensive
`uv run --python 3.12 -- cargo test --features nlp,python` gate outside the
sandbox at niceness 10 with `BIFROST_SEMANTIC_INDEX=off` and normal Cargo/uv
storage. Reconcile any concurrent `origin/master` changes, prove
every fixing head is ancestral, and verify local HEAD, local `origin/master`,
and remote `refs/heads/master` are identical. Re-audit all campaign issues for
assignment and closed state. Only after compact evidence is pushed, inventory
and remove the contents of `/mnt/optane/tmp/bifrost-fird/`.

## Concrete Steps

All commands use `/mnt/optane/bifrost-fird` as the working directory unless a
different path is explicit. Cargo, Bifrost, GitHub CLI, and networked Git
commands run outside the restricted sandbox. Every Cargo and Bifrost command
is prefixed with `nice -n 10`. Do not set `CARGO_TARGET_DIR`, `CARGO_HOME`,
`UV_CACHE_DIR`, or another build/cache path under `/tmp`.

Recompute one language selection with:

    PYTHONDONTWRITEBYTECODE=1 python3 -c '
    import sys
    sys.path.insert(0, "/home/jonathan/Projects/brokkbench")
    import tasks
    rows = tasks.task_repos(tasks.SFT_PREDICATES, langs=["c"])
    print(sorted(rows, key=lambda row: -row.task_count)[10:20])'

Build and identify the runner with:

    nice -n 10 cargo build --release --bin bifrost_reference_differential
    git rev-parse HEAD
    sha256sum target/release/bifrost_reference_differential

The C language-wide dry-run shape is:

    nice -n 10 target/release/bifrost_reference_differential run-corpus \
      --clones-root /home/jonathan/Projects/brokkbench/clones \
      --commits-root /home/jonathan/Projects/brokkbench/sft-tools-commits \
      --language c \
      --repo trifectatechfoundation__sudo-rs \
      --repo raphw__byte-buddy \
      --repo LMCache__LMCache \
      --repo DaveGamble__cJSON \
      --repo unicorn-engine__unicorn \
      --repo igraph__igraph \
      --repo libuv__libuv \
      --repo Mbed-TLS__mbedtls \
      --repo ClusterLabs__pacemaker \
      --repo getvictor__fleet-edr \
      --repo-jobs 1 --jobs 8 --cache-mode persisted --strict \
      --max-files 1000 --max-sites 10000 \
      --max-candidates-per-file 50000 --max-source-bytes 4194304 \
      --max-targets 1000 --max-usage-files 1000 --max-usages 100000 \
      --seed 0 --dry-run

For the real rank-eleven baseline, remove the nine later `--repo` arguments,
remove `--dry-run`, and add:

    --output /mnt/optane/tmp/bifrost-fird/c-r11-sudo-rs-HEAD.jsonl

Capture process output in the corresponding
`/mnt/optane/tmp/bifrost-fird/c-r11-sudo-rs-HEAD.log` without changing the
runner's JSONL destination. Fully triage, fix, replay, and close rank eleven
before issuing the analogous single-repository rank-twelve command. Repeat in
rank order, then use all ten explicit slugs for the final language
certification. If interrupted, confirm the process is gone and repeat the
identical command and output path without `--force`; the runner resumes at
repository-envelope granularity.

One exact residual probe uses:

    nice -n 10 target/release/bifrost_reference_differential run-repo \
      --root /home/jonathan/Projects/brokkbench/clones/REPOSITORY_SLUG \
      --language LANGUAGE --jobs 8 --cache-mode ephemeral --strict \
      --path REPOSITORY_RELATIVE_PATH \
      --start-byte START --end-byte END \
      --output /mnt/optane/tmp/bifrost-fird/ISSUE-exact-HEAD.jsonl

Issue tracker operations use `gh` outside the sandbox. Search both open and
closed issues before creation. New issue titles begin `FIRD:` and creation is
immediately followed by assignment verification for `jbellis`. Do not edit
product code until that verification succeeds.

Focused validation depends on the affected analyzer. The minimum transition
before each code push is:

    nice -n 10 cargo fmt --all -- --check
    nice -n 10 cargo test TARGET_OR_FILTER
    nice -n 10 cargo test

The language-stack gate additionally runs:

    nice -n 10 cargo clippy --all-targets --all-features -- -D warnings

The final campaign gate adds, after checking available disk and ensuring no
other NLP build is active:

    BIFROST_SEMANTIC_INDEX=off nice -n 10 uv run --python 3.12 -- \
      cargo test --features nlp,python

## Validation and Acceptance

Selection acceptance requires 110 unique language/repository rank records,
exactly ten ranks per language, all from the live filtered selector's
`[10:20]` slice. Every canonical clone must exist at its pinned readable clean
HEAD and each language dry-run must select exactly its ten explicit slugs.

Language acceptance requires ten completed final envelopes on one clean pushed
language head and intended fingerprint. Every envelope must report the pinned
clone head and clean Bifrost/clone flags. Candidate-limit files, file errors,
skipped targets, target-truncated sites, and raw missing rows must be enumerated
and dispositioned; none may be silently excluded. Every legitimate owned issue
must have been assigned before edits, tested, pushed, replayed cleanly, and
closed. Externally assigned issues must remain untouched and be identified in
the summary.

Campaign acceptance requires all eleven durable language summaries, one
110-record compact manifest, zero actionable owned discrepancy, and a complete
issue ledger. Formatting, strict Clippy, focused regressions, and the final
feature-enabled Cargo suite must pass locally. Every fixing head and evidence
commit must be ancestral to the exact remote master ref. The worktree must be
clean, local and remote heads identical, no campaign process active, and the
dedicated Optane directory empty after cleanup.

## Idempotence and Recovery

Selector and dry-run commands are read-only. Corpus JSONL output is append-only
and completion-key resumable; preserve an interrupted artifact and rerun the
same command without `--force`. Exact probes always use unique output names.
Do not delete persisted `.brokk` caches to recover from analyzer errors; trace
cache epoch or migration failures to their source. Add only generated `.brokk/`
or `.bifrost/` paths to a clone's local `.git/info/exclude` when needed to keep
tracked evidence clean.

Before a code edit, confirm issue assignment again. Before a push, fetch and
merge `origin/master`; never rebase, switch branches, or create a PR. Stage only
files owned by the current change. If another contributor changes overlapping
code, preserve their work and review the combined behavior rather than
reverting it.

Temporary cleanup is deliberately deferred until compact evidence and raw
checksums are pushed. Before deletion, list the exact contents, total bytes,
and active processes. Remove only the reviewed contents of
`/mnt/optane/tmp/bifrost-fird/`, leave the directory itself available, and
verify it is empty.

## Artifacts and Notes

Raw repository artifacts use
`/mnt/optane/tmp/bifrost-fird/<language>-r<rank>-<repo>-<head>.jsonl` and
`.log`; final language certifications use
`<language>-task-ranks11-20-<head>.jsonl` and `.log`. Derived exhaustive audits
use `-missing-audit.{jsonl,tsv,summary.json}`
and `-missing-ledger.{jsonl,tsv,sha256}`. Exact probes include the issue or
root-cause identifier, repository, and head. These large files remain
untracked.

Compact language manifests and summaries use
`.agents/docs/reference-differential/<language>-task-ranks11-20-<head>.jsonl`
and `-summary.md`. The final campaign files use
`.agents/docs/reference-differential/task-ranks11-20-final-manifest.jsonl` and
`task-ranks11-20-final-summary.md`. They pin raw artifact paths and SHA-256
values even though the raw files are removed at final cleanup.

## Interfaces and Dependencies

No runner API change is planned. `bifrost_reference_differential run-corpus`
must continue to accept repeated `--language` and `--repo` filters, persisted
cache mode, strict limits, dry-run, and an append-only JSONL output. `run-repo`
must continue to accept exact path and zero-based byte-range filters with
ephemeral cache mode. Product fixes stay within the existing analyzer,
`SearchToolsService`, MCP symbols, Rust API, and Python API surfaces. LSP behavior
may improve through shared code but does not define campaign acceptance.

Revision note (2026-08-01): Created the ranks-eleven-through-twenty expansion
as a distinct 110-repository campaign, recorded the live filtered selection,
defined language-depth-first issue and fix ordering, and incorporated the
normal-storage niceness and cleanup requirements.

Revision note (2026-08-01): Tightened execution to repository-depth-first
within each language: no later repository baseline or ticket creation begins
until the current repository has clean replay evidence and all owned issues are
closed. Recorded independent selector and C preflight results, input hashes,
generated-cache cleanliness handling, live per-language reselection, and the
Python 3.12 final gate.
