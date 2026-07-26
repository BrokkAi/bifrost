# Expand the task-ranked reference differential to ten repositories per language

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`,
`Decision Log`, and `Outcomes & Retrospective` current while work proceeds.
Maintain it in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost's public MCP `symbols` toolset and associated Rust and Python APIs
support both forward definition lookup and inverse reference lookup. When a
source reference resolves forward to a workspace declaration group, a complete
inverse query for that declaration should recover the same source range. This
campaign tests that contract on the ten repositories with the most eligible
tasks in each of the eleven languages recognized by
`/home/jonathan/Projects/brokkbench/tasks.py`.

Repository membership is selected only by calling
`tasks.task_repos(tasks.SFT_PREDICATES, langs=[LANG])`, sorting the returned
records by descending `task_count` while preserving selector order for ties,
and retaining ten. `SFT_PREDICATES` is the required selector because it
excludes `large-repos.csv` entries and applies the task corpus eligibility
gates. The differential runner receives the ten slugs as explicit repeated
`--repo` arguments. Its `--repos-per-language` option ranks by code size and is
not valid for this objective.

The observable result is 110 completed repository envelopes, ten per language,
with every raw `missing` row exhaustively dispositioned. Every legitimate
defect must have a GitHub issue whose title starts `FIRD:` and which is assigned
to `jbellis` before product code changes begin. If a matching issue is assigned
to somebody else, record it and skip that issue. Owned fixes receive structured
behavior tests, exact production proof, formatting, all-feature Clippy, the
complete `cargo test --features nlp,python` gate, direct publication to
`origin/master`, and issue closure. LSP shares much of the implementation and
comes through the local gate, but is not the focus.

## Progress

- [x] (2026-07-23) Read the repository instructions, `.agents/PLANS.md`, and
  `/home/jonathan/Projects/bifrost/.agents/docs/reference-differential-runbook.md`.
- [x] (2026-07-23) Recomputed all eleven top-ten sets through
  `task_repos(SFT_PREDICATES, langs=[LANG])`, using stable descending task
  counts rather than the runner's LOC ranking.
- [x] (2026-07-23) Delegated an independent read-only selector audit to the
  requested Oldskool role. All 110 canonical clones exist, have readable HEADs,
  are tracked-clean, and have both corpus `.jsonl` and `.testsome.jsonl`
  inputs.
- [x] (2026-07-23) Ran eleven separate runner dry-runs, one per language with
  exactly its ten explicit slugs. Each produced exactly ten expected records,
  for 110 total, with no missing, extra, or invalid selections.
- [x] (2026-07-24) Received direct authorization for the top-ten expansion,
  fetched `origin/master`, and fast-forwarded the current `bifrost-fird`
  branch from `8b3423b9` to current shared baseline `40d98491`.
- [ ] Build and fingerprint a clean release runner from the plan checkpoint.
- [ ] Complete C and publish its evidence and user summary.
- [ ] Complete C++ and publish its evidence and user summary.
- [ ] Complete C# and publish its evidence and user summary.
- [ ] Complete Go and publish its evidence and user summary.
- [ ] Complete Java and publish its evidence and user summary.
- [ ] Complete JavaScript and publish its evidence and user summary.
- [ ] Complete TypeScript and publish its evidence and user summary.
- [ ] Complete PHP and publish its evidence and user summary.
- [ ] Complete Rust and publish its evidence and user summary.
- [ ] Complete Scala and publish its evidence and user summary.
- [ ] Complete Python and publish its evidence and user summary.
- [ ] Prove all 110 accepted envelopes and every fixing head are present on
  final `origin/master`, run the final local gate, and remove temporary
  diagnostics while retaining the compact checked-in evidence.

## Surprises & Discoveries

- The live selector changed membership relative to the completed top-five
  campaign. C now ranks Pillow first; PHP now ranks Skipper second and Passbolt
  fifth; and the C++ 32-task tie places `ljharb__qs` before `PJK__libcbor`.
  Therefore the final top-ten proof must rerun all ten repositories at one head
  rather than concatenate five old and five new records.

- `task_repos` returns eligible records in corpus order, not task-count order.
  The campaign must apply a stable descending `task_count` sort explicitly.

- `tasks.py` canonical language keys are `js` and `ts`. Long aliases can return
  an empty result because the module filters its raw task directory before
  normalizing aliases.

- Repeated `--language` and `--repo` arguments in one runner process do not
  create independent language/repository partitions. The repository filter is
  global, which expanded an attempted combined dry-run to 146 records. Every
  acceptance run must therefore contain exactly one language and only that
  language's ten slugs.

- Some selector records report zero code LOC in task metadata, including Keras,
  Nacos, Dubbo, RocketMQ, WxJava, Angular.js, Dayjs, PhpSpreadsheet, and
  oh-my-openagent. They remain valid task-selected members; this field is not a
  proof that the analyzer sees no source files.

- `origin/master` advanced substantially after the top-five campaign and
  contains broad structured resolver, same-owner, receiver, boundary, cache,
  Rust, C++, Scala, and search-tool changes. Historical artifacts remain
  regression evidence only; all expanded baselines start from the synchronized
  head.

## Decision Log

- Decision: Use the live `SFT_PREDICATES` selector and stable descending task
  counts immediately before each language begins.
  Rationale: The user's acceptance set is defined by `tasks.py`, including its
  `large-repos.csv` exclusion, rather than by a frozen hand-copied list.
  Date/Author: 2026-07-23 / Codex

- Decision: Run exactly one language per runner process with ten explicit
  `--repo` arguments.
  Rationale: Repository filters are global across repeated languages, while
  `--repos-per-language` ranks by LOC. Separate processes are the only command
  shape that directly proves the requested membership.
  Date/Author: 2026-07-23 / Codex

- Decision: Treat every earlier top-five result as regression evidence, not as
  an accepted half of a top-ten result.
  Rationale: Live membership changed, and an accepted language must have all
  ten envelopes produced by one immutable pushed Bifrost head.
  Date/Author: 2026-07-23 / Codex

- Decision: Prefix every newly created defect title with `FIRD:` and assign it
  to `jbellis` before editing.
  Rationale: This is an explicit campaign contract. Existing issues assigned to
  another person are documented skips and are not modified.
  Date/Author: 2026-07-23 / Codex

- Decision: Process language acceptance serially, while delegating disjoint
  row-ledger/source diagnosis and substantial structured implementations to
  Oldskool agents.
  Rationale: Persisted caches and the runner's global filters favor one
  authoritative language process at a time, while residual research partitions
  safely and accelerates diagnosis. Root retains issue ownership checks, code
  review, gates, publication, and acceptance decisions.
  Date/Author: 2026-07-23 / Codex

## Outcomes & Retrospective

The top-ten expansion is in progress. The completed historical top-five
campaign proved the method and remains useful regression evidence, but it does
not satisfy this plan because current acceptance requires 110 envelopes from
the live task-selected membership.

## Context and Orientation

Work in `/mnt/optane/bifrost-fird` on the existing `bifrost-fird` branch. Do not
create or switch branches, rebase, or open a pull request. Commit only files
changed for this campaign. Before each publication, fetch `origin/master`,
merge it into the current branch without rebasing if necessary, repeat
proportionate local gates, and push the integrated `HEAD` directly to
`origin/master`.

The differential CLI is `src/bin/bifrost_reference_differential.rs`; the engine
and JSONL schema are in `src/reference_differential/mod.rs`. Forward definition
resolution lives under `src/analyzer/usages/get_definition/`; inverse reference
logic lives in `src/analyzer/usages/` and its language modules. Public symbols
surfaces live under `src/searchtools/`, `src/searchtools_service.rs`, MCP
registry/core modules, and Python bindings. Use
`tests/common/inline_project.rs::InlineTestProject` for small reductions.

Canonical clones are below
`/home/jonathan/Projects/brokkbench/clones`, which resolves to
`/mnt/T9/repo-clones`. Task selection and corpus eligibility reads go only
through `/home/jonathan/Projects/brokkbench/tasks.py`. Durable raw artifacts,
logs, exact records, and row ledgers belong under
`/mnt/optane/tmp/bifrost-fird/`; compact manifests and narrative summaries
belong under `.agents/docs/reference-differential/`.

The authoritative selections at plan creation are:

- C: `python-pillow__Pillow` (159),
  `roseteromeo56-cb-id__go-ethereum` (105), `rui314__chibicc` (77),
  `libgit2__libgit2` (60), `bernardladenthin__BitcoinAddressFinder` (42),
  `jerryscript-project__jerryscript` (41), `aws__s2n-tls` (39),
  `nanomsg__nng` (32), `CESNET__libyang` (31), `dovecot__core` (27).

- C++: `esphome__esphome` (151), `cloudflare__circl` (68),
  `ljharb__qs` (32), `PJK__libcbor` (32), `apache__qpid-proton` (27),
  `LMCache__LMCache` (25), `zeromq__libzmq` (22),
  `apache__logging-log4cxx` (22), `Blosc__c-blosc2` (21),
  `ccache__ccache` (20).

- C#: `granit-fx__granit-dotnet` (110), `riok__mapperly` (85),
  `ClosedXML__ClosedXML` (68), `tui-cs__Terminal.Gui` (56),
  `JoshClose__CsvHelper` (53),
  `vkhorikov__CSharpFunctionalExtensions` (53), `ScottPlot__ScottPlot` (45),
  `neo-project__neo` (45), `Radarr__Radarr` (42), `Cysharp__R3` (39).

- Go: `afadesigns__zshellcheck` (499), `cli__cli` (476),
  `open-telemetry__opentelemetry-collector` (377),
  `router-for-me__CLIProxyAPI` (242), `ollama__ollama` (233),
  `jeduden__mdsmith` (227), `open-policy-agent__opa` (224),
  `helm__helm` (192), `invopop__gobl` (186), `rclone__rclone` (178).

- Java: `alibaba__fastjson2` (328), `chinabugotech__hutool` (208),
  `languagetool-org__languagetool` (192), `halo-dev__halo` (163),
  `apache__dubbo` (126), `pinpoint-apm__pinpoint` (112),
  `apache__commons-lang` (83), `apache__rocketmq` (77),
  `binarywang__WxJava` (70), `alibaba__nacos` (54).

- JavaScript: `argoproj__argo-cd` (266), `josephfung__curia` (254),
  `iamkun__dayjs` (109), `pipe-cd__pipecd` (101),
  `bancolombia__devsecops-engine-tools` (78),
  `Hack23__European-Parliament-MCP-Server` (74),
  `weaveworks__weave-gitops` (60), `Stormheg__wagtail` (47),
  `angular__angular.js` (41), `pewdiepie-archdaemon__odysseus` (40).

- TypeScript: `code-yeongyu__oh-my-openagent` (272),
  `storybookjs__storybook` (180),
  `Yeachan-Heo__oh-my-claudecode` (162),
  `woodpecker-ci__woodpecker` (113), `vuejs__core` (87),
  `lerna__lerna` (76), `qdraw__starsky` (70),
  `react-hook-form__react-hook-form` (63), `vitejs__vite` (55),
  `carbon-design-system__carbon` (33).

- PHP: `laravel__framework` (126), `zalando__skipper` (119),
  `cakephp__cakephp` (95), `PHPOffice__PhpSpreadsheet` (84),
  `passbolt__passbolt` (83), `grokability__snipe-it` (82),
  `codeigniter4__CodeIgniter4` (74), `phpactor__phpactor` (55),
  `phpmyadmin__phpmyadmin` (49), `doctrine__dbal` (45).

- Rust: `tokio-rs__tokio` (142), `kivikakk__comrak` (59),
  `ordian__toml_edit` (44), `tokio-rs__tracing` (40),
  `foobarto__stado` (37), `QWED-AI__qwed-verification` (34),
  `wealthfolio__wealthfolio` (24), `tracel-ai__burn` (23),
  `hickory-dns__hickory-dns` (22), `nmstate__nmstate` (21).

- Scala: `scala-steward-org__scala-steward` (147), `zio__zio` (106),
  `linkerd__linkerd` (72), `scalameta__metals` (71),
  `typelevel__fs2` (62), `zio__zio-http` (62),
  `lichess-org__scalachess` (48), `lensesio__stream-reactor` (48),
  `http4s__http4s` (40), `guardian__grid` (39).

- Python: `bytedance__deer-flow` (208),
  `pewdiepie-archdaemon__odysseus` (137), `kornia__kornia` (112),
  `quantumlib__Cirq` (105), `powsybl__powsybl-core` (97),
  `mahmoud__glom` (90), `caikit__caikit` (84),
  `keras-team__keras` (70), `fsspec__filesystem_spec` (65),
  `python-websockets__websockets` (57).

## Plan of Work

Immediately before a language begins, regenerate its live selection through
`tasks.py`, compare it with this plan, and update the plan if the live selector
has changed. Record the ten clone heads and tracked cleanliness. Rebuild and
fingerprint a release runner from an immutable clean Bifrost checkpoint.

Run one language at a time with ten explicit slugs, one repository job, eight
inner workers, persisted cache mode, strict classification, and the established
bounds. Verify ten completed envelopes, exact Bifrost and repository heads,
clean flags, semantic fingerprints, JSON integrity, configured limits, and file
errors. Extract every raw `missing` site to a checksummed ledger.

Delegate disjoint ledger/source research where useful. Root verifies source
bytes, token and tree-sitter role, forward declaration group, inverse
completeness, and exact-site reproducibility. Classify only after the full row
set is accounted for.

For every legitimate root, search open and closed GitHub issues. If a matching
issue is assigned to another user, record and skip it. Otherwise assign an
existing issue to `jbellis`, or create a `FIRD:` issue already assigned to
`jbellis`, before product edits. Build a faithful structured reduction with
negative controls, implement at the graph/parser/resolver root, review the
diff, and run focused tests. Do not use regex, substring, delimiter splitting,
or source-text mini-parsers.

At the language publication boundary, run formatting, isolated all-target and
all-feature Clippy, and the complete isolated
`cargo test --features nlp,python` gate. Commit only campaign files with a
multiline why-oriented message. Fetch and merge current `origin/master`, repeat
proportionate gates, and push the integrated current branch directly to
`origin/master` without waiting for CI.

Rebuild the runner from the exact pushed head. Replay every fixed exact witness
and all ten authoritative repositories into new head-scoped artifacts.
Exhaustively audit residuals. Only then comment on and close owned issues,
commit compact evidence, verify local/remote agreement, summarize the completed
language to the user, and continue immediately to the next language.

## Concrete Steps

Regenerate a selection without manually reading task stores. Substitute the
canonical language key:

    cd /mnt/optane/bifrost-fird
    PYTHONDONTWRITEBYTECODE=1 python3 -c \
      'import sys; sys.path.insert(0,"/home/jonathan/Projects/brokkbench"); import tasks; rows=tasks.task_repos(tasks.SFT_PREDICATES, langs=["c"]); print(sorted(rows, key=lambda r: -r.task_count)[:10])'

Build and fingerprint the runner from a clean checkpoint:

    cargo build --release --bin bifrost_reference_differential
    git rev-parse HEAD
    sha256sum target/release/bifrost_reference_differential

The C command shape is:

    set -o pipefail
    /usr/bin/time -v target/release/bifrost_reference_differential run-corpus \
      --clones-root /home/jonathan/Projects/brokkbench/clones \
      --commits-root /home/jonathan/Projects/brokkbench/sft-tools-commits \
      --language c \
      --repo python-pillow__Pillow \
      --repo roseteromeo56-cb-id__go-ethereum \
      --repo rui314__chibicc \
      --repo libgit2__libgit2 \
      --repo bernardladenthin__BitcoinAddressFinder \
      --repo jerryscript-project__jerryscript \
      --repo aws__s2n-tls \
      --repo nanomsg__nng \
      --repo CESNET__libyang \
      --repo dovecot__core \
      --repo-jobs 1 --jobs 8 --cache-mode persisted --strict \
      --max-files 1000 --max-sites 10000 \
      --max-candidates-per-file 50000 --max-source-bytes 4194304 \
      --max-targets 1000 --max-usage-files 1000 --max-usages 100000 \
      --seed 0 \
      --output /mnt/optane/tmp/bifrost-fird/c-task-top10-HEAD8.jsonl \
      2>&1 | tee -a /mnt/optane/tmp/bifrost-fird/c-task-top10-HEAD8.log

Repeat with each exact language list above and the matching canonical language
key (`c`, `cpp`, `csharp`, `go`, `java`, `js`, `ts`, `php`, `rust`, `scala`,
`py`). Never combine languages in one process. Do not use
`--repos-per-language`, `--include-tests`, or routine `--force`. Resume an
interrupted run by confirming the old process is gone and repeating its
identical command and output path.

Before pushing Rust changes, run:

    cargo fmt --all -- --check
    git diff --check
    scripts/with-isolated-cargo-target.sh \
      cargo clippy --all-targets --all-features -- -D warnings
    UV_CACHE_DIR=/tmp/bifrost-uv-cache BIFROST_SEMANTIC_INDEX=off \
      scripts/with-isolated-cargo-target.sh cargo test --features nlp,python

## Validation and Acceptance

A language is complete only when exactly its ten live task-selected
repositories have completed records on one clean pushed Bifrost head, every
repository head is pinned and clean, the configuration is uniform, every error
and limit is accounted for, and every raw missing row has a reviewed
disposition. Each owned legitimate defect must have a preassigned `FIRD:`
issue, structured regression, fixing commit on `origin/master`, clean exact
witness, clean final corpus proof, and closed issue. An issue assigned to
another user is an explicit documented skip and is not modified.

The campaign is complete only when all eleven language boundaries pass, the
compact evidence is committed, every accepted fixing head is an ancestor of
final `origin/master`, the complete local gate passes after final integration,
and local HEAD, local `origin/master`, and the remote master agree. GitHub CI is
not a blocking gate.

## Idempotence and Recovery

`run-corpus` appends one completed repository envelope and skips an identical
completion key on resume. Preserve JSONL, logs, and persisted caches after
interruption; repeat the exact command without `--force`. If Bifrost source
changes, rebuild the runner and use a new head-scoped artifact. Never mutate
selected clone sources or delete caches to hide migration failures.

Run isolated Cargo work through
`scripts/with-isolated-cargo-target.sh`. Use
`scripts/cleanup-bifrost-tmp.sh` only after reviewing its dry-run candidates.
At campaign completion, remove disposable exact diagnostics and scratch
ledgers from `/mnt/optane/tmp/bifrost-fird/`, retaining only the final
head-scoped evidence required by the checked-in summaries.

## Artifacts and Notes

Keep raw JSONL, logs, exact records, ledgers, and checksums under
`/mnt/optane/tmp/bifrost-fird/`. Check in only compact manifests and narrative
summaries under `.agents/docs/reference-differential/`. Every artifact name
must include the language, `task-top10`, and the eight-character source head.

## Interfaces and Dependencies

Reuse `reference_differential::run_reference_differential`,
`WorkspaceAnalyzer`, `UsageFinder`, language-specific structured forward
resolvers and inverse graphs, `AnalyzerStore`, and `InlineTestProject`. Preserve
explicit target/file/usage limits and honest `unproven` or `inconclusive`
outcomes. Add public SearchTools or Python binding coverage only when the
exposed surface changes. Avoid new dependencies unless a reduced root cause
requires them and this plan records why.

Revision note (2026-07-24): Created after direct authorization for the expansion
from the completed historical five-repository campaign to the live task-ranked
ten-repository campaign. Records the independently audited 110-repository
selection, global-filter runner pitfall, current synchronized baseline, and
publication contract.
