# Audit the five largest Java, Go, and Python corpora through the public symbols surface

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this document in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost's forward-vs-inverse reference differential asks a simple user-facing question: when the public symbols API resolves a source reference to a declaration, can the inverse usage query find that same source range again? Earlier work closed this campaign for one large Java, Go, and Python repository per language. This campaign expands coverage to the five largest valid local clones for each language, runs repositories concurrently within the 120-core and 98-GiB host budget, exhaustively distinguishes genuine analyzer defects from invalid forward identities or explicit limits, and fixes every genuine defect that is not already owned by somebody else.

The observable result is three complete JSONL corpus records, one per language and five repositories per record, produced by `bifrost_reference_differential run-corpus`. For each language, every raw `missing` site is either fixed and proven by an exact production rerun or documented with source evidence showing why it is not a valid actionable forward/inverse pair. Genuine defects receive GitHub issues assigned to `jbellis` before implementation. Each language ends with the complete feature-enabled local Cargo test suite passing, a direct integration to `origin/master`, issue evidence and closure, and a concise summary. GitHub CI is intentionally not a blocking gate for this campaign because the user asked the root session to move on once local `cargo test` passes.

## Progress

- [x] (2026-07-17 00:32Z) Fast-forwarded the clean detached Optane worktree to current `origin/master` at `1a37f639e5dc247eda66419482786c469759fbc3`, read `.agents/PLANS.md`, reconciled the canonical N=1 campaign, and reviewed the completed repository-concurrency plan.
- [x] (2026-07-17 00:32Z) Ran a read-only GPT-5.4/medium Oldskool research pass. It confirmed the clean N=1 closure boundaries and identified the dominant stale/false-forward families that must not be rediscovered as inverse bugs.
- [x] (2026-07-17 00:32Z) Repaired `/mnt/c/Users/jbell/.codex/agents/oldskool.toml` by adding the role's now-required `developer_instructions`; the initial invocation had warned that Codex ignored the malformed role, although explicit model/reasoning overrides still ran GPT-5.4/medium.
- [x] (2026-07-17 00:32Z) Built the release differential runner and selected the exact top five Java, Go, and Python clones with a no-write dry-run. All fifteen Git repositories are clean; three N=1 repositories and IntelliJ have existing persisted caches, while the other eleven are cold.
- [x] (2026-07-17 00:36Z) Committed and pushed the campaign-start plan as `2366ea0e`, establishing a clean published Bifrost checkpoint before analyzer cache mutation.
- [ ] Complete the Java top-five run, triage every raw missing site, file/assign/fix legitimate issues, pass the complete local gate, integrate to `origin/master`, rerun from the fixing head, close issues with evidence, and publish the Java summary.
- [ ] Complete the Go top-five run under the same discipline and publish the Go summary.
- [ ] Complete the Python top-five run under the same discipline and publish the Python summary.
- [ ] Reconcile the final canonical campaign evidence, record outcomes and limitations, and leave the Optane worktree clean.

## Surprises & Discoveries

- Observation: The configured Oldskool role existed but was not valid under the current Codex schema.
  Evidence: the first delegated invocation reported that `/mnt/c/Users/jbell/.codex/agents/oldskool.toml` must define `developer_instructions`. Explicit `-m gpt-5.4 -c model_reasoning_effort=\"medium\"` overrides still produced a completed read-only handoff, and the role file now includes the missing field.

- Observation: Eleven of the fifteen selected repositories are genuinely cold, rather than merely having small caches.
  Evidence: only `googleapis__google-cloud-java` (5.8 GiB), `JetBrains__intellij-community` (987 MiB), `aws__aws-sdk-go-v2` (1.6 GiB), and `googleapis__google-cloud-python` (1.5 GiB) currently have `.brokk` directories. The other selected clones report no cache.

- Observation: The Python corpus metadata selects two strongly polyglot repositories, `tektoncd__operator` and `kubevirt__kubevirt`, because their recorded Python LOC ranks fourth and fifth among available valid clones.
  Evidence: selection is metadata-driven and deterministic; the dry-run reported 2,156,538 and 2,151,738 Python LOC respectively. Do not replace them manually with repositories that merely look more Python-centric.

- Observation: The N=1 closure records contain many raw missing rows that are not genuine inverse defects.
  Evidence: final Java retained 122 rows partitioned into 92 invalid class forward identities and 30 owner/receiver-focus method rows; final Go retained 126 invalid rows partitioned into 117 incompatible focus/target identities and nine wrong-owner keyed labels; final Python retained six invalid rows consisting of one wrong receiver identity and five post-rebind wrong-import identities.

## Decision Log

- Decision: Process languages in the requested Java, Go, Python order and establish a clean published checkpoint after each language.
  Rationale: The user requested a summary and master integration after each completed language. This also prevents one language's unresolved experiments from contaminating the next language's Bifrost metadata or corpus records.
  Date/Author: 2026-07-17 / Codex

- Decision: Run one language at a time with `--repo-jobs 5 --jobs 24` rather than running all fifteen repositories together.
  Rationale: Five times twenty-four uses the host's 120 logical processors without deliberately oversubscribing analyzer construction. Language staging keeps triage and cache behavior understandable, bounds aggregate memory, and provides the required integration boundary after each language.
  Date/Author: 2026-07-17 / Codex

- Decision: Use the persisted cache mode and never delete existing `.brokk` directories.
  Rationale: The campaign is intentionally resumable and measures the real symbols-tool path, including cold population and warm reuse. Eleven cold repositories will create new caches; existing N=1 caches contain valuable completed population work.
  Date/Author: 2026-07-17 / Codex

- Decision: Treat only a valid forward identity plus a complete, non-truncated inverse query with no covering proven or unproven hit as a candidate defect.
  Rationale: A forward resolver can focus an owner, receiver, qualifier, wrong overload, wrong module, or ambiguous declaration. Fixing the inverse query to agree with that invalid identity would make the public symbols API less correct. Explicit file, candidate, target, or usage limits are honest inconclusive boundaries rather than defects.
  Date/Author: 2026-07-17 / Codex

- Decision: Delegate broad source inspection, missing-row clustering, reduced-boundary research, and substantial synchronous implementations to the Oldskool GPT-5.4/medium role, while the root session alone owns the plan, issue mutations, acceptance decisions, review, local gates, commits, merges, pushes, and issue closure.
  Rationale: This matches the user's requested division of labor and allows independent research/implementation to overlap safe root work without delegating authority over GitHub or final correctness judgments.
  Date/Author: 2026-07-17 / Codex

- Decision: Do not wait for GitHub CI after a language push.
  Rationale: The user explicitly asked the campaign to move on after local `cargo test` passes and will report CI failures separately. Local formatting, clippy, focused tests, and the full `cargo test --features nlp,python` suite remain mandatory before integration.
  Date/Author: 2026-07-17 / Codex

## Outcomes & Retrospective

Planning and corpus selection are complete. This section will gain a language-by-language summary after Java, Go, and Python, including selected repository heads, baseline/final counts, resource observations, raw-missing partitions, issue links, fixing commits, exact production witnesses, and local validation results. The final entry will compare the top-five findings with the prior N=1 closure and state whether any public symbols-tool boundary remains unresolved.

## Context and Orientation

Work in `/mnt/optane/tmp/bifrost-java-n10`. The worktree is detached by design but pushes `HEAD:master` directly, following the repository rule not to create branches or pull requests. Before every push, fetch `origin/master`; if it advanced, merge it with `git merge --no-edit origin/master`, never rebase. Stage only files changed for this campaign.

The command-line driver is `src/bin/bifrost_reference_differential.rs`. `run-corpus` reads corpus metadata below `/home/jonathan/Projects/brokkbench/sft-tools-commits`, validates clones below `/home/jonathan/Projects/brokkbench/clones` (a symlink to `/mnt/T9/repo-clones`), chooses repositories by descending recorded `code_loc`, and writes one JSON object per completed repository. `--repo-jobs` limits concurrent repository analyzers. `--jobs` limits both analyzer construction and the per-repository forward-file/inverse-target Rayon pool. Jobs sharing one canonical clone root are grouped and serialized, and one caller thread appends completed JSON records so interruption remains resumable.

The differential implementation is `src/reference_differential/mod.rs`. It samples at most 1,000 language files and 10,000 structured reference candidates per repository, resolves each sampled site forward through the analyzer, groups stable declaration identities, and asks the inverse usage path for the supplied source range. The word `missing` is a raw classification, not automatically a product bug. A `consistent` site has a covering proven inverse hit. `unproven` means the inverse returned the covering range but could not prove precise semantic identity. `inconclusive` covers missing forward identity, external boundaries, explicit limits, errors, or incompatible evidence. An actionable defect is a raw missing row that survives source and identity triage.

The acceptance surface is the MCP `symbols` toolset and its corresponding Rust and Python APIs: location/reference definition lookup, symbol search, summaries, and reference-based usage scans. LSP shares analyzer code and must keep passing, but editor protocol behavior is not the campaign focus. Reduced tests should therefore prefer the shared `tests/common/inline_project.rs` harness, language usage-graph tests, definition tests when forward identity is wrong, and public searchtools/Python bindings tests only when the exposed symbols behavior changes.

The prior authoritative N=1 closures are recorded in `.agents/plans/reference-differential-corpus.md`. Java's final clean google-cloud-java record is `/mnt/optane/tmp/java-n1-final-5440d102-j120.jsonl`; Go's AWS record is `/tmp/go-n1-91cddbf2.jsonl`; Python's google-cloud-python record is `/tmp/python-n1-6d6d76f3.jsonl`. Older baseline counts are stale leads only. The top-five campaign must rerun current code and may reuse known residual shapes only after comparing exact path, range, target identity, and diagnostics.

The selected repositories are:

Java: `googleapis__google-cloud-java` at `20f3d257f09d9509ed1d8902b89fbd03879d6b72` (33,055,102 LOC), `aws__aws-sdk-java` at `d866126817fcc10595a3e7cd4b40efe626f05a7c` (10,787,979), `JetBrains__intellij-community` at `7f7d95f16cc696f47e55796f4320342adaef11df` (9,464,217), `alibaba__dragonwell8` at `1ff7e7caac5fde54cadda31de2a4cc5a8ece23a7` (5,059,105), and `DrKLO__Telegram` at `9fea7264725bbac16e5bd5f18fe22d7c6e8a3117` (3,258,310).

Go: `aws__aws-sdk-go-v2` at `91eca463daf932474778dc4a984c41ecfcd9dc3c` (13,062,919 LOC), `grafana__loki` at `e347d20b0d0012b437b781c98c1903279214d4f5` (7,573,895), `GoogleCloudPlatform__gcloud-golang` at `bcbcd0f855f076f7ef962910603c71efc7b4a83b` (4,517,109), `googleapis__google-cloud-go` at `6e83ba0d835265b71a84bd4f2a5780547532f6c8` (4,384,016), and `kubernetes__kubernetes` at `d7eae6c8fded976adddfb1767ddc9bd17a8e2562` (3,843,632).

Python: `googleapis__google-cloud-python` at `d0b2abc2aef8d95402c026cccbc866d812b819b8` (14,880,589 LOC), `azure__azure-sdk-for-python` at `55aa7fb68558daac3c27c7dcdb5c3a438705afbe` (6,898,111), `home-assistant__core` at `dba09c334a2883eb919f4e8770d7dd65f06b9216` (2,541,573), `tektoncd__operator` at `b85bd9630bac02f36707a71d192527fbd59d227f` (2,156,538), and `kubevirt__kubevirt` at `7f6aafda23840435042a54afe29873b6a7c4341b` (2,151,738).

## Plan of Work

First commit and push this plan so the release runner and Bifrost repository metadata are both clean and published. Rebuild the release runner after that checkpoint. For Java, invoke `run-corpus` with the exact language filter, five repositories, five outer jobs, twenty-four inner jobs, persisted caches, the full N=1 limits, and an output under `/mnt/optane/tmp/reference-differential`. Redirect stderr to a durable adjacent log while retaining interactive progress. Do not run any other analyzer process against these five clones until the command exits. The JSONL writer appends each repository immediately, so a stopped command can be repeated without `--force` and will skip completed semantic keys.

After the five repository records complete, extract every raw missing site grouped by repository and target kind. Preserve the report's exact `path`, `start_byte`, `end_byte`, `text`, `source_evidence`, `targets`, `note`, and `diagnostics`. Delegate disjoint repository clusters to Oldskool read-only passes. Root review checks the actual source bytes, confirms the forward declaration group is semantically valid, verifies inverse limits are complete, and compares known N=1 false-forward families. For suspicious sites, run exact `run-repo` commands against only that path/range on the same clean Bifrost head. The exact rerun must reproduce before any reduction.

Reduce each surviving defect with `InlineTestProject`. Put inverse-only boundaries in `tests/usages_java_graph_test.rs`, `tests/usages_go_graph_test.rs`, or `tests/usages_python_graph_test.rs`; whole-workspace graph differences belong in the corresponding `tests/usage_graph_*_test.rs`; forward identity defects belong in `tests/get_definition_test.rs` or the focused language analyzer/FQN suites. Include strong negative cases for wrong packages/modules, owners/receivers, overload/signature arity, imports/aliases, lexical shadowing/rebinding, nested scopes, duplicate physical declarations, and external imports as relevant. Use tree-sitter nodes, persisted declarations, import binders, and analyzer structures only. Never repair a structured gap with regex, substring search, delimiter scanning, or a source-text mini-parser.

Only after a behavior-focused reduction fails should root search open and closed GitHub issues with the production symbol/FQN, language, and root-boundary terms from the reduction. Inspect assignees before mutation. If an existing issue has an assignee other than `jbellis`, record it as skipped and do not work on it. If a reusable issue is unassigned, assign it only to `jbellis` before implementation. Otherwise create a new issue assigned to `jbellis` whose body includes the exact production site, differential evidence, reduced failing behavior, scope, and acceptance criteria. The root session performs every assignment and issue mutation.

Delegate the substantial implementation to a synchronous Oldskool GPT-5.4/medium subagent with the issue and reduced test as its contract. Root review inspects every diff, runs focused tests, rejects structured-correctness shortcuts, adds missing negative coverage, and retains ownership of edits needed to finish the fix. Repeat exact production probes on the dirty tree only as provisional evidence.

When no genuine sites remain for the language, run formatting, all-target/all-feature clippy, affected focused suites, and the complete `cargo test --features nlp,python` gate with `UV_CACHE_DIR=/tmp/bifrost-uv-cache`. Update this living plan and the canonical campaign plan with baseline/final counts and evidence. Commit only relevant files with a multiline why-oriented message. Fetch and merge current `origin/master`, rerun at least formatting, focused tests, and the complete Cargo test if the merge touched analyzer code, then push `HEAD:master` directly. Do not wait for CI.

Rebuild the release runner from the pushed head. Exact-rerun every fixed production site and then rerun the complete language top-five command into the same JSONL; the changed Bifrost head makes those records distinct. Exhaustively triage the final raw missing rows. Comment on each assigned issue with the fixing commit, pushed Bifrost head, exact production evidence, and local test results, then close it. Publish the requested language summary and move to the next language only when the final five-repository record has zero genuine actionable defects.

Repeat the same lifecycle for Go and then Python. Do not carry dirty code, uncommitted plan changes, active analyzer processes, or unreviewed Oldskool edits across a language boundary.

## Concrete Steps

From `/mnt/optane/tmp/bifrost-java-n10`, verify and build the clean checkpoint:

    git status --short
    git rev-parse HEAD
    git rev-parse origin/master
    cargo build --release --bin bifrost_reference_differential

Use this command shape for each language, substituting `LANG` and a clean `BIFROST_HEAD`. `LANG` is `java`, `go`, or `py`:

    mkdir -p /mnt/optane/tmp/reference-differential
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
      --output /mnt/optane/tmp/reference-differential/LANG-top5.jsonl \
      2>&1 | tee /mnt/optane/tmp/reference-differential/LANG-top5-BIFROST_HEAD.log

Do not use `--include-tests`. Do not use `--force` unless intentionally repeating the same repository head, Bifrost head, and fingerprint after proving that the existing record is invalid. The pipeline above must be run outside the filesystem sandbox because it writes persisted caches below `/mnt/T9`.

Extract summaries and raw missing rows with structured JSON queries:

    jq -c 'select(.record_type == "repository") | {repo_slug,repo_head,bifrost_head,elapsed_seconds,summary:.report.summary}' \
      /mnt/optane/tmp/reference-differential/LANG-top5.jsonl

    jq -c 'select(.record_type == "repository") as $r | $r.report.sites[] | select(.classification == "missing") | {repo_slug:$r.repo_slug,path,start_byte,end_byte,line,text,source_evidence,targets,note,diagnostics}' \
      /mnt/optane/tmp/reference-differential/LANG-top5.jsonl

An exact reproduction uses `run-repo` with the selected clone, language, exact relative path and byte range, persisted mode, twenty-four jobs, and a fresh `/mnt/optane/tmp/reference-differential/LANG-exact-SLUG-BIFROST_HEAD.jsonl` output. Preserve all report fields; do not infer identity from rendered text alone.

Before each language push, run at minimum:

    cargo fmt --all -- --check
    cargo clippy --all-targets --all-features -- -D warnings
    UV_CACHE_DIR=/tmp/bifrost-uv-cache cargo test --features nlp,python --test get_definition_test
    UV_CACHE_DIR=/tmp/bifrost-uv-cache cargo test --features nlp,python --test usages_LANG_graph_test
    UV_CACHE_DIR=/tmp/bifrost-uv-cache cargo test --features nlp,python --test usage_graph_LANG_test
    UV_CACHE_DIR=/tmp/bifrost-uv-cache cargo test --features nlp,python

The Java whole-workspace binary is `usage_graph_java_test`; Go is `usage_graph_go_test`; Python is `usage_graph_python_test`. If a named target is absent, inspect `tests/` and use the actual corresponding target rather than silently skipping equivalent coverage. Run all commands outside the restricted Optane sandbox when Python sidecars or process-tree tests require it. Follow `scripts/with-isolated-cargo-target.sh` only for deliberately isolated validation; do not create manually named Cargo target directories under `/tmp`.

GitHub issue discipline uses the `gh` CLI. Search both states, inspect assignees, assign before code, and skip other owners. The representative sequence is:

    gh issue list --repo BrokkAi/bifrost --state all --search 'LANG ROOT_BOUNDARY' --limit 100
    gh issue view NUMBER --repo BrokkAi/bifrost --json number,title,state,assignees,body,url
    gh issue edit NUMBER --repo BrokkAi/bifrost --add-assignee jbellis

For a new issue, use `gh issue create --repo BrokkAi/bifrost --assignee jbellis`. After the pushed-head proof, add a comment and close with `gh issue close NUMBER --repo BrokkAi/bifrost --comment ...`. Never assign or close an issue through the delegated subagent.

## Validation and Acceptance

A language is complete only when exactly five selected repositories have completed records on the final pushed Bifrost head, all raw missing rows have an explicit reviewed disposition, and zero genuine actionable defects remain. A genuine fixed site must have a reduced behavior test that failed before the change, focused and full local gates that pass after it, and a clean pushed-head exact production record with a covering inverse hit or a correct honest non-actionable classification. Issues must be assigned only to `jbellis`, include the fixing commit and production proof, and be closed. An issue already assigned to another user is a documented skip, not authorization to alter their work.

The final local integration gate is `cargo test --features nlp,python`; a featureless `cargo test` is insufficient because it omits NLP-gated integration targets. Formatting and all-target/all-feature clippy must also pass. GitHub CI status is not part of the blocking acceptance criterion for this run, per the user's explicit instruction.

The campaign is complete when Java, Go, and Python each meet that language boundary, the plan contains three summaries and all issue/fix evidence, `origin/master` contains every accepted change, and the worktree has no campaign changes left uncommitted.

## Idempotence and Recovery

`run-corpus` is append-only and resume-safe. It derives a completion key from language, repository slug/head, Bifrost head, and configuration fingerprint. Repeating the same command without `--force` skips completed repositories and runs only missing keys. Records can arrive in completion order; JSONL line order is not semantic. Keep the output and log on Optane so `/tmp` cleanup or tmpfs pressure cannot erase long-run evidence.

If the process stops, first confirm no `bifrost_reference_differential` process still owns a selected clone, then repeat the same command. Never delete a clone's `.brokk` cache as a retry strategy. If a cache migration fails, inspect the error and database ownership; preserve the database for diagnosis. If a Bifrost code change occurs during a run, let already-running work finish only when the exact binary/head is known and the source tree remains stable; otherwise stop and rerun from a clean published head. Never combine records from different Bifrost heads when claiming a final language closure.

Oldskool research tasks must be read-only when they overlap a corpus run. Implementation delegation begins only after the analyzer command has stopped and a reduced failing test exists. Root review must discard or revise unproven edits before starting another analyzer against the affected clone.

## Artifacts and Notes

The host has 120 logical processors, 98 GiB RAM, 255 GiB swap, about 816 GiB free on `/mnt/optane`, about 816 GiB free on `/mnt/T9`, and about 901 GiB free on `/tmp` at campaign start. The concurrency product is exactly 120 configured workers, but aggregate CPU may stay below 12,000% because database work, filesystem latency, language-specific serial sections, and unequal repository completion create idle intervals. Wall-clock and RSS are evidence, not fixed performance requirements.

The initial dry-run skipped metadata members with invalid `code_loc`, a missing Java OpenAPI Generator clone, and a missing PyTorch clone before selecting the fifteen repositories listed above. Those skips are expected input validation and do not reduce the requested count because five valid clones remain for each language.

The Oldskool read-only handoff identified useful duplicate-search families. Java terms include nested return declaring scope, usage-facts full scan, generic signature arity, overload arity, static nested imports, duplicate physical source FQN identity, self-type references, and class-body initializer owners. Go terms include exact-owner keyed struct literal labels, composite literal wrong owner, selector focus/receiver, and ServiceID/DiscoverEndpoint owner identity. Python terms include module qualifier usage, re-export aliases, nested class ownership, source-ordered binding, deferred-body final binding, post-rebind imports, wrong receiver columns, and stdlib/workspace module collisions. These are search hints, not proof that a new top-five row is a duplicate.

## Interfaces and Dependencies

No campaign feature is planned up front; production edits are determined by reduced defects. Preserve the existing CLI contract in `src/bin/bifrost_reference_differential.rs`: `--repo-jobs` is outer repository concurrency, `--jobs` is per-repository analyzer and audit parallelism, output is append-only JSONL, and progress is repository-qualified. Preserve the report schema and stable declaration identity in `src/reference_differential/mod.rs` so records remain comparable.

Analyzer fixes must operate through the existing structured Java, Go, or Python analyzers and public symbols APIs. Rust tests should use `InlineTestProject` from `tests/common/inline_project.rs`. Python binding behavior is tested through the existing Python integration targets with `--features python` included via the full feature gate. Do not introduce new crates, persistence schemas, or public API shapes unless the reduced root cause genuinely requires them and the plan is revised first with the reason.

Revision note (2026-07-17 00:32Z): Created this self-contained top-five campaign plan after reconciling the completed N=1 Java/Go/Python evidence, validating the new repository-concurrency runner, repairing the Oldskool role schema, pinning all fifteen selected clone heads, and measuring cache/disk/host readiness. It records the user's issue ownership, delegation, local-test, per-language integration, and no-CI-wait requirements before any analyzer mutation.

Revision note (2026-07-17 00:36Z): Recorded the published campaign-start checkpoint so later corpus evidence can distinguish planning state from analyzer/fix heads.
