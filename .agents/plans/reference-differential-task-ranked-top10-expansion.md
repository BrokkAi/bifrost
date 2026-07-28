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
- [x] (2026-07-24) Committed and published this plan at `37412679`, then
  built the clean release runner with SHA-256
  `2f32980c15c556f7e4b9a9b6453f93ec040aec310920cd3039b744b955a3d735`.
- [x] (2026-07-24) Started the authoritative C top-ten baseline. Dovecot and
  go-ethereum completed with zero raw missing rows. Libgit2 exposed a severe
  guarded-type inverse performance regression: 365 of 796 targets required
  3,034 seconds, versus a historical 666-target completed envelope in 911.9
  seconds on the same clone head. The interrupted evidence is preserved as
  `/mnt/optane/tmp/bifrost-fird/c-task-top10-37412679-aborted-issue1165.*`.
- [x] (2026-07-24) Searched the complete issue tracker, found no matching
  owner, then created and assigned `FIRD:` issue #1165 to `jbellis` before
  implementation. Delegated the bounded structured visibility-memoization
  implementation to Oldskool while root retains review and publication.
- [x] (2026-07-24) Added only generated `.bifrost/` and `.brokk/` directories
  to the four affected C clones' local Git excludes; all ten selected C clones
  now report clean state without altering corpus source.
- [x] (2026-07-24) Implemented and independently reviewed the first #1165
  candidate. Both new tests, the nearby guard regressions, and all 146 C/C++
  usage integration tests passed before the final mixed-outcome strengthening.
- [x] (2026-07-25) Rejected that first candidate during isolated libgit2
  performance validation: eager normalization preserved semantics but made the
  forward phase exceed 1,618 seconds versus 264.9 seconds on the unmodified
  head. Preserved the aborted replay and delegated a lazy peer-level revision.
- [x] (2026-07-25) Rejected the subsequent declaration-guard-only cache after
  its clean isolated replay retained the pathological inverse tail. It
  completed forward in 237.5 seconds and initially improved inverse
  checkpoints, but reached only 360 of 796 targets in 2,822 seconds and then
  made no progress for more than twelve minutes with eight broad targets in
  flight. Preserved the failed log and started targeted root-cause analysis.
- [x] (2026-07-25) Rejected a batch-only cache of the final
  `(consumer, candidate, reference span)` visibility decision after an
  eight-target-only replay left every broad target unfinished for roughly
  twelve inverse minutes. Removed both the candidate and the temporary
  differential target filter.
- [x] (2026-07-25) Traced the remaining #1165 work to target-specific lexical
  resolution of unrelated type-shaped nodes in every candidate file. Updated
  the issue ExecPlan to optimize at a conservative structured may-resolve
  boundary ahead of that work.
- [x] (2026-07-25) Replayed `git_diff` as the sole inverse target. It still
  failed to finish after twelve inverse minutes, ruling out eight-worker
  contention as the primary cause and preserving the solo log for #1165.
- [x] (2026-07-25) Implemented and independently reviewed the conservative
  two-stage type-reference prefilter for #1165. After confining it away from
  static qualifier and method-owner classification, focused exactness and
  work-count tests passed and the complete C/C++ usage integration target
  passed all 147 tests.
- [x] (2026-07-25) Completed the corrected full-workload libgit2 replay:
  forward finished in 202.9 seconds, inverse reached the old 365-target
  checkpoint in 1,011.5 seconds instead of 3,034.3, and all 796 targets
  completed in 3,060.9 seconds. The one completed envelope has zero missing,
  zero truncation, zero file errors, and exact 10,000-site accounting.
- [x] (2026-07-25) Delegated a second live-selector audit for the ten languages
  after C. Oldskool confirmed every slug, task count, stable tie ordering, and
  the `SFT_PREDICATES.not_overlarge` path against current `tasks.py`; the plan
  has no selector discrepancies.
- [x] (2026-07-25) The first repository-wide gate exposed an eager provider
  scaling regression in the candidate's global alias-name classification. I
  removed that global pass, retained only lazy visible parser aliases plus
  same-terminal indexed candidates, and restored the focused provider count
  from 140/137 calls to within its 20/10 bounds. The complete 147-test C/C++
  usage target and all-feature Clippy are green on the corrected source.
- [x] (2026-07-25) Delegated a final read-only #1165 review to Oldskool. It
  found no actionable correctness, cache-concurrency, or coverage issue and
  confirmed that unresolved/template/cyclic aliases stay conservative.
- [x] (2026-07-25) The corrected repository-wide gate found one pre-existing
  stale PHP graph assertion from the shared same-owner policy. After confirming
  no existing owner, I created and assigned `FIRD:` issue #1169 to `jbellis`,
  changed the test to reject a proven `$this` self edge, and passed its isolated
  all-feature regression. Existing targeted symbols coverage continues to prove
  the site is retained as `SelfReceiver`.
- [x] (2026-07-25) The next complete gate reached the analogous pre-existing
  Ruby assertion. I confirmed no existing owner, created and assigned `FIRD:`
  issue #1170 to `jbellis`, changed the test to reject a proven implicit-self
  edge, and passed its isolated all-feature regression. A delegated audit of
  every remaining usage-graph language found no further stale positive
  same-owner expectations.
- [x] (2026-07-25) A later complete-gate attempt exposed a timing-sensitive
  same-process cache initialization race: 15 of 16 openers exhausted SQLite's
  five-second lock window while one migrated successfully. I found no existing
  owner, created and assigned `FIRD:` issue #1173 to `jbellis`, wrote its
  ExecPlan, and delegated `src/cache_db.rs` implementation to Oldskool.
- [x] (2026-07-25) Reviewed #1173's accepted path-local
  `Weak<Mutex<()>>` registry. It serializes persistent pragma setup and
  migration only for one canonical path, prunes unused cells, leaves
  cross-process locking to SQLite, returns poison errors, and passes focused
  canonical-path, independent-path, and 16-opener tests.
- [x] (2026-07-26) Passed formatting, `git diff --check`, focused cache and
  C/C++ regressions, all 147 C/C++ usage tests, and all-target/all-feature
  Clippy. The full normal-permission gate passed all 1,872 substantive library
  tests, all 193 LSP tests, and the separately isolated MCP integration target
  28/28.
- [x] (2026-07-26) Stopped creating isolated Cargo targets under `/tmp` after
  direct user correction, removed both abandoned targets created by this work,
  and switched all subsequent Cargo and Bifrost commands to normal
  outside-sandbox execution at niceness 10. One older explicitly retained
  `.bifrost-keep` target was left untouched.
- [x] (2026-07-26) Merged current `origin/master` at `09771a77`, resolving the
  only textual conflicts by retaining master's equivalent negative PHP/Ruby
  same-owner assertions. The merge also aligned this branch with cache schema
  version 12, so the CLI children no longer need any cache override.
- [x] (2026-07-26) Passed `cargo fmt --all -- --check`,
  `git diff --check`, all-target/all-feature Clippy with warnings denied, and
  the complete normal-permission `cargo test --features nlp,python` matrix on
  merged head `5a54b026`. Cargo ran outside the sandbox with its normal
  repository target and every Cargo process ran at niceness 10. The matrix
  included the symbols MCP and CLI surfaces, all LSP tests, the 16-opener cache
  regression, all 147 C/C++ usage tests, and doc tests.
- [x] (2026-07-26) Published reviewed head `d9df6f92` directly to
  `origin/master`. Closed assigned issues #1169, #1170, and #1173 with the
  complete local-gate evidence, then closed #1165 after its exact pushed-head
  Libgit2 replay completed all 796 inverse targets.
- [x] (2026-07-26) Completed the exact task-ranked C top ten at niceness 10:
  ten completed clean-head envelopes, 90,000 accepted sampled sites, zero raw
  missing, and zero actionable residuals. The primary run's only scope caveat
  was go-ethereum's generated file exceeding the 50,000-candidate ceiling; a
  same-head 250,000-candidate supplement covered all 18 files with zero file
  errors and replaced that envelope.
- [x] (2026-07-26) Independently audited the C selector, heads, all accounting
  partitions, target-limit disposition, raw missing set, and
  BitcoinAddressFinder's selector-faithful zero-file record. Added the durable
  C manifest and narrative under `.agents/docs/reference-differential/`.
- [x] (2026-07-26) Committed and published the C evidence summary, merged the
  concurrently advanced `origin/master`, and repeated formatting,
  all-target/all-feature Clippy, and the complete `nlp,python` matrix on the
  integrated head. Local HEAD, local `origin/master`, and remote master agree
  at `5f04aa52`. Removed every obsolete C diagnostic while retaining only the
  four final raw artifacts through the 110-envelope audit.
- [x] (2026-07-26) Regenerated the live C++ selector and delegated an
  independent Oldskool preflight. Both checks reproduce the planned ten
  repositories and task counts, including stable 32-task and 22-task tie
  ordering; none is excluded by `large-repos.csv`, and all ten clones are
  tracked-clean at the expected readable heads with complete corpus metadata.
- [x] (2026-07-26) Built the clean C++ baseline runner from `baa33f66` in the
  normal repository target at niceness 10, then completed all ten explicit
  task-ranked envelopes at the same niceness. The append-only strict run
  returned the expected status 2 for 488 raw missing rows, not an
  infrastructure failure. All records share fingerprint `f1ba53ab`, have clean
  Bifrost and clone heads, satisfy every accounting invariant, and have no file
  or candidate-limit errors.
- [x] (2026-07-26) Independently audited the ten C++ envelopes and all raw
  rows. Only ESPHome and Qpid reached the deliberate 1,000-target sample
  ceiling; the other eight queried every distinct target. Blosc and libcbor
  have zero raw missing rows, while `ljharb__qs` is a selector-faithful
  zero-eligible-C++-file record.
- [x] (2026-07-26) Searched the complete `FIRD:` issue set and found no
  existing owner for the seven reduced C++ roots. Created issues #1182 through
  #1188 already assigned to `jbellis`, covering temporary construction,
  inherited fields, file-local globals, member calls, non-reference forward
  contexts, nested owner references, and qualified constants. Delegated three
  disjoint first implementations to Oldskool while root retains review,
  integration, replay, publication, and issue closure.
- [x] (2026-07-26) Integrated structured fixes for all seven C++ issue
  families, then addressed three independent review findings: qualified
  free-function calls now retain precedence over same-named construction
  syntax, namespace-scope `const`/`constexpr` linkage honors `extern` and
  `inline` peers, and malformed out-of-line ownership is recovered only through
  a target-guided ambiguity-refusing lookup rather than rewriting declaration
  identity.
- [x] (2026-07-26) Passed all 154 C++ usage-graph tests, all 640
  get-definition tests, all 11 file-local linkage tests, the reference
  differential integration target, and the focused exported-class parser unit.
  Rebuilt the release runner in the normal repository target and replayed the
  Qpid `link.credit` and CCache `detail.mmap.close` production witnesses at
  niceness 10; both completed with zero actionable discrepancy. A final
  Oldskool read-only review found no actionable issue or leftover debug
  scaffolding.
- [x] (2026-07-26) Checkpointed the reviewed C++ fixes at `cf607aee`, then
  passed `cargo fmt --all -- --check`, `git diff --check`,
  all-target/all-feature Clippy with warnings denied, and the complete
  `cargo test --features nlp,python` matrix. Every Cargo process ran outside
  the sandbox at niceness 10 with the normal repository target; the full
  matrix included 1,937 library tests, all symbols MCP/CLI and LSP surfaces,
  every language usage graph, and doc tests.
- [x] (2026-07-26) Fetched advanced `origin/master` at `5476da46` and merged
  it as `70160699`; the concurrent changes touched C++ resolver and extractor
  paths but merged without textual conflicts. On the integrated head,
  formatting, `git diff --check`, all-target/all-feature Clippy, and the
  complete `nlp,python` matrix are green at niceness 10 with the normal Cargo
  target. The matrix now contains 1,943 library tests and again passed the
  complete symbols MCP/CLI, LSP, definition, and language-usage surfaces.
- [x] (2026-07-27) Integrated two later `origin/master` evidence-only commits,
  published clean head `af0968fa`, and rebuilt the release differential runner
  at niceness 10 with SHA-256
  `880157807974ca0b25c6ae575d19df6c08e35ad998435cc1cbd4978dec48121d`.
  The authoritative explicit C++ top-ten replay completed all ten envelopes
  in 233.6 seconds with one shared fingerprint, clean pinned heads, no file
  errors, and no candidate-limit escapes.
- [x] (2026-07-27) Exhaustively dispositioned the clean-head C++ replay's 444
  residual missing rows and reduced its remaining legitimate gap to recovered
  typedef-base qualifier resolution, tracked as #1208. The raw report and
  checksummed ledger remain historical reduction evidence at
  `/mnt/optane/tmp/bifrost-fird/cpp-task-top10-af0968fa.jsonl` and
  `/mnt/optane/tmp/bifrost-fird/cpp-task-top10-af0968fa-missing.tsv`.
- [x] (2026-07-27) Assigned C++ follow-up #1208 to `jbellis` before changing
  code. Its two exact log4cxx witnesses expose one root cause: tree-sitter
  recovers `typedef spi::Filter BASE_CLASS;` inside an export-macro class as a
  qualified declarator plus a displaced `ERROR` identifier, so declaration
  extraction published the false nested alias `LevelRangeFilter$Filter`.
  The reviewed fix recovers `BASE_CLASS` structurally and resolves a
  qualified inherited injected-class name through the nearest unambiguous base
  tier. A negative regression prevents that best-effort path from overriding a
  nearer lexical type alias. Commit `c53d3b9c` passed formatting,
  all-target/all-feature Clippy, all 161 C++ usage tests, the differential
  target, and the complete `nlp,python` matrix; merge head `8d62804b` was
  pushed directly to `origin/master` and #1208 closed. Clean-head exact
  witnesses are consistent at both production sites. Their JSONL SHA-256
  values are `cbe3c35d9a8854e9777fffc50374c07e937e9341b11617f423ca3954fd7943ff`
  and `d3235279aa764e0a515ce9ec1cc74e0270ef61173b4f2596625478eb354ea60a`.
- [x] (2026-07-27) The post-#1208 C++ top-ten replay at clean
  head `8d62804b` completed all ten task-selected envelopes in 1:49:05 at
  niceness 10. All records have clean Bifrost and corpus heads, no file errors,
  no candidate-limit escapes, and one shared fingerprint. Raw missing fell
  from 444 to 152: LMCache 9, Qpid 32, CIRCL 4, libzmq 5, log4cxx 92, and
  CCache 10; ESPHome, Blosc, libcbor, and the selector-faithful zero-eligible
  qs envelope have zero. ESPHome and Qpid alone reached the deliberate
  1,000-target ceiling. The raw report and generated ledger are
  `/mnt/optane/tmp/bifrost-fird/cpp-task-top10-8d62804b.jsonl` and
  `/mnt/optane/tmp/bifrost-fird/cpp-task-top10-8d62804b-missing.tsv`, with
  SHA-256 values `a971c2bbdad85dd5c3228c1e4cda9d207a6349f9d05a93c4ff73ac274af6fe1b`
  and `32f3a55dfa2a1b1427a3e7b26cd7da6ef54dafb82079da9c5020e18f37860c45`.
  This is complete historical evidence but not an acceptance artifact: an
  exact log4cxx range resolved correctly in same-head ephemeral mode while the
  persisted envelope returned the pre-#1208 synthetic declaration identity.
- [x] (2026-07-27) Reopened assigned issue #1208 after proving the persisted
  C++ epoch still accepted pre-fix parsed blobs. Added a C++-scoped epoch salt
  for the recovered typedef-base identity change and an exact store regression
  that reconstructs the previously accepted corpus epoch
  `098fd5644803843b42c6da3dea0ddea7f5036faf404414d146a9021ed6d265f9`,
  writes a parsed blob under it, switches through the public current-epoch
  path, and proves the stale blob is invisible. An independent Oldskool review
  found no actionable issue. Formatting, all-target/all-feature Clippy, the
  focused regression, and the complete `cargo test --features nlp,python`
  matrix are green outside the sandbox at niceness 10 with the normal Cargo
  target; the matrix skipped only the separately known hanging Ruby LSP test.
- [x] (2026-07-27) Merged current `origin/master` at `a913c29c` into the
  epoch-correction checkpoint as `7591e788`. The post-merge full matrix then
  reproduced the watcher single-flight regression's five-second callback
  timeout twice under suite load even though the exact test passed in 0.07
  seconds. After searching the complete issue tracker, created and assigned
  `FIRD:` issue #1211 to `jbellis` before editing. An Oldskool diagnosis and
  implementation review confirmed that the timeout covered synchronous
  persisted-workspace construction, not just watcher publication, so the test
  now uses an explicit 30-second bounded hang watchdog instead of an accidental
  five-second performance contract. The exact regression and the complete
  `cargo test --features nlp,python` matrix pass outside the sandbox at
  niceness 10 with normal Cargo storage.
- [x] (2026-07-27) Committed #1211 as `4b43b528`, fetched the concurrently
  advanced `origin/master` at `85771d08`, and merged its C++ reconciliation
  and symbols-search changes as `c4d871a4`. A delegated Oldskool overlap audit
  confirmed that the new C++ reconciliation is a separate resolution-time
  overlay: the #1208 parser identity fix, C++ epoch salt, reconstructed prior
  epoch, and exact log4cxx regression all remain intact. On that integrated
  head, formatting, `git diff --check`, all-target/all-feature Clippy, and the
  complete `cargo test --features nlp,python` matrix pass outside the sandbox
  with normal Cargo storage at niceness 10. The matrix passed 1,964 substantive
  library tests, 194 LSP tests with the separately known Ruby hang filtered,
  28 MCP tests, all 161 C++ usage tests, the exact #1208 differential
  regression, and doc tests.
- [x] (2026-07-27) Published the #1208 epoch correction and closed the issue
  after exact persisted and ephemeral log4cxx witnesses agreed. The new-epoch
  clean-head C++ replay at `003a2be4` completed all ten envelopes with no file
  or candidate-limit errors and reduced the trustworthy residual set to 150
  rows. The corrected exhaustive disposition maps every row to assigned
  issues: #1182 (2), #1184 (9), #1185 (11), #1186 (47), #1187 (64),
  #1190 (16), and #1221 (1). The correction moves two template-specialization
  declaration heads from #1190 to #1186 and separates one implicit-self field
  read from #1187 into #1221.
  The accepted raw report and complete ledger are
  `/mnt/optane/tmp/bifrost-fird/cpp-task-top10-003a2be4.jsonl` and
  `/mnt/optane/tmp/bifrost-fird/cpp-task-top10-003a2be4-missing-v2.tsv`,
  with SHA-256 values
  `959cd6350db4194f9e14ce73d567206ddedc41bf6b4e0d37b21e71b5df4f64d7`
  and
  `f51583f2390d3df592c502d2d380a2ac638ee46d63c6e205a0afb7f1a8597683`.
- [x] (2026-07-27) Diagnosed the replay's 72-minute ESPHome pre-inverse gap,
  created and assigned #1215 before implementation, reused root-independent
  linkage classification across the 477-root batch, and added explicit
  visibility progress. The same-limits clean production replay preserved every
  summary count while reducing visibility setup from 4,341.8 to 562.7 seconds
  (7.72x). Formatting, all-feature Clippy, and the complete `nlp,python`
  matrix passed on the merged head; `1409d086` was pushed to `origin/master`
  and #1215 closed.
- [x] (2026-07-27) Resolved assigned #1220 by replacing the per-global cloned
  workspace declaration scan with an exact-FQN definition-bucket lookup while
  preserving logical-symbol and explicit-external checks. A bounded regression
  proves that one relevant peer is inspected despite 32 unrelated globals.
  Formatting, all-feature Clippy, focused linkage regressions, and the complete
  `nlp,python` test matrix passed at niceness 10 with normal Cargo storage.
  Implementation commit `9ac8a4d9` was integrated and pushed at `123670bc`;
  #1220 is closed.
- [x] (2026-07-27) Resolved assigned #1184 at the shared authoritative-batch
  boundary. `VisibilityIndex` now retains the field-only internal-linkage
  classifications already produced for its identifier index, and internal
  globals are visible only from roots that reach the target source rather than
  through a same-name declaration in a sibling translation unit. Cache misses
  remain correct for explicit scopes by classifying the target on demand. One
  two-root `CppAuthoritativeUsageBatch` regression proves exact byte ranges for
  both anonymous-namespace constants; all 12 issue-linkage tests, formatting,
  all-feature Clippy, all 161 C++ usage tests, and the complete `nlp,python`
  matrix pass with normal Cargo storage at niceness 10.
- [x] (2026-07-27) Resolved assigned #1186 by rejecting structured C++ type
  declaration heads from forward definition lookup while preserving real tag
  type references and owner qualifiers in out-of-line tagged definitions.
  Focused regressions cover template-specialization heads, typedef targets,
  qualified enum parameter types, and out-of-line nested owners. Formatting,
  all-target/all-feature Clippy, all 646 definition-lookup tests, all 161 C++
  usage tests, and the complete `nlp,python` matrix pass with normal Cargo
  storage at niceness 10. This removes the 47 non-reference declaration
  contexts from the differential's forward premise rather than manufacturing
  inverse usages for them.
- [x] (2026-07-27) Isolated the remaining `syslogEquivalent` implicit-self
  field read from the outer-owner qualifier family, created #1221 with the
  required `FIRD:` prefix, and assigned it to `jbellis` before implementation.
  A current-head exact replay confirms that forward resolves
  `LOG4CXX_NS.Level.syslogEquivalent` while authoritative inverse returns no
  hit; the issue remains queued behind the already-started #1182 publication.
- [x] (2026-07-27) Resolved assigned #1182 at its two exact corpus sites.
  Qualified direct temporaries now preserve the terminal type-token range,
  constructor declarations misindexed as free functions are recognized from
  their structured class ancestry, and target-guided namespace imports
  conservatively reconcile macro-spelled declaration namespaces. The exact
  Qpid and log4cxx artifacts report one consistent site and zero missing sites
  each: `issue-1182-qpid-exact-6e0ce028-final.jsonl` has SHA-256
  `6b7dac12941f5a7ede572647527cdb96e03c9a12be3e90e8f2af9b8acdc94553`;
  `issue-1182-log4cxx-exact-6e0ce028-final.jsonl` has SHA-256
  `14f61f675f217fdcbe161f7f8d2582571f287a776023976728d5f1748befca7f`.
  Focused metadata and end-to-end regressions, formatting, all-feature Clippy,
  and the complete `nlp,python` test matrix with eight test threads pass using
  normal Cargo storage at niceness 10.
- [x] (2026-07-27) Resolved assigned #1185 by admitting a receiver or recovered
  out-of-line owner only when the query target group contains its specific
  physical declaration/body owner peer and that peer's declaration source is
  visible from the scanned file. Same-FQN owners without that relationship
  remain conservatively unproven. The behavior regression covers explicit
  receivers, templated bare implicit-self calls, wrong owners, and free
  functions; all 162 C++ usage tests, formatting, and all-target/all-feature
  Clippy pass with eight jobs at niceness 10. Final-reviewed exact evidence:
  Qpid `credit` is consistent with SHA-256
  `02d825b29bb7c582c858256633f7538c028cf631c7a8204336e03c4004a6163c`;
  Qpid `connection` is consistent with SHA-256
  `41e39bafb213cefb31b6921a4901178c2edd9f135317d33eb89e011cb11c9267`;
  libzmq `start` is an exact editor-only self-receiver with SHA-256
  `b62447367a064ae84bc025c7bbdad48b5a135f565c37ad7f43bb404856943c16`;
  and libzmq `get_tid` is consistent with SHA-256
  `b4e85b9a6940bf93ff79f0d49a5d7d97a7d289dcffb33ff136f85607c750d1c5`.
- [x] (2026-07-28) Published the remaining mapped C++ repairs through clean
  head `d3a3e9b6`: #1187 and #1221 restore structured nested-owner and
  implicit-self field ranges, while #1190 restores declaration, template,
  alias, using, and cast type references without admitting wrong-owner or
  callable-shadow false positives. The final #1190 commit is `786bf00a`;
  formatting, all-target/all-feature Clippy, all 168 C++ usage tests, all 28
  workspace-graph tests, and the complete `nlp,python` matrix pass at niceness
  10 with normal Cargo storage. Exact Qpid, libzmq, and log4cxx witnesses are
  consistent, two independent Oldskool reviews found no blocker, the changes
  are pushed to `origin/master`, and all three assigned issues are closed.
- [x] (2026-07-28) Ran a clean `d3a3e9b6` C++ top-ten certification with four
  concurrent repository jobs and twelve inner workers. All ten envelopes
  completed in 5:09 with no file or candidate-limit errors. Exact-key
  reconciliation reduced the trusted 150-row ledger to 81 current raw rows:
  80 are mapped survivors and one new Qpid key was absent from the ledger.
  Exact replay proved that bytes `5194..5200` select only the `source` owner in
  `enum source::distribution_mode`, while forward lookup incorrectly returns
  the same-named `distribution_mode()` method. Created `FIRD:` issue #1226
  already assigned to `jbellis` before implementation and delegated the
  structured forward-resolution correction to Oldskool.
- [x] (2026-07-28) Completed the Python top-ten certification at clean pushed
  head `d3a3e9b6`. All ten envelopes completed in 6:49 with one shared
  fingerprint, clean Bifrost and repository heads, no file errors, no
  candidate-limit event, and complete inverse target coverage. Exact identity
  comparison against the 379-row pre-#1225 report removed only the two fixed
  Caikit witnesses, retained the 377 previously dispositioned non-actionable
  module/import-collision rows, and introduced zero novel identities. Added
  `.agents/docs/reference-differential/python-task-top10-d3a3e9b6-summary.md`
  with the provenance, aggregate accounting, checksums, repair evidence, and
  final zero-actionable disposition.
- [x] (2026-07-28) Published the final C++ repairs and closed their assigned
  issues. #1226 rejects the misbound Qpid qualified-type owner range; the
  corrected #1185 preserves concrete receivers and structured out-of-line
  operator ownership; and corrected #1186 follows only contiguous erroneous
  tree-sitter wrapper siblings in recovered CIRCL macro tails. Final commits
  `4edf61e3`, `e1acf863`, and `5e17ecf5` are on `origin/master`. Focused issue
  suites, all 168 authoritative C++ usage tests, all 28 workspace-graph tests,
  all 651 definition tests, formatting, and all-target/all-feature Clippy pass
  with normal Cargo storage at niceness 10.
- [x] (2026-07-28) The clean `5e17ecf5` C++ task-selected top-ten
  certification completed all ten envelopes in 5:13.45. All records share
  fingerprint `93d14bd1`, have clean Bifrost and clone heads, and report zero
  file or candidate-limit errors. Across 72,177 sites, the run classified
  10,422 consistent, 367 editor-only, 1,034 unproven, 60,296 inconclusive,
  and 58 raw missing. Exact-key comparison against the clean `d3a3e9b6`
  report removed 23 identities and introduced none; the 58 survivors are the
  already-audited non-actionable subset of 56 declaration/type/self-owner
  heads and two exact-unproven Qpid link-unit calls. The report SHA-256 is
  `9397f5381ee975b7a894cdd44c7bccd76c598524d1260fab32a5a26dadfa8e70`;
  the log SHA-256 is
  `05e23c9dd00b2e919e17ff953864cb1eee8239de7c18987755ea362d60f29e36`.
  Durable provenance, per-repository accounting, exact evidence, and residual
  disposition are in
  `.agents/docs/reference-differential/cpp-task-top10-5e17ecf5-summary.md`.
- [x] (2026-07-28) Merged concurrent `origin/master` head `b60688de` after
  confirming its CLI and Git-selector changes were disjoint from the final
  differential repairs. The integrated symbols CLI target passed all 28 tests.
  The final feature-enabled matrix then exposed two Python usage-graph
  regressions in the inverted lexical merge. After finding no existing owner,
  created and assigned `FIRD:` issue #1229 to `jbellis` before editing.
  Complete indexed top-level function facts now remain authoritative, while
  nested functions and lambdas continue to merge structural local shadows.
  Focused Python suites, formatting, all-target/all-feature Clippy, and the
  complete `cargo test --features nlp,python` matrix pass at niceness 10 with
  normal Cargo storage. Commit `3235743d` is on `origin/master`, and #1229 is
  closed.
- [x] (2026-07-28) Verified the accepted eleven-language set comprises all 110
  task-selected repository envelopes, every campaign fixing commit is an
  ancestor of remote `origin/master`, and local HEAD, the remote-tracking ref,
  and the hosted master agree after publication. Removed 38 GB of disposable
  corpus reports, logs, ledgers, caches, and exact diagnostics from the exact
  campaign scratch directory plus the three named Qpid files in `/tmp`; the
  compact checked-in summaries retain the final provenance and checksums.
- [x] Publish the remaining mapped C++ semantic issue families and run one final
  task-selected top-ten certification.
- [x] Complete C++ and publish its evidence and user summary.
- [x] Complete C# and publish its evidence and user summary.
- [x] Complete Go and publish its evidence and user summary.
- [x] Complete Java and publish its evidence and user summary.
- [x] Complete JavaScript and publish its evidence and user summary.
- [x] Complete TypeScript and publish its evidence and user summary.
- [x] Complete PHP and publish its evidence and user summary.
- [x] Complete Rust and publish its evidence and user summary.
- [x] Complete Scala and publish its evidence and user summary.
- [x] Complete Python and publish its evidence and user summary.
- [x] Prove all 110 accepted envelopes and every fixing head are present on
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

- C++ `run-corpus` appends completed envelopes in finish order, so the ten
  authoritative records do not appear in selector rank order. Repository
  identity, not JSONL line position, is the acceptance key.

- The C++ baseline has no candidate-limit or file-error escape hatch. Its raw
  discrepancies reduce to recurring structured families rather than repository
  failures: declaration/definition pseudo-reference contexts dominate
  log4cxx, while temporary construction, receiver/member resolution,
  file-local identity, nested-owner ranges, and qualified values recur across
  multiple repositories.

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

- The synchronized C/C++ inverse path repeats declaration-side conditional
  visibility normalization for every broad type occurrence. On libgit2 this
  made the new baseline more than three times slower than the completed
  historical envelope before reaching half its target groups. The differential
  wrapper still shares one prepared batch; the hot work is
  `external_type_candidate_visible_in_context`, which repeatedly enumerates
  logical peers, declaration guards, include projections, and macro stability.

- Libgit2's forward phase also contains a few extreme file outliers: in the
  eager #1165 candidate the first 306 of 312 files finished in 61 seconds, but
  file 311 did not complete until 1,619 seconds. The same unmodified head
  completed all 312 files in 264.9 seconds. The memo must therefore preserve
  the legacy peer/declaration short circuit in forward as well as improving
  repeated inverse work.

- A cache can pass focused semantics and improve early inverse checkpoints
  without removing the true tail. The declaration-guard-only candidate reached
  100 targets 15 percent faster than pre-fix, but its eight remaining broad
  workers (`git_diff`, `git_vector`, `git_str`, `git_index_entry`,
  `git_iterator_status_t`, `git_diff_options`, `git_config`, and
  `checkout_data`) still ran for many minutes. Acceptance therefore requires a
  completed repository envelope and targeted evidence for these broad types.

- The final visibility decision is not the repeated boundary that controls the
  broad-target tail. Exact reference spans are mostly unique, and the
  extractor performs structured type parsing, lexical-scope reconstruction,
  candidate lookup, and alias handling before or around that decision. The
  accepted fix must reject only structurally impossible target/name pairs
  before expensive target-specific resolution, while leaving plausible alias
  and scope cases on the exact legacy path.

- The structured prefilter removed the broad-target tail at its actual source.
  The accepted dirty-candidate replay completed all 796 inverse targets in
  3,060.9 seconds; at the comparable 365-target checkpoint it was about three
  times faster than the pre-fix run. Its one-record envelope covers 326 of 326
  eligible files and 10,000 sites with 1,249 consistent, 13 unproven, 8,738
  inconclusive, and zero missing classifications.

- The prefilter is semantically appropriate only for actual type-reference
  queries. Applying it to static qualifier and method-owner classification
  changed three exact integration results because a known non-target owner was
  weakened to an unproven owner. Passing an explicit query-path flag preserves
  those owner classifiers and keeps the optimization's proof boundary narrow.

- A target-independent alias-name set is only useful when it stays lazy and
  visibility-bounded. Eagerly classifying every parser alias through
  provider-backed APIs caused 140 first-run and 137 warm-run provider calls in
  a scale test whose bounds are 20 and 10. Removing the global classification
  set and consulting only the per-file visible parser-alias cell plus
  same-terminal indexed candidates restored the intended locality.

- The shared same-owner policy made an old PHP usage-graph assertion internally
  inconsistent. `$this->viaInstance()` is intentionally recorded as unproven
  inbound, and targeted PHP usage tests already classify it as `SelfReceiver`;
  only the old graph test still expected a proven edge. Issue #1169 tracks the
  corrected expectation.

- Ruby had the same test drift: the inverted builder deliberately routes a bare
  `local` call as unproven implicit-self inbound, while the old usage-graph test
  expected a proven `calls_local -> local` edge. Issue #1170 tracks the
  correction; all other language graph expectations were audited against the
  shared policy before the next full gate.

- Same-process cache initialization depended on the schema migration finishing
  within each peer connection's five-second SQLite busy window. Under load one
  opener completed while fifteen peers failed or timed out. Issue #1173 fixes
  this at the admission boundary with one weakly retained mutex per canonical
  cache path; SQLite transactions still provide cross-process correctness.

- A clean Bifrost Git head is not sufficient when a language-specific semantic
  change fails to advance that language's analysis epoch. The post-#1208
  persisted log4cxx envelope reused declaration rows whose accepted C++ epoch
  was `098fd5644803843b42c6da3dea0ddea7f5036faf404414d146a9021ed6d265f9`;
  an ephemeral run over the identical file and byte range produced the correct
  `LOG4CXX_NS::spi.Filter` identity. Therefore all 152 residual rows from that
  envelope are untrusted until a new C++ epoch forces a full persisted rebuild.

- The watcher single-flight regression's old five-second receive timeout
  begins before persisted workspace construction, while its callback is
  deliberately blocked to test publication. Under the complete library suite,
  construction alone can exceed five seconds even though an isolated run takes
  0.07 seconds. A longer named watchdog preserves deadlock detection without
  asserting a performance guarantee that the test does not measure.

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

- Decision: Interrupt the `37412679` C run after it supplied reproducible
  #1165 baseline evidence, preserve it under an explicit `aborted` name, and
  rerun all ten repositories from the fixed pushed head.
  Rationale: Any #1165 product change makes the old head ineligible for final
  acceptance. Continuing a multi-hour obsolete envelope would delay the
  required fixed-head proof without adding final evidence. The two completed
  repository records and exact libgit2 progress log remain sufficient
  before/after performance evidence.
  Date/Author: 2026-07-24 / Codex

- Decision: Reject every #1165 cache candidate and optimize the extractor's
  structured target plausibility boundary instead.
  Rationale: Four isolated cache designs either destroyed legacy short
  circuits or failed to remove the eight-target tail. The remaining repeated
  cost is target-specific lexical resolution for unrelated type nodes, which
  can be avoided conservatively using tree-sitter components and indexed
  alias/visibility facts without changing exact proof semantics.
  Date/Author: 2026-07-25 / Codex

- Decision: Accept the two-stage structured prefilter for #1165 and proceed to
  publication gates.
  Rationale: The complete C/C++ usage suite preserves exact direct, qualified,
  alias, inherited-alias, template, guard, macro, and owner-classification
  behavior; work counters prove unrelated bare types bypass lexical scope and
  target-specific resolution; and the decisive unfiltered libgit2 replay
  completed every target with exact accounting and zero missing rows.
  Date/Author: 2026-07-25 / Codex

- Decision: Invalidate the persisted C++ analysis generation for #1208 and
  discard the 152-row post-fix replay as acceptance evidence.
  Rationale: Same-head persisted and ephemeral queries disagree at the exact
  log4cxx witness because the cache still contains the old fabricated
  `LevelRangeFilter$Filter` declaration. Auditing or fixing those rows before a
  language-epoch cutover would turn stale cache artifacts into false product
  work.
  Date/Author: 2026-07-27 / Codex

- Decision: Retain a bounded watcher-startup watchdog for #1211 but raise it
  from five to thirty seconds and name its purpose in the test.
  Rationale: The assertion still detects a failure to publish the one
  single-flight startup outcome, while no longer conflating full-suite
  persisted workspace construction time with the concurrency contract under
  test.
  Date/Author: 2026-07-27 / Codex

- Decision: Use complete indexed lexical facts for a Python top-level function,
  but keep structural recomputation plus inherited-shadow merging for nested
  functions and lambdas.
  Rationale: The index is the only layer with the complete factory-return map;
  recomputing the same top-level function from node-local facts erased precise
  receiver types. Nested scopes still need their own structural bindings, and
  lambdas must retain parameter shadowing rather than inheriting module facts
  unchanged.
  Date/Author: 2026-07-28 / Codex

## Outcomes & Retrospective

The top-ten expansion is complete. All eleven user-confirmed language
boundaries cover their ten live `SFT_PREDICATES` task-selected repositories,
for 110 accepted repository envelopes. C++ closed with 72,177 classified
sites, 58 exhaustively audited non-actionable raw rows, and no new or
actionable residual; Python closed with 87,254 sites, 377 previously audited
non-actionable module/import-collision rows, and no new identity. The durable
C++, Python, and earlier language evidence records the exact selections,
immutable heads, accounting, checksums, and residual dispositions.

Every legitimate defect found during the expansion was assigned to `jbellis`
before implementation, fixed with structured behavior coverage, published
directly to `origin/master`, and closed. The final integration-only discovery,
#1229, corrected the Python inverted graph's indexed-versus-structural lexical
scope boundary and passed the complete feature-enabled local matrix. Final
local HEAD, local `origin/master`, and hosted master agreed at `3235743d`
before this closing evidence commit. Disposable campaign storage was removed
only after compact provenance had been checked in: 38 GB under
`/mnt/optane/tmp/bifrost-fird/` and three named Qpid scratch reports under
`/tmp` are gone and cannot be recovered.

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

At the language publication boundary, run formatting, all-target and
all-feature Clippy, and the complete `cargo test --features nlp,python` gate
normally outside the sandbox at niceness 10. Commit only campaign files with a
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

    nice -n 10 cargo build --release --bin bifrost_reference_differential
    git rev-parse HEAD
    sha256sum target/release/bifrost_reference_differential

The C command shape is:

    set -o pipefail
    /usr/bin/time -v nice -n 10 \
      target/release/bifrost_reference_differential run-corpus \
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
    nice -n 10 cargo clippy --all-targets --all-features -- -D warnings
    BIFROST_SEMANTIC_INDEX=off nice -n 10 \
      cargo test --features nlp,python

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

Run Cargo normally outside the restrictive sandbox at niceness 10. Do not set
`CARGO_TARGET_DIR` or create Cargo targets under `/tmp`. Use
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

Revision note (2026-07-26): Recorded the completed focused, Clippy, library,
LSP, and MCP gates, the linked-primary schema drift that requires merging
current master before the final integration pass, and the user's direct
instruction to run normal Cargo/Bifrost work at niceness 10 without temporary
Cargo targets.
