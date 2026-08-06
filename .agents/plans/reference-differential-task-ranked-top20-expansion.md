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
- [x] (2026-08-02 16:45Z) Complete C ranks eleven through twenty and publish
  its evidence and user summary.
  - [x] (2026-08-01 05:47Z) Built release runner `913e3d98` outside the
    sandbox at niceness 10 with normal Cargo storage; SHA-256
    `dad8dab06932e8890ed0521b1cf61738dafa8a0e8f18a17377aa6422ba9ae95b`.
    The explicit all-ten C dry-run returned exactly the selected slugs.
  - [x] (2026-08-01 05:47Z) Completed C rank eleven
    `trifectatechfoundation__sudo-rs` at pinned head `f48bb86`. Its clean
    selector-faithful envelope has zero eligible/audited files, zero missing,
    and zero file errors because the clone has no `.c` translation unit (207
    Rust files and one header). Raw JSONL SHA-256 is
    `bf8b8eae4c3eab979a5de990a4629dba94999e4798d2dc84e7bdd6236a2f1efd`.
    No issue was warranted. Final language replay and durable publication are
    still required.
  - [x] (2026-08-01 06:01Z) Completed C rank twelve
    `raphw__byte-buddy` at pinned head `fe2f8d0`. Its clean envelope audited
    1/1 eligible production C file, 176 sites, and 4/4 inverse targets with
    zero missing rows, errors, limits, skips, or truncation. Raw JSONL SHA-256
    is `1a214a8353323286ae58b2d95f7c52cca6d1e56c0b5d919df4bba3c402c8ba0d`.
    No issue was warranted.
  - [x] (2026-08-01 06:03Z) Completed C rank thirteen
    `LMCache__LMCache` at pinned head `495cc9a`. Its selector-faithful C
    envelope has zero eligible/audited files because the clone contains C++
    and CUDA sources but no `.c` translation unit. It reported zero missing
    rows and errors. Raw JSONL SHA-256 is
    `d03adff79d74616fe930727ae6a4e380811275818c3353bf13caa13a1d53618c`.
    No issue was warranted.
  - [x] (2026-08-01 06:12Z) Completed C rank fourteen
    `DaveGamble__cJSON` at pinned head `fb16e5c`. Its clean envelope audited
    6/6 eligible files, 5,291 sites, and 115/115 inverse targets with zero
    missing rows, errors, limits, skips, or truncation. Raw JSONL SHA-256 is
    `3200574f2c40c98440417fca1a3b3283fe1b785131e348a9a34180ba99c52f11`.
    No issue was warranted.
  - [x] (2026-08-02 15:01Z) Completed C rank fifteen
    `unicorn-engine__unicorn` at pinned head `7c5db941`. Its mandatory
    250,000-candidate supplement is correctness-clean across 258/258 files,
    651,656 candidates, 10,000 sites, and 697/697 targets. The inverse phase
    exposed severe shared-cache contention, owned by Jonathan-assigned issue
    #1433. The fix landed on `origin/master` through `c5770999`, after the exact
    clean merge-head replay at `666f7c04` repeated zero missing/actionable
    findings in 53.2 seconds. Issue #1433 was closed at 2026-08-02T15:01:39Z.
  - [x] (2026-08-02 15:11Z) Completed C rank sixteen `igraph__igraph` at
    pinned head `e8e03b2`. Its clean selector-faithful envelope audited 958/958
    files, 474,242 structured candidates, 10,000 sites, and 684/684 inverse
    targets in 23.9 seconds. It reported zero missing/actionable findings,
    file errors, candidate-limit exclusions, skipped or truncated targets, or
    configured-limit failures. The 24 `unproven` rows are honest structured
    ambiguity, not claimed misses. Open-and-closed issue search found no
    igraph-specific owner and no clean-envelope symptom warranting a new
    ticket. JSONL and log SHA-256 values are
    `ec425987b493aefcd0915bae86c5b774240af758a276f2c17ea31fee2cd8d57b`
    and `7e14fc804388325240ebf1f5acc54199ae516ff04fb04e024e35bb2778bb42fc`.
  - [x] (2026-08-02 16:26Z) Completed C rank seventeen `libuv__libuv` at
    pinned head `4b9d359b`. The starting envelope's one missing
    `uv_tty_set_mode` call exposed C translation-unit lookup admitting a
    `__cplusplus`-only overload in both forward candidate expansion and
    inverse argument filtering. Jonathan-assigned issue #1465 is fixed and
    closed through implementation commit `6e2b80ac`; the exact merged-head
    replay at pushed `origin/master` `442890bb` is 1/1 consistent and its
    JSONL SHA-256 is
    `05fcc7072c5f6133a6d5e1f3ed24c307119dbc968585044ba8e5220c34e285e5`.
    The full clean envelope audited 120/120 files, 66,928 structured
    candidates, 10,000 sites, and 512/512 targets, with 1,015 consistent, 21
    honestly unproven, 8,964 inconclusive, and zero missing/actionable rows;
    it had no errors, skipped or truncated targets, or configured-limit
    failures. Its JSONL SHA-256 is
    `69d06bf975b47de0929714d66c82380805592a98d09429781ed6a491a332d54a`.
    Both records report clean Bifrost and corpus worktrees. Formatting, the
    focused C/C++ tests, all seven pool-memo tests, and strict all-target,
    all-feature Clippy pass. Jonathan-assigned issue #1467, found during that
    Clippy gate, was independently fixed upstream by `a02b2b09`; the merge
    retained upstream's version and the superseded ticket is closed.
  - [x] (2026-08-02 16:30Z) Completed C rank eighteen
    `Mbed-TLS__mbedtls` at pinned head `9e9eb069`. The live selector still
    reports 19 qualifying tasks and excludes it from `large-repos.csv`. Its
    clean envelope audited 59/59 eligible C files, 67,431 structured
    candidates, 10,000 sites, and 214/214 inverse targets in 8.1 seconds. It
    reported 494 consistent, 30 honestly unproven, 9,476 inconclusive, and
    zero missing/actionable rows, with no file errors, candidate-limit
    exclusions, skipped or truncated targets, or configured-limit failures.
    Both Bifrost and corpus worktrees were clean. The JSONL and log SHA-256
    values are
    `8cd16e9c899d728a899ba8c50cc720ee8825b20668c9b71e3422250435863a69`
    and
    `6f1d03a29c4fd58cec6f783d917b8e09faee3a3349a151502d253e59e5c374b7`.
    Independent oldskool review found no Mbed-specific or open matching issue;
    related closed C visibility issues #1465, #940, #934, #923, and #997 do
    not own a symptom in this clean run, so no issue was warranted.
  - [x] (2026-08-02 16:36Z) Completed C rank nineteen
    `ClusterLabs__pacemaker` at pinned head `e561664d`. The live selector
    reports 19 qualifying tasks and excludes it from `large-repos.csv`. Its
    clean envelope audited 248/248 eligible C files, 218,054 structured
    candidates, 10,000 sites, and 952/952 inverse targets in 62.4 seconds. It
    reported 1,648 consistent, 63 honestly unproven, 8,289 inconclusive, and
    zero missing/actionable rows, with no file errors, candidate-limit
    exclusions, skipped or truncated targets, or configured-limit failures.
    The JSONL and log SHA-256 values are
    `89b300164dbadaf68e27385def6d573a4313a0d5e7ae663eb4311f347730d742`
    and
    `983f81024773d0fbfebb4d5972786ee40e1bb9bb904fadcf7963571cb6257a20`.
    The eight-worker run's broad `pcmk__resource` target spent 27.8 seconds
    in flight, so it was not dismissed from aggregate timing alone. An
    ephemeral exact one-target control completed the inverse phase in 0.9
    seconds and the entire run in 2.1 seconds, demonstrating shared-run
    scheduling/CPU overlap rather than an isolated plugin-latency regression;
    its JSONL SHA-256 is
    `2fa6bb4788e481ebe9c60f6fe173b4a3bee6d6de1c47490715e5800d8115bc6e`.
    Independent oldskool review and open/closed issue search found no
    Pacemaker-specific owner or new symptom, so no issue was warranted.
  - [x] (2026-08-02 16:40Z) Completed C rank twenty
    `getvictor__fleet-edr` at pinned head `69ad7b8a`. The live selector reports
    18 qualifying tasks and excludes it from `large-repos.csv`. Its clean
    envelope audited both eligible C translation units, all 402 structured
    candidates, all 392 sites, and 5/5 inverse targets in 1.2 seconds. It
    reported 52 consistent, 340 inconclusive, and zero unproven,
    missing/actionable, or editor-only rows, with no file errors,
    candidate-limit exclusions, skipped or truncated targets, or
    configured-limit failures. Both Bifrost and corpus worktrees were clean.
    The JSONL and log SHA-256 values are
    `ab5baa30efb1353ba759e9cd1a1dc9cd9ff67b0aec1e20942a0a34fed5e2e377`
    and
    `a9b4282d03252e3c86de3207b9e5d2368cff32203a65bd5094ba96fb2e163600`.
    Independent oldskool review specifically checked the direct
    `bridge.c` inclusion of `xpc_bridge.c` and its Clang Blocks/callback
    syntax against closed Jonathan-owned owner #928; the clean envelope and
    issue search exposed no Fleet-specific or open matching symptom, so no
    issue was warranted.
  - [x] (2026-08-02 16:45Z) Rebuilt from clean pushed head `f8e5022d` and
    certified all ten selected repositories serially. The accepted set uses
    nine records from the standard-cap run plus Unicorn's mandatory complete
    250,000-candidate replacement. It contains 1,652/1,652 files, 1,484,401
    candidates, 55,859 sampled sites, and 3,183/3,183 inverse targets, with
    zero missing rows, errors, skips, truncation, or candidate exclusions.
    The durable manifest and narrative are
    `.agents/docs/reference-differential/c-task-ranks11-20-f8e5022d.jsonl`
    and its `-summary.md` companion. Their SHA-256 values are
    `03032e1666b255dd51b7301ae68e004d55b28f5bead89864ab6bc6d59755402b`
    and
    `fd816b03037760fde6fa5f2b0df1bd776859f18b9da63816467ad163d3169e72`.
    Final live GitHub audit confirms #1433, #1465, and #1467 are closed and
    assigned only to `jbellis`.
- [ ] Complete C++ ranks eleven through twenty and publish its evidence and
  user summary.
  - [x] (2026-08-02 17:04Z) Completed C++ rank eleven
    `libarchive__libarchive` at pinned head `40a71c83`. The live selector
    reports 20 qualifying tasks and excludes it from `large-repos.csv`. Its
    clean envelope audited all 98 eligible files, 11,354 structured
    candidates, 8,324 sites, and 344/344 inverse targets in 3.6 seconds. It
    reported 1,598 consistent, 173 unproven, 6,553 inconclusive, and zero
    missing/actionable or editor-only rows, with no file errors,
    candidate-limit exclusions, skipped or truncated targets, or configured
    limit failures. Both Bifrost and corpus worktrees were clean. The JSONL
    and log SHA-256 values are
    `6e2b018e7864f1f9ba8e16782c7add280e01e950f127c86c79c74b5498fc140a`
    and
    `3e81b49cb43695503ea18591a5e303d46f70e09f381aeba36f7512e15d17712c`.
    Independent oldskool review covered the C-linkage APIs, repeated fuzzer
    entry points, callbacks, platform/config guards, and the optional
    Clang/LLVM tool. Its open and closed issue search found no open
    libarchive-specific or C++ inverse owner and no new symptom, so no issue
    was warranted.
  - [x] (2026-08-02 17:10Z) Completed C++ rank twelve
    `DaveGamble__cJSON` at pinned head `fb16e5cf`. The live selector reports
    19 qualifying tasks and excludes it from `large-repos.csv`. Its clean
    header-as-C++ envelope audited both eligible public headers, all 612
    structured candidates, all 571 sites, and 3/3 inverse targets in 0.3
    seconds. It reported 142 consistent, 429 inconclusive, and zero unproven,
    missing/actionable, or editor-only rows, with no file errors,
    candidate-limit exclusions, skipped or truncated targets, or configured
    limit failures. Both Bifrost and corpus worktrees were clean. The JSONL
    and log SHA-256 values are
    `7fb9cfcf00e471392e367cd8f412f2ea4b23a1d2d0f1bd7f45f0e67206d8fbac`
    and
    `e896015621146b7815043006a008039c22dc58cc41122f9fbec1c828aeda5619`.
    Independent oldskool review covered the `extern "C"` groups,
    `CJSON_PUBLIC` visibility/calling-convention macros, callbacks,
    self-referential structures, and platform/config guards. Closed
    Jonathan-owned #1122 explicitly used cJSON for the same-file macro gap;
    the clean envelope and open-issue search exposed no current cJSON-specific
    symptom, so no issue was warranted.
  - [x] (2026-08-02 17:17Z) Completed C++ rank thirteen
    `open62541__open62541` at pinned head `1fe3a857`. The live selector reports
    19 qualifying tasks and excludes it from `large-repos.csv`. Its clean
    envelope audited all 78 eligible files and all 22,064 structured
    candidates, then compared the configured deterministic 10,000-site sample
    against 312/312 inverse targets in 3.6 seconds. It reported 2,634
    consistent, 123 unproven, 7,243 inconclusive, and zero missing/actionable
    or editor-only rows, with no file errors, candidate-limit exclusions,
    skipped or truncated targets, or configured inverse-query limit failures.
    Both Bifrost and corpus worktrees were clean. The JSONL and log SHA-256
    values are
    `c47e889f84614766ce14b3d7004e7bf7ac0fb90c0c75d2a463fc1f103f3bace3`
    and
    `a21953e486a49e927f0f29c457b005a426f261d5ee85f4a962a5590091623a78`.
    Independent oldskool review covered its C++ fuzz/test consumers, repeated
    C-linkage entry points, public/generated/plugin headers, callbacks,
    feature/config guards, opaque types, and vendored portability code. Direct
    and related open-issue searches found no owner or new symptom, so no issue
    was warranted.
  - [x] (2026-08-02 19:26Z) Completed C++ rank fourteen `google__wuffs` at
    pinned head `46ac36bd`. The live selector reports 18 qualifying tasks and
    excludes it from `large-repos.csv`. Its starting strict envelope audited
    all 36 eligible files and 17,918 structured candidates, then found 23
    missing rows in the deterministic 10,000-site sample: 17 typedef-alias
    outer qualifiers and 6 generated constructor calls. Jonathan-assigned
    issues #1470 and #1471 were created and verified before implementation.
    The root cause shared by both shapes was type-spec deduplication retaining
    a same-FQN declaration from a generated file not physically included by
    the consumer while another queried physical peer was visible. Commit
    `4e5533cc` selects that visible logical peer before applying structured
    lexical constructor or exact canonical-alias proofs, with ambiguity,
    shadow, namespace, and unrelated-name controls. It reached
    `origin/master` through merge head
    `6d6f6661af32bc85d47764f0edf7fdb291fee5dd`; both issues auto-closed there,
    remain assigned only to `jbellis`, and carry post-merge evidence comments.
    The exact constructor and qualifier reproducers each report
    `actionable=0`; their JSONL SHA-256 values are
    `bbada54ba9ae7c97046a8d1826f7f5af6dd94b1539f4f2dcd6cb285e3d4cbc90`
    and
    `e9a4bfe9cd026a67b84efefc15bba7c50be3a45fa8cd6857693eb35ea2849fc8`.
    The accepted clean-head full replay audited 36/36 files, 605,282 source
    bytes, all 17,918 candidates, 10,000 sampled sites, and 585/585 inverse
    targets in 311.2 seconds. It reported 2,087 consistent, 16 editor-only, 66
    honestly unproven, 7,831 inconclusive, and zero missing/actionable rows,
    with no file errors, candidate-limit exclusions, skipped or truncated
    targets, or configured-limit failures. Its JSONL and log SHA-256 values
    are `1c94eefad773c7b82a0a24e26f544c11350d662bd9966c77f701eea6b127296f`
    and `acf44e34ba6350f1538a221b60a22b1d615c01e5aeb9b79d04f5dc9597b78e41`;
    the exact-head release runner SHA-256 is
    `4f79886714397f39381a517a762d83dfbdf5d6aeff5128e827655fa390b5f66f`.
    The final 166-test C++ usage module and strict all-target, all-feature
    Clippy pass on the merged tree. A full featureless run twice exposed only
    the pre-existing concurrent wall-clock flake in
    `csharp_scan_usages_truncated_scan_does_not_report_verified_absent`
    (1,457 sibling tests passed); that exact C# test passes alone in 0.75
    seconds. Independent oldskool review found no blocker and root review
    removed all temporary diagnosis instrumentation before commit.
  - [x] (2026-08-03 02:42Z) Completed C++ rank fifteen
    `BehaviorTree__BehaviorTree.CPP` at pinned head `4630e066`. Its starting
    envelope audited all 168 eligible files, 85,531 structured candidates,
    10,000 sites, and 835 inverse targets, exposing 81 missing rows across a
    related family of C++ declaration ownership, template, macro, and inverse
    resolution defects. Jonathan-assigned issues #1484 through #1490, #1494
    through #1497, and #1523 were fixed depth-first in the repository through
    implementation commit `1c570a35` and pushed merge head `a8957399`. The
    final clean replay queried all 935 distinct targets with zero missing,
    skipped, truncated, or error rows. Its JSONL and log SHA-256 values are
    `9226096a6e139deb4c29c52096b13cf825a55a0249dcca7f891f4bfdf24fbfa7`
    and
    `3ca260b1e163edd3916a0f6310ea15ab767ad38cc40445e3acb5a624e2cfeee3`.
  - [x] (2026-08-05) Revalidated C++ rank fifteen after later C++ resolver
    changes at Bifrost `e926cd4d`. The new baseline audited 168 files and
    10,000 sites against 941 inverse target groups. It exposed 27 missing
    rows in four related structured C++ root causes. Jonathan-assigned issues
    #1684 through #1687 cover partial-specialization alias ownership, owner
    qualifiers, template forward-declaration names, and class-owned aliases.
    The grouped fixes were pushed through commits `0e6df36d` and `780cacc6`.
    Exact probes for `invalid_iterator`, `error_handler_t`, `value_t`, and the
    final `error_type` witness are consistent. The stable featureless CLI
    suite, six focused BehaviorTree tests, and strict workspace all-target,
    all-feature Clippy pass. The final clean replay at pushed head `780cacc6`
    audited all 168 files, 10,000 sites, and 944 target groups with zero
    missing, skipped, truncated, or file-error rows. Its JSONL SHA-256 was
    `54c0858e85ff10d1cf564562ce82db39f38a804412524fc98e64c304dbc457a3`.
    Issues #1684 through #1687 are closed with the clean evidence.
  - [x] (2026-08-03 03:21Z) Completed C++ rank sixteen
    `GoogleCloudPlatform__esp-v2` at pinned head `1c176f5a`. Its starting
    81/81-file, 10,000-site envelope queried 535 inverse targets and exposed
    seven missing rows caused by a macro field absorbing its owning class
    terminator. Jonathan-assigned issue #1530 was fixed in `ce58a646` and
    pushed through merge head `6013c8ed`. The clean replay resolved 3,204
    forward sites and queried all 535 targets with zero missing, skipped,
    truncated, or error rows in 3.63 seconds.
  - [x] (2026-08-04 12:02Z) Completed C++ rank seventeen
    `abseil__abseil-cpp` at pinned head `e65a8cbf`. The accepted pushed-head
    replay at clean Bifrost `b235b350` audited 614/614 files, 6,233,064 source
    bytes, 212,425 structured candidates, 10,000 sites, and 1,000 of 1,131
    distinct targets in 89.7 seconds. It reported 1,340 consistent, 73
    editor-only, 107 honestly unproven, 8,478 inconclusive, and two
    configuration-dependent missing rows: a
    `__cpp_lib_containers_ranges >= 202202L` constructor and the fallback arm
    of `__cpp_lib_type_identity`. Neither is actionable without one concrete
    preprocessor configuration. All legitimate rows owned by
    Jonathan-assigned issues #1536, #1537, and #1560 were fixed and closed on
    2026-08-04 through the rank's implementation series, upstream merge
    `8fc8d267`, and final
    sentinel-ordering fix `b235b350`; the five exact beta/discrete probes all
    have exact inverse hits. The final JSONL SHA-256 is
    `c2c7e86251fd2ce16f44c654fc39307c31841c0335f3ce497f7f160c4cae931e`.
    Formatting, all 105 C++ analyzer tests, focused inverse and epoch tests,
    and strict all-target/all-feature Clippy pass. The broad featureless
    workspace run also passed every reached suite except nine MCP CLI tests
    whose default cache path intentionally collapsed to the primary checkout
    and found its newer schema; all 33 affected CLI tests pass against an
    isolated cache, while persistence/default-cache tests pass under their
    normal environment.
  - [x] (2026-08-04 12:14Z) Completed C++ rank eighteen
    `Mbed-TLS__mbedtls` at pinned head `9e9eb069`. The live selector reports
    16 qualifying tasks, applies `not_overlarge=true`, and excludes the repo
    from `large-repos.csv`. Its clean C++ header envelope audited 57/57
    eligible files, 743,297 source bytes, all 6,716 structured candidates, all
    4,522 sites, and 92/92 inverse targets in 2.5 seconds. It reported 409
    consistent, 150 honestly unproven, 3,963 inconclusive, and zero
    editor-only or missing/actionable rows, with no file errors,
    candidate-limit exclusions, skipped or truncated targets, or configured
    limit failures. Both Bifrost `642d77da` and the corpus worktree were clean.
    Existing C rank-eighteen evidence was not reused because it audited `.c`
    translation units rather than this C++ header corpus. Independent oldskool
    review and open-issue search found no Mbed-specific owner or symptom, so no
    issue was warranted. The JSONL and log SHA-256 values are
    `3a722da19f9bd635444c7db9da1946f2dbf89d1158ec57be6caa8602365aadfe`
    and
    `c99f8aedca1a637404d044ce2c8b2f45b78f395aba644c9f0200840a2432a3e6`.
  - [x] (2026-08-04 12:20Z) Completed C++ rank nineteen
    `pyro-ppl__pyro` at pinned head `6cc3ecdc`. The live selector reports 13
    qualifying tasks, applies `not_overlarge=true`, and excludes the repo from
    `large-repos.csv`. Its entire C++ surface is the one 7,746-byte
    `pyro/distributions/spanning_tree.cpp` extension. The accepted clean replay
    audited that file, all 590 structured candidates, all 582 sites, and 4/4
    inverse targets in 0.63 seconds. It reported six consistent and 576
    inconclusive rows with zero editor-only, unproven, or missing/actionable
    rows, and no file errors, candidate-limit exclusions, skipped or truncated
    targets, or configured limit failures. Generated `.bifrost/` and `.brokk/`
    databases were retained and ignored through clone-local metadata before
    the accepted replay; both Bifrost `4446e420` and the corpus worktree report
    clean. Independent oldskool review and open/closed issue search found no
    Pyro-specific owner or symptom, so no issue was warranted. The JSONL and
    log SHA-256 values are
    `81e80740bdda0b4017d1bde7e84d9f78ad470ff6987e451db8ca5ca7cf16d915`
    and
    `2592520007ef93b828ff6a5e10e9c56d0714c55055776ac3fc63bda9397a23b7`.
  - [x] (2026-08-06) Completed C++ rank twenty
    `cppcheck-opensource__cppcheck` at pinned head `4517bc76`. Its fresh
    persisted-cache replay at pushed Bifrost `1f0bd3ac` audited 290 files,
    296,420 structured candidates, 10,000 sites, and all 1,226 inverse target
    groups. It reported 3,137 consistent, 110 editor-only, 33 honestly
    unproven, 6,720 inconclusive, and zero missing rows, with no file errors,
    skipped targets, or truncation. The report SHA-256 is
    `8b6aeab029f8a4ceff0998f07c679dce38e6eeb5e95b6e18bae18041273c7768`;
    the exact-head release runner SHA-256 is
    `59c352607e9c57c171c2a654fb1e0773bf0f5dff8079803bbeecfdae4dcc5363`.
    Jonathan-assigned issue #1691 fixed exhaustive conditional same-FQN alias
    families, physical alias ranges, branch isolation, and C++ store
    invalidation. Jonathan-assigned issue #1694 made cache mode part of the
    repository and corpus completion fingerprint. Both issues are closed and
    assigned only to `jbellis`. Formatting, 233 C++ usage tests, all nine
    differential runner tests, the persisted-cache epoch test, and strict
    workspace all-target/all-feature Clippy pass. The broad featureless run
    reached one unrelated C# wall-clock failure after 1,529 sibling tests;
    that exact test passed alone.
  - [ ] (2026-08-06) Complete the fresh-epoch language certification and
    reclose earlier ranks in repository order. The first ten-repository replay
    at clean pushed head `1f0bd3ac` queried every configured target with no
    file errors, skips, or truncation, but it correctly rejected the language
    envelope. Fresh C++ blobs exposed 34 missing rows in rank-eleven
    libarchive, 16 in rank-thirteen open62541, 7 in rank-fourteen Wuffs, 5 in
    rank-sixteen esp-v2, and 8 in rank-seventeen Abseil. Ranks twelve,
    fifteen, eighteen, nineteen, and twenty remained clean. Triage resumed at
    libarchive; later repositories remain read-only until each earlier rank is
    closed.
    - [x] (2026-08-06 08:11Z) Revalidated rank eleven
      `libarchive__libarchive` at pinned head `40a71c83`. All 34 fresh-epoch
      misses shared one structured cause: a tagged type use with a declarator
      was treated as a local tag declaration. Jonathan-assigned issue #1697
      corrected that shadow test and selected a physically visible peer from
      each repeated same-logical tag group. The fix is closed and pushed to
      `origin/master` at `668af778`. Its regression covers repeated visible
      forward declarations, a hidden-only definition, and a true block-scope
      tag shadow. Formatting, all 234 C++ usage tests, and strict workspace
      all-target/all-feature Clippy pass. The clean-head persisted replay
      audited 98 files and 8,212 sites, then queried all 330 targets. It
      reported 1,632 consistent, 91 honestly unproven, 6,489 inconclusive,
      and zero missing rows, errors, skips, or truncation. Repeated physical
      declarations keep the corrected exact-range rows unproven; the result
      restores inverse presence without claiming one physical identity. The
      report and runner SHA-256 values are
      `1447fac16c2f1fb306245f13c71c921d2b14b34a465d03da1ff080c75725837e`
      and
      `533eb542663ff104142e628503dcc1db8957510005b285decc0705df87df7bac`.
      Rank twelve remains clean in the fresh certification, so the next
      active triage repository is rank thirteen `open62541__open62541`.
    - [x] (2026-08-06 08:29Z) Revalidated rank thirteen
      `open62541__open62541` at pinned head `1fe3a857`. The rank-eleven fix
      removed 15 of its 16 fresh-epoch missing rows. The residual body use was
      hidden because the callable-local shadow scan treated the function's
      tagged return type as a body-local declaration. Jonathan-assigned issue
      #1699 now requires both the declaration and queried reference to be in
      the callable's structured body. It preserves namespace-scope return-tag
      declarations and true block-scope shadows. The fix is closed and pushed
      to `origin/master` at `c628a36c`. The exact witness is consistent, and
      the focused regression, all 235 C++ usage tests, formatting, and strict
      workspace all-target/all-feature Clippy pass. The clean-head persisted
      replay audited 78 files and 10,000 sites, then queried all 302 targets.
      It reported 2,976 consistent, 44 honestly unproven, 6,980 inconclusive,
      and zero missing rows, errors, skips, or truncation. The report and
      runner SHA-256 values are
      `32dc6dfc9abcc2f32935ad0509dd486f3966ad641225c1c6eb1a01d850e08b04`
      and
      `63efc0366803e9bdbe3680f646bcad991ad9d99ab4c1e923b9c963ecde9b090e`.
      The next active triage repository is rank fourteen `google__wuffs`.
    - [x] (2026-08-06 12:00Z) Rank fourteen `google__wuffs` completed
      depth-first repair at pinned head `46ac36bd`. A clean fresh-epoch
      baseline had seven missing rows. The repeated-tag visibility correction
      then changed 37 prior unproven source-fragment rows to missing because
      those generated fragments omit local include envelopes. Jonathan-assigned
      issue #1702 now retains these structured matches as unproven when no
      queried target peer is physically visible. It still rejects a hidden-only
      target group when a different same-logical peer is visible. The fix is
      closed and pushed to `origin/master` through merge head `f1bb2c6f`.
      Focused visibility, repeated-tag, and return-tag tests pass. The full
      featureless gate passed all suites except one known timing-sensitive C#
      truncation test under full load; that exact test passed alone in 0.75
      seconds. The clean-head exact `MemOwner` witness is an exact unproven hit.
      The clean-head full replay audited 36 files and 10,000 sites, then queried
      all 606 targets. It reported 2,142 consistent, 17 editor-only, 75
      honestly unproven, 7,759 inconclusive, and seven missing rows, with no
      file errors, skips, or truncation. The exact report, full report, and
      runner SHA-256 values are
      `50d596748b4cb816f3f1728284bf021fd15de1ec676efc532291ec936469d1d0`,
      `03a81d43dce5f3b9746767d8b0dd0dc511cc6b5d912ee108d2b576742340da67`,
      and
      `407306979b7168b49e71c0b61a070368496f48344729b3f427922896a2b8868b`.
      Assigned issues #1703 and #1704 shared the guarded C++ type-resolution
      path, so one grouped implementation retained both shapes as exact
      unproven evidence. It requires a physically visible target and exact
      structured owner or alias identity. It excludes template alias
      applications and does not relax normal visibility. Commit `98dd40a3`
      reached `origin/master` through merge head `d11ccdb0`; both issues are
      closed and have clean evidence comments. All 239 C++ usage tests pass.
      The four clean exact reports have SHA-256 values
      `598ff6f419973d1c819fb911d86bd104e4ea5355d962f088e236b41ddbc1dbaa`,
      `5c7e5766a24804f3e3695d6c09b65ed872bdf5a5d7ceb06991137eaf11e3d0b2`,
      `72428b588efeac7d86088369c315deb09b461b6f10b0496b38e91ccfe90310e9`,
      and
      `f0a89f823f55b84cdc1d1778b58778dc7125b41bb353d21160c4b46325b7bcc0`.
      The clean full replay now reports 2,142 consistent, 17 editor-only, 79
      honestly unproven, 7,759 inconclusive, and three missing rows. Its
      SHA-256 is
      `abafd6611d0a02daf0638590a74cf0c9fbb51fb5da6942b2bac75860868265c7`.
      Jonathan-assigned issue #1705 found that tree-sitter split a
      function-like macro typedef into a partial `type_definition` and a
      following identifier statement. Bifrost published the macro argument as
      a false alias, which hid the real tagged typedef and three `repr` field
      uses. Commit `507b0bab` now reads structured declarator fields, recovers
      the real sibling alias with its complete signature and range, rejects a
      non-macro near-miss, and invalidates stale C++ parsed blobs. It reached
      `origin/master` through merge head `327a6217`; issue #1705 is closed and
      assigned only to `jbellis`. All 240 C++ usage tests, the focused stale
      generation test, formatting, and diff checks pass.
      The three clean pushed-head exact witnesses are consistent. Their report
      SHA-256 values are
      `c241157503e852cfde7e7a5379a63e148d3bfe6b3814603ff13d0dc5144a1aed`,
      `1c7e430a51eae972ab4ec47b11ac81b42a6e58fd3c687a076d1de2902e4b393d`,
      and
      `1fe79ce07f4f958d2e14f348fe393115b82a92c2726cbfb73a6ae8a9bd548510`.
      The clean full replay audited 36 files and 10,000 sites, then queried all
      622 targets. It reported 2,219 consistent, 17 editor-only, 70 honestly
      unproven, 7,694 inconclusive, and zero missing rows, with no file errors,
      skips, or truncation. The full report and runner SHA-256 values are
      `112bd4443f86683b0ce66ec539103a5d97a405305c17d6c8d74ecbd4d56626cf`
      and
      `6bf35bd98b235d7460aac5cb3ee31cd97870cf8c14b38edbdc08447165df1ff0`.
      The next active repository is rank fifteen.
    - [x] (2026-08-06 12:57Z) Rank fifteen
      `BehaviorTree__BehaviorTree.CPP` completed at pinned head `4630e066`.
      The fresh pushed-head baseline kept zero missing rows across all 957
      inverse targets. It exposed nine `invalid_location` rows for compound C++
      operator names. Seven were declaration-like sites in the vendored JSON
      header. Two were explicit `operator[]` calls. The reference candidate
      frontier retained each complete structured operator range, but the
      differential sent that range through the single lexical-token definition
      location contract. Jonathan-assigned issue #1716 grouped these related
      forms. An oldskool implementation pass and an independent oldskool review
      identified the existing structured point-lookup rule used by call
      relations. Root review moved that rule to the shared reference-candidate
      API, retained complete report and inverse ranges, and preserved the full
      operator evidence text. Commit `a3f77da9` reached `origin/master` through
      merge head `a45fcbab`; issue #1716 is closed and remains assigned only to
      `jbellis`. The focused end-to-end `operator[]` regression passes. It proves
      exact inverse round-trip, declaration exclusion, and the unchanged normal
      identifier path. The featureless workspace library gate passed after the
      one Java parity fixture was skipped because this host lacks `javac` and
      `jar`; the initial unskipped gate passed 1,821 analyzer tests before that
      environment-only failure. The final clean replay audited all 168 files,
      2,181,895 source bytes, 85,336 candidates, and 10,000 sites. It queried all
      957 targets and reported 4,801 resolved forward sites, zero invalid
      locations, 1,920 consistent, 194 editor-only, 110 honestly unproven,
      7,776 inconclusive, and zero missing rows. It had no file errors, skipped
      targets, truncation, or configured-limit failures. The report and exact
      pushed-head runner SHA-256 values are
      `ca5fb63150d88e911b80f405002e28cac50723bf6c514e44cd8ac2748f88e6cb`
      and
      `81f90974a3c547077cef72e35ef4cb23b739964b8dd5c3059ec8561f11ced92a`.
      The next active repository is rank sixteen
      `GoogleCloudPlatform__esp-v2`.
    - [x] (2026-08-06 13:13Z) Rank sixteen
      `GoogleCloudPlatform__esp-v2` completed at pinned head `1c176f5a`.
      The fresh clean replay at Bifrost `4f7218b7` audited all 81 files,
      367,301 source bytes, 14,846 structured candidates, and 10,000 sites.
      It queried all 540 inverse targets. It reported 4,014 resolved forward
      sites, 1,661 consistent, 71 editor-only, 34 honestly unproven, 8,234
      inconclusive, and zero missing rows. It had no invalid locations, file
      errors, skipped targets, truncation, or configured-limit failures. The
      report and exact runner SHA-256 values are
      `9825ce8980dca0b82acc9099641f20c3cd373a8f128c909897171bcff4c44b49`
      and
      `ab8e8801562ec1a967107ded8ef6eff06fdb358aac52a330a88658a46e4a81e8`.
      No new issue was necessary. The next active repository is rank seventeen
      `abseil__abseil-cpp`.
    - [x] (2026-08-06 15:33Z) Rank seventeen `abseil__abseil-cpp`
      completed at pinned head `e65a8cbf`. The fresh baseline at Bifrost
      `f3ceca2c` audited all 614 files and 10,000 sites. It exposed six missing
      rows across one recovered namespace-sentinel root cause. Two were
      qualified `EnableIf` template-alias references. One was a nested
      `StructuredProtoField::Varint` alias. Three were out-of-line
      `ElfMemImage` and `Win32Waiter` owner qualifiers under unknown guards.
      Jonathan-assigned issue #1728 grouped these related forms. An oldskool
      implementation pass, an independent oldskool owner review, and a final
      oldskool cycle review informed the change. Root review retained exact
      structured alias identity, required unique visible candidates, reused
      recovered lexical scope, rejected alias cycles, and kept incompatible
      unknown guards unproven. Implementation commit `0b70286f` reached
      `origin/master` through merge head `46be6d27`; issue #1728 is closed and
      remains assigned only to `jbellis`.
      All 241 C++ usage tests and featureless workspace Clippy pass. The
      featureless workspace unit gate also passes. The full 1,539-test usage
      suite passed 1,538 tests; its unrelated C# wall-clock test failed under
      load and passed alone in 1.04 seconds. All six clean exact probes report
      zero missing. Both `EnableIf` rows and `Varint` are consistent. Both
      Win32 rows retain exact unproven inverse hits. The `ElfMemImage` probe is
      honestly inconclusive because the inverse unproven sample is truncated.
      The exact-report SHA-256 values are
      `d0319c1c0f19be270aebbee396db05895730bd45884289e4fbe18edff69efee4`,
      `38ec5b3b40d560cacfb185a1ba9e1a674977aa4b44630d3ebbf0aec4225bcc64`,
      `ede17800771976dfbf8b7043779a32a32fc6dd599ded9cd410545fdc789ddea3`,
      `c4eed47284d36cafa8a75ede7b335660e0246476313535dcf555924487622a76`,
      `c867c4f4bef75554c023b781fcac40180efe8356b98f097704205522cd4332ea`,
      and
      `74c9fec06db36ba2465c6c41ce0ec7b8cdb6a3796d69d7f91fbae4b804ea528d`.
      The final clean replay at pushed head `46be6d27` audited 614/614 files,
      6,233,064 source bytes, 211,947 candidates, and 10,000 sites. It resolved
      4,912 forward sites and queried 1,000 of 1,143 target groups. It reported
      1,357 consistent, 73 editor-only, 97 honestly unproven, 8,473
      inconclusive, and zero missing rows, with no file errors or configured
      limit failures. The final report and runner SHA-256 values are
      `6fd1ee1ad37ec964ebbf04fe57cbe48c67a7184b7eb967b586085fd24d3fd75c`
      and
      `5508ea3494449e8c8d8b44e0c3e53c37a12a11e2cfae8899d2b60d577ac4c611`.
      The next active repository is rank eighteen `Mbed-TLS__mbedtls`.
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

- Observation: C rank eleven `sudo-rs` has no C translation unit even though
  the live task selector places it in the C slice.
  Evidence: the pinned clone has 207 `.rs` files and one
  `src/pam/wrapper.h`, but no `.c` file. C frontier eligibility intentionally
  accepts `.c` only, so the clean zero-file envelope is an honest corpus
  bucketing result. This matches the prior accepted BitcoinAddressFinder
  precedent; do not substitute another repository or silently widen to headers.

- Observation: libuv's C compatibility overload makes translation-unit
  dialect part of callable visibility. `include/uv.h` declares the C API with
  an enum parameter, closes its split `extern "C"` wrapper, and then defines
  an integer convenience overload inside `#ifdef __cplusplus`. Before #1465,
  forward definition expansion and inverse argument filtering both considered
  that inactive overload in a `.c` consumer, but at different stages; fixing
  only forward resolution changed the target group without restoring the
  inverse hit. The shared structured visibility boundary must therefore run
  before both forward and inverse overload filtering, evaluate
  `__cplusplus` from the reference translation unit, retain unknown feature
  guards as fail-closed, and carry the original reference dialect through
  transitive includes.

- Observation: Unicorn's correctness-clean supplement exposed a separate
  performance regression in broad C type targets. The 8-worker run completed
  in 415.7 seconds, with individual target lifetimes up to 311.69 seconds,
  15,861,694 voluntary context switches, and 17.33% of user-cycle samples in
  futex mutex contention. An exact isolated `float64` inverse query took 1.1
  seconds versus 18.28 seconds in the shared run. `source_snapshot_file_states`
  is immutable after analyzer construction but every `ranges` call currently
  serializes on its mutable LRU mutex and writes touch metadata. This is owned
  by assigned issue #1433; correctness evidence alone does not close rank
  fifteen while the legitimate symbols-path latency regression remains.

- Observation: the one-worker control completed the same clean 697-target
  envelope in 365.0 seconds; its `DisasContext` query took about 24.5 seconds,
  versus 311.69 seconds with eight workers. Removing only the immutable
  source-snapshot LRU mutex left the eight-worker replay at 421.6 seconds and
  `DisasContext` at 316.29 seconds, proving that change was necessary but not
  sufficient. The remaining hot path was the same request's coarse
  `QueryReadCache` mutex: every live-OID, hydrated-state, and prepared-syntax
  cache hit still serialized. The complete #1433 fix therefore also uses
  concurrent read guards, write guards only for cache insertion/lifecycle, and
  a read-fast/write-recheck path for prepared-syntax cells.

- Observation: publishing the fully validated live-OID map as an immutable
  request snapshot removed the dominant shared-cache serialization. The exact
  8-worker supplement remained correctness-clean and fell from 415.7 seconds
  at the issue baseline (199.4 seconds after the independent-cache split) to
  91.6 seconds, while the one-worker control is 365.0 seconds. The result JSONL
  SHA-256 is `fce69a42057b47882d18c5e60dd6ab1e7e80d24af066fb8e693ed66348fb9554`
  and the timing log SHA-256 is
  `685ab38879ad7bea025153b45acad509b4ce2a0cd4fdcf1131666b2f6c116448`.
  A 55,752-sample follow-up profile lost zero samples and reduced
  `resolve_live_source_for_file` to 2.88% self cost, but exposed the next
  in-scope shared-state layer: `fetch_file_state_for_key_with_source` at
  38.10% and `RwLock::read_contended` at 7.71%. Issue #1433 therefore stays
  open until the same batch also publishes immutable file-state/range data.

- Observation: publishing a bounded immutable file-state snapshot completed
  the contention fix. A 72,231-sample profile lost zero samples and has neither
  repeated `fetch_file_state_for_key_with_source` nor request-cache lock
  contention above 0.5% self cost; the remaining leading costs are tree-sitter
  traversal, byte comparison, dirty-state retry, path hashing, and range
  projection. Its JSONL, timing log, perf data, and profile JSONL SHA-256 values
  are respectively
  `3e08d1fd1b9cf70bcca6f72febd8b880f1091b3ee1b044cca5d021a0f7ad5004`,
  `aed07c0610bb6ded4e8fea3b2580a5aa3063a0141d504ddd01ef8baeebc950cf`,
  `32aaf8c0130a868177573234fcc677af72b0d3e83361c24939f5190a8ac5a538`,
  and `0f278941c4a81f661950e10149d7036844b9af654ea99962596977aa1cf06783`.
  That run's 193.4-second wall time is not comparable because unrelated host
  load averages were roughly 119/174/149 during the replay; the cycle profile,
  correctness result, and removal of the contended frames are the acceptance
  evidence.

- Observation: the featureless full test run reached thousands of passing
  tests across the analyzer, policy, cross-language, issue, and usage suites.
  Three C# usage tests with explicit wall-clock budgets failed while unrelated
  host load was extreme; each passed when rerun alone, including the final
  exact-source build after the bounded file-state prewarm change. This is an
  environmental scheduling failure rather than a semantic regression, so the
  repository-depth-first gate uses those isolated green reruns plus the broad
  run's otherwise-green evidence instead of repeatedly competing with the same
  host saturation.

- Observation: the exact committed-head Unicorn replay completed cleanly at
  Bifrost `e087290f89ffb619033331ed2e3347cafbc43f2d` with
  `bifrost_dirty=false` and repository head
  `7c5db94191defc1e04a4f66f4eb1220903cba837`. It audited 258/258 files,
  651,656 structured candidates, 10,000 sampled sites, and 697/697 inverse
  targets with zero missing classifications and zero actionable findings in
  114.5 seconds. The JSONL and log SHA-256 values are
  `a866b742e4c94af8f0d324a675625b6dd95364eb1814cb79501383ab09cae8d7`
  and `8870a3eb9d03bca2e5f060ee316bf885578668c783a57d429c2e29c2c75363f1`.

- Observation: `origin/master` advanced before the first authorized push and
  overlapped #1433 in `tree_sitter_analyzer.rs`. Merge commit `666f7c04`
  retained both designs: #1433's concurrent request-cache/immutable-snapshot
  layer and upstream's cross-request prepared-syntax/import-info stores. All 56
  tree-sitter analyzer tests, the focused C++ inverse-batch regression,
  formatting, and all-target/all-feature Clippy under Python 3.12 pass. The
  exact merge-head replay is clean at 258/258 files, 651,656 candidates,
  10,000 sites, and 697/697 targets with zero missing/actionable findings in
  53.2 seconds. Its JSONL and log SHA-256 values are
  `adb7a530bff52c419ff5edd139e25b33ccca2aaa27a332ce534a096fd2a42a9b`
  and `dc72761ace52a808b19bf0fe2788d932fd1c667dd2b136c5352e94bbbd726d47`.

- Observation: merging upstream after the first Abseil correction introduced
  a real rank-seventeen regression. Upstream's OpenJDK safety guard rejected
  every malformed sentinel envelope that retained a callable declarator, but
  tree-sitter also retains a later Abseil class member as that declarator when
  `ABSL_NAMESPACE_BEGIN` swallows the class. The structural discriminator is
  ordering: a displaced class keyword precedes the spurious member callable,
  while a genuine `struct` parameter is nested inside or follows the real
  callable. The final predicate and regression fixtures cover both an
  `operator_name` and a constructor `identifier`, retain the OpenJDK control,
  and bump the C++ persistence epoch.

- Observation: the rank-twenty C++ epoch bump invalidated all older C++
  persisted blobs, so the final language certification became the first
  same-head fresh extraction for several earlier ranks. It exposed 70 raw
  missing rows across libarchive, open62541, Wuffs, esp-v2, and Abseil while
  cppcheck, cJSON, BehaviorTree, Mbed TLS, and Pyro stayed clean. This proves
  that a clean replay from an older analyzer blob is not final evidence after
  a declaration-extraction epoch change. The campaign therefore returned to
  rank eleven and will repeat repository-depth-first closure before it accepts
  a C++ language manifest.

- Observation: all 34 fresh libarchive misses formed one root-cause group.
  The local-shadow scan treated `struct Foo *value` as if it declared a local
  `Foo` tag. The existing structured declaration predicate distinguishes that
  use from a real block-scope `struct Foo;` declaration. A second visibility
  guard is necessary because type scan keys collapse repeated physical
  declarations with one logical name. A consumer can use that group only when
  at least one physical peer is in its include closure.

- Observation: repository-depth-first replay can still reuse a prior fix.
  The libarchive correction removed 15 of open62541's 16 initial misses. The
  one residual had a separate scope boundary and warranted issue #1699. This
  kept the grouping useful without combining two different root causes in one
  ticket.

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

- Decision: Group multiple rows and tickets within one active repository when
  they share one demonstrated analyzer root cause and one cohesive test/fix,
  while preserving repository-depth-first sequencing.
  Rationale: Beta and discrete Abseil aliases were separate symptoms of the
  same malformed-sentinel predicate. Grouping their investigation and build
  gates eliminated redundant work without mixing unrelated repositories or
  deferring ticket closure behind a breadth-first batch.
  Date/Author: 2026-08-04 / root.

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

The expansion is in progress. The exact 110-repository scope comes from the
live filtered selector. C ranks eleven through twenty are complete and have a
published language manifest. C++ ranks eleven and thirteen are clean again
through closed issues #1697 and #1699, rank twelve stayed clean, and rank
twenty remains clean with its two issues closed on `origin/master`. The
campaign is processing the remaining fresh-epoch regressions from rank
fourteen forward before it starts C#.

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

Revision note (2026-08-01): Recorded the clean release-runner build, exact C
dry-run, and C rank-eleven `sudo-rs` zero-file completion. The live selector is
authoritative even when a repository contains no translation unit for its
corpus bucket, so the literal rank is retained and no substitute is introduced.

Revision note (2026-08-01): Recorded Unicorn #1433's immutable live-source and
file-state snapshots, clean correctness replays, cycle profiles, environmental
wall-time caveat, broad and isolated test evidence, focused Clippy result, and
the behavior-focused request-snapshot lifecycle regression required by final
review.

Revision note (2026-08-02): Integrated the advanced `origin/master` without a
rebase, recorded the additive cache-layer conflict resolution and full merged
Clippy gate, and pinned the exact clean merge-head Unicorn replay.

Revision note (2026-08-02): Completed C ranks eleven through twenty
repository-depth-first, closed the Jonathan-owned Unicorn and libuv findings,
replaced Unicorn's limit-invalid standard-cap certification row with its
complete 250,000-candidate supplement, and published the frozen-head C
manifest and language summary.
