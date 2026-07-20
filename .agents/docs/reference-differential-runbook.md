# Reference-differential runner runbook

This runbook explains how to operate `bifrost_reference_differential` (sometimes abbreviated
FIRD): how to select corpus repositories, run resumable forward-versus-inverse audits, rerun one
exact source site, interpret the JSONL, reduce legitimate defects, and produce acceptance-grade
evidence. It is intentionally operational. Campaign-specific repository lists, issue ledgers, and
progress belong in an ExecPlan under `.agents/plans/`.

## What the differential proves

For each sampled structured reference site, the runner:

1. asks the public definition-resolution path which declaration group the reference targets;
2. asks the inverse usage path for all references to that target; and
3. checks whether the original source range is present in the inverse result.

The runner exercises the analyzer used by the MCP `symbols` toolset and the associated Rust and
Python APIs. LSP shares much of the implementation, but editor-protocol behavior is not the primary
surface of this audit.

A raw `missing` classification is a triage input, not proof of a product defect. Before filing an
issue, confirm that the forward target is semantically correct, the inverse query was complete, the
focused bytes are the actual reference token, and the result is reproducible at the exact site.

## Authoritative implementation and tests

- CLI driver and help: `src/bin/bifrost_reference_differential.rs`
- Differential engine and report schema: `src/reference_differential/mod.rs`
- CLI integration tests: `tests/bifrost_reference_differential_cli.rs`
- Engine tests: `tests/reference_differential.rs`
- Historical design and corpus semantics: `.agents/plans/reference-differential-corpus.md`
- Bounded corpus concurrency: `.agents/plans/concurrent-reference-corpus.md`

When this runbook and the executable disagree, the executable's `--help` and behavior are
authoritative. Update this runbook as part of any user-visible runner change.

## Standard machine layout

The established corpus installation uses these paths:

```text
Bifrost repository:
  /home/jonathan/Projects/bifrost

Canonical clone root:
  /home/jonathan/Projects/brokkbench/clones
    -> symlink to /mnt/T9/repo-clones

Corpus membership, pinned commits, and LOC metadata:
  /home/jonathan/Projects/brokkbench/sft-tools-commits

Durable raw run output and logs:
  /mnt/optane/tmp/reference-differential
```

The clone directory name is the canonical repository slug, for example
`/mnt/T9/repo-clones/llvm__llvm-project`.

Corpus membership comes from:

```text
<commits-root>/<language>/<slug>.jsonl
```

Repository ranking uses `repos.csv::code_loc` under the commits root. Sidecar files such as
`.testsome.jsonl` are not corpus members. A missing clone, invalid pinned commit, missing LOC value,
or dirty tracked checkout must be reported rather than silently treated as a smaller repository.

## Preconditions

Before an accepted run:

1. Work from the intended Bifrost commit and a clean tracked worktree.
2. Ensure each selected corpus clone is at its pinned clean commit.
3. Ensure no other persisted differential or analyzer process is using the same physical clone.
4. Choose a new, head-scoped JSONL output path; never overwrite accepted evidence.
5. Build a fresh release runner from the exact Bifrost head being reported.

The executable reads Bifrost revision and dirtiness metadata dynamically. An old executable run
from a newer checkout can therefore claim the checkout's current head while containing older code.
Always rebuild after changing or reconciling the Bifrost checkout.

Useful checks:

```bash
cd /home/jonathan/Projects/bifrost
git status --short
git rev-parse HEAD
git -C /home/jonathan/Projects/brokkbench/clones/REPOSITORY_SLUG status --short
git -C /home/jonathan/Projects/brokkbench/clones/REPOSITORY_SLUG rev-parse HEAD
```

Persisted analyzer caches live below each clone in `.brokk/bifrost_cache.db`. If `.brokk/` is
untracked, exclude it locally in the clone's `.git/info/exclude` so cache creation does not make an
otherwise clean evidence record appear dirty. Do not delete `.brokk` as a retry strategy; diagnose
epoch or migration failures at their source.

## Build the runner

From the Bifrost repository:

```bash
cargo build --release --bin bifrost_reference_differential
target/release/bifrost_reference_differential --help
target/release/bifrost_reference_differential run-corpus --help
target/release/bifrost_reference_differential run-repo --help
```

For a long campaign, record the Bifrost head and runner checksum alongside the launch manifest:

```bash
git rev-parse HEAD
sha256sum target/release/bifrost_reference_differential
```

Do not use an isolated Cargo target for the final release build unless the binary is deliberately
copied to a durable location before the helper removes its target directory.

## Select repositories without running analyzers

Use `run-corpus --dry-run` to validate corpus membership, LOC ordering, clone paths, and explicit
filters without opening analyzers or caches:

```bash
target/release/bifrost_reference_differential run-corpus \
  --clones-root /home/jonathan/Projects/brokkbench/clones \
  --commits-root /home/jonathan/Projects/brokkbench/sft-tools-commits \
  --language cpp \
  --repos-per-language 5 \
  --repo-jobs 1 \
  --jobs 8 \
  --dry-run
```

`--language` and `--repo` are repeatable. Use explicit `--repo SLUG` filters when the requested set
has exclusions, such as selecting the five largest non-Chromium C++ repositories. Record the dry-run
selection and pinned clone heads in the campaign ExecPlan before starting the expensive run.

## Run a resumable corpus audit

The established large-repository semantic budget is:

```text
sampled files                 1,000
sampled reference sites      10,000
structured candidates/file  50,000
source bytes/file         4,194,304
inverse target groups        1,000
usage files/target           1,000
usage hits/target          100,000
seed                             0
```

Start conservatively with one active repository and eight inner workers. Increase outer concurrency
only after measuring memory and I/O headroom.

```bash
set -o pipefail
/usr/bin/time -v target/release/bifrost_reference_differential run-corpus \
  --clones-root /home/jonathan/Projects/brokkbench/clones \
  --commits-root /home/jonathan/Projects/brokkbench/sft-tools-commits \
  --language cpp \
  --repo REPOSITORY_SLUG \
  --repo-jobs 1 \
  --jobs 8 \
  --cache-mode persisted \
  --strict \
  --max-files 1000 \
  --max-sites 10000 \
  --max-candidates-per-file 50000 \
  --max-source-bytes 4194304 \
  --max-targets 1000 \
  --max-usage-files 1000 \
  --max-usages 100000 \
  --seed 0 \
  --output /mnt/optane/tmp/reference-differential/LANGUAGE-CAMPAIGN-BIFROST_HEAD.jsonl \
  2>&1 | tee -a /mnt/optane/tmp/reference-differential/LANGUAGE-CAMPAIGN-BIFROST_HEAD.log
```

For a complete top-N run, omit explicit `--repo` filters and use `--repos-per-language N`, or repeat
`--repo` for an exact selected set. `run-corpus` appends one JSON object per completed repository.
Records are written in completion order; JSONL line order is not semantically meaningful.

### Parallelism

- `--repo-jobs N` bounds repositories audited concurrently by one `run-corpus` process.
- `--jobs N` bounds analyzer construction and forward/inverse workers inside each repository.
- Jobs that resolve to the same physical clone are serialized within one `run-corpus` process.
- Two independently launched processes are not coordinated. Never point two persisted runs at the
  same clone concurrently.

The product of outer and inner concurrency is not a sufficient memory estimate. Workspace size,
prepared syntax trees, the shared authoritative usage batch, and unusually broad targets can dominate
resource use. Large C++ repositories should begin at `--repo-jobs 1 --jobs 8`.

### Cache modes

- `--cache-mode persisted` is the default and is appropriate for deliberately warmed or resumable
  corpus campaigns. It uses the clone's `.brokk/bifrost_cache.db`.
- `--cache-mode ephemeral` uses an in-memory store and is appropriate for exact reruns and one-off
  smoke tests that must not mutate a clone cache.

Cache mode is operational and does not change sampling semantics.

### Strict mode and exit status

`--strict` exits with status 2 when actionable raw findings exist. This is expected during a baseline
campaign. Acceptance is based on durable completed JSONL records and their audited contents, not on a
zero shell status alone. A killed process or a log without a completed record is not evidence.

## Resume an interrupted corpus

`run-corpus` is append-only and resume-safe at repository-record granularity.

1. Confirm that no previous process still owns a selected clone.
2. Preserve the existing JSONL and log.
3. Repeat the identical command and output path without `--force`.

The runner computes a semantic completion key from language, repository slug/head, Bifrost head, and
the configuration fingerprint. Completed keys are skipped; incomplete repositories rerun. Do not
truncate the JSONL, delete clone caches, or add `--force` merely because a run was interrupted.

Progress within one repository is not checkpointed as a completed record. If that repository process
dies before append, its forward and inverse phases repeat, although a persisted analyzer cache can
make workspace reconstruction much faster.

## Rerun one exact source site

After identifying a suspicious row, rerun precisely its path and byte range against the same clone
head. Use a unique output file and ephemeral cache mode:

```bash
target/release/bifrost_reference_differential run-repo \
  --root /home/jonathan/Projects/brokkbench/clones/REPOSITORY_SLUG \
  --language cpp \
  --output /mnt/optane/tmp/reference-differential/ISSUE-exact-BIFROST_HEAD.jsonl \
  --jobs 8 \
  --cache-mode ephemeral \
  --strict \
  --path path/inside/repository.cpp \
  --start-byte START \
  --end-byte END
```

The byte offsets are zero-based source byte offsets, not character columns. Preserve the source
evidence, forward target group, exact inverse hit (if any), diagnostics, Bifrost head/dirtiness, clone
head, and SHA-256 of the exact output.

With a unique exact-output path, `--force` is unnecessary. Use it only when intentionally appending a
new record whose semantic completion key already exists in the chosen output; never make it part of a
routine resume command.

An exact rerun proves only that site. It does not replace exhaustive review of every raw residual in a
complete final corpus.

## Read the JSONL report

Each JSONL line is a repository envelope. Provenance and repository status are top-level fields; for a
completed record, the engine configuration, summary counters, sampled sites, and file errors are
nested under `.report`. A compact first pass is:

```bash
jq -r 'select(.status == "completed") |
  [.corpus_language, .repo_slug, .bifrost_head, .bifrost_dirty,
   .repo_head, .repo_dirty, .run_fingerprint,
   .report.summary.classifications.missing] | @tsv' RUN.jsonl
```

First verify:

- `status == "completed"`;
- `bifrost_head` is the freshly built frozen head;
- `bifrost_dirty == false`;
- `repo_head` is the pinned corpus commit;
- repository tracked state is clean;
- the configuration fingerprint is shared by records intended for one campaign leg; and
- no file error or truncation invalidates the claimed scope.

Important site classifications:

- `consistent`: the inverse result contains the forward-resolved site.
- `editor_only`: editor/definition behavior is intentionally outside the inverse contract.
- `unproven`: structured evidence is incomplete or ambiguous, so the analyzer correctly declines to
  claim a proven miss.
- `inconclusive`: the forward lookup, focused token, declaration role, explicit limit, or boundary does
  not form a valid complete comparison.
- `missing`: a forward-resolved site is absent from the complete inverse result and requires triage.

Also inspect each site's `forward_status`, `targets`, `note`, `diagnostics`, and `inverse_hit`
(including its nested `exact_range`). At report level, inspect `summary.target_truncated_sites`,
`summary.skipped_targets`, candidate-limit counters, configured usage limits, and `file_errors`. A
forward status of `resolved` with an empty or semantically wrong target group is not a legitimate
inverse miss.

## Triage every raw missing row

For every `missing` site:

1. Re-read the live source bytes and tree-sitter role at the recorded range.
2. Verify the focused token is the referenced terminal, not a qualifier, label, declaration, comment,
   macro artifact, or parser-recovery frontier.
3. Verify every forward target is the declaration group a language-aware user would expect.
4. Verify the inverse query was complete: no target truncation, file limit, usage limit, candidate limit,
   file error, unsupported boundary, or cancellation invalidated it.
5. Run the exact-site command on the same clean heads.
6. Search the existing issue ledger and prior campaign families.
7. Group genuine witnesses by root cause, not by repository or syntax spelling.
8. Record every row in a checksummed ledger, including non-actionable dispositions and evidence.

Do not infer that a large cluster is one bug merely because source text looks similar. Conversely, do
not file one issue per symptom when structured tracing proves a shared resolver invariant.

## Reduce and fix a legitimate defect

Before implementation:

1. search open issues for the root-cause family;
2. if an issue is assigned to somebody else, record it and skip the implementation;
3. otherwise create or reuse an issue assigned only to the authorized owner; and
4. ensure assignment is complete before changing product code.

Use `tests/common/inline_project.rs::InlineTestProject` for small behavior-focused analyzer projects.
Put forward identity regressions in definition tests, targeted inverse regressions in usage-graph tests,
and whole-workspace parity regressions in inverted-graph tests. Add public symbols-service and Python
API coverage when the public surface changes.

Reductions must model the semantic cause and include relevant negative controls: owners, namespaces,
aliases, overloads and arity, receiver types, inheritance, lexical shadowing, duplicate declarations,
include visibility, templates, macro recovery, and C/C++ partition as applicable.

Use tree-sitter nodes, declaration ranges, import binders, visibility indexes, and analyzer graph
structures. Do not replace missing structured support with regular expressions, substring matching,
delimiter splitting, or a source-text mini-parser.

## Local acceptance gates

After integrating a fix stack, run at least:

```bash
cargo fmt --all -- --check
scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
UV_CACHE_DIR=/tmp/bifrost-uv-cache \
  BIFROST_SEMANTIC_INDEX=off \
  scripts/with-isolated-cargo-target.sh cargo test --features nlp,python
```

Run focused behavior suites before the broad gates, then rebuild the release runner from the exact
clean integrated head and rerun every accepted production witness. Do not wait for CI when a campaign
explicitly defines the complete local gate as its transition boundary.

If the execution sandbox denies process-I/O tests, rerun the same full feature-enabled suite outside
that sandbox. Do not reinterpret a sandbox denial as a passing test or silently narrow the suite.

## Final campaign proof

Exact probes and a dirty integration-candidate corpus are not closure evidence. After all fixes:

1. reconcile and publish the integrated head according to the repository's Git instructions;
2. rebuild the release runner from that exact clean pushed head;
3. run the complete selected corpus into new head-scoped JSONL and log files;
4. exhaustively audit every final raw `missing` row;
5. verify all expected exact witnesses are `consistent` or honestly fail closed as `unproven`/
   `inconclusive` with zero actionable discrepancy;
6. run formatting, Clippy, focused tests, and the full feature-enabled test suite;
7. comment on and close only the assigned issues proven fixed by clean production evidence; and
8. verify local HEAD, local `origin/master`, and remote `refs/heads/master` agree.

Do not claim closure by subtracting baseline rows that exact probes fixed. Fixes can change forward
target identity, sampled target groups, and shared C/C++ behavior, so the full clean corpus must be
rerun and independently audited.

## Evidence layout and naming

Keep large, resumable raw artifacts outside the repository:

```text
/mnt/optane/tmp/reference-differential/
  <language>-<campaign>-<bifrost-head>.jsonl
  <language>-<campaign>-<bifrost-head>.log
  ...-missing-audit.jsonl
  ...-missing-audit.tsv
  ...-missing-audit.summary.json
  ...-missing-ledger.jsonl
  ...-missing-ledger.tsv
  ...-missing-ledger.sha256
```

Keep compact, durable LLM-facing manifests and narrative summaries under:

```text
.agents/docs/reference-differential/
```

The compact manifest should pin repository and Bifrost heads, the configuration fingerprint, summary
counters, runtime, file errors, audit checksums, issue ledger, and raw artifact paths. Do not commit
multi-megabyte raw sampled-site payloads or analyzer logs.

## Temporary storage and cleanup

For Cargo validation, never create manually named `CARGO_TARGET_DIR=/tmp/bifrost-*` directories. Use:

```bash
scripts/with-isolated-cargo-target.sh cargo COMMAND
```

Do not set `BIFROST_KEEP_TARGET=1` unless artifacts are deliberately needed after the command. Inspect
stale managed directories with:

```bash
scripts/cleanup-bifrost-tmp.sh
```

Review the dry run before using `--apply`. The cleanup command deliberately skips live PIDs, open
directories, symlinks, young targets, retained targets, and unmanaged historical directories.

Use durable Optane paths for long corpus JSONL and logs. Exact smoke outputs may live in `/tmp`, but
copy acceptance evidence to the campaign's durable artifact directory before routine cleanup.

## Common failure modes

### Strict run exits 2

Expected when raw actionable rows exist. Inspect the completed JSONL. Do not discard the record.

### Log ends without a completed repository record

The repository is incomplete even if thousands of progress lines were printed. Repeat the identical
`run-corpus` command without `--force`; completed repository records will be skipped.

### Reported Bifrost head does not match executable code

The release binary was stale or the checkout changed after the build. Freeze the worktree, rebuild,
and write to a new head-scoped output.

### Clone becomes dirty during a persisted run

If only `.brokk/` is untracked, add a local `.git/info/exclude` entry and rerun the accepted record. If
tracked source changed, restore or re-create the pinned clone through the normal corpus workflow; do
not accept the dirty record.

### Progress is quiet for several minutes

One broad inverse target or shared authoritative-batch construction can dominate wall time. Check that
the process is alive and consuming CPU before declaring it stalled. Explicit file and usage limits
still apply. Do not kill a healthy repository late in its run merely because target costs are uneven.

### Process is killed or the host reboots

Preserve JSONL, logs, and clone caches. Confirm the old process is gone, then repeat the identical
command. Repository-level records are resumable; incomplete within-repository target progress is not.

### Multiple corpus processes contend on one clone

Stop the duplicate before trusting either result. `--repo-jobs` coordinates clone reuse only inside one
`run-corpus` process; independently launched commands must be scheduled by the operator.

## Operator checklist

Before launch:

- [ ] clean, pinned Bifrost head;
- [ ] fresh release runner and recorded checksum;
- [ ] deterministic dry-run selection recorded;
- [ ] clean, pinned clone heads;
- [ ] unique head-scoped output and append-only log paths;
- [ ] persisted versus ephemeral cache mode chosen intentionally;
- [ ] resource shape starts conservatively; and
- [ ] no competing process owns a selected clone.

Before accepting a baseline:

- [ ] every selected repository has one completed record;
- [ ] heads, dirtiness, and fingerprints are correct;
- [ ] every raw missing row has an evidence-backed ledger disposition;
- [ ] every legitimate root cause has an assigned issue before implementation; and
- [ ] exact production witnesses and structured reductions exist.

Before closure:

- [ ] integrated clean head is published;
- [ ] release runner rebuilt from that exact head;
- [ ] fresh complete corpus finished on the selected repositories;
- [ ] every final residual exhaustively audited;
- [ ] focused tests, formatting, all-feature Clippy, and `cargo test --features nlp,python` pass;
- [ ] compact manifest and narrative committed;
- [ ] fixed assigned issues commented and closed with clean evidence; and
- [ ] local and remote `master` agree.
