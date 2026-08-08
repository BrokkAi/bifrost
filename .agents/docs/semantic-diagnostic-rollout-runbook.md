# Unrecognized-symbol diagnostic rollout runbook (#1628)

How to run a rollout campaign against a pinned real project, how to review it,
and what must be true before anyone proposes changing the default.

Unrecognized-symbol diagnostics are opt-in through the LSP runtime setting
`unrecognizedSymbolDiagnostics`. This runbook does not change that, and no step
in it authorizes changing it.

## Acceptance for default enablement

Default enablement requires a team review of two reports, together:

1. A correctness report with zero confirmed false positives on the pinned
   projects, produced by the review procedure below.
2. A latency report produced by the harness, reviewed against baselines the
   team accepts.

Neither report is self-certifying. A green harness run is not approval. The
harness deliberately sets no threshold: #1628 reserves that decision for review
of measured baselines, so a run that "passes" only means it produced a valid
artifact.

The current baseline is
`.agents/docs/semantic-diagnostic-rollout-baseline-2026-08.md`. It covers
in-repo offline fixtures only and explicitly does not stand in for a real
project.

## Running the harness against a pinned project

Build with release tooling, then measure:

    cargo build --release --features release-tooling --bin bifrost_benchmark
    ./target/release/bifrost_benchmark rollout \
        --fixture-id <stable-name> \
        --fixture-root /path/to/checkout \
        --fixture-revision <commit sha of the checkout> \
        --configuration-id <configuration name> \
        --output report.md \
        --artifact artifact.json

Rules for a campaign run:

- Pin the checkout to an exact revision and pass it as `--fixture-revision`.
  The artifact records it, and aggregation refuses to combine artifacts whose
  pinned identity differs, so an unpinned run cannot silently merge with a
  pinned one.
- Measure a clean tree. The artifact records `bifrost_dirty`; a dirty
  measurement is still valid evidence but cannot be compared to a later one.
- Do not restore, build, or install dependencies as part of the measurement.
  Measure the checkout in whatever state the project's own workflow leaves it.
  Bifrost never runs a package manager and never opens a network connection
  during discovery, and the campaign must not do it on Bifrost's behalf.
- Keep `--max-files` off for a campaign. Use it only for a smoke run.
- Run on a quiet machine. Percentiles are nearest-rank, so one preempted file
  moves p95 on a small corpus.

Repeat per project. Keep each `artifact.json`; the aggregation function accepts
several artifacts with the same pinned identity, which is how repeated runs of
one project become one distribution rather than several single-run reports.

### Reading activation latency from a live session

The LSP host writes one line per completed dependency-pack activation to
stderr:

    [bifrost-lsp] dependency-pack activation ecosystems=[Python] elapsed_ms=... complete=... refresh=... cancelled=...

This is the field counterpart to the harness's activation samples. Use it to
confirm how often a real editing session activates and what it costs there.
Activation always runs on a background worker and never on a request path, so
these milliseconds are background cost; a client never waits on them.

A session that never enables `unrecognizedSymbolDiagnostics` produces no such
line, because it schedules no activation at all.

## The zero-confirmed-false-positive review

The claim under review is narrow: every published error is a proven absence.
Suppressions are not defects, and a missing error is not a false positive.

For each project:

1. Take `artifact.json` and list every file whose report counts a nonzero
   `absent` proof class. Those are the only files that can publish an error;
   the artifact validator enforces that emitted errors equal the
   complete-absence count.
2. For each published error, open the file at the reported range and decide one
   of three verdicts:
   - **True positive.** The name does not exist in the workspace or in any
     activated dependency pack. Record it and move on.
   - **Confirmed false positive.** The name does exist and the session had the
     evidence to know it. This blocks enablement. Reduce it to the smallest
     fixture that reproduces, and file it against the owning language.
   - **Unproven.** The name exists somewhere the session had no evidence for,
     for example a dependency whose ecosystem published no pack. This is a
     proof gap, not a false positive, but it means the collector reported
     `absent` where it should have reported a typed suppression. Treat it as
     blocking too, and file it: the whole opt-in rests on that distinction.
3. Record the counts per language. A project is clear only at zero confirmed
   false positives and zero unproven verdicts.

Review the suppression classes as a separate, non-blocking signal. A large
`missing_dependency_discovery` count means the session could not see that
project's dependencies at all, which makes its correctness result weak evidence
rather than strong evidence. Prefer projects whose activation reaches `ready`
with a nonempty active pack list.

## The producer-version invariant

Every dependency-pack producer reports its version as the Bifrost package
version:

    fn producer(&self) -> Producer {
        Producer {
            name: "bifrost-python-stub".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

The same shape appears in the TypeScript declaration, Ruby gem, Composer
package, C# assembly, and rustdoc-JSON producers.

The consequence for a campaign: a cached production is keyed by a producer
identity that only changes at a release version bump. Change a producer's
behavior during a development cycle without changing the version, and a
persisted catalog can keep serving packs built by the old behavior until the
next release.

Therefore:

- A campaign run that must reflect current producer behavior needs a fresh
  catalog. The harness always opens an ephemeral catalog, so a harness run is
  never affected. A hand-run session against a persisted catalog root is.
- Never compare a correctness result produced before a producer change with one
  produced after it unless the version changed between them.
- If a campaign result looks inconsistent with a producer change you know
  landed, suspect a stale cached production first.

## Cost model to keep in mind while reviewing

- Activation is background, coalescing, and cancellable. A newer schedule
  cancels the running job, so a burst of saves costs one superseded activation
  rather than one per save.
- A new analyzer generation starts with no published pack proof, because
  `MultiAnalyzer::update` allocates fresh snapshot caches whenever a delegate
  claims a changed file. The host therefore re-activates at every point that
  installs a generation: session start, `didOpen`, `didSave`, watched-file
  changes, and workspace rebuild. It deliberately does not re-activate per
  `didChange` keystroke, so during typing the diagnostics fall back to typed
  suppressions and return on save.
- This is why the harness measures a refresh series. Refresh cost, not cold
  cost, is what a real editing session pays repeatedly.
- A changed dependency input additionally withdraws the proof built from its
  previous content before re-activating. The file names that trigger this are
  declared once, in `DependencyPackEcosystem::dependency_inputs`.

## What to record

Store each campaign result under `.agents/docs/` with:

- The exact Bifrost revision and whether the tree was dirty.
- Each project's name and pinned revision.
- The configuration id and its hash, both of which the artifact carries.
- The rendered markdown report.
- The correctness verdict counts per language, and every confirmed false
  positive or unproven verdict with its smallest fixture.
- Whether the run used a release build.

State plainly whether the result supports enablement. Do not state that a gate
passed: there is no threshold to pass yet.
