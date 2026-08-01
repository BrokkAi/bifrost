# Package and distribute optional prebuilt semantic packs

This ExecPlan is a living document. The sections `Progress`, `Surprises &
Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to
date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost's protocol-neutral analyzer already understands semantic-model packs:
versioned, content-addressed descriptions of declarations, relationships, and
procedure summaries that are not ordinary workspace source. It does not yet
have a product layer that ships Bifrost-curated packs, obtains larger prebuilt
packs safely, or lets a user inspect and control those installed resources.

After this work, the published `brokk-bifrost` driver will compose the generic
analyzer with a new published `brokk-bifrost-semantic-packs` crate. The new
crate will own Bifrost-curated embedded resources, release indexes, explicit
download/install orchestration, and user-facing lifecycle operations. The
`brokk-bifrost-analysis` crate will not depend on that crate. An embedding
product can therefore use analysis, runtime, LSP, or MCP packages with only
its own semantic packs, while the normal Bifrost binary gets curated defaults.

The result will be observable in three ways. A package-graph test will prove
that `brokk-bifrost-analysis` has no dependency on the new distribution crate.
An integration test will install the same fixture once as an embedded pack and
once from a release index and prove that the catalog stores one logical digest.
The `bifrost semantic-packs list`, `status`, `install`, `update`, `rollback`,
`disable`, and `gc` commands will show where packs came from, why they are or
are not usable, and will remain deterministic while offline.

This issue does not generate packs from locally resolved project dependencies;
issue #1150 owns that work. It also does not author the production JDK/Scala
packs from #1152 or the initial generated-code behavior models from #1153.
Those issues will publish content through the interfaces established here.

## Progress

- [x] (2026-08-01 06:28Z) Refreshed the worktree and remote state and verified
  that the issue branch and `origin/master` both point at `1c2f1923`.
- [x] (2026-08-01 06:28Z) Read live issues #1144, #1145, #1146, #1147, #1150,
  #1152, #1153, and #1154 and fixed the boundary between distribution, local
  dependency generation, and curated content authoring.
- [x] (2026-08-01 06:28Z) Inspected the current Cargo workspace, package and
  release checks, analyzer semantic-pack compiler/catalog/runtime, facade, and
  CLI composition points.
- [x] (2026-08-01 06:28Z) Drafted this implementation plan and selected a
  separate downstream distribution crate rather than moving generic pack
  support out of the analyzer.
- [x] (2026-08-01 06:44Z) Added the published
  `brokk-bifrost-semantic-packs` crate, explicit embedded-pack registry,
  package checks, release ordering, CI coverage, facade composition, and
  dependency-direction tests. Two focused Rust tests, 33 Node graph/workflow
  tests, strict Clippy, and the six-archive package gate passed; the gate
  compiled both the facade and an analysis-only consumer from unpacked crate
  archives.
- [x] (2026-08-01 06:49Z) Completed the post-milestone repository policy review.
  `list_policies` exposed correctness and performance categories, and one
  `run_policy` request selected `bifrost.code-smells` with no repository policy
  roots. The result was `unreliable`/exit 2 under the existing whole-workspace
  budget failure; no finding points into Milestone 1 files.
- [ ] Define and validate the compact release-index and asset-envelope
  contracts, including compatibility, provenance, checksums, sizes, notices,
  revocation, and deterministic serialization.
- [ ] Implement explicit offline-by-default acquisition and atomic catalog
  installation with bounded transfer, digest, size, and compatibility checks.
- [ ] Implement durable desired-state history for pin, disable, update,
  downgrade, rollback, and garbage collection without placing network or
  product policy in `brokk-bifrost-analysis`.
- [ ] Add driver composition and user-facing `semantic-packs` list, status,
  explain, install, update, rollback, disable, and gc commands.
- [ ] Extend release automation, third-party notices, package verification,
  lifecycle tests, staged-binary smoke tests, formatting, Clippy, and repository
  policy validation.

## Surprises & Discoveries

- Observation: The generic analyzer already contains nearly all of the trusted
  local storage boundary required by #1154.
  Evidence: `SemanticPackCatalog::install` validates canonical manifests and
  shards before atomic publication; the catalog also exposes sources, pins,
  active sets, leases, accounting, quarantine, and garbage collection.

- Observation: The facade package is already a composition package over four
  published implementation crates, so a fifth downstream crate follows an
  established release shape.
  Evidence: root `Cargo.toml` depends on `brokk-bifrost-analysis`,
  `brokk-bifrost-runtime`, `brokk-bifrost-mcp`, and `brokk-bifrost-lsp`, while
  `.github/workflows/release.yml` publishes them in dependency order before
  `brokk-bifrost`.

- Observation: The issue's production content belongs to later sibling issues.
  Evidence: #1152 depends on #1154 and owns JDK/Scala release assets; #1153 owns
  curated Scala/Lombok/macro behavior models. #1154 must therefore ship a
  fixture-backed distribution mechanism without inventing those packs here.

- Observation: Semantic packs are not a global analyzer configuration today.
  Evidence: `AnalyzerConfig` contains general, JVM, and C# configuration, while
  active semantic models are acquired explicitly from a caller-provided
  `SemanticPackCatalog` and activation request. The driver can compose bundled
  content without adding product defaults to `AnalyzerConfig`.

- Observation: Broad parallel Bifrost intelligence calls remain unreliable on
  the rmcp host at this revision, but narrow warm calls work.
  Evidence: a parallel `search_symbols` request with patterns `Semantic.*`,
  `Model.*`, `Pack.*`, and `Built.*` returned a cancelled zero-file result, and
  `get_summaries` for `Cargo.toml` and `crates` returned request-budget error
  `-32603`. A later two-file semantic-model summary completed in 6.1 seconds.
  Existing issues #1419 and #1423 own this behavior, including current-tip rmcp
  evidence from the parallel #1150 investigation.

- Observation: This machine's default Rust tools mix rustup Cargo/rustc with
  Homebrew rustdoc and Clippy even though both report Rust 1.96.
  Evidence: unit tests passed, then the doctest rejected an analysis rlib built
  by the rustup compiler as incompatible with Homebrew rustdoc. Setting
  `RUSTDOC=/Users/dave/.cargo/bin/rustdoc` made the focused tests pass, and the
  isolated strict Clippy gate passed with the complete Homebrew toolchain.

- Observation: The required whole-workspace policy gate still cannot establish
  a trustworthy result at current tip.
  Evidence: `run_policy({policy_packs:["bifrost.code-smells"],
  evaluation_date:"2026-08-01",fail_on:"warning"})` returned
  `status=unreliable`, `exit_status=2` after five seconds. Three known
  dynamic-evaluation findings completed outside this change; the nested-loop
  rule exhausted its budget after 1,110 files and 29,055,861 bytes, and later
  policies were cancelled. Existing issues #1296 and #1423 own the incomplete
  run behavior.

## Decision Log

- Decision: Create `crates/bifrost-semantic-packs` with package name
  `brokk-bifrost-semantic-packs`, and make it depend on
  `brokk-bifrost-analysis`; never add the reverse dependency.
  Rationale: The analyzer owns the generic artifact, catalog, activation, and
  overlay contracts. The new crate owns Bifrost's content and distribution
  policy. Depending downstream reuses the trusted contracts without making
  custom analyzer consumers compile or ship curated resources.
  Date/Author: 2026-08-01 / Codex

- Decision: Keep the generic semantic-model module inside
  `brokk-bifrost-analysis` for this issue.
  Rationale: Moving schema, compiler, catalog, runtime, and overlay types into a
  separate neutral crate would be a large unrelated refactor and would not
  improve optionality: analysis must understand those types to apply any
  caller-supplied pack. The optional boundary is bundled content and network
  lifecycle policy, not the capability to consume semantic facts.
  Date/Author: 2026-08-01 / Codex

- Decision: Make `brokk-bifrost` depend on the new crate as its standard driver
  composition, while keeping embedded content selectable through an explicit
  driver configuration rather than silently registering it in analyzer
  constructors.
  Rationale: The product binary should provide the complete Bifrost tool set,
  but libraries and tests need deterministic control over which rules are
  active. Explicit composition also lets a custom host reuse the facade's
  protocols without accepting Bifrost's defaults.
  Date/Author: 2026-08-01 / Codex

- Decision: Do not add a second semantic-pack format.
  Rationale: The compiled pack manifest already binds schema, producer,
  selectors, provenance, license, shard digests, encodings, and sizes. A release
  index should reference those immutable artifacts and add only transport-level
  information such as asset URL, total download bytes, notice asset, revocation,
  and publication provenance.
  Date/Author: 2026-08-01 / Codex

- Decision: Keep automatic network access off and model acquisition as an
  explicit operation with an injected transport.
  Rationale: Missing network or registry state must not alter local correctness.
  An injected bounded transport makes offline behavior and corrupt/interrupted
  downloads testable without a live service and lets embedding products choose
  their own HTTP/authentication implementation.
  Date/Author: 2026-08-01 / Codex

- Decision: Store lifecycle intent and history in the distribution crate's own
  small state database or file, while continuing to store immutable pack bytes
  and analyzer activation authority in `SemanticPackCatalog`.
  Rationale: Update channels, disabled registries, rollback history, and desired
  versions are product policy, not semantic truth. Putting those rows in the
  analyzer catalog would couple every custom host to Bifrost's distribution
  semantics and blur the existing catalog's trusted local-content role.
  Date/Author: 2026-08-01 / Codex

## Outcomes & Retrospective

Planning and the first implementation milestone are complete. The chosen
architecture agrees with the proposed crate split, with the important
qualification that the analyzer continues to own the generic ability to consume
semantic packs. The workspace now enforces the one-way dependency, packages and
publishes the new crate before the facade, and provides an explicit validated
embedded-pack registry whose production inventory remains empty until #1152 or
#1153 supplies reviewed content. Release-index and acquisition work remains.

## Context and Orientation

The repository root is both a Cargo workspace and the `brokk-bifrost` facade
package. `Cargo.toml` lists implementation packages under `crates/` and the
facade re-exports their public APIs from `src/lib.rs`. The facade's
`src/bin/bifrost.rs` is the end-user driver and manually parses its command-line
options. `scripts/check-workspace-packages.sh` packages every publishable crate,
unpacks the archives, patches their registry dependencies to those local
archives, and compiles a consumer. `.github/workflows/release.yml` publishes
implementation crates in dependency order and publishes the facade last.

Generic semantic-pack support is under
`crates/bifrost-analysis/src/analyzer/semantic_model/`. `artifact.rs` defines
the canonical compiled manifest and shard envelope. `catalog/mod.rs` stores
immutable verified objects, pack sources, pins, activations, and leases.
`runtime.rs` selects compatible candidates from caller-provided evidence and
controls, hydrates the generation-scoped in-memory matcher, and produces an
explanation report. `overlay.rs` maps active modeled facts into navigation and
query results. These types are useful to every host, including hosts that never
use Bifrost-curated content, so they remain in the analysis crate.

The new `crates/bifrost-semantic-packs/` package is a distribution layer. A
"release index" is a small canonical JSON document that lists immutable pack
assets and enough metadata to reject an asset before download when it is
incompatible, revoked, or too large. A "transport" is a caller-provided object
that reads bytes for an explicit asset request. An "embedded pack" is an
immutable compiled manifest and its shards included in a binary or library
archive. Embedded and downloaded copies with the same manifest digest are one
logical pack because the existing catalog is content-addressed.

Issue #1150 may later call `SemanticPackCatalog::install` with packs generated
from exact local dependency artifacts. It must not depend on the new release
index, transport, update history, or Bifrost-curated embedded registry. This
plan will avoid editing #1150's dependency-discovery and producer adapters.

## Plan of Work

Milestone 1 establishes the package boundary without pretending that production
packs from #1152 or #1153 already exist. Add
`crates/bifrost-semantic-packs/Cargo.toml` and `src/lib.rs`, define an explicit
`EmbeddedPackRegistry` over validated compiled bytes, and add a small test-only
fixture registry. Update the workspace, facade dependency, package checker,
workspace dependency checker, CI impact rules, and release publication graph.
Add a package-graph regression that proves `brokk-bifrost-analysis` does not
depend on `brokk-bifrost-semantic-packs`. Package both crates and compile a
consumer that can choose analysis without the distribution package.

Milestone 2 defines the release trust envelope. In the new crate, add a strict
version-one release index with denied unknown fields, canonical serialization,
explicit Bifrost/schema/producer compatibility, selectors copied from the
compiled manifest for pre-download filtering, source commit and input artifact
digests, license and notice references, exact manifest/shard URLs, stored
SHA-256 digests, and byte sizes. Decode under explicit count, string, and byte
limits. Validate that index metadata agrees exactly with the decoded compiled
manifest and shard descriptors. Add deterministic JSON fixtures and corruption,
unknown-field, size, compatibility, provenance, notice, and revocation tests.

Milestone 3 implements acquisition without implicit networking. Define a
`PackTransport` trait whose bounded read method receives one asset descriptor
and a cancellation token. Supply a filesystem implementation for local release
mirrors and an HTTP implementation only if the facade explicitly enables and
configures one. Stream each object to a uniquely named staging file under a
temporary directory, reject content that exceeds its declared size, verify the
exact stored digest and final size, decode the complete pack, then call
`SemanticPackCatalog::install`. Remove staging state on every failure. Tests
will simulate interruption, truncation, oversize, digest mismatch, manifest
disagreement, incompatible versions, and concurrent identical installs.

Milestone 4 adds distribution policy outside the analyzer. Define a durable
`PackStateStore` that records configured release sources, opt-in network policy,
desired pack selectors, pins, disables, successful install history, and the
previous known-good manifest digest. Implement install, update, explicit
downgrade, rollback, disable/enable, and garbage-collection planning as
separate operations rather than mode flags. A failed acquisition must leave
the current desired and active state unchanged. Activation controls supplied to
the analyzer come from this state store plus explicit workspace controls, but
the analyzer remains the authority that explains compatibility and conflicts.

Milestone 5 composes the normal driver. Add a facade module that resolves an
explicit semantic-pack root, registers the embedded registry as session packs,
opens the durable catalog/state store, and supplies activation context to tool
execution. Extend `src/bin/bifrost.rs` with a `semantic-packs` command family for
`list`, `status`, `explain`, `install`, `update`, `rollback`, `disable`,
`enable`, and `gc`. Read-only commands must never contact the network. Mutating
commands contact only explicitly configured sources and print the origin,
manifest digest, compatibility, activation state, and reason. Preserve direct
construction paths for custom hosts and tests that supply no bundled registry.

Milestone 6 makes distribution releasable. Extend the release workflow so the
new crate publishes after analysis and before the facade. Add a deterministic
asset-index generation and verification command for later #1152/#1153 jobs;
do not commit large generated payloads. Require notices for every non-Bifrost
input, verify all asset digests and sizes before GitHub Release publication,
and fail if the compact index names an absent asset. Run package archives,
focused lifecycle tests, a staged-binary offline/install/rollback smoke, Cargo
formatting, focused featureless Clippy/tests, and the repository code-smell
policy pack.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/cd36/bifrost` on the existing
`1154-package-and-distribute-compatible-prebuilt-semantic-packs-safely` branch.
Do not create or switch branches. At the beginning and after each milestone,
run:

    git status --short --branch
    git diff --check

For Milestone 1, run the package and dependency checks plus focused tests:

    cargo fmt --all -- --check
    cargo test -p brokk-bifrost-semantic-packs
    bash scripts/check-workspace-packages.sh
    node --test scripts/check-workspace-dependencies.test.mjs scripts/ci-impact.test.mjs

The package checker must report six archives, including
`brokk-bifrost-semantic-packs`, and both its default consumer and the
analysis-only consumer must compile.

For Milestones 2 through 4, use focused package tests during development:

    cargo test -p brokk-bifrost-semantic-packs

Tests that exercise catalog behavior should use temporary catalog and state
roots and fixture transports. They must not read the user's cache, mutate
process-global network settings, or contact the internet.

For Milestone 5, build the staged binary and run the lifecycle smoke against a
temporary root and local fixture release mirror. The exact CLI spelling may be
adjusted once the existing manual parser is extended, but the final plan must
record the actual commands. The expected sequence is:

    cargo run -- semantic-packs status --offline --root <temporary-root>
    cargo run -- semantic-packs install fixture.pack --source <fixture-index>
    cargo run -- semantic-packs disable fixture.pack --root <temporary-root>
    cargo run -- semantic-packs rollback fixture.pack --root <temporary-root>

Status must work with no source available. Install must show the verified
digest. Disable must retain bytes while preventing activation. Rollback must
restore the previously successful digest without downloading it again.

Before completing the issue, run the practical featureless Rust gate because
this work does not touch NLP or Python:

    cargo fmt --all -- --check
    cargo test -p brokk-bifrost-semantic-packs
    cargo test -p brokk-bifrost-analysis semantic_model
    cargo test -p brokk-bifrost
    scripts/with-isolated-cargo-target.sh cargo clippy -p brokk-bifrost-semantic-packs -p brokk-bifrost --all-targets -- -D warnings
    bash scripts/check-workspace-packages.sh

Then use the installed Bifrost policy tool to run `bifrost.code-smells` together
with every executable repository policy root named by the repository in one
request. A `finding` requires review or correction. An `unreliable` result is a
failed validation and must be reported with its owning issue rather than called
green.

## Validation and Acceptance

The crate boundary is accepted when Cargo metadata and a regression test show
that `brokk-bifrost-analysis` has no dependency path to
`brokk-bifrost-semantic-packs`, while the `brokk-bifrost` facade does. A custom
consumer must compile using only analysis and must be able to register its own
compiled fixture with `SemanticPackCatalog`.

The release contract is accepted when semantically identical indexes serialize
to identical bytes, every asset is bound by exact digest and size, and malformed,
unknown-schema, revoked, incompatible, or notice-incomplete entries are rejected
before activation. Release metadata must agree with the canonical compiled
manifest rather than becoming a second semantic authority.

Installation is accepted when interrupted, corrupt, oversized, incompatible,
or partially downloaded packs never appear as catalog candidates or replace a
known-good desired version. Installing an embedded and downloaded copy with the
same digest must produce one logical catalog identity while preserving both
origins for inspection.

Lifecycle behavior is accepted when offline status/list/explain are complete;
network access occurs only during an explicit configured operation; pin,
disable, update, downgrade, rollback, and GC tests pass; and rollback reuses a
verified cached digest atomically. Missing registries must report unavailable
coverage without changing analyzer results that do not depend on the missing
pack.

Release behavior is accepted when package checks include the new crate,
third-party notices cover every indexed input, generated payloads are absent
from Git, the compact release index cannot publish before all named assets and
checksums exist, and the facade publishes only after its new dependency.

## Idempotence and Recovery

All release assets are immutable and content-addressed, so retrying a verified
install is a logical no-op. Downloads use unique temporary staging paths and
publish through the existing catalog only after complete verification; a crash
may leave an unreferenced staging file but never an active partial pack. Startup
and explicit cleanup may remove stale staging files that are older than the
configured safety window and are not open by a live process.

State changes write a new desired-state generation atomically. Keep the prior
known-good digest until the replacement has been installed and validated.
Rollback selects that retained digest and never reconstructs bytes from mutable
metadata. If the state database is newer than the running binary, open it
read-only for status where safe and refuse mutation with an actionable error.

Milestone commits must stage only files changed by this plan. If another task
advances #1150 concurrently, refresh from the shared base only when explicitly
authorized and resolve overlap by preserving #1150's local-artifact generation
boundary. Do not edit or discard unrelated worktree changes.

## Artifacts and Notes

Live issue state at plan creation:

    #1145 closed: authoring schema and deterministic compiler
    #1146 closed: content-addressed catalog and lifecycle
    #1147 closed: generation-scoped runtime matcher
    #1150 open: exact local dependency generation, worked separately
    #1152 open: JDK and Scala prebuilt content, depends on #1154
    #1153 open: initial curated generated-code behavior models
    #1154 open: this distribution and packaging work

The intended dependency shape is:

    brokk-bifrost-analysis
              ^
              |
    brokk-bifrost-semantic-packs
              ^
              |
        brokk-bifrost facade/driver

`brokk-bifrost-runtime`, `brokk-bifrost-mcp`, and `brokk-bifrost-lsp` continue
to depend on generic analysis/runtime packages and do not gain a dependency on
Bifrost-curated content.

## Interfaces and Dependencies

In `crates/bifrost-semantic-packs/src/embedded.rs`, define a small registry that
returns immutable `CompiledSemanticModelPack` values or manifest/shard byte
views suitable for `SemanticPackCatalog::register_session_pack`. The registry
must not perform global registration in a constructor or static initializer.

In `crates/bifrost-semantic-packs/src/release.rs`, define strict versioned DTOs
for `SemanticPackReleaseIndex`, `SemanticPackRelease`, and `ReleaseAsset`. They
must use `serde` with unknown-field rejection and share digest/compatibility
validation helpers with the compiled artifact contract where possible.

In `crates/bifrost-semantic-packs/src/transport.rs`, define a cancellable,
bounded `PackTransport` interface. Keep the interface about reading an explicit
asset; registry discovery, authentication, retries, and network policy belong
to the caller or concrete transport and must not leak into the analyzer.

In `crates/bifrost-semantic-packs/src/installer.rs`, define a `PackInstaller`
that accepts a release entry, transport, `SemanticPackCatalog`, limits, and
cancellation token. It returns a structured installed/already-present outcome
or a typed failure. It must verify transport metadata and compiled semantic
metadata before invoking the catalog install operation.

In `crates/bifrost-semantic-packs/src/state.rs`, define a durable state store
and separate operation types for install, update, downgrade, rollback, enable,
disable, pin, unpin, and GC. Avoid a shared mode flag. Expose a method that
derives `SemanticModelActivationControl` values for the generic analyzer
runtime without making analysis depend on this crate.

In the root facade, add a driver-level semantic-pack configuration and lifecycle
service. The service may depend on the new crate, analysis, and runtime. Analyzer
constructors remain neutral and direct analysis consumers continue to supply
their own catalog and activation request.

Revision note: 2026-08-01 06:49Z. Updated after Milestone 1 implementation,
validation, and policy review to record the concrete package boundary, empty
production registry, release/CI integration, analysis-only consumer proof,
local Rust toolchain discovery, and the existing unreliable policy budget
boundary. The next milestone is the strict release index and asset envelope.
