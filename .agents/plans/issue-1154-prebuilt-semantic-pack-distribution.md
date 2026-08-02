# Establish the optional prebuilt semantic-pack crate boundary

This ExecPlan is a living document. The sections `Progress`, `Surprises &
Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to
date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost's analyzer can compile, store, select, and apply semantic-model packs:
typed descriptions of declarations and behavior that are not ordinary workspace
source. The analyzer should not force every embedding product to ship Bifrost's
curated pack inventory. Conversely, the normal `brokk-bifrost` driver should
have one clear place from which it can obtain Bifrost-curated packs.

This initial implementation establishes that Cargo boundary and nothing more.
It adds a published `brokk-bifrost-semantic-packs` crate downstream of
`brokk-bifrost-analysis`. The new crate validates and explicitly registers
embedded compiled packs with the existing generic catalog. The root
`brokk-bifrost` facade depends on both crates, while analysis, runtime, MCP, and
LSP packages do not depend on the curated-pack crate. A consumer can therefore
exclude Bifrost's curated rules by depending on the lower-level packages and
registering its own packs.

The implementation is observable through unit tests that decode a fixture pack,
register it twice without duplicating its logical identity, and reject a broken
registry before catalog mutation. Workspace graph tests reject the forbidden
`brokk-bifrost-analysis -> brokk-bifrost-semantic-packs` edge. The package gate
builds six crate archives and compiles both a facade consumer and a consumer
that depends only on `brokk-bifrost-analysis`.

This initial slice does not close all of issue #1154. It deliberately defers
release-index schemas, remote acquisition, update/rollback policy, CLI lifecycle
commands, and production JDK/Scala or generated-code content. Those are
follow-up milestones after the package boundary has landed and should receive
their own reviewed plan rather than expanding this one.

## Progress

- [x] (2026-08-01 06:28Z) Inspected issue #1154, its closed schema/catalog/runtime
  prerequisites, sibling content issues #1152/#1153, and the separately active
  #1150 local-dependency work.
- [x] (2026-08-01 06:44Z) Implemented the downstream
  `brokk-bifrost-semantic-packs` package, explicit embedded registry, facade
  composition, dependency graph rules, CI selection, release publication order,
  package checks, and focused tests.
- [x] (2026-08-01 06:49Z) Ran the initial focused tests, graph/workflow tests,
  strict task-scoped Clippy, six-archive packaging gate, and repository policy
  check; recorded the pre-existing unreliable whole-workspace policy boundary.
- [x] (2026-08-01 15:50Z) Fetched current origin state and rebased the three
  #1154 commits onto `origin/master` at `4e716f57`. Resolved the sole conflict by
  retaining master's `0.8.18` release version on every workspace dependency.
  The new base includes merged #1150 local-dependency pack generation.
- [x] (2026-08-01 15:50Z) Narrowed this ExecPlan from the full future
  distribution system to the requested initial implementation boundary.
- [x] (2026-08-01 16:22Z) Re-ran focused Rust, workspace graph/workflow,
  formatting, six-archive packaging, and task-scoped strict Clippy checks
  against the rebased `0.8.18` base; every executable build and test gate
  passed.
- [x] (2026-08-01 16:22Z) Reviewed the final `origin/master...HEAD` diff. The
  only semantic-model path changed is the generic public re-export in
  `semantic_model/mod.rs`; #1150's dependency discovery, producer, caching,
  and activation implementations are unchanged.

## Surprises & Discoveries

- Observation: The generic analyzer already owns the trusted local mechanics
  needed by an embedded-content crate.
  Evidence: `crates/bifrost-analysis/src/analyzer/semantic_model/` exposes the
  compiled artifact contract, defensive decoding, `SemanticPackCatalog`,
  session sources, activation, overlays, and content-addressed identity.

- Observation: #1150 merged into `origin/master` before this plan was narrowed.
  Evidence: master commit `4e716f57` is `Generate and cache semantic packs from
  exact local dependencies (#1436)`.

- Observation: The merged #1150 implementation strengthens the proposed
  boundary rather than replacing it.
  Evidence: local dependency discovery and generation now live in the generic
  analysis layer; Bifrost-curated embedded content still has no reason to flow
  back into that layer. The new crate remains downstream of analysis.

- Observation: Production curated content is owned by later issues.
  Evidence: #1152 owns reproducible JDK/Scala release assets and depends on
  #1154; #1153 owns initial Scala, Lombok, and explicit workspace behavior
  models. This slice leaves `BIFROST_EMBEDDED_PACKS` empty rather than inventing
  unreviewed product behavior.

- Observation: The only rebase conflict was a release version change.
  Evidence: the old issue commit added `=0.8.17` package edges while current
  master is `0.8.18`; keeping all master dependencies and adding the new edge at
  `=0.8.18` completed the rebase without semantic conflict.

- Observation: Local Rust command resolution mixes rustup Cargo/rustc with
  Homebrew rustdoc/Clippy.
  Evidence: the initial doctest rejected an LLVM-distinct rlib until rustdoc was
  pinned to `/Users/dave/.cargo/bin/rustdoc`; isolated Clippy passed using the
  complete Homebrew toolchain. Rebased validation must keep one toolchain per
  command.

- Observation: The whole-workspace policy pack does not currently finish
  reliably within its MCP budget.
  Evidence: the initial `bifrost.code-smells` run returned
  `status=unreliable`, exit 2 after the nested-loop rule exhausted discovery and
  later rules were cancelled. Existing issues #1296 and #1423 own this behavior;
  no reported finding was in the initial implementation files.

- Observation: The post-rebase policy rerun remained unreliable even though it
  returned completed per-policy results.
  Evidence: `run_policy` for `bifrost.code-smells` on 2026-08-01 returned
  `status=unreliable`, exit 2, empty top-level execution metadata, and a report
  too large for the MCP response budget. Surfaced findings were repository-wide
  pre-existing locations outside the #1154 diff.

- Observation: The rmcp workspace snapshot was briefly unavailable during the
  final code-reading review.
  Evidence: the first `get_summaries` call for the three boundary files failed
  after five seconds with `workspace snapshot was not ready`; an identical
  retry completed in 3.4 seconds after initialization.

## Decision Log

- Decision: Add `crates/bifrost-semantic-packs` with published package name
  `brokk-bifrost-semantic-packs` and dependency
  `brokk-bifrost-analysis = "=0.8.18"`.
  Rationale: Curated bytes and distribution defaults consume the generic pack
  contract. Keeping the dependency downstream makes them optional for analysis
  consumers and prevents a cycle.
  Date/Author: 2026-08-01 / Codex

- Decision: Keep compiler, artifact, catalog, activation, and overlay types in
  `brokk-bifrost-analysis`.
  Rationale: Every consumer-provided pack needs those generic capabilities.
  Moving them would be an unrelated refactor and would not make curated content
  more optional.
  Date/Author: 2026-08-01 / Codex

- Decision: Let the root `brokk-bifrost` facade depend on and re-export the new
  crate, but do not add it to runtime, MCP, or LSP dependencies.
  Rationale: The root is the complete product driver. Lower-level packages are
  composition points for embedders that want their own semantic rules.
  Date/Author: 2026-08-01 / Codex

- Decision: Require explicit registry invocation and avoid static/global
  registration.
  Rationale: Tests and custom drivers must control the active pack inventory.
  Merely linking the crate must not silently change analyzer correctness.
  Date/Author: 2026-08-01 / Codex

- Decision: Leave the production embedded registry empty in this slice.
  Rationale: The package boundary can be proven with a compiled test fixture;
  #1152 and #1153 own reviewed production content. An empty registry is more
  honest than shipping placeholder behavior.
  Date/Author: 2026-08-01 / Codex

- Decision: Treat release indexes, downloading, lifecycle state, and CLI
  commands as follow-up work outside this initial plan.
  Rationale: Those features introduce network, persistence, rollback, and
  supply-chain policy. They should not obscure review of the fundamental Cargo
  dependency boundary.
  Date/Author: 2026-08-01 / Codex

## Outcomes & Retrospective

The initial crate-boundary slice is implemented and validated on the rebased
`0.8.18` base. Generic analysis and merged #1150 local generation remain
independent of curated Bifrost content; the facade composes both; package and CI
metadata know about the sixth crate. The two focused Rust tests, all 38 selected
Node tests, formatting, task-scoped strict Clippy, dependency validation, and
the package gate all pass. The package gate produced all six archives and
compiled both unpacked consumer shapes, proving that the facade includes the
new crate while an analysis-only consumer does not.

The final diff changes no #1150 producer, dependency-discovery, cache, or
activation implementation. The mandatory `bifrost.code-smells` run remains an
explicit validation limitation: it returned `unreliable` with repository-wide
pre-existing findings and no surfaced location in this issue's files. No remote
registry, automatic networking, lifecycle UI, or production pack content is
claimed; those remain follow-up work.

## Context and Orientation

The repository root is both a Cargo workspace and the `brokk-bifrost` facade.
The workspace members are declared in root `Cargo.toml`. The generic analyzer
is `crates/bifrost-analysis`; protocol hosts are `crates/bifrost-mcp` and
`crates/bifrost-lsp`; `crates/bifrost-runtime` is the typed shared driver
runtime. `src/lib.rs` re-exports the packages that form the complete facade.

Semantic-model support lives under
`crates/bifrost-analysis/src/analyzer/semantic_model/`. A compiled semantic pack
contains canonical manifest bytes and one or more verified shard byte strings.
`SemanticPackCatalog::register_session_pack` accepts a validated pack and a
session source such as `Embedded`; a session pack is visible for that catalog
instance but is not copied into durable storage. The manifest's content digest
is the logical pack identity.

The new `crates/bifrost-semantic-packs/src/lib.rs` defines
`EmbeddedSemanticPack`, a borrowed manifest and shard-byte view;
`EmbeddedPackRegistry`, an explicitly invoked registry; and
`BIFROST_EMBEDDED_PACKS`, the empty production inventory. `decode` uses the
analysis crate's `decode_manifest` and `decode_shard_for_manifest`, then builds
the existing `CompiledSemanticModelPack`. `register_all` decodes every entry
before registering session sources and returns source IDs plus manifest
digests.

`scripts/check-workspace-dependencies.mjs` is the enforced workspace dependency
graph. `scripts/check-workspace-packages.sh` packages every published crate,
unpacks the archives, and compiles consumers. `.github/workflows/ci.yml` selects
the new crate's tests in the Rust matrix. `.github/workflows/release.yml`
publishes analysis first, then the semantic-pack crate, and allows the facade to
publish only after both protocol hosts and semantic packs are visible.

## Plan of Work

First, preserve the new crate boundary after the rebase. Confirm root
`Cargo.toml`, `crates/bifrost-semantic-packs/Cargo.toml`, and `Cargo.lock` all use
workspace version `0.8.18`. Run the workspace dependency validator and its tests
to prove that semantic packs may depend on analysis, analysis may not depend on
semantic packs, runtime/MCP/LSP remain independent, and the facade may compose
the new package.

Second, validate embedded pack behavior. Run the new crate's unit tests with a
single consistent Rust toolchain. Confirm the valid fixture decodes and repeated
registration returns the same logical digest. Confirm the invalid multi-entry
registry produces a shard-count error before the valid first entry appears in
catalog accounting. Inspect the public API to ensure construction and
registration remain explicit and no global initializer mutates catalog state.

Third, validate packaging and release metadata. Run Node tests for CI impact,
workspace graph, CI workflow, and release-promotion workflow. Run the six-crate
package gate with Python 3.12 so the facade's full `python` feature can link.
Confirm it compiles both unpacked consumers: one facade consumer and one
analysis-only consumer with no semantic-pack dependency.

Finally, run formatting, task-scoped strict Clippy, and `git diff --check`.
Inspect `git diff origin/master...HEAD` and specifically search for edits to
#1150's dependency discovery, producer, and activation paths; there should be
none. Update `Progress`, `Surprises & Discoveries`, and `Outcomes &
Retrospective` with exact post-rebase evidence. Commit only the plan update and
any fixes required by validation; do not begin the deferred release-index or
network lifecycle implementation under this plan.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/cd36/bifrost` on the existing
`1154-package-and-distribute-compatible-prebuilt-semantic-packs-safely` branch.
The branch is based on `origin/master` commit `4e716f57`; do not create or switch
branches.

Run the dependency and workflow checks:

    node scripts/check-workspace-dependencies.mjs
    node --test scripts/check-workspace-dependencies.test.mjs \
      scripts/ci-impact.test.mjs \
      scripts/ci-impact-workflow.test.mjs \
      scripts/release-promotion-workflow.test.mjs

Run the focused Rust tests with rustup rustdoc to avoid mixing toolchains:

    RUSTDOC=/Users/dave/.cargo/bin/rustdoc \
      cargo test -p brokk-bifrost-semantic-packs

Run formatting and isolated task-scoped Clippy:

    cargo fmt --all -- --check
    RUSTC=/opt/homebrew/bin/rustc \
      RUSTDOC=/opt/homebrew/bin/rustdoc \
      scripts/with-isolated-cargo-target.sh \
      /opt/homebrew/bin/cargo clippy \
      -p brokk-bifrost-semantic-packs --all-targets -- -D warnings

Run the package gate with an explicit Python 3.12 interpreter:

    PYO3_PYTHON=/Users/dave/.local/share/uv/python/cpython-3.12.11-macos-aarch64-none/bin/python3.12 \
      bash scripts/check-workspace-packages.sh

The package gate may require registry network access. It must end with:

    Validated all six package archives and their unpacked facade and analysis-only consumers

Finish with:

    git diff --check
    git diff --name-only origin/master...HEAD
    git status --short --branch

## Validation and Acceptance

Acceptance requires all focused Rust and Node tests to pass on the rebased
`0.8.18` base. `cargo metadata` validation must show exactly six expected
workspace packages. It must reject an analysis-to-semantic-packs dependency and
require semantic-packs-to-analysis with an exact workspace version.

The embedded registry is accepted when valid canonical manifest/shard bytes
register as `SessionPackSourceKind::Embedded`, repeated registration preserves
one manifest digest, and a later invalid entry prevents earlier registry entries
from being registered in the tested catalog. The production registry must be
empty and registration must require an explicit call.

Packaging is accepted when all six archives remain below the configured size
budget, the semantic-pack archive includes its `Cargo.toml` and `src/lib.rs`,
the unpacked facade consumer compiles, and the unpacked analysis-only consumer
compiles without a dependency on the new crate. Release workflow tests must
show that semantic packs publish after analysis and the facade waits for them.

The final diff must not modify merged #1150 local artifact discovery or pack
generation. It must not add a network dependency, registry URL, update state,
CLI command, large generated payload, or production semantic rule. Those are
explicitly outside this initial implementation.

## Idempotence and Recovery

All validation commands are read-only except Cargo build outputs and temporary
package directories. The package script creates a unique temporary directory
and removes it through its shell trap. The isolated Cargo-target helper likewise
removes its marked target on success, failure, or interruption.

`EmbeddedPackRegistry::register_all` is safe to repeat because the catalog
deduplicates the same manifest digest and session source. Tests use an ephemeral
catalog and do not touch user cache state.

If the rebase validation uncovers a semantic conflict with merged #1150, stop
and record the exact overlap rather than changing #1150 behavior under this
plan. The completed rebase can be inspected with `git reflog`; do not reset or
discard commits. Stage and commit only files changed for this initial slice.

## Artifacts and Notes

The intended dependency shape is:

    brokk-bifrost-analysis
              ^
              |
    brokk-bifrost-semantic-packs
              ^
              |
        brokk-bifrost facade

`brokk-bifrost-runtime`, `brokk-bifrost-mcp`, and `brokk-bifrost-lsp` continue
to depend only on generic analysis/runtime packages. Merged #1150 is part of the
analysis side of this boundary and does not depend on the new crate.

Initial implementation commits after the rebase are:

    841ee8a4 Plan optional semantic pack distribution
    06a2d754 Add optional semantic pack distribution crate
    83b2abea Record semantic pack milestone review

These hashes are historical evidence for this branch state and may change if a
later authorized rebase rewrites them again.

## Interfaces and Dependencies

`EmbeddedSemanticPack::new(source_id, manifest_bytes, shard_bytes)` constructs a
borrowed view without decoding or registering anything.

`EmbeddedSemanticPack::decode(&DecodeLimits)` returns the analysis crate's
`CompiledSemanticModelPack` only after canonical manifest decoding, shard-count
agreement, and manifest-bound shard decoding.

`EmbeddedPackRegistry::register_all(&SemanticPackCatalog, &DecodeLimits)` first
decodes every entry, then explicitly registers each as an embedded session
source and returns `Vec<EmbeddedPackRegistration>`.

`BIFROST_EMBEDDED_PACKS` is a public empty registry prepared for reviewed
content from #1152/#1153. Adding production bytes is not part of this plan.

The new crate has one direct workspace dependency:

    brokk-bifrost-analysis = { path = "../bifrost-analysis", version = "=0.8.18" }

Do not add HTTP, filesystem discovery, database, CLI parsing, or product host
dependencies in this initial slice.

Revision note: 2026-08-01 16:22Z. Rewritten after rebasing onto current
`origin/master` to scope the plan to the requested initial implementation, then
updated with the complete post-rebase validation evidence and outcome. The
former full distribution roadmap was intentionally removed; release indexes,
remote acquisition, lifecycle state, CLI commands, and production content now
require separate follow-up planning.
