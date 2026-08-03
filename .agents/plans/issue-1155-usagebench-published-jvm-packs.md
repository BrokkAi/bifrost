# Exercise published JVM semantic packs through UsageBench

This ExecPlan is a living document and must be maintained in accordance with `.agents/PLANS.md`. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` are updated as work proceeds. The original hand-off forbade publication actions, so implementation and validation completed without them; the user subsequently authorized commits, pushes, and ready-for-review pull requests.

## Purpose / Big Picture

After this work, a UsageBench run can acquire the exact Bifrost v0.8.19 semantic-pack release bundle, verify its SHA-256, install it into a fresh isolated catalog, activate its JDK 21.0.8 and Scala 2.13.16 declaration packs, and assert analyzer-visible navigation, signature, hierarchy, provenance, completeness, and version behavior. A report records both repository revisions plus the release-bundle and activation identities, so an inactive or empty catalog cannot appear to pass.

## Progress

- [x] (2026-08-03 00:00Z) Fetch and inspect both repositories, issue #1155, and the v0.8.19 release asset.
- [x] (2026-08-03 00:00Z) Diagnose the existing Bifrost model-URI/provenance contract and UsageBench's workspace-only location/reporting contract.
- [x] (2026-08-03 10:00Z) Add an explicit SearchTools host configuration that opens a caller-selected semantic-pack catalog and activates exact Java/Scala evidence.
- [x] (2026-08-03 10:00Z) Add focused Bifrost integration tests for positive, absent, and incompatible activation/navigation behavior.
- [x] (2026-08-03 10:00Z) Extend UsageBench's schema, runner, isolated acquisition/install lifecycle, external-location matching, probes, and report evidence.
- [x] (2026-08-03 10:00Z) Add representative Java and Scala fixture cases selected from the actual v0.8.19 bundle.
- [x] (2026-08-03 10:30Z) Run final offline schema validation, focused Rust tests, exact positive and negative executions, formatting, and Bifrost policy checks.
- [x] (2026-08-03 11:00Z) Publish the validated Bifrost and UsageBench changes for ready-for-review pull requests after explicit user authorization.
- [x] (2026-08-03 12:00Z) Repair PR #1515's external authored-source regression and rerun the three CI failures plus the issue-specific navigation tests.

## Surprises & Discoveries

- Observation: Bifrost already exposes the required portable destination and provenance rather than requiring a benchmark identity.
  Evidence: `SemanticModelLocation::Model` uses `bifrost-model://v1/<pack-semantic-digest>/<record-kind>/<stable-record-id>`, while `SemanticModelProvenance` serializes pack, producer, completeness, and activation evidence.
- Observation: release installation exists, but the SearchTools host cannot opt into a Java/Scala catalog at startup.
  Evidence: `bifrost-semantic-pack install BUNDLE CATALOG` installs verified packs, while SearchTools constructs `SearchToolsService` without a semantic-model host context; the only caller-owned workspace activation helper is Python-specific.
- Observation: the rmcp `search_symbols` call with six semantic-model patterns hung for more than one minute and was terminated.
  Evidence: request arguments were `patterns=[SemanticModelLocation, SemanticModelProvenance, Virtual, PackActivation, SemanticPack, ModelLocation], include_tests=true, limit=100` with `BIFROST_MCP_RMCP=on`.
- Observation: the published Scala pack exposed three product gaps when exercised through ordinary tools: external source locators became fake workspace anchors, explicit imports fell back to conflicting short-name model lookup, and model-only hierarchy was bypassed when the workspace provider was absent or ambiguous.
  Evidence: focused regression tests now cover portable source-locator URIs and Java/Scala explicit-import navigation; the exact Scala run now passes its `List` hierarchy probe.
- Observation: JDK shard selection requires the exact module as well as toolchain, target, and artifact digest.
  Evidence: `java.base` evidence activates one shard with 15,394 records; omitting the module safely selected zero shards with incompatible explanations.
- Observation: the repository-wide `bifrost.code-smells` pack reports existing findings, but none overlap changed hunks.
  Evidence: the only findings in changed files are pre-existing sleep-loop sites at `searchtools_service.rs:4160` and `:4925`, plus a pre-existing sort-loop site at `overlay.rs:947`.
- Observation: a `Locator::Source` remains authored-source evidence even when its archive path is outside the workspace.
  Evidence: the JDK, Scala, and npm semantic-pack integration tests preserve external source locators; converting those records to model-only URIs broke all three on PR #1515.

## Decision Log

- Decision: Reuse Bifrost's `bifrost-model://v1` URI and serialized `SemanticModelProvenance` directly.
  Rationale: It is already the stable public product contract and avoids translating dependency records into workspace files.
  Date/Author: 2026-08-03 / Codex
- Decision: Keep release acquisition and installation in UsageBench, but put activation into a generic Bifrost host configuration.
  Rationale: Acquisition must remain separate from analyzer startup, while activation is product behavior and must not be emulated by benchmark-side raw-pack inspection.
  Date/Author: 2026-08-03 / Codex
- Decision: Use fresh run-scoped download, bundle, and catalog directories, with offline unit fixtures.
  Rationale: This prevents mutable host caches or implicit downloads from determining results.
  Date/Author: 2026-08-03 / Codex
- Decision: Preserve external `Locator::Source` records as zero-range authored anchors and reserve portable model URIs for records without authored-source evidence.
  Rationale: Workspace membership determines whether source text can be opened locally, not whether the pack's structured source provenance is authored.
  Date/Author: 2026-08-03 / Codex

## Outcomes & Retrospective

The exact v0.8.19 Java and Scala UsageBench cases pass. Each run downloads and verifies the 9,226,203-byte release archive, uses the shipped verifier and installer with a fresh catalog, asserts type and member surfaces, signature, hierarchy, exact provenance/completeness, and portable model navigation. The Java case activates `java.base`; the Scala case activates `scala-library` 2.13.16. Absent and incompatible evidence remain safe misses in focused integration coverage. The validated changes were later committed and published for review after explicit user authorization.

## Context and Orientation

Bifrost stores compiled semantic packs in `crates/bifrost-analysis/src/analyzer/semantic_model/catalog/` and projects activated declarations through `crates/bifrost-analysis/src/analyzer/semantic_model/overlay.rs`. The command in `crates/bifrost-semantic-packs/src/bin/bifrost-semantic-pack.rs` verifies and installs a release bundle. SearchTools MCP servers are assembled in `crates/bifrost-mcp/src/mcp_common.rs` and `crates/bifrost-mcp/src/rmcp_host.rs`, backed by `crates/bifrost-mcp/src/searchtools_service.rs`.

UsageBench's authored contract is in `src/lib.rs` and `schema/benchmark-case.schema.json`. Its Bifrost execution path is `src/runners/bifrost.rs`; shared normalized locations and report structs are in `src/runners/mod.rs`. Existing case documents are under `benchmarks/cases/`, and `.github/workflows/benchmark.yml` is the scheduled runner.

A semantic-pack catalog is an explicit directory containing the immutable compiled pack objects and SQLite lifecycle metadata. Activation means matching exact workspace evidence, such as JDK or Scala version, against installed pack selectors and publishing a non-empty immutable overlay into the analyzer snapshot. A model URI identifies a declaration in that overlay without pretending it is source code.

## Plan of Work

First, add one explicit Bifrost SearchTools startup configuration accepted by both the handwritten and rmcp hosts. It names a catalog root and exact activation evidence. The service opens the catalog read-only, builds the workspace analyzer, activates the requested packs, and exposes a structured activation snapshot through public tool results or a small status tool. Startup must fail or report incomplete state honestly; it must never select a newer pack after a version mismatch.

Second, add Bifrost integration coverage using bounded compiled pack fixtures. Start both activation paths against Java and Scala fixture workspaces and assert type/member/signature/hierarchy navigation plus full model provenance. Repeat with an absent catalog and incompatible version and assert safe misses.

Third, extend UsageBench documents with optional semantic-pack requirements that pin release version, asset URL, asset SHA-256, pack selectors, and activation evidence. Validate these fields strictly. During `run-bifrost`, acquire the asset into the run directory, verify the digest, unpack and verify it with the exact built Bifrost companion CLI, and install into a fresh catalog before any analyzer process starts. Pass only the catalog and evidence into analyzer startup.

Fourth, represent expected model destinations with their actual `bifrost-model` URI identity and independent provenance assertions. Workspace locations continue to require `benchmark://source`; location matching branches by scheme so external identities are exact while source range behavior is unchanged. Record bundle digest, installed pack identities, active pack hashes, activation explanations, and non-empty activation state in the run report.

Finally, inspect the v0.8.19 bundle to select stable JDK and Scala declarations, add small workspace fixtures that reference them, and run exact positive, absent, and incompatible versions. The negative executions must fail the corresponding positive assertions rather than becoming skipped or expected failures.

## Concrete Steps

Work in `/Users/dave/.codex/worktrees/508a/bifrost` for Bifrost and `/Users/dave/Workspace/BrokkAi/usagebench` for UsageBench. Use `cargo fmt` and focused `cargo test` commands in each repository. Use `cargo run -- validate benchmarks/cases` in UsageBench. For the exact run, invoke UsageBench with a pinned Bifrost revision and the v0.8.19 semantic bundle. Do not commit or publish.

## Validation and Acceptance

Offline tests must prove schema compatibility for all existing cases and validate bounded Java/Scala semantic-pack fixtures. The exact online preparation must accept only v0.8.19 and SHA-256 `6f28e083f8be1a5d27465d8aeb0d2de1146b490bfac3e32949481b4478e24568`. A positive report passes type and member navigation, signatures, hierarchy, provenance, completeness, and exact-version assertions for both packs. The same cases fail with the catalog absent, and incompatible version evidence yields no modeled target and never falls forward. Reports contain exact UsageBench and Bifrost revisions, the bundle digest, installed pack identities, active semantic digests, and activation explanations.

Before completion, run Bifrost's `bifrost.code-smells` policy pack together with every executable repository policy root named by the repository in one MCP request. A `finding` must be reviewed and an `unreliable` result is a failed validation.

## Idempotence and Recovery

All acquisition and catalog directories are run-scoped and may be recreated. Digest verification occurs before extraction or installation. Unit tests use checked-in bounded fixtures and do not access the network. If an exact run is interrupted, delete only its named run directory and retry; never use or mutate the host's normal semantic-pack cache.

## Artifacts and Notes

The live GitHub release reports the semantic bundle as 9,226,203 bytes with digest `sha256:6f28e083f8be1a5d27465d8aeb0d2de1146b490bfac3e32949481b4478e24568`.

## Interfaces and Dependencies

Bifrost must expose one serializable host configuration shared by both MCP stacks and one structured activation-status response whose fields are product types, not benchmark wrappers. UsageBench must add optional document configuration and report structs derived with Serde and JsonSchema, use its existing MCP client for analyzer-visible assertions, and use standard Rust filesystem/process primitives plus its existing hashing dependencies for acquisition verification.

Revision note (2026-08-03): Initial plan created after live repository, issue, release, URI, reporting, and activation-seam inspection. Updated after exact artifact runs exposed and verified the import, URI, hierarchy, and selector seams.
