# Implement a versioned semantic-model schema and deterministic pack compiler

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document is maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost needs one reviewable contract for facts learned from external API artifacts and facts generated from declarative framework behavior. After this work, a library caller can construct that contract as Rust values or load strict YAML or JSON, compile it to deterministic manifest and shard bytes, and safely decode those bytes under explicit resource limits. Equivalent source formatting produces identical semantic bytes and digests, while malformed versions, references, captures, identifiers, license expressions, or corrupt artifacts are rejected with structured diagnostics.

This issue stops at the schema/compiler boundary. The produced pack is not installed, stored, matched against a workspace, or used by an analyzer. Those lifecycle stages belong to issues #1146 through #1151. Procedure-effect and data-flow summaries remain owned by #823.

## Progress

- [x] (2026-07-29 07:21Z) Refreshed the live branch, remote, and issue #1145 state and confirmed that the existing issue branch is clean.
- [x] (2026-07-29 07:21Z) Inspected the analyzer module boundary, canonical hashing helper, identifier rules, packaging exclusions, and documentation navigation.
- [x] (2026-07-29 08:13Z) Added the strict public authoring model, source loaders, validation, compiler options, diagnostics, and generated JSON Schema.
- [x] (2026-07-29 08:13Z) Added the canonical compiled manifest/shard model, stable semantic/content/stored digests, deterministic routing metadata, measured raw-DEFLATE compression, and bounded decoder.
- [x] (2026-07-29 08:13Z) Added declaration and generator fixtures plus behavior-focused integration and unit tests for equivalence, invalid inputs, corruption, non-canonical bytes, cross-shard references, and resource caps.
- [x] (2026-07-29 08:13Z) Added public semantic-model-pack documentation, sidebar navigation, and exact fixture-backed documentation checks.
- [x] (2026-07-29 10:16Z) Ran architecture, security, intent, duplication, and DevOps reviews; addressed the confirmed schema, vocabulary, capture-binding, integrity, decoder-validation, cross-shard-reference, and compiler-limit findings.
- [x] (2026-07-29 09:43Z) Completed the Rust, docs, and package validation matrix; recorded the policy-checking service as unavailable in the implementation session rather than treating tool visibility as a successful policy run.
- [x] (2026-07-29 09:55Z) Rebased the five issue commits onto current `origin/master`, reran formatting, strict all-feature Clippy, and the 19 semantic-pack plus five docs-focused tests, and exercised the newly available policy service before publication.

## Surprises & Discoveries

- Observation: The issue branch is five commits behind `origin/master`, but the repository instructions prohibit rebasing or switching branches without an explicit request.
  Evidence: `git rev-list --left-right --count HEAD...origin/master` returned `0 5`; work continues on the prepared branch.
- Observation: The installed Bifrost navigation skill is present, but its MCP search and source-reading tools are not callable in this session.
  Evidence: the active tool inventory contained no `search_symbols`, `get_symbol_sources`, or `get_summaries` entry, so repository-local `rg` and focused file reads are the available fallback.
- Observation: Declaration references must be collected across the whole pack before individual shards can be validated, because a member or relation may point into a later shard.
  Evidence: the focused `cross_shard_references_are_resolved_after_global_collection` test moves the owning type to a later shard and compiles successfully after validation became two-pass.
- Observation: This host exposes same-version Rust tools from both Homebrew and rustup, but their compiler metadata is incompatible; explicitly selecting only Cargo is insufficient because Cargo resolves `cargo-clippy` and `rustdoc` separately.
  Evidence: strict Clippy passed through `/Users/dave/.cargo/bin/cargo-clippy`; the all-feature test matrix reached doctests after every runnable Rust target passed, then Homebrew `rustdoc` rejected rustup-built dependencies with E0514. The isolated doctest gate passed after setting `RUSTDOC=/Users/dave/.cargo/bin/rustdoc`.
- Observation: A syntactically strict compiled struct is not a sufficient trust boundary: compact JSON can still contain semantically invalid values or non-normalized semantic-set ordering after an attacker recomputes byte hashes.
  Evidence: Specialist review produced both cases; the decoder now reconstructs an authored pack, runs bounded semantic validation, compares shared normalization, and adversarial tests rehash both invalid forms.
- Observation: Cross-shard references cannot be fully validated by an independently decoded shard.
  Evidence: descriptors now carry compiler-derived sorted definition/reference inventories, allowing manifest decoding to prove pack-wide uniqueness and reference closure before individual shards are loaded.
- Observation: Three process-spawning MCP session tests cannot run inside the filesystem sandbox even though they pass with ordinary host permissions.
  Evidence: the sandboxed all-feature run reported `PermissionDenied` only for the three `benchmark::mcp_session` cases; the elevated exact rerun passed all 2,071 runnable library tests, with seven ignored, and continued through every runnable integration target without a failure.
- Observation: The installed policy skill does not imply that its runtime service is callable or that a completed response is reliable.
  Evidence: the implementation session exposed neither `list_policies` nor `run_policy`. During publication the tools became callable, but the first `bifrost.code-smells` run cancelled at 5.06 seconds and the warm run returned `status: unreliable` because multiple repository-wide queries exhausted their fact budgets. Existing issues #1296 and #1306 own this behavior.

## Decision Log

- Decision: Expose both a typed Rust authoring API and strict YAML/JSON loading into that same type.
  Rationale: Producers can construct packs without text serialization, while humans can review and maintain source packs; both paths necessarily share validation and lowering.
  Date/Author: 2026-07-29 / Codex
- Decision: Use compact canonical JSON as the uncompressed artifact representation and raw DEFLATE level 6 only when compression saves at least 1 KiB and five percent.
  Rationale: Canonical JSON is inspectable and easy to validate by reserialization; measured compression avoids CPU and format overhead for small shards.
  Date/Author: 2026-07-29 / Codex
- Decision: Keep provenance and license in the content identity but outside semantic identity.
  Rationale: Repackaging metadata must remain integrity protected without changing the identity of the facts and rules a runtime would apply.
  Date/Author: 2026-07-29 / Codex
- Decision: Model recursive type references and template expressions as bounded trees and validate them with explicit work stacks.
  Rationale: Inputs are untrusted, and iterative validation keeps the compiler stack-safe while enforcing a depth limit of 64.
  Date/Author: 2026-07-29 / Codex
- Decision: Do not introduce analyzer activation or conversion adapters in this change.
  Rationale: Existing JVM and C# external declarations are useful vocabulary references, but connecting compiled packs to analyzers would cross the runtime-matching and installation boundaries explicitly excluded by #1145.
  Date/Author: 2026-07-29 / Codex
- Decision: Distinguish stable-ID template positions from language-name template positions during validation.
  Rationale: Stable IDs intentionally accept only lowercase portable characters, while real declaration names may be qualified or case-sensitive. Applying the stable-ID rule to both would reject valid generated declarations and still fail to constrain ID-only transforms.
  Date/Author: 2026-07-29 / Codex
- Decision: Validate declaration references after a pack-wide declaration-ID collection pass.
  Rationale: Shards are routing/storage boundaries, not semantic visibility boundaries; source order must not decide whether a cross-shard owner or relation reference is valid.
  Date/Author: 2026-07-29 / Codex
- Decision: Bind captures to explicit trigger-relative sources and projections rather than declaring only their result type and cardinality.
  Rationale: A machine-authored rule must say how a trigger produces each value. The typed binding also lets compilation reject unavailable sources, kind mismatches, and cardinality mismatches before runtime integration.
  Date/Author: 2026-07-29 / Codex
- Decision: Keep the decoded compiled payload behind an immutable validated wrapper and expose read-only typed views.
  Rationale: Direct deserialization into publicly mutable authoring structures would let callers bypass normalization and semantic validation while presenting a value as compiled IR.
  Date/Author: 2026-07-29 / Codex
- Decision: Use ordinary SHA-256 for exact content and stored byte identities, and reserve domain-separated length-framed hashing for semantic identities.
  Rationale: Content fields should be independently reproducible with standard tooling; semantic identity benefits from explicit domain separation. The public documentation specifies both domains and framing.
  Date/Author: 2026-07-29 / Codex
- Decision: Add a full manifest content digest and a manifest-bound shard decoder.
  Rationale: The semantic digest intentionally excludes provenance, license, and producer, but those fields still require integrity protection and must agree with duplicated shard envelope fields.
  Date/Author: 2026-07-29 / Codex

## Outcomes & Retrospective

The version-one authoring and artifact contract is implemented for both typed machine producers and strict YAML/JSON authors. Nineteen focused integration tests and seven artifact unit tests cover source equivalence, schema drift, deterministic lowering, digest boundaries, compression, semantic canonicality, cross-shard references, corrupt artifacts, and resource limits. Architecture, security, intent, duplication, and DevOps reviews were completed and all confirmed findings were addressed.

Release validation is green for formatting, strict all-target/all-feature Clippy, the all-feature Rust test matrix, the matching-toolchain doctest stage, docs checks/build, and crate packaging. The all-feature library suite reported 2,071 passed and seven ignored before all runnable integration targets completed without failure. The docs build produced 58 pages and checked 5,555 links. The packaged crate was 7,093,389 bytes and included the public schema while excluding development fixtures.

The built-in `bifrost.code-smells` gate was ultimately executable but unreliable: the cold request cancelled at the MCP deadline and warm requests completed with inconclusive repository-wide policies after fact-budget exhaustion. Changed-file prompts were reviewed individually. Fixture reads and serialization operate on different fixtures or mutated values per iteration, while semantic-model sorting canonicalizes distinct selector, fact, and shard-local sets; none is loop-invariant work that can be hoisted. The service limitation is tracked by #1296 and #1306 and is not represented as a clean policy result.

## Context and Orientation

The crate root is `src/lib.rs`, and analyzer-owned public APIs are exported through `src/analyzer/mod.rs`. The new `src/analyzer/semantic_model/` module will be public but inert: it defines data and compilation functions without registering with any analyzer. Existing external declaration DTOs in `src/analyzer/jvm/external.rs` and `src/analyzer/csharp/external.rs` inform the declaration vocabulary but remain unchanged.

An authored pack is the human- or producer-written value. A compiled pack is an in-memory manifest plus separately addressable shard byte strings. A shard is one independently loadable group containing exactly one payload kind: declaration facts or generator rules. Canonical means that one semantic value has one compact JSON encoding: object field order follows Rust struct field order, semantic sets are sorted by stable identifier, and ordered values such as parameters and concatenation operands retain their authored order. A routing key is a small manifest value, such as a package/module selector or generator trigger kind, that lets a later runtime avoid loading unrelated shards.

Three shard digests serve different boundaries. The semantic digest covers activation, compatibility, completeness, safety, and the payload after default expansion. The content digest covers the entire uncompressed compiled shard including provenance and license. The stored digest covers the actual raw or compressed bytes and detects transport/storage corruption. Digests are lowercase SHA-256 hexadecimal strings; semantic digests use documented domain separation, while exact byte digests use ordinary SHA-256. A separate manifest content digest integrity-protects its complete non-self-referential view.

The compiler enforces conservative defaults: at most 64 MiB of source input or uncompressed data per shard, 1 GiB across a pack, 4,096 shards, two million records per pack, 250,000 records per shard, 16 KiB per string, and depth 64 for type/template trees. All limits live in public option structs so tests and embedders can lower them defensively.

## Plan of Work

Create `src/analyzer/semantic_model/model.rs` with strict `serde` and `schemars` structs and tagged enums for the version-one envelope. The envelope contains identity, producer, language/ecosystem, compatibility, activation selectors, provenance, SPDX license, completeness, safety, and shards. A declaration shard contains types and members with structured signatures, type references, ownership, hierarchy, aliases, extension surfaces, navigation/reference relations, and typed locators. A generator shard contains typed triggers, declared captures, and typed declaration/relation emissions. Template values permit only literals, declared capture references, ordered concatenation, and a fixed set of ASCII transforms.

Create `src/analyzer/semantic_model/source.rs` to deserialize one JSON or YAML document. Both formats target the same `#[serde(deny_unknown_fields)]` model. YAML loading uses `serde-saphyr` with duplicate-key rejection, strict booleans, merge-key rejection, and alias/depth/event/scalar budgets. Source size is checked before parsing. Parsing errors become path-addressed diagnostics immediately.

Create `src/analyzer/semantic_model/validate.rs` to aggregate deterministic diagnostics for invalid schema versions, stable identifiers, language/ecosystem and activation compatibility, SPDX expressions, duplicate or missing references, record counts, structured type shapes, capture declarations and cardinality, emitted identifier positions, and unsupported transform/shape combinations. Sort diagnostics by path and code. Traverse recursive values iteratively and stop at the configured depth.

Create `src/analyzer/semantic_model/artifact.rs` and `compiler.rs`. Validation feeds a lowering pass that fills defaults, sorts semantic sets, derives routing keys, serializes compact canonical JSON, and computes domain-separated hashes. Each shard is optionally encoded with fixed raw DEFLATE level 6 according to measured savings or an explicit test option. The readable manifest records payload kind, routing keys, encoding, raw/stored sizes, and all three digest roles. Defensive decoders check versions and declared sizes before allocation, hash stored bytes before decoding, stream decompression into a bounded output, reject truncation/trailing data, deserialize strict compiled structs, reserialize to require canonical bytes, and confirm descriptor identity, kind, routing keys, sizes, and digests.

Generate `schemas/semantic-model-pack-v1.schema.json` from the Rust authoring model. An exact integration test compares the checked-in file with `authoring_json_schema()`, so changing the model without regenerating the contract fails. Add source and golden artifact fixtures under `tests/fixtures/semantic-model-packs/` and behavior-focused tests in `tests/semantic_model_pack.rs`.

Document authoring, extension/versioning, payload boundaries, digest meanings, limits, and the inactive-runtime boundary in `docs/src/content/docs/semantic-model-packs.md`, then add it to `docs/astro.config.mjs`. Examples in the page refer to the tested fixture files so documentation cannot silently invent a second syntax.

## Milestones

Milestone one establishes the authoring contract. At its end, typed Rust, YAML, and JSON values deserialize to one strict model; semantic validation returns stable structured diagnostics; the generated schema is checked in and protected by a drift test. Run the focused semantic-model tests and observe valid fixtures accepted and malformed fixtures rejected.

Milestone two establishes deterministic artifacts. At its end, equivalent YAML/JSON and typed inputs produce byte-identical manifests and shards, measured compression follows the documented threshold, and defensive decoding rejects corruption, mismatch, non-canonical bytes, truncation, trailing data, or configured cap violations. Focused golden and corruption tests prove each behavior.

Milestone three completes the public contract and release evidence. At its end, the docs site exposes the format and its current non-runtime status, specialist review findings have been resolved or recorded, and formatting, strict Clippy, full feature tests, docs checks/build, package verification, and repository policies pass.

## Concrete Steps

All commands run from `/Users/dave/.codex/worktrees/fa9e/bifrost`.

After each code milestone, format and run the focused target:

    cargo fmt
    scripts/with-isolated-cargo-target.sh cargo test --test semantic_model_pack

After documentation changes, run:

    npm --prefix docs run check
    npm --prefix docs run build

For final Rust and packaging validation, run:

    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python
    scripts/check-crate-package.sh

Finally run the repository policy roots together with `bifrost.code-smells` through the installed policy-checking service. A clean result has no finding and no unreliable result.

## Validation and Acceptance

The checked-in schema must be byte-for-byte equal to `authoring_json_schema()`. Version omission, version zero, future versions, and unknown fields must fail. A declaration fixture and a generator fixture must compile from both YAML and JSON to exactly the same canonical bytes and semantic digest as the equivalent typed Rust value. Reordering source object keys, adding YAML comments, and formatting whitespace must not change output; reordering ordered parameters must change semantic identity.

Validation tests must cover duplicate stable IDs, invalid stable IDs, incompatible selectors, invalid SPDX expressions, missing type or owner references, unknown captures, capture cardinality mismatches, invalid identifier emission, excessive strings/records/depth, and every tagged payload boundary. Decoder tests must cover raw and compressed shards, stored-hash corruption, wrong sizes and digests, truncated streams, trailing compressed bytes, excessive expansion, non-canonical JSON, and descriptor/payload mismatches.

The public documentation must show fixture-backed examples and state plainly that compiling a pack does not activate it in Java, C#, or any other analyzer. The crate packaging check must include the generated schema because library consumers need the public format contract.

## Idempotence and Recovery

Compilation and schema generation are pure operations: rerunning them replaces no user data and produces the same bytes. Focused builds use `scripts/with-isolated-cargo-target.sh`, which removes its managed temporary target even after failure. If a generated-schema test reports drift, regenerate from the current model, inspect the diff, and rerun the exact test. No database migrations, downloads, registry writes, or analyzer state mutations occur in this plan.

## Artifacts and Notes

The live issue is `https://github.com/BrokkAi/bifrost/issues/1145`. Its parent epic is #1144. Follow-on issues #1146 through #1151 own persistence, matching, installation, registry, and user tooling. The branch started from commit `49a7d86f` and intentionally remains there because branch movement was not requested.

## Interfaces and Dependencies

`src/analyzer/semantic_model/mod.rs` must publicly expose:

    pub fn compile_source(
        format: SourceFormat,
        bytes: &[u8],
        options: &CompilerOptions,
    ) -> Result<CompiledSemanticModelPack, Vec<Diagnostic>>;

    pub fn compile_pack(
        pack: &AuthoredSemanticModelPack,
        options: &CompilerOptions,
    ) -> Result<CompiledSemanticModelPack, Vec<Diagnostic>>;

    pub fn decode_manifest(
        bytes: &[u8],
        limits: &DecodeLimits,
    ) -> Result<CompiledPackManifest, ArtifactError>;

    pub fn decode_shard(
        descriptor: &CompiledShardDescriptor,
        bytes: &[u8],
        limits: &DecodeLimits,
    ) -> Result<CompiledShard, ArtifactError>;

    pub fn decode_shard_for_manifest(
        manifest: &CompiledPackManifest,
        descriptor: &CompiledShardDescriptor,
        bytes: &[u8],
        limits: &DecodeLimits,
    ) -> Result<CompiledShard, ArtifactError>;

    pub fn authoring_json_schema() -> String;

The public types include `AuthoredSemanticModelPack`, `CompiledSemanticModelPack`, `CompiledPackManifest`, `CompiledShardDescriptor`, `CompiledShard`, `CompilerOptions`, `DecodeLimits`, `Diagnostic`, `SourceFormat`, and the tagged declaration/generator vocabulary. `CompilerOptions` carries source and semantic limits plus a compression policy with automatic, always-raw, and always-compressed modes. `DecodeLimits` independently caps manifest bytes, stored shard bytes, raw shard bytes, and total decoded records.

Add direct dependencies on `serde-saphyr` for strict reviewed YAML, `schemars` for a Rust-derived JSON Schema, `spdx` for standard license-expression validation, and `flate2` for a fixed raw-DEFLATE codec. Reuse `serde`, `serde_json`, `semver`, `sha2`, and `src/analyzer/canonical_hash.rs` already present in the crate.

Plan revision note (2026-07-29 07:21Z): Created the initial self-contained implementation plan after refreshing the live issue and repository state. It fixes the typed-plus-source API, canonical JSON artifact, digest boundaries, compression rule, resource limits, and strict follow-on issue boundaries approved in the preceding planning discussion.

Plan revision note (2026-07-29 08:13Z): Marked the authoring, artifact, fixture, and documentation milestones complete after focused tests passed; recorded the two-pass cross-shard reference requirement, separate stable-ID/language-name template validation, and the shared-target compiler contamination that makes isolated final checks mandatory.

Plan revision note (2026-07-29 10:16Z): Recorded and resolved specialist-review findings by tightening schema version/variant closure, adding trigger-bound captures and missing declaration vocabulary, separating the validated compiled boundary, covering full manifest integrity and envelope agreement, validating semantic canonicality on decode, carrying cross-shard reference inventories, and aligning compiler output limits with decoder defaults.

Plan revision note (2026-07-29 09:43Z): Completed final Rust, docs, and packaging validation; documented the host's mixed Homebrew/rustup toolchain and sandbox-only process-test failures; verified the affected stages with a consistent rustup toolchain and host permissions; and recorded the unavailable policy service as the only remaining environmental validation limitation.

Plan revision note (2026-07-29 09:55Z): Rebased onto current `origin/master`, reran the post-rebase Rust gates, and replaced the earlier unavailable-policy note with the actual cold-cancellation and warm-unreliable results after the MCP tools became callable. Reviewed every changed-file prompt and linked the existing runtime owners rather than claiming a clean policy result.
