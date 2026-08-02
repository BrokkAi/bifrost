# Index exact Go module and standard-library APIs

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document is maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

After this change, a Go workspace can resolve symbols from the exact locally available module graph and selected Go standard library without treating dependency or GOROOT source files as ordinary workspace files. Definition, source presentation, signature, hierarchy, symbol-search, and reference paths will see exported external packages, declarations, members, method sets, and promotion through the existing semantic-model overlay. Resolution remains offline and reproducible: it uses an explicitly selected Go toolchain, target platform, build tags, workspace/vendor mode, exact module versions and checksums, replacements, and content digests.

The behavior is visible in focused integration tests. A small authored Go project imports a fixture dependency and standard-library package whose source roots are deliberately absent from `Project::all_files()`. After discovery, pack preparation, and activation, navigation reaches stable external/model locations, signatures and hierarchy are present, and reference searches identify workspace call sites. Changing a module file, version, replacement, target, or build tag changes only the affected production or active set. Missing local artifacts, cgo, generated declarations that cannot be modeled faithfully, invalid internal imports, cancellation, and budget exhaustion produce explicit incomplete coverage rather than false absence.

## Progress

- [x] (2026-08-02) Verified issue #1353, its parent and completed prerequisites, the clean current issue branch, and exact alignment with `origin/master` at `ddb435c1`.
- [x] (2026-08-02) Diagnosed the existing workspace-only Go package path, structured import/method resolution, exact dependency coordinator, catalog/runtime, and overlay boundaries.
- [x] (2026-08-02) Presented and received approval for the implementation plan.
- [x] (2026-08-02) Recorded and committed this ExecPlan as the design milestone.
- [x] (2026-08-02) Milestone 1: added exact source-set inputs and the minimum structured semantic facts required by Go, with focused unit and integration coverage.
- [ ] Milestone 2: add deterministic, bounded, offline Go toolchain and module-graph discovery.
- [ ] Milestone 3: produce deterministic Go dependency and standard-library API packs from retained exact source bytes.
- [ ] Milestone 4: integrate activated Go packs with definition, presentation, hierarchy, symbol, and reference paths.
- [ ] Milestone 5: complete adversarial fixtures, lifecycle measurements, documentation, validation, policy checking, and specialist review.

## Surprises & Discoveries

- Observation: The shared dependency coordinator accepts only regular-file artifacts.
  Evidence: `read_exact_artifact_while` in `crates/bifrost-analysis/src/analyzer/semantic_model/producer.rs` rejects non-files with `artifact.not_file`, while Go module cache, local replacement, vendor, and GOROOT inputs are selected source trees.
- Observation: Go already has the structured semantic machinery needed after external declarations enter the overlay.
  Evidence: `crates/bifrost-analysis/src/analyzer/go/declarations.rs` extracts signatures and structured type identities; `go/hierarchy.rs` computes aliases, embedded fields, pointer/value method sets, promotion, and structural interface satisfaction; `analyzer/usages/get_definition/go.rs` and `analyzer/usages/go_graph/resolver.rs` use canonical import paths rather than bare package names.
- Observation: The common semantic fact vocabulary does not distinguish constrained type parameters, underlying type expressions, embedded Go types, or pointer receivers.
  Evidence: `TypeFact` stores only parameter names and conventional class hierarchy, while `MemberFact` stores an owner but no receiver form.
- Observation: Two warm `scan_usages_by_location` requests exceeded an explicit ten-second budget during diagnosis.
  Evidence: exact scans for `resolve_jvm_semantic_pack_dependencies` and `prepare_discovered_dependency_semantic_packs` returned empty incomplete failures under rmcp at `ddb435c1`; the evidence is recorded on issue #1416.
- Observation: The authoring schema can add Go's optional structured facts without invalidating existing version-one packs.
  Evidence: Serde defaults make constraints, underlying expressions, embedded types, and receiver metadata absent in existing sources; all 24 semantic-model compiler/schema/golden tests pass with only the expected regenerated golden artifacts.
- Observation: The shell path selected Homebrew's `cargo-clippy` beside rustup's Cargo, which makes same-version compiler artifacts incompatible because their LLVM builds differ.
  Evidence: Strict Clippy initially failed with `E0514` for `cc`; prioritizing `/Users/dave/.cargo/bin` selected one coherent rustup toolchain and the identical isolated-target command passed.

## Decision Log

- Decision: Resolve package selection with the exact configured `go` executable, but permit only metadata commands.
  Rationale: The Go toolchain is the authoritative implementation of module/workspace/vendor selection and build constraints. Bifrost will invoke bounded `go env` and `go list` requests with local-toolchain and offline settings; it will never invoke `go build`, `go test`, `go run`, `go generate`, package initialization, or a project-provided executable.
  Date/Author: 2026-08-02 / Codex
- Decision: Represent directory-backed inputs as exact source sets rather than temporary or fake archives.
  Rationale: A source set records one canonical root plus explicitly selected relative files, reads and retains each file once, and hashes normalized paths plus bytes. This works for module-cache directories, replacements, vendor trees, and GOROOT while keeping absolute paths and mtimes out of identity.
  Date/Author: 2026-08-02 / Codex
- Decision: Reuse Go's current AST declaration and method-resolution machinery rather than parse signatures or paths from text.
  Rationale: The repository forbids mini parsers, and the current Tree-sitter-backed Go implementation already encodes canonical names, structured types, embedding, method sets, promotion, and interface satisfaction.
  Date/Author: 2026-08-02 / Codex
- Decision: Keep external Go source outside the ordinary analyzer and expose stable artifact/model locations through the semantic overlay.
  Rationale: Dependency and GOROOT files are evidence for an immutable pack, not authored workspace `ProjectFile` values. Workspace source retains precedence and external paths do not leak into analyzer persistence or file watching.
  Date/Author: 2026-08-02 / Codex
- Decision: Retain non-exported carrier facts only when an exported surface depends on them.
  Rationale: Go can promote exported methods through an unexported embedded type. The producer needs those private support facts to compute correct public method sets, but search and navigation must not advertise them as exported declarations.
  Date/Author: 2026-08-02 / Codex
- Decision: Keep the semantic authoring schema at version one for the additive Go fields.
  Rationale: The new records are optional, absent fields preserve identical old semantics, and producer identity already invalidates generated outputs when producer behavior changes. A version bump would unnecessarily reject all existing installed and distributed JVM packs.
  Date/Author: 2026-08-02 / Codex

## Outcomes & Retrospective

Milestone 1 is complete. Dependency inputs now distinguish regular files from explicitly selected source sets. Source sets are mount- and enumeration-independent, reject unsafe paths and symlinks, retain each selected file's bytes, and participate in the same catalog production identity and reuse path as regular artifacts. Semantic type/member facts now preserve structured constraints, underlying type expressions, embedded types, and pointer/value receiver metadata through validation, compilation, artifact dependency inventory, decoding, and overlay projection.

## Context and Orientation

A semantic API pack is a deterministic, immutable description of declarations that come from an exact external artifact rather than authored workspace source. `crates/bifrost-analysis/src/analyzer/semantic_model/model.rs` defines authored facts. `compiler.rs` validates and compiles them into content-addressed artifacts. `catalog/` stores and reuses those artifacts. `runtime.rs` selects compatible packs from exact activation evidence. `overlay.rs` exposes active external declarations and relations to ordinary analyzer consumers without inventing workspace files.

`crates/bifrost-analysis/src/analyzer/semantic_model/dependency.rs` joins discovery to production. A `ResolvedDependency` carries activation evidence, provenance, and one or more artifact descriptors. `prepare_discovered_dependency_semantic_packs` reads exact artifact bytes, derives a production identity, reuses a compatible catalog entry or calls a language adapter, compiles and installs the result, and returns activation evidence plus bounded diagnostics. JVM and C# implementations in `analyzer/jvm/external.rs` and `analyzer/csharp/external.rs` are working examples.

Go analysis lives under `crates/bifrost-analysis/src/analyzer/go/`. `packages.rs` derives canonical package identities from the nearest workspace `go.mod` and resolves workspace/vendor import directories. `declarations.rs` parses package declarations, imports, types, aliases, functions, methods, fields, constants, variables, signatures, parameters, and structured type identities. `hierarchy.rs` computes alias targets, embedded types, value and pointer method sets, promotion, and structural interface relations. `analyzer/usages/get_definition/go.rs` performs definition and member resolution. `analyzer/usages/go_graph/resolver.rs` builds canonical usage edges. Today these paths see only files from `Project::all_files()`.

An exact source set is a bounded external input consisting of a canonical logical identity, a filesystem root, and an ordered list of relative source paths selected by the Go toolchain. The reader validates every path, rejects escapes and unsupported filesystem objects, reads each file once under cancellation and size/count budgets, sorts by slash-normalized relative path, and derives a content digest from domain-separated path and byte records. Producers receive the retained bytes, preventing a second read and time-of-check/time-of-use drift.

Go discovery uses a configured `go` executable because Go module minimal-version selection, workspaces, replacements, vendoring, standard-library package selection, and build constraints are toolchain semantics. The production runner sets `GOTOOLCHAIN=local`, `GOPROXY=off`, `GOSUMDB=off`, `GOENV=off`, an explicit `GOOS`, `GOARCH`, `CGO_ENABLED=0`, and explicit build tags. It uses machine-readable `go env -json` and `go list -deps -json -e`/module metadata output only. Missing cache entries or a required newer toolchain remain incomplete; the runner never downloads them.

## Plan of Work

Milestone 1 establishes the shared contracts. Extend the artifact input descriptor in `semantic_model/dependency.rs` so an input is either one regular file or one exact source set with a root and selected relative paths. Extend `producer.rs` with a retained source-set representation and one canonical, stack-safe reader that enforces total files, per-file bytes, total bytes, path depth, symlink, non-regular-file, cancellation, and diagnostic limits. Preserve the existing regular-file API for JVM and C# by projecting it into the generalized representation. Hash source-set records independently of absolute root paths and pass retained bytes to adapters.

In the same milestone, extend `semantic_model/model.rs` with the smallest language-neutral facts needed for Go: a type parameter fact with an optional structured constraint expression, an optional structured underlying type expression, an embedded hierarchy relation, and an optional receiver form distinguishing value and pointer receivers. A structured type expression retains stable rendered text plus the declared type identities found from AST nodes; it is not reparsed from strings. Update compiler validation, canonical ordering, artifact encoding/decoding, overlay projection, JSON schema, tests, and every existing JVM/.NET producer construction site. Preserve semantic schema version one because the additions are optional and producer identity safely invalidates newly generated outputs.

Milestone 2 adds `crates/bifrost-analysis/src/analyzer/go/dependency_discovery.rs` and Go fields in `analyzer/config.rs`. Define a small production command runner with a hand-written fake for tests. The runner starts the configured executable directly, captures bounded stdout/stderr, enforces a timeout, and kills/reaps the child after cancellation or timeout. It clears ambient Go configuration and supplies only reviewed environment values. Parse concatenated JSON values with Serde rather than splitting output.

Discovery first records exact toolchain evidence from `go env -json`, then asks `go list` for the packages reachable from the configured workspace patterns under the selected target and tags. For every returned package, retain its canonical import path, standard-library flag, selected Go files, ignored/cgo/generated coverage, module path/version/sum/go.mod path, replacement metadata, main-module/workspace identity, vendor identity, target, tags, and toolchain. Validate that returned file paths stay below an allowed GOROOT, module-cache module directory, workspace vendor directory, or explicit local replacement root. Group packages into deterministic `ResolvedDependency` values and keep package source lists exact. Missing directories, invalid JSON, command failure, network/toolchain unavailability, cgo-only packages, and truncated output produce bounded diagnostics.

Milestone 3 adds `crates/bifrost-analysis/src/analyzer/go/artifact.rs` and a `GoDependencyPackAdapter`. Refactor cohesive AST helpers from `go/declarations.rs` and `go/hierarchy.rs` so one external source file can be parsed from retained bytes with an explicit canonical import path and logical locator, without constructing an external `ProjectFile` or admitting the file to `TreeSitterAnalyzer`. Convert selected packages into package-module facts, type/alias facts, package-level function/variable/constant facts, type-owned methods and fields, signatures, type parameters and constraints, underlying types, embedding relations, pointer/value receiver metadata, and deterministic method-set/promotion facts.

The producer filters ordinary unexported declarations. It retains only private carriers reachable from an exported declaration when needed to derive an exported promoted member. It records generated-file and unsupported syntax gaps as partial completeness. Standard-library packages use exact toolchain/target selectors; module packages use exact module version/checksum/replacement selectors; all locators are logical and mount-independent. Reordering files or moving identical source roots must not change compiled bytes or digests.

Milestone 4 connects discovery and production to the normal Go analyzer lifecycle through the host-owned catalog and existing activation request, following the JVM/C# preparation pattern. Update Go definition, presentation, hierarchy, symbol, and usage paths only where generic overlay lookup is insufficient. Canonical import paths remain the only package identity; bare package-clause names and same-tail paths never become fallback identities. Add a structured internal-package accessibility check based on import paths and the importing workspace module. Merge pack-provided embedded types and receiver metadata into existing Go method-set and promotion traversal, preserving depth, ambiguity, and pointer-addressability rules. Workspace declarations win conflicts; incompatible or ambiguous pack records remain explicit.

Milestone 5 adds `tests/suite_semantic/go_api_pack.rs` and registers it in the consolidated semantic harness. Tiny consumer projects use `InlineTestProject`; filesystem/toolchain fixtures use temporary directory trees because they test module cache, vendor, GOROOT, and command behavior. Cover module-cache, replacement, vendor, `go.work`, multiple modules, standard library, aliases, generics, constraints, internal packages, build tags, GOOS/GOARCH, same-last-segment imports, embedded fields/interfaces, promotion, pointer receivers, incomplete cgo/generated surfaces, cancellation, limits, and hostile missing-network inputs. Exercise definition, presentation/hover, signature, hierarchy, symbol, and reference APIs through a real activated overlay. Assert every external path is absent from `Project::all_files()`.

Add a deterministic lifecycle measurement alongside the existing semantic-pack measurement suites. Record discovery, source reading, generation, compilation/compression, catalog installation/reuse, activation, retained overlay bytes, cold representative lookups, and warm lookups for a bounded fixture plus an installed local Go toolchain when available. Document the supported discovery contract and explicit incomplete boundaries in `docs/src/content/docs/semantic-model-packs.md` or a focused linked Go library page. Finish with focused tests, formatting, strict featureless Clippy, affected integration suites, package/schema checks, `git diff --check`, the required Bifrost policy selection, and the five guided specialist reviews. Fix accepted findings and rerun the same gates.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/c6d6/bifrost` on the existing branch `1353-index-go-module-and-standard-library-exports-as-exact-api-packs`. Do not create, switch, or rebase branches. At plan approval the branch, its upstream, and `origin/master` all point to `ddb435c1`.

After each Rust edit, run formatting and the narrowest matching tests. Expected commands will evolve with test names, but the final plan must contain the exact successful invocations. Initial commands are:

    cargo fmt --all -- --check
    cargo test -p brokk-bifrost-analysis semantic_model::producer
    cargo test -p brokk-bifrost-analysis semantic_model::compiler
    cargo test -p brokk-bifrost-analysis analyzer::go
    cargo test --test suite_semantic go_api_pack
    cargo test --test suite_analyzers go_
    cargo test --test suite_symbols go_
    cargo test --test suite_usages go_

Run strict task-scoped Clippy without NLP during milestones:

    scripts/with-isolated-cargo-target.sh cargo clippy -p brokk-bifrost-analysis --all-targets -- -D warnings

Before each milestone commit, run `git status --short`, `git diff --check`, and inspect the exact staged file list. Stage only milestone files by explicit path and use a multiline commit body explaining why the milestone exists. Do not push, tag, publish, or open a pull request without explicit authorization.

Before task completion, discover executable repository policy roots as required by repository instructions and make one MCP `run_policy` request selecting `bifrost.code-smells` plus those roots with evaluation date `2026-08-02` and `fail_on: warning`. A `finding` must be reviewed or fixed; an `unreliable` result is a failed validation and must be reported with exact diagnostics.

## Validation and Acceptance

Exact discovery is accepted when fixture metadata selects only locally present package sources for the configured workspace, vendor mode, toolchain, target, and tags; preserves module path/version/sum/replacement and toolchain provenance; refuses implicit downloads; and returns explicit incomplete diagnostics after cancellation, timeout, missing artifacts, cgo-only packages, generated gaps, path escapes, or limits.

Exact production is accepted when identical selected files under different absolute roots and enumeration order produce identical source-set digests, compiled manifests, and shards. Changing one selected file changes only that dependency production. Files excluded by target/build tags do not enter the digest or API. Package, exported type/alias/function/variable/constant/method/field facts, signatures, constraints, underlying types, embedding, method sets, and promotion match the structured fixture expectation.

Consumer integration is accepted when a workspace imports a fixture module and standard-library package whose files are outside `Project::all_files()`, then definition, source presentation, signature, hierarchy, symbol search, and reference APIs return the activated facts and stable external/model locations. Invalid internal imports, wrong module versions/checksums, wrong targets/tags, ambiguous promotion, and unrelated same-tail package names must not resolve.

Performance acceptance requires phase-specific measurements with bounded work counters and no SQL lookup per declaration/reference after activation. Warm representative lookups should remain comfortably below the repository's five-second interactive threshold; any call exceeding five seconds follows the issue-search and evidence protocol in `AGENTS.md`.

The task is complete only after all focused tests, task-scoped strict Clippy, formatting, schema/package checks, documentation checks, policy validation, and guided review are recorded here with their actual results.

## Idempotence and Recovery

Discovery commands are read-only and use offline settings. Source-set reading does not mutate module caches, GOROOT, vendor directories, replacements, or workspace files. Pack installation remains transactional and content-addressed, so retrying after cancellation or failure either reuses a verified production or installs the same immutable bytes. Tests create automatically removed temporary directories and never write to the user's real Go caches.

If a milestone fails, repair forward on the current branch. Do not reset or discard unrelated changes. If a child process times out, kill and reap only the exact child started by the discovery runner. If production is incomplete, do not publish an authoritative empty activation request. Existing catalog compatibility checks quarantine incompatible schema versions and corrupt objects.

## Artifacts and Notes

Initial repository state:

    branch: 1353-index-go-module-and-standard-library-exports-as-exact-api-packs
    HEAD: ddb435c1
    origin/master: ddb435c1
    upstream: origin/1353-index-go-module-and-standard-library-exports-as-exact-api-packs
    worktree: clean
    BIFROST_MCP_RMCP: on

The issue depends on completed semantic-pack catalog, activation, overlay, producer, and exact dependency work. Large generated Go standard-library payloads are not committed merely to satisfy tests. The ordinary analyzer remains useful when no catalog, Go executable, or local dependency source is available; it reports reduced external coverage rather than failing workspace construction.

## Interfaces and Dependencies

The exact names may be refined while preserving these responsibilities. In `semantic_model/dependency.rs`, generalize artifact inputs to a shape equivalent to:

    pub enum ResolvedDependencyInput {
        File { role: DependencyArtifactRole, kind: ExternalArtifactKind, path: PathBuf },
        SourceSet { role: DependencyArtifactRole, kind: ExternalArtifactKind, root: PathBuf, files: Vec<PathBuf> },
    }

The retained exact form must expose ordered logical entries and bytes without rereading:

    pub struct ExactSourceEntry {
        pub relative_path: String,
        pub bytes: Vec<u8>,
    }

    pub enum ExactArtifactPayload {
        File(Vec<u8>),
        SourceSet(Vec<ExactSourceEntry>),
    }

In `analyzer/config.rs`, add `GoAnalyzerConfig` containing the configured executable, discovery enablement, workspace patterns, explicit target, build tags, timeout, and safe bounds. Defaults must preserve today's behavior unless a host explicitly enables Go semantic-pack discovery.

In `analyzer/go/dependency_discovery.rs`, expose a function parallel to JVM/C# discovery:

    pub fn resolve_go_semantic_pack_dependencies(
        config: &GoAnalyzerConfig,
        project: &dyn Project,
        limits: &DependencyPackLimits,
        cancellation: Option<&CancellationToken>,
    ) -> DependencyDiscoveryOutcome;

In `analyzer/go/artifact.rs`, define `GoDependencyPackAdapter` implementing `DependencyPackAdapter`. It accepts only Go source-set artifact kinds, consumes retained exact entries, and delegates no parsing to regex, splitting, or delimiter scanning. A cohesive structured API conversion helper may be shared with workspace declaration and hierarchy code.

The Go command integration uses only the Rust standard library process API and existing Serde dependencies. Do not add a network client, invoke a shell, or add a Go source helper unless direct JSON output proves insufficient and this ExecPlan is updated with measured evidence and a decision-log entry.

Revision note: 2026-08-02 initial approved design recorded before implementation so the feature can be resumed from this file alone.
