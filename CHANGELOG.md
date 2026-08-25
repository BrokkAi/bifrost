# Changelog

This changelog records meaningful changes to Bifrost's public interfaces,
analysis behavior, integrations, and release artifacts. It is curated from the
complete private release range because the public open-core repository is a
projection and its commit history does not contain every source commit.

## [0.10.6] - 2026-08-25

### Added

- Shipped standard-library procedure-summary packs for three new languages:
  Rust (`bifrost.rust-std-golden-summaries`), JavaScript, and TypeScript
  (`bifrost.javascript-golden-summaries`, `bifrost.typescript-golden-summaries`),
  joining the existing JDK and CPython golden packs so every policy-pack
  language carries stdlib taint-flow summaries.
- Rust, JavaScript, and TypeScript call sites now publish bindable external
  identities: Rust `::`-qualified and `use`-imported callees, JS/TS
  module-bound callees (`path.join` after an import or `require`), and JS/TS
  runtime globals (`JSON.parse`, `Buffer.from`) can all bind authored
  procedure summaries under `require-model` taint policies.
- Golden summary packs can activate language-intrinsically for ecosystems
  without toolchain version evidence (cargo, npm).
- Added configurable forward, backward, and automatic direction planning for
  value-flow, taint, and typestate analyses, with selection reasons and work
  estimates.
- Added bounded near-miss ranking to policy explanations in the CLI and MCP,
  helping authors understand why an expected policy match was not produced.
- Made the standalone `bifrost-policy-scan` action publishable through the
  GitHub Actions Marketplace.

### Changed

- Split flow solvers and RQL execution into dedicated public crates, reducing
  analyzer coupling while preserving the facade query API and wire formats.
- Made reusable flow caches explicitly owned by each logical workspace so MCP,
  LSP, runtime, and policy evaluation retain them across analyzer replacement.
- Accelerated definition navigation and path-scoped Java caller scans with
  targeted, bounded relational queries.
- GitHub Releases now use this curated version entry as their release notes
  instead of generating an incomplete list from projected pull requests.
- Rust `Self` is no longer reported as a textual type reference to its nominal
  owner. It still resolves associated members, return types, and constructors
  inside an `impl`, but rename and reference results list only explicit
  nominal-type tokens.
- Scala find-usages of a base method no longer reports statically concrete
  calls made through a subtype receiver; the overriding declaration is still
  reported, so the family stays reachable in one hop. Case-class `copy` now
  navigates to the case class itself while still carrying the generated-member
  provenance that names the rule which produced it.
- C# references to a `using` alias navigate to the written alias binder,
  matching Roslyn go-to-definition. An alias whose target the workspace does
  not index still reports the unresolvable import boundary rather than
  resolving to a dead end.

### Fixed

- Recovered MCP tool calls from stale analyzer snapshots after workspace
  changes instead of returning a persistent store error.
- Restored bounded Kotlin constructor usage scans by avoiding unnecessary
  polymorphic candidate expansion.
- Fixed `analyze_diff` context expansion so changed symbols retain the
  workspace-qualified names and newly referenced declarations are reported.
- Reduced repeated `go.mod` discovery in large multi-module Go workspaces by
  memoizing nearest-module resolution for sibling files.
- Made every symbol spelling emitted by file summaries resolve back to its
  declaration, including dollar-prefixed JavaScript names, Scala companions,
  and basename-qualified C/C++ selectors.
- Included the sigil in static PHP property usage ranges.
- Rejected a malformed `run_policy` suppression document during request
  preparation, returning one bounded unreliable report instead of spending
  workspace readiness and analyzer admission before failing.

## [0.10.5] - 2026-08-21

### Added

- Expanded RQL and policy analysis with callable visibility and parameter-type
  predicates, relational effects, call bindings, generic flow obligations, and
  explanations for retained flow and taint evidence.
- Added named argument-port binding for flow and taint endpoints, so policies
  can address formal parameters without depending on argument position.
- Made orphaned suppression records visible, repairable, and enforceable in
  policy gates.

### Changed

- Reduced cold navigation and usage-scan work, coordinated persisted analyzer
  startup, and avoided blocking extension workspace opens on cache rewrites.
- Improved TypeScript inherited and union receiver resolution, C++ qualified
  occurrence and alias identity, C# semantic identity, and structured usage-kind
  classification across language adapters.
- Made release tags self-describing for artifact discovery and stopped shipping
  superseded GPLv3 and LGPLv3 license texts.

## [0.10.4] - 2026-08-19

### Added

- Added the DeepSeek Harness plugin bundle for using Bifrost code intelligence
  from DSH.

### Changed

- Improved Scala resolution for type projections, nested objects, wildcard
  singleton imports, and cross-build replica families.
- Improved C# qualified nested-type lookup, C++ declaration/body identity, PHP
  dynamic receiver handling, and PHP property ranges, including the sigil.
- Automated synchronization of qualified launcher metadata so managed clients
  receive checksums for the artifacts that were actually released.

## [0.10.3] - 2026-08-18

### Added

- Added official MCP conformance and wire-schema validation, including output
  schemas for the first stable tool set and negotiation of the existing
  `value_dependence` capability.
- Shipped the first standard-library procedure-summary packs for the JDK and
  CPython.
- Promoted the refined loop-invariance check into the built-in
  `bifrost.code-smells` policy pack.

### Changed

- Made `scan_usages` duration limits and analyzer store or workspace-listing
  failures explicit instead of silently returning incomplete empty results.
- Improved Java try/catch flow, C and C++ reference resolution, and Rust usage
  ownership and visibility.
- Reworked release qualification and artifact promotion so interrupted releases
  can resume from one immutable, verified bundle.

## [0.10.2] - 2026-08-17

### Added

- Added a native Codex Agent Plugin adapter, Codex marketplace metadata, and a
  post-release consumer smoke test for the published agent bundle.

### Changed

- Tightened the open-core projection to publish only explicitly reviewed paths
  and fixtures, while keeping the projected package, launcher, and release
  recovery flow self-contained.
- Fixed launcher handling when a compatible release series is already open.

## [0.10.1] - 2026-08-15

### Fixed

- Corrected C++ resolution for macro-displaced callable names, template-method
  callable fields, templated fragment aliases, and free-function receiver return
  precedence.

## [0.10.0] - 2026-08-15

### Changed

- Began the public open-core release line under Apache-2.0, with public source,
  crates, Python packages, CLI archives, editor support, and agent integrations
  released from one qualified public tag.
- Added practical Apache-2.0 guidance for research, internal use, redistribution,
  embedding, modification, and proprietary products.
- Made public policy scans and release validation self-contained in projected
  checkouts.

## [0.9.5] - 2026-08-14

### Added

- Added a stable extension SDK boundary with reproducible extension bundles,
  bounded semantic relation snapshots, generic observation mapping, typed
  control dependence, and bounded source-backed value dependence.

### Changed

- Improved Go promoted-method and container-owner resolution; Python nested
  module, annotation, and rebinding lookup; PHP factory receivers; C# aliases
  and default values; and JavaScript and TypeScript lexical identity.
- Restored and optimized Rust usage candidate discovery.
- Fixed VS Code managed-binary background upgrades and removed repeated
  observation-mapping work.

[0.10.6]: https://github.com/BrokkAi/bifrost/releases/tag/v0.10.6
[0.10.5]: https://github.com/BrokkAi/bifrost/releases/tag/v0.10.5
[0.10.4]: https://github.com/BrokkAi/bifrost/releases/tag/v0.10.4
[0.10.3]: https://github.com/BrokkAi/bifrost/releases/tag/v0.10.3
[0.10.2]: https://github.com/BrokkAi/bifrost/releases/tag/v0.10.2
[0.10.1]: https://github.com/BrokkAi/bifrost/releases/tag/v0.10.1
[0.10.0]: https://github.com/BrokkAi/bifrost/releases/tag/v0.10.0
[0.9.5]: https://github.com/BrokkAi/bifrost/releases/tag/v0.9.5
