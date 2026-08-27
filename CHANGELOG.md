# Changelog

This changelog records meaningful changes to Bifrost's public interfaces,
analysis behavior, integrations, and release artifacts. It is curated from the
complete private release range because the public open-core repository is a
projection and its commit history does not contain every source commit.

## [0.10.7] - 2026-08-27

### Changed

- Generated dependency semantic-model packs now persist in a versioned,
  repository-scoped catalog, allowing CLI, MCP, LSP, Python, and policy hosts
  to reuse locally built packs across sessions.
- Upgraded the native Python extension to PyO3 0.29.2 and adopted its
  interpreter-detachment API, removing the known upstream soundness defects
  from the shipped binding dependency.
- Removed the optional NLP and embedding-based semantic-search stack, including
  its Cargo feature and crate, MCP toolset, Python API, model sidecars, and
  accelerator controls. Structured semantic analysis, semantic-model packs,
  and seed-based relevant-file ranking remain available.
- Structural queries can now address a for-each loop's iterated expression
  (`iterable` role), collection display literals (`collection_literal`, a
  `literal` subtype), and their entries (`elements` role, counted by the
  `arity` predicate) in JavaScript, TypeScript, Python, Java, and Rust.
- Added the `assert-origin-shape` policy assertion: a review-prompt policy can
  withdraw a finding when the enclosing loop's iterated expression provably
  resolves to a small collection literal, and keeps it in every unproven case.
  `bifrost.code-smells` 2.2.0 applies it to `file-read-in-loop` and
  `parsing-in-loop`, so loops over small fixed literal collections -- the
  dominant accepted-suppression cluster -- stop reporting.
- Demoted the built-in `bifrost.code-smells` loop-containment family (file
  reads, parsing, serialization, regex compilation, subprocess launches,
  network and database calls in a loop, and the nested-loop variant) from
  `warning` to `note` (pack 2.1.0). These policies are review prompts that
  cannot prove per-iteration cost, so they no longer fail a
  `--fail-on warning` gate; `--fail-on note` restores the stricter behavior.
- Semantic-model packs now record which source paths their producer actually
  parsed from a sources artifact, and navigation uses that inventory: a
  dependency source the pack carries stays an authored navigation target, while
  a source path a pack merely names without carrying it resolves to the durable
  `bifrost-model://` identity instead of an unopenable external path. The field
  is additive, so existing packs keep their bytes and digests; packs published
  before it exist fall back to the model URI for out-of-workspace sources.
- Scala value-flow and taint analysis now decides the object, field, alias, and
  array strata. Member and element assignments lower into real heap stores and
  loads with resolved member identities, a class's primary constructor
  publishes the stores for the members it initializes, `new Array[T](n)` is an
  allocation rather than an unresolvable call, and a single typed `catch` arm
  binds the thrown value to its parameter. Together with the relay and
  control-transfer repairs in the same series -- proven identity returns,
  language-defined operators, `var` reassignment, and two-armed `if` values --
  Scala reaches the same decided answers on these shapes that Java and Go
  already gave, instead of reporting them as open.
- Scala now folds a constant `if` condition to its taken arm and publishes the
  guard fact, and a `while` loop whose counter is provably below a literal
  bound on entry routes straight into its first iteration. A branch guarded by
  `if (false)` and a value overwritten by a provably entered loop no longer
  report taint that no execution can carry.
- Rust value-flow and taint analysis now decides direct calls and returns,
  constant branches, local assignments, and single-selector field and array
  stores and loads when their targets are structurally known. Array literals
  now carry allocation identities, allowing a later write to one exact element
  to replace the element's prior value instead of conservatively retaining it.
- The shipped Python standard-library semantic pack now activates by default
  when a workspace declares a compatible CPython version in `.python-version`
  or `pyproject.toml`. Unsupported constraints, unavailable packs, and version
  mismatches remain explicit diagnostics rather than guessed activation.
- TypeScript call-target selection now recognizes members of classes with
  private constructors as closed dispatch and refuses conflicting local
  receiver assignments. Supported reference-flow policies can therefore reach
  complete finding and clean outcomes for TypeScript while open or structurally
  unresolved calls remain explicitly incomplete.
- Exact reference scans now retain request-scoped resolution state across the
  whole scan, resolve structural fallback data only for ambiguous sites that
  need it, and process independent files in parallel. Large `scan_usages` and
  `analyze_diff` workloads no longer repeat whole-workspace resolution work per
  file or occurrence.

### Fixed

- C and C++ procedure value-flow snapshots now complete for ordinary scalar
  code instead of reporting a blanket unknown. The C-family adapter treats
  by-value transfers as exact wherever the language guarantees it (all of C,
  and C++ scalar types; C++ class-typed copies keep their conservative gap),
  models taint through arithmetic, unary, and cast expressions, folds constant
  branch conditions and literal-bounded counted-loop entries with published
  guard facts, and publishes evaluation-order and initializer gaps only where
  the order or transfer is genuinely unmodeled. C++ calls that elide a
  defaulted argument now carry an explicit unsupported-binding gap.
- C and C++ data-flow and taint analysis gained a heap stratum on top of that
  scalar repair: member, static, and array-element accesses lower into heap
  reads and writes whose identity is the member's own declaration, and a
  `throw` binds its operand to the handler parameter that observes it. Many C
  and C++ flows that previously stayed inconclusive now resolve. Where the
  analyzer deliberately does not model a construct -- a class-typed by-value
  copy or conversion, a user-defined subscript operator, a write through a
  parameter -- it reports a precise decline scoped to that value or location,
  naming the unsupported capability, instead of an indistinct partial result.
  Constant branch conditions and literal-bounded counted loops also fold for
  the C family, so an infeasible branch and a provably entered loop no longer
  report taint no execution can carry. On the DataFlowBench taint kernels this
  moves decided core assertions from 2 to 41 of 50 for C and from 2 to 30 of 56
  for C++ with no wrong decisions; the remaining incompleteness is
  function-pointer and virtual dispatch and the callable-shaped strata behind
  them.
- Fixed the 0.10.6 `analyze_diff` performance regression on Rust workspaces:
  reference resolution rebuilt a whole-file lexical scope index for every
  occurrence it inspected, so review-sized Rust diffs no longer completed
  within practical time budgets. The index is now memoized per distinct source,
  and both diff endpoints share the memo.
- Extended that per-occurrence rebuild fix across the other languages'
  reference resolution: the per-file enclosing-class index is now built at
  most once per request instead of once per occurrence (previously rebuilt
  inside per-import and per-preceding-binding loops in Scala, and per
  occurrence in C#, PHP, and C++), whole-file re-parses during Java, Kotlin,
  Go, and PHP resolution are memoized per distinct source, Scala's bulk
  call-site fast path now reuses the shared lookup and import context instead
  of rebuilding them per occurrence, and C# memoizes its per-file and
  workspace `using` namespace sets. This addresses the corresponding
  `scan_usages`, `dead_code_smells`, and `analyze_diff` slowdowns on
  non-Rust workspaces.
- A one-shot `--tool` run now detects that its parent process died, cancels
  the in-flight analysis, and exits, instead of surviving as an orphan
  consuming a full core after the caller's timeout kill.
- RMCP response delivery now remains ordered through the transport timing
  barrier, so a later response cannot finish its measured boundary while an
  earlier delivery is still pending. This removes intermittent incomplete
  timing profiles from otherwise successful benchmark runs.
- Bound persisted workspace queries to immutable worktree revisions, preserving
  retained-analyzer results across concurrent worktree publication and avoiding
  large temporary candidate tables during Java reverse-reference analysis.
- Python call binding now handles a method invoked on a call result when the
  receiver's return type proves the target, so calls such as
  `make_store().put(key)` bind receiver, positional, and defaulted formals
  without falling back to `receiver_binding_unsupported`. Unresolved and
  spread-argument cases retain their explicit incomplete outcomes.

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

- Made compatible discovered semantic packs activate by default across CLI,
  MCP, and LSP policy hosts, with one workspace configuration and attributable
  activation state in policy reports; an explicit empty ecosystem list
  disables ambient activation without fabricating external declarations.
- Split flow solvers and RQL execution into dedicated public crates, reducing
  analyzer coupling while preserving the facade query API and wire formats.
- Made reusable flow caches explicitly owned by each logical workspace so MCP,
  LSP, runtime, and policy evaluation retain them across analyzer replacement.
- Accelerated definition navigation and path-scoped Java caller scans with
  targeted, bounded relational queries.
- Made `BIFROST_PARALLELISM` consistently cap analyzer, usage-scan, and
  semantic vector-scan worker pools for batch consumers.
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
- Reported an orphaned policy suppression as its own structured cause with
  re-key candidates, instead of mislabelling it as a finding at or above the
  `fail-on` threshold. A scan run with `--fail-on never` no longer reports
  threshold findings it did not have.

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
