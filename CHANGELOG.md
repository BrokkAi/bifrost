# Changelog

This changelog records meaningful changes to Bifrost's public interfaces,
analysis behavior, integrations, and release artifacts. It is curated from the
complete private release range because the public open-core repository is a
projection and its commit history does not contain every source commit.

## [0.10.9] - 2026-09-03

### Added

- A `--diff-base` policy run now persists what it evaluated in the
  repository's analyzer cache and reuses it. Each policy's per-file evaluation
  units are stored with the exact inputs they read, and a completed base
  evaluation is stored under the base subtree's git tree id, so a second run
  against the same base neither exports nor builds the base revision and
  recomputes only the units whose recorded inputs can have changed. The report
  gains an additive `incremental` section reporting what was reused, what was
  recomputed, and why any policy was evaluated in full; findings, identities,
  diagnostics, completion tiers and exit status are unchanged. `bifrost
  --no-incremental` and the `run_policy` MCP parameter `incremental: false`
  force the full dual-snapshot evaluation for comparison.

- CodeQuery/RQL gained the `module` normalized kind, a `declaration` subtype
  that matches a module or namespace declaration and encloses everything
  written inside it, so `(not-inside (module :name "tests") ...)` is now
  expressible. Rust `mod`, C# block and file-scoped `namespace`, C++ and PHP
  `namespace`, and Ruby `module` produce the kind; a Ruby `module` is
  therefore no longer reported as a `class`. Languages whose module structure
  is a file-level clause rather than a container keep reporting a capability
  diagnostic.

- The Rust CodeQuery/RQL adapter now answers the `decorators` role. An outer
  attribute is a `decorator` edge on the declaration it annotates, so
  `(function :decorators [(name "test")])` and
  `(class :decorators [(name "derive")])` match instead of returning an
  `unsupported_structural_feature` diagnostic.

- Added the `bifrost scan [PATH]` subcommand: the zero-configuration
  shipped-product entry point. A scan evaluates every built-in policy pack on
  one project path (default: the current directory), witnesses the activated
  pack identities, versions, and catalog SHA-256 on stderr in the same line
  shape `--version` prints, and shares the policy exit contract.
  `bifrost scan --list-builtin-policies` prints the shipped catalog without
  running anything. The subcommand is additive: the flag-based policy
  surface, which benchmark-controlled runs configure explicitly, is
  unchanged, and a build that ships no packs scans to a clean, empty result
  rather than erroring.

- The standalone CLI now activates every built-in policy pack by default: a
  policy invocation with no `--policy-file` and no built-in selector (plainly
  `bifrost --policy`) evaluates the shipped catalog, an explicit selection
  replaces that default, and `--no-builtin-policies` keeps controlled runs
  free of shipped policies. `bifrost --version` now records each shipped
  pack's id, version, and policy count plus a catalog SHA-256, so a
  shipped-catalog change is a visible version event.

- Added CSMI v0.1 logical-pack import, export, offline schema validation, and
  RFC 8785 canonicalization for exact Maven/JVM declaration and procedure-
  summary models. Artifact digests and callable identities remain exact, while
  unsupported effects, locations, identity profiles, and required
  vocabularies fail closed with typed diagnostics. The semantic-pack CLI can
  now check standalone CSMI documents and manifest-relative logical packs with
  stable human or JSON diagnostics.

- Semantic-model call binding now resolves exact Python targets and Kotlin
  external-dispatch identities, while ambiguous or unmodeled routes remain
  explicit.

- Added `bifrost.correctness.go-wrong-error-on-failure-path`, which reports a
  call returned from an exact reviewed Go API failure edge when it consumes a
  different error binding proven to still hold Go's zero value. Correct error
  propagation, deliberate non-nil sentinels, unrelated same-named APIs, and
  incomplete origins remain outside the finding set.

### Changed

- A policy run no longer forwards the CodeQuery `broad_query` advisory as a
  policy diagnostic. The advisory is a measurement of the execution that raised
  it -- its message renders that execution's own scanned-file and scanned-byte
  counters, which the report's `work` section already carries -- and the advice
  it gives, to add an anchor or a language filter, is for an interactive
  `query_code` caller rather than for a policy that audits the whole workspace
  by design. Keeping it also made a report's bytes and its retention boundary
  depend on how a run was executed rather than on what the workspace contains.
  Every other query diagnostic is forwarded unchanged.

- JavaScript and TypeScript now treat Node's `node:` module scheme as spelling
  rather than identity. `import fs from 'node:fs'` and `import fs from 'fs'`
  name one module, so they mint one external owner, one package identity, and
  one discovery evidence entry across import binding, receiver analysis,
  external-callee owners, and semantic diagnostics. A semantic pack authored
  for the bare builtin now binds both spellings, so the shipped JavaScript and
  TypeScript golden summary packs (0.4.0) and the Node child-process
  declaration packs (0.2.0) no longer duplicate every module entry per
  spelling.

- The MCP `query_code` structural search path now reads analyzed source blobs
  without hydrating full file state when the query only needs source text,
  substantially reducing warm whole-workspace query latency.

- The built-in OWASP XSS policy now limits servlet response sinks to exact
  `PrintWriter` calls, avoiding broader same-surface matches.

- Upgraded `bifrost.code-smells` to 2.7.0 for the exact Go failure-path error
  policy. Its initial scope is limited to arguments of calls whose result is
  returned; direct returns and statement-only calls remain available through
  RQL but are not yet built-in findings.

### Fixed

- Extension capability negotiation now derives from the same published
  capability table as the extension workspace report, so clients can require
  every capability the report marks as served.

- C/C++ definition lookup now preserves structured preprocessor-guard context
  across unrelated macro definitions, resolving guarded same-file typedef
  parameters without a spurious include-boundary diagnostic.

- CodeQuery/RQL now enforces every list role. The `elements`, `attributes`,
  and `children` patterns were decoded and documented but never checked, so
  `(collection_literal :elements [(numeric_literal)])` matched a literal of
  strings and a JSX attribute or child list narrowed nothing. All five list
  roles now read the same way, the rule `args` always used: each listed
  pattern must match a distinct edge of that role in source order. That also
  tightens `decorators`, which previously let two patterns match one
  annotation and accepted any order.

- `query_code` full-detail rows now carry their own source columns even when
  an earlier row in the same answer resolved into their file. Rendering
  hydrates a bounded set of sources, and a file that was consulted for a
  nested reference target before its own rows were rendered was recorded as
  having no source at all, so every row of that file reported column 1 for
  both ends of its range while its lines stayed correct. Which rows were
  affected depended on the order the answer happened to render, so the same
  row could report different columns in a workspace-wide query and in a
  path-scoped one.

- When a `--diff-base` run repairs more than 256 base findings, the diff
  review's `fixed` list now deterministically retains the 256 smallest
  `(policy_id, finding_id)` identities in sorted order. Previously the
  retained subset was taken in hash-map iteration order before sorting, so two
  runs of the same build over the same inputs could report different entries
  while agreeing on `fixed_count`.

- The base revision of a `--diff-base` run is now analyzed with the same
  analyzer configuration as the head, including a configuration a host such as
  the MCP server or the LSP session supplied. The base previously built with
  the analyzer defaults, so dependency discovery, dispatch expansion, and
  per-language behavior could differ from the head whose findings it was joined
  with.

- The exported base revision of a `--diff-base` run now honors the
  `.bifrostignore` file that revision commits, so a file the head excludes from
  analysis no longer contributes base findings that the diff reports as fixed.
  Ignored paths stay in the file view on both sides, as they always have.

- Watched workspaces now keep overlays and linked-worktree updates coherent
  across file deletion and other incremental changes, with background reads
  anchored to the selected analyzer generation.

- LSP position conversion and word lookup now handle CRLF and multibyte text
  without offset errors, dropped blank snippet rows, or panics.

- Semantic-pack activation retries transient catalog locks and reports rejected
  source entries instead of silently treating them as usable pack input.

- `bifrost.code-smells` 2.10.0 extends the small-fixed-literal exclusion to
  serialization, regular-expression compilation, sleeps, network and database
  calls, subprocess launches, expensive operations, and nested loops. The
  policies now report as assertion findings, so their finding identities
  changed and existing suppression records for them need re-keying.

## [0.10.8] - 2026-08-31

### Added

- Partial semantic-model declaration packs can now establish the exact callable
  scope they cover, allowing complete modeled call bindings without treating
  unlisted declarations as absent.
- Exact modeled call binding now covers Java static imports and JavaScript/
  TypeScript named imports, so external summaries can bind without source-text
  fallbacks.
- Rust trait resolution now follows workspace-crate exports and inline-module
  imports, enabling exact trait-method dispatch for supported workspace
  implementations.
- Rust trait-method dispatch now resolves exact workspace implementations
  through trait-implementation families, while unresolved, blanket, and
  macro-derived families remain explicitly incomplete.
- Added a core `diff` MCP toolset containing `analyze_diff`, `blast_radius`,
  endpoint-oriented `cyclomatic_complexity`, and `missing_tests`. Complexity
  reports introduced and patch-edited functions with before/after scores and
  signed deltas. Missing-test analysis uses the file graph to bound exact
  reverse usage traversal, and separates incomplete evidence from confident
  negative results. Both tools are available through the typed Python client.
- Added `score_diff` to the `diff` toolset. It returns a deterministic vector of
  raw named features describing how hard a revision range makes future
  maintenance -- change geometry, review coordination load, symbol-level test
  verification, and cognitive-complexity baselines -- and publishes no weights
  and no single score, because no validated weighting exists yet. Unmeasurable
  and unresolved inputs are named rather than dropped, so a consumer can tell a
  zero from an absence.
- Semantic-model-pack hosts can download and verify exact release-hosted
  dependency packs, reusing a compatible prebuilt output while safely falling
  back to local production when no matching asset is available.
- Added typed RQL projections for indexed call results and normalized Go guard
  conditions, enabling policies to correlate paired returns with the exact
  success branch that dominates a later use.
- Added three-state operation preconditions to reviewed result-member
  contracts and the typed `result-contract-operation-uses` RQL relation. A
  policy can now distinguish an unreviewed operation, a reviewed operation
  with no input requirement, and an operation that requires an exact receiver
  or parameter predicate, while retaining the operation's own source location.
- Added reviewed Go standard-library result contracts and a built-in
  correctness policy for dereferencing selected `os` results before their
  paired error establishes success. The same typed RQL relations can validate
  opt-in reviewed contracts such as URL parsers without expanding the default
  rule.
- Added partial exact declaration companion packs for the reviewed Go `os`,
  `net/url`, `errors`, `log`, and Testify `require` behavior packs, plus a
  declarations-only `path/filepath` pack for the exact variadic
  `Join(...string) string` signature. Modeled calls can select these functions,
  concrete result types, and single-result nested arguments without treating
  unlisted package members as absent or changing the behavior packs' own
  completeness claims.
- Added an explicit no-normal-continuation claim to reviewed procedure
  summaries. The Go standard-library `os` pack now models `os.Exit`, and the
  new `log` pack models the receiverless `log.Fatal`, `log.Fatalf`, and
  `log.Fatalln` functions. Exact external error paths that terminate the
  process can participate in ICFG, dominance, and reaching-definition analysis
  without name-based exceptions.
- Added authored variadic procedure targets to semantic-model packs. They match
  every applicable actual arity while keeping semantic claims on the fixed
  parameter prefix until packed-tail flow ports are available. The shallow Go
  Testify model now uses this support so normal return from `require.NoError`,
  including calls with optional message arguments, establishes the exact error
  argument as nil without treating nonfatal assertions as guards.
- Added reviewed boolean-outcome predicate refinements to procedure summaries,
  with bounded composition through exact identity-preserving workspace
  wrappers. The Go standard-library `errors` pack now models the false result
  of `errors.Is` as insufficient to establish that its first argument is nil,
  without inferring the opposite predicate or trusting same-named functions.
- Reviewed result contracts can now express a direct result's own success
  predicate. The Go `encoding/pem` packs use it so unguarded operations on
  nullable decode results are reported without inventing a second condition
  port.
- Procedure summaries can now publish reviewed receiver and parameter entry
  preconditions, and result-contract queries expose exact positional argument
  uses with their formal parameter ordinal. The Go correctness policy uses
  this with `crypto/x509.IsEncryptedPEMBlock`; a declarations-only `bytes`
  pack preserves the exact single-result arity of nested `bytes.TrimSpace`
  calls, so unchecked `pem.Decode` blocks report at the x509 argument without
  admitting same-named or uncertain targets.

### Changed

- Upgraded `bifrost.code-smells` to 2.5.0. The Go result-contract rule now
  includes exact `net.Listen` acquisitions and reports required operations on
  the returned listener when its paired error has not established success.
- A persisted analyzer build over a project with no persistence identity is now
  a hard error instead of a silent downgrade to a throwaway store. A caller that
  asked for reuse across runs no longer receives a database deleted on drop and
  pays a full re-parse every run with nothing said about it. The error names its
  exits: analyze through a rooted project, put a whole immutable revision on the
  shared revision cache, state a deliberately session-only or partial view with
  the ephemeral footgun constructor, or set `BIFROST_CACHE_ROOT` for a multi-root
  host with no resolvable machine cache directory.
- Diff tools now report a shared revision cache that cannot open instead of
  falling back to an ephemeral store and re-parsing every blob. For a read-only
  checkout, `BIFROST_CACHE_ROOT` relocates the cache to a writable local root.
- LSP sessions with several workspace folders now persist their analyzer facts
  to a machine-local cache keyed by the root set, so reopening the same
  multi-root session reuses what the previous one parsed.
- `policy --diff-base` now evaluates the base revision through the primary
  repository's content-addressed cache rather than a per-run throwaway store, so
  a warm base run costs only the delta.
- Policy runs now reuse the persisted analyzer cache. A run that builds its own
  workspace -- the policy CLI, the MCP workspace-less arm, and policy
  explanations -- reads the content-addressed facts an earlier run parsed
  instead of rebuilding the whole workspace into a throwaway database, so warm
  runs are substantially faster. The policy CLI now writes the same `.bifrost`
  cache every other one-shot tool already writes.
- Official GNU/Linux binaries now target glibc 2.28 or newer and statically
  link zlib. The x86-64 musl archive and npm package are no longer published;
  musl source builds are untested and unsupported.
- Usage scans no longer create or clamp wall-clock deadlines in the analysis
  layer. The MCP and Python scan APIs no longer accept `max_duration_secs`;
  frontends own latency policy and pass cooperative cancellation into analysis.
- Upgraded `bifrost.code-smells` to 2.4.0. The Go result-contract rule now
  includes exact `net.Dial` and `net.DialTimeout` acquisitions, so a required
  operation on their connection result can report when its paired error has
  not established success.
- Upgraded `bifrost.code-smells` to 2.3.0. Its Go result-contract rule now
  selects exact required, unguarded operation rows: ignoring a paired error can
  still report when a success-gated operation uses the result, while reviewed
  nil-tolerant operations such as `(*os.File).Close`, `Read`, `Seek`, and
  `Stat` no longer produce a nil-dereference finding.

### Fixed

- Go result-contract analysis now follows direct modeled results through
  assignments, conversions, conditional switches, deferred cleanup, and early
  exits while retaining explicit boundaries for unsupported paths.
- C# persisted visible-type lookup now shares race-safe in-flight work, and
  large file-graph hydration avoids repeatedly building transient indexes.
- C++ declaration recovery no longer reparses each fragmented class body with
  a whole-file padded prefix, keeping recovery work scoped to the affected
  region.
- Go result-contract analysis now proves success guards relative to each
  acquired result, so unrelated early exits no longer leave locally guarded
  `encoding/pem.Decode` values inconclusive.
- Go result-contract analysis now distinguishes an ignored conditional result
  from real consumers even when later statements, nested field loads, or
  conservative operand-order gaps make the surrounding procedure incomplete.
  This preserves definite unguarded operation findings without treating an
  assigned, guarded, captured, or passed boolean as discarded.
- Let Go value-flow combine canonical literal-index identity with an
  independently proven singleton allocation and no secondary local storage
  owner, so an exact later store can kill an overwritten element while
  dynamic, rebound, copied, or alias-open indexing and the unsupported
  flow-state projection boundary remain explicit.
- Included strong-update behavior in value-flow propagation compatibility
  hashes, preventing semantically distinct policy plans from colliding in one
  batch before the exact compatibility check.
- Definition lookup keeps anchored package searches selective, avoiding severe
  latency on ambiguous Ruby references in large workspaces.
- Kotlin and JavaScript/TypeScript definition navigation now selects the true
  declaration name for positional declarations, including Kotlin function
  headers and anonymous default exports.
- Distinguished Go package-function calls from bound receivers and method
  expressions during modeled-result discovery, preserving aliases and unique
  dot imports while respecting predeclared and package-local names plus
  receiver arity.
- Scoped Go range short-declaration bindings to their containing loops in exact
  reference resolution and semantic diagnostics, so the range expression and
  post-loop references retain their outer bindings while `=` range clauses
  declare none.
- Proved all-path success guards with exact conditional-edge dominance,
  preventing a fall-through error arm that rejoins at a result use from
  falsely certifying that use as safe.
- Kept semantic-model requests and reusable flow caches coherent across model,
  source, configuration, and dependency changes. Active summaries and
  declaration overlays are frozen atomically per request; dispatch-sensitive
  cache identities now include effective matcher behavior, whole-workspace and
  hierarchy behavior, and path-independent JVM external declaration surfaces.
- Preserved caller-owned semantic-model publications when policy batches use a
  supplied analyzer, instead of freezing absent document activation and
  silently hiding reviewed contracts.
- Counted retained external dispatch identities and formal contracts against
  semantic work budgets, so configured entry and byte limits cover modeled
  workspace-boundary results.
- Preserved exact reusable summaries for call-free procedures across unrelated
  workspace edits while keeping solved results and call-bearing summaries keyed
  by complete workspace dispatch behavior.
- Kept composed interprocedural witnesses root-relative by omitting validated
  callee-entry join seeds while retaining every call, body, and return step.
- Kept success-conditioned typestate acquisitions inside their owning analysis
  root while preserving reusable callee summaries, preventing unrelated
  procedures from contaminating lifecycle findings.
- Bounded conditional-result validation by candidate file and switched guard
  checks to the exact dominator tree already derived by flow state, allowing Go
  correctness policies to finish on medium-sized repositories without
  retaining every semantic artifact or enumerating unrelated control
  relations, while preserving honest capability diagnostics.
- Preserved distinct Go multi-result values through explicit callee returns,
  including swapped return expressions and interface-call result identities.
- Preserved Go multi-result assignments into fields and named result bindings,
  allowing guarded resource uses to remain clean without conflating reads that
  occur before or after an assignment.
- Modeled acyclic path-scoped Go defers, including conditional registration,
  registration-time operand capture, LIFO cleanup on return and panic paths,
  and typed unsupported evidence for loop-contained registration.
- Counted direct Go defer receiver invocations in conditional-result checks, so
  registering cleanup before the paired success check is reported while a
  checked registration remains clean.
- Preserved exact immutable Go values across direct function-literal captures,
  allowing deferred resource uses to participate in result-contract checks
  without misclassifying bindings that nested closures mutate.
- Scoped a nested Go procedure's capture uncertainty to values that actually
  cross the procedure boundary, substantially reducing open callback results
  without closing entry-origin, mutable, or indirect captures.
- Retained exact Go result uses that occur before every possible success-guard
  input as violations even when later identity or validator evidence remains
  open; the policy still reports incomplete coverage for the unresolved uses.
- Treated opaque Go scalar call reassignment as a definite overwrite even when
  exact result type identity is unavailable, preventing an earlier result
  definition from incorrectly reaching later guards while preserving ordinary
  data dependence through a non-identity conversion boundary.
- Reused exact source-dispatch answers across result-validation consumers
  within one request, avoiding duplicate bounded semantic work while retaining
  the existing materialization and work-ledger accounting.
- Made result-contract policy discovery follow canonical modeled call identity,
  including import aliases, without claiming unrelated same-named methods.
- Preserved event-local resource identity for direct receiver operations while
  keeping universal identity closure for deferred, captured, and intrinsic
  uses, so one operation cannot borrow another operation's proof.
- Distinguished exact modeled single-result calls used as Go arguments from
  possible multi-result expansion, allowing nested calls such as
  `os.Create(filepath.Join(...))` without weakening tuple, spread, shadowing,
  or ambiguous-call barriers.
- Kept intrinsic semantic-pack activation separate from workspace configuration
  reviews and skipped declaration-wide review evidence when no configured
  review can consume it.

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
- Clarified `blast_radius` output as file-graph reachability evidence: graph
  completion and reached-test counts no longer imply exhaustive test impact,
  changed paths outside analyzer coverage are reported explicitly, and Rust
  external-module declarations now connect private implementation files to
  tests importing their enclosing modules. Changed callables now label
  test-tree or structural attribution as `in_test_context`, avoiding any
  implication that they are individually runnable tests. Results also expose
  analyzer-classified changed test files explicitly, so distance-zero evidence
  remains inspectable after directory-scope compaction.
- Removed exact method-call analysis from `blast_radius` callable discovery;
  historical immutable revisions that previously stalled now stop after symbol
  pairing and use exact call graphs only when running `analyze_diff` itself.
- Scoped immutable `blast_radius` graph builds to the changed language
  ecosystems, parallelized complete revision export, and added compact
  graph-only JVM parsing, eliminating cold timeouts on very large source trees
  without dropping graph files or structured dependency facts.
- `analyze_diff` and `blast_radius` now default zero-argument worktree analysis
  to the merge base of `HEAD` and the default branch, so one-shot CLI calls
  include committed feature-branch changes as well as uncommitted edits.
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

- Policy-local taint sanitizers now lower their exact selected call identity,
  input operand, output carrier, and removed labels through the shipped CLI.
  Same-named owners, unrelated operands, non-reaching calls, and unresolved or
  ambiguous selections no longer produce false clean conclusions.
- JavaScript and TypeScript taint-policy runs now finish with explicit
  summary-backed completion when a shipped complete semantic summary binds an
  otherwise unavailable external procedure. Missing, partial, unrelated, or
  ambiguous external models remain inconclusive.
- Rust require-model taint runs now complete for resolved same-file flows whose
  sinks discard a value with `let _ = value`, and for values returned through
  reference-typed functions. Wildcard lets no longer masquerade as unsupported
  destructuring or create lexical cleanup obligations; genuinely droppable
  discarded temporaries retain an immediate cleanup frontier.
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
- Recognized structured JavaScript and TypeScript test declarations, ESLint
  `RuleTester` suites, and Node-style `test-*.js` runners without classifying
  ordinary production calls such as `emit(...)` as tests. `blast_radius` now
  includes those changed and importing tests without fabricating production
  file scopes from test-like source substrings.
- Included Java same-package dependencies and framework-specific `*TestCase`
  subclasses in file-level blast-radius evidence, including type names used as
  structured static/value qualifiers.
- Replaced Scala file-graph definition prefetch with bulk structured import,
  export, and same-package resolution, avoiding cold historical timeouts
  without treating every file in one package as a dependency.
- Python call binding now handles a method invoked on a call result when the
  receiver's return type proves the target, so calls such as
  `make_store().put(key)` bind receiver, positional, and defaulted formals
  without falling back to `receiver_binding_unsupported`. Unresolved and
  spread-argument cases retain their explicit incomplete outcomes.

## [0.10.6] - 2026-08-25

### Added

- Added the `blast_radius` slopcop MCP/CLI and Python-client tool, which maps
  diff endpoints to changed callables and compact affected-test scopes using
  structured file-import evidence with explicit partial-result states.
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
