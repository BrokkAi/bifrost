# Create the static-analysis policy format and reporting boundary

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` current as implementation proceeds. Maintain this document in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

After this work, a rule author can put one schema-resolved static-analysis document in a `.rqlp` file, use native Rune Query Language (RQL) expressions to select source entities, and run an executable policy through Bifrost to obtain deterministic human, canonical JSON, and SARIF 2.1.0 reports. A policy is not an ad-hoc query with a message attached: the policy supplies stable rule identity and reporting metadata, evaluation records whether the analysis was complete, and only a `PolicyEvaluator` may turn diagnostic-neutral query or future solver output into a `PolicyFinding`.

The human authoring syntax is a separate S-expression policy language which shares RQL's concrete parser, formatter, comments, and nested query expressions. Canonical JSON is generated from the typed model for hashing, debugging, and embedding; JSON and YAML are not alternate `.rqlp` authoring syntaxes in schema version 1. A human author may omit `:schema-version`; Bifrost then records the current head of a strictly compatible, compiled-in schema lineage, while an explicit value remains an exact reproducibility pin. This makes policies readable, deterministic, and straightforward for an LLM to generate while deliberately exercising the same RQL implementation the policies depend on.

This issue establishes the public boundary before the later taint and typestate solvers freeze competing wire types. It fully parses and validates public `match`, `taint`, and `typestate` variants, but initially executes only `match`. Evaluating a valid taint or typestate policy before the #824 compiler/adapter exists yields an explicit unsupported run, never a successful empty result. The same canonical finding model feeds every renderer, so human and SARIF output cannot disagree about identity, location, completion, certainty, classification, or CVSS evidence.

The same format also supports one diagnostic-neutral `(endpoint ...)` document per file. An endpoint gives a native RQL selector one stable source-or-sink identity, typed value/API binding, exact categories, display phrase, taint semantics where applicable, and explicit dominance declarations. Runnable policies may select endpoint leaves from an explicitly named capability-rooted directory by category or exact ID. Imported endpoints are dependencies, not extra policy runs. A taint policy executes one set-oriented propagation over all selected endpoints, reports every actual compatible meeting, renders a fixed generated `{source display} can reach {sink display}` message when no explicit combination applies, and lets one uniquely dominant intentional combination replace that generic presentation. Match co-presence alone never licenses the phrase “can reach”; reachability still requires #821/#824's structured analysis.

Typestate policies reuse the same bound endpoint leaves for tracked subjects and phase-specific API events, then add protocol transitions and terminal expectations. An explicit API observation may move the tracked value into a non-absorbing accepting state; an implicit normal/exceptional analysis-root exit may require that an accepting state was already reached. Helper returns are not terminals. Endpoint directories, categories, display phrases, and messages remain public composition/reporting inputs and never enter #822's automaton engine or #823's summary state.

The first observable example is:

    (policy
      :id "bifrost.security.dynamic-eval"
      :name "No dynamic evaluation"
      :message "Dynamic evaluation is forbidden"
      :severity warning
      :analysis
        (analysis
          :type match
          :selector
            (rql
              (language python
                (call :callee (name "eval"))))))

Running it with `bifrost --policy-file policies/dynamic-eval.rqlp` reports each selected call with the policy ID, severity, message, stable finding ID, source location, analysis evidence, and completion. `--format sarif` emits the equivalent SARIF rule and results. A truncated, cancelled, capability-incomplete, or unsupported evaluation says so and uses exit status 2 even when it found no rows.

## Progress

- [x] (2026-07-17 08:18Z) Fetched the live issue and related roadmap issues, confirmed the clean issue branch and current `origin/master` are both `3bd7b75a`, and inspected the RQL parser/schema/formatter, typed query executor/results, workspace-safe query loader, CLI, LSP/VS Code integration, docs harnesses, semantic roadmap, SARIF 2.1.0, FIRST CVSS v4.0, and the current Rust CVSS library.
- [x] (2026-07-17 08:18Z) Chose the schema-version-1 S-expression `.rqlp` contract, the distinct policy/query boundary, independent selector schema resolution, match-only initial evaluator, canonical finding/completion model, CLI exit contract, and human/SARIF mappings described below.
- [x] (2026-07-17 10:42Z) Ran parallel format/surface/ExecPlan/contract reviews; closed the report-metadata, failure-state, semantic-hash, budget, stable-anchor, severity, registry-authority, query-diagnostic, dependency-pin, acceptance-transcript, and #709/#824 ownership gaps; and synchronized the umbrella roadmap's planning contract.
- [x] (2026-07-17 13:14Z) Incorporated the intended library workflow: compatible omitted schema versions, diagnostic-neutral categorized match models loaded from explicit directories, generated broad flow messages with deterministic specific-rule precedence, and typestate reuse of the same bound source/sink models plus explicit and implicit terminal expectations.
- [x] (2026-07-17 13:33+02:00) Began implementation on the existing `709-create-static-analysis-policy-format` branch, fetched `origin/master` at `5395b789`, confirmed the branch was seven commits behind with no overlapping policy-plan changes, and completed the pre-implementation plan/adversarial review checkpoint. The refreshed Bifrost MCP methods were still absent from the callable tool catalog, so implementation continues with narrow repository search/direct-source fallbacks.
- [x] (2026-07-17 11:27Z) Merged `origin/master` at `5395b789` into the existing issue branch without conflicts, preserving the repository's no-rebase/no-branch-switch rule and placing implementation on the current analyzer/LSP baseline.
- [x] (2026-07-17 14:16+02:00) Pre-implementation issue sync: updated both live #709 and #824 bodies so #709 owns syntactic catalog registration/composition, presentation precedence, and the generic classification/CVSS reducer, while #824 owns semantic selector/binding resolution, same-site dominance, plan compilation, analysis-specific projection evidence, and the adapter into #709's evidence boundary.
- [x] (2026-07-17 11:50Z) Milestone 1a implementation: extracted the shared spanned S-expression parser/AST/generic formatter into crate-internal `src/sexp/`; kept the query lowerer in `analyzer::structural::query::sexp`; preserved RQL/Rune formatting and query-specific trailing-input wording; and added direct AST-subtree query lowering whose syntax/lowering/semantic errors retain original absolute byte ranges without render/reparse.
- [x] (2026-07-17 14:16Z) Milestone 1b infrastructure: added a deterministic compatible-lineage registry, registered RQL schema version 2, made query AST lowering carry the resolved version/origin, and added configurable S-expression depth/node budgets for the 256-KiB/4,096-node RQLP parser boundary. Registry tests (12), the complete shared S-expression suite (40), and the structural-query suite (85) pass; exact pins never fall back and explicit-only successors never become the omitted-version head.
- [x] (2026-07-17 14:16Z) Milestone 1b implementation: added the schema-version-1 declarative policy/endpoint registry, complete typed match/taint/typestate/classification/CVSS authoring graph, bounded parser and multi-diagnostic validator, exact source maps, unresolved selector references, deterministic normalized authored JSON, and parser-gated inline/local semantic projection for document shapes that require no endpoint composition.
- [x] (2026-07-17 14:16Z) Milestone 1c implementation: added the registry-aware 100-column policy formatter with validated 80-through-120 widths, checked golds, idempotence, and preservation of comments, schema-version omission, string bytes, and syntactically complete schema-invalid editor buffers.
- [x] (2026-07-17 14:20Z) Milestone 1 validation/review/checkpoint: passed 12 schema-registry, 40 shared S-expression, 85 structural-query, 46 policy-unit, and 12 policy-source integration tests; checked 80/100/120-column formatter golds; passed `cargo check --lib`, `cargo fmt --check`, strict all-feature library Clippy, and `git diff --check`; closed every accepted finding from two adversarial closure rounds; and recorded the reviewed authoring boundary in this checkpoint.
- [x] (2026-07-18 09:14Z) Milestone 2a implementation: extracted a shared `cap-std` workspace-document authority, retained one opened root per workspace, preserved capability-confined explicit-file symlinks, added same-handle bounded UTF-8 reads, and implemented lexical, bounded, symlink-free, race-rechecked transactional endpoint-directory traversal. Unix opens use no-follow/type/nonblocking flags where needed so a file-to-symlink/FIFO replacement cannot escape or hang; portable drive/UNC/device prefixes are rejected consistently on every host.
- [x] (2026-07-18 09:14Z) Milestone 2b implementation: added strict content-addressed catalog registration, category/exact/directory endpoint selection, catalog-qualified auxiliary selector identities, setwise taint composition, reusable typestate endpoint/event/terminal composition, finite supersedes/combination precedence, and stored fully resolved taint/typestate specifications without solver plans.
- [x] (2026-07-18 09:14Z) Milestone 2c implementation: added closed loaded models, bounded immutable registry authority, selected directory manifests, resolved schema/dependency provenance, domain-separated source/selector/catalog/endpoint/policy/projection hashes, semantic-collision guards, duplicate-ID rejection, transactional byte/slot accounting, and read-only manifest/dependency accessors. Referenced catalog canonical content is charged once per catalog identity per policy and all retained auxiliary models consume registry slots.
- [x] (2026-07-18 09:14Z) Milestone 2 validation/review/checkpoint: passed 89 policy unit tests, 8 workspace-document tests, 21 path-normalization tests, 16 policy-loading integrations, and 8 shared-workspace integrations covering Unicode, portable Windows prefixes, internal/escaping symlinks, FIFO replacement, selected/unselected manifests, catalog auxiliaries, and low-limit transactionality. Strict all-feature library Clippy, formatting, whitespace, `cargo deny`, reproducible `cargo about`, and supplemental-notice checks pass; two adversarial rounds have no remaining accepted finding.
- [x] (2026-07-18 12:30Z) Milestone 3a implementation: added 28 stable query diagnostic codes with typed advisory/incomplete/invalid impact, machine-readable completion with invalid/cancelled/incomplete precedence, cancellation-aware detailed execution, bounded source/evidence hydration, aligned partial rows, and Rust/Python/text/JSON propagation. Audited semantic, hierarchy, member, call, reference, formal-input, and enclosing-declaration producers so retained positives survive while every proven omission prevents a complete negative conclusion.
- [x] (2026-07-18 12:30Z) Milestone 3b implementation: added the canonical schema-version-1 run/finding/report, stable semantic identity, match/taint/typestate evidence, classification/CVSS report shapes, immutable host budgets, and transactional report builder. Strong identities exclude coordinates and native paths; weak identities force inconclusive completion; rule/run/finding joins include policy ID, semantic hash, and analysis type; duplicate policy IDs are unrepresentable; and retained-byte/count exhaustion records typed omissions without constructing an over-budget sentinel.
- [x] (2026-07-18 12:30Z) Milestone 3c implementation: added context-requiring match evaluation over every accepted location-bearing terminal domain, exact source slices and semantic owners, deterministic duplicate ordinals, bounded query provenance, conservative proof/certainty, artifact-only file findings, and rejection of receiver-analysis terminals. Partial diagnostics or malformed rows retain later valid diagnostics/findings, cancellation and capability gaps never become clean, and future taint/typestate dispatch receives the exact stored resolved specification without rescanning authoring inputs.
- [x] (2026-07-18 12:30Z) Milestone 3 validation/review/checkpoint: passed 166 policy units, 29 structural-search units, 7 call-relation units, 14 evaluator units, 142 consolidated match/query/cross-language/planner/usage integrations, and 42 Python client tests. Formatting, whitespace, and strict all-feature library Clippy pass. Adversarial closure fixed false-clean projection drops, lost bounded positives, invalid stable-key encodings, lower-budget constructor/builder bypasses, weak terminal-run insertion, analysis-type and duplicate-rule joins, duplicate/no-growth truncation, diagnostic/candidate adaptation loss, and zero/tiny retained-cap fabrication; no accepted M3 finding remains.
- [x] (2026-07-18 15:30Z) Milestone 4a implementation: added a crate-sealed but production-usable #824 projection seam, exact loaded-policy/compilation authority, pair-local taint and typestate validation, deterministic unique finding-combination precedence, generated flow messages, terminal-violation joins, and generic broad/refined classification from complete facts. Adapters return unsealed payloads; the evaluator owns final sealing, presentation, classification, risk/CVSS reduction, report retention, findings, and runs.
- [x] (2026-07-18 15:30Z) Milestone 4b implementation: added RustSec-backed CVSS v4 evidence normalization, policy/static/overlay provenance, exact scope and scenario correlation, coherent variant reduction, B/BT/BE/BTE component scoring, deterministic display selection, scored/unscored results, and full-semantic versus bounded-display identities. Organizational risk remains orthogonal and all secondary evidence shares one bounded reference/byte coordinator.
- [x] (2026-07-18 15:32Z) Milestone 4 validation/review/checkpoint: passed 218 policy units, 13 public match-evaluation integrations, and 7 public CVSS integrations, including all pinned FIRST vectors. Production library check, formatting, whitespace, final coherent all-target/all-feature strict Clippy, `cargo deny`, byte-identical `cargo about`, and supplemental-notice regeneration pass. Adversarial closure fixed adapter seams usable only through test backdoors, private final-finding authority leakage, pair-local classification/CVSS joins, scenario/evidence retention drift, aggregate byte overflow, incompatible terminal completion, and physical-error/duplicate overcounting of omitted semantic findings; the final recheck found no remaining checkpoint blocker.
- [x] (2026-07-18 17:42Z) Milestone 5a implementation: added bounded deterministic human and canonical JSON writers over the canonical report only. Human output is location-first but follows with typed, escaped, line-structured rule, schema, endpoint, anchor, evidence, proof, classification, CVSS, organizational-risk, witness, diagnostic, completion, and truncation detail; it contains no embedded JSON detail blobs. Canonical JSON streams directly through one byte-counting formatter which visibly escapes terminal controls and bidirectional controls without changing safe Unicode.
- [x] (2026-07-18 17:42Z) Milestone 5b implementation: added the private borrowed SARIF 2.1.0 serializer, preflighted rule/run joins, streaming result and artifact-URI projections, exact Unicode-code-point regions, strong-only fingerprints, unsuccessful invocation notifications, and the pinned OASIS errata-01 schema plus checksum and offline Draft 4 validation.
- [x] (2026-07-18 17:42Z) Milestone 5c implementation: added repeatable policy roots, stable duplicate exclusion, collect-and-continue coordination, strict schema mode, human/JSON/SARIF formats, all `--fail-on` thresholds, status-2 precedence, terminal-safe stderr, and same-directory synchronized atomic output replacement. Requested source identities are bounded and validated before reads or duplicate grouping; unsafe identities use deterministic hash surrogates in report diagnostics.
- [x] (2026-07-18 17:42Z) Milestone 5 validation/review/checkpoint: passed 248 policy units, 85 structural-query units, 13 match-evaluation, 4 human/JSON rendering, 14 SARIF, 13 policy-CLI, and 24 legacy-CLI integrations. The eight-command acceptance transcript produced the expected `1,0,2,1,2,2,0,0` statuses and matching finding IDs. Formatting, whitespace, isolated all-target/all-feature strict Clippy, `cargo deny`, byte-identical `cargo about`, supplemental-notice regeneration, and offline OASIS schema validation pass. Adversarial closure fixed eager SARIF allocation, incomplete typed terminal evidence, source-identity amplification, duplicate-order/status drift, terminal-unsafe stderr/human text, embedded JSON human details, truncated-diagnostic lower bounds, weak SARIF identity loss, argument-order-dependent policy error status, and schema-invalid zero-step witnesses; the final re-audit found no remaining checkpoint blocker.
- [x] (2026-07-18 18:40Z) Milestone 6a implementation: registered `.rqlp` as the distinct `bifrost-rql-policy` editor language with its own icon and conservative TextMate grammar; added source-only validation and schema hover, registry-derived optional-version completion, UTF-16 ranges, and 100-column formatting which preserves comments/version omission and emits no edits for malformed or incomplete buffers; and kept policy documents out of query execution/results.
- [x] (2026-07-18 18:40Z) Milestone 6b implementation: added the navigable static-analysis policy guide, executable fixture-backed match example, checked normalized endpoint/taint/typestate fragments, and synchronized CLI/RQL/editor/reproducibility/result-safety documentation for both document kinds, all variants, composition, completeness, identity, reporting, CVSS, and the #824 execution boundary.
- [x] (2026-07-18 18:40Z) Milestone 6 validation/review/checkpoint: passed 15 policy-source units, 12 policy-source integrations, the full 187-test LSP integration suite, 57 VS Code tests, 7 policy-doc/common-harness tests, and 3 query-doc tests; built 55 documentation pages and checked 4,725 internal links with zero Astro diagnostics; visually inspected desktop and narrow previews without page-level overflow or console errors; passed formatting, whitespace, and isolated all-target/all-feature strict Clippy; and closed all accepted documentation and mid-token-completion audit findings.
- [x] (2026-07-18 19:52Z) Milestone 7 adversarial review/fixes: four independent schema/loading, public-surface, evaluation/report, and documentation audits closed every accepted finding. Match-directory traversal now counts all filesystem entries under a 65,536-entry ceiling, opens explicit directory components directly without sibling enumeration, retains only O(depth) handles, and preserves typed limit diagnostics. Workspace source identities are validated before I/O; author-facing catalog text shares the control/bidirectional validator; help URIs preserve strict authored HTTP(S) authority form as well as maintained URL parsing; schema-lineage, retained-size, composition, and adapter machinery are no longer publicly reachable; and executable tutorial outputs/completeness guidance match current structured diagnostics.
- [x] (2026-07-18 19:52Z) Milestone 7 final gates/checkpoint: passed the complete post-fix `--features nlp` Rust matrix (1,360 library tests passed, 4 ignored, plus every integration and doc-test binary), repository-supported Python fallback (42/42), 57 VS Code tests, 21 executable tutorials, Astro check/build for 55 pages and 4,725 links, isolated all-target/all-feature strict Clippy, formatting, whitespace, license policy, byte-identical generated notices, and SARIF fixture verification. The eight-command CLI transcript returned `1,0,2,1,2,2,0,0`; human, JSON, and SARIF shared finding ID `48f5e3d114587c05c1767f552ba1a41d4f39fd0bae0a41c54128328e93e848d8`. The combined `nlp,python` Rust link failed on this macOS host at PyO3 Python C symbols, so the prescribed full-NLP plus `scripts/test_python.sh` split was used. No review blocker remains; no push or PR was requested.

## Surprises & Discoveries

- Observation: the live issue's illustrative `CodeQueryResult { matches: ... }` has drifted; the current executor returns a tagged `results: Vec<CodeQueryResultItem>` covering structural matches, declarations, files, references, calls, expression sites, and receiver-analysis reports.
  Evidence: `src/analyzer/structural/search.rs` defines the current result union. The match adapter must deliberately choose reportable terminal domains rather than assume every row is a `CodeQueryMatch`.

- Observation: the generic S-expression parser already has every primitive schema version 1 needs: byte-spanned lists, vectors, JSON-escaped strings, symbols, unsigned integers, comments, and a bounded nesting depth.
  Evidence: `src/sexp/syntax.rs` and `format.rs` now parse and format schema-agnostic expressions. Large policy maps can use tagged records and vectors of records without a new lexer, map literal, set literal, decimal, or raw-string syntax.

- Observation: standalone `CodeQuery` JSON and RQL already resolve an omitted query version to current schema version 2, but the current decoder conflates that default with its only supported version and does not retain version-origin provenance.
  Evidence: `CodeQuery::from_json` uses `SCHEMA_VERSION` when `schema_version` is absent, and `CodeQuery::from_sexp` lowers through that path. Policy loading should preserve that behavior while separating an implicit compatibility head from an explicit pin before more versions exist.

- Observation: selector strings would weaken both authoring and diagnostics even inside an S-expression envelope.
  Evidence: passing `(call ...)` as an AST child allows the existing RQL lowerer to retain exact ranges. A quoted string would require escaping and a decoded-to-source offset map, the same main problem a YAML block scalar would introduce.

- Observation: current query completeness is not safe enough for a diagnostic policy boundary.
  Evidence: `CodeQueryResult.truncated` covers limits and cancellation, but unsupported language features can emit ordinary string diagnostics while leaving `truncated` false. Broad-query advice is also an ordinary diagnostic but does not imply incompleteness. The policy evaluator cannot classify these strings without a typed code and impact.

- Observation: current full-detail structural match IDs contain byte offsets and therefore are not suitable as cross-revision SARIF fingerprints.
  Evidence: `match_id` in `src/analyzer/structural/search.rs` renders `path:kind:start-end`. Policy identity needs a separate domain-separated anchor that excludes absolute line and byte positions.

- Observation: the current query file loader already enforces most of the right path boundary, but its read/extension logic is private to `SearchToolsService`.
  Evidence: `src/searchtools_service.rs` performs a bounded regular-file read and `src/tool_arguments.rs` rejects workspace and symlink escapes. Policy and referenced-selector loading should share a single reusable workspace-document loader rather than copy these checks.

- Observation: `.rql` is intentionally a query-only editor language and its result tree cannot double as policy diagnostics.
  Evidence: the VS Code extension registers only `.rql` as `bifrost-rql`, invokes `bifrost/queryCode`, and labels the view as query results. `.rqlp` needs a distinct language ID and validation surface; the first issue need not add a policy findings tree.

- Observation: no YAML, SARIF, CVSS, or JSON Schema validator dependency currently exists.
  Evidence: `Cargo.toml` already has Serde, `serde_json`, `sha2`, and the RQL parser. S-expression authoring adds no format dependency; a narrow CVSS runtime dependency and SARIF-schema test dependency still require license-report updates.

- Observation: RustSec `cvss` 2.2.0 implements the full v4 vector score, nomenclature, and severity, but one `Vector::score()` returns the score for that vector rather than a list of component projections.
  Evidence: the tagged `cvss/v2.2.0` source constructs `Score { value, nomenclature }` from one `Vector`. Bifrost must construct and score the coherent B, BT, BE, or BTE projections it publishes instead of assuming one library call returns every component result.

- Observation: the installed Bifrost code-navigation skills had no callable Bifrost MCP tools in this Codex session.
  Evidence: the active tool catalog exposed no `search_symbols`, `get_symbol_sources`, `scan_usages_by_location`, or related methods, so the investigation used the skills' narrow `rg`, direct-source, Git, and GitHub fallbacks. This is a tooling availability gap worth a follow-up, not evidence about the analyzer itself.

- Observation: the live #709/#824 prose overlapped on who expands catalogs and performs classification, while the detailed roadmap needs one owner to avoid duplicate reducers.
  Evidence: both live issue bodies now mirror this plan: #709 owns syntactic catalog registration/composition plus the generic classification/CVSS reducer, and #824 owns semantic selector compilation plus analysis-specific evidence/adaptation. This closes the pre-implementation ownership gate.

- Observation: a source-level `rql-file` selector cannot have final query semantics or a resolved referenced-document version until the workspace loader reads that file in Milestone 2.
  Evidence: `PolicySelector::File` deliberately retains only the authored optional wrapper version and workspace-relative path. Milestone 1 can normalize the authored document for diagnostics/debugging, but only `LoadedPolicy` can supply final canonical semantic JSON and hashes after resolving the referenced selector and dependency manifests.

- Observation: “inline/local” does not by itself mean “composition-free”: a category or exact endpoint predicate still needs the loaded endpoint identities, analysis-projection hashes, and precedence manifest even when every endpoint was authored in the same policy.
  Evidence: the public parser-gated inline/local projection now rejects every endpoint predicate with `EndpointPredicateRequiresComposition`; a focused local category-combination regression prevents unresolved authored predicates from being mislabeled canonical semantic JSON.

- Observation: implementation began with the issue branch seven commits behind current `origin/master`, but none of those commits touched the policy plans or the structural-query concrete-syntax files targeted by Milestone 1.
  Evidence: after `git fetch origin`, `git rev-list --left-right --count HEAD...origin/master` printed `0 7`; `git diff --name-status HEAD..origin/master` showed C#/definition/LSP/skill changes and no issue-709 or RQL syntax/formatter files.

- Observation: the generic parser could be moved without changing RQL behavior, but a policy-safe AST lowering seam needed range-bearing errors before the existing JSON decoder.
  Evidence: lowering-stage errors occur before `CodeQuery::from_json`, while decoder errors carry semantic JSON paths. The RQL lowerer now propagates the exact offending `Expr` range through recursive and multi-branch forms; the query source path table maps that range to a semantic path, and decoder paths map back through the same table. Focused tests prove an unknown field selects only `:unknown`, a missing value selects only its keyword, a bad limit selects only `0`, multi-branch lowering reports the first failing branch, and a prior decoder-only diagnostic cannot displace a later lowering error.

- Observation: no-follow plus post-open metadata is not by itself a nonblocking filesystem safety boundary.
  Evidence: a regular directory candidate can be replaced by a FIFO after `DirEntry::file_type`; a blocking read open waits before `fstat` can reject the object. Explicit workspace documents have the same problem even without a classification race. Unix candidate-file opens now add `O_NONBLOCK`, directory opens add `O_DIRECTORY | O_NONBLOCK`, final directory components use `O_NOFOLLOW`, and delayed-peer regressions prove a future flag regression fails on elapsed time rather than hanging the test process.

- Observation: catalog auxiliary models need the same globally qualified closure identity as source/sink endpoint dependencies.
  Evidence: re-keying a catalog sanitizer, transform, or external model under `/analysis/...` aliases distinct catalog entries and loses the source-form selector path. Resolved auxiliaries now retain local or catalog-qualified identities, `/dependencies/catalogs/{name}@{version}/{entry}/selector` paths, typed origins, canonical content, and idempotent repeated-catalog behavior; equal bare IDs from different catalogs coexist.

- Observation: Serde's ordinary JSON object lowering and the catalog registry's independent 64-MiB bound were both insufficient at the loaded-policy boundary.
  Evidence: `serde_json::Value` replaces earlier duplicate object keys, including keys nested inside a query, and a policy can clone selected catalog selectors/models many times without consuming the catalog registry again. Catalog byte inputs now pass a depth-bounded duplicate-key visitor before typed decode; each loaded policy conservatively charges one canonical copy of every referenced catalog identity and counts every retained auxiliary slot before transactional insertion.

- Observation: host-native `Path::components` is not enough to enforce a portable workspace-relative wire contract.
  Evidence: Unix treats `C:query.rql` as an ordinary filename and query argument normalization could turn a UNC/device spelling into a relative path before the capability loader saw it. Shared prefix detection now rejects drive-relative, drive-rooted, UNC, verbatim UNC/drive, and device spellings consistently, with Unicode paths and contents covered separately so portability hardening does not reduce the supported source alphabet.

- Observation: structured query producers had several ways to retain a real semantic candidate but silently lose its exact report projection.
  Evidence: missing declaration ranges, enclosing owners, hierarchy members, call/reference targets, formal-parameter layouts, bounded callsite samples, and source snapshots could previously collapse to an empty complete result. The audited producers now retain every exact positive, emit `SemanticResultsOmitted` or the domain-specific typed omission, suppress ambiguity advice that assumed a complete candidate set, and set truncation/completion conservatively. Synthetic/file-scope no-owner cases and known formal nonmatches remain clean.

- Observation: a host may configure a retained-byte cap smaller than the fixed storage of any `PolicyRun`.
  Evidence: forcing the evaluator to return a run under a zero- or one-byte cap required an over-budget internal-failure sentinel. `PolicyRun::try_new` now enforces its post-refresh size, and `PolicyEvaluator::evaluate` returns `Result<PolicyRun, PolicyRunError>` so a physically unrepresentable result fails honestly while unsupported/failed runs remain ordinary report values whenever they fit.

- Observation: a public incremental report builder needs to defend the same canonical invariants as raw report construction, including no-growth operations.
  Evidence: lower-budget findings, weak findings added to terminal runs, mismatched analysis types, same policy IDs with different hashes, and duplicate diagnostics at capacity could previously bypass or falsely poison final state. Builder and document joins now agree; whole findings that exceed host retention limits become counted omissions, while identical retained diagnostics consume no additional capacity.

- Observation: public future-analysis adapters can return final report objects, so budget and join checks alone do not prove that taint/typestate evidence came from the loaded policy and validated dominance projection.
  Evidence: Milestone 3 closes the exact resolved-spec dispatch and report-shape boundary, but `TaintPolicyEvaluator`/`TypestatePolicyEvaluator` still form a trusted seam. Milestone 4a must mint validated projection/compilation tokens, bind presentation and evidence to the loaded policy hashes, and make the sealed path the only way future adapters can construct analysis findings.

- Observation: a sealed trait is not a usable integration seam if only a child test module can construct its private inputs and install it through private field literals.
  Evidence: the first Milestone 4 adapter tests passed by calling `#[cfg(test)]` batch/hash factories and writing `DefaultPolicyEvaluator`'s private fields directly. A sibling #824 module could implement the crate-sealed traits but could not install an adapter, create typed compilation hashes, or return an authority-bound batch. The production seam now accepts crate-private unsealed payloads, seals them only inside the evaluator with the exact freshly minted authority, and exposes a crate-private adapter constructor and typed compilation-hash constructor; the same fake adapters use only that production path.

- Observation: report retention and semantic identity have different domains for taint scenarios and CVSS evidence.
  Evidence: full sorted scenario sets and the complete applicable semantic evidence set must remain identity/correlation inputs even when bounded display vectors retain only a prefix. Core finding evidence, organizational risk, and CVSS also share one evidence-reference namespace and per-finding byte budget, so independent reducers can otherwise retain dangling or duplicate references and overstate omission counts.

- Observation: `omitted_findings_lower_bound` must count distinct semantic findings, not rejected projection envelopes, facts, or diagnostics.
  Evidence: one taint source endpoint can legally contribute multiple label facts to one source/sink pair, and duplicate envelopes can repeat one `PolicyFindingId` arbitrarily many times. Counting each failed fact or physical copy can exceed the number of omitted findings. Milestone 4 validation therefore aggregates known omissions by `PolicyFindingId`, rejects an endpoint pair as a unit when any of its facts fails authority validation, removes every retained ID from the omission set, and preserves multiple diagnostics without multiplying the finding count.

- Observation: `cvss` 2.2.0 cannot compile its v4 API with only the documented v4 feature in this dependency graph.
  Evidence: the crate's public `MetricType` references its feature-gated v3 module unconditionally. Enabling `std`, `v3`, and `v4` compiles the RustSec scoring implementation; Bifrost still parses, reduces, and reports only CVSS v4.0.

- Observation: a candidate cap does not bound the work or memory needed to discover candidates in an adversarial endpoint directory.
  Evidence: the first directory implementation counted only retained `.rqlp` candidates and materialized all entries of every opened directory. Milestone 7 now counts every visited entry before filtering, stops collection at the caller's remaining budget, traverses iteratively with O(depth) open handles, and resolves an explicitly authored directory component-by-component with no-follow opens rather than scanning unbounded siblings.

- Observation: WHATWG URL parsing deliberately repairs malformed web-URL spellings that the RQLP authoring contract must reject.
  Evidence: inputs such as `https:example.test`, `https:/example.test`, `https:///example.test`, backslash paths, and malformed percent escapes can otherwise normalize to usable URLs. Help-URI validation now first requires the authored lowercase `http://` or `https://` authority form, rejects parser syntax violations, then requires an HTTP(S) URL with a host while retaining the original string.

## Decision Log

- Decision: use one S-expression RQLP document—either `(policy ...)` or diagnostic-neutral `(endpoint ...)`—per `.rqlp` file; do not accept YAML or JSON as schema-version-1 authoring formats.
  Rationale: native nested RQL remains readable and unescaped, the existing byte-spanned parser and formatter can be shared, comments and duplicate detection are deterministic, and LLM output is not sensitive to indentation, anchors, aliases, tags, merge keys, or YAML implicit typing. Canonical JSON remains available from the typed model for machine interchange and hashing.
  Date/Author: 2026-07-17 / Codex

- Decision: distinguish normalized authored JSON from canonical semantic JSON.
  Rationale: the parsed authoring model can contain unresolved `rql-file`, catalog, exact-endpoint, match-directory, category-predicate, and endpoint-predicate meaning. Milestone 1 exposes deterministic normalized authored JSON for debugging and gold tests, while Milestone 2 exposes canonical semantic JSON only from `LoadedPolicy`/`LoadedMatchEndpoint` after every referenced selector, version, endpoint, predicate, precedence edge, and manifest is resolved. Semantic hashes consume only the latter. The parser-gated Milestone 1 semantic helper accepts only shapes already identical to that loaded projection and rejects any endpoint composition predicate. Query execution controls (`limit` and `result-detail`) are never part of policy selector semantics.
  Date/Author: 2026-07-17 / Codex

- Decision: give RQLP a registry-driven record formatter with a 100-column default while preserving the existing generic/RQL formatter behavior.
  Rationale: the generic syntax formatter is reusable, but large vectors of endpoint/event records need policy schema knowledge to keep each `:field value` pair together and choose stable record breaks. The formatter accepts 80/100/120-column options for gold tests, places one large tagged record per vector line, preserves comments/string contents, and is idempotent. It does not create a second keyword table because field signatures come from `policy/schema.rs`.
  Date/Author: 2026-07-17 / Codex

- Decision: make RQLP a distinct declarative grammar, not a new `CodeQuery`/RQL query form.
  Rationale: query matches are diagnostic-neutral and must remain usable for exploration. The shared concrete S-expression AST is generic, but policy vocabulary belongs in `src/analyzer/policy/schema.rs`; nested selectors alone use the RQL query registry.
  Date/Author: 2026-07-17 / Codex

- Decision: encode the public variant with exactly `(analysis :type match|taint|typestate ...)` and reject fields owned by another variant.
  Rationale: this preserves the issue's literal `analysis.type` contract in canonical JSON and produces precise missing, unknown, and wrong-variant diagnostics. The type is not inferred from whichever fields happen to be present.
  Date/Author: 2026-07-17 / Codex

- Decision: make `:schema-version` optional on top-level `policy`/`endpoint`, inline `rql`, and `rql-file` forms, using one compiled-in implicit compatibility lineage per format.
  Rationale: an explicit version is an exact pin and decodes only that version; an unsupported explicit value never falls back. Omission selects the greatest supported member of that format's implicit lineage before decoding. A successor may join the lineage only when every valid predecessor document stays valid with identical normalized meaning after erasing the version number; changing an existing spelling, default, validation rule, or interpretation makes the successor explicit-only. A decode error at the selected head never retries an older decoder. Today omission resolves policy documents to version 1 and RQL to version 2. There is no filesystem, network, environment, or installed-version negotiation.
  Date/Author: 2026-07-17 / Codex

- Decision: wrap every selector as either `(rql [:schema-version N] QUERY)` or `(rql-file [:schema-version N] :path "workspace/relative.rql")`, exclusively.
  Rationale: policy schema evolution and query schema evolution are independent. The inline child lowers directly from the spanned AST, while a referenced selector is read once through the workspace boundary and retains its own source identity. For `rql-file`, equal explicit wrapper/document versions agree; an explicit wrapper supplies an omitted document version; an explicit document supplies an omitted wrapper version; both omitted use the RQL implicit lineage head; and unequal explicit versions fail with `conflicting-rql-schema-version`. Quoted RQL strings remain rejected.
  Date/Author: 2026-07-17 / Codex

- Decision: let a referenced `.rql` file contain either the existing raw `QUERY` form or one explicit `(rql :schema-version N QUERY)` document envelope; no other envelope fields or multiple forms are accepted.
  Rationale: raw files preserve all existing `query_code` behavior, while the envelope creates an unambiguous document-level exact pin for the four wrapper/document precedence cases. Milestone 2 will implement this through one shared query-document decoder over the spanned S-expression AST, not a source-text mini parser; the policy loader retains both authored pins as provenance and resolves one effective schema version.
  Date/Author: 2026-07-17 / Codex

- Decision: require `id`, `name`, `message`, `severity`, and `analysis` for runnable policies; accept either a static message or the structured taint-only `generated can-reach` message.
  Rationale: direct match and typestate policies retain static report text. A taint aggregate may instead render exactly `{source endpoint display-name} can reach {sink endpoint display-name}` after a real compatible meeting. This is a closed typed variant, not an interpolation language; it performs no casing rewrite or category-name humanization. Endpoint documents have identity and description but no severity/message because they are diagnostic-neutral dependencies rather than SARIF rules.
  Date/Author: 2026-07-17 / Codex

- Decision: model reusable categorized source/sink matches as one diagnostic-neutral `(endpoint ...)` leaf per file, not as runnable match policies whose behavior changes when imported.
  Rationale: an endpoint owns one selector, typed matched-value/receiver/return/argument binding, source-or-sink role, opaque exact categories, a human display phrase, optional taint semantics, and explicit `supersedes` IDs. Direct `analysis.type = match` policies remain findings. Loading an endpoint as a dependency never creates a `PolicyRun`, while passing one as an execution root fails visibly as `NotExecutableEndpoint`; a raw match is still not a diagnostic.
  Date/Author: 2026-07-17 / Codex

- Decision: let aggregate policies select endpoint leaves through explicit capability-rooted directory references or exact endpoint IDs.
  Rationale: `(match-directory :path ... :scope direct|recursive :categories (any|all [...]) [:manifest-sha256 ...])` is a deliberate input, not ambient discovery. Traversal is workspace-rooted, lexical, bounded, transactional, `.rqlp`-only, and never follows symlinks or consults ignore files. Endpoint leaves cannot import directories. The selected endpoint ID/semantic-hash manifest enters policy meaning; directory paths, layout, source hashes, and pin spelling remain provenance. There is still no implicit project scan, environment lookup, or network load.
  Date/Author: 2026-07-17 / Codex

- Decision: make broad-versus-specific precedence explicit at both endpoint resolution and finding presentation.
  Rationale: #824 may remove a broad endpoint only when two selected models resolve to the same semantic event, role, and typed binding and a validated acyclic `supersedes` relation names a unique winner. For an actual source/sink meeting, any matching explicit combination beats the generated default; overlapping explicit combinations also require one unique non-superseded winner or loading fails with `AmbiguousCombinationPrecedence`. Never infer specificity from RQL text, path order, message text, or source location. Precedence is scoped to one aggregate policy and never suppresses an unrelated policy.
  Date/Author: 2026-07-17 / Codex

- Decision: reuse resolved endpoint sets in typestate subject/event selection and represent terminal obligations explicitly.
  Rationale: each endpoint keeps its own API binding and observation phase, so one protocol event can cover receiver-, return-, or argument-bound APIs without copying selectors. Explicit call endpoints can transition to non-absorbing accepting states. Normal or exceptional analysis-root exit can impose a terminal expectation over the current state; helper returns remain ordinary interprocedural transfers. Violating an expectation is a distinct diagnostic-neutral finding kind, not a fake transition to an `error` state. #709 stores the pre-semantic `ResolvedTypestatePolicySpec`; #824 compiles bound semantic event classes and the final binding-plan hash; #822 owns protocol execution; categories and display/reporting data never enter solver or summary keys.
  Date/Author: 2026-07-17 / Codex

- Decision: parse and fully shape-validate match, taint, and typestate policies now, but execute only match policies in #709.
  Rationale: #709 must freeze public authoring types before #824, but it must not invent #821's taint plan or serialize #822's internal `ProtocolSpec`. Taint and typestate evaluation returns `Unsupported`, retains diagnostics/work, and cannot look like a complete negative.
  Date/Author: 2026-07-17 / Codex

- Decision: permit match selectors whose terminal domain is structural match, declaration, reference site, call site, expression site, or file; reject receiver-analysis terminal rows in schema version 1.
  Rationale: the accepted domains represent positive, location-bearing entities or sites. File findings legitimately have an artifact URI without a region. A receiver-analysis row can represent precise, ambiguous, unknown, unsupported, or exhausted analysis and is not by itself a positive diagnostic condition.
  Date/Author: 2026-07-17 / Codex

- Decision: policy selectors cannot author `limit` or `result-detail`; evaluation forces full detail and receives work bounds from `PolicyBudget`/execution context.
  Rationale: a result limit changes the truth of a negative policy run and compact detail drops exact ranges. A bounded evaluator may return partial findings, but it must mark the run inconclusive rather than silently adopting an author-controlled output truncation as policy semantics.
  Date/Author: 2026-07-17 / Codex

- Decision: add stable query diagnostic codes and typed impact (`advisory`, `incomplete`, or `invalid`) at the origin of each diagnostic.
  Rationale: policy completion must never depend on English string matching. `truncated` remains the bounded-output signal; policy match completion is `Complete` only when it is false and no diagnostic affects completeness or validity.
  Date/Author: 2026-07-17 / Codex

- Decision: give runs and findings independent completion, and keep certainty, severity, classification, CVSS, and organizational risk orthogonal.
  Rationale: a run can be incomplete while containing real partial findings; one finding can be well-supported while enumeration is incomplete elsewhere. Severity is a reporting decision, certainty is analyzer evidence, CVSS measures vulnerability severity rather than probability or business risk, and an empty incomplete run is not clean.
  Date/Author: 2026-07-17 / Codex

- Decision: derive `PolicyFindingId` from a versioned, adapter-supplied neutral anchor, record whether that anchor is strong or weak, and exclude source coordinates and presentation fields.
  Rationale: a strong SHA-256 input contains a domain label, policy ID, analysis type, workspace-relative path, result domain, stable semantic owner when available, full source-slice digest, and same-anchor occurrence ordinal. It excludes line/column/byte offsets, message, severity, classification, CVSS, witnesses, and bounded provenance, so unrelated preceding edits and report changes minimize SARIF churn. The guarantee deliberately excludes edits inside the selected slice and insertion/removal of an otherwise equal anchor earlier in the same owner/file, either of which changes the digest or ordinal. If execution cannot retain either exact selected bytes or a stable semantic identity, the deterministic fallback ID is marked weak, the run is inconclusive, and SARIF omits `partialFingerprints`; it never presents an offset-only ID as cross-revision stable. The policy content hash is recorded separately.
  Date/Author: 2026-07-17 / Codex

- Decision: make catalog registration explicit, versioned, content-hashed, and separate from the human policy file syntax.
  Rationale: a `.rqlp` can name a built-in or embedding-registered catalog by name/version and optionally pin its SHA-256. `TaintCatalogRegistry` accepts typed values, canonical JSON bytes, or explicitly requested workspace-safe paths; the catalog registry itself performs no directory scan or network load. Human-authored reusable leaves use the separate endpoint document and explicit `match-directory` composition surface rather than becoming a second catalog JSON frontend.
  Date/Author: 2026-07-17 / Codex

- Decision: retain source-form-qualified identities for every composed catalog auxiliary and conservatively charge referenced catalog canonical bytes at the policy-registry boundary.
  Rationale: sanitizers, transforms, and external models carry executable selector meaning even though they are not source/sink endpoints. Treating them as policy-local aliases loses catalog provenance and permits collisions; excluding them from registry byte/slot totals permits repeated policy loads to amplify a bounded catalog registry into unbounded retained state. The loaded model therefore uses catalog-qualified identities/paths/origins, counts every composed auxiliary slot, and charges each referenced catalog identity once per policy before insertion. This may overestimate a policy which selects only a small catalog subset, but it is deterministic, bounded, and safe until a more exact retained-size implementation can prove a lower charge.
  Date/Author: 2026-07-18 / Codex

- Decision: keep explicit internal-file symlinks compatible while making directory composition symlink-free and all Unix document opens nonblocking.
  Rationale: existing `query_file` behavior intentionally accepts an internal symlink, and `cap-std` confines that resolution beneath the retained workspace root. Match-directory traversal has a stronger reproducibility contract and rejects/skips symlink entries. `O_NONBLOCK` is orthogonal to those follow rules: it ensures a FIFO/device substitution reaches the same-handle regular-file check instead of blocking first; `O_DIRECTORY` and `O_NOFOLLOW` protect classified directory entries.
  Date/Author: 2026-07-18 / Codex

- Decision: calculate CVSS v4.0 from typed evidence with the RustSec `cvss` v4 implementation, never from an authored score.
  Rationale: all eleven Base metrics must be established without `X` before a numerical Base score exists. Coherent conflicting scenarios remain separate variants; incomplete or conflicting evidence remains `Unscored`. The policy layer owns evidence, provenance, variant coherence, and display selection while the library owns vector parsing/canonicalization and the FIRST scoring algorithm.
  Date/Author: 2026-07-17 / Codex

- Decision: emit SARIF from private strongly typed SARIF 2.1.0 DTOs and validate gold output against a pinned official OASIS schema.
  Rationale: a loose `serde_json::Value` tree makes required members, level mapping, locations, fingerprints, and notification shape easy to drift. Bifrost does not need a public general-purpose SARIF model or a heavy runtime SARIF dependency.
  Date/Author: 2026-07-17 / Codex

- Decision: retain the exact typed terminal result, including domain-specific semantic identities and proof, in every match finding rather than reconstructing it in renderers from provenance or display strings.
  Rationale: a direct terminal row legitimately has no provenance steps, and the prior anchor/domain pair could not distinguish a structural call from other structural matches or preserve caller/callee and reference-target identities. Renderer inference would make JSON, SARIF, and human output disagree and could overstate name-based call/reference proof. The detailed query seam now supplies typed terminal identities; missing required call/reference identities conservatively downgrade certainty and proof.
  Date/Author: 2026-07-18 / Codex

- Decision: SARIF sequence and artifact-URI projections are borrowed streaming serializers, and report/tool joins are preflighted before the first output byte.
  Rationale: constructing a full private DTO tree before wrapping the destination bypassed the serialized-byte budget through report-sized vectors and escaped path copies. Borrowed `SerializeSeq` views let a zero/tiny bound stop before later results or URIs are visited while preserving a strongly typed private SARIF schema.
  Date/Author: 2026-07-18 / Codex

- Decision: validate bounded policy source identities before reading, duplicate grouping, or registry insertion; represent an invalid requested identity in reports with a domain-separated SHA-256 surrogate plus its byte length and typed reason.
  Rationale: the registry's 1,024-byte/control-free identity contract must apply before duplicate diagnostics retain source strings. Otherwise a long or control-containing requested path can exceed the mandatory 8-KiB diagnostic skeleton and turn a reportable status-2 input failure into a stderr-only coordinator failure. The surrogate is bounded, deterministic, terminal-safe, and still distinguishes every invalid requested input without retaining unsafe raw text.
  Date/Author: 2026-07-18 / Codex

- Decision: keep human output line-structured and typed all the way down instead of embedding canonical JSON fragments for detailed fields.
  Rationale: JSON fragments made nominally human output hundreds of columns wide and introduced a second escaping convention. Explicit field lines preserve renderer parity, remain reviewable in terminals and diffs, use one terminal-safe escape convention, and still keep the first finding/evidence lines concise for immediate action.
  Date/Author: 2026-07-18 / Codex

- Decision: add a repeatable one-shot CLI with `--policy-file`, `--format`, `--fail-on`, and optional `--output`; reserve exit status 2 for any unreliable run.
  Rationale: complete findings and incomplete analysis have different automation meaning. Exit 0 means a complete run without a threshold finding, exit 1 means a complete run with a threshold finding, and exit 2 means loading/validation/internal failure or any incomplete/unsupported run. If both conditions occur, 2 wins. A report document retains completed/partial runs and report-level diagnostics, so failures in one of several inputs still produce a machine-readable partial report whenever serialization itself remains possible.
  Date/Author: 2026-07-17 / Codex

- Decision: register `.rqlp` as `bifrost-rql-policy` with validation, hover, formatting, and syntax highlighting, but do not route it through `bifrost/queryCode` or the RQL result tree.
  Rationale: authoring support is part of a human-readable language, while policy execution and diagnostics have different identity/completion semantics. A policy findings view can be added against the canonical model later without contaminating the query-only surface.
  Date/Author: 2026-07-17 / Codex

- Decision: keep unsaved `.rqlp` validation and hover source-only, and route completion/formatting through standard LSP requests only after the open document is identified as `bifrost-rql-policy`.
  Rationale: editor feedback must remain fast and useful before analyzer initialization without reading `rql-file`, endpoint-directory, or catalog dependencies. Source-only methods therefore run before `AnalyzerQueryScope`; registry-derived completion replaces the entire parsed symbol (including when invoked mid-token); formatting uses the policy formatter over the live overlay and preserves malformed/incomplete text byte-for-byte. Workspace-backed loading remains the sole authority for deferred dependency resolution.
  Date/Author: 2026-07-18 / Codex

- Decision: checkpoint the reviewed ExecPlan, then merge current `origin/master` into the existing issue branch before source implementation; do not rebase or switch branches.
  Rationale: the repository requires work to land on the already checked-out branch and forbids an unrequested rebase/branch switch. Merging preserves the published issue-branch history while ensuring implementation and validation use the current analyzer/LSP/dependency baseline.
  Date/Author: 2026-07-17 / Codex

- Decision: place compatibility-lineage mechanics in a neutral crate-internal `src/schema_version.rs`, with RQL and RQLP declaring their own descriptors in their schema modules.
  Rationale: omitted-version resolution is shared behavior, but query must not depend on policy and the two languages must not duplicate lineage validation. The neutral registry owns exact versus compatible-head resolution; query schema registers version 2 and policy schema registers version 1. Public policy types may re-export the resolution/origin values without exposing registry internals.
  Date/Author: 2026-07-17 / Codex

- Decision: derive query completion only from typed diagnostic impact and the bounded-output flag, with precedence `Invalid` over `Cancelled` over `Incomplete` over `Complete`.
  Rationale: diagnostic prose is presentation and cannot safely control policy reliability. Advisory guidance such as a broad-query hint remains compatible with a complete negative result, while every unsupported capability, semantic omission, work/output limit, and cancellation is machine-readable and prevents one. Producer order remains deterministic and is retained as causal order rather than replaced by enum sorting.
  Date/Author: 2026-07-18 / Codex

- Decision: let policy evaluation return `Result<PolicyRun, PolicyRunError>` only when the host budget cannot represent any canonical run; encode ordinary incomplete, unsupported, and failed analysis outcomes inside `PolicyRunCompletion`.
  Rationale: callers need canonical report values for reportable status-2 outcomes, but a zero/tiny retained cap cannot be satisfied by fabricating an oversized failure record. Exact constructor errors preserve the distinction between an analysis outcome and inability to retain its mandatory representation.
  Date/Author: 2026-07-18 / Codex

- Decision: separate strong stable anchors from explicitly weak opaque identities and make weakness contagious to finding and run completeness.
  Rationale: stable fingerprints may use structured analyzer declaration identities or canonical AST identities plus source-slice hashes and deterministic ordinals, but never absolute paths, line/column/byte coordinates, or dense run-local handles. When exact identity material is unavailable, a retained weak positive is still useful but cannot support baseline stability or a clean run.
  Date/Author: 2026-07-18 / Codex

- Decision: enforce canonical report identity at every construction seam, not only in the future CLI coordinator.
  Rationale: rule descriptors derive analysis type from `LoadedPolicy`; rules, runs, and findings join on policy ID/hash/type; one report cannot contain the same policy ID under multiple hashes; and builder operations that omit a real positive mark the run inconclusive. This keeps direct library callers from constructing JSON/SARIF states that the CLI contract forbids.
  Date/Author: 2026-07-18 / Codex

- Decision: keep final taint/typestate finding authority in #709 while giving #824 a genuinely usable crate-private unsealed projection seam.
  Rationale: the evaluator mints an authority from one exact loaded policy (and, for typestate, one typed compiler-hash claim), passes that authority plus the closed resolved specification to a crate-sealed adapter, receives an unsealed diagnostic-neutral payload, and binds the payload to that same authority before validation. Adapters cannot construct `PolicyFinding`/`PolicyRun`, forge a seal, replay a batch across policies, or supply presentation/classification/CVSS results. Downstream crates cannot install adapters, while a sibling #824 module can use the production constructor and payload types without test-only backdoors.
  Date/Author: 2026-07-18 / Codex

- Decision: separate full semantic correlation from bounded display retention and coordinate all per-finding secondary evidence centrally.
  Rationale: full scenario/evidence-set hashes determine taint/CVSS identity and coherent variants; report options and host budgets may retain only deterministic scenario/reference prefixes without changing those hashes. Core evidence is retained first, organizational risk second, and CVSS third under one distinct evidence-reference namespace and remaining byte budget. Displayed CVSS scenarios must be a subset of retained taint-evidence scenarios, and known omitted reference IDs are unioned before combining with any unknown lower bound so the report never double-counts them.
  Date/Author: 2026-07-18 / Codex

- Decision: retain the largest deterministic canonical report prefix that fits aggregate byte limits.
  Rationale: a complete set of individually valid findings can still exceed the per-policy retained-report cap after final vector/string allocation. The evaluator sorts by stable finding ID, retains the largest fitting finding prefix, then the largest fitting diagnostic prefix, records exact known omissions, and returns a canonical inconclusive run. It returns a `PolicyRunError` only when even the mandatory minimal run skeleton cannot fit.
  Date/Author: 2026-07-18 / Codex

- Decision: account projection omissions by distinct `PolicyFindingId`, independently of diagnostic multiplicity.
  Rationale: one finding may have multiple invalid source facts or arbitrarily many duplicate physical envelopes. Authority validation rejects all facts for an affected source endpoint/pair, records every useful bounded diagnostic, and adds the pair's stable finding ID to a set once. Budget-skipped and duplicate groups contribute their distinct pair IDs; IDs that are ultimately retained are removed before the known count is added to the adapter's prior lower bound.
  Date/Author: 2026-07-18 / Codex

- Decision: bound match-directory discovery by total visited filesystem entries, not only retained endpoint candidates.
  Rationale: irrelevant files, empty directories, and hostile breadth consume enumeration work even when no `.rqlp` candidate survives. Schema version 1 therefore fixes a 65,536 total-entry ceiling which embeddings may lower but not raise; exhaustion is a typed `match-directory-limit` report diagnostic and leaves registry state unchanged.
  Date/Author: 2026-07-18 / Codex

- Decision: keep schema-lineage inference, retained-size accounting, raw composition, and future-analysis adapter authority crate-private.
  Rationale: downstream callers need resolved version/origin values, closed loaded policies, public registry/report errors, and canonical renderers—not the machinery that chooses compatibility heads, asserts byte charges, composes unresolved models, or installs trusted analysis producers. Public errors expose only nameable stable payloads, while #824 remains a sibling module with the crate-private adapter seam described below.
  Date/Author: 2026-07-18 / Codex

## Outcomes & Retrospective

Planning is complete and Milestone 1a has established the shared concrete-syntax boundary. RQL and Rune formatting remain unchanged at 120 columns, the parser is schema-neutral, and nested selectors lower from their original AST ranges without rendering or reparsing. Validation passed `cargo check --lib`, 29 shared/S-expression tests, all 78 structural-query tests, the focused RQL/Rune LSP formatting integration test, `cargo fmt --check`, and `git diff --check`; the two accepted adversarial findings (lowering-stage range loss, including multi-branch ordering, and query-specific wording in the shared parser) were fixed with regressions. The remaining implementation risks are compatibility-head drift, nondeterministic endpoint-directory composition, ambiguous broad-versus-specific precedence, completeness drift in `CodeQueryResult`, unstable finding fingerprints, accidental exposure of internal taint/typestate types, catalog collisions, CVSS inference from missing evidence, and renderer divergence. Each is assigned an explicit public type and acceptance test below.

Milestone 1b/1c now freeze the complete schema-version-1 authoring boundary: both document kinds and all three policy variants parse through one declarative vocabulary registry; omitted policy/RQL versions resolve through compatible lineages while explicit pins remain exact; normalized authored JSON is deterministic; only parser-validated, composition-free inline/local shapes expose the provisional semantic projection; and formatting is stable at 80, 100, and 120 columns without rewriting comments, strings, or version omission. The final matrix passed 12 schema-registry, 40 shared S-expression, 85 structural-query, 46 policy-unit, and 12 policy-source integration tests, plus `cargo check --lib`, `cargo fmt --check`, strict `cargo clippy --lib --all-features -- -D warnings`, and `git diff --check`. The strict gate used one coherent Homebrew Cargo/rustc/Clippy toolchain because the default shell paired rustup rustc (LLVM 22.1.2) with Homebrew `clippy-driver` (LLVM 22.1.6); every repository-managed isolated target was removed. Accepted closure findings fixed exact nested query ranges, bounded parser reuse, global/local identity and graph invariants, multi-error recovery, semantic-projection gating, public CVSS construction invariants, registry-owned CVSS tokens/port shapes, and comment ordering.

Milestone 2 now turns authored RQLP into a closed, bounded semantic model under explicit authority. One retained capability root serves query, policy, endpoint, selector, catalog, and directory reads; path traversal, portable prefixes, escape symlinks, special files, unbounded reads, changing directory path sets, duplicate endpoint IDs, manifest mismatches, and catalog/query duplicate keys fail transactionally. Diagnostic-neutral endpoint leaves can be selected by exact ID or category from explicitly named directories, and local/catalog/directory inputs compose into one deterministic setwise taint or typestate specification with qualified provenance and precedence. Full versus analysis-projection hashes separate display-only changes from executable meaning; directory hashes include only the selected set, while the richer path/source manifest remains provenance. The reviewed matrix passed 89 policy units, 8 workspace-document units, 21 tool-argument units, 16 policy-loading integrations, and 8 shared-workspace integrations, plus strict all-feature library Clippy, formatting, whitespace, dependency-license policy, and byte-for-byte notice regeneration. Accepted adversarial findings fixed catalog auxiliary aliasing, byte/slot amplification, match-set hash overreach, incomparable precedence winners, strict nested duplicate JSON keys, forged public hash inputs, symlink/FIFO races, and host-dependent Windows-prefix parsing.

Milestone 3 now provides the reliability and identity boundary that turns diagnostic-neutral query matches into policy results. Query diagnostics have stable typed impact; detailed execution retains exact evidence and work under the same budget; match evaluation covers structural matches, declarations, files, references, call sites, and expression sites without a context-free raw-row converter; and canonical findings distinguish proven/possible, complete/partial, and strong/weak identity. The report builder reserves every input skeleton, accounts findings and diagnostics transactionally, preserves partial positives, and rejects contradictory rule/run identities. The reviewed matrix passed 166 policy units, 29 structural-search units, 7 call-relation units, 14 evaluator units, 142 consolidated integration tests, and 42 Python client tests, plus formatting, whitespace, and strict all-feature library Clippy. Milestone 4 retains one explicit authority task: dominance-projected taint/typestate facts must be sealed against the loaded policy before classification, presentation, and CVSS reduction can produce findings.

Milestone 4 closes that future-analysis authority boundary. A crate-sealed #824 adapter can be installed through the normative independent builders, receives only the exact closed resolved specification and freshly minted authority, and returns an unsealed diagnostic-neutral payload; #709 then validates every endpoint/hash/pair/origin/terminal join before it alone constructs presentation, classification, organizational risk, CVSS, findings, and runs. Taint reduction is pair-local, explicit finding combinations have graph-defined precedence over generated defaults, and typestate error transitions remain distinct from terminal expectations. CVSS v4 variants preserve complete semantic scenario/evidence correlation while bounded display prefixes, globally distinct evidence references, and aggregate report retention remain deterministic and explicit about omissions. Known projection omissions are counted by distinct `PolicyFindingId`, so multiple invalid facts or duplicate physical envelopes cannot inflate the semantic finding count. The final matrix passed 218 policy units, 13 public match-evaluation integrations, and 7 public CVSS integrations, plus a warning-free production check, formatting, whitespace, coherent all-target/all-feature strict Clippy, `cargo deny`, and byte-identical crate/supplemental notice regeneration. The RustSec `cvss` dependency is pinned at 2.2.0 with `std`, `v3`, and `v4`; `v3` is only the compile workaround documented above and the policy surface remains CVSS v4.0.

Milestone 5 makes that canonical model observable without weakening its bounds. Human output starts with an actionable location, severity, ID, message, finding identity, analysis, and terminal evidence, then renders every remaining typed field as escaped structured lines. Canonical JSON and the private borrowed SARIF projection stream through the encoded-byte bound; SARIF preflights every join, reports Unicode-code-point regions, always retains the canonical finding ID, emits fingerprints only for strong identities, and validates against the pinned OASIS 2.1.0 errata-01 schema. The one-shot coordinator validates source identities before retaining them, excludes every conflicting definition deterministically, continues across independent roots, and gives invalid/incomplete/unsupported outcomes status 2 precedence over finding thresholds regardless of argument order. Atomic file output never falls back to truncation. Root validation passed 248 policy units, 85 structural-query units, 13 match-evaluation, 4 human/JSON rendering, 14 SARIF, 13 policy-CLI, and 24 legacy-CLI integrations; the checked eight-command acceptance transcript produced statuses `1,0,2,1,2,2,0,0` for positive, clean, strict-inference, default-inference, endpoint-root, unsupported-typestate, JSON-never, and SARIF-never respectively. Formatting, whitespace, isolated all-target/all-feature strict Clippy, `cargo deny`, byte-identical `cargo about`, and supplemental-notice regeneration pass. The vendored SARIF schema checksum is `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`.

Milestone 6 completes the human authoring surface without blurring policy and query semantics. `.rqlp` is a distinct VS Code language with an inspected policy icon, a conservative grammar that embeds native RQL scopes only inside exact `(rql ...)` forms, debounced source validation, schema-resolution hover, registry-derived optional-version completion, and 100-column live-buffer formatting. Policy files never acquire the RQL Play action or publish into the query-results tree. The executable documentation now separates normalized authored JSON, loaded canonical semantic JSON, and report JSON; spells out all four `rql-file` version cases, endpoint-index/catalog embedding boundaries, directory hash projection versus report manifest, generated-versus-specific presentation, typestate terminals, and reproduction metadata. The reviewed matrix passed 15 policy-source units, 12 policy-source integrations, all 187 LSP integrations, all 57 VS Code tests, 7 policy-doc/common-harness tests, and 3 query-doc tests. Astro reported zero diagnostics, built 55 pages, and resolved all 4,725 internal links. Desktop and 390-pixel-wide previews had no page-level horizontal overflow or console errors. The final isolated all-target/all-feature strict Clippy, formatting, and whitespace gates pass. Adversarial closure corrected seven documentation/test-contract defects and a mid-token completion suffix defect; the independent re-audits found no remaining Milestone 6 blocker.

Milestone 7 completes issue #709 at policy schema 1, RQL schema 2, and report schema 1. The final hardening pass bounds total endpoint-directory breadth at 65,536 entries, avoids sibling scans and symlink traversal during explicit directory resolution, validates portable source identities before any read, applies one safe-text contract to typed and JSON catalog metadata, rejects normalized-but-inauthentic help URI spellings, preserves match-directory limit diagnostics, and removes implementation-only authority from the public API. Executable tutorial expectations now include the current typed omission diagnostics and make clear that `truncated: false` is insufficient when an `incomplete` or `invalid` diagnostic remains. Independent re-audits found no blocker.

The release matrix passed the complete post-fix NLP Rust suite (1,360 library tests passed, 4 ignored, then every integration and doc-test binary), Python 42/42 through the repository-supported split fallback, VS Code 57/57, executable tutorials 21/21, and the final docs check/build/link pass for 55 pages and 4,725 links. Isolated all-target/all-feature Clippy passed with `-D warnings`; formatting and whitespace are clean; `cargo deny` accepts the locked graph; `cargo about` and supplemental notices reproduce byte-for-byte. The OASIS SARIF 2.1.0 errata-01 fixture remains `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`. Runtime dependency pins are `cap-std`/`cap-fs-ext` 4.0.2, `cvss` 2.2.0, and `url` 2.5.8; the test-only `jsonschema` lock is 0.48.1. The checked dynamic-eval fixture has policy hash `5cf37a869e311d9c8c5c20dcb0c96dea81066eaa7be2109a2a87e602b55f6bbc` and cross-renderer finding ID `48f5e3d114587c05c1767f552ba1a41d4f39fd0bae0a41c54128328e93e848d8`; the CLI statuses are exactly `1,0,2,1,2,2,0,0`.

The handoff is now precise: #824 consumes only the stored resolved taint/typestate specs, selectors, endpoint dependencies, and crate-private adapter seam; it owns semantic binding, same-site dominance, compiled plan/protocol hashes, complete analysis-specific projection facts, and adaptation of #821/#822 results without reopening RQLP sources. #825 exercises the first TypeScript/Java cross-surface pilot and must prove internal/query/policy/report parity against this frozen public contract rather than adding a second policy model or renderer path.

Update this section after every milestone with observable behavior, exact validation evidence, accepted review findings, and any contract changes. At completion, record the implemented schema version, dependency versions, fixture hashes, CLI exit behavior, SARIF schema revision, and the precise #824/#825 handoff.

## Context and Orientation

### Terms

An S-expression is a parenthesized, whitespace-separated tree such as `(policy :id "example")`; vectors use square brackets, strings use JSON escaping, symbols are unquoted words, and `;` starts a comment. RQL is Bifrost's existing Rune Query Language for selecting code. RQLP is the separate policy language defined here; it embeds a versioned RQL tree but adds diagnostic identity and reporting semantics. An AST is the byte-spanned in-memory syntax tree produced by the shared parser.

Normalized authored JSON is the deterministic serialization of a parsed typed source while unresolved file/catalog/directory references still retain their authored form. Canonical semantic JSON is the one deterministic serialization of a fully loaded typed value after every dependency and selector has been resolved; only it is a semantic-hash input. A source hash covers the original bytes and therefore changes with comments or layout; a semantic hash covers canonical loaded meaning and therefore does not. Provenance is bounded evidence explaining where a result came from. A DTO is a private data-transfer record used only to serialize a standard wire shape.

An endpoint is a diagnostic-neutral, reusable source-or-sink model with one selector and one typed API/value binding. A category is an opaque exact identifier attached to endpoints for explicit set selection; it is not a hierarchy and does not itself imply taint, reachability, severity, or protocol behavior. A match-directory is an authored, capability-rooted dependency reference whose selected endpoint manifest becomes part of the aggregate policy's resolved meaning. A generated message is a closed renderer variant over a proven analysis relationship, not a string-template language and never an inference from match co-presence.

SARIF 2.1.0 is the OASIS JSON standard used by static-analysis consumers. CVSS v4.0 is FIRST's vulnerability-severity metric system; CWE is the MITRE weakness taxonomy. Neither CVSS nor CWE decides whether Bifrost found a policy violation. TTY means an interactive terminal, relevant only to optional color. TOCTOU means a time-of-check/time-of-use path race; the loader avoids it by validating and reading the same canonical regular-file target under a fixed workspace boundary.

The current RQL frontend lives in `src/analyzer/structural/query/`. `syntax.rs` owns the generic spanned S-expression AST/parser, `format.rs` formats generic documents, `sexp.rs` lowers a parsed RQL expression to canonical CodeQuery JSON, `schema.rs` owns visible query vocabulary, `source.rs` produces range-bearing diagnostics/help, and `ir.rs` defines the schema-version-2 typed recursive query plan. Move only generic concrete-syntax code to a shared internal module such as `src/sexp/{mod.rs,syntax.rs,format.rs}`; preserve the query module's public behavior and keep query and policy schema registries separate.

The query executor and public query rows live in `src/analyzer/structural/search.rs`. It executes a `CodeQuery` against an `IAnalyzer`, returns typed location-bearing values plus bounded provenance, and currently supplies `truncated` plus untyped diagnostic messages. Add stable diagnostic code/impact at emission sites before the policy adapter relies on this result. Public rows have already discarded some byte-authoritative internal evidence, so also add a crate-private detailed execution result whose evidence vector stays one-to-one with rendered rows and retains `ProjectFile`, result domain/key, byte span when present, stable declaration/owner identity when present, and a digest of the exact indexed source slice when available. Ordinary `execute` discards this evidence; policy evaluation consumes it from the same single execution. Do not create `impl From<CodeQueryResultItem> for PolicyFinding`; adaptation needs the policy definition, detailed execution evidence, workspace/source context, completion, and finding-identity builder.

The reusable path boundary begins in `src/tool_arguments.rs` and `src/searchtools_service.rs`. Extract a workspace-root capability backed by one opened `cap_std::fs::Dir`, then open every explicitly relative document through that handle. Reject absolute/prefix/root/parent components before open; `cap-std` prevents a followed symlink from escaping the directory capability on Linux, macOS, and Windows. Check regular-file metadata and perform the bounded read from that same open handle, which avoids a canonicalize-then-reopen race. Query files continue to use 64 KiB. Policy files use a separate 256 KiB cap, a maximum of 4,096 syntax nodes, 128 syntax depth, bounded strings/vectors/records, and the existing lower query-specific limits for every nested selector.

Add the public policy domain under `src/analyzer/policy/` and re-export its intended embedding types from `src/analyzer/mod.rs` and `src/lib.rs`:

    src/analyzer/policy/
      mod.rs
      definition.rs
      schema.rs
      source.rs
      loading.rs
      catalog.rs
      finding.rs
      identity.rs
      evaluator.rs
      classification.rs
      cvss.rs
      render/
        mod.rs
        human.rs
        sarif.rs

`definition.rs` contains authoring types only. `finding.rs` contains stable output types only. `evaluator.rs` owns context-requiring projection from diagnostic-neutral analysis into output. `catalog.rs` owns explicit content-addressed registration/composition. `render` consumes only `PolicyReportDocument`; it never receives raw query or solver rows.

The initial public type boundary is:

    enum RqlpDocument {
        Policy { definition: PolicyDefinition },
        Endpoint { definition: MatchEndpointDefinition },
    }

    struct PolicyDefinition {
        schema_version: PolicySchemaVersion,
        metadata: PolicyMetadata,
        analysis: PolicyAnalysis,
        classification: Option<PolicyClassificationSpec>,
        report: PolicyReportOptions,
    }

    enum PolicyAnalysis {
        Match { spec: MatchPolicySpec },
        Taint { spec: TaintPolicySpec },
        Typestate { spec: TypestatePolicySpec },
    }

    struct LoadedPolicy {
        definition: PolicyDefinition,
        source: PolicySourceIdentity,
        source_hash: PolicySourceHash,
        semantic_hash: PolicySemanticHash,
        schema_resolution: SchemaVersionResolution,
        resolved_selectors: Vec<ResolvedPolicySelector>,
        selector_origins: Vec<SelectorOrigin>,
        endpoint_dependencies: Vec<ResolvedEndpointDependency>,
        match_directory_manifests: Vec<ResolvedMatchDirectoryManifest>,
        precedence_manifest: PolicyPrecedenceManifest,
        resolved_taint: Option<ResolvedTaintPolicySpec>,
        resolved_typestate: Option<ResolvedTypestatePolicySpec>,
    }

    struct PolicyMetadata {
        id: PolicyId,
        name: String,
        message: PolicyMessageSpec,
        severity: PolicySeveritySpec,
        description: Option<String>,
        help_uri: Option<String>,
        tags: Vec<String>,
    }

    enum PolicyMessageSpec {
        Static { text: String },
        Generated { relation: GeneratedRelation },
    }

    enum GeneratedRelation { CanReach }

    enum PolicySeveritySpec {
        Fixed { level: PolicyLevel },
        Unrated,
        Cvss { when_unscored: FindingSeverity },
    }

    enum PolicyLevel { Note, Warning, Error }

    struct MatchPolicySpec { selector: PolicySelector }

    enum PolicySelector {
        Inline { schema: SchemaVersionResolution, query: CodeQuery },
        File {
            authored_schema_version: Option<u32>,
            path: WorkspaceRelativePath,
        },
    }

    enum SchemaVersionOrigin {
        Explicit,
        ImplicitCompatible,
        ReferencedDocumentExplicit,
    }

    struct SchemaVersionResolution {
        version: u32,
        origin: SchemaVersionOrigin,
    }

    struct ResolvedPolicySelector {
        path: PolicySelectorPath,
        schema_resolution: SchemaVersionResolution,
        query: CodeQuery,
        semantic_hash: ResolvedSelectorSemanticHash,
        origin: SelectorOrigin,
    }

    struct MatchEndpointDefinition {
        schema_version: PolicySchemaVersion,
        id: EndpointId,
        name: String,
        display_name: String,
        description: Option<String>,
        help_uri: Option<String>,
        role: EndpointRole,
        categories: Vec<PolicyCategoryId>,
        selector: PolicySelector,
        binding: PolicyEndpointBinding,
        taint: Option<EndpointTaintSemantics>,
        supersedes: Vec<EndpointId>,
    }

    enum EndpointRole { Source, Sink }

    enum PolicyEndpointBinding {
        MatchedValue,
        Receiver,
        ReturnValue,
        ArgumentIndex { index: u32 },
        ArgumentName { name: String },
    }

    enum EndpointTaintSemantics {
        Source {
            labels: Vec<TaintLabel>,
            evidence: Option<TaintSourceEvidence>,
        },
        Sink {
            accepts: Vec<TaintLabel>,
            tags: Vec<TaintTag>,
            impacts: Vec<TaintImpact>,
        },
    }

    struct LoadedEndpoint {
        definition: MatchEndpointDefinition,
        source: PolicySourceIdentity,
        source_hash: PolicySourceHash,
        semantic_hash: EndpointSemanticHash,
        schema_resolution: SchemaVersionResolution,
        resolved_selector: ResolvedPolicySelector,
    }

    struct ResolvedEndpointDependency {
        identity: ResolvedEndpointIdentity,
        definition_schema: EndpointDefinitionSchemaResolution,
        selector_path: PolicySelectorPath,
        selector_schema: SchemaVersionResolution,
        model: ResolvedEndpointModel,
        semantic_hash: EndpointSemanticHash,
        analysis_projection_hash: EndpointAnalysisProjectionHash,
        origins: Vec<EndpointOrigin>,
    }

    enum EndpointDefinitionSchemaResolution {
        PolicyDocument { resolution: SchemaVersionResolution },
        CatalogDocument { schema_version: u32 },
    }

    struct ResolvedEndpointModel {
        role: EndpointRole,
        display_name: String,
        categories: Vec<PolicyCategoryId>,
        binding: PolicyEndpointBinding,
        taint: Option<EndpointTaintSemantics>,
        supersedes: Vec<ResolvedEndpointIdentity>,
    }

    enum EndpointOrigin {
        PolicyLocal { path: PolicyDependencyPath },
        Catalog { catalog: ResolvedCatalogIdentity },
        ExactMatch {
            path: PolicyDependencyPath,
            source: PolicySourceIdentity,
        },
        MatchDirectory {
            path: PolicyDependencyPath,
            source: PolicySourceIdentity,
        },
    }

    enum ResolvedEndpointIdentity {
        Local { policy_id: PolicyId, entry_id: TaintEntryId },
        Catalog { catalog: ResolvedCatalogIdentity, entry_id: TaintEntryId },
        MatchEndpoint { endpoint_id: EndpointId },
    }

    struct ResolvedEndpointManifestEntry {
        identity: ResolvedEndpointIdentity,
        definition_schema: EndpointDefinitionSchemaResolution,
        selector_schema: SchemaVersionResolution,
        semantic_hash: EndpointSemanticHash,
        analysis_projection_hash: EndpointAnalysisProjectionHash,
    }

    struct ResolvedMatchDirectoryManifest {
        path: PolicyDependencyPath,
        directory: WorkspaceRelativePath,
        scope: DirectoryScope,
        role: Option<EndpointRole>,
        categories: CategoryPredicate,
        selected: Vec<ResolvedEndpointManifestEntry>,
        semantic_hash: MatchSetManifestHash,
    }

    struct PolicyPrecedenceManifest {
        edges: Vec<ResolvedPrecedenceEdge>,
    }

    enum ResolvedPrecedenceEdge {
        Endpoint {
            dominant: ResolvedEndpointIdentity,
            dominated: ResolvedEndpointIdentity,
        },
        FindingCombination {
            dominant: FindingCombinationId,
            dominated: FindingCombinationId,
        },
        TypestateEvent {
            dominant: TypestateEventId,
            dominated: TypestateEventId,
        },
        TypestateExpectation {
            dominant: TypestateExpectationId,
            dominated: TypestateExpectationId,
        },
    }

    struct PolicyReportOptions {
        witness: WitnessOptions,
        witnesses_per_finding: usize,
        origins_per_finding: usize,
    }

    struct WitnessOptions { max_steps: usize, max_bytes: usize }

`PolicySchemaVersion` resolves to integer `1` in this issue. Explicit other values are rejected before document decoding; omission resolves through the compatibility lineage above. `MayMode`, `InconclusivePolicy`, and `AnyOrAll` are all-unit enums with the only accepted spellings `may`, `inconclusive`, and `any|all`, respectively. `PolicySelectorPath` is a validated stable semantic path, not a dense handle: `/analysis/selector` for match selectors, `/analysis/{sources|sinks|sanitizers|transforms|external_models}/entries/ID/selector` for policy-local taint entries, `/endpoint/selector` inside an independently loaded endpoint, `/dependencies/match-endpoints/ENDPOINT-ID/selector` or `/dependencies/catalogs/CATALOG/ENTRY/selector` after composition into a policy, and stable resolved subject/event paths for typestate. `PolicyDependencyPath` uses the same escaped stable-path rules for catalog, exact-endpoint, match-directory, combination, event, and expectation fields; neither type is a filesystem path or hash input by itself. IDs are escaped with JSON Pointer escaping. `LoadedPolicy` has exactly one qualified resolved selector for every source-form selector and rejects missing/duplicate paths. Each dependency carries its definition-format resolution and selector resolution; match-directory manifest entries repeat those resolved versions as a transactional integrity record. Its sorted dependency, match-directory, and precedence manifests are complete provenance; semantic hashing projects resolved version numbers but not their origins or dependency paths. `resolved_taint` and `resolved_typestate` are `Some` exactly for successfully composed policies of those variants; a dependency, catalog, selector, precedence, or manifest failure prevents construction of `LoadedPolicy`. `PolicyMetadata` requires `PolicyId`, `name`, a valid `PolicyMessageSpec`, and `PolicySeveritySpec`; optional fields are `description`, an absolute HTTP(S) `help_uri`, and a duplicate-free set of tags. `Generated { CanReach }` is legal only for taint. A `PolicyId` is 1 through 200 ASCII bytes, begins and ends with a lowercase alphanumeric character, and otherwise permits lowercase alphanumeric characters plus `.`, `-`, and `_`. Preserve it as an opaque stable SARIF rule ID; do not derive behavior from dotted components. `EndpointId` uses the same grammar; `PolicyCategoryId` uses that grammar with a 128-byte cap and is an opaque exact identifier rather than a dotted-prefix hierarchy. `PolicyReportOptions` defaults to a 64-step/16-KiB bound per witness, eight witnesses, and eight origins per finding when the whole record or a field is omitted.

Fixed severity is `note`, `warning`, or `error`; `unrated` is allowed for a policy whose finding is intentionally not assigned a fixed level. `(cvss-severity :when-unscored unrated|note|warning|error)` derives the report level only from the selected complete assessment variant and uses the declared fallback when no complete variant exists. CVSS None or Low maps to policy/SARIF `note`, Medium maps to `warning`, and High or Critical maps to `error`. A complete all-None impact vector is a valid scored 0.0/None assessment and maps to `note`; it does not erase the policy finding. Analyzer certainty and organizational risk never alter severity implicitly. CLI thresholds order `note < warning < error`; `finding` additionally includes unrated, while a level threshold excludes unrated unless the policy supplied a rated `when-unscored` fallback.

A string `:message "..."` lowers to `PolicyMessageSpec::Static`. `(generated-message :relation can-reach)` lowers to the only schema-version-1 generated variant and is accepted only for taint; direct match and typestate policies reject it at the message range. Specific `finding-combination` messages are always static strings, so generated output has one fixed auditable relation rather than a template language.

### Authoring contract

Every selector uses one of these shapes:

    (rql
      (call :callee (name "eval")))

    (rql-file
      :path "queries/eval.rql")

Both may add `:schema-version N` as an exact pin. The inline form contains exactly one RQL query expression after its optional version pair. The file form accepts only the optional version and required path fields. Referenced paths resolve against the workspace root, not the policy directory or process working directory. Both lower once to typed `CodeQuery`; evaluation never reparses selector text. Policy validation rejects selector `limit` and `result-detail`, and it reports nested RQL errors at their original inline range or the external `.rql` source plus a related range on the reference token.

Successful inference is provenance, not a warning, and never affects completion or exit status. Normalized authored JSON emits every version already resolvable at parse time and preserves unresolved file/dependency references as authored references; canonical semantic JSON from the loaded model always emits resolved numeric policy and selector versions and contains no source-form selector discriminator. `SchemaVersionOrigin` is excluded from semantic hashes: explicit and omitted sources that resolve to the same versions have equal canonical semantics/hash but different source hashes and origins. Resolved version numbers remain semantic-hash inputs, so advancing an omitted source to a future compatible lineage head deliberately makes runtime drift visible. Human output prints one concise schema-resolution note when anything was inferred; canonical semantic JSON and SARIF rule properties carry the path-sorted resolution manifest. `--require-explicit-schema-versions` rejects any remaining `ImplicitCompatible` policy/selector resolution before evaluation with status 2. Formatting preserves omission; hover explains the inferred version and offers an exact pin.

A reusable human-authored endpoint leaf is:

    (endpoint
      :id "bifrost.sources.http-request-parameter"
      :name "HTTP request parameter"
      :display-name "User-controlled I/O"
      :role source
      :categories [input.user-controlled io.external]
      :selector
        (rql
          (call :callee (name "requestParameter")))
      :binding return-value
      :taint
        (source-semantics
          :labels [attacker-controlled]
          :evidence
            (evidence :trust-boundary external))
      :supersedes [])

The sink form has `:role sink`, an exact matched-value/receiver/return/argument binding, and optional `(sink-semantics :accepts [...] :tags [...] :impacts [...])`. Role and taint-semantics variant must agree. Source labels and sink accepts are required when taint semantics is present; typestate-only endpoints may omit taint semantics. `display-name` is a bounded phrase used verbatim in generated messages. Categories are sorted/deduplicated exact identifiers. `supersedes` is a sorted duplicate-free endpoint-ID set; the selected endpoint universe must contain every referenced ID and be acyclic. The endpoint semantic hash covers the entire normalized loaded definition: resolved schema and selector versions, identity/reporting fields, role, canonical selector, binding, categories, taint semantics, and supersedes. Its separate analysis-projection hash covers only resolved query semantics, role, typed binding, taint transfer semantics, and behavior-bearing supersedes declarations; it excludes names, display/description/help text, categories, source bytes, filesystem identity, and directory provenance. Category changes may alter which endpoints a policy selects and therefore its resolved policy hash, but cannot invalidate a solver summary when the selected analysis projections are otherwise identical.

A taint policy is set-oriented:

    (policy
      :schema-version 1
      :id "bifrost.security.untrusted-sql"
      :name "Untrusted data reaches SQL structure"
      :message (generated-message :relation can-reach)
      :severity (cvss-severity :when-unscored unrated)
      :analysis
        (analysis
          :type taint
          :mode may
          :sources
            (endpoint-set
              :include-matches [
                (match-directory
                  :path "policies/endpoints"
                  :scope recursive
                  :categories (all [input.user-controlled]))]
              :include-sets [
                (catalog
                  :name "bifrost.sources.attacker-controlled"
                  :version 1)]
              :entries [
                (source
                  :id "http-request-parameter"
                  :display-name "User-controlled HTTP input"
                  :categories [input.user-controlled io.external]
                  :selector
                    (rql :schema-version 2
                      (call :callee (name "requestParameter")))
                  :bind return-value
                  :labels [attacker-controlled]
                  :evidence
                    (evidence
                      :trust-boundary external
                      :system-entry vulnerable-system-network-stack))])
          :sinks
            (endpoint-set
              :include-matches [
                (match-directory
                  :path "policies/endpoints"
                  :scope recursive
                  :categories (all [data.sensitive]))]
              :include-sets [
                (catalog
                  :name "bifrost.sinks.persistent-data-write"
                  :version 1)]
              :entries [
                (sink
                  :id "sql-execute"
                  :display-name "SQL structure"
                  :categories [data.persistent sql.structure]
                  :selector
                    (rql :schema-version 2
                      (call :callee (name "execute")))
                  :dangerous-operand (argument :index 0)
                  :accepts [attacker-controlled]
                  :tags [security-sensitive sql-execution]
                  :impacts [vulnerable-system-integrity])])
          :finding-combinations [
            (finding-combination
              :id "user-input-to-sql"
              :source (categories :all [input.user-controlled])
              :sink (categories :all [sql.structure])
              :message "User-controlled input can alter SQL structure"
              :severity error
              :supersedes [])]
          :sanitizers
            (endpoint-set
              :include-sets [
                (catalog :name "bifrost.sanitizers.default" :version 1)]))
      :classification
        (classification
          :fallback
            (classification-id
              :taxonomy "bifrost"
              :id "untrusted-data-to-sensitive-operation")
          :refinements [
            (refinement
              :when (sink-tags :all [sql-execution])
              :add [
                (classification-id
                  :taxonomy "CWE"
                  :id "CWE-89")])]
          :cvss
            (cvss
              :version "4.0"
              :emit when-base-complete
              :metric-rules [
                (metric
                  :name AV
                  :value N
                  :when
                    (source-evidence
                      :system-entry vulnerable-system-network-stack)
                  :basis policy-assertion
                  :scope vulnerable-system
                  :evidence-refs [
                    (endpoint-ref :local "http-request-parameter")]
                  :rationale "The vulnerable system receives the input through its network stack")]))
      :report
        (report
          :witness (witness :max-steps 64 :max-bytes 16384)
          :origins-per-finding 8))

The schema-version-1 taint types are exact rather than placeholders:

    struct TaintPolicySpec {
        mode: MayMode,
        sources: TaintEndpointSet<TaintSourceSpec>,
        sinks: TaintEndpointSet<TaintSinkSpec>,
        sanitizers: TaintEndpointSet<TaintSanitizerSpec>,
        transforms: TaintEndpointSet<TaintTransformSpec>,
        external_models: TaintEndpointSet<TaintExternalModelSpec>,
        finding_combinations: Vec<FindingCombinationSpec>,
    }

    struct TaintEndpointSet<T> {
        include_sets: Vec<CatalogRef>,
        include_matches: Vec<MatchEndpointSetRef>,
        entries: Vec<T>,
    }

    enum MatchEndpointSetRef {
        Directory { reference: MatchDirectoryRef },
        Exact { endpoint_ids: Vec<EndpointId> },
    }

An exact endpoint ID resolves only against the immutable endpoint index already populated through an explicit `load_endpoint_path`/`register_endpoint_bytes` call or another authored directory dependency in the same transactional closure. It never causes an ID-to-file search. The one-shot CLI therefore uses `match-directory` for filesystem model packs unless an embedding pre-registers exact endpoints; an unknown exact ID is a deterministic load error.

    struct MatchDirectoryRef {
        path: WorkspaceRelativePath,
        scope: DirectoryScope,
        categories: CategoryPredicate,
        manifest_sha256: Option<MatchSetManifestHash>,
    }

    enum DirectoryScope { Direct, Recursive }

    enum CategoryPredicate {
        Any { categories: Vec<PolicyCategoryId> },
        All { categories: Vec<PolicyCategoryId> },
    }

    struct FindingCombinationSpec {
        id: FindingCombinationId,
        source: EndpointPredicate,
        sink: EndpointPredicate,
        message: String,
        severity: Option<PolicySeveritySpec>,
        add_classifications: Vec<TaxonomyClassificationSpec>,
        supersedes: Vec<FindingCombinationId>,
    }

    enum EndpointPredicate {
        Categories { predicate: CategoryPredicate },
        Exact { endpoints: Vec<EndpointRef> },
    }

    enum EndpointRef {
        Local { entry_id: TaintEntryId },
        Catalog { catalog: CatalogRef, entry_id: TaintEntryId },
        MatchEndpoint { endpoint_id: EndpointId },
    }

    enum PolicyPort {
        MatchedValue,
        Receiver,
        ReturnValue,
        ArgumentIndex { index: u32 },
        ArgumentName { name: String },
    }

    struct TaintSourceSpec {
        id: TaintEntryId,
        display_name: String,
        categories: Vec<PolicyCategoryId>,
        selector: PolicySelector,
        bind: PolicyPort,
        labels: Vec<TaintLabel>,
        evidence: Option<TaintSourceEvidence>,
    }

    struct TaintSourceEvidence {
        trust_boundary: Option<TaintTrustBoundary>,
        system_entry: Option<TaintSystemEntry>,
    }

    enum TaintTrustBoundary { External, Internal, SameTrustZone }

    enum TaintSystemEntry {
        VulnerableSystemNetworkStack,
        DownloadedArtifact,
        LocalInput,
        AdjacentNetwork,
        Physical,
    }

    struct TaintSinkSpec {
        id: TaintEntryId,
        display_name: String,
        categories: Vec<PolicyCategoryId>,
        selector: PolicySelector,
        dangerous_operand: PolicyPort,
        accepts: Vec<TaintLabel>,
        tags: Vec<TaintTag>,
        impacts: Vec<TaintImpact>,
    }

    struct TaintSanitizerSpec {
        id: TaintEntryId,
        selector: PolicySelector,
        input: PolicyPort,
        output: PolicyPort,
        removes: Vec<TaintLabel>,
    }

    struct TaintTransformSpec {
        id: TaintEntryId,
        selector: PolicySelector,
        input: PolicyPort,
        output: PolicyPort,
        removes: Vec<TaintLabel>,
        adds: Vec<TaintLabel>,
    }

    struct TaintExternalModelSpec {
        id: TaintEntryId,
        selector: PolicySelector,
        transfers: Vec<TaintTransferSpec>,
    }

    struct TaintTransferSpec {
        from: PolicyPort,
        to: PolicyPort,
        labels: Vec<TaintLabel>,
        effect: TaintTransferEffect,
    }

    enum TaintTransferEffect {
        Propagate,
        Sanitize { removes: Vec<TaintLabel> },
        Transform { removes: Vec<TaintLabel>, adds: Vec<TaintLabel> },
    }

`PolicyPort` is written as `matched-value`, `receiver`, `return-value`, `(argument :index N)`, or `(argument :name "NAME")`; an argument record contains exactly one of index or name, and indexes are zero-based. `matched-value` binds the location-bearing value selected directly by non-call RQL and remains subject to #824's typed selector-domain validation. It is valid for source/sink/sanitizer/transform selectors but rejected in an `external-model` transfer, whose ports describe a call signature. The remaining entry signatures are:

    (sanitizer
      :id "sql-escape"
      :selector (rql :schema-version 2 QUERY)
      :input (argument :index 0)
      :output return-value
      :removes [attacker-controlled])

    (transform
      :id "decode"
      :selector (rql :schema-version 2 QUERY)
      :input (argument :index 0)
      :output return-value
      :removes [encoded]
      :adds [attacker-controlled])

    (external-model
      :id "library-copy"
      :selector (rql :schema-version 2 QUERY)
      :transfers [
        (transfer
          :from (argument :index 0)
          :to return-value
          :labels [attacker-controlled]
          :effect propagate)
        (transfer
          :from receiver
          :to return-value
          :labels [secret]
          :effect (sanitize :removes [secret]))])

The `sources` and `sinks` fields are syntactically required; `sanitizers`, `transforms`, and `external-models` default to empty endpoint sets when omitted. `include-sets`, `include-matches`, and `entries` default to empty within a present endpoint set. Match-directory references are legal only for source/sink sets in schema version 1; sanitizer, transform, and external-model composition remains catalog/local. A match endpoint selected into a taint source set must have `role source` plus non-empty source semantics, and one selected into a sink set must have `role sink` plus non-empty sink semantics. A role mismatch or typestate-only endpoint with omitted taint semantics fails the aggregate load as `EndpointMissingOrMismatchedTaintSemantics`; it is never silently filtered after satisfying the authored ID/category predicate. Source labels, sink accepts, sanitizer removes, external-model transfers, and transfer labels are non-empty. Local/catalog source and sink entries require a bounded `display_name` and categories so they participate in the same generated-message and combination algebra as endpoint leaves. A transform requires at least one value across removes/adds, and a transfer effect's remove/add rules have the same constraint. Every vector is duplicate-free after typed normalization. `TaintSourceEvidence` has optional `trust_boundary` (`external`, `internal`, or `same-trust-zone`) and `system_entry` (`vulnerable-system-network-stack`, `downloaded-artifact`, `local-input`, `adjacent-network`, or `physical`); at least one field is required. These facts are evidence inputs, not automatic CVSS metric values.

`FindingCombinationSpec` is presentation/classification policy over actual structured meetings, not a second flow-analysis plan. Each source/sink predicate resolves during loading to finite endpoint-identity sets. A matching explicit combination always beats the implicit policy default. Explicit combinations form an acyclic `supersedes` graph; if one actual permitted pair is covered by multiple non-dominated rules, loading fails with `AmbiguousCombinationPrecedence`. The winning rule replaces the generic message/severity/classification additions before grouping and report truncation. The generated `can-reach` default renders the two endpoint `display_name` values verbatim. It never infers a message from a category ID, never suppresses an independent policy, and never reports mere source/sink co-presence as reachability.

These remain authoring declarations, not serialized `TaintAnalysisPlan` rows. #709 owns their syntax, typed normalization, endpoint/category/catalog identity and composition, explicit presentation precedence, generated messages, and generic classification/CVSS output algebra. #824 owns semantic selector/binding resolution, same-site endpoint dominance, conversion of these declarations and resolved dependencies into #821's one seed/observer plan, analysis-specific projection evidence, and adaptation of solver findings into the #709 output types.

Catalog references contain a name using the `PolicyId` spelling/200-byte bound, a version from 1 through `u32::MAX`, and an optional lowercase 64-hex `:sha256` pin. Canonical catalog JSON is the Serde form of `TaintCatalogDefinition { schema_version: 1, name, version, sources, sinks, sanitizers, transforms, external_models }`; those are the only top-level keys, and every endpoint-array key is required (an unused category is `[]`). Catalog source/sink records include `display_name` and categories. A selector is exactly `{ "type": "inline", "schema_version": 2, "query": CANONICAL_CODE_QUERY }`; catalogs cannot contain `include_sets`, `include_matches`, `rql-file`, or a file selector. Because `PolicyPort` has data-bearing argument variants, every port is tagged: `{ "type": "matched_value" }`, `{ "type": "receiver" }`, `{ "type": "return_value" }`, `{ "type": "argument_index", "index": N }`, or `{ "type": "argument_name", "name": "NAME" }`. Transfer effects use `{ "type": "propagate" }`, `{ "type": "sanitize", "removes": [...] }`, or `{ "type": "transform", "removes": [...], "adds": [...] }`. All other keys are the snake-case names of the exact Rust fields above, and all-unit enums are snake-case strings. At least one endpoint array is non-empty. JSON registration rejects unknown/duplicate object keys before typed decoding, then hashes canonical typed JSON rather than the supplied byte layout. The JSON byte API accepts at most 4 MiB and only explicit `.json` workspace paths; typed registration enforces the same entry/registry counts. Composition sorts by stable identity, rejects duplicate entry IDs with different semantic hashes, accepts semantically identical repeat registration idempotently, and records every resolved catalog version/hash. After expansion, sources and sinks must both be non-empty. A three-source/four-sink fixture resolves to one `ResolvedTaintPolicySpec`; no #709 type contains or implies twelve pair plans.

    struct ResolvedTaintEndpoint<T> {
        identity: ResolvedEndpointIdentity,
        semantic_hash: EndpointSemanticHash,
        analysis_projection_hash: EndpointAnalysisProjectionHash,
        definition: T,
        origins: Vec<EndpointOrigin>,
    }

    struct ResolvedTaintPolicySpec {
        mode: MayMode,
        sources: Vec<ResolvedTaintEndpoint<ResolvedTaintSourceDefinition>>,
        sinks: Vec<ResolvedTaintEndpoint<ResolvedTaintSinkDefinition>>,
        sanitizers: Vec<TaintSanitizerSpec>,
        transforms: Vec<TaintTransformSpec>,
        external_models: Vec<TaintExternalModelSpec>,
        catalogs: Vec<ResolvedCatalogIdentity>,
        match_manifests: Vec<ResolvedMatchDirectoryManifest>,
        finding_combinations: Vec<ResolvedFindingCombination>,
    }

    struct ResolvedTaintSourceDefinition {
        display_name: String,
        categories: Vec<PolicyCategoryId>,
        selector_path: PolicySelectorPath,
        bind: PolicyPort,
        labels: Vec<TaintLabel>,
        evidence: Option<TaintSourceEvidence>,
    }

    struct ResolvedTaintSinkDefinition {
        display_name: String,
        categories: Vec<PolicyCategoryId>,
        selector_path: PolicySelectorPath,
        dangerous_operand: PolicyPort,
        accepts: Vec<TaintLabel>,
        tags: Vec<TaintTag>,
        impacts: Vec<TaintImpact>,
    }

    struct ResolvedFindingCombination {
        id: FindingCombinationId,
        source_endpoints: Vec<ResolvedEndpointIdentity>,
        sink_endpoints: Vec<ResolvedEndpointIdentity>,
        message: String,
        severity: Option<PolicySeveritySpec>,
        add_classifications: Vec<TaxonomyClassificationSpec>,
        supersedes: Vec<FindingCombinationId>,
    }

Each resolved endpoint vector is the stable-identity-sorted union of local, catalog, and selected endpoint leaves and contains no unresolved catalog/directory reference. Loading normalizes all three source forms into `ResolvedTaintSourceDefinition`/`ResolvedTaintSinkDefinition`: endpoint `PolicyEndpointBinding` converts exhaustively to the equal `PolicyPort` variant, its selector is re-keyed into `LoadedPolicy.resolved_selectors`, and its taint semantics populate the required labels/accepts/evidence/tags/impacts fields. No ID is coerced into `TaintEntryId`; identity remains the enclosing `ResolvedEndpointIdentity`. Selecting the same ID/hash through overlapping directory references is idempotent and retains bounded multi-origin provenance; same ID/different hash is a collision, while duplicate endpoint IDs within one scanned collection are errors even for identical bytes. Combination predicates are replaced by sorted finite identity sets, while their presentation and supersedes edges remain intact. The resolved endpoint definitions in `ResolvedTaintPolicySpec`/`ResolvedTypestatePolicySpec`, together with `LoadedPolicy.resolved_selectors` and the dependency manifests, supply every already lowered `CodeQuery`, typed binding, category/display phrase, schema resolution, and origin. This keeps source diagnostics intact without asking #824 to reopen, rescan, or reparse a file.

A typestate policy is author-facing and deliberately not #822's internal protocol:

    (policy
      :schema-version 1
      :id "bifrost.test.resource-lifecycle"
      :name "Resource lifecycle"
      :message "Resource is used outside its open lifecycle"
      :severity error
      :analysis
        (analysis
          :type typestate
          :mode may
          :subjects
            (subject-set
              :include-matches [
                (match-directory
                  :path "policies/endpoints/resources"
                  :scope recursive
                  :categories (all [resource.acquire]))]
              :entries [])
          :uncertainty
            (uncertainty
              :unknown-call inconclusive
              :escape inconclusive)
          :automaton
            (automaton
              :states [open closed error]
              :initial open
              :accepting-states [closed]
              :error-states [error]
              :events [
                (event
                  :id use
                  :matches
                    (match-directory
                      :path "policies/endpoints/resources"
                      :scope recursive
                      :role sink
                      :phase before-call
                      :categories (all [resource.use])))
                (event
                  :id close
                  :matches
                    (match-directory
                      :path "policies/endpoints/resources"
                      :scope recursive
                      :role sink
                      :phase after-normal-return
                      :categories (all [resource.close])))]
              :transitions [
                (transition :from open :on use :to open)
                (transition :from open :on close :to closed)
                (transition :from closed :on use :to error)]
              :terminal-expectations [
                (terminal-expectation
                  :id close-reaches-closed
                  :matches
                    (match-directory
                      :path "policies/endpoints/resources"
                      :scope recursive
                      :role sink
                      :phase after-normal-return
                      :categories (all [resource.close]))
                  :expected-states [closed])
                (terminal-expectation
                  :id normal-exit-closed
                  :on (normal-procedure-exit :scope analysis-root)
                  :expected-states [closed])
                (terminal-expectation
                  :id exceptional-exit-closed
                  :on (exceptional-procedure-exit :scope analysis-root)
                  :expected-states [closed])])))

The schema-version-1 typestate types are:

    struct TypestatePolicySpec {
        mode: MayMode,
        subjects: TypestateSubjectSet,
        uncertainty: TypestateUncertaintySpec,
        automaton: TypestateAutomatonSpec,
    }

    struct TypestateSubjectSet {
        include_matches: Vec<MatchEndpointSetRef>,
        entries: Vec<TypestateSubjectSpec>,
    }

    struct TypestateSubjectSpec {
        id: TaintEntryId,
        selector: PolicySelector,
        subject: TypestateSeedBinding,
    }

    enum TypestateSeedBinding {
        MatchedValue,
        Receiver,
        ReturnValue,
        ArgumentIndex { index: u32 },
        ArgumentName { name: String },
    }

    struct TypestateUncertaintySpec {
        unknown_call: InconclusivePolicy,
        escape: InconclusivePolicy,
    }

    struct TypestateAutomatonSpec {
        states: Vec<TypestateStateId>,
        initial: TypestateStateId,
        accepting_states: Vec<TypestateStateId>,
        error_states: Vec<TypestateStateId>,
        events: Vec<TypestateEventSpec>,
        transitions: Vec<TypestateTransitionSpec>,
        terminal_expectations: Vec<TypestateTerminalExpectationSpec>,
    }

    struct TypestateEventSpec {
        id: TypestateEventId,
        trigger: TypestateEventTrigger,
        applies_to_subjects: Option<EndpointPredicate>,
        supersedes: Vec<TypestateEventId>,
    }

    enum TypestateEventTrigger {
        Calls {
            selector: PolicySelector,
            subject: TypestateCallBinding,
            phase: EndpointObservationPhase,
        },
        MatchEndpoints {
            set: MatchEndpointSetRef,
            role: EndpointRole,
            phase: EndpointObservationPhase,
        },
        SemanticEvent { event: PolicySemanticEvent },
    }

    enum TypestateCallBinding {
        Receiver,
        ReturnValue,
        ArgumentIndex { index: u32 },
        ArgumentName { name: String },
    }

    enum PolicySemanticEvent {
        NormalProcedureExit { scope: TypestateExitScope },
        ExceptionalProcedureExit { scope: TypestateExitScope },
    }

    enum TypestateExitScope { AnalysisRoot }

    struct TypestateTransitionSpec {
        from: TypestateStateId,
        on: TypestateEventId,
        to: TypestateStateId,
    }

    struct TypestateTerminalExpectationSpec {
        id: TypestateExpectationId,
        trigger: TypestateTerminalTrigger,
        applies_to_subjects: Option<EndpointPredicate>,
        expected_states: Vec<TypestateStateId>,
        supersedes: Vec<TypestateExpectationId>,
    }

    enum TypestateTerminalTrigger {
        MatchEndpoints {
            set: MatchEndpointSetRef,
            role: EndpointRole,
            phase: EndpointObservationPhase,
        },
        SemanticEvent { event: PolicySemanticEvent },
    }

    enum EndpointObservationPhase {
        AtMatch,
        BeforeCall,
        AfterNormalReturn,
        AfterExceptionalReturn,
    }

    struct ResolvedTypestatePolicySpec {
        mode: MayMode,
        subjects: Vec<ResolvedTypestateSubject>,
        uncertainty: TypestateUncertaintySpec,
        automaton: ResolvedTypestateAutomatonSpec,
        endpoint_dependencies: Vec<ResolvedEndpointDependency>,
        match_manifests: Vec<ResolvedMatchDirectoryManifest>,
        authoring_projection_hash: TypestateAuthoringProjectionHash,
    }

    struct ResolvedTypestateSubject {
        identity: ResolvedEndpointIdentity,
        selector_path: PolicySelectorPath,
        binding: ResolvedTypestateBinding,
        semantic_hash: EndpointSemanticHash,
        analysis_projection_hash: EndpointAnalysisProjectionHash,
        origins: Vec<EndpointOrigin>,
    }

    enum ResolvedTypestateBinding {
        MatchedValue,
        Receiver,
        ReturnValue,
        ArgumentIndex { index: u32 },
        ArgumentName { name: String },
    }

    struct ResolvedTypestateAutomatonSpec {
        states: Vec<TypestateStateId>,
        initial: TypestateStateId,
        accepting_states: Vec<TypestateStateId>,
        error_states: Vec<TypestateStateId>,
        events: Vec<ResolvedTypestateEventSpec>,
        transitions: Vec<TypestateTransitionSpec>,
        terminal_expectations: Vec<ResolvedTypestateTerminalExpectationSpec>,
    }

    struct ResolvedTypestateEventSpec {
        id: TypestateEventId,
        trigger: ResolvedTypestateEventTrigger,
        applies_to_subjects: Vec<ResolvedEndpointIdentity>,
        supersedes: Vec<TypestateEventId>,
    }

    enum ResolvedTypestateEventTrigger {
        Calls {
            selector_path: PolicySelectorPath,
            subject: TypestateCallBinding,
            phase: EndpointObservationPhase,
        },
        MatchEndpoints {
            endpoints: Vec<ResolvedEndpointIdentity>,
            phase: EndpointObservationPhase,
        },
        SemanticEvent { event: PolicySemanticEvent },
    }

    struct ResolvedTypestateTerminalExpectationSpec {
        id: TypestateExpectationId,
        trigger: ResolvedTypestateTerminalTrigger,
        applies_to_subjects: Vec<ResolvedEndpointIdentity>,
        expected_states: Vec<TypestateStateId>,
        supersedes: Vec<TypestateExpectationId>,
    }

    enum ResolvedTypestateTerminalTrigger {
        MatchEndpoints {
            endpoints: Vec<ResolvedEndpointIdentity>,
            phase: EndpointObservationPhase,
        },
        SemanticEvent { event: PolicySemanticEvent },
    }

The subject set identifies newly tracked values through endpoint-source models or local selectors. A local seed uses one concrete matched-value/receiver/return/argument `TypestateSeedBinding`; a direct `Calls` event uses the narrower receiver/return/argument `TypestateCallBinding`. `tracked-object` is not an authoring binding because a seed has no prior object and a call site may carry several tracked objects. Semantic events and terminal observations operate on the already bound current subject implicitly. Endpoint events inherit the selected `ResolvedEndpointDependency.model.binding` and its selector path, and forbid a second subject field. `applies_to_subjects` resolves to finite source endpoint sets, so one aggregate can express known source/sink API pairs without scheduling one solver run per pair. Schema version 1 requires both uncertainty fields and accepts only `inconclusive`, making unknown calls and escapes explicit capability gaps rather than soundness assumptions. State, event, and expectation IDs are 1 through 128 ASCII bytes using lowercase alphanumerics, `-`, and `_`. States/events/expectations are duplicate-free; `initial`, accepting/error/expected/transition states are declared; accepting and error sets are disjoint and non-empty; every terminal `expected_states` set is non-empty and a subset of `accepting_states`; every event has exactly one direct selector, endpoint set, or semantic event; every transition references declared values; and `(from, event)` is unique. Accepting states are expectation labels, not absorbing or automatically terminal states: tracking continues and later transitions may leave an accepting state or enter an error state.

Endpoint and direct-call observations are typed. `matched-value` permits only `at-match`; receiver/argument bindings permit `before-call`, `after-normal-return`, or `after-exceptional-return`; a return-value binding permits only `after-normal-return`. A direct non-call selector uses `at-match`, while a direct `Calls` trigger authors the same phase field as an endpoint call trigger. At one observation, the unique applicable protocol transition is applied first and terminal expectations at that same phase inspect the resulting state; this lets a successful `close` transition to `closed` before an `after-normal-return` expectation checks it. Normal and exceptional continuations are never conflated, and an unavailable continuation/binding makes evaluation inconclusive rather than choosing another phase.

`normal-procedure-exit` and `exceptional-procedure-exit` require `:scope analysis-root` in schema version 1. The analysis root is the outer demand procedure under which #824 tracks that subject/scenario; helper and factory returns are interprocedural transfers, not terminal observations. Multiple roots produce distinct semantic scenarios. If the subject escapes beyond a root or the adapter cannot distinguish completion kind, the configured uncertainty rule makes the run inconclusive. A current state outside `expected_states` produces a diagnostic-neutral `TerminalExpectationViolation { expectation_id, terminal, observed_state, expected_states }`, distinct from `ErrorTransition { event_id, from, to }`.

`ResolvedTypestatePolicySpec.authoring_projection_hash` covers the normalized endpoint sets, bindings, phases, exit scopes, pair restrictions, automaton, expectations, and declared supersedes edges before semantic matching. It is a policy-composition integrity hash, never a protocol/summary/finding key. #824 resolves semantic event/binding classes, proves same-site dominance, remaps every dominated identity in subject/event/expectation sets and pair restrictions to its unique live winner, deduplicates those finite sets, and only then computes `TypestateBindingPlanHash` and lowers #822's protocol. Endpoints proved semantically distinct both remain live; inability to decide equivalence makes the analysis inconclusive, while multiple live winners make compilation fail. Protocol/summary keys contain the compiled protocol hash, compiled binding-plan hash, matcher/compiler version, workspace/analyzer snapshot, solver configuration, and completeness-affecting semantics. They exclude the authoring projection hash, categories, directory paths, display names, messages, severity, and classifications. This work consumes only the stored resolved spec, selectors, and dependency models; it never reopens, rescans, or reparses a file.

Classification authoring also has a complete public shape:

    struct PolicyClassificationSpec {
        fallback: TaxonomyClassificationSpec,
        refinements: Vec<ClassificationRefinementSpec>,
        cvss: Option<CvssPolicySpec>,
    }

    struct ClassificationRefinementSpec {
        when: ClassificationPredicate,
        add: Vec<TaxonomyClassificationSpec>,
    }

    struct TaxonomyClassificationSpec {
        taxonomy: String,
        identifier: String,
        name: Option<String>,
    }

    enum ClassificationPredicate {
        All { predicates: Vec<ClassificationPredicate> },
        Any { predicates: Vec<ClassificationPredicate> },
        AnalysisType { analysis_type: PolicyAnalysisType },
        SourceCategories { quantifier: AnyOrAll, values: Vec<PolicyCategoryId> },
        SinkCategories { quantifier: AnyOrAll, values: Vec<PolicyCategoryId> },
        SourceLabels { quantifier: AnyOrAll, values: Vec<TaintLabel> },
        SinkTags { quantifier: AnyOrAll, values: Vec<TaintTag> },
        SinkImpacts { quantifier: AnyOrAll, values: Vec<TaintImpact> },
        FindingCombination { id: FindingCombinationId },
        TypestateExpectation { id: TypestateExpectationId },
    }

    struct CvssPolicySpec {
        version: CvssVersion,
        emit: CvssEmitPolicy,
        metric_rules: Vec<CvssMetricRule>,
    }

    enum CvssVersion { V4_0 }

    enum CvssEmitPolicy { WhenBaseComplete }

    struct CvssMetricRule {
        metric: CvssBaseMetric,
        value: CvssMetricValue,
        when: CvssEvidencePredicate,
        basis: PolicyCvssBasis,
        scope: CvssEvidenceScope,
        evidence_refs: Vec<PolicyEvidenceRef>,
        rationale: String,
        assumptions: Vec<String>,
    }

    enum CvssEvidencePredicate {
        All { predicates: Vec<CvssEvidencePredicate> },
        Any { predicates: Vec<CvssEvidencePredicate> },
        AnalysisType { analysis_type: PolicyAnalysisType },
        SourceEvidence { evidence: TaintSourceEvidence },
        SourceCategories { quantifier: AnyOrAll, values: Vec<PolicyCategoryId> },
        SinkCategories { quantifier: AnyOrAll, values: Vec<PolicyCategoryId> },
        SourceLabels { quantifier: AnyOrAll, values: Vec<TaintLabel> },
        SinkTags { quantifier: AnyOrAll, values: Vec<TaintTag> },
        SinkImpacts { quantifier: AnyOrAll, values: Vec<TaintImpact> },
    }

    enum PolicyCvssBasis { PolicyAssertion }

    enum CvssSystemScope { VulnerableSystem, SubsequentSystem }

    enum CvssEvidenceScope { Global, System { system: CvssSystemScope } }

    enum CvssBaseMetric { AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA }

    enum CvssThreatMetric { E }

    enum CvssEnvironmentalOrSupplementalMetric {
        CR, IR, AR, MAV, MAC, MAT, MPR, MUI, MVC, MVI, MVA, MSC, MSI, MSA,
        S, AU, R, V, RE, U,
    }

    enum CvssMetric {
        Base { metric: CvssBaseMetric },
        Threat { metric: CvssThreatMetric },
        EnvironmentalOrSupplemental {
            metric: CvssEnvironmentalOrSupplementalMetric,
        },
    }

    struct CvssMetricValue {
        metric: CvssMetric,
        token: CvssMetricValueToken,
    }

    enum CvssMetricValueToken {
        X, N, A, L, P, H, M, U, S, Y, I, D, C,
        Clear, Green, Amber, Red,
    }

    enum PolicyEvidenceRef {
        PolicySelf,
        Endpoint { endpoint: EndpointRef },
        Selector { path: PolicySelectorPath },
    }

`TaxonomyClassificationSpec` is `(classification-id :taxonomy "NAME" :id "IDENTIFIER" [:name "DISPLAY NAME"])`. Predicate spellings are `(all [PREDICATE...])`, `(any [PREDICATE...])`, `(analysis-type :is match|taint|typestate)`, `(source-categories :any|all [...])`, `(sink-categories :any|all [...])`, `(source-labels :any|all [...])`, and the same quantified forms for `sink-tags` and `sink-impacts`; exact selected finding-combination and typestate-expectation IDs are also available. Every `all`/`any` predicate vector, quantified values vector, refinement `add` vector, and CVSS metric rule vector is non-empty and duplicate-free; empty forms fail at the vector range, so schema version 1 has no vacuous-truth or no-op refinement cases. Each quantified record contains exactly one of `:any` or `:all`. Declared refinements run in source order, every matching refinement adds classifications, and the result is deduplicated and sorted by taxonomy/identifier. Omitting the entire classification record produces the explicit output variant `FindingClassification::Unclassified`; it does not invent a default taxonomy. #709 implements only this generic evidence projection. #824 supplies complete endpoint-pair/typestate projection facts that make the predicates decidable without categories entering solver state.

Schema version 1 accepts only CVSS version `"4.0"`, emit policy `when-base-complete`, and authoring basis `policy-assertion`. Authorable rules accept exactly the eleven `CvssBaseMetric` names; Threat, Environmental/Modified, and Supplemental metrics are evaluation-context-only in this version. The metric enums serialize as their exact uppercase FIRST names rather than snake case. `CvssMetricValue` has private fields and `try_new(metric, token)` validates this complete legality table; the stable wire value is the exact token shown:

| Metric | Legal values |
| --- | --- |
| `AV` | `N A L P` |
| `AC` | `L H` |
| `AT` | `N P` |
| `PR` | `N L H` |
| `UI` | `N P A` |
| `VC VI VA SC SI SA` | `H L N` |
| `E` | `X A P U` |
| `CR IR AR` | `X H M L` |
| `MAV` | `X N A L P` |
| `MAC` | `X L H` |
| `MAT` | `X N P` |
| `MPR` | `X N L H` |
| `MUI` | `X N P A` |
| `MVC MVI MVA MSC` | `X H L N` |
| `MSI MSA` | `X S H L N` |
| `S` | `X N P` |
| `AU` | `X N Y` |
| `R` | `X A U I` |
| `V` | `X D C` |
| `RE` | `X L M H` |
| `U` | `X Clear Green Amber Red` |

Metric scope is validated rather than trusted: `AV/AC/AT/PR/UI/VC/VI/VA` and `MAV/MAC/MAT/MPR/MUI/MVC/MVI/MVA` require `vulnerable-system`; `SC/SI/SA` and `MSC/MSI/MSA` require `subsequent-system`; `E`, `CR/IR/AR`, and Supplemental `S/AU/R/V/RE/U` require `global`. Author syntax accepts `:scope vulnerable-system|subsequent-system|global` and lowers to `CvssEvidenceScope`; an incompatible metric/scope pair fails at the scope range. The decoder rejects an unknown metric, a value illegal for that metric, any numeric score field, and `X` for Base metrics. The `when` predicate uses the same `(all ...)`, `(any ...)`, analysis, source/sink-category, source-label, sink-tag, and sink-impact spellings plus `(source-evidence [:trust-boundary VALUE] [:system-entry VALUE])`, with at least one evidence field. Author evidence references use exactly `policy:self`, structured local/catalog/match endpoint references, or `selector:/semantic/path`; the decoder produces `PolicyEvidenceRef`, requires at least one per metric rule, and after composition rejects a dangling endpoint, wrong analysis kind, missing selector path, or cross-policy spelling. Resolution converts each one to a report `EvidenceRef` carrying the referenced fact's semantic/content hash. These are verified policy assertions, not opaque proof annotations. Policy metric rules may establish static Base facts only. Runtime witness, environment, threat-feed, and analyst bases enter through typed `PolicyEvaluationContext` overlays and cannot be forged by `.rqlp`.

Schema version 1 fixes these bounds and defaults so different hosts and agents do not produce different accepted languages:

| Item | Bound/default | Exhaustion behavior |
| --- | --- | --- |
| RQLP document source | 256 KiB UTF-8, 128 nesting depth, 4,096 syntax nodes | Parse/load error |
| Metadata | policy/endpoint ID 200 bytes; name 256; endpoint display name and message/description/help URI 4,096 each; 64 tags/categories of 128 bytes | Validation error at value |
| Selectors | 512 total and 8 MiB resolved selector source per policy; each retains existing RQL 64 KiB/depth/schema limits | Validation/load error |
| Policy registry | 256 runnable policies, 4,096 endpoint leaves, and 128 MiB total retained document plus resolved-selector source | Reject next registration before retention |
| Match directories | 64 refs per consumer; recursion depth 32; 65,536 total visited entries; 4,096 candidate endpoint leaves; 128 MiB retained candidate source; 64 categories/ref; optional one SHA-256 manifest pin | Typed transactional limit/load error; no partial set |
| Endpoint sets | 64 catalog refs, 64 match refs, and 256 local entries per kind; 4,096 resolved entries per role | Catalog/endpoint/validation error |
| Catalogs | 4 MiB/depth 128 per canonical JSON document; 4,096 entries per kind; 1,024 identities, 65,536 entries, and 64 MiB canonical typed content per registry | Reject next registration before retention |
| Taint entry vectors | 64 labels/tags/impacts; 256 transfers per external model | Validation error |
| Finding combinations | 256 rules; 4,096 resolved endpoints per predicate; acyclic supersedes graph | Validation/composition error |
| Typestate | 256 states, 256 events, 256 terminal expectations, 4,096 transitions, 4,096 resolved subjects/events per role | Validation/composition error |
| Classification/CVSS | 128 refinements; 256 metric rules; predicate depth 16 and 256 predicate nodes per tree; 64 added classifications/evidence refs/assumptions per record | Validation error |
| Report options | witness defaults 64 steps/16 KiB; max 1,024 steps/1 MiB; witnesses default 8/max 64; origins default 8/max 256 | Values above maximum fail validation |

All omitted optional vectors are empty, all required non-empty vectors are stated above, and local entry/state/event/label/tag/impact identifiers are 1 through 128 ASCII bytes with the state-ID spelling. Policy names/messages/descriptions, taxonomy display names/identifiers, rationales, and other user-visible prose allow Unicode within their stated byte caps. Limits are checked during iterative decoding before allocation growth. No authoring field can raise analysis work budgets.

Every visible record, field, enum spelling, value shape, signature, description, collection semantics, and analysis ownership enters through `src/analyzer/policy/schema.rs`. The parser, source diagnostics, hover help, formatter decisions, and TextMate vocabulary derive from or exhaustively test that registry. Do not add editor-only keyword arrays or parse records by ad-hoc string splitting.

### Evaluation and finding contract

The output boundary is:

    struct PolicyReportDocument {
        schema_version: u32,
        rules: Vec<PolicyRuleDescriptor>,
        runs: Vec<PolicyRun>,
        diagnostics: Vec<PolicyReportDiagnostic>,
        diagnostics_truncated: bool,
        omitted_diagnostics_lower_bound: u64,
        worst_omitted_diagnostic_severity: Option<PolicyDiagnosticSeverity>,
    }

    struct PolicyRuleDescriptor {
        policy_id: PolicyId,
        policy_hash: PolicySemanticHash,
        policy_schema: SchemaVersionResolution,
        selector_schemas: Vec<SelectorSchemaVersionResolution>,
        endpoint_dependencies: Vec<ResolvedEndpointDependency>,
        match_directory_manifests: Vec<ResolvedMatchDirectoryManifest>,
        precedence_manifest: PolicyPrecedenceManifest,
        name: String,
        message: PolicyMessageSpec,
        severity: PolicySeveritySpec,
        description: Option<String>,
        help_uri: Option<String>,
        tags: Vec<String>,
    }

    struct SelectorSchemaVersionResolution {
        path: PolicySelectorPath,
        resolution: SchemaVersionResolution,
    }

`PolicyRuleDescriptor` is the canonical report projection of one loaded rule, not a second loader model. Its endpoint dependencies, selected directory manifests, and validated precedence edges are path/identity sorted and bounded before any renderer sees them. Human output may summarize them, while canonical JSON and SARIF rule properties retain the complete bounded manifest so an omitted compatibility version or changed model library is auditable even for a zero-finding run.

    struct PolicyRun {
        policy_id: PolicyId,
        policy_hash: PolicySemanticHash,
        analysis_type: PolicyAnalysisType,
        completion: PolicyRunCompletion,
        findings: Vec<PolicyFinding>,
        diagnostics: Vec<PolicyDiagnostic>,
        diagnostics_truncated: bool,
        work: PolicyWorkReport,
    }

    enum PolicyRunCompletion {
        Complete,
        Inconclusive { reasons: Vec<PolicyIncompleteReason> },
        Unsupported { capability: PolicyCapability },
        Failed { reasons: Vec<PolicyFailureReason> },
    }

    enum PolicyCapability {
        TaintEvaluation,
        TypestateEvaluation,
        QueryFeature { language: String, feature: String },
    }

    enum FindingIdentityStability { Strong, Weak }

    struct PolicyFinding {
        id: PolicyFindingId,
        identity_stability: FindingIdentityStability,
        policy_id: PolicyId,
        policy_hash: PolicySemanticHash,
        analysis_type: PolicyAnalysisType,
        severity: FindingSeverity,
        message: String,
        classification: FindingClassification,
        certainty: FindingCertainty,
        completeness: FindingCompleteness,
        primary: PolicySourceLocation,
        related: Vec<RelatedPolicyLocation>,
        related_truncated: bool,
        omitted_related_locations_lower_bound: u64,
        evidence: PolicyFindingEvidence,
        evidence_refs_truncated: bool,
        omitted_evidence_refs_lower_bound: u64,
        cvss: Option<CvssAssessmentSet>,
        organizational_risk: Option<OrganizationalRiskAssessment>,
        proof: ProofMetadata,
        witnesses: Vec<BoundedWitness>,
        witnesses_truncated: bool,
        omitted_witnesses_lower_bound: u64,
    }

The remaining public report types are also fixed in schema version 1. An enum with any data-bearing variant is an internally tagged sum using a `type` discriminator with snake-case values, so even its unit variant is an object (for example `PolicyRunCompletion::Complete` is `{ "type": "complete" }`). An enum whose variants are all unit-like serializes as one snake-case string (for example `FindingSeverity::Warning` is `"warning"`). The explicit custom-wire exceptions are the FIRST CVSS atoms: `CvssVersion::V4_0` is `"4.0"`; `CvssBaseMetric`, `CvssThreatMetric`, `CvssEnvironmentalOrSupplementalMetric`, and the data-bearing `CvssMetric` flatten to the uppercase metric string such as `"AV"`; and `CvssMetricValue` serializes only its validated case-sensitive token such as `"N"` or `"Clear"` (its stored metric is validation context, not a nested wire field). Canonical JSON golds cover every metric/value token and these exceptions override the generic enum rule. Vectors are deterministically sorted unless their order is evidence, such as query provenance or witness steps.

    enum FindingSeverity { Unrated, Note, Warning, Error }

    enum FindingClassification {
        Unclassified,
        Classified {
            broad: TaxonomyClassification,
            refinements: Vec<TaxonomyClassification>,
        },
    }

    struct TaxonomyClassification {
        taxonomy: String,
        identifier: String,
        name: Option<String>,
        provenance: ClassificationProvenance,
    }

    enum ClassificationProvenance {
        PolicyFallback,
        PolicyRefinement { refinement_index: u32 },
        AnalysisEvidence { adapter: String, evidence_refs: Vec<EvidenceRef> },
    }

    enum FindingCertainty {
        Definite,
        Possible { reasons: Vec<CertaintyReason> },
    }

    enum FindingCompleteness {
        Complete,
        Partial { reasons: Vec<FindingIncompleteReason> },
    }

    struct PolicySourceLocation {
        path: String,
        byte_span: Option<PolicyByteSpan>,
        region: Option<PolicyDisplayRegion>,
    }

    struct PolicyByteSpan { start: u64, end: u64 }

    struct PolicyDisplayRegion {
        start_line: u64,
        start_column: u64,
        end_line: u64,
        end_column: u64,
    }

    enum MatchFindingAnchor {
        Strong {
            result_domain: MatchResultDomain,
            path: WorkspaceRelativePath,
            semantic_owner: Option<StableSemanticIdentity>,
            selected_source_sha256: Option<SourceSliceHash>,
            occurrence_ordinal: u32,
        },
        Weak {
            result_domain: MatchResultDomain,
            path: WorkspaceRelativePath,
            typed_key: OpaqueFindingKey,
        },
    }

    enum CertaintyReason {
        AmbiguousReceiver,
        AmbiguousDispatch,
        NameBasedResolution,
        MultipleCandidateDeclarations,
        AnalyzerAmbiguity { code: String },
    }

    enum PolicyFindingEvidence {
        Match { evidence: MatchFindingEvidence },
        Taint { evidence: TaintFindingEvidence },
        Typestate { evidence: TypestateFindingEvidence },
    }

    struct MatchFindingEvidence {
        result_domain: MatchResultDomain,
        anchor: MatchFindingAnchor,
        terminal: PolicyQueryResultRef,
        provenance: Vec<PolicyQueryProvenance>,
        provenance_truncated: bool,
    }

    struct PolicyQueryProvenance {
        branch: Vec<u32>,
        seed: PolicyQueryResultRef,
        steps: Vec<PolicyQueryProvenanceStep>,
    }

    struct PolicyQueryProvenanceStep {
        operation: String,
        result: PolicyQueryResultRef,
        via: Option<PolicyQueryResultRef>,
    }

    enum PolicyQueryResultRef {
        StructuralMatch { kind: String, location: PolicySourceLocation, identity: Option<StableSemanticIdentity> },
        Declaration { kind: String, fq_name: String, location: PolicySourceLocation, identity: Option<StableSemanticIdentity> },
        File { path: WorkspaceRelativePath },
        ReferenceSite { location: PolicySourceLocation, target_fq_name: String, target_identity: Option<StableSemanticIdentity>, usage_kind: Option<String>, proof: PolicyQueryProof },
        CallSite { location: PolicySourceLocation, caller_fq_name: String, caller_identity: Option<StableSemanticIdentity>, callee_fq_name: String, callee_identity: Option<StableSemanticIdentity>, proof: PolicyQueryProof },
        ExpressionSite { location: PolicySourceLocation, input_kind: String, parameter_index: Option<u32>, parameter_name: Option<String> },
        ReceiverAnalysis { location: PolicySourceLocation, analysis_kind: String, outcome: String, capture: Option<String> },
        Unsupported { query_result_kind: String, location: Option<PolicySourceLocation> },
    }

    enum PolicyQueryProof { Exact, Resolved, NameBased, Ambiguous, Unknown }

    enum MatchResultDomain {
        StructuralMatch,
        Declaration,
        ReferenceSite,
        CallSite,
        ExpressionSite,
        File,
    }

`PolicyQueryProvenance` is a policy/report-owned schema-version-1 copy, not the mutable query DTO. Its adapter validates all strings against the report bounds, converts ranges once, and maps the current `CodeQueryResultRef` variants exhaustively. Current reference provenance has an optional target ID, while current call provenance has only FQ names, so the stable identity fields remain optional and the names are always preserved; an absent identity cannot be fabricated from a name and yields `NameBasedResolution`/`Possible` when the policy proof relies on that target. It does not by itself weaken an independently strong source anchor. A future query result/provenance variant maps to `Unsupported`, marks the finding evidence partial, and makes the run inconclusive until report schema support is deliberately added; it can never silently alter canonical policy JSON/SARIF through a new query enum field. `operation` and the optional descriptive kinds are 1-through-128-byte lowercase namespaced identifiers, while names/captures use the 4-KiB prose bound.

    struct TaintFindingEvidence {
        analysis_finding_id: AnalysisFindingId,
        anchor: TaintFindingAnchor,
        sink: AnalysisEventRef,
        source_endpoint: ResolvedEndpointIdentity,
        sink_endpoint: ResolvedEndpointIdentity,
        source_display_name: String,
        sink_display_name: String,
        source_categories: Vec<PolicyCategoryId>,
        sink_categories: Vec<PolicyCategoryId>,
        selected_combination: Option<FindingCombinationId>,
        sink_tags: Vec<TaintTag>,
        sink_impacts: Vec<TaintImpact>,
        reached_source_labels: Vec<TaintLabel>,
        origins: Vec<TaintOriginEvidence>,
        origins_truncated: bool,
        source_scenarios: Vec<SourceScenarioId>,
        source_scenarios_truncated: bool,
        omitted_source_scenarios_lower_bound: u64,
        source_scenario_set_hash: SourceScenarioSetHash,
        witness_refs: Vec<WitnessId>,
        witness_refs_truncated: bool,
        projection_facts_hash: TaintProjectionFactsHash,
    }

    pub struct TaintPolicyProjectionFacts {
        pub sink_endpoint: ResolvedEndpointIdentity,
        pub sink_endpoint_semantic_hash: EndpointSemanticHash,
        pub sink_endpoint_analysis_projection_hash: EndpointAnalysisProjectionHash,
        pub sink_display_name: String,
        pub sink_categories: Vec<PolicyCategoryId>,
        pub sink_tags: Vec<TaintTag>,
        pub sink_impacts: Vec<TaintImpact>,
        pub reached_source_labels: Vec<TaintLabel>,
        pub source_facts: Vec<TaintSourceProjectionFact>,
        pub semantic_hash: TaintProjectionFactsHash,
    }

    pub struct TaintSourceProjectionFact {
        pub source_endpoint: ResolvedEndpointIdentity,
        pub source_endpoint_semantic_hash: EndpointSemanticHash,
        pub source_endpoint_analysis_projection_hash: EndpointAnalysisProjectionHash,
        pub source_display_name: String,
        pub source_categories: Vec<PolicyCategoryId>,
        pub source_label: TaintLabel,
        pub source_evidence: Option<TaintSourceEvidence>,
        pub source_scenario_ids: Vec<SourceScenarioId>,
        pub scenario_set_hash: SourceScenarioSetHash,
        pub evidence_ref: EvidenceRef,
        pub content_hash: CvssEvidenceContentHash,
    }

    enum TaintFindingAnchor {
        Strong {
            sink_identity: StableSemanticIdentity,
            source_endpoint_analysis_projection_hash: EndpointAnalysisProjectionHash,
            sink_endpoint_analysis_projection_hash: EndpointAnalysisProjectionHash,
            source_scenario_set_hash: SourceScenarioSetHash,
        },
        Weak { typed_key: OpaqueFindingKey },
    }

    struct TaintOriginEvidence {
        source_endpoint: ResolvedEndpointIdentity,
        source_label: TaintLabel,
        source_evidence: Option<TaintSourceEvidence>,
        primary: PolicySourceLocation,
        scenario_id: SourceScenarioId,
        evidence_refs: Vec<EvidenceRef>,
    }

`TaintPolicyProjectionFacts` is the complete, sorted, duplicate-free reducer input produced from one diagnostic-neutral sink meeting plus its exact `ResolvedTaintPolicySpec`; it is not a display DTO. It contains at most the 4,096 resolved source endpoints already allowed per policy, retains each fact's complete sorted scenario-ID set so overlay-scope membership and endpoint-pair precedence are decidable, verifies that set against `scenario_set_hash`, and is charged to the analysis fact/byte budget before construction. The host permits at most 16,384 total source-fact/scenario memberships per finding by default and hard cap; exhaustion makes the run inconclusive before reduction. Full endpoint semantic hashes validate the exact loaded model and `TaintProjectionFactsHash` uses domain `bifrost-taint-projection-facts/v1` over the full typed content; the finding anchor uses only endpoint analysis-projection hashes plus the semantic sink/scenario anchor. Before constructing this value, #824 applies a declared endpoint supersedes edge only when it proves the same semantic event, role, and binding: proved-distinct endpoints both remain, an undecidable comparison makes the run inconclusive, and multiple live winners fail compilation. #709 validates that every surviving exact endpoint ID/hash belongs to the loaded policy, partitions actual scenarios by source/sink endpoint pair, selects the unique presentation rule or generated default, runs classification/CVSS, and only then derives one bounded `TaintFindingEvidence` per actual pair. It never attempts semantic dominance and never materializes pair solver plans. Report options, display-name edits, and message-only edits therefore cannot change reachability, coherent scenarios, or pair identity.

Every `(source-evidence ...)` predicate is evaluated against one `TaintSourceProjectionFact`: the same source entry and scenario set must satisfy every supplied trust-boundary/system-entry field. More generally, a CVSS metric rule is evaluated per candidate source fact; global analysis/source-label/sink predicates may inspect the complete aggregate, but all source-evidence leaves in one rule must match that same candidate fact. Results from different candidates remain separate scenario groups/variants and are never field-wise existentially combined into a synthetic fact.

    struct TypestateFindingEvidence {
        analysis_finding_id: AnalysisFindingId,
        anchor: TypestateFindingAnchor,
        protocol_hash: TypestateProtocolHash,
        binding_plan_hash: TypestateBindingPlanHash,
        subject: AnalysisSubjectRef,
        source_endpoint: ResolvedEndpointIdentity,
        violation_site: Option<StableSemanticIdentity>,
        violation: TypestateViolationEvidence,
        scenario_ids: Vec<TypestateScenarioId>,
        scenarios_truncated: bool,
        omitted_scenarios_lower_bound: u64,
        scenario_set_hash: TypestateScenarioSetHash,
        witness_refs: Vec<WitnessId>,
        witness_refs_truncated: bool,
        projection_facts_hash: TypestateProjectionFactsHash,
    }

    enum TypestateViolationEvidence {
        ErrorTransition {
            event_id: TypestateEventId,
            endpoint: Option<ResolvedEndpointIdentity>,
            from: TypestateStateId,
            to: TypestateStateId,
        },
        TerminalExpectation {
            expectation_id: TypestateExpectationId,
            terminal: ResolvedTypestateTerminal,
            observed_state: TypestateStateId,
            expected_states: Vec<TypestateStateId>,
        },
    }

    enum ResolvedTypestateTerminal {
        Endpoint {
            endpoint: ResolvedEndpointIdentity,
            phase: EndpointObservationPhase,
        },
        SemanticEvent { event: PolicySemanticEvent },
    }

    pub struct TypestatePolicyProjectionFacts {
        pub protocol_hash: TypestateProtocolHash,
        pub binding_plan_hash: TypestateBindingPlanHash,
        pub source_endpoint: ResolvedEndpointIdentity,
        pub source_endpoint_hash: EndpointSemanticHash,
        pub source_categories: Vec<PolicyCategoryId>,
        pub source_display_name: String,
        pub violation_site: Option<StableSemanticIdentity>,
        pub violation: TypestateViolationEvidence,
        pub scenario_ids: Vec<TypestateScenarioId>,
        pub scenario_set_hash: TypestateScenarioSetHash,
        pub semantic_hash: TypestateProjectionFactsHash,
    }

    enum TypestateFindingAnchor {
        Strong {
            protocol_hash: TypestateProtocolHash,
            binding_plan_hash: TypestateBindingPlanHash,
            subject_identity: StableSemanticIdentity,
            violation_site_identity: StableSemanticIdentity,
            scenario_set_hash: TypestateScenarioSetHash,
            violation_hash: TypestateViolationHash,
        },
        Weak { typed_key: OpaqueFindingKey },
    }

`TypestatePolicyProjectionFacts` is the complete pre-retention adapter input. #824 produces it from one diagnostic-neutral #822 finding and the exact `ResolvedTypestatePolicySpec`; #709 validates endpoint, protocol, compiled binding-plan, event/expectation, state, terminal, site, scenario-set, and content identities before rendering. Scenario IDs are stable semantic path/scenario identities, sorted and duplicate-free before hashing, and the complete membership count shares `PolicyBudget.max_projection_scenario_memberships`; exhaustion makes the run inconclusive before reduction. `TypestateScenarioSetHash` uses domain `bifrost-typestate-scenario-set/v1`. A strong finding requires a stable semantic violation-site identity; if the adapter has only a coordinate/run-local site, the anchor is weak and the run is inconclusive. `TypestateViolationHash` uses domain `bifrost-typestate-violation/v1` over the typed violation kind/IDs, stable violation site, and complete scenario-set hash, while excluding messages, display names, severity, classifications, witnesses, and bounded report evidence. A weak projection does not fabricate that hash from coordinates; it carries only its adapter-namespaced `OpaqueFindingKey`. The strong anchor repeats the site and scenario hash as an integrity check. Two branch-separated violating calls or exits therefore cannot collide, and an explicit error transition cannot collide with an unmet terminal expectation. Findings group only equal subject/source endpoint, semantic violation, terminal/expectation, violation site, and complete scenario identity; presentation-only changes retain protocol/summary/finding identity while changing the policy hash and rendered text.

    struct ProofMetadata {
        state: ProofState,
        reasons: Vec<ProofReason>,
        evidence_refs: Vec<EvidenceRef>,
    }

    enum ProofState { Proven, Unproven, Ambiguous }

    enum ProofReason {
        DirectStructuralMatch,
        ResolvedDeclaration,
        ResolvedReference,
        ExactCallTarget,
        DataflowWitness,
        TypestateWitness,
        AmbiguousTarget,
        PartialWitness,
        AnalyzerEvidence { code: String },
    }

    struct RelatedPolicyLocation {
        relationship: PolicyLocationRelationship,
        location: PolicySourceLocation,
        evidence_refs: Vec<EvidenceRef>,
    }

    enum PolicyLocationRelationship {
        Source, Sink, Origin, Evidence, WitnessStep, Declaration, CallTarget,
    }

    struct StableSemanticIdentity {
        namespace: String,
        path: WorkspaceRelativePath,
        derivation: StableIdentityDerivation,
        semantic_key: String,
    }

    enum StableIdentityDerivation {
        AnalyzerDeclarationId,
        CanonicalAstIdentity,
        CatalogEntry,
        ProtocolSubject,
        ProtocolViolationSite,
    }

    struct BoundedWitness {
        id: WitnessId,
        steps: Vec<WitnessStep>,
        truncated: bool,
        omitted_steps_lower_bound: u64,
        retained_bytes: u64,
    }

    struct WitnessStep {
        kind: WitnessStepKind,
        location: Option<PolicySourceLocation>,
        label: String,
        evidence_refs: Vec<EvidenceRef>,
    }

    enum WitnessStepKind {
        Source, Propagation, Call, Return, Sanitizer, Transform,
        Transition, Violation,
    }

`PolicyReportDocument.schema_version` is always the JSON integer `1`; renderers reject another value. `AnalysisFindingId`, `AnalysisEventRef`, `AnalysisSubjectRef`, `SourceScenarioId`, `TypestateScenarioId`, `WitnessId`, `EvidenceRef`, and `OpaqueFindingKey` are validated adapter-namespaced opaque strings of 1 through 256 UTF-8 bytes; the report layer never parses them. `StableSemanticIdentity` is deliberately not opaque: `try_new` requires a lowercase 1-through-128-byte namespace, validated workspace-relative path, explicit stable derivation, and 1-through-256-byte canonical semantic key. It rejects control characters, absolute/native path prefixes, coordinate/offset encodings, and documented dense/run-local handle forms. Producers may call it only for declaration/AST/catalog/protocol identities whose contract survives unrelated preceding edits; current query match IDs containing offsets are ineligible, and an unproved identity forces a weak anchor. `SourceSliceHash`, `SourceScenarioSetHash`, `TypestateScenarioSetHash`, `EndpointSemanticHash`, `EndpointAnalysisProjectionHash`, `TypestateAuthoringProjectionHash`, `TypestateProtocolHash`, `TypestateBindingPlanHash`, `TypestateViolationHash`, policy hashes, and catalog hashes are distinct newtypes over lowercase 64-hex SHA-256 values and cannot be interchanged. `SourceScenarioSetHash` and `TypestateScenarioSetHash` are computed before report truncation from their sorted, duplicate-free full semantic scenario sets using their distinct domains; they are identity inputs, while displayed scenario vectors are bounded provenance with explicit truncation and omitted-count fields. `AnalyzerAmbiguity.code` and `AnalyzerEvidence.code` use the same 1-through-128-byte lowercase identifier spelling as policy diagnostic codes. `ClassificationProvenance::AnalysisEvidence.adapter` is a 1-through-128-byte namespaced identifier. Every span-bearing strong match anchor requires the exact selected-source hash; a semantic owner is additional identity when available but never substitutes for unavailable indexed bytes. A `File` anchor is strong from its normalized primary path and has neither span nor slice hash. A strong taint anchor contains the exact semantic sink identity, selected source/sink endpoint analysis-projection hashes, and non-empty full scenario-set hash. A strong typestate anchor contains the compiled protocol and binding-plan hashes, semantic subject and violation-site identities, complete typestate scenario-set hash, and typed violation hash. `AnalysisFindingId` is provenance, never the public identity input. Any weak anchor marks identity stability weak, makes the run inconclusive, and cannot produce a SARIF fingerprint. Only complete pre-retention `TaintPolicyProjectionFacts` and `TypestatePolicyProjectionFacts` drive #709 precedence, message generation, classification, and CVSS. Their bounded finding evidence explains the result but is never reread as reducer input. #824 must populate projection facts from the exact resolved endpoint/policy identities used to compile each finding. A source location either has both a byte span and display region or neither; `start <= end`, lines/columns are one-based, bytes are zero-based and end-exclusive, and display end line/column denote the position immediately after the region, matching SARIF's exclusive `endColumn` (including multiline and EOF regions). File findings use neither. Evidence/witness/scenario vectors are capped by the report options and hard budget below. Truncating witness/provenance/origins/scenario display marks the finding partial but does not by itself make reachability or a complete negative run inconclusive.

The stable completion, failure, diagnostic, and work vocabularies are:

    enum PolicyIncompleteReason {
        Cancelled,
        QueryResultLimit,
        BatchFindingLimit,
        ScannedFileBudget,
        SourceByteBudget,
        FactNodeBudget,
        PipelineRowBudget,
        ImportGraphBudget,
        ReferenceCandidateBudget,
        PartialDiscovery,
        CapabilityIncomplete,
        EndpointDominanceUndecidable,
        StableAnchorUnavailable,
        ReportRetentionBudget,
        CvssVariantBudget,
        ProjectionScenarioMembershipBudget,
        OrganizationalRiskOverlayBudget,
    }

    enum FindingIncompleteReason {
        QueryProvenanceTruncated,
        RelatedLocationsTruncated,
        OriginsTruncated,
        SourceScenariosTruncated,
        TypestateScenariosTruncated,
        WitnessTruncated,
        EvidenceTruncated,
        ProofPartial,
        StableAnchorWeak,
    }

    enum PolicyFailureReason {
        InvalidExecutionPlan,
        WorkspaceSnapshotUnavailable,
        SourceReadFailed,
        WorkspaceIo,
        AmbiguousEndpointDominance,
        AmbiguousTypestateBinding,
        ConflictingOrganizationalRiskOverlay,
        InternalInvariant,
    }

    struct PolicyDiagnostic {
        code: PolicyDiagnosticCode,
        severity: PolicyDiagnosticSeverity,
        impact: PolicyDiagnosticImpact,
        message: String,
        primary: Option<PolicySourceLocation>,
        related: Vec<RelatedPolicyLocation>,
    }

    enum PolicyDiagnosticCode {
        CodeQuery { code: CodeQueryDiagnosticCode },
        UnsupportedAnalysis,
        StableAnchorUnavailable,
        EndpointDominanceUndecidable,
        EvaluationFailure,
        BatchFindingLimit,
        ReportRetentionBudget,
        CvssVariantBudget,
        ProjectionScenarioMembershipBudget,
        OrganizationalRiskOverlayBudget,
    }

    enum PolicyDiagnosticImpact {
        Advisory, FindingPartial, RunIncomplete, RunUnsupported, RunFailed,
    }

    struct PolicyReportDiagnostic {
        code: PolicyReportDiagnosticCode,
        severity: PolicyDiagnosticSeverity,
        message: String,
        source: Option<PolicySourceIdentity>,
        byte_range: Option<PolicySourceRange>,
        related: Vec<PolicySourceRelatedDiagnostic>,
    }

    enum PolicyReportDiagnosticCode {
        PolicyLoadFailed,
        PolicyParseFailed,
        PolicyValidationFailed,
        EndpointParseFailed,
        EndpointValidationFailed,
        NotExecutableEndpoint,
        DuplicatePolicyId,
        DuplicateEndpointId,
        PolicyCountLimit,
        EndpointCountLimit,
        MatchDirectoryLimit,
        MatchDirectoryChangedDuringLoad,
        MatchDirectoryManifestMismatch,
        NonEndpointInMatchDirectory,
        EndpointMissingOrMismatchedTaintSemantics,
        AmbiguousCombinationPrecedence,
        UnsupportedPolicySchemaVersion,
        UnsupportedRqlSchemaVersion,
        ConflictingRqlSchemaVersion,
        ExplicitPolicySchemaVersionRequired,
        ExplicitRqlSchemaVersionRequired,
    }

    enum PolicyDiagnosticSeverity { Note, Warning, Error }

The schema-related report codes serialize exactly as `unsupported-policy-schema-version`, `unsupported-rql-schema-version`, `conflicting-rql-schema-version`, `explicit-policy-schema-version-required`, and `explicit-rql-schema-version-required`. The policy code covers both top-level policy and endpoint documents because they share one policy-format lineage; the diagnostic source/range identifies the document kind. An explicit unsupported value points at the numeric value and lists supported exact versions without suggesting fallback. Strict mode emits the policy and/or RQL required code for every inferred resolution it rejects.

    struct PolicyWorkReport {
        scanned_files: u64,
        scanned_source_bytes: u64,
        fact_nodes: u64,
        pipeline_rows: u64,
        examined_references: u64,
        retained_findings: u64,
        omitted_findings_lower_bound: u64,
        retained_report_bytes: u64,
        metrics: Vec<PolicyWorkMetric>,
    }

    struct PolicyWorkMetric {
        name: String,
        unit: PolicyWorkUnit,
        value: u64,
    }

    enum PolicyWorkUnit { Count, Bytes, Rows }

    struct OrganizationalRiskAssessment {
        scheme: String,
        rating: String,
        rationale: String,
        evidence_refs: Vec<EvidenceRef>,
        assessor: Option<String>,
        content_hash: OrganizationalRiskAssessmentHash,
    }

Known common counters have dedicated fields. Future #821/#822 metrics use sorted namespaced names such as `taint.propagation_states`; they cannot redefine common counters. Timings and wall-clock timestamps are intentionally absent from canonical deterministic output.

Analysis work is controlled by host configuration, never by policy source:

    pub struct PolicyBudget {
        query: CodeQueryExecutionLimits,
        max_findings: usize,
        max_diagnostics: usize,
        max_related_locations_per_finding: usize,
        max_evidence_refs_per_finding: usize,
        max_evidence_bytes_per_finding: usize,
        max_witnesses_per_finding: usize,
        max_witness_steps: usize,
        max_witness_bytes: usize,
        max_cvss_overlays: usize,
        max_cvss_evidence_records_per_finding: usize,
        max_cvss_variants_per_finding: usize,
        max_cvss_reduction_steps: usize,
        max_projection_scenario_memberships: usize,
        max_organizational_risk_overlays: usize,
        max_retained_report_bytes: usize,
    }

    pub struct PolicyBatchBudget {
        max_policies: usize,
        max_total_findings: usize,
        max_retained_report_bytes: usize,
        max_serialized_report_bytes: usize,
        per_policy: PolicyBudget,
    }

    pub struct PolicyBudgetBuilder { /* private fields */ }
    pub struct PolicyBatchBudgetBuilder { /* private fields */ }

    impl Default for PolicyBudget { /* exact CLI defaults below */ }
    impl Default for PolicyBatchBudget { /* exact CLI defaults below */ }

    impl PolicyBudget {
        pub fn builder() -> PolicyBudgetBuilder;
    }

    impl PolicyBatchBudget {
        pub fn builder() -> PolicyBatchBudgetBuilder;
    }

CLI defaults are exactly 20,000 scanned files, 128 MiB scanned source, 2,000,000 fact nodes, and 50,000 pipeline rows (the current `CodeQueryExecutionLimits::default()`); 1,000 findings per policy; 256 diagnostics; 64 related locations; 256 evidence references; 64 KiB retained evidence per finding; author-selected defaults of eight witnesses each bounded to 64 steps/16 KiB, with schema maxima of 64 witnesses each bounded to 1,024 steps/1 MiB; 256 CVSS overlays, 256 CVSS evidence records per finding, 32 coherent CVSS variants per finding, 32,768 CVSS reduction steps, 16,384 complete projection scenario memberships, and 64 organizational-risk overlays; 16 MiB of retained report data per policy; 256 policies; 10,000 total findings; 64 MiB retained report data per batch; and 64 MiB serialized output. The host witness hard caps default to the schema maxima so a valid authored report choice is honored; each effective bound is the minimum of the author option and host budget. Every `witness_refs` entry in finding evidence/CVSS must resolve uniquely to one witness retained by the same `PolicyFinding`; omitted witnesses set both the owning finding's and each affected reference list's truncation fields. Policy match execution clones the selector, sets `result_detail = full`, and sets `query.limit = max_findings`, which cannot exceed the current `CodeQuery::MAX_LIMIT` of 1,000. A host may lower any bound but cannot exceed these schema-version-1 hard caps through this API.

All budget fields are private. Each builder starts from `Default`, exposes one fallible `with_<field>(value)` setter per field plus `with_query_limits`, and `build() -> Result<..., PolicyBudgetError>`; a setter may lower a bound to zero where zero means retain/execute none, but rejects any value above the hard cap just listed and rejects internally inconsistent batch/per-policy retained-byte limits. External callers never mutate raw fields. CVSS reduction processes sorted evidence incrementally, charges one step before each compatibility/branch operation, and refuses to create variant `N+1` before the 32-variant bound. Overlay/evidence/step/variant exhaustion yields an unscored variant containing `RunIncomplete { CvssVariantBudget }`, marks the policy run inconclusive with the same typed reason, and returns status 2; it never silently drops a variant or constructs a Cartesian product before checking the bound.

Report construction is incrementally bounded rather than checked only after a potentially huge document exists. A shared `RetainedSize` implementation counts each report record's owned strings, vectors, and fixed-size storage. Before retaining findings or secondary diagnostics, `PolicyReportBuilder` reserves and charges an exact bounded skeleton allowance for every requested input (at most 256): each successfully loaded policy gets its rule descriptor and minimal run, while each failed/duplicate input gets one bounded primary report diagnostic. Each message is capped at 4 KiB, so the preflight reservation is at most 8 KiB per input plus vector storage; construction fails before evaluation if the configured batch budget cannot represent all skeletons. It also reserves a 4-KiB emergency diagnostic allowance. The builder then charges both per-policy and batch retained-byte trackers before transactionally inserting a secondary diagnostic or whole finding and never partially retains one record. If a finding would cross either retained bound, it omits that entire finding, increments `omitted_findings_lower_bound`, and marks the current/later affected run `Inconclusive { ReportRetentionBudget }` in its already reserved skeleton. The emergency allowance guarantees the reason itself can be reported.

If a secondary report diagnostic cannot fit, the document sets `diagnostics_truncated`, increments `omitted_diagnostics_lower_bound`, and retains the worst omitted severity; the one primary outcome per requested input is never omitted. Run-level diagnostic truncation uses the existing `diagnostics_truncated` flag and worst impact tracker. Any report-diagnostic truncation forces status 2 and a batch SARIF notification even if all loaded runs completed. A query/per-policy/batch finding cap similarly makes affected and skipped runs inconclusive with the exact reason and status 2; retained rows remain findings. Evidence, related-location, witness, and advisory-diagnostic retention caps set explicit truncation/lower-bound fields but do not change reachability. The tracker retains the worst diagnostic impact even when diagnostic text is capped, so truncating messages cannot turn an incomplete run into a complete one. Serialized output beyond 64 MiB is a coordinator failure reported on stderr with status 2; serialization/report-encoding and output-write failures are the size/transport cases for which a valid partial machine report cannot be promised.

`PolicyReportDocument` is the canonical render input. The coordinator creates a rule descriptor for every successfully loaded policy before evaluation, so a zero-finding or failed run still has all metadata required by human/JSON/SARIF renderers. Parse/load failures which cannot yield a trustworthy policy ID become report-level diagnostics tied to their source identity; valid policies in the same invocation retain their descriptors and runs. Rule descriptors and runs join by `(policy_id, policy_hash)`, and construction rejects a missing or ambiguous join.

`PolicyFindingEvidence` is the tagged union above. The match variant retains the terminal query domain, stable neutral anchor inputs, bounded query provenance, and domain proof; it does not serialize an entire analyzer or source file. The future variants retain the diagnostic-neutral finding identity, reached classes/events, scenario identity, bounded origins, and witness references needed for classification without exposing solver storage handles.

`FindingCertainty` is the nonnumeric enum `Definite` or `Possible`, plus structured reasons when possible. Exact structural matches/declarations/files are definite; reference/call proof and receiver/dispatch ambiguity map conservatively. It is not a probability. `FindingCompleteness` says whether this finding's evidence is complete or partial and why. `PolicyRunCompletion` independently says whether complete enumeration/no-finding is justified; `Failed` is an operational or invalid-execution outcome, not semantic uncertainty or unsupported capability.

`PolicySourceLocation` contains a slash-normalized workspace-relative filesystem path, optional zero-based end-exclusive UTF-8 byte span, and a one-based Unicode-code-point display region. File findings omit the region. The adapter centralizes conversion from current one-based `CodeQueryRange` and later zero-based semantic locators. The SARIF renderer does not copy this filesystem string verbatim: it converts each normalized path segment to an RFC 3986 relative URI reference, UTF-8 percent-encodes spaces, Unicode bytes, `#`, `%`, and every non-unreserved byte, preserves `/` only as the segment separator, and sets `artifactLocation.uriBaseId` to the stable logical base `SRCROOT`. It never emits a drive letter, UNC prefix, absolute workspace path, or unescaped filesystem string; the consumer supplies/resolves `SRCROOT`, so deterministic output does not contain the checkout location. Human output and SARIF are tested with ASCII, multibyte text, spaces, `#`, `%`, empty lines, end-of-file, normalized Windows-shaped paths, and URI round trips. SARIF declares `columnKind: unicodeCodePoints`.

Match evaluation clones the validated query, removes/forbids author output controls, forces full detail, executes once through the crate-private detailed result, classifies typed query diagnostics, and adapts accepted terminal rows together with their byte/semantic evidence. `Complete` requires `truncated == false`, no `incomplete`/`invalid` diagnostic impact, no weak finding anchor, and no domain-specific partial outcome. Cancellation and work limits are inconclusive; unsupported adapters/features are unsupported or inconclusive according to whether any requested domain remains answerable; invalid programmatic plans and operational snapshot/source failures are failed. Partial positive rows may still become findings; an empty non-complete result never becomes a clean run.

The match `PolicyFindingId` is lowercase 64-character SHA-256 over a canonical tuple beginning with `bifrost-policy-finding/v1`. A strong anchor includes policy ID, analysis type, result domain, normalized path, stable semantic owner or declaration identity when available, the required exact selected source-slice digest for every span-bearing domain, and a deterministic ordinal among otherwise equal anchors inside that owner/file. It excludes policy hash so metadata/classification revisions do not churn identity; the finding still records the new policy hash. File findings use the normalized file identity. If exact indexed bytes are unavailable for a span-bearing result, use a deterministic typed-key fallback marked `Weak` even when a semantic owner exists, make the run inconclusive with `stable_anchor_unavailable`, and omit the SARIF partial fingerprint. Tests insert unrelated lines before a strong finding without adding an equal anchor and change message/severity to prove the ID remains stable; changing selected bytes or inserting an equal earlier anchor must change it. A custom analyzer with unavailable indexed source proves the weak behavior.

### Classification and CVSS contract

Classification is a pure post-analysis projection. It first preserves the policy fallback/broad classification, then applies deterministic ordered refinements to typed finding evidence. Failure to match a narrow CWE never deletes a broad taint finding. A generic `TaxonomyClassification` carries taxonomy, identifier, optional name, and provenance; CWE is a validated well-known taxonomy, not the only possible classification.

`CvssMetricEvidence` contains metric, value, basis (`static-witness`, `policy-assertion`, `environment-profile`, `threat-feed`, or `analyst-override`), evidence references, rationale, assumptions, assessor/tool, assessment time, and system scope. Catalog/policy assertions record their content hash. Environmental, Threat, and analyst overlays arrive in `PolicyEvaluationContext`; they do not change reusable query/flow summaries.

Schema version 1 resolves applicable evidence with an explicit, order-independent scope partial order. `AllFindings < Policy`; `Finding` and `SourceScenario` each refine `Policy` but are incomparable with one another; `FindingScenario { finding, scenario }` refines both. For a concrete finding/scenario, discard non-containing scopes and keep the maximal applicable scopes. If different values survive at incomparable maximal scopes, they form coherent variants when possible or a typed conflict—neither axis arbitrarily wins. Metric-family admissibility is exact: `policy-assertion` and `static-witness` may establish Base metrics only, `threat-feed` may establish Threat metrics only, `environment-profile` may establish Environmental/Modified/Supplemental metrics only, and `analyst-override` may establish any typed metric. Basis-specific constructors enforce that matrix before evaluation. Within the same maximal scope, basis precedence is `analyst-override > environment-profile|threat-feed > static-witness > policy-assertion`. Evidence at a lower basis rank remains provenance but cannot replace the chosen value. Two different values at the same highest rank form separate coherent variants when their scenario constraints allow it, otherwise produce `ConflictingMetricEvidence`; insertion/provider order never breaks the tie and the reducer never falls through to a lower rank. Tests cover every admissibility, scope-containment/incomparability, basis comparison, and equal-rank conflict.

    struct CvssMetricEvidence {
        metric: CvssMetric,
        value: CvssMetricValue,
        basis: CvssEvidenceBasis,
        evidence_refs: Vec<EvidenceRef>,
        rationale: String,
        assumptions: Vec<String>,
        assessor_or_tool: String,
        assessed_at: Option<String>,
        system_scope: CvssEvidenceScope,
        content_hash: CvssEvidenceContentHash,
    }

    enum CvssEvidenceBasis {
        StaticWitness,
        PolicyAssertion,
        EnvironmentProfile,
        ThreatFeed,
        AnalystOverride,
    }

    enum CvssUnscoredReason {
        MissingBaseEvidence,
        ConflictingMetricEvidence {
            metric: CvssMetric,
            evidence_set_hash: CvssEvidenceSetHash,
            evidence_refs: Vec<EvidenceRef>,
            evidence_refs_truncated: bool,
            omitted_evidence_refs_lower_bound: u64,
        },
        IncoherentScenario {
            scenario_set_hash: SourceScenarioSetHash,
            scenario_ids: Vec<SourceScenarioId>,
            scenario_ids_truncated: bool,
            omitted_scenario_ids_lower_bound: u64,
            rationale: String,
        },
        RunIncomplete { reason: PolicyIncompleteReason },
    }

    struct CvssComponentResult {
        nomenclature: CvssNomenclature,
        vector: String,
        score: f64,
        severity: CvssSeverity,
    }

    enum CvssNomenclature { B, BT, BE, BTE }

    enum CvssSeverity { None, Low, Medium, High, Critical }

    struct CvssAssessmentProvenance {
        reducer: String,
        evidence_refs: Vec<EvidenceRef>,
        overlay_scopes: Vec<PolicyOverlayScope>,
        content_hashes: Vec<CvssEvidenceContentHash>,
    }

The assessment algebra is:

    struct CvssAssessmentSet {
        variants: Vec<CvssAssessmentVariant>,
        selected_for_display: Option<CvssAssessmentVariantId>,
        selection_rationale: Option<String>,
    }

    struct CvssAssessmentVariant {
        id: CvssAssessmentVariantId,
        vulnerability_identity: VulnerabilityIdentity,
        source_scenarios: Vec<SourceScenarioId>,
        source_scenarios_truncated: bool,
        omitted_source_scenarios_lower_bound: u64,
        source_scenario_set_hash: SourceScenarioSetHash,
        witness_refs: Vec<WitnessId>,
        witness_refs_truncated: bool,
        assessment: CvssAssessment,
    }

    enum CvssAssessment {
        Scored {
            version: CvssVersion,
            nomenclature: CvssNomenclature,
            vector: String,
            components: Vec<CvssComponentResult>,
            metrics: Vec<CvssMetricEvidence>,
            provenance: CvssAssessmentProvenance,
        },
        Unscored {
            version: CvssVersion,
            established: Vec<CvssMetricEvidence>,
            missing_base_metrics: Vec<CvssBaseMetric>,
            reasons: Vec<CvssUnscoredReason>,
            provenance: CvssAssessmentProvenance,
        },
    }

`CvssEvidenceContentHash`, `CvssEvidenceSetHash`, `VulnerabilityIdentity`, and `CvssAssessmentVariantId` are distinct lowercase 64-hex SHA-256 newtypes. Evidence content hashes use the basis-specific normalized fact/overlay bytes described above; an evidence-set hash uses domain `bifrost-cvss-evidence-set/v1` over the full sorted content-hash set before display retention. `VulnerabilityIdentity` uses the domain `bifrost-policy-vulnerability/v1` plus the analysis type and typed finding anchor, excluding policy ID, policy hash, source coordinates, messages, classifications, score, and report metadata; its stability is therefore the containing finding's declared `identity_stability`. A variant ID uses `bifrost-policy-cvss-variant/v1` plus the vulnerability identity, the full `SourceScenarioSetHash`, canonical established evidence hashes, and either the canonical complete vector or sorted unscored reason metric/set hashes. It deliberately excludes bounded displayed scenario/evidence/witness references, their truncation, rationale prose, display selection, and provider iteration order, so report limits cannot churn a variant ID or its display tie-break. The scenario/evidence/witness truncation fields record omitted supporting provenance.

`CvssAssessmentSet.variants` is non-empty, sorted by variant ID, and duplicate-free. Every variant's `vulnerability_identity` must match the containing finding anchor. For match and typestate findings, `source_scenarios` is empty, its truncation/count fields are false/zero, and `source_scenario_set_hash` is the canonical hash of the empty set; adapters never invent a sentinel scenario. For taint it is the full-set hash described above. Every serialized source-scenario/witness reference resolves to a retained item; omitted IDs are removed from reference vectors and represented only by the matching truncation/omitted-count fields plus full-set hash. If any variant is scored, `selected_for_display` is `Some` and names exactly the deterministic scored variant selected below; if every variant is unscored it is `None`. A dangling selection, two equal IDs with different content, an unresolved retained reference, or a scored vector whose recomputed ID differs is an internal-invariant failure, not renderer repair work.

All CVSS v4 Base metrics (`AV`, `AC`, `AT`, `PR`, `UI`, `VC`, `VI`, `VA`, `SC`, `SI`, and `SA`) are required before scoring and reject `X`. Threat, Environmental/Modified, and Supplemental metrics accept `X` only where FIRST defines it. Every evidence record has a validated content hash. A policy assertion hashes only the normalized metric rule plus resolved referenced fact/catalog hashes under `bifrost-cvss-policy-evidence/v1`; it excludes unrelated policy ID/message/severity/report metadata. Static witness evidence hashes the full semantic witness/fact derivation before display step/byte truncation under `bifrost-cvss-static-evidence/v1`. Runtime overlays hash their normalized typed content. Constructors are basis-specific and private fields prevent a caller from claiming another basis or omitting/malforming the hash; report limits therefore cannot churn evidence or variant identity. The implementation canonicalizes vectors and recomputes scores; it never accepts a numeric score from policy/evaluation input. Every scored variant includes the Base (`B`) projection. It additionally includes `BT` when non-default Threat evidence exists, `BE` when non-default Environmental/Modified evidence exists, and `BTE` when both exist; each component is built as its own coherent vector and scored independently with `cvss`, while Supplemental metrics remain in the full canonical vector/provenance without changing nomenclature. Network transport alone does not establish `AV:N`: a downloaded file remains local unless evidence says the vulnerable system itself exposes the attack path over a network. Conflicts produce separate coherent variants when possible and otherwise an `Unscored` assessment whose CVSS-specific reasons identify missing Base evidence, metric conflicts, incoherent scenarios, or an incomplete run. Variants are never averaged, spliced, or collapsed by provider order.

Display selection is deterministic and presentation-only. If any variant is scored, select the variant whose most complete applicable component has the highest numeric score; break ties by canonical full vector and then variant ID. If every variant is unscored, select none. Record exactly `selected highest scored coherent variant; ties use canonical vector then variant id` (or `no complete scored variant`) as the rationale. All variants remain serialized and a consumer may choose differently; the selection never feeds propagation, classification, or finding identity.

### Rendering and CLI contract

Human output is deterministic and starts each finding with a clickable location:

    src/app.py:12:5: [warning] bifrost.security.dynamic-eval: Dynamic evaluation is forbidden
      finding: 3b3d...64-hex
      analysis: match (definite, complete)
      evidence: structural_match call

It then renders related locations, concise bounded evidence/witnesses, classification, every CVSS variant, and run-completion notes in stable order. A no-finding complete run prints an explicit clean summary. An incomplete or unsupported run prints an explicit non-clean summary even with zero findings. ANSI color, if added, is opt-in/TTY-sensitive and never appears in redirected or gold output.

Policy/source validation rejects C0/C1 controls (including CR/LF/TAB/ESC), NUL, and Unicode bidi controls in every author-supplied metadata, label, rationale, assessor, taxonomy, and other single-line string. Analyzer/workspace strings and filenames cannot be assumed clean, so all human fields pass through one `escape_terminal_text` function: C0/C1, ESC, CR/LF/TAB, DEL, and bidi controls render as visible `\u{HEX}` escapes and can never create a new line or ANSI sequence. SARIF artifact URIs percent-encode those path bytes; canonical JSON uses explicit `\uXXXX` escapes for controls/bidi. Golds cover newline, ESC, U+202E, U+2066, and a filename containing each, proving a finding cannot forge another diagnostic line or reorder terminal text.

Canonical JSON serializes the exact `PolicyReportDocument` model with snake_case tagged enums, stable vector ordering, normalized paths, and no map-order-dependent identity. It is the machine/debug contract and hash input where noted, but is not accepted as `.rqlp` authoring input.

SARIF output uses version `2.1.0` and the official schema URI. `tool.driver.rules[].id` is `PolicyId`; name, descriptions, help URI, tags, and default level come from metadata. A generated-message rule uses the fixed descriptor text `Selected source can reach selected sink`, while every result carries the exact endpoint-derived message. Fixed levels map directly, `unrated` maps to SARIF `none`, and a CVSS-derived rule uses its `when-unscored` fallback (`unrated` also maps to `none`) as the rule default. Every result explicitly sets `level`, including `none`, and an unrated result also sets `kind: "informational"` plus `properties["bifrost.unrated"] = true`, so SARIF's default `warning` can never accidentally rate or visually imply an unrated finding. Each finding also sets `ruleId`/`ruleIndex`, message, primary `locations`, evidence `relatedLocations`, ordered witness `codeFlows`, and `partialFingerprints["bifrostFinding/v1"] = PolicyFindingId` only for strong identities. It does not set `baselineState` without a real baseline comparison. Bifrost namespaced properties retain policy hash, resolved policy/selector schema manifests, selected endpoint identities/hashes, chosen combination/expectation, analysis type, completion, certainty, classifications, proof/evidence, and every CVSS scored/unscored variant. Run completion also appears in run properties; incomplete/unsupported runs add a stable invocation notification so zero-result SARIF is not falsely clean.

The private SARIF DTO implements this normative subset rather than relying on readers to infer it from the external specification: the log always has `$schema`, `version`, and `runs`; the CLI batch emits exactly one SARIF run with `tool.driver.name`, tool version/information URI when known, a deterministic `rules` array, `columnKind: "unicodeCodePoints"`, `results` (including an explicit empty array), exactly one batch `invocation`, and Bifrost properties. Rules carry `id`, `name`, short/full descriptions, optional `helpUri`, explicit `defaultConfiguration.level`, and tags; their policy-ID-sorted array position is the `ruleIndex` referenced by results, and no non-schema `index` member is emitted. Results carry `ruleId`, `ruleIndex`, rendered message, explicit level (`none|note|warning|error`), primary/related locations, code flows when present, strong partial fingerprint when available, and Bifrost properties. The batch invocation has `executionSuccessful = true` only when every requested policy loaded uniquely and every emitted policy run is `Complete`; a threshold finding and CLI status 1 do not make execution unsuccessful. Any report-level load diagnostic or inconclusive, unsupported, or failed policy run makes it false and adds a policy/reason-specific stable `toolExecutionNotification` at warning/warning/error level respectively. `baselineState` is never serialized in schema version 1.

Add these mutually exclusive one-shot CLI options to `src/bin/bifrost.rs`:

    --policy-file PATH          repeatable workspace-relative .rqlp path
    --format human|json|sarif  default human
    --fail-on never|finding|note|warning|error
                               default warning
    --require-explicit-schema-versions
                               reject every inferred policy/RQL version
    --output PATH              optional output file; stdout otherwise

`finding` includes unrated findings; level thresholds include only findings at that fixed/derived level or higher. Policy mode is exclusive with query/tool/MCP/LSP/REPL/skill-install options and `--sources`. Load all explicit policy roots and their endpoint dependencies into one registry, reject duplicate IDs/collisions, evaluate only runnable roots in stable policy-ID order, and combine them into one canonical `PolicyReportDocument`, then render that document as human, JSON, or one SARIF run. Imported endpoints never become rules/runs. Passing an endpoint document itself as `--policy-file` returns report diagnostic `NotExecutableEndpoint` and status 2 rather than a clean result. Strict schema mode rejects each inferred root/dependency/selector before evaluation with report diagnostics; default mode accepts inference. Output paths may be outside the analyzed workspace because they are caller-selected destinations, but writing is explicit and never happens by default.

Loading is collect-and-continue at the coordinator boundary. A valid, unique policy receives a descriptor and run even if another explicit file fails. A parse/load failure with no trustworthy ID becomes a report diagnostic. If an ID is duplicated, every definition with that ID is excluded from `rules` and `runs` and the diagnostic names all source identities; the first file does not silently win. Any such diagnostic forces status 2, so the retained runs cannot be mistaken for a complete batch.

Refactor the CLI return path so exact statuses are possible: 0 for every run complete with no threshold finding, 1 for every run complete with at least one threshold finding, and 2 for any load/parse/validation/internal error or any incomplete/unsupported run. Status 2 takes precedence over 1. For reportable load/evaluation causes, including incremental finding/secondary-diagnostic retention exhaustion, emit the retained partial report before returning 2 when bounded serialization and the destination write succeed, and summarize the cause on stderr. Only inability to reserve the mandatory per-input report skeletons, encoding/serialization, broken-pipe, and write/replace failures are stderr-only status 2. Do not add an `--allow-incomplete` escape hatch in this issue.

## Plan of Work

### Milestone 1: shared syntax and the complete authoring contract

Move the generic expression/range/parser and formatter code from the query directory into a crate-internal `src/sexp/` module, then update RQL imports without behavior changes. Preserve all parser limits, comments, incomplete-document handling, formatting, and existing query tests. Expose an AST-to-`CodeQuery` lowering/validation seam so policy selectors pass an `Expr` subtree directly instead of rendering and reparsing it.

Create `src/analyzer/policy/{mod,definition,schema,source}.rs`. Implement strict decoding for exactly one top-level `(policy ...)` or `(endpoint ...)`, the compiled-in policy/RQL compatibility lineages, required policy versus endpoint metadata, severity/message variants, explicit `analysis.type`, categorized bound endpoint leaves, all match/taint/typestate authoring records, finding combinations, typed endpoint observation phases, analysis-root terminal expectations, classification/report options, and selector wrappers. Explicit unsupported versions never fall back; omitted versions resolve only to their lineage head. Reject unknown/duplicate fields, duplicate set identities, invalid enum values, cross-document/cross-variant fields, conflicting file/wrapper versions, nested output controls, invalid precedence DAGs/transitions/expectations, illegal binding/phase combinations, terminal expected states outside the accepting set, invalid CVSS Base values, and every configured count/byte/depth limit at the narrowest byte range. Lower inline selectors at parse time, defer file/directory resolution to the workspace loader, and retain source maps/version origins.

Implement deterministic normalized-authored JSON plus, for fully inline/local documents, the same loaded canonical-semantic projection Milestone 2 will generalize; unresolved file/catalog/directory references must not masquerade as final semantic JSON or enter semantic hashes. Implement a source-preserving, registry-driven S-expression formatter. Keep the shared generic/RQL default output unchanged; the RQLP formatter uses 100 columns by default, never separates a field keyword from its value, lays out large tagged-record vectors predictably, and preserves version omission. Loaded canonical JSON always materializes resolved versions and excludes selector execution controls. Canonicalize semantic sets by stable ID and preserve only sequences whose order is a contract, such as classification refinements and witness steps. Add `tests/policy_source.rs` with exact endpoint/match/taint/typestate examples, generated-message/combination/terminal shapes, normalized-authored and inline semantic JSON golds, parser/formatter idempotence, comments, Unicode, incomplete buffers, schema/variant errors, limits, and nested RQL diagnostic ranges. Test omitted policy -> 1 and RQL -> 2, explicit/implicit semantic-hash equality with source/origin inequality for fully resolved inputs, explicit unsupported no-fallback behavior, test-only compatible versus explicit-only successors, and all four `rql-file` precedence cases at the source/loading seam. Store full-document formatting golds at 80, 100, and 120 columns. Update this plan, inspect the milestone diff, run formatting and focused tests, and make a multiline checkpoint commit containing only this milestone when implementation begins under this ExecPlan.

### Milestone 2: safe loading, content identity, and catalog composition

Extract the existing query read/path checks into a reusable capability-based workspace-document loader and keep accepted query behavior byte-for-byte compatible. Add `cap-std = { version = "4.0.2", default-features = false }`, open the workspace root once, and perform path-relative open, same-handle metadata, and bounded reads without canonicalize/reopen. Implement `PolicyRegistry` APIs for explicit workspace-relative policy/endpoint paths and embedding-supplied bytes with a named source identity. Enforce `.rqlp`, 256 KiB, no absolute/parent/prefix components or symlink escape, regular files, valid UTF-8, and one RQLP document per file. Resolve referenced `.rql` selectors and explicit match directories through the same root capability. Directory scans are lexical, bounded, transactional, symlink-free, `.rqlp` endpoint-only, re-enumerated against races, and optionally manifest-pinned. Include resolved schema versions and canonical typed `CodeQuery`/selected endpoint meaning in semantic identity; retain version origin, referenced paths, directory manifests, and raw source hashes as provenance. Reject file/directory references for byte-only documents that have no workspace context.

Implement `TaintCatalogDefinition`, `CatalogRef`, and `TaintCatalogRegistry` for explicit built-ins, canonical JSON bytes, or workspace-safe registered paths. Bound registrations and entries, record name/version/hash, make equal canonical typed content idempotent despite JSON whitespace/key order, reject one name/version with a different semantic hash, enforce optional hash pins, and compose local/catalog/match endpoints deterministically into uniform `ResolvedEndpointIdentity` values. Validate endpoint and finding-combination supersedes DAGs, finite predicates, conflicts, generated-message display inputs, typed bindings, taint-role/semantics completeness, and manifest pins. Construct both `ResolvedTaintPolicySpec` and `ResolvedTypestatePolicySpec`, each with fully resolved selector/model/schema/dependency provenance and a pre-semantic authoring projection hash, without constructing solver plans or a compiled typestate binding-plan hash.

Add `tests/policy_loading.rs` for missing/wrong extensions, absolute/traversal paths, symlink escape, directories, oversized and invalid UTF-8 content, referenced-selector source diagnostics, duplicate policy/endpoint IDs, wrong document kind, path-separator normalization, source versus semantic/projection hash behavior, catalog collisions/pins, directory scope/order/race/manifest/category behavior, supersedes cycles/ambiguity, and deterministic taint/typestate composition. Prove selected endpoint changes affect the aggregate policy hash, unselected endpoint edits do not, display-only edits preserve analysis-projection hashes, imported endpoints create no runs, and an endpoint root is status 2. Include the three-source/four-sink fixture and assert one resolved policy set rather than a pair product. Use platform-neutral `Path`/`PathBuf` and conditional symlink setup only where the OS permits it. Update the plan, review, and checkpoint the milestone.

### Milestone 3: typed completeness, policy findings, and match evaluation

Extend `CodeQueryDiagnostic` with stable codes and typed impact at every emission site. Audit every diagnostic creator: broad-query guidance is advisory; unsupported adapters/features and incomplete discovery are incomplete; invalid Rust-constructed plans are invalid; cancellation and all work/output limits are incomplete/truncated. Add a helper that derives query completion without parsing message text. Update Rust text/JSON, Python, VS Code result types, and behavior tests only where the serialized contract changes.

Implement `finding.rs`, `identity.rs`, and `evaluator.rs` with public run/finding/completion/certainty/location/evidence/work types. Build the versioned stable anchor from structured result fields and exact source ranges, not regex or line-number text. Implement match evaluation over accepted terminal domains, full-detail ranges, source-slice hashing, semantic owner identities, deterministic duplicate ordinals, bounded provenance, and conservative proof/certainty mapping. File results produce artifact-only locations; receiver-analysis terminal queries fail policy validation.

Add `tests/policy_match_evaluation.rs` using `InlineTestProject`. Prove complete finding, complete no-finding, advisory broad query still complete, unsupported feature with `truncated=false` still inconclusive, limits/cancellation incomplete, invalid plan failed, partial positive findings retained without clean completion, every accepted result domain location, receiver-analysis rejection, Unicode ranges, Windows-style normalization, deterministic ordering, and stable/changing fingerprint cases. Explicitly prove no public/context-free raw-row conversion exists and no endpoint document can emit a finding merely because its selector matched. Update the plan, review, and checkpoint the milestone.

### Milestone 4: classification and CVSS v4.0

Implement `classification.rs` as a deterministic projection from complete typed endpoint-pair/typestate evidence and ordered declarative refinements. Preserve the fallback broad classification even when no refinement applies. Require incoming #824 projection facts to contain only semantically dominance-resolved endpoint identities, validate them against the loaded dependency/precedence manifest, and then resolve explicit finding-combination presentation before report grouping: one actual source/sink pair receives either one unique explicit winner or the generated default, never both; an ambiguous live presentation winner is a policy failure. Produce the exact fixed can-reach message from endpoint display phrases, with no interpolation parser. Validate complete `TypestatePolicyProjectionFacts` and keep error-transition versus terminal-expectation violations distinct. Implement `cvss.rs` with typed metrics, evidence/provenance, coherent scenario grouping, assessment variants, display selection, components, and scored/unscored results. Add `cvss = { version = "2.2.0", default-features = false, features = ["std", "v3", "v4"] }`; use it for CVSS v4 vector parsing, canonicalization, nomenclature, and scoring rather than reimplementing the algorithm. The otherwise-unused `v3` feature is a compile-time workaround for `cvss` 2.2.0's public `MetricType` referencing its feature-gated v3 module; it does not add a Bifrost CVSS v3 policy surface.

Reject authored numeric scores, Base `X`, metric/value mismatches, incomplete Base scoring, vector/recomputed-score mismatch, incompatible evidence splicing, and silent provider-order conflict resolution. Preserve established/missing metrics and reasons in `Unscored`. Compute Base and applicable Threat/Environmental component projections from coherent evidence. Keep organizational risk separate and accept Threat/Environmental/analyst overlays only from evaluation context.

Add `tests/cvss_classification.rs` for all eleven complete Base metrics, every missing Base metric, Base `X`, canonical vector/score recomputation, a valid 0.0/None all-None-impact vector, evidence conflicts and coherent variants, deterministic selection rationale, fallback-without-CWE behavior, network-bound `AV:N`, and downloaded-file non-`AV:N`. Cover category predicates, exact endpoint pairs, generated defaults, explicit combination replacement/no duplicate, supersedes cycles and incomparable winners, message-only hash stability, terminal-expectation projection, the full metric/value/scope and basis-family matrices, the two-dimensional overlay-scope partial order, same-record source-evidence coherence, classification-before-display-retention, non-taint empty scenario sets, overlay/evidence/step/variant caps, and report-limit-independent evidence/variant hashes. Assert the exact pinned FIRST-derived vectors, nomenclatures, scores, and severities in Artifacts and Notes below rather than choosing new representative cases during implementation. Update Cargo lock/license artifacts and run the repository's `cargo deny`/`cargo about` checks. Update the plan, review, and checkpoint the milestone.

### Milestone 5: one canonical report through human, JSON, SARIF, and CLI

Implement `render/human.rs` and `render/sarif.rs` from `PolicyReportDocument` only. Define minimal private SARIF 2.1.0 DTOs, deterministic rule/result/location ordering, Unicode-code-point regions, stable fingerprints, classifications/evidence/CVSS properties, related locations, code flows, and incomplete/unsupported/failed invocation notifications. Vendor the official OASIS SARIF 2.1.0 errata-01 schema at `tests/fixtures/sarif/sarif-schema-2.1.0.json`, pin its SHA-256 `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`, record its source/revision/checksum in a neighboring README, validate the checksum in a test, and validate representative complete, incomplete-empty, partial-finding, scored, and unscored documents offline with dev-only `jsonschema` draft 4.

Add the repeatable policy CLI options, strict-schema switch, endpoint-root rejection, exclusivity checks, explicit output writes, combined reports, threshold behavior, and 0/1/2 statuses. Keep ordinary `run() -> Result` errors distinguishable from policy status instead of collapsing every non-success into status 1. Ensure broken pipes and output write failures are operational errors, and never leave a partially overwritten `--output` file: serialize through the bounded writer to a same-directory temporary file, sync/close it, and atomically replace the destination. If atomic replacement is unavailable or fails, leave any existing destination untouched, remove the temporary file, report the error, and return 2; never fall back to truncate/in-place writing.

Add `tests/policy_rendering.rs` and `tests/bifrost_policy_cli.rs`. Gold human/JSON/SARIF output must carry the same finding IDs, policy IDs/hashes, resolved schema manifests/origins, endpoint pair/combination/terminal identities, locations, severity, certainty, completion, classifications, evidence, and every CVSS variant. Test multiple policies, endpoint dependencies without extra runs, an endpoint passed as a root, explicit versus inferred versions in default/strict modes, duplicate IDs, stdout/file output, CLI exclusivity, every threshold including unrated under `finding`, all statuses, a retained partial report for reportable status-2 load/evaluation causes, stderr-only behavior for encoding/write failures, deterministic reruns, bounded escaped serialization, destination preservation when replacement fails, and schema validation. The decisive mixed-batch case contains one complete threshold finding plus one invalid or unsupported policy: human/JSON/SARIF retain the valid finding through both stdout and `--output`, the one SARIF invocation is unsuccessful with a policy-keyed notification, and exit 2 wins over exit 1. Update the plan, review, and checkpoint the milestone.

### Milestone 6: `.rqlp` authoring experience and executable documentation

Register `.rqlp` as `bifrost-rql-policy` with scope `source.bifrost-rql-policy`, a dedicated icon/file association, language configuration, and a conservative grammar that includes nested `source.bifrost-rql` patterns only inside selector forms. Add `bifrost/validatePolicy` and `bifrost/policyHover` source-only LSP methods, policy diagnostics/debounce/hover in the extension, and formatter support in `src/lsp/handlers/formatting.rs`. Reuse generic controller/types where appropriate but keep query and policy methods/language IDs distinct. Do not make `.rqlp` satisfy the `bifrost.runRqlQuery` menu condition or publish findings into the RQL result tree.

Add editor tests for policy and endpoint document association, grammar vocabulary, nested RQL highlighting, inferred/explicit/deferred schema hover and optional-version completion, exact validation ranges, stale-request cancellation, formatting/comment/version-omission preservation, and absence of the query-run command. Keep all RQLP vocabulary in the Rust schema registry and test the grammar as a conservative view, not an independent exhaustive schema table.

Add `docs/src/content/docs/static-analysis-policies.md` and update the static-analysis-rule, RQL, VS Code, CLI, reproducibility, and result-safety pages. State explicitly that a query candidate/endpoint match is not a diagnostic and co-presence is not reachability. Document both RQLP document kinds, all three policy variants, compatible omitted versus pinned schema versions, selector precedence/references, one-document-per-file, explicit endpoint-directory/category composition, endpoint and combination supersedes semantics, generated defaults, catalog registration, typestate endpoint/terminal reuse, complete/no-finding versus inconclusive, finding identity, human/JSON/SARIF parity, CVSS evidence rules, and CLI statuses. Add executable `.rqlp` match examples and checked endpoint/taint/typestate canonical outputs; future taint/typestate execution examples must say unsupported until #824.

Keep `.agents/plans/language-agnostic-composable-typestate-platform.md` synchronized if implementation changes the reviewed contract; the planning-time S-expression decision and removal of JSON-as-authoring examples are already complete and must not be reintroduced as milestone work. Build and link-check the docs, start a fresh preview, and visually inspect the rendered policy page, examples, tables, callouts, and navigation. Update the plan, review, and checkpoint the milestone.

### Milestone 7: adversarial review and complete validation

Review the complete diff for duplicated parsers/keyword tables, reparsed selector strings, unsafe version fallback, unbounded input/recursion, path escape/directory TOCTOU/symlink mistakes, nondeterministic hash-map iteration, endpoint/category/manifest collisions, implicit or order-based precedence, mutable identity inputs, coordinate off-by-one/Unicode errors, lost query incompleteness, endpoint/co-presence rendered as reachability, partial results rendered clean, taint pair-product plan types, categories/messages leaking into solver or summary keys, unresolved typestate specs rescanned by adapters, fake terminal error transitions, leaked internal protocol/solver types, message-template behavior, authored/trusted CVSS scores, incompatible metric splicing, human/SARIF drift, SARIF line-based fingerprints, unsafe output overwrites, CLI status precedence, query/editor cross-contamination, and stale public docs. Fix every accepted finding and add a regression before final gates.

Run focused suites, formatting, strict all-target/all-feature Clippy, the complete feature-enabled Rust matrix, Python and VS Code suites, docs check/build/link validation, dependency-license checks, and `git diff --check`. Render and inspect the final docs page. Record exact test counts/results, any host-specific supported test path, dependency/license evidence, review fixes, final schema examples/hashes, and the #824/#825 handoff in this plan. Make the final reviewed checkpoint commit without pushing or opening a pull request unless explicitly requested.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/cd85/bifrost` on `709-create-static-analysis-policy-format`. The branch began clean at `3bd7b75a`, equal to both its upstream and `origin/master` after the 2026-07-17 fetch. Do not create/switch branches, rebase, push, or open a pull request unless explicitly requested. Once implementation starts under this ExecPlan, stage only milestone files and make the required multiline rationale checkpoint after every implemented milestone and post-milestone review.

Start each milestone with:

    git status --short --branch
    git diff --check

Use focused commands as the corresponding files appear:

    cargo test analyzer::structural::query
    cargo test --test policy_source
    cargo test --test policy_loading
    cargo test --test policy_match_evaluation
    cargo test --test cvss_classification
    cargo test --test policy_rendering
    cargo test --test bifrost_policy_cli
    cargo test lsp::
    npm --prefix editors/vscode test
    npm --prefix docs run check
    npm --prefix docs run build

Milestone 5 adds a checked miniature workspace at `tests/fixtures/policy-cli/project/` with `src/app.py`, `policies/dynamic-eval.rqlp`, `policies/no-exec.rqlp`, `policies/resource-lifecycle.rqlp`, an inferred-version policy twin, and `policies/endpoints/` source/sink leaves. The source contains this violation at line 2:

    def run(user_code):
        return eval(user_code)

After `cargo build --bin bifrost`, run this acceptance transcript from the repository root. The annotations after each command are expected observations, not shell syntax:

    target/debug/bifrost \
      --root tests/fixtures/policy-cli/project \
      --policy-file policies/dynamic-eval.rqlp

Expected stdout begins with:

    src/app.py:2:12: [warning] bifrost.security.dynamic-eval: Dynamic evaluation is forbidden
      finding: <64 lowercase hex characters>
      analysis: match (definite, complete)
      evidence: structural_match call
    summary: 1 finding; 1 complete policy run

Expected process status: `1`, because the default `warning` threshold was met and the run was complete.

    target/debug/bifrost \
      --root tests/fixtures/policy-cli/project \
      --policy-file policies/no-exec.rqlp

Expected stdout: `summary: 0 findings; 1 complete policy run; clean`. Expected status: `0`.

    target/debug/bifrost \
      --root tests/fixtures/policy-cli/project \
      --policy-file policies/inferred-dynamic-eval.rqlp \
      --require-explicit-schema-versions

Expected report diagnostics name the inferred policy and inline-RQL paths, human output does not claim a clean run, and status is `2`. Running the same file without the strict flag succeeds normally and prints one concise note that policy schema 1 and RQL schema 2 were inferred.

    target/debug/bifrost \
      --root tests/fixtures/policy-cli/project \
      --policy-file policies/endpoints/http-request-parameter.rqlp

Expected report diagnostic: `not executable endpoint`; no rule/finding/run is fabricated. Expected status: `2`.

    target/debug/bifrost \
      --root tests/fixtures/policy-cli/project \
      --policy-file policies/resource-lifecycle.rqlp

Expected stdout names `bifrost.test.resource-lifecycle`, says `unsupported: typestate policy compilation`, and never says clean. Expected status: `2`.

    target/debug/bifrost \
      --root tests/fixtures/policy-cli/project \
      --policy-file policies/dynamic-eval.rqlp \
      --format json \
      --fail-on never

Expected JSON contains one rule descriptor, one complete run, one match finding, the same 64-hex ID as human output, and `"completion":{"type":"complete"}`. Expected status: `0` because `never` disables the finding threshold, not completeness checks.

    target/debug/bifrost \
      --root tests/fixtures/policy-cli/project \
      --policy-file policies/dynamic-eval.rqlp \
      --format sarif \
      --fail-on never

Expected SARIF contains `"version":"2.1.0"`, rule ID `bifrost.security.dynamic-eval`, `columnKind` `unicodeCodePoints`, the same primary region, and `partialFingerprints.bifrostFinding/v1` equal to the human/JSON ID. It validates against the pinned offline schema and exits `0`.

Milestone 6 verifies and previews the rendered documentation with:

    npm --prefix docs run check
    npm --prefix docs run build
    npm --prefix docs run check:links
    npm --prefix docs run dev -- --host 127.0.0.1 --port 4321

Open `http://127.0.0.1:4321/static-analysis-policies/` in a fresh browser preview. Expected: the page is in navigation, both document kinds, all three policy variants, schema inference/pinning, endpoint-directory composition, generated/specific messages, typestate terminal expectations, and CLI outputs render without horizontal clipping; code blocks match checked fixtures; the query/endpoint-versus-diagnostic warning is visible; and no local/external link check fails. Stop the preview after inspection.

Run Rust lint/test gates through managed isolated targets when practical:

    cargo fmt
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python

If the host's Python extension configuration cannot link the combined Rust test matrix, record that exact failure and use the repository-supported `scripts/test_python.sh` plus the complete `--features nlp` Rust suite; do not silently count zero-test feature gates as coverage. Tests must disable real semantic model downloads/indexer threads.

After dependency changes, reproduce CI license checks with the pinned tools from `.github/workflows/ci.yml`:

    cargo deny --config licenses/deny.toml --locked check licenses
    cargo about generate --offline --config licenses/about.toml --features python --locked --fail licenses/about.hbs -o /tmp/THIRD_PARTY_LICENSES.html
    cmp licenses/THIRD_PARTY_LICENSES.html /tmp/THIRD_PARTY_LICENSES.html
    node scripts/generate-supplemental-third-party-notices.mjs /tmp/SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt
    cmp licenses/SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt /tmp/SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt

Acquire and verify the test-only SARIF schema once during milestone 5 (the committed fixture makes later tests offline):

    curl -fsS \
      https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json \
      -o tests/fixtures/sarif/sarif-schema-2.1.0.json
    shasum -a 256 tests/fixtures/sarif/sarif-schema-2.1.0.json

Expected checksum: `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`. If it differs, stop and inspect the retrieved response/revision rather than updating the pin silently. Add the neighboring provenance README with `apply_patch`.

Do not create manually named Cargo targets under `/tmp` or `/private/tmp`. Use `scripts/with-isolated-cargo-target.sh`, and use `scripts/cleanup-bifrost-tmp.sh` only according to the repository cleanup instructions.

## Validation and Acceptance

### Format and source behavior

- Exactly one top-level `(policy ...)` or `(endpoint ...)` is accepted per `.rqlp`; a runnable policy has required reporting metadata and exactly one analysis variant, while an endpoint has one diagnostic-neutral role/selector/binding/category definition and no policy severity.
- Match, taint, and typestate examples parse into a tagged `PolicyAnalysis` whose normalized authored JSON contains exactly `analysis.type = match|taint|typestate`; endpoint JSON is the distinct document variant. Composition-free inline/local fixtures also have a complete canonical semantic projection in Milestone 1, while source forms that require files, endpoint predicates, or composed dependencies gain that projection only from the Milestone 2 loaded model. Fields owned by another document/analysis variant fail at their field range.
- Omitted policy/endpoint versions resolve to compatibility head 1 and omitted RQL to head 2. Explicit versions are exact and never fall back. Explicit/omitted forms resolving equally have equal canonical semantics/hash but different source hash/origin; strict CLI mode rejects inferred versions. All `rql-file` wrapper/document precedence cases are exact.
- Inline selectors remain native AST children. After loading, inline and file selectors lower to equal policy-query semantic projections and hashes; the projection contains the resolved query schema and canonical plan but excludes query execution controls (`limit` and `result-detail`). Schema origin and referenced source identity/path remain provenance only. Neither selector is reparsed during evaluation.
- Unknown/duplicate fields, IDs, categories, endpoints, combinations, set entries, states, events, transitions, terminal expectations, refinements, catalogs, and selector controls fail deterministically with exact byte ranges and stable codes.
- Formatting is idempotent, preserves comments/string content/version omission, and produces readable large vectors of tagged records. No YAML, JSON authoring, anchors, aliases, implicit scalar types, free-form message interpolation, raw-string mini-parser, or private keyword list exists.
- Every input layer has bounded bytes, depth, node count, collection entries, strings, referenced documents, and diagnostics; traversal over untrusted policy/query structures is iterative or explicitly bounded.

### Loading, identity, and catalogs

- Explicit `.rqlp`, referenced `.rql`, catalog, and match-directory paths cannot escape the workspace lexically or through symlinks, use wrong file kinds, exceed limits, or depend on the process working directory.
- There is no ambient policy/catalog/endpoint scan, environment lookup, or network load. Only an authored `match-directory` triggers bounded endpoint traversal. Embedding bytes have an explicit stable source label and cannot use file/directory selectors without a workspace context.
- Match-directory traversal is lexical, transactional, race-checked, symlink-free, endpoint-only, category/role filtered, and optionally manifest pinned. Selected endpoint changes affect the aggregate semantic hash; unselected endpoint edits do not. Imported endpoints create no rule or run.
- Source hashes change with comments/formatting; semantic hashes do not. Semantic hashes change with resolved schema versions, typed metadata/analysis, referenced selector semantics, selected endpoint manifests, behavior/precedence rules, or resolved catalog manifests. Presentation-only endpoint edits preserve the analysis-projection hash. Duplicate policy/endpoint IDs and same-ID/different-hash collisions are rejected regardless of source path.
- Catalog and endpoint registration is content-addressed and deterministic. Same selected identity/hash through overlapping refs is idempotent with bounded provenance; same identity/different hash is an error; optional pins are enforced. Composition rejects conflicting IDs, missing supersedes targets/cycles/ambiguous winners, and empty resolved source/sink sides.
- The three-source/four-sink fixture remains one resolved set-oriented public specification and contains no twelve-element pair-plan representation.

### Evaluation and reporting soundness

- A raw query/analysis row has no policy severity or message. Only context-requiring evaluation against a `LoadedPolicy` produces `PolicyFinding`.
- A raw endpoint match and source/sink co-presence are not reachability. Imported endpoint documents never emit findings; passing one as an execution root is status 2.
- Complete positive, complete negative, inconclusive, unsupported, and operational failure are distinct. An empty incomplete/unsupported result is never rendered or exited as clean.
- Broad-query advice remains complete when no other issue exists. Unsupported adapters/features, incomplete discovery, limits, cancellation, and invalid plans have typed non-advisory impacts without message matching.
- All accepted match terminal domains produce the documented primary location; receiver-analysis terminal output is rejected. Exact query evidence/provenance remains bounded and indicates truncation separately from analysis completion.
- Strong finding IDs survive unrelated preceding line insertion that neither changes selected bytes nor adds an equal earlier anchor, and survive report metadata/CVSS changes. They change when the selected semantic/source anchor or equal-anchor ordinal changes, exclude absolute paths/coordinates, and appear identically in JSON and SARIF partial fingerprints. Weak IDs are labeled and omitted from SARIF partial fingerprints.
- One set-oriented taint run reports only actual compatible endpoint meetings. Each actual endpoint pair has one generated-default or uniquely dominant explicit presentation, never both; message edits do not create a second solver run or churn the pair anchor.
- Typestate compilation consumes stored resolved endpoint selector/model/terminal dependencies. Receiver/return/argument/matched-value bindings and typed observation phases survive composition; accepting states are non-absorbing; terminal expected states are accepting subsets; only normal/exceptional analysis-root exits are implicit terminals; and helper returns remain transfers. #824 computes the binding-plan hash only after semantic dominance/remapping. Distinct violation sites/scenario sets and error-transition versus terminal-expectation kinds cannot collide, while categories/messages never enter protocol/summary keys.
- Human, JSON, and SARIF output are deterministically ordered and preserve identical policy/finding IDs, resolved schema/endpoint/precedence manifests, locations, severity, certainty, completion, classification, evidence, witnesses, and CVSS variants.

### CVSS and SARIF

- No input accepts a numeric CVSS score. All eleven Base metrics and no Base `X` are required for a number; every incomplete case is retained as unscored/unrated with exact missing/conflicting evidence.
- Vector canonicalization and component scores recompute from typed evidence. Complete coherent conflicts remain separate variants; incompatible evidence is not averaged, spliced, or resolved by provider order.
- Tests distinguish a network-bound vulnerable service from content merely delivered over a network. Static reachability never guesses missing exploitability, impact magnitude, system boundary, Threat, Environmental, or organizational-risk values.
- SARIF output validates offline against the pinned official 2.1.0 schema. Rule IDs are policy IDs; finding fingerprints exclude line numbers; locations/related locations/code flows map correctly; incomplete empty runs carry stable invocation notifications; `baselineState` is absent.
- The CLI returns 0, 1, or 2 exactly as documented, with status 2 taking precedence. A retained partial report is emitted for reportable load/evaluation failures—including incremental finding/secondary-diagnostic retention exhaustion—when serialization and writing succeed. Mandatory skeleton preflight failure, serialization/encoding, broken-pipe, and write/replace failures are stderr-only status 2. `--fail-on finding` includes unrated findings, and an explicit output write either atomically replaces the destination or leaves the previous destination untouched.

### Editor and documentation

- `.rqlp` is recognized only as `bifrost-rql-policy`, receives policy/endpoint validation, schema-resolution hover, formatting, and highlighting, and is never eligible for the RQL run-query command or query-results view.
- Nested selector grammar/diagnostics use RQL vocabulary without copying the policy or query schema into TypeScript-only tables.
- The rendered docs distinguish exploratory queries, policy diagnostics, and future diagnostic-neutral solver results; all commands, formats, statuses, completeness rules, CVSS rules, and handoff boundaries match executable fixtures.
- Match examples execute end to end. Taint/typestate examples parse and validate but visibly report unsupported evaluation until #824; no documentation implies otherwise.

## Idempotence and Recovery

Parsing, validation, hashing, policy evaluation, and rendering are read-only over policy and workspace sources. Re-running them is safe and deterministic for the same analyzer snapshot and evaluation context. Tests use inline projects/tempdirs and leave only ordinary Cargo/Node build products.

Registry registration is transactional: validate and hash a complete policy/endpoint/catalog/dependency closure before inserting it. A failed registration leaves no partial identity reservation. Re-registering identical catalog/selected endpoint content is a no-op; conflicting content returns an error without replacing the original. Multi-policy CLI loading first collects every valid definition/dependency and every report diagnostic, removes all members of a duplicate policy-ID group, then evaluates only unique runnable policies. The final report retains those runs plus the load diagnostics and exits 2, so a late invalid file cannot make a partial batch look authoritative.

For `--output`, serialize through the bounded writer into a same-directory temporary file before opening/replacing the destination. After a successful close/sync, atomically replace the destination. If the platform cannot provide that replacement or it fails, leave any existing destination untouched, clean the temporary file, return status 2, and do not retry by truncating or writing in place. Stdout mode first renders into a bounded in-memory buffer so a size/encoding failure emits no partial machine document, then writes that buffer once; a broken pipe is still an operational status-2 error and never mutates the workspace.

If loading/evaluation exhausts work or is cancelled, preserve bounded positive findings/evidence where the underlying operation can do so, mark run/finding completion accurately, and return status 2. Never retry with wider implicit limits, an older schema decoder, or a textual fallback. If a selector/catalog/match-directory path or capability is unavailable, return a typed error/unsupported result; do not scan source text or search alternate directories.

If a milestone exposes a format flaw, update this plan's Decision Log and canonical examples before changing code. There is no backward-compatibility burden before the first release, so prefer a clean schema correction to aliases or permissive fallback parsing. Once a checkpoint is committed, recover by fixing forward on the current branch; do not reset unrelated user work.

## Artifacts and Notes

Canonical authoring fixtures:

    tests/fixtures/policies/dynamic-eval.rqlp
    tests/fixtures/policies/attacker-controlled-to-sensitive-sinks.rqlp
    tests/fixtures/policies/resource-lifecycle.rqlp
    tests/fixtures/policies/endpoints/http-request-parameter.rqlp
    tests/fixtures/policies/endpoints/sensitive-user-pii.rqlp
    tests/fixtures/policies/endpoints/resource-acquire.rqlp
    tests/fixtures/policies/endpoints/resource-close.rqlp

Canonical generated/report golds should live beside focused test data rather than public docs when large. Keep the pinned SARIF schema and its provenance note under `tests/fixtures/sarif/`. It is the OASIS errata-01 schema from `https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json`, declares JSON Schema draft 4, and must hash to `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`. Docs copy only compact checked examples and link to the complete contract.

Pin these CVSS golds from the FIRST CVSS v4.0 Examples document version 1.8 (the version reviewed on 2026-07-17). Tests must parse and canonicalize the complete vector, assert the named projection's nomenclature, score, and severity, and independently construct that projection through Bifrost's typed evidence reducer:

| Projection | Canonical vector | Expected |
| --- | --- | --- |
| CVSS-B | `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` | `7.3 High` |
| CVSS-BT | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U` | `5.2 Medium` |
| CVSS-BE | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N/CR:H/IR:L/AR:L/MAV:N/MAC:H/MVC:H/MVI:L/MVA:L` | `8.1 High` |
| CVSS-BTE | `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/MAC:L/MAT:N/MVC:N/MVI:N/MVA:L` | `5.5 Medium` |
| CVSS-B all-None impact | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N` | `0.0 None` |

The first four are fixed conformance cases from the FIRST examples; the final vector is the explicit FIRST Base-score-zero rule exercised against the library. If FIRST changes the examples document, update only after recording the new source revision and explaining any changed expected value in this plan; do not silently bless the library's current output.

The canonical data flow is:

    explicit .rqlp policy/endpoint bytes
      -> bounded spanned S-expression document
      -> compatibility-resolved RqlpDocument
      -> selectors lowered once to CodeQuery
      -> capability-rooted catalog + explicit endpoint-directory composition
      -> LoadedPolicy + resolved schema/catalog/endpoint/precedence manifests
      -> PolicyEvaluator(policy, context, budget)
      -> complete endpoint-pair / typestate projection facts
      -> PolicyRun / PolicyFinding
      -> bounded PolicyReportBuilder
      -> PolicyReportDocument schema_version 1
      -> bounded human | canonical JSON | SARIF 2.1.0 writer

The ownership boundary is:

    #709  public policy/endpoint authoring, schema/category/directory loading,
          syntactic catalog/endpoint composition and precedence, resolved taint/typestate
          authoring specs, identity, generated messages, findings, completion, generic
          classification/CVSS algebra and reducer, match evaluation, human/JSON/SARIF,
          CLI/editor authoring
    #821  diagnostic-neutral set-oriented taint plans, propagation, findings, witnesses
    #822  diagnostic-neutral internal ProtocolSpec and typestate findings
    #824  semantic selector/binding compilers, same-site endpoint dominance, analysis-specific
          complete projection evidence, query analysis domains, protocol registration, and
          adapters from #821/#822 results into #709 PolicyFinding
    #825  TypeScript/Java cross-surface pilot and internal/query/policy/report parity

Normative external contracts used during implementation:

- OASIS SARIF 2.1.0 specification and errata schema: `https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html` and `https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json`.
- FIRST CVSS v4.0 specification, examples version 1.8, user guide, and data representations: `https://www.first.org/cvss/v4.0/specification-document`, `https://www.first.org/cvss/v4.0/examples`, `https://www.first.org/cvss/v4.0/user-guide`, and `https://www.first.org/cvss/data-representations`.
- RustSec `cvss` v4 implementation, version 2.2.0 at planning time: `https://docs.rs/cvss/2.2.0/cvss/v4/`.

## Interfaces and Dependencies

The shared S-expression module is crate-internal. It must expose the existing spanned `Expr`, `ExprKind`, parser result/error, and generic formatter without making policy types depend on the structural analyzer. RQL and RQLP both call it, while Rune IR formatting may reuse only the formatter. Preserve a bounded document parse entry point and an expression-subtree entry point; do not expose a source-text reconstruction API as the way to lower a subtree.

In `src/analyzer/structural/query/sexp.rs`, provide an AST lowering seam equivalent to:

    pub(crate) fn query_expr_to_json(expr: &Expr) -> Result<serde_json::Value, QueryError>;

    pub(crate) fn code_query_from_expr(
        expr: &Expr,
        version: SchemaVersionResolution,
    ) -> Result<CodeQuery, QueryError>;

The exact error type may reuse or extend the current query error, but it must retain a semantic path and the original expression range. `CodeQuery::from_sexp(&str)` remains the ordinary full-document API and delegates with the RQL implicit lineage head, preserving current unversioned-RQL behavior.

In `src/analyzer/policy/schema.rs` and the RQL schema registry, define bounded static descriptors equivalent to:

    struct SchemaVersionDescriptor {
        version: u32,
        implicit_predecessor: Option<u32>,
        inference: SchemaInference,
    }

    enum SchemaInference { AutoCompatible, ExplicitOnly }

Registry validation rejects duplicate versions, missing predecessors, cycles, and more than one implicit head. Today policy/endpoint documents register only auto-compatible version 1 and RQL registers only auto-compatible version 2. An implementation/test-only successor can become the head only after conformance golds prove every predecessor source retains identical normalized meaning apart from its emitted version field.

In `src/analyzer/policy/source.rs`, define these source-facing functions:

    pub fn parse_rqlp_source(
        source: &str,
        identity: PolicySourceIdentity,
    ) -> Result<ParsedRqlpDocument, PolicySourceError>;

    pub fn validate_rqlp_source(source: &str) -> Vec<PolicySourceDiagnostic>;

    pub fn rqlp_source_help_at(
        source: &str,
        byte_offset: usize,
    ) -> Option<PolicySourceHelp>;

    pub fn format_rqlp_source(source: &str) -> Result<String, PolicySourceError>;

    pub fn format_rqlp_source_with_options(
        source: &str,
        options: &PolicyFormatOptions,
    ) -> Result<String, PolicySourceError>;

`PolicyFormatOptions` has one validated `max_width` field (80 through 120), default 100. Formatting requires a syntactically complete S-expression tree but not a schema-valid document: known records use schema-aware grouping and an unknown/wrong-variant field falls back to deterministic generic list grouping, so an author can format while fixing validation errors. It preserves omitted versions rather than silently pinning them. An incomplete or syntactically invalid buffer returns a parse error; the LSP adapter preserves the existing editor contract by returning no formatting edit rather than replacing the user's buffer. `ParsedRqlpDocument` contains the typed policy/endpoint union, resolved top-level version and origin, source map, and unresolved file-selector references. The workspace loader resolves file selectors and constructs `LoadedPolicy` or `LoadedEndpoint`. Diagnostics contain stable code, severity, message, byte range, optional fix, and optional related source/range. Validation of an unsaved buffer never reads the workspace or match directories; an `rql-file`/`match-directory` is shape-validated there and resolved only by the loader surface that has a workspace.

In `src/analyzer/policy/loading.rs`, define a reusable loader boundary and registry:

    pub struct PolicyRegistryLimits {
        max_policies: usize,
        max_endpoints: usize,
        max_match_directories_per_policy: usize,
        max_match_directory_depth: usize,
        max_match_directory_candidates: usize,
        max_retained_source_and_selector_bytes: usize,
    }

    impl Default for PolicyRegistryLimits { /* 256; 4,096; 64; 32; 4,096; 128 MiB */ }

    pub struct WorkspaceRoot {
        display_path: PathBuf,
        directory: cap_std::fs::Dir,
    }

    impl WorkspaceRoot {
        pub fn open(path: &Path) -> Result<Self, WorkspaceDocumentError>;
    }

    pub(crate) fn read_workspace_document(
        root: &WorkspaceRoot,
        relative_path: &Path,
        allowed_extensions: &[&str],
        max_bytes: u64,
    ) -> Result<WorkspaceDocument, WorkspaceDocumentError>;

    impl PolicyRegistry {
        pub fn new_without_workspace(
            catalogs: Arc<TaintCatalogRegistry>,
            limits: PolicyRegistryLimits,
        ) -> Self;

        pub fn new_for_workspace(
            workspace_root: PathBuf,
            catalogs: Arc<TaintCatalogRegistry>,
            limits: PolicyRegistryLimits,
        ) -> Result<Self, PolicyRegistryError>;

        pub fn load_policy_path(
            &mut self,
            relative_path: impl AsRef<Path>,
        ) -> Result<&LoadedPolicy, PolicyRegistryError>;

        pub fn register_policy_bytes(
            &mut self,
            identity: PolicySourceIdentity,
            bytes: &[u8],
        ) -> Result<&LoadedPolicy, PolicyRegistryError>;

        pub fn load_endpoint_path(
            &mut self,
            relative_path: impl AsRef<Path>,
        ) -> Result<&LoadedEndpoint, PolicyRegistryError>;

        pub fn register_endpoint_bytes(
            &mut self,
            identity: PolicySourceIdentity,
            bytes: &[u8],
        ) -> Result<&LoadedEndpoint, PolicyRegistryError>;

        pub fn policies(&self) -> impl ExactSizeIterator<Item = &LoadedPolicy>;

        pub fn endpoints(&self) -> impl ExactSizeIterator<Item = &LoadedEndpoint>;
    }

`PolicyRegistryLimits` fields are private; its default is the schema hard cap and fallible lowering setters mirror the policy-budget builders. The registry charges original document bytes plus every resolved selector source before insertion and rejects the next whole policy, endpoint, or dependency closure before allocation/retention would exceed 128 MiB.

The catalog registry is fully populated before it is wrapped in `Arc` and passed to either constructor; `PolicyRegistry` treats that immutable snapshot as part of its authority and deterministic load context. An explicitly empty registry is still required for match/typestate-only embeddings, so there is no process-global catalog seam. `new_without_workspace` accepts only self-contained byte registrations whose selectors are inline and rejects file/directory references. `new_for_workspace` opens one explicit root and is the only constructor that permits path loading, file selectors, and match directories; byte registration never acquires a root from its source label, process working directory, or environment.

Resolving `MatchDirectoryRef` enumerates regular `.rqlp` files in normalized lexical path order under the explicit workspace-relative directory, directly or recursively as requested. It does not follow symlinked files/directories or consult ignore files. Every candidate must parse as an endpoint document; endpoint leaves cannot reference directories. The loader validates every candidate, category predicate, endpoint-ID collision, supersedes target/DAG, and optional manifest pin transactionally, then re-enumerates before insertion and fails with `DirectoryChangedDuringLoad` if the path set changed. `MatchSetManifestHash` uses domain `bifrost-policy-match-set/v1` over normalized scope, effective role filter, category predicate, and the sorted selected endpoint IDs/full semantic hashes; the directory path is deliberately excluded. Adding/changing a selected endpoint changes it, while changing an unselected endpoint does not. Directory/file paths, source hashes, and pin spelling remain provenance. Same selected ID/hash through overlapping refs is idempotent with bounded multi-origin provenance; same ID/different hash is an error.

During policy load/register, the registry expands catalogs and explicit endpoint sets, lowers all source/dependency selectors, validates precedence, constructs/stores `LoadedPolicy.resolved_taint` or `resolved_typestate`, and includes resolved schema versions, catalogs, endpoints, behavior rules, and selected manifests in the policy semantic hash. It never asks #824 to rescan. If Rust borrowing makes returning an inserted reference awkward, return a stable `PolicyHandle`/`EndpointHandle`; do not return a dense unscoped integer.

In `src/analyzer/policy/catalog.rs`, define `TaintCatalogDefinition`, `TaintCatalogIdentity { name, version }`, `TaintCatalogHash`, `CatalogRef`, and:

    pub struct CatalogRegistryLimits {
        max_identities: usize,
        max_entries: usize,
        max_retained_canonical_bytes: usize,
    }

    impl Default for CatalogRegistryLimits { /* 1,024; 65,536; 64 MiB */ }

    impl TaintCatalogRegistry {
        pub fn new_without_workspace(limits: CatalogRegistryLimits) -> Self;

        pub fn new_for_workspace(
            workspace_root: PathBuf,
            limits: CatalogRegistryLimits,
        ) -> Result<Self, CatalogRegistryError>;

        pub fn register(
            &mut self,
            catalog: TaintCatalogDefinition,
        ) -> Result<TaintCatalogHash, CatalogRegistryError>;

        pub fn register_json_path(
            &mut self,
            relative_path: impl AsRef<Path>,
        ) -> Result<TaintCatalogHash, CatalogRegistryError>;

        pub fn register_json_bytes(
            &mut self,
            source: CatalogSourceIdentity,
            bytes: &[u8],
        ) -> Result<TaintCatalogHash, CatalogRegistryError>;

        pub fn resolve(
            &self,
            reference: &CatalogRef,
        ) -> Result<&RegisteredTaintCatalog, CatalogRegistryError>;
    }

`CatalogRegistryLimits` fields are private and have fallible lowering setters. Each registration incrementally parses/normalizes under the per-document cap, computes its retained canonical size, and transactionally rejects the whole registration before the 64-MiB/entry/identity totals are exceeded.

`register_json_path` is available only on a workspace-backed catalog registry, accepts `.json`, and uses the same opened capability root and 4-MiB same-handle read bound; the context-free registry returns `WorkspaceAccessUnavailable`. Neither registry owns or calls a solver. Canonical catalog JSON is a machine registration contract, not another `.rqlp` authoring frontend.

In `src/analyzer/structural/search.rs`, make diagnostic semantics public and serializable:

    pub enum CodeQueryDiagnosticCode {
        InvalidPlan,
        Cancelled,
        UnsupportedStructuralFeature,
        MissingStructuralAdapter,
        UnsupportedImportAnalysis,
        SemanticResultsOmitted,
        ReceiverAnalysisPartial,
        CallRelationBudgetExhausted,
        CallRelationParseFailed,
        CallRelationCandidatesOmitted,
        CallRelationTargetsAmbiguous,
        CallRelationCandidateLimit,
        CallRelationAnalysisFailed,
        ReferenceSourceBytesTruncated,
        ReferenceCandidateFilesTruncated,
        ReferenceCandidatesOmitted,
        ReferenceTargetsAmbiguous,
        ReferenceCallsiteLimit,
        ReferenceAnalysisFailed,
        UsesParserUnsupported,
        UsesCandidateLimit,
        UsesTargetsAmbiguous,
        UsesCandidatesOmitted,
        ExecutionBudgetExhausted,
        PipelineBudgetExhausted,
        ImportGraphBudgetExhausted,
        ResultLimitReached,
        BroadQuery,
    }

    pub enum CodeQueryDiagnosticImpact {
        Advisory,
        Incomplete,
        Invalid,
    }

    impl CodeQueryResult {
        pub fn completion(&self) -> CodeQueryCompletion;
    }

    pub(crate) struct DetailedCodeQueryResult {
        pub result: CodeQueryResult,
        pub work: CodeQueryExecutionWork,
        pub evidence: Vec<DetailedCodeQueryEvidence>,
    }

    pub(crate) struct DetailedCodeQueryEvidence {
        pub result_index: usize,
        pub domain: DetailedCodeQueryDomain,
        pub key: DetailedCodeQueryKey,
        pub file: ProjectFile,
        pub byte_span: Option<std::ops::Range<usize>>,
        pub stable_owner_candidate: Option<CodeQueryStableOwnerCandidate>,
        pub source_slice_sha256: Option<[u8; 32]>,
    }

    pub(crate) struct CodeQueryStableOwnerCandidate {
        pub namespace: String,
        pub derivation: CodeQueryStableOwnerDerivation,
        pub semantic_key: String,
    }

    pub(crate) enum CodeQueryStableOwnerDerivation {
        AnalyzerDeclarationId,
        CanonicalAstIdentity,
    }

    pub(crate) enum DetailedCodeQueryDomain {
        StructuralMatch, Declaration, File, ReferenceSite, CallSite,
        ExpressionSite, ReceiverAnalysis,
    }

    pub(crate) enum DetailedCodeQueryKey {
        StructuralMatch { kind: String, analyzer_id: Option<String> },
        Declaration { kind: String, fq_name: String, analyzer_id: Option<String> },
        File,
        ReferenceSite { target_id: Option<String>, target_fq_name: String },
        CallSite { caller_fq_name: String, callee_fq_name: String },
        ExpressionSite { input_kind: String, parameter_index: Option<u32>, parameter_name: Option<String> },
        ReceiverAnalysis { analysis_kind: String, outcome: String, capture: Option<String> },
    }

    pub struct CodeQueryExecutionWork {
        pub scanned_files: u64,
        pub scanned_source_bytes: u64,
        pub fact_nodes: u64,
        pub pipeline_rows: u64,
        pub examined_references: u64,
    }

    pub(crate) fn execute_code_query_detailed(
        analyzer: &dyn IAnalyzer,
        query: &CodeQuery,
        limits: CodeQueryExecutionLimits,
        cancellation: Option<&CancellationToken>,
    ) -> DetailedCodeQueryResult;

The detailed search evidence remains diagnostic-neutral and cannot import `analyzer::policy`: it carries native byte ranges, raw SHA-256 bytes, `ProjectFile`, and an explicitly labeled owner candidate only. `policy/evaluator.rs` converts the file to `WorkspaceRelativePath`, validates the candidate with `StableSemanticIdentity::try_new`, wraps the digest in `SourceSliceHash`, and constructs report anchors; a rejected candidate becomes weak rather than being trusted by the search layer.

The code enum has one stable snake-case label per current emission condition. `BroadQuery`, `CallRelationTargetsAmbiguous`, `ReferenceTargetsAmbiguous`, and `UsesTargetsAmbiguous` are advisory when every candidate is retained; they lower affected findings to `Possible`. `InvalidPlan` is invalid. Every cancellation, unsupported/missing capability, omission, parse/analysis failure, candidate/result/work limit, and budget code is incomplete. The impact is assigned in the constructor/emission branch, not inferred later. `CodeQueryCompletion` is `Complete`, `Incomplete { codes }`, `Cancelled`, or `Invalid { codes }`; `truncated` remains serialized for existing callers. `evidence` has exactly one entry per `result.results` item in the same order, and each `result_index` equals its vector index; construction fails an internal invariant rather than dropping/misaligning evidence. Byte spans and source-slice hashes are taken from the same indexed snapshot during that execution. The existing `SearchToolsService`, public/MCP/Python query wrappers, and the policy evaluator all call this crate-private free function once; wrappers discard or expose only the public result as their contract permits, while policy evaluation consumes result, work, and evidence. Counters come directly from the execution budget/tracker and are never reconstructed from diagnostics or measured by rerunning the query.

This audit must remove the lower-level string hole rather than wrap it at the final call site. Change `CallRelationResult.diagnostics: Vec<String>` in `src/analyzer/usages/call_relations.rs` to `Vec<CallRelationDiagnostic>` with codes `BudgetExhausted`, `ParseFailed`, `CandidatesOmitted`, `TargetsAmbiguous`, `CandidateLimit`, and `AnalysisFailed`, plus message/context fields. Preserve `UsageAnalysisDiagnostic.reason_kind` in `FuzzyResult::Failure` instead of forwarding only a reason string. Map `ReferenceCandidateRanges::{Complete, LimitExceeded}` and `DefinitionLookupStatus` directly to the `uses` codes. Add an exhaustive origin test which constructs every code at its producer and asserts its impact; no adapter or test may classify English text.

Promote the existing cooperative token at its source. In `src/cancellation.rs`, make the
type and these methods public:

    pub struct CancellationToken { /* existing fields remain private */ }

    impl CancellationToken {
        pub fn new() -> Self;
        pub fn cancel(&self);
        pub fn is_cancelled(&self) -> bool;
    }

Re-export it from the crate root in `src/lib.rs` with
`pub use crate::cancellation::CancellationToken;`. Then import that root re-export from
`src/analyzer/policy/evaluator.rs` and define:

    pub struct PolicyEvaluationContext<'a> {
        pub analyzer: &'a dyn IAnalyzer,
        pub cancellation: Option<&'a CancellationToken>,
        pub cvss_overlays: &'a [CvssEvaluationOverlay],
        pub organizational_risk: &'a [OrganizationalRiskOverlay],
    }

    pub enum CvssEvaluationOverlay {
        EnvironmentProfile {
            scope: PolicyOverlayScope,
            evidence: CvssEnvironmentOverlayEvidence,
        },
        ThreatFeed {
            scope: PolicyOverlayScope,
            evidence: CvssThreatOverlayEvidence,
        },
        AnalystOverride {
            scope: PolicyOverlayScope,
            evidence: CvssAnalystOverlayEvidence,
        },
    }

    pub struct CvssEnvironmentOverlayEvidence {
        metric: CvssEnvironmentalOrSupplementalMetric,
        value: CvssMetricValue,
        metadata: CvssOverlayEvidenceMetadata,
    }

    pub struct CvssThreatOverlayEvidence {
        metric: CvssThreatMetric,
        value: CvssMetricValue,
        metadata: CvssOverlayEvidenceMetadata,
    }

    pub struct CvssAnalystOverlayEvidence {
        metric: CvssMetric,
        value: CvssMetricValue,
        metadata: CvssOverlayEvidenceMetadata,
    }

    pub struct CvssOverlayEvidenceMetadata {
        evidence_refs: Vec<EvidenceRef>,
        rationale: String,
        assumptions: Vec<String>,
        assessor_or_tool: String,
        assessed_at: String,
        system_scope: CvssEvidenceScope,
        external_artifact_hash: Option<CvssExternalArtifactHash>,
    }

    impl CvssMetricValue {
        pub fn try_new(
            metric: CvssMetric,
            token: CvssMetricValueToken,
        ) -> Result<Self, CvssEvidenceError>;

        pub fn metric(&self) -> CvssMetric;
        pub fn token(&self) -> CvssMetricValueToken;
    }

    impl CvssOverlayEvidenceMetadata {
        pub fn try_new(
            evidence_refs: Vec<EvidenceRef>,
            rationale: String,
            assumptions: Vec<String>,
            assessor_or_tool: String,
            assessed_at: String,
            system_scope: CvssEvidenceScope,
            external_artifact_hash: Option<CvssExternalArtifactHash>,
        ) -> Result<Self, CvssEvidenceError>;
    }

    impl CvssEnvironmentOverlayEvidence {
        pub fn try_new(
            metric: CvssEnvironmentalOrSupplementalMetric,
            value: CvssMetricValue,
            metadata: CvssOverlayEvidenceMetadata,
        ) -> Result<Self, CvssEvidenceError>;
        pub fn metric(&self) -> CvssEnvironmentalOrSupplementalMetric;
        pub fn value(&self) -> &CvssMetricValue;
        pub fn metadata(&self) -> &CvssOverlayEvidenceMetadata;
        pub fn content_hash(&self) -> CvssEvidenceContentHash;
    }

    impl CvssThreatOverlayEvidence {
        pub fn try_new(
            metric: CvssThreatMetric,
            value: CvssMetricValue,
            metadata: CvssOverlayEvidenceMetadata,
        ) -> Result<Self, CvssEvidenceError>;
        pub fn metric(&self) -> CvssThreatMetric;
        pub fn value(&self) -> &CvssMetricValue;
        pub fn metadata(&self) -> &CvssOverlayEvidenceMetadata;
        pub fn content_hash(&self) -> CvssEvidenceContentHash;
    }

    impl CvssAnalystOverlayEvidence {
        pub fn try_new(
            metric: CvssMetric,
            value: CvssMetricValue,
            metadata: CvssOverlayEvidenceMetadata,
        ) -> Result<Self, CvssEvidenceError>;
        pub fn metric(&self) -> CvssMetric;
        pub fn value(&self) -> &CvssMetricValue;
        pub fn metadata(&self) -> &CvssOverlayEvidenceMetadata;
        pub fn content_hash(&self) -> CvssEvidenceContentHash;
    }

`CvssExternalArtifactHash` is an optional distinct lowercase SHA-256 newtype for the raw signed/feed/profile artifact supplied by the embedding; it is provenance, not the final evidence identity. The basis-specific `try_new` computes `CvssEvidenceContentHash` internally from the overlay variant/basis, metric, validated value, all normalized metadata, and the optional external-artifact hash. Callers cannot submit or spoof the final content hash. Read-only accessors expose the computed evidence hash alongside the fields above.

    pub struct OrganizationalRiskOverlay {
        pub scope: PolicyOverlayScope,
        pub assessment: OrganizationalRiskAssessment,
    }

    impl OrganizationalRiskAssessment {
        pub fn try_new(
            scheme: String,
            rating: String,
            rationale: String,
            evidence_refs: Vec<EvidenceRef>,
            assessor: Option<String>,
        ) -> Result<Self, OrganizationalRiskError>;

        pub fn content_hash(&self) -> OrganizationalRiskAssessmentHash;
    }

`OrganizationalRiskAssessmentHash` is a lowercase 64-hex SHA-256 newtype over the normalized assessment content. Before sorting, selecting, or retaining an overlay, the evaluator compares the input length with `PolicyBudget.max_organizational_risk_overlays`; at most 64 are accepted by the schema-version-1 hard cap. Exceeding the effective bound retains no organizational-risk assessment and makes the affected run inconclusive with `PolicyIncompleteReason::OrganizationalRiskOverlayBudget`, with a structured diagnostic and CLI status 2 rather than silently discarding context. For an in-budget set, apply the same scope partial order as CVSS and retain the one assessment at the unique maximal applicable scope; byte-identical/hash-identical duplicates are idempotent. Different assessments at the same or incomparable maximal scopes fail the run with `ConflictingOrganizationalRiskOverlay` rather than depending on slice order. Lower scopes remain unused context and are not merged. This keeps the single `PolicyFinding.organizational_risk` field deterministic; it never feeds severity, CVSS, identity, or solver state.

    pub enum PolicyOverlayScope {
        AllFindings,
        Policy { policy_id: PolicyId },
        Finding { finding_id: PolicyFindingId },
        SourceScenario { scenario_id: SourceScenarioId },
        FindingScenario { finding: PolicyFindingId, scenario: SourceScenarioId },
    }

    pub trait PolicyEvaluator {
        fn evaluate(
            &self,
            policy: &LoadedPolicy,
            context: &PolicyEvaluationContext<'_>,
            budget: &mut PolicyBudget,
        ) -> Result<PolicyRun, PolicyRunError>;
    }

    pub(crate) trait TaintPolicyEvaluator: sealed::TaintAdapter {
        fn evaluate_taint(
            &self,
            authority: &TaintProjectionAuthority<'_>,
            policy: &LoadedPolicy,
            spec: &ResolvedTaintPolicySpec,
            context: &PolicyEvaluationContext<'_>,
            budget: &PolicyBudget,
        ) -> TaintProjectionPayload;
    }

    pub(crate) trait TypestatePolicyEvaluator: sealed::TypestateAdapter {
        fn compilation_hashes(
            &self,
            policy: &LoadedPolicy,
            spec: &ResolvedTypestatePolicySpec,
            context: &PolicyEvaluationContext<'_>,
            budget: &PolicyBudget,
        ) -> Option<TypestateCompilationHashes>;

        fn evaluate_typestate(
            &self,
            authority: &TypestateProjectionAuthority<'_>,
            policy: &LoadedPolicy,
            spec: &ResolvedTypestatePolicySpec,
            context: &PolicyEvaluationContext<'_>,
            budget: &PolicyBudget,
        ) -> TypestateProjectionPayload;
    }

    pub struct DefaultPolicyEvaluator<'a> {
        taint: Option<&'a dyn TaintPolicyEvaluator>,
        typestate: Option<&'a dyn TypestatePolicyEvaluator>,
    }

    impl<'a> DefaultPolicyEvaluator<'a> {
        pub fn new() -> Self;
        pub(crate) fn with_taint(mut self, adapter: &'a dyn TaintPolicyEvaluator) -> Self;
        pub(crate) fn with_typestate(mut self, adapter: &'a dyn TypestatePolicyEvaluator) -> Self;
    }

The named `new`/`with_taint`/`with_typestate` methods are the normative construction surface: each builder replaces only its corresponding explicit trait object while preserving the other. The future-analysis traits, their builders, authorities, compilation hashes, projection payloads, and sealing traits are crate-private. Downstream callers can run match policies or receive the explicit unsupported taint/typestate result but cannot self-register as a trusted analysis producer. A #824 sibling module returns only an unsealed diagnostic-neutral payload; `DefaultPolicyEvaluator` binds it to the exact freshly minted authority before validation and final assembly. No alternative constructor shape or final-finding authority is left to #824.

`DefaultPolicyEvaluator::new()` installs no future adapters; builder/constructor arguments may install either explicit trait object. It dispatches runnable `Match` itself and returns `Unsupported { TaintEvaluation|TypestateEvaluation }` when the relevant adapter is absent. It passes the exact stored `LoadedPolicy.resolved_taint` or `resolved_typestate`; a missing resolved value is an internal-invariant failed run, never a fallback to the unresolved authoring declaration or an adapter-side directory rescan. #824 implements these two policy-facing traits while keeping compiler/solver types private. The overlay enum fixes the evidence basis and metric family by variant: Threat accepts only FIRST Threat metrics, Environment accepts only Environmental/Modified/Supplemental metrics, Analyst explicitly accepts any typed metric, and callers cannot construct static-witness or policy-assertion overlays. Evidence fields are private and validated constructors require a legal metric/value pair, non-empty evidence/rationale/provider, RFC 3339 assessment time, and a normalized content hash. Overlay vectors use the scope/basis lattice above; equal-highest-rank conflicts produce variants or unscored output, never last-writer-wins behavior. Internal helpers may return private Rust errors, but this boundary converts every recoverable operational failure, including an unavailable workspace snapshot, into a `PolicyRunCompletion::Failed` run with diagnostics, work, and any already retained findings. Only process-level allocation failure/panic or inability to serialize/write the report can escape the canonical report model; the CLI reports those on stderr and returns 2.

In `src/analyzer/policy/identity.rs`, define constructors which accept typed anchors rather than arbitrary strings:

    impl PolicyFindingId {
        pub fn from_match_anchor(
            policy_id: &PolicyId,
            anchor: &MatchFindingAnchor,
        ) -> Self;

        pub fn from_taint_anchor(
            policy_id: &PolicyId,
            anchor: &TaintFindingAnchor,
        ) -> Self;

        pub fn from_typestate_anchor(
            policy_id: &PolicyId,
            anchor: &TypestateFindingAnchor,
        ) -> Self;
    }

    impl PolicySemanticHash {
        pub fn from_resolved_policy(
            definition: &PolicyDefinition,
            analysis: ResolvedPolicyAnalysisRef<'_>,
            selectors: &[ResolvedPolicySelector],
            catalogs: &[ResolvedCatalogIdentity],
            endpoints: &[ResolvedEndpointDependency],
            match_manifests: &[ResolvedMatchDirectoryManifest],
            precedence: &PolicyPrecedenceManifest,
        ) -> Self;
    }

    enum ResolvedPolicyAnalysisRef<'a> {
        Match,
        Taint { spec: &'a ResolvedTaintPolicySpec },
        Typestate { spec: &'a ResolvedTypestatePolicySpec },
    }

`from_resolved_policy` canonicalizes a resolved projection without rerunning composition: it walks the typed definition plus the matching resolved analysis value, materializes every resolved policy/RQL version, replaces every inline/file selector at its `PolicySelectorPath` with only `{ schema_version, canonical CodeQuery }`, replaces catalog/match-directory/exact endpoint source forms and category/pair predicates with their sorted resolved identities and semantic/analysis hashes, and appends the selected and precedence manifests once as integrity cross-checks. Supplying the wrong `ResolvedPolicyAnalysisRef` variant is an internal invariant failure before hashing. Version origin, catalog/reference order and optional pin spelling, directory/file paths, unselected endpoints, raw selector bytes, source hash, selector-form discriminator, and registration source live in provenance and are forbidden hash inputs. Explicit and omitted sources resolving to the same versions hash equally. Endpoint semantic hashes include display/report data, while endpoint analysis-projection hashes exclude it; typestate protocol/binding and taint propagation keys use only the latter plus behavior semantics. Finding constructors use distinct `bifrost-policy-finding/v1/{match|taint|typestate}` domain prefixes, the policy ID, analysis type, and the strong/weak typed fields defined above; they never hash the adapter's opaque `AnalysisFindingId`, generated/static message, selected combination presentation, or severity. Every identity constructor uses existing `sha2` with deterministic length-prefixed fields. Never accept prejoined delimiter strings or platform-native absolute paths.

In `src/analyzer/policy/render/mod.rs`, expose only canonical-report renderers:

    pub fn write_policy_human<W: std::io::Write>(
        report: &PolicyReportDocument,
        options: &HumanRenderOptions,
        output: W,
        max_serialized_bytes: usize,
    ) -> Result<u64, PolicyRenderError>;

    pub fn write_policy_json<W: std::io::Write>(
        report: &PolicyReportDocument,
        output: W,
        max_serialized_bytes: usize,
    ) -> Result<u64, PolicyRenderError>;

    pub fn write_policy_sarif<W: std::io::Write>(
        report: &PolicyReportDocument,
        tool: &SarifToolIdentity,
        output: W,
        max_serialized_bytes: usize,
    ) -> Result<u64, PolicyRenderError>;

Each renderer wraps `output` in a `BoundedWriter` which checks the next write before growing/writing, counts the bytes produced after JSON/SARIF escaping, and returns `SerializedReportLimit` before exceeding `max_serialized_bytes`. JSON and SARIF use `serde_json::Serializer` directly against that writer; they never build an intermediate `serde_json::Value`, DTO string, or escaped copy. Tests may pass a `Vec<u8>`, whose capacity therefore remains bounded. SARIF DTOs remain private to `render/sarif.rs`. No renderer receives `CodeQueryResult`, `TaintFinding`, or `TypestateFinding` directly.

Add runtime dependencies `cap-std = { version = "4.0.2", default-features = false }` for capability-relative, race-resistant workspace reads, `cvss = { version = "2.2.0", default-features = false, features = ["std", "v3", "v4"] }` for scoring, and `url = { version = "2.5.8", default-features = false, features = ["std"] }` for maintained absolute tool-information-URI validation without a handwritten URI parser. The `v3` feature is enabled only because `cvss` 2.2.0's public `MetricType` otherwise fails to compile when v4 is used alone; Bifrost exposes only the planned CVSS v4 policy model. Keep SARIF serialization on existing Serde/`serde_json` and stable hashing on existing `sha2`. Add `jsonschema = { version = "0.48.0", default-features = false }` under dev-dependencies; the test constructs `jsonschema::draft4` directly, needs no file/HTTP resolver, and never performs network access. Any dependency change must update `Cargo.lock`, `licenses/THIRD_PARTY_LICENSES.html`, and supplemental notices when the repository generators say they changed; never hand-edit generated license contents.

Revision note (2026-07-17): Created the initial self-contained plan after fetching live issue #709 and its roadmap dependencies, confirming the clean issue branch/current master, tracing the current RQL/query/load/CLI/editor surfaces, comparing S-expression/YAML/JSON authoring, and reviewing SARIF/CVSS contracts. The plan chooses a distinct S-expression RQLP language with native versioned selectors, canonical JSON only as generated interchange, all public variants parsed, match-only initial execution, typed completeness, evidence-backed CVSS, and one canonical finding model for every renderer. Direct inspection of the tagged RustSec `cvss` 2.2.0 source confirmed vector scoring/nomenclature support and made the per-component projection responsibility explicit.

Revision note (2026-07-17, adversarial planning review): Closed the resolved-taint/registry/compiler seam, generic evidence projection inputs, report schema/version and incremental retained/serialized byte bounds, report-level truncation, all three finding-anchor algorithms, CVSS provenance/precedence/conflict algebra and exact conformance golds, SARIF unrated/URI/invocation semantics, formatter behavior while typing, atomic destination preservation, and mixed status-2 output rules. Removed stale JSON and duplicated public wire mirrors from the umbrella roadmap, recorded the remaining live-issue wording sync as an explicit pre-implementation item, and split Progress into independently recordable implementation stops.

Revision note (2026-07-17, endpoint-composition clarification): Made policy and RQL version pins optional through strict compiled-in compatibility lineages; added diagnostic-neutral categorized endpoint leaves and explicit capability-rooted directory composition; specified endpoint and finding-rule supersedes semantics, generated can-reach messages, uniform endpoint identity, and complete endpoint-pair projection facts; and replaced typestate's one-selector surface with resolved endpoint subject/event sets plus explicit/implicit terminal expectations. Preserved the #709 public composition/reporting versus #821/#822 solver and #824 compiler boundary.

Revision note (2026-07-18, Milestone 4 reviewed implementation): Recorded the evaluator-owned projection seal and production-usable crate-private adapter payload seam, exact pair/terminal/presentation/classification joins, evidence-backed coherent CVSS v4 reduction, full-semantic versus bounded-display correlation, shared evidence/report retention, aggregate prefix retention, and distinct-finding omission accounting. Updated the dependency feature pin for the `cvss` 2.2.0 v3-reference defect and recorded the final 218-unit plus public integration, strict-Clippy, and license-reproducibility evidence after adversarial closure.

Revision note (2026-07-18, Milestone 5 reviewed implementation): Recorded renderer parity through exact typed terminal evidence, structured terminal-safe human detail, canonical bounded JSON, borrowed streaming SARIF, official offline schema conformance, early bounded source-identity validation, deterministic duplicate exclusion, parser-state CLI mode detection, status-2 precedence, and atomic destination preservation. Added the runtime `url` parser and dev-only offline `jsonschema` validator, regenerated license artifacts, and recorded focused, legacy, strict-Clippy, reproducibility, and acceptance-transcript evidence.

Revision note (2026-07-18, Milestone 6 reviewed implementation): Recorded the distinct `.rqlp` VS Code language/icon/grammar, source-only validation and hover, registry-derived optional-version completion, policy-width overlay formatting, executable fixture-backed documentation, exact selector-version and endpoint-registry boundaries, and rendered desktop/narrow preview evidence. Closed documentation projection/reproducibility/reachability/test-harness drift plus the mid-token completion edit-range defect, and recorded the complete LSP/editor/docs/strict-Clippy matrix after independent adversarial closure.

Revision note (2026-07-18, Milestone 7 completion): Recorded total-entry-bounded and direct no-follow directory loading, pre-I/O source-identity validation, shared catalog author-text safety, strict authored help-URI form, typed directory-limit diagnostics, private authority cleanup, executable tutorial synchronization, final schema/dependency/hash values, the complete split feature matrix, exact CLI transcript, and the #824/#825 handoff. Four adversarial audits and their rechecks found no remaining blocker.
