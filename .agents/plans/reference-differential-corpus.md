# Build and run a corpus reference differential

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain it in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost currently learns about false-negative reference resolution after agents encounter them in production. This work adds a dedicated offline engine that audits real repositories by resolving a source reference forward to its declaration and then asking the inverse usage resolver for the same declaration. A reference resolved by the forward path but absent from the inverse path is a concrete disagreement with enough source and identity evidence to reproduce locally. The first campaign runs the engine against the largest available repository in each target corpus language, creates GitHub issues for genuine defects, fixes and closes those issues, and reports the result by language.

## Progress

- [x] (2026-07-12 03:00Z) Inspected repository instructions, current analyzer architecture, benchmark conventions, corpus metadata, clone availability, and the canonical target language registry.
- [x] (2026-07-12 03:00Z) Selected the deterministic N=1 repository for each of the eleven target corpus languages by recorded `code_loc`, restricted to available valid clones.
- [x] (2026-07-12 04:10Z) Implemented shared structured reference-candidate enumeration and the library-owned differential runner.
- [x] (2026-07-12 04:10Z) Implemented the dedicated corpus CLI with deterministic selection, commit-aware resumable JSONL reports, exact-site reruns, and bounded sampling.
- [x] (2026-07-12 04:50Z) Addressed review findings and validated the engine with all-language fixtures plus bounded real-repository preflights.
- [x] (2026-07-12 05:05Z) Committed engine checkpoint `6c056e91`; full `cargo test --features nlp,python`, all-target/all-feature clippy, formatting, and diff checks pass.
- [x] (2026-07-12 05:10Z) Pushed engine checkpoint and plan through `2c0ceff6` to `origin/master`.
- [x] (2026-07-12 11:20Z) Fixed #643's repeated SQLite scans and recursive Rust binding/re-export walks; the exact 512 KiB-stack validation completed in 554.7 seconds with 101,192 KiB peak RSS.
- [x] (2026-07-12 11:35Z) Pushed `4b3f6065`, corrected #643 with the definitive debugger diagnosis and measured validation, and closed it.
- [x] (2026-07-12 12:15Z) Completed the committed-HEAD Rust baseline and triaged all 961 disagreements into forward-focus/scope, inverse-member, and follow-on import/type clusters; filed #644 and #645.
- [x] (2026-07-12 13:05Z) Fixed and corpus-validated #644 and #645; targeted definition/usage suites and all-feature clippy pass.
- [x] (2026-07-12 15:10Z) Pushed `03646ad1`, closed #644/#645, and reran the complete Rust N=1 repository from the fixing HEAD. Missing sites fell from 961 to 628; the record is commit-pinned but reports dirty because unrelated untracked agent/cache artifacts exist in both worktrees.
- [x] (2026-07-12 16:05Z) Triaged all 628 post-fix Rust disagreements. Filed #646/#647 for the dominant cross-file type and `self`/`Self` inverse gaps, and #648/#649/#650 for independently reproduced forward scoped-focus, namespace/prelude, and let-condition defects.
- [x] (2026-07-12 16:30Z) Implemented and behavior-tested #646/#647: nested workspace file modules now retain structured module identity, and Rust class usage emits exact editor-only owner-alias hits with CodeUnit identity checks.
- [x] (2026-07-12 17:25Z) Pushed and closed #646/#647, then fixed, pushed, and closed #648 through the `get_definitions_by_location` symbols surface; no LSP-only acceptance work was retained.
- [x] (2026-07-12 18:20Z) Implemented and symbols-tested #649 with AST namespace roles, tri-state visible imports, exact lexical-module fallback, and a cached Cargo path-dependency route index shared by forward and inverse Rust resolution.
- [x] (2026-07-12 19:05Z) Pushed and closed #649, then implemented and symbols-tested #650 with ordered `let_condition`/let-chain visibility and fully iterative lexical/pattern traversal.
- [x] (2026-07-12 19:45Z) Pushed and closed #650 and completed the next Rust N=1 rerun at `edd7beaa`: missing classifications fell from 628 to 268 while consistent/editor-only coverage rose from 696 to 1,758.
- [x] (2026-07-12 20:00Z) Found and symbols-tested Scala blocker #651 before the cold Scala corpus run: inverse usage now preserves every overload CodeUnit and enforces the usage cap across their merged hit set.
- [x] (2026-07-12 20:35Z) Pushed and closed #651, then removed Rust/C++ cross-language scoped-owner leakage in #654 with mixed-language symbols regressions.
- [x] (2026-07-12 21:05Z) Implemented and symbols-tested #652: named Rust module segments in runtime/type paths now resolve through the structured reference context, while import-only sites and unrelated same-name modules remain excluded.
- [x] (2026-07-12 21:30Z) Implemented and symbols-tested #653 by generalizing the exact scoped-prefix walk from modules to class/type owners; all four corpus shapes and same-name fully qualified negatives are covered through `scan_usages_by_reference`.
- [x] (2026-07-12 22:15Z) Revalidated all six remaining Rust defect boundaries with exact-site runs on current `master`, excluded the expected import-only omission from the production surface, and filed #655-#660 for the surviving public symbols behaviors.
- [x] (2026-07-13 02:20Z) Completed Scala N=1 on `JetBrains__intellij-scala` at `dd63058d`: 1,000/18,936 eligible files, 10,000 sites, 1,000 queried target groups, and 473 missing classifications in 1,761.8 seconds; production-symbol triage is in progress.
- [x] (2026-07-13 02:35Z) Implemented and symbols-tested #656 with a shared position-aware Rust lexical-scope index; inverse scanning no longer suppresses names file-wide and the touched AST walk is iterative.
- [x] (2026-07-13 02:45Z) Implemented and symbols-tested #657: focused nonterminal Rust path segments inside macro token trees now retain owner identity instead of falling through to the terminal associated item.
- [x] (2026-07-13 03:05Z) Triaged all 473 Scala missing classifications into 25 wrong forward identities, 219 genuine inverse omissions, and 229 non-defects/artifacts; exact current-code probes confirmed four production boundaries and #661-#664 were filed.
- [x] (2026-07-13 03:35Z) Implemented and symbols-tested #663 by extending the existing Scala hierarchy-family usage proof from traits to class methods while preserving overload buckets, conflicts, caps, and exact unrelated-base negatives.
- [x] (2026-07-13 03:45Z) Implemented and symbols-tested #655 with AST-derived full focused `use` paths and one exact Rust path-to-FQN resolver shared by forward definition lookup and inverse runtime call proof; import-only sites remain excluded.
- [x] (2026-07-13 03:55Z) Implemented and symbols-tested #664: Scala forward lookup now gives lexical bindings precedence and validates term/type namespace visibility before accepting indexed identities.
- [x] (2026-07-13 04:15Z) Implemented and symbols-tested #660 with shared Rust struct-field AST roles, exact literal/pattern owner proof, lexical `Self`, declaration no-definition behavior, and matching differential sampler exclusion.
- [x] (2026-07-13 04:25Z) Implemented and symbols-tested #662 with AST-level Scala companion-`apply` and infix lowering, exact receiver/owner proof, symbolic-method candidate routing, caps, and unrelated-owner negatives.
- [x] (2026-07-13 04:40Z) Implemented and symbols-tested #659 by reusing forward Rust expression-type resolution on exact inverse receiver nodes, with tri-state owner proof across parameters, typed locals, nested fields, and returned values.
- [x] (2026-07-13 04:55Z) Implemented and symbols-tested #661 by extending Scala hierarchy proof to class fields and resolving named-argument labels through their structured invocation owners; the remaining selection/stable/type roles are pinned with exact-owner regressions.
- [x] (2026-07-13 05:05Z) Implemented and symbols-tested #658 with one exact associated-item resolver across normal and macro token-tree paths, preserving call/value roles, requested identity, import exclusion, and multi-segment owners.
- [x] (2026-07-13 05:20Z) Reopened #659 after its exact corpus site remained missing, then added structured concrete-receiver-to-trait-impl dispatch proof while leaving generic and trait-object receivers unproven.
- [x] (2026-07-13 06:20Z) Reopened #661-#663 after synthetic symbols regressions passed but their exact Scala corpus sites remained missing; generalized callable matching to persisted required/total/repeated arity and propagated structured qualified-call return types into local receiver bindings. Exact public-symbol probes now pass for inherited default arguments, companion `apply` defaults, and call-result member dispatch.
- [x] (2026-07-13 07:00Z) Completed the JavaScript N=1 run on `nodejs__node`: 2,247 forward-resolved sites, 1,720 consistent, 105 raw missing, 8 editor-only, and 90 unproven in 134.2s. Exact public-symbol probes reduced the missing set to five root boundaries filed as #665-#669.
- [x] (2026-07-13 07:15Z) Completed the PHP N=1 run on `moodle__moodle`: 1,888 forward-resolved sites, 1,331 consistent, and 91 raw missing in 311.3s. Public probes partitioned these into three product boundaries (#672-#674) plus nine false missing test sites caused by differential filter drift (#671).
- [x] (2026-07-13 08:15Z) Fixed and exact-validated all five JavaScript boundaries #665-#669: lexical/role precedence, namespace aliases, exported executable bodies and bare calls, CommonJS value roles, and modeled-property provenance. Production probes are now consistent or correctly inconclusive under the local-binding contract, with direct public inverse scans proving the latter sites.
- [x] (2026-07-13 08:25Z) Fixed and exact-validated all PHP boundaries #671-#674: aligned test filtering, prevented cross-language bare lookup, made ambiguous selectors round-trip, and separated workspace hierarchy proof from output path scope.
- [x] (2026-07-13 08:35Z) Profiled the long Go and Python 1,000-target runs after cache construction: Go repeatedly parses scoped graphs; Python repeatedly rebuilds path/module routing. Filed #675 for bounded structured bulk-query reuse, explicitly rejecting SQLite materialization and unbounded syntax-tree caches.
- [x] (2026-07-13 09:00Z) Implemented the measured Python half of #675 by removing per-target transitive import-closure parsing; the immutable `PythonUsageIndex` continues to own routing while exact candidate-plus-target graphs retain public scope and proof behavior. A four-file reachable fixture now parses only the two required files.
- [x] (2026-07-13 09:35Z) Fixed #676 after default and 64 MiB stacks both crashed in TypeScript receiver inference; iterative AST/pattern walks, shared RAII cycle state, bounded semantic proof, and fail-closed qualified calls let the exact default-stack Kibana run complete in 83.9s.
- [x] (2026-07-13 09:50Z) Completed and triaged the TypeScript N=1 run on `elastic__kibana`: 1,017 consistent, 31 missing, 20 editor-only, 82 unproven, and 8,850 inconclusive. Ten exact probes confirmed eight public-symbol boundaries filed as #678-#685.
- [x] (2026-07-13 10:00Z) Stopped the Go run after three hours when GDB proved it had never reached the differential: persisted symbols startup was eagerly rebuilding `DefinitionLookupIndex` through `all_declarations` and reparsing Go content qualifiers. Corrected #675 to Python per-query reuse and filed the distinct warm-start blocker as #677.
- [x] (2026-07-12 20:38Z) Resumed after release `0.7.6`, migrated the Azure PowerShell cache with the required external write access, and found the remaining C# forward amplification: extension visibility performed a generic SQLite parent-definition query for every exact identifier candidate. Replaced it with the persisted member namespace and per-file structural parent map; the fixed warm 1,000-site/100-target smoke completed in 232.1 seconds with a valid record.
- [x] (2026-07-12 20:50Z) Pushed C# parent lookup fix `b842208a` and completed the full Azure PowerShell N=1 record in 425.0 seconds: 3,269 forward-resolved sites, 598 consistent, 40 unproven, 1,339 missing, and 8,023 inconclusive. Initial triage shows 1,304 class/type targets; exact production rerun confirms the dominant fully qualified partial/interface type boundary, but no correctness issue is filed until a reduced authoritative-scope regression pins the resolver gap.
- [x] (2026-07-12 21:11Z) Pinned the first C# correctness boundary with a three-file authoritative-scope regression, filed #698, recognized tree-sitter C#'s `returns` field, and emitted qualified-type hits on their containing AST node. The exact Azure bytes `5677..5693` changed from missing to consistent in 146.7 seconds; focused tests, affected all-feature clippy, and the complete `nlp,python` test gate pass.
- [x] (2026-07-12 21:18Z) Pushed `7ccce3dd` to `master` and closed #698 with the exact Azure evidence; the next C# step is a complete fixing-HEAD rerun before triaging residual sites.
- [x] (2026-07-12 21:31Z) Completed the post-#698 full C# rerun at `3b2e2665` in 486.4 seconds. Consistent sites increased from 598 to 1,717 and missing sites fell from 1,339 to 220; 73 residuals form the next explicit-interface owner declaration boundary.
- [x] (2026-07-12 21:44Z) Delegated and independently reviewed the dominant C# residual, filed #701, recognized `explicit_interface_specifier` as a structured type role, passed the full validation gate, and changed exact `ApiKey.cs` bytes `2898..2913` from missing to consistent.
- [x] (2026-07-12 21:50Z) Pushed `2b617770` and closed #701 with exact and full-suite evidence.
- [x] (2026-07-12 22:12Z) Rejected the first full post-#701 record after it silently lost audited candidate files between forward and inverse phases; filed #703 and made the engine retain the original audited scope or fail explicitly.
- [x] (2026-07-12 22:35Z) Validated #703 with a complete post-#701 C# rerun at `c8524f86`: all 1,000 configured groups were queried, candidate-loss notes fell to zero, and the trustworthy C# missing set fell from 220 to 144.
- [x] (2026-07-12 22:38Z) Pushed `85aa48cd` and closed #703 with stable-scope production evidence.
- [x] (2026-07-12 23:17Z) Delegated and independently reviewed the next 39-site C# cluster, filed #704, treated generic argument lists as their own structured type boundary, passed focused/negative coverage, and changed the exact BillingBenefits site from missing to consistent.
- [x] (2026-07-12 23:24Z) Passed the complete `cargo test --features nlp,python` validation gate for #704; affected all-feature library and C# test clippy targets also pass.
- [x] (2026-07-12 23:27Z) Pushed `cf2743de` and closed #704.
- [x] (2026-07-12 23:49Z) Completed a valid post-#704 full C# rerun: all 1,000 target groups queried with zero candidate-scope-loss notes, and missing sites fell from 144 to 103.
- [x] (2026-07-13 00:10Z) Filed #705 from a reduced failing inventory-observer regression and made exact-site selection validate and point-check one project file without calling the full analyzed-file inventory.
- [x] (2026-07-13 00:26Z) Production-validated #705 on the same BillingBenefits reference: consistent semantics, one truthful eligible/audited file, and runtime reduced from 1,134.4 to 865.2 seconds.
- [x] (2026-07-13 00:31Z) Pushed and closed #705 after safely merging concurrent `master` work and restoring the unrelated Rust test edits.
- [x] (2026-07-13 00:37Z) Reproduced and filed #706 for the 34-site `using static` cluster; shared its structured AST role across inverse scanning and persisted candidate routing and bumped the C# analyzer epoch.
- [x] (2026-07-13 00:54Z) Exact production validation changed MachineLearningServices `PsHelpers` bytes `498..508` from missing to consistent after the expected C# persisted-index rebuild.
- [x] (2026-07-13 00:58Z) Passed the complete `cargo test --features nlp,python` validation gate for #706.
- [x] (2026-07-13 01:01Z) Pushed `2a365fce` and closed #706.
- [x] (2026-07-13 01:19Z) Completed the valid post-#706 full C# run with all 1,000 target groups, zero scope-loss notes, and 69 missing sites, exactly 34 fewer than before the static-import fix.
- [x] (2026-07-13 01:22Z) Paused post-#706 triage at the user's request to cut release `0.8.0`; the 69-site C# record is the explicit resumption boundary.
- [x] (2026-07-13 02:01Z) Resumed the campaign after `v0.8.0` published successfully and delegated the three cast-type families across oldskool and a child read-only reducer.
- [x] (2026-07-13 02:06Z) Filed #707 from a primary failing regression and shared the grammar-specific `as_expression.right` type role across inverse scanning and persisted candidate routing with a C# epoch bump.
- [x] (2026-07-13 02:09Z) Independently confirmed all 33 cast-family class misses share #707: 16 `IAsyncCommandRuntimeExtensions`, 10 `EventData`, and seven `JsonArray`.
- [x] (2026-07-13 02:31Z) Exact Automanage production validation changed the former cast-type miss to consistent after the persisted C# rebuild.
- [x] (2026-07-13 02:34Z) Passed the complete `cargo test --features nlp,python` gate for #707; focused C# and affected all-feature clippy validation also pass.
- [x] (2026-07-13 03:00Z) Pushed `062ae98e`, closed #707, and completed the valid post-#707 C# rerun: all 1,000 targets were queried with zero scope-loss notes, 1,899 consistent, 40 unproven, 38 missing, and 8,023 inconclusive sites in 1,265.0 seconds.
- [x] (2026-07-13 03:20Z) Delegated the 38-site residual audit. It contains 33 functions, three attribute-context `Parameter` false forwards, and two fields; the dominant ten-site `RestException<T>` cluster is a same-file generic/nongeneric declaration identity collision.
- [x] (2026-07-13 03:45Z) Added failing forward and inverse inline regressions for same-named generic/nongeneric constructors, then implemented metadata-style arity identity for every declared C# type segment, same-file partial-body merging, structured generic-reference arity, exact-before-normalized lookup, source-facing display, and a C# epoch bump.
- [x] (2026-07-13 04:35Z) Completed three delegated read-only audits and fixed every generic-root finding: receiver inference preserves arity, grouped overloads all scan, exact candidate routing is symmetric, and visible structured lookup never normalizes an arity miss. The complete all-feature suite and affected all-feature clippy targets pass; production exact validation is blocked only on explicit outside-sandbox approval.
- [x] (2026-07-13 11:35Z) Filed #726 and completed the final exact CDN production rerun in 341.0 seconds. The former false-forward now resolves to `RestException`1.RestException(System.Net.Http.HttpResponseMessage,T)` and has a proven covering inverse hit; zero exact findings remain.
- [x] (2026-07-13 12:10Z) Pushed and closed #726 after merging concurrent `master`; the complete post-fix C# run at `b75f6b53` finished in 621.0 seconds with 1,902 consistent, 40 unproven, 8,019 inconclusive, and 39 missing sites. All ten generic-constructor misses disappeared; the residual partition is 23 functions, twelve attribute names, and four fields.
- [x] (2026-07-13 13:40Z) Verified #727 was assigned only to `jbellis`, then reduced the twelve-site attribute boundary with delegated tests and review. C# attribute lookup now models exact and `Attribute`-suffixed AST identities independently, rejects indexed non-attribute ancestry, preserves partial declarations, reports ambiguous spellings, shares the role with forward/type lookup and both inverse graph paths, persists both routing identities, and handles alias/global qualification without per-target global lookup amplification. Exact Azure reruns now classify the external `[Parameter]` spelling as an honest unresolved `ParameterAttribute` import boundary and prove the fully qualified `PSArgumentCompleterAttribute` inverse hit. The complete `cargo test --features nlp,python` gate passes outside the filesystem sandbox; focused all-feature clippy passes, while all-target clippy remains blocked only by the preserved pre-existing `tests/rust_analyzer_goto_definition.rs:65` needless borrow.
- [x] (2026-07-13 14:05Z) Pushed `5a75ab33`, closed #727, and completed the post-fix Azure PowerShell run from merged/pushed `1a14bc92` in 517.8 seconds: 1,961 consistent, 36 unproven, 23 missing, and 7,980 inconclusive sites. All twelve attribute misses disappeared. The remaining actionable set is nineteen functions and four fields; delegated read-only triage partitions it into callable applicability, local-function method groups, inherited members, cast/local receivers, generic member names, partial-type initializer identity, and one deliberate `nameof` surface mismatch.
- [x] (2026-07-13 16:05Z) Filed #732 after verifying assignment only to `jbellis`, reduced both callable-applicability directions, and completed delegated read-only review. C# now persists required/total/repeated arity, applies intervals in forward/inverse/constructor/extension/return-type consumers, keeps overlapping intervals conservative, lets applicable extensions beat inapplicable direct members, persists local and global static-using owners, and filters only structurally proven incompatible extension receivers. Focused validation passes 55 get-definition, 75 forward graph, and 23 inverted graph tests; the complete `cargo test --features nlp,python` gate and affected all-feature clippy targets pass, while all-target clippy remains blocked only by the preserved pre-existing `tests/rust_analyzer_goto_definition.rs:65` needless borrow. The epoch-rebuilt Azure `eventListener.Signal` exact run is consistent in 618.6 seconds with seven applicable extension overloads and an exact inverse hit; the optional `AddMultipleTypeNameIntoPSObject` exact run changes the former miss to a retained exact-range unproven hit in 332.6 seconds.
- [x] (2026-07-13 16:18Z) Reopened #732 after its first full rerun exposed extension-visibility hydration amplification. Static-import candidates now come from the persisted exact owner/member index, namespace candidates are filtered before any parent/signature hydration, and a 256-file same-name regression permits at most two relevant-file hydrations. The complete Azure sample now terminates with 4,548 forward-resolved sites, 1,934 consistent, 45 unproven, 16 missing, and 8,005 inconclusive classifications; its 18,410,868 KiB peak stabilized instead of entering the repeated candidate-file hydration loop. Read-only triage found one #732 false forward among the sixteen: a fully qualified property receiver fell back to 25 arity-inapplicable extensions. Iterative declared-member typing now preserves value shadowing and nearest hidden-member semantics, and the exact StackHCIVM site resolves only the nine-argument `Module.Signal` with an exact retained inverse hit. The complete `cargo test --features nlp,python` gate passes outside the filesystem sandbox; affected all-feature clippy passes, while all-target clippy remains blocked only by the preserved pre-existing `tests/rust_analyzer_goto_definition.rs:65` needless borrow.
- [x] (2026-07-13 16:45Z) Pushed #732 as `545ce984`, merged concurrent `master` into pushed head `dde2fc2d`, and verified its CI matrix green. The fixing-head Azure N=1 run completed with 4,737 forward-resolved sites, 1,887 consistent, 47 unproven, 14 missing, and 8,052 inconclusive classifications at 18,372,500 KiB peak RSS. The StackHCIVM false forward is gone; the sampled Elastic method-group boundary is explicitly target-truncated rather than misclassified, so the residual actionable set is fourteen sites.
- [x] (2026-07-13 17:20Z) Filed #737 only after a reduced authoritative-scope regression proved that a uniquely declared unqualified method-group argument resolves forward but disappears from both inverse paths. Added a shared AST classifier, lexical shadowing checks, nearest-owner and partial-type hierarchy resolution, conservative overload handling, and cached inverted-graph owner/name lookup. Delegated read-only review found the final implementation clean. All 78 targeted C# graph tests, 24 whole-workspace graph tests, 60 C# definition tests, formatting, and affected all-feature clippy pass; all-target clippy remains blocked only by the preserved unrelated Rust needless borrow. The exact Azure `onDefault` site at bytes `60843..60852` is now consistent with a proven exact-range inverse hit in `/tmp/csharp-exact-737-ondefault-fixed.jsonl`.
- [x] (2026-07-13 17:27Z) Pushed #737 as `3ca1a8fe`, closed it with the exact production evidence, and verified the complete Rust/Python CI matrix green on Linux, Windows, macOS, Android, and the configured cross targets.
- [x] (2026-07-13 18:12Z) Filed #738 only after the reduced three-level inheritance test resolved `Base.Report` forward and returned zero authoritative inverse hits from the derived consumer. Replaced exact-owner matching with a shared iterative nearest-declaring-level walk across partial type parts, preserved hiding and callable applicability, kept exact generic identity ahead of normalized fallback, rejected lexical shadows, and cached both targeted and whole-workspace lookups. Delegated review found and verified fixes for shadowed-call unproven leakage, generic inverted identity, and repeated hierarchy work. All 79 targeted C# graph tests, 25 whole-workspace graph tests, 60 C# definition tests, affected all-feature clippy, and the complete `cargo test --features nlp,python` gate pass; all-target clippy remains blocked only by the preserved unrelated Rust needless borrow. The exact Azure `this.PrintSdkExceptionDetail` site at bytes `5184..5207` is consistent with a proven exact-range inverse hit in `/tmp/csharp-exact-738-inherited-final.jsonl`.
- [x] (2026-07-14) Pushed #738 as `6d89ff5c`, closed it with exact Azure evidence, and completed the post-#738 Azure PowerShell N=1 run using the binary pinned to pushed HEAD. It reports 4,737 forward-resolved sites, 1,903 consistent, 40 unproven, 6 missing, and 8,051 inconclusive classifications. The JSONL truthfully records `bifrost_dirty:true` because #739 worktree edits began while the run was in flight; this is a pushed-commit binary result, not a clean-worktree record.
- [x] (2026-07-14) Filed #739 only after a reduced inline regression proved that the fully qualified explicit generic call `PsHelpers.RunScript<T>(...)` resolves forward while an authoritative inverse scan of only the consumer returns zero hits. Implemented metadata-arity method identity, explicit generic-arity filtering before value applicability and hiding, AST-carried actual type arguments, persisted bare method-type-parameter return facts, and one shared lexical extension-visibility model across forward, targeted inverse, and whole-workspace graph resolution. The shared signature serialization change bumps the global store epoch. Delegated read-only review found and verified fixes for instance-member precedence, ambiguous-receiver gating, lexical sibling isolation, cache keys, inherited declaring-owner return resolution, wrapped-return negatives, and persistence after reopening. All 84 targeted C# usage tests, 27 whole-workspace graph tests, 60 C# definition tests, formatting, diff checks, affected all-feature clippy, and the complete `cargo test --features nlp,python` gate pass; all-target clippy remains blocked only by the preserved unrelated Rust needless borrow. The epoch-rebuilt Azure exact site at bytes `7144..7153` is consistent with the exact generic signature `` `1(CommandInvocationIntrinsics, string)`` and a proven exact-range inverse hit in `/tmp/csharp-exact-739-generic-final.jsonl`.
- [x] (2026-07-14) Pushed #739 as `9ece3b65`, verified it closed while assigned only to `jbellis`, and reproduced the exact generic-method proof on pushed HEAD in `/tmp/csharp-exact-739-generic-pushed.jsonl`. The complete post-#739 C# N=1 run in `/tmp/csharp-n1-739-pushed.jsonl` queried all 1,000 configured targets and reports 4,738 forward-resolved sites, 1,907 consistent, 37 unproven, 5 missing, and 8,051 inconclusive classifications. `RunScript<T>` accounts for the one-site improvement from the post-#738 six-miss boundary. The remaining five sites partition into three suspicious `ToString` forwards, one `nameof` field, and one object-initializer field; read-only triage is delegated before any new issue is filed.
- [x] (2026-07-14) Delegated the five-site post-#739 triage across Oldskool and two read-only agents. The `nameof(field)` site is an intentional editor-navigation/runtime-usage surface mismatch and therefore a differential-engine false positive. Three null-conditional `ToString` sites are one false-forward boundary: an explicit `(object)` cast should resolve to external `System.Object.ToString`, but forward lookup mistakes the `member_binding_expression` for an unqualified containing-class call. The remaining object-initializer field is a genuine partial-type inverse defect.
- [x] (2026-07-14) Filed #740 only after a two-file inline regression proved that adding another physical part of the initializer type drops the field-label hit while preserving `this.field`. Narrowed logical partial-type identity to the object creation's actual type AST, retained physical identity on the pre-binding value-receiver fast path, and added a PascalCase parameter-shadow negative after delegated review caught the unsafe broader change. All 86 targeted C# usage tests, affected all-feature clippy, and the complete `cargo test --features nlp,python` gate pass; all-target clippy remains blocked only by the preserved unrelated Rust needless borrow. The exact Mdp `pipeline` label at bytes `3733..3741` is consistent with a proven exact-range inverse hit in `/tmp/csharp-exact-740-partial-initializer-final.jsonl`.
- [x] (2026-07-14) Filed #741 only after an inline partial-model regression proved that a null-conditional `member_binding_expression` on an explicit `(object)` receiver fell through to unqualified lookup and selected the containing model's `ToString`. Delegated synchronous implementation to Oldskool, then review caught and corrected a trivially scoped authoritative negative before landing. The final structured fix shares direct conditional binding extraction, preserves cast and `as` receiver identities, types chained conditional properties and method returns, carries value and generic arity, and keeps compatible extension matching exact even for builtin aliases. Focused definition/targeted/inverted tests, affected all-feature clippy, formatting, diff checks, and the complete `cargo test --features nlp,python` gate pass. The rebuilt Azure exact site at bytes `7147..7155` now returns `no_definition` for external `System.Object.ToString`, with zero actionable findings in `/tmp/csharp-exact-741-conditional-final.jsonl`.
- [x] (2026-07-14) Delegated the remaining C# `nameof(member)` corpus false-positive implementation to Oldskool. The differential engine now identifies the nearest structured `nameof` invocation, classifies resolved field/property/function targets as `editor_only`, and omits them from runtime inverse grouping while ordinary reads still require a proven inverse hit. Review caught a direct-`argument_list` production AST gap; the corrected nested-call regression proves only the inner `nameof(member)` is excluded and the sibling outer-call argument remains consistent. All nine engine tests, all-feature library clippy, formatting, and diff checks pass. The rebuilt Azure exact site at bytes `15226..15254` is `editor_only` with zero actionable findings in `/tmp/csharp-exact-nameof-editor-only-final.jsonl`.
- [x] (2026-07-14) Completed the pushed-head Azure PowerShell C# N=1 closure run in `/tmp/csharp-n1-741-nameof-pushed.jsonl`. It audited 1,000 of 126,829 eligible files, sampled 10,000 sites, queried 1,000 of 2,252 target groups, and reports 1,858 consistent, 3 editor-only, 30 unproven, 0 missing, and 8,109 inconclusive classifications. One 50,000-candidate file and 2,271 target-truncated sites remain explicitly inconclusive. C# now has zero actionable findings; proceed to the C corpus.
- [x] (2026-07-14) Fixed and closed incidental Windows CI issue #743 before continuing the corpus. Oldskool synchronously implemented kill-on-close Job Object ownership with suspended assign-before-resume startup and complete job/pipe-worker draining; independent review found no remaining lifecycle defect. The first pushed head exposed only a Windows-only `needless_return` lint, which Oldskool corrected in `d4923a53`. Merged head `1f569e75` passed both Windows clippy targets, Windows ARM64 completed green, and Windows x86_64 passed the exact `bifrost_lsp_server_runtime_configuration_rebuild_releases_windows_children_and_handles` regression plus its full test command in CI run `29337853743`.
- [x] (2026-07-14) Completed the C N=1 run on `RMerl__asuswrt-merlin.ng` in `/tmp/c-n1-current.jsonl`, pinned to Bifrost `4fe9cbeb` and corpus head `e7c13912`. It audited 1,000 of 164,927 eligible files, sampled 10,000 sites, queried 1,000 of 1,332 target groups, and reports 661 consistent, 264 unproven, 126 missing, and 8,949 inconclusive classifications in 8,158.1 seconds. There were zero file errors and zero candidate-limit files; 370 target-truncated sites remain explicitly inconclusive. Highest sampled RSS was 24,051,264 KiB because the report schema does not record an exact peak. Read-only triage is partitioning the 111 field, ten class, and five function misses before any issue is filed.
- [x] (2026-07-14) Completed delegated read-only triage of all 126 C misses. The refined partition is 114 genuine inverse omissions, eleven forward false targets, and one persisted/full-corpus differential artifact that passes an exact authoritative query. Genuine roots are 35 global receiver/base references, ten intermediate member receivers, 41 nested terminal members, fourteen one-hop typedef-owned members, eight canonical typedef type references, five variadic calls, and one macro-recovered type node. False forwards are ten designated-initializer pseudo-fields plus one malformed `__iomem` field declaration.
- [x] (2026-07-14) Filed #760 only after an authoritative inline regression proved that forward lookup resolves global `bs` in `bs.cluster_size` while inverse target routing returns an empty hit set. Delegated synchronous implementation to Oldskool, then review corrected local-class member shadowing, removed a non-protective implementation-shaped stress test, and added a real direct-arrow positive. The final AST receiver-edge walk handles dot, arrow, and nested chains, rejects member descendants and lexical shadows, and filters persisted global/member identity without parent lookup amplification. After merging concurrent reference-traversal changes, all 53 C++ usage and 17 C++ inverted graph tests pass. Pushed head `bfffb6e5` exact-validates RMerl bytes `21623..21625` as consistent with an exact inverse range and zero actionable findings in `/tmp/c-exact-760-bs-pushed.jsonl`; #760 is closed.
- [x] (2026-07-14) Filed #762 after a reduced consumer-only authoritative regression for `Leaf.value` returned zero expected mixed dot/arrow nested-chain hits while preserving wrong-owner and local-shadow negatives. Synchronous Oldskool implementation advances exact structural owners through nested dot/arrow, pointer, parenthesized, subscript, `this`, implicit-member, and qualified-global chains using name-indexed lookups and cached tree-sitter declaration facts. Root review rejected all-visible-unit amplification, arbitrary short-type selection, source-text field routing, unresolved-global type fallback, and missing structured roots before acceptance. The first production exact rerun exposed a second reduced boundary: persisted inline tagged typedef aliases are Class units distinct from their tag owners, and alias hops had switched away from the consumer visibility root. Cached structured alias decoding plus unique, cycle-safe owner canonicalization fixes that boundary. Commit `7f72d0a2` is pushed; the 58 C++ usage, 17 inverted graph, and 56 C++ get-definition tests pass, as does affected all-feature clippy. Pushed-head `/tmp/c-exact-762-omcast-pushed.jsonl` classifies RMerl `new_vals->stats.omcast` bytes `17343..17349` as consistent with the identical inverse range and zero actionable findings; #762 is closed.
- [ ] Run N=1 for c, cpp, csharp, go, java, js, php, py, rust, scala, and ts.
- [ ] Triage every reported inverse disagreement; create GitHub tickets only for genuine analyzer defects.
- [ ] Fix, test, push, and close every genuine ticket found by the N=1 campaign.
- [ ] Complete the campaign report and final verification, then mark the goal complete.

## Surprises & Discoveries

- Observation: The user-referenced `../brokkbench/test.py` does not exist in the current brokkbench checkout or its Git history.
  Evidence: The authoritative current registry is `/home/jonathan/Projects/brokkbench/tasks.py::LANGUAGE_RANKING_NAMES`, whose keys exactly match the eleven `sft-tools-commits` language directories: `c`, `cpp`, `csharp`, `go`, `java`, `js`, `php`, `py`, `rust`, `scala`, and `ts`.

- Observation: The N=1 repositories are exceptionally large, so an unbounded all-target inverse query campaign would become impractical.
  Evidence: Recorded sizes include 49,660,873 LOC for `RMerl__asuswrt-merlin.ng`, 25,845,431 LOC for `chromium__chromium`, and 33,055,102 LOC for `googleapis__google-cloud-java`.

- Observation: Bifrost has no distinct C analyzer.
  Evidence: `src/analyzer/model.rs::Language::Cpp` owns both C and C++ extensions. The engine must preserve corpus label `c` while filtering C seed files and reporting analyzer language `cpp`.

- Observation: Existing semantic-token code already performs the correct structured first half of the audit: iteratively enumerate grammar identifier leaves, subtract structured declaration-name ranges, and batch definition lookup per file.
  Evidence: `src/lsp/handlers/semantic_tokens.rs::reference_candidate_ranges` and `DeclarationNameRangeContext` provide this behavior; the candidate collector should move to an analyzer-owned shared module rather than be duplicated.

- Observation: None of the eleven N=1 clones has an existing Bifrost database, and the clone volume has about 219 GiB free at 94% utilization.
  Evidence: The selected checkouts occupy about 33 GB logically before analyzer caches. Run smaller analyzers first, inspect database/WAL growth and free space after each repository, and stop before free space falls below 100 GiB.

- Observation: A bounded real-repository preflight completed across every analyzer and immediately exercised genuine forward/inverse disagreements without requiring a production trajectory.
  Evidence: With at most 100 sites and 50 target groups per repository, the reviewed pass reported missing sites in C (2), C++ (4), C# (3), Go (4), JavaScript (4), Rust (12), and Scala (1), and none in Java, PHP, Python, or TypeScript. These are validation leads, not tickets, until exact-site reruns confirm them.

- Observation: The semantic-token identifier frontier was structured but narrower than the resolver's accepted syntax.
  Evidence: Existing forward resolvers handle C++ operator/destructor nodes, Rust `self`/`super`/`crate`, and receiver keywords in several languages. The differential now scans a strict superset of the old identifier frontier, while a separate shared helper preserves the LSP's prior token ranges exactly.

- Observation: The first Rust N=1 run found two pre-differential defects, neither of which was SQLite workspace construction.
  Evidence: `biomejs__gritql` completes construction and a one-target run in about 21 seconds even with a 512 KiB main stack. At the 1,000-target campaign budget, lazy `RustUsageIndex` construction repeatedly called `resolve_module_files -> analyzed_live_files -> AnalyzerStore::contains_parsed_blob -> SQLite`, driving roughly 5 GiB RSS. A debugger then captured the actual stack failure as mutual recursion between `rust_collect_binding_type_fqn` and `rust_expression_type_fqn_mode` for a binding considered in scope inside its own initializer. The fix uses a compact 306-file routing projection, a chunked set query over requested `(blob_oid, language)` keys, and iterative binding/re-export traversals. The exact 512 KiB-stack rerun completed in 554.7 seconds with 101,192 KiB peak RSS and no swaps. Filed as #643.

- Observation: The first completed high-budget Rust differential contains a large follow-on triage set, independent of #643.
  Evidence: Both the dirty-worktree validation and committed-HEAD baseline audited all 306 eligible Rust files and 10,000 sampled sites. Forward resolution uniquely resolved 1,549 sites across 784 targets; inverse comparison classified 517 consistent, 41 editor-only, 5 unproven, and 961 missing. Structured triage found 280 nonterminal focus errors, 93 local binding/declaration false resolutions, 73 terminal `Self::item` inverse gaps, and private inherent member gaps. Filed as #644 and #645. The baseline artifact is marked dirty because delegated fixes began while it ran, so the canonical clean record follows those commits.

- Observation: Macro token trees are a distinct structured Rust usage surface, not source-text noise.
  Evidence: The real `json!(..., "path": self.file)` site remained missing after private-member visibility and receiver fixes because `record_token_tree_instance_member_hits` explicitly returned for field targets. Extending its token-node walk to distinguish field access from method calls made the exact corpus site consistent without text search.

- Observation: Correcting receiver focus substantially reduced false inverse misses but exposed the owner-type surface explicitly.
  Evidence: On `03646ad1`, the complete 10,000-site gritql rerun changed forward resolution from 1,549 to 1,348 sites and reduced missing classifications from 961 to 628. All 250 same-file class misses were focused `Self`, `Self::item`, or `self.member` owner tokens; 251 more were cross-file class references. Exact reruns and independent reviews separated these from noisy residual field/function/module collisions.

- Observation: Rust workspace file modules had contradictory declaration and import identities below nested crate `src` roots.
  Evidence: `crates/cli/src/ux.rs` declared `CheckResult` under flattened package `crates.cli.src`, while `use crate::ux::CheckResult` structurally resolved the module as `crates.cli.src.ux`. A multi-file authoritative regression recovered zero of two type annotations before #646. Applying the existing file-module stem rule to nested workspace crates aligns both sides and keeps `lib.rs` at the crate root.

- Observation: Package version alone is insufficient resume identity during a fix campaign.
  Evidence: Analyzer fixes can land without changing `CARGO_PKG_VERSION`; a report produced before the fix would otherwise suppress the required rerun. Repository records and completion keys therefore include the Bifrost source HEAD as well as the target repository HEAD and configuration fingerprint.

- Observation: C# fully qualified method-return sites exposed a focus-range asymmetry rather than a partial-declaration or authoritative-scope failure.
  Evidence: The reduced #698 query received both partial interface declarations and only the consumer candidate, yet initially emitted only the terminal parameter-type identifier. The grammar names method return types `returns`, and the differential had focused `ADDomainServices` inside the qualified return. Recognizing that field and emitting the containing qualified type produced a covering `5642..5712` hit for exact site `5677..5693`.

- Observation: The #698 range/return-role fix removed 83.6% of the C# actionable set and exposed several smaller structured roles.
  Evidence: `/tmp/csharp-n1-698-fixed.jsonl` retained the same 3,269 forward-resolved sites but changed consistent/missing from 598/1,339 to 1,717/220. The largest residual is 73 interface-owner focuses inside explicit interface property and method declarations; other buckets include generic `PropertyT<T>` arguments, `using static` imports, functions, and miscellaneous class roles.

- Observation: The 73-site explicit-interface cluster is independent of partial declaration grouping and path-scoped routing.
  Evidence: Primary and delegated inline regressions both supplied two partial interface declarations to an authoritative one-file query. The only pre-fix hit was the class base-list type. Adding the dedicated tree-sitter `explicit_interface_specifier` role recovered property and method owners, and the exact Azure site became consistent with a covering AST-derived hit.

- Observation: Re-reading analyzer liveness between differential phases can invalidate an otherwise deterministic corpus record.
  Evidence: `/tmp/csharp-n1-701-fixed.jsonl` selected 1,000 audited files and forward-resolved 3,269 sites, but its later inverse path map admitted only 31 target groups. The report silently classified 1,910 sites as having no sampled file and emitted `completed`. #703 carries the authoritative audited `ProjectFile`s across phases and returns an engine error on impossible scope loss.

- Observation: The stable-scope rerun proved #701 removed 76 valid missing classifications and exposed 144 trustworthy residuals.
  Evidence: `/tmp/csharp-n1-703-fixed.jsonl` queried all 1,000 configured target groups with zero candidate-loss notes, producing 1,793 consistent, 40 unproven, 144 missing, and 8,023 inconclusive sites. The largest next cluster is 39 C# generic type arguments inside generated `PropertyT<T>` calls.

- Observation: C# generic method type arguments need a type-role stop at `type_argument_list`, not traversal into the callable `generic_name`.
  Evidence: The primary and delegated authoritative fixtures failed with zero hits before #704 and passed repeated exact positives plus three negative roles afterward. Exact BillingBenefits bytes `4325..4335` became consistent with a full qualified-argument hit.

- Observation: Exact-site mode unnecessarily inventories every analyzed file before selecting its requested path.
  Evidence: The post-#704 exact C# probe audited one file and one site but enumerated 126,829 eligible files and took 1,134.4 seconds. Avoiding this inventory is a campaign-engine performance task separate from analyzer correctness.

- Observation: The full post-#704 record removed the complete generic-argument residual and exposed `using static` as the next C# boundary.
  Evidence: `/tmp/csharp-n1-704-fixed.jsonl` is pinned to pushed `cf2743de`, shares the same repository head, run fingerprint, audited/sample counts, and zero candidate-loss notes with the valid pre-fix record, and reports 1,834 consistent, 40 unproven, 103 missing, and 8,023 inconclusive sites. The missing set is 34 `using static` classes, 34 other class roles, 33 functions, and two fields.

- Observation: The exact-site inventory cost has a direct engine seam independent of analyzer construction.
  Evidence: `run_reference_differential` calls `analyzer.analyzed_files()` before `select_audited_files` applies the exact-path filter. A safe fast path can validate the requested relative `ProjectFile`, apply the same language/test eligibility rules, point-check `is_analyzed`, and then reuse the unchanged semantic pipeline against the full persisted analyzer.

- Observation: The exact-site point lookup removes 23.7% of end-to-end time while exposing persisted analyzer startup as the remaining dominant cost.
  Evidence: `/tmp/csharp-exact-generic-type-705-fixed.jsonl` completed the same consistent BillingBenefits site in 865.2 seconds versus 1,134.4 seconds before #705. Its summary truthfully reports one eligible, audited, sampled, resolved, and consistent item. Full analyzer construction is retained so declarations outside the exact file remain resolvable.

- Observation: The 34-site `using static` cluster spans both inverse recognition and default candidate routing.
  Evidence: Delegated partial-target authoritative fixtures failed because `is_type_reference_node` rejected `qualified_name -> using_directive(static)`. Adding that structured role fixed inverse scanning, but default `UsageFinder` required the same role in persisted type-identifier collection. Negative ordinary/alias/unrelated-static imports pass, and the persisted identifier change requires a C# epoch bump.

- Observation: #706's cache-aware fix is exact-validated on the rebuilt production index.
  Evidence: `/tmp/csharp-exact-using-static-706-fixed.jsonl` reports one consistent MachineLearningServices `PsHelpers` import-type site with a proven hit covering the full `using static` directive. It completed in 831.1 seconds with one truthful eligible/audited file and no actionable finding.

- Observation: The full post-#706 corpus confirms every static-import miss was removed.
  Evidence: `/tmp/csharp-n1-706-fixed.jsonl` is pinned to pushed `2a365fce`, queried all 1,000 target groups with zero scope-loss notes, and reports 1,875 consistent, 40 unproven, 69 missing, and 8,016 inconclusive sites in 1,008.2 seconds. The remaining 34 classes partition into 16 `IAsyncCommandRuntimeExtensions`, 10 `EventData`, seven `JsonArray`, and one `Parameter`; 33 functions and two fields remain.

- Observation: All 33 post-#706 cast-family class misses are the same grammar-field mismatch.
  Evidence: Clean-`v0.8.0` primary and delegated fixtures failed for singular and partial targets because the typed operand is `as_expression.right`, not a field literally named `type`. The shared role fixes authoritative inverse scanning and default persisted routing; unrelated RHS and left-expression negatives remain excluded. `/tmp/csharp-exact-as-type-707-fixed.jsonl` confirms the rebuilt production path is consistent.

- Observation: C# attribute spellings require two independently resolved structural identities, not suffix normalization before lookup.
  Evidence: `/tmp/csharp-exact-attribute-727-parameter.jsonl` completed in 474.9 seconds and reports `[Parameter]` as an unresolved external `ParameterAttribute` boundary instead of resolving to the workspace non-attribute model. `/tmp/csharp-exact-attribute-727-psargument.jsonl` completed in 269.3 seconds and reports the fully qualified `PSArgumentCompleterAttribute` reference consistent with a proven inverse hit covering bytes `5405..5492`.

- Observation: Callable applicability is the largest post-#727 C# correctness boundary and already has a shared persisted representation.
  Evidence: `/tmp/csharp-n1-727-fixed.jsonl` retains seven wrong-forward `IEventListener.Signal` sites plus one sampled optional-argument inverse miss. Read-only reduction found that C# does not populate or consume the existing `CallableArity { required, total, repeated }` metadata used by Scala: forward filtering falls back to inapplicable direct members before extension lookup, while inverse filtering requires exact total arity.

- Observation: Arity intervals establish applicability but cannot rank overlapping C# overloads without argument-type evidence.
  Evidence: delegated .NET 8 reductions prove both counterexamples: `M(object)` loses to `M(string, int = 0)` for a string argument despite the former's exact total, while fixed and `params` overloads exchange precedence depending on whether the final argument is an array. #732 therefore retains every interval-applicable forward overload and leaves return inference untyped when applicable declarations disagree.

- Observation: Static-using extension visibility must come from persisted structured import identities, not a per-click syntax-tree walk.
  Evidence: `/tmp/csharp-exact-callable-732-signal-final.jsonl` rebuilt the C# store under the new epoch and resolved the production `using static ...Runtime.Extensions` owner to seven receiver-compatible overloads with a proven exact inverse hit. Inline coverage also proves same-namespace short targets, project-wide global static usings, external receiver best effort, and rejection of a known incompatible receiver.

- Observation: Filtering a global identifier bucket by static-import visibility cannot call `parent_of` before visibility is known.
  Evidence: Azure PowerShell contains 4,675 static `Signal` declarations. The first #732 full run hydrated same-name declaration files while checking each structural parent and retained enough full file states to reach 17.6 GiB before it was stopped. The fixed lookup unions namespace-filtered identifier candidates with exact persisted `(static owner, member)` candidates, and the inline 256-noise-file query hydrates no more than the consumer and visible declaration.

- Observation: A dotted C# receiver needs value-first, iterative declared-member typing before extension fallback.
  Evidence: The post-visibility corpus resolved `Microsoft.Azure.PowerShell.Cmdlets.StackHCIVM.Module.Instance.Signal(...)` to 25 visible but arity-inapplicable extensions because the receiver typer did not follow the fully qualified `Module.Instance` property's declared type. The fixed exact rerun resolves only `Module.Signal(string, CancellationToken, Func<EventArgs>, SignalDelegate, InvocationInfo, string, string, string, Exception)` and retains the exact inverse range. Inline negatives preserve unresolved local shadowing and nearest hidden-property semantics.

- Observation: C# unqualified method-group arguments were asymmetric between forward and inverse resolution.
  Evidence: Forward lookup treats a bare value-position identifier as an implicit-`this` member reference, but both inverse scanners previously accepted a bare method only when it was the direct callee of an invocation. The reduced `Accept(onDefault)` regression therefore resolved the unique private method forward and returned no inverse hit. The shared structured classifier now recognizes transparent wrappers, rejects declarations, types, named-argument labels, `nameof`, and lexical shadows, and the exact Azure site is consistent.

- Observation: Precise C# receiver typing did not imply precise declaring-member identity across inheritance.
  Evidence: `this.PrintSdkExceptionDetail(ex)` typed its receiver as the derived Azure cmdlet, but targeted inverse scanning accepted only exact equality with the base declaration owner and the whole-workspace graph synthesized `Derived.PrintSdkExceptionDetail`. The shared nearest-level walk now reaches the indexed base declaration, stops at derived hiding members even when their arity is inapplicable, unions partial type parts at every level, and preserves metadata arity when generic and nongeneric owners share a normalized name.

- Observation: C# method generic arity is a declaration and lookup identity dimension distinct from value-argument arity.
  Evidence: `RunScript<T>(CommandInvocation, string)` and its nongeneric sibling have the same source-facing FQN and value-parameter shape. Before #739 their internal signature keys collided and generic calls stopped at `generic_name` without carrying metadata arity into inverse matching. The reduced regression and production site now exercise one shared generic-arity selector across forward lookup, targeted inverse scanning, whole-workspace edges, extension lookup, hiding, and return inference.

- Observation: C# extension visibility is lexical, not merely a property of the enclosing namespace FQN.
  Evidence: Same-FQN sibling namespace blocks can have different local usings; file-scoped namespaces distinguish pre-marker compilation-unit usings from post-marker namespace usings; qualified namespaces expose syntactic parent frames; and global usings apply across files. The #739 tests prove these scopes independently and require cache keys to retain the exact AST frame range so sibling blocks cannot leak candidates.

- Observation: A C# type AST should compare logical partial identity, but source expressions must still honor value bindings before visible type names.
  Evidence: The #740 initializer `new HttpPipeline { pipeline = this.pipeline }` resolved its type to a different physical partial declaration than the target field owner, so physical `CodeUnit` equality dropped the label. Broadly replacing physical equality with FQN equality created a false hit when a PascalCase parameter shadowed the same-spelled partial type. The fixed path applies logical identity only to the object creation's structured type node.

- Observation: Null-conditional C# member bindings need receiver classification before unqualified-member fallback.
  Evidence: In three Azure serializers, `(((object)value)?.ToString())` is a `conditional_access_expression` with a `member_binding_expression`. Forward lookup did not climb that structure, treated `ToString` as unqualified, and selected the containing partial model's override even though the explicit cast makes the semantic target external `System.Object.ToString`. Inverse analysis correctly omitted those sites for the model targets.

- Observation: C# `nameof` is an intentional editor-only reference surface in this campaign.
  Evidence: Forward definition lookup resolves `nameof(field)` for navigation, while inverse runtime usage tests deliberately exclude both bare and qualified `nameof` arguments. The differential engine currently samples the identifier and reports a false missing classification; the symbols analyzer behavior should remain unchanged.

## Decision Log

- Decision: Implement a library-owned engine plus a dedicated Rust binary, not a unit test or brokkbench production trajectory.
  Rationale: The engine needs direct access to structured definition and usage internals, must run independently over large clones, and must emit durable campaign artifacts even when interrupted.
  Date/Author: 2026-07-12 / Codex

- Decision: Use grammar-derived identifier leaves from real source, with structured declaration-name exclusion, rather than text search or generated programs.
  Rationale: This uses the user's real-world corpus and respects the repository rule against string-scanning substitutes for analyzer structure.
  Date/Author: 2026-07-12 / Codex

- Decision: Deterministically hash-sample eligible file paths before parsing, then hash-sample reference sites by repository-relative path and byte range, group resolved sites by exact declaration set, and run the inverse resolver once per group.
  Rationale: Path-order truncation would bias large repositories toward a few directories, while parsing all 170,000 matching files in the largest C checkout merely to select 10,000 sites would make sampling the bottleneck. Two-stage stable sampling bounds parsing while preserving repository-wide path coverage; reports retain total eligible files and audited files so coverage is explicit.
  Date/Author: 2026-07-12 / Codex

- Decision: Restrict each inverse query to the files containing sampled forward references for that declaration and mark the scope authoritative.
  Rationale: The differential asks whether inverse resolution can recover already-known sites, not whether candidate discovery can rediscover the whole workspace. This isolates semantic disagreement and prevents whole-repository candidate enumeration per target.
  Date/Author: 2026-07-12 / Codex

- Decision: Apply a second deterministic cap of 1,000 unique target groups after forward resolution.
  Rationale: Ten thousand sampled sites can approach ten thousand unique inverse queries. A target-group cap retains wider forward coverage and makes omitted sites explicitly inconclusive without allowing the inverse phase to dominate the campaign.
  Date/Author: 2026-07-12 / Codex

- Decision: Treat ambiguous forward results, inverse failures, call-site caps, and truncated unproven samples as inconclusive rather than defects.
  Rationale: Only a unique forward declaration coupled with a complete inverse answer can prove a contradiction. The report must separate unsupported or bounded work from actionable missing references.
  Date/Author: 2026-07-12 / Codex

- Decision: Key resumable records by Bifrost source HEAD in addition to target HEAD and run configuration.
  Rationale: Every landed analyzer fix must invalidate earlier evidence automatically even when the package version and corpus checkout are unchanged.
  Date/Author: 2026-07-12 / Codex

- Decision: Differential inverse scope is the stable audited file set chosen before sampling; it must not be reconstructed from a later analyzer liveness snapshot.
  Rationale: The experiment compares forward and inverse answers over one fixed sample. Allowing candidate identity to drift mid-run creates false inconclusive results and can make an invalid partial record look complete.
  Date/Author: 2026-07-12 / Codex

- Decision: Treat the symbols MCP toolset as the production acceptance surface for corpus findings; LSP coverage is incidental and must not expand campaign scope.
  Rationale: The campaign exists to improve `get_definitions_by_location`, `get_definitions_by_reference`, usage scanning, symbol sources, and related symbols tools. Their shared resolver may also improve LSP behavior, but LSP-only discrepancies are outside this campaign.
  Date/Author: 2026-07-12 / Codex

- Decision: Resolve indexed Rust path dependencies through one cached Cargo route index shared by forward module lookup and the inverse usage index.
  Rationale: Per-reference manifest parsing would be a hot-path regression, while a forward-only filesystem fallback would recreate definition/usage disagreement. The compact route index parses indexed manifests once, preserves importer-scoped aliases and library names, and refuses to guess registry dependencies from coincidental workspace names.
  Date/Author: 2026-07-12 / Codex

- Decision: Use persisted callable arity only to reject inapplicable C# declarations; do not rank overlapping intervals without structured argument-type evidence.
  Rationale: Required/total/repeated counts can prove that a declaration cannot accept a call, but C# overload precedence also depends on conversions and normal versus expanded `params` form. Preserving grouped candidates and declining conflicting return inference is safer than introducing wrong definitions or receiver types.
  Date/Author: 2026-07-13 / Codex

- Decision: Construct the C# extension visibility set from persisted namespace and exact static-owner indexes before hydrating semantic declaration details.
  Rationale: Namespace identity and resolved static-import owner identity are already persisted and sufficient to exclude workspace-global same-name declarations. Parent/signature hydration belongs only after that bounded visibility union, preserving structured resolution without global fanout.
  Date/Author: 2026-07-13 / Codex

- Decision: Prove an unqualified C# method-group inverse hit only when structured lexical and owner lookup leaves one callable declaration; retain overloaded groups as unproven until delegate-parameter typing exists.
  Rationale: A bare argument has no invocation arity of its own, and borrowing the containing call's argument count would be incorrect. AST context, lexical shadowing, and nearest-owner hierarchy lookup can prove a unique member without guessing overload applicability.
  Date/Author: 2026-07-13 / Codex

- Decision: Resolve ordinary C# inverse member ownership at the nearest hierarchy level that declares the exact name, expanding every logical partial type before descending.
  Rationale: Accepting any ancestor would misattribute hidden members, while flattening the hierarchy would lose the level where C# name hiding becomes decisive. Callable arity filters candidates only after the declaring level is fixed; an inapplicable nearer declaration must not reopen a base member. Per-file caches keep the structured breadth-first lookup bounded in both targeted and whole-workspace scans.
  Date/Author: 2026-07-13 / Codex

- Decision: Encode C# method generic arity in the structural signature key while retaining the source-facing FQN, and apply an explicit call-site arity before value applicability and hiding.
  Rationale: Metadata arity distinguishes declarations that C# permits to share the same name and value-parameter shape. An explicit `M<T>` call can reject a wrong-arity declaration structurally, while a call without explicit type arguments must leave generic inference eligible rather than inventing a zero-arity constraint.
  Date/Author: 2026-07-14 / Codex

- Decision: Carry generic call arguments from tree-sitter nodes and persist only an AST-proven bare method-type-parameter return marker for substitution.
  Rationale: Exact `T` returns can be substituted from the explicit call arguments, while `T[]`, `T?`, and constructed forms require their existing structured return facts and must not be treated as bare `T`. Persisting this fact avoids source mini-parsing and supports reopened analyzers; changing shared bincode metadata requires a global store-epoch bump rather than relying on serde defaults.
  Date/Author: 2026-07-14 / Codex

- Decision: Derive C# extension visibility from ordered AST lexical frames and share it across forward, targeted inverse, and whole-workspace resolution.
  Rationale: Visibility must respect namespace-block range, file-scoped pre/post partitions, qualified parents, static aliases, and global usings. A common structured candidate set preserves instance-member precedence and prevents both false inverse hits and cache leakage between same-named namespace blocks.
  Date/Author: 2026-07-14 / Codex

- Decision: Use logical C# type identity only after structured syntax proves a type context; do not widen pre-binding expression receivers from physical declarations to logical FQNs.
  Rationale: Partial declarations represent one semantic type, so an object creation's type node must match every physical part with the same exact FQN and metadata arity. Ordinary receivers can be locals, parameters, or fields whose spelling resembles a type; value bindings must win before static type lookup.
  Date/Author: 2026-07-14 / Codex

## Outcomes & Retrospective

Implementation and the N=1 campaign are in progress. This section will contain the final per-language counts, issue links, fixes, performance observations, and remaining limitations.

## Context and Orientation

`src/analyzer/usages/get_definition/` resolves a source reference forward to one or more `CodeUnit` declarations. A `CodeUnit` is Bifrost's structured declaration identity and includes source path, declaration kind, package/name, signature, and synthetic status. `src/analyzer/usages/finder.rs::UsageFinder` resolves in the opposite direction, from declarations to `UsageHit` source sites. A proven differential defect exists when forward resolution uniquely identifies a declaration set, the inverse query completes without truncation, and no proven inverse hit covers the original reference token.

`src/lsp/handlers/semantic_tokens.rs` currently owns a useful but overly local `reference_candidate_ranges` helper. Move that iterative tree-sitter traversal into `src/analyzer/reference_candidates.rs` and reuse it from both semantic tokens and the new engine. Continue to use `src/analyzer/declaration_range.rs::DeclarationNameRangeContext` so declaration identifiers are not mistaken for references.

The new library module belongs under `src/reference_differential/`. It owns serializable configuration, stable declaration identity, per-site evidence, repository summaries, deterministic sampling, forward batching, inverse grouping, and comparison. The separate binary `src/bin/bifrost_reference_differential.rs` owns command-line parsing, corpus selection, Git metadata, JSONL output, progress, and exit behavior.

The corpus lives at `/home/jonathan/Projects/brokkbench/clones`, a symlink to `/mnt/T9/repo-clones`. Repository membership is the set of canonical `<commits-root>/<language>/<slug>.jsonl` files, excluding `.testsome.jsonl` sidecars. Repository size comes from `/home/jonathan/Projects/brokkbench/sft-tools-commits/repos.csv::code_loc`. Missing or invalid size metadata and invalid clones must be reported rather than silently ranked as zero.

## Plan of Work

First extract the structured reference-candidate traversal from semantic tokens without changing LSP behavior. Build the engine around one persisted `WorkspaceAnalyzer` per repository. Filter audited files by requested corpus language; C uses C-family `.c` seeds and C++ uses the remaining C++ family, while both resolve through `Language::Cpp`. Enumerate the full eligible path inventory, retain the `--max-files` lowest stable path hashes, then for each retained file read the analyzer-generation source, parse it once through `DeclarationNameRangeContext`, subtract declaration-name ranges, and feed a stable site hash-priority sampler. This makes both file and site selection independent of lexical traversal order without reparsing the entire largest checkout.

Batch sampled forward lookups per file with `resolve_definition_batch_with_source`. Preserve every status count, but assert only resolved sites whose declaration identities form one semantic target group. Exclude a recursive definition-contained site only when `analyzer.enclosing_code_unit` equals one of its forward targets, matching existing usage-hit behavior.

Group remaining sites by the full sorted `CodeUnit` set. For each target group, create an explicit candidate provider containing only files with sampled sites, set authoritative scope, and call `UsageFinder::query_with_provider` once. Compare proven and unproven hits by file and byte range. An exact or containing proven hit is consistent. A proven import or self-receiver hit is editor-only and not a production `scan_usages` defect. A retained unproven hit is reported as unproven, not inverse-missing. Incomplete inverse outcomes remain inconclusive. Only complete queries with no covering proven or unproven hit become actionable findings.

The CLI selects N repositories per language by recorded LOC and available clone, supports repeated language/repository filters, records repository HEAD and dirty state, writes append-safe JSONL records, and supports exact-site reruns. Progress goes to stderr. Normal corpus findings do not make the process fail; `--strict` makes actionable findings return a nonzero exit code for later CI use.

After small-fixture and local-repository validation, run the eleven selected repositories sequentially. Preserve reports under `.agents/docs/reference-differential/` because they are agent-facing campaign evidence, not public documentation. Triage each actionable record against source and analyzer behavior. File GitHub issues only after confirming the forward identity and inverse absence are semantically valid. Fix root causes through structured analyzer support, add behavior regressions, run CI-equivalent checks, push `master`, comment on and close fixed issues, then resume the campaign until every target language has a completed report.

## Concrete Steps

Work from `/home/jonathan/Projects/bifrost`.

Build and smoke-test the engine:

    cargo fmt --all -- --check
    cargo test --features nlp,python --test bifrost_reference_differential_cli
    cargo run --release --bin bifrost_reference_differential -- run-repo \
      --root /home/jonathan/Projects/bifrost \
      --language rust --max-sites 200 \
      --output /tmp/bifrost-reference-differential-smoke.jsonl

Run the corpus campaign with N=1 and resumable output:

    cargo run --release --bin bifrost_reference_differential -- run-corpus \
      --clones-root /home/jonathan/Projects/brokkbench/clones \
      --commits-root /home/jonathan/Projects/brokkbench/sft-tools-commits \
      --repos-per-language 1 --max-files 1000 --max-sites 10000 --max-targets 1000 \
      --output .agents/docs/reference-differential/n1.jsonl

The deterministic N=1 selection is:

    c       RMerl__asuswrt-merlin.ng       49,660,873 LOC
    cpp     chromium__chromium              25,845,431 LOC
    csharp  Azure__azure-powershell         17,025,991 LOC
    go      aws__aws-sdk-go-v2              13,062,919 LOC
    java    googleapis__google-cloud-java   33,055,102 LOC
    js      nodejs__node                    11,009,467 LOC
    php     moodle__moodle                   4,155,681 LOC
    py      googleapis__google-cloud-python 14,880,589 LOC
    rust    biomejs__gritql                  5,863,967 LOC
    scala   JetBrains__intellij-scala          749,890 LOC
    ts      elastic__kibana                  9,622,097 LOC

Before each push, run:

    cargo fmt --all -- --check
    cargo clippy --all-targets --all-features -- -D warnings
    cargo test --features nlp,python

If the complete suite is impractical after a narrow language fix, the ExecPlan must record the targeted suites and why any broader gate was not run; before final completion the full required gate must pass.

## Validation and Acceptance

The engine is accepted when a dedicated CLI can select repositories reproducibly, scan real structured references, emit deterministic resumable evidence, and reproduce one site exactly. A controlled fixture must prove that a forward-resolved reference present in inverse results is classified consistent and that an intentionally withheld inverse site is classified missing without using text search.

The campaign is accepted only when all eleven target language buckets have a completed N=1 repository record. Every actionable disagreement must be triaged. Every genuine defect must have an issue URL, a root-cause fix on pushed `master`, behavior-focused regression coverage, and a closed issue containing the fixing commit. The final summary must state per language: selected repository, sampled and forward-resolved site counts, consistent/editor-only/unproven/inconclusive/actionable counts, runtime, issues created, and fixes landed.

## Idempotence and Recovery

Repository selection and sampling are deterministic for the same metadata, HEAD, seed, and budgets. JSONL output is append-safe and identifies completed repositories so an interrupted campaign can resume without re-running them unless `--force` is supplied. Analyzer caches are the existing per-clone `.brokk/bifrost_cache.db`; do not invent another cache. Do not alter corpus checkouts. Exact-site reruns must be read-only. Existing unrelated untracked `.agents/docs` and `.brokk` files in the Bifrost worktree must remain untouched.

If a corpus repository fails to build an analyzer, record an engine-error repository summary with the failure and continue to the next language. Such a failure does not satisfy campaign completion until it is fixed or shown to be an environmental limitation outside Bifrost and explicitly documented.

## Artifacts and Notes

The canonical campaign output will live at `.agents/docs/reference-differential/n1.jsonl`, with a concise final narrative at `.agents/docs/reference-differential/n1-summary.md`. These are LLM-facing run artifacts and therefore belong under `.agents/docs`, not public `docs/`.

The N=1 ranking uses whole-repository recorded LOC, not per-language LOC. This is the corpus's existing uniform size measure. The report also records matching tracked-file counts so mixed-language repositories remain interpretable.

The post-#738 C# result is a binary-pinned pushed-commit measurement whose JSONL records a dirty worktree because #739 edits overlapped the run. Treat its counts as the aggregate #737/#738 boundary and use the post-#739 clean-head rerun as the next durable resumption record.

The #739 production proof is `/tmp/csharp-exact-739-generic-final.jsonl`: Azure PowerShell `PsExtensions.cs` bytes `7144..7153` resolve to `Microsoft.Azure.PowerShell.Cmdlets.CustomProviders.Runtime.PowerShell.PsHelpers.RunScript` with signature `` `1(CommandInvocationIntrinsics, string)`` and retain a proven exact inverse range after the global store-epoch rebuild.

The pushed-head #739 proof is `/tmp/csharp-exact-739-generic-pushed.jsonl`, and the complete post-fix resumption record is `/tmp/csharp-n1-739-pushed.jsonl`. Both are pinned to `9ece3b65`; their dirty flag reflects preserved unrelated working-tree files, not analyzer-source drift. The full record audited 1,000 of 126,829 eligible C# files, sampled 10,000 sites, queried 1,000 of 2,136 distinct target groups, and explicitly records one candidate-limit-exceeded file plus 2,082 target-truncated sites as inconclusive rather than actionable.

The #740 production proof is `/tmp/csharp-exact-740-partial-initializer-final.jsonl`: Azure PowerShell `generated/Mdp/Mdp.Autorest/generated/runtime/ISendAsync.cs` bytes `3733..3741` resolve to `Microsoft.Azure.PowerShell.Cmdlets.Mdp.Runtime.HttpPipeline.pipeline` and retain a proven exact inverse range across the type's physical partial declarations.

The #741 production proof is the final record in `/tmp/csharp-exact-741-conditional-final.jsonl`: Azure PowerShell `generated/MachineLearningServices/MachineLearningServices.Autorest/generated/api/Models/PartialBatchDeployment.json.cs` bytes `7147..7155` no longer resolve to the sibling partial model's `ToString`; the structured explicit `(object)` receiver produces `no_definition`, an inconclusive external boundary, and zero actionable findings.

The C# `nameof(member)` differential-engine proof is the final record in `/tmp/csharp-exact-nameof-editor-only-final.jsonl`: Azure PowerShell `generated/ConnectedMachine/ConnectedMachine.Autorest/generated/api/Models/HybridIdentityMetadata.cs` bytes `15226..15254` remain forward-resolved for editor navigation but are classified `editor_only`, omitted from inverse grouping, and produce zero missing or actionable findings.

The durable C# N=1 closure record is `/tmp/csharp-n1-741-nameof-pushed.jsonl`, pinned to pushed head `1a1bc901`. Its dirty flag reflects the preserved unrelated Rust test and untracked working artifacts, not analyzer or differential-engine drift. The completed report contains zero missing/actionable sites, so later work should not reopen C# unless another language exposes a shared root cause.

## Interfaces and Dependencies

In `src/analyzer/reference_candidates.rs`, provide an iterative function that accepts a tree-sitter root and `Language` and returns stable `Range` values for structured identifier leaves, with a caller-provided limit or explicit overflow result. Semantic tokens and the differential engine must call this shared function.

In `src/reference_differential/mod.rs`, expose serializable report types and a repository runner. The core configuration must include corpus language label, site/target/file/usage limits, deterministic seed, test inclusion, and optional exact site. Stable declaration identity must include normalized path, fully qualified name, kind, signature, and synthetic status. The runner must accept an already-built analyzer so tests can use transient workspaces while the CLI uses persisted workspaces.

In `src/bin/bifrost_reference_differential.rs`, provide `run-repo` and `run-corpus` subcommands, `--help`, JSONL output, stderr progress, and `--strict`. Add the `csv` crate only if structured CSV parsing cannot reuse an existing dependency; do not parse `repos.csv` with string splitting.

Revision note (2026-07-12): Created the initial self-contained plan after architecture and corpus inventory. It records the full N=1 campaign, not merely engine construction, because completion requires triage and fixes across every target language.

Revision note (2026-07-12): Changed sampling to a deterministic two-stage file/site design after confirming that the largest selected repositories contain more than 100,000 matching source files. This preserves broad path coverage without parsing every file solely for sample selection.

Revision note (2026-07-12): Added a deterministic target-group cap and disk-safety checks after inventory showed that all large-repository analyzer databases must be built cold and that sampled sites may otherwise produce thousands of separate inverse queries.

Revision note (2026-07-12): Recorded the all-language preflight and made resume identity commit-aware after review showed that package-version-only records could survive analyzer fixes incorrectly.

Revision note (2026-07-12): Corrected the #643 diagnosis after debugger capture identified self-initializer binding recursion as the stack overflow, and recorded the exact low-stack/RSS validation of the SQLite and traversal fixes.

Revision note (2026-07-12): Recorded the first complete Rust differential triage and the #644/#645 root fixes, including the macro-token field gap found by exact-site validation.

Revision note (2026-07-12): Recorded pushed and closed #698 and its exact Azure production proof, separating C# qualified-type focus/range semantics from partial target grouping and authoritative candidate routing.

Revision note (2026-07-12): Recorded the full post-#698 C# rerun, its 83.6% missing-site reduction, and the next explicit-interface declaration triage boundary.

Revision note (2026-07-12): Recorded delegated #701 investigation, complete validation, and exact production proof for the explicit-interface owner role.

Revision note (2026-07-12): Recorded #703 after rejecting the invalid post-#701 C# record and made stable audited scope a campaign-engine invariant.

Revision note (2026-07-12): Recorded the valid post-#701/#703 full C# rerun and the next 39-site generic-argument boundary.

Revision note (2026-07-12): Recorded delegated #704 investigation, exact production proof, and exact-mode full-inventory cost for the next engine optimization.

Revision note (2026-07-12): Recorded pushed/closed #704, the valid post-fix full C# record, its 103-site residual partition, and the reviewed exact-mode fast-path boundary.

Revision note (2026-07-13): Recorded reduced #705, its production timing and truthful summary semantics, and the delegated shared `using static` type-role boundary.

Revision note (2026-07-13): Recorded pushed/closed #705 and #706's reduced shared-role fix, persistence epoch bump, focused validation, and exact production proof.

Revision note (2026-07-13): Recorded pushed/closed #706, the valid complete post-fix C# record, removal of all 34 static-import misses, and the 69-site residual partition.

Revision note (2026-07-13): Marked the campaign deliberately paused after #706 for release `0.8.0` without changing the remaining campaign scope.

Revision note (2026-07-13): Recorded post-release resumption, delegated #707 analysis across all cast families, the shared persisted/inverse fix, and exact production validation.

Revision note (2026-07-13): Recorded pushed/closed #707, the complete post-fix 1,000-target record and its 38-site residual, plus the reduced generic-identity boundary and local structured fix awaiting production validation.

Revision note (2026-07-13): Recorded #726, the audited generic identity fix, and exact Azure validation before the fixing checkpoint.

Revision note (2026-07-13): Recorded #727's delegated reduction and review, dual-spelling structured attribute resolution, complete feature-suite validation, and both exact Azure production outcomes.

Revision note (2026-07-13): Recorded pushed/closed #727, the complete post-fix C# record, elimination of every attribute miss, and delegated prioritization of the nineteen-function/four-field residual.

Revision note (2026-07-13): Recorded #732's delegated review, conservative callable-interval implementation, persisted local/global static-import visibility, receiver compatibility, focused validation, and both exact Azure production outcomes.

Revision note (2026-07-13): Recorded pushed #732, its green CI and final fixing-head Azure record, plus #737's reduced method-group boundary, reviewed structured fix, complete affected validation, and exact production proof.

Revision note (2026-07-13): Recorded pushed/closed #737 with green CI, then #738's reduced inherited-member differential, reviewed nearest-level implementation, full feature-suite validation, and exact Azure production proof.

Revision note (2026-07-14): Recorded pushed/closed #738 and its binary-pinned post-fix corpus counts, then #739's reduced explicit-generic-method boundary, shared generic-arity and lexical-visibility design, delegated review, complete feature-suite validation, and exact Azure production proof.

Revision note (2026-07-14): Recorded pushed/closed #739, its pushed-head exact proof, the complete post-fix Azure N=1 counts, and delegated the five-site residual partition for read-only triage.

Revision note (2026-07-14): Recorded the five-site residual triage, #740's reduced partial-type initializer defect, the narrowed logical-identity fix and shadowing negative, delegated review, and exact Azure production proof.

Revision note (2026-07-14): Recorded the synchronous Oldskool implementation, review, Windows-only clippy repair, exact CI proof, and closure of incidental issue #743 before the C corpus run.

Revision note (2026-07-14): Recorded the completed C N=1 corpus counts, commit pins, resource observation, and delegated read-only triage boundary.

Revision note (2026-07-14): Recorded the complete C missing-site partition, pushed/closed #760 with exact production evidence, and the reduced assigned #762 nested-member boundary.

Revision note (2026-07-14): Recorded #762's reviewed structural chain implementation, the production-only inline-tag typedef boundary found by exact validation, its structured canonicalization fix, and the successful dirty-tree exact rerun pending pushed-head proof.

Revision note (2026-07-14): Recorded pushed commit `7f72d0a2`, the clean exact-range production proof for nested typedef member chains, focused gate counts, and closure of #762.
