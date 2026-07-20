# Complete the C#, Go, Java, JavaScript, and TypeScript top-five reference differential

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` current while the work proceeds. Maintain it in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost's forward-vs-inverse reference differential checks a public symbols invariant: when definition lookup resolves a source reference to a declaration group, the inverse usage query should recover the same source range. This campaign completes that audit for the five repositories with the most fully filtered SFT tasks in each of C#, Go, Java, JavaScript, and TypeScript.

The observable result is 25 accepted repository records selected by descending fully filtered task count through `/home/jonathan/Projects/brokkbench/tasks.py`. The selection calls `task_repos(SFT_PREDICATES, langs=[...])` and orders the returned `RepoRef` values by descending `task_count`; `SFT_PREDICATES` excludes `large-repos.csv` members and also enforces the build, testsome, binding, generated-prompt, non-fragile-test, and skip gates. Earlier Java, Go, C#, JavaScript, and TypeScript records selected repositories by code size and remain useful regression evidence, but they do not satisfy this task-ranked campaign. Every new raw `missing` site is checked against live source bytes, the tree-sitter role, forward identity, inverse limits, and an exact-site rerun. A legitimate defect receives a GitHub issue assigned to `jbellis` before implementation; an issue assigned to anybody else is recorded and skipped. Accepted fixes receive structured behavior tests, exact production evidence, formatting, all-target/all-feature Clippy, the complete `cargo test --features nlp,python` gate, direct integration to `origin/master`, and a clean final corpus confirmation. GitHub CI is not a blocking gate after local tests pass.

The acceptance surface is the MCP `symbols` toolset and its associated Rust and Python APIs. LSP shares analyzer implementation and remains covered by the full test suite, but editor-protocol behavior is not the focus.

## Progress

- [x] (2026-07-19 18:30Z) Reconciled the clean current worktree with `origin/master` at `b20da06f6ed1646289dc8bbd6ee9a6ca5b9fcc0d` and read `.agents/PLANS.md` plus the operator runbook at `/home/jonathan/Projects/bifrost/.agents/docs/reference-differential-runbook.md`.
- [x] (2026-07-19 18:35Z) Independently audited durable campaign evidence and GitHub state. Java has five accepted records at `431f1292`; Go has five accepted records at `20fec8af`; all campaign-created Java and Go issues are assigned to `jbellis` and closed.
- [x] (2026-07-19 18:38Z) Ran the current runner's no-write dry-run and pinned the canonical 25-repository selection. All 15 C#/JS/TS clone heads match corpus metadata and have no tracked dirtiness; no analyzer process owns a selected clone.
- [x] (2026-07-19 18:45Z) Committed the campaign-start plan as `127c5817`, locally excluded generated `.brokk/` state in all 15 selected C#/JS/TS clones, verified their tracked cleanliness, rebuilt the release runner, and recorded SHA-256 `4fcf6bf7c500906cb6ad1e845eac5a450e6b3a14608b22bd34ddcc8c3eb81edf`.
- [x] (2026-07-19 23:10Z) Diagnosed the first C# attempt without accepting it: Azure PowerShell's preserved 4.9 GB cache is physically malformed, and Azure SDK was interrupted before writing a record when the shared worktree changed. Recorded the diagnostic provenance and clean-head restart requirements in `.agents/docs/reference-differential/csharp-adfa8e0f-baseline-audit.md`.
- [x] (2026-07-20 02:50Z) Preserved three clean C# `08ca4f09` repository envelopes and exhaustively classified their 89 raw missing rows: Azure PowerShell has no missing rows, Azure SDK's 27 are wrong-forward overload/extension identities, and Mono has 17 legitimate rows in four root-cause families plus 45 non-actionable rows. Exact clean witnesses reproduce all four Mono families.
- [x] (2026-07-20 03:50Z) Profiled the remaining .NET runtime inverse target after the other 999 groups completed. The worker was productive but pathologically CPU-bound in SQLite short-name definition fanout for more than two hours. Filed and assigned #945 before implementation, then intentionally interrupted the diagnostic baseline. The partial artifact is not a five-repository acceptance record; runtime emitted no envelope and Roslyn never started.
- [x] (2026-07-20 03:36Z) Implemented and independently reviewed #945: C# inverse resolution now shares the generation-scoped definition index, prepares each candidate file once per target group, and logs target starts. The persisted regression proves exact alias/global-using hits, same-name-owner exclusion, one index build across repeated queries, zero inverse candidate SQL, and unchanged bounded forward lookup. Formatting, all-target/all-feature Clippy, 89 targeted usage tests, 28 whole-graph tests, and the CLI progress test pass.
- [x] (2026-07-20) Production-proved and closed #945 on clean .NET runtime: all 1,000 inverse groups completed, the former outlier is `Interop` and fell from more than two hours to 63.5 seconds, total repository time was 495.9 seconds, and peak RSS was 1.40 GiB.
- [x] (2026-07-20) Exhaustively classified all 174 clean .NET runtime raw rows as 45 genuine across seven structured families and 129 nonactionable forward/declaration rows. Eight clean exact records reproduce every family. Reopened assigned #231, #423, #701, #726, and #737; created assigned #946. Durable ledger: `.agents/docs/reference-differential/csharp-b645f878-runtime-audit.md`.
- [x] (2026-07-20) Implemented and independently reviewed the first bounded C# correctness checkpoint. #231 no longer treats class fields/events as lexical locals and retains structured field/property receiver typing; #737 recognizes the null-forgiving postfix wrapper around method-group arguments. A persisted duplicate-physical regression for #423 is already green and makes zero inverse candidate SQL queries, so no speculative #423 change was made. Formatting, all-target/all-feature Clippy, 92 targeted C# usage tests, 29 whole-workspace C# graph tests, and 503 feature-enabled definition tests pass.
- [x] (2026-07-20) Cleanly exact-proved and closed #231 and #737 at `2436a662`. The runtime `SQLTicksPerMinute` and `PoolableCommit!` witnesses are each completed, clean, consistent one-site records with zero file errors. Exact reruns also prove #423 and #726 still reproduce, and production tracing reduces both to one visible-type precedence defect: imported `System.Collections.Generic.List`1` is incorrectly combined with lower-priority global `List`1` declarations.
- [x] (2026-07-20) Implemented and independently reviewed the shared #423/#726 visibility fix. Type lookup now stops at the first nonempty workspace visibility tier while preserving ambiguity within the using tier, and explicit `global::` survives graph alias expansion. Persisted runtime-shaped receiver and constructor regressions cover duplicate physical declarations, generic/non-generic identity, arity, nearest enclosing fallback, explicit global lookup, and reopened default routing. Formatting, diff hygiene, 93 targeted inverse tests, 29 whole-workspace graph tests, 503 feature-enabled definition tests, and isolated all-target/all-feature Clippy pass.
- [x] (2026-07-20) Cleanly exact-proved and closed #423 and #726 at fixing commit `fadbaa91` with release runner SHA-256 `d5c2fcb5f83be17336ea5c2da0ab53ec39da62cc06e0aad596645e44507c4cf9`. Runtime `argNames.ToArray()` is one consistent site with zero missing/file errors (23.5 s wall, 1.07 GiB peak RSS; artifact SHA-256 `96fa5964e672342c293824cbedba6e22ccf8ea4a4cb6080ff65c13d8cf9cd665`). Mono `new List<ActivityPropertyReference>()` is likewise one consistent site with zero missing/file errors (18.7 s wall, 946 MiB peak RSS; artifact SHA-256 `6b86a4dcde4551ea9a57f5ec72a6c18007b4d9e12b87b7fbf5b0fafd1030f03d`).
- [x] (2026-07-20) Re-profiled every #946 production witness before implementing the proposed overload metadata refactor. All three `Vector128.As<TFrom,TTo>` sites are clean, consistent, exact-range inverse hits at `fadbaa91`/`204061c6`, with zero file errors and 23.7-24.6 s wall profiles. Closed #946 with the corrected root cause: the shared visibility-tier repair recovered the `Vector128` owner, so structured argument-type overload filtering was not required by these witnesses.
- [x] (2026-07-20) Preflighted the remaining broadened #701 matrix at the clean fixing head. Four runtime and three Mono witnesses remain resolved-forward/missing-inverse with zero diagnostics or file errors. Read-only production tracing separates AST role/root omissions (alias RHS, intermediate nested/static owners, and type patterns) from an arity-unsafe normalized-FQN fallback that combines nongeneric `ICollection` with `ICollection<T>` even in already-recognized parameter and explicit-interface roles.
- [x] (2026-07-20) Implemented and independently reviewed the first #701 checkpoint. Shared tree-sitter type-root helpers now cover alias RHS, ordinary type roles, intermediate nested/generic receivers, and speculative type-pattern candidates; arity-preserving normalized lookup retains nested-separator parity and all physical partial declarations. Review found and fixed constant-pattern member suppression plus inherited field/property shadow omissions. The first clean exact attempt accepted the runtime alias but retained `Constants.Globals` only as unproven, correctly preventing premature issue closure.
- [x] (2026-07-20) Fixed and independently reviewed the remaining relative dotted-type lookup defect exposed by exact proof. Current and enclosing namespace tiers now resolve `Constants.Globals`; the using tier admits only nested types whose declaration package is the imported namespace, so `using Imported; System.String` cannot incorrectly select `Imported.System.String`. Direct, inverted, and forward controls cover relative nested types, imported nested types, imported child-namespace rejection, global fallback, and routing. Formatting, diff hygiene, 95 targeted inverse tests, 30 whole-workspace graph tests, 505 feature-enabled definition tests, 11 C# analyzer tests, the focused arity unit test, and isolated all-target/all-feature Clippy pass.
- [x] (2026-07-20) Restarted exact proof at clean `379f0819`: runtime alias RHS and `Constants.Globals` are each consistent, but the simple `member is TypeBuilderInstantiation` witness remained missing. A temporary tree-sitter ancestry probe, removed immediately after diagnosis, proved this grammar emits the simple form as `is_expression` with a required `right: type` field rather than the already-covered `constant_pattern` shape.
- [x] (2026-07-20) Added and independently reviewed the missing structured `is_expression.right` type role in the shared root helper. A production-shaped two-physical-part regression covers authoritative inverse use and default routing, and whole-graph coverage proves the logical partial-type edge. Formatting, diff hygiene, 96 targeted inverse tests, 31 whole-workspace graph tests, 505 feature-enabled definition tests, 11 C# analyzer tests, the focused arity unit test, and isolated all-target/all-feature Clippy pass.
- [x] (2026-07-20) Exact-proved all seven #701 production witnesses at clean final fixing head `530fb3d1` with release runner SHA-256 `1a3fa81fdaf482891e38acf42e654f4cf32da989149389f67e5d174f28b1a707`. Every runtime and Mono record is completed, samples exactly one requested site, classifies it consistent, and has zero missing/unproven rows or file errors. The recovered runtime pattern invocation appended two independently clean identical records to one preserved raw artifact; the duplicate is disclosed and both records pass the same checks.
- [x] (2026-07-20) Posted the final fixing commits, runner checksum, and all seven artifact checksums to solely assigned issue #701 and closed it as completed.
- [x] (2026-07-20) Preserved the fresh `f7511c92` C# run as diagnostic after three completed envelopes exposed four candidate-ceiling exclusions and runtime's final `Interop` inverse target remained CPU-active for more than 20 minutes. Two zero-loss profiles identify `CodeUnit` sorting and `namespace_of_file`, distinct from #945's former SQLite fanout. Runtime wrote no envelope and Roslyn did not start. Durable audit: `.agents/docs/reference-differential/csharp-f7511c92-baseline-audit.md`.
- [x] (2026-07-20) Reduced the blocker to a persisted multi-namespace routing failure, filed solely assigned #954, and implemented a structured implicit-index fix that records all top-level namespaces without ordering complete declaration sets. The formerly red regression, 97 targeted C# usage tests, 31 whole-workspace graph tests, 11 analyzer tests, six persisted C# cache tests, 505 definition tests, formatting, diff hygiene, and isolated all-target/all-feature Clippy pass. A dirty exact runtime proof reduces `Interop` inverse time to 34.1 seconds and is strict/consistent with zero file errors.
- [x] (2026-07-20) Cleanly exact-proved and closed #954 at fixing commit `093b17cd` with runner SHA-256 `9b879fa7d56a25cceee881abb1bdb466783e1d854a11dbcc9d2438cd8446461f`. The runtime witness resolves 1,219 physical `Interop` declarations, completes inverse in 36.8 seconds, recovers the exact requested range, and reports one consistent site with zero missing/unproven rows or file errors. Artifact SHA-256: `aecfcaa16544e17645a9f0f4446757c08bcfceda1145618ce91e8d569a67abc4`.
- [x] (2026-07-20) Reopened #954 after the raised-ceiling full run exposed a second `Interop` hot path. A live zero-loss 30-second profile attributes 77.29% self time to `memcmp` while graph resolution repeatedly materializes sorted declarations for global-namespace `namespace_of_file` lookups. Added a bounded per-generation namespace cache without changing first-lookup semantics; all 97 C# usage graph tests pass, and a dirty ephemeral exact proof completes the 1,219-target inverse group in 26.9 seconds with one exact consistent hit and zero file errors.
- [x] (2026-07-20) Committed the residual #954 namespace cache as `cf8e7ff0`, passed formatting, isolated all-target/all-feature Clippy, 97 targeted C# usage tests, 31 whole-workspace graph tests, 11 analyzer tests, six persisted-cache tests, and 505 feature-enabled definition tests, then cleanly exact-proved the runtime witness. The 1,219-target inverse phase completes in 27.9 seconds with one exact consistent hit and zero diagnostics/file errors; artifact SHA-256 `f01e3959814f8190e994aab4e5b8e846828841e408826130775314140169f9b3`.
- [x] (2026-07-20) Audited the user's explicit selector requirement against `tasks.py` and found that the existing plan and records used the differential runner's code-LOC ranking instead of descending filtered task count. Recomputed all five language sets through `task_repos(SFT_PREDICATES, langs=[...])`, which explicitly filters `large-repos.csv`, and invalidated the prior LOC-ranked records as completion evidence for this objective without discarding their regression value.
- [x] (2026-07-20) Merged the completed analyzer work from `bifrost-burndown-3` into the current `bifrost-burndown-a1` branch, configured clone-local excludes for generated `.bifrost/` and `.brokk/` state in all 25 newly selected clones, and verified every selected clone and the Bifrost worktree are clean at their pinned heads.
- [x] (2026-07-20) Passed the publication gate for the accumulated analyzer fixes: `cargo fmt --all -- --check`, the complete `cargo test --features nlp,python` suite outside the restricted process sandbox, and isolated `cargo clippy --all-targets --all-features -- -D warnings`. The sandboxed test attempt's only failures were three process-I/O tests blocked by `EPERM`; the identical escalated suite passed them and all remaining tests.
- [x] (2026-07-20) Published clean campaign checkpoint `c7c62c4f593de15b31ceceb17044abf3bbb51aca`, rebuilt the release runner (SHA-256 `0a13f2c686d2d8f6ad45b776b9c57018a54ff579aad9986ce950e9a4a18ed7`), and dry-ran each language with exactly the five explicit task-ranked slugs. A combined-language invocation was rejected because polyglot membership leaked across language sets; the accepted campaign therefore uses five independent commands.
- [x] (2026-07-20) Completed all 25 task-ranked repository envelopes with clean pinned repository and Bifrost provenance, zero file errors, and zero candidate-limit overruns. C#, Go, JavaScript, and TypeScript each have one five-record artifact. Java is the union of clean fastjson2 and LanguageTool records in the interrupted main artifact plus clean one-record Hutool, Halo, and Dubbo artifacts; the main runner was stopped only after LanguageTool's second envelope became durable and before its redundant Halo pass completed.
- [x] (2026-07-20) Exhaustively dispositioned every baseline `missing` row against source bytes, structured AST roles, forward identities, inverse diagnostics, and query limits. Go has 1,935 rows (1,782 focus artifacts, 148 explicit partial chains, four declaration candidates, one package-variable write); JavaScript has 46 (18 genuine across #944/#964, 28 nonactionable); TypeScript has ten genuine across #963-#965; C# has 60 (47 genuine, twelve wrong-forward, one declaration candidate); Java has 979 (882 focus artifacts, five static-import shadow errors, four explicit-import errors, four constructor references, 82 generated-accessor references, one nested-type method reference, and one local-receiver/import collision).
- [x] (2026-07-20) Filed or broadened every legitimate task-ranked issue and assigned it solely to `jbellis` before implementation: #963-#986 and #989, with #944 reopened for the assignment-RHS extension. Verified that #665, #942, and #943 are already implemented and closed. No issue has another assignee.
- [x] (2026-07-20) Cleanly exact-reproduced every new root family at the frozen checkpoint, including all prior Go/JS/TS witnesses, the Terminal/Granit C# families, the remaining Mapperly/ClosedXML families, and the Java focus/import/static-shadow/constructor/generated-accessor/nested-method-reference/local-receiver families. The fresh ephemeral Mapperly tuple-type run remains actionable, disproving a cache-only explanation; its implementation must repair the structured tuple role and bump the C# analysis epoch because `e1a55cb3` also changed persisted type edges without invalidation.
- [x] (2026-07-20) Completed delegated read-only implementation designs for every open issue. While the long LanguageTool tail ran, created a non-Git scratch copy and delegated isolated prototypes for #944, #968, and #970; the actual branch and every selected clone remained unchanged until all corpus and exact evidence was durable.
- [x] (2026-07-20) Published and closed #968 after the exact Go partial-selector witness became clean at `e000d73d`; published and closed #944 at `89c45e9f` after same-binding JavaScript assignment/object-member reads became exact. Both release-built exact records are clean, strict, consistent, and have zero missing rows.
- [x] (2026-07-20) Completed the task-ranked TypeScript issue set. #963 was already fixed upstream and exact-proved for both Vue qualified-type witnesses at `89c45e9f`; #964 added canonical inverse seeds for anonymous JavaScript/TypeScript default exports and was published at `9dfe32ab`; #965 expanded intersection-alias receiver annotations through structured property-owner resolution and was published at `8b42786b`. All three issues are closed with clean exact evidence.
- [x] (2026-07-20) Published and closed C# #974 at `ff95321d`: logical partial-type ancestry now combines bases from every physical declaration, and the Terminal.Gui inherited `KeyBindings` witness is exact and consistent. Published and closed #971 at `a86ae862`: structured method-group value contexts now cover event/delegate assignments and initializers while preserving shadowing and overload ambiguity.
- [x] (2026-07-20) Published and closed C# #966 at `40474cd1`: object-initializer labels resolve the constructed type and select the nearest inherited member rather than requiring direct owner equality. Both Granit inherited-property witnesses are clean and exact. The publication gate included formatting, all-target/all-feature Clippy, the full serialized `cargo test --features nlp,python` suite, direct `origin/master` integration, and release-built proof.
- [x] (2026-07-20) Published and closed Go #970 at `7f99a891`: ordinary `=` writes preserve an unshadowed package-variable binding in both targeted and inverted scanners while `:=`, local `var`, and parameter shadows remain lexical. The clean Ollama exact record is consistent with zero actionable findings; formatting, Clippy, focused Go suites, and the complete serialized all-feature test suite passed before publication.
- [ ] File/assign, implement, review, test, and exact-prove every legitimate C# root cause not owned by another user.
- [x] (2026-07-20) Implement, review, test, exact-prove, and close the remaining assigned JavaScript issue #944 and shared JS/TS default-export issue #964; retain already-closed #665/#942/#943 without speculative changes.
- [x] (2026-07-20) Complete the same baseline, disposition, issue, implementation, and proof lifecycle for TypeScript.
- [ ] Implement, review, test, exact-prove, and close the assigned Go issues #967-#970, Java issues #976-#979/#985/#986/#989, and runner/declaration issues #968/#969.
- [ ] Run final local gates, integrate directly to `origin/master`, rebuild from the clean pushed head, rerun every affected top-five leg, close assigned issues with evidence, and publish compact checked-in reports.
- [ ] Perform a 25-repository completion audit against the authoritative artifacts, issue state, clean worktree, and remote master, then record the final retrospective.

## Surprises & Discoveries

- Observation: One .NET runtime inverse target remained serially CPU-bound for more than two hours after the other 999 target groups completed; the process was healthy rather than deadlocked.
  Evidence: A 30-second `perf` capture collected 2,917 samples without loss. Self time included 23.33% `sqlite3BtreeIndexMoveto`, 14.21% `memcmp`, 18.17% pthread mutex lock/unlock, and 7.15% SQLite page-cache fetch. A 15-second hot-thread sample measured 0.91 instructions per cycle and about 20% cache misses among reported cache references while RSS remained near 7 GB.

- Observation: C# inverse type resolution uses forward-oriented short-name fanout even when it knows the candidate FQN and already owns a generation-scoped whole-workspace definition index.
  Evidence: `CSharpAnalyzer::type_candidates_by_fqn` calls `forward_definition_fqn`, and `partial_type_parts` calls `get_definitions`; both reach `TreeSitterAnalyzer::sql_definition_candidates_vec`, which fetches every same-short-name declaration and filters exact identity in Rust. Java commit `1f5b5b00` is the direct precedent for routing only inverse resolution through `GlobalUsageDefinitionIndex` while leaving public forward requests bounded.

- Observation: Eliminating the C# inverse SQL fanout required a complete usage-only resolver surface, not only replacing the first type lookup.
  Evidence: The reviewed implementation routes visible and partial types, member owners, identifiers, namespaces, attributes, inheritance, extensions, aliases, and global static usings through `GlobalUsageDefinitionIndex`; forward wrappers retain persisted lookup. The persisted `InlineTestProject` regression exercises partial generic declarations, alias and global-using consumers, and an unrelated normalized same-name owner. Two inverse queries share one index build and make zero definition-candidate queries, while the preceding forward lookup does not build the index and does exercise bounded SQL.

- Observation: #945 converts the runtime inverse phase from an unbounded campaign blocker into a bounded workload, while target-start progress identifies the remaining heaviest group exactly.
  Evidence: At clean `b645f878`, inverse started at 430.8 seconds, 999 groups completed by 441.2 seconds, and `Interop` completed at 494.3 seconds. The repository envelope was durable at 495.9 seconds. The earlier diagnostic remained at 999/1000 for more than two additional hours and consumed about 7 GiB RSS; the fixing run peaked at 1.40 GiB.

- Observation: The completed runtime corpus has a high raw missing count but a compact genuine root surface.
  Evidence: Exhaustive byte/AST review partitions 174 rows into 104 generic-parameter short-name false forwards, 24 other wrong-forward identities, one declaration terminal, and 45 genuine inverse gaps. The genuine rows reduce to alias RHS, self fields, nested qualifiers, typed receivers, type roles, overload-typed chained returns, and a null-forgiving method group. Eight clean exact reruns reproduce one representative per surface with no limits or file errors.

- Observation: C# member declarations were entering the local-inference engine as lexical bindings, which made a field initializer such as `Minute = Tick` reject `Tick` as a local shadow.
  Evidence: The faithful duplicate-physical `InlineTestProject` failed with zero hits before the change and four exact initializer reads after it. Simply dropping member bindings from the whole-workspace scanner initially regressed `_service?.Run()`; the accepted implementation instead recovers an unshadowed enclosing field/property's declared type structurally before considering a static type. The complete 29-test whole-workspace suite caught and now covers that boundary.

- Observation: The runtime null-forgiving method-group miss is an AST transparency gap, not a method-candidate ambiguity.
  Evidence: Tree-sitter represents `PoolableCommit!` as a `postfix_unary_expression`; admitting only the exact postfix `!` wrapper lets the existing unique/ambiguous method-group resolver prove the intended edge while preserving parameter shadowing and overloaded candidates as non-proven.

- Historical observation: The first production-shaped #423 receiver reduction did not fail before the global-collision fixture was made faithful.
  Evidence: Duplicate physical declarations for `List<T>` and `NodeFactory` alone recovered `argNames.ToArray()`, `parts.Reverse()`, and `factory.Target`. Adding the unrelated global `List<T>` declarations present in dotnet/runtime exposed the actual visibility-tier ambiguity; #423 is now fixed, exact-proved, and closed.

- Observation: #423 and #726 share a visible-type precedence defect rather than a receiver or generic-identity defect.
  Evidence: Clean `2436a662` exact records still miss runtime `argNames.ToArray()` and Mono `new List<ActivityPropertyReference>()`. Runtime's persisted usage index contains the two correct physical `System.Collections.Generic.List`1` declarations plus two unrelated global `List`1` test types; Mono contains the correct imported type plus seven unrelated global `List`1` declarations and `Bar.List`1`. `visible_type_candidates_inner` returns early for a current-namespace match, but after a using-namespace match it keeps appending enclosing and global namespace candidates. The resulting two logical FQNs make usage resolution fail closed. A faithful reduction becomes red by adding one unrelated global `List<T>` to the previously green persisted fixture.

- Observation: #701 contains both type-role discovery gaps and an arity-unsafe inverse fallback.
  Evidence: Alias RHS, nested qualifier, and pattern exact queries remain missing even though their inverse phases complete almost immediately after workspace startup, showing that those roots never enter type scanning. Runtime contains three physical declarations each of `System.Collections.ICollection` and `System.Collections.Generic.ICollection`1`; Mono contains one each. When an exact namespace candidate misses, `usage_type_candidates_by_fqn` strips arity in its normalized fallback and admits `ICollection`1` for a source-arity-zero `ICollection`, poisoning ordinary parameter and explicit-interface roles that are already structurally recognized.

- Observation: Constant patterns need a speculative type candidate without becoming an unconditional type-reference classification.
  Evidence: Treating the left spine of every constant pattern as a generic type reference suppressed legitimate enum/member usage such as `value is Mode.Enabled`. The reviewed implementation instead routes the enclosing pattern as a candidate, preserves ordinary member extraction, and accepts a type interpretation only after structured owner resolution and hierarchy-aware value-shadow checks. Direct tests retain qualified, bare self, and inherited constants; whole-graph tests retain the receiver-type edge and inherited-shadow exclusions. Public workspace graphs intentionally exclude fields from their endpoint catalog, so the direct usage surface is the observable assertion for the `Mode.Enabled` field itself.

- Observation: #701 exact proof exposed a third resolver layer after AST discovery and arity filtering: dotted type identities can be relative to the file namespace.
  Evidence: At clean `e1a55cb3`, runtime alias RHS became one consistent site, but `Constants.Globals` changed only from missing to unproven because `visible_type_candidates_inner` treated every dotted identity as globally absolute. The diagnostic alias artifact SHA-256 is `ac469080e94b0a4ca313f704e0d868fb252355278e586d736d0bbd71249aafe0`; the diagnostic nested artifact SHA-256 is `a9171181fbcc504ef4fe3db47f3025240a9150da6bd9425d4677f6c913110803`. Independent review then caught that blindly applying using-namespace prefixes would import child namespaces. Filtering using-tier candidates by declaration package admits `using Imported; ImportedOwner.Nested` but rejects `using Imported; System.String` as an alias for `Imported.System.String`, while current/enclosing namespace tiers and global fallback retain C# precedence.

- Observation: Tree-sitter C# represents simple type tests and pattern expressions with distinct node contracts.
  Evidence: Clean `379f0819` artifacts prove alias RHS consistent (`edd98093aa972771bdd79af525f24f4f7975817593edc827ac7b0a699baf8b4b`) and relative nested owner consistent (`ad7240f615964297690d7054f93f58395085f8edc04dbe91db880aa4c51f1cbd`), but runtime `member is TypeBuilderInstantiation` remained one clean missing row (`c0c8fac45cbb0c8627f68bdceb577c809e953746d7944d8a84654f1785af048c`). Its exact ancestry is `identifier -> is_expression`, whose required `right` field is a `type`; the earlier reduction exercised `is_pattern_expression`/`constant_pattern`. Admitting only the exact right-field node is structured and cannot capture the left value expression.

- Observation: The final #701 proof closes every originally profiled runtime and Mono family at one clean fixing head.
  Evidence: At `530fb3d1`, the runtime alias, ordinary interface parameter, relative nested owner, and simple type-test artifacts have SHA-256 `c244ec4cdabbfdfdaa2aee4ce0261cd794f997dda63950d9e661733238684b3e`, `1f0881df327603cb027c69b1d08c42db3d06c65993aec559296a3ff760449914`, `2821abdaf3339e2edef0f9585d2b034a55b973bd7622f21a668e7366d2f55d20`, and `1545267cae8cb5e3c9af860f5fc59fa784ef6bc81473e2c6c9dec2b953d5406e`. The Mono alias RHS, explicit interface, and simple `is` type artifacts have SHA-256 `dea4950ebb99dc291aebbe0280e5a6e0ceeadd50fb0aaa142a52aa1ae6cadcfc`, `3db776df14a3eeb1e48e584df316b4211195fd942ec6aa25e240a1f35b4669aa`, and `da0fc7bd6c86cfb79e45d872c431da0d8f5c3ed2eafb54086c7d7988aea6369d`. All records pin clean runtime `a0311b34` or Mono `0f53e9e1`, one sampled/forward-resolved/queried target, one consistent classification, and no file errors. The pattern artifact contains two records because a session presumed interrupted was still running outside the sandbox process namespace when its replacement began; both independently meet those criteria and the raw append-only artifact was not rewritten.

- Observation: #701's broader structured type inventory exposed an independent scaling and correctness defect in the C# implicit reverse-reference index.
  Evidence: At clean `f7511c92`, runtime completed 999 inverse groups but `Interop` remained active for more than 20 minutes at about 126-128% CPU and 4.1 GiB RSS, versus 63.5 seconds in the earlier #945 proof. A 1,570-sample zero-loss DWARF profile attributes 79.8% self time to `memcmp`, with 55.4% below stable quicksort, 16.7% in `CodeUnit::cmp`, and `namespace_of_file` frames. The reduced persisted project proves the index also omits an unqualified reference from the second namespace in one physical file. Issue #954 replaces the single-namespace/all-declarations path with all distinct structured top-level namespaces; clean exact proof over 1,219 physical `Interop` declarations completes inverse in 36.8 seconds.

- Observation: Exact one-site timing did not cover the full `Interop` graph-resolution scope.
  Evidence: The clean raised-ceiling run completed 999 runtime inverse groups quickly, but `Interop` remained active for more than 15 minutes. Its live 2,000-sample DWARF profile still attributes 77.29% self time to `memcmp` and shows `namespace_of_file`. Reference differential inverse queries use `ExplicitCandidateProvider`, ruling out default import routing. Global-namespace graph resolution repeatedly rebuilt the sorted declaration set solely to recover the same empty namespace. A per-generation namespace memo retains structured semantics while reducing the repeated exact inverse phase to 26.9 seconds in the dirty proof.

- Observation: The canonical 50,000 per-file candidate ceiling excludes valid sampled C# source below the separate 4 MiB source limit.
  Evidence: The diagnostic Azure PowerShell envelope excludes one 2.86 MB generated file; Azure SDK excludes three generated files from 0.89 MB to 3.26 MB. All report `candidate_limit_exceeded` with a 50,001 lower bound. Because accepted evidence cannot contain file errors or silently excluded source, the clean C# rerun must use one uniformly raised 250,000 ceiling while retaining every other campaign bound.

- Observation: The three rows assigned to #946 were visibility casualties, not evidence that overloaded producer arguments require new persisted type-shape metadata.
  Evidence: At the visibility fixing head, `DegreesToRadians.cs` bytes `2241..2243` and `IBinaryOperator.cs` bytes `149098..149100` and `149229..149231` are each completed one-site records classified consistent with exact inverse ranges and zero file errors. Their artifact SHA-256 values are `1fdc4c58c983cc9fcdc21603de05d501848fde68f1a7552514d4621e36779983`, `e7a1c2e181e8d51f91514c921454f037e8a914d05f4b240fa49ba347167b551a`, and `08dc12dd564c7f56d9d7fac4e1db23593fa1756c5e51d845adf2f2b23856f840`.

- Observation: The diagnostic C# artifact contains three internally clean completed envelopes but cannot be accepted as a top-five corpus.
  Evidence: `/mnt/optane/tmp/reference-differential/csharp-top5-08ca4f09.jsonl` has SHA-256 `46bd556fb236274e05ee16de65d4ef0d159d3d3d579c5159c8c7d1fa77747ba2`; its log has SHA-256 `a174d57ec8dd7c07b675794ef7bf3b005d58103f7cba4742437f20572c3d7f9d`. Runtime stopped at 999/1000 completed inverse groups and wrote no repository envelope; Roslyn never started. Because progress currently logs only after query completion, the pathological target name is not present and must not be inferred from the preceding completed target `T`.

- Observation: The canonical C#/JS/TS N=1 repositories have prior semantic coverage, but those records cannot substitute for uniform top-five evidence.
  Evidence: `.agents/docs/reference-differential/n1-summary.md` records Azure PowerShell, Node.js, and Kibana, but the original raw C# JSONL was lost and the three records do not share a current clean head/fingerprint with the remaining twelve repositories.

- Observation: Java and Go already meet the requested top-five acceptance boundary.
  Evidence: `/mnt/optane/tmp/reference-differential/java-top5-431f1292.jsonl` has five clean completed records and an exhaustive 601-row zero-genuine-residue review; `/mnt/optane/tmp/reference-differential/go-top5-20fec8af.jsonl` has five clean completed records and an exhaustive 1,114-row zero-genuine-residue review. The evidence and closed issue ledger are recorded in `.agents/plans/reference-differential-top-five-jgp.md`.

- Observation: Several nominally large JavaScript repositories are polyglot repositories with JavaScript corpus membership.
  Evidence: Canonical LOC ranking selects Kubernetes, KubeEdge, Karmada, and DevSpace after Node.js. This campaign preserves metadata-defined membership and ranking rather than replacing it with hand-picked JavaScript-heavy projects.

- Observation: One selected C# clone has generated cache state visible to Git.
  Evidence: `Azure__azure-powershell` reports only untracked `.brokk/`; the other 14 C#/JS/TS clones are clean. A local `.git/info/exclude` entry is required before accepted persisted-mode evidence.

- Observation: The first JavaScript five-repository record was semantically complete but failed the cleanliness gate for one empty-frontier repository.
  Evidence: `/mnt/optane/tmp/reference-differential/js-top5-127c5817.jsonl` has five completed pinned-head records, one fingerprint, no file errors, 11,609 total sampled sites, and 23 raw missing rows. Kubernetes reports `repo_dirty=true` solely because its newly generated `.brokk/` was not yet excluded; the local exclude now makes all five checkouts clean, so a fixing-head full rerun is required.

- Observation: Three canonical JavaScript top-five repositories have an empty current JavaScript frontier.
  Evidence: Kubernetes, KubeEdge, and Karmada each have zero tracked `.js`, `.jsx`, `.mjs`, or `.cjs` files at their pinned heads. The runbook and runner define top-N by language metadata membership, LOC rank, valid clone, and pinned head rather than by a nonempty current frontier. Their completed zero-site records are vacuous but contract-valid and must be disclosed rather than replaced with hand-picked repositories.

- Observation: DevSpace exposed two independent symbols defects despite auditing only 25 eligible JavaScript files.
  Evidence: `typeof Promise` forward-resolves to the same global property assigned as `window.Promise` but inverse lookup omits the bare read (#942). Two independent `module.exports` sites forward-resolve the CommonJS runtime host binding to an unrelated exported configuration property named `module` (#943). Both issues were created assigned to `jbellis` before implementation.

- Observation: A browser-global alias cannot be inferred from the declaration name alone.
  Evidence: Independent review of the first #942 draft found false-positive paths through local/imported `window`, later lexical `Promise` declarations (including TDZ and `var` hoisting), and a missing whole-graph edge for explicit `window.Promise`. The accepted implementation builds a shared tree-sitter lexical index only for files with exact same-file JavaScript `window.<one segment>` field/function candidates, validates the declaration receiver structurally, and covers both targeted and whole-graph paths.

- Observation: The clean fixing-head exact probes split the six unresolved Node rows into one forward and one inverse root.
  Evidence: At clean Bifrost `9547d828` and Node `2f2b81095bdc`, bare `foo()` and nested bare `pause()` incorrectly resolve to unrelated `__v_0.foo` and `Readable.prototype.pause`; four direct property reads correctly resolve to `node.quoteMark`, `node.operator`, `safer.kStringMaxLength`, and `meta.shortCircuited` but remain absent from complete inverse results. All six exact records are completed with both dirty flags false, one queried target, no truncation, and no file errors.

- Observation: Definition-lookup-only local properties are an intentional declaration boundary, not disposable symbols.
  Evidence: Plain-local member assignments and object-literal fields remain outside the public declaration graph to prevent arbitrary `obj.x` pollution, but bounded forward lookup retains their exact ranges and lexical receiver identity. #944 must recover direct same-binding reads without promoting those units into declarations or weakening the closed #386 boundary owned by another user.

- Observation: A later CommonJS default export changes a plain local property's declaration surface.
  Evidence: The first clean #944 fixing head made `node.quoteMark`, `node.operator`, and `meta.shortCircuited` consistent, but `safer.kStringMaxLength` remained missing. Prescan recognizes `module.exports = safer`, promotes `safer` to a declared export root, and excludes it from the lookup-only gate even though same-file member identity still depends on the same receiver binding. The follow-up requires an exact structured default-export local, declared parentless field, persisted target range, and matching assignment receiver before adding the default seed and applying lexical-scope matching.

- Observation: The clean final JavaScript sample exposed one deeper instance of the same local-property identity boundary.
  Evidence: `/mnt/optane/tmp/reference-differential/js-top5-adfa8e0f.jsonl` contains five completed clean records at fingerprint `4e2100493f415809bff86a802609e65dd80c2520904ebfb5a76516b603512b22`. Exhaustive review of all 39 Node residuals found 9 write/declaration terminals, 11 reads before the reported write, 18 receiver/binding false forwards, and one genuine row: `deps/undici/src/lib/web/fetch/index.js` bytes `78788..78798`, where the exact lexical `fetchParams.controller.controller` chain is assigned earlier in the same closure and later read without an inverse hit. Assigned #944 now records this witness before follow-up implementation.

- Observation: Azure PowerShell's persisted analyzer database is physically corrupt rather than merely schema-incompatible.
  Evidence: The 4,895,506,432-byte `.brokk/bifrost_cache.db` has SHA-256 `914bbecdafc9dc6c441b03ca6336739e0b4987080b1fe11eb06043edb4bc6f81`; SQLite `PRAGMA integrity_check` exits 11 with `database disk image is malformed`. The cache layer can transactionally rebuild an invalid schema but cannot recover whole-file corruption. The original file must be quarantined and retained before a fresh canonical cache is built.

- Observation: Sandbox-local process inspection cannot establish host corpus isolation.
  Evidence: A sandboxed `ps` hid the active C# and two unrelated C++ differential processes, while escalated host `ps` showed them. The first C# attempt was interrupted at Azure SDK forward file 524/878 before any successful envelope because the shared worktree changed during JavaScript implementation. Its one Azure PowerShell engine-error envelope and log are diagnostic only.

## Decision Log

- Decision: Accept the completed Java and Go top-five legs as authoritative rather than rerunning them merely because later unrelated language work exists.
  Rationale: Each leg has exactly five clean completed records, a shared per-language fingerprint, exhaustive final residual dispositions, closed assigned issues, and complete local gates. They will be rerun only if new work changes shared behavior that can affect their evidence.
  Date/Author: 2026-07-19 / Codex

- Decision: Run complete uniform top-five legs for C#, JavaScript, and TypeScript, including their previously audited N=1 repository.
  Rationale: Mixing a historical single-repository summary with four current records would weaken provenance and fingerprint integrity. One five-record leg per language is straightforward, resumable, and auditable.
  Date/Author: 2026-07-19 / Codex

- Decision: Begin each new language with one active repository and eight inner workers in persisted cache mode; increase only outer concurrency after measuring memory and I/O headroom.
  Rationale: Azure PowerShell, Azure SDK, .NET runtime, Roslyn, Node.js, and Kibana are large workspaces. The runbook's conservative shape minimizes simultaneous cache and prepared-tree pressure while retaining resumability.
  Date/Author: 2026-07-19 / Codex

- Decision: Treat `missing` as triage input, not proof of a defect.
  Rationale: A ticket requires a semantically correct forward group, the actual referenced terminal, a complete inverse query, live clean source, exact reproduction, and a structured reduction. Qualifier focus, declaration roles, invalid forward identity, explicit limits, and parser recovery boundaries are not inverse defects.
  Date/Author: 2026-07-19 / Codex

- Decision: Root owns planning, source/identity adjudication, GitHub mutation, review, tests, integration, and closure; substantial research and implementation are delegated to Oldskool-compatible subagents when independent work exists.
  Rationale: This is the user's requested division of labor and preserves a single authority for issue ownership and acceptance.
  Date/Author: 2026-07-19 / Codex

- Decision: Do not implement an issue assigned to another user and do not wait for GitHub CI.
  Rationale: Both boundaries are explicit user instructions. Formatting, Clippy, focused tests, and `cargo test --features nlp,python` remain mandatory local gates.
  Date/Author: 2026-07-19 / Codex

- Decision: Retain canonical zero-frontier repositories in the JavaScript top five.
  Rationale: `run-corpus --repos-per-language 5` is the authoritative membership and ranking operation. Substituting the next repository with current JS files would silently change the contract to an unstated rule and contradict prior accepted polyglot corpus precedent.
  Date/Author: 2026-07-19 / Codex

- Decision: Reject the first #942 implementation until lexical `window`, hoisted/TDZ shadowing, explicit-member parity, and parent-lookup cost are covered.
  Rationale: Independent review found real false-positive and performance risks not exercised by the first parameter-shadow control. Focused green tests are evidence only for the cases they cover, not acceptance of a broader alias rule.
  Date/Author: 2026-07-19 / Codex

- Decision: Accept the revised #942 and narrow #943 implementations for fixing-head production proof.
  Rationale: #942 now gates all added indexing and parent lookup behind exact JavaScript browser-global candidates, rejects lexical receiver/property shadows, and preserves explicit-member parity. #943 follows assignment/member AST fields and retains explicit lexical CommonJS bindings and exported-property consumer resolution. The focused targeted suite passed 80 tests with two pre-existing ignores, the whole graph suite passed 21 tests, all-feature focused Clippy passed, and the feature-enabled JavaScript definition slice passed 23 tests.
  Date/Author: 2026-07-19 / Codex

- Decision: Reopen #665 for the Node bare-call forward regression and create #944 for direct reads of definition-only local properties.
  Rationale: #665 is the exact closed, unassigned lexical-precedence issue and was assigned solely to `jbellis` before reopening and renewed implementation. No exact duplicate exists for the #944 inverse boundary; the new issue was created assigned to `jbellis`. Closed #667 concerns alias propagation, while #386 is owned by another user and concerns over-declaration rather than inverse recovery.
  Date/Author: 2026-07-19 / Codex

- Decision: Accept the #665 and #944 implementations for clean production proof without promoting local properties into the declaration graph.
  Rationale: #665 recognizes hoisted function/generator/class declaration bindings and restricts bare same-file fallback to true bare declarations, preserving #942 only through exact unbound `window.<name>` validation. #944 mirrors forward lookup with a prior structured assignment/object-key range plus equal innermost lexical receiver scope. Its bounded location fallback runs only after ordinary declaration matching fails and accepts only exact same-file parentless fields absent from declarations. The root gate passed 503 definition, 151 public service, 25 JavaScript analyzer, 21 whole-graph, and 81 targeted usage tests (two existing ignores), plus formatting, diff checks, and all-target/all-feature Clippy.
  Date/Author: 2026-07-19 / Codex

- Decision: Extend #944 to declared properties only when the exact local receiver is the file's structured default export.
  Rationale: This covers `safer.kStringMaxLength` without general member-name widening. The seed path requires the target to be a parentless declared JavaScript field, the export index to map `default` to one local root, and an exact target range to contain a direct assignment on that root. Same-file reads additionally require a prior range and equal lexical scope; other files retain normal import-edge resolution. The production-shaped public regression reports only two intended same-file reads and the exact `require` consumer, with all pre-definition, write, non-exported, unrelated, and shadowed controls absent.
  Date/Author: 2026-07-19 / Codex

- Decision: Extend #944's local receiver identity to exact structured static member chains, not arbitrary nested expressions.
  Rationale: The remaining production witness has an identifier lexical root plus one ordinary static receiver segment before the target member. Tree-sitter member fields preserve that exact segment sequence while lexical scope remains keyed to the root binding. The reviewed implementation rejects different intermediate paths, other roots, sibling/shadowed bindings, pre-definition reads, writes, class-private segments whose spelling lacks sufficient identity, and recovered nested declarator names. It introduces no source splitting or receiver-insensitive name matching.
  Date/Author: 2026-07-19 / Codex

- Decision: Restart C# from a new clean head after quarantining, not deleting, the corrupt Azure PowerShell cache.
  Rationale: Accepted records must agree with the exact clean source head and rebuilt runner. The interrupted `adfa8e0f` attempt produced no successful report and cannot be resumed after source mutation. A checksum-bearing sibling quarantine preserves the corrupt artifact for diagnosis while allowing the explicitly rebuildable cache to be recreated at its canonical path. Future overlap checks use escalated host process inspection.
  Date/Author: 2026-07-19 / Codex

- Decision: Interrupt the agent-owned diagnostic C# run after profiling the final .NET runtime target, fix assigned #945, and rerun from a new clean head.
  Rationale: The final target consumed more than two hours after every other target completed, while repeated profiles and source tracing already established the production defect. Waiting longer could not expose its name because the runner logs target identity only after completion and could not produce an accepted runtime envelope sooner than fixing the root. The preserved three-envelope artifact remains useful baseline evidence but is explicitly non-accepting.
  Date/Author: 2026-07-20 / Codex

- Decision: Preserve bounded persisted lookup for forward APIs while routing C# inverse resolution through the existing generation-scoped global usage definition index; then remove remaining file-by-spec parse and walk multiplication as measured evidence requires.
  Rationale: Exact persisted-FQN lookup would avoid workspace-wide short-name fanout but still repeats SQL at every matching syntax site. The global index is explicitly designed for whole-workspace inverse analysis, already has clone-safe one-time initialization and dirty-overlay semantics, and Java proved the same split with zero definition SQL after index construction. The inverse path must use a distinct resolver entry point so MCP forward definition calls do not eagerly hydrate the global index. Focused tests will assert result parity, one shared index build, zero post-build definition SQL, and bounded forward behavior.
  Date/Author: 2026-07-20 / Codex

- Decision: Accept the reviewed #945 implementation for clean .NET runtime production proof.
  Rationale: Inverse-only entry points now cover every structured C# resolution dependency identified in review, candidate files are read and parsed once before scanning the target specifications, cancellation and usage limits are checked before preparation, and target-start progress identifies any future outlier. The persisted regression checks intended files rather than only hit count. `cargo fmt --all -- --check`, isolated `cargo clippy --all-targets --all-features -- -D warnings`, all 89 `usages_csharp_graph_test` tests, all 28 `usage_graph_csharp_test` tests, and the CLI progress regression pass.
  Date/Author: 2026-07-20 / Codex

- Decision: Accept the narrow #231 and #737 checkpoint, but do not claim or implement a #423 fix from a green reduction.
  Rationale: #231 has a faithful red-before/green-after duplicate-physical field-initializer test and preserves member receiver typing through structured owner metadata. #737 changes only the exact tree-sitter postfix `!` wrapper and retains shadow/overload controls. The persisted #423 shapes already pass on the fixing base, so changing receiver resolution without a failing contract would be guesswork; exact production evidence must decide whether #945 fixed it incidentally or whether the corpus has a different missing shape.
  Date/Author: 2026-07-20 / Codex

- Decision: Repair #423 and #726 through namespace lookup precedence, not special handling for `List`, constructors, or receiver locals.
  Rationale: C# lookup may remain ambiguous among multiple matches within the same using tier, but a successful using-namespace tier must stop lookup before lower-priority enclosing/global namespace fallbacks. Applying that rule in the shared structured visible-type resolver fixes both production shapes while preserving generic arity and physical declaration grouping. Tests must cover multiple using ambiguity, nearest enclosing precedence, global fallback when no nearer tier matches, generic/non-generic separation, and persisted reopen behavior.
  Date/Author: 2026-07-20 / Codex

- Decision: Fix #701 in two structured layers: shared AST type-root discovery and arity-preserving normalized lookup.
  Rationale: Expanding only the scanner roles cannot repair the already-recognized runtime parameter and Mono explicit-interface sites, while filtering lookup alone cannot make alias RHS, intermediate nested/static owners, or ambiguous type patterns enter scanning. The normalized index remains useful for dotted-versus-nested separator parity and physical partial declarations, but fallback candidates must match an arity-preserving canonical key. Type-root discovery must return AST roots shared by routing and extraction, reject alias LHS and value-shadowed receivers/patterns, and avoid source-text parsing.
  Date/Author: 2026-07-20 / Codex

- Decision: Accept the reviewed #701 implementation for immutable release-binary proof without broadening the public usage graph to field nodes.
  Rationale: Shared structured roots and arity keys cover all seven production families, while hierarchy-aware member lookup keeps inherited fields and constants from being misclassified as types. Independent review's two correctness findings are fixed and covered. Temporary tracing confirmed that inverted resolution records the qualified enum field before `WorkspaceUsageCatalog` deliberately filters non-class/non-callable endpoints; changing that catalog would be an unrelated public graph expansion and would violate its endpoint/node invariant. The direct usage regression proves the supported field surface, and whole-graph regressions prove the observable type edge and false-edge exclusions.
  Date/Author: 2026-07-20 / Codex

- Decision: Treat the `e1a55cb3` and `379f0819` exact artifacts as diagnostic and require all seven witnesses to restart from the `is_expression.right` fixing commit.
  Rationale: A `consistent` alias or nested-owner record cannot offset an `unproven` or missing witness, and changing shared AST or lookup semantics invalidates a mixed-head evidence set. The follow-ups resolve relative qualified names through structured visibility tiers and admit the exact tree-sitter type-test field without source-string parsing. All accepted #701 evidence must share the rebuilt binary, clean final fixing head, and checksum.
  Date/Author: 2026-07-20 / Codex

- Decision: Reject the partial `f7511c92` C# run as acceptance evidence and raise only the C# per-file candidate ceiling from 50,000 to 250,000 on restart.
  Rationale: Four sampled generated files are smaller than the accepted 4 MiB source ceiling but exceed 50,000 structured candidates, so accepting their exclusion would leave known coverage holes. The higher bound remains explicit and finite, applies uniformly to all five C# repositories, and does not alter site, target, usage-file, or usage-count limits. JavaScript and TypeScript retain the original 50,000 bound unless their own completed evidence demonstrates the same conflict.
  Date/Author: 2026-07-20 / Codex

## Outcomes & Retrospective

The selector correction resets objective completion to zero of 25 accepted records. All earlier LOC-ranked Java, Go, C#, JavaScript, and TypeScript artifacts remain regression evidence for the fixes they exposed, but none contains a repository selected by the authoritative task-ranked matrix. The accumulated fixes and their focused production proofs are locally integrated and have passed the complete publication gate. The next acceptance boundary is a clean pushed `origin/master`, a release runner built from that exact revision, and five new explicit-repository corpus legs.

## Context and Orientation

Work in `/mnt/optane/tmp/bifrost-burndown-a1` on the existing branch `bifrost-burndown-a1`. Do not create or switch branches, rebase, or open a pull request. Commit only campaign files on the current branch. At each publication boundary fetch `origin/master`, merge it with `git merge --no-edit origin/master` if needed, never rebase, and push the integrated `HEAD` directly to `origin/master`.

The operator runbook is `/home/jonathan/Projects/bifrost/.agents/docs/reference-differential-runbook.md`. The CLI driver is `src/bin/bifrost_reference_differential.rs`; the engine and report schema are `src/reference_differential/mod.rs`. `run-corpus` appends one repository JSON object after a repository finishes. Its completion key includes language, repository slug and head, Bifrost head, and a semantic configuration fingerprint. `--repo-jobs` bounds active repositories and `--jobs` bounds analyzer and forward/inverse work inside each repository.

Canonical corpus metadata lives in `/home/jonathan/Projects/brokkbench/sft-tools-commits`, and the selection API plus prompt metadata live in `/home/jonathan/Projects/brokkbench/tasks.py` and its default `sfttasks` root. Language membership and every large-repo/build/testsome/binding/prompt/non-fragile/skip filter are applied through `tasks.py`; no campaign code reads those stores directly. Clone paths under `/home/jonathan/Projects/brokkbench/clones` resolve to `/mnt/T9/repo-clones`. The differential runner receives explicit selected slugs so its unrelated code-LOC ranking cannot alter membership.

The task-ranked selections and filtered primary-task counts are:

- C#: `granit-fx__granit-dotnet` (110), `riok__mapperly` (85), `ClosedXML__ClosedXML` (68), `tui-cs__Terminal.Gui` (56), and `JoshClose__CsvHelper` (53).
- Go: `afadesigns__zshellcheck` (499), `cli__cli` (476), `open-telemetry__opentelemetry-collector` (377), `router-for-me__CLIProxyAPI` (242), and `ollama__ollama` (233).
- Java: `alibaba__fastjson2` (328), `chinabugotech__hutool` (208), `languagetool-org__languagetool` (192), `halo-dev__halo` (163), and `apache__dubbo` (126).
- JavaScript: `josephfung__curia` (254), `iamkun__dayjs` (109), `Hack23__European-Parliament-MCP-Server` (74), `Stormheg__wagtail` (47), and `angular__angular.js` (41).
- TypeScript: `code-yeongyu__oh-my-openagent` (272), `storybookjs__storybook` (180), `Yeachan-Heo__oh-my-claudecode` (162), `vuejs__core` (87), and `lerna__lerna` (76).

The earlier LOC-ranked Java record `/mnt/optane/tmp/reference-differential/java-top5-431f1292.jsonl` and Go record `/mnt/optane/tmp/reference-differential/go-top5-20fec8af.jsonl`, plus the C#/JS/TS artifacts documented below, are regression evidence only for this objective. Their historical fixes and issue closures remain valid, but the task-ranked matrix must be run and audited independently.

Open CFG/ICFG issues #886, #887, and #889 are assigned to another user and are outside the symbols scope. Open issue #895 concerns Java outer-type qualifier usages and is currently unassigned; reuse it only if a new matching production witness exists, and assign it to `jbellis` before any implementation.

## Plan of Work

Publish the gated accumulated fixes directly to `origin/master`, verify local, tracking, and remote revisions agree, build the release runner from that exact clean Bifrost head, and record `sha256sum target/release/bifrost_reference_differential`. Do not mutate Bifrost source or selected clone content while a corpus process is active, because revision and dirtiness metadata are read dynamically.

Then run all five languages as independent resumable corpus processes, with languages allowed to proceed concurrently because their selected clones and output files are disjoint. Pass the five task-ranked slugs through repeated explicit `--repo` options; never use `--repos-per-language`, whose code-LOC ranking is a different selection contract. Each language run uses one active repository, eight inner workers, persisted cache mode, strict reporting, 1,000 sampled files, 10,000 sites, 4 MiB source files, 1,000 inverse target groups, 1,000 usage files per target, 100,000 hits per target, and seed zero. C# uses the revised 250,000 candidates-per-file ceiling; the other languages retain 50,000. Preserve head-scoped JSONL and logs under `/mnt/optane/tmp/reference-differential`. A strict exit status of two is expected when raw missing sites exist; accepted evidence requires five completed JSON objects.

After each baseline, verify JSON parsing, exact Bifrost and pinned repository heads, clean flags, one fingerprint, completed status, summary limits, and file errors. Extract every raw `missing` site to a stable ledger keyed by repository, path, byte range, and target declarations. Delegate disjoint read-only source partitions, while root verifies the focused bytes and exact tree-sitter role and adjudicates every disposition.

Exact-rerun suspicious sites against the same clone head. A surviving defect needs a behavior-focused `InlineTestProject` reduction. Put forward identity bugs in definition tests, targeted inverse bugs in language usage-graph tests, whole-workspace parity bugs in inverted graph tests, and public surface changes in symbols-service and Python API coverage as appropriate. Include negative controls for owners, module/package identity, aliases, arity, receiver type, inheritance, lexical shadowing/rebinding, duplicate declarations, JSX/TSX boundaries, generated declarations, and external imports as relevant. Use tree-sitter nodes and analyzer graph structures; never replace structured support with regex, substring search, delimiter splitting, or a source-text mini-parser.

Only after a faithful reduction fails should root search open and closed GitHub issues, inspect assignees, and mutate issue state. Reuse an unassigned issue only after assigning it solely to `jbellis`; otherwise create a new issue already assigned to `jbellis`. If a duplicate is assigned to another user, record and skip it. Delegate substantial implementation with the issue and failing behavior as the contract. Root reviews every diff, rejects text-scanning shortcuts or broad ambiguous candidate amplification, adds missing controls, and runs focused tests. Dirty-tree exact probes are provisional.

When a language has no unclassified genuine sites, run formatting, all-target/all-feature Clippy, affected focused suites, and `UV_CACHE_DIR=/tmp/bifrost-uv-cache cargo test --features nlp,python`. Commit only relevant files with a multiline why-oriented message. Continue directly to the next language without waiting for CI.

At final integration, fetch and merge current `origin/master` into the current branch if needed, repeat proportionate local gates, and push the integrated `HEAD` directly to `origin/master`. Rebuild the runner from the exact clean pushed head and rerun every C#/JS/TS leg affected by accepted changes. If common analyzer code could affect Java or Go, rerun those affected legs too. Exhaustively classify all final residuals, comment on and close assigned issues with the fixing commit and production evidence, check in compact manifests and summaries, and verify the worktree is clean and local HEAD, `origin/master`, and remote master agree.

## Concrete Steps

From `/mnt/optane/tmp/bifrost-burndown-a1`, build the frozen runner after the plan checkpoint:

    git status --short
    git rev-parse HEAD
    cargo build --release --bin bifrost_reference_differential
    sha256sum target/release/bifrost_reference_differential

The C# command shape is:

    set -o pipefail
    /usr/bin/time -v target/release/bifrost_reference_differential run-corpus \
      --clones-root /home/jonathan/Projects/brokkbench/clones \
      --commits-root /home/jonathan/Projects/brokkbench/sft-tools-commits \
      --language csharp \
      --repo granit-fx__granit-dotnet --repo riok__mapperly \
      --repo ClosedXML__ClosedXML --repo tui-cs__Terminal.Gui \
      --repo JoshClose__CsvHelper --repo-jobs 1 --jobs 8 \
      --cache-mode persisted --strict \
      --max-files 1000 --max-sites 10000 \
      --max-candidates-per-file 250000 --max-source-bytes 4194304 \
      --max-targets 1000 --max-usage-files 1000 --max-usages 100000 \
      --seed 0 \
      --output /mnt/optane/tmp/reference-differential/csharp-top5-BIFROST_HEAD.jsonl \
      2>&1 | tee -a /mnt/optane/tmp/reference-differential/csharp-top5-BIFROST_HEAD.log

Repeat with the exact Go, Java, JavaScript, and TypeScript slug sets recorded above, the matching `--language`, `--max-candidates-per-file 50000`, and a task-ranked head-scoped output name. Do not use `--repos-per-language` or `--include-tests`. Do not use `--force` unless an existing record for the same semantic completion key is proven invalid. Resume an interrupted run by confirming no process owns a selected clone and repeating the identical command without `--force`.

Extract structured repository summaries and raw rows with:

    jq -c 'select(.record_type == "repository") | {repo_slug,repo_head,bifrost_head,bifrost_dirty,repo_dirty,status,elapsed_seconds,summary:.report.summary,file_errors:.report.file_errors}' FILE.jsonl

    jq -c 'select(.record_type == "repository") as $r | $r.report.sites[] | select(.classification == "missing") | {repo_slug:$r.repo_slug,path,start_byte,end_byte,line,text,source_evidence,targets,note,diagnostics}' FILE.jsonl

Before integration, run at minimum:

    cargo fmt --all -- --check
    cargo clippy --all-targets --all-features -- -D warnings
    UV_CACHE_DIR=/tmp/bifrost-uv-cache cargo test --features nlp,python --test get_definition_test
    UV_CACHE_DIR=/tmp/bifrost-uv-cache cargo test --features nlp,python

Also run the actual C#, JavaScript, and TypeScript targeted and whole-workspace usage test binaries found under `tests/`; never silently omit equivalent coverage because a guessed target name differs.

## Validation and Acceptance

A language leg is valid only when exactly five selected repositories have completed records for one exact clean Bifrost head and configuration, both dirtiness flags are false, every repository head matches metadata, JSON parses, and every engine/file error or explicit limit is accounted for. A strict exit of two is acceptable only after all records are durable.

A fixed defect is accepted only with a pre-fix failing structured behavior reduction, compliant issue ownership, focused green tests, root review, and an exact clean production rerun. A covering inverse hit must include the original byte range for the intended declaration identity. Honest `no_definition`, `unproven`, or `inconclusive` is acceptable only when the former comparison was semantically invalid or incomplete.

The campaign is complete only when all 25 requested repositories have accepted evidence, every final raw missing row has an explicit reviewed disposition, zero legitimate unowned in-scope defects remain, every worked issue was assigned to `jbellis` before implementation and is closed with evidence, formatting and all-target/all-feature Clippy pass, the complete `cargo test --features nlp,python` suite passes, compact reports are checked in, and the clean integrated worktree plus local and remote master agree. CI is deliberately not awaited.

## Idempotence and Recovery

`run-corpus` is append-only and resume-safe. Repeating an unchanged command without `--force` skips completed semantic keys and reruns incomplete repositories. Preserve partial JSONL and logs; record order is completion order and has no semantic meaning. Never truncate accepted evidence or delete `.brokk` to retry.

If a process stops, verify no differential/analyzer process still owns the clone, inspect the terminal log, and repeat the exact command. Retain cache databases when diagnosing migrations or epochs. If Bifrost source changes while a process is active, stop and rerun from a new clean checkpoint because the executable and dynamically reported revision can diverge. Research agents may inspect source during a run but must not mutate Bifrost or selected clones.

## Artifacts and Notes

Raw evidence and logs live under `/mnt/optane/tmp/reference-differential/` with `csharp-top5-<head>`, `js-top5-<head>`, and `ts-top5-<head>` prefixes. Derived exhaustive ledgers should use `-missing-ledger.{jsonl,tsv,sha256}` and summaries should preserve artifact checksums. Raw multi-megabyte site payloads and analyzer logs are not committed.

The durable repository deliverables are this plan, `.agents/docs/reference-differential/top5-csharp-js-ts.jsonl`, and `.agents/docs/reference-differential/top5-csharp-js-ts-summary.md`. The compact manifest must pin Bifrost and repository heads, configuration fingerprints, summary counters, elapsed time, file errors, ledger checksums, issue ledger, and raw artifact paths.

## Interfaces and Dependencies

No production interface change is planned in advance. Preserve the existing differential CLI, append-only JSONL schema, stable declaration identity, and public symbols contract. Fixes belong in existing structured analyzers and resolvers, with small project coverage using `tests/common/inline_project.rs::InlineTestProject`.

C# uses the C# tree-sitter analyzer; JavaScript and TypeScript have distinct language frontiers but share substantial ECMAScript resolution and usage machinery. Declaration-emission or identity changes may require a language-local analysis epoch bump so persisted caches cannot retain stale facts. Avoid new dependencies, persistence schemas, or public API shapes unless a reduced production root cause requires them and this plan records the decision.

Revision note (2026-07-19 18:40Z): Created this self-contained five-language completion plan after auditing accepted Java/Go evidence and issue state, pinning all 25 canonical repositories, proving the remaining 15 C#/JS/TS clone heads and tracked cleanliness, and recording the user's issue-assignment, delegation, symbols-scope, local-test, no-CI-wait, direct-master, exhaustive-triage, and final-confirmation boundaries before analyzer mutation.

Revision note (2026-07-19 19:25Z): Recorded the published clean campaign checkpoint and runner checksum, the five-record JavaScript baseline and its single invalid dirtiness flag, the canonical zero-frontier decision, exhaustive 23-row partition, assigned #942/#943 defects, clone-local cache exclusions, and the independent review controls required before accepting #942.

Revision note (2026-07-19 20:10Z): Recorded acceptance of the revised candidate-gated #942 browser-global implementation and narrow #943 CommonJS host-binding correction after independent review, structured shadowing/parity controls, focused targeted and whole-graph suites, focused all-feature Clippy, feature-enabled JavaScript definition tests, formatting, and diff checks.

Revision note (2026-07-19 20:45Z): Recorded clean `9547d828` exact proof for #942/#943, the six Node exact-probe dispositions, assigned/reopened #665, newly assigned #944, and the requirement to preserve definition-only local-property identity without reopening the over-declaration boundary owned in #386.

Revision note (2026-07-19 21:30Z): Recorded acceptance of the structured #665 lexical-precedence correction and #944 lookup-only local-property inverse/location path after independent implementation, root review, combined feature-enabled public/analyzer regressions, formatting, diff checks, and all-target/all-feature Clippy.

Revision note (2026-07-19 22:10Z): Recorded the clean `a72a3892` exact outcomes, the remaining `safer.kStringMaxLength` declared default-export-root trigger, and acceptance of its exact structured export/receiver extension after production-shaped public coverage and repeated all-target/all-feature Clippy.

Revision note (2026-07-19 22:55Z): Integrity-checked the five clean `adfa8e0f` JavaScript baseline records and exhaustive 39-row review, recorded the 38 non-actionable dispositions, and constrained the sole remaining assigned #944 witness to exact tree-sitter static receiver-chain identity before follow-up implementation.

Revision note (2026-07-19 23:10Z): Marked the first C# attempt diagnostic-only after physical Azure PowerShell cache corruption and shared-worktree provenance invalidation, preserved its checksums, and required a clean-head rebuild plus checksum-bearing cache quarantine before restart.

Revision note (2026-07-19 23:25Z): Accepted the reviewed #944 nested ordinary-property receiver implementation after correcting private-name and recovered-declarator overreach; both syntax exclusions, four public property regressions, 81 JS/TS usage tests with two existing ignores, formatting, and all-target/all-feature Clippy pass.

Revision note (2026-07-20 03:55Z): Recorded the three-envelope diagnostic C# baseline, exhaustive Azure SDK and Mono disposition, clean exact witnesses for all four Mono root causes, the profiled two-hour .NET runtime inverse-query amplification, assigned #945, the intentional baseline interruption, immutable artifact checksums, and the inverse-only global-definition-index implementation and rerun contract.

Revision note (2026-07-20 03:36Z): Accepted the independently reviewed #945 implementation for production proof after auditing all inverse/forward resolver boundaries, strengthening the persisted regression to assert exact positive and negative files, and passing formatting, isolated all-target/all-feature Clippy, both complete C# usage suites, and the CLI target-start progress test.

Revision note (2026-07-20): Recorded clean .NET runtime production acceptance and closure of #945, the exhaustive 174-row runtime audit, eight clean exact reproductions, compliant assignment/reopening of #231/#423/#701/#726/#737, and newly assigned #946 before correctness implementation.

Revision note (2026-07-20): Recorded exact closure of #423/#726, the corrected visibility-root diagnosis and exact closure of #946 without a speculative metadata refactor, the seven still-red #701 preflights, and the two-layer structured #701 implementation contract.

Revision note (2026-07-20): Accepted the independently reviewed #701 implementation after correcting constant-pattern member suppression and inherited member-shadow handling, recorded the intentional public graph field-endpoint boundary, and captured the complete focused test, definition, analyzer, formatting, and isolated Clippy gates before clean exact proof.

Revision note (2026-07-20): Recorded the first clean #701 exact attempt as diagnostic after `Constants.Globals` remained unproven, fixed relative dotted-name visibility without importing child namespaces, added direct/inverted/forward precedence controls, and captured independent approval plus the complete 95/30/505/11/unit/isolated-Clippy gate set before restarting all seven witnesses.

Revision note (2026-07-20): Recorded the second clean #701 exact attempt as diagnostic after the simple runtime type test remained missing, distinguished tree-sitter `is_expression.right` from constant-pattern syntax with a removed temporary ancestry probe, added the shared structured role plus physical-part routing/direct/inverted regressions, and captured independent approval and 96/31/505/11/unit/isolated-Clippy gates before another full restart.

Revision note (2026-07-20): Accepted the final seven #701 exact witnesses at clean `530fb3d1`, pinned the rebuilt runner and every raw artifact checksum, and disclosed the two independently clean records appended by the recovered runtime-pattern session rather than rewriting raw evidence.

Revision note (2026-07-20): Preserved the three-envelope `f7511c92` C# run as diagnostic after four candidate-ceiling exclusions and a newly pathological runtime `Interop` query, pinned both zero-loss profiles, reduced the shared single-namespace correctness defect, filed assigned #954, implemented all-top-level-namespace indexing, and recorded its complete focused gates plus 34.1-second dirty production proof. Raised the clean C# restart ceiling to 250,000 candidates per file rather than accepting known exclusions.

Revision note (2026-07-20): Accepted and closed #954 after clean `093b17cd` exact proof resolved the 1,219-part runtime `Interop` group in 36.8 seconds with an exact consistent hit and zero file errors, then advanced the C# leg to its raised-ceiling full restart.

Revision note (2026-07-20): Corrected the campaign selection after an explicit `tasks.py` audit proved that the earlier plan used code-LOC ranking. Pinned the five descending fully filtered `SFT_PREDICATES` task-count leaders for C#, Go, Java, JavaScript, and TypeScript, classified all prior LOC-ranked corpus records as regression-only evidence, and required repeated explicit `--repo` filters for the authoritative 25-repository matrix.
