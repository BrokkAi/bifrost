# Bound C# extension-method candidate lookup

This ExecPlan is a living document maintained according to `.agents/PLANS.md`.

## Purpose / Big Picture

C# definition lookup currently scans every workspace declaration whenever a member might be an extension method. On Azure PowerShell this leaves a 10,000-site differential in forward resolution for more than forty minutes. After this change, extension candidates come from an exact persisted identifier index and retain the same namespace visibility, extension-method syntax, and call-arity checks.

## Progress

- [x] (2026-07-12 22:00Z) Captured the production performance boundary and terminated the superseded full run.
- [x] (2026-07-12 23:10Z) Added an indexed persisted declaration identifier and replaced the full scan with exact identifier candidates.
- [x] (2026-07-12 23:15Z) Added a public regression covering visible and hidden namespaces, extension and ordinary methods, overload arity, and zero full scans.
- [x] (2026-07-12 23:20Z) Ran all 34 C# definition tests and the cache schema tests successfully.
- [x] (2026-07-13) Passed formatting, all-target/all-feature clippy, the 710-test `nlp,python` library suite, and focused C# extension tests.
- [x] (2026-07-12 20:30Z) Rebuilt release `0.7.6`, separated sandbox cache-write failure from analyzer cost, completed the schema-v10 cache population far enough to enter the differential, and captured the surviving per-candidate parent-definition query.
- [x] (2026-07-12 20:38Z) Routed C# parent lookup through the per-file structural child map and used the member's persisted namespace directly for extension visibility; all 35 focused definition tests and affected all-feature clippy targets pass.
- [x] (2026-07-12 20:38Z) Completed the warm 1,000-site/100-target Azure PowerShell smoke in 232.1 seconds: 336 resolved sites, 41 consistent, 3 unproven, 82 missing, and 874 inconclusive; peak RSS was 6,972,940 KiB.
- [x] (2026-07-12 20:50Z) Committed and pushed parent-lookup fix `b842208a`, then completed the full 10,000-site/1,000-target C# run in 425.0 seconds (7:07 wall) at 6,969,144 KiB peak RSS; the canonical record contains 598 consistent, 40 unproven, 1,339 missing, and 8,023 inconclusive sites.
- [x] (2026-07-12 21:11Z) Reduced the first correctness boundary under an authoritative one-file scope, filed #698, fixed C# method-return recognition and qualified-type usage ranges, passed 59 focused tests, affected all-feature clippy, and the complete `nlp,python` test gate, then changed the exact Azure site from missing to consistent in 146.7 seconds.
- [x] (2026-07-12 21:18Z) Pushed fixing commit `7ccce3dd` to `master` and closed #698 with the reduced regression and exact Azure evidence.
- [x] (2026-07-12 21:31Z) Completed the fixing-HEAD full C# N=1 rerun in 486.4 seconds: consistent sites rose from 598 to 1,717 and missing sites fell from 1,339 to 220, an 83.6% reduction.
- [x] (2026-07-12 21:44Z) Delegated an independent reduced review to `oldskool`, reproduced the 73-site explicit-interface owner boundary locally, filed #701, recognized tree-sitter's structured `explicit_interface_specifier` type role, and passed a two-partial-declaration authoritative regression, all 60 C# graph tests, affected all-feature clippy, and the complete `nlp,python` gate.
- [x] (2026-07-12 21:44Z) Changed exact Azure `ApiKey.cs` bytes `2898..2913` from missing to consistent with a covering `2839..2913` inverse hit in 317.7 seconds.
- [x] (2026-07-12 21:50Z) Pushed `2b617770` to `master` and closed #701 with full validation and exact production evidence.
- [x] (2026-07-12 22:12Z) Rejected the first post-#701 full record as invalid after it queried only 31 of 1,000 configured target groups and marked 1,910 forward-resolved sites `no sampled files remained for inverse query`; filed #703 and changed inverse comparison to retain the original audited `ProjectFile` scope.
- [x] (2026-07-12 22:35Z) Validated #703 with a complete 1,000-target C# rerun: zero candidate-loss notes, 1,793 consistent, 40 unproven, 144 missing, and 8,023 inconclusive sites in 1,104.1 seconds. The complete `nlp,python` gate passes.
- [x] (2026-07-12 22:38Z) Pushed `85aa48cd` and closed #703 with the complete 1,000-target evidence.
- [x] (2026-07-12 22:58Z) Delegated and independently reproduced the 39-site generic `PropertyT<T>` boundary, filed #704, made `type_argument_list` an intrinsic structured type role, and passed a two-partial-target authoritative regression with repeated positives and unrelated-type, generic-method-name, and type-parameter negatives.
- [x] (2026-07-12 23:17Z) Changed exact BillingBenefits bytes `4325..4335` from missing to consistent with a covering `4309..4383` inverse hit across both partial `JsonString` targets.
- [x] (2026-07-12 23:24Z) Passed the complete `cargo test --features nlp,python` gate for #704; affected all-feature library and C# test clippy targets also pass.
- [x] (2026-07-12 23:27Z) Pushed `cf2743de` and closed #704 with focused, exact-production, and complete-suite evidence.
- [x] (2026-07-12 23:49Z) Completed the valid post-#704 C# N=1 rerun: all 1,000 target groups queried, zero candidate-scope-loss notes, 1,834 consistent, 40 unproven, 103 missing, and 8,023 inconclusive sites in 1,132.3 seconds.
- [x] (2026-07-13 00:10Z) Filed #705 after a reduced observable-inventory regression proved exact mode called the full inventory before retaining one path; switched exact selection to safe project-relative point lookup and preserved full-workspace semantic resolution.
- [x] (2026-07-13 00:26Z) Exact BillingBenefits production validation remained consistent and fell from 1,134.4 to 865.2 seconds while truthful eligibility counts changed from 126,829/1 to 1/1; the remaining startup cost is separate from the eliminated runner pass.
- [x] (2026-07-13 00:31Z) Pushed `d8f073d7` through merged `master` and closed #705; preserved the unrelated Rust test edits across the concurrent upstream merge.
- [x] (2026-07-13 00:37Z) Reproduced the 34-site `using static` boundary in the shared inline harness, filed #706, and added one shared AST predicate to inverse type scanning and persisted type-identifier routing with a C# epoch bump.
- [x] (2026-07-13 00:54Z) Changed exact MachineLearningServices bytes `498..508` from missing to consistent with a covering `482..569` inverse hit after the required persisted C# rebuild; all 62 C# usage tests and affected all-feature clippy pass.
- [x] (2026-07-13 00:58Z) Passed the complete `cargo test --features nlp,python` gate for #706.
- [x] (2026-07-13 01:01Z) Pushed `2a365fce` and closed #706.
- [x] (2026-07-13 01:19Z) Completed the valid post-#706 full C# rerun: all 1,000 target groups queried with zero scope-loss notes, 1,875 consistent, 40 unproven, 69 missing, and 8,016 inconclusive sites in 1,008.2 seconds.
- [x] (2026-07-13 01:22Z) Paused the C# triage campaign at the user's requested post-#706 boundary to cut release `0.8.0`.
- [x] (2026-07-13 02:01Z) Resumed after the successful `0.8.0` release and delegated the cast families to oldskool with an independent child reduction for `EventData`/`JsonArray`.
- [x] (2026-07-13 02:06Z) Reproduced the `as_expression.right` boundary in the shared inline harness, filed #707, and added one shared structured role to inverse scanning and persisted type-identifier routing with a C# epoch bump.
- [x] (2026-07-13 02:09Z) Independent fixtures and all 33 archived offsets confirmed one root across 16 `IAsyncCommandRuntimeExtensions`, 10 `EventData`, and seven `JsonArray` sites; partial targets, authoritative/default routing, and negative left/unrelated expressions pass.
- [x] (2026-07-13 02:31Z) Changed exact Automanage bytes `27236..27266` from missing to consistent with a covering `27171..27266` inverse hit after rebuilding the C# epoch.
- [x] (2026-07-13 02:34Z) Passed the complete `cargo test --features nlp,python` gate for #707; all 63 C# usage tests and affected all-feature clippy targets also pass.
- [ ] Push and close #707, then rerun the full C# corpus and triage the expected 36-site residual.

## Surprises & Discoveries

- Observation: The run remained in forward resolution after forty minutes.
  Evidence: GDB showed `resolve_definition_batch_with_source -> resolve_csharp -> csharp_extension_method_candidates -> parent_of -> definitions -> rebase_project_file_to_root`; RSS was stable near 8.8 GB.
- Observation: Persisted C# member short names include their owner, such as `Extensions.Convert`, so exact short-name lookup for `Convert` cannot return extension candidates.
  Evidence: `csharp/declarations.rs` constructs method short names from `parent.short_name()` and the method identifier; the focused public regression failed with no candidate under the initial approach.
- Observation: Sandboxed corpus runs cannot perform analyzer schema migration because the clone cache is outside the writable workspace; failed blob writes retain dirty file states and invalidate RSS conclusions.
  Evidence: The sandboxed smoke reached about 8.1 GiB RSS, but GDB showed `build_persisted -> reconcile_file_states -> write_parsed_blob`. The explicitly unsandboxed run committed schema-v10 rows and later entered `run_reference_differential`.
- Observation: After writable cache population reached the forward batch, extension visibility still queried generic FQN-derived parents once per exact identifier candidate.
  Evidence: The writable 1,000-site/100-target run was stopped after 17m44s at 10,112,644 KiB peak RSS. GDB captured `csharp_extension_method_candidates -> parent_of -> definitions -> declaration_candidate_rows_by_short_name -> SQLite`. Each member already carries its declaring namespace in `CodeUnit::package_name`, and the parsed per-file `children` map carries its exact structural owner.
- Observation: The dominant partial-interface report was not caused by partial target grouping or authoritative candidate handling.
  Evidence: The reduced three-file query reached the consumer and produced a terminal `IReplicaSet` hit, but the production focus was the nonterminal `ADDomainServices` segment in a method return type. Tree-sitter C# calls that field `returns`, while `is_type_reference_node` recognized only `type` and `return_type`; after recognizing `returns`, the inverse hit still needed the containing `qualified_name` range to cover the forward-focused segment.
- Observation: #698 removed the dominant qualified-type cluster but left a smaller set of distinct structured roles.
  Evidence: `/tmp/csharp-n1-698-fixed.jsonl` completed from `3b2e2665` with 1,717 consistent and 220 missing sites, versus 598 consistent and 1,339 missing before the fix. Residual source-shape partitioning found 73 qualified interface owners in explicit member declarations, 39 generic `PropertyT<T>` type sites, 34 `using static` imports, 33 function targets, two field targets, and 39 other class sites.
- Observation: Explicit-interface misses were one omitted tree-sitter role, not an overload-grouping or authoritative-scope defect.
  Evidence: Both the primary inline regression and the delegated `oldskool` reproduction scanned only the implementer and received two partial interface CodeUnits. Pre-fix they emitted only the base-list type hit; `identifier -> qualified_name -> explicit_interface_specifier` returned false from `is_type_reference_node`. Recognizing that parent kind made both explicit property and method owners pass without changing `TargetSpec`, candidate routing, or range expansion.
- Observation: The first full post-#701 record was not valid campaign evidence despite its `completed` status and five missing classifications.
  Evidence: `/tmp/csharp-n1-701-fixed.jsonl` began with 126,829 eligible and 1,000 audited files, but inverse comparison rebuilt its path map from a later `analyzer.analyzed_files()` snapshot. Only 31 target groups were queried, 1,672 were skipped, and 1,910 sites became inconclusive because their sampled files disappeared. The engine already possessed the authoritative audited files and had no reason to query mutable liveness again.
- Observation: Preserving audited scope restored a comparable post-#701 record and showed the explicit-interface fix removed 76 genuine misses.
  Evidence: `/tmp/csharp-n1-703-fixed.jsonl` queried the configured 1,000 groups with zero candidate-loss notes. Relative to the valid post-#698 baseline, consistent sites rose from 1,717 to 1,793 and missing sites fell from 220 to 144. Runtime rose from 486.4 to 1,104.1 seconds because the newly recognized interface-owner role performs real inverse work that the invalid 31-group record had skipped.
- Observation: Generic method type arguments were lost because the type-role walk continued past their semantic boundary.
  Evidence: Primary and delegated fixtures both returned no hits for `PropertyT<Demo.Json.JsonString>()` before #704. The AST is `qualified_name -> type_argument_list -> generic_name -> member_binding_expression`; continuing into the callable generic name eventually returned false. Returning true at `type_argument_list` recovered repeated positive calls while exact FQ identity rejected unrelated same-terminal types, and generic method names plus type parameters remained outside the role.
- Observation: Exact mode still performs a full analyzed-file inventory before retaining its one requested path.
  Evidence: `/tmp/csharp-exact-generic-type-704-fixed.jsonl` audited one 7,633-byte file and one site but reported 126,829 eligible files and took 1,134.4 seconds. This is separate from #704 correctness and should be fixed in the differential runner before many more exact C# probes.
- Observation: #704 removed the complete generic-argument cluster from the trustworthy corpus residual.
  Evidence: `/tmp/csharp-n1-704-fixed.jsonl` has the same repository head, run fingerprint, 1,000 audited files, 10,000 sampled sites, and zero candidate-loss notes as the valid pre-fix record. Missing sites fell from 144 to 103 while consistent sites rose by 41. The residual partitions into 34 `using static` classes, 34 other class roles, 33 functions, and two fields.
- Observation: Exact filtering currently occurs only after the expensive analyzer inventory.
  Evidence: `run_reference_differential` calls `analyzer.analyzed_files()`, filters and sorts the complete live snapshot, and only then lets `select_audited_files` retain the requested path. The exact path can instead be validated and point-checked with `Project::file_by_rel_path` plus `IAnalyzer::is_analyzed`, while retaining the full persisted analyzer for external target resolution.
- Observation: Removing the redundant exact inventory saves meaningful time but does not make persisted analyzer construction cheap.
  Evidence: `/tmp/csharp-exact-generic-type-705-fixed.jsonl` audited the same BillingBenefits bytes with the same two external partial targets and consistent covering hit in 865.2 seconds, down 269.2 seconds or 23.7%. It reports one eligible and one audited file because no repository-wide eligibility inventory was computed. The remaining elapsed time occurs while constructing/reconciling the full persisted analyzer and is a distinct optimization boundary.
- Observation: `using static` needs one shared structural type-role rule at both scanning and candidate-routing layers.
  Evidence: Delegated isolated fixtures with three partial target declarations failed in authoritative inverse scanning until `using_directive` with an unnamed `static` child was recognized. Default routing still failed until the same role was added to persisted C# type-identifier collection. Ordinary namespace using, unrelated alias RHS, and unrelated same-terminal static imports remained negative. Changing persisted identifiers requires a C# analyzer epoch bump.
- Observation: The shared `using static` role survives persisted production rebuilding and exact differential comparison.
  Evidence: `/tmp/csharp-exact-using-static-706-fixed.jsonl` rebuilt the bumped C# epoch, audited only `ExportProxyCmdlet.cs`, and changed the forward-resolved `PsHelpers` import type to consistent with a proven full-directive hit at bytes `482..569`. The exact record reports one eligible, audited, sampled, resolved, queried, and consistent site in 831.1 seconds.
- Observation: #706 removed the complete 34-site static-import cluster from the trustworthy full corpus residual.
  Evidence: `/tmp/csharp-n1-706-fixed.jsonl` is pinned to pushed `2a365fce`, retains the same repository head/fingerprint, 1,000 audited files, 10,000 sampled sites, and zero scope-loss notes, and reports 69 missing sites versus 103 before #706. No remaining missing evidence begins with `using static`. The residual is 34 classes, 33 functions, and two fields; class terminals are 16 `IAsyncCommandRuntimeExtensions`, 10 `EventData`, seven `JsonArray`, and one `Parameter`.
- Observation: C# `as_expression` names its semantically typed operand `right`, which the generic type-role field checks did not recognize.
  Evidence: The primary and delegated fixtures failed with empty authoritative hits and omitted default candidates on clean `v0.8.0`. A shared `as_expression`/`right` AST predicate made singular and partial target fixtures pass while unrelated same-terminal RHS types and same-named left expressions stayed negative. Source-offset auditing placed all 33 cast-family production sites inside the same field.
- Observation: #707 survives a rebuilt persisted production index.
  Evidence: `/tmp/csharp-exact-as-type-707-fixed.jsonl` reports the Automanage `IAsyncCommandRuntimeExtensions` focus as consistent with a proven full qualified RHS hit after the required epoch rebuild. It audited one file/site and queried one target group in 1,299.5 seconds.

## Decision Log

- Decision: Persist and index `CodeUnit::identifier()` separately, then query exact declaration identifiers while preserving all existing semantic filters.
  Rationale: A member identifier is a structured property of a `CodeUnit`; indexing it supports owner-qualified member names without substring scans or language-specific source parsing.
  Date/Author: 2026-07-12 / Codex
- Decision: Add a test-only observable counter at the shared all-declaration SQL boundary.
  Rationale: Behavioral tests alone cannot prevent a future implementation from restoring the same asymptotic scan while returning correct answers.
  Date/Author: 2026-07-12 / Codex
- Decision: Emit C# type-reference hits on the existing AST-derived containing type node rather than the terminal identifier leaf.
  Rationale: Forward lookup interprets any structured segment of a qualified type through the whole type identity. Using the same qualified/generic/nullable/array node climb for inverse range emission makes those focus positions round-trip without source scanning or a second parser.
  Date/Author: 2026-07-12 / Codex
- Decision: Treat `explicit_interface_specifier` as a C# type-reference role in the shared structural predicate.
  Rationale: The grammar gives explicit implementation owners a dedicated node, and its child name is semantically the interface type. The existing qualified-name resolver already proves exact identity, so recognizing the role is sufficient and avoids declaration-text interpretation.
  Date/Author: 2026-07-12 / Codex
- Decision: Carry the selected audited `ProjectFile` set into inverse comparison and fail the run if any retained target group loses all sampled files.
  Rationale: Candidate scope is defined by sampled audited sites, not by a later workspace liveness snapshot. Reusing the stable identities prevents false inconclusive records, removes a redundant workspace-wide persisted integrity query, and makes impossible scope loss an engine error rather than silently completed evidence.
  Date/Author: 2026-07-12 / Codex
- Decision: Treat a child of C# `type_argument_list` as a type reference immediately rather than walking into the enclosing generic name.
  Rationale: C# generic arguments are structurally types whether the generic owner is a declared type or a callable. Stopping at that grammar boundary preserves the qualified argument node while preventing callable identifiers and type-parameter declarations from becoming false type usages.
  Date/Author: 2026-07-12 / Codex

## Outcomes & Retrospective

The exact identifier index, direct namespace visibility check, and structural C# parent lookup are implemented and pushed through `b842208a`. The full Azure PowerShell N=1 run now completes instead of remaining indefinitely in forward resolution. Its initial 1,339 actionable sites comprised 1,304 target classes/types, 33 functions, and two fields. #698 reduced that set to 220 by aligning method-return roles and qualified ranges. #701 reduced the trustworthy set to 144 by recognizing explicit-interface owners, and #703 repaired the campaign engine's audited-scope drift. #704 is pushed and closed; its full rerun removed the generic-argument cluster and left 103 trustworthy sites led by 34 fully qualified `using static` references.

## Context and Orientation

`src/analyzer/usages/get_definition/csharp.rs` resolves C# reference locations. Its `csharp_extension_method_candidates` function previously called `CSharpAnalyzer::get_all_declarations` for every unresolved member. `TreeSitterAnalyzer::lookup_declarations_by_identifier` now queries persisted declaration rows by exact `CodeUnit::identifier()` and merges dirty and non-persisted declarations. Tests in `tests/get_definition_test.rs` exercise the public definition tool.

## Plan of Work

Change only candidate acquisition in `csharp_extension_method_candidates`; leave function-kind, identifier, visible declaring namespace, structured `this` parameter, and arity filtering intact. Instrument the shared all-declaration query count so a test can reset it, make a public extension lookup, and assert zero full scans. Add behavior tests for a visible public extension, a same-named non-extension, an invisible namespace, and overload arity.

## Concrete Steps

From `/home/jonathan/Projects/bifrost`, edit the analyzer and tests, then run C# definition and service tests, `cargo test --lib`, `cargo fmt --check`, and `cargo clippy --all-targets --all-features -- -D warnings`. Rebuild the release differential binary and rerun the exact Azure PowerShell full-limit command.

## Validation and Acceptance

Public extension lookups must resolve only visible structured extension methods with matching arity. The full-declaration scan counter must remain zero for the query. The requested corpus run must complete and write `/tmp/n1-csharp.jsonl`; every proposed public missing-symbol issue must reproduce in exact-site mode.

## Idempotence and Recovery

All tests and corpus commands are repeatable. The interrupted pre-fix run wrote no output record. `--force` permits rerunning after release rebuild while retaining the persisted cache.

## Artifacts and Notes

The pre-fix process was stopped with exit 130 after issue #686 was filed. Its 1.1 GB persisted cache is intentionally retained for the post-fix comparison.

The schema-v10 migration and query measurements must run outside the Codex filesystem sandbox because the corpus clone cache lives under `/mnt/T9/repo-clones`. Sandboxed migration attempts fail blob writes and retain dirty parsed states, so their RSS is not valid product evidence. The writable cold 1,000-site/100-target run was stopped after 17m44s at 10,112,644 KiB peak RSS after GDB proved it had entered the surviving parent-definition query. The fixed warm smoke record is `/tmp/bifrost-csharp-structural-parent-warm.jsonl`.

The full committed-HEAD result is the final line of `.agents/docs/reference-differential/n1.jsonl`, pinned to `b842208a23fa7b620848c96da0db05d617bb848d`. The representative exact type result is `/tmp/csharp-exact-type-replica.jsonl`. The record is marked `bifrost_dirty=true` solely because the shared worktree retains unrelated user/untracked artifacts; the release binary and reported HEAD are pinned to the pushed commit.

The fixed #698 exact result is `/tmp/csharp-exact-type-replica-698-fixed.jsonl`. It completed in 146.7 seconds with one forward-resolved site, one consistent classification, zero missing classifications, and an inverse hit covering bytes `5642..5712` around the requested `5677..5693` focus.

The full fixing-HEAD result is `/tmp/csharp-n1-698-fixed.jsonl`, pinned to plan-only HEAD `3b2e26657c430eced2e074ca825359ca59ff5e61` whose analyzer code is `7ccce3dd`. It completed in 486.4 seconds with the same 3,269 forward-resolved sites, 1,717 consistent, 40 unproven, 220 missing, and 8,023 inconclusive.

The fixed #701 exact result is `/tmp/csharp-exact-explicit-interface-701-fixed.jsonl`. It completed in 317.7 seconds with one consistent site and an inverse hit covering bytes `2839..2913` around the requested `2898..2913` focus.

`/tmp/csharp-n1-701-fixed.jsonl` is invalid evidence and must not be used as the post-#701 baseline. Although it reported five missing sites, it queried only 31 target groups and contains 1,910 `no sampled files remained for inverse query` classifications caused by #703.

The canonical post-#701/#703 result is `/tmp/csharp-n1-703-fixed.jsonl`, pinned to `c8524f8693483bf6c6b7cf750eaafd07c82e4fb5`. It completed in 1,104.1 seconds with all 1,000 target groups queried, 1,793 consistent, 40 unproven, 144 missing, and 8,023 inconclusive sites.

The fixed #704 exact result is `/tmp/csharp-exact-generic-type-704-fixed.jsonl`. It completed in 1,134.4 seconds with one consistent site and an inverse hit covering bytes `4309..4383` around requested `4325..4335`; both partial `JsonString` declarations remained in the target group.

The canonical post-#704 result is `/tmp/csharp-n1-704-fixed.jsonl`, pinned to pushed HEAD `cf2743dec7cdce53b4437f799412cabf3d43689a`. It completed in 1,132.3 seconds with all 1,000 configured target groups queried, zero candidate-scope-loss notes, 1,834 consistent, 40 unproven, 103 missing, and 8,023 inconclusive sites.

The canonical post-#706 result is `/tmp/csharp-n1-706-fixed.jsonl`, pinned to pushed HEAD `2a365fce4142b2b92c712b9b7233fc8bd14c7a35`. It completed in 1,008.2 seconds with all 1,000 configured target groups queried, zero candidate-scope-loss notes, 1,875 consistent, 40 unproven, 69 missing, and 8,016 inconclusive sites.

`cargo clippy --all-targets --all-features -- -D warnings` reached an unrelated uncommitted `tests/rust_analyzer_goto_definition.rs` edit and failed on its line 65 `needless_borrow`. That file was left untouched. `cargo clippy --lib --all-features -- -D warnings` and `cargo clippy --test get_definition_test --all-features -- -D warnings` both pass for this change.

## Interfaces and Dependencies

The analyzer cache schema stores `CodeUnit::identifier()` in `code_units.identifier` and indexes `(lang, identifier)` for declaration rows. `CSharpAnalyzer::declaration_candidates_by_identifier` exposes the exact structured candidate set to C# definition lookup. No text search or source mini-parser is involved.

Revision note (2026-07-12): Created from the Azure PowerShell production profile before implementation.

Revision note (2026-07-12): Recorded the reduced, pushed, and closed #698 correctness boundary plus exact production validation so continued C# triage starts from proven current behavior rather than the pre-fix missing report.

Revision note (2026-07-12): Recorded the full post-#698 C# rerun and partitioned its 220 residual sites, making explicit-interface owner declarations the next reduced-test boundary.

Revision note (2026-07-12): Recorded the delegated #701 reduction, structured fix, complete validation, and exact Azure proof so the next checkpoint can push, close, and quantify the residual corpus.

Revision note (2026-07-12): Recorded pushed/closed #701 and rejected its invalid full rerun after #703 exposed mutable candidate-snapshot drift; the next run must preserve the audited scope and query the configured 1,000 target groups.

Revision note (2026-07-12): Recorded the valid post-#701/#703 1,000-target rerun, its 144-site residual, and `PropertyT<T>` generic arguments as the next C# boundary.

Revision note (2026-07-12): Recorded delegated #704 reduction, negative coverage, exact production proof, and the newly measured exact-mode inventory cost.

Revision note (2026-07-12): Recorded pushed/closed #704, its complete 1,000-target rerun, the 103-site residual partition, and the independently reviewed exact-mode inventory seam.

Revision note (2026-07-13): Recorded #705 reduction/fix and production timing, plus the delegated `using static` root boundary across inverse scanning, persisted routing, and cache epoching.

Revision note (2026-07-13): Recorded pushed/closed #705 and #706's shared-role implementation, cache epoch bump, focused validation, and exact persisted production proof.

Revision note (2026-07-13): Recorded pushed/closed #706, its valid complete corpus rerun, the eliminated static-import cluster, and the 69-site residual partition.

Revision note (2026-07-13): Marked the campaign intentionally paused after #706 for the `0.8.0` release, preserving the exact resumption boundary.

Revision note (2026-07-13): Recorded post-release resumption, aggressively delegated #707 reduction, the shared inverse/persisted role fix, 33-site scope, and exact production proof.
