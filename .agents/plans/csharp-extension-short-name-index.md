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
- [ ] Commit and push the parent-lookup fix, rerun the full C# corpus command from committed HEAD, and exact-rerun public missing boundaries.

## Surprises & Discoveries

- Observation: The run remained in forward resolution after forty minutes.
  Evidence: GDB showed `resolve_definition_batch_with_source -> resolve_csharp -> csharp_extension_method_candidates -> parent_of -> definitions -> rebase_project_file_to_root`; RSS was stable near 8.8 GB.
- Observation: Persisted C# member short names include their owner, such as `Extensions.Convert`, so exact short-name lookup for `Convert` cannot return extension candidates.
  Evidence: `csharp/declarations.rs` constructs method short names from `parent.short_name()` and the method identifier; the focused public regression failed with no candidate under the initial approach.
- Observation: Sandboxed corpus runs cannot perform analyzer schema migration because the clone cache is outside the writable workspace; failed blob writes retain dirty file states and invalidate RSS conclusions.
  Evidence: The sandboxed smoke reached about 8.1 GiB RSS, but GDB showed `build_persisted -> reconcile_file_states -> write_parsed_blob`. The explicitly unsandboxed run committed schema-v10 rows and later entered `run_reference_differential`.
- Observation: After writable cache population reached the forward batch, extension visibility still queried generic FQN-derived parents once per exact identifier candidate.
  Evidence: The writable 1,000-site/100-target run was stopped after 17m44s at 10,112,644 KiB peak RSS. GDB captured `csharp_extension_method_candidates -> parent_of -> definitions -> declaration_candidate_rows_by_short_name -> SQLite`. Each member already carries its declaring namespace in `CodeUnit::package_name`, and the parsed per-file `children` map carries its exact structural owner.

## Decision Log

- Decision: Persist and index `CodeUnit::identifier()` separately, then query exact declaration identifiers while preserving all existing semantic filters.
  Rationale: A member identifier is a structured property of a `CodeUnit`; indexing it supports owner-qualified member names without substring scans or language-specific source parsing.
  Date/Author: 2026-07-12 / Codex
- Decision: Add a test-only observable counter at the shared all-declaration SQL boundary.
  Rationale: Behavioral tests alone cannot prevent a future implementation from restoring the same asymptotic scan while returning correct answers.
  Date/Author: 2026-07-12 / Codex

## Outcomes & Retrospective

The exact identifier index, direct namespace visibility check, and structural C# parent lookup are implemented. A warm production smoke now completes instead of remaining indefinitely in forward resolution. The 100-target smoke completed in 232.1 seconds with 6,972,940 KiB peak RSS and wrote a valid record; the full 1,000-target committed-HEAD corpus run and correctness triage remain pending.

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

`cargo clippy --all-targets --all-features -- -D warnings` reached an unrelated uncommitted `tests/rust_analyzer_goto_definition.rs` edit and failed on its line 65 `needless_borrow`. That file was left untouched. `cargo clippy --lib --all-features -- -D warnings` and `cargo clippy --test get_definition_test --all-features -- -D warnings` both pass for this change.

## Interfaces and Dependencies

The analyzer cache schema stores `CodeUnit::identifier()` in `code_units.identifier` and indexes `(lang, identifier)` for declaration rows. `CSharpAnalyzer::declaration_candidates_by_identifier` exposes the exact structured candidate set to C# definition lookup. No text search or source mini-parser is involved.

Revision note (2026-07-12): Created from the Azure PowerShell production profile before implementation.
