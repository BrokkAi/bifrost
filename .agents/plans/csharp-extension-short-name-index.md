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
- [ ] Rebuild release, rerun the full C# corpus command, and exact-rerun public missing boundaries.

## Surprises & Discoveries

- Observation: The run remained in forward resolution after forty minutes.
  Evidence: GDB showed `resolve_definition_batch_with_source -> resolve_csharp -> csharp_extension_method_candidates -> parent_of -> definitions -> rebase_project_file_to_root`; RSS was stable near 8.8 GB.
- Observation: Persisted C# member short names include their owner, such as `Extensions.Convert`, so exact short-name lookup for `Convert` cannot return extension candidates.
  Evidence: `csharp/declarations.rs` constructs method short names from `parent.short_name()` and the method identifier; the focused public regression failed with no candidate under the initial approach.

## Decision Log

- Decision: Persist and index `CodeUnit::identifier()` separately, then query exact declaration identifiers while preserving all existing semantic filters.
  Rationale: A member identifier is a structured property of a `CodeUnit`; indexing it supports owner-qualified member names without substring scans or language-specific source parsing.
  Date/Author: 2026-07-12 / Codex
- Decision: Add a test-only observable counter at the shared all-declaration SQL boundary.
  Rationale: Behavioral tests alone cannot prevent a future implementation from restoring the same asymptotic scan while returning correct answers.
  Date/Author: 2026-07-12 / Codex

## Outcomes & Retrospective

The exact identifier index and public behavior regression are implemented and pass the local CI-equivalent gates. Full-corpus timing remains pending until the release binary is rebuilt; schema version 9 intentionally requires a one-time analyzer-cache rebuild so the identifier lookup is genuinely indexed.

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

## Interfaces and Dependencies

The analyzer cache schema stores `CodeUnit::identifier()` in `code_units.identifier` and indexes `(lang, identifier)` for declaration rows. `CSharpAnalyzer::declaration_candidates_by_identifier` exposes the exact structured candidate set to C# definition lookup. No text search or source mini-parser is involved.

Revision note (2026-07-12): Created from the Azure PowerShell production profile before implementation.
