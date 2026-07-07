# Fix scan_usages issue #528 failure modes 1–3 generally: backend inference gaps plus a proof-tier result model

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document must be maintained in accordance with `.agent/PLANS.md` (from the repository root).

## Purpose / Big Picture

`scan_usages` is one of bifrost's MCP tools: given a symbol (for example `NzbDrone.Common.Extensions.NumberExtensions.SizeSuffix`), it returns the locations in the workspace where that symbol is used. A live audit of 109 calls across 15 repositories (GitHub issue BrokkAi/bifrost#528) measured only a 37.6% useful-return rate. Three of the four dominant failure modes were root-caused on 2026-07-07, each verified with a minimal failing test:

1. Rust: querying a crate-private member or an `impl`-target of an imported type fails hard with `RustExportUsageGraphStrategy: no export seed resolved`, even though in-crate usages exist and are structurally discoverable.
2. C#: querying an extension method on a builtin receiver (`this long bytes`) fails hard with `CSharpUsageGraphStrategy: no proven structured hits`, and the failure's recovery hint recommends a `targets` re-call that reproduces the identical failure.
3. Go: querying a method reached through a struct field whose declared type is a package-qualified interface (`c.localBase.MoveTempFileAndCreateArtifact()` where the field is `localBase base.LocalBase`) silently returns `total_hits: 0` despite real call sites.

(The fourth mode, Python timeouts, is explicitly out of scope — it is being handled separately.)

After this plan is complete: all three query shapes above return their real usages; when the analyzer genuinely cannot prove a candidate call site it returns that site in a clearly-labeled "unproven" tier instead of failing or silently dropping it; a zero-hit result distinguishes "verified absent" (scan completed, definitively nothing) from "scan failed" (with a reason); and failure hints never recommend a recovery that re-enters the same failure. The observable proof is six previously-failing tests passing plus new tests for the result-model behavior.

The user-level directive shaping this plan: fix causes at the level of the general contract (seeding contract, type-identity contract, receiver-fact contract, result-model policy), not point patches. A point patch (for example, special-casing `long` next to the existing `string` special case) is explicitly unacceptable.

## Progress

- [x] (2026-07-07) Root causes for all three modes confirmed with failing repro tests (see Context; patches in `.agents/docs/issue-528-repro-tests/`).
- [x] (2026-07-07) The shared-usage-index refactor merged into master (`9de316e`) after root-causing; all root-cause anchors re-verified present on merged master (line shifts only — Go `resolver.rs:1426` and `:1692`, C# `resolver.rs:611/:626`; Rust and hint sites unchanged).
- [x] (2026-07-07 16:34Z) Stage 1 (Go receiver-fact contract): qualified field types resolve through import edges; field-owner facts cross packages.
- [x] (2026-07-07 16:42Z) Stage 2 (C# type-identity contract): canonical builtin-type table replaces the `string` special case; unqualified same-class calls get structural proof.
- [ ] Stage 3 (Rust seeding contract): local-declaration scan seeds + impl-target canonicalization.
- [ ] Stage 4 (proof-tier result model): `UsageProof` tier, unproven sites through `FuzzyResult::Success`, `verified_absent` in scan_usages summaries; C#/Go/Rust emit unproven candidates.
- [ ] Stage 5 (hint contract): hints context-derived; location-anchored queries never re-suggest `targets`.
- [ ] Final full-workspace gate (fmt, clippy all-features, full test suite incl. `--features nlp,python`); retrospective.

## Surprises & Discoveries

- Observation: the shared-usage-index refactor (`9de316e`, merged 2026-07-07 between root-causing and Stage 1) rewrote lookup plumbing in `go_graph/resolver.rs` (−266 lines), `csharp_graph/resolver.rs` (−200), and `csharp_graph/extractor.rs`, but every root-cause site survived verbatim (only line shifts). Re-verify the repro tests still fail at the start of each stage rather than trusting pre-merge evidence.
  Evidence: `grep` re-location of all anchors on `9de316e` (see Progress entry); repro-failure re-confirmation is a required first step of each stage.
- Observation: Stage 1's two Go repro tests still failed on merged master before the fix, then both passed after import-qualified field-owner resolution was implemented.
  Evidence: Before the fix, `BIFROST_SEMANTIC_INDEX=off cargo test --test usages_go_graph_test -- imported_interface` ran 2 tests and both failed with `expected imported interface field hit: {}`. After the fix, the same command ran 2 tests and both passed.
- Observation: `src/analyzer/usages/go_graph/inverted.rs` did not contain the forward resolver's qualifier rejection for type references; its `FileScan::type_tokens` already resolves `qualified_type` and `selector_expression` qualifiers through `GoEdgeIndex::namespace_packages`.
  Evidence: Stage 1 inspection found `type_tokens` mapping `Some(qualifier)` through `alias_packages` to canonical package prefixes before building `{package}.{name}` tokens, so no inverted-edge change was needed for this stage.
- Observation: Stage 2's two C# primitive receiver repro tests still failed on merged master before the fix, then both passed after builtin type identity canonicalization.
  Evidence: Before the fix, `BIFROST_SEMANTIC_INDEX=off cargo test --test usages_csharp_graph_test -- primitive` ran 2 tests and both failed, one with `No relevant usages found for symbol: NzbDrone.Common.Extensions.NumberExtensions.SizeSuffix` and one with `CSharpUsageGraphStrategy: no proven structured hits`. After the fix, the same command ran 2 tests and both passed.
- Observation: Adding `object` to the builtin table changed two existing C# tests from unsafe-inference failures to successful empty results, because `object` receivers are now known `System.Object` nonmatches rather than untyped receivers.
  Evidence: The first full `BIFROST_SEMANTIC_INDEX=off cargo test --test usages_csharp_graph_test` run after Stage 2 implementation failed only `csharp_graph_fails_when_inner_block_shadows_typed_receiver` and `csharp_graph_avoids_unrelated_same_name_symbols_and_fails_on_unsupported_receivers`; both old assertions expected `FuzzyResult::Failure`. Updating them to assert empty success yielded 48/48 passing tests.

(Add entries as implementation proceeds.)

## Decision Log

- Decision (D1): Stage order is Go → C# → Rust → result model → hints.
  Rationale: the three backend fixes are independent, smallest-first builds confidence, and they shrink the unproven population before Stage 4 exposes it; Stage 5 depends on Stage 4's outcome taxonomy.
  Date/Author: 2026-07-07 / Claude + Jonathan.
- Decision (D2): Per-site verdicts are proven / disproven / unproven; "failure" exists only at query level (scan could not run or complete). Disproven sites are silently discarded. "Verified absent" is claimable only when the candidate set was complete (not truncated) and no site was left unproven.
  Rationale: settled in design discussion with Jonathan 2026-07-07; unproven is an irreducible residue of best-effort static analysis (dynamic dispatch, `interface{}`/`dynamic`, reflection), not a temporary state — the model must represent "can't tell" honestly.
  Date/Author: 2026-07-07 / Jonathan.
- Decision (D3): Unproven sites must pass structural plausibility (correct AST shape, arity match where applicable, member-name match on a receiver expression) — bare name equality anywhere is NOT enough to enter the unproven tier.
  Rationale: without this bar, common method names flood the tier with noise; this is also required by the repo design philosophy (no text-scan fallbacks).
  Date/Author: 2026-07-07 / Claude, per design discussion.
- Decision (D4): Unproven tier is capped at 20 sites per symbol with a total count always reported.
  Rationale: bounded output for MCP consumers; count preserves signal even when capped.
  Date/Author: 2026-07-07 / Claude.
- Decision (D5): Stage 4 wires unproven-site collection for C#, Go, and Rust only; Java/Ruby/C++/others keep their current boolean gates and emit no unproven sites yet.
  Rationale: scope control — the audit's failures are these three backends; the shared model is general and other backends can adopt it incrementally.
  Date/Author: 2026-07-07 / Claude.
- Decision (D6): `GraphFailureReason::UnsafeInference` ceases to be a query-killing outcome for "candidates seen but unproven" — that state becomes a Resolved success carrying unproven sites. UnsafeInference remains only for cases where the strategy cannot scan at all safely.
  Rationale: this is the core policy fix; "I found sites but can't prove them" is information, not an error.
  Date/Author: 2026-07-07 / Claude, per design discussion.
- Decision (D7): The C# builtin-type table lives in `src/analyzer/usages/csharp_graph/resolver.rs` as a canonicalization used by the usages proof pipeline, not inside `CSharpAnalyzer::resolve_visible_type`.
  Rationale: `resolve_visible_type` returns `CodeUnit`s (project declarations) and is shared with definition/hover paths; builtins have no CodeUnit. Canonical type identity is a string-level concept for receiver matching.
  Date/Author: 2026-07-07 / Claude (plan-time decision; revisit during Stage 2 if the merged refactor changed `resolve_visible_type` call sites).
- Decision (D8): Rust Stage 3 keeps the "export seed" fast path untouched and adds a second seed source ("local declaration seeds") when export seeds are empty, rather than rewriting `seeds_for_target`.
  Rationale: additive change preserves the large passing Rust suite; the export path's narrowing behavior for public APIs is correct and performance-relevant.
  Date/Author: 2026-07-07 / Claude (plan-time decision).
- Decision (D9): Go Stage 1 stores field-owner facts by the file that declares the owner type, and `ScanBindings::new` derives per-scan-file direct facts for same-package owners plus namespace-qualified facts through `GoProjectGraph::matching_edges_for_importer`.
  Rationale: a single owner-name map was only safe inside the target package. Keying facts by declaring file preserves package identity, lets same-package files merge their local owner facts, and lets cross-package owner references be admitted only when an import edge proves the qualifier.
  Date/Author: 2026-07-07 / Codex.
- Decision (D10): `type_ref_matches_compatible_receiver` now resolves package-qualified field types by matching the qualifier against namespace import edges for compatible receiver-type seeds, with a direct `(file, type)` seed fallback only when the existing export-seed helper cannot produce a seed.
  Rationale: the receiver-fact contract should be independent of textual package-name matching and should reuse the Go import graph that already understands package clauses, aliases, module paths, and local workspace resolution.
  Date/Author: 2026-07-07 / Codex.
- Decision (D11): C# builtin type identities canonicalize to their CLR `System.*` names in the usages pipeline; for example `long` and `System.Int64` both become `System.Int64`, and `string` and `System.String` both become `System.String`.
  Rationale: a single canonical spelling keeps receiver bindings, extension-method target receiver types, and receiver-target matching on one equality contract. The table remains in `src/analyzer/usages/csharp_graph/resolver.rs`; `CSharpAnalyzer::resolve_visible_type` was not widened because builtins have no project `CodeUnit`.
  Date/Author: 2026-07-07 / Codex.
- Decision (D12): Same-class unqualified method invocations are proven only when the AST enclosing type resolves to the target owner's same `CodeUnit` and the invocation argument count matches the target arity.
  Rationale: this proves ordinary `Run();` calls inside the declaring class without claiming cross-class `using static` imports, and it preserves the existing self-hit filter for recursive calls inside the target method body.
  Date/Author: 2026-07-07 / Codex.
- Decision (D13): Update the old unqualified-call fallback test to assert the new proven hit, and update two `object` receiver tests to assert successful empty results rather than fallback.
  Rationale: the unqualified-call test documented the old Stage 1 behavior and is superseded by Stage 2's same-class proof. The `object` tests changed because builtin canonicalization turns `object` into a known `System.Object` receiver, which can safely disprove `Target.Run`/`Alpha.Target.Run` instead of forcing an unsafe-inference failure.
  Date/Author: 2026-07-07 / Codex.

## Outcomes & Retrospective

(To be written at stage boundaries and completion.)

## Context and Orientation

bifrost is a Rust codebase (repository root: the directory containing this file's `.agents` parent) implementing an MCP server exposing code-analysis tools built on tree-sitter parsers. All commands below run from the repository root. Work happens directly on the `master` branch (repo rule: no new branches, no pushes; the session driver commits after verifying each stage — implementation agents must NOT commit).

Key vocabulary, defined once:

- A "CodeUnit" is bifrost's record for one declaration (a class, function, field...) with an identifier, a fully-qualified name (FQ name), a source file, and parentage. See `src/analyzer/mod.rs`.
- A "usage graph strategy" is a per-language resolver that, given a target CodeUnit, finds usage sites. They live under `src/analyzer/usages/` — `rust_graph.rs`/`rust_graph/`, `csharp_graph.rs`/`csharp_graph/`, `go_graph.rs`/`go_graph/`, and siblings for other languages. The orchestration entry is `UsageFinder::query` in `src/analyzer/usages/finder.rs`, and the MCP tool surface is `scan_usages` in `src/searchtools.rs` (rendering/summary around lines 3800+) and `src/searchtools_service.rs`.
- A strategy returns `GraphUsageOutcome` (`src/analyzer/usages/outcome.rs`): `Resolved(FuzzyResult)`, `FallbackSafe(diagnostic)`, or `TerminalFailure(diagnostic)`. As of the start of this plan, `finder.rs:149-162` treats FallbackSafe and TerminalFailure identically — both become `FuzzyResult::Failure`. There is deliberately no regex/text fallback (removed in PR #130); the repo design philosophy (see `CLAUDE.md`, "Design philosophy") permits structured best-effort built on AST nodes and CodeUnits, and bans string-scanning fallbacks.
- A "seed" (Rust backend) is a `(ProjectFile, name)` pair from which the strategy derives the candidate file set to scan, via the importer index. Built in `src/analyzer/rust/usage_index.rs` (`seeds_for_target`, line ~119) and consumed via `infer_graph_seeds` in `src/analyzer/usages/rust_graph/resolver.rs` (line ~218).
- A "receiver fact" (Go backend) is knowledge that some expression (a variable, a struct field) carries a type compatible with the query target, so a method call through it counts. Built in `src/analyzer/usages/go_graph/resolver.rs` (`ScanBindings`, `collect_compatible_receiver_types`, field-owner collection ~line 1345, `type_ref_matches_compatible_receiver` ~line 1459).
- A "proven hit" (C# backend) is a candidate site whose receiver type was resolved and matched. The scan pipeline is `src/analyzer/usages/csharp_graph/extractor.rs` (`scan_member_reference` ~line 173, `scan_unqualified_member_reference` ~line 286), type resolution in `csharp_graph/resolver.rs` (`resolve_type_fq_name` ~line 616 — note the lone `string` special case at `is_csharp_string_type`), and the discard-all-unproven gate in `csharp_graph/shared.rs` lines 70-76.

The verified root causes (each item names the defect, the evidence, and the repro test):

1. Rust — the seeding contract conflates export identity with scan identity. `infer_graph_seeds` only produces seeds reachable through export/re-export chains (`usage_index.rs:119-182` drops unexported bootstrap seeds by design). Crate-private declarations used cross-file via `use crate::...` produce zero seeds; member targets then get only a same-file scan before hard-failing (`rust_graph.rs:86-107`), and non-member targets hard-fail immediately (`rust_graph.rs:128-136`). Additionally, declaration collection synthesizes a Class CodeUnit for every `impl ... for Type` target (`src/analyzer/rust/declarations.rs`, `extract_rust_impl_target_name` ~line 919), so an FQ name like `utils.language.StorageField` resolves to a synthetic unit in the impl file — which is never exported from that file, so seeding always fails for it. Repro tests: `rust_graph_strategy_finds_private_member_usages_without_export_seed` and `rust_graph_strategy_finds_imported_type_impl_target_usages_without_export_seed` in `tests/usages_rust_graph_test.rs`.
2. C# — the type-identity model covers only project classes plus a hard-coded `string`. `resolve_type_fq_name` (`csharp_graph/resolver.rs:611-630` on merged master) resolves `string` by special case and everything else through project class declarations; builtin receivers (`long`, `int`, `decimal`...) resolve to nothing, so extension-method call sites on them can never be proven — and the target's own `this long bytes` receiver type also resolves to None. Separately, unqualified same-class calls are unconditionally unproven (`extractor.rs:298-305`); there is no "enclosing class equals target owner" proof. All real sites land in `saw_unproven_match` and the gate at `shared.rs:70-76` discards them and hard-fails with `UnsafeInference("no proven structured hits")`. Repro tests: `csharp_graph_should_find_extension_method_on_primitive_long_receiver` and `csharp_scan_usages_target_anchor_should_find_primitive_extension_receiver_usage` in `tests/usages_csharp_graph_test.rs`.
3. Go — receiver facts stop at the package boundary and reject qualified types. `type_ref_matches_compatible_receiver` (`go_graph/resolver.rs:1426` on merged master) returns false for any type reference with a package qualifier, so a field declared `localBase base.LocalBase` can never match; field-owner fact collection only walks structs in the target's own package (collector, mid-file); and `ScanBindings::new` (~line 1692 on merged master) drops `field_owner_direct_names` for files outside the target's package. Cross-package calls through interface-typed fields are therefore invisible, and the strategy returns a silent zero-hit success (`go_graph.rs:190`). Struct-to-interface compatibility linking itself works, including unexported implementers (`resolver.rs:1024`) — the chain breaks at typing the field. Repro tests: `go_graph_strategy_finds_imported_interface_method_calls_through_struct_fields` and `go_graph_strategy_finds_unexported_impl_method_calls_through_imported_interface_fields` in `tests/usages_go_graph_test.rs`.

Cross-cutting: the hint generator `usage_failure_hint` (`src/searchtools.rs:2574-2590`) recommends a location-anchored `targets` selector for every `unsafe_inference` failure, but the `targets` path feeds the same proof pipeline (`searchtools.rs:2948, 3023`; `location_selected` only affects the Ambiguous branch, ~lines 3067, 3139), and the location-selector failure path emits the same hint again (`searchtools.rs:2561`) — a self-defeating loop.

The six repro tests exist as three patch files (test-file-only diffs against master commit 9131080) in `.agents/docs/issue-528-repro-tests/`: `rust-no-export-seed.patch`, `csharp-unproven-hits.patch`, `go-interface-field-zero-hits.patch`. Apply each with `git apply .agents/docs/issue-528-repro-tests/<name>.patch` at the start of the corresponding stage. Each test asserts the CORRECT behavior, so it fails before the stage's fix and must pass after.

Test environment rules (repo-wide, non-negotiable): every `cargo test` invocation must run with `BIFROST_SEMANTIC_INDEX=off` so tests never download models or spawn indexer threads. The lint gate is `cargo fmt` plus `cargo clippy --all-targets --all-features -- -D warnings`, both must be clean before a stage is considered done. For inline multi-file test projects, use the shared harness `InlineTestProject` in `tests/common/inline_project.rs` (the repro tests already do).

## Plan of Work

Five stages, each independently verifiable and committed separately (by the session driver, not the implementation agent). Stages 1-3 are the backend contract fixes and are independent of each other; Stage 4 is the shared result model; Stage 5 fixes hints on top of Stage 4's taxonomy.

### Stage 1 — Go: receiver facts must cross package boundaries through imports

Scope: make a struct field whose declared type is package-qualified (for example `base.LocalBase`) produce the same receiver facts as an unqualified local type, wherever the file's imports make that resolution structurally certain.

Work, all in `src/analyzer/usages/go_graph/resolver.rs` unless noted: extend `type_ref_matches_compatible_receiver` (~line 1426) so a qualified `TypeRef` matches when the qualifier resolves — through the scanning file's import edges (the `GoProjectGraph` import machinery already used by `matching_edges_for_importer` / namespace bindings) — to the package containing a compatible receiver type of the same name. Extend the field-owner fact collector to walk struct declarations in candidate/importer files, not only the target's package, recording facts for fields whose types now match. Change `ScanBindings::new` (~line 1692 on merged master) to retain field-owner facts for cross-package files instead of dropping them wholesale; the retention criterion is that the fact was proven through import resolution, not text. Check `go_graph/inverted.rs` for the same qualifier restriction (the inverted edge builder shares helpers) and apply the same generalization if present. Do not special-case interface types: the contract is "declared field type resolves via imports to a compatible receiver type", which covers structs and interfaces alike.

The general contract after this stage: a receiver fact is derivable wherever the AST plus import graph make the type resolution certain, regardless of package of the consuming file.

Acceptance: apply `go-interface-field-zero-hits.patch`; both new tests pass; the full `usages_go_graph_test`, `usage_graph_go_test`, and `cross_language_self_usages` suites pass; fmt and clippy clean.

### Stage 2 — C#: a canonical type-identity table, and same-class call proof

Scope: builtin/primitive C# types become first-class type identities in the usages proof pipeline, and unqualified calls inside the declaring class become provable.

Work in `src/analyzer/usages/csharp_graph/resolver.rs`: replace `is_csharp_string_type` (~line 626) with a canonicalization function over C#'s builtin aliases — the keyword forms (`bool`, `byte`, `sbyte`, `char`, `decimal`, `double`, `float`, `int`, `uint`, `nint`, `nuint`, `long`, `ulong`, `short`, `ushort`, `string`, `object`) and their `System.*` struct/class equivalents (`System.Int64` etc.), normalizing both spellings to one canonical identity, and handling nullable (`long?`) and array (`long[]`) wrappers consistently with how project types are normalized (`normalize_type_text` already exists — extend, don't duplicate). Use this canonicalization uniformly in `resolve_type_fq_name`, in extension-receiver-type resolution (`extension_method_receiver_type` and `resolve_member_type_fq_name` paths, ~line 650), and in receiver-target matching, so that a `this long bytes` target and a `long`-typed local both canonicalize to the same identity and match. `string` becomes one row of the table, not an exception. Do NOT widen `CSharpAnalyzer::resolve_visible_type` (`src/analyzer/csharp/mod.rs` ~line 263): it returns project CodeUnits and is shared with definition paths; builtins have no CodeUnit (record this boundary in the Decision Log if any deviation proves necessary).

Work in `src/analyzer/usages/csharp_graph/extractor.rs`: in `scan_unqualified_member_reference` (~line 298), for `TargetKind::Method`, resolve the call site's enclosing type declaration (walk AST ancestors to the enclosing `class_declaration`/`struct_declaration` and map to its CodeUnit); when the enclosing type IS the target's owner (same CodeUnit identity) and the invocation arity is compatible, record a proven hit instead of setting `saw_unproven_match`. Sites in other classes remain unproven (C# `using static` imports make cross-class unqualified calls possible; proving those is out of scope). Note: a recursive call inside the target method itself is excluded from external-usage results by the existing self-hit filter (`hits.rs:17`) — that behavior is correct and stays.

One existing test documents the old always-unproven behavior (`tests/usages_csharp_graph_test.rs` ~line 1003); update it to the new expectation and note the change in the Decision Log.

Acceptance: apply `csharp-unproven-hits.patch`; both new tests pass (the second exercises the full scan_usages tool surface with a `targets` selector and now expects hits); full `usages_csharp_graph_test` and `usage_graph_csharp_test` suites pass; fmt and clippy clean.

### Stage 3 — Rust: seeds are scan identities, not export identities

Scope: a Rust declaration that resolves to a CodeUnit must be scannable whenever the analyzer's own structures (declarations, importer index, reference contexts) identify where it can be referenced — export chains remain an optimization for public API, not a gate.

Work in `src/analyzer/usages/rust_graph/resolver.rs` and `rust_graph.rs`: keep the existing export-seed path untouched (it is correct and narrowing for public APIs). Add a second, additive seed source when export seeds come back empty and the target (or its owner, for members) is a real local declaration: seed from the declaration identity — `(target_file, identifier)` for free items, `(owner_file, owner_identifier)` for members — and let the existing importer index (`RustAnalyzer::usage_importers`, which tracks `use crate::...` edges regardless of export status — verify this during implementation and record findings) plus same-file scope define the candidate files. Then remove the hard-fail branches: the member path (`rust_graph.rs:86-107`) scans the seeded candidates instead of only `target.source()`, and the non-member path (`rust_graph.rs:128-136`) does the same. `NoGraphSeed` remains only for targets that are not local declarations at all and cannot be canonicalized (below). Watch the interaction with `is_graph_visible_member_target` (`resolver.rs:39`): it currently returns empty-success for seeded-but-private members on the assumption that seeds imply export-visibility; with local-declaration seeds that assumption changes — private members with local seeds must scan, while the existing public-surface behavior stays. Expect to split or adjust tests that encoded the old conflation; record each in the Decision Log.

Impl-target canonicalization: when the queried CodeUnit is a synthetic impl-target unit (a Class CodeUnit created by `visit_rust_impl` whose name is bound by an import in the same file), canonicalize the query — resolve the name through the file's import binder / `RustReferenceContext` to the defining declaration's CodeUnit, and run the query against that identity (its usages include the impl file's references). If the name resolves to no in-workspace declaration (type from an unanalyzed external crate), fall back to local-declaration seeding scoped to files that import the same path — structurally, via import binders, never by text search. Use existing resolver helpers (`resolve_scoped_associated_item`, reference contexts); add a shared helper if the interpretation is needed in more than one place.

Acceptance: apply `rust-no-export-seed.patch`; both new tests pass; the full `usages_rust_graph_test` (96+ tests), `usage_graph_rust_test`, `usage_graph_identity_test`, and `cross_language_self_usages` suites pass; fmt and clippy clean.

### Stage 4 — Result model: proven/unproven per-site tiers, verified-absent at query level

Scope: implement the two-level taxonomy settled in the design discussion (Decision D2): per-site verdicts proven/disproven/unproven; query-level outcomes results / verified-absent / failure.

Shared model work: in `src/analyzer/usages/model.rs`, extend `UsageHit` (or accompany it — implementer's choice, recorded in the Decision Log) with a proof tier: an enum `UsageProof { Proven, Unproven }`, defaulting Proven for all existing construction sites so untouched backends are unaffected. Extend `FuzzyResult::Success` to carry unproven sites alongside proven `hits_by_overload` — capped at 20 per symbol (Decision D4) with an uncapped total count. In `finder.rs`, thread the new data through `QueryResult` unchanged in shape otherwise.

Backend emission (C#, Go, Rust only — Decision D5): C# — replace the boolean `saw_unproven_match` in `csharp_graph/extractor.rs`/`shared.rs` with collection of the actual unproven sites (they are exactly the sites currently setting the boolean, which already pass structural plausibility per Decision D3: invocation shape plus member-name match plus, for extension methods, arity match); delete the discard-and-fail gate at `shared.rs:70-76` — the outcome becomes `Resolved` success with proven hits (possibly zero) plus unproven sites (Decision D6). Go — in `go_graph/extractor.rs` (~lines 470-518), selector-expression sites that match the member name but fail every receiver proof become unproven sites instead of nothing. Rust — in the member-scan path, name-matching method/field reference sites whose receiver analysis returns unknown become unproven sites; if this wiring proves invasive, it may be deferred to a follow-up with the deferral recorded in the Decision Log (Rust's Stage 3 already removed its hard-fail, so the tier is an enhancement there, not the bug fix).

Tool surface work in `src/searchtools.rs` (rendering ~lines 3800+): per-symbol summaries gain `unproven_hits` (total count) and rendered unproven sites appear under a clearly-labeled section separate from proven usages; a symbol whose scan completed (candidate set not truncated, no strategy failure) with zero proven and zero unproven hits reports `verified_absent: true`. Truncation or any unproven site downgrades the verified-absent claim (Decision D2). Keep every existing summary field intact — the brokkbench/usagebench harness parses this JSON; additive changes only.

Add behavior tests: a C# extension method with an untypeable receiver (e.g. receiver from a `dynamic` or an untyped lambda parameter) yields zero proven hits, nonzero unproven, no failure; a Go query whose only candidates fail receiver typing yields unproven sites rather than silent zero; a symbol with genuinely no references in a complete scan yields `verified_absent: true`; a truncated scan does not claim verified-absent. Use `InlineTestProject`.

Acceptance: new result-model tests pass; the entire usages/usage_graph test family passes; fmt and clippy clean.

### Stage 5 — Hints derive from what failed, never from a fixed reason-kind table

Scope: make `usage_failure_hint` (`src/searchtools.rs:2574`) context-aware. Inputs: the reason kind, whether the query was already location-anchored (`location_selected` is already tracked, ~line 2948), and truncation state. Rules: never recommend a `targets` selector to a query that already used one (the location-selector failure path at `searchtools.rs:2561` currently does exactly that); after Stage 4, `unsafe_inference` no longer occurs for scannable targets, so its hint disappears for that case — where a result contains only unproven hits, the summary (not a failure hint) explains that receiver types could not be verified; `no_graph_seed` keeps the `search_symbols` suggestion, and offers `targets` only when the query was not already anchored. Add a test asserting the anchored re-call of a failing query does not receive the same recovery hint it just followed.

Acceptance: hint tests pass; full test family passes; fmt and clippy clean.

## Concrete Steps

All commands run from the repository root.

Per stage N (1-5):

    # Stage 1/2/3 only: apply the stage's repro patch first and watch it fail
    git apply .agents/docs/issue-528-repro-tests/<stage patch>.patch
    BIFROST_SEMANTIC_INDEX=off cargo test --test <stage suite> -- <new test filter>
    # expect: FAILED (this proves the bug before the fix)

    # implement the stage's changes, then:
    cargo fmt
    cargo clippy --all-targets --all-features -- -D warnings
    BIFROST_SEMANTIC_INDEX=off cargo test --test <stage suite>
    BIFROST_SEMANTIC_INDEX=off cargo test --test usage_graph_test --test cross_language_self_usages

Stage suites: Stage 1 `usages_go_graph_test` and `usage_graph_go_test`; Stage 2 `usages_csharp_graph_test` and `usage_graph_csharp_test`; Stage 3 `usages_rust_graph_test`, `usage_graph_rust_test`, `usage_graph_identity_test`; Stages 4-5 the full usages/usage_graph family plus new tests.

Final gate after Stage 5 (full workspace):

    cargo fmt
    cargo clippy --all-targets --all-features -- -D warnings
    BIFROST_SEMANTIC_INDEX=off cargo test --features nlp,python

(The `--features nlp,python` full run is required because featureless `cargo test` silently skips `#![cfg(feature = "nlp")]` suites.)

The session driver commits after each verified stage with a multiline checkpoint message explaining the why; implementation agents leave all changes uncommitted in the working tree. Never push.

## Validation and Acceptance

Behavioral acceptance, per the issue's three repro shapes, exercised by the six repro tests plus Stage 4/5 tests:

- Rust: querying a crate-private method used from another file of the same crate returns that call site; querying an impl-target name for an imported type returns the impl-file references. Before: `RustExportUsageGraphStrategy: no export seed resolved`. Run `BIFROST_SEMANTIC_INDEX=off cargo test --test usages_rust_graph_test -- without_export_seed` — expect 2 passed.
- C#: querying an extension method on `long` returns the receiver-syntax call site. Before: `CSharpUsageGraphStrategy: no proven structured hits`. Run `BIFROST_SEMANTIC_INDEX=off cargo test --test usages_csharp_graph_test -- primitive` — expect 2 passed.
- Go: querying either the interface method or the unexported implementing struct's method returns the cross-package `c.localBase.Method()` call site. Before: silent `total_hits: 0`. Run `BIFROST_SEMANTIC_INDEX=off cargo test --test usages_go_graph_test -- imported_interface` — expect 2 passed.
- Result model: unproven sites are returned and labeled; complete zero scans report verified-absent; truncated scans do not. Hints never recommend the recovery that was just attempted.

## Idempotence and Recovery

Each stage is additive and independently committable; a failed stage is recovered by `git checkout -- <files>` back to the last stage commit (nothing is committed until verified, so the working tree is the only volatile state). `git apply` of a repro patch is idempotent-unsafe (re-applying fails cleanly with "patch does not apply") — check `git status` before applying. If a stage's suite regresses tests outside its scope, stop, record the interaction in Surprises & Discoveries, and resolve before committing. The investigation worktrees under the session scratchpad and `.agents/docs/issue-528-repro-tests/` patches are session artifacts; the patches become redundant once their tests are committed with the stages (remove the patch directory in the final cleanup commit).

## Artifacts and Notes

Failing-before evidence (2026-07-07, master @ 9131080), abridged:

    rust:   expected private member usage success, got Failure { reason: "RustExportUsageGraphStrategy: no export seed resolved" }
    csharp: NzbDrone...SizeSuffix should resolve: No relevant usages found  /  reason_kind: unsafe_inference, hint recommends targets selector (self-defeating)
    go:     assertion failed: expected imported interface field hit: left: 1, right: 0

## Interfaces and Dependencies

No new external dependencies. End-state interfaces (names may be adjusted during implementation if recorded in the Decision Log):

In `src/analyzer/usages/model.rs`:

    pub(crate) enum UsageProof { Proven, Unproven }
    // UsageHit carries a proof tier; FuzzyResult::Success carries capped
    // unproven sites plus an uncapped unproven count alongside hits_by_overload.

In `src/analyzer/usages/csharp_graph/resolver.rs`: a canonicalization of C# builtin type aliases (keyword and System.* forms, nullable/array wrappers) used by all receiver/target type resolution in the usages pipeline.

In `src/analyzer/usages/go_graph/resolver.rs`: `type_ref_matches_compatible_receiver` resolves package qualifiers through import edges; field-owner facts exist for consumer packages.

In `src/analyzer/usages/rust_graph/resolver.rs`: seed inference falls back from export seeds to local-declaration seeds (declaration identity + importer index); synthetic impl-target CodeUnits canonicalize to the imported type's declaration before seeding.

In `src/searchtools.rs`: `usage_failure_hint` takes the query's anchoring context; scan_usages summaries additively include `unproven_hits` and `verified_absent`.

---

Revision note (2026-07-07, Claude): initial plan authored from the verified root-cause investigation of issue #528 items 1-3 and the design discussion with Jonathan settling the proven/unproven/failure taxonomy. A first draft of this file wrongly pre-filled the living sections with hypothetical completed-stage entries; this revision resets Progress/Surprises/Outcomes to the true pre-implementation state and re-anchors code references after the shared-usage-index refactor merge (`9de316e`).

Revision note (2026-07-07, Codex): Stage 1 implementation completed and the living sections were updated with the failed-before/passed-after Go repro evidence, the `inverted.rs` inspection result, and the import-edge field-owner fact decisions.

Revision note (2026-07-07, Codex): Stage 2 implementation completed and the living sections were updated with failed-before/passed-after C# primitive receiver evidence, the builtin `object` test expectation changes, and decisions for canonical builtin type identity plus same-class unqualified call proof.
