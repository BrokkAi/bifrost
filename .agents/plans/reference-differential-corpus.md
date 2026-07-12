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

- Decision: Treat the symbols MCP toolset as the production acceptance surface for corpus findings; LSP coverage is incidental and must not expand campaign scope.
  Rationale: The campaign exists to improve `get_definitions_by_location`, `get_definitions_by_reference`, usage scanning, symbol sources, and related symbols tools. Their shared resolver may also improve LSP behavior, but LSP-only discrepancies are outside this campaign.
  Date/Author: 2026-07-12 / Codex

- Decision: Resolve indexed Rust path dependencies through one cached Cargo route index shared by forward module lookup and the inverse usage index.
  Rationale: Per-reference manifest parsing would be a hot-path regression, while a forward-only filesystem fallback would recreate definition/usage disagreement. The compact route index parses indexed manifests once, preserves importer-scoped aliases and library names, and refuses to guess registry dependencies from coincidental workspace names.
  Date/Author: 2026-07-12 / Codex

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
