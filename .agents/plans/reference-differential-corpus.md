# Build and run a corpus reference differential

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain it in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost currently learns about false-negative reference resolution after agents encounter them in production. This work adds a dedicated offline engine that audits real repositories by resolving a source reference forward to its declaration and then asking the inverse usage resolver for the same declaration. A reference resolved by the forward path but absent from the inverse path is a concrete disagreement with enough source and identity evidence to reproduce locally. The first campaign runs the engine against the largest available repository in each target corpus language, creates GitHub issues for genuine defects, fixes and closes those issues, and reports the result by language.

## Progress

- [x] (2026-07-12 03:00Z) Inspected repository instructions, current analyzer architecture, benchmark conventions, corpus metadata, clone availability, and the canonical target language registry.
- [x] (2026-07-12 03:00Z) Selected the deterministic N=1 repository for each of the eleven target corpus languages by recorded `code_loc`, restricted to available valid clones.
- [ ] Implement shared structured reference-candidate enumeration and the library-owned differential runner.
- [ ] Implement the dedicated corpus CLI with deterministic selection, resumable JSONL reports, exact-site reruns, and bounded sampling.
- [ ] Validate the engine on small repositories and commit the engine checkpoint.
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

## Decision Log

- Decision: Implement a library-owned engine plus a dedicated Rust binary, not a unit test or brokkbench production trajectory.
  Rationale: The engine needs direct access to structured definition and usage internals, must run independently over large clones, and must emit durable campaign artifacts even when interrupted.
  Date/Author: 2026-07-12 / Codex

- Decision: Use grammar-derived identifier leaves from real source, with structured declaration-name exclusion, rather than text search or generated programs.
  Rationale: This uses the user's real-world corpus and respects the repository rule against string-scanning substitutes for analyzer structure.
  Date/Author: 2026-07-12 / Codex

- Decision: Deterministically sample reference sites by a stable hash of repository-relative path and byte range, then group resolved sites by exact declaration set and run the inverse resolver once per group.
  Rationale: Path-order truncation would bias large repositories toward a few directories. Grouping preserves broad real-world coverage while bounding repeated inverse work.
  Date/Author: 2026-07-12 / Codex

- Decision: Restrict each inverse query to the files containing sampled forward references for that declaration and mark the scope authoritative.
  Rationale: The differential asks whether inverse resolution can recover already-known sites, not whether candidate discovery can rediscover the whole workspace. This isolates semantic disagreement and prevents whole-repository candidate enumeration per target.
  Date/Author: 2026-07-12 / Codex

- Decision: Treat ambiguous forward results, inverse failures, call-site caps, and truncated unproven samples as inconclusive rather than defects.
  Rationale: Only a unique forward declaration coupled with a complete inverse answer can prove a contradiction. The report must separate unsupported or bounded work from actionable missing references.
  Date/Author: 2026-07-12 / Codex

## Outcomes & Retrospective

Implementation and the N=1 campaign are in progress. This section will contain the final per-language counts, issue links, fixes, performance observations, and remaining limitations.

## Context and Orientation

`src/analyzer/usages/get_definition/` resolves a source reference forward to one or more `CodeUnit` declarations. A `CodeUnit` is Bifrost's structured declaration identity and includes source path, declaration kind, package/name, signature, and synthetic status. `src/analyzer/usages/finder.rs::UsageFinder` resolves in the opposite direction, from declarations to `UsageHit` source sites. A proven differential defect exists when forward resolution uniquely identifies a declaration set, the inverse query completes without truncation, and no proven inverse hit covers the original reference token.

`src/lsp/handlers/semantic_tokens.rs` currently owns a useful but overly local `reference_candidate_ranges` helper. Move that iterative tree-sitter traversal into `src/analyzer/reference_candidates.rs` and reuse it from both semantic tokens and the new engine. Continue to use `src/analyzer/declaration_range.rs::DeclarationNameRangeContext` so declaration identifiers are not mistaken for references.

The new library module belongs under `src/reference_differential/`. It owns serializable configuration, stable declaration identity, per-site evidence, repository summaries, deterministic sampling, forward batching, inverse grouping, and comparison. The separate binary `src/bin/bifrost_reference_differential.rs` owns command-line parsing, corpus selection, Git metadata, JSONL output, progress, and exit behavior.

The corpus lives at `/home/jonathan/Projects/brokkbench/clones`, a symlink to `/mnt/T9/repo-clones`. Repository membership is the set of canonical `<commits-root>/<language>/<slug>.jsonl` files, excluding `.testsome.jsonl` sidecars. Repository size comes from `/home/jonathan/Projects/brokkbench/sft-tools-commits/repos.csv::code_loc`. Missing or invalid size metadata and invalid clones must be reported rather than silently ranked as zero.

## Plan of Work

First extract the structured reference-candidate traversal from semantic tokens without changing LSP behavior. Build the engine around one persisted `WorkspaceAnalyzer` per repository. Filter audited files by requested corpus language; C uses C-family `.c` seeds and C++ uses the remaining C++ family, while both resolve through `Language::Cpp`. For each eligible file, read the analyzer-generation source, parse it once through `DeclarationNameRangeContext`, subtract declaration-name ranges, and feed a stable hash-priority sampler. The sampler must scan the full eligible file inventory so `--max-sites` is unbiased by lexical path order.

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
      --repos-per-language 1 --max-sites 10000 \
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
