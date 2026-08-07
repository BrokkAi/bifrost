# Census-seeded FIRD: implement the census probe seed (M1-M3) and run the 11-language campaign

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. It is maintained in accordance with `.agents/PLANS.md` (read that file before editing this plan).

It builds on the design in `.agents/plans/reference-differential-census-seeding.md` (checked in). That design is incorporated by reference; the essential parts are restated below so this plan is self-contained.

## Purpose / Big Picture

The forward-vs-inverse reference differential (FIRD) audits whether Bifrost's inverse usage query can recover the sites that forward definition-resolution finds. Today it can only probe sites the analyzer's own filtered candidate frontier proposes (`reference_candidate_ranges` in `crates/bifrost-analysis/src/analyzer/reference_candidates.rs`). Constructs the analyzer mis-parses produce no probe, so joint blindness (both forward and inverse silently failing on the same construct) reads as health.

After this change a contributor can run:

    target/release/bifrost_reference_differential run-repo --root <clone> --language rust \
      --probe-seed census --tiers 1,2,3 --output <out.jsonl> ...

and receive a report whose probe sites came from a **raw tree-sitter identifier census** (every identifier-class leaf token, ignorant of the analyzer index), so it surfaces usage-loss at sites the index never proposed. Forward-resolved census sites flow through the existing inverse comparison (a miss is a finding with no external referee). Forward-unresolvable census sites are graded into deterministic evidence tiers. The end state is a per-language campaign over the top-20 task-weighted repos of all 11 corpus languages, producing triaged issues assigned to `jbellis`, fixed and closed depth-first per language, merged to `origin/master` as we go.

Scope is the MCP `symbols` toolset and the associated Rust and Python APIs; LSP comes along for the ride but is not a focus. M4 (external referee) is intentionally **not** built; tier-3 residue is adjudicated by the agent during triage.

## Progress

- [x] (2026-08-07) Recon: confirmed census seeding is unimplemented (no `census.rs`, no `--probe-seed`); mapped FIRD engine seam (`collect_sampled_sites` at `src/reference_differential/mod.rs:555`), report schema, CLI parsers, and the candidate walk (`collect_candidate_ranges`); confirmed tasks.py selector (`task_repos(Predicates(not_overlarge=True).resolved(), langs=[lang])` ranked by `task_count`) and the 11 languages.
- [x] (2026-08-07) M1: census walk (`CandidateFrontier::Census` + `census_identifier_ranges`), `ProbeSeed`/`TierSelection` in engine config + CLI (`--probe-seed`, `--tiers`), `collect_sampled_sites` seed branch, `classify_census_gaps` (tier 1/2/3 via `census_site_role` + same-file decl), report rows tagged `seed`/`tier`. Tests: frontier superset unit test, two engine integration tests (census proposes macro-body occurrence + stays silent without same-file decl), all green. End-to-end tokio census pass succeeded (seed-tagged sites, tier-2 gaps, 5 forward-adjudicated misses).
- [ ] M2: `--probe-seed` pluggability in `collect_sampled_sites`, forward adjudication of census sites tagged `seed: census`, tier-2/3 classification, ledger/shrink/single-line rerun.
- [ ] M3: inverse-precision check (name-literal), sharded corpus runner (`--shard K/N`), per-language ranking; two-language corpus pass.
- [ ] Campaign: per-language depth-first passes over top-20 repos; file/fix/close/merge; per-language summary. Rediscovery audit against #1526/#1527/#1528/#1537/#1377 (#1376 already fixed and closed).
  - [x] (2026-08-07) RUST run complete (20/20 repos, `--tiers 1`, clone HEADs, `/mnt/optane/tmp/bifrost-fird/rust-census-54eee258.jsonl`). 471 actionable = 293 forward-adjudicated misses + 178 tier-1 gaps. Signal/noise: ~183 are prelude/std noise (`Err` 116, `Ok` 48, `drop` 19) - forward can't resolve external std, or mis-resolves `Err` to a same-named local enum (nom). Many remaining forward-adjudicated misses are forward mis-resolutions to a *module* target (e.g. `field::ValueSet` -> `tracing.field` module), which the runbook says is not a legitimate inverse miss. Clearest genuine finding: tracing-subscriber `Filter` trait-reference inverse miss (6 witnesses, forward-correct, complete-but-absent). It does not minimize (plain trait-bound/cross-module/simple-cfg cases are all Consistent), so it was FILED + ESCALATED to Dave as #1749 (cfg-gated-trait-in-multi-crate-workspace interaction, same area as #1377).
  - [ ] RUST remaining: triage the non-noise tail (coreutils `Type::method`/`Type::CONST` associated-member misses; `State`/`Self::Error` associated-type refs) for any minimizable, generalizable, fixable bug; else conclude rust's directly-fixable yield is low and summarize.

## Surprises & Discoveries

- Observation: Census seeding was entirely unbuilt despite being a detailed design doc; all its milestones were unchecked.
  Evidence: `grep -rn "probe.seed\|census" src/reference_differential/ src/bin/` finds nothing; `find . -name census.rs` empty.
- Observation: The FIRD engine lives in the facade crate at `src/reference_differential/mod.rs`, not `crates/bifrost-analysis/...` as the design doc's path suggested.
  Evidence: `find . -path '*reference_differential*' -name '*.rs'` -> `./src/reference_differential/mod.rs`, `./src/bin/bifrost_reference_differential.rs`.
- Observation: The index (reference) frontier already proposes identifier occurrences inside `macro_rules!` bodies, contrary to the design doc's premise that macro-block items are index-blind. The census's actual difference from the index frontier is the per-language reference *exclusions* (Go/C# decl names, Rust associated-type decl names, JS export aliases) plus receiver keywords - not macro bodies.
  Evidence: an inline census-vs-index engine test showed both seeds propose the macro-body `frobnicate` occurrence at the same byte; the first draft assertion (index excludes it) failed.
- Observation: On a 60-file tokio census smoke run, the census produced 5 forward-adjudicated misses (forward resolved, inverse missed) and 8 tier-2 gaps, with every site tagged `seed: census`. The forward-adjudicated misses are FIRD's classic finding class, now reachable at census sites.
  Evidence: `/mnt/optane/tmp/bifrost-fird/smoke-tokio-census.jsonl`; `.report.config.probe_seed == "census"`.

## Decision Log

- Decision: Build M1-M3, skip M4 (external referee); the agent adjudicates tier-3 during triage.
  Rationale: Forward-adjudicated misses plus tiers 1-2 need no referee and carry the designed yield; M4 is marked optional/cuttable and only pre-ranks the tier-3 long tail. User confirmed 2026-08-07.
  Date/Author: 2026-08-07, Claude (Opus) with Jonathan.
- Decision: Implement the census walk as a new `CandidateFrontier::Census` variant of the existing iterative `collect_candidate_ranges` rather than a separate module.
  Rationale: The traversal, limit handling, and cancellation are already correct and stack-safe; census differs only in the leaf predicate (identifier-class, comment/string excluded) and the absence of per-language reference exclusions. Reuse avoids a parallel divergent walker. (Revisit if scope-path/role recording makes the shared function unwieldy.)
  Date/Author: 2026-08-07, Claude (Opus).
- Decision: M2's ledger/shrink/rerun is realized as a post-processing triage script (`/mnt/optane/tmp/bifrost-fird/triage.py`) over the report JSONL rather than embedded in the engine; M3's `--shard` is realized as subagent-level parallelism (independent per-repo/per-language runs) rather than an in-process shard flag.
  Rationale: The report JSONL already carries every evidence field the ledger needs (seed, tier, forward_status, targets, inverse_hit, source_evidence, repo_head), and this campaign is agent-adjudicated (not the autonomous run-until-dry loop the in-engine ledger/shrink was designed for). Subagent parallelism (user-authorized) covers corpus throughput without an in-process sharder. Keeps engine risk low and gets to real findings faster. The census FINDING capability (forward adjudication + tier grading) is fully in the engine.
  Date/Author: 2026-08-07, Claude (Opus).
- Decision: Campaign runs use `--tiers 1` (actionable = forward-adjudicated misses + tier-1 gaps) at first, widening only if the high-precision set dries up.
  Rationale: A 60-file tokio smoke run already produced ~160 tier-3 rows; tier-3 is exploration-grade and would swamp hand-adjudication at full budget. Forward-adjudicated misses are reported regardless of `--tiers`, so `--tiers 1` keeps the actionable set high-precision.
  Date/Author: 2026-08-07, Claude (Opus).
- Decision: Campaign runs analyze each clone at its current clean HEAD (recorded as `repo_head`) rather than force-checking-out corpus pins.
  Rationale: `run-corpus` reads and records the clone HEAD; all sampled clones are clean. A bug reproduced at a clean checkout is a valid finding, and the recorded head makes it reproducible. Force-checkout of 220 clones is out of scope for finding+fixing analyzer bugs.
  Date/Author: 2026-08-07, Claude (Opus).

## Outcomes & Retrospective

(Pending. Filled per milestone and at completion.)

## Context and Orientation

FIRD engine: `src/reference_differential/mod.rs`. Key items:
- `ReferenceDifferentialConfig` (line ~34): run knobs (`max_files`, `max_sites`, `seed`, `exact_site`, ...). Add `probe_seed: ProbeSeed` and `tiers: TierSelection` here.
- `collect_sampled_sites` (line ~514): parses each file via `DeclarationNameRangeContext`, calls `reference_candidate_ranges(root, language, max)` at line ~555, subtracts declaration-name ranges, and pushes `SampledSite`s into a bounded heap keyed by `site_priority`. This is the seed seam.
- `forward_resolve_sites`/`forward_resolve_file` (line ~638/687): forward definition lookup per site, producing `ReferenceDifferentialSite` records and `ResolvedSite`s.
- `compare_inverse` (line ~347): runs the inverse usage query per resolved group and marks each site consistent/missing.
- `ReferenceClassification` enum (line ~134): `Consistent`, `EditorOnly`, `Unproven`, `Inconclusive`, `Missing`.
- `ReferenceDifferentialSite` (line ~143): the per-site report row. Add `seed` and `tier` fields.

Candidate walk: `crates/bifrost-analysis/src/analyzer/reference_candidates.rs`. `collect_candidate_ranges` is an iterative stack walk with a `CandidateFrontier` (References | SemanticTokens). A leaf qualifies when its kind matches the frontier predicate, it is not an excluded reference candidate, it is a leaf (or a compound reference), and it is non-empty.

CLI: `src/bin/bifrost_reference_differential.rs`. `parse_run_repo_args`/`parse_run_corpus_args` plus shared option parsing (`--max-*`, `--seed`, ...). Add `--probe-seed index|census`, `--tiers 1,2,3`, and (M3) `--shard K/N`.

Corpus tooling: `~/Projects/brokkbench/tasks.py`. `task_repos(predicates, langs=[lang])` returns `RepoRef{lang, repo_slug, task_count}`; `Predicates(not_overlarge=True)` excludes `sft-tools-commits/large-repos.csv`. The 11 languages are the dir names under `~/Projects/brokkbench/sft-tools-commits/`: c, cpp, csharp, go, java, js, php, py, rust, scala, ts. Clones live at `~/Projects/brokkbench/clones` -> `/mnt/T9/repo-clones`.

Terms: "census" = every identifier-class leaf token from a tree-sitter parse (comments/strings excluded by node kind), independent of the analyzer index. "Seed" = the generator of probe sites; pluggable as `index` (today) or `census`. "Tier" = deterministic evidence grade for a forward-unresolvable census site (tier 1 same-scope member/field with same-file/module decl and no shadow; tier 2 same-module or import-connected; tier 3 else). "Forward adjudication" = using forward resolution itself as the referee: a census site forward-resolves to D and the inverse query for D misses the site.

## Plan of Work

M1 — Census walk + tier 1 + CLI. In `reference_candidates.rs` add `CandidateFrontier::Census` and a public `census_identifier_ranges(root, language, limit)` (plus a cancellable variant) that collects identifier-class leaf ranges with no reference exclusions, excluding comment/string node kinds. Add a `ProbeSeed` enum and `TierSelection` to the engine config and CLI. In `collect_sampled_sites`, branch on `config.probe_seed` to choose the walk. Add a census scope/role helper for tier-1: for a forward-unresolved census member/field occurrence of name N, check the census's own same-file/same-module declaration of N with no local shadow. Add unit tests + a firing fixture (unindexed same-file receiver call yields one tier-1 finding) and a silent healthy fixture.

M2 — Forward adjudication + tiers + ledger. Route census sites through the unchanged forward/inverse pipeline; tag report rows `seed: census`. Classify forward-unresolved sites into tiers 2/3. Emit a ledger (append-only JSONL, dedup key `(tier, language, syntactic shape)`, minimal repro, single-line rerun) under `/mnt/optane/tmp/bifrost-fird/`.

M3 — Inverse-precision + sharded runner. After inverse comparison, check every inverse hit's range corresponds to a census occurrence of the name (name-literal); unbacked hits become their own signature class. Add `--shard K/N` (hash-partition files) to `run-corpus`. Wire per-language ranking from tasks.py.

Campaign — Per language A..K (depth-first): select top-20 repos via tasks.py; build the release runner from clean HEAD; run census FIRD (tier-1 first, then 2-3); triage every finding per the runbook; file issues assigned to `jbellis` (skip issues already assigned to others; escalate non-generalizable/hacky ones to `DavidBakerEffendi` with a comment); fix with structured (non-regex) solutions + regressions; `cargo test` green; commit; merge to `origin/master`; summarize the language before moving on.

## Concrete Steps

Build: `cd /mnt/optane/bifrost-fird && scripts/with-isolated-cargo-target.sh cargo build --release --bin bifrost_reference_differential` (final campaign builds must be non-isolated and durable per the runbook; use isolated target only for iteration).

Select repos (per language): a small Python driver importing tasks.py, printing the top-20 `not_overlarge` repos by `task_count`. Stored under `/mnt/optane/tmp/bifrost-fird/select_repos.py`.

Run: `run-repo`/`run-corpus` with `--probe-seed census --tiers 1,2,3` and the standard semantic budget from the runbook. Outputs and ledgers under `/mnt/optane/tmp/bifrost-fird/`.

## Validation and Acceptance

- M1: `cargo test -p brokk-bifrost-analysis reference_candidates` (census walk unit tests) and the engine fixture tests pass; the firing fixture yields exactly one tier-1 finding and the healthy fixture yields zero.
- M2: one census pass on a rust and a go corpus repo produces report rows tagged `seed: census`; tier-1/2 rows rerun deterministically via the single-line rerun command.
- M3: a two-language corpus pass completes; an injected fabricated inverse hit surfaces as an inverse-precision signature.
- Campaign per language: `cargo test` green after fixes; issues filed/closed; language summary delivered.

## Idempotence and Recovery

All runs write unique head-scoped outputs under `/mnt/optane/tmp/bifrost-fird/`; reruns overwrite their own unique paths. `run-corpus` is append-only and resume-safe at repo-record granularity. Temporary outputs are cleaned at campaign end. Code changes are committed frequently to `bifrost-fird` and merged to `origin/master` per language.

## Interfaces and Dependencies

In `crates/bifrost-analysis/src/analyzer/reference_candidates.rs`:

    pub fn census_identifier_ranges(root: Node<'_>, language: Language, limit: usize) -> ReferenceCandidateRanges;

In `src/reference_differential/mod.rs`:

    pub enum ProbeSeed { Index, Census }
    pub struct TierSelection { /* which of tiers 1,2,3 to report */ }
    // ReferenceDifferentialConfig gains: pub probe_seed: ProbeSeed, pub tiers: TierSelection
    // ReferenceDifferentialSite gains: pub seed: &'static str, pub tier: Option<u8>

CLI (`src/bin/bifrost_reference_differential.rs`): `--probe-seed index|census` (default index), `--tiers 1,2,3` (default all), `--shard K/N` (run-corpus, M3).

## Artifacts and Notes

(Transcripts and evidence appended per milestone.)
