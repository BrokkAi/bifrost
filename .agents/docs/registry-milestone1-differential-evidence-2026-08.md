# Milestone 1 acceptance: reference-differential invariance evidence (2026-08-04)

Acceptance evidence for `.agents/plans/analysis-language-registry-spi.md`, milestone 1
("differential smoke flat"). The plan's Validation section asks for one
`bifrost_reference_differential --cache-mode ephemeral` smoke on a mixed-language corpus
showing an identical divergence census before and after the dispatch inversion.

**Verdict: IDENTICAL.** The eleven-language census is byte-identical between the
pre-milestone-1 baseline and the milestone-1-complete candidate, and so is the full
per-site record payload once run provenance and timing are removed. No milestone-1
behavior regression is visible to this audit.

## Commits compared

| Role | Commit | Subject |
| --- | --- | --- |
| Baseline | `508b073759adb25fde692ad5a5104759a18e2ba4` | Tick milestone 0 in the registry ExecPlan (46cfb520 merged) |
| Candidate | `74bf60a31db3d530317867dfaf78b8e3eacdeb2a` | Milestone 1f: the adding-a-language runbook; tick 1f and record its decisions |

`508b0737` is the true pre-milestone-1a tip: it is the doc-only tick that closes milestone 0,
and the next commit (`281624d6`) is the first milestone-1a code change. The comparison
therefore spans the whole of milestone 1 (1a through 1f). The commissioning brief named
`7e1045bc` as "the pre-milestone-1a tip", but `7e1045bc` is actually the milestone-1b tick;
using it would have excluded 1a (the `LanguageSupport` registry itself and the finder /
dead-code strategy dispatch) and 1b (the receiver, `get_type`, and forward-query tables) from
the audit. `508b0737..74bf60a3` strictly contains `7e1045bc..74bf60a3` and contains no
upstream churn: every commit in the range is registry-plan work plus two worktree merges.

Both runs recorded `bifrost_dirty = false`.

## Corpus

Eleven pinned clones from the established local corpus, one per corpus language, chosen for
small-to-medium size (roughly 44k code LOC total) rather than by the runbook's largest-first
default. Kotlin has no membership directory under the commits root, and Ruby is not a
`bifrost_reference_differential` corpus language at all, so neither is covered here; the Ruby
`UsageQueryResolver` fold-in of milestone 1d needs its acceptance from the unit pins the plan
already names, not from this smoke.

| Corpus language | Repository slug | Pinned clone head | code_loc |
| --- | --- | --- | --- |
| c | `ggreer__the_silver_searcher` | `a61f1780b64266587e7bc30f0f5f71c6cca97c0f` | 3951 |
| cpp | `gabime__spdlog` | `8671ca4d492c8ee1cdfd3dd88afb9f88dd268178` | 3811 |
| csharp | `khellang__Scrutor` | `7f315dab5b0f7134a6be58941db1da8c904507e2` | 3698 |
| go | `jellydator__ttlcache` | `db85e4f64251c73b33ba055e3fe07d70870992ce` | 3077 |
| java | `semver4j__semver4j` | `751b5f5fba3ac3a7eafa758b95a22eaf3d3c5dfb` | 3248 |
| js | `ging__fiware-pep-proxy` | `475474ad47de7dd46fb40473ed3b1db420c1181a` | 3224 |
| php | `symfony__property-access` | `9261ef060f26cc7b728f67f141ba19b98a6209a9` | 3150 |
| py | `Suor__funcy` | `9eb04473e31b6b60bd459e4dda24f6b1db5a3773` | 3131 |
| rust | `XAMPPRocky__tokei` | `fa44e5194060305576514d59b850353643afbfc8` | 4045 |
| scala | `typelevel__scalacheck` | `3b1e58f6f06cd540bd9acda7794c5fc51665866f` | 9706 |
| ts | `xurei__restgoose` | `43cd725534e8ea83936b052f4c97f3b020c30200` | 3553 |

Clones root `/home/jonathan/Projects/brokkbench/clones`, commits root
`/home/jonathan/Projects/brokkbench/sft-tools-commits`. All eleven clones were clean at run
time; `khellang__Scrutor`, `jellydator__ttlcache` and `typelevel__scalacheck` carried an
untracked `.bifrost/` from earlier work, excluded locally through each clone's
`.git/info/exclude` as the runbook prescribes.

The rust slot was originally `dtolnay__anyhow`. It aborts the runner at both commits; see
"Unrelated pre-existing finding" below. `XAMPPRocky__tokei` replaced it so the census could
complete.

## Command

Identical at both commits except the runner binary and the output path. Each binary was a
fresh featureless release build of its own commit (`nlp` is not needed: the
`reference_differential` module is not feature-gated).

```bash
cargo build --release --bin bifrost_reference_differential

target/release/bifrost_reference_differential run-corpus \
  --clones-root /home/jonathan/Projects/brokkbench/clones \
  --commits-root /home/jonathan/Projects/brokkbench/sft-tools-commits \
  --language c --language cpp --language csharp --language go --language java \
  --language js --language php --language py --language rust --language scala --language ts \
  --repo ggreer__the_silver_searcher --repo gabime__spdlog --repo khellang__Scrutor \
  --repo jellydator__ttlcache --repo semver4j__semver4j --repo ging__fiware-pep-proxy \
  --repo symfony__property-access --repo Suor__funcy --repo XAMPPRocky__tokei \
  --repo typelevel__scalacheck --repo xurei__restgoose \
  --repos-per-language 1 \
  --repo-jobs 1 \
  --jobs 8 \
  --cache-mode ephemeral \
  --seed 0 \
  --output RUN.jsonl
```

All engine budgets were the runner defaults (`--max-files 1000`, `--max-sites 10000`,
`--max-candidates-per-file 50000`, `--max-source-bytes 4194304`, `--max-targets 1000`,
`--max-usage-files 1000`, `--max-usages 100000`). `--strict` was deliberately omitted so the
process exit code did not depend on the presence of raw findings; both runs exited 0 with
11/11 completed repository records. `--repo-jobs 1` makes JSONL record order deterministic.
`--cache-mode ephemeral` keeps the clone caches untouched, per CLAUDE.md.

Runner checksums: baseline `0b4b2fa3f20ee80117b924a69b77348e17f1d5c3a79b531cfc410e234669f28b`,
candidate `23854d4c50a79d563004e98e85ccc9981ceb434b094083e24d5c578b5074db72`.

The eleven per-language `run_fingerprint` values are pairwise equal between the two runs, so
both legs audited the same configuration.

## The divergence census (identical at both commits)

Per repository: sampled sites, then the five classification counts.

| Language | Repository | sampled | consistent | editor_only | unproven | inconclusive | missing |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| c | `ggreer__the_silver_searcher` | 6494 | 1343 | 0 | 10 | 5141 | 0 |
| cpp | `gabime__spdlog` | 10000 | 1069 | 84 | 77 | 8711 | 59 |
| csharp | `khellang__Scrutor` | 3959 | 701 | 92 | 36 | 3130 | 0 |
| go | `jellydator__ttlcache` | 3085 | 311 | 263 | 9 | 2434 | 68 |
| java | `semver4j__semver4j` | 3291 | 637 | 125 | 0 | 2528 | 1 |
| js | `ging__fiware-pep-proxy` | 2837 | 499 | 0 | 0 | 2338 | 0 |
| php | `symfony__property-access` | 1946 | 131 | 238 | 0 | 1577 | 0 |
| py | `Suor__funcy` | 3922 | 346 | 39 | 0 | 3537 | 0 |
| rust | `XAMPPRocky__tokei` | 7540 | 802 | 110 | 0 | 6607 | 21 |
| scala | `typelevel__scalacheck` | 10000 | 1307 | 159 | 0 | 8493 | 41 |
| ts | `xurei__restgoose` | 3432 | 581 | 9 | 0 | 2842 | 0 |

Totals: 56506 sampled sites, 7727 consistent, 1119 editor_only, 132 unproven, 47338
inconclusive, 190 missing. Zero `file_errors` across all eleven repositories, and no
`target_truncated_sites`, `skipped_targets` or `candidate_limit_exceeded_files` distortion.
Two repositories, cpp `gabime__spdlog` and scala `typelevel__scalacheck`, sit exactly on the
default `--max-sites 10000` sampling cap; the cap is deterministic and seeded, and applies
identically to both legs, so it narrows the audit's reach on those two but not the
comparison.

The `missing` rows are the pre-existing raw-finding population of this corpus at both commits;
they are unchanged by milestone 1 and are not triaged here. This document is an invariance
proof, not a defect audit.

## How "identical" was checked

Two comparisons, both over the completed JSONL records.

1. Census projection: corpus language, repo slug, repo head, repo dirtiness, status,
   run fingerprint, every summary counter (`eligible_files`, `audited_files`, `source_bytes`,
   `structured_candidates`, `sampled_sites`, `declaration_sites_excluded`, the whole
   `forward` status object, `distinct_targets`, `queried_targets`, `skipped_targets`,
   `target_truncated_sites`, the whole `classifications` object) and the `file_errors` count.
   `diff` reports no difference; both projections hash to
   `933716bd112659828163626e3b177c5c26760e25839f80d4724a33af6e813a54`.

2. Full record content: every record with `bifrost_head`, `bifrost_version` and
   `elapsed_seconds` removed and keys sorted. This includes `report.config`,
   `report.sites` (every sampled site's forward status, resolved targets, note,
   diagnostics and inverse hit) and `report.file_errors`. `diff` reports no difference;
   both hash to `f97e1242789f186cd7c41a5b98e0ab68d1e442a764f11929a45d9521f4f032e5`.

So the invariance claim is not merely counter-level: no individual site changed its
forward resolution, its target group, or its classification.

## Wall-clock

Timing is informational; the acceptance criterion is content, not speed.

| Leg | Corpus wall-clock | Release build |
| --- | --- | --- |
| Baseline `508b0737` | 125.23 s | 5 m 13 s (cold target) |
| Candidate `74bf60a3` | 125.46 s | 3 m 57 s (warm target) |

Per repository (baseline s / candidate s): c 1.99 / 1.95, cpp 47.82 / 49.00, csharp 3.58 /
3.86, go 1.34 / 1.46, java 0.76 / 0.70, js 0.81 / 0.78, php 0.53 / 0.53, py 0.58 / 0.57,
rust 4.15 / 4.40, scala 60.78 / 59.56, ts 1.46 / 1.20. The two builds ran into the same
worktree target directory sequentially, so the build times are not comparable to each other.

## Unrelated pre-existing finding: `dtolnay__anyhow` aborts the runner

The first corpus attempt used `dtolnay__anyhow` (head
`5bdb0e24db3994be119d42f18fe2d655e1f68f4a`) for the rust slot. The runner panics during the
Rust workspace build and the panic propagates out of the scoped thread, killing the whole
`run-corpus` process at repository 9 of 11:

```
thread '<unnamed>' panicked at crates/bifrost-analysis/src/analyzer/store/mod.rs:7605:13:
assertion `left == right` failed: path-derived package prefix must equal the CodeUnit's structured prefix
  left: FqName { segments: [SegmentId(7864)] }
 right: FqName { segments: [] }
thread 'bifrost-build-Rust' panicked at crates/bifrost-analysis/src/analyzer/tree_sitter_analyzer.rs:2447:9: a scoped thread panicked
thread 'main' panicked at src/bin/bifrost_reference_differential.rs:585:5: a scoped thread panicked
```

Reproduced with identical assertion text at **both** `508b0737` and `74bf60a3`, so it is not
a milestone-1 regression. The assertion is the one added by `f25cb966` ("Make CodeUnit
identity structurally authoritative") in `encode_unit_fq_segments`: the adapter's
`path_derived_package_fq` returns a one-segment prefix while the `CodeUnit`'s own
`package_fq()` is empty. Two separate concerns for whoever picks this up: the identity
mismatch itself, and the fact that one repository's analyzer panic takes down an entire
resumable corpus run instead of being recorded as that repository's `engine_error`.

Reproducer at either commit:

```bash
target/release/bifrost_reference_differential run-corpus \
  --clones-root /home/jonathan/Projects/brokkbench/clones \
  --commits-root /home/jonathan/Projects/brokkbench/sft-tools-commits \
  --language rust --repo dtolnay__anyhow \
  --repos-per-language 1 --repo-jobs 1 --jobs 8 \
  --cache-mode ephemeral --seed 0 --output /tmp/anyhow-probe.jsonl
```

## Raw artifacts

Kept outside the repository per the runbook, under
`/home/jonathan/Projects/brokkbench/reference-differential/` (the runbook's
`/mnt/optane/tmp/reference-differential` no longer exists on this host; the clone root has
moved to `/mnt/minasmorgul/repo-clones`).

| File | sha256 |
| --- | --- |
| `registry-m1-run-baseline-508b0737.jsonl.gz` | `e49359a407d0a0ab4ab877df5baccaa3e1bfa44a9069615219aa876bc13c8d2c` |
| `registry-m1-run-candidate-74bf60a3.jsonl.gz` | `0935e92a049b1f48c7dc61711aab99365f511d4ada5955336e4086eb49592e42` |
| `registry-m1-baseline-508b0737.census.tsv` | `933716bd112659828163626e3b177c5c26760e25839f80d4724a33af6e813a54` |
| `registry-m1-candidate-74bf60a3.census.tsv` | `933716bd112659828163626e3b177c5c26760e25839f80d4724a33af6e813a54` |
| `registry-m1-run-baseline-508b0737.log` | `a83f58f6d5a52a77d49f203af58df39179c9aeffda54d2ea1b2b8d42dc5a2942` |
| `registry-m1-run-candidate-74bf60a3.log` | `879e53c38fd76ac07f629327c921618174e77965ae35d2eae0d6c2b7d21fa450` |
| `registry-m1-probe-anyhow-508b0737.log` | `e3520908db83acde32691c096f718aa1d3ddba6f9b2020b04ec3ef92a47b6d2a` |
| `registry-m1-probe-anyhow-74bf60a3.log` | `c89269ff8c49c3daa2c27170106cae4f1f6443932357c7f701dc61d1ff8af4d7` |

Uncompressed run JSONL checksums (these differ, and must: each embeds its own
`bifrost_head` and per-repository `elapsed_seconds`): baseline
`3a5d3fe7eaffea490b3b4f6679fa60bf3aec65ff12bc4e63b86625166e5a9eb3`, candidate
`e71097eb23aa9ccd00d6030e900fe368c6b4ce600a7028e8a2b62ef622889303`.

## Scope of this evidence

This smoke covers the forward-definition and inverse-usage paths for eleven languages. It
does not cover Kotlin or Ruby, and — as the plan already states — it does not cover most of
the absent-capability behaviors (dead-code skips, receiver unsupported-reasons, policy
`unreliable` classification, MCP error strings, `Language::None` terminal outcomes). Those
remain the job of the inventory pins in
`.agents/docs/registry-preflight-absent-capability-inventory-2026-08.md`, and milestone 1
acceptance is not complete on this document alone.
