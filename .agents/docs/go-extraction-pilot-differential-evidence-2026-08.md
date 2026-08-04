# Go extraction pilot: reference-differential invariance evidence (2026-08-04)

Acceptance evidence for `.agents/plans/analysis-go-extraction-pilot.md`, milestone P2 item 2
("Reference-differential smoke: identical divergence census on the 11-repo corpus (includes
jellydator/ttlcache for Go) between the pre-P0 commit and P1 tip").

This campaign deliberately reuses the corpus, pins, flags and comparison method of
`.agents/docs/registry-milestone1-differential-evidence-2026-08.md` so the two audits are
directly comparable.

**Verdict: PASS -- IDENTICAL.** The eleven-language census is byte-identical between the
pre-P0 baseline and the P1 tip candidate, and so is the full per-site record payload once run
provenance and timing are removed. The additional Go-only, tests-included pass (2.7x denser on
`jellydator__ttlcache`) is likewise byte-identical on both projections. Extracting Go into
`brokk-bifrost-go` produced no observable behavior change on this corpus.

## Commits compared

| Role | Commit | Subject |
| --- | --- | --- |
| Baseline | `adb2c42d142b755aa0e203c4c28f2b7d7c023553` | Stage-3 pilot ExecPlan: extract Go onto analysis-owned shims |
| Candidate | `87625563f56fe61471c29710f0247e8766125087` | P1.4: wire brokk-bifrost-go into the workspace gates and the release DAG |

`adb2c42d` is the pilot ExecPlan commit itself (doc-only), so it is the true pre-P0 tip: the
next commit is the first P0 lowering. The comparison therefore spans the whole pilot, P0.1
through P1.4:

```
4f913fd9 P0.1-2: lower the usages product types and the pure resolution helpers into core
4a99644e P0.3-4: split inverted_edges along the analyzer boundary and lower UsageScanScope
3434d692 P0.5: promote the pure analyzer helpers into core
087a0bac P1.1: create brokk-bifrost-go and move the core-clean Go language knowledge
edd0924b P1.2: move Go's type hierarchy and import resolution into brokk-bifrost-go
c520ffdb P1.3: move the Go usage graph's language half into brokk-bifrost-go
87625563 P1.4: wire brokk-bifrost-go into the workspace gates and the release DAG
```

Every commit in the range is pilot work; there is no upstream churn in it. Both runs recorded
`bifrost_dirty = false` for every repository.

## Corpus

The same eleven pinned clones as the registry milestone 1 audit, one per corpus language.
Clones root `/home/jonathan/Projects/brokkbench/clones`, commits root
`/home/jonathan/Projects/brokkbench/sft-tools-commits`. All eleven were verified clean
(`git status --porcelain` empty) immediately before the campaign, and every head matched the
pin recorded in the milestone 1 document:

| Corpus language | Repository slug | Pinned clone head |
| --- | --- | --- |
| c | `ggreer__the_silver_searcher` | `a61f1780b64266587e7bc30f0f5f71c6cca97c0f` |
| cpp | `gabime__spdlog` | `8671ca4d492c8ee1cdfd3dd88afb9f88dd268178` |
| csharp | `khellang__Scrutor` | `7f315dab5b0f7134a6be58941db1da8c904507e2` |
| go | `jellydator__ttlcache` | `db85e4f64251c73b33ba055e3fe07d70870992ce` |
| java | `semver4j__semver4j` | `751b5f5fba3ac3a7eafa758b95a22eaf3d3c5dfb` |
| js | `ging__fiware-pep-proxy` | `475474ad47de7dd46fb40473ed3b1db420c1181a` |
| php | `symfony__property-access` | `9261ef060f26cc7b728f67f141ba19b98a6209a9` |
| py | `Suor__funcy` | `9eb04473e31b6b60bd459e4dda24f6b1db5a3773` |
| rust | `XAMPPRocky__tokei` | `fa44e5194060305576514d59b850353643afbfc8` |
| scala | `typelevel__scalacheck` | `3b1e58f6f06cd540bd9acda7794c5fc51665866f` |
| ts | `xurei__restgoose` | `43cd725534e8ea83936b052f4c97f3b020c30200` |

`dtolnay__anyhow` remains excluded from the rust slot. It still aborts the whole `run-corpus`
process on the `path-derived package prefix must equal the CodeUnit's structured prefix` assert
in `analyzer/store/mod.rs`; that is a pre-existing, non-pilot defect owned by issues #1595 and
#1596, and `XAMPPRocky__tokei` stands in for rust as it did in the milestone 1 audit. Kotlin has
no membership directory under the commits root and Ruby is not a corpus language, so neither is
covered here.

## Commands

Identical at both commits except the runner binary and the output path. Each binary was a fresh
**featureless** release build of its own commit; `nlp` is not needed (the `reference_differential`
module is not feature-gated), and both `target/release` trees were checked to contain zero
`tokenizers` / `hf-hub` / `fastrq` artifacts.

```bash
cargo build --release --bin bifrost_reference_differential
```

Leg 1, the eleven-language corpus:

```bash
target/release/bifrost_reference_differential run-corpus \
  --clones-root /home/jonathan/Projects/brokkbench/clones \
  --commits-root /home/jonathan/Projects/brokkbench/sft-tools-commits \
  --language c --language cpp --language csharp --language go --language java \
  --language js --language php --language py --language rust --language scala --language ts \
  --repo ggreer__the_silver_searcher --repo gabime__spdlog --repo khellang__Scrutor \
  --repo jellydator__ttlcache --repo semver4j__semver4j --repo ging__fiware-pep-proxy \
  --repo symfony__property-access --repo Suor__funcy --repo XAMPPRocky__tokei \
  --repo typelevel__scalacheck --repo xurei__restgoose \
  --repos-per-language 1 --repo-jobs 1 --jobs 8 \
  --cache-mode ephemeral --seed 0 --output RUN.jsonl
```

Leg 2, the Go-focused denser pass (P2 item 4):

```bash
target/release/bifrost_reference_differential run-corpus \
  --clones-root /home/jonathan/Projects/brokkbench/clones \
  --commits-root /home/jonathan/Projects/brokkbench/sft-tools-commits \
  --language go --repo jellydator__ttlcache \
  --repos-per-language 1 --repo-jobs 1 --jobs 8 \
  --include-tests \
  --cache-mode ephemeral --seed 0 --output GO.jsonl
```

`--include-tests` is the only flag that differs from leg 1, and it is what makes leg 2 a denser
sample rather than a duplicate: `jellydator__ttlcache` has 13 eligible non-test files and hits
none of the runner's sampling caps in leg 1, so a Go-only run at the leg-1 flags would have
reproduced the leg-1 record exactly. With tests included the repository contributes 18 audited
files and 8239 sampled sites against leg 1's 13 and 3085 -- 2.7x the Go site population, and it
exercises the Go table-test idioms (subtests, closures over `*testing.T`, `require`-style helper
chains) that the non-test half never reaches.

All other engine budgets were the runner defaults (`--max-files 1000`, `--max-sites 10000`,
`--max-candidates-per-file 50000`, `--max-source-bytes 4194304`, `--max-targets 1000`,
`--max-usage-files 1000`, `--max-usages 100000`). `--strict` was deliberately omitted so the exit
code did not depend on raw findings; all four runs exited 0, with 11/11 and 1/1 completed
repository records respectively. `--repo-jobs 1` makes JSONL record order deterministic, and
`--cache-mode ephemeral` keeps the clone caches untouched per CLAUDE.md.

Runner checksums: baseline `08bff3d58863cd804d55ec8d17355c356f4ac1e77e5bbd267928c84f5533858d`,
candidate `d7c7997c0814df2aeafd75e0afaed839b7471c02acede9906290f38463232f2f`. The eleven
per-language `run_fingerprint` values (and the Go leg's single one,
`87c26f7539d8fd8f10f7c0ef285aacf4f4f6cbc340b977377353e77b5da1097e`) are pairwise equal between
the legs, so each pair audited the same configuration.

## Leg 1: the divergence census (identical at both commits)

Per repository: sampled sites, then the five classification counts.

| Language | Repository | sampled | consistent | editor_only | unproven | inconclusive | missing |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| c | `ggreer__the_silver_searcher` | 6494 | 1343 | 0 | 10 | 5141 | 0 |
| cpp | `gabime__spdlog` | 10000 | 1159 | 82 | 96 | 8639 | 24 |
| csharp | `khellang__Scrutor` | 3959 | 701 | 92 | 36 | 3130 | 0 |
| go | `jellydator__ttlcache` | 3085 | 311 | 263 | 9 | 2434 | 68 |
| java | `semver4j__semver4j` | 3291 | 637 | 125 | 0 | 2528 | 1 |
| js | `ging__fiware-pep-proxy` | 2837 | 499 | 0 | 0 | 2338 | 0 |
| php | `symfony__property-access` | 1946 | 131 | 238 | 0 | 1577 | 0 |
| py | `Suor__funcy` | 3922 | 346 | 39 | 0 | 3537 | 0 |
| rust | `XAMPPRocky__tokei` | 7540 | 802 | 110 | 0 | 6607 | 21 |
| scala | `typelevel__scalacheck` | 10000 | 1307 | 159 | 0 | 8493 | 41 |
| ts | `xurei__restgoose` | 3432 | 581 | 9 | 0 | 2842 | 0 |

Totals: 56506 sampled sites, 7817 consistent, 1117 editor_only, 151 unproven, 47266
inconclusive, 155 missing. Zero `file_errors` across all eleven repositories, and no
`target_truncated_sites`, `skipped_targets` or `candidate_limit_exceeded_files` distortion.
Two repositories, cpp `gabime__spdlog` and scala `typelevel__scalacheck`, sit exactly on the
default `--max-sites 10000` cap; the cap is deterministic and seeded and applies identically to
both legs, so it narrows the audit's reach on those two but not the comparison.

Ten of the eleven rows are identical to the milestone 1 audit two days ago; `gabime__spdlog` is
not (it read 1069/84/77/8711/59 there, 1159/82/96/8639/24 here). That drift is upstream C++ work
landed between the two campaigns, not pilot work: it is present in *both* of this campaign's
legs, which are byte-identical to each other. It is recorded only so the two documents can be
read side by side without confusion.

The `missing` rows are the corpus's pre-existing raw-finding population at both commits. They
are unchanged by the pilot and are not triaged here; this document is an invariance proof, not a
defect audit.

## Leg 2: the Go-focused denser pass (identical at both commits)

`jellydator__ttlcache`, `--include-tests`, one repository:

| metric | value (both commits) |
| --- | ---: |
| audited files | 18 |
| sampled sites | 8239 |
| forward resolved | 4711 |
| forward no_definition | 1978 |
| forward unresolvable_import_boundary | 1550 |
| forward ambiguous / unsupported_language / invalid_location / not_found | 0 / 0 / 0 / 0 |
| distinct inverse targets | 172 |
| consistent | 1162 |
| editor_only | 263 |
| unproven | 61 |
| inconclusive | 6685 |
| missing | 68 |
| file_errors | 0 |

Every one of those 8239 Go sites has the same forward status, the same resolved target set, the
same note and diagnostics, and the same inverse classification at `adb2c42d` and `87625563`.

## How "identical" was checked

Two comparisons per leg, both over the completed JSONL records, exactly as in the milestone 1
audit.

1. **Census projection**: corpus language, repo slug, repo head, repo dirtiness, status, run
   fingerprint, every summary counter (`eligible_files`, `audited_files`, `source_bytes`,
   `structured_candidates`, `sampled_sites`, `declaration_sites_excluded`, the whole `forward`
   status object, `distinct_targets`, `queried_targets`, `skipped_targets`,
   `target_truncated_sites`, the whole `classifications` object) and the `file_errors` count.

2. **Full record content**: every record with `bifrost_head`, `bifrost_version` and
   `elapsed_seconds` removed and keys sorted recursively. This includes `report.config`,
   `report.sites` (every sampled site's forward status, resolved targets, note, diagnostics and
   inverse hit) and `report.file_errors`.

`diff` reports no difference on any of the four comparisons:

| Leg | Projection | Baseline `adb2c42d` | Candidate `87625563` | Verdict |
| --- | --- | --- | --- | --- |
| corpus (11 repos) | census | `2b26c933120de18c066c86b8ed8b846eee4dc81a0cfa1d6686db1a0826fbe557` | `2b26c933120de18c066c86b8ed8b846eee4dc81a0cfa1d6686db1a0826fbe557` | equal |
| corpus (11 repos) | full payload | `32e1485af340e1e6f334bf275580e58e4cb488adb63c29f3fdecaa6a5f643b0e` | `32e1485af340e1e6f334bf275580e58e4cb488adb63c29f3fdecaa6a5f643b0e` | equal |
| go (`--include-tests`) | census | `e99199c562127fb8513a09025a948d9f38e422ddaed4c1721462ecf8bbd7e6a1` | `e99199c562127fb8513a09025a948d9f38e422ddaed4c1721462ecf8bbd7e6a1` | equal |
| go (`--include-tests`) | full payload | `0f7e932a739e76211d636a990c66be560ca89cc92b9ced0a0638ddd471925195` | `0f7e932a739e76211d636a990c66be560ca89cc92b9ced0a0638ddd471925195` | equal |

The hashes are not comparable to the milestone 1 document's: this campaign emits the projections
with a compact one-record-per-line serialization rather than that document's, so only the
within-campaign baseline/candidate equality is meaningful.

So the invariance claim is not merely counter-level: no individual site changed its forward
resolution, its target group, or its classification, in Go or in any other language.

## Wall-clock

Timing is informational; the acceptance criterion is content, not speed.

| Leg | Baseline `adb2c42d` | Candidate `87625563` |
| --- | ---: | ---: |
| corpus run (11 repos) | 140.34 s | 134.12 s |
| go run (`--include-tests`) | 4.32 s | 4.31 s |
| release build | 302.69 s (cold target) | 219.31 s (warm target) |

Per repository in leg 1 (baseline s / candidate s): c 2.02 / 1.96, cpp 65.29 / 57.96, csharp
3.80 / 3.54, go 1.51 / 1.40, java 0.82 / 0.72, js 1.00 / 0.80, php 0.65 / 0.58, py 0.70 / 0.56,
rust 4.40 / 4.34, scala 57.27 / 59.55, ts 1.15 / 1.03. The two builds ran sequentially into the
same worktree target directory, so the build times are not comparable to each other and are not
evidence for or against P2 item 1's compile-time claim -- that is measured separately with
`--timings` in an isolated target.

## Raw artifacts

Kept outside the repository per the runbook, under
`/home/jonathan/Projects/brokkbench/reference-differential/`.

| File | sha256 |
| --- | --- |
| `gopilot-run-baseline-adb2c42d.jsonl.gz` | `1487afac8e1932e3fe717e8878f883398c01342846db46880f4a41970221ccab` |
| `gopilot-run-candidate-87625563.jsonl.gz` | `7f46b2938f2fd423cadcf4f1e93de6af52ba9d095930cb81dd152993bbf8ae97` |
| `gopilot-go-baseline-adb2c42d.jsonl.gz` | `82e6e08ae15e028cdae08beafb588c6d3d3781374fb3830dc229c0ba9cd4c644` |
| `gopilot-go-candidate-87625563.jsonl.gz` | `86a132b27487b378f5295bba29693b06463b1c434dbdc0806475336bf45c4d35` |
| `gopilot-corpus-baseline-adb2c42d.census.tsv` | `2b26c933120de18c066c86b8ed8b846eee4dc81a0cfa1d6686db1a0826fbe557` |
| `gopilot-corpus-candidate-87625563.census.tsv` | `2b26c933120de18c066c86b8ed8b846eee4dc81a0cfa1d6686db1a0826fbe557` |
| `gopilot-go-baseline-adb2c42d.census.tsv` | `e99199c562127fb8513a09025a948d9f38e422ddaed4c1721462ecf8bbd7e6a1` |
| `gopilot-go-candidate-87625563.census.tsv` | `e99199c562127fb8513a09025a948d9f38e422ddaed4c1721462ecf8bbd7e6a1` |
| `gopilot-run-baseline-adb2c42d.log` | `317c600acbc9da141bbbd945511ae2d51a80f10fb6f2ce30f5b61f4c82aa521c` |
| `gopilot-run-candidate-87625563.log` | `4a6dfb346eb7830c06d79ade37ea02c24ff144df56907e20321a83a538041f0f` |
| `gopilot-go-baseline-adb2c42d.log` | `64d84db9acbb35c2f3daa8528eb15d59abc6e5249924e492bcabf1da09fe6606` |
| `gopilot-go-candidate-87625563.log` | `a943b5dc31223c766f2e24df8eba2195f2bf591fe7adc281610f888b912e9592` |

The compressed run JSONL checksums differ within each pair, and must: each embeds its own
`bifrost_head` and per-repository `elapsed_seconds`. The equality claim is the payload row of the
comparison table above, not these.

## Scope of this evidence

This smoke covers the forward-definition and inverse-usage paths for eleven languages, with Go
sampled twice and at 2.7x density the second time. It satisfies P2 item 2 of the pilot plan and
nothing more. It does not cover Kotlin or Ruby; it does not cover the absent-capability
behaviors (dead-code skips, receiver unsupported-reasons, policy `unreliable` classification,
MCP error strings, `Language::None` terminal outcomes), which remain the job of the inventory
pins in `.agents/docs/registry-preflight-absent-capability-inventory-2026-08.md`; and it says
nothing about P2 items 1 and 3, the compile-time measurement and the shim-size budget. The
pilot's PASS verdict needs those alongside this document.
