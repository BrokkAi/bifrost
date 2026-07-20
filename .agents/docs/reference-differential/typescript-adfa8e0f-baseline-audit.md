# TypeScript top-five baseline audit at `adfa8e0f`

This note records the prepared and, once the shared corpus slot is available, completed TypeScript baseline for the C#/Go/Java/JavaScript/TypeScript top-five reference-differential campaign. The operator contract is the canonical runbook at `/home/jonathan/Projects/bifrost/.agents/docs/reference-differential-runbook.md`; campaign-wide decisions remain in `.agents/plans/reference-differential-csharp-go-java-js-ts-top-five.md`.

## Prepared provenance

- Bifrost head: `adfa8e0f9d915f998f3f91ddbc36ab5ea0ae220f`
- Release runner SHA-256: `de662c0f4de22a8ff97f8ccf6b3600ec7c29735a3d7fb682997996143df6977e`
- Clone root: `/home/jonathan/Projects/brokkbench/clones` (resolves to `/mnt/T9/repo-clones`)
- Commit metadata root: `/home/jonathan/Projects/brokkbench/sft-tools-commits`
- Prepared output: `/mnt/optane/tmp/reference-differential/ts-top5-adfa8e0f.jsonl`
- Prepared log: `/mnt/optane/tmp/reference-differential/ts-top5-adfa8e0f.log`

The dry-run skipped 206 metadata members with missing or invalid `code_loc` and reported six higher-ranked metadata members with no canonical clone: `grafana__grafana`, `openclaw__openclaw`, `n8n-io__n8n`, `lobehub__lobehub`, `nocodb__nocodb`, and `expo__expo`. It then selected the following five valid clones in descending metadata LOC order.

| Rank | Repository | `code_loc` | Pinned and clone HEAD | Tracked TS-family files | Tracked clean | `.brokk` ignored |
| ---: | --- | ---: | --- | ---: | --- | --- |
| 1 | `elastic__kibana` | 9,622,097 | `3a186638c45f9cbeeaacb6ce4c05a7d242c9017e` | 93,610 | yes | yes |
| 2 | `elizaOS__eliza` | 4,454,072 | `03f8dcdcf9d069ab97a8db1488c322c5a2d06f07` | 19,978 | yes | yes |
| 3 | `kedacore__keda` | 3,933,397 | `875675ce5cd1d34772fe00a228a71b8bf05b3b43` | 0 | yes | yes |
| 4 | `NativeScript__NativeScript` | 2,788,269 | `d41dcd7a93b0b06afeb4f4d225678cc1d0e83a14` | 1,402 | yes | yes |
| 5 | `open-metadata__OpenMetadata` | 1,941,692 | `5e31ae5871a3de87196495bc71828ae0b92470b4` | 5,396 | yes | yes |

The tracked-file inventory counts `.ts`, `.tsx`, `.mts`, and `.cts` paths. KEDA is a valid canonical TypeScript metadata member with an empty current TypeScript frontier. Its eventual zero-site record is therefore a disclosed vacuous result, not grounds to substitute a hand-picked repository.

At preparation time no C# reference-differential process was visible, but two unrelated C++ persisted corpus processes were active. The TypeScript baseline was not launched: the delegated campaign contract requires an explicit report that the C# corpus process has finished before TypeScript takes the shared campaign slot.

## Accepted launch command

Run from `/mnt/optane/tmp/bifrost-burndown-3` after confirming that the C# process is gone and that these five clones remain at their pinned clean heads:

```bash
set -o pipefail
/usr/bin/time -v target/release/bifrost_reference_differential run-corpus \
  --clones-root /home/jonathan/Projects/brokkbench/clones \
  --commits-root /home/jonathan/Projects/brokkbench/sft-tools-commits \
  --language ts \
  --repos-per-language 5 \
  --repo-jobs 1 \
  --jobs 8 \
  --cache-mode persisted \
  --strict \
  --max-files 1000 \
  --max-sites 10000 \
  --max-candidates-per-file 50000 \
  --max-source-bytes 4194304 \
  --max-targets 1000 \
  --max-usage-files 1000 \
  --max-usages 100000 \
  --seed 0 \
  --output /mnt/optane/tmp/reference-differential/ts-top5-adfa8e0f.jsonl \
  2>&1 | tee -a /mnt/optane/tmp/reference-differential/ts-top5-adfa8e0f.log
```

Strict exit status 2 is expected if the baseline contains raw actionable rows. Acceptance requires five completed pinned-head records, identical configuration fingerprints, clean Bifrost and repository flags, no truncation, no file errors, exhaustive residual classification, and exact ephemeral reruns for suspicious rows.

## Run integrity and residual audit

Pending the C# corpus-slot handoff.
