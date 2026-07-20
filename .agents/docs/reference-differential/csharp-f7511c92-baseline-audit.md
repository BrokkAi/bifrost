# C# f7511c92 diagnostic baseline and Interop profile

## Provenance

- Bifrost: clean `f7511c92cf3abce8ec94cfb64f143f4f9808baae`
- Release runner SHA-256: `1a3fa81fdaf482891e38acf42e654f4cf32da989149389f67e5d174f28b1a707`
- Partial artifact: `/mnt/optane/tmp/reference-differential/csharp-top5-f7511c92.jsonl`
- Partial artifact SHA-256: `840e9721b37cfa018b4ff5514773fad84058ca41e74237c30de684752c0a60b6`
- Log: `/mnt/optane/tmp/reference-differential/csharp-top5-f7511c92.log`
- Log SHA-256: `90e540ae462e43609df3344bae1a86625da6611de80b652aa34fb4b360c65ad1`

The canonical run used one active repository, eight inner workers, persisted cache mode, strict reporting, 1,000 files, 10,000 sites, 50,000 candidates per file, 4 MiB source files, 1,000 inverse targets, 1,000 usage files, 100,000 usages, and seed zero. It is diagnostic rather than accepting: three repository envelopes completed, four sampled files exceeded the candidate ceiling, runtime was intentionally interrupted while profiling a pathological final inverse target, and Roslyn did not start.

## Completed envelopes

All three envelopes pin clean Bifrost and repository trees, completed status, the expected repository heads, 10,000 sampled sites, and 1,000 queried inverse targets.

- Azure PowerShell `409b39eb8c26`: 1,871.7 seconds, zero missing rows, and one candidate-limit file, `generated/SecurityInsights/SecurityInsights.Autorest/generated/api/SecurityInsights.cs`.
- Azure SDK for .NET `a54cb128cf3d`: 2,202.7 seconds, 27 missing rows, and three candidate-limit files: `sdk/networkcloud/Azure.ResourceManager.NetworkCloud/api/Azure.ResourceManager.NetworkCloud.net8.0.cs`, `sdk/oracle/Azure.ResourceManager.OracleDatabase/api/Azure.ResourceManager.OracleDatabase.net10.0.cs`, and `sdk/websites/Azure.ResourceManager.AppService/src/Generated/RestOperations/WebAppsRestOperations.cs`.
- Mono `0f53e9e151d9`: 358.7 seconds, 37 missing rows, and no file errors or candidate exclusions.

The 27 Azure SDK rows match the previously exhaustively audited count, but the current byte ranges and identities still require final-head verification. Mono's 37 rows are fewer than the earlier pre-fix baseline and likewise require a fresh exhaustive ledger. None of these envelopes can be accepted while four sampled files are excluded.

The excluded files range from 887,849 to 3,258,662 bytes and are below the configured 4 MiB source ceiling. The 50,000-candidate ceiling is therefore the limiting configuration rather than source eligibility. The clean acceptance rerun will raise the C# candidate ceiling uniformly to 250,000 and retain every other corpus bound.

## Runtime blocker and profile

Runtime completed all 756 forward files, resolved 4,668 sites to 2,737 distinct targets, and completed 999 of 1,000 inverse groups. The last group was `Interop`, started at repository elapsed 543.3 seconds. It remained CPU-active for more than 20 minutes at about 126-128% CPU and 4.1 GiB RSS before the diagnostic process was intentionally interrupted. No runtime envelope was written, and Roslyn did not start.

Two read-only `perf` captures sampled only the C# process:

- Frame-pointer capture: `/tmp/csharp-interop-f7511c92.perf.data`, 2,960 samples, zero lost, SHA-256 `96a55368181b4bb651001bf6a730053f25b944ef759c95fdcf7c523076bd1bdf`.
- DWARF capture: `/tmp/csharp-interop-f7511c92-dwarf.perf.data`, 1,570 samples, zero lost, SHA-256 `ed94a024508bc05c649579a2f36aa3a8a6c6d2855f3fdc82c3b034e9d4c991ce`.

The DWARF sample reports 79.8% self time in `memcmp`, 55.4% below stable quicksort, 16.7% in `CodeUnit::cmp`, and visible `CSharpAnalyzer::namespace_of_file` frames. This is not the SQLite short-name fanout fixed by #945. `compute_implicit_reference_index` collapsed each candidate file to one namespace and called `namespace_of_file`; files without one stored package materialized and ordered the complete declaration set. The same single-namespace model also omitted valid references from later namespaces in one physical file.

## Issue 954

Issue #954 is solely assigned to `jbellis`. The persisted `InlineTestProject` regression `csharp_default_candidates_cover_each_namespace_declared_in_one_file` failed before the fix because `referencing_files_of` returned an empty set for an unqualified type reference in the second namespace of one source file.

The fix enumerates analyzed files once, derives every distinct namespace from the existing top-level declaration projection, and uses a nested namespace/name index with borrowed lookups. It removes the all-declarations ordering fallback from the parallel implicit-index build and preserves global-namespace handling without source parsing.

The focused regression, all 97 targeted C# usage tests, all 31 whole-workspace C# graph tests, 11 C# analyzer tests, six persisted C# cache tests, 505 feature-enabled definition tests, formatting, diff hygiene, and isolated all-target/all-feature Clippy pass.

A dirty-tree exact runtime witness at `src/libraries/Common/src/Interop/Interop.Odbc.cs` bytes `818..825` completed the `Interop` inverse group in 34.1 seconds. It is a strict, consistent, exact-range one-site record with zero missing rows or file errors. The artifact is `/mnt/optane/tmp/reference-differential/csharp-954-runtime-interop-dirty-f7511c92.jsonl`, SHA-256 `b6a88c48c8b32a5969b5be28f491eb53059ecffe131b8a2e3cbc72505652dcf9`; Bifrost dirtiness makes it diagnostic. A clean fixing-head rebuild and exact rerun are required before closing #954 and restarting the full C# leg.
