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

A dirty-tree exact runtime witness at `src/libraries/Common/src/Interop/Interop.Odbc.cs` bytes `818..825` completed the `Interop` inverse group in 34.1 seconds. It is a strict, consistent, exact-range one-site record with zero missing rows or file errors. The artifact is `/mnt/optane/tmp/reference-differential/csharp-954-runtime-interop-dirty-f7511c92.jsonl`, SHA-256 `b6a88c48c8b32a5969b5be28f491eb53059ecffe131b8a2e3cbc72505652dcf9`; Bifrost dirtiness makes it diagnostic.

The first clean rerun pins fixing commit `093b17cd76edaf2c67b3189fd0045262d0b4608b`, clean runtime `a0311b3485a8df84608d9aab82aa98e097c21948`, and release runner SHA-256 `9b879fa7d56a25cceee881abb1bdb466783e1d854a11dbcc9d2438cd8446461f`. Its single forward site resolves to the 1,219 physical declarations in the logical `Interop` group; inverse completes in 36.8 seconds and recovers bytes `818..825` exactly. The strict artifact has one consistent classification, zero missing or unproven rows, and zero file errors. Artifact: `/mnt/optane/tmp/reference-differential/csharp-954-runtime-interop-093b17cd.jsonl`; SHA-256 `aecfcaa16544e17645a9f0f4446757c08bcfceda1145618ce91e8d569a67abc4`. This evidence closed #954 provisionally, but the full-corpus rerun below exposed a residual hot path and the issue was reopened.

## Full-run residual

The clean raised-ceiling acceptance attempt at `25d05ef28a1c53d3f73d136d84255cb02bf279a0` completed Azure PowerShell, Azure SDK, and Mono with zero file errors and zero candidate-limit exclusions. Runtime completed all 756 forward files and 999 inverse groups in about 11 minutes, then the final `Interop` group remained CPU-active for more than 15 minutes. Only this C# process was interrupted; no runtime envelope was emitted. The first three envelopes remain diagnostic because the run did not reach all five repositories.

A 30-second live DWARF capture contains 2,000 samples with zero lost samples. It reports 77.29% self time in `__memcmp_evex_movbe`, with stable quicksort, `CodeUnit::cmp`, and `CSharpAnalyzer::namespace_of_file` frames. Artifact: `/tmp/csharp-interop-full-25d05ef2.perf.data`; SHA-256 `01cf565799a0a9ce6a1fe7d6fc4c43901052f8b2038cf9fd171e48dac0895455`.

The reference differential supplies an explicit audited-file provider for inverse queries, so default candidate discovery is not this caller. Graph resolution repeatedly asks for a candidate file's namespace. Global-namespace files have no stored package and `namespace_of_file` therefore materialized a sorted `BTreeSet<CodeUnit>` from `declarations(file)` on every lookup. The one-site proof touches a much narrower file scope than the full target group, which is why it did not expose the same wall-clock outlier.

The residual fix adds a weighted `ProjectFile -> namespace` cache to the C# analyzer generation. The first lookup retains the existing structured package/declaration semantics exactly; analyzer updates construct a fresh memo generation. All 97 C# usage graph tests pass. A dirty ephemeral exact proof at the same runtime bytes resolves the same 1,219 physical targets, completes inverse in 26.9 seconds, recovers the exact requested range, and reports one consistent site with zero missing/unproven rows or file errors. Artifact: `/tmp/reference-differential/csharp-954-runtime-interop-namespace-cache-dirty.jsonl`; SHA-256 `4ab090f3a51879b3169e3e15874753bdc651f5024562e37d8657c8f7c32dc9ac`. Release runner SHA-256: `b18c4d18c1c5750f8807a59a1aacb8f5b6f0ab08da4bfa65afe7412410ed7f22`. This record is diagnostic until the cache change is committed and repeated from a clean head.

The closure-grade ephemeral rerun pins clean fixing commit `cf8e7ff0935bc560d6572165c75dbca5ce70fe19`, clean runtime `a0311b3485a8df84608d9aab82aa98e097c21948`, and the same release runner SHA-256 `b18c4d18c1c5750f8807a59a1aacb8f5b6f0ab08da4bfa65afe7412410ed7f22`. Its inverse phase completes in 27.9 seconds and recovers bytes `818..825` exactly across the same 1,219 physical declarations. The record is completed and strict with one consistent classification, zero missing/unproven rows, zero diagnostics, and zero file errors. Artifact: `/tmp/reference-differential/csharp-954-runtime-interop-cf8e7ff0.jsonl`; SHA-256 `f01e3959814f8190e994aab4e5b8e846828841e408826130775314140169f9b3`.
