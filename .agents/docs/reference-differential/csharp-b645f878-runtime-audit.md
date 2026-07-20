# C# dotnet/runtime b645f878 differential audit

## Provenance

- Bifrost: `b645f878fb5b4c41423513eb1dd1d04d904d849c`
- Release runner SHA-256: `762e44781b26f7215d4e901d795f26340094c6d8415e793d559b2d18366135b7`
- Repository: `dotnet__runtime` at `a0311b3485a8df84608d9aab82aa98e097c21948`
- Full artifact: `/mnt/optane/tmp/reference-differential/csharp-runtime-b645f878.jsonl`
- Full artifact SHA-256: `8017c1ccde9b279b10fae852828c801f1857f816502638a319a418f9f09b78fe`
- Log SHA-256: `4649d3bc721d8a7c8345409e497db5a2bbe842b3a879e958a0312f2c25a07248`
- Exact artifact: `/mnt/optane/tmp/reference-differential/csharp-runtime-exact-b645f878.jsonl`
- Exact artifact SHA-256: `a5251fda0c3403751d500d64b6140cae10d4f69e3d1ab8505478a0029336ffd6`

Both artifacts report clean Bifrost and repository trees, completed records, the pinned heads above, and no file errors. The full run audited 1,000 of 15,449 eligible files, sampled 10,000 sites, resolved 6,049 forward sites to 2,528 distinct targets, queried the configured 1,000 target groups, and reported 174 missing rows. The run completed in 495.9 seconds. The former two-hour outlier was identified as `Interop` and completed in 63.5 seconds; the other 999 groups completed within 10.4 seconds of inverse start. Issue #945 is closed with this proof.

## Exhaustive disposition

The missing-row indices below refer to:

    .report.sites | map(select(.classification == "missing")) | to_entries

All 174 rows were checked against the pinned source bytes and tree-sitter role. All diagnostics arrays were empty.

### Genuine inverse gaps: 45

- Using-alias RHS type references, 4: `1,2,5,152`.
- Same/enclosing-owner field reads, 10: `3,8,9,10,11,12,141,147,148,151`.
- Nested/static type qualifiers, 7: `14,28,135,153,154,170,171`.
- Precisely typed receiver members, 7: `7,17,143,144,145,150,157`.
- Structured type roles, 13: `22,26,30,31,32,33,39,146,159,163,165,172,173`.
- Overloaded producer return inference for chained generic extensions, 3: `71,72,75`.
- Null-forgiving bare method group, 1: `164`.

The first five runtime groups recur under reopened assigned issues #701, #231, and #423. Mono additionally has the exact generic-constructor recurrence tracked by reopened assigned #726. The null-forgiving method group extends reopened assigned #737. The overload-return inference boundary is newly assigned #946.

Eight representative clean exact records reproduce one forward-resolved site, one queried target, one missing inverse result, and no file errors:

- Alias RHS: `CngHelpers.cs` bytes `317..335`.
- Same-owner field: `SqlUtils.cs` bytes `20714..20731`.
- Nested type qualifier: `GC_1.cs` bytes `8472..8479`.
- Typed receiver: `XmlSerializationWriterILGen.cs` bytes `24980..24987`.
- Pattern type: `RuntimeModuleBuilder.Mono.cs` bytes `26798..26822`.
- Ordinary interface parameter: `Parallel.cs` bytes `185521..185532`.
- Chained extension: `TensorPrimitives.DegreesToRadians.cs` bytes `2241..2243`.
- Null-forgiving method group: `VolatileEnlistmentMultiplexing.cs` bytes `4810..4824`.

### Nonactionable differential rows: 129

- Generic-parameter short-name false forwards, 104: slice A indices `0,18,19,20,21,23,24,25,34,35,36,37,38,40,41,42,43,44,45,46,47,48,49,51,52,53,54,55,56,57`; slice B `58..70,73,74,76..83,86..91,96,98..115`; slice C `116..134,149,155,156,158,160,161,162`.
- Other wrong forward receiver/member/type identities, 24: `4,6,13,15,27,29,50,84,85,92,93,94,95,97,136,137,138,139,140,142,166,167,168,169`.
- Declaration terminal rather than a reference, 1: `16` (`tuple_element` name `Id`).

These rows do not establish an inverse defect because the forward target is not the referenced declaration. Frequent examples include generic parameters `T`/`Tn` mapped to unrelated test classes, collection `Count` mapped to incompatible `MemoryExtensions.Count` overloads, generic `Vector<T>` mapped to nongeneric `Vector`, and `DataContract` qualifiers mapped to constructors.

## Root boundaries

- Type scanning recognizes only selected parent kinds and only a one-segment static receiver. It omits ordinary using-alias RHS, constant/is/switch patterns, and intermediate nested type owners.
- Self-member and typed-receiver paths still lose valid fields/methods when physical duplicate or partial targets participate in the query group.
- Constructor scanning loses generic owner identity for the Mono `new List<T>()` witnesses even though forward identity is arity-correct.
- `containing_argument_through_transparent_expressions` does not treat the null-forgiving postfix wrapper as transparent.
- Invocation return inference narrows overloads by value/generic arity but not structured argument types. Same-arity `Vector128` producers therefore yield several possible return types and make the chained `As<TFrom,TTo>` receiver unknown.
