# Kotlin standard-library semantic pack measurement

Issue: #1481

Input: `org.jetbrains.kotlin:kotlin-stdlib:2.2.20` official sources JAR,
712,992 bytes, SHA-256
`27b9b8672ef33ae9c345b3e57d39b705560e7eca9ca2bf6485f323f612276c26`.

The debug release-bundle generator ran locally on 2026-08-03. The numbers are
observations, not release thresholds:

| Measurement | Value |
| --- | ---: |
| Generation | 1,178 ms |
| Activation | 94,170 us |
| Declaration records | 7,377 |
| Manifest | 569,966 bytes |
| Stored shard | 645,423 bytes |
| Raw shard | 5,337,227 bytes |
| Retained active overlay | 7,004,913 bytes |
| `kotlin.collections.List` cold / warm | 625 ns / 125 ns |
| `kotlin.collections.map` cold / warm | 1,542 ns / 792 ns |

Generation and subsequent bundle verification both succeeded. The pack is
explicitly partial: eight source entries use syntax that the repository's
pinned Kotlin grammar does not currently accept. Those entries are skipped
with bounded diagnostics; the producer does not recover declarations through
text scanning or JVM facade-name guesses. Representative collection types and
top-level extensions are present and were used for the lookup measurements;
the pack retains 15 `kotlin.collections.map` overload records.

The bundle was generated with:

    cargo run --locked --release --features release-tooling -p brokk-bifrost-semantic-packs --bin bifrost-semantic-pack -- generate <output> semantic-packs/jvm/kotlin-stdlib-2.2.20.json /private/tmp/kotlin-stdlib-2.2.20-sources.jar
    cargo run --locked --release --features release-tooling -p brokk-bifrost-semantic-packs --bin bifrost-semantic-pack -- verify <output>

The generation output is temporary and is not checked in. Release automation
repeats the same digest check, generation, and verification from the pinned
specification.
