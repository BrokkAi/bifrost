# Semantic-pack catalog storage benchmark

This note records the retained storage decision for Bifrost issue #1146. It
compares exact compiler-emitted semantic-pack shard bytes stored in an SQLite
BLOB with the same bytes stored in a digest-addressed file referenced by
SQLite. Every measured read passes through `decode_shard_for_manifest`; the
benchmark does not substitute an unchecked byte read for catalog hydration.

## Decision

The production inline-shard threshold is **zero bytes**. Semantic-pack shard
payloads belong in the content-addressed file store. The catalog database keeps
manifest and indexed selector metadata, but it does not inline shard bytes.

The 8 KiB candidate failed the preregistered read gate. All three payloads below
that threshold passed the install-cost and total-storage gates, but two of the
three did not make verified cold reads at least ten percent faster:

- the 1,824-byte raw fixture improved from 0.399 ms to 0.349 ms, about 12.6%;
- the 952-byte DEFLATE shard improved from 0.416 ms to 0.391 ms, about 5.9%;
- the 4,921-byte DEFLATE shard improved from 0.645 ms to 0.611 ms, about 5.4%.

Because every payload at a candidate threshold must pass, 8 KiB and every
larger threshold are ineligible. This follows the plan's conservative rule:
missing or failing evidence selects zero rather than assuming that BLOB storage
will help.

## Environment and command

- Bifrost commit: `91357eecb7d528f674cf9845aacddeb280919388`
- Date: 2026-07-31
- OS/architecture: macOS/aarch64
- Rust: 1.96.0 (`ac68faa20`)
- SQLite: 3.46.0
- Samples: 9 independent installs and cold reads per cell, with 7 additional
  verified warm reads per install

The exact command was:

    scripts/with-isolated-cargo-target.sh cargo test --release \
      --test suite_semantic -- \
      measure_semantic_pack_catalog::measure_inline_and_file_storage \
      --ignored --exact --nocapture

The optimized build and test completed successfully. The isolated target was
removed automatically.

## Measurements

Times are milliseconds. Storage is the median total regular-file bytes in the
temporary catalog root after a WAL checkpoint.

| Encoding | Raw bytes | Stored bytes | Layout | Install p95 | Cold read median | Cold read p95 | Warm read median | Total bytes |
| --- | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| raw | 1,824 | 1,824 | inline | 1.859 | 0.349 | 0.599 | 0.345 | 8,192 |
| raw | 1,824 | 1,824 | file | 11.620 | 0.399 | 1.628 | 0.337 | 10,016 |
| deflate | 4,347 | 952 | inline | 0.805 | 0.391 | 0.405 | 0.347 | 8,192 |
| deflate | 4,347 | 952 | file | 7.302 | 0.416 | 0.598 | 0.318 | 9,144 |
| deflate | 30,079 | 4,921 | inline | 1.303 | 0.611 | 1.099 | 0.563 | 12,288 |
| deflate | 30,079 | 4,921 | file | 6.585 | 0.645 | 0.834 | 0.543 | 13,113 |
| deflate | 118,304 | 18,329 | inline | 0.819 | 1.250 | 1.747 | 1.201 | 28,672 |
| deflate | 118,304 | 18,329 | file | 8.172 | 1.188 | 1.273 | 1.192 | 30,617 |
| deflate | 235,936 | 36,076 | inline | 0.939 | 2.070 | 2.230 | 2.076 | 49,152 |
| deflate | 235,936 | 36,076 | file | 7.737 | 2.227 | 3.919 | 2.133 | 52,460 |
| deflate | 941,729 | 142,478 | inline | 1.436 | 7.945 | 8.649 | 7.872 | 180,224 |
| deflate | 941,729 | 142,478 | file | 8.602 | 7.785 | 9.042 | 7.726 | 179,342 |

The file layout pays a separate synchronized-file publication cost during
installation, but installation is not the hot path and the plan requires a
read improvement as well. At 18,329 and 142,478 stored bytes, file-backed cold
reads were already faster at the median. Warm medians were close at every size
and do not justify putting immutable payload growth into SQLite.

## Compression

The catalog must retain the compiler-selected encoding rather than recompress
objects. The automatically compressed generated shards reduced their stored
size by about 78% to 85%:

- 4,347 to 952 bytes;
- 30,079 to 4,921 bytes;
- 118,304 to 18,329 bytes;
- 235,936 to 36,076 bytes;
- 941,729 to 142,478 bytes.

The raw cell deliberately used `CompressionPolicy::AlwaysRaw` so both artifact
encodings exercised the storage comparison. This benchmark supports preserving
the existing compiler compression policy; it does not change that policy or
introduce a catalog compression layer.

## Reproduction and interpretation

The ignored test is
`tests/suite_semantic/measure_semantic_pack_catalog.rs`. It generates
deterministic declaration packs for the size sweep and uses the checked-in
declaration fixture for the raw cell. SQLite uses WAL and `synchronous=FULL`;
file objects are flushed with `sync_all` before metadata commit. Each install
uses a new temporary catalog and each read reopens SQLite, reads the BLOB or
file, and performs the same manifest-bound defensive decode.

These are microbenchmark results for the storage boundary, not end-to-end
analyzer latency. #1147 must separately measure generation-scoped candidate
selection and matcher hydration. The zero threshold remains correct unless a
future retained benchmark changes the workload and passes explicit promotion
gates.
