# JVM standard-library semantic packs

This directory pins the source inputs used to build Bifrost's published JDK
and Scala standard-library declaration packs. Generated manifests and shards
are release assets; they are not checked into Git.

The Scala pack is source-semantic: it preserves authored declarations,
signatures, companions, traits, hierarchy, and source locators. It does not
invent compiler-generated case-class members such as `copy`. The JDK pack is
also source-derived and includes only packages exported without qualification
by each module descriptor. Unsupported advanced Java type shapes make the pack
honestly partial instead of producing guessed declarations.

## Regeneration

Download the exact artifacts named by the JSON specifications and verify both
their pinned file names and SHA-256 values. For the Temurin input, extract the
pinned `src.zip` path from the pinned outer archive and verify the inner digest
as well. Then run:

```console
cargo run --locked --release --features release-tooling -p brokk-bifrost-semantic-packs --bin bifrost-semantic-pack -- generate \
  /path/to/output \
  semantic-packs/jvm/temurin-jdk-21.0.8+9.json /path/to/src.zip \
  semantic-packs/jvm/scala-library-2.13.16.json /path/to/scala-library-2.13.16-sources.jar

cargo run --locked --release --features release-tooling -p brokk-bifrost-semantic-packs --bin bifrost-semantic-pack -- verify \
  /path/to/output
```

Generation performs no downloads. It refuses an artifact whose file name or
digest differs from the specification and refuses to replace a release asset
with different bytes.

The output contains a canonical `index.json`, content-addressed manifests and
shards, content-addressed notices, `measurements.json`, and `SHA256SUMS`.
Verification re-hashes and decodes every indexed asset and cross-checks the
index, compiled metadata, measurements, and checksum inventory. Measurements
record generation and activation time, stored/raw bytes, retained active-model
index bytes, and cold/warm representative lookup timings. Timing values are
observations; the canonical index, manifests, shards, notices, and checksum
inventory are deterministic for the same pinned inputs. The release workflow
publishes `measurements.json` as a separate CI artifact and excludes it from
the immutable GitHub Release archive so a retry can reproduce the archive
byte-for-byte.

After selecting and unpacking a compatible published bundle, a consumer can
verify and install it into a durable semantic-pack catalog explicitly:

```console
cargo run --release --features release-tooling -p brokk-bifrost-semantic-packs \
  --bin bifrost-semantic-pack -- install /path/to/bundle /path/to/catalog
```

Installation does not activate a pack by itself. Normal workspace evidence
still selects only compatible shards from the catalog.
