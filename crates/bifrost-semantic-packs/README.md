# brokk-bifrost-semantic-packs

This crate is the optional distribution companion for Bifrost's curated,
prebuilt semantic-model packs. Most applications should depend on
[`brokk-bifrost`](https://crates.io/crates/brokk-bifrost) instead.

The generic pack model, compiler, catalog, activation logic, and analyzer
overlays live in
[`brokk-bifrost-analysis`](https://crates.io/crates/brokk-bifrost-analysis).
This crate is reserved for reviewed content shipped by Bifrost and the tooling
used to build and distribute that content. Analyzer consumers can omit it and
register their own packs.

Semantic-model packs describe API facts that are unavailable from workspace
source, declarative facts produced by frameworks or generators, and reviewed
external procedure behavior. They are versioned data artifacts: packs do not
contain executable code, and installing one does not implicitly select the
newest available content. Generic analysis, explicit catalog activation, and
direct consumers of this crate remain network-free; the released
`brokk-bifrost` facade has a separate exact-production acquisition path.

See the
[semantic-model pack documentation](https://github.com/BrokkAi/bifrost/blob/master/docs/src/content/docs/semantic-model-packs.md)
for the format, lifecycle, compatibility rules, and security boundaries.

## Facade release-bundle acquisition

The published `brokk-bifrost` facade opts into an acquisition provider for an
exact generated dependency production. After a locked catalog miss, it checks
only the matching public release for the running Bifrost version: the
`bifrost-semantic-packs-vX.Y.Z.tar.gz` asset and its `.sha256` sidecar from the
`BrokkAi/bifrost` release tagged `vX.Y.Z`. It verifies the archive checksum,
safely extracts it, verifies the release index and inner manifest and shard
checksums, and installs the requested production only when its exact
`GeneratedProductionKey` matches (input digest, producer name and version,
semantic schema version, and generated-production cache version).

It does not consult a mutable branch, package index, or third-party source. A
missing or invalid bundle, or any provider failure, becomes a warning and the
normal local generation path remains the fallback. Set
`BIFROST_SEMANTIC_PACK_DOWNLOAD=off` to disable this facade acquisition path;
the unset/default value enables it. Dependency discovery still does not
download package artifacts.

## Version 0.8.18

Version 0.8.18 is a bootstrap release that reserves the package name and
establishes crates.io trusted publishing. It intentionally contains no bundled
semantic-pack content or public pack API. Functional distribution support is
available beginning with Bifrost 0.8.19.

## Version 0.8.19

Version 0.8.19 adds the opt-in `release-tooling` feature and the
`bifrost-semantic-pack` binary used by Bifrost's release workflow to generate
and verify pinned JVM semantic-pack bundles. Ordinary consumers keep the
feature disabled and do not compile the packaging dependencies.

## Embedded registry

The crate exposes `EmbeddedSemanticPack` and `EmbeddedPackRegistry` for
reviewed Bifrost content. Registration is explicit. The registry validates all
artifacts before it changes the target catalog. It returns ordered source IDs
and manifest digests for deterministic provenance.

`BIFROST_EMBEDDED_PACKS` is the production registry. Generic analyzer clients
can omit this crate and register their own packs with
`brokk-bifrost-analysis`.

## Authoring commands

The same binary validates, lints, and compiles reviewed YAML or JSON through
the production semantic-model compiler:

```text
bifrost-semantic-pack validate pack.yaml --format json
bifrost-semantic-pack lint pack.yaml
bifrost-semantic-pack compile pack.yaml compiled-pack
bifrost-semantic-pack workspace-check /path/to/workspace
bifrost-semantic-pack list /path/to/catalog activation.json --format json
```

Human output is the default. JSON reports use versioned format identifiers.
Invalid models and lint findings return status 1. Invalid arguments and
incomplete bounded operations return status 2.

Workspace rules are opt-in direct files under `.bifrost/semantic-models/`.
Discovery rejects links and path escape. It reports an exact content hash for
review. It does not load code or activate a rule by itself.

## Procedure-summary corpus translation

The `release-tooling` feature also carries the procedure-summary model foundry
(#1871). It translates external procedure-model corpora into the authored
procedure-summary IR, compiles every translated entry back through the
production pack compiler, and joins the corpora into one deterministic report:

```text
scripts/public/fetch-pinned-summary-corpora.sh /path/to/work-dir
bifrost-semantic-pack summary-corpus-join PINS CODEQL_MODELS JOERN_SOURCE report.json
```

`semantic-packs/summary-corpora/pins.json` is the single source of truth for
the upstream, revision, archive checksum, and license of each corpus. The
corpora are third-party content and are not vendored here. The report records
each corpus's revision and a digest of the exact bytes read, every row the
translator could not carry and why, and each target the corpora agree on,
dispute, or cover alone. Two runs over the same pins produce the same bytes.
