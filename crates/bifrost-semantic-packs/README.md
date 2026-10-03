# brokk-bifrost-semantic-packs

This crate is the optional distribution companion for Bifrost's curated,
prebuilt semantic-model packs. Most applications should depend on
[`brokk-bifrost`](https://crates.io/crates/brokk-bifrost) instead.

The generic pack model, compiler, catalog, activation logic, and analyzer
overlays live in
[`brokk-bifrost-analysis`](https://crates.io/crates/brokk-bifrost-analysis).
Open semantic packs and policy rules are authored, generated, and released in
[Bifrost-packs](https://github.com/BrokkAi/bifrost-packs). This crate retains
engine-side compilation, verification, installation, and authoring tooling,
plus existing embedded content during the v0.13.0 transition. Analyzer consumers can omit it and
register their own packs.

Semantic-model packs describe API facts that are unavailable from workspace
source, declarative facts produced by frameworks or generators, and reviewed
external procedure behavior. They are versioned data artifacts: packs do not
contain executable code, and installing one does not implicitly select the
newest available content. Generic analysis, explicit catalog activation, and
direct consumers of this crate remain network-free. Host plugins acquire
compatible qualified releases into a persistent cache before runtime activation.

See the
[semantic-model pack documentation](https://github.com/BrokkAi/bifrost/blob/master/docs/src/content/docs/semantic-model-packs.md)
for the format, lifecycle, compatibility rules, and security boundaries.

## Cached open content

Engine releases retain semantic-pack tooling and no longer generate or publish
native semantic-pack content. Open content uses the independent rules and packs
streams in Bifrost-packs; its `pack-release.json` records exact source, artifact
hashes, compatibility, and qualification. A release version alone does not prove
that a pack applies to this engine or workspace.

The facade imports `BIFROST_OPEN_SEMANTIC_PACK_BUNDLE` into the host's catalog
through the existing native verifier and installer. Set
`BIFROST_SEMANTIC_PACK_CACHE_ROOT` to the host's persistent directory. Explicit
bundle configuration replaces embedded semantic registration, and a malformed
or incompatible installation fails explicitly. Embedded defaults remain when
no external bundle is configured. The facade no longer registers the legacy
engine-release downloader; hosts own public pack acquisition and offline reuse.

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
bifrost-semantic-pack csmi-check model.csmi.json --format json
bifrost-semantic-pack csmi-check pack-manifest.json
bifrost-semantic-pack compile pack.yaml compiled-pack
bifrost-semantic-pack workspace-check /path/to/workspace
bifrost-semantic-pack list /path/to/catalog activation.json --format json
```

Human output is the default. JSON reports use versioned format identifiers.
Invalid models and lint findings return status 1. Invalid arguments and
incomplete bounded operations return status 2.

`csmi-check` validates standalone CSMI documents directly. When the input is a
pack manifest, it also resolves the manifest's declared resources relative to
that file and verifies canonical bytes, sizes, and digests. Its report keeps
structural validity, semantic validity, integrity, and consumer-specific
interpretability separate. A conforming document can therefore exit
successfully while reporting that its required vocabulary is not interpretable
by this consumer.

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
