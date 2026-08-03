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
newest available content or download anything at runtime.

See the
[semantic-model pack documentation](https://github.com/BrokkAi/bifrost/blob/master/docs/src/content/docs/semantic-model-packs.md)
for the format, lifecycle, compatibility rules, and security boundaries.

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
