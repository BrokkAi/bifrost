# brokk-bifrost-semantic

Shared executable-semantics vocabulary, pure algorithms, and semantic-model
artifact contracts for Bifrost. The analysis engine re-exports these modules
at their existing paths and supplies the operations that need an analyzer,
resolution, structural facts, or the analyzer store.

This crate depends on core types and language knowledge, independently of the
analysis engine. Its catalog migrations define the semantic-pack catalog
format; installing and activating packs remains engine work.
