//! Strict authoring and deterministic artifact contracts for semantic-model packs.
//!
//! Compiling a pack does not install or activate it in an analyzer. This module owns only the
//! versioned source model, validation, canonical compilation, and defensive artifact decoding.

mod artifact;
mod compiler;
mod model;
mod source;
mod validate;

pub use artifact::{
    ArtifactEncoding, ArtifactError, CompiledPackManifest, CompiledSemanticModelPack,
    CompiledShard, CompiledShardDescriptor, DecodeLimits, PayloadKind, decode_manifest,
    decode_shard,
};
pub use compiler::{CompilerOptions, CompressionPolicy, compile_pack, compile_source};
pub use model::*;
pub use source::SourceFormat;
pub use validate::{Diagnostic, DiagnosticSeverity};

/// Returns the version-one authoring schema as stable, pretty-printed JSON.
pub fn authoring_json_schema() -> String {
    let schema = schemars::schema_for!(AuthoredSemanticModelPack);
    let mut rendered = serde_json::to_string_pretty(&schema).expect("JSON Schema is serializable");
    rendered.push('\n');
    rendered
}
