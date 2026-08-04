//! Strict authoring and deterministic artifact contracts for semantic-model packs.
//!
//! Compiling a pack does not install or activate it in an analyzer. This module owns only the
//! versioned source model, validation, canonical compilation, and defensive artifact decoding.

mod artifact;
mod authoring;
mod catalog;
mod compiler;
mod dependency;
mod identity;
mod model;
mod overlay;
mod producer;
mod runtime;
mod source;
mod summary_binding;
mod validate;

pub use artifact::{
    ArtifactEncoding, ArtifactError, CompiledPackManifest, CompiledPayload,
    CompiledProcedureSummary, CompiledProcedureTarget, CompiledSemanticModelPack, CompiledShard,
    CompiledShardArtifact, CompiledShardDescriptor, CompiledSummaryEffect, CompiledSummaryExitKind,
    CompiledSummaryInput, CompiledSummaryLocation, CompiledSummaryLocationKind,
    CompiledSummaryOutput, CompiledSummaryTransfer, DecodeLimits, PayloadKind, decode_manifest,
    decode_shard, decode_shard_for_manifest,
};
pub use authoring::*;
pub use catalog::*;
pub use compiler::{CompilerOptions, CompressionPolicy, compile_pack, compile_source};
pub use dependency::*;
pub use identity::{MemberIdentity, TypeIdentity, member_declaration_id, type_declaration_id};
pub use model::*;
pub use overlay::*;
pub(crate) use producer::read_exact_artifact_while;
pub use producer::{
    ArtifactProducerLimits, ArtifactProduction, ArtifactProductionRequest,
    BoundedProducerDiagnostics, ExactArtifact, ExactSourceEntry, ExternalArtifactKind,
    ExternalArtifactPackProducer, ProducerDiagnostic, ProducerDiagnosticSeverity,
    read_exact_artifact,
};
pub use runtime::*;
pub use source::SourceFormat;
pub use summary_binding::{
    ExactProcedureSummaryBoundary, ExactProcedureSummaryParameter, ExactProcedureSummaryReceiver,
    ExactProcedureSummaryTargetBinding, ProcedureSummaryBindingError,
    bind_compiled_procedure_summaries,
};
pub use validate::{Diagnostic, DiagnosticSeverity};

/// Returns the version-one authoring schema as stable, pretty-printed JSON.
pub fn authoring_json_schema() -> String {
    let schema = schemars::schema_for!(AuthoredSemanticModelPack);
    let mut rendered = serde_json::to_string_pretty(&schema).expect("JSON Schema is serializable");
    rendered.push('\n');
    rendered
}
