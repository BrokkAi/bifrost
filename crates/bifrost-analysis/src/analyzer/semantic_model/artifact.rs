use super::conversion::{
    authored_concurrency_effect_from_compiled, authored_declared_effect_from_compiled,
    authored_result_predicate_from_compiled, authored_summary_effect_from_compiled,
    authored_summary_input_from_compiled, authored_summary_output_from_compiled,
    authored_summary_value_transfer_from_compiled,
};
use super::model::*;
use super::validate::{
    Diagnostic, ValidationLimits, is_canonical_relative_path, validate_pack_locally,
};
use crate::analyzer::canonical_hash::{hash_domain_bytes, is_lower_sha256, lower_hex_string};
use crate::analyzer::identifier::validate_identifier;
use brokk_bifrost_core::analyzer::model::CallableArity;
use flate2::bufread::DeflateDecoder;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::io::{Cursor, Read};

const MANIFEST_HASH_DOMAIN: &[u8] = b"bifrost.semantic-model.manifest.v1";
const SEMANTIC_HASH_DOMAIN: &[u8] = b"bifrost.semantic-model.shard.semantic.v1";
const PROCEDURE_TARGET_HASH_DOMAIN: &[u8] = b"bifrost.semantic-model.procedure-target.inventory.v1";
const PROCEDURE_ID_INVENTORY_PREFIX: &str = "procedure:";
const PROCEDURE_TARGET_INVENTORY_PREFIX: &str = "procedure-target:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadKind {
    DeclarationFacts,
    GeneratorRules,
    ProcedureSummaries,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactEncoding {
    Raw,
    Deflate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledShardDescriptor {
    pub shard_id: String,
    pub payload_kind: PayloadKind,
    pub routing_keys: Vec<String>,
    pub encoding: ArtifactEncoding,
    pub raw_size: u64,
    pub stored_size: u64,
    pub record_count: u64,
    pub defined_ids: Vec<String>,
    pub referenced_ids: Vec<String>,
    pub semantic_sha256: String,
    pub content_sha256: String,
    pub stored_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledPackManifest {
    pub schema_version: u32,
    pub pack_id: String,
    pub version: String,
    pub producer: Producer,
    pub language: String,
    pub ecosystem: String,
    pub compatibility: Compatibility,
    pub provenance: Provenance,
    pub license: String,
    pub completeness: Completeness,
    pub safety: Safety,
    /// The producer's claim that it parsed each of these relative source paths
    /// from a sources artifact while generating the pack (#2613); strictly
    /// ascending. Serialized only when non-empty so packs without carried
    /// sources keep byte-identical manifests and digests.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub carried_sources: Vec<String>,
    /// Exact native C/C++ portability evidence retained at pack scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpp_portability: Option<CppPortabilityEvidence>,
    /// Exact Python cross-artifact correspondence retained at pack scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub python_correspondence: Option<PythonCorrespondenceEvidence>,
    pub semantic_sha256: String,
    pub content_sha256: String,
    pub shards: Vec<CompiledShardDescriptor>,
}

impl CompiledPackManifest {
    pub fn matches_generated_identity(
        &self,
        producer_name: &str,
        producer_version: &str,
        schema_version: u32,
    ) -> bool {
        self.producer.name == producer_name
            && self.producer.version == producer_version
            && self.schema_version == schema_version
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledShard {
    pub(crate) schema_version: u32,
    pub(crate) pack_id: String,
    pub(crate) pack_version: String,
    pub(crate) producer: Producer,
    pub(crate) shard_id: String,
    pub(crate) language: String,
    pub(crate) ecosystem: String,
    pub(crate) compatibility: Compatibility,
    pub(crate) activation: Vec<ActivationSelector>,
    pub(crate) provenance: Provenance,
    pub(crate) license: String,
    pub(crate) completeness: Completeness,
    pub(crate) safety: Safety,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) runtime_values: Option<RuntimeValuesPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) runtime_contracts: Option<RuntimeContractsPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) collection_flows: Option<CollectionFlowsPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) deferred_yields: Option<DeferredYieldsPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) conditional_type_refinements: Option<ConditionalTypeRefinementsPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) callable_values: Option<CallableValuesPayload>,
    /// The pack-level native C/C++ evidence is repeated in each shard wire
    /// envelope so a shard remains self-describing after extraction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cpp_portability: Option<CppPortabilityEvidence>,
    /// The pack-level Python correspondence evidence is repeated in each
    /// shard wire envelope so a shard remains self-describing after extraction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) python_correspondence: Option<PythonCorrespondenceEvidence>,
    pub(crate) payload: CompiledPayload,
}

impl CompiledShard {
    pub fn payload_kind(&self) -> PayloadKind {
        self.payload.payload_kind()
    }

    pub fn record_count(&self) -> usize {
        self.payload
            .record_count()
            .saturating_add(
                self.runtime_values
                    .as_ref()
                    .map_or(0, RuntimeValuesPayload::record_count),
            )
            .saturating_add(
                self.runtime_contracts
                    .as_ref()
                    .map_or(0, RuntimeContractsPayload::record_count),
            )
            .saturating_add(
                self.collection_flows
                    .as_ref()
                    .map_or(0, CollectionFlowsPayload::record_count),
            )
            .saturating_add(
                self.deferred_yields
                    .as_ref()
                    .map_or(0, DeferredYieldsPayload::record_count),
            )
            .saturating_add(
                self.conditional_type_refinements
                    .as_ref()
                    .map_or(0, ConditionalTypeRefinementsPayload::record_count),
            )
            .saturating_add(
                self.callable_values
                    .as_ref()
                    .map_or(0, CallableValuesPayload::record_count),
            )
    }

    pub fn pack_id(&self) -> &str {
        &self.pack_id
    }

    pub fn shard_id(&self) -> &str {
        &self.shard_id
    }

    pub fn payload(&self) -> &CompiledPayload {
        &self.payload
    }

    pub fn compatibility(&self) -> &Compatibility {
        &self.compatibility
    }

    pub fn activation(&self) -> &[ActivationSelector] {
        &self.activation
    }

    pub fn completeness(&self) -> Completeness {
        self.completeness
    }

    pub fn safety(&self) -> &Safety {
        &self.safety
    }

    pub fn cpp_portability(&self) -> Option<&CppPortabilityEvidence> {
        self.cpp_portability.as_ref()
    }

    pub fn runtime_values(&self) -> Option<&RuntimeValuesPayload> {
        self.runtime_values.as_ref()
    }

    pub fn runtime_contracts(&self) -> Option<&RuntimeContractsPayload> {
        self.runtime_contracts.as_ref()
    }

    pub fn collection_flows(&self) -> Option<&CollectionFlowsPayload> {
        self.collection_flows.as_ref()
    }

    pub fn conditional_type_refinements(&self) -> Option<&ConditionalTypeRefinementsPayload> {
        self.conditional_type_refinements.as_ref()
    }

    pub fn deferred_yields(&self) -> Option<&DeferredYieldsPayload> {
        self.deferred_yields.as_ref()
    }

    pub fn callable_values(&self) -> Option<&CallableValuesPayload> {
        self.callable_values.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompiledPayload {
    DeclarationFacts {
        #[serde(default)]
        types: Vec<TypeFact>,
        #[serde(default)]
        members: Vec<MemberFact>,
        #[serde(default)]
        relations: Vec<RelationFact>,
    },
    GeneratorRules {
        rules: Vec<GeneratorRule>,
    },
    ProcedureSummaries {
        summaries: Vec<CompiledProcedureSummary>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledProcedureSummary {
    pub id: String,
    pub model_id: String,
    pub contract_version: u32,
    pub content_sha256: String,
    pub target: CompiledProcedureTarget,
    pub completeness: Completeness,
    /// Authored claim that this procedure and its transitive behavior do not
    /// write, publish, or escape ordinary program storage, or invoke an
    /// unaccounted callback. Synchronization bookkeeping remains represented
    /// separately.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ordinary_heap_unchanged: bool,
    /// Reviewed claim that this procedure neither synchronizes with
    /// caller-visible memory nor retains caller-visible memory for concurrent
    /// work. It is independent of ordinary-heap preservation.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_concurrency_effects: bool,
    /// The author's explicit claim that every implementation outside the
    /// workspace conforms to this summary (#2371). Serialized only when
    /// claimed, so a summary that does not claim it keeps its content digest.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub covers_overrides: bool,
    /// The reviewed claim that this procedure has no normal continuation.
    /// Serialized only when true so old compiled bytes and digests stay stable.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub normal_continuation_absent: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normal_result_count: Option<u32>,
    pub locations: Vec<CompiledSummaryLocation>,
    pub transfers: Vec<CompiledSummaryTransfer>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transfer_partitions: Vec<NormalResultTransferPartition>,
    pub effects: Vec<CompiledSummaryEffect>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub concurrency_effects: Vec<CompiledConcurrencyEffect>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub returned_callables: Vec<CompiledReturnedCallable>,
    /// Namespaced effect identifiers declared for this exact procedure (#2437).
    /// Serialized only when non-empty, so a summary that declares none keeps the
    /// compiled bytes -- and therefore the shard digests -- it had before the
    /// field existed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared_effects: Vec<CompiledDeclaredEffect>,
    /// Compiled mirror of the procedure-level operation-precondition review
    /// state. `None` and `Some([])` are intentionally distinct claims.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preconditions: Option<Vec<CompiledOperationPrecondition>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub result_contracts: Vec<CompiledResultContract>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub result_use_obligations: Vec<CompiledResultUseObligation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditional_result_refinements: Vec<CompiledConditionalResultRefinement>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditional_indirect_writes: Vec<CompiledConditionalIndirectWrite>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub normal_return_refinements: Vec<CompiledNormalReturnRefinement>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub normal_return_type_refinements: Vec<CompiledNormalReturnTypeRefinement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class_decorator_identity: Option<CompiledClassDecoratorIdentity>,
}

/// Whether two compiled summaries make the same flow-observable claims.
pub fn compiled_flow_claims_agree(
    left: &CompiledProcedureSummary,
    right: &CompiledProcedureSummary,
) -> bool {
    left.completeness == right.completeness
        && left.covers_overrides == right.covers_overrides
        && left.normal_continuation_absent == right.normal_continuation_absent
        && left.normal_result_count == right.normal_result_count
        && left.locations == right.locations
        && left.transfers == right.transfers
        && left.effects == right.effects
        && left.concurrency_effects == right.concurrency_effects
        && left.returned_callables == right.returned_callables
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledClassDecoratorIdentity {
    pub direct: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub factory_keywords: Option<Vec<CompiledClassDecoratorKeyword>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledClassDecoratorKeyword {
    pub name: String,
    pub allowed_values: Vec<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledConditionalResultRefinement {
    pub result_ordinal: u32,
    pub outcome: bool,
    pub parameter_ordinal: u32,
    pub predicate: CompiledResultPredicate,
    pub proof_effect: CompiledPredicateProofEffect,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledConditionalIndirectWrite {
    pub result_ordinal: u32,
    pub outcome: bool,
    pub parameter_ordinal: u32,
    pub target: CompiledIndirectWriteTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledIndirectWriteTarget {
    Pointee,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledPredicateProofEffect {
    Establishes,
    DoesNotEstablish,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledNormalReturnRefinement {
    pub parameter_ordinal: u32,
    pub predicate: CompiledResultPredicate,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledNormalReturnTypeRefinement {
    pub parameter_ordinal: u32,
    pub class_parameter_ordinal: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_receiver_members: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledResultContract {
    pub result_ordinal: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition_result_ordinal: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicate: Option<CompiledResultPredicate>,
    /// Reviewed predicate over the protected result. It is an independent
    /// correlation for a paired contract and the validity predicate itself
    /// for a direct contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_success_predicate: Option<CompiledResultPredicate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub member_contracts: Vec<CompiledResultMemberContract>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledResultUseObligation {
    pub result_ordinal: u32,
    pub kind: ResultUseObligationKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_predicate: Option<CompiledResultPredicate>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledResultMemberContract {
    pub member: String,
    pub parameter_count: u32,
    pub completeness: Completeness,
    /// Compiled mirror of the operation-precondition review state. `None` and
    /// `Some([])` are intentionally distinct semantic claims.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preconditions: Option<Vec<CompiledOperationPrecondition>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared_effects: Vec<CompiledDeclaredEffect>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledOperationPrecondition {
    pub input: CompiledSummaryInput,
    pub predicate: CompiledResultPredicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledResultPredicate {
    Null,
    NonNull,
    True,
    False,
    Eof,
    #[serde(rename = "nonzero")]
    NonZero,
    MinusOne,
}

/// Compiled mirror of `AuthoredDeclaredEffect` (#2437).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledDeclaredEffect {
    pub id: String,
    pub timing: CompiledDeclaredEffectTiming,
    pub certainty: CompiledDeclaredEffectCertainty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledDeclaredEffectTiming {
    Immediate,
    Deferred,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledDeclaredEffectCertainty {
    Definite,
    Possible,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledProcedureTarget {
    pub path: String,
    pub symbol: String,
    pub has_receiver: bool,
    /// Compiled mirror of the authored target's variadic-tail declaration.
    /// Serialized only when true so existing fixed-arity artifacts keep their
    /// canonical bytes and semantic digests.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub variadic: bool,
    pub parameter_count: u32,
    /// Structured fixed-formal binding shape. Empty preserves legacy exact
    /// arity behavior; populated targets carry every fixed formal in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub formals: Vec<AuthoredProcedureFormal>,
}

impl CompiledProcedureTarget {
    /// Smallest actual argument count accepted by this declaration shape.
    pub const fn minimum_parameter_count(&self) -> u32 {
        if self.variadic {
            assert!(
                self.parameter_count > 0,
                "validated variadic targets declare their final formal"
            );
            self.parameter_count - 1
        } else {
            self.parameter_count
        }
    }

    /// Compact declaration shape used for applicability checks and indexes.
    pub const fn callable_arity(&self) -> CallableArity {
        CallableArity::new(
            self.minimum_parameter_count() as usize,
            self.parameter_count as usize,
            self.variadic,
        )
    }

    /// Whether an actual call arity is applicable to this declaration shape.
    pub const fn accepts_parameter_count(&self, actual: u32) -> bool {
        self.callable_arity().accepts(actual as usize)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledSummaryLocation {
    pub id: String,
    pub location_kind: CompiledSummaryLocationKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledSummaryLocationKind {
    Capture,
    Heap,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompiledSummaryInput {
    Receiver {},
    Parameter { ordinal: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompiledSummaryOutput {
    NormalReturn {},
    IndexedNormalReturn { ordinal: u32 },
    Receiver {},
    Capture { location: String },
    Heap { location: String },
    ExceptionalReturn {},
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompiledSummaryPort {
    Input { input: CompiledSummaryInput },
    Output { output: CompiledSummaryOutput },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledSummaryTransfer {
    pub input: CompiledSummaryInput,
    pub exit_kind: CompiledSummaryExitKind,
    pub output: CompiledSummaryOutput,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_transfer: Option<CompiledSummaryValueTransfer>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledSummaryValueTransfer {
    pub kind: CompiledSummaryValueTransferKind,
    pub operation: CompiledSummaryValueTransferOperation,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompiledSummaryValueTransferKind {
    Copy {},
    AggregateCopy {},
    Move {
        invalidation: CompiledSummaryMoveInvalidation,
    },
    Conversion {
        preservation: CompiledSummaryValuePreservation,
    },
    Boxing {},
    Unboxing {},
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledSummaryMoveInvalidation {
    Invalidated,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledSummaryValuePreservation {
    Identity,
    Preserving,
    Changing,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompiledSummaryValueTransferOperation {
    None {},
    Implicit {
        member: String,
    },
    Unknown {
        limitation: CompiledSummaryValueTransferLimitation,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledSummaryValueTransferLimitation {
    pub kind: CompiledSummaryValueTransferLimitationKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledSummaryValueTransferLimitationKind {
    BudgetExhausted,
    Cancelled,
    Unsupported,
    UnresolvedIdentity,
    AmbiguousIdentity,
    IncompleteInput,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledSummaryExitKind {
    Normal,
    Exceptional,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompiledSummaryEffect {
    Allocation {
        event: String,
        output: CompiledSummaryOutput,
    },
    Call {
        event: String,
        callee: String,
    },
    Escape {
        event: String,
        input: CompiledSummaryInput,
    },
    UnknownCall {
        event: String,
        input: CompiledSummaryInput,
    },
    UnknownCallBoundary {
        event: String,
    },
    AmbiguousCall {
        event: String,
        input: CompiledSummaryInput,
        candidates: Vec<String>,
    },
    Sanitize {
        input: CompiledSummaryInput,
        output: CompiledSummaryOutput,
        removes: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompiledConcurrencyEffect {
    Unsupported {
        protocol: String,
    },
    TaskSpawn {
        callable: CompiledSummaryInput,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        group: Option<CompiledSummaryInput>,
        /// The spawn condition this modeled call establishes itself. `None` is
        /// an unconditional spawn; `call_result_true` is the
        /// `errgroup.Group.TryGo` contract, where the callable starts exactly
        /// when the call's boolean result reports that it did.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        condition: Option<CompiledTaskSpawnCondition>,
        /// The timer object this spawn call returns, when the spawned
        /// callback belongs to a cancellable timer (`time.AfterFunc`). A
        /// later `timer_stop` or `timer_reset` on the same object binds
        /// against this identity.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timer: Option<CompiledSummaryOutput>,
    },
    TaskJoin {
        group: CompiledSummaryInput,
    },
    /// One `sync.Once.Do` call: `callable` runs at most once per `once`
    /// object, and the completion of that single execution synchronizes
    /// before the return of every `Do` on the same object.
    ///
    /// The contract is the `sync.Once` package documentation together with
    /// the Go memory model's "the return of a call of `f` from `once.Do(f)`
    /// is synchronized before the return of any call of `once.Do(f)`". The
    /// package documentation's panic clause is part of the same completion:
    /// a panicking `f` is still considered to have returned, so later calls
    /// of `Do` return without calling `f`. This is not a mutex and not an
    /// unconditional spawn: the callable is conditional on the object's
    /// completion state, and the effect itself carries the completion
    /// barrier that publishes it.
    OnceDo {
        once: CompiledSummaryInput,
        callable: CompiledSummaryInput,
    },
    LockAcquire {
        lock: CompiledSummaryInput,
        mode: CompiledLockMode,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        condition: Option<CompiledLockCondition>,
    },
    LockRelease {
        lock: CompiledSummaryInput,
        mode: CompiledLockMode,
    },
    WaitGroupAdd {
        group: CompiledSummaryInput,
        delta: CompiledSummaryInput,
    },
    WaitGroupDone {
        group: CompiledSummaryInput,
    },
    WaitGroupWait {
        group: CompiledSummaryInput,
    },
    Atomic {
        location: CompiledSummaryInput,
        operation: CompiledAtomicOperation,
    },
    /// Associate the condition variable named by `condition` with `lock`.
    ///
    /// `condition` is the constructed object, so the association is published
    /// to the *result* of the construction call and consumed by every later
    /// `CondWait`/`CondNotify` on the same object.
    CondBind {
        condition: CompiledSummaryOutput,
        lock: CompiledSummaryInput,
    },
    /// Release the associated locker, suspend the task, and re-acquire it.
    CondWait {
        condition: CompiledSummaryInput,
    },
    /// Wake one or every suspended waiter without claiming one exists.
    CondNotify {
        condition: CompiledSummaryInput,
        waiters: CompiledCondWaiters,
    },
    /// One `sync.Map` entry operation on the (map, key) entry named by the
    /// exact receiver and key inputs. The compiled form carries the reviewed
    /// classification; the solver binds observation and guard structure.
    SyncMap {
        map: CompiledSummaryInput,
        /// The key input naming the entry; `Clear` names none.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        key: Option<CompiledSummaryInput>,
        operation: CompiledSyncMapOperation,
    },
    /// One `(*time.Timer).Stop` call: when the call's boolean result is
    /// established true, the `time.AfterFunc` callback for `timer` did not
    /// and will not run. The solver binds the guard structure.
    TimerStop {
        timer: CompiledSummaryInput,
    },
    /// One `(*time.Timer).Reset` call, which re-arms `timer` and voids the
    /// `timer_stop` cancellation downstream of it.
    TimerReset {
        timer: CompiledSummaryInput,
    },
    ChannelClose {
        channel: CompiledSummaryPort,
        fresh: bool,
    },
    ChannelCloseAsync {
        channel: CompiledSummaryPort,
        fresh: bool,
    },
    ChannelClosePropagate {
        source: CompiledSummaryPort,
        target: CompiledSummaryPort,
        target_fresh: bool,
    },
    /// One `testing.T.Run` call: `callable` is the subtest callback and
    /// `group` is the parent test node (issue #3383). The solver spawns the
    /// callback on every path and joins it at the call exactly when no
    /// execution of the callback calls `Parallel` on its own parameter.
    SubtestRun {
        callable: CompiledSummaryInput,
        group: CompiledSummaryInput,
    },
    /// One `testing.T.Parallel` call marking `receiver` (issue #3383). The
    /// solver consumes it as classification evidence for the enclosing `Run`
    /// callback; it creates no task and orders nothing by itself.
    SubtestParallel {
        receiver: CompiledSummaryInput,
    },
    /// One `testing.T.Cleanup` call: `callable` is the registered callback
    /// and `group` is the test node whose completion runs it (issue #3383).
    /// The solver spawns the callback as a deferred task and joins the
    /// receiver's subtest subtree before its body.
    SubtestCleanup {
        callable: CompiledSummaryInput,
        group: CompiledSummaryInput,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledReturnedCallable {
    pub result_ordinal: u32,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub at_most_once: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub concurrency_effects: Vec<CompiledConcurrencyEffect>,
}

/// The documented entry-level classification of one `sync.Map` operation
/// (issue #3370). See the authored form for the per-variant contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledSyncMapOperation {
    Store,
    Delete,
    Clear,
    Load,
    Range,
    LoadOrStore,
    LoadAndDelete,
    Swap,
    CompareAndSwap,
    CompareAndDelete,
}

/// How many suspended waiters one notification can resume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledCondWaiters {
    One,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledLockMode {
    Shared,
    Exclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledLockCondition {
    CallResultTrue,
}

/// The spawn condition a compiled summary call establishes by its own boolean
/// result (issue #3371). `CallResultTrue` is `errgroup.Group.TryGo`: the
/// callable starts in a new goroutine exactly when the call reports that it
/// did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledTaskSpawnCondition {
    CallResultTrue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledAtomicOperation {
    Load,
    Store,
    ReadModifyWrite,
}

impl CompiledPayload {
    pub fn payload_kind(&self) -> PayloadKind {
        match self {
            Self::DeclarationFacts { .. } => PayloadKind::DeclarationFacts,
            Self::GeneratorRules { .. } => PayloadKind::GeneratorRules,
            Self::ProcedureSummaries { .. } => PayloadKind::ProcedureSummaries,
        }
    }

    pub fn record_count(&self) -> usize {
        match self {
            Self::DeclarationFacts {
                types,
                members,
                relations,
            } => types.len() + members.len() + relations.len(),
            Self::GeneratorRules { rules } => rules.len(),
            Self::ProcedureSummaries { summaries } => summaries.len(),
        }
    }

    pub fn declaration_facts(&self) -> Option<(&[TypeFact], &[MemberFact], &[RelationFact])> {
        match self {
            Self::DeclarationFacts {
                types,
                members,
                relations,
            } => Some((types, members, relations)),
            Self::GeneratorRules { .. } | Self::ProcedureSummaries { .. } => None,
        }
    }

    pub fn generator_rules(&self) -> Option<&[GeneratorRule]> {
        match self {
            Self::DeclarationFacts { .. } | Self::ProcedureSummaries { .. } => None,
            Self::GeneratorRules { rules } => Some(rules),
        }
    }

    pub fn procedure_summaries(&self) -> Option<&[CompiledProcedureSummary]> {
        match self {
            Self::ProcedureSummaries { summaries } => Some(summaries),
            Self::DeclarationFacts { .. } | Self::GeneratorRules { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCompiledShard {
    schema_version: u32,
    pack_id: String,
    pack_version: String,
    producer: Producer,
    shard_id: String,
    language: String,
    ecosystem: String,
    compatibility: Compatibility,
    activation: Vec<ActivationSelector>,
    provenance: Provenance,
    license: String,
    completeness: Completeness,
    safety: Safety,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    runtime_values: Option<RuntimeValuesPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    runtime_contracts: Option<RuntimeContractsPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    collection_flows: Option<CollectionFlowsPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    deferred_yields: Option<DeferredYieldsPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    conditional_type_refinements: Option<ConditionalTypeRefinementsPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    callable_values: Option<CallableValuesPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cpp_portability: Option<CppPortabilityEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    python_correspondence: Option<PythonCorrespondenceEvidence>,
    payload: CompiledPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledShardArtifact {
    pub descriptor: CompiledShardDescriptor,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledSemanticModelPack {
    pub manifest: CompiledPackManifest,
    pub manifest_bytes: Vec<u8>,
    pub shards: Vec<CompiledShardArtifact>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeLimits {
    pub max_manifest_bytes: usize,
    pub max_stored_shard_bytes: usize,
    pub max_raw_shard_bytes: usize,
    pub max_total_raw_bytes: u64,
    pub max_shards: usize,
    pub max_records_per_shard: usize,
    pub max_total_records: u64,
    pub max_text_bytes: usize,
    pub max_depth: usize,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_manifest_bytes: 16 * 1024 * 1024,
            max_stored_shard_bytes: 64 * 1024 * 1024,
            max_raw_shard_bytes: 64 * 1024 * 1024,
            max_total_raw_bytes: 1024 * 1024 * 1024,
            max_shards: 4_096,
            max_records_per_shard: 250_000,
            max_total_records: 2_000_000,
            max_text_bytes: 16 * 1024,
            max_depth: 64,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactError {
    LimitExceeded(&'static str),
    InvalidJson(String),
    UnsupportedVersion(u32),
    NonCanonical,
    InvalidDescriptor(String),
    SizeMismatch { expected: u64, actual: u64 },
    DigestMismatch(&'static str),
    SemanticValidation(Vec<Diagnostic>),
    Decompression(String),
    Allocation,
    TrailingCompressedData,
}

impl fmt::Display for ArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitExceeded(limit) => write!(formatter, "artifact exceeds {limit}"),
            Self::InvalidJson(error) => write!(formatter, "invalid artifact JSON: {error}"),
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported semantic-model schema version {version}"
                )
            }
            Self::NonCanonical => formatter.write_str("artifact bytes are not canonical JSON"),
            Self::InvalidDescriptor(message) => {
                write!(formatter, "invalid shard descriptor: {message}")
            }
            Self::SizeMismatch { expected, actual } => {
                write!(
                    formatter,
                    "size mismatch: expected {expected}, found {actual}"
                )
            }
            Self::DigestMismatch(kind) => write!(formatter, "{kind} digest mismatch"),
            Self::SemanticValidation(diagnostics) => write!(
                formatter,
                "artifact failed semantic validation with {} diagnostic(s)",
                diagnostics.len()
            ),
            Self::Decompression(error) => write!(formatter, "DEFLATE decode failed: {error}"),
            Self::Allocation => formatter.write_str("artifact allocation failed"),
            Self::TrailingCompressedData => {
                formatter.write_str("compressed shard has trailing data")
            }
        }
    }
}

impl std::error::Error for ArtifactError {}

pub fn decode_manifest(
    bytes: &[u8],
    limits: &DecodeLimits,
) -> Result<CompiledPackManifest, ArtifactError> {
    if bytes.len() > limits.max_manifest_bytes {
        return Err(ArtifactError::LimitExceeded("manifest byte limit"));
    }
    let manifest: CompiledPackManifest = serde_json::from_slice(bytes)
        .map_err(|error| ArtifactError::InvalidJson(error.to_string()))?;
    require_version(manifest.schema_version)?;
    manifest
        .compatibility
        .validate_for_schema(manifest.schema_version)
        .map_err(|error| ArtifactError::InvalidDescriptor(error.to_string()))?;
    if canonical_json(&manifest)? != bytes {
        return Err(ArtifactError::NonCanonical);
    }
    if manifest.shards.len() > limits.max_shards {
        return Err(ArtifactError::LimitExceeded("shard count limit"));
    }
    if validate_identifier(&manifest.pack_id, 256, true).is_err() {
        return Err(ArtifactError::InvalidDescriptor(
            "manifest pack id is invalid".to_owned(),
        ));
    }
    validate_text(&manifest.version, limits, "manifest version")?;
    validate_text(&manifest.producer.name, limits, "manifest producer name")?;
    validate_text(
        &manifest.producer.version,
        limits,
        "manifest producer version",
    )?;
    validate_text(&manifest.language, limits, "manifest language")?;
    validate_text(&manifest.ecosystem, limits, "manifest ecosystem")?;
    if let Some(requirement) = &manifest.compatibility.bifrost {
        validate_text(requirement, limits, "manifest Bifrost compatibility")?;
    }
    validate_text(&manifest.provenance.source, limits, "manifest provenance")?;
    if let Some(revision) = &manifest.provenance.revision {
        validate_text(revision, limits, "manifest provenance revision")?;
    }
    validate_text(&manifest.license, limits, "manifest license")?;
    if semver::Version::parse(&manifest.version).is_err()
        || semver::Version::parse(&manifest.producer.version).is_err()
    {
        return Err(ArtifactError::InvalidDescriptor(
            "manifest versions must be semantic versions".to_owned(),
        ));
    }
    if spdx::Expression::parse(&manifest.license).is_err() {
        return Err(ArtifactError::InvalidDescriptor(
            "manifest license must be an SPDX expression".to_owned(),
        ));
    }
    if !is_lower_sha256(&manifest.semantic_sha256) || !is_lower_sha256(&manifest.content_sha256) {
        return Err(ArtifactError::InvalidDescriptor(
            "manifest digests must be lowercase SHA-256 hex".to_owned(),
        ));
    }
    if manifest
        .compatibility
        .toolchains
        .windows(2)
        .any(|pair| (&pair[0].name, &pair[0].requirement) >= (&pair[1].name, &pair[1].requirement))
    {
        return Err(ArtifactError::InvalidDescriptor(
            "toolchain constraints must be unique and ascending".to_owned(),
        ));
    }
    for toolchain in &manifest.compatibility.toolchains {
        validate_text(&toolchain.name, limits, "toolchain name")?;
        validate_text(&toolchain.requirement, limits, "toolchain requirement")?;
        if semver::VersionReq::parse(&toolchain.requirement).is_err() {
            return Err(ArtifactError::InvalidDescriptor(
                "toolchain requirements must be semantic-version requirements".to_owned(),
            ));
        }
    }
    if manifest
        .carried_sources
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(ArtifactError::InvalidDescriptor(
            "carried sources must be unique ascending paths".to_owned(),
        ));
    }
    for path in &manifest.carried_sources {
        validate_text(path, limits, "carried source path")?;
        if !is_canonical_relative_path(path) {
            return Err(ArtifactError::InvalidDescriptor(
                "carried sources must be relative canonical slash-separated paths".to_owned(),
            ));
        }
    }
    if manifest
        .shards
        .windows(2)
        .any(|pair| pair[0].shard_id >= pair[1].shard_id)
    {
        return Err(ArtifactError::InvalidDescriptor(
            "shard descriptors must have unique ascending ids".to_owned(),
        ));
    }
    let mut total_records = 0u64;
    let total_raw = manifest.shards.iter().try_fold(0u64, |total, shard| {
        validate_descriptor(shard, limits)?;
        total_records = total_records
            .checked_add(shard.record_count)
            .ok_or(ArtifactError::LimitExceeded("total record limit"))?;
        total
            .checked_add(shard.raw_size)
            .ok_or(ArtifactError::LimitExceeded("total raw byte limit"))
    })?;
    if total_raw > limits.max_total_raw_bytes {
        return Err(ArtifactError::LimitExceeded("total raw byte limit"));
    }
    if total_records > limits.max_total_records {
        return Err(ArtifactError::LimitExceeded("total record limit"));
    }
    validate_manifest_inventory(&manifest)?;
    if manifest_semantic_digest(&manifest)? != manifest.semantic_sha256 {
        return Err(ArtifactError::DigestMismatch("manifest semantic"));
    }
    if manifest_content_digest(&manifest)? != manifest.content_sha256 {
        return Err(ArtifactError::DigestMismatch("manifest content"));
    }
    Ok(manifest)
}

pub fn decode_shard(
    descriptor: &CompiledShardDescriptor,
    bytes: &[u8],
    limits: &DecodeLimits,
) -> Result<CompiledShard, ArtifactError> {
    let (wire, raw) = read_shard_wire(descriptor, bytes, limits)?;
    if canonical_json(&wire)? != raw {
        return Err(ArtifactError::NonCanonical);
    }
    let shard = compiled_from_wire(wire);
    let authored = authored_pack_from_compiled_shard(&shard);
    let diagnostics = validate_pack_locally(
        &authored,
        ValidationLimits {
            max_shards: 1,
            max_records_per_shard: limits.max_records_per_shard,
            max_records_per_pack: usize::try_from(limits.max_total_records).unwrap_or(usize::MAX),
            max_text_bytes: limits.max_text_bytes,
            max_depth: limits.max_depth,
        },
    );
    if !diagnostics.is_empty() {
        return Err(ArtifactError::SemanticValidation(diagnostics));
    }
    validate_compiled_procedure_metadata(&shard, &authored)?;
    if super::compiler::normalize(authored.clone()) != authored {
        return Err(ArtifactError::NonCanonical);
    }
    if shard.shard_id != descriptor.shard_id {
        return Err(ArtifactError::InvalidDescriptor(
            "shard id does not match payload".to_owned(),
        ));
    }
    if shard.payload_kind() != descriptor.payload_kind {
        return Err(ArtifactError::InvalidDescriptor(
            "payload kind does not match payload".to_owned(),
        ));
    }
    if shard.record_count() != usize::try_from(descriptor.record_count).unwrap_or(usize::MAX) {
        return Err(ArtifactError::InvalidDescriptor(
            "record count does not match payload".to_owned(),
        ));
    }
    if routing_keys(&shard.activation, &shard.payload) != descriptor.routing_keys {
        return Err(ArtifactError::InvalidDescriptor(
            "routing keys do not match payload".to_owned(),
        ));
    }
    let (defined_ids, referenced_ids) = shard_inventory(&shard);
    if defined_ids != descriptor.defined_ids || referenced_ids != descriptor.referenced_ids {
        return Err(ArtifactError::InvalidDescriptor(
            "declaration inventory does not match payload".to_owned(),
        ));
    }
    if semantic_digest(&shard)? != descriptor.semantic_sha256 {
        return Err(ArtifactError::DigestMismatch("semantic"));
    }
    Ok(shard)
}

// This performs the integrity checks needed on every read, including reads of
// previously validated bytes. Semantic validation remains in decode_shard.
fn read_shard_wire(
    descriptor: &CompiledShardDescriptor,
    bytes: &[u8],
    limits: &DecodeLimits,
) -> Result<(WireCompiledShard, Vec<u8>), ArtifactError> {
    validate_descriptor(descriptor, limits)?;
    let actual_stored = u64::try_from(bytes.len())
        .map_err(|_| ArtifactError::LimitExceeded("stored shard byte limit"))?;
    if descriptor.stored_size != actual_stored {
        return Err(ArtifactError::SizeMismatch {
            expected: descriptor.stored_size,
            actual: actual_stored,
        });
    }
    if content_digest(bytes) != descriptor.stored_sha256 {
        return Err(ArtifactError::DigestMismatch("stored"));
    }

    let raw = match descriptor.encoding {
        ArtifactEncoding::Raw => bytes.to_vec(),
        ArtifactEncoding::Deflate => {
            let _scope = crate::profiling::scope("semantic_pack.inflate_shard");
            inflate_bounded(bytes, descriptor.raw_size, limits)?
        }
    };
    let actual_raw = u64::try_from(raw.len())
        .map_err(|_| ArtifactError::LimitExceeded("raw shard byte limit"))?;
    if descriptor.raw_size != actual_raw {
        return Err(ArtifactError::SizeMismatch {
            expected: descriptor.raw_size,
            actual: actual_raw,
        });
    }
    if content_digest(&raw) != descriptor.content_sha256 {
        return Err(ArtifactError::DigestMismatch("content"));
    }
    let wire: WireCompiledShard = {
        let _scope = crate::profiling::scope("semantic_pack.parse_shard_json");
        serde_json::from_slice(&raw)
            .map_err(|error| ArtifactError::InvalidJson(error.to_string()))?
    };
    require_version(wire.schema_version)?;
    Ok((wire, raw))
}

/// Hydrate bytes with a current catalog validation certificate. The catalog
/// must bind that certificate to this exact manifest, descriptor, and limits.
/// Content digests and the manifest envelope are checked on every read.
pub(super) fn hydrate_certified_shard(
    manifest: &CompiledPackManifest,
    descriptor: &CompiledShardDescriptor,
    bytes: &[u8],
    limits: &DecodeLimits,
) -> Result<CompiledShard, ArtifactError> {
    let (wire, _raw) = read_shard_wire(descriptor, bytes, limits)?;
    let shard = compiled_from_wire(wire);
    validate_shard_envelope(manifest, descriptor, &shard)?;
    Ok(shard)
}

fn validate_compiled_procedure_metadata(
    shard: &CompiledShard,
    authored: &AuthoredSemanticModelPack,
) -> Result<(), ArtifactError> {
    let CompiledPayload::ProcedureSummaries { summaries } = &shard.payload else {
        return Ok(());
    };
    let AuthoredPayload::ProcedureSummaries {
        summaries: authored_summaries,
    } = &authored.shards[0].payload
    else {
        return Err(ArtifactError::InvalidDescriptor(
            "compiled procedure payload did not reconstruct as authored procedures".to_owned(),
        ));
    };
    if summaries.len() != authored_summaries.len() {
        return Err(ArtifactError::InvalidDescriptor(
            "compiled procedure record count changed during reconstruction".to_owned(),
        ));
    }
    for (compiled, authored) in summaries.iter().zip(authored_summaries) {
        if compiled.contract_version != PROCEDURE_SUMMARY_CONTRACT_VERSION {
            return Err(ArtifactError::InvalidDescriptor(
                "procedure summary contract version is unsupported".to_owned(),
            ));
        }
        if compiled.model_id != format!("{}#{}", shard.pack_id, compiled.id) {
            return Err(ArtifactError::InvalidDescriptor(
                "procedure summary model id was not derived from the pack and record ids"
                    .to_owned(),
            ));
        }
        if !is_lower_sha256(&compiled.content_sha256)
            || compiled.content_sha256 != content_digest(&canonical_json(authored)?)
        {
            return Err(ArtifactError::InvalidDescriptor(
                "procedure summary content hash is invalid".to_owned(),
            ));
        }
    }
    Ok(())
}

fn compiled_from_wire(wire: WireCompiledShard) -> CompiledShard {
    CompiledShard {
        schema_version: wire.schema_version,
        pack_id: wire.pack_id,
        pack_version: wire.pack_version,
        producer: wire.producer,
        shard_id: wire.shard_id,
        language: wire.language,
        ecosystem: wire.ecosystem,
        compatibility: wire.compatibility,
        activation: wire.activation,
        provenance: wire.provenance,
        license: wire.license,
        completeness: wire.completeness,
        safety: wire.safety,
        runtime_values: wire.runtime_values,
        runtime_contracts: wire.runtime_contracts,
        collection_flows: wire.collection_flows,
        deferred_yields: wire.deferred_yields,
        conditional_type_refinements: wire.conditional_type_refinements,
        callable_values: wire.callable_values,
        cpp_portability: wire.cpp_portability,
        python_correspondence: wire.python_correspondence,
        payload: wire.payload,
    }
}

pub fn decode_shard_for_manifest(
    manifest: &CompiledPackManifest,
    descriptor: &CompiledShardDescriptor,
    bytes: &[u8],
    limits: &DecodeLimits,
) -> Result<CompiledShard, ArtifactError> {
    validate_manifest_inventory(manifest)?;
    decode_present_shard_for_manifest(manifest, descriptor, bytes, limits)
}

/// Decode one shard of a manifest whose inventory the caller already validated.
///
/// [`validate_manifest_inventory`] proves properties of the whole manifest and
/// never looks at one shard's bytes, so a reader that decodes every shard of a
/// manifest validates it once and decodes the rest through this entry point
/// (#3101). A caller that has not validated the inventory must not use it.
pub fn decode_validated_shard_for_manifest(
    manifest: &CompiledPackManifest,
    descriptor: &CompiledShardDescriptor,
    bytes: &[u8],
    limits: &DecodeLimits,
) -> Result<CompiledShard, ArtifactError> {
    decode_present_shard_for_manifest(manifest, descriptor, bytes, limits)
}

fn decode_present_shard_for_manifest(
    manifest: &CompiledPackManifest,
    descriptor: &CompiledShardDescriptor,
    bytes: &[u8],
    limits: &DecodeLimits,
) -> Result<CompiledShard, ArtifactError> {
    let shard = decode_shard(descriptor, bytes, limits)?;
    validate_shard_envelope(manifest, descriptor, &shard)?;
    Ok(shard)
}

fn validate_shard_envelope(
    manifest: &CompiledPackManifest,
    descriptor: &CompiledShardDescriptor,
    shard: &CompiledShard,
) -> Result<(), ArtifactError> {
    if !manifest
        .shards
        .iter()
        .any(|candidate| candidate == descriptor)
    {
        return Err(ArtifactError::InvalidDescriptor(
            "shard descriptor is not present in manifest".to_owned(),
        ));
    }
    if shard.schema_version != manifest.schema_version
        || shard.pack_id != manifest.pack_id
        || shard.pack_version != manifest.version
        || shard.producer != manifest.producer
        || shard.language != manifest.language
        || shard.ecosystem != manifest.ecosystem
        || shard.compatibility != manifest.compatibility
        || shard.provenance != manifest.provenance
        || shard.license != manifest.license
        || shard.completeness != manifest.completeness
        || shard.safety != manifest.safety
    {
        return Err(ArtifactError::InvalidDescriptor(
            "shard envelope does not match manifest".to_owned(),
        ));
    }
    Ok(())
}

fn inflate_bounded(
    bytes: &[u8],
    declared_raw_size: u64,
    limits: &DecodeLimits,
) -> Result<Vec<u8>, ArtifactError> {
    if declared_raw_size > limits.max_raw_shard_bytes as u64 {
        return Err(ArtifactError::LimitExceeded("raw shard byte limit"));
    }
    let capacity = usize::try_from(declared_raw_size)
        .map_err(|_| ArtifactError::LimitExceeded("raw shard byte limit"))?;
    let mut decoder = DeflateDecoder::new(Cursor::new(bytes));
    let mut output = Vec::new();
    output
        .try_reserve(capacity.min(16 * 1024))
        .map_err(|_| ArtifactError::Allocation)?;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = decoder
            .read(&mut buffer)
            .map_err(|error| ArtifactError::Decompression(error.to_string()))?;
        if read == 0 {
            break;
        }
        if output.len().saturating_add(read) > capacity
            || output.len().saturating_add(read) > limits.max_raw_shard_bytes
        {
            return Err(ArtifactError::LimitExceeded("raw shard byte limit"));
        }
        output
            .try_reserve(read)
            .map_err(|_| ArtifactError::Allocation)?;
        output.extend_from_slice(&buffer[..read]);
    }
    if decoder.total_in() != bytes.len() as u64 {
        return Err(ArtifactError::TrailingCompressedData);
    }
    Ok(output)
}

fn validate_descriptor(
    descriptor: &CompiledShardDescriptor,
    limits: &DecodeLimits,
) -> Result<(), ArtifactError> {
    if validate_identifier(&descriptor.shard_id, 256, true).is_err() {
        return Err(ArtifactError::InvalidDescriptor(
            "shard id is invalid".to_owned(),
        ));
    }
    if descriptor
        .routing_keys
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(ArtifactError::InvalidDescriptor(
            "routing keys must be unique and ascending".to_owned(),
        ));
    }
    for (name, ids) in [
        ("defined ids", &descriptor.defined_ids),
        ("referenced ids", &descriptor.referenced_ids),
    ] {
        if ids.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ArtifactError::InvalidDescriptor(format!(
                "{name} must be unique and ascending"
            )));
        }
        if ids.iter().any(|id| !valid_inventory_id(id)) {
            return Err(ArtifactError::InvalidDescriptor(format!(
                "{name} must contain valid stable ids"
            )));
        }
    }
    if descriptor.stored_size > limits.max_stored_shard_bytes as u64 {
        return Err(ArtifactError::LimitExceeded("stored shard byte limit"));
    }
    if descriptor.raw_size > limits.max_raw_shard_bytes as u64 {
        return Err(ArtifactError::LimitExceeded("raw shard byte limit"));
    }
    if descriptor.record_count > limits.max_records_per_shard as u64 {
        return Err(ArtifactError::LimitExceeded("records per shard limit"));
    }
    if descriptor.encoding == ArtifactEncoding::Raw && descriptor.raw_size != descriptor.stored_size
    {
        return Err(ArtifactError::InvalidDescriptor(
            "raw shards must have equal raw and stored sizes".to_owned(),
        ));
    }
    for digest in [
        &descriptor.semantic_sha256,
        &descriptor.content_sha256,
        &descriptor.stored_sha256,
    ] {
        if !is_lower_sha256(digest) {
            return Err(ArtifactError::InvalidDescriptor(
                "digests must be lowercase SHA-256 hex".to_owned(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, ArtifactError> {
    super::compact_json_bytes(value).map_err(|error| ArtifactError::InvalidJson(error.to_string()))
}

pub(crate) fn semantic_digest(shard: &CompiledShard) -> Result<String, ArtifactError> {
    #[derive(Serialize)]
    struct SemanticView<'a> {
        schema_version: u32,
        pack_id: &'a str,
        shard_id: &'a str,
        language: &'a str,
        ecosystem: &'a str,
        compatibility: &'a Compatibility,
        activation: &'a [ActivationSelector],
        completeness: Completeness,
        safety: &'a Safety,
        #[serde(skip_serializing_if = "Option::is_none")]
        runtime_values: &'a Option<RuntimeValuesPayload>,
        #[serde(skip_serializing_if = "Option::is_none")]
        runtime_contracts: &'a Option<RuntimeContractsPayload>,
        #[serde(skip_serializing_if = "Option::is_none")]
        collection_flows: &'a Option<CollectionFlowsPayload>,
        #[serde(skip_serializing_if = "Option::is_none")]
        deferred_yields: &'a Option<DeferredYieldsPayload>,
        #[serde(skip_serializing_if = "Option::is_none")]
        conditional_type_refinements: &'a Option<ConditionalTypeRefinementsPayload>,
        #[serde(skip_serializing_if = "Option::is_none")]
        callable_values: &'a Option<CallableValuesPayload>,
        #[serde(skip_serializing_if = "Option::is_none")]
        cpp_portability: &'a Option<CppPortabilityEvidence>,
        #[serde(skip_serializing_if = "Option::is_none")]
        python_correspondence: &'a Option<PythonCorrespondenceEvidence>,
        payload: &'a CompiledPayload,
    }
    let bytes = canonical_json(&SemanticView {
        schema_version: shard.schema_version,
        pack_id: &shard.pack_id,
        shard_id: &shard.shard_id,
        language: &shard.language,
        ecosystem: &shard.ecosystem,
        compatibility: &shard.compatibility,
        activation: &shard.activation,
        completeness: shard.completeness,
        safety: &shard.safety,
        runtime_values: &shard.runtime_values,
        runtime_contracts: &shard.runtime_contracts,
        collection_flows: &shard.collection_flows,
        deferred_yields: &shard.deferred_yields,
        conditional_type_refinements: &shard.conditional_type_refinements,
        callable_values: &shard.callable_values,
        cpp_portability: &shard.cpp_portability,
        python_correspondence: &shard.python_correspondence,
        payload: &shard.payload,
    })?;
    Ok(digest_hex(SEMANTIC_HASH_DOMAIN, &bytes))
}

pub(crate) fn manifest_semantic_digest(
    manifest: &CompiledPackManifest,
) -> Result<String, ArtifactError> {
    #[derive(Serialize)]
    struct ManifestSemanticView<'a> {
        schema_version: u32,
        pack_id: &'a str,
        version: &'a str,
        language: &'a str,
        ecosystem: &'a str,
        compatibility: &'a Compatibility,
        completeness: Completeness,
        safety: &'a Safety,
        #[serde(skip_serializing_if = "Option::is_none")]
        cpp_portability: &'a Option<CppPortabilityEvidence>,
        #[serde(skip_serializing_if = "Option::is_none")]
        python_correspondence: &'a Option<PythonCorrespondenceEvidence>,
        shards: Vec<(&'a str, &'a str)>,
    }
    let bytes = canonical_json(&ManifestSemanticView {
        schema_version: manifest.schema_version,
        pack_id: &manifest.pack_id,
        version: &manifest.version,
        language: &manifest.language,
        ecosystem: &manifest.ecosystem,
        compatibility: &manifest.compatibility,
        completeness: manifest.completeness,
        safety: &manifest.safety,
        cpp_portability: &manifest.cpp_portability,
        python_correspondence: &manifest.python_correspondence,
        shards: manifest
            .shards
            .iter()
            .map(|shard| (shard.shard_id.as_str(), shard.semantic_sha256.as_str()))
            .collect(),
    })?;
    Ok(digest_hex(MANIFEST_HASH_DOMAIN, &bytes))
}

pub(crate) fn manifest_content_digest(
    manifest: &CompiledPackManifest,
) -> Result<String, ArtifactError> {
    #[derive(Serialize)]
    struct ManifestContentView<'a> {
        schema_version: u32,
        pack_id: &'a str,
        version: &'a str,
        producer: &'a Producer,
        language: &'a str,
        ecosystem: &'a str,
        compatibility: &'a Compatibility,
        provenance: &'a Provenance,
        license: &'a str,
        completeness: Completeness,
        safety: &'a Safety,
        #[serde(skip_serializing_if = "Option::is_none")]
        cpp_portability: &'a Option<CppPortabilityEvidence>,
        #[serde(skip_serializing_if = "Option::is_none")]
        python_correspondence: &'a Option<PythonCorrespondenceEvidence>,
        #[serde(skip_serializing_if = "<[String]>::is_empty")]
        carried_sources: &'a [String],
        semantic_sha256: &'a str,
        shards: &'a [CompiledShardDescriptor],
    }
    let bytes = canonical_json(&ManifestContentView {
        schema_version: manifest.schema_version,
        pack_id: &manifest.pack_id,
        version: &manifest.version,
        producer: &manifest.producer,
        language: &manifest.language,
        ecosystem: &manifest.ecosystem,
        compatibility: &manifest.compatibility,
        provenance: &manifest.provenance,
        license: &manifest.license,
        completeness: manifest.completeness,
        safety: &manifest.safety,
        cpp_portability: &manifest.cpp_portability,
        python_correspondence: &manifest.python_correspondence,
        carried_sources: &manifest.carried_sources,
        semantic_sha256: &manifest.semantic_sha256,
        shards: &manifest.shards,
    })?;
    Ok(content_digest(&bytes))
}

pub(crate) fn content_digest(bytes: &[u8]) -> String {
    crate::analyzer::semantic_model::csmi::sha256_hex(bytes)
}

pub(crate) fn routing_keys(
    selectors: &[ActivationSelector],
    payload: &CompiledPayload,
) -> Vec<String> {
    let mut keys = Vec::new();
    for selector in selectors {
        for (prefix, selected) in [
            ("package", selector.package.as_ref()),
            ("module", selector.module.as_ref()),
            ("toolchain", selector.toolchain.as_ref()),
        ] {
            if let Some(selected) = selected {
                keys.push(format!("{prefix}:{}", selected.name));
            }
        }
    }
    if let CompiledPayload::GeneratorRules { rules } = payload {
        for rule in rules {
            let kind = match rule.trigger {
                RuleTrigger::LanguageConstruct { .. } => "language_construct",
                RuleTrigger::Annotation { .. } => "annotation",
                RuleTrigger::AnnotatedField { .. } => "annotated_field",
                RuleTrigger::MacroInvocation { .. } => "macro_invocation",
                RuleTrigger::GeneratorInvocation { .. } => "generator_invocation",
                RuleTrigger::ResolvedOwner { .. } => "resolved_owner",
                RuleTrigger::ResolvedCall { .. } => "resolved_call",
            };
            keys.push(format!("trigger:{kind}"));
        }
    }
    if matches!(payload, CompiledPayload::ProcedureSummaries { .. }) {
        keys.push("payload:procedure_summaries".to_owned());
    }
    keys.sort_unstable();
    keys.dedup();
    keys
}

pub(crate) fn shard_inventory(shard: &CompiledShard) -> (Vec<String>, Vec<String>) {
    use super::csmi::{
        CsmiCallableValuesArgument, CsmiCallableValuesPayload, CsmiConditionalTypeOutcome,
        CsmiTypeExpression,
    };
    let (mut defined, mut referenced) = payload_inventory(&shard.payload);
    if let Some(payload) = &shard.conditional_type_refinements {
        let mut pending = Vec::new();
        for fact in &payload.refinements {
            referenced.push(fact.payload.callable.clone());
            if let CsmiConditionalTypeOutcome::Supported { target, .. } = &fact.payload.outcome {
                pending.push(target);
            }
        }
        while let Some(target) = pending.pop() {
            match target {
                CsmiTypeExpression::Reference(reference) => {
                    referenced.push(reference.symbol.clone());
                    pending.extend(&reference.arguments);
                }
                CsmiTypeExpression::Parameter(parameter) => {
                    referenced.push(parameter.symbol.clone())
                }
                CsmiTypeExpression::Intrinsic(_) => {}
                CsmiTypeExpression::Unknown(_) => {}
            }
        }
    }
    if let Some(payload) = &shard.callable_values {
        defined.extend(
            payload
                .anonymous_callables
                .iter()
                .map(|identity| identity.id.clone()),
        );
        for fact in &payload.facts {
            match &fact.payload {
                CsmiCallableValuesPayload::ReturnedCallable {
                    callable, target, ..
                } => {
                    referenced.push(callable.clone());
                    referenced.push(target.clone());
                }
                CsmiCallableValuesPayload::CallbackInvocation {
                    callable,
                    callback,
                    arguments,
                    ..
                } => {
                    referenced.push(callable.clone());
                    callable_values_location_inventory(callback, &mut referenced);
                    for argument in arguments {
                        if let CsmiCallableValuesArgument::Input { source } = argument {
                            callable_values_location_inventory(source, &mut referenced);
                        }
                    }
                }
            }
        }
        referenced.extend(
            payload
                .coverage
                .iter()
                .map(|coverage| coverage.callable.clone()),
        );
    }
    defined.sort_unstable();
    defined.dedup();
    referenced.sort_unstable();
    referenced.dedup();
    (defined, referenced)
}

fn callable_values_location_inventory(
    location: &super::csmi::CsmiInputLocation,
    referenced: &mut Vec<String>,
) {
    if let super::csmi::CsmiInputBoundaryRoot::Capture(root) = &location.root {
        referenced.push(root.symbol.clone());
    }
    let Some(projection) = &location.projection else {
        return;
    };
    for step in &projection.steps {
        if let Some(symbol) = step
            .args
            .as_ref()
            .and_then(|args| args.get("symbol"))
            .and_then(serde_json::Value::as_str)
        {
            referenced.push(symbol.to_owned());
        }
    }
}

pub(crate) fn payload_inventory(payload: &CompiledPayload) -> (Vec<String>, Vec<String>) {
    let mut defined = HashSet::new();
    let mut referenced = HashSet::new();
    match payload {
        CompiledPayload::DeclarationFacts {
            types,
            members,
            relations,
        } => {
            for fact in types {
                defined.insert(fact.id.clone());
                for hierarchy in &fact.hierarchy {
                    collect_declared_type_refs(&hierarchy.target, &mut referenced);
                }
                for base in fact.runtime_bases.iter().flatten() {
                    collect_declared_type_refs(base, &mut referenced);
                }
                for constraint in &fact.type_parameter_constraints {
                    for type_ref in &constraint.constraint.referenced_types {
                        collect_declared_type_refs(type_ref, &mut referenced);
                    }
                }
                if let Some(underlying) = &fact.underlying_type {
                    for type_ref in &underlying.referenced_types {
                        collect_declared_type_refs(type_ref, &mut referenced);
                    }
                }
                if let Some(TypeValueSemantics {
                    copy: Some(TypeCopySemantics::ViaMember { member }),
                    ..
                }) = &fact.value_semantics
                {
                    referenced.insert(member.clone());
                }
                for embedded in &fact.embedded_types {
                    collect_declared_type_refs(&embedded.target, &mut referenced);
                }
            }
            for fact in members {
                defined.insert(fact.id.clone());
                referenced.insert(fact.owner.clone());
                if let Some(signature) = &fact.signature {
                    for parameter in &signature.parameters {
                        collect_declared_type_refs(&parameter.r#type, &mut referenced);
                    }
                    if let Some(returns) = &signature.returns {
                        collect_declared_type_refs(returns, &mut referenced);
                    }
                }
                if let Some(ImplicitOperation::ConversionOperator { target }) =
                    &fact.implicit_operation
                {
                    collect_declared_type_refs(target, &mut referenced);
                }
            }
            for relation in relations {
                referenced.insert(relation.from.clone());
                referenced.insert(relation.to.clone());
            }
        }
        CompiledPayload::ProcedureSummaries { summaries } => {
            for summary in summaries {
                defined.insert(format!("{PROCEDURE_ID_INVENTORY_PREFIX}{}", summary.id));
                defined.insert(procedure_target_inventory_id(&summary.target));
                for transfer in &summary.transfers {
                    if let Some(CompiledSummaryValueTransfer {
                        operation: CompiledSummaryValueTransferOperation::Implicit { member },
                        ..
                    }) = &transfer.value_transfer
                    {
                        referenced.insert(member.clone());
                    }
                }
                for effect in &summary.effects {
                    match effect {
                        CompiledSummaryEffect::Call { callee, .. } => {
                            referenced.insert(format!("{PROCEDURE_ID_INVENTORY_PREFIX}{callee}"));
                        }
                        CompiledSummaryEffect::AmbiguousCall { candidates, .. } => {
                            referenced.extend(candidates.iter().map(|candidate| {
                                format!("{PROCEDURE_ID_INVENTORY_PREFIX}{candidate}")
                            }));
                        }
                        CompiledSummaryEffect::Allocation { .. }
                        | CompiledSummaryEffect::Escape { .. }
                        | CompiledSummaryEffect::UnknownCall { .. }
                        | CompiledSummaryEffect::UnknownCallBoundary { .. }
                        | CompiledSummaryEffect::Sanitize { .. } => {}
                    }
                }
            }
        }
        CompiledPayload::GeneratorRules { .. } => {}
    }
    let mut defined: Vec<_> = defined.into_iter().collect();
    let mut referenced: Vec<_> = referenced.into_iter().collect();
    defined.sort_unstable();
    referenced.sort_unstable();
    (defined, referenced)
}

fn procedure_target_inventory_id(target: &CompiledProcedureTarget) -> String {
    let bytes = canonical_json(&(target.path.as_str(), target.symbol.as_str()))
        .expect("procedure target identity is JSON serializable");
    format!(
        "{PROCEDURE_TARGET_INVENTORY_PREFIX}{}",
        digest_hex(PROCEDURE_TARGET_HASH_DOMAIN, &bytes)
    )
}

fn valid_inventory_id(id: &str) -> bool {
    if let Some(procedure_id) = id.strip_prefix(PROCEDURE_ID_INVENTORY_PREFIX) {
        validate_identifier(procedure_id, 256, true).is_ok()
    } else if let Some(target_digest) = id.strip_prefix(PROCEDURE_TARGET_INVENTORY_PREFIX) {
        is_lower_sha256(target_digest)
    } else {
        validate_identifier(id, 256, true).is_ok()
    }
}

fn collect_declared_type_refs(root: &TypeRef, ids: &mut HashSet<String>) {
    crate::analyzer::common::visit_declared_type_refs(std::iter::once(root), |id| {
        ids.insert(id.to_owned());
    });
}

fn authored_pack_from_compiled_shard(shard: &CompiledShard) -> AuthoredSemanticModelPack {
    AuthoredSemanticModelPack {
        schema_version: shard.schema_version,
        pack_id: shard.pack_id.clone(),
        version: shard.pack_version.clone(),
        producer: shard.producer.clone(),
        language: shard.language.clone(),
        ecosystem: shard.ecosystem.clone(),
        compatibility: shard.compatibility.clone(),
        provenance: shard.provenance.clone(),
        license: shard.license.clone(),
        completeness: shard.completeness,
        safety: shard.safety.clone(),
        carried_sources: Vec::new(),
        cpp_portability: shard.cpp_portability.clone(),
        python_correspondence: shard.python_correspondence.clone(),
        shards: vec![authored_shard_from_compiled(shard)],
    }
}

pub(crate) fn authored_pack_from_decoded_shards(
    manifest: &CompiledPackManifest,
    shards: &[CompiledShard],
) -> AuthoredSemanticModelPack {
    AuthoredSemanticModelPack {
        schema_version: manifest.schema_version,
        pack_id: manifest.pack_id.clone(),
        version: manifest.version.clone(),
        producer: manifest.producer.clone(),
        language: manifest.language.clone(),
        ecosystem: manifest.ecosystem.clone(),
        compatibility: manifest.compatibility.clone(),
        provenance: manifest.provenance.clone(),
        license: manifest.license.clone(),
        completeness: manifest.completeness,
        safety: manifest.safety.clone(),
        carried_sources: manifest.carried_sources.clone(),
        cpp_portability: manifest.cpp_portability.clone(),
        python_correspondence: manifest.python_correspondence.clone(),
        shards: shards.iter().map(authored_shard_from_compiled).collect(),
    }
}

fn authored_shard_from_compiled(shard: &CompiledShard) -> AuthoredShard {
    AuthoredShard {
        id: shard.shard_id.clone(),
        activation: shard.activation.clone(),
        payload: authored_payload_from_compiled(&shard.payload),
        runtime_values: shard.runtime_values.clone(),
        runtime_contracts: shard.runtime_contracts.clone(),
        collection_flows: shard.collection_flows.clone(),
        deferred_yields: shard.deferred_yields.clone(),
        conditional_type_refinements: shard.conditional_type_refinements.clone(),
        callable_values: shard.callable_values.clone(),
    }
}

fn authored_payload_from_compiled(payload: &CompiledPayload) -> AuthoredPayload {
    match payload {
        CompiledPayload::DeclarationFacts {
            types,
            members,
            relations,
        } => AuthoredPayload::DeclarationFacts {
            types: types.clone(),
            members: members.clone(),
            relations: relations.clone(),
        },
        CompiledPayload::GeneratorRules { rules } => AuthoredPayload::GeneratorRules {
            rules: rules.clone(),
        },
        CompiledPayload::ProcedureSummaries { summaries } => AuthoredPayload::ProcedureSummaries {
            summaries: summaries
                .iter()
                .map(authored_procedure_summary_from_compiled)
                .collect(),
        },
    }
}

fn authored_procedure_summary_from_compiled(
    summary: &CompiledProcedureSummary,
) -> AuthoredProcedureSummary {
    AuthoredProcedureSummary {
        id: summary.id.clone(),
        target: AuthoredProcedureTarget {
            path: summary.target.path.clone(),
            symbol: summary.target.symbol.clone(),
            has_receiver: summary.target.has_receiver,
            variadic: summary.target.variadic,
            parameter_count: summary.target.parameter_count,
            formals: summary.target.formals.clone(),
        },
        completeness: summary.completeness,
        ordinary_heap_unchanged: summary.ordinary_heap_unchanged,
        no_concurrency_effects: summary.no_concurrency_effects,
        covers_overrides: summary.covers_overrides,
        normal_continuation_absent: summary.normal_continuation_absent,
        normal_result_count: summary.normal_result_count,
        locations: summary
            .locations
            .iter()
            .map(|location| AuthoredSummaryLocation {
                id: location.id.clone(),
                location_kind: match location.location_kind {
                    CompiledSummaryLocationKind::Capture => AuthoredSummaryLocationKind::Capture,
                    CompiledSummaryLocationKind::Heap => AuthoredSummaryLocationKind::Heap,
                },
            })
            .collect(),
        transfers: summary
            .transfers
            .iter()
            .map(|transfer| AuthoredSummaryTransfer {
                input: authored_summary_input_from_compiled(&transfer.input),
                exit_kind: match transfer.exit_kind {
                    CompiledSummaryExitKind::Normal => AuthoredSummaryExitKind::Normal,
                    CompiledSummaryExitKind::Exceptional => AuthoredSummaryExitKind::Exceptional,
                },
                output: authored_summary_output_from_compiled(&transfer.output),
                value_transfer: transfer
                    .value_transfer
                    .as_ref()
                    .map(authored_summary_value_transfer_from_compiled),
            })
            .collect(),
        transfer_partitions: summary.transfer_partitions.clone(),
        effects: summary
            .effects
            .iter()
            .map(authored_summary_effect_from_compiled)
            .collect(),
        concurrency_effects: summary
            .concurrency_effects
            .iter()
            .map(authored_concurrency_effect_from_compiled)
            .collect(),
        returned_callables: summary
            .returned_callables
            .iter()
            .map(|callable| AuthoredReturnedCallable {
                result_ordinal: callable.result_ordinal,
                at_most_once: callable.at_most_once,
                concurrency_effects: callable
                    .concurrency_effects
                    .iter()
                    .map(authored_concurrency_effect_from_compiled)
                    .collect(),
            })
            .collect(),
        declared_effects: summary
            .declared_effects
            .iter()
            .map(authored_declared_effect_from_compiled)
            .collect(),
        preconditions: summary.preconditions.as_ref().map(|preconditions| {
            preconditions
                .iter()
                .map(|precondition| AuthoredOperationPrecondition {
                    input: authored_summary_input_from_compiled(&precondition.input),
                    predicate: authored_result_predicate_from_compiled(precondition.predicate),
                })
                .collect()
        }),
        result_contracts: summary
            .result_contracts
            .iter()
            .map(|contract| AuthoredResultContract {
                result_ordinal: contract.result_ordinal,
                condition_result_ordinal: contract.condition_result_ordinal,
                predicate: contract
                    .predicate
                    .map(authored_result_predicate_from_compiled),
                result_success_predicate: contract
                    .result_success_predicate
                    .map(authored_result_predicate_from_compiled),
                member_contracts: contract
                    .member_contracts
                    .iter()
                    .map(|member| AuthoredResultMemberContract {
                        member: member.member.clone(),
                        parameter_count: member.parameter_count,
                        completeness: member.completeness,
                        preconditions: member.preconditions.as_ref().map(|preconditions| {
                            preconditions
                                .iter()
                                .map(|precondition| AuthoredOperationPrecondition {
                                    input: authored_summary_input_from_compiled(
                                        &precondition.input,
                                    ),
                                    predicate: authored_result_predicate_from_compiled(
                                        precondition.predicate,
                                    ),
                                })
                                .collect()
                        }),
                        declared_effects: member
                            .declared_effects
                            .iter()
                            .map(authored_declared_effect_from_compiled)
                            .collect(),
                    })
                    .collect(),
            })
            .collect(),
        result_use_obligations: summary
            .result_use_obligations
            .iter()
            .map(|obligation| AuthoredResultUseObligation {
                result_ordinal: obligation.result_ordinal,
                kind: obligation.kind,
                failure_predicate: obligation
                    .failure_predicate
                    .map(authored_result_predicate_from_compiled),
            })
            .collect(),
        conditional_result_refinements: summary
            .conditional_result_refinements
            .iter()
            .map(|refinement| AuthoredConditionalResultRefinement {
                result_ordinal: refinement.result_ordinal,
                outcome: refinement.outcome,
                parameter_ordinal: refinement.parameter_ordinal,
                predicate: authored_result_predicate_from_compiled(refinement.predicate),
                proof_effect: match refinement.proof_effect {
                    CompiledPredicateProofEffect::Establishes => {
                        AuthoredPredicateProofEffect::Establishes
                    }
                    CompiledPredicateProofEffect::DoesNotEstablish => {
                        AuthoredPredicateProofEffect::DoesNotEstablish
                    }
                },
            })
            .collect(),
        conditional_indirect_writes: summary
            .conditional_indirect_writes
            .iter()
            .map(|write| AuthoredConditionalIndirectWrite {
                result_ordinal: write.result_ordinal,
                outcome: write.outcome,
                parameter_ordinal: write.parameter_ordinal,
                target: match write.target {
                    CompiledIndirectWriteTarget::Pointee => AuthoredIndirectWriteTarget::Pointee,
                },
            })
            .collect(),
        normal_return_refinements: summary
            .normal_return_refinements
            .iter()
            .map(|refinement| AuthoredNormalReturnRefinement {
                parameter_ordinal: refinement.parameter_ordinal,
                predicate: authored_result_predicate_from_compiled(refinement.predicate),
            })
            .collect(),
        normal_return_type_refinements: summary
            .normal_return_type_refinements
            .iter()
            .map(|refinement| AuthoredNormalReturnTypeRefinement {
                parameter_ordinal: refinement.parameter_ordinal,
                class_parameter_ordinal: refinement.class_parameter_ordinal,
                required_receiver_members: refinement.required_receiver_members.clone(),
            })
            .collect(),
        class_decorator_identity: summary.class_decorator_identity.as_ref().map(|identity| {
            AuthoredClassDecoratorIdentity {
                direct: identity.direct,
                factory_keywords: identity.factory_keywords.as_ref().map(|keywords| {
                    keywords
                        .iter()
                        .map(|keyword| AuthoredClassDecoratorKeyword {
                            name: keyword.name.clone(),
                            allowed_values: keyword.allowed_values.clone(),
                        })
                        .collect()
                }),
            }
        }),
    }
}

/// Prove the whole-manifest inventory invariants: no payload record id is
/// defined twice across shards, and every referenced id is defined.
///
/// The cost is proportional to every id in the manifest, so a reader that
/// decodes several shards of one manifest validates it once, not per shard
/// (#3101).
pub fn validate_manifest_inventory(manifest: &CompiledPackManifest) -> Result<(), ArtifactError> {
    let mut definitions = HashSet::new();
    let mut record_ids = HashSet::new();
    for descriptor in &manifest.shards {
        for id in &descriptor.defined_ids {
            if !definitions.insert(id) {
                return Err(ArtifactError::InvalidDescriptor(format!(
                    "payload record id `{id}` is defined more than once"
                )));
            }
            let record_id =
                if let Some(procedure_id) = id.strip_prefix(PROCEDURE_ID_INVENTORY_PREFIX) {
                    Some(procedure_id)
                } else if id.starts_with(PROCEDURE_TARGET_INVENTORY_PREFIX) {
                    None
                } else {
                    Some(id.as_str())
                };
            if let Some(record_id) = record_id
                && !record_ids.insert(record_id)
            {
                return Err(ArtifactError::InvalidDescriptor(format!(
                    "payload record id `{record_id}` is defined more than once"
                )));
            }
        }
    }
    for descriptor in &manifest.shards {
        for id in &descriptor.referenced_ids {
            if !definitions.contains(id) {
                return Err(ArtifactError::InvalidDescriptor(format!(
                    "payload record id `{id}` is referenced but not defined"
                )));
            }
        }
    }
    Ok(())
}

fn validate_text(
    value: &str,
    limits: &DecodeLimits,
    field: &'static str,
) -> Result<(), ArtifactError> {
    if value.is_empty() || value.len() > limits.max_text_bytes || value.contains('\0') {
        return Err(ArtifactError::InvalidDescriptor(format!(
            "{field} is empty, too long, or contains NUL"
        )));
    }
    Ok(())
}

/// Decoding accepts every supported schema version, not only the one this
/// build mints: an installed artifact keeps loading across a version bump and
/// is regenerated on its producer's normal cadence.
fn require_version(version: u32) -> Result<(), ArtifactError> {
    if SEMANTIC_MODEL_SUPPORTED_SCHEMA_VERSIONS.contains(&version) {
        Ok(())
    } else {
        Err(ArtifactError::UnsupportedVersion(version))
    }
}

fn digest_hex(domain: &[u8], bytes: &[u8]) -> String {
    lower_hex_string(&hash_domain_bytes(domain, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic_model::{
        CompilerOptions, CompressionPolicy, SourceFormat,
        VERSION_INDEPENDENT_COMPATIBILITY_SCHEMA_VERSION, compile_pack, compile_source,
    };
    use flate2::Compression;
    use flate2::write::DeflateEncoder;
    use std::io::Write;

    const DECLARATIONS: &[u8] =
        include_bytes!("../../../testdata/semantic-model-packs/declarations-v1.json");
    const PROCEDURE_SUMMARIES: &[u8] =
        include_bytes!("../../../testdata/semantic-model-packs/procedure-summaries-v1.json");

    #[test]
    fn structured_procedure_formals_require_schema_eleven_and_round_trip() {
        let mut source: serde_json::Value = serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
        source["schema_version"] = 11.into();
        source["compatibility"]
            .as_object_mut()
            .unwrap()
            .remove("bifrost");
        source["shards"][0]["payload"]["summaries"][0]["target"]["formals"] =
            serde_json::json!([{"name": "value", "optional": true}]);
        let compiled = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&source).unwrap(),
            &CompilerOptions::default(),
        )
        .expect("schema eleven accepts structured procedure formals");
        let shard = decode_shard(
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .expect("structured procedure formals decode");
        let summaries = shard.payload().procedure_summaries().unwrap();
        assert_eq!(summaries[0].target.formals.len(), 1);
        assert_eq!(summaries[0].target.formals[0].name, "value");
        assert!(summaries[0].target.formals[0].optional);

        source["schema_version"] = 10.into();
        let diagnostics = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&source).unwrap(),
            &CompilerOptions::default(),
        )
        .expect_err("schema ten cannot carry structured formals");
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| { diagnostic.code == "summary.formals_schema_version" })
        );
    }

    #[test]
    fn schema_eight_compiles_without_engine_gate_and_keeps_partial_state() {
        let mut authored: AuthoredSemanticModelPack = serde_json::from_slice(DECLARATIONS).unwrap();
        let legacy = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        assert_eq!(legacy.manifest.schema_version, 2);
        assert!(legacy.manifest.compatibility.bifrost.is_some());
        decode_manifest(&legacy.manifest_bytes, &DecodeLimits::default()).unwrap();

        authored.schema_version = VERSION_INDEPENDENT_COMPATIBILITY_SCHEMA_VERSION;
        authored.compatibility.bifrost = None;
        authored.completeness = Completeness::Partial;
        let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        let manifest_json: serde_json::Value =
            serde_json::from_slice(&compiled.manifest_bytes).unwrap();
        assert_eq!(
            manifest_json["schema_version"],
            VERSION_INDEPENDENT_COMPATIBILITY_SCHEMA_VERSION
        );
        assert!(manifest_json["compatibility"].get("bifrost").is_none());
        assert!(manifest_json["compatibility"].get("toolchains").is_some());
        let decoded = decode_manifest(&compiled.manifest_bytes, &DecodeLimits::default()).unwrap();
        assert_eq!(decoded.compatibility.bifrost, None);
        assert_eq!(decoded.completeness, Completeness::Partial);

        let mut forbidden_gate = manifest_json.clone();
        forbidden_gate["compatibility"]["bifrost"] = serde_json::json!("*");
        let forbidden_gate_bytes = canonical_json(&forbidden_gate).unwrap();
        assert!(matches!(
            decode_manifest(&forbidden_gate_bytes, &DecodeLimits::default()),
            Err(ArtifactError::InvalidDescriptor(message)) if message == "schema 8 and later forbid compatibility.bifrost"
        ));

        let mut null_gate = manifest_json.clone();
        null_gate["compatibility"]["bifrost"] = serde_json::Value::Null;
        let null_gate_bytes = canonical_json(&null_gate).unwrap();
        assert!(matches!(
            decode_manifest(&null_gate_bytes, &DecodeLimits::default()),
            Err(ArtifactError::InvalidJson(_))
        ));

        let mut missing_legacy_gate: serde_json::Value =
            serde_json::from_slice(&legacy.manifest_bytes).unwrap();
        missing_legacy_gate["compatibility"]
            .as_object_mut()
            .unwrap()
            .remove("bifrost");
        let missing_legacy_bytes = canonical_json(&missing_legacy_gate).unwrap();
        assert!(matches!(
            decode_manifest(&missing_legacy_bytes, &DecodeLimits::default()),
            Err(ArtifactError::InvalidDescriptor(message)) if message.contains("requires")
        ));

        let unsupported_schema_version = SEMANTIC_MODEL_SCHEMA_VERSION + 1;
        let mut unknown_schema = manifest_json.clone();
        unknown_schema["schema_version"] = serde_json::json!(unsupported_schema_version);
        let unknown_schema_bytes = canonical_json(&unknown_schema).unwrap();
        assert_eq!(
            decode_manifest(&unknown_schema_bytes, &DecodeLimits::default()),
            Err(ArtifactError::UnsupportedVersion(
                unsupported_schema_version
            ))
        );

        let mut missing_legacy = authored.clone();
        missing_legacy.schema_version = 7;
        assert!(
            compile_pack(&missing_legacy, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| diagnostic.code == "compatibility.schema_shape")
        );

        let mut mixed_schema_eight = authored.clone();
        mixed_schema_eight.compatibility.bifrost = Some("=0.12.0".to_owned());
        assert!(
            compile_pack(&mixed_schema_eight, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| diagnostic.code == "compatibility.schema_shape")
        );

        let mut unknown_schema = authored;
        unknown_schema.schema_version = unsupported_schema_version;
        assert!(
            compile_pack(&unknown_schema, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| diagnostic.code == "schema.unsupported_version")
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#3815: schema-aware native-pack compatibility disagreed across authoring and compilation"
    )]
    #[test]
    fn authoring_schema_and_rust_compiler_agree_on_engine_gate_shapes() {
        let schema: serde_json::Value =
            serde_json::from_str(&crate::analyzer::semantic_model::authoring_json_schema())
                .unwrap();
        let validator = jsonschema::draft202012::new(&schema)
            .expect("semantic-model authoring schema is valid Draft 2020-12");
        let fixture: serde_json::Value = serde_json::from_slice(DECLARATIONS).unwrap();

        let assert_agreement = |value: &serde_json::Value, accepted: bool| {
            assert_eq!(validator.is_valid(value), accepted);
            let bytes = serde_json::to_vec(value).unwrap();
            assert_eq!(
                compile_source(SourceFormat::Json, &bytes, &CompilerOptions::default()).is_ok(),
                accepted
            );
        };

        assert_agreement(&fixture, true);

        let mut missing_legacy_gate = fixture.clone();
        missing_legacy_gate["compatibility"]
            .as_object_mut()
            .unwrap()
            .remove("bifrost");
        assert_agreement(&missing_legacy_gate, false);

        let mut native = fixture;
        native["schema_version"] = serde_json::json!(SEMANTIC_MODEL_SCHEMA_VERSION);
        native["compatibility"]
            .as_object_mut()
            .unwrap()
            .remove("bifrost");
        native["compatibility"]
            .as_object_mut()
            .unwrap()
            .remove("toolchains");
        assert_agreement(&native, true);
        let decoded: AuthoredSemanticModelPack = serde_json::from_value(native.clone()).unwrap();
        assert!(decoded.compatibility.bifrost.is_none());
        assert!(decoded.compatibility.toolchains.is_empty());

        let mut native_with_gate = native.clone();
        native_with_gate["compatibility"]["bifrost"] = serde_json::json!("=0.12.0");
        assert_agreement(&native_with_gate, false);

        let mut native_with_null_gate = native;
        native_with_null_gate["compatibility"]["bifrost"] = serde_json::Value::Null;
        assert_agreement(&native_with_null_gate, false);
    }

    #[test]
    fn callable_inventory_round_trips_only_in_its_schema() {
        let mut authored: AuthoredSemanticModelPack = serde_json::from_slice(DECLARATIONS).unwrap();
        authored.schema_version = CALLABLE_SURFACE_MIN_SCHEMA_VERSION;
        let AuthoredPayload::DeclarationFacts { types, .. } = &mut authored.shards[0].payload
        else {
            unreachable!()
        };
        types[0].callable_surface_complete = true;
        let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        let decoded = decode_shard_for_manifest(
            &compiled.manifest,
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        assert!(decoded.payload().declaration_facts().unwrap().0[0].callable_surface_complete);
        authored.schema_version = CALLABLE_SURFACE_MIN_SCHEMA_VERSION - 1;
        assert!(
            compile_pack(&authored, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| diagnostic.code == "schema.callable_surface_version")
        );
    }

    fn callable_values_authored_pack() -> AuthoredSemanticModelPack {
        let mut authored: AuthoredSemanticModelPack = serde_json::from_slice(DECLARATIONS).unwrap();
        authored.schema_version = CALLABLE_VALUES_MIN_SCHEMA_VERSION;
        authored.compatibility.bifrost = None;
        authored.language = "go".to_owned();
        let digest = "b".repeat(64);
        for selector in &mut authored.shards[0].activation {
            selector.artifact_sha256 = Some(digest.clone());
        }
        let literal_id = "go.literal.callback".to_owned();
        authored.shards[0].callable_values = Some(CallableValuesPayload {
            facts: vec![CallableValuesFact {
                payload: crate::analyzer::semantic_model::csmi::CsmiCallableValuesPayload::ReturnedCallable {
                    callable: "member.widget.create".to_owned(),
                    result: 0,
                    target: literal_id.clone(),
                },
                provenance: vec!["opaque.producer.fact".to_owned()],
            }],
            coverage: vec![CallableValuesCoverage {
                family: CallableValuesFamily::ReturnedCallables,
                callable: "member.widget.create".to_owned(),
                status: crate::analyzer::semantic_model::csmi::CsmiCoverageStatus::Partial,
                limitations: Vec::new(),
                provenance: vec!["opaque.producer.coverage".to_owned()],
            }],
            anonymous_callables: vec![AnonymousCallableIdentity {
                id: literal_id,
                artifact_sha256: digest,
                package_identity: "example.test/module/pkg".to_owned(),
                anchor: crate::analyzer::semantic_model::SourceAnchor {
                    file: "callbacks.go".to_owned(),
                    byte_range: crate::analyzer::semantic_model::SourceByteRange { start: 20, end: 50 },
                    kind: crate::analyzer::semantic_model::SourceDeclarationKind::FunctionLiteral,
                },
                lexical_owner_chain: vec![crate::analyzer::semantic_model::SourceAnchor {
                    file: "callbacks.go".to_owned(),
                    byte_range: crate::analyzer::semantic_model::SourceByteRange { start: 0, end: 100 },
                    kind: crate::analyzer::semantic_model::SourceDeclarationKind::Function,
                }],
                signature: crate::analyzer::semantic_model::SourceCallableShape {
                    function_type: crate::analyzer::semantic_model::SourceTypeNode {
                        file: "callbacks.go".to_owned(),
                        byte_range: crate::analyzer::semantic_model::SourceByteRange { start: 20, end: 35 },
                    },
                    parameters: Vec::new(),
                    results: Vec::new(),
                    declaration_chain: Vec::new(),
                },
            }],
        });
        authored
    }

    #[test]
    fn callable_values_encode_decode_hash_and_preserve_old_wire_shape() {
        let authored = callable_values_authored_pack();
        let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        assert_eq!(
            compiled.manifest.schema_version,
            CALLABLE_VALUES_MIN_SCHEMA_VERSION
        );
        use crate::analyzer::semantic_model::csmi::{
            CsmiArtifactEvidence, CsmiExportError, CsmiExportOptions, export_csmi_pack,
            export_runtime_contracts_csmi_pack,
        };
        let options = CsmiExportOptions::default();
        let artifact = CsmiArtifactEvidence::new("pkg:generic/test@1.0.0", "a".repeat(64));
        // This generic selector is insufficient for the artifact-local Go
        // source mapping. Standard export now supports properly pinned Go
        // callable-values; runtime-contract export still refuses the carrier.
        assert!(matches!(
            export_csmi_pack(&compiled, &artifact, &options).unwrap_err(),
            CsmiExportError::InvalidEvidence(message)
                if message.contains("exact versioned pkg:golang PURL")
        ));
        assert!(matches!(
            export_runtime_contracts_csmi_pack(&compiled, &options).unwrap_err(),
            CsmiExportError::Unsupported { path, .. } if path.ends_with(".callable_values")
        ));
        let (wire, _) = read_shard_wire(
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        assert!(wire.callable_values.is_some());

        let decoded = decode_shard_for_manifest(
            &compiled.manifest,
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        let callable_values = decoded.callable_values().expect("carrier round-trips");
        assert_eq!(callable_values.record_count(), 3);
        assert_eq!(callable_values.anonymous_callables.len(), 1);
        assert_eq!(
            callable_values.anonymous_callables[0].id,
            "go.literal.callback"
        );
        assert!(
            compiled.shards[0]
                .descriptor
                .defined_ids
                .iter()
                .any(|id| id == "go.literal.callback")
        );
        assert!(
            compiled.shards[0]
                .descriptor
                .referenced_ids
                .iter()
                .any(|id| id == "go.literal.callback")
        );
        assert_eq!(
            decoded.record_count(),
            compiled.shards[0].descriptor.record_count as usize
        );

        let mut changed = authored.clone();
        changed.shards[0].callable_values.as_mut().unwrap().facts[0]
            .provenance
            .push("opaque.producer.changed".to_owned());
        let changed_compiled = compile_pack(&changed, &CompilerOptions::default()).unwrap();
        assert_ne!(
            compiled.shards[0].descriptor.semantic_sha256,
            changed_compiled.shards[0].descriptor.semantic_sha256
        );

        let legacy: AuthoredSemanticModelPack = serde_json::from_slice(DECLARATIONS).unwrap();
        let legacy_compiled = compile_pack(&legacy, &CompilerOptions::default()).unwrap();
        let (legacy_wire, _) = read_shard_wire(
            &legacy_compiled.shards[0].descriptor,
            &legacy_compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        assert!(legacy_wire.callable_values.is_none());
    }

    #[test]
    fn callable_values_schema_floor_and_bad_references_fail_closed() {
        let mut old_schema = callable_values_authored_pack();
        old_schema.schema_version = CALLABLE_VALUES_MIN_SCHEMA_VERSION - 1;
        let diagnostics = compile_pack(&old_schema, &CompilerOptions::default()).unwrap_err();
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "schema.callable_values_version")
        );

        let mut bad_reference = callable_values_authored_pack();
        let Some(CallableValuesPayload { facts, .. }) =
            bad_reference.shards[0].callable_values.as_mut()
        else {
            unreachable!();
        };
        let crate::analyzer::semantic_model::csmi::CsmiCallableValuesPayload::ReturnedCallable {
            target,
            ..
        } = &mut facts[0].payload
        else {
            unreachable!();
        };
        *target = "missing.callable".to_owned();
        let diagnostics = compile_pack(&bad_reference, &CompilerOptions::default()).unwrap_err();
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "callable_values.symbol_reference")
        );
    }

    #[test]
    fn anonymous_callable_targets_require_exact_artifact_owner_range_and_unique_id() {
        let mut wrong_artifact = callable_values_authored_pack();
        wrong_artifact.shards[0]
            .callable_values
            .as_mut()
            .unwrap()
            .anonymous_callables[0]
            .artifact_sha256 = "c".repeat(64);
        let diagnostics = compile_pack(&wrong_artifact, &CompilerOptions::default()).unwrap_err();
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "callable_values.anonymous_artifact")
        );

        let mut wrong_owner = callable_values_authored_pack();
        wrong_owner.shards[0]
            .callable_values
            .as_mut()
            .unwrap()
            .anonymous_callables[0]
            .lexical_owner_chain[0]
            .byte_range
            .start = 25;
        let diagnostics = compile_pack(&wrong_owner, &CompilerOptions::default()).unwrap_err();
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "callable_values.anonymous_owner")
        );

        let mut wrong_range = callable_values_authored_pack();
        wrong_range.shards[0]
            .callable_values
            .as_mut()
            .unwrap()
            .anonymous_callables[0]
            .signature
            .function_type
            .byte_range
            .start = 21;
        let diagnostics = compile_pack(&wrong_range, &CompilerOptions::default()).unwrap_err();
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "callable_values.anonymous_signature")
        );

        let mut duplicate = callable_values_authored_pack();
        let identity = duplicate.shards[0]
            .callable_values
            .as_ref()
            .unwrap()
            .anonymous_callables[0]
            .clone();
        duplicate.shards[0]
            .callable_values
            .as_mut()
            .unwrap()
            .anonymous_callables
            .push(identity);
        let diagnostics = compile_pack(&duplicate, &CompilerOptions::default()).unwrap_err();
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| { diagnostic.code == "callable_values.anonymous_duplicate_id" })
        );
    }

    #[test]
    fn field_member_with_signature_is_not_a_callable_values_factory() {
        let mut authored = callable_values_authored_pack();
        let AuthoredPayload::DeclarationFacts { members, .. } = &mut authored.shards[0].payload
        else {
            unreachable!();
        };
        let factory = members
            .iter_mut()
            .find(|member| member.id == "member.widget.create")
            .expect("fixture factory member");
        factory.member_kind = MemberKind::Field;
        let diagnostics = compile_pack(&authored, &CompilerOptions::default()).unwrap_err();
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "callable_values.factory")
        );
    }

    #[test]
    fn unknown_type_refs_compile_and_decode_in_schema_nine() {
        let mut authored: AuthoredSemanticModelPack = serde_json::from_slice(DECLARATIONS).unwrap();
        authored.schema_version = UNKNOWN_TYPE_MIN_SCHEMA_VERSION;
        authored.compatibility.bifrost = None;
        let AuthoredPayload::DeclarationFacts { members, .. } = &mut authored.shards[0].payload
        else {
            unreachable!();
        };
        let signature = members[0]
            .signature
            .as_mut()
            .expect("fixture member has a signature");
        let original_parameter_count = signature.parameters.len();
        let original_parameter_name = signature.parameters[0].name.clone();
        let original_parameter_optional = signature.parameters[0].optional;
        let original_parameter_variadic = signature.parameters[0].variadic;
        let original_passing_mode = signature.parameters[0].passing_mode;
        signature.parameters[0].r#type = TypeRef::Named {
            name: "typing.Optional".to_owned(),
            arguments: vec![TypeRef::Unknown],
            nullable: false,
        };
        signature.returns = Some(TypeRef::Unknown);

        let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        let decoded = decode_shard_for_manifest(
            &compiled.manifest,
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        let (_, members, _) = decoded.payload().declaration_facts().unwrap();
        let signature = members[0]
            .signature
            .as_ref()
            .expect("decoded fixture member has a signature");
        assert!(signature.contains_unknown_types());
        assert_eq!(signature.parameters.len(), original_parameter_count);
        assert_eq!(signature.parameters[0].name, original_parameter_name);
        assert_eq!(
            signature.parameters[0].optional,
            original_parameter_optional
        );
        assert_eq!(
            signature.parameters[0].variadic,
            original_parameter_variadic
        );
        assert_eq!(signature.parameters[0].passing_mode, original_passing_mode);
        assert_eq!(
            signature.parameters[0].r#type,
            TypeRef::Named {
                name: "typing.Optional".to_owned(),
                arguments: vec![TypeRef::Unknown],
                nullable: false,
            }
        );
        assert_eq!(signature.returns, Some(TypeRef::Unknown));

        authored.schema_version = UNKNOWN_TYPE_MIN_SCHEMA_VERSION - 1;
        assert!(
            compile_pack(&authored, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| {
                    diagnostic.code == "schema.unknown_type_version"
                        && diagnostic.path.ends_with("signature.returns")
                })
        );
    }

    #[test]
    fn callable_parameter_roles_require_schema_fifteen_and_round_trip() {
        let mut authored: AuthoredSemanticModelPack = serde_json::from_slice(DECLARATIONS).unwrap();
        authored.schema_version = TYPED_VALUES_AND_PARAMETER_ROLES_MIN_SCHEMA_VERSION;
        authored.compatibility.bifrost = None;
        let AuthoredPayload::DeclarationFacts { members, .. } = &mut authored.shards[0].payload
        else {
            unreachable!();
        };
        members[0]
            .signature
            .as_mut()
            .expect("fixture member has a signature")
            .parameters[0]
            .role = Some(ParameterRole::Request);

        let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        let decoded = decode_shard_for_manifest(
            &compiled.manifest,
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        let (_, members, _) = decoded.payload().declaration_facts().unwrap();
        assert_eq!(
            members[0].signature.as_ref().unwrap().parameters[0].role,
            Some(ParameterRole::Request)
        );

        authored.schema_version -= 1;
        assert!(
            compile_pack(&authored, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| diagnostic.code == "parameter.role_schema_version")
        );
    }

    #[test]
    fn exact_return_class_sets_require_schema_sixteen() {
        let mut authored: AuthoredSemanticModelPack = serde_json::from_slice(DECLARATIONS).unwrap();
        authored.schema_version = EXACT_RETURN_CLASSES_MIN_SCHEMA_VERSION;
        authored.compatibility.bifrost = None;
        let AuthoredPayload::DeclarationFacts { members, .. } = &mut authored.shards[0].payload
        else {
            unreachable!();
        };
        members[0].exact_return_classes = members[0]
            .signature
            .as_ref()
            .and_then(|signature| signature.returns.clone())
            .into_iter()
            .collect();

        compile_pack(&authored, &CompilerOptions::default()).unwrap();

        authored.schema_version = EXACT_RETURN_CLASSES_MIN_SCHEMA_VERSION - 1;
        assert!(
            compile_pack(&authored, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| {
                    diagnostic.code == "declaration.exact_return_classes_schema_version"
                        && diagnostic.path.ends_with("exact_return_classes")
                })
        );
    }

    #[test]
    fn reviewed_result_use_obligation_round_trips_and_rejects_unsupported_claims() {
        let mut authored: AuthoredSemanticModelPack =
            serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
        authored.schema_version = RESULT_USE_OBLIGATIONS_MIN_SCHEMA_VERSION;
        let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload
        else {
            unreachable!()
        };
        let summary = &mut summaries[1];
        summary.effects.clear();
        summary.ordinary_heap_unchanged = true;
        summary.normal_result_count = Some(1);
        summary.result_use_obligations = vec![AuthoredResultUseObligation {
            result_ordinal: 0,
            kind: ResultUseObligationKind::PureTransformationValue,
            failure_predicate: None,
        }];
        let expected = summary.clone();

        let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        let decoded = decode_shard_for_manifest(
            &compiled.manifest,
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        let observed = &decoded.payload().procedure_summaries().unwrap()[1];
        assert_eq!(observed.result_use_obligations.len(), 1);
        assert_eq!(authored_procedure_summary_from_compiled(observed), expected);

        let mut rejected = authored.clone();
        rejected.schema_version = RESULT_USE_OBLIGATIONS_MIN_SCHEMA_VERSION - 1;
        assert!(
            compile_pack(&rejected, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| diagnostic.code == "summary.result_use_obligations_schema")
        );
        rejected.schema_version = RESULT_USE_OBLIGATIONS_MIN_SCHEMA_VERSION;
        if let AuthoredPayload::ProcedureSummaries { summaries } = &mut rejected.shards[0].payload {
            summaries[1].result_use_obligations[0].result_ordinal = 1;
        } else {
            unreachable!()
        }
        assert!(
            compile_pack(&rejected, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| diagnostic.code == "summary.result_ordinal_out_of_range")
        );
        if let AuthoredPayload::ProcedureSummaries { summaries } = &mut rejected.shards[0].payload {
            summaries[1].result_use_obligations[0].result_ordinal = 0;
            summaries[1].ordinary_heap_unchanged = false;
        } else {
            unreachable!()
        }
        assert!(
            compile_pack(&rejected, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| diagnostic.code
                    == "summary.pure_result_has_unreviewed_heap_effects")
        );

        let mut status = authored.clone();
        if let AuthoredPayload::ProcedureSummaries { summaries } = &mut status.shards[0].payload {
            summaries[1].ordinary_heap_unchanged = false;
            summaries[1].result_use_obligations[0] = AuthoredResultUseObligation {
                result_ordinal: 0,
                kind: ResultUseObligationKind::FallibleStatus,
                failure_predicate: Some(AuthoredResultPredicate::False),
            };
            summaries[1].completeness = Completeness::Partial;
            summaries[1].transfers.clear();
        } else {
            unreachable!()
        }
        assert!(compile_pack(&status, &CompilerOptions::default()).is_ok());
        if let AuthoredPayload::ProcedureSummaries { summaries } = &mut status.shards[0].payload {
            summaries[1].result_use_obligations[0].failure_predicate = None;
        } else {
            unreachable!()
        }
        assert!(
            compile_pack(&status, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| diagnostic.code
                    == "summary.fallible_status_needs_failure_predicate")
        );
    }

    #[test]
    fn control_only_normal_continuation_absence_round_trips() {
        let mut authored: AuthoredSemanticModelPack =
            serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
        let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload
        else {
            unreachable!()
        };
        let authored_summary = &mut summaries[1];
        authored_summary.completeness = Completeness::Partial;
        authored_summary.normal_continuation_absent = true;
        authored_summary.transfers.clear();
        authored_summary.effects.clear();
        let expected = authored_summary.clone();

        let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        let decoded = decode_shard_for_manifest(
            &compiled.manifest,
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        let summary = &decoded.payload().procedure_summaries().unwrap()[1];
        assert!(summary.normal_continuation_absent);
        assert_eq!(
            authored_procedure_summary_from_compiled(summary),
            expected,
            "compiled-to-authored defensive reconstruction preserves the claim"
        );
        assert!(
            String::from_utf8(canonical_json(summary).unwrap())
                .unwrap()
                .contains("\"normal_continuation_absent\":true")
        );
    }

    #[test]
    fn normal_return_type_refinements_compile_decode_and_validate() {
        let mut authored: AuthoredSemanticModelPack =
            serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
        let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload
        else {
            unreachable!()
        };
        let authored_summary = &mut summaries[1];
        authored_summary.target.parameter_count = 3;
        authored_summary.target.has_receiver = true;
        authored_summary.transfers.clear();
        authored_summary.effects.clear();
        authored_summary.locations.clear();
        authored_summary.completeness = Completeness::Partial;
        authored_summary.normal_return_type_refinements = vec![
            AuthoredNormalReturnTypeRefinement {
                parameter_ordinal: 1,
                class_parameter_ordinal: 2,
                required_receiver_members: vec!["helper".to_owned(), "fail".to_owned()],
            },
            AuthoredNormalReturnTypeRefinement {
                parameter_ordinal: 0,
                class_parameter_ordinal: 1,
                required_receiver_members: Vec::new(),
            },
        ];
        let mut expected = authored_summary.clone();
        expected.normal_return_type_refinements[0]
            .required_receiver_members
            .sort();
        expected.normal_return_type_refinements.sort();

        let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        let decoded = decode_shard_for_manifest(
            &compiled.manifest,
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        let summary = decoded
            .payload()
            .procedure_summaries()
            .unwrap()
            .iter()
            .find(|summary| summary.id == expected.id)
            .unwrap();
        assert_eq!(
            summary.normal_return_type_refinements,
            vec![
                CompiledNormalReturnTypeRefinement {
                    parameter_ordinal: 0,
                    class_parameter_ordinal: 1,
                    required_receiver_members: Vec::new(),
                },
                CompiledNormalReturnTypeRefinement {
                    parameter_ordinal: 1,
                    class_parameter_ordinal: 2,
                    required_receiver_members: vec!["fail".to_owned(), "helper".to_owned()],
                },
            ]
        );
        assert_eq!(authored_procedure_summary_from_compiled(summary), expected);
        assert!(
            String::from_utf8(canonical_json(summary).unwrap())
                .unwrap()
                .contains("\"normal_return_type_refinements\"")
        );

        let empty: AuthoredSemanticModelPack = serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
        let empty_summary = match &empty.shards[0].payload {
            AuthoredPayload::ProcedureSummaries { summaries } => &summaries[1],
            _ => unreachable!(),
        };
        assert!(
            !String::from_utf8(canonical_json(empty_summary).unwrap())
                .unwrap()
                .contains("normal_return_type_refinements")
        );

        fn diagnostics_for(
            refinements: Vec<AuthoredNormalReturnTypeRefinement>,
            parameter_count: u32,
            variadic: bool,
            has_receiver: bool,
        ) -> Vec<Diagnostic> {
            let mut authored: AuthoredSemanticModelPack =
                serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
            let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload
            else {
                unreachable!()
            };
            let summary = &mut summaries[1];
            summary.target.parameter_count = parameter_count;
            summary.target.variadic = variadic;
            summary.target.has_receiver = has_receiver;
            summary.normal_return_type_refinements = refinements;
            compile_pack(&authored, &CompilerOptions::default()).unwrap_err()
        }

        assert!(
            diagnostics_for(
                vec![AuthoredNormalReturnTypeRefinement {
                    parameter_ordinal: 1,
                    class_parameter_ordinal: 0,
                    required_receiver_members: Vec::new(),
                }],
                1,
                false,
                false,
            )
            .iter()
            .any(|diagnostic| diagnostic.code == "summary.parameter_ordinal_out_of_range")
        );
        assert!(
            diagnostics_for(
                vec![AuthoredNormalReturnTypeRefinement {
                    parameter_ordinal: 0,
                    class_parameter_ordinal: 0,
                    required_receiver_members: Vec::new(),
                }],
                1,
                false,
                false,
            )
            .iter()
            .any(|diagnostic| {
                diagnostic.code == "summary.same_normal_return_type_refinement_parameter"
            })
        );
        assert!(
            diagnostics_for(
                vec![
                    AuthoredNormalReturnTypeRefinement {
                        parameter_ordinal: 0,
                        class_parameter_ordinal: 1,
                        required_receiver_members: Vec::new(),
                    },
                    AuthoredNormalReturnTypeRefinement {
                        parameter_ordinal: 0,
                        class_parameter_ordinal: 1,
                        required_receiver_members: Vec::new(),
                    },
                ],
                2,
                false,
                false,
            )
            .iter()
            .any(|diagnostic| {
                diagnostic.code == "summary.duplicate_normal_return_type_refinement"
            })
        );
        assert!(
            diagnostics_for(
                vec![
                    AuthoredNormalReturnTypeRefinement {
                        parameter_ordinal: 0,
                        class_parameter_ordinal: 1,
                        required_receiver_members: Vec::new(),
                    },
                    AuthoredNormalReturnTypeRefinement {
                        parameter_ordinal: 0,
                        class_parameter_ordinal: 2,
                        required_receiver_members: Vec::new(),
                    },
                ],
                3,
                false,
                false,
            )
            .iter()
            .any(|diagnostic| {
                diagnostic.code == "summary.conflicting_normal_return_type_refinement"
            })
        );
        assert!(
            diagnostics_for(
                vec![AuthoredNormalReturnTypeRefinement {
                    parameter_ordinal: 0,
                    class_parameter_ordinal: 1,
                    required_receiver_members: Vec::new(),
                }],
                2,
                true,
                false,
            )
            .iter()
            .any(|diagnostic| diagnostic.code == "summary.unsupported_variadic_tail_reference")
        );
        assert!(
            diagnostics_for(
                vec![AuthoredNormalReturnTypeRefinement {
                    parameter_ordinal: 0,
                    class_parameter_ordinal: 1,
                    required_receiver_members: vec!["fail".to_owned()],
                }],
                2,
                false,
                false,
            )
            .iter()
            .any(|diagnostic| {
                diagnostic.code == "summary.required_receiver_members_without_receiver"
            })
        );
        assert!(
            diagnostics_for(
                vec![AuthoredNormalReturnTypeRefinement {
                    parameter_ordinal: 0,
                    class_parameter_ordinal: 1,
                    required_receiver_members: vec!["fail".to_owned(), "fail".to_owned()],
                }],
                2,
                false,
                true,
            )
            .iter()
            .any(|diagnostic| { diagnostic.code == "summary.duplicate_required_receiver_member" })
        );
        assert!(
            diagnostics_for(
                vec![AuthoredNormalReturnTypeRefinement {
                    parameter_ordinal: 0,
                    class_parameter_ordinal: 1,
                    required_receiver_members: vec![String::new()],
                }],
                2,
                false,
                true,
            )
            .iter()
            .any(|diagnostic| diagnostic.code == "text.empty")
        );
        let bounded_members = (0..=MAX_NORMAL_RETURN_TYPE_REFINEMENT_RECEIVER_MEMBERS)
            .map(|index| format!("member{index}"))
            .collect();
        assert!(
            diagnostics_for(
                vec![AuthoredNormalReturnTypeRefinement {
                    parameter_ordinal: 0,
                    class_parameter_ordinal: 1,
                    required_receiver_members: bounded_members,
                }],
                2,
                false,
                true,
            )
            .iter()
            .any(|diagnostic| {
                diagnostic.code == "limit.normal_return_type_refinement_receiver_members"
            })
        );
    }

    #[test]
    fn class_decorator_identity_compile_decode_and_canonicalize() {
        let mut authored: AuthoredSemanticModelPack =
            serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
        let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload
        else {
            unreachable!()
        };
        let summary = &mut summaries[1];
        summary.class_decorator_identity = Some(AuthoredClassDecoratorIdentity {
            direct: false,
            factory_keywords: Some(vec![
                AuthoredClassDecoratorKeyword {
                    name: "slots".to_owned(),
                    allowed_values: vec![true, false],
                },
                AuthoredClassDecoratorKeyword {
                    name: "frozen".to_owned(),
                    allowed_values: vec![false],
                },
            ]),
        });
        let mut expected = summary.clone();
        let identity = expected.class_decorator_identity.as_mut().unwrap();
        let keywords = identity.factory_keywords.as_mut().unwrap();
        for keyword in keywords.iter_mut() {
            keyword.allowed_values.sort_unstable();
        }
        keywords.sort();

        let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        let decoded = decode_shard_for_manifest(
            &compiled.manifest,
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        let compiled_summary = decoded
            .payload()
            .procedure_summaries()
            .unwrap()
            .iter()
            .find(|candidate| candidate.id == expected.id)
            .unwrap();
        assert_eq!(
            compiled_summary.class_decorator_identity,
            Some(CompiledClassDecoratorIdentity {
                direct: false,
                factory_keywords: Some(vec![
                    CompiledClassDecoratorKeyword {
                        name: "frozen".to_owned(),
                        allowed_values: vec![false],
                    },
                    CompiledClassDecoratorKeyword {
                        name: "slots".to_owned(),
                        allowed_values: vec![false, true],
                    },
                ]),
            })
        );
        let round_tripped = authored_procedure_summary_from_compiled(compiled_summary);
        assert_eq!(
            round_tripped.class_decorator_identity, expected.class_decorator_identity,
            "the decorator identity claim survives authored/compiled round-trip"
        );
        assert!(
            String::from_utf8(canonical_json(compiled_summary).unwrap())
                .unwrap()
                .contains("\"class_decorator_identity\"")
        );

        let omitted: AuthoredSemanticModelPack =
            serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
        let omitted_summary = match &omitted.shards[0].payload {
            AuthoredPayload::ProcedureSummaries { summaries } => &summaries[1],
            _ => unreachable!(),
        };
        assert!(
            !String::from_utf8(canonical_json(omitted_summary).unwrap())
                .unwrap()
                .contains("class_decorator_identity")
        );
    }

    #[test]
    fn class_decorator_identity_validation_rejects_unsafe_claims() {
        fn diagnostics_for(
            target: AuthoredProcedureTarget,
            completeness: Completeness,
            identity: AuthoredClassDecoratorIdentity,
            normal_continuation_absent: bool,
        ) -> Vec<Diagnostic> {
            diagnostics_for_with_covers(
                target,
                completeness,
                identity,
                normal_continuation_absent,
                false,
            )
        }

        fn diagnostics_for_with_covers(
            target: AuthoredProcedureTarget,
            completeness: Completeness,
            identity: AuthoredClassDecoratorIdentity,
            normal_continuation_absent: bool,
            covers_overrides: bool,
        ) -> Vec<Diagnostic> {
            let mut authored: AuthoredSemanticModelPack =
                serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
            let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload
            else {
                unreachable!()
            };
            summaries[1].target = target;
            summaries[1].completeness = completeness;
            summaries[1].covers_overrides = covers_overrides;
            summaries[1].normal_continuation_absent = normal_continuation_absent;
            summaries[1].class_decorator_identity = Some(identity);
            compile_pack(&authored, &CompilerOptions::default()).unwrap_err()
        }

        fn compiles_variadic_direct(parameter_count: u32) -> bool {
            let mut authored: AuthoredSemanticModelPack =
                serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
            let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload
            else {
                unreachable!()
            };
            let summary = &mut summaries[1];
            summary.target.parameter_count = parameter_count;
            summary.target.variadic = true;
            summary.transfers.clear();
            summary.effects.clear();
            summary.locations.clear();
            summary.class_decorator_identity = Some(AuthoredClassDecoratorIdentity {
                direct: true,
                factory_keywords: None,
            });
            compile_pack(&authored, &CompilerOptions::default()).is_ok()
        }

        let target = AuthoredProcedureTarget {
            path: "com/acme/Flows.class".to_owned(),
            symbol: "wrapper(java.lang.String)".to_owned(),
            has_receiver: false,
            variadic: false,
            parameter_count: 1,
            formals: Vec::new(),
        };
        assert!(
            diagnostics_for(
                target.clone(),
                Completeness::Partial,
                AuthoredClassDecoratorIdentity {
                    direct: true,
                    factory_keywords: None,
                },
                false,
            )
            .iter()
            .any(|diagnostic| diagnostic.code
                == "summary.class_decorator_identity_requires_complete")
        );
        assert!(
            diagnostics_for(
                AuthoredProcedureTarget {
                    parameter_count: 0,
                    ..target.clone()
                },
                Completeness::Complete,
                AuthoredClassDecoratorIdentity {
                    direct: true,
                    factory_keywords: None,
                },
                false,
            )
            .iter()
            .any(|diagnostic| diagnostic.code == "summary.class_decorator_identity_arity")
        );
        assert!(
            diagnostics_for(
                AuthoredProcedureTarget {
                    parameter_count: 2,
                    ..target.clone()
                },
                Completeness::Complete,
                AuthoredClassDecoratorIdentity {
                    direct: true,
                    factory_keywords: None,
                },
                false,
            )
            .iter()
            .any(|diagnostic| diagnostic.code == "summary.class_decorator_identity_arity")
        );
        assert!(
            diagnostics_for(
                AuthoredProcedureTarget {
                    parameter_count: 3,
                    variadic: true,
                    ..target.clone()
                },
                Completeness::Complete,
                AuthoredClassDecoratorIdentity {
                    direct: true,
                    factory_keywords: None,
                },
                false,
            )
            .iter()
            .any(|diagnostic| diagnostic.code == "summary.class_decorator_identity_arity")
        );
        assert!(compiles_variadic_direct(1));
        assert!(compiles_variadic_direct(2));
        assert!(diagnostics_for(
            AuthoredProcedureTarget {
                has_receiver: true,
                ..target.clone()
            },
            Completeness::Complete,
            AuthoredClassDecoratorIdentity {
                direct: true,
                factory_keywords: None,
            },
            false,
        )
        .iter()
        .any(|diagnostic| diagnostic.code == "summary.class_decorator_identity_receiver_target"));
        assert!(
            diagnostics_for(
                target.clone(),
                Completeness::Complete,
                AuthoredClassDecoratorIdentity {
                    direct: false,
                    factory_keywords: None,
                },
                false,
            )
            .iter()
            .any(|diagnostic| diagnostic.code == "summary.empty_class_decorator_identity")
        );
        assert!(
            diagnostics_for(
                target.clone(),
                Completeness::Complete,
                AuthoredClassDecoratorIdentity {
                    direct: false,
                    factory_keywords: Some(vec![AuthoredClassDecoratorKeyword {
                        name: "frozen".to_owned(),
                        allowed_values: vec![],
                    }]),
                },
                false,
            )
            .iter()
            .any(|diagnostic| diagnostic.code
                == "summary.empty_class_decorator_factory_allowed_values")
        );
        assert!(
            diagnostics_for(
                target.clone(),
                Completeness::Complete,
                AuthoredClassDecoratorIdentity {
                    direct: true,
                    factory_keywords: None,
                },
                true,
            )
            .iter()
            .any(|diagnostic| diagnostic.code == "summary.normal_continuation_conflict")
        );
        assert!(
            diagnostics_for_with_covers(
                AuthoredProcedureTarget {
                    parameter_count: 1,
                    ..target
                },
                Completeness::Complete,
                AuthoredClassDecoratorIdentity {
                    direct: true,
                    factory_keywords: None,
                },
                false,
                true,
            )
            .iter()
            .any(|diagnostic| {
                diagnostic.code == "summary.class_decorator_identity_covers_overrides"
            })
        );
    }

    #[test]
    fn absent_procedure_preconditions_preserve_existing_bytes_and_digests() {
        let authored: AuthoredSemanticModelPack =
            serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
        let AuthoredPayload::ProcedureSummaries { summaries } = &authored.shards[0].payload else {
            unreachable!()
        };
        assert!(
            summaries
                .iter()
                .all(|summary| summary.preconditions.is_none())
        );
        assert!(summaries.iter().all(|summary| {
            !String::from_utf8(canonical_json(summary).unwrap())
                .unwrap()
                .contains("\"preconditions\"")
        }));

        // Captured for schema v2 before procedure-level preconditions existed.
        // An omitted optional claim must leave the authored content, compiled
        // shard, and manifest identities byte-for-byte compatible within the
        // same schema version.
        let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        crate::test_support::assert_no_optional_claim_pack_v2_digests(&compiled);

        let decoded = decode_shard_for_manifest(
            &compiled.manifest,
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        assert!(
            decoded
                .payload()
                .procedure_summaries()
                .unwrap()
                .iter()
                .all(|summary| summary.preconditions.is_none())
        );
        assert!(
            !String::from_utf8(canonical_json(&decoded).unwrap())
                .unwrap()
                .contains("\"preconditions\"")
        );
    }

    #[test]
    fn procedure_precondition_review_states_compile_canonically_and_round_trip() {
        let mut reviewed_empty: AuthoredSemanticModelPack =
            serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
        let unreviewed = reviewed_empty.clone();
        let AuthoredPayload::ProcedureSummaries { summaries } =
            &mut reviewed_empty.shards[0].payload
        else {
            unreachable!()
        };
        summaries[0].preconditions = Some(Vec::new());

        let options = CompilerOptions {
            compression: CompressionPolicy::AlwaysRaw,
            ..CompilerOptions::default()
        };
        let baseline = compile_pack(&unreviewed, &options).unwrap();
        let reviewed_empty_compiled = compile_pack(&reviewed_empty, &options)
            .expect("a reviewed-empty precondition set is a substantive summary claim");
        assert_ne!(
            reviewed_empty_compiled.manifest.semantic_sha256,
            baseline.manifest.semantic_sha256
        );
        assert!(
            String::from_utf8(reviewed_empty_compiled.shards[0].bytes.clone())
                .unwrap()
                .contains("\"preconditions\":[]")
        );

        let mut precondition_only = reviewed_empty.clone();
        let AuthoredPayload::ProcedureSummaries { summaries } =
            &mut precondition_only.shards[0].payload
        else {
            unreachable!()
        };
        summaries[0].transfers.clear();
        summaries[0].effects.clear();
        compile_pack(&precondition_only, &options)
            .expect("a reviewed-empty precondition set is a substantive summary claim");

        let decoded = decode_shard_for_manifest(
            &reviewed_empty_compiled.manifest,
            &reviewed_empty_compiled.shards[0].descriptor,
            &reviewed_empty_compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        assert_eq!(
            decoded.payload().procedure_summaries().unwrap()[0].preconditions,
            Some(Vec::new())
        );

        let mut populated = reviewed_empty;
        let AuthoredPayload::ProcedureSummaries { summaries } = &mut populated.shards[0].payload
        else {
            unreachable!()
        };
        summaries[0].preconditions = Some(vec![
            AuthoredOperationPrecondition {
                input: AuthoredSummaryInput::Parameter { ordinal: 0 },
                predicate: AuthoredResultPredicate::Null,
            },
            AuthoredOperationPrecondition {
                input: AuthoredSummaryInput::Receiver {},
                predicate: AuthoredResultPredicate::NonNull,
            },
        ]);
        let populated_compiled = compile_pack(&populated, &options).unwrap();
        let mut reordered = populated.clone();
        let AuthoredPayload::ProcedureSummaries { summaries } = &mut reordered.shards[0].payload
        else {
            unreachable!()
        };
        summaries[0].preconditions.as_mut().unwrap().reverse();
        assert_eq!(
            compile_pack(&reordered, &options).unwrap(),
            populated_compiled,
            "operation preconditions compile as a deterministic set keyed by input"
        );
        assert_ne!(
            populated_compiled.manifest.semantic_sha256,
            reviewed_empty_compiled.manifest.semantic_sha256
        );

        let decoded = decode_shard_for_manifest(
            &populated_compiled.manifest,
            &populated_compiled.shards[0].descriptor,
            &populated_compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        let summary = &decoded.payload().procedure_summaries().unwrap()[0];
        assert_eq!(
            summary.preconditions,
            Some(vec![
                CompiledOperationPrecondition {
                    input: CompiledSummaryInput::Receiver {},
                    predicate: CompiledResultPredicate::NonNull,
                },
                CompiledOperationPrecondition {
                    input: CompiledSummaryInput::Parameter { ordinal: 0 },
                    predicate: CompiledResultPredicate::Null,
                },
            ])
        );
        assert_eq!(
            authored_procedure_summary_from_compiled(summary).preconditions,
            Some(vec![
                AuthoredOperationPrecondition {
                    input: AuthoredSummaryInput::Receiver {},
                    predicate: AuthoredResultPredicate::NonNull,
                },
                AuthoredOperationPrecondition {
                    input: AuthoredSummaryInput::Parameter { ordinal: 0 },
                    predicate: AuthoredResultPredicate::Null,
                },
            ])
        );
    }

    #[test]
    fn procedure_preconditions_validate_inputs_duplicates_and_conflicts() {
        fn with_preconditions(
            preconditions: Vec<AuthoredOperationPrecondition>,
        ) -> AuthoredSemanticModelPack {
            let mut authored: AuthoredSemanticModelPack =
                serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
            let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload
            else {
                unreachable!()
            };
            summaries[1].preconditions = Some(preconditions);
            authored
        }

        let receiver = AuthoredOperationPrecondition {
            input: AuthoredSummaryInput::Receiver {},
            predicate: AuthoredResultPredicate::NonNull,
        };
        let out_of_range = AuthoredOperationPrecondition {
            input: AuthoredSummaryInput::Parameter { ordinal: u32::MAX },
            predicate: AuthoredResultPredicate::NonNull,
        };
        let parameter_null = AuthoredOperationPrecondition {
            input: AuthoredSummaryInput::Parameter { ordinal: 0 },
            predicate: AuthoredResultPredicate::Null,
        };
        let parameter_non_null = AuthoredOperationPrecondition {
            input: AuthoredSummaryInput::Parameter { ordinal: 0 },
            predicate: AuthoredResultPredicate::NonNull,
        };
        for (pack, expected_code, expected_path_suffix) in [
            (
                with_preconditions(vec![receiver]),
                "summary.receiver_unavailable",
                ".preconditions[0].input",
            ),
            (
                with_preconditions(vec![out_of_range]),
                "summary.invalid_ordinal",
                ".preconditions[0].input.ordinal",
            ),
            (
                with_preconditions(vec![parameter_null.clone(), parameter_null.clone()]),
                "summary.duplicate_operation_precondition",
                ".preconditions[1].input",
            ),
            (
                with_preconditions(vec![parameter_null, parameter_non_null]),
                "summary.conflicting_operation_precondition",
                ".preconditions[1].predicate",
            ),
        ] {
            let diagnostics = compile_pack(&pack, &CompilerOptions::default()).unwrap_err();
            assert!(
                diagnostics.iter().any(|diagnostic| {
                    diagnostic.code == expected_code
                        && diagnostic.path.ends_with(expected_path_suffix)
                }),
                "missing `{expected_code}` at `*{expected_path_suffix}` in {diagnostics:#?}"
            );
        }

        let mut variadic = with_preconditions(vec![AuthoredOperationPrecondition {
            input: AuthoredSummaryInput::Parameter { ordinal: 0 },
            predicate: AuthoredResultPredicate::NonNull,
        }]);
        let AuthoredPayload::ProcedureSummaries { summaries } = &mut variadic.shards[0].payload
        else {
            unreachable!()
        };
        summaries[1].target.variadic = true;
        let diagnostics = compile_pack(&variadic, &CompilerOptions::default()).unwrap_err();
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "summary.unsupported_variadic_tail_reference"
                && diagnostic.path.ends_with(".preconditions[0].input.ordinal")
        }));
    }

    #[test]
    fn concurrency_effects_validate_and_round_trip_canonically() {
        fn with_effects(effects: Vec<AuthoredConcurrencyEffect>) -> AuthoredSemanticModelPack {
            let mut authored: AuthoredSemanticModelPack =
                serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
            let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload
            else {
                unreachable!()
            };
            summaries[0].concurrency_effects = effects;
            authored
        }

        let spawn = AuthoredConcurrencyEffect::TaskSpawn {
            callable: AuthoredSummaryInput::Parameter { ordinal: 0 },
            group: Some(AuthoredSummaryInput::Receiver {}),
            condition: None,
            timer: None,
        };
        let lock = AuthoredConcurrencyEffect::LockAcquire {
            lock: AuthoredSummaryInput::Receiver {},
            mode: AuthoredLockMode::Exclusive,
            condition: Some(AuthoredLockCondition::CallResultTrue),
        };
        let atomic = AuthoredConcurrencyEffect::Atomic {
            location: AuthoredSummaryInput::Parameter { ordinal: 0 },
            operation: AuthoredAtomicOperation::ReadModifyWrite,
        };
        let unsupported = AuthoredConcurrencyEffect::Unsupported {
            protocol: "sync.Cond".to_owned(),
        };
        let once = AuthoredConcurrencyEffect::OnceDo {
            once: AuthoredSummaryInput::Receiver {},
            callable: AuthoredSummaryInput::Parameter { ordinal: 0 },
        };
        let mut expected = vec![spawn.clone(), lock, atomic, unsupported, once];
        expected.sort_by_cached_key(|effect| canonical_json(effect).unwrap());
        let compiled =
            compile_pack(&with_effects(expected.clone()), &CompilerOptions::default()).unwrap();
        let decoded = decode_shard_for_manifest(
            &compiled.manifest,
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        let summary = &decoded.payload().procedure_summaries().unwrap()[0];
        assert_eq!(
            authored_procedure_summary_from_compiled(summary).concurrency_effects,
            expected
        );

        for (effects, expected_code) in [
            (
                vec![spawn.clone(), spawn],
                "summary.duplicate_concurrency_effect",
            ),
            (
                vec![AuthoredConcurrencyEffect::TaskSpawn {
                    callable: AuthoredSummaryInput::Receiver {},
                    group: None,
                    condition: None,
                    timer: None,
                }],
                "summary.invalid_task_callable",
            ),
            (
                vec![AuthoredConcurrencyEffect::WaitGroupAdd {
                    group: AuthoredSummaryInput::Parameter { ordinal: 0 },
                    delta: AuthoredSummaryInput::Parameter { ordinal: 0 },
                }],
                "summary.conflicting_concurrency_effect",
            ),
            (
                vec![AuthoredConcurrencyEffect::Unsupported {
                    protocol: " ".to_owned(),
                }],
                "summary.invalid_unsupported_concurrency_protocol",
            ),
            (
                vec![AuthoredConcurrencyEffect::OnceDo {
                    once: AuthoredSummaryInput::Receiver {},
                    callable: AuthoredSummaryInput::Receiver {},
                }],
                "summary.invalid_once_callable",
            ),
            (
                vec![AuthoredConcurrencyEffect::OnceDo {
                    once: AuthoredSummaryInput::Parameter { ordinal: 0 },
                    callable: AuthoredSummaryInput::Parameter { ordinal: 0 },
                }],
                "summary.conflicting_concurrency_effect",
            ),
        ] {
            let diagnostics =
                compile_pack(&with_effects(effects), &CompilerOptions::default()).unwrap_err();
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == expected_code),
                "missing {expected_code} in {diagnostics:#?}"
            );
        }
    }

    #[test]
    fn returned_callable_channel_effect_requires_schema_eleven_and_valid_results() {
        fn with_returned_callable(result_ordinal: u32) -> AuthoredSemanticModelPack {
            let mut authored: AuthoredSemanticModelPack =
                serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
            authored.schema_version = SEMANTIC_MODEL_SCHEMA_VERSION;
            authored.compatibility.bifrost = None;
            let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload
            else {
                unreachable!()
            };
            let summary = &mut summaries[1];
            summary.normal_result_count = Some(2);
            summary.returned_callables = vec![AuthoredReturnedCallable {
                result_ordinal,
                at_most_once: false,
                concurrency_effects: vec![AuthoredConcurrencyEffect::ChannelClose {
                    channel: AuthoredSummaryPort::Output {
                        output: AuthoredSummaryOutput::IndexedNormalReturn { ordinal: 0 },
                    },
                    fresh: false,
                }],
            }];
            authored
        }

        let authored = with_returned_callable(1);
        let expected = match &authored.shards[0].payload {
            AuthoredPayload::ProcedureSummaries { summaries } => {
                summaries[1].returned_callables.clone()
            }
            _ => unreachable!(),
        };
        let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        let decoded = decode_shard_for_manifest(
            &compiled.manifest,
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        let summary = &decoded.payload().procedure_summaries().unwrap()[1];
        assert_eq!(
            authored_procedure_summary_from_compiled(summary).returned_callables,
            expected
        );

        let mut old_schema = authored.clone();
        old_schema.schema_version = CHANNEL_CLOSE_EFFECTS_MIN_SCHEMA_VERSION - 1;
        assert!(
            compile_pack(&old_schema, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| diagnostic.code == "summary.channel_close_schema_version")
        );

        let invalid_ordinal = with_returned_callable(2);
        assert!(
            compile_pack(&invalid_ordinal, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| diagnostic.code == "summary.invalid_returned_callable_ordinal")
        );

        let mut self_target = with_returned_callable(1);
        let AuthoredPayload::ProcedureSummaries { summaries } = &mut self_target.shards[0].payload
        else {
            unreachable!()
        };
        let AuthoredConcurrencyEffect::ChannelClose { channel, .. } =
            &mut summaries[1].returned_callables[0].concurrency_effects[0]
        else {
            unreachable!()
        };
        *channel = AuthoredSummaryPort::Output {
            output: AuthoredSummaryOutput::IndexedNormalReturn { ordinal: 1 },
        };
        assert!(
            compile_pack(&self_target, &CompilerOptions::default())
                .unwrap_err()
                .iter()
                .any(|diagnostic| {
                    diagnostic.code == "summary.invalid_returned_callable_effect_target"
                })
        );
    }

    #[test]
    fn ordinary_heap_unchanged_defaults_omits_and_round_trips() {
        let mut authored: AuthoredSemanticModelPack =
            serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
        let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload
        else {
            unreachable!()
        };
        assert!(
            summaries
                .iter()
                .all(|summary| !summary.ordinary_heap_unchanged)
        );
        let mut summary = summaries[1].clone();
        summary.ordinary_heap_unchanged = true;
        summary.effects.clear();
        let expected = summary.clone();
        summaries[1] = summary;

        let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        let decoded = decode_shard_for_manifest(
            &compiled.manifest,
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        let summary = &decoded.payload().procedure_summaries().unwrap()[1];
        assert!(summary.ordinary_heap_unchanged);
        assert_eq!(authored_procedure_summary_from_compiled(summary), expected);
        assert!(
            String::from_utf8(canonical_json(summary).unwrap())
                .unwrap()
                .contains("\"ordinary_heap_unchanged\":true")
        );

        let decoded_default = decode_shard_for_manifest(
            &compiled.manifest,
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        assert!(
            !decoded_default.payload().procedure_summaries().unwrap()[0].ordinary_heap_unchanged
        );
        assert!(
            !String::from_utf8(
                canonical_json(&decoded_default.payload().procedure_summaries().unwrap()[0])
                    .unwrap(),
            )
            .unwrap()
            .contains("ordinary_heap_unchanged")
        );
    }

    #[test]
    fn ordinary_heap_unchanged_rejects_incomplete_and_conflicting_claims() {
        fn with_claim(
            mutate: impl FnOnce(&mut AuthoredProcedureSummary),
        ) -> AuthoredSemanticModelPack {
            let mut authored: AuthoredSemanticModelPack =
                serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
            let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload
            else {
                unreachable!()
            };
            summaries[1].ordinary_heap_unchanged = true;
            summaries[1].effects.clear();
            mutate(&mut summaries[1]);
            authored
        }

        let call = AuthoredSummaryEffect::Call {
            event: "event.wrapper.call".to_owned(),
            callee: "summary.helper".to_owned(),
        };
        let escape = AuthoredSummaryEffect::Escape {
            event: "event.wrapper.escape".to_owned(),
            input: AuthoredSummaryInput::Parameter { ordinal: 0 },
        };
        let unknown = AuthoredSummaryEffect::UnknownCallBoundary {
            event: "event.wrapper.unknown".to_owned(),
        };
        let ambiguous = AuthoredSummaryEffect::AmbiguousCall {
            event: "event.wrapper.ambiguous".to_owned(),
            input: AuthoredSummaryInput::Parameter { ordinal: 0 },
            candidates: vec!["summary.helper".to_owned(), "summary.wrapper".to_owned()],
        };
        let conditional_write = AuthoredConditionalIndirectWrite {
            result_ordinal: 0,
            outcome: true,
            parameter_ordinal: 0,
            target: AuthoredIndirectWriteTarget::Pointee,
        };
        let storage_location = AuthoredSummaryLocation {
            id: "location.heap".to_owned(),
            location_kind: AuthoredSummaryLocationKind::Heap,
        };
        let storage_transfer = AuthoredSummaryTransfer {
            input: AuthoredSummaryInput::Parameter { ordinal: 0 },
            exit_kind: AuthoredSummaryExitKind::Normal,
            output: AuthoredSummaryOutput::Heap {
                location: storage_location.id.clone(),
            },
            value_transfer: None,
        };
        let receiver_transfer = AuthoredSummaryTransfer {
            input: AuthoredSummaryInput::Parameter { ordinal: 0 },
            exit_kind: AuthoredSummaryExitKind::Normal,
            output: AuthoredSummaryOutput::Receiver {},
            value_transfer: None,
        };
        let atomic_store = AuthoredConcurrencyEffect::Atomic {
            location: AuthoredSummaryInput::Parameter { ordinal: 0 },
            operation: AuthoredAtomicOperation::Store,
        };
        let spawn = AuthoredConcurrencyEffect::TaskSpawn {
            callable: AuthoredSummaryInput::Parameter { ordinal: 0 },
            group: None,
            condition: None,
            timer: None,
        };

        let cases = vec![
            (
                with_claim(|summary| summary.completeness = Completeness::Partial),
                "summary.ordinary_heap_unchanged_on_partial_summary",
            ),
            (
                with_claim(|summary| summary.effects = vec![call]),
                "summary.ordinary_heap_unchanged_conflict",
            ),
            (
                with_claim(|summary| summary.effects = vec![escape]),
                "summary.ordinary_heap_unchanged_conflict",
            ),
            (
                with_claim(|summary| summary.effects = vec![unknown]),
                "summary.ordinary_heap_unchanged_conflict",
            ),
            (
                with_claim(|summary| summary.effects = vec![ambiguous]),
                "summary.ordinary_heap_unchanged_conflict",
            ),
            (
                with_claim(|summary| {
                    summary.normal_result_count = Some(1);
                    summary.conditional_indirect_writes = vec![conditional_write];
                }),
                "summary.ordinary_heap_unchanged_conflict",
            ),
            (
                with_claim(|summary| {
                    summary.locations = vec![storage_location];
                    summary.transfers = vec![storage_transfer];
                }),
                "summary.ordinary_heap_unchanged_conflict",
            ),
            (
                with_claim(|summary| summary.transfers = vec![receiver_transfer]),
                "summary.ordinary_heap_unchanged_conflict",
            ),
            (
                with_claim(|summary| summary.concurrency_effects = vec![atomic_store]),
                "summary.ordinary_heap_unchanged_conflict",
            ),
            (
                with_claim(|summary| summary.concurrency_effects = vec![spawn]),
                "summary.ordinary_heap_unchanged_conflict",
            ),
            (
                with_claim(|summary| {
                    summary.concurrency_effects = vec![AuthoredConcurrencyEffect::Unsupported {
                        protocol: "unknown.protocol".to_owned(),
                    }]
                }),
                "summary.ordinary_heap_unchanged_conflict",
            ),
        ];
        for (pack, expected_code) in cases {
            let diagnostics = compile_pack(&pack, &CompilerOptions::default()).unwrap_err();
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == expected_code),
                "missing {expected_code} in {diagnostics:#?}"
            );
        }
    }

    #[test]
    fn no_concurrency_effects_defaults_omits_and_round_trips_independently() {
        let mut authored: AuthoredSemanticModelPack =
            serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
        authored.schema_version = NO_CONCURRENCY_EFFECTS_MIN_SCHEMA_VERSION;
        let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload
        else {
            unreachable!()
        };
        assert!(
            summaries
                .iter()
                .all(|summary| !summary.no_concurrency_effects)
        );

        let mut summary = summaries[1].clone();
        summary.effects.clear();
        summary.no_concurrency_effects = true;
        assert!(!summary.ordinary_heap_unchanged);
        let expected = summary.clone();
        summaries[1] = summary;

        let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        let decoded = decode_shard_for_manifest(
            &compiled.manifest,
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        let summaries = decoded.payload().procedure_summaries().unwrap();
        assert!(summaries[1].no_concurrency_effects);
        assert!(!summaries[1].ordinary_heap_unchanged);
        assert_eq!(
            authored_procedure_summary_from_compiled(&summaries[1]),
            expected
        );
        assert!(
            String::from_utf8(canonical_json(&summaries[1]).unwrap())
                .unwrap()
                .contains("\"no_concurrency_effects\":true")
        );
        assert!(
            !String::from_utf8(canonical_json(&summaries[0]).unwrap())
                .unwrap()
                .contains("no_concurrency_effects")
        );
    }

    #[test]
    fn no_concurrency_effects_requires_schema_seven_complete_and_empty_effects() {
        fn with_claim(
            mutate: impl FnOnce(&mut AuthoredProcedureSummary),
        ) -> AuthoredSemanticModelPack {
            let mut authored: AuthoredSemanticModelPack =
                serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
            authored.schema_version = NO_CONCURRENCY_EFFECTS_MIN_SCHEMA_VERSION;
            let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload
            else {
                unreachable!()
            };
            let summary = &mut summaries[1];
            summary.effects.clear();
            summary.no_concurrency_effects = true;
            mutate(summary);
            authored
        }

        let cases = [
            (
                with_claim(|summary| summary.completeness = Completeness::Partial),
                "summary.no_concurrency_effects_on_partial_summary",
            ),
            (
                with_claim(|summary| {
                    summary.concurrency_effects = vec![AuthoredConcurrencyEffect::LockAcquire {
                        lock: AuthoredSummaryInput::Parameter { ordinal: 0 },
                        mode: AuthoredLockMode::Exclusive,
                        condition: None,
                    }]
                }),
                "summary.no_concurrency_effects_conflict",
            ),
        ];
        for (pack, expected_code) in cases {
            let diagnostics = compile_pack(&pack, &CompilerOptions::default()).unwrap_err();
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == expected_code),
                "missing {expected_code} in {diagnostics:#?}"
            );
        }

        let mut old_schema: AuthoredSemanticModelPack =
            serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
        let AuthoredPayload::ProcedureSummaries { summaries } = &mut old_schema.shards[0].payload
        else {
            unreachable!()
        };
        summaries[1].effects.clear();
        summaries[1].no_concurrency_effects = true;
        let diagnostics = compile_pack(&old_schema, &CompilerOptions::default()).unwrap_err();
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "summary.no_concurrency_effects_schema_version"
        }));
    }

    #[test]
    fn conditional_indirect_writes_validate_and_round_trip_canonically() {
        fn with_writes(writes: Vec<AuthoredConditionalIndirectWrite>) -> AuthoredSemanticModelPack {
            let mut authored: AuthoredSemanticModelPack =
                serde_json::from_slice(PROCEDURE_SUMMARIES).unwrap();
            let AuthoredPayload::ProcedureSummaries { summaries } = &mut authored.shards[0].payload
            else {
                unreachable!()
            };
            summaries[1].normal_result_count = Some(1);
            summaries[1].conditional_indirect_writes = writes;
            authored
        }

        let write = AuthoredConditionalIndirectWrite {
            result_ordinal: 0,
            outcome: true,
            parameter_ordinal: 0,
            target: AuthoredIndirectWriteTarget::Pointee,
        };
        let compiled = compile_pack(
            &with_writes(vec![write.clone()]),
            &CompilerOptions::default(),
        )
        .expect("one in-range pointee write compiles");
        let decoded = decode_shard_for_manifest(
            &compiled.manifest,
            &compiled.shards[0].descriptor,
            &compiled.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .expect("compiled indirect write decodes");
        let summary = &decoded.payload().procedure_summaries().unwrap()[1];
        assert_eq!(
            authored_procedure_summary_from_compiled(summary).conditional_indirect_writes,
            vec![write.clone()]
        );
        assert!(
            String::from_utf8(canonical_json(summary).unwrap())
                .unwrap()
                .contains("\"conditional_indirect_writes\":[{\"result_ordinal\":0,\"outcome\":true,\"parameter_ordinal\":0,\"target\":\"pointee\"}]")
        );

        for (writes, expected_code) in [
            (
                vec![write.clone(), write],
                "summary.duplicate_conditional_indirect_write",
            ),
            (
                vec![AuthoredConditionalIndirectWrite {
                    result_ordinal: 1,
                    outcome: true,
                    parameter_ordinal: 0,
                    target: AuthoredIndirectWriteTarget::Pointee,
                }],
                "summary.result_ordinal_out_of_range",
            ),
            (
                vec![AuthoredConditionalIndirectWrite {
                    result_ordinal: 0,
                    outcome: true,
                    parameter_ordinal: 1,
                    target: AuthoredIndirectWriteTarget::Pointee,
                }],
                "summary.parameter_ordinal_out_of_range",
            ),
        ] {
            let diagnostics =
                compile_pack(&with_writes(writes), &CompilerOptions::default()).unwrap_err();
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == expected_code),
                "missing `{expected_code}` in {diagnostics:#?}"
            );
        }
    }

    #[test]
    fn shard_decoder_rejects_noncanonical_json_with_valid_digests() {
        let compiled = compile_source(
            SourceFormat::Json,
            DECLARATIONS,
            &CompilerOptions {
                compression: CompressionPolicy::AlwaysRaw,
                ..CompilerOptions::default()
            },
        )
        .unwrap();
        let artifact = &compiled.shards[0];
        let shard = decode_shard(
            &artifact.descriptor,
            &artifact.bytes,
            &DecodeLimits::default(),
        )
        .unwrap();
        let raw = serde_json::to_vec_pretty(&shard).unwrap();
        let mut descriptor = artifact.descriptor.clone();
        descriptor.raw_size = raw.len() as u64;
        descriptor.stored_size = raw.len() as u64;
        descriptor.content_sha256 = content_digest(&raw);
        descriptor.stored_sha256 = content_digest(&raw);

        assert_eq!(
            decode_shard(&descriptor, &raw, &DecodeLimits::default()).unwrap_err(),
            ArtifactError::NonCanonical
        );
    }

    #[test]
    fn shard_decoder_rejects_trailing_deflate_data_with_valid_stored_digest() {
        let raw = b"{}";
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::new(6));
        encoder.write_all(raw).unwrap();
        let mut stored = encoder.finish().unwrap();
        stored.extend_from_slice(b"trailing");
        let descriptor = descriptor_for_test(raw, &stored, raw.len() as u64);

        assert_eq!(
            decode_shard(&descriptor, &stored, &DecodeLimits::default()).unwrap_err(),
            ArtifactError::TrailingCompressedData
        );
    }

    #[test]
    fn shard_decoder_stops_excessive_expansion_at_declared_size() {
        let raw = vec![0u8; 4096];
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::new(6));
        encoder.write_all(&raw).unwrap();
        let stored = encoder.finish().unwrap();
        let descriptor = descriptor_for_test(&raw, &stored, 32);

        assert_eq!(
            decode_shard(&descriptor, &stored, &DecodeLimits::default()).unwrap_err(),
            ArtifactError::LimitExceeded("raw shard byte limit")
        );
    }

    #[test]
    fn manifest_decoder_binds_metadata_and_total_record_limit() {
        let compiled = compile_source(
            SourceFormat::Json,
            DECLARATIONS,
            &CompilerOptions::default(),
        )
        .unwrap();
        let mut tampered = compiled.manifest.clone();
        tampered.provenance.source = "https://mirror.example/widget.jar".to_owned();
        let bytes = canonical_json(&tampered).unwrap();
        assert_eq!(
            decode_manifest(&bytes, &DecodeLimits::default()).unwrap_err(),
            ArtifactError::DigestMismatch("manifest content")
        );

        let limits = DecodeLimits {
            max_total_records: 2,
            ..DecodeLimits::default()
        };
        assert_eq!(
            decode_manifest(&compiled.manifest_bytes, &limits).unwrap_err(),
            ArtifactError::LimitExceeded("total record limit")
        );
    }

    #[test]
    fn shard_decoder_rejects_rehashed_semantically_invalid_payload() {
        let compiled = compile_source(
            SourceFormat::Json,
            DECLARATIONS,
            &CompilerOptions {
                compression: CompressionPolicy::AlwaysRaw,
                ..CompilerOptions::default()
            },
        )
        .unwrap();
        let artifact = &compiled.shards[0];
        let mut wire: WireCompiledShard = serde_json::from_slice(&artifact.bytes).unwrap();
        let CompiledPayload::DeclarationFacts { types, .. } = &mut wire.payload else {
            unreachable!()
        };
        types[0].aliases.push("invalid alias".to_owned());
        let (descriptor, raw) = rehash_raw_descriptor(&artifact.descriptor, &wire);

        assert!(matches!(
            decode_shard(&descriptor, &raw, &DecodeLimits::default()),
            Err(ArtifactError::SemanticValidation(_))
        ));
    }

    #[test]
    fn shard_decoder_rejects_rehashed_procedure_metadata_tampering() {
        let compiled = compile_source(
            SourceFormat::Json,
            PROCEDURE_SUMMARIES,
            &CompilerOptions {
                compression: CompressionPolicy::AlwaysRaw,
                ..CompilerOptions::default()
            },
        )
        .unwrap();
        let artifact = &compiled.shards[0];
        let mut wire: WireCompiledShard = serde_json::from_slice(&artifact.bytes).unwrap();
        let CompiledPayload::ProcedureSummaries { summaries } = &mut wire.payload else {
            unreachable!()
        };
        summaries[0].model_id = "acme.procedure-summaries#summary.forged".to_owned();
        let (descriptor, raw) = rehash_raw_descriptor(&artifact.descriptor, &wire);

        let error = decode_shard(&descriptor, &raw, &DecodeLimits::default()).unwrap_err();
        assert!(
            matches!(
                &error,
                ArtifactError::InvalidDescriptor(message)
                    if message.contains("procedure summary model id")
            ),
            "unexpected decoder error: {error:?}"
        );
    }

    #[test]
    fn manifest_bound_decoder_rejects_rehashed_unbound_procedure_callee() {
        let compiled = compile_source(
            SourceFormat::Json,
            PROCEDURE_SUMMARIES,
            &CompilerOptions {
                compression: CompressionPolicy::AlwaysRaw,
                ..CompilerOptions::default()
            },
        )
        .unwrap();
        let artifact = &compiled.shards[0];
        let mut wire: WireCompiledShard = serde_json::from_slice(&artifact.bytes).unwrap();
        let CompiledPayload::ProcedureSummaries { summaries } = &mut wire.payload else {
            unreachable!()
        };
        let callee = summaries[1]
            .effects
            .iter_mut()
            .find_map(|effect| match effect {
                CompiledSummaryEffect::Call { callee, .. } => Some(callee),
                _ => None,
            })
            .expect("fixture contains an exact call effect");
        *callee = "summary.missing".to_owned();
        summaries[1].content_sha256 = content_digest(
            &canonical_json(&authored_procedure_summary_from_compiled(&summaries[1])).unwrap(),
        );
        let (descriptor, raw) = rehash_raw_descriptor(&artifact.descriptor, &wire);
        let mut manifest = compiled.manifest.clone();
        manifest.shards[0] = descriptor.clone();

        assert!(matches!(
            decode_shard_for_manifest(&manifest, &descriptor, &raw, &DecodeLimits::default()),
            Err(ArtifactError::InvalidDescriptor(message))
                if message.contains("summary.missing")
        ));
    }

    #[test]
    fn manifest_inventory_keeps_declaration_and_procedure_namespaces_distinct() {
        let declaration_pack = compile_source(
            SourceFormat::Json,
            DECLARATIONS,
            &CompilerOptions::default(),
        )
        .unwrap();
        let mut manifest = declaration_pack.manifest.clone();
        let mut procedure_descriptor = declaration_pack.manifest.shards[0].clone();
        procedure_descriptor.shard_id = "summaries.forged".to_owned();
        procedure_descriptor.defined_ids.clear();
        procedure_descriptor.referenced_ids = vec!["procedure:type.widget".to_owned()];
        manifest.shards.push(procedure_descriptor);

        assert!(matches!(
            validate_manifest_inventory(&manifest),
            Err(ArtifactError::InvalidDescriptor(message))
                if message.contains("procedure:type.widget")
        ));
    }

    #[test]
    fn manifest_inventory_rejects_duplicate_procedure_targets_across_shards() {
        let compiled = compile_source(
            SourceFormat::Json,
            PROCEDURE_SUMMARIES,
            &CompilerOptions::default(),
        )
        .unwrap();
        let target_id = compiled.manifest.shards[0]
            .defined_ids
            .iter()
            .find(|id| id.starts_with(PROCEDURE_TARGET_INVENTORY_PREFIX))
            .unwrap()
            .clone();
        let mut first = compiled.manifest.shards[0].clone();
        first.defined_ids = vec![target_id.clone()];
        first.referenced_ids.clear();
        let mut second = first.clone();
        second.shard_id = "summaries.duplicate-target".to_owned();
        let mut manifest = compiled.manifest.clone();
        manifest.shards = vec![first, second];

        assert!(matches!(
            validate_manifest_inventory(&manifest),
            Err(ArtifactError::InvalidDescriptor(message))
                if message.contains(&target_id)
        ));
    }

    #[test]
    fn shard_decoder_rejects_rehashed_semantic_set_reordering() {
        let mut authored: AuthoredSemanticModelPack = serde_json::from_slice(DECLARATIONS).unwrap();
        let AuthoredPayload::DeclarationFacts { types, .. } = &mut authored.shards[0].payload
        else {
            unreachable!()
        };
        types[0]
            .aliases
            .extend(["com.acme.Alpha".to_owned(), "com.acme.Zeta".to_owned()]);
        let compiled = compile_pack(
            &authored,
            &CompilerOptions {
                compression: CompressionPolicy::AlwaysRaw,
                ..CompilerOptions::default()
            },
        )
        .unwrap();
        let artifact = &compiled.shards[0];
        let mut wire: WireCompiledShard = serde_json::from_slice(&artifact.bytes).unwrap();
        let CompiledPayload::DeclarationFacts { types, .. } = &mut wire.payload else {
            unreachable!()
        };
        types[0].aliases.reverse();
        let (descriptor, raw) = rehash_raw_descriptor(&artifact.descriptor, &wire);

        assert_eq!(
            decode_shard(&descriptor, &raw, &DecodeLimits::default()).unwrap_err(),
            ArtifactError::NonCanonical
        );
    }

    #[test]
    fn manifest_bound_decoder_rejects_a_different_envelope() {
        let compiled = compile_source(
            SourceFormat::Json,
            DECLARATIONS,
            &CompilerOptions::default(),
        )
        .unwrap();
        let mut manifest = compiled.manifest.clone();
        manifest.producer.name = "other-producer".to_owned();
        manifest.content_sha256 = manifest_content_digest(&manifest).unwrap();
        let artifact = &compiled.shards[0];

        assert!(matches!(
            decode_shard_for_manifest(
                &manifest,
                &artifact.descriptor,
                &artifact.bytes,
                &DecodeLimits::default()
            ),
            Err(ArtifactError::InvalidDescriptor(message))
                if message == "shard envelope does not match manifest"
        ));
    }

    fn rehash_raw_descriptor(
        descriptor: &CompiledShardDescriptor,
        wire: &WireCompiledShard,
    ) -> (CompiledShardDescriptor, Vec<u8>) {
        let raw = canonical_json(wire).unwrap();
        let shard = compiled_from_wire(wire.clone());
        let mut descriptor = descriptor.clone();
        descriptor.encoding = ArtifactEncoding::Raw;
        descriptor.raw_size = raw.len() as u64;
        descriptor.stored_size = raw.len() as u64;
        descriptor.semantic_sha256 = semantic_digest(&shard).unwrap();
        descriptor.content_sha256 = content_digest(&raw);
        descriptor.stored_sha256 = content_digest(&raw);
        (descriptor.defined_ids, descriptor.referenced_ids) = payload_inventory(&wire.payload);
        (descriptor, raw)
    }

    fn descriptor_for_test(
        raw: &[u8],
        stored: &[u8],
        declared_raw_size: u64,
    ) -> CompiledShardDescriptor {
        CompiledShardDescriptor {
            shard_id: "test.shard".to_owned(),
            payload_kind: PayloadKind::DeclarationFacts,
            routing_keys: Vec::new(),
            encoding: ArtifactEncoding::Deflate,
            raw_size: declared_raw_size,
            stored_size: stored.len() as u64,
            record_count: 0,
            defined_ids: Vec::new(),
            referenced_ids: Vec::new(),
            semantic_sha256: "0".repeat(64),
            content_sha256: content_digest(raw),
            stored_sha256: content_digest(stored),
        }
    }
}
