// Boundary-visible child modules keep their qualified paths when short names collide.
#![allow(ambiguous_glob_reexports)]

//! Language-neutral executable semantics and adapter contracts.

macro_rules! count_idents {
    ($($value:ident),* $(,)?) => {
        <[()]>::len(&[$(count_idents!(@unit $value)),*])
    };
    (@unit $value:ident) => { () };
}

pub(crate) fn hash_arc_key<T: ?Sized, K: std::hash::Hash, H: std::hash::Hasher>(
    owner: &std::sync::Arc<T>,
    key: &K,
    state: &mut H,
) {
    std::hash::Hash::hash(&std::sync::Arc::as_ptr(owner), state);
    std::hash::Hash::hash(key, state);
}

#[doc(hidden)]
pub fn completeness_reason_bytes(completeness: &EvidenceCompleteness) -> usize {
    completeness.retained_heap_bytes()
}

#[doc(hidden)]
pub const fn procedure_relays_receiver_capture(kind: ProcedureKind) -> bool {
    matches!(kind, ProcedureKind::Lambda)
}

pub mod binding_origins;
pub mod capabilities;
#[doc(hidden)]
pub mod cfg;
pub mod cfg_algorithms;
pub mod icfg;
pub mod ids;
#[doc(hidden)]
pub mod inventory;
pub mod ir;
pub mod leases;
#[doc(hidden)]
pub mod lowering;
pub mod oracle;
pub mod partial_flow;
pub mod property_reaching;
pub mod provider;
pub mod render;
pub mod service;
pub mod statement_entries;
#[doc(hidden)]
pub mod structural_identity;
pub mod type_flow;
pub mod value_type_barriers;
pub mod workspace_oracle;

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn floating_value_for_test(value: f64) -> SemanticValueKind {
    SemanticValueKind::FloatingPoint {
        bits: value.to_bits(),
    }
}

pub use brokk_bifrost_core::cancellation::CancellationToken;

pub use crate::analyzer::semantic::binding_origins::*;

pub use crate::analyzer::semantic::capabilities::*;

pub use crate::analyzer::semantic::icfg::*;

pub use crate::analyzer::semantic::ids::*;

pub use crate::analyzer::semantic::ir::*;

pub use crate::analyzer::semantic::leases::*;

pub use crate::analyzer::semantic::oracle::*;

pub use crate::analyzer::semantic::property_reaching::*;

pub use crate::analyzer::semantic::provider::*;

pub use crate::analyzer::semantic::render::*;

#[cfg(any(test, feature = "test-support"))]
pub use crate::analyzer::semantic::service::SemanticCacheRevivalCensus;
#[cfg(any(test, feature = "test-support"))]
pub use crate::analyzer::semantic::service::SemanticMaterializationCensus;
pub use crate::analyzer::semantic::service::semantic_artifact_retained_bytes;

pub use crate::analyzer::semantic::statement_entries::*;

pub use crate::analyzer::semantic::type_flow::CallGuardOutcome;

pub use crate::analyzer::semantic::type_flow::ClassAtom;

pub use crate::analyzer::semantic::type_flow::ClassBodyMemberBinding;

pub use crate::analyzer::semantic::type_flow::ClassHierarchy;

pub use crate::analyzer::semantic::type_flow::ClassIdentity;

pub use crate::analyzer::semantic::type_flow::ClassSeed;

pub use crate::analyzer::semantic::type_flow::ConstructorResultEvidence;

pub use crate::analyzer::semantic::type_flow::ConstructorResultOrigin;

pub use crate::analyzer::semantic::type_flow::DispatchHint;

pub use crate::analyzer::semantic::type_flow::DispatchHintCallSiteKey;

pub use crate::analyzer::semantic::type_flow::DispatchHintSet;

pub use crate::analyzer::semantic::type_flow::DispatchHints;

pub use crate::analyzer::semantic::type_flow::DynamicFieldNameSet;

pub use crate::analyzer::semantic::type_flow::DynamicFieldWrite;

pub use crate::analyzer::semantic::type_flow::ExactResultProducer;

pub use crate::analyzer::semantic::type_flow::ExternalMemberDeclaration;

pub use crate::analyzer::semantic::type_flow::MemberAccessKind;

pub use crate::analyzer::semantic::type_flow::MemberAccessQuery;

pub use crate::analyzer::semantic::type_flow::MemberDeclaration;

pub use crate::analyzer::semantic::type_flow::MemberLookup;

pub use crate::analyzer::semantic::type_flow::MemberLookupHit;

pub use crate::analyzer::semantic::type_flow::MemberReceiverQuery;

pub use crate::analyzer::semantic::type_flow::NarrowingVerdict;

pub use crate::analyzer::semantic::type_flow::NormalReturnTypeConstraint;

pub use crate::analyzer::semantic::type_flow::SourceSite;

pub use crate::analyzer::semantic::type_flow::SourceSiteKind;

pub use crate::analyzer::semantic::type_flow::UnknownReason;

pub use crate::analyzer::semantic::type_flow::source_site_kind_tag;

pub use crate::analyzer::semantic::value_type_barriers::*;

pub use crate::analyzer::semantic::workspace_oracle::*;

pub mod local_value_origins;

pub use crate::analyzer::semantic::local_value_origins::*;

#[doc(hidden)]
pub mod call_binding;
#[doc(hidden)]
pub mod call_conversion;
#[doc(hidden)]
pub mod call_relations;
#[doc(hidden)]
pub mod common;
#[doc(hidden)]
pub mod content_identity;
#[doc(hidden)]
pub mod digest;
#[doc(hidden)]
pub mod invalidation;
#[doc(hidden)]
pub mod languages;
#[doc(hidden)]
pub mod lexical_definitions;
#[doc(hidden)]
pub mod read_ledger;
#[doc(hidden)]
pub mod source_admission;
#[doc(hidden)]
pub mod topology;
#[doc(hidden)]
pub mod trace;
#[doc(hidden)]
pub mod workspace_document;
