//! What one analysis row proves about the rows its producer did not return.
//!
//! A row's `evidence` object answers "is this row real". It says nothing about
//! the rows that are absent, and an absence claim -- an anti join, a zero
//! count, a `none` assertion -- reads exactly that second question. The two are
//! independent: a value-flow endpoint can be a proven meeting while the solve
//! that found it stopped against a budget, so the endpoint set it belongs to is
//! not the complete one.
//!
//! Only families that run a solver publish coverage, and each one publishes it
//! for the partition its solver enumerated: the value-flow plan, the typestate
//! protocol, the taint sink, the member-access class set, or the call site. A
//! structural row has no solver and no partition; its coverage is the executed
//! query's own envelope, which the consumer already has.
//!
//! The vocabulary here is deliberately the CodeQuery diagnostic vocabulary
//! rather than a policy one. A producer states what happened in the terms it
//! already reports; mapping that onto a report's incompleteness reasons is the
//! consumer's job, and is the same mapping a query-level diagnostic takes.

use super::*;
use brokk_bifrost_core::analyzer::structural::callable::CallShapeCoverage;
use brokk_bifrost_flow::type_flow::ClassSetStatus;

/// One row's coverage statement and the analysis partition it is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeQueryRowCoverage {
    /// The producing analysis partition this row belongs to, in the family's
    /// own published identity: a value-flow plan reference, a typestate
    /// protocol reference, a taint sink event id, a class-set row id, or a call
    /// site id. The row's domain names which family minted it, so the family is
    /// not repeated here.
    pub partition: Box<str>,
    #[serde(flatten)]
    pub extent: CodeQueryRowCoverageExtent,
}

/// How much of one partition the producing analysis actually enumerated.
///
/// Ordered from most to least informative, and deliberately without a
/// `proven_subset` member: no analysis family narrows its own partition by a
/// declared restriction today, and a deliberate restriction that does appear
/// belongs on the query envelope where `CodeQueryCompletion` already states it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "extent", rename_all = "snake_case")]
pub enum CodeQueryRowCoverageExtent {
    /// Every row of this partition that exists was returned.
    Exhaustive,
    /// Rows of this partition may be missing. The codes are the same typed
    /// causes the query would report as diagnostics.
    Incomplete { codes: Vec<CodeQueryDiagnosticCode> },
    /// The producer cannot describe this partition at all. The capability is a
    /// report identifier, not prose.
    Unsupported { capability: Box<str> },
}

impl CodeQueryRowCoverageExtent {
    /// An incomplete extent with canonical, non-empty codes.
    fn incomplete(mut codes: Vec<CodeQueryDiagnosticCode>) -> Self {
        codes.sort();
        codes.dedup();
        debug_assert!(
            !codes.is_empty(),
            "an incomplete row coverage always states a cause"
        );
        Self::Incomplete { codes }
    }
}

impl CodeQueryResultValue {
    /// The coverage this row publishes, or `None` for a family that runs no
    /// solver and therefore enumerates no partition of its own.
    ///
    /// Derived from the same solver outcome the row already publishes as its
    /// status columns, so a row and its coverage cannot disagree, and a
    /// replayed row answers exactly what the live row answered.
    pub fn row_coverage(&self) -> Option<CodeQueryRowCoverage> {
        match self {
            // The one status per flow row (#3151) is the value-flow solve's
            // whole public outcome: the semantic input status merged with the
            // plan's discovery status, then capped by the solver termination.
            Self::FlowEndpoint { value } => Some(CodeQueryRowCoverage {
                partition: Box::from(value.plan_ref.as_str()),
                extent: flow_status_extent(value.status),
            }),
            // `analysis_complete` is the typestate report's own completeness,
            // and an abstained finding is one the solver declined to conclude
            // over, so neither supports an absence claim about its protocol.
            Self::TypestateFinding { value } => {
                let mut codes = Vec::new();
                if !value.analysis_complete || value.abstained {
                    codes.push(CodeQueryDiagnosticCode::TypestateAnalysisPartial);
                }
                Some(CodeQueryRowCoverage {
                    partition: Box::from(value.protocol_ref.as_str()),
                    extent: if codes.is_empty() {
                        CodeQueryRowCoverageExtent::Exhaustive
                    } else {
                        CodeQueryRowCoverageExtent::incomplete(codes)
                    },
                })
            }
            // A taint finding's retained origins and witnesses are per finding,
            // so a projection that dropped some of them leaves the query
            // envelope complete while this sink's evidence set is not.
            Self::TaintFinding { value } => {
                let mut codes = Vec::new();
                if value.origins_truncated || value.witnesses_truncated {
                    codes.push(CodeQueryDiagnosticCode::TaintFindingTruncated);
                }
                if value.evidence.completeness == CodeQuerySemanticCompleteness::Partial {
                    codes.push(CodeQueryDiagnosticCode::SemanticAnalysisPartial);
                }
                Some(CodeQueryRowCoverage {
                    partition: Box::from(value.sink_event_id.as_str()),
                    extent: if codes.is_empty() {
                        CodeQueryRowCoverageExtent::Exhaustive
                    } else {
                        CodeQueryRowCoverageExtent::incomplete(codes)
                    },
                })
            }
            // A class set that is anything but fully known is missing atoms, so
            // the member access it describes cannot support "no class here
            // declares that member".
            Self::ClassSetRow { value } => Some(CodeQueryRowCoverage {
                partition: Box::from(value.id.as_str()),
                extent: if value.status == ClassSetStatus::Known.label() {
                    CodeQueryRowCoverageExtent::Exhaustive
                } else {
                    CodeQueryRowCoverageExtent::incomplete(vec![
                        CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                    ])
                },
            }),
            // A shape the lowering could not read suppresses every row family
            // derived from it; no larger budget recovers those rows, which is
            // why this is unsupported rather than incomplete (#1949).
            Self::CallShape { value } => Some(CodeQueryRowCoverage {
                partition: Box::from(value.site_id.as_str()),
                extent: if value.coverage == CallShapeCoverage::Exact.label() {
                    CodeQueryRowCoverageExtent::Exhaustive
                } else {
                    CodeQueryRowCoverageExtent::Unsupported {
                        capability: Box::from(SUPPRESSED_ROW_SET_CAPABILITY),
                    }
                },
            }),
            // Every other family answers a structural or lexical question and
            // runs no solver of its own: there is no partition for it to be
            // exhaustive over, and the executed query's envelope already states
            // what its row set proves. Exhaustive rather than a wildcard, so a
            // new analysis family has to decide rather than defaulting to
            // adding no restriction.
            Self::StructuralMatch { .. }
            | Self::Declaration { .. }
            | Self::Procedure { .. }
            | Self::ProgramPoint { .. }
            | Self::ControlEdge { .. }
            | Self::ConcurrentAccessConflict { .. }
            | Self::TypestateWitness { .. }
            | Self::FlowWitness { .. }
            | Self::AbsentMemberFinding { .. }
            | Self::AbsentMemberWitness { .. }
            | Self::File { .. }
            | Self::ConfigurationFact { .. }
            | Self::ReferenceSite { .. }
            | Self::CallSite { .. }
            | Self::ExpressionSite { .. }
            | Self::JsxAttributeValue { .. }
            | Self::ReceiverAnalysis { .. }
            | Self::MemberTargetAnalysis { .. }
            | Self::ReceiverOutcome { .. }
            | Self::ReceiverEvidence { .. }
            | Self::FieldWriteValue { .. }
            | Self::RuntimeKeyedReadValue { .. }
            | Self::CallResult { .. }
            | Self::CallArgumentGroup { .. }
            | Self::CallArgument { .. }
            | Self::CallBinding { .. }
            | Self::CallEffect { .. }
            | Self::CallResultContract { .. }
            | Self::ResultContractUse { .. }
            | Self::ResultContractFailureUse { .. }
            | Self::NilnessOperation { .. }
            | Self::SwitchCoverage { .. }
            | Self::DetachedTaskTransfer { .. }
            | Self::ProcedureEffect { .. }
            | Self::CallableSignature { .. }
            | Self::SignatureParameter { .. }
            | Self::DecoratedParameter { .. }
            | Self::CallableApplicability { .. }
            | Self::OverloadSelection { .. }
            | Self::MemberSelection { .. }
            | Self::DispatchOutcome { .. }
            | Self::DispatchTarget { .. }
            | Self::MemberFamily { .. }
            | Self::MemberFamilyEdge { .. }
            | Self::Occurrence { .. }
            | Self::LexicalScope { .. }
            | Self::Binding { .. }
            | Self::ResolutionCandidate { .. }
            | Self::CandidateHop { .. }
            | Self::GenerationSite { .. }
            | Self::Export { .. }
            | Self::DeclarationState { .. }
            | Self::ReferenceEdge { .. }
            | Self::StateEvent { .. }
            | Self::FlowRelation { .. }
            | Self::ControlRelation { .. }
            | Self::Guard { .. }
            | Self::RewritePath { .. }
            | Self::QualifiedPath { .. }
            | Self::PathSegment { .. }
            | Self::SourceSet { .. }
            | Self::BuildTarget { .. }
            | Self::TopologyEdge { .. } => None,
        }
    }
}

/// The capability a consumer names when a producer refused to describe a row
/// set rather than describing part of it.
pub const SUPPRESSED_ROW_SET_CAPABILITY: &str = "suppressed_row_set";

/// The capability a consumer names when a value-flow solve could not run at all
/// for the selected input.
pub const VALUE_FLOW_CAPABILITY: &str = "value_flow";

/// Project one public flow-row status onto the coverage it implies.
///
/// `Complete` is the only status that establishes the endpoint set; every other
/// status names a frontier, a limit, or a stop, and a stopped solve returns a
/// subset of the meetings a finished one would have.
fn flow_status_extent(status: CodeQueryFlowStatus) -> CodeQueryRowCoverageExtent {
    let code = match status {
        CodeQueryFlowStatus::Complete => return CodeQueryRowCoverageExtent::Exhaustive,
        CodeQueryFlowStatus::Unsupported => {
            return CodeQueryRowCoverageExtent::Unsupported {
                capability: Box::from(VALUE_FLOW_CAPABILITY),
            };
        }
        CodeQueryFlowStatus::Partial
        | CodeQueryFlowStatus::Ambiguous
        | CodeQueryFlowStatus::Unknown
        | CodeQueryFlowStatus::Unproven => CodeQueryDiagnosticCode::ValueFlowAnalysisPartial,
        CodeQueryFlowStatus::SemanticBudgetExhausted => {
            CodeQueryDiagnosticCode::SemanticBudgetExhausted
        }
        CodeQueryFlowStatus::SolverBudgetExhausted => {
            CodeQueryDiagnosticCode::ValueFlowSolverBudgetExhausted
        }
        CodeQueryFlowStatus::SemanticCancelled
        | CodeQueryFlowStatus::SolverCancelled
        | CodeQueryFlowStatus::QueryCancelled => CodeQueryDiagnosticCode::Cancelled,
    };
    CodeQueryRowCoverageExtent::Incomplete { codes: vec![code] }
}
