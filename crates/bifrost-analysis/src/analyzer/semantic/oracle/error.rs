use std::fmt;

use super::super::ids::MemoryLocationId;
use super::super::ir::ProcedureHandle;

/// A construction-time oracle-contract violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleContractError {
    CrossProcedure,
    LimitExceeded {
        dimension: &'static str,
        limit: usize,
        attempted: usize,
    },
    InvalidReceiverPort,
    InvalidParameterOrdinal {
        ordinal: u32,
    },
    InvalidCaptureSlot {
        slot: MemoryLocationId,
    },
    InvalidAccessRoot(&'static str),
    InvalidAccessSelector(&'static str),
    InvalidSemanticScope,
    InvalidObjectCardinality(&'static str),
    ObjectPathMismatch,
    InvalidRelationIdentity,
    InvalidRelationQuality,
    DuplicateDispatchTarget,
    InconsistentCoverage,
    InvalidCallBinding(&'static str),
    InvalidStoreEvent,
    InvalidStoreObservation,
    StoreLocationMismatch,
    MismatchedObservation,
}

impl fmt::Display for OracleContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CrossProcedure => {
                formatter.write_str("oracle handles belong to different procedures")
            }
            Self::LimitExceeded {
                dimension,
                limit,
                attempted,
            } => write!(
                formatter,
                "oracle limit `{dimension}` is {limit}, but the query attempted {attempted} items"
            ),
            Self::InvalidReceiverPort => {
                formatter.write_str("procedure does not publish a receiver port")
            }
            Self::InvalidParameterOrdinal { ordinal } => {
                write!(
                    formatter,
                    "procedure does not publish parameter ordinal {ordinal}"
                )
            }
            Self::InvalidCaptureSlot { slot } => {
                write!(formatter, "memory location {slot} is not a capture slot")
            }
            Self::InvalidAccessRoot(detail)
            | Self::InvalidAccessSelector(detail)
            | Self::InvalidObjectCardinality(detail)
            | Self::InvalidCallBinding(detail) => formatter.write_str(detail),
            Self::InvalidSemanticScope => formatter
                .write_str("semantic locator does not belong to the live oracle artifact scope"),
            Self::ObjectPathMismatch => {
                formatter.write_str("abstract object identity does not match the access-path root")
            }
            Self::InvalidRelationIdentity => formatter
                .write_str("oracle relation does not belong to the required query arena and role"),
            Self::InvalidRelationQuality => formatter.write_str(
                "oracle relation claims stronger proof or completeness than its semantic evidence",
            ),
            Self::DuplicateDispatchTarget => {
                formatter.write_str("dispatch result contains a duplicate procedure target")
            }
            Self::InconsistentCoverage => formatter
                .write_str("dispatch coverage contradicts an unresolved or truncated boundary"),
            Self::InvalidStoreEvent => {
                formatter.write_str("store handle does not name a MemoryStore event")
            }
            Self::InvalidStoreObservation => formatter.write_str(
                "store observation must use the stored value immediately before its effects",
            ),
            Self::StoreLocationMismatch => {
                formatter.write_str("store access path does not match the MemoryStore location")
            }
            Self::MismatchedObservation => formatter
                .write_str("oracle observations must share one point, phase, and call context"),
        }
    }
}

impl std::error::Error for OracleContractError {}

pub(super) fn require_same_procedure(
    left: &ProcedureHandle,
    right: &ProcedureHandle,
) -> Result<(), OracleContractError> {
    if left == right {
        Ok(())
    } else {
        Err(OracleContractError::CrossProcedure)
    }
}
