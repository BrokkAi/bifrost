//! Operational classification for semantic producers.

pub use brokk_bifrost_core::analyzer::derivation_cause::*;

pub fn from_cfg_error<Node: std::fmt::Debug>(
    error: &crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmError<Node>,
) -> DerivationExecutionCause {
    use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmError;
    match error {
        CfgAlgorithmError::Cancelled { .. } => DerivationExecutionCause::Cancelled,
        CfgAlgorithmError::ExceededBudget(_) => DerivationExecutionCause::Budget,
        CfgAlgorithmError::InvalidNode(node) => {
            panic!("validated procedure has invalid CFG point {node:?}")
        }
    }
}
