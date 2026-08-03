//! Protocol-neutral code-intelligence runtime for Bifrost hosts.

pub mod code_intelligence;

pub use brokk_bifrost_analysis::{CancellationToken, analyzer};
pub use brokk_bifrost_policy as policy;
pub use code_intelligence::CodeIntelligenceRuntime;
