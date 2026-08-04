//! Protocol-neutral code-intelligence runtime for Bifrost hosts.
//!
//! Internal implementation detail of `brokk-bifrost`; no stability guarantees --
//! depend on `brokk-bifrost` instead.

pub mod code_intelligence;

pub use brokk_bifrost_analysis::{CancellationToken, analyzer};
pub use brokk_bifrost_policy as policy;
pub use code_intelligence::CodeIntelligenceRuntime;
