//! Protocol-neutral code-intelligence runtime for Bifrost hosts.
//!
//! [`extension`] is the supported application boundary. Other exports are host
//! implementation interfaces and carry no compatibility guarantee.

pub mod code_intelligence;
pub mod extension;

pub use brokk_bifrost_analysis::{CancellationToken, analyzer};
pub use brokk_bifrost_policy as policy;
pub use code_intelligence::CodeIntelligenceRuntime;
