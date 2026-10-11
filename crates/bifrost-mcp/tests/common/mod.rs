#[path = "../../../../test-support/inline_project.rs"]
mod inline_project;
#[allow(dead_code)]
#[path = "../../../../test-support/mcp_server.rs"]
pub mod mcp_server;
#[allow(dead_code)]
#[path = "../../../../test-support/mcp_wire.rs"]
pub mod mcp_wire;
#[path = "../../../../test-support/policy_report.rs"]
pub mod policy_report;
#[path = "../../../../test-support/scratch_cache.rs"]
mod scratch_cache;

pub use inline_project::{BuiltInlineTestProject, InlineTestProject};
pub use scratch_cache::FixtureCorpus;

#[allow(dead_code)]
pub fn stateless_search_symbols_call(id: i64, pattern: &str) -> serde_json::Value {
    mcp_server::stateless_search_symbols_call(id, pattern, mcp_server::stateless_meta())
}
