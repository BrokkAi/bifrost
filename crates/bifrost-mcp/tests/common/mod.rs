#[path = "../../../../test-support/inline_project.rs"]
mod inline_project;
#[path = "../../../../test-support/scratch_cache.rs"]
mod scratch_cache;

pub use inline_project::{BuiltInlineTestProject, InlineTestProject};
pub use scratch_cache::FixtureCorpus;
