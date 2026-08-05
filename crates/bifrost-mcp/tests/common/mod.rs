#[path = "../../../../tests/common/inline_project.rs"]
mod inline_project;
#[path = "../../../../tests/common/scratch_cache.rs"]
mod scratch_cache;

pub use inline_project::InlineTestProject;
pub use scratch_cache::FixtureCorpus;
