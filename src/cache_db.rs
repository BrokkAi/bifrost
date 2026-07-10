//! Shared SQLite setup for Bifrost's rebuildable cache database.
//!
//! Milestone 1 needs the stable filename for primary-repository path
//! resolution. Connection and schema lifecycle are added in Milestone 2.

pub(crate) const CACHE_DB_FILE_NAME: &str = "bifrost_cache.db";
