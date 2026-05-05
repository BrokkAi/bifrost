//! Analyzer persistence layer (SQLite + bincode payload blobs).
//!
//! The on-disk layout is intentionally narrow: one row per analyzed file,
//! plus a per-language epoch row. The reconcile algorithm at startup is:
//!
//! 1. Open the DB, run sequential migrations, run `PRAGMA integrity_check`.
//! 2. Read the persisted baseline for the language we are about to analyze.
//! 3. Compute the current `analysis_epoch` (grammar + query content + crate
//!    version). If it differs from what was persisted, every baseline row
//!    is logically dirty and is re-analyzed.
//! 4. Otherwise compare each candidate file's `(mtime_ns, size)` against
//!    its baseline row to decide `clean` vs. `dirty`. Files in the
//!    workspace but not in the baseline are dirty (new). Baseline rows
//!    whose paths are no longer in the workspace are deletes.
//! 5. Hydrate `clean` rows from blob payload; analyze `dirty` files via the
//!    existing tree-sitter pipeline.
//! 6. Persist all `dirty` payloads and apply deletes in a single
//!    transaction, then update the epoch.
//!
//! See `reconcile` for the implementation; `storage` for the open/read/
//! write API.

mod epoch;
mod migrations;
mod payload;
pub(crate) mod reconcile;
mod storage;

pub use storage::{
    AnalyzerStorage, BaselineRow, DB_FILE_NAME, DEFAULT_CACHE_DIR, PersistenceError, Result,
    WriteRow, default_db_path,
};

pub(crate) use epoch::epoch_for;
pub(crate) use payload::{decode, encode};
