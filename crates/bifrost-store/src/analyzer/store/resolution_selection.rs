//! Connection-local selection of complete persisted resolution interiors.
//!
//! This module owns only the exact mount inventory. Fact-family readers and
//! transient replacement lowering are later Milestone 5 tranches.

use std::cell::{Cell, OnceCell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use git2::Oid;
use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension, Transaction, params, params_from_iter};

use brokk_bifrost_core::analyzer::canonical_hash::{
    CanonicalHasher, lower_hex_string, parse_lower_sha256,
};

use crate::CancellationToken;
use crate::analyzer::resolution::{
    BindingFragmentId, MountRebaser, SelectedContextPathToken, SelectedResolutionFragmentDigest,
    SelectedResolutionMountOrdinal, language_has_jvm_semantics, selected_resolution_fragment_id,
};

use crate::hash::{HashMap, HashSet};

type PythonReceiverRows = super::selected_read_memo::RequestReadCache<(i64, u32), Vec<(u32, u32)>>;

pub(crate) use super::resolution::ResolutionManifestCounts;
use super::resolution::{
    RESOLUTION_MANIFEST_COUNT_COLUMNS, resolution_bundle_epoch, with_resolution_progress_handler,
};

use super::{
    AnalyzerStore, GenerationId, PathSymbolRow, ReaderGuard, Result, StoreError,
    WorkspaceAnchorRow, WorkspaceFileRow, WorkspaceId, WorkspacePackageEdgeRow,
    WorkspacePackageFileRow, WorkspaceSnapshotId, WorkspaceSnapshots,
    ensure_revisioned_workspace_views, selected_workspace_file_projection_digest,
};

use crate::analyzer::Language;

const SELECTED_RESOLUTION_INPUT_SCHEMA_SQL: &str = r#"
CREATE TEMP TABLE IF NOT EXISTS selected_resolution_context(
  singleton    INTEGER NOT NULL PRIMARY KEY CHECK(singleton = 0),
  workspace_id TEXT NOT NULL
) WITHOUT ROWID, STRICT;

CREATE TEMP TABLE IF NOT EXISTS selected_resolution_languages(
  storage_language                  TEXT NOT NULL PRIMARY KEY,
  semantic_language                 TEXT NOT NULL,
  expected_producer_epoch           TEXT NOT NULL,
  expected_base_mount_count         INTEGER NOT NULL DEFAULT 0 CHECK(expected_base_mount_count >= 0),
  masked_base_mount_count           INTEGER NOT NULL DEFAULT 0 CHECK(masked_base_mount_count >= 0),
  expected_unmasked_mount_count     INTEGER NOT NULL DEFAULT 0 CHECK(expected_unmasked_mount_count >= 0)
) WITHOUT ROWID, STRICT;

CREATE TEMP TABLE IF NOT EXISTS selected_resolution_overlay_masks(
  storage_language                     TEXT NOT NULL,
  persisted_relative_path              TEXT NOT NULL CHECK(length(persisted_relative_path) > 0),
  intent                               TEXT NOT NULL CHECK(intent IN ('replacement', 'removal')),
  masked_file_version_id               INTEGER,
  masked_blob_oid                      TEXT,
  masked_projection_digest             BLOB,
  expected_transient_replacement_count INTEGER NOT NULL DEFAULT 0
    CHECK(expected_transient_replacement_count IN (0, 1)),
  PRIMARY KEY(storage_language, persisted_relative_path),
  CHECK((masked_file_version_id IS NULL) = (masked_blob_oid IS NULL)),
  CHECK((masked_file_version_id IS NULL) = (masked_projection_digest IS NULL)),
  CHECK(masked_projection_digest IS NULL OR
        (typeof(masked_projection_digest) = 'blob' AND length(masked_projection_digest) = 32))
) WITHOUT ROWID, STRICT;

CREATE TEMP TABLE IF NOT EXISTS selected_resolution_content_mounts(
  storage_language         TEXT NOT NULL,
  generation               INTEGER NOT NULL CHECK(generation >= 0),
  persisted_relative_path  TEXT NOT NULL CHECK(length(persisted_relative_path) > 0),
  blob_oid                 TEXT NOT NULL,
  publication_digest      BLOB NOT NULL CHECK(length(publication_digest)=32),
  projection_digest       BLOB NOT NULL
    CHECK(typeof(projection_digest) = 'blob' AND length(projection_digest) = 32),
  overlay_authority_kind INTEGER NOT NULL DEFAULT 0 CHECK(overlay_authority_kind IN (0,1,2)),
  overlay_authority_digest BLOB,
  CHECK((overlay_authority_kind=0 AND overlay_authority_digest IS NULL) OR
        (overlay_authority_kind<>0 AND typeof(overlay_authority_digest)='blob' AND length(overlay_authority_digest)=32)),
  PRIMARY KEY(storage_language, persisted_relative_path)
) WITHOUT ROWID, STRICT;

"#;

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static SELECTED_STATIC_SQL_CAPACITIES: std::cell::Cell<[usize; 17]> = const {
        std::cell::Cell::new([0; 17])
    };
}

#[cfg(any(test, feature = "test-support"))]
pub(in crate::analyzer::store) fn note_selected_static_sql_capacity(index: usize, capacity: usize) {
    SELECTED_STATIC_SQL_CAPACITIES.with(|values| {
        let mut capacities = values.get();
        assert_eq!(capacities[index], 0, "static SQL initializes once");
        capacities[index] = capacity;
        values.set(capacities);
    });
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn selected_static_sql_capacities() -> [(&'static str, usize); 17] {
    let capacities = SELECTED_STATIC_SQL_CAPACITIES.with(std::cell::Cell::get);
    let names = [
        "temp_schema",
        "mount_status_initial",
        "mount_status_continuation",
        "content_mount_status",
        "mount_record_columns",
        "stage_schema",
        "stage_validate_admission",
        "stage_admission_validation_sql",
        "stage_admission_validation_body",
        "stage_rows_schema",
        "stage_reverse_candidates",
        "stage_candidate_unconditional",
        "stage_candidate_branches",
        "stage_root_terminal_candidates",
        "stage_effective_gap_remains",
        "stage_frontier_completion",
        "stage_capsule_closed_reasons",
    ];
    std::array::from_fn(|index| (names[index], capacities[index]))
}

#[doc(hidden)]
pub fn selected_resolution_temp_schema_sql() -> &'static str {
    static SQL: OnceLock<String> = OnceLock::new();
    SQL.get_or_init(|| {
        let count_columns = RESOLUTION_MANIFEST_COUNT_COLUMNS
            .iter()
            .map(|column| format!("  {column} INTEGER NOT NULL CHECK({column} >= 0)"))
            .collect::<Vec<_>>()
            .join(",\n");
        let sql = format!(
            "{SELECTED_RESOLUTION_INPUT_SCHEMA_SQL}
             {stage_schema}
             CREATE TEMP TABLE IF NOT EXISTS selected_resolution_mounts(
               mount_ordinal       INTEGER NOT NULL PRIMARY KEY CHECK(mount_ordinal >= 0),
               fragment_id         BLOB NOT NULL UNIQUE
                 CHECK(typeof(fragment_id) = 'blob' AND length(fragment_id) = 32),
               workspace_id        TEXT NOT NULL,
               revision            INTEGER NOT NULL CHECK(revision > 0),
               generation          INTEGER NOT NULL CHECK(generation >= 0),
               file_version_id     INTEGER UNIQUE,
               storage_language    TEXT NOT NULL,
               semantic_language   TEXT NOT NULL,
               persisted_relative_path TEXT NOT NULL,
               blob_id             INTEGER NOT NULL,
               blob_oid            TEXT NOT NULL,
               projection_digest   BLOB NOT NULL
                 CHECK(typeof(projection_digest) = 'blob' AND length(projection_digest) = 32),
               interior_digest     BLOB NOT NULL
                 CHECK(typeof(interior_digest) = 'blob' AND length(interior_digest) = 32),
               producer_epoch      TEXT NOT NULL,
               logical_rows        INTEGER NOT NULL CHECK(logical_rows >= 1),
               payload_bytes       INTEGER NOT NULL CHECK(payload_bytes >= 0),
             {count_columns},
               UNIQUE(storage_language, persisted_relative_path)
             ) WITHOUT ROWID, STRICT;
             CREATE INDEX IF NOT EXISTS temp.selected_resolution_mounts_blob_ordinal
               ON selected_resolution_mounts(blob_id, mount_ordinal);
             {go_placements}
             CREATE TEMP TABLE IF NOT EXISTS selected_resolution_scope_mounts(
               mount_ordinal INTEGER NOT NULL PRIMARY KEY CHECK(mount_ordinal >= 0)
             ) WITHOUT ROWID, STRICT;
             {module_placements_schema}",
            stage_schema = super::resolution_stage::schema_sql(),
            module_placements_schema = super::resolution_operation::rust_crate_context::SELECTED_MODULE_PLACEMENTS_SCHEMA_SQL,
            go_placements = super::resolution_operation::go_context::GO_TRANSIENT_PLACEMENTS_SQL,
        );
        #[cfg(any(test, feature = "test-support"))]
        note_selected_static_sql_capacity(0, sql.capacity());
        sql
    })
}

// One declaration owns the guard names in installation, cleanup and test support.
macro_rules! selected_mount_guards {
    ($($name:ident => $event:literal),+; $clear:literal) => {
        const SELECTED_MOUNT_GUARDS_SQL: &str = concat!($(
            "CREATE TEMP TRIGGER ", stringify!($name), " BEFORE ", $event,
            " ON temp.selected_resolution_mounts BEGIN SELECT RAISE(ABORT, '",
            "selected resolution mounts are immutable while retained",
            "'); END;",
        )+);
        #[cfg(any(test, feature = "test-support"))]
        const DROP_SELECTED_MOUNT_GUARDS_SQL: &str = concat!($(
            "DROP TRIGGER IF EXISTS temp.", stringify!($name), ";",
        )+);
        #[doc(hidden)]
        pub const CLEAR_SELECTED_RESOLUTION_TEMP_SQL: &str = concat!($(
            "DROP TRIGGER IF EXISTS temp.", stringify!($name), ";",
        )+ $clear);
    };
}

selected_mount_guards! {
    selected_resolution_mounts_no_insert => "INSERT",
    selected_resolution_mounts_no_update => "UPDATE",
    selected_resolution_mounts_no_delete => "DELETE";
r#"
DELETE FROM temp.selected_resolution_stage_producers;
DELETE FROM temp.selected_resolution_stage_nodes;
DELETE FROM temp.selected_resolution_admissions;
DELETE FROM temp.selected_resolution_scope_mounts;
DELETE FROM temp.selected_rust_transient_placement_attributes;
DELETE FROM temp.selected_resolution_transient_placements;
DELETE FROM temp.selected_resolution_mounts;
DELETE FROM temp.selected_resolution_overlay_masks;
DELETE FROM temp.selected_resolution_content_mounts;
DELETE FROM temp.selected_resolution_languages;
DELETE FROM temp.selected_resolution_context;
DELETE FROM temp.selected_rust_unit_closure;
DELETE FROM temp.selected_rust_unit_summaries;
DELETE FROM temp.selected_workspace_revisions;
"#
}

/// Tests that deliberately replace selected mount rows must remove their guards.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn drop_selected_mount_guards_for_test(conn: &Connection) -> Result<()> {
    conn.execute_batch(DROP_SELECTED_MOUNT_GUARDS_SQL)?;
    Ok(())
}

/// The mounts a request may bind into, restored to the whole selection.
///
/// Every membership read that turns a name into a set of blobs joins
/// `temp.selected_resolution_scope_mounts`, so the scope is not an optional
/// predicate a reader can forget: it is the only route from a name to a mount.
/// The default content is the whole selection, which is what a reverse request
/// and every non-Rust request need. A forward Rust request narrows it to its
/// own crate's dependency closure for the length of that request and this
/// statement puts it back.
pub(super) const RESET_SELECTED_RESOLUTION_SCOPE_SQL: &str = r#"
DELETE FROM temp.selected_resolution_scope_mounts;
INSERT INTO temp.selected_resolution_scope_mounts(mount_ordinal)
SELECT mount_ordinal FROM temp.selected_resolution_mounts;
"#;

pub(super) const SELECTED_MOUNT_PAGE_ROWS: usize = 256;

/// One index seek of the selection's path key. The temp table declares
/// `UNIQUE(storage_language, persisted_relative_path)`, so at most one row
/// matches and SQLite reads it through that index.
const SELECTED_MOUNT_ORDINAL_BY_PATH_SQL: &str = r#"
SELECT mounts.mount_ordinal
FROM temp.selected_resolution_mounts AS mounts
WHERE mounts.storage_language = ?1 AND mounts.persisted_relative_path = ?2
"#;

#[doc(hidden)]
pub const SELECTED_LANGUAGE_AUTHORITY_SQL: &str = r#"
SELECT languages.storage_language, languages.semantic_language,
       languages.expected_producer_epoch,
       selected.workspace_id, selected.generation, selected.revision,
       revisions.revision, COALESCE(epochs.generation, 0), active.producer_epoch
FROM temp.selected_resolution_languages AS languages
LEFT JOIN temp.selected_workspace_revisions AS selected
  ON selected.lang = languages.storage_language
LEFT JOIN main.workspace_revisions AS revisions
  ON revisions.workspace_id = selected.workspace_id
 AND revisions.lang = selected.lang
 AND revisions.generation = selected.generation
 AND revisions.revision = selected.revision
LEFT JOIN main.analysis_epochs AS epochs
  ON epochs.lang = languages.storage_language
LEFT JOIN main.resolution_producer_epochs AS active
  ON active.lang = languages.storage_language
ORDER BY languages.storage_language
"#;

#[doc(hidden)]
pub const SELECTED_MASK_PAGE_INITIAL_SQL: &str = r#"
SELECT masks.persisted_relative_path, masks.intent
FROM temp.selected_resolution_overlay_masks AS masks
WHERE masks.storage_language = ?1
ORDER BY masks.persisted_relative_path
LIMIT 256
"#;

#[doc(hidden)]
pub const SELECTED_MASK_PAGE_CONTINUATION_SQL: &str = r#"
SELECT masks.persisted_relative_path, masks.intent
FROM temp.selected_resolution_overlay_masks AS masks
WHERE masks.storage_language = ?1 AND masks.persisted_relative_path > ?2
ORDER BY masks.persisted_relative_path
LIMIT 256
"#;

#[doc(hidden)]
pub const SELECTED_MASK_BASE_SQL: &str = r#"
SELECT files.file_version_id, files.blob_oid, files.projection_digest
FROM temp.selected_workspace_file_versions AS files
WHERE files.lang = ?1 AND files.rel_path = ?2
ORDER BY files.valid_from
LIMIT 2
"#;

fn selected_mount_status_counts() -> String {
    RESOLUTION_MANIFEST_COUNT_COLUMNS
        .iter()
        .map(|column| format!("interiors.{column}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn selected_mount_status_joins(mount_alias: &str, language_column: &str) -> String {
    format!(
        "LEFT JOIN main.blobs AS blobs\n\
           ON blobs.blob_oid = {mount_alias}.blob_oid\n\
          AND blobs.lang = {mount_alias}.{language_column}\n\
         LEFT JOIN main.blob_meta AS meta\n\
           ON meta.blob_id = blobs.id\n\
          AND meta.lang = blobs.lang\n\
          AND EXISTS (\n\
            SELECT 1 FROM main.source_fact_readiness AS visibility\n\
            WHERE visibility.blob_id = blobs.id AND visibility.available = 1\n\
          )\n\
         LEFT JOIN main.resolution_fragment_interiors AS interiors\n\
           ON interiors.blob_id = blobs.id"
    )
}

#[doc(hidden)]
pub fn selected_mount_status_sql(continuation: bool) -> &'static str {
    static INITIAL_SQL: OnceLock<String> = OnceLock::new();
    static CONTINUATION_SQL: OnceLock<String> = OnceLock::new();
    let cell = if continuation {
        &CONTINUATION_SQL
    } else {
        &INITIAL_SQL
    };
    cell.get_or_init(|| {
        let counts = selected_mount_status_counts();
        let status_joins = selected_mount_status_joins("files", "lang");
        let sql = format!(
            "SELECT files.workspace_id, files.revision, files.file_version_id,
                    files.valid_from, files.lang, files.generation, files.rel_path, files.blob_oid,
                    files.projection_digest, blobs.id, blobs.generation,
                    meta.is_complete,
                    interiors.lang, interiors.semantic_language,
                    interiors.producer_epoch, interiors.interior_digest,
                    interiors.publication_state, interiors.logical_rows,
                    interiors.payload_bytes, {counts}
             FROM temp.selected_resolution_languages AS languages
             CROSS JOIN temp.selected_workspace_file_versions AS files
               ON files.lang = languages.storage_language
             LEFT JOIN temp.selected_resolution_overlay_masks AS masks
               ON masks.storage_language = files.lang
              AND masks.persisted_relative_path = files.rel_path
             {status_joins}
             WHERE languages.storage_language = ?1
               AND masks.storage_language IS NULL
               {continuation_predicate}
             ORDER BY files.rel_path, files.valid_from
             LIMIT {SELECTED_MOUNT_PAGE_ROWS}",
            continuation_predicate = if continuation {
                "AND (files.rel_path, files.valid_from) > (?2, ?3)"
            } else {
                ""
            },
        );
        #[cfg(any(test, feature = "test-support"))]
        note_selected_static_sql_capacity(if continuation { 2 } else { 1 }, sql.capacity());
        sql
    })
}

#[doc(hidden)]
pub fn selected_content_mount_status_sql() -> &'static str {
    static SQL: OnceLock<String> = OnceLock::new();
    SQL.get_or_init(|| {
        let counts = selected_mount_status_counts();
        let status_joins = selected_mount_status_joins("requests", "storage_language");
        let sql = format!(
            "SELECT requests.storage_language, requests.generation,
                    requests.persisted_relative_path, requests.blob_oid,
                    requests.projection_digest, blobs.id, blobs.generation,
                    meta.is_complete,
                    interiors.lang, interiors.semantic_language,
                    interiors.producer_epoch, interiors.interior_digest,
                    interiors.publication_state, interiors.logical_rows,
                    interiors.payload_bytes, {counts}
             FROM temp.selected_resolution_content_mounts AS requests
             {status_joins}
             ORDER BY requests.storage_language, requests.persisted_relative_path"
        );
        #[cfg(any(test, feature = "test-support"))]
        note_selected_static_sql_capacity(3, sql.capacity());
        sql
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct SelectedResolutionLanguage {
    #[doc(hidden)]
    pub storage_language: String,
    semantic_language: Language,
}

impl SelectedResolutionLanguage {
    #[doc(hidden)]
    pub fn new(storage_language: impl Into<String>, semantic_language: Language) -> Self {
        let storage_language = storage_language.into();
        assert!(
            !storage_language.is_empty(),
            "selected resolution storage language must not be empty"
        );
        assert_ne!(
            semantic_language,
            Language::None,
            "selected resolution semantic language must be analyzable"
        );
        Self {
            storage_language,
            semantic_language,
        }
    }

    #[doc(hidden)]
    pub fn storage_language(&self) -> &str {
        &self.storage_language
    }

    #[doc(hidden)]
    pub const fn semantic_language(&self) -> Language {
        self.semantic_language
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct SelectedResolutionOverlayMask {
    storage_language: String,
    persisted_relative_path: String,
    intent: SelectedResolutionOverlayIntent,
}

impl SelectedResolutionOverlayMask {
    #[doc(hidden)]
    pub fn replacement(
        storage_language: impl Into<String>,
        persisted_relative_path: impl Into<String>,
    ) -> Self {
        Self::new(
            storage_language,
            persisted_relative_path,
            SelectedResolutionOverlayIntent::Replacement,
        )
    }

    #[doc(hidden)]
    pub fn removal(
        storage_language: impl Into<String>,
        persisted_relative_path: impl Into<String>,
    ) -> Self {
        Self::new(
            storage_language,
            persisted_relative_path,
            SelectedResolutionOverlayIntent::Removal,
        )
    }

    fn new(
        storage_language: impl Into<String>,
        persisted_relative_path: impl Into<String>,
        intent: SelectedResolutionOverlayIntent,
    ) -> Self {
        let storage_language = storage_language.into();
        let persisted_relative_path = persisted_relative_path.into();
        assert!(
            !storage_language.is_empty(),
            "selected resolution mask needs a storage language"
        );
        assert!(
            !persisted_relative_path.is_empty(),
            "selected resolution mask needs a persisted relative path"
        );
        Self {
            storage_language,
            persisted_relative_path,
            intent,
        }
    }

    pub(crate) fn storage_language(&self) -> &str {
        &self.storage_language
    }

    pub(crate) fn persisted_relative_path(&self) -> &str {
        &self.persisted_relative_path
    }

    pub(crate) const fn intent(&self) -> SelectedResolutionOverlayIntent {
        self.intent
    }
}

/// A persisted resolution interior mounted for an exact content OID while a
/// selected overlay replaces the workspace revision's path. The projection
/// digest is derived from structured workspace rows at construction time;
/// callers cannot supply an opaque digest or fragment identity.
#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct SelectedResolutionContentMountRequest {
    #[doc(hidden)]
    pub publication: super::resolution_publication::ResolutionContentWitness,
    storage_language: String,
    generation: GenerationId,
    file: WorkspaceFileRow,
    projection_digest: [u8; 32],
    #[doc(hidden)]
    pub overlay_authority: Option<SelectedResolutionOverlayAuthority>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum SelectedResolutionOverlayAuthority {
    LiveOverlay { content_digest: [u8; 32] },
    Counterfactual { base_content_digest: [u8; 32] },
}

impl SelectedResolutionContentMountRequest {
    #[doc(hidden)]
    pub fn publication(&self) -> &super::resolution_publication::ResolutionContentWitness {
        &self.publication
    }

    fn publication_digest(&self) -> [u8; 32] {
        let witness = &self.publication;
        let owner = witness.owner();
        let mut hash = CanonicalHasher::new(b"bifrost-content-mount-publication:v1");
        hash.field("workspace", owner.workspace_id.as_str().as_bytes());
        hash.field("language", owner.lang.as_bytes());
        hash.field("generation", &owner.generation.get().to_be_bytes());
        hash.field("revision", &owner.revision.to_be_bytes());
        hash.field("blob_id", &witness.blob_id().to_be_bytes());
        hash.field("blob_oid", witness.blob_oid().as_bytes());
        hash.field("manifest", &witness.manifest_digest());
        hash.field("producer", witness.producer_epoch().as_bytes());
        hash.field("logical_rows", &witness.logical_rows().to_be_bytes());
        hash.field("payload_bytes", &witness.payload_bytes().to_be_bytes());
        for count in witness.manifest_counts().values() {
            hash.field("count", &count.to_be_bytes());
        }
        let super::resolution_publication::ResolutionContentInput::Parsed {
            semantic_language, ..
        } = witness.input()
        else {
            unreachable!("ordinary content constructor accepts only parsed witnesses")
        };
        hash.field(
            "semantic_language",
            semantic_language.config_label().as_bytes(),
        );
        hash.finish()
    }

    fn validate_publication(
        &self,
        conn: &Connection,
        owner: &WorkspaceSnapshotId,
        cancellation: &CancellationToken,
    ) -> Result<Option<StagedSelection>> {
        use super::resolution_publication::{
            ResolutionContentInput, ResolutionContentPublicationOutcome,
        };

        if cancellation.is_cancelled() {
            return Ok(Some(StagedSelection::Cancelled));
        }
        let witness = &self.publication;
        if witness.owner() != owner {
            return Ok(Some(StagedSelection::Stale(
                SelectedResolutionStale::WorkspaceRevision {
                    storage_language: self.storage_language.clone(),
                },
            )));
        }
        if let Some(outcome) = super::resolution_publication::validate_owner_conn(
            conn,
            owner,
            witness.producer_epoch(),
        )? {
            return Ok(Some(match outcome {
                ResolutionContentPublicationOutcome::Cancelled => StagedSelection::Cancelled,
                ResolutionContentPublicationOutcome::Stale(stale) => StagedSelection::Stale(stale),
                ResolutionContentPublicationOutcome::Unavailable(unavailable) => {
                    StagedSelection::Unavailable(unavailable)
                }
                ResolutionContentPublicationOutcome::Ready(_) => {
                    unreachable!("owner validation does not publish content")
                }
            }));
        }
        let columns = RESOLUTION_MANIFEST_COUNT_COLUMNS
            .iter()
            .map(|column| format!("manifest.{column}"))
            .collect::<Vec<_>>()
            .join(",");
        let sql=format!("SELECT manifest.interior_digest,manifest.producer_epoch,manifest.logical_rows,
            manifest.payload_bytes,manifest.semantic_language,{columns}
            FROM blobs AS blob JOIN resolution_fragment_interiors AS manifest ON manifest.blob_id=blob.id
            JOIN blob_meta AS meta ON meta.blob_id=blob.id AND meta.is_complete=1
            JOIN source_fact_readiness AS source ON source.blob_id=blob.id AND source.available=1
            JOIN workspace_resolution_content_roots AS root ON root.blob_id=blob.id
            WHERE blob.id=?1 AND blob.blob_oid=?2 AND blob.lang=?3 AND blob.generation=?4
            AND manifest.lang=?3 AND manifest.publication_state='complete'
            AND root.workspace_id=?5 AND root.lang=?3 AND root.generation=?4 AND root.revision=?6");
        let actual = conn
            .prepare_cached(&sql)?
            .query_row(
                params![
                    witness.blob_id(),
                    witness.blob_oid().to_string(),
                    owner.lang,
                    owner.generation.get(),
                    owner.workspace_id.as_str(),
                    owner.revision
                ],
                |row| {
                    let digest: Vec<u8> = row.get(0)?;
                    let producer: String = row.get(1)?;
                    let logical: u64 = row.get(2)?;
                    let payload: u64 = row.get(3)?;
                    let semantic: String = row.get(4)?;
                    let mut counts = [0; RESOLUTION_MANIFEST_COUNT_COLUMNS.len()];
                    for (index, count) in counts.iter_mut().enumerate() {
                        *count = row.get::<_, u64>(index + 5)?;
                    }
                    Ok((digest, producer, logical, payload, semantic, counts))
                },
            )
            .optional()?;
        if cancellation.is_cancelled() {
            return Ok(Some(StagedSelection::Cancelled));
        }
        if actual.is_none() {
            let (blob_exists, state, parsed_ready):(bool,Option<String>,bool)=conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM blobs WHERE id=?1),
                    (SELECT publication_state FROM resolution_fragment_interiors WHERE blob_id=?1),
                    EXISTS(SELECT 1 FROM blob_meta AS meta JOIN source_fact_readiness AS source ON source.blob_id=meta.blob_id
                        WHERE meta.blob_id=?1 AND meta.is_complete=1 AND source.available=1)",
                [witness.blob_id()], |row|Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?;
            let unavailable = if !blob_exists {
                Some(SelectedResolutionUnavailable::MissingBlob {
                    storage_language: self.storage_language.clone(),
                    persisted_relative_path: self.file.rel_path.clone(),
                })
            } else if state.is_none() {
                Some(SelectedResolutionUnavailable::MissingInterior {
                    storage_language: self.storage_language.clone(),
                    persisted_relative_path: self.file.rel_path.clone(),
                })
            } else if state.as_deref() != Some("complete") {
                Some(SelectedResolutionUnavailable::IncompleteInterior {
                    storage_language: self.storage_language.clone(),
                    persisted_relative_path: self.file.rel_path.clone(),
                })
            } else if !parsed_ready {
                Some(SelectedResolutionUnavailable::IncompleteParsedBlob {
                    storage_language: self.storage_language.clone(),
                    persisted_relative_path: self.file.rel_path.clone(),
                })
            } else {
                None
            };
            if let Some(unavailable) = unavailable {
                return Ok(Some(StagedSelection::Unavailable(unavailable)));
            }
        }
        let ResolutionContentInput::Parsed {
            semantic_language, ..
        } = witness.input()
        else {
            unreachable!()
        };
        if actual.is_some_and(|(digest, producer, logical, payload, semantic, counts)| {
            digest.as_slice() == witness.manifest_digest()
                && producer == witness.producer_epoch()
                && logical == witness.logical_rows()
                && payload == witness.payload_bytes()
                && semantic == semantic_language.config_label()
                && counts.as_slice() == witness.manifest_counts().values()
        }) {
            Ok(None)
        } else {
            Ok(Some(StagedSelection::Unavailable(
                SelectedResolutionUnavailable::InteriorOwnershipMismatch {
                    storage_language: self.storage_language.clone(),
                    persisted_relative_path: self.file.rel_path.clone(),
                },
            )))
        }
    }

    fn overlay_authority_columns(&self) -> (i64, Option<&[u8; 32]>) {
        match &self.overlay_authority {
            None => (0, None),
            Some(SelectedResolutionOverlayAuthority::LiveOverlay { content_digest }) => {
                (1, Some(content_digest))
            }
            Some(SelectedResolutionOverlayAuthority::Counterfactual {
                base_content_digest,
            }) => (2, Some(base_content_digest)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    pub fn new(
        publication: super::resolution_publication::ResolutionContentWitness,
        file: WorkspaceFileRow,
        path_symbols: Vec<PathSymbolRow>,
        package_files: Vec<WorkspacePackageFileRow>,
        package_edges: Vec<WorkspacePackageEdgeRow>,
        anchors: Vec<WorkspaceAnchorRow>,
    ) -> Self {
        use super::resolution_publication::ResolutionContentInput;
        let ResolutionContentInput::Parsed {
            content_oid,
            semantic_language,
        } = publication.input()
        else {
            panic!("ordinary content mounts require published parsed content");
        };
        assert_eq!(
            *content_oid, file.blob_oid,
            "parsed publication input has the mounted source OID"
        );
        assert_eq!(
            publication.blob_oid(),
            file.blob_oid,
            "published blob owns the mounted source OID"
        );
        assert_eq!(
            publication.producer_epoch(),
            resolution_bundle_epoch(*semantic_language),
            "parsed publication has its selected semantic producer"
        );
        let storage_language = publication.owner().lang.clone();
        let generation = publication.owner().generation;
        assert!(
            !storage_language.is_empty(),
            "a content mount needs a storage language"
        );
        assert!(
            !file.rel_path.is_empty(),
            "a content mount needs a persisted relative path"
        );
        let mut path_symbol_keys = BTreeSet::new();
        for row in &path_symbols {
            assert_eq!(
                row.rel_path, file.rel_path,
                "content mount path-symbol row belongs to a foreign path"
            );
            assert_eq!(
                row.blob_oid, file.blob_oid,
                "content mount path-symbol OID does not match the file OID"
            );
            assert!(
                path_symbol_keys.insert((row.exact_fqn.as_str(), row.kind)),
                "content mount path-symbol natural key repeats"
            );
        }
        let mut package_file_keys = BTreeSet::new();
        for row in &package_files {
            assert_eq!(
                row.rel_path, file.rel_path,
                "content mount package-file row belongs to a foreign path"
            );
            assert!(
                package_file_keys.insert(row.package_name.as_str()),
                "content mount package-file natural key repeats"
            );
        }
        let mut edge_keys = BTreeSet::new();
        for row in &package_edges {
            assert_eq!(
                row.rel_path, file.rel_path,
                "content mount package-edge row belongs to a foreign path"
            );
            assert_ne!(
                row.parent_package_name, row.child_package_name,
                "content mount package edge cannot be self-referential"
            );
            assert!(
                edge_keys.insert((
                    row.parent_package_name.as_str(),
                    row.child_package_name.as_str(),
                )),
                "content mount package-edge natural key repeats"
            );
        }
        let mut anchor_keys = BTreeSet::new();
        for row in &anchors {
            assert_eq!(
                row.rel_path, file.rel_path,
                "content mount anchor row belongs to a foreign path"
            );
            assert!(
                anchor_keys.insert(row.anchor),
                "content mount anchor natural key repeats"
            );
        }
        let projection_digest = selected_workspace_file_projection_digest(
            &file,
            &path_symbols,
            &package_files,
            &package_edges,
            &anchors,
        );
        Self {
            publication,
            storage_language,
            generation,
            file,
            projection_digest,
            overlay_authority: None,
        }
    }

    #[doc(hidden)]
    pub fn with_live_overlay_content_digest(self, content_digest: [u8; 32]) -> Self {
        self.with_overlay_authority(SelectedResolutionOverlayAuthority::LiveOverlay {
            content_digest,
        })
    }

    #[doc(hidden)]
    pub fn with_counterfactual_base_content_digest(self, base_content_digest: [u8; 32]) -> Self {
        self.with_overlay_authority(SelectedResolutionOverlayAuthority::Counterfactual {
            base_content_digest,
        })
    }

    fn with_overlay_authority(mut self, authority: SelectedResolutionOverlayAuthority) -> Self {
        assert!(
            self.overlay_authority.replace(authority).is_none(),
            "a content mount cannot have two overlay authorities"
        );
        self
    }

    pub(crate) fn storage_language(&self) -> &str {
        &self.storage_language
    }

    pub(crate) const fn generation(&self) -> GenerationId {
        self.generation
    }

    #[doc(hidden)]
    pub fn persisted_relative_path(&self) -> &str {
        &self.file.rel_path
    }

    #[doc(hidden)]
    pub const fn blob_oid(&self) -> Oid {
        self.file.blob_oid
    }

    pub(crate) const fn projection_digest(&self) -> [u8; 32] {
        self.projection_digest
    }

    #[doc(hidden)]
    pub fn overlay_authority(&self) -> Option<&SelectedResolutionOverlayAuthority> {
        self.overlay_authority.as_ref()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SelectedResolutionOverlayIntent {
    Replacement,
    Removal,
}

impl SelectedResolutionOverlayIntent {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Replacement => "replacement",
            Self::Removal => "removal",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "replacement" => Some(Self::Replacement),
            "removal" => Some(Self::Removal),
            _ => None,
        }
    }

    const fn expected_transient_replacement_count(self) -> u32 {
        match self {
            Self::Replacement => 1,
            Self::Removal => 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct SelectedResolutionMaskedBase {
    file_version_id: i64,
    blob_oid: Oid,
    projection_digest: [u8; 32],
}

impl SelectedResolutionMaskedBase {
    pub(crate) const fn file_version_id(&self) -> i64 {
        self.file_version_id
    }

    pub(crate) const fn blob_oid(&self) -> Oid {
        self.blob_oid
    }

    pub(crate) const fn projection_digest(&self) -> [u8; 32] {
        self.projection_digest
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct SelectedResolutionOverlayMaskState {
    storage_language: String,
    #[doc(hidden)]
    pub persisted_relative_path: String,
    intent: SelectedResolutionOverlayIntent,
    #[doc(hidden)]
    pub masked_base: Option<SelectedResolutionMaskedBase>,
    expected_transient_replacement_count: u32,
}

impl SelectedResolutionOverlayMaskState {
    pub(crate) fn storage_language(&self) -> &str {
        &self.storage_language
    }

    #[doc(hidden)]
    pub fn persisted_relative_path(&self) -> &str {
        &self.persisted_relative_path
    }

    #[doc(hidden)]
    pub const fn masked_base(&self) -> Option<&SelectedResolutionMaskedBase> {
        self.masked_base.as_ref()
    }

    pub(crate) const fn intent(&self) -> SelectedResolutionOverlayIntent {
        self.intent
    }

    pub(crate) const fn expected_transient_replacement_count(&self) -> u32 {
        self.expected_transient_replacement_count
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct SelectedResolutionLanguageState {
    storage_language: String,
    semantic_language: Language,
    workspace_id: String,
    #[doc(hidden)]
    pub generation: i64,
    #[doc(hidden)]
    pub revision: i64,
    #[doc(hidden)]
    pub expected_base_mount_count: usize,
    #[doc(hidden)]
    pub masked_base_mount_count: usize,
    #[doc(hidden)]
    pub expected_unmasked_mount_count: usize,
}

impl SelectedResolutionLanguageState {
    pub(crate) fn storage_language(&self) -> &str {
        &self.storage_language
    }

    pub(crate) const fn semantic_language(&self) -> Language {
        self.semantic_language
    }

    pub(crate) fn workspace_id(&self) -> &str {
        &self.workspace_id
    }

    #[doc(hidden)]
    pub const fn generation(&self) -> i64 {
        self.generation
    }

    #[doc(hidden)]
    pub const fn revision(&self) -> i64 {
        self.revision
    }

    #[doc(hidden)]
    pub const fn expected_base_mount_count(&self) -> usize {
        self.expected_base_mount_count
    }

    #[doc(hidden)]
    pub const fn masked_base_mount_count(&self) -> usize {
        self.masked_base_mount_count
    }

    #[doc(hidden)]
    pub const fn expected_unmasked_mount_count(&self) -> usize {
        self.expected_unmasked_mount_count
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct SelectedResolutionMountRecord {
    #[doc(hidden)]
    pub ordinal: SelectedResolutionMountOrdinal,
    /// The mount's content key: what its `BindingFragmentId` used to be.
    ///
    /// A `BindingFragmentId` is the mount ordinal now, which is a property of
    /// this selection rather than of the blob, so the value the selection
    /// fingerprint hashes and the interior cache keys on lives here.
    pub(crate) fragment_digest: SelectedResolutionFragmentDigest,
    workspace_id: String,
    revision: i64,
    #[doc(hidden)]
    pub generation: i64,
    #[doc(hidden)]
    pub file_version_id: Option<i64>,
    #[doc(hidden)]
    pub storage_language: String,
    #[doc(hidden)]
    pub semantic_language: Language,
    #[doc(hidden)]
    pub persisted_relative_path: String,
    #[doc(hidden)]
    pub blob_id: i64,
    #[doc(hidden)]
    pub blob_oid: Oid,
    projection_digest: [u8; 32],
    #[doc(hidden)]
    pub interior_digest: [u8; 32],
    producer_epoch: String,
    #[doc(hidden)]
    pub manifest_counts: ResolutionManifestCounts,
    logical_rows: u64,
    payload_bytes: u64,
}

/// Request-owned memo. Only explicit ordinal/path reads add records; warm
/// operation construction leaves it empty and reader checkin never owns it.
#[derive(Default)]
#[doc(hidden)]
pub struct RequestedResolutionMountRows {
    paths: RefCell<HashMap<(String, String), Option<SelectedResolutionMountOrdinal>>>,
    records: RefCell<
        HashMap<SelectedResolutionMountOrdinal, std::sync::Arc<SelectedResolutionMountRecord>>,
    >,
}

fn selected_mount_record_columns() -> &'static str {
    static COLUMNS: OnceLock<String> = OnceLock::new();
    COLUMNS.get_or_init(|| {
        let sql = format!("mount_ordinal,fragment_id,workspace_id,revision,generation,file_version_id,storage_language,semantic_language,persisted_relative_path,blob_id,blob_oid,projection_digest,interior_digest,producer_epoch,logical_rows,payload_bytes,{}", RESOLUTION_MANIFEST_COUNT_COLUMNS.join(","));
        #[cfg(any(test, feature = "test-support"))]
        note_selected_static_sql_capacity(4, sql.capacity());
        sql
    })
}

fn decode_selected_mount_record(row: &rusqlite::Row<'_>) -> Result<SelectedResolutionMountRecord> {
    let mut counts = [0_u64; RESOLUTION_MANIFEST_COUNT_COLUMNS.len()];
    for (index, count) in counts.iter_mut().enumerate() {
        *count = nonnegative_u64(row.get(16 + index)?, "selected manifest count")?;
    }
    let semantic_label: String = row.get(7)?;
    Ok(SelectedResolutionMountRecord {
        ordinal: SelectedResolutionMountOrdinal::new(
            u32::try_from(row.get::<_, i64>(0)?)
                .map_err(|_| StoreError::corrupt("selected mount ordinal exceeds u32"))?,
        ),
        fragment_digest: SelectedResolutionFragmentDigest::new(parse_digest_blob(
            row.get(1)?,
            "selected fragment digest",
        )?),
        workspace_id: row.get(2)?,
        revision: row.get(3)?,
        generation: row.get(4)?,
        file_version_id: row.get(5)?,
        storage_language: row.get(6)?,
        semantic_language: Language::from_config_label(&semantic_label).ok_or_else(|| {
            StoreError::corrupt(format!("unknown selected language {semantic_label:?}"))
        })?,
        persisted_relative_path: row.get(8)?,
        blob_id: row.get(9)?,
        blob_oid: parse_oid(&row.get::<_, String>(10)?, "selected blob OID")?,
        projection_digest: parse_digest_blob(row.get(11)?, "selected projection digest")?,
        interior_digest: parse_digest_blob(row.get(12)?, "selected interior digest")?,
        producer_epoch: row.get(13)?,
        logical_rows: nonnegative_u64(row.get(14)?, "selected logical rows")?,
        payload_bytes: nonnegative_u64(row.get(15)?, "selected payload bytes")?,
        manifest_counts: ResolutionManifestCounts::from_array(counts),
    })
}

impl RequestedResolutionMountRows {
    pub(crate) fn by_ordinal(
        &self,
        conn: &Connection,
        ordinal: SelectedResolutionMountOrdinal,
    ) -> Result<Option<std::sync::Arc<SelectedResolutionMountRecord>>> {
        if let Some(record) = self.records.borrow().get(&ordinal) {
            return Ok(Some(record.clone()));
        }
        let sql = format!(
            "SELECT {} FROM temp.selected_resolution_mounts WHERE mount_ordinal=?1",
            selected_mount_record_columns()
        );
        let mut statement = conn.prepare_cached(&sql)?;
        let mut rows = statement.query([i64::from(ordinal.get())])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let record = std::sync::Arc::new(decode_selected_mount_record(row)?);
        assert_eq!(
            record.ordinal(),
            ordinal,
            "requested ordinal returns its own row"
        );
        self.records.borrow_mut().insert(ordinal, record.clone());
        Ok(Some(record))
    }

    pub(crate) fn by_path(
        &self,
        conn: &Connection,
        language: &str,
        path: &str,
    ) -> Result<Option<std::sync::Arc<SelectedResolutionMountRecord>>> {
        let key = (language.to_owned(), path.to_owned());
        if let Some(record) = self.paths.borrow().get(&key) {
            return Ok(record.map(|ordinal| {
                self.records
                    .borrow()
                    .get(&ordinal)
                    .expect("memoized path has its mount record")
                    .clone()
            }));
        }
        let sql = format!(
            "SELECT {} FROM temp.selected_resolution_mounts WHERE storage_language=?1 AND persisted_relative_path=?2",
            selected_mount_record_columns()
        );
        let mut statement = conn.prepare_cached(&sql)?;
        let mut rows = statement.query(params![language, path])?;
        let Some(row) = rows.next()? else {
            self.paths.borrow_mut().insert(key, None);
            return Ok(None);
        };
        let record = std::sync::Arc::new(decode_selected_mount_record(row)?);
        self.records
            .borrow_mut()
            .insert(record.ordinal(), record.clone());
        self.paths.borrow_mut().insert(key, Some(record.ordinal()));
        Ok(Some(record))
    }
}

impl SelectedResolutionMountRecord {
    #[doc(hidden)]
    pub const fn ordinal(&self) -> SelectedResolutionMountOrdinal {
        self.ordinal
    }

    /// The mount's runtime fragment, which is its ordinal.
    #[doc(hidden)]
    pub fn fragment_id(&self) -> BindingFragmentId {
        BindingFragmentId::at_ordinal(self.ordinal.get())
    }

    /// The mount's content key, which keys the interior cache and the
    /// selection fingerprint.
    #[doc(hidden)]
    pub const fn fragment_digest(&self) -> SelectedResolutionFragmentDigest {
        self.fragment_digest
    }

    pub(crate) fn workspace_id(&self) -> &str {
        &self.workspace_id
    }

    pub(crate) const fn revision(&self) -> i64 {
        self.revision
    }

    #[doc(hidden)]
    pub const fn generation(&self) -> i64 {
        self.generation
    }

    #[doc(hidden)]
    pub const fn file_version_id(&self) -> Option<i64> {
        self.file_version_id
    }

    #[doc(hidden)]
    pub fn storage_language(&self) -> &str {
        &self.storage_language
    }

    #[doc(hidden)]
    pub const fn semantic_language(&self) -> Language {
        self.semantic_language
    }

    #[doc(hidden)]
    pub fn persisted_relative_path(&self) -> &str {
        &self.persisted_relative_path
    }

    #[doc(hidden)]
    pub const fn blob_id(&self) -> i64 {
        self.blob_id
    }

    #[doc(hidden)]
    pub const fn blob_oid(&self) -> Oid {
        self.blob_oid
    }

    pub(crate) const fn projection_digest(&self) -> [u8; 32] {
        self.projection_digest
    }

    #[doc(hidden)]
    pub const fn interior_digest(&self) -> [u8; 32] {
        self.interior_digest
    }

    pub(crate) fn producer_epoch(&self) -> &str {
        &self.producer_epoch
    }

    #[doc(hidden)]
    pub const fn manifest_counts(&self) -> &ResolutionManifestCounts {
        &self.manifest_counts
    }

    pub(crate) const fn logical_rows(&self) -> u64 {
        self.logical_rows
    }

    pub(crate) const fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum SelectedResolutionUnavailable {
    JvmContextUnavailable {
        storage_language: String,
        persisted_relative_path: String,
    },
    GoContextUnavailable {
        persisted_relative_path: String,
    },
    MissingWorkspaceSnapshot {
        storage_language: String,
    },
    MissingProducerEpoch {
        storage_language: String,
    },
    MissingBlob {
        storage_language: String,
        persisted_relative_path: String,
    },
    BlobGenerationMismatch {
        storage_language: String,
        persisted_relative_path: String,
    },
    IncompleteParsedBlob {
        storage_language: String,
        persisted_relative_path: String,
    },
    MissingInterior {
        storage_language: String,
        persisted_relative_path: String,
    },
    IncompleteInterior {
        storage_language: String,
        persisted_relative_path: String,
    },
    InteriorOwnershipMismatch {
        storage_language: String,
        persisted_relative_path: String,
    },
    MissingTransientReplacement {
        storage_language: String,
        persisted_relative_path: String,
    },
    MissingTransientOverlayInput {
        storage_language: String,
        persisted_relative_path: String,
    },
    MissingDefinitionUnit {
        storage_language: String,
        persisted_relative_path: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum SelectedResolutionStale {
    NativeContextPublication {
        storage_language: String,
    },
    WorkspaceRevision {
        storage_language: String,
    },
    AnalysisGeneration {
        storage_language: String,
    },
    ProducerEpoch {
        storage_language: String,
    },
    MountInventoryChanged,
    /// While this operation had lent the in-memory fallback's writer
    /// connection, another user wrote rows or schema there that an ordinary
    /// selection read never writes, so its temp selection is no longer known
    /// to be the one it installed.
    LentWriterChanged,
    TransientAnalysisGeneration {
        expected: u64,
        actual: u64,
    },
    TransientOverlayChanged {
        storage_language: String,
        persisted_relative_path: String,
        expected_content_digest: [u8; 32],
        actual_content_digest: Option<[u8; 32]>,
    },
}

#[doc(hidden)]
pub enum SelectedResolutionMountInventoryOutcome<'store> {
    Ready(Box<SelectedResolutionMountInventory<'store>>),
    Unavailable(SelectedResolutionUnavailable),
    Cancelled,
    Stale(SelectedResolutionStale),
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum SelectedResolutionRevalidationOutcome {
    Current,
    Cancelled,
    Stale(SelectedResolutionStale),
}

/// Transaction visibility is separate from a typed domain outcome. A rollback
/// does not subtract SQLite's attempted writes from the freshness stamp.
#[doc(hidden)]
pub enum SelectedResolutionTempTransaction<T> {
    Commit(T),
    Rollback(T),
}

/// One value for the set of mounts a request may bind into.
///
/// The empty list is the whole selection, which is what the relation holds
/// until a forward Rust request narrows it and what it holds again afterwards.
/// A narrowed scope is the transitive dependency closure of its crate keys over
/// this selection, so the keys plus the selection identify the mounts exactly;
/// the selection's own fingerprint is the other half and travels beside this
/// one in `candidate_coverage_fingerprint`.
fn scope_identity_of(crate_keys: &[[u8; 32]]) -> [u8; 32] {
    let mut digest = CanonicalHasher::new(b"bifrost-selected-request-scope:v1");
    digest.sequence("crates", crate_keys, |digest, key| digest.value(key));
    digest.finish()
}

fn next_stage_request_identity() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        value.checked_add(1)
    })
    .expect("selected stage request identity space exhausted")
}

#[doc(hidden)]
pub struct SelectedResolutionMountInventory<'store> {
    #[doc(hidden)]
    pub conn: ReaderGuard<'store>,
    #[doc(hidden)]
    pub retained: Option<RetainedResolutionSelection>,
    requested_mounts: RequestedResolutionMountRows,
    enumerated_mounts: OnceCell<Vec<SelectedResolutionMountRecord>>,
    requested_languages: OnceCell<Vec<SelectedResolutionLanguageState>>,
    requested_masks: OnceCell<Vec<SelectedResolutionOverlayMaskState>>,
    #[doc(hidden)]
    pub mount_rebaser: RefCell<MountRebaser>,
    retention_authorized: bool,
    stage_request_used: Cell<bool>,
    stage_request_identity: u64,
    stage_content_epoch: Cell<u64>,
    /// Version of arbitrary owned TEMP row writes. Staged read memos must
    /// distinguish them from publication commits and private request buffers.
    stage_direct_write_epoch: Cell<u64>,
    /// Which mounts the request may currently bind into, as a value.
    ///
    /// Written by the scope relation's two writers and read by
    /// [`Self::scope_identity`]; see that method for why it is kept at all.
    scope_identity: Cell<[u8; 32]>,
    /// What this request has already asked the store about shared names.
    ///
    /// The inventory is built for one request and dropped with it (the
    /// retained half is the selection it carries, not this), so the table is
    /// bounded by the names one request meets, like the macro-walk memo.
    #[doc(hidden)]
    pub shared_names: super::resolution::SharedNameTable,
    /// The current crate stage's placement and membership answers; `None`
    /// outside a crate stage. See `rust_crate_access::CrateAccessMemo`.
    crate_access: RefCell<Option<super::resolution_operation::rust_crate_access::CrateAccessMemo>>,
    /// The current crate stage's checked publications; `None` outside a crate
    /// stage. See `resolution_authority::AuthorityValidations`.
    #[doc(hidden)]
    pub authority_validations: RefCell<Option<super::resolution_authority::AuthorityValidations>>,
    /// Published authority and identity answers touched by this one operation.
    #[doc(hidden)]
    pub authority_request_memo: RefCell<super::resolution_authority::AuthorityRequestMemo>,
    /// Published site rows touched by this one operation.
    site_row_memo: RefCell<super::resolution_lexical::SiteRowMemo>,
    // Durable recipes owned by this selected request, never pooled. Only found
    // recipes are kept; see read_stored_lookup_recipes.
    pub(super) identity_recipe_memo: RefCell<
        super::selected_read_memo::RequestReadCache<
            i64,
            crate::analyzer::resolution::ResolutionLookupSemanticRecipe,
        >,
    >,
    pub(super) python_receiver_rows: RefCell<PythonReceiverRows>,
    #[cfg(any(test, feature = "test-support"))]
    pub(super) python_unit_metadata:
        RefCell<super::selected_read_memo::RequestReadCache<i64, (Vec<u8>, String)>>,
    /// Complete header-read answers demanded by this query, never retained
    /// with the pooled selection. Mount rows do not change while this owner
    /// lives; scope writers invalidate this memo before changing its scope.
    path_endpoint_header_memo: RefCell<
        super::selected_read_memo::ExactReadMemo<
            super::resolution_lexical::PathEndpointHeaderReadKey,
            Vec<SelectedResolutionMountOrdinal>,
        >,
    >,
    /// One successful inventory query at an exact read stamp. This request
    /// may finish several point operations after private TEMP schema setup;
    /// the same unchanged stamp need not reread every mount for each finish.
    inventory_revalidation_memo: Cell<Option<SelectedResolutionReadStamp>>,
    /// Enabled only while a ReadySelectedResolution owns this inventory.
    /// One entry, replaced at the existing scope/stage read-memo boundary.
    operation_change_stamp: Option<Cell<Option<OperationChangeStamp>>>,
    /// Family occupancy is bounded by the fixed stage schema, never by hosts.
    /// Only the current scope/epochs are retained for this request.
    stage_family_occupancy: RefCell<StageFamilyOccupancyMemo>,
    /// Context tokens committed by this operation, whose rows live in its temp database.
    published_context_tokens: RefCell<HashSet<i64>>,
    /// The derive-helper gaps this operation has already decided; see
    /// `resolution_operation::rust_derive_helpers`.
    derive_helper_decisions:
        RefCell<super::resolution_operation::rust_derive_helpers::DeriveHelperDecisions>,
    /// Whether a crate stage holds a read transaction on this reader; see
    /// [`SelectedResolutionMountInventory::begin_stage_read`].
    stage_read: Cell<bool>,
    /// Whether this request has ensured the optional generic-formals stage
    /// family exists on its connection.
    generic_formals_schema_ready: Cell<bool>,
    generic_formal_defaults_schema_ready: Cell<bool>,
    reverse_candidate_keys_schema_ready: Cell<bool>,
    /// The snapshots whose revision rows this selection staged on the
    /// in-memory fallback's writer connection; `None` for a pooled reader.
    /// See [`Self::lend_writer`].
    writer_installed_snapshots: Option<WorkspaceSnapshots>,
    /// Set when another store user made a change other than an ordinary
    /// selection read while this inventory had lent its writer connection.
    /// The temp selection is then not known to be this one, so the operation
    /// is stale and its selection is not retained.
    lent_writer_changed: bool,
}

#[derive(Clone, Copy)]
struct OperationChangeStamp {
    scope: [u8; 32],
    stage: (u64, u64),
    stamp: super::WorkspaceSelectionStamp,
}

#[derive(Default)]
struct StageFamilyOccupancyMemo {
    key: Option<([u8; 32], (u64, u64))>,
    families: HashMap<super::resolution_stage::StageFamily, StageFamilyOccupancy>,
}

#[derive(Clone, Copy)]
struct StageFamilyOccupancy {
    global: bool,
    scoped: bool,
}

/// Freshness of the retained reader, excluding its private buffers and owned schema setup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct SelectedResolutionReadStamp {
    #[doc(hidden)]
    pub main_data_version: i64,
    #[doc(hidden)]
    pub main_schema_version: i64,
    #[doc(hidden)]
    pub temp_schema_version: i64,
    #[doc(hidden)]
    pub unowned_changes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct RetainedResolutionSelectionKey {
    #[doc(hidden)]
    pub workspace_id: String,
    #[doc(hidden)]
    pub snapshots: WorkspaceSnapshots,
    #[doc(hidden)]
    pub languages: Vec<SelectedResolutionLanguage>,
    #[doc(hidden)]
    pub overlay_masks: Vec<SelectedResolutionOverlayMask>,
    #[doc(hidden)]
    pub content_mounts: Vec<SelectedResolutionContentMountRequest>,
}

// Routing is deliberately separate from authority. The exact comparison below
// reads only selection input rows, never the unrelated mount inventory.
pub(crate) const SELECTED_INPUT_EQUALS_SQL: &str = r#"
WITH requested(kind,a,b,c,d,e,f,g,h) AS (
 SELECT json_extract(value,'$[0]'),json_extract(value,'$[1]'),
 json_extract(value,'$[2]'),json_extract(value,'$[3]'),json_extract(value,'$[4]'),
 json_extract(value,'$[5]'),json_extract(value,'$[6]'),json_extract(value,'$[7]'),
 json_extract(value,'$[8]') FROM json_each(?1)
), actual(kind,a,b,c,d,e,f,g,h) AS (
 SELECT 0,workspace_id,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM temp.selected_resolution_context
 UNION ALL SELECT 1,lang,workspace_id,generation,revision,NULL,NULL,NULL,NULL FROM temp.selected_workspace_revisions
 UNION ALL SELECT 2,storage_language,semantic_language,NULL,NULL,NULL,NULL,NULL,NULL FROM temp.selected_resolution_languages
 UNION ALL SELECT 3,storage_language,persisted_relative_path,intent,NULL,NULL,NULL,NULL,NULL FROM temp.selected_resolution_overlay_masks
 UNION ALL SELECT 4,storage_language,generation,persisted_relative_path,blob_oid,lower(hex(projection_digest)),overlay_authority_kind,
 CASE WHEN overlay_authority_digest IS NULL THEN NULL ELSE lower(hex(overlay_authority_digest)) END,lower(hex(publication_digest)) FROM temp.selected_resolution_content_mounts
)
SELECT NOT EXISTS(SELECT * FROM requested EXCEPT SELECT * FROM actual)
 AND NOT EXISTS(SELECT * FROM actual EXCEPT SELECT * FROM requested)
"#;

impl RetainedResolutionSelectionKey {
    fn relational_rows(&self) -> String {
        use serde_json::json;
        let mut rows = vec![json!([
            0,
            self.workspace_id,
            null,
            null,
            null,
            null,
            null,
            null,
            null
        ])];
        let snapshots = self.snapshots.iter().collect::<BTreeMap<_, _>>();
        for (language, snapshot) in snapshots {
            rows.push(json!([
                1,
                language,
                snapshot.workspace_id.as_str(),
                snapshot.generation.get(),
                snapshot.revision,
                null,
                null,
                null,
                null
            ]));
        }
        for language in &self.languages {
            rows.push(json!([
                2,
                language.storage_language,
                language.semantic_language.config_label(),
                null,
                null,
                null,
                null,
                null,
                null
            ]));
        }
        for mask in &self.overlay_masks {
            rows.push(json!([
                3,
                mask.storage_language,
                mask.persisted_relative_path,
                mask.intent.as_str(),
                null,
                null,
                null,
                null,
                null
            ]));
        }
        for mount in &self.content_mounts {
            let (kind, digest) = mount.overlay_authority_columns();
            rows.push(json!([
                4,
                mount.storage_language,
                mount.generation.get(),
                mount.file.rel_path,
                mount.file.blob_oid.to_string(),
                lower_hex_string(&mount.projection_digest),
                kind,
                digest.map(lower_hex_string),
                lower_hex_string(&mount.publication_digest())
            ]));
        }
        serde_json::to_string(&rows).expect("selection scalar rows serialize")
    }

    #[doc(hidden)]
    pub fn routing_digest(&self) -> [u8; 32] {
        let mut hash = CanonicalHasher::new(b"bifrost-selected-input-routing:v1");
        hash.field("rows", self.relational_rows().as_bytes());
        hash.finish()
    }

    #[doc(hidden)]
    pub fn equals_selected_rows(&self, conn: &Connection) -> Result<bool> {
        Ok(conn
            .prepare_cached(SELECTED_INPUT_EQUALS_SQL)?
            .query_row([self.relational_rows()], |row| row.get(0))?)
    }
}

/// Complete selected state retained with the SQLite reader whose TEMP mount
/// tables hold the corresponding relational selection.
///
/// The value moves out while an operation owns the reader and moves back before
/// checkin. This avoids cloning a workspace-sized mount inventory and keeps the
/// cache inseparable from the connection-local tables used by bounded reads.
#[doc(hidden)]
pub struct RetainedResolutionSelection {
    #[doc(hidden)]
    pub routing_digest: [u8; 32],
    ready: RetainedSelectedMetadata,
    stamp: SelectedResolutionReadStamp,
    owned_change_baseline: u64,
    #[doc(hidden)]
    pub committed_request_changes: Cell<u64>,
    committed_schema_changes: Cell<i64>,
    // Keep pooled readers small when moved by value; this is fixed-size metadata.
    pub(super) interior_certificates: Box<SelectedInteriorCertificates>,
}

pub(super) struct SelectedInteriorCertificates {
    // Main data_version excludes same-connection commits on the writer fallback.
    main_is_readonly: bool,
    // Distinct predicates: typed also requires source_fact_readiness.available.
    // Raw TEMP schema versions witness DDL that can remove the mount guards.
    pub(super) lexical: Cell<Option<super::WorkspaceSelectionStamp>>,
    pub(super) typed: Cell<Option<super::WorkspaceSelectionStamp>>,
}

impl RetainedResolutionSelection {
    pub(super) fn matches_key(&self, key: &RetainedResolutionSelectionKey) -> bool {
        self.routing_digest == key.routing_digest()
    }

    pub(super) fn same_key_as(&self, other: &Self) -> bool {
        self.routing_digest == other.routing_digest
    }

    fn current_stamp(&self, conn: &Connection) -> Result<SelectedResolutionReadStamp> {
        Ok(self.stamp_from_workspace(conn, super::workspace_selection_stamp(conn)?))
    }

    fn stamp_from_workspace(
        &self,
        conn: &Connection,
        stamp: super::WorkspaceSelectionStamp,
    ) -> SelectedResolutionReadStamp {
        let mut stamp = selected_read_stamp(
            conn,
            self.owned_change_baseline,
            self.committed_request_changes.get(),
            stamp,
        );
        stamp.temp_schema_version -= self.committed_schema_changes.get();
        stamp
    }

    #[doc(hidden)]
    pub fn is_current(&self, conn: &Connection) -> Result<bool> {
        Ok(self.current_stamp(conn)? == self.stamp)
    }
}

impl SelectedResolutionMountInventory<'_> {
    #[doc(hidden)]
    pub fn retained(&self) -> &RetainedResolutionSelection {
        self.retained
            .as_ref()
            .expect("selected inventory retains its complete selection until drop")
    }

    pub(crate) fn module_definition_providers(
        &self,
    ) -> &[super::language_support::ModuleDefinitionProvider] {
        &self.retained().ready.module_definition_providers
    }

    pub(crate) fn namespace_definition_providers(
        &self,
    ) -> &[(
        String,
        Language,
        super::language_support::NamespaceDefinitionProvider,
    )] {
        &self.retained().ready.namespace_definition_providers
    }

    pub(crate) fn has_conditional_type_seeds(&self) -> bool {
        self.retained().ready.has_conditional_type_seeds
    }

    pub(crate) fn has_registered_member_semantics(&self) -> bool {
        self.retained().ready.has_registered_member_semantics
    }

    pub(crate) fn has_go_semantics(&self) -> bool {
        self.retained().ready.has_go_semantics
    }

    pub(crate) fn has_java_semantics(&self) -> bool {
        self.retained().ready.has_java_semantics
    }

    pub(crate) fn has_jvm_semantics(&self) -> bool {
        self.retained().ready.has_jvm_semantics
    }

    /// Whether any selected language has a fixed universe table to consult.
    pub(crate) fn has_universe_semantics(&self) -> bool {
        self.retained().ready.has_universe_semantics
    }

    #[doc(hidden)]
    pub fn workspace_id(&self) -> &str {
        &self.retained().ready.workspace_id
    }

    pub(crate) fn workspace_digest(&self) -> Result<[u8; 32]> {
        parse_digest_text(self.workspace_id(), "workspace identity")
    }

    /// Canonical selected-input identity used by dependency-complete caches.
    /// The retained selection separately checks its exact TEMP rows and
    /// freshness stamp before an operation can use this digest.
    pub(crate) fn routing_digest(&self) -> [u8; 32] {
        self.retained().routing_digest
    }

    #[doc(hidden)]
    pub fn languages(&self) -> Result<&[SelectedResolutionLanguageState]> {
        if self.requested_languages.get().is_none() {
            let mut statement = self.connection().prepare_cached("SELECT l.storage_language,l.semantic_language,r.workspace_id,r.generation,r.revision,l.expected_base_mount_count,l.masked_base_mount_count,l.expected_unmasked_mount_count FROM temp.selected_resolution_languages l JOIN temp.selected_workspace_revisions r ON r.lang=l.storage_language ORDER BY l.storage_language")?;
            let mut rows = statement.query([])?;
            let mut result = Vec::new();
            while let Some(row) = rows.next()? {
                let label: String = row.get(1)?;
                result.push(SelectedResolutionLanguageState {
                    storage_language: row.get(0)?,
                    semantic_language: Language::from_config_label(&label).ok_or_else(|| {
                        StoreError::corrupt(format!("unknown selected language {label:?}"))
                    })?,
                    workspace_id: row.get(2)?,
                    generation: row.get(3)?,
                    revision: row.get(4)?,
                    expected_base_mount_count: row.get(5)?,
                    masked_base_mount_count: row.get(6)?,
                    expected_unmasked_mount_count: row.get(7)?,
                });
            }
            assert!(self.requested_languages.set(result).is_ok());
        }
        Ok(self
            .requested_languages
            .get()
            .expect("requested language rows initialized"))
    }

    #[doc(hidden)]
    pub fn overlay_masks(&self) -> Result<&[SelectedResolutionOverlayMaskState]> {
        if self.requested_masks.get().is_none() {
            let mut statement = self.connection().prepare_cached("SELECT storage_language,persisted_relative_path,intent,masked_file_version_id,masked_blob_oid,masked_projection_digest,expected_transient_replacement_count FROM temp.selected_resolution_overlay_masks ORDER BY storage_language,persisted_relative_path")?;
            let mut rows = statement.query([])?;
            let mut result = Vec::new();
            while let Some(row) = rows.next()? {
                let intent: String = row.get(2)?;
                let masked_base = row
                    .get::<_, Option<i64>>(3)?
                    .map(|file_version_id| -> Result<_> {
                        Ok(SelectedResolutionMaskedBase {
                            file_version_id,
                            blob_oid: parse_oid(&row.get::<_, String>(4)?, "masked blob OID")?,
                            projection_digest: parse_digest_blob(
                                row.get(5)?,
                                "masked projection digest",
                            )?,
                        })
                    })
                    .transpose()?;
                result.push(SelectedResolutionOverlayMaskState {
                    storage_language: row.get(0)?,
                    persisted_relative_path: row.get(1)?,
                    intent: match intent.as_str() {
                        "replacement" => SelectedResolutionOverlayIntent::Replacement,
                        "removal" => SelectedResolutionOverlayIntent::Removal,
                        _ => {
                            return Err(StoreError::corrupt(format!(
                                "unknown selected intent {intent:?}"
                            )));
                        }
                    },
                    masked_base,
                    expected_transient_replacement_count: row.get(6)?,
                });
            }
            assert!(self.requested_masks.set(result).is_ok());
        }
        Ok(self
            .requested_masks
            .get()
            .expect("requested mask rows initialized"))
    }

    #[doc(hidden)]
    pub fn persisted_mount_count(&self) -> usize {
        self.retained().ready.persisted_mount_count
    }

    /// Explicit full-inventory consumers own this enumeration for their query.
    /// Keyed point readers must use ordinal/path APIs instead.
    #[doc(hidden)]
    pub fn mounts(&self) -> Result<&[SelectedResolutionMountRecord]> {
        if self.enumerated_mounts.get().is_none() {
            let sql = format!(
                "SELECT {} FROM temp.selected_resolution_mounts ORDER BY mount_ordinal",
                selected_mount_record_columns()
            );
            let mut statement = self.connection().prepare_cached(&sql)?;
            let mut rows = statement.query([])?;
            let mut result = Vec::new();
            while let Some(row) = rows.next()? {
                result.push(decode_selected_mount_record(row)?);
            }
            assert!(self.enumerated_mounts.set(result).is_ok());
        }
        Ok(self
            .enumerated_mounts
            .get()
            .expect("explicit mount enumeration initialized"))
    }

    #[doc(hidden)]
    pub fn requested_mount_rows(&self) -> &RequestedResolutionMountRows {
        &self.requested_mounts
    }

    #[doc(hidden)]
    pub fn persisted_mount_record(
        &self,
        ordinal: SelectedResolutionMountOrdinal,
    ) -> Result<Option<std::sync::Arc<SelectedResolutionMountRecord>>> {
        if ordinal.get() as usize >= self.persisted_mount_count() {
            return Ok(None);
        }
        self.requested_mounts.by_ordinal(self.connection(), ordinal)
    }

    #[doc(hidden)]
    pub fn mount_record_by_ordinal(
        &self,
        ordinal: SelectedResolutionMountOrdinal,
    ) -> Result<std::sync::Arc<SelectedResolutionMountRecord>> {
        Ok(self
            .persisted_mount_record(ordinal)?
            .expect("validated persisted ordinal has a selected row"))
    }

    /// Put the request scope back to the whole selection.
    ///
    /// A forward Rust request narrows `temp.selected_resolution_scope_mounts`
    /// to its crate's dependency closure while it runs; every other request
    /// binds into the whole selection, and so does the next one after a
    /// narrowed request finishes, whether it finished by returning or by
    /// unwinding. `ForwardCrateScope`'s `Drop` is the caller.
    #[doc(hidden)]
    pub fn reset_scope_mounts(&self) -> Result<()> {
        self.with_owned_temp_write(|conn| {
            conn.execute_batch(RESET_SELECTED_RESOLUTION_SCOPE_SQL)?;
            Ok(())
        })?;
        self.scope_identity.set(scope_identity_of(&[]));
        Ok(())
    }

    /// Record which crates the request scope has just been narrowed to.
    ///
    /// `narrow_forward_scope_to_crates` is the caller and the only one: the
    /// scope relation has exactly two writers, that one and
    /// [`Self::reset_scope_mounts`].
    pub(super) fn note_scope_narrowed(&self, crate_keys: &[[u8; 32]]) {
        self.scope_identity.set(scope_identity_of(crate_keys));
    }

    /// Which mounts the request may currently bind into, as a value.
    ///
    /// The scope itself lives only in `temp.selected_resolution_scope_mounts`
    /// and in no Rust value, which is deliberate: it is the one relation every
    /// membership read joins, so no reader can forget it. A read that has to
    /// say *which* scope answered it -- the seed-key profile is the only one --
    /// cannot ask that table without issuing SQL of its own, so the two writers
    /// keep the answer here instead.
    pub(crate) fn scope_identity(&self) -> [u8; 32] {
        self.scope_identity.get()
    }

    /// The parts of a reference-seed read's identity that belong to the
    /// selection rather than to the reference.
    pub(crate) fn seed_read_authority(&self) -> crate::analyzer::resolution::SeedReadAuthority {
        crate::analyzer::resolution::SeedReadAuthority {
            request: self.stage_request_identity,
            content_epoch: self.stage_content_epoch.get(),
            scope: self.scope_identity(),
        }
    }

    /// Run one write this request owns against the selection's own temp tables
    /// and account the rows it changed.
    ///
    /// The retained selection survives a request only when the connection's
    /// change counter is exactly where the selection left it: `current_stamp`
    /// subtracts the baseline and the committed request changes, and a nonzero
    /// remainder says somebody else wrote, so `Drop` discards the selection and
    /// clears the temp tables. A row a request writes and restores itself is
    /// not that, and it has to be added to the committed total or every later
    /// request on the same inventory pays a cold open: 329 statements instead
    /// of 3 on the 256-mount point fixture, measured when the forward crate
    /// scope reached the production point route.
    #[doc(hidden)]
    pub fn with_owned_temp_write<T>(
        &self,
        write: impl FnOnce(&Connection) -> Result<T>,
    ) -> Result<T> {
        // This escape hatch may write the scope relation directly.
        *self.path_endpoint_header_memo.borrow_mut() = Default::default();
        self.inventory_revalidation_memo.set(None);
        // Invalidate even if an arbitrary writer returns an error after a
        // partial write.
        self.stage_direct_write_epoch.set(
            self.stage_direct_write_epoch
                .get()
                .checked_add(1)
                .expect("selected direct stage write epoch exhausted"),
        );
        let before = self.connection().total_changes();
        let value = write(self.connection())?;
        let changed = self
            .connection()
            .total_changes()
            .checked_sub(before)
            .expect("a temp write cannot lower the connection's change counter");
        self.account_committed_request_changes(changed);
        Ok(value)
    }

    // Private request-buffer writers account only their own successful writes.
    pub(super) fn account_committed_request_changes(&self, changed: u64) {
        let committed = &self.retained().committed_request_changes;
        committed.set(
            committed
                .get()
                .checked_add(changed)
                .expect("committed request changes fit u64"),
        );
    }

    pub(super) fn mark_stage_used(&self) {
        self.stage_request_used.set(true);
    }

    /// No committed content, including arbitrary direct writes that failed
    /// after inserting rows. Private request buffers do not publish content.
    fn stage_has_no_content(&self) -> bool {
        self.staged_read_epoch() == (0, 0)
    }

    /// Scoped readers must prove absence in the same scope as their SQL.
    pub(super) fn stage_family_is_empty(
        &self,
        family: super::resolution_stage::StageFamily,
    ) -> Result<bool> {
        Ok(!self.stage_family_occupancy(family)?.scoped)
    }

    /// A scoped inner-join read is empty when any mandatory family is empty.
    /// Optional joins and union arms do not belong in this list.
    pub(super) fn stage_read_is_empty(
        &self,
        required: &[super::resolution_stage::StageFamily],
    ) -> Result<bool> {
        assert!(
            !required.is_empty(),
            "a stage read names its mandatory families"
        );
        for &family in required {
            if self.stage_family_is_empty(family)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Proof readers retain rows outside scope and require global absence.
    pub(super) fn stage_family_is_globally_empty(
        &self,
        family: super::resolution_stage::StageFamily,
    ) -> Result<bool> {
        Ok(!self.stage_family_occupancy(family)?.global)
    }

    fn stage_family_occupancy(
        &self,
        family: super::resolution_stage::StageFamily,
    ) -> Result<StageFamilyOccupancy> {
        if self.stage_has_no_content() {
            return Ok(StageFamilyOccupancy {
                global: false,
                scoped: false,
            });
        }
        let key = (self.scope_identity(), self.staged_read_epoch());
        let mut memo = self.stage_family_occupancy.borrow_mut();
        if memo.key != Some(key) {
            memo.families.clear();
            memo.key = Some(key);
        }
        if let Some(occupancy) = memo.families.get(&family) {
            return Ok(*occupancy);
        }
        // One existence probe per demanded family and epoch, shared by every
        // reader. Both answers come from the same TEMP snapshot. Do not scan
        // or retain the host inventory in Rust.
        let occupancy = self
            .connection()
            .prepare_cached(family.occupancy_sql())?
            .query_row([], |row| {
                Ok(StageFamilyOccupancy {
                    global: row.get(0)?,
                    scoped: row.get(1)?,
                })
            })?;
        memo.families.insert(family, occupancy);
        Ok(occupancy)
    }

    #[doc(hidden)]
    pub fn note_stage_content_commit(&self) {
        self.stage_content_epoch.set(
            self.stage_content_epoch
                .get()
                .checked_add(1)
                .expect("selected stage content epoch exhausted"),
        );
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn stage_content_epoch_for_test(&self) -> u64 {
        self.stage_content_epoch.get()
    }

    pub(super) fn staged_read_epoch(&self) -> (u64, u64) {
        (
            self.stage_content_epoch.get(),
            self.stage_direct_write_epoch.get(),
        )
    }

    /// Raw candidate coverage belongs to this request and exact committed stage.
    #[doc(hidden)]
    pub fn candidate_coverage_fingerprint(&self) -> [u8; 32] {
        let mut digest = CanonicalHasher::new(b"bifrost-selected-stage-coverage:v1");
        digest.field("selection", &self.fingerprint());
        digest.field("request", &self.stage_request_identity.to_be_bytes());
        digest.field(
            "content-epoch",
            &self.stage_content_epoch.get().to_be_bytes(),
        );
        digest.finish()
    }

    /// Account only committed private rows. A typed cancellation or stale
    /// outcome can roll back without being disguised as a store error.
    #[doc(hidden)]
    pub fn with_owned_temp_transaction<T>(
        &self,
        write: impl FnOnce(&Connection) -> Result<SelectedResolutionTempTransaction<T>>,
    ) -> Result<T> {
        let before = self.connection().total_changes();
        let transaction = TempWrite::begin(self.connection())?;
        let outcome = match write(self.connection()) {
            Ok(outcome) => outcome,
            Err(error) => {
                transaction.rollback()?;
                return Err(error);
            }
        };
        match outcome {
            SelectedResolutionTempTransaction::Commit(value) => {
                transaction.commit()?;
                let changed = self
                    .connection()
                    .total_changes()
                    .checked_sub(before)
                    .expect("a transaction cannot lower total changes");
                self.account_committed_request_changes(changed);
                Ok(value)
            }
            SelectedResolutionTempTransaction::Rollback(value) => {
                // Interrupted DML may already have rolled the SQLite transaction
                // back. rollback() honors that state and otherwise rolls back;
                // unlike Drop, it reports an actual cleanup failure.
                transaction.rollback()?;
                Ok(value)
            }
        }
    }

    /// How many mounts the current request may bind into.
    ///
    /// Test-only: production reads ask this question in SQL through the join,
    /// one mount at a time. The pin that a panicking forward request leaves the
    /// whole selection in scope has nothing else to look at, because the scope
    /// lives in a temp table and in no Rust value.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn scope_mount_count(&self) -> Result<usize> {
        let count: i64 = self.connection().query_row(
            "SELECT COUNT(*) FROM temp.selected_resolution_scope_mounts",
            [],
            |row| row.get(0),
        )?;
        Ok(usize::try_from(count).expect("a scope mount count fits usize"))
    }

    /// The persisted mount ordinal for one selected path, sought through the
    /// temp table's `UNIQUE(storage_language, persisted_relative_path)`.
    ///
    /// The selection indexes this key already, so the answer is one index seek
    /// rather than a walk of the mount table.
    pub(crate) fn mount_ordinal_for_path(
        &self,
        storage_language: &str,
        persisted_relative_path: &str,
    ) -> Result<Option<SelectedResolutionMountOrdinal>> {
        let ordinal = self
            .connection()
            .prepare_cached(SELECTED_MOUNT_ORDINAL_BY_PATH_SQL)?
            .query_row(params![storage_language, persisted_relative_path], |row| {
                row.get::<_, i64>(0)
            })
            .optional()?;
        ordinal
            .map(|ordinal| {
                u32::try_from(ordinal)
                    .map(SelectedResolutionMountOrdinal::new)
                    .map_err(|_| StoreError::corrupt("selected mount ordinal exceeds u32"))
            })
            .transpose()
    }

    #[doc(hidden)]
    pub fn mount_record_for_path(
        &self,
        storage_language: &str,
        persisted_relative_path: &str,
    ) -> Result<Option<std::sync::Arc<SelectedResolutionMountRecord>>> {
        self.requested_mounts
            .by_path(self.connection(), storage_language, persisted_relative_path)
    }

    pub(crate) fn mount_record_for_fragment(
        &self,
        fragment: BindingFragmentId,
    ) -> Result<Option<std::sync::Arc<SelectedResolutionMountRecord>>> {
        self.persisted_mount_record(SelectedResolutionMountOrdinal::new(fragment.ordinal()))
    }

    #[doc(hidden)]
    pub const fn mount_rebaser(&self) -> &RefCell<MountRebaser> {
        &self.mount_rebaser
    }

    pub(crate) fn mount_ordinal_for_fragment(
        &self,
        fragment: BindingFragmentId,
    ) -> Option<SelectedResolutionMountOrdinal> {
        self.mount_rebaser
            .borrow()
            .mount_for_fragment(fragment)
            .map(|mount| mount.ordinal())
    }

    #[doc(hidden)]
    pub fn fingerprint(&self) -> [u8; 32] {
        self.retained
            .as_ref()
            .expect("selected inventory retains its complete selection until drop")
            .ready
            .fingerprint
    }

    #[doc(hidden)]
    pub fn expected_transient_replacement_count(&self) -> usize {
        self.retained
            .as_ref()
            .expect("selected inventory retains its complete selection until drop")
            .ready
            .expected_transient_replacement_count
    }

    #[doc(hidden)]
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    #[doc(hidden)]
    pub fn ensure_generic_formals_schema(&self, connection: &Connection) -> Result<()> {
        if self.generic_formals_schema_ready.get() {
            return Ok(());
        }
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM temp.sqlite_schema WHERE type='table' AND name=?1)",
            ["selected_resolution_stage_generic_formals"],
            |row| row.get(0),
        )?;
        if !exists {
            self.initialize_owned_temp_schema(
                connection,
                super::resolution_stage::generic_formals_schema_sql(),
            )?;
        }
        self.generic_formals_schema_ready.set(true);
        Ok(())
    }

    #[doc(hidden)]
    pub fn ensure_generic_formal_defaults_schema(&self, connection: &Connection) -> Result<()> {
        if self.generic_formal_defaults_schema_ready.get() {
            return Ok(());
        }
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM temp.sqlite_schema WHERE type='table' AND name=?1)",
            ["selected_resolution_stage_generic_formal_defaults"],
            |row| row.get(0),
        )?;
        if !exists {
            self.initialize_owned_temp_schema(
                connection,
                super::resolution_stage::generic_formal_defaults_schema_sql(),
            )?;
        }
        self.generic_formal_defaults_schema_ready.set(true);
        Ok(())
    }

    /// The reverse reader's keys are private buffers, not selected authority.
    pub(super) fn ensure_reverse_candidate_keys_schema(&self) -> Result<()> {
        if !self.reverse_candidate_keys_schema_ready.get() {
            self.initialize_owned_temp_schema(
                self.connection(),
                super::resolution_operation::REVERSE_CANDIDATE_KEYS_DDL,
            )?;
            self.reverse_candidate_keys_schema_ready.set(true);
        }
        Ok(())
    }

    /// Account only the fixed, owned CREATE TABLE/INDEX batches above.
    /// These schemas do not change selected authority. Read both witnesses on
    /// this same connection around the batch so earlier unowned schema changes
    /// remain visible, as do all main-database and unowned row changes. A failed
    /// batch is not accounted and conservatively invalidates retention.
    fn initialize_owned_temp_schema(&self, connection: &Connection, sql: &str) -> Result<()> {
        assert!(std::ptr::eq(connection, self.connection()));
        let schema_version = || -> Result<i64> {
            Ok(connection
                .prepare_cached("PRAGMA temp.schema_version")?
                .query_row([], |row| row.get(0))?)
        };
        // Even a partially failed DDL batch must not leave a cached witness.
        self.clear_operation_change_stamp();
        let before = schema_version()?;
        connection.execute_batch(sql)?;
        let changes = schema_version()? - before;
        let committed = &self.retained().committed_schema_changes;
        committed.set(committed.get() + changes);
        Ok(())
    }

    /// Where this request's lowerings get a shared name's id.
    #[doc(hidden)]
    pub fn shared_names(&self) -> super::resolution::StoreSharedNames<'_> {
        self.shared_names.interner(self.connection())
    }

    /// This request's shared-name answers, for a reader that holds the table
    /// and the connection for the same lifetime.
    #[doc(hidden)]
    pub fn shared_name_table(&self) -> &super::resolution::SharedNameTable {
        &self.shared_names
    }

    #[doc(hidden)]
    pub fn authority_validations(
        &self,
    ) -> &RefCell<Option<super::resolution_authority::AuthorityValidations>> {
        &self.authority_validations
    }

    pub(super) fn authority_validation_memo_stats(&self) -> (u64, usize) {
        self.authority_validations.borrow().as_ref().map_or(
            (0, 0),
            super::resolution_authority::AuthorityValidations::memo_stats,
        )
    }

    #[doc(hidden)]
    pub fn authority_request_memo(
        &self,
    ) -> &RefCell<super::resolution_authority::AuthorityRequestMemo> {
        &self.authority_request_memo
    }

    pub(super) fn site_row_memo(&self) -> &RefCell<super::resolution_lexical::SiteRowMemo> {
        &self.site_row_memo
    }

    pub(super) fn derive_helper_decisions(
        &self,
    ) -> &RefCell<super::resolution_operation::rust_derive_helpers::DeriveHelperDecisions> {
        &self.derive_helper_decisions
    }

    pub(super) fn has_published_context(&self, context: SelectedContextPathToken) -> bool {
        self.published_context_tokens
            .borrow()
            .contains(&context.get())
    }

    pub(super) fn record_published_context(&self, context: SelectedContextPathToken) {
        assert!(
            self.published_context_tokens
                .borrow_mut()
                .insert(context.get()),
            "one operation publishes each context token once"
        );
    }

    /// Hold one read transaction on this reader for a crate stage.
    ///
    /// Without it every autocommit statement opens and closes its own WAL
    /// read transaction, and the shared-memory locking that costs was 16% of
    /// the whole tract graph's busy samples. The stage's temp writes are
    /// savepoints ([`TempWrite`]), so they nest inside it and lock only the
    /// temp database. The reader writes nothing to main: see
    /// [`Self::end_stage_read`].
    pub(super) fn begin_stage_read(&self) -> Result<()> {
        assert!(!self.stage_read.get(), "crate stages do not nest");
        assert!(
            self.connection().is_autocommit(),
            "a crate stage starts outside any transaction"
        );
        self.connection().execute_batch("BEGIN DEFERRED")?;
        self.stage_read.set(true);
        self.clear_operation_change_stamp();
        Ok(())
    }

    /// End the stage's read transaction, before the reader can return to its
    /// pool. An interrupted temp write rolls the whole transaction back, so
    /// COMMIT runs only when one is still open.
    pub(super) fn end_stage_read(&self) -> Result<()> {
        assert!(self.stage_read.get(), "no crate stage holds a read");
        self.stage_read.set(false);
        self.clear_operation_change_stamp();
        self.commit_stage_read()
    }

    /// Let this request's own publication be seen. A capsule is published
    /// through the store's writer in the middle of a stage and admitted from
    /// this reader right after, so the stage's snapshot ends before the
    /// publication and a new one starts after it
    /// ([`Self::resume_stage_read`]). Outside a stage this does nothing.
    #[doc(hidden)]
    pub fn pause_stage_read(&self) -> Result<()> {
        if self.stage_read.get() {
            self.clear_operation_change_stamp();
            self.commit_stage_read()?;
        }
        Ok(())
    }

    /// Let code outside this operation use the store until
    /// [`Self::reclaim_writer`]. A pooled reader is the operation's own
    /// connection and is not lent.
    ///
    /// The in-memory fallback reads through the one writer connection, so an
    /// operation that held it while a caller read the store would wait for
    /// itself (#6018). The temp selection stays on the connection, and an
    /// ordinary read of this selection's snapshots finds its revision rows
    /// already installed. A read of other snapshots replaces them until
    /// [`Self::reclaim_writer`] restores them.
    pub(crate) fn lend_writer(&mut self) -> Result<()> {
        if !self.conn.excludes_store_access() {
            return Ok(());
        }
        assert!(
            !self.stage_read.get(),
            "a crate stage does not lend its reader"
        );
        assert_no_statement_in_progress(self.connection());
        let installed = lent_writer_installed_snapshots(
            self.lent_writer_changed,
            &self.writer_installed_snapshots,
        );
        self.conn.lend_writer(installed)
    }

    /// Take back a connection lent by [`Self::lend_writer`] before this
    /// operation answers, waiting for it while observing `cancellation`.
    /// `Current` also covers a reader that was not lent.
    ///
    /// The selection keeps its authority while every other user of the
    /// connection only applied ordinary workspace selections: their writes
    /// replace only its revision rows, which it restores. After any other
    /// write its temp rows may belong to another operation: the operation is
    /// stale and stays stale, and its connection stays lent so the caller can
    /// still read the store.
    pub(crate) fn reclaim_writer(
        &mut self,
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionRevalidationOutcome> {
        if !self.conn.is_lent_writer() {
            return Ok(SelectedResolutionRevalidationOutcome::Current);
        }
        if !self.lent_writer_changed {
            match self.take_back_writer(Some(cancellation))? {
                super::WriterReclaim::Unchanged | super::WriterReclaim::Restored { .. } => {
                    return Ok(SelectedResolutionRevalidationOutcome::Current);
                }
                super::WriterReclaim::Cancelled => {
                    return Ok(SelectedResolutionRevalidationOutcome::Cancelled);
                }
                super::WriterReclaim::Changed => self.lend_writer()?,
            }
        }
        Ok(SelectedResolutionRevalidationOutcome::Stale(
            SelectedResolutionStale::LentWriterChanged,
        ))
    }

    /// Take back a lent connection for this operation's own cleanup and
    /// final authority check, which need it whatever the request's
    /// cancellation says.
    pub(crate) fn end_writer_loan(&mut self) -> Result<()> {
        if self.conn.is_lent_writer() {
            self.take_back_writer(None)?;
        }
        Ok(())
    }

    fn take_back_writer(
        &mut self,
        cancellation: Option<&CancellationToken>,
    ) -> Result<super::WriterReclaim> {
        let installed = lent_writer_installed_snapshots(
            self.lent_writer_changed,
            &self.writer_installed_snapshots,
        );
        let reclaim = self.conn.reclaim_writer(cancellation, installed)?;
        match reclaim {
            // The restored connection holds exactly what this selection
            // staged, so the retained stamp still describes it.
            super::WriterReclaim::Restored { changes } => {
                self.account_committed_request_changes(changes);
            }
            super::WriterReclaim::Changed => self.lent_writer_changed = true,
            super::WriterReclaim::Unchanged | super::WriterReclaim::Cancelled => {}
        }
        Ok(reclaim)
    }

    #[doc(hidden)]
    pub fn resume_stage_read(&self) -> Result<()> {
        if self.stage_read.get() {
            assert!(self.connection().is_autocommit());
            self.clear_operation_change_stamp();
            self.connection().execute_batch("BEGIN DEFERRED")?;
        }
        Ok(())
    }

    fn commit_stage_read(&self) -> Result<()> {
        let conn = self.connection();
        assert_no_statement_in_progress(conn);
        assert_no_main_write(conn);
        if !conn.is_autocommit() {
            conn.execute_batch("COMMIT")?;
        }
        Ok(())
    }

    pub(super) fn crate_access_memo(
        &self,
    ) -> &RefCell<Option<super::resolution_operation::rust_crate_access::CrateAccessMemo>> {
        &self.crate_access
    }

    pub(super) fn path_endpoint_header_memo(
        &self,
    ) -> &RefCell<
        super::selected_read_memo::ExactReadMemo<
            super::resolution_lexical::PathEndpointHeaderReadKey,
            Vec<SelectedResolutionMountOrdinal>,
        >,
    > {
        &self.path_endpoint_header_memo
    }

    // Only SQLite-enforced read-only main connections may reuse a certificate:
    // data_version does not witness commits made by the same connection.
    pub(super) fn interior_validation_stamp(
        &self,
    ) -> Result<Option<super::WorkspaceSelectionStamp>> {
        if self.retained().interior_certificates.main_is_readonly {
            self.operation_workspace_stamp().map(Some)
        } else {
            Ok(None)
        }
    }

    pub(super) fn begin_operation_reads(&mut self) {
        assert!(self.operation_change_stamp.is_none());
        self.operation_change_stamp = Some(Cell::new(None));
    }

    fn clear_operation_change_stamp(&self) {
        *self.stage_family_occupancy.borrow_mut() = Default::default();
        if let Some(memo) = &self.operation_change_stamp {
            memo.set(None);
        }
    }

    fn operation_workspace_stamp(&self) -> Result<super::WorkspaceSelectionStamp> {
        let Some(memo) = &self.operation_change_stamp else {
            return super::workspace_selection_stamp(self.connection());
        };
        let scope = self.scope_identity();
        let stage = self.staged_read_epoch();
        if let Some(cached) = memo.get()
            && cached.scope == scope
            && cached.stage == stage
        {
            return Ok(cached.stamp);
        }
        // Selected main facts and mounts are immutable for this operation.
        // Arbitrary TEMP writes advance the direct epoch before writing, even
        // on failure; publication commits advance the content epoch before
        // another selected read. Private buffers are excluded from authority.
        let stamp = super::workspace_selection_stamp(self.connection())?;
        memo.set(Some(OperationChangeStamp {
            scope,
            stage,
            stamp,
        }));
        Ok(stamp)
    }

    #[doc(hidden)]
    pub fn read_change_stamp(&self) -> Result<SelectedResolutionReadStamp> {
        // Keep the connection's unowned-write accounting fresh even on a
        // pragma memo hit. Successful private buffer writes cancel exactly.
        Ok(self
            .retained()
            .stamp_from_workspace(self.connection(), self.operation_workspace_stamp()?))
    }

    #[doc(hidden)]
    pub fn revalidate(
        &mut self,
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionRevalidationOutcome> {
        if cancellation.is_cancelled() {
            return Ok(SelectedResolutionRevalidationOutcome::Cancelled);
        }
        self.retention_authorized = false;
        if self.lent_writer_changed {
            return Ok(SelectedResolutionRevalidationOutcome::Stale(
                SelectedResolutionStale::LentWriterChanged,
            ));
        }
        // Finish is an external freshness boundary, not an interior memo hit.
        self.clear_operation_change_stamp();
        let current = self.retained().current_stamp(self.connection())?;
        if cancellation.is_cancelled() {
            return Ok(SelectedResolutionRevalidationOutcome::Cancelled);
        }
        if current == self.retained().stamp {
            self.retention_authorized = true;
            return Ok(SelectedResolutionRevalidationOutcome::Current);
        }

        if self.stage_request_used.get() {
            match super::resolution_stage::validate_admissions(self.connection(), cancellation)? {
                SelectedResolutionRevalidationOutcome::Current => {}
                outcome => return Ok(outcome),
            }
        }

        if self.inventory_revalidation_memo.get() == Some(current) {
            // Stage admissions above still belong to this finish. Only the
            // unchanged mount-inventory read is reused. Do not authorize
            // cross-request reader retention against the original stamp.
            return Ok(SelectedResolutionRevalidationOutcome::Current);
        }

        // Drift is exceptional. Re-read only after the constant-size stamp
        // changed so typed authority failures remain visible to callers.
        let expected_fingerprint = self.fingerprint();
        let result = with_resolution_progress_handler(&mut self.conn, cancellation, |conn| {
            read_selected_inventory(conn, cancellation)
        });
        let staged = match result {
            Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => {
                return Ok(SelectedResolutionRevalidationOutcome::Cancelled);
            }
            Err(error) => return Err(error),
            Ok(staged) => staged,
        };
        if cancellation.is_cancelled() {
            return Ok(SelectedResolutionRevalidationOutcome::Cancelled);
        }
        match staged {
            StagedSelection::Ready(staged) if staged.fingerprint == expected_fingerprint => {
                self.inventory_revalidation_memo.set(Some(current));
                Ok(SelectedResolutionRevalidationOutcome::Current)
            }
            StagedSelection::Ready(_) | StagedSelection::Unavailable(_) => {
                Ok(SelectedResolutionRevalidationOutcome::Stale(
                    SelectedResolutionStale::MountInventoryChanged,
                ))
            }
            StagedSelection::Cancelled => Ok(SelectedResolutionRevalidationOutcome::Cancelled),
            StagedSelection::Stale(reason) => {
                Ok(SelectedResolutionRevalidationOutcome::Stale(reason))
            }
        }
    }
}

impl Drop for SelectedResolutionMountInventory<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.end_writer_loan() {
            eprintln!("failed to check the lent selected resolution writer: {error}");
            self.lent_writer_changed = true;
        }
        if self.stage_request_used.get()
            && let Err(error) = self.with_owned_temp_write(|connection| {
                connection.execute_batch(super::resolution_stage::CLEAR_REQUEST_SQL)?;
                Ok(())
            })
        {
            eprintln!("failed to clear selected resolution stage request rows: {error}");
            self.conn.discard_before_checkin();
            return;
        }
        let retained = self
            .retained
            .take()
            .expect("selected inventory returns its retained selection exactly once");
        let current = if self.retention_authorized {
            Ok(retained.stamp)
        } else {
            retained.current_stamp(&self.conn)
        };
        match current {
            Ok(current) if current == retained.stamp && !self.lent_writer_changed => {
                self.conn.put_retained_resolution_selection(retained);
            }
            Ok(_) | Err(_) => {
                self.conn
                    .cleanup_before_checkin(CLEAR_SELECTED_RESOLUTION_TEMP_SQL);
            }
        }
    }
}

/// The snapshots a lent writer connection's revision rows are to hold, or
/// `None` once the lending selection's authority over them is gone.
fn lent_writer_installed_snapshots(
    changed: bool,
    installed: &Option<WorkspaceSnapshots>,
) -> Option<&WorkspaceSnapshots> {
    (!changed).then(|| {
        installed
            .as_ref()
            .expect("a writer-backed selection records its installed snapshots")
    })
}

/// A write to this reader's temp tables.
///
/// It is a SAVEPOINT, so it nests inside a crate stage's read transaction
/// and, outside one, starts and commits its own transaction as BEGIN and
/// COMMIT did. An interrupted INSERT, UPDATE or DELETE rolls back the whole
/// enclosing transaction, so a rollback that finds the connection in
/// autocommit has nothing left to undo.
struct TempWrite<'c> {
    conn: &'c Connection,
    open: bool,
}

const TEMP_WRITE_SAVEPOINT: &str = "selected_temp_write";

impl<'c> TempWrite<'c> {
    fn begin(conn: &'c Connection) -> Result<Self> {
        conn.execute_batch(&format!("SAVEPOINT {TEMP_WRITE_SAVEPOINT}"))?;
        Ok(Self { conn, open: true })
    }

    fn commit(mut self) -> Result<()> {
        self.open = false;
        if self.conn.is_autocommit() {
            return Err(StoreError::new(
                "a temp write's transaction was rolled back before it committed",
            ));
        }
        self.conn
            .execute_batch(&format!("RELEASE {TEMP_WRITE_SAVEPOINT}"))?;
        Ok(())
    }

    fn rollback(mut self) -> Result<()> {
        self.open = false;
        self.undo()
    }

    fn undo(&self) -> Result<()> {
        if self.conn.is_autocommit() {
            return Ok(());
        }
        self.conn.execute_batch(&format!(
            "ROLLBACK TO {TEMP_WRITE_SAVEPOINT}; RELEASE {TEMP_WRITE_SAVEPOINT}"
        ))?;
        Ok(())
    }
}

impl Drop for TempWrite<'_> {
    fn drop(&mut self) {
        if self.open
            && let Err(error) = self.undo()
        {
            eprintln!("analyzer store could not roll back a temp write: {error}");
        }
    }
}

/// A read transaction ends only when no statement on the connection is still
/// stepping: a stage's snapshot must not end under a cursor that is reading it.
fn assert_no_statement_in_progress(conn: &Connection) {
    // SAFETY: `handle` is this open connection's database. sqlite3_next_stmt,
    // sqlite3_stmt_busy and sqlite3_sql only read the connection's own
    // statement list and statement text, and nothing here outlives the call.
    unsafe {
        let db = conn.handle();
        let mut statement = rusqlite::ffi::sqlite3_next_stmt(db, std::ptr::null_mut());
        while !statement.is_null() {
            if rusqlite::ffi::sqlite3_stmt_busy(statement) != 0 {
                let sql = std::ffi::CStr::from_ptr(rusqlite::ffi::sqlite3_sql(statement));
                panic!(
                    "a stage read transaction ends while a statement is stepping: {}",
                    sql.to_string_lossy()
                );
            }
            statement = rusqlite::ffi::sqlite3_next_stmt(db, statement);
        }
    }
}

/// A selected reader writes only its temp tables. A crate stage holds its
/// read transaction on the reader, so a main-database write there would be
/// committed with the stage instead of on its own.
fn assert_no_main_write(conn: &Connection) {
    // SAFETY: `handle` is this open connection's database and the schema name
    // is a NUL-terminated literal; sqlite3_txn_state only reads state.
    let state = unsafe { rusqlite::ffi::sqlite3_txn_state(conn.handle(), c"main".as_ptr()) };
    assert_ne!(
        state,
        rusqlite::ffi::SQLITE_TXN_WRITE,
        "a selected reader wrote the main database"
    );
}

fn read_change_stamp(
    conn: &Connection,
    owned_change_baseline: u64,
    committed_request_changes: u64,
) -> Result<SelectedResolutionReadStamp> {
    Ok(selected_read_stamp(
        conn,
        owned_change_baseline,
        committed_request_changes,
        super::workspace_selection_stamp(conn)?,
    ))
}

fn selected_read_stamp(
    conn: &Connection,
    owned_change_baseline: u64,
    committed_request_changes: u64,
    stamp: super::WorkspaceSelectionStamp,
) -> SelectedResolutionReadStamp {
    let super::WorkspaceSelectionStamp {
        main_data_version,
        main_schema_version,
        temp_schema_version,
    } = stamp;
    let unowned_changes = conn
        .total_changes()
        .checked_sub(owned_change_baseline)
        .and_then(|changes| changes.checked_sub(committed_request_changes))
        .expect("owned selection changes are a subset of connection total changes");
    SelectedResolutionReadStamp {
        main_data_version,
        main_schema_version,
        temp_schema_version,
        unowned_changes,
    }
}

/// Bounded language authority metadata; the workspace identity has validated
/// fixed digest width. Variable selection inputs and all mount rows stay in TEMP.
struct RetainedSelectedMetadata {
    // Bounded by the registered language inventory, independent of mount count.
    module_definition_providers: Vec<super::language_support::ModuleDefinitionProvider>,
    namespace_definition_providers: Vec<(
        String,
        Language,
        super::language_support::NamespaceDefinitionProvider,
    )>,
    has_conditional_type_seeds: bool,
    // A fixed selection property, so endpoint admission need not query language
    // rows on every newly borrowed Rust-only operation.
    has_registered_member_semantics: bool,
    has_go_semantics: bool,
    // Likewise for the Java lexical hierarchy replay: a selection without Java
    // semantics never prepares one, so Rust-only points pay no read for it.
    has_java_semantics: bool,
    // The shared JVM hierarchy replay is available to Java, Kotlin, and Scala
    // selections while keeping Rust-only point work out of that path.
    has_jvm_semantics: bool,
    // A selection whose languages have no universe table never reads a
    // reference spelling for one.
    has_universe_semantics: bool,
    workspace_id: String,
    fingerprint: [u8; 32],
    persisted_mount_count: usize,
    expected_transient_replacement_count: usize,
}

impl RetainedSelectedMetadata {
    fn from_staged(staged: &StagedReadySelection) -> Self {
        Self {
            module_definition_providers: staged
                .languages
                .iter()
                .filter_map(|language| {
                    super::store_language_support(language.semantic_language())?
                        .module_definition_provider()
                })
                .collect(),
            namespace_definition_providers: staged
                .languages
                .iter()
                .filter_map(|language| {
                    let provider = super::store_language_support(language.semantic_language())?
                        .namespace_definition_provider()?;
                    Some((
                        language.storage_language().to_owned(),
                        language.semantic_language(),
                        provider,
                    ))
                })
                .collect(),
            has_conditional_type_seeds: staged.languages.iter().any(|language| {
                super::store_language_support(language.semantic_language())
                    .is_some_and(|support| support.has_conditional_type_seeds())
            }),
            has_registered_member_semantics: staged.languages.iter().any(|language| {
                super::language_support::qualified_member_registrations()
                    .iter()
                    .any(|entry| entry.language == language.semantic_language())
            }),
            has_go_semantics: staged
                .languages
                .iter()
                .any(|language| language.semantic_language() == Language::Go),
            has_java_semantics: staged
                .languages
                .iter()
                .any(|language| language.semantic_language() == Language::Java),
            has_jvm_semantics: staged
                .languages
                .iter()
                .any(|language| language_has_jvm_semantics(language.semantic_language())),
            has_universe_semantics: staged.languages.iter().any(|language| {
                crate::analyzer::resolution::universe_has_table(language.semantic_language())
            }),
            workspace_id: staged.workspace_id.clone(),
            fingerprint: staged.fingerprint,
            persisted_mount_count: staged.mounts.len(),
            expected_transient_replacement_count: staged.expected_transient_replacement_count,
        }
    }
}

#[doc(hidden)]
pub struct StagedReadySelection {
    #[doc(hidden)]
    pub workspace_id: String,
    #[doc(hidden)]
    pub languages: Vec<SelectedResolutionLanguageState>,
    #[doc(hidden)]
    pub overlay_masks: Vec<SelectedResolutionOverlayMaskState>,
    #[doc(hidden)]
    pub mounts: Vec<SelectedResolutionMountRecord>,
    #[doc(hidden)]
    pub fingerprint: [u8; 32],
    #[doc(hidden)]
    pub expected_transient_replacement_count: usize,
}

enum StagedSelection {
    Ready(Box<StagedReadySelection>),
    Unavailable(SelectedResolutionUnavailable),
    Cancelled,
    Stale(SelectedResolutionStale),
}

impl AnalyzerStore {
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn open_selected_resolution_mount_inventory(
        &self,
        workspace_id: &WorkspaceId,
        snapshots: &WorkspaceSnapshots,
        languages: &[SelectedResolutionLanguage],
        overlay_masks: &[SelectedResolutionOverlayMask],
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionMountInventoryOutcome<'_>> {
        self.open_selected_resolution_mount_inventory_with_content_mounts(
            workspace_id,
            snapshots,
            languages,
            overlay_masks,
            &[],
            cancellation,
        )
    }

    #[doc(hidden)]
    pub fn open_selected_resolution_mount_inventory_with_content_mounts(
        &self,
        workspace_id: &WorkspaceId,
        snapshots: &WorkspaceSnapshots,
        languages: &[SelectedResolutionLanguage],
        overlay_masks: &[SelectedResolutionOverlayMask],
        content_mounts: &[SelectedResolutionContentMountRequest],
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionMountInventoryOutcome<'_>> {
        if cancellation.is_cancelled() {
            return Ok(SelectedResolutionMountInventoryOutcome::Cancelled);
        }
        let Some(validated) = validate_selection_input(
            workspace_id,
            snapshots,
            languages,
            overlay_masks,
            content_mounts,
            cancellation,
        )?
        else {
            return Ok(SelectedResolutionMountInventoryOutcome::Cancelled);
        };
        let RetainedResolutionSelectionKey {
            workspace_id,
            snapshots: selected_snapshots,
            languages,
            overlay_masks,
            content_mounts,
        } = &validated;
        if cancellation.is_cancelled() {
            return Ok(SelectedResolutionMountInventoryOutcome::Cancelled);
        }
        if let Some(language) = languages
            .iter()
            .find(|language| !selected_snapshots.contains_key(language.storage_language()))
        {
            return Ok(SelectedResolutionMountInventoryOutcome::Unavailable(
                SelectedResolutionUnavailable::MissingWorkspaceSnapshot {
                    storage_language: language.storage_language.clone(),
                },
            ));
        }
        let Some(mut conn) = self.cancellable_read_conn_for_resolution(&validated, cancellation)?
        else {
            return Ok(SelectedResolutionMountInventoryOutcome::Cancelled);
        };
        // These indexed query shapes have parameter-independent access-path
        // laws. Keep plans and planner policy for the retained pooled reader;
        // a general checkout restores its prior policy. Writer fallback stays
        // scoped and restores even on cancellation/unwind.
        conn.retain_resolution_query_plans()?;

        let admitted = with_resolution_progress_handler(&mut conn, cancellation, |conn| {
            for request in content_mounts {
                let owner = selected_snapshots
                    .get(request.storage_language())
                    .expect("selected language snapshot checked above");
                if let Some(outcome) = request.validate_publication(conn, owner, cancellation)? {
                    return Ok(Some(outcome));
                }
            }
            Ok(None)
        });
        // Admission only reads main authority; preserve any existing reader TEMP
        // state on failure, including writer fallback readers without a pool.
        match admitted {
            Ok(None) => {}
            Ok(Some(outcome)) => {
                return Ok(match outcome {
                    StagedSelection::Cancelled => {
                        SelectedResolutionMountInventoryOutcome::Cancelled
                    }
                    StagedSelection::Stale(stale) => {
                        SelectedResolutionMountInventoryOutcome::Stale(stale)
                    }
                    StagedSelection::Unavailable(unavailable) => {
                        SelectedResolutionMountInventoryOutcome::Unavailable(unavailable)
                    }
                    StagedSelection::Ready(_) => {
                        unreachable!("witness validation does not construct an inventory")
                    }
                });
            }
            Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => {
                return Ok(SelectedResolutionMountInventoryOutcome::Cancelled);
            }
            Err(error) => {
                return Err(error);
            }
        }

        if let Some(retained) = conn.take_retained_resolution_selection()
            && retained.routing_digest == validated.routing_digest()
        {
            let current = with_resolution_progress_handler(&mut conn, cancellation, |conn| {
                validated.equals_selected_rows(conn).and_then(|equal| {
                    if equal {
                        retained.is_current(conn)
                    } else {
                        Ok(false)
                    }
                })
            });
            match current {
                Ok(true) => {
                    let mount_rebaser = MountRebaser::for_persisted_mount_count(
                        retained.ready.persisted_mount_count,
                    );
                    return Ok(SelectedResolutionMountInventoryOutcome::Ready(Box::new(
                        SelectedResolutionMountInventory {
                            retained: Some(retained),
                            requested_mounts: RequestedResolutionMountRows::default(),
                            enumerated_mounts: OnceCell::new(),
                            requested_languages: OnceCell::new(),
                            requested_masks: OnceCell::new(),
                            mount_rebaser: RefCell::new(mount_rebaser),
                            retention_authorized: false,
                            stage_request_used: Cell::new(false),
                            stage_request_identity: next_stage_request_identity(),
                            stage_content_epoch: Cell::new(0),
                            stage_direct_write_epoch: Cell::new(0),
                            scope_identity: Cell::new(scope_identity_of(&[])),
                            crate_access: RefCell::default(),
                            authority_validations: RefCell::default(),
                            authority_request_memo: RefCell::default(),
                            site_row_memo: RefCell::default(),
                            identity_recipe_memo: RefCell::default(),
                            python_receiver_rows: RefCell::default(),
                            #[cfg(any(test, feature = "test-support"))]
                            python_unit_metadata: RefCell::default(),
                            path_endpoint_header_memo: RefCell::default(),
                            inventory_revalidation_memo: Cell::new(None),
                            operation_change_stamp: None,
                            stage_family_occupancy: RefCell::default(),
                            published_context_tokens: RefCell::default(),
                            derive_helper_decisions: RefCell::default(),
                            stage_read: Cell::new(false),
                            generic_formals_schema_ready: Cell::new(false),
                            generic_formal_defaults_schema_ready: Cell::new(false),
                            reverse_candidate_keys_schema_ready: Cell::new(false),
                            writer_installed_snapshots: conn
                                .excludes_store_access()
                                .then(|| selected_snapshots.clone()),
                            lent_writer_changed: false,
                            shared_names: super::resolution::SharedNameTable::new(
                                self.resolution_shared_name_cache().clone(),
                            ),
                            conn,
                        },
                    )));
                }
                Ok(false) => {}
                Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => {
                    conn.cleanup_before_checkin(CLEAR_SELECTED_RESOLUTION_TEMP_SQL);
                    return Ok(SelectedResolutionMountInventoryOutcome::Cancelled);
                }
                Err(error) => {
                    conn.cleanup_before_checkin(CLEAR_SELECTED_RESOLUTION_TEMP_SQL);
                    return Err(error);
                }
            }
        }

        conn.discard_before_checkin();
        if let Err(error) = ensure_revisioned_workspace_views(&conn) {
            conn.cleanup_before_checkin(CLEAR_SELECTED_RESOLUTION_TEMP_SQL);
            return Err(error);
        }
        if let Err(error) = conn.execute_batch(selected_resolution_temp_schema_sql()) {
            conn.cleanup_before_checkin(CLEAR_SELECTED_RESOLUTION_TEMP_SQL);
            return Err(error.into());
        }
        if let Err(error) = conn.execute_batch(CLEAR_SELECTED_RESOLUTION_TEMP_SQL) {
            conn.cleanup_before_checkin(CLEAR_SELECTED_RESOLUTION_TEMP_SQL);
            return Err(error.into());
        }
        // A publication that commits to the main store while this selection
        // stages leaves the staged inventory stale. That is a race with a
        // concurrent writer, not a property of the request, so stage again
        // against a fresh start stamp a bounded number of times; publication
        // that keeps moving still reports stale (#3823).
        let mut remaining_attempts = SELECTED_INVENTORY_ACQUISITION_ATTEMPTS;
        let (staged, verified_stamp) = loop {
            remaining_attempts -= 1;
            let selection_start_stamp = match read_change_stamp(&conn, conn.total_changes(), 0) {
                Ok(stamp) => stamp,
                Err(error) => {
                    conn.cleanup_before_checkin(CLEAR_SELECTED_RESOLUTION_TEMP_SQL);
                    return Err(error);
                }
            };

            let result = with_resolution_progress_handler(&mut conn, cancellation, |conn| {
                let tx = conn.transaction()?;
                if !insert_selection_input(
                    &tx,
                    workspace_id,
                    selected_snapshots,
                    languages,
                    overlay_masks,
                    content_mounts,
                    cancellation,
                )? {
                    tx.rollback()?;
                    return Ok(StagedSelection::Cancelled);
                }
                let staged = read_selected_inventory(&tx, cancellation)?;
                if let StagedSelection::Ready(ready) = &staged
                    && !persist_selected_inventory(&tx, ready, cancellation)?
                {
                    tx.rollback()?;
                    return Ok(StagedSelection::Cancelled);
                }
                tx.commit()?;
                Ok(staged)
            });

            let staged = match result {
                Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => {
                    conn.cleanup_before_checkin(CLEAR_SELECTED_RESOLUTION_TEMP_SQL);
                    return Ok(SelectedResolutionMountInventoryOutcome::Cancelled);
                }
                Err(error) => {
                    conn.cleanup_before_checkin(CLEAR_SELECTED_RESOLUTION_TEMP_SQL);
                    return Err(error);
                }
                Ok(staged) => staged,
            };
            if cancellation.is_cancelled() {
                conn.cleanup_before_checkin(CLEAR_SELECTED_RESOLUTION_TEMP_SQL);
                return Ok(SelectedResolutionMountInventoryOutcome::Cancelled);
            }
            if !matches!(staged, StagedSelection::Ready(_)) {
                break (staged, None);
            }
            debug_assert!(
                conn.is_autocommit(),
                "selected mount inventory must not pin a main-database read transaction"
            );
            let owned_change_baseline = conn.total_changes();
            let stamp = match read_change_stamp(&conn, owned_change_baseline, 0) {
                Ok(stamp) => stamp,
                Err(error) => {
                    conn.cleanup_before_checkin(CLEAR_SELECTED_RESOLUTION_TEMP_SQL);
                    return Err(error);
                }
            };
            if stamp.main_data_version == selection_start_stamp.main_data_version
                && stamp.main_schema_version == selection_start_stamp.main_schema_version
            {
                break (staged, Some((stamp, owned_change_baseline)));
            }
            if remaining_attempts == 0 {
                conn.cleanup_before_checkin(CLEAR_SELECTED_RESOLUTION_TEMP_SQL);
                return Ok(SelectedResolutionMountInventoryOutcome::Stale(
                    SelectedResolutionStale::MountInventoryChanged,
                ));
            }
            if let Err(error) = conn.execute_batch(CLEAR_SELECTED_RESOLUTION_TEMP_SQL) {
                conn.cleanup_before_checkin(CLEAR_SELECTED_RESOLUTION_TEMP_SQL);
                return Err(error.into());
            }
        };
        match staged {
            StagedSelection::Ready(staged) => {
                let (stamp, owned_change_baseline) =
                    verified_stamp.expect("a ready selection carries its verified change stamp");
                let retained = RetainedResolutionSelection {
                    routing_digest: validated.routing_digest(),
                    ready: RetainedSelectedMetadata::from_staged(&staged),
                    stamp,
                    owned_change_baseline,
                    committed_request_changes: Cell::new(0),
                    committed_schema_changes: Cell::new(0),
                    interior_certificates: Box::new(SelectedInteriorCertificates {
                        main_is_readonly: conn.is_readonly(rusqlite::MAIN_DB)?,
                        lexical: Cell::new(None),
                        typed: Cell::new(None),
                    }),
                };
                let mount_rebaser =
                    MountRebaser::for_persisted_mount_count(retained.ready.persisted_mount_count);
                conn.retain_before_checkin();
                Ok(SelectedResolutionMountInventoryOutcome::Ready(Box::new(
                    SelectedResolutionMountInventory {
                        retained: Some(retained),
                        requested_mounts: RequestedResolutionMountRows::default(),
                        enumerated_mounts: OnceCell::new(),
                        requested_languages: OnceCell::new(),
                        requested_masks: OnceCell::new(),
                        mount_rebaser: RefCell::new(mount_rebaser),
                        retention_authorized: false,
                        stage_request_used: Cell::new(false),
                        stage_request_identity: next_stage_request_identity(),
                        stage_content_epoch: Cell::new(0),
                        stage_direct_write_epoch: Cell::new(0),
                        scope_identity: Cell::new(scope_identity_of(&[])),
                        crate_access: RefCell::default(),
                        authority_validations: RefCell::default(),
                        authority_request_memo: RefCell::default(),
                        site_row_memo: RefCell::default(),
                        identity_recipe_memo: RefCell::default(),
                        python_receiver_rows: RefCell::default(),
                        #[cfg(any(test, feature = "test-support"))]
                        python_unit_metadata: RefCell::default(),
                        path_endpoint_header_memo: RefCell::default(),
                        inventory_revalidation_memo: Cell::new(None),
                        operation_change_stamp: None,
                        stage_family_occupancy: RefCell::default(),
                        published_context_tokens: RefCell::default(),
                        derive_helper_decisions: RefCell::default(),
                        stage_read: Cell::new(false),
                        generic_formals_schema_ready: Cell::new(false),
                        generic_formal_defaults_schema_ready: Cell::new(false),
                        reverse_candidate_keys_schema_ready: Cell::new(false),
                        writer_installed_snapshots: conn
                            .excludes_store_access()
                            .then(|| selected_snapshots.clone()),
                        lent_writer_changed: false,
                        shared_names: super::resolution::SharedNameTable::new(
                            self.resolution_shared_name_cache().clone(),
                        ),
                        conn,
                    },
                )))
            }
            StagedSelection::Unavailable(reason) => {
                conn.cleanup_before_checkin(CLEAR_SELECTED_RESOLUTION_TEMP_SQL);
                Ok(SelectedResolutionMountInventoryOutcome::Unavailable(reason))
            }
            StagedSelection::Cancelled => {
                conn.cleanup_before_checkin(CLEAR_SELECTED_RESOLUTION_TEMP_SQL);
                Ok(SelectedResolutionMountInventoryOutcome::Cancelled)
            }
            StagedSelection::Stale(reason) => {
                conn.cleanup_before_checkin(CLEAR_SELECTED_RESOLUTION_TEMP_SQL);
                Ok(SelectedResolutionMountInventoryOutcome::Stale(reason))
            }
        }
    }
}

/// How many times selection staging may restart after a concurrent main-store
/// commit before the request reports `MountInventoryChanged`.
const SELECTED_INVENTORY_ACQUISITION_ATTEMPTS: usize = 3;

type ValidatedSelectionInput = RetainedResolutionSelectionKey;

#[doc(hidden)]
pub fn validate_selection_input(
    selected_workspace_id: &WorkspaceId,
    snapshots: &WorkspaceSnapshots,
    languages: &[SelectedResolutionLanguage],
    overlay_masks: &[SelectedResolutionOverlayMask],
    content_mounts: &[SelectedResolutionContentMountRequest],
    cancellation: &CancellationToken,
) -> Result<Option<ValidatedSelectionInput>> {
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    let mut ordered_languages = BTreeMap::new();
    for language in languages {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let entry = ordered_languages
            .entry(language.storage_language.clone())
            .or_insert_with(|| (0_usize, language.clone()));
        entry.0 += 1;
    }
    if let Some((storage_language, _)) = ordered_languages
        .iter()
        .find(|(_, (occurrences, _))| *occurrences > 1)
    {
        return Err(StoreError::new(format!(
            "duplicate selected resolution language {storage_language:?}"
        )));
    }
    let mut languages = Vec::with_capacity(ordered_languages.len());
    for (_, (_, language)) in ordered_languages {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        languages.push(language);
    }
    let requested = languages
        .iter()
        .map(|language| language.storage_language.as_str())
        .collect::<HashSet<_>>();

    let mut selected_snapshots = HashMap::default();
    let workspace_id = selected_workspace_id.as_str();
    for (key, snapshot) in snapshots {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        if key != &snapshot.lang {
            return Err(StoreError::new(format!(
                "workspace snapshot key {key:?} carries language {:?}",
                snapshot.lang
            )));
        }
        if workspace_id != snapshot.workspace_id.as_str() {
            return Err(StoreError::new(
                "selected resolution snapshots belong to a different workspace",
            ));
        }
    }
    for language in &languages {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let Some(snapshot) = snapshots.get(&language.storage_language) else {
            continue;
        };
        if snapshot.lang != language.storage_language {
            return Err(StoreError::new(format!(
                "selected snapshot key {:?} carries language {:?}",
                language.storage_language, snapshot.lang
            )));
        }
        selected_snapshots.insert(language.storage_language.clone(), snapshot.clone());
    }

    let mut ordered_masks = BTreeMap::new();
    for mask in overlay_masks {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        if !requested.contains(mask.storage_language.as_str()) {
            return Err(StoreError::new(format!(
                "selected resolution mask names unrequested language {:?}",
                mask.storage_language
            )));
        }
        let key = (
            mask.storage_language.clone(),
            mask.persisted_relative_path.clone(),
        );
        let entry = ordered_masks
            .entry(key)
            .or_insert_with(|| (0_usize, mask.clone()));
        entry.0 += 1;
    }
    if let Some(((storage_language, persisted_relative_path), _)) = ordered_masks
        .iter()
        .find(|(_, (occurrences, _))| *occurrences > 1)
    {
        return Err(StoreError::new(format!(
            "duplicate selected resolution mask {storage_language}/{persisted_relative_path}"
        )));
    }
    let mut overlay_masks = Vec::with_capacity(ordered_masks.len());
    for (_, (_, mask)) in ordered_masks {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        overlay_masks.push(mask);
    }

    let mut ordered_content_mounts = BTreeMap::new();
    for content_mount in content_mounts {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        if !requested.contains(content_mount.storage_language()) {
            return Err(StoreError::new(format!(
                "selected resolution content mount names unrequested language {:?}",
                content_mount.storage_language()
            )));
        }
        let key = (
            content_mount.storage_language().to_owned(),
            content_mount.persisted_relative_path().to_owned(),
        );
        if ordered_content_mounts
            .insert(key.clone(), content_mount.clone())
            .is_some()
        {
            return Err(StoreError::new(format!(
                "duplicate selected resolution content mount {}/{}",
                key.0, key.1
            )));
        }
    }
    let content_mounts = ordered_content_mounts.into_values().collect();
    Ok(Some(RetainedResolutionSelectionKey {
        workspace_id: workspace_id.to_owned(),
        snapshots: selected_snapshots,
        languages,
        overlay_masks,
        content_mounts,
    }))
}

#[doc(hidden)]
pub fn insert_selection_input(
    tx: &Transaction<'_>,
    workspace_id: &str,
    snapshots: &WorkspaceSnapshots,
    languages: &[SelectedResolutionLanguage],
    overlay_masks: &[SelectedResolutionOverlayMask],
    content_mounts: &[SelectedResolutionContentMountRequest],
    cancellation: &CancellationToken,
) -> Result<bool> {
    if cancellation.is_cancelled() {
        return Ok(false);
    }
    debug_assert_eq!(
        tx.query_row(
            "SELECT count(*) FROM temp.selected_rust_container_placements",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0,
        "selection inputs must be installed before materializing module placements"
    );
    debug_assert_eq!(
        tx.query_row(
            "SELECT count(*) FROM temp.selected_rust_unit_summaries",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0,
        "selection revisions must precede materializing Rust units"
    );
    tx.execute(
        "INSERT INTO temp.selected_resolution_context(singleton, workspace_id) VALUES(0, ?1)",
        [workspace_id],
    )?;
    {
        let mut insert = tx.prepare_cached(
            "INSERT INTO temp.selected_workspace_revisions(
               workspace_id, lang, generation, revision
             ) VALUES(?1, ?2, ?3, ?4)",
        )?;
        for snapshot in snapshots.values() {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            insert.execute(params![
                snapshot.workspace_id.as_str(),
                snapshot.lang,
                snapshot.generation.0,
                snapshot.revision,
            ])?;
        }
    }
    super::fill_selected_rust_units(tx)?;
    {
        let mut insert = tx.prepare_cached(
            "INSERT INTO temp.selected_resolution_languages(
               storage_language, semantic_language, expected_producer_epoch
             ) VALUES(?1, ?2, ?3)",
        )?;
        for language in languages {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            insert.execute(params![
                language.storage_language,
                language.semantic_language.config_label(),
                resolution_bundle_epoch(language.semantic_language),
            ])?;
        }
    }
    {
        let mut insert = tx.prepare_cached(
            "INSERT INTO temp.selected_resolution_overlay_masks(
               storage_language, persisted_relative_path, intent
             ) VALUES(?1, ?2, ?3)",
        )?;
        for mask in overlay_masks {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            insert.execute(params![
                mask.storage_language,
                mask.persisted_relative_path,
                mask.intent.as_str(),
            ])?;
        }
    }
    {
        let mut insert = tx.prepare_cached(
            "INSERT INTO temp.selected_resolution_content_mounts(
               storage_language, generation, persisted_relative_path,
               blob_oid, projection_digest, overlay_authority_kind, overlay_authority_digest, publication_digest
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?;
        for content_mount in content_mounts {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            insert.execute(params![
                content_mount.storage_language(),
                content_mount.generation().get(),
                content_mount.persisted_relative_path(),
                content_mount.blob_oid().to_string(),
                content_mount.projection_digest().as_slice(),
                content_mount.overlay_authority_columns().0,
                content_mount
                    .overlay_authority_columns()
                    .1
                    .map(|digest| digest.as_slice()),
                content_mount.publication_digest().as_slice(),
            ])?;
        }
    }
    Ok(true)
}

#[derive(Clone)]
struct SelectedLanguageAuthority {
    storage_language: String,
    semantic_language: Language,
    expected_producer_epoch: String,
    workspace_id: String,
    generation: i64,
    revision: i64,
}

fn read_selected_inventory(
    conn: &Connection,
    cancellation: &CancellationToken,
) -> Result<StagedSelection> {
    let workspace_id = conn.query_row(
        "SELECT workspace_id FROM temp.selected_resolution_context WHERE singleton = 0",
        [],
        |row| row.get::<_, String>(0),
    )?;
    let authorities = match read_selected_language_authorities(conn, cancellation)? {
        StagedAuthorities::Ready(authorities) => authorities,
        StagedAuthorities::Unavailable(reason) => {
            return Ok(StagedSelection::Unavailable(reason));
        }
        StagedAuthorities::Cancelled => return Ok(StagedSelection::Cancelled),
        StagedAuthorities::Stale(reason) => return Ok(StagedSelection::Stale(reason)),
    };
    let overlay_masks = read_selected_mask_states(conn, &authorities, cancellation)?;
    if cancellation.is_cancelled() {
        return Ok(StagedSelection::Cancelled);
    }
    let mut mounts = Vec::new();
    let mut language_states = Vec::with_capacity(authorities.len());
    for authority in &authorities {
        let before = mounts.len();
        if let Some(non_ready) =
            read_selected_language_mounts(conn, authority, cancellation, &mut mounts)?
        {
            return Ok(non_ready);
        }
        let unmasked = mounts.len() - before;
        let masked = overlay_masks
            .iter()
            .filter(|mask| {
                mask.storage_language == authority.storage_language && mask.masked_base.is_some()
            })
            .count();
        language_states.push(SelectedResolutionLanguageState {
            storage_language: authority.storage_language.clone(),
            semantic_language: authority.semantic_language,
            workspace_id: authority.workspace_id.clone(),
            generation: authority.generation,
            revision: authority.revision,
            expected_base_mount_count: unmasked
                .checked_add(masked)
                .ok_or_else(|| StoreError::new("selected resolution base mount count overflow"))?,
            masked_base_mount_count: masked,
            expected_unmasked_mount_count: unmasked,
        });
    }
    if let Some(non_ready) = read_selected_content_mounts(
        conn,
        &authorities,
        &overlay_masks,
        cancellation,
        &mut mounts,
    )? {
        return Ok(non_ready);
    }
    let mut fragments = HashSet::default();
    // These ordinals cover only validated persisted mounts. They are
    // operation-local provenance, excluded from fragment identity, and leave
    // transient replacements free to append densely in the composite-source
    // tranche without renumbering this inventory.
    for (index, mount) in mounts.iter_mut().enumerate() {
        if cancellation.is_cancelled() {
            return Ok(StagedSelection::Cancelled);
        }
        let ordinal = u32::try_from(index)
            .map_err(|_| StoreError::new("selected resolution mount ordinal exceeds u32"))?;
        mount.ordinal = SelectedResolutionMountOrdinal::new(ordinal);
        if !fragments.insert(mount.fragment_digest) {
            return Err(StoreError::new(format!(
                "selected resolution fragment id repeats at {}/{}",
                mount.storage_language, mount.persisted_relative_path
            )));
        }
    }
    let Some(fingerprint) = selection_fingerprint(
        &workspace_id,
        &language_states,
        &overlay_masks,
        &mounts,
        cancellation,
    ) else {
        return Ok(StagedSelection::Cancelled);
    };
    let mut expected_transient_replacement_count = 0_usize;
    let mut content_mount_paths = HashSet::default();
    for mount in &mounts {
        if cancellation.is_cancelled() {
            return Ok(StagedSelection::Cancelled);
        }
        if mount.file_version_id().is_none() {
            content_mount_paths.insert((mount.storage_language(), mount.persisted_relative_path()));
        }
    }
    for mask in &overlay_masks {
        if cancellation.is_cancelled() {
            return Ok(StagedSelection::Cancelled);
        }
        let content_mount_replaces_path = content_mount_paths
            .contains(&(mask.storage_language(), mask.persisted_relative_path()));
        if !content_mount_replaces_path {
            expected_transient_replacement_count = expected_transient_replacement_count
                .checked_add(mask.expected_transient_replacement_count as usize)
                .ok_or_else(|| StoreError::new("selected overlay replacement count overflow"))?;
        }
    }
    if cancellation.is_cancelled() {
        return Ok(StagedSelection::Cancelled);
    }
    Ok(StagedSelection::Ready(Box::new(StagedReadySelection {
        workspace_id,
        languages: language_states,
        overlay_masks,
        mounts,
        fingerprint,
        expected_transient_replacement_count,
    })))
}

enum StagedAuthorities {
    Ready(Vec<SelectedLanguageAuthority>),
    Unavailable(SelectedResolutionUnavailable),
    Cancelled,
    Stale(SelectedResolutionStale),
}

fn read_selected_language_authorities(
    conn: &Connection,
    cancellation: &CancellationToken,
) -> Result<StagedAuthorities> {
    let mut statement = conn.prepare_cached(SELECTED_LANGUAGE_AUTHORITY_SQL)?;
    let mut rows = statement.query([])?;
    let mut authorities = Vec::new();
    while let Some(row) = rows.next()? {
        if cancellation.is_cancelled() {
            return Ok(StagedAuthorities::Cancelled);
        }
        let storage_language: String = row.get(0)?;
        let semantic_text: String = row.get(1)?;
        let expected_producer_epoch: String = row.get(2)?;
        let Some(workspace_id) = row.get::<_, Option<String>>(3)? else {
            return Ok(StagedAuthorities::Unavailable(
                SelectedResolutionUnavailable::MissingWorkspaceSnapshot { storage_language },
            ));
        };
        let generation: i64 = row
            .get::<_, Option<i64>>(4)?
            .expect("selected workspace generation accompanies workspace id");
        let revision: i64 = row
            .get::<_, Option<i64>>(5)?
            .expect("selected workspace revision accompanies workspace id");
        if row.get::<_, Option<i64>>(6)?.is_none() {
            return Ok(StagedAuthorities::Stale(
                SelectedResolutionStale::WorkspaceRevision { storage_language },
            ));
        }
        if row.get::<_, i64>(7)? != generation {
            return Ok(StagedAuthorities::Stale(
                SelectedResolutionStale::AnalysisGeneration { storage_language },
            ));
        }
        let active_epoch = row.get::<_, Option<String>>(8)?;
        if active_epoch.is_none() {
            return Ok(StagedAuthorities::Unavailable(
                SelectedResolutionUnavailable::MissingProducerEpoch { storage_language },
            ));
        }
        if active_epoch.as_deref() != Some(&expected_producer_epoch) {
            return Ok(StagedAuthorities::Stale(
                SelectedResolutionStale::ProducerEpoch { storage_language },
            ));
        }
        let semantic_language = Language::from_config_label(&semantic_text).ok_or_else(|| {
            StoreError::new(format!(
                "invalid selected semantic language {semantic_text:?} for {storage_language}"
            ))
        })?;
        if semantic_language.config_label() != semantic_text
            || resolution_bundle_epoch(semantic_language) != expected_producer_epoch
        {
            return Err(StoreError::new(format!(
                "selected language authority is not code-owned for {storage_language}"
            )));
        }
        authorities.push(SelectedLanguageAuthority {
            storage_language,
            semantic_language,
            expected_producer_epoch,
            workspace_id,
            generation,
            revision,
        });
    }
    Ok(StagedAuthorities::Ready(authorities))
}

fn read_selected_mask_states(
    conn: &Connection,
    authorities: &[SelectedLanguageAuthority],
    cancellation: &CancellationToken,
) -> Result<Vec<SelectedResolutionOverlayMaskState>> {
    let mut states = Vec::new();
    for authority in authorities {
        let mut cursor: Option<String> = None;
        loop {
            if cancellation.is_cancelled() {
                return Ok(Vec::new());
            }
            let mut page_statement = conn.prepare_cached(if cursor.is_some() {
                SELECTED_MASK_PAGE_CONTINUATION_SQL
            } else {
                SELECTED_MASK_PAGE_INITIAL_SQL
            })?;
            let mut page_rows = match &cursor {
                Some(path) => page_statement.query(params![authority.storage_language, path])?,
                None => page_statement.query([&authority.storage_language])?,
            };
            let mut page = Vec::new();
            while let Some(row) = page_rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(Vec::new());
                }
                page.push((row.get::<_, String>(0)?, row.get::<_, String>(1)?));
            }
            let page_len = page.len();
            for (persisted_relative_path, intent_text) in page {
                if cancellation.is_cancelled() {
                    return Ok(Vec::new());
                }
                let intent =
                    SelectedResolutionOverlayIntent::from_str(&intent_text).ok_or_else(|| {
                        StoreError::new(format!("invalid selected overlay intent {intent_text:?}"))
                    })?;
                let mut base_statement = conn.prepare_cached(SELECTED_MASK_BASE_SQL)?;
                let mut base_rows = base_statement
                    .query(params![authority.storage_language, persisted_relative_path])?;
                let masked_base = if let Some(row) = base_rows.next()? {
                    let base = SelectedResolutionMaskedBase {
                        file_version_id: row.get(0)?,
                        blob_oid: parse_oid(&row.get::<_, String>(1)?, "masked base blob OID")?,
                        projection_digest: parse_digest_text(
                            &row.get::<_, String>(2)?,
                            "masked base projection digest",
                        )?,
                    };
                    if base_rows.next()?.is_some() {
                        return Err(StoreError::new(format!(
                            "selected revision contains overlapping file versions for masked path \
                             {}/{persisted_relative_path}",
                            authority.storage_language
                        )));
                    }
                    Some(base)
                } else {
                    None
                };
                cursor = Some(persisted_relative_path.clone());
                states.push(SelectedResolutionOverlayMaskState {
                    storage_language: authority.storage_language.clone(),
                    persisted_relative_path,
                    intent,
                    expected_transient_replacement_count: intent
                        .expected_transient_replacement_count(),
                    masked_base,
                });
            }
            if cancellation.is_cancelled() {
                return Ok(Vec::new());
            }
            if page_len < SELECTED_MOUNT_PAGE_ROWS {
                break;
            }
        }
    }
    Ok(states)
}

fn read_selected_language_mounts(
    conn: &Connection,
    authority: &SelectedLanguageAuthority,
    cancellation: &CancellationToken,
    mounts: &mut Vec<SelectedResolutionMountRecord>,
) -> Result<Option<StagedSelection>> {
    let mut previous_path: Option<String> = None;
    let mut cursor: Option<(String, i64)> = None;
    loop {
        if cancellation.is_cancelled() {
            return Ok(Some(StagedSelection::Cancelled));
        }
        let mut statement = conn.prepare_cached(selected_mount_status_sql(cursor.is_some()))?;
        let mut rows = match &cursor {
            Some((path, valid_from)) => {
                statement.query(params![authority.storage_language, path, valid_from])?
            }
            None => statement.query([&authority.storage_language])?,
        };
        let mut page_rows = 0_usize;
        let mut page_cursor = None;
        while let Some(row) = rows.next()? {
            page_rows += 1;
            if cancellation.is_cancelled() {
                return Ok(Some(StagedSelection::Cancelled));
            }
            let workspace_id: String = row.get(0)?;
            let revision: i64 = row.get(1)?;
            let file_version_id: i64 = row.get(2)?;
            let valid_from: i64 = row.get(3)?;
            let storage_language: String = row.get(4)?;
            let generation: i64 = row.get(5)?;
            let persisted_relative_path: String = row.get(6)?;
            let blob_oid_text: String = row.get(7)?;
            let projection_text: String = row.get(8)?;
            page_cursor = Some((persisted_relative_path.clone(), valid_from));
            if previous_path.as_deref() == Some(&persisted_relative_path) {
                return Err(StoreError::new(format!(
                    "selected revision contains overlapping file versions for \
                 {storage_language}/{persisted_relative_path}"
                )));
            }
            previous_path = Some(persisted_relative_path.clone());
            let Some(blob_id) = row.get::<_, Option<i64>>(9)? else {
                return Ok(Some(StagedSelection::Unavailable(
                    SelectedResolutionUnavailable::MissingBlob {
                        storage_language,
                        persisted_relative_path,
                    },
                )));
            };
            if row.get::<_, Option<i64>>(10)? != Some(generation) {
                return Ok(Some(StagedSelection::Unavailable(
                    SelectedResolutionUnavailable::BlobGenerationMismatch {
                        storage_language,
                        persisted_relative_path,
                    },
                )));
            }
            if row.get::<_, Option<i64>>(11)? != Some(1) {
                return Ok(Some(StagedSelection::Unavailable(
                    SelectedResolutionUnavailable::IncompleteParsedBlob {
                        storage_language,
                        persisted_relative_path,
                    },
                )));
            }
            let Some(interior_language) = row.get::<_, Option<String>>(12)? else {
                return Ok(Some(StagedSelection::Unavailable(
                    SelectedResolutionUnavailable::MissingInterior {
                        storage_language,
                        persisted_relative_path,
                    },
                )));
            };
            let semantic_text: String = row.get(13)?;
            let producer_epoch: String = row.get(14)?;
            let interior_digest = parse_digest_blob(row.get(15)?, "interior digest")?;
            let publication_state: String = row.get(16)?;
            if publication_state != "complete" {
                return Ok(Some(StagedSelection::Unavailable(
                    SelectedResolutionUnavailable::IncompleteInterior {
                        storage_language,
                        persisted_relative_path,
                    },
                )));
            }
            if interior_language != storage_language {
                return Err(StoreError::new(format!(
                    "resolution interior storage language {:?} disagrees with blob language \
                     {storage_language:?} at {persisted_relative_path}",
                    interior_language
                )));
            }
            if semantic_text != authority.semantic_language.config_label()
                || producer_epoch != authority.expected_producer_epoch
            {
                return Ok(Some(StagedSelection::Unavailable(
                    SelectedResolutionUnavailable::InteriorOwnershipMismatch {
                        storage_language,
                        persisted_relative_path,
                    },
                )));
            }
            if workspace_id != authority.workspace_id
                || revision != authority.revision
                || generation != authority.generation
            {
                return Err(StoreError::new(format!(
                    "selected workspace view disagrees with authority for {}",
                    authority.storage_language
                )));
            }
            let logical_rows = nonnegative_u64(row.get(17)?, "resolution logical rows")?;
            let payload_bytes = nonnegative_u64(row.get(18)?, "resolution payload bytes")?;
            let mut counts = [0_u64; RESOLUTION_MANIFEST_COUNT_COLUMNS.len()];
            for (index, count) in counts.iter_mut().enumerate() {
                *count = nonnegative_u64(row.get(19 + index)?, "resolution manifest count")?;
            }
            let workspace_digest = parse_digest_text(&workspace_id, "workspace identity")?;
            let projection_digest = parse_digest_text(&projection_text, "projection digest")?;
            let blob_oid = parse_oid(&blob_oid_text, "selected blob OID")?;
            let fragment_digest = selected_resolution_fragment_id(
                workspace_digest,
                &storage_language,
                &persisted_relative_path,
                projection_digest,
                interior_digest,
            );
            mounts.push(SelectedResolutionMountRecord {
                ordinal: SelectedResolutionMountOrdinal::new(0),
                fragment_digest,
                workspace_id,
                revision,
                generation,
                file_version_id: Some(file_version_id),
                storage_language,
                semantic_language: authority.semantic_language,
                persisted_relative_path,
                blob_id,
                blob_oid,
                projection_digest,
                interior_digest,
                producer_epoch,
                manifest_counts: ResolutionManifestCounts::from_array(counts),
                logical_rows,
                payload_bytes,
            });
        }
        if cancellation.is_cancelled() {
            return Ok(Some(StagedSelection::Cancelled));
        }
        if page_rows < SELECTED_MOUNT_PAGE_ROWS {
            break;
        }
        cursor = page_cursor;
    }
    if cancellation.is_cancelled() {
        Ok(Some(StagedSelection::Cancelled))
    } else {
        Ok(None)
    }
}

fn read_selected_content_mounts(
    conn: &Connection,
    authorities: &[SelectedLanguageAuthority],
    overlay_masks: &[SelectedResolutionOverlayMaskState],
    cancellation: &CancellationToken,
    mounts: &mut Vec<SelectedResolutionMountRecord>,
) -> Result<Option<StagedSelection>> {
    let mut mounted_paths = HashSet::default();
    for mount in mounts.iter() {
        if cancellation.is_cancelled() {
            return Ok(Some(StagedSelection::Cancelled));
        }
        mounted_paths.insert((
            mount.storage_language().to_owned(),
            mount.persisted_relative_path().to_owned(),
        ));
    }
    let masks_by_key = overlay_masks
        .iter()
        .map(|mask| {
            (
                (
                    mask.storage_language.as_str(),
                    mask.persisted_relative_path.as_str(),
                ),
                mask,
            )
        })
        .collect::<HashMap<_, _>>();
    let mut statement = conn.prepare_cached(selected_content_mount_status_sql())?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        if cancellation.is_cancelled() {
            return Ok(Some(StagedSelection::Cancelled));
        }
        let storage_language: String = row.get(0)?;
        let generation: i64 = row.get(1)?;
        let persisted_relative_path: String = row.get(2)?;
        let blob_oid_text: String = row.get(3)?;
        let projection_digest = parse_digest_blob(row.get(4)?, "content mount projection digest")?;
        let Some(authority) = authorities
            .iter()
            .find(|authority| authority.storage_language == storage_language)
        else {
            return Err(StoreError::new(format!(
                "content mount names unselected storage language {storage_language:?}"
            )));
        };
        let Some(mask) =
            masks_by_key.get(&(storage_language.as_str(), persisted_relative_path.as_str()))
        else {
            return Ok(Some(StagedSelection::Unavailable(
                SelectedResolutionUnavailable::MissingTransientOverlayInput {
                    storage_language,
                    persisted_relative_path,
                },
            )));
        };
        if mask.intent != SelectedResolutionOverlayIntent::Replacement {
            return Err(StoreError::new(format!(
                "content mount requires a replacement mask at {storage_language}/{persisted_relative_path}"
            )));
        }
        if generation != authority.generation {
            return Ok(Some(StagedSelection::Stale(
                SelectedResolutionStale::AnalysisGeneration { storage_language },
            )));
        }
        let Some(blob_id) = row.get::<_, Option<i64>>(5)? else {
            return Ok(Some(StagedSelection::Unavailable(
                SelectedResolutionUnavailable::MissingBlob {
                    storage_language,
                    persisted_relative_path,
                },
            )));
        };
        if row.get::<_, Option<i64>>(6)? != Some(generation) {
            return Ok(Some(StagedSelection::Unavailable(
                SelectedResolutionUnavailable::BlobGenerationMismatch {
                    storage_language,
                    persisted_relative_path,
                },
            )));
        }
        if row.get::<_, Option<i64>>(7)? != Some(1) {
            return Ok(Some(StagedSelection::Unavailable(
                SelectedResolutionUnavailable::IncompleteParsedBlob {
                    storage_language,
                    persisted_relative_path,
                },
            )));
        }
        let Some(interior_language) = row.get::<_, Option<String>>(8)? else {
            return Ok(Some(StagedSelection::Unavailable(
                SelectedResolutionUnavailable::MissingInterior {
                    storage_language,
                    persisted_relative_path,
                },
            )));
        };
        let semantic_text: String = row.get(9)?;
        let producer_epoch: String = row.get(10)?;
        let interior_digest = parse_digest_blob(row.get(11)?, "content mount interior digest")?;
        let publication_state: String = row.get(12)?;
        if publication_state != "complete" {
            return Ok(Some(StagedSelection::Unavailable(
                SelectedResolutionUnavailable::IncompleteInterior {
                    storage_language,
                    persisted_relative_path,
                },
            )));
        }
        if interior_language != storage_language
            || semantic_text != authority.semantic_language.config_label()
            || producer_epoch != authority.expected_producer_epoch
        {
            return Ok(Some(StagedSelection::Unavailable(
                SelectedResolutionUnavailable::InteriorOwnershipMismatch {
                    storage_language,
                    persisted_relative_path,
                },
            )));
        }
        if !mounted_paths.insert((storage_language.clone(), persisted_relative_path.clone())) {
            return Err(StoreError::new(format!(
                "content mount path remains in the unmasked selected inventory at {storage_language}/{persisted_relative_path}"
            )));
        }
        let logical_rows = nonnegative_u64(row.get(13)?, "resolution logical rows")?;
        let payload_bytes = nonnegative_u64(row.get(14)?, "resolution payload bytes")?;
        let mut counts = [0_u64; RESOLUTION_MANIFEST_COUNT_COLUMNS.len()];
        for (index, count) in counts.iter_mut().enumerate() {
            *count = nonnegative_u64(row.get(15 + index)?, "resolution manifest count")?;
        }
        let workspace_digest = parse_digest_text(&authority.workspace_id, "workspace identity")?;
        let blob_oid = parse_oid(&blob_oid_text, "content mount blob OID")?;
        let fragment_digest = selected_resolution_fragment_id(
            workspace_digest,
            &storage_language,
            &persisted_relative_path,
            projection_digest,
            interior_digest,
        );
        mounts.push(SelectedResolutionMountRecord {
            ordinal: SelectedResolutionMountOrdinal::new(0),
            fragment_digest,
            workspace_id: authority.workspace_id.clone(),
            revision: authority.revision,
            generation,
            file_version_id: None,
            storage_language,
            semantic_language: authority.semantic_language,
            persisted_relative_path,
            blob_id,
            blob_oid,
            projection_digest,
            interior_digest,
            producer_epoch,
            manifest_counts: ResolutionManifestCounts::from_array(counts),
            logical_rows,
            payload_bytes,
        });
    }
    if cancellation.is_cancelled() {
        Ok(Some(StagedSelection::Cancelled))
    } else {
        Ok(None)
    }
}

#[doc(hidden)]
pub fn persist_selected_inventory(
    tx: &Transaction<'_>,
    staged: &StagedReadySelection,
    cancellation: &CancellationToken,
) -> Result<bool> {
    debug_assert_eq!(
        tx.query_row(
            "SELECT count(*) FROM temp.selected_rust_container_placements",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0,
        "selected mounts must be installed before materializing module placements"
    );
    {
        let mut update = tx.prepare_cached(
            "UPDATE temp.selected_resolution_languages
             SET expected_base_mount_count = ?2,
                 masked_base_mount_count = ?3,
                 expected_unmasked_mount_count = ?4
             WHERE storage_language = ?1",
        )?;
        for language in &staged.languages {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            update.execute(params![
                language.storage_language,
                usize_to_i64(language.expected_base_mount_count)?,
                usize_to_i64(language.masked_base_mount_count)?,
                usize_to_i64(language.expected_unmasked_mount_count)?,
            ])?;
        }
    }
    {
        let mut update = tx.prepare_cached(
            "UPDATE temp.selected_resolution_overlay_masks
             SET masked_file_version_id = ?3,
                 masked_blob_oid = ?4,
                 masked_projection_digest = ?5,
                 expected_transient_replacement_count = ?6
             WHERE storage_language = ?1 AND persisted_relative_path = ?2",
        )?;
        for mask in &staged.overlay_masks {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            update.execute(params![
                mask.storage_language,
                mask.persisted_relative_path,
                mask.masked_base.as_ref().map(|base| base.file_version_id),
                mask.masked_base
                    .as_ref()
                    .map(|base| base.blob_oid.to_string()),
                mask.masked_base
                    .as_ref()
                    .map(|base| base.projection_digest.as_slice()),
                i64::from(mask.expected_transient_replacement_count),
            ])?;
        }
    }
    let count_columns = RESOLUTION_MANIFEST_COUNT_COLUMNS.join(", ");
    const FIXED_MOUNT_COLUMN_COUNT: usize = 16;
    let mount_column_count = FIXED_MOUNT_COLUMN_COUNT + RESOLUTION_MANIFEST_COUNT_COLUMNS.len();
    let placeholders = (1..=mount_column_count)
        .map(|index| format!("?{index}"))
        .collect::<Vec<_>>()
        .join(", ");
    let insert_sql = format!(
        "INSERT INTO temp.selected_resolution_mounts(
           mount_ordinal, fragment_id, workspace_id, revision, generation,
           file_version_id, storage_language, semantic_language,
           persisted_relative_path, blob_id, blob_oid, projection_digest,
           interior_digest, producer_epoch, logical_rows, payload_bytes,
           {count_columns}
         ) VALUES({placeholders})"
    );
    let mut insert = tx.prepare_cached(&insert_sql)?;
    for mount in &staged.mounts {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let mut values = Vec::with_capacity(mount_column_count);
        values.extend([
            Value::Integer(i64::from(mount.ordinal.get())),
            Value::Blob(mount.fragment_digest.as_bytes().to_vec()),
            Value::Text(mount.workspace_id.clone()),
            Value::Integer(mount.revision),
            Value::Integer(mount.generation),
            match mount.file_version_id {
                Some(file_version_id) => Value::Integer(file_version_id),
                None => Value::Null,
            },
            Value::Text(mount.storage_language.clone()),
            Value::Text(mount.semantic_language.config_label().to_owned()),
            Value::Text(mount.persisted_relative_path.clone()),
            Value::Integer(mount.blob_id),
            Value::Text(mount.blob_oid.to_string()),
            Value::Blob(mount.projection_digest.to_vec()),
            Value::Blob(mount.interior_digest.to_vec()),
            Value::Text(mount.producer_epoch.clone()),
            Value::Integer(u64_to_i64(mount.logical_rows, "resolution logical rows")?),
            Value::Integer(u64_to_i64(mount.payload_bytes, "resolution payload bytes")?),
        ]);
        for &count in mount.manifest_counts.values() {
            values.push(Value::Integer(u64_to_i64(
                count,
                "resolution manifest count",
            )?));
        }
        assert_eq!(
            values.len(),
            mount_column_count,
            "selected mount values must match their dynamic manifest columns"
        );
        insert.execute(params_from_iter(values))?;
    }
    tx.execute_batch(RESET_SELECTED_RESOLUTION_SCOPE_SQL)?;
    // Selection completion: revisions, overlay masks, and every persisted or
    // content mount are installed. Consumers only change request/stage rows;
    // changed inputs acquire a new selection, and retained reuse validates its
    // TEMP input rows and main-store change stamp before serving them.
    tx.execute_batch(
        super::resolution_operation::rust_crate_context::SELECTED_MODULE_PLACEMENTS_FILL_SQL,
    )?;
    tx.execute_batch(SELECTED_MOUNT_GUARDS_SQL)?;
    Ok(!cancellation.is_cancelled())
}

fn selection_fingerprint(
    workspace_id: &str,
    languages: &[SelectedResolutionLanguageState],
    masks: &[SelectedResolutionOverlayMaskState],
    mounts: &[SelectedResolutionMountRecord],
    cancellation: &CancellationToken,
) -> Option<[u8; 32]> {
    let mut hasher = CanonicalHasher::new(b"bifrost-selected-resolution-inventory:v1");
    hasher.field("workspace_id", workspace_id.as_bytes());
    hasher.field(
        "language_count",
        &usize_as_u64(languages.len()).to_be_bytes(),
    );
    for language in languages {
        if cancellation.is_cancelled() {
            return None;
        }
        hasher.field("storage_language", language.storage_language.as_bytes());
        hasher.field(
            "semantic_language",
            language.semantic_language.config_label().as_bytes(),
        );
        hasher.field("workspace_id", language.workspace_id.as_bytes());
        hasher.field("generation", &language.generation.to_be_bytes());
        hasher.field("revision", &language.revision.to_be_bytes());
        hasher.field(
            "expected_base_mount_count",
            &usize_as_u64(language.expected_base_mount_count).to_be_bytes(),
        );
        hasher.field(
            "masked_base_mount_count",
            &usize_as_u64(language.masked_base_mount_count).to_be_bytes(),
        );
        hasher.field(
            "expected_unmasked_mount_count",
            &usize_as_u64(language.expected_unmasked_mount_count).to_be_bytes(),
        );
    }
    hasher.field(
        "overlay_mask_count",
        &usize_as_u64(masks.len()).to_be_bytes(),
    );
    for mask in masks {
        if cancellation.is_cancelled() {
            return None;
        }
        hasher.field("storage_language", mask.storage_language.as_bytes());
        hasher.field("relative_path", mask.persisted_relative_path.as_bytes());
        hasher.field("intent", mask.intent.as_str().as_bytes());
        if let Some(base) = &mask.masked_base {
            hasher.field(
                "masked_file_version_id",
                &base.file_version_id.to_be_bytes(),
            );
            hasher.field("masked_blob_oid", base.blob_oid.as_bytes());
            hasher.field("masked_projection_digest", &base.projection_digest);
        }
        hasher.field(
            "expected_transient_replacement_count",
            &mask.expected_transient_replacement_count.to_be_bytes(),
        );
    }
    hasher.field("mount_count", &usize_as_u64(mounts.len()).to_be_bytes());
    for mount in mounts {
        if cancellation.is_cancelled() {
            return None;
        }
        // Placement ordinals are selection-local aliases. The content digest
        // and placement fields below already identify this mount completely.
        hasher.field("fragment_id", &mount.fragment_digest.as_bytes());
        hasher.field("workspace_id", mount.workspace_id.as_bytes());
        hasher.field("revision", &mount.revision.to_be_bytes());
        hasher.field("generation", &mount.generation.to_be_bytes());
        match mount.file_version_id {
            Some(file_version_id) => {
                hasher.field("file_version_id", &file_version_id.to_be_bytes())
            }
            None => hasher.field("content_mount_origin", b"cached_blob"),
        };
        hasher.field("storage_language", mount.storage_language.as_bytes());
        hasher.field(
            "semantic_language",
            mount.semantic_language.config_label().as_bytes(),
        );
        hasher.field("relative_path", mount.persisted_relative_path.as_bytes());
        hasher.field("blob_id", &mount.blob_id.to_be_bytes());
        hasher.field("blob_oid", mount.blob_oid.as_bytes());
        hasher.field("projection_digest", &mount.projection_digest);
        hasher.field("interior_digest", &mount.interior_digest);
        hasher.field("producer_epoch", mount.producer_epoch.as_bytes());
        for &count in mount.manifest_counts.values() {
            hasher.field("manifest_count", &count.to_be_bytes());
        }
        hasher.field("logical_rows", &mount.logical_rows.to_be_bytes());
        hasher.field("payload_bytes", &mount.payload_bytes.to_be_bytes());
    }
    if cancellation.is_cancelled() {
        None
    } else {
        Some(hasher.finish())
    }
}

fn parse_digest_text(value: &str, label: &str) -> Result<[u8; 32]> {
    parse_lower_sha256(value)
        .ok_or_else(|| StoreError::new(format!("invalid lower-hex {label}: {value:?}")))
}

fn parse_digest_blob(value: Vec<u8>, label: &str) -> Result<[u8; 32]> {
    value.try_into().map_err(|value: Vec<u8>| {
        StoreError::new(format!("invalid {label} length {}", value.len()))
    })
}

fn parse_oid(value: &str, label: &str) -> Result<Oid> {
    Oid::from_str(value).map_err(|error| StoreError::new(format!("invalid {label}: {error}")))
}

fn nonnegative_u64(value: i64, label: &str) -> Result<u64> {
    u64::try_from(value).map_err(|_| StoreError::new(format!("negative {label}: {value}")))
}

fn usize_to_i64(value: usize) -> Result<i64> {
    crate::analyzer::store::sqlite_integer(value)
        .ok_or_else(|| StoreError::new("selected resolution count exceeds SQLite integer"))
}

fn u64_to_i64(value: u64, label: &str) -> Result<i64> {
    crate::analyzer::store::sqlite_integer(value)
        .ok_or_else(|| StoreError::new(format!("{label} exceeds SQLite integer")))
}

fn usize_as_u64(value: usize) -> u64 {
    u64::try_from(value).expect("usize fits u64 on supported targets")
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod tests {

    use super::*;

    #[cfg(test)]
    use brokk_bifrost_test_macros::hardwon;

    // A real published store mount with one catalog-backed qualifier. Key 1
    // represents the gap-reason suffix retained only in a completion, with no
    // active resolution_gap_reasons row, as in #6597.
    #[cfg(test)]
    pub(crate) fn qualifier_completion_gap_fixture()
    -> (AnalyzerStore, WorkspaceId, WorkspaceSnapshots) {
        qualifier_completion_gap_fixture_in(AnalyzerStore::open_ephemeral().unwrap())
    }

    #[cfg(test)]
    fn qualifier_completion_gap_fixture_in(
        store: AnalyzerStore,
    ) -> (AnalyzerStore, WorkspaceId, WorkspaceSnapshots) {
        use super::super::resolution::{
            PreparedResolutionBundle, PreparedResolutionBundleRows, PreparedResolutionRow,
            PreparedResolutionValue, insert_prepared_bundle_tx,
        };
        let generation = store
            .ensure_language_epoch_value("go", "6597-test")
            .unwrap();
        store
            .ensure_resolution_producer_epoch("go", Language::Go)
            .unwrap();
        let oid = Oid::from_str("0000000000000000000000000000000000000001").unwrap();
        store.register_blobs(&[oid], "go", generation).unwrap();
        let mut rows = PreparedResolutionBundleRows::default();
        rows.semantic_catalog.push(PreparedResolutionRow::new(vec![
            0_i64.into(),
            [1_u8; 32].into(),
            PreparedResolutionValue::Null,
            PreparedResolutionValue::Null,
            PreparedResolutionValue::Null,
            PreparedResolutionValue::Null,
            PreparedResolutionValue::Null,
        ]));
        let bundle = PreparedResolutionBundle::new(
            Language::Go,
            rows,
            Default::default(),
            Vec::new(),
            Default::default(),
            Vec::new(),
            Default::default(),
            Vec::new(),
            &CancellationToken::new(),
        )
        .unwrap();
        let workspace_id = WorkspaceId("a".repeat(64));
        let writer_workspace = workspace_id.0.clone();
        store.conn.execute(move |conn| {
            let tx = conn.transaction().unwrap();
            let blob_id = tx.query_row("SELECT id FROM blobs WHERE blob_oid=?1 AND lang='go'", [oid.to_string()], |row| row.get::<_, i64>(0)).unwrap();
            tx.execute("INSERT INTO blob_meta(blob_id,lang,contains_tests,content_package,stored_unit_count,range_count,signature_count,signature_metadata_count,supertype_count,child_count,import_statement_count,type_identifier_count,is_complete) VALUES(?1,'go',0,'',0,0,0,0,0,0,0,0,1)", [blob_id]).unwrap();
            assert!(insert_prepared_bundle_tx(&tx, blob_id, "go", &bundle, &CancellationToken::new()).unwrap());
            tx.execute("INSERT INTO workspace_revisions(workspace_id,lang,generation,revision) VALUES(?1,'go',?2,1)", params![writer_workspace, generation.0]).unwrap();
            tx.execute("INSERT INTO workspace_heads(workspace_id,lang,generation,revision) VALUES(?1,'go',?2,1)", params![writer_workspace, generation.0]).unwrap();
            tx.execute("INSERT INTO workspace_file_versions(workspace_id,lang,generation,rel_path,blob_oid,projection_digest,valid_from) VALUES(?1,'go',?2,'fixture.go',?3,?4,1)", params![writer_workspace, generation.0, oid.to_string(), "b".repeat(64)]).unwrap();
            tx.commit().unwrap();
        });
        let snapshots = WorkspaceSnapshots::from_iter([(
            "go".to_owned(),
            super::super::WorkspaceSnapshotId {
                workspace_id: workspace_id.clone(),
                lang: "go".to_owned(),
                generation,
                revision: 1,
            },
        )]);
        (store, workspace_id, snapshots)
    }

    #[test]
    fn stage_family_occupancy_tracks_scope_epochs_and_transaction_boundaries() {
        use super::super::resolution_stage::StageFamily;

        let (store, workspace, snapshots) = qualifier_completion_gap_fixture();
        let cancellation = CancellationToken::new();
        let languages = [SelectedResolutionLanguage::new("go", Language::Go)];
        let SelectedResolutionMountInventoryOutcome::Ready(mut selection) = store
            .open_selected_resolution_mount_inventory(
                &workspace,
                &snapshots,
                &languages,
                &[],
                &cancellation,
            )
            .unwrap()
        else {
            panic!("published fixture must open a selected inventory");
        };
        selection.begin_operation_reads();
        let family = StageFamily::TypeFrontiers;
        assert!(selection.stage_family_is_empty(family).unwrap());
        assert!(selection.stage_family_is_globally_empty(family).unwrap());

        // Force the SQL path, then prove repeated absence uses its one entry.
        selection.note_stage_content_commit();
        assert!(selection.stage_family_is_empty(family).unwrap());
        assert_eq!(selection.stage_family_occupancy.borrow().families.len(), 1);
        assert!(selection.stage_family_is_globally_empty(family).unwrap());
        assert_eq!(selection.stage_family_occupancy.borrow().families.len(), 1);

        let host: u32 = selection
            .connection()
            .query_row(
                "SELECT mount_ordinal FROM temp.selected_resolution_scope_mounts LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        // The write errors after inserting content. Its direct epoch must
        // invalidate the empty answer despite the failed accounting closure.
        let failed: Result<()> = selection.with_owned_temp_write(|connection| {
            connection.execute(
                "INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(?1,zeroblob(32),zeroblob(32))", [host],
            )?;
            connection.execute(
                "INSERT INTO temp.selected_resolution_stage_type_frontiers(host_ordinal,producer_id,sequence,slot_key,role) VALUES(?1,last_insert_rowid(),0,0,0)", [host],
            )?;
            Err(StoreError::new("failure after stage content write"))
        });
        assert!(failed.is_err());
        assert!(!selection.stage_family_is_empty(family).unwrap());
        assert!(!selection.stage_family_is_globally_empty(family).unwrap());

        selection
            .with_owned_temp_write(|connection| {
                connection.execute("DELETE FROM temp.selected_resolution_scope_mounts", [])?;
                Ok(())
            })
            .unwrap();
        selection.note_scope_narrowed(&[[1; 32]]);
        assert!(selection.stage_family_is_empty(family).unwrap());
        assert!(!selection.stage_family_is_globally_empty(family).unwrap());
        selection.reset_scope_mounts().unwrap();
        assert!(!selection.stage_family_is_empty(family).unwrap());

        // Owned TEMP DDL and transaction boundaries clear the same inventory
        // as the stamp memo, even when neither staged read epoch moved.
        let epochs = selection.staged_read_epoch();
        selection
            .initialize_owned_temp_schema(
                selection.connection(),
                "CREATE TEMP TABLE occupancy_ddl_probe(value)",
            )
            .unwrap();
        assert_eq!(selection.staged_read_epoch(), epochs);
        assert!(
            selection
                .stage_family_occupancy
                .borrow()
                .families
                .is_empty()
        );
        assert!(!selection.stage_family_is_empty(family).unwrap());
        selection.begin_stage_read().unwrap();
        assert!(
            selection
                .stage_family_occupancy
                .borrow()
                .families
                .is_empty()
        );
        assert!(!selection.stage_family_is_empty(family).unwrap());
        selection.pause_stage_read().unwrap();
        assert!(
            selection
                .stage_family_occupancy
                .borrow()
                .families
                .is_empty()
        );
        selection.resume_stage_read().unwrap();
        assert!(!selection.stage_family_is_empty(family).unwrap());
        selection.end_stage_read().unwrap();
        assert!(
            selection
                .stage_family_occupancy
                .borrow()
                .families
                .is_empty()
        );

        selection
            .with_owned_temp_write(|connection| {
                connection.execute("DELETE FROM temp.selected_resolution_stage_producers", [])?;
                Ok(())
            })
            .unwrap();
        assert!(selection.stage_family_is_globally_empty(family).unwrap());
        // Exercise the content epoch independently of the direct epoch.
        selection.with_owned_temp_transaction(|connection| {
            connection.execute(
                "INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(?1,zeroblob(32),zeroblob(32))", [host],
            )?;
            connection.execute(
                "INSERT INTO temp.selected_resolution_stage_type_frontiers(host_ordinal,producer_id,sequence,slot_key,role) VALUES(?1,last_insert_rowid(),0,0,0)", [host],
            )?;
            Ok(SelectedResolutionTempTransaction::Commit(()))
        }).unwrap();
        selection.note_stage_content_commit();
        assert!(!selection.stage_family_is_empty(family).unwrap());
    }

    #[test]
    fn operation_stamp_follows_stage_epochs_and_failed_temp_writes() {
        let (store, workspace, snapshots) = qualifier_completion_gap_fixture();
        let cancellation = CancellationToken::new();
        let languages = [SelectedResolutionLanguage::new("go", Language::Go)];
        let SelectedResolutionMountInventoryOutcome::Ready(mut selection) = store
            .open_selected_resolution_mount_inventory(
                &workspace,
                &snapshots,
                &languages,
                &[],
                &cancellation,
            )
            .unwrap()
        else {
            panic!("published fixture must open a selected inventory");
        };
        assert!(selection.operation_change_stamp.is_none());
        selection.begin_operation_reads();
        let initial = selection.operation_workspace_stamp().unwrap();
        assert_eq!(selection.operation_workspace_stamp().unwrap(), initial);
        assert!(
            selection
                .operation_change_stamp
                .as_ref()
                .unwrap()
                .get()
                .is_some()
        );

        // A writer publication becomes visible at the content-commit epoch.
        store.conn.execute(|conn| {
            conn.execute_batch("CREATE TABLE selected_stamp_publication_probe(value INTEGER)")
                .unwrap();
        });
        selection.note_stage_content_commit();
        let published = selection.operation_workspace_stamp().unwrap();
        assert_ne!(published.main_data_version, initial.main_data_version);
        assert_eq!(
            selection
                .operation_change_stamp
                .as_ref()
                .unwrap()
                .get()
                .unwrap()
                .stage,
            selection.staged_read_epoch()
        );

        // DDL can succeed before a later statement fails. The direct-write
        // epoch moves before the closure runs, so its old witness cannot hit.
        let failed: Result<()> = selection.with_owned_temp_write(|conn| {
            conn.execute_batch(
                "CREATE TEMP TABLE stamp_failure_probe(value); SELECT * FROM absent_stamp_table",
            )?;
            Ok(())
        });
        assert!(failed.is_err());
        let after_failure = selection.operation_workspace_stamp().unwrap();
        assert_ne!(
            after_failure.temp_schema_version,
            published.temp_schema_version
        );

        // Private schema initialization uses accounting rather than the
        // direct-write epoch, but the raw TEMP schema witness must refresh.
        let stage = selection.staged_read_epoch();
        selection
            .initialize_owned_temp_schema(
                selection.connection(),
                "CREATE TEMP TABLE stamp_owned_probe(value)",
            )
            .unwrap();
        assert_eq!(selection.staged_read_epoch(), stage);
        let after_schema = selection.operation_workspace_stamp().unwrap();
        assert_ne!(
            after_schema.temp_schema_version,
            after_failure.temp_schema_version
        );

        // Rolled-back private writes still count as attempted writes. The
        // pragma memo must not freeze this independent, in-memory witness.
        let before_rollback = selection.read_change_stamp().unwrap();
        selection
            .with_owned_temp_transaction(|conn| {
                conn.execute("INSERT INTO stamp_owned_probe VALUES(1)", [])?;
                Ok(SelectedResolutionTempTransaction::Rollback(()))
            })
            .unwrap();
        assert_eq!(
            selection.read_change_stamp().unwrap().unowned_changes,
            before_rollback.unowned_changes + 1
        );

        // Finishing an operation always checks external commits afresh.
        store.conn.execute(|conn| {
            conn.execute("INSERT INTO selected_stamp_publication_probe VALUES(1)", [])
                .unwrap();
        });
        assert!(matches!(
            selection.revalidate(&cancellation).unwrap(),
            SelectedResolutionRevalidationOutcome::Current
        ));
        assert!(
            selection
                .operation_change_stamp
                .as_ref()
                .unwrap()
                .get()
                .is_none()
        );
        assert_ne!(
            selection
                .operation_workspace_stamp()
                .unwrap()
                .main_data_version,
            after_schema.main_data_version
        );
    }

    #[cfg(test)]
    #[test]
    fn scoped_query_plans_restore_writer_fallback_after_success_and_error() {
        use rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_QPSG;

        let store = AnalyzerStore::open_in_memory_single_connection().unwrap();
        for previous in [false, true] {
            store
                .active_read_conn()
                .unwrap()
                .set_db_config(SQLITE_DBCONFIG_ENABLE_QPSG, previous)
                .unwrap();
            {
                let mut conn = store.active_read_conn().unwrap();
                conn.stabilize_query_plans().unwrap();
                assert!(conn.db_config(SQLITE_DBCONFIG_ENABLE_QPSG).unwrap());
            }
            assert_eq!(
                store
                    .active_read_conn()
                    .unwrap()
                    .db_config(SQLITE_DBCONFIG_ENABLE_QPSG)
                    .unwrap(),
                previous
            );
            let failure = (|| -> Result<()> {
                let mut conn = store.active_read_conn()?;
                conn.stabilize_query_plans()?;
                conn.execute_batch("SELECT * FROM absent_planner_lifecycle_table")?;
                Ok(())
            })();
            assert!(failure.is_err(), "the SQL error must propagate");
            assert_eq!(
                store
                    .active_read_conn()
                    .unwrap()
                    .db_config(SQLITE_DBCONFIG_ENABLE_QPSG)
                    .unwrap(),
                previous,
                "a failed read must restore the writer's planner configuration"
            );
        }
    }

    /// A token that cancels itself as soon as its holder starts to wait for
    /// the writer, so the wait it observes is the one being tested.
    #[cfg(test)]
    fn cancelled_on_writer_wait() -> CancellationToken {
        let token = CancellationToken::new();
        let canceller = token.clone();
        token.with_phase_sink(move |phase| {
            assert_eq!(phase, super::super::writer::WRITER_WAIT_PHASE);
            canceller.cancel();
        })
    }

    #[cfg(test)]
    #[test]
    #[hardwon(
        "#6018: writer-only waits for the selected writer ignored the request's cancellation"
    )]
    fn writer_only_waits_for_the_writer_observe_cancellation() {
        let (store, workspace, snapshots) = qualifier_completion_gap_fixture_in(
            AnalyzerStore::open_in_memory_single_connection().unwrap(),
        );
        let languages = [SelectedResolutionLanguage::new("go", Language::Go)];
        let open = |cancellation: &CancellationToken| {
            store
                .open_selected_resolution_mount_inventory(
                    &workspace,
                    &snapshots,
                    &languages,
                    &[],
                    cancellation,
                )
                .unwrap()
        };
        let SelectedResolutionMountInventoryOutcome::Ready(mut selection) =
            open(&CancellationToken::new())
        else {
            panic!("published fixture must open a selected inventory");
        };
        selection.lend_writer().unwrap();
        std::thread::scope(|scope| {
            let (held, wait_until_held) = std::sync::mpsc::channel();
            let (release, wait_for_release) = std::sync::mpsc::channel::<()>();
            let writer = &store.conn;
            let holder = scope.spawn(move || {
                let _writer = writer.lock().unwrap();
                held.send(()).unwrap();
                wait_for_release.recv().unwrap();
            });
            wait_until_held.recv().unwrap();
            // Only the wait's phase cancels these tokens, so each outcome is
            // a wait that stopped while the other thread held the writer.
            let opener = cancelled_on_writer_wait();
            assert!(matches!(
                open(&opener),
                SelectedResolutionMountInventoryOutcome::Cancelled
            ));
            assert!(opener.is_cancelled() && opener.phase().is_none());
            let operation = cancelled_on_writer_wait();
            assert_eq!(
                selection.reclaim_writer(&operation).unwrap(),
                SelectedResolutionRevalidationOutcome::Cancelled
            );
            assert!(operation.is_cancelled() && operation.phase().is_none());
            release.send(()).unwrap();
            holder.join().unwrap();
        });
        // The other thread wrote nothing, so the lent selection is still the
        // operation's authority.
        let cancellation = CancellationToken::new();
        assert_eq!(
            selection.reclaim_writer(&cancellation).unwrap(),
            SelectedResolutionRevalidationOutcome::Current
        );
        assert_eq!(
            selection.revalidate(&cancellation).unwrap(),
            SelectedResolutionRevalidationOutcome::Current
        );
    }

    #[cfg(test)]
    #[test]
    fn lent_writer_selection_survives_ordinary_reads_but_not_another_selection() {
        let (store, workspace, snapshots) = qualifier_completion_gap_fixture_in(
            AnalyzerStore::open_in_memory_single_connection().unwrap(),
        );
        let languages = [SelectedResolutionLanguage::new("go", Language::Go)];
        let cancellation = CancellationToken::new();
        let open = || {
            let SelectedResolutionMountInventoryOutcome::Ready(selection) = store
                .open_selected_resolution_mount_inventory(
                    &workspace,
                    &snapshots,
                    &languages,
                    &[],
                    &cancellation,
                )
                .unwrap()
            else {
                panic!("published fixture must open a selected inventory");
            };
            selection
        };
        let retained = || store.writer_resolution_selection.lock().unwrap().is_some();
        let revisions = |selection: &SelectedResolutionMountInventory<'_>| {
            selection
                .connection()
                .prepare("SELECT revision FROM temp.selected_workspace_revisions")
                .unwrap()
                .query_map([], |row| row.get::<_, i64>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        let mut other = snapshots.clone();
        other.get_mut("go").unwrap().revision += 1;

        // Ordinary reads share the selection's revision rows. A read of its own
        // snapshots leaves them as they are; a read of other snapshots replaces
        // them, and the selection restores them when it takes the connection
        // back.
        let mut selection = open();
        selection.lend_writer().unwrap();
        drop(store.read_conn_for_workspace(&snapshots).unwrap());
        drop(store.read_conn_for_workspace(&other).unwrap());
        assert_eq!(
            selection.reclaim_writer(&cancellation).unwrap(),
            SelectedResolutionRevalidationOutcome::Current
        );
        assert_eq!(revisions(&selection), [1]);
        assert_eq!(
            selection.revalidate(&cancellation).unwrap(),
            SelectedResolutionRevalidationOutcome::Current
        );
        drop(selection);
        assert!(retained(), "a restored selection is retained");

        // Another selection staged over the lent one replaces rows that
        // ordinary reads never write. The lent operation is stale from then on,
        // and its connection stays lent so the caller can still read.
        let mut selection = open();
        selection.lend_writer().unwrap();
        drop(open());
        assert!(retained(), "the other selection retains its own rows");
        let stale = SelectedResolutionRevalidationOutcome::Stale(
            SelectedResolutionStale::LentWriterChanged,
        );
        assert_eq!(selection.reclaim_writer(&cancellation).unwrap(), stale);
        drop(store.read_conn_for_workspace(&other).unwrap());
        assert_eq!(selection.reclaim_writer(&cancellation).unwrap(), stale);
        selection.end_writer_loan().unwrap();
        assert_eq!(selection.revalidate(&cancellation).unwrap(), stale);
        // It clears the connection instead of returning its selection over
        // the other one.
        drop(selection);
        assert!(!retained());
        assert_eq!(revisions(&open()), [1]);
    }

    #[doc(hidden)]
    pub fn explain_plan(conn: &Connection, sql: &str, parameters: Vec<Value>) -> Vec<String> {
        crate::analyzer::store::planner_statistics::pinned_plans::plan_rows_for_sql(
            conn,
            sql,
            &parameters,
        )
        .unwrap()
    }

    #[doc(hidden)]
    pub fn required_plan_step(plan: &[String], label: &str, needles: &[&str]) -> usize {
        plan.iter()
            .position(|detail| needles.iter().all(|needle| detail.contains(needle)))
            .unwrap_or_else(|| panic!("{label} needs {needles:?}: {plan:#?}"))
    }

    #[doc(hidden)]
    pub fn assert_plan_order(plan: &[String], label: &str, steps: &[(&str, &[&str])]) {
        let mut previous = None;
        for (step_label, needles) in steps {
            let position = required_plan_step(plan, label, needles);
            if let Some((previous_label, previous_position)) = previous {
                assert!(
                    previous_position < position,
                    "{label} must drive {previous_label} before {step_label}: {plan:#?}"
                );
            }
            previous = Some((step_label, position));
        }
    }

    #[doc(hidden)]
    pub fn assert_plan_has_no_hazards(plan: &[String], label: &str, scan_aliases: &[&str]) {
        for hazard in ["AUTOMATIC", "MATERIALIZE", "CO-ROUTINE", "USE TEMP B-TREE"] {
            assert!(
                plan.iter().all(|detail| !detail.contains(hazard)),
                "{label} must not use {hazard}: {plan:#?}"
            );
        }
        for alias in scan_aliases {
            let scan = format!("SCAN {alias}");
            assert!(
                plan.iter().all(|detail| !detail.contains(&scan)),
                "{label} must seek {alias}, not scan it: {plan:#?}"
            );
        }
    }

    #[doc(hidden)]
    pub fn assert_workspace_snapshot_path_seek(plan: &[String], position: usize, label: &str) {
        let detail = &plan[position];
        assert!(
            detail.contains("idx_workspace_file_versions_snapshot_path")
                || detail.contains("idx_workspace_file_versions_snapshot_kind")
                || detail.contains("sqlite_autoindex_workspace_file_versions_1"),
            "{label} must use the snapshot-path index or its exact UNIQUE prefix: {plan:#?}"
        );
    }
}
