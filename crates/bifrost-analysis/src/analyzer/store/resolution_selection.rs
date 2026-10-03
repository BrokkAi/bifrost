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
    BindingFragmentId, MountRebaser, SelectedResolutionFragmentDigest,
    SelectedResolutionMountOrdinal, selected_resolution_fragment_id,
};
use crate::hash::{HashMap, HashSet};

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

#[cfg(test)]
thread_local! {
    static SELECTED_STATIC_SQL_CAPACITIES: std::cell::Cell<[usize; 17]> = const {
        std::cell::Cell::new([0; 17])
    };
}

#[cfg(test)]
pub(in crate::analyzer::store) fn note_selected_static_sql_capacity(index: usize, capacity: usize) {
    SELECTED_STATIC_SQL_CAPACITIES.with(|values| {
        let mut capacities = values.get();
        assert_eq!(capacities[index], 0, "static SQL initializes once");
        capacities[index] = capacity;
        values.set(capacities);
    });
}

#[cfg(test)]
pub(super) fn selected_static_sql_capacities() -> [(&'static str, usize); 17] {
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

fn selected_resolution_temp_schema_sql() -> &'static str {
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
             CREATE TEMP TABLE IF NOT EXISTS selected_resolution_typed_requests_1(
               mount_ordinal INTEGER NOT NULL CHECK(mount_ordinal >= 0),
               key0          INTEGER NOT NULL CHECK(key0 >= 0),
               PRIMARY KEY(mount_ordinal, key0)
             ) WITHOUT ROWID, STRICT;
             CREATE TEMP TABLE IF NOT EXISTS selected_resolution_typed_requests_2(
               mount_ordinal INTEGER NOT NULL CHECK(mount_ordinal >= 0),
               key0          INTEGER NOT NULL CHECK(key0 >= 0),
               key1          INTEGER NOT NULL CHECK(key1 >= 0),
               PRIMARY KEY(mount_ordinal, key0, key1)
             ) WITHOUT ROWID, STRICT;
             {module_placements_schema}",
            stage_schema = super::resolution_stage::schema_sql(),
            module_placements_schema = super::resolution_operation::rust_crate_context::SELECTED_MODULE_PLACEMENTS_SCHEMA_SQL,
            go_placements = super::resolution_operation::go_context::GO_TRANSIENT_PLACEMENTS_SQL,
        );
        #[cfg(test)]
        note_selected_static_sql_capacity(0, sql.capacity());
        sql
    })
}

const CLEAR_SELECTED_RESOLUTION_TEMP_SQL: &str = r#"
DELETE FROM temp.selected_resolution_stage_producers;
DELETE FROM temp.selected_resolution_stage_nodes;
DELETE FROM temp.selected_resolution_admissions;
DELETE FROM temp.selected_resolution_scope_mounts;
DELETE FROM temp.selected_resolution_mounts;
DELETE FROM temp.selected_resolution_typed_requests_1;
DELETE FROM temp.selected_resolution_typed_requests_2;
DELETE FROM temp.selected_resolution_overlay_masks;
DELETE FROM temp.selected_resolution_content_mounts;
DELETE FROM temp.selected_resolution_languages;
DELETE FROM temp.selected_resolution_context;
DELETE FROM temp.selected_workspace_revisions;
"#;

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

const SELECTED_LANGUAGE_AUTHORITY_SQL: &str = r#"
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

const SELECTED_MASK_PAGE_INITIAL_SQL: &str = r#"
SELECT masks.persisted_relative_path, masks.intent
FROM temp.selected_resolution_overlay_masks AS masks
WHERE masks.storage_language = ?1
ORDER BY masks.persisted_relative_path
LIMIT 256
"#;

const SELECTED_MASK_PAGE_CONTINUATION_SQL: &str = r#"
SELECT masks.persisted_relative_path, masks.intent
FROM temp.selected_resolution_overlay_masks AS masks
WHERE masks.storage_language = ?1 AND masks.persisted_relative_path > ?2
ORDER BY masks.persisted_relative_path
LIMIT 256
"#;

const SELECTED_MASK_BASE_SQL: &str = r#"
SELECT files.file_version_id, files.blob_oid, files.projection_digest
FROM temp.selected_workspace_file_versions AS files
WHERE files.lang = ?1 AND files.rel_path = ?2
ORDER BY files.valid_from
LIMIT 2
"#;

fn selected_mount_status_sql(continuation: bool) -> &'static str {
    static INITIAL_SQL: OnceLock<String> = OnceLock::new();
    static CONTINUATION_SQL: OnceLock<String> = OnceLock::new();
    let cell = if continuation {
        &CONTINUATION_SQL
    } else {
        &INITIAL_SQL
    };
    cell.get_or_init(|| {
        let counts = RESOLUTION_MANIFEST_COUNT_COLUMNS
            .iter()
            .map(|column| format!("interiors.{column}"))
            .collect::<Vec<_>>()
            .join(", ");
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
             LEFT JOIN main.blobs AS blobs
              ON blobs.blob_oid = files.blob_oid
              AND blobs.lang = files.lang
             LEFT JOIN main.blob_meta AS meta
               ON meta.blob_id = blobs.id
              AND meta.lang = blobs.lang
              AND EXISTS (
                SELECT 1 FROM main.source_fact_readiness AS visibility
                WHERE visibility.blob_id = blobs.id AND visibility.available = 1
              )
             LEFT JOIN main.resolution_fragment_interiors AS interiors
               ON interiors.blob_id = blobs.id
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
        #[cfg(test)]
        note_selected_static_sql_capacity(if continuation { 2 } else { 1 }, sql.capacity());
        sql
    })
}

fn selected_content_mount_status_sql() -> &'static str {
    static SQL: OnceLock<String> = OnceLock::new();
    SQL.get_or_init(|| {
        let counts = RESOLUTION_MANIFEST_COUNT_COLUMNS
            .iter()
            .map(|column| format!("interiors.{column}"))
            .collect::<Vec<_>>()
            .join(", ");
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
             LEFT JOIN main.blobs AS blobs
               ON blobs.blob_oid = requests.blob_oid
              AND blobs.lang = requests.storage_language
             LEFT JOIN main.blob_meta AS meta
               ON meta.blob_id = blobs.id
              AND meta.lang = blobs.lang
              AND EXISTS (
                SELECT 1 FROM main.source_fact_readiness AS visibility
                WHERE visibility.blob_id = blobs.id AND visibility.available = 1
              )
             LEFT JOIN main.resolution_fragment_interiors AS interiors
               ON interiors.blob_id = blobs.id
             ORDER BY requests.storage_language, requests.persisted_relative_path"
        );
        #[cfg(test)]
        note_selected_static_sql_capacity(3, sql.capacity());
        sql
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedResolutionLanguage {
    storage_language: String,
    semantic_language: Language,
}

impl SelectedResolutionLanguage {
    pub(crate) fn new(storage_language: impl Into<String>, semantic_language: Language) -> Self {
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

    pub(crate) fn storage_language(&self) -> &str {
        &self.storage_language
    }

    pub(crate) const fn semantic_language(&self) -> Language {
        self.semantic_language
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedResolutionOverlayMask {
    storage_language: String,
    persisted_relative_path: String,
    intent: SelectedResolutionOverlayIntent,
}

impl SelectedResolutionOverlayMask {
    pub(crate) fn replacement(
        storage_language: impl Into<String>,
        persisted_relative_path: impl Into<String>,
    ) -> Self {
        Self::new(
            storage_language,
            persisted_relative_path,
            SelectedResolutionOverlayIntent::Replacement,
        )
    }

    pub(crate) fn removal(
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
pub(crate) struct SelectedResolutionContentMountRequest {
    publication: super::resolution_publication::ResolutionContentWitness,
    storage_language: String,
    generation: GenerationId,
    file: WorkspaceFileRow,
    projection_digest: [u8; 32],
    overlay_authority: Option<SelectedResolutionOverlayAuthority>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SelectedResolutionOverlayAuthority {
    LiveOverlay { content_digest: [u8; 32] },
    Counterfactual { base_content_digest: [u8; 32] },
}

impl SelectedResolutionContentMountRequest {
    pub(crate) fn publication(&self) -> &super::resolution_publication::ResolutionContentWitness {
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
    pub(crate) fn new(
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

    pub(crate) fn with_live_overlay_content_digest(mut self, content_digest: [u8; 32]) -> Self {
        assert!(
            self.overlay_authority
                .replace(SelectedResolutionOverlayAuthority::LiveOverlay { content_digest })
                .is_none(),
            "a content mount cannot have two overlay authorities"
        );
        self
    }

    pub(crate) fn with_counterfactual_base_content_digest(
        mut self,
        base_content_digest: [u8; 32],
    ) -> Self {
        assert!(
            self.overlay_authority
                .replace(SelectedResolutionOverlayAuthority::Counterfactual {
                    base_content_digest,
                })
                .is_none(),
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

    pub(crate) fn persisted_relative_path(&self) -> &str {
        &self.file.rel_path
    }

    pub(crate) const fn blob_oid(&self) -> Oid {
        self.file.blob_oid
    }

    pub(crate) const fn projection_digest(&self) -> [u8; 32] {
        self.projection_digest
    }

    pub(crate) fn overlay_authority(&self) -> Option<&SelectedResolutionOverlayAuthority> {
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
pub(crate) struct SelectedResolutionMaskedBase {
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
pub(crate) struct SelectedResolutionOverlayMaskState {
    storage_language: String,
    persisted_relative_path: String,
    intent: SelectedResolutionOverlayIntent,
    masked_base: Option<SelectedResolutionMaskedBase>,
    expected_transient_replacement_count: u32,
}

impl SelectedResolutionOverlayMaskState {
    pub(crate) fn storage_language(&self) -> &str {
        &self.storage_language
    }

    pub(crate) fn persisted_relative_path(&self) -> &str {
        &self.persisted_relative_path
    }

    pub(crate) const fn masked_base(&self) -> Option<&SelectedResolutionMaskedBase> {
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
pub(crate) struct SelectedResolutionLanguageState {
    storage_language: String,
    semantic_language: Language,
    workspace_id: String,
    generation: i64,
    revision: i64,
    expected_base_mount_count: usize,
    masked_base_mount_count: usize,
    expected_unmasked_mount_count: usize,
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

    pub(crate) const fn generation(&self) -> i64 {
        self.generation
    }

    pub(crate) const fn revision(&self) -> i64 {
        self.revision
    }

    pub(crate) const fn expected_base_mount_count(&self) -> usize {
        self.expected_base_mount_count
    }

    pub(crate) const fn masked_base_mount_count(&self) -> usize {
        self.masked_base_mount_count
    }

    pub(crate) const fn expected_unmasked_mount_count(&self) -> usize {
        self.expected_unmasked_mount_count
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedResolutionMountRecord {
    ordinal: SelectedResolutionMountOrdinal,
    /// The mount's content key: what its `BindingFragmentId` used to be.
    ///
    /// A `BindingFragmentId` is the mount ordinal now, which is a property of
    /// this selection rather than of the blob, so the value the selection
    /// fingerprint hashes and the interior cache keys on lives here.
    fragment_digest: SelectedResolutionFragmentDigest,
    workspace_id: String,
    revision: i64,
    generation: i64,
    file_version_id: Option<i64>,
    storage_language: String,
    semantic_language: Language,
    persisted_relative_path: String,
    blob_id: i64,
    blob_oid: Oid,
    projection_digest: [u8; 32],
    interior_digest: [u8; 32],
    producer_epoch: String,
    manifest_counts: ResolutionManifestCounts,
    logical_rows: u64,
    payload_bytes: u64,
}

/// Request-owned memo. Only explicit ordinal/path reads add records; warm
/// operation construction leaves it empty and reader checkin never owns it.
#[derive(Default)]
pub(crate) struct RequestedResolutionMountRows {
    records: RefCell<
        HashMap<SelectedResolutionMountOrdinal, std::sync::Arc<SelectedResolutionMountRecord>>,
    >,
}

fn selected_mount_record_columns() -> &'static str {
    static COLUMNS: OnceLock<String> = OnceLock::new();
    COLUMNS.get_or_init(|| {
        let sql = format!("mount_ordinal,fragment_id,workspace_id,revision,generation,file_version_id,storage_language,semantic_language,persisted_relative_path,blob_id,blob_oid,projection_digest,interior_digest,producer_epoch,logical_rows,payload_bytes,{}", RESOLUTION_MANIFEST_COUNT_COLUMNS.join(","));
        #[cfg(test)]
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
        let sql = format!(
            "SELECT {} FROM temp.selected_resolution_mounts WHERE storage_language=?1 AND persisted_relative_path=?2",
            selected_mount_record_columns()
        );
        let mut statement = conn.prepare_cached(&sql)?;
        let mut rows = statement.query(params![language, path])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let record = std::sync::Arc::new(decode_selected_mount_record(row)?);
        self.records
            .borrow_mut()
            .insert(record.ordinal(), record.clone());
        Ok(Some(record))
    }
}

impl SelectedResolutionMountRecord {
    pub(crate) const fn ordinal(&self) -> SelectedResolutionMountOrdinal {
        self.ordinal
    }

    /// The mount's runtime fragment, which is its ordinal.
    pub(crate) fn fragment_id(&self) -> BindingFragmentId {
        BindingFragmentId::at_ordinal(self.ordinal.get())
    }

    /// The mount's content key, which keys the interior cache and the
    /// selection fingerprint.
    pub(crate) const fn fragment_digest(&self) -> SelectedResolutionFragmentDigest {
        self.fragment_digest
    }

    pub(crate) fn workspace_id(&self) -> &str {
        &self.workspace_id
    }

    pub(crate) const fn revision(&self) -> i64 {
        self.revision
    }

    pub(crate) const fn generation(&self) -> i64 {
        self.generation
    }

    pub(crate) const fn file_version_id(&self) -> Option<i64> {
        self.file_version_id
    }

    pub(crate) fn storage_language(&self) -> &str {
        &self.storage_language
    }

    pub(crate) const fn semantic_language(&self) -> Language {
        self.semantic_language
    }

    pub(crate) fn persisted_relative_path(&self) -> &str {
        &self.persisted_relative_path
    }

    pub(crate) const fn blob_id(&self) -> i64 {
        self.blob_id
    }

    pub(crate) const fn blob_oid(&self) -> Oid {
        self.blob_oid
    }

    pub(crate) const fn projection_digest(&self) -> [u8; 32] {
        self.projection_digest
    }

    pub(crate) const fn interior_digest(&self) -> [u8; 32] {
        self.interior_digest
    }

    pub(crate) fn producer_epoch(&self) -> &str {
        &self.producer_epoch
    }

    pub(crate) const fn manifest_counts(&self) -> &ResolutionManifestCounts {
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
pub(crate) enum SelectedResolutionUnavailable {
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
pub(crate) enum SelectedResolutionStale {
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

pub(crate) enum SelectedResolutionMountInventoryOutcome<'store> {
    Ready(Box<SelectedResolutionMountInventory<'store>>),
    Unavailable(SelectedResolutionUnavailable),
    Cancelled,
    Stale(SelectedResolutionStale),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SelectedResolutionRevalidationOutcome {
    Current,
    Cancelled,
    Stale(SelectedResolutionStale),
}

/// Transaction visibility is separate from a typed domain outcome. A rollback
/// does not subtract SQLite's attempted writes from the freshness stamp.
pub(super) enum SelectedResolutionTempTransaction<T> {
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
    NEXT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        value.checked_add(1)
    })
    .expect("selected stage request identity space exhausted")
}

pub(crate) struct SelectedResolutionMountInventory<'store> {
    conn: ReaderGuard<'store>,
    retained: Option<RetainedResolutionSelection>,
    requested_mounts: RequestedResolutionMountRows,
    enumerated_mounts: OnceCell<Vec<SelectedResolutionMountRecord>>,
    requested_languages: OnceCell<Vec<SelectedResolutionLanguageState>>,
    requested_masks: OnceCell<Vec<SelectedResolutionOverlayMaskState>>,
    mount_rebaser: RefCell<MountRebaser>,
    retention_authorized: bool,
    stage_request_used: Cell<bool>,
    stage_request_identity: u64,
    stage_content_epoch: Cell<u64>,
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
    shared_names: super::resolution::SharedNameTable,
    /// The current crate stage's placement and membership answers; `None`
    /// outside a crate stage. See `rust_crate_access::CrateAccessMemo`.
    crate_access: RefCell<Option<super::resolution_operation::rust_crate_access::CrateAccessMemo>>,
    /// The current crate stage's checked publications; `None` outside a crate
    /// stage. See `resolution_authority::AuthorityValidations`.
    authority_validations: RefCell<Option<super::resolution_authority::AuthorityValidations>>,
    /// Whether a crate stage holds a read transaction on this reader; see
    /// [`SelectedResolutionMountInventory::begin_stage_read`].
    stage_read: Cell<bool>,
}

/// Freshness of the retained reader, excluding only its private request buffers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SelectedResolutionReadStamp {
    main_data_version: i64,
    main_schema_version: i64,
    temp_schema_version: i64,
    unowned_changes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RetainedResolutionSelectionKey {
    workspace_id: String,
    snapshots: WorkspaceSnapshots,
    languages: Vec<SelectedResolutionLanguage>,
    overlay_masks: Vec<SelectedResolutionOverlayMask>,
    content_mounts: Vec<SelectedResolutionContentMountRequest>,
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

    fn routing_digest(&self) -> [u8; 32] {
        let mut hash = CanonicalHasher::new(b"bifrost-selected-input-routing:v1");
        hash.field("rows", self.relational_rows().as_bytes());
        hash.finish()
    }

    fn equals_selected_rows(&self, conn: &Connection) -> Result<bool> {
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
pub(super) struct RetainedResolutionSelection {
    routing_digest: [u8; 32],
    ready: RetainedSelectedMetadata,
    stamp: SelectedResolutionReadStamp,
    owned_change_baseline: u64,
    committed_request_changes: Cell<u64>,
}

impl RetainedResolutionSelection {
    pub(super) fn matches_key(&self, key: &RetainedResolutionSelectionKey) -> bool {
        self.routing_digest == key.routing_digest()
    }

    pub(super) fn same_key_as(&self, other: &Self) -> bool {
        self.routing_digest == other.routing_digest
    }

    fn current_stamp(&self, conn: &Connection) -> Result<SelectedResolutionReadStamp> {
        read_change_stamp(
            conn,
            self.owned_change_baseline,
            self.committed_request_changes.get(),
        )
    }

    fn is_current(&self, conn: &Connection) -> Result<bool> {
        Ok(self.current_stamp(conn)? == self.stamp)
    }
}

impl SelectedResolutionMountInventory<'_> {
    fn retained(&self) -> &RetainedResolutionSelection {
        self.retained
            .as_ref()
            .expect("selected inventory retains its complete selection until drop")
    }

    pub(crate) fn has_go_semantics(&self) -> bool {
        self.retained().ready.has_go_semantics
    }

    pub(crate) fn has_java_semantics(&self) -> bool {
        self.retained().ready.has_java_semantics
    }

    pub(crate) fn workspace_id(&self) -> &str {
        &self.retained().ready.workspace_id
    }

    pub(crate) fn workspace_digest(&self) -> Result<[u8; 32]> {
        parse_digest_text(self.workspace_id(), "workspace identity")
    }

    pub(crate) fn languages(&self) -> Result<&[SelectedResolutionLanguageState]> {
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

    pub(crate) fn overlay_masks(&self) -> Result<&[SelectedResolutionOverlayMaskState]> {
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

    pub(crate) fn persisted_mount_count(&self) -> usize {
        self.retained().ready.persisted_mount_count
    }

    /// Explicit full-inventory consumers own this enumeration for their query.
    /// Keyed point readers must use ordinal/path APIs instead.
    pub(crate) fn mounts(&self) -> Result<&[SelectedResolutionMountRecord]> {
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

    pub(crate) fn requested_mount_rows(&self) -> &RequestedResolutionMountRows {
        &self.requested_mounts
    }

    pub(crate) fn persisted_mount_record(
        &self,
        ordinal: SelectedResolutionMountOrdinal,
    ) -> Result<Option<std::sync::Arc<SelectedResolutionMountRecord>>> {
        if ordinal.get() as usize >= self.persisted_mount_count() {
            return Ok(None);
        }
        self.requested_mounts.by_ordinal(self.connection(), ordinal)
    }

    pub(crate) fn mount_record_by_ordinal(
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
    pub(crate) fn reset_scope_mounts(&self) -> Result<()> {
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
    /// `replace_resolution_requests_1` and `_2` account their own inserts the
    /// same way; this is the form for a write whose row count the caller does
    /// not already hold.
    pub(super) fn with_owned_temp_write<T>(
        &self,
        write: impl FnOnce(&Connection) -> Result<T>,
    ) -> Result<T> {
        let before = self.connection().total_changes();
        let value = write(self.connection())?;
        let changed = self
            .connection()
            .total_changes()
            .checked_sub(before)
            .expect("a temp write cannot lower the connection's change counter");
        let committed = &self.retained().committed_request_changes;
        committed.set(
            committed
                .get()
                .checked_add(changed)
                .expect("committed request changes fit u64"),
        );
        Ok(value)
    }

    pub(super) fn mark_stage_used(&self) {
        self.stage_request_used.set(true);
    }

    pub(super) fn note_stage_content_commit(&self) {
        self.stage_content_epoch.set(
            self.stage_content_epoch
                .get()
                .checked_add(1)
                .expect("selected stage content epoch exhausted"),
        );
    }

    #[cfg(test)]
    pub(in crate::analyzer::store) fn stage_content_epoch_for_test(&self) -> u64 {
        self.stage_content_epoch.get()
    }

    /// Raw candidate coverage belongs to this request and exact committed stage.
    pub(crate) fn candidate_coverage_fingerprint(&self) -> [u8; 32] {
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
    pub(super) fn with_owned_temp_transaction<T>(
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
                let committed = &self.retained().committed_request_changes;
                committed.set(
                    committed
                        .get()
                        .checked_add(changed)
                        .expect("committed request changes fit u64"),
                );
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
    #[cfg(test)]
    pub(crate) fn scope_mount_count(&self) -> Result<usize> {
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

    pub(crate) fn mount_record_for_path(
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

    pub(crate) const fn mount_rebaser(&self) -> &RefCell<MountRebaser> {
        &self.mount_rebaser
    }

    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        self.retained
            .as_ref()
            .expect("selected inventory retains its complete selection until drop")
            .ready
            .fingerprint
    }

    pub(crate) fn expected_transient_replacement_count(&self) -> usize {
        self.retained
            .as_ref()
            .expect("selected inventory retains its complete selection until drop")
            .ready
            .expected_transient_replacement_count
    }

    pub(super) fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Where this request's lowerings get a shared name's id.
    pub(super) fn shared_names(&self) -> super::resolution::StoreSharedNames<'_> {
        self.shared_names.interner(self.connection())
    }

    /// This request's shared-name answers, for a reader that holds the table
    /// and the connection for the same lifetime.
    pub(super) fn shared_name_table(&self) -> &super::resolution::SharedNameTable {
        &self.shared_names
    }

    pub(super) fn authority_validations(
        &self,
    ) -> &RefCell<Option<super::resolution_authority::AuthorityValidations>> {
        &self.authority_validations
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
        Ok(())
    }

    /// End the stage's read transaction, before the reader can return to its
    /// pool. An interrupted temp write rolls the whole transaction back, so
    /// COMMIT runs only when one is still open.
    pub(super) fn end_stage_read(&self) -> Result<()> {
        assert!(self.stage_read.get(), "no crate stage holds a read");
        self.stage_read.set(false);
        self.commit_stage_read()
    }

    /// Let this request's own publication be seen. A capsule is published
    /// through the store's writer in the middle of a stage and admitted from
    /// this reader right after, so the stage's snapshot ends before the
    /// publication and a new one starts after it
    /// ([`Self::resume_stage_read`]). Outside a stage this does nothing.
    pub(super) fn pause_stage_read(&self) -> Result<()> {
        if self.stage_read.get() {
            self.commit_stage_read()?;
        }
        Ok(())
    }

    pub(super) fn resume_stage_read(&self) -> Result<()> {
        if self.stage_read.get() {
            assert!(self.connection().is_autocommit());
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

    pub(super) fn read_change_stamp(&self) -> Result<SelectedResolutionReadStamp> {
        self.retained().current_stamp(self.connection())
    }

    pub(super) fn replace_resolution_requests_1(
        &self,
        requests: impl IntoIterator<Item = (SelectedResolutionMountOrdinal, i64)>,
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        let requests = requests.into_iter().collect::<Vec<_>>();
        assert!(requests.len() <= SELECTED_MOUNT_PAGE_ROWS);
        assert!(requests.iter().all(|(_, key)| *key >= 0));
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let transaction = TempWrite::begin(self.connection())?;
        let mut changed = self
            .connection()
            .prepare_cached("DELETE FROM temp.selected_resolution_typed_requests_1")?
            .execute([])?;
        let mut statement = self.connection().prepare_cached(
            "INSERT INTO temp.selected_resolution_typed_requests_1(mount_ordinal, key0) \
             VALUES(?1, ?2)",
        )?;
        for (mount, key) in requests {
            if cancellation.is_cancelled() {
                drop(statement);
                transaction.rollback()?;
                return Ok(false);
            }
            changed += statement.execute([i64::from(mount.get()), key])?;
        }
        drop(statement);
        if cancellation.is_cancelled() {
            transaction.rollback()?;
            return Ok(false);
        }
        transaction.commit()?;
        // Subtract exact committed direct writes, never a fresh total-change
        // baseline: preceding unowned mutations and rolled-back work stay visible.
        let committed = &self.retained().committed_request_changes;
        committed.set(
            committed
                .get()
                .checked_add(u64::try_from(changed).expect("request changes fit u64"))
                .expect("committed request changes fit u64"),
        );
        Ok(!cancellation.is_cancelled())
    }

    pub(super) fn replace_resolution_requests_2(
        &self,
        requests: impl IntoIterator<Item = (SelectedResolutionMountOrdinal, i64, i64)>,
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        let requests = requests.into_iter().collect::<Vec<_>>();
        assert!(requests.len() <= SELECTED_MOUNT_PAGE_ROWS);
        assert!(
            requests
                .iter()
                .all(|(_, first, second)| *first >= 0 && *second >= 0)
        );
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let transaction = TempWrite::begin(self.connection())?;
        let mut changed = self
            .connection()
            .prepare_cached("DELETE FROM temp.selected_resolution_typed_requests_2")?
            .execute([])?;
        let mut statement = self.connection().prepare_cached(
            "INSERT INTO temp.selected_resolution_typed_requests_2(mount_ordinal, key0, key1) \
             VALUES(?1, ?2, ?3)",
        )?;
        for (mount, first, second) in requests {
            if cancellation.is_cancelled() {
                drop(statement);
                transaction.rollback()?;
                return Ok(false);
            }
            changed += statement.execute([i64::from(mount.get()), first, second])?;
        }
        drop(statement);
        if cancellation.is_cancelled() {
            transaction.rollback()?;
            return Ok(false);
        }
        transaction.commit()?;
        let committed = &self.retained().committed_request_changes;
        committed.set(
            committed
                .get()
                .checked_add(u64::try_from(changed).expect("request changes fit u64"))
                .expect("committed request changes fit u64"),
        );
        Ok(!cancellation.is_cancelled())
    }

    pub(crate) fn revalidate(
        &mut self,
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionRevalidationOutcome> {
        if cancellation.is_cancelled() {
            return Ok(SelectedResolutionRevalidationOutcome::Cancelled);
        }
        self.retention_authorized = false;
        let current = self.read_change_stamp()?;
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
            Ok(current) if current == retained.stamp => {
                self.conn.put_retained_resolution_selection(retained);
            }
            Ok(_) | Err(_) => {
                self.conn
                    .cleanup_before_checkin(CLEAR_SELECTED_RESOLUTION_TEMP_SQL);
            }
        }
    }
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
    // Table-valued pragmas prepare an inner statement on every scan, even when
    // their outer SELECT is cached. Cache the direct pragmas instead.
    let main_data_version = conn
        .prepare_cached("PRAGMA main.data_version")?
        .query_row([], |row| row.get(0))?;
    let main_schema_version = conn
        .prepare_cached("PRAGMA main.schema_version")?
        .query_row([], |row| row.get(0))?;
    let temp_schema_version = conn
        .prepare_cached("PRAGMA temp.schema_version")?
        .query_row([], |row| row.get(0))?;
    let unowned_changes = conn
        .total_changes()
        .checked_sub(owned_change_baseline)
        .and_then(|changes| changes.checked_sub(committed_request_changes))
        .expect("owned selection changes are a subset of connection total changes");
    Ok(SelectedResolutionReadStamp {
        main_data_version,
        main_schema_version,
        temp_schema_version,
        unowned_changes,
    })
}

/// Fixed-size authority metadata; the workspace identity has validated fixed
/// digest width. Variable selection inputs and all mount rows stay in TEMP.
struct RetainedSelectedMetadata {
    // A fixed selection property, so endpoint admission need not query language
    // rows on every newly borrowed Rust-only operation.
    has_go_semantics: bool,
    // Likewise for the Java lexical hierarchy replay: a selection without Java
    // semantics never prepares one, so Rust-only points pay no read for it.
    has_java_semantics: bool,
    workspace_id: String,
    fingerprint: [u8; 32],
    persisted_mount_count: usize,
    expected_transient_replacement_count: usize,
}

impl RetainedSelectedMetadata {
    fn from_staged(staged: &StagedReadySelection) -> Self {
        Self {
            has_go_semantics: staged
                .languages
                .iter()
                .any(|language| language.semantic_language() == Language::Go),
            has_java_semantics: staged
                .languages
                .iter()
                .any(|language| language.semantic_language() == Language::Java),
            workspace_id: staged.workspace_id.clone(),
            fingerprint: staged.fingerprint,
            persisted_mount_count: staged.mounts.len(),
            expected_transient_replacement_count: staged.expected_transient_replacement_count,
        }
    }
}

struct StagedReadySelection {
    workspace_id: String,
    languages: Vec<SelectedResolutionLanguageState>,
    overlay_masks: Vec<SelectedResolutionOverlayMaskState>,
    mounts: Vec<SelectedResolutionMountRecord>,
    fingerprint: [u8; 32],
    expected_transient_replacement_count: usize,
}

enum StagedSelection {
    Ready(Box<StagedReadySelection>),
    Unavailable(SelectedResolutionUnavailable),
    Cancelled,
    Stale(SelectedResolutionStale),
}

impl AnalyzerStore {
    #[cfg(test)]
    pub(crate) fn open_selected_resolution_mount_inventory(
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

    pub(crate) fn open_selected_resolution_mount_inventory_with_content_mounts(
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
        let mut conn = self.active_read_conn_for_resolution(&validated)?;
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
                            conn,
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
                            scope_identity: Cell::new(scope_identity_of(&[])),
                            crate_access: RefCell::default(),
                            authority_validations: RefCell::default(),
                            stage_read: Cell::new(false),
                            shared_names: super::resolution::SharedNameTable::new(
                                self.resolution_shared_name_cache().clone(),
                            ),
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
        match staged {
            StagedSelection::Ready(staged) => {
                if cancellation.is_cancelled() {
                    conn.cleanup_before_checkin(CLEAR_SELECTED_RESOLUTION_TEMP_SQL);
                    return Ok(SelectedResolutionMountInventoryOutcome::Cancelled);
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
                if stamp.main_data_version != selection_start_stamp.main_data_version
                    || stamp.main_schema_version != selection_start_stamp.main_schema_version
                {
                    conn.cleanup_before_checkin(CLEAR_SELECTED_RESOLUTION_TEMP_SQL);
                    return Ok(SelectedResolutionMountInventoryOutcome::Stale(
                        SelectedResolutionStale::MountInventoryChanged,
                    ));
                }
                let retained = RetainedResolutionSelection {
                    routing_digest: validated.routing_digest(),
                    ready: RetainedSelectedMetadata::from_staged(&staged),
                    stamp,
                    owned_change_baseline,
                    committed_request_changes: Cell::new(0),
                };
                let mount_rebaser =
                    MountRebaser::for_persisted_mount_count(retained.ready.persisted_mount_count);
                conn.retain_before_checkin();
                Ok(SelectedResolutionMountInventoryOutcome::Ready(Box::new(
                    SelectedResolutionMountInventory {
                        conn,
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
                        scope_identity: Cell::new(scope_identity_of(&[])),
                        crate_access: RefCell::default(),
                        authority_validations: RefCell::default(),
                        stage_read: Cell::new(false),
                        shared_names: super::resolution::SharedNameTable::new(
                            self.resolution_shared_name_cache().clone(),
                        ),
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

type ValidatedSelectionInput = RetainedResolutionSelectionKey;

fn validate_selection_input(
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

fn insert_selection_input(
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

fn persist_selected_inventory(
    tx: &Transaction<'_>,
    staged: &StagedReadySelection,
    cancellation: &CancellationToken,
) -> Result<bool> {
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
        hasher.field("ordinal", &mount.ordinal.get().to_be_bytes());
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
    i64::try_from(value)
        .map_err(|_| StoreError::new("selected resolution count exceeds SQLite integer"))
}

fn u64_to_i64(value: u64, label: &str) -> Result<i64> {
    i64::try_from(value).map_err(|_| StoreError::new(format!("{label} exceeds SQLite integer")))
}

fn usize_as_u64(value: usize) -> u64 {
    u64::try_from(value).expect("usize fits u64 on supported targets")
}

#[cfg(test)]
pub(super) mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use rusqlite::OptionalExtension;
    use tree_sitter::Parser;

    use crate::analyzer::ProjectFile;
    use crate::analyzer::cpp::CppAdapter;
    use crate::analyzer::java::JavaAdapter;
    use crate::analyzer::rust::RustAdapter;
    use crate::analyzer::tree_sitter_analyzer::{FileState, LanguageAdapter, ParsedFile};
    use crate::analyzer::typescript::TypescriptAdapter;

    use super::super::{GenerationId, WorkspaceSnapshotId};
    use super::*;

    const WORKSPACE_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn parsed_fixture_state<A: LanguageAdapter>(
        adapter: &A,
        relative_path: &str,
        source: &str,
    ) -> FileState {
        let file = ProjectFile::new(
            std::env::current_dir()
                .expect("resolve selection fixture root")
                .join("selected-resolution-context-does-not-touch-disk"),
            relative_path,
        );
        let mut parser = Parser::new();
        parser
            .set_language(&adapter.parser_language_for_file(&file))
            .expect("configure fixture grammar");
        let tree = parser.parse(source, None).expect("parse fixture source");
        let mut parsed: ParsedFile = adapter.parse_file(&file, source, &tree);
        parsed.add_file_scope(&file, source);
        let contains_tests = adapter.contains_tests(&file, source, &tree, &parsed);
        let declarations = parsed.declarations().clone();
        FileState {
            source: source.to_owned(),
            package_name: parsed.package_name,
            content_qualifier: parsed.content_qualifier,
            top_level_declarations: parsed.top_level_declarations,
            declarations,
            definition_lookup_units: parsed.definition_lookup_units,
            imports: parsed.imports,
            scala_exports: parsed.scala_exports,
            rust_usage_facts: parsed.rust_usage_facts,
            source_facts: parsed.source_facts,
            source_declaration_units: parsed.source_declaration_units,
            source_declaration_metadata: parsed.source_declaration_metadata,
            resolution_facts: parsed.resolution_facts,
            raw_supertypes: parsed.raw_supertypes,
            supertype_lookup_paths: parsed.supertype_lookup_paths,
            type_identifiers: parsed.type_identifiers,
            signatures: parsed.signatures,
            signature_metadata: parsed.signature_metadata,
            signature_metadata_signature_ordinals: parsed.signature_metadata_signature_ordinals,
            cpp_template_metadata: parsed.cpp_template_metadata,
            ruby_method_dispatch_modes: parsed.ruby_method_dispatch_modes,
            ranges: parsed.ranges,
            children: parsed.children,
            scala_traits: parsed.scala_traits,
            type_aliases: parsed.type_aliases,
            contains_tests,
            test_region_units: parsed.test_region_units,
            materialization_records: parsed.materialization_records,
            parse_errors: Some(Vec::new()),
            parse_complete: true,
            additional_projections: Vec::new(),
        }
    }

    fn write_fixture_blob(
        store: &AnalyzerStore,
        oid: &str,
        storage_language: &str,
        semantic_language: Language,
        generation: GenerationId,
    ) {
        let (relative_path, source) = match semantic_language {
            Language::Java => ("src/Model.java", "package demo; class Model {}\n"),
            Language::TypeScript => ("src/Model.tsx", "export class Model {}\n"),
            Language::Cpp => ("src/Model.c", "class Model {};\n"),
            _ => panic!("selection fixture adapter is not defined for {semantic_language:?}"),
        };
        let result = match semantic_language {
            Language::Java => {
                let state = parsed_fixture_state(&JavaAdapter, relative_path, source);
                store.write_parsed_blob_at_generation(
                    Oid::from_str(oid).unwrap(),
                    storage_language,
                    generation,
                    &JavaAdapter,
                    &state,
                )
            }
            Language::TypeScript => {
                let state = parsed_fixture_state(&TypescriptAdapter, relative_path, source);
                store.write_parsed_blob_at_generation(
                    Oid::from_str(oid).unwrap(),
                    storage_language,
                    generation,
                    &TypescriptAdapter,
                    &state,
                )
            }
            Language::Cpp => {
                let state = parsed_fixture_state(&CppAdapter, relative_path, source);
                store.write_parsed_blob_at_generation(
                    Oid::from_str(oid).unwrap(),
                    storage_language,
                    generation,
                    &CppAdapter,
                    &state,
                )
            }
            _ => unreachable!(),
        };
        result.expect("persist selected-resolution fixture blob");
    }

    pub(in crate::analyzer::store) struct SelectionFixture {
        pub(in crate::analyzer::store) store: AnalyzerStore,
        workspace_id: WorkspaceId,
        snapshots: WorkspaceSnapshots,
        storage_language: String,
        semantic_language: Language,
    }

    impl SelectionFixture {
        pub(in crate::analyzer::store) fn retain_one_reader(&mut self) {
            self.store.active_readers.capacity = 1;
        }

        fn content_witness(
            &self,
            oid: &str,
        ) -> super::super::resolution_publication::ResolutionContentWitness {
            use super::super::resolution_publication::{
                ResolutionContentInput, ResolutionContentPublicationOutcome,
            };
            let oid = Oid::from_str(oid).unwrap();
            let outcome = self
                .store
                .admit_cached_selected_content(
                    &self.snapshots[&self.storage_language],
                    "src/cached.java",
                    oid,
                    &ResolutionContentInput::Parsed {
                        content_oid: oid,
                        semantic_language: self.semantic_language,
                    },
                    &CancellationToken::default(),
                )
                .unwrap();
            let ResolutionContentPublicationOutcome::Ready(content) = outcome else {
                panic!("real fixture publication: {outcome:?}");
            };
            content.into_parts().0
        }

        pub(in crate::analyzer::store) fn new(mount_count: usize) -> Self {
            Self::with_language(mount_count, "java", Language::Java, false)
        }

        pub(in crate::analyzer::store) fn shared_blob(mount_count: usize) -> Self {
            Self::with_language(mount_count, "java", Language::Java, true)
        }

        pub(in crate::analyzer::store) fn custom_source(mount_count: usize, source: &str) -> Self {
            Self::with_store(
                AnalyzerStore::open_ephemeral().unwrap(),
                mount_count,
                "java",
                Language::Java,
                false,
                false,
                Some(source),
            )
        }

        pub(in crate::analyzer::store) fn custom_rust_source(
            mount_count: usize,
            source: &str,
        ) -> Self {
            Self::with_store(
                AnalyzerStore::open_ephemeral().unwrap(),
                mount_count,
                "rust",
                Language::Rust,
                false,
                false,
                Some(source),
            )
        }

        fn bootstrap(mount_count: usize) -> Self {
            Self::with_authority(mount_count, "java", Language::Java, false, true)
        }

        fn with_language(
            mount_count: usize,
            storage_language: &str,
            semantic_language: Language,
            shared_blob: bool,
        ) -> Self {
            Self::with_authority(
                mount_count,
                storage_language,
                semantic_language,
                shared_blob,
                false,
            )
        }

        fn with_authority(
            mount_count: usize,
            storage_language: &str,
            semantic_language: Language,
            shared_blob: bool,
            bootstrap: bool,
        ) -> Self {
            Self::with_store(
                AnalyzerStore::open_ephemeral().unwrap(),
                mount_count,
                storage_language,
                semantic_language,
                shared_blob,
                bootstrap,
                None,
            )
        }

        fn persistent(mount_count: usize) -> (tempfile::TempDir, Self) {
            let temp = tempfile::tempdir().unwrap();
            let store = AnalyzerStore::open_persistent(&temp.path().join("cache.db")).unwrap();
            let fixture = Self::with_store(
                store,
                mount_count,
                "java",
                Language::Java,
                false,
                false,
                None,
            );
            (temp, fixture)
        }

        fn with_store(
            store: AnalyzerStore,
            mount_count: usize,
            storage_language: &str,
            semantic_language: Language,
            shared_blob: bool,
            bootstrap: bool,
            source: Option<&str>,
        ) -> Self {
            let generation = if bootstrap {
                GenerationId::BOOTSTRAP
            } else {
                store
                    .ensure_language_epoch_value(storage_language, "selection-test-v1")
                    .unwrap()
            };
            store
                .ensure_resolution_producer_epoch(storage_language, semantic_language)
                .unwrap();
            let workspace_id = WorkspaceId(WORKSPACE_ID.to_owned());
            let storage_language_owned = storage_language.to_owned();
            let blob_count = if shared_blob && mount_count > 0 {
                1
            } else {
                mount_count
            };
            let blob_oids = (0..blob_count)
                .map(|index| format!("{:040x}", index + 1))
                .collect::<Vec<_>>();
            let writer_workspace_id = workspace_id.as_str().to_owned();
            let writer_language = storage_language_owned.clone();
            let writer_blob_oids = blob_oids.clone();
            store.conn.execute(move |conn| {
                let tx = conn.transaction().unwrap();
                tx.execute(
                    "INSERT INTO workspace_revisions(workspace_id, lang, generation, revision)
                     VALUES(?1, ?2, ?3, 1)",
                    params![writer_workspace_id, writer_language, generation.0],
                )
                .unwrap();
                tx.execute(
                    "INSERT INTO workspace_heads(workspace_id, lang, generation, revision)
                     VALUES(?1, ?2, ?3, 1)",
                    params![writer_workspace_id, writer_language, generation.0],
                )
                .unwrap();
                for index in 0..mount_count {
                    let oid = if shared_blob {
                        &writer_blob_oids[0]
                    } else {
                        &writer_blob_oids[index]
                    };
                    tx.execute(
                        "INSERT INTO workspace_file_versions(
                           workspace_id, lang, generation, rel_path, blob_oid,
                           projection_digest, valid_from
                         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, 1)",
                        params![
                            writer_workspace_id,
                            writer_language,
                            generation.0,
                            match semantic_language {
                                Language::Rust => format!("src/{index:04}.rs"),
                                _ => format!("src/{index:04}.java"),
                            },
                            oid,
                            format!("{:064x}", index + 1),
                        ],
                    )
                    .unwrap();
                }
                tx.commit().unwrap();
            });

            for oid in &blob_oids {
                if let Some(source) = source {
                    let result = match semantic_language {
                        Language::Java => {
                            let state =
                                parsed_fixture_state(&JavaAdapter, "src/Model.java", source);
                            store.write_parsed_blob_at_generation(
                                Oid::from_str(oid).unwrap(),
                                storage_language,
                                generation,
                                &JavaAdapter,
                                &state,
                            )
                        }
                        Language::Rust => {
                            let state = parsed_fixture_state(&RustAdapter, "src/Model.rs", source);
                            store.write_parsed_blob_at_generation(
                                Oid::from_str(oid).unwrap(),
                                storage_language,
                                generation,
                                &RustAdapter,
                                &state,
                            )
                        }
                        _ => panic!(
                            "custom selection fixture adapter is not defined for {semantic_language:?}"
                        ),
                    };
                    result.expect("persist custom selected-resolution fixture blob");
                } else {
                    write_fixture_blob(
                        &store,
                        oid,
                        storage_language,
                        semantic_language,
                        generation,
                    );
                }
            }

            let mut snapshots = WorkspaceSnapshots::default();
            snapshots.insert(
                storage_language_owned.clone(),
                WorkspaceSnapshotId {
                    workspace_id: workspace_id.clone(),
                    lang: storage_language_owned.clone(),
                    generation,
                    revision: 1,
                },
            );
            Self {
                store,
                workspace_id,
                snapshots,
                storage_language: storage_language_owned,
                semantic_language,
            }
        }

        fn language(&self) -> SelectedResolutionLanguage {
            SelectedResolutionLanguage::new(self.storage_language.clone(), self.semantic_language)
        }

        pub(in crate::analyzer::store) fn open_ready<'a>(
            &'a self,
            masks: &[SelectedResolutionOverlayMask],
        ) -> Box<SelectedResolutionMountInventory<'a>> {
            match self
                .store
                .open_selected_resolution_mount_inventory(
                    &self.workspace_id,
                    &self.snapshots,
                    &[self.language()],
                    masks,
                    &CancellationToken::default(),
                )
                .unwrap()
            {
                SelectedResolutionMountInventoryOutcome::Ready(ready) => ready,
                _ => panic!("complete fixture must open Ready"),
            }
        }
    }

    #[test]
    fn selected_inventory_handles_zero_one_and_page_boundaries() {
        for count in [0, 1, 256, 257] {
            let fixture = SelectionFixture::with_language(count, "java", Language::Java, true);
            let ready = fixture.open_ready(&[]);
            assert_eq!(ready.workspace_id(), WORKSPACE_ID);
            assert!(ready.connection().is_autocommit());
            assert_eq!(ready.mounts().unwrap().len(), count);
            assert_eq!(
                ready.languages().unwrap()[0].expected_base_mount_count(),
                count
            );
            assert_eq!(
                ready
                    .mounts()
                    .unwrap()
                    .iter()
                    .map(|mount| mount.ordinal().get())
                    .collect::<Vec<_>>(),
                (0..u32::try_from(count).unwrap()).collect::<Vec<_>>()
            );
            assert!(ready.mounts().unwrap().windows(2).all(|pair| {
                pair[0].persisted_relative_path() < pair[1].persisted_relative_path()
            }));
            let rebaser = ready.mount_rebaser().borrow();
            for mount in ready.mounts().unwrap() {
                let registered = rebaser
                    .mount(mount.ordinal())
                    .expect("every validated persisted mount is registered");
                assert_eq!(registered.ordinal(), mount.ordinal());
                assert_eq!(registered.fragment(), mount.fragment_id());
            }
        }
    }

    #[test]
    fn selected_input_rows_preserve_canonical_order_and_overlay_authority() {
        let fixture = SelectionFixture::new(2);
        let cancellation = CancellationToken::default();
        let masks = [
            SelectedResolutionOverlayMask::removal("java", "src/0000.java"),
            SelectedResolutionOverlayMask::removal("java", "src/0001.java"),
        ];
        let mut content = SelectedResolutionContentMountRequest::new(
            fixture.content_witness("0000000000000000000000000000000000000001"),
            WorkspaceFileRow {
                rel_path: "src/cached.java".into(),
                blob_oid: Oid::from_str("0000000000000000000000000000000000000001").unwrap(),
            },
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        for authority in [
            None,
            Some(SelectedResolutionOverlayAuthority::LiveOverlay {
                content_digest: [1; 32],
            }),
            Some(SelectedResolutionOverlayAuthority::Counterfactual {
                base_content_digest: [1; 32],
            }),
            Some(SelectedResolutionOverlayAuthority::LiveOverlay {
                content_digest: [2; 32],
            }),
        ] {
            content.overlay_authority = authority.clone();
            let key = validate_selection_input(
                &fixture.workspace_id,
                &fixture.snapshots,
                &[fixture.language()],
                &masks,
                std::slice::from_ref(&content),
                &cancellation,
            )
            .unwrap()
            .unwrap();
            let conn = fixture.store.conn.lock().unwrap();
            ensure_revisioned_workspace_views(&conn).unwrap();
            conn.execute_batch(selected_resolution_temp_schema_sql())
                .unwrap();
            conn.execute_batch(CLEAR_SELECTED_RESOLUTION_TEMP_SQL)
                .unwrap();
            let tx = conn.unchecked_transaction().unwrap();
            assert!(
                insert_selection_input(
                    &tx,
                    &key.workspace_id,
                    &key.snapshots,
                    &key.languages,
                    &key.overlay_masks,
                    &key.content_mounts,
                    &cancellation
                )
                .unwrap()
            );
            tx.commit().unwrap();
            assert!(key.equals_selected_rows(&conn).unwrap());
            let reversed = [masks[1].clone(), masks[0].clone()];
            let reordered = validate_selection_input(
                &fixture.workspace_id,
                &fixture.snapshots,
                &[fixture.language()],
                &reversed,
                std::slice::from_ref(&content),
                &cancellation,
            )
            .unwrap()
            .unwrap();
            assert_eq!(key, reordered);
            assert_eq!(key.routing_digest(), reordered.routing_digest());
            assert!(reordered.equals_selected_rows(&conn).unwrap());
            for other in [
                None,
                Some(SelectedResolutionOverlayAuthority::LiveOverlay {
                    content_digest: [1; 32],
                }),
                Some(SelectedResolutionOverlayAuthority::Counterfactual {
                    base_content_digest: [1; 32],
                }),
                Some(SelectedResolutionOverlayAuthority::LiveOverlay {
                    content_digest: [2; 32],
                }),
            ] {
                let mut changed = key.clone();
                changed.content_mounts[0].overlay_authority = other.clone();
                assert_eq!(
                    changed.equals_selected_rows(&conn).unwrap(),
                    other == authority
                );
            }
        }
    }

    #[test]
    fn selected_input_routing_collision_rebuilds_exact_relational_selection() {
        let (_temp, mut fixture) = SelectionFixture::persistent(1);
        fixture.store.active_readers.capacity = 1;
        drop(fixture.open_ready(&[]));
        let mask = SelectedResolutionOverlayMask::removal("java", "src/0000.java");
        let key = validate_selection_input(
            &fixture.workspace_id,
            &fixture.snapshots,
            &[fixture.language()],
            std::slice::from_ref(&mask),
            &[],
            &CancellationToken::default(),
        )
        .unwrap()
        .unwrap();
        {
            let mut conn = fixture.store.active_read_conn().unwrap();
            let mut retained = conn.take_retained_resolution_selection().unwrap();
            retained.routing_digest = key.routing_digest();
            conn.put_retained_resolution_selection(retained);
        }
        let ready = fixture.open_ready(std::slice::from_ref(&mask));
        assert_eq!(
            ready.persisted_mount_count(),
            0,
            "a routing collision cannot return the old unmasked inventory"
        );
        assert!(key.equals_selected_rows(ready.connection()).unwrap());
    }

    #[test]
    fn selected_input_equality_query_failure_discards_unowned_temp_state() {
        let (_temp, mut fixture) = SelectionFixture::persistent(1);
        fixture.store.active_readers.capacity = 1;
        drop(fixture.open_ready(&[]));
        {
            let mut conn = fixture.store.active_read_conn().unwrap();
            let retained = conn.take_retained_resolution_selection().unwrap();
            conn.execute_batch("DROP TABLE temp.selected_resolution_content_mounts")
                .unwrap();
            conn.put_retained_resolution_selection(retained);
        }
        let error = fixture
            .store
            .open_selected_resolution_mount_inventory(
                &fixture.workspace_id,
                &fixture.snapshots,
                &[fixture.language()],
                &[],
                &CancellationToken::default(),
            )
            .err()
            .expect("missing key relation propagates its SQL failure");
        assert!(
            error
                .to_string()
                .contains("selected_resolution_content_mounts"),
            "{error}"
        );
        assert_eq!(
            fixture.open_ready(&[]).persisted_mount_count(),
            1,
            "a later reader rebuilds clean TEMP authority after the failed comparison"
        );
    }

    #[test]
    fn single_reader_exact_selection_key_reuses_materialization_and_changed_mask_rebuilds() {
        let (_temp, mut fixture) = SelectionFixture::persistent(1);
        // Force eviction to certify rematerialization separately from the
        // multi-reader pool's retention of alternating exact selections.
        fixture.store.active_readers.capacity = 1;
        {
            let conn = fixture.store.active_read_conn().unwrap();
            ensure_revisioned_workspace_views(&conn).unwrap();
            conn.execute_batch(selected_resolution_temp_schema_sql())
                .unwrap();
            conn.execute_batch(
                "CREATE TEMP TABLE selection_materialization_probe(insertions INTEGER NOT NULL);
                 CREATE TEMP TRIGGER count_selected_resolution_materialization
                 AFTER INSERT ON selected_resolution_context
                 BEGIN
                   INSERT INTO selection_materialization_probe VALUES(1);
                 END;",
            )
            .unwrap();
        }

        drop(fixture.open_ready(&[]));
        drop(fixture.open_ready(&[]));
        let removal = SelectedResolutionOverlayMask::removal("java", "src/0000.java");
        drop(fixture.open_ready(std::slice::from_ref(&removal)));
        drop(fixture.open_ready(std::slice::from_ref(&removal)));

        let conn = fixture.store.active_read_conn().unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM temp.selection_materialization_probe",
                [],
                |row| row.get::<_, usize>(0),
            )
            .unwrap(),
            2,
            "only each distinct exact selection key may materialize"
        );
    }

    #[test]
    fn alternating_exact_selection_keys_retain_their_own_reader_and_temp_inventory() {
        let (_temp, fixture) = SelectionFixture::persistent(2);
        let removal = SelectedResolutionOverlayMask::removal("java", "src/0000.java");
        for (masks, marker) in [(&[][..], -8193), (std::slice::from_ref(&removal), -8194)] {
            let ready = fixture.open_ready(masks);
            // A connection-local pragma identifies the reader without changing
            // its schema or data freshness stamp.
            ready
                .connection()
                .pragma_update(None, "cache_size", marker)
                .unwrap();
        }
        for _ in 0..4 {
            for (masks, marker, mounts) in [
                (&[][..], -8193, 2),
                (std::slice::from_ref(&removal), -8194, 1),
            ] {
                let ready = fixture.open_ready(masks);
                assert_eq!(ready.mounts().unwrap().len(), mounts);
                assert_eq!(
                    ready
                        .connection()
                        .pragma_query_value(None, "cache_size", |row| row.get::<_, i32>(0))
                        .unwrap(),
                    marker
                );
            }
        }
        let third = SelectedResolutionOverlayMask::removal("java", "src/0001.java");
        drop(fixture.open_ready(&[third]));
        let state = fixture.store.active_readers.state.lock().unwrap();
        assert_eq!(
            state
                .idle
                .iter()
                .filter(|reader| reader.resolution_selection.is_some())
                .count(),
            2
        );
    }

    #[test]
    fn concurrent_same_key_returns_keep_one_retained_reader() {
        let (_temp, fixture) = SelectionFixture::persistent(1);
        let first = fixture.open_ready(&[]);
        let concurrent = fixture.open_ready(&[]);
        drop(first);
        drop(concurrent);
        let state = fixture.store.active_readers.state.lock().unwrap();
        assert_eq!(
            state
                .idle
                .iter()
                .filter(|reader| reader.resolution_selection.is_some())
                .count(),
            1
        );
    }

    #[test]
    fn external_store_change_invalidates_retained_materialization() {
        let (_temp, fixture) = SelectionFixture::persistent(1);
        {
            let conn = fixture.store.active_read_conn().unwrap();
            ensure_revisioned_workspace_views(&conn).unwrap();
            conn.execute_batch(selected_resolution_temp_schema_sql())
                .unwrap();
            conn.execute_batch(
                "CREATE TEMP TABLE selection_materialization_probe(insertions INTEGER NOT NULL);
                 CREATE TEMP TRIGGER count_selected_resolution_materialization
                 AFTER INSERT ON selected_resolution_context
                 BEGIN
                   INSERT INTO selection_materialization_probe VALUES(1);
                 END;",
            )
            .unwrap();
        }
        drop(fixture.open_ready(&[]));
        fixture.store.conn.execute(|writer| {
            writer
                .execute_batch("CREATE TABLE retained_selection_invalidation_probe(value INTEGER)")
                .unwrap();
        });
        drop(fixture.open_ready(&[]));

        let conn = fixture.store.active_read_conn().unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM temp.selection_materialization_probe",
                [],
                |row| row.get::<_, usize>(0),
            )
            .unwrap(),
            2,
            "a main-database commit must rebuild the selected TEMP state"
        );
    }

    #[test]
    fn empty_requested_language_set_retains_explicit_workspace_identity() {
        let fixture = SelectionFixture::new(0);
        let ready = match fixture
            .store
            .open_selected_resolution_mount_inventory(
                &fixture.workspace_id,
                &WorkspaceSnapshots::default(),
                &[],
                &[],
                &CancellationToken::default(),
            )
            .unwrap()
        {
            SelectedResolutionMountInventoryOutcome::Ready(ready) => ready,
            _ => panic!("empty exact selection must be Ready"),
        };
        assert_eq!(ready.workspace_id(), WORKSPACE_ID);
        assert!(ready.languages().unwrap().is_empty());
        assert!(ready.mounts().unwrap().is_empty());
    }

    #[test]
    fn requested_language_permutation_has_one_deterministic_missing_reason() {
        let fixture = SelectionFixture::new(0);
        for languages in [
            vec![
                SelectedResolutionLanguage::new("rust", Language::Rust),
                fixture.language(),
            ],
            vec![
                fixture.language(),
                SelectedResolutionLanguage::new("rust", Language::Rust),
            ],
        ] {
            let outcome = fixture
                .store
                .open_selected_resolution_mount_inventory(
                    &fixture.workspace_id,
                    &WorkspaceSnapshots::default(),
                    &languages,
                    &[],
                    &CancellationToken::default(),
                )
                .unwrap();
            assert!(matches!(
                outcome,
                SelectedResolutionMountInventoryOutcome::Unavailable(
                    SelectedResolutionUnavailable::MissingWorkspaceSnapshot {
                        storage_language
                    }
                ) if storage_language == "java"
            ));
        }
    }

    #[test]
    fn duplicate_or_cross_workspace_selection_input_fails_before_publication() {
        let fixture = SelectionFixture::new(0);
        let duplicate_languages = fixture.store.open_selected_resolution_mount_inventory(
            &fixture.workspace_id,
            &fixture.snapshots,
            &[fixture.language(), fixture.language()],
            &[],
            &CancellationToken::default(),
        );
        let duplicate_languages = match duplicate_languages {
            Err(error) => error,
            Ok(_) => panic!("duplicate languages must fail before publication"),
        };
        assert!(
            duplicate_languages
                .to_string()
                .contains("duplicate selected resolution language")
        );

        let duplicate_masks = fixture.store.open_selected_resolution_mount_inventory(
            &fixture.workspace_id,
            &fixture.snapshots,
            &[fixture.language()],
            &[
                SelectedResolutionOverlayMask::replacement("java", "src/New.java"),
                SelectedResolutionOverlayMask::removal("java", "src/New.java"),
            ],
            &CancellationToken::default(),
        );
        let duplicate_masks = match duplicate_masks {
            Err(error) => error,
            Ok(_) => panic!("duplicate masks must fail before publication"),
        };
        assert!(
            duplicate_masks
                .to_string()
                .contains("duplicate selected resolution mask")
        );

        let mut foreign_snapshots = fixture.snapshots.clone();
        foreign_snapshots.get_mut("java").unwrap().workspace_id =
            WorkspaceId("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into());
        let foreign = fixture.store.open_selected_resolution_mount_inventory(
            &fixture.workspace_id,
            &foreign_snapshots,
            &[fixture.language()],
            &[],
            &CancellationToken::default(),
        );
        let foreign = match foreign {
            Err(error) => error,
            Ok(_) => panic!("cross-workspace snapshots must fail before publication"),
        };
        assert!(foreign.to_string().contains("different workspace"));
    }

    #[test]
    fn overlay_masks_keep_suppressed_base_and_replacement_obligations_separate() {
        let fixture = SelectionFixture::new(3);
        let masks = [
            SelectedResolutionOverlayMask::replacement("java", "src/0000.java"),
            SelectedResolutionOverlayMask::removal("java", "src/0001.java"),
            SelectedResolutionOverlayMask::replacement("java", "src/new.java"),
        ];
        let ready = fixture.open_ready(&masks);
        assert_eq!(ready.mounts().unwrap().len(), 1);
        assert_eq!(
            ready.mounts().unwrap()[0].persisted_relative_path(),
            "src/0002.java"
        );
        assert_eq!(ready.overlay_masks().unwrap().len(), 3);
        assert_eq!(
            ready
                .overlay_masks()
                .unwrap()
                .iter()
                .filter(|mask| mask.masked_base().is_some())
                .count(),
            2
        );
        assert_eq!(ready.expected_transient_replacement_count(), 2);
        assert_eq!(ready.languages().unwrap()[0].expected_base_mount_count(), 3);
        assert_eq!(ready.languages().unwrap()[0].masked_base_mount_count(), 2);
        assert_eq!(
            ready.languages().unwrap()[0].expected_unmasked_mount_count(),
            1
        );
    }

    #[test]
    fn cached_content_mounts_replace_masked_paths_without_transient_count() {
        let fixture = SelectionFixture::new(1);
        let content_mount = SelectedResolutionContentMountRequest::new(
            fixture.content_witness("0000000000000000000000000000000000000001"),
            WorkspaceFileRow {
                rel_path: "src/cached.java".to_owned(),
                blob_oid: Oid::from_str("0000000000000000000000000000000000000001").unwrap(),
            },
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let second_content_mount = SelectedResolutionContentMountRequest::new(
            fixture.content_witness("0000000000000000000000000000000000000001"),
            WorkspaceFileRow {
                rel_path: "src/cached-again.java".to_owned(),
                blob_oid: Oid::from_str("0000000000000000000000000000000000000001").unwrap(),
            },
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let ready = fixture
            .store
            .open_selected_resolution_mount_inventory_with_content_mounts(
                &fixture.workspace_id,
                &fixture.snapshots,
                &[fixture.language()],
                &[
                    SelectedResolutionOverlayMask::replacement("java", "src/cached.java"),
                    SelectedResolutionOverlayMask::replacement("java", "src/cached-again.java"),
                ],
                &[content_mount, second_content_mount],
                &CancellationToken::default(),
            )
            .unwrap();
        let ready = match ready {
            SelectedResolutionMountInventoryOutcome::Ready(ready) => ready,
            _ => panic!("cached content mount should be ready"),
        };
        assert_eq!(ready.mounts().unwrap().len(), 3);
        assert_eq!(
            ready.mounts().unwrap()[0].persisted_relative_path(),
            "src/0000.java"
        );
        assert_eq!(
            ready.mounts().unwrap()[1].persisted_relative_path(),
            "src/cached-again.java"
        );
        assert_eq!(
            ready.mounts().unwrap()[2].persisted_relative_path(),
            "src/cached.java"
        );
        assert!(
            ready.mounts().unwrap()[1..]
                .iter()
                .all(|mount| mount.file_version_id().is_none())
        );
        assert_ne!(
            ready.mounts().unwrap()[1].fragment_id(),
            ready.mounts().unwrap()[2].fragment_id()
        );
        assert_eq!(ready.expected_transient_replacement_count(), 0);
        assert_eq!(ready.languages().unwrap()[0].expected_base_mount_count(), 1);
        assert_eq!(ready.languages().unwrap()[0].masked_base_mount_count(), 0);
    }

    #[test]
    fn cached_content_mount_requires_a_published_interior() {
        let fixture = SelectionFixture::new(1);
        let content_mount = SelectedResolutionContentMountRequest::new(
            fixture.content_witness("0000000000000000000000000000000000000001"),
            WorkspaceFileRow {
                rel_path: "src/cached.java".to_owned(),
                blob_oid: Oid::from_str("0000000000000000000000000000000000000001").unwrap(),
            },
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        fixture.store.conn.execute(|conn| {
            conn.execute("DELETE FROM resolution_fragment_interiors", [])
                .unwrap();
        });
        let outcome = fixture
            .store
            .open_selected_resolution_mount_inventory_with_content_mounts(
                &fixture.workspace_id,
                &fixture.snapshots,
                &[fixture.language()],
                &[SelectedResolutionOverlayMask::replacement(
                    "java",
                    "src/cached.java",
                )],
                &[content_mount],
                &CancellationToken::default(),
            )
            .unwrap();
        assert!(matches!(
            outcome,
            SelectedResolutionMountInventoryOutcome::Unavailable(
                SelectedResolutionUnavailable::MissingInterior { .. }
            )
        ));
    }

    #[test]
    fn cached_content_mount_lookup_seeks_published_rows_before_and_after_statistics() {
        let fixture = SelectionFixture::new(128);
        let request = SelectedResolutionContentMountRequest::new(
            fixture.content_witness("0000000000000000000000000000000000000080"),
            WorkspaceFileRow {
                rel_path: "src/0000.java".to_owned(),
                blob_oid: Oid::from_str("0000000000000000000000000000000000000080").unwrap(),
            },
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let check = || {
            let outcome = fixture
                .store
                .open_selected_resolution_mount_inventory_with_content_mounts(
                    &fixture.workspace_id,
                    &fixture.snapshots,
                    &[fixture.language()],
                    &[SelectedResolutionOverlayMask::replacement(
                        "java",
                        "src/0000.java",
                    )],
                    std::slice::from_ref(&request),
                    &CancellationToken::default(),
                )
                .unwrap();
            let SelectedResolutionMountInventoryOutcome::Ready(ready) = outcome else {
                panic!("cached changed content must be available");
            };
            let plan = ready
                .connection()
                .prepare(&format!(
                    "EXPLAIN QUERY PLAN {}",
                    selected_content_mount_status_sql()
                ))
                .unwrap()
                .query_map([], |row| row.get::<_, String>(3))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            for table in ["blobs", "meta", "interiors"] {
                assert!(
                    plan.iter()
                        .any(|detail| detail.starts_with(&format!("SEARCH {table} USING "))),
                    "{plan:?}"
                );
                assert!(
                    !plan
                        .iter()
                        .any(|detail| detail.starts_with(&format!("SCAN {table}"))),
                    "{plan:?}"
                );
            }
            assert_eq!(ready.mounts().unwrap().len(), 128);
            assert_eq!(
                ready.mounts().unwrap().last().unwrap().blob_oid(),
                request.blob_oid()
            );
        };
        check();
        fixture.store.refresh_planner_statistics().unwrap();
        check();
    }

    #[test]
    fn cached_content_mount_generation_is_authoritative() {
        let fixture = SelectionFixture::new(1);
        let content_mount = SelectedResolutionContentMountRequest::new(
            fixture.content_witness("0000000000000000000000000000000000000001"),
            WorkspaceFileRow {
                rel_path: "src/cached.java".to_owned(),
                blob_oid: Oid::from_str("0000000000000000000000000000000000000001").unwrap(),
            },
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        fixture
            .store
            .ensure_language_epoch_value("java", "content-witness-next-generation")
            .unwrap();
        let outcome = fixture
            .store
            .open_selected_resolution_mount_inventory_with_content_mounts(
                &fixture.workspace_id,
                &fixture.snapshots,
                &[fixture.language()],
                &[SelectedResolutionOverlayMask::replacement(
                    "java",
                    "src/cached.java",
                )],
                &[content_mount],
                &CancellationToken::default(),
            )
            .unwrap();
        assert!(matches!(
            outcome,
            SelectedResolutionMountInventoryOutcome::Stale(
                SelectedResolutionStale::AnalysisGeneration { .. }
            )
        ));
    }

    #[test]
    fn overlay_masks_handle_exact_and_overfull_pages_in_storage_order() {
        for count in [256, 257] {
            let fixture = SelectionFixture::new(0);
            let mut masks = (0..count)
                .rev()
                .map(|index| {
                    SelectedResolutionOverlayMask::replacement(
                        "java",
                        format!("generated/{index:04}.java"),
                    )
                })
                .collect::<Vec<_>>();
            let first = fixture.open_ready(&masks);
            assert_eq!(first.overlay_masks().unwrap().len(), count);
            assert_eq!(first.expected_transient_replacement_count(), count);
            assert!(first.mounts().unwrap().is_empty());
            assert!(first.overlay_masks().unwrap().windows(2).all(|pair| {
                pair[0].persisted_relative_path() < pair[1].persisted_relative_path()
            }));
            let expected_fingerprint = first.fingerprint();
            drop(first);

            masks.reverse();
            let reordered = fixture.open_ready(&masks);
            assert_eq!(reordered.fingerprint(), expected_fingerprint);
        }
    }

    #[test]
    fn mask_exclusion_precedes_persisted_artifact_availability() {
        let fixture = SelectionFixture::new(1);
        fixture.store.conn.execute(|conn| {
            conn.execute("DELETE FROM resolution_fragment_interiors", [])
                .unwrap();
            conn.execute("UPDATE blob_meta SET is_complete = 0", [])
                .unwrap();
        });
        let ready = fixture.open_ready(&[SelectedResolutionOverlayMask::replacement(
            "java",
            "src/0000.java",
        )]);
        assert!(ready.mounts().unwrap().is_empty());
        assert!(ready.overlay_masks().unwrap()[0].masked_base().is_some());
        assert_eq!(ready.expected_transient_replacement_count(), 1);
    }

    #[test]
    fn all_masked_language_remains_distinct_from_empty_language() {
        let fixture = SelectionFixture::new(1);
        let ready = fixture.open_ready(&[SelectedResolutionOverlayMask::removal(
            "java",
            "src/0000.java",
        )]);
        assert!(ready.mounts().unwrap().is_empty());
        assert_eq!(ready.languages().unwrap()[0].expected_base_mount_count(), 1);
        assert_eq!(ready.languages().unwrap()[0].masked_base_mount_count(), 1);
        assert_eq!(
            ready.languages().unwrap()[0].expected_unmasked_mount_count(),
            0
        );
        assert_eq!(ready.expected_transient_replacement_count(), 0);
    }

    #[test]
    fn duplicate_blob_mounts_and_storage_aliases_retain_distinct_fragment_identity() {
        let fixture =
            SelectionFixture::with_language(2, "typescript:tsx", Language::TypeScript, true);
        let ready = fixture.open_ready(&[]);
        assert_eq!(
            ready.mounts().unwrap()[0].blob_id(),
            ready.mounts().unwrap()[1].blob_id()
        );
        // Two paths holding the same blob are two mounts of one content, so
        // what separates them is the mount's content key; the ordinal
        // separates them too, but only because they are two positions.
        assert_ne!(
            ready.mounts().unwrap()[0].fragment_digest(),
            ready.mounts().unwrap()[1].fragment_digest()
        );
        assert!(
            ready
                .mounts()
                .unwrap()
                .iter()
                .all(|mount| mount.storage_language() == "typescript:tsx"
                    && mount.semantic_language() == Language::TypeScript)
        );

        let c_fixture = SelectionFixture::with_language(1, "cpp:c", Language::Cpp, false);
        let c_ready = c_fixture.open_ready(&[]);
        assert_eq!(c_ready.mounts().unwrap()[0].storage_language(), "cpp:c");
        assert_eq!(
            c_ready.mounts().unwrap()[0].semantic_language(),
            Language::Cpp
        );
    }

    #[test]
    fn exact_mount_identity_restores_across_a_b_a_revisions() {
        let fixture = SelectionFixture::new(1);
        let first = fixture.open_ready(&[]).mounts().unwrap()[0].fragment_digest();
        let generation = fixture.snapshots["java"].generation;
        let workspace_id = fixture.workspace_id.as_str().to_owned();
        fixture.store.conn.execute(move |conn| {
            let tx = conn.transaction().unwrap();
            tx.execute(
                "INSERT INTO workspace_revisions(workspace_id, lang, generation, revision)
                 VALUES(?1, 'java', ?2, 2)",
                params![workspace_id, generation.0],
            )
            .unwrap();
            tx.execute(
                "UPDATE workspace_file_versions SET valid_until = 2
                 WHERE workspace_id = ?1 AND lang = 'java' AND valid_until IS NULL",
                [&workspace_id],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO workspace_file_versions(
                   workspace_id, lang, generation, rel_path, blob_oid,
                   projection_digest, valid_from
                 ) SELECT ?1, 'java', ?2, 'src/0000.java', blob_oid,
                          ?3, 2
                   FROM workspace_file_versions
                  WHERE workspace_id = ?1 AND lang = 'java' AND valid_from = 1",
                params![workspace_id, generation.0, "b".repeat(64)],
            )
            .unwrap();
            tx.execute(
                "UPDATE workspace_heads SET revision = 2
                 WHERE workspace_id = ?1 AND lang = 'java' AND generation = ?2",
                params![workspace_id, generation.0],
            )
            .unwrap();
            tx.commit().unwrap();
        });
        let mut revision_two = fixture.snapshots.clone();
        revision_two.get_mut("java").unwrap().revision = 2;
        let second = match fixture
            .store
            .open_selected_resolution_mount_inventory(
                &fixture.workspace_id,
                &revision_two,
                &[fixture.language()],
                &[],
                &CancellationToken::default(),
            )
            .unwrap()
        {
            SelectedResolutionMountInventoryOutcome::Ready(ready) => {
                ready.mounts().unwrap()[0].fragment_digest()
            }
            _ => panic!("revision B must be Ready"),
        };
        // Two revisions of one file are two contents at one mount ordinal, so
        // what separates them is the mount's content key. The ordinal is a
        // position in the selection and is the same in both.
        assert_ne!(first, second);

        let workspace_id = fixture.workspace_id.as_str().to_owned();
        fixture.store.conn.execute(move |conn| {
            let tx = conn.transaction().unwrap();
            tx.execute(
                "INSERT INTO workspace_revisions(workspace_id, lang, generation, revision)
                 VALUES(?1, 'java', ?2, 3)",
                params![workspace_id, generation.0],
            )
            .unwrap();
            tx.execute(
                "UPDATE workspace_file_versions SET valid_until = 3
                 WHERE workspace_id = ?1 AND lang = 'java' AND valid_from = 2",
                [&workspace_id],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO workspace_file_versions(
                   workspace_id, lang, generation, rel_path, blob_oid,
                   projection_digest, valid_from
                 ) SELECT ?1, 'java', ?2, 'src/0000.java', blob_oid,
                          ?3, 3
                   FROM workspace_file_versions
                  WHERE workspace_id = ?1 AND lang = 'java' AND valid_from = 1",
                params![workspace_id, generation.0, format!("{:064x}", 1)],
            )
            .unwrap();
            tx.execute(
                "UPDATE workspace_heads SET revision = 3
                 WHERE workspace_id = ?1 AND lang = 'java' AND generation = ?2",
                params![workspace_id, generation.0],
            )
            .unwrap();
            tx.commit().unwrap();
        });
        let mut revision_three = fixture.snapshots.clone();
        revision_three.get_mut("java").unwrap().revision = 3;
        let restored = match fixture
            .store
            .open_selected_resolution_mount_inventory(
                &fixture.workspace_id,
                &revision_three,
                &[fixture.language()],
                &[],
                &CancellationToken::default(),
            )
            .unwrap()
        {
            SelectedResolutionMountInventoryOutcome::Ready(ready) => {
                ready.mounts().unwrap()[0].fragment_digest()
            }
            _ => panic!("restored revision A must be Ready"),
        };
        assert_eq!(restored, first);

        let retained = fixture.open_ready(&[]);
        assert_eq!(retained.languages().unwrap()[0].revision(), 1);
        assert_eq!(retained.mounts().unwrap()[0].fragment_digest(), first);
    }

    #[test]
    fn overlapping_path_at_page_boundary_fails_closed() {
        let fixture = SelectionFixture::with_language(256, "java", Language::Java, true);
        let generation = fixture.snapshots["java"].generation;
        let workspace_id = fixture.workspace_id.as_str().to_owned();
        fixture.store.conn.execute(move |conn| {
            let tx = conn.transaction().unwrap();
            tx.execute(
                "INSERT INTO workspace_revisions(workspace_id, lang, generation, revision)
                 VALUES(?1, 'java', ?2, 2)",
                params![workspace_id, generation.0],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO workspace_file_versions(
                   workspace_id, lang, generation, rel_path, blob_oid,
                   projection_digest, valid_from, valid_until
                 ) SELECT ?1, 'java', ?2, rel_path, blob_oid,
                          projection_digest, 2, 3
                   FROM workspace_file_versions
                  WHERE workspace_id = ?1 AND lang = 'java'
                    AND rel_path = 'src/0255.java' AND valid_from = 1",
                params![workspace_id, generation.0],
            )
            .unwrap();
            tx.commit().unwrap();
        });
        let mut overlapping = fixture.snapshots.clone();
        overlapping.get_mut("java").unwrap().revision = 2;
        let result = fixture.store.open_selected_resolution_mount_inventory(
            &fixture.workspace_id,
            &overlapping,
            &[fixture.language()],
            &[],
            &CancellationToken::default(),
        );
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("overlapping selected path must fail closed"),
        };
        assert!(error.to_string().contains("overlapping file versions"));
    }

    #[test]
    fn missing_and_stale_authority_are_typed_whole_operation_outcomes() {
        let fixture = SelectionFixture::new(1);
        let missing_snapshot = fixture
            .store
            .open_selected_resolution_mount_inventory(
                &fixture.workspace_id,
                &WorkspaceSnapshots::default(),
                &[fixture.language()],
                &[],
                &CancellationToken::default(),
            )
            .unwrap();
        assert!(matches!(
            missing_snapshot,
            SelectedResolutionMountInventoryOutcome::Unavailable(
                SelectedResolutionUnavailable::MissingWorkspaceSnapshot { .. }
            )
        ));

        let language = fixture.storage_language.clone();
        fixture.store.conn.execute(move |conn| {
            conn.execute(
                "DELETE FROM resolution_producer_epochs WHERE lang = ?1",
                [language],
            )
            .unwrap();
        });
        let missing_epoch = fixture
            .store
            .open_selected_resolution_mount_inventory(
                &fixture.workspace_id,
                &fixture.snapshots,
                &[fixture.language()],
                &[],
                &CancellationToken::default(),
            )
            .unwrap();
        assert!(matches!(
            missing_epoch,
            SelectedResolutionMountInventoryOutcome::Unavailable(
                SelectedResolutionUnavailable::MissingProducerEpoch { .. }
            )
        ));

        fixture
            .store
            .ensure_resolution_producer_epoch("java", Language::Java)
            .unwrap();
        fixture.store.conn.execute(|conn| {
            conn.execute(
                "UPDATE resolution_producer_epochs SET producer_epoch = 'future'
                 WHERE lang = 'java'",
                [],
            )
            .unwrap();
        });
        let stale = fixture
            .store
            .open_selected_resolution_mount_inventory(
                &fixture.workspace_id,
                &fixture.snapshots,
                &[fixture.language()],
                &[],
                &CancellationToken::default(),
            )
            .unwrap();
        assert!(matches!(
            stale,
            SelectedResolutionMountInventoryOutcome::Stale(
                SelectedResolutionStale::ProducerEpoch { .. }
            )
        ));
    }

    #[test]
    fn bootstrap_generation_without_analysis_epoch_is_current() {
        let bootstrap = SelectionFixture::bootstrap(1);
        let epoch_rows = bootstrap.store.conn.execute(|conn| {
            conn.query_row("SELECT COUNT(*) FROM analysis_epochs", [], |row| {
                row.get::<_, usize>(0)
            })
            .unwrap()
        });
        assert_eq!(epoch_rows, 0);
        let ready = bootstrap.open_ready(&[]);
        assert_eq!(ready.languages().unwrap()[0].generation(), 0);
        drop(ready);

        let non_bootstrap = SelectionFixture::new(1);
        non_bootstrap.store.conn.execute(|conn| {
            conn.execute("DELETE FROM analysis_epochs WHERE lang = 'java'", [])
                .unwrap();
        });
        let stale = non_bootstrap
            .store
            .open_selected_resolution_mount_inventory(
                &non_bootstrap.workspace_id,
                &non_bootstrap.snapshots,
                &[non_bootstrap.language()],
                &[],
                &CancellationToken::default(),
            )
            .unwrap();
        assert!(matches!(
            stale,
            SelectedResolutionMountInventoryOutcome::Stale(
                SelectedResolutionStale::AnalysisGeneration { .. }
            )
        ));
    }

    #[test]
    fn read_change_stamp_excludes_only_committed_private_request_rows() {
        let fixture = SelectionFixture::new(1);
        let ready = fixture.open_ready(&[]);
        let mount = ready.mounts().unwrap()[0].ordinal();
        let cancellation = CancellationToken::default();
        let original = ready.read_change_stamp().unwrap();
        for key in [0, 1, 2] {
            assert!(
                ready
                    .replace_resolution_requests_1([(mount, key)], &cancellation)
                    .unwrap()
            );
            assert!(
                ready
                    .replace_resolution_requests_2([(mount, key, key)], &cancellation)
                    .unwrap()
            );
            assert_eq!(ready.read_change_stamp().unwrap(), original);
        }

        // An unrelated write before a successful carrier replacement must not
        // be swallowed by accounting for that replacement.
        ready
            .connection()
            .execute(
                "UPDATE temp.selected_resolution_mounts SET interior_digest = zeroblob(32)",
                [],
            )
            .unwrap();
        assert!(
            ready
                .replace_resolution_requests_1([(mount, 3)], &cancellation)
                .unwrap()
        );
        assert!(
            ready
                .replace_resolution_requests_2([(mount, 3, 3)], &cancellation)
                .unwrap()
        );
        let changed = ready.read_change_stamp().unwrap();
        assert_eq!(changed.unowned_changes, original.unowned_changes + 1);

        // Duplicate rows roll back the DELETE and successful first INSERT.
        // SQLite still counts their work; neither helper may neutralize it.
        assert!(
            ready
                .replace_resolution_requests_1([(mount, 4), (mount, 4)], &cancellation)
                .is_err()
        );
        let failed_one = ready.read_change_stamp().unwrap();
        assert_eq!(failed_one.unowned_changes, changed.unowned_changes + 2);
        assert!(
            ready
                .replace_resolution_requests_2([(mount, 4, 4), (mount, 4, 4)], &cancellation)
                .is_err()
        );
        let failed_two = ready.read_change_stamp().unwrap();
        assert_eq!(failed_two.unowned_changes, failed_one.unowned_changes + 2);
        assert!(
            ready
                .replace_resolution_requests_1([], &cancellation)
                .unwrap()
        );
        assert!(
            ready
                .replace_resolution_requests_2([], &cancellation)
                .unwrap()
        );
        assert_eq!(ready.read_change_stamp().unwrap(), failed_two);
    }

    #[test]
    fn read_change_stamp_observes_schema_external_and_same_connection_changes() {
        // The single-connection store retains the writable fallback; pooled
        // readers permit TEMP writes but intentionally reject main writes.
        let fixture = SelectionFixture::with_store(
            AnalyzerStore::open_in_memory_single_connection().unwrap(),
            1,
            "java",
            Language::Java,
            false,
            false,
            None,
        );
        let ready = fixture.open_ready(&[]);
        let conn = ready.connection();
        let original = ready.read_change_stamp().unwrap();
        conn.execute_batch("CREATE TEMP TABLE validation_probe(value INTEGER)")
            .unwrap();
        let temp_schema = ready.read_change_stamp().unwrap();
        assert_ne!(
            temp_schema.temp_schema_version,
            original.temp_schema_version
        );
        assert_eq!(
            temp_schema.main_schema_version,
            original.main_schema_version
        );
        conn.execute_batch("CREATE TABLE main.validation_probe(value INTEGER)")
            .unwrap();
        let main_schema = ready.read_change_stamp().unwrap();
        assert_ne!(
            main_schema.main_schema_version,
            temp_schema.main_schema_version
        );
        assert_eq!(
            main_schema.temp_schema_version,
            temp_schema.temp_schema_version
        );
        conn.execute("INSERT INTO main.validation_probe VALUES(1)", [])
            .unwrap();
        let same_connection = ready.read_change_stamp().unwrap();
        assert_eq!(
            same_connection.main_data_version,
            main_schema.main_data_version
        );
        assert_eq!(
            same_connection.unowned_changes,
            main_schema.unowned_changes + 1
        );
        let mount = ready.mounts().unwrap()[0].ordinal();
        assert!(
            ready
                .replace_resolution_requests_1([(mount, 0)], &CancellationToken::default())
                .unwrap()
        );
        assert_eq!(ready.read_change_stamp().unwrap(), same_connection);
        conn.execute_batch("VACUUM").unwrap();
        let vacuumed = ready.read_change_stamp().unwrap();
        assert_eq!(vacuumed.unowned_changes, same_connection.unowned_changes);
        assert_ne!(
            vacuumed.main_schema_version,
            same_connection.main_schema_version
        );

        let (_temp, persistent) = SelectionFixture::persistent(1);
        persistent.store.conn.execute(|writer| {
            writer
                .execute_batch("CREATE TABLE main.validation_probe(value INTEGER)")
                .unwrap();
        });
        let pooled = persistent.open_ready(&[]);
        let before_external = pooled.read_change_stamp().unwrap();
        persistent.store.conn.execute(|writer| {
            writer
                .execute("INSERT INTO main.validation_probe VALUES(2)", [])
                .unwrap();
        });
        let external = pooled.read_change_stamp().unwrap();
        assert_ne!(
            external.main_data_version,
            before_external.main_data_version
        );
        assert_eq!(
            external.main_schema_version,
            before_external.main_schema_version
        );
        assert_eq!(external.unowned_changes, before_external.unowned_changes);
    }

    #[test]
    fn missing_interior_and_incomplete_parent_cannot_disappear_from_inventory() {
        let missing = SelectionFixture::new(1);
        missing.store.conn.execute(|conn| {
            conn.execute("DELETE FROM resolution_fragment_interiors", [])
                .unwrap();
        });
        let outcome = missing
            .store
            .open_selected_resolution_mount_inventory(
                &missing.workspace_id,
                &missing.snapshots,
                &[missing.language()],
                &[],
                &CancellationToken::default(),
            )
            .unwrap();
        assert!(matches!(
            outcome,
            SelectedResolutionMountInventoryOutcome::Unavailable(
                SelectedResolutionUnavailable::MissingInterior { .. }
            )
        ));

        let incomplete = SelectionFixture::new(1);
        incomplete.store.conn.execute(|conn| {
            conn.execute("UPDATE blob_meta SET is_complete = 0", [])
                .unwrap();
        });
        let outcome = incomplete
            .store
            .open_selected_resolution_mount_inventory(
                &incomplete.workspace_id,
                &incomplete.snapshots,
                &[incomplete.language()],
                &[],
                &CancellationToken::default(),
            )
            .unwrap();
        assert!(matches!(
            outcome,
            SelectedResolutionMountInventoryOutcome::Unavailable(
                SelectedResolutionUnavailable::IncompleteParsedBlob { .. }
            )
        ));
    }

    #[test]
    fn cancellation_is_terminal_before_input_and_during_paged_materialization() {
        let fixture = SelectionFixture::with_language(257, "java", Language::Java, true);
        let cancelled = CancellationToken::default();
        cancelled.cancel();
        assert!(matches!(
            fixture
                .store
                .open_selected_resolution_mount_inventory(
                    &fixture.workspace_id,
                    &WorkspaceSnapshots::default(),
                    &[fixture.language()],
                    &[],
                    &cancelled,
                )
                .unwrap(),
            SelectedResolutionMountInventoryOutcome::Cancelled
        ));

        let writer_fixture = SelectionFixture::with_store(
            AnalyzerStore::open_in_memory_single_connection().unwrap(),
            257,
            "java",
            Language::Java,
            true,
            false,
            None,
        );
        let writer_cancelled = CancellationToken::cancel_after_checks_for_test(400);
        assert!(matches!(
            writer_fixture
                .store
                .open_selected_resolution_mount_inventory(
                    &writer_fixture.workspace_id,
                    &writer_fixture.snapshots,
                    &[writer_fixture.language()],
                    &[],
                    &writer_cancelled,
                )
                .unwrap(),
            SelectedResolutionMountInventoryOutcome::Cancelled
        ));
        drop(writer_fixture.open_ready(&[]));

        let mid_read = CancellationToken::cancel_after_checks_for_test(400);
        assert!(matches!(
            fixture
                .store
                .open_selected_resolution_mount_inventory(
                    &fixture.workspace_id,
                    &fixture.snapshots,
                    &[fixture.language()],
                    &[],
                    &mid_read,
                )
                .unwrap(),
            SelectedResolutionMountInventoryOutcome::Cancelled
        ));
    }

    #[test]
    fn post_ready_epoch_drift_revalidates_stale() {
        let fixture = SelectionFixture::new(1);
        let mut ready = fixture.open_ready(&[]);
        fixture.store.conn.execute(|conn| {
            conn.execute(
                "UPDATE resolution_producer_epochs SET producer_epoch = 'future'
                 WHERE lang = 'java'",
                [],
            )
            .unwrap();
        });
        assert!(matches!(
            ready.revalidate(&CancellationToken::default()).unwrap(),
            SelectedResolutionRevalidationOutcome::Stale(
                SelectedResolutionStale::ProducerEpoch { .. }
            )
        ));
    }

    #[test]
    fn post_ready_membership_or_artifact_loss_is_inventory_drift() {
        let membership = SelectionFixture::new(1);
        let mut ready = membership.open_ready(&[]);
        membership.store.conn.execute(|conn| {
            conn.execute("DELETE FROM workspace_file_versions", [])
                .unwrap();
        });
        assert!(matches!(
            ready.revalidate(&CancellationToken::default()).unwrap(),
            SelectedResolutionRevalidationOutcome::Stale(
                SelectedResolutionStale::MountInventoryChanged
            )
        ));
        drop(ready);

        let artifact = SelectionFixture::new(1);
        let mut ready = artifact.open_ready(&[]);
        artifact.store.conn.execute(|conn| {
            conn.execute("DELETE FROM resolution_fragment_interiors", [])
                .unwrap();
        });
        assert!(matches!(
            ready.revalidate(&CancellationToken::default()).unwrap(),
            SelectedResolutionRevalidationOutcome::Stale(
                SelectedResolutionStale::MountInventoryChanged
            )
        ));
    }

    #[test]
    fn interrupted_stage_dml_rolls_back_and_releases_reader_cancellation() {
        use super::super::resolution::with_resolution_read_progress_handler;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let fixture = SelectionFixture::new(1);
        let ready = fixture.open_ready(&[]);
        let cancellation = CancellationToken::default();
        let calls = Arc::new(AtomicUsize::new(0));
        let callback_calls = Arc::clone(&calls);
        let callback_token = cancellation.clone();
        ready
            .connection()
            .create_scalar_function(
                "cancel_stage_dml",
                1,
                rusqlite::functions::FunctionFlags::SQLITE_UTF8,
                move |context| {
                    if callback_calls.fetch_add(1, Ordering::Relaxed) + 1 == 128 {
                        callback_token.cancel();
                    }
                    context.get::<i64>(0)
                },
            )
            .unwrap();
        let committed_before = ready.retained().committed_request_changes.get();
        let cancelled = ready.with_owned_temp_transaction(|connection| {
            let interrupted = with_resolution_read_progress_handler(connection, &cancellation, |connection| {
                // Admission validation nests a handler on this same connection.
                // Its removal must leave the outer DML cancellation active.
                with_resolution_read_progress_handler(connection, &cancellation, |connection| {
                    let value: i64 = connection.query_row("SELECT 7", [], |row| row.get(0))?;
                    assert_eq!(value, 7);
                    Ok(())
                })?;
                connection.execute(
                    "WITH RECURSIVE generated(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM generated WHERE n<100000) INSERT INTO temp.selected_resolution_typed_requests_1(mount_ordinal,key0) SELECT 0,cancel_stage_dml(n) FROM generated",
                    [],
                )?;
                Ok(())
            }).expect_err("the SQL callback cancels during actual DML");
            assert!(interrupted.is_sqlite_interrupted());
            assert!(connection.is_autocommit(), "SQLite interrupt rolls back the transaction");
            Ok(SelectedResolutionTempTransaction::Rollback(true))
        }).unwrap();
        assert!(cancelled);
        assert!((128..100000).contains(&calls.load(Ordering::Relaxed)));
        assert_eq!(
            ready.retained().committed_request_changes.get(),
            committed_before
        );
        assert!(ready.connection().is_autocommit());
        let count: i64 = ready
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM temp.selected_resolution_typed_requests_1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
        // This exceeds the progress quantum while the original token remains
        // cancelled; a leaked handler would interrupt it.
        let sum: i64 = ready.connection().query_row(
            "WITH RECURSIVE generated(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM generated WHERE n<10000) SELECT sum(n) FROM generated", [], |row| row.get(0),
        ).unwrap();
        assert_eq!(sum, 50_005_000);
        ready
            .connection()
            .remove_function("cancel_stage_dml", 1)
            .unwrap();
        assert_eq!(ready.mounts().unwrap().len(), 1);
        drop(ready);
        let reused = fixture.open_ready(&[]);
        assert_eq!(reused.mounts().unwrap().len(), 1);
        assert!(reused.connection().is_autocommit());
    }

    #[test]
    fn temp_state_clears_before_active_reader_reuse() {
        let fixture = SelectionFixture::new(1);
        let ready = fixture.open_ready(&[]);
        ready
            .connection()
            .execute(
                "INSERT INTO temp.selected_resolution_typed_requests_1(mount_ordinal, key0)
                 VALUES(0, 7)",
                [],
            )
            .unwrap();
        ready
            .connection()
            .execute(
                "INSERT INTO temp.selected_resolution_typed_requests_2(mount_ordinal, key0, key1)
                 VALUES(0, 7, 42)",
                [],
            )
            .unwrap();
        drop(ready);
        let conn = fixture.store.active_read_conn().unwrap();
        for table in [
            "selected_resolution_context",
            "selected_resolution_languages",
            "selected_resolution_overlay_masks",
            "selected_resolution_content_mounts",
            "selected_resolution_mounts",
            "selected_resolution_typed_requests_1",
            "selected_resolution_typed_requests_2",
            "selected_workspace_revisions",
        ] {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM temp.{table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "{table} leaked through the active-reader pool");
        }
    }

    #[test]
    fn selected_mount_blob_index_is_recreated_and_survives_retained_state() {
        let fixture = SelectionFixture::new(1);
        let ready = fixture.open_ready(&[]);
        ready
            .connection()
            .execute_batch("DROP INDEX temp.selected_resolution_mounts_blob_ordinal")
            .unwrap();
        assert_eq!(
            ready
                .connection()
                .query_row(
                    "SELECT COUNT(*) FROM temp.sqlite_schema
                     WHERE type = 'index'
                       AND name = 'selected_resolution_mounts_blob_ordinal'",
                    [],
                    |row| row.get::<_, usize>(0),
                )
                .unwrap(),
            0
        );
        drop(ready);

        let ready = fixture.open_ready(&[]);
        assert_eq!(
            ready
                .connection()
                .prepare(
                    "SELECT name
                     FROM pragma_index_info('selected_resolution_mounts_blob_ordinal')
                     ORDER BY seqno",
                )
                .unwrap()
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap(),
            ["blob_id", "mount_ordinal"].map(str::to_owned),
            "opening a Ready selection must restore the exact TEMP covering index"
        );
        drop(ready);

        let conn = fixture.store.active_read_conn().unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM temp.selected_resolution_mounts",
                [],
                |row| row.get::<_, usize>(0),
            )
            .unwrap(),
            1,
            "the rebuilt Ready selection must retain its exact TEMP mount row"
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM temp.sqlite_schema
                 WHERE type = 'index'
                   AND name = 'selected_resolution_mounts_blob_ordinal'",
                [],
                |row| row.get::<_, usize>(0),
            )
            .unwrap(),
            1
        );
    }

    #[test]
    fn simultaneous_ready_sessions_keep_connection_local_workspace_state() {
        let (_temp, fixture) = SelectionFixture::persistent(1);
        let other_workspace =
            WorkspaceId("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
        let other_workspace_text = other_workspace.as_str().to_owned();
        let generation = fixture.snapshots["java"].generation;
        fixture.store.conn.execute(move |conn| {
            let tx = conn.transaction().unwrap();
            tx.execute(
                "INSERT INTO workspace_revisions(workspace_id, lang, generation, revision)
                 VALUES(?1, 'java', ?2, 1)",
                params![other_workspace_text, generation.0],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO workspace_heads(workspace_id, lang, generation, revision)
                 VALUES(?1, 'java', ?2, 1)",
                params![other_workspace_text, generation.0],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO workspace_file_versions(
                   workspace_id, lang, generation, rel_path, blob_oid,
                   projection_digest, valid_from
                 ) SELECT ?1, 'java', ?2, 'src/0000.java', blob_oid, ?3, 1
                     FROM blobs WHERE lang = 'java' LIMIT 1",
                params![other_workspace_text, generation.0, format!("{:064x}", 1)],
            )
            .unwrap();
            tx.commit().unwrap();
        });
        let other_snapshots = WorkspaceSnapshots::from_iter([(
            "java".to_owned(),
            WorkspaceSnapshotId {
                workspace_id: other_workspace.clone(),
                lang: "java".to_owned(),
                generation,
                revision: 1,
            },
        )]);

        let mut first = fixture.open_ready(&[]);
        let mut second = match fixture
            .store
            .open_selected_resolution_mount_inventory(
                &other_workspace,
                &other_snapshots,
                &[fixture.language()],
                &[],
                &CancellationToken::default(),
            )
            .unwrap()
        {
            SelectedResolutionMountInventoryOutcome::Ready(ready) => ready,
            _ => panic!("second exact workspace selection must be Ready"),
        };
        assert_eq!(first.workspace_id(), WORKSPACE_ID);
        assert_eq!(
            first.mounts().unwrap()[0].persisted_relative_path(),
            "src/0000.java"
        );
        assert_eq!(second.workspace_id(), other_workspace.as_str());
        assert_eq!(
            second.mounts().unwrap()[0].persisted_relative_path(),
            "src/0000.java"
        );
        // A runtime fragment is its mount's ordinal, and each selection
        // numbers its own mounts from zero, so two sessions' first mounts
        // share a fragment id and are told apart by what they mount: these
        // two name different content in different workspaces.
        assert_eq!(
            first.mounts().unwrap()[0].fragment_id(),
            second.mounts().unwrap()[0].fragment_id()
        );
        assert_ne!(
            first.mounts().unwrap()[0].fragment_digest(),
            second.mounts().unwrap()[0].fragment_digest()
        );
        assert!(!std::ptr::eq(first.connection(), second.connection()));
        for (ready, expected) in [
            (&first, fixture.workspace_id.as_str()),
            (&second, other_workspace.as_str()),
        ] {
            assert_eq!(
                ready
                    .connection()
                    .query_row(
                        "SELECT workspace_id FROM temp.selected_resolution_context",
                        [],
                        |row| row.get::<_, String>(0),
                    )
                    .unwrap(),
                expected
            );
        }
        assert_eq!(
            first.revalidate(&CancellationToken::default()).unwrap(),
            SelectedResolutionRevalidationOutcome::Current
        );
        assert_eq!(
            second.revalidate(&CancellationToken::default()).unwrap(),
            SelectedResolutionRevalidationOutcome::Current
        );
        drop(first);
        drop(second);

        let first_conn = fixture.store.active_read_conn().unwrap();
        let second_conn = fixture.store.active_read_conn().unwrap();
        assert!(!std::ptr::eq(&*first_conn, &*second_conn));
        for conn in [&*first_conn, &*second_conn] {
            for (table, expected) in [
                ("selected_resolution_context", 1),
                ("selected_resolution_languages", 1),
                ("selected_resolution_overlay_masks", 0),
                ("selected_resolution_content_mounts", 0),
                ("selected_resolution_mounts", 1),
                ("selected_resolution_typed_requests_1", 0),
                ("selected_resolution_typed_requests_2", 0),
                ("selected_workspace_revisions", 1),
            ] {
                assert_eq!(
                    conn.query_row(&format!("SELECT COUNT(*) FROM temp.{table}"), [], |row| row
                        .get::<_, usize>(0),)
                        .unwrap(),
                    expected,
                    "{table} must retain exactly one connection-local selection"
                );
            }
        }
    }

    #[test]
    fn selected_query_plans_restore_the_pooled_readers_previous_setting() {
        use rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_QPSG;

        let fixture = SelectionFixture::new(1);
        for previous in [false, true] {
            {
                let conn = fixture.store.active_read_conn().unwrap();
                conn.set_db_config(SQLITE_DBCONFIG_ENABLE_QPSG, previous)
                    .unwrap();
                conn.execute_batch("CREATE TEMP TABLE IF NOT EXISTS planner_reuse_marker(x)")
                    .unwrap();
            }
            for unwind in [false, true] {
                let result = catch_unwind(AssertUnwindSafe(|| {
                    let ready = fixture.open_ready(&[]);
                    assert!(
                        ready
                            .connection()
                            .db_config(SQLITE_DBCONFIG_ENABLE_QPSG)
                            .unwrap()
                    );
                    assert!(!unwind, "exercise selected-reader unwinding");
                }));
                assert_eq!(result.is_err(), unwind);
                let conn = fixture.store.active_read_conn().unwrap();
                assert_eq!(
                    conn.db_config(SQLITE_DBCONFIG_ENABLE_QPSG).unwrap(),
                    previous,
                    "selected planner configuration leaked after unwind={unwind}"
                );
                assert_eq!(
                    conn.query_row(
                        "SELECT COUNT(*) FROM temp.planner_reuse_marker",
                        [],
                        |row| { row.get::<_, usize>(0) }
                    )
                    .unwrap(),
                    0,
                    "the same cleaned reader must remain reusable"
                );
            }
        }
    }

    #[test]
    fn retained_selection_checkout_preserves_prepared_query_plans() {
        use rusqlite::StatementStatus;
        use rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_QPSG;

        let mut fixture = SelectionFixture::new(1);
        fixture.retain_one_reader();
        for run in 1..=3 {
            let ready = fixture.open_ready(&[]);
            let mut statement = ready
                .connection()
                .prepare_cached(
                    "SELECT workspace_id FROM temp.selected_resolution_context /* plan lifetime */",
                )
                .unwrap();
            let workspace: String = statement.query_row([], |row| row.get(0)).unwrap();
            assert_eq!(workspace, fixture.workspace_id.as_str());
            assert_eq!(statement.get_status(StatementStatus::Run), run);
            assert_eq!(
                statement.get_status(StatementStatus::RePrepare),
                0,
                "unchanged retained selection must reuse its compiled plan at run {run}"
            );
        }
        // An ordinary borrower must receive its original planner policy,
        // even when its pooled connection previously served resolution.
        let ordinary = fixture.store.active_read_conn().unwrap();
        assert!(!ordinary.db_config(SQLITE_DBCONFIG_ENABLE_QPSG).unwrap());
    }

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

    #[test]
    fn cleanup_failure_discards_pooled_reader_and_writer_fallback_fails_stop() {
        let fixture = SelectionFixture::new(1);
        let ready = fixture.open_ready(&[]);
        ready
            .connection()
            .execute_batch("DROP TABLE temp.selected_resolution_mounts")
            .unwrap();
        assert_eq!(
            ready
                .connection()
                .query_row(
                    "SELECT COUNT(*) FROM temp.sqlite_schema
                     WHERE type = 'index'
                       AND name = 'selected_resolution_mounts_blob_ordinal'",
                    [],
                    |row| row.get::<_, usize>(0),
                )
                .unwrap(),
            0,
            "dropping the TEMP mount table must also remove its connection-local index"
        );
        drop(ready);
        let conn = fixture.store.active_read_conn().unwrap();
        let table_exists = conn
            .query_row(
                "SELECT 1 FROM temp.sqlite_schema
                 WHERE type = 'table' AND name = 'selected_resolution_context'",
                [],
                |_| Ok(()),
            )
            .optional()
            .unwrap()
            .is_some();
        assert!(!table_exists, "failed cleanup connection returned to pool");
        drop(conn);

        let fallback = AnalyzerStore::open_in_memory_single_connection().unwrap();
        let panic = catch_unwind(AssertUnwindSafe(|| {
            let mut conn = fallback.active_read_conn().unwrap();
            conn.discard_before_checkin();
        }));
        assert!(
            panic.is_err(),
            "writer fallback must fail-stop on contamination"
        );
    }

    fn explain_plan(conn: &Connection, sql: &str, parameters: Vec<Value>) -> Vec<String> {
        conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .unwrap()
            .query_map(params_from_iter(parameters), |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap()
    }

    fn required_plan_step(plan: &[String], label: &str, needles: &[&str]) -> usize {
        plan.iter()
            .position(|detail| needles.iter().all(|needle| detail.contains(needle)))
            .unwrap_or_else(|| panic!("{label} needs {needles:?}: {plan:#?}"))
    }

    fn assert_plan_order(plan: &[String], label: &str, steps: &[(&str, &[&str])]) {
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

    fn assert_plan_has_no_hazards(plan: &[String], label: &str, scan_aliases: &[&str]) {
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

    fn assert_workspace_snapshot_path_seek(plan: &[String], position: usize, label: &str) {
        let detail = &plan[position];
        assert!(
            detail.contains("idx_workspace_file_versions_snapshot_path")
                || detail.contains("idx_workspace_file_versions_snapshot_kind")
                || detail.contains("sqlite_autoindex_workspace_file_versions_1"),
            "{label} must use the snapshot-path index or its exact UNIQUE prefix: {plan:#?}"
        );
    }

    #[test]
    fn selected_queries_are_context_first_keyed_and_sort_free() {
        let fixture = SelectionFixture::with_language(257, "java", Language::Java, true);
        let mut masks = (0..256)
            .map(|index| {
                SelectedResolutionOverlayMask::replacement("java", format!("src/{index:04}.java"))
            })
            .collect::<Vec<_>>();
        masks.push(SelectedResolutionOverlayMask::replacement(
            "java",
            "generated/New.java",
        ));
        let ready = fixture.open_ready(&masks);
        assert_eq!(ready.overlay_masks().unwrap().len(), 257);
        assert_eq!(ready.mounts().unwrap().len(), 1);

        let mount_index_columns = ready
            .connection()
            .prepare(
                "SELECT name
                 FROM pragma_index_info('selected_resolution_mounts_blob_ordinal')
                 ORDER BY seqno",
            )
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            mount_index_columns,
            ["blob_id", "mount_ordinal"].map(str::to_owned),
            "the selected root lookup index must retain its exact covering order"
        );

        let root_membership = explain_plan(
            ready.connection(),
            "SELECT mount_ordinal
             FROM temp.selected_resolution_mounts AS mounts
             WHERE blob_id = ?1
             ORDER BY mount_ordinal",
            vec![Value::Integer(ready.mounts().unwrap()[0].blob_id())],
        );
        required_plan_step(
            &root_membership,
            "selected root blob membership",
            &[
                "SEARCH mounts",
                "COVERING INDEX selected_resolution_mounts_blob_ordinal",
                "blob_id=?",
            ],
        );
        assert_plan_has_no_hazards(
            &root_membership,
            "selected root blob membership",
            &["mounts"],
        );

        let authority = explain_plan(ready.connection(), SELECTED_LANGUAGE_AUTHORITY_SQL, vec![]);
        assert_plan_order(
            &authority,
            "selected language authority",
            &[
                ("language input", &["SCAN languages"]),
                (
                    "selected revision",
                    &["SEARCH selected", "PRIMARY KEY", "lang=?"],
                ),
                (
                    "revision authority",
                    &[
                        "SEARCH revisions",
                        "PRIMARY KEY",
                        "workspace_id=?",
                        "lang=?",
                        "generation=?",
                        "revision=?",
                    ],
                ),
                (
                    "generation authority",
                    &["SEARCH epochs", "PRIMARY KEY", "lang=?"],
                ),
                (
                    "producer authority",
                    &["SEARCH active", "PRIMARY KEY", "lang=?"],
                ),
            ],
        );
        assert_plan_has_no_hazards(
            &authority,
            "selected language authority",
            &["selected", "revisions", "epochs", "active"],
        );

        for (label, sql, parameters, continuation) in [
            (
                "initial mask page",
                SELECTED_MASK_PAGE_INITIAL_SQL,
                vec![Value::Text("java".into())],
                false,
            ),
            (
                "continuation mask page",
                SELECTED_MASK_PAGE_CONTINUATION_SQL,
                vec![Value::Text("java".into()), Value::Text(String::new())],
                true,
            ),
        ] {
            let plan = explain_plan(ready.connection(), sql, parameters);
            let position = required_plan_step(
                &plan,
                label,
                &["SEARCH masks", "PRIMARY KEY", "storage_language=?"],
            );
            assert_eq!(position, 0, "{label} must start at the bounded mask input");
            if continuation {
                assert!(
                    plan[position].contains("persisted_relative_path>?"),
                    "continuation mask page must seek after its path cursor: {plan:#?}"
                );
            }
            assert_plan_has_no_hazards(&plan, label, &["masks"]);
        }

        let mask_base = explain_plan(
            ready.connection(),
            SELECTED_MASK_BASE_SQL,
            vec![
                Value::Text("java".into()),
                Value::Text("src/0000.java".into()),
            ],
        );
        assert_plan_order(
            &mask_base,
            "masked base point lookup",
            &[
                (
                    "selected revision",
                    &["SEARCH selected", "PRIMARY KEY", "lang=?"],
                ),
                (
                    "selected version",
                    &[
                        "SEARCH versions",
                        "workspace_id=?",
                        "lang=?",
                        "generation=?",
                        "rel_path=?",
                        "valid_from<?",
                    ],
                ),
            ],
        );
        let mask_base_version = required_plan_step(
            &mask_base,
            "masked base point lookup",
            &[
                "SEARCH versions",
                "workspace_id=?",
                "lang=?",
                "generation=?",
            ],
        );
        assert_workspace_snapshot_path_seek(
            &mask_base,
            mask_base_version,
            "masked base point lookup",
        );
        assert_plan_has_no_hazards(
            &mask_base,
            "masked base point lookup",
            &["selected", "versions"],
        );

        for (label, sql, parameters, continuation) in [
            (
                "initial selected mount page",
                selected_mount_status_sql(false),
                vec![Value::Text("java".into())],
                false,
            ),
            (
                "continuation selected mount page",
                selected_mount_status_sql(true),
                vec![
                    Value::Text("java".into()),
                    Value::Text(String::new()),
                    Value::Integer(0),
                ],
                true,
            ),
        ] {
            let plan = explain_plan(ready.connection(), sql, parameters);
            assert_plan_order(
                &plan,
                label,
                &[
                    (
                        "language input",
                        &["SEARCH languages", "PRIMARY KEY", "storage_language=?"],
                    ),
                    (
                        "selected revision",
                        &["SEARCH selected", "PRIMARY KEY", "lang=?"],
                    ),
                    (
                        "selected versions",
                        &[
                            "SEARCH versions",
                            "workspace_id=?",
                            "lang=?",
                            "generation=?",
                        ],
                    ),
                    (
                        "overlay mask",
                        &[
                            "SEARCH masks",
                            "PRIMARY KEY",
                            "storage_language=?",
                            "persisted_relative_path=?",
                        ],
                    ),
                    (
                        "blob identity",
                        &[
                            "SEARCH blobs",
                            "sqlite_autoindex_blobs_1",
                            "blob_oid=?",
                            "lang=?",
                        ],
                    ),
                    (
                        "blob completeness",
                        &["SEARCH meta", "PRIMARY KEY", "blob_id=?"],
                    ),
                    (
                        "resolution interior",
                        &["SEARCH interiors", "PRIMARY KEY", "blob_id=?"],
                    ),
                ],
            );
            let versions = required_plan_step(
                &plan,
                label,
                &[
                    "SEARCH versions",
                    "workspace_id=?",
                    "lang=?",
                    "generation=?",
                ],
            );
            assert_workspace_snapshot_path_seek(&plan, versions, label);
            if continuation {
                assert!(
                    plan[versions].contains("rel_path>?")
                        || plan[versions].contains("(rel_path,valid_from)>(?,?)"),
                    "continuation mount page must seek after its storage cursor: {plan:#?}"
                );
            }
            assert_plan_has_no_hazards(
                &plan,
                label,
                &[
                    "languages",
                    "selected",
                    "versions",
                    "masks",
                    "blobs",
                    "meta",
                    "interiors",
                ],
            );
            assert!(
                plan.iter()
                    .all(|detail| !detail.contains("resolution_semantic_terms")),
                "mount inventory must not read fact-family payloads: {plan:#?}"
            );
        }

        let mount = &ready.mounts().unwrap()[0];
        let legacy = explain_plan(
            ready.connection(),
            "SELECT 1 FROM temp.workspace_files AS files
             WHERE files.lang = ?1 AND files.generation = ?2 AND files.blob_oid = ?3
             LIMIT 1",
            vec![
                Value::Text("java".into()),
                Value::Integer(mount.generation()),
                Value::Text(mount.blob_oid().to_string()),
            ],
        );
        assert_plan_order(
            &legacy,
            "legacy workspace blob membership",
            &[
                (
                    "selected revision",
                    &["SEARCH selected", "PRIMARY KEY", "lang=?"],
                ),
                (
                    "selected blob version",
                    &[
                        "SEARCH versions",
                        "COVERING INDEX",
                        "idx_workspace_file_versions_snapshot_blob",
                        "workspace_id=?",
                        "lang=?",
                        "generation=?",
                        "blob_oid=?",
                        "valid_from<?",
                    ],
                ),
            ],
        );
        assert_plan_has_no_hazards(
            &legacy,
            "legacy workspace blob membership",
            &["selected", "versions"],
        );
        assert!(
            legacy
                .iter()
                .all(|detail| !detail.contains("idx_workspace_file_versions_snapshot_path")),
            "legacy blob membership must retain its blob-oriented index: {legacy:#?}"
        );
    }

    #[test]
    fn named_manifest_counts_round_trip_in_family_order() {
        let fixture = SelectionFixture::new(1);
        let mut ready = fixture.open_ready(&[]);
        let expected = std::array::from_fn(|index| u64::try_from(index + 1).unwrap());
        let mut mount = ready.mounts().unwrap()[0].clone();
        mount.manifest_counts = ResolutionManifestCounts::from_array(expected);
        let staged = StagedReadySelection {
            workspace_id: ready.workspace_id().to_owned(),
            languages: ready.languages().unwrap().to_vec(),
            overlay_masks: ready.overlay_masks().unwrap().to_vec(),
            mounts: vec![mount],
            fingerprint: ready.fingerprint(),
            expected_transient_replacement_count: ready.expected_transient_replacement_count(),
        };
        let tx = ready.conn.transaction().unwrap();
        tx.execute("DELETE FROM temp.selected_resolution_mounts", [])
            .unwrap();
        assert!(persist_selected_inventory(&tx, &staged, &CancellationToken::default()).unwrap());
        tx.commit().unwrap();

        let count_sql = format!(
            "SELECT {} FROM temp.selected_resolution_mounts WHERE mount_ordinal = 0",
            RESOLUTION_MANIFEST_COUNT_COLUMNS.join(", ")
        );
        let named_counts = ready
            .connection()
            .query_row(&count_sql, [], |row| {
                (0..RESOLUTION_MANIFEST_COUNT_COLUMNS.len())
                    .map(|index| row.get::<_, u64>(index))
                    .collect::<std::result::Result<Vec<_>, _>>()
            })
            .unwrap();
        assert_eq!(named_counts, expected);
        assert!(
            (0..RESOLUTION_MANIFEST_COUNT_COLUMNS.len())
                .all(|index| staged.mounts[0].manifest_counts().get(index) == expected[index])
        );
    }
}
