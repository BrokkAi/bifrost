//! Private SQL facts for the active stage and authority for the whole request.
//!
//! A stage borrows its selected inventory. Capsule bodies live in main-store
//! rows; their assigned projection lives in TEMP until stage cleanup. Complete
//! admission witnesses survive that cleanup and are checked at final release.

pub(super) mod allocation;
mod closure;
pub(super) mod codec;
pub(super) mod context;
mod coordinates;
pub(super) mod frontier_completion;
mod generated;
pub(super) mod lexical;
pub(super) mod lexical_readers;
mod projection;
mod rows;
pub(super) mod rust_context;
pub(super) mod typed;

use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension, params, params_from_iter};
use std::sync::OnceLock;

#[cfg(any(test, feature = "test-support"))]
pub(super) const CAPSULE_MEMBERSHIP_QUERY: &str = projection::CAPSULE_MEMBERSHIP_SQL;

#[cfg(any(test, feature = "test-support"))]
pub(super) const TYPED_FRONTIER_QUERY: &str = typed::VISIT_TYPED_FRONTIER_PAGES_SQL;
#[cfg(any(test, feature = "test-support"))]
pub(super) const TYPED_OBSERVATION_QUERY: &str = typed::OBSERVATION_REFERENCE_SQL;
#[cfg(any(test, feature = "test-support"))]
pub(super) const TYPED_PROPERTY_GAP_REASON_QUERY: &str =
    typed::VISIT_DEFINITION_PROPERTY_GAP_PAGES_FOR_REASONS_SQL;

use super::Result;
use super::resolution::RESOLUTION_MANIFEST_COUNT_COLUMNS;
use super::resolution_publication::{
    PublishedResolutionContent, ResolutionContentInput, ResolutionContentWitness,
};
use super::resolution_selection::{
    SelectedResolutionMountInventory, SelectedResolutionMountRecord,
    SelectedResolutionRevalidationOutcome, SelectedResolutionStale,
    SelectedResolutionTempTransaction, SelectedResolutionUnavailable,
};
use crate::CancellationToken;

pub(super) const STAGE_SCHEMA_SQL: &str = r#"
CREATE TEMP TABLE IF NOT EXISTS selected_resolution_admissions(
  admission_id INTEGER PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  storage_language TEXT NOT NULL,
  generation INTEGER NOT NULL CHECK(generation >= 0),
  revision INTEGER NOT NULL CHECK(revision > 0),
  blob_id INTEGER NOT NULL,
  blob_oid TEXT NOT NULL,
  manifest_digest BLOB NOT NULL CHECK(length(manifest_digest)=32),
  producer_epoch TEXT NOT NULL,
  logical_rows INTEGER NOT NULL CHECK(logical_rows >= 0),
  payload_bytes INTEGER NOT NULL CHECK(payload_bytes >= 0),
  input_kind INTEGER NOT NULL CHECK(input_kind IN (0,1)),
  semantic_language TEXT,
  host_content_oid TEXT,
  invocation INTEGER,
  definition_content_oid TEXT,
  selected_declaration INTEGER,
  matched_arm_index INTEGER,
  derivation_digest BLOB,
  checkpoint_digest BLOB,
  host_module_scope INTEGER,
  CHECK((input_kind=0 AND semantic_language IS NOT NULL
         AND host_content_oid IS NULL AND invocation IS NULL
         AND definition_content_oid IS NULL AND selected_declaration IS NULL
         AND matched_arm_index IS NULL AND derivation_digest IS NULL
         AND checkpoint_digest IS NULL AND host_module_scope IS NULL)
     OR (input_kind=1 AND semantic_language IS NULL
         AND host_content_oid IS NOT NULL AND invocation IS NOT NULL
         AND definition_content_oid IS NOT NULL AND selected_declaration IS NOT NULL
         AND matched_arm_index IS NOT NULL AND derivation_digest IS NOT NULL AND length(derivation_digest)=32
         AND checkpoint_digest IS NOT NULL AND length(checkpoint_digest)=32 AND host_module_scope IS NOT NULL)),
  UNIQUE(workspace_id,storage_language,generation,revision,blob_oid)
) STRICT;
CREATE INDEX IF NOT EXISTS temp.selected_resolution_admissions_invocation
 ON selected_resolution_admissions(workspace_id,storage_language,generation,revision,host_content_oid,invocation)
 WHERE input_kind=1;
CREATE TEMP TABLE IF NOT EXISTS selected_resolution_admission_counts(
  admission_id INTEGER NOT NULL REFERENCES selected_resolution_admissions(admission_id) ON DELETE CASCADE,
  family INTEGER NOT NULL CHECK(family >= 0),
  family_name TEXT NOT NULL,
  count INTEGER NOT NULL CHECK(count >= 0),
  PRIMARY KEY(admission_id,family),
  UNIQUE(admission_id,family_name)
) WITHOUT ROWID, STRICT;
CREATE TEMP TABLE IF NOT EXISTS selected_resolution_stage_producers(
  producer_id INTEGER PRIMARY KEY,
  host_ordinal INTEGER NOT NULL CHECK(host_ordinal >= 0),
  admission_id INTEGER REFERENCES selected_resolution_admissions(admission_id) ON DELETE CASCADE,
  bridge_identity BLOB,
  content_digest BLOB,
  CHECK((admission_id IS NOT NULL AND bridge_identity IS NULL AND content_digest IS NULL)
     OR (admission_id IS NULL AND bridge_identity IS NOT NULL AND length(bridge_identity)=32 AND content_digest IS NOT NULL AND length(content_digest)=32))
) STRICT;
CREATE UNIQUE INDEX IF NOT EXISTS temp.selected_resolution_stage_capsule
  ON selected_resolution_stage_producers(host_ordinal,admission_id) WHERE admission_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS temp.selected_resolution_stage_bridge
  ON selected_resolution_stage_producers(host_ordinal,bridge_identity) WHERE bridge_identity IS NOT NULL;
"#;

pub(super) fn schema_sql() -> &'static str {
    static SQL: OnceLock<String> = OnceLock::new();
    SQL.get_or_init(|| {
        let sql = {
            format!(
                "{STAGE_SCHEMA_SQL}{}{}",
                rows::schema_sql(),
                context::SCHEMA_SQL
            )
        };
        #[cfg(test)]
        crate::analyzer::store::resolution_selection::note_selected_static_sql_capacity(
            5,
            sql.capacity(),
        );
        sql
    })
}

pub(super) const CLEAR_REQUEST_SQL: &str = "DELETE FROM temp.selected_resolution_stage_producers; DELETE FROM temp.selected_resolution_stage_nodes; DELETE FROM temp.selected_resolution_admissions; DELETE FROM temp.selected_resolution_contexts; DELETE FROM temp.selected_resolution_stage_allocation_counters;";

pub(crate) enum SelectedResolutionStageOutcome {
    Ready,
    Cancelled,
    Unavailable(SelectedResolutionUnavailable),
    Stale(SelectedResolutionStale),
}

/// A view, never an owner of a lexical or typed fact collection.
pub(crate) struct SelectedResolutionStage<'selection, 'store> {
    selection: &'selection SelectedResolutionMountInventory<'store>,
}

impl<'selection, 'store> SelectedResolutionStage<'selection, 'store> {
    pub(crate) fn new(selection: &'selection SelectedResolutionMountInventory<'store>) -> Self {
        Self { selection }
    }

    pub(crate) fn clear_facts(&self) -> Result<()> {
        let changed = self.selection.with_owned_temp_transaction(|connection| {
            let before = connection.total_changes();
            let producers =
                connection.execute("DELETE FROM temp.selected_resolution_stage_producers", [])?;
            connection.execute("DELETE FROM temp.selected_resolution_stage_nodes", [])?;
            let deleted = connection
                .total_changes()
                .checked_sub(before)
                .expect("a stage clear cannot lower SQLite total changes");
            let content_changed = deleted
                .checked_sub(producers as u64)
                .expect("total changes include directly deleted producer rows")
                != 0;
            Ok(SelectedResolutionTempTransaction::Commit(content_changed))
        })?;
        if changed {
            self.selection.note_stage_content_commit();
        }
        Ok(())
    }

    /// Commit the witness and its entire projection together. The callback is
    /// one capsule's row conversion, not an engine reader or retained service.
    pub(super) fn with_capsule_admission(
        &self,
        content: PublishedResolutionContent,
        host: &SelectedResolutionMountRecord,
        dense: crate::analyzer::resolution::LoweredResolutionFactsWithIdentityCatalog,
        cancellation: &CancellationToken,
        project: impl FnOnce(
            &Connection,
            i64,
            &crate::analyzer::resolution::LoweredResolutionFactsWithIdentityCatalog,
        ) -> Result<bool>,
    ) -> Result<SelectedResolutionStageOutcome> {
        if cancellation.is_cancelled() {
            return Ok(SelectedResolutionStageOutcome::Cancelled);
        }
        let (witness, membership) = content.into_parts();
        let owner = witness.owner();
        let host_agrees = owner.workspace_id.as_str() == host.workspace_id()
            && owner.lang == host.storage_language()
            && owner.generation.get() == host.generation()
            && owner.revision == host.revision()
            && matches!(witness.input(), ResolutionContentInput::Capsule { key, .. }
                if key.host_content_oid == host.blob_oid());
        if !host_agrees {
            return Ok(SelectedResolutionStageOutcome::Unavailable(
                SelectedResolutionUnavailable::InteriorOwnershipMismatch {
                    storage_language: host.storage_language().to_owned(),
                    persisted_relative_path: host.persisted_relative_path().to_owned(),
                },
            ));
        }

        if !self
            .selection
            .shared_name_table()
            .admit_persisted_names(&membership, cancellation)
        {
            return Ok(SelectedResolutionStageOutcome::Cancelled);
        }
        drop(membership);
        self.selection.mark_stage_used();
        let mut content_changed = false;
        let outcome = self.selection.with_owned_temp_transaction(|connection| {
            let projected = super::resolution::with_resolution_read_progress_handler(
                connection, cancellation, |connection| {
            let Some(admission) = insert_admission(connection, &witness)? else {
                return Ok(SelectedResolutionTempTransaction::Rollback(SelectedResolutionStageOutcome::Unavailable(
                    SelectedResolutionUnavailable::InteriorOwnershipMismatch {
                        storage_language: host.storage_language().to_owned(),
                        persisted_relative_path: host.persisted_relative_path().to_owned(),
                    },
                )));
            };
            match validate_admission(connection, admission, cancellation)? {
                SelectedResolutionRevalidationOutcome::Cancelled => return Ok(SelectedResolutionTempTransaction::Rollback(SelectedResolutionStageOutcome::Cancelled)),
                SelectedResolutionRevalidationOutcome::Stale(reason) => {
                    // Do not commit the just-inserted witness on failed authority.
                    return Ok(SelectedResolutionTempTransaction::Rollback(SelectedResolutionStageOutcome::Stale(reason)));
                }
                SelectedResolutionRevalidationOutcome::Current => {}
            }
            let previous = connection.prepare_cached(
                "SELECT producer_id FROM temp.selected_resolution_stage_producers WHERE host_ordinal=?1 AND admission_id=?2"
            )?.query_row(params![host.ordinal().get(), admission], |row| row.get::<_, i64>(0)).optional()?;
            let runtime = match previous {
                Some(producer) => allocation::replay_catalog(self.selection, connection, producer, host.ordinal(), dense.identities(), cancellation)?,
                None => allocation::assign_catalog(self.selection, connection, host.ordinal(), dense.identities(), cancellation)?,
            };
            let Some(runtime) = runtime else {
                return Ok(SelectedResolutionTempTransaction::Rollback(SelectedResolutionStageOutcome::Cancelled));
            };
            let Some(assigned) = dense.retargeted(&runtime, cancellation) else {
                return Ok(SelectedResolutionTempTransaction::Rollback(SelectedResolutionStageOutcome::Cancelled));
            };
            drop(runtime);
            assert_eq!(assigned.lexical().fragment(), assigned.typed().fragment());
            assert_eq!(assigned.lexical().language(), assigned.typed().language());
            assert_eq!(assigned.lexical().fragment(), assigned.identities().fragment());
            assert_eq!(assigned.identities().fragment().ordinal(), host.ordinal().get());
            let Some(coordinates) = coordinates::PreparedStageCoordinates::new(assigned.identities(), &assigned.common().root_import_provenance, cancellation) else {
                return Ok(SelectedResolutionTempTransaction::Rollback(SelectedResolutionStageOutcome::Cancelled));
            };
            let Some(coordinates) = coordinates.with_package_metadata(&assigned.common().package_references, &assigned.common().package_members, cancellation) else {
                return Ok(SelectedResolutionTempTransaction::Rollback(SelectedResolutionStageOutcome::Cancelled));
            };
            let Some(coordinates) = coordinates.with_go_import_metadata(&assigned.common().go_package_imports, cancellation) else {
                return Ok(SelectedResolutionTempTransaction::Rollback(SelectedResolutionStageOutcome::Cancelled));
            };
            if let Some(producer) = previous {
                if !coordinates.agrees(connection, producer)? {
                    return Err(super::StoreError::new("repeated capsule admission changed its assigned identity catalog"));
                }
                return Ok(if cancellation.is_cancelled() {
                    SelectedResolutionTempTransaction::Rollback(SelectedResolutionStageOutcome::Cancelled)
                } else {
                    SelectedResolutionTempTransaction::Commit(SelectedResolutionStageOutcome::Ready)
                });
            }
            connection
                .prepare_cached(
                    "INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,admission_id) VALUES(?1,?2)",
                )?
                .execute(params![host.ordinal().get(), admission])?;
            let producer = connection.last_insert_rowid();
            let content_before = connection.total_changes();
            coordinates.insert(connection, producer, host.ordinal())?;
            let ResolutionContentInput::Capsule { key, .. } = witness.input() else {
                unreachable!("capsule admission has an authenticated capsule witness");
            };
            closure::insert_capsule_closed_reasons(connection, producer, host, key.invocation)?;
            if !lexical::insert_capsule_source(connection, producer, host.ordinal(), witness.blob_id(), cancellation)?
                || !project(connection, producer, &assigned)? || cancellation.is_cancelled() {
                return Ok(SelectedResolutionTempTransaction::Rollback(SelectedResolutionStageOutcome::Cancelled));
            }
            content_changed = connection.total_changes() != content_before;
            Ok(SelectedResolutionTempTransaction::Commit(SelectedResolutionStageOutcome::Ready))
                },
            );
            match projected {
                Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => {
                    Ok(SelectedResolutionTempTransaction::Rollback(SelectedResolutionStageOutcome::Cancelled))
                }
                outcome => outcome,
            }
        })?;
        if content_changed && matches!(outcome, SelectedResolutionStageOutcome::Ready) {
            self.selection.note_stage_content_commit();
        }
        Ok(outcome)
    }
}

const WITNESS_COLUMNS: &str = "workspace_id,storage_language,generation,revision,blob_id,blob_oid,manifest_digest,producer_epoch,logical_rows,payload_bytes,input_kind,semantic_language,host_content_oid,invocation,definition_content_oid,selected_declaration,matched_arm_index,derivation_digest,checkpoint_digest,host_module_scope";

fn witness_cells(witness: &ResolutionContentWitness) -> Vec<Value> {
    let owner = witness.owner();
    let mut cells = vec![
        Value::Text(owner.workspace_id.as_str().to_owned()),
        Value::Text(owner.lang.clone()),
        Value::Integer(owner.generation.0),
        Value::Integer(owner.revision),
        Value::Integer(witness.blob_id()),
        Value::Text(witness.blob_oid().to_string()),
        Value::Blob(witness.manifest_digest().to_vec()),
        Value::Text(witness.producer_epoch().to_owned()),
        Value::Integer(
            i64::try_from(witness.logical_rows()).expect("manifest rows fit SQLite INTEGER"),
        ),
        Value::Integer(
            i64::try_from(witness.payload_bytes()).expect("manifest payload fits SQLite INTEGER"),
        ),
    ];
    match witness.input() {
        ResolutionContentInput::Parsed {
            content_oid,
            semantic_language,
        } => {
            assert_eq!(*content_oid, witness.blob_oid());
            cells.extend([
                Value::Integer(0),
                Value::Text(semantic_language.config_label().to_owned()),
            ]);
            cells.extend(std::iter::repeat_n(Value::Null, 8));
        }
        ResolutionContentInput::Capsule {
            key,
            checkpoint_digest,
            host_module_scope,
        } => {
            assert_eq!(key.producer_epoch, witness.producer_epoch());
            cells.extend([
                Value::Integer(1),
                Value::Null,
                Value::Text(key.host_content_oid.to_string()),
                Value::Integer(i64::from(key.invocation.get())),
                Value::Text(key.definition_content_oid.to_string()),
                Value::Integer(i64::from(key.selected_declaration.get())),
                Value::Integer(
                    i64::try_from(key.matched_arm_index).expect("matched arm fits SQLite INTEGER"),
                ),
                Value::Blob(key.digest().to_vec()),
                Value::Blob(checkpoint_digest.to_vec()),
                Value::Integer(i64::from(host_module_scope.get())),
            ]);
        }
    }
    cells
}

/// A complete exact witness is idempotent. Same input with changed authority
/// is an ownership mismatch, never replacement. Counts include known empties.
fn insert_admission(
    connection: &Connection,
    witness: &ResolutionContentWitness,
) -> Result<Option<i64>> {
    let cells = witness_cells(witness);
    let sql = format!(
        "SELECT admission_id,{WITNESS_COLUMNS} FROM temp.selected_resolution_admissions WHERE workspace_id=?1 AND storage_language=?2 AND generation=?3 AND revision=?4 AND blob_oid=?5"
    );
    let prior = connection
        .prepare_cached(&sql)?
        .query_row(
            params![cells[0], cells[1], cells[2], cells[3], cells[5]],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    (0..cells.len())
                        .map(|index| row.get::<_, Value>(index + 1))
                        .collect::<rusqlite::Result<Vec<_>>>()?,
                ))
            },
        )
        .optional()?;
    let counts = RESOLUTION_MANIFEST_COUNT_COLUMNS
        .iter()
        .copied()
        .zip(witness.manifest_counts().values().iter().copied())
        .collect::<Vec<_>>();
    assert_eq!(counts.len(), RESOLUTION_MANIFEST_COUNT_COLUMNS.len());
    let counts_json =
        serde_json::to_string(&counts).expect("named scalar manifest counts serialize");
    if let Some((admission, previous)) = prior {
        if previous != cells {
            return Ok(None);
        }
        let agrees: bool = connection.query_row(
            "SELECT (SELECT COUNT(*) FROM temp.selected_resolution_admission_counts WHERE admission_id=?1)=json_array_length(?2) AND NOT EXISTS(SELECT 1 FROM json_each(?2) expected LEFT JOIN temp.selected_resolution_admission_counts actual ON actual.admission_id=?1 AND actual.family=expected.key WHERE actual.family_name IS NOT expected.value->>0 OR actual.count IS NOT expected.value->>1)",
            params![admission, counts_json], |row| row.get(0),
        )?;
        return Ok(agrees.then_some(admission));
    }
    let placeholders = (1..=cells.len())
        .map(|index| format!("?{index}"))
        .collect::<Vec<_>>()
        .join(",");
    connection.execute(&format!("INSERT INTO temp.selected_resolution_admissions({WITNESS_COLUMNS}) VALUES({placeholders})"), params_from_iter(cells))?;
    let admission = connection.last_insert_rowid();
    connection.execute(
        "INSERT INTO temp.selected_resolution_admission_counts(admission_id,family,family_name,count) SELECT ?1,key,value->>0,value->>1 FROM json_each(?2)",
        params![admission, counts_json],
    )?;
    Ok(Some(admission))
}

/// One request-wide query validates earlier stages as well as the active one.
/// The query scans only request admissions; all durable joins use their keys.
pub(super) fn validate_admissions(
    connection: &Connection,
    cancellation: &CancellationToken,
) -> Result<SelectedResolutionRevalidationOutcome> {
    if cancellation.is_cancelled() {
        return Ok(SelectedResolutionRevalidationOutcome::Cancelled);
    }
    super::resolution::with_resolution_read_progress_handler(
        connection,
        cancellation,
        |connection| {
            let mut statement = connection.prepare_cached(admission_validation_sql())?;
            let mut rows = statement.query([])?;
            validation_outcome(&mut rows, cancellation)
        },
    )
    .or_else(|error| {
        if error.is_sqlite_interrupted() && cancellation.is_cancelled() {
            Ok(SelectedResolutionRevalidationOutcome::Cancelled)
        } else {
            Err(error)
        }
    })
}

fn validate_admission(
    connection: &Connection,
    admission: i64,
    cancellation: &CancellationToken,
) -> Result<SelectedResolutionRevalidationOutcome> {
    static SQL: OnceLock<String> = OnceLock::new();
    let sql = SQL.get_or_init(|| {
        let sql = format!("WITH requested_admissions AS (SELECT * FROM temp.selected_resolution_admissions WHERE admission_id=?1) {}", admission_validation_body());
        #[cfg(test)]
        crate::analyzer::store::resolution_selection::note_selected_static_sql_capacity(6, sql.capacity());
        sql
    });
    if cancellation.is_cancelled() {
        return Ok(SelectedResolutionRevalidationOutcome::Cancelled);
    }
    super::resolution::with_resolution_read_progress_handler(
        connection,
        cancellation,
        |connection| {
            let mut statement = connection.prepare_cached(sql)?;
            let mut rows = statement.query([admission])?;
            validation_outcome(&mut rows, cancellation)
        },
    )
    .or_else(|error| {
        if error.is_sqlite_interrupted() && cancellation.is_cancelled() {
            Ok(SelectedResolutionRevalidationOutcome::Cancelled)
        } else {
            Err(error)
        }
    })
}

fn validation_outcome(
    rows: &mut rusqlite::Rows<'_>,
    cancellation: &CancellationToken,
) -> Result<SelectedResolutionRevalidationOutcome> {
    let Some(row) = rows.next()? else {
        return Ok(if cancellation.is_cancelled() {
            SelectedResolutionRevalidationOutcome::Cancelled
        } else {
            SelectedResolutionRevalidationOutcome::Current
        });
    };
    if cancellation.is_cancelled() {
        return Ok(SelectedResolutionRevalidationOutcome::Cancelled);
    }
    let language: String = row.get(0)?;
    let kind: i64 = row.get(1)?;
    Ok(SelectedResolutionRevalidationOutcome::Stale(match kind {
        1 => SelectedResolutionStale::AnalysisGeneration {
            storage_language: language,
        },
        2 => SelectedResolutionStale::ProducerEpoch {
            storage_language: language,
        },
        3 => SelectedResolutionStale::WorkspaceRevision {
            storage_language: language,
        },
        4 => SelectedResolutionStale::MountInventoryChanged,
        _ => unreachable!("validation emits one of four stale kinds"),
    }))
}

fn admission_validation_sql() -> &'static str {
    static SQL: OnceLock<String> = OnceLock::new();
    SQL.get_or_init(|| {
        let sql = {
        format!(
            "WITH requested_admissions AS (SELECT * FROM temp.selected_resolution_admissions) {}",
            admission_validation_body()
        )
    };
        #[cfg(test)]
        crate::analyzer::store::resolution_selection::note_selected_static_sql_capacity(7, sql.capacity());
        sql
    })
}

fn admission_validation_body() -> &'static str {
    static SQL: OnceLock<String> = OnceLock::new();
    SQL.get_or_init(|| {
        let sql = {
        let counts = RESOLUTION_MANIFEST_COUNT_COLUMNS.iter().map(|column| format!("json_array('{column}',manifest.{column})")).collect::<Vec<_>>().join(",");
        format!(r#"
SELECT admission.storage_language,
 CASE WHEN COALESCE(epoch.generation,0) IS NOT admission.generation THEN 1
      WHEN producer.producer_epoch IS NOT admission.producer_epoch THEN 2
      WHEN revision.revision IS NULL THEN 3 ELSE 4 END
FROM requested_admissions admission
LEFT JOIN main.analysis_epochs epoch ON epoch.lang=admission.storage_language
LEFT JOIN main.resolution_producer_epochs producer ON producer.lang=admission.storage_language
LEFT JOIN main.workspace_revisions revision
 ON revision.workspace_id=admission.workspace_id AND revision.lang=admission.storage_language
 AND revision.generation=admission.generation AND revision.revision=admission.revision
LEFT JOIN main.workspace_resolution_content_roots root
 ON root.workspace_id=admission.workspace_id AND root.lang=admission.storage_language
 AND root.generation=admission.generation AND root.revision=admission.revision AND root.blob_id=admission.blob_id
LEFT JOIN main.blobs blob ON blob.id=admission.blob_id
LEFT JOIN main.resolution_fragment_interiors manifest ON manifest.blob_id=admission.blob_id
LEFT JOIN main.resolution_capsule_inputs capsule ON capsule.blob_id=admission.blob_id
WHERE COALESCE(epoch.generation,0) IS NOT admission.generation
 OR producer.producer_epoch IS NOT admission.producer_epoch
 OR revision.revision IS NULL OR root.blob_id IS NULL
 OR blob.blob_oid IS NOT admission.blob_oid OR blob.lang IS NOT admission.storage_language
 OR blob.generation IS NOT admission.generation OR manifest.publication_state IS NOT 'complete'
 OR manifest.producer_epoch IS NOT admission.producer_epoch
 OR manifest.interior_digest IS NOT admission.manifest_digest
 OR manifest.logical_rows IS NOT admission.logical_rows OR manifest.payload_bytes IS NOT admission.payload_bytes
 OR (admission.input_kind=0 AND manifest.semantic_language IS NOT admission.semantic_language)
 OR (admission.input_kind=1 AND (
      capsule.host_content_oid IS NOT admission.host_content_oid OR capsule.invocation IS NOT admission.invocation
   OR capsule.definition_content_oid IS NOT admission.definition_content_oid OR capsule.selected_declaration IS NOT admission.selected_declaration
   OR capsule.matched_arm_index IS NOT admission.matched_arm_index OR capsule.producer_epoch IS NOT admission.producer_epoch
   OR capsule.derivation_digest IS NOT admission.derivation_digest OR capsule.checkpoint_digest IS NOT admission.checkpoint_digest
   OR capsule.host_module_scope IS NOT admission.host_module_scope))
 OR (SELECT COUNT(*) FROM temp.selected_resolution_admission_counts c WHERE c.admission_id=admission.admission_id)<>{count}
 OR EXISTS(SELECT 1 FROM json_each(json_array({counts})) actual
 LEFT JOIN temp.selected_resolution_admission_counts expected
   ON expected.admission_id=admission.admission_id AND expected.family=actual.key
 WHERE expected.family_name IS NOT actual.value->>0 OR expected.count IS NOT actual.value->>1)
LIMIT 1
"#, count=RESOLUTION_MANIFEST_COUNT_COLUMNS.len())
    };
        #[cfg(test)]
        crate::analyzer::store::resolution_selection::note_selected_static_sql_capacity(8, sql.capacity());
        sql
    })
}
