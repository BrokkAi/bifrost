//! Immutable request-owned path contexts, addressed only by an explicit token.

use super::{SelectedResolutionStage, codec, lexical};
use crate::CancellationToken;
use crate::analyzer::resolution::{CandidatePathIdentity, PartialPath, SelectedContextPathToken};
use crate::analyzer::store::resolution::with_resolution_read_progress_handler;
use crate::analyzer::store::resolution_selection::SelectedResolutionTempTransaction;
use crate::analyzer::store::{Result, StoreError};
use rusqlite::{Connection, OptionalExtension, params};
use std::sync::atomic::{AtomicI64, Ordering};

pub(super) const SCHEMA_SQL: &str = r#"
CREATE TEMP TABLE IF NOT EXISTS selected_resolution_contexts(
 context_id INTEGER PRIMARY KEY CHECK(context_id>0)
) STRICT;
CREATE TEMP TABLE IF NOT EXISTS selected_resolution_context_paths(
 context_id INTEGER NOT NULL REFERENCES selected_resolution_contexts(context_id) ON DELETE CASCADE,
 host_ordinal INTEGER NOT NULL CHECK(host_ordinal>=0),
 path INTEGER NOT NULL CHECK(path>=0),
 start_node INTEGER NOT NULL CHECK(start_node>=0),
 end_node INTEGER NOT NULL CHECK(end_node>=0),
 start_lead_key INTEGER CHECK(start_lead_key IS NULL OR start_lead_key>=0),
 start_lead_shared INTEGER CHECK(start_lead_shared IS NULL OR start_lead_shared>0),
 end_lead_key INTEGER CHECK(end_lead_key IS NULL OR end_lead_key>=0),
 end_lead_shared INTEGER CHECK(end_lead_shared IS NULL OR end_lead_shared>0),
 body BLOB NOT NULL CHECK(json_valid(body,8)),
 CHECK(start_lead_key IS NULL OR start_lead_shared IS NULL),
 CHECK(end_lead_key IS NULL OR end_lead_shared IS NULL),
 PRIMARY KEY(context_id,host_ordinal,path)
) WITHOUT ROWID, STRICT;
CREATE INDEX IF NOT EXISTS temp.selected_resolution_context_paths_forward
 ON selected_resolution_context_paths(context_id,start_node,start_lead_shared,start_lead_key,host_ordinal,path);
CREATE INDEX IF NOT EXISTS temp.selected_resolution_context_paths_reverse
 ON selected_resolution_context_paths(context_id,end_node,end_lead_shared,end_lead_key,host_ordinal,path);
"#;

fn mint_context_token() -> SelectedContextPathToken {
    static NEXT: AtomicI64 = AtomicI64::new(1);
    let value = NEXT
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .expect("selected context token space exhausted");
    SelectedContextPathToken::new(value)
}

/// Call within the reader's existing progress/read scope before using its token.
pub(in crate::analyzer::store) fn require_context(
    connection: &Connection,
    context: SelectedContextPathToken,
) -> Result<()> {
    let exists: bool = connection
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM temp.selected_resolution_contexts WHERE context_id=?1)",
        )?
        .query_row([context.get()], |row| row.get(0))?;
    if !exists {
        return Err(StoreError::new(format!(
            "selected context token has no request-owned rows: {context:?}"
        )));
    }
    Ok(())
}

/// One transaction's borrowed writer, with no retained path collection.
pub(crate) struct SelectedContextPathWriter<'a> {
    connection: &'a Connection,
    context: SelectedContextPathToken,
    cancellation: &'a CancellationToken,
}

impl SelectedContextPathWriter<'_> {
    pub(crate) fn insert(
        &mut self,
        identity: CandidatePathIdentity,
        path: &PartialPath,
    ) -> Result<bool> {
        if self.cancellation.is_cancelled() {
            return Ok(false);
        }
        let start = path
            .start()
            .symbols()
            .fixed()
            .first()
            .map(|symbol| lexical::semantic_cells(symbol.symbol()))
            .unwrap_or((None, None));
        let end = path
            .end()
            .symbols()
            .fixed()
            .first()
            .map(|symbol| lexical::semantic_cells(symbol.symbol()))
            .unwrap_or((None, None));
        let start_node = codec::encode_node(path.start().node());
        let end_node = codec::encode_node(path.end().node());
        let body = codec::encode_path(path);
        let values = params![
            self.context.get(),
            identity.fragment().ordinal(),
            codec::encode_path_id(identity.path()),
            start_node,
            end_node,
            start.0,
            start.1,
            end.0,
            end.1,
            body
        ];
        let previous = self.connection.prepare_cached(
            "SELECT CASE WHEN p.path IS NULL THEN NULL ELSE p.start_node=?4 AND p.end_node=?5 AND p.start_lead_key IS ?6 AND p.start_lead_shared IS ?7 AND p.end_lead_key IS ?8 AND p.end_lead_shared IS ?9 AND p.body IS jsonb(?10) END FROM temp.selected_resolution_mounts m LEFT JOIN temp.selected_resolution_context_paths p ON p.context_id=?1 AND p.host_ordinal=m.mount_ordinal AND p.path=?3 WHERE m.mount_ordinal=?2",
        )?.query_row(values, |row| row.get::<_,Option<bool>>(0)).optional()?;
        let Some(previous) = previous else {
            return Err(StoreError::new(format!(
                "selected context candidate has no selected host: {identity:?}"
            )));
        };
        match previous {
            Some(true) => {}
            Some(false) => {
                return Err(StoreError::new(format!(
                    "selected context candidate changed its complete path: {identity:?}"
                )));
            }
            None => {
                self.connection
                    .prepare_cached(
                        "INSERT INTO temp.selected_resolution_context_paths(context_id,host_ordinal,path,start_node,end_node,start_lead_key,start_lead_shared,end_lead_key,end_lead_shared,body) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,jsonb(?10))",
                    )?
                    .execute(values)?;
            }
        }
        Ok(!self.cancellation.is_cancelled())
    }
}

impl SelectedResolutionStage<'_, '_> {
    /// Publish one immutable context atomically. The callback compiles one
    /// descriptor at a time; only committed rows yield a request authority token.
    pub(crate) fn publish_context_paths(
        &self,
        cancellation: &CancellationToken,
        publish: impl FnOnce(&mut SelectedContextPathWriter<'_>) -> Result<bool>,
    ) -> Result<Option<SelectedContextPathToken>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let context = mint_context_token();
        self.selection.mark_stage_used();
        self.selection.with_owned_temp_transaction(|connection| {
            let result =
                with_resolution_read_progress_handler(connection, cancellation, |connection| {
                    connection
                        .prepare_cached(
                            "INSERT INTO temp.selected_resolution_contexts(context_id) VALUES(?1)",
                        )?
                        .execute([context.get()])?;
                    let mut writer = SelectedContextPathWriter {
                        connection,
                        context,
                        cancellation,
                    };
                    Ok(if !publish(&mut writer)? || cancellation.is_cancelled() {
                        SelectedResolutionTempTransaction::Rollback(None)
                    } else {
                        SelectedResolutionTempTransaction::Commit(Some(context))
                    })
                });
            match result {
                Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => {
                    Ok(SelectedResolutionTempTransaction::Rollback(None))
                }
                outcome => outcome,
            }
        })
    }
}

#[cfg(test)]
#[path = "context_tests.rs"]
mod tests;
