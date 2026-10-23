//! Immutable request-owned path contexts, addressed only by an explicit token.

use super::{SelectedResolutionStage, codec, lexical};
use crate::CancellationToken;
use crate::analyzer::resolution::{CandidatePathIdentity, PartialPath, SelectedContextPathToken};
use crate::analyzer::store::resolution::with_resolution_read_progress_handler;
use crate::analyzer::store::resolution_selection::{
    SelectedResolutionMountInventory, SelectedResolutionTempTransaction,
};
use crate::analyzer::store::{Result, StoreError};
use rusqlite::{Connection, OptionalExtension, params};
use std::sync::atomic::{AtomicI64, Ordering};

#[doc(hidden)]
pub const REUSED_CONTEXT_CELL_COPY: &str = "INSERT INTO temp.selected_resolution_context_paths SELECT ?2,source.host_ordinal,source.path,source.start_node,source.end_node,source.start_lead_key,source.start_lead_shared,source.end_lead_key,source.end_lead_shared,source.body FROM json_each(?1) input CROSS JOIN temp.selected_resolution_context_paths source ON source.context_id=input.value->>0 AND source.host_ordinal=input.value->>1 AND source.path=input.value->>2 WHERE NOT EXISTS (SELECT 1 FROM temp.selected_resolution_context_paths target WHERE target.context_id=?2 AND target.host_ordinal=source.host_ordinal AND target.path=source.path)";

#[doc(hidden)]
pub const REUSED_CONTEXT_CELL_MEMBERSHIP: &str = "SELECT count(source.path),coalesce(sum(target.path IS NOT NULL AND NOT (source.start_node=target.start_node AND source.end_node=target.end_node AND source.start_lead_key IS target.start_lead_key AND source.start_lead_shared IS target.start_lead_shared AND source.end_lead_key IS target.end_lead_key AND source.end_lead_shared IS target.end_lead_shared AND source.body IS target.body)),0) FROM json_each(?1) input LEFT JOIN temp.selected_resolution_context_paths source ON source.context_id=input.value->>0 AND source.host_ordinal=input.value->>1 AND source.path=input.value->>2 LEFT JOIN temp.selected_resolution_context_paths target ON target.context_id=?2 AND target.host_ordinal=source.host_ordinal AND target.path=source.path";

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
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .expect("selected context token space exhausted");
    SelectedContextPathToken::new(value)
}

/// Check a token minted by this inventory's committed context publication.
#[doc(hidden)]
pub fn require_context(
    selection: &SelectedResolutionMountInventory<'_>,
    context: SelectedContextPathToken,
) -> Result<()> {
    if !selection.has_published_context(context) {
        return Err(StoreError::new(format!(
            "selected context token has no request-owned rows: {context:?}"
        )));
    }
    Ok(())
}

/// One transaction's borrowed writer, with no retained path collection.
#[doc(hidden)]
pub struct SelectedContextPathWriter<'a> {
    connection: &'a Connection,
    context: SelectedContextPathToken,
    cancellation: &'a CancellationToken,
    reused: std::collections::HashMap<CandidatePathIdentity, SelectedContextPathToken>,
}

impl SelectedContextPathWriter<'_> {
    /// Include one already-published complete cell. A repeated candidate must
    /// agree even when its authority comes from another immutable context.
    #[doc(hidden)]
    pub fn reuse(
        &mut self,
        source: SelectedContextPathToken,
        identity: CandidatePathIdentity,
    ) -> Result<bool> {
        if self.cancellation.is_cancelled() {
            return Ok(false);
        }
        if let Some(previous) = self.reused.insert(identity, source)
            && previous != source
        {
            let same = self.connection.prepare_cached(
                "SELECT l.start_node=r.start_node AND l.end_node=r.end_node AND l.start_lead_key IS r.start_lead_key AND l.start_lead_shared IS r.start_lead_shared AND l.end_lead_key IS r.end_lead_key AND l.end_lead_shared IS r.end_lead_shared AND l.body IS r.body FROM temp.selected_resolution_context_paths l JOIN temp.selected_resolution_context_paths r ON r.context_id=?2 AND r.host_ordinal=l.host_ordinal AND r.path=l.path WHERE l.context_id=?1 AND l.host_ordinal=?3 AND l.path=?4"
            )?.query_row(params![previous.get(),source.get(),identity.fragment().ordinal(),codec::encode_path_id(identity.path())], |row| row.get::<_,bool>(0)).optional()?;
            if same != Some(true) {
                return Err(StoreError::new(format!(
                    "selected context candidate changed its complete path: {identity:?}"
                )));
            }
            debug_assert_eq!(same, Some(true), "reused complete cells agree");
        }
        Ok(true)
    }

    fn flush_reused(&mut self) -> Result<bool> {
        // Generic publication has no reuse work and must retain its original
        // cancellation observation order.
        if self.reused.is_empty() {
            return Ok(true);
        }
        if self.cancellation.is_cancelled() {
            return Ok(false);
        }
        let mut cells = self
            .reused
            .iter()
            .map(|(identity, source)| {
                (
                    source.get(),
                    identity.fragment().ordinal(),
                    codec::encode_path_id(identity.path()),
                )
            })
            .collect::<Vec<_>>();
        cells.sort_unstable();
        let json = serde_json::to_string(&cells).expect("scalar context coordinates serialize");
        let (found, conflicts): (usize, usize) = self
            .connection
            .prepare_cached(REUSED_CONTEXT_CELL_MEMBERSHIP)?
            .query_row(params![&json, self.context.get()], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?;
        if found != cells.len() {
            return Err(StoreError::new(format!(
                "selected context reuse lacks published source cells: {cells:?}"
            )));
        }
        if conflicts != 0 {
            return Err(StoreError::new(format!(
                "selected context candidate changed its complete path during reuse: {cells:?}"
            )));
        }
        debug_assert_eq!(
            conflicts, 0,
            "identical-cell reuse agrees on target and completion"
        );
        self.connection
            .prepare_cached(REUSED_CONTEXT_CELL_COPY)?
            .execute(params![&json, self.context.get()])?;
        Ok(!self.cancellation.is_cancelled())
    }

    #[doc(hidden)]
    pub fn insert(&mut self, identity: CandidatePathIdentity, path: &PartialPath) -> Result<bool> {
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
    /// Copy only cells absent from the immutable base. Membership uses the
    /// (context_id, host_ordinal, path) primary key before candidate charging.
    /// The caller verifies overlapping complete cells before requesting a delta.
    #[doc(hidden)]
    pub fn publish_context_delta(
        &self,
        source: SelectedContextPathToken,
        base: SelectedContextPathToken,
        cancellation: &CancellationToken,
    ) -> Result<Option<SelectedContextPathToken>> {
        require_context(self.selection, source)?;
        require_context(self.selection, base)?;
        self.publish_context_paths(cancellation, |writer| {
            writer.connection.prepare_cached(
                "INSERT INTO temp.selected_resolution_context_paths SELECT ?1,p.host_ordinal,p.path,p.start_node,p.end_node,p.start_lead_key,p.start_lead_shared,p.end_lead_key,p.end_lead_shared,p.body FROM temp.selected_resolution_context_paths p WHERE p.context_id=?2 AND NOT EXISTS (SELECT 1 FROM temp.selected_resolution_context_paths b WHERE b.context_id=?3 AND b.host_ordinal=p.host_ordinal AND b.path=p.path)",
            )?.execute(params![writer.context.get(), source.get(), base.get()])?;
            Ok(!cancellation.is_cancelled())
        })
    }

    /// Publish one immutable context atomically. The callback compiles one
    /// descriptor at a time; only committed rows yield a request authority token.
    #[doc(hidden)]
    pub fn publish_context_paths(
        &self,
        cancellation: &CancellationToken,
        publish: impl FnOnce(&mut SelectedContextPathWriter<'_>) -> Result<bool>,
    ) -> Result<Option<SelectedContextPathToken>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let context = mint_context_token();
        self.selection.mark_stage_used();
        let published = self.selection.with_owned_temp_transaction(|connection| {
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
                        reused: std::collections::HashMap::new(),
                    };
                    Ok(
                        if !publish(&mut writer)?
                            || !writer.flush_reused()?
                            || cancellation.is_cancelled()
                        {
                            SelectedResolutionTempTransaction::Rollback(None)
                        } else {
                            SelectedResolutionTempTransaction::Commit(Some(context))
                        },
                    )
                });
            match result {
                Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => {
                    Ok(SelectedResolutionTempTransaction::Rollback(None))
                }
                outcome => outcome,
            }
        })?;
        if let Some(context) = published {
            self.selection.record_published_context(context);
        }
        Ok(published)
    }
}
