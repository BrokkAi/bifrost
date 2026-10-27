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
use std::sync::OnceLock;
use std::sync::atomic::{AtomicI64, Ordering};

#[doc(hidden)]
pub const REUSED_CONTEXT_CELL_COPY: &str = "INSERT INTO temp.selected_resolution_context_paths(context_id,host_ordinal,path,start_node,end_node,start_lead_key,start_lead_shared,end_lead_key,end_lead_shared,body,start_fixed_key,start_open_tail,end_fixed_key,end_open_tail) SELECT ?2,source.host_ordinal,source.path,source.start_node,source.end_node,source.start_lead_key,source.start_lead_shared,source.end_lead_key,source.end_lead_shared,source.body,source.start_fixed_key,source.start_open_tail,source.end_fixed_key,source.end_open_tail FROM json_each(?1) input CROSS JOIN temp.selected_resolution_context_paths source ON source.context_id=input.value->>0 AND source.host_ordinal=input.value->>1 AND source.path=input.value->>2 WHERE NOT EXISTS (SELECT 1 FROM temp.selected_resolution_context_paths target WHERE target.context_id=?2 AND target.host_ordinal=source.host_ordinal AND target.path=source.path)";

#[doc(hidden)]
pub const REUSED_CONTEXT_CELL_MEMBERSHIP: &str = "SELECT count(source.path),coalesce(sum(target.path IS NOT NULL AND NOT (source.start_node=target.start_node AND source.end_node=target.end_node AND source.start_lead_key IS target.start_lead_key AND source.start_lead_shared IS target.start_lead_shared AND source.end_lead_key IS target.end_lead_key AND source.end_lead_shared IS target.end_lead_shared AND source.body IS target.body)),0) FROM json_each(?1) input LEFT JOIN temp.selected_resolution_context_paths source ON source.context_id=input.value->>0 AND source.host_ordinal=input.value->>1 AND source.path=input.value->>2 LEFT JOIN temp.selected_resolution_context_paths target ON target.context_id=?2 AND target.host_ordinal=source.host_ordinal AND target.path=source.path";

const CONTEXT_DELTA_COPY: &str = "INSERT INTO temp.selected_resolution_context_paths(context_id,host_ordinal,path,start_node,end_node,start_lead_key,start_lead_shared,end_lead_key,end_lead_shared,body,start_fixed_key,start_open_tail,end_fixed_key,end_open_tail) SELECT ?1,p.host_ordinal,p.path,p.start_node,p.end_node,p.start_lead_key,p.start_lead_shared,p.end_lead_key,p.end_lead_shared,p.body,p.start_fixed_key,p.start_open_tail,p.end_fixed_key,p.end_open_tail FROM temp.selected_resolution_context_paths p WHERE p.context_id=?2 AND NOT EXISTS (SELECT 1 FROM temp.selected_resolution_context_paths b WHERE b.context_id=?3 AND b.host_ordinal=p.host_ordinal AND b.path=p.path)";

pub(super) fn schema_sql() -> &'static str {
    static SQL: OnceLock<String> = OnceLock::new();
    SQL.get_or_init(|| format!(r#"
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
 start_fixed_key TEXT, start_open_tail INTEGER CHECK(start_open_tail IN (0,1)),
 end_fixed_key TEXT, end_open_tail INTEGER CHECK(end_open_tail IN (0,1)),
 CHECK(start_lead_key IS NULL OR start_lead_shared IS NULL),
 CHECK(end_lead_key IS NULL OR end_lead_shared IS NULL),
 CHECK((start_node={root} AND start_fixed_key IS NOT NULL AND start_open_tail IS NOT NULL)
    OR (start_node<>{root} AND start_fixed_key IS NULL AND start_open_tail IS NULL)),
 CHECK((end_node={root} AND end_fixed_key IS NOT NULL AND end_open_tail IS NOT NULL)
    OR (end_node<>{root} AND end_fixed_key IS NULL AND end_open_tail IS NULL)),
 PRIMARY KEY(context_id,host_ordinal,path)
) WITHOUT ROWID, STRICT;
CREATE INDEX IF NOT EXISTS temp.selected_resolution_context_paths_forward
 ON selected_resolution_context_paths(context_id,start_node,start_lead_shared,start_lead_key,host_ordinal,path);
CREATE INDEX IF NOT EXISTS temp.selected_resolution_context_paths_reverse
 ON selected_resolution_context_paths(context_id,end_node,end_lead_shared,end_lead_key,host_ordinal,path);
CREATE INDEX IF NOT EXISTS temp.selected_resolution_context_paths_forward_root_prefix
 ON selected_resolution_context_paths(context_id,start_fixed_key COLLATE BINARY,start_open_tail,host_ordinal,path) WHERE start_node={root};
CREATE INDEX IF NOT EXISTS temp.selected_resolution_context_paths_reverse_root_prefix
 ON selected_resolution_context_paths(context_id,end_fixed_key COLLATE BINARY,end_open_tail,host_ordinal,path) WHERE end_node={root};
"#, root=codec::encode_node(crate::analyzer::resolution::BindingNodeId::universal_root())))
}

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
                let Some(start) = lexical::root_endpoint_key(path.start(), self.cancellation)
                else {
                    return Ok(false);
                };
                let Some(end) = lexical::root_endpoint_key(path.end(), self.cancellation) else {
                    return Ok(false);
                };
                let (start_fixed, start_tail) = start.unzip();
                let (end_fixed, end_tail) = end.unzip();
                let keys: [&dyn rusqlite::ToSql; 4] =
                    [&start_fixed, &start_tail, &end_fixed, &end_tail];
                self.connection
                    .prepare_cached(
                        "INSERT INTO temp.selected_resolution_context_paths(context_id,host_ordinal,path,start_node,end_node,start_lead_key,start_lead_shared,end_lead_key,end_lead_shared,body,start_fixed_key,start_open_tail,end_fixed_key,end_open_tail) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,jsonb(?10),?11,?12,?13,?14)",
                    )?
                    .execute(rusqlite::params_from_iter(values.iter().copied().chain(keys)))?;
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
            writer
                .connection
                .prepare_cached(CONTEXT_DELTA_COPY)?
                .execute(params![writer.context.get(), source.get(), base.get()])?;
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

#[cfg(test)]
pub(super) fn insert_test_paths(connection: &Connection, paths: &[PartialPath]) {
    let cancellation = CancellationToken::new();
    let mut writer = SelectedContextPathWriter {
        connection,
        context: SelectedContextPathToken::new(1),
        cancellation: &cancellation,
        reused: std::collections::HashMap::new(),
    };
    for (index, path) in paths.iter().enumerate() {
        assert!(
            writer
                .insert(
                    CandidatePathIdentity::new(
                        crate::analyzer::resolution::BindingFragmentId::at_ordinal(0),
                        crate::analyzer::resolution::PartialPathId::context_local(index as u64),
                    ),
                    path
                )
                .unwrap()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::resolution::{
        BindingFragmentId, BindingNodeId, EndpointSignature, PartialPathId, ResolutionCompletion,
        SemanticId, StackPattern, StackVariableId,
    };

    #[test]
    fn copied_context_root_keys_match_their_bodies() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(schema_sql()).unwrap();
        connection.execute_batch("CREATE TEMP TABLE selected_resolution_mounts(mount_ordinal INTEGER PRIMARY KEY); INSERT INTO temp.selected_resolution_mounts VALUES(0); INSERT INTO temp.selected_resolution_contexts VALUES(1),(2),(3),(4)").unwrap();
        let cancellation = CancellationToken::new();
        let root = BindingNodeId::universal_root();
        let local = BindingNodeId::local(0, 7);
        let endpoint = |node, symbols, tail| {
            EndpointSignature::new(
                node,
                StackPattern::new(symbols, tail),
                StackPattern::closed(vec![]),
            )
        };
        let paths = [
            PartialPath::new(
                endpoint(
                    root,
                    vec![SemanticId::local(0, 3)],
                    Some(StackVariableId::context_local(0)),
                ),
                endpoint(local, vec![], None),
                vec![],
                vec![],
                ResolutionCompletion::Complete,
            ),
            PartialPath::new(
                endpoint(local, vec![], None),
                endpoint(root, vec![SemanticId::context_local(5)], None),
                vec![],
                vec![],
                ResolutionCompletion::Complete,
            ),
            PartialPath::new(
                endpoint(root, vec![], None),
                endpoint(root, vec![], Some(StackVariableId::context_local(1))),
                vec![],
                vec![],
                ResolutionCompletion::Complete,
            ),
        ];
        let writer = |context| SelectedContextPathWriter {
            connection: &connection,
            context: SelectedContextPathToken::new(context),
            cancellation: &cancellation,
            reused: std::collections::HashMap::new(),
        };
        let mut source = writer(1);
        let mut copied = writer(2);
        for (ordinal, path) in paths.iter().enumerate() {
            let identity = CandidatePathIdentity::new(
                BindingFragmentId::at_ordinal(0),
                PartialPathId::context_local(ordinal as u64),
            );
            assert!(source.insert(identity, path).unwrap());
            assert!(copied.reuse(source.context, identity).unwrap());
        }
        assert!(copied.flush_reused().unwrap());
        assert_eq!(
            connection
                .execute(CONTEXT_DELTA_COPY, params![4, 1, 3])
                .unwrap(),
            paths.len()
        );
        for context in [2, 4] {
            let mut statement = connection.prepare("SELECT start_node,end_node,json(body),start_fixed_key,start_open_tail,end_fixed_key,end_open_tail FROM temp.selected_resolution_context_paths WHERE context_id=?1 ORDER BY path").unwrap();
            let mut rows = statement.query([context]).unwrap();
            let mut seen = 0;
            while let Some(row) = rows.next().unwrap() {
                let path = codec::decode_path(
                    row.get(0).unwrap(),
                    row.get(1).unwrap(),
                    &row.get::<_, String>(2).unwrap(),
                );
                let start = lexical::root_endpoint_key(path.start(), &cancellation)
                    .unwrap()
                    .unzip();
                let end = lexical::root_endpoint_key(path.end(), &cancellation)
                    .unwrap()
                    .unzip();
                assert_eq!(
                    (
                        row.get::<_, Option<String>>(3).unwrap(),
                        row.get::<_, Option<bool>>(4).unwrap()
                    ),
                    start
                );
                assert_eq!(
                    (
                        row.get::<_, Option<String>>(5).unwrap(),
                        row.get::<_, Option<bool>>(6).unwrap()
                    ),
                    end
                );
                seen += 1;
            }
            assert_eq!(seen, paths.len(), "copy paths must publish every cell");
        }
    }
}
