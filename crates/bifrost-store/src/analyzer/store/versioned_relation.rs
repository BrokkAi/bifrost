//! Shared publication lifecycle for an indexed, single-key versioned relation.

use super::Result;
use brokk_bifrost_core::cancellation::CancellationToken;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

pub(crate) struct VersionedRelation {
    pub table: &'static str,
    pub id_column: &'static str,
    pub key_column: &'static str,
    pub output_digest_column: &'static str,
}

pub(crate) enum PublicationOutcome {
    Published { key: i64, row_id: i64 },
    Unchanged { key: i64, row_id: i64 },
    InputsChanged,
    Cancelled,
}

impl VersionedRelation {
    /// `prepare` validates the selected inputs and obtains the relation key in
    /// this transaction. `insert` creates the parent row; `write_children`
    /// returns false if cancelled. All writes roll back on cancellation.
    ///
    /// The relation must enforce a unique key WHERE valid_until IS NULL.
    #[allow(clippy::too_many_arguments)]
    pub fn publish(
        &self,
        conn: &mut Connection,
        revision: i64,
        input_digest: &[u8],
        output_digest: &[u8],
        cancellation: &CancellationToken,
        prepare: impl FnOnce(&Transaction<'_>) -> Result<Option<i64>>,
        insert: impl FnOnce(&Transaction<'_>, i64) -> Result<i64>,
        write_children: impl FnOnce(&Transaction<'_>, i64) -> Result<bool>,
    ) -> Result<PublicationOutcome> {
        let Self {
            table,
            id_column,
            key_column,
            output_digest_column,
        } = self;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if cancellation.is_cancelled() {
            return Ok(PublicationOutcome::Cancelled);
        }
        let Some(key) = prepare(&tx)? else {
            return Ok(PublicationOutcome::InputsChanged);
        };
        // The immediate transaction observes the winner of any concurrent
        // publication before deciding cutoff or closing its open row.
        let current: Option<(i64, Vec<u8>, i64)> = tx.query_row(
            &format!("SELECT {id_column},{output_digest_column},valid_from FROM {table} WHERE {key_column}=?1 AND valid_until IS NULL"),
            [key], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).optional()?;
        if let Some((row_id, digest, valid_from)) = current {
            assert!(valid_from <= revision, "cannot replace a later publication");
            if digest == output_digest {
                let changed = tx.execute(
                    &format!("UPDATE {table} SET input_digest=?2 WHERE {id_column}=?1 AND valid_until IS NULL AND input_digest<>?2"),
                    params![row_id, input_digest],
                )?;
                assert!(changed <= 1, "cutoff updates at most the open row");
                self.assert_intervals(&tx, key)?;
                if cancellation.is_cancelled() {
                    return Ok(PublicationOutcome::Cancelled);
                }
                tx.commit()?;
                return Ok(PublicationOutcome::Unchanged { key, row_id });
            }
            assert_eq!(tx.execute(
                &format!("UPDATE {table} SET valid_until=?2 WHERE {id_column}=?1 AND valid_until IS NULL"),
                params![row_id, revision],
            )?, 1, "one open publication closed by compare-and-swap");
        }
        let row_id = insert(&tx, key)?;
        if !write_children(&tx, row_id)? || cancellation.is_cancelled() {
            return Ok(PublicationOutcome::Cancelled);
        }
        self.assert_intervals(&tx, key)?;
        tx.commit()?;
        Ok(PublicationOutcome::Published { key, row_id })
    }

    fn assert_intervals(&self, tx: &Transaction<'_>, key: i64) -> Result<()> {
        #[cfg(debug_assertions)]
        {
            let Self {
                table,
                id_column,
                key_column,
                ..
            } = self;
            let open: i64 = tx.query_row(
                &format!(
                    "SELECT count(*) FROM {table} WHERE {key_column}=?1 AND valid_until IS NULL"
                ),
                [key],
                |row| row.get(0),
            )?;
            debug_assert_eq!(open, 1, "one open publication per relation key");
            let overlaps: bool = tx.query_row(
                &format!("SELECT EXISTS(SELECT 1 FROM {table} a JOIN {table} b ON b.{key_column}=a.{key_column} AND b.{id_column}>a.{id_column} WHERE a.{key_column}=?1 AND (a.valid_until IS NULL OR a.valid_from<a.valid_until) AND (b.valid_until IS NULL OR b.valid_from<b.valid_until) AND (a.valid_until IS NULL OR b.valid_from<a.valid_until) AND (b.valid_until IS NULL OR a.valid_from<b.valid_until))"),
                [key], |row| row.get(0),
            )?;
            debug_assert!(!overlaps, "nonempty publication intervals cannot overlap");
        }
        #[cfg(not(debug_assertions))]
        let _ = (tx, key);
        Ok(())
    }
}
