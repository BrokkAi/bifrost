//! Exact source-owned frontier closure, independent of capsule body publication.

use super::{SelectedResolutionStage, SelectedResolutionStageOutcome};
use crate::CancellationToken;
use crate::analyzer::resolution::LoweringGapOrigin;
use crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code;
use crate::analyzer::store::resolution_selection::SelectedResolutionMountRecord;
use crate::analyzer::store::{Result, StoreError};
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::source_facts::{SourceDeclarationId, SourceOccurrenceId};
use brokk_bifrost_core::analyzer::structural::resolution::ResolutionGapOriginKind;
use rusqlite::{Connection, OptionalExtension, params};

pub(super) const MACRO_GAP_REASONS_SQL: &str = "SELECT DISTINCT ?4+gap.reason AS runtime FROM main.source_rust_macro_inputs input CROSS JOIN main.resolution_gap_reasons gap ON gap.blob_id=input.blob_id AND gap.site=input.native_gap_site AND gap.origin IN(?5,?6) WHERE input.blob_id=?1 AND input.invocation_occurrence_id=?2 ORDER BY runtime";

/// Gaps in the invocation's argument references that capsule lowering can close.
/// This does not expand the transcriber: even reference-free arguments can
/// produce declarations or impls. UnexpandedItemMacro therefore remains open.
fn origins() -> (i64, i64) {
    (
        gap_origin_code(LoweringGapOrigin::from_kind(
            ResolutionGapOriginKind::UnsupportedScopeOrBinder,
        )),
        gap_origin_code(LoweringGapOrigin::from_kind(
            ResolutionGapOriginKind::UnsupportedExpression,
        )),
    )
}

pub(super) fn insert_capsule_closed_reasons(
    connection: &Connection,
    producer: i64,
    host: &SelectedResolutionMountRecord,
    invocation: SourceOccurrenceId,
) -> Result<()> {
    static SQL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let sql = SQL.get_or_init(|| {
 let sql = format!("INSERT INTO temp.selected_resolution_stage_closed_reasons(producer_id,semantic_key,semantic_shared) SELECT ?3,runtime,NULL FROM ({MACRO_GAP_REASONS_SQL})");
 #[cfg(test)]
 crate::analyzer::store::resolution_selection::note_selected_static_sql_capacity(16, sql.capacity());
 sql
});
    let (first, second) = origins();
    connection.execute(
        sql,
        params![
            host.blob_id(),
            invocation.get(),
            producer,
            i64::from(host.ordinal().get()) << 32,
            first,
            second
        ],
    )?;
    Ok(())
}

fn require_selected_host(
    connection: &Connection,
    host: &SelectedResolutionMountRecord,
) -> Result<()> {
    let agrees: bool=connection.query_row("SELECT EXISTS(SELECT 1 FROM temp.selected_resolution_mounts WHERE mount_ordinal=?1 AND workspace_id=?2 AND storage_language=?3 AND generation=?4 AND revision=?5 AND blob_id=?6 AND blob_oid=?7 AND producer_epoch=?8 AND persisted_relative_path=?9 AND projection_digest=?10 AND interior_digest=?11)",params![host.ordinal().get(),host.workspace_id(),host.storage_language(),host.generation(),host.revision(),host.blob_id(),host.blob_oid().to_string(),host.producer_epoch(),host.persisted_relative_path(),host.projection_digest().as_slice(),host.interior_digest().as_slice()],|row|row.get(0))?;
    if !agrees {
        return Err(StoreError::new(
            "macro frontier closure owner is not the actual selected host",
        ));
    }
    Ok(())
}

fn proof(
    domain: &'static [u8],
    host: &SelectedResolutionMountRecord,
    invocation: SourceOccurrenceId,
) -> CanonicalHasher {
    let mut hash = CanonicalHasher::new(domain);
    hash.field("host", host.blob_oid().as_bytes());
    hash.field("host-epoch", host.producer_epoch().as_bytes());
    hash.field("invocation", &invocation.get().to_be_bytes());
    hash
}

impl SelectedResolutionStage<'_, '_> {
    pub(crate) fn close_unmatched_macro_input(
        &self,
        host: &SelectedResolutionMountRecord,
        invocation: SourceOccurrenceId,
        definition: &SelectedResolutionMountRecord,
        declaration: SourceDeclarationId,
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionStageOutcome> {
        let mut hash = proof(
            b"bifrost-selected-unmatched-macro-closure:v1",
            host,
            invocation,
        );
        hash.field("definition", definition.blob_oid().as_bytes());
        hash.field("definition-epoch", definition.producer_epoch().as_bytes());
        hash.field("declaration", &declaration.get().to_be_bytes());
        self.publish_macro_closure(host, invocation, definition, hash.finish(), cancellation)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn close_empty_macro_input(
        &self,
        host: &SelectedResolutionMountRecord,
        invocation: SourceOccurrenceId,
        definition: &SelectedResolutionMountRecord,
        declaration: SourceDeclarationId,
        arm_index: usize,
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionStageOutcome> {
        let mut hash = proof(b"bifrost-selected-empty-macro-closure:v1", host, invocation);
        hash.field("definition", definition.blob_oid().as_bytes());
        hash.field("definition-epoch", definition.producer_epoch().as_bytes());
        hash.field("declaration", &declaration.get().to_be_bytes());
        hash.field(
            "arm",
            &u64::try_from(arm_index)
                .expect("arm index fits u64")
                .to_be_bytes(),
        );
        self.publish_macro_closure(host, invocation, definition, hash.finish(), cancellation)
    }

    pub(crate) fn close_included_macro_input(
        &self,
        host: &SelectedResolutionMountRecord,
        invocation: SourceOccurrenceId,
        included: &SelectedResolutionMountRecord,
        include_start: usize,
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionStageOutcome> {
        let mut hash = proof(
            b"bifrost-selected-included-macro-closure:v1",
            host,
            invocation,
        );
        hash.field("included", included.blob_oid().as_bytes());
        hash.field("included-epoch", included.producer_epoch().as_bytes());
        hash.field(
            "edge-start",
            &u64::try_from(include_start)
                .expect("include start fits u64")
                .to_be_bytes(),
        );
        self.publish_macro_closure(host, invocation, included, hash.finish(), cancellation)
    }

    fn publish_macro_closure(
        &self,
        host: &SelectedResolutionMountRecord,
        invocation: SourceOccurrenceId,
        proof_owner: &SelectedResolutionMountRecord,
        identity: [u8; 32],
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionStageOutcome> {
        let result = self.with_generated_admission(cancellation, |connection| {
            require_selected_host(connection, host)?;
            require_selected_host(connection, proof_owner)?;
            let (first, second) = origins();
            let mut statement = connection.prepare_cached(MACRO_GAP_REASONS_SQL)?;
            let mut cursor = statement.query(params![
                host.blob_id(),
                invocation.get(),
                rusqlite::types::Value::Null,
                i64::from(host.ordinal().get()) << 32,
                first,
                second
            ])?;
            let mut reasons = Vec::new();
            while let Some(row) = cursor.next()? {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                reasons.push(row.get::<_, i64>(0)?);
            }
            drop(cursor);
            drop(statement);
            publish_closed_reasons(connection, host, identity, &reasons)
        })?;
        Ok(match result {
            Some(()) => SelectedResolutionStageOutcome::Ready,
            None => SelectedResolutionStageOutcome::Cancelled,
        })
    }

    /// Close the open binder gaps of `host`'s structs and enums whose `serde`
    /// helper the crate route proved inert: each item's derive name resolves
    /// to serde's derive through the crate rows. `reasons` are the gaps'
    /// runtime reason keys, ascending; the proof is the host's content and the
    /// reasons themselves, since the rows that decided them belong to the
    /// same selected revision.
    pub(crate) fn close_serde_helper_reasons(
        &self,
        host: &SelectedResolutionMountRecord,
        reasons: &[i64],
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionStageOutcome> {
        assert!(
            reasons.windows(2).all(|pair| pair[0] < pair[1]),
            "serde helper reasons are ascending and distinct: {reasons:?}"
        );
        let mut hash = CanonicalHasher::new(b"bifrost-selected-serde-helper-closure:v1");
        hash.field("host", host.blob_oid().as_bytes());
        hash.field("host-epoch", host.producer_epoch().as_bytes());
        for reason in reasons {
            hash.field("reason", &reason.to_be_bytes());
        }
        let identity = hash.finish();
        let result = self.with_generated_admission(cancellation, |connection| {
            require_selected_host(connection, host)?;
            publish_closed_reasons(connection, host, identity, reasons)
        })?;
        Ok(match result {
            Some(()) => SelectedResolutionStageOutcome::Ready,
            None => SelectedResolutionStageOutcome::Cancelled,
        })
    }
}

/// Publish one closure producer for `host` and the reasons it closes, or
/// confirm that an identical producer is already published.
fn publish_closed_reasons(
    connection: &Connection,
    host: &SelectedResolutionMountRecord,
    identity: [u8; 32],
    reasons: &[i64],
) -> Result<Option<((), bool)>> {
    let mut descriptor = CanonicalHasher::new(b"bifrost-selected-macro-closure-content:v1");
    descriptor.field("proof", &identity);
    for reason in reasons {
        descriptor.field("reason", &reason.to_be_bytes());
    }
    let descriptor = descriptor.finish();
    let previous:Option<(i64,Vec<u8>)>=connection.prepare_cached("SELECT producer_id,content_digest FROM temp.selected_resolution_stage_producers WHERE host_ordinal=?1 AND bridge_identity=?2")?.query_row(params![host.ordinal().get(),identity],|row|Ok((row.get(0)?,row.get(1)?))).optional()?;
    if let Some((producer, previous)) = previous {
        if previous.as_slice() != descriptor {
            return Err(StoreError::new(
                "closure changed its complete source descriptor",
            ));
        }
        let actual=connection.prepare_cached("SELECT semantic_key FROM temp.selected_resolution_stage_closed_reasons WHERE producer_id=?1 ORDER BY semantic_key")?.query_map([producer],|row|row.get::<_,i64>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        if actual != reasons {
            return Err(StoreError::new(
                "closure changed its producer-owned reasons",
            ));
        }
        return Ok(Some(((), false)));
    }
    connection.prepare_cached("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(?1,?2,?3)")?.execute(params![host.ordinal().get(),identity,descriptor])?;
    let producer = connection.last_insert_rowid();
    connection.prepare_cached("INSERT INTO temp.selected_resolution_stage_closed_reasons(producer_id,semantic_key,semantic_shared) SELECT ?1,value,NULL FROM json_each(?2)")?.execute(params![producer,serde_json::to_string(reasons).expect("closure reason parameters")])?;
    Ok(Some(((), !reasons.is_empty())))
}

#[cfg(test)]
#[path = "closure_tests.rs"]
mod tests;
