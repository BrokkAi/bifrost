//! Source-local rows for a Rust closure written as a call argument: its
//! identifier binder slots and its return observations. A closure is not a
//! declaration, so none of this is registered as a definition, catalog node or
//! callable signature. The only reader is the evaluator step that fills a
//! binder from a formal's function shape, through `binder_contexts` below.
use super::rust_macro_types::catalog_slot_key;
use super::*;
use crate::analyzer::resolution::fact_source::ClosureBinderContext;
use brokk_bifrost_core::analyzer::resolution_facts::*;
use rusqlite::{Transaction, params};

const BINDER: u8 = 0;
const RETURN: u8 = 1;

pub fn publish(
    tx: &Transaction<'_>,
    blob: i64,
    facts: &FileResolutionFacts,
    cancellation: &CancellationToken,
) -> Result<()> {
    // The member rows go with their header through the foreign key.
    tx.prepare_cached("DELETE FROM resolution_closure_literals WHERE blob_id=?1")?
        .execute([blob])?;
    let slot_key = |slot| catalog_slot_key(tx, blob, slot);
    for closure in &facts.closure_literals {
        if cancellation.is_cancelled() {
            return Ok(());
        }
        assert!(
            closure.complete || closure.parameters.is_empty(),
            "an incomplete closure publishes no binder: {closure:?}"
        );
        let value = slot_key(closure.value)?;
        let result = match closure.result {
            Some(result) => Some(slot_key(result)?),
            None => None,
        };
        tx.prepare_cached("INSERT INTO resolution_closure_literals(blob_id,value_slot,complete,parameter_count,return_count,result_slot) VALUES(?1,?2,?3,?4,?5,?6)")?.execute(params![
            blob,
            value,
            closure.complete,
            closure.parameters.len(),
            closure.returns.len(),
            result,
        ])?;
        for (ordinal, binder) in closure.parameters.iter().enumerate() {
            tx.prepare_cached("INSERT INTO resolution_closure_members(blob_id,value_slot,kind,ordinal,slot,binder_site,annotated) VALUES(?1,?2,?3,?4,?5,?6,?7)")?.execute(params![
                blob,
                value,
                BINDER,
                ordinal,
                slot_key(binder.slot)?,
                binder.declaration.get(),
                binder.annotated,
            ])?;
        }
        for (ordinal, slot) in closure.returns.iter().enumerate() {
            tx.prepare_cached("INSERT INTO resolution_closure_members(blob_id,value_slot,kind,ordinal,slot,binder_site,annotated) VALUES(?1,?2,?3,?4,?5,NULL,NULL)")?.execute(params![
                blob,
                value,
                RETURN,
                ordinal,
                slot_key(*slot)?,
            ])?;
        }
    }
    Ok(())
}

/// The unannotated binders among the requested slots, each with the call
/// argument its closure feeds and the callee reference of that call. A slot
/// that is not Rust, is not an unannotated binder of a complete closure, or
/// belongs to a closure that is not a call argument contributes nothing.
/// Requests are paged, and every statement is a point read on an index: the
/// member by its slot, the transfer that feeds the closure's value into the
/// call's argument slot by its source, the argument by that slot, the call's
/// identity by its digest and the obligation by that identity.
#[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
pub fn binder_contexts(
    selection: &SelectedResolutionMountInventory<'_>,
    binders: &[SemanticId],
    cancellation: &CancellationToken,
) -> Result<Vec<ClosureBinderContext>> {
    let conn = selection.connection();
    let mut requested = Vec::new();
    for &binder in binders {
        let (Some(ordinal), Some(key)) = (binder.ordinal(), binder.local_key()) else {
            continue;
        };
        if ordinal as usize >= selection.persisted_mount_count() {
            continue;
        }
        let mount =
            selection.mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        if mount.semantic_language() == Language::Rust && mount.may_have_closure_members() {
            requested.push((ordinal, key, mount.blob_id()));
        }
    }
    let mut result = Vec::new();
    for page in requested.chunks(512) {
        if cancellation.is_cancelled() {
            return Ok(Vec::new());
        }
        let request = serde_json::json!(page).to_string();
        let members = conn
            .prepare_cached(
                "SELECT json_extract(request.value,'$[0]'), json_extract(request.value,'$[2]'),
                    member.slot, member.ordinal, transfer.target_slot,
                    literal.parameter_count, argument.call_site
             FROM json_each(?1) request
             JOIN resolution_closure_members member
               ON member.blob_id=json_extract(request.value,'$[2]')
              AND member.slot=json_extract(request.value,'$[1]')
              AND member.kind=?2 AND member.annotated=0
             JOIN resolution_closure_literals literal
               ON literal.blob_id=member.blob_id AND literal.value_slot=member.value_slot
              AND literal.complete=1
             JOIN resolution_type_transfers transfer
               ON transfer.blob_id=member.blob_id AND transfer.source_slot=member.value_slot
             JOIN resolution_call_arguments argument
               ON argument.blob_id=transfer.blob_id
              AND argument.value_semantic_key=transfer.target_slot",
            )?
            .query_map(params![request, BINDER], |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, u32>(2)?,
                    row.get::<_, usize>(3)?,
                    row.get::<_, u32>(4)?,
                    row.get::<_, usize>(5)?,
                    row.get::<_, u32>(6)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (ordinal, blob, binder, member_ordinal, argument, binder_count, call_site) in members {
            // The obligation is keyed by the call's own semantic identity, a
            // digest of its site, not by the site number the argument row holds.
            let call = crate::analyzer::resolution::call_semantic_identity(ResolutionSiteId::new(
                call_site,
            ));
            let callee = conn
                .prepare_cached(
                    "SELECT obligation.callee_reference
                 FROM resolution_semantic_catalog call
                 JOIN resolution_call_obligations obligation
                   ON obligation.blob_id=call.blob_id AND obligation.call=call.local_key
                 WHERE call.blob_id=?1 AND call.identity_digest=?2",
                )?
                .query_map(
                    params![blob, call.fragment_local_digest().as_slice()],
                    |row| row.get::<_, u32>(0),
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let [callee] = callee[..] else {
                continue;
            };
            result.push(ClosureBinderContext {
                binder: SemanticId::local(ordinal, binder),
                ordinal: member_ordinal,
                binder_count,
                argument: SemanticId::local(ordinal, argument),
                callee_reference: SemanticId::local(ordinal, callee),
            });
        }
    }
    Ok(result)
}
