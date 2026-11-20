//! Source-local function-family bounds (`F: FnMut(A) -> B`, `impl Fn(A)`) of
//! Rust type slots. The rows are syntax: whether a shape's trait head is the
//! standard `Fn`, `FnMut` or `FnOnce` is decided by the consumer from the
//! head slot's resolution, never from the written spelling.
use super::rust_macro_types::catalog_slot_key;
use super::*;
use crate::analyzer::resolution::fact_source::{FormalFunctionShape, FormalFunctionShapeType};
use brokk_bifrost_core::analyzer::resolution_facts::*;
use rusqlite::{Transaction, params};

pub fn publish(
    tx: &Transaction<'_>,
    blob: i64,
    facts: &FileResolutionFacts,
    cancellation: &CancellationToken,
) -> Result<()> {
    // The parameter rows go with their header through the foreign key.
    tx.prepare_cached("DELETE FROM resolution_function_shapes WHERE blob_id=?1")?
        .execute([blob])?;
    let slot_key = |slot| catalog_slot_key(tx, blob, slot);
    for shape in &facts.function_shapes {
        if cancellation.is_cancelled() {
            return Ok(());
        }
        let owner = slot_key(shape.owner)?;
        let result = match shape.result {
            Some(result) => Some((slot_key(result.slot)?, result)),
            None => None,
        };
        tx.prepare_cached("INSERT INTO resolution_function_shapes(blob_id,owner_slot,trait_slot,parameter_count,result_slot,result_indirection,result_reference_indirection) VALUES(?1,?2,?3,?4,?5,?6,?7)")?.execute(params![
            blob,
            owner,
            slot_key(shape.trait_head)?,
            shape.parameters.len(),
            result.map(|(slot, _)| slot),
            result.map(|(_, result)| result.indirection_delta),
            result.map(|(_, result)| result.reference_indirection_delta),
        ])?;
        for (ordinal, parameter) in shape.parameters.iter().enumerate() {
            tx.prepare_cached("INSERT INTO resolution_function_shape_parameters(blob_id,owner_slot,ordinal,parameter_slot,indirection,reference_indirection) VALUES(?1,?2,?3,?4,?5,?6)")?.execute(params![
                blob,
                owner,
                ordinal,
                slot_key(parameter.slot)?,
                parameter.indirection_delta,
                parameter.reference_indirection_delta,
            ])?;
        }
    }
    Ok(())
}

/// The shapes of the requested owner slots. A slot that is not Rust, or that
/// carries no shape, contributes nothing. Requests are paged so ordinary
/// slots cost one statement per page.
#[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
pub fn shapes(
    selection: &SelectedResolutionMountInventory<'_>,
    owners: &[SemanticId],
    cancellation: &CancellationToken,
) -> Result<Vec<FormalFunctionShape>> {
    let conn = selection.connection();
    let mut requested = Vec::new();
    for &owner in owners {
        let (Some(ordinal), Some(key)) = (owner.ordinal(), owner.local_key()) else {
            continue;
        };
        if ordinal as usize >= selection.persisted_mount_count() {
            continue;
        }
        let mount =
            selection.mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        if mount.semantic_language() == Language::Rust {
            requested.push((ordinal, key, mount.blob_id()));
        }
    }
    let mut result = Vec::new();
    for page in requested.chunks(512) {
        if cancellation.is_cancelled() {
            return Ok(Vec::new());
        }
        let request = serde_json::json!(page).to_string();
        let headers = conn
            .prepare_cached(
                "SELECT json_extract(request.value,'$[0]'), shape.owner_slot, shape.blob_id,
                    shape.trait_slot, shape.parameter_count, shape.result_slot,
                    shape.result_indirection, shape.result_reference_indirection
             FROM json_each(?1) request
             JOIN resolution_function_shapes shape
               ON shape.blob_id=json_extract(request.value,'$[2]')
              AND shape.owner_slot=json_extract(request.value,'$[1]')",
            )?
            .query_map([request], |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, u32>(3)?,
                    row.get::<_, usize>(4)?,
                    row.get::<_, Option<u32>>(5)?,
                    row.get::<_, Option<u8>>(6)?,
                    row.get::<_, Option<u8>>(7)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (
            ordinal,
            key,
            blob,
            trait_slot,
            parameter_count,
            result_slot,
            result_ind,
            result_ref,
        ) in headers
        {
            if cancellation.is_cancelled() {
                return Ok(Vec::new());
            }
            let rows = conn.prepare_cached("SELECT ordinal, parameter_slot, indirection, reference_indirection FROM resolution_function_shape_parameters WHERE blob_id=?1 AND owner_slot=?2 ORDER BY ordinal")?.query_map(params![blob, key], |row| {
                Ok((
                    row.get::<_, usize>(0)?,
                    FormalFunctionShapeType {
                        slot: SemanticId::local(ordinal, row.get::<_, u32>(1)?),
                        indirection: row.get::<_, u8>(2)?,
                        reference_indirection: row.get::<_, u8>(3)?,
                    },
                ))
            })?.collect::<rusqlite::Result<Vec<_>>>()?;
            if rows.len() != parameter_count
                || !rows
                    .iter()
                    .enumerate()
                    .all(|(expected, (ordinal, _))| expected == *ordinal)
            {
                return Err(StoreError::corrupt(
                    "function shape is missing parameter rows",
                ));
            }
            let result_type = match (result_slot, result_ind, result_ref) {
                (Some(slot), Some(indirection), Some(reference_indirection)) => {
                    Some(FormalFunctionShapeType {
                        slot: SemanticId::local(ordinal, slot),
                        indirection,
                        reference_indirection,
                    })
                }
                (None, None, None) => None,
                // The table's CHECK constraints make the three columns agree.
                _ => unreachable!("function shape result columns agree"),
            };
            result.push(FormalFunctionShape {
                owner: SemanticId::local(ordinal, key),
                trait_head: SemanticId::local(ordinal, trait_slot),
                parameters: rows.into_iter().map(|(_, parameter)| parameter).collect(),
                result: result_type,
            });
        }
    }
    Ok(result)
}
