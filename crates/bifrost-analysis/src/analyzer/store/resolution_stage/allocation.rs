//! Request-owned supplemental coordinates. Every helper runs inside the caller's
//! admission transaction; assignments live only until that producer is projected.
//! Cleanup deletes correspondence, never the committed high-water counters.

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::json;

use super::codec;
use crate::CancellationToken;
use crate::analyzer::resolution::{
    BindingFragmentId, BindingNodeId, PartialPathId, ResolutionIdentityCatalog,
    ResolutionRegisteredIdentities, SelectedResolutionMountOrdinal, SemanticId, SharedNameInterner,
    StackVariableId,
};
use crate::analyzer::store::resolution_selection::SelectedResolutionMountInventory;
use crate::analyzer::store::{Result, StoreError, resolution_lexical::hex_digest};

/// The first key a stage allocates. Ordinary keys (semantic, node, path and
/// gap ordinals) are dense positions below it, so the two never collide.
pub(in crate::analyzer::store) const BASE: i64 = 1 << 31;

/// Whether a blob-local key is the blob's own rather than stage-allocated.
///
/// A gap reason has no catalog row (#3737), so this range is the only thing
/// that classifies a reason as ordinary or stage. Reasons are never shared.
pub(in crate::analyzer::store) const fn is_ordinary_key(key: u32) -> bool {
    (key as i64) < BASE
}
const END: i64 = 1 << 32;
const BATCH: usize = 256;

pub(in crate::analyzer::store) const SEMANTICS_SQL: &str = r#"
SELECT input.key, (mount.mount_ordinal << 32)+ordinary.local_key,
       staged.runtime_key, staged.shared_id
FROM json_each(?1) input
CROSS JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=input.value->>0
LEFT JOIN main.resolution_semantic_catalog ordinary
 ON ordinary.blob_id=mount.blob_id AND ordinary.identity_digest=unhex(input.value->>1)
 AND input.value->>2=0
LEFT JOIN temp.selected_resolution_stage_semantic_coordinates staged
 ON staged.host_ordinal=mount.mount_ordinal AND staged.identity_digest=unhex(input.value->>1)
 AND (staged.shared_id IS NOT NULL)=(input.value->>2)
"#;
pub(in crate::analyzer::store) const NODES_SQL: &str = r#"
SELECT input.key, (mount.mount_ordinal << 32)+ordinary.local_key,
       staged.runtime_key, NULL
FROM json_each(?1) input
CROSS JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=input.value->>0
LEFT JOIN main.resolution_node_catalog ordinary
 ON ordinary.blob_id=mount.blob_id AND ordinary.identity_digest=unhex(input.value->>1)
LEFT JOIN temp.selected_resolution_stage_node_coordinates staged
 ON staged.host_ordinal=mount.mount_ordinal AND staged.identity_digest=unhex(input.value->>1)
"#;
pub(in crate::analyzer::store) const PATHS_SQL: &str = r#"
SELECT input.key, NULL, staged.runtime_key, NULL
FROM json_each(?1) input
CROSS JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=input.value->>0
LEFT JOIN temp.selected_resolution_stage_path_coordinates staged
 ON staged.host_ordinal=mount.mount_ordinal AND staged.identity_digest=unhex(input.value->>1)
"#;

fn require_transaction(connection: &Connection) {
    assert!(
        !connection.is_autocommit(),
        "coordinate assignment belongs to admission"
    );
}

fn require_host(connection: &Connection, host: SelectedResolutionMountOrdinal) -> Result<()> {
    let found = connection
        .prepare_cached("SELECT 1 FROM temp.selected_resolution_mounts WHERE mount_ordinal=?1")?
        .exists([host.get()])?;
    if !found {
        return Err(StoreError::new(format!(
            "coordinate allocation has no selected host: {host:?}"
        )));
    }
    Ok(())
}

/// The existing host/identity indexes return every active owner. Equal answers
/// collapse only for this query; conflicting owners are never silently preferred.
#[derive(Clone, Copy)]
struct IdentityRequest {
    digest: [u8; 32],
    shared: bool,
}

impl From<[u8; 32]> for IdentityRequest {
    fn from(digest: [u8; 32]) -> Self {
        Self {
            digest,
            shared: false,
        }
    }
}

fn lookup(
    connection: &Connection,
    names: &dyn SharedNameInterner,
    host: SelectedResolutionMountOrdinal,
    requests: &[IdentityRequest],
    sql: &str,
    cancellation: &CancellationToken,
) -> Result<Option<Vec<Option<i64>>>> {
    let mut answers = Vec::with_capacity(requests.len());
    for chunk in requests.chunks(BATCH) {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let request = chunk
            .iter()
            .map(|request| {
                json!([
                    host.get(),
                    hex_digest(request.digest),
                    i64::from(request.shared)
                ])
            })
            .collect::<Vec<_>>();
        let request = serde_json::to_string(&request).expect("identity parameters serialize");
        let mut held = vec![None; chunk.len()];
        let mut statement = connection.prepare_cached(sql)?;
        let mut rows = statement.query([request])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let index: usize = row.get(0)?;
            let ordinary: Option<i64> = row.get(1)?;
            let runtime: Option<i64> = row.get(2)?;
            let shared: Option<i64> = row.get(3)?;
            let staged = match (runtime, shared) {
                (Some(_), Some(_)) => {
                    return Err(StoreError::new(
                        "stage coordinate has both local and shared authority",
                    ));
                }
                (Some(value), None) => Some(value),
                (None, Some(value)) => {
                    let semantic = codec::decode_semantic(-value);
                    let name = semantic
                        .shared_name_id()
                        .expect("negative semantic is shared");
                    let name = if name.is_interned() {
                        names.from_persisted(name)
                    } else {
                        name
                    };
                    Some(codec::encode_semantic(SemanticId::shared_name(name)))
                }
                (None, None) => None,
            };
            for candidate in [ordinary, staged].into_iter().flatten() {
                if let Some(previous) = held[index]
                    && previous != candidate
                {
                    return Err(StoreError::new(format!(
                        "selected coordinate authorities disagree: host={host:?}, identity={:?}, previous={previous}, candidate={candidate}",
                        chunk[index].digest
                    )));
                }
                held[index] = Some(candidate);
            }
        }
        answers.extend(held);
    }
    Ok((!cancellation.is_cancelled()).then_some(answers))
}

/// Reserve a contiguous run, or observe an existing key with count zero. The
/// exhausted sentinel is representable; only actual emitted keys must fit u32.
fn reserve(
    connection: &Connection,
    host: SelectedResolutionMountOrdinal,
    domain: i64,
    floor: i64,
    count: usize,
) -> Result<i64> {
    require_transaction(connection);
    let count = i64::try_from(count).expect("one catalog length fits i64");
    let (start, end): (i64, i64) = connection
        .prepare_cached(
            r#"
INSERT INTO temp.selected_resolution_stage_allocation_counters(host_ordinal,domain,next_key)
VALUES(?1,?2,?3+?4)
ON CONFLICT(host_ordinal,domain) DO UPDATE SET next_key=max(next_key,?3)+?4
RETURNING next_key-?4,next_key
"#,
        )?
        .query_row(params![host.get(), domain, floor.max(BASE), count], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
    assert!(start >= BASE && end <= END);
    Ok(start)
}

fn local_key(host: SelectedResolutionMountOrdinal, runtime: i64) -> Result<u32> {
    let runtime = u64::try_from(runtime)
        .map_err(|_| StoreError::new("local allocation authority is shared"))?;
    if runtime >> 32 != u64::from(host.get()) {
        return Err(StoreError::new(format!(
            "coordinate authority has wrong runtime host: host={host:?}, runtime={runtime}"
        )));
    }
    Ok(runtime as u32)
}

/// Preserve catalog order. A reuse observation splits a reservation run, so an
/// early fresh identity cannot be raised by a later reused high coordinate.
fn assign_keys(
    connection: &Connection,
    host: SelectedResolutionMountOrdinal,
    domain: i64,
    reuse: &[Option<i64>],
    cancellation: &CancellationToken,
) -> Result<Option<Vec<u32>>> {
    let mut keys = Vec::with_capacity(reuse.len());
    let mut index = 0;
    while index < reuse.len() {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        if let Some(runtime) = reuse[index] {
            let key = local_key(host, runtime)?;
            if i64::from(key) >= BASE {
                reserve(connection, host, domain, i64::from(key) + 1, 0)?;
            }
            keys.push(key);
            index += 1;
        } else {
            let start = index;
            while index < reuse.len() && reuse[index].is_none() {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                index += 1;
            }
            let first = reserve(connection, host, domain, BASE, index - start)?;
            for offset in 0..index - start {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                keys.push(
                    u32::try_from(first + i64::try_from(offset).expect("run offset fits i64"))
                        .expect("reserved keys fit u32"),
                );
            }
        }
    }
    Ok((!cancellation.is_cancelled()).then_some(keys))
}

/// Reserve one contiguous run of stage gap keys for a fresh producer.
///
/// A gap is not a catalog identity (#3737), so it is never looked up by digest
/// against the ordinary catalog or the stage coordinates. An ordinary gap and
/// a stage gap cannot be the same gap: a capsule rehashes every fragment-local
/// identity under its invocation digest
/// (`ResolutionIdentityCatalog::specialize_macro_input`), and a gap names its
/// reason, which is one of those identities. Identical stage gaps of one host
/// collapse on their content tuple when projected; the key only names the
/// survivor.
pub(super) fn reserve_gap_keys(
    connection: &Connection,
    host: SelectedResolutionMountOrdinal,
    count: usize,
) -> Result<i64> {
    require_host(connection, host)?;
    reserve(connection, host, 4, BASE, count)
}

pub(super) fn assign_catalog(
    selection: &SelectedResolutionMountInventory<'_>,
    connection: &Connection,
    host: SelectedResolutionMountOrdinal,
    catalog: &ResolutionIdentityCatalog,
    cancellation: &CancellationToken,
) -> Result<Option<ResolutionRegisteredIdentities>> {
    require_transaction(connection);
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    require_host(connection, host)?;
    let names = selection.shared_name_table().interner(connection);
    let mut assigned =
        ResolutionRegisteredIdentities::new(BindingFragmentId::at_ordinal(host.get()));
    let mut requests = Vec::with_capacity(catalog.semantics().len());
    for &(_, identity) in catalog.semantics() {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        requests.push(IdentityRequest {
            digest: catalog.identity_hash_bytes(identity),
            shared: identity.shared_name().is_some(),
        });
    }
    let Some(mut reuse) = lookup(
        connection,
        &names,
        host,
        &requests,
        SEMANTICS_SQL,
        cancellation,
    )?
    else {
        return Ok(None);
    };
    let mut shared = Vec::with_capacity(reuse.len());
    for (index, &(_, identity)) in catalog.semantics().iter().enumerate() {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let runtime = identity
            .shared_name()
            .map(|_| SemanticId::shared_name(names.intern(requests[index].digest)));
        if let Some(runtime) = runtime {
            if reuse[index].is_some_and(|held| held != codec::encode_semantic(runtime)) {
                return Err(StoreError::new(format!(
                    "shared coordinate authority disagrees: identity={:?}, held={:?}, requested={runtime:?}",
                    requests[index].digest, reuse[index]
                )));
            }
            // Shared entries consume a semantic key even though the emitted
            // runtime identity is shared. Preserve the old allocator's policy.
            reuse[index] = None;
        }
        shared.push(runtime);
    }
    let Some(keys) = assign_keys(connection, host, 0, &reuse, cancellation)? else {
        return Ok(None);
    };
    for (index, &(dense, _)) in catalog.semantics().iter().enumerate() {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        assigned.assign_semantic(
            dense,
            shared[index].unwrap_or_else(|| SemanticId::local(host.get(), keys[index])),
        );
    }
    requests.clear();
    for &(_, identity) in catalog.nodes() {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        requests.push(identity.digest().into());
    }
    let Some(reuse) = lookup(connection, &names, host, &requests, NODES_SQL, cancellation)? else {
        return Ok(None);
    };
    let Some(keys) = assign_keys(connection, host, 1, &reuse, cancellation)? else {
        return Ok(None);
    };
    for (&(dense, _), key) in catalog.nodes().iter().zip(keys) {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        assigned.assign_node(dense, BindingNodeId::local(host.get(), key));
    }
    requests.clear();
    for &(_, identity) in catalog.paths() {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        requests.push(identity.digest().into());
    }
    let Some(reuse) = lookup(connection, &names, host, &requests, PATHS_SQL, cancellation)? else {
        return Ok(None);
    };
    let Some(keys) = assign_keys(connection, host, 2, &reuse, cancellation)? else {
        return Ok(None);
    };
    for (&(dense, _), key) in catalog.paths().iter().zip(keys) {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        assigned.assign_path(dense, PartialPathId::local(host.get(), key));
    }
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    let start = reserve(connection, host, 3, BASE, catalog.stack_variables().len())?;
    for (index, &(dense, _)) in catalog.stack_variables().iter().enumerate() {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let key = u32::try_from(start + i64::try_from(index).expect("variable index fits i64"))
            .expect("reserved keys fit u32");
        assigned.assign_stack_variable(dense, StackVariableId::local(host.get(), key));
    }
    Ok((!cancellation.is_cancelled()).then_some(assigned))
}

/// Internal generated-bridge node assignment. The owner projects its catalog
/// before another unit can reuse it, in the same outer admission transaction.
pub(super) fn assign_node(
    selection: &SelectedResolutionMountInventory<'_>,
    connection: &Connection,
    host: SelectedResolutionMountOrdinal,
    identity: crate::analyzer::resolution::ResolutionNodeIdentity,
    cancellation: &CancellationToken,
) -> Result<Option<BindingNodeId>> {
    require_transaction(connection);
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    require_host(connection, host)?;
    let names = selection.shared_name_table().interner(connection);
    let Some(reuse) = lookup(
        connection,
        &names,
        host,
        &[identity.digest().into()],
        NODES_SQL,
        cancellation,
    )?
    else {
        return Ok(None);
    };
    let Some(keys) = assign_keys(connection, host, 1, &reuse, cancellation)? else {
        return Ok(None);
    };
    Ok(Some(BindingNodeId::local(host.get(), keys[0])))
}

/// Internal generated-bridge path assignment; never commits a reservation.
pub(super) fn assign_path(
    selection: &SelectedResolutionMountInventory<'_>,
    connection: &Connection,
    host: SelectedResolutionMountOrdinal,
    identity: crate::analyzer::resolution::ResolutionPathIdentity,
    cancellation: &CancellationToken,
) -> Result<Option<PartialPathId>> {
    require_transaction(connection);
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    require_host(connection, host)?;
    let names = selection.shared_name_table().interner(connection);
    let Some(reuse) = lookup(
        connection,
        &names,
        host,
        &[identity.digest().into()],
        PATHS_SQL,
        cancellation,
    )?
    else {
        return Ok(None);
    };
    let Some(keys) = assign_keys(connection, host, 2, &reuse, cancellation)? else {
        return Ok(None);
    };
    Ok(Some(PartialPathId::local(host.get(), keys[0])))
}

/// Replay only the exact saved producer, including variables. Missing or changed
/// correspondence is an admission error, not permission to allocate again.
fn replay_rows(
    connection: &Connection,
    producer: i64,
    host: SelectedResolutionMountOrdinal,
    digests: &[[u8; 32]],
    sql: &str,
    cancellation: &CancellationToken,
) -> Result<Option<Vec<i64>>> {
    let mut statement = connection.prepare_cached(sql)?;
    let mut rows = statement.query([producer])?;
    let mut result = Vec::with_capacity(digests.len());
    while let Some(row) = rows.next()? {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let dense: usize = row.get(0)?;
        let runtime: i64 = row.get(1)?;
        let digest: Vec<u8> = row.get(2)?;
        let actual_host: u32 = row.get(3)?;
        if dense != result.len()
            || digests
                .get(dense)
                .is_none_or(|expected| digest.as_slice() != expected)
            || actual_host != host.get()
        {
            return Err(StoreError::new(format!(
                "saved coordinate correspondence disagrees: producer={producer}, host={host:?}, dense={dense}, runtime={runtime}, digest={digest:?}, actual_host={actual_host}"
            )));
        }
        result.push(runtime);
    }
    if result.len() != digests.len() {
        return Err(StoreError::new(format!(
            "saved coordinate correspondence is incomplete: producer={producer}, expected={}, actual={}",
            digests.len(),
            result.len()
        )));
    }
    Ok((!cancellation.is_cancelled()).then_some(result))
}

pub(super) fn replay_catalog(
    selection: &SelectedResolutionMountInventory<'_>,
    connection: &Connection,
    producer: i64,
    host: SelectedResolutionMountOrdinal,
    catalog: &ResolutionIdentityCatalog,
    cancellation: &CancellationToken,
) -> Result<Option<ResolutionRegisteredIdentities>> {
    require_transaction(connection);
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    require_host(connection, host)?;
    let actual: Option<u32> = connection.prepare_cached("SELECT host_ordinal FROM temp.selected_resolution_stage_producers WHERE producer_id=?1")?.query_row([producer], |row| row.get(0)).optional()?;
    if actual != Some(host.get()) {
        return Err(StoreError::new(format!(
            "saved producer has wrong selected host: producer={producer}, host={host:?}, actual={actual:?}"
        )));
    }
    let names = selection.shared_name_table().interner(connection);
    let mut assigned =
        ResolutionRegisteredIdentities::new(BindingFragmentId::at_ordinal(host.get()));
    let mut digests = Vec::with_capacity(catalog.semantics().len());
    for &(_, identity) in catalog.semantics() {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        digests.push(catalog.identity_hash_bytes(identity));
    }
    let Some(values) = replay_rows(
        connection,
        producer,
        host,
        &digests,
        "SELECT dense_key,coalesce(runtime_key,-shared_id),identity_digest,host_ordinal FROM temp.selected_resolution_stage_semantic_coordinates WHERE producer_id=?1 ORDER BY dense_key",
        cancellation,
    )?
    else {
        return Ok(None);
    };
    for (index, (&(dense, identity), value)) in catalog.semantics().iter().zip(values).enumerate() {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let runtime = if identity.shared_name().is_some() {
            let held = codec::decode_semantic(value)
                .shared_name_id()
                .ok_or_else(|| StoreError::new("saved shared coordinate is local"))?;
            let held = if held.is_interned() {
                names.from_persisted(held)
            } else {
                held
            };
            let expected = names.intern(digests[index]);
            if held != expected {
                return Err(StoreError::new(format!(
                    "saved shared coordinate disagrees: held={held:?}, expected={expected:?}"
                )));
            }
            SemanticId::shared_name(expected)
        } else {
            SemanticId::local(host.get(), local_key(host, value)?)
        };
        assigned.assign_semantic(dense, runtime);
    }
    digests.clear();
    for &(_, identity) in catalog.nodes() {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        digests.push(identity.digest());
    }
    let Some(values) = replay_rows(
        connection,
        producer,
        host,
        &digests,
        "SELECT dense_key,runtime_key,identity_digest,host_ordinal FROM temp.selected_resolution_stage_node_coordinates WHERE producer_id=?1 ORDER BY dense_key",
        cancellation,
    )?
    else {
        return Ok(None);
    };
    for (&(dense, _), value) in catalog.nodes().iter().zip(values) {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        assigned.assign_node(
            dense,
            BindingNodeId::local(host.get(), local_key(host, value)?),
        );
    }
    digests.clear();
    for &(_, identity) in catalog.paths() {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        digests.push(identity.digest());
    }
    let Some(values) = replay_rows(
        connection,
        producer,
        host,
        &digests,
        "SELECT dense_key,runtime_key,identity_digest,host_ordinal FROM temp.selected_resolution_stage_path_coordinates WHERE producer_id=?1 ORDER BY dense_key",
        cancellation,
    )?
    else {
        return Ok(None);
    };
    for (&(dense, _), value) in catalog.paths().iter().zip(values) {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        assigned.assign_path(
            dense,
            PartialPathId::local(host.get(), local_key(host, value)?),
        );
    }
    digests.clear();
    for &(_, identity) in catalog.stack_variables() {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        digests.push(identity.digest());
    }
    let Some(values) = replay_rows(
        connection,
        producer,
        host,
        &digests,
        "SELECT dense_key,runtime_key,identity_digest,host_ordinal FROM temp.selected_resolution_stage_variable_coordinates WHERE producer_id=?1 ORDER BY dense_key",
        cancellation,
    )?
    else {
        return Ok(None);
    };
    for (&(dense, _), value) in catalog.stack_variables().iter().zip(values) {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        assigned.assign_stack_variable(
            dense,
            StackVariableId::local(host.get(), local_key(host, value)?),
        );
    }
    Ok((!cancellation.is_cancelled()).then_some(assigned))
}

#[cfg(test)]
#[path = "allocation_tests.rs"]
mod tests;
