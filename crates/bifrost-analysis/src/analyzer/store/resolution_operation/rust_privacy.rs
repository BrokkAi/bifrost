//! Exact Rust declaration authority for selected root endpoints.
//!
//! This module deliberately keeps the source identity chain explicit.  A
//! selected endpoint is admitted only after its definition `source_site` is
//! joined to `source_native_declaration_bridges.declaration_id`, and that
//! declaration id is joined to the Rust property row.  Names, display units,
//! and shared root-export tokens are not authority keys.

use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;
use brokk_bifrost_core::analyzer::rust_facts::{RustVisibility, decode_rust_visibility};
use brokk_bifrost_core::analyzer::source_facts::SourceDeclarationId;
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
use rusqlite::types::Value;
use std::path::{Path, PathBuf};

use crate::CancellationToken;
use crate::analyzer::resolution::{
    MAX_SOURCE_ROWS_PER_BATCH, ResolutionCompletion, SelectedResolutionMountOrdinal,
    TypedFactReadOutcome, TypedFactReadTerminal,
};
use brokk_bifrost_rust::selected_context::RustSelectedDeclarationAuthority;

use super::super::resolution::with_resolution_read_progress_handler;
use super::super::resolution_selection::SelectedResolutionMountInventory;
use super::{Result, StoreError};

/// One exact source-owned visibility fact attached to a selected mount.
///
/// `source_site` and `declaration` are retained together so callers cannot
/// accidentally replace this identity with a display name or unit key while
/// constructing a root endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RustSelectedDeclarationAuthorityFact {
    pub(crate) mount: Option<SelectedResolutionMountOrdinal>,
    pub(crate) source_site: ResolutionSiteId,
    pub(crate) declaration: SourceDeclarationId,
    pub(crate) visibility: RustVisibility,
}

/// Attach the selected topology's crate and declaring-module coordinates to a
/// source-owned authority fact. The source identity and visibility remain
/// exactly those returned by the canonical source-site bridge; topology only
/// supplies the lexical context needed to evaluate restricted visibility.
pub(crate) fn rust_selected_declaration_authority(
    fact: RustSelectedDeclarationAuthorityFact,
    crate_root: &Path,
    declaring_module_segments: &[String],
) -> RustSelectedDeclarationAuthority {
    RustSelectedDeclarationAuthority {
        source_site: fact.source_site,
        declaration: fact.declaration,
        crate_root: PathBuf::from(crate_root),
        declaring_module_segments: declaring_module_segments.to_vec().into_boxed_slice(),
        visibility: fact.visibility,
    }
}

pub(super) fn complete_access_source_read(
    outcome: TypedFactReadOutcome,
    cancellation: &CancellationToken,
    family: &str,
) -> Result<Option<TypedFactReadOutcome>> {
    if cancellation.is_cancelled() {
        return Ok(Some(TypedFactReadOutcome::cancelled(
            outcome.evidence().clone(),
        )));
    }
    match outcome.terminal() {
        TypedFactReadTerminal::Cancelled => Ok(Some(outcome)),
        TypedFactReadTerminal::Stopped => Err(StoreError::new(format!(
            "selected {family} read stopped before exact authority completion: evidence={:?}",
            outcome.evidence()
        ))),
        TypedFactReadTerminal::Exhausted => {
            if outcome.evidence() != &ResolutionCompletion::Complete {
                return Err(StoreError::new(format!(
                    "selected {family} read returned incomplete authority evidence: {:?}",
                    outcome.evidence()
                )));
            }
            Ok(None)
        }
    }
}

/// Read the exact native visibility authority of every requested definition
/// source site.
///
/// A caller holding a definition node translates it to its source site
/// through the mount's interior first: the source site is the only key this
/// authority chain admits.
pub(crate) fn read_selected_rust_declaration_authority_with_cancellation(
    inventory: &SelectedResolutionMountInventory<'_>,
    requests: &[(SelectedResolutionMountOrdinal, ResolutionSiteId)],
    cancellation: &CancellationToken,
    session: Option<&ResolutionSession>,
) -> Result<Option<Vec<RustSelectedDeclarationAuthorityFact>>> {
    let mut authorities = Vec::with_capacity(requests.len());
    for chunk in requests.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
        if cancellation.is_cancelled()
            || session.is_some_and(|session| !session.observe_cancellation())
        {
            return Ok(None);
        }
        let chunk_authorities = match with_resolution_read_progress_handler(
            inventory.connection(),
            cancellation,
            |connection| read_selected_rust_declaration_authority_chunk(connection, chunk, session),
        ) {
            Ok(Some(authorities)) => authorities,
            Ok(None) => return Ok(None),
            Err(error) if cancellation.is_cancelled() && error.is_sqlite_interrupted() => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        if cancellation.is_cancelled()
            || session.is_some_and(|session| !session.observe_cancellation())
        {
            return Ok(None);
        }
        if chunk_authorities.len() != chunk.len() {
            return Err(StoreError::corrupt(format!(
                "Rust declaration authority returned {} rows for {} requests in one bounded page: requests={chunk:?}, authorities={chunk_authorities:?}",
                chunk_authorities.len(),
                chunk.len()
            )));
        }
        authorities.extend(chunk_authorities);
    }
    if authorities.len() != requests.len() {
        return Err(StoreError::corrupt(format!(
            "Rust declaration authority returned {} rows for {} requests: requests={requests:?}, authorities={authorities:?}",
            authorities.len(),
            requests.len()
        )));
    }
    Ok(Some(authorities))
}

fn read_selected_rust_declaration_authority_chunk(
    connection: &rusqlite::Connection,
    requests: &[(SelectedResolutionMountOrdinal, ResolutionSiteId)],
    session: Option<&ResolutionSession>,
) -> Result<Option<Vec<RustSelectedDeclarationAuthorityFact>>> {
    if requests.is_empty() {
        return Ok(Some(Vec::new()));
    }
    assert!(
        requests.len() <= MAX_SOURCE_ROWS_PER_BATCH,
        "Rust declaration authority SQL page exceeds the bounded source-row contract"
    );

    let sql = selected_rust_declaration_authority_sql(requests.len());
    let mut parameters = Vec::with_capacity(requests.len() * 2);
    for (mount, source_site) in requests {
        if session.is_some_and(|session| !session.scope_step()) {
            return Ok(None);
        }
        parameters.push(Value::Integer(i64::from(mount.get())));
        parameters.push(Value::Integer(i64::from(source_site.get())));
    }

    let mut statement = connection.prepare(&sql)?;
    let mut rows = statement.query(rusqlite::params_from_iter(parameters))?;
    let mut authorities = Vec::with_capacity(requests.len());
    while let Some(row) = rows.next()? {
        if session.is_some_and(|session| !session.scope_step()) {
            return Ok(None);
        }
        let request_ordinal: usize = row.get::<_, i64>(0)?.try_into().map_err(|_| {
            StoreError::corrupt("Rust declaration authority request ordinal is invalid")
        })?;
        let expected = requests.get(request_ordinal).ok_or_else(|| {
            StoreError::corrupt(format!(
                "Rust declaration authority returned unknown request ordinal {request_ordinal}"
            ))
        })?;
        let requested_mount = nonnegative_u32(row.get(1)?, "requested Rust authority mount")?;
        let requested_site = nonnegative_u32(row.get(2)?, "requested Rust authority source site")?;
        let selected_mount = row
            .get::<_, Option<i64>>(3)?
            .map(|value| nonnegative_u32(value, "selected Rust authority mount"))
            .transpose()?;
        let blob_id = row.get::<_, Option<i64>>(4)?;
        let semantic_site = row
            .get::<_, Option<i64>>(5)?
            .map(|value| nonnegative_u32(value, "Rust semantic source site"))
            .transpose()?;
        let semantic_role = row.get::<_, Option<String>>(6)?;
        let declaration = row
            .get::<_, Option<i64>>(7)?
            .map(|value| nonnegative_u32(value, "Rust declaration id"))
            .transpose()?;
        let property_declaration = row
            .get::<_, Option<i64>>(8)?
            .map(|value| nonnegative_u32(value, "Rust property declaration id"))
            .transpose()?;
        let visibility = row.get::<_, Option<String>>(9)?;
        if requested_mount != expected.0.get()
            || requested_site != expected.1.get()
            || semantic_site != Some(requested_site)
            || selected_mount != Some(requested_mount)
            || blob_id.is_none()
            || semantic_role.as_deref() != Some("definition")
            || declaration.is_none()
            || property_declaration != declaration
            || visibility.is_none()
        {
            return Err(StoreError::corrupt(format!(
                "incomplete Rust declaration authority for request {expected:?}: requested_mount={requested_mount}, requested_site={requested_site}, selected_mount={selected_mount:?}, blob_id={blob_id:?}, semantic_site={semantic_site:?}, semantic_role={semantic_role:?}, declaration={declaration:?}, property_declaration={property_declaration:?}, visibility={visibility:?}"
            )));
        }
        let visibility = decode_rust_visibility(
            visibility
                .as_deref()
                .expect("visibility is checked above"),
        )
        .ok_or_else(|| {
            StoreError::corrupt(format!(
                "unknown Rust declaration visibility for selected mount {requested_mount} source site {requested_site:?}"
            ))
        })?;
        authorities.push(RustSelectedDeclarationAuthorityFact {
            mount: Some(SelectedResolutionMountOrdinal::new(requested_mount)),
            source_site: ResolutionSiteId::new(
                semantic_site.expect("semantic source site is checked above"),
            ),
            declaration: SourceDeclarationId::new(
                declaration.expect("declaration is checked above"),
            ),
            visibility,
        });
    }
    if authorities.len() != requests.len() {
        return Err(StoreError::corrupt(format!(
            "Rust declaration authority returned {} rows for {} requests: requests={requests:?}, authorities={authorities:?}",
            authorities.len(),
            requests.len()
        )));
    }
    Ok(Some(authorities))
}

/// Canonical persisted authority query. Keep this builder shared by the
/// bounded reader and planner-statistics pin so the plan assertion cannot
/// silently drift from production SQL.
pub(crate) fn selected_rust_declaration_authority_sql(request_count: usize) -> String {
    assert!(
        (1..=MAX_SOURCE_ROWS_PER_BATCH).contains(&request_count),
        "Rust declaration authority SQL request count is outside the bounded page contract"
    );

    let values = (0..request_count)
        .map(|index| format!("({index}, ?, ?)"))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "WITH requested(request_ordinal, mount_ordinal, source_site) AS (VALUES {values})
         SELECT DISTINCT requested.request_ordinal,
                requested.mount_ordinal,
                requested.source_site,
                selected.mount_ordinal,
                interior.blob_id,
                semantic.source_site,
                semantic.semantic_role,
                native.declaration_id,
                property.declaration_id,
                property.visibility
           FROM requested
           LEFT JOIN temp.selected_resolution_mounts AS selected
             ON selected.mount_ordinal = requested.mount_ordinal
           LEFT JOIN main.resolution_fragment_interiors AS interior
             ON interior.blob_id = selected.blob_id
            AND interior.lang = selected.storage_language
            AND interior.semantic_language = selected.semantic_language
            AND interior.producer_epoch = selected.producer_epoch
            AND interior.interior_digest = selected.interior_digest
            AND interior.publication_state = 'complete'
           LEFT JOIN main.resolution_semantic_sites AS semantic
             ON semantic.blob_id = interior.blob_id
            AND semantic.semantic_role = 'definition'
            AND semantic.source_site = requested.source_site
           LEFT JOIN main.source_native_declaration_bridges AS native
             ON native.blob_id = semantic.blob_id
            AND native.source_site = semantic.source_site
           LEFT JOIN main.source_rust_declaration_properties AS property
             ON property.blob_id = native.blob_id
            AND property.declaration_id = native.declaration_id
          ORDER BY requested.request_ordinal"
    );
    sql
}

fn nonnegative_u32(value: i64, description: &str) -> Result<u32> {
    u32::try_from(value)
        .map_err(|_| StoreError::corrupt(format!("{description} is outside u32: {value}")))
}

fn nonnegative_i64(value: i64, description: &str) -> Result<i64> {
    if value < 0 {
        return Err(StoreError::corrupt(format!(
            "{description} is negative: {value}"
        )));
    }
    Ok(value)
}
