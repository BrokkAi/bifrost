//! The one acquired Cargo configuration input set (#12398).
//! Rows are unselected inputs, keyed by the acquired digest. Derived evidence
//! names that exact digest in its input identity; no mutable-head lookup or
//! query-time filesystem acquisition is permitted.
use std::collections::BTreeSet;
use std::path::PathBuf;

use brokk_bifrost_core::analyzer::canonical_hash::{lower_hex_string, parse_lower_sha256};
use brokk_bifrost_rust::cargo_config::acquired::*;
use brokk_bifrost_rust::cargo_config::{RustCargoConfigSourceEffect, RustStdlibBuildMode};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::{Result, StoreError, WorkspaceSnapshotId};

const FAMILY: &str = "bifrost.acquired-cargo-config.v2";
const DERIVED: &str = "bifrost.cargo-config-bound.v1";
/// Families whose unreferenced input sets are reclaimed: the current one and
/// the retired v1 that stores written before #12600 still hold. Nothing reads
/// v1 sets, but derived sets of retained revisions still name them.
const RECLAIMED_FAMILIES: [&str; 2] = [FAMILY, "bifrost.acquired-cargo-config.v1"];

fn path_row_id(kind: &str, path: &std::path::Path) -> String {
    format!(
        "{kind}/{}",
        brokk_bifrost_core::path_utils::workspace_relative_slash_path(path)
    )
}

fn invalid() -> StoreError {
    StoreError::new("invalid recorded Cargo configuration input")
}
fn value<T: DeserializeOwned>(row: &Value, key: &str) -> Result<T> {
    serde_json::from_value(row.get(key).cloned().ok_or_else(invalid)?).map_err(|_| invalid())
}
fn mode(label: &str) -> Result<RustStdlibBuildMode> {
    match label {
        "prebuilt" => Ok(RustStdlibBuildMode::Prebuilt),
        "build_std" => Ok(RustStdlibBuildMode::BuildStd),
        "unknown" => Ok(RustStdlibBuildMode::Unknown),
        _ => Err(invalid()),
    }
}
fn effect(label: &str) -> Result<RustCargoConfigSourceEffect> {
    match label {
        "preserves" => Ok(RustCargoConfigSourceEffect::Preserves),
        "changes" => Ok(RustCargoConfigSourceEffect::Changes),
        "unknown" => Ok(RustCargoConfigSourceEffect::Unknown),
        _ => Err(invalid()),
    }
}
fn failure(label: &str) -> Result<RustCargoConfigReadFailure> {
    [
        RustCargoConfigReadFailure::Unreadable,
        RustCargoConfigReadFailure::Malformed,
        RustCargoConfigReadFailure::OutsideInclude,
        RustCargoConfigReadFailure::CyclicInclude,
        RustCargoConfigReadFailure::SourceFilesLimit,
        RustCargoConfigReadFailure::TotalBytesLimit,
        RustCargoConfigReadFailure::FileBytesLimit,
        RustCargoConfigReadFailure::MissingRequiredInclude,
        RustCargoConfigReadFailure::Unclassifiable,
        RustCargoConfigReadFailure::UnknownHome,
        RustCargoConfigReadFailure::ChangedDuringAcquisition,
    ]
    .into_iter()
    .find(|reason| reason.label() == label)
    .ok_or_else(invalid)
}

pub(super) fn bound_digest(derived: &str, acquired: &[u8; 32]) -> String {
    format!("{DERIVED}:{derived}:{}", lower_hex_string(acquired))
}
fn acquired_digest(identity: &str) -> Option<[u8; 32]> {
    let suffix = identity.strip_prefix(DERIVED)?.strip_prefix(':')?;
    let (derived, acquired) = suffix.split_once(':')?;
    parse_lower_sha256(derived)?;
    parse_lower_sha256(acquired)
}

pub(super) fn selected_digest(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
) -> Result<Option<[u8; 32]>> {
    let identity:Option<String>=conn.prepare_cached(
        "SELECT inputs.input_digest FROM dependency_evidence_selections AS selection JOIN dependency_evidence_sets AS inputs USING(set_id)
         WHERE selection.workspace_id=?1 AND selection.lang=?2 AND selection.generation=?3 AND selection.revision=?4")?
        .query_row(
        params![snapshot.workspace_id.as_str(),snapshot.lang,snapshot.generation.get(),snapshot.revision],|row|row.get(0)).optional()?;
    Ok(identity.as_deref().and_then(acquired_digest))
}

pub(super) fn persist(
    tx: &Transaction<'_>,
    snapshot: &WorkspaceSnapshotId,
    view: &RustCargoAcquiredConfigView,
) -> Result<[u8; 32]> {
    let digest = view.digest();
    let identity = format!("{FAMILY}:{}", lower_hex_string(&digest));
    let existing:Option<i64>=tx.prepare_cached("SELECT set_id FROM dependency_evidence_sets WHERE workspace_id=?1 AND lang='rust' AND generation=?2 AND input_digest=?3")?.query_row(params![snapshot.workspace_id.as_str(),snapshot.generation.get(),identity],|row|row.get(0)).optional()?;
    if existing.is_some() {
        return Ok(digest);
    }
    tx.prepare_cached("INSERT INTO dependency_evidence_sets(workspace_id,lang,generation,input_digest) VALUES(?1,'rust',?2,?3)")?.execute(params![snapshot.workspace_id.as_str(),snapshot.generation.get(),identity])?;
    let set = tx.last_insert_rowid();
    let mut insert=tx.prepare_cached("INSERT INTO dependency_file_evidence(set_id,id,ecosystem,package,kind,scope,conditions,build_file,source_digest,start_byte,end_byte,complete) VALUES(?1,?2,?3,'','declared','acquired-input',?4,?5,?6,0,0,?7)")?;
    let mut row = |id: String, path: &str, body: Value| -> Result<()> {
        insert.execute(params![
            set,
            id,
            FAMILY,
            body.to_string(),
            path,
            lower_hex_string(&digest),
            view.complete
        ])?;
        Ok(())
    };
    row(
        "header".into(),
        "",
        json!({"complete":view.complete,"host_triple":view.host_triple}),
    )?;
    for (path, input) in &view.local_inputs {
        row(
            path_row_id("local", path),
            &path.to_string_lossy(),
            json!({"path":path,"oid":input.oid.to_string(),"present":input.present}),
        )?;
    }
    for (index, read) in view.reads.iter().enumerate() {
        let state = match &read.state {
            RustCargoConfigReadState::Absent => json!({"kind":"absent"}),
            RustCargoConfigReadState::File { sha256, bytes } => {
                json!({"kind":"file","sha256":lower_hex_string(sha256),"bytes":bytes})
            }
            RustCargoConfigReadState::Environment {
                value_sha256,
                working_directory_sha256,
            } => {
                let mut state = json!({"kind":"environment","value_sha256":value_sha256.as_ref().map(lower_hex_string)});
                if let Some(digest) = working_directory_sha256 {
                    state["working_directory_sha256"] = json!(lower_hex_string(digest));
                }
                state
            }
            RustCargoConfigReadState::Unavailable { reason } => {
                json!({"kind":"unavailable","reason":reason.label()})
            }
        };
        row(
            format!("read/{index}"),
            "",
            json!({"label":read.label,"state":state}),
        )?;
    }
    for (owner, facts) in &view.owners {
        row(
            path_row_id("owner", owner),
            &owner.to_string_lossy(),
            json!({
                "owner":owner,"workspace":facts.workspace,"targets":facts.targets,"target_configured":facts.target_configured,
                "target_unsupported":facts.target_unsupported,"target_defining":facts.target_defining,"build_mode":build_mode_label(facts.build_mode),
                "cfg_atoms":facts.cfg_atoms,"host_cfg_atoms":facts.host_cfg_atoms,"has_extern_flags":facts.has_extern_flags,
                "source_effect":source_effect_label(facts.source_effect),"complete":facts.complete,
                "external_source_unresolved":facts.external_source_unresolved,
                "local_layers":facts.local_layers.iter().map(|layer|(&layer.path,&layer.base)).collect::<Vec<_>>()
            }),
        )?;
    }
    Ok(digest)
}

pub(super) fn load(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
    expected: &[u8; 32],
) -> Result<Option<RustCargoAcquiredConfigView>> {
    let identity = format!("{FAMILY}:{}", lower_hex_string(expected));
    let set:Option<i64>=conn.prepare_cached("SELECT set_id FROM dependency_evidence_sets WHERE workspace_id=?1 AND lang='rust' AND generation=?2 AND input_digest=?3")?.query_row(params![snapshot.workspace_id.as_str(),snapshot.generation.get(),identity],|row|row.get(0)).optional()?;
    let Some(set) = set else {
        return Ok(None);
    };
    let mut statement = conn.prepare_cached(
        "SELECT id,conditions FROM dependency_file_evidence WHERE set_id=?1 ORDER BY id",
    )?;
    let mut rows = statement.query([set])?;
    let mut view = RustCargoAcquiredConfigView::default();
    let mut header = false;
    while let Some(row) = rows.next()? {
        let id: String = row.get(0)?;
        let text: String = row.get(1)?;
        let body: Value = serde_json::from_str(&text).map_err(|_| invalid())?;
        if id == "header" {
            let Some(host_triple) = body.get("host_triple") else {
                // Recorded before the host triple was part of the view (#12604):
                // its digest cannot be reproduced, so it is a missing legacy
                // acquisition, as for a store that never recorded one.
                return Ok(None);
            };
            header = true;
            view.complete = value(&body, "complete")?;
            view.host_triple =
                serde_json::from_value(host_triple.clone()).map_err(|_| invalid())?;
        } else if id.starts_with("local/") {
            let path: PathBuf = value(&body, "path")?;
            let oid: String = value(&body, "oid")?;
            view.local_inputs.insert(
                path,
                RustCargoLocalInputRef {
                    oid: git2::Oid::from_str(&oid).map_err(|_| invalid())?,
                    present: value(&body, "present")?,
                },
            );
        } else if id.starts_with("read/") {
            let state = body.get("state").ok_or_else(invalid)?;
            let kind: String = value(state, "kind")?;
            let state = match kind.as_str() {
                "absent" => RustCargoConfigReadState::Absent,
                "file" => {
                    let digest: String = value(state, "sha256")?;
                    RustCargoConfigReadState::File {
                        sha256: parse_lower_sha256(&digest).ok_or_else(invalid)?,
                        bytes: value(state, "bytes")?,
                    }
                }
                "environment" => {
                    let digest: Option<String> = value(state, "value_sha256")?;
                    RustCargoConfigReadState::Environment {
                        working_directory_sha256: state
                            .get("working_directory_sha256")
                            .map(|digest| {
                                digest
                                    .as_str()
                                    .and_then(parse_lower_sha256)
                                    .ok_or_else(invalid)
                            })
                            .transpose()?,
                        value_sha256: digest
                            .map(|digest| parse_lower_sha256(&digest).ok_or_else(invalid))
                            .transpose()?,
                    }
                }
                "unavailable" => RustCargoConfigReadState::Unavailable {
                    reason: failure(&value::<String>(state, "reason")?)?,
                },
                _ => return Err(invalid()),
            };
            view.reads.push(RustCargoConfigRead {
                label: value(&body, "label")?,
                state,
            });
        } else if id.starts_with("owner/") {
            let (owner, facts) = owner_facts(&body)?;
            view.owners.insert(owner, facts);
        } else {
            return Err(invalid());
        }
    }
    if !header || view.digest() != *expected {
        return Err(invalid());
    }
    Ok(Some(view))
}

pub(super) fn selected(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
) -> Result<Option<RustCargoAcquiredConfigView>> {
    selected_digest(conn, snapshot)?
        .map(|digest| load(conn, snapshot, &digest))
        .transpose()
        .map(Option::flatten)
}

/// Reclaim only input sets unreferenced by any retained derived identity.
/// Old snapshot selections continue to own their original recorded view.
pub(super) fn reclaim(conn: &Connection, snapshot: &WorkspaceSnapshotId) -> Result<()> {
    for family in RECLAIMED_FAMILIES {
        let prefix = format!("{family}:%");
        conn.prepare_cached("DELETE FROM dependency_evidence_sets AS acquired WHERE acquired.workspace_id=?1 AND acquired.lang='rust' AND acquired.generation=?2 AND acquired.input_digest LIKE ?3
           AND NOT EXISTS(SELECT 1 FROM dependency_evidence_sets AS derived WHERE derived.workspace_id=acquired.workspace_id AND derived.lang=acquired.lang AND derived.generation=acquired.generation
           AND derived.input_digest LIKE ?4 || substr(acquired.input_digest,?5))")?
           .execute(params![snapshot.workspace_id.as_str(),snapshot.generation.get(),prefix,format!("{DERIVED}:%:"),family.len()+2])?;
    }
    Ok(())
}

/// Reconciliation consumes the same acquired record and retained local bytes
/// as pure evidence, including arbitrary contained include filenames.
pub(super) fn configuration(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
) -> Result<Option<brokk_bifrost_rust::cargo_config::RustCargoConfiguration>> {
    let Some(view) = selected(conn, snapshot)? else {
        return Ok(None);
    };
    let mut statement=conn.prepare_cached("SELECT files.rel_path,files.blob_oid,files.file_present,retained.source_bytes FROM workspace_file_versions AS files JOIN workspace_input_sources AS retained ON retained.content_oid=files.blob_oid WHERE files.workspace_id=?1 AND files.lang='rust' AND files.generation=?2 AND files.input_kind='configuration' AND files.valid_from<=?3 AND (files.valid_until IS NULL OR ?3<files.valid_until) ORDER BY files.rel_path")?;
    let rows = statement
        .query_map(
            params![
                snapshot.workspace_id.as_str(),
                snapshot.generation.get(),
                snapshot.revision
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<bool>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let inputs = rows
        .iter()
        .map(|(path, oid, present, bytes)| {
            Ok((
                PathBuf::from(path),
                git2::Oid::from_str(oid).map_err(|_| invalid())?,
                *present,
                bytes,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Some(
        brokk_bifrost_rust::cargo_config::RustCargoConfiguration::from_acquired_view(
            &view,
            inputs.iter().map(|(path, oid, present, bytes)| {
                (path.as_path(), *oid, *present, bytes.as_slice())
            }),
        ),
    ))
}

impl super::AnalyzerStore {
    /// The reader is bound to the selected immutable snapshot and exact input
    /// record identity. Missing legacy acquisition is explicitly partial.
    #[doc(hidden)]
    pub fn selected_rust_cargo_configuration(
        &self,
        snapshot: &WorkspaceSnapshotId,
    ) -> Result<brokk_bifrost_rust::cargo_config::RustCargoConfiguration> {
        let conn = self.read_conn()?;
        Ok(configuration(&conn, snapshot)?.unwrap_or_else(
            brokk_bifrost_rust::cargo_config::RustCargoConfiguration::unknown_acquired,
        ))
    }
}

pub(super) fn reclaim_all(conn: &Connection) -> Result<()> {
    for family in RECLAIMED_FAMILIES {
        conn.prepare_cached("DELETE FROM dependency_evidence_sets AS acquired WHERE acquired.lang='rust' AND acquired.input_digest LIKE ?1
           AND NOT EXISTS(SELECT 1 FROM dependency_evidence_sets AS derived WHERE derived.workspace_id=acquired.workspace_id AND derived.lang=acquired.lang AND derived.generation=acquired.generation
           AND derived.input_digest LIKE ?2 || substr(acquired.input_digest,?3))")?
           .execute(params![format!("{family}:%"),format!("{DERIVED}:%:"),family.len()+2])?;
    }
    Ok(())
}

pub(super) fn load_for_set(
    conn: &Connection,
    set_id: i64,
    snapshot: &WorkspaceSnapshotId,
) -> Result<Option<RustCargoAcquiredConfigView>> {
    let identity: String = conn
        .prepare_cached("SELECT input_digest FROM dependency_evidence_sets WHERE set_id=?1")?
        .query_row([set_id], |row| row.get(0))?;
    acquired_digest(&identity)
        .map(|digest| load(conn, snapshot, &digest))
        .transpose()
        .map(Option::flatten)
}

fn owner_facts(body: &Value) -> Result<(PathBuf, RustCargoConfigOwnerFacts)> {
    let owner: PathBuf = value(body, "owner")?;
    let layers: Vec<(PathBuf, PathBuf)> = value(body, "local_layers")?;
    let facts = RustCargoConfigOwnerFacts {
        workspace: value(body, "workspace")?,
        targets: value(body, "targets")?,
        target_configured: value(body, "target_configured")?,
        target_defining: value(body, "target_defining")?,
        target_unsupported: value(body, "target_unsupported")?,
        build_mode: mode(&value::<String>(body, "build_mode")?)?,
        cfg_atoms: value::<BTreeSet<String>>(body, "cfg_atoms")?,
        host_cfg_atoms: value(body, "host_cfg_atoms")?,
        has_extern_flags: value(body, "has_extern_flags")?,
        source_effect: effect(&value::<String>(body, "source_effect")?)?,
        complete: value(body, "complete")?,
        external_source_unresolved: value(body, "external_source_unresolved")?,
        local_layers: layers
            .into_iter()
            .map(|(path, base)| RustCargoLocalLayerRef { path, base })
            .collect(),
    };
    Ok((owner, facts))
}

/// Point lookup by selected set + owner + local layer. The publisher validated
/// the entire acquired view against this revision; no full-workspace hydration
/// or filesystem acquisition belongs in this query-facing accessor.
pub(super) fn configuration_at_directory(
    conn: &Connection,
    snapshot: &WorkspaceSnapshotId,
    directory: &std::path::Path,
) -> Result<Option<brokk_bifrost_rust::cargo_config::RustCargoConfiguration>> {
    let Some(expected) = selected_digest(conn, snapshot)? else {
        return Ok(None);
    };
    let identity = format!("{FAMILY}:{}", lower_hex_string(&expected));
    let set:Option<i64>=conn.prepare_cached("SELECT set_id FROM dependency_evidence_sets WHERE workspace_id=?1 AND lang='rust' AND generation=?2 AND input_digest=?3")?.query_row(params![snapshot.workspace_id.as_str(),snapshot.generation.get(),identity],|row|row.get(0)).optional()?;
    let Some(set) = set else {
        return Ok(None);
    };
    let read = |id: &str| -> Result<Option<Value>> {
        let text: Option<String> = conn
            .prepare_cached(
                "SELECT conditions FROM dependency_file_evidence WHERE set_id=?1 AND id=?2",
            )?
            .query_row(params![set, id], |row| row.get(0))
            .optional()?;
        text.map(|text| serde_json::from_str(&text).map_err(|_| invalid()))
            .transpose()
    };
    let Some(header) = read("header")? else {
        return Err(invalid());
    };
    let Some(body) = read(&path_row_id("owner", directory))? else {
        return Ok(Some(
            brokk_bifrost_rust::cargo_config::RustCargoConfiguration::unknown_acquired(),
        ));
    };
    let (owner, facts) = owner_facts(&body)?;
    if owner != directory {
        return Err(invalid());
    }
    // A header recorded before the host triple was part of the view cannot
    // reproduce the view's identity; use the file-reading path instead.
    let Some(host_triple) = header.get("host_triple") else {
        return Ok(None);
    };
    let mut view = RustCargoAcquiredConfigView {
        complete: value(&header, "complete")?,
        host_triple: serde_json::from_value(host_triple.clone()).map_err(|_| invalid())?,
        ..Default::default()
    };
    let mut snapshots = Vec::new();
    for layer in &facts.local_layers {
        let Some(body) = read(&path_row_id("local", &layer.path))? else {
            return Err(invalid());
        };
        let oid: String = value(&body, "oid")?;
        let present: Option<bool> = value(&body, "present")?;
        let oid = git2::Oid::from_str(&oid).map_err(|_| invalid())?;
        view.local_inputs
            .insert(layer.path.clone(), RustCargoLocalInputRef { oid, present });
        let input:Option<(String,Option<bool>,Vec<u8>)>=conn.prepare_cached("SELECT files.blob_oid,files.file_present,retained.source_bytes FROM workspace_file_versions AS files JOIN workspace_input_sources AS retained ON retained.content_oid=files.blob_oid WHERE files.workspace_id=?1 AND files.lang='rust' AND files.generation=?2 AND files.input_kind='configuration' AND files.rel_path=?3 AND files.valid_from<=?4 AND (files.valid_until IS NULL OR ?4<files.valid_until)")?.query_row(params![snapshot.workspace_id.as_str(),snapshot.generation.get(),brokk_bifrost_core::path_utils::workspace_relative_slash_path(&layer.path),snapshot.revision],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional()?;
        if let Some((oid, present, bytes)) = input {
            snapshots.push((
                layer.path.clone(),
                git2::Oid::from_str(&oid).map_err(|_| invalid())?,
                present,
                bytes,
            ));
        }
    }
    view.owners.insert(owner, facts);
    Ok(Some(
        brokk_bifrost_rust::cargo_config::RustCargoConfiguration::from_acquired_view(
            &view,
            snapshots.iter().map(|(path, oid, present, bytes)| {
                (path.as_path(), *oid, *present, bytes.as_slice())
            }),
        ),
    ))
}
