//! Persisted facts of workspace RBS signature files (#12967), one head per
//! signature file blob and producer identity. Written when the Ruby analyzer
//! builds or updates, never on the query path.

use brokk_bifrost_analysis::analyzer::store::{AnalyzerStore, Result};
use git2::Oid;
use rusqlite::{OptionalExtension, params};

use super::workspace_signatures::{
    RbsClassType, RbsTypeName, RubySignatureFile, RubySignatureMethod,
};

/// The identity of the producer that wrote a head. A head another producer
/// wrote is invisible to readers; garbage collection removes it with its
/// blob.
fn producer_identity() -> [u8; 32] {
    static IDENTITY: std::sync::LazyLock<[u8; 32]> = std::sync::LazyLock::new(|| {
        brokk_bifrost_core::lever_tokens::lever_identity(
            "ruby-workspace-signatures",
            brokk_bifrost_core::lever_file!("ruby-workspace-signatures.tokens"),
        )
    });
    *IDENTITY
}

const INSERT_HEAD_SQL: &str =
    "INSERT OR IGNORE INTO ruby_signature_files(content_oid, producer_identity, parse_state)
     VALUES (?1, ?2, ?3)";
const INSERT_METHOD_SQL: &str = "INSERT INTO ruby_signature_methods(signature_file_id, method_ordinal, owner, member, is_singleton, overload_count, leading_required)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";
const INSERT_POSITIONAL_SQL: &str = "INSERT INTO ruby_signature_positionals(signature_file_id, method_ordinal, ordinal, receiver_absolute, receiver_name, argument_count, element_absolute, element_name)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)";
const INSERT_TYPE_SQL: &str =
    "INSERT OR IGNORE INTO ruby_signature_types(signature_file_id, name) VALUES (?1, ?2)";
const TYPE_DECLARED_SQL: &str = "SELECT file.content_oid FROM ruby_signature_types AS declared
     JOIN ruby_signature_files AS file ON file.signature_file_id = declared.signature_file_id
     WHERE declared.name = ?1 AND file.producer_identity = ?2";
const COLLECTION_EPOCH_SQL: &str = "SELECT epoch FROM ruby_signature_collection_epoch WHERE id = 1";
const HEAD_SQL: &str =
    "SELECT 1 FROM ruby_signature_files WHERE content_oid = ?1 AND producer_identity = ?2";
const METHODS_NAMED_SQL: &str = "SELECT file.content_oid, method.signature_file_id, method.method_ordinal, method.is_singleton, method.overload_count, method.leading_required
     FROM ruby_signature_methods AS method
     JOIN ruby_signature_files AS file ON file.signature_file_id = method.signature_file_id
     WHERE method.owner = ?1 AND method.member = ?2 AND file.producer_identity = ?3";
const POSITIONALS_SQL: &str = "SELECT ordinal, receiver_absolute, receiver_name, argument_count, element_absolute, element_name
     FROM ruby_signature_positionals WHERE signature_file_id = ?1 AND method_ordinal = ?2";

/// Persist `file`, the facts of blob `oid`. A blob that already has a head
/// for this producer writes nothing.
pub(super) fn publish_ruby_signature_file(
    store: &AnalyzerStore,
    oid: Oid,
    file: RubySignatureFile,
) -> Result<()> {
    let identity = producer_identity();
    store.conn.execute(move |conn| -> Result<()> {
        let tx = conn.transaction()?;
        let inserted = tx.execute(
            INSERT_HEAD_SQL,
            params![oid.to_string(), &identity[..], file.state.label()],
        )?;
        if inserted == 1 {
            let head = tx.last_insert_rowid();
            let mut insert_method = tx.prepare_cached(INSERT_METHOD_SQL)?;
            let mut insert_positional = tx.prepare_cached(INSERT_POSITIONAL_SQL)?;
            let mut insert_type = tx.prepare_cached(INSERT_TYPE_SQL)?;
            for name in &file.types {
                insert_type.execute(params![head, &**name])?;
            }
            for (ordinal, method) in file.methods.iter().enumerate() {
                insert_method.execute(params![
                    head,
                    ordinal,
                    method.owner_name(),
                    &*method.member,
                    method.is_singleton,
                    method.overload_count,
                    method.leading_required,
                ])?;
                for (position, class) in method.positionals.iter().enumerate() {
                    let Some(class) = class else {
                        continue;
                    };
                    insert_positional.execute(params![
                        head,
                        ordinal,
                        position,
                        class.name.absolute,
                        class.name.segments.join("::"),
                        class.argument_count,
                        class.element.as_ref().map(|element| element.absolute),
                        class
                            .element
                            .as_ref()
                            .map(|element| element.segments.join("::")),
                    ])?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    })
}

/// The garbage-collection epoch at which every one of `blobs` had a head
/// for this producer, or `None` when one has none (never published, or
/// collected), so its facts are unknown.
#[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
pub(super) fn ruby_signature_heads_present(
    store: &AnalyzerStore,
    blobs: &[Oid],
) -> Result<Option<i64>> {
    let identity = producer_identity();
    let mut conn = store.read_conn()?;
    let tx = conn.transaction()?;
    let epoch = tx.query_row(COLLECTION_EPOCH_SQL, [], |row| row.get::<_, i64>(0))?;
    let mut head = tx.prepare_cached(HEAD_SQL)?;
    for blob in blobs {
        if head
            .query_row(params![blob.to_string(), &identity[..]], |_| Ok(()))
            .optional()?
            .is_none()
        {
            return Ok(None);
        }
    }
    Ok(Some(epoch))
}

/// The stored declarations of `member` of `owner` in each of `blobs`, one
/// entry per blob in order, or `None` when garbage collection has deleted
/// a head since `epoch`, when the heads were all present.
#[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
pub(super) fn ruby_signature_methods_named(
    store: &AnalyzerStore,
    owner: &str,
    member: &str,
    blobs: &[Oid],
    epoch: i64,
) -> Result<Option<Vec<Vec<RubySignatureMethod>>>> {
    let identity = producer_identity();
    let mut conn = store.read_conn()?;
    let conn = conn.transaction()?;
    if conn.query_row(COLLECTION_EPOCH_SQL, [], |row| row.get::<_, i64>(0))? != epoch {
        return Ok(None);
    }
    let mut methods = conn.prepare_cached(METHODS_NAMED_SQL)?;
    let mut positionals = conn.prepare_cached(POSITIONALS_SQL)?;
    let rows = methods
        .query_map(params![owner, member, &identity[..]], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, bool>(3)?,
                row.get::<_, u32>(4)?,
                row.get::<_, u32>(5)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut by_blob = vec![Vec::new(); blobs.len()];
    for (content_oid, head, ordinal, is_singleton, overload_count, leading_required) in rows {
        let content_oid = Oid::from_str(&content_oid).map_err(|error| {
            brokk_bifrost_analysis::analyzer::store::StoreError::new(format!(
                "ruby_signature_files holds a malformed OID {content_oid}: {error}"
            ))
        })?;
        let declared_in = blobs
            .iter()
            .enumerate()
            .filter(|(_, blob)| **blob == content_oid)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if declared_in.is_empty() {
            continue;
        }
        let mut typed = vec![None; usize::try_from(leading_required).unwrap_or(usize::MAX)];
        for positional in positionals.query_map(params![head, ordinal], |row| {
            Ok((
                row.get::<_, usize>(0)?,
                RbsClassType {
                    name: stored_name(row.get(1)?, &row.get::<_, String>(2)?),
                    argument_count: row.get(3)?,
                    element: row
                        .get::<_, Option<bool>>(4)?
                        .zip(row.get::<_, Option<String>>(5)?)
                        .map(|(absolute, name)| stored_name(absolute, &name)),
                },
            ))
        })? {
            let (position, class) = positional?;
            let slot = typed.get_mut(position).ok_or_else(|| {
                brokk_bifrost_analysis::analyzer::store::StoreError::new(format!(
                    "ruby_signature_positionals ordinal {position} exceeds leading_required {leading_required} for {owner}#{member}"
                ))
            })?;
            *slot = Some(class);
        }
        let method = RubySignatureMethod {
            owner: owner.split("::").map(Box::from).collect(),
            member: member.into(),
            is_singleton,
            overload_count,
            leading_required,
            positionals: typed.into(),
        };
        for index in declared_in {
            by_blob[index].push(method.clone());
        }
    }
    Ok(Some(by_blob))
}

/// Which of `names` (`::`-joined constant paths) some of `blobs` declares,
/// or `None` when garbage collection has deleted a head since `epoch`.
#[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
pub(super) fn ruby_signature_types_declared(
    store: &AnalyzerStore,
    names: &[String],
    blobs: &[Oid],
    epoch: i64,
) -> Result<Option<Vec<String>>> {
    let identity = producer_identity();
    let mut conn = store.read_conn()?;
    let conn = conn.transaction()?;
    if conn.query_row(COLLECTION_EPOCH_SQL, [], |row| row.get::<_, i64>(0))? != epoch {
        return Ok(None);
    }
    let mut declaring = conn.prepare_cached(TYPE_DECLARED_SQL)?;
    let mut declared = Vec::new();
    for name in names {
        let files = declaring
            .query_map(params![name, &identity[..]], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if files
            .iter()
            .any(|oid| blobs.iter().any(|blob| blob.to_string() == *oid))
        {
            declared.push(name.clone());
        }
    }
    Ok(Some(declared))
}

/// A `::`-joined constant path this module wrote.
fn stored_name(absolute: bool, name: &str) -> RbsTypeName {
    RbsTypeName {
        absolute,
        segments: name.split("::").map(Box::from).collect(),
    }
}
