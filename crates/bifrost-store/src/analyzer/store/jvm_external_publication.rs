//! Exact, sealed publication of a JVM provider's catalog row projection.

use super::{AnalyzerStore, Result, StoreError};
use rusqlite::{
    OptionalExtension, Transaction, TransactionBehavior, params, params_from_iter, types::Value,
};
use sha2::{Digest, Sha256};

pub fn jvm_external_projection_identity() -> [u8; 32] {
    static IDENTITY: std::sync::LazyLock<[u8; 32]> = std::sync::LazyLock::new(|| {
        brokk_bifrost_core::lever_tokens::lever_identity(
            "jvm-external-projection",
            brokk_bifrost_core::lever_file!("jvm-external-projection.tokens"),
        )
    });
    *IDENTITY
}

/// Values use the target inventory table's column order, including provider_id.
/// The caller reads these through its pinned catalog handle. No decoded shard is used.
#[derive(Debug)]
pub struct JvmExternalProjection {
    pub provider_id: String,
    pub source_identity: String,
    pub owners: Vec<Vec<Value>>,
    pub members: Vec<Vec<Value>>,
    pub supertypes: Vec<Vec<Value>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JvmExternalPublication {
    Available,
    Unavailable,
    Conflict,
}

const OWNER_COLUMNS: &str = "provider_id,owner_fqn,callables_complete,values_complete,types_complete,supertypes_complete,type_parameters_jsonb";
const MEMBER_COLUMNS: &str = "provider_id,owner_fqn,ordinal,member_name,member_kind,visibility,is_static,signature_present,callable_family_complete,non_overridable,parameters_jsonb,return_type_jsonb,is_abstract,type_parameters_jsonb";
const MEMBER_READ_COLUMNS: &str = "provider_id,owner_fqn,ordinal,member_name,member_kind,visibility,is_static,signature_present,callable_family_complete,non_overridable,json(parameters_jsonb),json(return_type_jsonb),is_abstract,json(type_parameters_jsonb)";
const SUPERTYPE_COLUMNS: &str = "provider_id,owner_fqn,supertype_fqn,ordinal,type_arguments_jsonb";

fn canonical_rows(rows: &[Vec<Value>], columns: usize, digest: &mut Sha256) -> Result<()> {
    let mut encoded = Vec::with_capacity(rows.len());
    for row in rows {
        assert_eq!(row.len(), columns, "JVM projection row width");
        let mut bytes = Vec::new();
        for value in row {
            let (tag, payload): (u8, Vec<u8>) = match value {
                Value::Null => (0, Vec::new()),
                Value::Integer(n) => (1, n.to_le_bytes().to_vec()),
                Value::Real(n) => (2, n.to_bits().to_le_bytes().to_vec()),
                Value::Text(s) => (3, s.as_bytes().to_vec()),
                Value::Blob(b) => (4, b.clone()),
            };
            bytes.push(tag);
            bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
            bytes.extend_from_slice(&payload);
        }
        encoded.push(bytes);
    }
    encoded.sort_unstable();
    for row in encoded {
        digest.update((row.len() as u64).to_le_bytes());
        digest.update(row);
    }
    Ok(())
}

fn projection_digest(source: &JvmExternalProjection) -> Result<Vec<u8>> {
    let mut digest = Sha256::new();
    digest.update(b"jvm-external-projection-v2");
    for (tag, rows, width) in [
        (0u8, &source.owners, 7),
        (1, &source.members, 14),
        (2, &source.supertypes, 5),
    ] {
        digest.update([tag]);
        digest.update((rows.len() as u64).to_le_bytes());
        canonical_rows(rows, width, &mut digest)?;
    }
    Ok(digest.finalize().to_vec())
}

fn certificate_matches(
    tx: &Transaction<'_>,
    source: &JvmExternalProjection,
    digest: &[u8],
) -> Result<bool> {
    type Certificate = (String, [u8; 32], Vec<u8>, i64, i64, i64);
    let certificate: Option<Certificate> = tx.prepare_cached(
        "SELECT source_identity,projection_identity,projected_rows_sha256,owner_count,member_count,supertype_count FROM jvm_external_provider_publications WHERE provider_id=?1",
    )?.query_row([&source.provider_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
    ).optional()?;
    Ok(certificate.is_some_and(|row| {
        row == (
            source.source_identity.clone(),
            jvm_external_projection_identity(),
            digest.to_vec(),
            source.owners.len() as i64,
            source.members.len() as i64,
            source.supertypes.len() as i64,
        )
    }))
}

fn read_rows(
    tx: &Transaction<'_>,
    table: &str,
    columns: &str,
    provider: &str,
    width: usize,
) -> Result<Vec<Vec<Value>>> {
    let sql = format!("SELECT {columns} FROM {table} WHERE provider_id=?1");
    let mut statement = tx.prepare(&sql)?;
    let rows = statement
        .query_map([provider], |row| {
            (0..width)
                .map(|i| row.get(i))
                .collect::<rusqlite::Result<Vec<Value>>>()
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn readback_matches(
    tx: &Transaction<'_>,
    source: &JvmExternalProjection,
    digest: &[u8],
) -> Result<bool> {
    let actual = JvmExternalProjection {
        provider_id: source.provider_id.clone(),
        source_identity: source.source_identity.clone(),
        owners: read_rows(
            tx,
            "jvm_external_owners",
            "provider_id,owner_fqn,callables_complete,values_complete,types_complete,supertypes_complete,json(type_parameters_jsonb)",
            &source.provider_id,
            7,
        )?,
        members: read_rows(
            tx,
            "jvm_external_owner_members",
            MEMBER_READ_COLUMNS,
            &source.provider_id,
            14,
        )?,
        supertypes: read_rows(
            tx,
            "jvm_external_owner_supertypes",
            "provider_id,owner_fqn,supertype_fqn,ordinal,json(type_arguments_jsonb)",
            &source.provider_id,
            5,
        )?,
    };
    Ok(actual.owners.len() == source.owners.len()
        && actual.members.len() == source.members.len()
        && actual.supertypes.len() == source.supertypes.len()
        && projection_digest(&actual)? == digest)
}

impl AnalyzerStore {
    /// A missing or conflicting certificate is typed unavailable for read-only callers.
    pub fn jvm_external_publication_status(
        &self,
        source: JvmExternalProjection,
    ) -> Result<JvmExternalPublication> {
        let digest = projection_digest(&source)?;
        self.conn.execute(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Deferred)?;
            let matches = certificate_matches(&tx, &source, &digest)?;
            Ok(if matches {
                JvmExternalPublication::Available
            } else {
                JvmExternalPublication::Unavailable
            })
        })
    }

    /// The source callback belongs to the pinned catalog handle. An absent source cannot certify absence.
    pub fn publish_jvm_external_projection(
        &self,
        source: impl FnOnce() -> Result<Option<JvmExternalProjection>>,
        cancelled: impl Fn() -> bool + Send + 'static,
    ) -> Result<JvmExternalPublication> {
        let Some(source) = source()? else {
            return Ok(JvmExternalPublication::Unavailable);
        };
        assert_ne!(source.provider_id, "jvm-intrinsic");
        for rows in [&source.owners, &source.members, &source.supertypes] {
            for row in rows {
                assert_eq!(row.first(), Some(&Value::Text(source.provider_id.clone())));
            }
        }
        let digest = projection_digest(&source)?;
        self.conn.execute(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if cancelled() { return Err(StoreError::cancelled("JVM publication cancelled")); }
            if certificate_matches(&tx, &source, &digest)? {
                if !readback_matches(&tx, &source, &digest)? {
                    return Ok(JvmExternalPublication::Conflict);
                }
                return Ok(JvmExternalPublication::Available);
            }
            let exists: bool = tx.prepare_cached("SELECT EXISTS(SELECT 1 FROM jvm_external_provider_publications WHERE provider_id=?1)")?.query_row([&source.provider_id], |row| row.get(0))?;
            if exists { return Ok(JvmExternalPublication::Conflict); }
            // Legacy rows have no certificate and cannot be trusted, even if their counts agree.
            tx.prepare_cached("DELETE FROM jvm_external_owners WHERE provider_id=?1")?.execute([&source.provider_id])?;
            for (table, columns, placeholders, rows) in [
                ("jvm_external_owners", OWNER_COLUMNS, "?1,?2,?3,?4,?5,?6,jsonb(?7)", &source.owners),
                ("jvm_external_owner_members", MEMBER_COLUMNS, "?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,jsonb(?11),jsonb(?12),?13,jsonb(?14)", &source.members),
                ("jvm_external_owner_supertypes", SUPERTYPE_COLUMNS, "?1,?2,?3,?4,jsonb(?5)", &source.supertypes),
            ] {
                let sql = format!("INSERT INTO {table}({columns}) VALUES({placeholders})");
                let mut statement = tx.prepare(&sql)?;
                for row in rows {
                    if cancelled() { return Err(StoreError::cancelled("JVM publication cancelled")); }
                    statement.execute(params_from_iter(row))?;
                }
            }
            if !readback_matches(&tx, &source, &digest)? {
                return Err(StoreError::new("JVM provider projection readback mismatch"));
            }
            if cancelled() { return Err(StoreError::cancelled("JVM publication cancelled")); }
            tx.prepare_cached("INSERT INTO jvm_external_provider_publications(provider_id,source_identity,projection_identity,projected_rows_sha256,owner_count,member_count,supertype_count) VALUES(?1,?2,?3,?4,?5,?6,?7)")?.execute(
                params![source.provider_id, source.source_identity, jvm_external_projection_identity(), digest,
                    source.owners.len(), source.members.len(), source.supertypes.len()])?;
            tx.commit()?;
            Ok(JvmExternalPublication::Available)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> JvmExternalProjection {
        JvmExternalProjection {
            provider_id: "sha".into(),
            source_identity: "sha".into(),
            owners: vec![vec![
                Value::Text("sha".into()),
                Value::Text("p.C".into()),
                Value::Integer(1),
                Value::Integer(1),
                Value::Integer(1),
                Value::Integer(1),
                Value::Text("[]".into()),
            ]],
            members: [false, true]
                .into_iter()
                .enumerate()
                .map(|(ordinal, is_abstract)| {
                    vec![
                        Value::Text("sha".into()),
                        Value::Text("p.C".into()),
                        Value::Integer(ordinal as i64),
                        Value::Text(format!("run{ordinal}")),
                        Value::Text("method".into()),
                        Value::Text("public".into()),
                        Value::Integer(0),
                        Value::Integer(1),
                        Value::Integer(1),
                        Value::Null,
                        Value::Text("[]".into()),
                        Value::Null,
                        Value::Integer(i64::from(is_abstract)),
                        Value::Text("[]".into()),
                    ]
                })
                .collect(),
            supertypes: vec![],
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11148: legacy JVM member rows lacked declaration kind and must reproject before sealing"
    )]
    fn publication_replaces_legacy_and_seals_rows() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .conn
            .execute(|conn| -> Result<()> {
                conn.execute(
                    "INSERT INTO jvm_external_owners(provider_id,owner_fqn,callables_complete,values_complete,types_complete,supertypes_complete) VALUES('sha','p.C',0,0,0,0)",
                    [],
                )?;
                conn.execute("INSERT INTO jvm_external_owner_members(provider_id,owner_fqn,ordinal,member_name,member_kind,visibility,is_static,signature_present,callable_family_complete,parameters_jsonb) VALUES('sha','p.C',0,'run0','method','public',0,1,1,jsonb('[]'))", [])?;
                let flag: Option<bool> = conn.query_row("SELECT is_abstract FROM jvm_external_owner_members WHERE provider_id='sha'", [], |row| row.get(0))?;
                assert_eq!(flag, None);
                Ok(())
            })
            .unwrap();
        assert_eq!(
            store.jvm_external_publication_status(source()).unwrap(),
            JvmExternalPublication::Unavailable
        );
        assert_eq!(
            store
                .publish_jvm_external_projection(|| Ok(Some(source())), || false)
                .unwrap(),
            JvmExternalPublication::Available
        );
        assert_eq!(
            store.jvm_external_publication_status(source()).unwrap(),
            JvmExternalPublication::Available
        );
        store
            .conn
            .execute(|conn| -> Result<()> {
                let flags = conn.prepare("SELECT is_abstract FROM jvm_external_owner_members WHERE provider_id='sha' ORDER BY ordinal")?
                    .query_map([], |row| row.get::<_, Option<bool>>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                assert_eq!(flags, [Some(false), Some(true)]);
                assert!(conn.execute("UPDATE jvm_external_owner_members SET is_abstract=NULL WHERE provider_id='sha'", []).is_err());
                assert!(
                    conn.execute(
                        "UPDATE jvm_external_owners SET values_complete=0 WHERE provider_id='sha'",
                        []
                    )
                    .is_err()
                );
                assert!(
                    conn.execute(
                        "DELETE FROM jvm_external_owners WHERE provider_id='sha'",
                        []
                    )
                    .is_err()
                );
            assert!(
                conn.execute(
                    "UPDATE jvm_external_provider_publications SET owner_count=0 WHERE provider_id='sha'",
                    []
                )
                .is_err()
            );
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn cancelled_publication_rolls_back() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        assert!(
            store
                .publish_jvm_external_projection(|| Ok(Some(source())), || true)
                .is_err()
        );
        assert_eq!(
            store.jvm_external_publication_status(source()).unwrap(),
            JvmExternalPublication::Unavailable
        );
        store
            .conn
            .execute(|conn| -> Result<()> {
                let count: i64 = conn.query_row(
                    "SELECT count(*) FROM jvm_external_owners WHERE provider_id='sha'",
                    [],
                    |row| row.get(0),
                )?;
                assert_eq!(count, 0);
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn missing_source_is_unavailable() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        assert_eq!(
            store
                .publish_jvm_external_projection(|| Ok(None), || false)
                .unwrap(),
            JvmExternalPublication::Unavailable
        );
    }

    #[test]
    fn same_sha_different_projection_conflicts() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .publish_jvm_external_projection(|| Ok(Some(source())), || false)
            .unwrap();
        let mut different = source();
        different.owners[0][2] = Value::Integer(0);
        assert_eq!(
            store
                .publish_jvm_external_projection(|| Ok(Some(different)), || false)
                .unwrap(),
            JvmExternalPublication::Conflict
        );
        assert_eq!(
            store.jvm_external_publication_status(source()).unwrap(),
            JvmExternalPublication::Available
        );
        let owner_complete: i64 = store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT callables_complete FROM jvm_external_owners WHERE provider_id='sha'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(owner_complete, 1);
    }

    #[test]
    fn concurrent_publishers_verify_one_certificate() {
        use std::sync::{Arc, Barrier};

        let store = Arc::new(AnalyzerStore::open_ephemeral().unwrap());
        let barrier = Arc::new(Barrier::new(2));
        std::thread::scope(|scope| {
            let spawn = || {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    store.publish_jvm_external_projection(|| Ok(Some(source())), || false)
                })
            };
            let first = spawn();
            let second = spawn();
            assert_eq!(
                first.join().unwrap().unwrap(),
                JvmExternalPublication::Available
            );
            assert_eq!(
                second.join().unwrap().unwrap(),
                JvmExternalPublication::Available
            );
        });
        store
            .conn
            .execute(|conn| -> Result<()> {
                let count: i64 = conn.query_row(
                "SELECT count(*) FROM jvm_external_provider_publications WHERE provider_id='sha'",
                [],
                |row| row.get(0),
            )?;
                assert_eq!(count, 1);
                Ok(())
            })
            .unwrap();
    }
}
