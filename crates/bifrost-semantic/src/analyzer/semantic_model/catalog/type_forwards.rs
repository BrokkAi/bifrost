//! Request-local assembly forwarding over an explicitly selected provider set.

use super::{CatalogError, statements};
use crate::analyzer::semantic_model::AssemblyReference;
use rusqlite::{Connection, OptionalExtension, named_params};
use serde::Serialize;
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssemblyProvider {
    pub manifest_digest: String,
    pub shard_id: String,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeForwardTrace {
    pub forwarder: AssemblyReference,
    pub requested: AssemblyReference,
    pub selected: Option<AssemblyReference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssemblyTypeTarget {
    Defined {
        provider: AssemblyProvider,
        identity: AssemblyReference,
        name: String,
        trace: Vec<TypeForwardTrace>,
    },
    /// Absence on this provider's external surface, never on its targets.
    AbsentOnProvider { provider: AssemblyProvider },
    OpenBoundary {
        reason: String,
        trace: Vec<TypeForwardTrace>,
    },
}

fn version(identity: &AssemblyReference) -> Result<[u16; 4], CatalogError> {
    identity.version_components().ok_or_else(|| {
        CatalogError::Integrity(format!("invalid stored assembly version {identity:?}"))
    })
}

fn identity(row: &rusqlite::Row<'_>) -> rusqlite::Result<AssemblyReference> {
    Ok(AssemblyReference {
        name: row.get("name")?,
        version: row.get("version")?,
        culture: row.get("culture")?,
        public_key_token: row.get("public_key_token")?,
    })
}

/// Each read seeks a single name or exact provider. The caller supplies only
/// providers selected for this compilation; catalog membership alone is never
/// authority to follow an assembly reference. All traversal state dies here.
pub fn resolve_assembly_type(
    connection: &Connection,
    selected: &[AssemblyProvider],
    provider: &AssemblyProvider,
    name: &str,
) -> Result<AssemblyTypeTarget, CatalogError> {
    let selected_json = serde_json::to_string(selected).map_err(|error| {
        CatalogError::Integrity(format!("encode selected assembly providers: {error}"))
    })?;
    let mut current = provider.clone();
    let mut trace: Vec<TypeForwardTrace> = Vec::new();
    let mut visited = HashSet::new();
    loop {
        if !selected.contains(&current) {
            return Ok(AssemblyTypeTarget::OpenBoundary {
                reason: format!(
                    "forwarder {provider:?}: provider {current:?} is not selected for this compilation"
                ),
                trace,
            });
        }
        let owner = connection.prepare_cached(statements::ASSEMBLY_IDENTITY_BY_PROVIDER)
            .and_then(|mut query|query.query_row(named_params! {":manifest":current.manifest_digest,":shard":current.shard_id},identity).optional())
            .map_err(|error|CatalogError::sqlite("read selected assembly identity",error))?;
        let Some(owner) = owner else {
            return Ok(AssemblyTypeTarget::OpenBoundary {
                reason: format!(
                    "forwarder {provider:?}: provider {current:?} carries no assembly identity"
                ),
                trace,
            });
        };
        if !visited.insert(owner.clone()) {
            return Ok(AssemblyTypeTarget::OpenBoundary {
                reason: format!(
                    "forwarder {provider:?}: assembly forward cycle for {name}: {trace:?}; repeated {owner:?}"
                ),
                trace,
            });
        }
        let visible = connection.prepare_cached(statements::ASSEMBLY_DEFINED_TYPES_BY_NAME)
            .and_then(|mut query|query.query_row(named_params! {":manifest":current.manifest_digest,":shard":current.shard_id,":name":name}, |row|row.get::<_,bool>(0)).optional())
            .map_err(|error|CatalogError::sqlite("read forwarded defining type",error))?;
        if visible == Some(true) {
            return Ok(AssemblyTypeTarget::Defined {
                provider: current,
                identity: owner,
                name: name.to_owned(),
                trace,
            });
        }
        if visible == Some(false) {
            return Ok(AssemblyTypeTarget::OpenBoundary {
                reason: format!(
                    "forwarder {provider:?}: defining type {name} in {owner:?} is not externally visible; {trace:?}"
                ),
                trace,
            });
        }
        let target = connection.prepare_cached(statements::TYPE_FORWARDS_BY_PROVIDER_NAME)
            .and_then(|mut query|query.query_row(named_params! {":manifest":current.manifest_digest,":shard":current.shard_id,":name":name},|row|Ok(AssemblyReference {
                name:row.get("target_name")?,version:row.get("target_version")?,culture:row.get("target_culture")?,public_key_token:row.get("target_public_key_token")?,
            })).optional())
            .map_err(|error|CatalogError::sqlite("read selected type forward",error))?;
        let Some(target) = target else {
            return Ok(if trace.is_empty() && current.complete {
                AssemblyTypeTarget::AbsentOnProvider { provider: current }
            } else {
                AssemblyTypeTarget::OpenBoundary {
                    reason: format!(
                        "forwarder {provider:?}: defining type {name} is missing or inaccessible in {owner:?}; {trace:?}"
                    ),
                    trace,
                }
            });
        };
        let requested_version = version(&target)?;
        let mut query = connection
            .prepare_cached(statements::ASSEMBLIES_BY_REFERENCE)
            .map_err(|error| CatalogError::sqlite("prepare forward target providers", error))?;
        let candidates=query.query_map(named_params! {":name":target.name,":culture":target.culture,":token":target.public_key_token,":providers":selected_json},|row| {
            Ok((row.get::<_,String>("manifest_digest")?,row.get::<_,String>("shard_id")?,identity(row)?))
        }).map_err(|error|CatalogError::sqlite("query forward target providers",error))?
            .collect::<rusqlite::Result<Vec<_>>>().map_err(|error|CatalogError::sqlite("read forward target providers",error))?;
        let mut compatible = Vec::new();
        for candidate in &candidates {
            let found_version = version(&candidate.2)?;
            // #7338 fourth amendment: reject candidates below the requested
            // version (compiler CS1705); the runtime's default binding context
            // also rejects a lower loaded version. Select the highest remaining
            // version; equal highest versions are an ambiguous open boundary
            // (CS1703: equivalent identities cannot both be imported).
            if found_version >= requested_version {
                compatible.push((found_version, candidate));
            }
        }
        compatible.sort_by_key(|candidate| std::cmp::Reverse(candidate.0));
        let Some((highest, chosen)) = compatible.first() else {
            trace.push(TypeForwardTrace {
                forwarder: owner.clone(),
                requested: target.clone(),
                selected: None,
            });
            return Ok(AssemblyTypeTarget::OpenBoundary {
                reason: format!(
                    "forwarder {owner:?}: no selected provider for {name} satisfies requested {target:?}; found {candidates:?}; {trace:?}"
                ),
                trace,
            });
        };
        if compatible.get(1).is_some_and(|next| next.0 == *highest) {
            return Ok(AssemblyTypeTarget::OpenBoundary {
                reason: format!(
                    "forwarder {owner:?}: ambiguous selected providers for requested {target:?}: {candidates:?}; {trace:?}"
                ),
                trace,
            });
        }
        trace.push(TypeForwardTrace {
            forwarder: owner,
            requested: target,
            selected: Some(chosen.2.clone()),
        });
        current = selected
            .iter()
            .find(|provider| provider.manifest_digest == chosen.0 && provider.shard_id == chosen.1)
            .expect("SQL returned only an explicitly selected provider")
            .clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic_model::catalog::{
        SessionSemanticCatalog, open_session_semantic_catalog, rows,
    };

    const REQUESTED_TOKEN: &str = "0011223344556677";

    fn provider(
        connection: &Connection,
        manifest: &str,
        name: &str,
        token: Option<&str>,
    ) -> AssemblyProvider {
        connection
            .execute(
                "INSERT INTO catalog_packs VALUES(?1,'verified')",
                [manifest],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO catalog_pack_shards VALUES(?1,'declarations')",
                [manifest],
            )
            .unwrap();
        connection.execute(
            "INSERT INTO catalog_semantic_rows_indexed_shards(manifest_digest,shard_id,index_version)
             VALUES(?1,'declarations',4)", [manifest],
        ).unwrap();
        let shard = connection.last_insert_rowid();
        connection
            .execute("INSERT INTO active_shards VALUES(?1,'durable')", [shard])
            .unwrap();
        connection.execute(
            "INSERT INTO catalog_assembly_identities VALUES(?1,'declarations',?2,'2.0.0.0',NULL,?3)",
            rusqlite::params![manifest,name,token],
        ).unwrap();
        AssemblyProvider {
            manifest_digest: manifest.to_owned(),
            shard_id: "declarations".to_owned(),
            complete: true,
        }
    }

    fn facade() -> (SessionSemanticCatalog, AssemblyProvider) {
        let catalog = open_session_semantic_catalog().unwrap();
        let empty = open_session_semantic_catalog().unwrap();
        rows::attach_session_rows(&catalog.connection, &empty).unwrap();
        let facade = provider(&catalog.connection, &"1".repeat(64), "Fixture.Facade", None);
        catalog
            .connection
            .execute(
                "INSERT INTO catalog_type_forwards VALUES(?1,'declarations',0,'Fixture.Visible',
             'Fixture',NULL,'Fixture.Target','1.0.0.0',NULL,?2)",
                rusqlite::params![facade.manifest_digest, REQUESTED_TOKEN],
            )
            .unwrap();
        (catalog, facade)
    }

    fn define_visible(connection: &Connection, provider: &AssemblyProvider) {
        let shard: i64 = connection
            .query_row(
                "SELECT shard_key FROM catalog_semantic_rows_indexed_shards
             WHERE manifest_digest=?1 AND shard_id=?2",
                rusqlite::params![provider.manifest_digest, provider.shard_id],
                |row| row.get(0),
            )
            .unwrap();
        connection
            .execute(
                r#"INSERT INTO catalog_declaration_types(shard_key,record_id,record_json)
             VALUES(?1,'visible','{"type_kind":"class","visibility":"public"}')"#,
                [shard],
            )
            .unwrap();
        let record = connection.last_insert_rowid();
        connection.execute(
            "INSERT INTO catalog_declaration_names(shard_key,record_key,name,language,namespace,identity_name)
             VALUES(?1,?2,'Fixture.Visible','csharp','type',1)",
            rusqlite::params![shard,record],
        ).unwrap();
    }

    #[test]
    fn signed_forward_rejects_a_provider_with_a_different_public_key_token() {
        let (catalog, facade) = facade();
        let target = provider(
            &catalog.connection,
            &"2".repeat(64),
            "Fixture.Target",
            Some("8899aabbccddeeff"),
        );
        define_visible(&catalog.connection, &target);
        let found = resolve_assembly_type(
            &catalog.connection,
            &[facade.clone(), target],
            &facade,
            "Fixture.Visible",
        )
        .unwrap();
        let AssemblyTypeTarget::OpenBoundary { reason, trace } = found else {
            panic!("{found:?}");
        };
        assert!(reason.contains("no selected provider"), "{reason}");
        assert_eq!(trace.len(), 1);
        assert_eq!(
            trace[0].requested.public_key_token.as_deref(),
            Some(REQUESTED_TOKEN)
        );
        assert!(trace[0].selected.is_none());
    }

    #[test]
    fn equivalent_highest_version_providers_are_an_ambiguous_open_boundary() {
        let (catalog, facade) = facade();
        let first = provider(
            &catalog.connection,
            &"2".repeat(64),
            "Fixture.Target",
            Some(REQUESTED_TOKEN),
        );
        let second = provider(
            &catalog.connection,
            &"3".repeat(64),
            "Fixture.Target",
            Some(REQUESTED_TOKEN),
        );
        define_visible(&catalog.connection, &first);
        define_visible(&catalog.connection, &second);
        let selected = [facade.clone(), first.clone(), second.clone()];
        let found =
            resolve_assembly_type(&catalog.connection, &selected, &facade, "Fixture.Visible")
                .unwrap();
        let AssemblyTypeTarget::OpenBoundary { reason, .. } = found else {
            panic!("{found:?}");
        };
        assert!(reason.contains("ambiguous selected providers"), "{reason}");
        assert!(reason.contains(&first.manifest_digest), "{reason}");
        assert!(reason.contains(&second.manifest_digest), "{reason}");
    }
}
