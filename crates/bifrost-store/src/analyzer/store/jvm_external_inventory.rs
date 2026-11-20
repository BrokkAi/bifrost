//! Durable, content-selected inventories for independently enumerated JVM owners.

use super::jvm_external_publication::{
    JvmExternalProjection, jvm_external_projection_identity, jvm_external_provider_id,
};
use super::{AnalyzerStore, Result, StoreError};
use crate::analyzer::semantic_model::{
    ActiveSemanticModelShard, Completeness, MemberFact, PayloadKind, ResolvedActiveSemanticModels,
    TypeFact, TypeRef, Visibility,
};
use crate::hash::HashMap;
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
use rusqlite::params;
use rusqlite::types::Value;

/// A projected declaration parameter. Missing bounds cannot prove unboundedness.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JvmExternalTypeParameter {
    pub name: String,
    pub bounds: JvmExternalTypeParameterBounds,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(
    tag = "state",
    content = "types",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum JvmExternalTypeParameterBounds {
    Unknown,
    Known(Vec<TypeRef>),
}

/// SQL NULL preserves the distinction between an old projection and no formals.
pub fn decode_jvm_external_type_parameters(
    encoded: Option<&str>,
) -> Result<Option<Vec<JvmExternalTypeParameter>>> {
    encoded
        .map(serde_json::from_str)
        .transpose()
        .map_err(|error| StoreError::new(format!("external type parameters: {error}")))
}

fn unknown_type_parameters(names: &[String]) -> Result<String> {
    json_value(
        &names
            .iter()
            .map(|name| JvmExternalTypeParameter {
                name: name.clone(),
                bounds: JvmExternalTypeParameterBounds::Unknown,
            })
            .collect::<Vec<_>>(),
    )
}

/// Convert one declaration shard to the exact inventory table column order.
pub fn jvm_external_projection<'a>(
    semantic_sha256: String,
    source_identity: String,
    types: impl IntoIterator<Item = &'a crate::analyzer::semantic_model::TypeFact>,
    members: impl IntoIterator<Item = &'a MemberFact>,
    complete: bool,
) -> Result<JvmExternalProjection> {
    let provider_id = jvm_external_provider_id(&semantic_sha256);
    let types = types.into_iter().collect::<Vec<_>>();
    let members = members.into_iter().collect::<Vec<_>>();
    let names_by_id = types
        .iter()
        .map(|owner| (owner.id.as_str(), owner.name.as_str()))
        .collect::<HashMap<_, _>>();
    let mut owners_by_name = HashMap::<&str, usize>::default();
    for owner in &types {
        *owners_by_name.entry(&owner.name).or_default() += 1;
    }
    let mut members_by_owner = HashMap::<&str, Vec<&MemberFact>>::default();
    for member in members {
        members_by_owner
            .entry(&member.owner)
            .or_default()
            .push(member);
    }
    let mut projection = JvmExternalProjection {
        semantic_sha256,
        provider_id: provider_id.clone(),
        source_identity,
        owners: Vec::new(),
        members: Vec::new(),
        supertypes: Vec::new(),
    };
    let mut projected_names = crate::hash::HashSet::default();
    for owner in types {
        // A duplicate fact must not contribute rows to the first fact's owner.
        if !projected_names.insert(owner.name.as_str()) {
            continue;
        }
        let owner_members = members_by_owner.get(owner.id.as_str());
        let additional_members = owner
            .jvm_inventory
            .iter()
            .flat_map(|inventory| &inventory.additional_members);
        let hierarchy = owner
            .jvm_inventory
            .as_ref()
            .map_or(owner.hierarchy.as_slice(), |inventory| {
                inventory.supertypes.as_slice()
            });
        let owner_complete = (complete || owner.jvm_inventory.is_some())
            && owners_by_name[owner.name.as_str()] == 1
            && owner.guard.is_none()
            && owner_members.is_none_or(|members| members.iter().all(|member| member.guard.is_none()))
            && additional_members.clone().all(|member| member.guard.is_none())
            && hierarchy.iter().all(|parent| {
                matches!(&parent.target, TypeRef::Named { name, .. } if !name.is_empty())
                    || matches!(&parent.target, TypeRef::Declared { id, .. } if names_by_id.contains_key(id.as_str()))
            });
        let text = |value: &str| Value::Text(value.to_owned());
        let boolean = |value: bool| Value::Integer(i64::from(value));
        projection.owners.push(vec![
            text(&provider_id),
            text(&owner.name),
            boolean(
                owner_complete
                    && owner
                        .jvm_inventory
                        .as_ref()
                        .is_some_and(|inventory| inventory.callables_complete),
            ),
            boolean(
                owner_complete
                    && owner
                        .jvm_inventory
                        .as_ref()
                        .is_some_and(|inventory| inventory.values_complete),
            ),
            boolean(
                owner_complete
                    && owner
                        .jvm_inventory
                        .as_ref()
                        .is_some_and(|inventory| inventory.types_complete),
            ),
            boolean(
                owner_complete
                    && owner
                        .jvm_inventory
                        .as_ref()
                        .is_some_and(|inventory| inventory.supertypes_complete),
            ),
            text(&unknown_type_parameters(&owner.type_parameters)?),
        ]);
        let mut ordinal = 0i64;
        for member in owner_members
            .into_iter()
            .flatten()
            .copied()
            .chain(additional_members)
            .filter(|member| member.guard.is_none())
        {
            let signature = member.signature.as_ref();
            projection.members.push(vec![
                text(&provider_id),
                text(&owner.name),
                Value::Integer(ordinal),
                text(&member.name),
                text(&enum_label(&member.member_kind)?),
                text(jvm_declared_visibility(member.visibility).label()),
                boolean(member.is_static),
                boolean(signature.is_some()),
                boolean(member.callable_family_complete),
                member
                    .non_overridable
                    .as_ref()
                    .map(enum_label)
                    .transpose()?
                    .map_or(Value::Null, Value::Text),
                text(&json_value(
                    &signature
                        .map(|signature| &signature.parameters)
                        .unwrap_or(&Vec::new()),
                )?),
                signature
                    .and_then(|signature| signature.returns.as_ref())
                    .map(json_value)
                    .transpose()?
                    .map_or(Value::Null, Value::Text),
                boolean(member.is_abstract),
                signature
                    .map(|signature| {
                        json_value(
                            &signature
                                .type_parameters
                                .iter()
                                .map(|name| JvmExternalTypeParameter {
                                    name: name.clone(),
                                    bounds: match &signature.bounds {
                                        None => JvmExternalTypeParameterBounds::Unknown,
                                        Some(bounds) => JvmExternalTypeParameterBounds::Known(bounds.iter()
                                            .filter(|bound| matches!(&bound.subject, TypeRef::TypeParameter { name: subject } if subject == name))
                                            .map(|bound| bound.bound.trait_type.clone()).collect()),
                                    },
                                })
                                .collect::<Vec<_>>(),
                        )
                    })
                    .transpose()?
                    .map_or(Value::Null, Value::Text),
            ]);
            ordinal += 1;
        }
        for nested in owner
            .jvm_inventory
            .iter()
            .flat_map(|inventory| &inventory.nested_types)
        {
            projection.members.push(vec![
                text(&provider_id),
                text(&owner.name),
                Value::Integer(ordinal),
                text(&nested.name),
                text("nested_type"),
                text(jvm_declared_visibility(nested.visibility).label()),
                boolean(nested.is_static),
                boolean(false),
                boolean(false),
                Value::Null,
                text("[]"),
                text(&json_value(&TypeRef::named(&nested.owner_fqn))?),
                Value::Null,
                text("[]"),
            ]);
            ordinal += 1;
        }
        for (ordinal, parent) in hierarchy.iter().enumerate() {
            let fqn = match &parent.target {
                TypeRef::Named { name, .. } => Some(name.as_str()),
                TypeRef::Declared { id, .. } => names_by_id.get(id.as_str()).copied(),
                _ => None,
            };
            if let Some(fqn) = fqn {
                projection.supertypes.push(vec![
                    text(&provider_id),
                    text(&owner.name),
                    text(fqn),
                    Value::Integer(ordinal as i64),
                    text(&json_value(match &parent.target {
                        TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } => {
                            arguments
                        }
                        _ => unreachable!("projected parent has a nominal target"),
                    })?),
                ]);
            }
        }
    }
    Ok(projection)
}

/// Result of an uncertified inventory write for one provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JvmExternalInventoryWrite {
    Written,
    AlreadyPresent,
    Sealed,
}

impl AnalyzerStore {
    /// Publication handles one activation-owned declaration shard. The temporary
    /// owner join and insert bindings die with this writer transaction; only
    /// relational inventory rows survive it.
    #[doc(hidden)]
    pub fn publish_jvm_external_owner_inventory_from_activation(
        &self,
        shard: &ActiveSemanticModelShard,
        active: &ResolvedActiveSemanticModels,
    ) -> Result<()> {
        if shard.request_owned() || shard.descriptor.payload_kind != PayloadKind::DeclarationFacts {
            return Ok(());
        }
        if super::resolution_operation::nominal_rules::nominal_package_rules_for_storage(
            &shard.manifest.language,
        )
        .is_none()
        {
            return Ok(());
        }
        let row_types;
        let row_members;
        let (types, members) = if let Some(decoded) = &shard.decoded {
            let (types, members, _) = decoded
                .payload()
                .declaration_facts()
                .expect("declaration descriptor has declaration payload");
            (types, members)
        } else {
            if shard.row_store.is_none() || active.activation_reader().is_none() {
                return Err(StoreError::new(format!(
                    "JVM declaration shard {} has neither decoded facts nor activation rows",
                    shard.descriptor.shard_id
                )));
            }
            use super::model_catalog::CatalogRowReader;
            use crate::analyzer::semantic_model::CatalogShardDatabase;
            let identity = shard.row_store.expect("row backing checked");
            let source = match identity.database {
                CatalogShardDatabase::Durable => "durable",
                CatalogShardDatabase::Session => "session",
            };
            let reader = active
                .activation_reader()
                .expect("activation reader checked");
            let names: Vec<String> = (reader as &dyn CatalogRowReader).scalar_question(
                "SELECT json_extract(record_json, '$.name') FROM active_catalog_declaration_types WHERE source_db=:source_db AND shard_key=:shard_key AND json_extract(record_json, '$.guard') IS NULL",
                rusqlite::named_params! { ":source_db": source, ":shard_key": identity.shard_key },
                |row| row.get(0),
            ).map_err(|error| StoreError::new(format!("JVM inventory owner names unavailable: {error}")))?;
            if !self.jvm_inventory_owners_missing(
                &jvm_external_provider_id(&shard.manifest.semantic_sha256),
                names.iter().map(String::as_str),
            )? {
                return Ok(());
            }
            row_types = activation_inventory_records::<TypeFact>(active, shard,
                "SELECT * FROM active_catalog_declaration_types WHERE source_db=:source_db AND shard_key=:shard_key ORDER BY record_key")
                .map_err(|error| StoreError::new(format!("JVM inventory types unavailable: {error:?}")))?;
            row_members = activation_inventory_records::<MemberFact>(active, shard,
                "SELECT * FROM active_catalog_declaration_members WHERE source_db=:source_db AND shard_key=:shard_key ORDER BY record_key")
                .map_err(|error| StoreError::new(format!("JVM inventory members unavailable: {error:?}")))?;
            (row_types.as_slice(), row_members.as_slice())
        };
        let enumerated_types = types
            .iter()
            .map(AsRef::as_ref)
            .filter(|owner| shard.admits_jvm_owner_declaration(owner))
            .collect::<Vec<_>>();
        match self.publish_jvm_external_inventory_facts(
            shard.manifest.semantic_sha256.clone(),
            enumerated_types,
            members.iter().map(AsRef::as_ref),
            shard.manifest.completeness == Completeness::Complete,
        )? {
            JvmExternalInventoryWrite::Written | JvmExternalInventoryWrite::AlreadyPresent => {
                Ok(())
            }
            JvmExternalInventoryWrite::Sealed => Err(StoreError::new(format!(
                "activation JVM inventory unavailable for sealed provider {}",
                shard.manifest.semantic_sha256
            ))),
        }
    }

    fn jvm_inventory_owners_missing<'a>(
        &self,
        provider_id: &str,
        names: impl Iterator<Item = &'a str>,
    ) -> Result<bool> {
        let requested_owners = json_value(&names.collect::<Vec<_>>())?;
        let checked_provider = provider_id.to_owned();
        self.conn.execute(move |conn| -> Result<bool> {
            Ok(conn
                .prepare_cached(
                    "SELECT EXISTS(
                SELECT 1 FROM json_each(?2) requested
                LEFT JOIN jvm_external_owners inventory
                  ON inventory.provider_id=?1 AND inventory.owner_fqn=requested.value
                WHERE inventory.owner_fqn IS NULL
            )",
                )?
                .query_row(params![checked_provider, requested_owners], |row| {
                    row.get(0)
                })?)
        })
    }

    #[doc(hidden)]
    pub fn publish_jvm_external_inventory_facts<'a>(
        &self,
        provider_id: String,
        types: impl IntoIterator<Item = &'a crate::analyzer::semantic_model::TypeFact>,
        members: impl IntoIterator<Item = &'a MemberFact>,
        complete: bool,
    ) -> Result<JvmExternalInventoryWrite> {
        // This provider is synthesized by the JVM intrinsic inventory and
        // must never acquire durable rows: operation-local owner-index reads
        // rely on its absence throughout the operation.
        assert_ne!(
            provider_id, "jvm-intrinsic",
            "intrinsic JVM provider cannot publish external inventory rows"
        );
        let semantic_sha256 = provider_id;
        let provider_id = jvm_external_provider_id(&semantic_sha256);
        let enumerated_types = types.into_iter().collect::<Vec<_>>();
        if enumerated_types.is_empty() {
            return Ok(JvmExternalInventoryWrite::AlreadyPresent);
        }
        // Check durable membership before copying any member payload. A cache
        // hit must not rematerialize the decoded declaration pack per request.
        if !self.jvm_inventory_owners_missing(
            &provider_id,
            enumerated_types.iter().map(|owner| owner.name.as_str()),
        )? {
            return Ok(JvmExternalInventoryWrite::AlreadyPresent);
        }
        let projection = jvm_external_projection(
            semantic_sha256.clone(),
            String::new(),
            enumerated_types,
            members,
            complete,
        )?;
        let own_clock = super::jvm_external_publication::own_jvm_inventory_publication_clock(self);
        self.conn.execute(move |conn| {
            let transaction = super::jvm_external_publication::JvmExternalPublicationTransaction::begin(conn, own_clock)?;
            transaction.prepare_cached("INSERT INTO jvm_external_provider_publications(provider_id,semantic_sha256,source_identity,projection_identity,publication_state) VALUES(?1,?2,'',?3,'uncertified') ON CONFLICT(provider_id) DO NOTHING")?.execute(params![provider_id, semantic_sha256, jvm_external_projection_identity()])?;
            let mut members_by_name = HashMap::<&str, Vec<&[Value]>>::default();
            for member in &projection.members {
                let Value::Text(name) = &member[1] else { unreachable!("projected owner name is text") };
                members_by_name.entry(name).or_default().push(member);
            }
            let mut supertypes_by_name = HashMap::<&str, Vec<&[Value]>>::default();
            for parent in &projection.supertypes {
                let Value::Text(name) = &parent[1] else { unreachable!("projected owner name is text") };
                supertypes_by_name.entry(name).or_default().push(parent);
            }
            let mut owner_insert = transaction.prepare_cached("INSERT OR IGNORE INTO jvm_external_owners(provider_id,owner_fqn,callables_complete,values_complete,types_complete,supertypes_complete,type_parameters_jsonb) VALUES(?1,?2,?3,?4,?5,?6,jsonb(?7))")?;
            let mut member_insert = transaction.prepare_cached("INSERT INTO jvm_external_owner_members(provider_id,owner_fqn,ordinal,member_name,member_kind,visibility,is_static,signature_present,callable_family_complete,non_overridable,parameters_jsonb,return_type_jsonb,is_abstract,type_parameters_jsonb) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,jsonb(?11),jsonb(?12),?13,jsonb(?14))")?;
            let mut supertype_insert = transaction.prepare_cached("INSERT INTO jvm_external_owner_supertypes(provider_id,owner_fqn,supertype_fqn,ordinal,type_arguments_jsonb) VALUES(?1,?2,?3,?4,jsonb(?5))")?;
            for owner in &projection.owners {
                match owner_insert.execute(rusqlite::params_from_iter(owner)) {
                    Ok(0) => continue,
                    Ok(_) => {},
                    Err(rusqlite::Error::SqliteFailure(error, _))
                        if error.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_TRIGGER => {
                            return Ok(JvmExternalInventoryWrite::Sealed);
                        }
                    Err(error) => return Err(error.into()),
                }
                let Value::Text(name) = &owner[1] else { unreachable!("projected owner name is text") };
                for member in members_by_name.get(name.as_str()).into_iter().flatten() {
                    member_insert.execute(rusqlite::params_from_iter(*member))?;
                }
                for parent in supertypes_by_name.get(name.as_str()).into_iter().flatten() {
                    supertype_insert.execute(rusqlite::params_from_iter(*parent))?;
                }
            }
            drop(owner_insert);
            drop(member_insert);
            drop(supertype_insert);
            transaction.commit()?;
            Ok(JvmExternalInventoryWrite::Written)
        })
    }
}

fn activation_inventory_records<T: serde::de::DeserializeOwned>(
    active: &ResolvedActiveSemanticModels,
    shard: &ActiveSemanticModelShard,
    statement: &str,
) -> Result<Vec<std::sync::Arc<T>>> {
    use super::model_catalog::CatalogRowReader;
    use crate::analyzer::semantic_model::CatalogShardDatabase;
    let identity = shard.row_store.expect("inventory row backing checked");
    let source = match identity.database {
        CatalogShardDatabase::Durable => "durable",
        CatalogShardDatabase::Session => "session",
    };
    let reader = active
        .activation_reader()
        .expect("inventory activation reader checked");
    (reader as &dyn CatalogRowReader)
        .raw_records(
            statement,
            rusqlite::named_params! { ":source_db": source, ":shard_key": identity.shard_key },
            &active.shards,
        )
        .map(|records| records.into_iter().map(|record| record.record).collect())
        .map_err(|error| {
            StoreError::new(format!(
                "JVM inventory declaration rows unavailable: {error}"
            ))
        })
}

fn jvm_declared_visibility(visibility: Visibility) -> DeclaredVisibility {
    match visibility {
        Visibility::Public => DeclaredVisibility::Public,
        Visibility::Protected => DeclaredVisibility::Protected,
        Visibility::Package => DeclaredVisibility::PackagePrivate,
        Visibility::Private => DeclaredVisibility::Private,
        Visibility::Internal => DeclaredVisibility::Internal,
        Visibility::ProtectedInternal => {
            unreachable!("JVM inventories have no protected-internal members")
        }
    }
}

fn json_value<T: serde::Serialize + ?Sized>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|error| StoreError::new(error.to_string()))
}

fn enum_label<T: serde::Serialize>(value: &T) -> Result<String> {
    let value = serde_json::to_value(value).map_err(|error| StoreError::new(error.to_string()))?;
    Ok(value
        .as_str()
        .expect("inventory enum vocabulary is a string")
        .to_owned())
}

impl AnalyzerStore {
    /// Read the full structured result of the exact selected declaration.
    /// Overload selection belongs to the caller; this point lookup never
    /// chooses a member by name or treats a summary as a declaration.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn selected_external_member_return_type(
        &self,
        member: &crate::analyzer::resolution::ExternalMemberIdentity,
    ) -> Result<Option<TypeRef>> {
        use rusqlite::OptionalExtension;
        let provider = member.owner.provider_id.to_string();
        let owner = member.owner.owner_fqn.to_string();
        let ordinal = member.ordinal;
        self.conn.execute(move |connection| {
            let encoded: Option<Option<String>> = connection
                .query_row(
                    super::resolution_operation::nominal_rules::jvm_external_owner_relations()
                        .member_return_type,
                    params![provider, owner, ordinal],
                    |row| row.get(0),
                )
                .optional()?;
            encoded
                .flatten()
                .map(|value| {
                    serde_json::from_str(&value).map_err(|error| StoreError::new(error.to_string()))
                })
                .transpose()
        })
    }
}

#[cfg(test)]
mod reserved_provider_tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "#12445: a projection token replayed old answer rows and the owner-existence shortcut"
    )]
    #[expect(
        clippy::disallowed_methods,
        reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
    )]
    fn jvm_external_token_changes_answer_reads_and_inventory_shortcut() {
        use super::super::jvm_external_publication::{
            jvm_external_projection_identity_before_last_token,
            jvm_external_provider_id_for_identity,
        };
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let previous_identity = jvm_external_projection_identity_before_last_token();
        assert_ne!(previous_identity, jvm_external_projection_identity());
        let old_provider = jvm_external_provider_id_for_identity("artifact", &previous_identity);
        let current_provider = jvm_external_provider_id("artifact");
        assert_ne!(old_provider, current_provider);
        let types: Vec<TypeFact> = serde_json::from_value(serde_json::json!([
            {"id":"owner","name":"example.Owner","type_kind":"class","visibility":"public","locator":{"kind":"artifact","path":"fixture.jar","symbol":"owner"}}
        ])).unwrap();
        let members: Vec<MemberFact> = serde_json::from_value(serde_json::json!([
            {"id":"member","owner":"owner","name":"run","member_kind":"method","visibility":"public","locator":{"kind":"artifact","path":"fixture.jar","symbol":"run"}}
        ])).unwrap();
        let mut old_projection =
            jvm_external_projection("artifact".into(), String::new(), &types, &members, true)
                .unwrap();
        for rows in [
            &mut old_projection.owners,
            &mut old_projection.members,
            &mut old_projection.supertypes,
        ] {
            for row in rows {
                row[0] = Value::Text(old_provider.clone());
            }
        }
        let old_id = old_provider.clone();
        store.conn.execute(move |conn| -> Result<()> {
            conn.execute("INSERT INTO jvm_external_provider_publications(provider_id,semantic_sha256,source_identity,projection_identity,publication_state) VALUES(?1,'artifact','old-binary',?2,'uncertified')", params![old_id, previous_identity])?;
            for row in old_projection.owners {
                conn.execute("INSERT INTO jvm_external_owners VALUES(?1,?2,?3,?4,?5,?6,jsonb(?7))", rusqlite::params_from_iter(row))?;
            }
            for row in old_projection.members {
                conn.execute("INSERT INTO jvm_external_owner_members VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,jsonb(?11),jsonb(?12),?13,jsonb(?14))", rusqlite::params_from_iter(row))?;
            }
            Ok(())
        }).unwrap();
        let answer = |provider: &str| {
            let conn = store.read_conn().unwrap();
            let relations =
                super::super::resolution_operation::nominal_rules::jvm_external_owner_relations();
            let selected = serde_json::to_string(&[provider]).unwrap();
            let mut query = conn.prepare(relations.member_by_definition).unwrap();
            let member = query
                .query_map(params![provider, "example.Owner", 0, selected], |row| {
                    (0..6)
                        .map(|column| row.get::<_, Value>(column))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            let mut query = conn.prepare(relations.members).unwrap();
            let members = query
                .query_map(
                    params![provider, "example.Owner", -1, 10, selected],
                    |row| {
                        (0..6)
                            .map(|column| row.get::<_, Value>(column))
                            .collect::<rusqlite::Result<Vec<_>>>()
                    },
                )
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            let mut query = conn.prepare(relations.owner_scopes).unwrap();
            let scopes = query
                .query_map(
                    params![provider, "example.Owner", -1, 10, selected],
                    |row| {
                        (0..5)
                            .map(|column| row.get::<_, Value>(column))
                            .collect::<rusqlite::Result<Vec<_>>>()
                    },
                )
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            let indexed: bool = conn
                .query_row(
                    relations.owner_indexed,
                    params![provider, "example.Owner"],
                    |row| row.get(0),
                )
                .unwrap();
            (member, members, scopes, indexed)
        };
        let old_answer = answer(&old_provider);
        assert_eq!(old_answer.0.len(), 1);
        assert_eq!(old_answer.1.len(), 1);
        assert_eq!(old_answer.2.len(), 1);
        assert!(old_answer.3);
        assert_eq!(
            answer(&current_provider),
            (Vec::new(), Vec::new(), Vec::new(), false)
        );
        assert!(
            !store
                .jvm_inventory_owners_missing(&old_provider, std::iter::once("example.Owner"))
                .unwrap()
        );
        assert!(
            store
                .jvm_inventory_owners_missing(&current_provider, std::iter::once("example.Owner"))
                .unwrap()
        );
        assert_eq!(
            store
                .publish_jvm_external_inventory_facts("artifact".into(), &types, &members, true)
                .unwrap(),
            JvmExternalInventoryWrite::Written
        );
        assert!(
            !store
                .jvm_inventory_owners_missing(&current_provider, std::iter::once("example.Owner"))
                .unwrap()
        );
        assert_eq!(answer(&current_provider), old_answer);
    }

    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
    )]
    fn projected_type_parameter_bounds_preserve_unknown() {
        let legacy: crate::analyzer::semantic_model::Signature =
            serde_json::from_str(r#"{"type_parameters":["T"]}"#).unwrap();
        assert!(legacy.bounds.is_none());
        assert_eq!(
            unknown_type_parameters(&legacy.type_parameters).unwrap(),
            r#"[{"name":"T","bounds":{"state":"unknown"}}]"#
        );
        assert!(decode_jvm_external_type_parameters(None).unwrap().is_none());
        assert!(
            decode_jvm_external_type_parameters(Some("[]"))
                .unwrap()
                .unwrap()
                .is_empty()
        );
        let unknown = decode_jvm_external_type_parameters(Some(
            r#"[{"name":"T","bounds":{"state":"unknown"}}]"#,
        ))
        .unwrap()
        .unwrap();
        assert!(matches!(
            unknown[0].bounds,
            JvmExternalTypeParameterBounds::Unknown
        ));
        let known = decode_jvm_external_type_parameters(Some(
            r#"[{"name":"T","bounds":{"state":"known","types":[]}}]"#,
        ))
        .unwrap()
        .unwrap();
        assert!(
            matches!(&known[0].bounds, JvmExternalTypeParameterBounds::Known(types) if types.is_empty())
        );
        for invalid in [
            r#"[{"name":"T"}]"#,
            r#"[{"name":"T","bounds":{}}]"#,
            r#"[{"name":"T","bounds":{"state":"known"}}]"#,
            r#"[{"name":"T","bounds":{"state":"unexpected"}}]"#,
        ] {
            assert!(
                decode_jvm_external_type_parameters(Some(invalid)).is_err(),
                "{invalid}"
            );
        }
        // An older writer omits nullable columns: missing projection remains unknown.
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store.conn.execute(|conn| -> Result<()> {
            conn.execute("INSERT INTO jvm_external_provider_publications(provider_id,semantic_sha256,source_identity,projection_identity,publication_state) VALUES('old','old','',zeroblob(32),'uncertified')", [])?;
            conn.execute("INSERT INTO jvm_external_owners(provider_id,owner_fqn,callables_complete,values_complete,types_complete,supertypes_complete) VALUES('old','Old',0,0,0,0)", [])?;
            Ok(())
        }).unwrap();
        let conn = store.read_conn().unwrap();
        let encoded: Option<String> = conn
            .query_row(
                "SELECT json(type_parameters_jsonb) FROM jvm_external_owners",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            decode_jvm_external_type_parameters(encoded.as_deref())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    #[hardwon("#9559: duplicate owner names aborted JVM inventory publication during review")]
    #[expect(
        clippy::disallowed_methods,
        reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
    )]
    fn duplicate_owner_facts_keep_only_first_members() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let types: Vec<crate::analyzer::semantic_model::TypeFact> = serde_json::from_value(serde_json::json!([
            {"id":"first","name":"example.Owner","type_kind":"class","visibility":"public","locator":{"kind":"artifact","path":"fixture.jar","symbol":"first"}},
            {"id":"second","name":"example.Owner","type_kind":"class","visibility":"public","locator":{"kind":"artifact","path":"fixture.jar","symbol":"second"}}
        ])).unwrap();
        let members: Vec<MemberFact> = serde_json::from_value(serde_json::json!([
            {"id":"first-member","owner":"first","name":"kept","member_kind":"method","visibility":"public","locator":{"kind":"artifact","path":"fixture.jar","symbol":"kept"}},
            {"id":"second-member","owner":"second","name":"dropped","member_kind":"method","visibility":"public","locator":{"kind":"artifact","path":"fixture.jar","symbol":"dropped"}}
        ])).unwrap();
        let generation_before = store.jvm_external_inventory_generation().unwrap();
        store
            .publish_jvm_external_inventory_facts("provider".into(), &types, &members, true)
            .unwrap();
        assert!(store.jvm_external_inventory_generation().unwrap() > generation_before);
        let conn = store.read_conn().unwrap();
        let names: Vec<String> = conn.prepare("SELECT member_name FROM jvm_external_owner_members WHERE provider_id=(SELECT provider_id FROM jvm_external_provider_publications WHERE semantic_sha256='provider') ORDER BY ordinal").unwrap()
            .query_map([], |row| row.get(0)).unwrap().map(|row| row.unwrap()).collect();
        assert_eq!(names, ["kept"]);
        let complete: i64 = conn
            .query_row(
                "SELECT callables_complete FROM jvm_external_owners WHERE provider_id=(SELECT provider_id FROM jvm_external_provider_publications WHERE semantic_sha256='provider')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(complete, 0);
    }

    #[test]
    #[should_panic(expected = "intrinsic JVM provider cannot publish external inventory rows")]
    fn intrinsic_provider_publication_is_rejected_before_empty_return() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .publish_jvm_external_inventory_facts(
                "jvm-intrinsic".to_owned(),
                std::iter::empty::<&crate::analyzer::semantic_model::TypeFact>(),
                std::iter::empty::<&MemberFact>(),
                true,
            )
            .unwrap();
    }
}
