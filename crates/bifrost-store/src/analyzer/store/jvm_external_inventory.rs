//! Durable, content-selected inventories for independently enumerated JVM owners.

use super::jvm_external_publication::JvmExternalProjection;
use super::{AnalyzerStore, Result, StoreError};
use crate::analyzer::semantic_model::{
    ActiveSemanticModelShard, Completeness, MemberFact, TypeRef, Visibility,
};
use crate::hash::HashMap;
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
use rusqlite::types::Value;
use rusqlite::{TransactionBehavior, params};

/// Convert one declaration shard to the exact inventory table column order.
pub fn jvm_external_projection<'a>(
    provider_id: String,
    source_identity: String,
    types: impl IntoIterator<Item = &'a crate::analyzer::semantic_model::TypeFact>,
    members: impl IntoIterator<Item = &'a MemberFact>,
    complete: bool,
) -> Result<JvmExternalProjection> {
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
                ]);
            }
        }
    }
    Ok(projection)
}

impl AnalyzerStore {
    /// Publication handles one already decoded provider shard. The temporary
    /// owner join and insert bindings die with this writer transaction; only
    /// relational inventory rows survive it.
    #[doc(hidden)]
    pub fn publish_jvm_external_owner_inventory(
        &self,
        shard: &ActiveSemanticModelShard,
    ) -> Result<()> {
        if super::resolution_operation::nominal_rules::nominal_package_rules_for_storage(
            &shard.manifest.language,
        )
        .is_none()
        {
            return Ok(());
        }
        let Some((types, members, _relations)) = shard.decoded().payload().declaration_facts()
        else {
            return Ok(());
        };
        let enumerated_types = types
            .iter()
            .map(AsRef::as_ref)
            .filter(|owner| shard.admits_jvm_owner_declaration(owner))
            .collect::<Vec<_>>();
        self.publish_jvm_external_inventory_facts(
            shard.manifest.semantic_sha256.clone(),
            enumerated_types,
            members.iter().map(AsRef::as_ref),
            shard.manifest.completeness == Completeness::Complete,
        )
    }

    #[doc(hidden)]
    pub fn publish_jvm_external_inventory_facts<'a>(
        &self,
        provider_id: String,
        types: impl IntoIterator<Item = &'a crate::analyzer::semantic_model::TypeFact>,
        members: impl IntoIterator<Item = &'a MemberFact>,
        complete: bool,
    ) -> Result<()> {
        // This provider is synthesized by the JVM intrinsic inventory and
        // must never acquire durable rows: operation-local owner-index reads
        // rely on its absence throughout the operation.
        assert_ne!(
            provider_id, "jvm-intrinsic",
            "intrinsic JVM provider cannot publish external inventory rows"
        );
        let enumerated_types = types.into_iter().collect::<Vec<_>>();
        if enumerated_types.is_empty() {
            return Ok(());
        }
        // Check durable membership before copying any member payload. A cache
        // hit must not rematerialize the decoded declaration pack per request.
        let requested_owners = json_value(
            &enumerated_types
                .iter()
                .map(|owner| &owner.name)
                .collect::<Vec<_>>(),
        )?;
        let checked_provider = provider_id.clone();
        let missing: bool = self.conn.execute(move |conn| -> Result<bool> {
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
        })?;
        if !missing {
            return Ok(());
        }
        let projection = jvm_external_projection(
            provider_id.clone(),
            String::new(),
            enumerated_types,
            members,
            complete,
        )?;
        self.conn.execute(move |conn| {
            let transaction = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
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
            let mut owner_insert = transaction.prepare_cached("INSERT OR IGNORE INTO jvm_external_owners(provider_id,owner_fqn,callables_complete,values_complete,types_complete,supertypes_complete) VALUES(?1,?2,?3,?4,?5,?6)")?;
            let mut member_insert = transaction.prepare_cached("INSERT INTO jvm_external_owner_members(provider_id,owner_fqn,ordinal,member_name,member_kind,visibility,is_static,signature_present,callable_family_complete,non_overridable,parameters_jsonb,return_type_jsonb) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,jsonb(?11),jsonb(?12))")?;
            let mut supertype_insert = transaction.prepare_cached("INSERT INTO jvm_external_owner_supertypes(provider_id,owner_fqn,supertype_fqn,ordinal) VALUES(?1,?2,?3,?4)")?;
            for owner in &projection.owners {
                if owner_insert.execute(rusqlite::params_from_iter(owner))? == 0 { continue; }
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
            Ok(())
        })
    }
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
    #[hardwon("#9559: duplicate owner names aborted JVM inventory publication during review")]
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
        store
            .publish_jvm_external_inventory_facts("provider".into(), &types, &members, true)
            .unwrap();
        let conn = store.read_conn().unwrap();
        let names: Vec<String> = conn.prepare("SELECT member_name FROM jvm_external_owner_members WHERE provider_id='provider' ORDER BY ordinal").unwrap()
            .query_map([], |row| row.get(0)).unwrap().map(|row| row.unwrap()).collect();
        assert_eq!(names, ["kept"]);
        let complete: i64 = conn
            .query_row(
                "SELECT callables_complete FROM jvm_external_owners WHERE provider_id='provider'",
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
