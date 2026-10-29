//! Durable, content-selected inventories for independently enumerated JVM owners.

use super::{AnalyzerStore, Result, StoreError};
use crate::analyzer::semantic_model::{
    ActiveSemanticModelShard, Completeness, MemberFact, TypeRef, Visibility,
};
use crate::hash::HashMap;
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
use rusqlite::{TransactionBehavior, params};

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
            Ok(conn.query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM json_each(?2) requested
                   LEFT JOIN jvm_external_owners inventory
                     ON inventory.provider_id=?1 AND inventory.owner_fqn=requested.value
                   WHERE inventory.owner_fqn IS NULL
                 )",
                params![checked_provider, requested_owners],
                |row| row.get(0),
            )?)
        })?;
        if !missing {
            return Ok(());
        }
        let types = enumerated_types.into_iter().cloned().collect::<Vec<_>>();
        let members = members.into_iter().cloned().collect::<Vec<_>>();
        self.conn.execute(move |conn| {
            let transaction = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let names_by_id = types
                .iter()
                .map(|owner| (owner.id.as_str(), owner.name.as_str()))
                .collect::<HashMap<_, _>>();
            let mut owners_by_name = HashMap::<&str, usize>::default();
            for owner in &types { *owners_by_name.entry(&owner.name).or_default() += 1; }
            let mut members_by_owner = HashMap::<&str, Vec<&MemberFact>>::default();
            for member in &members {
                members_by_owner.entry(&member.owner).or_default().push(member);
            }
            for owner in &types {
                for member in owner.jvm_inventory.iter().flat_map(|inventory| &inventory.additional_members) {
                    members_by_owner.entry(&member.owner).or_default().push(member);
                }
            }
            for owner in &types {
                let owner_members = members_by_owner.get(owner.id.as_str());
                // Guards depend on activation coordinates, whereas these rows
                // belong to content alone. Retain conditional inventories as
                // partial until a structured guard reader can select them.
                let hierarchy = owner.jvm_inventory.as_ref().map_or(owner.hierarchy.as_slice(), |inventory| inventory.supertypes.as_slice());
                let owner_complete = (complete || owner.jvm_inventory.is_some())
                    && owners_by_name[owner.name.as_str()] == 1
                    && owner.guard.is_none()
                    && owner_members.is_none_or(|members| {
                        members.iter().all(|member| member.guard.is_none())
                    })
                    && hierarchy.iter().all(|parent| {
                        matches!(&parent.target, TypeRef::Named { name, .. } if !name.is_empty())
                            || matches!(&parent.target, TypeRef::Declared { id, .. } if names_by_id.contains_key(id.as_str()))
                    });
                let inserted = transaction.execute(
                    "INSERT OR IGNORE INTO jvm_external_owners(provider_id, owner_fqn, callables_complete, values_complete, types_complete, supertypes_complete)
                     VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
                    params![provider_id, owner.name,
                        owner_complete && owner.jvm_inventory.as_ref().is_some_and(|inventory| inventory.callables_complete),
                        owner_complete && owner.jvm_inventory.as_ref().is_some_and(|inventory| inventory.values_complete),
                        owner_complete && owner.jvm_inventory.as_ref().is_some_and(|inventory| inventory.types_complete),
                        owner_complete && owner.jvm_inventory.as_ref().is_some_and(|inventory| inventory.supertypes_complete)],
                )?;
                if inserted == 0 {
                    continue;
                }
                for (ordinal, member) in owner_members.into_iter().flatten()
                    .filter(|member| member.guard.is_none()).enumerate() {
                    let signature = member.signature.as_ref();
                    let parameters = json_value(&signature.map(|signature| &signature.parameters).unwrap_or(&Vec::new()))?;
                    let returns = signature.and_then(|signature| signature.returns.as_ref()).map(json_value).transpose()?;
                    transaction.execute(
                        "INSERT INTO jvm_external_owner_members(
                           provider_id, owner_fqn, ordinal, member_name, member_kind, visibility,
                           is_static, signature_present, callable_family_complete, non_overridable,
                           parameters_jsonb, return_type_jsonb
                         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, jsonb(?11), jsonb(?12))",
                        params![
                            provider_id, owner.name, ordinal, member.name,
                            enum_label(&member.member_kind)?, jvm_declared_visibility(member.visibility).label(),
                            member.is_static, signature.is_some(), member.callable_family_complete,
                            member.non_overridable.as_ref().map(enum_label).transpose()?,
                            parameters, returns,
                        ],
                    )?;
                }
                let member_count = owner_members.into_iter().flatten().filter(|member| member.guard.is_none()).count();
                for (offset, nested) in owner.jvm_inventory.iter().flat_map(|inventory| &inventory.nested_types).enumerate() {
                    transaction.execute(
                        "INSERT INTO jvm_external_owner_members(provider_id, owner_fqn, ordinal, member_name, member_kind, visibility, is_static, signature_present, callable_family_complete, parameters_jsonb, return_type_jsonb)
                         VALUES(?1, ?2, ?3, ?4, 'nested_type', ?5, ?6, 0, 0, jsonb('[]'), jsonb(?7))",
                        params![provider_id, owner.name, member_count + offset, nested.name, jvm_declared_visibility(nested.visibility).label(), nested.is_static, json_value(&TypeRef::named(&nested.owner_fqn))?],
                    )?;
                }
                for (ordinal, parent) in hierarchy.iter().enumerate() {
                    let fqn = match &parent.target {
                        TypeRef::Named { name, .. } => Some(name.as_str()),
                        TypeRef::Declared { id, .. } => names_by_id.get(id.as_str()).copied(),
                        _ => None,
                    };
                    if let Some(fqn) = fqn {
                        transaction.execute(
                            "INSERT INTO jvm_external_owner_supertypes(provider_id, owner_fqn, supertype_fqn, ordinal)
                             VALUES(?1, ?2, ?3, ?4)",
                            params![provider_id, owner.name, fqn, ordinal],
                        )?;
                    }
                }
            }
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
