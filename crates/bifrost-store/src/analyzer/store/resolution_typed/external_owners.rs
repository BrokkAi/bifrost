//! Durable external inventories selected by the request's exact provider identities.
use super::*;
use crate::analyzer::resolution::ExternalOwnerIdentity;
use brokk_bifrost_core::analyzer::resolution_facts::{
    ResolutionMemberAccess, ResolutionMemberKind, ResolutionMemberQualifierCompatibility,
    ResolutionNamespace,
};
use std::sync::Arc;

pub(in crate::analyzer::store) const EXTERNAL_MEMBER_OWNER_BY_DEFINITION_SQL: &str = "SELECT member.ordinal,member.member_name,member.member_kind,member.visibility,member.is_static FROM jvm_external_owner_members member JOIN jvm_external_owners inventory USING(provider_id,owner_fqn) WHERE member.provider_id=?1 AND member.owner_fqn=?2 AND member.ordinal=?3 AND member.provider_id IN (SELECT value FROM json_each(?4))";

pub(in crate::analyzer::store) const INTRINSIC_MEMBER_OWNER_INDEXED_SQL: &str =
    "SELECT EXISTS(SELECT 1 FROM jvm_external_owners WHERE provider_id=?1 AND owner_fqn=?2)";

fn decode_external_member_visibility(label: &str) -> StoreResult<DeclaredVisibility> {
    DeclaredVisibility::from_label(label)
        .ok_or_else(|| invalid_fact(format!("invalid external member visibility {label:?}")))
}

pub(in crate::analyzer::store) fn intrinsic_member_inventory_for_owner(
    connection: &rusqlite::Connection,
    owner: &ExternalOwnerIdentity,
) -> StoreResult<Option<&'static [crate::analyzer::resolution::universe::IntrinsicMember]>> {
    let Some(inventory) =
        crate::analyzer::resolution::universe::intrinsic_member_inventory(&owner.owner_fqn)
    else {
        return Ok(None);
    };
    // Indexed artifacts own their ordinals. Never overlay intrinsic ordinals
    // onto an existing provider's rows; the fixed table fills an unindexed root.
    let indexed: bool = connection.query_row(
        INTRINSIC_MEMBER_OWNER_INDEXED_SQL,
        rusqlite::params![owner.provider_id.as_ref(), owner.owner_fqn.as_ref()],
        |row| row.get(0),
    )?;
    Ok((!indexed).then_some(inventory))
}

impl SelectedResolutionTypedSource<'_, '_> {
    pub(super) fn external_callable_result_type_identities(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<(SemanticId, SemanticId)>>> {
        let mut requested = std::collections::BTreeMap::new();
        for &definition in definitions {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            if let Some((owner, ordinal)) =
                self.context_identities.external_member_identity(definition)
            {
                requested.insert(
                    (
                        owner.provider_id.to_string(),
                        owner.owner_fqn.to_string(),
                        ordinal,
                    ),
                    definition,
                );
            }
        }
        if requested.is_empty() {
            return Ok(Some(Vec::new()));
        }
        let coordinates = requested.keys().collect::<Vec<_>>();
        let coordinates = serde_json::to_string(&coordinates)
            .map_err(|error| StoreError::new(error.to_string()))?;
        let providers = serde_json::to_string(&self.external_providers)
            .map_err(|error| StoreError::new(error.to_string()))?;
        let rows = self.read_statement(cancellation, |conn| {
            let mut statement = conn.prepare_cached(
                "WITH requested AS (
                   SELECT json_extract(value, '$[0]') provider_id,
                          json_extract(value, '$[1]') owner_fqn,
                          json_extract(value, '$[2]') ordinal
                   FROM json_each(?1)
                 )
                 SELECT member.provider_id,member.owner_fqn,member.ordinal,
                        json_extract(member.return_type_jsonb, '$.name'),
                        (SELECT CASE WHEN count(*)=1 THEN min(owner.provider_id) END
                           FROM jvm_external_owners owner
                          WHERE owner.owner_fqn=json_extract(member.return_type_jsonb, '$.name')
                            AND owner.provider_id IN (SELECT value FROM json_each(?2)))
                   FROM requested
                   JOIN jvm_external_owner_members member
                     ON member.provider_id=requested.provider_id
                    AND member.owner_fqn=requested.owner_fqn
                    AND member.ordinal=requested.ordinal
                  WHERE member.member_kind IN ('method','function')
                    AND json_extract(member.return_type_jsonb, '$.kind')='named'
                    AND member.provider_id IN (SELECT value FROM json_each(?2))
                  ORDER BY member.provider_id,member.owner_fqn,member.ordinal",
            )?;
            let mut rows = statement.query([coordinates, providers])?;
            let mut result = Vec::new();
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let provider: String = row.get(0)?;
                let owner_fqn: String = row.get(1)?;
                let ordinal: u32 = row.get(2)?;
                let Some(type_fqn) = row.get::<_, Option<String>>(3)? else {
                    continue;
                };
                let Some(type_provider) = row.get::<_, Option<String>>(4)? else {
                    continue;
                };
                let definition = requested
                    .get(&(provider.clone(), owner_fqn, ordinal))
                    .copied()
                    .expect("external result row matches one requested member coordinate");
                result.push((definition, type_provider, type_fqn));
            }
            Ok(Some(result))
        })?;
        let Some(rows) = rows else {
            return Ok(None);
        };
        let names = self
            .selection
            .shared_name_table()
            .interner(self.selection.connection());
        Ok(Some(
            rows.into_iter()
                .map(|(definition, provider_id, owner_fqn)| {
                    let identity = self.context_identities.external_owner_semantic(
                        &ExternalOwnerIdentity {
                            provider_id: Arc::<str>::from(provider_id),
                            owner_fqn: Arc::<str>::from(owner_fqn),
                        },
                        &names,
                    );
                    (definition, identity)
                })
                .collect(),
        ))
    }

    fn intrinsic_member_inventory_for_owner(
        &self,
        owner: &ExternalOwnerIdentity,
        cancellation: &CancellationToken,
    ) -> StoreResult<
        Option<Option<&'static [crate::analyzer::resolution::universe::IntrinsicMember]>>,
    > {
        self.read_statement(cancellation, |connection| {
            Ok(Some(intrinsic_member_inventory_for_owner(
                connection, owner,
            )?))
        })
    }

    fn visit_external_rows<T>(
        &self,
        definitions: &[SemanticId],
        sql: &str,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, T>,
        decode: impl Fn(&ExternalOwnerIdentity, SemanticId, &Row<'_>) -> StoreResult<T>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let providers = serde_json::to_string(&self.external_providers)
            .map_err(|error| StoreError::new(error.to_string()))?;
        for &definition in definitions {
            let Some(owner) = self.context_identities.external_owner_identity(definition) else {
                continue;
            };
            let Some(intrinsic) =
                self.intrinsic_member_inventory_for_owner(&owner, cancellation)?
            else {
                return cancelled();
            };
            if intrinsic.is_some() {
                continue;
            }
            let mut cursor = -1i64;
            loop {
                if cancellation.is_cancelled() {
                    return cancelled();
                }
                let Some(page) = self.read_statement(cancellation, |conn| {
                    let mut statement = conn.prepare_cached(sql)?;
                    let mut rows = statement.query(rusqlite::params![
                        owner.provider_id.as_ref(),
                        owner.owner_fqn.as_ref(),
                        cursor,
                        visitor.maximum_rows() as i64,
                        providers
                    ])?;
                    let mut page = Vec::new();
                    while let Some(row) = rows.next()? {
                        if cancellation.is_cancelled() {
                            break;
                        }
                        cursor = row.get(0)?;
                        page.push(decode(&owner, definition, row)?);
                    }
                    Ok(Some(page))
                })?
                else {
                    return cancelled();
                };
                if cancellation.is_cancelled() {
                    return cancelled();
                }
                if page.is_empty() {
                    break;
                }
                let keep_going = visitor.visit_page(&page)?;
                if cancellation.is_cancelled() {
                    return cancelled();
                }
                if !keep_going {
                    return Ok(TypedFactReadOutcome::stopped(
                        ResolutionCompletion::Complete,
                    ));
                }
            }
        }
        Ok(if cancellation.is_cancelled() {
            TypedFactReadOutcome::cancelled(ResolutionCompletion::Complete)
        } else {
            TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
        })
    }

    fn external_owner_family_is_enumerated(&self, owner: &ExternalOwnerIdentity) -> bool {
        let Some(models) = &self.external_models else {
            return true;
        };
        // Artifact inventory providers are independent of model activation.
        // A model provider's content rows survive activation changes, so its
        // current source's enumeration authority must be checked at selection.
        if !models
            .shards()
            .iter()
            .any(|shard| shard.manifest.semantic_sha256 == owner.provider_id.as_ref())
        {
            return true;
        }
        models
            .types_named(&owner.owner_fqn)
            .records
            .iter()
            .any(|candidate| {
                candidate.shard.manifest.semantic_sha256 == owner.provider_id.as_ref()
                    && candidate
                        .shard
                        .independently_enumerates_jvm_owner(candidate.record)
            })
    }

    pub(super) fn visit_external_member_scopes(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberScopeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        for &definition in definitions {
            if cancellation.is_cancelled() {
                return cancelled();
            }
            let Some(owner) = self.context_identities.external_owner_identity(definition) else {
                continue;
            };
            let Some(intrinsic) =
                self.intrinsic_member_inventory_for_owner(&owner, cancellation)?
            else {
                return cancelled();
            };
            let names_only = owner.provider_id.as_ref() == "jvm-intrinsic"
                && brokk_bifrost_jvm::intrinsics::closed_owner_member_inventory(&owner.owner_fqn)
                    .is_some()
                && self.jvm_intrinsic_owner_is_unshadowed(&owner.owner_fqn, cancellation)?;
            if intrinsic.is_some() || names_only {
                let row = SelectedTypedRow::external_owner(
                    owner,
                    LoweredMemberScopeProperty::external(
                        definition,
                        crate::analyzer::resolution::ExternalMemberCoverage {
                            callables_complete: true,
                            values_complete: true,
                            types_complete: true,
                            supertypes_complete: !names_only,
                            member_names_only: names_only,
                        },
                    ),
                );
                let keep_going = visitor.visit_page(std::slice::from_ref(&row))?;
                if cancellation.is_cancelled() {
                    return cancelled();
                }
                if !keep_going {
                    return Ok(TypedFactReadOutcome::stopped(
                        ResolutionCompletion::Complete,
                    ));
                }
            }
        }
        self.visit_external_rows(definitions,
            "SELECT 0,callables_complete,values_complete,types_complete,supertypes_complete FROM jvm_external_owners WHERE provider_id=?1 AND owner_fqn=?2 AND 0>?3 AND provider_id IN (SELECT value FROM json_each(?5)) LIMIT ?4",
            cancellation, visitor, |owner, definition, row| {
                let enumerated = self.external_owner_family_is_enumerated(owner);
                Ok(SelectedTypedRow::external_owner(owner.clone(), LoweredMemberScopeProperty::external(definition, crate::analyzer::resolution::ExternalMemberCoverage {
                    callables_complete: enumerated && row.get(1)?,
                    values_complete: enumerated && row.get(2)?,
                    types_complete: enumerated && row.get(3)?,
                    supertypes_complete: enumerated && row.get(4)?,
                    member_names_only: false,
                })))
            })
    }

    pub(super) fn visit_external_member_owners(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberOwnerProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let names = self
            .selection
            .shared_name_table()
            .interner(self.selection.connection());
        for &definition in definitions {
            if cancellation.is_cancelled() {
                return cancelled();
            }
            let Some(owner) = self.context_identities.external_owner_identity(definition) else {
                continue;
            };
            let Some(intrinsic) =
                self.intrinsic_member_inventory_for_owner(&owner, cancellation)?
            else {
                return cancelled();
            };
            if let Some(members) = intrinsic {
                for (ordinal, member) in members.iter().enumerate() {
                    let row = self.external_member_owner_row(
                        &owner,
                        definition,
                        ordinal as u32,
                        member.name,
                        "method",
                        member.visibility,
                        false,
                        &names,
                    )?;
                    let keep_going = visitor.visit_page(std::slice::from_ref(&row))?;
                    if cancellation.is_cancelled() {
                        return cancelled();
                    }
                    if !keep_going {
                        return Ok(TypedFactReadOutcome::stopped(
                            ResolutionCompletion::Complete,
                        ));
                    }
                }
            }
        }
        self.visit_external_rows(definitions,
            "SELECT member.ordinal,member.member_name,member.member_kind,member.visibility,member.is_static FROM jvm_external_owner_members member JOIN jvm_external_owners inventory USING(provider_id,owner_fqn) WHERE member.provider_id=?1 AND member.owner_fqn=?2 AND member.ordinal>?3 AND member.provider_id IN (SELECT value FROM json_each(?5)) ORDER BY member.ordinal LIMIT ?4",
            cancellation, visitor, |owner, definition, row| {
                self.decode_external_member_owner(owner, definition, row, &names)
            })
    }

    pub(super) fn visit_external_member_owners_for_definitions(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberOwnerProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let names = self
            .selection
            .shared_name_table()
            .interner(self.selection.connection());
        let providers = serde_json::to_string(&self.external_providers)
            .map_err(|error| StoreError::new(error.to_string()))?;
        for &definition in definitions {
            if cancellation.is_cancelled() {
                return cancelled();
            }
            let Some((owner, ordinal)) =
                self.context_identities.external_member_identity(definition)
            else {
                continue;
            };
            let owner_definition = self
                .context_identities
                .external_owner_semantic(&owner, &names);
            let Some(intrinsic) =
                self.intrinsic_member_inventory_for_owner(&owner, cancellation)?
            else {
                return cancelled();
            };
            if let Some(members) = intrinsic {
                let member = &members[ordinal as usize];
                let row = self.external_member_owner_row(
                    &owner,
                    owner_definition,
                    ordinal,
                    member.name,
                    "method",
                    member.visibility,
                    false,
                    &names,
                )?;
                let keep_going = visitor.visit_page(std::slice::from_ref(&row))?;
                if cancellation.is_cancelled() {
                    return cancelled();
                }
                if !keep_going {
                    return Ok(TypedFactReadOutcome::stopped(
                        ResolutionCompletion::Complete,
                    ));
                }
                continue;
            }
            let Some(row) = self.read_statement(cancellation, |conn| {
                let mut statement = conn.prepare_cached(EXTERNAL_MEMBER_OWNER_BY_DEFINITION_SQL)?;
                let mut rows = statement.query(rusqlite::params![
                    owner.provider_id.as_ref(),
                    owner.owner_fqn.as_ref(),
                    ordinal,
                    providers
                ])?;
                rows.next()?
                    .map(|row| {
                        self.decode_external_member_owner(&owner, owner_definition, row, &names)
                    })
                    .transpose()
                    .map(Some)
            })?
            else {
                return cancelled();
            };
            if cancellation.is_cancelled() {
                return cancelled();
            }
            if let Some(row) = row {
                debug_assert_eq!(row.row().definition(), definition);
                let keep_going = visitor.visit_page(std::slice::from_ref(&row))?;
                if cancellation.is_cancelled() {
                    return cancelled();
                }
                if !keep_going {
                    return Ok(TypedFactReadOutcome::stopped(
                        ResolutionCompletion::Complete,
                    ));
                }
            }
        }
        Ok(if cancellation.is_cancelled() {
            TypedFactReadOutcome::cancelled(ResolutionCompletion::Complete)
        } else {
            TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
        })
    }

    fn decode_external_member_owner(
        &self,
        owner: &ExternalOwnerIdentity,
        definition: SemanticId,
        row: &Row<'_>,
        names: &dyn SharedNameInterner,
    ) -> StoreResult<SelectedTypedRow<LoweredMemberOwnerProperty>> {
        let ordinal: u32 = row.get(0)?;
        let name: String = row.get(1)?;
        let kind: String = row.get(2)?;
        let visibility: String = row.get(3)?;
        let is_static: bool = row.get(4)?;
        self.external_member_owner_row(
            owner,
            definition,
            ordinal,
            &name,
            &kind,
            &visibility,
            is_static,
            names,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn external_member_owner_row(
        &self,
        owner: &ExternalOwnerIdentity,
        definition: SemanticId,
        ordinal: u32,
        name: &str,
        kind: &str,
        visibility: &str,
        is_static: bool,
        names: &dyn SharedNameInterner,
    ) -> StoreResult<SelectedTypedRow<LoweredMemberOwnerProperty>> {
        let kind = match kind {
            "method" | "function" => ResolutionMemberKind::Method,
            "constructor" => ResolutionMemberKind::Constructor,
            "nested_type" => ResolutionMemberKind::NestedType,
            _ => ResolutionMemberKind::Field,
        };
        let visibility = decode_external_member_visibility(visibility)?;
        // External member lookup identities use effective namespaces;
        // TypeOrValue is a source-site union and cannot form a lookup recipe.
        let namespaces = [
            ResolutionNamespace::Callable,
            ResolutionNamespace::Value,
            ResolutionNamespace::Constant,
            ResolutionNamespace::Type,
            ResolutionNamespace::Type,
        ];
        let languages = [Language::Java, Language::Kotlin, Language::Scala];
        let lookups = std::array::from_fn(|i| {
            crate::analyzer::resolution::lookup_semantic(
                names,
                languages[i / 5],
                namespaces[i % 5],
                name,
            )
        });
        let member = self
            .context_identities
            .external_member_semantic(owner, ordinal, names);
        Ok(SelectedTypedRow::external_member(
            owner.clone(),
            ordinal,
            LoweredMemberOwnerProperty::external(
                member,
                definition,
                name,
                kind,
                if is_static || kind == ResolutionMemberKind::NestedType {
                    ResolutionMemberAccess::Type
                } else {
                    ResolutionMemberAccess::Instance
                },
                if is_static || kind == ResolutionMemberKind::NestedType {
                    ResolutionMemberQualifierCompatibility::RuntimeOrType
                } else {
                    ResolutionMemberQualifierCompatibility::RuntimeOnly
                },
                lookups,
                visibility,
            ),
        ))
    }

    pub(super) fn visit_external_supertypes(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredSupertypeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let names = self
            .selection
            .shared_name_table()
            .interner(self.selection.connection());
        self.visit_external_rows(definitions,
            "SELECT edge.ordinal,edge.supertype_fqn,COALESCE((SELECT provider_id FROM jvm_external_owners WHERE owner_fqn=edge.supertype_fqn AND provider_id=?1),(SELECT CASE WHEN count(*)=1 THEN min(provider_id) END FROM jvm_external_owners WHERE owner_fqn=edge.supertype_fqn AND provider_id IN (SELECT value FROM json_each(?5))),?1) FROM jvm_external_owner_supertypes edge JOIN jvm_external_owners inventory USING(provider_id,owner_fqn) WHERE edge.provider_id=?1 AND edge.owner_fqn=?2 AND edge.ordinal>?3 AND edge.provider_id IN (SELECT value FROM json_each(?5)) ORDER BY edge.ordinal LIMIT ?4",
            cancellation, visitor, |owner, definition, row| {
                let ordinal: u32 = row.get(0)?;
                let target = ExternalOwnerIdentity { provider_id: Arc::<str>::from(row.get::<_, String>(2)?), owner_fqn: Arc::<str>::from(row.get::<_, String>(1)?) };
                let target_semantic = self.context_identities.external_owner_semantic(&target, &names);
                let reference = self.context_identities.external_supertype_reference(owner, ordinal, &names);
                self.context_identities.record_external_hierarchy_reference(reference, target_semantic);
                Ok(SelectedTypedRow::external_owner(owner.clone(), LoweredSupertypeProperty::external(definition, reference, reference, ordinal, target)))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::decode_external_member_visibility;
    use crate::analyzer::semantic_model::{MemberFact, TypeFact};
    use crate::analyzer::store::AnalyzerStore;
    use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#6214: package-private JVM members were stored as \"package\" and failed to decode")]
    fn published_package_private_member_and_nested_type_decode_from_inventory() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let types: Vec<TypeFact> = serde_json::from_value(serde_json::json!([{
            "id": "owner", "name": "example.Owner", "type_kind": "class",
            "visibility": "public", "locator": {"kind":"artifact","path":"fixture.jar","symbol":"example.Owner"},
            "jvm_inventory": {
                "callables_complete": true, "values_complete": true, "types_complete": true,
                "supertypes_complete": true, "supertypes": [], "additional_members": [],
                "nested_types": [{"name":"Nested","owner_fqn":"example.Owner.Nested","visibility":"package","is_static":false}]
            }
        }])).unwrap();
        let members: Vec<MemberFact> = serde_json::from_value(serde_json::json!([{
            "id":"package-member", "owner":"owner", "name":"ordinary", "member_kind":"method",
            "visibility":"package", "locator":{"kind":"artifact","path":"fixture.jar","symbol":"example.Owner.ordinary"}
        }])).unwrap();
        store
            .publish_jvm_external_inventory_facts("provider".to_owned(), &types, &members, true)
            .unwrap();

        let conn = store.read_conn().unwrap();
        let mut statement = conn.prepare(
            "SELECT member_name, visibility FROM jvm_external_owner_members WHERE provider_id='provider' AND owner_fqn='example.Owner' ORDER BY ordinal",
        ).unwrap();
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap();
        let decoded = rows
            .map(|row| {
                let (name, label) = row.unwrap();
                (name, decode_external_member_visibility(&label).unwrap())
            })
            .collect::<Vec<_>>();
        assert_eq!(
            decoded,
            vec![
                ("ordinary".to_owned(), DeclaredVisibility::PackagePrivate),
                ("Nested".to_owned(), DeclaredVisibility::PackagePrivate),
            ]
        );
    }
}
