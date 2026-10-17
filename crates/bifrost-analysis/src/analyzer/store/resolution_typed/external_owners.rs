//! Durable external inventories selected by the request's exact provider identities.
use super::*;
use crate::analyzer::resolution::ExternalOwnerIdentity;
use brokk_bifrost_core::analyzer::resolution_facts::{
    ResolutionMemberAccess, ResolutionMemberKind, ResolutionMemberQualifierCompatibility,
    ResolutionNamespace,
};
use std::sync::Arc;

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

    pub(super) fn visit_external_member_scopes(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberScopeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        self.visit_external_rows(definitions,
            "SELECT 0,callables_complete,values_complete,types_complete,supertypes_complete FROM jvm_external_owners WHERE provider_id=?1 AND owner_fqn=?2 AND 0>?3 AND provider_id IN (SELECT value FROM json_each(?5)) LIMIT ?4",
            cancellation, visitor, |owner, definition, row| Ok(SelectedTypedRow::external_owner(owner.clone(), LoweredMemberScopeProperty::external(definition, crate::analyzer::resolution::ExternalMemberCoverage {
                callables_complete: row.get(1)?, values_complete: row.get(2)?, types_complete: row.get(3)?, supertypes_complete: row.get(4)?,
            }))))
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
        self.visit_external_rows(definitions,
            "SELECT member.ordinal,member.member_name,member.member_kind,member.visibility,member.is_static FROM jvm_external_owner_members member JOIN jvm_external_owners inventory USING(provider_id,owner_fqn) WHERE member.provider_id=?1 AND member.owner_fqn=?2 AND member.ordinal>?3 AND member.provider_id IN (SELECT value FROM json_each(?5)) ORDER BY member.ordinal LIMIT ?4",
            cancellation, visitor, |owner, definition, row| {
                let ordinal: u32 = row.get(0)?;
                let name: String = row.get(1)?;
                let kind: String = row.get(2)?;
                let visibility: String = row.get(3)?;
                let is_static: bool = row.get(4)?;
                let kind = match kind.as_str() { "method"|"function" => ResolutionMemberKind::Method, "constructor" => ResolutionMemberKind::Constructor, "nested_type" => ResolutionMemberKind::NestedType, _ => ResolutionMemberKind::Field };
                let visibility = DeclaredVisibility::from_label(&visibility).ok_or_else(|| invalid_fact(format!("invalid external member visibility {visibility:?}")))?;
                // External member lookup identities use effective namespaces;
                // TypeOrValue is a source-site union and cannot form a lookup recipe.
                let namespaces = [ResolutionNamespace::Callable, ResolutionNamespace::Value, ResolutionNamespace::Constant, ResolutionNamespace::Type, ResolutionNamespace::Type];
                let languages = [Language::Java,Language::Kotlin,Language::Scala];
                let lookups = std::array::from_fn(|i| crate::analyzer::resolution::lookup_semantic(&names,languages[i/5],namespaces[i%5],&name));
                let member = self.context_identities.external_member_semantic(owner, ordinal, &names);
                Ok(SelectedTypedRow::external_member(owner.clone(), ordinal, LoweredMemberOwnerProperty::external(member, definition, name.as_str(), kind,
                    if is_static || kind == ResolutionMemberKind::NestedType { ResolutionMemberAccess::Type } else { ResolutionMemberAccess::Instance },
                    if is_static || kind == ResolutionMemberKind::NestedType { ResolutionMemberQualifierCompatibility::RuntimeOrType } else { ResolutionMemberQualifierCompatibility::RuntimeOnly }, lookups, visibility)))
            })
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
