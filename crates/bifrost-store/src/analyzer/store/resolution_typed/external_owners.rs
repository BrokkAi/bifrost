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
                        .independently_enumerates_jvm_owner(&candidate.record)
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
                    callables_complete: brokk_bifrost_jvm::intrinsics::specified_method_inventory(&owner.owner_fqn).is_some() || (enumerated && row.get::<_, bool>(1)?),
                    values_complete: enumerated && row.get(2)?,
                    types_complete: enumerated && row.get(3)?,
                    supertypes_complete: brokk_bifrost_jvm::intrinsics::specified_method_inventory(&owner.owner_fqn).is_some() || (enumerated && row.get::<_, bool>(4)?),
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

/// Only facts reached by this operation are retained. In particular this is
/// not a provider-wide signature inventory or a workspace-sized type arena.
#[derive(Default)]
pub(super) struct ExternalSignatureMemo {
    inheritance: crate::hash::HashMap<
        SemanticId,
        Option<crate::analyzer::resolution::JavaInheritanceDeclaration>,
    >,
    signatures: crate::hash::HashMap<
        SemanticId,
        Option<SelectedTypedRow<LoweredCallableSignatureProperty>>,
    >,
    seeds: crate::hash::HashMap<SemanticId, SelectedTypedRow<LoweredIntrinsicSeed>>,
    parameter_slots: crate::hash::HashSet<SemanticId>,
    components: crate::hash::HashMap<SemanticId, SelectedTypedRow<LoweredTypeComponent>>,
    descriptors: crate::hash::HashMap<SemanticId, SelectedTypedRow<LoweredIntrinsicTypeDescriptor>>,
    owners: crate::hash::HashMap<String, Option<ExternalOwnerIdentity>>,
}

impl SelectedResolutionTypedSource<'_, '_> {
    fn external_signature_rows<T>(
        &self,
        rows: Vec<T>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, T>,
    ) -> StoreResult<TypedFactReadOutcome> {
        Ok(match Self::page_out(&rows, cancellation, visitor)? {
            PageOutcome::Exhausted => {
                TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
            }
            PageOutcome::Stopped => TypedFactReadOutcome::stopped(ResolutionCompletion::Complete),
            PageOutcome::Cancelled => {
                TypedFactReadOutcome::cancelled(ResolutionCompletion::Complete)
            }
        })
    }

    pub(super) fn visit_external_callable_signatures(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredCallableSignatureProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        use crate::analyzer::resolution::{
            LoweredCallableParameterApplicability, LoweredCallableParameterProperty,
            LoweredCallableResultTypeProperty,
        };
        use crate::analyzer::semantic_model::{Parameter, TypeRef};
        let mut requested = std::collections::BTreeMap::new();
        for &definition in definitions {
            if cancellation.is_cancelled() {
                return cancelled();
            }
            if !self
                .external_signatures
                .borrow()
                .signatures
                .contains_key(&definition)
                && let Some((owner, ordinal)) =
                    self.context_identities.external_member_identity(definition)
            {
                if !self
                    .external_providers
                    .iter()
                    .any(|provider| provider == owner.provider_id.as_ref())
                {
                    continue;
                }
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
        if !requested.is_empty() {
            let coordinates = serde_json::to_string(&requested.keys().collect::<Vec<_>>())
                .map_err(|error| StoreError::new(error.to_string()))?;
            let providers = serde_json::to_string(&self.external_providers)
                .map_err(|error| StoreError::new(error.to_string()))?;
            let rows = self.read_statement(cancellation, |connection| {
                let mut statement = connection.prepare_cached(EXTERNAL_CALLABLE_SIGNATURES_SQL)?;
                let mut cursor = statement.query([coordinates, providers])?;
                let mut rows = Vec::new();
                while let Some(row) = cursor.next()? {
                    if cancellation.is_cancelled() {
                        return Ok(None);
                    }
                    rows.push((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, u32>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                    ));
                }
                Ok(Some(rows))
            })?;
            let Some(rows) = rows else {
                return cancelled();
            };
            let mut decoded = Vec::new();
            let mut type_names = BTreeSet::new();
            for (provider, owner, ordinal, parameters, result) in rows {
                let parameters: Vec<Parameter> =
                    serde_json::from_str(&parameters).map_err(|error| {
                        invalid_fact(format!("external callable parameters: {error}"))
                    })?;
                let result: Option<TypeRef> = result
                    .map(|value| serde_json::from_str(&value))
                    .transpose()
                    .map_err(|error| invalid_fact(format!("external callable result: {error}")))?;
                let mut pending = parameters
                    .iter()
                    .map(|parameter| &parameter.r#type)
                    .chain(result.iter())
                    .collect::<Vec<_>>();
                let mut generic = false;
                while let Some(term) = pending.pop() {
                    if cancellation.is_cancelled() {
                        return cancelled();
                    }
                    match term {
                        TypeRef::Named {
                            name, arguments, ..
                        } => {
                            if brokk_bifrost_jvm::java::primitives::primitive_for_name(name)
                                .is_none()
                            {
                                type_names.insert(name.clone());
                            }
                            pending.extend(arguments);
                        }
                        TypeRef::Declared { arguments, .. } => pending.extend(arguments),
                        TypeRef::TypeParameter { .. } => generic = true,
                        TypeRef::Array { element }
                        | TypeRef::ByRef { element, .. }
                        | TypeRef::Pointer { element }
                        | TypeRef::Slice { element }
                        | TypeRef::FixedArray { element, .. }
                        | TypeRef::Channel { element, .. } => pending.push(element),
                        TypeRef::Map { key, value } => {
                            pending.push(key);
                            pending.push(value);
                        }
                        TypeRef::Wildcard { bound, .. } => pending.extend(bound.as_deref()),
                        TypeRef::Tuple { elements } => pending.extend(elements),
                        TypeRef::Function { parameters, result } => {
                            pending.extend(parameters.iter().map(|parameter| &parameter.r#type));
                            pending.extend(result.as_deref());
                        }
                        // Rust projections have no Java owner or substitution proof.
                        // lower_type_term retains their unsupported type obligation.
                        TypeRef::Projection { .. } | TypeRef::Unknown => {}
                    }
                }
                let coordinate = ExternalOwnerIdentity {
                    provider_id: Arc::from(provider.as_str()),
                    owner_fqn: Arc::from(owner.as_str()),
                };
                let definition = self.context_identities.external_member_semantic(
                    &coordinate,
                    ordinal,
                    &self.selection.shared_names(),
                );
                decoded.push((
                    definition,
                    ExternalOwnerIdentity {
                        provider_id: Arc::from(provider),
                        owner_fqn: Arc::from(owner),
                    },
                    ordinal,
                    parameters,
                    result,
                    generic,
                ));
            }
            let missing = type_names
                .into_iter()
                .filter(|name| !self.external_signatures.borrow().owners.contains_key(name))
                .collect::<Vec<_>>();
            if !missing.is_empty() {
                let names = serde_json::to_string(&missing)
                    .map_err(|error| StoreError::new(error.to_string()))?;
                let providers = serde_json::to_string(&self.external_providers)
                    .map_err(|error| StoreError::new(error.to_string()))?;
                let owners = self.read_statement(cancellation, |connection| {
                    let mut statement =
                        connection.prepare_cached(EXTERNAL_SIGNATURE_TYPE_OWNERS_SQL)?;
                    let mut cursor = statement.query([names, providers])?;
                    let mut owners = Vec::new();
                    while let Some(row) = cursor.next()? {
                        if cancellation.is_cancelled() {
                            return Ok(None);
                        }
                        owners.push((row.get::<_, String>(0)?, row.get::<_, String>(1)?));
                    }
                    Ok(Some(owners))
                })?;
                let Some(owners) = owners else {
                    return cancelled();
                };
                let mut memo = self.external_signatures.borrow_mut();
                for name in missing {
                    memo.owners.insert(name, None);
                }
                let mut grouped = std::collections::BTreeMap::<String, Vec<String>>::new();
                for (name, provider) in owners {
                    grouped.entry(name).or_default().push(provider);
                }
                for (name, providers) in grouped {
                    if let [provider] = providers.as_slice() {
                        memo.owners.insert(
                            name.clone(),
                            Some(ExternalOwnerIdentity {
                                provider_id: Arc::from(provider.as_str()),
                                owner_fqn: Arc::from(name),
                            }),
                        );
                    }
                }
            }
            // Decode the batch before publishing its reached signatures and terms.
            let names = self
                .selection
                .shared_name_table()
                .interner(self.selection.connection());
            let mut memo = self.external_signatures.borrow_mut();
            for definition in requested.values() {
                memo.signatures.insert(*definition, None);
            }
            for (definition, owner, ordinal, parameters, result, generic) in decoded {
                let member = crate::analyzer::resolution::ExternalMemberIdentity {
                    owner: owner.clone(),
                    ordinal,
                };
                let mut next_slot = 0u32;
                let mut properties = Vec::new();
                let mut applicability = Vec::new();
                for (index, parameter) in parameters.iter().enumerate() {
                    let position =
                        u32::try_from(index).expect("external parameter ordinal fits u32");
                    // The shared source contract stores a repeated component,
                    // while JVM declaration packs retain the physical array.
                    let term = match (&parameter.r#type, parameter.variadic) {
                        (TypeRef::Array { element }, true) => element.as_ref(),
                        (term, _) => term,
                    };
                    let Some(slot) = memo.lower_type_term(
                        &member,
                        term,
                        &mut next_slot,
                        &names,
                        &self.context_identities,
                        cancellation,
                    ) else {
                        return cancelled();
                    };
                    // A source formal carries its value type, rather than a
                    // type qualifier. Preserve the same category for external
                    // formals so ordinary applicability can compare them.
                    let seed = memo.seeds.get(&slot).expect("lowered parameter has a seed");
                    let row = seed.row();
                    let frontier = crate::analyzer::resolution::TypedFrontierState::new(
                        slot,
                        row.frontier()
                            .possible_values()
                            .iter()
                            .map(|value| {
                                crate::analyzer::resolution::ResolutionSlotValue::runtime(
                                    value.ty(),
                                    false,
                                )
                            })
                            .collect::<Vec<_>>(),
                        row.frontier().completion().clone(),
                    );
                    let seed = seed.with_row(LoweredIntrinsicSeed::new(
                        row.kind(),
                        row.spelling(),
                        frontier,
                    ));
                    memo.seeds.insert(slot, seed);
                    memo.parameter_slots.insert(slot);
                    properties.push(LoweredCallableParameterProperty::new(
                        position,
                        slot,
                        slot,
                        parameter.variadic,
                    ));
                    applicability.push(LoweredCallableParameterApplicability::new(
                        position,
                        0,
                        parameter.name.as_deref().map(Into::into),
                        parameter.optional,
                        parameter.passing_mode.accepts_positional(),
                    ));
                }
                let mut result_types = Vec::new();
                if let Some(term) = result.as_ref() {
                    let Some(slot) = memo.lower_type_term(
                        &member,
                        term,
                        &mut next_slot,
                        &names,
                        &self.context_identities,
                        cancellation,
                    ) else {
                        return cancelled();
                    };
                    result_types.push(LoweredCallableResultTypeProperty::new(0, slot));
                }
                let completion = if generic {
                    // No erased signature or unconstrained inference is a proof
                    // of an exact substitution for an external type variable.
                    let mut hash =
                        brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(
                            b"bifrost-jvm-external-generic-signature-obligation:v1",
                        );
                    hash.field("provider", owner.provider_id.as_bytes());
                    hash.field("owner", owner.owner_fqn.as_bytes());
                    hash.field("member", &ordinal.to_be_bytes());
                    let reason = self.context_identities.named_semantic(
                        hash.finish(),
                        "UnsupportedExternalSignatureTypeVariable",
                        "The external declaration has an unproven type-variable substitution",
                    );
                    ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(reason),
                    ])
                } else {
                    ResolutionCompletion::Complete
                };
                let signature =
                    LoweredCallableSignatureProperty::new(definition, 0, properties, completion)
                        .with_result_types(result_types)
                        .with_applicability_shape(
                            vec![0].into_boxed_slice(),
                            applicability.into_boxed_slice(),
                            None,
                        );
                memo.signatures.insert(
                    definition,
                    Some(SelectedTypedRow::external_member(owner, ordinal, signature)),
                );
            }
        }
        let memo = self.external_signatures.borrow();
        let rows = definitions
            .iter()
            .filter_map(|definition| memo.signatures.get(definition).and_then(Clone::clone))
            .collect();
        self.external_signature_rows(rows, cancellation, visitor)
    }

    pub(super) fn visit_external_type_frontiers(
        &self,
        slots: &[SemanticId],
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypedFrontier>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let memo = self.external_signatures.borrow();
        let rows = slots.iter().filter_map(|slot| memo.seeds.get(slot).map(|seed| {
            let role = if memo.parameter_slots.contains(slot) {
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeSlotRole::ExpressionValue
                    } else {
                        brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeSlotRole::TargetTypeIdentity
                    };
            seed.with_row(LoweredTypedFrontier::new(*slot, role))
        })).collect();
        self.external_signature_rows(rows, cancellation, visitor)
    }

    pub(super) fn visit_external_type_seeds(
        &self,
        slots: &[SemanticId],
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredIntrinsicSeed>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let memo = self.external_signatures.borrow();
        self.external_signature_rows(
            slots
                .iter()
                .filter_map(|slot| memo.seeds.get(slot).cloned())
                .collect(),
            cancellation,
            visitor,
        )
    }

    pub(super) fn visit_external_type_components(
        &self,
        containers: &[SemanticId],
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypeComponent>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let memo = self.external_signatures.borrow();
        self.external_signature_rows(
            containers
                .iter()
                .filter_map(|slot| memo.components.get(slot).cloned())
                .collect(),
            cancellation,
            visitor,
        )
    }

    pub(super) fn visit_external_type_descriptors(
        &self,
        identities: &[SemanticId],
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredIntrinsicTypeDescriptor>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        use brokk_bifrost_core::analyzer::resolution_facts::IntrinsicTypeKind;
        let memo = self.external_signatures.borrow();
        // Nominal spelling is already part of a selected external identity.
        // Read it independently of signature discovery: the session can ask
        // for a type descriptor before it asks for any callable signatures.
        // This supplies no member or callable declaration for name-only owners.
        let rows = identities
            .iter()
            .filter_map(|&identity| {
                memo.descriptors.get(&identity).cloned().or_else(|| {
                    let owner = self.context_identities.external_owner_identity(identity)?;
                    Some(SelectedTypedRow::external_owner(
                        owner.clone(),
                        LoweredIntrinsicTypeDescriptor::new(
                            identity,
                            IntrinsicTypeKind::LanguageBuiltin,
                            owner.owner_fqn.as_ref(),
                        ),
                    ))
                })
            })
            .collect();
        self.external_signature_rows(rows, cancellation, visitor)
    }
}

pub(in crate::analyzer::store) const EXTERNAL_CALLABLE_SIGNATURES_SQL: &str = r#"
WITH requested AS (
    SELECT json_extract(value,'$[0]') provider_id,
           json_extract(value,'$[1]') owner_fqn,
           json_extract(value,'$[2]') ordinal
    FROM json_each(?1)
)
SELECT DISTINCT member.provider_id,member.owner_fqn,member.ordinal,
       json(member.parameters_jsonb),json(member.return_type_jsonb)
FROM requested
JOIN jvm_external_owner_members selected USING(provider_id,owner_fqn,ordinal)
JOIN jvm_external_owner_members member
  ON member.provider_id=selected.provider_id AND member.owner_fqn=selected.owner_fqn
 AND member.member_name=selected.member_name AND member.member_kind=selected.member_kind
WHERE member.signature_present=1 AND member.member_kind IN ('method','function','constructor')
  AND member.provider_id IN (SELECT value FROM json_each(?2))
ORDER BY member.provider_id,member.owner_fqn,member.ordinal
"#;

pub(in crate::analyzer::store) const EXTERNAL_SIGNATURE_TYPE_OWNERS_SQL: &str = r#"
SELECT owner_fqn,provider_id
FROM json_each(?1) requested
JOIN jvm_external_owners owner ON owner.owner_fqn=requested.value
WHERE provider_id IN (SELECT value FROM json_each(?2))
ORDER BY owner_fqn,provider_id
"#;

impl ExternalSignatureMemo {
    /// Lower the structured declaration term without parsing display text or
    /// erasing a generic variable to its bound. The explicit postorder stack
    /// also keeps deeply nested array signatures off the Rust call stack.
    fn lower_type_term(
        &mut self,
        member: &crate::analyzer::resolution::ExternalMemberIdentity,
        term: &crate::analyzer::semantic_model::TypeRef,
        next_slot: &mut u32,
        names: &dyn SharedNameInterner,
        identities: &crate::analyzer::resolution::SelectedContextIdentities,
        cancellation: &CancellationToken,
    ) -> Option<SemanticId> {
        use crate::analyzer::resolution::{
            ResolutionSlotValue, ResolutionTypeRef, TypedFrontierState,
        };
        use crate::analyzer::semantic_model::TypeRef;
        use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
        use brokk_bifrost_core::analyzer::resolution_facts::{
            IntrinsicTypeKind, ResolutionTypeComponentKind, ResolutionTypeConstructorKind,
        };
        let owner = &member.owner;
        let member_ordinal = member.ordinal;
        let mut allocate = || {
            let mut hash = CanonicalHasher::new(b"bifrost-jvm-external-signature-slot:v1");
            hash.field("provider", owner.provider_id.as_bytes());
            hash.field("owner", owner.owner_fqn.as_bytes());
            hash.field("member", &member_ordinal.to_be_bytes());
            hash.field("slot", &next_slot.to_be_bytes());
            *next_slot = next_slot
                .checked_add(1)
                .expect("external signature slots fit u32");
            let digest = hash.finish();
            (SemanticId::shared_name(names.intern(digest)), digest)
        };
        let root = allocate();
        let mut pending = vec![(term, root, None)];
        while let Some((term, (slot, digest), component)) = pending.pop() {
            if cancellation.is_cancelled() {
                return None;
            }
            if let Some(element) = component {
                let child = self
                    .seeds
                    .get(&element)
                    .expect("external array component was lowered first");
                let completion = child.row().frontier().completion().clone();
                self.components.insert(
                    slot,
                    SelectedTypedRow::external_member(
                        owner.clone(),
                        member_ordinal,
                        LoweredTypeComponent::new(
                            slot,
                            ResolutionTypeConstructorKind::Sequence,
                            ResolutionTypeComponentKind::Element,
                            element,
                        ),
                    ),
                );
                self.seeds.insert(
                    slot,
                    SelectedTypedRow::external_member(
                        owner.clone(),
                        member_ordinal,
                        LoweredIntrinsicSeed::new(
                            IntrinsicTypeKind::Structural,
                            "structural-type",
                            TypedFrontierState::new(
                                slot,
                                vec![ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                                    slot, 0,
                                ))],
                                completion,
                            ),
                        ),
                    ),
                );
                continue;
            }
            if let TypeRef::Array { element } = term {
                let child = allocate();
                pending.push((term, (slot, digest), Some(child.0)));
                pending.push((element, child, None));
                continue;
            }
            let known = if let TypeRef::Named { name, .. } = term {
                if brokk_bifrost_jvm::java::primitives::primitive_for_name(name).is_some() {
                    let digest =
                        crate::analyzer::resolution::universe::intrinsic_type_identity_digest(
                            Language::Java,
                            IntrinsicTypeKind::Primitive,
                            name,
                        );
                    Some((
                        SemanticId::shared_name(names.intern(digest)),
                        IntrinsicTypeKind::Primitive,
                        name.as_str(),
                    ))
                } else {
                    self.owners.get(name).and_then(Option::as_ref).map(|owner| {
                        (
                            identities.external_owner_semantic(owner, names),
                            IntrinsicTypeKind::LanguageBuiltin,
                            name.as_str(),
                        )
                    })
                }
            } else {
                None
            };
            let incomplete_type = || {
                let reason = identities.named_semantic(
                    digest,
                    "UnsupportedExternalSignatureType",
                    "The external declaration type term has no proven exact native substitution",
                );
                ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                    reason,
                )])
            };
            let (kind, spelling, values, completion) = if let Some((identity, kind, spelling)) =
                known
            {
                self.descriptors.insert(
                    identity,
                    SelectedTypedRow::external_member(
                        owner.clone(),
                        member_ordinal,
                        LoweredIntrinsicTypeDescriptor::new(identity, kind, spelling),
                    ),
                );
                (
                    kind,
                    spelling,
                    vec![ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                        identity, 0,
                    ))],
                    if matches!(term, TypeRef::Named { arguments, nullable, .. } if !arguments.is_empty() || *nullable)
                    {
                        incomplete_type()
                    } else {
                        ResolutionCompletion::Complete
                    },
                )
            } else {
                (
                    IntrinsicTypeKind::Structural,
                    "unknown-external-type",
                    Vec::new(),
                    incomplete_type(),
                )
            };
            self.seeds.insert(
                slot,
                SelectedTypedRow::external_member(
                    owner.clone(),
                    member_ordinal,
                    LoweredIntrinsicSeed::new(
                        kind,
                        spelling,
                        TypedFrontierState::new(slot, values, completion),
                    ),
                ),
            );
        }
        Some(root.0)
    }
}

impl SelectedResolutionTypedSource<'_, '_> {
    pub(super) fn external_inheritance_declarations(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<crate::analyzer::resolution::JavaInheritanceDeclaration>>> {
        use crate::analyzer::resolution::fact_source::JvmDeclarationPackage;
        use crate::analyzer::resolution::{
            JavaInheritanceDeclaration, JavaInheritanceDeclarationKind,
        };
        let mut requested = std::collections::BTreeMap::new();
        for &definition in definitions {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            if !self
                .external_signatures
                .borrow()
                .inheritance
                .contains_key(&definition)
                && let Some((owner, ordinal)) =
                    self.context_identities.external_member_identity(definition)
            {
                if !self
                    .external_providers
                    .iter()
                    .any(|provider| provider == owner.provider_id.as_ref())
                {
                    continue;
                }
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
        if !requested.is_empty() {
            let coordinates = serde_json::to_string(&requested.keys().collect::<Vec<_>>())
                .map_err(|error| StoreError::new(error.to_string()))?;
            let providers = serde_json::to_string(&self.external_providers)
                .map_err(|error| StoreError::new(error.to_string()))?;
            let rows = self.read_statement(cancellation, |connection| {
                let mut statement =
                    connection.prepare_cached(EXTERNAL_INHERITANCE_DECLARATIONS_SQL)?;
                let mut cursor = statement.query([coordinates, providers])?;
                let mut rows = Vec::new();
                while let Some(row) = cursor.next()? {
                    if cancellation.is_cancelled() {
                        return Ok(None);
                    }
                    let coordinate = (
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, u32>(2)?,
                    );
                    let visibility: String = row.get(5)?;
                    rows.push(JavaInheritanceDeclaration {
                        definition: requested[&coordinate],
                        name: row.get(3)?,
                        package: JvmDeclarationPackage::Unknown,
                        kind: JavaInheritanceDeclarationKind::Method {
                            is_static: row.get(4)?,
                            is_abstract: None,
                            visibility: decode_external_member_visibility(&visibility)?,
                        },
                    });
                }
                Ok(Some(rows))
            })?;
            let Some(rows) = rows else {
                return Ok(None);
            };
            let mut memo = self.external_signatures.borrow_mut();
            for definition in requested.values() {
                memo.inheritance.insert(*definition, None);
            }
            for row in rows {
                memo.inheritance.insert(row.definition, Some(row));
            }
        }
        let memo = self.external_signatures.borrow();
        Ok(Some(
            definitions
                .iter()
                .filter_map(|definition| memo.inheritance.get(definition).and_then(Clone::clone))
                .collect(),
        ))
    }
}

pub(in crate::analyzer::store) const EXTERNAL_INHERITANCE_DECLARATIONS_SQL: &str = r#"
WITH requested AS (
    SELECT json_extract(value,'$[0]') provider_id,
           json_extract(value,'$[1]') owner_fqn,
           json_extract(value,'$[2]') ordinal
    FROM json_each(?1)
)
SELECT member.provider_id,member.owner_fqn,member.ordinal,member.member_name,
       member.is_static,member.visibility
FROM requested JOIN jvm_external_owner_members member USING(provider_id,owner_fqn,ordinal)
WHERE member.member_kind='method'
  AND member.provider_id IN (SELECT value FROM json_each(?2))
ORDER BY member.provider_id,member.owner_fqn,member.ordinal
"#;

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
