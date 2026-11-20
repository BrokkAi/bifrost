//! Durable external inventories selected by the request's exact provider identities.
use super::super::resolution_operation::nominal_rules::{
    ExternalOwnerRelations, jvm_external_owner_relations,
};
use super::*;
use crate::analyzer::resolution::ExternalOwnerIdentity;
use crate::analyzer::store::AnalyzerStore;
use brokk_bifrost_core::analyzer::resolution_facts::{
    DeclarationTypeRole, ResolutionMemberAccess, ResolutionMemberKind,
    ResolutionMemberQualifierCompatibility, ResolutionNamespace,
};
use std::sync::Arc;

pub(in crate::analyzer::store) const EXTERNAL_MEMBER_OWNER_BY_DEFINITION_SQL: &str = "SELECT member.ordinal,member.member_name,member.member_kind,member.visibility,member.is_static,CASE WHEN member.member_kind IN ('method','function') AND member.is_static=0 AND member.signature_present=1 AND json_array_length(member.parameters_jsonb)=0 AND member.return_type_jsonb IS NOT NULL AND NOT (json_extract(member.return_type_jsonb,'$.kind')='named' AND json_extract(member.return_type_jsonb,'$.name')='void') THEN 1 ELSE 0 END FROM jvm_external_owner_members member JOIN jvm_external_owners inventory USING(provider_id,owner_fqn) WHERE member.provider_id=?1 AND member.owner_fqn=?2 AND member.ordinal=?3 AND member.provider_id IN (SELECT value FROM json_each(?4))";

pub(in crate::analyzer::store) const INTRINSIC_MEMBER_OWNER_INDEXED_SQL: &str =
    "SELECT EXISTS(SELECT 1 FROM jvm_external_owners WHERE provider_id=?1 AND owner_fqn=?2)";

pub(in crate::analyzer::store) fn intrinsic_member_inventory_for_owner(
    connection: &rusqlite::Connection,
    owner: &ExternalOwnerIdentity,
    generation: i64,
) -> StoreResult<Option<&'static [crate::analyzer::resolution::universe::IntrinsicMember]>> {
    let Some(inventory) =
        crate::analyzer::resolution::universe::intrinsic_member_inventory(&owner.owner_fqn)
    else {
        return Ok(None);
    };
    let (indexed, current) = intrinsic_member_owner_indexed(connection, owner, generation)?;
    if !current && owner.provider_id.as_ref() != "jvm-intrinsic" {
        return Err(StoreError::stale_resolution(
            "JVM provider inventory changed during the request",
        ));
    }
    Ok((!indexed).then_some(inventory))
}

fn intrinsic_member_owner_indexed(
    connection: &rusqlite::Connection,
    owner: &ExternalOwnerIdentity,
    generation: i64,
) -> StoreResult<(bool, bool)> {
    let guarded = super::super::jvm_external_publication::jvm_inventory_guarded_sql(
        jvm_external_owner_relations().owner_indexed,
        3,
    );
    Ok(connection.query_row(
        &guarded,
        rusqlite::params![
            owner.provider_id.as_ref(),
            owner.owner_fqn.as_ref(),
            generation
        ],
        |row| Ok((row.get(0)?, row.get(2)?)),
    )?)
}

struct ExternalOwnerScopes {
    callables_complete: bool,
    values_complete: bool,
    types_complete: bool,
    supertypes_complete: bool,
}

fn decode_external_owner_scopes(
    owner: &ExternalOwnerIdentity,
    row: &Row<'_>,
    enumerated: bool,
) -> StoreResult<ExternalOwnerScopes> {
    // Intrinsic specified inventories establish callable and supertype completeness.
    let specified_inventory =
        brokk_bifrost_jvm::intrinsics::specified_method_inventory(&owner.owner_fqn).is_some();
    Ok(ExternalOwnerScopes {
        callables_complete: specified_inventory || (enumerated && row.get(1)?),
        values_complete: enumerated && row.get(2)?,
        types_complete: enumerated && row.get(3)?,
        supertypes_complete: specified_inventory || (enumerated && row.get(4)?),
    })
}

fn decode_external_member_visibility(label: &str) -> StoreResult<DeclaredVisibility> {
    DeclaredVisibility::from_label(label)
        .ok_or_else(|| invalid_fact(format!("invalid external member visibility {label:?}")))
}

impl SelectedResolutionTypedSource<'_, '_> {
    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
    pub(super) fn external_inventory_generation(&self) -> StoreResult<i64> {
        let reader = if let Some(models) = &self.external_models {
            super::super::jvm_external_publication::request_jvm_inventory_reader(models)
                .map_err(|open| StoreError::new(open.reason))?
        } else {
            None
        };
        let captured = reader
            .as_ref()
            .and_then(|reader| reader.inventory_generation);
        let shared = self.external_inventory_generation.as_ref().or_else(|| {
            reader
                .as_ref()
                .and_then(|reader| reader.inventory_clock.as_ref())
        });
        let clock = match shared {
            Some(clock) => clock.snapshot(),
            None => super::super::jvm_external_publication::JvmInventoryRequestClock::captured(
                match captured {
                    Some(generation) => generation,
                    // Proof preparation shares the selected provider snapshot, never an independent reader.
                    None => AnalyzerStore::jvm_external_inventory_generation_in_snapshot(
                        self.selection.connection(),
                    )?,
                },
            ),
        }
        .with_source_generation(captured);
        Ok(clock.generation())
    }

    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
    fn validate_external_signature_memo(&self) -> StoreResult<()> {
        if let Some(proof) = self.external_signature_memo_proof.get() {
            proof.validate_cached(self.selection.connection())?;
        }
        Ok(())
    }

    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
    fn capture_external_signature_memo_proof(&self) -> StoreResult<()> {
        if self.external_signature_memo_proof.get().is_none() {
            let proof = super::super::jvm_external_publication::JvmInventoryMemoProof::capture(
                self.selection.connection(),
                &self.external_providers,
                self.external_inventory_generation()?,
            )?;
            self.external_signature_memo_proof.set(Some(proof));
        }
        Ok(())
    }

    fn external_inventory_unavailable(&self) -> TypedFactReadOutcome {
        use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
        let reason = self.context_identities.named_semantic(
            CanonicalHasher::new(b"jvm-provider-inventory-changed:v1").finish(),
            "JVMProviderPublicationUnavailable",
            crate::analyzer::resolution::ReasonDeterminism::Unaudited,
            "JVM provider inventory changed during the request",
        );
        TypedFactReadOutcome::exhausted(ResolutionCompletion::incomplete([
            ResolutionIncompleteReason::UnsupportedSemantic(reason),
        ]))
    }

    fn external_owner_adapter(
        &self,
        owner: &ExternalOwnerIdentity,
    ) -> Option<&'static ExternalOwnerRelations> {
        self.is_jvm_external_provider(&owner.provider_id)
            .then(jvm_external_owner_relations)
    }

    pub(super) fn external_argument_proof_reasons(
        &self,
        definitions: &[SemanticId],
        receiver_reasons: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<SemanticId>>> {
        self.validate_external_signature_memo()?;
        // This exemption still requires Java's exact argument-conversion proof.
        // TypeParameter (also nested) is nonground: see java_known_ground_type,
        // crates/bifrost-jvm-analysis/src/analyzer/jvm/external.rs:4337.
        // crates/bifrost-jvm/src/java/conversion.rs:74-75 returns Unknown for a
        // nonground formal, so List.add(E) cannot satisfy the bridge. A variable
        // only in the result does not participate in argument conversion.
        let memo = self.external_signatures.borrow();
        let mut reasons = Vec::new();
        for &reason in receiver_reasons {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            // Class (i)'s sole exception: this registered known nominal head
            // does not require its unknown arguments to select this member.
            if memo.nominal_argument_reasons.contains(&reason) {
                reasons.push(reason);
            }
        }
        for definition in definitions {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            // Class (ii) for the binding only: a proven argument conversion
            // does not depend on a variable that occurs solely in the result.
            // Its original result-type obligation remains unchanged.
            // A repeated call to the same declaration can inherit this same
            // registered identity from its receiver. That inner result remains
            // open even when it is also this call's own result obligation (#7667).
            if let Some(&reason) = memo.result_only_generic_reasons.get(definition)
                && !receiver_reasons.contains(&reason)
            {
                reasons.push(reason);
            }
            // Class (ii) for the binding only: a formal with a known nominal
            // head and unproven type arguments, such as ProcessBuilder's
            // List<String>, leaves applicability open. Java's conversion
            // prover compares every actual with that declared formal (a type
            // parameter in it returns Unknown), so its proof closes the
            // applicability this identity holds open (#9532).
            if let Some(formal) = memo.formal_nominal_argument_reasons.get(definition) {
                reasons.extend(formal.iter().copied());
            }
        }
        Ok(Some(reasons))
    }

    pub(super) fn external_receiver_argument_reasons(
        &self,
        definitions: &[SemanticId],
        reasons: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<SemanticId>>> {
        self.validate_external_signature_memo()?;
        let memo = self.external_signatures.borrow();
        let independent = !definitions.is_empty()
            && definitions.iter().all(|definition| {
                memo.signatures
                    .get(definition)
                    .and_then(Option::as_ref)
                    .is_some_and(|signature| {
                        signature.row().completion() == &ResolutionCompletion::Complete
                    })
            });
        let mut selected = Vec::new();
        for &reason in reasons {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            if independent && memo.nominal_argument_reasons.contains(&reason) {
                selected.push(reason);
            }
        }
        Ok(Some(selected))
    }

    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
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
                if self.external_owner_adapter(&owner).is_none() {
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
        if requested.is_empty() {
            return Ok(Some(Vec::new()));
        }
        let coordinates = requested.keys().collect::<Vec<_>>();
        let coordinates = serde_json::to_string(&coordinates)
            .map_err(|error| StoreError::new(error.to_string()))?;
        let providers = serde_json::to_string(&self.external_providers)
            .map_err(|error| StoreError::new(error.to_string()))?;
        let rows = self.read_statement(cancellation, |conn| {
            let mut statement =
                conn.prepare_cached(jvm_external_owner_relations().callable_result_owners)?;
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
        if self.external_owner_adapter(owner).is_none() {
            return Ok(Some(None));
        }
        let generation = self.external_inventory_generation()?;
        self.read_statement(cancellation, |connection| {
            let Some(inventory) =
                crate::analyzer::resolution::universe::intrinsic_member_inventory(&owner.owner_fqn)
            else {
                return Ok(Some(None));
            };
            // Preserve the inventory read's own publication check, and make
            // its exact answer available to the root shadow check.
            let (indexed, current) = intrinsic_member_owner_indexed(connection, owner, generation)?;
            if !current && owner.provider_id.as_ref() != "jvm-intrinsic" {
                // Do not turn an evicted indexed owner into an intrinsic fallback.
                // The guarded relation readers carry the unavailable completion.
                return Ok(Some(None));
            }
            self.intrinsic_owner_indexed.borrow_mut().insert_bounded(
                (owner.provider_id.to_string(), owner.owner_fqn.to_string()),
                indexed,
            );
            Ok(Some((!indexed).then_some(inventory)))
        })
    }

    fn visit_external_rows<T>(
        &self,
        definitions: &[SemanticId],
        sql: fn(&ExternalOwnerRelations) -> &'static str,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, T>,
        decode: impl Fn(&ExternalOwnerIdentity, SemanticId, &Row<'_>) -> StoreResult<T>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let generation = self.external_inventory_generation()?;
        let providers = serde_json::to_string(&self.external_providers)
            .map_err(|error| StoreError::new(error.to_string()))?;
        for &definition in definitions {
            let Some(owner) = self.context_identities.external_owner_identity(definition) else {
                continue;
            };
            let Some(adapter) = self.external_owner_adapter(&owner) else {
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
                    let guarded = super::super::jvm_external_publication::jvm_inventory_guarded_sql(
                        sql(adapter),
                        6,
                    );
                    let mut statement = conn.prepare_cached(&guarded)?;
                    let guard_column = statement.column_count() - 1;
                    let mut rows = statement.query(rusqlite::params![
                        owner.provider_id.as_ref(),
                        owner.owner_fqn.as_ref(),
                        cursor,
                        visitor.maximum_rows() as i64,
                        providers,
                        generation
                    ])?;
                    let mut page = Vec::new();
                    while let Some(row) = rows.next()? {
                        if !row.get::<_, bool>(guard_column)? {
                            return Ok(Some((page, false)));
                        }
                        if row.get::<_, Option<i64>>(0)?.is_none() {
                            break;
                        }
                        if cancellation.is_cancelled() {
                            break;
                        }
                        cursor = row.get(0)?;
                        page.push(decode(&owner, definition, row)?);
                    }
                    Ok(Some((page, true)))
                })?
                else {
                    return cancelled();
                };
                if cancellation.is_cancelled() {
                    return cancelled();
                }
                let (page, current) = page;
                if !current {
                    return Ok(self.external_inventory_unavailable());
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

    pub(in crate::analyzer::store) fn external_owner_type_is_indexed(
        &self,
        owner: &ExternalOwnerIdentity,
    ) -> StoreResult<bool> {
        self.external_owner_type_is_indexed_with_memo_proof(owner)
            .map(super::super::jvm_external_publication::JvmInventoryMemoValue::into_value)
    }

    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
    pub(in crate::analyzer::store) fn external_owner_type_is_indexed_with_memo_proof(
        &self,
        owner: &ExternalOwnerIdentity,
    ) -> StoreResult<super::super::jvm_external_publication::JvmInventoryMemoValue<bool>> {
        use super::super::jvm_external_publication::{
            JvmInventoryMemoProof, JvmInventoryMemoValue,
        };
        // Only a selected inventory provider can close an owner, and the
        // scope query is restricted to those providers. Answer without a
        // read for every other destination, which is every destination when
        // no JVM inventory is selected.
        if !self.is_jvm_external_provider(&owner.provider_id)
            || !self
                .external_providers
                .iter()
                .any(|provider| provider == owner.provider_id.as_ref())
            || !self.external_owner_family_is_enumerated(owner)
        {
            return Ok(JvmInventoryMemoValue::new(
                false,
                JvmInventoryMemoProof::Immutable,
            ));
        }
        let providers = serde_json::to_string(&self.external_providers)
            .map_err(|error| StoreError::new(error.to_string()))?;
        let generation = self.external_inventory_generation()?;
        let guarded = super::super::jvm_external_publication::jvm_inventory_guarded_memo_sql(
            jvm_external_owner_relations().owner_scopes,
            6,
            7,
            8,
        );
        let mut statement = self.selection.connection().prepare_cached(&guarded)?;
        let mut rows = statement.query(rusqlite::params![
            owner.provider_id.as_ref(),
            owner.owner_fqn.as_ref(),
            -1,
            1,
            providers,
            generation,
            serde_json::to_string(&[owner.provider_id.as_ref()])
                .expect("provider identity serializes"),
            super::super::jvm_external_publication::jvm_external_projection_identity()
        ])?;
        let row = rows
            .next()?
            .expect("the generation guard always returns a row");
        if !row.get::<_, bool>(6)? {
            return Err(StoreError::stale_resolution(
                "JVM provider inventory changed during the request",
            ));
        }
        let proof = JvmInventoryMemoProof::from_sealed(row.get(7)?, generation);
        if row.get::<_, Option<i64>>(0)?.is_none() {
            return Ok(JvmInventoryMemoValue::new(false, proof));
        }
        let scopes = decode_external_owner_scopes(owner, row, true)?;
        Ok(JvmInventoryMemoValue::new(
            scopes.types_complete && scopes.supertypes_complete,
            proof,
        ))
    }

    /// The model-declared counterpart of `external_owner_has_no_static_value`:
    /// `None` when no active model declares `fqn`. Otherwise every type of the
    /// supertype closure must carry a positive `jvm_inventory` claim for its
    /// static values and supertypes from a shard that independently enumerates
    /// it (the authority `external_owner_family_is_enumerated` applies), and none may declare a static value named `name`.
    pub(in crate::analyzer::store) fn model_owner_has_no_static_value(
        &self,
        fqn: &str,
        name: &str,
    ) -> Option<bool> {
        use crate::analyzer::semantic_model::{MemberKind, TypeRef};
        let models = self.external_models.as_ref()?;
        if models.types_named(fqn).records.is_empty() {
            return None;
        }
        let mut seen = std::collections::HashSet::new();
        let mut pending = vec![fqn.to_owned()];
        while let Some(owner) = pending.pop() {
            if owner == "java.lang.Object" || !seen.insert(owner.clone()) {
                continue;
            }
            let types = models.types_named(&owner);
            // Only a record's own positive inventory claim, from a shard with
            // enumeration authority, closes the owner's static values and
            // supertypes; absence of either is unknown.
            if types.records.is_empty()
                || !types.records.iter().any(|candidate| {
                    candidate
                        .shard
                        .independently_enumerates_jvm_owner(&candidate.record)
                        && candidate
                            .record
                            .jvm_inventory
                            .as_ref()
                            .is_some_and(|inventory| {
                                inventory.values_complete && inventory.supertypes_complete
                            })
                })
            {
                return Some(false);
            }
            if models
                .members_named(&owner, name)
                .records
                .iter()
                .any(|member| {
                    member.record.is_static
                        && matches!(
                            member.record.member_kind,
                            MemberKind::Field
                                | MemberKind::Property
                                | MemberKind::Constant
                                | MemberKind::Static
                        )
                })
            {
                return Some(false);
            }
            for candidate in &types.records {
                if candidate
                    .record
                    .jvm_inventory
                    .as_ref()
                    .is_some_and(|inventory| {
                        inventory.additional_members.iter().any(|member| {
                            member.name == name
                                && member.is_static
                                && matches!(
                                    member.member_kind,
                                    MemberKind::Field
                                        | MemberKind::Property
                                        | MemberKind::Constant
                                        | MemberKind::Static
                                )
                        })
                    })
                {
                    return Some(false);
                }
                for edge in &candidate.record.hierarchy {
                    match &edge.target {
                        TypeRef::Named { name, .. } => pending.push(name.clone()),
                        _ => return Some(false),
                    }
                }
            }
        }
        Some(true)
    }

    /// Whether this owner's static values are enumerated completely, through
    /// every supertype, and none is named `name` (JLS 7.5.4 imports inherited
    /// static members too). False means a static import of this owner may supply
    /// a field `name`: the owner or a supertype is not enumerated, or declares
    /// one. `java.lang.Object` has no static member and needs no inventory.
    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
    pub(in crate::analyzer::store) fn external_owner_has_no_static_value(
        &self,
        owner: &ExternalOwnerIdentity,
        name: &str,
    ) -> StoreResult<bool> {
        if !self.is_jvm_external_provider(&owner.provider_id)
            || !self
                .external_providers
                .iter()
                .any(|provider| provider == owner.provider_id.as_ref())
            || !self.external_owner_family_is_enumerated(owner)
        {
            return Ok(false);
        }
        let providers = serde_json::to_string(&self.external_providers)
            .map_err(|error| StoreError::new(error.to_string()))?;
        let mut statement = self.selection.connection().prepare_cached(
            "WITH RECURSIVE closure(owner_fqn) AS (\
                SELECT ?1 \
                UNION \
                SELECT edge.supertype_fqn FROM jvm_external_owner_supertypes edge \
                JOIN closure ON edge.owner_fqn=closure.owner_fqn \
                WHERE edge.provider_id IN (SELECT value FROM json_each(?3)) \
                  AND edge.supertype_fqn<>'java.lang.Object') \
             SELECT NOT EXISTS(SELECT 1 FROM closure WHERE NOT EXISTS(\
                        SELECT 1 FROM jvm_external_owners inventory \
                        WHERE inventory.owner_fqn=closure.owner_fqn \
                          AND inventory.values_complete=1 AND inventory.supertypes_complete=1 \
                          AND inventory.provider_id IN (SELECT value FROM json_each(?3)))) \
                AND NOT EXISTS(SELECT 1 FROM jvm_external_owner_members member \
                        JOIN closure ON member.owner_fqn=closure.owner_fqn \
                        WHERE member.provider_id IN (SELECT value FROM json_each(?3)) \
                          AND member.member_name=?2 AND member.is_static=1 \
                          AND member.member_kind IN ('field','property','constant','static'))",
        )?;
        Ok(statement.query_row(
            rusqlite::params![owner.owner_fqn.as_ref(), name, providers],
            |row| row.get(0),
        )?)
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
            .any(|shard| shard.inventory_provider_id() == owner.provider_id.as_ref())
        {
            return true;
        }
        models
            .types_named(&owner.owner_fqn)
            .records
            .iter()
            .any(|candidate| {
                candidate.shard.inventory_provider_id() == owner.provider_id.as_ref()
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
            if self.external_owner_adapter(&owner).is_none() {
                continue;
            }
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
        self.visit_external_rows(
            definitions,
            |adapter| adapter.owner_scopes,
            cancellation,
            visitor,
            |owner, definition, row| {
                let enumerated = self.external_owner_family_is_enumerated(owner);
                let scopes = decode_external_owner_scopes(owner, row, enumerated)?;
                Ok(SelectedTypedRow::external_owner(
                    owner.clone(),
                    LoweredMemberScopeProperty::external(
                        definition,
                        crate::analyzer::resolution::ExternalMemberCoverage {
                            callables_complete: scopes.callables_complete,
                            values_complete: scopes.values_complete,
                            types_complete: scopes.types_complete,
                            supertypes_complete: scopes.supertypes_complete,
                            member_names_only: false,
                        },
                    ),
                ))
            },
        )
    }

    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
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
            if self.external_owner_adapter(&owner).is_none() {
                continue;
            }
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
        self.visit_external_rows(
            definitions,
            |adapter| adapter.members,
            cancellation,
            visitor,
            |owner, definition, row| {
                self.decode_external_member_owner(owner, definition, row, &names)
            },
        )
    }

    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
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
        let generation = self.external_inventory_generation()?;
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
            let Some(adapter) = self.external_owner_adapter(&owner) else {
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
            let Some((row, current)) = self.read_statement(cancellation, |conn| {
                let guarded = super::super::jvm_external_publication::jvm_inventory_guarded_sql(
                    adapter.member_by_definition,
                    5,
                );
                let mut statement = conn.prepare_cached(&guarded)?;
                let guard_column = statement.column_count() - 1;
                let mut rows = statement.query(rusqlite::params![
                    owner.provider_id.as_ref(),
                    owner.owner_fqn.as_ref(),
                    ordinal,
                    providers,
                    generation
                ])?;
                let row = rows
                    .next()?
                    .expect("guarded query always returns its proof row");
                if !row.get::<_, bool>(guard_column)? {
                    return Ok(Some((None, false)));
                }
                if row.get::<_, Option<u32>>(0)?.is_none() {
                    return Ok(Some((None, true)));
                }
                Ok(Some((
                    Some(self.decode_external_member_owner(
                        &owner,
                        owner_definition,
                        row,
                        &names,
                    )?),
                    true,
                )))
            })?
            else {
                return cancelled();
            };
            if cancellation.is_cancelled() {
                return cancelled();
            }
            if !current {
                return Ok(self.external_inventory_unavailable());
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
        let property_getter: bool = row.get(5)?;
        self.external_member_owner_row(
            owner,
            definition,
            ordinal,
            &name,
            &kind,
            &visibility,
            is_static,
            property_getter,
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
        property_getter: bool,
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
        let languages = self
            .external_owner_adapter(owner)
            .expect("external member has a selected inventory adapter")
            .languages;
        let lookups = std::array::from_fn(|i| {
            crate::analyzer::resolution::lookup_semantic(
                names,
                languages[i / 5],
                namespaces[i % 5],
                name,
            )
        });
        // Kotlin reads an instance `getX()` that returns a value as the
        // property `x`; no other caller language has synthetic properties.
        let property_lookup = (property_getter && languages.contains(&Language::Kotlin))
            .then(|| brokk_bifrost_jvm::kotlin::resolution::kotlin_synthetic_property_name(name))
            .flatten()
            .map(|property| {
                crate::analyzer::resolution::lookup_semantic(
                    names,
                    Language::Kotlin,
                    ResolutionNamespace::Value,
                    &property,
                )
            });
        let member = self
            .context_identities
            .external_member_semantic(owner, ordinal, names);
        let property = LoweredMemberOwnerProperty::external(
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
        );
        Ok(SelectedTypedRow::external_member(
            owner.clone(),
            ordinal,
            match property_lookup {
                Some(lookup) => property.with_external_property_lookup(lookup),
                None => property,
            },
        ))
    }

    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
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
        self.visit_external_rows(
            definitions,
            |adapter| adapter.supertypes,
            cancellation,
            visitor,
            |owner, definition, row| {
                let ordinal: u32 = row.get(0)?;
                let target = ExternalOwnerIdentity {
                    provider_id: Arc::<str>::from(row.get::<_, String>(2)?),
                    owner_fqn: Arc::<str>::from(row.get::<_, String>(1)?),
                };
                let target_semantic = self
                    .context_identities
                    .external_owner_semantic(&target, &names);
                let reference = self
                    .context_identities
                    .external_supertype_reference(owner, ordinal, &names);
                self.context_identities
                    .record_external_hierarchy_reference(reference, target_semantic);
                Ok(SelectedTypedRow::external_owner(
                    owner.clone(),
                    LoweredSupertypeProperty::external(
                        // This adapter reads the JVM binary inventory.
                        Language::Java,
                        definition,
                        reference,
                        reference,
                        ordinal,
                        target,
                    )
                    .with_external_arguments(row.get::<_, Option<String>>(3)?.as_deref())
                    .map_err(|error| {
                        invalid_fact(format!("external supertype arguments: {error}"))
                    })?,
                ))
            },
        )
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
    declarations:
        crate::hash::HashMap<SemanticId, SelectedTypedRow<LoweredDeclarationTypeProperty>>,
    pub(super) seeds: crate::hash::HashMap<SemanticId, SelectedTypedRow<LoweredIntrinsicSeed>>,
    parameter_slots: crate::hash::HashSet<SemanticId>,
    generic_formals: crate::hash::HashMap<SemanticId, Vec<SelectedTypedRow<LoweredGenericFormal>>>,
    nominal_argument_reasons: crate::hash::HashSet<SemanticId>,
    formal_nominal_argument_reasons: crate::hash::HashMap<SemanticId, Vec<SemanticId>>,
    result_only_generic_reasons: crate::hash::HashMap<SemanticId, SemanticId>,
    pub(super) components:
        crate::hash::HashMap<SemanticId, Vec<SelectedTypedRow<LoweredTypeComponent>>>,
    pub(super) descriptors:
        crate::hash::HashMap<SemanticId, SelectedTypedRow<LoweredIntrinsicTypeDescriptor>>,
    owners: crate::hash::HashMap<String, Option<ExternalOwnerIdentity>>,
}

impl SelectedResolutionTypedSource<'_, '_> {
    /// An ordinary catalog identity cannot belong to the model-owned
    /// external signature arena. Prove this disjointness from the same
    /// selected catalog authority, not from an empty memo or integer range.
    fn ordinary_external_absence(
        &self,
        identities: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<crate::analyzer::resolution::TypedFactInventoryEvidence> {
        use crate::analyzer::resolution::TypedFactInventoryEvidence;
        for &identity in identities {
            if !matches!(
                self.authority
                    .semantic_catalog_provenance(identity, cancellation)?,
                Some(Some(
                    crate::analyzer::resolution::SelectedSemanticProvenance::FragmentLocal(_)
                ))
            ) {
                return Ok(TypedFactInventoryEvidence::Unestablished);
            }
        }
        Ok(TypedFactInventoryEvidence::Established(
            ResolutionCompletion::Complete,
        ))
    }

    fn external_signature_rows<T>(
        &self,
        rows: Vec<T>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, T>,
    ) -> StoreResult<TypedFactReadOutcome> {
        self.validate_external_signature_memo()?;
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

    fn read_external_signature_type_owners(
        &self,
        names: &str,
        providers: &str,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<(String, String)>>> {
        self.read_statement(cancellation, |connection| {
            let guarded = super::super::jvm_external_publication::jvm_inventory_guarded_sql(
                jvm_external_owner_relations().signature_type_owners,
                3,
            );
            let mut statement = connection.prepare_cached(&guarded)?;
            let guard_column = statement.column_count() - 1;
            let mut cursor = statement.query(rusqlite::params![
                names,
                providers,
                self.external_inventory_generation()?
            ])?;
            let mut owners = Vec::new();
            while let Some(row) = cursor.next()? {
                if !row.get::<_, bool>(guard_column)? {
                    return Err(StoreError::stale_resolution(
                        "JVM provider inventory changed during the request",
                    ));
                }
                if row.get::<_, Option<i64>>(guard_column - 1)?.is_none() {
                    break;
                }
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                owners.push((row.get::<_, String>(0)?, row.get::<_, String>(1)?));
            }
            Ok(Some(owners))
        })
    }

    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
    fn materialize_external_declaration_types(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<TypedFactReadOutcome> {
        self.validate_external_signature_memo()?;
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
            self.capture_external_signature_memo_proof()?;
            let coordinates = serde_json::to_string(&requested.keys().collect::<Vec<_>>())
                .map_err(|error| StoreError::new(error.to_string()))?;
            let providers = serde_json::to_string(&self.external_providers)
                .map_err(|error| StoreError::new(error.to_string()))?;
            let rows = self.read_statement(cancellation, |connection| {
                let guarded = super::super::jvm_external_publication::jvm_inventory_guarded_sql(
                    jvm_external_owner_relations().declaration_signatures,
                    3,
                );
                let mut statement = connection.prepare_cached(&guarded)?;
                let guard_column = statement.column_count() - 1;
                let mut cursor = statement.query(rusqlite::params![
                    coordinates,
                    providers,
                    self.external_inventory_generation()?
                ])?;
                let mut rows = Vec::new();
                while let Some(row) = cursor.next()? {
                    if !row.get::<_, bool>(guard_column)? {
                        return Err(StoreError::stale_resolution(
                            "JVM provider inventory changed during the request",
                        ));
                    }
                    if row.get::<_, Option<i64>>(guard_column - 1)?.is_none() {
                        break;
                    }
                    if cancellation.is_cancelled() {
                        return Ok(None);
                    }
                    rows.push((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, u32>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, Option<String>>(6)?,
                    ));
                }
                Ok(Some(rows))
            })?;
            let Some(rows) = rows else {
                return cancelled();
            };
            let mut decoded = Vec::new();
            let mut type_names = BTreeSet::new();
            for (provider, owner, ordinal, parameters, result, kind, type_parameters) in rows {
                let type_parameters =
                    super::super::jvm_external_inventory::decode_jvm_external_type_parameters(
                        type_parameters.as_deref(),
                    )?;
                let parameters: Vec<Parameter> =
                    serde_json::from_str(&parameters).map_err(|error| {
                        invalid_fact(format!("external declaration parameters: {error}"))
                    })?;
                let result: Option<TypeRef> = result
                    .map(|value| serde_json::from_str(&value))
                    .transpose()
                    .map_err(|error| invalid_fact(format!("external declaration type: {error}")))?;
                let mut pending = parameters
                    .iter()
                    .map(|parameter| (&parameter.r#type, true))
                    .chain(result.iter().map(|term| (term, false)))
                    .collect::<Vec<_>>();
                let mut generic = false;
                let mut generic_parameters = false;
                while let Some((term, parameter)) = pending.pop() {
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
                            pending.extend(arguments.iter().map(|term| (term, parameter)));
                        }
                        TypeRef::Declared { arguments, .. } => {
                            pending.extend(arguments.iter().map(|term| (term, parameter)))
                        }
                        TypeRef::TypeParameter { .. } => {
                            generic = true;
                            generic_parameters |= parameter;
                        }
                        TypeRef::Array { element }
                        | TypeRef::ByRef { element, .. }
                        | TypeRef::Pointer { element }
                        | TypeRef::Slice { element }
                        | TypeRef::FixedArray { element, .. }
                        | TypeRef::Channel { element, .. } => pending.push((element, parameter)),
                        TypeRef::Map { key, value } => {
                            pending.push((key, parameter));
                            pending.push((value, parameter));
                        }
                        TypeRef::Wildcard { bound, .. } => {
                            pending.extend(bound.as_deref().map(|term| (term, parameter)))
                        }
                        TypeRef::Tuple { elements } => {
                            pending.extend(elements.iter().map(|term| (term, parameter)))
                        }
                        TypeRef::Function { parameters, result } => {
                            pending.extend(
                                parameters.iter().map(|formal| (&formal.r#type, parameter)),
                            );
                            pending.extend(result.as_deref().map(|term| (term, parameter)));
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
                    generic_parameters,
                    type_parameters,
                    kind,
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
                let owners =
                    self.read_external_signature_type_owners(&names, &providers, cancellation)?;
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
            for (
                definition,
                owner,
                ordinal,
                parameters,
                result,
                generic,
                generic_parameters,
                type_parameters,
                kind,
            ) in decoded
            {
                let callable = matches!(kind.as_str(), "method" | "function" | "constructor");
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
                        &crate::analyzer::resolution::ExternalMemberCoordinate::InventoryOrdinal(
                            member.ordinal,
                        ),
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
                    memo.materialize_value_seed(slot);
                    memo.parameter_slots.insert(slot);
                    if let ResolutionCompletion::Incomplete(reasons) = memo
                        .seeds
                        .get(&slot)
                        .expect("lowered formal type has a seed")
                        .row()
                        .frontier()
                        .completion()
                    {
                        let formal_reasons = reasons
                            .iter()
                            .filter_map(|reason| match reason {
                                ResolutionIncompleteReason::UnsupportedSemantic(reason)
                                | ResolutionIncompleteReason::ReceiverSubclassObligation(reason)
                                    if memo.nominal_argument_reasons.contains(reason) =>
                                {
                                    Some(*reason)
                                }
                                _ => None,
                            })
                            .collect::<Vec<_>>();
                        if !formal_reasons.is_empty() {
                            memo.formal_nominal_argument_reasons
                                .entry(definition)
                                .or_default()
                                .extend(formal_reasons);
                        }
                    }
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
                        &crate::analyzer::resolution::ExternalMemberCoordinate::InventoryOrdinal(
                            member.ordinal,
                        ),
                        term,
                        &mut next_slot,
                        &names,
                        &self.context_identities,
                        cancellation,
                    ) else {
                        return cancelled();
                    };
                    memo.declarations.insert(
                        definition,
                        SelectedTypedRow::external_member(
                            owner.clone(),
                            ordinal,
                            LoweredDeclarationTypeProperty::new(
                                definition,
                                slot,
                                if callable {
                                    DeclarationTypeRole::Return
                                } else if kind == "nested_type" {
                                    // A nested declaration denotes its declared owner type;
                                    // definition lookup still retains the member identity.
                                    DeclarationTypeRole::Identity
                                } else {
                                    DeclarationTypeRole::Value
                                },
                            ),
                        ),
                    );
                    if !callable && kind != "nested_type" {
                        memo.materialize_value_seed(slot);
                    }
                    result_types.push(LoweredCallableResultTypeProperty::new(0, slot));
                }
                if !callable {
                    continue;
                }
                let completion = if generic {
                    // No erased signature or unconstrained inference is a proof
                    // of an exact substitution for an external type variable.
                    let reason = self.context_identities.named_semantic(
                        member.jvm_generic_signature_obligation_digest(),
                        "UnsupportedExternalSignatureTypeVariable",
                        crate::analyzer::resolution::ReasonDeterminism::Unaudited,
                        "The external declaration has an unproven type-variable substitution",
                    );
                    if !generic_parameters {
                        memo.result_only_generic_reasons.insert(definition, reason);
                    }
                    ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(reason),
                    ])
                } else {
                    ResolutionCompletion::Complete
                };
                // Allocate formal declaration identities after the old type slots so
                // signature type identities and existing refusal reasons remain stable.
                let own_count = type_parameters.as_ref().map_or(0, Vec::len);
                let coordinate =
                    crate::analyzer::resolution::ExternalMemberCoordinate::InventoryOrdinal(
                        ordinal,
                    );
                let mut hooks = JvmTypeTermHooks {
                    member: &member,
                    coordinate: &coordinate,
                    next_slot: &mut next_slot,
                    names: &names,
                    identities: &self.context_identities,
                };
                let formals = (0..own_count)
                    .map(|position| {
                        let (parameter, _) = hooks.allocate();
                        hooks.wrap(LoweredGenericFormal::new(
                            definition,
                            u32::try_from(position).expect("external generic ordinal fits u32"),
                            parameter,
                        ))
                    })
                    .collect();
                memo.generic_formals.insert(definition, formals);
                let signature = LoweredCallableSignatureProperty::new(
                    definition,
                    u32::try_from(own_count).expect("external generic count fits u32"),
                    properties,
                    completion,
                )
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
        Ok(TypedFactReadOutcome::exhausted(
            ResolutionCompletion::Complete,
        ))
    }

    pub(super) fn visit_external_generic_formals(
        &self,
        owners: &[SemanticId],
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredGenericFormal>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let outcome = self.materialize_external_declaration_types(owners, cancellation)?;
        if !outcome.is_exhausted() {
            return Ok(outcome);
        }
        let memo = self.external_signatures.borrow();
        let rows = owners
            .iter()
            .filter_map(|owner| memo.generic_formals.get(owner))
            .flatten()
            .cloned()
            .collect();
        let inventory = self.ordinary_external_absence(owners, cancellation)?;
        Ok(self
            .external_signature_rows(rows, cancellation, visitor)?
            .with_inventory_evidence(inventory))
    }

    pub(super) fn visit_external_declaration_types(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDeclarationTypeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let outcome = self.materialize_external_declaration_types(definitions, cancellation)?;
        if !outcome.is_exhausted() {
            return Ok(outcome);
        }
        let memo = self.external_signatures.borrow();
        let rows = definitions
            .iter()
            .filter_map(|definition| memo.declarations.get(definition).cloned())
            .collect();
        let inventory = self.ordinary_external_absence(definitions, cancellation)?;
        Ok(self
            .external_signature_rows(rows, cancellation, visitor)?
            .with_inventory_evidence(inventory))
    }

    pub(super) fn visit_external_declaration_types_for_slots(
        &self,
        slots: &[SemanticId],
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDeclarationTypeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let memo = self.external_signatures.borrow();
        let rows = slots
            .iter()
            .filter_map(|slot| {
                memo.declarations
                    .values()
                    .find(|property| property.row().slot() == *slot)
                    .cloned()
            })
            .collect();
        let inventory = self.ordinary_external_absence(slots, cancellation)?;
        Ok(self
            .external_signature_rows(rows, cancellation, visitor)?
            .with_inventory_evidence(inventory))
    }

    pub(super) fn visit_external_callable_signatures(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredCallableSignatureProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let outcome = self.materialize_external_declaration_types(definitions, cancellation)?;
        if !outcome.is_exhausted() {
            return Ok(outcome);
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
                .filter_map(|slot| memo.components.get(slot))
                .flat_map(|rows| rows.iter().cloned())
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

pub(in crate::analyzer::store) const EXTERNAL_DECLARATION_SIGNATURES_SQL: &str = r#"
WITH requested AS (
    SELECT json_extract(value,'$[0]') provider_id,
           json_extract(value,'$[1]') owner_fqn,
           json_extract(value,'$[2]') ordinal
    FROM json_each(?1)
)
SELECT DISTINCT member.provider_id,member.owner_fqn,member.ordinal,
       json(member.parameters_jsonb),json(member.return_type_jsonb),member.member_kind,json(member.type_parameters_jsonb)
FROM requested
JOIN jvm_external_owner_members selected USING(provider_id,owner_fqn,ordinal)
JOIN jvm_external_owner_members member
  ON member.provider_id=selected.provider_id AND member.owner_fqn=selected.owner_fqn
 AND member.member_name=selected.member_name AND member.member_kind=selected.member_kind
WHERE (member.signature_present=1 OR member.member_kind='nested_type')
  AND member.member_kind IN ('method','function','constructor','field','constant','nested_type')
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
    pub(super) fn type_frontier(
        &self,
        slot: SemanticId,
    ) -> &crate::analyzer::resolution::TypedFrontierState {
        self.seeds
            .get(&slot)
            .expect("lowered type has a seed")
            .row()
            .frontier()
    }

    /// Parameters and fields carry runtime values of their declared types.
    fn materialize_value_seed(&mut self, slot: SemanticId) {
        let seed = self
            .seeds
            .get(&slot)
            .expect("lowered declaration type has a seed");
        let row = seed.row();
        let frontier = crate::analyzer::resolution::TypedFrontierState::new(
            slot,
            row.frontier()
                .possible_values()
                .iter()
                .map(|value| {
                    crate::analyzer::resolution::ResolutionSlotValue::runtime(value.ty(), false)
                })
                .collect::<Vec<_>>(),
            row.frontier().completion().clone(),
        );
        let seed = seed.with_row(LoweredIntrinsicSeed::new(
            row.kind(),
            row.spelling(),
            frontier,
        ));
        self.seeds.insert(slot, seed);
    }

    /// Lower the structured declaration term without parsing display text or
    /// erasing a generic variable to its bound. The explicit postorder stack
    /// also keeps deeply nested array signatures off the Rust call stack.
    #[allow(clippy::too_many_arguments)]
    fn lower_type_term(
        &mut self,
        member: &crate::analyzer::resolution::ExternalMemberIdentity,
        coordinate: &crate::analyzer::resolution::ExternalMemberCoordinate,
        term: &crate::analyzer::semantic_model::TypeRef,
        next_slot: &mut u32,
        names: &dyn SharedNameInterner,
        identities: &crate::analyzer::resolution::SelectedContextIdentities,
        cancellation: &CancellationToken,
    ) -> Option<SemanticId> {
        // The JVM hook retains its existing allocation domain and provenance.
        lower_type_term(
            self,
            term,
            &mut JvmTypeTermHooks {
                member,
                coordinate,
                next_slot,
                names,
                identities,
            },
            identities,
            cancellation,
        )
        .expect("JVM nominal lookup is infallible")
    }
}

use crate::analyzer::semantic_model::TypeRef;
use brokk_bifrost_core::analyzer::resolution_facts::IntrinsicTypeKind;

/// The traversal and slot producers are shared; a language supplies nominal
/// authority, constructors, allocation coordinates and selected provenance.
pub(super) trait TypeTermHooks {
    fn allocate(&mut self) -> (SemanticId, [u8; 32]);
    fn wrap<T>(&self, row: T) -> SelectedTypedRow<T>;
    fn nominal(
        &mut self,
        term: &TypeRef,
        owners: &crate::hash::HashMap<String, Option<ExternalOwnerIdentity>>,
    ) -> StoreResult<Option<(SemanticId, IntrinsicTypeKind, String)>>;
    fn exact_nominal(&self, term: &TypeRef) -> bool;
    fn sequence_element<'a>(&self, _term: &'a TypeRef) -> Option<&'a TypeRef> {
        None
    }
    fn slice_element<'a>(&self, _term: &'a TypeRef) -> Option<&'a TypeRef> {
        None
    }
    fn map_elements<'a>(&self, _term: &'a TypeRef) -> Option<(&'a TypeRef, &'a TypeRef)> {
        None
    }
    fn pointer_element<'a>(&self, _term: &'a TypeRef) -> Option<&'a TypeRef> {
        None
    }
    /// A generic application `Head<Arguments>` splits into the nominal head and
    /// its arguments. The default reports no application, so a language
    /// without generic type values keeps treating the whole term as a nominal
    /// head whose arguments leave it incomplete. The lowerer resolves the
    /// head through `nominal`; it does not yet produce argument slots, so a
    /// hook that reports an application must keep `exact_nominal` false for it.
    fn application_arguments<'a>(
        &self,
        _term: &'a TypeRef,
    ) -> Option<(&'a TypeRef, &'a [TypeRef])> {
        None
    }
}

struct JvmTypeTermHooks<'a> {
    member: &'a crate::analyzer::resolution::ExternalMemberIdentity,
    coordinate: &'a crate::analyzer::resolution::ExternalMemberCoordinate,
    next_slot: &'a mut u32,
    names: &'a dyn SharedNameInterner,
    identities: &'a crate::analyzer::resolution::SelectedContextIdentities,
}

impl TypeTermHooks for JvmTypeTermHooks<'_> {
    fn allocate(&mut self) -> (SemanticId, [u8; 32]) {
        let mut hash = brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(
            b"bifrost-jvm-external-signature-slot:v1",
        );
        hash.field("provider", self.member.owner.provider_id.as_bytes());
        hash.field("owner", self.member.owner.owner_fqn.as_bytes());
        match self.coordinate {
            crate::analyzer::resolution::ExternalMemberCoordinate::InventoryOrdinal(ordinal) => {
                hash.field("member", &ordinal.to_be_bytes());
            }
            crate::analyzer::resolution::ExternalMemberCoordinate::ModelMember(member) => {
                hash.field("pack-id", member.provider.pack_id.as_bytes());
                hash.field("pack-version", member.provider.pack_version.as_bytes());
                hash.field("pack-digest", member.provider.pack_digest.as_bytes());
                hash.field("symbol-id", member.symbol_id.as_bytes());
            }
        }
        hash.field("slot", &self.next_slot.to_be_bytes());
        *self.next_slot = self
            .next_slot
            .checked_add(1)
            .expect("external signature slots fit u32");
        let digest = hash.finish();
        (SemanticId::shared_name(self.names.intern(digest)), digest)
    }

    fn wrap<T>(&self, row: T) -> SelectedTypedRow<T> {
        SelectedTypedRow::external_member(self.member.owner.clone(), self.member.ordinal, row)
    }
    fn nominal(
        &mut self,
        term: &TypeRef,
        owners: &crate::hash::HashMap<String, Option<ExternalOwnerIdentity>>,
    ) -> StoreResult<Option<(SemanticId, IntrinsicTypeKind, String)>> {
        Ok(if let TypeRef::Named { name, .. } = term {
            if brokk_bifrost_jvm::java::primitives::primitive_for_name(name).is_some() {
                let digest = crate::analyzer::resolution::universe::intrinsic_type_identity_digest(
                    Language::Java,
                    IntrinsicTypeKind::Primitive,
                    name,
                );
                Some((
                    SemanticId::shared_name(self.names.intern(digest)),
                    IntrinsicTypeKind::Primitive,
                    name.clone(),
                ))
            } else {
                owners.get(name).and_then(Option::as_ref).map(|owner| {
                    (
                        self.identities.external_owner_semantic(owner, self.names),
                        IntrinsicTypeKind::LanguageBuiltin,
                        name.clone(),
                    )
                })
            }
        } else {
            None
        })
    }
    fn exact_nominal(&self, term: &TypeRef) -> bool {
        !matches!(term, TypeRef::Named { arguments, nullable, .. } if !arguments.is_empty() || *nullable)
    }
    fn sequence_element<'a>(&self, term: &'a TypeRef) -> Option<&'a TypeRef> {
        if let TypeRef::Array { element } = term {
            Some(element)
        } else {
            None
        }
    }
}

/// Iterative postorder lowering retains unsupported terms as incomplete slots.
pub(super) fn lower_type_term(
    memo: &mut ExternalSignatureMemo,
    term: &TypeRef,
    hooks: &mut impl TypeTermHooks,
    identities: &crate::analyzer::resolution::SelectedContextIdentities,
    cancellation: &CancellationToken,
) -> StoreResult<Option<SemanticId>> {
    use crate::analyzer::resolution::{ResolutionSlotValue, ResolutionTypeRef, TypedFrontierState};
    use brokk_bifrost_core::analyzer::resolution_facts::{
        ResolutionTypeComponentKind, ResolutionTypeConstructorKind,
    };
    let root = hooks.allocate();
    enum Children {
        Pointer(SemanticId),
        Sequence(SemanticId),
        Slice(SemanticId),
        Map(SemanticId, SemanticId),
    }
    let mut pending = vec![(term, root, None)];
    while let Some((term, (slot, digest), component)) = pending.pop() {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        if let Some(component) = component {
            if let Children::Pointer(element) = component {
                let child = memo
                    .seeds
                    .get(&element)
                    .expect("pointer operand was lowered first");
                let frontier = child.row().frontier();
                let values: Vec<_> = frontier
                    .possible_values()
                    .iter()
                    .map(|value| {
                        let ty = value.ty();
                        ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                            ty.identity(),
                            ty.indirection()
                                .checked_add(1)
                                .expect("type depth fits u32"),
                        ))
                    })
                    .collect();
                memo.seeds.insert(
                    slot,
                    hooks.wrap(LoweredIntrinsicSeed::new(
                        IntrinsicTypeKind::Structural,
                        "pointer-type",
                        TypedFrontierState::new(slot, values, frontier.completion().clone()),
                    )),
                );

                continue;
            }
            let (constructor, children) = match component {
                Children::Sequence(element) => (
                    ResolutionTypeConstructorKind::Sequence,
                    vec![(ResolutionTypeComponentKind::Element, element)],
                ),
                Children::Slice(element) => (
                    ResolutionTypeConstructorKind::Slice,
                    vec![(ResolutionTypeComponentKind::Element, element)],
                ),
                Children::Map(key, value) => (
                    ResolutionTypeConstructorKind::Map,
                    vec![
                        (ResolutionTypeComponentKind::Key, key),
                        (ResolutionTypeComponentKind::Value, value),
                    ],
                ),
                Children::Pointer(_) => unreachable!(),
            };
            let completion =
                children
                    .iter()
                    .fold(ResolutionCompletion::Complete, |completion, (_, child)| {
                        completion.combine(
                            memo.seeds
                                .get(child)
                                .expect("constructor operand was lowered first")
                                .row()
                                .frontier()
                                .completion(),
                        )
                    });
            for (kind, child) in children {
                memo.components
                    .entry(slot)
                    .or_default()
                    .push(hooks.wrap(LoweredTypeComponent::new(slot, constructor, kind, child)));
            }
            memo.seeds.insert(
                slot,
                hooks.wrap(LoweredIntrinsicSeed::new(
                    IntrinsicTypeKind::Structural,
                    "structural-type",
                    TypedFrontierState::new(
                        slot,
                        vec![ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                            slot, 0,
                        ))],
                        completion,
                    ),
                )),
            );
            continue;
        }
        if let Some(element) = hooks.pointer_element(term) {
            let child = hooks.allocate();
            pending.push((term, (slot, digest), Some(Children::Pointer(child.0))));
            pending.push((element, child, None));
            continue;
        }
        if let Some(element) = hooks.sequence_element(term) {
            let child = hooks.allocate();
            pending.push((term, (slot, digest), Some(Children::Sequence(child.0))));
            pending.push((element, child, None));
            continue;
        }
        if let Some(element) = hooks.slice_element(term) {
            let child = hooks.allocate();
            pending.push((term, (slot, digest), Some(Children::Slice(child.0))));
            pending.push((element, child, None));
            continue;
        }
        if let Some((key, value)) = hooks.map_elements(term) {
            let key_child = hooks.allocate();
            let value_child = hooks.allocate();
            pending.push((
                term,
                (slot, digest),
                Some(Children::Map(key_child.0, value_child.0)),
            ));
            pending.push((value, value_child, None));
            pending.push((key, key_child, None));
            continue;
        }
        let head = hooks
            .application_arguments(term)
            .map_or(term, |(head, _arguments)| head);
        let known = hooks.nominal(head, &memo.owners)?;
        let incomplete_type = || {
            let reason = identities.named_semantic(
                digest,
                "UnsupportedExternalSignatureType",
                crate::analyzer::resolution::ReasonDeterminism::Unaudited,
                "The external declaration type term has no proven exact native substitution",
            );
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                reason,
            )])
        };
        let (kind, spelling, values, completion) = if let Some((identity, kind, spelling)) = known {
            memo.descriptors.insert(
                identity,
                hooks.wrap(LoweredIntrinsicTypeDescriptor::new(
                    identity,
                    kind,
                    spelling.as_str(),
                )),
            );
            (
                kind,
                spelling.clone(),
                vec![ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                    identity, 0,
                ))],
                if !hooks.exact_nominal(term) {
                    incomplete_type()
                } else {
                    ResolutionCompletion::Complete
                },
            )
        } else {
            (
                IntrinsicTypeKind::Structural,
                "unknown-external-type".to_owned(),
                Vec::new(),
                incomplete_type(),
            )
        };
        // #7619: this known non-nullable head has an incomplete argument term.
        // Retain that exact reason identity without certifying the full type.
        if !values.is_empty()
            && matches!(term, TypeRef::Named { arguments, nullable: false, .. } if !arguments.is_empty())
            && let ResolutionCompletion::Incomplete(reasons) = &completion
        {
            for reason in reasons.iter() {
                if let ResolutionIncompleteReason::UnsupportedSemantic(reason)
                | ResolutionIncompleteReason::ReceiverSubclassObligation(reason) = reason
                {
                    memo.nominal_argument_reasons.insert(*reason);
                }
            }
        }
        memo.seeds.insert(
            slot,
            hooks.wrap(LoweredIntrinsicSeed::new(
                kind,
                spelling,
                TypedFrontierState::new(slot, values, completion),
            )),
        );
    }
    Ok(Some(root.0))
}

impl SelectedResolutionTypedSource<'_, '_> {
    pub(super) fn external_inheritance_declarations(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<crate::analyzer::resolution::JavaInheritanceDeclaration>>> {
        self.validate_external_signature_memo()?;
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
            self.capture_external_signature_memo_proof()?;
            let coordinates = serde_json::to_string(&requested.keys().collect::<Vec<_>>())
                .map_err(|error| StoreError::new(error.to_string()))?;
            let providers = serde_json::to_string(&self.external_providers)
                .map_err(|error| StoreError::new(error.to_string()))?;
            let rows = self.read_statement(cancellation, |connection| {
                let guarded = super::super::jvm_external_publication::jvm_inventory_guarded_sql(
                    jvm_external_owner_relations().inheritance_declarations,
                    3,
                );
                let mut statement = connection.prepare_cached(&guarded)?;
                let guard_column = statement.column_count() - 1;
                let mut cursor = statement.query(rusqlite::params![
                    coordinates,
                    providers,
                    self.external_inventory_generation()?
                ])?;
                let mut rows = Vec::new();
                while let Some(row) = cursor.next()? {
                    if !row.get::<_, bool>(guard_column)? {
                        return Err(StoreError::stale_resolution(
                            "JVM provider inventory changed during the request",
                        ));
                    }
                    if row.get::<_, Option<i64>>(guard_column - 1)?.is_none() {
                        break;
                    }
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
    #[expect(
        clippy::disallowed_methods,
        reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
    )]
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
            "SELECT member_name, visibility FROM jvm_external_owner_members WHERE provider_id=(SELECT provider_id FROM jvm_external_provider_publications WHERE semantic_sha256='provider') AND owner_fqn='example.Owner' ORDER BY ordinal",
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

#[cfg(test)]
mod inventory_generation_tests {
    use super::*;
    use crate::analyzer::store::jvm_external_publication::{
        JvmExternalProjection, jvm_external_provider_id,
    };
    use crate::analyzer::store::resolution_selection::{
        SelectedResolutionLanguage, SelectedResolutionMountInventoryOutcome,
        tests::qualifier_completion_gap_fixture,
    };
    use rusqlite::types::Value;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12245: evicted JVM declarations and owner authority returned complete answers"
    )]
    #[expect(
        clippy::disallowed_methods,
        reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
    )]
    fn evicted_member_signature_and_inheritance_reads_are_unavailable() {
        let (store, workspace, snapshots) = qualifier_completion_gap_fixture();
        let provider = jvm_external_provider_id("definition-fixture");
        let owner = ExternalOwnerIdentity {
            provider_id: Arc::from(provider.as_str()),
            owner_fqn: Arc::from("java.lang.Object"),
        };
        assert!(
            crate::analyzer::resolution::universe::intrinsic_member_inventory(&owner.owner_fqn)
                .is_some()
        );
        let projection = JvmExternalProjection {
            provider_id: provider.clone(),
            semantic_sha256: "definition-fixture".into(),
            source_identity: "fixture".into(),
            owners: vec![vec![
                Value::Text(provider.clone()),
                Value::Text(owner.owner_fqn.to_string()),
                Value::Integer(1),
                Value::Integer(1),
                Value::Integer(1),
                Value::Integer(1),
                Value::Text("[]".into()),
            ]],
            members: vec![vec![
                Value::Text(provider.clone()),
                Value::Text(owner.owner_fqn.to_string()),
                Value::Integer(0),
                Value::Text("toString".into()),
                Value::Text("method".into()),
                Value::Text("public".into()),
                Value::Integer(0),
                Value::Integer(1),
                Value::Integer(1),
                Value::Null,
                Value::Text("[]".into()),
                Value::Null,
                Value::Integer(0),
                Value::Text("[]".into()),
            ]],
            supertypes: Vec::new(),
        };
        store
            .publish_jvm_external_projection(|| Ok(Some(projection)), || false)
            .unwrap();
        let competing_provider = jvm_external_provider_id("competing-definition");
        let competing = JvmExternalProjection {
            provider_id: competing_provider.clone(),
            semantic_sha256: "competing-definition".into(),
            source_identity: "fixture".into(),
            owners: vec![vec![
                Value::Text(competing_provider.clone()),
                Value::Text(owner.owner_fqn.to_string()),
                Value::Integer(1),
                Value::Integer(1),
                Value::Integer(1),
                Value::Integer(1),
                Value::Text("[]".into()),
            ]],
            members: Vec::new(),
            supertypes: Vec::new(),
        };
        store
            .publish_jvm_external_projection(|| Ok(Some(competing)), || false)
            .unwrap();
        let generation = store.jvm_external_inventory_generation().unwrap();
        let cancellation = CancellationToken::new();
        let languages = [SelectedResolutionLanguage::new("go", Language::Go)];
        let SelectedResolutionMountInventoryOutcome::Ready(selection) = store
            .open_selected_resolution_mount_inventory(
                &workspace,
                &snapshots,
                &languages,
                &[],
                &cancellation,
            )
            .unwrap()
        else {
            panic!("fixture must select");
        };
        let typed = SelectedResolutionTypedSource::new_on_demand(&selection)
            .with_external_providers(vec![provider.clone()])
            .with_external_inventory_generation(&store, Some(generation));
        let names = selection
            .shared_name_table()
            .interner(selection.connection());
        let present = typed
            .context_identities
            .external_member_semantic(&owner, 0, &names);
        let absent = typed
            .context_identities
            .external_member_semantic(&owner, 99, &names);
        let read = |definition| {
            let mut count = 0;
            let mut sink = |page: &[_]| {
                count += page.len();
                Ok(true)
            };
            let outcome = typed
                .visit_external_member_owners_for_definitions(
                    &[definition],
                    &cancellation,
                    &mut TypedFactPageVisitor::new(&mut sink),
                )
                .unwrap();
            (count, outcome)
        };
        let (count, outcome) = read(absent);
        assert_eq!(count, 0);
        assert_eq!(outcome.evidence(), &ResolutionCompletion::Complete);
        assert_eq!(read(present).0, 1);
        assert!(
            intrinsic_member_inventory_for_owner(selection.connection(), &owner, generation)
                .unwrap()
                .is_none()
        );
        let member: String = selection.connection().query_row("SELECT member_name FROM jvm_external_owner_members WHERE provider_id=?1 AND ordinal=0", [&provider], |row| row.get(0)).unwrap();
        assert_eq!(member, "toString");
        // Exercise each declaration reader with a cold memo before eviction.
        let fresh = || {
            SelectedResolutionTypedSource::new_on_demand(&selection)
                .with_context_identities(typed.context_identities.clone())
                .with_external_providers(vec![owner.provider_id.to_string()])
                .with_external_inventory_generation(&store, Some(generation))
        };
        let control = fresh();
        let missing_owner = ExternalOwnerIdentity {
            provider_id: owner.provider_id.clone(),
            owner_fqn: Arc::from("example.Missing"),
        };
        assert!(control.external_owner_type_is_indexed(&owner).unwrap());
        assert!(
            !control
                .external_owner_type_is_indexed(&missing_owner)
                .unwrap()
        );
        assert_eq!(
            control
                .selected_jvm_declaration_owner(&owner.owner_fqn, &cancellation)
                .unwrap(),
            Some(Some(owner.clone()))
        );
        let ambiguous = SelectedResolutionTypedSource::new_on_demand(&selection)
            .with_external_providers(vec![owner.provider_id.to_string(), competing_provider])
            .with_external_inventory_generation(&store, Some(generation));
        assert_eq!(
            ambiguous
                .selected_jvm_declaration_owner(&owner.owner_fqn, &cancellation)
                .unwrap(),
            Some(None)
        );
        let owner_consumer = |source: &dyn SelectedTypedFactSource| {
            crate::analyzer::resolution::fact_resolution::fixture_support::selected_jvm_owner_semantic(source, &owner.owner_fqn, &cancellation)
        };
        assert_eq!(owner_consumer(&ambiguous).unwrap(), None);
        let metadata = super::super::super::resolution_operation::native_units::selected_jvm_external_member_metadata(selection.connection(), &owner, 0, generation).unwrap();
        assert_eq!(metadata.member_name, "toString");

        assert_eq!(
            control
                .materialize_external_declaration_types(&[present], &cancellation)
                .unwrap()
                .evidence(),
            &ResolutionCompletion::Complete
        );
        assert!(control.external_signatures.borrow().signatures[&present].is_some());
        assert_eq!(
            control
                .external_inheritance_declarations(&[present], &cancellation)
                .unwrap()
                .unwrap()
                .len(),
            1
        );
        let requested_names = serde_json::to_string(&[owner.owner_fqn.as_ref()]).unwrap();
        let requested_providers = serde_json::to_string(&[owner.provider_id.as_ref()]).unwrap();
        assert_eq!(
            control
                .read_external_signature_type_owners(
                    &requested_names,
                    &requested_providers,
                    &cancellation
                )
                .unwrap()
                .unwrap(),
            vec![(owner.owner_fqn.to_string(), owner.provider_id.to_string())]
        );
        // No inventory change: a genuinely absent signature is complete.
        assert_eq!(
            control
                .materialize_external_declaration_types(&[absent], &cancellation)
                .unwrap()
                .evidence(),
            &ResolutionCompletion::Complete
        );
        store
            .conn
            .execute(move |conn| -> StoreResult<()> {
                conn.execute(
                    "DELETE FROM jvm_external_provider_publications WHERE provider_id=?1",
                    [provider],
                )?;
                Ok(())
            })
            .unwrap();
        // These exact request-local answers were fully acquired from the
        // sealed provider before eviction, so their snapshot proof survives.
        assert_eq!(
            control
                .materialize_external_declaration_types(&[present], &cancellation)
                .unwrap()
                .evidence(),
            &ResolutionCompletion::Complete
        );
        assert_eq!(
            control
                .external_inheritance_declarations(&[present], &cancellation)
                .unwrap()
                .unwrap()
                .len(),
            1
        );
        let stale = fresh();
        assert!(
            stale
                .external_owner_type_is_indexed(&owner)
                .unwrap_err()
                .is_stale_resolution()
        );
        assert!(
            stale
                .external_owner_type_is_indexed(&missing_owner)
                .unwrap_err()
                .is_stale_resolution()
        );
        assert!(
            stale
                .jvm_external_owner_is_indexed(&owner)
                .unwrap_err()
                .is_stale_resolution()
        );
        // Ambiguity permits the caller's ordinary no-owner result; generation
        // drift must instead propagate unavailable resolution to its caller.
        assert!(
            owner_consumer(&ambiguous)
                .unwrap_err()
                .is_stale_resolution()
        );

        assert!(
            stale
                .selected_jvm_declaration_owner(&owner.owner_fqn, &cancellation)
                .unwrap_err()
                .is_stale_resolution()
        );
        assert!(
            ambiguous
                .selected_jvm_declaration_owner(&owner.owner_fqn, &cancellation)
                .unwrap_err()
                .is_stale_resolution()
        );
        assert!(super::super::super::resolution_operation::native_units::selected_jvm_external_member_metadata(selection.connection(), &owner, 0, generation).unwrap_err().is_stale_resolution());

        assert!(
            stale
                .materialize_external_declaration_types(&[present], &cancellation)
                .unwrap_err()
                .is_stale_resolution()
        );
        assert!(
            stale
                .external_inheritance_declarations(&[present], &cancellation)
                .unwrap_err()
                .is_stale_resolution()
        );
        assert!(
            stale
                .read_external_signature_type_owners(
                    &requested_names,
                    &requested_providers,
                    &cancellation
                )
                .unwrap_err()
                .is_stale_resolution()
        );
        assert!(stale.external_signatures.borrow().signatures.is_empty());
        assert!(stale.external_signatures.borrow().inheritance.is_empty());
        let failure =
            intrinsic_member_inventory_for_owner(selection.connection(), &owner, generation)
                .err()
                .expect("evicted inventory must be stale");
        assert!(failure.is_stale_resolution(), "{failure:?}");
        let (count, outcome) = read(present);
        assert_eq!(count, 0);
        assert!(matches!(
            outcome.evidence(),
            ResolutionCompletion::Incomplete(_)
        ));
    }
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12245: legacy signature and inheritance memos carried mutable inventory across generation changes"
    )]
    #[expect(
        clippy::disallowed_methods,
        reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
    )]
    fn legacy_signature_memos_do_not_carry_acquired_absence() {
        use crate::analyzer::semantic_model::{MemberFact, TypeFact};
        let (store, workspace, snapshots) = qualifier_completion_gap_fixture();
        let types: Vec<TypeFact> = serde_json::from_value(serde_json::json!([{
            "id":"owner", "name":"example.Legacy", "type_kind":"class", "visibility":"public",
            "locator":{"kind":"artifact","path":"legacy.jar","symbol":"example.Legacy"}
        }]))
        .unwrap();
        let members: Vec<MemberFact> = serde_json::from_value(serde_json::json!([{
            "id":"method", "owner":"owner", "name":"call", "member_kind":"method", "visibility":"public",
            "locator":{"kind":"artifact","path":"legacy.jar","symbol":"example.Legacy.call"}
        }])).unwrap();
        store
            .publish_jvm_external_inventory_facts(
                "legacy-signature-memo".into(),
                &types,
                &members,
                true,
            )
            .unwrap();
        let provider = jvm_external_provider_id("legacy-signature-memo");
        let generation = store.jvm_external_inventory_generation().unwrap();
        let cancellation = CancellationToken::new();
        let languages = [SelectedResolutionLanguage::new("go", Language::Go)];
        let SelectedResolutionMountInventoryOutcome::Ready(selection) = store
            .open_selected_resolution_mount_inventory(
                &workspace,
                &snapshots,
                &languages,
                &[],
                &cancellation,
            )
            .unwrap()
        else {
            panic!("fixture must select");
        };
        let typed = SelectedResolutionTypedSource::new_on_demand(&selection)
            .with_external_providers(vec![provider.clone()])
            .with_external_inventory_generation(&store, Some(generation));
        let owner = ExternalOwnerIdentity {
            provider_id: Arc::from(provider.as_str()),
            owner_fqn: Arc::from("example.Legacy"),
        };
        let names = selection
            .shared_name_table()
            .interner(selection.connection());
        let definition = typed
            .context_identities
            .external_member_semantic(&owner, 0, &names);
        assert_eq!(
            typed
                .materialize_external_declaration_types(&[definition], &cancellation)
                .unwrap()
                .evidence(),
            &ResolutionCompletion::Complete
        );
        assert!(typed.external_signatures.borrow().signatures[&definition].is_none());
        assert_eq!(
            typed
                .external_inheritance_declarations(&[definition], &cancellation)
                .unwrap()
                .unwrap()
                .len(),
            1
        );
        store.conn.execute(move |conn| -> StoreResult<()> {
            assert_eq!(conn.execute("UPDATE jvm_external_owner_members SET signature_present=1 WHERE provider_id=?1", [provider])?, 1);
            Ok(())
        }).unwrap();
        assert!(store.jvm_external_inventory_generation().unwrap() > generation);
        assert!(
            typed
                .materialize_external_declaration_types(&[definition], &cancellation)
                .unwrap_err()
                .is_stale_resolution()
        );
        assert!(
            typed
                .external_inheritance_declarations(&[definition], &cancellation)
                .unwrap_err()
                .is_stale_resolution()
        );
        assert!(
            typed
                .external_receiver_argument_reasons(&[definition], &[], &cancellation)
                .unwrap_err()
                .is_stale_resolution()
        );
    }
}
