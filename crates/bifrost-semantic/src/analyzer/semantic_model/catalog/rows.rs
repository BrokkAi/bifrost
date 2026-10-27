//! Shard-local semantic rows and connection-local active-set views.

use crate::analyzer::semantic_model::{CompiledPackManifest, CompiledShard, Locator};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::{CatalogError, SessionSemanticCatalog};

pub const SEMANTIC_ROWS_INDEX_VERSION: i64 = 4;

/// Optional companions whose child rows cannot distinguish absent from empty.
/// The schema boundary test keeps this vocabulary equal to the table CHECK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticPayloadFamily {
    CallableValues,
    CollectionFlows,
    ConditionalTypeRefinements,
    DeferredYields,
}

impl SemanticPayloadFamily {
    pub const ALL: [Self; 4] = [
        Self::CallableValues,
        Self::CollectionFlows,
        Self::ConditionalTypeRefinements,
        Self::DeferredYields,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CallableValues => "callable_values",
            Self::CollectionFlows => "collection_flows",
            Self::ConditionalTypeRefinements => "conditional_type_refinements",
            Self::DeferredYields => "deferred_yields",
        }
    }

    pub fn is_present(self, shard: &CompiledShard) -> bool {
        match self {
            Self::CallableValues => shard.callable_values().is_some(),
            Self::CollectionFlows => shard.collection_flows().is_some(),
            Self::ConditionalTypeRefinements => shard.conditional_type_refinements().is_some(),
            Self::DeferredYields => shard.deferred_yields().is_some(),
        }
    }
}

/// One reader connection serves one immutable active set. Integer keys never
/// leave their source schema before the joins that establish record identity.
pub fn attach_session_rows(
    connection: &Connection,
    session: &SessionSemanticCatalog,
) -> Result<(), CatalogError> {
    connection
        .execute(
            "ATTACH DATABASE ?1 AS session",
            [session.path.to_string_lossy().as_ref()],
        )
        .map_err(|error| CatalogError::sqlite("attach session semantic catalog", error))?;
    connection
        .execute_batch(
            "CREATE TEMP TABLE
                         active_shards( shard_key INTEGER NOT NULL, source_db TEXT
                         NOT NULL CHECK(source_db IN ('durable', 'session' )),
                         PRIMARY KEY(source_db, shard_key) ) STRICT;",
        )
        .map_err(|error| CatalogError::sqlite("create active shard membership", error))?;
    // Membership is decided at activation, after pack verification. A pack
    // quarantined mid-session keeps serving this active set, like decoded
    // shards. Rechecking pack state per row also traverses the manifest BLOB
    // overflow chain to reach its late state column.
    for table in [
        "catalog_semantic_rows_indexed_shards",
        "catalog_semantic_payload_families",
        "catalog_declaration_types",
        "catalog_declaration_members",
        "catalog_declaration_names",
        "catalog_member_aliases",
        "catalog_declaration_relations",
        "catalog_generator_rules",
        "catalog_procedure_summaries",
        "catalog_collection_flows",
        "catalog_conditional_type_refinements",
        "catalog_deferred_yields",
        "catalog_runtime_value_payloads",
        "catalog_runtime_exposures",
        "catalog_runtime_behaviors",
        "catalog_runtime_contract_payloads",
        "catalog_callable_value_facts",
        "catalog_callable_value_coverage",
        "catalog_anonymous_callable_identities",
        "catalog_anonymous_callable_identity_anchors",
        "catalog_anonymous_callable_signature_shapes",
    ] {
        let legacy =
            table.starts_with("catalog_callable_") || table.starts_with("catalog_anonymous_");
        let mut branches = Vec::new();
        for (schema, source) in [("main", "durable"), ("session", "session")] {
            let join = if legacy {
                "s.manifest_digest=r.manifest_digest AND s.shard_id=r.shard_id"
            } else {
                "s.shard_key=r.shard_key"
            };
            let identity = if legacy {
                String::new()
            } else {
                "s.manifest_digest,s.shard_id,".to_owned()
            };
            let record_join = match table {
                "catalog_declaration_names" => format!(
                    "JOIN {schema}.catalog_declaration_types owner
                     ON owner.record_key=r.record_key
                     AND owner.shard_key=r.shard_key"
                ),
                "catalog_member_aliases" => format!(
                    "JOIN {schema}.catalog_declaration_members owner
                     ON owner.record_key=r.member_key
                     AND owner.shard_key=r.shard_key"
                ),
                _ => String::new(),
            };
            branches.push(format!(
                "SELECT '{source}' AS
                         source_db, {identity}r.* FROM {schema}.{table} r JOIN
                         {schema}.catalog_semantic_rows_indexed_shards s ON {join}
                         JOIN temp.active_shards a ON a.shard_key=s.shard_key AND
                         a.source_db='{source}'
                         {record_join} WHERE s.index_version=4"
            ));
        }
        connection
            .execute_batch(&format!(
                "CREATE TEMP VIEW active_{table} AS {}",
                branches.join(" UNION ALL ")
            ))
            .map_err(|error| CatalogError::sqlite("create active semantic row view", error))?;
    }
    connection
        .execute_batch(
            "CREATE TEMP VIEW active_catalog_packs AS
            SELECT DISTINCT source_db,manifest_digest,'verified' AS state
            FROM active_catalog_semantic_rows_indexed_shards",
        )
        .map_err(|error| CatalogError::sqlite("create active pack view", error))?;
    for table in [
        "catalog_pack_shards",
        "catalog_selectors",
        "catalog_exact_go_source_sets",
        "catalog_exact_go_source_files",
        "catalog_exact_go_packages",
        "catalog_exact_go_package_files",
    ] {
        // Session metadata intentionally carries only the columns its readers
        // need. Project the common contract rather than UNIONing table shapes.
        let projection = match table {
            "catalog_pack_shards" => "r.manifest_digest,r.shard_id",
            "catalog_selectors" => "r.manifest_digest,r.shard_id,r.artifact_sha256",
            _ => "r.*",
        };
        let shard_predicate = if matches!(table, "catalog_pack_shards" | "catalog_selectors") {
            "AND s.shard_id=r.shard_id"
        } else {
            ""
        };
        let mut branches = Vec::new();
        for (schema, source) in [("main", "durable"), ("session", "session")] {
            branches.push(format!(
                "SELECT '{source}' AS
                         source_db, {projection} FROM {schema}.{table} r WHERE
                         EXISTS(SELECT 1 FROM
                         {schema}.catalog_semantic_rows_indexed_shards s JOIN
                         temp.active_shards a ON a.shard_key=s.shard_key AND
                         a.source_db='{source}'
                         WHERE s.manifest_digest=r.manifest_digest AND
                         s.index_version=4 {shard_predicate})"
            ));
        }
        connection
            .execute_batch(&format!(
                "CREATE TEMP VIEW active_{table} AS {}",
                branches.join(" UNION ALL ")
            ))
            .map_err(|error| CatalogError::sqlite("create active source view", error))?;
    }
    Ok(())
}

/// Resolve the selected shard's database-local key before adding membership.
/// The old reader preferred a durable publication when both copies exist.
#[cfg(any(test, feature = "test-support"))]
pub fn select_active_shard(
    connection: &Connection,
    manifest: &str,
    shard: &str,
) -> Result<bool, CatalogError> {
    if select_active_shard_source(connection, manifest, shard, "durable")?.is_some() {
        return Ok(true);
    }
    select_active_shard_source(connection, manifest, shard, "session").map(|key| key.is_some())
}

/// Publish one complete source shard. All facts and the completeness marker
/// commit together; no query decodes or reconstructs an installed-pack index.
pub fn publish_semantic_rows(
    transaction: &Transaction<'_>,
    manifest: &CompiledPackManifest,
    shard: &CompiledShard,
) -> Result<bool, CatalogError> {
    use super::json_text;
    use crate::analyzer::semantic::oracle::dispatch::authored_procedure_target_identity;
    use crate::analyzer::semantic_model::model::{RuleTrigger, TypeKind};
    use crate::analyzer::semantic_model::overlay::{
        project_hierarchy_relation, relation_kind_label, terminal_name,
    };
    use crate::analyzer::semantic_model::runtime::procedure_summary_minimum_actual_count;
    use brokk_bifrost_core::analyzer::model::semantic_pack_realm;
    use std::collections::HashSet;

    // Immutable content is already complete. Keep its database-local key stable
    // while active-set reader connections hold membership in that generation.
    let indexed: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1
                         FROM catalog_semantic_rows_indexed_shards WHERE
                         manifest_digest=?1 AND shard_id=?2 AND index_version=4)",
            params![manifest.content_sha256, shard.shard_id()],
            |row| row.get(0),
        )
        .map_err(|error| CatalogError::sqlite("check semantic shard publication", error))?;
    if indexed {
        return Ok(false);
    }
    transaction
        .execute(
            "INSERT INTO
                         catalog_semantic_rows_indexed_shards(manifest_digest,
                         shard_id, index_version) VALUES(?1, ?2, 4)",
            params![manifest.content_sha256, shard.shard_id()],
        )
        .map_err(|error| CatalogError::sqlite("publish semantic shard marker", error))?;
    let shard_key = transaction.last_insert_rowid();
    for family in SemanticPayloadFamily::ALL {
        if family.is_present(shard) {
            transaction.execute(
                "INSERT INTO catalog_semantic_payload_families(shard_key, family) VALUES(?1, ?2)",
                params![shard_key, family.as_str()],
            ).map_err(|error| CatalogError::sqlite("publish semantic payload family", error))?;
        }
    }
    if let Some((types, members, relations)) = shard.payload().declaration_facts() {
        for fact in types {
            let path = match &fact.locator {
                Locator::Source { path, .. } => Some(path.as_str()),
                _ => None,
            };
            let json = json_text(fact, "type record")?;
            transaction
                .prepare_cached(
                    "INSERT INTO
                         catalog_declaration_types(shard_key, record_id,
                         authored_path, record_json) VALUES(?1, ?2, ?3, ?4)",
                )
                .and_then(|mut statement| {
                    statement.execute(params![shard_key, fact.id, path, json])
                })
                .map_err(|error| CatalogError::sqlite("publish type record", error))?;
            let key = transaction.last_insert_rowid();
            let mut seen = HashSet::new();
            for name in std::iter::once(fact.name.as_str())
                .chain(fact.aliases.iter().map(String::as_str))
                .chain(std::iter::once(terminal_name(&fact.name)))
            {
                if !seen.insert(name) {
                    continue;
                }
                let identity = name == fact.name || fact.aliases.iter().any(|alias| alias == name);
                transaction
                    .prepare_cached(
                        "INSERT INTO
                         catalog_declaration_names(shard_key, record_key, name,
                         language, namespace, identity_name) VALUES(?1, ?2, ?3, ?4,
                         ?5, ?6)",
                    )
                    .map_err(|error| CatalogError::sqlite("prepare semantic record", error))?
                    .execute(params![
                        shard_key,
                        key,
                        name,
                        manifest.language,
                        if fact.type_kind == TypeKind::Module {
                            "module"
                        } else {
                            "type"
                        },
                        identity
                    ])
                    .map_err(|error| CatalogError::sqlite("publish type name", error))?;
            }
            for hierarchy in &fact.hierarchy {
                let edge = project_hierarchy_relation(&fact.id, hierarchy);
                transaction
                    .prepare_cached(
                        "INSERT INTO
                         catalog_declaration_relations(shard_key, origin,
                         record_id, from_id, to_id, relation_kind,
                         declaration_ordinal) VALUES(?1, 'type_hierarchy' , ?2, ?3,
                         ?4, ?5, ?6)",
                    )
                    .map_err(|error| CatalogError::sqlite("prepare semantic record", error))?
                    .execute(params![
                        shard_key,
                        edge.id,
                        edge.from,
                        edge.to,
                        edge.kind,
                        edge.declaration_ordinal
                    ])
                    .map_err(|error| CatalogError::sqlite("publish hierarchy edge", error))?;
            }
        }
        for fact in members {
            let path = match &fact.locator {
                Locator::Source { path, .. } => Some(path.as_str()),
                _ => None,
            };
            transaction
                .prepare_cached(
                    "INSERT INTO
                         catalog_declaration_members(shard_key, record_id,
                         owner_id, name, language, authored_path, record_json)
                         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                )
                .map_err(|error| CatalogError::sqlite("prepare semantic record", error))?
                .execute(params![
                    shard_key,
                    fact.id,
                    fact.owner,
                    fact.name,
                    manifest.language,
                    path,
                    json_text(fact, "member record")?
                ])
                .map_err(|error| CatalogError::sqlite("publish member record", error))?;
            let key = transaction.last_insert_rowid();
            for alias in &fact.aliases {
                transaction
                    .prepare_cached(
                        "INSERT INTO
                         catalog_member_aliases(shard_key, member_key, alias)
                         VALUES(?1, ?2, ?3)",
                    )
                    .map_err(|error| CatalogError::sqlite("prepare semantic record", error))?
                    .execute(params![shard_key, key, alias])
                    .map_err(|error| CatalogError::sqlite("publish member alias", error))?;
            }
        }
        for fact in relations {
            transaction
                .prepare_cached(
                    "INSERT INTO
                         catalog_declaration_relations(shard_key, origin,
                         record_id, from_id, to_id, relation_kind) VALUES(?1,
                         'relation_fact' , ?2, ?3, ?4, ?5)",
                )
                .map_err(|error| CatalogError::sqlite("prepare semantic record", error))?
                .execute(params![
                    shard_key,
                    fact.id,
                    fact.from,
                    fact.to,
                    relation_kind_label(fact.relation_kind)
                ])
                .map_err(|error| CatalogError::sqlite("publish relation fact", error))?;
        }
    }
    if let Some(rules) = shard.payload().generator_rules() {
        for rule in rules {
            let (family, key, member) = match &rule.trigger {
                RuleTrigger::LanguageConstruct { construct } => {
                    ("language-construct", construct, None)
                }
                RuleTrigger::Annotation { name } => ("annotation", name, None),
                RuleTrigger::AnnotatedField { annotation, .. } => ("annotation", annotation, None),
                RuleTrigger::MacroInvocation { name } => ("macro", name, None),
                RuleTrigger::GeneratorInvocation { name } => ("generator", name, None),
                RuleTrigger::ResolvedOwner { owner } => ("owner", owner, None),
                RuleTrigger::ResolvedCall { owner, name } => ("call", owner, Some(name)),
            };
            transaction
                .prepare_cached(
                    "INSERT INTO
                         catalog_generator_rules(shard_key, record_id,
                         trigger_family, trigger_key, call_member, record_json)
                         VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
                )
                .map_err(|error| CatalogError::sqlite("prepare semantic record", error))?
                .execute(params![
                    shard_key,
                    rule.id,
                    family,
                    key,
                    member,
                    json_text(rule, "generator rule")?
                ])
                .map_err(|error| CatalogError::sqlite("publish generator rule", error))?;
        }
    }
    if let Some(summaries) = shard.payload().procedure_summaries() {
        for summary in summaries {
            let target = &summary.target;
            let identity = authored_procedure_target_identity(&target.path, &target.symbol);
            let owner = identity.as_ref().map(|(owner, _)| owner.as_ref());
            let member = identity.as_ref().map(|(_, member)| *member);
            let minimum = if target.variadic {
                procedure_summary_minimum_actual_count(target)
            } else {
                target.parameter_count
            };
            let optional = target
                .formals
                .iter()
                .any(|formal| formal.optional)
                .then(|| {
                    u32::try_from(
                        target
                            .formals
                            .iter()
                            .filter(|formal| !formal.optional)
                            .count(),
                    )
                    .expect("validated formal count fits u32")
                });
            transaction
                .prepare_cached(
                    "INSERT INTO
                         catalog_procedure_summaries(shard_key, language,
                         target_path, target_symbol, owner_fqn, member,
                         has_receiver, declared_arity, variadic,
                         minimum_actual_count, optional_minimum, record_json)
                         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                )
                .map_err(|error| CatalogError::sqlite("prepare semantic record", error))?
                .execute(params![
                    shard_key,
                    semantic_pack_realm(&manifest.language),
                    target.path,
                    target.symbol,
                    owner,
                    member,
                    target.has_receiver,
                    target.parameter_count,
                    target.variadic,
                    minimum,
                    optional,
                    json_text(summary, "procedure summary")?
                ])
                .map_err(|error| CatalogError::sqlite("publish procedure summary", error))?;
        }
    }
    if let Some(payload) = shard.collection_flows() {
        for fact in &payload.flows {
            transaction
                .prepare_cached(
                    "INSERT INTO
                         catalog_collection_flows(shard_key, callable, record_json)
                         VALUES(?1, ?2, ?3)",
                )
                .map_err(|error| CatalogError::sqlite("prepare semantic record", error))?
                .execute(params![
                    shard_key,
                    fact.callable,
                    json_text(fact, "collection flow")?
                ])
                .map_err(|error| CatalogError::sqlite("publish collection flow", error))?;
        }
    }
    if let Some(payload) = shard.conditional_type_refinements() {
        for fact in &payload.refinements {
            transaction
                .prepare_cached(
                    "INSERT INTO
                         catalog_conditional_type_refinements(shard_key, callable,
                         record_json) VALUES(?1, ?2, ?3)",
                )
                .map_err(|error| CatalogError::sqlite("prepare semantic record", error))?
                .execute(params![
                    shard_key,
                    fact.payload.callable,
                    json_text(fact, "conditional type refinement")?
                ])
                .map_err(|error| {
                    CatalogError::sqlite("publish conditional type refinement", error)
                })?;
        }
    }
    if let Some(payload) = shard.deferred_yields() {
        for fact in &payload.yields {
            transaction
                .prepare_cached(
                    "INSERT INTO
                         catalog_deferred_yields(shard_key, factory, resume,
                         handle_type, record_json) VALUES(?1, ?2, ?3, ?4, ?5)",
                )
                .map_err(|error| CatalogError::sqlite("prepare semantic record", error))?
                .execute(params![
                    shard_key,
                    fact.factory,
                    fact.resume,
                    fact.handle_type,
                    json_text(fact, "deferred yield")?
                ])
                .map_err(|error| CatalogError::sqlite("publish deferred yield", error))?;
        }
    }
    if let Some(payload) = shard.runtime_values() {
        transaction
            .prepare_cached(
                "INSERT INTO
                         catalog_runtime_value_payloads(shard_key, record_json)
                         VALUES(?1, ?2)",
            )
            .map_err(|error| CatalogError::sqlite("prepare semantic record", error))?
            .execute(params![shard_key, json_text(payload, "runtime values")?])
            .map_err(|error| CatalogError::sqlite("publish runtime values", error))?;
        let key = transaction.last_insert_rowid();
        for (ordinal, exposure) in payload.exposures.iter().enumerate() {
            transaction
                .prepare_cached(
                    "INSERT INTO
                         catalog_runtime_exposures(shard_key, payload_key,
                         exposure_ordinal, exposure_id, binding_name) VALUES(?1,
                         ?2, ?3, ?4, ?5)",
                )
                .map_err(|error| CatalogError::sqlite("prepare semantic record", error))?
                .execute(params![
                    shard_key,
                    key,
                    i64::try_from(ordinal).expect("validated exposure count fits i64"),
                    exposure.exposure_id,
                    exposure.binding_name
                ])
                .map_err(|error| CatalogError::sqlite("publish runtime exposure", error))?;
        }
        for (ordinal, behavior) in payload.behaviors.iter().enumerate() {
            transaction
                .prepare_cached(
                    "INSERT INTO
                         catalog_runtime_behaviors(shard_key, payload_key,
                         behavior_ordinal, exposure_id, container_member)
                         VALUES(?1, ?2, ?3, ?4, ?5)",
                )
                .map_err(|error| CatalogError::sqlite("prepare semantic record", error))?
                .execute(params![
                    shard_key,
                    key,
                    i64::try_from(ordinal).expect("validated behavior count fits i64"),
                    behavior.exposure_id,
                    behavior.container_member
                ])
                .map_err(|error| CatalogError::sqlite("publish runtime behavior", error))?;
        }
    }
    if let Some(payload) = shard.runtime_contracts() {
        transaction
            .prepare_cached(
                "INSERT INTO
                         catalog_runtime_contract_payloads(shard_key, record_json)
                         VALUES(?1, ?2)",
            )
            .map_err(|error| CatalogError::sqlite("prepare semantic record", error))?
            .execute(params![shard_key, json_text(payload, "runtime contracts")?])
            .map_err(|error| CatalogError::sqlite("publish runtime contracts", error))?;
    }
    super::publish_callable_value_rows(
        transaction,
        &manifest.content_sha256,
        shard.shard_id(),
        shard.callable_values(),
    )?;
    Ok(true)
}

/// Select a shard from its actual publishing schema; no catalog fallback.
pub fn select_active_shard_source(
    connection: &Connection,
    manifest: &str,
    shard: &str,
    source: &str,
) -> Result<Option<i64>, CatalogError> {
    assert!(matches!(source, "durable" | "session"));
    let schema = if source == "durable" {
        "main"
    } else {
        "session"
    };
    let selected = connection
        .query_row(
            &format!(
                "INSERT OR REPLACE INTO
                         temp.active_shards(shard_key, source_db) SELECT s.shard_key,
                         ?3 FROM {schema}.catalog_semantic_rows_indexed_shards s
                         JOIN {schema}.catalog_packs p ON p.manifest_digest=s.manifest_digest
                         WHERE s.manifest_digest=?1 AND s.shard_id=?2 AND
                         s.index_version=4 AND p.state='verified' RETURNING shard_key"
            ),
            params![manifest, shard, source],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| CatalogError::sqlite("select active source shard", error))?;
    #[cfg(debug_assertions)]
    if selected.is_some() {
        let verified: bool = connection
            .query_row(
                &format!(
                    "SELECT state='verified' FROM {schema}.catalog_packs WHERE manifest_digest=?1"
                ),
                [manifest],
                |row| row.get(0),
            )
            .map_err(|error| CatalogError::sqlite("assert selected pack verification", error))?;
        debug_assert!(
            verified,
            "active membership requires verified pack {source}:{manifest}"
        );
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic_model::catalog::open_session_semantic_catalog;
    use brokk_bifrost_test_macros::hardwon;
    use rusqlite::OpenFlags;

    fn seed(connection: &Connection, manifest: &str, id: &str) -> i64 {
        connection
            .execute(
                "INSERT OR IGNORE INTO catalog_packs(manifest_digest, state)
                 VALUES(?1, 'verified')",
                [manifest],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO
                         catalog_pack_shards(manifest_digest, shard_id) VALUES(?1,
                         ?2)",
                params![manifest, id],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO
                         catalog_semantic_rows_indexed_shards(manifest_digest,
                         shard_id, index_version) VALUES(?1, ?2, 4)",
                params![manifest, id],
            )
            .unwrap();
        let shard = connection.last_insert_rowid();
        connection
            .execute(
                "INSERT INTO
                         catalog_declaration_types(shard_key, record_id,
                         record_json) VALUES(?1, ?2, ?3)",
                params![shard, id, r#"{"type_kind":"trait"}"#],
            )
            .unwrap();
        let record = connection.last_insert_rowid();
        connection
            .execute(
                "INSERT INTO
                         catalog_declaration_names(shard_key, record_key, name,
                         language, namespace, identity_name) VALUES(?1, ?2, ?3,
                         'rust' , 'type' , 1)",
                params![shard, record, id],
            )
            .unwrap();
        shard
    }

    #[test]
    #[hardwon(
        "#6685: per-row pack verification changed already selected membership after quarantine"
    )]
    fn activation_checks_verification_once_for_both_sources() {
        let durable = open_session_semantic_catalog().unwrap();
        let session = open_session_semantic_catalog().unwrap();
        // Session catalogs only publish verified rows. Permit the negative
        // fixture state to exercise the identical membership SQL in both schemas.
        durable
            .connection
            .execute_batch("PRAGMA ignore_check_constraints=ON")
            .unwrap();
        let manifest = "1".repeat(64);
        seed(&durable.connection, &manifest, "s");
        seed(&session.connection, &manifest, "s");
        attach_session_rows(&durable.connection, &session).unwrap();
        for (source, schema) in [("durable", "main"), ("session", "session")] {
            durable
                .connection
                .execute_batch(&format!(
                    "UPDATE {schema}.catalog_packs SET state='quarantined'"
                ))
                .unwrap();
            assert!(
                select_active_shard_source(&durable.connection, &manifest, "s", source)
                    .unwrap()
                    .is_none()
            );
            durable
                .connection
                .execute_batch(&format!(
                    "UPDATE {schema}.catalog_packs SET state='verified'"
                ))
                .unwrap();
            assert!(
                select_active_shard_source(&durable.connection, &manifest, "s", source)
                    .unwrap()
                    .is_some()
            );
            durable
                .connection
                .execute_batch(&format!(
                    "UPDATE {schema}.catalog_packs SET state='quarantined'"
                ))
                .unwrap();
        }
        assert_eq!(
            durable
                .connection
                .query_row(
                    "SELECT count(*) FROM active_catalog_declaration_types",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            2
        );
        assert_eq!(
            durable
                .connection
                .query_row(
                    "SELECT count(*) FROM active_catalog_packs WHERE state='verified'",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            2
        );
        assert_eq!(
            durable
                .connection
                .query_row(
                    "SELECT count(*) FROM active_catalog_pack_shards",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            2
        );
    }

    #[test]
    fn migration_25_invalidates_old_publications_and_requires_exact_presence() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch("PRAGMA foreign_keys=ON;
            CREATE TABLE catalog_packs(manifest_digest TEXT PRIMARY KEY,state TEXT);
            CREATE TABLE catalog_pack_shards(manifest_digest TEXT,shard_id TEXT,PRIMARY KEY(manifest_digest,shard_id));").unwrap();
        connection
            .execute_batch(super::super::db::CALLABLE_VALUE_ROWS_SQL)
            .unwrap();
        connection
            .execute_batch(super::super::db::SEMANTIC_ROWS_SQL)
            .unwrap();
        connection.execute_batch(r#"INSERT INTO catalog_packs VALUES('pack','verified');
            INSERT INTO catalog_pack_shards VALUES('pack','s');
            INSERT INTO catalog_semantic_rows_indexed_shards VALUES(1,'pack','s',2);
            INSERT INTO catalog_declaration_types(shard_key,record_id,record_json) VALUES(1,'type','{"type_kind":"trait"}');
            INSERT INTO catalog_procedure_summaries(shard_key,language,target_path,target_symbol,has_receiver,declared_arity,variadic,minimum_actual_count,record_json)
            VALUES(1,'rust','p','f',0,0,0,0,'{"id":"old"}');"#).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT count(*) FROM catalog_procedure_summaries",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
        connection
            .execute_batch(super::super::db::SEMANTIC_ROW_QUESTIONS_SQL)
            .unwrap();
        for table in [
            "catalog_semantic_rows_indexed_shards",
            "catalog_declaration_types",
            "catalog_procedure_summaries",
        ] {
            assert_eq!(
                connection
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                        .get::<_, i64>(0))
                    .unwrap(),
                0,
                "{table}"
            );
        }
        assert!(
            connection
                .execute(
                    "INSERT INTO catalog_semantic_rows_indexed_shards VALUES(1,'pack','s',3,2)",
                    []
                )
                .is_err()
        );
        assert!(
            connection
                .execute(
                    "INSERT INTO catalog_semantic_rows_indexed_shards VALUES(1,'pack','s',2,0)",
                    []
                )
                .is_err()
        );
        assert!(connection.execute("INSERT INTO catalog_semantic_rows_indexed_shards(shard_key,manifest_digest,shard_id,index_version) VALUES(1,'pack','s',3)",[]).is_err());
        connection
            .execute(
                "INSERT INTO catalog_semantic_rows_indexed_shards VALUES(1,'pack','s',3,1)",
                [],
            )
            .unwrap();
        connection.execute(r#"INSERT INTO catalog_procedure_summaries(shard_key,language,target_path,target_symbol,has_receiver,declared_arity,variadic,minimum_actual_count,record_json) VALUES(1,'rust','p','f',0,0,0,0,'{"id":"new"}')"#,[]).unwrap();
        assert_eq!(connection.query_row("SELECT record_id FROM catalog_procedure_summaries WHERE shard_key=1 AND record_id='new'",[],|row|row.get::<_,String>(0)).unwrap(),"new");
        assert_eq!(connection.query_row("SELECT hidden FROM pragma_table_xinfo('catalog_procedure_summaries') WHERE name='record_id'",[],|row|row.get::<_,i64>(0)).unwrap(),2,"record ID must be virtual");
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
    }

    #[test]
    fn every_semantic_row_family_has_valid_json_and_cascading_foreign_keys() {
        let catalog = open_session_semantic_catalog().unwrap();
        let connection = &catalog.connection;
        let manifest = "3".repeat(64);
        let shard = seed(connection, &manifest, "schema-boundary");
        // Exercise empty-in-the-real-pack companion families too. This checks
        // schema ownership and cleanup, independently of the Rust publisher.
        connection
            .execute_batch(&format!(
                r#"INSERT INTO catalog_semantic_payload_families(shard_key, family)
                         VALUES({shard}, 'callable_values'); INSERT INTO
                         catalog_declaration_members(shard_key, record_id,
                         owner_id, name, language, record_json) VALUES({shard}, 'm'
                         , 't' , 'f' , 'rust' , '{{}}' ); INSERT INTO
                         catalog_member_aliases(shard_key, member_key, alias)
                         VALUES({shard}, 1, 'alias' ); INSERT INTO
                         catalog_declaration_relations(shard_key, origin,
                         record_id, from_id, to_id, relation_kind) VALUES({shard},
                         'relation_fact' , 'r' , 't' , 'u' , 'extends' ); INSERT
                         INTO catalog_generator_rules(shard_key, record_id,
                         trigger_family, trigger_key, record_json) VALUES({shard},
                         'rule' , 'annotation' , 'a' , '{{}}' ); INSERT INTO
                         catalog_procedure_summaries(shard_key, language,
                         target_path, target_symbol, has_receiver, declared_arity,
                         variadic, minimum_actual_count, record_json)
                         VALUES({shard}, 'rust' , 'p' , 'f' , 0, 0, 0, 0, '{{}}' );
                         INSERT INTO catalog_collection_flows(shard_key, callable,
                         record_json) VALUES({shard}, 'm' , '{{}}' ); INSERT INTO
                         catalog_conditional_type_refinements(shard_key, callable,
                         record_json) VALUES({shard}, 'm' , '{{}}' ); INSERT INTO
                         catalog_deferred_yields(shard_key, factory, resume,
                         handle_type, record_json) VALUES({shard}, 'm' , 'r' , 't'
                         , '{{}}' ); INSERT INTO
                         catalog_runtime_value_payloads(shard_key, record_json)
                         VALUES({shard}, '{{}}' ); INSERT INTO
                         catalog_runtime_exposures(shard_key, payload_key,
                         exposure_ordinal, exposure_id, binding_name)
                         VALUES({shard}, 1, 0, 'e' , 'binding' ); INSERT INTO
                         catalog_runtime_behaviors(shard_key, payload_key,
                         behavior_ordinal, exposure_id, container_member)
                         VALUES({shard}, 1, 0, 'e' , 'get' ); INSERT INTO
                         catalog_runtime_contract_payloads(shard_key, record_json)
                         VALUES({shard}, '{{}}' );"#
            ))
            .unwrap();
        let tables = connection
            .prepare(
                "SELECT name FROM
                         sqlite_schema WHERE type='table' AND name NOT IN
                         ('catalog_packs', 'catalog_pack_shards' )",
            )
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let families = tables
            .into_iter()
            .filter(|table| {
                connection
                    .prepare(&format!("SELECT shard_key FROM {table} LIMIT 0"))
                    .is_ok()
            })
            .collect::<Vec<_>>();
        assert_eq!(families.len(), 16);
        for table in &families {
            // Deleting one parent must probe each child through a leading key,
            // rather than scanning a pack-sized family once per parent.
            let ids = connection
                .prepare(&format!(
                    "SELECT DISTINCT id FROM pragma_foreign_key_list('{table}')"
                ))
                .unwrap()
                .query_map([], |row| row.get::<_, i64>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            for id in ids {
                let columns = connection
                    .prepare(&format!(
                        "SELECT \"from\" FROM
                         pragma_foreign_key_list('{table}') WHERE id=?1 ORDER BY
                         seq"
                    ))
                    .unwrap()
                    .query_map([id], |row| row.get::<_, String>(0))
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                let predicates = columns
                    .iter()
                    .map(|column| format!("{column}=NULL"))
                    .collect::<Vec<_>>()
                    .join(" AND ");
                let plan = connection
                    .prepare(&format!(
                        "EXPLAIN QUERY PLAN SELECT rowid FROM {table} WHERE {predicates}"
                    ))
                    .unwrap()
                    .query_map([], |row| row.get::<_, String>(3))
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                assert!(
                    plan.iter()
                        .all(|line| !line.contains("SCAN ") && !line.contains("AUTOMATIC")),
                    "{table} {columns:?}: {plan:?}"
                );
            }
        }
        for table in &families {
            let count: i64 = connection
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 1, "{table}: path must run before asserting cascade");
            if connection
                .prepare(&format!("SELECT record_json FROM {table} LIMIT 0"))
                .is_ok()
            {
                assert!(
                    connection
                        .execute(&format!("UPDATE {table} SET record_json='[]'"), [])
                        .is_err(),
                    "{table}"
                );
            }
        }
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
        connection
            .execute(
                "DELETE FROM catalog_semantic_rows_indexed_shards WHERE shard_key=?1",
                [shard],
            )
            .unwrap();
        for table in &families {
            assert_eq!(
                connection
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                        .get::<_, i64>(0))
                    .unwrap(),
                0,
                "{table}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    #[hardwon("#6685: macOS temp paths hold a /var symlink that NOFOLLOW readers rejected")]
    fn session_rows_attach_to_a_nofollow_reader_through_a_symlinked_temp_root() {
        use crate::analyzer::semantic_model::catalog::open_session_semantic_catalog_in;

        let parent = tempfile::tempdir().unwrap();
        let real = parent.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let linked = parent.path().join("linked");
        std::os::unix::fs::symlink(&real, &linked).unwrap();
        let durable = open_session_semantic_catalog().unwrap();
        let session = open_session_semantic_catalog_in(&linked).unwrap();
        assert!(
            session
                .path
                .starts_with(std::fs::canonicalize(&real).unwrap())
        );
        // Production readers open the durable catalog with these flags, and an
        // attached database inherits SQLITE_OPEN_NOFOLLOW.
        let reader = Connection::open_with_flags(
            &durable.path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .unwrap();
        attach_session_rows(&reader, &session).unwrap();
        let session_manifest = "3".repeat(64);
        seed(&session.connection, &session_manifest, "linked-session");
        assert!(select_active_shard(&reader, &session_manifest, "linked-session").unwrap());
    }

    #[test]
    #[hardwon("#6685: attach a session WAL before its first pack registration")]
    fn active_views_isolate_inactive_shards_and_database_local_keys() {
        let durable = open_session_semantic_catalog().unwrap();
        let session = open_session_semantic_catalog().unwrap();
        let main_manifest = "1".repeat(64);
        let session_manifest = "2".repeat(64);
        seed(&durable.connection, &main_manifest, "active-main");
        seed(&durable.connection, &main_manifest, "inactive-main");
        let reader =
            Connection::open_with_flags(&durable.path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        attach_session_rows(&reader, &session).unwrap();
        assert!(select_active_shard(&reader, &main_manifest, "active-main").unwrap());
        // Attach before the first session registration. Schema initialization
        // creates a WAL database, but there have been no session pack writes.
        assert_eq!(
            reader
                .query_row("PRAGMA session.journal_mode", [], |row| row
                    .get::<_, String>(0))
                .unwrap(),
            "wal"
        );
        assert_eq!(
            reader
                .query_row(
                    "SELECT count(*) FROM active_catalog_declaration_types",
                    [],
                    |row| { row.get::<_, i64>(0) }
                )
                .unwrap(),
            1
        );
        seed(&session.connection, &session_manifest, "active-session");
        assert!(select_active_shard(&reader, &session_manifest, "active-session").unwrap());
        let rows = reader
            .prepare(
                "SELECT source_db, name,
                         record_id FROM active_catalog_declaration_names JOIN
                         active_catalog_declaration_types USING(source_db,
                         shard_key, record_key) ORDER BY source_db",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            rows,
            vec![
                ("durable".into(), "active-main".into(), "active-main".into()),
                (
                    "session".into(),
                    "active-session".into(),
                    "active-session".into()
                )
            ]
        );
        // Both databases start at record/shard key 1. Each branch joined its
        // own schema before UNION, and the indexed inactive row is invisible.
        assert_eq!(
            reader
                .query_row(
                    "SELECT count(*) FROM active_catalog_declaration_types",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            2
        );
        assert_eq!(
            reader
                .query_row(
                    "SELECT count(*) FROM main.catalog_declaration_types",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            2
        );
    }
}

#[cfg(test)]
mod payload_family_tests {
    use super::*;

    #[test]
    fn payload_family_check_matches_publisher_vocabulary() {
        let catalog = super::super::open_session_semantic_catalog().unwrap();
        let sql: String = catalog.connection.query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='catalog_semantic_payload_families'",
            [], |row| row.get(0)).unwrap();
        // This table's only quoted SQL values are its family CHECK literals.
        let schema = sql
            .split('\'')
            .skip(1)
            .step_by(2)
            .collect::<std::collections::BTreeSet<_>>();
        let publisher = SemanticPayloadFamily::ALL
            .into_iter()
            .map(SemanticPayloadFamily::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(schema, publisher);
    }

    #[test]
    fn migration_26_invalidates_publications_and_preserves_summary_id_index() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch("PRAGMA foreign_keys=ON;
            CREATE TABLE catalog_packs(manifest_digest TEXT PRIMARY KEY,state TEXT);
            CREATE TABLE catalog_pack_shards(manifest_digest TEXT,shard_id TEXT,PRIMARY KEY(manifest_digest,shard_id));").unwrap();
        for sql in [
            super::super::db::CALLABLE_VALUE_ROWS_SQL,
            super::super::db::SEMANTIC_ROWS_SQL,
            super::super::db::SEMANTIC_ROW_QUESTIONS_SQL,
        ] {
            connection.execute_batch(sql).unwrap();
        }
        connection
            .execute_batch(
                r#"INSERT INTO catalog_packs VALUES('pack','verified');
            INSERT INTO catalog_pack_shards VALUES('pack','s');
            INSERT INTO catalog_semantic_rows_indexed_shards VALUES(1,'pack','s',3,1);
            INSERT INTO catalog_declaration_types(shard_key,record_id,record_json)
                VALUES(1,'type','{"type_kind":"trait"}');
            INSERT INTO catalog_procedure_summaries(shard_key,language,target_path,target_symbol,
                has_receiver,declared_arity,variadic,minimum_actual_count,record_json)
                VALUES(1,'rust','p','f',0,0,0,0,'{"id":"old"}');"#,
            )
            .unwrap();
        connection
            .execute_batch(super::super::db::SEMANTIC_PAYLOAD_FAMILIES_SQL)
            .unwrap();
        for table in [
            "catalog_semantic_rows_indexed_shards",
            "catalog_declaration_types",
            "catalog_procedure_summaries",
            "catalog_semantic_payload_families",
        ] {
            assert_eq!(
                connection
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                        .get::<_, i64>(0))
                    .unwrap(),
                0,
                "{table}"
            );
        }
        assert!(
            connection
                .execute(
                    "INSERT INTO catalog_semantic_rows_indexed_shards VALUES(1,'pack','s',3)",
                    []
                )
                .is_err()
        );
        connection
            .execute(
                "INSERT INTO catalog_semantic_rows_indexed_shards VALUES(1,'pack','s',4)",
                [],
            )
            .unwrap();
        for family in SemanticPayloadFamily::ALL {
            connection
                .execute(
                    "INSERT INTO catalog_semantic_payload_families VALUES(1,?1)",
                    [family.as_str()],
                )
                .unwrap();
        }
        assert!(
            connection
                .execute(
                    "INSERT INTO catalog_semantic_payload_families VALUES(1,'future_family')",
                    []
                )
                .is_err()
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT count(*) FROM catalog_semantic_payload_families",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            4
        );
        assert_eq!(connection.query_row("SELECT count(*) FROM sqlite_master WHERE type='index' AND name='catalog_procedure_summaries_record_id'", [],
            |row| row.get::<_, i64>(0)).unwrap(), 1);
        connection
            .execute("DELETE FROM catalog_semantic_rows_indexed_shards", [])
            .unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT count(*) FROM catalog_semantic_payload_families",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
    }
}
