//! Integration oracle for the catalog schema and its active-set views.
//! All unbounded snapshots below are test-local and die with this one query.

use super::*;
use crate::CancellationToken;
use crate::analyzer::semantic::oracle::dispatch::split_owner_member;
use crate::analyzer::semantic_model::DecodeLimits;
use crate::analyzer::semantic_model::artifact::{CompiledPayload, compiled_from_wire};
use crate::analyzer::semantic_model::catalog::{
    CatalogOptions, SessionPackSource, SessionPackSourceKind, validate_pack,
};
#[cfg(test)]
use crate::analyzer::semantic_model::runtime::SemanticModelRuntimeLimits;
use crate::analyzer::semantic_model::runtime::{
    EvidenceRank, MatcherIndexes, SemanticModelActivationEvidence, resolved_active_models_fixture,
};
use crate::analyzer::semantic_model::{
    CatalogPackSourceKind, CompiledSemanticModelPack, SemanticPackCatalog,
};
use crate::analyzer::workspace::EmptyAnalyzer;
use crate::{Language, TestProject};
use brokk_bifrost_semantic::analyzer::semantic_model::catalog::statements as questions;
use rusqlite::Connection;
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;

type Snapshot = BTreeMap<(String, Vec<String>), BTreeSet<String>>;

fn canonical(value: impl Serialize) -> String {
    serde_json::to_string(&serde_json::to_value(value).unwrap()).unwrap()
}

fn put(snapshot: &mut Snapshot, family: &str, key: Vec<String>, value: impl Serialize) {
    snapshot
        .entry((family.into(), key))
        .or_default()
        .insert(canonical(value));
}

#[track_caller]
fn active(shards: Vec<ActiveSemanticModelShard>) -> ResolvedActiveSemanticModels {
    let shards = shards.into_iter().map(Arc::new).collect::<Vec<_>>();
    resolved_active_models_fixture("catalog-row-parity", shards)
}

fn matcher_snapshot(active: &ResolvedActiveSemanticModels) -> Snapshot {
    let mut result = Snapshot::new();
    for (family, key, addresses) in active.indexes.parity_postings() {
        for address in addresses {
            let shard = &active.shards[address.shard as usize];
            let index = address.record as usize;
            let payload = shard.decoded().payload();
            let record = if family.starts_with("types_") {
                serde_json::to_value(&payload.declaration_facts().unwrap().0[index]).unwrap()
            } else if family.starts_with("members_") {
                serde_json::to_value(&payload.declaration_facts().unwrap().1[index]).unwrap()
            } else if family.starts_with("relations_") {
                serde_json::to_value(&payload.declaration_facts().unwrap().2[index]).unwrap()
            } else if family.starts_with("rules_") {
                serde_json::to_value(&payload.generator_rules().unwrap()[index]).unwrap()
            } else {
                serde_json::to_value(&payload.procedure_summaries().unwrap()[index]).unwrap()
            };
            put(
                &mut result,
                family,
                key.clone(),
                (
                    &shard.manifest.content_sha256,
                    shard.descriptor.shard_id.as_str(),
                    record,
                ),
            );
        }
    }
    result
}

fn sql_matcher_snapshot(connection: &Connection, expected: &Snapshot) -> Snapshot {
    let mut result = Snapshot::new();
    // Ask the production questions for every decoded posting key. Full record
    // reconstruction below independently catches surplus records and keys.
    for (family, key) in expected.keys() {
        let mut bindings = Vec::<(&str, String)>::new();
        let sql = match family.as_str() {
            "types_id" => {
                bindings.push((":id", key[0].clone()));
                questions::TYPES_BY_ID
            }
            "types_name" => {
                bindings.push((":name", key[0].clone()));
                questions::TYPES_BY_IDENTITY_NAME
            }
            "members_id" => {
                bindings.push((":id", key[0].clone()));
                questions::MEMBERS_BY_ID
            }
            "members_owner_name" => {
                bindings.extend([(":owner", key[0].clone()), (":name", key[1].clone())]);
                questions::MEMBERS_BY_OWNER_NAME
            }
            "relations_id" | "relations_from" | "relations_to" => {
                bindings.push((":id", key[0].clone()));
                match family.as_str() {
                    "relations_id" => questions::RELATIONS_BY_ID,
                    "relations_from" => questions::RELATIONS_FROM,
                    _ => questions::RELATIONS_TO,
                }
            }
            "rules_id" => {
                bindings.push((":id", key[0].clone()));
                questions::RULES_BY_ID
            }
            "rules_call" => {
                bindings.extend([(":owner", key[0].clone()), (":member", key[1].clone())]);
                questions::RULES_BY_CALL
            }
            "rules_construct" | "rules_annotation" | "rules_macro" | "rules_generator"
            | "rules_owner" => {
                let trigger = match family.as_str() {
                    "rules_construct" => "language-construct",
                    "rules_annotation" => "annotation",
                    "rules_macro" => "macro",
                    "rules_generator" => "generator",
                    _ => "owner",
                };
                bindings.extend([(":family", trigger.into()), (":key", key[0].clone())]);
                questions::RULES_BY_TRIGGER
            }
            "summaries_target" => {
                bindings.extend([
                    (":realm", key[0].clone()),
                    (":path", key[1].clone()),
                    (":symbol", key[2].clone()),
                    (":receiver", key[4].clone()),
                ]);
                questions::SUMMARY_TARGET_FAMILY
            }
            "summaries_member" => {
                bindings.extend([
                    (":realm", key[0].clone()),
                    (":owners", serde_json::to_string(&[&key[1]]).unwrap()),
                    (":member", key[2].clone()),
                    (":receiver", key[4].clone()),
                ]);
                questions::SUMMARY_MEMBER
            }
            _ => unreachable!("unknown decoded posting family: {family}"),
        };
        let params = bindings
            .iter()
            .map(|(name, value)| (*name, value as &dyn rusqlite::ToSql))
            .collect::<Vec<_>>();
        let mut statement = connection.prepare_cached(sql).unwrap();
        let rows = statement.query_map(params.as_slice(), |row| {
            if family.starts_with("summaries_") {
                let arity = key[5].parse::<i64>().unwrap();
                let variadic: bool = row.get("variadic")?;
                let declared: i64 = row.get("declared_arity")?;
                let include = match key[3].as_str() {
                    "fixed" => !variadic && declared == arity,
                    "variadic" => variadic && declared == arity,
                    "minimum" => variadic && row.get::<_,i64>("minimum_actual_count")? == arity,
                    "optional" => row.get::<_,Option<i64>>("optional_minimum")? == Some(arity) && declared == key[6].parse::<i64>().unwrap(),
                    _ => unreachable!(),
                };
                if !include { return Ok(None); }
            }
            let record = if family.starts_with("relations_") {
                json!({"id":row.get::<_,String>("record_id")?, "relation_kind":row.get::<_,String>("relation_kind")?, "from":row.get::<_,String>("from_id")?, "to":row.get::<_,String>("to_id")?})
            } else {
                serde_json::from_str::<Value>(&row.get::<_,String>("record_json")?).unwrap()
            };
            Ok(Some((row.get::<_,String>("manifest_digest")?, row.get::<_,String>("shard_id")?, record)))
        }).unwrap();
        for row in rows {
            if let Some(record) = row.unwrap() {
                put(&mut result, family, key.clone(), record);
            }
        }
    }
    result
}

fn records(connection: &Connection, table: &str, manifest: &str, shard: &str) -> Vec<Value> {
    let sql = match table {
        "catalog_declaration_types" => questions::ALL_TYPES,
        "catalog_declaration_members" => questions::ALL_MEMBERS,
        "catalog_generator_rules" => questions::RULES,
        "catalog_procedure_summaries" => questions::ALL_SUMMARIES,
        "catalog_collection_flows" => questions::ALL_COLLECTION_FLOWS,
        "catalog_conditional_type_refinements" => questions::ALL_CONDITIONAL_REFINEMENTS,
        "catalog_deferred_yields" => questions::ALL_DEFERRED_YIELDS,
        "catalog_runtime_value_payloads" => questions::ALL_RUNTIME_VALUES,
        "catalog_runtime_contract_payloads" => questions::ALL_RUNTIME_CONTRACTS,
        _ => unreachable!("unknown record family"),
    };
    let mut rows = connection
        .prepare_cached(sql)
        .unwrap()
        .query_map([], |row| {
            Ok((
                row.get::<_, String>("manifest_digest")?,
                row.get::<_, String>("shard_id")?,
                row.get::<_, i64>("record_key")?,
                row.get::<_, String>("record_json")?,
            ))
        })
        .unwrap()
        .map(Result::unwrap)
        .filter(|row| row.0 == manifest && row.1 == shard)
        .collect::<Vec<_>>();
    rows.sort_by_key(|row| row.2);
    rows.into_iter()
        .map(|row| serde_json::from_str(&row.3).unwrap())
        .collect()
}

fn row_shards(
    connection: &Connection,
    original: &[Arc<ActiveSemanticModelShard>],
) -> Vec<ActiveSemanticModelShard> {
    original
        .iter()
        .map(|shard| {
            let manifest = &shard.manifest.content_sha256;
            let id = shard.descriptor.shard_id.as_str();
            // Only the envelope metadata is reused. Every fact and companion is
            // replaced by records read from the scoped views, including empties.
            let mut wire = serde_json::to_value(shard.decoded()).unwrap();
            let payload = match shard.decoded().payload() {
                CompiledPayload::DeclarationFacts { .. } => {
                    let mut relations = connection.prepare_cached(questions::ALL_RELATIONS).unwrap().query_map([], |row| {
                        Ok((row.get::<_,String>("manifest_digest")?,row.get::<_,String>("shard_id")?,row.get::<_,String>("origin")?,row.get::<_,i64>("record_key")?,
                          json!({"id":row.get::<_,String>("record_id")?,"relation_kind":row.get::<_,String>("relation_kind")?,"from":row.get::<_,String>("from_id")?,"to":row.get::<_,String>("to_id")?})))
                    }).unwrap().map(Result::unwrap).filter(|row| row.0==*manifest && row.1==id && row.2=="relation_fact").collect::<Vec<_>>();
                    relations.sort_by_key(|row|row.3);
                    let relations=relations.into_iter().map(|row|row.4).collect::<Vec<_>>();
                    let mut payload = json!({"kind":"declaration_facts",
                    "types":records(connection,"catalog_declaration_types",manifest,id),
                    "members":records(connection,"catalog_declaration_members",manifest,id),
                    "relations":relations});
                    // The assembly identity and type forwards are rows of their
                    // own tables; both stay absent from the payload when empty.
                    let identity = connection.prepare_cached(questions::ASSEMBLY_IDENTITY_BY_PROVIDER).unwrap()
                        .query_map(rusqlite::named_params!{":manifest":manifest,":shard":id}, |row| {
                            Ok(json!({"name":row.get::<_,String>("name")?,"version":row.get::<_,String>("version")?,
                              "culture":row.get::<_,Option<String>>("culture")?,"public_key_token":row.get::<_,Option<String>>("public_key_token")?}))
                        }).unwrap().map(Result::unwrap).collect::<Vec<_>>();
                    assert!(identity.len() <= 1, "{identity:?}");
                    if let Some(identity) = identity.into_iter().next() {
                        payload["assembly_identity"] = identity;
                    }
                    let forwards = connection.prepare_cached(
                        "SELECT f.name,f.namespace,o.name AS outer_name,f.target_name,f.target_version,f.target_culture,f.target_public_key_token
                         FROM active_catalog_type_forwards f LEFT JOIN active_catalog_type_forwards o
                         ON o.source_db=f.source_db AND o.manifest_digest=f.manifest_digest AND o.shard_id=f.shard_id AND o.ordinal=f.outer_ordinal
                         WHERE f.manifest_digest=?1 AND f.shard_id=?2 ORDER BY f.ordinal").unwrap()
                        .query_map(rusqlite::params![manifest, id], |row| {
                            Ok(json!({"name":row.get::<_,String>("name")?,"namespace":row.get::<_,String>("namespace")?,
                              "outer":row.get::<_,Option<String>>("outer_name")?,
                              "target":{"name":row.get::<_,String>("target_name")?,"version":row.get::<_,String>("target_version")?,
                                "culture":row.get::<_,Option<String>>("target_culture")?,"public_key_token":row.get::<_,Option<String>>("target_public_key_token")?}}))
                        }).unwrap().map(Result::unwrap).collect::<Vec<_>>();
                    if !forwards.is_empty() {
                        payload["type_forwards"] = json!(forwards);
                    }
                    payload
                }
                CompiledPayload::GeneratorRules { .. } => json!({"kind":"generator_rules",
                "rules":records(connection,"catalog_generator_rules",manifest,id)}),
                CompiledPayload::ProcedureSummaries { .. } => json!({"kind":"procedure_summaries",
                "summaries":records(connection,"catalog_procedure_summaries",manifest,id)}),
            };
            wire["payload"] = payload;
            for (field, table, array) in [
                ("runtime_values", "catalog_runtime_value_payloads", None),
                (
                    "runtime_contracts",
                    "catalog_runtime_contract_payloads",
                    None,
                ),
                (
                    "collection_flows",
                    "catalog_collection_flows",
                    Some("flows"),
                ),
                (
                    "conditional_type_refinements",
                    "catalog_conditional_type_refinements",
                    Some("refinements"),
                ),
                ("deferred_yields", "catalog_deferred_yields", Some("yields")),
            ] {
                let values = records(connection, table, manifest, id);
                let value = match array {
                    Some(array) if wire.get(field).is_some() => {
                        let mut envelope = wire[field].clone();
                        envelope[array] = json!(values);
                        envelope
                    }
                    None => values.into_iter().next().unwrap_or(Value::Null),
                    _ => {
                        assert!(values.is_empty());
                        Value::Null
                    }
                };
                if value.is_null() {
                    wire.as_object_mut().unwrap().remove(field);
                } else {
                    wire[field] = value;
                }
            }
            let decoded = compiled_from_wire(serde_json::from_value(wire).unwrap());
            {
                let manifest = Arc::clone(&shard.manifest);
                let has_callable_values = decoded.callable_values().is_some();
                ActiveSemanticModelShard {
                    metadata: Arc::new(
                        crate::analyzer::store::active_models::ActiveSemanticModelShardMetadata {
                            assumed_rust_toolchain: false,
                            descriptor: manifest
                                .shards
                                .iter()
                                .find(|descriptor| descriptor.shard_id == decoded.shard_id())
                                .expect("fixture descriptor exists")
                                .clone(),
                            selectors: decoded.activation().to_vec(),
                            row_store: None,
                            has_callable_values,
                            manifest,
                            approximate: shard.approximate,
                            source_kind: shard.source_kind,
                            source_id: shard.source_id.clone(),
                            matched_evidence: shard.matched_evidence.clone(),
                            matching_evidence: shard.matching_evidence.clone(),
                            evidence_rank: shard.evidence_rank,
                            source_rank: shard.source_rank,
                            extraction_deferred: false,
                        },
                    ),
                    decoded: Some(decoded),
                }
            }
        })
        .collect()
}

fn overlay_snapshot(overlay: &SemanticModelOverlay) -> Snapshot {
    let mut result = Snapshot::new();
    for (family, map) in [
        ("symbols_id", &overlay.symbols_by_id),
        ("symbols_name", &overlay.symbols_by_name),
        ("symbols_uri", &overlay.symbols_by_uri),
        ("symbols_path", &overlay.symbols_by_authored_path),
        ("symbols_owner", &overlay.symbols_by_owner),
    ] {
        for (key, indices) in map {
            for index in indices {
                put(
                    &mut result,
                    family,
                    vec![key.clone()],
                    &overlay.symbols[*index],
                );
            }
        }
    }
    for (family, map) in [
        ("relations_from", &overlay.relations_from),
        ("relations_to", &overlay.relations_to),
    ] {
        for (key, indices) in map {
            for index in indices {
                let r = &overlay.relations[*index];
                put(
                    &mut result,
                    family,
                    vec![key.clone()],
                    (&r.id, &r.kind, &r.from, &r.to, r.declaration_ordinal),
                );
            }
        }
    }
    for (key, indices) in &overlay.collection_flows_by_callable {
        for index in indices {
            let f = &overlay.collection_flows[*index];
            put(
                &mut result,
                "collection_flows",
                vec![key.clone()],
                (&f.callable, &f.payload, f.coverage),
            );
        }
    }
    for (key, indices) in &overlay.conditional_types_by_callable {
        for index in indices {
            let f = &overlay.conditional_type_refinements[*index];
            put(
                &mut result,
                "conditional_types",
                vec![key.clone()],
                (&f.payload, f.coverage),
            );
        }
    }
    for ((factory, resume, handle), indices) in &overlay.deferred_yields_by_scope {
        for index in indices {
            let f = &overlay.deferred_yields[*index];
            put(
                &mut result,
                "deferred_yields",
                vec![factory.clone(), resume.clone(), handle.clone()],
                (&f.payload, f.coverage),
            );
        }
    }
    result
}

fn absence_snapshot(index: &MatcherIndexes) -> BTreeMap<(String, String, bool), Vec<String>> {
    let mut result = BTreeMap::new();
    for (language, members) in &index.parity_absence_candidates().by_language {
        for (member, owners) in members {
            result.insert(
                (language.clone(), member.clone(), false),
                owners.receiverless_owners.clone(),
            );
            result.insert(
                (language.clone(), member.clone(), true),
                owners.receiver_owners.clone(),
            );
        }
    }
    result
}

fn compare(label: &str, expected: &Snapshot, actual: &Snapshot, failures: &mut Vec<String>) {
    for key in expected
        .keys()
        .chain(actual.keys())
        .collect::<BTreeSet<_>>()
    {
        if expected.get(key) != actual.get(key) {
            let empty = BTreeSet::new();
            let wanted = expected.get(key).unwrap_or(&empty);
            let got = actual.get(key).unwrap_or(&empty);
            failures.push(format!(
                "{label} {key:?}: missing={:?}, extra={:?}",
                wanted.difference(got).collect::<Vec<_>>(),
                got.difference(wanted).collect::<Vec<_>>()
            ));
        }
    }
}

fn fixture_shards(
    pack: &CompiledSemanticModelPack,
    shards: Vec<crate::analyzer::semantic_model::catalog::ValidatedShard>,
    label: &str,
) -> Vec<ActiveSemanticModelShard> {
    shards
        .into_iter()
        .map(|shard| {
            let decoded = shard.decoded;
            let manifest = Arc::new(pack.manifest.clone());
            let has_callable_values = decoded.callable_values().is_some();
            ActiveSemanticModelShard {
                metadata: Arc::new(
                    crate::analyzer::store::active_models::ActiveSemanticModelShardMetadata {
                        assumed_rust_toolchain: false,
                        descriptor: manifest
                            .shards
                            .iter()
                            .find(|descriptor| descriptor.shard_id == decoded.shard_id())
                            .expect("fixture descriptor exists")
                            .clone(),
                        selectors: decoded.activation().to_vec(),
                        row_store: None,
                        has_callable_values,
                        manifest,
                        approximate: false,
                        source_kind: CatalogPackSourceKind::EphemeralWorkspace,
                        source_id: label.into(),
                        matched_evidence: SemanticModelActivationEvidence {
                            language: pack.manifest.language.clone(),
                            ecosystem: pack.manifest.ecosystem.clone(),
                            package: None,
                            module: None,
                            toolchain: None,
                            target: None,
                            configuration: None,
                            artifact_sha256: None,
                        },
                        matching_evidence: Vec::new(),
                        evidence_rank: EvidenceRank::Language,
                        source_rank: 0,
                        extraction_deferred: false,
                    },
                ),
                decoded: Some(decoded),
            }
        })
        .collect()
}

pub fn assert_pack_parity(pack: &CompiledSemanticModelPack, label: &str) {
    assert_pack_set_parity(std::slice::from_ref(pack), label);
}

fn catalog_fixture_active(
    packs: &[CompiledSemanticModelPack],
    label: &str,
) -> (
    Arc<ResolvedActiveSemanticModels>,
    crate::analyzer::store::model_catalog::CatalogRuntimeSourceReader,
) {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let mut shards = Vec::new();
    for pack in packs {
        catalog
            .register_compiled_pack(
                pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::EphemeralWorkspace,
                    source_id: label.into(),
                },
            )
            .unwrap();
        let validated = validate_pack(pack, &DecodeLimits::default()).unwrap();
        eprintln!(
            "{label}: unresolved shard-local callees: {:?}",
            validated
                .shards
                .iter()
                .flat_map(|shard| shard.diagnostics.iter())
                .collect::<Vec<_>>()
        );
        shards.extend(fixture_shards(pack, validated.shards, label));
    }
    let mut original = active(shards);
    let (reader, row_identities) = catalog
        .runtime_source_reader_with_shard_keys(original.shards.iter().map(|s| {
            (
                s.manifest.content_sha256.as_str(),
                s.descriptor.shard_id.as_str(),
                s.source_kind,
            )
        }))
        .unwrap();
    for (shard, identity) in original.shards.iter_mut().zip(row_identities) {
        let shard = Arc::get_mut(shard).expect("parity handles not yet shared");
        Arc::get_mut(&mut shard.metadata)
            .expect("parity metadata not yet shared")
            .row_store = Some(identity);
    }
    original.source_reader = Some(Arc::new(reader.clone()));
    {
        let installed_source: Option<
            Arc<dyn crate::analyzer::store::model_catalog::RequestRowReaderSource>,
        > = Some(Arc::new(
            crate::analyzer::store::model_catalog::ActivationRowReaderSource::new(
                original.source_reader.as_ref().unwrap().clone(),
                &original.active_model_set_hash,
            ),
        ));
        original.install_request_source(installed_source).unwrap();
    };
    (Arc::new(original), reader)
}

struct CatalogParity {
    active: Arc<ResolvedActiveSemanticModels>,
    reader: crate::analyzer::store::model_catalog::CatalogRuntimeSourceReader,
    overlay: SemanticModelOverlay,
    analyzer: EmptyAnalyzer,
    _directory: TempDir,
}

pub fn assert_pack_set_parity(packs: &[CompiledSemanticModelPack], label: &str) {
    let fixture = assert_catalog_row_index_parity(packs, label);
    assert_active_keyed_parity(&fixture.active, &fixture.reader);
    assert_keyed_overlay_entries(
        &fixture.analyzer,
        &fixture.active,
        &fixture.reader,
        &fixture.overlay,
        label,
    );
}

fn assert_catalog_row_index_parity(
    packs: &[CompiledSemanticModelPack],
    label: &str,
) -> CatalogParity {
    let pack = &packs[0];
    let (original, reader) = catalog_fixture_active(packs, label);
    for (family, sql) in [
        ("types", questions::ALL_TYPES),
        ("members", questions::ALL_MEMBERS),
        ("rules", questions::RULES),
        ("summaries", questions::ALL_SUMMARIES),
    ] {
        let rows = (&reader as &dyn crate::analyzer::store::model_catalog::CatalogRowReader)
            .raw_records::<Value>(sql, &[], &original.shards)
            .unwrap();
        let mut actual = Vec::new();
        for row in rows {
            assert!(
                original
                    .shards
                    .iter()
                    .any(|shard| Arc::ptr_eq(&shard.metadata, &row.shard)),
                "raw records must share selected metadata"
            );
            actual.push(canonical((
                &row.shard.manifest.content_sha256,
                row.shard.descriptor.shard_id.as_str(),
                &row.record,
            )));
        }
        let mut expected = Vec::new();
        for shard in &original.shards {
            let wire = serde_json::to_value(shard.decoded()).unwrap();
            if let Some(records) = wire["payload"][family].as_array() {
                expected.extend(records.iter().map(|record| {
                    canonical((
                        &shard.manifest.content_sha256,
                        shard.descriptor.shard_id.as_str(),
                        record,
                    ))
                }));
            }
            assert_eq!(
                (&reader as &dyn crate::analyzer::store::model_catalog::CatalogRowReader)
                    .callable_values_presence(shard.row_store.unwrap())
                    .unwrap(),
                shard.has_callable_values,
                "exact marker payload presence"
            );
        }
        actual.sort();
        expected.sort();
        assert_eq!(actual, expected, "{label}: owned raw {family}");
    }
    for shard in &original.shards {
        use brokk_bifrost_semantic::analyzer::semantic_model::catalog::rows::SemanticPayloadFamily;
        for family in SemanticPayloadFamily::ALL {
            assert_eq!(
                (&reader as &dyn crate::analyzer::store::model_catalog::CatalogRowReader)
                    .payload_family_presence(shard.row_store.unwrap(), family)
                    .unwrap(),
                family.is_present(shard.decoded()),
                "{label}: exact {family:?} presence"
            );
        }
        assert_eq!(
            shard.descriptor.payload_kind
                == crate::analyzer::semantic_model::PayloadKind::ProcedureSummaries,
            shard.decoded().payload().procedure_summaries().is_some(),
            "{label}: descriptor primary-family presence"
        );
        {
            let connection = reader.connection.lock().unwrap();
            for (statement, present) in [
                (
                    questions::ALL_RUNTIME_VALUES,
                    shard.decoded().runtime_values().is_some(),
                ),
                (
                    questions::ALL_RUNTIME_CONTRACTS,
                    shard.decoded().runtime_contracts().is_some(),
                ),
            ] {
                let mut query = connection.prepare_cached(statement).unwrap();
                let metadata = query
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, String>("source_db")?,
                            row.get::<_, i64>("shard_key")?,
                        ))
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                let identity = shard.row_store.unwrap();
                let source = match identity.database {
                    crate::analyzer::store::active_models::CatalogShardDatabase::Durable => {
                        "durable"
                    }
                    crate::analyzer::store::active_models::CatalogShardDatabase::Session => {
                        "session"
                    }
                };
                assert_eq!(
                    metadata
                        .iter()
                        .any(|(database, key)| database == source && *key == identity.shard_key),
                    present,
                    "{label}: whole-payload row presence"
                );
            }
        }
        if let Some(summaries) = shard.decoded().payload().procedure_summaries() {
            assert_eq!(
                (&reader as &dyn crate::analyzer::store::model_catalog::CatalogRowReader)
                    .procedure_summary_shard_order(shard, &original.shards)
                    .unwrap(),
                original
                    .procedure_summary_shard_order(shard)
                    .expect("the parity oracle compares single-reader paths"),
                "{label}: keyed summary shard order"
            );
            for summary in summaries {
                let roots = [summary.id.as_str()];
                assert_eq!(
                    (&reader as &dyn crate::analyzer::store::model_catalog::CatalogRowReader)
                        .procedure_summary_family(shard, roots)
                        .unwrap(),
                    original
                        .procedure_summary_family(shard, roots)
                        .expect("the parity oracle compares single-reader paths"),
                    "{label}: family rooted at {}",
                    summary.id
                );
            }
        }
    }
    let connection = reader.connection.lock().unwrap();
    // SQLite's busy handler belongs to the connection, including attached
    // databases; session reads must retain the opener's contention wait.
    for pragma in ["PRAGMA main.busy_timeout", "PRAGMA session.busy_timeout"] {
        assert_eq!(
            connection
                .query_row(pragma, [], |row| row.get::<_, u64>(0))
                .unwrap(),
            5_000
        );
    }
    let reconstructed = Arc::new(active(row_shards(&connection, &original.shards)));
    let mut failures = Vec::new();
    eprintln!("{label}: comparing matcher postings");
    let expected_matcher = matcher_snapshot(&original);
    let matcher_keys = expected_matcher.len();
    compare(
        "matcher",
        &expected_matcher,
        &sql_matcher_snapshot(&connection, &expected_matcher),
        &mut failures,
    );
    drop(expected_matcher);
    // Full record equality also covers all companion payload kinds, including
    // fields that no SQL predicate indexes and therefore remain in JSON.
    for (before, after) in original.shards.iter().zip(&reconstructed.shards) {
        if before.decoded() != after.decoded() {
            failures.push(format!(
                "full records differ: {}",
                before.descriptor.shard_id.as_str()
            ));
        }
    }
    let raw_expected = original
        .indexes
        .parity_raw_absence_claims()
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut raw_actual = BTreeSet::new();
    for realm in original
        .shards
        .iter()
        .map(|shard| {
            brokk_bifrost_core::analyzer::model::semantic_pack_realm(&shard.manifest.language)
        })
        .collect::<BTreeSet<_>>()
    {
        raw_actual.extend(
            connection
                .prepare_cached(questions::SUMMARY_ABSENT_FAMILIES)
                .unwrap()
                .query_map(rusqlite::named_params! { ":realm": realm }, |row| {
                    Ok((
                        realm.to_owned(),
                        row.get::<_, String>("owner_fqn")?,
                        row.get::<_, String>("member")?,
                        row.get::<_, bool>("has_receiver")?,
                    ))
                })
                .unwrap()
                .map(Result::unwrap),
        );
    }
    assert_eq!(raw_expected, raw_actual, "raw absence discovery hints");
    assert_eq!(
        absence_snapshot(&original.indexes),
        absence_snapshot(&reconstructed.indexes),
        "effective absence must resolve all raw true/false claims query-locally"
    );
    let directory = TempDir::new().unwrap();
    let analyzer = EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Rust)));
    drop(connection);
    let (composition_groups, generated_groups) =
        assert_group_parity_with_reader(&analyzer, &original, &reader);
    eprintln!(
        "{label}: composition_groups={composition_groups}, generated_groups={generated_groups}"
    );
    let before = SemanticModelOverlay::build(
        &analyzer,
        &original,
        &CancellationToken::new(),
        u64::MAX,
        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
    )
    .unwrap();
    if label == "csharp-external" {
        assert!(
            before
                .symbols_named("Fixture.Api.Client`1..ctor")
                .records
                .iter()
                .any(|symbol| symbol.name == ".ctor")
        );
    }
    let after = SemanticModelOverlay::build(
        &analyzer,
        &reconstructed,
        &CancellationToken::new(),
        u64::MAX,
        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
    )
    .unwrap();
    eprintln!("{label}: comparing overlay postings");
    let expected_overlay = overlay_snapshot(&before);
    let overlay_keys = expected_overlay.len();
    compare(
        "overlay",
        &expected_overlay,
        &overlay_snapshot(&after),
        &mut failures,
    );
    drop(expected_overlay);
    assert_eq!(before.java_hierarchy, after.java_hierarchy);
    let connection = reader.connection.lock().unwrap();
    eprintln!("{label}: comparing structural endpoints");
    check_row_relations(&connection, &analyzer, &original, &before, &mut failures);
    eprintln!("{label}: comparing spelling routes and authored paths");
    let parameter_report =
        check_names_and_paths(&connection, &analyzer, &original, &before, &mut failures);
    check_companion_postings(&connection, &original, &mut failures);
    drop(connection);
    if let Some(path) = std::env::var_os("BIFROST_PARITY_REPORT") {
        let path = Path::new(&path);
        std::fs::create_dir_all(path).unwrap();
        std::fs::write(
            path.join(format!("{}.txt", pack.manifest.content_sha256)),
            format!(
                "pack={label}\ncomposition_groups={composition_groups}\ngenerated_groups={generated_groups}\nmatcher_keys={}\noverlay_keys={}\n{parameter_report}\n{}\n",
                matcher_keys,
                overlay_keys,
                failures.join("\n")
            ),
        )
        .unwrap();
    }
    assert!(
        failures.is_empty(),
        "{label}: {} parity differences; first: {:?}",
        failures.len(),
        failures.first()
    );
    CatalogParity {
        active: original,
        reader,
        overlay: before,
        analyzer,
        _directory: directory,
    }
}

fn assert_keyed_overlay_entries(
    analyzer: &dyn IAnalyzer,
    original: &Arc<ResolvedActiveSemanticModels>,
    reader: &crate::analyzer::store::model_catalog::CatalogRuntimeSourceReader,
    before: &SemanticModelOverlay,
    label: &str,
) {
    let row_active = metadata_only_active(original, reader);
    let mut row_overlay = SemanticModelOverlay::build(
        analyzer,
        &row_active,
        &CancellationToken::new(),
        u64::MAX,
        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
    )
    .unwrap();
    if let Some(rows) = &mut row_overlay.row_source {
        Arc::make_mut(rows).cache =
            Some(crate::analyzer::store::cache_budget::StoreCacheBudget::new(
                &crate::retention_budget::RetentionBudget::for_tests(),
            ));
    }
    assert_overlay_entry_parity(original, &row_active, before, &row_overlay, label);
    let mut entry_ids = BTreeSet::new();
    for shard in &original.shards {
        if let Some((types, members, _)) = shard.decoded().payload().declaration_facts() {
            entry_ids.extend(types.iter().map(|r| r.id.as_str()));
            entry_ids.extend(members.iter().map(|r| r.id.as_str()));
        }
    }
    let mut names = BTreeSet::new();
    let mut owners = BTreeSet::new();
    let mut uris = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for symbol in before.symbols() {
        names.insert(symbol.name.clone());
        names.insert(symbol.qualified_name.clone());
        names.extend(symbol.aliases.iter().cloned());
        if let Some(owner) = &symbol.owner_id {
            owners.insert(owner.clone());
        }
        match &symbol.location {
            SemanticModelLocation::Model(location) => {
                uris.insert(location.uri.clone());
            }
            SemanticModelLocation::Authored(anchor) => {
                paths.insert(anchor.path.clone());
            }
        }
    }
    let compare_entry =
        |question: &str,
         expected: SemanticModelOverlayMatch<SemanticModelSymbol>,
         actual: SemanticModelOverlayMatch<SemanticModelSymbol>| {
            assert_eq!(
                expected.disposition, actual.disposition,
                "{label}: {question} disposition"
            );
            assert_eq!(
                expected.records, actual.records,
                "{label}: {question} ordered records"
            );
        };
    for name in names {
        compare_entry(
            &format!("name {name}"),
            before.symbols_named(&name),
            row_overlay.symbols_named(&name),
        );
        assert_eq!(
            before.trait_owners_with_callable_member(&name),
            row_overlay.trait_owners_with_callable_member(&name),
            "{label}: trait owners {name}"
        );
    }
    for owner in owners {
        compare_entry(
            &format!("members {owner}"),
            before.members_of(&owner),
            row_overlay.members_of(&owner),
        );
    }
    for uri in uris {
        compare_entry(
            "URI",
            before.symbols_at_uri(&uri),
            row_overlay.symbols_at_uri(&uri),
        );
    }
    for path in paths {
        compare_entry(
            "authored path",
            before.symbols_at_authored_path(&path),
            row_overlay.symbols_at_authored_path(&path),
        );
    }
    for id in entry_ids {
        let expected = before.symbols_with_id(id);
        let actual = row_overlay.symbols_with_id(id);
        assert_eq!(
            expected.disposition, actual.disposition,
            "{label}: overlay ID {id} disposition"
        );
        assert_eq!(
            expected.records, actual.records,
            "{label}: overlay ID {id} records"
        );
    }
}

fn check_row_relations(
    connection: &Connection,
    analyzer: &dyn IAnalyzer,
    active: &ResolvedActiveSemanticModels,
    overlay: &SemanticModelOverlay,
    failures: &mut Vec<String>,
) {
    let mut symbols = Vec::new();
    let mut owners = HashMap::default();
    for shard in &active.shards {
        if let Some((types, _, _)) = shard.decoded().payload().declaration_facts() {
            for fact in types {
                if shard.guard_excludes(fact.guard.as_ref()) {
                    continue;
                }
                let symbol = type_symbol(analyzer, active, shard, fact, false);
                owners.insert(fact.id.clone(), symbol.qualified_name.clone());
                symbols.push(symbol);
            }
        }
    }
    for shard in &active.shards {
        if let Some((_, members, _)) = shard.decoded().payload().declaration_facts() {
            for fact in members {
                if shard.guard_excludes(fact.guard.as_ref()) {
                    continue;
                }
                symbols.push(member_symbol(
                    analyzer,
                    active,
                    shard,
                    fact,
                    owners.get(&fact.owner).map(String::as_str),
                    false,
                ));
            }
        }
    }
    let mut relations = Vec::new();
    let mut statement = connection.prepare(questions::ALL_RELATIONS).unwrap();
    for row in statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>("manifest_digest")?,
                row.get::<_, String>("shard_id")?,
                row.get::<_, String>("record_id")?,
                row.get::<_, String>("relation_kind")?,
                row.get::<_, String>("from_id")?,
                row.get::<_, String>("to_id")?,
                row.get::<_, Option<u32>>("declaration_ordinal")?,
            ))
        })
        .unwrap()
    {
        let (manifest, shard, id, kind, from, to, ordinal) = row.unwrap();
        let active_shard = active
            .shards
            .iter()
            .find(|s| {
                s.manifest.content_sha256 == manifest && s.descriptor.shard_id.as_str() == shard
            })
            .unwrap();
        // Only structural columns come from rows. Active provenance belongs to
        // the query, and composition rewrites both endpoints at query time.
        relations.push(SemanticModelRelation {
            pre_composition_endpoints: None,
            id: id.clone(),
            kind,
            from,
            to,
            declaration_ordinal: ordinal,
            provenance: provenance(
                active,
                active_shard,
                &id,
                &model_location(active_shard, "relation", &id),
                None,
                false,
            ),
        });
    }
    composition::compose_eager(
        &mut symbols,
        &mut relations,
        active,
        &CancellationToken::new(),
    )
    .unwrap();
    let mut expected = Snapshot::new();
    let mut actual = Snapshot::new();
    for (output, relations) in [
        (
            &mut expected,
            overlay
                .relations
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<_>>(),
        ),
        (&mut actual, relations.iter().collect::<Vec<_>>()),
    ] {
        for r in relations {
            for (family, key) in [("from", &r.from), ("to", &r.to)] {
                put(
                    output,
                    family,
                    vec![key.clone()],
                    (&r.id, &r.kind, &r.from, &r.to, r.declaration_ordinal),
                );
            }
        }
    }
    compare(
        "structural relation endpoints",
        &expected,
        &actual,
        failures,
    );
}

fn check_names_and_paths(
    connection: &Connection,
    analyzer: &dyn IAnalyzer,
    active: &ResolvedActiveSemanticModels,
    overlay: &SemanticModelOverlay,
    failures: &mut Vec<String>,
) -> String {
    let mut identities = BTreeMap::<String, BTreeSet<String>>::new();
    let mut published_names = BTreeMap::<String, BTreeSet<String>>::new();
    for symbol in &overlay.symbols {
        published_names
            .entry(symbol.id.clone())
            .or_default()
            .extend(
                std::iter::once(symbol.name.clone())
                    .chain(std::iter::once(symbol.qualified_name.clone()))
                    .chain(symbol.aliases.iter().cloned()),
            );
        identities
            .entry(symbol.id.clone())
            .or_default()
            .insert(symbol.id.clone());
        for contributor in &symbol.semantic_contributors {
            identities
                .entry(contributor.record_id.clone())
                .or_default()
                .insert(symbol.id.clone());
        }
    }
    let lookup = |name: &str| -> BTreeSet<String> {
        let mut ids = BTreeSet::new();
        for sql in [
            questions::TYPE_SPELLINGS,
            questions::MEMBER_SPELLINGS,
            questions::MEMBER_ALIASES,
        ] {
            ids.extend(
                connection
                    .prepare_cached(sql)
                    .unwrap()
                    .query_map(rusqlite::named_params! { ":name": name }, |row| {
                        row.get::<_, String>("record_id")
                    })
                    .unwrap()
                    .map(Result::unwrap),
            );
        }
        if let Some((owner, member)) = split_owner_member(name) {
            // Ambiguous owners retain their raw owner-ID qualification.
            ids.extend(
                connection
                    .prepare_cached(questions::MEMBERS_BY_OWNER_NAME)
                    .unwrap()
                    .query_map(
                        rusqlite::named_params! { ":owner":owner, ":name":member },
                        |row| row.get::<_, String>("record_id"),
                    )
                    .unwrap()
                    .map(Result::unwrap),
            );
            for sql in [
                questions::MEMBERS_QUALIFIED,
                questions::MEMBERS_ALIAS_QUALIFIED,
            ] {
                ids.extend(
                    connection
                        .prepare_cached(sql)
                        .unwrap()
                        .query_map(
                            rusqlite::named_params! { ":owner_name": owner, ":member": member },
                            |row| row.get::<_, String>("record_id"),
                        )
                        .unwrap()
                        .map(Result::unwrap),
                );
            }
        }
        // An explicit interface member's metadata name contains dots, so the
        // qualified posting cannot be split at its last dot. The symbol has
        // the structured owner and exact member name needed by this query.
        for &index in overlay.symbols_by_name.get(name).into_iter().flatten() {
            let symbol = &overlay.symbols[index];
            let Some(owner_id) = symbol.owner_id.as_ref() else {
                continue;
            };
            if symbol.qualified_name != name {
                continue;
            }
            ids.extend(
                connection
                    .prepare_cached(questions::MEMBERS_BY_OWNER_NAME)
                    .unwrap()
                    .query_map(
                        rusqlite::named_params! { ":owner": owner_id, ":name": &symbol.name },
                        |row| row.get::<_, String>("record_id"),
                    )
                    .unwrap()
                    .map(Result::unwrap),
            );
        }
        ids.into_iter()
            .flat_map(|id| identities.get(&id).cloned().unwrap_or_default())
            // Raw spelling questions are a candidate superset. Composition
            // determines whether an owner spelling survives on each symbol.
            .filter(|id| {
                published_names
                    .get(id)
                    .is_some_and(|names| names.contains(name))
            })
            .collect()
    };
    let mut stripped = 0usize;
    let mut stripping_changes = 0usize;
    let mut posted_answer_changes = 0usize;
    for (name, indices) in &overlay.symbols_by_name {
        let expected = indices
            .iter()
            .map(|i| overlay.symbols[*i].id.clone())
            .collect::<BTreeSet<_>>();
        let actual = lookup(name);
        if let Some((owner, member)) = split_owner_member(name) {
            let head = format!("{owner}.{member}");
            if head != *name {
                stripped += 1;
                if actual != lookup(&head) {
                    stripping_changes += 1;
                }
                if expected != lookup(&head) {
                    posted_answer_changes += 1;
                }
            }
        }
        if expected != actual {
            failures.push(format!(
                "member/type spelling {name:?}: missing={:?}, extra={:?}",
                expected.difference(&actual).collect::<Vec<_>>(),
                actual.difference(&expected).collect::<Vec<_>>()
            ));
        }
    }
    eprintln!(
        "parameter-list question: {stripped} posted names stripped; \
         {stripping_changes} SQL answers changed by stripping"
    );
    let mut expected = Snapshot::new();
    let mut actual = Snapshot::new();
    for (path, indices) in &overlay.symbols_by_authored_path {
        for index in indices {
            put(
                &mut expected,
                "path",
                vec![path.clone()],
                &overlay.symbols[*index].id,
            );
        }
    }
    for sql in [questions::ALL_TYPES, questions::ALL_MEMBERS] {
        for row in connection
            .prepare_cached(sql)
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>("manifest_digest")?,
                    row.get::<_, String>("shard_id")?,
                    row.get::<_, String>("record_id")?,
                    row.get::<_, Option<String>>("authored_path")?,
                    row.get::<_, String>("record_json")?,
                ))
            })
            .unwrap()
        {
            let (manifest, shard, id, path, record) = row.unwrap();
            let Some(path) = path else {
                continue;
            };
            let shard = active
                .shards
                .iter()
                .find(|s| {
                    s.manifest.content_sha256 == manifest && s.descriptor.shard_id.as_str() == shard
                })
                .unwrap();
            let value: Value = serde_json::from_str(&record).unwrap();
            let locator: Locator = serde_json::from_value(value["locator"].clone()).unwrap();
            assert!(matches!(&locator,Locator::Source {path:source,..} if source==&path));
            if let Some(anchor) = authored_anchor(
                analyzer,
                &shard.manifest.carried_sources,
                &locator,
                value["name"].as_str().unwrap(),
            ) {
                for identity in identities.get(&id).into_iter().flatten() {
                    put(&mut actual, "path", vec![anchor.path.clone()], identity);
                }
            }
        }
    }
    compare("translated authored paths", &expected, &actual, failures);
    let mut signature_queries = BTreeSet::new();
    for shard in &active.shards {
        if let Some((_, members, _)) = shard.decoded().payload().declaration_facts() {
            for fact in members {
                if let Some(symbol) = locator_symbol(&fact.locator)
                    && symbol.contains('(')
                {
                    signature_queries.insert(symbol.to_owned());
                }
            }
        }
    }
    let signature_changes = signature_queries
        .iter()
        .filter(|name| {
            let expected = overlay
                .symbols_by_name
                .get(*name)
                .into_iter()
                .flatten()
                .map(|index| overlay.symbols[*index].id.clone())
                .collect::<BTreeSet<_>>();
            expected != lookup(name)
        })
        .collect::<Vec<_>>();
    // Posting keys and caller-supplied signature requests are distinct domains.
    // Probe the latter without changing the old exact-name posting oracle.
    let mut parameter_probes = Vec::new();
    for name in overlay.symbols_by_name.keys().collect::<BTreeSet<_>>() {
        if name.contains('(') || split_owner_member(name).is_none() {
            continue;
        }
        if !overlay.symbols_by_name[name]
            .iter()
            .any(|index| overlay.symbols[*index].owner_id.is_some())
        {
            continue;
        }
        let request = format!("{name}()");
        let old_answer = overlay
            .symbols_by_name
            .get(&request)
            .into_iter()
            .flatten()
            .map(|index| overlay.symbols[*index].id.clone())
            .collect::<BTreeSet<_>>();
        let row_answer = lookup(&request);
        assert_eq!(
            row_answer, old_answer,
            "exact parameter-list lookup: {request}"
        );
        assert!(
            row_answer.is_empty(),
            "unexpected parameter-list key: {request}"
        );
        parameter_probes.push((request, row_answer));
        break;
    }
    for request in ["reqwest.Client.delete()", "alloc.alloc.Global.allocate()"] {
        let row_answer = lookup(request);
        assert!(
            row_answer.is_empty(),
            "exact parameter-list lookup: {request}"
        );
        assert!(!overlay.symbols_by_name.contains_key(request));
        parameter_probes.push((request.to_owned(), row_answer));
    }
    format!(
        "parameter-list question: posted_stripped={stripped}, \
         posted_answer_changes={posted_answer_changes}, \
         alias_answer_changes={stripping_changes}; authored_signature_queries={}, \
         authored_signature_answer_changes={}, samples={:?}; \
         off-domain parameter probes={parameter_probes:?}",
        signature_queries.len(),
        signature_changes.len(),
        signature_changes.iter().take(8).collect::<Vec<_>>()
    )
}

fn check_companion_postings(
    connection: &Connection,
    active: &ResolvedActiveSemanticModels,
    failures: &mut Vec<String>,
) {
    let mut expected = Snapshot::new();
    let mut actual = Snapshot::new();
    for shard in &active.shards {
        let mut add = |family: &str, key: Vec<String>, record: Value| {
            put(
                &mut expected,
                family,
                key,
                (
                    &shard.manifest.content_sha256,
                    shard.descriptor.shard_id.as_str(),
                    record,
                ),
            );
        };
        if let Some(p) = shard.decoded().collection_flows() {
            for f in &p.flows {
                add("flows", vec![f.callable.clone()], json!(f));
            }
        }
        if let Some(p) = shard.decoded().conditional_type_refinements() {
            for f in &p.refinements {
                add("refinements", vec![f.payload.callable.clone()], json!(f));
            }
        }
        if let Some(p) = shard.decoded().deferred_yields() {
            for f in &p.yields {
                add(
                    "yields",
                    vec![f.factory.clone(), f.resume.clone(), f.handle_type.clone()],
                    json!(f),
                );
            }
        }
        if let Some(p) = shard.decoded().runtime_contracts() {
            add("contracts", vec![], json!(p));
        }
        if let Some(p) = shard.decoded().runtime_values() {
            add("values", vec![], json!(p));
            for (i, e) in p.exposures.iter().enumerate() {
                add(
                    "exposures",
                    vec![e.binding_name.clone()],
                    json!([i, e.exposure_id, e.binding_name]),
                );
            }
            for (i, b) in p.behaviors.iter().enumerate() {
                add(
                    "behaviors",
                    vec![b.exposure_id.clone(), b.container_member.clone()],
                    json!([i, b.exposure_id, b.container_member]),
                );
            }
        }
    }
    for (family, sql) in [
        ("flows", questions::ALL_COLLECTION_FLOWS),
        ("refinements", questions::ALL_CONDITIONAL_REFINEMENTS),
        ("yields", questions::ALL_DEFERRED_YIELDS),
        ("contracts", questions::ALL_RUNTIME_CONTRACTS),
        ("values", questions::ALL_RUNTIME_VALUES),
        ("exposures", questions::ALL_RUNTIME_EXPOSURES),
        ("behaviors", questions::ALL_RUNTIME_BEHAVIORS),
    ] {
        let mut statement = connection.prepare_cached(sql).unwrap();
        let rows = statement
            .query_map([], |row| {
                let (key, record) = match family {
                    "exposures" => {
                        let binding = row.get::<_, String>("binding_name")?;
                        (
                            vec![binding.clone()],
                            json!([
                                row.get::<_, i64>("exposure_ordinal")?,
                                row.get::<_, String>("exposure_id")?,
                                binding
                            ]),
                        )
                    }
                    "behaviors" => {
                        let exposure = row.get::<_, String>("exposure_id")?;
                        let member = row.get::<_, String>("container_member")?;
                        (
                            vec![exposure.clone(), member.clone()],
                            json!([row.get::<_, i64>("behavior_ordinal")?, exposure, member]),
                        )
                    }
                    _ => {
                        let record =
                            serde_json::from_str::<Value>(&row.get::<_, String>("record_json")?)
                                .unwrap();
                        let key = match family {
                            "flows" => vec![row.get::<_, String>("callable")?],
                            "refinements" => vec![row.get::<_, String>("callable")?],
                            "yields" => vec![
                                row.get::<_, String>("factory")?,
                                row.get::<_, String>("resume")?,
                                row.get::<_, String>("handle_type")?,
                            ],
                            _ => vec![],
                        };
                        (key, record)
                    }
                };
                Ok((
                    key,
                    row.get::<_, String>("manifest_digest")?,
                    row.get::<_, String>("shard_id")?,
                    record,
                ))
            })
            .unwrap();
        for row in rows {
            let (key, manifest, shard, record) = row.unwrap();
            put(&mut actual, family, key, (manifest, shard, record));
        }
    }
    compare("companion postings", &expected, &actual, failures);
    let mut keyed = Snapshot::new();
    for (family, key) in expected.keys() {
        let mut bindings = Vec::<(&str, String)>::new();
        let sql = match family.as_str() {
            "flows" | "refinements" => {
                bindings.push((":callable_ids", serde_json::to_string(&[&key[0]]).unwrap()));
                if family == "flows" {
                    questions::COLLECTION_FLOWS
                } else {
                    questions::CONDITIONAL_REFINEMENTS
                }
            }
            "yields" => {
                bindings.extend([
                    (":factory_ids", serde_json::to_string(&[&key[0]]).unwrap()),
                    (":resume", key[1].clone()),
                    (":handle_type", key[2].clone()),
                ]);
                questions::DEFERRED_YIELDS
            }
            "exposures" => {
                bindings.push((":binding", key[0].clone()));
                questions::RUNTIME_EXPOSURES
            }
            "behaviors" => {
                bindings.extend([
                    (":exposure", key[0].clone()),
                    (":container", key[1].clone()),
                ]);
                questions::RUNTIME_BEHAVIORS
            }
            "values" => questions::ALL_RUNTIME_VALUES,
            "contracts" => questions::ALL_RUNTIME_CONTRACTS,
            _ => unreachable!(),
        };
        let params = bindings
            .iter()
            .map(|(name, value)| (*name, value as &dyn rusqlite::ToSql))
            .collect::<Vec<_>>();
        let mut query = connection.prepare_cached(sql).unwrap();
        let rows = query
            .query_map(params.as_slice(), |row| {
                let record = match family.as_str() {
                    "exposures" => {
                        let value =
                            serde_json::from_str::<Value>(&row.get::<_, String>("exposure_json")?)
                                .unwrap();
                        json!([
                            row.get::<_, i64>("exposure_ordinal")?,
                            value["exposureId"],
                            value["bindingName"]
                        ])
                    }
                    "behaviors" => {
                        let value =
                            serde_json::from_str::<Value>(&row.get::<_, String>("behavior_json")?)
                                .unwrap();
                        json!([
                            row.get::<_, i64>("behavior_ordinal")?,
                            value["exposureId"],
                            value["containerMember"]
                        ])
                    }
                    _ => serde_json::from_str::<Value>(&row.get::<_, String>("record_json")?)
                        .unwrap(),
                };
                Ok((
                    row.get::<_, String>("manifest_digest")?,
                    row.get::<_, String>("shard_id")?,
                    record,
                ))
            })
            .unwrap();
        for row in rows {
            put(&mut keyed, family, key.clone(), row.unwrap());
        }
    }
    compare("keyed companion questions", &expected, &keyed, failures);
}

// In-crate and public packs only. Trimmed golden summary models run through
// the same harness in tests/suite_semantic/catalog_row_parity_corpus.rs,
// because crate tests must not read the private root corpus.
#[cfg(test)]
const GOLDEN_PACKS: &[&str] = &[
    "crates/bifrost-analysis/testdata/semantic-model-packs/declarations-v1.json",
    "crates/bifrost-analysis/testdata/semantic-model-packs/generator-rules-v1.json",
    "crates/bifrost-analysis/testdata/semantic-model-packs/procedure-summaries-v1.json",
    "semantic-packs/rust-codeql-parity/bifrost.rust-std-fs.json",
    "semantic-packs/rust-codeql-parity/bifrost.rust-std-process.json",
];

#[test]
fn lifecycle_claims_survive_catalog_row_and_decoded_readers() {
    use crate::analyzer::semantic_model::SourceFormat;
    use crate::analyzer::semantic_model::compiler::{CompilerOptions, compile_source};
    let source =
        include_bytes!("../../../../testdata/semantic-model-packs/lifecycle-coverage-v26.json");
    let pack = compile_source(SourceFormat::Json, source, &CompilerOptions::default()).unwrap();
    assert_pack_parity(&pack, "test-only lifecycle coverage carrier");
    let (active, reader) = catalog_fixture_active(std::slice::from_ref(&pack), "lifecycle claims");
    let decoded = &active.shards[0]
        .decoded()
        .payload()
        .procedure_summaries()
        .unwrap()[0];
    assert_eq!(decoded.subject_effects()[0].id, "release");
    assert_eq!(decoded.lifecycle_coverage()[0].witnesses, ["release"]);
    let key = crate::analyzer::semantic_model::ProcedureSummaryTargetKey {
        language: "java",
        path: "com/example/Resource.class",
        symbol: "Resource.close",
        has_receiver: true,
        parameter_count: 0,
    };
    let rows = metadata_only_active(&active, &reader).procedure_summaries_for(key);
    assert_eq!(rows.records.len(), 1);
    let installed = &rows.records[0].record;
    assert_eq!(installed.subject_effects(), decoded.subject_effects());
    assert_eq!(installed.lifecycle_coverage(), decoded.lifecycle_coverage());
}

#[test]
fn catalog_row_index_parity_for_golden_packs() {
    use crate::analyzer::semantic_model::SourceFormat;
    use crate::analyzer::semantic_model::compiler::{CompilerOptions, compile_source};
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut packs = Vec::new();
    for path in GOLDEN_PACKS {
        eprintln!("parity fixture: {path}");
        let pack = compile_source(
            SourceFormat::Json,
            &std::fs::read(root.join(path)).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap_or_else(|diagnostics| panic!("{path}: {diagnostics:#?}"));
        assert_pack_parity(&pack, path);
        packs.push(pack);
    }
    assert_pack_set_parity(&packs, "mixed-public-packs");
}

#[test]
#[ignore = "operator supplies BIFROST_PARITY_BUNDLE pointing at a copied real release bundle"]
fn catalog_row_index_parity_for_real_bundle() {
    assert_catalog_row_index_parity(&real_bundle_packs(), "real-std-and-curated-rust");
}

#[cfg(test)]
fn real_bundle_packs() -> Vec<CompiledSemanticModelPack> {
    use crate::analyzer::semantic_model::artifact::CompiledShardArtifact;
    use crate::analyzer::semantic_model::decode_manifest;
    let root = std::env::var_os("BIFROST_PARITY_BUNDLE").expect("BIFROST_PARITY_BUNDLE");
    let root = Path::new(&root);
    let index: Value =
        serde_json::from_slice(&std::fs::read(root.join("index.json")).unwrap()).unwrap();
    let mut packs = Vec::new();
    for entry in index["packs"].as_array().unwrap() {
        let manifest_bytes =
            std::fs::read(root.join(entry["manifest"]["path"].as_str().unwrap())).unwrap();
        let manifest = decode_manifest(&manifest_bytes, &DecodeLimits::default()).unwrap();
        let shards = entry["shards"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| CompiledShardArtifact {
                descriptor: manifest
                    .shards
                    .iter()
                    .find(|d| d.shard_id == s["shard_id"].as_str().unwrap())
                    .unwrap()
                    .clone(),
                bytes: std::fs::read(root.join(s["asset"]["path"].as_str().unwrap())).unwrap(),
            })
            .collect();
        let pack = CompiledSemanticModelPack {
            manifest,
            manifest_bytes,
            shards,
        };
        packs.push(pack);
    }
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for path in GOLDEN_PACKS
        .iter()
        .filter(|path| path.starts_with("semantic-packs/rust-codeql-parity/"))
    {
        let pack = crate::analyzer::semantic_model::compile_source(
            crate::analyzer::semantic_model::SourceFormat::Json,
            &std::fs::read(repository.join(path)).unwrap(),
            &crate::analyzer::semantic_model::CompilerOptions::default(),
        )
        .unwrap();
        packs.push(pack);
    }
    packs
}

#[test]
fn catalog_full_ordered_selectors_preserve_activation_and_explanations() {
    use crate::analyzer::semantic_model::SourceFormat;
    use crate::analyzer::semantic_model::catalog::{DurablePackSource, DurablePackSourceKind};
    use crate::analyzer::semantic_model::compiler::{CompilerOptions, compile_source};
    use crate::analyzer::semantic_model::runtime::{
        strict_activation_match, strict_activation_mismatch_reason,
    };
    use crate::analyzer::semantic_model::{CatalogCoordinate, SemanticPackSelectorQuery};
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let version = semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
    let mut checked = 0;
    for path in GOLDEN_PACKS {
        let mut source: Value =
            serde_json::from_slice(&std::fs::read(root.join(path)).unwrap()).unwrap();
        if path.ends_with("/declarations-v1.json") {
            // Exercise multiple ordered selectors, including rows that reject
            // a selected evidence case. The on-disk golden pack is unchanged.
            let selectors = source["shards"][0]["activation"].as_array_mut().unwrap();
            let mut alternate = selectors[0].clone();
            alternate["targets"] = json!(["alternate-selector-target"]);
            alternate["configurations"] = json!(["alternate-selector-profile"]);
            selectors.push(alternate);
        }
        let pack = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&source).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap();
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        catalog
            .install(
                &pack,
                &DurablePackSource {
                    kind: DurablePackSourceKind::Installed,
                    source_id: path.to_string(),
                },
            )
            .unwrap();
        catalog
            .register_compiled_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::EphemeralWorkspace,
                    source_id: path.to_string(),
                },
            )
            .unwrap();
        let candidates = catalog
            .candidates(&SemanticPackSelectorQuery {
                language: pack.manifest.language.clone(),
                ecosystem: pack.manifest.ecosystem.clone(),
                package: None,
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
                bifrost_version: version.clone(),
            })
            .unwrap();
        assert_eq!(
            candidates.len(),
            pack.shards.len() * 2,
            "both publishing databases: {path}"
        );
        for candidate in candidates {
            let loaded = catalog.load_decoded_for_test(&candidate).unwrap();
            let reads = crate::analyzer::semantic_model::artifact::thread_shard_wire_read_count();
            let metadata = catalog.load_metadata_only_for_test(&candidate).unwrap();
            assert!(metadata.shard.is_none(), "metadata-only load: {path}");
            assert_eq!(
                crate::analyzer::semantic_model::artifact::thread_shard_wire_read_count(),
                reads,
                "metadata-only loading must not decode: {path}"
            );
            assert_eq!(metadata.manifest, loaded.manifest);
            assert_eq!(metadata.descriptor, loaded.descriptor);
            assert_eq!(metadata.selectors, loaded.selectors);
            assert_eq!(metadata.source_kind, loaded.source_kind);
            assert_eq!(metadata.source_id, loaded.source_id);
            assert_eq!(metadata.has_callable_values, loaded.has_callable_values);
            let header = loaded.decoded();
            assert_eq!(
                loaded.selectors,
                header.activation(),
                "full ordered selectors: {path}"
            );
            assert_eq!(loaded.descriptor.record_count, header.record_count() as u64);
            assert_eq!(loaded.descriptor.payload_kind, header.payload_kind());
            assert_eq!(loaded.descriptor.shard_id, header.shard_id());
            assert_eq!(loaded.manifest.safety, *header.safety());
            let mut cases = vec![Vec::new()];
            for selector in header.activation() {
                let coordinate =
                    |selector: &Option<crate::analyzer::semantic_model::NameSelector>| {
                        selector.as_ref().map(|selector| CatalogCoordinate {
                            name: selector.name.clone(),
                            version: Some(semver::Version::new(21, 0, 0)),
                        })
                    };
                let evidence = SemanticModelActivationEvidence {
                    language: loaded.manifest.language.clone(),
                    ecosystem: loaded.manifest.ecosystem.clone(),
                    package: coordinate(&selector.package),
                    module: coordinate(&selector.module),
                    toolchain: coordinate(&selector.toolchain),
                    target: selector.targets.first().cloned(),
                    configuration: selector.configurations.first().cloned(),
                    artifact_sha256: selector.artifact_sha256.clone(),
                };
                cases.push(vec![evidence.clone()]);
                cases.push(vec![SemanticModelActivationEvidence {
                    package: None,
                    module: None,
                    toolchain: None,
                    target: None,
                    configuration: None,
                    artifact_sha256: None,
                    ..evidence.clone()
                }]);
                cases.push(vec![SemanticModelActivationEvidence {
                    target: Some("nonmatching-target".into()),
                    configuration: Some("nonmatching-configuration".into()),
                    artifact_sha256: Some("ff".repeat(32)),
                    ..evidence
                }]);
            }
            for evidence in cases {
                let outcome = |selectors: &[_]| {
                    strict_activation_match(&loaded.manifest, selectors, &evidence, &version).map(
                        |matched| {
                            (
                                matched.evidence_rank,
                                matched.matched_evidence,
                                matched.matching_evidence,
                                matched.matched_requirements,
                            )
                        },
                    )
                };
                assert_eq!(
                    outcome(&loaded.selectors),
                    outcome(header.activation()),
                    "strict activation: {path}"
                );
                assert_eq!(
                    strict_activation_mismatch_reason(
                        &loaded.manifest,
                        &loaded.selectors,
                        &evidence
                    ),
                    strict_activation_mismatch_reason(
                        &loaded.manifest,
                        header.activation(),
                        &evidence
                    ),
                    "explanation: {path}"
                );
                checked += 1;
            }
        }
    }
    assert!(
        checked > GOLDEN_PACKS.len() * 2,
        "both selector sources and evidence variants ran"
    );
}

/// Exercise the group driver on a live analyzer, including workspace-generated
/// owners and members. The source reader belongs to the selected active set.
pub fn assert_active_group_parity(
    analyzer: &dyn IAnalyzer,
    active: &ResolvedActiveSemanticModels,
) -> (usize, usize) {
    assert_group_parity_with_reader(
        analyzer,
        active,
        active
            .source_reader
            .as_ref()
            .expect("activated catalog reader"),
    )
}

fn assert_group_parity_with_reader(
    analyzer: &dyn IAnalyzer,
    active: &ResolvedActiveSemanticModels,
    reader: &crate::analyzer::store::model_catalog::CatalogRuntimeSourceReader,
) -> (usize, usize) {
    let mut type_ids = BTreeSet::new();
    let mut member_ids = BTreeSet::new();
    let mut relation_ids = BTreeSet::new();
    for shard in &active.shards {
        if let Some((types, members, relations)) = shard.decoded().payload().declaration_facts() {
            type_ids.extend(
                types
                    .iter()
                    .filter(|r| !shard.guard_excludes(r.guard.as_ref()))
                    .map(|r| r.id.clone()),
            );
            member_ids.extend(
                members
                    .iter()
                    .filter(|r| !shard.guard_excludes(r.guard.as_ref()))
                    .map(|r| r.id.clone()),
            );
            relation_ids.extend(relations.iter().map(|r| r.id.clone()));
        }
    }
    let cancellation = CancellationToken::new();
    let (symbols, relations) = overlay_declarations(
        analyzer,
        active,
        &cancellation,
        type_ids.into_iter().collect(),
        member_ids.into_iter().collect(),
        relation_ids.into_iter().collect(),
    )
    .unwrap();
    let generated = generated_overlay_facts(analyzer, active, &cancellation).unwrap();
    composition::assert_group_parity(
        analyzer,
        active,
        reader,
        &symbols,
        &relations,
        &generated.symbols,
        &generated.relations,
    )
}

fn assert_active_keyed_parity(
    decoded: &ResolvedActiveSemanticModels,
    reader: &crate::analyzer::store::model_catalog::CatalogRuntimeSourceReader,
) {
    use crate::analyzer::semantic_model::RuleTriggerKey;
    let rows = metadata_only_active(decoded, reader);
    fn single_reader_rows<R>(family: crate::analyzer::store::active_models::FamilyRows<R>) -> R {
        assert!(
            family.jvm_open.is_none(),
            "the parity oracle compares single-reader paths"
        );
        family.rows
    }
    fn records<T: Serialize>(
        records: Vec<crate::analyzer::semantic_model::ActivatedSemanticModelRecord<T>>,
    ) -> Vec<String> {
        payloads(records.into_iter().map(|r| (r.record, r.shard)))
    }
    fn matched<T: Serialize>(
        label: &str,
        left: SemanticModelMatch<T>,
        right: SemanticModelMatch<T>,
    ) {
        assert_eq!(left.disposition, right.disposition, "{label}: disposition");
        assert_eq!(
            left.candidates_examined, right.candidates_examined,
            "{label}: candidates"
        );
        assert_eq!(
            left.fallback_candidates_examined, right.fallback_candidates_examined,
            "{label}: fallback candidates"
        );
        assert_eq!(
            records(left.records),
            records(right.records),
            "{label}: ordered records"
        );
    }
    fn payloads<T: Serialize>(
        records: impl Iterator<Item = (Arc<T>, Arc<ActiveSemanticModelShard>)>,
    ) -> Vec<String> {
        records
            .map(|(record, shard)| {
                canonical((
                    record,
                    &shard.manifest.content_sha256,
                    &shard.descriptor.shard_id,
                    shard.source_kind,
                    &shard.source_id,
                ))
            })
            .collect()
    }
    assert_eq!(
        single_reader_rows(decoded.result_contract_name_inventory())
            .into_iter()
            .collect::<Vec<_>>(),
        single_reader_rows(rows.result_contract_name_inventory())
            .into_iter()
            .collect::<Vec<_>>(),
        "result-contract name inventory"
    );
    let targets = |active: &ResolvedActiveSemanticModels| {
        let mut result = Vec::new();
        active
            .visit_procedure_summary_targets(|digest, language, targets| {
                result.push((
                    digest.to_owned(),
                    language.to_owned(),
                    targets
                        .map(|(id, target)| (id.to_owned(), target.clone()))
                        .collect::<Vec<_>>(),
                ));
            })
            .expect("the parity oracle compares single-reader paths");
        result
    };
    assert_eq!(
        targets(decoded),
        targets(&rows),
        "target census, including present-empty primary payloads"
    );
    assert_eq!(
        payloads(single_reader_rows(decoded.runtime_values()).into_iter()),
        payloads(single_reader_rows(rows.runtime_values()).into_iter()),
        "runtime values"
    );
    assert_eq!(
        payloads(single_reader_rows(decoded.runtime_contracts()).into_iter()),
        payloads(single_reader_rows(rows.runtime_contracts()).into_iter()),
        "runtime contracts"
    );
    assert_eq!(
        payloads(single_reader_rows(decoded.collection_flows()).into_iter()),
        payloads(single_reader_rows(rows.collection_flows()).into_iter()),
        "collection flows"
    );
    assert_eq!(
        payloads(single_reader_rows(decoded.deferred_yields()).into_iter()),
        payloads(single_reader_rows(rows.deferred_yields()).into_iter()),
        "deferred yields"
    );
    assert_eq!(
        records(
            single_reader_rows(decoded.generator_rules())
                .into_iter()
                .collect()
        ),
        records(
            single_reader_rows(rows.generator_rules())
                .into_iter()
                .collect()
        ),
        "generator inventory"
    );
    for (family, key, _) in decoded.indexes.parity_postings() {
        let label = format!("{family}: {key:?}");
        match family {
            "types_id" => {
                matched(
                    &label,
                    decoded.types_with_id(&key[0]),
                    rows.types_with_id(&key[0]),
                );
                assert_eq!(
                    records(
                        single_reader_rows(decoded.all_type_records_with_id(&key[0])).collect()
                    ),
                    records(single_reader_rows(rows.all_type_records_with_id(&key[0])).collect()),
                    "{label}: raw records"
                );
            }
            "types_name" => {
                matched(
                    &label,
                    decoded.types_named(&key[0]),
                    rows.types_named(&key[0]),
                );
                assert_eq!(
                    records(single_reader_rows(decoded.all_type_records_named(&key[0])).collect()),
                    records(single_reader_rows(rows.all_type_records_named(&key[0])).collect()),
                    "{label}: raw records"
                );
            }
            "members_id" => {
                matched(
                    &label,
                    decoded.members_with_id(&key[0]),
                    rows.members_with_id(&key[0]),
                );
                assert_eq!(
                    records(
                        single_reader_rows(decoded.all_member_records_with_id(&key[0])).collect()
                    ),
                    records(single_reader_rows(rows.all_member_records_with_id(&key[0])).collect()),
                    "{label}: raw records"
                );
            }
            "members_owner_name" => matched(
                &label,
                decoded.members_named(&key[0], &key[1]),
                rows.members_named(&key[0], &key[1]),
            ),
            "relations_id" => matched(
                &label,
                decoded.relations_with_id(&key[0]),
                rows.relations_with_id(&key[0]),
            ),
            "relations_from" => matched(
                &label,
                decoded.relations_from(&key[0]),
                rows.relations_from(&key[0]),
            ),
            "relations_to" => matched(
                &label,
                decoded.relations_to(&key[0]),
                rows.relations_to(&key[0]),
            ),
            "rules_id" => matched(
                &label,
                decoded.rules_with_id(&key[0]),
                rows.rules_with_id(&key[0]),
            ),
            "rules_call" | "rules_construct" | "rules_annotation" | "rules_macro"
            | "rules_generator" | "rules_owner" => {
                let trigger = || match family {
                    "rules_call" => RuleTriggerKey::ResolvedCall {
                        owner: &key[0],
                        name: &key[1],
                    },
                    "rules_construct" => RuleTriggerKey::LanguageConstruct(&key[0]),
                    "rules_annotation" => RuleTriggerKey::Annotation(&key[0]),
                    "rules_macro" => RuleTriggerKey::MacroInvocation(&key[0]),
                    "rules_generator" => RuleTriggerKey::GeneratorInvocation(&key[0]),
                    "rules_owner" => RuleTriggerKey::ResolvedOwner(&key[0]),
                    _ => unreachable!(),
                };
                matched(
                    &label,
                    decoded.rules_for("jvm", trigger()),
                    rows.rules_for("jvm", trigger()),
                );
            }
            _ => {}
        }
    }
    matched(
        "missing type",
        decoded.types_with_id("not.in.this.pack"),
        rows.types_with_id("not.in.this.pack"),
    );
    matched(
        "missing member",
        decoded.members_with_id("not.in.this.pack"),
        rows.members_with_id("not.in.this.pack"),
    );
    for (shard, row_shard) in decoded.shards.iter().zip(&rows.shards) {
        if let Some(summaries) = shard.decoded().payload().procedure_summaries() {
            assert_eq!(
                decoded.procedure_summary_shard_order(shard),
                rows.procedure_summary_shard_order(row_shard)
            );
            for summary in summaries {
                use crate::analyzer::semantic_model::{
                    ProcedureSummaryDeclarationKey, ProcedureSummaryMemberKey,
                    ProcedureSummaryTargetKey,
                };
                let target = &summary.target;
                let key = ProcedureSummaryTargetKey {
                    language: &shard.manifest.language,
                    path: &target.path,
                    symbol: &target.symbol,
                    has_receiver: target.has_receiver,
                    parameter_count: target.parameter_count,
                };
                summary_match(
                    "exact target",
                    decoded.procedure_summaries_for(key),
                    rows.procedure_summaries_for(key),
                );
                if let Some((owner, member)) =
                    crate::analyzer::semantic::oracle::dispatch::authored_procedure_target_identity(
                        &target.path,
                        &target.symbol,
                    )
                {
                    let mut counts = BTreeSet::from([0, target.parameter_count]);
                    if let Some(next) = target.parameter_count.checked_add(1) {
                        counts.insert(next);
                    }
                    for count in counts {
                        let key = ProcedureSummaryMemberKey::new(
                            &shard.manifest.language,
                            &owner,
                            member,
                            target.has_receiver,
                            count,
                        );
                        summary_match(
                            "member",
                            decoded.procedure_summaries_for_member(key),
                            rows.procedure_summaries_for_member(key),
                        );
                        if let Some(language) =
                            Language::from_config_label(&shard.manifest.language)
                        {
                            let external = crate::analyzer::semantic::oracle::dispatch::UnmaterializedExternalTarget::new_modeled(
                                &*owner,
                                member,
                                crate::analyzer::semantic::ids::SemanticLanguage::Standard(language),
                                count,
                                target.has_receiver,
                            ).expect("authored summary target has a modeled locator");
                            summary_match(
                                "external target",
                                decoded.procedure_summaries_for_external_target(&external),
                                rows.procedure_summaries_for_external_target(&external),
                            );
                            summary_match(
                                "selected JDK requires resolver-owned evidence",
                                decoded.procedure_summaries_for_selected_jdk_artifact(&external),
                                rows.procedure_summaries_for_selected_jdk_artifact(&external),
                            );
                        }
                        assert_eq!(
                            decoded.has_normal_return_type_refinement_candidate(
                                &shard.manifest.language,
                                member,
                                target.has_receiver,
                                count
                            ),
                            rows.has_normal_return_type_refinement_candidate(
                                &shard.manifest.language,
                                member,
                                target.has_receiver,
                                count
                            ),
                            "return refinement hint"
                        );
                        assert_eq!(
                            decoded.proves_normal_continuation_absent(key),
                            rows.proves_normal_continuation_absent(key),
                            "absence proof"
                        );
                        assert_eq!(
                            decoded.normal_continuation_absence_candidate_owners(
                                &shard.manifest.language,
                                member,
                                target.has_receiver
                            ),
                            rows.normal_continuation_absence_candidate_owners(
                                &shard.manifest.language,
                                member,
                                target.has_receiver
                            ),
                            "absence candidate owners"
                        );
                        assert_eq!(
                            decoded.has_normal_continuation_absence_candidates(
                                &shard.manifest.language
                            ),
                            rows.has_normal_continuation_absence_candidates(
                                &shard.manifest.language
                            ),
                            "absence language hint"
                        );
                        assert_eq!(
                            decoded.has_receiverless_procedure_summary_member(
                                &shard.manifest.language,
                                &owner,
                                member
                            ),
                            rows.has_receiverless_procedure_summary_member(
                                &shard.manifest.language,
                                &owner,
                                member
                            ),
                            "receiverless hint"
                        );
                        let key = ProcedureSummaryDeclarationKey::new(
                            &shard.manifest.language,
                            &target.path,
                            member,
                            target.has_receiver,
                            count,
                        );
                        summary_match(
                            "declaration",
                            decoded.procedure_summaries_for_declaration(key),
                            rows.procedure_summaries_for_declaration(key),
                        );
                    }
                }
                assert_eq!(
                    decoded.procedure_summary_family(shard, [summary.id.as_str()]),
                    rows.procedure_summary_family(row_shard, [summary.id.as_str()])
                );
            }
        }
    }
}

fn summary_match(
    label: &str,
    left: crate::analyzer::semantic_model::runtime::ProcedureSummaryMatch,
    right: crate::analyzer::semantic_model::runtime::ProcedureSummaryMatch,
) {
    assert_eq!(
        left.applicability, right.applicability,
        "{label}: applicability"
    );
    assert_eq!(left.disposition, right.disposition, "{label}: disposition");
    assert_eq!(
        left.candidates_examined, right.candidates_examined,
        "{label}: candidates"
    );
    assert_eq!(
        left.fallback_candidates_examined, right.fallback_candidates_examined,
        "{label}: fallback candidates"
    );
    assert_eq!(
        left.records.len(),
        right.records.len(),
        "{label}: selected count"
    );
    for (left, right) in left.records.iter().zip(&right.records) {
        assert_eq!(left.record, right.record, "{label}: ordered summary");
        assert_eq!(
            left.actual_to_formal, right.actual_to_formal,
            "{label}: formal mapping"
        );
        assert_eq!(
            left.matched_owner_identity, right.matched_owner_identity,
            "{label}: owner"
        );
        assert_eq!(
            left.matched_target_locator, right.matched_target_locator,
            "{label}: locator"
        );
        assert_eq!(
            left.matched_call_arguments, right.matched_call_arguments,
            "{label}: arguments"
        );
        assert_eq!(
            left.shard.manifest.content_sha256, right.shard.manifest.content_sha256,
            "{label}: manifest"
        );
        assert_eq!(
            left.shard.descriptor.shard_id, right.shard.descriptor.shard_id,
            "{label}: shard"
        );
    }
}

#[doc(hidden)]
pub fn metadata_only_active(
    decoded: &ResolvedActiveSemanticModels,
    reader: &crate::analyzer::store::model_catalog::CatalogRuntimeSourceReader,
) -> Arc<ResolvedActiveSemanticModels> {
    let mut rows = active(
        decoded
            .shards
            .iter()
            .map(|shard| ActiveSemanticModelShard {
                metadata: Arc::clone(&shard.metadata),
                decoded: if crate::analyzer::semantic_model::runtime::row_backing_language_supported_in_m2(&shard.manifest.language) {
                    None
                } else { shard.decoded.clone() },
            })
            .collect(),
    );
    rows.report = decoded.report.clone();
    rows.active_model_set_hash = decoded.active_model_set_hash.clone();
    rows.extraction_gaps = decoded.extraction_gaps.clone();
    rows.extraction_gaps_by_declaration = decoded.extraction_gaps_by_declaration.clone();
    let reader = Arc::new(reader.clone());
    {
        let installed_source: Option<
            Arc<dyn crate::analyzer::store::model_catalog::RequestRowReaderSource>,
        > = Some(Arc::new(
            crate::analyzer::store::model_catalog::ActivationRowReaderSource::new(
                Arc::clone(&reader),
                &rows.active_model_set_hash,
            ),
        ));
        rows.install_request_source(installed_source).unwrap();
    };
    rows.source_reader = Some(reader);
    eprintln!(
        "entry backing: row_backed_shards={}, decoded_shards={}",
        rows.shards
            .iter()
            .filter(|shard| shard.decoded.is_none())
            .count(),
        rows.shards
            .iter()
            .filter(|shard| shard.decoded.is_some())
            .count()
    );
    Arc::new(rows)
}

#[cfg(test)]
#[test]
fn selected_external_descriptor_preserves_owner_member_ordinal_across_backings() {
    use crate::analyzer::resolution::{ExternalMemberIdentity, ExternalOwnerIdentity};
    use crate::analyzer::semantic_model::{CompilerOptions, SourceFormat, compile_source};
    use crate::analyzer::store::active_models::selected_external_descriptor;

    // Test-only declaration fixture: public members precede additional inventory
    // members, with guards excluded before assigning provider ordinals.
    let mut source: Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/semantic-model-packs/declarations-v1.json"
    )))
    .unwrap();
    let payload = &mut source["shards"][0]["payload"];
    let member = payload["members"][0].clone();
    let mut second = member.clone();
    second["id"] = json!("member.widget.z");
    second["name"] = json!("second");
    let mut additional = member.clone();
    additional["id"] = json!("member.widget.a");
    additional["name"] = json!("additional");
    payload["members"] = json!([second, member]);
    payload["types"][0]["jvm_inventory"] = json!({
        "callables_complete": true, "values_complete": true,
        "types_complete": true, "supertypes_complete": true,
        "supertypes": [], "nested_types": [], "additional_members": [additional]
    });
    let pack = compile_source(
        SourceFormat::Json,
        &serde_json::to_vec(&source).unwrap(),
        &CompilerOptions::default(),
    )
    .unwrap();
    let (decoded, reader) = catalog_fixture_active(&[pack], "external-descriptor-order");
    let mut rows = active(
        decoded
            .shards
            .iter()
            .map(|shard| ActiveSemanticModelShard {
                metadata: Arc::clone(&shard.metadata),
                decoded: None,
            })
            .collect(),
    );
    let reader = Arc::new(reader);
    {
        let installed_source: Option<
            Arc<dyn crate::analyzer::store::model_catalog::RequestRowReaderSource>,
        > = Some(Arc::new(
            crate::analyzer::store::model_catalog::ActivationRowReaderSource::new(
                Arc::clone(&reader),
                &rows.active_model_set_hash,
            ),
        ));
        rows.install_request_source(installed_source).unwrap();
    };
    rows.source_reader = Some(reader);
    assert!(decoded.shards.iter().all(|shard| shard.decoded.is_some()));
    assert!(rows.shards.iter().all(|shard| shard.decoded.is_none()));
    let shard = &decoded.shards[0];
    let (types, members, _) = shard.decoded().payload().declaration_facts().unwrap();
    let owner = &types[0];
    let published = members
        .iter()
        .map(AsRef::as_ref)
        .chain(&owner.jvm_inventory.as_ref().unwrap().additional_members)
        .filter(|member| member.owner == owner.id && member.guard.is_none())
        .collect::<Vec<_>>();
    assert_eq!(published.len(), 3);
    for (ordinal, member) in published.iter().enumerate() {
        let selected = ExternalMemberIdentity {
            owner: ExternalOwnerIdentity {
                provider_id: shard.manifest.semantic_sha256.as_str().into(),
                owner_fqn: owner.name.as_str().into(),
            },
            ordinal: u32::try_from(ordinal).unwrap(),
        };
        let expected = Some((shard.manifest.semantic_sha256.clone(), member.id.clone()));
        assert_eq!(
            selected_external_descriptor(&decoded, &selected)
                .expect("the parity oracle compares single-reader paths"),
            expected
        );
        assert_eq!(
            selected_external_descriptor(&rows, &selected)
                .expect("the parity oracle compares single-reader paths"),
            expected
        );
    }
}

#[cfg(test)]
#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#6685: summaries for a declaration followed HashMap bucket order"
)]
fn declaration_summaries_follow_symbol_publication_order() {
    use crate::analyzer::semantic_model::{
        CompilerOptions, ProcedureSummaryDeclarationKey, SourceFormat, compile_source,
    };
    let mut source: Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/semantic-model-packs/procedure-summaries-v1.json"
    )))
    .unwrap();
    let mut first = source["shards"][0]["payload"]["summaries"][0].clone();
    first["id"] = json!("summary.a");
    first["target"]["symbol"] = json!("lookup(Z)");
    first["effects"] = json!([]);
    first["locations"] = json!([]);
    first["transfers"] = json!([{ "input": { "kind":"parameter", "ordinal":0 },
        "exit_kind":"normal", "output": { "kind":"normal_return" } }]);
    first["completeness"] = json!("partial");
    let mut second = first.clone();
    second["id"] = json!("summary.b");
    second["target"]["symbol"] = json!("lookup(A)");
    second["completeness"] = json!("complete");
    source["shards"][0]["payload"]["summaries"] = json!([second, first]);
    let pack = compile_source(
        SourceFormat::Json,
        &serde_json::to_vec(&source).unwrap(),
        &CompilerOptions::default(),
    )
    .unwrap();
    let validated = validate_pack(&pack, &DecodeLimits::default()).unwrap();
    let active = active(fixture_shards(&pack, validated.shards, "declaration-order"));
    let result = active.procedure_summaries_for_declaration(ProcedureSummaryDeclarationKey::new(
        "java",
        "com/acme/Flows.class",
        "lookup",
        true,
        1,
    ));
    assert_eq!(
        result
            .records
            .iter()
            .map(|r| r.record.id.as_str())
            .collect::<Vec<_>>(),
        ["summary.a", "summary.b"]
    );
    assert_pack_parity(&pack, "declaration-publication-order");
}

#[cfg(test)]
#[test]
fn catalog_presence_distinguishes_absent_and_present_empty_payloads() {
    use crate::analyzer::semantic_model::{CompilerOptions, SourceFormat, compile_source};
    let mut source: Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/semantic-model-packs/declarations-v1.json"
    )))
    .unwrap();
    source["language"] = json!("rust");
    source["ecosystem"] = json!("cargo");
    source["compatibility"]["toolchains"] = json!([]);
    let absent = compile_source(
        SourceFormat::Json,
        &serde_json::to_vec(&source).unwrap(),
        &CompilerOptions::default(),
    )
    .unwrap();
    assert_pack_parity(&absent, "absent-companions");
    use brokk_bifrost_semantic::analyzer::semantic_model::catalog::rows::SemanticPayloadFamily;
    // These companions live on the shard and distinguish absence from an
    // explicitly empty payload. Type forwards are a declaration vector;
    // an empty vector is omitted, not a present-empty companion.
    let present_empty = [
        SemanticPayloadFamily::CollectionFlows,
        SemanticPayloadFamily::ConditionalTypeRefinements,
        SemanticPayloadFamily::DeferredYields,
    ];
    for family in present_empty {
        source["shards"][0][family.as_str()] = json!({});
    }
    source["shards"][0]["runtime_values"] = json!({});
    let present = compile_source(
        SourceFormat::Json,
        &serde_json::to_vec(&source).unwrap(),
        &CompilerOptions::default(),
    )
    .unwrap();
    let validated = validate_pack(&present, &DecodeLimits::default()).unwrap();
    assert_eq!(validated.shards.len(), 1);
    for family in
        brokk_bifrost_semantic::analyzer::semantic_model::catalog::rows::SemanticPayloadFamily::ALL
    {
        assert_eq!(
            family.is_present(&validated.shards[0].decoded),
            present_empty.contains(&family),
            "{family:?} fixture route ran"
        );
    }
    assert_pack_parity(&present, "present-empty-companions");
}

fn assert_overlay_entry_parity(
    decoded_active: &ResolvedActiveSemanticModels,
    row_active: &ResolvedActiveSemanticModels,
    decoded: &SemanticModelOverlay,
    rows: &SemanticModelOverlay,
    label: &str,
) {
    let symbols = decoded.symbols();
    assert_eq!(symbols, rows.symbols(), "{label}: symbol enumeration");
    let relations = decoded.relations();
    assert_eq!(relations, rows.relations(), "{label}: relation enumeration");
    assert_eq!(
        decoded.composition_diagnostics(),
        rows.composition_diagnostics(),
        "{label}: diagnostic enumeration"
    );
    assert_eq!(
        format!("{:?}", decoded.runtime_value_contracts()),
        format!("{:?}", rows.runtime_value_contracts()),
        "{label}: runtime contracts"
    );
    assert_eq!(
        format!("{:?}", decoded.collection_flow_contracts()),
        format!("{:?}", rows.collection_flow_contracts()),
        "{label}: flow inventory"
    );
    assert_eq!(
        format!("{:?}", decoded.deferred_yield_contracts()),
        format!("{:?}", rows.deferred_yield_contracts()),
        "{label}: yield inventory"
    );
    let mut endpoints = BTreeSet::new();
    for relation in &relations {
        endpoints.insert(relation.from.as_str());
        endpoints.insert(relation.to.as_str());
    }
    endpoints.insert("not.in.this.pack");
    for id in endpoints {
        assert_eq!(
            format!("{:?}", decoded.relations_from(id)),
            format!("{:?}", rows.relations_from(id)),
            "{label}: relations from {id}"
        );
        assert_eq!(
            format!("{:?}", decoded.relations_to(id)),
            format!("{:?}", rows.relations_to(id)),
            "{label}: relations to {id}"
        );
    }
    for symbol in &symbols {
        assert_eq!(
            decoded.visible_public_symbol(&symbol.qualified_name, &symbol.language),
            rows.visible_public_symbol(&symbol.qualified_name, &symbol.language),
            "{label}: public symbol"
        );
        assert_eq!(
            decoded.callable_family_id_for_symbol(symbol),
            rows.callable_family_id_for_symbol(symbol),
            "{label}: callable family"
        );
        assert_eq!(
            format!("{:?}", decoded.collection_flows_for(&symbol.id)),
            format!("{:?}", rows.collection_flows_for(&symbol.id)),
            "{label}: collection flow"
        );
        assert_eq!(
            format!(
                "{:?}",
                decoded
                    .conditional_type_refinements_for(symbol)
                    .collect::<Vec<_>>()
            ),
            format!(
                "{:?}",
                rows.conditional_type_refinements_for(symbol)
                    .collect::<Vec<_>>()
            ),
            "{label}: refinement"
        );
        assert_eq!(
            format!("{:?}", decoded.deferred_yields_for_factory(&symbol.id)),
            format!("{:?}", rows.deferred_yields_for_factory(&symbol.id)),
            "{label}: yield factory"
        );
        assert_eq!(
            decoded.has_generated_functions(&symbol.language),
            rows.has_generated_functions(&symbol.language),
            "{label}: generated language"
        );
        assert_eq!(
            format!(
                "{:?}",
                decoded.universal_root_for_language(&symbol.language)
            ),
            format!("{:?}", rows.universal_root_for_language(&symbol.language)),
            "{label}: universal root"
        );
        // This shared crate does not link language hook implementations. The
        // root corpus invokes this same matrix with the real language table.
        if Language::from_config_label(&symbol.language)
            .and_then(crate::analyzer::languages::language_support)
            .is_none()
        {
            continue;
        }
        if let Some(owner_id) = &symbol.owner_id {
            assert_eq!(
                format!("{:?}", decoded.members_named(owner_id, &symbol.name)),
                format!("{:?}", rows.members_named(owner_id, &symbol.name)),
                "{label}: named member"
            );
            assert_eq!(
                format!(
                    "{:?}",
                    decoded.member_target_on_owner(owner_id, &symbol.name)
                ),
                format!("{:?}", rows.member_target_on_owner(owner_id, &symbol.name)),
                "{label}: member target"
            );
            assert_eq!(
                decoded.member_present_on_owner(owner_id, &symbol.name),
                rows.member_present_on_owner(owner_id, &symbol.name),
                "{label}: member presence"
            );
            if let Some(operation) = &symbol.implicit_operation {
                assert_eq!(
                    format!(
                        "{:?}",
                        decoded.implicit_member_target_on_owner(owner_id, operation)
                    ),
                    format!(
                        "{:?}",
                        rows.implicit_member_target_on_owner(owner_id, operation)
                    ),
                    "{label}: implicit operation"
                );
            }
            let owners = decoded.symbols_with_id(owner_id);
            for owner in owners.records {
                assert_eq!(
                    format!(
                        "{:?}",
                        decoded.callable_owners_on_surface(decoded_active, &owner, &symbol.name)
                    ),
                    format!(
                        "{:?}",
                        rows.callable_owners_on_surface(row_active, &owner, &symbol.name)
                    ),
                    "{label}: callable owner surface"
                );
                let count = symbol
                    .structured_signature
                    .as_ref()
                    .map_or(0, |signature| signature.parameters.len() as u32);
                for arity in [0, count, count.saturating_add(1)] {
                    let key = SemanticModelCallableKey::new(
                        &symbol.language,
                        &owner.qualified_name,
                        &symbol.name,
                        symbol.has_receiver(),
                        arity,
                    );
                    assert_eq!(
                        format!("{:?}", decoded.callable_for_target(key)),
                        format!("{:?}", rows.callable_for_target(key)),
                        "{label}: callable target"
                    );
                    assert_eq!(
                        format!(
                            "{:?}",
                            decoded.callable_for_application(
                                key,
                                &SemanticModelCallApplication::positional(arity)
                            )
                        ),
                        format!(
                            "{:?}",
                            rows.callable_for_application(
                                key,
                                &SemanticModelCallApplication::positional(arity)
                            )
                        ),
                        "{label}: callable application"
                    );
                    assert_eq!(
                        decoded.callable_family_id_for_target(key),
                        rows.callable_family_id_for_target(key),
                        "{label}: target family"
                    );
                    assert_eq!(
                        format!(
                            "{:?}",
                            decoded.explicit_member_target_on_owner(
                                owner_id,
                                &symbol.name,
                                arity as usize
                            )
                        ),
                        format!(
                            "{:?}",
                            rows.explicit_member_target_on_owner(
                                owner_id,
                                &symbol.name,
                                arity as usize
                            )
                        ),
                        "{label}: explicit operation"
                    );
                }
            }
        } else {
            let ancestry = decoded.ancestors_of(symbol);
            let actual = rows.ancestors_of(symbol);
            assert_eq!(ancestry.records, actual.records, "{label}: ancestor order");
            assert_eq!(
                ancestry.disposition, actual.disposition,
                "{label}: ancestor disposition"
            );
            assert_eq!(
                ancestry.defects, actual.defects,
                "{label}: ancestor defects"
            );
            assert_eq!(
                format!("{:?}", decoded.owner_surface(symbol)),
                format!("{:?}", rows.owner_surface(symbol)),
                "{label}: owner surface"
            );
        }
    }
    for contract in decoded.runtime_value_contracts() {
        for exposure in contract.exposures() {
            for language in &exposure.languages {
                assert_eq!(
                    format!(
                        "{:?}",
                        decoded.runtime_exposures(&exposure.binding_name, language)
                    ),
                    format!(
                        "{:?}",
                        rows.runtime_exposures(&exposure.binding_name, language)
                    ),
                    "{label}: runtime exposure"
                );
            }
        }
    }
    for contract in decoded.deferred_yield_contracts() {
        assert_eq!(
            format!(
                "{:?}",
                decoded.deferred_yields_for(
                    &contract.factory,
                    &contract.resume,
                    &contract.handle_type
                )
            ),
            format!(
                "{:?}",
                rows.deferred_yields_for(
                    &contract.factory,
                    &contract.resume,
                    &contract.handle_type
                )
            ),
            "{label}: deferred scope"
        );
    }
    for pattern in [".*", "create|open|spawn", "^no_such_semantic_symbol$"] {
        let patterns = crate::analyzer::SearchSymbolPatternBatch::compile(
            vec![pattern.to_owned()],
            false,
            None,
        );
        for limit in [0, 1, 3, usize::MAX] {
            assert_eq!(
                decoded.search_with_limit(&patterns, limit, None),
                rows.search_with_limit(&patterns, limit, None),
                "{label}: bounded search {pattern} limit {limit}"
            );
            assert_eq!(
                decoded.search_with_limit_filter(&patterns, limit, None, |s| s.name.len() % 2 == 0),
                rows.search_with_limit_filter(&patterns, limit, None, |s| s.name.len() % 2 == 0),
                "{label}: predicate search {pattern}"
            );
        }
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        // Cancellation stops pending row work. Both complete answers must
        // match exactly; a cancelled row read may be incomplete where an
        // already-composed empty decoded publication needs no further work.
        let expected = decoded.search_with_limit(&patterns, 3, Some(&cancelled));
        let actual = rows.search_with_limit(&patterns, 3, Some(&cancelled));
        if expected.2 && !actual.2 {
            assert!(
                cancelled.is_cancelled(),
                "only cancellation permits incomplete row parity"
            );
        } else {
            assert_eq!(expected, actual, "{label}: cancelled search");
        }
    }
    eprintln!(
        "{label}: full entry parity, symbols={}, relations={}",
        symbols.len(),
        relations.len()
    );
}

#[cfg(test)]
#[test]
fn catalog_row_entries_for_rust_summary_families() {
    use crate::analyzer::semantic_model::{CompilerOptions, SourceFormat, compile_source};
    let mut source: Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/semantic-model-packs/procedure-summaries-v1.json"
    )))
    .unwrap();
    source["language"] = json!("rust");
    source["ecosystem"] = json!("cargo");
    source["compatibility"]["toolchains"] = json!([]);
    let pack = compile_source(
        SourceFormat::Json,
        &serde_json::to_vec(&source).unwrap(),
        &CompilerOptions::default(),
    )
    .unwrap();
    assert_pack_parity(&pack, "rust-summary-family-entries");
}

/// Search parity for explicitly test-only packs in a row-supported language.
pub fn assert_pack_search_parity(
    analyzer: &dyn IAnalyzer,
    packs: &[CompiledSemanticModelPack],
    pattern: &str,
) -> Vec<Arc<SemanticModelSymbol>> {
    let (active, reader) = catalog_fixture_active(packs, "exact-search-spelling");
    let rows = metadata_only_active(&active, &reader);
    assert!(
        rows.shards.iter().all(|s| s.decoded.is_none()),
        "the row search must run"
    );
    let before = SemanticModelOverlay::build(
        analyzer,
        &active,
        &CancellationToken::new(),
        u64::MAX,
        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
    )
    .unwrap();
    let after = SemanticModelOverlay::build(
        analyzer,
        &rows,
        &CancellationToken::new(),
        u64::MAX,
        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
    )
    .unwrap();
    let patterns =
        crate::analyzer::SearchSymbolPatternBatch::compile(vec![pattern.to_owned()], false, None);
    for limit in [0, 1, usize::MAX] {
        assert_eq!(
            before.search_with_limit(&patterns, limit, None),
            after.search_with_limit(&patterns, limit, None),
            "exact spelling {pattern}, limit {limit}"
        );
    }
    after.search_with_limit(&patterns, usize::MAX, None).0
}

#[cfg(test)]
#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#6685: pre-composition candidates omitted a curated-only member's representative-qualified name"
)]
fn catalog_row_search_preserves_renamed_curated_only_member() {
    use crate::analyzer::semantic_model::{
        ArtifactExtraction, ArtifactExtractionKind, CompilerOptions, SourceFormat, compile_source,
    };
    let mut source: Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/semantic-model-packs/declarations-v1.json"
    )))
    .unwrap();
    source["language"] = json!("rust");
    source["ecosystem"] = json!("cargo");
    source["compatibility"]["toolchains"] = json!([]);
    let mut owner = source["shards"][0]["payload"]["types"][0].clone();
    owner["hierarchy"] = json!([]);
    owner["aliases"] = json!([]);
    let mut member = source["shards"][0]["payload"]["members"][0].clone();
    source["shards"][0]["payload"] = json!({ "kind":"declaration_facts", "types":[owner.clone()], "members":[], "relations":[] });
    source["pack_id"] = json!("fixture.search-artifact");
    source["schema_version"] =
        json!(crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION);
    source["compatibility"]
        .as_object_mut()
        .unwrap()
        .remove("bifrost");
    let mut artifact: crate::analyzer::semantic_model::AuthoredSemanticModelPack =
        serde_json::from_value(source.clone()).unwrap();
    artifact.extraction = Some(ArtifactExtraction::single(
        ArtifactExtractionKind::RustdocJson,
        &"a".repeat(64),
    ));
    let artifact =
        crate::analyzer::semantic_model::compile_pack(&artifact, &CompilerOptions::default())
            .unwrap();
    source["pack_id"] = json!("fixture.search-curated");
    owner["id"] = json!("type.curated.widget");
    owner["name"] = json!("alias.Widget");
    owner["aliases"] = json!(["com.acme.Widget"]);
    member["id"] = json!("member.curated.only");
    member["owner"] = json!("type.curated.widget");
    member["name"] = json!("curated_only");
    member["aliases"] = json!([]);
    member["visibility"] = json!("public");
    source["shards"][0]["payload"]["types"] = json!([owner]);
    source["shards"][0]["payload"]["members"] = json!([member]);
    let curated = compile_source(
        SourceFormat::Json,
        &serde_json::to_vec(&source).unwrap(),
        &CompilerOptions::default(),
    )
    .unwrap();
    source["pack_id"] = json!("fixture.search-single");
    source["shards"][0]["payload"]["types"][0]["id"] = json!("type.single");
    source["shards"][0]["payload"]["types"][0]["name"] = json!("standalone.Widget");
    source["shards"][0]["payload"]["types"][0]["aliases"] = json!([]);
    source["shards"][0]["payload"]["members"][0]["id"] = json!("member.single.only");
    source["shards"][0]["payload"]["members"][0]["owner"] = json!("type.single");
    let single = compile_source(
        SourceFormat::Json,
        &serde_json::to_vec(&source).unwrap(),
        &CompilerOptions::default(),
    )
    .unwrap();
    let (active, reader) =
        catalog_fixture_active(&[artifact, curated, single], "renamed-curated-only-member");
    let rows = metadata_only_active(&active, &reader);
    assert!(
        rows.shards.iter().all(|s| s.decoded.is_none()),
        "the witness must use rows"
    );
    let directory = TempDir::new().unwrap();
    let analyzer = EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Rust)));
    let before = SemanticModelOverlay::build(
        &analyzer,
        &active,
        &CancellationToken::new(),
        u64::MAX,
        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
    )
    .unwrap();
    let mut after = SemanticModelOverlay::build(
        &analyzer,
        &rows,
        &CancellationToken::new(),
        u64::MAX,
        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
    )
    .unwrap();
    let cache = crate::analyzer::store::cache_budget::StoreCacheBudget::new(
        &crate::retention_budget::RetentionBudget::for_tests(),
    );
    Arc::make_mut(after.row_source.as_mut().unwrap()).cache = Some(cache.clone());
    // Group the terminal identifier so sigil normalization preserves '$' as an anchor.
    let patterns = crate::analyzer::SearchSymbolPatternBatch::compile(
        vec!["^com[.]acme[.]Widget[.](?:curated_only)$".into()],
        false,
        None,
    );
    for limit in [0, 1, usize::MAX] {
        let expected = before.search_with_limit(&patterns, limit, None);
        let actual = after.search_with_limit(&patterns, limit, None);
        assert_eq!(expected, actual);
        assert_eq!(actual.1, 1, "the composed spelling must match");
        assert!(actual.2);
        if let Some(symbol) = actual.0.first() {
            assert_eq!(symbol.id, "member.curated.only");
            assert_eq!(symbol.qualified_name, "com.acme.Widget.curated_only");
            assert!(
                symbol
                    .aliases
                    .iter()
                    .any(|a| a == "alias.Widget.curated_only")
            );
        }
    }
    let mixed = crate::analyzer::SearchSymbolPatternBatch::compile(
        vec!["curated_only".into()],
        false,
        None,
    );
    for limit in [0, 1, 2, usize::MAX] {
        let expected = before.search_with_limit(&mixed, limit, None);
        let actual = after.search_with_limit(&mixed, limit, None);
        assert_eq!(expected, actual, "single/multi merge, limit {limit}");
        assert_eq!(actual.1, 2, "both matching groups ran");
        assert!(actual.2);
    }
    assert_eq!(
        cache.composition_cache_stats().group_misses,
        1,
        "only the matching multi-contributor group composes"
    );
    assert_overlay_entry_parity(
        &active,
        &rows,
        &before,
        &after,
        "renamed-curated-only-member",
    );
}

#[cfg(test)]
#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#6685: a sole owner in an alias group still needs global raw-ID and guarded qualification"
)]
fn catalog_row_single_contributor_search_preserves_exceptional_qualification() {
    use crate::analyzer::semantic_model::{CompilerOptions, SourceFormat, compile_source};
    use crate::analyzer::store::cache_budget::StoreCacheBudget;
    let mut alpha: Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/semantic-model-packs/declarations-v1.json"
    )))
    .unwrap();
    alpha["schema_version"] = json!(crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION);
    alpha["language"] = json!("rust");
    alpha["ecosystem"] = json!("cargo");
    alpha["compatibility"] = json!({"toolchains":[]});
    alpha["pack_id"] = json!("fixture.single-alpha");
    let mut owner = alpha["shards"][0]["payload"]["types"][0].clone();
    owner["id"] = json!("shared.curated");
    owner["name"] = json!("Alpha");
    owner["aliases"] = json!([]);
    owner["hierarchy"] = json!([]);
    let mut member = alpha["shards"][0]["payload"]["members"][0].clone();
    member["id"] = json!("alpha.create");
    member["owner"] = json!("shared.curated");
    member["signature"] = json!({"parameters":[]});
    alpha["shards"][0]["payload"] =
        json!({"kind":"declaration_facts","types":[owner],"members":[member],"relations":[]});
    let mut beta = alpha.clone();
    beta["pack_id"] = json!("fixture.single-beta");
    beta["shards"][0]["payload"]["types"][0]["name"] = json!("Beta");
    beta["shards"][0]["payload"]["members"][0]["id"] = json!("beta.create");
    let mut guarded = alpha.clone();
    guarded["shards"][0]["payload"]["types"][0]["guard"] = json!({"required_targets":["windows"]});
    for (label, sources) in [("shared", vec![alpha, beta]), ("guarded", vec![guarded])] {
        let packs = sources
            .iter()
            .map(|source| {
                compile_source(
                    SourceFormat::Json,
                    &serde_json::to_vec(source).unwrap(),
                    &CompilerOptions::default(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let (mut active, reader) = catalog_fixture_active(&packs, label);
        let mutable = Arc::get_mut(&mut active).unwrap();
        for shard in &mut mutable.shards {
            Arc::get_mut(&mut Arc::get_mut(shard).unwrap().metadata)
                .unwrap()
                .matched_evidence
                .target = Some("linux".into());
        }
        mutable.indexes = MatcherIndexes::build(
            &mutable.shards,
            SemanticModelRuntimeLimits::default(),
            &CancellationToken::new(),
            &mut mutable.report,
        )
        .unwrap();
        let rows = metadata_only_active(&active, &reader);
        assert!(rows.shards.iter().all(|s| s.decoded.is_none()));
        let directory = TempDir::new().unwrap();
        let analyzer =
            EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Rust)));
        let before = SemanticModelOverlay::build(
            &analyzer,
            &active,
            &CancellationToken::new(),
            u64::MAX,
            &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
        )
        .unwrap();
        let mut after = SemanticModelOverlay::build(
            &analyzer,
            &rows,
            &CancellationToken::new(),
            u64::MAX,
            &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
        )
        .unwrap();
        let cache = StoreCacheBudget::new(&crate::retention_budget::RetentionBudget::for_tests());
        Arc::make_mut(after.row_source.as_mut().unwrap()).cache = Some(cache.clone());
        let patterns = crate::analyzer::SearchSymbolPatternBatch::compile(
            vec!["^shared[.]curated[.](?:create)$".into()],
            false,
            None,
        );
        for limit in [0, 1, usize::MAX] {
            let expected = before.search_with_limit(&patterns, limit, None);
            let actual = after.search_with_limit(&patterns, limit, None);
            assert_eq!(expected, actual, "{label}, limit {limit}");
            assert_eq!(actual.1, packs.len(), "positive matching path ran");
            assert!(actual.2);
            assert!(
                actual
                    .0
                    .iter()
                    .all(|s| s.qualified_name == "shared.curated.create")
            );
        }
        let stats = cache.composition_cache_stats();
        assert_eq!(
            stats.group_misses, 0,
            "single groups never compose: {label}"
        );
        assert!(stats.search_retained_bytes > 0, "row candidate stream ran");
    }
}

/// Entry parity on a live analyzer also checks generated facts and authored anchors.
pub fn assert_active_entry_parity(
    analyzer: &dyn IAnalyzer,
    active: &Arc<ResolvedActiveSemanticModels>,
) {
    let row_active = metadata_only_active(
        active,
        active
            .source_reader
            .as_ref()
            .expect("activated catalog reader"),
    );
    let mut before = SemanticModelOverlay::build(
        analyzer,
        active,
        &CancellationToken::new(),
        u64::MAX,
        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
    )
    .unwrap();
    let mut after = SemanticModelOverlay::build(
        analyzer,
        &row_active,
        &CancellationToken::new(),
        u64::MAX,
        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
    )
    .unwrap();
    assert!(
        active.shards.iter().all(|shard| shard.decoded.is_some()),
        "the accounting regression must exercise an all-decoded set"
    );
    assert!(before.row_source.is_none());
    let source = before
        .selected_source
        .take()
        .expect("selected original inputs");
    let [anchors, generated_symbols, generated_relations] = source.retained_owned_input_bytes();
    assert!(
        anchors > std::mem::size_of::<locations::SourceAnchors>(),
        "authored anchors must be retained"
    );
    assert!(
        generated_symbols > std::mem::size_of::<Vec<SemanticModelSymbol>>(),
        "generated symbols must be retained"
    );
    assert!(
        generated_relations > std::mem::size_of::<Vec<SemanticModelRelation>>(),
        "generated relations must be retained"
    );
    let without_copies = before.retained_bytes_lower_bound();
    before.selected_source = Some(source);
    let with_copies = before.retained_bytes_lower_bound();
    assert_eq!(
        with_copies - without_copies,
        (anchors + generated_symbols + generated_relations) as u64,
        "all-decoded overlay must charge exactly the retained anchors and generated vectors"
    );
    eprintln!(
        "D2_RETENTION live Rust generator/authored fixture: before={without_copies} after={with_copies} anchors={anchors} generated_symbols={generated_symbols} generated_relations={generated_relations}"
    );
    let both_sources = after.retained_bytes_lower_bound();
    let row_source = after.row_source.take().expect("row reader alias");
    assert!(Arc::ptr_eq(
        &row_source,
        after.selected_source.as_ref().unwrap()
    ));
    assert_eq!(
        after.retained_bytes_lower_bound(),
        both_sources,
        "aliased row and selected sources are charged once"
    );
    after.row_source = Some(row_source);
    assert_overlay_entry_parity(
        active,
        &row_active,
        &before,
        &after,
        "live-generated-and-authored-entry-parity",
    );
}

#[cfg(test)]
#[test]
fn catalog_row_cancelled_search_does_not_prove_guarded_emptiness() {
    use crate::analyzer::semantic_model::{CompilerOptions, SourceFormat, compile_source};
    let mut source: Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/semantic-model-packs/declarations-v1.json"
    )))
    .unwrap();
    source["schema_version"] =
        json!(crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION);
    source["compatibility"]
        .as_object_mut()
        .unwrap()
        .remove("bifrost");
    source["language"] = json!("rust");
    source["ecosystem"] = json!("cargo");
    source["compatibility"]["toolchains"] = json!([]);
    for records in ["types", "members"] {
        for record in source["shards"][0]["payload"][records]
            .as_array_mut()
            .unwrap()
        {
            record["guard"] = json!({"required_targets":["windows"]});
        }
    }
    let pack = compile_source(
        SourceFormat::Json,
        &serde_json::to_vec(&source).unwrap(),
        &CompilerOptions::default(),
    )
    .unwrap();
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    catalog
        .register_compiled_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::EphemeralWorkspace,
                source_id: "guard-empty-cancellation".into(),
            },
        )
        .unwrap();
    let validated = validate_pack(&pack, &DecodeLimits::default()).unwrap();
    let mut shards = fixture_shards(&pack, validated.shards, "guard-empty-cancellation");
    for shard in &mut shards {
        Arc::get_mut(&mut shard.metadata)
            .unwrap()
            .matched_evidence
            .target = Some("linux".into());
    }
    let mut decoded = active(shards);
    let (reader, identities) = catalog
        .runtime_source_reader_with_shard_keys(decoded.shards.iter().map(|s| {
            (
                s.manifest.content_sha256.as_str(),
                s.descriptor.shard_id.as_str(),
                s.source_kind,
            )
        }))
        .unwrap();
    for (shard, identity) in decoded.shards.iter_mut().zip(identities) {
        Arc::get_mut(&mut Arc::get_mut(shard).unwrap().metadata)
            .unwrap()
            .row_store = Some(identity);
    }
    let decoded = Arc::new(decoded);
    let rows = metadata_only_active(&decoded, &reader);
    let directory = TempDir::new().unwrap();
    let analyzer = EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Rust)));
    let before = SemanticModelOverlay::build(
        &analyzer,
        &decoded,
        &CancellationToken::new(),
        u64::MAX,
        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
    )
    .unwrap();
    let after = SemanticModelOverlay::build(
        &analyzer,
        &rows,
        &CancellationToken::new(),
        u64::MAX,
        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
    )
    .unwrap();
    assert!(
        before.symbols().is_empty(),
        "guards actually removed every symbol"
    );
    let patterns =
        crate::analyzer::SearchSymbolPatternBatch::compile(vec![".*".into()], false, None);
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    assert_eq!(
        before.search_with_limit(&patterns, 3, Some(&cancellation)),
        (Vec::new(), 0, true)
    );
    assert_eq!(
        after.search_with_limit(&patterns, 3, Some(&cancellation)),
        (Vec::new(), 0, false)
    );
    assert_overlay_entry_parity(
        &decoded,
        &rows,
        &before,
        &after,
        "guard-empty-cancelled-search",
    );
}

#[cfg(test)]
#[test]
fn catalog_row_entries_preserve_positive_companion_records() {
    use crate::analyzer::semantic_model::{CompilerOptions, SourceFormat, compile_source};
    let mut source: Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/semantic-model-packs/declarations-v1.json"
    )))
    .unwrap();
    source["schema_version"] = json!(4);
    source["language"] = json!("rust");
    source["ecosystem"] = json!("cargo");
    source["compatibility"]["toolchains"] = json!([]);
    let types = ["map", "iter-handle", "key", "value"]
        .into_iter()
        .map(|id| {
            json!({
                "id":id,"name":format!("fixture.{id}"),"type_kind":"struct","visibility":"public",
                "locator":{"kind":"artifact","path":"fixture","symbol":id}
            })
        })
        .collect::<Vec<_>>();
    source["shards"][0]["payload"] = json!({"kind":"declaration_facts","types":types,"members":[
        {"id":"iter","owner":"map","name":"iter","member_kind":"method","visibility":"public","callable_family_complete":true,
         "signature":{"parameters":[],"returns":{"kind":"declared","id":"iter-handle"}},"receiver":{"pointer":false},
         "locator":{"kind":"artifact","path":"fixture","symbol":"iter"}},
        {"id":"next","owner":"iter-handle","name":"next","member_kind":"method","visibility":"public","callable_family_complete":true,
         "signature":{"parameters":[],"returns":{"kind":"tuple","elements":[
             {"kind":"by_ref","element":{"kind":"declared","id":"key"}},
             {"kind":"by_ref","element":{"kind":"declared","id":"value"}}
         ]}},"receiver":{"pointer":false},"locator":{"kind":"artifact","path":"fixture","symbol":"next"}},
        {"id":"is_key","owner":"map","name":"is_key","member_kind":"method","visibility":"public","callable_family_complete":true,
         "signature":{"parameters":[{"name":"input","type":{"kind":"declared","id":"key"}}],"returns":{"kind":"named","name":"bool"}},
         "receiver":{"pointer":false},"locator":{"kind":"artifact","path":"fixture","symbol":"is_key"}}
    ],"relations":[]});
    let mut deferred:Value = serde_json::from_slice(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/../bifrost-semantic/src/analyzer/semantic_model/csmi/profiles/deferred-yield-shared-entry.json"))).unwrap();
    let mut pending = vec![&mut deferred];
    while let Some(value) = pending.pop() {
        match value {
            Value::String(text) => {
                if let Some((_, replacement)) = [
                    ("Map", "map"),
                    ("Iter", "iter-handle"),
                    ("Key", "key"),
                    ("Value", "value"),
                ]
                .iter()
                .find(|(old, _)| old == text)
                {
                    *text = (*replacement).to_owned();
                }
            }
            Value::Array(values) => pending.extend(values.iter_mut()),
            Value::Object(values) => pending.extend(values.values_mut()),
            _ => {}
        }
    }
    source["shards"][0]["deferred_yields"] = json!({"yields":[{
        "factory":"iter","resume":"next","handleType":"iter-handle","payload":deferred,"coverage":"complete"
    }]});
    source["shards"][0]["collection_flows"] = json!({"flows":[{
        "callable":"iter","payload":{"kind":"collection-flow","callable":"iter","roots":[],"transfers":[],"invocations":[]},"coverage":"complete"
    }]});
    source["shards"][0]["conditional_type_refinements"] = json!({"refinements":[{
        "payload":{"kind":"conditional-type-refinement","callable":"is_key","subject":{"kind":"parameter","position":0},
            "outcome":{"kind":"supported","semantics":"biconditional","target":{"kind":"reference","symbol":"key"}}},"coverage":"complete"
    }]});
    let pack = compile_source(
        SourceFormat::Json,
        &serde_json::to_vec(&source).unwrap(),
        &CompilerOptions::default(),
    )
    .unwrap();
    let validated = validate_pack(&pack, &DecodeLimits::default()).unwrap();
    assert_eq!(
        validated.shards[0]
            .decoded
            .collection_flows()
            .unwrap()
            .flows
            .len(),
        1,
        "positive flow route ran"
    );
    assert_eq!(
        validated.shards[0]
            .decoded
            .conditional_type_refinements()
            .unwrap()
            .refinements
            .len(),
        1,
        "positive refinement route ran"
    );
    assert_eq!(
        validated.shards[0]
            .decoded
            .deferred_yields()
            .unwrap()
            .yields
            .len(),
        1,
        "positive deferred route ran"
    );
    assert_pack_parity(&pack, "positive-rust-companions");

    // Reuse the independent public CSMI runtime fixture on its own eligible
    // JavaScript publication. Its activation/profile binding remains exact.
    let document: Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../bifrost-semantic/src/analyzer/semantic_model/csmi/profiles/runtime-values.fixture.json"
    )))
    .unwrap();
    let mut exposure = document["semanticModels"][0]["extensionFacts"][0]["payload"].clone();
    exposure.as_object_mut().unwrap().remove("kind");
    let mut behavior = document["semanticModels"][0]["extensionFacts"][1]["payload"].clone();
    behavior.as_object_mut().unwrap().remove("kind");
    source["language"] = json!("javascript");
    source["ecosystem"] = json!("npm");
    source["pack_id"] = json!("fixture.runtime-row-parity");
    for family in [
        "deferred_yields",
        "collection_flows",
        "conditional_type_refinements",
    ] {
        source["shards"][0].as_object_mut().unwrap().remove(family);
    }
    source["shards"][0]["activation"] = json!([{
        "package":{"name":exposure["runtime"]["runtimeArtifact"]},
        "artifact_sha256":exposure["runtime"]["runtimeArtifactDigest"],"configurations":[exposure["runtimeProfileDigest"]]
    }]);
    source["shards"][0]["runtime_values"] = json!({"exposures":[exposure],"behaviors":[behavior]});
    let pack = compile_source(
        SourceFormat::Json,
        &serde_json::to_vec(&source).unwrap(),
        &CompilerOptions::default(),
    )
    .unwrap();
    let validated = validate_pack(&pack, &DecodeLimits::default()).unwrap();
    assert_eq!(
        validated.shards[0]
            .decoded
            .runtime_values()
            .unwrap()
            .exposures
            .len(),
        1,
        "positive exposure route ran"
    );
    assert_pack_parity(&pack, "positive-javascript-runtime-values");
}

#[test]
#[ignore = "operator supplies BIFROST_PARITY_BUNDLE pointing at a copied release bundle"]
fn catalog_row_search_parity_for_real_bundle() {
    let packs = real_bundle_packs();
    let (active, reader) = catalog_fixture_active(&packs, "real-std-and-curated-search");
    let rows = metadata_only_active(&active, &reader);
    let owner_ids = active
        .shards
        .iter()
        .filter_map(|s| s.decoded().payload().declaration_facts())
        .flat_map(|(types, _, _)| types.iter().map(|t| t.id.clone()))
        .collect::<BTreeSet<_>>();
    let mut qualifications = HashMap::default();
    (&reader as &dyn crate::analyzer::store::model_catalog::CatalogRowReader)
        .visit_owned_rows(
            questions::SEARCH_OWNER_QUALIFICATIONS,
            rusqlite::named_params! { ":ids":serde_json::to_string(&owner_ids).unwrap() },
            None,
            |row| {
                super::row_entry_points::reduce_owner_qualification_row(&mut qualifications, row)?;
                Ok(true)
            },
        )
        .unwrap();
    let owner_records = qualifications
        .values()
        .map(|q| q.addresses.len())
        .sum::<usize>();
    let exceptional_records = qualifications
        .values()
        .filter(|q| q.addresses.len() != 1 || q.guarded)
        .map(|q| q.addresses.len())
        .sum::<usize>();
    let exceptional_ids = qualifications
        .iter()
        .filter(|(_, q)| q.addresses.len() != 1 || q.guarded)
        .map(|(id, _)| id)
        .collect::<Vec<_>>();
    eprintln!(
        "real corpus qualification: owner_records={owner_records}, exceptional_records={exceptional_records}, exceptional_ids={exceptional_ids:?}"
    );
    let directory = TempDir::new().unwrap();
    let analyzer = EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Rust)));
    let started_cpu = process_cpu_seconds();
    let before = SemanticModelOverlay::build(
        &analyzer,
        &active,
        &CancellationToken::new(),
        u64::MAX,
        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
    )
    .unwrap();
    if let (Some(start), Some(end)) = (started_cpu, process_cpu_seconds()) {
        eprintln!(
            "release corpus decoded eager build CPU_ms={:.3}",
            (end - start) * 1000.0
        );
    }
    let mut after = SemanticModelOverlay::build(
        &analyzer,
        &rows,
        &CancellationToken::new(),
        u64::MAX,
        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
    )
    .unwrap();
    let cache = crate::analyzer::store::cache_budget::StoreCacheBudget::new(
        &crate::retention_budget::RetentionBudget::for_tests(),
    );
    Arc::make_mut(after.row_source.as_mut().unwrap()).cache = Some(cache.clone());
    assert!(before.symbols().len() > 10_000, "real std corpus route ran");
    for (pattern, limit) in [
        (".*", 17),
        ("File|Command|spawn", 3),
        ("^std::", 0),
        ("File|Command|spawn", 3),
    ] {
        let patterns = crate::analyzer::SearchSymbolPatternBatch::compile(
            vec![pattern.to_owned()],
            false,
            None,
        );
        let expected = before.search_with_limit(&patterns, limit, None);
        let _request = crate::cache_db::sql_profile::request_scope("real-std-row-search-parity");
        let started_cpu = process_cpu_seconds();
        let actual = after.search_with_limit(&patterns, limit, None);
        if let (Some(start), Some(end)) = (started_cpu, process_cpu_seconds()) {
            eprintln!(
                "release corpus row search {pattern} CPU_ms={:.3}",
                (end - start) * 1000.0
            );
        }
        eprintln!(
            "release corpus cache {pattern}: {:?}",
            cache.composition_cache_stats()
        );
        assert_eq!(expected.1, actual.1, "{pattern}: exact total");
        assert_eq!(expected.2, actual.2, "{pattern}: completeness");
        assert_eq!(expected.0.len(), actual.0.len(), "{pattern}: first-N count");
        for (index, (expected, actual)) in expected.0.iter().zip(&actual.0).enumerate() {
            assert_eq!(expected, actual, "{pattern}: first-N order at {index}");
        }
        eprintln!(
            "real std + curated: {pattern}, first-N={}, exact_total={}",
            actual.0.len(),
            actual.1
        );
    }
}

#[cfg(all(test, unix))]
fn process_cpu_seconds() -> Option<f64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: getrusage initializes this correctly sized output on success.
    let status = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    assert_eq!(
        status,
        0,
        "getrusage: {:?}",
        std::io::Error::last_os_error()
    );
    // SAFETY: the successful call above initialized every field.
    let usage = unsafe { usage.assume_init() };
    Some(
        usage.ru_utime.tv_sec as f64
            + usage.ru_utime.tv_usec as f64 / 1_000_000.0
            + usage.ru_stime.tv_sec as f64
            + usage.ru_stime.tv_usec as f64 / 1_000_000.0,
    )
}

#[cfg(all(test, not(unix)))]
fn process_cpu_seconds() -> Option<f64> {
    None
}

#[cfg(test)]
#[test]
fn catalog_row_composition_cache_eviction_preserves_answers() {
    use crate::analyzer::store::cache_budget::StoreCacheBudget;
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let packs = GOLDEN_PACKS
        .iter()
        .filter(|path| path.starts_with("semantic-packs/rust-codeql-parity/"))
        .map(|path| {
            crate::analyzer::semantic_model::compile_source(
                crate::analyzer::semantic_model::SourceFormat::Json,
                &std::fs::read(root.join(path)).unwrap(),
                &crate::analyzer::semantic_model::CompilerOptions::default(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    assert!(!packs.is_empty(), "public Rust packs exercised");
    let (active, reader) = catalog_fixture_active(&packs, "composition-cache-eviction");
    let rows = metadata_only_active(&active, &reader);
    let directory = TempDir::new().unwrap();
    let analyzer = EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Rust)));
    let before = SemanticModelOverlay::build(
        &analyzer,
        &active,
        &CancellationToken::new(),
        u64::MAX,
        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
    )
    .unwrap();
    let mut after = SemanticModelOverlay::build(
        &analyzer,
        &rows,
        &CancellationToken::new(),
        u64::MAX,
        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
    )
    .unwrap();
    let cache = StoreCacheBudget::new(&crate::retention_budget::RetentionBudget::new(1));
    Arc::make_mut(after.row_source.as_mut().unwrap()).cache = Some(cache.clone());
    assert_overlay_entry_parity(
        &active,
        &rows,
        &before,
        &after,
        "every cache entry oversized",
    );
    let first = cache.composition_cache_stats();
    assert!(first.group_misses > 0, "composition actually ran");
    assert_overlay_entry_parity(&active, &rows, &before, &after, "all groups must be reread");
    let second = cache.composition_cache_stats();
    assert!(second.group_misses > first.group_misses);
    assert_eq!(second.group_hits, 0);
    assert_eq!(second.discovery_hits, 0);
    assert_eq!(second.search_hits, 0);
    assert!(second.search_misses > first.search_misses);
    assert_eq!(second.retained_bytes, 0);

    let shared = StoreCacheBudget::new(&crate::retention_budget::RetentionBudget::for_tests());
    Arc::make_mut(after.row_source.as_mut().unwrap()).cache = Some(shared.clone());
    assert_overlay_entry_parity(&active, &rows, &before, &after, "retained groups");
    assert_overlay_entry_parity(&active, &rows, &before, &after, "retained search stream");
    let retained = shared.composition_cache_stats();
    assert!(retained.search_hits > 0, "immutable stream reused");
    assert!(
        retained.search_retained_bytes > 0,
        "stream charged to shared budget"
    );
    let mut changed = self::active(
        active
            .shards
            .iter()
            .map(|shard| {
                let mut metadata = (*shard.metadata).clone();
                metadata.source_id.push_str("-republished");
                ActiveSemanticModelShard {
                    metadata: Arc::new(metadata),
                    decoded: shard.decoded.clone(),
                }
            })
            .collect(),
    );
    changed.active_model_set_hash = active.active_model_set_hash.clone();
    let changed = Arc::new(changed);
    let changed_rows = metadata_only_active(&changed, &reader);
    let expected = SemanticModelOverlay::build(
        &analyzer,
        &changed,
        &CancellationToken::new(),
        u64::MAX,
        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
    )
    .unwrap();
    let mut actual = SemanticModelOverlay::build(
        &analyzer,
        &changed_rows,
        &CancellationToken::new(),
        u64::MAX,
        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
    )
    .unwrap();
    Arc::make_mut(actual.row_source.as_mut().unwrap()).cache = Some(shared.clone());
    assert_ne!(
        before.symbols(),
        expected.symbols(),
        "provenance-only publication change ran"
    );
    assert_eq!(
        active.active_model_set_hash(),
        changed.active_model_set_hash()
    );
    assert_overlay_entry_parity(
        &changed,
        &changed_rows,
        &expected,
        &actual,
        "same semantic hash, different publication",
    );
    assert!(
        shared.composition_cache_stats().group_hits > 0,
        "cross-question reuse ran"
    );
}

#[cfg(test)]
#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#7560: G1 selected composition folded owners across providers"
)]
fn model_declarations_preserve_folded_provider_owner() {
    use crate::analyzer::semantic_model::{
        ArtifactExtraction, ArtifactExtractionKind, AuthoredSemanticModelPack, CompilerOptions,
        compile_pack,
    };
    // Test-only extracted releases with identical owner structure. Activation
    // deliberately has no exact artifact evidence to distinguish the releases.
    let mut source: Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/semantic-model-packs/declarations-v1.json"
    )))
    .unwrap();
    source["schema_version"] =
        json!(crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION);
    source["pack_id"] = json!("fixture.provider-folding");
    source["language"] = json!("rust");
    source["ecosystem"] = json!("cargo");
    source["compatibility"]["toolchains"] = json!([]);
    source["compatibility"]
        .as_object_mut()
        .unwrap()
        .remove("bifrost");
    let mut owner = source["shards"][0]["payload"]["types"][0].clone();
    owner["hierarchy"] = json!([]);
    owner["aliases"] = json!([]);
    source["shards"][0]["payload"] = json!({
        "kind": "declaration_facts", "types": [owner], "members": [], "relations": []
    });
    let mut authored: AuthoredSemanticModelPack = serde_json::from_value(source).unwrap();
    authored.extraction = Some(ArtifactExtraction::single(
        ArtifactExtractionKind::RustdocJson,
        &"a".repeat(64),
    ));
    let mut packs = Vec::new();
    for version in ["1.0.0", "2.0.0"] {
        authored.version = version.into();
        let pack = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        packs.push(pack);
    }
    let (mut active, reader) = catalog_fixture_active(&packs, "provider-folding");
    let selected = Arc::get_mut(&mut active).unwrap();
    let reader = Arc::new(reader);
    {
        let installed_source: Option<
            Arc<dyn crate::analyzer::store::model_catalog::RequestRowReaderSource>,
        > = Some(Arc::new(
            crate::analyzer::store::model_catalog::ActivationRowReaderSource::new(
                Arc::clone(&reader),
                &selected.active_model_set_hash,
            ),
        ));
        selected.install_request_source(installed_source).unwrap();
    };
    selected.source_reader = Some(reader);
    for shard in &mut selected.shards {
        Arc::get_mut(shard).unwrap().decoded = None;
    }
    assert_eq!(active.shards.len(), 2, "both extracted releases are active");
    assert!(active.shards.iter().all(|shard| {
        shard.manifest.extraction.is_some() && shard.matched_evidence.artifact_sha256.is_none()
    }));
    let providers = active
        .shards
        .iter()
        .map(|shard| ModelProvider {
            pack_id: shard.manifest.pack_id.clone(),
            pack_version: shard.manifest.version.clone(),
            pack_digest: shard.manifest.semantic_sha256.clone(),
        })
        .collect::<Vec<_>>();
    assert_ne!(providers[0], providers[1]);
    let directory = TempDir::new().unwrap();
    let analyzer = EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Rust)));
    let overlay = SemanticModelOverlay::build(
        &analyzer,
        &active,
        &CancellationToken::new(),
        u64::MAX,
        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
    )
    .unwrap();
    let composed = overlay.symbols_with_id("type.widget").records;
    assert!(!composed.is_empty(), "fixture must publish the owner");
    let representative = ModelProvider::from(&composed[0].provenance);
    let provider = providers
        .into_iter()
        .find(|provider| provider != &representative)
        .unwrap();
    let selection = ModelProviderSelection::new([provider.clone()]);
    let owner = ModelSymbolRef {
        symbol_id: "type.widget".into(),
        provider,
    };
    assert!(
        matches!(overlay.model_member_declarations(&owner, &selection, &crate::CancellationToken::new()).unwrap(), Some(ModelOwnerAnswer::Declared(answer)) if answer.owner == owner),
        "non-representative provider must retain its own owner: {owner}"
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#7560: G1 selected composition folded owners across providers"
)]
fn model_selected_composition_keeps_member_surfaces_per_provider() {
    use crate::analyzer::semantic_model::{
        ArtifactExtraction, ArtifactExtractionKind, AuthoredSemanticModelPack, CompilerOptions,
        compile_pack,
    };
    for (language, extracted) in [("rust", false), ("rust", true), ("go", false), ("go", true)] {
        let mut source: Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/semantic-model-packs/declarations-v1.json"
        )))
        .unwrap();
        source["schema_version"] =
            json!(crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION);
        source["pack_id"] = json!("fixture.selected-providers");
        source["language"] = json!(language);
        source["ecosystem"] = json!(if language == "rust" {
            "cargo"
        } else {
            "go-module"
        });
        source["compatibility"] = json!({});
        let mut owner = source["shards"][0]["payload"]["types"][0].clone();
        owner["hierarchy"] = json!([]);
        owner["aliases"] = json!([]);
        let template = source["shards"][0]["payload"]["members"][0].clone();
        let mut packs = Vec::new();
        for (version, name, result) in [
            (
                "1.0.0",
                "First",
                json!({"kind": "tuple", "elements": [
                    {"kind": "unknown"}, {"kind": "named", "name": "example.Result"}
                ]}),
            ),
            ("2.0.0", "Second", Value::Null),
        ] {
            let mut member = template.clone();
            member["id"] = json!("member.shared");
            member["name"] = json!(name);
            member["signature"]["returns"] = result;
            source["version"] = json!(version);
            source["shards"][0]["payload"] = json!({
                "kind": "declaration_facts", "types": [owner.clone()],
                "members": [member], "relations": []
            });
            let mut authored: AuthoredSemanticModelPack =
                serde_json::from_value(source.clone()).unwrap();
            authored.extraction = extracted.then(|| {
                ArtifactExtraction::single(ArtifactExtractionKind::RustdocJson, &"a".repeat(64))
            });
            packs.push(compile_pack(&authored, &CompilerOptions::default()).unwrap());
        }
        let (mut active, reader) = catalog_fixture_active(&packs, "selected-providers");
        let providers = active.model_provider_selection();
        let scope = Arc::get_mut(&mut active).unwrap();
        let reader = Arc::new(reader);
        {
            let installed_source: Option<
                Arc<dyn crate::analyzer::store::model_catalog::RequestRowReaderSource>,
            > = Some(Arc::new(
                crate::analyzer::store::model_catalog::ActivationRowReaderSource::new(
                    Arc::clone(&reader),
                    &scope.active_model_set_hash,
                ),
            ));
            scope.install_request_source(installed_source).unwrap();
        };
        scope.source_reader = Some(reader);
        if language == "rust" {
            for shard in &mut scope.shards {
                Arc::get_mut(shard).unwrap().decoded = None;
            }
        }
        let directory = TempDir::new().unwrap();
        let analyzer = EmptyAnalyzer::new(Arc::new(TestProject::new(
            directory.path(),
            if language == "rust" {
                Language::Rust
            } else {
                Language::Go
            },
        )));
        let mut overlay = SemanticModelOverlay::build(
            &analyzer,
            &active,
            &CancellationToken::new(),
            u64::MAX,
            &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
        )
        .unwrap();
        // Exercise hits and distinct selection contexts through the shared byte cap.
        // Row and selected views share the source; mutate before installing either view.
        let mut source = row_entry_points::RowOverlay::new(
            &analyzer,
            &active,
            Vec::new(),
            Vec::new(),
            None,
            &[],
        );
        source.cache = Some(crate::analyzer::store::cache_budget::StoreCacheBudget::new(
            &crate::retention_budget::RetentionBudget::new(1024 * 1024),
        ));
        overlay.selected_source = Some(Arc::new(source));
        let mut selected_owners = Vec::new();
        for (index, expected) in ["First", "Second"].into_iter().enumerate() {
            let shard = &active.shards[index];
            let provider = ModelProvider {
                pack_id: shard.manifest.pack_id.clone(),
                pack_version: shard.manifest.version.clone(),
                pack_digest: shard.manifest.semantic_sha256.clone(),
            };
            let owner = ModelSymbolRef {
                symbol_id: "type.widget".into(),
                provider: provider.clone(),
            };
            let selection = ModelProviderSelection::new([provider.clone()]);
            for selected in [&selection, &providers, &selection] {
                let Some(ModelOwnerAnswer::Declared(answer)) = overlay
                    .model_member_declarations(&owner, selected, &crate::CancellationToken::new())
                    .unwrap()
                else {
                    panic!("{language}: selected owner {owner}");
                };
                assert_eq!(answer.owner, owner);
                assert_eq!(
                    answer
                        .members
                        .iter()
                        .map(|m| m.declaration.name.as_str())
                        .collect::<Vec<_>>(),
                    vec![expected],
                    "{language}: provider must keep its own surface"
                );
                assert_eq!(answer.members[0].member.provider, provider);
                let callable = ModelSymbolRef {
                    symbol_id: "member.shared".into(),
                    provider: provider.clone(),
                };
                let results = overlay
                    .model_callable_results(&callable, selected, &crate::CancellationToken::new())
                    .unwrap()
                    .unwrap();
                if index == 0 {
                    assert_eq!(results.len(), 2);
                    assert_eq!(results[0], None);
                    assert!(
                        matches!(&results[1], Some(TypeRef::Named { name, .. }) if name == "example.Result")
                    );
                } else {
                    assert!(results.is_empty());
                }
            }
            assert!(
                overlay
                    .model_member_declarations(
                        &owner,
                        &ModelProviderSelection::new([]),
                        &crate::CancellationToken::new()
                    )
                    .unwrap()
                    .is_none()
            );
            selected_owners.push(owner);
        }
        assert_ne!(selected_owners[0], selected_owners[1]);
        let reference = TypeRef::Named {
            name: "com.acme.Widget".into(),
            arguments: Vec::new(),
            nullable: false,
        };
        let groups = overlay
            .model_selected_groups(
                language,
                &reference,
                &providers,
                &crate::CancellationToken::new(),
            )
            .unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].iter().filter(|s| s.owner_id.is_none()).count(), 2);
        let authority: &dyn crate::analyzer::store::resolution_operation::SelectedModelAuthority =
            &overlay;
        assert_eq!(
            authority
                .model_selected_groups(
                    language,
                    &reference,
                    &providers,
                    &crate::CancellationToken::new()
                )
                .unwrap()
                .len(),
            1
        );

        let cache = overlay
            .selected_source
            .as_ref()
            .unwrap()
            .cache
            .as_ref()
            .unwrap();
        assert!(
            cache.composition_cache_stats().group_hits > 0,
            "selected group cache was exercised"
        );
        // D3: the ordinary view retains its original fold and member union.
        let ordinary = overlay.symbols_with_id("type.widget").records;
        assert_eq!(
            ordinary.len(),
            1,
            "{language}: unselected owner still folds"
        );
        let members = overlay.members_of("type.widget").records;
        assert!(members.iter().any(|m| m.name == "First"));
        assert!(members.iter().any(|m| m.name == "Second"));
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#7560: selected Go groups inherited whole-set promotion marks"
)]
fn model_selected_go_group_recomputes_promotion_state() {
    use crate::analyzer::semantic_model::{
        AuthoredSemanticModelPack, CompilerOptions, compile_pack,
    };
    let mut source: Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/semantic-model-packs/declarations-v1.json"
    )))
    .unwrap();
    source["schema_version"] =
        json!(crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION);
    source["language"] = json!("go");
    source["ecosystem"] = json!("go-module");
    source["compatibility"] = json!({});
    let mut owner = source["shards"][0]["payload"]["types"][0].clone();
    owner["type_kind"] = json!("struct");
    owner["hierarchy"] = json!([]);
    owner["type_parameters"] = json!([]);
    owner["aliases"] = json!([]);
    owner["extension_surfaces"] = json!([]);
    let mut member = source["shards"][0]["payload"]["members"][0].clone();
    member["name"] = json!("Ping");
    member["receiver"] = json!({"pointer": false});
    member["signature"] = json!({"parameters": [], "returns": null});
    // Identical Artifact declaring coordinates identify the producer's copy.
    member["locator"] =
        json!({"kind": "artifact", "path": "base.go", "symbol": "example.Base.Ping"});
    let mut packs = Vec::new();
    for (pack_id, id, name) in [
        ("fixture.go.outer", "type.outer", "example.Outer"),
        ("fixture.go.base", "type.base", "example.Base"),
    ] {
        source["pack_id"] = json!(pack_id);
        owner["id"] = json!(id);
        owner["name"] = json!(name);
        owner["embedded_types"] = if id == "type.outer" {
            json!([{"target": {"kind": "named", "name": "example.Base"}, "pointer": false}])
        } else {
            json!([])
        };
        member["id"] = json!(format!("{id}.ping"));
        member["owner"] = json!(id);
        source["shards"][0]["payload"] = json!({
            "kind": "declaration_facts", "types": [owner.clone()],
            "members": [member.clone()], "relations": []
        });
        let authored: AuthoredSemanticModelPack = serde_json::from_value(source.clone()).unwrap();
        packs.push(compile_pack(&authored, &CompilerOptions::default()).unwrap());
    }
    let (active, _reader) = catalog_fixture_active(&packs, "go-selected-promotion");
    assert!(active.shards.iter().all(|s| s.decoded.is_some()));
    let directory = TempDir::new().unwrap();
    let analyzer = EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Go)));
    let overlay = SemanticModelOverlay::build(
        &analyzer,
        &active,
        &CancellationToken::new(),
        u64::MAX,
        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
    )
    .unwrap();
    let owner = overlay.symbols_with_id("type.outer").records[0].clone();
    let provider = ModelProvider::from(&owner.provenance);
    assert_eq!(
        owner.members_state,
        ModelMembersState::Exact,
        "whole-set Go surface is exact"
    );
    let owner = ModelSymbolRef {
        symbol_id: owner.id.clone(),
        provider: provider.clone(),
    };
    let all = active.model_provider_selection();
    let narrow = ModelProviderSelection::new([provider]);
    let Some(ModelOwnerAnswer::Declared(broad)) = overlay
        .model_member_declarations(&owner, &all, &crate::CancellationToken::new())
        .unwrap()
    else {
        panic!("broad owner exists");
    };
    let Some(ModelOwnerAnswer::Declared(narrow)) = overlay
        .model_member_declarations(&owner, &narrow, &crate::CancellationToken::new())
        .unwrap()
    else {
        panic!("narrow owner exists");
    };
    // Cross-provider declaring sites cannot prove this authored member is a
    // copy: both selections retain it, but only the full selection closes Base.
    assert_eq!(broad.members_state, ModelMembersState::Exact);
    assert_eq!(
        narrow.members_state,
        ModelMembersState::MayIncludePromotionCopies
    );
    assert_eq!(broad.members.len(), 1);
    assert_eq!(narrow.members.len(), 1);
    assert!(broad.members[0].declaration.promoted_from.is_none());
}

#[test]
fn selected_go_embedding_bound_returns_an_error_and_preserves_cancellation() {
    use crate::analyzer::semantic_model::{
        AuthoredSemanticModelPack, CompilerOptions, compile_pack,
    };
    let mut source: Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/semantic-model-packs/declarations-v1.json"
    )))
    .unwrap();
    source["schema_version"] =
        json!(crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION);
    source["pack_id"] = json!("fixture.go.embedding-bound");
    source["language"] = json!("go");
    source["ecosystem"] = json!("go-module");
    source["compatibility"] = json!({});
    source["shards"][0]["activation"] = json!([{}]);
    // Walking the reachable embeddings for all 2002 owners exceeds the
    // shared hook's two-million-step bound without a large pack payload.
    let types = (0..2002)
        .map(|index| {
            json!({
                "id": format!("type.node.{index}"),
                "name": format!("fixture.Node{index}"),
                "type_kind": "struct", "visibility": "public",
                "embedded_types": if index < 2001 {
                    json!([{"target": {"kind": "declared",
                        "id": format!("type.node.{}", index + 1), "arguments": [],
                        "nullable": false}, "pointer": false}])
                } else { json!([]) },
                "locator": {"kind": "artifact", "path": "embedding.go",
                    "symbol": format!("fixture.Node{index}")}
            })
        })
        .collect::<Vec<_>>();
    source["shards"][0]["payload"] = json!({
        "kind": "declaration_facts", "types": types, "members": [], "relations": []
    });
    let authored: AuthoredSemanticModelPack = serde_json::from_value(source).unwrap();
    let pack = compile_pack(&authored, &CompilerOptions::default()).unwrap();
    let (active, _reader) = catalog_fixture_active(&[pack], "go-selected-embedding-bound");
    let directory = TempDir::new().unwrap();
    let analyzer = EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Go)));
    // Install the selected source directly: ordinary eager construction would
    // reject this pack at its own traversal gate before a selected request.
    let mut overlay = test_support::overlay(Vec::new(), Vec::new());
    overlay.active_model_set_hash = active.active_model_set_hash().to_owned();
    overlay.selected_source = Some(Arc::new(row_entry_points::RowOverlay::new(
        &analyzer,
        &active,
        Vec::new(),
        Vec::new(),
        None,
        &[],
    )));
    let selection = active.model_provider_selection();
    let owner = ModelSymbolRef {
        symbol_id: "type.node.0".into(),
        provider: ModelProvider {
            pack_id: active.shards[0].manifest.pack_id.clone(),
            pack_version: active.shards[0].manifest.version.clone(),
            pack_digest: active.shards[0].manifest.semantic_sha256.clone(),
        },
    };
    assert!(matches!(
        overlay.model_member_declarations(&owner, &selection, &CancellationToken::new()),
        Err(SemanticModelOverlayBuildError::GoSurfaceTraversalExceeded)
    ));
    assert!(
        overlay
            .model_member_cache
            .get_ready(
                &overlay
                    .model_declaration_request(&owner, &selection)
                    .unwrap(),
                &CancellationToken::new()
            )
            .is_none()
    );
    // Closure materialization polls fewer than 5000 times. This token reaches
    // the shared Go walk before it cancels, so a fresh hook token would fail.
    let cancellation = CancellationToken::cancel_after_checks_for_test(10_000);
    let authority: &dyn crate::analyzer::store::resolution_operation::SelectedModelAuthority =
        &overlay;
    assert!(matches!(
        authority.model_member_declarations(&owner, &selection, &cancellation),
        Err(SemanticModelOverlayBuildError::Cancelled)
    ));
    assert!(cancellation.is_cancelled());
    assert!(matches!(
        overlay.model_selected_groups(
            "go",
            &TypeRef::Declared {
                id: owner.symbol_id.clone(),
                arguments: Vec::new(),
                nullable: false,
            },
            &selection,
            &cancellation
        ),
        Err(SemanticModelOverlayBuildError::Cancelled)
    ));
    assert!(matches!(
        authority.model_callable_results(&owner, &selection, &cancellation),
        Err(SemanticModelOverlayBuildError::Cancelled)
    ));
}

/// Two versions of one pack declare the same Java class, and both are selected.
/// The JVM's unselected lookup folds them into one owner on purpose until #7605
/// moves the JVM onto a selection; the selected view keeps each defining
/// provider, so the same reference is Ambiguous there. Both answers come from
/// the shared classify_model_type_owner core, fed different candidates.
#[test]
fn jvm_folded_owner_and_selected_type_owner_keep_their_contracts() {
    use crate::analyzer::semantic_model::{
        AuthoredSemanticModelPack, CompilerOptions, compile_pack,
    };
    let mut source: Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/semantic-model-packs/declarations-v1.json"
    )))
    .unwrap();
    source["schema_version"] =
        json!(crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION);
    source["pack_id"] = json!("fixture.jvm-owner-contracts");
    source["compatibility"] = json!({});
    source["shards"][0]["activation"] = json!([{}]);
    let mut owner = source["shards"][0]["payload"]["types"][0].clone();
    owner["hierarchy"] = json!([]);
    owner["aliases"] = json!([]);
    source["shards"][0]["payload"] = json!({
        "kind": "declaration_facts", "types": [owner], "members": [], "relations": []
    });
    let mut packs = Vec::new();
    for version in ["1.0.0", "2.0.0"] {
        source["version"] = json!(version);
        let authored: AuthoredSemanticModelPack = serde_json::from_value(source.clone()).unwrap();
        packs.push(compile_pack(&authored, &CompilerOptions::default()).unwrap());
    }
    let (mut active, reader) = catalog_fixture_active(&packs, "jvm-owner-contracts");
    let reader = Arc::new(reader);
    {
        let installed_source: Option<
            Arc<dyn crate::analyzer::store::model_catalog::RequestRowReaderSource>,
        > = Some(Arc::new(
            crate::analyzer::store::model_catalog::ActivationRowReaderSource::new(
                Arc::clone(&reader),
                &active.active_model_set_hash,
            ),
        ));
        Arc::get_mut(&mut active)
            .unwrap()
            .install_request_source(installed_source)
            .unwrap();
    };
    Arc::get_mut(&mut active).unwrap().source_reader = Some(reader);
    let directory = TempDir::new().unwrap();
    let analyzer = EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Java)));
    let cancellation = CancellationToken::new();
    let overlay = SemanticModelOverlay::build(
        &analyzer,
        &active,
        &cancellation,
        u64::MAX,
        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
    )
    .unwrap();
    let fqn = "com.acme.Widget";

    let selected = overlay
        .model_type_owner(
            "java",
            &TypeRef::Named {
                name: fqn.into(),
                arguments: Vec::new(),
                nullable: false,
            },
            &active.model_provider_selection(),
            &cancellation,
        )
        .unwrap();
    let ModelTypeOwnerAnswer::Ambiguous(owners) = selected else {
        panic!("each selected provider stays a separate owner: {selected:?}");
    };
    let versions: BTreeSet<_> = owners
        .iter()
        .map(|owner| owner.provider.pack_version.as_str())
        .collect();
    assert_eq!(versions, BTreeSet::from(["1.0.0", "2.0.0"]));

    // The JVM's folded lookup, reached through the shared authority trait.
    let authority: &dyn crate::analyzer::store::resolution_operation::SelectedModelAuthority =
        &overlay;
    let folded = authority
        .declared_jvm_owner(fqn)
        .expect("the unselected view folds both versions into one owner (#7605)");
    let first = owners
        .iter()
        .find(|owner| owner.provider.pack_version == "1.0.0")
        .expect("version 1.0.0 is selected");
    assert_eq!(&*folded.provider_id, first.provider.pack_digest.as_str());
    assert_eq!(&*folded.owner_fqn, fqn);
}

#[test]
fn relation_ranking_includes_other_origins_before_filtering() {
    use crate::analyzer::semantic_model::{
        AuthoredSemanticModelPack, CompilerOptions, compile_pack,
    };
    let mut source: Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/semantic-model-packs/declarations-v1.json"
    )))
    .unwrap();
    source["schema_version"] =
        json!(crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION);
    source["language"] = json!("rust");
    source["ecosystem"] = json!("cargo");
    source["compatibility"] = json!({});
    let template = source["shards"][0]["payload"]["types"][0].clone();
    let mut packs = Vec::new();
    for name in ["first", "second"] {
        source["pack_id"] = json!(format!("fixture.relation-{name}"));
        let mut owner = template.clone();
        owner["id"] = json!(name);
        owner["name"] = json!(format!("example.{name}"));
        owner["hierarchy"] = json!([]);
        owner["aliases"] = json!([]);
        source["shards"][0]["payload"] = json!({
            "kind": "declaration_facts", "types": [owner], "members": [],
            "relations": [{"id": "shared", "relation_kind": "navigates_to", "from": name, "to": name}]
        });
        let authored: AuthoredSemanticModelPack = serde_json::from_value(source.clone()).unwrap();
        packs.push(compile_pack(&authored, &CompilerOptions::default()).unwrap());
    }
    let (active, reader) = catalog_fixture_active(&packs, "relation-origin-ranking");
    let active = metadata_only_active(&active, &reader);
    let directory = TempDir::new().unwrap();
    let analyzer = EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Rust)));
    let reads = composition::RowCompositionReads::new(&active, &[], &[]);
    let origins = HashSet::from_iter(["first".to_owned()]);
    let relations = reads.relations_for_origins(&analyzer, &origins).unwrap();
    assert_eq!(relations.len(), 1);
    assert_eq!(relations[0].from, "first");
    assert!(
        relations[0].provenance.ambiguous,
        "same-id records from both origins must participate in ranking: {relations:?}"
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#10045: authored family certification was lost when a partial generated std member survived composition"
)]
fn rust_authored_free_function_family_precedence_requires_exact_defining_member() {
    use crate::analyzer::semantic_model::{
        ArtifactExtraction, ArtifactExtractionKind, AuthoredSemanticModelPack, CompilerOptions,
        compile_pack,
    };
    for (case, certified, defining_path, extra_sibling, expected) in [
        ("matched", true, true, false, true),
        ("reexport", true, false, false, false),
        ("sibling", true, true, true, false),
        ("uncertified", false, true, false, false),
    ] {
        let mut source: Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/semantic-model-packs/declarations-v1.json"
        )))
        .unwrap();
        source["schema_version"] =
            json!(crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION);
        source["language"] = json!("rust");
        source["ecosystem"] = json!("cargo");
        source["compatibility"] = json!({});
        source["shards"][0]["activation"] = json!([{}]);
        source["shards"][0]["payload"]["types"] = json!([{
            "id": "owner.core.panicking", "name": "core.panicking",
            "type_kind": "module", "visibility": "public",
            "locator": {"kind": "artifact", "path": "library/core/src/panicking.rs", "symbol": "core.panicking"}
        }]);
        let member = json!({
            "id": "member.panic", "owner": "owner.core.panicking", "name": "panic_fmt",
            "member_kind": "function", "visibility": "public",
            "signature": {"parameters": [{"name":"fmt", "type":{"kind":"named", "name":"core.fmt.Arguments"}}]},
            "locator": {"kind":"artifact", "path":"library/core/src/panicking.rs", "symbol":"core.panicking.panic_fmt"}
        });
        source["shards"][0]["payload"]["members"] = json!([member.clone()]);
        source["shards"][0]["payload"]["relations"] = json!([]);
        let mut authored_source = source.clone();
        authored_source["pack_id"] = json!(format!("fixture.authored.{case}"));
        authored_source["completeness"] = json!("partial");
        authored_source["shards"][0]["payload"]["members"][0]["callable_family_complete"] =
            json!(certified);
        if !defining_path {
            authored_source["shards"][0]["payload"]["types"][0]["name"] = json!("std.panicking");
            authored_source["shards"][0]["payload"]["members"][0]["locator"]["symbol"] =
                json!("std.panicking.panic_fmt");
        }
        let authored: AuthoredSemanticModelPack = serde_json::from_value(authored_source).unwrap();
        let authored = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        source["pack_id"] = json!(format!("fixture.generated.{case}"));
        source["completeness"] = json!("partial");
        source["shards"][0]["payload"]["members"][0]["id"] = json!("member.generated.panic");
        if extra_sibling {
            let mut sibling = member;
            sibling["id"] = json!("member.generated.sibling");
            sibling["signature"]["parameters"][0]["type"]["name"] = json!("core.fmt.Other");
            source["shards"][0]["payload"]["members"]
                .as_array_mut()
                .unwrap()
                .push(sibling);
        }
        let mut generated: AuthoredSemanticModelPack = serde_json::from_value(source).unwrap();
        generated.extraction = Some(ArtifactExtraction::single(
            ArtifactExtractionKind::RustdocJson,
            &"a".repeat(64),
        ));
        let generated = compile_pack(&generated, &CompilerOptions::default()).unwrap();
        let (active, _reader) = catalog_fixture_active(&[authored, generated], case);
        let directory = TempDir::new().unwrap();
        let analyzer =
            EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Rust)));
        let overlay = SemanticModelOverlay::build(
            &analyzer,
            &active,
            &CancellationToken::new(),
            u64::MAX,
            &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
        )
        .unwrap();
        let family = if defining_path {
            overlay.symbols_named("core.panicking.panic_fmt")
        } else {
            overlay.symbols_with_id("member.generated.panic")
        };
        assert_eq!(
            family.records.len(),
            if extra_sibling { 2 } else { 1 },
            "{case}: {family:?}"
        );
        assert!(
            family
                .records
                .iter()
                .all(|record| record.callable_family_complete == expected),
            "{case}: {family:?}"
        );
    }
}

#[cfg(test)]
mod partition_tests {
    use super::*;
    use crate::analyzer::semantic_model::catalog::CatalogError;
    use crate::analyzer::semantic_model::runtime::FamilyOpen;
    use crate::analyzer::store::model_catalog::{
        CatalogRowReader, OwnedCatalogRows, ReaderBinding, RequestRowReader, RequestRowReaderSource,
    };

    fn request_reader(
        reader: &crate::analyzer::store::model_catalog::CatalogRuntimeSourceReader,
        activation: &ResolvedActiveSemanticModels,
    ) -> Arc<crate::analyzer::store::model_catalog::CatalogRuntimeSourceReader> {
        Arc::new(
            reader
                .reopen_with_shard_keys(
                    activation
                        .shards
                        .iter()
                        .filter(|shard| {
                            crate::analyzer::store::active_models::shard_owner_index(
                                shard,
                                Some(0),
                                Some(1),
                            ) == Some(1)
                        })
                        .filter_map(|shard| shard.row_store),
                )
                .unwrap(),
        )
    }

    #[derive(Debug)]
    struct DistinctSource {
        reader: Arc<crate::analyzer::store::model_catalog::CatalogRuntimeSourceReader>,
        empty: bool,
    }

    struct DistinctReader {
        reader: Arc<crate::analyzer::store::model_catalog::CatalogRuntimeSourceReader>,
        empty: bool,
    }

    impl CatalogRowReader for DistinctReader {
        fn owned_rows(
            &self,
            statement: &str,
            bindings: &[(&str, &dyn rusqlite::ToSql)],
            cancellation: &CancellationToken,
        ) -> Result<OwnedCatalogRows, CatalogError> {
            let mut rows = self.reader.owned_rows(statement, bindings, cancellation)?;
            if self.empty {
                rows.rows.clear();
            }
            Ok(rows)
        }
    }

    impl RequestRowReaderSource for DistinctSource {
        fn jvm_reader(
            &self,
            activation: &ResolvedActiveSemanticModels,
        ) -> Result<RequestRowReader, FamilyOpen> {
            Ok(RequestRowReader {
                reader: Arc::new(DistinctReader {
                    reader: request_reader(&self.reader, activation),
                    empty: self.empty,
                }),
                binding: ReaderBinding([1; 32]),
            })
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: every row owner re-read all active shards and discarded the rows it did not own"
    )]
    fn installing_distinct_owner_preserves_earlier_reader_view() {
        let mut active = mixed_active(false, false);
        let active = Arc::get_mut(&mut active).unwrap();
        let source = active.request_source().unwrap().clone();
        active.install_request_source(None).unwrap();
        let earlier = active.source_reader.as_ref().unwrap().clone();
        let membership =
            |reader: &crate::analyzer::store::model_catalog::CatalogRuntimeSourceReader| {
                reader
                    .owned_rows(
                        "SELECT source_db, shard_key FROM temp.active_shards",
                        &[],
                        &CancellationToken::new(),
                    )
                    .unwrap()
                    .rows
                    .len()
            };
        assert_eq!(membership(&earlier), 2);
        active.install_request_source(Some(source)).unwrap();
        assert_eq!(membership(active.source_reader.as_ref().unwrap()), 1);
        assert_eq!(membership(&earlier), 2);

        // Give every shard to the request owner, so activation must execute
        // no statements even while the JVM part is unavailable.
        active.install_request_source(None).unwrap();
        for shard in &mut active.shards {
            Arc::get_mut(&mut Arc::get_mut(shard).unwrap().metadata)
                .unwrap()
                .source_kind = CatalogPackSourceKind::Generated;
        }
        #[derive(Debug)]
        struct Source(Arc<crate::analyzer::store::model_catalog::CatalogRuntimeSourceReader>);
        impl RequestRowReaderSource for Source {
            fn jvm_reader(
                &self,
                _: &ResolvedActiveSemanticModels,
            ) -> Result<RequestRowReader, FamilyOpen> {
                Ok(RequestRowReader {
                    reader: self.0.clone(),
                    binding: ReaderBinding([7; 32]),
                })
            }
        }
        let request = request_reader(&earlier, active);
        let source = Arc::new(Source(request.clone()));
        active.install_request_source(Some(source)).unwrap();
        use brokk_bifrost_core::cache_db::sql_profile::{ListenerEvent, attach_listener};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let activation_calls = Arc::new(AtomicUsize::new(0));
        let request_calls = Arc::new(AtomicUsize::new(0));
        let count = |calls: Arc<AtomicUsize>| {
            Arc::new(move |event: ListenerEvent<'_>| {
                if matches!(event, ListenerEvent::Statement { .. }) {
                    calls.fetch_add(1, Ordering::Relaxed);
                }
            })
        };
        let _request_trace = attach_listener(
            &request.connection.lock().unwrap(),
            count(request_calls.clone()),
        );
        let activation_reader = active.source_reader.as_ref().unwrap().clone();
        let _activation_trace = attach_listener(
            &activation_reader.connection.lock().unwrap(),
            count(activation_calls.clone()),
        );
        {
            let rows = active.all_type_records_named("com.acme.Widget");
            assert_eq!(rows.rows.count(), 2);
        }
        assert!(request_calls.load(Ordering::Relaxed) > 0);
        assert_eq!(activation_calls.load(Ordering::Relaxed), 0);

        active
            .install_request_source(Some(Arc::new(OpenSource)))
            .unwrap();
        let open_reader = active.source_reader.as_ref().unwrap().clone();
        let _open_trace = attach_listener(
            &open_reader.connection.lock().unwrap(),
            count(activation_calls.clone()),
        );
        activation_calls.store(0, Ordering::Relaxed);
        request_calls.store(0, Ordering::Relaxed);
        let rows = active.all_type_records_named("com.acme.Widget");
        assert!(rows.jvm_open.is_some());
        assert_eq!(rows.rows.count(), 0);
        assert_eq!(activation_calls.load(Ordering::Relaxed), 0);
        assert_eq!(request_calls.load(Ordering::Relaxed), 0);
    }

    fn mixed_active(empty: bool, carried: bool) -> Arc<ResolvedActiveSemanticModels> {
        mixed_active_edited(empty, carried, |_, _| {})
    }

    /// `mixed_active` with each pack's source edited by version before it
    /// compiles: 1.0.0 becomes the activation-owned shard, 1.1.0 the JVM one.
    fn mixed_active_edited(
        empty: bool,
        carried: bool,
        edit: impl Fn(&mut Value, &str),
    ) -> Arc<ResolvedActiveSemanticModels> {
        use crate::analyzer::semantic_model::{CompilerOptions, SourceFormat, compile_source};
        let source: Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/semantic-model-packs/declarations-v1.json"
        )))
        .unwrap();
        let packs = ["1.0.0", "1.1.0"].map(|version| {
            let mut source = source.clone();
            source["version"] = json!(version);
            edit(&mut source, version);
            if carried {
                source["carried_sources"] = json!(["com/acme/Widget.java"]);
                source["shards"][0]["payload"]["types"][0]["locator"] = json!({
                    "kind": "source", "path": "com/acme/Widget.java", "symbol": "com.acme.Widget"
                });
            }
            compile_source(
                SourceFormat::Json,
                &serde_json::to_vec(&source).unwrap(),
                &CompilerOptions::default(),
            )
            .unwrap()
        });
        let (mut active, reader) = catalog_fixture_active(&packs, "mixed-row-owners");
        let active = Arc::get_mut(&mut active).unwrap();
        active.indexes = MatcherIndexes::default();
        for (index, shard) in active.shards.iter_mut().enumerate() {
            let shard = Arc::get_mut(shard).unwrap();
            Arc::get_mut(&mut shard.metadata).unwrap().source_kind = if index == 0 {
                CatalogPackSourceKind::WorkspaceProduced
            } else {
                CatalogPackSourceKind::Generated
            };
            shard.decoded = None;
        }
        {
            let installed_source: Option<
                Arc<dyn crate::analyzer::store::model_catalog::RequestRowReaderSource>,
            > = Some(Arc::new(DistinctSource {
                reader: Arc::new(reader),
                empty,
            }));
            active.install_request_source(installed_source).unwrap();
        };
        Arc::new(std::mem::take(active))
    }

    struct CountingSource {
        calls: std::sync::atomic::AtomicUsize,
        reader: Option<Arc<crate::analyzer::store::model_catalog::CatalogRuntimeSourceReader>>,
    }

    impl std::fmt::Debug for CountingSource {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("CountingSource").finish_non_exhaustive()
        }
    }

    impl RequestRowReaderSource for CountingSource {
        fn jvm_reader(
            &self,
            activation: &ResolvedActiveSemanticModels,
        ) -> Result<RequestRowReader, FamilyOpen> {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            crate::analyzer::i_analyzer::refuse_request_row_read_reuse();
            Ok(RequestRowReader {
                reader: request_reader(
                    self.reader
                        .as_ref()
                        .ok_or(FamilyOpen::jvm("test unavailable"))?,
                    activation,
                ),
                binding: ReaderBinding([9; 32]),
            })
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: row composition bound the JVM request owner for non-JVM groups, recording a JVM read and an open part they never used"
    )]
    fn composition_binds_request_owner_only_for_jvm_reads() {
        for available in [false, true] {
            let mut active = mixed_active(false, false);
            Arc::get_mut(&mut active)
                .unwrap()
                .install_request_source(None)
                .unwrap();
            let source = Arc::new(CountingSource {
                calls: std::sync::atomic::AtomicUsize::new(0),
                reader: available.then(|| Arc::clone(active.source_reader.as_ref().unwrap())),
            });
            {
                let installed_source: Option<
                    Arc<dyn crate::analyzer::store::model_catalog::RequestRowReaderSource>,
                > = Some(source.clone());
                Arc::get_mut(&mut active)
                    .unwrap()
                    .install_request_source(installed_source)
                    .unwrap();
            };
            let directory = TempDir::new().unwrap();
            let analyzer =
                EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Java)));
            let ledger = Arc::new(crate::analyzer::read_ledger::ReadLedger::new());
            let _capture = crate::analyzer::i_analyzer::AnalyzerQueryScope::with_read_ledger(
                &analyzer,
                Arc::clone(&ledger),
            );
            let reads = composition::RowCompositionReads::new(&active, &[], &[]);
            // The fixture has JVM shards only: a Rust-scoped scalar question
            // uses the activation alone, even when the JVM owner is unavailable.
            let rust = reads.for_language("rust");
            let rows = rust
                .scalar_question("SELECT 1", &[], |row| row.get::<_, i64>(0))
                .unwrap();
            assert_eq!(rows, vec![1]);
            assert_eq!(source.calls.load(std::sync::atomic::Ordering::Relaxed), 0);
            assert!(!ledger.reuse_refused());
            assert_eq!(rust.open_part(), None);
            let java = reads.for_language("java");
            for _ in 0..2 {
                let result = java.scalar_question("SELECT 1", &[], |row| row.get::<_, i64>(0));
                assert_eq!(result.is_ok(), available);
            }
            assert_eq!(source.calls.load(std::sync::atomic::Ordering::Relaxed), 1);
            assert!(ledger.reuse_refused());
        }
    }

    #[test]
    fn distinct_request_reader_keeps_workspace_jvm_rows_on_activation_owner() {
        let active = mixed_active(true, false);
        let owners = active.question_row_owners(Some("jvm"));
        assert_eq!(owners.readers.len(), 2);
        assert!(!active.shards[0].request_owned());
        assert!(active.shards[1].request_owned());
        let rows = active.all_type_records_named("com.acme.Widget");
        assert_eq!(rows.rows.count(), 1);
    }

    #[test]
    fn distinct_request_reader_merges_realm_scoped_jvm_rows_once() {
        let active = mixed_active(false, false);
        let rows = active.all_type_records_named("com.acme.Widget");
        assert_eq!(rows.rows.count(), 2);
    }

    /// The generator-rule shard of the fixture pack. Its id sorts before
    /// "declarations.widget", so in a pack with both it is the first shard.
    fn generator_shard() -> Value {
        let generators: Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/semantic-model-packs/generator-rules-v1.json"
        )))
        .unwrap();
        let mut shard = generators["shards"][0].clone();
        shard["id"] = json!("a.generators");
        shard
    }

    /// One Generated JVM pack with `shards`, row-backed, with `source` as its
    /// request owner. Returns the activation and each shard's payload kind and
    /// request ownership, in activation order.
    fn row_backed_jvm_pack(
        shards: Vec<Value>,
        source: impl FnOnce(
            crate::analyzer::store::model_catalog::CatalogRuntimeSourceReader,
        ) -> Arc<dyn RequestRowReaderSource>,
    ) -> (
        Arc<ResolvedActiveSemanticModels>,
        Vec<(crate::analyzer::semantic_model::PayloadKind, bool)>,
    ) {
        use crate::analyzer::semantic_model::{CompilerOptions, SourceFormat, compile_source};
        let mut pack: Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/semantic-model-packs/declarations-v1.json"
        )))
        .unwrap();
        pack["shards"] = Value::Array(shards);
        let pack = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&pack).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap();
        let (mut active, reader) = catalog_fixture_active(&[pack], "row-backed-jvm-pack");
        let fixture = Arc::get_mut(&mut active).unwrap();
        // Row-backed shards have no decoded matcher postings.
        fixture.indexes = MatcherIndexes::default();
        for shard in &mut fixture.shards {
            let shard = Arc::get_mut(shard).unwrap();
            Arc::get_mut(&mut shard.metadata).unwrap().source_kind =
                CatalogPackSourceKind::Generated;
            shard.decoded = None;
        }
        {
            let installed_source: Option<
                Arc<dyn crate::analyzer::store::model_catalog::RequestRowReaderSource>,
            > = Some(source(reader));
            fixture.install_request_source(installed_source).unwrap();
        };
        let owners = active
            .shards
            .iter()
            .map(|shard| (shard.descriptor.payload_kind, shard.request_owned()))
            .collect();
        (active, owners)
    }

    fn declarations_and_generator_shards() -> Vec<Value> {
        let declarations: Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/semantic-model-packs/declarations-v1.json"
        )))
        .unwrap();
        vec![declarations["shards"][0].clone(), generator_shard()]
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: cached declarations of a JVM pack whose first or only shard was a generator-rule shard carried no JVM reader binding, though composing them read the request owner"
    )]
    fn every_jvm_provider_binds_its_cached_declarations_to_the_request_owner() {
        use crate::analyzer::semantic_model::PayloadKind::{DeclarationFacts, GeneratorRules};
        for (shards, expected) in [
            (
                declarations_and_generator_shards(),
                vec![(GeneratorRules, false), (DeclarationFacts, true)],
            ),
            (vec![generator_shard()], vec![(GeneratorRules, false)]),
        ] {
            let (active, owners) = row_backed_jvm_pack(shards, |reader| {
                Arc::new(DistinctSource {
                    reader: Arc::new(reader),
                    empty: false,
                })
            });
            assert_eq!(owners, expected);
            let directory = TempDir::new().unwrap();
            let analyzer =
                EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Java)));
            let overlay = SemanticModelOverlay::build(
                &analyzer,
                &active,
                &CancellationToken::new(),
                u64::MAX,
                &crate::retention_budget::RetentionBudget::for_tests(),
            )
            .unwrap();
            let manifest = &active.shards[0].manifest;
            assert!(
                overlay.provider_reads_request_owner(&ModelProvider {
                    pack_id: manifest.pack_id.clone(),
                    pack_version: manifest.version.clone(),
                    pack_digest: manifest.semantic_sha256.clone(),
                }),
                "{owners:?}"
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: with the JVM request owner unavailable, rule lookups by ID, trigger or call still asked it and came back open, so activation-owned rules looked unmapped"
    )]
    fn rule_questions_answer_on_the_activation_owner_while_the_request_owner_is_open() {
        let (active, owners) = row_backed_jvm_pack(declarations_and_generator_shards(), |_| {
            Arc::new(OpenSource)
        });
        assert_eq!(
            owners,
            [
                (
                    crate::analyzer::semantic_model::PayloadKind::GeneratorRules,
                    false
                ),
                (
                    crate::analyzer::semantic_model::PayloadKind::DeclarationFacts,
                    true
                ),
            ]
        );
        assert_eq!(
            active.rules_with_id("rule.builder").disposition,
            SemanticModelMatchDisposition::Unique
        );
        assert_eq!(
            active
                .rules_for(
                    "jvm",
                    crate::analyzer::semantic_model::runtime::RuleTriggerKey::Annotation(
                        "com.acme.GenerateBuilder"
                    )
                )
                .disposition,
            SemanticModelMatchDisposition::Unique
        );
        assert_eq!(unique_active_rules(&active).len(), 1);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: request relation lookup panicked on an open JVM owner"
    )]
    fn open_jvm_owner_does_not_break_overlay_build_and_reports_open() {
        let mut active = mixed_active(false, false);
        Arc::get_mut(&mut active)
            .unwrap()
            .install_request_source(None)
            .unwrap();
        {
            let installed_source: Option<
                Arc<dyn crate::analyzer::store::model_catalog::RequestRowReaderSource>,
            > = Some(Arc::new(
                crate::analyzer::store::model_catalog::RefusingRowReaderSource {
                    reason: FamilyOpen::jvm("test JVM owner open"),
                },
            ));
            Arc::get_mut(&mut active)
                .unwrap()
                .install_request_source(installed_source)
                .unwrap();
        };
        let directory = TempDir::new().unwrap();
        let analyzer =
            EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Java)));
        let overlay = row_entry_points::RowOverlay::new(
            &analyzer,
            &active,
            Vec::new(),
            Vec::new(),
            None,
            &[],
        );
        assert_eq!(
            overlay.relations_to("com.acme.Widget").1,
            Some(FamilyOpen::jvm("test JVM owner open")),
        );
    }

    #[test]
    fn carried_request_source_and_uncarried_model_locations() {
        use locations::SemanticModelLocations;
        let active = mixed_active(false, true);
        let directory = TempDir::new().unwrap();
        let analyzer =
            EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Java)));
        let source = row_entry_points::RowOverlay::new(
            &analyzer,
            &active,
            Vec::new(),
            Vec::new(),
            None,
            &[],
        );
        let (rows, open) = source.symbols_at_authored_path("com/acme/Widget.java");
        assert!(open.is_none());
        assert_eq!(rows.len(), 1, "same-ID pack rows compose to one symbol");
        assert!(rows.iter().all(|row| matches!(&row.location, SemanticModelLocation::Authored(anchor) if anchor.path == "com/acme/Widget.java")));

        let uncarried = mixed_active(false, false);
        let shard = &uncarried.shards[1];
        assert!(shard.manifest.carried_sources.is_empty());
        let locator = Locator::Source {
            path: "com/acme/Missing.java".into(),
            symbol: Some("com.acme.Missing".into()),
        };
        assert_eq!(
            locations::CarriedSourceLocations.record_location(
                shard,
                &locator,
                "com.acme.Missing",
                "type",
                "missing"
            ),
            model_location(shard, "type", "missing"),
            "a request-owned JMOD-like record without carried source keeps its model URI",
        );
    }

    /// A real-like request owner whose binding the test moves between requests.
    #[derive(Debug)]
    struct BindingSource {
        reader: Arc<crate::analyzer::store::model_catalog::CatalogRuntimeSourceReader>,
        binding: std::sync::atomic::AtomicU8,
    }

    impl RequestRowReaderSource for BindingSource {
        fn jvm_reader(
            &self,
            activation: &ResolvedActiveSemanticModels,
        ) -> Result<RequestRowReader, FamilyOpen> {
            use crate::analyzer::read_ledger::{LookupKind, LookupQuestion, ReadKey};
            for tag in [1, 2] {
                crate::analyzer::i_analyzer::record_request_row_selection_read(ReadKey::lookup(
                    LookupKind::ExternalSelection,
                    LookupQuestion::ExternalSelection {
                        question_digest: [tag; 32],
                    },
                    crate::analyzer::semantic::ids::StableDigest::from_array(
                        [self.binding.load(std::sync::atomic::Ordering::Relaxed); 32],
                    ),
                ));
            }
            Ok(RequestRowReader {
                reader: Arc::new(DistinctReader {
                    reader: request_reader(&self.reader, activation),
                    empty: false,
                }),
                binding: ReaderBinding(
                    [self.binding.load(std::sync::atomic::Ordering::Relaxed); 32],
                ),
            })
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10689: cross-family ranking rejected an admitted type declaration"
    )]
    fn type_declaration_admission_ignores_other_families() {
        let active = mixed_active_edited(false, false, |source, version| {
            if version == "1.0.0" {
                source["pack_id"] = json!("acme.widget.py");
                source["language"] = json!("python");
                source["ecosystem"] = json!("pypi");
                source["shards"][0]["payload"]["types"][0]["name"] = json!("python.Widget");
            }
        });
        let candidates = active.all_type_records_with_id("type.widget");
        let mut visited = 0;
        for candidate in candidates.rows {
            assert!(
                active
                    .type_declaration_admitted::<FamilyOpen>(&candidate, &mut || {
                        visited += 1;
                        Ok(())
                    })
                    .unwrap()
            );
        }
        assert!(visited > 0);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: a Python model search returned no rows while the JVM request owner was open"
    )]
    fn failed_jvm_read_keeps_python_search_complete() {
        use brokk_bifrost_semantic::analyzer::semantic_model::catalog::statements;
        let mut active = mixed_active_edited(false, false, |source, version| {
            if version == "1.0.0" {
                source["pack_id"] = json!("acme.widget.py");
                source["language"] = json!("python");
                source["ecosystem"] = json!("pypi");
            }
        });
        Arc::get_mut(&mut active)
            .unwrap()
            .install_request_source(None)
            .unwrap();
        let reader = active.source_reader.as_ref().unwrap().clone();
        let counting = Arc::new(CountingSource {
            calls: std::sync::atomic::AtomicUsize::new(0),
            reader: None,
        });
        let sources: Vec<Arc<dyn RequestRowReaderSource>> = vec![
            Arc::new(OpenSource),
            Arc::new(LaterOpenSource {
                reader,
                statement: statements::SEARCH_ORDERED_CANDIDATES,
            }),
            counting.clone(),
        ];
        let patterns =
            crate::analyzer::SearchSymbolPatternBatch::compile(vec![".*".into()], false, None);
        for source in sources {
            {
                let installed_source: Option<
                    Arc<dyn crate::analyzer::store::model_catalog::RequestRowReaderSource>,
                > = Some(source);
                Arc::get_mut(&mut active)
                    .unwrap()
                    .install_request_source(installed_source)
                    .unwrap();
            };
            let directory = TempDir::new().unwrap();
            let analyzer =
                EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Java)));
            let overlay = SemanticModelOverlay::build(
                &analyzer,
                &active,
                &CancellationToken::new(),
                u64::MAX,
                &crate::retention_budget::RetentionBudget::for_tests(),
            )
            .unwrap();
            let (rows, _, complete) = overlay.search_with_limit_filter_in_family(
                &patterns,
                usize::MAX,
                None,
                "python",
                |_| true,
            );
            assert!(complete);
            assert!(!rows.is_empty());
            assert!(rows.iter().all(|row| row.language == "python"));
            assert_eq!(counting.calls.load(std::sync::atomic::Ordering::Relaxed), 0);
            for answer in [
                overlay.search_with_limit_filter(&patterns, usize::MAX, None, |_| true),
                overlay.search_with_limit_filter_in_family(
                    &patterns,
                    usize::MAX,
                    None,
                    "java",
                    |_| true,
                ),
            ] {
                assert!(!answer.2);
                assert!(answer.0.is_empty());
            }
        }
        {
            let installed_source: Option<
                Arc<dyn crate::analyzer::store::model_catalog::RequestRowReaderSource>,
            > = Some(Arc::new(CountingSource {
                calls: std::sync::atomic::AtomicUsize::new(0),
                reader: Some({
                    Arc::get_mut(&mut active)
                        .unwrap()
                        .install_request_source(None)
                        .unwrap();
                    active.source_reader.as_ref().unwrap().clone()
                }),
            }));
            Arc::get_mut(&mut active)
                .unwrap()
                .install_request_source(installed_source)
                .unwrap();
        };
        let directory = TempDir::new().unwrap();
        let analyzer =
            EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Java)));
        let mut overlay = SemanticModelOverlay::build(
            &analyzer,
            &active,
            &CancellationToken::new(),
            u64::MAX,
            &crate::retention_budget::RetentionBudget::for_tests(),
        )
        .unwrap();
        let cache = crate::analyzer::store::cache_budget::StoreCacheBudget::new(
            &crate::retention_budget::RetentionBudget::for_tests(),
        );
        Arc::make_mut(overlay.row_source.as_mut().unwrap()).cache = Some(cache);
        for _ in 0..2 {
            let scoped = overlay.search_with_limit_filter_in_family(
                &patterns,
                usize::MAX,
                None,
                "python",
                |_| true,
            );
            let unscoped = overlay.search_with_limit_filter(&patterns, usize::MAX, None, |_| true);
            assert!(scoped.2 && unscoped.2);
            assert!(scoped.0.iter().all(|row| row.language == "python"));
            assert!(unscoped.0.iter().any(|row| row.language == "java"));
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: skipping a request owner with no request-owned activation shard answered a request-only JVM selection as complete"
    )]
    fn request_owner_is_consulted_without_request_owned_shards() {
        // Both packs are Python, so the activation holds no request-owned
        // shard. The request owner's bind is still the check that the
        // request's JVM selection matches the activation; when it refuses,
        // an unscoped answer is Open, not complete.
        let mut active = mixed_active_edited(false, false, |source, version| {
            source["pack_id"] = json!(format!("acme.widget.py.{version}"));
            source["language"] = json!("python");
            source["ecosystem"] = json!("pypi");
        });
        assert!(!active.shards.iter().any(|shard| shard.request_owned()));
        Arc::get_mut(&mut active)
            .unwrap()
            .install_request_source(Some(Arc::new(OpenSource)))
            .unwrap();
        // The store's question owners (`question_row_owners`) and the overlay's
        // composition reads each decide the request owner.
        assert!(matches!(
            active.types_with_id("type.widget").disposition,
            SemanticModelMatchDisposition::Open(_)
        ));
        let directory = TempDir::new().unwrap();
        let analyzer =
            EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Java)));
        let overlay = SemanticModelOverlay::build(
            &analyzer,
            &active,
            &CancellationToken::new(),
            u64::MAX,
            &crate::retention_budget::RetentionBudget::for_tests(),
        )
        .unwrap();
        assert!(
            matches!(
                overlay.symbols_with_id("type.widget").disposition,
                SemanticModelOverlayDisposition::Open(_)
            ),
            "an unscoped answer read past a refused request owner"
        );
        // A Python-scoped answer never consults the JVM owner.
        assert!(!matches!(
            overlay
                .symbols_with_id_for("type.widget", "python")
                .disposition,
            SemanticModelOverlayDisposition::Open(_)
        ));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: a Python *_for lookup bound and waited on the JVM request owner; scoped Python reads are now unaffected"
    )]
    fn failed_jvm_read_keeps_python_questions_complete() {
        use brokk_bifrost_semantic::analyzer::semantic_model::catalog::statements;
        let mut active = mixed_active_edited(false, false, |source, version| {
            if version == "1.0.0" {
                source["pack_id"] = json!("acme.widget.py");
                source["language"] = json!("python");
                source["ecosystem"] = json!("pypi");
            }
        });
        Arc::get_mut(&mut active)
            .unwrap()
            .install_request_source(None)
            .unwrap();
        let reader = active.source_reader.as_ref().unwrap().clone();
        let counting = Arc::new(CountingSource {
            calls: std::sync::atomic::AtomicUsize::new(0),
            reader: None,
        });
        let sources: Vec<Arc<dyn RequestRowReaderSource>> = vec![
            Arc::new(OpenSource),
            Arc::new(LaterOpenSource {
                reader: reader.clone(),
                statement: statements::TYPES_BY_ID,
            }),
            Arc::new(LaterOpenSource {
                reader: reader.clone(),
                statement: statements::MEMBERS_BY_OWNERS,
            }),
            Arc::new(LaterOpenSource {
                reader,
                statement: statements::TYPE_SPELLINGS,
            }),
            counting.clone(),
        ];
        for (index, source) in sources.into_iter().enumerate() {
            {
                let installed_source: Option<
                    Arc<dyn crate::analyzer::store::model_catalog::RequestRowReaderSource>,
                > = Some(source);
                Arc::get_mut(&mut active)
                    .unwrap()
                    .install_request_source(installed_source)
                    .unwrap();
            };
            let directory = TempDir::new().unwrap();
            let analyzer =
                EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Java)));
            let overlay = SemanticModelOverlay::build(
                &analyzer,
                &active,
                &CancellationToken::new(),
                u64::MAX,
                &crate::retention_budget::RetentionBudget::for_tests(),
            )
            .unwrap();
            for answer in [
                overlay.symbols_with_id_for("type.widget", "python"),
                overlay.symbols_named_for("com.acme.Widget", "python"),
                overlay.members_of_for("type.widget", "python"),
            ] {
                assert!(
                    !matches!(answer.disposition, SemanticModelOverlayDisposition::Open(_)),
                    "{answer:?}"
                );
                assert!(!answer.records.is_empty());
            }
            assert_eq!(counting.calls.load(std::sync::atomic::Ordering::Relaxed), 0);
            // Statement failures affect only queries that execute that statement.
            // Bind failures affect all three JVM entry points.
            let answers = match index {
                1 => vec![overlay.symbols_with_id_for("type.widget", "java")],
                2 => vec![overlay.members_of_for("type.widget", "java")],
                3 => vec![overlay.symbols_named_for("com.acme.Widget", "java")],
                _ => vec![
                    overlay.symbols_with_id_for("type.widget", "java"),
                    overlay.symbols_named_for("com.acme.Widget", "java"),
                    overlay.members_of_for("type.widget", "java"),
                ],
            };
            for answer in answers {
                assert!(
                    matches!(answer.disposition, SemanticModelOverlayDisposition::Open(_)),
                    "{answer:?}"
                );
            }
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: a Python relations_to lookup composed a generated Java owner and opened on the JVM request owner"
    )]
    fn scoped_relations_to_skips_other_family_generated_owners() {
        let python_pack = |source: &mut Value, version: &str| {
            if version == "1.0.0" {
                source["pack_id"] = json!("acme.widget.py");
                source["language"] = json!("python");
                source["ecosystem"] = json!("pypi");
            }
        };
        let directory = TempDir::new().unwrap();
        let analyzer =
            EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Java)));
        // A real Java symbol and relation, re-identified as generated facts
        // whose relation targets the shared type ID.
        let working = mixed_active_edited(false, false, python_pack);
        let working_source = row_entry_points::RowOverlay::new(
            &analyzer,
            &working,
            Vec::new(),
            Vec::new(),
            None,
            &[],
        );
        let (symbols, _) = working_source.symbols_with_id_scoped("type.widget", Some("jvm"));
        let mut generated_owner = (*symbols
            .into_iter()
            .find(|symbol| symbol.language == "java")
            .expect("the Java pack declares the type"))
        .clone();
        generated_owner.id = "generated.java.owner".into();
        let (relations, _) =
            working_source.relations_from_scoped("member.widget.create", Some("jvm"));
        let mut generated_relation = (*relations
            .into_iter()
            .next()
            .expect("the Java pack declares the relation"))
        .clone();
        generated_relation.id = "generated.java.relation".into();
        generated_relation.from = generated_owner.id.clone();
        generated_relation.to = "type.widget".into();
        generated_relation.pre_composition_endpoints = None;

        let mut active = mixed_active_edited(false, false, python_pack);
        {
            let installed_source: Option<
                Arc<dyn crate::analyzer::store::model_catalog::RequestRowReaderSource>,
            > = Some(Arc::new(OpenSource));
            Arc::get_mut(&mut active)
                .unwrap()
                .install_request_source(installed_source)
                .unwrap();
        };
        let source = row_entry_points::RowOverlay::new(
            &analyzer,
            &active,
            vec![generated_owner],
            vec![generated_relation],
            None,
            &[],
        );
        let (_, open) = source.relations_to_scoped("type.widget", Some("python"));
        assert!(open.is_none(), "{open:?}");
        let (_, open) = source.relations_to_scoped("type.widget", Some("jvm"));
        assert!(open.is_some());
    }

    /// Decoded Java and Python packs compiled from one source, so they
    /// publish the same declaration and relation IDs.
    fn decoded_family_overlay() -> (
        SemanticModelOverlay,
        crate::analyzer::store::model_catalog::CatalogRuntimeSourceReader,
        TempDir,
    ) {
        use crate::analyzer::semantic_model::{CompilerOptions, SourceFormat, compile_source};
        let source: Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/semantic-model-packs/declarations-v1.json"
        )))
        .unwrap();
        let packs = [
            ("java", "maven", "acme.widget"),
            ("python", "pypi", "acme.widget.py"),
        ]
        .map(|(language, ecosystem, pack_id)| {
            let mut source = source.clone();
            source["language"] = json!(language);
            source["ecosystem"] = json!(ecosystem);
            source["pack_id"] = json!(pack_id);
            if language == "python" {
                source["shards"][0]["payload"]["types"][0]["name"] = json!("python.Widget");
            }
            source["shards"]
                .as_array_mut()
                .unwrap()
                .push(generator_shard());
            compile_source(
                SourceFormat::Json,
                &serde_json::to_vec(&source).unwrap(),
                &CompilerOptions::default(),
            )
            .unwrap()
        });
        assert_pack_set_parity(&packs, "cross-family-shared-ids");
        let (mut active, reader) = catalog_fixture_active(&packs, "decoded-families");
        for shard in &mut Arc::get_mut(&mut active).unwrap().shards {
            let shard = Arc::get_mut(shard).unwrap();
            Arc::make_mut(&mut shard.metadata).source_rank = if shard.manifest.language == "java" {
                2
            } else {
                1
            };
        }
        // Equal extraction contributors remain equivalent, while equal records
        // from distinct JDK artifacts retain their artifact ambiguity (#10689).
        let mut equivalent = active.members_with_id("member.widget.create");
        equivalent
            .records
            .retain(|record| record.shard.manifest.language == "java");
        equivalent.records.push(equivalent.records[0].clone());
        assert_eq!(
            matches_by_family(SemanticModelMatch {
                disposition: equivalent.disposition,
                records: equivalent.records.clone(),
                candidates_examined: equivalent.candidates_examined,
                fallback_candidates_examined: equivalent.fallback_candidates_examined
            })[0]
                .1
                .disposition,
            SemanticModelMatchDisposition::Unique
        );
        for (index, record) in equivalent.records.iter_mut().enumerate() {
            let mut metadata = (*record.shard.metadata).clone();
            metadata.matched_evidence.ecosystem = "jdk".into();
            metadata.matched_evidence.artifact_sha256 = Some(index.to_string());
            record.shard = Arc::new(ActiveSemanticModelShard {
                metadata: Arc::new(metadata),
                decoded: record.shard.decoded.clone(),
            });
        }
        assert_eq!(
            matches_by_family(equivalent)[0].1.disposition,
            SemanticModelMatchDisposition::Conflict
        );
        let rows = metadata_only_active(&active, &reader);
        for backing in [&active, &rows] {
            assert_eq!(
                unique_active_rules(backing).len(),
                2,
                "shared rule IDs remain active in both families"
            );
        }
        let directory = TempDir::new().unwrap();
        let analyzer =
            EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Java)));
        let overlay = SemanticModelOverlay::build(
            &analyzer,
            &active,
            &CancellationToken::new(),
            u64::MAX,
            &crate::retention_budget::RetentionBudget::for_tests(),
        )
        .unwrap();
        (overlay, reader, directory)
    }

    fn packs_of<T>(
        matched: SemanticModelOverlayMatch<T>,
        pack_id: impl Fn(&T) -> &str,
    ) -> Vec<String> {
        let mut packs = matched
            .records
            .iter()
            .map(|record| pack_id(record).to_owned())
            .collect::<Vec<_>>();
        packs.sort();
        packs.dedup();
        packs
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: a family-scoped relation lookup returned another family's decoded relations for a shared declaration ID"
    )]
    fn scoped_relation_lookups_keep_only_their_family_decoded_relations() {
        let (overlay, _reader, _directory) = decoded_family_overlay();
        let relation_packs = |matched: SemanticModelOverlayMatch<SemanticModelRelation>| {
            packs_of(matched, |relation| &relation.provenance.pack_id)
        };
        for python in [
            overlay.relations_from_for("member.widget.create", "python"),
            overlay.relations_to_for("type.widget", "python"),
        ] {
            assert!(
                relation_packs(python) == ["acme.widget.py"],
                "a Python lookup must preserve its family's relation"
            );
        }
        assert_eq!(
            relation_packs(overlay.relations_from_for("member.widget.create", "java")),
            ["acme.widget"]
        );
        assert_eq!(
            relation_packs(overlay.relations_to_for("type.widget", "java")),
            ["acme.widget"]
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon("#10689: a Java pack hid Python records with the same ID")]
    fn decoded_packs_of_different_families_keep_their_own_records_for_a_shared_id() {
        let (overlay, _reader, _directory) = decoded_family_overlay();
        let relations = overlay.relations_from("member.widget.create").records;
        let rewritten = composition::rewrite_relations(
            relations
                .iter()
                .enumerate()
                .map(|(index, relation)| (index, (**relation).clone()))
                .collect(),
            &[(
                ("jvm".to_owned(), "type.widget".to_owned()),
                "java.representative".to_owned(),
            )]
            .into_iter()
            .collect(),
            &HashSet::default(),
            &composition::OriginRewrites::default(),
        );
        for (_, relation) in rewritten {
            assert_eq!(
                relation.to,
                if relation.provenance.pack_id == "acme.widget.py" {
                    "type.widget"
                } else {
                    "java.representative"
                }
            );
        }
        let python_members = overlay.symbols_with_id_for("member.widget.create", "python");
        assert_eq!(
            python_members.records[0].qualified_name,
            "python.Widget.create"
        );
        let symbol_packs = |matched: SemanticModelOverlayMatch<SemanticModelSymbol>| {
            packs_of(matched, |symbol| &symbol.provenance.pack_id)
        };
        let relation_packs = |matched: SemanticModelOverlayMatch<SemanticModelRelation>| {
            packs_of(matched, |relation| &relation.provenance.pack_id)
        };
        assert_eq!(
            symbol_packs(overlay.symbols_with_id_for("type.widget", "python")),
            ["acme.widget.py"]
        );
        assert_eq!(
            relation_packs(overlay.relations_from_for("member.widget.create", "python")),
            ["acme.widget.py"]
        );
        assert_eq!(
            relation_packs(overlay.relations_from("member.widget.create")),
            ["acme.widget", "acme.widget.py"]
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: a Python relation and owner-surface read waited on the JVM request owner"
    )]
    fn failed_jvm_read_keeps_python_relations_complete() {
        use brokk_bifrost_semantic::analyzer::semantic_model::catalog::statements;
        let mut active = mixed_active_edited(false, false, |source, version| {
            if version == "1.0.0" {
                source["pack_id"] = json!("acme.widget.py");
                source["language"] = json!("python");
                source["ecosystem"] = json!("pypi");
            }
        });
        Arc::get_mut(&mut active)
            .unwrap()
            .install_request_source(None)
            .unwrap();
        let reader = active.source_reader.as_ref().unwrap().clone();
        let counting = Arc::new(CountingSource {
            calls: std::sync::atomic::AtomicUsize::new(0),
            reader: None,
        });
        let sources: Vec<Arc<dyn RequestRowReaderSource>> = vec![
            Arc::new(OpenSource),
            Arc::new(LaterOpenSource {
                reader: reader.clone(),
                statement: statements::TYPES_BY_ID,
            }),
            Arc::new(LaterOpenSource {
                reader: reader.clone(),
                statement: statements::OVERLAY_RELATIONS_FROM,
            }),
            Arc::new(LaterOpenSource {
                reader,
                statement: statements::OVERLAY_RELATIONS_TO,
            }),
            Arc::new(LaterOpenSource {
                reader: {
                    Arc::get_mut(&mut active)
                        .unwrap()
                        .install_request_source(None)
                        .unwrap();
                    active.source_reader.as_ref().unwrap().clone()
                },
                statement: statements::RELATIONS_FROM,
            }),
            counting.clone(),
        ];
        for (index, source) in sources.into_iter().enumerate() {
            {
                let installed_source: Option<
                    Arc<dyn crate::analyzer::store::model_catalog::RequestRowReaderSource>,
                > = Some(source);
                Arc::get_mut(&mut active)
                    .unwrap()
                    .install_request_source(installed_source)
                    .unwrap();
            };
            let directory = TempDir::new().unwrap();
            let analyzer =
                EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Java)));
            let overlay = SemanticModelOverlay::build(
                &analyzer,
                &active,
                &CancellationToken::new(),
                u64::MAX,
                &crate::retention_budget::RetentionBudget::for_tests(),
            )
            .unwrap();
            for answer in [
                overlay.relations_from_for("member.widget.create", "python"),
                overlay.relations_to_for("type.widget", "python"),
            ] {
                assert!(
                    !matches!(answer.disposition, SemanticModelOverlayDisposition::Open(_)),
                    "{answer:?}"
                );
                assert!(!answer.records.is_empty(), "{answer:?}");
            }
            assert_eq!(counting.calls.load(std::sync::atomic::Ordering::Relaxed), 0);
            // Statement failures affect only queries that execute that statement.
            // OVERLAY_RELATIONS_FROM is not executed by relation composition.
            let answers = match index {
                2 => Vec::new(),
                3 => vec![overlay.relations_to_for("type.widget", "java")],
                _ => vec![
                    overlay.relations_from_for("member.widget.create", "java"),
                    overlay.relations_to_for("type.widget", "java"),
                ],
            };
            for answer in answers {
                assert!(
                    matches!(answer.disposition, SemanticModelOverlayDisposition::Open(_)),
                    "{answer:?}"
                );
            }
        }
    }

    #[test]
    fn overlay_build_never_consults_the_request_owner() {
        let mut active = mixed_active(false, false);
        Arc::get_mut(&mut active)
            .unwrap()
            .install_request_source(None)
            .unwrap();
        {
            let installed_source: Option<
                Arc<dyn crate::analyzer::store::model_catalog::RequestRowReaderSource>,
            > = Some(Arc::new(OpenSource));
            Arc::get_mut(&mut active)
                .unwrap()
                .install_request_source(installed_source)
                .unwrap();
        };
        let directory = TempDir::new().unwrap();
        let analyzer =
            EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Java)));
        let overlay = SemanticModelOverlay::build(
            &analyzer,
            &active,
            &CancellationToken::new(),
            u64::MAX,
            &crate::retention_budget::RetentionBudget::for_tests(),
        )
        .expect("overlay construction reads only the activation owner");
        // At request time the JVM part is still open.
        assert!(matches!(
            overlay.symbols_named("com.acme.Widget").disposition,
            SemanticModelOverlayDisposition::Open(_)
        ));
    }

    #[test]
    fn declared_type_name_memo_follows_the_request_binding() {
        let mut active = mixed_active(false, false);
        Arc::get_mut(&mut active)
            .unwrap()
            .install_request_source(None)
            .unwrap();
        Arc::get_mut(&mut active)
            .unwrap()
            .install_request_source(None)
            .unwrap();
        let reader = Arc::clone(active.source_reader.as_ref().expect("row-backed fixture"));
        let source = Arc::new(BindingSource {
            reader,
            binding: std::sync::atomic::AtomicU8::new(1),
        });
        {
            let installed_source: Option<
                Arc<dyn crate::analyzer::store::model_catalog::RequestRowReaderSource>,
            > = Some(source.clone());
            Arc::get_mut(&mut active)
                .unwrap()
                .install_request_source(installed_source)
                .unwrap();
        };
        let directory = TempDir::new().unwrap();
        let analyzer =
            EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Java)));
        let overlay = SemanticModelOverlay::build(
            &analyzer,
            &active,
            &CancellationToken::new(),
            u64::MAX,
            &crate::retention_budget::RetentionBudget::for_tests(),
        )
        .unwrap();
        let binding_of =
            |overlay: &SemanticModelOverlay| overlay.declared_type_names.lock().unwrap()["java"].0;
        let first = overlay
            .model_declared_types_named("java", &["Widget"])
            .unwrap();
        assert_eq!(binding_of(&overlay), Some(ReaderBinding([1; 32])));
        // A later request with another binding never sees the first entry.
        source
            .binding
            .store(2, std::sync::atomic::Ordering::Relaxed);
        let ledger = Arc::new(crate::analyzer::read_ledger::ReadLedger::new());
        let second = {
            let _capture = crate::analyzer::i_analyzer::AnalyzerQueryScope::with_read_ledger(
                &analyzer,
                Arc::clone(&ledger),
            );
            overlay
                .model_declared_types_named("java", &["Widget"])
                .unwrap()
        };
        assert_eq!(binding_of(&overlay), Some(ReaderBinding([2; 32])));
        assert_eq!(first, second);
        assert!(!Arc::ptr_eq(&first, &second));
        // The request owner records both selection keys on fills and memo hits.
        assert!(!ledger.reuse_refused());
        assert_eq!(ledger.len(), 2);
        let hit_ledger = Arc::new(crate::analyzer::read_ledger::ReadLedger::new());
        let third = {
            let _capture = crate::analyzer::i_analyzer::AnalyzerQueryScope::with_read_ledger(
                &analyzer,
                Arc::clone(&hit_ledger),
            );
            overlay
                .model_declared_types_named("java", &["Widget"])
                .unwrap()
        };
        assert!(Arc::ptr_eq(&second, &third));
        assert!(!hit_ledger.reuse_refused());
        assert_eq!(ledger.keys(), hit_ledger.keys());
    }

    /// Like the real JVM owner, answers only inside a request scope.
    #[derive(Debug)]
    struct RequestScopedSource {
        reader: Arc<crate::analyzer::store::model_catalog::CatalogRuntimeSourceReader>,
    }

    impl RequestRowReaderSource for RequestScopedSource {
        fn jvm_reader(
            &self,
            activation: &ResolvedActiveSemanticModels,
        ) -> Result<RequestRowReader, FamilyOpen> {
            crate::analyzer::i_analyzer::current_outer_request()
                .ok_or(FamilyOpen::jvm("no request scope"))?;
            Ok(RequestRowReader {
                reader: Arc::new(DistinctReader {
                    reader: request_reader(&self.reader, activation),
                    empty: false,
                }),
                binding: ReaderBinding([7; 32]),
            })
        }
    }

    #[test]
    fn carried_helper_threads_see_the_request_owner_and_uncarried_ones_are_open() {
        let mut active = mixed_active(false, false);
        Arc::get_mut(&mut active)
            .unwrap()
            .install_request_source(None)
            .unwrap();
        Arc::get_mut(&mut active)
            .unwrap()
            .install_request_source(None)
            .unwrap();
        let reader = Arc::clone(active.source_reader.as_ref().expect("row-backed fixture"));
        {
            let installed_source: Option<
                Arc<dyn crate::analyzer::store::model_catalog::RequestRowReaderSource>,
            > = Some(Arc::new(RequestScopedSource { reader }));
            Arc::get_mut(&mut active)
                .unwrap()
                .install_request_source(installed_source)
                .unwrap();
        };
        let directory = TempDir::new().unwrap();
        let analyzer =
            EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Java)));
        let overlay = SemanticModelOverlay::build(
            &analyzer,
            &active,
            &CancellationToken::new(),
            u64::MAX,
            &crate::retention_budget::RetentionBudget::for_tests(),
        )
        .unwrap();
        let request = brokk_bifrost_core::analyzer::outer_request::OuterRequest::new();
        let _scope =
            crate::analyzer::i_analyzer::AnalyzerQueryScope::with_outer_request(&analyzer, request);
        let carried = brokk_bifrost_core::analyzer::carried_context::CarriedContext::current();
        std::thread::scope(|scope| {
            let seen = scope
                .spawn(|| carried.run(|| overlay.symbols_named("com.acme.Widget")))
                .join()
                .unwrap();
            assert!(!matches!(
                seen.disposition,
                SemanticModelOverlayDisposition::Open(_)
            ));
            // Same-ID pack rows compose to one symbol, so the request owner's
            // part shows as a complete answer rather than as a second record.
            assert!(!seen.records.is_empty());
            // Without the carried request the JVM part is open: possible
            // candidates only, never an empty complete answer.
            let uncarried = scope
                .spawn(|| overlay.symbols_named("com.acme.Widget"))
                .join()
                .unwrap();
            assert!(matches!(
                uncarried.disposition,
                SemanticModelOverlayDisposition::Open(_)
            ));
        });
    }

    #[derive(Debug)]
    struct LaterOpenSource {
        reader: Arc<crate::analyzer::store::model_catalog::CatalogRuntimeSourceReader>,
        statement: &'static str,
    }

    impl CatalogRowReader for LaterOpenSource {
        fn owned_rows(
            &self,
            statement: &str,
            bindings: &[(&str, &dyn rusqlite::ToSql)],
            cancellation: &CancellationToken,
        ) -> Result<OwnedCatalogRows, CatalogError> {
            if statement.contains(self.statement.trim_end_matches(';')) {
                return Err(CatalogError::FamilyOpen(FamilyOpen::jvm(
                    "JVM catalog busy",
                )));
            }
            self.reader.owned_rows(statement, bindings, cancellation)
        }
    }

    impl RequestRowReaderSource for LaterOpenSource {
        fn jvm_reader(
            &self,
            activation: &ResolvedActiveSemanticModels,
        ) -> Result<RequestRowReader, FamilyOpen> {
            Ok(RequestRowReader {
                reader: Arc::new(Self {
                    reader: request_reader(&self.reader, activation),
                    statement: self.statement,
                }),
                binding: ReaderBinding([19; 32]),
            })
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: a JVM statement that failed after binding discarded the activation owner's rows of the same read"
    )]
    fn failed_jvm_statement_keeps_activation_rows() {
        use brokk_bifrost_semantic::analyzer::semantic_model::catalog::statements;
        // The activation-owned pack is Python, the JVM-owned one Java: an
        // unscoped read spans both families.
        let mut active = mixed_active_edited(false, false, |source, version| {
            if version == "1.0.0" {
                source["pack_id"] = json!("acme.widget.py");
                source["language"] = json!("python");
                source["ecosystem"] = json!("pypi");
            }
        });
        Arc::get_mut(&mut active)
            .unwrap()
            .install_request_source(None)
            .unwrap();
        let reader = active.source_reader.as_ref().unwrap().clone();
        {
            let installed_source: Option<
                Arc<dyn crate::analyzer::store::model_catalog::RequestRowReaderSource>,
            > = Some(Arc::new(LaterOpenSource {
                reader,
                statement: statements::TYPES_BY_ID,
            }));
            Arc::get_mut(&mut active)
                .unwrap()
                .install_request_source(installed_source)
                .unwrap();
        };
        let directory = TempDir::new().unwrap();
        let analyzer =
            EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Java)));
        let source = row_entry_points::RowOverlay::new(
            &analyzer,
            &active,
            Vec::new(),
            Vec::new(),
            None,
            &[],
        );
        // The Python shard's rows stand next to the JVM owner's failed part,
        // as candidates; before, the failed statement discarded them too.
        let (records, open) = source.symbols_with_id("type.widget");
        assert!(open.is_some());
        assert!(
            records
                .iter()
                .any(|record| record.id == "type.widget" && record.language == "python"),
            "{records:?}"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: relation and search hydration panicked when a bound JVM reader opened"
    )]
    fn bound_reader_open_is_incomplete() {
        use brokk_bifrost_semantic::analyzer::semantic_model::catalog::statements;
        for statement in [
            statements::OVERLAY_RELATIONS_TO,
            statements::TYPES_BY_ID,
            statements::GROUP_OWNER_IDS,
        ] {
            let mut active = mixed_active(false, false);
            Arc::get_mut(&mut active)
                .unwrap()
                .install_request_source(None)
                .unwrap();
            Arc::get_mut(&mut active)
                .unwrap()
                .install_request_source(None)
                .unwrap();
            let reader = active.source_reader.as_ref().unwrap().clone();
            {
                let installed_source: Option<
                    Arc<dyn crate::analyzer::store::model_catalog::RequestRowReaderSource>,
                > = Some(Arc::new(LaterOpenSource { reader, statement }));
                Arc::get_mut(&mut active)
                    .unwrap()
                    .install_request_source(installed_source)
                    .unwrap();
            };
            let directory = TempDir::new().unwrap();
            let analyzer =
                EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Java)));
            let source = row_entry_points::RowOverlay::new(
                &analyzer,
                &active,
                Vec::new(),
                Vec::new(),
                None,
                &[],
            );
            if statement == statements::OVERLAY_RELATIONS_TO {
                assert!(source.relations_to("widget").1.is_some());
            } else if statement == statements::TYPES_BY_ID {
                assert!(source.relations_from("widget").1.is_some());
            } else {
                let patterns = crate::analyzer::SearchSymbolPatternBatch::compile(
                    vec![".*".into()],
                    false,
                    None,
                );
                assert!(!source.search_symbols(&patterns, None, None).1);
            }
        }
    }

    #[derive(Debug)]
    struct OpenSource;

    impl RequestRowReaderSource for OpenSource {
        fn jvm_reader(
            &self,
            _activation: &ResolvedActiveSemanticModels,
        ) -> Result<RequestRowReader, FamilyOpen> {
            Err(FamilyOpen::jvm("request source unavailable"))
        }
    }

    #[test]
    fn open_split_question_is_not_retained() {
        let mut active = mixed_active(false, true);
        Arc::get_mut(&mut active)
            .unwrap()
            .install_request_source(Some(Arc::new(OpenSource)))
            .unwrap();
        let directory = TempDir::new().unwrap();
        let analyzer =
            EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Java)));
        let cache = crate::analyzer::store::cache_budget::StoreCacheBudget::new(
            &crate::retention_budget::RetentionBudget::for_tests(),
        );
        let source = row_entry_points::RowOverlay::new(
            &analyzer,
            &active,
            Vec::new(),
            Vec::new(),
            Some(cache.clone()),
            &[],
        );
        // The dot-boundary split questions run even when the request-owned JVM
        // reader is open. Their openness must reach the lookup disposition.
        let (_, open) = source.symbols_named("com.acme.Widget.Missing");
        assert_eq!(open, Some(FamilyOpen::jvm("request source unavailable")));
        let discovery = cache
            .region_stats()
            .into_iter()
            .find(|(name, _)| *name == "store.composition-discovery")
            .unwrap();
        assert_eq!(discovery.1.entries, 0);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: search panicked on an open JVM part instead of reporting an incomplete answer"
    )]
    fn open_request_search_and_enumeration_are_incomplete() {
        let mut active = mixed_active(false, true);
        {
            let installed_source: Option<
                Arc<dyn crate::analyzer::store::model_catalog::RequestRowReaderSource>,
            > = Some(Arc::new(OpenSource));
            Arc::get_mut(&mut active)
                .unwrap()
                .install_request_source(installed_source)
                .unwrap();
        };
        let directory = TempDir::new().unwrap();
        let analyzer =
            EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Java)));
        let source = row_entry_points::RowOverlay::new(
            &analyzer,
            &active,
            Vec::new(),
            Vec::new(),
            None,
            &[],
        );
        let patterns =
            crate::analyzer::SearchSymbolPatternBatch::compile(vec![".*".into()], false, None);
        assert!(!source.search_symbols(&patterns, None, None).1);
        assert!(!source.symbols(None).1);
        assert!(!source.groups(None).2);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: relation lookups, ancestry and search read an open JVM part without recording the query incomplete, so product callers and member-absence proofs treated partial answers as complete"
    )]
    fn open_request_lookups_record_the_query_incomplete_and_refuse_absence_proofs() {
        use crate::analyzer::QueryReadIncomplete;
        use crate::analyzer::i_analyzer::AnalyzerQueryScope;
        use crate::analyzer::semantic_model::overlay::{
            SemanticModelEdgeDefect, SemanticModelSurfaceGap,
        };
        let directory = TempDir::new().unwrap();
        let analyzer =
            EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Java)));
        let build = |active: &Arc<ResolvedActiveSemanticModels>| {
            SemanticModelOverlay::build(
                &analyzer,
                active,
                &CancellationToken::new(),
                u64::MAX,
                &crate::retention_budget::RetentionBudget::for_tests(),
            )
            .unwrap()
        };
        let patterns =
            crate::analyzer::SearchSymbolPatternBatch::compile(vec![".*".into()], false, None);
        // The owner symbol is read with a working owner; the open overlay
        // below must still not prove anything about it.
        let working = mixed_active(false, false);
        let owner = build(&working)
            .search(&patterns)
            .into_iter()
            .find(|symbol| symbol.kind.is_type_declaration())
            .expect("the fixture declares a type");

        let mut open = mixed_active(false, false);
        {
            let installed_source: Option<
                Arc<dyn crate::analyzer::store::model_catalog::RequestRowReaderSource>,
            > = Some(Arc::new(OpenSource));
            Arc::get_mut(&mut open)
                .unwrap()
                .install_request_source(installed_source)
                .unwrap();
        };
        let overlay = build(&open);
        let incomplete = |run: &dyn Fn()| {
            let scope = AnalyzerQueryScope::capturing_read_incompleteness(&analyzer);
            run();
            let reasons = scope.captured_read_incompleteness();
            assert!(
                reasons.iter().any(|reason| matches!(
                    reason,
                    QueryReadIncomplete::SemanticEvidenceUnavailable(_)
                )),
                "{reasons:?}"
            );
        };
        incomplete(&|| {
            let matched = overlay.relations_from(&owner.id);
            assert!(matches!(
                matched.disposition,
                SemanticModelOverlayDisposition::Open(_)
            ));
        });
        incomplete(&|| {
            let matched = overlay.relations_to(&owner.id);
            assert!(matches!(
                matched.disposition,
                SemanticModelOverlayDisposition::Open(_)
            ));
        });
        incomplete(&|| {
            let (_, _, complete) = overlay.search_with_limit(&patterns, usize::MAX, None);
            assert!(!complete);
        });
        incomplete(&|| {
            let surface = overlay.owner_surface(&owner);
            assert!(
                surface.gaps.iter().any(|gap| matches!(
                    gap,
                    SemanticModelSurfaceGap::UnresolvedEdge(edge)
                        if edge.defect == SemanticModelEdgeDefect::RelationsOpen
                )),
                "{:?}",
                surface.gaps
            );
            assert!(
                overlay
                    .callable_owners_on_surface(&open, &owner, "create")
                    .is_none()
            );
            let answer = overlay.ancestry_answer(&owner);
            assert!(
                !answer.missing.is_empty(),
                "an open relation read must not read as a type with no base"
            );
            // Bases read next to an open part are candidates, never definite.
            assert!(answer.records.is_empty(), "{:?}", answer.records);
            assert!(matches!(
                overlay.ancestors_of(&owner).disposition,
                SemanticModelOverlayDisposition::Open(_)
            ));
        });
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: an open owner reused a retained search stream with no binding"
    )]
    fn open_request_search_refuses_retained_placeholder_stream() {
        let directory = TempDir::new().unwrap();
        let analyzer =
            EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Java)));
        let cache = crate::analyzer::store::cache_budget::StoreCacheBudget::new(
            &crate::retention_budget::RetentionBudget::for_tests(),
        );
        let patterns =
            crate::analyzer::SearchSymbolPatternBatch::compile(vec![".*".into()], false, None);
        let mut active = mixed_active(false, true);
        {
            let installed_source: Option<
                Arc<dyn crate::analyzer::store::model_catalog::RequestRowReaderSource>,
            > = None;
            Arc::get_mut(&mut active)
                .unwrap()
                .install_request_source(installed_source)
                .unwrap();
        };
        let source = row_entry_points::RowOverlay::new(
            &analyzer,
            &active,
            Vec::new(),
            Vec::new(),
            Some(cache.clone()),
            &[],
        );
        assert!(source.search_symbols(&patterns, None, None).1);
        let before = cache.region_stats();
        let mut active = mixed_active(false, true);
        {
            let installed_source: Option<
                Arc<dyn crate::analyzer::store::model_catalog::RequestRowReaderSource>,
            > = Some(Arc::new(OpenSource));
            Arc::get_mut(&mut active)
                .unwrap()
                .install_request_source(installed_source)
                .unwrap();
        };
        let source = row_entry_points::RowOverlay::new(
            &analyzer,
            &active,
            Vec::new(),
            Vec::new(),
            Some(cache.clone()),
            &[],
        );
        assert!(!source.search_symbols(&patterns, None, None).1);
        assert_eq!(
            format!("{:?}", before),
            format!("{:?}", cache.region_stats())
        );
    }

    #[test]
    fn open_request_anchors_are_not_retained() {
        let mut active = mixed_active(false, true);
        {
            let installed_source: Option<
                Arc<dyn crate::analyzer::store::model_catalog::RequestRowReaderSource>,
            > = Some(Arc::new(OpenSource));
            Arc::get_mut(&mut active)
                .unwrap()
                .install_request_source(installed_source)
                .unwrap();
        };
        let directory = TempDir::new().unwrap();
        let analyzer =
            EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Java)));
        let cache = crate::analyzer::store::cache_budget::StoreCacheBudget::new(
            &crate::retention_budget::RetentionBudget::for_tests(),
        );
        let source = row_entry_points::RowOverlay::new(
            &analyzer,
            &active,
            Vec::new(),
            Vec::new(),
            Some(cache.clone()),
            &[],
        );
        let (_, open) = source.symbols_at_authored_path("com/acme/Widget.java");
        assert_eq!(open, Some(FamilyOpen::jvm("request source unavailable")));
        let stats = cache.region_stats();
        let anchors = stats
            .iter()
            .find(|(name, _)| *name == "store.request-source-anchors")
            .unwrap();
        assert_eq!(anchors.1.entries, 0);
    }

    #[test]
    fn declared_type_names_open_under_a_real_request_owner() {
        let mut active = mixed_active(false, true);
        let directory = TempDir::new().unwrap();
        let analyzer =
            EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Java)));
        // With no request owner (as with the placeholder, which reads through
        // the activation) the activation owns every shard and the names are
        // complete.
        {
            let installed_source: Option<
                Arc<dyn crate::analyzer::store::model_catalog::RequestRowReaderSource>,
            > = None;
            Arc::get_mut(&mut active)
                .unwrap()
                .install_request_source(installed_source)
                .unwrap();
        };
        let placeholder = row_entry_points::RowOverlay::new(
            &analyzer,
            &active,
            Vec::new(),
            Vec::new(),
            None,
            &[],
        );
        assert!(placeholder.declaration_type_names("java").is_ok());
        // The overlay holds a clone of the activation; release it before the swap.
        drop(placeholder);
        // A real owner whose JVM part is open answers Java names Open, while a
        // non-JVM language's activation-owned names stay complete.
        {
            let installed_source: Option<
                Arc<dyn crate::analyzer::store::model_catalog::RequestRowReaderSource>,
            > = Some(Arc::new(OpenSource));
            Arc::get_mut(&mut active)
                .unwrap()
                .install_request_source(installed_source)
                .unwrap();
        };
        let owned = row_entry_points::RowOverlay::new(
            &analyzer,
            &active,
            Vec::new(),
            Vec::new(),
            None,
            &[],
        );
        assert!(matches!(
            owned.declaration_type_names("java"),
            Err(SemanticModelOverlayBuildError::Open(_))
        ));
        assert!(owned.declaration_type_names("python").is_ok());
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#10497: external intermediate hierarchy ignored row-backed JVM inventories"
)]
fn java_direct_hierarchy_reads_row_backed_inventory() {
    use crate::analyzer::semantic_model::{CompilerOptions, SourceFormat, compile_source};
    for exhaustive in [true, false] {
        let mut document: Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/semantic-model-packs/declarations-v1.json"
        )))
        .unwrap();
        document["shards"][0]["payload"]["types"][0]["hierarchy"] = json!([{"hierarchy_kind": "extends", "target": {"kind": "named", "name": "java.lang.Object"}}]);
        document["shards"][0]["payload"]["types"][0]["jvm_inventory"] = if exhaustive {
            json!({
                "callables_complete": true, "values_complete": true, "types_complete": true,
                "supertypes_complete": true,
                "supertypes": [{"hierarchy_kind": "extends", "target": {"kind": "named", "name": "java.lang.Object"}}],
                "nested_types": [], "additional_members": []
            })
        } else {
            Value::Null
        };
        let pack = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&document).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap();
        let mut results = Vec::new();
        for row_backed in [false, true] {
            let (mut active, _reader) =
                catalog_fixture_active(std::slice::from_ref(&pack), "10497-row-hierarchy");
            if row_backed {
                let fixture = Arc::get_mut(&mut active).unwrap();
                fixture.indexes = MatcherIndexes::default();
                for shard in &mut fixture.shards {
                    Arc::get_mut(shard).unwrap().decoded = None;
                }
            }
            let directory = TempDir::new().unwrap();
            let analyzer =
                EmptyAnalyzer::new(Arc::new(TestProject::new(directory.path(), Language::Java)));
            let overlay = SemanticModelOverlay::build(
                &analyzer,
                &active,
                &CancellationToken::new(),
                u64::MAX,
                &crate::retention_budget::RetentionBudget::for_tests(),
            )
            .unwrap();
            let matched = overlay.symbols_with_id("type.widget");
            let [symbol] = matched.records.as_slice() else {
                panic!("{matched:?}")
            };
            let (parents, complete) = overlay.java_direct_hierarchy(symbol).unwrap();
            assert_eq!(complete, exhaustive);
            assert_eq!(parents.len(), 1);
            assert_eq!(parents[0].target, TypeRef::named("java.lang.Object"));
            let mut closure = brokk_bifrost_jvm::ExternalSupertypeClosure::default();
            let mut visited = 0;
            let answer = closure
                .reaches_root(
                    "Owner",
                    "java.lang.Object",
                    &mut visited,
                    2,
                    None,
                    |raw| Some(raw.into()),
                    |identity| {
                        assert_eq!(identity, "Owner");
                        Some(brokk_bifrost_jvm::ExternalSupertypeFacts {
                            supertypes: parents
                                .iter()
                                .map(|edge| {
                                    let TypeRef::Named { name, .. } = &edge.target else {
                                        panic!("fixture parent: {edge:?}")
                                    };
                                    name.clone()
                                })
                                .collect(),
                            complete,
                        })
                    },
                )
                .unwrap();
            assert!(answer.reaches_root);
            assert_eq!(answer.unresolved_supertype.is_none(), exhaustive);
            assert_eq!(visited, 2);
            results.push((answer, visited));
        }
        assert_eq!(results[0], results[1]);
    }
}
