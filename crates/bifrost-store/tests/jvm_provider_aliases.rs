//! Shared-store publication lifecycle and retention across projection identities.
use brokk_bifrost_store::analyzer::resolution::ResolutionDiagnostics;
use brokk_bifrost_store::analyzer::store::jvm_external_publication::{
    JvmExternalProjection, JvmExternalPublication, jvm_external_projection_identity,
    jvm_external_provider_id, jvm_external_provider_id_for_identity,
};
use brokk_bifrost_store::analyzer::store::{AnalyzerStore, Result};
use rusqlite::{params, types::Value};

// This store-only fixture supplies the host assembly symbol without pulling
// analyzer implementations back into their store dependency. Publication must
// not request language hooks; fail if that boundary changes.
#[unsafe(no_mangle)]
fn __brokk_bifrost_store_language_supports_v1()
-> &'static brokk_bifrost_store::analyzer::store::StoreLanguageTable {
    unreachable!("publication fixtures do not request language hooks")
}

// The store library declares resolution diagnostics as a link-time extern.
// Its cfg(test) stand-in is absent from an integration-test build, and the
// analysis assembly that defines the real recorder must not be linked here.
// A standalone store fixture has no recorder, so diagnostics are off.
struct StandaloneResolutionDiagnostics;

impl ResolutionDiagnostics for StandaloneResolutionDiagnostics {
    fn recording(&self) -> bool {
        false
    }

    fn native_rejection_projection_active(&self) -> bool {
        false
    }
}

#[unsafe(no_mangle)]
fn __brokk_bifrost_resolution_diagnostics_v1() -> &'static dyn ResolutionDiagnostics {
    &StandaloneResolutionDiagnostics
}

fn projection(artifact: &str) -> JvmExternalProjection {
    let provider = jvm_external_provider_id(artifact);
    JvmExternalProjection {
        semantic_sha256: artifact.into(),
        provider_id: provider.clone(),
        source_identity: "catalog".into(),
        owners: vec![vec![
            Value::Text(provider),
            Value::Text("example.Owner".into()),
            Value::Integer(1),
            Value::Integer(1),
            Value::Integer(1),
            Value::Integer(1),
            // Known-empty type parameters: the generic-surface column (#12385).
            Value::Text("[]".into()),
        ]],
        members: Vec::new(),
        supertypes: Vec::new(),
    }
}

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
)]
fn legacy_parent_and_sealed_parent_are_distinct_states() {
    let config = brokk_bifrost_core::analyzer::config::AnalyzerConfig::default();
    let budget =
        brokk_bifrost_core::retention_budget::RetentionBudget::new(config.retention_budget_bytes());
    let store = AnalyzerStore::open_ephemeral_with_config(&config, &budget).unwrap();
    let types: Vec<brokk_bifrost_store::analyzer::semantic_model::TypeFact> = serde_json::from_value(serde_json::json!([
        {"id":"owner","name":"example.Owner","type_kind":"class","visibility":"public","locator":{"kind":"artifact","path":"fixture.jar","symbol":"owner"}}
    ])).unwrap();
    store
        .publish_jvm_external_inventory_facts("artifact".into(), &types, &[], true)
        .unwrap();
    let provider = jvm_external_provider_id("artifact");
    let conn = store.read_conn().unwrap();
    let state: String = conn
        .query_row(
            "SELECT publication_state FROM jvm_external_provider_publications WHERE provider_id=?1",
            [&provider],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "uncertified");
    let owners: usize = conn
        .query_row(
            "SELECT count(*) FROM jvm_external_owners WHERE provider_id=?1",
            [&provider],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(owners, 1);
    drop(conn);
    assert!(
        store
            .jvm_external_source_certificate(&provider, "catalog")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .publish_jvm_external_projection(|| Ok(Some(projection("sealed-artifact"))), || false)
            .unwrap(),
        JvmExternalPublication::Available
    );
    let sealed = jvm_external_provider_id("sealed-artifact");
    store.conn.execute(move |conn| -> Result<()> {
        let state: String = conn.query_row("SELECT publication_state FROM jvm_external_provider_publications WHERE provider_id=?1", [&sealed], |row| row.get(0))?;
        assert_eq!(state, "sealed");
        assert!(conn.execute("INSERT INTO jvm_external_owners(provider_id,owner_fqn,callables_complete,values_complete,types_complete,supertypes_complete) VALUES(?1,'other.Owner',0,0,0,0)", [&sealed]).is_err());
        assert!(conn.execute("UPDATE jvm_external_provider_publications SET publication_state='sealed',projected_rows_sha256=zeroblob(32),owner_count=1,member_count=0,supertype_count=0 WHERE semantic_sha256='artifact'", []).is_err());
        Ok(())
    }).unwrap();
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#12245: an uncertified publication blocked the later certified activation for the same provider"
)]
#[expect(
    clippy::disallowed_methods,
    reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
)]
fn certified_publication_replaces_uncertified_inventory() {
    let config = brokk_bifrost_core::analyzer::config::AnalyzerConfig::default();
    let budget =
        brokk_bifrost_core::retention_budget::RetentionBudget::new(config.retention_budget_bytes());
    let store = AnalyzerStore::open_ephemeral_with_config(&config, &budget).unwrap();
    let fresh = AnalyzerStore::open_ephemeral_with_config(&config, &budget).unwrap();
    let types: Vec<brokk_bifrost_store::analyzer::semantic_model::TypeFact> = serde_json::from_value(serde_json::json!([
        {"id":"old","name":"example.Old","type_kind":"class","visibility":"public","locator":{"kind":"artifact","path":"fixture.jar","symbol":"old"}}
    ])).unwrap();
    store
        .publish_jvm_external_inventory_facts("artifact".into(), &types, &[], true)
        .unwrap();
    let provider = jvm_external_provider_id("artifact");
    store.conn.execute({ let provider = provider.clone(); move |conn| -> Result<()> {
        conn.execute("INSERT INTO jvm_external_owner_supertypes(provider_id,owner_fqn,supertype_fqn,ordinal) VALUES(?1,'example.Old','example.Base',0)", [&provider])?;
        conn.execute("INSERT INTO jvm_external_owner_members(provider_id,owner_fqn,ordinal,member_name,member_kind,visibility,is_static,signature_present,callable_family_complete,non_overridable,is_abstract,parameters_jsonb) VALUES(?1,'example.Old',0,'old','method','public',0,0,0,NULL,0,jsonb('[]'))", [&provider])?;
        Ok(())
    }}).unwrap();
    for target in [&store, &fresh] {
        assert_eq!(
            target
                .publish_jvm_external_projection(|| Ok(Some(projection("artifact"))), || false)
                .unwrap(),
            JvmExternalPublication::Available
        );
    }
    assert_eq!(
        store
            .jvm_external_provider_inventory_digest(&provider)
            .unwrap(),
        fresh
            .jvm_external_provider_inventory_digest(&provider)
            .unwrap()
    );
    let snapshot = || {
        let conn = store.read_conn().unwrap();
        conn.query_row("SELECT generation, (SELECT publication_sequence FROM jvm_external_provider_publications WHERE provider_id=?1) FROM jvm_external_inventory_generation WHERE id=0", [&provider], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))).unwrap()
    };
    let before = snapshot();
    assert_eq!(
        store
            .publish_jvm_external_projection(|| Ok(Some(projection("artifact"))), || false)
            .unwrap(),
        JvmExternalPublication::Available
    );
    assert_eq!(snapshot(), before); // Identical publication is a no-op, including the clock.
    // An uncertified writer cannot replace the sealed projection.
    store
        .publish_jvm_external_inventory_facts("artifact".into(), &types, &[], true)
        .unwrap();
    assert_eq!(snapshot(), before);
    let conn = store.read_conn().unwrap();
    for table in [
        "jvm_external_owner_members",
        "jvm_external_owner_supertypes",
    ] {
        let count: i64 = conn
            .query_row(
                &format!("SELECT count(*) FROM {table} WHERE provider_id=?1"),
                [&provider],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }
    let owner: String = conn
        .query_row(
            "SELECT owner_fqn FROM jvm_external_owners WHERE provider_id=?1",
            [&provider],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(owner, "example.Owner");
    let state: String = conn
        .query_row(
            "SELECT publication_state FROM jvm_external_provider_publications WHERE provider_id=?1",
            [&provider],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(state, "sealed");
}

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
)]
fn identities_coexist_then_republish_after_retention_with_pinned_reader() {
    let dir = tempfile::tempdir().unwrap();
    let config = brokk_bifrost_core::analyzer::config::AnalyzerConfig::default();
    let budget =
        brokk_bifrost_core::retention_budget::RetentionBudget::new(config.retention_budget_bytes());
    let store = AnalyzerStore::open_persistent_with_config(
        &dir.path().join("inventory.db"),
        &config,
        &budget,
    )
    .unwrap();
    let current = jvm_external_provider_id("artifact");
    assert_eq!(
        store
            .publish_jvm_external_projection(|| Ok(Some(projection("artifact"))), || false)
            .unwrap(),
        JvmExternalPublication::Available
    );
    let mut identity = jvm_external_projection_identity();
    identity[0] ^= 1;
    let previous = jvm_external_provider_id_for_identity("artifact", &identity);
    let older_unavailable = store
        .jvm_external_provider_inventory_digest(&previous)
        .unwrap();
    // A second binary uses the same schema with a different projection identity.
    let second = previous.clone();
    store.conn.execute(move |conn| -> Result<()> {
        conn.execute("INSERT INTO jvm_external_provider_publications(provider_id,semantic_sha256,source_identity,projection_identity,publication_state) VALUES(?1,'artifact','',?2,'uncertified')", params![second, identity])?;
        conn.execute("INSERT INTO jvm_external_owners(provider_id,owner_fqn,callables_complete,values_complete,types_complete,supertypes_complete) VALUES(?1,'example.Owner',1,1,1,1)", [second])?;
        Ok(())
    }).unwrap();
    assert_eq!(
        store
            .jvm_external_provider_inventory_digest(&previous)
            .unwrap(),
        older_unavailable
    );
    for _ in 0..3 {
        assert_eq!(store.reclaim_jvm_external_publications().unwrap(), 0);
        assert_eq!(
            store
                .publish_jvm_external_projection(|| Ok(Some(projection("artifact"))), || false)
                .unwrap(),
            JvmExternalPublication::Available
        );
        let conn = store.read_conn().unwrap();
        for provider in [&current, &previous] {
            let owner: String = conn
                .query_row(
                    "SELECT owner_fqn FROM jvm_external_owners WHERE provider_id=?1",
                    [provider],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(owner, "example.Owner");
        }
    }
    identity[0] ^= 2;
    let third = jvm_external_provider_id_for_identity("artifact", &identity);
    let third_reader = third.clone();
    let sealed_unavailable = store
        .jvm_external_provider_inventory_digest(&third)
        .unwrap();
    store.conn.execute(move |conn| -> Result<()> {
        conn.execute("INSERT INTO jvm_external_provider_publications(provider_id,semantic_sha256,source_identity,projection_identity,publication_state,projected_rows_sha256,owner_count,member_count,supertype_count) VALUES(?1,'artifact','third',?2,'sealed',zeroblob(32),0,0,0)", params![third, identity])?;
        Ok(())
    }).unwrap();
    assert_eq!(
        store
            .jvm_external_provider_inventory_digest(&third_reader)
            .unwrap(),
        sealed_unavailable
    );
    let conn = store.read_conn().unwrap();
    let snapshot = conn.unchecked_transaction().unwrap();
    let before: String = snapshot
        .query_row(
            "SELECT owner_fqn FROM jvm_external_owners WHERE provider_id=?1",
            [&current],
            |row| row.get(0),
        )
        .unwrap();
    std::thread::scope(|scope| {
        assert_eq!(
            scope
                .spawn(|| store.reclaim_jvm_external_publications())
                .join()
                .unwrap()
                .unwrap(),
            1
        );
    });
    let pinned: String = snapshot
        .query_row(
            "SELECT owner_fqn FROM jvm_external_owners WHERE provider_id=?1",
            [&current],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(pinned, before);
    snapshot.commit().unwrap();
    drop(conn);
    assert!(
        store
            .jvm_external_source_certificate(&current, "catalog")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .publish_jvm_external_projection(|| Ok(Some(projection("artifact"))), || false)
            .unwrap(),
        JvmExternalPublication::Available
    );
    assert_eq!(store.reclaim_jvm_external_publications().unwrap(), 1);
    let conn = store.read_conn().unwrap();
    let after: String = conn
        .query_row(
            "SELECT owner_fqn FROM jvm_external_owners WHERE provider_id=?1",
            [&current],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(after, before);
    let removed: usize = conn
        .query_row(
            "SELECT count(*) FROM jvm_external_provider_publications WHERE provider_id=?1",
            [previous],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(removed, 0); // The same retention rule removes uncertified parents.
}
